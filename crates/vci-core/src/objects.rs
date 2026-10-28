//! Store format 3 (`design/STORE-V2.md`, "store format 3, predicate v2"):
//! the per-run objects a unit's record points at and the descriptor inside
//! the record that indexes them.
//!
//! Section 1.3: an object is bytes; its id is the BLAKE3 of the bytes
//! ([`object_id`]); the canonical encoding is `magic "vo"`, `u8 kind`, `u8
//! version`, body. Four kinds: [`Hdr`] (1: the header a run shares with every
//! run at the same toolchain and global inputs), [`Tables`] (2: the waiver,
//! env-name and externals tables of a run's header group), [`Shape`] (3: the
//! sorted `(path, kind, exec)` entries of every unit of a run and the groups
//! they share), [`State`] (4: the entries with sizes and hashes, which only
//! `explain` reads). Section 1.2: the [`Descriptor`] names a shape and lists
//! a unit's entries, env and externals as indices and bitmaps into it and
//! the tables; [`Descriptor::resolve`] gives the unit's observation set back
//! ([`ResolvedManifest`]). Section 1.4 steps 1-3: [`Run::build`] makes all of
//! them from a run's manifests.
//!
//! Section 1.6, the decoder rules: every decoder here is fallible, refuses
//! what rule 2 (minimal varints), 3 (delta-coded indices), 4 (env overrides),
//! 5 (canonical paths, strictly increasing lists, 255 groups), 6 (kind bytes)
//! and 8 (byte bounds, counts against the bytes remaining before anything is
//! allocated) forbid, and so decodes one content from one encoding only. The
//! frame around the record (`vci3`, base64) and the statement's own fields are
//! not here. Safety rule as everywhere in this crate: **fail open**; a value
//! this module refuses makes the caller run the unit.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::hash::ABSENT_HASH;
use crate::manifest::{
    AUTOLOAD_MARK, EntryKind, EnvEntry, External, InputEntry, InputManifest, autoload_dir_hash,
    excluded_hash,
};
use crate::path::{PathError, RepoPath};
use crate::predicate::Toolchain;

/// The 32-byte BLAKE3 id of an object (hex in statements, columns and keys).
pub type ObjectId = [u8; 32];

/// The id of an object: BLAKE3 of its bytes (section 1.3). Readers recompute
/// it for every object they load.
pub fn object_id(bytes: &[u8]) -> ObjectId {
    *blake3::hash(bytes).as_bytes()
}

/// Lowercase hex of 32 bytes (an object id, a hash).
pub fn hex32(b: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 15) as usize] as char);
    }
    s
}

/// The 32 bytes 64 lowercase hex digits spell; `None` for anything else
/// (upper case included: one spelling per value).
pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Some(out)
}

/// The object kinds (section 1.3) and their byte bounds (rule 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectKind {
    Hdr = 1,
    Tables = 2,
    Shape = 3,
    State = 4,
}

impl ObjectKind {
    /// The largest object of this kind a decoder accepts (section 1.6 rule 8).
    pub fn max_bytes(self) -> usize {
        match self {
            ObjectKind::Hdr => 1 << 20,
            ObjectKind::Tables => 4 << 20,
            ObjectKind::Shape => 8 << 20,
            ObjectKind::State => 16 << 20,
        }
    }

    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            1 => ObjectKind::Hdr,
            2 => ObjectKind::Tables,
            3 => ObjectKind::Shape,
            4 => ObjectKind::State,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            ObjectKind::Hdr => "hdr",
            ObjectKind::Tables => "tables",
            ObjectKind::Shape => "shape",
            ObjectKind::State => "state",
        }
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The largest descriptor a decoder accepts: a record is bounded at 1 MiB
/// (rule 8) and the descriptor is inside it.
pub const DESCRIPTOR_MAX: usize = 1 << 20;
/// A shape holds at most this many groups (section 1.2: the descriptor's
/// group byte, `0xff` meaning none).
pub const MAX_GROUPS: usize = 255;
/// The descriptor's group byte for a unit in no group.
pub const NO_GROUP: u8 = 0xff;

const MAGIC: &[u8; 2] = b"vo";
const VERSION: u8 = 1;
/// The longest minimal LEB128 encoding of a `u64`.
const UV_MAX_BYTES: usize = 10;

/// What a decoder refused and why (section 1.6). A record or object that
/// fails one of these fails its candidate's `envelope`, `statement` or
/// `inputs` check, and the unit runs.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DecodeError {
    #[error("{len} bytes is over the {max}-byte bound of a {what}")]
    TooLarge {
        what: &'static str,
        len: usize,
        max: usize,
    },
    #[error("truncated: the bytes end inside {0}")]
    Truncated(&'static str),
    #[error("{0} bytes follow the end of the object")]
    Trailing(usize),
    #[error("not an object: the magic is not \"vo\"")]
    Magic,
    #[error("object kind byte {found} where {expected} ({}) was expected", ObjectKind::from_u8(*expected).map(|k| k.name()).unwrap_or("?"))]
    Kind { expected: u8, found: u8 },
    #[error("object version {0} (expected 1)")]
    Version(u8),
    #[error("varint {0}")]
    Varint(&'static str),
    #[error("{0} is not UTF-8")]
    Utf8(&'static str),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("autoload-miss entry {0:?} is not of the form .vci-autoload/<name>")]
    AutoloadMiss(String),
    #[error("kind byte {0:#04x} names no entry kind")]
    KindByte(u8),
    #[error("a count of {count} {what} with {remaining} bytes remaining")]
    Count {
        what: &'static str,
        count: u64,
        remaining: usize,
    },
    #[error("{what} index {index} is not below {len}")]
    Index {
        what: &'static str,
        index: u64,
        len: usize,
    },
    #[error("{0} are not strictly increasing")]
    Unsorted(&'static str),
    #[error("prefix coding: {0}")]
    Prefix(&'static str),
    #[error("{0} groups (at most 255)")]
    TooManyGroups(u64),
    #[error("group {0} is not in the shape")]
    Group(u8),
    #[error("env override: {0}")]
    EnvOverride(&'static str),
    #[error("{0} bitmap has a bit set past the table's length")]
    Bitmap(&'static str),
    #[error("own entry {0} is already in the unit's group")]
    Overlap(usize),
    #[error("inline external {0:?} is in the tables object")]
    Extra(String),
    #[error("invalid environment variable name {0:?}")]
    EnvKey(String),
    #[error("toolchain: {0}")]
    Toolchain(String),
}

/// Why a value cannot be encoded canonically (a writer's error, never a
/// store's: a run with such a value is not attested).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum EncodeError {
    #[error("entry {path:?}: hash {hash:?} is not 64 hex digits (or not its kind's constant)")]
    Hash { path: String, hash: String },
    #[error("{0} are not strictly increasing")]
    Unsorted(&'static str),
    #[error("{len} bytes is over the {max}-byte bound of a {what}")]
    TooLarge {
        what: &'static str,
        len: usize,
        max: usize,
    },
    #[error("{0} groups (at most 255)")]
    TooManyGroups(usize),
    #[error("{what} index {index} is not below {len}")]
    Index {
        what: &'static str,
        index: usize,
        len: usize,
    },
    #[error("no unit has header group {0}")]
    Header(usize),
    #[error("a waiver table of {0} strings (ids are u16)")]
    WaiverTable(usize),
    #[error("invalid environment variable name {0:?}")]
    EnvKey(String),
    #[error("toolchain JSON: {0}")]
    Json(String),
}

// ---------------------------------------------------------------- primitives

/// `uv`: unsigned LEB128, minimal (section 1.6 rule 2).
fn put_uv(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// A string: `uv len`, then the UTF-8.
fn put_str(out: &mut Vec<u8>, s: &str) {
    put_uv(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// Prefix coding of a sorted list of strings (section 1.3): each item is
/// `uv shared-with-previous`, `uv suffix-len`, the suffix; the writer shares
/// the longest common prefix. Whatever follows an item (its tail) is the
/// caller's.
#[derive(Default)]
struct PrefixWriter {
    prev: Vec<u8>,
}

impl PrefixWriter {
    fn write(&mut self, out: &mut Vec<u8>, s: &str) {
        let p = s.as_bytes();
        let shared = p.iter().zip(&self.prev).take_while(|(a, b)| a == b).count();
        put_uv(out, shared as u64);
        put_uv(out, (p.len() - shared) as u64);
        out.extend_from_slice(&p[shared..]);
        self.prev = p.to_vec();
    }
}

/// A fallible cursor over an object's bytes.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, DecodeError> {
        let b = *self.buf.get(self.pos).ok_or(DecodeError::Truncated(what))?;
        self.pos += 1;
        Ok(b)
    }

    fn bytes(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(DecodeError::Truncated(what));
        }
        let b = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(b)
    }

    fn hash(&mut self, what: &'static str) -> Result<[u8; 32], DecodeError> {
        let b = self.bytes(32, what)?;
        let mut h = [0u8; 32];
        h.copy_from_slice(b);
        Ok(h)
    }

    /// Rule 2: minimal LEB128, at most 10 bytes, within `u64`.
    fn uv(&mut self, what: &'static str) -> Result<u64, DecodeError> {
        let mut v: u64 = 0;
        for i in 0..UV_MAX_BYTES {
            let b = self.u8(what)?;
            let low = u64::from(b & 0x7f);
            if i == UV_MAX_BYTES - 1 && low > 1 {
                return Err(DecodeError::Varint("past u64::MAX"));
            }
            v |= low << (7 * i);
            if b & 0x80 == 0 {
                if i > 0 && low == 0 {
                    return Err(DecodeError::Varint("not minimal (a zero last byte)"));
                }
                return Ok(v);
            }
        }
        Err(DecodeError::Varint("longer than 10 bytes"))
    }

    /// A count of items of at least `min_bytes` each (rule 8): checked
    /// against the bytes remaining before the caller allocates for it.
    fn count(&mut self, what: &'static str, min_bytes: usize) -> Result<usize, DecodeError> {
        let n = self.uv(what)?;
        let remaining = self.remaining();
        if n > (remaining / min_bytes.max(1)) as u64 {
            return Err(DecodeError::Count {
                what,
                count: n,
                remaining,
            });
        }
        Ok(n as usize)
    }

    /// An index below `len`.
    fn index(&mut self, what: &'static str, len: usize) -> Result<usize, DecodeError> {
        let i = self.uv(what)?;
        if i >= len as u64 {
            return Err(DecodeError::Index {
                what,
                index: i,
                len,
            });
        }
        Ok(i as usize)
    }

    fn str(&mut self, what: &'static str) -> Result<&'a str, DecodeError> {
        let n = self.count(what, 1)?;
        std::str::from_utf8(self.bytes(n, what)?).map_err(|_| DecodeError::Utf8(what))
    }

    /// The object header: magic, the kind the caller expects, version 1.
    fn object(&mut self, kind: ObjectKind) -> Result<(), DecodeError> {
        if self.bytes(2, "magic")? != MAGIC {
            return Err(DecodeError::Magic);
        }
        let found = self.u8("kind")?;
        if found != kind as u8 {
            return Err(DecodeError::Kind {
                expected: kind as u8,
                found,
            });
        }
        let v = self.u8("version")?;
        if v != VERSION {
            return Err(DecodeError::Version(v));
        }
        Ok(())
    }

    fn finish(self) -> Result<(), DecodeError> {
        match self.remaining() {
            0 => Ok(()),
            n => Err(DecodeError::Trailing(n)),
        }
    }
}

/// The reader of a [`PrefixWriter`]'s list. The prefix must be the longest
/// shared one (rule 5 as applied here: one encoding per list), the joined
/// bytes UTF-8.
#[derive(Default)]
struct PrefixReader {
    prev: Vec<u8>,
}

impl PrefixReader {
    fn read(&mut self, r: &mut Reader<'_>, what: &'static str) -> Result<String, DecodeError> {
        let shared = r.uv(what)?;
        if shared > self.prev.len() as u64 {
            return Err(DecodeError::Prefix(
                "shared prefix longer than the previous item",
            ));
        }
        let shared = shared as usize;
        let n = r.count(what, 1)?;
        let suffix = r.bytes(n, what)?;
        if shared < self.prev.len() && suffix.first() == Some(&self.prev[shared]) {
            return Err(DecodeError::Prefix("shared prefix is not the longest"));
        }
        let mut p = Vec::with_capacity(shared + n);
        p.extend_from_slice(&self.prev[..shared]);
        p.extend_from_slice(suffix);
        let s = String::from_utf8(p).map_err(|_| DecodeError::Utf8(what))?;
        self.prev = s.as_bytes().to_vec();
        Ok(s)
    }

    fn path(&mut self, r: &mut Reader<'_>, what: &'static str) -> Result<RepoPath, DecodeError> {
        Ok(RepoPath::try_from(self.read(r, what)?)?)
    }
}

fn check_object_size(what: &'static str, len: usize, max: usize) -> Result<(), DecodeError> {
    if len > max {
        return Err(DecodeError::TooLarge { what, len, max });
    }
    Ok(())
}

fn encoded(kind: ObjectKind, out: Vec<u8>) -> Result<Vec<u8>, EncodeError> {
    let max = kind.max_bytes();
    if out.len() > max {
        return Err(EncodeError::TooLarge {
            what: kind.name(),
            len: out.len(),
            max,
        });
    }
    Ok(out)
}

fn start(kind: ObjectKind, capacity: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(MAGIC);
    out.push(kind as u8);
    out.push(VERSION);
    out
}

fn strictly_increasing<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|w| w[0] < w[1])
}

/// `manifest.rs`'s rule for an env key, as a store object's decoder and the
/// encoder apply it: non-empty, no `=`, no NUL.
fn valid_env_key(k: &str) -> bool {
    !k.is_empty() && !k.contains('=') && !k.contains('\0')
}

// ---------------------------------------------------------------- kinds and entries

/// The kinds in kind-byte order (rule 6: `f l a d t x m u`, the same order
/// as [`EntryKind`]'s, so that sorting by the byte sorts as the enum does).
const KIND_CODES: [EntryKind; 8] = [
    EntryKind::File,
    EntryKind::Symlink,
    EntryKind::Absent,
    EntryKind::DirListing,
    EntryKind::Dir,
    EntryKind::Excluded,
    EntryKind::AutoloadMiss,
    EntryKind::AutoloadDir,
];

/// The kind byte: the kind's code in the low 7 bits, exec in bit 7.
fn kind_byte(kind: EntryKind, exec: bool) -> u8 {
    let code = KIND_CODES
        .iter()
        .position(|k| *k == kind)
        .expect("every kind has a code") as u8;
    code | if exec { 0x80 } else { 0 }
}

/// Rule 6: the low 7 bits must name a kind.
fn parse_kind_byte(b: u8) -> Result<(EntryKind, bool), DecodeError> {
    let kind = *KIND_CODES
        .get((b & 0x7f) as usize)
        .ok_or(DecodeError::KindByte(b))?;
    Ok((kind, b & 0x80 != 0))
}

/// The hash every entry of a constant-hash kind has (section 1.3: absent,
/// excluded, autoload-dir), which the encodings leave out.
fn constant_hash(kind: EntryKind) -> Option<String> {
    match kind {
        EntryKind::Absent => Some(ABSENT_HASH.to_owned()),
        EntryKind::Excluded => Some(excluded_hash()),
        EntryKind::AutoloadDir => Some(autoload_dir_hash()),
        _ => None,
    }
}

/// Rule 5's form of an autoload-miss entry's path (`autoload_miss`,
/// `manifest.rs`): `.vci-autoload/<name>`.
fn check_autoload_miss(path: &RepoPath, kind: EntryKind) -> Result<(), DecodeError> {
    if kind == EntryKind::AutoloadMiss {
        let comps: Vec<&str> = path.components().collect();
        if comps.len() != 2 || comps[0] != AUTOLOAD_MARK {
            return Err(DecodeError::AutoloadMiss(path.to_string()));
        }
    }
    Ok(())
}

/// A sorted list of full entries (the state object, the hdr's global
/// manifest): prefix-coded path, kind byte, `uv size`, 32 B hash except for
/// the constant-hash kinds. Strictly increasing in `(path, kind, exec, size,
/// hash)`, which is [`InputEntry`]'s order.
fn put_entries(
    out: &mut Vec<u8>,
    what: &'static str,
    entries: &[InputEntry],
) -> Result<(), EncodeError> {
    if !strictly_increasing(entries) {
        return Err(EncodeError::Unsorted(what));
    }
    put_uv(out, entries.len() as u64);
    let mut pw = PrefixWriter::default();
    for e in entries {
        pw.write(out, e.path.as_str());
        out.push(kind_byte(e.kind, e.exec));
        put_uv(out, e.size);
        let bad = || EncodeError::Hash {
            path: e.path.to_string(),
            hash: e.hash.clone(),
        };
        match constant_hash(e.kind) {
            Some(c) => {
                if e.hash != c {
                    return Err(bad());
                }
            }
            None => out.extend_from_slice(&parse_hex32(&e.hash).ok_or_else(bad)?),
        }
    }
    Ok(())
}

fn read_entries(r: &mut Reader<'_>, what: &'static str) -> Result<Vec<InputEntry>, DecodeError> {
    // shared, suffix-len, kind byte, size: four bytes at least.
    let n = r.count(what, 4)?;
    let mut out: Vec<InputEntry> = Vec::with_capacity(n);
    let mut pr = PrefixReader::default();
    for _ in 0..n {
        let path = pr.path(r, what)?;
        let (kind, exec) = parse_kind_byte(r.u8(what)?)?;
        check_autoload_miss(&path, kind)?;
        let size = r.uv(what)?;
        let hash = match constant_hash(kind) {
            Some(c) => c,
            None => hex32(&r.hash(what)?),
        };
        let e = InputEntry {
            path,
            kind,
            exec,
            size,
            hash,
        };
        if out.last().is_some_and(|p| *p >= e) {
            return Err(DecodeError::Unsorted(what));
        }
        out.push(e);
    }
    Ok(out)
}

/// A sorted list of plain strings (toolchain lists), prefix-coded.
fn put_strings(out: &mut Vec<u8>, what: &'static str, items: &[String]) -> Result<(), EncodeError> {
    if !strictly_increasing(items) {
        return Err(EncodeError::Unsorted(what));
    }
    put_uv(out, items.len() as u64);
    let mut pw = PrefixWriter::default();
    for s in items {
        pw.write(out, s);
    }
    Ok(())
}

fn read_strings(r: &mut Reader<'_>, what: &'static str) -> Result<Vec<String>, DecodeError> {
    let n = r.count(what, 2)?;
    let mut out: Vec<String> = Vec::with_capacity(n);
    let mut pr = PrefixReader::default();
    for _ in 0..n {
        let s = pr.read(r, what)?;
        if out.last().is_some_and(|p| *p >= s) {
            return Err(DecodeError::Unsorted(what));
        }
        out.push(s);
    }
    Ok(out)
}

/// The delta coding of a sorted index list (rule 3): `uv n`, then the first
/// index, then each next index as `previous + 1 + delta`.
fn put_indices(out: &mut Vec<u8>, indices: &[usize]) {
    put_uv(out, indices.len() as u64);
    let mut prev: Option<usize> = None;
    for &i in indices {
        put_uv(out, (i - prev.map_or(0, |p| p + 1)) as u64);
        prev = Some(i);
    }
}

/// Reads a delta-coded list; the indices are strictly increasing by
/// construction and each below `len`.
fn read_indices(
    r: &mut Reader<'_>,
    what: &'static str,
    len: usize,
) -> Result<Vec<usize>, DecodeError> {
    let n = r.count(what, 1)?;
    let mut out = Vec::with_capacity(n);
    let mut prev: Option<u64> = None;
    for _ in 0..n {
        let delta = r.uv(what)?;
        let i = prev
            .map_or(Some(0), |p| p.checked_add(1))
            .and_then(|b| b.checked_add(delta))
            .ok_or(DecodeError::Varint("past u64::MAX"))?;
        if i >= len as u64 {
            return Err(DecodeError::Index {
                what,
                index: i,
                len,
            });
        }
        out.push(i as usize);
        prev = Some(i);
    }
    Ok(out)
}

/// A bitmap of `len` bits, one byte per eight, bit `i` at byte `i / 8` bit
/// `i % 8` (least significant first); the bits past `len` are zero.
fn put_bitmap(out: &mut Vec<u8>, len: usize, set: &[usize]) -> Result<(), EncodeError> {
    let start = out.len();
    out.resize(start + len.div_ceil(8), 0);
    for &i in set {
        if i >= len {
            return Err(EncodeError::Index {
                what: "bitmap",
                index: i,
                len,
            });
        }
        out[start + i / 8] |= 1 << (i % 8);
    }
    Ok(())
}

fn read_bitmap(
    r: &mut Reader<'_>,
    what: &'static str,
    len: usize,
) -> Result<Vec<usize>, DecodeError> {
    let bytes = r.bytes(len.div_ceil(8), what)?;
    let mut set = Vec::new();
    for (i, b) in bytes.iter().enumerate() {
        for bit in 0..8 {
            if b & (1 << bit) != 0 {
                let idx = i * 8 + bit;
                if idx >= len {
                    return Err(DecodeError::Bitmap(what));
                }
                set.push(idx);
            }
        }
    }
    Ok(set)
}

// ---------------------------------------------------------------- hdr

/// The header object (kind 1, section 1.3): what every run at the same
/// toolchain and global inputs shares, content-addressed so that they name
/// the same one. The scalars are the v1 predicate's fields that moved out of
/// the statement (section 1.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Hdr {
    pub repo_id: String,
    pub adapter: String,
    pub project_name: String,
    pub project_dir: String,
    pub runner_project: String,
    pub tool_version: String,
    /// `railsInputs`: `loose`, `strict`, or empty.
    pub rails_inputs: String,
    pub env_config_digest: [u8; 32],
    pub global_input_root: [u8; 32],
    /// The global manifest's entries, sorted and distinct ([`InputEntry`]'s
    /// order); its `root()` must equal `global_input_root`, which the plan
    /// checks per hdr.
    pub global_manifest: Vec<InputEntry>,
    /// `ignoredInputs`, in the predicate's order.
    pub ignored_inputs: Vec<String>,
    /// `envSet`, in the predicate's order.
    pub env_set: Vec<String>,
    /// The toolchain; its four lists (`go_env`, `python_dists`,
    /// `ruby_gems`, `rust_cfg`) must be sorted and distinct.
    pub toolchain: Toolchain,
}

/// The toolchain's scalar fields as compact JSON with sorted keys (the
/// lists cleared), the one spelling the hdr holds.
fn toolchain_scalars_json(tc: &Toolchain) -> Result<String, EncodeError> {
    let mut t = tc.clone();
    t.go_env.clear();
    t.python_dists.clear();
    t.ruby_gems.clear();
    t.rust_cfg.clear();
    let v = serde_json::to_value(&t).map_err(|e| EncodeError::Json(e.to_string()))?;
    let obj = v
        .as_object()
        .ok_or_else(|| EncodeError::Json("not an object".to_owned()))?;
    let sorted: BTreeMap<&String, &serde_json::Value> = obj.iter().collect();
    serde_json::to_string(&sorted).map_err(|e| EncodeError::Json(e.to_string()))
}

impl Hdr {
    /// The global manifest the hdr holds, as the plan rehashes it.
    pub fn global_manifest(&self) -> InputManifest {
        InputManifest {
            entries: self.global_manifest.clone(),
            externals: Vec::new(),
            env: Vec::new(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = start(ObjectKind::Hdr, 4096);
        for s in [
            &self.repo_id,
            &self.adapter,
            &self.project_name,
            &self.project_dir,
            &self.runner_project,
            &self.tool_version,
            &self.rails_inputs,
        ] {
            put_str(&mut out, s);
        }
        out.extend_from_slice(&self.env_config_digest);
        out.extend_from_slice(&self.global_input_root);
        put_entries(&mut out, "global manifest entries", &self.global_manifest)?;
        for list in [&self.ignored_inputs, &self.env_set] {
            put_uv(&mut out, list.len() as u64);
            for s in list {
                put_str(&mut out, s);
            }
        }
        put_str(&mut out, &toolchain_scalars_json(&self.toolchain)?);
        let tc = &self.toolchain;
        put_strings(&mut out, "toolchain goEnv", &tc.go_env)?;
        put_strings(&mut out, "toolchain pythonDists", &tc.python_dists)?;
        put_strings(&mut out, "toolchain rubyGems", &tc.ruby_gems)?;
        put_strings(&mut out, "toolchain rustCfg", &tc.rust_cfg)?;
        encoded(ObjectKind::Hdr, out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        check_object_size("hdr", bytes.len(), ObjectKind::Hdr.max_bytes())?;
        let mut r = Reader::new(bytes);
        r.object(ObjectKind::Hdr)?;
        let mut h = Hdr::default();
        for (what, field) in [
            ("repoId", &mut h.repo_id),
            ("adapter", &mut h.adapter),
            ("projectName", &mut h.project_name),
            ("projectDir", &mut h.project_dir),
            ("runnerProject", &mut h.runner_project),
            ("toolVersion", &mut h.tool_version),
            ("railsInputs", &mut h.rails_inputs),
        ] {
            *field = r.str(what)?.to_owned();
        }
        h.env_config_digest = r.hash("envConfigDigest")?;
        h.global_input_root = r.hash("globalInputRoot")?;
        h.global_manifest = read_entries(&mut r, "global manifest entries")?;
        for (what, list) in [
            ("ignoredInputs", &mut h.ignored_inputs),
            ("envSet", &mut h.env_set),
        ] {
            let n = r.count(what, 1)?;
            list.reserve(n);
            for _ in 0..n {
                list.push(r.str(what)?.to_owned());
            }
        }
        let json = r.str("toolchain")?;
        let mut tc: Toolchain =
            serde_json::from_str(json).map_err(|e| DecodeError::Toolchain(e.to_string()))?;
        // One spelling: the scalars must re-encode to the bytes read, so no
        // list, no unknown field and no other key order or spacing passes.
        if toolchain_scalars_json(&tc).ok().as_deref() != Some(json) {
            return Err(DecodeError::Toolchain(
                "the scalar fields are not in their canonical JSON".to_owned(),
            ));
        }
        tc.go_env = read_strings(&mut r, "toolchain goEnv")?;
        tc.python_dists = read_strings(&mut r, "toolchain pythonDists")?;
        tc.ruby_gems = read_strings(&mut r, "toolchain rubyGems")?;
        tc.rust_cfg = read_strings(&mut r, "toolchain rustCfg")?;
        h.toolchain = tc;
        r.finish()?;
        Ok(h)
    }
}

// ---------------------------------------------------------------- tables

/// The tables object (kind 2, section 1.3): per run and header group, the
/// unions the statements' `waived` ids and the descriptors' env and
/// externals indices point into. Every list is sorted and distinct.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tables {
    /// The waiver table: the distinct waived strings of the group's units.
    pub waivers: Vec<String>,
    /// The env names any of the group's units read.
    pub env_names: Vec<String>,
    /// The `(name, version)` pairs of the group's units' externals.
    pub externals: Vec<External>,
}

impl Tables {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        if !strictly_increasing(&self.waivers) {
            return Err(EncodeError::Unsorted("waiver table"));
        }
        if !strictly_increasing(&self.externals) {
            return Err(EncodeError::Unsorted("externals table"));
        }
        if let Some(k) = self.env_names.iter().find(|k| !valid_env_key(k)) {
            return Err(EncodeError::EnvKey(k.clone()));
        }
        let mut out = start(ObjectKind::Tables, 1024);
        put_uv(&mut out, self.waivers.len() as u64);
        for w in &self.waivers {
            put_str(&mut out, w);
        }
        put_strings(&mut out, "env names", &self.env_names)?;
        put_uv(&mut out, self.externals.len() as u64);
        let mut pw = PrefixWriter::default();
        for x in &self.externals {
            pw.write(&mut out, &x.name);
            put_str(&mut out, &x.version);
        }
        encoded(ObjectKind::Tables, out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        check_object_size("tables", bytes.len(), ObjectKind::Tables.max_bytes())?;
        let mut r = Reader::new(bytes);
        r.object(ObjectKind::Tables)?;
        let n = r.count("waiver table", 1)?;
        let mut waivers: Vec<String> = Vec::with_capacity(n);
        for _ in 0..n {
            let w = r.str("waiver table")?.to_owned();
            if waivers.last().is_some_and(|p| *p >= w) {
                return Err(DecodeError::Unsorted("waiver table"));
            }
            waivers.push(w);
        }
        let env_names = read_strings(&mut r, "env names")?;
        if let Some(k) = env_names.iter().find(|k| !valid_env_key(k)) {
            return Err(DecodeError::EnvKey(k.clone()));
        }
        let n = r.count("externals table", 3)?;
        let mut externals: Vec<External> = Vec::with_capacity(n);
        let mut pr = PrefixReader::default();
        for _ in 0..n {
            let name = pr.read(&mut r, "externals table")?;
            let version = r.str("externals table")?.to_owned();
            let x = External { name, version };
            if externals.last().is_some_and(|p| *p >= x) {
                return Err(DecodeError::Unsorted("externals table"));
            }
            externals.push(x);
        }
        r.finish()?;
        Ok(Tables {
            waivers,
            env_names,
            externals,
        })
    }
}

// ---------------------------------------------------------------- shape

/// One entry of a shape, and of a resolved manifest: a path and what kind
/// of thing was observed there. Ordered as [`InputEntry`] is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShapeEntry {
    pub path: RepoPath,
    pub kind: EntryKind,
    pub exec: bool,
}

impl ShapeEntry {
    pub fn of(e: &InputEntry) -> Self {
        ShapeEntry {
            path: e.path.clone(),
            kind: e.kind,
            exec: e.exec,
        }
    }
}

/// The shape object (kind 3, section 1.3): the sorted distinct `(path, kind,
/// exec)` entries of every unit of a run and the groups (today's shared
/// bases) as index lists into them. Nothing in it depends on file content.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Shape {
    pub entries: Vec<ShapeEntry>,
    /// At most [`MAX_GROUPS`], each strictly increasing and in range.
    pub groups: Vec<Vec<usize>>,
}

impl Shape {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        if !strictly_increasing(&self.entries) {
            return Err(EncodeError::Unsorted("shape entries"));
        }
        if self.groups.len() > MAX_GROUPS {
            return Err(EncodeError::TooManyGroups(self.groups.len()));
        }
        let mut out = start(ObjectKind::Shape, 32 + self.entries.len() * 20);
        put_uv(&mut out, self.entries.len() as u64);
        let mut pw = PrefixWriter::default();
        for e in &self.entries {
            pw.write(&mut out, e.path.as_str());
            out.push(kind_byte(e.kind, e.exec));
        }
        put_uv(&mut out, self.groups.len() as u64);
        for g in &self.groups {
            if !strictly_increasing(g) {
                return Err(EncodeError::Unsorted("group indices"));
            }
            if let Some(&i) = g.last().filter(|&&i| i >= self.entries.len()) {
                return Err(EncodeError::Index {
                    what: "group entry",
                    index: i,
                    len: self.entries.len(),
                });
            }
            put_indices(&mut out, g);
        }
        encoded(ObjectKind::Shape, out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        check_object_size("shape", bytes.len(), ObjectKind::Shape.max_bytes())?;
        let mut r = Reader::new(bytes);
        r.object(ObjectKind::Shape)?;
        let n = r.count("shape entries", 3)?;
        let mut entries: Vec<ShapeEntry> = Vec::with_capacity(n);
        let mut pr = PrefixReader::default();
        for _ in 0..n {
            let path = pr.path(&mut r, "shape entries")?;
            let (kind, exec) = parse_kind_byte(r.u8("shape entries")?)?;
            check_autoload_miss(&path, kind)?;
            let e = ShapeEntry { path, kind, exec };
            if entries.last().is_some_and(|p| *p >= e) {
                return Err(DecodeError::Unsorted("shape entries"));
            }
            entries.push(e);
        }
        let g = r.uv("groups")?;
        if g > MAX_GROUPS as u64 {
            return Err(DecodeError::TooManyGroups(g));
        }
        let mut groups = Vec::with_capacity(g as usize);
        for _ in 0..g {
            groups.push(read_indices(&mut r, "group entry", entries.len())?);
        }
        r.finish()?;
        Ok(Shape { entries, groups })
    }
}

// ---------------------------------------------------------------- state

/// The state object (kind 4, section 1.3): every entry of every unit of a
/// run with its size and hash, sorted and distinct in `(path, kind, exec,
/// size, hash)`, so that a `(path, kind)` observed with two values during the
/// run is listed twice, side by side. No verdict reads it: `explain` prints
/// the attested value from it, labelled unsigned.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct State {
    pub entries: Vec<InputEntry>,
}

impl State {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = start(ObjectKind::State, 32 + self.entries.len() * 44);
        put_entries(&mut out, "state entries", &self.entries)?;
        encoded(ObjectKind::State, out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        check_object_size("state", bytes.len(), ObjectKind::State.max_bytes())?;
        let mut r = Reader::new(bytes);
        r.object(ObjectKind::State)?;
        let entries = read_entries(&mut r, "state entries")?;
        r.finish()?;
        Ok(State { entries })
    }

    /// The attested values of a path, in order (one, or several when the
    /// run observed it with different values).
    pub fn lookup(&self, path: &RepoPath) -> &[InputEntry] {
        let from = self.entries.partition_point(|e| e.path < *path);
        let to = from + self.entries[from..].partition_point(|e| e.path == *path);
        &self.entries[from..to]
    }
}

// ---------------------------------------------------------------- descriptor

/// A unit's descriptor (section 1.2, `descriptor_bytes`): which shape, which
/// of its groups, which of its entries are the unit's own, which env names
/// of the tables it read and with what value hash, which externals of the
/// tables it had, plus inline externals. It is bound by the signed input
/// root through [`Descriptor::resolve`], never by itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Descriptor {
    pub shape: ObjectId,
    /// The group of the shape the unit's entries extend, if any.
    pub group: Option<u8>,
    /// The unit's own entries: sorted distinct indices into the shape's
    /// entries, none of them in the group.
    pub own: Vec<usize>,
    /// The env names the unit read: sorted distinct indices into the tables'
    /// env names (the bitmap).
    pub env_read: Vec<usize>,
    /// The value hashes of the env names that were set: `(index, BLAKE3)`,
    /// sorted by index, each index in `env_read`, no hash [`ABSENT_HASH`].
    pub env_values: Vec<(usize, [u8; 32])>,
    /// The unit's externals: sorted distinct indices into the tables'
    /// externals (the bitmap).
    pub externals: Vec<usize>,
    /// Externals not in the tables (never by construction), sorted distinct.
    pub extras: Vec<External>,
}

impl Descriptor {
    /// The shape id of an encoded descriptor, read before its tables are
    /// known (section 1.5 step 5: it is collected with the statement's ids).
    pub fn shape_id(bytes: &[u8]) -> Result<ObjectId, DecodeError> {
        check_object_size("descriptor", bytes.len(), DESCRIPTOR_MAX)?;
        Reader::new(bytes).hash("shape id")
    }

    /// The descriptor's bytes; the tables give the bitmaps their lengths.
    pub fn encode(&self, tables: &Tables) -> Result<Vec<u8>, EncodeError> {
        if !strictly_increasing(&self.own) {
            return Err(EncodeError::Unsorted("own entries"));
        }
        if !strictly_increasing(&self.env_read) {
            return Err(EncodeError::Unsorted("env names"));
        }
        if !strictly_increasing(&self.externals) {
            return Err(EncodeError::Unsorted("externals"));
        }
        if !strictly_increasing(&self.extras) {
            return Err(EncodeError::Unsorted("inline externals"));
        }
        let mut out = Vec::with_capacity(64 + self.own.len() * 2 + self.env_values.len() * 33);
        out.extend_from_slice(&self.shape);
        out.push(self.group.unwrap_or(NO_GROUP));
        put_indices(&mut out, &self.own);
        put_uv(&mut out, self.env_values.len() as u64);
        let mut prev: Option<usize> = None;
        for (i, h) in &self.env_values {
            if prev.is_some_and(|p| p >= *i) {
                return Err(EncodeError::Unsorted("env overrides"));
            }
            if *i >= tables.env_names.len() {
                return Err(EncodeError::Index {
                    what: "env override",
                    index: *i,
                    len: tables.env_names.len(),
                });
            }
            prev = Some(*i);
            put_uv(&mut out, *i as u64);
            out.extend_from_slice(h);
        }
        put_bitmap(&mut out, tables.env_names.len(), &self.env_read)?;
        put_bitmap(&mut out, tables.externals.len(), &self.externals)?;
        put_uv(&mut out, self.extras.len() as u64);
        for x in &self.extras {
            put_str(&mut out, &x.name);
            put_str(&mut out, &x.version);
        }
        Ok(out)
    }

    /// Decodes a descriptor against the tables object its record's statement
    /// names (rules 3 and 4 as far as the tables decide them; the shape's
    /// checks are [`Descriptor::resolve`]'s).
    pub fn decode(bytes: &[u8], tables: &Tables) -> Result<Self, DecodeError> {
        check_object_size("descriptor", bytes.len(), DESCRIPTOR_MAX)?;
        let mut r = Reader::new(bytes);
        let shape = r.hash("shape id")?;
        let group = match r.u8("group")? {
            NO_GROUP => None,
            g => Some(g),
        };
        // The shape is not at hand: its length bounds the indices in resolve.
        let own = read_indices(&mut r, "own entry", usize::MAX)?;
        let k = r.count("env overrides", 33)?;
        let mut env_values: Vec<(usize, [u8; 32])> = Vec::with_capacity(k);
        for _ in 0..k {
            let i = r.index("env override", tables.env_names.len())?;
            let h = r.hash("env override")?;
            if env_values.last().is_some_and(|(p, _)| *p >= i) {
                return Err(DecodeError::EnvOverride("indices not strictly increasing"));
            }
            if h == [0u8; 32] {
                return Err(DecodeError::EnvOverride("ABSENT_HASH listed as a value"));
            }
            env_values.push((i, h));
        }
        let env_read = read_bitmap(&mut r, "env names", tables.env_names.len())?;
        for (i, _) in &env_values {
            if env_read.binary_search(i).is_err() {
                return Err(DecodeError::EnvOverride("the name's bitmap bit is clear"));
            }
        }
        let externals = read_bitmap(&mut r, "externals", tables.externals.len())?;
        let m = r.count("inline externals", 2)?;
        let mut extras: Vec<External> = Vec::with_capacity(m);
        for _ in 0..m {
            let name = r.str("inline external name")?.to_owned();
            let version = r.str("inline external version")?.to_owned();
            let x = External { name, version };
            if extras.last().is_some_and(|p| *p >= x) {
                return Err(DecodeError::Unsorted("inline externals"));
            }
            extras.push(x);
        }
        r.finish()?;
        Ok(Descriptor {
            shape,
            group,
            own,
            env_read,
            env_values,
            externals,
            extras,
        })
    }

    /// The unit's observation set, externals and env (section 1.5 step 8):
    /// the group's entries and the own ones, the externals from the bitmap
    /// and the inline extras, the env names from the bitmap with
    /// [`ABSENT_HASH`] unless a value is listed. Fails on an index past the
    /// shape or tables, a group the shape lacks, an own entry the group has,
    /// or an inline external the tables have.
    pub fn resolve(&self, shape: &Shape, tables: &Tables) -> Result<ResolvedManifest, DecodeError> {
        let group: &[usize] = match self.group {
            None => &[],
            Some(g) => shape.groups.get(g as usize).ok_or(DecodeError::Group(g))?,
        };
        let table = |what, i: usize, n: usize| {
            if i >= n {
                return Err(DecodeError::Index {
                    what,
                    index: i as u64,
                    len: n,
                });
            }
            Ok(i)
        };
        // The union of two sorted index lists, which must not meet.
        let mut set = Vec::with_capacity(group.len() + self.own.len());
        let (mut a, mut b) = (0, 0);
        while a < group.len() || b < self.own.len() {
            let (what, i) = match (group.get(a), self.own.get(b)) {
                (Some(&g), Some(&o)) if g == o => return Err(DecodeError::Overlap(o)),
                (Some(&g), Some(&o)) if g > o => {
                    b += 1;
                    ("own entry", o)
                }
                (Some(&g), _) => {
                    a += 1;
                    ("group entry", g)
                }
                (None, Some(&o)) => {
                    b += 1;
                    ("own entry", o)
                }
                (None, None) => break,
            };
            set.push(shape.entries[table(what, i, shape.entries.len())?].clone());
        }
        let mut env = Vec::with_capacity(self.env_read.len());
        let mut values = self.env_values.iter().peekable();
        for &i in &self.env_read {
            let key = tables.env_names[table("env name", i, tables.env_names.len())?].clone();
            let hash = match values.peek() {
                Some((vi, h)) if *vi == i => {
                    values.next();
                    hex32(h)
                }
                _ => ABSENT_HASH.to_owned(),
            };
            env.push(EnvEntry { key, hash });
        }
        if values.next().is_some() {
            return Err(DecodeError::EnvOverride("the name's bitmap bit is clear"));
        }
        let mut externals: Vec<External> =
            Vec::with_capacity(self.externals.len() + self.extras.len());
        for &i in &self.externals {
            externals.push(tables.externals[table("external", i, tables.externals.len())?].clone());
        }
        externals.extend(self.extras.iter().cloned());
        externals.sort();
        if let Some(w) = externals.windows(2).find(|w| w[0] == w[1]) {
            return Err(DecodeError::Extra(format!(
                "{} {}",
                w[0].name, w[0].version
            )));
        }
        Ok(ResolvedManifest {
            set,
            externals,
            env,
        })
    }
}

/// A descriptor resolved against its shape and tables: today's
/// [`InputManifest`] minus the attested sizes and hashes of the entries.
/// The plan observes every entry of `set` at HEAD and requires the root of
/// the observed entries with these externals and env to equal the signed
/// input root.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvedManifest {
    /// Sorted and distinct.
    pub set: Vec<ShapeEntry>,
    /// Sorted and distinct.
    pub externals: Vec<External>,
    /// Sorted by key; [`ABSENT_HASH`] for a name that was unset.
    pub env: Vec<EnvEntry>,
}

impl ResolvedManifest {
    /// The shape of a manifest as a descriptor resolves to it: what a
    /// round trip through [`Run::build`] must give back.
    pub fn of(m: &InputManifest) -> Self {
        let set: BTreeSet<ShapeEntry> = m.entries.iter().map(ShapeEntry::of).collect();
        let externals: BTreeSet<External> = m.externals.iter().cloned().collect();
        let env: BTreeSet<EnvEntry> = m.env.iter().cloned().collect();
        ResolvedManifest {
            set: set.into_iter().collect(),
            externals: externals.into_iter().collect(),
            env: env.into_iter().collect(),
        }
    }
}

// ---------------------------------------------------------------- the run builder

/// An object encoded for the store: the value, its bytes and their id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded<T> {
    pub value: T,
    pub bytes: Vec<u8>,
    pub id: ObjectId,
}

impl<T> Encoded<T> {
    pub fn new(value: T, bytes: Vec<u8>) -> Self {
        let id = object_id(&bytes);
        Encoded { value, bytes, id }
    }
}

/// One unit of a run, as `vci run` knows it after the tests (section 1.4
/// steps 1-3): the input to [`Run::build`].
#[derive(Debug, Clone, Copy)]
pub struct UnitInputs<'a> {
    /// The header group the unit belongs to (step 1: units with the same
    /// header tuple, so the same hdr), as an index the caller assigns, dense
    /// from 0; one tables object is built per header group.
    pub header: usize,
    /// The shared-base group of the unit (`shared_manifest_bases`' key),
    /// whose units' common entries become a group of the shape; `None` for a
    /// unit in no group.
    pub group: Option<&'a str>,
    pub manifest: &'a InputManifest,
    /// The waived strings of the unit's predicate.
    pub waived: &'a [String],
}

/// What a unit's record carries of a built run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRecord {
    pub descriptor: Descriptor,
    /// The unit's `waived` ids into its tables' waiver table, sorted.
    pub waived: Vec<u16>,
}

/// The objects of one run (section 1.4 step 2) and every unit's descriptor
/// (step 3). The hdr per header group is the caller's ([`Hdr::encode`]): its
/// fields are the predicate's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub shape: Encoded<Shape>,
    /// Written unless `explain_hashes = false`.
    pub state: Encoded<State>,
    /// By header group index.
    pub tables: Vec<Encoded<Tables>>,
    /// In the order of the units given.
    pub units: Vec<UnitRecord>,
}

impl Run {
    /// Builds the shape over all units (its groups the intersection of the
    /// entries of each shared-base group with two or more units, in key
    /// order, the first [`MAX_GROUPS`] of them), the state over all entries,
    /// one tables object per header group, and each unit's descriptor, so
    /// that [`Descriptor::resolve`] gives back exactly the unit's manifest's
    /// `(path, kind, exec)` set, externals and env.
    pub fn build(units: &[UnitInputs<'_>]) -> Result<Run, EncodeError> {
        // The shape's entries and the state's.
        let shape_set: BTreeSet<ShapeEntry> = units
            .iter()
            .flat_map(|u| u.manifest.entries.iter().map(ShapeEntry::of))
            .collect();
        let entries: Vec<ShapeEntry> = shape_set.into_iter().collect();
        let state_set: BTreeSet<InputEntry> = units
            .iter()
            .flat_map(|u| u.manifest.entries.iter().cloned())
            .collect();
        let index_of = |e: &InputEntry| -> usize {
            entries
                .binary_search(&ShapeEntry::of(e))
                .expect("every entry is in the shape")
        };
        let unit_indices: Vec<BTreeSet<usize>> = units
            .iter()
            .map(|u| u.manifest.entries.iter().map(index_of).collect())
            .collect();

        // Groups: the intersection per shared-base key, at most 255.
        let mut by_key: BTreeMap<&str, (usize, BTreeSet<usize>)> = BTreeMap::new();
        for (u, mine) in units.iter().zip(&unit_indices) {
            let Some(key) = u.group else { continue };
            match by_key.get_mut(key) {
                None => {
                    by_key.insert(key, (1, mine.clone()));
                }
                Some((n, s)) => {
                    *n += 1;
                    *s = s.intersection(mine).copied().collect();
                }
            }
        }
        let mut groups: Vec<Vec<usize>> = Vec::new();
        let mut group_of: BTreeMap<&str, u8> = BTreeMap::new();
        for (key, (n, s)) in by_key {
            if n < 2 || s.is_empty() || groups.len() >= MAX_GROUPS {
                continue;
            }
            group_of.insert(key, groups.len() as u8);
            groups.push(s.into_iter().collect());
        }
        let shape = Shape { entries, groups };
        let shape = Encoded::new(shape.clone(), shape.encode()?);
        let state = State {
            entries: state_set.into_iter().collect(),
        };
        let state = Encoded::new(state.clone(), state.encode()?);

        // One tables object per header group.
        let headers = units.iter().map(|u| u.header + 1).max().unwrap_or(0);
        let mut tables = Vec::with_capacity(headers);
        for h in 0..headers {
            let mine = units.iter().filter(|u| u.header == h);
            if mine.clone().next().is_none() {
                return Err(EncodeError::Header(h));
            }
            let waivers: BTreeSet<String> = mine
                .clone()
                .flat_map(|u| u.waived.iter().cloned())
                .collect();
            if waivers.len() > usize::from(u16::MAX) + 1 {
                return Err(EncodeError::WaiverTable(waivers.len()));
            }
            let env_names: BTreeSet<String> = mine
                .clone()
                .flat_map(|u| u.manifest.env.iter().map(|e| e.key.clone()))
                .collect();
            let externals: BTreeSet<External> = mine
                .flat_map(|u| u.manifest.externals.iter().cloned())
                .collect();
            let t = Tables {
                waivers: waivers.into_iter().collect(),
                env_names: env_names.into_iter().collect(),
                externals: externals.into_iter().collect(),
            };
            tables.push(Encoded::new(t.clone(), t.encode()?));
        }

        // Each unit's descriptor and waived ids.
        let mut records = Vec::with_capacity(units.len());
        for (u, mine) in units.iter().zip(&unit_indices) {
            let t = &tables[u.header].value;
            let group = u.group.and_then(|k| group_of.get(k).copied());
            let own: Vec<usize> = match group {
                None => mine.iter().copied().collect(),
                Some(g) => {
                    let shared: BTreeSet<usize> =
                        shape.value.groups[g as usize].iter().copied().collect();
                    mine.difference(&shared).copied().collect()
                }
            };
            let lookup =
                |what: &'static str, list: &[String], s: &str| -> Result<usize, EncodeError> {
                    list.binary_search_by(|x| x.as_str().cmp(s))
                        .map_err(|_| EncodeError::Index {
                            what,
                            index: usize::MAX,
                            len: list.len(),
                        })
                };
            let mut env_read = BTreeSet::new();
            let mut env_values = BTreeMap::new();
            for e in &u.manifest.env {
                if !valid_env_key(&e.key) {
                    return Err(EncodeError::EnvKey(e.key.clone()));
                }
                let i = lookup("env name", &t.env_names, &e.key)?;
                env_read.insert(i);
                if e.hash != ABSENT_HASH {
                    let h = parse_hex32(&e.hash).ok_or_else(|| EncodeError::Hash {
                        path: format!("env:{}", e.key),
                        hash: e.hash.clone(),
                    })?;
                    env_values.insert(i, h);
                }
            }
            let externals: BTreeSet<usize> = u
                .manifest
                .externals
                .iter()
                .map(|x| {
                    t.externals
                        .binary_search(x)
                        .map_err(|_| EncodeError::Index {
                            what: "external",
                            index: usize::MAX,
                            len: t.externals.len(),
                        })
                })
                .collect::<Result<_, _>>()?;
            let waived: BTreeSet<u16> = u
                .waived
                .iter()
                .map(|w| lookup("waiver", &t.waivers, w).map(|i| i as u16))
                .collect::<Result<_, _>>()?;
            records.push(UnitRecord {
                descriptor: Descriptor {
                    shape: shape.id,
                    group,
                    own,
                    env_read: env_read.into_iter().collect(),
                    env_values: env_values.into_iter().collect(),
                    externals: externals.into_iter().collect(),
                    extras: Vec::new(),
                },
                waived: waived.into_iter().collect(),
            });
        }
        Ok(Run {
            shape,
            state,
            tables,
            units: records,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::dir_type_hash;

    fn rp(s: &str) -> RepoPath {
        RepoPath::new(s).unwrap()
    }

    fn h(seed: u8) -> String {
        hex32(&[seed; 32])
    }

    fn entry(path: &str, kind: EntryKind, exec: bool, size: u64, hash: &str) -> InputEntry {
        InputEntry {
            path: rp(path),
            kind,
            exec,
            size,
            hash: hash.to_owned(),
        }
    }

    fn file(path: &str, seed: u8) -> InputEntry {
        entry(path, EntryKind::File, false, u64::from(seed) * 10, &h(seed))
    }

    fn ext(name: &str, version: &str) -> External {
        External {
            name: name.into(),
            version: version.into(),
        }
    }

    fn env(key: &str, hash: &str) -> EnvEntry {
        EnvEntry {
            key: key.into(),
            hash: hash.into(),
        }
    }

    fn uv_bytes(n: u64) -> Vec<u8> {
        let mut v = Vec::new();
        put_uv(&mut v, n);
        v
    }

    fn read_uv(b: &[u8]) -> Result<u64, DecodeError> {
        let mut r = Reader::new(b);
        let v = r.uv("test")?;
        r.finish()?;
        Ok(v)
    }

    // ------------------------------------------------------------ ids

    #[test]
    fn object_id_is_blake3_and_hex_round_trips() {
        let id = object_id(b"");
        assert_eq!(
            hex32(&id),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(parse_hex32(&hex32(&id)), Some(id));
        assert_eq!(parse_hex32(ABSENT_HASH), Some([0u8; 32]));
        assert_eq!(
            parse_hex32(&"A".repeat(64)),
            None,
            "upper case is another spelling"
        );
        assert_eq!(parse_hex32(&"a".repeat(63)), None);
        assert_eq!(parse_hex32(&"g".repeat(64)), None);
    }

    // ------------------------------------------------------------ varints

    #[test]
    fn uv_round_trips_and_is_minimal() {
        for n in [
            0,
            1,
            127,
            128,
            255,
            300,
            16_383,
            16_384,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let b = uv_bytes(n);
            assert_eq!(read_uv(&b).unwrap(), n, "{n}");
            assert!(b.len() <= UV_MAX_BYTES);
            assert!(b.last().is_some_and(|l| *l != 0) || n == 0);
        }
        assert_eq!(uv_bytes(0), [0]);
        assert_eq!(uv_bytes(128), [0x80, 0x01]);
        assert_eq!(uv_bytes(u64::MAX).len(), 10);
    }

    #[test]
    fn uv_refuses_non_minimal_too_long_and_overflow() {
        assert_eq!(
            read_uv(&[0x80, 0x00]),
            Err(DecodeError::Varint("not minimal (a zero last byte)"))
        );
        assert_eq!(
            read_uv(&[0x81, 0x80, 0x00]),
            Err(DecodeError::Varint("not minimal (a zero last byte)"))
        );
        assert_eq!(
            read_uv(&[0x80; 11]),
            Err(DecodeError::Varint("longer than 10 bytes"))
        );
        let mut over = vec![0xff; 9];
        over.push(0x02);
        assert_eq!(read_uv(&over), Err(DecodeError::Varint("past u64::MAX")));
        assert_eq!(read_uv(&[0x80]), Err(DecodeError::Truncated("test")));
        assert_eq!(read_uv(&[]), Err(DecodeError::Truncated("test")));
        assert_eq!(read_uv(&[1, 2]), Err(DecodeError::Trailing(1)));
    }

    // ------------------------------------------------------------ strings and counts

    #[test]
    fn strings_round_trip_and_are_bounded_by_the_bytes_left() {
        let mut v = Vec::new();
        put_str(&mut v, "héllo");
        let mut r = Reader::new(&v);
        assert_eq!(r.str("s").unwrap(), "héllo");
        r.finish().unwrap();
        let mut r = Reader::new(&[5, b'a', b'b']);
        assert_eq!(
            r.str("s"),
            Err(DecodeError::Count {
                what: "s",
                count: 5,
                remaining: 2
            })
        );
        let mut r = Reader::new(&[2, 0xff, 0xfe]);
        assert_eq!(r.str("s"), Err(DecodeError::Utf8("s")));
    }

    #[test]
    fn a_count_is_checked_against_the_remaining_bytes_before_allocation() {
        let mut v = Vec::new();
        put_uv(&mut v, 1 << 40);
        v.extend_from_slice(&[0, 0, 0]);
        let mut r = Reader::new(&v);
        assert_eq!(
            r.count("entries", 4),
            Err(DecodeError::Count {
                what: "entries",
                count: 1 << 40,
                remaining: 3
            })
        );
        let mut r = Reader::new(&[2, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(r.count("entries", 4).unwrap(), 2);
        let mut r = Reader::new(&[3, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            r.count("entries", 4),
            Err(DecodeError::Count { .. })
        ));
    }

    // ------------------------------------------------------------ prefix coding

    fn coded(items: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        let mut pw = PrefixWriter::default();
        for s in items {
            pw.write(&mut v, s);
        }
        v
    }

    fn decoded(bytes: &[u8], n: usize) -> Result<Vec<String>, DecodeError> {
        let mut r = Reader::new(bytes);
        let mut pr = PrefixReader::default();
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(pr.read(&mut r, "p")?);
        }
        r.finish()?;
        Ok(out)
    }

    #[test]
    fn prefix_coding_round_trips_and_shares_the_longest_prefix() {
        let items = [
            "app/models/a.rb",
            "app/models/b.rb",
            "app/models/b.rb",
            "lib/x",
            "lib/x/y",
        ];
        let b = coded(&items);
        assert_eq!(decoded(&b, items.len()).unwrap(), items);
        // shared 0, 10, 15, 0, 5 ; suffix lens 15, 4, 0, 5, 2
        assert_eq!(b[0], 0);
        assert_eq!(b[1], 15);
        assert_eq!(b[17], 11);
        assert_eq!(b[18], 4);
        assert_eq!(&b[23..25], &[15, 0]);
        assert_eq!(&b[25..27], &[0, 5]);
        assert_eq!(&b[32..34], &[5, 2]);
        assert_eq!(b.len(), 36);
        // A multibyte character split by the shared prefix is fine.
        let items = ["caf\u{e9}", "caf\u{e8}"];
        assert_eq!(decoded(&coded(&items), 2).unwrap(), items);
    }

    #[test]
    fn prefix_coding_refuses_a_prefix_past_the_previous_item() {
        let mut b = coded(&["ab"]);
        b.extend_from_slice(&[3, 1, b'c']);
        assert_eq!(
            decoded(&b, 2),
            Err(DecodeError::Prefix(
                "shared prefix longer than the previous item"
            ))
        );
        assert_eq!(
            decoded(&[1, 1, b'a'], 1),
            Err(DecodeError::Prefix(
                "shared prefix longer than the previous item"
            ))
        );
    }

    #[test]
    fn prefix_coding_refuses_a_shorter_than_longest_prefix() {
        let mut b = coded(&["abc"]);
        b.extend_from_slice(&[1, 2, b'b', b'd']); // "abd" shares 2, not 1
        assert_eq!(
            decoded(&b, 2),
            Err(DecodeError::Prefix("shared prefix is not the longest"))
        );
        let mut b = coded(&["abc"]);
        b.extend_from_slice(&[2, 1, b'd']);
        assert_eq!(decoded(&b, 2).unwrap(), ["abc", "abd"]);
    }

    #[test]
    fn prefix_coding_refuses_invalid_utf8() {
        let mut b = coded(&["a"]);
        b.extend_from_slice(&[1, 1, 0xff]);
        assert_eq!(decoded(&b, 2), Err(DecodeError::Utf8("p")));
    }

    #[test]
    fn prefix_coded_paths_must_be_canonical_repo_paths() {
        for bad in ["a//b", "../x", "a/", "/a", "./a", "a\\b", ""] {
            let b = coded(&[bad]);
            let mut r = Reader::new(&b);
            let mut pr = PrefixReader::default();
            let e = pr.path(&mut r, "p").unwrap_err();
            assert!(matches!(e, DecodeError::Path(_)), "{bad:?}: {e}");
        }
        let b = coded(&["."]);
        let mut r = Reader::new(&b);
        assert!(PrefixReader::default().path(&mut r, "p").unwrap().is_root());
    }

    // ------------------------------------------------------------ kind bytes

    #[test]
    fn kind_bytes_follow_the_code_order_with_exec_in_bit_7() {
        let codes = ["f", "l", "a", "d", "t", "x", "m", "u"];
        for (i, k) in KIND_CODES.iter().enumerate() {
            assert_eq!(k.code(), codes[i]);
            assert_eq!(kind_byte(*k, false), i as u8);
            assert_eq!(parse_kind_byte(i as u8).unwrap(), (*k, false));
            assert_eq!(parse_kind_byte(i as u8 | 0x80).unwrap(), (*k, true));
        }
        assert_eq!(kind_byte(EntryKind::File, true), 0x80);
        assert_eq!(parse_kind_byte(8), Err(DecodeError::KindByte(8)));
        assert_eq!(parse_kind_byte(0x88), Err(DecodeError::KindByte(0x88)));
        assert_eq!(parse_kind_byte(0x7f), Err(DecodeError::KindByte(0x7f)));
        // The byte order of the kinds is the enum's, so sorted entries sort
        // the same whichever is compared.
        let mut ks = KIND_CODES;
        ks.sort();
        assert_eq!(ks, KIND_CODES);
    }

    // ------------------------------------------------------------ object headers

    #[test]
    fn object_header_is_checked() {
        let s = Shape::default().encode().unwrap();
        assert_eq!(&s[..4], b"vo\x03\x01");
        assert_eq!(Shape::decode(&s).unwrap(), Shape::default());
        assert_eq!(
            Tables::decode(&s),
            Err(DecodeError::Kind {
                expected: 2,
                found: 3
            })
        );
        assert_eq!(
            State::decode(&s),
            Err(DecodeError::Kind {
                expected: 4,
                found: 3
            })
        );
        assert_eq!(
            Hdr::decode(&s),
            Err(DecodeError::Kind {
                expected: 1,
                found: 3
            })
        );
        let mut m = s.clone();
        m[0] = b'x';
        assert_eq!(Shape::decode(&m), Err(DecodeError::Magic));
        let mut v = s.clone();
        v[3] = 2;
        assert_eq!(Shape::decode(&v), Err(DecodeError::Version(2)));
        let mut t = s.clone();
        t.push(0);
        assert_eq!(Shape::decode(&t), Err(DecodeError::Trailing(1)));
        assert_eq!(
            Shape::decode(&s[..3]),
            Err(DecodeError::Truncated("version"))
        );
        assert_eq!(Shape::decode(b""), Err(DecodeError::Truncated("magic")));
        assert_eq!(
            format!(
                "{}",
                DecodeError::Kind {
                    expected: 2,
                    found: 3
                }
            ),
            "object kind byte 3 where 2 (tables) was expected"
        );
    }

    #[test]
    fn object_bounds_are_enforced_before_decoding() {
        let big = vec![0u8; ObjectKind::Hdr.max_bytes() + 1];
        assert_eq!(
            Hdr::decode(&big),
            Err(DecodeError::TooLarge {
                what: "hdr",
                len: big.len(),
                max: 1 << 20
            })
        );
        let big = vec![0u8; ObjectKind::Tables.max_bytes() + 1];
        assert!(matches!(
            Tables::decode(&big),
            Err(DecodeError::TooLarge { what: "tables", .. })
        ));
        let big = vec![0u8; ObjectKind::Shape.max_bytes() + 1];
        assert!(matches!(
            Shape::decode(&big),
            Err(DecodeError::TooLarge { what: "shape", .. })
        ));
        let big = vec![0u8; ObjectKind::State.max_bytes() + 1];
        assert!(matches!(
            State::decode(&big),
            Err(DecodeError::TooLarge { what: "state", .. })
        ));
        let big = vec![0u8; DESCRIPTOR_MAX + 1];
        assert!(matches!(
            Descriptor::decode(&big, &Tables::default()),
            Err(DecodeError::TooLarge {
                what: "descriptor",
                ..
            })
        ));
        assert!(matches!(
            Descriptor::shape_id(&big),
            Err(DecodeError::TooLarge {
                what: "descriptor",
                ..
            })
        ));
        assert_eq!(ObjectKind::Hdr.max_bytes(), 1 << 20);
        assert_eq!(ObjectKind::Tables.max_bytes(), 4 << 20);
        assert_eq!(ObjectKind::Shape.max_bytes(), 8 << 20);
        assert_eq!(ObjectKind::State.max_bytes(), 16 << 20);
        // The encoder refuses to make one over the bound as well.
        let state = State {
            entries: (0..500_000)
                .map(|i| file(&format!("f/{i:06}"), (i % 251) as u8))
                .collect(),
        };
        assert!(matches!(
            state.encode(),
            Err(EncodeError::TooLarge { what: "state", .. })
        ));
    }

    #[test]
    fn a_huge_count_in_an_object_is_refused_before_allocation() {
        let mut b = b"vo\x03\x01".to_vec();
        put_uv(&mut b, 1 << 40);
        b.extend_from_slice(&[0, 1, b'a', 0]);
        assert!(matches!(
            Shape::decode(&b),
            Err(DecodeError::Count { what: "shape entries", count, .. }) if count == 1 << 40
        ));
        let mut b = b"vo\x04\x01".to_vec();
        put_uv(&mut b, u64::MAX / 2);
        assert!(matches!(State::decode(&b), Err(DecodeError::Count { .. })));
        let mut b = b"vo\x02\x01".to_vec();
        put_uv(&mut b, 1 << 30);
        assert!(matches!(Tables::decode(&b), Err(DecodeError::Count { .. })));
        let mut d = [7u8; 32].to_vec();
        d.push(NO_GROUP);
        put_uv(&mut d, 1 << 30);
        assert!(matches!(
            Descriptor::decode(&d, &Tables::default()),
            Err(DecodeError::Count {
                what: "own entry",
                ..
            })
        ));
    }

    // ------------------------------------------------------------ hdr

    fn sample_hdr() -> Hdr {
        Hdr {
            repo_id: "github.com/vexscm/vex".into(),
            adapter: "rails".into(),
            project_name: "vex-api".into(),
            project_dir: "apps/api".into(),
            runner_project: String::new(),
            tool_version: "2.9.0".into(),
            rails_inputs: "loose".into(),
            env_config_digest: [1; 32],
            global_input_root: [2; 32],
            global_manifest: vec![
                entry("Gemfile", EntryKind::File, false, 100, &h(3)),
                entry("Gemfile.lock", EntryKind::File, true, 2000, &h(4)),
                entry("config/boot.rb", EntryKind::Absent, false, 0, ABSENT_HASH),
                entry("target", EntryKind::Excluded, false, 0, &excluded_hash()),
                entry("vendor", EntryKind::Dir, false, 0, &dir_type_hash()),
            ],
            ignored_inputs: vec!["log/**".into(), "tmp/**".into()],
            env_set: vec!["TZ".into(), "LANG".into()],
            toolchain: Toolchain {
                ruby: "3.4.9p82".into(),
                ruby_engine: "ruby 3.4.9".into(),
                rails: "8.1.3.1".into(),
                bundler: "4.0.9".into(),
                ruby_test: "minitest 6.0.6".into(),
                ruby_libs: "sqlite=3.53.2;yaml=0.2.5".into(),
                ruby_db: "sqlite3".into(),
                ruby_gems: vec!["nokogiri==1.19.4".into(), "rack==3.2.7".into()],
                rust_cfg: vec!["target_os=\"macos\"".into(), "unix".into()],
                superuser: true,
                os: "linux".into(),
                arch: "x86_64".into(),
                ..Default::default()
            },
        }
    }

    #[test]
    fn hdr_round_trips_and_is_content_addressed() {
        let hdr = sample_hdr();
        let b = hdr.encode().unwrap();
        assert_eq!(&b[..4], b"vo\x01\x01");
        let back = Hdr::decode(&b).unwrap();
        assert_eq!(back, hdr);
        assert_eq!(back.encode().unwrap(), b);
        assert_eq!(object_id(&b), object_id(&hdr.clone().encode().unwrap()));
        let mut other = hdr.clone();
        other.toolchain.ruby_gems.push("zeitwerk==2.7.0".into());
        assert_ne!(object_id(&other.encode().unwrap()), object_id(&b));
        assert_eq!(back.global_manifest().entries, hdr.global_manifest);
        // The constant hashes come back although they were not stored.
        assert_eq!(back.global_manifest[2].hash, ABSENT_HASH);
        assert_eq!(back.global_manifest[3].hash, excluded_hash());
        // Five global entries and a Rails toolchain: well under a kilobyte
        // (the real Rails hdr is 4.5 KB for 25 entries and 300 gems).
        assert!(b.len() < 1024, "{}", b.len());
    }

    #[test]
    fn hdr_toolchain_json_must_be_canonical_and_lists_sorted() {
        let hdr = sample_hdr();
        let b = hdr.encode().unwrap();
        let json = toolchain_scalars_json(&hdr.toolchain).unwrap();
        assert!(
            json.starts_with("{\"arch\":\"x86_64\",\"bundler\""),
            "{json}"
        );
        assert!(!json.contains("rubyGems"));
        // The encoded string (length and bytes) replaced by another.
        let replace_str = |old: &str, new: &str| -> Vec<u8> {
            let mut o = Vec::new();
            put_str(&mut o, old);
            let at = b.windows(o.len()).position(|w| w == o).unwrap();
            let mut out = b[..at].to_vec();
            put_str(&mut out, new);
            out.extend_from_slice(&b[at + o.len()..]);
            out
        };
        assert_eq!(Hdr::decode(&replace_str(&json, &json)).unwrap(), hdr);
        // The same scalars with a space after a colon: another spelling.
        let spaced = replace_str(&json, &json.replacen(":", ": ", 1));
        assert!(matches!(
            Hdr::decode(&spaced),
            Err(DecodeError::Toolchain(_))
        ));
        // A list inside the JSON instead of after it.
        let listed = replace_str(&json, &json.replacen("{", "{\"rubyGems\":[\"a==1\"],", 1));
        assert!(matches!(
            Hdr::decode(&listed),
            Err(DecodeError::Toolchain(_))
        ));
        // An unknown field.
        let extra = replace_str(&json, &json.replacen("{", "{\"zzz\":1,", 1));
        assert!(matches!(
            Hdr::decode(&extra),
            Err(DecodeError::Toolchain(_))
        ));
        // Not JSON at all.
        let bad = replace_str(&json, "nope");
        assert!(matches!(Hdr::decode(&bad), Err(DecodeError::Toolchain(_))));
        // Unsorted lists are refused by the encoder and the decoder.
        let mut unsorted = hdr.clone();
        unsorted.toolchain.ruby_gems.reverse();
        assert_eq!(
            unsorted.encode(),
            Err(EncodeError::Unsorted("toolchain rubyGems"))
        );
        let mut dup = hdr.clone();
        dup.toolchain.rust_cfg.push("unix".into());
        assert_eq!(
            dup.encode(),
            Err(EncodeError::Unsorted("toolchain rustCfg"))
        );
        let mut e = b.clone();
        let gems = coded(&["nokogiri==1.19.4", "rack==3.2.7"]);
        let at = e.windows(gems.len()).position(|w| w == gems).unwrap();
        let swapped = coded(&["rack==3.2.7", "nokogiri==1.19.4"]);
        e.splice(at..at + gems.len(), swapped);
        assert_eq!(
            Hdr::decode(&e),
            Err(DecodeError::Unsorted("toolchain rubyGems"))
        );
    }

    #[test]
    fn hdr_global_manifest_rules() {
        let mut hdr = sample_hdr();
        hdr.global_manifest.swap(0, 1);
        assert_eq!(
            hdr.encode(),
            Err(EncodeError::Unsorted("global manifest entries"))
        );
        let mut hdr = sample_hdr();
        hdr.global_manifest[0].hash = "zz".into();
        assert!(matches!(hdr.encode(), Err(EncodeError::Hash { .. })));
        let mut hdr = sample_hdr();
        hdr.global_manifest[2].hash = h(9); // an absent entry with a hash
        assert!(matches!(hdr.encode(), Err(EncodeError::Hash { .. })));
        // In bytes: the same entry twice is not strictly increasing.
        let mut hdr = sample_hdr();
        hdr.global_manifest = vec![
            entry("a", EntryKind::File, false, 1, &h(1)),
            entry("a", EntryKind::File, false, 1, &h(1)),
        ];
        let mut out = start(ObjectKind::Hdr, 64);
        for _ in 0..7 {
            put_str(&mut out, "");
        }
        out.extend_from_slice(&[0; 64]);
        put_uv(&mut out, 2);
        let mut pw = PrefixWriter::default();
        for e in &hdr.global_manifest {
            pw.write(&mut out, e.path.as_str());
            out.push(0);
            put_uv(&mut out, 1);
            out.extend_from_slice(&[1; 32]);
        }
        assert_eq!(
            Hdr::decode(&out),
            Err(DecodeError::Unsorted("global manifest entries"))
        );
    }

    // ------------------------------------------------------------ tables

    fn sample_tables() -> Tables {
        Tables {
            waivers: vec![
                "cargo:undeclared-reads: x".into(),
                "env:enumerated: y".into(),
            ],
            env_names: vec!["HOME".into(), "LANG".into(), "TZ".into()],
            externals: vec![
                ext("rack", "3.2.7"),
                ext("rack", "3.2.8"),
                ext("rails", "8.1.3"),
            ],
        }
    }

    #[test]
    fn tables_round_trip() {
        let t = sample_tables();
        let b = t.encode().unwrap();
        assert_eq!(&b[..4], b"vo\x02\x01");
        assert_eq!(Tables::decode(&b).unwrap(), t);
        let empty = Tables::default();
        assert_eq!(Tables::decode(&empty.encode().unwrap()).unwrap(), empty);
    }

    #[test]
    fn tables_lists_must_be_sorted_distinct_and_env_keys_valid() {
        let mut t = sample_tables();
        t.waivers.reverse();
        assert_eq!(t.encode(), Err(EncodeError::Unsorted("waiver table")));
        let mut t = sample_tables();
        t.env_names.push("A".into());
        assert_eq!(t.encode(), Err(EncodeError::Unsorted("env names")));
        let mut t = sample_tables();
        t.externals.push(ext("rack", "3.2.7"));
        assert_eq!(t.encode(), Err(EncodeError::Unsorted("externals table")));
        let mut t = sample_tables();
        t.env_names = vec!["A=B".into()];
        assert_eq!(t.encode(), Err(EncodeError::EnvKey("A=B".into())));

        // The same, in bytes.
        let mut b = start(ObjectKind::Tables, 64);
        put_uv(&mut b, 2);
        put_str(&mut b, "b");
        put_str(&mut b, "a");
        assert_eq!(
            Tables::decode(&b),
            Err(DecodeError::Unsorted("waiver table"))
        );
        let mut b = start(ObjectKind::Tables, 64);
        put_uv(&mut b, 0);
        put_uv(&mut b, 2);
        b.extend_from_slice(&coded(&["TZ", "TZ"]));
        assert_eq!(Tables::decode(&b), Err(DecodeError::Unsorted("env names")));
        let mut b = start(ObjectKind::Tables, 64);
        put_uv(&mut b, 0);
        put_uv(&mut b, 1);
        b.extend_from_slice(&coded(&["A=B"]));
        put_uv(&mut b, 0);
        assert_eq!(Tables::decode(&b), Err(DecodeError::EnvKey("A=B".into())));
        let mut b = start(ObjectKind::Tables, 64);
        put_uv(&mut b, 0);
        put_uv(&mut b, 0);
        put_uv(&mut b, 2);
        let mut pw = PrefixWriter::default();
        pw.write(&mut b, "rack");
        put_str(&mut b, "2");
        pw.write(&mut b, "rack");
        put_str(&mut b, "1");
        assert_eq!(
            Tables::decode(&b),
            Err(DecodeError::Unsorted("externals table"))
        );
    }

    // ------------------------------------------------------------ shape

    fn se(path: &str, kind: EntryKind, exec: bool) -> ShapeEntry {
        ShapeEntry {
            path: rp(path),
            kind,
            exec,
        }
    }

    fn sample_shape() -> Shape {
        Shape {
            entries: vec![
                se(".vci-autoload/foo", EntryKind::AutoloadMiss, false),
                se("app/.vci-autoload", EntryKind::AutoloadDir, false),
                se("app/a.rb", EntryKind::File, false),
                se("app/a.rb", EntryKind::File, true),
                se("app/b.rb", EntryKind::Absent, false),
                se("bin", EntryKind::DirListing, false),
                se("bin/run", EntryKind::Symlink, false),
                se("lib", EntryKind::Dir, false),
                se("target", EntryKind::Excluded, false),
            ],
            groups: vec![vec![2, 5, 7], vec![0, 1], vec![8]],
        }
    }

    #[test]
    fn shape_round_trips() {
        let s = sample_shape();
        let b = s.encode().unwrap();
        assert_eq!(Shape::decode(&b).unwrap(), s);
        // Every kind and the exec bit survive.
        let back = Shape::decode(&b).unwrap();
        assert!(back.entries[3].exec);
        assert_eq!(back.entries[6].kind, EntryKind::Symlink);
        // The group lists are delta-coded: [2, 5, 7] is 3, 2, 2, 1.
        let tail = &b[b.len() - 10..];
        assert_eq!(tail, &[3, 3, 2, 2, 1, 2, 0, 0, 1, 8]);
    }

    #[test]
    fn shape_entries_must_be_strictly_increasing() {
        let mut s = sample_shape();
        s.entries.swap(2, 3);
        assert_eq!(s.encode(), Err(EncodeError::Unsorted("shape entries")));
        let mut b = start(ObjectKind::Shape, 64);
        put_uv(&mut b, 2);
        let mut pw = PrefixWriter::default();
        pw.write(&mut b, "a");
        b.push(0);
        pw.write(&mut b, "a");
        b.push(0);
        put_uv(&mut b, 0);
        assert_eq!(
            Shape::decode(&b),
            Err(DecodeError::Unsorted("shape entries"))
        );
        let mut b = start(ObjectKind::Shape, 64);
        put_uv(&mut b, 2);
        let mut pw = PrefixWriter::default();
        pw.write(&mut b, "a");
        b.push(0x80);
        pw.write(&mut b, "a");
        b.push(0);
        put_uv(&mut b, 0);
        assert_eq!(
            Shape::decode(&b),
            Err(DecodeError::Unsorted("shape entries"))
        );
    }

    #[test]
    fn shape_refuses_a_bad_kind_byte_and_a_bad_autoload_miss() {
        let mut b = start(ObjectKind::Shape, 64);
        put_uv(&mut b, 1);
        PrefixWriter::default().write(&mut b, "a");
        b.push(9);
        put_uv(&mut b, 0);
        assert_eq!(Shape::decode(&b), Err(DecodeError::KindByte(9)));
        for bad in [
            "foo",
            ".vci-autoload",
            ".vci-autoload/a/b",
            "x/.vci-autoload/a",
        ] {
            let mut b = start(ObjectKind::Shape, 64);
            put_uv(&mut b, 1);
            PrefixWriter::default().write(&mut b, bad);
            b.push(kind_byte(EntryKind::AutoloadMiss, false));
            put_uv(&mut b, 0);
            assert_eq!(
                Shape::decode(&b),
                Err(DecodeError::AutoloadMiss(bad.into()))
            );
        }
        let mut b = start(ObjectKind::Shape, 64);
        put_uv(&mut b, 1);
        PrefixWriter::default().write(&mut b, "a/../b");
        b.push(0);
        put_uv(&mut b, 0);
        assert!(matches!(Shape::decode(&b), Err(DecodeError::Path(_))));
    }

    #[test]
    fn shape_groups_are_bounded_in_count_and_range() {
        let mut s = sample_shape();
        s.groups = (0..256).map(|_| vec![0]).collect();
        assert_eq!(s.encode(), Err(EncodeError::TooManyGroups(256)));
        s.groups.pop();
        assert_eq!(
            Shape::decode(&s.encode().unwrap()).unwrap().groups.len(),
            255
        );
        let mut s = sample_shape();
        s.groups = vec![vec![9]];
        assert_eq!(
            s.encode(),
            Err(EncodeError::Index {
                what: "group entry",
                index: 9,
                len: 9
            })
        );
        let mut s = sample_shape();
        s.groups = vec![vec![2, 1]];
        assert_eq!(s.encode(), Err(EncodeError::Unsorted("group indices")));

        let mut b = Shape {
            entries: sample_shape().entries,
            groups: vec![],
        }
        .encode()
        .unwrap();
        b.pop();
        put_uv(&mut b, 256);
        assert_eq!(Shape::decode(&b), Err(DecodeError::TooManyGroups(256)));
        let mut b = Shape {
            entries: sample_shape().entries,
            groups: vec![],
        }
        .encode()
        .unwrap();
        b.pop();
        put_uv(&mut b, 1);
        put_indices(&mut b, &[8, 9]);
        assert_eq!(
            Shape::decode(&b),
            Err(DecodeError::Index {
                what: "group entry",
                index: 9,
                len: 9
            })
        );
    }

    #[test]
    fn delta_coded_indices_are_absolute_first_then_previous_plus_one_plus_delta() {
        let mut b = Vec::new();
        put_indices(&mut b, &[0, 1, 2, 10]);
        assert_eq!(b, [4, 0, 0, 0, 7]);
        let mut b = Vec::new();
        put_indices(&mut b, &[5]);
        assert_eq!(b, [1, 5]);
        let mut r = Reader::new(&[4, 0, 0, 0, 7]);
        assert_eq!(read_indices(&mut r, "i", 11).unwrap(), [0, 1, 2, 10]);
        let mut r = Reader::new(&[4, 0, 0, 0, 7]);
        assert_eq!(
            read_indices(&mut r, "i", 10),
            Err(DecodeError::Index {
                what: "i",
                index: 10,
                len: 10
            })
        );
        // An index past u64::MAX by accumulation.
        let mut b = Vec::new();
        put_uv(&mut b, 2);
        put_uv(&mut b, u64::MAX - 2);
        put_uv(&mut b, 5);
        let mut r = Reader::new(&b);
        assert_eq!(
            read_indices(&mut r, "i", usize::MAX),
            Err(DecodeError::Varint("past u64::MAX"))
        );
    }

    // ------------------------------------------------------------ state

    fn sample_state() -> State {
        State {
            entries: vec![
                entry(
                    ".vci-autoload/foo",
                    EntryKind::AutoloadMiss,
                    false,
                    0,
                    ABSENT_HASH,
                ),
                entry(
                    "app/.vci-autoload",
                    EntryKind::AutoloadDir,
                    false,
                    0,
                    &autoload_dir_hash(),
                ),
                file("app/a.rb", 1),
                file("app/a.rb", 2), // written during the run: two values
                entry("app/a.rb", EntryKind::File, true, 10, &h(1)),
                entry("app/b.rb", EntryKind::Absent, false, 0, ABSENT_HASH),
                entry("bin", EntryKind::DirListing, false, 3, &h(5)),
                entry("bin/run", EntryKind::Symlink, false, 6, &h(6)),
                entry("lib", EntryKind::Dir, false, 0, &dir_type_hash()),
                entry("target", EntryKind::Excluded, false, 0, &excluded_hash()),
            ],
        }
    }

    #[test]
    fn state_round_trips_with_duplicates_and_constant_hashes() {
        let s = sample_state();
        let b = s.encode().unwrap();
        assert_eq!(&b[..4], b"vo\x04\x01");
        let back = State::decode(&b).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.lookup(&rp("app/a.rb")).len(), 3);
        assert_eq!(back.lookup(&rp("app/b.rb"))[0].hash, ABSENT_HASH);
        assert!(back.lookup(&rp("nope")).is_empty());
        assert!(back.lookup(&rp("app")).is_empty());
        // Constant-hash kinds carry no hash: 33 bytes fewer than a file.
        let one = |e: InputEntry| State { entries: vec![e] }.encode().unwrap().len();
        assert_eq!(
            one(entry("x", EntryKind::Absent, false, 0, ABSENT_HASH)) + 32,
            one(entry("x", EntryKind::File, false, 0, &h(1)))
        );
    }

    #[test]
    fn state_entries_must_be_sorted_distinct_with_their_kinds_hash() {
        let mut s = sample_state();
        s.entries.swap(2, 3);
        assert_eq!(s.encode(), Err(EncodeError::Unsorted("state entries")));
        let mut s = sample_state();
        s.entries.push(s.entries[9].clone());
        assert_eq!(s.encode(), Err(EncodeError::Unsorted("state entries")));
        let mut s = sample_state();
        s.entries[9].hash = h(1); // an excluded entry with a real hash
        assert!(matches!(s.encode(), Err(EncodeError::Hash { .. })));
        let mut s = sample_state();
        s.entries[2].hash = "0x".repeat(32);
        assert!(matches!(s.encode(), Err(EncodeError::Hash { .. })));
        let mut b = start(ObjectKind::State, 64);
        put_uv(&mut b, 2);
        let mut pw = PrefixWriter::default();
        for seed in [2u8, 1] {
            pw.write(&mut b, "a");
            b.push(0);
            put_uv(&mut b, 1);
            b.extend_from_slice(&[seed; 32]);
        }
        assert_eq!(
            State::decode(&b),
            Err(DecodeError::Unsorted("state entries"))
        );
        let mut b = start(ObjectKind::State, 64);
        put_uv(&mut b, 1);
        PrefixWriter::default().write(&mut b, "a");
        b.push(0);
        put_uv(&mut b, 1);
        b.extend_from_slice(&[1; 31]);
        assert_eq!(
            State::decode(&b),
            Err(DecodeError::Truncated("state entries"))
        );
    }

    // ------------------------------------------------------------ descriptor

    fn sample_descriptor() -> Descriptor {
        Descriptor {
            shape: [9; 32],
            group: Some(0),
            own: vec![3, 4, 6],
            env_read: vec![0, 2],
            env_values: vec![(2, [5; 32])],
            externals: vec![0, 2],
            extras: vec![ext("zlib", "1.3")],
        }
    }

    #[test]
    fn descriptor_round_trips_and_resolves() {
        let t = sample_tables();
        let d = sample_descriptor();
        let b = d.encode(&t).unwrap();
        assert_eq!(Descriptor::shape_id(&b).unwrap(), [9; 32]);
        assert_eq!(Descriptor::decode(&b, &t).unwrap(), d);
        // 32 id, group, [3, 3, 0, 1], [1, 2, hash], bitmap 0b101, bitmap 0b101, extras.
        assert_eq!(b[32], 0);
        assert_eq!(&b[33..37], &[3, 3, 0, 1]);
        assert_eq!(&b[37..39], &[1, 2]);
        assert_eq!(b[71], 0b101);
        assert_eq!(b[72], 0b101);
        assert_eq!(b[73], 1);
        let r = d.resolve(&sample_shape(), &t).unwrap();
        let s = sample_shape();
        assert_eq!(
            r.set,
            vec![
                s.entries[2].clone(),
                s.entries[3].clone(),
                s.entries[4].clone(),
                s.entries[5].clone(),
                s.entries[6].clone(),
                s.entries[7].clone(),
            ]
        );
        assert_eq!(
            r.env,
            vec![env("HOME", ABSENT_HASH), env("TZ", &hex32(&[5; 32]))]
        );
        assert_eq!(
            r.externals,
            vec![
                ext("rack", "3.2.7"),
                ext("rails", "8.1.3"),
                ext("zlib", "1.3")
            ]
        );
        // No group, nothing read.
        let d = Descriptor {
            shape: [9; 32],
            ..Default::default()
        };
        let b = d.encode(&t).unwrap();
        assert_eq!(b.len(), 32 + 1 + 1 + 1 + 1 + 1 + 1);
        assert_eq!(b[32], NO_GROUP);
        assert_eq!(Descriptor::decode(&b, &t).unwrap(), d);
        assert_eq!(
            d.resolve(&sample_shape(), &t).unwrap(),
            ResolvedManifest::default()
        );
    }

    #[test]
    fn descriptor_env_override_rules() {
        let t = sample_tables();
        let mut d = sample_descriptor();
        d.env_values = vec![(1, [5; 32])]; // bit 1 is clear
        let b = d.encode(&t).unwrap();
        assert_eq!(
            Descriptor::decode(&b, &t),
            Err(DecodeError::EnvOverride("the name's bitmap bit is clear"))
        );
        let mut d = sample_descriptor();
        d.env_values = vec![(2, [0; 32])];
        let b = d.encode(&t).unwrap();
        assert_eq!(
            Descriptor::decode(&b, &t),
            Err(DecodeError::EnvOverride("ABSENT_HASH listed as a value"))
        );
        let mut d = sample_descriptor();
        d.env_values = vec![(2, [5; 32]), (2, [6; 32])];
        assert_eq!(d.encode(&t), Err(EncodeError::Unsorted("env overrides")));
        let mut d = sample_descriptor();
        d.env_read = vec![0, 1, 2];
        d.env_values = vec![(2, [5; 32]), (0, [6; 32])];
        assert_eq!(d.encode(&t), Err(EncodeError::Unsorted("env overrides")));
        // The same in bytes: two overrides for index 2, and index 0 after 2.
        let good = sample_descriptor().encode(&t).unwrap();
        let mut b = good[..37].to_vec();
        put_uv(&mut b, 2);
        put_uv(&mut b, 2);
        b.extend_from_slice(&[5; 32]);
        put_uv(&mut b, 2);
        b.extend_from_slice(&[6; 32]);
        b.extend_from_slice(&good[70..]);
        assert_eq!(
            Descriptor::decode(&b, &t),
            Err(DecodeError::EnvOverride("indices not strictly increasing"))
        );
        let mut b = good[..37].to_vec();
        put_uv(&mut b, 1);
        put_uv(&mut b, 3); // past the three env names
        b.extend_from_slice(&[5; 32]);
        b.extend_from_slice(&good[70..]);
        assert_eq!(
            Descriptor::decode(&b, &t),
            Err(DecodeError::Index {
                what: "env override",
                index: 3,
                len: 3
            })
        );
        let mut d = sample_descriptor();
        d.env_values = vec![(3, [5; 32])];
        assert!(matches!(d.encode(&t), Err(EncodeError::Index { .. })));
    }

    #[test]
    fn descriptor_bitmaps_are_sized_by_the_tables_and_padded_with_zeros() {
        let t = sample_tables();
        let good = sample_descriptor().encode(&t).unwrap();
        let mut b = good.clone();
        b[71] |= 0b1000; // a fourth env name the table lacks
        assert_eq!(
            Descriptor::decode(&b, &t),
            Err(DecodeError::Bitmap("env names"))
        );
        let mut b = good.clone();
        b[72] |= 0x80;
        assert_eq!(
            Descriptor::decode(&b, &t),
            Err(DecodeError::Bitmap("externals"))
        );
        // Nine names take two bytes.
        let mut wide = t.clone();
        wide.env_names = (0..9).map(|i| format!("E{i}")).collect();
        let d = Descriptor {
            shape: [1; 32],
            env_read: vec![0, 8],
            ..Default::default()
        };
        let b = d.encode(&wide).unwrap();
        assert_eq!(&b[35..37], &[0b1, 0b1]);
        assert_eq!(Descriptor::decode(&b, &wide).unwrap(), d);
        // Decoded against other tables, the bytes do not fit.
        assert!(Descriptor::decode(&b, &t).is_err());
        let mut d = sample_descriptor();
        d.env_read = vec![0, 3];
        assert!(matches!(
            d.encode(&t),
            Err(EncodeError::Index { what: "bitmap", .. })
        ));
    }

    #[test]
    fn descriptor_inline_externals_rules() {
        let t = sample_tables();
        let mut d = sample_descriptor();
        d.extras = vec![ext("zlib", "1.3"), ext("abc", "1")];
        assert_eq!(d.encode(&t), Err(EncodeError::Unsorted("inline externals")));
        let good = sample_descriptor().encode(&t).unwrap();
        let mut b = good[..73].to_vec();
        put_uv(&mut b, 2);
        for (n, v) in [("zlib", "1.3"), ("zlib", "1.3")] {
            put_str(&mut b, n);
            put_str(&mut b, v);
        }
        assert_eq!(
            Descriptor::decode(&b, &t),
            Err(DecodeError::Unsorted("inline externals"))
        );
        // An extra the table holds is the bitmap's job.
        let mut d = sample_descriptor();
        d.extras = vec![ext("rails", "8.1.3")];
        let d = Descriptor::decode(&d.encode(&t).unwrap(), &t).unwrap();
        assert_eq!(
            d.resolve(&sample_shape(), &t),
            Err(DecodeError::Extra("rails 8.1.3".into()))
        );
        let mut b = good.clone();
        b.push(0);
        assert_eq!(Descriptor::decode(&b, &t), Err(DecodeError::Trailing(1)));
        assert_eq!(
            Descriptor::decode(&good[..36], &t),
            Err(DecodeError::Count {
                what: "own entry",
                count: 3,
                remaining: 2
            })
        );
        assert_eq!(
            Descriptor::decode(&good[..32], &t),
            Err(DecodeError::Truncated("group"))
        );
        assert_eq!(
            Descriptor::shape_id(&good[..31]),
            Err(DecodeError::Truncated("shape id"))
        );
    }

    #[test]
    fn descriptor_resolve_checks_the_shape() {
        let t = sample_tables();
        let s = sample_shape();
        let mut d = sample_descriptor();
        d.group = Some(3);
        assert_eq!(d.resolve(&s, &t), Err(DecodeError::Group(3)));
        let mut d = sample_descriptor();
        d.own = vec![3, 4, 6, 9];
        assert_eq!(
            d.resolve(&s, &t),
            Err(DecodeError::Index {
                what: "own entry",
                index: 9,
                len: 9
            })
        );
        let mut d = sample_descriptor();
        d.own = vec![2, 3]; // 2 is in group 0
        assert_eq!(d.resolve(&s, &t), Err(DecodeError::Overlap(2)));
        // A shape with a group past the entries.
        let mut bad = s.clone();
        bad.groups[0] = vec![2, 5, 7, 42];
        assert_eq!(
            sample_descriptor().resolve(&bad, &t),
            Err(DecodeError::Index {
                what: "group entry",
                index: 42,
                len: 9
            })
        );
        // Another tables object (shorter) than the one decoded against.
        let mut short = t.clone();
        short.env_names.pop();
        short.externals.pop();
        assert_eq!(
            sample_descriptor().resolve(&s, &short),
            Err(DecodeError::Index {
                what: "env name",
                index: 2,
                len: 2
            })
        );
        let mut d = sample_descriptor();
        d.env_read = vec![0];
        d.env_values = vec![];
        assert_eq!(
            d.resolve(&s, &short),
            Err(DecodeError::Index {
                what: "external",
                index: 2,
                len: 2
            })
        );
        // A relabelled kind in the shape resolves to another set (the root
        // then differs: the store cannot choose what is observed).
        let mut relabelled = s.clone();
        relabelled.entries[3].kind = EntryKind::Symlink;
        relabelled.entries[3].exec = false;
        let a = sample_descriptor().resolve(&s, &t).unwrap();
        let b = sample_descriptor().resolve(&relabelled, &t).unwrap();
        assert_ne!(a.set, b.set);
    }

    // ------------------------------------------------------------ the run builder

    fn manifest(
        entries: Vec<InputEntry>,
        externals: Vec<External>,
        env: Vec<EnvEntry>,
    ) -> InputManifest {
        InputManifest {
            entries,
            externals,
            env,
        }
    }

    fn check_round_trip(units: &[UnitInputs<'_>], run: &Run) {
        let shape = Shape::decode(&run.shape.bytes).unwrap();
        assert_eq!(shape, run.shape.value);
        assert_eq!(object_id(&run.shape.bytes), run.shape.id);
        let state = State::decode(&run.state.bytes).unwrap();
        assert_eq!(state, run.state.value);
        let tables: Vec<Tables> = run
            .tables
            .iter()
            .map(|t| {
                assert_eq!(object_id(&t.bytes), t.id);
                let d = Tables::decode(&t.bytes).unwrap();
                assert_eq!(d, t.value);
                d
            })
            .collect();
        for (u, rec) in units.iter().zip(&run.units) {
            let t = &tables[u.header];
            let bytes = rec.descriptor.encode(t).unwrap();
            assert_eq!(Descriptor::shape_id(&bytes).unwrap(), run.shape.id);
            let d = Descriptor::decode(&bytes, t).unwrap();
            assert_eq!(d, rec.descriptor);
            let resolved = d.resolve(&shape, t).unwrap();
            assert_eq!(resolved, ResolvedManifest::of(u.manifest));
            for e in &u.manifest.entries {
                assert!(state.lookup(&e.path).contains(e), "{e:?}");
            }
            let waived: Vec<&str> = rec
                .waived
                .iter()
                .map(|i| t.waivers[*i as usize].as_str())
                .collect();
            let mut expected: Vec<&str> = u.waived.iter().map(String::as_str).collect();
            expected.sort_unstable();
            expected.dedup();
            assert_eq!(waived, expected);
        }
    }

    #[test]
    fn run_round_trips_every_kind_groups_duplicates_and_a_node_unit() {
        // Rails-like units sharing a group: a.rb is the same everywhere,
        // b.rb was rewritten between unit 1 and unit 2 (two values).
        let shared = vec![
            entry(
                ".vci-autoload/htmlparser",
                EntryKind::AutoloadMiss,
                false,
                0,
                ABSENT_HASH,
            ),
            entry(
                "app/.vci-autoload",
                EntryKind::AutoloadDir,
                false,
                0,
                &autoload_dir_hash(),
            ),
            file("app/a.rb", 1),
            entry("bin", EntryKind::DirListing, false, 2, &h(7)),
            entry("bin/run", EntryKind::Symlink, false, 5, &h(8)),
            entry("bin/x", EntryKind::File, true, 9, &h(9)),
            entry("config/x.yml", EntryKind::Absent, false, 0, ABSENT_HASH),
            entry("lib", EntryKind::Dir, false, 0, &dir_type_hash()),
            entry("tmp", EntryKind::Excluded, false, 0, &excluded_hash()),
        ];
        let mut e1 = shared.clone();
        e1.push(file("app/b.rb", 2));
        e1.push(file("test/one_test.rb", 11));
        e1.sort();
        let mut e2 = shared.clone();
        e2.push(file("app/b.rb", 3));
        e2.push(file("test/two_test.rb", 12));
        e2.sort();
        let mut e3 = shared.clone();
        e3.push(file("test/three_test.rb", 13));
        e3.sort();
        let m1 = manifest(
            e1,
            vec![ext("rails", "8.1"), ext("rack", "3.2")],
            vec![
                env("TZ", &h(20)),
                env("HOME", ABSENT_HASH),
                env("LANG", &h(21)),
            ],
        );
        let m2 = manifest(
            e2,
            vec![ext("rails", "8.1")],
            vec![env("TZ", &h(20)), env("RAILS_ENV", &h(22))],
        );
        let m3 = manifest(e3, vec![], vec![]);
        // A unit of a group with one member: no group.
        let m4 = manifest(
            vec![file("only.rb", 30)],
            vec![ext("ms", "2")],
            vec![env("CI", &h(1))],
        );
        // A unit in no group at all, with nothing.
        let m5 = manifest(vec![file("solo.rb", 31)], vec![], vec![]);
        // A node-style unit with 700+ own entries in another header group,
        // with an env name of the Rails group too (tables are per header).
        let mut node_entries: Vec<InputEntry> = (0..760)
            .map(|i| {
                file(
                    &format!("node_modules/pkg{}/lib/index{}.js", i % 37, i),
                    (i % 250) as u8,
                )
            })
            .collect();
        node_entries.push(file("app/a.rb", 1)); // the same entry as the Rails units'
        node_entries.sort();
        node_entries.dedup();
        let m6 = manifest(
            node_entries,
            (0..40)
                .map(|i| ext(&format!("@scope/pkg{i}"), "1.0.0"))
                .collect(),
            vec![env("TZ", &h(20)), env("NODE_OPTIONS", ABSENT_HASH)],
        );
        let w_a = vec![
            "env:enumerated: b".to_owned(),
            "cargo:x: a".to_owned(),
            "env:enumerated: b".to_owned(),
        ];
        let w_b = vec!["env:enumerated: b".to_owned()];
        let none: Vec<String> = vec![];
        let units = [
            UnitInputs {
                header: 0,
                group: Some("slot-1"),
                manifest: &m1,
                waived: &w_a,
            },
            UnitInputs {
                header: 0,
                group: Some("slot-1"),
                manifest: &m2,
                waived: &w_b,
            },
            UnitInputs {
                header: 0,
                group: Some("slot-1"),
                manifest: &m3,
                waived: &none,
            },
            UnitInputs {
                header: 0,
                group: Some("lonely"),
                manifest: &m4,
                waived: &none,
            },
            UnitInputs {
                header: 0,
                group: None,
                manifest: &m5,
                waived: &none,
            },
            UnitInputs {
                header: 1,
                group: Some("node"),
                manifest: &m6,
                waived: &none,
            },
        ];
        let run = Run::build(&units).unwrap();
        check_round_trip(&units, &run);

        // One group: the shared entries of slot-1 (b.rb is in two of the
        // three units only, so it is each one's own).
        assert_eq!(run.shape.value.groups.len(), 1);
        assert_eq!(run.shape.value.groups[0].len(), shared.len());
        assert_eq!(run.units[0].descriptor.group, Some(0));
        assert_eq!(run.units[0].descriptor.own.len(), 2);
        assert_eq!(run.units[1].descriptor.own.len(), 2);
        assert_eq!(run.units[2].descriptor.own.len(), 1);
        // b.rb's two values are one shape entry, two state entries.
        assert_eq!(
            run.shape
                .value
                .entries
                .iter()
                .filter(|e| e.path.as_str() == "app/b.rb")
                .count(),
            1
        );
        assert_eq!(run.units[3].descriptor.group, None);
        assert_eq!(run.units[4].descriptor.group, None);
        assert_eq!(run.units[5].descriptor.group, None);
        assert_eq!(run.units[5].descriptor.own.len(), 761);
        // Two values of app/b.rb in the state, every kind present once.
        assert_eq!(run.state.value.lookup(&rp("app/b.rb")).len(), 2);
        let kinds: BTreeSet<EntryKind> = run.state.value.entries.iter().map(|e| e.kind).collect();
        assert_eq!(kinds.len(), 8);
        assert!(run.shape.value.entries.iter().any(|e| e.exec));
        // Two tables: the Rails group's unions, the node group's.
        assert_eq!(run.tables.len(), 2);
        let t0 = &run.tables[0].value;
        assert_eq!(t0.waivers, ["cargo:x: a", "env:enumerated: b"]);
        assert_eq!(t0.env_names, ["CI", "HOME", "LANG", "RAILS_ENV", "TZ"]);
        assert_eq!(
            t0.externals,
            [ext("ms", "2"), ext("rack", "3.2"), ext("rails", "8.1")]
        );
        assert_eq!(run.units[0].waived, [0, 1]);
        assert_eq!(run.units[1].waived, [1]);
        assert_eq!(run.tables[1].value.env_names, ["NODE_OPTIONS", "TZ"]);
        assert_eq!(run.tables[1].value.externals.len(), 40);
        // Sizes in the design's range: a descriptor of a Rails-like unit is
        // small, the node unit's is under 1 KB.
        let d0 = run.units[0].descriptor.encode(t0).unwrap();
        assert!(d0.len() < 120, "{}", d0.len());
        let d5 = run.units[5]
            .descriptor
            .encode(&run.tables[1].value)
            .unwrap();
        assert!(d5.len() < 1000, "{}", d5.len());
    }

    #[test]
    fn run_build_refuses_an_unused_header_and_a_bad_env_value() {
        let m = manifest(vec![file("a", 1)], vec![], vec![env("K", "nothex")]);
        let none: Vec<String> = vec![];
        let u = [UnitInputs {
            header: 1,
            group: None,
            manifest: &m,
            waived: &none,
        }];
        assert_eq!(Run::build(&u), Err(EncodeError::Header(0)));
        let u = [UnitInputs {
            header: 0,
            group: None,
            manifest: &m,
            waived: &none,
        }];
        assert!(matches!(Run::build(&u), Err(EncodeError::Hash { .. })));
        let m = manifest(vec![file("a", 1)], vec![], vec![env("A=B", &h(1))]);
        let u = [UnitInputs {
            header: 0,
            group: None,
            manifest: &m,
            waived: &none,
        }];
        assert_eq!(Run::build(&u), Err(EncodeError::EnvKey("A=B".into())));
        let m = manifest(vec![file("a", 1)], vec![], vec![env("A", &h(1))]);
        let u = [UnitInputs {
            header: 0,
            group: None,
            manifest: &m,
            waived: &none,
        }];
        let run = Run::build(&u).unwrap();
        assert_eq!(run.units[0].descriptor.env_values, [(0, [1; 32])]);
    }

    #[test]
    fn run_build_keeps_at_most_255_groups() {
        let manifests: Vec<InputManifest> = (0..600)
            .map(|i| {
                manifest(
                    vec![
                        file(&format!("g{:03}", i / 2), 1),
                        file(&format!("u{i}"), 2),
                    ],
                    vec![],
                    vec![],
                )
            })
            .collect();
        let keys: Vec<String> = (0..600).map(|i| format!("k{:03}", i / 2)).collect();
        let none: Vec<String> = vec![];
        let units: Vec<UnitInputs<'_>> = manifests
            .iter()
            .zip(&keys)
            .map(|(m, k)| UnitInputs {
                header: 0,
                group: Some(k),
                manifest: m,
                waived: &none,
            })
            .collect();
        let run = Run::build(&units).unwrap();
        assert_eq!(run.shape.value.groups.len(), 255);
        assert_eq!(run.units[0].descriptor.group, Some(0));
        assert_eq!(run.units[0].descriptor.own.len(), 1);
        assert_eq!(run.units[599].descriptor.group, None);
        assert_eq!(run.units[599].descriptor.own.len(), 2);
        check_round_trip(&units, &run);
    }

    #[test]
    fn an_empty_run_builds() {
        let run = Run::build(&[]).unwrap();
        assert!(run.tables.is_empty() && run.units.is_empty());
        assert_eq!(Shape::decode(&run.shape.bytes).unwrap(), Shape::default());
        assert_eq!(State::decode(&run.state.bytes).unwrap(), State::default());
    }
}
