//! Input manifests: capture from the working tree, the input root, and
//! re-verification against a checkout.
//!
//! Safety rule: **fail open**. Anything unexpected during capture is an error
//! (the test is then not attestable and simply runs); anything that differs
//! during verification is a [`Mismatch`] or an error (the test runs).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::sync::{Arc, Mutex};

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::hash::{self, ABSENT_HASH, ChildType, Enc, INPUT_ROOT_DOMAIN, blake3_hex};
use crate::path::{PathError, RepoPath, strip_root};

/// Maximum symlink hops followed from one observed path.
pub const MAX_SYMLINK_HOPS: usize = 40;

/// `hash` of an [`EntryKind::Dir`] entry: BLAKE3 of the bytes `dir`.
pub fn dir_type_hash() -> String {
    blake3_hex(b"dir")
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub enum EntryKind {
    /// Regular file; `hash` is BLAKE3 of the contents, `size` the byte length.
    File,
    /// Symbolic link; `hash` is BLAKE3 of the link target string, `size` its
    /// byte length. The link's resolution is recorded as separate entries.
    Symlink,
    /// Nothing exists at the path; `hash` is [`ABSENT_HASH`], `size` 0.
    Absent,
    /// Directory; `hash` covers the sorted child names (and their types),
    /// `size` is the number of children.
    DirListing,
    /// A real directory (not a symlink) whose contents were not observed, only
    /// its type (e.g. a path component `realpath()` walked through); `hash` is
    /// [`dir_type_hash`], `size` 0.
    Dir,
    /// Build output or bookkeeping that is never an input (Cargo's target
    /// directory, vci's `.vci/out`, the repository's `.git`), recorded so
    /// that its name is left out of its parent directory's listing: a fresh
    /// checkout has no `target/`, and the listing must still match. Whether
    /// it exists is not compared; `hash` is [`excluded_hash`], `size` 0.
    Excluded,
    /// Rails, `policy.rails_autoload_lookups` (2.6.0): a constant name the
    /// test's process looked up without loading it (missed, or asked about
    /// with `const_defined?`). The path is `.vci-autoload/<name>` (the name
    /// normalized by [`autoload_name`]); what matters is which children of
    /// the manifest's autoload directories ([`EntryKind::AutoloadDir`])
    /// would define it: `hash` is [`ABSENT_HASH`] when none does, else the
    /// BLAKE3 of their paths; `size` is their number. A file added to an
    /// autoload directory defines a constant; it matters only when a lookup
    /// asked for that name.
    AutoloadMiss,
    /// Rails (2.6.0): a directory Zeitwerk listed only to define constants;
    /// the path is `<directory>/.vci-autoload`. Its listing is not an input
    /// (the [`EntryKind::AutoloadMiss`] entries are); `hash` is
    /// [`autoload_dir_hash`], `size` 0.
    AutoloadDir,
}

/// `hash` of an [`EntryKind::AutoloadDir`] entry: BLAKE3 of `autoload-dir`.
pub fn autoload_dir_hash() -> String {
    blake3_hex(b"autoload-dir")
}

/// The name an autoload directory's child defines, or a missed constant,
/// normalized so the two compare: a `.rb` suffix removed, ASCII lower case,
/// underscores removed (`html_parser.rb`, `HTMLParser` and `HtmlParser` are
/// all `htmlparser`). Two names that normalize alike count as the same,
/// which only ever runs a unit that need not have run.
pub fn autoload_name(s: &str) -> String {
    s.strip_suffix(".rb")
        .unwrap_or(s)
        .chars()
        .filter(|c| *c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Children of autoload directories by [`autoload_name`] (paths).
type AutoloadIndex = HashMap<String, Vec<String>>;

/// The directory component that marks an [`EntryKind::AutoloadMiss`] path.
pub const AUTOLOAD_MARK: &str = ".vci-autoload";

impl EntryKind {
    /// One-letter code of the compact manifest encoding
    /// ([`InputManifest::to_compact`]).
    pub fn code(self) -> &'static str {
        match self {
            EntryKind::File => "f",
            EntryKind::Symlink => "l",
            EntryKind::Absent => "a",
            EntryKind::DirListing => "d",
            EntryKind::Dir => "t",
            EntryKind::Excluded => "x",
            EntryKind::AutoloadMiss => "m",
            EntryKind::AutoloadDir => "u",
        }
    }

    /// The kind a [`EntryKind::code`] names.
    pub fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "f" => EntryKind::File,
            "l" => EntryKind::Symlink,
            "a" => EntryKind::Absent,
            "d" => EntryKind::DirListing,
            "t" => EntryKind::Dir,
            "x" => EntryKind::Excluded,
            "m" => EntryKind::AutoloadMiss,
            "u" => EntryKind::AutoloadDir,
            _ => return None,
        })
    }

    /// Tag used in the input root encoding (same spelling as the JSON form).
    pub fn tag(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Symlink => "symlink",
            EntryKind::Absent => "absent",
            EntryKind::DirListing => "dirListing",
            EntryKind::Dir => "dir",
            EntryKind::Excluded => "excluded",
            EntryKind::AutoloadMiss => "autoloadMiss",
            EntryKind::AutoloadDir => "autoloadDir",
        }
    }
}

/// `hash` of an [`EntryKind::Excluded`] entry: BLAKE3 of the bytes `excluded`.
pub fn excluded_hash() -> String {
    blake3_hex(b"excluded")
}

/// Child names left out of directory listings: parent path -> names, from
/// the [`EntryKind::Excluded`] entries (or [`Observation::Exclude`]
/// observations) of one manifest.
type Exclusions = BTreeMap<RepoPath, BTreeSet<String>>;

fn exclusions<'a>(paths: impl Iterator<Item = &'a RepoPath>) -> Exclusions {
    let mut out = Exclusions::new();
    for p in paths {
        if let (Some(parent), Some(name)) = (p.parent(), p.components().last()) {
            out.entry(parent).or_default().insert(name.to_owned());
        }
    }
    out
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct InputEntry {
    pub path: RepoPath,
    pub kind: EntryKind,
    /// Owner-executable bit (`mode & 0o100`), as git records it. Only
    /// meaningful for files; always false otherwise.
    pub exec: bool,
    pub size: u64,
    pub hash: String,
}

impl InputEntry {
    pub fn absent(path: RepoPath) -> Self {
        InputEntry {
            path,
            kind: EntryKind::Absent,
            exec: false,
            size: 0,
            hash: ABSENT_HASH.to_owned(),
        }
    }

    fn describe(&self) -> String {
        match self.kind {
            EntryKind::Absent => "absent".to_owned(),
            EntryKind::File => {
                format!(
                    "file exec={} size={} blake3={}",
                    self.exec, self.size, self.hash
                )
            }
            EntryKind::Symlink => format!("symlink size={} blake3={}", self.size, self.hash),
            EntryKind::DirListing => {
                format!("dirListing entries={} blake3={}", self.size, self.hash)
            }
            EntryKind::Dir => "directory".to_owned(),
            EntryKind::Excluded => "excluded (build output, not an input)".to_owned(),
            EntryKind::AutoloadDir => {
                "an autoload directory (its listing is not an input)".to_owned()
            }
            EntryKind::AutoloadMiss if self.size == 0 => {
                "no file or directory defines the constant".to_owned()
            }
            EntryKind::AutoloadMiss => format!(
                "{} file(s) or directories define the constant, blake3={}",
                self.size, self.hash
            ),
        }
    }

    fn excluded(path: RepoPath) -> Self {
        InputEntry {
            path,
            kind: EntryKind::Excluded,
            exec: false,
            size: 0,
            hash: excluded_hash(),
        }
    }

    fn same_state(&self, other: &InputEntry) -> bool {
        self.kind == other.kind
            && self.exec == other.exec
            && self.size == other.size
            && self.hash == other.hash
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct External {
    pub name: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct EnvEntry {
    pub key: String,
    /// BLAKE3 of the value's bytes; [`ABSENT_HASH`] if unset.
    pub hash: String,
}

/// What the collector saw a test do with a path.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub enum Observation {
    /// Successful read or stat. Must exist at capture time.
    Read,
    /// stat/exists/read that failed with ENOENT. Must be absent at capture time.
    Probe,
    /// Directory listing. Must be a directory at capture time.
    ReadDir,
    /// The path's type was observed, not its contents (`realpath()` walking a
    /// component). Must exist at capture time: a file is recorded like a
    /// `Read`, a directory as a type-only [`EntryKind::Dir`].
    Stat,
    /// Not an input (build output such as Cargo's target directory): recorded
    /// as [`EntryKind::Excluded`], whether it exists or not, and left out of
    /// its parent directory's listing.
    Exclude,
    /// Rails (2.6.0): a constant name looked up without loading it; the
    /// path is `.vci-autoload/<name>` ([`EntryKind::AutoloadMiss`]).
    AutoloadMiss,
    /// Rails (2.6.0): a directory Zeitwerk listed to define constants; the
    /// path is `<directory>/.vci-autoload` ([`EntryKind::AutoloadDir`]).
    AutoloadDir,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct InputManifest {
    pub entries: Vec<InputEntry>,
    pub externals: Vec<External>,
    pub env: Vec<EnvEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Mismatch {
    /// `entry:<repo path>` or `env:<KEY>`.
    pub what: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("{0} was read by the test but does not exist now")]
    ReadMissing(String),
    #[error("{0} was probed as absent by the test but exists now")]
    ProbeExists(String),
    #[error("{0} was listed as a directory by the test but is not a directory now")]
    NotADirectory(String),
    #[error("symlink {link} points outside the repository (target {target:?})")]
    SymlinkOutsideRepo { link: String, target: String },
    #[error(
        "symlink {link} target {target:?} cannot be resolved lexically (a '..' crosses a symlink or missing directory)"
    )]
    SymlinkUnresolvable { link: String, target: String },
    #[error("too many symlink hops starting at {0}")]
    SymlinkLoop(String),
    #[error("non-UTF-8 name under {0}")]
    NonUtf8Name(String),
    #[error("{0} is not a regular file, directory or symlink")]
    UnsupportedFileType(String),
    #[error("conflicting entries recorded for {0}")]
    ConflictingEntries(String),
    #[error("paths collide under case folding: {a:?} and {b:?}")]
    CaseCollision { a: String, b: String },
    #[error("invalid environment variable name {0:?}")]
    InvalidEnvKey(String),
    #[error("not a compact input manifest: {0}")]
    Compact(String),
    #[error(
        "compact input manifest lists its entries on top of base manifest {0}, which must be read first"
    )]
    NeedsBase(String),
    #[error("base input manifest {0} is not in the store")]
    MissingBase(String),
}

fn io_err(path: &Utf8Path, source: io::Error) -> ManifestError {
    ManifestError::Io {
        path: path.to_string(),
        source,
    }
}

fn is_absent_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// `lstat`, except that the repository root itself is always followed (the
/// caller chose it; it is never a recorded symlink).
fn lstat(abs: &Utf8Path, is_root: bool) -> io::Result<fs::Metadata> {
    if is_root {
        fs::metadata(abs)
    } else {
        fs::symlink_metadata(abs)
    }
}

#[cfg(unix)]
fn exec_bit(md: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o100 != 0
}

#[cfg(not(unix))]
fn exec_bit(_md: &fs::Metadata) -> bool {
    false
}

fn read_link_utf8(abs: &Utf8Path) -> Result<Utf8PathBuf, ManifestError> {
    let t = fs::read_link(abs).map_err(|e| io_err(abs, e))?;
    Utf8PathBuf::from_path_buf(t).map_err(|_| ManifestError::NonUtf8Name(abs.to_string()))
}

fn hash_file(abs: &Utf8Path) -> Result<(String, u64), ManifestError> {
    let mut f = fs::File::open(abs).map_err(|e| io_err(abs, e))?;
    let mut h = blake3::Hasher::new();
    let n = io::copy(&mut f, &mut h).map_err(|e| io_err(abs, e))?;
    Ok((h.finalize().to_hex().to_string(), n))
}

fn hash_dir(
    abs: &Utf8Path,
    skip: Option<&BTreeSet<String>>,
) -> Result<(String, u64), ManifestError> {
    let mut children = Vec::new();
    for ent in fs::read_dir(abs).map_err(|e| io_err(abs, e))? {
        let ent = ent.map_err(|e| io_err(abs, e))?;
        let name = ent
            .file_name()
            .into_string()
            .map_err(|_| ManifestError::NonUtf8Name(abs.to_string()))?;
        if skip.is_some_and(|s| s.contains(&name)) {
            continue;
        }
        let ft = ent.file_type().map_err(|e| io_err(abs, e))?;
        children.push((name, ChildType::from_file_type(ft)));
    }
    let n = children.len() as u64;
    Ok((hash::dir_listing_hash(&mut children), n))
}

/// Observe the current state of one path without following a final symlink.
/// With `dir_type_only`, a directory is recorded as a type-only
/// [`EntryKind::Dir`] instead of its listing.
fn observe_as(
    repo_root: &Utf8Path,
    path: &RepoPath,
    dir_type_only: bool,
    skip: Option<&BTreeSet<String>>,
) -> Result<InputEntry, ManifestError> {
    let abs = path.to_abs(repo_root);
    let md = match lstat(&abs, path.is_root()) {
        Ok(md) => md,
        Err(e) if is_absent_error(&e) => return Ok(InputEntry::absent(path.clone())),
        Err(e) => return Err(io_err(&abs, e)),
    };
    let ft = md.file_type();
    let (kind, exec, size, hash) = if ft.is_symlink() {
        let target = read_link_utf8(&abs)?;
        let t = target.as_str();
        (
            EntryKind::Symlink,
            false,
            t.len() as u64,
            blake3_hex(t.as_bytes()),
        )
    } else if ft.is_file() {
        let (h, n) = hash_file(&abs)?;
        (EntryKind::File, exec_bit(&md), n, h)
    } else if ft.is_dir() && dir_type_only {
        (EntryKind::Dir, false, 0, dir_type_hash())
    } else if ft.is_dir() {
        let (h, n) = hash_dir(&abs, skip)?;
        (EntryKind::DirListing, false, n, h)
    } else {
        return Err(ManifestError::UnsupportedFileType(path.to_string()));
    };
    Ok(InputEntry {
        path: path.clone(),
        kind,
        exec,
        size,
        hash,
    })
}

/// What `lstat` finds at a path, as [`resolve_chain`] follows it.
enum Link {
    Absent,
    Target(Utf8PathBuf),
    NotSymlink,
}

/// Where a capture or a diff observes paths: the checkout itself, or a
/// [`CheckoutCache`] of it. Both observe a path the same way.
#[derive(Clone, Copy)]
enum Source<'a> {
    Fs(&'a Utf8Path),
    Cache(&'a CheckoutCache),
}

impl Source<'_> {
    /// The child names of `dir` (none when it is not a directory; a marker
    /// when it is a symlink, so that its replacement shows).
    fn child_names(&self, dir: &RepoPath) -> Result<Vec<String>, ManifestError> {
        Ok(match self {
            Source::Fs(root) => {
                let abs = dir.to_abs(root);
                match fs::symlink_metadata(&abs) {
                    Ok(md) if md.file_type().is_dir() => {
                        let mut v = Vec::new();
                        for ent in fs::read_dir(&abs).map_err(|e| io_err(&abs, e))? {
                            let ent = ent.map_err(|e| io_err(&abs, e))?;
                            v.push(
                                ent.file_name()
                                    .into_string()
                                    .map_err(|_| ManifestError::NonUtf8Name(abs.to_string()))?,
                            );
                        }
                        v
                    }
                    Ok(md) if md.file_type().is_symlink() => {
                        vec![format!("{AUTOLOAD_MARK}:symlink")]
                    }
                    Ok(_) => Vec::new(),
                    Err(e) if is_absent_error(&e) => Vec::new(),
                    Err(e) => return Err(io_err(&abs, e)),
                }
            }
            Source::Cache(c) => match &*c.node(dir)? {
                Node::Dir(d) => c.children(dir, d)?.iter().map(|(n, _)| n.clone()).collect(),
                Node::Symlink { .. } => vec![format!("{AUTOLOAD_MARK}:symlink")],
                _ => Vec::new(),
            },
        })
    }

    /// The children of the autoload directories `dirs` (their marker
    /// paths, `<dir>/.vci-autoload`) by [`autoload_name`]: listed and
    /// normalized once per manifest, not once per name (2.6.4: once per
    /// name took 1,061 thread-seconds of a vex job).
    fn autoload_index(&self, dirs: &[RepoPath]) -> Result<AutoloadIndex, ManifestError> {
        let mut idx = AutoloadIndex::new();
        for marker in dirs {
            let dir = marker
                .parent()
                .ok_or_else(|| ManifestError::ConflictingEntries(marker.to_string()))?;
            for n in self.child_names(&dir)? {
                let key = if n.starts_with(AUTOLOAD_MARK) {
                    // A symlinked directory: every name matches it.
                    String::new()
                } else {
                    autoload_name(&n)
                };
                idx.entry(key)
                    .or_default()
                    .push(format!("{}/{n}", dir.as_str()));
            }
        }
        Ok(idx)
    }

    /// [`EntryKind::AutoloadMiss`] for `path` (`.vci-autoload/<name>`): the
    /// children of the autoload directories (`idx`, [`Source::autoload_index`])
    /// whose [`autoload_name`] is `<name>`.
    fn autoload_miss(
        &self,
        path: &RepoPath,
        idx: &AutoloadIndex,
    ) -> Result<InputEntry, ManifestError> {
        let comps: Vec<&str> = path.components().collect();
        if comps.len() != 2 || comps[0] != AUTOLOAD_MARK {
            return Err(ManifestError::ConflictingEntries(path.to_string()));
        }
        let mut hits: Vec<String> = idx
            .get(comps[1])
            .into_iter()
            .chain(idx.get(""))
            .flatten()
            .cloned()
            .collect();
        hits.sort();
        hits.dedup();
        let hash = if hits.is_empty() {
            ABSENT_HASH.to_owned()
        } else {
            blake3_hex(hits.join("\0").as_bytes())
        };
        Ok(InputEntry {
            path: path.clone(),
            kind: EntryKind::AutoloadMiss,
            exec: false,
            size: hits.len() as u64,
            hash,
        })
    }

    fn root(&self) -> &Utf8Path {
        match self {
            Source::Fs(root) => root,
            Source::Cache(c) => &c.root,
        }
    }

    fn link(&self, path: &RepoPath) -> Result<Link, ManifestError> {
        match self {
            Source::Fs(root) => {
                let abs = path.to_abs(root);
                let md = match lstat(&abs, path.is_root()) {
                    Ok(md) => md,
                    Err(e) if is_absent_error(&e) => return Ok(Link::Absent),
                    Err(e) => return Err(io_err(&abs, e)),
                };
                if md.file_type().is_symlink() {
                    Ok(Link::Target(read_link_utf8(&abs)?))
                } else {
                    Ok(Link::NotSymlink)
                }
            }
            Source::Cache(c) => Ok(match &*c.node(path)? {
                Node::Absent => Link::Absent,
                Node::Symlink { target, .. } => Link::Target(target.clone()),
                _ => Link::NotSymlink,
            }),
        }
    }

    fn observe(
        &self,
        path: &RepoPath,
        dir_type_only: bool,
        skip: Option<&BTreeSet<String>>,
    ) -> Result<InputEntry, ManifestError> {
        match self {
            Source::Fs(root) => observe_as(root, path, dir_type_only, skip),
            Source::Cache(c) => c.observe(path, dir_type_only, skip),
        }
    }
}

/// One observation of each path of a checkout, shared by every capture and
/// diff made through the cache ([`InputManifest::capture_cached`],
/// [`InputManifest::diff_against_cache`]): a path's type, a file's contents
/// hash, a symlink's target and a directory's children are read once, however
/// many manifests name the path, and a directory's listing hash is computed
/// once per set of children left out. Thread-safe (sharded locks; a path is
/// observed by one thread while the others wait for it).
///
/// Nothing invalidates it: it is for a checkout that does not change while
/// the cache is used (a plan verifying stored manifests, the inputs of a run
/// that has finished). An observation that fails (an I/O error, a non-UTF-8
/// name) is not kept, and is attempted again by the next caller, which then
/// fails as the uncached observation would.
pub struct CheckoutCache {
    root: Utf8PathBuf,
    hasher: std::hash::RandomState,
    shards: Vec<Mutex<HashMap<RepoPath, Arc<Slot>>>>,
}

const CACHE_SHARDS: usize = 64;

/// A path's observation, made once (`None` until then, or after a failure).
#[derive(Default)]
struct Slot(Mutex<Option<Arc<Node>>>);

/// What `lstat` found at a path (the repository root itself is followed),
/// with what [`observe_as`] reads of it.
enum Node {
    Absent,
    Symlink {
        target: Utf8PathBuf,
        hash: String,
    },
    File {
        exec: bool,
        size: u64,
        hash: String,
    },
    Dir(DirNode),
    /// Not a regular file, directory or symlink.
    Other,
}

#[derive(Default)]
struct DirNode {
    /// Every child (name, type), read on first use (a type-only observation
    /// does not list the directory). A child whose type could not be read
    /// keeps its error: it fails a listing that does not leave it out, as
    /// [`hash_dir`] does.
    #[allow(clippy::type_complexity)]
    children: Mutex<Option<Arc<Vec<(String, Result<ChildType, (io::ErrorKind, String)>)>>>>,
    /// Listing hash and size per set of children left out.
    listings: Mutex<HashMap<BTreeSet<String>, (String, u64)>>,
}

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl CheckoutCache {
    /// An empty cache of the checkout at `repo_root`.
    pub fn new(repo_root: &Utf8Path) -> Self {
        CheckoutCache {
            root: repo_root.to_owned(),
            hasher: std::hash::RandomState::new(),
            shards: (0..CACHE_SHARDS).map(|_| Mutex::default()).collect(),
        }
    }

    /// The repository root the cache observes.
    pub fn root(&self) -> &Utf8Path {
        &self.root
    }

    /// The names of `dir`'s children now, unsorted; empty when `dir` is not
    /// a directory (a symlink is not followed) or cannot be listed.
    pub fn child_names(&self, dir: &RepoPath) -> Vec<String> {
        let Ok(node) = self.node(dir) else {
            return vec![];
        };
        let Node::Dir(d) = &*node else {
            return vec![];
        };
        match self.children(dir, d) {
            Ok(c) => c.iter().map(|(n, _)| n.clone()).collect(),
            Err(_) => vec![],
        }
    }

    fn node(&self, path: &RepoPath) -> Result<Arc<Node>, ManifestError> {
        use std::hash::BuildHasher as _;
        let shard = &self.shards[self.hasher.hash_one(path) as usize % CACHE_SHARDS];
        let slot = {
            let mut m = locked(shard);
            match m.get(path) {
                Some(s) => s.clone(),
                None => m.entry(path.clone()).or_default().clone(),
            }
        };
        let mut g = locked(&slot.0);
        if let Some(n) = &*g {
            return Ok(n.clone());
        }
        let n = Arc::new(self.read_node(path)?);
        *g = Some(n.clone());
        Ok(n)
    }

    fn read_node(&self, path: &RepoPath) -> Result<Node, ManifestError> {
        let abs = path.to_abs(&self.root);
        let md = match lstat(&abs, path.is_root()) {
            Ok(md) => md,
            Err(e) if is_absent_error(&e) => return Ok(Node::Absent),
            Err(e) => return Err(io_err(&abs, e)),
        };
        let ft = md.file_type();
        Ok(if ft.is_symlink() {
            let target = read_link_utf8(&abs)?;
            let hash = blake3_hex(target.as_str().as_bytes());
            Node::Symlink { target, hash }
        } else if ft.is_file() {
            let (hash, size) = hash_file(&abs)?;
            Node::File {
                exec: exec_bit(&md),
                size,
                hash,
            }
        } else if ft.is_dir() {
            Node::Dir(DirNode::default())
        } else {
            Node::Other
        })
    }

    #[allow(clippy::type_complexity)]
    fn children(
        &self,
        path: &RepoPath,
        d: &DirNode,
    ) -> Result<Arc<Vec<(String, Result<ChildType, (io::ErrorKind, String)>)>>, ManifestError> {
        let mut g = locked(&d.children);
        if let Some(c) = &*g {
            return Ok(c.clone());
        }
        let abs = path.to_abs(&self.root);
        let mut children = Vec::new();
        for ent in fs::read_dir(&abs).map_err(|e| io_err(&abs, e))? {
            let ent = ent.map_err(|e| io_err(&abs, e))?;
            let name = ent
                .file_name()
                .into_string()
                .map_err(|_| ManifestError::NonUtf8Name(abs.to_string()))?;
            let ty = ent
                .file_type()
                .map(ChildType::from_file_type)
                .map_err(|e| (e.kind(), e.to_string()));
            children.push((name, ty));
        }
        let c = Arc::new(children);
        *g = Some(c.clone());
        Ok(c)
    }

    /// [`hash_dir`] of a directory, from its cached children.
    fn listing(
        &self,
        path: &RepoPath,
        d: &DirNode,
        skip: Option<&BTreeSet<String>>,
    ) -> Result<(String, u64), ManifestError> {
        static NONE: BTreeSet<String> = BTreeSet::new();
        let skip = skip.unwrap_or(&NONE);
        if let Some(l) = locked(&d.listings).get(skip) {
            return Ok(l.clone());
        }
        let children = self.children(path, d)?;
        let mut kept = Vec::with_capacity(children.len());
        for (name, ty) in children.iter() {
            if skip.contains(name) {
                continue;
            }
            match ty {
                Ok(t) => kept.push((name.clone(), *t)),
                Err((kind, msg)) => {
                    return Err(io_err(
                        &path.to_abs(&self.root),
                        io::Error::new(*kind, msg.clone()),
                    ));
                }
            }
        }
        let n = kept.len() as u64;
        let l = (hash::dir_listing_hash(&mut kept), n);
        locked(&d.listings).insert(skip.clone(), l.clone());
        Ok(l)
    }

    /// [`observe_as`], from the cache.
    fn observe(
        &self,
        path: &RepoPath,
        dir_type_only: bool,
        skip: Option<&BTreeSet<String>>,
    ) -> Result<InputEntry, ManifestError> {
        let node = self.node(path)?;
        let (kind, exec, size, hash) = match &*node {
            Node::Absent => return Ok(InputEntry::absent(path.clone())),
            Node::Symlink { target, hash } => (
                EntryKind::Symlink,
                false,
                target.as_str().len() as u64,
                hash.clone(),
            ),
            Node::File { exec, size, hash } => (EntryKind::File, *exec, *size, hash.clone()),
            Node::Dir(_) if dir_type_only => (EntryKind::Dir, false, 0, dir_type_hash()),
            Node::Dir(d) => {
                let (h, n) = self.listing(path, d, skip)?;
                (EntryKind::DirListing, false, n, h)
            }
            Node::Other => return Err(ManifestError::UnsupportedFileType(path.to_string())),
        };
        Ok(InputEntry {
            path: path.clone(),
            kind,
            exec,
            size,
            hash,
        })
    }
}

/// Resolve a symlink's target to the repo path the OS will follow next.
///
/// Relative targets are resolved lexically against the link's parent. A `..`
/// is only accepted when the component it cancels is an existing real
/// directory (not a symlink), which is exactly when lexical and physical
/// resolution agree. Absolute targets must be lexically inside the repo root
/// (as given or canonical).
fn resolve_link_target(
    repo_root: &Utf8Path,
    link: &RepoPath,
    target: &Utf8Path,
) -> Result<RepoPath, ManifestError> {
    let outside = || ManifestError::SymlinkOutsideRepo {
        link: link.to_string(),
        target: target.to_string(),
    };
    let unresolvable = || ManifestError::SymlinkUnresolvable {
        link: link.to_string(),
        target: target.to_string(),
    };
    if target.as_str().is_empty() {
        return Err(unresolvable());
    }
    if target.is_absolute() {
        return match strip_root(repo_root, target, false) {
            Ok(p) => Ok(p),
            Err(PathError::OutsideRepo { .. }) => Err(outside()),
            Err(_) => Err(unresolvable()),
        };
    }
    let mut parts: Vec<String> = link
        .parent()
        .map(|p| p.components().map(str::to_owned).collect())
        .unwrap_or_default();
    for c in target.components() {
        match c {
            Utf8Component::CurDir => {}
            Utf8Component::ParentDir => {
                if parts.is_empty() {
                    return Err(outside());
                }
                let cancelled = repo_root.join(parts.join("/"));
                match fs::symlink_metadata(&cancelled) {
                    Ok(md) if md.file_type().is_dir() => {}
                    _ => return Err(unresolvable()),
                }
                parts.pop();
            }
            Utf8Component::Normal(n) => parts.push(n.to_owned()),
            Utf8Component::RootDir | Utf8Component::Prefix(_) => return Err(unresolvable()),
        }
    }
    if parts.is_empty() {
        return Ok(RepoPath::root());
    }
    RepoPath::new(&parts.join("/")).map_err(|_| unresolvable())
}

/// Follow symlinks starting at `start`, pushing a `Symlink` entry for every
/// hop. Returns the first path that is not a symlink (possibly absent).
fn resolve_chain(
    src: Source<'_>,
    start: &RepoPath,
    out: &mut Vec<InputEntry>,
) -> Result<RepoPath, ManifestError> {
    let mut cur = start.clone();
    for _ in 0..MAX_SYMLINK_HOPS {
        let target = match src.link(&cur)? {
            Link::Absent | Link::NotSymlink => return Ok(cur),
            Link::Target(t) => t,
        };
        let next = resolve_link_target(src.root(), &cur, &target)?;
        out.push(InputEntry {
            path: cur.clone(),
            kind: EntryKind::Symlink,
            exec: false,
            size: target.as_str().len() as u64,
            hash: blake3_hex(target.as_str().as_bytes()),
        });
        cur = next;
    }
    Err(ManifestError::SymlinkLoop(start.to_string()))
}

fn capture_one(
    src: Source<'_>,
    path: &RepoPath,
    obs: Observation,
    excl: &Exclusions,
) -> Result<Vec<InputEntry>, ManifestError> {
    if obs == Observation::AutoloadDir {
        let bad = || ManifestError::ConflictingEntries(path.to_string());
        if path.components().last() != Some(AUTOLOAD_MARK) || path.parent().is_none() {
            return Err(bad());
        }
        return Ok(vec![InputEntry {
            path: path.clone(),
            kind: EntryKind::AutoloadDir,
            exec: false,
            size: 0,
            hash: autoload_dir_hash(),
        }]);
    }
    if obs == Observation::AutoloadMiss {
        // Captured once every autoload directory is known (capture_from).
        return Ok(vec![]);
    }
    if obs == Observation::Exclude {
        if path.is_root() {
            return Err(ManifestError::ConflictingEntries(path.to_string()));
        }
        return Ok(vec![InputEntry::excluded(path.clone())]);
    }
    let mut out = Vec::new();
    let fin = resolve_chain(src, path, &mut out)?;
    let e = src.observe(&fin, obs == Observation::Stat, excl.get(&fin))?;
    match (obs, e.kind) {
        (Observation::AutoloadMiss | Observation::AutoloadDir, _)
        | (_, EntryKind::AutoloadMiss | EntryKind::AutoloadDir) => {
            return Err(ManifestError::ConflictingEntries(fin.to_string()));
        }
        (Observation::Exclude, _) | (_, EntryKind::Excluded) => {
            return Err(ManifestError::ConflictingEntries(fin.to_string()));
        }
        (Observation::Read | Observation::ReadDir | Observation::Stat, EntryKind::Absent) => {
            return Err(ManifestError::ReadMissing(path.to_string()));
        }
        (Observation::Stat, EntryKind::File | EntryKind::Dir) => {}
        (Observation::Stat, _) => {
            return Err(ManifestError::ConflictingEntries(fin.to_string()));
        }
        (Observation::ReadDir, EntryKind::DirListing) => {}
        (Observation::ReadDir, _) => return Err(ManifestError::NotADirectory(path.to_string())),
        (Observation::Probe, EntryKind::Absent) => {}
        (Observation::Probe, _) => return Err(ManifestError::ProbeExists(path.to_string())),
        (Observation::Read, EntryKind::File | EntryKind::DirListing) => {}
        (Observation::Read, EntryKind::Symlink | EntryKind::Dir) => {
            // resolve_chain only stops on a symlink if it vanished and was
            // recreated underneath us.
            return Err(ManifestError::ConflictingEntries(fin.to_string()));
        }
    }
    out.push(e);
    Ok(out)
}

fn validate_env_key(k: &str) -> Result<(), ManifestError> {
    if k.is_empty() || k.contains('=') || k.contains('\0') {
        return Err(ManifestError::InvalidEnvKey(k.to_owned()));
    }
    Ok(())
}

/// Hash of an environment variable value; [`ABSENT_HASH`] if unset.
pub fn env_value_hash(value: Option<&std::ffi::OsStr>) -> String {
    match value {
        Some(v) => blake3_hex(v.as_encoded_bytes()),
        None => ABSENT_HASH.to_owned(),
    }
}

fn process_env(k: &str) -> Option<OsString> {
    std::env::var_os(k)
}

/// Case folding used for collision checks: full Unicode upper- then
/// lower-casing (so `ß` and `SS` also collide). Deliberately over-eager.
fn fold(s: &str) -> String {
    s.to_uppercase().to_lowercase()
}

impl InputManifest {
    /// Build from observations by hashing the working tree under `repo_root`,
    /// reading env values from the current process. Sorts and dedups.
    ///
    /// Per observation: symlinks along the path are followed hop by hop, each
    /// hop recorded as a `Symlink` entry, and the final target recorded as its
    /// own entry (error if any hop leaves the repo). `Read` must find a file
    /// or directory (a directory is recorded as a `DirListing`), `ReadDir` a
    /// directory, and `Probe` nothing. Any other state is an error.
    ///
    /// Does not check case collisions; call [`Self::check_case_collisions`].
    pub fn capture(
        repo_root: &Utf8Path,
        observed: &[(RepoPath, Observation)],
        externals: Vec<External>,
        env_keys: &[String],
    ) -> Result<Self, ManifestError> {
        Self::capture_with_env(repo_root, observed, externals, env_keys, process_env)
    }

    /// [`Self::capture`] with an explicit environment lookup.
    pub fn capture_with_env<F>(
        repo_root: &Utf8Path,
        observed: &[(RepoPath, Observation)],
        externals: Vec<External>,
        env_keys: &[String],
        env: F,
    ) -> Result<Self, ManifestError>
    where
        F: Fn(&str) -> Option<OsString> + Sync,
    {
        Self::capture_from(Source::Fs(repo_root), observed, externals, env_keys, env)
    }

    /// [`Self::capture_with_env`] observing the checkout through `cache`
    /// (its root is the repository root): a path another capture or diff
    /// through the same cache observed is not read again.
    pub fn capture_cached<F>(
        cache: &CheckoutCache,
        observed: &[(RepoPath, Observation)],
        externals: Vec<External>,
        env_keys: &[String],
        env: F,
    ) -> Result<Self, ManifestError>
    where
        F: Fn(&str) -> Option<OsString> + Sync,
    {
        Self::capture_from(Source::Cache(cache), observed, externals, env_keys, env)
    }

    fn capture_from<F>(
        src: Source<'_>,
        observed: &[(RepoPath, Observation)],
        mut externals: Vec<External>,
        env_keys: &[String],
        env: F,
    ) -> Result<Self, ManifestError>
    where
        F: Fn(&str) -> Option<OsString> + Sync,
    {
        let excl = exclusions(
            observed
                .iter()
                .filter(|(_, o)| *o == Observation::Exclude)
                .map(|(p, _)| p),
        );
        let per_obs: Vec<Vec<InputEntry>> = observed
            .par_iter()
            .map(|(p, o)| capture_one(src, p, *o, &excl))
            .collect::<Result<_, _>>()?;
        let mut entries: Vec<InputEntry> = per_obs.into_iter().flatten().collect();
        let dirs: Vec<RepoPath> = entries
            .iter()
            .filter(|e| e.kind == EntryKind::AutoloadDir)
            .map(|e| e.path.clone())
            .collect();
        if !dirs.is_empty() {
            let idx = src.autoload_index(&dirs)?;
            for (p, o) in observed {
                if *o == Observation::AutoloadMiss {
                    entries.push(src.autoload_miss(p, &idx)?);
                }
            }
        }
        // A type-only `Dir` is implied by a listing of the same directory.
        let listed: BTreeSet<RepoPath> = entries
            .iter()
            .filter(|e| e.kind == EntryKind::DirListing)
            .map(|e| e.path.clone())
            .collect();
        entries.retain(|e| e.kind != EntryKind::Dir || !listed.contains(&e.path));
        entries.sort();
        entries.dedup();
        for w in entries.windows(2) {
            if w[0].path == w[1].path {
                return Err(ManifestError::ConflictingEntries(w[0].path.to_string()));
            }
        }

        externals.sort();
        externals.dedup();

        let mut keys: Vec<&str> = env_keys.iter().map(String::as_str).collect();
        keys.sort_unstable();
        keys.dedup();
        let mut envs = Vec::with_capacity(keys.len());
        for k in keys {
            validate_env_key(k)?;
            envs.push(EnvEntry {
                key: k.to_owned(),
                hash: env_value_hash(env(k).as_deref()),
            });
        }

        Ok(InputManifest {
            entries,
            externals,
            env: envs,
        })
    }

    /// Deterministic BLAKE3 input root, lowercase hex.
    ///
    /// Encoding (see [`crate::hash`] for field encoding): domain tag
    /// `vci/input-root/v1`; `"entries"`, count, then per entry in sorted
    /// order: path, kind tag, exec (u64 0/1), size (u64), hash;
    /// `"externals"`, count, then name, version per external in sorted order;
    /// `"env"`, count, then key, hash per entry in sorted order.
    ///
    /// The result does not depend on the order of the vectors.
    pub fn root(&self) -> String {
        let mut entries: Vec<&InputEntry> = self.entries.iter().collect();
        entries.sort();
        let mut externals: Vec<&External> = self.externals.iter().collect();
        externals.sort();
        let mut env: Vec<&EnvEntry> = self.env.iter().collect();
        env.sort();

        let mut e = Enc::new(INPUT_ROOT_DOMAIN);
        e.str("entries").u64(entries.len() as u64);
        for x in entries {
            e.str(x.path.as_str())
                .str(x.kind.tag())
                .u64(x.exec as u64)
                .u64(x.size)
                .str(&x.hash);
        }
        e.str("externals").u64(externals.len() as u64);
        for x in externals {
            e.str(&x.name).str(&x.version);
        }
        e.str("env").u64(env.len() as u64);
        for x in env {
            e.str(&x.key).str(&x.hash);
        }
        e.finish()
    }

    /// The compact encoding a manifest is stored in on its own (since vci
    /// 1.9.0 an attestation references its manifest by input root instead of
    /// embedding it). One JSON document, version 2:
    ///
    /// ```text
    /// {"v":2,"entries":[[path,kind,size,hash,exec?],...],
    ///  "externals":[[name,version],...],"env":[[key,hash|null],...]}
    /// ```
    ///
    /// `kind` is [`EntryKind::code`] (`f` file, `l` symlink, `a` absent,
    /// `d` dirListing, `t` dir, `x` excluded), `hash` lowercase hex as
    /// recorded, `exec` present (as `1`) only when true, and an env hash
    /// `null` when the variable was unset ([`ABSENT_HASH`]). The vectors keep
    /// their order. The bytes carry no trust: [`Self::root`] of the decoded
    /// manifest must equal the signed input root, and it hashes the entries,
    /// not this encoding.
    pub fn to_compact(&self) -> String {
        self.compact_with(None)
    }

    /// [`Self::to_compact`] on top of a base manifest (since vci 2.1.8): a
    /// `"base"` member names the base's root, and only the entries the
    /// base does not have are listed (`"entries"`); externals and env are
    /// always this manifest's own. The base must have every one of its
    /// entries in this manifest (as the entries a run's units share do),
    /// else the plain encoding is written. Decoding
    /// ([`Self::from_compact_with`]) puts the base's entries back, so the
    /// decoded manifest and its root are exactly this one's. A base is
    /// itself a plain manifest (no base of its own), stored under its own
    /// root like any other.
    pub fn to_compact_on(&self, base: &InputManifest) -> String {
        let mine: HashSet<&InputEntry> = self.entries.iter().collect();
        if base.entries.is_empty()
            || !base.entries.iter().all(|e| mine.contains(e))
            || base.has_base_marker()
            || base.root() == self.root()
        {
            // Nothing to share, or the base is this manifest itself (it
            // would name its own root).
            return self.compact_with(None);
        }
        let shared: HashSet<&InputEntry> = base.entries.iter().collect();
        self.compact_with(Some((&base.root(), &shared)))
    }

    /// Whether this manifest, encoded plainly, could stand as a base: it
    /// never is one with externals or env (those are a unit's own).
    fn has_base_marker(&self) -> bool {
        !self.externals.is_empty() || !self.env.is_empty()
    }

    /// The root of the base manifest a compact encoding lists its entries on
    /// top of, if any, without decoding the rest.
    pub fn compact_base(bytes: &[u8]) -> Result<Option<String>, ManifestError> {
        #[derive(Deserialize)]
        struct Head {
            v: u32,
            #[serde(default)]
            base: Option<String>,
        }
        let h: Head =
            serde_json::from_slice(bytes).map_err(|e| ManifestError::Compact(e.to_string()))?;
        if h.v != 2 {
            return Err(ManifestError::Compact(format!(
                "version {} (expected 2)",
                h.v
            )));
        }
        Ok(h.base)
    }

    fn compact_with(&self, base: Option<(&str, &HashSet<&InputEntry>)>) -> String {
        fn s(out: &mut String, v: &str) {
            // Serializing a str cannot fail.
            out.push_str(&serde_json::to_string(v).unwrap_or_default());
        }
        let mut out = String::with_capacity(64 + self.entries.len() * 120);
        out.push_str("{\"v\":2,");
        if let Some((root, _)) = base {
            out.push_str("\"base\":");
            s(&mut out, root);
            out.push(',');
        }
        out.push_str("\"entries\":[");
        let mut i = 0;
        for e in &self.entries {
            if base.is_some_and(|(_, shared)| shared.contains(e)) {
                continue;
            }
            if i > 0 {
                out.push(',');
            }
            i += 1;
            out.push('[');
            s(&mut out, e.path.as_str());
            out.push_str(",\"");
            out.push_str(e.kind.code());
            out.push_str("\",");
            out.push_str(&e.size.to_string());
            out.push(',');
            s(&mut out, &e.hash);
            if e.exec {
                out.push_str(",1");
            }
            out.push(']');
        }
        out.push_str("],\"externals\":[");
        for (i, x) in self.externals.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('[');
            s(&mut out, &x.name);
            out.push(',');
            s(&mut out, &x.version);
            out.push(']');
        }
        out.push_str("],\"env\":[");
        for (i, x) in self.env.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('[');
            s(&mut out, &x.key);
            out.push(',');
            if x.hash == ABSENT_HASH {
                out.push_str("null");
            } else {
                s(&mut out, &x.hash);
            }
            out.push(']');
        }
        out.push_str("]}");
        out
    }

    /// Decode [`Self::to_compact`]'s encoding. Anything else (another
    /// version, an unknown kind or field, a path that is not a canonical
    /// [`RepoPath`]) is an error; an encoding on top of a base
    /// ([`Self::to_compact_on`]) is [`ManifestError::NeedsBase`]: decode it
    /// with [`Self::from_compact_with`].
    pub fn from_compact(bytes: &[u8]) -> Result<Self, ManifestError> {
        Self::from_compact_with(bytes, |root| Err(ManifestError::NeedsBase(root.to_owned())))
    }

    /// [`Self::from_compact`], reading the base manifest an encoding lists
    /// its entries on top of through `base` (the base's stored bytes, or
    /// why there are none). The base must be a plain manifest whose root is
    /// the one named; the result has the base's entries and this one's.
    pub fn from_compact_with(
        bytes: &[u8],
        base: impl FnOnce(&str) -> Result<Vec<u8>, ManifestError>,
    ) -> Result<Self, ManifestError> {
        let mut base = Some(base);
        Self::decode_compact(bytes, &mut |root| match base.take() {
            Some(f) => f(root),
            None => Err(ManifestError::NeedsBase(root.to_owned())),
        })
    }

    fn decode_compact(
        bytes: &[u8],
        base: &mut dyn FnMut(&str) -> Result<Vec<u8>, ManifestError>,
    ) -> Result<Self, ManifestError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Compact {
            v: u32,
            #[serde(default)]
            base: Option<String>,
            entries: Vec<Vec<serde_json::Value>>,
            externals: Vec<(String, String)>,
            env: Vec<(String, Option<String>)>,
        }
        let bad = |m: String| ManifestError::Compact(m);
        let c: Compact = serde_json::from_slice(bytes).map_err(|e| bad(e.to_string()))?;
        if c.v != 2 {
            return Err(bad(format!("version {} (expected 2)", c.v)));
        }
        let shared = match &c.base {
            None => Vec::new(),
            Some(root) => {
                let b = base(root)?;
                let b = Self::decode_compact(&b, &mut |inner| {
                    Err(bad(format!(
                        "base manifest {root} has a base of its own ({inner})"
                    )))
                })?;
                if b.root() != *root {
                    return Err(bad(format!(
                        "base manifest {root}'s entries hash to {}",
                        b.root()
                    )));
                }
                b.entries
            }
        };
        let mut entries = Vec::with_capacity(c.entries.len());
        for (i, e) in c.entries.into_iter().enumerate() {
            let at = |what: &str| bad(format!("entry {i}: {what}"));
            let (path, kind, size, hash, exec) = match e.as_slice() {
                [p, k, n, h] => (p, k, n, h, false),
                [p, k, n, h, x] if x.as_u64() == Some(1) => (p, k, n, h, true),
                _ => return Err(at("expected [path, kind, size, hash] or [..., 1]")),
            };
            let path = path
                .as_str()
                .ok_or_else(|| at("path is not a string"))
                .and_then(|p| RepoPath::try_from(p.to_owned()).map_err(|e| at(&e.to_string())))?;
            let kind = kind
                .as_str()
                .and_then(EntryKind::from_code)
                .ok_or_else(|| at("unknown kind"))?;
            let size = size.as_u64().ok_or_else(|| at("size is not a u64"))?;
            let hash = hash
                .as_str()
                .ok_or_else(|| at("hash is not a string"))?
                .to_owned();
            entries.push(InputEntry {
                path,
                kind,
                exec,
                size,
                hash,
            });
        }
        let own: HashSet<&RepoPath> = entries.iter().map(|e| &e.path).collect();
        let mut all: Vec<InputEntry> = shared
            .into_iter()
            .filter(|e| !own.contains(&e.path))
            .collect();
        all.extend(entries);
        Ok(InputManifest {
            entries: all,
            externals: c
                .externals
                .into_iter()
                .map(|(name, version)| External { name, version })
                .collect(),
            env: c
                .env
                .into_iter()
                .map(|(key, hash)| EnvEntry {
                    key,
                    hash: hash.unwrap_or_else(|| ABSENT_HASH.to_owned()),
                })
                .collect(),
        })
    }

    /// Re-observe every entry path under `repo_root` (without re-following
    /// symlinks: each recorded hop is checked on its own) and every env key in
    /// the current process environment, and list differences. Externals are
    /// compared by the caller. An empty result means everything matches.
    pub fn diff_against_checkout(
        &self,
        repo_root: &Utf8Path,
    ) -> Result<Vec<Mismatch>, ManifestError> {
        self.diff_against_checkout_with_env(repo_root, process_env)
    }

    /// [`Self::diff_against_checkout`] with an explicit environment lookup.
    pub fn diff_against_checkout_with_env<F>(
        &self,
        repo_root: &Utf8Path,
        env: F,
    ) -> Result<Vec<Mismatch>, ManifestError>
    where
        F: Fn(&str) -> Option<OsString> + Sync,
    {
        self.diff_against_checkout_excluding(repo_root, env, &[])
    }

    /// [`Self::diff_against_checkout_with_env`] leaving `extra_excluded`
    /// (children of listed directories present in this checkout but not
    /// inputs: what git ignores here, since 2.0.3) out of the listings it
    /// rehashes, as the manifest's own [`EntryKind::Excluded`] entries are.
    pub fn diff_against_checkout_excluding<F>(
        &self,
        repo_root: &Utf8Path,
        env: F,
        extra_excluded: &[RepoPath],
    ) -> Result<Vec<Mismatch>, ManifestError>
    where
        F: Fn(&str) -> Option<OsString> + Sync,
    {
        self.diff_from(Source::Fs(repo_root), env, extra_excluded)
    }

    /// [`Self::diff_against_checkout_excluding`] observing the checkout
    /// through `cache` (its root is the repository root): every path is read
    /// once for every manifest diffed through the same cache, which assumes
    /// the checkout does not change while the cache is used. The mismatches
    /// are the uncached diff's.
    pub fn diff_against_cache<F>(
        &self,
        cache: &CheckoutCache,
        env: F,
        extra_excluded: &[RepoPath],
    ) -> Result<Vec<Mismatch>, ManifestError>
    where
        F: Fn(&str) -> Option<OsString> + Sync,
    {
        self.diff_from(Source::Cache(cache), env, extra_excluded)
    }

    fn diff_from<F>(
        &self,
        src: Source<'_>,
        env: F,
        extra_excluded: &[RepoPath],
    ) -> Result<Vec<Mismatch>, ManifestError>
    where
        F: Fn(&str) -> Option<OsString> + Sync,
    {
        let mut excl = self.exclusions();
        for (parent, names) in exclusions(extra_excluded.iter()) {
            excl.entry(parent).or_default().extend(names);
        }
        let autoload_dirs: Vec<RepoPath> = self
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::AutoloadDir)
            .map(|e| e.path.clone())
            .collect();
        let autoload_idx = if autoload_dirs.is_empty() {
            AutoloadIndex::new()
        } else {
            src.autoload_index(&autoload_dirs)?
        };
        let entry_results: Vec<Option<Mismatch>> = self
            .entries
            .par_iter()
            .map(|exp| {
                if exp.kind == EntryKind::AutoloadDir {
                    // Only marks the directory for the lookups.
                    return Ok(None);
                }
                if exp.kind == EntryKind::Excluded {
                    // Not an input: only its parent's listing leaves it out.
                    return Ok(None);
                }
                let act = if exp.kind == EntryKind::AutoloadMiss {
                    src.autoload_miss(&exp.path, &autoload_idx)?
                } else {
                    src.observe(&exp.path, exp.kind == EntryKind::Dir, excl.get(&exp.path))?
                };
                Ok(if exp.same_state(&act) {
                    None
                } else {
                    Some(Mismatch {
                        what: format!("entry:{}", exp.path),
                        expected: exp.describe(),
                        actual: act.describe(),
                    })
                })
            })
            .collect::<Result<_, ManifestError>>()?;
        let mut out: Vec<Mismatch> = entry_results.into_iter().flatten().collect();

        for exp in &self.env {
            validate_env_key(&exp.key)?;
            let act = env_value_hash(env(&exp.key).as_deref());
            if act != exp.hash {
                let show = |h: &str| {
                    if h == ABSENT_HASH {
                        "unset".to_owned()
                    } else {
                        format!("blake3={h}")
                    }
                };
                out.push(Mismatch {
                    what: format!("env:{}", exp.key),
                    expected: show(&exp.hash),
                    actual: show(&act),
                });
            }
        }
        Ok(out)
    }

    /// Child names each directory listing of this manifest leaves out (its
    /// [`EntryKind::Excluded`] entries, by parent).
    pub fn excluded_children(&self) -> BTreeMap<RepoPath, BTreeSet<String>> {
        self.exclusions()
    }

    fn exclusions(&self) -> Exclusions {
        exclusions(
            self.entries
                .iter()
                .filter(|e| e.kind == EntryKind::Excluded)
                .map(|e| &e.path),
        )
    }

    /// Err if two distinct paths (or directory prefixes of paths) are equal
    /// under case folding, which would make them the same file on a
    /// case-insensitive filesystem. Two paths under which nothing exists
    /// (absent probes, such as `public/ACME` and `public/acme` for one
    /// request's two spellings) do not collide: there is no file to be the
    /// same one, and should either come to exist, on any filesystem at least
    /// one of the two probes finds it and the unit runs again.
    pub fn check_case_collisions(&self) -> Result<(), ManifestError> {
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        let mut paths: Vec<&str> = self.entries.iter().map(|e| e.path.as_str()).collect();
        paths.sort_unstable();
        let all_absent = |prefix: &str| {
            self.entries
                .iter()
                .filter(|e| {
                    e.path.as_str() == prefix
                        || e.path
                            .as_str()
                            .strip_prefix(prefix)
                            .is_some_and(|r| r.starts_with('/'))
                })
                .all(|e| e.kind == EntryKind::Absent)
        };
        for p in paths {
            let mut end = 0;
            loop {
                end = match p[end..].find('/') {
                    Some(i) => end + i,
                    None => p.len(),
                };
                let prefix = &p[..end];
                let folded = fold(prefix);
                match seen.get(&folded) {
                    Some(prev) if prev != prefix && !(all_absent(prev) && all_absent(prefix)) => {
                        return Err(ManifestError::CaseCollision {
                            a: prev.clone(),
                            b: prefix.to_owned(),
                        });
                    }
                    Some(prev) if prev != prefix => {}
                    Some(_) => {}
                    None => {
                        seen.insert(folded, prefix.to_owned());
                    }
                }
                if end == p.len() {
                    break;
                }
                end += 1;
            }
        }
        Ok(())
    }
}
