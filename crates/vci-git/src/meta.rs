//! Attestation storage on [git-meta](https://git-meta.com/).
//!
//! vci has no storage format of its own: every attestation is one git-meta
//! string value, exchanged on `refs/<namespace>/main` (namespace `meta` unless
//! `meta.namespace` says otherwise) by ordinary `git push` / `git fetch`, and
//! readable with the stock `git meta` CLI.
//!
//! # Layout
//!
//! * Target: the test unit's path, `path:<test file | Go package dir | cargo
//!   package dir>` (for cargo units, the part of the test id before `#`). A
//!   unit whose path git-meta cannot hold as a path target (the repository root
//!   `.`, or a value shorter than git-meta's minimum of three bytes) is stored
//!   on the `project` target instead.
//! * Key: `vci:attestation:<test key>:<signer id>:<storage key>[:<hint>]`,
//!   where the
//!   test key is BLAKE3 of the test id (it separates units sharing a path,
//!   such as the cargo targets of one package), the signer id names the
//!   signing key (so two signers never write the same key), and the storage
//!   key hashes everything that makes two attestations interchangeable (input
//!   root, toolchain, argv, ...). The same signer re-attesting the same unit
//!   and inputs therefore rewrites the same key. Since vci 2.2 the key ends
//!   with a hint, `<issuedAt seconds, hex>.<first 16 hex digits of the tree
//!   the attestation records, or ->`, so a plan picks the candidates to
//!   download without reading any (a vci before 2.2 does not read such keys:
//!   their units run there). The same inputs re-attested replace the key
//!   whatever its hint.
//! * Value: the signed DSSE envelope, byte for byte.
//! * Input manifests (since vci 1.9.0 an attestation references its manifest
//!   by input root instead of embedding it): target `project`, key
//!   `vci:manifest:<input root>`, value the manifest's compact encoding.
//!   Content-addressed: written once, shared by every attestation, unit and
//!   signer with that root, and trusted only when its recomputed root is
//!   the root an attestation signed.
//!
//! Nothing here is trusted: keys and values are hints. `vci plan` verifies
//! every envelope's signature against the base commit's `allowed_signers` and
//! recomputes every hash, so a deleted, overwritten or forged value can only
//! ever make a unit run.
//!
//! # Exchange
//!
//! [`AttestStore::fetch`] and [`AttestStore::push`] follow git-meta's own
//! pull/push workflow with the git CLI for transport: fetch `refs/<ns>/main`
//! into the tracking ref, serialize local values, materialize (git-meta's
//! merge), and for push rewrite the local metadata commit as one fast-forward
//! commit on the remote tip, retrying when the remote moved. A plain
//! `git meta pull` / `git meta push` works on the same refs and store.
//!
//! git-meta serializes the local SQLite store as a commit on top of
//! `refs/<ns>/local/main`, so a store that lacks keys that ref holds (a new
//! or emptied `.git/git-meta.sqlite`, a linked worktree, whose store is its
//! own while the refs are shared) would publish their deletion. vci therefore
//! first copies into the store whatever that ref holds and the store has no
//! row or deletion record for, refuses any serialization or push that would
//! drop a key without a deletion record, ignores tree entries git-meta cannot
//! read, and removes store rows git-meta cannot serialize.
//!
//! # Lazy values (vci 2.0)
//!
//! A fetch downloads the metadata commits and the trees it reads, not the
//! values: `git fetch --filter=blob:none`, and for the first fetch of a
//! tracking ref `--filter=tree:0` (every commit, no tree) followed by the
//! tip's tree alone (fetched by object id), so a fresh clone's download does
//! not grow with the length of the metadata history while the history stays
//! complete (never shallow: `.git/shallow` and `git fetch --unshallow` only
//! ever concern the code). The tree's paths are its keys, so the store gets a row per key without reading
//! a value: a value whose blob is already here is stored as a reference to it
//! (as git-meta stores values over its size limit), any other one as a
//! git-meta *promised* row (`is_promised`: known to exist, not fetched). The
//! value of a promised row is the blob at its key's path in
//! `refs/<ns>/local/main`; [`AttestStore::hydrate_units`] and its siblings
//! fetch the blobs a caller is about to read in one `git fetch --stdin` of
//! object ids and turn those rows into blob references. Deletion records
//! (tiny) are fetched and read as before. A serialization never needs the
//! values it does not change: git-meta reuses unchanged targets' subtrees by
//! object id, and the promised entries of a target it rebuilds are put back
//! at the object ids the previous commit held. A value that cannot be fetched
//! (offline) only reads as not fetched, which makes its unit run.
//!
//! git keeps such a repository working (`gc`, `fsck`, connectivity checks)
//! only with a *promisor* remote configured, and asks a promisor remote for
//! any object it misses, code included, with its whole history (`git fetch`
//! without negotiation). So the metadata remote is never recorded as one:
//! vci's own fetches name it a promisor for that command only (`-c
//! remote.<name>.promisor=true`), and the repository's promisor is
//! [`NO_LAZY_FETCH_REMOTE`], a remote without a URL: a missing object is
//! reported missing at once, as in a repository vci never fetched into,
//! instead of being downloaded. A value vci reads is fetched by vci, in
//! batches; a merge never keeps a value this clone never had that the
//! fetched tip no longer has (it could not publish it).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::str::FromStr;
use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use git_meta_lib::tree::format::{parse_path_parts, parse_tree};
use git_meta_lib::tree::model::{Key, ParsedTree, Tombstone, TreeValue};
use git_meta_lib::{MetaValue, Session, Target, TargetType};

use crate::GitError;
use crate::cmd::{IDENTITY, command_error};
use crate::repo::{Repo, is_oid, parse_oid};
use crate::validate;

/// Key namespace of every vci attestation.
pub const KEY_PREFIX: &str = "vci:attestation";
/// Key namespace of the stored input manifests (`vci:manifest:<root>`, on
/// the `project` target).
pub const MANIFEST_PREFIX: &str = "vci:manifest";
/// The project-local file naming the recommended metadata remote
/// (`url: <url>`), as read by `git meta setup`.
pub const SETUP_FILE: &str = ".git-meta";
/// Name given to a metadata remote vci configures (git-meta's default).
pub const DEFAULT_REMOTE_NAME: &str = "meta";
/// git-meta's minimum target value length.
const MIN_TARGET_LEN: usize = 3;
const PUSH_ATTEMPTS: u32 = 10;
/// How many times [`AttestStore::complete_tree`] asks for the subtrees a
/// fetch of a tree's id left out.
const COMPLETE_TREE_ROUNDS: usize = 5;
/// The repack [`AttestStore::consolidate_packs`] runs when the geometric one
/// fails, as it always does in a partial clone on git before 2.45
/// (`cannot use internal rev list with --stdin-packs`; Ubuntu 24.04's
/// 2.43, GitHub's runners). `-A`, never `-a` (2.2.2): `-a -d` deletes the
/// packed objects no ref reaches, and a value vci wrote is packed while
/// its local metadata commit reaches it, then unreferenced when vci
/// rewrites that commit (a merge, an undo) before the push that sends it:
/// every vex job that lost its attestations to `could not fetch <its own
/// value> from promisor remote` (no loose object file left) did so this
/// way. `-A` turns such objects loose instead; nothing prunes them (vci's
/// git runs with `gc.auto=0`).
const REPACK_FALLBACK: &[&str] = &["-A", "-d", "-q"];
/// Attempts of a fetch that loses a ref-lock race to another git process.
const FETCH_ATTEMPTS: u32 = 5;
/// Project-target settings that make every `git meta serialize` prune.
const PRUNE_KEYS: &[&str] = &["meta:prune:max-keys", "meta:prune:max-size"];
/// Blobs asked for in one `git fetch --stdin` (git-meta's batch size: GitHub
/// rejects very large want lists).
const FETCH_BLOB_BATCH: usize = 4000;
/// Below this many blobs a fetch runs alone; above, in parallel batches of
/// at least this many.
///
/// 2.3.9: 4,000 (was 500). A plan's 2,018 values came in four packs, which
/// pushed a restored store past [`PACKS_BEFORE_REPACK`] and into a 6.7 s
/// repack on git 2.43; one `git fetch` of 2,000 values from GitHub takes
/// about as long as four (1.6 s against 1.4 s on a laptop).
const FETCH_BLOB_PARALLEL_MIN: usize = 4000;

/// Packs in the object database from which a batched fetch merges them
/// (gix, which git-meta reads it with, has 32 pack slots at least).
const PACKS_BEFORE_REPACK: usize = 16;

/// How many `git fetch` processes [`AttestStore`] runs at once for values:
/// `VCI_FETCH_JOBS`, default 4.
fn fetch_jobs() -> usize {
    std::env::var("VCI_FETCH_JOBS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(4)
}
/// The repository's promisor remote (see the module docs): no URL, so git
/// never downloads an object it misses (the metadata values vci fetches
/// itself). `skipFetchAll`/`skipDefaultUpdate` keep `git fetch --all` and
/// `git remote update` away from it.
pub const NO_LAZY_FETCH_REMOTE: &str = "vci-no-lazy-fetch";
/// How a value not fetched yet reads (a promised row).
const NOT_FETCHED: &str = "value not fetched: run `vci fetch` online (a git-meta promised entry; its blob is not in this clone yet)";

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// What [`AttestStore::hydrate_units`] and its siblings did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hydration {
    /// Values that had not been fetched and now are readable.
    pub resolved: usize,
    /// Values asked for that are still not fetched (the fetch failed, or the
    /// local metadata commit does not hold them).
    pub unresolved: usize,
    /// Blobs downloaded.
    pub fetched: usize,
    /// Why some values could not be fetched.
    pub error: Option<String>,
}

impl Hydration {
    /// This hydration and `o` together (the first error kept).
    pub fn add(&mut self, o: Hydration) {
        self.resolved += o.resolved;
        self.unresolved += o.unresolved;
        self.fetched += o.fetched;
        if self.error.is_none() {
            self.error = o.error;
        }
    }
}

/// An envelope read back from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEnvelope {
    /// git-meta target, as `git meta get` takes it: `path:<p>` or `project`.
    pub target: String,
    /// Full git-meta key.
    pub key: String,
    /// BLAKE3 of the test id.
    pub test_key: String,
    /// 16 hex characters naming the signing key (a hint; unverified).
    pub signer: String,
    /// Storage key (see the module docs).
    pub storage_key: String,
    /// When the key says the attestation was issued (seconds since the
    /// epoch; vci 2.2 keys), read without the value.
    pub issued: Option<i64>,
    /// The first 16 hex digits of the tree the key says it was made on.
    pub tree: Option<String>,
    /// The stored bytes, exactly as passed to `put` (empty when `error` is
    /// set).
    pub bytes: Vec<u8>,
    /// Why the value could not be read (a blob missing from the object
    /// database, a value not fetched yet). Such an entry is never valid; it
    /// is listed so that only its own unit loses it.
    pub error: Option<String>,
}

impl StoredEnvelope {
    /// Whether the value is unread only because it has not been fetched
    /// yet (a git-meta promised entry, see the module docs).
    pub fn not_fetched(&self) -> bool {
        self.error.as_deref() == Some(NOT_FETCHED)
    }
}

/// An input manifest read back from storage (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredManifest {
    /// The input root it is stored under (a hint until the manifest's own
    /// root is recomputed).
    pub root: String,
    /// Full git-meta key (`vci:manifest:<root>`, target `project`).
    pub key: String,
    /// The stored bytes (empty when `error` is set).
    pub bytes: Vec<u8>,
    /// Why the value could not be read.
    pub error: Option<String>,
}

impl StoredManifest {
    /// Whether the value is unread only because it has not been fetched
    /// yet ([`StoredEnvelope::not_fetched`]).
    pub fn not_fetched(&self) -> bool {
        self.error.as_deref() == Some(NOT_FETCHED)
    }
}

/// What the hydrations of one exchange share (see
/// [`AttestStore::hydrate_ctx`]).
struct HydrateCtx {
    /// The store's rows whose values are not fetched yet, less those a
    /// round of this exchange resolved.
    promised: BTreeSet<Key>,
    local_ref: String,
    /// The local metadata tree's keys and blobs, listed by the first round
    /// that fetches anything.
    snap: Option<KeySnapshot>,
}

/// What [`AttestStore::fetch`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOutcome {
    /// The metadata remote used.
    pub remote: String,
    /// False when the remote has no `refs/<ns>/main` yet.
    pub found: bool,
    /// Problems worth a warning (values dropped by the remote without a
    /// deletion record, shared auto-prune or filter settings, entries
    /// ignored because git-meta cannot read them).
    pub warnings: Vec<String>,
    /// What vci repaired on the way (values restored into a store that did
    /// not match the local metadata ref).
    pub notes: Vec<String>,
}

/// How [`AttestStore::push`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushStatus {
    /// The remote's `refs/<ns>/main` now holds the local metadata commit.
    Pushed,
    /// The remote already held everything stored locally; nothing was sent.
    UpToDate,
    /// Nothing is stored locally; nothing was sent.
    NothingStored,
}

/// What [`AttestStore::push`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    /// The metadata remote used.
    pub remote: String,
    pub status: PushStatus,
    /// As for [`FetchOutcome::warnings`].
    pub warnings: Vec<String>,
    /// As for [`FetchOutcome::notes`].
    pub notes: Vec<String>,
}

/// Attestation store backed by git-meta in a repository.
#[derive(Debug, Clone, Copy)]
pub struct AttestStore<'a> {
    repo: &'a Repo,
}

/// The git-meta target for a test id.
pub fn target_for(test_id: &str) -> Target {
    let path = test_id.split('#').next().unwrap_or(test_id);
    let ok = path.len() >= MIN_TARGET_LEN
        && !path.starts_with('/')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..");
    if ok {
        Target::path(path)
    } else {
        Target::project()
    }
}

/// `path:<p>` or `project`, the spelling `git meta get` accepts.
pub fn target_label(t: &Target) -> String {
    t.to_string()
}

/// The key an attestation is stored under (without a hint, as before 2.2).
pub fn attestation_key(test_key: &str, signer: &str, storage_key: &str) -> String {
    format!("{KEY_PREFIX}:{test_key}:{signer}:{storage_key}")
}

/// What a key says about its attestation without the value (vci 2.2): when
/// it was issued and, when known, the git tree it was made on. A plan
/// chooses which candidates to download from this; before, it downloaded
/// every candidate of every unit to find the newest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHint {
    /// `issuedAt`, seconds since the epoch.
    pub issued: i64,
    /// The first 16 hex digits of the tree the attestation records.
    pub tree: Option<String>,
}

/// The key an attestation is stored under, with its hint:
/// `vci:attestation:<test key>:<signer>:<storage key>:<issued hex>.<tree16 | ->`.
pub fn attestation_key_hinted(
    test_key: &str,
    signer: &str,
    storage_key: &str,
    hint: &KeyHint,
) -> String {
    let tree = hint
        .tree
        .as_deref()
        .map(|t| t.chars().take(16).collect::<String>())
        .filter(|t| t.len() == 16 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| "-".to_owned());
    format!(
        "{KEY_PREFIX}:{test_key}:{signer}:{storage_key}:{:x}.{tree}",
        hint.issued.max(0)
    )
}

fn parse_hint(part: &str) -> Option<KeyHint> {
    let (issued, tree) = part.split_once('.')?;
    if issued.is_empty() || issued.len() > 16 || !issued.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let issued = i64::from_str_radix(issued, 16).ok()?;
    let tree = match tree {
        "-" => None,
        t if t.len() == 16 && t.bytes().all(|b| b.is_ascii_hexdigit()) => Some(t.to_owned()),
        _ => return None,
    };
    Some(KeyHint { issued, tree })
}

/// The hint a key carries, if any (keys written before 2.2 carry none).
pub fn parse_key_hint(key: &str) -> Option<KeyHint> {
    let rest = key.strip_prefix(KEY_PREFIX)?.strip_prefix(':')?;
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() == 4 {
        parse_hint(parts[3])
    } else {
        None
    }
}

/// The key the input manifest with this root is stored under (target
/// `project`).
pub fn manifest_key(root: &str) -> String {
    format!("{MANIFEST_PREFIX}:{root}")
}

/// The input root a manifest key names, if it has vci's shape.
pub fn parse_manifest_key(key: &str) -> Option<&str> {
    let root = key.strip_prefix(MANIFEST_PREFIX)?.strip_prefix(':')?;
    validate::is_hex_id(root).then_some(root)
}

/// Decode a stored input manifest's bytes, reading the base manifest it
/// lists its entries on top of (vci 2.1.8) from the store through
/// `reader`. The bytes carry no trust: the caller compares the result's
/// root with the signed input root.
pub fn decode_manifest(reader: &Reader, bytes: &[u8]) -> Result<vci_core::InputManifest, String> {
    vci_core::InputManifest::from_compact_with(bytes, |base| match reader.manifest(base) {
        Ok(Some(b)) if b.error.is_none() => Ok(b.bytes),
        Ok(Some(b)) => Err(vci_core::ManifestError::Compact(format!(
            "base manifest {base} unreadable: {}",
            b.error.unwrap_or_default()
        ))),
        Ok(None) => Err(vci_core::ManifestError::MissingBase(base.to_owned())),
        Err(e) => Err(vci_core::ManifestError::Compact(format!(
            "base manifest {base}: {e}"
        ))),
    })
    .map_err(|e| e.to_string())
}

/// The `manifestRef` of a stored DSSE envelope's vci predicate (unverified:
/// only which stored manifest it names), if it has one.
fn envelope_manifest_ref(bytes: &[u8]) -> Option<String> {
    use base64::Engine as _;
    let env: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(env["payload"].as_str()?)
        .ok()?;
    let st: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let r = st["predicate"]["manifestRef"].as_str()?;
    validate::is_hex_id(r).then(|| r.to_owned())
}

/// The id of the blob git-meta writes for deletion record `t`, in the hash
/// of `like` (an object id of the same repository); `None` when it cannot be
/// computed here.
fn tombstone_blob_id(t: &Tombstone, like: &str) -> Option<String> {
    if like.len() != 40 {
        return None;
    }
    let bytes = serde_json::to_vec(t).ok()?;
    gix::objs::compute_hash(gix::hash::Kind::Sha1, gix::objs::Kind::Blob, &bytes)
        .ok()
        .map(|id| id.to_string())
}

/// Split a key into (test key, signer, storage key) if it has vci's shape,
/// with or without a hint (vci 2.2).
pub fn parse_key(key: &str) -> Option<(&str, &str, &str)> {
    let rest = key.strip_prefix(KEY_PREFIX)?.strip_prefix(':')?;
    let mut parts = rest.split(':');
    let (Some(tk), Some(signer), Some(sk)) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    match (parts.next(), parts.next()) {
        (None, _) => {}
        (Some(h), None) if parse_hint(h).is_some() => {}
        _ => return None,
    }
    (validate::is_hex_id(tk) && validate::is_signer_id(signer) && validate::is_hex_id(sk))
        .then_some((tk, signer, sk))
}

fn meta_err(e: git_meta_lib::Error) -> GitError {
    GitError::Meta(e.to_string())
}

fn sql_err(path: &Utf8Path, e: rusqlite::Error) -> GitError {
    GitError::Store(format!("{path}: {e}"))
}

/// Whether git-meta can serialize a target: its value is long enough for
/// `Target::parse`, and a commit target is plain ASCII (git-meta slices its
/// first two bytes for the fan-out directory).
fn valid_target(ty: &TargetType, value: &str) -> bool {
    if *ty == TargetType::Project {
        return true;
    }
    if value.contains('\0') {
        return false;
    }
    let t = Target::from_parts(ty.clone(), Some(value.to_owned()));
    Target::parse(&t.to_string()).is_ok()
        && (*ty != TargetType::Commit || value.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn valid_key(k: &Key) -> bool {
    valid_target(&k.target_type, &k.target_value)
}

/// Run a git-meta operation that might panic on input it does not expect;
/// a panic becomes an error (the caller then runs everything).
fn guarded<T>(what: &str, f: impl FnOnce() -> git_meta_lib::Result<T>) -> Result<T, GitError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r.map_err(meta_err),
        Err(_) => Err(GitError::Meta(format!("{what} panicked"))),
    }
}

// ---- reading ----------------------------------------------------------------

/// Read-only access to the local git-meta store, for many lookups.
///
/// The SQLite file is opened read-only and no lock file is created, so a
/// read-only `.git` (or another process holding vci's lock) does not stop
/// `vci plan`. Values git-meta keeps as blob references are read through one
/// `git cat-file --batch` process.
pub struct Reader {
    db: Option<(Utf8PathBuf, rusqlite::Connection)>,
    root: Utf8PathBuf,
    blobs: RefCell<Option<CatFile>>,
}

impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("open", &self.db.is_some())
            .finish()
    }
}

/// A `git cat-file --batch` process.
struct CatFile {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl CatFile {
    fn start(root: &Utf8Path) -> Result<Self, GitError> {
        // A blob missing here reads as missing: values are fetched in
        // batches, never one by one behind a read (`GIT_NO_LAZY_FETCH`).
        let mut child = crate::cmd::Git::at(root)
            .args(["cat-file", "--batch"])
            .env("GIT_NO_LAZY_FETCH", "1")
            .spawn_piped()?;
        let stdin = child.stdin.take().expect("stdin piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout piped"));
        Ok(CatFile {
            child,
            stdin,
            stdout,
        })
    }

    fn blob(&mut self, oid: &str) -> Result<Vec<u8>, String> {
        if !is_oid(oid) {
            return Err(format!("not an object id: {oid:?}"));
        }
        let io = |e: std::io::Error| format!("git cat-file: {e}");
        writeln!(self.stdin, "{oid}").map_err(io)?;
        self.stdin.flush().map_err(io)?;
        let mut header = String::new();
        self.stdout.read_line(&mut header).map_err(io)?;
        let fields: Vec<&str> = header.split_whitespace().collect();
        match fields.as_slice() {
            [_, "blob", size] => {
                let size: usize = size.parse().map_err(|_| format!("bad size {size:?}"))?;
                let mut buf = vec![0u8; size + 1];
                self.stdout.read_exact(&mut buf).map_err(io)?;
                buf.pop();
                Ok(buf)
            }
            [_, "missing"] => Err(format!("blob {oid} is missing from the object database")),
            [_, kind, size] => {
                // Skip the object so the stream stays in sync.
                if let Ok(size) = size.parse::<usize>() {
                    let mut buf = vec![0u8; size + 1];
                    self.stdout.read_exact(&mut buf).map_err(io)?;
                }
                Err(format!("{oid} is a {kind}, not a blob"))
            }
            _ => Err(format!("unexpected git cat-file output {header:?}")),
        }
    }
}

impl Drop for CatFile {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One `metadata` row with a vci-shaped key.
struct Row {
    target: Target,
    key: String,
    value: String,
    value_type: String,
    is_git_ref: bool,
    is_promised: bool,
}

impl Reader {
    fn open(root: &Utf8Path, db_path: Utf8PathBuf) -> Result<Self, GitError> {
        let empty = |root: &Utf8Path| Reader {
            db: None,
            root: root.to_owned(),
            blobs: RefCell::new(None),
        };
        match std::fs::metadata(&db_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(empty(root)),
            Err(e) => {
                return Err(GitError::Store(format!("cannot read {db_path}: {e}")));
            }
            Ok(m) if m.len() == 0 => return Ok(empty(root)),
            Ok(_) => {}
        }
        use rusqlite::OpenFlags;
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI;
        let has_table = |c: &rusqlite::Connection| -> rusqlite::Result<bool> {
            c.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'metadata'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
        };
        let try_open = |spec: &str| -> rusqlite::Result<(rusqlite::Connection, bool)> {
            let c = rusqlite::Connection::open_with_flags(spec, flags)?;
            c.busy_timeout(Duration::from_secs(5))?;
            let t = has_table(&c)?;
            Ok((c, t))
        };
        // A read-only open of a WAL database needs its -shm file (or the
        // right to create it); when that fails (a read-only `.git`), read
        // the database file as it is.
        let uri = |immutable: bool| {
            let mut p = String::from("file:");
            for ch in db_path.as_str().chars() {
                match ch {
                    '%' => p.push_str("%25"),
                    '?' => p.push_str("%3f"),
                    '#' => p.push_str("%23"),
                    c => p.push(c),
                }
            }
            if immutable {
                p.push_str("?immutable=1");
            }
            p
        };
        let opened = match try_open(&uri(false)) {
            Ok(o) => o,
            Err(first) => try_open(&uri(true)).map_err(|second| {
                GitError::Store(format!(
                    "cannot open {db_path} read-only: {first} (and as an immutable file: {second})"
                ))
            })?,
        };
        match opened {
            (c, true) => Ok(Reader {
                db: Some((db_path, c)),
                root: root.to_owned(),
                blobs: RefCell::new(None),
            }),
            (_, false) => Ok(empty(root)),
        }
    }

    /// False when the repository has no git-meta store (nothing was ever
    /// attested or fetched here).
    pub fn has_store(&self) -> bool {
        self.db.is_some()
    }

    fn rows(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Result<Vec<Row>, GitError> {
        let Some((path, db)) = &self.db else {
            return Ok(Vec::new());
        };
        let mut stmt = db.prepare(sql).map_err(|e| sql_err(path, e))?;
        let rows = stmt
            .query_map(params, |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, bool>(5)?,
                    r.get::<_, bool>(6)?,
                ))
            })
            .map_err(|e| sql_err(path, e))?;
        let mut out = Vec::new();
        for r in rows {
            let (ty, value, key, v, vt, is_git_ref, is_promised) =
                r.map_err(|e| sql_err(path, e))?;
            let Ok(ty) = TargetType::from_str(&ty) else {
                continue;
            };
            let target = if ty == TargetType::Project {
                Target::project()
            } else {
                Target::from_parts(ty, Some(value))
            };
            out.push(Row {
                target,
                key,
                value: v,
                value_type: vt,
                is_git_ref,
                is_promised,
            });
        }
        Ok(out)
    }

    /// Decode one row the way git-meta's `get_value` does. Read errors
    /// belong to the row, not to the lookup.
    fn decode(&self, row: Row) -> Option<StoredEnvelope> {
        let (tk, signer, sk) = parse_key(&row.key)?;
        if row.value_type != "string" {
            return None;
        }
        let hint = parse_key_hint(&row.key);
        let mut env = StoredEnvelope {
            target: target_label(&row.target),
            key: row.key.clone(),
            test_key: tk.to_owned(),
            signer: signer.to_owned(),
            storage_key: sk.to_owned(),
            issued: hint.as_ref().map(|h| h.issued),
            tree: hint.and_then(|h| h.tree),
            bytes: Vec::new(),
            error: None,
        };
        match self.value_bytes(row) {
            Ok(b) => env.bytes = b,
            Err(e) => env.error = Some(e),
        }
        Some(env)
    }

    /// A string row's value, read the way git-meta's `get_value` does (a
    /// blob reference through `git cat-file`, a promised entry an error).
    fn value_bytes(&self, row: Row) -> Result<Vec<u8>, String> {
        let raw = if row.is_promised {
            Err(NOT_FETCHED.to_owned())
        } else if row.is_git_ref {
            let mut blobs = self.blobs.borrow_mut();
            if blobs.is_none() {
                match CatFile::start(&self.root) {
                    Ok(c) => *blobs = Some(c),
                    Err(e) => return Err(format!("reading blob {}: {e}", row.value)),
                }
            }
            let r = blobs.as_mut().expect("started").blob(row.value.trim());
            if r.is_err() {
                // The stream may be out of sync after an error.
                *blobs = None;
            }
            r.map(|b| String::from_utf8_lossy(&b).into_owned())
        } else {
            Ok(row.value)
        };
        raw.map(|s| {
            let s: String = serde_json::from_str(&s).unwrap_or(s);
            s.into_bytes()
        })
    }

    /// The stored input manifest with this root (see the module docs), or
    /// `None` when the store has none. A value that cannot be read is
    /// returned with [`StoredManifest::error`] set.
    pub fn manifest(&self, root: &str) -> Result<Option<StoredManifest>, GitError> {
        if !validate::is_hex_id(root) {
            return Ok(None);
        }
        let key = manifest_key(root);
        let ty = TargetType::Project.as_str().to_owned();
        let rows = self.rows(
            "SELECT target_type, target_value, key, value, value_type, is_git_ref, is_promised
             FROM metadata WHERE target_type = ?1 AND key = ?2",
            &[&ty, &key],
        )?;
        let Some(row) = rows.into_iter().find(|r| r.key == key) else {
            return Ok(None);
        };
        let mut m = StoredManifest {
            root: root.to_owned(),
            key,
            bytes: Vec::new(),
            error: None,
        };
        if row.value_type != "string" {
            m.error = Some(format!("a {} value, not a string", row.value_type));
            return Ok(Some(m));
        }
        match self.value_bytes(row) {
            Ok(b) => m.bytes = b,
            Err(e) => m.error = Some(e),
        }
        Ok(Some(m))
    }

    /// The roots of every stored input manifest, sorted (values not read).
    pub fn manifest_roots(&self) -> Result<Vec<String>, GitError> {
        let prefix = format!("{MANIFEST_PREFIX}:");
        let len = prefix.len() as i64;
        let ty = TargetType::Project.as_str().to_owned();
        let rows = self.rows(
            "SELECT target_type, target_value, key, '', value_type, is_git_ref, is_promised
             FROM metadata WHERE target_type = ?1 AND substr(key, 1, ?2) = ?3",
            &[&ty, &len, &prefix],
        )?;
        let mut out: Vec<String> = rows
            .iter()
            .filter_map(|r| parse_manifest_key(&r.key).map(str::to_owned))
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Every stored attestation for `test_id`. Entries whose key does not
    /// have vci's shape or whose value is not a string are ignored; entries
    /// whose value cannot be read are returned with [`StoredEnvelope::error`]
    /// set.
    pub fn candidates(&self, test_id: &str) -> Result<Vec<StoredEnvelope>, GitError> {
        let tk = vci_core::test_key(test_id);
        let target = target_for(test_id);
        let prefix = format!("{KEY_PREFIX}:{tk}:");
        let ty = target.target_type().as_str().to_owned();
        let value = target.value().unwrap_or("").to_owned();
        let len = prefix.len() as i64;
        let rows = self.rows(
            "SELECT target_type, target_value, key, value, value_type, is_git_ref, is_promised
             FROM metadata WHERE target_type = ?1 AND target_value = ?2 AND substr(key, 1, ?3) = ?4",
            &[&ty, &value, &len, &prefix],
        )?;
        let mut out: Vec<StoredEnvelope> = rows
            .into_iter()
            .filter_map(|r| self.decode(r))
            .filter(|e| e.test_key == tk)
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    /// How many attestations are stored (values not read).
    pub fn count(&self) -> Result<usize, GitError> {
        let prefix = format!("{KEY_PREFIX}:");
        let len = prefix.len() as i64;
        let rows = self.rows(
            "SELECT target_type, target_value, key, '', value_type, is_git_ref, is_promised
             FROM metadata WHERE substr(key, 1, ?1) = ?2",
            &[&len, &prefix],
        )?;
        Ok(rows
            .iter()
            .filter(|r| r.value_type == "string" && parse_key(&r.key).is_some())
            .count())
    }

    /// How many values of the store have not been fetched (promised rows).
    pub fn promised(&self) -> Result<usize, GitError> {
        let Some((path, db)) = &self.db else {
            return Ok(0);
        };
        db.query_row(
            "SELECT count(*) FROM metadata WHERE is_promised = 1",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n.max(0) as usize)
        .map_err(|e| sql_err(path, e))
    }

    /// Every stored attestation on any target.
    pub fn all(&self) -> Result<Vec<StoredEnvelope>, GitError> {
        let prefix = format!("{KEY_PREFIX}:");
        let len = prefix.len() as i64;
        let rows = self.rows(
            "SELECT target_type, target_value, key, value, value_type, is_git_ref, is_promised
             FROM metadata WHERE substr(key, 1, ?1) = ?2",
            &[&len, &prefix],
        )?;
        let mut out: Vec<StoredEnvelope> =
            rows.into_iter().filter_map(|r| self.decode(r)).collect();
        out.sort_by(|a, b| (&a.target, &a.key).cmp(&(&b.target, &b.key)));
        Ok(out)
    }
}

// ---- tree snapshots -----------------------------------------------------------

/// A metadata commit's tree as git-meta parses it, minus the entries it
/// cannot read.
struct Snapshot {
    parsed: ParsedTree,
}

/// What a metadata commit's tree holds, read from its paths alone: the keys
/// of its string values and of its whole-key tombstones (git-meta's tree
/// layout: `<target>/<key segments>/__value` and
/// `<target>/__tombstones/<key segments>/__deleted`, a key's segments being
/// its `:`-separated parts), plus what [`Snapshot`] records about entries
/// git-meta cannot read. No blob is read: parsing values ([`Snapshot`]) reads
/// every attestation of the tree, which on a large store is most of the
/// cost of a fetch or push.
struct KeySnapshot {
    tree: String,
    values: BTreeSet<Key>,
    /// The blob of each string value.
    value_blobs: BTreeMap<Key, String>,
    tombstones: BTreeSet<Key>,
    /// The blob of each whole-key tombstone (its deletion record).
    tombstone_blobs: BTreeMap<Key, String>,
    /// The blob of each stored input manifest, by input root.
    manifest_blobs: BTreeMap<String, String>,
    /// Entries of a target git-meta reads that are neither a string value
    /// nor a whole-key deletion record (a set or list value, or a member
    /// deletion record), by path: only git-meta's own merge reads those.
    others: Vec<String>,
    bad: Vec<String>,
    clean_tree: Option<String>,
}

/// git-meta's tree layout names (pinned with the crate version).
const VALUE_BLOB: &str = "__value";
const TOMBSTONE_DIR: &str = "__tombstones";
const TOMBSTONE_BLOB: &str = "__deleted";
const SET_DIR: &str = "__set";
const LIST_DIR: &str = "__list";

/// The key a git-meta tree path names, as [`KeySnapshot`] classifies it.
#[derive(Debug, PartialEq, Eq)]
enum PathKey {
    Value(String),
    Tombstone(String),
    Other,
}

fn classify_key_parts(key_parts: &[&str]) -> PathKey {
    let reserved = |segs: &[&str]| {
        segs.iter()
            .any(|s| [VALUE_BLOB, TOMBSTONE_DIR, TOMBSTONE_BLOB, SET_DIR, LIST_DIR].contains(s))
    };
    match key_parts.split_last() {
        Some((&VALUE_BLOB, segs)) if !segs.is_empty() && !reserved(segs) => {
            PathKey::Value(segs.join(":"))
        }
        Some((&TOMBSTONE_BLOB, rest))
            if rest.first() == Some(&TOMBSTONE_DIR) && rest.len() >= 2 && !reserved(&rest[1..]) =>
        {
            PathKey::Tombstone(rest[1..].join(":"))
        }
        _ => PathKey::Other,
    }
}

/// A `--full-tree -r -z` ls-tree record: (mode, type, oid, path bytes).
type TreeRecord<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8]);

fn split_ls_tree(out: &[u8]) -> Vec<TreeRecord<'_>> {
    out.split(|b| *b == 0)
        .filter(|r| !r.is_empty())
        .filter_map(|rec| {
            let tab = rec.iter().position(|b| *b == b'\t')?;
            let (meta, path) = (&rec[..tab], &rec[tab + 1..]);
            let mut f = meta.split(|b| *b == b' ');
            Some((f.next()?, f.next()?, f.next()?, path))
        })
        .collect()
}

// ---- writing and exchange -----------------------------------------------------

/// What one fetch-and-merge round found.
struct Round {
    found: bool,
    /// Keys with a local deletion record before the merge: the only keys a
    /// push may drop from the remote tip.
    deleted_here: BTreeSet<Key>,
}

/// What a merge from the trees' paths ([`AttestStore::materialize_lazy`])
/// did.
struct Materialized {
    /// Entries changed (values taken, deletion records applied, values
    /// deleted).
    changed: usize,
    /// Whether it merged two histories (else a fast-forward).
    merged: bool,
    /// Values taken whose blobs are not here (promised rows).
    promised: usize,
}

/// Messages collected along an exchange.
#[derive(Default)]
struct Report {
    warnings: Vec<String>,
    notes: Vec<String>,
}

impl Report {
    fn warn(&mut self, w: String) {
        if !self.warnings.contains(&w) {
            self.warnings.push(w);
        }
    }
    fn note(&mut self, n: String) {
        if !self.notes.contains(&n) {
            self.notes.push(n);
        }
    }
}

/// `git fetch` of a ref the remote does not have: the remote has no metadata
/// yet (git says "couldn't find remote ref", older versions capitalise it).
fn is_missing_remote_ref(e: &GitError) -> bool {
    let text = e.to_string().to_ascii_lowercase();
    text.contains("couldn't find remote ref") || text.contains("could not find remote ref")
}

/// What [`AttestStore::unsendable`] found.
#[derive(Debug, Default)]
struct Unsendable {
    /// Values the remote does not have (any more).
    gone: Vec<Key>,
    /// Values that could not be fetched for another reason, with it.
    stuck: Vec<(Key, Option<String>)>,
}

/// A fetch of object ids the server refused because it does not have them
/// (any more): not reachable from its refs, or never there.
fn is_unavailable_object(text: &str) -> bool {
    text.contains("not our ref")
        || text.contains("unadvertised object")
        || text.contains("no such object")
}

/// The object a failed `git push` named as one it could not read (git
/// tried its lazy fetch, which vci disables): `fatal: could not fetch <oid>
/// from promisor remote`.
fn unreadable_object(stderr: &str) -> Option<String> {
    stderr
        .lines()
        .find_map(|l| {
            l.strip_prefix("fatal: could not fetch ")
                .or_else(|| l.strip_prefix("fatal: unable to read "))
        })
        .and_then(|l| l.split_whitespace().next())
        .filter(|o| is_oid(o))
        .map(str::to_owned)
}

fn is_ref_race(e: &GitError) -> bool {
    let text = e.to_string();
    text.contains("cannot lock ref")
        || text.contains("Unable to create") && text.contains(".lock")
        || text.contains("but expected")
        || matches!(e, GitError::Meta(m) if m.contains("lock"))
}

impl<'a> AttestStore<'a> {
    pub fn new(repo: &'a Repo) -> Self {
        AttestStore { repo }
    }

    fn db_path(&self) -> Result<Utf8PathBuf, GitError> {
        Ok(self.repo.git_dir()?.join("git-meta.sqlite"))
    }

    fn lock_file(&self, path: Utf8PathBuf) -> Result<std::fs::File, GitError> {
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| GitError::Store(format!("cannot create lock file {path}: {e}")))?;
        lock.lock()
            .map_err(|e| GitError::Store(format!("cannot lock {path}: {e}")))?;
        Ok(lock)
    }

    /// Open (creating if needed) the git-meta session.
    ///
    /// git-meta migrates a new or old database schema on open, outside a
    /// transaction, so two processes opening a fresh store at once can fail
    /// ("duplicate column name"). vci processes take a lock file around the
    /// open, and retry in case another git-meta client migrated concurrently.
    fn session(&self) -> Result<Session, GitError> {
        let _lock = self.lock_file(self.repo.git_dir()?.join("git-meta.sqlite.vci-lock"))?;
        let mut last = None;
        for attempt in 0..5u64 {
            match Session::open(self.repo.root().as_std_path()) {
                Ok(s) => return Ok(s),
                Err(e) => {
                    last = Some(e);
                    std::thread::sleep(Duration::from_millis(20 * (attempt + 1)));
                }
            }
        }
        Err(meta_err(last.expect("at least one attempt")))
    }

    /// Serializes fetches and pushes of one repository (all its worktrees:
    /// the metadata refs are shared), so two of them never race on
    /// `refs/<ns>/local/main` or the tracking ref.
    fn exchange_lock(&self) -> Result<std::fs::File, GitError> {
        let common = self
            .repo
            .git()
            .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
            .run_str()?;
        self.lock_file(Utf8PathBuf::from(common).join("git-meta.vci-exchange.lock"))
    }

    /// A reader over the local store. When the repository has no git-meta
    /// store yet, the reader is empty and nothing is created.
    pub fn reader(&self) -> Result<Reader, GitError> {
        Reader::open(self.repo.root(), self.db_path()?)
    }

    /// Store `bytes` for `test_id` under the signer's key in the local
    /// git-meta store (`.git/git-meta.sqlite`). Nothing is serialized or
    /// pushed; the user's index, HEAD and working tree are never touched.
    /// Storing identical bytes again is a no-op; different bytes under the
    /// same key replace the old envelope.
    pub fn put(
        &self,
        test_id: &str,
        signer: &str,
        storage_key: &str,
        bytes: &[u8],
    ) -> Result<StoredEnvelope, GitError> {
        self.put_hinted(test_id, signer, storage_key, None, bytes)
    }

    /// [`AttestStore::put`] with the key's hint (vci 2.2: when the
    /// attestation was issued and the tree it was made on). An attestation
    /// of the same unit, signer and storage key stored under another hint
    /// (an earlier one of the same inputs) is replaced, as the same key was
    /// before.
    pub fn put_hinted(
        &self,
        test_id: &str,
        signer: &str,
        storage_key: &str,
        hint: Option<&KeyHint>,
        bytes: &[u8],
    ) -> Result<StoredEnvelope, GitError> {
        validate::signer_id(signer)?;
        validate::hex_id("storage_key", storage_key)?;
        let text = std::str::from_utf8(bytes).map_err(|_| GitError::Invalid {
            what: "envelope",
            value: String::new(),
            reason: "must be UTF-8",
        })?;
        let tk = vci_core::test_key(test_id);
        let target = target_for(test_id);
        let same_inputs: Vec<StoredEnvelope> = self
            .reader()?
            .candidates(test_id)?
            .into_iter()
            .filter(|e| e.signer == signer && e.storage_key == storage_key)
            .collect();
        let key = match hint {
            Some(h) => attestation_key_hinted(&tk, signer, storage_key, h),
            // No hint: the same inputs' existing key, whatever its hint
            // (a rewrite in place), else the plain key.
            None => same_inputs
                .first()
                .map(|e| e.key.clone())
                .unwrap_or_else(|| attestation_key(&tk, signer, storage_key)),
        };
        // The same inputs stored under another hint: replaced.
        let others: Vec<StoredEnvelope> =
            same_inputs.into_iter().filter(|e| e.key != key).collect();
        if !others.is_empty() {
            self.remove_envelopes(others)?;
        }
        let session = self.session()?;
        let handle = session.target(&target);
        let current = handle.get_value(&key).ok().flatten();
        if current != Some(MetaValue::String(text.to_owned())) {
            handle.set(&key, text).map_err(meta_err)?;
            self.stamp_written([(&target, key.as_str())])?;
        }
        Ok(StoredEnvelope {
            target: target_label(&target),
            key,
            test_key: tk,
            signer: signer.to_owned(),
            storage_key: storage_key.to_owned(),
            issued: hint.map(|h| h.issued),
            tree: hint.and_then(|h| h.tree.clone()),
            bytes: bytes.to_vec(),
            error: None,
        })
    }

    /// All stored envelopes, or only those for one test id.
    pub fn list(&self, test_id: Option<&str>) -> Result<Vec<StoredEnvelope>, GitError> {
        let r = self.reader()?;
        match test_id {
            Some(id) => r.candidates(id),
            None => r.all(),
        }
    }

    /// Delete one envelope (git-meta writes a tombstone, which `push`
    /// publishes). Returns whether it existed.
    pub fn remove(&self, e: &StoredEnvelope) -> Result<bool, GitError> {
        let target = Target::parse(&e.target).map_err(meta_err)?;
        let removed = self
            .session()?
            .target(&target)
            .remove(&e.key)
            .map_err(meta_err)?;
        if removed {
            self.stamp_written([(&target, e.key.as_str())])?;
        }
        Ok(removed)
    }

    /// Delete the envelopes of `test_id` signed by `signer` that `keep`
    /// rejects (one session; git-meta tombstones, published by `push`).
    /// Returns the deleted envelopes.
    pub fn remove_for_signer(
        &self,
        test_id: &str,
        signer: &str,
        keep: impl Fn(&StoredEnvelope) -> bool,
    ) -> Result<Vec<StoredEnvelope>, GitError> {
        let doomed: Vec<StoredEnvelope> = self
            .list(Some(test_id))?
            .into_iter()
            .filter(|e| e.signer == signer && !keep(e))
            .collect();
        self.remove_envelopes(doomed)
    }

    /// Delete these envelopes (one session; git-meta tombstones, published
    /// by `push`). Returns the ones that existed.
    pub fn remove_envelopes(
        &self,
        doomed: Vec<StoredEnvelope>,
    ) -> Result<Vec<StoredEnvelope>, GitError> {
        if doomed.is_empty() {
            return Ok(doomed);
        }
        let session = self.session()?;
        let mut removed = Vec::new();
        let mut targets = Vec::new();
        for e in doomed {
            let target = Target::parse(&e.target).map_err(meta_err)?;
            if session.target(&target).remove(&e.key).map_err(meta_err)? {
                targets.push(target);
                removed.push(e);
            }
        }
        self.stamp_written(
            targets
                .iter()
                .zip(&removed)
                .map(|(t, e)| (t, e.key.as_str())),
        )?;
        Ok(removed)
    }

    /// Store an input manifest's encoded `bytes` under its `root` (target
    /// `project`, key `vci:manifest:<root>`) unless the store already holds
    /// exactly those bytes. Returns whether a value was written. The caller
    /// guarantees `bytes` decode to a manifest whose root is `root` (a
    /// reader recomputes it anyway).
    pub fn put_manifest(&self, root: &str, bytes: &[u8]) -> Result<bool, GitError> {
        validate::hex_id("input root", root)?;
        let text = std::str::from_utf8(bytes).map_err(|_| GitError::Invalid {
            what: "manifest",
            value: String::new(),
            reason: "must be UTF-8",
        })?;
        let key = manifest_key(root);
        let session = self.session()?;
        let handle = session.target(&Target::project());
        let current = handle.get_value(&key).ok().flatten();
        if current == Some(MetaValue::String(text.to_owned())) {
            return Ok(false);
        }
        handle.set(&key, text).map_err(meta_err)?;
        self.stamp_written([(&Target::project(), key.as_str())])?;
        Ok(true)
    }

    /// The stored input manifest with this root (see [`Reader::manifest`]).
    pub fn manifest(&self, root: &str) -> Result<Option<StoredManifest>, GitError> {
        self.reader()?.manifest(root)
    }

    /// The roots of every stored input manifest.
    pub fn manifests(&self) -> Result<Vec<String>, GitError> {
        self.reader()?.manifest_roots()
    }

    /// The stored input manifest with this root, decoded (its base manifest
    /// read from the store when it has one): `None` when not stored, `Err`
    /// with why when it cannot be read or decoded.
    pub fn manifest_decoded(
        &self,
        root: &str,
    ) -> Result<Option<Result<vci_core::InputManifest, String>>, GitError> {
        let reader = self.reader()?;
        let Some(m) = reader.manifest(root)? else {
            return Ok(None);
        };
        Ok(Some(match m.error {
            Some(e) => Err(e),
            None => decode_manifest(&reader, &m.bytes),
        }))
    }

    /// Delete the stored input manifest with this root (a tombstone, which
    /// `push` publishes). Returns whether it existed.
    pub fn remove_manifest(&self, root: &str) -> Result<bool, GitError> {
        validate::hex_id("input root", root)?;
        let key = manifest_key(root);
        let removed = self
            .session()?
            .target(&Target::project())
            .remove(&key)
            .map_err(meta_err)?;
        if removed {
            self.stamp_written([(&Target::project(), key.as_str())])?;
        }
        Ok(removed)
    }

    /// Delete the stored input manifests with these roots, in one session
    /// (tombstones, which `push` publishes). Returns how many existed. A
    /// root that is not one is an error before anything is deleted.
    pub fn remove_manifests<'r>(
        &self,
        roots: impl IntoIterator<Item = &'r str>,
    ) -> Result<usize, GitError> {
        let mut keys = Vec::new();
        for root in roots {
            validate::hex_id("input root", root)?;
            keys.push(manifest_key(root));
        }
        if keys.is_empty() {
            return Ok(0);
        }
        let session = self.session()?;
        let project = Target::project();
        let mut removed = Vec::new();
        for key in keys {
            if session.target(&project).remove(&key).map_err(meta_err)? {
                removed.push(key);
            }
        }
        if !removed.is_empty() {
            self.stamp_written(removed.iter().map(|k| (&project, k.as_str())))?;
        }
        Ok(removed.len())
    }

    /// How many attestations are stored (values not read).
    pub fn count(&self) -> Result<usize, GitError> {
        self.reader()?.count()
    }

    // ---- lazy values -----------------------------------------------------

    /// Fetch the values of the stored attestations of these units that were
    /// not fetched yet (see the module docs), then those of the input
    /// manifests the units' attestations reference: at most two `git fetch`
    /// of object ids, whatever the number of units. Nothing is done (and
    /// nothing locked or written) when no value is missing. A fetch that
    /// fails leaves the values unread ([`Hydration::error`]): their units
    /// run.
    pub fn hydrate_units<'s>(
        &self,
        test_ids: impl IntoIterator<Item = &'s str>,
    ) -> Result<Hydration, GitError> {
        self.hydrate_units_choosing(test_ids, |c| (0..c.len()).collect())
    }

    /// [`AttestStore::hydrate_units`], fetching the input manifests of only
    /// the attestations `choose` picks among each unit's (by index into the
    /// unit's stored attestations, every one fetched by then): a plan checks
    /// a unit's newest attestation first and reads the others' manifests
    /// only when it fails, so it fetches the newest's here and the rest in a
    /// second round ([`AttestStore::hydrate_manifests`]) for the units that
    /// need them (2.1.13: vex's Rails jobs fetched 12,000 manifests to read
    /// 2,000).
    pub fn hydrate_units_choosing<'s>(
        &self,
        test_ids: impl IntoIterator<Item = &'s str>,
        choose: impl Fn(&[StoredEnvelope]) -> Vec<usize>,
    ) -> Result<Hydration, GitError> {
        let ids: BTreeSet<&str> = test_ids.into_iter().collect();
        if ids.is_empty() || self.reader()?.promised()? == 0 {
            return Ok(Hydration::default());
        }
        let wanted: BTreeSet<(String, String, String)> = ids
            .iter()
            .map(|id| {
                let t = target_for(id);
                (
                    t.target_type().as_str().to_owned(),
                    t.value().unwrap_or("").to_owned(),
                    vci_core::test_key(id),
                )
            })
            .collect();
        let _lock = self.exchange_lock()?;
        let remote = self.value_remote()?;
        let mut ctx = self.hydrate_ctx()?;
        // `choose` sees the candidates as stored (values not read): keys
        // with a hint (vci 2.2) say enough to pick the newest.
        let reader = self.reader()?;
        let mut chosen_keys: BTreeSet<(String, String, String)> = BTreeSet::new();
        for id in &ids {
            let cands = reader.candidates(id)?;
            for i in choose(&cands) {
                if let Some(e) = cands.get(i) {
                    let t = target_for(id);
                    chosen_keys.insert((
                        t.target_type().as_str().to_owned(),
                        t.value().unwrap_or("").to_owned(),
                        e.key.clone(),
                    ));
                }
            }
        }
        drop(reader);
        let mut out = self.hydrate_with(&mut ctx, &remote, |k| {
            parse_key(&k.key).is_some_and(|(tk, _, _)| {
                wanted.contains(&(
                    k.target_type.as_str().to_owned(),
                    k.target_value.clone(),
                    tk.to_owned(),
                ))
            }) && chosen_keys.contains(&(
                k.target_type.as_str().to_owned(),
                k.target_value.clone(),
                k.key.clone(),
            ))
        })?;
        let reader = self.reader()?;
        let mut roots = BTreeSet::new();
        for id in &ids {
            let t = target_for(id);
            for e in reader.candidates(id)? {
                if e.error.is_none()
                    && chosen_keys.contains(&(
                        t.target_type().as_str().to_owned(),
                        t.value().unwrap_or("").to_owned(),
                        e.key.clone(),
                    ))
                    && let Some(r) = envelope_manifest_ref(&e.bytes)
                {
                    roots.insert(r);
                }
            }
        }
        drop(reader);
        if !roots.is_empty() {
            out.add(self.hydrate_with(&mut ctx, &remote, |k| {
                k.target_type == TargetType::Project
                    && parse_manifest_key(&k.key).is_some_and(|r| roots.contains(r))
            })?);
            out.add(self.hydrate_bases_with(&mut ctx, &remote, &roots)?);
        }
        Ok(out)
    }

    /// Fetch the base manifests (vci 2.1.8: the entries a run's units share,
    /// stored once and named by each unit's manifest) of the stored
    /// manifests among `roots` that have one, when not fetched yet.
    fn hydrate_bases_with(
        &self,
        ctx: &mut HydrateCtx,
        remote: &str,
        roots: &BTreeSet<String>,
    ) -> Result<Hydration, GitError> {
        let reader = self.reader()?;
        let mut bases = BTreeSet::new();
        for r in roots {
            if let Some(m) = reader.manifest(r)?
                && m.error.is_none()
                && let Ok(Some(b)) = vci_core::InputManifest::compact_base(&m.bytes)
            {
                bases.insert(b);
            }
        }
        drop(reader);
        if bases.is_empty() {
            return Ok(Hydration::default());
        }
        self.hydrate_with(ctx, remote, |k| {
            k.target_type == TargetType::Project
                && parse_manifest_key(&k.key).is_some_and(|r| bases.contains(r))
        })
    }

    /// Fetch the stored input manifests with these roots that were not
    /// fetched yet (see [`AttestStore::hydrate_units`]).
    pub fn hydrate_manifests<'s>(
        &self,
        roots: impl IntoIterator<Item = &'s str>,
    ) -> Result<Hydration, GitError> {
        let roots: BTreeSet<&str> = roots.into_iter().collect();
        if roots.is_empty() || self.reader()?.promised()? == 0 {
            return Ok(Hydration::default());
        }
        let _lock = self.exchange_lock()?;
        let remote = self.value_remote()?;
        let mut ctx = self.hydrate_ctx()?;
        let mut out = self.hydrate_with(&mut ctx, &remote, |k| {
            k.target_type == TargetType::Project
                && parse_manifest_key(&k.key).is_some_and(|r| roots.contains(r))
        })?;
        let owned: BTreeSet<String> = roots.iter().map(|r| (*r).to_owned()).collect();
        out.add(self.hydrate_bases_with(&mut ctx, &remote, &owned)?);
        Ok(out)
    }

    /// Fetch every stored attestation not fetched yet (input manifests
    /// excluded): what reading the whole store (`vci prune`) needs. On a
    /// large store that is most of what a full fetch used to download.
    pub fn hydrate_attestations(&self) -> Result<Hydration, GitError> {
        if self.reader()?.promised()? == 0 {
            return Ok(Hydration::default());
        }
        let _lock = self.exchange_lock()?;
        let remote = self.value_remote()?;
        self.hydrate_locked(&remote, |k| parse_key(&k.key).is_some())
    }

    /// Before supersession deletes the stored input manifests among `roots`
    /// that no stored attestation references: fetch, in one batch, the
    /// attestations not fetched yet that could reference one of them, and
    /// return the roots that cannot be decided (keep them): a manifest that
    /// cannot be read, or one an attestation still not fetched could
    /// reference. Any other root is referenced by the readable attestations
    /// or by none (an attestation [`StoredEnvelope::not_fetched`] then
    /// cannot reference it).
    ///
    /// Which attestations could: one referencing a manifest was made by a
    /// unit that observed exactly the manifest's inputs, its own path among
    /// them (its test file, or the files of its package directory), so it is
    /// stored on the `project` target or on a path target at or above a
    /// path the manifest lists. (Were a unit's path ever missing from its
    /// own inputs, a manifest still referenced could go: its unit runs,
    /// and is attested again.)
    pub fn hydrate_manifest_referrers(
        &self,
        roots: &BTreeSet<String>,
    ) -> Result<BTreeSet<String>, GitError> {
        let is_attestation = |k: &Key| parse_key(&k.key).is_some();
        if roots.is_empty() || !self.promised_keys()?.iter().any(is_attestation) {
            return Ok(BTreeSet::new());
        }
        let _ = self.hydrate_manifests(roots.iter().map(String::as_str))?;
        let mut undecided = BTreeSet::new();
        let mut scopes: Vec<(&String, BTreeSet<String>)> = Vec::new();
        let reader = self.reader()?;
        for r in roots {
            let decoded = reader
                .manifest(r)?
                .filter(|m| m.error.is_none())
                .and_then(|m| decode_manifest(&reader, &m.bytes).ok());
            let Some(m) = decoded else {
                undecided.insert(r.clone());
                continue;
            };
            let mut paths = BTreeSet::new();
            for e in &m.entries {
                let p = e.path.as_str();
                paths.extend(p.match_indices('/').map(|(i, _)| p[..i].to_owned()));
                paths.insert(p.to_owned());
            }
            scopes.push((r, paths));
        }
        drop(reader);
        let may_reference = |k: &Key, paths: &BTreeSet<String>| {
            is_attestation(k)
                && (k.target_type == TargetType::Project
                    || k.target_type == TargetType::Path && paths.contains(&k.target_value))
        };
        let could = |k: &Key| scopes.iter().any(|(_, p)| may_reference(k, p));
        if self.promised_keys()?.iter().any(could) {
            let _lock = self.exchange_lock()?;
            if let Ok(remote) = self.value_remote() {
                self.hydrate_locked(&remote, could)?;
            }
        }
        let still = self.promised_keys()?;
        for (r, paths) in &scopes {
            if still.iter().any(|k| may_reference(k, paths)) {
                undecided.insert((*r).clone());
            }
        }
        Ok(undecided)
    }

    /// The metadata remote values are fetched from: the primary git-meta
    /// remote, the one `vci fetch` fetched them from.
    fn value_remote(&self) -> Result<String, GitError> {
        let remotes = self.remotes()?;
        remotes
            .iter()
            .find(|r| r.2 && !r.3)
            .map(|r| r.0.clone())
            .ok_or_else(|| {
                GitError::NoMetaRemote(
                    "no git-meta remote is configured to fetch values from; run `vci fetch`"
                        .to_owned(),
                )
            })
    }

    /// [`AttestStore::hydrate_units`]'s work for the promised rows `wanted`
    /// selects, the exchange lock held: their blobs are the ones at their
    /// keys' paths in `refs/<ns>/local/main` (a promised row stands for
    /// exactly that value), fetched from `remote` when missing, and each row
    /// whose blob is now here becomes a reference to it.
    fn hydrate_locked(
        &self,
        remote: &str,
        wanted: impl Fn(&Key) -> bool,
    ) -> Result<Hydration, GitError> {
        let mut ctx = self.hydrate_ctx()?;
        self.hydrate_with(&mut ctx, remote, wanted)
    }

    /// What the hydrations of one exchange read once (2.1.13: each of a
    /// plan's three rounds listed the store's promised rows and the whole
    /// local metadata tree, 12 s of a vex Rails job's 24 s value fetch).
    fn hydrate_ctx(&self) -> Result<HydrateCtx, GitError> {
        Ok(HydrateCtx {
            promised: self.promised_keys()?,
            local_ref: format!("refs/{}/local/main", self.namespace()?),
            snap: None,
        })
    }

    /// [`AttestStore::hydrate_locked`] with the rows and tree `ctx` holds;
    /// the rows resolved leave `ctx` (a later round does not ask for them).
    fn hydrate_with(
        &self,
        ctx: &mut HydrateCtx,
        remote: &str,
        wanted: impl Fn(&Key) -> bool,
    ) -> Result<Hydration, GitError> {
        let started = std::time::Instant::now();
        let promised: Vec<Key> = ctx.promised.iter().filter(|k| wanted(k)).cloned().collect();
        if promised.is_empty() {
            return Ok(Hydration::default());
        }
        if ctx.snap.is_none() {
            let Some(local) = self.read_ref(&ctx.local_ref)? else {
                return Ok(Hydration {
                    unresolved: promised.len(),
                    error: Some(format!("{} does not exist", ctx.local_ref)),
                    ..Default::default()
                });
            };
            ctx.snap = Some(self.snapshot_keys(&local)?);
        }
        let snap = ctx.snap.as_ref().expect("snapshot read above");
        let blobs: BTreeMap<&Key, &String> = promised
            .iter()
            .filter_map(|k| snap.value_blobs.get(k).map(|o| (k, o)))
            .collect();
        let oids: BTreeSet<String> = blobs.values().map(|o| (*o).clone()).collect();
        let (have, fetched, error) = self.ensure_blobs(remote, &oids)?;
        let mut out = Hydration {
            fetched,
            error,
            ..Default::default()
        };
        let resolve: Vec<(&Key, &String)> = blobs
            .iter()
            .filter(|(_, o)| have.contains(**o))
            .map(|(k, o)| (*k, *o))
            .collect();
        out.unresolved = promised.len() - resolve.len();
        if let Some((path, db)) = self.db_rw()? {
            let tx = db.unchecked_transaction().map_err(|e| sql_err(&path, e))?;
            for (k, oid) in &resolve {
                out.resolved += tx
                    .execute(
                        "UPDATE metadata SET value = ?4, value_type = 'string', is_git_ref = 1, is_promised = 0
                         WHERE target_type = ?1 AND target_value = ?2 AND key = ?3 AND is_promised = 1",
                        rusqlite::params![k.target_type.as_str(), k.target_value, k.key, oid],
                    )
                    .map_err(|e| sql_err(&path, e))?;
            }
            tx.commit().map_err(|e| sql_err(&path, e))?;
        }
        let resolved: Vec<Key> = resolve.iter().map(|(k, _)| (*k).clone()).collect();
        for k in &resolved {
            ctx.promised.remove(k);
        }
        if std::env::var_os("VCI_TIMING").is_some() {
            eprintln!(
                "vci: timing: fetch {} value(s) ({} blob(s) downloaded): {:.2}s",
                out.resolved,
                out.fetched,
                started.elapsed().as_secs_f64()
            );
        }
        Ok(out)
    }

    /// The objects reachable from `commit` but not from `tip` (the remote's,
    /// when it has one) that this clone does not have: what a push of
    /// `commit` would have to send without being able to read it.
    fn missing_for_push(
        &self,
        commit: &str,
        tip: Option<&str>,
    ) -> Result<BTreeSet<String>, GitError> {
        let mut git = self.repo.git().args([
            "rev-list",
            "--objects",
            "--missing=print",
            "--no-object-names",
            commit,
        ]);
        if let Some(t) = tip {
            git = git.arg(format!("^{t}"));
        }
        let out = git.env("GIT_NO_LAZY_FETCH", "1").run_str()?;
        Ok(out
            .lines()
            .filter_map(|l| l.strip_prefix('?'))
            .map(|o| o.trim().to_owned())
            .filter(|o| !o.is_empty())
            .collect())
    }

    /// A read-write connection to the store, `None` when there is none yet.
    fn db_rw(&self) -> Result<Option<(Utf8PathBuf, rusqlite::Connection)>, GitError> {
        let path = self.db_path()?;
        if !path.exists() {
            return Ok(None);
        }
        let db = rusqlite::Connection::open(&path).map_err(|e| sql_err(&path, e))?;
        db.busy_timeout(Duration::from_secs(5))
            .map_err(|e| sql_err(&path, e))?;
        let tables: i64 = db
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'metadata'",
                [],
                |r| r.get(0),
            )
            .map_err(|e| sql_err(&path, e))?;
        Ok((tables > 0).then_some((path, db)))
    }

    /// Stamps the store's log entry of each key just written (its latest)
    /// with the time now, after the write was committed.
    ///
    /// git-meta stamps a write with the time it was asked for, before the
    /// write waits for the store's lock, and its incremental serialization
    /// takes the rows stamped after the last materialization marker. A
    /// serialization running alongside (`vci push` or `git meta push` in
    /// another thread or process) takes its own time first, reads the
    /// modified rows (not this one, not committed yet), serializes them, and
    /// sets the marker to its time, which is later than this row's stamp:
    /// the row is never "modified since" a marker again, and never
    /// published (`serialize_checked` even finds nothing to serialize). This
    /// stamp is taken once the write is committed, so a serialization whose
    /// read missed the row took its time before the commit, and the row
    /// stays newer than its marker; one whose read had the row serialized
    /// it. (A stamp that is already newer is left alone.)
    fn stamp_written<'k>(
        &self,
        written: impl IntoIterator<Item = (&'k Target, &'k str)>,
    ) -> Result<(), GitError> {
        let mut written = written.into_iter().peekable();
        if written.peek().is_none() {
            return Ok(());
        }
        let Some((path, mut db)) = self.db_rw()? else {
            return Err(GitError::Store(
                "the git-meta store is gone right after a write".to_owned(),
            ));
        };
        let now = now_ms();
        let tx = db.transaction().map_err(|e| sql_err(&path, e))?;
        {
            let mut stmt = tx
                .prepare(
                    "UPDATE metadata_log SET timestamp = ?1
                     WHERE rowid = (
                         SELECT rowid FROM metadata_log
                         WHERE target_type = ?2 AND target_value = ?3 AND key = ?4
                         ORDER BY timestamp DESC, rowid DESC LIMIT 1
                     ) AND timestamp < ?1",
                )
                .map_err(|e| sql_err(&path, e))?;
            for (target, key) in written {
                stmt.execute(rusqlite::params![
                    now,
                    target.target_type().as_str(),
                    target.value().unwrap_or(""),
                    key
                ])
                .map_err(|e| sql_err(&path, e))?;
            }
        }
        tx.commit().map_err(|e| sql_err(&path, e))
    }

    /// The store's value rows (promised ones included, side-remote imports
    /// excluded, as git-meta's serialization reads them): key -> (time of the
    /// last write, promised).
    fn store_rows(&self) -> Result<BTreeMap<Key, (i64, bool)>, GitError> {
        let Some((path, db)) = self.db_rw()? else {
            return Ok(BTreeMap::new());
        };
        let mut stmt = db
            .prepare(
                "SELECT target_type, target_value, key, last_timestamp, is_promised
                 FROM metadata WHERE source_ref IS NULL",
            )
            .map_err(|e| sql_err(&path, e))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, bool>(4)?,
                ))
            })
            .map_err(|e| sql_err(&path, e))?;
        let mut out = BTreeMap::new();
        for r in rows {
            let (ty, value, key, ts, promised) = r.map_err(|e| sql_err(&path, e))?;
            if let Ok(target_type) = TargetType::from_str(&ty) {
                out.insert(
                    Key {
                        target_type,
                        target_value: value,
                        key,
                    },
                    (ts, promised),
                );
            }
        }
        Ok(out)
    }

    /// The keys of the store's promised rows.
    fn promised_keys(&self) -> Result<BTreeSet<Key>, GitError> {
        Ok(self
            .store_rows()?
            .into_iter()
            .filter(|(_, (_, p))| *p)
            .map(|(k, _)| k)
            .collect())
    }

    /// Point the store's rows for `entries` (key -> blob id in `commit`'s
    /// tree) at those values, reading none that is not here: a blob in the
    /// object database is stored as git-meta's merge stores the value (up to
    /// `inline_max` bytes in the row, a larger one as a reference to the
    /// blob), a missing one as a promised row. Like git-meta's own write of a
    /// value, it replaces the row and deletes a deletion record of the key;
    /// unlike it, nothing is logged as a local change (the tree already
    /// holds the value). Returns how many rows are promised.
    fn mark_values(
        &self,
        entries: &BTreeMap<Key, String>,
        commit: &str,
        now: i64,
        inline_max: usize,
    ) -> Result<usize, GitError> {
        if entries.is_empty() {
            return Ok(0);
        }
        let oids: BTreeSet<String> = entries.values().cloned().collect();
        let sizes = self.present_sizes(&oids)?;
        let small: BTreeSet<String> = sizes
            .iter()
            .filter(|(_, n)| usize::try_from(**n).is_ok_and(|n| n <= inline_max))
            .map(|(o, _)| o.clone())
            .collect();
        let read = self.read_blobs(&small)?;
        let Some((path, db)) = self.db_rw()? else {
            return Err(GitError::Store(
                "the git-meta store does not exist".to_owned(),
            ));
        };
        let tx = db.unchecked_transaction().map_err(|e| sql_err(&path, e))?;
        let mut promised = 0;
        for (k, oid) in entries {
            let here = sizes.contains_key(oid);
            promised += usize::from(!here);
            // git-meta's parse reads a value blob as (lossy) UTF-8, and its
            // merge keeps a value of up to its size limit in the row, as JSON.
            let inline = read
                .get(oid)
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .filter(|s| s.len() <= inline_max)
                .map(|s| serde_json::to_string(&s))
                .transpose()
                .map_err(|e| GitError::Store(format!("encoding a value: {e}")))?;
            let (value, git_ref) = match (&inline, here) {
                (Some(json), _) => (json.as_str(), false),
                (None, true) => (oid.as_str(), true),
                (None, false) => ("", false),
            };
            let (ty, tv, key) = (k.target_type.as_str(), &k.target_value, &k.key);
            tx.execute(
                "INSERT INTO metadata (target_type, target_value, key, value, value_type, last_timestamp, is_git_ref, is_promised, promised_commit, source_ref)
                 VALUES (?1, ?2, ?3, ?4, 'string', ?5, ?6, ?7, ?8, NULL)
                 ON CONFLICT(target_type, target_value, key) DO UPDATE
                 SET value = excluded.value, value_type = 'string', last_timestamp = excluded.last_timestamp,
                     is_git_ref = excluded.is_git_ref, is_promised = excluded.is_promised,
                     promised_commit = excluded.promised_commit, source_ref = NULL",
                rusqlite::params![
                    ty,
                    tv,
                    key,
                    value,
                    now,
                    git_ref,
                    !here,
                    if here { None } else { Some(commit) },
                ],
            )
            .map_err(|e| sql_err(&path, e))?;
            for sql in [
                "DELETE FROM list_values WHERE metadata_id IN
                 (SELECT rowid FROM metadata WHERE target_type = ?1 AND target_value = ?2 AND key = ?3)",
                "DELETE FROM set_values WHERE metadata_id IN
                 (SELECT rowid FROM metadata WHERE target_type = ?1 AND target_value = ?2 AND key = ?3)",
                "DELETE FROM tombstones WHERE tombstone_type = 'metadata'
                 AND target_type = ?1 AND target_value = ?2 AND key = ?3",
            ] {
                tx.execute(sql, rusqlite::params![ty, tv, key])
                    .map_err(|e| sql_err(&path, e))?;
            }
        }
        tx.commit().map_err(|e| sql_err(&path, e))?;
        Ok(promised)
    }

    /// Which of `oids` the local object database holds (nothing is fetched:
    /// `GIT_NO_LAZY_FETCH`).
    fn present(&self, oids: &BTreeSet<String>) -> Result<BTreeSet<String>, GitError> {
        Ok(self.present_sizes(oids)?.into_keys().collect())
    }

    /// The size of each blob of `oids` the local object database holds
    /// (nothing is fetched).
    ///
    /// Two steps, because `git cat-file --batch-check` asked about an object
    /// the repository does not hold tries the promisor remote first, and with
    /// lazy fetching off (`GIT_NO_LAZY_FETCH`) git before 2.45 then dies
    /// (`fatal: could not fetch <oid> from promisor remote`; Ubuntu 24.04's
    /// 2.43 does) instead of answering `missing`. `git rev-list
    /// --missing=allow-any` never fetches on any version, and with
    /// `--ignore-missing` an absent object named on its input is left out
    /// instead of being a `bad object`: it lists what is present, and only
    /// that is then asked for.
    fn present_sizes(&self, oids: &BTreeSet<String>) -> Result<BTreeMap<String, u64>, GitError> {
        if oids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let mut input = Vec::new();
        for o in oids {
            if !is_oid(o) {
                return Err(GitError::Parse(format!("not an object id: {o:?}")));
            }
            input.extend_from_slice(o.as_bytes());
            input.push(b'\n');
        }
        let listed = self
            .repo
            .git()
            .args([
                "rev-list",
                "--objects",
                "--no-walk",
                "--missing=allow-any",
                "--ignore-missing",
                "--stdin",
            ])
            .env("GIT_NO_LAZY_FETCH", "1")
            .run_with_stdin(&input)?;
        let mut input = Vec::new();
        for l in String::from_utf8_lossy(&listed).lines() {
            let o = l.split(' ').next().unwrap_or("");
            if oids.contains(o) {
                input.extend_from_slice(o.as_bytes());
                input.push(b'\n');
            }
        }
        if input.is_empty() {
            return Ok(BTreeMap::new());
        }
        let out = self
            .repo
            .git()
            .args([
                "cat-file",
                "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            ])
            .env("GIT_NO_LAZY_FETCH", "1")
            .run_with_stdin(&input)?;
        Ok(String::from_utf8_lossy(&out)
            .lines()
            .filter_map(|l| {
                let mut f = l.split(' ');
                match (f.next(), f.next(), f.next().map(str::parse::<u64>)) {
                    (Some(o), Some("blob"), Some(Ok(n))) if oids.contains(o) => {
                        Some((o.to_owned(), n))
                    }
                    _ => None,
                }
            })
            .collect())
    }

    /// Download the blobs `oids` from `remote` as a blobless clone fetches a
    /// value it reads (`git fetch --filter=blob:none --stdin`, in batches).
    fn fetch_blobs(&self, remote: &str, oids: &[&String]) -> Result<(), GitError> {
        // Several `git fetch` processes at once (since 2.1.11): the server
        // packs each want list on its own, so a plan's 8,000 values come in
        // a quarter of the time with four connections. VCI_FETCH_JOBS sets
        // how many (1: one after the other, as before).
        let jobs = fetch_jobs();
        if jobs <= 1 || oids.len() <= FETCH_BLOB_PARALLEL_MIN {
            for batch in oids.chunks(FETCH_BLOB_BATCH) {
                self.fetch_objects(remote, batch)?;
            }
            // Each fetch adds a pack: merged once they near gix's slots.
            self.consolidate_packs();
            return Ok(());
        }
        self.ensure_no_lazy_fetch_remote()?;
        let per = oids
            .len()
            .div_ceil(jobs)
            .clamp(FETCH_BLOB_PARALLEL_MIN, FETCH_BLOB_BATCH);
        let batches: Vec<&[&String]> = oids.chunks(per).collect();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let results: Vec<Result<(), GitError>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..jobs.min(batches.len()))
                .map(|_| {
                    let (next, batches) = (&next, &batches);
                    s.spawn(move || {
                        loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some(b) = batches.get(i) else {
                                return Ok(());
                            };
                            self.fetch_objects(remote, b)?;
                        }
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
                .collect()
        });
        let out: Result<(), GitError> = results.into_iter().collect();
        self.consolidate_packs();
        out
    }

    /// Merge the packs a batched fetch left (one per `git fetch`) into
    /// fewer, as git-meta does after its own batched fetches: gix (which
    /// git-meta reads the object database with) sizes its pack slots when
    /// a repository is opened, 32 at least, and once the packs outnumber
    /// them every read fails with "The slotmap turned out to be too small"
    /// (2.1.15: a laptop clone with 74 packs after a fetch of 10,000
    /// values could not materialize what it had just downloaded). A
    /// geometric repack is proportional to what was added; a git without
    /// it, or one that cannot repack, is not a reason to fail the fetch.
    fn consolidate_packs(&self) {
        // Only when the packs come near gix's 32 slots (2.3.1): a git
        // without a geometric repack (2.43, Ubuntu's) repacks the whole
        // repository instead, several seconds on vex's runners after each
        // batched fetch of a plan, which added a few packs at a time.
        if self.pack_count().is_some_and(|n| n < PACKS_BEFORE_REPACK) {
            return;
        }
        let repack = |args: &[&str]| {
            self.repo
                .git()
                .args(["-c", "gc.auto=0", "repack"])
                .args(args)
                .output_described()
                .map(|(_, out)| out.status.success())
                .unwrap_or(false)
        };
        if !repack(&["--geometric=2", "-d", "-q"]) {
            let _ = repack(REPACK_FALLBACK);
        }
    }

    /// How many packs the object database has, when that can be read.
    fn pack_count(&self) -> Option<usize> {
        let dir = self
            .repo
            .git()
            .args([
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "objects/pack",
            ])
            .run_str()
            .ok()?;
        let n = std::fs::read_dir(dir)
            .ok()?
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".pack"))
            .count();
        Some(n)
    }

    /// `git fetch --stdin` of the objects `oids` (blobs, or a tree with its
    /// subtrees) from `remote`, values left out, without negotiation: what
    /// git's own lazy fetch runs, except that `remote` is a promisor for
    /// this command only (see the module docs).
    fn fetch_objects(&self, remote: &str, oids: &[&String]) -> Result<(), GitError> {
        let mut input = Vec::new();
        for o in oids {
            input.extend_from_slice(o.as_bytes());
            input.push(b'\n');
        }
        self.filtered_fetch(remote, "blob:none")?
            .args(["-c", "fetch.negotiationAlgorithm=noop"])
            .args([
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-write-fetch-head",
                "--recurse-submodules=no",
                "--filter=blob:none",
                "--stdin",
                remote,
            ])
            .run_with_stdin(&input)?;
        Ok(())
    }

    /// The start of a `git fetch` from `remote` with `--filter` (the caller
    /// adds `fetch`, its options and `--filter=<filter>`): `remote` named a
    /// promisor on the command line, so git neither records it as one in
    /// the repository's configuration (which would make it the remote of
    /// every lazy fetch) nor refuses the objects it leaves out; the
    /// repository's own promisor is [`NO_LAZY_FETCH_REMOTE`], configured
    /// first so `git gc` and `git fsck` accept the objects left out.
    fn filtered_fetch(&self, remote: &str, filter: &str) -> Result<crate::cmd::Git, GitError> {
        self.ensure_no_lazy_fetch_remote()?;
        // No `gc --auto` after a metadata fetch (2.1.15): it detaches and
        // repacks the object database while the serialization and push that
        // follow read and write it; the user's own git runs it later.
        Ok(self.repo.git().args([
            "-c".to_owned(),
            format!("remote.{remote}.promisor=true"),
            "-c".to_owned(),
            format!("remote.{remote}.partialclonefilter={filter}"),
            "-c".to_owned(),
            "gc.auto=0".to_owned(),
        ]))
    }

    /// Configure [`NO_LAZY_FETCH_REMOTE`] as the repository's promisor
    /// remote unless it is (see the module docs).
    fn ensure_no_lazy_fetch_remote(&self) -> Result<(), GitError> {
        let section = format!("remote.{NO_LAZY_FETCH_REMOTE}");
        if self.config_get(&format!("{section}.promisor"))?.as_deref() == Some("true") {
            return Ok(());
        }
        self.config_set(&format!("{section}.skipFetchAll"), "true")?;
        self.config_set(&format!("{section}.skipDefaultUpdate"), "true")?;
        self.config_set(&format!("{section}.promisor"), "true")
    }

    /// Make `commit`'s whole tree present (not its values): a commit fetched
    /// without trees (`--filter=tree:0`), or one whose trees a fetch left
    /// out because the server counted them as reachable from a commit whose
    /// trees this clone never fetched, gets its tree and subtrees in one
    /// fetch of the tree's id. Nothing is fetched when they are here.
    fn complete_tree(&self, remote: &str, commit: &str) -> Result<(), GitError> {
        let complete = || -> Result<bool, GitError> {
            let (_, out) = self
                .repo
                .git()
                .args(["ls-tree", "-r", "-d", "-z", "--full-tree", commit])
                .env("GIT_NO_LAZY_FETCH", "1")
                .output_described()?;
            Ok(out.status.success())
        };
        if complete()? {
            return Ok(());
        }
        // The commit's own record (`<commit>^{tree}` wants the tree there).
        let raw = self
            .repo
            .git()
            .args(["cat-file", "commit", commit])
            .env("GIT_NO_LAZY_FETCH", "1")
            .run_str()?;
        let tree = raw
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("tree "))
            .filter(|t| is_oid(t))
            .ok_or_else(|| GitError::Parse(format!("no tree in commit {commit}")))?
            .to_owned();
        self.fetch_objects(remote, &[&tree])?;
        // A fetch of the tree's id can leave subtrees out (2.1.15: GitHub
        // served vex's 108,000-tree tip without 12 of them, twice in CI and
        // on a laptop, and served each of the 12 when asked by id): ask git
        // which are missing and fetch those by id, until none is.
        for _ in 0..COMPLETE_TREE_ROUNDS {
            if complete()? {
                return Ok(());
            }
            let missing = self.missing_trees(&tree)?;
            if missing.is_empty() {
                break;
            }
            self.fetch_objects(remote, &missing.iter().collect::<Vec<_>>())?;
        }
        if complete()? {
            Ok(())
        } else {
            Err(GitError::Meta(format!(
                "the tree of metadata commit {commit} is incomplete after fetching it from {remote}"
            )))
        }
    }

    /// The subtrees of `tree` this clone does not have (values left out).
    fn missing_trees(&self, tree: &str) -> Result<BTreeSet<String>, GitError> {
        let out = self
            .repo
            .git()
            .args([
                "rev-list",
                "--objects",
                "--missing=print",
                "--no-object-names",
                "--filter=blob:none",
                tree,
            ])
            .env("GIT_NO_LAZY_FETCH", "1")
            .run_str()?;
        Ok(out
            .lines()
            .filter_map(|l| l.strip_prefix('?'))
            .map(|o| o.trim().to_owned())
            .filter(|o| is_oid(o))
            .collect())
    }

    /// Make the blobs `oids` present, fetching the missing ones from
    /// `remote`: (the ones present now, how many were downloaded, why the
    /// fetch failed).
    fn ensure_blobs(
        &self,
        remote: &str,
        oids: &BTreeSet<String>,
    ) -> Result<(BTreeSet<String>, usize, Option<String>), GitError> {
        let mut have = self.present(oids)?;
        let missing: BTreeSet<String> = oids.difference(&have).cloned().collect();
        if missing.is_empty() {
            return Ok((have, 0, None));
        }
        let error = self
            .fetch_blobs(remote, &missing.iter().collect::<Vec<_>>())
            .err()
            .map(|e| e.to_string());
        let now = self.present(&missing)?;
        let fetched = now.len();
        have.extend(now);
        Ok((have, fetched, error))
    }

    /// The contents of the blobs `oids` that can be read.
    fn read_blobs(&self, oids: &BTreeSet<String>) -> Result<BTreeMap<String, Vec<u8>>, GitError> {
        let mut out = BTreeMap::new();
        if oids.is_empty() {
            return Ok(out);
        }
        let mut cat = CatFile::start(self.repo.root())?;
        for o in oids {
            match cat.blob(o) {
                Ok(b) => {
                    out.insert(o.clone(), b);
                }
                Err(_) => cat = CatFile::start(self.repo.root())?,
            }
        }
        Ok(out)
    }

    /// Every blob of `commit`'s tree.
    fn tree_blobs(&self, commit: &str) -> Result<BTreeSet<String>, GitError> {
        let listing = self
            .repo
            .git()
            .args(["ls-tree", "-r", "-z", "--full-tree"])
            .arg(format!("{commit}^{{tree}}"))
            .run()?;
        Ok(split_ls_tree(&listing)
            .into_iter()
            .filter(|(_, kind, _, _)| *kind == b"blob")
            .map(|(_, _, oid, _)| String::from_utf8_lossy(oid).into_owned())
            .collect())
    }

    /// Fetch every blob git-meta's own merge of these commits reads (it
    /// reads every value of the trees it merges, through gix, which never
    /// fetches a missing object).
    fn hydrate_trees(&self, remote: &str, commits: &[&str]) -> Result<usize, GitError> {
        let mut oids = BTreeSet::new();
        for c in commits {
            self.complete_tree(remote, c)?;
            oids.extend(self.tree_blobs(c)?);
        }
        let (have, fetched, error) = self.ensure_blobs(remote, &oids)?;
        if let Some(e) = error
            && have.len() < oids.len()
        {
            return Err(GitError::Meta(format!(
                "fetching the {} value(s) git-meta's merge reads: {e}",
                oids.len() - have.len()
            )));
        }
        Ok(fetched)
    }

    /// The empty tree's id (written if needed).
    fn empty_tree(&self) -> Result<String, GitError> {
        parse_oid(&self.repo.git().args(["mktree", "-z"]).run_with_stdin(b"")?)
    }

    // ---- remotes ---------------------------------------------------------

    /// The metadata namespace (`meta.namespace`, default `meta`).
    fn namespace(&self) -> Result<String, GitError> {
        Ok(self
            .config_get("meta.namespace")?
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "meta".to_owned()))
    }

    fn config_get(&self, key: &str) -> Result<Option<String>, GitError> {
        let (describe, out) = self
            .repo
            .git()
            .args(["config", "--get", key])
            .output_described()?;
        match out.status.code() {
            Some(0) => Ok(Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())),
            Some(1) => Ok(None),
            _ => Err(command_error(&describe, &out)),
        }
    }

    fn config_set(&self, key: &str, value: &str) -> Result<(), GitError> {
        self.repo.git().args(["config", key, value]).run()?;
        Ok(())
    }

    /// `(name, url, meta, side)` for every configured remote.
    fn remotes(&self) -> Result<Vec<(String, String, bool, bool)>, GitError> {
        let (describe, out) = self
            .repo
            .git()
            .args([
                "config",
                "-z",
                "--get-regexp",
                r"^remote\..*\.(url|meta|metaside)$",
            ])
            .output_described()?;
        if out.status.code() == Some(1) {
            return Ok(Vec::new());
        }
        if !out.status.success() {
            return Err(command_error(&describe, &out));
        }
        let mut map: BTreeMap<String, (String, bool, bool)> = Default::default();
        for rec in out.stdout.split(|b| *b == 0).filter(|r| !r.is_empty()) {
            let rec = String::from_utf8_lossy(rec);
            let (k, v) = rec.split_once('\n').unwrap_or((&rec, ""));
            let Some(rest) = k.strip_prefix("remote.") else {
                continue;
            };
            let Some((name, field)) = rest.rsplit_once('.') else {
                continue;
            };
            let e = map.entry(name.to_owned()).or_default();
            let truthy = matches!(v.trim(), "true" | "yes" | "on" | "1" | "");
            match field {
                "url" => e.0 = v.to_owned(),
                "meta" => e.1 = truthy,
                "metaside" => e.2 = truthy,
                _ => {}
            }
        }
        Ok(map.into_iter().map(|(n, (u, m, s))| (n, u, m, s)).collect())
    }

    /// Resolve (and if needed configure) the git-meta remote to exchange
    /// attestations with, and return its name.
    ///
    /// * `None`: the first primary metadata remote (`remote.<name>.meta =
    ///   true`); with none configured, one named `meta` is configured from the
    ///   `url:` in `.git-meta`, else from `origin`'s URL. A `.git-meta` URL
    ///   comes from the checkout, so it must be an https, http, ssh, git or
    ///   file URL, an scp-like address or a path (no remote helpers such as
    ///   `fd::` or `ext::`).
    /// * `Some(name)` of a metadata remote: that remote.
    /// * `Some(name)` of another remote (such as `origin`), or a URL / path: a
    ///   metadata remote with that URL (configured if there is none).
    pub fn ensure_remote(&self, spec: Option<&str>) -> Result<String, GitError> {
        if let Some(s) = spec {
            validate::remote(s)?;
        }
        let remotes = self.remotes()?;
        let url = match spec {
            None => {
                if let Some((n, ..)) = remotes
                    .iter()
                    .find(|r| r.2 && !r.3)
                    .or_else(|| remotes.iter().find(|r| r.2))
                {
                    return Ok(n.clone());
                }
                let from_file = match self.repo.work_tree() {
                    Some(root) => read_setup_url(&root.join(SETUP_FILE))?,
                    None => None,
                };
                if let Some(u) = &from_file {
                    validate::setup_url(u)?;
                }
                match from_file.or_else(|| {
                    remotes
                        .iter()
                        .find(|r| r.0 == "origin" && !r.1.is_empty())
                        .map(|r| r.1.clone())
                }) {
                    Some(u) => u,
                    None => {
                        return Err(GitError::NoMetaRemote(format!(
                            "no git-meta remote is configured, there is no {SETUP_FILE} file and no origin remote; run `vci init --meta-url <url>` or `git meta remote add <url>`"
                        )));
                    }
                }
            }
            Some(s) => match remotes.iter().find(|r| r.0 == s) {
                Some((n, _, true, _)) => return Ok(n.clone()),
                Some((_, u, false, _)) if !u.is_empty() => u.clone(),
                Some(_) => {
                    return Err(GitError::NoMetaRemote(format!("remote {s:?} has no URL")));
                }
                None => s.to_owned(),
            },
        };
        if let Some((n, ..)) = remotes.iter().find(|r| r.2 && r.1 == url) {
            return Ok(n.clone());
        }
        self.add_remote(&url, &remotes)
    }

    /// The names of the configured git remotes (metadata remotes or not).
    pub fn remote_names(&self) -> Result<Vec<String>, GitError> {
        Ok(self.remotes()?.into_iter().map(|r| r.0).collect())
    }

    /// The URL of a configured remote.
    pub fn remote_url(&self, name: &str) -> Result<Option<String>, GitError> {
        Ok(self
            .remotes()?
            .into_iter()
            .find(|r| r.0 == name)
            .map(|r| r.1))
    }

    /// Configure a metadata remote for `url` the way `git meta remote add`
    /// does (minus its starter commit; never as a promisor remote, see the
    /// module docs).
    fn add_remote(
        &self,
        url: &str,
        remotes: &[(String, String, bool, bool)],
    ) -> Result<String, GitError> {
        let taken = |n: &str| remotes.iter().any(|r| r.0 == n);
        let name = [DEFAULT_REMOTE_NAME.to_owned(), "vci-meta".to_owned()]
            .into_iter()
            .chain((2..100).map(|i| format!("vci-meta-{i}")))
            .find(|n| !taken(n))
            .ok_or_else(|| GitError::NoMetaRemote("no free remote name".into()))?;
        let side = remotes.iter().any(|r| r.2 && !r.3);
        let ns = self.namespace()?;
        let tracking = if side {
            format!("refs/{ns}/remotes/{name}/main")
        } else {
            format!("refs/{ns}/remotes/main")
        };
        self.config_set(&format!("remote.{name}.url"), url)?;
        self.config_set(
            &format!("remote.{name}.fetch"),
            &format!("+refs/{ns}/main:{tracking}"),
        )?;
        self.config_set(&format!("remote.{name}.meta"), "true")?;
        if side {
            self.config_set(&format!("remote.{name}.metaside"), "true")?;
        }
        Ok(name)
    }

    /// The local tracking ref of a metadata remote.
    /// The file recording the tip of `tracking` last materialized into this
    /// repository's store (in the git directory, next to git-meta's store).
    fn materialized_marker(&self, tracking: &str) -> Result<Utf8PathBuf, GitError> {
        let name: String = tracking
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        Ok(self
            .repo
            .git_dir()?
            .join(format!("vci-materialized-{name}")))
    }

    fn tracking_ref(&self, name: &str, ns: &str) -> Result<String, GitError> {
        let side = self.remotes()?.iter().any(|r| r.0 == name && r.2 && r.3);
        Ok(if side {
            format!("refs/{ns}/remotes/{name}/main")
        } else {
            format!("refs/{ns}/remotes/main")
        })
    }

    fn read_ref(&self, refname: &str) -> Result<Option<String>, GitError> {
        let (describe, out) = self
            .repo
            .git()
            .args(["rev-parse", "--verify", "--quiet"])
            .arg(format!("{refname}^{{commit}}"))
            .output_described()?;
        if out.status.success() {
            return parse_oid(&out.stdout).map(Some);
        }
        if out.status.code() == Some(1) {
            return Ok(None);
        }
        Err(command_error(&describe, &out))
    }

    /// Point `refname` at `new` if it still points at `old` (`None`: delete).
    fn cas_ref(
        &self,
        refname: &str,
        new: Option<&str>,
        old: &str,
        why: &str,
    ) -> Result<(), GitError> {
        let git = self.repo.git();
        match new {
            Some(n) => git.args(["update-ref", "-m", why, refname, n, old]).run()?,
            None => git
                .args(["update-ref", "-m", why, "-d", refname, old])
                .run()?,
        };
        Ok(())
    }

    fn is_ancestor(&self, a: &str, b: &str) -> Result<bool, GitError> {
        let (describe, out) = self
            .repo
            .git()
            .args(["merge-base", "--is-ancestor", a, b])
            .output_described()?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(command_error(&describe, &out)),
        }
    }

    /// Parse `commit`'s tree as git-meta does, leaving out entries git-meta
    /// cannot read (a name that is not UTF-8 fails git-meta's whole parse; a
    /// target it cannot serialize fails every later serialization).
    /// The keys `commit`'s tree holds, from its paths (see [`KeySnapshot`]).
    fn snapshot_keys(&self, commit: &str) -> Result<KeySnapshot, GitError> {
        let tree = self
            .repo
            .git()
            .args(["rev-parse", "--verify"])
            .arg(format!("{commit}^{{tree}}"))
            .run()?;
        let tree = parse_oid(&tree)?;
        let listing = self
            .repo
            .git()
            .args(["ls-tree", "-r", "-z", "--full-tree", &tree])
            .run()?;
        let records = split_ls_tree(&listing);
        let mut bad = Vec::new();
        let mut keep: Vec<u8> = Vec::new();
        let mut values = BTreeSet::new();
        let mut value_blobs = BTreeMap::new();
        let mut tombstones = BTreeSet::new();
        let mut tombstone_blobs = BTreeMap::new();
        let mut manifest_blobs = BTreeMap::new();
        let mut others = Vec::new();
        for (mode, kind, oid, path) in &records {
            let oid_str = || String::from_utf8_lossy(oid).into_owned();
            let reason = match std::str::from_utf8(path) {
                Err(_) => Some("name is not UTF-8"),
                Ok(p) => {
                    let parts: Vec<&str> = p.split('/').collect();
                    match parse_path_parts(&parts) {
                        Ok((ty, value, _)) if !valid_target(&ty, &value) => {
                            Some("target git-meta cannot serialize")
                        }
                        Ok((ty, value, key_parts)) => {
                            let key = |key: String| Key {
                                target_type: ty.clone(),
                                target_value: value.clone(),
                                key,
                            };
                            match classify_key_parts(key_parts) {
                                PathKey::Value(k) => {
                                    let k = key(k);
                                    if valid_key(&k) {
                                        if k.target_type == TargetType::Project
                                            && let Some(root) = parse_manifest_key(&k.key)
                                        {
                                            manifest_blobs.insert(root.to_owned(), oid_str());
                                        }
                                        value_blobs.insert(k.clone(), oid_str());
                                        values.insert(k);
                                    }
                                }
                                PathKey::Tombstone(k) => {
                                    let k = key(k);
                                    if valid_key(&k) {
                                        tombstone_blobs.insert(k.clone(), oid_str());
                                        tombstones.insert(k);
                                    }
                                }
                                PathKey::Other => others.push(p.to_owned()),
                            }
                            None
                        }
                        Err(_) => None,
                    }
                }
            };
            match reason {
                Some(r) => bad.push(format!("{} ({r})", String::from_utf8_lossy(path))),
                None => {
                    keep.extend_from_slice(mode);
                    keep.push(b' ');
                    keep.extend_from_slice(kind);
                    keep.push(b' ');
                    keep.extend_from_slice(oid);
                    keep.push(b'\t');
                    keep.extend_from_slice(path);
                    keep.push(0);
                }
            }
        }
        let clean_tree = if bad.is_empty() {
            None
        } else {
            let dir = tempfile::tempdir()?;
            let index = dir.path().join("index");
            self.repo
                .git()
                .args(["update-index", "-z", "--index-info"])
                .env("GIT_INDEX_FILE", &index)
                .run_with_stdin(&keep)?;
            let t = self
                .repo
                .git()
                .args(["write-tree", "--missing-ok"])
                .env("GIT_INDEX_FILE", &index)
                .run()?;
            Some(parse_oid(&t)?)
        };
        Ok(KeySnapshot {
            tree,
            values,
            value_blobs,
            tombstones,
            tombstone_blobs,
            manifest_blobs,
            others,
            bad,
            clean_tree,
        })
    }

    /// Parse `commit`'s tree as git-meta does (reading every value), leaving
    /// out entries git-meta cannot read.
    fn snapshot(&self, session: &Session, commit: &str) -> Result<Snapshot, GitError> {
        let KeySnapshot {
            tree, clean_tree, ..
        } = self.snapshot_keys(commit)?;
        let id = clean_tree.as_deref().unwrap_or(&tree);
        let oid = gix::ObjectId::from_hex(id.as_bytes())
            .map_err(|e| GitError::Parse(format!("object id {id}: {e}")))?;
        let mut parsed = guarded("parsing a git-meta tree", || {
            parse_tree(session.repo(), oid, "")
        })?;
        parsed.values.retain(|k, _| valid_key(k));
        parsed.tombstones.retain(|k, _| valid_key(k));
        parsed.set_tombstones.retain(|(k, _), _| valid_key(k));
        parsed.list_tombstones.retain(|(k, _), _| valid_key(k));
        Ok(Snapshot { parsed })
    }

    /// Delete store rows (values, deletion records) whose target git-meta
    /// cannot serialize: one such row (left by an earlier fetch of a
    /// malformed tree) fails every serialization. Returns how many.
    fn purge_unserializable_rows(&self) -> Result<usize, GitError> {
        let path = self.db_path()?;
        if !path.exists() {
            return Ok(0);
        }
        let db = rusqlite::Connection::open(&path).map_err(|e| sql_err(&path, e))?;
        db.busy_timeout(Duration::from_secs(5))
            .map_err(|e| sql_err(&path, e))?;
        let tables: i64 = db
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN ('metadata', 'tombstones')",
                [],
                |r| r.get(0),
            )
            .map_err(|e| sql_err(&path, e))?;
        if tables < 2 {
            return Ok(0);
        }
        let bad = |table: &str| -> Result<Vec<i64>, GitError> {
            let mut stmt = db
                .prepare(&format!(
                    "SELECT rowid, target_type, target_value FROM {table}"
                ))
                .map_err(|e| sql_err(&path, e))?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })
                .map_err(|e| sql_err(&path, e))?;
            let mut out = Vec::new();
            for r in rows {
                let (id, ty, value) = r.map_err(|e| sql_err(&path, e))?;
                let ok = TargetType::from_str(&ty).is_ok_and(|ty| valid_target(&ty, &value));
                if !ok {
                    out.push(id);
                }
            }
            Ok(out)
        };
        let values = bad("metadata")?;
        let deletions = bad("tombstones")?;
        if values.is_empty() && deletions.is_empty() {
            return Ok(0);
        }
        let tx = db.unchecked_transaction().map_err(|e| sql_err(&path, e))?;
        for id in &values {
            for sql in [
                "DELETE FROM list_values WHERE metadata_id = ?1",
                "DELETE FROM set_values WHERE metadata_id = ?1",
                "DELETE FROM metadata WHERE rowid = ?1",
            ] {
                tx.execute(sql, [id]).map_err(|e| sql_err(&path, e))?;
            }
        }
        for id in &deletions {
            tx.execute("DELETE FROM tombstones WHERE rowid = ?1", [id])
                .map_err(|e| sql_err(&path, e))?;
        }
        tx.commit().map_err(|e| sql_err(&path, e))?;
        Ok(values.len() + deletions.len())
    }

    /// Make the store cover `refs/<ns>/local/main`: copy in every value of
    /// that ref the store has neither a row nor a deletion record for (a new,
    /// emptied or replaced `.git/git-meta.sqlite`, or a linked worktree,
    /// whose store is its own while the ref is shared), and apply the ref's
    /// deletion records that are newer than the store's row. Without this,
    /// git-meta's serialization (a commit on top of that ref, built from the
    /// store alone) would delete those values for everyone on the next push.
    /// Returns how many entries were applied.
    fn cover_local_ref(
        &self,
        session: &Session,
        remote: &str,
        local_ref: &str,
    ) -> Result<usize, GitError> {
        let Some(local) = self.read_ref(local_ref)? else {
            return Ok(0);
        };
        let store = session.store();
        // Promised rows are rows: the store holds those values, unread.
        let rows: BTreeMap<Key, i64> = self
            .store_rows()?
            .into_iter()
            .map(|(k, (ts, _))| (k, ts))
            .collect();
        let deleted: BTreeSet<Key> = guarded("reading the store", || store.get_all_tombstones())?
            .into_iter()
            .map(|t| Key {
                target_type: t.target_type,
                target_value: t.target_value,
                key: t.key,
            })
            .collect();
        // The usual case, decided from the tree's paths alone: the store
        // holds (or deleted) every value of the ref, and every deletion the
        // ref records is one the store made itself (no row, a deletion
        // record), so nothing is restored and no value needs reading. A
        // deletion record for a key the store still holds needs its
        // timestamp, read below.
        let keys = self.snapshot_keys(&local)?;
        if keys
            .tombstones
            .iter()
            .all(|k| !rows.contains_key(k) && deleted.contains(k))
            && keys
                .values
                .iter()
                .all(|k| rows.contains_key(k) || deleted.contains(k))
        {
            return Ok(0);
        }
        if !keys.others.is_empty() {
            // A set or list value: git-meta parses the tree, every value
            // read, so every blob of it must be here first.
            self.hydrate_trees(remote, &[&local])?;
            let fresh = self.session()?;
            return self.cover_local_ref_parsed(&fresh, &local, &rows, &deleted);
        }
        // From the paths: a value the store lacks becomes a row pointing at
        // the ref's blob (promised when the blob is not here); only the
        // deletion records that may apply are read (tiny blobs, fetched in
        // one batch when missing).
        let missing: BTreeMap<Key, String> = keys
            .value_blobs
            .iter()
            .filter(|(k, _)| !rows.contains_key(*k) && !deleted.contains(*k))
            .map(|(k, o)| (k.clone(), o.clone()))
            .collect();
        let candidates: BTreeMap<&Key, &String> = keys
            .tombstone_blobs
            .iter()
            .filter(|(k, _)| rows.contains_key(*k) || !deleted.contains(*k))
            .collect();
        let oids: BTreeSet<String> = candidates.values().map(|o| (*o).clone()).collect();
        let (_, _, error) = self.ensure_blobs(remote, &oids)?;
        let read = self.read_blobs(&oids)?;
        let mut deletions: Vec<(&Key, Tombstone)> = Vec::new();
        for (k, oid) in candidates {
            // git-meta's parse skips a record it cannot read.
            let Some(t) = read
                .get(oid)
                .and_then(|b| serde_json::from_slice::<Tombstone>(b).ok())
            else {
                if let Some(e) = &error {
                    return Err(GitError::Meta(format!(
                        "fetching the deletion records of {local_ref}: {e}"
                    )));
                }
                continue;
            };
            let applies = match rows.get(k) {
                Some(ts) => *ts < t.timestamp,
                None => !deleted.contains(k),
            };
            if applies {
                deletions.push((k, t));
            }
        }
        if missing.is_empty() && deletions.is_empty() {
            return Ok(0);
        }
        let inline_max = guarded("reading the store", || store.object_max_size())?;
        self.mark_values(&missing, &local, now_ms(), inline_max)?;
        for (k, t) in &deletions {
            guarded("applying a deletion record", || {
                store.apply_tombstone(&k.to_target(), &k.key, &t.email, t.timestamp)
            })?;
        }
        Ok(missing.len() + deletions.len())
    }

    /// [`AttestStore::cover_local_ref`] for a ref holding entries only
    /// git-meta's parse reads (every blob of it present).
    fn cover_local_ref_parsed(
        &self,
        session: &Session,
        local: &str,
        rows: &BTreeMap<Key, i64>,
        deleted: &BTreeSet<Key>,
    ) -> Result<usize, GitError> {
        let store = session.store();
        let snap = self.snapshot(session, local)?;
        let missing: BTreeMap<Key, TreeValue> = snap
            .parsed
            .values
            .iter()
            .filter(|(k, _)| !rows.contains_key(*k) && !deleted.contains(*k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let set_t: BTreeMap<(Key, String), String> = snap
            .parsed
            .set_tombstones
            .iter()
            .filter(|((k, _), _)| missing.contains_key(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let list_t: BTreeMap<(Key, String), Tombstone> = snap
            .parsed
            .list_tombstones
            .iter()
            .filter(|((k, _), _)| missing.contains_key(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let deletions: Vec<(&Key, &Tombstone)> = snap
            .parsed
            .tombstones
            .iter()
            .filter(|(k, t)| match rows.get(*k) {
                Some(ts) => *ts < t.timestamp,
                None => !deleted.contains(*k),
            })
            .collect();
        if missing.is_empty() && deletions.is_empty() {
            return Ok(0);
        }
        let now = now_ms();
        let email = session.email().to_owned();
        guarded("restoring values into the store", || {
            store.apply_tree(&missing, &BTreeMap::new(), &set_t, &list_t, &email, now)
        })?;
        for (k, t) in &deletions {
            guarded("applying a deletion record", || {
                store.apply_tombstone(&k.to_target(), &k.key, &t.email, t.timestamp)
            })?;
        }
        Ok(missing.len() + deletions.len())
    }

    /// Every key the store has a deletion record for.
    fn deletion_records(&self, session: &Session) -> Result<BTreeSet<Key>, GitError> {
        Ok(
            guarded("reading the store", || session.store().get_all_tombstones())?
                .into_iter()
                .map(|t| Key {
                    target_type: t.target_type,
                    target_value: t.target_value,
                    key: t.key,
                })
                .collect(),
        )
    }

    /// vci attestation keys the store holds a value for (fetched or not).
    fn attestation_keys(&self) -> Result<BTreeSet<Key>, GitError> {
        Ok(self
            .store_rows()?
            .into_keys()
            .filter(|k| parse_key(&k.key).is_some())
            .collect())
    }

    /// git-meta's full serialization of the store onto `local_ref`, refused
    /// (and undone) when the new commit would drop a value the previous one
    /// held without the store having a deletion record for it: a filter rule
    /// that excludes or routes the key elsewhere, or a store that does not
    /// match the ref. Publishing such a commit would delete the value for
    /// everyone.
    fn serialize_checked(&self, session: &Session, local_ref: &str) -> Result<(), GitError> {
        let prev = self.read_ref(local_ref)?;
        // With filter rules (meta:filter, local:meta:filter), git-meta's
        // incremental serialization keeps the untouched targets' subtrees as
        // they are, so a rule that excludes vci's keys would leave the
        // published values in place but silently leave new ones out: the
        // full serialization applies the rules to everything, and the check
        // below then refuses the commit that drops values.
        let rules = guarded("reading git-meta filter rules", || {
            git_meta_lib::tree::filter::parse_filter_rules(session.store())
        })?;
        let full = !rules.is_empty();
        // Nothing changed in the store since it was last serialized or
        // materialized: the ref already holds it. (git-meta's serialization
        // with no modified rows rebuilds, and hashes, the whole tree.)
        if !full
            && prev.is_some()
            && let Some(since) = guarded("reading the store", || {
                session.store().get_last_materialized()
            })?
            && guarded("reading the store", || {
                session.store().get_modified_since(since)
            })?
            .is_empty()
        {
            return Ok(());
        }
        let deleted = self.deletion_records(session)?;
        let promised = self.promised_keys()?;
        // Incremental: only the targets with rows modified since the last
        // materialization are rebuilt (the rest of the tree is reused by
        // object id); a full serialization hashes every value of the store
        // again, most of the cost of a fetch or push on a large store. The
        // check below still refuses a commit that drops a value.
        let t = std::time::Instant::now();
        let fast = if full {
            Ok(None)
        } else {
            self.serialize_changed(session, local_ref)
        };
        match fast {
            Ok(Some(n)) => {
                if std::env::var_os("VCI_TIMING").is_some() {
                    eprintln!(
                        "vci: timing: serialize {n} changed entr{} onto the local metadata: {:.2}s",
                        if n == 1 { "y" } else { "ies" },
                        t.elapsed().as_secs_f64()
                    );
                }
                // Only keys with a row or a deletion record were written:
                // no value was dropped without one, and no value not fetched
                // fell out (the check below is for git-meta's rebuild).
                return Ok(());
            }
            other => {
                if let Err(e) = other
                    && std::env::var_os("VCI_TIMING").is_some()
                {
                    eprintln!(
                        "vci: serializing the changed entries failed ({e}); git-meta serializes"
                    );
                }
                let _ = guarded("serializing the git-meta store", || {
                    if full {
                        session.serialize_full()
                    } else {
                        session.serialize()
                    }
                })?;
            }
        }
        let new = self.read_ref(local_ref)?;
        let (Some(prev), Some(mut new)) = (prev, new) else {
            return Ok(());
        };
        if prev == new {
            return Ok(());
        }
        let before = self.snapshot_keys(&prev)?;
        let after = self.snapshot_keys(&new)?.values;
        let (graft, dropped): (Vec<&Key>, Vec<&Key>) = before
            .values
            .difference(&after)
            .filter(|k| !deleted.contains(*k))
            .partition(|k| promised.contains(*k));
        if !graft.is_empty() {
            // git-meta rebuilds a changed target's subtree from the rows it
            // holds values for, so the target's values not fetched yet fell
            // out: put them back at the blobs the previous commit held (the
            // values those rows stand for), without reading them.
            let entries: Vec<(&Key, &String)> = graft
                .iter()
                .filter_map(|k| before.value_blobs.get(*k).map(|o| (*k, o)))
                .collect();
            new = self.graft_values(local_ref, &new, &entries)?;
        }
        if dropped.is_empty() {
            return Ok(());
        }
        // Put the ref back; the store is unchanged.
        let _ = self.cas_ref(
            local_ref,
            Some(&prev),
            &new,
            "vci: undo serialization that drops keys",
        );
        Err(GitError::Meta(format!(
            "serializing the local git-meta store would drop {} value(s) of {local_ref} that it has no deletion record for (first: {} {}); a meta:filter rule (`git meta get project meta:filter`, `local:meta:filter`) probably excludes or routes them. Nothing was published",
            dropped.len(),
            target_label(&dropped[0].to_target()),
            dropped[0].key
        )))
    }

    /// git-meta's incremental serialization, for the entries vci writes,
    /// without rebuilding every changed target: the local metadata commit's
    /// tree with only the keys modified since the last serialization
    /// written again, each as git-meta writes it (a value's path holds the
    /// row's string, or the blob it names; a deletion record's path holds
    /// `{"timestamp","email"}`; a path without a row or record is
    /// removed), then the store marked serialized as of before it read.
    ///
    /// git-meta rebuilds a changed target's subtree from every row it
    /// holds: one new input manifest made it read and write every manifest
    /// on the `project` target (18 s a push on vex, with thousands). The
    /// result is the same tree when the local ref holds what the store
    /// held at the last serialization, which git-meta's incremental mode
    /// assumes too. Returns how many entries were written, or `None` when
    /// git-meta must serialize (no local metadata commit or marker yet,
    /// prune rules, a set or list value, a value not fetched, a row gone
    /// without a deletion record; or `VCI_SERIALIZE=git-meta`).
    fn serialize_changed(
        &self,
        session: &Session,
        local_ref: &str,
    ) -> Result<Option<usize>, GitError> {
        if std::env::var_os("VCI_SERIALIZE").is_some_and(|v| v == "git-meta") {
            return Ok(None);
        }
        let Some(prev) = self.read_ref(local_ref)? else {
            return Ok(None);
        };
        let store = session.store();
        let Some(since) = guarded("reading the store", || store.get_last_materialized())? else {
            return Ok(None);
        };
        if guarded("reading git-meta prune rules", || {
            git_meta_lib::prune::read_prune_rules(store)
        })?
        .is_some()
        {
            return Ok(None);
        }
        // As git-meta does: the marker is the time before the store is
        // read, so a row stored meanwhile stays newer than it.
        let now = now_ms();
        let modified = guarded("reading the store", || store.get_modified_since(since))?;
        let keys: BTreeSet<(TargetType, String, String)> = modified
            .into_iter()
            .map(|m| (m.target_type, m.target_value, m.key))
            .collect();
        let deleted: BTreeMap<(TargetType, String, String), Tombstone> =
            guarded("reading the store", || store.get_all_tombstones())?
                .into_iter()
                .map(|t| {
                    (
                        (t.target_type, t.target_value, t.key),
                        Tombstone {
                            timestamp: t.timestamp,
                            email: t.email,
                        },
                    )
                })
                .collect();
        let Some((db_path, db)) = self.db_rw()? else {
            return Ok(None);
        };
        let mut stmt = db
            .prepare(
                "SELECT value, value_type, is_git_ref, is_promised FROM metadata
                 WHERE target_type = ?1 AND target_value = ?2 AND key = ?3",
            )
            .map_err(|e| sql_err(&db_path, e))?;
        // Paths and their blob (an object id, or bytes to write), and the
        // paths to remove.
        let mut by_oid: Vec<(String, String)> = Vec::new();
        let mut by_bytes: Vec<(String, Vec<u8>)> = Vec::new();
        let mut removed: Vec<String> = Vec::new();
        for (tt, tv, key) in &keys {
            let target = if *tt == TargetType::Project {
                Target::project()
            } else {
                match Target::parse(&format!("{}:{tv}", tt.as_str())) {
                    Ok(t) => t,
                    Err(_) => return Ok(None),
                }
            };
            let (Ok(vpath), Ok(dpath)) = (
                git_meta_lib::tree_paths::tree_path(&target, key),
                git_meta_lib::tree_paths::tombstone_path(&target, key),
            ) else {
                return Ok(None);
            };
            let row: Option<(String, String, i64, i64)> = stmt
                .query_row(rusqlite::params![tt.as_str(), tv, key], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    e => Err(e),
                })
                .map_err(|e| sql_err(&db_path, e))?;
            match row {
                Some((value, vt, git_ref, promised)) => {
                    if vt != "string" || promised != 0 {
                        return Ok(None);
                    }
                    if git_ref != 0 {
                        if !is_oid(&value) {
                            return Ok(None);
                        }
                        by_oid.push((vpath, value));
                    } else {
                        let raw = serde_json::from_str::<String>(&value).unwrap_or(value);
                        by_bytes.push((vpath, raw.into_bytes()));
                    }
                }
                // A row gone without a deletion record (purged): git-meta
                // serializes, and the check after it decides.
                None if !deleted.contains_key(&(tt.clone(), tv.clone(), key.clone())) => {
                    return Ok(None);
                }
                None => removed.push(vpath),
            }
            match deleted.get(&(tt.clone(), tv.clone(), key.clone())) {
                Some(t) => {
                    let Ok(bytes) = serde_json::to_vec(t) else {
                        return Ok(None);
                    };
                    by_bytes.push((dpath, bytes));
                }
                None => removed.push(dpath),
            }
        }
        drop(stmt);
        drop(db);
        // The new blobs and the trees on their paths, written through gix
        // (only the subtrees that change; 2,000 entries through a git
        // index took 5 s on a laptop).
        let n = by_oid.len() + by_bytes.len() + removed.len();
        let repo = session.repo();
        let gerr =
            |e: &dyn std::fmt::Display| GitError::Meta(format!("writing the metadata tree: {e}"));
        let prev_tree_id = repo
            .rev_parse_single(format!("{prev}^{{tree}}").as_str())
            .map_err(|e| gerr(&e))?
            .detach();
        let mut editor = repo.edit_tree(prev_tree_id).map_err(|e| gerr(&e))?;
        for path in &removed {
            // A path the tree does not have is left alone.
            let _ = editor.remove(path.as_str());
        }
        for (path, oid) in &by_oid {
            let id = gix::ObjectId::from_hex(oid.as_bytes()).map_err(|e| gerr(&e))?;
            editor
                .upsert(path.as_str(), gix::objs::tree::EntryKind::Blob, id)
                .map_err(|e| gerr(&e))?;
        }
        for (path, bytes) in &by_bytes {
            let id = repo.write_blob(bytes).map_err(|e| gerr(&e))?.detach();
            editor
                .upsert(path.as_str(), gix::objs::tree::EntryKind::Blob, id)
                .map_err(|e| gerr(&e))?;
        }
        let tree = editor.write().map_err(|e| gerr(&e))?.detach().to_string();
        let prev_tree = prev_tree_id.to_string();
        if tree != prev_tree {
            let mut git = self.repo.git().args([
                "commit-tree",
                "--no-gpg-sign",
                &tree,
                "-p",
                &prev,
                "-m",
                &format!("vci: serialize {n} change(s)"),
            ]);
            for (k, v) in IDENTITY {
                git = git.env(k, v);
            }
            let commit = parse_oid(&git.run()?)?;
            self.cas_ref(local_ref, Some(&commit), &prev, "vci: serialize")?;
        }
        guarded("writing the store", || store.set_last_materialized(now))?;
        Ok(Some(n))
    }

    /// Rewrite `commit` (the tip of `local_ref`) with `entries` (key -> blob
    /// id) put back into its tree, none of the blobs read; the same commit
    /// otherwise (parents, message, author). Returns the new commit.
    fn graft_values(
        &self,
        local_ref: &str,
        commit: &str,
        entries: &[(&Key, &String)],
    ) -> Result<String, GitError> {
        let mut paths = Vec::new();
        for (k, oid) in entries {
            let p = guarded("building a git-meta tree path", || {
                git_meta_lib::tree_paths::tree_path(&k.to_target(), &k.key)
            })?;
            paths.push((p, oid.as_str()));
        }
        let tree = self.tree_with(Some(&format!("{commit}^{{tree}}")), &paths)?;
        let raw = self.repo.git().args(["cat-file", "commit", commit]).run()?;
        let mut lines = raw.splitn(2, |b| *b == b'\n');
        let (Some(first), Some(rest)) = (lines.next(), lines.next()) else {
            return Err(GitError::Parse(format!("commit {commit} has no header")));
        };
        if !first.starts_with(b"tree ") {
            return Err(GitError::Parse(format!(
                "commit {commit} does not start with its tree"
            )));
        }
        let mut obj = format!("tree {tree}\n").into_bytes();
        obj.extend_from_slice(rest);
        let c = self
            .repo
            .git()
            .args(["hash-object", "-t", "commit", "-w", "--stdin"])
            .run_with_stdin(&obj)?;
        let c = parse_oid(&c)?;
        self.cas_ref(
            local_ref,
            Some(&c),
            commit,
            "vci: keep the values not fetched yet",
        )?;
        Ok(c)
    }

    /// Write the tree `base` (a tree-ish; `None`: empty) with `entries`
    /// (path -> blob id) added or replaced, none of the blobs read.
    fn tree_with(
        &self,
        base: Option<&str>,
        entries: &[(String, &str)],
    ) -> Result<String, GitError> {
        let dir = tempfile::tempdir()?;
        let index = dir.path().join("index");
        if let Some(b) = base {
            self.repo
                .git()
                .args(["read-tree", b])
                .env("GIT_INDEX_FILE", &index)
                .run()?;
        }
        let mut info = Vec::new();
        for (path, oid) in entries {
            info.extend_from_slice(format!("100644 blob {oid}\t{path}").as_bytes());
            info.push(0);
        }
        self.repo
            .git()
            .args(["update-index", "-z", "--index-info"])
            .env("GIT_INDEX_FILE", &index)
            .run_with_stdin(&info)?;
        let t = self
            .repo
            .git()
            .args(["write-tree", "--missing-ok"])
            .env("GIT_INDEX_FILE", &index)
            .run()?;
        parse_oid(&t)
    }

    /// Warnings about project-target settings that affect attestations for
    /// everyone who exchanges metadata with this repository.
    fn settings_warnings(&self, session: &Session, report: &mut Report) {
        let store = session.store();
        let mut prune = Vec::new();
        for k in PRUNE_KEYS {
            if let Ok(Some(v)) = store.get(&Target::project(), k) {
                let v: String = serde_json::from_str(&v.value).unwrap_or(v.value);
                prune.push(format!("{k} = {v}"));
            }
        }
        if !prune.is_empty() {
            report.warn(format!(
                "git-meta auto-prune is configured in this repository's shared metadata ({}): every `git meta serialize` or `git meta push`, by anyone, then drops the least recently written keys, attestations included, from the remote and from every store that fetches it. Pruned attestations only make their units run until attested again (vci's own push never prunes). To turn it off: `git meta rm project meta:prune:max-keys` (and max-size), then `git meta push`",
                prune.join(", ")
            ));
        }
        match git_meta_lib::tree::filter::parse_filter_rules(store) {
            Err(e) => report.warn(format!("cannot read git-meta filter rules: {e}")),
            Ok(rules) => {
                let sample = attestation_key(&"0".repeat(64), &"0".repeat(16), &"0".repeat(64));
                match git_meta_lib::tree::filter::classify_key(&sample, &rules) {
                    Some(d) if d == ["main"] => {}
                    other => report.warn(format!(
                        "a git-meta filter rule (meta:filter or local:meta:filter on the project target) {} vci's attestation keys; vci refuses to fetch or push while serializing would drop them",
                        match other {
                            None => "excludes".to_owned(),
                            Some(d) => format!("routes to {} instead of main", d.join(",")),
                        }
                    )),
                }
            }
        }
    }

    /// Fetch the remote's `refs/<ns>/main` into its tracking ref (its
    /// commits and trees, no values: see the module docs), serialize local
    /// values, and materialize the remote's into the local store (git-meta's
    /// merge, done from the trees' paths). Same refs and result as `git meta
    /// pull`.
    pub fn fetch(&self, remote: Option<&str>) -> Result<FetchOutcome, GitError> {
        let _lock = self.exchange_lock()?;
        let name = self.ensure_remote(remote)?;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut report = Report::default();
            match self.fetch_named(&name, &mut report) {
                Ok(round) => {
                    return Ok(FetchOutcome {
                        remote: name,
                        found: round.found,
                        warnings: report.warnings,
                        notes: report.notes,
                    });
                }
                Err(e) if attempt < FETCH_ATTEMPTS && is_ref_race(&e) => {
                    backoff(attempt, 20, 500);
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn fetch_named(&self, name: &str, report: &mut Report) -> Result<Round, GitError> {
        let ns = self.namespace()?;
        let remote_ref = format!("refs/{ns}/main");
        let local_ref = format!("refs/{ns}/local/main");
        let tracking = self.tracking_ref(name, &ns)?;
        // Commits and trees only (a tree's paths are its keys): values are
        // fetched when read (see the module docs). The first fetch of the
        // tracking ref takes the commits alone (`tree:0`) and then the tip's
        // tree: the history is complete (never shallow) without
        // downloading the trees of every commit in it. Later ones take the
        // commits since the tip they have, with their trees, so the local
        // metadata commit and the remote's keep the history (and the merge
        // bases' trees) they share.
        let first = self.read_ref(&tracking)?.is_none();
        let refspec = format!("+{remote_ref}:{tracking}");
        // One round trip: fetch the ref, and read "not there yet" from git's
        // own error (an `ls-remote` first would be a second round trip, about
        // half a second against GitHub).
        let fetch = |filter: &str| -> Result<Vec<u8>, GitError> {
            self.filtered_fetch(name, filter)?
                .args([
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--no-write-fetch-head",
                    "--recurse-submodules=no",
                ])
                .arg(format!("--filter={filter}"))
                .arg(name)
                .arg(&refspec)
                .run()
        };
        // Each step's time under VCI_TIMING (2.1.14: a job's push spent 28 s
        // here before its 3.5 s materialize, in no step the log named).
        let timed = std::env::var_os("VCI_TIMING").is_some();
        let step = |what: &str, since: std::time::Instant| {
            if timed {
                eprintln!(
                    "vci: timing: fetch: {what}: {:.2}s",
                    since.elapsed().as_secs_f64()
                );
            }
        };
        let t = std::time::Instant::now();
        let mut fetched = fetch(if first { "tree:0" } else { "blob:none" });
        if first && matches!(&fetched, Err(e) if e.to_string().contains("filter")) {
            // A server that refuses tree filters (`uploadpackfilter.tree.allow
            // = false`) still serves blobless fetches.
            fetched = fetch("blob:none");
        }
        let found = match fetched {
            Ok(_) => true,
            Err(e) if is_missing_remote_ref(&e) => false,
            Err(e) => return Err(e),
        };
        step("git fetch (commits and trees)", t);
        if found && let Some(tip) = self.read_ref(&tracking)? {
            let t = std::time::Instant::now();
            self.complete_tree(name, &tip)?;
            step("complete the tip's tree", t);
        }
        let purged = self.purge_unserializable_rows()?;
        if purged > 0 {
            report.warn(format!(
                "removed {purged} entr{} from the local git-meta store whose target git-meta cannot serialize (left by an earlier fetch of a malformed tree)",
                if purged == 1 { "y" } else { "ies" }
            ));
        }
        // A fresh session sees the objects the fetch just wrote.
        let mut session = self.session()?;
        let mut remote_deleted = BTreeSet::new();
        let mut tip_snap: Option<KeySnapshot> = None;
        if found && let Some(tip) = self.read_ref(&tracking)? {
            let t = std::time::Instant::now();
            let snap = self.snapshot_keys(&tip)?;
            step("list the tip's keys", t);
            if let Some(clean) = &snap.clean_tree {
                // Merge a copy of the tip without what git-meta cannot read:
                // a commit on top of it, so a push stays a fast-forward. It is
                // made the same way every time (same tree, parent, identity
                // and date), so later fetches merge the same commit.
                let date = self
                    .repo
                    .git()
                    .args(["log", "-1", "--format=@%ct +0000", &tip])
                    .run_str()?;
                let mut git = self.repo.git().args([
                    "commit-tree",
                    "--no-gpg-sign",
                    clean,
                    "-p",
                    &tip,
                    "-m",
                    "vci: leave out entries git-meta cannot read",
                ]);
                for (k, v) in IDENTITY {
                    git = git.env(k, v);
                }
                let git = git
                    .env("GIT_AUTHOR_DATE", &date)
                    .env("GIT_COMMITTER_DATE", &date);
                let commit = parse_oid(&git.run()?)?;
                self.cas_ref(
                    &tracking,
                    Some(&commit),
                    &tip,
                    "vci: sanitize fetched metadata",
                )?;
                report.warn(format!(
                    "ignored {} entr{} of {name}'s {remote_ref} that git-meta cannot read (first: {}); a vci push publishes the tree without them",
                    snap.bad.len(),
                    if snap.bad.len() == 1 { "y" } else { "ies" },
                    snap.bad[0]
                ));
            }
            remote_deleted = snap.tombstones.clone();
            tip_snap = Some(snap);
        }
        let remote_manifest_blobs = tip_snap
            .as_ref()
            .map(|s| s.manifest_blobs.clone())
            .unwrap_or_default();
        let t = std::time::Instant::now();
        let restored = self.cover_local_ref(&session, name, &local_ref)?;
        step("cover the local ref", t);
        if restored > 0 {
            report.note(format!(
                "restored {restored} entr{} of {local_ref} into this repository's git-meta store, which did not hold them (a new or replaced .git/git-meta.sqlite, or a linked worktree)",
                if restored == 1 { "y" } else { "ies" }
            ));
        }
        let deleted_here = self.deletion_records(&session)?;
        // Taken before the serialization reads the store (see below).
        let serialized_as_of = now_ms();
        let t = std::time::Instant::now();
        self.serialize_checked(&session, &local_ref)?;
        step("serialize the local metadata", t);
        // Materializing is skipped when the fetched tip is the one
        // materialized into this store last time (and nothing had to be
        // restored into the store, which would mean it is not that store any
        // more).
        let tip_now = if found {
            self.read_ref(&tracking)?
        } else {
            None
        };
        let marker = self.materialized_marker(&tracking)?;
        let previous = std::fs::read_to_string(&marker)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| is_oid(s));
        // Nor is there anything to merge when the local metadata commit
        // descends from the fetched tip (this clone pushed it, or merged it
        // before, and stored more since): a merge took 5 s on a laptop to
        // change nothing.
        let local_now = self.read_ref(&local_ref)?;
        let descends = match (tip_now.as_deref(), local_now.as_deref()) {
            (Some(tip), Some(l)) if restored == 0 => {
                tip == l || self.is_ancestor(tip, l).unwrap_or(false)
            }
            _ => false,
        };
        // git-meta imports a side remote's values as rows of their own
        // (never serialized, the local ref left alone), not as a merge.
        let side = self
            .remotes()?
            .iter()
            .any(|r| r.3 && tracking == format!("refs/{ns}/remotes/{}/main", r.0));
        let materialized = (descends && !side)
            || tip_now
                .as_deref()
                .is_some_and(|tip| restored == 0 && previous.as_deref() == Some(tip));
        if found && !materialized {
            let before = self.attestation_keys()?;
            let manifests_before: BTreeSet<String> = if side {
                BTreeSet::new()
            } else {
                self.reader()?.manifest_roots()?.into_iter().collect()
            };
            let local_before = self.read_ref(&local_ref)?;
            let started = std::time::Instant::now();
            // From the trees' paths (see `materialize_lazy`); git-meta's
            // materialize, which reads every value of the trees it merges,
            // imports side remotes and is the fallback for anything else.
            // `VCI_MATERIALIZE=full` (tests): git-meta's merge, every value
            // fetched and read, to compare with.
            let full = std::env::var_os("VCI_MATERIALIZE").is_some_and(|v| v == "full");
            let lazy = match (&tip_now, &tip_snap) {
                (Some(tip), Some(snap)) if !side && !full => match self
                    .materialize_lazy(&session, name, &local_ref, &tracking, tip, snap, report)
                {
                    Ok(m) => m,
                    Err(e) => {
                        report.note(format!(
                            "merging {name}'s {remote_ref} from its paths failed ({e}); merged it in full, every value read"
                        ));
                        None
                    }
                },
                _ => None,
            };
            if lazy.is_none() {
                if let Some(tip) = &tip_now {
                    let mut commits = vec![tip.clone()];
                    if !side && let Some(l) = self.read_ref(&local_ref)? {
                        if let Some(b) = self.merge_base(&l, tip)? {
                            commits.push(b);
                        }
                        commits.push(l);
                    }
                    let commits: Vec<&str> = commits.iter().map(String::as_str).collect();
                    self.hydrate_trees(name, &commits)?;
                }
                let suffix = tracking
                    .strip_prefix(&format!("refs/{ns}/"))
                    .unwrap_or(&tracking)
                    .to_owned();
                // git-meta's materialize marks the store materialized as of
                // its time without reading what was modified, which would
                // leave out a row another writer stored since the
                // serialization above read the store (`vci run` beside this
                // fetch): it is pinned to the time that serialization is
                // marked as of (or the time before it read, when it had
                // nothing to do), so such a row stays newer than the marker
                // and the serialization that follows takes it, while the
                // rows the merge writes (the tree holds them) do not. A fresh
                // session reads the blobs just fetched.
                let marker = guarded("reading the store", || {
                    session.store().get_last_materialized()
                })?;
                let as_of = marker.map_or(serialized_as_of, |m| m.max(serialized_as_of));
                let pinned = self.session()?.with_timestamp(as_of);
                let _ = guarded("materializing fetched metadata", || {
                    pinned.materialize(Some(&suffix))
                })?;
                drop(pinned);
                session = self.session()?;
            }
            if std::env::var_os("VCI_TIMING").is_some() {
                let how = match &lazy {
                    Some(m) => format!(
                        "from paths{}, {} changed entr{}, {} not fetched",
                        if m.merged { ", a merge" } else { "" },
                        m.changed,
                        if m.changed == 1 { "y" } else { "ies" },
                        m.promised
                    ),
                    None => "full".to_owned(),
                };
                eprintln!(
                    "vci: timing: materialize ({how}): {:.2}s",
                    started.elapsed().as_secs_f64()
                );
            }
            if self.purge_unserializable_rows()? > 0 {
                report.warn(
                    "removed entries the merge wrote that git-meta cannot serialize".to_owned(),
                );
            }
            if !side {
                let back = self.restore_referenced_manifests(
                    &session,
                    name,
                    &manifests_before,
                    local_before.as_deref(),
                    &remote_manifest_blobs,
                )?;
                if back > 0 {
                    report.note(format!(
                        "put back {back} input manifest(s) that attestations here reference, which a `vci prune` or supersession elsewhere deleted; the next `vci push` publishes them"
                    ));
                }
            }
            // Materialize may have applied tombstones or legacy deletes.
            self.serialize_checked(&session, &local_ref)?;
            if lazy.as_ref().is_none_or(|m| m.merged)
                && !side
                && let Some(tip) = &tip_now
            {
                self.adopt_equal_tip(&local_ref, tip)?;
            }
            let after = self.attestation_keys()?;
            let implicit = before
                .difference(&after)
                .filter(|k| !remote_deleted.contains(*k))
                .count();
            if implicit > 0 {
                report.warn(format!(
                    "{implicit} attestation(s) were dropped from {name}'s {remote_ref} without a deletion record (git-meta's auto-prune does this) and are gone from this store too; their units run until attested again"
                ));
            }
            if let Some(tip) = &tip_now {
                let _ = std::fs::write(&marker, format!("{tip}\n"));
            }
        }
        self.settings_warnings(&session, report);
        Ok(Round {
            found,
            deleted_here,
        })
    }

    /// The merge base of two commits, `None` when they share no history.
    fn merge_base(&self, a: &str, b: &str) -> Result<Option<String>, GitError> {
        let (describe, out) = self
            .repo
            .git()
            .args(["merge-base", a, b])
            .output_described()?;
        match out.status.code() {
            Some(0) => parse_oid(&out.stdout).map(Some),
            Some(1) => Ok(None),
            _ => Err(command_error(&describe, &out)),
        }
    }

    /// Merge the fetched tip `tip` (whose tree `tip_snap` lists) into the
    /// store from the trees' paths, with the result of git-meta's
    /// materialize and without reading a value: git-meta's merge rules
    /// decide between values by equality only (a string conflict goes to
    /// the local side), so blob ids stand in for the values.
    ///
    /// * No local metadata commit (a clone's first fetch): every entry of the
    ///   tip is taken, as git-meta's fast-forward from nothing does.
    /// * `refs/<ns>/local/main` an ancestor of `tip` (the store, just
    ///   serialized onto it, holds exactly its tree): what `git diff-tree`
    ///   says changed is taken, as git-meta's fast-forward does.
    /// * Otherwise git-meta's three-way merge (two-way when the commits share
    ///   no history) of the trees' entries makes a merge commit, and what
    ///   differs between the local commit and it is taken.
    ///
    /// A value taken becomes a row pointing at its blob (promised when the
    /// blob is not here, see [`AttestStore::mark_values`]); deletion records
    /// are read (fetched in one batch when missing): the changed ones, and
    /// every other one the store holds differently is set back to the
    /// tree's, as git-meta's fast-forward does; a value the tree no longer
    /// has is deleted (git-meta's legacy delete, unless a merge keeps a
    /// deletion record for it); the local ref moves to the tip or the merge,
    /// and the store is marked materialized. The caller never asks for a
    /// side remote's tip, which git-meta imports instead of merging.
    ///
    /// `Ok(None)` applies nothing and leaves the merge to git-meta: another
    /// ref git-meta would materialize with this one, or an entry this does
    /// not read the way git-meta's parse does (a set or list value, a path
    /// that is not where git-meta writes its key, a mode change; noted in
    /// `report`).
    #[allow(clippy::too_many_arguments)]
    fn materialize_lazy(
        &self,
        session: &Session,
        remote: &str,
        local_ref: &str,
        tracking: &str,
        tip: &str,
        tip_snap: &KeySnapshot,
        report: &mut Report,
    ) -> Result<Option<Materialized>, GitError> {
        // Taken before anything is read: a row another writer stores from
        // here on is newer than the merge and stays to be serialized.
        let now = now_ms();
        let store = session.store();
        let since = guarded("reading the store", || store.get_last_materialized())?;
        // git-meta materializes every ref whose name starts with the
        // tracking ref's; any other such ref takes the full path.
        let dir = tracking.rsplit_once('/').map_or(tracking, |(d, _)| d);
        let refs = self
            .repo
            .git()
            .args(["for-each-ref", "--format=%(refname)", dir])
            .run_str()?;
        if refs
            .lines()
            .any(|r| r != tracking && r.starts_with(tracking))
        {
            return Ok(None);
        }
        let mut fallback = |why: String| -> Result<Option<Materialized>, GitError> {
            report.note(format!(
                "merged the fetched metadata in full, every value read: {why} is not merged from paths"
            ));
            Ok(None)
        };
        let local = self.read_ref(local_ref)?;
        // A fast-forward takes only what changed (a changed set or list entry
        // falls back below); taking a whole tree or merging two reads them
        // all.
        let set_or_list = |first: &String| format!("{first} (a git-meta set or list entry)");
        let (from_tree, to_commit, merged) = match &local {
            None if !tip_snap.others.is_empty() => {
                return fallback(set_or_list(&tip_snap.others[0]));
            }
            None => (self.empty_tree()?, tip.to_owned(), false),
            Some(l) if self.is_ancestor(l, tip)? => {
                (format!("{l}^{{tree}}"), tip.to_owned(), false)
            }
            Some(l) => match self.merge_from_paths(remote, l, tip, tip_snap)? {
                Err(why) => return fallback(why),
                Ok(m) => (format!("{l}^{{tree}}"), m, true),
            },
        };
        let merged_snap;
        let to_snap = if merged {
            merged_snap = self.snapshot_keys(&to_commit)?;
            &merged_snap
        } else {
            tip_snap
        };
        let raw = self
            .repo
            .git()
            .args(["diff-tree", "-r", "-z", "--no-renames", "--no-commit-id"])
            .arg(&from_tree)
            .arg(format!("{to_commit}^{{tree}}"))
            .run()?;
        let Some(changes) = Self::tree_changes(&raw) else {
            return fallback("git diff-tree output".to_owned());
        };
        let mut values: BTreeMap<Key, String> = BTreeMap::new();
        let mut changed_tombstones: BTreeMap<Key, String> = BTreeMap::new();
        let mut removed: Vec<Key> = Vec::new();
        for ([status, old_mode, new_mode, oid], path) in changes {
            let (key, tombstone) = match Self::classify_change(status, old_mode, new_mode, path) {
                Err(why) => return fallback(why),
                Ok(None) => continue,
                Ok(Some(c)) => c,
            };
            if status == "D" {
                // The tree no longer has the value. Still holding it (under
                // another spelling of its path) is not something to guess.
                if to_snap.values.contains(&key) {
                    return fallback(String::from_utf8_lossy(path).into_owned());
                }
                removed.push(key);
            } else if tombstone {
                changed_tombstones.insert(key, oid.to_owned());
            } else {
                if !to_snap.values.contains(&key) {
                    return fallback(String::from_utf8_lossy(path).into_owned());
                }
                values.insert(key, oid.to_owned());
            }
        }
        // In one tree a value wins over a deletion record of its key.
        changed_tombstones.retain(|k, _| !to_snap.values.contains(k) && !values.contains_key(k));
        // git-meta's fast-forward applies every deletion record of the tree,
        // not only the changed ones: a record this store holds with another
        // time or email than the tree's is set back to the tree's. (A value
        // deleted by an earlier merge was stamped with that merge's own time
        // and email, git-meta's legacy delete below, until the next merge.)
        // Compared by blob id first, the blob git-meta writes for the stored
        // record, so only a record that differs is read.
        let held: BTreeMap<Key, Tombstone> =
            guarded("reading the store", || store.get_all_tombstones())?
                .into_iter()
                .map(|t| {
                    (
                        Key {
                            target_type: t.target_type,
                            target_value: t.target_value,
                            key: t.key,
                        },
                        Tombstone {
                            timestamp: t.timestamp,
                            email: t.email,
                        },
                    )
                })
                .collect();
        let restamp: BTreeMap<Key, String> = {
            let skip: BTreeSet<&Key> = removed.iter().chain(changed_tombstones.keys()).collect();
            to_snap
                .tombstone_blobs
                .iter()
                .filter(|(k, oid)| {
                    !to_snap.values.contains(*k)
                        && !skip.contains(*k)
                        && !held
                            .get(*k)
                            .is_some_and(|t| tombstone_blob_id(t, oid).as_deref() == Some(oid))
                })
                .map(|(k, o)| (k.clone(), o.clone()))
                .collect()
        };
        let oids: BTreeSet<String> = changed_tombstones
            .values()
            .chain(restamp.values())
            .cloned()
            .collect();
        let (have, _, error) = self.ensure_blobs(remote, &oids)?;
        if let Some(e) = error
            && changed_tombstones.values().any(|o| !have.contains(o))
        {
            return Err(GitError::Meta(format!(
                "fetching the deletion records of {tracking}: {e}"
            )));
        }
        let read = self.read_blobs(&oids)?;
        let tombstone = |oid: &String| {
            read.get(oid)
                .and_then(|b| serde_json::from_slice::<Tombstone>(b).ok())
        };
        let mut tombstones: BTreeMap<Key, Tombstone> = BTreeMap::new();
        for (k, oid) in &changed_tombstones {
            let Some(t) = tombstone(oid) else {
                return fallback(format!(
                    "the deletion record of {} {} (unreadable)",
                    target_label(&k.to_target()),
                    k.key
                ));
            };
            tombstones.insert(k.clone(), t);
        }
        // git-meta's parse skips a record it cannot read.
        let restamped: Vec<(Key, Tombstone)> = restamp
            .iter()
            .filter_map(|(k, oid)| tombstone(oid).map(|t| (k.clone(), t)))
            .filter(|(k, t)| held.get(k) != Some(t))
            .collect();
        let changed = values.len() + tombstones.len() + removed.len();
        let inline_max = guarded("reading the store", || store.object_max_size())?;
        let promised = self.mark_values(&values, &to_commit, now, inline_max)?;
        let email = session.email().to_owned();
        if !tombstones.is_empty() {
            guarded("applying fetched metadata", || {
                store.apply_tree(
                    &BTreeMap::new(),
                    &tombstones,
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    &email,
                    now,
                )
            })?;
        }
        for (k, t) in &restamped {
            guarded("applying a deletion record", || {
                store.apply_tombstone(&k.to_target(), &k.key, &t.email, t.timestamp)
            })?;
        }
        // The values deleted now are stamped after the tree's records, as
        // git-meta does; a merge keeps the deletion record its tree holds.
        let legacy: Vec<&Key> = removed
            .iter()
            .filter(|k| !(merged && to_snap.tombstones.contains(*k)))
            .collect();
        for k in &legacy {
            guarded("applying a deletion", || {
                store.apply_tombstone(&k.to_target(), &k.key, &email, now)
            })?;
        }
        match &local {
            Some(l) if *l == to_commit => {}
            Some(l) => self.cas_ref(local_ref, Some(&to_commit), l, "vci: materialize")?,
            None => self.cas_ref(local_ref, Some(&to_commit), "", "vci: materialize")?,
        }
        // Marked materialized (git-meta's next serialization then skips
        // what this merge wrote, which the tree already holds) only when every
        // row modified since the last serialization is one this merge wrote:
        // a row another writer (a `vci run` beside this fetch, a git-meta
        // client) stored meanwhile must stay modified, or it would never be
        // published. Otherwise the serialization that follows rewrites what
        // this merge wrote, unchanged, with it. (The values taken are not
        // logged as changes at all.)
        let ours: BTreeSet<&Key> = tombstones
            .keys()
            .chain(removed.iter())
            .chain(restamped.iter().map(|(k, _)| k))
            .collect();
        let others = guarded("reading the store", || {
            store.get_modified_since(since.unwrap_or(0))
        })?
        .into_iter()
        .any(|m| {
            !ours.contains(&Key {
                target_type: m.target_type,
                target_value: m.target_value,
                key: m.key,
            })
        });
        if !others {
            guarded("recording the materialization", || {
                store.set_last_materialized(now)
            })?;
        }
        Ok(Some(Materialized {
            changed,
            merged,
            promised,
        }))
    }

    /// git-meta's merge of the local metadata commit `local` and the fetched
    /// tip `tip` (three-way on their merge base, two-way without one), on
    /// the trees' entries with blob ids standing in for the values, written
    /// as a merge commit (parents `local` and `tip`) without reading a
    /// value. `Ok(Err(why))` when a tree holds what only git-meta's own
    /// merge reads.
    fn merge_from_paths(
        &self,
        remote: &str,
        local: &str,
        tip: &str,
        tip_snap: &KeySnapshot,
    ) -> Result<Result<String, String>, GitError> {
        use git_meta_lib::tree::merge::{
            merge_tombstones, three_way_merge, two_way_merge_no_common_ancestor,
        };
        let base = self.merge_base(local, tip)?;
        let ours = self.snapshot_keys(local)?;
        let base_snap = match &base {
            Some(b) => {
                // The first fetch of a tracking ref takes commits without
                // their trees (only the tip's).
                self.complete_tree(remote, b)?;
                Some(self.snapshot_keys(b)?)
            }
            None => None,
        };
        if let Some(first) = ours
            .others
            .first()
            .or_else(|| tip_snap.others.first())
            .or_else(|| base_snap.as_ref().and_then(|b| b.others.first()))
        {
            return Ok(Err(format!("{first} (a git-meta set or list entry)")));
        }
        let values = |s: &KeySnapshot| -> BTreeMap<Key, TreeValue> {
            s.value_blobs
                .iter()
                .map(|(k, o)| (k.clone(), TreeValue::String(o.clone())))
                .collect()
        };
        let tombstones = |s: &KeySnapshot| -> BTreeMap<Key, Tombstone> {
            s.tombstone_blobs
                .iter()
                .map(|(k, o)| {
                    (
                        k.clone(),
                        Tombstone {
                            timestamp: 0,
                            email: o.clone(),
                        },
                    )
                })
                .collect()
        };
        let (mut merged_values, mut merged_tombstones) = match &base_snap {
            Some(b) => {
                let (mv, _) = guarded("merging metadata", || {
                    three_way_merge(&values(b), &values(&ours), &values(tip_snap), 0, 0)
                })?;
                let mt = merge_tombstones(
                    &tombstones(b),
                    &tombstones(&ours),
                    &tombstones(tip_snap),
                    &mv,
                );
                (mv, mt)
            }
            None => {
                let (mv, mt, _) = two_way_merge_no_common_ancestor(
                    &values(&ours),
                    &tombstones(&ours),
                    &values(tip_snap),
                    &tombstones(tip_snap),
                );
                (mv, mt)
            }
        };
        // A value whose blob this clone never had (a promised row: the
        // remote's value, never written here) that the merge keeps although
        // the tip no longer holds it takes the tip's state instead. git-meta
        // keeps the local side of a conflict, and a two-way merge (the
        // remote's history rewritten) keeps every local value; but this one
        // was never local, the remote dropped it, and a push could not
        // publish a blob it does not have (once the remote's gc removed
        // it, nobody can).
        let unsure: BTreeSet<String> = merged_values
            .iter()
            .filter_map(|(k, v)| match v {
                TreeValue::String(o) if tip_snap.value_blobs.get(k) != Some(o) => Some(o.clone()),
                _ => None,
            })
            .collect();
        let here = self.present(&unsure)?;
        let never_had: Vec<Key> = merged_values
            .iter()
            .filter(|(_, v)| matches!(v, TreeValue::String(o) if unsure.contains(o) && !here.contains(o)))
            .map(|(k, _)| k.clone())
            .collect();
        for k in never_had {
            merged_values.remove(&k);
            if let Some(o) = tip_snap.value_blobs.get(&k) {
                merged_values.insert(k, TreeValue::String(o.clone()));
            } else if let Some(o) = tip_snap.tombstone_blobs.get(&k) {
                merged_tombstones.insert(
                    k,
                    Tombstone {
                        timestamp: 0,
                        email: o.clone(),
                    },
                );
            }
        }
        let mut entries: Vec<(String, &str)> = Vec::new();
        for (k, v) in &merged_values {
            let TreeValue::String(oid) = v else {
                return Ok(Err("a git-meta set or list value".to_owned()));
            };
            let Ok(p) = git_meta_lib::tree_paths::tree_path(&k.to_target(), &k.key) else {
                return Ok(Err(format!("{} {}", target_label(&k.to_target()), k.key)));
            };
            entries.push((p, oid));
        }
        for (k, t) in &merged_tombstones {
            let Ok(p) = git_meta_lib::tree_paths::tombstone_path(&k.to_target(), &k.key) else {
                return Ok(Err(format!("{} {}", target_label(&k.to_target()), k.key)));
            };
            entries.push((p, &t.email));
        }
        let tree = self.tree_with(None, &entries)?;
        let mut git = self.repo.git().args([
            "commit-tree",
            "--no-gpg-sign",
            &tree,
            "-p",
            local,
            "-p",
            tip,
            "-m",
            "materialize",
        ]);
        for (k, v) in IDENTITY {
            git = git.env(k, v);
        }
        Ok(Ok(parse_oid(&git.run()?)?))
    }

    /// Put back the stored input manifests this merge left deleted although
    /// an attestation in the store references them, from the tree that
    /// still has them (the fetched tip, whose manifest blobs are
    /// `tip_blobs`, or `local_before`, the local metadata commit before the
    /// merge). Two clones cross that way: one
    /// deletes a manifest no attestation it knows of references (`vci
    /// prune`, supersession), while the other publishes, or holds, an
    /// attestation referencing it; git-meta's merge then keeps the deletion
    /// (one side deleted, the other left the value alone), and the
    /// attestation would run its unit until re-attested. Only manifests
    /// deleted in the store that the store held before the merge or the tip
    /// holds are candidates, so a merge that deletes no manifest reads no
    /// attestation; the bytes put back must decode to a manifest with the
    /// root they are stored under. Returns how many were put back.
    fn restore_referenced_manifests(
        &self,
        session: &Session,
        remote: &str,
        before: &BTreeSet<String>,
        local_before: Option<&str>,
        tip_blobs: &BTreeMap<String, String>,
    ) -> Result<usize, GitError> {
        let store = session.store();
        let deleted: BTreeSet<String> =
            guarded("reading the store", || store.get_all_tombstones())?
                .into_iter()
                .filter(|t| t.target_type == TargetType::Project)
                .filter_map(|t| parse_manifest_key(&t.key).map(str::to_owned))
                .filter(|r| before.contains(r) || tip_blobs.contains_key(r))
                .collect();
        if deleted.is_empty() {
            return Ok(0);
        }
        let handle = session.target(&Target::project());
        let mut candidates = BTreeSet::new();
        for r in deleted {
            if handle.get_value(&manifest_key(&r)).ok().flatten().is_none() {
                candidates.insert(r);
            }
        }
        if candidates.is_empty() {
            return Ok(0);
        }
        // Which attestations reference them needs every attestation read:
        // fetch the ones not fetched yet (rare: a merge just deleted a
        // manifest). One that still cannot be read might reference any of
        // them, so then every candidate is put back (an unreferenced
        // manifest only takes space until `vci prune`).
        let fetched = self.hydrate_locked(remote, |k| parse_key(&k.key).is_some());
        let all = self.list(None)?;
        let referenced: BTreeSet<String> =
            if fetched.is_err() || all.iter().any(|e| e.error.is_some()) {
                candidates.clone()
            } else {
                all.iter()
                    .filter_map(|e| envelope_manifest_ref(&e.bytes))
                    .collect()
            };
        let mut back = 0;
        let project = Target::project();
        let mut put_back: Vec<String> = Vec::new();
        for root in candidates.intersection(&referenced) {
            let key = manifest_key(root);
            let mut sources: Vec<String> = Vec::new();
            if let Some(oid) = tip_blobs.get(root) {
                sources.push(oid.clone());
            }
            if let Some(local) = local_before {
                let path = guarded("building a git-meta tree path", || {
                    git_meta_lib::tree_paths::tree_path(&Target::project(), &key)
                })?;
                sources.push(format!("{local}:{path}"));
            }
            for src in sources {
                let Ok(bytes) = self.repo.git().args(["cat-file", "blob", &src]).run() else {
                    continue;
                };
                let ok = self
                    .reader()
                    .ok()
                    .and_then(|reader| decode_manifest(&reader, &bytes).ok())
                    .is_some_and(|m| m.root() == *root);
                let Ok(text) = String::from_utf8(bytes) else {
                    continue;
                };
                if !ok {
                    continue;
                }
                guarded("putting back an input manifest", || {
                    handle.set(&key, text.as_str())
                })?;
                put_back.push(key);
                back += 1;
                break;
            }
        }
        self.stamp_written(put_back.iter().map(|k| (&project, k.as_str())))?;
        Ok(back)
    }

    /// After git-meta merged `tip` into the local metadata commit: when the
    /// merge commit holds exactly the tip's tree (nothing local that the tip
    /// lacks, such as after the remote's history was rewritten), point the
    /// local ref at the tip itself. The next fetch is then a fast-forward
    /// (merged incrementally) instead of another merge, and a push has
    /// nothing to send rather than the old history merged back in.
    fn adopt_equal_tip(&self, local_ref: &str, tip: &str) -> Result<(), GitError> {
        let Some(local) = self.read_ref(local_ref)? else {
            return Ok(());
        };
        if local == tip {
            return Ok(());
        }
        let tree = |c: &str| {
            self.repo
                .git()
                .args(["rev-parse", "--verify"])
                .arg(format!("{c}^{{tree}}"))
                .run()
                .and_then(|o| parse_oid(&o))
        };
        if tree(&local)? != tree(tip)? {
            return Ok(());
        }
        self.cas_ref(
            local_ref,
            Some(tip),
            &local,
            "vci: the merge holds exactly the fetched tip",
        )
    }

    /// The records of `git diff-tree -r -z` raw output: `[status, old mode,
    /// new mode, new object id]` and the path. `None` when the output does
    /// not have that shape.
    fn tree_changes(raw: &[u8]) -> Option<Vec<([&str; 4], &[u8])>> {
        let mut out = Vec::new();
        let mut fields = raw.split(|b| *b == 0);
        while let Some(head) = fields.next() {
            if head.is_empty() {
                // The output ends with a NUL.
                continue;
            }
            let head = std::str::from_utf8(head.strip_prefix(b":")?).ok()?;
            let path = fields.next().filter(|p| !p.is_empty())?;
            let f: Vec<&str> = head.split(' ').collect();
            let [old_mode, new_mode, _old_oid, new_oid, status] = f.as_slice() else {
                return None;
            };
            out.push(([*status, *old_mode, *new_mode, *new_oid], path));
        }
        Some(out)
    }

    /// How the store takes one changed tree entry, read the way git-meta's
    /// tree parse reads it: `Ok(Some((key, is a deletion record)))` for a
    /// string value or a whole-key deletion record added or modified (a
    /// value also deleted: status `D`), `Ok(None)` for what the merge
    /// ignores (a path naming no target, which git-meta's parse skips too,
    /// or a deletion record removed: the store keeps its own), and `Err`
    /// naming the entry for anything else.
    fn classify_change(
        status: &str,
        old_mode: &str,
        new_mode: &str,
        path: &[u8],
    ) -> Result<Option<(Key, bool)>, String> {
        let Ok(p) = std::str::from_utf8(path) else {
            return Err(format!(
                "{} (name is not UTF-8)",
                String::from_utf8_lossy(path)
            ));
        };
        let parts: Vec<&str> = p.split('/').collect();
        let Ok((ty, value, key_parts)) = parse_path_parts(&parts) else {
            return Ok(None);
        };
        if !valid_target(&ty, &value) {
            return Err(format!("{p} (target git-meta cannot serialize)"));
        }
        let (key, tombstone) = match classify_key_parts(key_parts) {
            PathKey::Value(k) => (k, false),
            PathKey::Tombstone(k) => (k, true),
            PathKey::Other => {
                return Err(format!("{p} (not a string value or a deletion record)"));
            }
        };
        let key = Key {
            target_type: ty,
            target_value: value,
            key,
        };
        let target = key.to_target();
        let canonical = guarded("building a git-meta tree path", || {
            if tombstone {
                git_meta_lib::tree_paths::tombstone_path(&target, &key.key)
            } else {
                git_meta_lib::tree_paths::tree_path(&target, &key.key)
            }
        });
        if canonical.ok().as_deref() != Some(p) {
            return Err(format!("{p} (not the path git-meta writes for its key)"));
        }
        match (status, old_mode, new_mode) {
            ("A", "000000", "100644") | ("M", "100644", "100644") => Ok(Some((key, tombstone))),
            ("D", "100644", "000000") if tombstone => Ok(None),
            ("D", "100644", "000000") => Ok(Some((key, false))),
            _ => Err(format!("{p} ({status} {old_mode} -> {new_mode})")),
        }
    }

    /// Fetch and merge, then push the local metadata commit as one
    /// fast-forward commit on the remote tip (git-meta's push), retrying from
    /// the fetch when the remote moved in the meantime.
    pub fn push(&self, remote: Option<&str>) -> Result<PushOutcome, GitError> {
        self.push_with_hook(remote, |_| {})
    }

    /// [`AttestStore::push`], publishing the local metadata as a single
    /// commit without parents (with a lease on the tip fetched): the
    /// remote's history then holds only the values the tree still has, so a
    /// fetch downloads the current attestations rather than every version
    /// ever published (`vci prune` only writes tombstones; the pruned values
    /// stay in the history until this). Other clones' next fetch merges onto
    /// the new history.
    pub fn push_rewriting_history(&self, remote: Option<&str>) -> Result<PushOutcome, GitError> {
        self.push_impl(remote, |_| {}, true)
    }

    /// `push`, calling `before_push(attempt)` right before each `git push`.
    /// Exists so tests can simulate a concurrent writer landing in that
    /// window.
    #[doc(hidden)]
    pub fn push_with_hook(
        &self,
        remote: Option<&str>,
        before_push: impl FnMut(u32),
    ) -> Result<PushOutcome, GitError> {
        self.push_impl(remote, before_push, false)
    }

    fn push_impl(
        &self,
        remote: Option<&str>,
        mut before_push: impl FnMut(u32),
        rewrite: bool,
    ) -> Result<PushOutcome, GitError> {
        let _lock = self.exchange_lock()?;
        let name = self.ensure_remote(remote)?;
        if self.remotes()?.iter().any(|r| r.0 == name && r.3) {
            // git-meta materializes a side remote's values without
            // re-serializing them, so the local metadata commit never contains
            // its tip: publishing goes to the primary metadata remote only.
            return Err(GitError::NoMetaRemote(format!(
                "{name} is a side git-meta remote (remote.{name}.metaside = true); vci pushes to the primary git-meta remote only"
            )));
        }
        let ns = self.namespace()?;
        let local_ref = format!("refs/{ns}/local/main");
        let remote_ref = format!("refs/{ns}/main");
        let tracking = self.tracking_ref(&name, &ns)?;
        let mut last = String::new();
        // Notes of a round that started over (see below).
        let mut carried: Vec<String> = Vec::new();
        // Whether a failed push already fetched every deletion record of
        // the pushed tree this clone lacks (see below).
        let mut fetched_tombstones = false;
        let done = |status, report: Report| PushOutcome {
            remote: name.clone(),
            status,
            warnings: report.warnings,
            notes: report.notes,
        };
        for attempt in 1..=PUSH_ATTEMPTS {
            let mut report = Report {
                notes: std::mem::take(&mut carried),
                ..Report::default()
            };
            let timing = std::env::var_os("VCI_TIMING").is_some();
            let t = std::time::Instant::now();
            let round = match self.fetch_named(&name, &mut report) {
                Ok(r) => r,
                Err(e) if is_ref_race(&e) && attempt < PUSH_ATTEMPTS => {
                    last = e.to_string();
                    backoff(attempt, 20, 1000);
                    continue;
                }
                Err(e) => return Err(e),
            };
            if timing {
                eprintln!(
                    "vci: timing: push: fetch and materialize {name}'s metadata: {:.2}s",
                    t.elapsed().as_secs_f64()
                );
            }
            let t = std::time::Instant::now();
            let Some(local) = self.read_ref(&local_ref)? else {
                return Ok(done(PushStatus::NothingStored, report));
            };
            let tip = self.read_ref(&tracking)?;
            let mut theirs_snap = None;
            if let Some(tip) = &tip {
                if *tip == local && round.found && !rewrite {
                    return Ok(done(PushStatus::UpToDate, report));
                }
                if !self.is_ancestor(tip, &local)? {
                    // Materialize always merges the tip in; pushing a tree
                    // that lacks the remote's values would delete them for
                    // everyone else, so refuse.
                    return Err(GitError::Meta(format!(
                        "{local_ref} does not contain {tracking} after materializing; not pushing"
                    )));
                }
                // Every value of the remote tip must still be there, unless
                // this store deleted it (vci prune, git meta rm).
                let theirs_keys = self.snapshot_keys(tip)?;
                let theirs = &theirs_keys.values;
                let ours = self.snapshot_keys(&local)?.values;
                let dropped: Vec<&Key> = theirs
                    .difference(&ours)
                    .filter(|k| !round.deleted_here.contains(*k))
                    .collect();
                if let Some(first) = dropped.first() {
                    return Err(GitError::Meta(format!(
                        "pushing would delete {} value(s) of {name}'s {remote_ref} that this store never deleted (first: {} {}); not pushing",
                        dropped.len(),
                        target_label(&first.to_target()),
                        first.key
                    )));
                }
                theirs_snap = Some(theirs_keys);
            }
            // Every value the push sends must be here: one this clone never
            // fetched (a promised row) is fetched now, and one the remote no
            // longer has (deleted and garbage-collected there) cannot be
            // published by anyone, so it is deleted here (a deletion record,
            // as the remote's own history says) and the round starts over.
            let ours_snap = self.snapshot_keys(&local)?;
            // A commit without parents (`--rewrite-history`) sends its
            // whole tree: every value must be here.
            let unsendable = self.unsendable(&name, &ours_snap, theirs_snap.as_ref(), !rewrite)?;
            if let Some((first, why)) = unsendable.stuck.first() {
                return Err(GitError::Meta(format!(
                    "the local metadata holds {} value(s) this clone never fetched that {name} did not serve (first: {} {}){}; not pushing (`vci fetch` and push again)",
                    unsendable.stuck.len(),
                    target_label(&first.to_target()),
                    first.key,
                    why.as_ref().map(|w| format!(": {w}")).unwrap_or_default()
                )));
            }
            if let Some(first) = unsendable.gone.first() {
                if attempt == PUSH_ATTEMPTS {
                    return Err(GitError::Meta(format!(
                        "the local metadata still holds {} value(s) {name} no longer has (first: {} {}); not pushing",
                        unsendable.gone.len(),
                        target_label(&first.to_target()),
                        first.key
                    )));
                }
                let session = self.session()?;
                let targets: Vec<Target> = unsendable.gone.iter().map(Key::to_target).collect();
                for (k, t) in unsendable.gone.iter().zip(&targets) {
                    session.target(t).remove(&k.key).map_err(meta_err)?;
                }
                self.stamp_written(
                    unsendable
                        .gone
                        .iter()
                        .zip(&targets)
                        .map(|(k, t)| (t, k.key.as_str())),
                )?;
                report.note(format!(
                    "deleted {} value(s) this clone never fetched that {name} no longer has (deleted there and garbage-collected; first: {} {}): no push can publish them",
                    unsendable.gone.len(),
                    target_label(&first.to_target()),
                    first.key
                ));
                carried = std::mem::take(&mut report.notes);
                continue;
            }
            if timing {
                eprintln!(
                    "vci: timing: push: check what the push would delete and what it sends: {:.2}s",
                    t.elapsed().as_secs_f64()
                );
            }
            let t = std::time::Instant::now();
            if let Some(tip) = &tip {
                match self.rebase_onto(&local_ref, &local, tip) {
                    Ok(()) => {}
                    Err(e) if is_ref_race(&e) && attempt < PUSH_ATTEMPTS => {
                        last = e.to_string();
                        backoff(attempt, 20, 1000);
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            let mut pushed = self.read_ref(&local_ref)?.unwrap_or(local);
            if rewrite {
                pushed = self.orphan_of(&local_ref, &pushed)?;
            }
            if timing {
                eprintln!(
                    "vci: timing: push: put the local metadata on top of {name}'s: {:.2}s",
                    t.elapsed().as_secs_f64()
                );
            }
            // What the pack sends must be readable here: git asked which
            // objects of the commit the remote's tip does not reach are
            // missing (a value or deletion record this clone holds as a key
            // only, which the remote's tip no longer reaches after a round's
            // merge), and they are fetched first; pack-objects would
            // otherwise try the lazy fetch vci disables and fail.
            let t = std::time::Instant::now();
            // The tip's tree must be complete here, not only when it was
            // fetched: git excludes the tip's objects from the pack by
            // walking its tree, and stops silently under a subtree it
            // cannot read, so the values under it would be packed, and a
            // value this clone never fetched fails the push (2.1.16: three
            // vex jobs lost their attestations to `could not fetch <a
            // concurrent job's deletion record> from promisor remote`).
            if let Some(tip) = tip.as_deref() {
                self.complete_tree(&name, tip)?;
            }
            let mut missing = self.missing_for_push(&pushed, tip.as_deref())?;
            missing.extend(self.changed_blobs_missing(&pushed, tip.as_deref())?);
            missing.extend(self.changed_targets_blobs_missing(&pushed, tip.as_deref())?);
            // Deletion records the store holds are written back first: their
            // content is the store's row, so a record whose blob this clone
            // lost (2.2.4: vex jobs failed ten pushes on their own deletion
            // records, stamped minutes earlier and absent from the remote)
            // is rewritten instead of fetched from a remote that never had it.
            if !missing.is_empty() {
                for o in self.rewrite_tombstone_blobs(&missing)? {
                    missing.remove(&o);
                }
            }
            if !missing.is_empty() {
                let (have, fetched, error) = self.ensure_blobs(&name, &missing)?;
                let still: Vec<&String> = missing.iter().filter(|o| !have.contains(*o)).collect();
                if let Some(first) = still.first() {
                    return Err(GitError::Meta(format!(
                        "the push needs {} object(s) this clone never fetched that {name} did not serve (first: {first}){}; not pushing (`vci fetch` and push again)",
                        still.len(),
                        error.map(|e| format!(": {e}")).unwrap_or_default()
                    )));
                }
                if timing {
                    eprintln!(
                        "vci: timing: push: fetch {} object(s) the pack needs ({fetched} downloaded): {:.2}s",
                        missing.len(),
                        t.elapsed().as_secs_f64()
                    );
                }
            }
            let t = std::time::Instant::now();
            before_push(attempt);
            // `--no-thin`: a thin pack deltifies against the remote's
            // versions of the values, which a blobless clone does not have
            // (git would try to download each).
            //
            // `pack.useSparse=false` (2.1.17): git builds a push's pack with
            // `pack-objects --sparse` by default (since 2.27), a path-based
            // walk of the tip's tree that git documents as packing extra
            // objects in some tree shapes, while the check above walks the
            // objects fully (`rev-list`) and so found nothing missing. On
            // vex's 100,000-entry metadata tree every master attest job
            // since 2.1.15 failed all ten attempts on a value the tip held
            // and this clone never fetched (`could not fetch ... from
            // promisor remote`); pull request jobs, whose trees differ
            // less, pushed. The full walk takes about a second here.
            let mut git = self.repo.git().args([
                "-c",
                "pack.useSparse=false",
                "push",
                "--porcelain",
                "--no-thin",
                "--no-verify",
                "--recurse-submodules=no",
            ]);
            if rewrite {
                // Only on top of the tip this round fetched.
                git = git.arg(format!(
                    "--force-with-lease={remote_ref}:{}",
                    tip.as_deref().unwrap_or("")
                ));
            }
            let (describe, out) = git
                .arg(&name)
                .arg(format!("{pushed}:{remote_ref}"))
                .output_described()?;
            if timing {
                eprintln!(
                    "vci: timing: push: git push (attempt {attempt}): {:.2}s",
                    t.elapsed().as_secs_f64()
                );
            }
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let status = if stdout.lines().any(|l| l.starts_with("=\t")) {
                    PushStatus::UpToDate
                } else {
                    PushStatus::Pushed
                };
                self.repo
                    .git()
                    .args(["update-ref", "-m", "vci push", &tracking, &pushed])
                    .run()?;
                return Ok(done(status, report));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            let rejected: Vec<&str> = stdout.lines().filter(|l| l.starts_with("!\t")).collect();
            // A pack that could not be built or unpacked (an object missing
            // here) fails the same way on every attempt.
            if rejected.is_empty() || rejected.iter().any(|l| l.contains("unpacker error")) {
                // git builds the pack against the remote's refs this clone
                // has: when the remote's tip moved since this round's fetch
                // (another job's push landed in between), it has none, so
                // the pack would hold the whole tree, and pack-objects
                // walks into a value this clone never fetched (2.1.15: a vex
                // job lost 1,025 attestations to `could not fetch ... from
                // promisor remote`). Another round fetches the new tip,
                // merges and pushes on top of it, as after a rejection.
                let stderr = String::from_utf8_lossy(&out.stderr);
                if unreadable_object(&stderr).is_some() && attempt < PUSH_ATTEMPTS {
                    let moved = self.remote_tip_moved(&name, &remote_ref, tip.as_deref())?;
                    last = format!(
                        "the pack needed an object this clone could not read ({remote_ref} {} since this round's fetch; {})",
                        if moved { "moved" } else { "did not move" },
                        self.push_diagnosis(&pushed, tip.as_deref(), &stderr)
                    );
                    // 2.1.18: the object git named is fetched by id (every
                    // such object on vex was served by id afterwards) and
                    // the push tried again at once; only an object the
                    // remote does not serve waits for another round.
                    // 2.2.9: the first such failure fetches, in one batch,
                    // every deletion record of the pushed tree this clone
                    // lacks (another job's, merged in; a vex job hit
                    // thousands, one per attempt), then tries again.
                    if !fetched_tombstones {
                        fetched_tombstones = true;
                        let missing = self.missing_tombstone_blobs(&pushed)?;
                        if !missing.is_empty() {
                            let (_, fetched, _) = self.ensure_blobs(&name, &missing)?;
                            if fetched > 0 {
                                report.note(format!(
                                    "push attempt {attempt}: {last}; fetched {fetched} of the {} deletion record(s) this clone lacked and trying again",
                                    missing.len()
                                ));
                                continue;
                            }
                        }
                    }
                    if let Some(o) = unreadable_object(&stderr) {
                        let one: BTreeSet<String> = [o.clone()].into_iter().collect();
                        if self.rewrite_tombstone_blobs(&one)?.contains(&o) {
                            report.note(format!(
                                "push attempt {attempt}: {last}; wrote {o} back from the store's deletion record and trying again"
                            ));
                            continue;
                        }
                        if !rewrite && self.replace_lost_tombstone(&local_ref, &pushed, &o)? {
                            report.note(format!(
                                "push attempt {attempt}: {last}; replaced the lost deletion record {o} with a new one for the same key and trying again"
                            ));
                            continue;
                        }
                        let (have, fetched, _) = self.ensure_blobs(&name, &one)?;
                        if have.contains(&o) {
                            report.note(format!(
                                "push attempt {attempt}: {last}; fetched {o} ({fetched} downloaded) and trying again"
                            ));
                            continue;
                        }
                    }
                    report.note(format!(
                        "push attempt {attempt}: {last}; fetching and trying again"
                    ));
                    backoff(attempt, 20, 1000);
                    continue;
                }
                // Not a ref rejection (unreachable remote, auth...): no retry.
                // The last of the attempts above ends here too: its
                // diagnosis goes with the error (the notes of a push that
                // fails are never printed).
                if unreadable_object(&stderr).is_some() {
                    return Err(GitError::Meta(format!(
                        "{} ({})",
                        command_error(&describe, &out),
                        self.push_diagnosis(&pushed, tip.as_deref(), &stderr)
                    )));
                }
                return Err(command_error(&describe, &out));
            }
            last = rejected.join("; ");
            if attempt < PUSH_ATTEMPTS {
                backoff(attempt, 20, 1000);
            }
        }
        Err(GitError::PushRejected {
            remote: name,
            attempts: PUSH_ATTEMPTS,
            detail: last,
        })
    }

    /// The blobs `pushed`'s tree holds at paths where it differs from
    /// `tip`'s (every blob of the tree without a tip) that this clone does
    /// not have: what the pack must send, found by comparing the trees
    /// (`git diff-tree`) rather than by git's object walk, which stops
    /// silently under a subtree it cannot read.
    fn changed_blobs_missing(
        &self,
        pushed: &str,
        tip: Option<&str>,
    ) -> Result<BTreeSet<String>, GitError> {
        let mut git =
            self.repo
                .git()
                .args(["diff-tree", "-r", "--no-commit-id", "--diff-filter=AM"]);
        git = match tip {
            Some(t) => git.arg(t).arg(pushed),
            None => git.arg("--root").arg(pushed),
        };
        let out = git.env("GIT_NO_LAZY_FETCH", "1").run_str()?;
        let blobs: BTreeSet<String> = out
            .lines()
            .filter_map(|l| {
                // :<mode> <mode> <old> <new> <status>\t<path>
                let mut f = l.strip_prefix(':')?.split_whitespace();
                let (_, _, _, new) = (f.next()?, f.next()?, f.next()?, f.next()?);
                is_oid(new).then(|| new.to_owned())
            })
            .collect();
        if blobs.is_empty() {
            return Ok(blobs);
        }
        let have = self.present(&blobs)?;
        Ok(blobs.difference(&have).cloned().collect())
    }

    /// The blobs of every deletion record in `pushed`'s tree that this
    /// clone does not have.
    fn missing_tombstone_blobs(&self, pushed: &str) -> Result<BTreeSet<String>, GitError> {
        let listing = self
            .repo
            .git()
            .args(["ls-tree", "-r", "-z", "--full-tree", pushed])
            .env("GIT_NO_LAZY_FETCH", "1")
            .run()?;
        let blobs: BTreeSet<String> = split_ls_tree(&listing)
            .into_iter()
            .filter(|(_, kind, _, p)| {
                *kind == b"blob" && p.windows(14).any(|w| w == b"/__tombstones/")
            })
            .map(|(_, _, o, _)| String::from_utf8_lossy(o).into_owned())
            .filter(|o| is_oid(o))
            .collect();
        let have = self.present(&blobs)?;
        Ok(blobs.difference(&have).cloned().collect())
    }

    /// Replace, in `pushed` (the tip of `local_ref`), a deletion record
    /// whose blob `oid` this clone lost and the store no longer holds, with
    /// a new deletion record of the same keys (stamped now): the same
    /// deletion, later, which git-meta's merge treats alike (2.2.8: a vex
    /// job failed ten pushes on its own deletion record of minutes before,
    /// with no row left to write it back from). Only when every path that
    /// holds `oid` is a deletion record's; moves `local_ref` only if it is
    /// still at `pushed`. Returns whether it replaced anything.
    fn replace_lost_tombstone(
        &self,
        local_ref: &str,
        pushed: &str,
        oid: &str,
    ) -> Result<bool, GitError> {
        if self.read_ref(local_ref)?.as_deref() != Some(pushed) {
            return Ok(false);
        }
        let listing = self
            .repo
            .git()
            .args(["ls-tree", "-r", "-z", "--full-tree", pushed])
            .env("GIT_NO_LAZY_FETCH", "1")
            .run()?;
        let paths: Vec<String> = split_ls_tree(&listing)
            .into_iter()
            .filter(|(_, kind, o, _)| *kind == b"blob" && *o == oid.as_bytes())
            .map(|(_, _, _, p)| String::from_utf8_lossy(p).into_owned())
            .collect();
        if paths.is_empty() || paths.iter().any(|p| !p.contains("/__tombstones/")) {
            return Ok(false);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let t = Tombstone {
            timestamp: now,
            email: "unknown".to_owned(),
        };
        let bytes = serde_json::to_vec(&t).map_err(|e| GitError::Parse(e.to_string()))?;
        let blob = parse_oid(
            &self
                .repo
                .git()
                .args(["hash-object", "-w", "--stdin"])
                .run_with_stdin(&bytes)?,
        )?;
        let dir = tempfile::tempdir()?;
        let index = dir.path().join("index");
        self.repo
            .git()
            .args(["read-tree", pushed])
            .env("GIT_INDEX_FILE", &index)
            .env("GIT_NO_LAZY_FETCH", "1")
            .run()?;
        for p in &paths {
            self.repo
                .git()
                .args(["update-index", "--add", "--cacheinfo"])
                .arg(format!("100644,{blob},{p}"))
                .env("GIT_INDEX_FILE", &index)
                .run()?;
        }
        let tree = parse_oid(
            &self
                .repo
                .git()
                .args(["write-tree", "--missing-ok"])
                .env("GIT_INDEX_FILE", &index)
                .env("GIT_NO_LAZY_FETCH", "1")
                .run()?,
        )?;
        let parents = self
            .repo
            .git()
            .args(["rev-list", "--parents", "-n", "1", pushed])
            .run_str()?;
        let mut git = self
            .repo
            .git()
            .args(["commit-tree", "--no-gpg-sign", &tree]);
        for p in parents.split_whitespace().skip(1) {
            git = git.arg("-p").arg(p);
        }
        git = git.args(["-m", "vci: replace a deletion record this clone lost"]);
        for (k, v) in IDENTITY {
            git = git.env(k, v);
        }
        let commit = parse_oid(&git.run()?)?;
        self.cas_ref(
            local_ref,
            Some(&commit),
            pushed,
            "vci: replace a deletion record this clone lost",
        )?;
        Ok(true)
    }

    /// Write back, from the store's rows, the blobs of the deletion records
    /// among `wanted` that this clone does not have: a deletion record's
    /// blob is exactly its row (`{"timestamp":..,"email":..}`, as git-meta
    /// serializes it). Returns the object ids written.
    fn rewrite_tombstone_blobs(
        &self,
        wanted: &BTreeSet<String>,
    ) -> Result<BTreeSet<String>, GitError> {
        let mut written = BTreeSet::new();
        let Some(like) = wanted.iter().next() else {
            return Ok(written);
        };
        let session = self.session()?;
        let records = guarded("reading the store", || session.store().get_all_tombstones())?;
        drop(session);
        for r in records {
            let t = Tombstone {
                timestamp: r.timestamp,
                email: r.email.clone(),
            };
            let Some(id) = tombstone_blob_id(&t, like) else {
                continue;
            };
            if !wanted.contains(&id) || written.contains(&id) {
                continue;
            }
            let Ok(bytes) = serde_json::to_vec(&t) else {
                continue;
            };
            let out = self
                .repo
                .git()
                .args(["hash-object", "-w", "--stdin"])
                .run_with_stdin(&bytes)?;
            if String::from_utf8_lossy(&out).trim() == id {
                written.insert(id);
            }
        }
        Ok(written)
    }

    /// Every deletion record `pushed` holds under the targets (or, outside
    /// a target, the key directories) where it differs from `tip` that this
    /// clone does not have, unchanged entries included.
    ///
    /// vci 2.2.1: two jobs that supersede the same attestations each write a
    /// deletion record for the same keys; the second to push merges the
    /// first's records, which it never downloaded, into targets its own
    /// attestations changed, and `git push` then failed on one of them
    /// (`could not fetch <record> from promisor remote`) although the
    /// remote's tip holds it: every vex master attest that lost its
    /// attestations, and pull request jobs racing another full run. A
    /// retry that fetched the object it named fixed one record per attempt
    /// of about a thousand. A changed target's deletion records are few
    /// and tiny: all of them are made present before the push.
    fn changed_targets_blobs_missing(
        &self,
        pushed: &str,
        tip: Option<&str>,
    ) -> Result<BTreeSet<String>, GitError> {
        let Some(tip) = tip else {
            return Ok(BTreeSet::new());
        };
        let out = self
            .repo
            .git()
            .args([
                "diff-tree",
                "-r",
                "--no-commit-id",
                "--name-only",
                "-z",
                tip,
                pushed,
            ])
            .env("GIT_NO_LAZY_FETCH", "1")
            .run()?;
        let mut dirs: BTreeSet<String> = BTreeSet::new();
        for p in out.split(|b| *b == 0).filter(|p| !p.is_empty()) {
            let p = String::from_utf8_lossy(p);
            let dir = match p.find("/__target__/") {
                Some(i) => p[..i + "/__target__".len()].to_owned(),
                None => match p.rsplit_once('/') {
                    Some((d, _)) => d.to_owned(),
                    None => continue,
                },
            };
            dirs.insert(dir);
        }
        if dirs.is_empty() {
            return Ok(BTreeSet::new());
        }
        let dirs: Vec<String> = dirs.into_iter().collect();
        let mut blobs: BTreeSet<String> = BTreeSet::new();
        for chunk in dirs.chunks(500) {
            let listing = self
                .repo
                .git()
                .args(["ls-tree", "-r", "-z", "--full-tree", pushed, "--"])
                .args(chunk)
                .env("GIT_NO_LAZY_FETCH", "1")
                .run()?;
            for (_, kind, oid, path) in split_ls_tree(&listing) {
                // Deletion records only (every object such a push failed
                // on was one): other attestations' envelopes in the target
                // stay unread.
                let tombstone = path.windows(14).any(|w| w == b"/__tombstones/");
                if kind == b"blob" && tombstone {
                    let o = String::from_utf8_lossy(oid).into_owned();
                    if is_oid(&o) {
                        blobs.insert(o);
                    }
                }
            }
        }
        let have = self.present(&blobs)?;
        Ok(blobs.difference(&have).cloned().collect())
    }

    /// For the note of a push whose pack needed an object this clone could
    /// not read: which object git named, whether this clone can read it
    /// now, whether `tip`'s tree is complete, and how many objects of
    /// `pushed` are missing here when nothing is excluded.
    fn push_diagnosis(&self, pushed: &str, tip: Option<&str>, stderr: &str) -> String {
        let named = unreadable_object(stderr);
        let readable = named.as_deref().map(|o| {
            let read = self
                .repo
                .git()
                .args(["cat-file", "-t", o])
                .env("GIT_NO_LAZY_FETCH", "1")
                .run_str()
                .map(|t| t.trim().to_owned())
                .unwrap_or_else(|e| format!("unreadable ({})", e.to_string().replace('\n', " ")));
            // A loose object file git cannot read is corrupt or still
            // being written; none at all means the object was never here.
            let loose = self
                .repo
                .git_dir()
                .map(|d| d.join("objects").join(&o[..2]).join(&o[2..]))
                .ok()
                .and_then(|p| std::fs::metadata(p).ok().map(|m| m.len()));
            match loose {
                Some(n) => format!("{read}; a loose object file of {n} bytes exists"),
                None => format!("{read}; no loose object file"),
            }
        });
        let tip_complete = tip.map(|t| {
            self.repo
                .git()
                .args(["ls-tree", "-r", "-d", "--full-tree", t])
                .env("GIT_NO_LAZY_FETCH", "1")
                .run()
                .is_ok()
        });
        let missing_all = self
            .repo
            .git()
            .args([
                "rev-list",
                "--objects",
                "--missing=print",
                "--no-object-names",
                pushed,
            ])
            .env("GIT_NO_LAZY_FETCH", "1")
            .run_str()
            .map(|o| o.lines().filter(|l| l.starts_with('?')).count());
        format!(
            "object {}: {}; the tip's tree is {}; {} object(s) of the pushed commit are not here",
            named.as_deref().unwrap_or("?"),
            readable.as_deref().unwrap_or("?"),
            match tip_complete {
                Some(true) => "complete",
                Some(false) => "INCOMPLETE",
                None => "absent",
            },
            missing_all
                .map(|n| n.to_string())
                .unwrap_or_else(|_| "?".to_owned())
        )
    }

    /// Whether `remote_ref` on `remote` is no longer at `tip` (one
    /// `ls-remote` round trip).
    fn remote_tip_moved(
        &self,
        remote: &str,
        remote_ref: &str,
        tip: Option<&str>,
    ) -> Result<bool, GitError> {
        let out = self
            .repo
            .git()
            .args(["ls-remote", "--", remote, remote_ref])
            .run_str()?;
        let now = out
            .lines()
            .find_map(|l| l.split_whitespace().next())
            .filter(|o| is_oid(o))
            .map(str::to_owned);
        Ok(now.as_deref() != tip)
    }

    /// The values of `ours` (the local metadata commit's tree) a push would
    /// send whose blobs are not here even after fetching them (in one batch)
    /// from the metadata remote they came from (`remote` when there is
    /// none): every value whose blob this clone never fetched, or with
    /// `on_theirs` only those `theirs` (the remote's tip, when it has one)
    /// does not hold (a commit on top of it sends nothing it holds). Split
    /// into the ones the remote said it does not have (deleted there, and
    /// not a value of `theirs`) and the others, with why their fetch failed.
    fn unsendable(
        &self,
        remote: &str,
        ours: &KeySnapshot,
        theirs: Option<&KeySnapshot>,
        on_theirs: bool,
    ) -> Result<Unsendable, GitError> {
        let sent_already: BTreeSet<&String> = theirs
            .filter(|_| on_theirs)
            .map(|t| {
                t.value_blobs
                    .values()
                    .chain(t.tombstone_blobs.values())
                    .collect()
            })
            .unwrap_or_default();
        let need: BTreeSet<String> = ours
            .value_blobs
            .values()
            .chain(ours.tombstone_blobs.values())
            .filter(|o| !sent_already.contains(o))
            .cloned()
            .collect();
        let here = self.present(&need)?;
        let missing: BTreeSet<String> = need.difference(&here).cloned().collect();
        let mut out = Unsendable::default();
        if missing.is_empty() {
            return Ok(out);
        }
        let from = self.value_remote().unwrap_or_else(|_| remote.to_owned());
        let list: Vec<&String> = missing.iter().collect();
        let mut why: BTreeMap<&String, String> = BTreeMap::new();
        if let Err(e) = self.fetch_blobs(&from, &list) {
            let e = e.to_string();
            if is_unavailable_object(&e) && list.len() > 1 && list.len() <= 100 {
                // One object the server does not have fails the whole
                // batch: ask for each alone to tell which.
                for o in &list {
                    if let Err(e) = self.fetch_objects(&from, &[o]) {
                        why.insert(o, e.to_string());
                    }
                }
            } else {
                why.extend(list.iter().map(|o| (*o, e.clone())));
            }
        }
        let now = self.present(&missing)?;
        for (k, o) in &ours.value_blobs {
            if !missing.contains(o) || now.contains(o) {
                continue;
            }
            let reason = why.get(o).cloned();
            let held_there = theirs.is_some_and(|t| t.values.contains(k));
            if !held_there && reason.as_deref().is_some_and(is_unavailable_object) {
                out.gone.push(k.clone());
            } else {
                out.stuck.push((k.clone(), reason));
            }
        }
        if out.gone.is_empty() && out.stuck.is_empty() {
            // A deletion record's blob is what is missing.
            if let Some(o) = missing.iter().find(|o| !now.contains(*o)) {
                return Err(GitError::Meta(format!(
                    "a deletion record of the local metadata ({o}) is not here and {from} did not serve it{}",
                    why.get(o).map(|w| format!(": {w}")).unwrap_or_default()
                )));
            }
        }
        Ok(out)
    }

    /// Rewrite `local_ref` as a commit without parents holding `local`'s
    /// tree (a no-op when it has none), returning the commit.
    fn orphan_of(&self, local_ref: &str, local: &str) -> Result<String, GitError> {
        let parents = self
            .repo
            .git()
            .args(["rev-list", "--parents", "-n", "1", local])
            .run_str()?;
        if parents.split_whitespace().count() == 1 {
            return Ok(local.to_owned());
        }
        let tree = self
            .repo
            .git()
            .args(["rev-parse", "--verify"])
            .arg(format!("{local}^{{tree}}"))
            .run()?;
        let tree = parse_oid(&tree)?;
        let mut git = self.repo.git().args([
            "commit-tree",
            "--no-gpg-sign",
            &tree,
            "-m",
            "vci: metadata history rewritten (vci push --rewrite-history)",
        ]);
        for (k, v) in IDENTITY {
            git = git.env(k, v);
        }
        let commit = parse_oid(&git.run()?)?;
        self.cas_ref(
            local_ref,
            Some(&commit),
            local,
            "vci push --rewrite-history",
        )?;
        Ok(commit)
    }

    /// Rewrite `local_ref` as a single commit with `local`'s tree on top of
    /// `tip` (git-meta keeps metadata history linear). A no-op when `local`
    /// already is such a commit.
    fn rebase_onto(&self, local_ref: &str, local: &str, tip: &str) -> Result<(), GitError> {
        let parents = self
            .repo
            .git()
            .args(["rev-list", "--parents", "-n", "1", local])
            .run_str()?;
        let parents: Vec<&str> = parents.split_whitespace().skip(1).collect();
        if parents == [tip] {
            return Ok(());
        }
        let tree = self
            .repo
            .git()
            .args(["rev-parse", "--verify"])
            .arg(format!("{local}^{{tree}}"))
            .run()?;
        let tree = parse_oid(&tree)?;
        let message = self
            .repo
            .git()
            .args(["log", "-1", "--format=%B", local])
            .run_str()?;
        let mut git = self.repo.git().args([
            "commit-tree",
            "--no-gpg-sign",
            &tree,
            "-p",
            tip,
            "-m",
            if message.trim().is_empty() {
                "git-meta: serialize"
            } else {
                message.as_str()
            },
        ]);
        for (k, v) in IDENTITY {
            git = git.env(k, v);
        }
        let commit = parse_oid(&git.run()?)?;
        self.cas_ref(
            local_ref,
            Some(&commit),
            local,
            "vci: rebase metadata for push",
        )
    }
}

/// The `url:` of a `.git-meta` file (`None` when the file does not exist).
pub fn read_setup_url(path: &Utf8Path) -> Result<Option<String>, GitError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix("url:") else {
            continue;
        };
        let v = rest.trim();
        let v = v
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(v)
            .trim();
        if !v.is_empty() {
            return Ok(Some(v.to_owned()));
        }
    }
    Err(GitError::NoMetaRemote(format!(
        "{path} has no `url:` entry"
    )))
}

/// Sleep a random duration in `[base, base + min(base * 2^attempt, cap))` ms,
/// so contending writers spread out instead of retrying in lockstep.
fn backoff(attempt: u32, base_ms: u64, cap_ms: u64) {
    use std::hash::{BuildHasher, Hasher};
    // RandomState is seeded randomly per instance: a dependency-free RNG.
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let window = (base_ms << attempt.min(10)).min(cap_ms).max(1);
    std::thread::sleep(Duration::from_millis(base_ms + random % window));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_paths_name_values_and_tombstones() {
        let c = |p: &str| classify_key_parts(&p.split('/').collect::<Vec<_>>());
        assert_eq!(
            c("vci:attestation/ab12/cd34/ef56/__value"),
            PathKey::Value("vci:attestation:ab12:cd34:ef56".into())
        );
        assert_eq!(
            c("__tombstones/vci:attestation/ab12/cd34/ef56/__deleted"),
            PathKey::Tombstone("vci:attestation:ab12:cd34:ef56".into())
        );
        for other in [
            "__value",
            "k/__set/member",
            "k/__list/0",
            "k/__tombstones/member",
            "__tombstones/__deleted",
            "k/__tombstones/x/__value",
        ] {
            assert_eq!(c(other), PathKey::Other, "{other}");
        }
    }

    #[test]
    fn diff_tree_records() {
        let (a, b) = ("1".repeat(40), "2".repeat(40));
        let raw = format!(
            ":100644 100644 {a} {b} M\0path/src/a.ts/__target__/k/__value\0:000000 100644 {z} {b} A\0project/k/__value\0",
            z = "0".repeat(40)
        );
        let got = AttestStore::tree_changes(raw.as_bytes()).unwrap();
        assert_eq!(
            got,
            vec![
                (
                    ["M", "100644", "100644", b.as_str()],
                    &b"path/src/a.ts/__target__/k/__value"[..]
                ),
                (
                    ["A", "000000", "100644", b.as_str()],
                    &b"project/k/__value"[..]
                ),
            ]
        );
        assert_eq!(AttestStore::tree_changes(b"").unwrap(), vec![]);
        for bad in [
            &b"100644 100644 a b M\0p\0"[..],
            b":100644 100644 a b\0p\0",
            b":100644 100644 a b M\0",
        ] {
            assert_eq!(AttestStore::tree_changes(bad), None);
        }
    }

    #[test]
    fn changed_entries_read_like_git_meta() {
        let key = attestation_key(&"ab".repeat(32), "0123456789abcdef", &"cd".repeat(32));
        let target = Target::path("src/a.test.ts");
        let value = git_meta_lib::tree_paths::tree_path(&target, &key).unwrap();
        let deleted = git_meta_lib::tree_paths::tombstone_path(&target, &key).unwrap();
        let k = Key {
            target_type: TargetType::Path,
            target_value: "src/a.test.ts".into(),
            key: key.clone(),
        };
        let c = |st, old, new, p: &str| AttestStore::classify_change(st, old, new, p.as_bytes());
        assert_eq!(
            c("A", "000000", "100644", &value),
            Ok(Some((k.clone(), false)))
        );
        assert_eq!(
            c("M", "100644", "100644", &value),
            Ok(Some((k.clone(), false)))
        );
        assert_eq!(
            c("D", "100644", "000000", &value),
            Ok(Some((k.clone(), false)))
        );
        assert_eq!(
            c("A", "000000", "100644", &deleted),
            Ok(Some((k.clone(), true)))
        );
        assert_eq!(c("D", "100644", "000000", &deleted), Ok(None));
        let project = git_meta_lib::tree_paths::tree_path(&Target::project(), "owner").unwrap();
        assert_eq!(
            c("A", "000000", "100644", &project),
            Ok(Some((
                Key {
                    target_type: TargetType::Project,
                    target_value: String::new(),
                    key: "owner".into(),
                },
                false
            )))
        );
        // git-meta's parse skips a path that names no target.
        assert_eq!(c("A", "000000", "100644", "README"), Ok(None));
        // Everything else is merged by git-meta.
        for (st, old, new, p) in [
            ("A", "000000", "100755", value.as_str()),
            ("A", "000000", "120000", value.as_str()),
            ("T", "100644", "120000", value.as_str()),
            ("M", "100755", "100644", value.as_str()),
            ("A", "000000", "100644", "project/meta/filter/__set/0123"),
            ("A", "000000", "100644", "project/notes/__list/0001-ab"),
            ("A", "000000", "100644", "project/__x/__value"),
            ("A", "000000", "100644", "project/k"),
            ("A", "000000", "100644", "path/ab/__target__/k/__value"),
            (
                "A",
                "000000",
                "100644",
                "path/~src/a.test.ts/__target__/k/__value",
            ),
        ] {
            assert!(c(st, old, new, p).is_err(), "{st} {old} {new} {p}");
        }
        assert!(
            AttestStore::classify_change("A", "000000", "100644", b"project/k\xff/__value")
                .is_err()
        );
    }

    /// The fallback repack keeps a value that was packed while a ref
    /// reached it and unreferenced after (2.2.2; `-a -d` deleted it).
    #[test]
    fn the_fallback_repack_keeps_a_value_whose_ref_moved_away() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let git = |args: &[&str], input: Option<&str>| -> String {
            use std::io::Write;
            let mut c = std::process::Command::new("git");
            c.current_dir(d)
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped());
            let mut ch = c.spawn().unwrap();
            if let Some(i) = input {
                ch.stdin.take().unwrap().write_all(i.as_bytes()).unwrap();
            }
            let out = ch.wait_with_output().unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        git(&["init", "-q"], None);
        let base = git(
            &["commit-tree", &git(&["mktree"], Some("")), "-m", "base"],
            None,
        );
        git(&["update-ref", "refs/meta/local/main", &base], None);
        let v = git(&["hash-object", "-w", "--stdin"], Some("a value vci wrote"));
        let t = git(&["mktree"], Some(&format!("100644 blob {v}\tv\n")));
        let c = git(&["commit-tree", &t, "-p", &base, "-m", "serialized"], None);
        git(&["update-ref", "refs/meta/local/main", &c], None);
        let mut args = vec!["-c", "gc.auto=0", "repack"];
        args.extend(REPACK_FALLBACK);
        git(&args, None);
        git(&["update-ref", "refs/meta/local/main", &base], None);
        git(&args, None);
        assert_eq!(
            git(&["cat-file", "-t", &v], None),
            "blob",
            "the value was deleted"
        );
    }

    #[test]
    fn hinted_keys_parse_and_plain_ones_still_do() {
        let (tk, signer, sk) = ("ab".repeat(32), "0123456789abcdef", "cd".repeat(32));
        let plain = attestation_key(&tk, signer, &sk);
        assert_eq!(parse_key(&plain), Some((tk.as_str(), signer, sk.as_str())));
        assert_eq!(parse_key_hint(&plain), None);
        let hint = KeyHint {
            issued: 1_792_430_181,
            tree: Some("0123456789abcdef".to_owned()),
        };
        let k = attestation_key_hinted(&tk, signer, &sk, &hint);
        assert!(k.ends_with(":6ad65065.0123456789abcdef"), "{k}");
        assert_eq!(parse_key(&k), Some((tk.as_str(), signer, sk.as_str())));
        assert_eq!(parse_key_hint(&k), Some(hint.clone()));
        let no_tree = attestation_key_hinted(
            &tk,
            signer,
            &sk,
            &KeyHint {
                issued: 7,
                tree: None,
            },
        );
        assert!(no_tree.ends_with(":7.-"), "{no_tree}");
        assert_eq!(parse_key_hint(&no_tree).unwrap().tree, None);
        // A 40-digit tree is cut to 16; a bad one reads as none.
        let long = attestation_key_hinted(
            &tk,
            signer,
            &sk,
            &KeyHint {
                issued: 1,
                tree: Some("f".repeat(40)),
            },
        );
        assert_eq!(
            parse_key_hint(&long).unwrap().tree.as_deref(),
            Some("ffffffffffffffff")
        );
        for bad in [
            format!("{plain}:zz.-"),
            format!("{plain}:1.abc"),
            format!("{plain}:1.-:more"),
            format!("{plain}:"),
        ] {
            assert_eq!(parse_key(&bad), None, "{bad}");
        }
    }

    #[test]
    fn tombstone_blob_ids_are_git_metas() {
        let t = Tombstone {
            timestamp: 1792185565887,
            email: "test@example.com".into(),
        };
        // `printf '{"timestamp":1792185565887,"email":"test@example.com"}' | git hash-object --stdin`
        let id = "d23a30604540207f251a99661cfbc79cd5a5fb72";
        assert_eq!(tombstone_blob_id(&t, id).as_deref(), Some(id));
        assert_eq!(tombstone_blob_id(&t, &"ab".repeat(32)), None);
    }

    #[test]
    fn manifest_refs_of_envelopes() {
        use base64::Engine as _;
        let b64 = |v: serde_json::Value| {
            serde_json::json!({
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64::engine::general_purpose::STANDARD.encode(v.to_string()),
                "signatures": [],
            })
            .to_string()
        };
        let root = "ab".repeat(32);
        let env = b64(serde_json::json!({"predicate": {"manifestRef": root}}));
        assert_eq!(envelope_manifest_ref(env.as_bytes()), Some(root));
        for bad in [
            b64(serde_json::json!({"predicate": {"manifest": {}}})),
            b64(serde_json::json!({"predicate": {"manifestRef": "../x"}})),
            "not json".to_owned(),
        ] {
            assert_eq!(envelope_manifest_ref(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn key_round_trip() {
        let (tk, sk) = ("ab".repeat(32), "cd".repeat(32));
        let k = attestation_key(&tk, "0123456789abcdef", &sk);
        assert_eq!(k, format!("vci:attestation:{tk}:0123456789abcdef:{sk}"));
        assert_eq!(
            parse_key(&k),
            Some((tk.as_str(), "0123456789abcdef", sk.as_str()))
        );
        for bad in [
            "vci:attestation",
            "vci:attestation:ab:0123456789abcdef",
            "vci:attestation:ab:0123456789abcdef:cd:x",
            "vci:attestation:AB:0123456789abcdef:cd",
            "vci:attestation:ab:0123:cd",
            "other:attestation:ab:0123456789abcdef:cd",
        ] {
            assert_eq!(parse_key(bad), None, "{bad}");
        }
    }

    #[test]
    fn targets() {
        let p = |id: &str| target_label(&target_for(id));
        assert_eq!(p("src/b.test.ts"), "path:src/b.test.ts");
        assert_eq!(p("demo/go-app/pkg"), "path:demo/go-app/pkg");
        assert_eq!(p("rust#lib"), "path:rust");
        assert_eq!(p("rust#test:it"), "path:rust");
        // git-meta cannot hold these as path targets.
        for id in [".", ".#lib", "rs#lib", "a", "go", ""] {
            assert_eq!(p(id), "project", "{id}");
        }
    }

    #[test]
    fn serializable_targets() {
        assert!(valid_target(&TargetType::Project, ""));
        assert!(valid_target(&TargetType::Path, "src/a.ts"));
        assert!(valid_target(&TargetType::Commit, "abc123"));
        assert!(!valid_target(&TargetType::Path, "ab"));
        assert!(!valid_target(&TargetType::Commit, "€12"));
        assert!(!valid_target(&TargetType::Path, "a\0bc"));
    }

    #[test]
    fn setup_file() {
        let t = tempfile::tempdir().unwrap();
        let p = Utf8PathBuf::from_path_buf(t.path().join(".git-meta")).unwrap();
        assert_eq!(read_setup_url(&p).unwrap(), None);
        std::fs::write(
            &p,
            "# metadata\nurl: \"git@github.com:o/r.git\"\ndepth: 5\n",
        )
        .unwrap();
        assert_eq!(
            read_setup_url(&p).unwrap().as_deref(),
            Some("git@github.com:o/r.git")
        );
        std::fs::write(&p, "depth: 5\n").unwrap();
        assert!(read_setup_url(&p).is_err());
    }
}
