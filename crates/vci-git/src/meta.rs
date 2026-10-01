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
//! * Key: `vci:attestation:<test key>:<signer id>:<storage key>`, where the
//!   test key is BLAKE3 of the test id (it separates units sharing a path,
//!   such as the cargo targets of one package), the signer id names the
//!   signing key (so two signers never write the same key), and the storage
//!   key hashes everything that makes two attestations interchangeable (input
//!   root, toolchain, argv, ...). The same signer re-attesting the same unit
//!   and inputs therefore rewrites the same key.
//! * Value: the signed DSSE envelope, byte for byte.
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
/// The project-local file naming the recommended metadata remote
/// (`url: <url>`), as read by `git meta setup`.
pub const SETUP_FILE: &str = ".git-meta";
/// Name given to a metadata remote vci configures (git-meta's default).
pub const DEFAULT_REMOTE_NAME: &str = "meta";
/// git-meta's minimum target value length.
const MIN_TARGET_LEN: usize = 3;
const PUSH_ATTEMPTS: u32 = 10;
/// Attempts of a fetch that loses a ref-lock race to another git process.
const FETCH_ATTEMPTS: u32 = 5;
/// Project-target settings that make every `git meta serialize` prune.
const PRUNE_KEYS: &[&str] = &["meta:prune:max-keys", "meta:prune:max-size"];

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
    /// The stored bytes, exactly as passed to `put` (empty when `error` is
    /// set).
    pub bytes: Vec<u8>,
    /// Why the value could not be read (a blob missing from the object
    /// database, a value not fetched yet). Such an entry is never valid; it
    /// is listed so that only its own unit loses it.
    pub error: Option<String>,
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

/// The key an attestation is stored under.
pub fn attestation_key(test_key: &str, signer: &str, storage_key: &str) -> String {
    format!("{KEY_PREFIX}:{test_key}:{signer}:{storage_key}")
}

/// Split a key into (test key, signer, storage key) if it has vci's shape.
pub fn parse_key(key: &str) -> Option<(&str, &str, &str)> {
    let rest = key.strip_prefix(KEY_PREFIX)?.strip_prefix(':')?;
    let mut parts = rest.split(':');
    let (Some(tk), Some(signer), Some(sk), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
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
        let mut child = crate::cmd::Git::at(root)
            .args(["cat-file", "--batch"])
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
        let mut env = StoredEnvelope {
            target: target_label(&row.target),
            key: row.key.clone(),
            test_key: tk.to_owned(),
            signer: signer.to_owned(),
            storage_key: sk.to_owned(),
            bytes: Vec::new(),
            error: None,
        };
        let raw = if row.is_promised {
            Err(
                "the value has not been fetched (git-meta promised entry); run `vci fetch`"
                    .to_owned(),
            )
        } else if row.is_git_ref {
            let mut blobs = self.blobs.borrow_mut();
            if blobs.is_none() {
                match CatFile::start(&self.root) {
                    Ok(c) => *blobs = Some(c),
                    Err(e) => {
                        env.error = Some(format!("reading blob {}: {e}", row.value));
                        return Some(env);
                    }
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
        match raw {
            Ok(s) => {
                let s: String = serde_json::from_str(&s).unwrap_or(s);
                env.bytes = s.into_bytes();
            }
            Err(e) => env.error = Some(e),
        }
        Some(env)
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
    /// Entries left out: names that are not UTF-8, or targets git-meta
    /// cannot serialize.
    bad: Vec<String>,
    /// The tree without `bad` entries, when there are any.
    clean_tree: Option<String>,
}

impl Snapshot {
    fn value_keys(&self) -> BTreeSet<Key> {
        self.parsed.values.keys().cloned().collect()
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
        validate::signer_id(signer)?;
        validate::hex_id("storage_key", storage_key)?;
        let text = std::str::from_utf8(bytes).map_err(|_| GitError::Invalid {
            what: "envelope",
            value: String::new(),
            reason: "must be UTF-8",
        })?;
        let tk = vci_core::test_key(test_id);
        let key = attestation_key(&tk, signer, storage_key);
        let target = target_for(test_id);
        let session = self.session()?;
        let handle = session.target(&target);
        let current = handle.get_value(&key).ok().flatten();
        if current != Some(MetaValue::String(text.to_owned())) {
            handle.set(&key, text).map_err(meta_err)?;
        }
        Ok(StoredEnvelope {
            target: target_label(&target),
            key,
            test_key: tk,
            signer: signer.to_owned(),
            storage_key: storage_key.to_owned(),
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
        self.session()?
            .target(&target)
            .remove(&e.key)
            .map_err(meta_err)
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

    /// The URL of a configured remote.
    pub fn remote_url(&self, name: &str) -> Result<Option<String>, GitError> {
        Ok(self
            .remotes()?
            .into_iter()
            .find(|r| r.0 == name)
            .map(|r| r.1))
    }

    /// Configure a metadata remote for `url` the way `git meta remote add`
    /// does (minus its starter commit and blobless fetch settings: vci
    /// fetches whole trees).
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
    fn snapshot(&self, session: &Session, commit: &str) -> Result<Snapshot, GitError> {
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
        for (mode, kind, oid, path) in &records {
            let reason = match std::str::from_utf8(path) {
                Err(_) => Some("name is not UTF-8"),
                Ok(p) => {
                    let parts: Vec<&str> = p.split('/').collect();
                    match parse_path_parts(&parts) {
                        Ok((ty, value, _)) if !valid_target(&ty, &value) => {
                            Some("target git-meta cannot serialize")
                        }
                        _ => None,
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
        Ok(Snapshot {
            parsed,
            bad,
            clean_tree,
        })
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
    fn cover_local_ref(&self, session: &Session, local_ref: &str) -> Result<usize, GitError> {
        let Some(local) = self.read_ref(local_ref)? else {
            return Ok(0);
        };
        let snap = self.snapshot(session, &local)?;
        let store = session.store();
        let rows: BTreeMap<Key, i64> = guarded("reading the store", || store.get_all_metadata())?
            .into_iter()
            .map(|e| {
                (
                    Key {
                        target_type: e.target_type,
                        target_value: e.target_value,
                        key: e.key,
                    },
                    e.last_timestamp,
                )
            })
            .collect();
        let deleted: BTreeSet<Key> = guarded("reading the store", || store.get_all_tombstones())?
            .into_iter()
            .map(|t| Key {
                target_type: t.target_type,
                target_value: t.target_value,
                key: t.key,
            })
            .collect();
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
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

    /// vci attestation keys the store holds a value for.
    fn attestation_keys(&self, session: &Session) -> Result<BTreeSet<Key>, GitError> {
        Ok(
            guarded("reading the store", || session.store().get_all_metadata())?
                .into_iter()
                .filter(|e| parse_key(&e.key).is_some())
                .map(|e| Key {
                    target_type: e.target_type,
                    target_value: e.target_value,
                    key: e.key,
                })
                .collect(),
        )
    }

    /// git-meta's full serialization of the store onto `local_ref`, refused
    /// (and undone) when the new commit would drop a value the previous one
    /// held without the store having a deletion record for it: a filter rule
    /// that excludes or routes the key elsewhere, or a store that does not
    /// match the ref. Publishing such a commit would delete the value for
    /// everyone.
    fn serialize_checked(&self, session: &Session, local_ref: &str) -> Result<(), GitError> {
        let deleted = self.deletion_records(session)?;
        let prev = self.read_ref(local_ref)?;
        let _ = guarded("serializing the git-meta store", || {
            session.serialize_full()
        })?;
        let new = self.read_ref(local_ref)?;
        let (Some(prev), Some(new)) = (prev, new) else {
            return Ok(());
        };
        if prev == new {
            return Ok(());
        }
        let before = self.snapshot(session, &prev)?.value_keys();
        let after = self.snapshot(session, &new)?.value_keys();
        let dropped: Vec<&Key> = before
            .difference(&after)
            .filter(|k| !deleted.contains(*k))
            .collect();
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

    /// Fetch the remote's `refs/<ns>/main` into its tracking ref (whole
    /// trees, no blob filter), serialize local values, and materialize the
    /// remote's into the local store (git-meta's merge). Same refs and result
    /// as `git meta pull`.
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
        let listed = self
            .repo
            .git()
            .args(["ls-remote", "--refs", name, &remote_ref])
            .run_str()?;
        let found = listed
            .lines()
            .any(|l| l.split('\t').nth(1) == Some(remote_ref.as_str()));
        if found {
            self.repo
                .git()
                .args([
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--no-write-fetch-head",
                    "--recurse-submodules=no",
                    "--no-filter",
                    name,
                ])
                .arg(format!("+{remote_ref}:{tracking}"))
                .run()?;
        }
        let purged = self.purge_unserializable_rows()?;
        if purged > 0 {
            report.warn(format!(
                "removed {purged} entr{} from the local git-meta store whose target git-meta cannot serialize (left by an earlier fetch of a malformed tree)",
                if purged == 1 { "y" } else { "ies" }
            ));
        }
        // A fresh session sees the objects the fetch just wrote.
        let session = self.session()?;
        let mut remote_deleted = BTreeSet::new();
        if found && let Some(tip) = self.read_ref(&tracking)? {
            let snap = self.snapshot(&session, &tip)?;
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
            remote_deleted = snap.parsed.tombstones.keys().cloned().collect();
        }
        let restored = self.cover_local_ref(&session, &local_ref)?;
        if restored > 0 {
            report.note(format!(
                "restored {restored} entr{} of {local_ref} into this repository's git-meta store, which did not hold them (a new or replaced .git/git-meta.sqlite, or a linked worktree)",
                if restored == 1 { "y" } else { "ies" }
            ));
        }
        let deleted_here = self.deletion_records(&session)?;
        self.serialize_checked(&session, &local_ref)?;
        if found {
            let before = self.attestation_keys(&session)?;
            let suffix = tracking
                .strip_prefix(&format!("refs/{ns}/"))
                .unwrap_or(&tracking)
                .to_owned();
            let _ = guarded("materializing fetched metadata", || {
                session.materialize(Some(&suffix))
            })?;
            if self.purge_unserializable_rows()? > 0 {
                report.warn(
                    "removed entries the merge wrote that git-meta cannot serialize".to_owned(),
                );
            }
            // Materialize may have applied tombstones or legacy deletes.
            self.serialize_checked(&session, &local_ref)?;
            let after = self.attestation_keys(&session)?;
            let implicit = before
                .difference(&after)
                .filter(|k| !remote_deleted.contains(*k))
                .count();
            if implicit > 0 {
                report.warn(format!(
                    "{implicit} attestation(s) were dropped from {name}'s {remote_ref} without a deletion record (git-meta's auto-prune does this) and are gone from this store too; their units run until attested again"
                ));
            }
        }
        self.settings_warnings(&session, report);
        Ok(Round {
            found,
            deleted_here,
        })
    }

    /// Fetch and merge, then push the local metadata commit as one
    /// fast-forward commit on the remote tip (git-meta's push), retrying from
    /// the fetch when the remote moved in the meantime.
    pub fn push(&self, remote: Option<&str>) -> Result<PushOutcome, GitError> {
        self.push_with_hook(remote, |_| {})
    }

    /// `push`, calling `before_push(attempt)` right before each `git push`.
    /// Exists so tests can simulate a concurrent writer landing in that
    /// window.
    #[doc(hidden)]
    pub fn push_with_hook(
        &self,
        remote: Option<&str>,
        mut before_push: impl FnMut(u32),
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
        let done = |status, report: Report| PushOutcome {
            remote: name.clone(),
            status,
            warnings: report.warnings,
            notes: report.notes,
        };
        for attempt in 1..=PUSH_ATTEMPTS {
            let mut report = Report::default();
            let round = match self.fetch_named(&name, &mut report) {
                Ok(r) => r,
                Err(e) if is_ref_race(&e) && attempt < PUSH_ATTEMPTS => {
                    last = e.to_string();
                    backoff(attempt, 20, 1000);
                    continue;
                }
                Err(e) => return Err(e),
            };
            let Some(local) = self.read_ref(&local_ref)? else {
                return Ok(done(PushStatus::NothingStored, report));
            };
            let tip = self.read_ref(&tracking)?;
            if let Some(tip) = &tip {
                if *tip == local && round.found {
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
                let session = self.session()?;
                let theirs = self.snapshot(&session, tip)?.value_keys();
                let ours = self.snapshot(&session, &local)?.value_keys();
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
            let pushed = self.read_ref(&local_ref)?.unwrap_or(local);
            before_push(attempt);
            let (describe, out) = self
                .repo
                .git()
                .args([
                    "push",
                    "--porcelain",
                    "--no-verify",
                    "--recurse-submodules=no",
                    &name,
                ])
                .arg(format!("{pushed}:{remote_ref}"))
                .output_described()?;
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
            if rejected.is_empty() {
                // Not a ref rejection (unreachable remote, auth...): no retry.
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
