//! # `vci-store-sqlite`: attestations in one SQLite file
//!
//! A [`vci_store::AttestationStore`] kept in a local SQLite file, by default
//! `<git common dir>/vci-store.sqlite`, shared by the repository's linked
//! worktrees (`VCI_STORE=sqlite`, or `VCI_STORE_URL=sqlite:<path>`).
//! `docs/STORE-BACKENDS.md` (section 16) is its design.
//!
//! * **Local.** It has no [`vci_store::Exchange`]: `vci fetch` and
//!   `vci push` say the store is local. Nothing propagates; sharing the file
//!   between machines (a CI cache of it) is up to the operator.
//! * **Lazy.** Opening the store opens nothing. Reading a store whose file
//!   does not exist answers as an empty store
//!   ([`StoreStatus::Absent`]) and creates nothing; the first write creates
//!   the file and its schema, under `BEGIN IMMEDIATE`, so concurrent
//!   first writers create it once.
//! * **Every value is here.** [`AttestationStore::prefetch`] has nothing to
//!   do, and a value never reads as [`vci_store::NOT_FETCHED`].
//! * **One writer at a time.** The file is in WAL mode: readers never wait,
//!   and each write is one `BEGIN IMMEDIATE` transaction that waits at most
//!   [`SqliteOptions::busy_timeout`] for another writer. A put replaces the
//!   older key of its (unit, signer, storage key) slot in one upsert on the
//!   slot's UNIQUE constraint.
//! * **Read-only files read.** A file that cannot be written is opened
//!   read-only, then (in a read-only directory, where the WAL index cannot
//!   be created) as an immutable file. Writes to it fail with
//!   [`StoreError::Denied`].
//! * **Errors say whether the store can be used.** A file that is not a
//!   database is [`StoreError::Unavailable`], a newer schema
//!   [`StoreError::Incompatible`], a file or directory that cannot be
//!   written [`StoreError::Denied`], a lock held past the busy timeout
//!   [`StoreError::Timeout`]; never [`StoreError::Backend`], so `vci run`
//!   keeps the tests' exit code when the store cannot be used.
//! * **A clean file at the end.** When the last handle on the file closes,
//!   the WAL is checkpointed and removed, so a CI cache of the file captures
//!   one consistent file without `-wal` and `-shm`.
//!
//! The pool hands each concurrent caller its own connection (a
//! [`rusqlite::Connection`] is `Send` but not `Sync`). A write batch
//! ([`AttestationStore::batch`]) pins one connection to the thread that
//! opened it, and its writes are one `BEGIN IMMEDIATE` transaction on it,
//! opened by the first write and committed when the batch finishes
//! ([`WriteBatch::deferred`]); each write is a savepoint in it, so a write
//! that fails leaves the others.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod read;
mod schema;
mod write;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, ErrorCode, OpenFlags, TransactionBehavior};
use vci_store::select::{DEFAULT_SQLITE_FILE, DEFAULT_TIMEOUT, Selection};
use vci_store::{
    AttestationStore, BackendFactory, BatchEnd, Caps, GONE, NewAttestation, OpenContext,
    StoreError, StoreStatus, StoredEnvelope, StoredManifest, WriteBatch, key, timing,
};

use crate::schema::{SCHEMA_VERSION, State};

/// The backend's name ([`AttestationStore::kind`]).
const KIND: &str = "sqlite";

/// What creates a store that does not exist yet ([`StoreStatus::Absent`]).
const ABSENT_ADVICE: &str = "the first `vci run` creates it";

/// `VCI_STORE_SYNC=off`: no `fsync` at all (the store is a cache).
const ENV_SYNC: &str = "VCI_STORE_SYNC";

/// Opens the SQLite store (`VCI_STORE=sqlite`, or `VCI_STORE_URL=sqlite:<path>`).
///
/// The file is `[store.sqlite] path` or the path of `VCI_STORE_URL`
/// (absolute, or relative to the git common directory), by default
/// `<git common dir>/vci-store.sqlite`. The busy timeout is the selection's
/// statement timeout (`VCI_STORE_TIMEOUT_SECS`, `[store] timeout`, 30 s by
/// default), and `VCI_STORE_SYNC=off`, read when the store is opened, turns
/// `fsync` off.
#[derive(Debug, Clone, Copy, Default)]
pub struct SqliteFactory;

impl SqliteFactory {
    /// The file `sel` names for the repository `cx` describes.
    pub fn path(sel: &Selection, cx: &OpenContext) -> PathBuf {
        match &sel.sqlite.path {
            None => cx.git_common_dir.join(DEFAULT_SQLITE_FILE),
            Some(p) => {
                let p = Path::new(&p.value);
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    cx.git_common_dir.join(p)
                }
            }
        }
    }
}

impl BackendFactory for SqliteFactory {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn summary(&self) -> &'static str {
        "a local SQLite file (default <git common dir>/vci-store.sqlite)"
    }

    /// The store at [`SqliteFactory::path`]. Nothing is opened or created
    /// until the store is used.
    fn open(
        &self,
        sel: &Selection,
        cx: &OpenContext,
    ) -> Result<Arc<dyn AttestationStore>, StoreError> {
        let opts = SqliteOptions {
            busy_timeout: sel.timeout.value,
            sync_off: std::env::var_os(ENV_SYNC).is_some_and(|v| v == "off"),
            read_only: false,
        };
        Ok(Arc::new(SqliteStore::open_path(
            SqliteFactory::path(sel, cx),
            opts,
        )))
    }
}

/// How [`SqliteStore::open_path`] uses its file.
///
/// Build it from [`SqliteOptions::default`] with struct update syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteOptions {
    /// How long one statement waits for another connection's lock
    /// (SQLite's `busy_timeout`) before failing with [`StoreError::Timeout`].
    /// Writes commit one by one, so waits are short. Default 30 s.
    pub busy_timeout: Duration,
    /// `PRAGMA synchronous = OFF` instead of `NORMAL` (`VCI_STORE_SYNC=off`):
    /// nothing is synced to disk, for a store that is only a cache. Default
    /// false.
    pub sync_off: bool,
    /// Never write: the file is opened read-only (then as an immutable
    /// file), every write is [`StoreError::Denied`], and hints keep nothing.
    /// Default false.
    pub read_only: bool,
}

impl Default for SqliteOptions {
    fn default() -> Self {
        SqliteOptions {
            busy_timeout: DEFAULT_TIMEOUT,
            sync_off: false,
            read_only: false,
        }
    }
}

/// The SQLite store of one file. One value serves every thread of a
/// process; each handle keeps its own pool of connections. See the crate
/// docs.
pub struct SqliteStore {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore")
            .field("path", &self.inner.path)
            .field("options", &self.inner.opts)
            .field("pooled_connections", &self.inner.pool().len())
            .finish()
    }
}

impl SqliteStore {
    /// The store in the file at `path`. Nothing is opened or created until
    /// the store is used: the first read of a missing file answers as an
    /// empty store, and the first write creates the file (and its parent
    /// directories) and its schema.
    pub fn open_path(path: impl Into<PathBuf>, opts: SqliteOptions) -> SqliteStore {
        SqliteStore {
            inner: Arc::new(Inner {
                id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                path: path.into(),
                opts,
                pool: Mutex::new(Vec::new()),
                writes: AtomicU64::new(0),
                write_nanos: AtomicU64::new(0),
            }),
        }
    }

    /// The file this store keeps its records in.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// The options it was opened with.
    pub fn options(&self) -> SqliteOptions {
        self.inner.opts
    }
}

impl AttestationStore for SqliteStore {
    fn kind(&self) -> &'static str {
        KIND
    }

    /// The file's path.
    fn location(&self) -> String {
        self.inner.path.display().to_string()
    }

    /// Local, every value present, keeping the memo and flags.
    fn caps(&self) -> Caps {
        Caps::LOCAL.with_hints(true)
    }

    /// `Absent` when there is no file or no schema yet (nothing is created
    /// to find out), `Ready` with the schema version otherwise.
    fn status(&self) -> Result<StoreStatus, StoreError> {
        Ok(match self.inner.read(|_| Ok(()))? {
            Some(()) => StoreStatus::Ready {
                schema_version: Some(SCHEMA_VERSION),
            },
            None => StoreStatus::Absent {
                advice: ABSENT_ADVICE.to_owned(),
            },
        })
    }

    /// One index-only seek per unit, on one connection in one read
    /// transaction.
    fn list_units(&self, test_ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
        let step = timing::Step::start(KIND);
        let out = self
            .inner
            .read(|c| read::list_units(c, test_ids))?
            .unwrap_or_else(|| vec![Vec::new(); test_ids.len()]);
        step.done(format!("list {} unit(s)", test_ids.len()));
        Ok(out)
    }

    fn list_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
        Ok(self.inner.read(read::list_all)?.unwrap_or_default())
    }

    /// One lookup by key per entry, in one read transaction. A key no
    /// longer stored reads as [`GONE`], a value of an unknown `encoding` as
    /// unreadable.
    fn read_values(&self, envs: &mut [&mut StoredEnvelope]) -> Result<(), StoreError> {
        let step = timing::Step::start(KIND);
        let n = envs.len();
        if self
            .inner
            .read(|c| read::read_values(c, &mut *envs))?
            .is_none()
        {
            for e in envs.iter_mut() {
                e.set_error(GONE);
            }
        }
        step.done(format!("read {n} value(s)"));
        Ok(())
    }

    fn manifest(&self, root: &str) -> Result<Option<StoredManifest>, StoreError> {
        Ok(self.inner.read(|c| read::manifest(c, root))?.flatten())
    }

    fn manifest_roots(&self) -> Result<Vec<String>, StoreError> {
        Ok(self.inner.read(read::manifest_roots)?.unwrap_or_default())
    }

    /// Validates, then one upsert on the slot's UNIQUE constraint in one
    /// `BEGIN IMMEDIATE` transaction.
    fn put(&self, att: &NewAttestation<'_>) -> Result<StoredEnvelope, StoreError> {
        att.validate()?;
        let now = unix_now();
        let k = self.inner.write("write", |c| write::put(c, att, now))?;
        Ok(att.stored(k))
    }

    /// Writes unless exactly these bytes are stored, and refreshes the
    /// manifest's `put_at` either way.
    fn put_manifest(&self, root: &str, bytes: &[u8]) -> Result<bool, StoreError> {
        key::check_hex("input root", root)?;
        if bytes.is_empty() {
            return Err(StoreError::invalid("manifest", "", "must not be empty"));
        }
        key::check_utf8("manifest", bytes)?;
        let now = unix_now();
        self.inner
            .write("write", |c| write::put_manifest(c, root, bytes, now))
    }

    /// One `BEGIN IMMEDIATE` transaction. A store whose file does not exist
    /// removes nothing and is not created.
    fn remove(&self, doomed: Vec<StoredEnvelope>) -> Result<Vec<StoredEnvelope>, StoreError> {
        if doomed.is_empty() || !self.inner.exists()? {
            return Ok(Vec::new());
        }
        self.inner.write("write", |c| write::remove(c, doomed))
    }

    /// Every root is validated first. Then, in one `BEGIN IMMEDIATE`
    /// transaction, only the roots that no attestation references and no
    /// manifest uses as its base are deleted: SQLite has one writer, so the
    /// check is atomic and needs no grace period.
    fn remove_manifests(&self, roots: &[&str]) -> Result<usize, StoreError> {
        for r in roots {
            key::check_hex("input root", r)?;
        }
        if roots.is_empty() || !self.inner.exists()? {
            return Ok(0);
        }
        self.inner
            .write("write", |c| write::remove_manifests(c, roots))
    }

    fn count(&self) -> Result<usize, StoreError> {
        Ok(self.inner.read(read::count)?.unwrap_or(0))
    }

    /// Every root on one connection in one read transaction.
    fn manifests(&self, roots: &[&str]) -> Result<Vec<Option<StoredManifest>>, StoreError> {
        Ok(self
            .inner
            .read(|c| read::manifests(c, roots))?
            .unwrap_or_else(|| vec![None; roots.len()]))
    }

    /// From the `manifest_ref` and `ref_state` columns written at put time:
    /// nothing when some attestation's reference is unknown, else the roots
    /// no attestation references. No value is read.
    fn orphan_manifests(&self, roots: &[&str]) -> Result<Vec<String>, StoreError> {
        let found = self.inner.read(|c| read::orphan_manifests(c, roots))?;
        Ok(found.unwrap_or_else(|| {
            // No store: nothing references anything.
            let wanted: BTreeSet<&str> = roots.iter().copied().collect();
            wanted.into_iter().map(str::to_owned).collect()
        }))
    }

    /// A deferred batch: this thread's writes share one connection and are
    /// one transaction on it, committed when the batch finishes (2.8: a
    /// commit per write was most of the time `vci run` spent storing).
    fn batch(&self) -> Result<WriteBatch, StoreError> {
        let id = self.inner.id;
        PINNED.with(|p| {
            let mut p = p.borrow_mut();
            match p.iter_mut().find(|x| x.store == id) {
                Some(x) => x.depth += 1,
                None => p.push(Pin {
                    store: id,
                    depth: 1,
                    conn: None,
                    writes: 0,
                    nanos: 0,
                    open: false,
                    broken: None,
                }),
            }
        });
        Ok(WriteBatch::deferred(Box::new(SqliteBatch {
            inner: Arc::clone(&self.inner),
        })))
    }

    /// Reads the file through once on a thread, so the first queries find
    /// it in the page cache.
    fn warm(&self) {
        let path = self.inner.path.clone();
        if !path.exists() {
            return;
        }
        let _ = std::thread::Builder::new()
            .name("vci-sqlite-warm".to_owned())
            .spawn(move || {
                if let Ok(mut f) = std::fs::File::open(path) {
                    let mut buf = vec![0u8; 1 << 20];
                    while matches!(f.read(&mut buf), Ok(n) if n > 0) {}
                }
            });
    }

    fn passing_on(&self, tree16: &str) -> BTreeMap<String, String> {
        self.inner
            .read(|c| read::passing_on(c, tree16))
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Also forgets memo rows older than a week. Nothing happens when the
    /// store's file does not exist yet.
    fn remember_passing(&self, tree16: &str, items: &[(String, String)]) {
        if items.is_empty() {
            return;
        }
        let now = unix_now();
        self.inner
            .hint(|c| write::remember_passing(c, tree16, items, now));
    }

    fn flag(&self, name: &str) -> bool {
        self.inner
            .read(|c| read::flag(c, name))
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// Nothing happens when the store's file does not exist yet.
    fn set_flag(&self, name: &str) {
        let now = unix_now();
        self.inner.hint(|c| write::set_flag(c, name, now));
    }

    /// `store: sqlite: N write(s): S s`, the writes of this handle so far
    /// and the seconds they took, when it wrote anything.
    fn timing_report(&self) -> Vec<String> {
        let n = self.inner.writes.load(Ordering::Relaxed);
        if n == 0 {
            return Vec::new();
        }
        let secs = self.inner.write_nanos.load(Ordering::Relaxed) as f64 / 1e9;
        vec![format!("store: {KIND}: {n} write(s): {secs:.2}s")]
    }
}

// ---- connections -----------------------------------------------------------------

/// Distinguishes handles, for this thread's batch connections.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// The batches open on this thread, one per store handle, each with the
    /// connection its writes share.
    static PINNED: RefCell<Vec<Pin>> = const { RefCell::new(Vec::new()) };
}

/// One store's write batch on this thread.
struct Pin {
    store: u64,
    /// Batches opened and not finished (a batch inside a batch shares it).
    depth: usize,
    /// The connection the batch's writes share, once one wrote.
    conn: Option<Conn>,
    /// Writes made in the batch, and their nanoseconds.
    writes: u64,
    nanos: u64,
    /// Whether the batch's transaction is open on `conn`.
    open: bool,
    /// Why the batch cannot commit: its transaction was lost.
    broken: Option<String>,
}

/// A connection and whether its file is known to hold the schema.
struct Conn {
    db: Connection,
    ready: bool,
}

/// What a connection is wanted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Reading: a missing file or schema is an empty store.
    Read,
    /// Writing: a missing file and schema are created.
    Write,
}

/// One handle's file, options and connections.
struct Inner {
    id: u64,
    path: PathBuf,
    opts: SqliteOptions,
    pool: Mutex<Vec<Conn>>,
    writes: AtomicU64,
    write_nanos: AtomicU64,
}

impl Inner {
    fn pool(&self) -> MutexGuard<'_, Vec<Conn>> {
        self.pool.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether the file exists.
    fn exists(&self) -> Result<bool, StoreError> {
        match std::fs::metadata(&self.path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(self.unavailable(format!("cannot read it: {e}"))),
        }
    }

    /// Run a read on a connection whose file holds the schema. `Ok(None)`
    /// when the store does not exist yet (no file, or no schema).
    fn read<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<Option<T>, StoreError> {
        self.with_conn(Mode::Read, |db| f(db).map_err(|e| self.error("read", e)))
    }

    /// Run `f` in one `BEGIN IMMEDIATE` transaction, creating the file and
    /// the schema first when they do not exist.
    fn write<T>(
        &self,
        operation: &'static str,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, StoreError> {
        if self.opts.read_only {
            return Err(StoreError::Denied {
                backend: KIND,
                operation,
                detail: format!("{}: the store was opened read-only", self.path.display()),
            });
        }
        let start = Instant::now();
        let batched = self.pin_with(|_| ()).is_some();
        let out = self.with_conn(Mode::Write, |db| {
            if batched {
                return self.write_in_batch(operation, db, f);
            }
            let tx = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| self.error(operation, e))?;
            let v = f(&tx).map_err(|e| self.error(operation, e))?;
            tx.commit().map_err(|e| self.error(operation, e))?;
            Ok(v)
        });
        self.count_write(start.elapsed());
        out?.ok_or_else(|| self.unavailable("its schema could not be created".to_owned()))
    }

    /// `f` as one write of this thread's batch: in the batch's transaction
    /// (begun by its first write) on `db`, the batch's connection, inside a
    /// savepoint that a failure rolls back. When SQLite ends the
    /// transaction itself (an I/O error, a full disk), the batch is broken:
    /// this and every later write fails, and so does its end.
    fn write_in_batch<T>(
        &self,
        operation: &'static str,
        db: &mut Connection,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, StoreError> {
        let (open, broken) = self
            .pin_with(|p| (p.open, p.broken.clone()))
            .unwrap_or((false, None));
        if let Some(why) = broken {
            return Err(self.unavailable(why));
        }
        let begin = if open {
            "SAVEPOINT vci_write"
        } else {
            "BEGIN IMMEDIATE; SAVEPOINT vci_write"
        };
        if let Err(e) = db.execute_batch(begin) {
            if !open && !db.is_autocommit() {
                let _ = db.execute_batch("ROLLBACK");
            }
            return Err(self.error(operation, e));
        }
        self.pin_with(|p| p.open = true);
        let out = f(db).map_err(|e| self.error(operation, e));
        let end = match &out {
            Ok(_) => db.execute_batch("RELEASE vci_write"),
            Err(_) => db.execute_batch("ROLLBACK TO vci_write; RELEASE vci_write"),
        };
        let out = match (out, end) {
            (Ok(_), Err(e)) => Err(self.error(operation, e)),
            (out, _) => out,
        };
        if db.is_autocommit() {
            let why = format!(
                "{}: the write batch's transaction was rolled back{}",
                self.path.display(),
                match &out {
                    Err(e) => format!(" ({e})"),
                    Ok(_) => String::new(),
                }
            );
            self.pin_with(|p| {
                p.open = false;
                p.broken.get_or_insert(why.clone());
            });
            return Err(self.unavailable(why));
        }
        out
    }

    /// `f` on this thread's batch on this store, when one is open.
    fn pin_with<R>(&self, f: impl FnOnce(&mut Pin) -> R) -> Option<R> {
        let id = self.id;
        PINNED
            .try_with(|p| p.borrow_mut().iter_mut().find(|x| x.store == id).map(f))
            .ok()
            .flatten()
    }

    /// A hint's write: only into a file that exists, and never failing.
    fn hint(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<()>) {
        if self.opts.read_only || !self.exists().unwrap_or(false) {
            return;
        }
        let _ = self.write("remember a hint", f);
    }

    fn count_write(&self, took: Duration) {
        let nanos = u64::try_from(took.as_nanos()).unwrap_or(u64::MAX);
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.write_nanos.fetch_add(nanos, Ordering::Relaxed);
        let id = self.id;
        let _ = PINNED.try_with(|p| {
            if let Some(x) = p.borrow_mut().iter_mut().find(|x| x.store == id) {
                x.writes += 1;
                x.nanos = x.nanos.saturating_add(nanos);
            }
        });
    }

    /// Run `f` on a connection: this thread's batch connection, a pooled
    /// one, or a new one, whose file holds the schema (created first for a
    /// write). The connection goes back where it came from afterwards (a
    /// write inside a batch keeps it for the batch), unless the store
    /// could not be used through it.
    fn with_conn<T>(
        &self,
        mode: Mode,
        f: impl FnOnce(&mut Connection) -> Result<T, StoreError>,
    ) -> Result<Option<T>, StoreError> {
        let pinned = self.pin_take();
        let in_batch = pinned.is_some();
        let from_pin = matches!(pinned, Some(Some(_)));
        let found = match pinned.flatten() {
            Some(c) => Some(c),
            None => self.pool().pop(),
        };
        let mut conn = match found {
            Some(c) => c,
            None => match self.open(mode)? {
                Some(c) => c,
                None => return Ok(None),
            },
        };
        let to_pin = from_pin || (in_batch && mode == Mode::Write);
        if !conn.ready {
            let (state, operation) = match mode {
                Mode::Read => (schema::state(&conn.db), "read"),
                Mode::Write => (
                    schema::migrate(&mut conn.db, self.opts.busy_timeout),
                    "create the schema",
                ),
            };
            match state.map_err(|e| self.error(operation, e))? {
                State::Ready => conn.ready = true,
                State::Empty => {
                    self.give_back(conn, to_pin);
                    return Ok(None);
                }
                State::Newer(found) => {
                    return Err(StoreError::Incompatible {
                        backend: KIND,
                        found,
                        supported: SCHEMA_VERSION,
                    });
                }
                State::Foreign(why) => {
                    return Err(self.unavailable(format!("not a vci store: {why}")));
                }
            }
        }
        let out = f(&mut conn.db);
        match &out {
            Err(StoreError::Unavailable { detail, .. }) => {
                if to_pin {
                    // The batch's connection is dropped, and its open
                    // transaction with it: the batch cannot commit.
                    let why = detail.clone();
                    self.pin_with(|p| {
                        if p.open {
                            p.open = false;
                            p.broken.get_or_insert(why);
                        }
                    });
                }
            }
            _ => self.give_back(conn, to_pin),
        }
        out.map(Some)
    }

    /// This thread's batch on this store: `None` when none is open, else
    /// its connection (taken out while it is used; `None` before the
    /// batch's first write).
    fn pin_take(&self) -> Option<Option<Conn>> {
        let id = self.id;
        PINNED
            .try_with(|p| {
                p.borrow_mut()
                    .iter_mut()
                    .find(|x| x.store == id)
                    .map(|x| x.conn.take())
            })
            .ok()
            .flatten()
    }

    /// Put `conn` back: into this thread's batch when `to_pin` and the
    /// batch is still open, else into the pool.
    fn give_back(&self, conn: Conn, to_pin: bool) {
        let id = self.id;
        let left = if to_pin {
            PINNED
                .try_with(
                    |p| match p.borrow_mut().iter_mut().find(|x| x.store == id) {
                        Some(x) => x.conn.replace(conn),
                        None => Some(conn),
                    },
                )
                .unwrap_or(None)
        } else {
            Some(conn)
        };
        if let Some(c) = left {
            self.pool().push(c);
        }
    }

    /// A new connection to the file. `Ok(None)` when reading and the file
    /// does not exist; a write creates it (and its directory).
    ///
    /// An existing file is opened read-write; when that cannot read it, it
    /// is opened read-only, then as an immutable file (a read-only
    /// directory, where the WAL index cannot be created). A file that is
    /// not a database fails at once.
    fn open(&self, mode: Mode) -> Result<Option<Conn>, StoreError> {
        if !self.exists()? {
            if mode == Mode::Read || self.opts.read_only {
                return Ok(None);
            }
            return self.create().map(Some);
        }
        let rw = OpenFlags::SQLITE_OPEN_READ_WRITE;
        let ro = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
        let mut tries: Vec<(PathBuf, OpenFlags)> = Vec::with_capacity(3);
        if !self.opts.read_only {
            tries.push((self.path.clone(), rw));
        }
        tries.push((uri(&self.path, "mode=ro").into(), ro));
        tries.push((uri(&self.path, "immutable=1").into(), ro));
        let mut failures = Vec::new();
        for (spec, flags) in tries {
            match self.connect(&spec, flags) {
                Ok(db) => return Ok(Some(Conn { db, ready: false })),
                Err(e) if not_a_database(&e) => return Err(self.error("read", e)),
                Err(e) => failures.push(e.to_string()),
            }
        }
        Err(self.unavailable(format!(
            "cannot open it: {}",
            failures.join("; read-only: ")
        )))
    }

    /// Create the file (and its directory) and connect to it.
    fn create(&self) -> Result<Conn, StoreError> {
        if let Some(dir) = self.path.parent()
            && !dir.as_os_str().is_empty()
            && let Err(e) = std::fs::create_dir_all(dir)
        {
            let detail = format!(
                "{}: cannot create {}: {e}",
                self.path.display(),
                dir.display()
            );
            return Err(if e.kind() == std::io::ErrorKind::PermissionDenied {
                StoreError::Denied {
                    backend: KIND,
                    operation: "create the store",
                    detail,
                }
            } else {
                StoreError::Unavailable {
                    backend: KIND,
                    detail,
                }
            });
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
        match self.connect(&self.path, flags) {
            Ok(db) => Ok(Conn { db, ready: false }),
            Err(e) if e.sqlite_error_code() == Some(ErrorCode::CannotOpen) => {
                Err(StoreError::Denied {
                    backend: KIND,
                    operation: "create the store",
                    detail: format!("{}: {e}", self.path.display()),
                })
            }
            Err(e) => Err(self.error("create the store", e)),
        }
    }

    /// Open `spec` with `flags`, set the connection up, and read the schema
    /// table once, so that a file that cannot be read fails here.
    fn connect(&self, spec: &Path, flags: OpenFlags) -> rusqlite::Result<Connection> {
        let db = Connection::open_with_flags(spec, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        db.busy_timeout(self.opts.busy_timeout)?;
        db.pragma_update(
            None,
            "synchronous",
            if self.opts.sync_off { "OFF" } else { "NORMAL" },
        )?;
        db.pragma_update(None, "foreign_keys", false)?;
        db.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
        Ok(db)
    }

    /// The store error for a SQLite error during `operation`: a lock held
    /// too long is [`StoreError::Timeout`], a file or directory that cannot
    /// be written [`StoreError::Denied`], anything else (not a database,
    /// corrupt, an I/O error) [`StoreError::Unavailable`].
    fn error(&self, operation: &'static str, e: rusqlite::Error) -> StoreError {
        match e.sqlite_error_code() {
            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => StoreError::Timeout {
                backend: KIND,
                operation: "waiting for another writer",
                after: self.opts.busy_timeout,
            },
            Some(
                ErrorCode::ReadOnly
                | ErrorCode::PermissionDenied
                | ErrorCode::AuthorizationForStatementDenied,
            ) => StoreError::Denied {
                backend: KIND,
                operation,
                detail: format!("{}: {e}", self.path.display()),
            },
            _ => self.unavailable(e.to_string()),
        }
    }

    fn unavailable(&self, why: String) -> StoreError {
        StoreError::Unavailable {
            backend: KIND,
            detail: format!("{}: {why}", self.path.display()),
        }
    }
}

impl Drop for Inner {
    /// Checkpoint the WAL into the file (best effort, waiting for no one),
    /// then close every connection; the last connection to the file removes
    /// the `-wal` and `-shm` files.
    fn drop(&mut self) {
        let conns = std::mem::take(self.pool.get_mut().unwrap_or_else(|p| p.into_inner()));
        if !self.opts.read_only
            && let Some(c) = conns.iter().find(|c| c.ready)
        {
            let _ = c.db.busy_timeout(Duration::from_millis(100));
            let _ =
                c.db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        }
        drop(conns);
    }
}

/// A write batch on one store: while it is open, this thread's writes
/// through the store share one connection.
struct SqliteBatch {
    inner: Arc<Inner>,
}

impl BatchEnd for SqliteBatch {
    /// The outermost batch commits the transaction, then gives the shared
    /// connection back to the pool. It fails when the commit does, or when
    /// the transaction was lost; nothing of the batch is stored then.
    fn finish(self: Box<Self>) -> Result<(), StoreError> {
        let id = self.inner.id;
        let ended = PINNED
            .try_with(|p| {
                let mut p = p.borrow_mut();
                let i = p.iter().position(|x| x.store == id)?;
                p[i].depth -= 1;
                (p[i].depth == 0).then(|| p.remove(i))
            })
            .ok()
            .flatten();
        let mut result = Ok(());
        if let Some(pin) = ended {
            if let Some(why) = pin.broken {
                result = Err(self.inner.unavailable(why));
            } else if pin.open && pin.conn.is_none() {
                result = Err(self.inner.unavailable(format!(
                    "{}: the write batch's connection was lost",
                    self.inner.path.display()
                )));
            }
            if let Some(c) = pin.conn {
                if !c.db.is_autocommit() {
                    let end = if result.is_ok() {
                        c.db.execute_batch("COMMIT")
                    } else {
                        c.db.execute_batch("ROLLBACK")
                    };
                    if let Err(e) = end {
                        let _ = c.db.execute_batch("ROLLBACK");
                        result = Err(self.inner.error("write", e));
                    }
                }
                self.inner.pool().push(c);
            }
            if pin.writes > 0 && vci_core::metrics::on() {
                vci_core::timing_line!(
                    "store: {KIND}: write {} record(s): {:.2}s",
                    pin.writes,
                    pin.nanos as f64 / 1e9
                );
            }
        }
        result
    }
}

/// Whether `e` says the file is not a SQLite database (or a damaged one):
/// no other way of opening it will read it.
fn not_a_database(e: &rusqlite::Error) -> bool {
    matches!(
        e.sqlite_error_code(),
        Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt)
    )
}

/// A `file:` URI for `path` with the query `query`, every byte outside a
/// safe set percent-encoded.
fn uri(path: &Path, query: &str) -> String {
    let mut out = String::from("file:");
    for &b in path.as_os_str().as_encoded_bytes() {
        if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out.push('?');
    out.push_str(query);
    out
}

/// Seconds since the epoch.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vci_store::select::{Source, Sourced};

    fn cx(common: &str) -> OpenContext {
        OpenContext {
            repo_root: "/repo".into(),
            git_dir: "/repo/.git/worktrees/w".into(),
            git_common_dir: common.into(),
            repo_id: Arc::new(|| Err("no repository".to_owned())),
            jobs: 1,
            command: "test".to_owned(),
            long_running: false,
        }
    }

    fn with_path(p: &str) -> Selection {
        let mut sel = Selection::for_backend("sqlite");
        sel.sqlite.path = Some(Sourced {
            value: p.to_owned(),
            source: Source::File,
        });
        sel
    }

    #[test]
    fn the_file_is_in_the_git_common_dir_by_default() {
        let sel = Selection::for_backend("sqlite");
        assert_eq!(
            SqliteFactory::path(&sel, &cx("/repo/.git")),
            PathBuf::from("/repo/.git/vci-store.sqlite")
        );
        assert_eq!(
            SqliteFactory::path(&with_path("ci/store.sqlite"), &cx("/repo/.git")),
            PathBuf::from("/repo/.git/ci/store.sqlite")
        );
        assert_eq!(
            SqliteFactory::path(&with_path("/var/cache/vci.sqlite"), &cx("/repo/.git")),
            PathBuf::from("/var/cache/vci.sqlite")
        );
    }

    #[test]
    fn opening_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let common = dir.path().join("common");
        let f = SqliteFactory;
        assert_eq!(f.kind(), "sqlite");
        let mut sel = Selection::for_backend("sqlite");
        sel.timeout = Sourced::default_value(Duration::from_secs(7));
        let store = f.open(&sel, &cx(common.to_str().unwrap())).unwrap();
        assert_eq!(store.kind(), "sqlite");
        assert_eq!(
            store.location(),
            common.join("vci-store.sqlite").display().to_string()
        );
        assert!(store.exchange().is_none());
        assert_eq!(store.caps(), Caps::LOCAL.with_hints(true));
        assert_eq!(
            store.status().unwrap(),
            StoreStatus::Absent {
                advice: "the first `vci run` creates it".to_owned()
            }
        );
        assert!(!common.exists());
    }

    #[test]
    fn uris_encode_what_sqlite_would_parse() {
        assert_eq!(
            uri(Path::new("/a b/c?d#e%f.sqlite"), "mode=ro"),
            "file:/a%20b/c%3Fd%23e%25f.sqlite?mode=ro"
        );
    }
}
