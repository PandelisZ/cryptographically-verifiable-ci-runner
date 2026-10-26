//! The replica mode: reads come from a local file, synced from the server
//! when the store is first used and again at each later prefetch; writes go
//! to the server, and through to the file once they are stored.
//! `docs/STORE-BACKENDS.md` section 18, "The replica mode".
//!
//! * **The file** is a SQLite store file ([`vci_store_sqlite`], under the
//!   name `libsql`), by default `<git common dir>/vci-store.libsql`. Beside
//!   it, `<file>.sync` says which server and namespace it copies, up to
//!   which entry of the server's change log, that entry's fingerprint and
//!   when the namespace was created. A file without one is not a replica (a
//!   local-mode store, say), and a file that is not a database is not one
//!   either: neither is read or written, and the store is unavailable until
//!   `VCI_STORE_REPLICA` names another file.
//! * **The sync** is one request (after the statement's description, a
//!   handle's first request, which is bounded by the connect timeout):
//!   the namespace's schema version (a newer one is refused) and
//!   everything the change log names since the last sync, in one
//!   snapshot. Everything is
//!   read when the file is new, belongs to another server or namespace, is
//!   older than the log, or when the log no longer holds the entry the file
//!   was synced to as it was (the namespace was dropped and created again,
//!   or restored to an earlier point). It is applied in one transaction, so
//!   a reader never sees half of it. A sync that fails (the server
//!   unreachable, a deadline run out) leaves the file as it was: the plan,
//!   `vci run`, `vci ci`, `vci explain` and `vci verify` read it as it is
//!   with a warning (a stale replica only makes units run), while `vci
//!   store`, `vci fetch`, `vci push` and `vci prune`, which are about the
//!   store itself, fail; they also fail on a replica they cannot keep (a
//!   directory vci cannot write, a sync that cannot be written to the
//!   file), whether or not the server holds anything yet.
//! * **Reads** come from the file, a snapshot taken at its sync. Before
//!   the caller's first prefetch, `read_values` syncs what changed first,
//!   so a key removed since it was listed reads as gone (section 4); after
//!   a prefetch, the file as that prefetch synced it.
//! * **Writes** are the remote mode's, then the same writes to the file.
//!   They need a usable replica (a file vci can keep beside its server). A
//!   write that cannot be written through leaves this handle reading from
//!   the server for the rest of the process, so it still reads its own
//!   writes; the next sync brings them to the file.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use libsql::Value as V;
use serde_json::json;
use vci_store::timing::Step;
use vci_store::{AttestationStore, KeyHint, NewAttestation, StoreError, StoredEnvelope, key};
use vci_store_sqlite::{SqliteOptions, SqliteStore};

use crate::batch::{After, Pending};
use crate::conn::{Fail, KIND, READ, col_int, col_text, col_value};
use crate::remote::Remote;

/// The commands for which a replica that cannot be synced is an error:
/// they report on or change the store itself (`vci store info`, fetch,
/// push, prune), so a stale file would answer for a server that was not
/// asked.
const STRICT_COMMANDS: &[&str] = &["store", "fetch", "push", "prune"];

/// The replica of one remote handle.
pub(crate) struct Replica {
    pub(crate) remote: Arc<Remote>,
    pub(crate) path: PathBuf,
    opts: SqliteOptions,
    /// Read the file as it is when a sync fails (with a warning), rather
    /// than fail.
    stale_ok: bool,
    local: OnceLock<Result<SqliteStore, String>>,
    /// One sync at a time.
    syncing: Mutex<()>,
    /// `<file>.sync` is known to exist.
    marked: AtomicBool,
    /// The file's directory was found writable.
    writable_dir: OnceLock<()>,
    /// The caller has prefetched: reads may come from the file as that
    /// prefetch synced it (section 4's snapshot), until the next one.
    prefetched: AtomicBool,
    /// A write could not be written through: reads go to the server.
    degraded: AtomicBool,
    write_through_warned: AtomicBool,
    resync_warned: AtomicBool,
}

/// What the sync found on the server.
#[derive(Default)]
struct Changes {
    /// The change log's last entry.
    seq: i64,
    /// Entries up to this one were dropped from the log.
    floor: i64,
    /// The fingerprint of the entry the file was synced to, as the log
    /// holds it now (`None`: gone, or the file was synced to none).
    mark_then: Option<String>,
    /// The fingerprint of the log's last entry.
    mark_now: Option<String>,
    /// When the namespace was created.
    epoch: Option<i64>,
    /// The attestations of the slots touched: key, target, value.
    attestations: Vec<(String, String, Result<Vec<u8>, String>)>,
    /// The slots touched, as `test key:signer:storage key`.
    slots: BTreeSet<String>,
    /// The manifests touched: root, value.
    manifests: Vec<(String, Result<Vec<u8>, String>)>,
    /// The roots touched.
    roots: BTreeSet<String>,
}

/// `<file>.sync`: which server and namespace the file copies, and up to
/// which entry of its log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Sidecar {
    source: String,
    seq: i64,
    /// The fingerprint of entry `seq` (its time, slot or root).
    mark: Option<String>,
    /// When the namespace was created.
    epoch: Option<i64>,
}

/// Why a sync did not happen.
enum SyncFail {
    /// The server could not be asked (or answered with an error).
    Server(StoreError),
    /// The file could not be brought up to date or marked.
    File(String),
}

/// `<file>.sync`.
fn sidecar(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".sync");
    PathBuf::from(s)
}

impl Replica {
    pub(crate) fn new(
        remote: Arc<Remote>,
        path: PathBuf,
        opts: SqliteOptions,
        command: &str,
    ) -> Replica {
        Replica {
            remote,
            path,
            opts,
            stale_ok: !STRICT_COMMANDS.contains(&command),
            local: OnceLock::new(),
            syncing: Mutex::new(()),
            marked: AtomicBool::new(false),
            writable_dir: OnceLock::new(),
            prefetched: AtomicBool::new(false),
            degraded: AtomicBool::new(false),
            write_through_warned: AtomicBool::new(false),
            resync_warned: AtomicBool::new(false),
        }
    }

    /// The replica, synced the first time it is asked for.
    pub(crate) fn local(&self) -> Result<&SqliteStore, StoreError> {
        self.local
            .get_or_init(|| self.open_and_sync())
            .as_ref()
            .map_err(|e| StoreError::unavailable(KIND, e.clone()))
    }

    /// Whether reads go to the server (a write could not be written
    /// through, so the file lacks it).
    pub(crate) fn degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// Before a write: the file is a usable replica, and one vci can keep
    /// (its directory takes `<file>.sync`), so a file that is not a
    /// replica, or a directory vci cannot write, refuses the write instead
    /// of leaving the file behind the server. Nothing is created here: the
    /// write marks the file once the server stored it.
    pub(crate) fn writable(&self) -> Result<(), StoreError> {
        self.local()?;
        if self.marked.load(Ordering::Relaxed) || self.writable_dir.get().is_some() {
            return Ok(());
        }
        self.probe(true)
            .map_err(|e| StoreError::unavailable(KIND, e))
    }

    /// Whether vci can write in the file's directory: a probe file, made
    /// there and removed at once. With `create`, the directory is made
    /// first when missing (a write is about to make the file there);
    /// without, nothing else is made, and a missing directory is judged by
    /// the nearest one above it, where it would be made.
    fn probe(&self, create: bool) -> Result<(), String> {
        let side = sidecar(&self.path);
        let dir = side
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let cannot = |at: &Path, e: std::io::Error| {
            format!(
                "the replica {} cannot be kept: cannot write in {}: {e}",
                self.path.display(),
                at.display()
            )
        };
        let at = if create {
            std::fs::create_dir_all(dir).map_err(|e| cannot(dir, e))?;
            dir
        } else {
            dir.ancestors()
                .find(|d| d.as_os_str().is_empty() || d.is_dir())
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
        };
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let name = side.file_name().map_or_else(
            || "vci-replica".into(),
            |n| n.to_string_lossy().into_owned(),
        );
        let probe = at.join(format!(
            "{name}.{}.{}.probe",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&probe, b"")
            .and_then(|()| std::fs::remove_file(&probe))
            .map_err(|e| cannot(at, e))?;
        if at == dir {
            let _ = self.writable_dir.set(());
        }
        Ok(())
    }

    /// A prefetch: the first use syncs (that is the opening sync); every
    /// later one syncs what changed since, so the next prefetch of data
    /// picks up other writers' changes (`docs/STORE-BACKENDS.md` section
    /// 4). A failed sync again is a warning, once.
    pub(crate) fn prefetch(&self) -> Result<(), StoreError> {
        self.prefetched.store(true, Ordering::Relaxed);
        let first = self.local.get().is_none();
        let store = self.local()?;
        if first || self.degraded() {
            return Ok(());
        }
        self.resync(store)
    }

    /// The file for a read that must see what the server holds now, as a
    /// remote handle's read without a prefetch does: before the caller's
    /// first prefetch, the changes since the last sync are synced first
    /// (one request when there are none), so a key another writer removed
    /// since it was listed reads as gone (section 4, `read_values`). After
    /// a prefetch, the file as that prefetch synced it.
    pub(crate) fn current(&self) -> Result<&SqliteStore, StoreError> {
        let first = self.local.get().is_none();
        let store = self.local()?;
        if !first && !self.degraded() && !self.prefetched.load(Ordering::Relaxed) {
            self.resync(store)?;
        }
        Ok(store)
    }

    /// Sync `store` again: a failure is a warning, once, and the file is
    /// read as it is; for the commands about the store itself, an error.
    fn resync(&self, store: &SqliteStore) -> Result<(), StoreError> {
        match self.sync(store) {
            Ok(()) => {}
            Err(SyncFail::Server(e)) if !self.stale_ok => return Err(e),
            Err(SyncFail::File(e)) if !self.stale_ok => {
                return Err(StoreError::unavailable(
                    KIND,
                    format!("the replica {} cannot be kept: {e}", self.path.display()),
                ));
            }
            Err(SyncFail::Server(e)) => self.warn_resync(&e.to_string()),
            Err(SyncFail::File(e)) => self.warn_resync(&e),
        }
        Ok(())
    }

    fn warn_resync(&self, why: &str) {
        if !self.resync_warned.swap(true, Ordering::Relaxed) {
            eprintln!(
                "vci: warning: cannot sync the libsql replica {} from {} again: {why}; reading the replica as it is",
                self.path.display(),
                self.remote.conn.display()
            );
        }
    }

    /// The source this file copies, as `<file>.sync` names it.
    fn source(&self) -> Result<String, StoreError> {
        Ok(format!(
            "{} namespace {}",
            self.remote.conn.display(),
            self.remote.ns()?
        ))
    }

    fn read_sidecar(&self) -> Option<Sidecar> {
        let text = std::fs::read_to_string(sidecar(&self.path)).ok()?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        Some(Sidecar {
            source: v["source"].as_str()?.to_owned(),
            seq: v["seq"].as_i64()?,
            mark: v["mark"].as_str().map(str::to_owned),
            epoch: v["epoch"].as_i64(),
        })
    }

    fn write_sidecar(&self, s: &Sidecar) -> std::io::Result<()> {
        let side = sidecar(&self.path);
        if let Some(dir) = side.parent() {
            std::fs::create_dir_all(dir)?;
        }
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let tmp = side.with_extension(format!(
            "sync.{}.{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let body = json!({
            "v": 1,
            "source": s.source,
            "seq": s.seq,
            "mark": s.mark,
            "epoch": s.epoch,
        })
        .to_string();
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, &side)
    }

    fn open_store(&self) -> SqliteStore {
        SqliteStore::open_path(&self.path, self.opts)
    }

    /// Open the file and bring it up to date (see the module docs).
    fn open_and_sync(&self) -> Result<SqliteStore, String> {
        let store = self.open_store();
        let found = self.read_sidecar();
        let exists = self.path.exists();
        if exists && found.is_none() {
            return Err(format!(
                "{} is not a replica (it has no {}): it may be a local libsql store; set $VCI_STORE_REPLICA to another file",
                self.path.display(),
                sidecar(&self.path).display()
            ));
        }
        if exists && let Err(e) = store.status() {
            return Err(format!(
                "the replica {} cannot be read ({e}): remove it, or set $VCI_STORE_REPLICA to another file",
                self.path.display()
            ));
        }
        let source = self.source().map_err(|e| e.to_string())?;
        let same = found.as_ref().is_some_and(|s| s.source == source);
        if !self.stale_ok {
            // The commands about the store say whether this replica can
            // be kept, before the sync finds anything to write (an empty
            // namespace writes nothing).
            self.probe(false)?;
        }
        match self.sync(&store) {
            Ok(()) => Ok(store),
            Err(SyncFail::Server(e)) if exists && !same => Err(format!(
                "{} copies another store, and syncing it from {source} failed: {e}",
                self.path.display()
            )),
            Err(SyncFail::Server(e)) if !self.stale_ok => Err(format!(
                "cannot sync the replica {} from {}: {e}",
                self.path.display(),
                self.remote.conn.display()
            )),
            Err(SyncFail::Server(e)) => {
                eprintln!(
                    "vci: warning: cannot sync the libsql replica {} from {}: {e}; reading the replica as it is",
                    self.path.display(),
                    self.remote.conn.display()
                );
                Ok(store)
            }
            Err(SyncFail::File(e)) if !self.stale_ok => Err(format!(
                "the replica {} cannot be kept: {e}",
                self.path.display()
            )),
            Err(SyncFail::File(e)) => {
                eprintln!(
                    "vci: warning: cannot apply the sync of the libsql replica {}: {e}; reading the replica as it is",
                    self.path.display()
                );
                Ok(store)
            }
        }
    }

    /// Bring `store` (this replica's file) up to date with the server: the
    /// changes since the entry `<file>.sync` names, or everything.
    fn sync(&self, store: &SqliteStore) -> Result<(), SyncFail> {
        let _one = self.syncing.lock().unwrap_or_else(PoisonError::into_inner);
        let source = self.source().map_err(SyncFail::Server)?;
        let found = self.read_sidecar();
        let exists = self.path.exists();
        let same = found.as_ref().filter(|s| s.source == source);
        let step = Step::start(KIND);
        let last = same.map_or(0, |s| s.seq);
        let mut full = last == 0;
        let mut changes = self.changes(last, full).map_err(SyncFail::Server)?;
        if let (Some(c), Some(s)) = (&changes, same)
            && !full
            && (c.floor > last
                || c.seq < last
                // The entry synced to is still in the log (none is dropped
                // above the floor) and must be the same one.
                || (c.floor < last && c.mark_then != s.mark)
                || c.epoch.is_none()
                || c.epoch != s.epoch)
        {
            // Older than the log, or the log is not the one the file was
            // synced from (dropped and created again, restored): all.
            full = true;
            changes = self.changes(0, true).map_err(SyncFail::Server)?;
        }
        let Some(changes) = changes else {
            // The server holds nothing for this namespace (its tables are
            // gone, or were never made): neither does the file.
            if exists {
                self.reconcile_to_nothing(store, &source)?;
            }
            return Ok(());
        };
        // The file is a replica from its first write on; an interrupted
        // full sync is done again in full.
        let before = if full {
            Sidecar {
                source: source.clone(),
                ..Sidecar::default()
            }
        } else {
            same.cloned().unwrap_or_default()
        };
        self.write_sidecar(&before).map_err(|e| {
            SyncFail::File(format!(
                "cannot write {}: {e}",
                sidecar(&self.path).display()
            ))
        })?;
        self.marked.store(true, Ordering::Relaxed);
        let (na, nm) = (changes.attestations.len(), changes.manifests.len());
        apply_changes(store, &changes, full).map_err(|e| SyncFail::File(e.to_string()))?;
        let after = Sidecar {
            source,
            seq: changes.seq,
            mark: changes.mark_now.clone(),
            epoch: changes.epoch,
        };
        if let Err(e) = self.write_sidecar(&after) {
            eprintln!(
                "vci: warning: cannot write {}: {e}; the next sync reads the same changes again",
                sidecar(&self.path).display()
            );
        }
        step.done(format_args!(
            "sync replica: {na} attestation(s), {nm} manifest(s), {}",
            if full { "everything" } else { "changes" }
        ));
        Ok(())
    }

    /// The server holds nothing for the namespace: empty the file, which
    /// stays a replica of it (from entry 0).
    fn reconcile_to_nothing(&self, store: &SqliteStore, source: &str) -> Result<(), SyncFail> {
        let empty = Sidecar {
            source: source.to_owned(),
            ..Sidecar::default()
        };
        self.write_sidecar(&empty).map_err(|e| {
            SyncFail::File(format!(
                "cannot write {}: {e}",
                sidecar(&self.path).display()
            ))
        })?;
        self.marked.store(true, Ordering::Relaxed);
        apply_changes(store, &Changes::default(), true).map_err(|e| SyncFail::File(e.to_string()))
    }

    /// What changed on the server since `last` (everything when `full`);
    /// `None` when the server holds nothing for this namespace. The
    /// namespace's schema version comes with it: a newer one is refused.
    fn changes(&self, last: i64, full: bool) -> Result<Option<Changes>, StoreError> {
        let t = self.remote.ready()?;
        let ns = self.remote.ns()?.to_owned();
        let r = self.remote.query(
            READ,
            &t.sync,
            vec![V::Integer(last), V::Integer(i64::from(full)), V::Text(ns)],
        );
        let rows = match r {
            Ok(rows) => rows,
            Err(Fail::Absent) => return Ok(None),
            Err(Fail::Store(e)) => return Err(e),
        };
        let mut c = Changes::default();
        let mut version = None;
        for row in rows {
            if row.len() < 7 {
                continue;
            }
            match col_int(&row[0]) {
                Some(0) => {
                    version = col_int(&row[4]);
                    c.mark_then = col_text(&row[1]);
                    c.mark_now = col_text(&row[2]);
                    c.epoch = col_int(&row[3]);
                    c.seq = col_int(&row[5]).unwrap_or(0);
                    c.floor = col_int(&row[6]).unwrap_or(0);
                }
                Some(1) => {
                    if let (Some(k), Some(t)) = (col_text(&row[1]), col_text(&row[2])) {
                        c.attestations.push((k, t, col_value(&row[3], &row[4])));
                    }
                }
                Some(2) => c.slots.extend(col_text(&row[1])),
                Some(3) => {
                    if let Some(r) = col_text(&row[1]) {
                        c.manifests.push((r, col_value(&row[3], &row[4])));
                    }
                }
                Some(4) => c.roots.extend(col_text(&row[1])),
                _ => {}
            }
        }
        match version {
            None => Ok(None),
            Some(v) => {
                self.remote.found_version(v)?;
                Ok(Some(c))
            }
        }
    }

    /// Make the file a replica before it is first written: when the server
    /// held nothing for this namespace at the sync, the file does not exist
    /// yet and has no `<file>.sync`; it gets one at entry 0, so the next
    /// sync reads everything.
    fn mark(&self) -> Result<(), StoreError> {
        if self.marked.load(Ordering::Relaxed) || self.read_sidecar().is_some() {
            self.marked.store(true, Ordering::Relaxed);
            return Ok(());
        }
        let source = self.source()?;
        self.write_sidecar(&Sidecar {
            source,
            ..Sidecar::default()
        })
        .map_err(|e| {
            StoreError::unavailable(
                KIND,
                format!("cannot write {}: {e}", sidecar(&self.path).display()),
            )
        })?;
        self.marked.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// The same writes as `p`, to the file (after the server stored them).
    /// A failure is a warning, and this handle reads from the server from
    /// then on (the file lacks the write); the next sync reads them from
    /// the server.
    pub(crate) fn write_through(&self, p: &Pending) {
        if self.degraded() {
            return;
        }
        let Some(Ok(store)) = self.local.get() else {
            return;
        };
        let r = (|| -> Result<(), StoreError> {
            self.mark()?;
            let b = store.batch()?;
            for (root, (_, bytes)) in &p.manifests {
                store.put_manifest(root, bytes)?;
            }
            let mut gone: Vec<StoredEnvelope> = p
                .removals
                .iter()
                .filter_map(|k| StoredEnvelope::from_key("project", k))
                .collect();
            if !p.emptied.is_empty() {
                for e in store.list_all()? {
                    if p.emptied.contains(&(
                        e.test_key.clone(),
                        e.signer.clone(),
                        e.storage_key.clone(),
                    )) {
                        gone.push(e);
                    }
                }
            }
            if !gone.is_empty() {
                store.remove(gone)?;
            }
            for r in p.attestations.values() {
                put_copy(store, &r.key, &r.target, &r.value)?;
            }
            // SQLite's batch warns of nothing after its commit.
            b.finish().map(drop)
        })();
        if let Err(e) = r {
            self.degraded.store(true, Ordering::Relaxed);
            if !self.write_through_warned.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "vci: warning: cannot write through to the libsql replica {}: {e}; reading from {} for the rest of this command, and the next sync brings the writes to the replica",
                    self.path.display(),
                    self.remote.conn.display()
                );
            }
        }
    }

    /// The hook a batch of this replica runs after each write.
    pub(crate) fn after(self: &Arc<Self>) -> After {
        let me = Arc::clone(self);
        Arc::new(move |p: &Pending| me.write_through(p))
    }
}

/// Store a record under exactly `key`: its hint makes the same key, and an
/// unhinted put of a slot keeps (or makes) the plain key.
fn put_copy(store: &SqliteStore, k: &str, target: &str, bytes: &[u8]) -> Result<(), StoreError> {
    let Some(mut e) = StoredEnvelope::from_key(target, k) else {
        return Ok(());
    };
    e.set_value(bytes.to_vec());
    let hint: Option<KeyHint> = key::parse_key_hint(k);
    store.put(&NewAttestation::copy_of(&e, hint.as_ref()))?;
    Ok(())
}

/// Apply what the server sent, in one transaction of the file. Each slot
/// touched ends as the server has it (its other keys removed, or every key
/// when the server holds none), and each root touched too; after a sync of
/// everything, so does every slot and root of the file (other handles may
/// be reading it, so it is reconciled in place, never replaced).
fn apply_changes(store: &SqliteStore, c: &Changes, full: bool) -> Result<(), StoreError> {
    let b = store.batch()?;
    let remote_keys: BTreeMap<String, &String> = c
        .attestations
        .iter()
        .filter_map(|(k, _, _)| {
            let (t, s, x) = key::parse_key(k)?;
            Some((format!("{t}:{s}:{x}"), k))
        })
        .collect();
    let gone: Vec<StoredEnvelope> = store
        .list_all()?
        .into_iter()
        .filter(|e| {
            let slot = format!("{}:{}:{}", e.test_key, e.signer, e.storage_key);
            let kept = remote_keys.get(&slot).is_some_and(|k| **k == e.key);
            !kept && (full || c.slots.contains(&slot))
        })
        .collect();
    if !gone.is_empty() {
        store.remove(gone)?;
    }
    for (root, value) in &c.manifests {
        if let Ok(bytes) = value
            && !bytes.is_empty()
        {
            store.put_manifest(root, bytes)?;
        }
    }
    for (k, target, value) in &c.attestations {
        match value {
            Ok(bytes) if !bytes.is_empty() => put_copy(store, k, target, bytes)?,
            // A value this vci cannot read is left out: its unit runs (and
            // `orphan_manifests` asks the server, which still counts it).
            _ => {
                if let Some(e) = StoredEnvelope::from_key(target.clone(), k) {
                    store.remove(vec![e])?;
                }
            }
        }
    }
    let stored: BTreeSet<&str> = c
        .manifests
        .iter()
        .filter(|(_, v)| v.as_ref().is_ok_and(|b| !b.is_empty()))
        .map(|(r, _)| r.as_str())
        .collect();
    let mut gone: Vec<String> = if full {
        store.manifest_roots()?
    } else {
        c.roots.iter().cloned().collect()
    };
    gone.retain(|r| !stored.contains(r.as_str()));
    // A base goes once the manifests on it went: a few passes.
    for _ in 0..4 {
        if gone.is_empty() {
            break;
        }
        let roots: Vec<&str> = gone.iter().map(String::as_str).collect();
        if store.remove_manifests(&roots)? == 0 {
            break;
        }
        let left: BTreeSet<String> = store.manifest_roots()?.into_iter().collect();
        gone.retain(|r| left.contains(r));
    }
    b.finish().map(drop)
}
