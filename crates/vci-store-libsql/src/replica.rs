//! The replica mode: reads come from a local file, synced from the server
//! once when the store is first used; writes go to the server, and through
//! to the file once they are stored. `docs/STORE-BACKENDS.md` section 18,
//! "The replica mode".
//!
//! * **The file** is a SQLite store file ([`vci_store_sqlite`], under the
//!   name `libsql`), by default `<git common dir>/vci-store.libsql`. Beside
//!   it, `<file>.sync` says which server and namespace it copies and up to
//!   which entry of the server's change log. A file without one is not a
//!   replica (a local-mode store, say) and is never written: the store is
//!   unavailable until `VCI_STORE_REPLICA` names another file.
//! * **The sync** is one request: everything the change log names since the
//!   last sync (every record when the file is new, belongs to another
//!   server or namespace, or is older than the log), in one snapshot. It is
//!   applied in one transaction, so a reader never sees half of it. A sync
//!   that fails (the server unreachable, a deadline run out) leaves the file
//!   as it was, says so on stderr, and the store reads it as it is: a stale
//!   replica only makes units run.
//! * **Writes** are the remote mode's, then the same writes to the file.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use libsql::Value as V;
use serde_json::json;
use vci_store::timing::Step;
use vci_store::{AttestationStore, KeyHint, NewAttestation, StoreError, StoredEnvelope, key};
use vci_store_sqlite::{SqliteOptions, SqliteStore};

use crate::batch::{After, Pending};
use crate::conn::{Fail, KIND, READ, col_int, col_text, col_value};
use crate::remote::Remote;

/// The replica of one remote handle.
pub(crate) struct Replica {
    pub(crate) remote: Arc<Remote>,
    pub(crate) path: PathBuf,
    opts: SqliteOptions,
    local: OnceLock<Result<SqliteStore, String>>,
    /// `<file>.sync` is known to exist.
    marked: AtomicBool,
    write_through_warned: AtomicBool,
}

/// What the sync found on the server.
#[derive(Default)]
struct Changes {
    /// The change log's last entry.
    seq: i64,
    /// Entries up to this one were dropped from the log.
    floor: i64,
    /// The attestations of the slots touched: key, target, value.
    attestations: Vec<(String, String, Result<Vec<u8>, String>)>,
    /// The slots touched, as `test key:signer:storage key`.
    slots: BTreeSet<String>,
    /// The manifests touched: root, value.
    manifests: Vec<(String, Result<Vec<u8>, String>)>,
    /// The roots touched.
    roots: BTreeSet<String>,
}

/// `<file>.sync`.
fn sidecar(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".sync");
    PathBuf::from(s)
}

impl Replica {
    pub(crate) fn new(remote: Arc<Remote>, path: PathBuf, opts: SqliteOptions) -> Replica {
        Replica {
            remote,
            path,
            opts,
            local: OnceLock::new(),
            marked: AtomicBool::new(false),
            write_through_warned: AtomicBool::new(false),
        }
    }

    /// The replica, synced the first time it is asked for.
    pub(crate) fn local(&self) -> Result<&SqliteStore, StoreError> {
        self.local
            .get_or_init(|| self.open_and_sync())
            .as_ref()
            .map_err(|e| StoreError::unavailable(KIND, e.clone()))
    }

    /// The source this file copies, as `<file>.sync` names it.
    fn source(&self) -> Result<String, StoreError> {
        Ok(format!(
            "{} namespace {}",
            self.remote.conn.display(),
            self.remote.ns()?
        ))
    }

    fn read_sidecar(&self) -> Option<(String, i64)> {
        let text = std::fs::read_to_string(sidecar(&self.path)).ok()?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        Some((v["source"].as_str()?.to_owned(), v["seq"].as_i64()?))
    }

    fn write_sidecar(&self, source: &str, seq: i64) -> std::io::Result<()> {
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
        let body = json!({"v": 1, "source": source, "seq": seq}).to_string();
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, &side)
    }

    fn open_store(&self) -> SqliteStore {
        SqliteStore::open_path(&self.path, self.opts)
    }

    /// Open the file and bring it up to date (see the module docs).
    fn open_and_sync(&self) -> Result<SqliteStore, String> {
        let source = self.source().map_err(|e| e.to_string())?;
        let found = self.read_sidecar();
        let exists = self.path.exists();
        if exists && found.is_none() {
            return Err(format!(
                "{} is not a replica (it has no {}): it may be a local libsql store; set $VCI_STORE_REPLICA to another file",
                self.path.display(),
                sidecar(&self.path).display()
            ));
        }
        let same = found.as_ref().is_some_and(|(s, _)| *s == source);
        let last = match &found {
            Some((_, seq)) if same => *seq,
            _ => 0,
        };
        let step = Step::start(KIND);
        let mut full = last == 0;
        let mut changes = self.changes(last, full);
        if let Ok(Some(c)) = &changes
            && !full
            && c.floor > last
        {
            full = true;
            changes = self.changes(0, true);
        }
        let changes = match changes {
            Ok(c) => c,
            Err(e) => {
                if exists && !same {
                    return Err(format!(
                        "{} copies another store, and syncing it from {source} failed: {e}",
                        self.path.display()
                    ));
                }
                eprintln!(
                    "vci: warning: cannot sync the libsql replica {} from {}: {e}; reading the replica as it is",
                    self.path.display(),
                    self.remote.conn.display()
                );
                return Ok(self.open_store());
            }
        };
        let Some(changes) = changes else {
            // Nothing on the server yet.
            return Ok(self.open_store());
        };
        // The file is a replica from its first write on.
        self.write_sidecar(&source, if full { 0 } else { last })
            .map_err(|e| format!("cannot write {}: {e}", sidecar(&self.path).display()))?;
        self.marked.store(true, Ordering::Relaxed);
        let store = self.open_store();
        let (na, nm) = (changes.attestations.len(), changes.manifests.len());
        if let Err(e) = apply_changes(&store, &changes, full) {
            eprintln!(
                "vci: warning: cannot apply the sync of the libsql replica {}: {e}; reading the replica as it is",
                self.path.display()
            );
            return Ok(store);
        }
        if let Err(e) = self.write_sidecar(&source, changes.seq) {
            eprintln!(
                "vci: warning: cannot write {}: {e}; the next sync reads the same changes again",
                sidecar(&self.path).display()
            );
        }
        step.done(format_args!(
            "sync replica: {na} attestation(s), {nm} manifest(s), {}",
            if full { "everything" } else { "changes" }
        ));
        Ok(store)
    }

    /// What changed on the server since `last` (everything when `full`);
    /// `None` when the server holds nothing for this namespace yet.
    fn changes(&self, last: i64, full: bool) -> Result<Option<Changes>, StoreError> {
        let t = self.remote.ready()?;
        let ns = self.remote.ns()?.to_owned();
        let r = self.remote.conn.query(
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
        for row in rows {
            if row.len() < 7 {
                continue;
            }
            match col_int(&row[0]) {
                Some(0) => {
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
        Ok(Some(c))
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
        self.write_sidecar(&source, 0).map_err(|e| {
            StoreError::unavailable(
                KIND,
                format!("cannot write {}: {e}", sidecar(&self.path).display()),
            )
        })?;
        self.marked.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// The same writes as `p`, to the file (after the server stored them).
    /// A failure is a warning: the next sync reads them from the server.
    pub(crate) fn write_through(&self, p: &Pending) {
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
            b.finish()
        })();
        if let Err(e) = r
            && !self.write_through_warned.swap(true, Ordering::Relaxed)
        {
            eprintln!(
                "vci: warning: cannot write through to the libsql replica {}: {e}; the next sync reads the writes from the server",
                self.path.display()
            );
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
            // A value this vci cannot read is left out: its unit runs.
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
    b.finish()
}
