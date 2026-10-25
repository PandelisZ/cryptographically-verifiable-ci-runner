//! The SQLite store against the conformance suite (`docs/STORE-BACKENDS.md`
//! section 14).
//!
//! A world is a temporary directory holding one store file. Its peers are
//! separate [`SqliteStore`] handles (each with its own connections) on that
//! file, so a write is visible to every peer at once and [`World::sync`]
//! does nothing. The unreachable store is a file that is not a database; the
//! read-only handle opens the file after it was made read-only (`chmod
//! 0444`); raw records and unreadable values are written with SQL behind
//! the store's back. Batches are immediate, so none can be made to fail.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rusqlite::{Connection, params};
use vci_store::conformance::{StoreFactory, World};
use vci_store::{AttestationStore, ManifestRef, key};
use vci_store_sqlite::{SqliteOptions, SqliteStore};

struct SqliteWorlds;

impl StoreFactory for SqliteWorlds {
    fn name(&self) -> &str {
        "sqlite"
    }

    fn world(&self) -> Box<dyn World> {
        Box::new(SqliteWorld::new())
    }
}

/// One store file and its handles.
struct SqliteWorld {
    dir: tempfile::TempDir,
    peers: Mutex<BTreeMap<usize, Arc<SqliteStore>>>,
    /// Files made read-only, given their permissions back on drop.
    read_only: Mutex<Vec<PathBuf>>,
}

impl SqliteWorld {
    fn new() -> Self {
        SqliteWorld {
            dir: tempfile::tempdir().expect("a temporary directory"),
            peers: Mutex::new(BTreeMap::new()),
            read_only: Mutex::new(Vec::new()),
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("vci-store.sqlite")
    }

    fn handle(&self, path: &Path) -> Arc<SqliteStore> {
        Arc::new(SqliteStore::open_path(
            path,
            SqliteOptions {
                busy_timeout: Duration::from_secs(20),
                ..SqliteOptions::default()
            },
        ))
    }

    /// A connection behind the store's back.
    fn raw(&self) -> Option<Connection> {
        let path = self.path();
        if !path.exists() {
            return None;
        }
        let c = Connection::open(path).ok()?;
        c.busy_timeout(Duration::from_secs(20)).ok()?;
        Some(c)
    }
}

impl World for SqliteWorld {
    fn peer(&self, i: usize) -> Arc<dyn AttestationStore> {
        assert!(i < 8, "peer {i}");
        let mut peers = self.peers.lock().unwrap_or_else(PoisonError::into_inner);
        peers
            .entry(i)
            .or_insert_with(|| self.handle(&self.path()))
            .clone()
    }

    fn fresh_peer(&self) -> Arc<dyn AttestationStore> {
        self.handle(&self.path())
    }

    /// Every handle reads the same file: nothing to do.
    fn sync(&self, _from: usize, _to: &[usize]) {}

    fn backing_exists(&self, _i: usize) -> Option<bool> {
        Some(self.path().exists())
    }

    fn unreachable(&self) -> Option<Arc<dyn AttestationStore>> {
        let garbage = self.dir.path().join("not-a-database.sqlite");
        std::fs::write(&garbage, "this is not a database\n".repeat(200)).ok()?;
        Some(self.handle(&garbage))
    }

    fn read_only(&self, _i: usize) -> Option<Arc<dyn AttestationStore>> {
        let path = self.path();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).ok()?;
        self.read_only
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(path.clone());
        if std::fs::OpenOptions::new().write(true).open(&path).is_ok() {
            eprintln!("the store file is still writable (running as root?)");
            return None;
        }
        Some(self.handle(&path))
    }

    fn inject_raw(&self, _i: usize, target: &str, key: &str, value: &[u8]) -> bool {
        let Some(db) = self.raw() else {
            return false;
        };
        // A key with vci's shape gets its own columns; a foreign one gets
        // columns no other row has (the slot is UNIQUE).
        let (test_key, signer, storage_key) = match key::parse_key(key) {
            Some((t, s, k)) => (t.to_owned(), s.to_owned(), k.to_owned()),
            None => (
                key.split(':').nth(2).unwrap_or_default().to_owned(),
                String::new(),
                key.to_owned(),
            ),
        };
        let hint = key::parse_key_hint(key);
        let (manifest_ref, ref_state) = match key::envelope_manifest_ref(value) {
            ManifestRef::Root(r) => (Some(r), 1),
            ManifestRef::Inline => (None, 2),
            ManifestRef::Unknown => (None, 0),
        };
        db.execute(
            "INSERT INTO attestations (key, test_key, signer, storage_key, target, issued, tree16,
                                       manifest_ref, ref_state, stored_at, value)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10)",
            params![
                key,
                test_key,
                signer,
                storage_key,
                target,
                hint.as_ref().map(|h| h.issued),
                hint.and_then(|h| h.tree),
                manifest_ref,
                ref_state,
                value,
            ],
        )
        .is_ok()
    }

    fn make_unreadable(&self, _i: usize, key: &str) -> bool {
        self.raw().is_some_and(|db| {
            db.execute(
                "UPDATE attestations SET encoding = 99 WHERE key = ?1",
                [key],
            )
            .is_ok_and(|n| n == 1)
        })
    }
}

impl Drop for SqliteWorld {
    fn drop(&mut self) {
        for p in self
            .read_only
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644));
        }
    }
}

vci_store::conformance_suite!(Some(Box::new(SqliteWorlds) as Box<dyn StoreFactory>));
