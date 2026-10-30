//! The libSQL store against the conformance suite (`docs/STORE-BACKENDS.md`
//! section 14), in each of its three modes.
//!
//! * **local**: a world is a temporary directory holding one store file;
//!   peers are separate handles on it. The unreachable store is a file that
//!   is not a database; the read-only handle opens the file after it was
//!   made read-only; raw records and unreadable values are written with SQL
//!   behind the store's back.
//! * **remote**: on the server [`vci_store_libsql::testkit`] finds
//!   (`VCI_TEST_LIBSQL_URL`, else a throwaway `sqld`, `turso dev` or Docker
//!   container; skipped without one, a failure under
//!   `VCI_TEST_LIBSQL=require`). A world is a namespace of its own; peers
//!   are separate handles (each with its own connections and cache). The
//!   unreachable store is a closed local port with a token in its URL;
//!   batches fail on a handle whose URL has a path the server does not
//!   serve; raw records and unreadable values are written with SQL.
//! * **replica**: the same server and namespaces; each peer reads its own
//!   replica file. A replica reads what it synced when it was opened, so a
//!   peer here opens a fresh handle on its file for every read (each one
//!   syncs what changed since the last), and writes through one long-lived
//!   handle: the suite's "visible to every peer at once" then checks the
//!   sync. An unreachable server leaves a replica readable (it reads what
//!   it has, with a warning), so the unreachable, secret and read-only
//!   hooks are left out; the crate's own tests check that.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use vci_store::conformance::{StoreFactory, World};
use vci_store::select::{LibsqlMode, Source, Sourced};
use vci_store::{
    AttestationStore, Caps, Columns, Hydration, KeyHint, ManifestRef, NewAttestation, NewObject,
    Prefetch, StoreError, StoreStatus, StoredEnvelope, StoredManifest, StoredObject, WriteBatch,
    key,
};

/// The statement that moves the objects `ids` of namespace `ns` back in
/// time by `by` (`World::age_objects`, behind the store's back).
fn age_objects_sql(ns: &str, ids: &[&str], by: Duration) -> String {
    let list = ids.iter().map(|i| lit(i)).collect::<Vec<_>>().join(", ");
    format!(
        "UPDATE {}objects SET put_at = put_at - {} WHERE id IN ({list})",
        table_prefix(ns),
        by.as_secs()
    )
}
use vci_store_libsql::testkit;
use vci_store_libsql::{LibsqlStore, table_prefix};

/// The token in the unreachable store's URL, which no message may show.
const SECRET: &str = "s3cret-conformance-token";

/// `s` as an SQL string literal.
fn lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map_or_else(|| "NULL".to_owned(), |v| lit(&v.to_string()))
}

/// The INSERT of a raw record into namespace `ns`'s tables (and its log
/// entry, for replicas).
fn raw_insert(ns: &str, target: &str, k: &str, value: &[u8]) -> Vec<String> {
    let p = table_prefix(ns);
    let (test_key, signer, storage_key) = match key::parse_key(k) {
        Some((t, s, x)) => (t.to_owned(), s.to_owned(), x.to_owned()),
        None => (
            k.split(':').nth(2).unwrap_or_default().to_owned(),
            String::new(),
            k.to_owned(),
        ),
    };
    let hint = key::parse_key_hint(k);
    let (manifest_ref, ref_state) = match key::envelope_manifest_ref(value) {
        ManifestRef::Root(r) => (Some(r), 1),
        ManifestRef::Inline => (None, 2),
        ManifestRef::Unknown => (None, 0),
    };
    let hex: String = value.iter().map(|b| format!("{b:02X}")).collect();
    vec![
        format!(
            "INSERT INTO {p}attestations (key, test_key, signer, storage_key, target, issued, \
               tree16, manifest_ref, ref_state, stored_at, value) \
             VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {ref_state}, 1, X'{hex}')",
            lit(k),
            lit(&test_key),
            lit(&signer),
            lit(&storage_key),
            lit(target),
            opt(hint.as_ref().map(|h| h.issued)),
            opt(hint.and_then(|h| h.tree)),
            opt(manifest_ref),
        ),
        format!(
            "INSERT INTO {p}log (test_key, signer, storage_key, root, at) VALUES ({}, {}, {}, NULL, 1)",
            lit(&test_key),
            lit(&signer),
            lit(&storage_key),
        ),
    ]
}

// ---- local ------------------------------------------------------------------------

mod local {
    use super::*;

    pub(super) struct Worlds;

    impl StoreFactory for Worlds {
        fn name(&self) -> &str {
            "libsql local"
        }

        fn world(&self) -> Box<dyn World> {
            Box::new(LocalWorld {
                dir: tempfile::tempdir().expect("a temporary directory"),
                peers: Mutex::new(BTreeMap::new()),
                read_only: Mutex::new(Vec::new()),
            })
        }
    }

    struct LocalWorld {
        dir: tempfile::TempDir,
        peers: Mutex<BTreeMap<usize, Arc<LibsqlStore>>>,
        read_only: Mutex<Vec<PathBuf>>,
    }

    impl LocalWorld {
        fn path(&self) -> PathBuf {
            self.dir.path().join("vci-store.libsql")
        }

        fn handle(&self, path: &Path) -> Arc<LibsqlStore> {
            let mut sel = testkit::selection(LibsqlMode::Local, None, None, None, Some(path));
            sel.timeout = Sourced {
                value: Duration::from_secs(20),
                source: Source::File,
            };
            Arc::new(
                LibsqlStore::open(&sel, &testkit::cx_in(self.dir.path(), false))
                    .expect("open the local store"),
            )
        }

        fn raw(&self) -> Option<rusqlite::Connection> {
            let path = self.path();
            if !path.exists() {
                return None;
            }
            let c = rusqlite::Connection::open(path).ok()?;
            c.busy_timeout(Duration::from_secs(20)).ok()?;
            Some(c)
        }
    }

    impl World for LocalWorld {
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

        fn sync(&self, _from: usize, _to: &[usize]) {}

        fn backing_exists(&self, _i: usize) -> Option<bool> {
            Some(self.path().exists())
        }

        fn unreachable(&self) -> Option<Arc<dyn AttestationStore>> {
            let garbage = self.dir.path().join("not-a-database.libsql");
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

        fn inject_raw(&self, _i: usize, target: &str, k: &str, value: &[u8]) -> bool {
            let Some(db) = self.raw() else {
                return false;
            };
            // The local file has the SQLite store's tables, unprefixed.
            let stmt = raw_insert("unused", target, k, value).remove(0).replace(
                &format!("{}attestations", table_prefix("unused")),
                "attestations",
            );
            db.execute(&stmt, []).is_ok()
        }

        fn make_unreadable(&self, _i: usize, k: &str) -> bool {
            self.raw().is_some_and(|db| {
                db.execute("UPDATE attestations SET encoding = 99 WHERE key = ?1", [k])
                    .is_ok_and(|n| n == 1)
            })
        }

        /// The local file has the SQLite store's `objects` table.
        fn age_objects(&self, _i: usize, ids: &[&str], by: Duration) -> bool {
            let list = ids.iter().map(|i| lit(i)).collect::<Vec<_>>().join(", ");
            // Every id must be there (the SQLite world checks the same).
            self.raw().is_some_and(|db| {
                db.execute(
                    &format!(
                        "UPDATE objects SET put_at = put_at - {} WHERE id IN ({list})",
                        by.as_secs()
                    ),
                    [],
                )
                .is_ok_and(|n| n == ids.len())
            })
        }
    }

    impl Drop for LocalWorld {
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

    vci_store::conformance_suite!(Some(Box::new(Worlds) as Box<dyn StoreFactory>));
}

// ---- remote -----------------------------------------------------------------------

mod remote {
    use super::*;

    pub(super) struct Worlds;

    impl StoreFactory for Worlds {
        fn name(&self) -> &str {
            "libsql remote"
        }

        fn world(&self) -> Box<dyn World> {
            Box::new(RemoteWorld {
                ns: testkit::namespace(),
                peers: Mutex::new(BTreeMap::new()),
            })
        }
    }

    struct RemoteWorld {
        ns: String,
        peers: Mutex<BTreeMap<usize, Arc<LibsqlStore>>>,
    }

    impl RemoteWorld {
        fn handle(&self) -> Arc<LibsqlStore> {
            Arc::new(
                testkit::open_remote(&self.ns).expect("the server this suite was started with"),
            )
        }

        fn raw(&self, stmts: &[String]) -> bool {
            self.handle().__execute_for_test(stmts).is_ok()
        }
    }

    impl World for RemoteWorld {
        fn peer(&self, i: usize) -> Arc<dyn AttestationStore> {
            assert!(i < 8, "peer {i}");
            let mut peers = self.peers.lock().unwrap_or_else(PoisonError::into_inner);
            peers.entry(i).or_insert_with(|| self.handle()).clone()
        }

        fn fresh_peer(&self) -> Arc<dyn AttestationStore> {
            self.handle()
        }

        fn sync(&self, _from: usize, _to: &[usize]) {}

        fn backing_exists(&self, _i: usize) -> Option<bool> {
            Some(matches!(
                self.handle().status(),
                Ok(StoreStatus::Ready { .. })
            ))
        }

        fn unreachable(&self) -> Option<Arc<dyn AttestationStore>> {
            let mut sel = testkit::selection(
                LibsqlMode::Remote,
                Some(&format!("http://127.0.0.1:1/?authToken={SECRET}")),
                None,
                Some(&self.ns),
                None,
            );
            sel.connect_timeout = Sourced {
                value: Duration::from_secs(1),
                source: Source::Env("VCI_STORE_CONNECT_TIMEOUT_SECS"),
            };
            Some(Arc::new(
                LibsqlStore::open(&sel, &testkit::cx()).expect("open the store"),
            ))
        }

        fn secret(&self) -> Option<String> {
            Some(SECRET.to_owned())
        }

        fn inject_raw(&self, _i: usize, target: &str, k: &str, value: &[u8]) -> bool {
            // A write creates the namespace's tables first.
            let setup = self.handle();
            if !matches!(setup.status(), Ok(StoreStatus::Ready { .. })) {
                let e = setup
                    .put_for_test("src/setup.test.ts", "1111111111111111", "00", None, b"{}")
                    .expect("a first write creates the tables");
                setup.remove(vec![e]).expect("remove the setup record");
            }
            self.raw(&raw_insert(&self.ns, target, k, value))
        }

        fn make_unreadable(&self, _i: usize, k: &str) -> bool {
            let p = table_prefix(&self.ns);
            self.raw(&[format!(
                "UPDATE {p}attestations SET encoding = 99 WHERE key = {}",
                lit(k)
            )])
        }

        fn age_objects(&self, _i: usize, ids: &[&str], by: Duration) -> bool {
            self.raw(&[age_objects_sql(&self.ns, ids, by)])
        }

        /// A handle on the same namespace whose requests go to a path the
        /// server does not serve: every request fails, and its batches
        /// fail when they finish.
        fn failing_batches(&self) -> Option<Arc<dyn AttestationStore>> {
            let server = testkit::server().ok()?;
            let sel = testkit::selection(
                LibsqlMode::Remote,
                Some(&format!("{}/no-such-database", server.url)),
                server.token.as_deref(),
                Some(&self.ns),
                None,
            );
            Some(Arc::new(
                LibsqlStore::open(&sel, &testkit::cx()).expect("open the store"),
            ))
        }
    }

    vci_store::conformance_suite!(
        testkit::available().then(|| Box::new(Worlds) as Box<dyn StoreFactory>)
    );
}

// ---- replica ----------------------------------------------------------------------

mod replica {
    use super::*;

    pub(super) struct Worlds;

    impl StoreFactory for Worlds {
        fn name(&self) -> &str {
            "libsql replica"
        }

        fn world(&self) -> Box<dyn World> {
            Box::new(ReplicaWorld {
                ns: testkit::namespace(),
                dir: tempfile::tempdir().expect("a temporary directory"),
                peers: Mutex::new(BTreeMap::new()),
            })
        }
    }

    struct ReplicaWorld {
        ns: String,
        dir: tempfile::TempDir,
        peers: Mutex<BTreeMap<usize, Arc<Peer>>>,
    }

    /// A peer: writes through one handle on its replica, reads through a
    /// fresh one (synced when it opens).
    struct Peer {
        ns: String,
        path: PathBuf,
        writer: LibsqlStore,
    }

    impl Peer {
        fn new(ns: &str, path: PathBuf) -> Peer {
            Peer {
                writer: testkit::open_replica(ns, &path).expect("the server"),
                ns: ns.to_owned(),
                path,
            }
        }

        fn fresh(&self) -> LibsqlStore {
            testkit::open_replica(&self.ns, &self.path).expect("the server")
        }
    }

    impl AttestationStore for Peer {
        fn kind(&self) -> &'static str {
            self.writer.kind()
        }
        fn location(&self) -> String {
            self.writer.location()
        }
        fn caps(&self) -> Caps {
            self.writer.caps()
        }
        fn status(&self) -> Result<StoreStatus, StoreError> {
            self.fresh().status()
        }
        fn list_units(&self, ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
            self.fresh().list_units(ids)
        }
        fn list_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
            self.fresh().list_all()
        }
        fn read_values(&self, envs: &mut [&mut StoredEnvelope]) -> Result<(), StoreError> {
            self.fresh().read_values(envs)
        }
        fn manifest(&self, root: &str) -> Result<Option<StoredManifest>, StoreError> {
            self.fresh().manifest(root)
        }
        fn manifest_roots(&self) -> Result<Vec<String>, StoreError> {
            self.fresh().manifest_roots()
        }
        fn put(&self, att: &NewAttestation<'_>) -> Result<StoredEnvelope, StoreError> {
            self.writer.put(att)
        }
        fn put_manifest(&self, root: &str, bytes: &[u8]) -> Result<bool, StoreError> {
            self.writer.put_manifest(root, bytes)
        }
        fn remove(&self, doomed: Vec<StoredEnvelope>) -> Result<Vec<StoredEnvelope>, StoreError> {
            self.writer.remove(doomed)
        }
        fn remove_manifests(&self, roots: &[&str]) -> Result<usize, StoreError> {
            self.writer.remove_manifests(roots)
        }
        fn read_units(&self, ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
            self.fresh().read_units(ids)
        }
        fn read_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
            self.fresh().read_all()
        }
        fn count(&self) -> Result<usize, StoreError> {
            self.fresh().count()
        }
        fn manifests(&self, roots: &[&str]) -> Result<Vec<Option<StoredManifest>>, StoreError> {
            self.fresh().manifests(roots)
        }
        fn orphan_manifests(&self, roots: &[&str]) -> Result<Vec<String>, StoreError> {
            self.fresh().orphan_manifests(roots)
        }
        fn put_for_test(
            &self,
            test_id: &str,
            signer: &str,
            storage_key: &str,
            hint: Option<&KeyHint>,
            envelope: &[u8],
        ) -> Result<StoredEnvelope, StoreError> {
            self.writer
                .put_for_test(test_id, signer, storage_key, hint, envelope)
        }
        fn batch(&self) -> Result<WriteBatch, StoreError> {
            self.writer.batch()
        }
        fn prefetch(&self, what: Prefetch<'_>) -> Result<Hydration, StoreError> {
            self.writer.prefetch(what)
        }
        fn passing_on(&self, tree16: &str) -> BTreeMap<String, String> {
            self.writer.passing_on(tree16)
        }
        fn remember_passing(&self, tree16: &str, items: &[(String, String)]) {
            self.writer.remember_passing(tree16, items)
        }
        fn flag(&self, name: &str) -> bool {
            self.writer.flag(name)
        }
        fn set_flag(&self, name: &str) {
            self.writer.set_flag(name)
        }
        // A replica's objects and columns are the server's: a fresh handle
        // reads them as it would anything else.
        fn get_objects(&self, ids: &[&str]) -> Result<Vec<StoredObject>, StoreError> {
            self.fresh().get_objects(ids)
        }
        fn put_objects(&self, objects: &[NewObject<'_>]) -> Result<usize, StoreError> {
            self.writer.put_objects(objects)
        }
        fn remove_objects(&self, ids: &[&str]) -> Result<usize, StoreError> {
            self.writer.remove_objects(ids)
        }
        fn orphan_objects(&self) -> Result<Vec<String>, StoreError> {
            self.fresh().orphan_objects()
        }
        fn prune_state_objects(&self, older_than: Duration) -> Result<usize, StoreError> {
            self.writer.prune_state_objects(older_than)
        }
        fn columns(&self, envs: &[&StoredEnvelope]) -> Result<Vec<Columns>, StoreError> {
            self.fresh().columns(envs)
        }
    }

    impl ReplicaWorld {
        fn peer_path(&self, i: usize) -> PathBuf {
            self.dir.path().join(format!("replica-{i}.libsql"))
        }
    }

    impl World for ReplicaWorld {
        fn peer(&self, i: usize) -> Arc<dyn AttestationStore> {
            assert!(i < 8, "peer {i}");
            let mut peers = self.peers.lock().unwrap_or_else(PoisonError::into_inner);
            peers
                .entry(i)
                .or_insert_with(|| Arc::new(Peer::new(&self.ns, self.peer_path(i))))
                .clone()
        }

        fn fresh_peer(&self) -> Arc<dyn AttestationStore> {
            let path = self
                .dir
                .path()
                .join(format!("replica-fresh-{}.libsql", testkit::namespace()));
            Arc::new(Peer::new(&self.ns, path))
        }

        fn sync(&self, _from: usize, _to: &[usize]) {}

        fn backing_exists(&self, _i: usize) -> Option<bool> {
            let probe = testkit::open_remote(&self.ns)?;
            Some(matches!(probe.status(), Ok(StoreStatus::Ready { .. })))
        }

        fn inject_raw(&self, _i: usize, target: &str, k: &str, value: &[u8]) -> bool {
            let setup = testkit::open_remote(&self.ns).expect("the server");
            if !matches!(setup.status(), Ok(StoreStatus::Ready { .. })) {
                let e = setup
                    .put_for_test("src/setup.test.ts", "1111111111111111", "00", None, b"{}")
                    .expect("a first write creates the tables");
                setup.remove(vec![e]).expect("remove the setup record");
            }
            setup
                .__execute_for_test(&raw_insert(&self.ns, target, k, value))
                .is_ok()
        }

        fn age_objects(&self, _i: usize, ids: &[&str], by: Duration) -> bool {
            testkit::open_remote(&self.ns).is_some_and(|s| {
                s.__execute_for_test(&[age_objects_sql(&self.ns, ids, by)])
                    .is_ok()
            })
        }
    }

    vci_store::conformance_suite!(
        testkit::available().then(|| Box::new(Worlds) as Box<dyn StoreFactory>)
    );
}
