//! The PostgreSQL store against the conformance suite
//! (`docs/STORE-BACKENDS.md` section 14), on the server
//! [`vci_store_postgres::testkit`] finds: `VCI_TEST_POSTGRES_URL`, else a
//! throwaway cluster of this test process. Without either every scenario is
//! skipped, and under `VCI_TEST_POSTGRES=require` it fails.
//!
//! A world is one schema of its own, in namespace `test`. Its peers are
//! separate [`PgStore`] handles, each with its own pool and cache, so a
//! write is visible to every peer at once and [`World::sync`] does nothing.
//! The unreachable store is a closed local port with a password in its URL
//! ([`SECRET`]); the read-only handle logs in as a role that may only read
//! (and keep hints); the failing batches belong to a role that may not
//! insert attestations; raw records and unreadable values are written with
//! SQL behind the store's back.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use vci_store::conformance::{StoreFactory, World};
use vci_store::select::{Source, Sourced};
use vci_store::{AttestationStore, ManifestRef, key};
use vci_store_postgres::PgStore;
use vci_store_postgres::testkit::{self, PgDb};

/// The password in the unreachable store's URL, which no message may show.
const SECRET: &str = "s3cret-conformance";

struct PgWorlds;

impl StoreFactory for PgWorlds {
    fn name(&self) -> &str {
        "postgres"
    }

    fn world(&self) -> Box<dyn World> {
        Box::new(PgWorld {
            peers: Mutex::new(BTreeMap::new()),
            db: testkit::pg().expect("the server this suite was started with"),
        })
    }
}

/// One schema and its handles. The handles are declared first, so they
/// close before the schema is dropped.
struct PgWorld {
    peers: Mutex<BTreeMap<usize, Arc<PgStore>>>,
    db: PgDb,
}

/// `s` as an SQL string literal.
fn lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// `v` as an SQL literal of `t`, or NULL.
fn opt<T: ToString>(v: Option<T>) -> String {
    v.map_or_else(|| "NULL".to_owned(), |v| lit(&v.to_string()))
}

impl PgWorld {
    /// Make sure the schema exists (a write creates it), so that grants
    /// and raw SQL have tables to name.
    fn ensure_schema(&self) {
        if self.db.schema_exists() {
            return;
        }
        let s = self.db.open();
        let e = s
            .put_for_test(
                "src/conformance-setup.test.ts",
                "1111111111111111",
                "00",
                None,
                b"{}",
            )
            .expect("a first write creates the schema");
        s.remove(vec![e]).expect("remove the setup record");
    }
}

impl World for PgWorld {
    fn peer(&self, i: usize) -> Arc<dyn AttestationStore> {
        assert!(i < 8, "peer {i}");
        let mut peers = self.peers.lock().unwrap_or_else(PoisonError::into_inner);
        peers
            .entry(i)
            .or_insert_with(|| Arc::new(self.db.open()))
            .clone()
    }

    fn fresh_peer(&self) -> Arc<dyn AttestationStore> {
        Arc::new(self.db.open())
    }

    /// Every handle reads the same server: nothing to do.
    fn sync(&self, _from: usize, _to: &[usize]) {}

    fn backing_exists(&self, _i: usize) -> Option<bool> {
        Some(self.db.schema_exists())
    }

    fn unreachable(&self) -> Option<Arc<dyn AttestationStore>> {
        let mut sel = testkit::selection(
            &format!("postgres://vci-user:{SECRET}@127.0.0.1:1/x"),
            &self.db.schema,
            "test",
        );
        sel.connect_timeout = Sourced {
            value: Duration::from_secs(1),
            source: Source::Env("VCI_STORE_CONNECT_TIMEOUT_SECS"),
        };
        Some(Arc::new(
            PgStore::open(&sel, &testkit::cx()).expect("open the store"),
        ))
    }

    fn secret(&self) -> Option<String> {
        Some(SECRET.to_owned())
    }

    /// The docs' `vci_reader` recipe: read everything, keep hints.
    fn read_only(&self, _i: usize) -> Option<Arc<dyn AttestationStore>> {
        self.ensure_schema();
        let url = self.db.role(
            "reader",
            "GRANT USAGE ON SCHEMA {schema} TO {role}; \
             GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {role}; \
             GRANT INSERT, UPDATE ON {schema}.memo, {schema}.flags TO {role}",
        );
        Some(Arc::new(self.db.open_as(&url)))
    }

    fn inject_raw(&self, _i: usize, target: &str, key: &str, value: &[u8]) -> bool {
        self.ensure_schema();
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
        let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
        let rows = self.db.query(&format!(
            "INSERT INTO {{schema}}.attestations
               (ns, key, test_key, signer, storage_key, target, issued, tree16,
                manifest_ref, ref_state, value)
             VALUES ('test', {}, {}, {}, {}, {}, {}, {}, {}, {ref_state}, decode('{hex}', 'hex'))
             RETURNING 1",
            lit(key),
            lit(&test_key),
            lit(&signer),
            lit(&storage_key),
            lit(target),
            opt(hint.as_ref().map(|h| h.issued)),
            opt(hint.and_then(|h| h.tree)),
            opt(manifest_ref),
        ));
        rows.len() == 1
    }

    fn make_unreadable(&self, _i: usize, key: &str) -> bool {
        self.ensure_schema();
        let rows = self.db.query(&format!(
            "UPDATE {{schema}}.attestations SET encoding = 99
             WHERE ns = 'test' AND key = {} RETURNING 1",
            lit(key)
        ));
        rows.len() == 1
    }

    /// A role that may read everything and write manifests, but not insert
    /// attestations: its deferred batches fail when they finish.
    fn failing_batches(&self) -> Option<Arc<dyn AttestationStore>> {
        self.ensure_schema();
        let url = self.db.role(
            "noinsert",
            "GRANT USAGE ON SCHEMA {schema} TO {role}; \
             GRANT SELECT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {role}; \
             GRANT INSERT ON {schema}.manifests TO {role}",
        );
        Some(Arc::new(self.db.open_as(&url)))
    }
}

vci_store::conformance_suite!(
    testkit::available().then(|| Box::new(PgWorlds) as Box<dyn StoreFactory>)
);
