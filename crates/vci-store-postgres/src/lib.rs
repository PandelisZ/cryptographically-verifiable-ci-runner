//! # `vci-store-postgres`: attestations on a shared PostgreSQL server
//!
//! A [`vci_store::AttestationStore`] kept in tables of one PostgreSQL schema
//! (default `vci`), one namespace per repository. Writes are visible to
//! every reader at once, so it has no exchange, and `vci ci` without
//! `--push` stores nothing (the publication gate). `docs/STORE-BACKENDS.md`
//! (section 17) is its design.
//!
//! * **Where.** The connection string comes only from `VCI_STORE_URL`
//!   ([`Selection::url`]), a `postgres://` URL or a libpq `key=value`
//!   string. vci reads `sslrootcert` itself; without an `sslmode`, TLS is
//!   required, except for `localhost`, `127.0.0.1`, `::1` and Unix sockets
//!   (`prefer`). With TLS, certificates are always verified (the webpki
//!   roots, plus `sslrootcert`). Every row carries a namespace:
//!   `VCI_STORE_NAMESPACE`, else `[store.postgres] namespace`, else the
//!   repository id.
//! * **Bounded time.** Connecting waits at most the connect timeout; every
//!   statement at most the statement timeout (ten minutes for `vci prune`);
//!   a lock at most ten seconds. After the first failure to reach the
//!   server, or the first wait that ran out, every call of the handle fails
//!   at once (a circuit breaker). Errors never carry the password.
//! * **Reads** are served from a per-handle cache that
//!   [`AttestationStore::prefetch`] fills in at most three statements, so a
//!   plan costs about a dozen statements whatever the number of units
//!   ([`PgStore::statements`]). A missing schema reads as an empty store;
//!   reads never create anything.
//! * **Writes** create the schema on first use, under an advisory lock.
//!   [`AttestationStore::batch`] is deferred: its writes are queued and
//!   written in one transaction when it finishes.
//! * **Hints** (the memo of passing attestations and the flags) live in two
//!   server-side tables per namespace and never fail.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod batch;
mod cache;
mod conn;
mod read;
mod schema;
mod write;

#[doc(hidden)]
pub mod testkit;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use postgres::types::Type;
use vci_store::select::Selection;
use vci_store::{
    AttestationStore, BackendFactory, Caps, Hydration, KeyHint, NewAttestation, OpenContext,
    Prefetch, StoreError, StoreStatus, StoredEnvelope, StoredManifest, WriteBatch, key,
};

pub use conn::PgError;

use cache::Cache;
use conn::{Conn, ConnSpec, Fail, KIND, LONG_RUNNING_TIMEOUT, Op};

/// Opens the PostgreSQL store (`VCI_STORE=postgres`, or a `postgres://`
/// `VCI_STORE_URL`).
#[derive(Debug, Clone, Copy, Default)]
pub struct PostgresFactory;

impl BackendFactory for PostgresFactory {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn summary(&self) -> &'static str {
        "a shared PostgreSQL server (VCI_STORE_URL), one namespace per repository"
    }

    fn open(
        &self,
        sel: &Selection,
        cx: &OpenContext,
    ) -> Result<Arc<dyn AttestationStore>, StoreError> {
        Ok(Arc::new(PgStore::open(sel, cx)?))
    }
}

/// The PostgreSQL store: one handle per repository per process, shared by
/// every thread. Cloning it gives another reference to the same handle (the
/// same pool, cache and circuit breaker).
#[derive(Clone)]
pub struct PgStore {
    inner: Arc<Inner>,
}

/// What a handle's connection settings came to (tests only).
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// The TLS mode used: `disable`, `prefer` or `require`.
    pub ssl_mode: &'static str,
    /// The `sslrootcert` file vci reads itself, if the URL named one.
    pub root_cert: Option<PathBuf>,
    /// `application_name`, as `pg_stat_activity` shows it.
    pub application_name: String,
    /// The `options` sent at connection (the URL's, then vci's).
    pub options: String,
    /// The schema.
    pub schema: String,
    /// The connect timeout.
    pub connect_timeout: Duration,
    /// The statement timeout.
    pub statement_timeout: Duration,
    /// The grace period of `remove_manifests`.
    pub manifest_grace: Duration,
    /// The most connections the handle opens.
    pub pool: usize,
}

/// The state of one handle, shared by its clones and its batches.
pub(crate) struct Inner {
    /// Identifies the handle's open batches on a thread.
    pub(crate) id: u64,
    pub(crate) conn: Conn,
    pub(crate) schema: String,
    pub(crate) schema_sql: schema::SchemaSql,
    pub(crate) read_sql: read::Sql,
    pub(crate) write_sql: write::Sql,
    pub(crate) batch_sql: batch::Sql,
    /// The schema version, once known.
    pub(crate) version: OnceLock<u32>,
    cache: Mutex<Cache>,
    memo: Mutex<HashMap<String, BTreeMap<String, String>>>,
    flags: Mutex<Option<BTreeSet<String>>>,
    pub(crate) memo_pruned: AtomicBool,
    namespace: OnceLock<Result<String, String>>,
    explicit_namespace: Option<String>,
    repo_id: Arc<dyn Fn() -> Result<String, String> + Send + Sync>,
    /// Where git keeps `shallow` when the clone is shallow.
    git_common_dir: PathBuf,
    /// `remove_manifests` keeps a root put more recently than this.
    pub(crate) grace: Duration,
    pool: usize,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn is_schema_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && (s.as_bytes()[0].is_ascii_lowercase() || s.as_bytes()[0] == b'_')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_namespace(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/@-".contains(&b))
}

impl Inner {
    pub(crate) fn cache(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn memo_cache(&self) -> MutexGuard<'_, HashMap<String, BTreeMap<String, String>>> {
        self.memo.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn flags(&self) -> MutexGuard<'_, Option<BTreeSet<String>>> {
        self.flags.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// This repository's namespace: the one configured, else the
    /// repository id (computed once). A shallow clone has none: its first
    /// commit is where the clone was cut, not the repository's, so every
    /// depth would get a namespace of its own.
    pub(crate) fn ns(&self) -> Result<&str, StoreError> {
        let r = self.namespace.get_or_init(|| match &self.explicit_namespace {
            Some(n) => Ok(n.clone()),
            None if self.git_common_dir.join("shallow").exists() => Err(
                "the postgres store keeps each repository's rows under a namespace, by default the repository id (its first commit); this is a shallow clone, whose first commit is where the clone was cut: set $VCI_STORE_NAMESPACE (the same value wherever the store is shared)"
                    .to_owned(),
            ),
            None => match (self.repo_id)() {
                Ok(id) if is_namespace(&id) => Ok(id),
                Ok(id) => Err(format!(
                    "the repository id {id:?} cannot name a postgres namespace: set $VCI_STORE_NAMESPACE"
                )),
                Err(e) => Err(format!(
                    "the postgres store keeps each repository's rows under a namespace, by default the repository id (its first commit), which this checkout cannot give ({e}; a shallow clone?): set $VCI_STORE_NAMESPACE"
                )),
            },
        });
        r.as_deref().map_err(|e| StoreError::Config(e.clone()))
    }

    /// What every call checks first: the circuit breaker, a schema found
    /// newer than this vci, the namespace. Costs no statement.
    pub(crate) fn ready(&self) -> Result<&str, StoreError> {
        self.conn.check()?;
        schema::refuse_newer(self)?;
        self.ns()
    }

    /// A row that does not decode as this vci wrote it.
    pub(crate) fn decode_error(&self, e: &postgres::Error) -> StoreError {
        StoreError::backend(PgError::from_text(conn::error_text(self.conn.secret(), e)))
    }

    fn location(&self, compute_namespace: bool) -> String {
        let ns = if compute_namespace {
            match self.ns() {
                Ok(n) => n.to_owned(),
                Err(_) => "(none: set $VCI_STORE_NAMESPACE)".to_owned(),
            }
        } else {
            match self.namespace.get() {
                Some(Ok(n)) => n.clone(),
                _ => match &self.explicit_namespace {
                    Some(n) => n.clone(),
                    None => "(the repository id)".to_owned(),
                },
            }
        };
        format!(
            "{} schema {} namespace {ns}",
            self.conn.spec().display(),
            self.schema
        )
    }
}

impl PgStore {
    /// Open the store `sel` describes, as [`PostgresFactory`] does. Nothing
    /// is connected or created here: a bad setting is
    /// [`StoreError::Config`] at once, and an unreachable server fails the
    /// first call, within the connect timeout.
    ///
    /// The statement timeout is the selection's, or ten minutes when
    /// [`OpenContext::long_running`] (`vci prune`), which also removes
    /// unreferenced manifests however recently they were put (no grace).
    pub fn open(sel: &Selection, cx: &OpenContext) -> Result<PgStore, StoreError> {
        let Some(url) = &sel.url else {
            return Err(StoreError::Config(
                "the postgres store needs $VCI_STORE_URL (postgres://<user>@<host>/<database>?sslmode=require)"
                    .into(),
            ));
        };
        let schema = sel.postgres.schema.value.clone();
        if !is_schema_name(&schema) {
            return Err(StoreError::Config(format!(
                "schema {schema:?} (from {}): expected a lowercase SQL identifier of at most 63 characters",
                sel.postgres.schema.source
            )));
        }
        let explicit_namespace = match &sel.namespace {
            Some(n) if !is_namespace(&n.value) => {
                return Err(StoreError::Config(format!(
                    "namespace {:?} (from {}): expected 1 to 128 of A-Z a-z 0-9 . _ : / @ -",
                    n.value, n.source
                )));
            }
            Some(n) => Some(n.value.clone()),
            None => None,
        };
        let statement_timeout = if cx.long_running {
            sel.timeout.value.max(LONG_RUNNING_TIMEOUT)
        } else {
            sel.timeout.value
        };
        let spec = ConnSpec::parse(
            &url.value,
            sel.connect_timeout.value,
            statement_timeout,
            &cx.command,
        )?;
        let pool = sel.postgres.pool.value.clamp(1, 64) as usize;
        let grace = if cx.long_running {
            Duration::ZERO
        } else {
            sel.postgres.manifest_grace.value
        };
        Ok(PgStore {
            inner: Arc::new(Inner {
                id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                conn: Conn::new(spec, url.value.clone(), pool),
                schema_sql: schema::SchemaSql::new(&schema),
                read_sql: read::Sql::new(&schema),
                write_sql: write::Sql::new(&schema),
                batch_sql: batch::Sql::new(&schema),
                schema,
                version: OnceLock::new(),
                cache: Mutex::new(Cache::default()),
                memo: Mutex::new(HashMap::new()),
                flags: Mutex::new(None),
                memo_pruned: AtomicBool::new(false),
                namespace: OnceLock::new(),
                explicit_namespace,
                repo_id: Arc::clone(&cx.repo_id),
                git_common_dir: cx.git_common_dir.clone(),
                grace,
                pool,
            }),
        })
    }

    /// How many statements this handle has sent (`BEGIN` and `COMMIT`
    /// included), for tests of the round-trip budget.
    pub fn statements(&self) -> u64 {
        self.inner.conn.statements()
    }

    /// The schema holding the tables.
    pub fn schema(&self) -> &str {
        &self.inner.schema
    }

    /// This repository's namespace (the configured one, else the
    /// repository id).
    pub fn namespace(&self) -> Result<String, StoreError> {
        self.inner.ns().map(str::to_owned)
    }

    /// Run `SELECT pg_sleep(secs)` as any statement runs (tests of the
    /// statement timeout and the circuit breaker).
    #[doc(hidden)]
    pub fn __sleep_for_test(&self, secs: f64) -> Result<(), StoreError> {
        self.inner.ready()?;
        let op = Op {
            verb: "read",
            retry: false,
            upsert: false,
        };
        let r = self.inner.conn.run(op, |db| {
            db.execute("SELECT pg_sleep($1)", &[(&secs, Type::FLOAT8)])
        });
        Fail::or_absent(r, || 0).map(|_| ())
    }

    /// What the connection settings came to (tests of URL handling).
    #[doc(hidden)]
    pub fn __connection_for_test(&self) -> ConnectionInfo {
        let spec = self.inner.conn.spec();
        let s = spec.summary();
        ConnectionInfo {
            ssl_mode: s.ssl_mode,
            root_cert: s.root_cert,
            application_name: s.application_name,
            options: s.options,
            schema: self.inner.schema.clone(),
            connect_timeout: spec.connect_timeout,
            statement_timeout: spec.statement_timeout,
            manifest_grace: self.inner.grace,
            pool: self.inner.pool,
        }
    }
}

impl fmt::Debug for PgStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgStore")
            .field("location", &self.inner.location(false))
            .field("statements", &self.statements())
            .finish_non_exhaustive()
    }
}

impl AttestationStore for PgStore {
    fn kind(&self) -> &'static str {
        KIND
    }

    /// `postgres://***@<host>:<port>/<database> schema <s> namespace <ns>`.
    fn location(&self) -> String {
        self.inner.location(true)
    }

    fn caps(&self) -> Caps {
        Caps::LOCAL.with_shared_writes(true).with_hints(true)
    }

    fn status(&self) -> Result<StoreStatus, StoreError> {
        read::status(&self.inner)
    }

    fn list_units(&self, test_ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
        read::list_units(&self.inner, test_ids)
    }

    fn list_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
        read::list_all(&self.inner)
    }

    fn read_values(&self, envs: &mut [&mut StoredEnvelope]) -> Result<(), StoreError> {
        read::read_values(&self.inner, envs)
    }

    fn manifest(&self, root: &str) -> Result<Option<StoredManifest>, StoreError> {
        read::manifest(&self.inner, root)
    }

    fn manifest_roots(&self) -> Result<Vec<String>, StoreError> {
        read::manifest_roots(&self.inner)
    }

    fn put(&self, att: &NewAttestation<'_>) -> Result<StoredEnvelope, StoreError> {
        if batch::is_open(&self.inner) {
            batch::put(&self.inner, att)
        } else {
            write::put(&self.inner, att)
        }
    }

    fn put_manifest(&self, root: &str, bytes: &[u8]) -> Result<bool, StoreError> {
        if batch::is_open(&self.inner) {
            batch::put_manifest(&self.inner, root, bytes)
        } else {
            write::put_manifest(&self.inner, root, bytes)
        }
    }

    fn remove(&self, doomed: Vec<StoredEnvelope>) -> Result<Vec<StoredEnvelope>, StoreError> {
        if batch::is_open(&self.inner) {
            batch::remove(&self.inner, doomed)
        } else {
            write::remove(&self.inner, doomed)
        }
    }

    /// Keeps (and does not count) a root that an attestation or another
    /// manifest (as its base) references, or that was put within the grace
    /// period (`[store.postgres] manifest_grace`, one hour by default; none
    /// for a long-running command such as `vci prune`). While a deferred
    /// batch is open on this thread, the roots it will write or reference
    /// are kept too.
    fn remove_manifests(&self, roots: &[&str]) -> Result<usize, StoreError> {
        match batch::queued_roots(&self.inner) {
            Some(queued) if roots.iter().any(|r| queued.contains(*r)) => {
                let rest: Vec<&str> = roots
                    .iter()
                    .copied()
                    .filter(|r| !queued.contains(*r))
                    .collect();
                for r in roots {
                    key::check_hex("input root", r)?;
                }
                write::remove_manifests(&self.inner, &rest)
            }
            _ => write::remove_manifests(&self.inner, roots),
        }
    }

    fn read_units(&self, test_ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
        read::read_units(&self.inner, test_ids)
    }

    fn read_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
        read::read_all(&self.inner)
    }

    fn count(&self) -> Result<usize, StoreError> {
        read::count(&self.inner)
    }

    fn manifests(&self, roots: &[&str]) -> Result<Vec<Option<StoredManifest>>, StoreError> {
        read::manifests(&self.inner, roots)
    }

    fn orphan_manifests(&self, roots: &[&str]) -> Result<Vec<String>, StoreError> {
        read::orphan_manifests(&self.inner, roots)
    }

    fn put_for_test(
        &self,
        test_id: &str,
        signer: &str,
        storage_key: &str,
        hint: Option<&KeyHint>,
        envelope: &[u8],
    ) -> Result<StoredEnvelope, StoreError> {
        self.put(&NewAttestation::for_test(
            test_id,
            signer,
            storage_key,
            hint,
            envelope,
        ))
    }

    /// A deferred batch: see the crate docs.
    fn batch(&self) -> Result<WriteBatch, StoreError> {
        batch::open(&self.inner)
    }

    fn prefetch(&self, what: Prefetch<'_>) -> Result<Hydration, StoreError> {
        read::prefetch(&self.inner, what)
    }

    /// Opens the first connection (and its TLS session) on a thread of its
    /// own.
    fn warm(&self) {
        let inner = Arc::clone(&self.inner);
        let _ = std::thread::Builder::new()
            .name("vci-postgres-warm".into())
            .spawn(move || inner.conn.warm());
    }

    fn passing_on(&self, tree16: &str) -> BTreeMap<String, String> {
        read::passing_on(&self.inner, tree16)
    }

    fn remember_passing(&self, tree16: &str, items: &[(String, String)]) {
        write::remember_passing(&self.inner, tree16, items)
    }

    fn flag(&self, name: &str) -> bool {
        read::flag(&self.inner, name)
    }

    fn set_flag(&self, name: &str) {
        write::set_flag(&self.inner, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vci_store::select::{Secret, Source, Sourced};

    fn cx(long_running: bool) -> OpenContext {
        OpenContext {
            repo_root: "/nonexistent".into(),
            git_dir: "/nonexistent/.git".into(),
            git_common_dir: "/nonexistent/.git".into(),
            repo_id: Arc::new(|| Err("no repository".to_owned())),
            jobs: 1,
            command: "test".to_owned(),
            long_running,
        }
    }

    fn sel(url: &str) -> Selection {
        let mut s = Selection::for_backend("postgres");
        s.url = Some(Sourced {
            value: Secret::new(url),
            source: Source::Env("VCI_STORE_URL"),
        });
        s
    }

    #[test]
    fn open_does_no_io_and_checks_settings() {
        let f = PostgresFactory;
        assert_eq!(f.kind(), "postgres");
        let store = f
            .open(&sel("postgres://u:pw@127.0.0.1:1/x"), &cx(false))
            .unwrap();
        assert_eq!(store.kind(), "postgres");
        assert!(store.caps().shared_writes && store.caps().keeps_hints);
        assert!(store.exchange().is_none());
        match f.open(&Selection::for_backend("postgres"), &cx(false)) {
            Err(StoreError::Config(m)) => assert!(m.contains("VCI_STORE_URL"), "{m}"),
            _ => panic!("expected Config"),
        }
        let mut bad = sel("postgres://u@h/x");
        bad.postgres.schema.value = "Bad-Name".into();
        assert!(matches!(
            f.open(&bad, &cx(false)),
            Err(StoreError::Config(_))
        ));
    }

    #[test]
    fn without_a_repository_id_the_namespace_must_be_set() {
        let store = PgStore::open(&sel("postgres://u@127.0.0.1:1/x"), &cx(false)).unwrap();
        match store.status() {
            Err(StoreError::Config(m)) => assert!(m.contains("VCI_STORE_NAMESPACE"), "{m}"),
            other => panic!("expected Config, got {other:?}"),
        }
        assert!(store.location().contains("set $VCI_STORE_NAMESPACE"));
    }

    #[test]
    fn a_shallow_clone_needs_a_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cx(false);
        c.git_common_dir = dir.path().to_path_buf();
        c.repo_id = Arc::new(|| Ok("0123456789abcdef0123456789abcdef01234567".to_owned()));
        let s = PgStore::open(&sel("postgres://u@127.0.0.1:1/x"), &c).unwrap();
        assert_eq!(
            s.namespace().unwrap(),
            "0123456789abcdef0123456789abcdef01234567"
        );
        std::fs::write(dir.path().join("shallow"), "0123\n").unwrap();
        let s = PgStore::open(&sel("postgres://u@127.0.0.1:1/x"), &c).unwrap();
        match s.status() {
            Err(StoreError::Config(m)) => {
                assert!(
                    m.contains("shallow") && m.contains("VCI_STORE_NAMESPACE"),
                    "{m}"
                )
            }
            other => panic!("expected Config, got {other:?}"),
        }
        let mut named = sel("postgres://u@127.0.0.1:1/x");
        named.namespace = Some(Sourced {
            value: "acme".into(),
            source: Source::Env("VCI_STORE_NAMESPACE"),
        });
        assert_eq!(
            PgStore::open(&named, &c).unwrap().namespace().unwrap(),
            "acme"
        );
    }

    #[test]
    fn long_running_commands_wait_longer_and_keep_no_grace() {
        let store = PgStore::open(&sel("postgres://u@127.0.0.1:1/x"), &cx(true)).unwrap();
        let c = store.__connection_for_test();
        assert_eq!(c.statement_timeout, LONG_RUNNING_TIMEOUT);
        assert_eq!(c.manifest_grace, Duration::ZERO);
        assert!(
            c.options.contains("statement_timeout=600000"),
            "{}",
            c.options
        );
        let store = PgStore::open(&sel("postgres://u@127.0.0.1:1/x"), &cx(false)).unwrap();
        let c = store.__connection_for_test();
        assert_eq!(c.statement_timeout, Duration::from_secs(30));
        assert_eq!(c.manifest_grace, Duration::from_secs(3600));
        assert_eq!(
            c.application_name,
            format!("vci {} test", env!("CARGO_PKG_VERSION"))
        );
    }
}
