//! The remote mode: every read and write goes to a libSQL server (Turso,
//! `sqld`). `docs/STORE-BACKENDS.md` section 18 is its design.
//!
//! * **Tables.** One set of the SQLite store's tables (schema version 1,
//!   [`vci_store_sqlite::sql`]) per namespace, under the name prefix
//!   `vci_<16 hex digits of BLAKE3(namespace)>_`, plus a change log the
//!   replicas sync from (`<prefix>log`). `vci_schema` names each
//!   namespace's prefix and version. The first write creates them in one
//!   transaction; reads never do.
//! * **Reads** are served from a per-handle cache ([`crate::cache`]) that
//!   [`AttestationStore::prefetch`] fills in two requests (the listings,
//!   then the chosen values with their manifests and bases), whatever the
//!   number of units; a miss is one request for any number of keys (a JSON
//!   array bound to `json_each`).
//! * **Writes** are queued in a deferred batch ([`crate::batch`]) and sent
//!   as one transactional request; a write outside a batch is a batch of
//!   one.
//!
//! [`AttestationStore::prefetch`]: vci_store::AttestationStore::prefetch

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libsql::Value as V;
use vci_store::timing::Step;
use vci_store::{
    Choose, GONE, Hydration, Prefetch, StoreError, StoreStatus, StoredEnvelope, StoredManifest, key,
};
use vci_store_sqlite::sql::{Names, Sql};

use crate::cache::{Cache, Listed, Manifest, Value};
use crate::conn::{Conn, Fail, KIND, READ, WRITE, col_int, col_text, col_value, json_list, text};

/// The newest schema version this vci reads and writes.
pub(crate) const SUPPORTED: u32 = 1;

/// Keys, test keys or roots per request.
const CHUNK: usize = 5_000;

/// How long the change log keeps an entry. A replica that last synced
/// before the oldest entry kept syncs everything again.
pub(crate) const LOG_KEEP_SECS: i64 = 30 * 24 * 60 * 60;

/// What creates a namespace's tables ([`StoreStatus::Absent`]).
pub(crate) const ABSENT_ADVICE: &str = "the first `vci run` creates it";

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The table name prefix of a namespace.
pub fn table_prefix(namespace: &str) -> String {
    format!("vci_{}_", &key::test_key(namespace)[..16])
}

/// The statements of one namespace's tables.
pub(crate) struct Tables {
    pub(crate) prefix: String,
    pub(crate) names: Names,
    /// The SQLite store's statements over these tables.
    pub(crate) shared: Sql,
    pub(crate) log: String,
    /// The DDL: `vci_schema`, the SQLite store's tables, the log.
    pub(crate) ddl: Vec<String>,
    list_units: String,
    values: String,
    manifests_and_bases: String,
    manifests_of: String,
    read_units: String,
    read_all: String,
    orphans: String,
    flags_all: String,
    pub(crate) existing_keys: String,
    pub(crate) removable: String,
    pub(crate) sync: String,
}

const SCHEMA_DDL: &str = "CREATE TABLE IF NOT EXISTS vci_schema (
  ns          TEXT    NOT NULL PRIMARY KEY,
  prefix      TEXT    NOT NULL,
  version     INTEGER NOT NULL,
  vci_version TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  log_floor   INTEGER NOT NULL DEFAULT 0
)";

const STATUS: &str = "SELECT version, log_floor FROM vci_schema WHERE ns = ?1";

impl Tables {
    fn new(namespace: &str) -> Tables {
        let prefix = table_prefix(namespace);
        let names = Names::prefixed(&prefix);
        let shared = Sql::new(&names);
        let (a, m, f) = (&names.attestations, &names.manifests, &names.flags);
        let log = format!("{prefix}log");
        let set = "SELECT value FROM json_each(?1)";
        let mut ddl = vec![SCHEMA_DDL.to_owned()];
        ddl.extend(
            shared
                .ddl
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
        );
        ddl.push(format!(
            "CREATE TABLE IF NOT EXISTS {log} (seq INTEGER PRIMARY KEY AUTOINCREMENT, \
             test_key TEXT, signer TEXT, storage_key TEXT, root TEXT, at INTEGER NOT NULL)"
        ));
        ddl.push(format!("CREATE INDEX IF NOT EXISTS {log}_at ON {log} (at)"));
        let touched_slots = format!(
            "SELECT DISTINCT test_key, signer, storage_key FROM {log} WHERE seq > ?1 AND root IS NULL"
        );
        let touched_roots =
            format!("SELECT DISTINCT root FROM {log} WHERE seq > ?1 AND root IS NOT NULL");
        // A log entry's fingerprint: when it was written and what it names.
        let mark = |seq: &str| {
            format!(
                "(SELECT at || ':' || coalesce(test_key, '') || ':' || coalesce(signer, '') \
                 || ':' || coalesce(storage_key, '') || ':' || coalesce(root, '') \
                 FROM {log} WHERE seq = {seq})"
            )
        };
        let mark_then = mark("?1");
        let mark_now = mark(&format!("(SELECT max(seq) FROM {log})"));
        Tables {
            list_units: format!(
                "SELECT test_key, key, target FROM {a} WHERE test_key IN ({set}) ORDER BY test_key, key"
            ),
            // The values of these keys (?1), and when ?2 is 1, the
            // manifests they reference with those manifests' bases: one
            // request.
            values: format!(
                "SELECT 0, key, value, encoding, manifest_ref FROM {a} WHERE key IN ({set}) \
                 UNION ALL \
                 SELECT 1, root, value, encoding, base FROM {m} WHERE ?2 = 1 AND (\
                   root IN (SELECT manifest_ref FROM {a} WHERE key IN ({set})) \
                   OR root IN (SELECT base FROM {m} WHERE base IS NOT NULL AND \
                     root IN (SELECT manifest_ref FROM {a} WHERE key IN ({set}))))"
            ),
            manifests_and_bases: format!(
                "SELECT root, value, encoding, base FROM {m} WHERE root IN ({set}) \
                 OR root IN (SELECT base FROM {m} WHERE base IS NOT NULL AND root IN ({set}))"
            ),
            manifests_of: format!("SELECT root, value, encoding FROM {m} WHERE root IN ({set})"),
            read_units: format!(
                "SELECT test_key, key, target, value, encoding FROM {a} \
                 WHERE test_key IN ({set}) ORDER BY test_key, key"
            ),
            read_all: format!("SELECT target, key, value, encoding FROM {a} ORDER BY target, key"),
            orphans: format!(
                "SELECT j.value FROM json_each(?1) AS j \
                 WHERE NOT EXISTS (SELECT 1 FROM {a} WHERE ref_state = 0) \
                 AND NOT EXISTS (SELECT 1 FROM {a} AS x WHERE x.manifest_ref = j.value)"
            ),
            flags_all: format!("SELECT name FROM {f}"),
            existing_keys: format!("SELECT key FROM {a} WHERE key IN ({set})"),
            removable: format!(
                "SELECT root FROM {m} AS r WHERE r.root IN ({set}) AND r.put_at <= ?2 \
                 AND NOT EXISTS (SELECT 1 FROM {a} WHERE manifest_ref = r.root) \
                 AND NOT EXISTS (SELECT 1 FROM {m} AS b WHERE b.base = r.root)"
            ),
            // What changed since seq ?1 (everything when ?2 is 1), in one
            // snapshot: the fingerprints of entry ?1 and of the last entry,
            // when the namespace was created, its schema version (NULL: the
            // namespace has no tables), the log's high-water mark and
            // the floor below which it dropped entries (0), the
            // attestations of the slots touched (1), those slots (2), the
            // manifests touched (3) and their roots (4). ?3 is the
            // namespace.
            sync: format!(
                "SELECT 0, {mark_then}, {mark_now}, \
                   (SELECT created_at FROM vci_schema WHERE ns = ?3), \
                   (SELECT version FROM vci_schema WHERE ns = ?3), \
                   (SELECT coalesce(max(seq), 0) FROM {log}), \
                   (SELECT log_floor FROM vci_schema WHERE ns = ?3) \
                 UNION ALL \
                 SELECT 1, a.key, a.target, a.value, a.encoding, NULL, NULL FROM {a} AS a \
                   JOIN ({touched_slots}) AS l USING (test_key, signer, storage_key) WHERE ?2 = 0 \
                 UNION ALL \
                 SELECT 1, key, target, value, encoding, NULL, NULL FROM {a} WHERE ?2 = 1 \
                 UNION ALL \
                 SELECT 2, test_key || ':' || signer || ':' || storage_key, NULL, NULL, NULL, \
                   NULL, NULL FROM ({touched_slots}) WHERE ?2 = 0 \
                 UNION ALL \
                 SELECT 3, m.root, NULL, m.value, m.encoding, NULL, NULL FROM {m} AS m \
                   JOIN ({touched_roots}) AS l USING (root) WHERE ?2 = 0 \
                 UNION ALL \
                 SELECT 3, root, NULL, value, encoding, NULL, NULL FROM {m} WHERE ?2 = 1 \
                 UNION ALL \
                 SELECT 4, root, NULL, NULL, NULL, NULL, NULL FROM ({touched_roots}) WHERE ?2 = 0"
            ),
            prefix,
            names,
            shared,
            log,
            ddl,
        }
    }
}

/// The state of one remote handle, shared by its replica and its batches.
pub(crate) struct Remote {
    /// Identifies the handle's open batches on a thread.
    pub(crate) id: u64,
    pub(crate) conn: Conn,
    namespace: OnceLock<Result<String, String>>,
    explicit_namespace: Option<String>,
    repo_id: Arc<dyn Fn() -> Result<String, String> + Send + Sync>,
    git_common_dir: PathBuf,
    tables: OnceLock<Tables>,
    /// The schema version, once known.
    version: OnceLock<u32>,
    cache: Mutex<Cache>,
    memo: Mutex<HashMap<String, BTreeMap<String, String>>>,
    flags: Mutex<Option<BTreeSet<String>>>,
    pub(crate) memo_pruned: AtomicBool,
    pub(crate) log_pruned: AtomicBool,
    /// `remove_manifests` keeps a root put more recently than this.
    pub(crate) grace: Duration,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn is_namespace(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/@-".contains(&b))
}

/// A row that does not have the shape this vci wrote.
fn malformed(what: &str) -> StoreError {
    StoreError::backend(crate::conn::LibsqlError::from_text(format!(
        "a row of the {what} does not have the shape this vci wrote"
    )))
}

impl Remote {
    pub(crate) fn new(
        conn: Conn,
        explicit_namespace: Option<String>,
        repo_id: Arc<dyn Fn() -> Result<String, String> + Send + Sync>,
        git_common_dir: PathBuf,
        grace: Duration,
    ) -> Remote {
        Remote {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            conn,
            namespace: OnceLock::new(),
            explicit_namespace,
            repo_id,
            git_common_dir,
            tables: OnceLock::new(),
            version: OnceLock::new(),
            cache: Mutex::new(Cache::default()),
            memo: Mutex::new(HashMap::new()),
            flags: Mutex::new(None),
            memo_pruned: AtomicBool::new(false),
            log_pruned: AtomicBool::new(false),
            grace,
        }
    }

    pub(crate) fn cache(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn memo_cache(&self) -> MutexGuard<'_, HashMap<String, BTreeMap<String, String>>> {
        self.memo.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn flags(&self) -> MutexGuard<'_, Option<BTreeSet<String>>> {
        self.flags.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// This repository's namespace: the one configured, else the
    /// repository id (computed once). A shallow clone has none: its first
    /// commit is where the clone was cut, not the repository's.
    pub(crate) fn ns(&self) -> Result<&str, StoreError> {
        let r = self.namespace.get_or_init(|| match &self.explicit_namespace {
            Some(n) => Ok(n.clone()),
            None if self.git_common_dir.join("shallow").exists() => Err(
                "the libsql store keeps each repository's records under a namespace, by default the repository id (its first commit); this is a shallow clone, whose first commit is where the clone was cut: set $VCI_STORE_NAMESPACE (the same value wherever the store is shared)"
                    .to_owned(),
            ),
            None => match (self.repo_id)() {
                Ok(id) if is_namespace(&id) => Ok(id),
                Ok(id) => Err(format!(
                    "the repository id {id:?} cannot name a libsql namespace: set $VCI_STORE_NAMESPACE"
                )),
                Err(e) => Err(format!(
                    "the libsql store keeps each repository's records under a namespace, by default the repository id (its first commit), which this checkout cannot give ({e}; a shallow clone?): set $VCI_STORE_NAMESPACE"
                )),
            },
        });
        r.as_deref().map_err(|e| StoreError::Config(e.clone()))
    }

    /// The namespace's statements.
    pub(crate) fn tables(&self) -> Result<&Tables, StoreError> {
        let ns = self.ns()?;
        Ok(self.tables.get_or_init(|| Tables::new(ns)))
    }

    fn incompatible(found: u32) -> StoreError {
        StoreError::Incompatible {
            backend: KIND,
            found,
            supported: SUPPORTED,
        }
    }

    /// What every call checks first: the circuit breaker, a schema found
    /// newer than this vci, the namespace. Sends nothing.
    pub(crate) fn ready(&self) -> Result<&Tables, StoreError> {
        self.conn.check()?;
        if let Some(&v) = self.version.get()
            && v > SUPPORTED
        {
            return Err(Self::incompatible(v));
        }
        self.tables()
    }

    /// The location for messages: the server and the namespace.
    pub(crate) fn location(&self, compute_namespace: bool) -> String {
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
        format!("{} namespace {ns}", self.conn.display())
    }

    // ---- requests ------------------------------------------------------------------

    /// The rows of one statement ([`Conn::query`]: the first request of a
    /// handle is bounded by the connect timeout).
    pub(crate) fn query(
        &self,
        op: crate::conn::Op,
        sql: &str,
        params: Vec<V>,
    ) -> Result<Vec<Vec<V>>, Fail> {
        self.conn.query(op, sql, params)
    }

    /// Statements in one transaction, one request ([`Conn::batch`]).
    pub(crate) fn write(&self, op: crate::conn::Op, statements: &[String]) -> Result<(), Fail> {
        self.conn.batch(op, statements)
    }

    // ---- the schema ---------------------------------------------------------------

    /// The namespace's schema version (one request, then remembered once
    /// the tables exist), or `None` when they do not exist yet.
    pub(crate) fn version(&self) -> Result<Option<u32>, StoreError> {
        if let Some(&v) = self.version.get() {
            return if v > SUPPORTED {
                Err(Self::incompatible(v))
            } else {
                Ok(Some(v))
            };
        }
        let ns = self.ns()?.to_owned();
        let r = self.query(READ, STATUS, vec![V::Text(ns)]);
        match Fail::or_absent(r, Vec::new)?.first() {
            Some(row) => {
                let v = row
                    .first()
                    .and_then(col_int)
                    .unwrap_or(0)
                    .clamp(0, i64::from(u32::MAX));
                let _ = self.version.set(u32::try_from(v).unwrap_or(u32::MAX));
                self.version()
            }
            None => Ok(None),
        }
    }

    /// Remember the schema version a replica's sync read (`v`), as
    /// [`Remote::version`] would: later calls send nothing for it, and a
    /// newer one is refused.
    pub(crate) fn found_version(&self, v: i64) -> Result<(), StoreError> {
        let v = u32::try_from(v.clamp(0, i64::from(u32::MAX))).unwrap_or(u32::MAX);
        let _ = self.version.set(v);
        self.version().map(drop)
    }

    /// Make sure the namespace's tables exist before a write. When the
    /// namespace's row in `vci_schema` says they do (one read, then
    /// remembered by the handle), nothing is sent: no DDL and no write
    /// transaction. Otherwise they are created in one transaction, which,
    /// as every write, takes the write lock before its first statement
    /// ([`Conn::batch`]). A token that may not create them gets
    /// [`StoreError::NotInitialized`]; a server that takes no more writes,
    /// [`StoreError::Denied`] as for any write.
    ///
    /// [`Conn::batch`]: crate::conn::Conn::batch
    pub(crate) fn ensure(&self) -> Result<&Tables, StoreError> {
        let t = self.ready()?;
        if self.version()?.is_some() {
            // The tables are there (a newer schema is refused by version()).
            return Ok(t);
        }
        let ns = self.ns()?;
        let mut stmts = t.ddl.clone();
        stmts.push(format!(
            "INSERT INTO vci_schema (ns, prefix, version, vci_version, created_at) \
             VALUES ({}, {}, {SUPPORTED}, {}, {}) ON CONFLICT (ns) DO NOTHING",
            text(ns),
            text(&t.prefix),
            text(env!("CARGO_PKG_VERSION")),
            now()
        ));
        let not_initialized = || StoreError::NotInitialized {
            backend: KIND,
            advice: "the first vci run with a token allowed to create tables creates them"
                .to_owned(),
        };
        match self.write(WRITE, &stmts) {
            Ok(()) => {}
            // A server that takes no more writes (blocked, full) refuses
            // this one as it would any other: the token is not the reason.
            Err(Fail::Store(e)) if crate::conn::is_no_writes(&e) => return Err(e),
            Err(Fail::Store(StoreError::Denied { .. })) => return Err(not_initialized()),
            Err(Fail::Absent) => return Err(not_initialized()),
            Err(Fail::Store(e)) => return Err(e),
        }
        match self.version()? {
            Some(_) => Ok(t),
            None => Err(not_initialized()),
        }
    }

    pub(crate) fn status(&self) -> Result<StoreStatus, StoreError> {
        self.ready()?;
        Ok(match self.version()? {
            None => StoreStatus::Absent {
                advice: ABSENT_ADVICE.to_owned(),
            },
            Some(v) => StoreStatus::Ready {
                schema_version: Some(v),
            },
        })
    }

    // ---- listings ------------------------------------------------------------------

    /// The listings of these test keys from the server, by test key.
    fn query_listings(
        &self,
        t: &Tables,
        test_keys: &[&str],
    ) -> Result<HashMap<String, Vec<Listed>>, StoreError> {
        let mut out: HashMap<String, Vec<Listed>> = HashMap::new();
        let mut step = Step::start(KIND);
        for chunk in test_keys.chunks(CHUNK) {
            let r = self
                .conn
                .query(READ, &t.list_units, vec![json_list(chunk.iter().copied())]);
            for row in Fail::or_absent(r, Vec::new)? {
                let (Some(tk), Some(k), Some(target)) = (
                    row.first().and_then(col_text),
                    row.get(1).and_then(col_text),
                    row.get(2).and_then(col_text),
                ) else {
                    continue;
                };
                if matches!(key::parse_key(&k), Some((t, _, _)) if t == tk) {
                    out.entry(tk).or_default().push(Listed { key: k, target });
                }
            }
        }
        step.lap(format_args!("list {} unit(s)", test_keys.len()));
        Ok(out)
    }

    pub(crate) fn list_units(
        &self,
        test_ids: &[&str],
    ) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
        let tks: Vec<String> = test_ids.iter().map(|id| key::test_key(id)).collect();
        let mut found: HashMap<String, Vec<StoredEnvelope>> = HashMap::new();
        let mut missing: BTreeSet<&str> = BTreeSet::new();
        {
            let c = self.cache();
            for tk in &tks {
                if found.contains_key(tk) || missing.contains(tk.as_str()) {
                    continue;
                }
                match c.listing(tk) {
                    Some(l) => {
                        found.insert(tk.clone(), l);
                    }
                    None => {
                        missing.insert(tk);
                    }
                }
            }
        }
        if !missing.is_empty() {
            let t = self.ready()?;
            let missing: Vec<&str> = missing.into_iter().collect();
            let mut listed = self.query_listings(t, &missing)?;
            for tk in missing {
                let l = listed.remove(tk).unwrap_or_default();
                found.insert(tk.to_owned(), entries(&l));
            }
        }
        Ok(tks
            .iter()
            .map(|tk| found.get(tk).cloned().unwrap_or_default())
            .collect())
    }

    pub(crate) fn list_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
        let t = self.ready()?;
        let r = self.query(READ, &t.shared.list_all, Vec::new());
        Ok(Fail::or_absent(r, Vec::new)?
            .into_iter()
            .filter_map(|row| {
                let k = row.first().and_then(col_text)?;
                let target = row.get(1).and_then(col_text)?;
                StoredEnvelope::from_key(target, &k)
            })
            .collect())
    }

    pub(crate) fn count(&self) -> Result<usize, StoreError> {
        let t = self.ready()?;
        let r = self.query(READ, &t.shared.keys, Vec::new());
        Ok(Fail::or_absent(r, Vec::new)?
            .iter()
            .filter(|row| {
                row.first()
                    .and_then(col_text)
                    .is_some_and(|k| key::parse_key(&k).is_some())
            })
            .count())
    }

    // ---- values ----------------------------------------------------------------------

    /// The values of these keys (with the manifest each references), and
    /// when `with_manifests`, those manifests and their bases into the
    /// cache (the ones not stored as absent): one request per [`CHUNK`].
    fn query_values(
        &self,
        t: &Tables,
        keys: &[&str],
        with_manifests: bool,
    ) -> Result<HashMap<String, (Value, Option<String>)>, StoreError> {
        let mut out = HashMap::new();
        for chunk in keys.chunks(CHUNK) {
            let r = self.query(
                READ,
                &t.values,
                vec![
                    json_list(chunk.iter().copied()),
                    V::Integer(i64::from(with_manifests)),
                ],
            );
            let rows = Fail::or_absent(r, Vec::new)?;
            let mut manifests: BTreeMap<String, Manifest> = BTreeMap::new();
            let mut bases: BTreeSet<String> = BTreeSet::new();
            let mut refs: BTreeSet<String> = BTreeSet::new();
            for row in rows {
                if row.len() < 5 {
                    return Err(malformed("values"));
                }
                let Some(name) = col_text(&row[1]) else {
                    continue;
                };
                let v = match col_value(&row[2], &row[3]) {
                    Ok(b) => Value::Bytes(b),
                    Err(why) => Value::Unreadable(why),
                };
                let extra = col_text(&row[4]);
                if col_int(&row[0]) == Some(0) {
                    if let Some(r) = &extra {
                        refs.insert(r.clone());
                    }
                    out.insert(name, (v, extra));
                } else {
                    if let Some(b) = extra {
                        bases.insert(b);
                    }
                    manifests.insert(
                        name,
                        match v {
                            Value::Bytes(b) => Manifest::Bytes(b),
                            Value::Unreadable(why) => Manifest::Unreadable(why),
                        },
                    );
                }
            }
            if with_manifests {
                let mut c = self.cache();
                for r in refs.iter().chain(bases.iter()) {
                    if !manifests.contains_key(r) && !c.has_stored_manifest(r) {
                        c.set_manifest(r.clone(), Manifest::Absent);
                    }
                }
                for (root, m) in manifests {
                    c.set_manifest(root, m);
                }
            }
        }
        Ok(out)
    }

    pub(crate) fn read_values(&self, envs: &mut [&mut StoredEnvelope]) -> Result<(), StoreError> {
        let mut misses: Vec<usize> = Vec::new();
        {
            let mut c = self.cache();
            for (i, e) in envs.iter_mut().enumerate() {
                match c.take_value(&e.key) {
                    Some(v) => v.apply(e),
                    None => misses.push(i),
                }
            }
        }
        if misses.is_empty() {
            return Ok(());
        }
        let t = self.ready()?;
        let step = Step::start(KIND);
        let keys: BTreeSet<String> = misses.iter().map(|&i| envs[i].key.clone()).collect();
        let n = keys.len();
        // Whoever reads a value verifies it next, which reads the manifest
        // it references and that manifest's base: they come in the same
        // request.
        let read = {
            let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
            self.query_values(t, &keys, true)?
        };
        for &i in &misses {
            match read.get(&envs[i].key) {
                Some((v, _)) => v.clone().apply(envs[i]),
                None => envs[i].set_error(GONE),
            }
        }
        step.done(format_args!("read {n} value(s)"));
        Ok(())
    }

    pub(crate) fn read_units(
        &self,
        test_ids: &[&str],
    ) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
        let tks: Vec<String> = test_ids.iter().map(|id| key::test_key(id)).collect();
        let mut found: HashMap<String, Vec<StoredEnvelope>> = HashMap::new();
        let mut missing: BTreeSet<&str> = BTreeSet::new();
        {
            // A unit whose listing and every value are cached is answered
            // from the cache, values left there: `vci run` reads its units
            // twice (last durations, then supersession).
            let c = self.cache();
            for tk in &tks {
                if found.contains_key(tk) || missing.contains(tk.as_str()) {
                    continue;
                }
                let cached = c.listing(tk).and_then(|mut l| {
                    for e in l.iter_mut() {
                        c.value(&e.key)?.clone().apply(e);
                    }
                    Some(l)
                });
                match cached {
                    Some(l) => {
                        found.insert(tk.clone(), l);
                    }
                    None => {
                        missing.insert(tk);
                    }
                }
            }
        }
        if !missing.is_empty() {
            let t = self.ready()?;
            let missing: Vec<&str> = missing.into_iter().collect();
            for chunk in missing.chunks(CHUNK) {
                let r =
                    self.conn
                        .query(READ, &t.read_units, vec![json_list(chunk.iter().copied())]);
                for row in Fail::or_absent(r, Vec::new)? {
                    if row.len() < 5 {
                        return Err(malformed("attestations"));
                    }
                    let (Some(tk), Some(k), Some(target)) =
                        (col_text(&row[0]), col_text(&row[1]), col_text(&row[2]))
                    else {
                        continue;
                    };
                    if !matches!(key::parse_key(&k), Some((t, _, _)) if t == tk) {
                        continue;
                    }
                    if let Some(mut e) = StoredEnvelope::from_key(target, &k) {
                        match col_value(&row[3], &row[4]) {
                            Ok(b) => e.set_value(b),
                            Err(why) => e.set_error(why),
                        }
                        found.entry(tk).or_default().push(e);
                    }
                }
                for tk in chunk {
                    found.entry((*tk).to_owned()).or_default();
                }
            }
        }
        Ok(tks
            .iter()
            .map(|tk| found.get(tk).cloned().unwrap_or_default())
            .collect())
    }

    pub(crate) fn read_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
        let t = self.ready()?;
        let r = self.query(READ, &t.read_all, Vec::new());
        let mut out = Vec::new();
        for row in Fail::or_absent(r, Vec::new)? {
            if row.len() < 4 {
                return Err(malformed("attestations"));
            }
            let (Some(target), Some(k)) = (col_text(&row[0]), col_text(&row[1])) else {
                continue;
            };
            if let Some(mut e) = StoredEnvelope::from_key(target, &k) {
                match col_value(&row[2], &row[3]) {
                    Ok(b) => e.set_value(b),
                    Err(why) => e.set_error(why),
                }
                out.push(e);
            }
        }
        Ok(out)
    }

    // ---- manifests -----------------------------------------------------------------------

    pub(crate) fn manifest(&self, root: &str) -> Result<Option<StoredManifest>, StoreError> {
        if !key::is_hex_id(root) {
            return Ok(None);
        }
        if let Some(m) = self.cache().manifest(root) {
            return Ok(m);
        }
        let t = self.ready()?;
        let r = self
            .conn
            .query(READ, &t.shared.manifest, vec![V::Text(root.to_owned())]);
        let rows = Fail::or_absent(r, Vec::new)?;
        Ok(rows.first().map(|row| manifest_of(root, row, 0)))
    }

    pub(crate) fn manifests(
        &self,
        roots: &[&str],
    ) -> Result<Vec<Option<StoredManifest>>, StoreError> {
        let mut found: HashMap<String, Option<StoredManifest>> = HashMap::new();
        let mut missing: BTreeSet<&str> = BTreeSet::new();
        {
            let c = self.cache();
            for r in roots.iter().copied().filter(|r| key::is_hex_id(r)) {
                match c.manifest(r) {
                    Some(m) => {
                        found.insert(r.to_owned(), m);
                    }
                    None => {
                        missing.insert(r);
                    }
                }
            }
        }
        if !missing.is_empty() {
            let t = self.ready()?;
            let missing: Vec<&str> = missing.into_iter().collect();
            for chunk in missing.chunks(CHUNK) {
                let r = self.query(
                    READ,
                    &t.manifests_of,
                    vec![json_list(chunk.iter().copied())],
                );
                for row in Fail::or_absent(r, Vec::new)? {
                    if let Some(root) = row.first().and_then(col_text) {
                        let m = manifest_of(&root, &row, 1);
                        found.insert(root, Some(m));
                    }
                }
            }
        }
        Ok(roots
            .iter()
            .map(|r| found.get(*r).cloned().flatten())
            .collect())
    }

    /// Read these manifests and their bases into the cache in one request;
    /// the ones not stored are cached as absent.
    fn fetch_manifests(&self, t: &Tables, roots: &[String]) -> Result<(), StoreError> {
        for chunk in roots.chunks(CHUNK) {
            let r = self.query(
                READ,
                &t.manifests_and_bases,
                vec![json_list(chunk.iter().map(String::as_str))],
            );
            let rows = Fail::or_absent(r, Vec::new)?;
            let mut got: BTreeMap<String, Manifest> = BTreeMap::new();
            let mut bases: BTreeSet<String> = BTreeSet::new();
            for row in rows {
                if row.len() < 4 {
                    return Err(malformed("manifests"));
                }
                let Some(root) = col_text(&row[0]) else {
                    continue;
                };
                if let Some(b) = col_text(&row[3]) {
                    bases.insert(b);
                }
                got.insert(
                    root,
                    match col_value(&row[1], &row[2]) {
                        Ok(b) => Manifest::Bytes(b),
                        Err(why) => Manifest::Unreadable(why),
                    },
                );
            }
            let mut c = self.cache();
            for r in chunk.iter().chain(bases.iter()) {
                if !got.contains_key(r) {
                    c.set_manifest(r.clone(), Manifest::Absent);
                }
            }
            for (root, m) in got {
                c.set_manifest(root, m);
            }
        }
        Ok(())
    }

    pub(crate) fn manifest_roots(&self) -> Result<Vec<String>, StoreError> {
        let t = self.ready()?;
        let r = self.query(READ, &t.shared.manifest_roots, Vec::new());
        Ok(Fail::or_absent(r, Vec::new)?
            .iter()
            .filter_map(|row| row.first().and_then(col_text))
            .filter(|r| key::is_hex_id(r))
            .collect())
    }

    pub(crate) fn orphan_manifests(&self, roots: &[&str]) -> Result<Vec<String>, StoreError> {
        if roots.is_empty() {
            return Ok(Vec::new());
        }
        let t = self.ready()?;
        let wanted: BTreeSet<&str> = roots.iter().copied().collect();
        let r = self
            .conn
            .query(READ, &t.orphans, vec![json_list(wanted.iter().copied())]);
        let rows = match r {
            Ok(rows) => rows,
            // No tables: nothing references anything.
            Err(Fail::Absent) => return Ok(wanted.into_iter().map(str::to_owned).collect()),
            Err(Fail::Store(e)) => return Err(e),
        };
        let out: BTreeSet<String> = rows
            .iter()
            .filter_map(|row| row.first().and_then(col_text))
            .collect();
        Ok(out.into_iter().collect())
    }

    // ---- prefetch ------------------------------------------------------------------------

    pub(crate) fn prefetch(&self, what: Prefetch<'_>) -> Result<Hydration, StoreError> {
        match what {
            Prefetch::Units { test_ids, choose } => self.prefetch_units(test_ids, choose),
            Prefetch::Manifests { roots } => {
                let t = self.ready()?;
                let want: Vec<String> = {
                    let c = self.cache();
                    let set: BTreeSet<&str> = roots
                        .iter()
                        .copied()
                        .filter(|r| key::is_hex_id(r) && !c.has_stored_manifest(r))
                        .collect();
                    set.into_iter().map(str::to_owned).collect()
                };
                if !want.is_empty() {
                    let step = Step::start(KIND);
                    let n0 = self.conn.requests();
                    self.fetch_manifests(t, &want)?;
                    step.done(format_args!(
                        "prefetch {} manifest(s), {} request(s)",
                        want.len(),
                        self.conn.requests() - n0
                    ));
                }
                Ok(Hydration::default())
            }
            // Values are read with the listing that needs them (`read_all`).
            _ => Ok(Hydration::default()),
        }
    }

    /// The listings of these units (always read again), then the values
    /// `choose` picks (all without it) that are not cached, with the
    /// manifests those values reference and their bases: two requests,
    /// whatever the number of units.
    fn prefetch_units(
        &self,
        test_ids: &[&str],
        choose: Option<Choose<'_>>,
    ) -> Result<Hydration, StoreError> {
        if test_ids.is_empty() {
            return Ok(Hydration::default());
        }
        let t = self.ready()?;
        let step = Step::start(KIND);
        let n0 = self.conn.requests();
        let mut tks: Vec<String> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for id in test_ids {
            let tk = key::test_key(id);
            if seen.insert(tk.clone()) {
                tks.push(tk);
            }
        }
        // 1. The listings, from the server even when cached: a prefetch is
        // where other writers' changes are picked up.
        let mut listings: HashMap<String, Vec<StoredEnvelope>> = HashMap::new();
        {
            let all: Vec<&str> = tks.iter().map(String::as_str).collect();
            let mut listed = self.query_listings(t, &all)?;
            let mut c = self.cache();
            for tk in &tks {
                let l = listed.remove(tk.as_str()).unwrap_or_default();
                listings.insert(tk.clone(), entries(&l));
                c.refresh_listing(tk.clone(), l);
            }
        }
        // 2. The values chosen, not cached yet, with their manifests.
        let mut want: BTreeSet<String> = BTreeSet::new();
        for tk in &tks {
            let Some(l) = listings.get(tk) else {
                continue;
            };
            let picked: Vec<usize> = match choose {
                Some(f) => f(l),
                None => (0..l.len()).collect(),
            };
            for i in picked {
                if let Some(e) = l.get(i) {
                    want.insert(e.key.clone());
                }
            }
        }
        let want: Vec<&str> = {
            let c = self.cache();
            want.iter()
                .map(String::as_str)
                .filter(|k| !c.has_value(k))
                .collect()
        };
        if !want.is_empty() {
            let mut read = self.query_values(t, &want, true)?;
            let mut c = self.cache();
            for k in &want {
                match read.remove(*k) {
                    Some((v, _)) => c.set_value((*k).to_owned(), v),
                    None => c.set_value((*k).to_owned(), Value::Unreadable(GONE.to_owned())),
                }
            }
        }
        step.done(format_args!(
            "prefetch {} unit(s), {} value(s), {} request(s)",
            tks.len(),
            want.len(),
            self.conn.requests() - n0
        ));
        Ok(Hydration::default())
    }

    // ---- hints ---------------------------------------------------------------------------

    pub(crate) fn passing_on(&self, tree16: &str) -> BTreeMap<String, String> {
        if let Some(m) = self.memo_cache().get(tree16) {
            return m.clone();
        }
        let Ok(t) = self.ready() else {
            return BTreeMap::new();
        };
        let r = self
            .conn
            .query(READ, &t.shared.memo, vec![V::Text(tree16.to_owned())]);
        let rows = match r {
            Ok(rows) => rows,
            Err(Fail::Absent) => Vec::new(),
            Err(Fail::Store(_)) => return BTreeMap::new(),
        };
        let out: BTreeMap<String, String> = rows
            .iter()
            .filter_map(|row| {
                Some((
                    row.first().and_then(col_text)?,
                    row.get(1).and_then(col_text)?,
                ))
            })
            .collect();
        self.memo_cache().insert(tree16.to_owned(), out.clone());
        out
    }

    /// Every flag of the namespace, read once per handle (the probe
    /// threads ask for one each).
    pub(crate) fn flag(&self, name: &str) -> bool {
        let mut flags = self.flags();
        if flags.is_none() {
            let mut set = BTreeSet::new();
            if let Ok(t) = self.ready()
                && let Ok(rows) = self.query(READ, &t.flags_all, Vec::new())
            {
                set.extend(rows.iter().filter_map(|row| row.first().and_then(col_text)));
            }
            *flags = Some(set);
        }
        flags.as_ref().is_some_and(|s| s.contains(name))
    }

    /// Remember these memo entries (and forget those older than a week,
    /// once per handle). Never creates the tables; failures are ignored.
    pub(crate) fn remember_passing(&self, tree16: &str, items: &[(String, String)]) {
        if items.is_empty() {
            return;
        }
        let Ok(t) = self.ready() else {
            return;
        };
        if !matches!(self.version(), Ok(Some(_))) {
            return;
        }
        let at = now();
        let rows: Vec<String> = items
            .iter()
            .map(|(tk, k)| format!("({}, {}, {}, {at})", text(tree16), text(tk), text(k)))
            .collect();
        let mut stmts = vec![t.shared.upsert_memo(&rows.join(", "))];
        if !self.memo_pruned.swap(true, Ordering::Relaxed) {
            stmts.push(inline(
                &t.shared.memo_prune,
                &[(at - vci_store_sqlite::sql::MEMO_KEEP_SECS).to_string()],
            ));
        }
        if self.write(WRITE, &stmts).is_ok() {
            let mut m = self.memo_cache();
            let e = m.entry(tree16.to_owned()).or_default();
            for (tk, k) in items {
                e.insert(tk.clone(), k.clone());
            }
        }
    }

    /// Flag `name`. Never creates the tables; failures are ignored.
    pub(crate) fn set_flag(&self, name: &str) {
        let Ok(t) = self.ready() else {
            return;
        };
        if !matches!(self.version(), Ok(Some(_))) {
            return;
        }
        let sql = inline(&t.shared.flag_put, &[text(name), now().to_string()]);
        if self.write(WRITE, &[sql]).is_ok()
            && let Some(f) = self.flags().as_mut()
        {
            f.insert(name.to_owned());
        }
    }
}

/// A unit's listing as unread entries.
fn entries(listed: &[Listed]) -> Vec<StoredEnvelope> {
    listed
        .iter()
        .filter_map(|l| StoredEnvelope::from_key(l.target.clone(), &l.key))
        .collect()
}

/// The manifest in `row` (value at `at`, encoding after it).
fn manifest_of(root: &str, row: &[V], at: usize) -> StoredManifest {
    match (row.get(at), row.get(at + 1)) {
        (Some(v), Some(e)) => match col_value(v, e) {
            Ok(b) if b.is_empty() => StoredManifest::with_error(root, vci_store::EMPTY_VALUE),
            Ok(b) => StoredManifest::with_bytes(root, b),
            Err(why) => StoredManifest::with_error(root, why),
        },
        _ => StoredManifest::with_error(root, "a manifest row without its value"),
    }
}

/// `sql` with each `?N` replaced by `literals[N - 1]` (already SQL
/// literals). The statements this is used on hold no `?` in a string.
pub(crate) fn inline(sql: &str, literals: &[String]) -> String {
    let b = sql.as_bytes();
    let mut out =
        String::with_capacity(sql.len() + literals.iter().map(String::len).sum::<usize>());
    let mut i = 0;
    let mut last = 0;
    while i < b.len() {
        if b[i] == b'?' {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if let Ok(n) = sql[i + 1..j].parse::<usize>()
                && let Some(l) = n.checked_sub(1).and_then(|k| literals.get(k))
            {
                out.push_str(&sql[last..i]);
                out.push_str(l);
                last = j;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out.push_str(&sql[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inlining_parameters() {
        assert_eq!(
            inline(
                "INSERT INTO f (name, at) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
                &["'n'".into(), "7".into()]
            ),
            "INSERT INTO f (name, at) VALUES ('n', 7) ON CONFLICT DO NOTHING"
        );
        assert_eq!(
            inline("a = ?10 OR b = ?1", &["x".into()]),
            "a = ?10 OR b = x"
        );
    }

    #[test]
    fn each_namespace_has_its_own_tables() {
        let a = Tables::new("acme");
        let b = Tables::new("0123456789abcdef0123456789abcdef01234567");
        assert_ne!(a.prefix, b.prefix);
        assert!(
            a.prefix.starts_with("vci_") && a.prefix.len() == 21,
            "{}",
            a.prefix
        );
        for s in a.ddl.iter().skip(1) {
            assert!(s.contains(&a.prefix), "{s}");
        }
        assert!(a.ddl[0].contains("vci_schema"));
    }
}
