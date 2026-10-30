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
//!   [`AttestationStore::prefetch`] fills: the listings in one request,
//!   then the chosen values with their manifests and bases,
//!   [`VALUES_PER_REQUEST`] to each of the first requests (as many at once
//!   as the handle sends) and later ones sized from the answers, within two
//!   request timeouts (one more per 800 values beyond 1,600) for the handle
//!   once one ran out of time; a request that fails costs only its own
//!   keys. A miss is read the same way (the keys a JSON array bound to
//!   `json_each`).
//! * **Writes** are queued in a deferred batch ([`crate::batch`]) and sent
//!   as transactions of whole units, one request each; a write outside a
//!   batch is a batch of one.
//!
//! [`AttestationStore::prefetch`]: vci_store::AttestationStore::prefetch

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libsql::Value as V;
use vci_core::ObjectKind;
use vci_store::timing::Step;
use vci_store::{
    Choose, Columns, GONE, Hydration, MAX_OBJECTS_ANSWER, NewObject, OBJECT_GRACE, Prefetch,
    StoreError, StoreStatus, StoredEnvelope, StoredManifest, StoredObject, key, object_from_base64,
    object_kind,
};
use vci_store_sqlite::sql::{Names, Sql};

use crate::cache::{Cache, Listed, Manifest, Value};
use crate::conn::{
    Conn, Fail, HINT, KIND, Op, READ, READ_AGAIN, READ_SHARED, WRITE, col_int, col_text, col_value,
    json_list, opt_int, opt_text, text,
};

/// The newest schema version this vci reads and writes.
pub(crate) const SUPPORTED: u32 = 1;

/// Keys, test keys or roots per request.
const CHUNK: usize = 5_000;

/// Attestation values in each of the first requests of a read, each with
/// the manifest it references: about 4 MB of vex's Rails values (about 37
/// kB each stored as they are, 13 kB compressed), so that one request is
/// answered within a few seconds even on a slow link, a slow one costs
/// little of the read, and one that fails costs only its own units. Later
/// requests are sized from the answers (`next_size`). 250 (9 MB) took 6 to
/// 19 s a request from a laptop, one straggler holding up the read.
pub(crate) const VALUES_PER_REQUEST: usize = 100;

/// A read of values is given at least this many request timeouts in all
/// (`Remote::query_values`).
const VALUES_DEADLINES: u32 = 2;

/// And one more request timeout for each this many values beyond
/// `VALUES_DEADLINES` of them (about 30 MB of vex's as they are stored,
/// 1 MB/s at the default 30 s): a read of vex-api's 2,195 values (81.5 MB)
/// from a laptop took 29.9 to 58.6 s, against two timeouts' 60 s.
const VALUES_PER_DEADLINE: usize = 800;

/// The most roots a read of values names as already cached (not sent
/// again): the bases an earlier request brought.
const EXCLUDE_CAP: usize = 4_096;

/// What a request of values is sized to take, as a share of the request
/// timeout (4.5 s at the default 30 s): well within the third that lets
/// one more request go at once, and small enough that one slow answer
/// costs little of the read.
const VALUES_TARGET: f64 = 0.15;

/// The fewest values a request is sized to.
const VALUES_MIN: usize = 25;

/// The most values a request is sized to (about 15 MB of vex's as they
/// are stored, 5 MB compressed).
const VALUES_MAX: usize = 400;

/// The size of the next request of values, after one of `last` values
/// took `took`, on a link where every answer waits `wait` whatever its
/// size (`Conn::fastest`): as many as fit in what `target` leaves beyond
/// that wait (at least a third of `target`) at the pace of the time
/// beyond it, which grows with the size on a link whose bandwidth is the
/// limit; at most four times `last`, between [`VALUES_MIN`] and
/// [`VALUES_MAX`]. A draft of 2.8.2 sized them from the whole time, so
/// that with each answer held 3 s they hardly grew (vex-api's prefetch
/// sent 12 to 14 requests where 2.8.1 sent 4).
fn next_size(last: usize, took: Duration, target: Duration, wait: Duration) -> usize {
    let wait = wait.min(took).as_secs_f64();
    let beyond = (took.as_secs_f64() - wait).max(0.001);
    let room = (target.as_secs_f64() - wait).max(target.as_secs_f64() / 3.0);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let fit = (last as f64 * room / beyond).min(1e9) as usize;
    fit.min(last.saturating_mul(4))
        .clamp(VALUES_MIN, VALUES_MAX)
}

/// How long the change log keeps an entry. A replica that last synced
/// before the oldest entry kept syncs everything again.
pub(crate) const LOG_KEEP_SECS: i64 = 30 * 24 * 60 * 60;

/// How long a `gone` row (a format-3 deletion, for replicas) is kept at
/// least (STORE-V2 section 2.1): the purge horizon is the larger of this
/// and the policy's `max_ttl` ([`Remote::set_max_ttl`]), so that no record
/// a replica could still serve outlives the deletion it would have synced.
/// A replica whose cursor is older than the horizon syncs everything.
pub(crate) const GONE_KEEP_SECS: i64 = 30 * 24 * 60 * 60;

/// The kind column of a state object (`vci_store::object_kind`).
const STATE_KIND: u8 = ObjectKind::State as u8;

/// A handle's objects by id (`None`: asked for and not stored).
type ObjectCache = HashMap<String, Option<(ObjectKind, Vec<u8>)>>;

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
    values_with_bases: String,
    manifests_and_bases: String,
    manifests_of: String,
    read_units: String,
    read_all: String,
    orphans: String,
    flags_all: String,
    pub(crate) existing_keys: String,
    pub(crate) removable: String,
    pub(crate) sync: String,
    /// Whether a manifest is stored with these bytes (`?2` as they are,
    /// `?3` compressed, or NULL).
    pub(crate) manifest_same: String,
    // ---- store format 3 (STORE-V2 section 2.1) ----
    /// `<prefix>objects`: the format-3 objects, base64 text.
    pub(crate) objects: String,
    /// `<prefix>gone`: the deletions of format-3 rows and objects, for
    /// replicas (`seq`, the key or the object id, `at`).
    pub(crate) gone: String,
    /// The columns of `vci_schema` and of the attestations table, as
    /// `('s' | 'a', name)` rows: what the schema upgrade still has to add.
    column_names: String,
    /// The objects under these ids (`?1`: a JSON array): id, kind, bytes.
    get_objects: String,
    /// Which of these ids (`?1`) are stored.
    existing_objects: String,
    /// The listing columns of these keys (`?1`).
    columns: String,
    /// The orphan objects: unreferenced and put before `?1`, sorted.
    orphan_objects: String,
    /// Of these ids (`?1`), the orphans put before `?2`.
    removable_objects: String,
    /// The state objects put before `?1`.
    state_objects_before: String,
    /// The sync on a namespace with the format-3 tables: the old log's
    /// rows and, by `seq`, the attestations (`?4`: the format-3 cursor) and
    /// the `gone` rows.
    pub(crate) sync_v2: String,
    /// The namespace's version, format-3 flag and whether it holds a
    /// manifest ([`status_v2`]).
    status_v2: String,
}

const SCHEMA_DDL: &str = "CREATE TABLE IF NOT EXISTS vci_schema (
  ns          TEXT    NOT NULL PRIMARY KEY,
  prefix      TEXT    NOT NULL,
  version     INTEGER NOT NULL,
  vci_version TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  log_floor   INTEGER NOT NULL DEFAULT 0
)";

/// [`SCHEMA_DDL`] with the format-3 columns, for a database `vci_schema`
/// is first made on by a 2.9 (an existing table gets them by `ALTER
/// TABLE`, [`Tables::ddl_v2`]).
const SCHEMA_DDL_V2: &str = "CREATE TABLE IF NOT EXISTS vci_schema (
  ns          TEXT    NOT NULL PRIMARY KEY,
  prefix      TEXT    NOT NULL,
  version     INTEGER NOT NULL,
  vci_version TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  log_floor   INTEGER NOT NULL DEFAULT 0,
  v2          INTEGER NOT NULL DEFAULT 0,
  seq         INTEGER NOT NULL DEFAULT 0,
  gone_floor  INTEGER NOT NULL DEFAULT 0
)";

/// The columns the format-3 upgrade adds to `vci_schema`: `v2` (1 once
/// the namespace has the columns and tables below), `seq` (the counter
/// every write transaction takes its position from) and `gone_floor` (the
/// `seq` below which `gone` rows were purged).
const SCHEMA_V2_COLUMNS: [(&str, &str); 3] = [
    ("v2", "INTEGER NOT NULL DEFAULT 0"),
    ("seq", "INTEGER NOT NULL DEFAULT 0"),
    ("gone_floor", "INTEGER NOT NULL DEFAULT 0"),
];

/// The nullable columns the upgrade adds to the attestations table
/// ([`Columns`], and the replica's `seq`).
const ATTESTATION_V2_COLUMNS: [(&str, &str); 11] = [
    ("format", "INTEGER"),
    ("commit_id", "TEXT"),
    ("platform", "TEXT"),
    ("state", "TEXT"),
    ("duration_ms", "INTEGER"),
    ("expires", "INTEGER"),
    ("hdr", "TEXT"),
    ("tables_id", "TEXT"),
    ("shape", "TEXT"),
    ("state_obj", "TEXT"),
    ("seq", "INTEGER"),
];

/// The namespace's schema version, on a database no vci 2.9 has written
/// (`vci_schema` without the `v2` column).
const STATUS: &str = "SELECT version, log_floor FROM vci_schema WHERE ns = ?1";

/// The namespace's schema version, its format-3 flag and whether it holds
/// any manifest, in one request (`no such column` on a database no 2.9
/// has written: then [`STATUS`]); `Tables::status_v2`, since the
/// manifests table is the namespace's.
fn status_v2(manifests: &str) -> String {
    format!(
        "SELECT version, log_floor, v2, EXISTS (SELECT 1 FROM {manifests}) \
         FROM vci_schema WHERE ns = ?1"
    )
}

/// The listing columns ([`Columns`]) as the attestations table names
/// them, in the order [`Tables::column_literals`] writes them.
const COLUMN_NAMES: [&str; 10] = [
    "format",
    "commit_id",
    "platform",
    "state",
    "duration_ms",
    "expires",
    "hdr",
    "tables_id",
    "shape",
    "state_obj",
];

/// The `seq` of the transaction being written: `vci_schema.seq` after the
/// transaction's bump ([`Tables::bump_seq`]).
pub(crate) fn seq_of(ns: &str) -> String {
    format!("(SELECT seq FROM vci_schema WHERE ns = {})", text(ns))
}

impl Tables {
    /// The statement that takes the next `seq` for a transaction: every
    /// row it writes (an attestation, an object, a `gone` row) then
    /// carries [`seq_of`] the namespace, one value per transaction, so
    /// that a replica syncing `seq > cursor` sees a transaction whole or
    /// not at all.
    pub(crate) fn bump_seq(ns: &str) -> String {
        format!(
            "UPDATE vci_schema SET seq = seq + 1 WHERE ns = {}",
            text(ns)
        )
    }

    /// The DDL that brings the namespace to the format-3 layout, given
    /// the columns `vci_schema` (`schema`; `None`: it was just created
    /// with them, [`SCHEMA_DDL_V2`]) and the attestations table
    /// (`attestations`) have now (none when the table is not there yet, in
    /// which case the v1 DDL before these creates it): `ALTER TABLE ADD
    /// COLUMN` for each column missing, the `objects` and `gone` tables
    /// and the indexes (`IF NOT EXISTS`), then the namespace's row marked
    /// `v2 = 1`. Sent as a request of its own, never inside a batch
    /// (STORE-V2 section 5).
    pub(crate) fn ddl_v2(
        &self,
        schema: Option<&BTreeSet<String>>,
        attestations: &BTreeSet<String>,
        ns: &str,
        vci_version: &str,
        at: i64,
    ) -> Vec<String> {
        let (a, o, g, p) = (
            &self.names.attestations,
            &self.objects,
            &self.gone,
            &self.prefix,
        );
        let mut out = Vec::new();
        if let Some(schema) = schema {
            for (name, ty) in SCHEMA_V2_COLUMNS {
                if !schema.contains(name) {
                    out.push(format!("ALTER TABLE vci_schema ADD COLUMN {name} {ty}"));
                }
            }
        }
        for (name, ty) in ATTESTATION_V2_COLUMNS {
            if !attestations.contains(name) {
                out.push(format!("ALTER TABLE {a} ADD COLUMN {name} {ty}"));
            }
        }
        for (col, idx) in [
            ("hdr", "hdr"),
            ("tables_id", "tables"),
            ("shape", "shape"),
            ("state_obj", "state"),
        ] {
            out.push(format!(
                "CREATE INDEX IF NOT EXISTS {p}attestations_{idx} ON {a} ({col}) WHERE {col} IS NOT NULL"
            ));
        }
        out.push(format!(
            "CREATE INDEX IF NOT EXISTS {p}attestations_seq ON {a} (seq)"
        ));
        out.push(format!(
            "CREATE TABLE IF NOT EXISTS {o} (id TEXT NOT NULL PRIMARY KEY, kind INTEGER NOT NULL, \
             put_at INTEGER NOT NULL, seq INTEGER, bytes TEXT NOT NULL)"
        ));
        out.push(format!("CREATE INDEX IF NOT EXISTS {o}_seq ON {o} (seq)"));
        out.push(format!(
            "CREATE INDEX IF NOT EXISTS {o}_kind_put ON {o} (kind, put_at)"
        ));
        out.push(format!(
            "CREATE TABLE IF NOT EXISTS {g} (seq INTEGER NOT NULL, key TEXT, object TEXT, \
             at INTEGER NOT NULL)"
        ));
        out.push(format!("CREATE INDEX IF NOT EXISTS {g}_seq ON {g} (seq)"));
        out.push(format!("CREATE INDEX IF NOT EXISTS {g}_at ON {g} (at)"));
        out.push(format!(
            "INSERT INTO vci_schema (ns, prefix, version, vci_version, created_at, v2) \
             VALUES ({}, {}, {SUPPORTED}, {}, {at}, 1) ON CONFLICT (ns) DO UPDATE SET v2 = 1",
            text(ns),
            text(&self.prefix),
            text(vci_version)
        ));
        out
    }

    /// The upsert of objects, `rows` being one or more `(id, kind, put_at,
    /// seq, bytes)` literals: an id stored already keeps its bytes and its
    /// `seq` (a replica has them) and gets its `put_at` refreshed, so that
    /// the grace period counts from the latest put.
    pub(crate) fn upsert_objects(&self, rows: &str) -> String {
        let o = &self.objects;
        format!(
            "INSERT INTO {o} (id, kind, put_at, seq, bytes) VALUES {rows} \
             ON CONFLICT (id) DO UPDATE SET put_at = excluded.put_at \
             WHERE {o}.put_at < excluded.put_at"
        )
    }

    /// The statements that remove the objects `ids` (literals, joined)
    /// that are orphans as of `cut` (put before it, referenced by no
    /// attestation's columns), with a `gone` row each at `at` carrying the
    /// transaction's `seq`; the DELETE repeats the rule, so that a
    /// referrer stored between the question and the write keeps its
    /// object.
    pub(crate) fn remove_objects(&self, ids: &str, cut: i64, at: i64, ns: &str) -> Vec<String> {
        let (o, g) = (&self.objects, &self.gone);
        let rule = format!(
            "o.id IN ({ids}) AND o.put_at < {cut} AND {}",
            self.unreferenced()
        );
        vec![
            format!(
                "INSERT INTO {g} (seq, object, at) SELECT {}, o.id, {at} FROM {o} AS o WHERE {rule}",
                seq_of(ns)
            ),
            format!("DELETE FROM {o} WHERE id IN (SELECT o.id FROM {o} AS o WHERE {rule})"),
        ]
    }

    /// The statements that remove the state objects `ids` put before
    /// `cut`, referenced or not, with a `gone` row each.
    pub(crate) fn prune_state_objects(
        &self,
        ids: &str,
        cut: i64,
        at: i64,
        ns: &str,
    ) -> Vec<String> {
        let (o, g) = (&self.objects, &self.gone);
        let rule = format!("id IN ({ids}) AND kind = {STATE_KIND} AND put_at < {cut}");
        vec![
            format!(
                "INSERT INTO {g} (seq, object, at) SELECT {}, id, {at} FROM {o} WHERE {rule}",
                seq_of(ns)
            ),
            format!("DELETE FROM {o} WHERE {rule}"),
        ]
    }

    /// No attestation's columns name the object `o` (each of the four
    /// columns through its partial index).
    fn unreferenced(&self) -> String {
        let a = &self.names.attestations;
        ["hdr", "tables_id", "shape", "state_obj"]
            .iter()
            .map(|c| format!("NOT EXISTS (SELECT 1 FROM {a} WHERE {c} = o.id)"))
            .collect::<Vec<_>>()
            .join(" AND ")
    }
    /// The upsert of attestations on their slot, `rows` being one or more
    /// `(key, test_key, signer, storage_key, target, issued, tree16,
    /// manifest_ref, ref_state, stored_at, encoding, format, commit_id,
    /// platform, state, duration_ms, expires, hdr, tables_id, shape,
    /// state_obj, seq, value)` literals: the SQLite store's
    /// ([`Sql::upsert_attestations`]) with the value's encoding (as it is,
    /// or compressed), the listing columns ([`Columns`], `NULL` for a put
    /// without them) and the transaction's `seq` written too. A row is
    /// rewritten when its key, its value, its encoding or any column
    /// differs: the same bytes put with other columns is not a no-op, and
    /// the same batch applied again rewrites nothing.
    pub(crate) fn upsert_attestations(&self, rows: &str) -> String {
        let a = &self.names.attestations;
        let differs = COLUMN_NAMES
            .iter()
            .map(|c| format!("{a}.{c} IS NOT excluded.{c}"))
            .collect::<Vec<_>>()
            .join(" OR ");
        format!(
            "INSERT INTO {a} \
               (key, test_key, signer, storage_key, target, issued, tree16, manifest_ref, \
                ref_state, stored_at, encoding, format, commit_id, platform, state, \
                duration_ms, expires, hdr, tables_id, shape, state_obj, seq, value) \
             VALUES {rows} \
             ON CONFLICT (test_key, signer, storage_key) DO UPDATE SET \
               key = excluded.key, target = excluded.target, issued = excluded.issued, \
               tree16 = excluded.tree16, manifest_ref = excluded.manifest_ref, \
               ref_state = excluded.ref_state, stored_at = excluded.stored_at, \
               encoding = excluded.encoding, format = excluded.format, \
               commit_id = excluded.commit_id, platform = excluded.platform, \
               state = excluded.state, duration_ms = excluded.duration_ms, \
               expires = excluded.expires, hdr = excluded.hdr, tables_id = excluded.tables_id, \
               shape = excluded.shape, state_obj = excluded.state_obj, seq = excluded.seq, \
               value = excluded.value \
             WHERE {a}.key IS NOT excluded.key \
                OR {a}.value IS NOT excluded.value \
                OR {a}.encoding IS NOT excluded.encoding \
                OR {differs}"
        )
    }

    /// The listing columns of an attestation row as SQL literals, in the
    /// order of [`COLUMN_NAMES`] (`NULL` each for a put without them).
    pub(crate) fn column_literals(c: Option<&Columns>) -> String {
        let Some(c) = c else {
            return vec!["NULL"; COLUMN_NAMES.len()].join(", ");
        };
        [
            opt_int(c.format.map(i64::from)),
            opt_text(c.commit.as_deref()),
            opt_text(c.platform.as_deref()),
            opt_text(c.state.as_deref()),
            opt_int(c.duration_ms.and_then(|d| i64::try_from(d).ok())),
            opt_int(c.expires),
            opt_text(c.hdr.as_deref()),
            opt_text(c.tables.as_deref()),
            opt_text(c.shape.as_deref()),
            opt_text(c.state_obj.as_deref()),
        ]
        .join(", ")
    }

    /// The upsert of manifests, `rows` being one or more `(root, base,
    /// put_at, encoding, value)` literals: `put_at` and `base` are
    /// refreshed, the value and its encoding replaced, but only where one
    /// of them changes or `put_at` moves forward, so that the same batch
    /// applied again (sent again after its deadline, see `Conn::batch`)
    /// rewrites no manifest.
    pub(crate) fn upsert_manifests(&self, rows: &str) -> String {
        let m = &self.names.manifests;
        format!(
            "INSERT INTO {m} (root, base, put_at, encoding, value) VALUES {rows} \
             ON CONFLICT (root) DO UPDATE SET \
               value = excluded.value, encoding = excluded.encoding, \
               base = excluded.base, put_at = excluded.put_at \
             WHERE {m}.value IS NOT excluded.value \
                OR {m}.encoding IS NOT excluded.encoding \
                OR {m}.base IS NOT excluded.base \
                OR {m}.put_at < excluded.put_at"
        )
    }

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
        let objects = format!("{prefix}objects");
        let gone = format!("{prefix}gone");
        let (o, g) = (&objects, &gone);
        let unreferenced = ["hdr", "tables_id", "shape", "state_obj"]
            .iter()
            .map(|c| format!("NOT EXISTS (SELECT 1 FROM {a} WHERE {c} = o.id)"))
            .collect::<Vec<_>>()
            .join(" AND ");
        let columns = COLUMN_NAMES.join(", ");
        Tables {
            column_names: format!(
                "SELECT 's', name FROM pragma_table_info('vci_schema') \
                 UNION ALL SELECT 'a', name FROM pragma_table_info('{a}')"
            ),
            get_objects: format!("SELECT id, kind, bytes FROM {o} WHERE id IN ({set})"),
            existing_objects: format!("SELECT id FROM {o} WHERE id IN ({set})"),
            columns: format!("SELECT key, {columns} FROM {a} WHERE key IN ({set})"),
            orphan_objects: format!(
                "SELECT o.id FROM {o} AS o WHERE o.put_at < ?1 AND {unreferenced} ORDER BY o.id"
            ),
            removable_objects: format!(
                "SELECT o.id FROM {o} AS o WHERE o.id IN ({set}) AND o.put_at < ?2 AND {unreferenced}"
            ),
            state_objects_before: format!(
                "SELECT id FROM {o} WHERE kind = {STATE_KIND} AND put_at < ?1"
            ),
            // The sync of a namespace with the format-3 tables: the old
            // log's rows as `sync` below, nine columns each (the header
            // row (0) adds the `seq` counter and the `gone` floor), then
            // the format-3 records (a frame: the value's first byte is
            // `v`, and a frame is never compressed) whose `seq` is past
            // the format-3 cursor (5: key, target, value, encoding) and
            // the `gone` rows past it (6: key or NULL, object id or NULL,
            // at). A format-1 row this vci wrote has a `seq` too, but the
            // old log names its slot (kind 1), so kind 5 leaves it out
            // rather than send it twice. A full sync brings every
            // attestation as row kind 1 and needs neither.
            sync_v2: format!(
                "SELECT 0, {mark_then}, {mark_now}, \
                   (SELECT created_at FROM vci_schema WHERE ns = ?3), \
                   (SELECT version FROM vci_schema WHERE ns = ?3), \
                   (SELECT coalesce(max(seq), 0) FROM {log}), \
                   (SELECT log_floor FROM vci_schema WHERE ns = ?3), \
                   (SELECT seq FROM vci_schema WHERE ns = ?3), \
                   (SELECT gone_floor FROM vci_schema WHERE ns = ?3) \
                 UNION ALL \
                 SELECT 1, a.key, a.target, a.value, a.encoding, NULL, NULL, NULL, NULL FROM {a} AS a \
                   JOIN ({touched_slots}) AS l USING (test_key, signer, storage_key) WHERE ?2 = 0 \
                 UNION ALL \
                 SELECT 1, key, target, value, encoding, NULL, NULL, NULL, NULL FROM {a} WHERE ?2 = 1 \
                 UNION ALL \
                 SELECT 2, test_key || ':' || signer || ':' || storage_key, NULL, NULL, NULL, \
                   NULL, NULL, NULL, NULL FROM ({touched_slots}) WHERE ?2 = 0 \
                 UNION ALL \
                 SELECT 3, m.root, NULL, m.value, m.encoding, NULL, NULL, NULL, NULL FROM {m} AS m \
                   JOIN ({touched_roots}) AS l USING (root) WHERE ?2 = 0 \
                 UNION ALL \
                 SELECT 3, root, NULL, value, encoding, NULL, NULL, NULL, NULL FROM {m} WHERE ?2 = 1 \
                 UNION ALL \
                 SELECT 4, root, NULL, NULL, NULL, NULL, NULL, NULL, NULL FROM ({touched_roots}) WHERE ?2 = 0 \
                 UNION ALL \
                 SELECT 5, key, target, value, encoding, NULL, NULL, NULL, NULL FROM {a} \
                   WHERE ?2 = 0 AND seq > ?4 AND hex(substr(value, 1, 1)) = '76' \
                 UNION ALL \
                 SELECT 6, key, object, NULL, NULL, at, NULL, NULL, NULL FROM {g} \
                   WHERE ?2 = 0 AND seq > ?4"
            ),
            status_v2: status_v2(m),
            objects,
            gone,
            list_units: format!(
                "SELECT test_key, key, target FROM {a} WHERE test_key IN ({set}) ORDER BY test_key, key"
            ),
            // The values of these keys (?1), and when ?2 is 1, the
            // manifests they reference and those manifests' bases, but those
            // named in ?3 (cached already, or brought by another request of
            // the read), each with the name of its base: one request.
            values_with_bases: format!(
                "SELECT 0, key, value, encoding, manifest_ref FROM {a} WHERE key IN ({set}) \
                 UNION ALL \
                 SELECT 1, root, value, encoding, base FROM {m} WHERE ?2 = 1 \
                   AND root NOT IN (SELECT value FROM json_each(?3)) \
                   AND (root IN (SELECT manifest_ref FROM {a} WHERE key IN ({set})) \
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
            manifest_same: format!(
                "SELECT (encoding = 0 AND value = ?2) OR (encoding = 1 AND value IS ?3) \
                 FROM {m} WHERE root = ?1"
            ),
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
    /// `remove_manifests` keeps a root put more recently than this, and a
    /// write that supersedes an attestation removes the manifest only it
    /// referenced when that was put before this.
    pub(crate) grace: Duration,
    /// Write values compressed (`VCI_STORE_COMPRESS=zstd`).
    compress: AtomicBool,
    /// When this handle's reads of values must end, once one had a request
    /// run out of time: that read's end (`Remote::query_values`). A slow
    /// link costs a process one read's time of reading values, not that
    /// for each read (the prefetch, the plan's read of its candidates,
    /// each later round's).
    values_until: Mutex<Option<Instant>>,
    /// The time spent on write transactions that failed and the pauses
    /// before they were sent again ([`Remote::spend_on_writes`]).
    write_spent: Mutex<Duration>,
    /// The time spent writing, all writes that ended so far
    /// ([`Remote::writing_out_of_time`]).
    write_time: Mutex<Duration>,
    /// Bytes of values (as sent) of the write transactions that committed
    /// ([`Remote::stored_writes`]): each [`crate::batch::WRITE_TIME_BYTES`]
    /// of them earns the process one more request timeout of writes.
    write_stored: AtomicU64,
    /// The most bytes of values the next transaction of a write sends
    /// ([`Remote::size_writes_from`]).
    tx_bytes: AtomicUsize,
    /// The shortest time a write transaction of this handle took to commit
    /// when first sent, within its deadline: the wait every transaction
    /// has (the link, the server's answer), which does not shrink with
    /// its size ([`Remote::size_writes_from`]).
    write_fastest: Mutex<Option<Duration>>,
    /// Roots a read of values found to be bases: a later read does not
    /// bring them again while they are cached.
    bases: Mutex<BTreeSet<String>>,
    /// Whether the namespace has the format-3 columns and tables
    /// (`vci_schema.v2`, read with the schema version): 0 not asked yet,
    /// 1 no, 2 yes. "No" stands for the handle until it upgrades the
    /// namespace itself (a replica's sync tries the format-3 statement
    /// first and learns from the answer); "yes" is final.
    v2: AtomicU8,
    /// The policy's `max_ttl` in seconds ([`Remote::set_max_ttl`]): the
    /// `gone` purge horizon is the larger of it and [`GONE_KEEP_SECS`].
    max_ttl_secs: AtomicI64,
    /// The objects read or written by this handle, by id (`None`: asked
    /// for and not stored), so that a plan's `prefetch(Objects)` and its
    /// `get_objects` cost one request between them.
    objects: Mutex<ObjectCache>,
    /// Write transactions committed by this handle, and the bytes of their
    /// statements (tests of the write model).
    txs: AtomicU64,
    sql_sent: AtomicU64,
    /// Whether the namespace held a manifest when the handle read its
    /// status: 0 not known, 1 none, 2 some. A write that removes or
    /// replaces attestations collects the manifests it leaves unreferenced
    /// (2.8.2) only where one may exist: past the migration window
    /// (STORE-V2 section 5) a format-3 namespace has none, and the
    /// statements cost about 1 MB of SQL per 800-unit partition.
    manifests: AtomicU8,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn is_namespace(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/@-".contains(&b))
}

/// Whether the server refused a statement for a column it lacks (a
/// namespace no 2.9 has written, asked a format-3 question).
fn is_no_such_column(e: &StoreError) -> bool {
    e.to_string()
        .to_ascii_lowercase()
        .contains("no such column")
}

/// Whether the server refused an `ALTER TABLE ADD COLUMN` because another
/// writer added the column first.
fn is_duplicate_column(e: &StoreError) -> bool {
    e.to_string()
        .to_ascii_lowercase()
        .contains("duplicate column")
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
        compress: bool,
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
            compress: AtomicBool::new(compress),
            values_until: Mutex::new(None),
            write_spent: Mutex::new(Duration::ZERO),
            write_time: Mutex::new(Duration::ZERO),
            write_stored: AtomicU64::new(0),
            tx_bytes: AtomicUsize::new(crate::batch::TX_BYTES),
            write_fastest: Mutex::new(None),
            bases: Mutex::new(BTreeSet::new()),
            v2: AtomicU8::new(0),
            max_ttl_secs: AtomicI64::new(0),
            objects: Mutex::new(HashMap::new()),
            txs: AtomicU64::new(0),
            sql_sent: AtomicU64::new(0),
            manifests: AtomicU8::new(0),
        }
    }

    /// Whether the namespace may hold a manifest (it did when the status
    /// was read, or that is not known): a write then collects the
    /// manifests it leaves unreferenced.
    pub(crate) fn manifests_may_exist(&self) -> bool {
        self.manifests.load(Ordering::Relaxed) != 1
    }

    /// This handle writes a manifest: from now on its writes collect.
    pub(crate) fn noted_manifests(&self) {
        self.manifests.store(2, Ordering::Relaxed);
    }

    /// The policy's `max_ttl`: `gone` rows are purged after the larger of
    /// it and [`GONE_KEEP_SECS`] (STORE-V2 section 2.1).
    pub(crate) fn set_max_ttl(&self, max_ttl: Duration) {
        self.max_ttl_secs.store(
            i64::try_from(max_ttl.as_secs()).unwrap_or(i64::MAX),
            Ordering::Relaxed,
        );
    }

    /// How long `gone` rows are kept: `max(30 days, max_ttl)`.
    pub(crate) fn gone_keep_secs(&self) -> i64 {
        self.max_ttl_secs
            .load(Ordering::Relaxed)
            .max(GONE_KEEP_SECS)
    }

    /// Count a write transaction committed, of `sql` bytes of statements.
    pub(crate) fn committed(&self, sql: usize) {
        self.txs.fetch_add(1, Ordering::Relaxed);
        self.sql_sent
            .fetch_add(u64::try_from(sql).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Write transactions committed by this handle, the bytes of values and
    /// objects sent in them as literals, and the bytes of their statements
    /// in all (the literals, the keys, the SQL around them).
    pub(crate) fn written(&self) -> (u64, u64, u64) {
        (
            self.txs.load(Ordering::Relaxed),
            self.write_stored.load(Ordering::Relaxed),
            self.sql_sent.load(Ordering::Relaxed),
        )
    }

    fn objects_cache(&self) -> MutexGuard<'_, ObjectCache> {
        self.objects.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Remember objects this handle wrote (it reads its own writes).
    pub(crate) fn objects_put(&self, objects: &BTreeMap<String, (ObjectKind, Vec<u8>)>) {
        let mut c = self.objects_cache();
        for (id, (k, b)) in objects {
            c.insert(id.clone(), Some((*k, b.clone())));
        }
    }

    /// Remember that this handle removed these objects.
    fn objects_removed(&self, ids: &[String]) {
        let mut c = self.objects_cache();
        for id in ids {
            c.insert(id.clone(), None);
        }
    }

    /// Forget what this handle holds of these objects: a batch asked the
    /// server to remove them under the orphan rule, and whether each went
    /// is known to the server alone (read again when asked for).
    pub(crate) fn objects_forget(&self, ids: &[String]) {
        let mut c = self.objects_cache();
        for id in ids {
            c.remove(id);
        }
    }

    /// Whether values are written compressed.
    pub(crate) fn compress(&self) -> bool {
        self.compress.load(Ordering::Relaxed)
    }

    /// Write values compressed from now on, or not (tests).
    pub(crate) fn set_compress(&self, on: bool) {
        self.compress.store(on, Ordering::Relaxed);
    }

    fn bases(&self) -> BTreeSet<String> {
        self.bases_mut().clone()
    }

    fn bases_mut(&self) -> MutexGuard<'_, BTreeSet<String>> {
        self.bases.lock().unwrap_or_else(PoisonError::into_inner)
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

    /// A transaction of the store's batches: [`Remote::write`] sent once,
    /// asking `committed` whether the server applied it when its deadline
    /// ran out ([`Conn::batch_checked`]).
    pub(crate) fn write_checked(
        &self,
        statements: &[String],
        committed: Option<&str>,
    ) -> Result<(), Fail> {
        self.conn.batch_checked(statements, committed)
    }

    /// The time this process may spend on write transactions that failed
    /// and on the pauses before sending them again
    /// ([`crate::batch::WRITE_RETRY_DEADLINES`] request timeouts).
    fn write_retry_time(&self) -> Duration {
        self.conn
            .timeout()
            .saturating_mul(crate::batch::WRITE_RETRY_DEADLINES)
    }

    /// Count `d` against the process's time for writes that fail; whether
    /// some is left.
    pub(crate) fn spend_on_writes(&self, d: Duration) -> bool {
        let mut spent = self
            .write_spent
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *spent += d;
        *spent < self.write_retry_time()
    }

    /// The time this process may spend on writes in all: as many request
    /// timeouts as [`crate::batch::WRITE_TIME_DEADLINES`], and one more for
    /// each [`crate::batch::WRITE_TIME_BYTES`] of values its transactions
    /// stored, so that the bound follows the work a slow server still
    /// does and cuts short only one that stores less than that a timeout.
    fn write_time_budget(&self) -> Duration {
        let stored = self.write_stored.load(Ordering::Relaxed);
        let per = u64::try_from(crate::batch::WRITE_TIME_BYTES).unwrap_or(u64::MAX);
        let t = self.conn.timeout();
        t.saturating_mul(crate::batch::WRITE_TIME_DEADLINES)
            .saturating_add(t.mul_f64(stored as f64 / per as f64))
    }

    /// Count `d` (a write that ended) against the process's time for
    /// writes.
    pub(crate) fn spent_writing(&self, d: Duration) {
        *self
            .write_time
            .lock()
            .unwrap_or_else(PoisonError::into_inner) += d;
    }

    /// Count `bytes` of values (as sent) a transaction stored: they earn
    /// the process more time for writes ([`Remote::write_time_budget`]).
    pub(crate) fn stored_writes(&self, bytes: usize) {
        self.write_stored
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Whether the process has spent its time for writes, with `now` spent
    /// by the write under way: its units still queued are then lost at
    /// once ([`Remote::write_time_error`]), and so is every later write's.
    pub(crate) fn writing_out_of_time(&self, now: Duration) -> bool {
        let spent = *self
            .write_time
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        spent + now >= self.write_time_budget()
    }

    /// Why a unit was lost once the process spent its time for writes.
    pub(crate) fn write_time_error(&self) -> StoreError {
        StoreError::Timeout {
            backend: KIND,
            operation: "this process's writes (the server took them too slowly)",
            after: Duration::from_secs(self.write_time_budget().as_secs()),
        }
    }

    /// The most bytes of values the next transaction of a write sends.
    pub(crate) fn tx_bytes(&self) -> usize {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    /// Size the next transactions from the time a transaction first sent
    /// took (`took`; `out_of_time`: its deadline ran out, whether it then
    /// turned out committed or not): half as large after one out of time
    /// (down to [`crate::batch::TX_MIN_BYTES`]), twice as large again (up
    /// to [`crate::batch::TX_BYTES`]) after one that took less than a
    /// tenth of the request timeout beyond the handle's fastest. Time
    /// within the deadline does not shrink them: much of it is a wait a
    /// smaller transaction pays again (the link, the server's answer,
    /// another writer's lock), and the review of a draft that halved after
    /// a third of the timeout found it stored 122 of 600 units within the
    /// bound behind a proxy holding each answer 1.1 s at a 3 s timeout,
    /// against 503 without it.
    pub(crate) fn size_writes_from(&self, took: Duration, out_of_time: bool) {
        let t = self.conn.timeout();
        let cur = self.tx_bytes();
        let next = if out_of_time {
            (cur / 2).max(crate::batch::TX_MIN_BYTES)
        } else {
            let fastest = {
                let mut f = self
                    .write_fastest
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let v = f.map_or(took, |f| f.min(took));
                *f = Some(v);
                v
            };
            if took.saturating_sub(fastest) < t / 10 {
                cur.saturating_mul(2).min(crate::batch::TX_BYTES)
            } else {
                cur
            }
        };
        self.tx_bytes.store(next, Ordering::Relaxed);
    }

    /// The process's time for writes that fail ran out (`last` the last
    /// failure): the breaker latches, and every later call fails at once.
    pub(crate) fn writes_out_of_time(&self, last: &StoreError) -> StoreError {
        self.conn.latch_now(StoreError::unavailable(
            KIND,
            format!(
                "{}: writes kept failing ({last}), and this process spent the {:?} it may on writes that fail",
                self.conn.display(),
                self.write_retry_time()
            ),
        ))
    }

    // ---- the schema ---------------------------------------------------------------

    /// The namespace's schema version (one request, then remembered once
    /// the tables exist), or `None` when they do not exist yet. The same
    /// request reads the namespace's format-3 flag ([`Remote::v2`]),
    /// unless the database has no such column (none written by 2.9 yet),
    /// in which case the version alone is asked for, once more.
    pub(crate) fn version(&self) -> Result<Option<u32>, StoreError> {
        if let Some(&v) = self.version.get() {
            return if v > SUPPORTED {
                Err(Self::incompatible(v))
            } else {
                Ok(Some(v))
            };
        }
        let ns = self.ns()?.to_owned();
        let status_v2 = self.tables()?.status_v2.clone();
        let r = match self.query(READ, &status_v2, vec![V::Text(ns.clone())]) {
            Err(Fail::Store(e)) if is_no_such_column(&e) => {
                self.v2.store(1, Ordering::Relaxed);
                self.query(READ, STATUS, vec![V::Text(ns)])
            }
            other => other,
        };
        match Fail::or_absent(r, Vec::new)?.first() {
            Some(row) => {
                let v = row
                    .first()
                    .and_then(col_int)
                    .unwrap_or(0)
                    .clamp(0, i64::from(u32::MAX));
                if let Some(flag) = row.get(2).and_then(col_int) {
                    self.found_v2(flag >= 1);
                }
                if let Some(some) = row.get(3).and_then(col_int) {
                    self.manifests
                        .store(if some >= 1 { 2 } else { 1 }, Ordering::Relaxed);
                }
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

    /// Whether this handle found the namespace without the format-3 layout
    /// (a replica then syncs with the plain statement first).
    pub(crate) fn v2_known_no(&self) -> bool {
        self.v2.load(Ordering::Relaxed) == 1
    }

    /// Remember whether the namespace has the format-3 layout, as a sync
    /// or the status found it ("yes" is final; "no" stands until this
    /// handle upgrades the namespace).
    pub(crate) fn found_v2(&self, yes: bool) {
        if yes {
            self.v2.store(2, Ordering::Relaxed);
        } else if self.v2.load(Ordering::Relaxed) == 0 {
            self.v2.store(1, Ordering::Relaxed);
        }
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
        self.create_or_upgrade(t, true)?;
        match self.version()? {
            Some(_) => Ok(t),
            None => Err(Self::not_initialized()),
        }
    }

    fn not_initialized() -> StoreError {
        StoreError::NotInitialized {
            backend: KIND,
            advice: "the first vci run with a token allowed to create tables creates them"
                .to_owned(),
        }
    }

    /// The columns `vci_schema` and the attestations table have now (one
    /// request; a table not there yet has none).
    fn column_names(&self, t: &Tables) -> Result<(BTreeSet<String>, BTreeSet<String>), StoreError> {
        let rows = Fail::or_absent(self.query(READ, &t.column_names, Vec::new()), Vec::new)?;
        let mut schema = BTreeSet::new();
        let mut attestations = BTreeSet::new();
        for row in rows {
            if let (Some(which), Some(name)) = (
                row.first().and_then(col_text),
                row.get(1).and_then(col_text),
            ) {
                if which == "s" {
                    schema.insert(name);
                } else {
                    attestations.insert(name);
                }
            }
        }
        Ok((schema, attestations))
    }

    /// Create the namespace's tables (`fresh`: no `vci_schema` row for it),
    /// or bring existing ones to the format-3 layout (STORE-V2 section
    /// 2.1), in **one transaction of its own**, never inside a batch
    /// (section 5: a 2 to 4 MB transaction already takes a third of the
    /// request's deadline). A fresh namespace is one request: the v1 DDL
    /// (`IF NOT EXISTS`), `vci_schema` created with the format-3 columns
    /// when it is not there, every column added to the attestations table
    /// just made, the `objects` and `gone` tables, the row with `v2 = 1`.
    /// That is refused on a database whose `vci_schema` a 2.8 made (it
    /// lacks the `v2` column) or on a namespace whose tables exist without
    /// a row, and an existing namespace is upgraded, so both read the
    /// columns `vci_schema` and the attestations table have (one request)
    /// and send only what is missing ([`Tables::ddl_v2`]). Two writers
    /// upgrading at once: whoever's `ALTER TABLE` comes second is refused
    /// (`duplicate column`), reads the columns again and sends what is
    /// still missing. A token that may not create tables gets
    /// [`StoreError::NotInitialized`]; a server that takes no more writes,
    /// [`StoreError::Denied`] as for any write.
    fn create_or_upgrade(&self, t: &Tables, fresh: bool) -> Result<(), StoreError> {
        let ns = self.ns()?.to_owned();
        let all: BTreeSet<String> = BTreeSet::new();
        let mut tries = if fresh { 0 } else { 1 };
        loop {
            let stmts = if tries == 0 {
                let mut stmts = vec![SCHEMA_DDL_V2.to_owned()];
                stmts.extend(t.ddl.iter().skip(1).cloned());
                stmts.extend(t.ddl_v2(None, &all, &ns, env!("CARGO_PKG_VERSION"), now()));
                stmts
            } else {
                let (schema, attestations) = self.column_names(t)?;
                let mut stmts = t.ddl.clone();
                stmts.extend(t.ddl_v2(
                    Some(&schema),
                    &attestations,
                    &ns,
                    env!("CARGO_PKG_VERSION"),
                    now(),
                ));
                stmts
            };
            tries += 1;
            match self.write(WRITE, &stmts) {
                Ok(()) => {
                    self.v2.store(2, Ordering::Relaxed);
                    return Ok(());
                }
                // The fast path met a 2.8 database or a torn namespace, or
                // another writer added a column between the question and
                // this write: ask what is there, once more.
                Err(Fail::Store(e))
                    if tries < 3 && (is_duplicate_column(&e) || is_no_such_column(&e)) =>
                {
                    continue;
                }
                // A server that takes no more writes (blocked, full)
                // refuses this one as it would any other: the token is not
                // the reason.
                Err(Fail::Store(e)) if crate::conn::is_no_writes(&e) => return Err(e),
                Err(Fail::Store(StoreError::Denied { .. })) | Err(Fail::Absent) => {
                    return Err(Self::not_initialized());
                }
                Err(Fail::Store(e)) => return Err(e),
            }
        }
    }

    /// Whether the namespace has the format-3 columns and tables
    /// (`vci_schema.v2 = 1`): read with the schema version
    /// ([`Remote::version`], one request), or by a replica's sync. No
    /// (a namespace a 2.8 made and no 2.9 wrote) stands for the handle until
    /// it upgrades the namespace itself ([`Remote::ensure_v2`]): the reads
    /// of objects and columns then answer nothing, and a `vci run` on it
    /// upgrades it before its first transaction.
    pub(crate) fn v2(&self) -> Result<bool, StoreError> {
        if self.v2.load(Ordering::Relaxed) == 0 {
            self.version()?;
        }
        Ok(self.v2.load(Ordering::Relaxed) == 2)
    }

    /// Before a write: the namespace has the format-3 layout, upgrading it
    /// in a request of its own when it does not (2.9's first write on a
    /// namespace a 2.8 created; `vci store upgrade --begin` does the same
    /// ahead of a rollout).
    pub(crate) fn ensure_v2(&self) -> Result<(), StoreError> {
        if self.v2()? {
            return Ok(());
        }
        let t = self.ready()?;
        self.create_or_upgrade(t, false)
    }

    /// `vci store upgrade --begin`: the namespace's tables, at the format-3
    /// layout, created or upgraded in one request of their own; whether
    /// anything was sent (`false`: the namespace had the layout already).
    pub(crate) fn upgrade(&self) -> Result<bool, StoreError> {
        let t = self.ready()?;
        let fresh = self.version()?.is_none();
        if !fresh && self.v2()? {
            return Ok(false);
        }
        self.create_or_upgrade(t, fresh)?;
        self.version()?;
        Ok(true)
    }

    /// How many rows of the namespace are not format-3 records: what
    /// `vci store upgrade --finish` would have to wait for (STORE-V2
    /// section 5 step 4 refuses while one exists). Counted by the value,
    /// as the SQLite store counts: a frame is never stored compressed and
    /// starts with `v`; anything else is a format-1 row or needs the
    /// manifests. The `format` column is not trusted here: a 2.8 writer's
    /// upsert sets the key and the value alone, leaving a frame's `3`
    /// beside the format-1 value it wrote into the slot, and a frame put
    /// without columns (a copy out of git-meta) has NULL.
    pub(crate) fn format_one_rows(&self) -> Result<usize, StoreError> {
        let t = self.ready()?;
        if self.version()?.is_none() {
            return Ok(0);
        }
        let sql = if self.v2()? {
            format!(
                "SELECT count(*) FROM {} WHERE encoding <> 0 OR hex(substr(value, 1, 1)) <> '76'",
                t.names.attestations
            )
        } else {
            format!("SELECT count(*) FROM {}", t.names.attestations)
        };
        let rows = Fail::or_absent(self.query(READ, &sql, Vec::new()), Vec::new)?;
        Ok(rows
            .first()
            .and_then(|row| row.first())
            .and_then(col_int)
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(0))
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
    /// cache (the ones not stored as absent), each request bringing the
    /// manifests and bases of its own values (`Tables::values_with_bases`)
    /// but the bases already cached or brought by an answer before it was
    /// sent: no request of bases follows.
    ///
    /// The keys go [`VALUES_PER_REQUEST`] to the first requests, as many at
    /// once as the pool has connections (at most one per request), and
    /// later requests are sized from the answers: as many keys as the last
    /// answer suggests fit in [`VALUES_TARGET`] of the request timeout,
    /// beyond the wait every answer has (the handle's shortest answer,
    /// `Conn::fastest`), between [`VALUES_MIN`] and [`VALUES_MAX`], at
    /// most four times as many as the last (`next_size`). On a link with a
    /// long wait for each answer but bandwidth to spare, requests grow and
    /// few are sent; on a slow link they stay small. After each answer that took more than half of the timeout one
    /// fewer request is out at once (at least one), after each within a
    /// third one more: requests sent at once may share a slow link's
    /// bandwidth. A request that runs out of time is not sent again whole:
    /// it stops the others from being sent, and its keys are read again one
    /// request at a time, half as many to a request, a half that fails
    /// costing only its own keys; the keys never sent go at the last size.
    ///
    /// The whole read is given [`VALUES_DEADLINES`] request timeouts, one
    /// more for each [`VALUES_PER_DEADLINE`] keys beyond that many: no
    /// request runs past them, and the keys not read by then are failed.
    /// Those are the handle's for every read of values: once a read had a
    /// request run out of time, the reads after it end when it had to, so
    /// that the plan's later reads (of the candidates, and each round's)
    /// do not each wait as long again for the same slow link
    /// (`Remote::values_until`). A request that fails leaves its keys out
    /// of [`Values::found`] and in [`Values::failed`]: the others are read.
    fn query_values(&self, t: &Tables, keys: &[&str], with_manifests: bool) -> Values {
        let mut out = Values::default();
        if keys.is_empty() {
            return out;
        }
        let timeout = self.conn.timeout();
        let deadlines = u32::try_from(keys.len().div_ceil(VALUES_PER_DEADLINE))
            .unwrap_or(u32::MAX)
            .max(VALUES_DEADLINES);
        let budget = timeout.saturating_mul(deadlines);
        let earlier = *self
            .values_until
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let until = match earlier {
            Some(u) => u.min(Instant::now() + budget),
            None => Instant::now() + budget,
        };
        let out_of_time = |earlier: bool| StoreError::Timeout {
            backend: KIND,
            operation: if earlier {
                "a read of values (an earlier one ran out of this process's time for them)"
            } else {
                "a read of values (its keys not read within its time)"
            },
            after: budget,
        };
        if Instant::now() >= until {
            out.failed.extend(keys.iter().map(|k| (*k).to_owned()));
            out.error = Some(out_of_time(true));
            return out;
        }
        // Bases not to bring again: those cached already, then those an
        // answer of this read brought.
        let bases: Mutex<BTreeSet<String>> = Mutex::new(if with_manifests {
            let known = self.bases();
            let c = self.cache();
            known
                .iter()
                .filter(|b| c.has_stored_manifest(b))
                .take(EXCLUDE_CAP)
                .cloned()
                .collect()
        } else {
            BTreeSet::new()
        });
        let ask = |op: Op, chunk: &[&str]| -> Option<Rows> {
            if Instant::now() >= until {
                return None;
            }
            let exclude = {
                let b = bases.lock().unwrap_or_else(PoisonError::into_inner);
                json_list(b.iter().take(EXCLUDE_CAP).map(String::as_str))
            };
            let r = self.conn.query_until(
                op,
                &t.values_with_bases,
                vec![
                    json_list(chunk.iter().copied()),
                    V::Integer(i64::from(with_manifests)),
                    exclude,
                ],
                Some(until),
            );
            let r = Fail::or_absent(r, Vec::new);
            if let Ok(rows) = &r {
                // The bases this answer brought: a manifest row (1) whose
                // root another manifest row names as its base.
                let named: BTreeSet<&str> = rows
                    .iter()
                    .filter(|row| row.first().and_then(col_int) == Some(1))
                    .filter_map(|row| match row.get(4) {
                        Some(V::Text(b)) => Some(b.as_str()),
                        _ => None,
                    })
                    .collect();
                if !named.is_empty() {
                    let mut b = bases.lock().unwrap_or_else(PoisonError::into_inner);
                    for row in rows {
                        if row.first().and_then(col_int) == Some(1)
                            && let Some(V::Text(root)) = row.get(1)
                            && named.contains(root.as_str())
                        {
                            b.insert(root.clone());
                        }
                    }
                }
            }
            Some(r)
        };
        let is_timeout = |r: &Option<Rows>| matches!(r, Some(Err(StoreError::Timeout { .. })));
        let n = keys.len();
        let max = self.conn.max().clamp(1, n.div_ceil(VALUES_PER_REQUEST));
        // How many requests may be out at once: as many as there are
        // connections at first, one fewer after each answer that took more
        // than half the timeout, one more after each within a third.
        let allowed = AtomicUsize::new(max);
        // The next key to send, and how many keys the next request takes.
        let next: Mutex<(usize, usize)> = Mutex::new((0, VALUES_PER_REQUEST));
        // A request ran out of time (or the read's time did): no more are
        // sent at once.
        let slow = AtomicBool::new(false);
        // Each request's keys (a range of `keys`) and answer.
        let done: Mutex<Vec<(std::ops::Range<usize>, Option<Rows>)>> = Mutex::new(Vec::new());
        let target = timeout.mul_f64(VALUES_TARGET);
        std::thread::scope(|sc| {
            for w in 0..max {
                let (allowed, next, slow, done, ask) = (&allowed, &next, &slow, &done, &ask);
                sc.spawn(move || {
                    while !slow.load(Ordering::Relaxed) {
                        if w >= allowed.load(Ordering::Relaxed) {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        let range = {
                            let mut g = next.lock().unwrap_or_else(PoisonError::into_inner);
                            if g.0 >= n {
                                break;
                            }
                            let lo = g.0;
                            g.0 = (lo + g.1).min(n);
                            lo..g.0
                        };
                        let t = Instant::now();
                        // Never sent again whole after its deadline: read
                        // again in halves below.
                        let r = ask(READ_SHARED, &keys[range.clone()]);
                        let took = t.elapsed();
                        if r.is_none() || is_timeout(&r) {
                            slow.store(true, Ordering::Relaxed);
                        } else if matches!(r, Some(Ok(_))) {
                            let _ = allowed.try_update(Ordering::Relaxed, Ordering::Relaxed, |a| {
                                Some(if took < timeout / 3 {
                                    (a + 1).min(max)
                                } else if took > timeout / 2 {
                                    a.saturating_sub(1).max(1)
                                } else {
                                    a
                                })
                            });
                            // The wait for each of its requests (a
                            // statement's description first, on a
                            // connection that had none).
                            let wait = self.conn.fastest().saturating_mul(
                                u32::try_from(crate::conn::last_requests().max(1)).unwrap_or(1),
                            );
                            let sized = next_size(range.len(), took, target, wait);
                            next.lock().unwrap_or_else(PoisonError::into_inner).1 = sized;
                        }
                        done.lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push((range, r));
                    }
                });
            }
        });
        // The keys of each request (or half of one) and its answer. A
        // request that ran out of time: its keys again, one request at a
        // time, half as many to a request, each half on its own; keys never
        // sent: at the last size. One out of time now latches the breaker
        // (it was the second try), and the rest then fail at once.
        let (sent_up_to, size) = *next.lock().unwrap_or_else(PoisonError::into_inner);
        let mut answers = done.into_inner().unwrap_or_else(PoisonError::into_inner);
        answers.sort_by_key(|(r, _)| r.start);
        let mut pieces: Vec<(&[&str], Rows)> = Vec::with_capacity(answers.len() + 1);
        let mut ran_out = false;
        let mut settle = |a: Option<Rows>| -> Rows {
            ran_out |= a.is_none() || matches!(a, Some(Err(StoreError::Timeout { .. })));
            a.unwrap_or_else(|| Err(out_of_time(false)))
        };
        let unsent = &keys[sent_up_to.min(n)..];
        for (range, answer) in answers {
            let chunk = &keys[range];
            match answer {
                None => pieces.push((chunk, settle(ask(READ_AGAIN, chunk)))),
                Some(Err(StoreError::Timeout { .. })) => {
                    for half in chunk.chunks(chunk.len().div_ceil(2).max(1)) {
                        pieces.push((half, settle(ask(READ_AGAIN, half))));
                    }
                }
                Some(other) => pieces.push((chunk, other)),
            }
        }
        for chunk in unsent.chunks(size.max(1)) {
            pieces.push((chunk, settle(ask(READ_AGAIN, chunk))));
        }
        if ran_out {
            let mut u = self
                .values_until
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *u = Some(u.map_or(until, |e| e.min(until)));
        }
        let mut manifests: BTreeMap<String, Manifest> = BTreeMap::new();
        let mut named_bases: BTreeSet<String> = BTreeSet::new();
        // Every manifest an answer brought.
        let mut brought: BTreeSet<String> = BTreeSet::new();
        let mut refs: BTreeSet<String> = BTreeSet::new();
        for (piece, answer) in pieces {
            let rows = match answer {
                Ok(rows) => rows,
                Err(e) => {
                    out.failed.extend(piece.iter().map(|k| (*k).to_owned()));
                    out.error.get_or_insert(e);
                    continue;
                }
            };
            for row in rows {
                if row.len() < 5 {
                    out.failed.extend(piece.iter().map(|k| (*k).to_owned()));
                    out.error.get_or_insert_with(|| malformed("values"));
                    break;
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
                    out.found.insert(name, (v, extra));
                } else {
                    if let Some(b) = extra {
                        named_bases.insert(b);
                    }
                    brought.insert(name.clone());
                    manifests.insert(
                        name,
                        match v {
                            Value::Bytes(b) => Manifest::Bytes(b),
                            Value::Unreadable(why) => Manifest::Unreadable(why),
                        },
                    );
                }
            }
        }
        // A request cut short by a malformed row: none of its keys count.
        for k in &out.failed {
            out.found.remove(k);
        }
        if with_manifests {
            let mut c = self.cache();
            for r in &refs {
                if !manifests.contains_key(r) && !c.has_stored_manifest(r) {
                    c.set_manifest(r.clone(), Manifest::Absent);
                }
            }
            for (root, m) in manifests {
                c.set_manifest(root, m);
            }
            // A base the answers named and that is neither cached nor among
            // them was not stored (a request brings every base it names
            // but those cached or brought already).
            let excluded = bases.lock().unwrap_or_else(PoisonError::into_inner);
            for b in &named_bases {
                if !excluded.contains(b) && !brought.contains(b) && c.manifest(b).is_none() {
                    c.set_manifest(b.clone(), Manifest::Absent);
                }
            }
            drop(excluded);
            drop(c);
            self.bases_mut().extend(named_bases);
        }
        out
    }

    /// Whether this handle's time for reading values ran out
    /// (`Remote::values_until`).
    fn values_out_of_time(&self) -> bool {
        self.values_until
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some_and(|u| Instant::now() >= u)
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
        let served = misses.len() < envs.len();
        // Values that cannot be read now read as such (their units run),
        // unless none could be served at all: then the call fails, as a
        // store that cannot be used does.
        let fail = |envs: &mut [&mut StoredEnvelope], misses: &[usize], e: StoreError| {
            if !served {
                return Err(e);
            }
            let why = format!("could not be read from the store: {e}");
            for &i in misses {
                envs[i].set_error(why.clone());
            }
            Ok(())
        };
        let t = match self.ready() {
            Ok(t) => t,
            Err(e) => return fail(envs, &misses, e),
        };
        let step = Step::start(KIND);
        let (n0, b0) = (self.conn.requests(), self.conn.received());
        let keys: BTreeSet<String> = misses.iter().map(|&i| envs[i].key.clone()).collect();
        let n = keys.len();
        // Whoever reads a value verifies it next, which reads the manifest
        // it references and that manifest's base: they come with it.
        let read = {
            let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
            self.query_values(t, &keys, true)
        };
        let mut read = read;
        if read.found.is_empty()
            && !served
            && let Some(e) = read.error.take()
        {
            return Err(e);
        }
        let why = read
            .error
            .as_ref()
            .map(|e| format!("could not be read from the store: {e}"));
        for &i in &misses {
            match read.found.get(&envs[i].key) {
                Some((v, _)) => v.clone().apply(envs[i]),
                None if read.failed.contains(&envs[i].key) => {
                    envs[i].set_error(why.clone().unwrap_or_default());
                }
                None => envs[i].set_error(GONE),
            }
        }
        step.done(format_args!(
            "read {n} value(s), {} request(s), {}",
            self.conn.requests() - n0,
            megabytes(self.conn.received() - b0)
        ));
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

    // ---- objects and columns (store format 3) ----------------------------------------

    /// Read the objects under `ids` not cached yet into the cache (one
    /// request per [`CHUNK`] ids; a text that is not an object's base64
    /// is cached as not stored). Stops as [`StoreError::Invalid`]
    /// (`objects`) once the objects decoded in this call pass
    /// [`MAX_OBJECTS_ANSWER`].
    fn fetch_objects(&self, ids: &[&str]) -> Result<(), StoreError> {
        let want: Vec<&str> = {
            let c = self.objects_cache();
            let mut seen = BTreeSet::new();
            ids.iter()
                .copied()
                .filter(|id| !c.contains_key(*id) && seen.insert(*id))
                .collect()
        };
        if want.is_empty() {
            return Ok(());
        }
        let t = self.ready()?;
        let step = Step::start(KIND);
        let (n0, b0) = (self.conn.requests(), self.conn.received());
        let mut total = 0usize;
        for chunk in want.chunks(CHUNK) {
            let r = self.query(READ, &t.get_objects, vec![json_list(chunk.iter().copied())]);
            let rows = Fail::or_absent(r, Vec::new)?;
            let mut got: HashMap<String, Option<(ObjectKind, Vec<u8>)>> = HashMap::new();
            for row in rows {
                if row.len() < 3 {
                    return Err(malformed("objects"));
                }
                let Some(id) = col_text(&row[0]) else {
                    continue;
                };
                let kind = col_int(&row[1])
                    .and_then(|k| u8::try_from(k).ok())
                    .and_then(object_kind);
                let bytes = match &row[2] {
                    V::Text(s) => object_from_base64(s).ok(),
                    V::Blob(b) => Some(b.clone()),
                    _ => None,
                };
                let value = match (kind, bytes) {
                    (Some(k), Some(b)) => {
                        total = total.saturating_add(b.len());
                        if total > MAX_OBJECTS_ANSWER {
                            return Err(StoreError::invalid(
                                "objects",
                                &format!("{} ids", want.len()),
                                "would answer more than 64 MiB of objects",
                            ));
                        }
                        Some((k, b))
                    }
                    _ => None,
                };
                got.insert(id, value);
            }
            let mut c = self.objects_cache();
            for id in chunk {
                let v = got.remove(*id).flatten();
                c.insert((*id).to_owned(), v);
            }
        }
        step.done(format_args!(
            "read {} object(s), {} request(s), {}",
            want.len(),
            self.conn.requests() - n0,
            megabytes(self.conn.received() - b0)
        ));
        Ok(())
    }

    /// The objects under `ids` in the order asked, those not stored left
    /// out and a repeated id answered once (section 4, "Objects and
    /// columns"): from the cache (a `prefetch(Objects)`, or this handle's
    /// own writes), the rest in one request. Each id answered leaves the
    /// cache, as a value read does (`read_values`): the next call asks the
    /// server again, so that another writer's removal is seen.
    pub(crate) fn get_objects(&self, ids: &[&str]) -> Result<Vec<StoredObject>, StoreError> {
        for id in ids {
            key::check_object_id(id)?;
        }
        self.fetch_objects(ids)?;
        let mut c = self.objects_cache();
        let mut seen = BTreeSet::new();
        let mut total = 0usize;
        let mut out = Vec::new();
        for id in ids {
            if !seen.insert(*id) {
                continue;
            }
            if let Some(Some((kind, bytes))) = c.remove(*id) {
                total = total.saturating_add(bytes.len());
                if total > MAX_OBJECTS_ANSWER {
                    return Err(StoreError::invalid(
                        "objects",
                        &format!("{} ids", ids.len()),
                        "would answer more than 64 MiB of objects",
                    ));
                }
                out.push(StoredObject {
                    id: (*id).to_owned(),
                    kind,
                    bytes,
                });
            }
        }
        Ok(out)
    }

    /// Store `objects` now, in one transaction (a batch of one); how many
    /// were not stored before (one request asks).
    pub(crate) fn put_objects_now(
        &self,
        objects: &[NewObject<'_>],
        after: Option<&crate::batch::After>,
    ) -> Result<usize, StoreError> {
        let queued = crate::batch::queue_objects(self, objects)?;
        if queued.is_empty() {
            return Ok(0);
        }
        let t = self.ready()?;
        let existing: BTreeSet<String> = if self.version()?.is_some() && self.v2()? {
            let r = self.query(
                READ,
                &t.existing_objects,
                vec![json_list(queued.keys().map(String::as_str))],
            );
            Fail::or_absent(r, Vec::new)?
                .iter()
                .filter_map(|row| row.first().and_then(col_text))
                .collect()
        } else {
            BTreeSet::new()
        };
        let new = queued.keys().filter(|id| !existing.contains(*id)).count();
        let mut p = crate::batch::Pending::with_after(after.cloned());
        p.objects = queued;
        p.recount();
        crate::batch::write(self, p)?;
        Ok(new)
    }

    /// The orphans among `ids` as of `cut`, from the server (one request).
    fn removable_objects(&self, ids: &[&str], cut: i64) -> Result<Vec<String>, StoreError> {
        let t = self.ready()?;
        if self.version()?.is_none() || !self.v2()? {
            return Ok(Vec::new());
        }
        let wanted: BTreeSet<&str> = ids.iter().copied().collect();
        let r = self.query(
            READ,
            &t.removable_objects,
            vec![json_list(wanted.iter().copied()), V::Integer(cut)],
        );
        Ok(Fail::or_absent(r, Vec::new)?
            .iter()
            .filter_map(|row| row.first().and_then(col_text))
            .collect())
    }

    /// Remove the objects among `ids` that are orphans (the rule of
    /// section 4: referenced by no attestation's columns, put more than
    /// [`OBJECT_GRACE`] ago), except `keep` (an open batch's own objects,
    /// which the server does not hold yet or whose grace it refreshes at
    /// finish); how many were removed. One request asks, one removes
    /// (with a `gone` row each), within the process's time for writes.
    pub(crate) fn remove_objects_now(
        &self,
        ids: &[&str],
        keep: &BTreeSet<String>,
    ) -> Result<usize, StoreError> {
        for id in ids {
            key::check_object_id(id)?;
        }
        let ids: Vec<&str> = ids.iter().copied().filter(|i| !keep.contains(*i)).collect();
        if ids.is_empty() {
            return Ok(0);
        }
        if self.writing_out_of_time(Duration::ZERO) {
            return Err(self.write_time_error());
        }
        let cut = now().saturating_sub(i64::try_from(OBJECT_GRACE.as_secs()).unwrap_or(i64::MAX));
        let found = self.removable_objects(&ids, cut)?;
        if found.is_empty() {
            return Ok(0);
        }
        let t = self.ready()?;
        let ns = self.ns()?.to_owned();
        let list = found.iter().map(|r| text(r)).collect::<Vec<_>>().join(", ");
        let mut stmts = vec![Tables::bump_seq(&ns)];
        stmts.extend(t.remove_objects(&list, cut, now(), &ns));
        let began = Instant::now();
        let r = self.write(WRITE, &stmts);
        self.spent_writing(began.elapsed());
        match r {
            Ok(()) | Err(Fail::Absent) => {}
            Err(Fail::Store(e)) => return Err(e),
        }
        self.objects_removed(&found);
        Ok(found.len())
    }

    /// Every orphan object's id, sorted (one request; none on a namespace
    /// without the format-3 tables).
    pub(crate) fn orphan_objects(&self) -> Result<Vec<String>, StoreError> {
        let t = self.ready()?;
        if self.version()?.is_none() || !self.v2()? {
            return Ok(Vec::new());
        }
        let cut = now().saturating_sub(i64::try_from(OBJECT_GRACE.as_secs()).unwrap_or(i64::MAX));
        let r = self.query(READ, &t.orphan_objects, vec![V::Integer(cut)]);
        Ok(Fail::or_absent(r, Vec::new)?
            .iter()
            .filter_map(|row| row.first().and_then(col_text))
            .collect())
    }

    /// Remove every state object put more than `older_than` ago,
    /// referenced or not (one request asks, one removes with a `gone` row
    /// each); how many.
    pub(crate) fn prune_state_objects(&self, older_than: Duration) -> Result<usize, StoreError> {
        let t = self.ready()?;
        if self.version()?.is_none() || !self.v2()? {
            return Ok(0);
        }
        if self.writing_out_of_time(Duration::ZERO) {
            return Err(self.write_time_error());
        }
        let cut = now().saturating_sub(i64::try_from(older_than.as_secs()).unwrap_or(i64::MAX));
        let r = self.query(READ, &t.state_objects_before, vec![V::Integer(cut)]);
        let found: Vec<String> = Fail::or_absent(r, Vec::new)?
            .iter()
            .filter_map(|row| row.first().and_then(col_text))
            .collect();
        if found.is_empty() {
            return Ok(0);
        }
        let ns = self.ns()?.to_owned();
        let list = found.iter().map(|r| text(r)).collect::<Vec<_>>().join(", ");
        let mut stmts = vec![Tables::bump_seq(&ns)];
        stmts.extend(t.prune_state_objects(&list, cut, now(), &ns));
        let began = Instant::now();
        let r = self.write(WRITE, &stmts);
        self.spent_writing(began.elapsed());
        match r {
            Ok(()) | Err(Fail::Absent) => {}
            Err(Fail::Store(e)) => return Err(e),
        }
        self.objects_removed(&found);
        Ok(found.len())
    }

    /// The listing columns of these records, one per entry in order
    /// (section 4): what an open batch on this thread queued for a key,
    /// else the server's (one request per [`CHUNK`] keys), none for a key
    /// not stored, a format-1 row, or a namespace without the columns.
    pub(crate) fn columns(&self, envs: &[&StoredEnvelope]) -> Result<Vec<Columns>, StoreError> {
        let mut out: Vec<Option<Columns>> = Vec::with_capacity(envs.len());
        let mut ask: BTreeSet<&str> = BTreeSet::new();
        for e in envs {
            let queued = crate::batch::queued_columns(self, &e.key);
            if queued.is_none() {
                ask.insert(e.key.as_str());
            }
            out.push(queued);
        }
        let mut found: HashMap<String, Columns> = HashMap::new();
        if !ask.is_empty() {
            let t = self.ready()?;
            if self.version()?.is_some() && self.v2()? {
                let ask: Vec<&str> = ask.into_iter().collect();
                for chunk in ask.chunks(CHUNK) {
                    let r = self.query(READ, &t.columns, vec![json_list(chunk.iter().copied())]);
                    for row in Fail::or_absent(r, Vec::new)? {
                        if row.len() < 11 {
                            return Err(malformed("attestations"));
                        }
                        let Some(k) = col_text(&row[0]) else {
                            continue;
                        };
                        let int = |i: usize| col_int(&row[i]);
                        let txt = |i: usize| col_text(&row[i]);
                        found.insert(
                            k,
                            Columns {
                                format: int(1).and_then(|v| u8::try_from(v).ok()),
                                commit: txt(2),
                                platform: txt(3),
                                state: txt(4),
                                duration_ms: int(5).and_then(|v| u64::try_from(v).ok()),
                                expires: int(6),
                                hdr: txt(7),
                                tables: txt(8),
                                shape: txt(9),
                                state_obj: txt(10),
                            },
                        );
                    }
                }
            }
        }
        Ok(out
            .into_iter()
            .zip(envs)
            .map(|(queued, e)| {
                queued.unwrap_or_else(|| found.get(&e.key).cloned().unwrap_or_default())
            })
            .collect())
    }

    // ---- prefetch ------------------------------------------------------------------------

    pub(crate) fn prefetch(&self, what: Prefetch<'_>) -> Result<Hydration, StoreError> {
        match what {
            Prefetch::Objects { ids } => {
                for id in ids {
                    key::check_object_id(id)?;
                }
                self.fetch_objects(ids)?;
                Ok(Hydration::default())
            }
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
        let (n0, b0) = (self.conn.requests(), self.conn.received());
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
        // A request that failed leaves its values uncached, to be read
        // again when they are asked for (`read_values`, which marks only
        // the ones that fail again as unreadable), and says so; the rest
        // is read. One that ran out of time used up the handle's time for
        // values: asked for, they fail at once, and their units run.
        let mut h = Hydration::default();
        if !want.is_empty() {
            let mut read = self.query_values(t, &want, true);
            let mut c = self.cache();
            for k in &want {
                match read.found.remove(*k) {
                    Some((v, _)) => c.set_value((*k).to_owned(), v),
                    None if read.failed.contains(*k) => {}
                    None => c.set_value((*k).to_owned(), Value::Unreadable(GONE.to_owned())),
                }
            }
            if let Some(e) = read.error {
                h.unresolved = read.failed.len();
                let then = if self.values_out_of_time() {
                    "their units run"
                } else {
                    "they are read again when asked for"
                };
                eprintln!(
                    "vci: warning: could not prefetch {} stored value(s) from {}: {e}; {then}",
                    read.failed.len(),
                    self.location(false)
                );
            }
        }
        step.done(format_args!(
            "prefetch {} unit(s), {} value(s), {} request(s), {}",
            tks.len(),
            want.len(),
            self.conn.requests() - n0,
            megabytes(self.conn.received() - b0)
        ));
        Ok(h)
    }

    /// Have the statements a plan's reads use (the listing, the values)
    /// described ahead on every connection of the pool
    /// ([`Conn::describe_ahead`]); the store's warm-up does it.
    pub(crate) fn describe_ahead(&self) {
        if let Ok(t) = self.ready() {
            self.conn
                .describe_ahead(&[t.list_units.as_str(), t.values_with_bases.as_str()]);
        }
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
    /// Only the entries the server does not hold already are written (a
    /// second plan of the same tree, which `passing_on` read, writes
    /// none), as a hint: given at most [`HINT_TIMEOUT`] behind other
    /// writers, never sent again after it, never latching the breaker.
    ///
    /// [`HINT_TIMEOUT`]: crate::conn::HINT_TIMEOUT
    pub(crate) fn remember_passing(&self, tree16: &str, items: &[(String, String)]) {
        if items.is_empty() {
            return;
        }
        let known = self.passing_on(tree16);
        let items: Vec<&(String, String)> = items
            .iter()
            .filter(|(tk, k)| known.get(tk) != Some(k))
            .collect();
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
        if self.write(HINT, &stmts).is_ok() {
            let mut m = self.memo_cache();
            let e = m.entry(tree16.to_owned()).or_default();
            for (tk, k) in items {
                e.insert(tk.clone(), k.clone());
            }
        }
    }

    /// Flag `name`, as a hint (see [`Remote::remember_passing`]): nothing
    /// is sent when the flags read once per handle hold it already. Never
    /// creates the tables; failures are ignored.
    pub(crate) fn set_flag(&self, name: &str) {
        if self.flag(name) {
            return;
        }
        let Ok(t) = self.ready() else {
            return;
        };
        if !matches!(self.version(), Ok(Some(_))) {
            return;
        }
        let sql = inline(&t.shared.flag_put, &[text(name), now().to_string()]);
        if self.write(HINT, &[sql]).is_ok()
            && let Some(f) = self.flags().as_mut()
        {
            f.insert(name.to_owned());
        }
    }
}

/// The rows of one request, or why there are none.
type Rows = Result<Vec<Vec<V>>, StoreError>;

/// What [`Remote::query_values`] read.
#[derive(Default)]
struct Values {
    /// Key -> its value and the manifest it references.
    found: HashMap<String, (Value, Option<String>)>,
    /// The keys whose request failed.
    failed: BTreeSet<String>,
    /// Why (the first failure).
    error: Option<StoreError>,
}

/// `bytes` as the timing lines show them.
pub(crate) fn megabytes(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let mb = bytes as f64 / 1e6;
    format!("{mb:.1} MB")
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
