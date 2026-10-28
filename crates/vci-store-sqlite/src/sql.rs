//! The SQL of schema version 1, its format-3 additions (vci 2.9, STORE-V2
//! section 2.1) and schema version 2: the tables and the statements this
//! crate runs, for its own file and for the libSQL store
//! (`vci-store-libsql`), whose server keeps one set of these tables per
//! namespace under a name prefix ([`Names::prefixed`]). One copy of the SQL
//! serves both: the libSQL store adds only what a server needs on top
//! (set-based reads and writes, a schema version per namespace, a change
//! log for replicas).
//!
//! Every text column compares with SQLite's default `BINARY` collation,
//! which is bytewise, as the store's order requires. `value` is each
//! table's last column as created, so reads of the other columns never
//! touch the value's overflow pages; the format-3 columns are added behind
//! it by `ALTER TABLE` ([`Sql::add_column`]), and a row that carries them
//! is a frame of about 2 KB, which overflows no page.
//!
//! The format-3 additions ([`Sql::ddl_v2`], [`COLUMNS_V2`]) are nullable
//! columns on the attestations table (`NULL` on a format-1 row), the
//! `objects` table and its indexes. There is no `gone` table and no `seq`
//! column in a SQLite file: nothing syncs from it (the design lists them
//! for the stores with replicas). Schema version 2 is version 1 with the
//! additions and without the `manifests` table (`vci store upgrade
//! --finish`, [`Sql::drop_manifests`]).

use std::sync::LazyLock;

/// `ref_state` of a row whose value's `manifestRef` is unknown (the value
/// does not parse as a vci envelope).
pub const REF_UNKNOWN: i64 = 0;
/// `ref_state` of a row whose value names a stored manifest (`manifest_ref`).
pub const REF_ROOT: i64 = 1;
/// `ref_state` of a row whose value carries its manifest inline.
pub const REF_INLINE: i64 = 2;

/// How long the memo keeps what a plan remembered: a week of trees.
pub const MEMO_KEEP_SECS: i64 = 7 * 24 * 60 * 60;

/// The format-3 columns of the attestations table (STORE-V2 section 2.1),
/// each `(name, type)`, in the order [`Sql::columns`] selects them and the
/// upserts take them: the record's format, the commit, the platform, the
/// result state (text, as [`vci_store::Columns::state`] is), the duration,
/// the expiry, and the hdr, tables, shape and state object ids (64 hex,
/// text, so they index as text). All nullable: `NULL` on a format-1 row
/// and on a record put without columns.
pub const COLUMNS_V2: [(&str, &str); 10] = [
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
];

/// The kind column of a state object (`vci_core::ObjectKind::State as u8`).
pub const KIND_STATE: i64 = 4;

/// The table names of one store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    /// Attestations: one row per (unit, signer, storage key) slot.
    pub attestations: String,
    /// Input manifests, by root.
    pub manifests: String,
    /// The memo of attestations that passed on a tree.
    pub memo: String,
    /// The flags.
    pub flags: String,
    /// The format-3 objects, by id (vci 2.9).
    pub objects: String,
    /// What index names start with.
    prefix: String,
}

impl Names {
    /// The names of a SQLite store file: `attestations`, `manifests`,
    /// `memo`, `flags`, `objects`.
    pub fn plain() -> Names {
        Names::prefixed("")
    }

    /// The names with `prefix` in front of each table and index name.
    ///
    /// # Panics
    ///
    /// When `prefix` holds anything but lowercase letters, digits and `_`
    /// (the names are not quoted).
    pub fn prefixed(prefix: &str) -> Names {
        assert!(
            prefix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "a table name prefix of lowercase letters, digits and `_`"
        );
        Names {
            attestations: format!("{prefix}attestations"),
            manifests: format!("{prefix}manifests"),
            memo: format!("{prefix}memo"),
            flags: format!("{prefix}flags"),
            objects: format!("{prefix}objects"),
            prefix: prefix.to_owned(),
        }
    }
}

/// The statements of schema version 1 over one set of [`Names`].
#[derive(Debug, Clone)]
pub struct Sql {
    /// Every table and index, each created only when missing.
    pub ddl: String,
    /// One unit's keys and targets (`?1`: test key), sorted by key.
    pub list_unit: String,
    /// Every key and target, sorted by (target, key).
    pub list_all: String,
    /// One attestation's value and encoding (`?1`: key).
    pub value: String,
    /// One manifest's value and encoding (`?1`: root).
    pub manifest: String,
    /// Every manifest root, sorted.
    pub manifest_roots: String,
    /// Every key (for a count of the keys of vci's shape).
    pub keys: String,
    /// Whether some attestation's manifest reference is unknown (`?1`: the
    /// unknown `ref_state`).
    pub ref_unknown: String,
    /// Whether some attestation references a root (`?1`: root).
    pub ref_exists: String,
    /// The memo of one tree (`?1`: tree16): test key, attestation key.
    pub memo: String,
    /// Whether a flag is set (`?1`: name).
    pub flag: String,
    /// The upsert of an attestation under a hinted key (`?1` key, `?2` test
    /// key, `?3` signer, `?4` storage key, `?5` target, `?6` issued, `?7`
    /// tree16, `?8` manifest ref, `?9` ref state, `?10` stored at, `?11`
    /// value, `?12` to `?21` the [`COLUMNS_V2`] in order), returning the
    /// key when a row changed.
    pub put_hinted: String,
    /// The same without a hint (`?1` plain key, `?2` to `?5` as above, `?6`
    /// manifest ref, `?7` ref state, `?8` stored at, `?9` value, `?10` to
    /// `?19` the columns): the slot keeps its key.
    pub put_plain: String,
    /// The key a slot is stored under (`?1` test key, `?2` signer, `?3`
    /// storage key).
    pub slot_key: String,
    /// Whether a manifest holds exactly these bytes, readable (`?1` root,
    /// `?2` bytes).
    pub manifest_same: String,
    /// Refresh a manifest's `put_at` (`?1` root, `?2` now).
    pub manifest_touch: String,
    /// The upsert of a manifest (`?1` root, `?2` base, `?3` now, `?4`
    /// bytes).
    pub manifest_upsert: String,
    /// Delete one attestation (`?1`: key).
    pub remove: String,
    /// Delete a manifest no attestation references and no manifest uses as
    /// its base (`?1`: root).
    pub remove_manifest: String,
    /// Remember one memo entry (`?1` tree16, `?2` test key, `?3` key, `?4`
    /// now).
    pub memo_put: String,
    /// Forget memo entries older than `?1`.
    pub memo_prune: String,
    /// Set a flag (`?1` name, `?2` now).
    pub flag_put: String,
    /// The format-3 additions that are not columns: the `objects` table,
    /// its index and the partial indexes on the object-id columns, each
    /// created only when missing. The columns go first, with
    /// [`Sql::add_column`] for each of [`COLUMNS_V2`] the table lacks
    /// (`ALTER TABLE ADD COLUMN` is not `IF NOT EXISTS`).
    pub ddl_v2: String,
    /// One record's format-3 columns, in [`COLUMNS_V2`] order (`?1`: key).
    pub columns: String,
    /// One object's kind and bytes (`?1`: id).
    pub object: String,
    /// One object's kind and size, bytes not read (`?1`: id).
    pub object_size: String,
    /// Refresh an object's `put_at` (`?1` id, `?2` now): a changed row
    /// means the object was stored already.
    pub object_touch: String,
    /// Store an object that is not stored (`?1` id, `?2` kind, `?3` now,
    /// `?4` bytes).
    pub object_insert: String,
    /// Delete one object under the orphan rule (`?1` id, `?2` the oldest
    /// `put_at` still within the grace): only when no attestation's `hdr`,
    /// `tables_id`, `shape` or `state_obj` column names it and it was put
    /// before `?2`.
    pub object_remove: String,
    /// The ids [`Sql::object_remove`] would delete now, sorted (`?1` as
    /// there).
    pub orphan_objects: String,
    /// Delete every state object put before `?1`, referenced or not.
    pub prune_state_objects: String,
    /// How many attestations are not format-3 frames (their value does not
    /// start with `v`): what `vci store upgrade --finish` refuses on.
    pub format_one_count: String,
    /// Drop the manifests table (`--finish`).
    pub drop_manifests: String,
    /// The table names (for statements built from rows,
    /// [`Sql::upsert_attestations`] and [`Sql::upsert_manifests`], and
    /// [`Sql::add_column`]).
    names: Names,
}

impl Sql {
    /// The statements over `n`.
    pub fn new(n: &Names) -> Sql {
        let (a, m, memo, flags, p) = (&n.attestations, &n.manifests, &n.memo, &n.flags, &n.prefix);
        let o = &n.objects;
        let referenced = format!(
            "EXISTS (SELECT 1 FROM {a} WHERE hdr = {o}.id OR tables_id = {o}.id
                                       OR shape = {o}.id OR state_obj = {o}.id)"
        );
        Sql {
            ddl: format!(
                "
CREATE TABLE IF NOT EXISTS {a} (
  key          TEXT    NOT NULL PRIMARY KEY,
  test_key     TEXT    NOT NULL,
  signer       TEXT    NOT NULL,
  storage_key  TEXT    NOT NULL,
  target       TEXT    NOT NULL,
  issued       INTEGER,
  tree16       TEXT,
  manifest_ref TEXT,
  ref_state    INTEGER NOT NULL,
  stored_at    INTEGER NOT NULL,
  encoding     INTEGER NOT NULL DEFAULT 0,
  value        BLOB    NOT NULL,
  UNIQUE (test_key, signer, storage_key)
);
CREATE INDEX IF NOT EXISTS {p}attestations_unit ON {a} (test_key, key, target);
CREATE INDEX IF NOT EXISTS {p}attestations_all  ON {a} (target, key);
CREATE INDEX IF NOT EXISTS {p}attestations_ref  ON {a} (manifest_ref) WHERE manifest_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS {p}attestations_unknown_ref ON {a} (ref_state) WHERE ref_state = 0;
CREATE TABLE IF NOT EXISTS {m} (
  root     TEXT    NOT NULL PRIMARY KEY,
  base     TEXT,
  put_at   INTEGER NOT NULL,
  encoding INTEGER NOT NULL DEFAULT 0,
  value    BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS {p}manifests_base ON {m} (base) WHERE base IS NOT NULL;
CREATE TABLE IF NOT EXISTS {memo}  (tree16 TEXT NOT NULL, test_key TEXT NOT NULL, key TEXT NOT NULL, at INTEGER NOT NULL,
                    PRIMARY KEY (tree16, test_key)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS {flags} (name TEXT NOT NULL PRIMARY KEY, at INTEGER NOT NULL) WITHOUT ROWID;
"
            ),
            list_unit: format!("SELECT key, target FROM {a} WHERE test_key = ?1 ORDER BY key"),
            list_all: format!("SELECT key, target FROM {a} ORDER BY target, key"),
            value: format!("SELECT value, encoding FROM {a} WHERE key = ?1"),
            manifest: format!("SELECT value, encoding FROM {m} WHERE root = ?1"),
            manifest_roots: format!("SELECT root FROM {m} ORDER BY root"),
            keys: format!("SELECT key FROM {a}"),
            ref_unknown: format!("SELECT EXISTS (SELECT 1 FROM {a} WHERE ref_state = ?1)"),
            ref_exists: format!("SELECT EXISTS (SELECT 1 FROM {a} WHERE manifest_ref = ?1)"),
            memo: format!("SELECT test_key, key FROM {memo} WHERE tree16 = ?1"),
            flag: format!("SELECT EXISTS (SELECT 1 FROM {flags} WHERE name = ?1)"),
            put_hinted: format!(
                "{} RETURNING key",
                upsert_attestations(
                    a,
                    "(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                      ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)"
                )
            ),
            put_plain: format!(
                "INSERT INTO {a}
                   (key, test_key, signer, storage_key, target, issued, tree16, manifest_ref,
                    ref_state, stored_at, value, {cols})
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, ?7, ?8, ?9,
                         ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
                 ON CONFLICT (test_key, signer, storage_key) DO UPDATE SET
                   target = excluded.target, manifest_ref = excluded.manifest_ref,
                   ref_state = excluded.ref_state, stored_at = excluded.stored_at,
                   encoding = 0, value = excluded.value, {set_cols}
                 WHERE {a}.value IS NOT excluded.value
                    OR {a}.encoding <> 0
                    OR {cols_differ}
                 RETURNING key",
                cols = column_list(),
                set_cols = column_sets(),
                cols_differ = columns_differ(a),
            ),
            slot_key: format!(
                "SELECT key FROM {a} WHERE test_key = ?1 AND signer = ?2 AND storage_key = ?3"
            ),
            manifest_same: format!(
                "SELECT value = ?2 AND encoding = 0 FROM {m} WHERE root = ?1"
            ),
            manifest_touch: format!("UPDATE {m} SET put_at = ?2 WHERE root = ?1"),
            manifest_upsert: format!(
                "INSERT INTO {m} (root, base, put_at, encoding, value) VALUES (?1, ?2, ?3, 0, ?4)
                 ON CONFLICT (root) DO UPDATE SET
                   base = excluded.base, put_at = excluded.put_at, encoding = 0, value = excluded.value"
            ),
            remove: format!("DELETE FROM {a} WHERE key = ?1"),
            remove_manifest: format!(
                "DELETE FROM {m} WHERE root = ?1
                   AND NOT EXISTS (SELECT 1 FROM {a} WHERE manifest_ref = ?1)
                   AND NOT EXISTS (SELECT 1 FROM {m} WHERE base = ?1)"
            ),
            memo_put: upsert_memo(memo, "(?1, ?2, ?3, ?4)"),
            memo_prune: format!("DELETE FROM {memo} WHERE at < ?1"),
            flag_put: format!(
                "INSERT INTO {flags} (name, at) VALUES (?1, ?2) ON CONFLICT (name) DO NOTHING"
            ),
            ddl_v2: format!(
                "
CREATE TABLE IF NOT EXISTS {o} (
  id     TEXT    NOT NULL PRIMARY KEY,
  kind   INTEGER NOT NULL,
  put_at INTEGER NOT NULL,
  bytes  BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS {p}objects_kind_put ON {o} (kind, put_at);
CREATE INDEX IF NOT EXISTS {p}attestations_hdr    ON {a} (hdr)       WHERE hdr       IS NOT NULL;
CREATE INDEX IF NOT EXISTS {p}attestations_tables ON {a} (tables_id) WHERE tables_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS {p}attestations_shape  ON {a} (shape)     WHERE shape     IS NOT NULL;
CREATE INDEX IF NOT EXISTS {p}attestations_state  ON {a} (state_obj) WHERE state_obj IS NOT NULL;
"
            ),
            columns: format!("SELECT {} FROM {a} WHERE key = ?1", column_list()),
            object: format!("SELECT kind, bytes FROM {o} WHERE id = ?1"),
            object_size: format!("SELECT kind, length(bytes) FROM {o} WHERE id = ?1"),
            object_touch: format!("UPDATE {o} SET put_at = ?2 WHERE id = ?1"),
            object_insert: format!(
                "INSERT INTO {o} (id, kind, put_at, bytes) VALUES (?1, ?2, ?3, ?4)"
            ),
            object_remove: format!(
                "DELETE FROM {o} WHERE id = ?1 AND put_at < ?2 AND NOT {referenced}"
            ),
            orphan_objects: format!(
                "SELECT id FROM {o} WHERE put_at < ?1 AND NOT {referenced} ORDER BY id"
            ),
            prune_state_objects: format!(
                "DELETE FROM {o} WHERE kind = {KIND_STATE} AND put_at < ?1"
            ),
            format_one_count: format!(
                "SELECT count(*) FROM {a} WHERE hex(substr(value, 1, 1)) <> '76'"
            ),
            drop_manifests: format!("DROP TABLE IF EXISTS {m}"),
            names: n.clone(),
        }
    }

    /// The table names these statements are over.
    pub fn names(&self) -> &Names {
        &self.names
    }

    /// `ALTER TABLE ... ADD COLUMN` for one of [`COLUMNS_V2`] (`(name,
    /// type)`), which the caller runs only when the attestations table
    /// lacks the column (`PRAGMA table_info`).
    pub fn add_column(&self, column: (&str, &str)) -> String {
        format!(
            "ALTER TABLE {} ADD COLUMN {} {}",
            self.names.attestations, column.0, column.1
        )
    }

    /// The upsert of attestations on their slot, `rows` being one or more
    /// `(key, test_key, signer, storage_key, target, issued, tree16,
    /// manifest_ref, ref_state, stored_at, value, format, commit_id,
    /// platform, state, duration_ms, expires, hdr, tables_id, shape,
    /// state_obj)` tuples (parameters or literals): each replaces its
    /// slot's row, key included, unless the key, the value, a readable
    /// encoding and the same columns are already there (a put of the same
    /// bytes with other columns, or without them, replaces the columns).
    /// [`Sql::put_hinted`] is this with parameters.
    pub fn upsert_attestations(&self, rows: &str) -> String {
        upsert_attestations(&self.names.attestations, rows)
    }

    /// The upsert of memo entries, `rows` being one or more `(tree16,
    /// test_key, key, at)` tuples. [`Sql::memo_put`] is this with
    /// parameters.
    pub fn upsert_memo(&self, rows: &str) -> String {
        upsert_memo(&self.names.memo, rows)
    }

    /// The upsert of manifests, `rows` being one or more `(root, base,
    /// put_at, encoding, value)` tuples: `put_at` and `base` are refreshed,
    /// the value replaced only when it differs or is unreadable.
    pub fn upsert_manifests(&self, rows: &str) -> String {
        let m = &self.names.manifests;
        format!(
            "INSERT INTO {m} (root, base, put_at, encoding, value) VALUES {rows}
             ON CONFLICT (root) DO UPDATE SET
               value = CASE WHEN {m}.value IS NOT excluded.value OR {m}.encoding <> 0
                 THEN excluded.value ELSE {m}.value END,
               base = excluded.base, put_at = excluded.put_at, encoding = 0"
        )
    }
}

fn upsert_memo(memo: &str, rows: &str) -> String {
    format!(
        "INSERT INTO {memo} (tree16, test_key, key, at) VALUES {rows}
         ON CONFLICT (tree16, test_key) DO UPDATE SET key = excluded.key, at = excluded.at"
    )
}

fn upsert_attestations(a: &str, rows: &str) -> String {
    format!(
        "INSERT INTO {a}
           (key, test_key, signer, storage_key, target, issued, tree16, manifest_ref,
            ref_state, stored_at, value, {cols})
         VALUES {rows}
         ON CONFLICT (test_key, signer, storage_key) DO UPDATE SET
           key = excluded.key, target = excluded.target, issued = excluded.issued,
           tree16 = excluded.tree16, manifest_ref = excluded.manifest_ref,
           ref_state = excluded.ref_state, stored_at = excluded.stored_at,
           encoding = 0, value = excluded.value, {set_cols}
         WHERE {a}.key IS NOT excluded.key
            OR {a}.value IS NOT excluded.value
            OR {a}.encoding <> 0
            OR {cols_differ}",
        cols = column_list(),
        set_cols = column_sets(),
        cols_differ = columns_differ(a),
    )
}

/// `format, commit_id, ...`: the [`COLUMNS_V2`] names.
fn column_list() -> String {
    COLUMNS_V2
        .iter()
        .map(|(c, _)| *c)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `format = excluded.format, ...` for an upsert's `DO UPDATE SET`.
fn column_sets() -> String {
    COLUMNS_V2
        .iter()
        .map(|(c, _)| format!("{c} = excluded.{c}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `a.format IS NOT excluded.format OR ...`: whether an upsert changes a
/// column (`IS NOT` so that `NULL` compares).
fn columns_differ(a: &str) -> String {
    COLUMNS_V2
        .iter()
        .map(|(c, _)| format!("{a}.{c} IS NOT excluded.{c}"))
        .collect::<Vec<_>>()
        .join(" OR ")
}

/// The statements of a SQLite store file ([`Names::plain`]).
pub fn plain() -> &'static Sql {
    static PLAIN: LazyLock<Sql> = LazyLock::new(|| Sql::new(&Names::plain()));
    &PLAIN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_names_rename_every_table_and_index() {
        let s = Sql::new(&Names::prefixed("vci_ab12_"));
        for t in ["attestations", "manifests", "memo", "flags"] {
            assert!(s.ddl.contains(&format!("vci_ab12_{t}")), "{t}");
        }
        assert!(s.ddl_v2.contains("vci_ab12_objects"));
        for line in s
            .ddl
            .lines()
            .chain(s.ddl_v2.lines())
            .filter(|l| l.starts_with("CREATE"))
        {
            let name = line.split_whitespace().nth(5).unwrap_or_default();
            assert!(name.starts_with("vci_ab12_"), "{line}");
        }
        assert_eq!(
            s.add_column(COLUMNS_V2[7]),
            "ALTER TABLE vci_ab12_attestations ADD COLUMN tables_id TEXT"
        );
        assert!(s.object_remove.contains("vci_ab12_objects.id"));
        assert_eq!(
            plain().list_unit,
            "SELECT key, target FROM attestations WHERE test_key = ?1 ORDER BY key"
        );
    }

    #[test]
    #[should_panic(expected = "a table name prefix")]
    fn a_prefix_that_would_need_quoting_is_refused() {
        let _ = Names::prefixed("vci-x.");
    }
}
