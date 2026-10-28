//! The format-3 side (`docs/STORE-BACKENDS.md` section 17, "Objects,
//! columns, `seq` and `gone`"; STORE-V2 section 2.1): the `objects` table
//! and its five operations, the listing columns of `attestations`, the
//! `gone` rows a removal leaves for a replica, and the per-namespace `seq`
//! counter.
//!
//! `seq` is handed out in **commit order**: a statement that needs numbers
//! takes them from `namespaces.seq` (`INSERT … ON CONFLICT DO UPDATE SET
//! seq = seq + n RETURNING seq`), whose row lock is held to the end of the
//! transaction, so the next transaction of the namespace gets its numbers
//! only once this one has committed or rolled back. Outside a batch each
//! write is one autocommit statement and holds the lock for its own
//! length; the deferred batch writes its rows with `seq` NULL and takes the
//! numbers in one statement right before `COMMIT` (`batch::Sql::stamp`), so
//! the writers of a namespace queue behind each other for that statement
//! and the commit, not for a whole flush.

use std::collections::BTreeSet;

use postgres::Row;
use postgres::types::Type;
use vci_store::timing::Step;
use vci_store::{
    Columns, MAX_OBJECTS_ANSWER, NewObject, OBJECT_GRACE, StoreError, StoredEnvelope, StoredObject,
    key, object_kind,
};

use crate::Inner;
use crate::conn::{Fail, KIND, READ, WRITE};
use crate::schema::{self, State};

/// Ids per statement.
const CHUNK: usize = 5_000;

/// The listing columns of `attestations` in the order every statement
/// names them (`Cols` reads and writes them in this order).
pub(crate) const COLUMNS: &str =
    "format, commit_id, platform, state, duration_ms, expires, hdr, tables_id, shape, state_obj";

/// `a.<column>` for each, as a row value.
pub(crate) fn columns_of(alias: &str) -> String {
    COLUMNS
        .split(", ")
        .map(|c| format!("{alias}.{c}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `<column> = EXCLUDED.<column>` for each.
pub(crate) fn set_columns() -> String {
    COLUMNS
        .split(", ")
        .map(|c| format!("{c} = EXCLUDED.{c}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The CTE `s` that takes `n` numbers from the namespace's counter (`$1`
/// is the namespace); `(SELECT seq FROM s)` is the last number taken, so
/// the i-th of them (from 1) is `(SELECT seq FROM s) - n + i`. With `n`
/// from an aggregate (`count(*) FROM d HAVING count(*) > 0`) nothing is
/// taken, and no lock held, when there is nothing to number.
pub(crate) fn take_seq(namespaces: &str, n: &str) -> String {
    format!(
        "INSERT INTO {namespaces} AS n (ns, seq) SELECT $1, {n} \
         ON CONFLICT (ns) DO UPDATE SET seq = n.seq + EXCLUDED.seq RETURNING seq"
    )
}

/// The `NOT EXISTS` of the orphan rule: no attestation of the namespace
/// names `o.id` in one of its object columns.
fn unreferenced(a: &str) -> String {
    format!(
        "NOT EXISTS (SELECT 1 FROM {a} x WHERE x.ns = $1 AND \
           (x.hdr = o.id OR x.tables_id = o.id OR x.shape = o.id OR x.state_obj = o.id))"
    )
}

/// The statements of one schema.
pub(crate) struct Sql {
    get: String,
    put: String,
    remove: String,
    orphans: String,
    prune_state: String,
    columns: String,
}

impl Sql {
    pub(crate) fn new(s: &str) -> Sql {
        let a = format!("\"{s}\".attestations");
        let o = format!("\"{s}\".objects");
        let g = format!("\"{s}\".gone");
        let n = format!("\"{s}\".namespaces");
        let orphan = format!(
            "o.ns = $1 AND o.put_at < now() - make_interval(secs => $2) AND {}",
            unreferenced(&a)
        );
        Sql {
            // The answer's size rides on every row, so an answer past the
            // bound is refused on its first row.
            get: format!(
                "SELECT id, kind, bytes, sum(octet_length(bytes)) OVER () FROM {o} \
                 WHERE ns = $1 AND id = ANY($2)"
            ),
            // `xmax = 0` on a returned row: inserted, not updated.
            put: format!(
                "WITH s AS ({}), \
                 up AS (INSERT INTO {o} AS o (ns, id, kind, seq, bytes) \
                   SELECT $1, u.id, u.kind, (SELECT seq FROM s) - cardinality($2::text[]) + u.i, u.bytes \
                   FROM unnest($2::text[], $3::int2[], $4::bytea[]) WITH ORDINALITY AS u(id, kind, bytes, i) \
                   ON CONFLICT (ns, id) DO UPDATE SET put_at = now() \
                   RETURNING (xmax = 0) AS inserted) \
                 SELECT count(*) FILTER (WHERE inserted) FROM up",
                take_seq(&n, "cardinality($2::text[])")
            ),
            remove: format!(
                "WITH d AS (DELETE FROM {o} AS o WHERE o.id = ANY($3) AND {orphan} RETURNING o.id), \
                 s AS ({}), \
                 g AS (INSERT INTO {g} (ns, seq, object) \
                   SELECT $1, (SELECT seq FROM s) - (SELECT count(*) FROM d) \
                     + row_number() OVER (ORDER BY id), id FROM d) \
                 SELECT count(*) FROM d",
                take_seq(&n, "count(*) FROM d HAVING count(*) > 0")
            ),
            orphans: format!("SELECT o.id FROM {o} AS o WHERE {orphan} ORDER BY o.id"),
            prune_state: format!(
                "WITH d AS (DELETE FROM {o} AS o WHERE o.ns = $1 AND o.kind = 4 \
                   AND o.put_at < now() - make_interval(secs => $2) RETURNING o.id), \
                 s AS ({}), \
                 g AS (INSERT INTO {g} (ns, seq, object) \
                   SELECT $1, (SELECT seq FROM s) - (SELECT count(*) FROM d) \
                     + row_number() OVER (ORDER BY id), id FROM d) \
                 SELECT count(*) FROM d",
                take_seq(&n, "count(*) FROM d HAVING count(*) > 0")
            ),
            columns: format!("SELECT key, {COLUMNS} FROM {a} WHERE ns = $1 AND key = ANY($2)"),
        }
    }
}

// ---- the listing columns as the table holds them ----------------------------------

/// [`Columns`] as the statements bind them, in the order of [`COLUMNS`].
#[derive(Debug, Clone, Default)]
pub(crate) struct Cols {
    pub(crate) format: Option<i16>,
    pub(crate) commit: Option<String>,
    pub(crate) platform: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) duration_ms: Option<i64>,
    pub(crate) expires: Option<i64>,
    pub(crate) hdr: Option<String>,
    pub(crate) tables: Option<String>,
    pub(crate) shape: Option<String>,
    pub(crate) state_obj: Option<String>,
}

impl Cols {
    /// What a put stores: every column NULL without columns.
    pub(crate) fn of(c: Option<&Columns>) -> Cols {
        let Some(c) = c else {
            return Cols::default();
        };
        Cols {
            format: c.format.map(i16::from),
            commit: c.commit.clone(),
            platform: c.platform.clone(),
            state: c.state.clone(),
            duration_ms: c.duration_ms.map(|d| i64::try_from(d).unwrap_or(i64::MAX)),
            expires: c.expires,
            hdr: c.hdr.clone(),
            tables: c.tables.clone(),
            shape: c.shape.clone(),
            state_obj: c.state_obj.clone(),
        }
    }

    /// The columns of a row, read from column `from` on.
    fn read(row: &Row, from: usize) -> Result<Cols, postgres::Error> {
        Ok(Cols {
            format: row.try_get(from)?,
            commit: row.try_get(from + 1)?,
            platform: row.try_get(from + 2)?,
            state: row.try_get(from + 3)?,
            duration_ms: row.try_get(from + 4)?,
            expires: row.try_get(from + 5)?,
            hdr: row.try_get(from + 6)?,
            tables: row.try_get(from + 7)?,
            shape: row.try_get(from + 8)?,
            state_obj: row.try_get(from + 9)?,
        })
    }

    /// As [`AttestationStore::columns`](vci_store::AttestationStore::columns)
    /// answers them. A value no column can hold (a negative format or
    /// duration, written behind the store's back) reads as none.
    fn to_columns(&self) -> Columns {
        Columns {
            format: self.format.and_then(|f| u8::try_from(f).ok()),
            commit: self.commit.clone(),
            platform: self.platform.clone(),
            state: self.state.clone(),
            duration_ms: self.duration_ms.and_then(|d| u64::try_from(d).ok()),
            expires: self.expires,
            hdr: self.hdr.clone(),
            tables: self.tables.clone(),
            shape: self.shape.clone(),
            state_obj: self.state_obj.clone(),
        }
    }
}

/// The ids, distinct in the order first asked, each validated.
fn distinct_ids<'a>(ids: &[&'a str]) -> Result<Vec<&'a str>, StoreError> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        key::check_object_id(id)?;
        if seen.insert(*id) {
            out.push(*id);
        }
    }
    Ok(out)
}

/// The schema is there for a removal (one that is not is nothing to
/// remove), with the format-3 additions (added when missing).
pub(crate) fn there_for_removal(inner: &Inner) -> Result<bool, StoreError> {
    match schema::check(inner)? {
        State::Absent => Ok(false),
        State::Version(_) => schema::ensure(inner).map(|()| true),
    }
}

// ---- reads ---------------------------------------------------------------------------

pub(crate) fn get_objects(inner: &Inner, ids: &[&str]) -> Result<Vec<StoredObject>, StoreError> {
    let ids = distinct_ids(ids)?;
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let ns = inner.ready()?;
    let step = Step::start(KIND);
    let mut found: Vec<StoredObject> = Vec::new();
    let mut total: usize = 0;
    for chunk in ids.chunks(CHUNK) {
        let mut over = false;
        let r = inner.conn.run(READ, |db| {
            over = false;
            db.for_each(
                &inner.objects_sql.get,
                &[(&ns, Type::TEXT), (&chunk, Type::TEXT_ARRAY)],
                |row| {
                    let size: i64 = row.try_get(3)?;
                    if over || usize::try_from(size).unwrap_or(usize::MAX) > MAX_OBJECTS_ANSWER {
                        // Past the bound: the rest of the rows are read off
                        // the connection and dropped, none is kept.
                        over = true;
                        return Ok(());
                    }
                    let id: String = row.try_get(0)?;
                    let kind: i16 = row.try_get(1)?;
                    let bytes: Vec<u8> = row.try_get(2)?;
                    // A kind no object has is a foreign row: left out.
                    if let Some(kind) = u8::try_from(kind).ok().and_then(object_kind) {
                        total += bytes.len();
                        found.push(StoredObject { id, kind, bytes });
                    }
                    Ok(())
                },
            )
        });
        Fail::or_absent(r, || ())?;
        if over || total > MAX_OBJECTS_ANSWER {
            return Err(StoreError::invalid(
                "objects",
                &format!("{} ids", ids.len()),
                "would answer more than MAX_OBJECTS_ANSWER bytes",
            ));
        }
    }
    // In the order asked.
    found.sort_by_cached_key(|o| ids.iter().position(|id| *id == o.id).unwrap_or(usize::MAX));
    step.done(format_args!(
        "read {} of {} object(s), {total} byte(s)",
        found.len(),
        ids.len()
    ));
    Ok(found)
}

pub(crate) fn orphan_objects(inner: &Inner) -> Result<Vec<String>, StoreError> {
    let ns = inner.ready()?;
    let grace = OBJECT_GRACE.as_secs_f64();
    let r = inner.conn.run(READ, |db| {
        db.query(
            &inner.objects_sql.orphans,
            &[(&ns, Type::TEXT), (&grace, Type::FLOAT8)],
        )
    });
    let mut out = Vec::new();
    for row in Fail::or_absent(r, Vec::new)? {
        let id: String = row.try_get(0).map_err(|e| inner.decode_error(&e))?;
        if key::is_object_id(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

pub(crate) fn columns(inner: &Inner, envs: &[&StoredEnvelope]) -> Result<Vec<Columns>, StoreError> {
    if envs.is_empty() {
        return Ok(Vec::new());
    }
    let ns = inner.ready()?;
    // A schema without the format-3 columns (a 2.8 schema nobody has
    // written to with this vci) keeps none.
    if !schema::has_v2(inner) {
        schema::check(inner)?;
        if !schema::has_v2(inner) {
            return Ok(vec![Columns::default(); envs.len()]);
        }
    }
    let keys: BTreeSet<&str> = envs.iter().map(|e| e.key.as_str()).collect();
    let keys: Vec<&str> = keys.into_iter().collect();
    let mut found: std::collections::HashMap<String, Columns> = std::collections::HashMap::new();
    for chunk in keys.chunks(CHUNK) {
        let r = inner.conn.run(READ, |db| {
            db.query(
                &inner.objects_sql.columns,
                &[(&ns, Type::TEXT), (&chunk, Type::TEXT_ARRAY)],
            )
        });
        for row in Fail::or_absent(r, Vec::new)? {
            let k: String = row.try_get(0).map_err(|e| inner.decode_error(&e))?;
            let c = Cols::read(&row, 1).map_err(|e| inner.decode_error(&e))?;
            found.insert(k, c.to_columns());
        }
    }
    Ok(envs
        .iter()
        .map(|e| found.get(&e.key).cloned().unwrap_or_default())
        .collect())
}

// ---- writes outside a batch -----------------------------------------------------------

/// The arrays a put binds: ids, kinds and bytes, one object per id (a
/// repeated id is put once, since an upsert may not touch a row twice).
pub(crate) struct ObjectArrays<'a> {
    pub(crate) ids: Vec<String>,
    pub(crate) kinds: Vec<i16>,
    pub(crate) bytes: Vec<&'a [u8]>,
}

impl<'a> ObjectArrays<'a> {
    /// Validate every object first; nothing is written on failure.
    pub(crate) fn of(objects: &[NewObject<'a>]) -> Result<ObjectArrays<'a>, StoreError> {
        let mut out = ObjectArrays {
            ids: Vec::with_capacity(objects.len()),
            kinds: Vec::with_capacity(objects.len()),
            bytes: Vec::with_capacity(objects.len()),
        };
        for o in objects {
            let id = o.validate()?;
            if out.ids.contains(&id) {
                continue;
            }
            out.ids.push(id);
            out.kinds.push(o.kind as i16);
            out.bytes.push(o.bytes);
        }
        Ok(out)
    }
}

pub(crate) fn put_objects(inner: &Inner, objects: &[NewObject<'_>]) -> Result<usize, StoreError> {
    let arrays = ObjectArrays::of(objects)?;
    if arrays.ids.is_empty() {
        return Ok(0);
    }
    let ns = inner.ready()?;
    schema::ensure(inner)?;
    let r = inner.conn.run(WRITE, |db| {
        db.query(
            &inner.objects_sql.put,
            &[
                (&ns, Type::TEXT),
                (&arrays.ids, Type::TEXT_ARRAY),
                (&arrays.kinds, Type::INT2_ARRAY),
                (&arrays.bytes, Type::BYTEA_ARRAY),
            ],
        )
    });
    let rows = match r {
        Ok(rows) => rows,
        Err(Fail::Absent) => {
            return Err(StoreError::NotInitialized {
                backend: KIND,
                advice: schema::advice(&inner.schema),
            });
        }
        Err(Fail::Store(e)) => return Err(e),
    };
    let n: i64 = rows
        .first()
        .map(|r| r.try_get(0))
        .transpose()
        .map_err(|e| inner.decode_error(&e))?
        .unwrap_or(0);
    Ok(usize::try_from(n).unwrap_or(0))
}

pub(crate) fn remove_objects(inner: &Inner, ids: &[&str]) -> Result<usize, StoreError> {
    let ids = distinct_ids(ids)?;
    if ids.is_empty() {
        return Ok(0);
    }
    let ns = inner.ready()?;
    if !there_for_removal(inner)? {
        return Ok(0);
    }
    let grace = OBJECT_GRACE.as_secs_f64();
    let r = inner.conn.run(WRITE, |db| {
        db.query(
            &inner.objects_sql.remove,
            &[
                (&ns, Type::TEXT),
                (&grace, Type::FLOAT8),
                (&ids, Type::TEXT_ARRAY),
            ],
        )
    });
    count_of(inner, r)
}

pub(crate) fn prune_state_objects(
    inner: &Inner,
    older_than: std::time::Duration,
) -> Result<usize, StoreError> {
    let ns = inner.ready()?;
    if !there_for_removal(inner)? {
        return Ok(0);
    }
    let secs = older_than.as_secs_f64();
    let r = inner.conn.run(WRITE, |db| {
        db.query(
            &inner.objects_sql.prune_state,
            &[(&ns, Type::TEXT), (&secs, Type::FLOAT8)],
        )
    });
    count_of(inner, r)
}

/// The one `count(*)` a removal statement answers (0 without the schema).
fn count_of(inner: &Inner, r: Result<Vec<Row>, Fail>) -> Result<usize, StoreError> {
    let rows = Fail::or_absent(r, Vec::new)?;
    let n: i64 = rows
        .first()
        .map(|r| r.try_get(0))
        .transpose()
        .map_err(|e| inner.decode_error(&e))?
        .unwrap_or(0);
    Ok(usize::try_from(n).unwrap_or(0))
}
