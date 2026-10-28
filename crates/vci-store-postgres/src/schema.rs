//! Schema v1, its format-3 additions, the version check and the end of the
//! migration window (`docs/STORE-BACKENDS.md` section 17, "Schema v1",
//! "The format-3 additions" and "Migrations").
//!
//! Reads never run DDL: a missing schema or table reads as an empty store.
//! The first write creates the schema in one transaction under an advisory
//! lock, so concurrent first writers create it once. The format-3 additions
//! of STORE-V2 section 2.1 (the listing columns and `seq` on
//! `attestations`, the `objects`, `gone` and `namespaces` tables) are part
//! of that DDL, so a new schema has them; a schema a 2.8 vci made lacks
//! them, and the first write of this vci adds them in a request of its own,
//! under the same lock, before anything else is written. Whether they are
//! there is read with the version in one statement: `objects` exists
//! (`to_regclass`), the DDL being one transaction. The version stays 1
//! while a format-1 row can exist, so a 2.8 vci keeps reading the rows it
//! can parse; [`finish`] ends the window (`vci store upgrade --finish`):
//! it drops `manifests` and sets version 2, which this vci reads and a 2.8
//! vci refuses as newer than it.

use std::sync::atomic::Ordering;

use postgres::types::Type;
use vci_store::StoreError;

use crate::Inner;
use crate::conn::{Fail, KIND, Op};

/// The newest schema version this vci reads and writes: 2, a schema whose
/// migration window [`finish`] closed (no `manifests` table).
pub(crate) const SUPPORTED: u32 = 2;

/// The version a new schema gets, and keeps while a format-1 row can exist
/// (STORE-V2 section 5).
pub(crate) const CREATED: u32 = 1;

/// The migration. Every statement in it is `IF NOT EXISTS` or `ON
/// CONFLICT DO NOTHING`, so it is retried like any write; a privilege error
/// in it means this role cannot create or alter the schema.
const MIGRATE: Op = Op {
    verb: "create the schema",
    retry: true,
    upsert: true,
};

/// The statements that create and check the schema.
pub(crate) struct SchemaSql {
    ddl: String,
    lock_key: String,
    insert_version: String,
    pub(crate) version: String,
    objects_regclass: String,
    format_one_rows: String,
    finish: String,
}

impl SchemaSql {
    pub(crate) fn new(s: &str) -> SchemaSql {
        SchemaSql {
            ddl: ddl(s),
            lock_key: format!("vci-store:{s}"),
            insert_version: format!(
                "INSERT INTO \"{s}\".schema_version (version, vci_version) VALUES ({CREATED}, $1) \
                 ON CONFLICT (id) DO NOTHING"
            ),
            // The version and whether the format-3 additions are there, in
            // one statement: `to_regclass` is NULL for a missing relation,
            // never an error.
            version: format!(
                "SELECT version, to_regclass($1) IS NOT NULL FROM \"{s}\".schema_version"
            ),
            objects_regclass: format!("\"{s}\".objects"),
            format_one_rows: format!(
                "SELECT count(*) FROM \"{s}\".attestations WHERE format IS DISTINCT FROM 3"
            ),
            finish: format!(
                "DROP TABLE IF EXISTS \"{s}\".manifests; \
                 UPDATE \"{s}\".schema_version SET version = {SUPPORTED}, \
                   vci_version = '{}', migrated_at = now(), migrated_by = session_user",
                env!("CARGO_PKG_VERSION")
            ),
        }
    }
}

/// Every table and index of v1 and the format-3 additions, each created
/// only when missing. Every column a listing sorts by, and every object
/// id, is `COLLATE "C"`: keys compare bytewise.
fn ddl(s: &str) -> String {
    format!(
        r#"
CREATE SCHEMA IF NOT EXISTS "{s}";
CREATE TABLE IF NOT EXISTS "{s}".schema_version (
  id          boolean     PRIMARY KEY DEFAULT true CHECK (id),
  version     integer     NOT NULL,
  vci_version text        NOT NULL,
  migrated_at timestamptz NOT NULL DEFAULT now(),
  migrated_by text        NOT NULL DEFAULT session_user
);
CREATE TABLE IF NOT EXISTS "{s}".attestations (
  ns           text        NOT NULL,
  key          text        COLLATE "C" NOT NULL,
  test_key     text        COLLATE "C" NOT NULL,
  signer       text        COLLATE "C" NOT NULL,
  storage_key  text        COLLATE "C" NOT NULL,
  target       text        COLLATE "C" NOT NULL,
  issued       bigint,
  tree16       text,
  manifest_ref text        COLLATE "C",
  ref_state    smallint    NOT NULL,
  encoding     smallint    NOT NULL DEFAULT 0,
  value        bytea       NOT NULL,
  stored_at    timestamptz NOT NULL DEFAULT now(),
  stored_by    text        NOT NULL DEFAULT session_user,
  PRIMARY KEY (ns, key),
  UNIQUE (ns, test_key, signer, storage_key)
);
CREATE INDEX IF NOT EXISTS attestations_unit ON "{s}".attestations (ns, test_key, key) INCLUDE (target);
CREATE INDEX IF NOT EXISTS attestations_all ON "{s}".attestations (ns, target, key);
CREATE INDEX IF NOT EXISTS attestations_ref ON "{s}".attestations (ns, manifest_ref) WHERE manifest_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS attestations_unknown_ref ON "{s}".attestations (ns) WHERE ref_state = 0;
CREATE TABLE IF NOT EXISTS "{s}".manifests (
  ns       text        NOT NULL,
  root     text        COLLATE "C" NOT NULL,
  base     text        COLLATE "C",
  encoding smallint    NOT NULL DEFAULT 0,
  value    bytea       NOT NULL,
  put_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ns, root)
);
CREATE INDEX IF NOT EXISTS manifests_base ON "{s}".manifests (ns, base) WHERE base IS NOT NULL;
CREATE TABLE IF NOT EXISTS "{s}".memo (
  ns       text NOT NULL,
  tree16   text NOT NULL,
  test_key text NOT NULL,
  key      text COLLATE "C" NOT NULL,
  at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ns, tree16, test_key)
);
CREATE TABLE IF NOT EXISTS "{s}".flags (
  ns   text NOT NULL,
  name text NOT NULL,
  at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ns, name)
);
ALTER TABLE "{s}".attestations
  ADD COLUMN IF NOT EXISTS format      smallint,
  ADD COLUMN IF NOT EXISTS commit_id   text,
  ADD COLUMN IF NOT EXISTS platform    text,
  ADD COLUMN IF NOT EXISTS state       text,
  ADD COLUMN IF NOT EXISTS duration_ms bigint,
  ADD COLUMN IF NOT EXISTS expires     bigint,
  ADD COLUMN IF NOT EXISTS hdr         text COLLATE "C",
  ADD COLUMN IF NOT EXISTS tables_id   text COLLATE "C",
  ADD COLUMN IF NOT EXISTS shape       text COLLATE "C",
  ADD COLUMN IF NOT EXISTS state_obj   text COLLATE "C",
  ADD COLUMN IF NOT EXISTS seq         bigint;
CREATE INDEX IF NOT EXISTS attestations_hdr ON "{s}".attestations (ns, hdr) WHERE hdr IS NOT NULL;
CREATE INDEX IF NOT EXISTS attestations_tables ON "{s}".attestations (ns, tables_id) WHERE tables_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS attestations_shape ON "{s}".attestations (ns, shape) WHERE shape IS NOT NULL;
CREATE INDEX IF NOT EXISTS attestations_state ON "{s}".attestations (ns, state_obj) WHERE state_obj IS NOT NULL;
CREATE INDEX IF NOT EXISTS attestations_seq ON "{s}".attestations (ns, seq);
CREATE TABLE IF NOT EXISTS "{s}".namespaces (
  ns  text   PRIMARY KEY,
  seq bigint NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS "{s}".gone (
  ns     text        NOT NULL,
  seq    bigint,
  key    text        COLLATE "C",
  object text        COLLATE "C",
  at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS gone_seq ON "{s}".gone (ns, seq);
CREATE TABLE IF NOT EXISTS "{s}".objects (
  ns     text        NOT NULL,
  id     text        COLLATE "C" NOT NULL,
  kind   smallint    NOT NULL,
  put_at timestamptz NOT NULL DEFAULT now(),
  seq    bigint,
  bytes  bytea       NOT NULL,
  PRIMARY KEY (ns, id)
);
CREATE INDEX IF NOT EXISTS objects_seq ON "{s}".objects (ns, seq);
CREATE INDEX IF NOT EXISTS objects_kind_put ON "{s}".objects (ns, kind, put_at);
"#
    )
}

/// Whether the schema exists, and its version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Absent,
    Version(u32),
}

/// What creates the schema, for [`vci_store::StoreStatus::Absent`] and
/// [`StoreError::NotInitialized`].
pub(crate) fn advice(schema: &str) -> String {
    format!("the first vci run with a role allowed to create schema {schema} creates it")
}

/// What adds the format-3 tables and columns to a schema that lacks them,
/// for [`StoreError::NotInitialized`].
pub(crate) fn upgrade_advice(schema: &str) -> String {
    format!(
        "schema {schema} lacks the format-3 tables (vci 2.9): the first vci run with a role allowed to alter it adds them"
    )
}

fn incompatible(found: u32) -> StoreError {
    StoreError::Incompatible {
        backend: KIND,
        found,
        supported: SUPPORTED,
    }
}

/// Refuse at once when an earlier check found a schema newer than this
/// vci (no statement).
pub(crate) fn refuse_newer(inner: &Inner) -> Result<(), StoreError> {
    match known_version(inner) {
        Some(v) if v > SUPPORTED => Err(incompatible(v)),
        _ => Ok(()),
    }
}

/// The version this handle remembers (0 is unknown: a schema is never at
/// version 0).
fn known_version(inner: &Inner) -> Option<u32> {
    match inner.version.load(Ordering::Relaxed) {
        0 => None,
        v => Some(v),
    }
}

/// Remember what a check or the DDL found.
fn learned(inner: &Inner, version: i32, v2: bool) {
    inner
        .version
        .store(version.max(0) as u32, Ordering::Relaxed);
    inner.v2.store(v2, Ordering::Relaxed);
}

/// Whether the format-3 additions were seen (or made) by this handle.
pub(crate) fn has_v2(inner: &Inner) -> bool {
    inner.v2.load(Ordering::Relaxed)
}

/// Read the schema's version and whether the format-3 additions are there
/// (one statement, then remembered once both are known: a schema that
/// lacks the additions is asked again, since any writer may add them). A
/// schema newer than this vci is [`StoreError::Incompatible`].
pub(crate) fn check(inner: &Inner) -> Result<State, StoreError> {
    if let Some(v) = known_version(inner) {
        if v > SUPPORTED {
            return Err(incompatible(v));
        }
        if has_v2(inner) {
            return Ok(State::Version(v));
        }
    }
    let sql = &inner.schema_sql;
    let r = inner.conn.run(crate::conn::READ, |db| {
        let rows = db.query(&sql.version, &[(&sql.objects_regclass, Type::TEXT)])?;
        rows.first()
            .map(|r| Ok((r.try_get::<_, i32>(0)?, r.try_get::<_, bool>(1)?)))
            .transpose()
    });
    match r {
        Ok(Some((v, v2))) => {
            learned(inner, v, v2);
            let v = v.max(0) as u32;
            if v > SUPPORTED {
                Err(incompatible(v))
            } else {
                Ok(State::Version(v))
            }
        }
        // The table exists with no row: a migration that has not
        // committed yet; treat it as absent.
        Ok(None) | Err(Fail::Absent) => Ok(State::Absent),
        Err(Fail::Store(e)) => Err(e),
    }
}

/// Make sure the schema exists with its format-3 additions before a write:
/// check it, and run the DDL (a request of its own, under the advisory
/// lock) when the schema is missing or lacks them. A role that cannot
/// create or alter it gets [`StoreError::NotInitialized`].
pub(crate) fn ensure(inner: &Inner) -> Result<(), StoreError> {
    let state = check(inner)?;
    if matches!(state, State::Version(_)) && has_v2(inner) {
        return Ok(());
    }
    let sql = &inner.schema_sql;
    let vci_version = env!("CARGO_PKG_VERSION");
    let r = inner.conn.run(MIGRATE, |db| {
        let mut tx = db.tx()?;
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1))",
            &[(&sql.lock_key, Type::TEXT)],
        )?;
        tx.batch_execute(&sql.ddl)?;
        tx.execute(&sql.insert_version, &[(&vci_version, Type::TEXT)])?;
        let rows = tx.query(&sql.version, &[(&sql.objects_regclass, Type::TEXT)])?;
        tx.commit()?;
        rows.first()
            .map(|r| Ok((r.try_get::<_, i32>(0)?, r.try_get::<_, bool>(1)?)))
            .transpose()
    });
    let advice = if state == State::Absent {
        advice(&inner.schema)
    } else {
        upgrade_advice(&inner.schema)
    };
    match r {
        Ok(Some((v, v2))) => {
            learned(inner, v, v2);
            check(inner).map(|_| ())
        }
        Ok(None) => Err(StoreError::NotInitialized {
            backend: KIND,
            advice,
        }),
        Err(Fail::Store(StoreError::Denied { .. })) | Err(Fail::Absent) => {
            Err(StoreError::NotInitialized {
                backend: KIND,
                advice,
            })
        }
        Err(Fail::Store(e)) => Err(e),
    }
}

/// What [`PgStore::upgrade_finish`](crate::PgStore::upgrade_finish) found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    /// The window is closed: `manifests` is gone and the version is 2.
    Done,
    /// Refused: this many rows of the schema (every namespace) are not
    /// format-3 records, and a 2.8 vci may still read them.
    FormatOneRows(u64),
}

/// End the migration window (`vci store upgrade --finish`, STORE-V2
/// section 5 step 4): when no row of the schema holds anything but a
/// format-3 record, drop `manifests` and set the version to
/// [`SUPPORTED`], in one transaction under the advisory lock; a schema
/// already there is left as it is. Refused with the count otherwise.
pub(crate) fn finish(inner: &Inner) -> Result<Finish, StoreError> {
    inner.ready()?;
    ensure(inner)?;
    let sql = &inner.schema_sql;
    let r = inner.conn.run(MIGRATE, |db| {
        let mut tx = db.tx()?;
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1))",
            &[(&sql.lock_key, Type::TEXT)],
        )?;
        let rows = tx.query(&sql.format_one_rows, &[])?;
        let n: i64 = rows.first().map(|r| r.try_get(0)).transpose()?.unwrap_or(0);
        if n > 0 {
            tx.commit()?;
            return Ok(Finish::FormatOneRows(n.max(0) as u64));
        }
        tx.batch_execute(&sql.finish)?;
        tx.commit()?;
        Ok(Finish::Done)
    });
    match r {
        Ok(Finish::Done) => {
            inner.version.store(SUPPORTED, Ordering::Relaxed);
            Ok(Finish::Done)
        }
        Ok(f) => Ok(f),
        Err(Fail::Absent) => Err(StoreError::NotInitialized {
            backend: KIND,
            advice: advice(&inner.schema),
        }),
        Err(Fail::Store(e)) => Err(e),
    }
}
