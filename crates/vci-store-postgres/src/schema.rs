//! Schema v1, its migration and the version check
//! (`docs/STORE-BACKENDS.md` section 17, "Schema v1" and "Migrations").
//!
//! Reads never run DDL: a missing schema or table reads as an empty store.
//! The first write creates the schema in one transaction under an advisory
//! lock, so concurrent first writers create it once.

use postgres::types::Type;
use vci_store::StoreError;

use crate::Inner;
use crate::conn::{Fail, KIND, Op};

/// The newest schema version this vci reads and writes.
pub(crate) const SUPPORTED: u32 = 1;

/// The migration. Every statement in it is `IF NOT EXISTS` or `ON
/// CONFLICT DO NOTHING`, so it is retried like any write; a privilege error
/// in it means this role cannot create the schema.
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
}

impl SchemaSql {
    pub(crate) fn new(s: &str) -> SchemaSql {
        SchemaSql {
            ddl: ddl(s),
            lock_key: format!("vci-store:{s}"),
            insert_version: format!(
                "INSERT INTO \"{s}\".schema_version (version, vci_version) VALUES ({SUPPORTED}, $1) \
                 ON CONFLICT (id) DO NOTHING"
            ),
            version: format!("SELECT version FROM \"{s}\".schema_version"),
        }
    }
}

/// Every table and index of v1, each created only when missing. Every
/// column a listing sorts by is `COLLATE "C"`: keys compare bytewise.
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
    match inner.version.get() {
        Some(&v) if v > SUPPORTED => Err(incompatible(v)),
        _ => Ok(()),
    }
}

/// Read the schema's version (one statement, then remembered once the
/// schema exists). A schema newer than this vci is
/// [`StoreError::Incompatible`].
pub(crate) fn check(inner: &Inner) -> Result<State, StoreError> {
    if let Some(&v) = inner.version.get() {
        return if v > SUPPORTED {
            Err(incompatible(v))
        } else {
            Ok(State::Version(v))
        };
    }
    let sql = &inner.schema_sql.version;
    let r = inner.conn.run(crate::conn::READ, |db| {
        let rows = db.query(sql, &[])?;
        Ok(rows
            .first()
            .map(|r| r.try_get::<_, i32>(0))
            .transpose()?
            .map(|v| v.max(0) as u32))
    });
    match r {
        Ok(Some(v)) => {
            let _ = inner.version.set(v);
            check(inner)
        }
        // The table exists with no row: a migration that has not
        // committed yet; treat it as absent.
        Ok(None) | Err(Fail::Absent) => Ok(State::Absent),
        Err(Fail::Store(e)) => Err(e),
    }
}

/// Make sure the schema exists before a write: check it, and create it
/// when it is missing. A role that cannot create it gets
/// [`StoreError::NotInitialized`].
pub(crate) fn ensure(inner: &Inner) -> Result<(), StoreError> {
    if let State::Version(_) = check(inner)? {
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
        let rows = tx.query(&sql.version, &[])?;
        tx.commit()?;
        Ok(rows
            .first()
            .map(|r| r.try_get::<_, i32>(0))
            .transpose()?
            .map(|v| v.max(0) as u32))
    });
    match r {
        Ok(Some(v)) => {
            let _ = inner.version.set(v);
            check(inner).map(|_| ())
        }
        Ok(None) => Err(StoreError::NotInitialized {
            backend: KIND,
            advice: advice(&inner.schema),
        }),
        Err(Fail::Store(StoreError::Denied { .. })) | Err(Fail::Absent) => {
            Err(StoreError::NotInitialized {
                backend: KIND,
                advice: advice(&inner.schema),
            })
        }
        Err(Fail::Store(e)) => Err(e),
    }
}
