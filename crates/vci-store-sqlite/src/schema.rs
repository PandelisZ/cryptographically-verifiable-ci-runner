//! The file's schema: version 1, how a connection finds out what a file
//! holds, and the migration a first write runs.
//!
//! A vci store file carries `PRAGMA application_id = 0x76636931` ('vci1')
//! and `PRAGMA user_version = 1`. A file with neither and no tables (a new
//! or empty file) is a store not created yet: reads answer as an empty
//! store and the first write creates the schema. Any other file is refused
//! rather than written: a newer `user_version` is
//! [`vci_store::StoreError::Incompatible`], and a database of something
//! else is not touched at all.

use std::time::{Duration, Instant};

use rusqlite::{Connection, ErrorCode, TransactionBehavior};

/// `PRAGMA application_id` of a vci store: the bytes `vci1`.
pub(crate) const APPLICATION_ID: i64 = 0x7663_6931;

/// The schema version this vci writes and reads (`PRAGMA user_version`).
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// Schema version 1. Every text column compares with SQLite's default
/// `BINARY` collation, which is bytewise, as the store's order requires.
/// `value` is each table's last column, so reads of the other columns
/// never touch the value's overflow pages.
const DDL_V1: &str = "
CREATE TABLE attestations (
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
CREATE INDEX attestations_unit ON attestations (test_key, key, target);
CREATE INDEX attestations_all  ON attestations (target, key);
CREATE INDEX attestations_ref  ON attestations (manifest_ref) WHERE manifest_ref IS NOT NULL;
CREATE INDEX attestations_unknown_ref ON attestations (ref_state) WHERE ref_state = 0;
CREATE TABLE manifests (
  root     TEXT    NOT NULL PRIMARY KEY,
  base     TEXT,
  put_at   INTEGER NOT NULL,
  encoding INTEGER NOT NULL DEFAULT 0,
  value    BLOB    NOT NULL
);
CREATE INDEX manifests_base ON manifests (base) WHERE base IS NOT NULL;
CREATE TABLE memo  (tree16 TEXT NOT NULL, test_key TEXT NOT NULL, key TEXT NOT NULL, at INTEGER NOT NULL,
                    PRIMARY KEY (tree16, test_key)) WITHOUT ROWID;
CREATE TABLE flags (name TEXT NOT NULL PRIMARY KEY, at INTEGER NOT NULL) WITHOUT ROWID;
";

/// `ref_state` of a row whose value's `manifestRef` is unknown (the value
/// does not parse as a vci envelope).
pub(crate) const REF_UNKNOWN: i64 = 0;
/// `ref_state` of a row whose value names a stored manifest (`manifest_ref`).
pub(crate) const REF_ROOT: i64 = 1;
/// `ref_state` of a row whose value carries its manifest inline.
pub(crate) const REF_INLINE: i64 = 2;

/// What a database file holds, as far as vci is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum State {
    /// No schema and no tables: a store not created yet.
    Empty,
    /// A vci store this vci reads.
    Ready,
    /// A vci store of a newer schema version.
    Newer(u32),
    /// Some other database, and why it is not a vci store.
    Foreign(String),
}

/// What `conn`'s file holds. Reads only the header and `sqlite_master`, in
/// one read transaction (unless the caller has one open): read one by one,
/// another connection's creation of the schema could commit between the
/// version and the tables.
pub(crate) fn state(conn: &Connection) -> rusqlite::Result<State> {
    let _snapshot = if conn.is_autocommit() {
        Some(conn.unchecked_transaction()?)
    } else {
        None
    };
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let app: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
    if version == 0 {
        let tables: i64 = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))?;
        return Ok(if tables == 0 && app == 0 {
            State::Empty
        } else {
            State::Foreign(format!(
                "it holds {tables} schema object(s) but no vci schema version"
            ))
        });
    }
    if app != APPLICATION_ID {
        return Ok(State::Foreign(format!(
            "its application_id is {app:#x}, not vci's {APPLICATION_ID:#x}"
        )));
    }
    match u32::try_from(version) {
        Ok(v) if v == SCHEMA_VERSION => Ok(State::Ready),
        Ok(v) if v > SCHEMA_VERSION => Ok(State::Newer(v)),
        _ => Ok(State::Foreign(format!(
            "its schema version {version} is not one vci wrote"
        ))),
    }
}

/// Create the schema in `conn`'s file if it is [`State::Empty`], and say
/// what the file holds afterwards. A file that is not empty is left as it
/// is.
///
/// The file is put in WAL mode first (a persistent setting that cannot
/// change inside a transaction), retrying while another connection holds
/// the lock, until `deadline` from now. The schema is then created under
/// `BEGIN IMMEDIATE`, which serializes concurrent creators: whoever comes
/// second finds [`State::Ready`] and changes nothing.
pub(crate) fn migrate(conn: &mut Connection, deadline: Duration) -> rusqlite::Result<State> {
    let found = state(conn)?;
    if found != State::Empty {
        return Ok(found);
    }
    let until = Instant::now() + deadline;
    loop {
        match conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0)) {
            Ok(_) => break,
            Err(e) if is_busy(&e) && Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(e),
        }
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let found = state(&tx)?;
    if found != State::Empty {
        return Ok(found);
    }
    tx.execute_batch(DDL_V1)?;
    tx.pragma_update(None, "application_id", APPLICATION_ID)?;
    tx.pragma_update(None, "user_version", i64::from(SCHEMA_VERSION))?;
    tx.commit()?;
    Ok(State::Ready)
}

/// Whether `e` says another connection holds the lock.
pub(crate) fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}
