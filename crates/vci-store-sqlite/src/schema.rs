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

pub(crate) use crate::sql::{REF_INLINE, REF_ROOT, REF_UNKNOWN};

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
    tx.execute_batch(&crate::sql::plain().ddl)?;
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
