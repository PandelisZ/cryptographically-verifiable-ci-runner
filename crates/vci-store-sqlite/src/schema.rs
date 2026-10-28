//! The file's schema: versions 1 and 2, the format-3 additions, how a
//! connection finds out what a file holds, and the migrations a first write
//! and `vci store upgrade` run.
//!
//! A vci store file carries `PRAGMA application_id = 0x76636931` ('vci1')
//! and `PRAGMA user_version = 1` or `2`. A file with neither and no tables
//! (a new or empty file) is a store not created yet: reads answer as an
//! empty store and the first write creates the schema. Any other file is
//! refused rather than written: a newer `user_version` is
//! [`vci_store::StoreError::Incompatible`], and a database of something
//! else is not touched at all.
//!
//! **Version 1 with the format-3 additions** (vci 2.9, STORE-V2 sections
//! 2.1 and 5): the nullable columns of [`crate::sql::COLUMNS_V2`], the
//! `objects` table and the indexes of [`crate::sql::Sql::ddl_v2`]. The
//! version stays 1 while a format-1 row can exist, so that a 2.8 binary
//! keeps reading the file (it lists keys, reads format-1 rows and fails
//! open on frames it cannot parse). Whether the additions are present is
//! read from `sqlite_master` (the `objects` table, created in the one
//! transaction that adds the columns): a SQLite file has no `vci_schema`
//! table, its version is `user_version`, so there is no flag row. A file
//! created by this vci has them from the start; an older file gets them
//! from [`upgrade`], which a 2.9 write runs in a transaction of its own
//! before its batch, or `vci store upgrade --begin` ahead of it.
//!
//! **Version 2** ([`finish`], `vci store upgrade --finish`): the additions
//! without the `manifests` table, once no format-1 row remains. A 2.8
//! binary then reports the schema too new and fails open.

use std::time::{Duration, Instant};

use rusqlite::{Connection, ErrorCode, TransactionBehavior};

use crate::sql::{COLUMNS_V2, plain as sql};

/// `PRAGMA application_id` of a vci store: the bytes `vci1`.
pub(crate) const APPLICATION_ID: i64 = 0x7663_6931;

/// The newest schema version this vci reads (`PRAGMA user_version`).
pub(crate) const SCHEMA_VERSION: u32 = 2;

/// The schema version a new file gets, and keeps while a format-1 row can
/// exist.
pub(crate) const SCHEMA_V1: u32 = 1;

pub(crate) use crate::sql::{REF_INLINE, REF_ROOT, REF_UNKNOWN};

/// What a vci store file holds, as a connection learned it: the version
/// and whether the format-3 additions are there. Carried by every
/// connection and passed to each read and write, so that a query touches
/// only the tables and columns the file has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Schema {
    /// `PRAGMA user_version`: 1 or 2.
    pub version: u32,
    /// The format-3 columns and the `objects` table are there (always at
    /// version 2).
    pub v2: bool,
}

impl Schema {
    /// Whether the file keeps format-1 manifests (gone at version 2).
    pub fn manifests(self) -> bool {
        self.version < 2
    }
}

/// What a database file holds, as far as vci is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum State {
    /// No schema and no tables: a store not created yet.
    Empty,
    /// A vci store this vci reads.
    Ready(Schema),
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
        Ok(v) if v == SCHEMA_V1 => Ok(State::Ready(Schema {
            version: v,
            v2: has_objects_table(conn)?,
        })),
        Ok(v) if v == SCHEMA_VERSION => Ok(State::Ready(Schema {
            version: v,
            v2: true,
        })),
        Ok(v) if v > SCHEMA_VERSION => Ok(State::Newer(v)),
        _ => Ok(State::Foreign(format!(
            "its schema version {version} is not one vci wrote"
        ))),
    }
}

/// Whether the `objects` table is there: the format-3 additions are made
/// in one transaction, so it stands for all of them.
fn has_objects_table(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [&sql().names().objects],
        |r| r.get(0),
    )
}

/// Create the schema in `conn`'s file if it is [`State::Empty`], and say
/// what the file holds afterwards. A file that is not empty is left as it
/// is. A file created here is at version 1 with the format-3 additions.
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
    tx.execute_batch(&sql().ddl)?;
    add_v2(&tx)?;
    tx.pragma_update(None, "application_id", APPLICATION_ID)?;
    tx.pragma_update(None, "user_version", i64::from(SCHEMA_V1))?;
    tx.commit()?;
    Ok(State::Ready(Schema {
        version: SCHEMA_V1,
        v2: true,
    }))
}

/// Add the format-3 additions to a version-1 file that lacks them, in one
/// `BEGIN IMMEDIATE` transaction of its own (STORE-V2 section 2.1: the DDL
/// is never part of a write batch), and say what the file holds
/// afterwards. Idempotent: a file that has them, or is at version 2, is
/// left as it is, and so is one that is not a ready store. Returns the
/// state and whether the additions were made now.
pub(crate) fn upgrade(conn: &mut Connection) -> rusqlite::Result<(State, bool)> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let found = state(&tx)?;
    let State::Ready(schema) = found else {
        return Ok((found, false));
    };
    if schema.v2 {
        return Ok((State::Ready(schema), false));
    }
    add_v2(&tx)?;
    tx.commit()?;
    Ok((State::Ready(Schema { v2: true, ..schema }), true))
}

/// The columns of [`COLUMNS_V2`] the attestations table lacks, then the
/// objects table and the indexes, inside the caller's transaction.
fn add_v2(conn: &Connection) -> rusqlite::Result<()> {
    let present: Vec<String> = {
        let mut stmt = conn.prepare(&format!(
            "PRAGMA table_info({})",
            sql().names().attestations
        ))?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for column in COLUMNS_V2 {
        if !present.iter().any(|c| c == column.0) {
            conn.execute_batch(&sql().add_column(column))?;
        }
    }
    conn.execute_batch(&sql().ddl_v2)
}

/// What [`finish`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Finished {
    /// The manifests table is dropped and the file is at version 2 now.
    Now,
    /// The file was at version 2 already.
    Already,
    /// Refused: this many attestations are not format-3 frames, and a
    /// reader of them needs the manifests.
    FormatOneRows(usize),
}

/// `vci store upgrade --finish` on a ready store: in one `BEGIN IMMEDIATE`
/// transaction, make sure the format-3 additions are there, count the
/// attestations that are not frames, and when there are none drop the
/// manifests table and set version 2. `Ok(None)` when the file is not a
/// ready store (the caller has refused it already).
pub(crate) fn finish(conn: &mut Connection) -> rusqlite::Result<Option<Finished>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let State::Ready(schema) = state(&tx)? else {
        return Ok(None);
    };
    if schema.version >= SCHEMA_VERSION {
        return Ok(Some(Finished::Already));
    }
    if !schema.v2 {
        add_v2(&tx)?;
    }
    let remaining: i64 = tx.query_row(&sql().format_one_count, [], |r| r.get(0))?;
    if remaining > 0 {
        // The additions, if made here, are kept: they are what `--begin`
        // would have made.
        tx.commit()?;
        return Ok(Some(Finished::FormatOneRows(
            usize::try_from(remaining).unwrap_or(usize::MAX),
        )));
    }
    tx.execute_batch(&sql().drop_manifests)?;
    tx.pragma_update(None, "user_version", i64::from(SCHEMA_VERSION))?;
    tx.commit()?;
    Ok(Some(Finished::Now))
}

/// Whether `e` says another connection holds the lock.
pub(crate) fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}
