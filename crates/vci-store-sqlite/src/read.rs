//! The queries behind the store's reads. Each function takes one
//! connection whose file holds the schema (the caller has checked which
//! version, and calls the format-3 reads only on a file that has the
//! additions); listings and batch reads run inside one read transaction,
//! so they see one snapshot.
//!
//! Rows are read leniently: a key that does not have vci's shape, or a
//! column of an unexpected type (a row written behind vci's back), is
//! skipped in a listing and makes only its own value unreadable, never the
//! call fail.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension};
use vci_store::{
    Columns, GONE, MAX_OBJECTS_ANSWER, StoredEnvelope, StoredManifest, StoredObject, key,
};

use crate::schema::REF_UNKNOWN;
use crate::sql::plain as sql;

/// Text of a column, `None` when it is not UTF-8 text.
fn text(v: ValueRef<'_>) -> Option<String> {
    v.as_str().ok().map(str::to_owned)
}

/// A stored value as it can be read: its bytes when its `encoding` is one
/// this vci writes (0, raw), else why not.
fn value(v: ValueRef<'_>, encoding: ValueRef<'_>) -> Result<Vec<u8>, String> {
    match encoding.as_i64() {
        Ok(0) => {}
        Ok(n) => return Err(format!("the stored value has an unknown encoding ({n})")),
        Err(_) => return Err("the stored value has no valid encoding".to_owned()),
    }
    match v {
        ValueRef::Blob(b) | ValueRef::Text(b) => Ok(b.to_vec()),
        _ => Err("the stored value is not a byte string".to_owned()),
    }
}

/// Each unit's records, keys only, sorted by key; one list per id, in
/// input order. One index seek per distinct unit, in one read transaction.
pub(crate) fn list_units(
    conn: &Connection,
    test_ids: &[&str],
) -> rusqlite::Result<Vec<Vec<StoredEnvelope>>> {
    let _snapshot = snapshot(conn)?;
    let mut stmt = conn.prepare(&sql().list_unit)?;
    let mut by_key: HashMap<String, usize> = HashMap::new();
    let mut out: Vec<Vec<StoredEnvelope>> = Vec::with_capacity(test_ids.len());
    for id in test_ids {
        let tk = key::test_key(id);
        if let Some(&i) = by_key.get(&tk) {
            let again = out[i].clone();
            out.push(again);
            continue;
        }
        let mut rows = stmt.query([&tk])?;
        let mut unit = Vec::new();
        while let Some(row) = rows.next()? {
            if let (Some(k), Some(target)) = (text(row.get_ref(0)?), text(row.get_ref(1)?))
                && let Some(e) = StoredEnvelope::from_key(target, &k)
                && e.test_key == tk
            {
                unit.push(e);
            }
        }
        by_key.insert(tk, out.len());
        out.push(unit);
    }
    Ok(out)
}

/// Every record, keys only, sorted by (target, key).
pub(crate) fn list_all(conn: &Connection) -> rusqlite::Result<Vec<StoredEnvelope>> {
    let mut stmt = conn.prepare(&sql().list_all)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        if let (Some(k), Some(target)) = (text(row.get_ref(0)?), text(row.get_ref(1)?))
            && let Some(e) = StoredEnvelope::from_key(target, &k)
        {
            out.push(e);
        }
    }
    Ok(out)
}

/// Read each entry's value again, matched by key, in one read
/// transaction: its bytes, [`GONE`] for a key no longer stored, or why it
/// cannot be read.
pub(crate) fn read_values(
    conn: &Connection,
    envs: &mut [&mut StoredEnvelope],
) -> rusqlite::Result<()> {
    if envs.is_empty() {
        return Ok(());
    }
    let _snapshot = snapshot(conn)?;
    let mut stmt = conn.prepare(&sql().value)?;
    for e in envs.iter_mut() {
        let got = stmt
            .query_row([&e.key], |r| Ok(value(r.get_ref(0)?, r.get_ref(1)?)))
            .optional()?;
        match got {
            None => e.set_error(GONE),
            Some(Ok(bytes)) => e.set_value(bytes),
            Some(Err(why)) => e.set_error(why),
        }
    }
    Ok(())
}

/// The manifest stored under `root`, without its base.
pub(crate) fn manifest(conn: &Connection, root: &str) -> rusqlite::Result<Option<StoredManifest>> {
    if !key::is_hex_id(root) {
        return Ok(None);
    }
    let mut stmt = conn.prepare(&sql().manifest)?;
    manifest_with(&mut stmt, root)
}

/// [`manifest`] for several roots, in order, in one read transaction.
pub(crate) fn manifests(
    conn: &Connection,
    roots: &[&str],
) -> rusqlite::Result<Vec<Option<StoredManifest>>> {
    let _snapshot = snapshot(conn)?;
    let mut stmt = conn.prepare(&sql().manifest)?;
    roots
        .iter()
        .map(|root| {
            if key::is_hex_id(root) {
                manifest_with(&mut stmt, root)
            } else {
                Ok(None)
            }
        })
        .collect()
}

fn manifest_with(
    stmt: &mut rusqlite::Statement<'_>,
    root: &str,
) -> rusqlite::Result<Option<StoredManifest>> {
    let got = stmt
        .query_row([root], |r| Ok(value(r.get_ref(0)?, r.get_ref(1)?)))
        .optional()?;
    Ok(got.map(|v| match v {
        Ok(bytes) if bytes.is_empty() => StoredManifest::with_error(root, vci_store::EMPTY_VALUE),
        Ok(bytes) => StoredManifest::with_bytes(root, bytes),
        Err(why) => StoredManifest::with_error(root, why),
    }))
}

/// Every stored manifest's root, sorted (the primary key keeps them
/// distinct).
pub(crate) fn manifest_roots(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(&sql().manifest_roots)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        if let Some(r) = text(row.get_ref(0)?)
            && key::is_hex_id(&r)
        {
            out.push(r);
        }
    }
    Ok(out)
}

/// How many records have a key of vci's shape (values not read).
pub(crate) fn count(conn: &Connection) -> rusqlite::Result<usize> {
    let mut stmt = conn.prepare(&sql().keys)?;
    let mut rows = stmt.query([])?;
    let mut n = 0;
    while let Some(row) = rows.next()? {
        if row
            .get_ref(0)?
            .as_str()
            .is_ok_and(|k| key::parse_key(k).is_some())
        {
            n += 1;
        }
    }
    Ok(n)
}

/// Of `roots`, the ones no record's `manifest_ref` names, sorted; nothing
/// when some record's reference is unknown. Two index lookups per root at
/// most, never a value read.
pub(crate) fn orphan_manifests(conn: &Connection, roots: &[&str]) -> rusqlite::Result<Vec<String>> {
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let _snapshot = snapshot(conn)?;
    let unknown: bool = conn.query_row(&sql().ref_unknown, [REF_UNKNOWN], |r| r.get(0))?;
    if unknown {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(&sql().ref_exists)?;
    let wanted: BTreeSet<&str> = roots.iter().copied().collect();
    let mut out = Vec::new();
    for r in wanted {
        let referenced: bool = stmt.query_row([r], |row| row.get(0))?;
        if !referenced {
            out.push(r.to_owned());
        }
    }
    Ok(out)
}

/// The memo of tree `tree16`: test key -> attestation key.
pub(crate) fn passing_on(
    conn: &Connection,
    tree16: &str,
) -> rusqlite::Result<BTreeMap<String, String>> {
    let mut stmt = conn.prepare(&sql().memo)?;
    let mut rows = stmt.query([tree16])?;
    let mut out = BTreeMap::new();
    while let Some(row) = rows.next()? {
        if let (Some(tk), Some(k)) = (text(row.get_ref(0)?), text(row.get_ref(1)?)) {
            out.insert(tk, k);
        }
    }
    Ok(out)
}

/// Whether `name` is flagged.
pub(crate) fn flag(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    conn.query_row(&sql().flag, [name], |r| r.get(0))
}

/// The objects stored under these (validated) ids, in the order asked,
/// missing ids left out and a repeated id answered once, in one read
/// transaction: first their sizes (one index lookup each, bytes not read),
/// so that an answer past [`MAX_OBJECTS_ANSWER`] is refused before any
/// object is read (`Err(total)`); then the bytes. A row whose kind column
/// names no kind is a foreign row and is left out.
pub(crate) fn objects(
    conn: &Connection,
    ids: &[&str],
) -> rusqlite::Result<Result<Vec<StoredObject>, usize>> {
    let _snapshot = snapshot(conn)?;
    let mut seen = BTreeSet::new();
    let wanted: Vec<&str> = ids.iter().copied().filter(|id| seen.insert(*id)).collect();
    let mut sizes = conn.prepare(&sql().object_size)?;
    let mut total = 0usize;
    let mut found: Vec<(&str, vci_core::ObjectKind)> = Vec::with_capacity(wanted.len());
    for id in wanted {
        let row: Option<(i64, i64)> = sizes
            .query_row([id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        if let Some((kind, len)) = row
            && let Some(kind) = u8::try_from(kind).ok().and_then(vci_store::object_kind)
        {
            total = total.saturating_add(usize::try_from(len).unwrap_or(usize::MAX));
            if total > MAX_OBJECTS_ANSWER {
                return Ok(Err(total));
            }
            found.push((id, kind));
        }
    }
    let mut stmt = conn.prepare(&sql().object)?;
    let mut out = Vec::with_capacity(found.len());
    for (id, kind) in found {
        let bytes: Option<Vec<u8>> = stmt
            .query_row([id], |r| match r.get_ref(1)? {
                ValueRef::Blob(b) => Ok(Some(b.to_vec())),
                _ => Ok(None),
            })
            .optional()?
            .flatten();
        if let Some(bytes) = bytes {
            out.push(StoredObject {
                id: id.to_owned(),
                kind,
                bytes,
            });
        }
    }
    Ok(Ok(out))
}

/// The ids of the objects the orphan rule would remove now: no
/// attestation's object-id column names them and they were put before
/// `before`; sorted, one index scan and four index lookups per object, no
/// value read. A row whose id is not an object id is foreign and left out.
pub(crate) fn orphan_objects(conn: &Connection, before: i64) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(&sql().orphan_objects)?;
    let mut rows = stmt.query([before])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        if let Some(id) = text(row.get_ref(0)?)
            && key::is_object_id(&id)
        {
            out.push(id);
        }
    }
    Ok(out)
}

/// Each entry's format-3 columns, matched by key, in one read transaction:
/// [`Columns::default`] for a key no longer stored and for a row whose
/// columns are `NULL` (a format-1 row, a record put without them). A
/// column of an unexpected type reads as `None`.
pub(crate) fn columns(
    conn: &Connection,
    envs: &[&StoredEnvelope],
) -> rusqlite::Result<Vec<Columns>> {
    if envs.is_empty() {
        return Ok(Vec::new());
    }
    let _snapshot = snapshot(conn)?;
    let mut stmt = conn.prepare(&sql().columns)?;
    envs.iter()
        .map(|e| {
            let got = stmt
                .query_row([&e.key], |r| {
                    let int = |i: usize| r.get_ref(i).map(|v| v.as_i64().ok());
                    let txt = |i: usize| r.get_ref(i).map(|v| v.as_str().ok().map(str::to_owned));
                    Ok(Columns {
                        format: int(0)?.and_then(|n| u8::try_from(n).ok()),
                        commit: txt(1)?,
                        platform: txt(2)?,
                        state: txt(3)?,
                        duration_ms: int(4)?.and_then(|n| u64::try_from(n).ok()),
                        expires: int(5)?,
                        hdr: txt(6)?,
                        tables: txt(7)?,
                        shape: txt(8)?,
                        state_obj: txt(9)?,
                    })
                })
                .optional()?;
            Ok(got.unwrap_or_default())
        })
        .collect()
}

/// One read transaction on `conn`, so that several statements see one
/// snapshot; none when `conn` already has a transaction open (a write
/// batch's, whose own writes the reads then see).
fn snapshot(conn: &Connection) -> rusqlite::Result<Option<rusqlite::Transaction<'_>>> {
    if conn.is_autocommit() {
        conn.unchecked_transaction().map(Some)
    } else {
        Ok(None)
    }
}
