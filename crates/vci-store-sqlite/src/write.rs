//! The statements behind the store's writes. Each function runs inside one
//! `BEGIN IMMEDIATE` transaction that the caller opened and commits, so a
//! write is atomic and serialized with every other writer of the file.
//! Arguments are validated by the caller before the transaction starts.

use rusqlite::{Connection, OptionalExtension, params};
use vci_store::{ManifestRef, NewAttestation, NewObject, StoredEnvelope, key};

use crate::schema::{REF_INLINE, REF_ROOT, REF_UNKNOWN};
use crate::sql::plain as sql;

use crate::sql::MEMO_KEEP_SECS;

/// Store one attestation under the hinted key, or (without a hint) under
/// the key its slot already has, else the plain key, with the format-3
/// columns it carries (`NULL` without them). The slot's UNIQUE constraint
/// makes the replacement of an older key of the same slot one atomic
/// upsert. Identical bytes and columns under the same key change nothing
/// (not even `stored_at`); the same bytes with other columns, or without
/// them, replace the columns. A row whose value this vci cannot read (an
/// unknown `encoding`) is rewritten. Returns the key stored under.
pub(crate) fn put(
    conn: &Connection,
    att: &NewAttestation<'_>,
    now: i64,
) -> rusqlite::Result<String> {
    let (manifest_ref, ref_state) = match key::envelope_manifest_ref(att.envelope) {
        ManifestRef::Root(r) => (Some(r), REF_ROOT),
        ManifestRef::Inline => (None, REF_INLINE),
        ManifestRef::Unknown => (None, REF_UNKNOWN),
    };
    let c = att.columns.cloned().unwrap_or_default();
    let duration_ms = c.duration_ms.and_then(|n| i64::try_from(n).ok());
    match att.hinted_key() {
        Some(k) => {
            let hint = key::parse_key_hint(&k);
            let mut stmt = conn.prepare(&sql().put_hinted)?;
            stmt.query_row(
                params![
                    k,
                    att.test_key,
                    att.signer,
                    att.storage_key,
                    att.target,
                    hint.as_ref().map(|h| h.issued),
                    hint.and_then(|h| h.tree),
                    manifest_ref,
                    ref_state,
                    now,
                    att.envelope,
                    c.format,
                    c.commit,
                    c.platform,
                    c.state,
                    duration_ms,
                    c.expires,
                    c.hdr,
                    c.tables,
                    c.shape,
                    c.state_obj,
                ],
                |_| Ok(()),
            )
            .optional()?;
            Ok(k)
        }
        None => {
            let mut stmt = conn.prepare(&sql().put_plain)?;
            let written: Option<String> = stmt
                .query_row(
                    params![
                        att.plain_key(),
                        att.test_key,
                        att.signer,
                        att.storage_key,
                        att.target,
                        manifest_ref,
                        ref_state,
                        now,
                        att.envelope,
                        c.format,
                        c.commit,
                        c.platform,
                        c.state,
                        duration_ms,
                        c.expires,
                        c.hdr,
                        c.tables,
                        c.shape,
                        c.state_obj,
                    ],
                    |r| r.get(0),
                )
                .optional()?;
            match written {
                Some(k) => Ok(k),
                // Nothing changed: the slot holds these bytes already, under
                // the key it keeps.
                None => conn.query_row(
                    &sql().slot_key,
                    params![att.test_key, att.signer, att.storage_key],
                    |r| r.get(0),
                ),
            }
        }
    }
}

/// Store a manifest's bytes under `root` unless exactly these bytes are
/// stored (compared inside SQLite, never read out), and refresh `put_at`
/// either way. Returns whether the stored bytes changed.
pub(crate) fn put_manifest(
    conn: &Connection,
    root: &str,
    bytes: &[u8],
    now: i64,
) -> rusqlite::Result<bool> {
    let same: Option<bool> = conn
        .query_row(&sql().manifest_same, params![root, bytes], |r| r.get(0))
        .optional()?;
    if same == Some(true) {
        conn.execute(&sql().manifest_touch, params![root, now])?;
        return Ok(false);
    }
    let base = vci_core::InputManifest::compact_base(bytes)
        .ok()
        .flatten()
        .filter(|b| key::is_hex_id(b));
    conn.execute(&sql().manifest_upsert, params![root, base, now, bytes])?;
    Ok(true)
}

/// Delete these records by key. Returns the ones that existed, with the
/// bytes the caller gave, in the caller's order.
pub(crate) fn remove(
    conn: &Connection,
    doomed: Vec<StoredEnvelope>,
) -> rusqlite::Result<Vec<StoredEnvelope>> {
    let mut stmt = conn.prepare(&sql().remove)?;
    let mut removed = Vec::new();
    for e in doomed {
        if stmt.execute([&e.key])? > 0 {
            removed.push(e);
        }
    }
    Ok(removed)
}

/// Delete the manifests under these (validated) roots that no record
/// references and no manifest uses as its base. Returns how many were
/// deleted. The check and the delete are one statement in the caller's
/// write transaction, and SQLite has one writer, so no grace period is
/// needed.
pub(crate) fn remove_manifests(conn: &Connection, roots: &[&str]) -> rusqlite::Result<usize> {
    let mut stmt = conn.prepare(&sql().remove_manifest)?;
    let mut n = 0;
    let unique: std::collections::BTreeSet<&str> = roots.iter().copied().collect();
    for r in unique {
        n += stmt.execute([r])?;
    }
    Ok(n)
}

/// Remember the (test key, attestation key) pairs that passed on
/// `tree16`, and forget memo rows older than a week.
pub(crate) fn remember_passing(
    conn: &Connection,
    tree16: &str,
    items: &[(String, String)],
    now: i64,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(&sql().memo_put)?;
    for (tk, k) in items {
        stmt.execute(params![tree16, tk, k, now])?;
    }
    conn.execute(&sql().memo_prune, [now.saturating_sub(MEMO_KEEP_SECS)])?;
    Ok(())
}

/// Flag `name`.
pub(crate) fn set_flag(conn: &Connection, name: &str, now: i64) -> rusqlite::Result<()> {
    conn.execute(&sql().flag_put, params![name, now])?;
    Ok(())
}

/// Store these (validated) objects, `ids` being each one's id: an id
/// already stored has its `put_at` refreshed (one `UPDATE`, which changes a
/// row exactly then), the others are inserted. Returns how many were
/// inserted. An id given twice is stored once.
pub(crate) fn put_objects(
    conn: &Connection,
    objects: &[NewObject<'_>],
    ids: &[String],
    now: i64,
) -> rusqlite::Result<usize> {
    let mut touch = conn.prepare(&sql().object_touch)?;
    let mut insert = conn.prepare(&sql().object_insert)?;
    let mut done = std::collections::BTreeSet::new();
    let mut new = 0;
    for (o, id) in objects.iter().zip(ids) {
        if !done.insert(id.as_str()) || touch.execute(params![id, now])? > 0 {
            continue;
        }
        insert.execute(params![id, o.kind as u8, now, o.bytes])?;
        new += 1;
    }
    Ok(new)
}

/// Delete these (validated) objects under the orphan rule: each goes only
/// when no attestation's object-id column names it and it was put before
/// `before` (now less the grace). Returns how many went. The check and the
/// delete are one statement in the caller's write transaction, and SQLite
/// has one writer, so nothing can reference an object between them.
pub(crate) fn remove_objects(
    conn: &Connection,
    ids: &[&str],
    before: i64,
) -> rusqlite::Result<usize> {
    let mut stmt = conn.prepare(&sql().object_remove)?;
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    let mut n = 0;
    for id in unique {
        n += stmt.execute(params![id, before])?;
    }
    Ok(n)
}

/// Delete every state object put before `before`, referenced or not.
/// Returns how many went.
pub(crate) fn prune_state_objects(conn: &Connection, before: i64) -> rusqlite::Result<usize> {
    conn.execute(&sql().prune_state_objects, [before])
}
