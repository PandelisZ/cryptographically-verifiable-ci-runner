//! The statements behind the store's writes. Each function runs inside one
//! `BEGIN IMMEDIATE` transaction that the caller opened and commits, so a
//! write is atomic and serialized with every other writer of the file.
//! Arguments are validated by the caller before the transaction starts.

use rusqlite::{Connection, OptionalExtension, params};
use vci_store::{ManifestRef, NewAttestation, StoredEnvelope, key};

use crate::schema::{REF_INLINE, REF_ROOT, REF_UNKNOWN};

/// How long the memo keeps what a plan remembered: a week of trees.
pub(crate) const MEMO_KEEP_SECS: i64 = 7 * 24 * 60 * 60;

/// Store one attestation under the hinted key, or (without a hint) under
/// the key its slot already has, else the plain key. The slot's UNIQUE
/// constraint makes the replacement of an older key of the same slot one
/// atomic upsert. Identical bytes under the same key change nothing (not
/// even `stored_at`). A row whose value this vci cannot read (an unknown
/// `encoding`) is rewritten. Returns the key stored under.
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
    match att.hinted_key() {
        Some(k) => {
            let hint = key::parse_key_hint(&k);
            let mut stmt = conn.prepare(
                "INSERT INTO attestations
                   (key, test_key, signer, storage_key, target, issued, tree16, manifest_ref,
                    ref_state, stored_at, value)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT (test_key, signer, storage_key) DO UPDATE SET
                   key = excluded.key, target = excluded.target, issued = excluded.issued,
                   tree16 = excluded.tree16, manifest_ref = excluded.manifest_ref,
                   ref_state = excluded.ref_state, stored_at = excluded.stored_at,
                   encoding = 0, value = excluded.value
                 WHERE attestations.key IS NOT excluded.key
                    OR attestations.value IS NOT excluded.value
                    OR attestations.encoding <> 0
                 RETURNING key",
            )?;
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
                ],
                |_| Ok(()),
            )
            .optional()?;
            Ok(k)
        }
        None => {
            let mut stmt = conn.prepare(
                "INSERT INTO attestations
                   (key, test_key, signer, storage_key, target, issued, tree16, manifest_ref,
                    ref_state, stored_at, value)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, ?7, ?8, ?9)
                 ON CONFLICT (test_key, signer, storage_key) DO UPDATE SET
                   target = excluded.target, manifest_ref = excluded.manifest_ref,
                   ref_state = excluded.ref_state, stored_at = excluded.stored_at,
                   encoding = 0, value = excluded.value
                 WHERE attestations.value IS NOT excluded.value
                    OR attestations.encoding <> 0
                 RETURNING key",
            )?;
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
                    ],
                    |r| r.get(0),
                )
                .optional()?;
            match written {
                Some(k) => Ok(k),
                // Nothing changed: the slot holds these bytes already, under
                // the key it keeps.
                None => conn.query_row(
                    "SELECT key FROM attestations
                     WHERE test_key = ?1 AND signer = ?2 AND storage_key = ?3",
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
        .query_row(
            "SELECT value = ?2 AND encoding = 0 FROM manifests WHERE root = ?1",
            params![root, bytes],
            |r| r.get(0),
        )
        .optional()?;
    if same == Some(true) {
        conn.execute(
            "UPDATE manifests SET put_at = ?2 WHERE root = ?1",
            params![root, now],
        )?;
        return Ok(false);
    }
    let base = vci_core::InputManifest::compact_base(bytes)
        .ok()
        .flatten()
        .filter(|b| key::is_hex_id(b));
    conn.execute(
        "INSERT INTO manifests (root, base, put_at, encoding, value) VALUES (?1, ?2, ?3, 0, ?4)
         ON CONFLICT (root) DO UPDATE SET
           base = excluded.base, put_at = excluded.put_at, encoding = 0, value = excluded.value",
        params![root, base, now, bytes],
    )?;
    Ok(true)
}

/// Delete these records by key. Returns the ones that existed, with the
/// bytes the caller gave, in the caller's order.
pub(crate) fn remove(
    conn: &Connection,
    doomed: Vec<StoredEnvelope>,
) -> rusqlite::Result<Vec<StoredEnvelope>> {
    let mut stmt = conn.prepare("DELETE FROM attestations WHERE key = ?1")?;
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
    let mut stmt = conn.prepare(
        "DELETE FROM manifests WHERE root = ?1
           AND NOT EXISTS (SELECT 1 FROM attestations WHERE manifest_ref = ?1)
           AND NOT EXISTS (SELECT 1 FROM manifests WHERE base = ?1)",
    )?;
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
    let mut stmt = conn.prepare(
        "INSERT INTO memo (tree16, test_key, key, at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (tree16, test_key) DO UPDATE SET key = excluded.key, at = excluded.at",
    )?;
    for (tk, k) in items {
        stmt.execute(params![tree16, tk, k, now])?;
    }
    conn.execute(
        "DELETE FROM memo WHERE at < ?1",
        [now.saturating_sub(MEMO_KEEP_SECS)],
    )?;
    Ok(())
}

/// Flag `name`.
pub(crate) fn set_flag(conn: &Connection, name: &str, now: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO flags (name, at) VALUES (?1, ?2) ON CONFLICT (name) DO NOTHING",
        params![name, now],
    )?;
    Ok(())
}
