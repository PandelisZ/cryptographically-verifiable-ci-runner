//! Writes outside a batch (`docs/STORE-BACKENDS.md` section 17, "Writes"):
//! each is one statement, durable and visible to every reader when it
//! returns. The first write creates the schema.

use std::collections::{BTreeMap, BTreeSet};

use postgres::types::Type;
use vci_store::{ManifestRef, NewAttestation, StoreError, StoredEnvelope, key};

use crate::Inner;
use crate::conn::{Fail, KIND, WRITE};
use crate::schema::{self, State};

/// The write statements of one schema.
pub(crate) struct Sql {
    put_hinted: String,
    put_plain: String,
    slot_key: String,
    put_manifest: String,
    remove: String,
    remove_manifests: String,
    memo_put: String,
    memo_prune: String,
    flag_put: String,
}

/// The upsert of one attestation. A conflict on the slot replaces the
/// slot's record (whatever its key) in the same statement, so concurrent
/// puts of one slot leave one row; identical bytes under the same key
/// change nothing. When nothing changed, the stored key is read back in the
/// same statement.
fn put_sql(a: &str, hinted: bool) -> String {
    let set = if hinted {
        "key = EXCLUDED.key, target = EXCLUDED.target, issued = EXCLUDED.issued, \
         tree16 = EXCLUDED.tree16,"
    } else {
        // Without a hint the slot keeps its key (a rewrite in place).
        "target = EXCLUDED.target,"
    };
    let changed = if hinted {
        "(a.key, a.value, a.encoding) IS DISTINCT FROM (EXCLUDED.key, EXCLUDED.value, EXCLUDED.encoding)"
    } else {
        "(a.value, a.encoding) IS DISTINCT FROM (EXCLUDED.value, EXCLUDED.encoding)"
    };
    format!(
        "WITH up AS (\
           INSERT INTO {a} AS a (ns, key, test_key, signer, storage_key, target, issued, tree16, \
             manifest_ref, ref_state, value) \
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
           ON CONFLICT (ns, test_key, signer, storage_key) DO UPDATE SET {set} \
             manifest_ref = EXCLUDED.manifest_ref, ref_state = EXCLUDED.ref_state, encoding = 0, \
             value = EXCLUDED.value, stored_at = now(), stored_by = session_user \
           WHERE {changed} \
           RETURNING a.key) \
         SELECT key FROM up \
         UNION ALL \
         SELECT key FROM {a} WHERE ns = $1 AND test_key = $3 AND signer = $4 AND storage_key = $5 \
           AND NOT EXISTS (SELECT 1 FROM up)"
    )
}

impl Sql {
    pub(crate) fn new(s: &str) -> Sql {
        let a = format!("\"{s}\".attestations");
        let m = format!("\"{s}\".manifests");
        Sql {
            put_hinted: put_sql(&a, true),
            put_plain: put_sql(&a, false),
            slot_key: format!(
                "SELECT key FROM {a} WHERE ns = $1 AND test_key = $2 AND signer = $3 AND storage_key = $4"
            ),
            // The snapshot before the upsert says whether the bytes
            // change; `put_at` is refreshed either way (the grace period
            // of `remove_manifests` counts from the latest put), and
            // unchanged bytes are not rewritten.
            put_manifest: format!(
                "WITH old AS (SELECT value, encoding FROM {m} WHERE ns = $1 AND root = $2) \
                 INSERT INTO {m} AS m (ns, root, base, value) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (ns, root) DO UPDATE SET \
                   value = CASE WHEN m.value IS DISTINCT FROM EXCLUDED.value OR m.encoding <> 0 \
                     THEN EXCLUDED.value ELSE m.value END, \
                   base = EXCLUDED.base, encoding = 0, put_at = now() \
                 RETURNING COALESCE((SELECT value FROM old) IS DISTINCT FROM $4 \
                   OR (SELECT encoding FROM old) <> 0, true) AS changed"
            ),
            remove: format!("DELETE FROM {a} WHERE ns = $1 AND key = ANY($2) RETURNING key"),
            remove_manifests: format!(
                "DELETE FROM {m} AS m WHERE m.ns = $1 AND m.root = ANY($2) \
                   AND m.put_at <= now() - make_interval(secs => $3) \
                   AND NOT EXISTS (SELECT 1 FROM {a} x WHERE x.ns = $1 AND x.manifest_ref = m.root) \
                   AND NOT EXISTS (SELECT 1 FROM {m} b WHERE b.ns = $1 AND b.base = m.root) \
                 RETURNING m.root"
            ),
            memo_put: format!(
                "INSERT INTO \"{s}\".memo (ns, tree16, test_key, key) \
                 SELECT $1, $2, u.t, u.k FROM unnest($3::text[], $4::text[]) AS u(t, k) \
                 ON CONFLICT (ns, tree16, test_key) DO UPDATE SET key = EXCLUDED.key, at = now()"
            ),
            memo_prune: format!(
                "DELETE FROM \"{s}\".memo WHERE ns = $1 AND at < now() - interval '7 days'"
            ),
            flag_put: format!(
                "INSERT INTO \"{s}\".flags (ns, name) VALUES ($1, $2) \
                 ON CONFLICT (ns, name) DO UPDATE SET at = now()"
            ),
        }
    }
}

/// The manifest an envelope's (unverified) payload references, as the
/// `manifest_ref` and `ref_state` columns: 1 a root, 2 inline, 0 unknown.
pub(crate) fn manifest_ref(envelope: &[u8]) -> (Option<String>, i16) {
    match key::envelope_manifest_ref(envelope) {
        ManifestRef::Root(r) => (Some(r), 1),
        ManifestRef::Inline => (None, 2),
        ManifestRef::Unknown => (None, 0),
    }
}

/// The base a manifest's compact bytes name, if any.
pub(crate) fn manifest_base(bytes: &[u8]) -> Option<String> {
    vci_core::InputManifest::compact_base(bytes)
        .ok()
        .flatten()
        .filter(|b| key::is_hex_id(b))
}

/// Check a manifest write's arguments, as every backend does.
pub(crate) fn check_manifest(root: &str, bytes: &[u8]) -> Result<(), StoreError> {
    key::check_hex("input root", root)?;
    if bytes.is_empty() {
        return Err(StoreError::invalid("manifest", "", "must not be empty"));
    }
    key::check_utf8("manifest", bytes)?;
    Ok(())
}

/// A write found the schema gone after it made sure it was there.
fn gone(inner: &Inner) -> StoreError {
    StoreError::NotInitialized {
        backend: KIND,
        advice: schema::advice(&inner.schema),
    }
}

/// The key the slot of `att` is stored under, if it is stored.
pub(crate) fn slot_key(
    inner: &Inner,
    ns: &str,
    att: &NewAttestation<'_>,
) -> Result<Option<String>, StoreError> {
    let r = inner.conn.run(WRITE, |db| {
        db.query(
            &inner.write_sql.slot_key,
            &[
                (&ns, Type::TEXT),
                (&att.test_key, Type::TEXT),
                (&att.signer, Type::TEXT),
                (&att.storage_key, Type::TEXT),
            ],
        )
    });
    let rows = Fail::or_absent(r, Vec::new)?;
    rows.first()
        .map(|r| r.try_get::<_, String>(0))
        .transpose()
        .map_err(|e| inner.decode_error(&e))
}

pub(crate) fn put(inner: &Inner, att: &NewAttestation<'_>) -> Result<StoredEnvelope, StoreError> {
    att.validate()?;
    let ns = inner.ready()?;
    schema::ensure(inner)?;
    let hinted = att.hinted_key();
    let insert_key = hinted.clone().unwrap_or_else(|| att.plain_key());
    let hint = key::parse_key_hint(&insert_key);
    let issued: Option<i64> = hint.as_ref().map(|h| h.issued);
    let tree16: Option<String> = hint.and_then(|h| h.tree);
    let (mref, ref_state) = manifest_ref(att.envelope);
    let sql = if hinted.is_some() {
        &inner.write_sql.put_hinted
    } else {
        &inner.write_sql.put_plain
    };
    let r = inner.conn.run(WRITE, |db| {
        db.query(
            sql,
            &[
                (&ns, Type::TEXT),
                (&insert_key, Type::TEXT),
                (&att.test_key, Type::TEXT),
                (&att.signer, Type::TEXT),
                (&att.storage_key, Type::TEXT),
                (&att.target, Type::TEXT),
                (&issued, Type::INT8),
                (&tree16, Type::TEXT),
                (&mref, Type::TEXT),
                (&ref_state, Type::INT2),
                (&att.envelope, Type::BYTEA),
            ],
        )
    });
    let rows = match r {
        Ok(rows) => rows,
        Err(Fail::Absent) => return Err(gone(inner)),
        Err(Fail::Store(e)) => return Err(e),
    };
    let returned = rows
        .first()
        .map(|r| r.try_get::<_, String>(0))
        .transpose()
        .map_err(|e| inner.decode_error(&e))?;
    let key = match (returned, hinted) {
        (Some(k), _) => k,
        (None, Some(k)) => k,
        // Another writer committed the slot while this statement ran
        // (its snapshot did not see the row): read the key it kept.
        (None, None) => slot_key(inner, ns, att)?.unwrap_or(insert_key),
    };
    let stored = att.stored(key);
    inner.cache().put(&stored);
    Ok(stored)
}

pub(crate) fn put_manifest(inner: &Inner, root: &str, bytes: &[u8]) -> Result<bool, StoreError> {
    check_manifest(root, bytes)?;
    let ns = inner.ready()?;
    schema::ensure(inner)?;
    let base = manifest_base(bytes);
    let r = inner.conn.run(WRITE, |db| {
        db.query(
            &inner.write_sql.put_manifest,
            &[
                (&ns, Type::TEXT),
                (&root, Type::TEXT),
                (&base, Type::TEXT),
                (&bytes, Type::BYTEA),
            ],
        )
    });
    let rows = match r {
        Ok(rows) => rows,
        Err(Fail::Absent) => return Err(gone(inner)),
        Err(Fail::Store(e)) => return Err(e),
    };
    let changed = rows
        .first()
        .map(|r| r.try_get::<_, bool>(0))
        .transpose()
        .map_err(|e| inner.decode_error(&e))?
        .unwrap_or(true);
    inner.cache().manifest_put(root, bytes);
    Ok(changed)
}

pub(crate) fn remove(
    inner: &Inner,
    doomed: Vec<StoredEnvelope>,
) -> Result<Vec<StoredEnvelope>, StoreError> {
    if doomed.is_empty() {
        return Ok(Vec::new());
    }
    let ns = inner.ready()?;
    let keys: BTreeSet<&str> = doomed.iter().map(|e| e.key.as_str()).collect();
    let keys: Vec<&str> = keys.into_iter().collect();
    let r = inner.conn.run(WRITE, |db| {
        db.query(
            &inner.write_sql.remove,
            &[(&ns, Type::TEXT), (&keys, Type::TEXT_ARRAY)],
        )
    });
    let rows = Fail::or_absent(r, Vec::new)?;
    let mut gone: BTreeSet<String> = BTreeSet::new();
    for row in rows {
        gone.insert(row.try_get(0).map_err(|e| inner.decode_error(&e))?);
    }
    {
        let mut c = inner.cache();
        for k in &keys {
            c.removed(k);
        }
    }
    let mut seen = BTreeSet::new();
    Ok(doomed
        .into_iter()
        .filter(|e| gone.contains(&e.key) && seen.insert(e.key.clone()))
        .collect())
}

pub(crate) fn remove_manifests(inner: &Inner, roots: &[&str]) -> Result<usize, StoreError> {
    for r in roots {
        key::check_hex("input root", r)?;
    }
    if roots.is_empty() {
        return Ok(0);
    }
    let ns = inner.ready()?;
    let wanted: BTreeSet<&str> = roots.iter().copied().collect();
    let wanted: Vec<&str> = wanted.into_iter().collect();
    let grace = inner.grace.as_secs_f64();
    let r = inner.conn.run(WRITE, |db| {
        db.query(
            &inner.write_sql.remove_manifests,
            &[
                (&ns, Type::TEXT),
                (&wanted, Type::TEXT_ARRAY),
                (&grace, Type::FLOAT8),
            ],
        )
    });
    let rows = Fail::or_absent(r, Vec::new)?;
    let mut c = inner.cache();
    let mut n = 0;
    for row in rows {
        let root: String = row.try_get(0).map_err(|e| inner.decode_error(&e))?;
        c.manifest_removed(&root);
        n += 1;
    }
    Ok(n)
}

// ---- hints (never fail; they never create the schema) ------------------------------

/// The schema is there for a hint to be written.
fn hint_target(inner: &Inner) -> Option<&str> {
    let ns = inner.ready().ok()?;
    matches!(schema::check(inner), Ok(State::Version(_))).then_some(ns)
}

pub(crate) fn remember_passing(inner: &Inner, tree16: &str, items: &[(String, String)]) {
    if items.is_empty() {
        return;
    }
    let Some(ns) = hint_target(inner) else {
        return;
    };
    // One row per test key: the last item wins (an upsert may not touch a
    // row twice).
    let by_unit: BTreeMap<&str, &str> = items
        .iter()
        .map(|(t, k)| (t.as_str(), k.as_str()))
        .collect();
    let tks: Vec<&str> = by_unit.keys().copied().collect();
    let keys: Vec<&str> = by_unit.values().copied().collect();
    let r = inner.conn.run(WRITE, |db| {
        db.execute(
            &inner.write_sql.memo_put,
            &[
                (&ns, Type::TEXT),
                (&tree16, Type::TEXT),
                (&tks, Type::TEXT_ARRAY),
                (&keys, Type::TEXT_ARRAY),
            ],
        )
    });
    if r.is_ok()
        && let Some(m) = inner.memo_cache().get_mut(tree16)
    {
        for (t, k) in &by_unit {
            m.insert((*t).to_owned(), (*k).to_owned());
        }
    }
    // Forget entries older than a week, once per handle (a role that may
    // only insert and update the memo cannot, which is fine).
    if !inner
        .memo_pruned
        .swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        let _ = inner.conn.run(WRITE, |db| {
            db.execute(&inner.write_sql.memo_prune, &[(&ns, Type::TEXT)])
        });
    }
}

pub(crate) fn set_flag(inner: &Inner, name: &str) {
    if inner.flags().as_ref().is_some_and(|s| s.contains(name)) {
        return;
    }
    let Some(ns) = hint_target(inner) else {
        return;
    };
    let r = inner.conn.run(WRITE, |db| {
        db.execute(
            &inner.write_sql.flag_put,
            &[(&ns, Type::TEXT), (&name, Type::TEXT)],
        )
    });
    if r.is_ok()
        && let Some(s) = inner.flags().as_mut()
    {
        s.insert(name.to_owned());
    }
}
