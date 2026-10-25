//! The deferred write batch (`docs/STORE-BACKENDS.md` sections 6 and 17).
//!
//! While a batch of a store is open on a thread, that thread's `put`,
//! `put_manifest` and `remove` through the store are queued, deduplicated
//! (by slot, root and key; the last call wins), and written at
//! [`WriteBatch::finish`] in one transaction: the manifests (one UNNEST
//! upsert), then the attestations (one UNNEST upsert), then the removals
//! (one `DELETE … = ANY`). A queue of [`FLUSH_WRITES`] attestations and
//! removals, or of [`FLUSH_BYTES`], is written early in a transaction of
//! its own; a failed early write fails `finish`.

use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use postgres::types::Type;
use vci_store::timing::Step;
use vci_store::{BatchEnd, NewAttestation, StoreError, StoredEnvelope, WriteBatch, key};

use crate::Inner;
use crate::conn::{Fail, KIND, WRITE};
use crate::schema;
use crate::write::{check_manifest, manifest_base, manifest_ref, slot_key};

/// Attestations and removals queued before they are written early.
pub(crate) const FLUSH_WRITES: usize = 2_000;
/// Bytes queued before they are written early.
pub(crate) const FLUSH_BYTES: usize = 32 << 20;

/// The batch statements of one schema.
pub(crate) struct Sql {
    manifests: String,
    attestations: String,
    remove: String,
}

impl Sql {
    pub(crate) fn new(s: &str) -> Sql {
        let a = format!("\"{s}\".attestations");
        let m = format!("\"{s}\".manifests");
        Sql {
            manifests: format!(
                "INSERT INTO {m} AS m (ns, root, base, value) \
                 SELECT $1, u.root, u.base, u.value \
                 FROM unnest($2::text[], $3::text[], $4::bytea[]) AS u(root, base, value) \
                 ON CONFLICT (ns, root) DO UPDATE SET \
                   value = CASE WHEN m.value IS DISTINCT FROM EXCLUDED.value OR m.encoding <> 0 \
                     THEN EXCLUDED.value ELSE m.value END, \
                   base = EXCLUDED.base, encoding = 0, put_at = now()"
            ),
            attestations: format!(
                "INSERT INTO {a} AS a (ns, key, test_key, signer, storage_key, target, issued, \
                   tree16, manifest_ref, ref_state, value) \
                 SELECT $1, u.key, u.test_key, u.signer, u.storage_key, u.target, u.issued, \
                   u.tree16, u.manifest_ref, u.ref_state, u.value \
                 FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], \
                   $7::int8[], $8::text[], $9::text[], $10::int2[], $11::bytea[]) \
                   AS u(key, test_key, signer, storage_key, target, issued, tree16, manifest_ref, \
                     ref_state, value) \
                 ON CONFLICT (ns, test_key, signer, storage_key) DO UPDATE SET \
                   key = EXCLUDED.key, target = EXCLUDED.target, issued = EXCLUDED.issued, \
                   tree16 = EXCLUDED.tree16, manifest_ref = EXCLUDED.manifest_ref, \
                   ref_state = EXCLUDED.ref_state, encoding = 0, value = EXCLUDED.value, \
                   stored_at = now(), stored_by = session_user \
                 WHERE (a.key, a.value, a.encoding) IS DISTINCT FROM \
                   (EXCLUDED.key, EXCLUDED.value, EXCLUDED.encoding)"
            ),
            remove: format!("DELETE FROM {a} WHERE ns = $1 AND key = ANY($2)"),
        }
    }
}

/// One queued attestation.
struct Row {
    key: String,
    target: String,
    manifest_ref: Option<String>,
    ref_state: i16,
    value: Vec<u8>,
}

/// (test key, signer, storage key).
type Slot = (String, String, String);

/// What a batch holds and has not written yet.
#[derive(Default)]
struct Pending {
    manifests: BTreeMap<String, (Option<String>, Vec<u8>)>,
    attestations: BTreeMap<Slot, Row>,
    removals: BTreeSet<String>,
    bytes: usize,
    /// An early write failed: the batch fails, and later writes are
    /// dropped.
    failed: Option<StoreError>,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.manifests.is_empty() && self.attestations.is_empty() && self.removals.is_empty()
    }

    fn full(&self) -> bool {
        self.attestations.len() + self.removals.len() >= FLUSH_WRITES || self.bytes >= FLUSH_BYTES
    }

    /// The queue, leaving an empty one (and the failure) in place.
    fn take(&mut self) -> Pending {
        Pending {
            manifests: std::mem::take(&mut self.manifests),
            attestations: std::mem::take(&mut self.attestations),
            removals: std::mem::take(&mut self.removals),
            bytes: std::mem::take(&mut self.bytes),
            failed: None,
        }
    }
}

thread_local! {
    /// The batches open on this thread, by store handle.
    static OPEN: RefCell<HashMap<u64, Pending>> = RefCell::new(HashMap::new());
}

/// Run `f` on this thread's open batch of `inner`, if there is one.
fn with_pending<T>(inner: &Inner, f: impl FnOnce(&mut Pending) -> T) -> Option<T> {
    OPEN.try_with(|o| o.borrow_mut().get_mut(&inner.id).map(f))
        .ok()
        .flatten()
}

/// Whether a batch of `inner` is open on this thread.
pub(crate) fn is_open(inner: &Inner) -> bool {
    with_pending(inner, |_| ()).is_some()
}

/// Open a deferred batch on this thread. A batch already open on this
/// thread keeps every write, so a second one groups nothing.
pub(crate) fn open(inner: &Arc<Inner>) -> Result<WriteBatch, StoreError> {
    inner.ready()?;
    let fresh = OPEN
        .try_with(|o| match o.borrow_mut().entry(inner.id) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                v.insert(Pending::default());
                true
            }
        })
        .unwrap_or(false);
    if !fresh {
        return Ok(WriteBatch::none());
    }
    Ok(WriteBatch::deferred(Box::new(End {
        inner: Arc::clone(inner),
    })))
}

struct End {
    inner: Arc<Inner>,
}

impl BatchEnd for End {
    fn finish(self: Box<Self>) -> Result<(), StoreError> {
        let p = OPEN
            .try_with(|o| o.borrow_mut().remove(&self.inner.id))
            .ok()
            .flatten()
            .unwrap_or_default();
        if let Some(e) = p.failed {
            return Err(e);
        }
        write(&self.inner, p)
    }
}

/// Write the queue early when it is full.
fn flush_if_full(inner: &Inner) {
    let Some(p) = with_pending(inner, |p| {
        (p.failed.is_none() && p.full()).then(|| p.take())
    })
    .flatten() else {
        return;
    };
    if let Err(e) = write(inner, p) {
        with_pending(inner, |p| {
            p.failed.get_or_insert(e);
        });
    }
}

/// Queue `att`; the entry it will be stored as.
pub(crate) fn put(inner: &Inner, att: &NewAttestation<'_>) -> Result<StoredEnvelope, StoreError> {
    att.validate()?;
    let ns = inner.ready()?;
    let slot: Slot = (
        att.test_key.clone(),
        att.signer.to_owned(),
        att.storage_key.to_owned(),
    );
    let key = match att.hinted_key() {
        Some(k) => k,
        None => {
            // Without a hint the slot keeps its key: the one queued, else
            // the one stored (one read), else the plain key.
            let queued =
                with_pending(inner, |p| p.attestations.get(&slot).map(|r| r.key.clone())).flatten();
            match queued {
                Some(k) => k,
                None => slot_key(inner, ns, att)?.unwrap_or_else(|| att.plain_key()),
            }
        }
    };
    let (mref, ref_state) = manifest_ref(att.envelope);
    let row = Row {
        key: key.clone(),
        target: att.target.clone(),
        manifest_ref: mref,
        ref_state,
        value: att.envelope.to_vec(),
    };
    with_pending(inner, |p| {
        if p.failed.is_some() {
            return;
        }
        p.removals.remove(&key);
        p.bytes += row.value.len() + row.key.len();
        if let Some(old) = p.attestations.insert(slot, row) {
            p.bytes = p.bytes.saturating_sub(old.value.len() + old.key.len());
        }
    });
    flush_if_full(inner);
    Ok(att.stored(key))
}

/// Queue a manifest; whether the bytes will change (as far as the batch
/// knows: `true` unless it holds these bytes already).
pub(crate) fn put_manifest(inner: &Inner, root: &str, bytes: &[u8]) -> Result<bool, StoreError> {
    check_manifest(root, bytes)?;
    inner.ready()?;
    let base = manifest_base(bytes);
    let changed = with_pending(inner, |p| {
        if p.failed.is_some() {
            return true;
        }
        let same = p.manifests.get(root).is_some_and(|(_, b)| b == bytes);
        p.bytes += bytes.len();
        if let Some((_, old)) = p.manifests.insert(root.to_owned(), (base, bytes.to_vec())) {
            p.bytes = p.bytes.saturating_sub(old.len());
        }
        !same
    })
    .unwrap_or(true);
    flush_if_full(inner);
    Ok(changed)
}

/// Queue removals; every entry asked for (once per key).
pub(crate) fn remove(
    inner: &Inner,
    doomed: Vec<StoredEnvelope>,
) -> Result<Vec<StoredEnvelope>, StoreError> {
    if doomed.is_empty() {
        return Ok(doomed);
    }
    inner.ready()?;
    with_pending(inner, |p| {
        if p.failed.is_some() {
            return;
        }
        for e in &doomed {
            if let Some((tk, signer, sk)) = key::parse_key(&e.key) {
                let slot: Slot = (tk.to_owned(), signer.to_owned(), sk.to_owned());
                if p.attestations.get(&slot).is_some_and(|r| r.key == e.key)
                    && let Some(old) = p.attestations.remove(&slot)
                {
                    p.bytes = p.bytes.saturating_sub(old.value.len() + old.key.len());
                }
            }
            p.removals.insert(e.key.clone());
        }
    });
    flush_if_full(inner);
    let mut seen = BTreeSet::new();
    Ok(doomed
        .into_iter()
        .filter(|e| seen.insert(e.key.clone()))
        .collect())
}

/// Write `p` in one transaction, then bring the cache up to date.
fn write(inner: &Inner, p: Pending) -> Result<(), StoreError> {
    if p.is_empty() {
        return Ok(());
    }
    let ns = inner.ready()?;
    let step = Step::start(KIND);
    let n0 = inner.conn.statements();
    let only_removals = p.manifests.is_empty() && p.attestations.is_empty();
    if !only_removals {
        schema::ensure(inner)?;
    }
    let m_roots: Vec<&str> = p.manifests.keys().map(String::as_str).collect();
    let m_bases: Vec<Option<&str>> = p.manifests.values().map(|(b, _)| b.as_deref()).collect();
    let m_values: Vec<&[u8]> = p.manifests.values().map(|(_, v)| v.as_slice()).collect();
    let mut a_keys: Vec<&str> = Vec::new();
    let mut a_tks: Vec<&str> = Vec::new();
    let mut a_signers: Vec<&str> = Vec::new();
    let mut a_sks: Vec<&str> = Vec::new();
    let mut a_targets: Vec<&str> = Vec::new();
    let mut a_issued: Vec<Option<i64>> = Vec::new();
    let mut a_trees: Vec<Option<String>> = Vec::new();
    let mut a_refs: Vec<Option<&str>> = Vec::new();
    let mut a_states: Vec<i16> = Vec::new();
    let mut a_values: Vec<&[u8]> = Vec::new();
    for ((tk, signer, sk), r) in &p.attestations {
        let hint = key::parse_key_hint(&r.key);
        a_keys.push(&r.key);
        a_tks.push(tk);
        a_signers.push(signer);
        a_sks.push(sk);
        a_targets.push(&r.target);
        a_issued.push(hint.as_ref().map(|h| h.issued));
        a_trees.push(hint.and_then(|h| h.tree));
        a_refs.push(r.manifest_ref.as_deref());
        a_states.push(r.ref_state);
        a_values.push(&r.value);
    }
    let removals: Vec<&str> = p.removals.iter().map(String::as_str).collect();
    let sql = &inner.batch_sql;
    let r = inner.conn.run(WRITE, |db| {
        let mut tx = db.tx()?;
        if !m_roots.is_empty() {
            tx.execute(
                &sql.manifests,
                &[
                    (&ns, Type::TEXT),
                    (&m_roots, Type::TEXT_ARRAY),
                    (&m_bases, Type::TEXT_ARRAY),
                    (&m_values, Type::BYTEA_ARRAY),
                ],
            )?;
        }
        if !a_keys.is_empty() {
            tx.execute(
                &sql.attestations,
                &[
                    (&ns, Type::TEXT),
                    (&a_keys, Type::TEXT_ARRAY),
                    (&a_tks, Type::TEXT_ARRAY),
                    (&a_signers, Type::TEXT_ARRAY),
                    (&a_sks, Type::TEXT_ARRAY),
                    (&a_targets, Type::TEXT_ARRAY),
                    (&a_issued, Type::INT8_ARRAY),
                    (&a_trees, Type::TEXT_ARRAY),
                    (&a_refs, Type::TEXT_ARRAY),
                    (&a_states, Type::INT2_ARRAY),
                    (&a_values, Type::BYTEA_ARRAY),
                ],
            )?;
        }
        if !removals.is_empty() {
            tx.execute(
                &sql.remove,
                &[(&ns, Type::TEXT), (&removals, Type::TEXT_ARRAY)],
            )?;
        }
        tx.commit()
    });
    match r {
        Ok(()) => {}
        // Only removals, and no schema: nothing to remove.
        Err(Fail::Absent) if only_removals => {}
        Err(Fail::Absent) => {
            return Err(StoreError::NotInitialized {
                backend: KIND,
                advice: schema::advice(&inner.schema),
            });
        }
        Err(Fail::Store(e)) => return Err(e),
    }
    step.done(format_args!(
        "write batch: {} manifest(s), {} attestation(s), {} removal(s), {} statement(s)",
        m_roots.len(),
        a_keys.len(),
        removals.len(),
        inner.conn.statements() - n0
    ));
    let mut c = inner.cache();
    for (root, (_, bytes)) in &p.manifests {
        c.manifest_put(root, bytes);
    }
    for r in p.attestations.into_values() {
        if let Some(mut e) = StoredEnvelope::from_key(r.target, &r.key) {
            e.set_value(r.value);
            c.put(&e);
        }
    }
    for k in &p.removals {
        c.removed(k);
    }
    Ok(())
}
