//! Writes to the server (`docs/STORE-BACKENDS.md` sections 6 and 18).
//!
//! Every write is a transaction sent in one request, which takes the write
//! lock before its first statement ([`crate::conn::Conn::batch`]): a write
//! outside a batch is a batch of one. While a batch of a store is open on a
//! thread, that thread's `put`, `put_manifest` and `remove` through the
//! store are queued and written when the batch finishes, ending in the
//! state the same calls made one by one would reach: per slot the last put
//! (which replaces every stored key of its slot), whether a later removal
//! took that put's key away again (the slot ends empty), and the keys
//! removed otherwise; per root the last manifest. It is written as the
//! manifests, the removed keys, the emptied slots, then the attestations,
//! each one statement with its values as literals, plus the change log a
//! replica syncs from, in one transaction. A queue of [`FLUSH_WRITES`]
//! attestations and removals, or of [`FLUSH_BYTES`], is written early in a
//! transaction of its own; a failed early write fails `finish`.
//!
//! A record a server would refuse as too big ([`MAX_RECORD`] bytes or
//! more: `sqld` keeps rows under 5,000,000 bytes) is refused before it is
//! queued or sent, as [`StoreError::Unsupported`]: that unit is not
//! attested, and the rest of the batch is stored.

use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use libsql::Value as V;
use vci_store::timing::Step;
use vci_store::{
    BatchEnd, ManifestRef, NewAttestation, StoreError, StoredEnvelope, WriteBatch, key,
};

use crate::conn::{
    Fail, KIND, MAX_RECORD, READ, TOO_BIG, WRITE, blob, col_int, col_text, json_list, opt_int,
    opt_text, text,
};
use crate::remote::{LOG_KEEP_SECS, Remote, Tables, now};

/// Attestations and removals queued before they are written early.
pub(crate) const FLUSH_WRITES: usize = 2_000;
/// Bytes queued before they are written early: one request stays a few
/// megabytes.
pub(crate) const FLUSH_BYTES: usize = 8 << 20;

/// One queued attestation.
#[derive(Debug, Clone)]
pub(crate) struct Row {
    pub(crate) key: String,
    pub(crate) target: String,
    manifest_ref: Option<String>,
    ref_state: i64,
    pub(crate) value: Vec<u8>,
}

/// (test key, signer, storage key).
pub(crate) type Slot = (String, String, String);

/// What is done after a queue was written (a replica writes it through).
pub(crate) type After = Arc<dyn Fn(&Pending) + Send + Sync>;

/// What a batch holds and has not written yet.
#[derive(Default)]
pub(crate) struct Pending {
    pub(crate) manifests: BTreeMap<String, (Option<String>, Vec<u8>)>,
    pub(crate) attestations: BTreeMap<Slot, Row>,
    /// Slots whose queued put was removed again: they end empty.
    pub(crate) emptied: BTreeSet<Slot>,
    pub(crate) removals: BTreeSet<String>,
    bytes: usize,
    /// An early write failed: the batch fails, and later writes are
    /// dropped.
    failed: Option<StoreError>,
    after: Option<After>,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.manifests.is_empty()
            && self.attestations.is_empty()
            && self.emptied.is_empty()
            && self.removals.is_empty()
    }

    fn full(&self) -> bool {
        self.attestations.len() + self.emptied.len() + self.removals.len() >= FLUSH_WRITES
            || self.bytes >= FLUSH_BYTES
    }

    /// The queue, leaving an empty one (and the failure and the hook) in
    /// place.
    fn take(&mut self) -> Pending {
        Pending {
            manifests: std::mem::take(&mut self.manifests),
            attestations: std::mem::take(&mut self.attestations),
            emptied: std::mem::take(&mut self.emptied),
            removals: std::mem::take(&mut self.removals),
            bytes: std::mem::take(&mut self.bytes),
            failed: None,
            after: self.after.clone(),
        }
    }
}

thread_local! {
    /// The batches open on this thread, by store handle.
    static OPEN: RefCell<HashMap<u64, Pending>> = RefCell::new(HashMap::new());
}

/// Run `f` on this thread's open batch of `remote`, if there is one.
fn with_pending<T>(remote: &Remote, f: impl FnOnce(&mut Pending) -> T) -> Option<T> {
    OPEN.try_with(|o| o.borrow_mut().get_mut(&remote.id).map(f))
        .ok()
        .flatten()
}

/// Whether a batch of `remote` is open on this thread.
pub(crate) fn is_open(remote: &Remote) -> bool {
    with_pending(remote, |_| ()).is_some()
}

/// The roots the open batch of `remote` on this thread will reference once
/// written (its attestations' manifests, its manifests and their bases),
/// or `None` without an open batch. `remove_manifests` keeps them: the
/// server cannot see them yet.
pub(crate) fn queued_roots(remote: &Remote) -> Option<BTreeSet<String>> {
    with_pending(remote, |p| {
        let mut roots: BTreeSet<String> = p
            .attestations
            .values()
            .filter_map(|r| r.manifest_ref.clone())
            .collect();
        for (root, (base, _)) in &p.manifests {
            roots.insert(root.clone());
            roots.extend(base.clone());
        }
        roots
    })
}

/// Open a deferred batch on this thread; `after` runs once each part of it
/// is written. A batch already open on this thread keeps every write, so a
/// second one groups nothing.
pub(crate) fn open(remote: &Arc<Remote>, after: Option<After>) -> Result<WriteBatch, StoreError> {
    remote.ready()?;
    let fresh = OPEN
        .try_with(|o| match o.borrow_mut().entry(remote.id) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                v.insert(Pending {
                    after,
                    ..Pending::default()
                });
                true
            }
        })
        .unwrap_or(false);
    if !fresh {
        return Ok(WriteBatch::none());
    }
    Ok(WriteBatch::deferred(Box::new(End {
        remote: Arc::clone(remote),
    })))
}

struct End {
    remote: Arc<Remote>,
}

impl BatchEnd for End {
    fn finish(self: Box<Self>) -> Result<(), StoreError> {
        let p = OPEN
            .try_with(|o| o.borrow_mut().remove(&self.remote.id))
            .ok()
            .flatten()
            .unwrap_or_default();
        if let Some(e) = p.failed {
            return Err(e);
        }
        write(&self.remote, &p)
    }
}

/// Write the queue early when it is full.
fn flush_if_full(remote: &Remote) {
    let Some(p) = with_pending(remote, |p| {
        (p.failed.is_none() && p.full()).then(|| p.take())
    })
    .flatten() else {
        return;
    };
    if let Err(e) = write(remote, &p) {
        with_pending(remote, |p| {
            p.failed.get_or_insert(e);
        });
    }
}

/// The manifest an envelope's (unverified) payload references, as the
/// `manifest_ref` and `ref_state` columns.
fn manifest_ref(envelope: &[u8]) -> (Option<String>, i64) {
    use vci_store_sqlite::sql::{REF_INLINE, REF_ROOT, REF_UNKNOWN};
    match key::envelope_manifest_ref(envelope) {
        ManifestRef::Root(r) => (Some(r), REF_ROOT),
        ManifestRef::Inline => (None, REF_INLINE),
        ManifestRef::Unknown => (None, REF_UNKNOWN),
    }
}

/// The base a manifest's compact bytes name, if any.
fn manifest_base(bytes: &[u8]) -> Option<String> {
    vci_core::InputManifest::compact_base(bytes)
        .ok()
        .flatten()
        .filter(|b| key::is_hex_id(b))
}

/// Check a manifest write's arguments, as every backend does, and that the
/// server would take its row.
pub(crate) fn check_manifest(root: &str, bytes: &[u8]) -> Result<(), StoreError> {
    key::check_hex("input root", root)?;
    if bytes.is_empty() {
        return Err(StoreError::invalid("manifest", "", "must not be empty"));
    }
    key::check_utf8("manifest", bytes)?;
    // The row: the root, its base, the value, the integers and the
    // record's header.
    check_size(bytes.len() + 2 * 64 + 64)
}

/// Refuse a record of [`MAX_RECORD`] bytes or more.
fn check_size(record: usize) -> Result<(), StoreError> {
    if record >= MAX_RECORD {
        return Err(StoreError::Unsupported {
            backend: KIND,
            operation: TOO_BIG,
        });
    }
    Ok(())
}

/// Check that the server would take `att`'s row: its value, its key (at
/// most the slot's parts and a hint), the slot's columns, the target, the
/// manifest reference, the tree, the integers and the record's header.
fn check_attestation_size(att: &NewAttestation<'_>) -> Result<(), StoreError> {
    let slot = att.test_key.len() + att.signer.len() + att.storage_key.len();
    check_size(att.envelope.len() + att.target.len() + 2 * slot + 64 + 64 + 16 + 128)
}

/// The key a slot is stored under on the server (one request), if any.
fn slot_key(
    remote: &Remote,
    t: &Tables,
    att: &NewAttestation<'_>,
) -> Result<Option<String>, StoreError> {
    let r = remote.query(
        READ,
        &t.shared.slot_key,
        vec![
            V::Text(att.test_key.clone()),
            V::Text(att.signer.to_owned()),
            V::Text(att.storage_key.to_owned()),
        ],
    );
    Ok(Fail::or_absent(r, Vec::new)?
        .first()
        .and_then(|row| row.first().and_then(col_text)))
}

fn row_of(att: &NewAttestation<'_>, key: String) -> Row {
    let (manifest_ref, ref_state) = manifest_ref(att.envelope);
    Row {
        key,
        target: att.target.clone(),
        manifest_ref,
        ref_state,
        value: att.envelope.to_vec(),
    }
}

fn slot_of(att: &NewAttestation<'_>) -> Slot {
    (
        att.test_key.clone(),
        att.signer.to_owned(),
        att.storage_key.to_owned(),
    )
}

// ---- writes inside a batch ------------------------------------------------------------

/// Queue `att`; the entry it will be stored as.
pub(crate) fn put(remote: &Remote, att: &NewAttestation<'_>) -> Result<StoredEnvelope, StoreError> {
    att.validate()?;
    check_attestation_size(att)?;
    let t = remote.ready()?;
    let slot = slot_of(att);
    let key = match att.hinted_key() {
        Some(k) => k,
        None => {
            // Without a hint the slot keeps its key: the one queued, else
            // the one stored (one request) unless the batch removes it,
            // else the plain key.
            let queued = with_pending(remote, |p| {
                if let Some(r) = p.attestations.get(&slot) {
                    Some(Some(r.key.clone()))
                } else if p.emptied.contains(&slot) {
                    Some(None)
                } else {
                    None
                }
            })
            .flatten();
            match queued {
                Some(Some(k)) => k,
                Some(None) => att.plain_key(),
                None => slot_key(remote, t, att)?
                    .filter(|k| !with_pending(remote, |p| p.removals.contains(k)).unwrap_or(false))
                    .unwrap_or_else(|| att.plain_key()),
            }
        }
    };
    let row = row_of(att, key.clone());
    with_pending(remote, |p| {
        if p.failed.is_some() {
            return;
        }
        // The put replaces the slot whatever was queued for it.
        p.removals.remove(&key);
        p.emptied.remove(&slot);
        p.bytes += row.value.len() + row.key.len();
        if let Some(old) = p.attestations.insert(slot, row) {
            p.bytes = p.bytes.saturating_sub(old.value.len() + old.key.len());
        }
    });
    flush_if_full(remote);
    Ok(att.stored(key))
}

/// Queue a manifest; whether the bytes will change (as far as the batch
/// knows: `true` unless it holds these bytes already).
pub(crate) fn put_manifest(remote: &Remote, root: &str, bytes: &[u8]) -> Result<bool, StoreError> {
    check_manifest(root, bytes)?;
    remote.ready()?;
    let base = manifest_base(bytes);
    let changed = with_pending(remote, |p| {
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
    flush_if_full(remote);
    Ok(changed)
}

/// Queue removals; every entry asked for (once per key).
pub(crate) fn remove(
    remote: &Remote,
    doomed: Vec<StoredEnvelope>,
) -> Result<Vec<StoredEnvelope>, StoreError> {
    if doomed.is_empty() {
        return Ok(doomed);
    }
    remote.ready()?;
    with_pending(remote, |p| {
        if p.failed.is_some() {
            return;
        }
        for e in &doomed {
            if let Some((tk, signer, sk)) = key::parse_key(&e.key) {
                let slot: Slot = (tk.to_owned(), signer.to_owned(), sk.to_owned());
                if p.attestations.get(&slot).is_some_and(|r| r.key == e.key)
                    && let Some(old) = p.attestations.remove(&slot)
                {
                    // The queued put already replaced every stored key of
                    // its slot, and this removes its own: the slot ends
                    // empty.
                    p.bytes = p.bytes.saturating_sub(old.value.len() + old.key.len());
                    p.emptied.insert(slot);
                    continue;
                }
            }
            p.removals.insert(e.key.clone());
        }
    });
    flush_if_full(remote);
    let mut seen = BTreeSet::new();
    Ok(doomed
        .into_iter()
        .filter(|e| seen.insert(e.key.clone()))
        .collect())
}

// ---- writes outside a batch: a batch of one --------------------------------------------

/// Store one attestation now (one request; an unhinted put first asks for
/// its slot's key).
pub(crate) fn put_now(
    remote: &Remote,
    att: &NewAttestation<'_>,
    after: Option<&After>,
) -> Result<StoredEnvelope, StoreError> {
    att.validate()?;
    check_attestation_size(att)?;
    let t = remote.ready()?;
    let key = match att.hinted_key() {
        Some(k) => k,
        None => slot_key(remote, t, att)?.unwrap_or_else(|| att.plain_key()),
    };
    let mut p = Pending {
        after: after.cloned(),
        ..Pending::default()
    };
    p.attestations
        .insert(slot_of(att), row_of(att, key.clone()));
    write(remote, &p)?;
    Ok(att.stored(key))
}

/// Store a manifest now; whether the stored bytes changed. `put_at` is
/// refreshed either way (the grace period counts from the latest put).
pub(crate) fn put_manifest_now(
    remote: &Remote,
    root: &str,
    bytes: &[u8],
    after: Option<&After>,
) -> Result<bool, StoreError> {
    check_manifest(root, bytes)?;
    let t = remote.ready()?;
    let r = remote.query(
        READ,
        &t.shared.manifest_same,
        vec![V::Text(root.to_owned()), V::Blob(bytes.to_vec())],
    );
    let same = Fail::or_absent(r, Vec::new)?
        .first()
        .and_then(|row| row.first().and_then(col_int))
        == Some(1);
    let mut p = Pending {
        after: after.cloned(),
        ..Pending::default()
    };
    p.manifests
        .insert(root.to_owned(), (manifest_base(bytes), bytes.to_vec()));
    write(remote, &p)?;
    Ok(!same)
}

/// Remove these entries now; the ones that existed (one request to find
/// them, one to remove them). Every key asked for leaves this handle's
/// cache and a replica's file, also one the server no longer held.
pub(crate) fn remove_now(
    remote: &Remote,
    doomed: Vec<StoredEnvelope>,
    after: Option<&After>,
) -> Result<Vec<StoredEnvelope>, StoreError> {
    if doomed.is_empty() {
        return Ok(doomed);
    }
    let t = remote.ready()?;
    let keys: BTreeSet<&str> = doomed.iter().map(|e| e.key.as_str()).collect();
    let r = remote.query(
        READ,
        &t.existing_keys,
        vec![json_list(keys.iter().copied())],
    );
    let existing: BTreeSet<String> = Fail::or_absent(r, Vec::new)?
        .iter()
        .filter_map(|row| row.first().and_then(col_text))
        .collect();
    if !existing.is_empty() {
        send(
            remote,
            &Pending {
                removals: existing.clone(),
                ..Pending::default()
            },
        )?;
    }
    settle(
        remote,
        &Pending {
            removals: keys.iter().map(|k| (*k).to_owned()).collect(),
            after: after.cloned(),
            ..Pending::default()
        },
    );
    let mut seen = BTreeSet::new();
    Ok(doomed
        .into_iter()
        .filter(|e| existing.contains(&e.key) && seen.insert(e.key.clone()))
        .collect())
}

/// Remove the manifests under these roots that no attestation references,
/// no manifest uses as its base, and that were put before the grace
/// period; the roots removed.
pub(crate) fn remove_manifests_now(
    remote: &Remote,
    roots: &[&str],
) -> Result<Vec<String>, StoreError> {
    for r in roots {
        key::check_hex("input root", r)?;
    }
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let t = remote.ready()?;
    if remote.version()?.is_none() {
        return Ok(Vec::new());
    }
    let cut = now().saturating_sub(i64::try_from(remote.grace.as_secs()).unwrap_or(i64::MAX));
    let wanted: BTreeSet<&str> = roots.iter().copied().collect();
    let r = remote.query(
        READ,
        &t.removable,
        vec![json_list(wanted.iter().copied()), V::Integer(cut)],
    );
    let found: Vec<String> = Fail::or_absent(r, Vec::new)?
        .iter()
        .filter_map(|row| row.first().and_then(col_text))
        .collect();
    if found.is_empty() {
        return Ok(found);
    }
    let (a, m, log) = (&t.names.attestations, &t.names.manifests, &t.log);
    let list = found.iter().map(|r| text(r)).collect::<Vec<_>>().join(", ");
    let at = now();
    let stmts = vec![
        format!(
            "DELETE FROM {m} WHERE root IN ({list}) AND put_at <= {cut} \
             AND NOT EXISTS (SELECT 1 FROM {a} WHERE manifest_ref = {m}.root) \
             AND NOT EXISTS (SELECT 1 FROM {m} AS b WHERE b.base = {m}.root)"
        ),
        format!(
            "INSERT INTO {log} (root, at) VALUES {}",
            found
                .iter()
                .map(|r| format!("({}, {at})", text(r)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ];
    match remote.write(WRITE, &stmts) {
        Ok(()) | Err(Fail::Absent) => {}
        Err(Fail::Store(e)) => return Err(e),
    }
    let mut c = remote.cache();
    for r in &found {
        c.manifest_removed(r);
    }
    Ok(found)
}

// ---- writing a queue -------------------------------------------------------------------

/// The statements that log these slots and roots for replicas.
fn log_rows(log: &str, slots: &[&Slot], roots: &[&str], at: i64) -> Option<String> {
    let mut values: Vec<String> = slots
        .iter()
        .map(|(t, s, k)| format!("({}, {}, {}, NULL, {at})", text(t), text(s), text(k)))
        .collect();
    values.extend(
        roots
            .iter()
            .map(|r| format!("(NULL, NULL, NULL, {}, {at})", text(r))),
    );
    (!values.is_empty()).then(|| {
        format!(
            "INSERT INTO {log} (test_key, signer, storage_key, root, at) VALUES {}",
            values.join(", ")
        )
    })
}

/// Write `p` in one transaction (one request), then bring the cache up to
/// date and run the queue's hook.
pub(crate) fn write(remote: &Remote, p: &Pending) -> Result<(), StoreError> {
    if p.is_empty() {
        return Ok(());
    }
    send(remote, p)?;
    settle(remote, p);
    Ok(())
}

/// Write `p` to the server in one transaction (one request).
fn send(remote: &Remote, p: &Pending) -> Result<(), StoreError> {
    if p.is_empty() {
        return Ok(());
    }
    let only_removals = p.manifests.is_empty() && p.attestations.is_empty();
    let t = if only_removals {
        let t = remote.ready()?;
        if remote.version()?.is_none() {
            // Nothing stored, nothing to remove.
            return Ok(());
        }
        t
    } else {
        remote.ensure()?
    };
    let step = Step::start(KIND);
    let n0 = remote.conn.requests();
    let at = now();
    let (a, log) = (&t.names.attestations, &t.log);
    let mut stmts: Vec<String> = Vec::new();
    if !p.manifests.is_empty() {
        let rows: Vec<String> = p
            .manifests
            .iter()
            .map(|(root, (base, bytes))| {
                format!(
                    "({}, {}, {at}, 0, {})",
                    text(root),
                    opt_text(base.as_deref()),
                    blob(bytes)
                )
            })
            .collect();
        stmts.push(t.shared.upsert_manifests(&rows.join(", ")));
    }
    // Removals before the upsert: a put queued after a removal of its slot
    // replaces the slot anyway, and an emptied slot has no put.
    let mut removed_slots: Vec<Slot> = Vec::new();
    if !p.removals.is_empty() {
        stmts.push(format!(
            "DELETE FROM {a} WHERE key IN ({})",
            p.removals
                .iter()
                .map(|k| text(k))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        removed_slots.extend(p.removals.iter().filter_map(|k| {
            key::parse_key(k).map(|(t, s, x)| (t.to_owned(), s.to_owned(), x.to_owned()))
        }));
    }
    for (tk, signer, sk) in &p.emptied {
        stmts.push(format!(
            "DELETE FROM {a} WHERE test_key = {} AND signer = {} AND storage_key = {}",
            text(tk),
            text(signer),
            text(sk)
        ));
    }
    if !p.attestations.is_empty() {
        let rows: Vec<String> = p
            .attestations
            .iter()
            .map(|((tk, signer, sk), r)| {
                let hint = key::parse_key_hint(&r.key);
                format!(
                    "({}, {}, {}, {}, {}, {}, {}, {}, {}, {at}, {})",
                    text(&r.key),
                    text(tk),
                    text(signer),
                    text(sk),
                    text(&r.target),
                    opt_int(hint.as_ref().map(|h| h.issued)),
                    opt_text(hint.as_ref().and_then(|h| h.tree.as_deref())),
                    opt_text(r.manifest_ref.as_deref()),
                    r.ref_state,
                    blob(&r.value)
                )
            })
            .collect();
        stmts.push(t.shared.upsert_attestations(&rows.join(", ")));
    }
    let slots: Vec<&Slot> = removed_slots
        .iter()
        .chain(p.emptied.iter())
        .chain(p.attestations.keys())
        .collect();
    let roots: Vec<&str> = p.manifests.keys().map(String::as_str).collect();
    stmts.extend(log_rows(log, &slots, &roots, at));
    if !remote.log_pruned.swap(true, Ordering::Relaxed) {
        let cut = at.saturating_sub(LOG_KEEP_SECS);
        stmts.push(format!(
            "UPDATE vci_schema SET log_floor = max(log_floor, \
               coalesce((SELECT max(seq) FROM {log} WHERE at < {cut}), 0)) WHERE ns = {}",
            text(remote.ns()?)
        ));
        stmts.push(format!("DELETE FROM {log} WHERE at < {cut}"));
    }
    match remote.write(WRITE, &stmts) {
        Ok(()) => {}
        // Only removals, and no tables: nothing to remove.
        Err(Fail::Absent) if only_removals => return Ok(()),
        Err(Fail::Absent) => {
            return Err(StoreError::NotInitialized {
                backend: KIND,
                advice: "the namespace's tables went away while vci wrote: run it again".to_owned(),
            });
        }
        Err(Fail::Store(e)) => return Err(e),
    }
    step.done(format_args!(
        "write batch: {} manifest(s), {} attestation(s), {} removal(s), {} request(s)",
        p.manifests.len(),
        p.attestations.len(),
        p.removals.len() + p.emptied.len(),
        remote.conn.requests() - n0
    ));
    Ok(())
}

/// What a write changes besides the server: this handle's cache (it reads
/// its own writes and removals), then the queue's hook (a replica's file).
fn settle(remote: &Remote, p: &Pending) {
    {
        let mut c = remote.cache();
        for (root, (_, bytes)) in &p.manifests {
            c.manifest_put(root, bytes);
        }
        for k in &p.removals {
            c.removed(k);
        }
        for (tk, signer, sk) in &p.emptied {
            c.removed_slot(tk, signer, sk);
        }
        for r in p.attestations.values() {
            if let Some(mut e) = StoredEnvelope::from_key(r.target.clone(), &r.key) {
                e.set_value(r.value.clone());
                c.put(&e);
            }
        }
    }
    if let Some(after) = &p.after {
        after(p);
    }
}
