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
//! replica syncs from; the manifests the write leaves without a reference
//! go in the same transaction (2.8.2, `superseded_manifests`), and values
//! are compressed when `VCI_STORE_COMPRESS=zstd` or `[store] compress`
//! asks for it. A queue of [`FLUSH_WRITES`] attestations and removals, or
//! of [`FLUSH_BYTES`], is written early, its whole units only
//! ([`Pending::take_whole_units`]).
//!
//! **Short transactions** (2.8.2). A queue is written as transactions of
//! whole units (every write of one test key, with the manifests its
//! attestations reference and their bases) of at most [`TX_BYTES`] as
//! sent or [`TX_UNITS`] attestations, one after the other, with a short
//! pause between them ([`yield_pause`]): each holds the server's one write
//! lock for one to a few seconds, not the 15 to 37 s an 8 MB transaction
//! held it on Turso (2.8.1). Another job's write (a hint, a shared
//! manifest, its own units) still waits behind every writer's transaction
//! that is waiting too: beside three processes writing at once on vex's
//! Turso database a manifest put waited up to 25 s and one-row writes up
//! to 47 s, with or without the pause, and a hint was sometimes dropped
//! at its 5 s deadline (section 18 of `docs/STORE-BACKENDS.md`).
//!
//! **Failures cost their own units.** A transaction that ran out of time
//! (or waited for the lock until then) is asked about first
//! ([`crate::conn::Conn::batch_checked`]: one the server committed is not
//! sent again), then sent again as it was after a pause; whichever of the
//! two the server applies second is refused as already committed ([`Tx`]),
//! so it is applied once. One the server refused is split down to the unit
//! that it refuses. Only the units whose transaction still fails are lost
//! ([`vci_store::Finished::lost`]): `vci run` refuses those and reports the
//! rest as stored. The time a process spends on writes that failed and on
//! the pauses between them is bounded by [`WRITE_RETRY_DEADLINES`]
//! request timeouts in all: past that the circuit breaker latches (a
//! server that cannot take writes is given up within a bounded time, not
//! once per transaction), and every write still queued fails at once. A
//! server that cannot be reached latches it at once, as before.
//!
//! A record a server would refuse as too big ([`MAX_RECORD`] bytes or
//! more: `sqld` keeps rows under 5,000,000 bytes) is refused before it is
//! queued or sent, as [`StoreError::Unsupported`]: that unit is not
//! attested, and the rest of the batch is stored.

use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use libsql::Value as V;
use vci_store::timing::Step;
use vci_store::{
    BatchEnd, Finished, ManifestRef, NewAttestation, StoreError, StoredEnvelope, WriteBatch, key,
};

use crate::conn::{
    Fail, KIND, MAX_RECORD, RAW, READ, TOO_BIG, WRITE, ZSTD, blob, col_int, col_text, compress,
    json_list, opt_int, opt_text, text,
};
use crate::remote::{LOG_KEEP_SECS, Remote, Tables, now};

/// Attestations and removals queued before they are written early.
pub(crate) const FLUSH_WRITES: usize = 2_000;
/// Bytes queued (values as they are) before they are written early, as
/// transactions of at most [`TX_BYTES`].
pub(crate) const FLUSH_BYTES: usize = 4 << 20;

/// The most bytes of values one transaction sends (as sent: compressed
/// when values are), unless one unit's writes alone are more. On vex's
/// Turso database from a laptop a transaction of 1 MB committed in 1.7 to
/// 3.7 s, of 2 MB in 2.5 to 10.6 s, of 4 MB in 5 to 10 s and of 8 MB in
/// 34 to 37 s (27 October 2026, while vex's CI wrote too): the time per
/// megabyte grows with the size, and every other writer waits for it.
pub(crate) const TX_BYTES: usize = 1 << 20;

/// The most attestations one transaction stores (about 30 of vex's units,
/// 36 kB each with their manifests as they are, fit in [`TX_BYTES`]).
pub(crate) const TX_UNITS: usize = 64;

/// The time a process may spend on write transactions that failed (ran
/// out of time, waited for the lock until their deadline) and on the
/// pauses before sending them again, in request timeouts: 60 s at the
/// default 30 s timeout. Past it the circuit breaker latches.
pub(crate) const WRITE_RETRY_DEADLINES: u32 = 2;

/// The pause after a transaction committed, before the next one of the
/// same write is sent, as a share of the time it took ([`yield_pause`]).
const YIELD_SHARE: f64 = 0.25;
/// The shortest such pause (before it is randomized).
const YIELD_MIN: Duration = Duration::from_millis(200);
/// The longest such pause (before it is randomized).
const YIELD_MAX: Duration = Duration::from_secs(2);

/// The most times one unit's writes are sent (each failure costing part
/// of the process's retry time).
const MAX_TRIES: u32 = 4;

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
#[derive(Default, Clone)]
pub(crate) struct Pending {
    pub(crate) manifests: BTreeMap<String, (Option<String>, Vec<u8>)>,
    pub(crate) attestations: BTreeMap<Slot, Row>,
    /// Slots whose queued put was removed again: they end empty.
    pub(crate) emptied: BTreeSet<Slot>,
    pub(crate) removals: BTreeSet<String>,
    bytes: usize,
    /// The test key of the last put or removal queued: its unit may still
    /// be queuing writes (the removals of what it supersedes follow its
    /// put), so an early write leaves it in the queue.
    last: Option<String>,
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

    /// The queue, leaving an empty one (and what was lost, and the hook)
    /// in place.
    fn take(&mut self) -> Pending {
        Pending {
            manifests: std::mem::take(&mut self.manifests),
            attestations: std::mem::take(&mut self.attestations),
            emptied: std::mem::take(&mut self.emptied),
            removals: std::mem::take(&mut self.removals),
            bytes: std::mem::take(&mut self.bytes),
            last: None,
            after: self.after.clone(),
        }
    }

    /// The bytes it holds, counted again.
    fn recount(&mut self) {
        self.bytes = self
            .attestations
            .values()
            .map(|r| r.value.len() + r.key.len())
            .chain(self.manifests.values().map(|(_, b)| b.len()))
            .sum();
    }

    /// The writes of whole units, for an early write: everything but the
    /// writes of the unit queued last (the removals of what it supersedes
    /// may follow), which stay queued with the manifests no attestation
    /// taken references (the next unit's, put before its attestation).
    /// The manifests the taken attestations reference, and their bases,
    /// go with them; copies stay queued of those the units left queued
    /// reference too and of every base, so that a later transaction never
    /// relies on one an earlier transaction lost (an early write's stored
    /// manifests are not sent again: [`Open::stored`]). A queue split
    /// anywhere else could store an attestation whose manifest was lost,
    /// or remove a superseded attestation whose successor was lost (a
    /// draft of 2.8.2).
    fn take_whole_units(&mut self) -> Pending {
        let mut out = self.take();
        if let Some(tk) = self.last.clone() {
            let slots: Vec<Slot> = out
                .attestations
                .keys()
                .filter(|s| s.0 == tk)
                .cloned()
                .collect();
            for slot in slots {
                if let Some(r) = out.attestations.remove(&slot) {
                    self.attestations.insert(slot, r);
                }
            }
            let emptied: Vec<Slot> = out.emptied.iter().filter(|s| s.0 == tk).cloned().collect();
            for slot in emptied {
                out.emptied.remove(&slot);
                self.emptied.insert(slot);
            }
            let removals: Vec<String> = out
                .removals
                .iter()
                .filter(|k| key::parse_key(k).is_some_and(|(t, _, _)| t == tk))
                .cloned()
                .collect();
            for k in removals {
                out.removals.remove(&k);
                self.removals.insert(k);
            }
        }
        let manifests = std::mem::take(&mut out.manifests);
        // The roots these attestations reference, and those roots' bases.
        let reach = |atts: &BTreeMap<Slot, Row>| -> BTreeSet<String> {
            let mut roots = BTreeSet::new();
            for r in atts.values() {
                if let Some(root) = &r.manifest_ref {
                    roots.insert(root.clone());
                    if let Some((Some(base), _)) = manifests.get(root) {
                        roots.insert(base.clone());
                    }
                }
            }
            roots
        };
        let taken = reach(&out.attestations);
        let left = reach(&self.attestations);
        let bases: BTreeSet<&String> = manifests.values().filter_map(|(b, _)| b.as_ref()).collect();
        for (root, m) in &manifests {
            if taken.contains(root) {
                out.manifests.insert(root.clone(), m.clone());
            }
            if !taken.contains(root) || left.contains(root) || bases.contains(root) {
                self.manifests.insert(root.clone(), m.clone());
            }
        }
        out.recount();
        self.recount();
        out
    }

    /// An empty queue with this one's hook.
    fn empty_like(&self) -> Pending {
        Pending {
            after: self.after.clone(),
            ..Pending::default()
        }
    }

    /// Add `other`'s writes (of other units) to this queue.
    fn merge(&mut self, other: Pending) {
        self.manifests.extend(other.manifests);
        self.attestations.extend(other.attestations);
        self.emptied.extend(other.emptied);
        self.removals.extend(other.removals);
        self.bytes += other.bytes;
    }

    /// The keys of the attestations it stores.
    fn keys(&self) -> impl Iterator<Item = String> + '_ {
        self.attestations.values().map(|r| r.key.clone())
    }

    /// Every root it references once written (its attestations' manifests,
    /// its manifests and their bases): no transaction of it removes them.
    fn referenced(&self) -> BTreeSet<String> {
        let mut roots: BTreeSet<String> = self
            .attestations
            .values()
            .filter_map(|r| r.manifest_ref.clone())
            .collect();
        for (root, (base, _)) in &self.manifests {
            roots.insert(root.clone());
            roots.extend(base.clone());
        }
        roots
    }
}

/// An open batch: its queue, what its early writes lost, and the
/// manifests they stored.
#[derive(Default)]
struct Open {
    queue: Pending,
    lost: Finished,
    /// The manifests the batch's early writes stored, by root, with a hash
    /// of their bytes: a later transaction does not send them again.
    stored: Stored,
}

/// Manifests a transaction stored, by root, with the BLAKE3 of their
/// bytes.
pub(crate) type Stored = HashMap<String, String>;

thread_local! {
    /// The batches open on this thread, by store handle.
    static OPEN: RefCell<HashMap<u64, Open>> = RefCell::new(HashMap::new());
}

/// Run `f` on this thread's open batch of `remote`, if there is one.
fn with_open<T>(remote: &Remote, f: impl FnOnce(&mut Open) -> T) -> Option<T> {
    OPEN.try_with(|o| o.borrow_mut().get_mut(&remote.id).map(f))
        .ok()
        .flatten()
}

/// Run `f` on the queue of this thread's open batch of `remote`, if there
/// is one.
fn with_pending<T>(remote: &Remote, f: impl FnOnce(&mut Pending) -> T) -> Option<T> {
    with_open(remote, |o| f(&mut o.queue))
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
    with_pending(remote, |p| p.referenced())
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
                v.insert(Open {
                    queue: Pending {
                        after,
                        ..Pending::default()
                    },
                    lost: Finished::default(),
                    stored: Stored::default(),
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
    /// Any write lost fails the whole batch (what a caller that cannot
    /// tell which were lost must assume).
    fn finish(self: Box<Self>) -> Result<Vec<String>, StoreError> {
        let f = self.finish_partial()?;
        if f.lost_count() > 0 {
            return Err(f
                .into_error()
                .unwrap_or_else(|| StoreError::other("a write of the batch was lost")));
        }
        Ok(f.warnings)
    }

    fn finish_partial(self: Box<Self>) -> Result<Finished, StoreError> {
        let Open {
            queue,
            lost: mut done,
            mut stored,
        } = OPEN
            .try_with(|o| o.borrow_mut().remove(&self.remote.id))
            .ok()
            .flatten()
            .unwrap_or_default();
        let w = write_all(&self.remote, queue, &mut stored, &BTreeSet::new());
        if let Some(e) = w.other {
            done.warnings.push(format!(
                "writes of the batch that no attestation depends on were not stored: {e}"
            ));
        }
        done.absorb(w.lost);
        Ok(done)
    }
}

/// Write the queue's whole units early when it is full
/// ([`Pending::take_whole_units`]); what it loses is reported when the
/// batch finishes.
fn flush_if_full(remote: &Remote) {
    let Some((p, mut stored, keep)) = with_open(remote, |o| {
        if !o.queue.full() {
            return None;
        }
        let p = o.queue.take_whole_units();
        // What stays queued references these: no transaction of this
        // write removes them as superseded.
        Some((p, std::mem::take(&mut o.stored), o.queue.referenced()))
    })
    .flatten() else {
        return;
    };
    let w = write_all(remote, p, &mut stored, &keep);
    with_open(remote, |o| {
        o.stored = stored;
        if let Some(e) = w.other {
            o.lost.warnings.push(format!(
                "writes of the batch that no attestation depends on were not stored: {e}"
            ));
        }
        o.lost.absorb(w.lost);
    });
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
        // The put replaces the slot whatever was queued for it.
        p.removals.remove(&key);
        p.emptied.remove(&slot);
        p.last = Some(slot.0.clone());
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
        for e in &doomed {
            if let Some((tk, signer, sk)) = key::parse_key(&e.key) {
                p.last = Some(tk.to_owned());
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
    write(remote, p)?;
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
    let packed = remote.compress().then(|| compress(bytes)).flatten();
    let r = remote.query(
        READ,
        &t.manifest_same,
        vec![
            V::Text(root.to_owned()),
            V::Blob(bytes.to_vec()),
            packed.map_or(V::Null, V::Blob),
        ],
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
    write(remote, p)?;
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
        write(
            remote,
            Pending {
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

/// The statements that log these slots and roots for replicas (a
/// transaction's nonce among the roots: no manifest has it).
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

/// What [`write_all`] could not store.
#[derive(Default)]
pub(crate) struct Written {
    /// The attestations not stored, by key, with why.
    pub(crate) lost: Finished,
    /// Why a transaction holding no attestation (manifests nothing queued
    /// references, removals of keys that name no unit) was not stored.
    pub(crate) other: Option<StoreError>,
}

/// Write `p` ([`write_all`]); the first failure, if any part was lost.
pub(crate) fn write(remote: &Remote, p: Pending) -> Result<(), StoreError> {
    let w = write_all(remote, p, &mut Stored::default(), &BTreeSet::new());
    match (w.lost.into_error(), w.other) {
        (Some(e), _) | (None, Some(e)) => Err(e),
        (None, None) => Ok(()),
    }
}

/// A queue's writes by unit (test key), each with the queued manifests
/// its attestations reference and their bases: what one transaction keeps
/// together, so that an attestation is never stored without its manifest
/// nor a superseded one removed without its successor stored. The writes
/// of no unit (manifests nothing queued references, a removal of a key
/// that names no unit) come first, as one.
fn units(mut p: Pending) -> Vec<Pending> {
    let empty = p.empty_like();
    let mut by: BTreeMap<String, Pending> = BTreeMap::new();
    let mut rest = empty.clone();
    for (slot, row) in std::mem::take(&mut p.attestations) {
        let g = by.entry(slot.0.clone()).or_insert_with(|| empty.clone());
        g.bytes += row.value.len() + row.key.len();
        g.attestations.insert(slot, row);
    }
    for slot in std::mem::take(&mut p.emptied) {
        by.entry(slot.0.clone())
            .or_insert_with(|| empty.clone())
            .emptied
            .insert(slot);
    }
    for k in std::mem::take(&mut p.removals) {
        match key::parse_key(&k) {
            Some((tk, _, _)) => {
                by.entry(tk.to_owned())
                    .or_insert_with(|| empty.clone())
                    .removals
                    .insert(k);
            }
            None => {
                rest.removals.insert(k);
            }
        }
    }
    let mut used: BTreeSet<String> = BTreeSet::new();
    for g in by.values_mut() {
        let refs: BTreeSet<String> = g
            .attestations
            .values()
            .filter_map(|r| r.manifest_ref.clone())
            .collect();
        for r in refs {
            let Some(m) = p.manifests.get(&r) else {
                continue;
            };
            let base = m.0.clone();
            for root in std::iter::once(r).chain(base) {
                if let Some(m) = p.manifests.get(&root)
                    && !g.manifests.contains_key(&root)
                {
                    g.bytes += m.1.len();
                    g.manifests.insert(root.clone(), m.clone());
                    used.insert(root);
                }
            }
        }
    }
    for (root, m) in std::mem::take(&mut p.manifests) {
        if !used.contains(&root) {
            rest.bytes += m.1.len();
            rest.manifests.insert(root, m);
        }
    }
    let mut out = Vec::with_capacity(by.len() + 1);
    if !rest.is_empty() {
        out.push(rest);
    }
    out.extend(by.into_values());
    out
}

/// Units packed, in order, into transactions of at most [`TX_BYTES`] as
/// sent and [`TX_UNITS`] attestations; a unit larger than that alone is a
/// transaction of its own. Compressed values are counted at two thirds of
/// their size: zstd makes vex's JSON about a third as large, and its bytes
/// travel as a hex literal, twice that.
fn pack(units: Vec<Pending>, compressed: bool) -> Vec<Vec<Pending>> {
    let sent = |b: usize| if compressed { b * 2 / 3 } else { b };
    let mut out: Vec<Vec<Pending>> = Vec::new();
    let (mut cur, mut bytes, mut n): (Vec<Pending>, usize, usize) = (Vec::new(), 0, 0);
    for u in units {
        let (b, k) = (sent(u.bytes), u.attestations.len());
        if !cur.is_empty() && (bytes + b > TX_BYTES || n + k > TX_UNITS) {
            out.push(std::mem::take(&mut cur));
            (bytes, n) = (0, 0);
        }
        bytes += b;
        n += k;
        cur.push(u);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Whether a failed transaction is worth sending again: it ran out of time
/// (or waited for the write lock until then), or the server dropped its
/// stream; not when the breaker latched meanwhile (the server cannot be
/// reached), nor for a refusal (sent again it is refused again).
fn worth_again(e: &StoreError) -> bool {
    matches!(
        e,
        StoreError::Timeout { .. } | StoreError::Unavailable { .. }
    )
}

/// Whether a failed transaction says that no other will be stored either:
/// the token may not write, the server takes no more writes, the tables
/// went away, the store is not configured or too new.
fn hopeless(e: &StoreError) -> bool {
    matches!(
        e,
        StoreError::Denied { .. }
            | StoreError::NotInitialized { .. }
            | StoreError::Config(_)
            | StoreError::Incompatible { .. }
    )
}

/// A pause before a transaction is sent again: 250 ms, doubling with each
/// try up to 4 s, between half and one and a half of that (jobs that
/// failed together do not come back together).
fn backoff(tries: u32) -> Duration {
    jitter(Duration::from_millis(250).saturating_mul(1 << tries.min(4)))
}

/// Between half and one and a half of `base`.
fn jitter(base: Duration) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    base.mul_f64(0.5 + f64::from(nanos % 1000) / 1000.0)
}

/// The pause after a transaction committed before the next one of the
/// same write is sent ([`YIELD_SHARE`] of the time it took, between
/// [`YIELD_MIN`] and [`YIELD_MAX`], randomized): another job's write that
/// waits for the lock takes it meanwhile.
fn yield_pause(took: Duration) -> Duration {
    jitter(took.mul_f64(YIELD_SHARE).clamp(YIELD_MIN, YIELD_MAX))
}

/// A transaction's nonce: a root no manifest has, logged by the
/// transaction ([`Tx`]).
fn nonce(remote: &Remote) -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    vci_core::blake3_hex(
        format!(
            "vci transaction {} {} {nanos} {}",
            std::process::id(),
            remote.id,
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
        .as_bytes(),
    )
}

/// Write `p` as transactions of whole units ([`units`], [`pack`]), one
/// after the other, pausing briefly after each one stored
/// ([`yield_pause`]); after each one stored, bring the cache up to date and
/// run the queue's hook. A transaction that fails is sent again (as it was:
/// [`Tx`]) or split as the module docs say, within the process's retry
/// time ([`Remote::spend_on_writes`]); the units whose transaction still
/// fails are lost, and the rest is stored. A manifest `stored` holds with
/// the same bytes is not sent again, and those stored are added to it;
/// `also_keep`: roots that writes still queued reference, which no
/// transaction removes as superseded.
pub(crate) fn write_all(
    remote: &Remote,
    p: Pending,
    stored: &mut Stored,
    also_keep: &BTreeSet<String>,
) -> Written {
    let mut w = Written::default();
    if p.is_empty() {
        return w;
    }
    let mut keep = p.referenced();
    keep.extend(also_keep.iter().cloned());
    let counts = (
        p.manifests.len(),
        p.attestations.len(),
        p.removals.len() + p.emptied.len(),
    );
    let step = Step::start(KIND);
    let n0 = remote.conn.requests();
    let mut queue: VecDeque<(Vec<Pending>, u32, Option<Tx>)> = pack(units(p), remote.compress())
        .into_iter()
        .map(|t| (t, 0, None))
        .collect();
    let (mut txs, mut bytes, mut longest, mut lost) = (0usize, 0usize, Duration::ZERO, 0usize);
    while let Some((group, tries, again)) = queue.pop_front() {
        let t = Instant::now();
        let built = match again {
            Some(tx) => Ok(tx),
            None => {
                let mut p = group[0].empty_like();
                for u in &group {
                    p.merge(u.clone());
                }
                // Not again what a stored transaction wrote.
                p.manifests.retain(|r, (_, b)| {
                    stored.get(r).is_none_or(|h| *h != vci_core::blake3_hex(b))
                });
                if p.is_empty() {
                    continue;
                }
                prepare(remote, p, &keep)
            }
        };
        let (tx, r) = match built {
            Ok(tx) => {
                let r = send(remote, &tx);
                (Some(tx), r)
            }
            Err(e) => (None, Err(e)),
        };
        let took = t.elapsed();
        longest = longest.max(took);
        let e = match (r, tx) {
            (Ok(n), Some(tx)) => {
                txs += 1;
                bytes += n;
                for (root, (_, b)) in &tx.p.manifests {
                    stored.insert(root.clone(), vci_core::blake3_hex(b));
                }
                settle(remote, &tx.p);
                if !queue.is_empty() {
                    std::thread::sleep(yield_pause(took));
                }
                continue;
            }
            (Ok(_), None) => continue,
            (Err(e), tx) => (e, tx),
        };
        let (mut why, tx) = e;
        // What failed: these units, or (the breaker latched, the token may
        // not write, the server takes no more writes) every unit still
        // queued.
        let mut failed = vec![group];
        let mut give_up = |why: &mut StoreError, failed: &mut Vec<Vec<Pending>>| {
            if let Err(l) = remote.conn.check() {
                *why = l;
            }
            failed.extend(queue.drain(..).map(|(g, _, _)| g));
        };
        if remote.conn.check().is_err() || hopeless(&why) {
            give_up(&mut why, &mut failed);
        } else if worth_again(&why) && tries + 1 < MAX_TRIES {
            // Time spent on a write that failed, and the pause before it is
            // sent again, count against the process's retry time.
            let pause = backoff(tries);
            if remote.spend_on_writes(took + pause) {
                std::thread::sleep(pause);
                // As it was sent: should the first commit after all (it
                // waited for the lock while the server answered that it had
                // not), one of the two is refused as already committed.
                let group = failed.pop().unwrap_or_default();
                queue.push_front((group, tries + 1, tx));
                continue;
            }
            // The process's retry time ran out: the server cannot take
            // writes now. Latched, so that every later call fails at once.
            why = remote.writes_out_of_time(&why);
            give_up(&mut why, &mut failed);
        } else if worth_again(&why) {
            remote.spend_on_writes(took);
        } else if failed[0].len() > 1 {
            // Refused: split down to the unit the server refuses.
            let mut group = failed.pop().unwrap_or_default();
            let second = group.split_off(group.len() / 2);
            queue.push_front((second, tries, None));
            queue.push_front((group, tries, None));
            continue;
        }
        let keys: Vec<String> = failed.iter().flatten().flat_map(Pending::keys).collect();
        if keys.is_empty() {
            w.other.get_or_insert(why);
        } else {
            lost += keys.len();
            w.lost.lose(keys, why);
        }
    }
    step.done(format_args!(
        "write batch: {} manifest(s), {} attestation(s), {} removal(s), {txs} transaction(s), {} request(s), {}{}, longest {:.2}s{}",
        counts.0,
        counts.1,
        counts.2,
        remote.conn.requests() - n0,
        crate::remote::megabytes(u64::try_from(bytes).unwrap_or(u64::MAX)),
        if remote.compress() { " compressed" } else { "" },
        longest.as_secs_f64(),
        if lost > 0 {
            format!(", {lost} attestation(s) not stored")
        } else {
            String::new()
        }
    ));
    w
}

/// What a transaction's guard says, with its nonce, when the transaction
/// was committed already.
const COMMITTED: &str = "vci: this transaction was committed already";

/// One transaction of a write, as sent: sent again as it is after its
/// deadline. Its first statement is a guard that stops it when the change
/// log holds its nonce (a root no manifest has, logged with the
/// transaction's time), and its log rows write the nonce: whichever of
/// the first send and a copy sent again commits first, the other is
/// refused with the nonce in the error, which counts as stored. A
/// transaction that ran out of time while it waited for the write lock
/// often commits after the client asked whether it had (the question is
/// a read, which does not wait for the lock): 2.8.2's drafts then sent it
/// again in halves, and it was applied twice (on vex's Turso database 18
/// slots in two of three writers, each a further 30 s under the very load
/// that made it late).
pub(crate) struct Tx {
    /// What it writes.
    p: Pending,
    /// Its statements (none: nothing to write).
    stmts: Vec<String>,
    /// Whether the server holds its nonce (asked after its deadline).
    probe: String,
    nonce: String,
    /// The bytes of values it sends.
    sent: usize,
    /// It prunes the change log.
    prune: bool,
    /// It only removes.
    only_removals: bool,
}

/// Send `tx` (one request, and when its deadline runs out, one more asking
/// whether the server committed it); the bytes of values sent.
fn send(remote: &Remote, tx: &Tx) -> Result<usize, StoreError> {
    if tx.stmts.is_empty() {
        return Ok(0);
    }
    match remote.write_checked(&tx.stmts, Some(&tx.probe)) {
        Ok(()) => {}
        // Its guard: a send of it before this one committed.
        Err(Fail::Store(e)) if e.to_string().contains(&tx.nonce) => {}
        // Only removals, and no tables: nothing to remove.
        Err(Fail::Absent) if tx.only_removals => return Ok(0),
        Err(Fail::Absent) => {
            return Err(StoreError::NotInitialized {
                backend: KIND,
                advice: "the namespace's tables went away while vci wrote: run it again".to_owned(),
            });
        }
        Err(Fail::Store(e)) => return Err(e),
    }
    if tx.prune {
        remote.log_pruned.store(true, Ordering::Relaxed);
    }
    Ok(tx.sent)
}

/// `p` as one transaction ([`Tx`]). `keep`: roots the whole queue
/// references, which no transaction of it removes as superseded.
fn prepare(remote: &Remote, p: Pending, keep: &BTreeSet<String>) -> Result<Tx, StoreError> {
    let only_removals = p.manifests.is_empty() && p.attestations.is_empty();
    let nothing = |p: Pending| Tx {
        p,
        stmts: Vec::new(),
        probe: String::new(),
        nonce: String::new(),
        sent: 0,
        prune: false,
        only_removals,
    };
    if p.is_empty() {
        return Ok(nothing(p));
    }
    let t = if only_removals {
        let t = remote.ready()?;
        if remote.version()?.is_none() {
            // Nothing stored, nothing to remove.
            return Ok(nothing(p));
        }
        t
    } else {
        remote.ensure()?
    };
    let at = now();
    let nonce = nonce(remote);
    let (a, log) = (&t.names.attestations, &t.log);
    let mut stmts: Vec<String> = vec![format!(
        "SELECT json_extract('{{}}', '{COMMITTED} ' || root) FROM {log} \
         WHERE at = {at} AND root = '{nonce}'"
    )];
    let mut sent = 0usize;
    // A value as written: `encoding, value` literals.
    let mut value = |b: &[u8]| -> String {
        let lit = match remote.compress().then(|| compress(b)).flatten() {
            Some(z) => format!("{ZSTD}, {}", blob(&z)),
            None => format!("{RAW}, {}", blob(b)),
        };
        sent += lit.len();
        lit
    };
    if !p.manifests.is_empty() {
        let rows: Vec<String> = p
            .manifests
            .iter()
            .map(|(root, (base, bytes))| {
                format!(
                    "({}, {}, {at}, {})",
                    text(root),
                    opt_text(base.as_deref()),
                    value(bytes)
                )
            })
            .collect();
        stmts.push(t.upsert_manifests(&rows.join(", ")));
    }
    stmts.extend(superseded_manifests(remote, t, &p, keep, at)?);
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
                    value(&r.value)
                )
            })
            .collect();
        stmts.push(t.upsert_attestations(&rows.join(", ")));
    }
    let slots: Vec<&Slot> = removed_slots
        .iter()
        .chain(p.emptied.iter())
        .chain(p.attestations.keys())
        .collect();
    let roots: Vec<&str> = p
        .manifests
        .keys()
        .map(String::as_str)
        .chain(std::iter::once(nonce.as_str()))
        .collect();
    stmts.extend(log_rows(log, &slots, &roots, at));
    let prune = !remote.log_pruned.load(Ordering::Relaxed);
    if prune {
        let cut = at.saturating_sub(LOG_KEEP_SECS);
        stmts.push(format!(
            "UPDATE vci_schema SET log_floor = max(log_floor, \
               coalesce((SELECT max(seq) FROM {log} WHERE at < {cut}), 0)) WHERE ns = {}",
            text(remote.ns()?)
        ));
        stmts.push(format!("DELETE FROM {log} WHERE at < {cut}"));
    }
    let probe = format!("SELECT 1 FROM {log} WHERE at = {at} AND root = '{nonce}'");
    Ok(Tx {
        p,
        stmts,
        probe,
        nonce,
        sent,
        prune,
        only_removals,
    })
}

/// The statements that remove the manifests this write leaves without a
/// reference (2.8.2): before the write, the attestations it removes or
/// replaces (the keys it removes, the slots it empties, the slots it puts
/// to) reference them, and once it is done nothing will. One is kept when
/// any other attestation references it, a manifest uses it as its base,
/// this write references it (an attestation it puts, a manifest it puts or
/// that one's base; with a queue written as several transactions, any of
/// the queue's), any attestation's reference is unknown, or it was put
/// within the grace period (the hour another writer has to reference a
/// manifest it put before its attestation; `vci prune` removes the rest).
/// The change log names the roots removed, as `remove_manifests` does.
/// Before 2.8.2 a superseded attestation's manifest stayed until `vci
/// prune`: 90% of vex's manifests (730 MB) were such orphans.
fn superseded_manifests(
    remote: &Remote,
    t: &Tables,
    p: &Pending,
    keep: &BTreeSet<String>,
    at: i64,
) -> Result<Vec<String>, StoreError> {
    let slots: Vec<&Slot> = p.emptied.iter().chain(p.attestations.keys()).collect();
    if p.removals.is_empty() && slots.is_empty() {
        return Ok(Vec::new());
    }
    let (a, m, log) = (&t.names.attestations, &t.names.manifests, &t.log);
    // An attestation this write removes or replaces (`x`: its alias).
    let affected = |x: &str| -> String {
        let mut parts: Vec<String> = Vec::new();
        if !p.removals.is_empty() {
            parts.push(format!(
                "{x}.key IN ({})",
                p.removals
                    .iter()
                    .map(|k| text(k))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !slots.is_empty() {
            parts.push(format!(
                "({x}.test_key, {x}.signer, {x}.storage_key) IN (VALUES {})",
                slots
                    .iter()
                    .map(|(tk, s, k)| format!("({}, {}, {})", text(tk), text(s), text(k)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        format!("({})", parts.join(" OR "))
    };
    let mut keep: BTreeSet<&str> = keep.iter().map(String::as_str).collect();
    keep.extend(
        p.attestations
            .values()
            .filter_map(|r| r.manifest_ref.as_deref()),
    );
    for (root, (base, _)) in &p.manifests {
        keep.insert(root);
        keep.extend(base.as_deref());
    }
    let keep = if keep.is_empty() {
        String::new()
    } else {
        format!(
            "AND r.root NOT IN ({}) ",
            keep.iter().map(|r| text(r)).collect::<Vec<_>>().join(", ")
        )
    };
    let cut = at.saturating_sub(i64::try_from(remote.grace.as_secs()).unwrap_or(i64::MAX));
    let doomed = format!(
        "SELECT r.root FROM {m} AS r WHERE r.root IN \
           (SELECT d.manifest_ref FROM {a} AS d WHERE {} AND d.manifest_ref IS NOT NULL) \
         {keep}AND r.put_at <= {cut} \
         AND NOT EXISTS (SELECT 1 FROM {a} AS o WHERE o.manifest_ref = r.root AND NOT {}) \
         AND NOT EXISTS (SELECT 1 FROM {m} AS b WHERE b.base = r.root) \
         AND NOT EXISTS (SELECT 1 FROM {a} WHERE ref_state = 0)",
        affected("d"),
        affected("o")
    );
    Ok(vec![
        format!("INSERT INTO {log} (root, at) SELECT root, {at} FROM ({doomed})"),
        format!("DELETE FROM {m} WHERE root IN ({doomed})"),
    ])
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
