//! # `vci-store`: where vci keeps attestations
//!
//! vci keeps two kinds of records. This crate says how any backend keeps
//! them.
//!
//! * An **attestation** is a DSSE envelope (UTF-8 JSON bytes, stored byte for
//!   byte) signed for one unit (test id) by one signer over one set of
//!   inputs. Its key is
//!   `vci:attestation:<test key>:<signer>:<storage key>[:<issued hex>.<tree16 | ->]`
//!   ([`key::attestation_key_hinted`]). There is at most one per (unit,
//!   signer, storage key): attesting the same inputs again replaces it,
//!   whatever its hint.
//! * An **input manifest** is the compact encoding of the inputs that an
//!   attestation's `manifestRef` names. It is content-addressed and stored
//!   once per input root under `vci:manifest:<root>` ([`key::manifest_key`]).
//!   It may list its entries on top of a *base* manifest stored the same way.
//!
//! | backend    | crate                | where the records are                                         | [`Exchange`] |
//! |------------|----------------------|---------------------------------------------------------------|--------------|
//! | `git-meta` | `vci-git`            | `.git/git-meta.sqlite`, published on `refs/meta/main`         | yes: `vci fetch` / `vci push` |
//! | `sqlite`   | `vci-store-sqlite`   | one SQLite file, default `<git common dir>/vci-store.sqlite`  | no (local)   |
//! | `postgres` | `vci-store-postgres` | tables in one PostgreSQL schema, one namespace per repository | no (shared)  |
//!
//! The command line registers a factory for each backend in every default
//! build (cargo features `sqlite` and `postgres` of vci-cli); git-meta is
//! the default. `docs/STORE-BACKENDS.md` is the implementer guide, and says
//! how far each backend is implemented. This page is the contract.
//!
//! ## Trust: the store is never trusted
//!
//! Nothing a store returns is trusted. `vci plan` verifies every envelope's
//! signature against the base commit's allowed signers and keyless
//! identities, and recomputes every manifest's root. A record that is lost,
//! corrupted, forged, replayed, reordered or duplicated can only make a unit
//! *run*, never make it *skip*. Two things follow:
//!
//! * write access to a store (push rights on `refs/meta/main`, a PostgreSQL
//!   role with INSERT and DELETE, write permission on a SQLite file) is an
//!   **availability** privilege, never an integrity one. A writer can make CI
//!   slower, by deleting records or by adding records the plan has to read
//!   and reject, but it cannot make CI skip a test it should run;
//! * the signer id inside a key is the writer's claim, checked only for its
//!   shape. A backend never filters, ranks or repairs records by signer.
//!
//! ## Fail open
//!
//! The command line treats every store error as "run the test". A lookup
//! that fails makes every test of every project run. A value that cannot be
//! read fails only its own candidate. A put that fails refuses only its own
//! unit (the test result stands). Hints that fail do nothing. `vci fetch`,
//! `vci push`, `vci prune` and `vci store info` report store errors as
//! failures (exit 2). `vci run` keeps the tests' exit code when a unit
//! cannot be stored because the store cannot be used ([`StoreError::Config`],
//! [`StoreError::Unavailable`], [`StoreError::Timeout`],
//! [`StoreError::NotInitialized`], [`StoreError::Incompatible`],
//! [`StoreError::Denied`], [`StoreError::Unsupported`]); any other error
//! (a backend's own, [`StoreError::Invalid`], [`StoreError::Other`]) is a
//! problem of the run, after which `vci run` exits 2, as git-meta's errors
//! always made it. A backend therefore reports "this store cannot be used
//! here" with those variants, never as [`StoreError::Backend`]. A store
//! that cannot be selected or opened becomes a [`FailedStore`], whose every
//! call fails, so the same error paths apply.
//!
//! ## Implementing a backend
//!
//! Implement [`AttestationStore`]. Ten methods are required: [`kind`],
//! [`list_units`], [`list_all`], [`read_values`], [`manifest`],
//! [`manifest_roots`], [`put`], [`put_manifest`], [`remove`] and
//! [`remove_manifests`]. Every other method has a default that is correct
//! for a backend whose values are always present and whose writes are
//! durable when the call returns. Override a default when the backend can
//! do better:
//!
//! | default                                         | override when                                                   |
//! |-------------------------------------------------|-----------------------------------------------------------------|
//! | [`read_units`] (list, then [`read_values`])     | a targeted "list with values" is cheaper than a batch read (git-meta must) |
//! | [`manifests`] (one [`manifest`] per root)       | one query can answer many roots                                 |
//! | [`orphan_manifests`] (reads every value)        | an index of `manifestRef` answers in one query                  |
//! | [`prefetch`] (does nothing)                     | values are lazy (download them) or remote (warm a cache)        |
//! | [`batch`] (groups nothing)                      | grouping writes saves round trips, sessions or commits          |
//! | [`status`] (`Ready`)                            | the store can be absent (no file, no schema) or versioned       |
//! | hints: [`passing_on`], [`flag`] (keep nothing)  | the backend can keep two small tables                           |
//! | [`exchange`] (`None`)                           | writes reach other machines only through a push and a fetch     |
//!
//! Then add a [`BackendFactory`] and register it in vci-cli's
//! `store::factories` (one line, or a [`MissingBackend`] when its cargo
//! feature is off), so the command line can open the backend by name, and
//! run the conformance suite (feature `conformance`, macro
//! `vci_store::conformance_suite!`) from the backend's own tests.
//!
//! ## Rules every backend keeps (the conformance suite checks them)
//!
//! 1. **Keys are identical across backends.** Build and parse them only with
//!    [`key`]. They appear in `vci plan --format json` (`by.metaKey`,
//!    `by.target`), in the audit log, in `vci explain`, and in the memo of
//!    passing attestations ([`AttestationStore::passing_on`]). Records can
//!    therefore be copied between backends unchanged.
//! 2. **Order is part of the result.** [`list_units`] sorts each unit's
//!    entries by key, bytewise. [`list_all`] sorts by (target, key),
//!    bytewise. [`manifest_roots`] is sorted and deduplicated. SQL backends
//!    use a binary collation (SQLite's default `BINARY`; PostgreSQL
//!    `COLLATE "C"`). The plan's choice of candidates is by index, and its
//!    verdict reasons depend on this order.
//! 3. **Errors are per entry.** A value that cannot be read is an error on
//!    its own entry ([`StoredEnvelope::error`], [`StoredManifest::error`]).
//!    `Err` means the store cannot answer at all.
//! 4. **Time is bounded.** Every call returns `Ok` or `Err` within a bounded
//!    time (connect, statement, busy and lock timeouts). After one failure to
//!    reach the store, later calls in the same process fail at once (a
//!    circuit breaker), so a store that is down costs one timeout per
//!    command, not one per call. A hung store would block `vci plan`; an
//!    erroring one only makes units run. (git-meta's one exception: its
//!    prefetch waits for another vci's fetch or push in the same repository
//!    for at most `VCI_LOCK_TIMEOUT_SECS`, 600 s by default.)
//! 5. **Concurrent use.** A store is `Send + Sync` and is called from many
//!    threads at once: the `--fetch` thread, the probe threads, the plan's
//!    `VCI_JOBS` verifying threads, and the run's supersession workers.
//!    Pools, per-thread connections and caches are the backend's business.
//! 6. **Writes** are validated first, idempotent, UTF-8 only, and a put of
//!    the same (unit, signer, storage key) replaces the earlier key
//!    atomically ([`AttestationStore::put`]).
//! 7. **Removal.** When [`AttestationStore::remove`] returns (or, inside a
//!    deferred [`WriteBatch`], when the batch finishes), no later read of
//!    this store returns the removed entries. Where the store has an
//!    [`Exchange`], the removal travels with the next push.
//! 8. **Reads create nothing.** Reading a store that does not exist (no
//!    file, no schema) answers as an empty store and creates nothing. Writes
//!    create or migrate the schema, under a lock; a schema newer than the
//!    backend understands is [`StoreError::Incompatible`].
//! 9. **Secrets stay secret.** No error, `Debug` output, location or timing
//!    line carries a password. Backends pass their libraries' messages
//!    through [`select::Secret::scrub`].
//!
//! ## Timing
//!
//! Backends report the time of their own steps through [`timing::Step`] as
//! `store: <kind>: <step>: <secs>s`, so that `vci metrics` can group them.
//! git-meta keeps the lines it printed before this crate existed.
//!
//! [`kind`]: AttestationStore::kind
//! [`list_units`]: AttestationStore::list_units
//! [`list_all`]: AttestationStore::list_all
//! [`read_values`]: AttestationStore::read_values
//! [`manifest`]: AttestationStore::manifest
//! [`manifest_roots`]: AttestationStore::manifest_roots
//! [`put`]: AttestationStore::put
//! [`put_manifest`]: AttestationStore::put_manifest
//! [`remove`]: AttestationStore::remove
//! [`remove_manifests`]: AttestationStore::remove_manifests
//! [`read_units`]: AttestationStore::read_units
//! [`manifests`]: AttestationStore::manifests
//! [`orphan_manifests`]: AttestationStore::orphan_manifests
//! [`prefetch`]: AttestationStore::prefetch
//! [`batch`]: AttestationStore::batch
//! [`status`]: AttestationStore::status
//! [`passing_on`]: AttestationStore::passing_on
//! [`flag`]: AttestationStore::flag
//! [`exchange`]: AttestationStore::exchange

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;

pub use key::{
    KEY_PREFIX, MANIFEST_PREFIX, ManifestRef, attestation_key, attestation_key_hinted,
    envelope_manifest_ref, manifest_key, parse_key, parse_key_hint, parse_manifest_key,
    target_label, test_key,
};

// ---- value states ------------------------------------------------------------

/// How a value reads when the store knows its key but does not hold the
/// value here yet (a git-meta promised entry in a blobless clone), and the
/// marker [`StoredEnvelope::mark_not_fetched`] sets for a candidate the plan
/// chose not to read yet.
///
/// The text is unchanged from vci 2.x: tests and log scrapers match its
/// first words (``value not fetched: run `vci fetch` online``). A backend
/// never produces it for a value it holds. [`AttestationStore::prefetch`] is
/// what makes a lazy value readable.
pub const NOT_FETCHED: &str = "value not fetched: run `vci fetch` online (a git-meta promised entry; its blob is not in this clone yet)";

/// How [`AttestationStore::read_values`] reports a listed key that the store
/// no longer holds (it was removed between the listing and the read).
pub const GONE: &str = "the store no longer holds this key";

/// How a value reads when the store holds empty bytes under its key. vci
/// never writes an empty value ([`NewAttestation::validate`]), so such a
/// value is never valid.
pub const EMPTY_VALUE: &str = "the stored value is empty";

/// What a key says about its attestation without the value (vci 2.2): when
/// it was issued and, when known, the git tree it was made on. A plan
/// chooses which candidates to read from these alone.
///
/// Callers and tests build it with a struct literal, so it has no private
/// fields and is not `#[non_exhaustive]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHint {
    /// `issuedAt`, in seconds since the epoch (written as lowercase hex, at
    /// least 0).
    pub issued: i64,
    /// The first 16 hex digits of the tree the attestation records. Anything
    /// that is not exactly 16 hex digits is written as `-` (unknown).
    pub tree: Option<String>,
}

/// Where a listed record's value stands, derived from
/// [`StoredEnvelope::bytes`] and [`StoredEnvelope::error`] (which stay public
/// for compatibility). There is no separate field to keep in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueState<'a> {
    /// The value was read. These are its bytes, exactly as written.
    Read(&'a [u8]),
    /// The record was listed without its value. A later
    /// [`AttestationStore::read_values`] reads it.
    Unread,
    /// The value is not read yet: either a lazy backend does not hold it
    /// here ([`AttestationStore::prefetch`] brings it), or the caller set it
    /// aside with [`StoredEnvelope::mark_not_fetched`].
    NotFetched,
    /// The value cannot be read, for this reason ([`GONE`], [`EMPTY_VALUE`],
    /// a missing blob, an I/O error...). The record is never valid, and only
    /// its own unit loses it.
    Unreadable(&'a str),
}

// ---- records -----------------------------------------------------------------

/// One stored attestation: where it is, what its key says, and its value
/// once read.
///
/// A listing ([`AttestationStore::list_units`], [`AttestationStore::list_all`])
/// returns entries in [`ValueState::Unread`]. [`AttestationStore::read_values`]
/// then sets either `bytes` or `error`. A caller that decides not to read an
/// entry yet marks it with [`StoredEnvelope::mark_not_fetched`].
///
/// The key alone identifies a record, because it embeds the unit's test key,
/// the signer id and the storage key. `target` is display data on every
/// backend (git-meta also files the record under it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEnvelope {
    /// `path:<p>` or `project`: [`key::target_label`] of the unit's test id.
    /// `vci plan --format json` prints it as `by.target`, so every backend
    /// fills it the same way.
    pub target: String,
    /// The full key ([`key`]).
    pub key: String,
    /// BLAKE3 of the test id, 64 lowercase hex (from the key).
    pub test_key: String,
    /// 16 lowercase hex characters naming the signing key (from the key; the
    /// writer's claim, never verified by a store).
    pub signer: String,
    /// The storage key, naming the inputs (from the key; lowercase hex).
    pub storage_key: String,
    /// When the key says the attestation was issued (seconds since the
    /// epoch), known without the value.
    pub issued: Option<i64>,
    /// The first 16 hex digits of the tree the key says the attestation was
    /// made on.
    pub tree: Option<String>,
    /// The stored bytes, exactly as passed to [`AttestationStore::put`].
    /// Empty unless the value was read ([`StoredEnvelope::state`]).
    pub bytes: Vec<u8>,
    /// Why the value is not here: [`NOT_FETCHED`] for a value not read yet,
    /// [`GONE`] for a key removed since it was listed, any other text for a
    /// value that cannot be read.
    pub error: Option<String>,
}

impl StoredEnvelope {
    /// An unread entry for `key` on `target`, with the fields parsed from
    /// the key. Returns `None` for a key that does not have vci's shape:
    /// backends skip such keys (they are foreign data) and never report them
    /// as errors.
    pub fn from_key(target: impl Into<String>, key: &str) -> Option<StoredEnvelope> {
        let (tk, signer, sk) = key::parse_key(key)?;
        let hint = key::parse_key_hint(key);
        Some(StoredEnvelope {
            target: target.into(),
            key: key.to_owned(),
            test_key: tk.to_owned(),
            signer: signer.to_owned(),
            storage_key: sk.to_owned(),
            issued: hint.as_ref().map(|h| h.issued),
            tree: hint.and_then(|h| h.tree),
            bytes: Vec::new(),
            error: None,
        })
    }

    /// Record the value read for this entry. Empty bytes are recorded as
    /// unreadable ([`EMPTY_VALUE`]), because vci never writes them.
    pub fn set_value(&mut self, bytes: Vec<u8>) {
        if bytes.is_empty() {
            self.set_error(EMPTY_VALUE);
        } else {
            self.bytes = bytes;
            self.error = None;
        }
    }

    /// Record why the value could not be read.
    pub fn set_error(&mut self, why: impl Into<String>) {
        self.bytes = Vec::new();
        self.error = Some(why.into());
    }

    /// Set the value aside: the plan reads first only the candidates it
    /// checks first, and reads the rest for the units it could not skip.
    pub fn mark_not_fetched(&mut self) {
        self.set_error(NOT_FETCHED);
    }

    /// Whether the value is unread only for now: set aside by the caller,
    /// or not fetched by a lazy backend ([`NOT_FETCHED`]).
    pub fn not_fetched(&self) -> bool {
        self.error.as_deref() == Some(NOT_FETCHED)
    }

    /// Where the value stands.
    pub fn state(&self) -> ValueState<'_> {
        match self.error.as_deref() {
            Some(NOT_FETCHED) => ValueState::NotFetched,
            Some(e) => ValueState::Unreadable(e),
            None if self.bytes.is_empty() => ValueState::Unread,
            None => ValueState::Read(&self.bytes),
        }
    }

    /// Which stored manifest the (unverified) value names. [`ManifestRef::Unknown`]
    /// unless the value was read and parses: a garbage collector then keeps
    /// every manifest.
    pub fn manifest_ref(&self) -> ManifestRef {
        match self.state() {
            ValueState::Read(b) => key::envelope_manifest_ref(b),
            _ => ManifestRef::Unknown,
        }
    }
}

/// An input manifest read back from a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredManifest {
    /// The input root it is stored under. This is a hint until the caller
    /// recomputes the manifest's own root.
    pub root: String,
    /// The full key, `vci:manifest:<root>`.
    pub key: String,
    /// The stored bytes (the compact encoding). Empty when `error` is set.
    pub bytes: Vec<u8>,
    /// Why the value cannot be read ([`NOT_FETCHED`] for a lazy one).
    pub error: Option<String>,
}

impl StoredManifest {
    /// A manifest read with these bytes.
    pub fn with_bytes(root: &str, bytes: Vec<u8>) -> Self {
        StoredManifest {
            root: root.to_owned(),
            key: key::manifest_key(root),
            bytes,
            error: None,
        }
    }

    /// A manifest that is stored but cannot be read, and why.
    pub fn with_error(root: &str, why: impl Into<String>) -> Self {
        StoredManifest {
            root: root.to_owned(),
            key: key::manifest_key(root),
            bytes: Vec::new(),
            error: Some(why.into()),
        }
    }

    /// A manifest whose key is known but whose value is not fetched yet.
    pub fn pending(root: &str) -> Self {
        Self::with_error(root, NOT_FETCHED)
    }

    /// Whether the value is unread only because it is not fetched yet.
    pub fn not_fetched(&self) -> bool {
        self.error.as_deref() == Some(NOT_FETCHED)
    }

    /// Whether `bytes` holds the value.
    pub fn is_read(&self) -> bool {
        self.error.is_none()
    }
}

/// One attestation to store ([`AttestationStore::put`]).
///
/// It carries the unit's target label and test key rather than its test id,
/// so that a copy between stores ([`NewAttestation::copy_of`]) can re-put a
/// record it knows only by key, with its key and target unchanged.
/// [`NewAttestation::for_test`] builds the usual case.
#[derive(Debug, Clone)]
pub struct NewAttestation<'a> {
    /// [`key::target_label`] of the unit's test id.
    pub target: String,
    /// BLAKE3 of the unit's test id ([`key::test_key`]).
    pub test_key: String,
    /// The signer id the writer claims: 16 lowercase hex characters,
    /// checked for its shape only.
    pub signer: &'a str,
    /// The storage key: 2 to 128 lowercase hex characters.
    pub storage_key: &'a str,
    /// The key's hint. `None` keeps the key of an existing record with the
    /// same (test key, signer, storage key), or uses the plain key when
    /// there is none.
    pub hint: Option<&'a KeyHint>,
    /// The DSSE envelope: non-empty UTF-8.
    pub envelope: &'a [u8],
}

impl<'a> NewAttestation<'a> {
    /// The record `vci run` stores for a test unit.
    pub fn for_test(
        test_id: &str,
        signer: &'a str,
        storage_key: &'a str,
        hint: Option<&'a KeyHint>,
        envelope: &'a [u8],
    ) -> Self {
        NewAttestation {
            target: key::target_label(test_id),
            test_key: key::test_key(test_id),
            signer,
            storage_key,
            hint,
            envelope,
        }
    }

    /// The same record again, for a copy between stores. Pass
    /// `key::parse_key_hint(&record.key).as_ref()` as `hint` so the copy
    /// keeps its key. `record` must have been read
    /// ([`ValueState::Read`]).
    pub fn copy_of(record: &'a StoredEnvelope, hint: Option<&'a KeyHint>) -> Self {
        NewAttestation {
            target: record.target.clone(),
            test_key: record.test_key.clone(),
            signer: &record.signer,
            storage_key: &record.storage_key,
            hint,
            envelope: &record.bytes,
        }
    }

    /// Check every argument before anything is written, with vci-git's
    /// `what` names and reasons: `signer_id`, `storage_key`, `test_key`,
    /// `target`, `envelope`. Every backend calls this first. Returns the
    /// envelope as text.
    pub fn validate(&self) -> Result<&'a str, StoreError> {
        key::check_signer(self.signer)?;
        key::check_hex("storage_key", self.storage_key)?;
        key::check_hex("test_key", &self.test_key)?;
        if !key::is_target_label(&self.target) {
            return Err(StoreError::invalid(
                "target",
                &self.target,
                "must be `project` or `path:<relative path>`",
            ));
        }
        if self.envelope.is_empty() {
            return Err(StoreError::invalid("envelope", "", "must not be empty"));
        }
        key::check_utf8("envelope", self.envelope)
    }

    /// The key when a hint is given.
    pub fn hinted_key(&self) -> Option<String> {
        self.hint
            .map(|h| key::attestation_key_hinted(&self.test_key, self.signer, self.storage_key, h))
    }

    /// The key without a hint (as before vci 2.2).
    pub fn plain_key(&self) -> String {
        key::attestation_key(&self.test_key, self.signer, self.storage_key)
    }

    /// The entry a successful put returns, given the key it was stored
    /// under: `bytes` set, `issued` and `tree` from the key.
    pub fn stored(&self, key: String) -> StoredEnvelope {
        let hint = key::parse_key_hint(&key);
        StoredEnvelope {
            target: self.target.clone(),
            key,
            test_key: self.test_key.clone(),
            signer: self.signer.to_owned(),
            storage_key: self.storage_key.to_owned(),
            issued: hint.as_ref().map(|h| h.issued),
            tree: hint.and_then(|h| h.tree),
            bytes: self.envelope.to_vec(),
            error: None,
        }
    }
}

// ---- outcomes ----------------------------------------------------------------

/// What an [`AttestationStore::prefetch`] did.
///
/// A backend without lazy values returns `Hydration::default()`, also when
/// it warmed a cache: nothing went from "not fetched" to readable. Callers
/// therefore never read `resolved == 0` as "nothing more is readable".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hydration {
    /// Values that were not fetched and now are readable.
    pub resolved: usize,
    /// Values asked for that are still not fetched (the fetch failed, or the
    /// store does not hold them).
    pub unresolved: usize,
    /// Objects or rows downloaded. Informational only.
    pub fetched: usize,
    /// Why some values could not be fetched (the first reason). Their units
    /// run; the call itself still succeeded.
    pub error: Option<String>,
}

impl Hydration {
    /// Add `o` to this one: counts are summed and the first error is kept.
    pub fn add(&mut self, o: Hydration) {
        self.resolved += o.resolved;
        self.unresolved += o.unresolved;
        self.fetched += o.fetched;
        if self.error.is_none() {
            self.error = o.error;
        }
    }
}

/// What [`Exchange::fetch`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOutcome {
    /// The remote fetched from, as the user names it (a git remote name for
    /// git-meta).
    pub remote: String,
    /// False when the remote holds no attestations yet.
    pub found: bool,
    /// Problems worth a warning.
    pub warnings: Vec<String>,
    /// What the backend repaired on the way.
    pub notes: Vec<String>,
}

/// How [`Exchange::push`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PushStatus {
    /// The remote now holds everything stored locally.
    Pushed,
    /// The remote already held everything stored locally; nothing was sent.
    UpToDate,
    /// Nothing is stored locally; nothing was sent.
    NothingStored,
}

/// What [`Exchange::push`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    /// The remote pushed to.
    pub remote: String,
    /// How the push ended.
    pub status: PushStatus,
    /// As for [`FetchOutcome::warnings`].
    pub warnings: Vec<String>,
    /// As for [`FetchOutcome::notes`].
    pub notes: Vec<String>,
}

/// How [`Exchange::push`] publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PushMode {
    /// Put the local writes and removals on top of the remote's.
    #[default]
    Merge,
    /// Publish the local state as a new history, so deleted values stop
    /// costing every fetch (`vci push --rewrite-history`). An exchange
    /// without history returns [`StoreError::Unsupported`].
    RewriteHistory,
}

/// Whether a store exists ([`AttestationStore::status`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreStatus {
    /// Nothing was ever written or fetched here (no file, no schema). Reads
    /// return nothing, and nothing was created to find out.
    Absent {
        /// What creates it, for the warning: ``run `vci fetch` `` (git-meta),
        /// "the first `vci run` creates it" (sqlite, postgres).
        advice: String,
    },
    /// The store exists and this vci can read it.
    Ready {
        /// The schema version found, for backends that have one.
        schema_version: Option<u32>,
    },
}

/// What a backend is, for the few callers whose behaviour must differ.
/// Callers branch on these, never on [`AttestationStore::kind`].
///
/// It is `#[non_exhaustive]`: build it from [`Caps::LOCAL`] with the
/// `with_*` methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Caps {
    /// Writes and removals are visible to other machines as soon as the call
    /// returns (a shared database), instead of after a push. `vci ci`
    /// without `--push` then neither stores nor supersedes (the publication
    /// gate, `docs/STORE-BACKENDS.md` section 7), and `vci fetch` and
    /// `vci push` call the store "shared" rather than "local".
    pub shared_writes: bool,
    /// Listings can name values the store does not hold here
    /// ([`NOT_FETCHED`]); [`AttestationStore::prefetch`] makes them
    /// readable. The plan and `vci prune` suggest `vci fetch` only then.
    pub lazy_values: bool,
    /// The hint methods ([`AttestationStore::passing_on`],
    /// [`AttestationStore::flag`]) keep what they are given.
    pub keeps_hints: bool,
}

impl Caps {
    /// A local store whose values are always present, keeping no hints.
    pub const LOCAL: Caps = Caps {
        shared_writes: false,
        lazy_values: false,
        keeps_hints: false,
    };

    /// These capabilities with [`Caps::shared_writes`] set to `v`.
    pub const fn with_shared_writes(mut self, v: bool) -> Self {
        self.shared_writes = v;
        self
    }

    /// These capabilities with [`Caps::lazy_values`] set to `v`.
    pub const fn with_lazy_values(mut self, v: bool) -> Self {
        self.lazy_values = v;
        self
    }

    /// These capabilities with [`Caps::keeps_hints`] set to `v`.
    pub const fn with_hints(mut self, v: bool) -> Self {
        self.keeps_hints = v;
        self
    }
}

impl Default for Caps {
    fn default() -> Self {
        Caps::LOCAL
    }
}

// ---- prefetch ----------------------------------------------------------------

/// Picks, from one unit's key-only listing (in
/// [`AttestationStore::list_units`] order), the indexes of the entries whose
/// values a caller will read first. It is pure, and a backend may not call
/// it at all.
pub type Choose<'a> = &'a dyn Fn(&[StoredEnvelope]) -> Vec<usize>;

/// What [`AttestationStore::prefetch`] should make cheap to read.
#[non_exhaustive]
pub enum Prefetch<'a> {
    /// The attestations of these units. With `choose`, only the entries it
    /// picks are required (a backend may fetch more). Also the input
    /// manifests those entries reference, and their base manifests.
    Units {
        /// The units (test ids).
        test_ids: &'a [&'a str],
        /// Which entries of each unit; `None` means every entry.
        choose: Option<Choose<'a>>,
    },
    /// These input manifests and their base manifests.
    Manifests {
        /// The input roots.
        roots: &'a [&'a str],
    },
    /// Every attestation's value (manifests excluded), before a full scan
    /// such as `vci prune`.
    Attestations,
}

impl fmt::Debug for Prefetch<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Prefetch::Units { test_ids, choose } => f
                .debug_struct("Units")
                .field("test_ids", &test_ids.len())
                .field("choose", &choose.is_some())
                .finish(),
            Prefetch::Manifests { roots } => f
                .debug_struct("Manifests")
                .field("roots", &roots.len())
                .finish(),
            Prefetch::Attestations => f.write_str("Attestations"),
        }
    }
}

// ---- write batches -------------------------------------------------------------

/// The end of a write batch, as a backend implements it
/// ([`AttestationStore::batch`]).
pub trait BatchEnd {
    /// Make every write of the batch durable and visible (commit, flush), or
    /// say why not. After an `Err`, treat every write of the batch as lost.
    fn finish(self: Box<Self>) -> Result<(), StoreError>;
}

/// An open write batch ([`AttestationStore::batch`]).
///
/// [`WriteBatch::finish`] ends it and reports a failure; dropping it also
/// ends it but ignores the failure, so callers always call `finish`. It is
/// `!Send` on purpose: it ends on the thread that opened it, and only that
/// thread's writes join it.
#[must_use = "dropping the batch ends it at once and loses its error"]
pub struct WriteBatch {
    end: Option<Box<dyn BatchEnd>>,
    deferred: bool,
    _thread: PhantomData<*const ()>,
}

impl WriteBatch {
    /// A batch that groups nothing (the default for every backend).
    pub fn none() -> Self {
        WriteBatch {
            end: None,
            deferred: false,
            _thread: PhantomData,
        }
    }

    /// A batch whose writes are durable as each call returns; `end` only
    /// releases what they shared (git-meta's session, SQLite's pinned
    /// connection). Callers report each write at once.
    pub fn immediate(end: Box<dyn BatchEnd>) -> Self {
        WriteBatch {
            end: Some(end),
            deferred: false,
            _thread: PhantomData,
        }
    }

    /// A batch whose writes are durable only when `end` finishes without an
    /// error (PostgreSQL's write-behind). Callers report the writes as stored
    /// only after [`WriteBatch::finish`] returns `Ok`.
    pub fn deferred(end: Box<dyn BatchEnd>) -> Self {
        WriteBatch {
            end: Some(end),
            deferred: true,
            _thread: PhantomData,
        }
    }

    /// Whether writes made in this batch are durable only after
    /// [`WriteBatch::finish`].
    pub fn defers_writes(&self) -> bool {
        self.deferred
    }

    /// End the batch: every write made in it is durable, or the error says
    /// why not.
    pub fn finish(mut self) -> Result<(), StoreError> {
        match self.end.take() {
            Some(e) => e.finish(),
            None => Ok(()),
        }
    }
}

impl Drop for WriteBatch {
    fn drop(&mut self) {
        if let Some(e) = self.end.take() {
            let _ = e.finish();
        }
    }
}

impl fmt::Debug for WriteBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteBatch")
            .field("open", &self.end.is_some())
            .field("deferred", &self.deferred)
            .finish()
    }
}

// ---- errors --------------------------------------------------------------------

/// Errors from a store.
///
/// Callers fail open on every variant except in `vci fetch`, `vci push`,
/// `vci prune` and `vci store info`, which exit 2. The variants exist for
/// messages, exit codes and tests, never to decide whether a unit runs.
/// One exit code depends on them: when a unit cannot be stored, `vci run`
/// keeps the tests' exit code for the variants that say the store cannot
/// be used (`Config`, `Unavailable`, `Timeout`, `NotInitialized`,
/// `Incompatible`, `Denied`, `Unsupported`), and exits 2 after the run for
/// the others (`Invalid`, `Backend`, `Other`), as it always did for
/// git-meta's errors. Every message is safe to print: no variant carries a
/// password.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// An argument failed validation. Nothing was written. The `what`
    /// strings match vci-git's: `signer_id`, `storage_key`, `test_key`,
    /// `target`, `envelope`, `input root`, `manifest`.
    Invalid {
        /// What was invalid.
        what: &'static str,
        /// The offending value (empty for bytes).
        value: String,
        /// Why.
        reason: &'static str,
    },
    /// The store selection or its settings are wrong: an unknown backend, a
    /// postgres store without `VCI_STORE_URL`, a bad timeout, connection
    /// settings in `vci.toml`, a backend left out of this build.
    Config(String),
    /// The store cannot be reached or opened: connection refused, file not
    /// readable, a database that is not one. After the first such failure,
    /// later calls of the same process return it at once.
    Unavailable {
        /// [`AttestationStore::kind`] of the store.
        backend: &'static str,
        /// What happened.
        detail: String,
    },
    /// A bounded wait ran out (connect, statement, busy or lock timeout).
    Timeout {
        /// [`AttestationStore::kind`] of the store.
        backend: &'static str,
        /// What was waited for ("connecting", "a statement", "the exchange
        /// lock").
        operation: &'static str,
        /// How long.
        after: std::time::Duration,
    },
    /// The store does not exist where a write expected it, and this role or
    /// file cannot create it.
    NotInitialized {
        /// [`AttestationStore::kind`] of the store.
        backend: &'static str,
        /// What creates it (an owner role's first write, or `vci store init`).
        advice: String,
    },
    /// The store's schema is newer than this vci understands.
    Incompatible {
        /// [`AttestationStore::kind`] of the store.
        backend: &'static str,
        /// The version found.
        found: u32,
        /// The newest version this vci reads.
        supported: u32,
    },
    /// The store refused for lack of privilege (a read-only role or file).
    Denied {
        /// [`AttestationStore::kind`] of the store.
        backend: &'static str,
        /// What was refused ("write", "create the schema").
        operation: &'static str,
        /// The backend's reason.
        detail: String,
    },
    /// The backend does not offer this operation (a remote for a store
    /// without an [`Exchange`], rewriting history outside git-meta).
    Unsupported {
        /// [`AttestationStore::kind`] of the store.
        backend: &'static str,
        /// The operation, in words ("rewriting history").
        operation: &'static str,
    },
    /// A backend's own error, displayed exactly as it is (git-meta's text is
    /// byte-identical to vci 2.7's). [`StoreError::downcast_backend`] gets it
    /// back, for example vci-git's `GitError::NoMetaRemote`.
    Backend(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// Anything else, as text (the command line's own errors, a cached
    /// earlier failure).
    Other(String),
}

impl StoreError {
    /// [`StoreError::Invalid`] for `value`.
    pub fn invalid(what: &'static str, value: &str, reason: &'static str) -> Self {
        StoreError::Invalid {
            what,
            value: value.to_owned(),
            reason,
        }
    }

    /// [`StoreError::Unavailable`].
    pub fn unavailable(backend: &'static str, detail: impl Into<String>) -> Self {
        StoreError::Unavailable {
            backend,
            detail: detail.into(),
        }
    }

    /// [`StoreError::Other`].
    pub fn other(msg: impl Into<String>) -> Self {
        StoreError::Other(msg.into())
    }

    /// Wrap a backend's own error.
    pub fn backend<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        StoreError::Backend(Box::new(e))
    }

    /// The backend error of type `E` this wraps, if it does.
    pub fn downcast_backend<E: std::error::Error + 'static>(&self) -> Option<&E> {
        match self {
            StoreError::Backend(b) => b.downcast_ref::<E>(),
            _ => None,
        }
    }

    /// Whether retrying later might succeed: the store was unreachable or a
    /// wait ran out.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            StoreError::Unavailable { .. } | StoreError::Timeout { .. }
        )
    }

    /// A stable short name for logs and `vci store info --format json`.
    pub fn code(&self) -> &'static str {
        match self {
            StoreError::Invalid { .. } => "invalid",
            StoreError::Config(_) => "config",
            StoreError::Unavailable { .. } => "unavailable",
            StoreError::Timeout { .. } => "timeout",
            StoreError::NotInitialized { .. } => "not-initialized",
            StoreError::Incompatible { .. } => "incompatible",
            StoreError::Denied { .. } => "denied",
            StoreError::Unsupported { .. } => "unsupported",
            StoreError::Backend(_) => "backend",
            StoreError::Other(_) => "other",
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Invalid {
                what,
                value,
                reason,
            } => write!(f, "invalid {what}: {value:?}: {reason}"),
            StoreError::Config(m) => write!(f, "attestation store: {m}"),
            StoreError::Unavailable { backend, detail } => {
                write!(f, "{backend} store unavailable: {detail}")
            }
            StoreError::Timeout {
                backend,
                operation,
                after,
            } => write!(f, "{backend} store: {operation} timed out after {after:?}"),
            StoreError::NotInitialized { backend, advice } => {
                write!(f, "{backend} store is not set up: {advice}")
            }
            StoreError::Incompatible {
                backend,
                found,
                supported,
            } => write!(
                f,
                "{backend} store schema version {found} is newer than this vci reads (up to {supported}): upgrade vci"
            ),
            StoreError::Denied {
                backend,
                operation,
                detail,
            } => write!(f, "{backend} store refused to {operation}: {detail}"),
            StoreError::Unsupported { backend, operation } => {
                write!(f, "the {backend} store does not support {operation}")
            }
            StoreError::Backend(e) => fmt::Display::fmt(e, f),
            StoreError::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Backend(e) => e.source(),
            _ => None,
        }
    }
}

// ---- the store -----------------------------------------------------------------

/// Where vci keeps attestations and input manifests.
///
/// One value per repository per process, shared by every thread as an
/// `Arc<dyn AttestationStore>` (the command line's `store::for_repo`). See
/// the crate docs for the rules every implementation keeps. Each method's
/// "Used by" line names the vci-cli call site it exists for.
pub trait AttestationStore: Send + Sync {
    // ---- identity --------------------------------------------------------

    /// The backend's short name: `"git-meta"`, `"sqlite"`, `"postgres"`.
    /// Messages name the store with it ("attested ... as git-meta `<target>`
    /// `<key>`", "candidate 1: git-meta ..."), so git-meta's output does not
    /// change.
    ///
    /// Used by: plan.rs (warnings, check failures, `vci explain`), run.rs
    /// (the attested line), cmds.rs (`vci fetch`, `vci push`, `vci ci`,
    /// `vci verify` and `vci store info` messages), the metrics log.
    fn kind(&self) -> &'static str;

    /// Where the store is, for messages and `vci store info`. It never
    /// carries a password. Default: [`AttestationStore::kind`].
    ///
    /// Used by: `vci fetch` on a store without an [`Exchange`],
    /// `vci store info`.
    fn location(&self) -> String {
        self.kind().to_owned()
    }

    /// What the backend can do ([`Caps`]). Cheap, with no I/O. Default:
    /// [`Caps::LOCAL`].
    ///
    /// Used by: `vci ci` (the publication gate for shared stores), the
    /// wording of plan.rs and `vci prune` (`run vci fetch` only for lazy
    /// stores) and of `vci fetch` and `vci push` ("local" or "shared"),
    /// `vci store info`.
    fn caps(&self) -> Caps {
        Caps::LOCAL
    }

    /// Whether the store exists. A fresh clone without a git-meta store, a
    /// missing SQLite file and a database without vci's schema answer
    /// [`StoreStatus::Absent`]. Answering creates nothing. Errors: the store
    /// cannot be reached, or its schema is newer than this vci
    /// ([`StoreError::Incompatible`]). Default: `Ready` with no version.
    ///
    /// Used by: plan.rs (the "no attestations are available" warning; an
    /// `Err` runs every test), `vci store info`, and `vci prune` and (on a
    /// store without an [`Exchange`]) `vci fetch` and `vci push`, which exit
    /// 2 on an `Err` before doing anything else.
    fn status(&self) -> Result<StoreStatus, StoreError> {
        Ok(StoreStatus::Ready {
            schema_version: None,
        })
    }

    // ---- reads (required) ------------------------------------------------

    /// The attestations of each of these units, **keys only**: values are
    /// not read ([`ValueState::Unread`]), but `target`, `issued` and `tree`
    /// are set. The result has one list per input id, in input order
    /// (duplicates answered twice; an unknown unit gets an empty list). Each
    /// list holds the records whose key starts with [`key::unit_prefix`] of
    /// the unit's test key and parses with [`key::parse_key`]; foreign keys
    /// are left out. Each list is sorted by key, bytewise, and is the same on
    /// every call while nothing is written. A network backend answers any
    /// number of units in one round trip (the plan asks for about 4,000), or
    /// from what [`AttestationStore::prefetch`] cached.
    ///
    /// Used by: plan.rs lookup (every unit of the plan, keys only);
    /// [`AttestationStore::read_units`].
    fn list_units(&self, test_ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError>;

    /// Every attestation, keys only, sorted by (target, key) bytewise.
    ///
    /// Used by: [`AttestationStore::read_all`] (`vci prune`, the default
    /// [`AttestationStore::orphan_manifests`]), [`AttestationStore::count`].
    fn list_all(&self) -> Result<Vec<StoredEnvelope>, StoreError>;

    /// Read the values of these listed entries in one batch, in place,
    /// matching them by key (pass entries as they were listed: git-meta,
    /// which files records by target, also matches their `target`). Each
    /// entry gets either `bytes`
    /// ([`StoredEnvelope::set_value`]) or an error
    /// ([`StoredEnvelope::set_error`]): [`GONE`] when the key is no longer
    /// stored, [`NOT_FETCHED`] when a lazy store does not hold the value
    /// here, or any other reason. Entries that already hold a value or an
    /// error are read again. `Err` means the store cannot be read at all;
    /// one bad value never fails the call. The listing and this read need
    /// not be one snapshot. Cost: a bounded number of round trips whatever
    /// the length.
    ///
    /// Used by: plan.rs (the chosen candidates; the re-read in rounds 2 and
    /// 3), [`AttestationStore::read_units`], [`AttestationStore::read_all`].
    fn read_values(&self, envs: &mut [&mut StoredEnvelope]) -> Result<(), StoreError>;

    /// The input manifest stored under `root`. `Ok(None)` when it is not
    /// stored or `root` is not a hex id. `Ok(Some)` with `error` set when it
    /// is stored but unreadable ([`NOT_FETCHED`] for a lazy one). It does not
    /// resolve the base ([`AttestationStore::manifest_decoded`] does). Called
    /// concurrently from every verifying thread, about 2,000 times in a large
    /// plan; a network backend serves it from what
    /// [`AttestationStore::prefetch`] cached.
    ///
    /// Used by: plan.rs ManifestLoader (a manifest and its base), cmds.rs
    /// (`vci verify`, `vci prune`).
    fn manifest(&self, root: &str) -> Result<Option<StoredManifest>, StoreError>;

    /// The roots of every stored input manifest, sorted and deduplicated.
    /// Values are not read.
    ///
    /// Used by: `vci prune`.
    fn manifest_roots(&self) -> Result<Vec<String>, StoreError>;

    // ---- writes (required) -----------------------------------------------

    /// Store one attestation.
    ///
    /// * [`NewAttestation::validate`] comes first; nothing is written on
    ///   failure ([`StoreError::Invalid`]).
    /// * The key is [`NewAttestation::hinted_key`]; without a hint, the
    ///   existing key of the same (test key, signer, storage key) (a rewrite
    ///   in place), else [`NewAttestation::plain_key`].
    /// * Every other key of the same (test key, signer, storage key) is
    ///   removed. A [`Caps::shared_writes`] store does it **in the same
    ///   atomic step** as the write, so concurrent puts of the same inputs
    ///   leave exactly one record (SQLite does too). A store may instead
    ///   list, remove and write as separate steps: git-meta does, so puts
    ///   of one slot racing in one repository (threads, or two `vci run`s)
    ///   may leave several records, as an [`Exchange`] store may after a
    ///   merge. Readers tolerate them (every record is verified), and the
    ///   slot's next put collapses them.
    /// * Identical bytes under the same key are a no-op.
    /// * Outside a deferred [`WriteBatch`], the write is durable and visible
    ///   to this store's later reads when the call returns (to every reader
    ///   when [`Caps::shared_writes`]).
    /// * The caller stores the referenced manifest first
    ///   ([`AttestationStore::put_manifest`]); a backend keeps that order
    ///   visible, so no reader sees an attestation before its manifest.
    ///
    /// Returns the stored entry ([`NewAttestation::stored`]).
    ///
    /// Used by: run.rs, through [`AttestationStore::put_for_test`] (each
    /// attested unit); a copy between stores ([`NewAttestation::copy_of`]).
    fn put(&self, att: &NewAttestation<'_>) -> Result<StoredEnvelope, StoreError>;

    /// Store an input manifest's compact bytes under `root`, unless exactly
    /// these bytes are already stored. Returns whether the stored bytes
    /// changed (inside a deferred batch: whether they will). `root` must be
    /// a hex id (`what` = `input root`) and `bytes` non-empty UTF-8 (`what` =
    /// `manifest`). The caller guarantees that `bytes` decode to a manifest
    /// with this root (readers recompute it anyway). A lazy store's
    /// not-fetched row counts as different, so storing the same bytes makes
    /// it readable. A backend that removes manifests by age
    /// ([`AttestationStore::remove_manifests`]) refreshes the age even when
    /// it returns `false`.
    ///
    /// Used by: run.rs (shared base manifests, then each unit's manifest).
    fn put_manifest(&self, root: &str, bytes: &[u8]) -> Result<bool, StoreError>;

    /// Remove these entries, matched by key. Returns the ones that existed,
    /// with their `bytes` as given (callers read the removed values'
    /// `manifestRef`); inside a deferred batch it may return every entry it
    /// was asked to remove. Afterwards no read of this store returns them
    /// (rule 7). A key written again after its removal is live again: a
    /// re-attestation beats an older removal.
    ///
    /// Used by: run.rs (superseded attestations), `vci prune`.
    fn remove(&self, doomed: Vec<StoredEnvelope>) -> Result<Vec<StoredEnvelope>, StoreError>;

    /// Remove the input manifests stored under these roots. Every root is
    /// validated before anything is removed. Returns how many existed and
    /// were removed. A backend with concurrent writers keeps (and does not
    /// count) a root that a stored attestation or another manifest (as its
    /// base) still references, or that was put within its grace period, so
    /// it never deletes a manifest a concurrent writer is about to
    /// reference.
    ///
    /// Used by: run.rs (orphans after supersession), `vci prune`.
    fn remove_manifests(&self, roots: &[&str]) -> Result<usize, StoreError>;

    // ---- reads (provided) ------------------------------------------------

    /// [`AttestationStore::list_units`], then their values in one
    /// [`AttestationStore::read_values`].
    ///
    /// A backend whose `read_values` costs more than a targeted read
    /// overrides this. git-meta must: its `read_values` scans every row of
    /// the store and starts a `git cat-file`, and supersession calls this
    /// once per unit from worker threads.
    ///
    /// Used by: run.rs supersession (one unit, from worker threads) and
    /// `last_durations` (every selected unit).
    fn read_units(&self, test_ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
        let mut units = self.list_units(test_ids)?;
        {
            let mut refs: Vec<&mut StoredEnvelope> = units.iter_mut().flatten().collect();
            self.read_values(&mut refs)?;
        }
        Ok(units)
    }

    /// [`AttestationStore::list_all`] with every value read.
    ///
    /// Used by: `vci prune`; the default [`AttestationStore::orphan_manifests`].
    fn read_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
        let mut all = self.list_all()?;
        {
            let mut refs: Vec<&mut StoredEnvelope> = all.iter_mut().collect();
            self.read_values(&mut refs)?;
        }
        Ok(all)
    }

    /// How many attestations are stored (values not read; values not
    /// fetched yet count).
    ///
    /// Used by: `vci fetch` ("N attestations stored locally", or "N
    /// attestations stored" on a store without an [`Exchange`]),
    /// `vci store info`.
    fn count(&self) -> Result<usize, StoreError> {
        Ok(self.list_all()?.len())
    }

    /// [`AttestationStore::manifest`] for several roots, answered in order.
    ///
    /// Used by: no vci-cli command yet (`vci verify` and `vci prune` read
    /// one root at a time). It is the batch form for a reader of many roots,
    /// such as a copy between stores, and a network backend's own prefetch.
    fn manifests(&self, roots: &[&str]) -> Result<Vec<Option<StoredManifest>>, StoreError> {
        roots.iter().map(|r| self.manifest(r)).collect()
    }

    /// The input manifest under `root`, decoded, with its base manifest read
    /// from this store. `None` when it is not stored; `Some(Err(why))` when
    /// it cannot be read or decoded. The caller still checks the root.
    ///
    /// Used by: run.rs supersession. The nested shape is that of vci-git's
    /// `AttestStore::manifest_decoded`, which the e2e helper `store_common`
    /// calls.
    fn manifest_decoded(
        &self,
        root: &str,
    ) -> Result<Option<Result<vci_core::InputManifest, String>>, StoreError> {
        let Some(m) = self.manifest(root)? else {
            return Ok(None);
        };
        Ok(Some(match m.error {
            Some(e) => Err(e),
            None => decode_manifest(&m.bytes, |base| self.manifest(base)),
        }))
    }

    /// Of these roots, the ones no stored attestation references, sorted.
    /// An attestation references the root its value's `manifestRef` names
    /// ([`key::envelope_manifest_ref`]). A backend may answer from that
    /// reference as recorded when the attestation was stored (an index),
    /// even when the value cannot be read now.
    ///
    /// When some attestation's reference is unknown (a payload that does
    /// not parse or names no hex root; without a recorded reference, a value
    /// that is unreadable or not fetched), the answer is empty and nothing
    /// is removed, unless the backend can tell that this attestation cannot
    /// reference any of these roots. git-meta can: a value not fetched,
    /// stored on a path target that is neither a path the manifests list
    /// nor a directory above one, is not waited for (a unit's manifest lists
    /// its own path); offline it answers empty. Removing a manifest that is still referenced only
    /// makes its unit run again.
    ///
    /// The default reads every value. A backend with an index of
    /// `manifestRef` answers in one query; a lazy backend first fetches the
    /// values that could reference these roots.
    ///
    /// Used by: run.rs after supersession (`drop_orphan_manifests`), then
    /// [`AttestationStore::remove_manifests`].
    fn orphan_manifests(&self, roots: &[&str]) -> Result<Vec<String>, StoreError> {
        if roots.is_empty() {
            return Ok(Vec::new());
        }
        let mut referenced: BTreeSet<String> = BTreeSet::new();
        for e in self.read_all()? {
            match e.manifest_ref() {
                ManifestRef::Root(r) => {
                    referenced.insert(r);
                }
                ManifestRef::Inline => {}
                ManifestRef::Unknown => return Ok(Vec::new()),
            }
        }
        let wanted: BTreeSet<&str> = roots.iter().copied().collect();
        Ok(wanted
            .into_iter()
            .filter(|r| !referenced.contains(*r))
            .map(str::to_owned)
            .collect())
    }

    // ---- writes (provided) -----------------------------------------------

    /// [`AttestationStore::put`] of [`NewAttestation::for_test`].
    ///
    /// Used by: run.rs.
    fn put_for_test(
        &self,
        test_id: &str,
        signer: &str,
        storage_key: &str,
        hint: Option<&KeyHint>,
        envelope: &[u8],
    ) -> Result<StoredEnvelope, StoreError> {
        self.put(&NewAttestation::for_test(
            test_id,
            signer,
            storage_key,
            hint,
            envelope,
        ))
    }

    /// Open a write batch on this thread. While it is open, this thread's
    /// writes through this store may share a session, a connection or a
    /// transaction. For a [`WriteBatch::deferred`] batch they become durable
    /// only at [`WriteBatch::finish`]: `put` returns the entry it will store,
    /// `put_manifest` may report `true`, `remove` may return every entry it
    /// was asked to remove, and reads made while the batch is open need not
    /// see the batch's writes. `finish` applies them in order (manifests,
    /// then attestations, then removals) and atomically, or fails. The
    /// default groups nothing. Callers ignore an `Err` from `batch` itself
    /// (they write without one) but never an `Err` from `finish`.
    ///
    /// Used by: run.rs. Every unit of a project is stored inside one batch,
    /// finished right after that project's units. A deferred batch's units
    /// are reported as attested only once it finishes `Ok`; if it fails,
    /// each of them is refused. An immediate batch's units are reported as
    /// each is stored, and a failure to finish it is a warning.
    fn batch(&self) -> Result<WriteBatch, StoreError> {
        Ok(WriteBatch::none())
    }

    // ---- prefetch and warm-up (provided) ---------------------------------

    /// Make what `what` names cheap to read next. A lazy store downloads the
    /// values that are not fetched yet (git-meta: one `git fetch` of object
    /// ids). A network store loads listings, values and manifests into a
    /// cache in a few round trips. A store that always holds its values does
    /// nothing (the default).
    ///
    /// After a prefetch, reads through this handle may be served from a
    /// snapshot taken at prefetch time. That snapshot always reflects this
    /// handle's own later writes and removals (a put evicts or updates what
    /// it touches, including a cached "no such manifest"). Other writers'
    /// changes may be missed until the next prefetch of the same data, which
    /// picks them up (a later prefetch of units lists them again). Missing
    /// them is safe: a stale record only makes a unit run, and every record
    /// is verified.
    ///
    /// Failing to fetch some values is reported in [`Hydration::error`] and
    /// [`Hydration::unresolved`] (their units run). `Err` is for a store
    /// that cannot be used at all. Callers treat both as warnings and read
    /// afterwards whatever the result.
    ///
    /// Used by: plan.rs (the chosen candidates before the lookup; rounds 2
    /// and 3), run.rs (before supersession), cmds.rs (`vci verify`,
    /// `vci prune`).
    fn prefetch(&self, what: Prefetch<'_>) -> Result<Hydration, StoreError> {
        let _ = what;
        Ok(Hydration::default())
    }

    /// Start, in the background, whatever makes the first reads fast (page
    /// in a file, open a connection and its TLS session). It never blocks
    /// and never fails. Default: nothing.
    ///
    /// Used by: plan.rs, at the start of a plan.
    fn warm(&self) {}

    // ---- hints (provided; best effort, never fail) ------------------------

    /// The attestations a plan remembered passing on the tree whose id
    /// starts with `tree16`, as test key -> attestation key. They only decide
    /// which candidates are read first; every candidate is still verified.
    /// Empty on any failure, bounded in time. Default: nothing remembered.
    ///
    /// Used by: plan.rs `passing_memos` (base tree, then head tree).
    fn passing_on(&self, tree16: &str) -> BTreeMap<String, String> {
        let _ = tree16;
        BTreeMap::new()
    }

    /// Remember that these (test key, attestation key) pairs passed on
    /// `tree16`, for [`AttestationStore::passing_on`]. A backend may forget
    /// entries older than a week. Failures are ignored.
    ///
    /// Used by: plan.rs, after the verdicts.
    fn remember_passing(&self, tree16: &str, items: &[(String, String)]) {
        let _ = (tree16, items);
    }

    /// Whether `name` was flagged ([`AttestationStore::set_flag`]), for
    /// example `plan:natives:<project>`. `false` on any failure. Called from
    /// probe threads while a fetch may be writing.
    ///
    /// Used by: plan.rs (start the Rails boot early).
    fn flag(&self, name: &str) -> bool {
        let _ = name;
        false
    }

    /// Remember `name`, a fact about this project's plans that a later plan
    /// reads before it reads any attestation. Failures are ignored.
    ///
    /// Used by: plan.rs (a verdict thread that compared native libraries).
    fn set_flag(&self, name: &str) {
        let _ = name;
    }

    // ---- reporting and exchange (provided) --------------------------------

    /// Lines the backend wants in the timing report after a write phase, in
    /// `<what>: <numbers>` form without the project label (the caller adds
    /// it). git-meta returns `"put_manifest seconds: session 1.0, read
    /// current 0.2, set 0.3, stamp 0.1"`, so the metrics history keeps its
    /// keys. Default: none.
    ///
    /// Used by: run.rs, when metrics are on.
    fn timing_report(&self) -> Vec<String> {
        Vec::new()
    }

    /// The store's exchange with a remote, when writes reach other machines
    /// only through push and fetch (git-meta). `None` for a store that is
    /// local (SQLite) or already shared (PostgreSQL): `vci fetch` and
    /// `vci push` then say so and exit 0, `vci plan --fetch` fetches nothing,
    /// and `vci ci --push` succeeds without sending anything.
    ///
    /// Used by: cmds.rs (`vci fetch`, `vci push`, `vci ci --push` and
    /// `vci ci`'s "N unit(s) attested" line, the default-remote message,
    /// `vci store info`), plan.rs (`--fetch`).
    fn exchange(&self) -> Option<&dyn Exchange> {
        None
    }
}

/// A store whose writes travel to other machines through push and fetch
/// with a remote ([`AttestationStore::exchange`]).
pub trait Exchange: Send + Sync {
    /// What the remote holds the attestations in, for messages
    /// (`"refs/meta/main"` for git-meta).
    fn exchange_point(&self) -> &str;

    /// The location of `remote` (a remote name as [`FetchOutcome::remote`]
    /// gives it) with any credentials removed ([`select::redact`]), printed
    /// by `vci fetch` and `vci push` as "vci: `<kind>` remote `<name>` is
    /// `<location>`" when the user named no remote. Default: unknown.
    fn remote_location(&self, remote: &str) -> Option<String> {
        let _ = remote;
        None
    }

    /// Make the remote's attestations visible to this store's reads (keys
    /// at least: a lazy store may leave values to
    /// [`AttestationStore::prefetch`]). `remote`: a name or URL, `None` for
    /// the configured default. It runs on a background thread during
    /// `vci plan --fetch` while other threads read the store, and is bounded
    /// by the backend's timeouts and locks. A store keeping a pool of
    /// readers refreshes it afterwards.
    fn fetch(&self, remote: Option<&str>) -> Result<FetchOutcome, StoreError>;

    /// Publish the local writes and removals to the remote.
    fn push(&self, remote: Option<&str>, mode: PushMode) -> Result<PushOutcome, StoreError>;
}

/// Decode a stored input manifest's compact `bytes`, reading the base
/// manifest it lists its entries on top of (vci 2.1.8) through `base`. The
/// bytes carry no trust: the caller compares the result's root with the
/// signed input root. A missing base reads as "base input manifest `<root>`
/// is not in the store".
pub fn decode_manifest(
    bytes: &[u8],
    base: impl FnOnce(&str) -> Result<Option<StoredManifest>, StoreError>,
) -> Result<vci_core::InputManifest, String> {
    vci_core::InputManifest::from_compact_with(bytes, |b| match base(b) {
        Ok(Some(m)) if m.error.is_none() => Ok(m.bytes),
        Ok(Some(m)) => Err(vci_core::ManifestError::Compact(format!(
            "base manifest {b} unreadable: {}",
            m.error.unwrap_or_default()
        ))),
        Ok(None) => Err(vci_core::ManifestError::MissingBase(b.to_owned())),
        Err(e) => Err(vci_core::ManifestError::Compact(format!(
            "base manifest {b}: {e}"
        ))),
    })
    .map_err(|e| e.to_string())
}

// ---- a store that failed -------------------------------------------------------

/// A store that could not be selected or opened. Every read and write
/// (and [`AttestationStore::status`], [`AttestationStore::batch`] and
/// [`AttestationStore::prefetch`]) returns [`StoreError::Unavailable`] and
/// every hint does nothing, so callers fail open through their usual error
/// paths: `vci plan` warns and runs everything, `vci run` refuses to store
/// each unit, saying why (the tests still run, and the exit code stays
/// theirs), and `vci fetch`, `vci push`, `vci prune` and `vci store info`
/// exit 2.
#[derive(Debug, Clone)]
pub struct FailedStore {
    kind: &'static str,
    why: String,
}

impl FailedStore {
    /// A store of `kind` that cannot be used, and why (never a password:
    /// pass the error's text, which is already scrubbed).
    pub fn new(kind: &'static str, why: impl Into<String>) -> Self {
        FailedStore {
            kind,
            why: why.into(),
        }
    }

    /// The failure for a store the user asked for by `wanted`: its kind is
    /// the matching factory's, or `"unknown"`.
    pub fn for_request(factories: &[&dyn BackendFactory], wanted: &str, err: &StoreError) -> Self {
        let kind = factories
            .iter()
            .map(|f| f.kind())
            .find(|k| *k == wanted)
            .unwrap_or("unknown");
        FailedStore::new(kind, err.to_string())
    }

    fn error(&self) -> StoreError {
        StoreError::Unavailable {
            backend: self.kind,
            detail: self.why.clone(),
        }
    }
}

impl AttestationStore for FailedStore {
    fn kind(&self) -> &'static str {
        self.kind
    }
    fn location(&self) -> String {
        format!("{} (unavailable: {})", self.kind, self.why)
    }
    fn status(&self) -> Result<StoreStatus, StoreError> {
        Err(self.error())
    }
    fn list_units(&self, _test_ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
        Err(self.error())
    }
    fn list_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
        Err(self.error())
    }
    fn read_values(&self, _envs: &mut [&mut StoredEnvelope]) -> Result<(), StoreError> {
        Err(self.error())
    }
    fn manifest(&self, _root: &str) -> Result<Option<StoredManifest>, StoreError> {
        Err(self.error())
    }
    fn manifest_roots(&self) -> Result<Vec<String>, StoreError> {
        Err(self.error())
    }
    fn put(&self, _att: &NewAttestation<'_>) -> Result<StoredEnvelope, StoreError> {
        Err(self.error())
    }
    fn put_manifest(&self, _root: &str, _bytes: &[u8]) -> Result<bool, StoreError> {
        Err(self.error())
    }
    fn remove(&self, _doomed: Vec<StoredEnvelope>) -> Result<Vec<StoredEnvelope>, StoreError> {
        Err(self.error())
    }
    fn remove_manifests(&self, _roots: &[&str]) -> Result<usize, StoreError> {
        Err(self.error())
    }
    fn batch(&self) -> Result<WriteBatch, StoreError> {
        Err(self.error())
    }
    fn prefetch(&self, _what: Prefetch<'_>) -> Result<Hydration, StoreError> {
        Err(self.error())
    }
}

// ---- opening a store -----------------------------------------------------------

/// What a backend may need from the repository to open its store. The
/// command line builds it once per repository per process.
#[derive(Clone)]
pub struct OpenContext {
    /// The work tree root.
    pub repo_root: PathBuf,
    /// This worktree's git directory (git-meta keeps `git-meta.sqlite` here).
    pub git_dir: PathBuf,
    /// The git directory shared by every linked worktree (the SQLite
    /// backend's default home, and the base of relative SQLite paths).
    pub git_common_dir: PathBuf,
    /// The repository id (its smallest root commit), computed on first call.
    /// It is the default namespace of a shared server: attestations made in
    /// another repository can never verify here.
    pub repo_id: Arc<dyn Fn() -> Result<String, String> + Send + Sync>,
    /// How many threads will use the store at once (`VCI_JOBS`, else one
    /// per CPU), for pool sizes.
    pub jobs: usize,
    /// The vci command (`plan`, `run`, ...; `vci` when unknown), shown by
    /// PostgreSQL in `application_name`.
    pub command: String,
    /// The command reads or writes the whole store (`vci prune`; a copy
    /// between stores would too): statement timeouts are lifted to ten
    /// minutes.
    pub long_running: bool,
}

impl fmt::Debug for OpenContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenContext")
            .field("repo_root", &self.repo_root)
            .field("git_dir", &self.git_dir)
            .field("git_common_dir", &self.git_common_dir)
            .field("jobs", &self.jobs)
            .field("command", &self.command)
            .field("long_running", &self.long_running)
            .finish_non_exhaustive()
    }
}

/// Opens one kind of store. The command line registers one per backend it
/// was built with, so a new backend is a new crate plus one registration
/// line, with no change to this crate.
pub trait BackendFactory: Send + Sync {
    /// The name `VCI_STORE` and `[store] backend` use, and
    /// [`AttestationStore::kind`] of what it opens.
    fn kind(&self) -> &'static str;

    /// One line saying what the backend is and where it keeps records, for
    /// a listing of the backends a vci has (vci-cli prints it nowhere yet).
    fn summary(&self) -> &'static str;

    /// Open the store `sel` describes.
    ///
    /// It must not block on the network or create anything: connections and
    /// files are opened on first use, so a bad setting fails here at once
    /// ([`StoreError::Config`]) and an unreachable server fails at the first
    /// call, bounded by its connect timeout.
    fn open(
        &self,
        sel: &select::Selection,
        cx: &OpenContext,
    ) -> Result<Arc<dyn AttestationStore>, StoreError>;
}

/// A backend this build of vci left out (a cargo feature turned off). Its
/// `open` says so.
#[derive(Debug, Clone, Copy)]
pub struct MissingBackend {
    /// The backend's name.
    pub kind: &'static str,
    /// The cargo feature that would build it in.
    pub feature: &'static str,
}

impl BackendFactory for MissingBackend {
    fn kind(&self) -> &'static str {
        self.kind
    }
    fn summary(&self) -> &'static str {
        "not built into this vci"
    }
    fn open(
        &self,
        _sel: &select::Selection,
        _cx: &OpenContext,
    ) -> Result<Arc<dyn AttestationStore>, StoreError> {
        Err(StoreError::Config(format!(
            "this vci was built without the {} store (cargo feature `{}`)",
            self.kind, self.feature
        )))
    }
}

/// Open the store `sel` names with the first factory of its kind. An
/// unknown name is a [`StoreError::Config`] that lists the backends this vci
/// has.
pub fn open(
    factories: &[&dyn BackendFactory],
    sel: &select::Selection,
    cx: &OpenContext,
) -> Result<Arc<dyn AttestationStore>, StoreError> {
    let want = sel.kind.value.as_str();
    match factories.iter().find(|f| f.kind() == want) {
        Some(f) => f.open(sel, cx),
        None => Err(StoreError::Config(format!(
            "unknown store backend {want:?} (from {}); this vci has: {}",
            sel.kind.source,
            factories
                .iter()
                .map(|f| f.kind())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

// ---- keys ----------------------------------------------------------------------

pub mod key {
    //! The key format every backend stores records under (vci 2.2 and
    //! later), and its parsers.
    //!
    //! ```text
    //! vci:attestation:<test key>:<signer>:<storage key>[:<issued hex>.<tree16 | ->]
    //! vci:manifest:<input root>
    //! ```
    //!
    //! * `<test key>` is the BLAKE3 hash of the test id, 64 lowercase hex
    //!   ([`test_key`]).
    //! * `<signer>` is 16 lowercase hex naming the signing key (a hint,
    //!   unverified).
    //! * `<storage key>` is 2 to 128 lowercase hex characters naming
    //!   everything that makes two attestations interchangeable.
    //! * The hint gives when the attestation was issued (seconds, in hex) and
    //!   the first 16 hex digits of the tree it was made on (`-` when
    //!   unknown). Keys written before vci 2.2 have no hint.
    //!
    //! Segments are separated by `:`. git-meta turns each segment into a tree
    //! directory, the only place a `/` form appears; the other backends store
    //! the key as one string. Keys compare bytewise (Rust's `str` order):
    //! under a natural-language collation, which skips `:`, `.` and `-` at
    //! its first level, a unit's listing would come back in another order.

    use super::{KeyHint, StoreError};

    /// Key namespace of every vci attestation.
    pub const KEY_PREFIX: &str = "vci:attestation";
    /// Key namespace of the stored input manifests.
    pub const MANIFEST_PREFIX: &str = "vci:manifest";
    /// Length of a signer id.
    pub const SIGNER_ID_LEN: usize = 16;
    /// Shortest hex id a key segment may hold (test key, storage key, root).
    pub const MIN_HEX_LEN: usize = 2;
    /// Longest hex id a key segment may hold.
    pub const MAX_HEX_LEN: usize = 128;
    /// git-meta's minimum path-target length: a unit path shorter than this
    /// goes on the [`PROJECT_TARGET`].
    pub const MIN_TARGET_LEN: usize = 3;
    /// The target of units without a usable path, and of every manifest.
    pub const PROJECT_TARGET: &str = "project";

    fn lower_hex(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    /// Whether `s` is lowercase hex of 2 to 128 characters.
    pub fn is_hex_id(s: &str) -> bool {
        (MIN_HEX_LEN..=MAX_HEX_LEN).contains(&s.len()) && lower_hex(s)
    }

    /// Whether `s` is a signer id: exactly 16 lowercase hex characters.
    pub fn is_signer_id(s: &str) -> bool {
        s.len() == SIGNER_ID_LEN && lower_hex(s)
    }

    /// [`is_signer_id`], as an error with vci-git's wording (`what` =
    /// `signer_id`).
    pub fn check_signer(s: &str) -> Result<(), StoreError> {
        if s.len() != SIGNER_ID_LEN {
            return Err(StoreError::invalid(
                "signer_id",
                s,
                "must be exactly 16 characters",
            ));
        }
        if !lower_hex(s) {
            return Err(StoreError::invalid("signer_id", s, "must be lowercase hex"));
        }
        Ok(())
    }

    /// [`is_hex_id`], as an error naming `what` (`storage_key`, `test_key`,
    /// `input root`), with vci-git's wording.
    pub fn check_hex(what: &'static str, s: &str) -> Result<(), StoreError> {
        if !(MIN_HEX_LEN..=MAX_HEX_LEN).contains(&s.len()) {
            return Err(StoreError::invalid(what, s, "must be 2 to 128 characters"));
        }
        if !lower_hex(s) {
            return Err(StoreError::invalid(what, s, "must be lowercase hex"));
        }
        Ok(())
    }

    /// `bytes` as text, or [`StoreError::Invalid`] naming `what`
    /// (`envelope`, `manifest`). Every backend stores UTF-8 only, so values
    /// can be copied into git-meta, which stores strings.
    pub fn check_utf8<'b>(what: &'static str, bytes: &'b [u8]) -> Result<&'b str, StoreError> {
        std::str::from_utf8(bytes).map_err(|_| StoreError::Invalid {
            what,
            value: String::new(),
            reason: "must be UTF-8",
        })
    }

    /// The test key of a test id: BLAKE3, 64 lowercase hex.
    pub fn test_key(test_id: &str) -> String {
        vci_core::test_key(test_id)
    }

    /// The target label of a test id: `path:<p>` where `p` is the test id
    /// before its first `#`, when `p` is a relative path of at least 3 bytes
    /// without NUL and without empty, `.` or `..` segments; otherwise
    /// [`PROJECT_TARGET`]. It equals git-meta's `Target` label (a parity test
    /// in vci-git checks this).
    pub fn target_label(test_id: &str) -> String {
        let path = test_id.split('#').next().unwrap_or(test_id);
        let ok = path.len() >= MIN_TARGET_LEN
            && !path.starts_with('/')
            && !path.contains('\0')
            && path
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != "..");
        if ok {
            format!("path:{path}")
        } else {
            PROJECT_TARGET.to_owned()
        }
    }

    /// Whether `t` could have come from [`target_label`].
    pub fn is_target_label(t: &str) -> bool {
        t == PROJECT_TARGET
            || t.strip_prefix("path:")
                .is_some_and(|p| !p.contains('#') && target_label(p) == t)
    }

    /// The prefix every attestation key of the unit with this test key
    /// starts with (SQL backends may range-scan on it).
    pub fn unit_prefix(test_key: &str) -> String {
        format!("{KEY_PREFIX}:{test_key}:")
    }

    /// The key without a hint (as before vci 2.2).
    pub fn attestation_key(test_key: &str, signer: &str, storage_key: &str) -> String {
        format!("{KEY_PREFIX}:{test_key}:{signer}:{storage_key}")
    }

    /// The key with its hint: `...:<issued hex>.<tree16 | ->`. The tree is
    /// written as `-` unless it gives 16 hex characters, and a negative
    /// `issued` counts as 0.
    pub fn attestation_key_hinted(
        test_key: &str,
        signer: &str,
        storage_key: &str,
        hint: &KeyHint,
    ) -> String {
        let tree = hint
            .tree
            .as_deref()
            .map(|t| t.chars().take(16).collect::<String>())
            .filter(|t| t.len() == 16 && t.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or_else(|| "-".to_owned());
        format!(
            "{KEY_PREFIX}:{test_key}:{signer}:{storage_key}:{:x}.{tree}",
            hint.issued.max(0)
        )
    }

    fn parse_hint(part: &str) -> Option<KeyHint> {
        let (issued, tree) = part.split_once('.')?;
        if issued.is_empty() || issued.len() > 16 || !issued.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        let issued = i64::from_str_radix(issued, 16).ok()?;
        let tree = match tree {
            "-" => None,
            t if t.len() == 16 && t.bytes().all(|b| b.is_ascii_hexdigit()) => Some(t.to_owned()),
            _ => return None,
        };
        Some(KeyHint { issued, tree })
    }

    /// The hint a key carries, if any (keys written before vci 2.2 carry
    /// none).
    pub fn parse_key_hint(key: &str) -> Option<KeyHint> {
        let rest = key.strip_prefix(KEY_PREFIX)?.strip_prefix(':')?;
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() == 4 {
            parse_hint(parts[3])
        } else {
            None
        }
    }

    /// (test key, signer, storage key) of a key with vci's shape, with or
    /// without a valid hint. Any other key is foreign: `None`.
    pub fn parse_key(key: &str) -> Option<(&str, &str, &str)> {
        let rest = key.strip_prefix(KEY_PREFIX)?.strip_prefix(':')?;
        let mut parts = rest.split(':');
        let (Some(tk), Some(signer), Some(sk)) = (parts.next(), parts.next(), parts.next()) else {
            return None;
        };
        match (parts.next(), parts.next()) {
            (None, _) => {}
            (Some(h), None) if parse_hint(h).is_some() => {}
            _ => return None,
        }
        (is_hex_id(tk) && is_signer_id(signer) && is_hex_id(sk)).then_some((tk, signer, sk))
    }

    /// The key of the input manifest with this root.
    pub fn manifest_key(root: &str) -> String {
        format!("{MANIFEST_PREFIX}:{root}")
    }

    /// The input root a manifest key names, if the key has vci's shape.
    pub fn parse_manifest_key(key: &str) -> Option<&str> {
        let root = key.strip_prefix(MANIFEST_PREFIX)?.strip_prefix(':')?;
        is_hex_id(root).then_some(root)
    }

    /// Which stored manifest an envelope's (unverified) payload names.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ManifestRef {
        /// `predicate.manifestRef`, a hex input root.
        Root(String),
        /// None: the manifest is inline (attestations made before vci 1.9.0).
        Inline,
        /// Unknown: the envelope, its payload or its predicate does not
        /// parse, or `manifestRef` is not a hex id. A garbage collector then
        /// keeps every manifest.
        Unknown,
    }

    /// The `manifestRef` of a stored DSSE envelope's vci predicate. A backend
    /// may store it in an indexed column at put time; it decides only what
    /// to keep and prefetch, never what to trust.
    pub fn envelope_manifest_ref(bytes: &[u8]) -> ManifestRef {
        use base64::Engine as _;
        let Ok(env) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return ManifestRef::Unknown;
        };
        let Some(payload) = env["payload"]
            .as_str()
            .and_then(|p| base64::engine::general_purpose::STANDARD.decode(p).ok())
        else {
            return ManifestRef::Unknown;
        };
        let Ok(st) = serde_json::from_slice::<serde_json::Value>(&payload) else {
            return ManifestRef::Unknown;
        };
        if !st["predicate"].is_object() {
            return ManifestRef::Unknown;
        }
        match &st["predicate"]["manifestRef"] {
            serde_json::Value::Null => ManifestRef::Inline,
            serde_json::Value::String(r) if is_hex_id(r) => ManifestRef::Root(r.clone()),
            _ => ManifestRef::Unknown,
        }
    }
}

// ---- selection -----------------------------------------------------------------

pub mod select {
    //! Which store a command uses, and its settings.
    //!
    //! The backend, highest precedence first:
    //!
    //! 1. `VCI_STORE` in the environment: a backend name (`git-meta`,
    //!    `sqlite`, `postgres`, or another registered backend). Never a URL:
    //!    a value with `://` is refused, without being printed.
    //! 2. The scheme of `VCI_STORE_URL`: `postgres://` or `postgresql://`
    //!    selects postgres, `sqlite:` selects sqlite, `libsql://` selects
    //!    libsql (an `https://` URL selects nothing: name the backend).
    //! 3. `[store] backend` in the working tree's `vci.toml`.
    //! 4. `git-meta`.
    //!
    //! Every other setting: the environment, then `vci.toml`, then the
    //! default. A server's address and credentials come only from
    //! `VCI_STORE_URL` and `VCI_STORE_TOKEN`, never from `vci.toml`, which
    //! every checkout carries (a pull request's too): a URL, host, user,
    //! password, token or database name there is refused, naming the key and
    //! never its value. The command line reads `VCI_STORE_URL`,
    //! `VCI_STORE_TOKEN` and `VCI_STORE` once at start-up and removes them
    //! from its own environment, so no test process, adapter or hook ever
    //! sees them ([`NEVER_TO_CHILDREN`]).
    //!
    //! This module only parses and validates. The command line turns a
    //! [`Selection`] into a store through the registered
    //! [`crate::BackendFactory`]s.

    use std::collections::BTreeMap;
    use std::fmt;
    use std::time::Duration;

    use serde::{Deserialize, Serialize};

    use crate::StoreError;

    /// Selects the backend by name.
    pub const ENV_STORE: &str = "VCI_STORE";
    /// The store's location: a `postgres://` URL (which may carry a
    /// password), `sqlite:<path>`, or a libSQL server (`libsql://`,
    /// `https://`, `http://`; it may carry an `authToken`) or file
    /// (`file:<path>`). The only place a connection string is read from.
    pub const ENV_STORE_URL: &str = "VCI_STORE_URL";
    /// A libSQL server's auth token (a Turso database token). A secret,
    /// like `VCI_STORE_URL`.
    pub const ENV_TOKEN: &str = "VCI_STORE_TOKEN";
    /// The libSQL store's local replica of a remote database: a path
    /// (absolute, or relative to the git common directory). Setting it asks
    /// for the replica mode.
    pub const ENV_REPLICA: &str = "VCI_STORE_REPLICA";
    /// `off`: no `fsync` in the SQLite files vci keeps (git-meta's, the
    /// SQLite store's, the libSQL store's local file); `replica`: the libSQL
    /// store reads a local replica of its remote database.
    pub const ENV_SYNC: &str = "VCI_STORE_SYNC";
    /// The namespace of this repository's rows on a shared server (default:
    /// the repository id).
    pub const ENV_NAMESPACE: &str = "VCI_STORE_NAMESPACE";
    /// Seconds to wait to connect (default 5).
    pub const ENV_CONNECT_TIMEOUT: &str = "VCI_STORE_CONNECT_TIMEOUT_SECS";
    /// Seconds one statement or request may take (default 30).
    pub const ENV_TIMEOUT: &str = "VCI_STORE_TIMEOUT_SECS";
    /// Every variable this module reads. The e2e harnesses remove them all.
    pub const ENV_VARS: &[&str] = &[
        ENV_STORE,
        ENV_STORE_URL,
        ENV_NAMESPACE,
        ENV_CONNECT_TIMEOUT,
        ENV_TIMEOUT,
        ENV_TOKEN,
        ENV_REPLICA,
        ENV_SYNC,
    ];
    /// Variables vci removes from its own environment at start-up (keeping
    /// their values in memory), and that the child environment builder drops
    /// again, so that they never reach a test, an adapter or a hook (other
    /// `VCI_*` variables pass through as built-in ignore). `VCI_STORE` is
    /// one of them because a connection string put there by mistake would
    /// otherwise reach every test.
    pub const NEVER_TO_CHILDREN: &[&str] = &[ENV_STORE, ENV_STORE_URL, ENV_TOKEN];
    /// The backend when nothing chooses one.
    pub const DEFAULT_BACKEND: &str = "git-meta";
    /// The SQLite store's file name in the git common directory.
    pub const DEFAULT_SQLITE_FILE: &str = "vci-store.sqlite";
    /// The libSQL store's file (its local mode) or replica (its replica
    /// mode) in the git common directory.
    pub const DEFAULT_LIBSQL_FILE: &str = "vci-store.libsql";
    /// The PostgreSQL schema holding vci's tables.
    pub const DEFAULT_SCHEMA: &str = "vci";
    /// The default bound on connecting.
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    /// The default bound on one statement or request.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
    /// The default number of connections one process opens to a server.
    pub const DEFAULT_POOL: u32 = 8;
    /// The default age below which an unreferenced manifest is never removed
    /// from a shared store.
    pub const DEFAULT_MANIFEST_GRACE: Duration = Duration::from_secs(3600);
    /// The longest connect or statement timeout accepted.
    pub const MAX_TIMEOUT: Duration = Duration::from_secs(3600);

    /// A `vci.toml` key that is refused: it deserializes from anything
    /// (without keeping or echoing the value) so the error can name the key.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Refused;

    impl<'de> Deserialize<'de> for Refused {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            serde::de::IgnoredAny::deserialize(d).map(|_| Refused)
        }
    }

    /// `[store]` in `vci.toml`. It is never an input of a test: changing it
    /// changes no config hash and invalidates no attestation.
    #[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct StoreSettings {
        /// `"git-meta"` (the default), `"sqlite"`, `"postgres"`, or another
        /// registered backend.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub backend: Option<String>,
        /// The connect timeout, as `"5s"`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub connect_timeout: Option<String>,
        /// The statement or request timeout, as `"30s"`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<String>,
        /// `[store.sqlite]`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sqlite: Option<SqliteSettings>,
        /// `[store.postgres]` (tuning only, never an address).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub postgres: Option<PostgresSettings>,
        /// `[store.libsql]` (never an address or a token).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub libsql: Option<LibsqlSettings>,
        /// `[store.options]`: non-secret string settings for backends this
        /// crate does not describe (an HTTP or gRPC service). The backend's
        /// factory reads them and refuses the ones it does not know.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub options: BTreeMap<String, String>,
        /// Refused ([`StoreSettings::check`]).
        #[serde(default, skip_serializing)]
        pub url: Option<Refused>,
    }

    /// `[store.sqlite]`.
    #[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct SqliteSettings {
        /// The database file, relative to the git common directory, without
        /// `..`. Default: `vci-store.sqlite`. An absolute path can be given
        /// only through `VCI_STORE_URL=sqlite:<path>`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
    }

    /// `[store.postgres]`: everything except how to connect.
    #[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct PostgresSettings {
        /// The schema holding vci's tables (`[a-z_][a-z0-9_]*`, at most 63
        /// bytes; default `vci`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<String>,
        /// The namespace of this repository's rows (default: the repository
        /// id). `VCI_STORE_NAMESPACE` overrides it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub namespace: Option<String>,
        /// The most connections one vci process opens, 1 to 64 (default 8).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pool: Option<u32>,
        /// The age below which an unreferenced manifest is kept, as `"1h"`
        /// (default one hour, at most 30 days).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub manifest_grace: Option<String>,
        /// Refused.
        #[serde(default, skip_serializing)]
        pub url: Option<Refused>,
        /// Refused.
        #[serde(default, skip_serializing)]
        pub host: Option<Refused>,
        /// Refused.
        #[serde(default, skip_serializing)]
        pub user: Option<Refused>,
        /// Refused.
        #[serde(default, skip_serializing)]
        pub password: Option<Refused>,
        /// Refused.
        #[serde(default, skip_serializing)]
        pub dbname: Option<Refused>,
    }

    /// `[store.libsql]`: everything except where the server is and how to
    /// sign in.
    #[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct LibsqlSettings {
        /// The local file (local mode) or the replica (replica mode),
        /// relative to the git common directory, without `..`. Default:
        /// `vci-store.libsql`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        /// Read a local replica of the remote database named by
        /// `VCI_STORE_URL` (synced when it is first read, and at each later
        /// prefetch) instead of
        /// asking the server for every read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub replica: Option<bool>,
        /// The namespace of this repository's records on a shared database
        /// (default: the repository id). `VCI_STORE_NAMESPACE` overrides it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub namespace: Option<String>,
        /// Refused.
        #[serde(default, skip_serializing)]
        pub url: Option<Refused>,
        /// Refused.
        #[serde(default, skip_serializing)]
        pub token: Option<Refused>,
        /// Refused.
        #[serde(default, skip_serializing, alias = "authToken")]
        pub auth_token: Option<Refused>,
    }

    impl StoreSettings {
        /// Refuse connection settings in `vci.toml`. A password there would
        /// be public, and a host there would let a pull request send CI's
        /// credentials to a server it controls. The error names the keys,
        /// never their values.
        pub fn check(&self) -> Result<(), StoreError> {
            let mut found = Vec::new();
            if self.url.is_some() {
                found.push("store.url");
            }
            if let Some(p) = &self.postgres {
                for (name, present) in [
                    ("store.postgres.url", p.url.is_some()),
                    ("store.postgres.host", p.host.is_some()),
                    ("store.postgres.user", p.user.is_some()),
                    ("store.postgres.password", p.password.is_some()),
                    ("store.postgres.dbname", p.dbname.is_some()),
                ] {
                    if present {
                        found.push(name);
                    }
                }
            }
            if let Some(l) = &self.libsql {
                for (name, present) in [
                    ("store.libsql.url", l.url.is_some()),
                    ("store.libsql.token", l.token.is_some()),
                    ("store.libsql.auth_token", l.auth_token.is_some()),
                ] {
                    if present {
                        found.push(name);
                    }
                }
            }
            if found.is_empty() {
                return Ok(());
            }
            Err(StoreError::Config(format!(
                "vci.toml sets {}: connection settings are read only from ${ENV_STORE_URL} and ${ENV_TOKEN} (vci.toml is in every checkout, a pull request's too); remove them and pass ${ENV_STORE_URL} (and ${ENV_TOKEN}) as secrets",
                found.join(", ")
            )))
        }
    }

    /// Where a setting came from, for `vci store info` and messages.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Source {
        /// The built-in default.
        Default,
        /// `[store]` in the working tree's `vci.toml`.
        File,
        /// This environment variable.
        Env(&'static str),
    }

    impl fmt::Display for Source {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Source::Default => f.write_str("the default"),
                Source::File => f.write_str("vci.toml [store]"),
                Source::Env(v) => write!(f, "${v}"),
            }
        }
    }

    /// A setting's value and where it came from.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Sourced<T> {
        /// The value.
        pub value: T,
        /// Where it came from.
        pub source: Source,
    }

    impl<T> Sourced<T> {
        /// A built-in default.
        pub fn default_value(value: T) -> Self {
            Sourced {
                value,
                source: Source::Default,
            }
        }
    }

    /// A string that may carry credentials (`VCI_STORE_URL`), or that is a
    /// credential as a whole (`VCI_STORE_TOKEN`, [`Secret::opaque`]).
    /// `Debug` and `Display` print it redacted; only [`Secret::expose`]
    /// gives it whole.
    #[derive(Clone, PartialEq, Eq)]
    pub struct Secret(String, bool);

    impl Secret {
        /// Wrap a secret that may carry credentials (a URL, a libpq string):
        /// its redacted form keeps what is not a credential.
        pub fn new(s: impl Into<String>) -> Self {
            Secret(s.into(), false)
        }

        /// Wrap a secret that is a credential as a whole (a token): its
        /// redacted form is `***`.
        pub fn opaque(s: impl Into<String>) -> Self {
            Secret(s.into(), true)
        }

        /// The secret itself, for the one place that needs it (the
        /// connection).
        pub fn expose(&self) -> &str {
            &self.0
        }

        /// The secret with its credentials replaced by `***` ([`redact`]);
        /// `***` for an opaque one.
        pub fn redacted(&self) -> String {
            if self.1 {
                return "***".to_owned();
            }
            redact(&self.0)
        }

        /// `text` with this secret replaced: the whole string by its
        /// redacted form, then its password (as written and
        /// percent-decoded, when at least 3 bytes) by `***`, and the forms
        /// a server or proxy may echo it in (JSON-escaped, once or again and
        /// again: any run of backslashes before any of its characters;
        /// base64, standard and URL-safe, inside a longer encoded text
        /// too). Backends pass every message from their libraries through
        /// this.
        ///
        /// A URL password holding an unencoded `@` is read differently by
        /// different parsers (the PostgreSQL client ends it at the first
        /// `@` and takes the rest, up to `/` or `?`, as the host), so every
        /// reading is removed: the password up to each `@`, each of its
        /// `@`-separated pieces, and the host such a client would see.
        pub fn scrub(&self, text: &str) -> String {
            let (mut out, mut found) = if self.1 {
                // An opaque secret: itself, and its percent-decoded and
                // percent-encoded forms (a token in a URL's query).
                (
                    text.to_owned(),
                    vec![
                        self.0.clone(),
                        percent_decode(&self.0),
                        percent_encode(&self.0),
                    ],
                )
            } else {
                (text.replace(&self.0, &self.redacted()), self.passwords())
            };
            let echoed: Vec<String> = found.iter().flat_map(|p| echoed_forms(p)).collect();
            found.extend(echoed);
            found.sort_by_key(|p| std::cmp::Reverse(p.len()));
            for p in &found {
                if p.len() >= 3 {
                    out = out.replace(p, "***");
                }
            }
            // Escaped again by whatever carried the text on (a JSON body
            // quoted in another, a message printed as JSON): any run of
            // backslashes before any of the secret's characters.
            if out.contains('\\') {
                for p in &found {
                    if p.len() >= 3 {
                        out = replace_escaped(&out, p);
                    }
                }
            }
            out
        }

        fn passwords(&self) -> Vec<String> {
            let mut found = Vec::new();
            let s = self.0.as_str();
            let mut add = |p: &str| {
                found.push(p.to_owned());
                found.push(percent_decode(p));
                let unquoted = unquote_value(p);
                if unquoted != p {
                    found.push(unquoted);
                }
            };
            if let Some((_, rest)) = split_url(s) {
                let ats: Vec<usize> = rest.match_indices('@').map(|(i, _)| i).collect();
                let ambiguous = ats.len() > 1;
                if let Some(&last) = ats.last()
                    && let Some(colon) = rest[..last].find(':')
                {
                    let p = &rest[colon + 1..last];
                    add(p);
                    if ambiguous {
                        for piece in p.split(['@', '/', '?']) {
                            add(piece);
                        }
                        for &at in ats.iter().filter(|&&at| at > colon) {
                            add(&rest[colon + 1..at]);
                        }
                    }
                }
                if ambiguous {
                    // What the PostgreSQL client reads as the host (after
                    // the first `@`, up to `/` or `?`) and the database (up
                    // to `?`): a server may name either.
                    let from = ats[0] + 1;
                    let host = rest[from..]
                        .find(['/', '?'])
                        .map_or(rest.len(), |i| from + i);
                    add(&rest[from..host]);
                    if rest[host..].starts_with('/') {
                        let db = rest[host..].find('?').map_or(rest.len(), |i| host + i);
                        add(&rest[host + 1..db]);
                    }
                }
                for (from, to) in query_secret_values(rest) {
                    let v = &rest[from..to];
                    add(v);
                    for piece in v.split('@') {
                        add(piece);
                    }
                }
            }
            for (from, to) in secret_values(s, split_url(s).is_some()) {
                add(&s[from..to]);
            }
            // A libSQL server's URL: every query value but `tls`'s, a bare
            // query key, and the path, may be a token (none of them is
            // printed by `redact` either).
            if is_libsql_server(s)
                && let Some((_, rest)) = split_url(s)
            {
                let rest = rest.split('#').next().unwrap_or_default();
                let (before_query, query) = rest.split_once('?').unwrap_or((rest, ""));
                for pair in query.split('&') {
                    match pair.split_once('=') {
                        Some((k, _)) if percent_decode(k).eq_ignore_ascii_case("tls") => {}
                        Some((_, v)) => add(v),
                        None => add(pair),
                    }
                }
                if let Some(i) = before_query.find('/') {
                    let path = before_query[i..].trim_matches('/');
                    if path.len() >= 8 {
                        add(path);
                        for seg in path.split('/').filter(|seg| seg.len() >= 8) {
                            add(seg);
                        }
                    }
                }
            }
            found
        }
    }

    /// The forms in which a server, a proxy or a library may echo the
    /// secret `p` back: JSON-escaped (`/` as `\/`, quotes and backslashes
    /// escaped), and base64, standard and URL-safe. A secret inside a
    /// longer base64 text (`Authorization: Bearer <token>`, encoded) shows
    /// as the encoding of its bytes from one of three offsets, whole groups
    /// only: each of those is a form. None for a secret under 6 bytes.
    fn echoed_forms(p: &str) -> Vec<String> {
        use base64::Engine as _;
        let mut out = Vec::new();
        let json: String = p
            .chars()
            .flat_map(|c| match c {
                '"' => vec!['\\', '"'],
                '\\' => vec!['\\', '\\'],
                c => vec![c],
            })
            .collect();
        for form in [json.clone(), json.replace('/', "\\/")] {
            if form != p && !out.contains(&form) {
                out.push(form);
            }
        }
        let b = p.as_bytes();
        if b.len() < 6 {
            return out;
        }
        for skip in 0..3 {
            let rest = &b[skip..];
            let whole = rest.len() / 3 * 3;
            if whole < 6 {
                continue;
            }
            for engine in [
                &base64::engine::general_purpose::STANDARD,
                &base64::engine::general_purpose::URL_SAFE,
            ] {
                let form = engine.encode(&rest[..whole]);
                if !out.contains(&form) {
                    out.push(form);
                }
            }
        }
        out
    }

    /// `text` with each occurrence of `secret` replaced by `***`, also where
    /// backslashes were put before any of its characters after the first
    /// (it was escaped once or more, as JSON escapes `/`, `"` and `\`): a
    /// backslash of the secret's own matches a run of backslashes.
    fn replace_escaped(text: &str, secret: &str) -> String {
        let t = text.as_bytes();
        let s = secret.as_bytes();
        let Some(&first) = s.first() else {
            return text.to_owned();
        };
        // Where an escaped occurrence starting at `i` ends, if one does.
        let ends = |i: usize| -> Option<usize> {
            let mut at = i;
            for (k, &c) in s.iter().enumerate() {
                if c == b'\\' {
                    let from = at;
                    while t.get(at) == Some(&b'\\') {
                        at += 1;
                    }
                    if at == from {
                        return None;
                    }
                    continue;
                }
                if k > 0 {
                    while t.get(at) == Some(&b'\\') {
                        at += 1;
                    }
                }
                if t.get(at) != Some(&c) {
                    return None;
                }
                at += 1;
            }
            Some(at)
        };
        let mut out = Vec::with_capacity(t.len());
        let mut i = 0;
        while i < t.len() {
            if t[i] == first
                && let Some(end) = ends(i)
            {
                out.extend_from_slice(b"***");
                i = end;
            } else {
                out.push(t[i]);
                i += 1;
            }
        }
        // A match starts and ends with whole characters of the secret (only
        // ASCII backslashes are skipped), so the text stays UTF-8.
        String::from_utf8(out)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
    }

    fn percent_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    fn percent_decode(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%'
                && i + 2 < b.len()
                && let Ok(hex) = std::str::from_utf8(&b[i + 1..i + 3])
                && let Ok(v) = u8::from_str_radix(hex, 16)
            {
                out.push(v);
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    impl fmt::Debug for Secret {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Secret({})", self.redacted())
        }
    }

    impl fmt::Display for Secret {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.redacted())
        }
    }

    /// The keys whose values are credentials, in any case.
    fn is_secret_key(k: &str) -> bool {
        let k = k.trim();
        k.eq_ignore_ascii_case("password")
            || k.eq_ignore_ascii_case("sslpassword")
            || k.eq_ignore_ascii_case("sslkey")
            || k.eq_ignore_ascii_case("authtoken")
            || k.eq_ignore_ascii_case("auth_token")
    }

    /// `s` as `(scheme, rest)` when it is a URL: a scheme (a letter, then
    /// letters, digits, `+`, `-` or `.`) and `://`. A libpq string whose
    /// value holds `://` is not one.
    fn split_url(s: &str) -> Option<(&str, &str)> {
        let (scheme, rest) = s.split_once("://")?;
        let mut b = scheme.bytes();
        let ok = b.next().is_some_and(|c| c.is_ascii_alphabetic())
            && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'));
        ok.then_some((scheme, rest))
    }

    /// Where the userinfo of a URL ends (`rest` follows `scheme://`): the
    /// `@` before the host, or `None` without one. A password may hold an
    /// unencoded `/`, `?` or `@`, in any order (`pa@ss/x@y` included), and
    /// a host never holds an `@`, so this is the last `@` of all. Where a
    /// path or query holds an `@` instead, more is masked than needed,
    /// never less (the PostgreSQL client itself takes everything before the
    /// first `@` as userinfo, so it cannot use such a URL as meant either).
    fn userinfo_end(rest: &str) -> Option<usize> {
        rest.rfind('@')
    }

    /// The byte ranges of the values of secret keys in the query of a URL
    /// (`rest` follows `scheme://`), keys percent-decoded. Any `?` or `&`
    /// may start a key (a password holding `?` cannot hide one), and a value
    /// runs to the next `&` (it may hold `?`): more is masked than needed,
    /// never less.
    fn query_secret_values(rest: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut i = 0;
        for seg in rest.split(['?', '&']) {
            if let Some((k, _)) = seg.split_once('=')
                && is_secret_key(&percent_decode(k))
            {
                let from = i + k.len() + 1;
                let to = rest[from..].find('&').map_or(rest.len(), |e| from + e);
                out.push((from, to));
            }
            i += seg.len() + 1;
        }
        out
    }

    /// `spans` sorted, with overlapping and touching ranges joined.
    fn merge_spans(mut spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
        spans.sort_unstable();
        let mut out: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
        for (from, to) in spans {
            match out.last_mut() {
                Some(last) if from <= last.1 => last.1 = last.1.max(to),
                _ => out.push((from, to)),
            }
        }
        out
    }

    /// Where the value starting at `from` ends: after its closing quote when
    /// it is single-quoted (libpq's `\'` and `\\` escapes kept), else at
    /// the first whitespace (or `&` in a URL), a backslash escaping the
    /// next byte. An unterminated quote runs to the end.
    fn value_end(b: &[u8], from: usize, in_url: bool) -> usize {
        let mut i = from;
        if b.get(i) == Some(&b'\'') {
            i += 1;
            while i < b.len() {
                match b[i] {
                    b'\\' => i += 2,
                    b'\'' => return i + 1,
                    _ => i += 1,
                }
            }
            return b.len();
        }
        while i < b.len() {
            match b[i] {
                b'\\' => i += 2,
                c if c.is_ascii_whitespace() || (in_url && c == b'&') => return i,
                _ => i += 1,
            }
        }
        b.len()
    }

    /// The byte ranges of every value given to a secret key in `s`, as libpq
    /// reads a `key = value` string: the key in any case, wherever it stands
    /// (so more is masked than needed, never less), spaces allowed around
    /// `=`, the value quoted or not.
    fn secret_values(s: &str, in_url: bool) -> Vec<(usize, usize)> {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            let Some(k) = [
                "password",
                "sslpassword",
                "sslkey",
                "authtoken",
                "auth_token",
            ]
            .into_iter()
            .find(|k| {
                b.len() - i >= k.len() && b[i..i + k.len()].eq_ignore_ascii_case(k.as_bytes())
            }) else {
                i += 1;
                continue;
            };
            let mut j = i + k.len();
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if b.get(j) != Some(&b'=') {
                i += k.len();
                continue;
            }
            j += 1;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            let end = value_end(b, j, in_url).min(b.len());
            if end > j {
                out.push((j, end));
            }
            i = end.max(j);
        }
        out
    }

    /// A libpq value without its quotes and backslash escapes.
    fn unquote_value(v: &str) -> String {
        let inner = v
            .strip_prefix('\'')
            .map(|x| x.strip_suffix('\'').unwrap_or(x))
            .unwrap_or(v);
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// `text` with each range of `spans` (sorted, disjoint) replaced by
    /// `***`.
    fn mask_spans(text: &str, spans: &[(usize, usize)]) -> String {
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for &(from, to) in spans {
            out.push_str(&text[last..from]);
            out.push_str("***");
            last = to;
        }
        out.push_str(&text[last..]);
        out
    }

    /// `s` without credentials: a URL's userinfo, everything between `//`
    /// and the last `@`, becomes `***` (`postgres://***@host/db`, as `vci
    /// fetch` already prints git remotes, even when the password holds an
    /// unencoded `/`, `?` or `@`), and so do the values of `password`,
    /// `sslpassword`, `sslkey` and `authToken`, in a query string (keys
    /// percent-decoded) or in a libpq `key=value` string (spaces around `=`
    /// and quoted values included). A secret value that runs past the last
    /// `@` (`?password=a@b`) is masked whole, its `@` with it.
    pub fn redact(s: &str) -> String {
        let Some((scheme, rest)) = split_url(s) else {
            return mask_spans(s, &secret_values(s, false));
        };
        if is_libsql_server(s) {
            return redact_server_url(scheme, rest);
        }
        let at = userinfo_end(rest);
        let mut spans = secret_values(rest, true);
        if let Some(at) = at {
            spans.push((0, at));
        }
        spans.extend(query_secret_values(rest));
        format!("{scheme}://{}", mask_spans(rest, &merge_spans(spans)))
    }

    /// A libSQL server's URL (`libsql://`, `https://`, `http://`; `rest`
    /// follows `scheme://`) as [`redact`] shows it: a user or password
    /// becomes `***@`, a path `/<path>` (a token could be written there),
    /// and of the query only `tls` is shown as written; an `authToken` (or
    /// another secret key) shows as `authToken=***`, any other parameter as
    /// `***`, its name too (a token may be either), and a fragment as
    /// `#***`.
    fn redact_server_url(scheme: &str, rest: &str) -> String {
        let (user, rest) = match userinfo_end(rest) {
            Some(at) => ("***@", &rest[at + 1..]),
            None => ("", rest),
        };
        let (rest, fragment) = match rest.find('#') {
            Some(i) => (&rest[..i], "#***"),
            None => (rest, ""),
        };
        let (before_query, query) = match rest.find('?') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };
        let (host, path) =
            before_query.split_at(before_query.find('/').unwrap_or(before_query.len()));
        let path = if path.trim_matches('/').is_empty() {
            path
        } else {
            "/<path>"
        };
        let mut out = format!("{scheme}://{user}{host}{path}");
        if let Some(q) = query {
            let shown: Vec<String> = q
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    _ if pair.is_empty() => String::new(),
                    Some((k, v))
                        if percent_decode(k).eq_ignore_ascii_case("tls")
                            && matches!(v, "0" | "1" | "true" | "false") =>
                    {
                        format!("tls={v}")
                    }
                    Some((k, _)) if is_secret_key(&percent_decode(k)) => {
                        let k = percent_decode(k);
                        if k.eq_ignore_ascii_case("authtoken")
                            || k.eq_ignore_ascii_case("auth_token")
                        {
                            format!("{k}=***")
                        } else {
                            "***".to_owned()
                        }
                    }
                    _ => "***".to_owned(),
                })
                .collect();
            out.push('?');
            out.push_str(&shown.join("&"));
        }
        out.push_str(fragment);
        out
    }

    /// `"500ms"`, `"5s"`, `"2m"`, `"1h"`, `"1d"`, or a bare number of
    /// seconds.
    pub fn parse_duration(s: &str) -> Option<Duration> {
        let s = s.trim();
        let i = s
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(s.len());
        let (num, unit) = (&s[..i], s[i..].trim());
        let n: f64 = num.parse().ok()?;
        let secs = match unit {
            "ms" => n / 1000.0,
            "" | "s" => n,
            "m" => n * 60.0,
            "h" => n * 3600.0,
            "d" => n * 86400.0,
            _ => return None,
        };
        (secs.is_finite() && secs >= 0.0).then(|| Duration::from_secs_f64(secs))
    }

    /// The SQLite settings as resolved.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SqliteSelection {
        /// The file, when set: absolute (only from `VCI_STORE_URL`) or
        /// relative to the git common directory. `None`: the default file.
        pub path: Option<Sourced<String>>,
    }

    /// How the libSQL store reaches its records.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LibsqlMode {
        /// A local file (no `VCI_STORE_URL`, or `file:<path>`).
        Local,
        /// A server (`libsql://`, `https://` or `http://`): every read and
        /// write goes to it.
        Remote,
        /// A server, read through a local replica synced when it is first
        /// read and at each later prefetch; writes go to the server.
        Replica,
    }

    impl LibsqlMode {
        /// `local`, `remote` or `replica`.
        pub fn name(self) -> &'static str {
            match self {
                LibsqlMode::Local => "local",
                LibsqlMode::Remote => "remote",
                LibsqlMode::Replica => "replica",
            }
        }
    }

    /// The libSQL settings as resolved (the server is [`Selection::url`],
    /// its token [`Selection::token`]).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LibsqlSelection {
        /// Local file, remote server, or replica of a remote server.
        pub mode: Sourced<LibsqlMode>,
        /// The local file (local mode) or the replica (replica mode):
        /// absolute (only from the environment) or relative to the git
        /// common directory. `None`: `vci-store.libsql` there.
        pub path: Option<Sourced<String>>,
    }

    /// Whether `url`'s query has an `authToken` (or `auth_token`)
    /// parameter.
    fn url_has_token(url: &str) -> bool {
        url.split_once('?').is_some_and(|(_, q)| {
            q.split('&').any(|kv| {
                let k = kv.split_once('=').map_or(kv, |(k, _)| k);
                let k = percent_decode(k);
                k.eq_ignore_ascii_case("authtoken") || k.eq_ignore_ascii_case("auth_token")
            })
        })
    }

    /// Whether `url` names a libSQL server: `libsql://`, `https://` or
    /// `http://`.
    pub fn is_libsql_server(url: &str) -> bool {
        let lower = url.trim_start().to_ascii_lowercase();
        ["libsql://", "https://", "http://"]
            .iter()
            .any(|p| lower.starts_with(p))
    }

    /// The PostgreSQL settings as resolved (the URL is
    /// [`Selection::url`]).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PostgresSelection {
        /// The schema.
        pub schema: Sourced<String>,
        /// Connections at most.
        pub pool: Sourced<u32>,
        /// A manifest put more recently than this is never removed as
        /// unreferenced.
        pub manifest_grace: Sourced<Duration>,
    }

    /// The store a command uses, with every setting and where it came from.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Selection {
        /// The backend's name.
        pub kind: Sourced<String>,
        /// `VCI_STORE_URL`, when set.
        pub url: Option<Sourced<Secret>>,
        /// `VCI_STORE_TOKEN`, when set (an [`Secret::opaque`] secret).
        pub token: Option<Sourced<Secret>>,
        /// The namespace on a shared server; `None`: the repository id.
        pub namespace: Option<Sourced<String>>,
        /// The longest wait to connect.
        pub connect_timeout: Sourced<Duration>,
        /// The longest wait for one statement or request.
        pub timeout: Sourced<Duration>,
        /// `[store.sqlite]` as resolved.
        pub sqlite: SqliteSelection,
        /// `[store.postgres]` as resolved.
        pub postgres: PostgresSelection,
        /// `[store.libsql]` and the libSQL variables as resolved.
        pub libsql: LibsqlSelection,
        /// `[store.options]`, for other backends.
        pub options: BTreeMap<String, String>,
        /// Settings that were overridden or ignored. The command line
        /// prints each once per process as a `vci: warning:` line and adds
        /// them to the plan's warnings.
        pub warnings: Vec<String>,
    }

    /// One line of `vci store info`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SettingLine {
        /// The setting.
        pub name: &'static str,
        /// Its value, safe to print.
        pub value: String,
        /// Where it came from.
        pub source: Source,
    }

    impl Selection {
        /// A selection of `kind` with every default and nothing from the
        /// environment, for tests and for tools that open a backend they
        /// name themselves (such as a copy between stores).
        pub fn for_backend(kind: &str) -> Self {
            Selection {
                kind: Sourced::default_value(kind.to_owned()),
                url: None,
                token: None,
                namespace: None,
                connect_timeout: Sourced::default_value(DEFAULT_CONNECT_TIMEOUT),
                timeout: Sourced::default_value(DEFAULT_TIMEOUT),
                sqlite: SqliteSelection { path: None },
                postgres: PostgresSelection {
                    schema: Sourced::default_value(DEFAULT_SCHEMA.to_owned()),
                    pool: Sourced::default_value(DEFAULT_POOL),
                    manifest_grace: Sourced::default_value(DEFAULT_MANIFEST_GRACE),
                },
                libsql: LibsqlSelection {
                    mode: Sourced::default_value(LibsqlMode::Local),
                    path: None,
                },
                options: BTreeMap::new(),
                warnings: Vec::new(),
            }
        }

        /// Every setting that applies to this backend, with its source, with
        /// secrets redacted.
        pub fn describe(&self) -> Vec<SettingLine> {
            let line = |name, value: String, source| SettingLine {
                name,
                value,
                source,
            };
            let mut v = vec![line("backend", self.kind.value.clone(), self.kind.source)];
            if let Some(u) = &self.url {
                v.push(line("url", u.value.redacted(), u.source));
            }
            match self.kind.value.as_str() {
                "sqlite" => v.push(match &self.sqlite.path {
                    Some(p) => line("path", p.value.clone(), p.source),
                    None => line(
                        "path",
                        format!("<git common dir>/{DEFAULT_SQLITE_FILE}"),
                        Source::Default,
                    ),
                }),
                "postgres" => {
                    let pg = &self.postgres;
                    v.push(line("schema", pg.schema.value.clone(), pg.schema.source));
                    v.push(match &self.namespace {
                        Some(n) => line("namespace", n.value.clone(), n.source),
                        None => line(
                            "namespace",
                            "(the repository id)".to_owned(),
                            Source::Default,
                        ),
                    });
                    v.push(line("pool", pg.pool.value.to_string(), pg.pool.source));
                    v.push(line(
                        "manifest_grace",
                        format!("{:?}", pg.manifest_grace.value),
                        pg.manifest_grace.source,
                    ));
                }
                "libsql" => {
                    let l = &self.libsql;
                    v.push(line("mode", l.mode.value.name().to_owned(), l.mode.source));
                    if l.mode.value != LibsqlMode::Remote {
                        let name = if l.mode.value == LibsqlMode::Replica {
                            "replica"
                        } else {
                            "path"
                        };
                        v.push(match &l.path {
                            Some(p) => line(name, p.value.clone(), p.source),
                            None => line(
                                name,
                                format!("<git common dir>/{DEFAULT_LIBSQL_FILE}"),
                                Source::Default,
                            ),
                        });
                    }
                    if l.mode.value != LibsqlMode::Local {
                        let in_url = self
                            .url
                            .as_ref()
                            .filter(|u| url_has_token(u.value.expose()));
                        v.push(match (&self.token, in_url) {
                            (Some(t), _) => line("token", "(set)".to_owned(), t.source),
                            (None, Some(u)) => {
                                line("token", "(the URL's authToken)".to_owned(), u.source)
                            }
                            (None, None) => line("token", "(none)".to_owned(), Source::Default),
                        });
                        v.push(match &self.namespace {
                            Some(n) => line("namespace", n.value.clone(), n.source),
                            None => line(
                                "namespace",
                                "(the repository id)".to_owned(),
                                Source::Default,
                            ),
                        });
                    }
                }
                _ => {}
            }
            v.push(line(
                "connect_timeout",
                format!("{:?}", self.connect_timeout.value),
                self.connect_timeout.source,
            ));
            v.push(line(
                "timeout",
                format!("{:?}", self.timeout.value),
                self.timeout.source,
            ));
            v
        }
    }

    /// The backend a URL's scheme names: `postgres://` or `postgresql://`
    /// for postgres, `sqlite:` for sqlite, `libsql://` for libsql; anything
    /// else names none (an `https://` URL may be a libSQL server, or not:
    /// `VCI_STORE=libsql` says so).
    pub fn backend_of_url(url: &str) -> Option<&'static str> {
        let lower = url.trim_start().to_ascii_lowercase();
        if lower.starts_with("postgres://") || lower.starts_with("postgresql://") {
            Some("postgres")
        } else if lower.starts_with("sqlite:") {
            Some("sqlite")
        } else if lower.starts_with("libsql://") {
            Some("libsql")
        } else {
            None
        }
    }

    fn canonical_kind(name: &str, source: Source) -> Result<String, StoreError> {
        let n = name.trim().to_ascii_lowercase();
        if n.contains("://") {
            return Err(StoreError::Config(format!(
                "{source} names a backend, not a location: put the URL in ${ENV_STORE_URL} (it was not printed)"
            )));
        }
        let n = match n.as_str() {
            "postgresql" | "pg" => "postgres".to_owned(),
            "sqlite3" => "sqlite".to_owned(),
            "turso" => "libsql".to_owned(),
            "gitmeta" | "git_meta" => "git-meta".to_owned(),
            _ => n,
        };
        let ok = !n.is_empty()
            && n.len() <= 32
            && n.as_bytes()[0].is_ascii_lowercase()
            && n.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            return Ok(n);
        }
        // Only a value that looks like a name is quoted back: a connection
        // string put here by mistake (a libpq `password=...`) is not.
        let shown = name.trim();
        let printable = !shown.is_empty()
            && shown.len() <= 40
            && shown
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        Err(StoreError::Config(if printable {
            format!("{shown:?} (from {source}) is not a store backend name")
        } else {
            format!("{source} is not a store backend name (it was not printed)")
        }))
    }

    /// The backend the user asked for, without validating anything else,
    /// for naming a [`crate::FailedStore`] when [`resolve`] fails.
    pub fn requested_kind(
        env: &dyn Fn(&str) -> Option<String>,
        file: Option<&StoreSettings>,
    ) -> String {
        let var = |k: &str| {
            env(k)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        if let Some(v) = var(ENV_STORE) {
            return canonical_kind(&v, Source::Env(ENV_STORE)).unwrap_or_else(|_| "unknown".into());
        }
        if let Some(k) = var(ENV_STORE_URL).as_deref().and_then(backend_of_url) {
            return k.to_owned();
        }
        match file.and_then(|f| f.backend.as_deref()) {
            Some(b) => canonical_kind(b, Source::File).unwrap_or_else(|_| "unknown".into()),
            None => DEFAULT_BACKEND.to_owned(),
        }
    }

    fn duration_setting(
        var: &dyn Fn(&'static str) -> Option<String>,
        env_key: &'static str,
        file_value: Option<&str>,
        file_name: &'static str,
        default: Duration,
    ) -> Result<Sourced<Duration>, StoreError> {
        let in_range = |d: &Duration| !d.is_zero() && *d <= MAX_TIMEOUT;
        if let Some(v) = var(env_key) {
            let d = v
                .parse::<f64>()
                .ok()
                .filter(|s| s.is_finite() && *s > 0.0)
                .map(Duration::from_secs_f64)
                .filter(in_range)
                .ok_or_else(|| {
                    StoreError::Config(format!(
                        "${env_key} = {v:?}: expected a number of seconds, more than 0 and at most 3600"
                    ))
                })?;
            return Ok(Sourced {
                value: d,
                source: Source::Env(env_key),
            });
        }
        if let Some(s) = file_value {
            let d = parse_duration(s).filter(in_range).ok_or_else(|| {
                StoreError::Config(format!(
                    "vci.toml [store] {file_name} = {s:?}: expected a duration such as \"5s\" or \"2m\", more than 0 and at most an hour"
                ))
            })?;
            return Ok(Sourced {
                value: d,
                source: Source::File,
            });
        }
        Ok(Sourced::default_value(default))
    }

    fn is_sql_identifier(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 63
            && (s.as_bytes()[0].is_ascii_lowercase() || s.as_bytes()[0] == b'_')
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    }

    fn is_namespace(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:/@-".contains(&b))
    }

    /// Why a `file:` or `sqlite:` `VCI_STORE_URL` holding a query is
    /// refused: it would be taken whole as a file name, and printed as one,
    /// while a query may hold a token (`?authToken=…`).
    fn file_url_query(scheme: &str) -> String {
        format!(
            "${ENV_STORE_URL}={scheme}:<path> names a file and takes no query (?…), which may hold a token (it was not printed)"
        )
    }

    fn relative_path(p: &str) -> Result<String, StoreError> {
        relative_path_of(p, "sqlite", &format!("{ENV_STORE_URL}=sqlite:<path>"))
    }

    fn relative_path_of(p: &str, table: &str, url: &str) -> Result<String, StoreError> {
        use std::path::{Component, Path};
        if p.contains("://") || p.contains('?') {
            // A server's URL put here by mistake (it may hold a token) is
            // neither taken as a file name nor printed.
            return Err(StoreError::Config(format!(
                "vci.toml [store.{table}] path holds a URL, not a file (it was not printed): a server's URL is read only from ${ENV_STORE_URL}, and its token from ${ENV_TOKEN}"
            )));
        }
        let ok = !p.is_empty()
            && !p.contains('\0')
            && Path::new(p)
                .components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
        if ok {
            Ok(p.to_owned())
        } else {
            Err(StoreError::Config(format!(
                "vci.toml [store.{table}] path {p:?} must be relative to the git common directory, without `..` (an absolute path can be given with {url})"
            )))
        }
    }

    /// The libSQL store's mode and file, for backend `k` (the defaults for
    /// any other backend).
    ///
    /// * A `libsql://`, `https://` or `http://` `VCI_STORE_URL` is a server:
    ///   the replica mode when `VCI_STORE_SYNC=replica`, `VCI_STORE_REPLICA`
    ///   or `[store.libsql] replica = true` asks for it, else the remote
    ///   mode. The replica is `VCI_STORE_REPLICA`, else `[store.libsql]
    ///   path`.
    /// * `file:<path>`, or no URL, is the local mode, in that file, else
    ///   `[store.libsql] path`. A replica asked for without a server is a
    ///   warning. A `file:` URL with a query (`?`) is refused, unprinted.
    /// * Any other URL is refused, without being printed.
    fn libsql_selection(
        k: &str,
        url: Option<&Sourced<Secret>>,
        file: Option<&LibsqlSettings>,
        var: &dyn Fn(&'static str) -> Option<String>,
        warnings: &mut Vec<String>,
    ) -> Result<LibsqlSelection, StoreError> {
        let local = LibsqlSelection {
            mode: Sourced::default_value(LibsqlMode::Local),
            path: None,
        };
        if k != "libsql" {
            return Ok(local);
        }
        let file_path = match file.and_then(|f| f.path.as_deref()) {
            Some(p) => Some(Sourced {
                value: relative_path_of(
                    p,
                    "libsql",
                    &format!("{ENV_STORE_URL}=file:<path> or {ENV_REPLICA}"),
                )?,
                source: Source::File,
            }),
            None => None,
        };
        let env_replica = var(ENV_REPLICA);
        let asked = if var(ENV_SYNC).is_some_and(|v| v.eq_ignore_ascii_case("replica")) {
            Some(Source::Env(ENV_SYNC))
        } else if env_replica.is_some() {
            Some(Source::Env(ENV_REPLICA))
        } else if file.and_then(|f| f.replica) == Some(true) {
            Some(Source::File)
        } else {
            None
        };
        let server = url.filter(|u| is_libsql_server(u.value.expose()));
        if let Some(u) = server {
            let path = match env_replica {
                Some(p) if p.contains('\0') => {
                    return Err(StoreError::Config(format!("${ENV_REPLICA} is not a path")));
                }
                Some(p) => Some(Sourced {
                    value: p,
                    source: Source::Env(ENV_REPLICA),
                }),
                None => file_path,
            };
            return Ok(match asked {
                Some(source) => LibsqlSelection {
                    mode: Sourced {
                        value: LibsqlMode::Replica,
                        source,
                    },
                    path,
                },
                None => LibsqlSelection {
                    mode: Sourced {
                        value: LibsqlMode::Remote,
                        source: u.source,
                    },
                    path: None,
                },
            });
        }
        if let Some(source) = asked {
            warnings.push(format!(
                "the libsql replica (from {source}) is ignored: ${ENV_STORE_URL} names no libsql server (libsql://, https:// or http://), so the store is a local file"
            ));
        }
        let Some(u) = url else {
            return Ok(LibsqlSelection {
                path: file_path,
                ..local
            });
        };
        let s = u.value.expose();
        let lower = s.to_ascii_lowercase();
        let p = if lower.starts_with("file://") {
            &s[7..]
        } else if lower.starts_with("file:") {
            &s[5..]
        } else {
            // Another scheme's URL (which may carry a password) is not
            // printed.
            return Err(StoreError::Config(format!(
                "${ENV_STORE_URL} is not a libsql location: expected libsql://<database>, https://<host>, http://<host> or file:<path> (it was not printed)"
            )));
        };
        if p.is_empty() || p.contains('\0') || p.contains("://") {
            return Err(StoreError::Config(format!(
                "${ENV_STORE_URL}=file:<path> needs a path"
            )));
        }
        if p.contains('?') {
            return Err(StoreError::Config(file_url_query("file")));
        }
        Ok(LibsqlSelection {
            mode: Sourced {
                value: LibsqlMode::Local,
                source: u.source,
            },
            path: Some(Sourced {
                value: p.to_owned(),
                source: u.source,
            }),
        })
    }

    /// Resolve the store from the environment (`env` reads a variable; the
    /// command line answers `VCI_STORE_URL` from the copy it took at
    /// start-up) and `[store]` of the working tree's `vci.toml` (`file`).
    ///
    /// Empty variables count as unset. Errors ([`StoreError::Config`]):
    /// connection settings in `vci.toml`; a URL in `VCI_STORE`; a malformed
    /// backend name; `VCI_STORE` disagreeing with the scheme of
    /// `VCI_STORE_URL`; postgres without `VCI_STORE_URL`; a `sqlite:` or
    /// `file:` `VCI_STORE_URL` without a path, or whose path holds `://`
    /// (another scheme's URL) or a query (`?`, which may hold a token),
    /// never printed; a timeout outside (0, 1 h]; a schema
    /// that is not a lowercase identifier; a malformed namespace; a pool
    /// outside 1 to 64; a grace over 30 days; a SQLite path in `vci.toml`
    /// that is absolute or climbs out with `..`. Overridden and ignored
    /// settings become [`Selection::warnings`]. A well-formed but unknown
    /// backend name is reported by [`crate::open`].
    pub fn resolve(
        env: &dyn Fn(&str) -> Option<String>,
        file: Option<&StoreSettings>,
    ) -> Result<Selection, StoreError> {
        let var = |k: &'static str| -> Option<String> {
            env(k)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        if let Some(f) = file {
            f.check()?;
        }
        let mut warnings = Vec::new();
        let url = var(ENV_STORE_URL).map(|u| Sourced {
            value: Secret::new(u),
            source: Source::Env(ENV_STORE_URL),
        });
        let url_kind = url.as_ref().and_then(|u| backend_of_url(u.value.expose()));
        let file_kind = match file.and_then(|f| f.backend.as_deref()) {
            Some(b) => Some(canonical_kind(b, Source::File)?),
            None => None,
        };
        let kind = match (var(ENV_STORE), url_kind, &file_kind) {
            (Some(v), _, _) => Sourced {
                value: canonical_kind(&v, Source::Env(ENV_STORE))?,
                source: Source::Env(ENV_STORE),
            },
            (None, Some(k), _) => Sourced {
                value: k.to_owned(),
                source: Source::Env(ENV_STORE_URL),
            },
            (None, None, Some(k)) => Sourced {
                value: k.clone(),
                source: Source::File,
            },
            (None, None, None) => Sourced::default_value(DEFAULT_BACKEND.to_owned()),
        };
        if let Some(k) = url_kind
            && k != kind.value
        {
            return Err(StoreError::Config(format!(
                "${ENV_STORE_URL} is a {k} location but the backend is {} (from {})",
                kind.value, kind.source
            )));
        }
        if let Some(fk) = &file_kind
            && kind.source != Source::File
            && *fk != kind.value
        {
            warnings.push(format!(
                "vci.toml [store] backend = {fk:?} is overridden: using {} (from {})",
                kind.value, kind.source
            ));
        }
        let k = kind.value.as_str();
        let f_sqlite = file.and_then(|f| f.sqlite.as_ref());
        let f_pg = file.and_then(|f| f.postgres.as_ref());
        let f_libsql = file.and_then(|f| f.libsql.as_ref());
        let token = var(ENV_TOKEN).map(|t| Sourced {
            value: Secret::opaque(t),
            source: Source::Env(ENV_TOKEN),
        });
        if k != "sqlite" && f_sqlite.is_some() {
            warnings.push(format!(
                "vci.toml [store.sqlite] is ignored: the store is {k} (from {})",
                kind.source
            ));
        }
        if k != "postgres" && f_pg.is_some() {
            warnings.push(format!(
                "vci.toml [store.postgres] is ignored: the store is {k} (from {})",
                kind.source
            ));
        }
        if k != "libsql" && f_libsql.is_some() {
            warnings.push(format!(
                "vci.toml [store.libsql] is ignored: the store is {k} (from {})",
                kind.source
            ));
        }
        if k == "git-meta"
            && let Some(u) = &url
        {
            warnings.push(format!(
                "${ENV_STORE_URL} ({}) is ignored by the git-meta store: its remote comes from --remote, .git-meta or git config",
                u.value.redacted()
            ));
        }
        if k == "postgres" && url.is_none() {
            return Err(StoreError::Config(format!(
                "the postgres store needs ${ENV_STORE_URL} (postgres://<user>@<host>/<database>?sslmode=require); it is never read from vci.toml, and GitHub does not pass secrets to pull requests from forks"
            )));
        }
        let libsql = libsql_selection(k, url.as_ref(), f_libsql, &var, &mut warnings)?;
        if token.is_some() && !(k == "libsql" && libsql.mode.value != LibsqlMode::Local) {
            warnings.push(format!(
                "${ENV_TOKEN} is ignored: the store is {k}{} (from {})",
                if k == "libsql" { " in local mode" } else { "" },
                kind.source
            ));
        }
        let sqlite = SqliteSelection {
            path: if k != "sqlite" {
                None
            } else if let Some(u) = &url {
                let s = u.value.expose();
                let p = s
                    .strip_prefix("sqlite://")
                    .or_else(|| s.strip_prefix("sqlite:"))
                    .unwrap_or(s);
                if p.is_empty() || p.contains('\0') {
                    return Err(StoreError::Config(format!(
                        "${ENV_STORE_URL}=sqlite:<path> needs a path"
                    )));
                }
                // Another scheme's URL (which may carry a password) is not
                // a path: it would be printed as one.
                if p.contains("://") {
                    return Err(StoreError::Config(format!(
                        "${ENV_STORE_URL} is not a sqlite:<path> location (it was not printed)"
                    )));
                }
                if p.contains('?') {
                    return Err(StoreError::Config(file_url_query("sqlite")));
                }
                Some(Sourced {
                    value: p.to_owned(),
                    source: u.source,
                })
            } else {
                match f_sqlite.and_then(|s| s.path.as_deref()) {
                    Some(p) => Some(Sourced {
                        value: relative_path(p)?,
                        source: Source::File,
                    }),
                    None => None,
                }
            },
        };
        let connect_timeout = duration_setting(
            &var,
            ENV_CONNECT_TIMEOUT,
            file.and_then(|f| f.connect_timeout.as_deref()),
            "connect_timeout",
            DEFAULT_CONNECT_TIMEOUT,
        )?;
        let timeout = duration_setting(
            &var,
            ENV_TIMEOUT,
            file.and_then(|f| f.timeout.as_deref()),
            "timeout",
            DEFAULT_TIMEOUT,
        )?;
        let schema = match f_pg.and_then(|p| p.schema.clone()) {
            Some(s) => Sourced {
                value: s,
                source: Source::File,
            },
            None => Sourced::default_value(DEFAULT_SCHEMA.to_owned()),
        };
        if !is_sql_identifier(&schema.value) {
            return Err(StoreError::Config(format!(
                "schema {:?} (from {}): expected a lowercase SQL identifier of at most 63 characters",
                schema.value, schema.source
            )));
        }
        let file_namespace = if k == "libsql" {
            f_libsql.and_then(|l| l.namespace.clone())
        } else {
            f_pg.and_then(|p| p.namespace.clone())
        };
        let namespace = match var(ENV_NAMESPACE) {
            Some(n) => Some(Sourced {
                value: n,
                source: Source::Env(ENV_NAMESPACE),
            }),
            None => file_namespace.map(|n| Sourced {
                value: n,
                source: Source::File,
            }),
        };
        if let Some(n) = &namespace
            && !is_namespace(&n.value)
        {
            return Err(StoreError::Config(format!(
                "namespace {:?} (from {}): expected 1 to 128 of A-Z a-z 0-9 . _ : / @ -",
                n.value, n.source
            )));
        }
        let pool = match f_pg.and_then(|p| p.pool) {
            Some(n) if (1..=64).contains(&n) => Sourced {
                value: n,
                source: Source::File,
            },
            Some(n) => {
                return Err(StoreError::Config(format!(
                    "vci.toml [store.postgres] pool = {n}: expected 1 to 64"
                )));
            }
            None => Sourced::default_value(DEFAULT_POOL),
        };
        let manifest_grace = match f_pg.and_then(|p| p.manifest_grace.as_deref()) {
            Some(s) => Sourced {
                value: parse_duration(s)
                    .filter(|d| d.as_secs() <= 30 * 86_400)
                    .ok_or_else(|| {
                        StoreError::Config(format!(
                            "vci.toml [store.postgres] manifest_grace = {s:?}: expected a duration of at most 30 days"
                        ))
                    })?,
                source: Source::File,
            },
            None => Sourced::default_value(DEFAULT_MANIFEST_GRACE),
        };
        Ok(Selection {
            kind,
            url,
            token,
            namespace,
            connect_timeout,
            timeout,
            sqlite,
            postgres: PostgresSelection {
                schema,
                pool,
                manifest_grace,
            },
            libsql,
            options: file.map(|f| f.options.clone()).unwrap_or_default(),
            warnings,
        })
    }
}

// ---- timing --------------------------------------------------------------------

pub mod timing {
    //! Timing lines for backends: `store: <kind>: <step>: <secs>s`. They are
    //! recorded in the metrics log (`vci metrics` groups them by step, with
    //! numbers replaced by `#`) and printed under `VCI_TIMING`. Keep step
    //! labels stable, because metric history is keyed by them. Put counts in
    //! labels (`list 4100 unit(s)`); never paths, test ids, hosts or URLs.

    use std::fmt::Display;
    use std::time::Instant;

    /// A running step.
    #[derive(Debug)]
    pub struct Step {
        kind: &'static str,
        start: Option<Instant>,
    }

    impl Step {
        /// Start timing a step of backend `kind`. Costs nothing when metrics
        /// are off.
        pub fn start(kind: &'static str) -> Self {
            Step {
                kind,
                start: vci_core::metrics::on().then(Instant::now),
            }
        }

        /// Record the time since the start or the last lap as `what`, and
        /// start again.
        pub fn lap(&mut self, what: impl Display) {
            if let Some(s) = self.start {
                vci_core::timing_line!(
                    "store: {}: {}: {:.2}s",
                    self.kind,
                    what,
                    s.elapsed().as_secs_f64()
                );
                self.start = Some(Instant::now());
            }
        }

        /// Record the last part as `what`.
        pub fn done(mut self, what: impl Display) {
            self.lap(what);
        }
    }
}

// ---- conformance (feature "conformance") ---------------------------------------

#[cfg(feature = "conformance")]
pub mod conformance {
    //! The behaviour every backend must have, as scenarios a backend runs
    //! against itself with [`conformance_suite!`](crate::conformance_suite):
    //!
    //! ```ignore
    //! // crates/vci-store-sqlite/tests/conformance.rs
    //! vci_store::conformance_suite!(Some(Box::new(SqliteWorlds) as Box<dyn vci_store::conformance::StoreFactory>));
    //! ```
    //!
    //! Scenarios check outcomes (bytes read, keys present, peers agree) and
    //! branch only on [`Caps`](crate::Caps) and on whether
    //! [`AttestationStore::exchange`] is
    //! present. A [`World`] hook that returns `None` or `false` skips the
    //! part of a scenario that needs it, and the scenario says so on stderr.
    //! Keep the suite in its own test binary: it reads no environment
    //! variable after start-up and sets none.

    use std::sync::Arc;

    use crate::AttestationStore;

    /// Makes isolated worlds of one backend: each scenario gets its own (a
    /// temporary directory, a fresh schema, a fresh bare remote with clones).
    pub trait StoreFactory: Sync {
        /// The backend's name, for failure messages.
        fn name(&self) -> &str;
        /// A new world that no other test shares.
        fn world(&self) -> Box<dyn World>;
    }

    /// Peers on one backend: handles (clones, processes, machines) that read
    /// and write the same records.
    pub trait World {
        /// Peer `i` (below 8). The same `i` always returns the same handle.
        fn peer(&self, i: usize) -> Arc<dyn AttestationStore>;
        /// A peer that has never stored or fetched anything.
        fn fresh_peer(&self) -> Arc<dyn AttestationStore>;
        /// Make what peer `from` holds reach `to`: push there and fetch here
        /// for a store with an exchange; nothing otherwise.
        fn sync(&self, from: usize, to: &[usize]);
        /// Whether peer `i`'s backing store exists (a file, a schema), or
        /// `None` when this backend cannot answer.
        fn backing_exists(&self, i: usize) -> Option<bool> {
            let _ = i;
            None
        }
        /// A handle on a store that cannot be reached: a closed port, a
        /// remote that does not exist, a file that is not a database.
        fn unreachable(&self) -> Option<Arc<dyn AttestationStore>> {
            None
        }
        /// The secret (a password) [`World::unreachable`]'s handle was
        /// configured with, which no message may show.
        fn secret(&self) -> Option<String> {
            None
        }
        /// A read-only handle on peer `i`'s records (a read-only file or
        /// `.git`, a SELECT-only role).
        fn read_only(&self, i: usize) -> Option<Arc<dyn AttestationStore>> {
            let _ = i;
            None
        }
        /// Write a raw record behind the backend's back. Returns whether it
        /// could.
        fn inject_raw(&self, i: usize, target: &str, key: &str, value: &[u8]) -> bool {
            let _ = (i, target, key, value);
            false
        }
        /// Make `key`'s value unreadable without removing the key (a git blob
        /// deleted, an unknown `encoding`). Returns whether it could.
        fn make_unreadable(&self, i: usize, key: &str) -> bool {
            let _ = (i, key);
            false
        }
        /// A handle whose batches fail at `finish` (fault injection), or
        /// `None` when the backend cannot.
        fn failing_batches(&self) -> Option<Arc<dyn AttestationStore>> {
            None
        }
    }

    /// Values shared by the scenarios. They match the git-meta tests'.
    pub mod fixtures {
        /// A signer id.
        pub const S1: &str = "1111111111111111";
        /// Another signer id.
        pub const S2: &str = "2222222222222222";
        /// A unit on a path target.
        pub const UNIT_A: &str = "src/a.test.ts";
        /// Another unit on a path target.
        pub const UNIT_B: &str = "src/b.test.ts";
        /// A cargo unit: target `path:rust/core`.
        pub const UNIT_CARGO: &str = "rust/core#test:it";
        /// The repository root, stored on the `project` target.
        pub const UNIT_ROOT: &str = ".";
        /// A tree id prefix.
        pub const TREE_HEAD: &str = "0123456789abcdef";
    }

    /// The scenario bodies (`src/conformance/scenarios.rs`), one per row of
    /// the table in `docs/STORE-BACKENDS.md` section 14. Each is a `pub fn
    /// cNN_...(f: &dyn StoreFactory)` that builds its own world.
    pub mod scenarios;
}

/// One `#[test]` per conformance scenario, run against the backend that
/// `$factory` makes: an expression of type
/// `Option<Box<dyn vci_store::conformance::StoreFactory>>`. `None` skips
/// every test and says so; a factory that is required here
/// (`VCI_TEST_POSTGRES=require`) panics instead of returning `None`.
#[cfg(feature = "conformance")]
#[macro_export]
macro_rules! conformance_suite {
    ($factory:expr) => {
        $crate::__conformance_tests!($factory;
            c01_round_trip_exact_bytes, c02_reading_creates_nothing,
            c03_invalid_arguments_write_nothing, c04_same_inputs_replace_whatever_the_hint,
            c05_listing_is_key_only_and_byte_ordered, c06_list_units_answers_each_id_in_order,
            c07_read_values_reports_each_record, c08_manifests_and_bases,
            c09_remove_returns_what_existed, c10_deletion_reaches_peers_and_reattestation_wins,
            c11_union_after_sync, c12_concurrent_writers_lose_nothing,
            c13_same_key_from_two_peers_converges, c14_fetch_and_push_say_what_happened,
            c15_prefetch_makes_chosen_values_readable, c16_an_unreachable_store_fails_fast,
            c17_read_only_store_reads, c18_hints_round_trip, c19_batch_writes_are_durable,
            c20_many_values, c21_concurrent_first_writes_create_the_store_once,
            c22_one_unreadable_value_hides_only_itself, c23_foreign_keys_are_ignored,
            c24_errors_never_show_secrets, c25_reads_see_this_handles_writes_after_a_prefetch,
            c26_status_and_count, c27_read_units_matches_list_then_read,
            c28_orphan_manifests_keeps_what_is_referenced_or_unknown,
            c29_remove_manifests_keeps_referenced_and_recent, c30_failed_batch_reports_and_loses,
            c31_failed_store_fails_every_call, c32_concurrent_readers_and_writer,
            c33_key_and_target_parity, c34_copy_keeps_keys_and_targets,
        );
    };
}

#[cfg(feature = "conformance")]
#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_tests {
    ($factory:expr; $($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let factory: ::std::option::Option<
                    ::std::boxed::Box<dyn $crate::conformance::StoreFactory>,
                > = $factory;
                match factory {
                    ::std::option::Option::Some(f) => $crate::conformance::scenarios::$name(&*f),
                    ::std::option::Option::None => ::std::eprintln!(
                        "skipping {}: this backend is not available here",
                        ::std::stringify!($name)
                    ),
                }
            }
        )*
    };
}
