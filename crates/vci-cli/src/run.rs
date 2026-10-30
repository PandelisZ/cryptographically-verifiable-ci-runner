//! `vci run`: run tests with collection on, then sign and store an
//! attestation for every test file that is provably attestable.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use vci_adapter::Observed;
use vci_attest::keyless::KeylessSigner;
use vci_attest::{FrameExt, Statement, Subject};
use vci_core::{
    Encoded, External, Frame, Hdr, InputManifest, ObjectKind, Observation, PREDICATE_TYPE,
    PREDICATE_TYPE_V2, Predicate, RepoPath, Tables, Toolchain, UnitInputs, UnitRecord,
    VciPredicateV2, sorted_compact_json,
};
use vci_store::{
    AttestationStore, Columns, KeyHint, NewAttestation, NewObject, Prefetch, Record, StoreError,
    StoredEnvelope, WriteBatch, decode_record,
};

use crate::ctx::{
    Ctx, Project, TestFile, VciPredicate, mark_cross_project_ambiguity, open_repo, storage_key,
    working_tree_config,
};
use crate::envpolicy::{ChildEnvMap, lookup};
use crate::treestat::TreeStat;
use crate::util::{now_unix, parse_duration, rfc3339};
use crate::{global, keys};

pub struct RunArgs {
    pub files: Vec<String>,
    pub key: Option<Utf8PathBuf>,
    /// Sign keylessly with the job's OIDC token, with this Sigstore
    /// instance (`--oidc[=github|public-good]`).
    pub oidc: Option<String>,
    pub ttl: String,
    /// Write a JSON summary of every unit (attested or not, with its
    /// reasons) to this file.
    pub summary: Option<Utf8PathBuf>,
}

/// What `vci run` decided for one unit (for the refusal summary and
/// `--summary`).
struct UnitOutcome {
    test_id: String,
    project: Option<String>,
    adapter: &'static str,
    attested: bool,
    /// Whether an attested unit's attestation was stored: false only when
    /// the run signs without storing ([`StoreMode::SignOnly`]). Serialized
    /// only when false, so the summary of a run that stores is unchanged.
    stored: bool,
    /// Stable reason keys ([`taint_key`], [`refusal_key`]), most frequent
    /// taint first.
    reasons: Vec<String>,
    /// The refusal line's text.
    detail: Option<String>,
    /// Every refusing taint, as the collector reported it.
    taints: Vec<String>,
    /// Attested units: the taints a policy waived (the attestation's
    /// `waived`).
    waived: Vec<String>,
}

/// The project a unit's outcome names: its `[[projects]]` name (none in
/// the single-project form) and adapter.
#[derive(Debug, Clone)]
struct Owner {
    project: Option<String>,
    adapter: &'static str,
}

impl Owner {
    fn of(project: &Project) -> Self {
        Owner {
            project: (!project.name.is_empty()).then(|| project.name.clone()),
            adapter: project.adapter.name(),
        }
    }
}

impl UnitOutcome {
    fn refused(test_id: &str, project: &Project, detail: String, reasons: Vec<String>) -> Self {
        Self::refused_by(test_id, &Owner::of(project), detail, reasons)
    }

    fn refused_by(test_id: &str, owner: &Owner, detail: String, reasons: Vec<String>) -> Self {
        Self {
            test_id: test_id.to_owned(),
            project: owner.project.clone(),
            adapter: owner.adapter,
            attested: false,
            stored: true,
            reasons,
            detail: Some(detail),
            taints: vec![],
            waived: vec![],
        }
    }
}

/// `vci: why not attested` lines: files per reason key, most first.
fn reason_counts(outcomes: &[UnitOutcome]) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for o in outcomes.iter().filter(|o| !o.attested) {
        for r in &o.reasons {
            *counts.entry(r.as_str()).or_default() += 1;
        }
    }
    let mut v: Vec<(String, usize)> = counts.into_iter().map(|(k, n)| (k.to_owned(), n)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

/// The `--summary` document.
fn summary_json(outcomes: &[UnitOutcome]) -> serde_json::Value {
    let attested = outcomes.iter().filter(|o| o.attested).count();
    serde_json::json!({
        "version": 1,
        "attested": attested,
        "notAttested": outcomes.len() - attested,
        "reasons": reason_counts(outcomes)
            .into_iter()
            .map(|(reason, files)| serde_json::json!({"reason": reason, "files": files}))
            .collect::<Vec<_>>(),
        "units": outcomes
            .iter()
            .map(|o| {
                let mut u = serde_json::json!({
                    "testId": o.test_id,
                    "project": o.project,
                    "adapter": o.adapter,
                    "attested": o.attested,
                    "reasons": o.reasons,
                    "detail": o.detail,
                    "taints": o.taints,
                    "waived": o.waived,
                });
                if !o.stored {
                    u["stored"] = false.into();
                }
                u
            })
            .collect::<Vec<_>>(),
    })
}

/// How [`run_units`] uses the store: the publication gate of `vci ci` on a
/// shared store (docs/STORE-BACKENDS.md section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreMode {
    /// Store every attestation and its input manifest, remove what each
    /// supersedes, and then the manifests no attestation references any
    /// more.
    Write,
    /// Sign every attestation but store nothing, supersede nothing and
    /// collect nothing: `vci ci` without `--push` on a store whose writes
    /// every machine sees at once (nothing leaves a CI job without
    /// `--push`, as with git-meta).
    SignOnly,
}

/// Whether a failure to store says that the store cannot be used (it
/// could not be selected or opened, cannot be reached, is not set up,
/// refuses this writer, is too new, or lacks the operation) rather than
/// that something went wrong. The unit is then refused like any other and
/// the exit code stays the tests' (docs/STORE-BACKENDS.md section 10). A
/// backend's own errors (every one of git-meta's) and invalid arguments
/// remain problems of the run, as in vci 2.7.
fn store_unusable(e: &StoreError) -> bool {
    matches!(
        e,
        StoreError::Config(_)
            | StoreError::Unavailable { .. }
            | StoreError::Timeout { .. }
            | StoreError::NotInitialized { .. }
            | StoreError::Incompatible { .. }
            | StoreError::Denied { .. }
            | StoreError::Unsupported { .. }
    )
}

/// One signed unit for [`StoreLoop::attest`], ready to store: made on the
/// check pool, stored on the writer thread.
struct ToStore {
    /// The unit as its lines name it.
    label: String,
    test_id: String,
    input_root: String,
    /// How many entries its input manifest has.
    entries: usize,
    /// A format-1 record's input manifest, encoded (on the shared manifest
    /// when there is one, vci 2.1.8), stored before the attestation. A
    /// format-3 record has none: its inputs are its descriptor and the
    /// run's objects (STORE-V2 section 1.2).
    manifest: Option<String>,
    storage_key: String,
    hint: Option<KeyHint>,
    /// The record: a DSSE envelope JSON (format 1) or a text frame
    /// (format 3).
    envelope: Vec<u8>,
    /// A format-3 record's listing columns, copied from the statement it
    /// signed (section 2.1); `None` for a format-1 record.
    columns: Option<Columns>,
    /// The same signer's attestations of the unit that storing this one
    /// supersedes ([`superseded_by`]).
    doomed: Vec<StoredEnvelope>,
    /// The object ids each doomed record (by key) names, removed under the
    /// orphan rule once per run ([`drop_orphan_objects`]).
    doomed_objects: BTreeMap<String, Vec<String>>,
    /// The taints a policy waived.
    waived: Vec<String>,
}

/// One signed unit of either format, before it is made ready to store.
struct Signed {
    /// The record bytes ([`ToStore::envelope`]).
    record: Vec<u8>,
    /// The listing columns ([`ToStore::columns`]).
    columns: Option<Columns>,
}

/// What [`run_units`]' writer thread does for one unit, in unit order.
enum Job {
    /// Not attested.
    Refused {
        label: String,
        reason: String,
        reasons: Vec<String>,
        taints: Vec<String>,
    },
    /// Attestable, with its warnings (whole lines, said first): stored, or
    /// it could not be signed.
    Attestable {
        warnings: Vec<String>,
        unit: Result<Box<ToStore>, (String, anyhow::Error)>,
    },
}

/// A line of a deferred batch's report, held until the batch finishes.
enum Held {
    Line(String),
    /// The line of the unit in this slot.
    Unit(usize),
}

/// One unit's place in [`StoreLoop`]'s report, in unit order.
enum Slot {
    /// Reported.
    Done(UnitOutcome),
    /// Stored inside a deferred batch: reported (its line, outcome,
    /// supersession) only once the batch finishes.
    Pending {
        outcome: UnitOutcome,
        line: String,
        superseded: usize,
        dropped: BTreeSet<String>,
        dropped_objects: BTreeSet<String>,
        /// The key it was stored under: a batch that loses some of its
        /// writes names them by key ([`vci_store::Finished::lost`]).
        key: String,
    },
}

/// What one project's [`StoreLoop`] did.
#[derive(Default)]
struct Stored {
    attested: usize,
    refused: usize,
    /// Superseded attestations removed.
    superseded: usize,
    /// Units signed and not stored ([`StoreMode::SignOnly`]); also counted
    /// in `attested`.
    signed_only: usize,
    /// In unit order.
    outcomes: Vec<UnitOutcome>,
    errors: Vec<String>,
    /// [`RunOutcome::store_failures`].
    store_failures: Vec<String>,
    /// The input roots the removed attestations referenced.
    dropped_roots: BTreeSet<String>,
    /// The object ids the removed format-3 attestations named.
    dropped_objects: BTreeSet<String>,
    /// Seconds storing and removing (manifests, then attestations, then
    /// removals), of which storing manifests and removing.
    store_secs: f64,
    manifest_secs: f64,
    remove_secs: f64,
    /// The bytes of the run's objects put, of the records stored, and the
    /// batches opened (the metrics lines).
    objects_bytes: usize,
    records_bytes: usize,
    batches: usize,
}

/// One project's store loop in [`run_units`]: each unit in order, refused
/// or signed and stored, inside one write batch, and reported.
///
/// With an immediate batch, each unit is reported as it is stored. With a
/// deferred one (every backend's since 2.8: one transaction per project),
/// the report waits for the batch to finish, and then says every line in
/// unit order, as an immediate batch would have: if the batch fails,
/// nothing of it was stored and every unit it held is refused instead
/// (docs/STORE-BACKENDS.md section 6), so no output claims a unit that was
/// not stored.
struct StoreLoop<'s> {
    store: &'s dyn AttestationStore,
    mode: StoreMode,
    signer: &'s str,
    owner: Owner,
    batch: Option<WriteBatch>,
    slots: Vec<Slot>,
    /// A deferred batch's report, in order.
    held: Vec<Held>,
    done: Stored,
    /// Why the run's objects could not be put ([`StoreLoop::put_objects`]),
    /// and whether the store cannot be used ([`store_unusable`]): every
    /// format-3 unit after it is refused, since its record would name
    /// objects the store does not hold.
    objects_failed: Option<(String, bool)>,
    /// Where the lines go (stderr; a test collects them).
    say: &'s mut dyn FnMut(&str),
}

impl<'s> StoreLoop<'s> {
    fn new(
        store: &'s dyn AttestationStore,
        mode: StoreMode,
        signer: &'s str,
        owner: Owner,
        say: &'s mut dyn FnMut(&str),
    ) -> Self {
        // One git-meta session and store connection for every unit's writes
        // (2.7.15; whatever the store shares between writes); without it
        // each write opens its own. Signing only writes nothing.
        let batch = match mode {
            StoreMode::Write => store.batch().ok(),
            StoreMode::SignOnly => None,
        };
        let done = Stored {
            batches: usize::from(batch.is_some()),
            ..Stored::default()
        };
        StoreLoop {
            store,
            mode,
            signer,
            owner,
            batch,
            slots: Vec::new(),
            held: Vec::new(),
            done,
            objects_failed: None,
            say,
        }
    }

    /// Put the run's format-3 objects (STORE-V2 section 1.4 step 4: the
    /// hdr and tables objects, the shape, the state), before any record
    /// that names them, inside the batch. A put the store refuses is a
    /// warning here and refuses every format-3 unit after it
    /// ([`StoreLoop::objects_failed`]), so that no record names an object
    /// the store does not hold. Signing only, nothing is put.
    fn put_objects(&mut self, objects: &[RunObject]) {
        if self.mode == StoreMode::SignOnly || objects.is_empty() {
            return;
        }
        let t = std::time::Instant::now();
        let news: Vec<NewObject<'_>> = objects
            .iter()
            .map(|o| NewObject::new(o.kind, &o.bytes))
            .collect();
        match self.store.put_objects(&news) {
            Ok(_) => {
                self.done.objects_bytes += objects.iter().map(|o| o.bytes.len()).sum::<usize>();
            }
            Err(e) => {
                self.note(format!(
                    "vci: warning: storing the run's {} object(s) in the {} store: {e}",
                    objects.len(),
                    self.store.kind()
                ));
                self.objects_failed = Some((e.to_string(), store_unusable(&e)));
            }
        }
        self.done.store_secs += t.elapsed().as_secs_f64();
    }

    fn deferred(&self) -> bool {
        self.batch.as_ref().is_some_and(WriteBatch::defers_writes)
    }

    /// Say `line` (a warning, a refusal): at once, or with a deferred
    /// batch in its place in the report.
    fn note(&mut self, line: String) {
        if self.deferred() {
            self.held.push(Held::Line(line));
        } else {
            (self.say)(&line);
        }
    }

    /// One unit's [`Job`].
    fn apply(&mut self, job: Job) {
        match job {
            Job::Refused {
                label,
                reason,
                reasons,
                taints,
            } => self.refuse(&label, reason, reasons, taints),
            Job::Attestable { warnings, unit } => {
                for w in warnings {
                    self.note(w);
                }
                match unit {
                    Ok(u) => self.attest(*u),
                    Err((label, e)) => self.failed(&label, &e),
                }
            }
        }
    }

    /// A unit not attested; `reason` is its line's text.
    fn refuse(&mut self, label: &str, reason: String, reasons: Vec<String>, taints: Vec<String>) {
        self.done.refused += 1;
        self.note(format!("vci: not attesting {label}: {reason}"));
        let mut out = UnitOutcome::refused_by(label, &self.owner, reason, reasons);
        out.taints = taints;
        self.slots.push(Slot::Done(out));
    }

    /// A unit that could not be signed or stored: a problem of the run,
    /// or, when the store cannot be used ([`store_unusable`]), a refusal
    /// that leaves the exit code to the tests.
    fn failed(&mut self, label: &str, e: &anyhow::Error) {
        let msg = format!("{label}: {e:#}");
        if e.downcast_ref::<StoreError>().is_some_and(store_unusable) {
            self.note(format!(
                "vci: not attesting {label}: signing or storing failed: {e:#}"
            ));
            self.done.store_failures.push(msg);
        } else {
            self.note(format!("vci: error: not attesting {msg}"));
            self.done.errors.push(msg);
        }
        self.done.refused += 1;
        self.slots.push(Slot::Done(UnitOutcome::refused_by(
            label,
            &self.owner,
            format!("signing or storing failed: {e:#}"),
            vec!["signing or storing failed".to_owned()],
        )));
    }

    /// A signed unit: store its manifest, then it, then remove what it
    /// supersedes, and report it (with a deferred batch: once the batch
    /// finishes). Signing only, it is counted and reported as not stored.
    fn attest(&mut self, u: ToStore) {
        let outcome = UnitOutcome {
            test_id: u.label.clone(),
            project: self.owner.project.clone(),
            adapter: self.owner.adapter,
            attested: true,
            stored: self.mode == StoreMode::Write,
            reasons: vec![],
            detail: None,
            taints: vec![],
            waived: u.waived.clone(),
        };
        if self.mode == StoreMode::SignOnly {
            self.done.attested += 1;
            self.done.signed_only += 1;
            self.slots.push(Slot::Done(outcome));
            return;
        }
        let label = u.label.clone();
        let entries = u.entries;
        let root = u.input_root[..16.min(u.input_root.len())].to_owned();
        let waived = u.waived.clone();
        if u.columns.is_some()
            && let Some((why, unusable)) = &self.objects_failed
        {
            // Its record would name objects the store did not take.
            let e = if *unusable {
                StoreError::unavailable(self.store.kind(), why.clone())
            } else {
                StoreError::other(why.clone())
            };
            let e = anyhow::Error::from(e).context("storing the run's objects");
            return self.failed(&label, &e);
        }
        let (stored, superseded, dropped, dropped_objects, warnings) = match self.write(u) {
            Ok(x) => x,
            Err(e) => return self.failed(&label, &e),
        };
        for w in warnings {
            self.note(w);
        }
        self.done.attested += 1;
        let waived = if waived.is_empty() {
            String::new()
        } else {
            format!(" (waived: {})", waived_note(&waived))
        };
        let line = format!(
            "vci: attested {label}{waived} ({entries} inputs, root {root}) as {} {} {}",
            self.store.kind(),
            stored.target,
            stored.key
        );
        if self.deferred() {
            self.held.push(Held::Unit(self.slots.len()));
            self.slots.push(Slot::Pending {
                outcome,
                line,
                superseded,
                dropped,
                dropped_objects,
                key: stored.key.clone(),
            });
        } else {
            self.done.superseded += superseded;
            self.done.dropped_roots.extend(dropped);
            self.done.dropped_objects.extend(dropped_objects);
            (self.say)(&line);
            self.slots.push(Slot::Done(outcome));
        }
    }

    /// Store `u` (a format-1 record's manifest first: an attestation is
    /// never stored without the manifest it references; a format-3
    /// record's objects went first, [`StoreLoop::put_objects`]) and remove
    /// what it supersedes: the entry stored, how many were removed, the
    /// roots and the object ids they referenced, and the warnings about
    /// removals that failed.
    #[allow(clippy::type_complexity)]
    fn write(
        &mut self,
        u: ToStore,
    ) -> Result<(
        StoredEnvelope,
        usize,
        BTreeSet<String>,
        BTreeSet<String>,
        Vec<String>,
    )> {
        let t = std::time::Instant::now();
        if let Some(m) = &u.manifest {
            self.store
                .put_manifest(&u.input_root, m.as_bytes())
                .context("storing the input manifest")?;
            self.done.manifest_secs += t.elapsed().as_secs_f64();
        }
        let mut att = NewAttestation::for_test(
            &u.test_id,
            self.signer,
            &u.storage_key,
            u.hint.as_ref(),
            &u.envelope,
        );
        if let Some(c) = &u.columns {
            att = att.with_columns(c);
        }
        let stored = self.store.put(&att)?;
        self.done.records_bytes += u.envelope.len();
        // Never the one just stored (the same storage key: the same
        // inputs, replaced).
        let doomed: Vec<_> = u
            .doomed
            .into_iter()
            .filter(|e| e.key != stored.key)
            .collect();
        let t_remove = std::time::Instant::now();
        let mut dropped = BTreeSet::new();
        let mut dropped_objects = BTreeSet::new();
        let mut warnings = Vec::new();
        let superseded = remove_superseded(
            self.store,
            &u.test_id,
            doomed,
            &u.doomed_objects,
            &mut dropped,
            &mut dropped_objects,
            &mut warnings,
        );
        self.done.remove_secs += t_remove.elapsed().as_secs_f64();
        self.done.store_secs += t.elapsed().as_secs_f64();
        Ok((stored, superseded, dropped, dropped_objects, warnings))
    }

    /// End the batch, then report every unit in order. A deferred batch
    /// that fails stored nothing: each unit it held is refused ("signing
    /// or storing failed") and counted as an error, and what it would have
    /// superseded stays. A batch that lost some of its units' writes and
    /// stored the rest (the libSQL store, which writes a batch as several
    /// short transactions) refuses only those units. What failed after the
    /// batch's writes were durable (git-meta's log re-stamp) is a warning
    /// after them.
    fn finish(self) -> Stored {
        let StoreLoop {
            store,
            batch,
            slots,
            held,
            mut done,
            say,
            owner,
            ..
        } = self;
        let deferred = batch.as_ref().is_some_and(WriteBatch::defers_writes);
        let mut after = Vec::new();
        let mut lost = vci_store::Finished::default();
        let failed = match batch.map(WriteBatch::finish_partial) {
            Some(Err(e)) if deferred => Some(e),
            Some(Err(e)) => {
                // Every write was durable already.
                say(&format!(
                    "vci: warning: ending the {} store's write batch: {e}",
                    store.kind()
                ));
                None
            }
            Some(Ok(mut finished)) => {
                after = std::mem::take(&mut finished.warnings);
                lost = finished;
                None
            }
            None => None,
        };
        // Each pending unit's line, by slot.
        let mut lines: Vec<Option<String>> = Vec::with_capacity(slots.len());
        for slot in slots {
            match slot {
                Slot::Done(o) => {
                    done.outcomes.push(o);
                    lines.push(None);
                }
                Slot::Pending {
                    outcome,
                    line,
                    superseded,
                    dropped,
                    dropped_objects,
                    key,
                } => match failed.as_ref().or_else(|| lost.lost(&key)) {
                    None => {
                        lines.push(Some(line));
                        done.superseded += superseded;
                        done.dropped_roots.extend(dropped);
                        done.dropped_objects.extend(dropped_objects);
                        done.outcomes.push(outcome);
                    }
                    Some(e) => {
                        let label = outcome.test_id;
                        let msg = format!("{label}: storing the batch: {e}");
                        if store_unusable(e) {
                            lines.push(Some(format!(
                                "vci: not attesting {label}: signing or storing failed: storing the batch: {e}"
                            )));
                            done.store_failures.push(msg);
                        } else {
                            lines.push(Some(format!("vci: error: not attesting {msg}")));
                            done.errors.push(msg);
                        }
                        done.attested -= 1;
                        done.refused += 1;
                        done.outcomes.push(UnitOutcome::refused_by(
                            &label,
                            &owner,
                            format!("signing or storing failed: storing the batch: {e}"),
                            vec!["signing or storing failed".to_owned()],
                        ));
                    }
                },
            }
        }
        for h in held {
            match h {
                Held::Line(l) => say(&l),
                Held::Unit(i) => {
                    if let Some(l) = lines.get_mut(i).and_then(Option::take) {
                        say(&l);
                    }
                }
            }
        }
        for w in after {
            say(&format!("vci: warning: {w}"));
        }
        done
    }
}

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Env vars hashed into every test file's global manifest, per adapter.
pub(crate) fn global_env_keys(adapter: &str) -> Vec<String> {
    match adapter {
        // vci sets NODE_OPTIONS itself; a non-empty user value still matters.
        "vitest" | "node-test" => vec!["NODE_OPTIONS".to_owned()],
        // PYTEST_*/PYTHON* are reported per file by the collector.
        _ => vec![],
    }
}

/// Global manifest (per test file): global observations plus the adapter's
/// global env keys (NODE_OPTIONS for Vitest).
pub fn global_manifest(
    ctx: &Ctx,
    project: &Project,
    child: &ChildEnvMap,
    test_abs: &Utf8Path,
) -> Result<InputManifest> {
    global_manifest_in(&Checkout::direct(&ctx.root), project, child, test_abs)
}

/// [`global_manifest`], reading the checkout through `checkout`.
fn global_manifest_in(
    checkout: &Checkout<'_>,
    project: &Project,
    child: &ChildEnvMap,
    test_abs: &Utf8Path,
) -> Result<InputManifest> {
    let mut obs = global::observations(checkout.root, project.adapter.as_ref(), test_abs)?;
    // Rails' `rails_inputs`/`ignore_inputs` (2.7.36): `config/application.rb`
    // and the other boot files are not global inputs either.
    obs.retain(|(p, _)| project.ignored_input(p.as_str()).is_none());
    let m = checkout.capture(
        &obs,
        vec![],
        &global_env_keys(project.adapter.name()),
        lookup(child),
    )?;
    m.check_case_collisions()?;
    Ok(m)
}

/// Observations of one test file, as repo paths (Vitest). Err names the
/// first path outside the repository.
#[cfg_attr(not(test), allow(dead_code))]
pub fn observations(root: &Utf8Path, o: &Observed) -> Result<Vec<(RepoPath, Observation)>, String> {
    observations_for(root, o, "vitest", true)
}

/// Observations of one test file for `adapter`: the collector's paths, plus
/// (Vitest and node-test) the package.json context of every module and,
/// when `tsconfig` (Vitest; node-test with a TypeScript loader), its
/// tsconfig.json chain.
pub fn observations_for(
    root: &Utf8Path,
    o: &Observed,
    adapter: &str,
    tsconfig: bool,
) -> Result<Vec<(RepoPath, Observation)>, String> {
    observations_in(&Checkout::direct(root), o, adapter, tsconfig)
}

/// [`observations_for`], reading the checkout through `checkout`.
fn observations_in(
    checkout: &Checkout<'_>,
    o: &Observed,
    adapter: &str,
    tsconfig: bool,
) -> Result<Vec<(RepoPath, Observation)>, String> {
    let root = checkout.root;
    let mut out = Vec::new();
    let groups: [(&BTreeSet<Utf8PathBuf>, Observation); 6] = [
        (&o.modules, Observation::Read),
        (&o.reads, Observation::Read),
        (&o.probes, Observation::Probe),
        (&o.readdirs, Observation::ReadDir),
        (&o.stats, Observation::Stat),
        (&o.excluded, Observation::Exclude),
    ];
    for (set, kind) in groups {
        for p in set {
            match RepoPath::from_abs(root, p) {
                Ok(rp) => out.push((rp, kind)),
                Err(_) => return Err(format!("input outside the repository: {p}")),
            }
        }
    }
    // Rails autoload lookups (2.6.0): each autoload directory marked, and
    // each name looked up checked against them all.
    for p in &o.autoload_dirs {
        match RepoPath::from_abs(root, &p.join(vci_core::AUTOLOAD_MARK)) {
            Ok(rp) => out.push((rp, Observation::AutoloadDir)),
            Err(_) => return Err(format!("input outside the repository: {p}")),
        }
    }
    if !o.autoload_dirs.is_empty() {
        // The names the process looked up, and those its repository code
        // asks about with `defined?(...)`, which Ruby answers without any
        // method the collector can hook (2.6.1).
        let mut names: BTreeSet<String> = o.autoload_names.clone();
        for m in &o.modules {
            if m.extension() == Some("rb") && m.starts_with(root) {
                names.extend(defined_names(m).iter().cloned());
            }
        }
        for n in &names {
            let rp = RepoPath::new(&format!("{}/{n}", vci_core::AUTOLOAD_MARK))
                .map_err(|e| format!("autoload name {n:?}: {e}"))?;
            out.push((rp, Observation::AutoloadMiss));
        }
    }
    let ignored = ignored_children(checkout, &out);
    out.extend(ignored);
    // package.json / tsconfig.json that decide how each module resolves its
    // imports and is transformed.
    if adapter == "vitest" || adapter == "node-test" {
        let ctx = global::module_context_with(
            root,
            o.modules.iter().map(|p| p.as_path()),
            adapter == "vitest" || tsconfig,
        )
        .map_err(|e| format!("module context: {e:#}"))?;
        out.extend(ctx);
    }
    Ok(out)
}

/// The constant names a Ruby source file asks about with `defined?`
/// (`defined?(::Agent::Swarms::LandingHolds)` gives `agent`, `swarms` and
/// `landingholds`, normalized by [`vci_core::autoload_name`]), read once
/// per file and run. A file that cannot be read gives none (it is an input
/// anyway, and its unit is refused if it changed).
fn defined_names(path: &Utf8Path) -> std::sync::Arc<Vec<String>> {
    type Cache =
        std::sync::Mutex<std::collections::HashMap<Utf8PathBuf, std::sync::Arc<Vec<String>>>>;
    static CACHE: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(v) = cache.lock().ok().and_then(|c| c.get(path).cloned()) {
        return v;
    }
    let v = std::sync::Arc::new(
        std::fs::read(path)
            .map(|b| scan_defined_names(&b))
            .unwrap_or_default(),
    );
    if let Ok(mut c) = cache.lock() {
        c.insert(path.to_owned(), v.clone());
    }
    v
}

/// Every constant path after `defined?` (with or without parentheses) in
/// `src`, split into its names, normalized.
fn scan_defined_names(src: &[u8]) -> Vec<String> {
    const KEY: &[u8] = b"defined?";
    let mut out = BTreeSet::new();
    let mut i = 0;
    while let Some(off) = src[i..].windows(KEY.len()).position(|w| w == KEY) {
        let mut j = i + off + KEY.len();
        i = j;
        while j < src.len() && (src[j] == b' ' || src[j] == b'(' || src[j] == b'\t') {
            j += 1;
        }
        let start = j;
        while j < src.len() && (src[j].is_ascii_alphanumeric() || src[j] == b'_' || src[j] == b':')
        {
            j += 1;
        }
        let path = String::from_utf8_lossy(&src[start..j]);
        for seg in path.split("::") {
            if seg.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                let n = vci_core::autoload_name(seg);
                if !n.is_empty() {
                    out.insert(n);
                }
            }
        }
    }
    out.into_iter().collect()
}

/// The paths of `o`'s observations (reads, modules, probes, listings, stats)
/// outside the repository `root`, sorted and once each.
fn outside_repository<'a>(root: &Utf8Path, o: &'a Observed) -> BTreeSet<&'a Utf8PathBuf> {
    [
        &o.modules,
        &o.reads,
        &o.probes,
        &o.readdirs,
        &o.stats,
        &o.excluded,
        &o.autoload_dirs,
    ]
    .into_iter()
    .flatten()
    .filter(|p| RepoPath::from_abs(root, p).is_err())
    .collect()
}

/// `o` without the observations of `paths` and of everything under them
/// (waived reads outside the repository, waived writes).
fn without_paths(o: &Observed, paths: &[Utf8PathBuf]) -> Observed {
    let mut o = o.clone();
    let keep = |p: &Utf8PathBuf| !paths.iter().any(|d| p.starts_with(d));
    for set in [
        &mut o.modules,
        &mut o.reads,
        &mut o.probes,
        &mut o.readdirs,
        &mut o.stats,
        &mut o.excluded,
        &mut o.autoload_dirs,
    ] {
        set.retain(keep);
    }
    o
}

/// Whether this process (and so the tests it starts) runs as the superuser:
/// the owner of a file it creates is uid 0 (the effective, or on Linux the
/// filesystem, uid). Permission checks do not apply to root, so a test's
/// result can depend on it (GitHub `container:` jobs run as root). Any error
/// counts as root, so that an attestation made or checked where this cannot
/// be decided only matches another such run.
pub fn running_as_root() -> bool {
    static ROOT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ROOT.get_or_init(|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            tempfile::NamedTempFile::new()
                .and_then(|f| f.as_file().metadata())
                .map(|m| m.uid() == 0)
                .unwrap_or(true)
        }
        #[cfg(not(unix))]
        {
            false
        }
    })
}

/// The toolchain recorded for (and compared against) an attestation.
pub fn toolchain_for(adapter: &str, v: &vci_adapter::ToolVersions) -> Toolchain {
    let mut t = Toolchain {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        superuser: running_as_root(),
        ..Default::default()
    };
    match adapter {
        "pytest" => {
            t.python = v.python.clone();
            t.implementation = v.implementation.clone();
            t.pytest = v.runner.clone();
            t.python_libs = v.python_libs.clone();
            t.python_dists = v.python_dists.clone();
        }
        "go" => {
            t.go = v.runner.clone();
            t.go_env = v.go_env.clone();
            t.go_arch_level = v.go_arch_level.clone();
        }
        "cargo" => {
            t.rust = v.runner.clone();
            t.cargo = v.cargo.clone();
            t.rust_host = v.rust_host.clone();
            t.rust_cfg = v.rust_cfg.clone();
        }
        // node:test is part of Node: the Node version is the runner's.
        "node-test" => {
            t.node = v.node.clone();
        }
        "rails" => {
            t.ruby = v.ruby.clone();
            t.ruby_engine = v.ruby_engine.clone();
            t.rails = v.rails.clone();
            t.bundler = v.ruby_bundler.clone();
            t.ruby_test = v.runner.clone();
            t.ruby_libs = v.ruby_libs.clone();
            t.ruby_db = v.ruby_db.clone();
            t.ruby_gems = v.ruby_gems.clone();
        }
        _ => {
            t.node = v.node.clone();
            t.vitest = v.runner.clone();
            t.vite = v.bundler.clone();
        }
    }
    t
}

struct Attestable {
    /// The predicate to sign: the manifest by reference (`manifestRef`).
    predicate: VciPredicate,
    /// The input manifest it references, stored on its own.
    manifest: InputManifest,
}

/// Collector versions vs the project's, per adapter.
fn collector_toolchain_mismatch(
    adapter: &str,
    o: &Observed,
    v: &vci_adapter::ToolVersions,
) -> Option<String> {
    match adapter {
        "pytest" => (o.python != v.python
            || o.implementation != v.implementation
            || o.runner_version != v.runner)
            .then(|| {
                format!(
                    "toolchain seen by the collector (python {} {}, pytest {}) differs from the project's (python {} {}, pytest {})",
                    o.implementation,
                    o.python,
                    o.runner_version,
                    v.implementation,
                    v.python,
                    v.runner
                )
            }),
        // The test binary reports runtime.Version(); `go env GOVERSION` is
        // what the project resolves (after any GOTOOLCHAIN switch).
        // Only the version token: with GOEXPERIMENT both may carry an
        // ` X:...` suffix (the experiments are compared in the toolchain).
        "go" => (o.runner_version.split_whitespace().next()
            != v.runner.split_whitespace().next())
        .then(|| {
            format!(
                "the test binary was built by {} but the project's go is {}",
                o.runner_version, v.runner
            )
        }),
        // The adapter records the rustc it probed; the build used the same
        // one unless something changed it in between.
        "cargo" => (o.runner_version != v.runner).then(|| {
            format!(
                "rustc changed during the run ({} -> {})",
                v.runner, o.runner_version
            )
        }),
        "rails" => (o.ruby != v.ruby
            || o.ruby_engine != v.ruby_engine
            || o.rails != v.rails
            || o.ruby_bundler != v.ruby_bundler
            || o.runner_version != v.runner)
            .then(|| {
                format!(
                    "toolchain seen by the collector ({} {}, rails {}, bundler {}, {}) differs from the project's ({} {}, rails {}, bundler {}, {})",
                    o.ruby_engine,
                    o.ruby,
                    o.rails,
                    o.ruby_bundler,
                    o.runner_version,
                    v.ruby_engine,
                    v.ruby,
                    v.rails,
                    v.ruby_bundler,
                    v.runner
                )
            }),
        "node-test" => (o.node != v.node).then(|| {
            format!(
                "the test ran on node {} but the project's node is {}",
                o.node, v.node
            )
        }),
        _ => (o.node != v.node || o.runner_version != v.runner || o.bundler_version != v.bundler)
            .then(|| {
                format!(
                    "toolchain seen by the collector (node {}, vitest {}, vite {}) differs from the project's (node {}, vitest {}, vite {})",
                    o.node, o.runner_version, o.bundler_version, v.node, v.runner, v.bundler
                )
            }),
    }
}

/// Names in a directory listing that a fresh CI checkout will not have:
/// OS metadata and bytecode caches.
const CHECKOUT_JUNK: &[&str] = &[".DS_Store", "Thumbs.db", "desktop.ini", "__pycache__"];

/// Warnings for attested directory listings that contain [`CHECKOUT_JUNK`]
/// git does not ignore (what it ignores is left out of the listing since
/// 2.0.3): the listing will differ in a fresh checkout, so the file will run
/// there (never a false skip, but a lost skip worth knowing about).
fn junk_in_listings(checkout: &Checkout<'_>, m: &InputManifest) -> Vec<String> {
    let mut out = Vec::new();
    for e in &m.entries {
        if e.kind != vci_core::EntryKind::DirListing {
            continue;
        }
        let Some(names) = checkout.child_names(&e.path) else {
            continue;
        };
        let junk: Vec<String> = names
            .iter()
            .filter(|n| CHECKOUT_JUNK.contains(&n.as_str()))
            .cloned()
            .collect();
        let paths: Vec<String> = junk
            .iter()
            .map(|n| {
                if e.path.is_root() {
                    n.clone()
                } else {
                    format!("{}/{n}", e.path.as_str())
                }
            })
            .collect();
        let ignored = checkout.git_ignored(&paths);
        let junk: Vec<String> = junk
            .into_iter()
            .zip(paths)
            .filter(|(_, p)| !ignored.contains(p))
            .map(|(n, _)| n)
            .collect();
        if !junk.is_empty() {
            let dir = if e.path.as_str().is_empty() {
                "."
            } else {
                e.path.as_str()
            };
            out.push(format!(
                "the listing of {dir} includes {} (not in a fresh checkout, e.g. in CI): this attestation will not match there. Remove {} and run again.",
                junk.join(", "),
                if junk.len() == 1 { "it" } else { "them" }
            ));
        }
    }
    out
}

/// The stable reason key of a taint: its category, without the paths,
/// arguments and explanations that vary between files. The first segment
/// (up to `:`, a space or `(`), and when it ends in a single `:`, the name
/// that follows (letters, digits, `_`, `-`): `native:FFI attach_function(...)`
/// -> `native:FFI`, `cargo:process: Command::new in ...` -> `cargo:process`,
/// `go:source: a.go uses Environ` -> `go:source`, `vci:not-hooked:ffi (...)` ->
/// `vci:not-hooked`, `external-without-version:/x` ->
/// `external-without-version`, `process:backtick` -> `process:backtick`.
pub fn taint_key(t: &str) -> String {
    let t = t.trim();
    let end = t.find([':', ' ', '(']).unwrap_or(t.len());
    let head = &t[..end];
    let rest = &t[end..];
    let Some(after) = rest.strip_prefix(':') else {
        return head.to_owned();
    };
    if after.starts_with(':') {
        return head.to_owned();
    }
    let name: String = after
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if name.is_empty() {
        head.to_owned()
    } else {
        format!("{head}:{name}")
    }
}

/// A read outside the repository (not an external, not a path the
/// collectors exempt): `outside-repository:<absolute path>`, key
/// `outside-repository`. It refuses the unit (the file cannot be an input)
/// unless `policy.ignore_taints` waives it; then the path is not hashed, only
/// recorded in the attestation's `waived`.
pub const OUTSIDE_REPOSITORY_TAINT: &str = "outside-repository:";
/// Paths the unit created, changed or deleted inside the repository:
/// `wrote-inside-repository: <path>, <path>` (repository-relative), key
/// `wrote-inside-repository`. Waived, the written paths are neither inputs
/// nor a refusal.
pub const WROTE_INSIDE_REPOSITORY_TAINT: &str = "wrote-inside-repository: ";
/// A passing result with skipped (or xfailed, or todo) tests:
/// `result:skipped:<skipped> of <tests>`, key `result:skipped`. A failed
/// result is never a taint.
pub const RESULT_SKIPPED_TAINT: &str = "result:skipped:";
/// A passing run in which no test ran (every test filtered out, as a
/// benchmark file gated by an environment variable): `result:no-tests`,
/// waivable; a run with tests that were filtered out is not.
pub const RESULT_NO_TESTS_TAINT: &str = "result:no-tests";

/// Directories inside `node_modules` that tools write caches to while tests
/// run (Vite's dependency optimizer, `.vite-temp` for bundled configs, the
/// `.cache` convention of babel-loader, eslint and others): writes there are
/// not outputs of the test, like Rails' log/ and tmp/.
const NODE_MODULES_CACHE_DIRS: &[&str] = &[".vite", ".vite-temp", ".cache"];

/// Is the repository-relative path `rel` (a write) in one of
/// [`NODE_MODULES_CACHE_DIRS`] of any `node_modules` directory (the
/// directory itself included)?
fn is_tool_cache_write(rel: &str) -> bool {
    let comps: Vec<&str> = rel.split('/').collect();
    comps
        .windows(2)
        .any(|w| w[0] == "node_modules" && NODE_MODULES_CACHE_DIRS.contains(&w[1]))
}

/// The stable reason key of a refusal message that is not a list of taints
/// (those are keyed by [`taint_key`]): the text before the first `:` or
/// `(`, or a fixed key for messages that start with a varying part.
pub fn refusal_key(msg: &str) -> String {
    const FIXED: &[(&str, &str)] = &[
        (
            "collector output is for adapter",
            "collector output is for another adapter",
        ),
        ("collector root ", "collector root is not the project dir"),
        ("go.work ", "go.work outside the repository"),
        (
            "its source refers to ",
            "source refers to a path that is not an input",
        ),
        ("declared input ", "declared input"),
        (
            "listed under more than one",
            "listed by more than one project",
        ),
    ];
    for (prefix, key) in FIXED {
        if msg.starts_with(prefix) {
            return (*key).to_owned();
        }
    }
    // The refusals `policy.ignore_taints` can waive are keyed by their taint
    // key, the pattern that waives them.
    if msg.starts_with("input outside the repository: ") {
        return taint_key(OUTSIDE_REPOSITORY_TAINT);
    }
    if msg.starts_with("wrote inside the repository: ") {
        return taint_key(WROTE_INSIDE_REPOSITORY_TAINT);
    }
    if msg.starts_with("result passed (0 failed, ") && msg.contains(" skipped or xfailed of ") {
        return taint_key(RESULT_SKIPPED_TAINT);
    }
    if msg.starts_with("result no-tests (") {
        return RESULT_NO_TESTS_TAINT.to_owned();
    }
    if msg.contains(" is built from a local directory") {
        return "external built from a local directory".into();
    }
    let end = msg.find([':', '(']).unwrap_or(msg.len());
    msg[..end].trim().to_owned()
}

/// Taints grouped by [`taint_key`], most frequent first (ties in order of
/// first appearance): `(key, first taint of the group, count)`.
fn group_taints<'a>(taints: &[&'a String]) -> Vec<(String, &'a str, usize)> {
    let mut groups: Vec<(String, &str, usize)> = Vec::new();
    for t in taints {
        let key = taint_key(t);
        match groups.iter_mut().find(|(k, _, _)| *k == key) {
            Some(g) => g.2 += 1,
            None => groups.push((key, t.as_str(), 1)),
        }
    }
    // A stable sort keeps first-appearance order among equal counts.
    groups.sort_by_key(|g| std::cmp::Reverse(g.2));
    groups
}

/// Taints for the refusal line, readable when a library makes hundreds of
/// similar calls (FFI's `attach_function` for every function of libvips):
/// taints with the same [`taint_key`] are shown once, as the first of them
/// with the count of the others, most frequent reason first. Every reason
/// is listed.
fn summarize_taints(taints: &[&String]) -> String {
    group_taints(taints)
        .into_iter()
        .map(|(key, first, count)| {
            if count > 1 {
                format!("{first} (+{} more {key})", count - 1)
            } else {
                first.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The taints of `o` a policy waives, and those that refuse it: `(waived,
/// refusing)`. Waived are those `policy.ignore_taints` matches (by
/// [`taint_key`]), Go's `go:net:` under `policy.go_allow_net`, and Cargo's
/// `cargo:undeclared-reads` when the unit declares `[[inputs]]`.
fn split_waived<'a>(
    project: &Project,
    declared: &[String],
    o: &'a Observed,
) -> (Vec<&'a String>, Vec<&'a String>) {
    split_waived_taints(&project.policy, project.adapter.name(), declared, &o.taints)
}

fn split_waived_taints<'a>(
    policy: &crate::config::Policy,
    adapter: &str,
    declared: &[String],
    taints: &'a [String],
) -> (Vec<&'a String>, Vec<&'a String>) {
    taints.iter().partition(|t| {
        (adapter == "cargo"
            && !declared.is_empty()
            && t.starts_with(vci_adapter::CARGO_UNDECLARED_TAINT))
            || policy.taint_waiver(adapter, t).is_some()
    })
}

/// `process:system, +2` for the `attested` line: the most frequent waived
/// reason key and the number of other keys.
fn waived_note(waived: &[String]) -> String {
    let refs: Vec<&String> = waived.iter().collect();
    let groups = group_taints(&refs);
    match groups.split_first() {
        None => String::new(),
        Some((first, [])) => first.0.clone(),
        Some((first, rest)) => format!("{}, +{}", first.0, rest.len()),
    }
}

/// What [`run_units`] decided for one unit, before storing it: made for
/// several units at once, reported and stored in their order.
enum Verdict {
    /// Not attested: the refusal line's text, the reason keys, the
    /// refusing taints.
    Refused {
        reason: String,
        reasons: Vec<String>,
        taints: Vec<String>,
    },
    /// Attestable: the warnings to print first (whole lines), and the signed
    /// record to store, or why it could not be signed. A format-1 record
    /// is signed with the verdict; a format-3 one once the run's objects
    /// are built, since its statement names them (`None` until then).
    Attestable {
        a: Box<Attestable>,
        warnings: Vec<String>,
        signed: Option<Result<Signed>>,
    },
}

/// How many units [`run_units`] checks and signs at once after their tests
/// ran: `$VCI_JOBS`, else the number of CPUs. Each mostly hashes inputs; a
/// key file signs in process (2.8), and only a key ssh-keygen must handle,
/// or keyless signing, waits for another process or service. One writer
/// thread stores the units, in order. Twice as many threads as CPUs were
/// not faster (1,200 Go packages on 14 cores: the check's thread-seconds
/// grew by half and the step's wall time did not fall), so the default
/// stays one per CPU.
fn check_jobs() -> usize {
    std::env::var("VCI_JOBS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
}

/// `work` on every item, `jobs` items at a time (on threads of their own),
/// and `sink` (on the calling thread) on each result in the items' order, as
/// soon as it and every result before it are ready. One job: one item after
/// the other, each sunk before the next is worked on.
fn in_order<T: Sync, R: Send>(
    items: &[T],
    jobs: usize,
    work: impl Fn(&T) -> R + Sync,
    mut sink: impl FnMut(usize, R),
) {
    if jobs <= 1 || items.len() <= 1 {
        for (i, t) in items.iter().enumerate() {
            sink(i, work(t));
        }
        return;
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        let (tx, rx) = std::sync::mpsc::channel();
        for _ in 0..jobs.min(items.len()) {
            let (tx, next, work) = (tx.clone(), &next, &work);
            s.spawn(move || {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(t) = items.get(i) else { break };
                    if tx.send((i, work(t))).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);
        let mut ready = BTreeMap::new();
        let mut due = 0;
        for (i, r) in rx {
            ready.insert(i, r);
            while let Some(r) = ready.remove(&due) {
                sink(due, r);
                due += 1;
            }
        }
    });
}

/// The warnings about an attestable unit's inputs (whole lines): listings
/// with checkout junk, `CI` taken from the machine, inputs git ignores.
fn attested_warnings(
    checkout: &Checkout<'_>,
    project: &Project,
    label: &str,
    a: &Attestable,
) -> Vec<String> {
    let mut out: Vec<String> = junk_in_listings(checkout, &a.manifest)
        .into_iter()
        .map(|w| format!("vci: warning: {label}: {w}"))
        .collect();
    // Stripped (absent on both sides) or set by vci, CI is the same
    // everywhere; taken from the machine, it is not.
    if a.manifest.env.iter().any(|e| e.key == "CI")
        && project.project_env().classify("CI") == crate::envpolicy::EnvClass::Hash
    {
        out.push(format!(
            "vci: warning: {label}: it reads CI, which vci.toml hashes and CI runners set (to \"true\"): unless it had that value here, this attestation will not match on a runner (set it instead: [env] set = {{ CI = \"true\" }}){}",
            if project.adapter.name() == "rails" {
                "; Rails' generated config/environments/test.rb reads it (config.eager_load = ENV[\"CI\"].present?)"
            } else {
                ""
            }
        ));
    }
    if matches!(project.adapter.name(), "cargo" | "rails" | "node-test") {
        let ignored = ignored_inputs(checkout, &a.manifest);
        if !ignored.is_empty() {
            let why = if project.adapter.name() == "cargo" {
                "every file in a package directory is an input"
            } else {
                "the test read them; delete them before attesting if they are leftovers"
            };
            out.push(format!(
                "vci: warning: {label}: inputs ignored by git (a fresh checkout, e.g. in CI, will not have them, so this attestation will not match there; {why}): {}{}",
                ignored
                    .iter()
                    .take(10)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                if ignored.len() > 10 { ", ..." } else { "" }
            ));
            if project.adapter.name() == "rails"
                && let Some(key) = ignored.iter().find(|p| is_rails_key_file(p))
            {
                out.push(format!(
                    "vci: warning: {label}: it read {key}, Rails' credentials key (git-ignored, so never in CI): in an app generated with credentials, Active Record reads it at boot, so no test that boots Rails is skipped in CI. Give the test environment its own credentials with a committed key (`bin/rails credentials:edit --environment test`, then commit config/credentials/test.key and test.yml.enc), or remove config/master.key and the credentials file if the tests need none, or declare RAILS_MASTER_KEY in vci.toml and set it to the same value here and in CI"
                ));
            }
        }
    }
    out
}

/// Sign the statement of an attestable unit: the envelope bytes to store.
fn sign_predicate(key: &Signer<'_>, p: &VciPredicate) -> Result<Vec<u8>> {
    let value = serde_json::to_value(p)?;
    let mut digest = BTreeMap::new();
    digest.insert("blake3".to_owned(), p.core.input_root.clone());
    let stmt = Statement::new(
        vec![Subject {
            name: p.core.test_id.clone(),
            digest,
        }],
        PREDICATE_TYPE,
        value,
    );
    key.sign(&stmt)
}

#[allow(clippy::too_many_arguments)]
fn check_one(
    ctx: &Ctx,
    project: &Project,
    o: &Observed,
    file: Option<&TestFile>,
    versions: &vci_adapter::ToolVersions,
    child: &ChildEnvMap,
    pre_stat: &TreeStat,
    pre_global: &BTreeMap<String, Result<String, String>>,
    base: &PredicateBase,
    locked: &Result<Option<crate::externals::LockedPackages>, String>,
    scratch: &[Utf8PathBuf],
    checkout: &Checkout<'_>,
) -> Result<Attestable, String> {
    let file = file.ok_or_else(|| "not in the runner's test file list".to_owned())?;
    if file.ambiguous {
        return Err(
            "listed under more than one runner project (or by more than one vci project)".into(),
        );
    }
    let adapter = project.adapter.as_ref();
    if o.adapter != adapter.name() {
        return Err(format!(
            "collector output is for adapter {:?}, not {:?}",
            o.adapter,
            adapter.name()
        ));
    }
    if Utf8Path::new(&o.root) != adapter.project_dir()
        && Utf8Path::new(&o.root).canonicalize_utf8().ok().as_deref() != Some(adapter.project_dir())
    {
        return Err(format!("collector root {} is not the project dir", o.root));
    }
    // `policy.ignore_taints` (and Go's `policy.go_allow_net`, which is
    // `ignore_taints = ["go:net"]`) waives matching taints (recorded in the
    // attestation, which is then only accepted while the base policy agrees).
    // Cargo: declaring inputs for the unit (`[[inputs]]`) waives the
    // "may read outside its package" refusal (the declaration is recorded
    // and must still be the base config's).
    let declared = project.extra_inputs(&file.project_rel);
    let (waived, taints) = split_waived(project, &declared, o);
    if !taints.is_empty() {
        return Err(format!("tainted: {}", summarize_taints(&taints)));
    }
    let mut waived: Vec<String> = waived.into_iter().cloned().collect();
    // vci's own refusals that are taints too (`outside-repository`,
    // `wrote-inside-repository`, `result:skipped`): waived by the same
    // policy, otherwise the refusal they always were.
    let waives = |taint: &str| project.policy.taint_waiver(adapter.name(), taint).is_some();
    if adapter.name() == "cargo" && project.env.mode == crate::config::EnvMode::Loose {
        // What a Rust test reads from the environment cannot be observed;
        // only strict mode (undeclared variables removed, so unset on both
        // sides) makes that safe.
        return Err(
            "env mode \"loose\": the cargo adapter only attests in strict mode (a Rust test's environment reads are not observed)"
                .into(),
        );
    }
    if adapter.name() == "go" {
        // A go.work outside the repository decides which module versions
        // are built, but is not an input CI can re-hash.
        let w = versions.go_work.as_str();
        if !w.is_empty() && w != "off" {
            let abs = Utf8Path::new(w);
            let inside = abs.starts_with(&ctx.root)
                || abs
                    .canonicalize_utf8()
                    .is_ok_and(|c| c.starts_with(&ctx.root));
            if !inside {
                return Err(format!(
                    "go.work {w} is outside the repository (set GOWORK=off or move it into the repository)"
                ));
            }
        }
    }
    // Files the test created, changed or deleted inside the repository are
    // outputs that later runs (or other test files) may read: not attestable.
    // Rails: writes to git-ignored paths in the project's log/, tmp/,
    // storage/ and coverage/ are allowed (derived state no checkout has; a
    // later read of such a file that existed before the reading process
    // started is an input, and will not match a fresh checkout).
    let mut written: Vec<String> = o
        .writes
        .iter()
        .filter_map(|p| RepoPath::from_abs(&ctx.root, p).ok())
        .map(|p| p.as_str().to_owned())
        .collect();
    if adapter.name() == "rails" && !written.is_empty() {
        let scratch: Vec<Utf8PathBuf> = vci_adapter::RAILS_SCRATCH_DIRS
            .iter()
            .map(|d| project.dir.join(d))
            .collect();
        let candidates: Vec<String> = written
            .iter()
            .filter(|w| {
                let abs = ctx.root.join(w);
                scratch.iter().any(|d| abs.starts_with(d) && abs != *d)
            })
            .cloned()
            .collect();
        let ignored: BTreeSet<String> = checkout.git_ignored(&candidates).into_iter().collect();
        written.retain(|w| !ignored.contains(w));
    }
    // Tool caches under node_modules (Vite's dependency optimizer) are not
    // outputs of the test.
    written.retain(|w| !is_tool_cache_write(w));
    // Waived writes: neither inputs nor a refusal.
    let mut not_inputs: Vec<Utf8PathBuf> = Vec::new();
    if !written.is_empty() {
        let taint = format!("{WROTE_INSIDE_REPOSITORY_TAINT}{}", written.join(", "));
        if !waives(&taint) {
            return Err(format!(
                "wrote inside the repository: {}",
                written.join(", ")
            ));
        }
        waived.push(taint);
        not_inputs.extend(written.iter().map(|w| ctx.root.join(w)));
    }
    let result = o.result.clone().ok_or("no result")?;
    // No test ran: refused unless `result:no-tests` is waived (a file whose
    // tests are all gated by an environment variable); tests filtered out
    // of a run never are.
    let mut no_tests_waived = false;
    if !result.is_pass() && matches!(result.state.as_str(), "no-tests" | "filtered") {
        if result.state == "no-tests" && result.failed == 0 && waives(RESULT_NO_TESTS_TAINT) {
            waived.push(RESULT_NO_TESTS_TAINT.to_owned());
            no_tests_waived = true;
        } else {
            return Err(format!(
                "result {} ({} tests; no test ran or some were filtered out, so the run cannot vouch for the unit)",
                result.state, result.tests
            ));
        }
    }
    if result.state == "no-assertions" {
        return Err(format!(
            "result no-assertions ({} tests; a test that makes no assertion vouches for nothing)",
            result.tests
        ));
    }
    // Passed, with skipped tests: refused unless `result:skipped` is waived
    // (a failed result never is).
    let mut skips_waived = false;
    if !result.is_pass() && result.state == "passed" && result.failed == 0 && result.skipped > 0 {
        let taint = format!(
            "{RESULT_SKIPPED_TAINT}{} of {}",
            result.skipped, result.tests
        );
        if waives(&taint) {
            waived.push(taint);
            skips_waived = true;
        }
    }
    if !result.is_pass() && !skips_waived && !no_tests_waived {
        return Err(if result.skipped > 0 {
            format!(
                "result {} ({} failed, {} skipped or xfailed of {}; a skipped test did not run, so it cannot be vouched for elsewhere)",
                result.state, result.failed, result.skipped, result.tests
            )
        } else {
            format!(
                "result {} ({} failed of {})",
                result.state, result.failed, result.tests
            )
        });
    }
    if adapter.name() == "pytest" {
        // The test saw vci's own PYTHONPATH (the collector directory), which
        // differs between machines and is not what a plain run sees.
        if o.env_keys.contains("PYTHONPATH") {
            return Err("read PYTHONPATH, which vci sets to its collector".into());
        }
        // Externals built from the repository itself are not identified by
        // their version.
        match locked {
            Ok(Some(lock)) => {
                for (n, _) in &o.externals {
                    if let Some(why) = crate::externals::local_source_reason(lock, n) {
                        return Err(why);
                    }
                }
            }
            Ok(None) => {}
            Err(e) if !o.externals.is_empty() => return Err(format!("uv.lock: {e}")),
            Err(_) => {}
        }
    }
    if let Some(m) = collector_toolchain_mismatch(adapter.name(), o, versions) {
        return Err(m);
    }
    // Reads outside the repository: refused, unless `outside-repository` is
    // waived (then they are not hashed, only recorded in `waived`).
    for p in outside_repository(&ctx.root, o) {
        let taint = format!("{OUTSIDE_REPOSITORY_TAINT}{p}");
        if !waives(&taint) {
            return Err(format!("input outside the repository: {p}"));
        }
        not_inputs.push(p.to_owned());
        waived.push(taint);
    }
    let pruned;
    let o = if not_inputs.is_empty() {
        o
    } else {
        pruned = without_paths(o, &not_inputs);
        &pruned
    };
    let mut obs = observations_in(checkout, o, adapter.name(), adapter.tsconfig_is_input())?;
    // Rails' `rails_inputs`/`ignore_inputs` (2.7.36): what Rails reads while
    // it boots is left out (declared `[[inputs]]` are not).
    if !project.ignored_inputs.is_empty() {
        let mut matched: BTreeSet<&str> = BTreeSet::new();
        let mut files = BTreeSet::new();
        obs.retain(|(p, _)| match project.ignored_input(p.as_str()) {
            Some(g) => {
                matched.insert(g);
                if g != vci_adapter::AUTOLOAD_INPUTS {
                    files.insert(p.as_str().to_owned());
                }
                false
            }
            None => true,
        });
        if !matched.is_empty()
            && !project
                .ignored_noted
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            eprintln!("vci: {}", ignored_note(project, files.len(), &matched));
        }
    }
    obs.extend(expand_extra_inputs(
        &ctx.root,
        &project.dir,
        &declared,
        scratch,
    )?);
    let mut platform_specific: Vec<String> = Vec::new();
    for p in &o.platform_files {
        let rp = RepoPath::from_abs(&ctx.root, p)
            .map_err(|_| format!("platform-specific file outside the repository: {p}"))?;
        platform_specific.push(rp.as_str().to_owned());
    }
    platform_specific.sort();
    let fenv = project.file_env(&file.project_rel);
    let keys = fenv.hashed_keys(child, &o.env_keys);
    let mut externals: Vec<External> = o
        .externals
        .iter()
        .map(|(n, v)| External {
            name: n.clone(),
            version: v.clone(),
        })
        .collect();
    externals.push(External {
        name: crate::ctx::CONFIG_EXTERNAL.to_owned(),
        version: project.config_hash.clone(),
    });
    let manifest = checkout
        .capture(&obs, externals, &keys, lookup(child))
        .map_err(|e| format!("capturing inputs: {e}"))?;
    manifest
        .check_case_collisions()
        .map_err(|e| format!("inputs: {e}"))?;
    // Paths the unit's source names outside its package directories must be
    // recorded inputs (declared with `[[inputs]]`), unless the policy waives
    // `cargo:undeclared-reads` (the path is then recorded as waived).
    for (p, seen) in &o.path_refs {
        let why = match RepoPath::from_abs(&ctx.root, p) {
            Err(_) => format!("its source refers to {p}, outside the repository ({seen})"),
            Ok(rp) if !covered(&ctx.root, &manifest, &rp) => format!(
                "its source refers to {} ({seen}), which is not an input; declare it in vci.toml ([[inputs]] match = [{:?}], extra = [...])",
                rp.as_str(),
                file.project_rel
            ),
            Ok(_) => continue,
        };
        let taint = format!("{}: {why}", vci_adapter::CARGO_UNDECLARED_TAINT);
        if !waives(&taint) {
            return Err(why);
        }
        waived.push(taint);
    }
    let gm = global_manifest_in(checkout, project, child, &file.abs)
        .map_err(|e| format!("global inputs: {e:#}"))?;
    match pre_global.get(file.test_id.as_str()) {
        Some(Ok(root)) if *root == gm.root() => {}
        Some(Ok(_)) => return Err("global inputs changed during the run".into()),
        Some(Err(e)) => return Err(format!("global inputs before the run: {e}")),
        None => return Err("no pre-run global snapshot".into()),
    }
    // What the manifest leaves out of its listings, plus what git ignores
    // in them now: a cache a test wrote into a listed directory during the
    // run (`__pycache__`) is not a change to the listing (since 2.0.3).
    let mut excluded = manifest.excluded_children();
    for p in ignored_listing_children(checkout, &manifest) {
        if let (Some(parent), Some(name)) = (p.parent(), p.components().last()) {
            excluded.entry(parent).or_default().insert(name.to_owned());
        }
    }
    for e in &manifest.entries {
        pre_stat
            .unchanged_excluding(e, excluded.get(&e.path))
            .map_err(|r| r.to_string())?;
    }
    for e in &gm.entries {
        pre_stat.unchanged(e).map_err(|r| r.to_string())?;
    }
    let core = Predicate {
        tool_version: TOOL_VERSION.to_owned(),
        adapter: adapter.name().to_owned(),
        test_id: file.test_id.as_str().to_owned(),
        argv: adapter.canonical_argv(&project.rel, &file.project_rel),
        repo_id: base.repo_id.clone(),
        commit: base.commit.clone(),
        tree_dirty: base.dirty,
        tree: base.tree.clone(),
        toolchain: toolchain_for(adapter.name(), versions),
        global_input_root: gm.root(),
        input_root: manifest.root(),
        manifest: None,
        manifest_ref: Some(manifest.root()),
        global_manifest: gm,
        result,
        tainted: vec![],
        issued_at: rfc3339(base.issued),
        expires_at: rfc3339(base.issued + base.ttl),
    };
    Ok(Attestable {
        predicate: VciPredicate {
            core,
            env_config_digest: fenv.digest(),
            project_dir: project.rel.clone(),
            runner_project: file.runner_project.clone(),
            project_name: project.name.clone(),
            platform_specific,
            arch_specific: o.arch_specific.iter().cloned().collect(),
            waived,
            cfg_predicates: o.cfg_predicates.iter().cloned().collect(),
            declared_inputs: declared,
            env_set: fenv.set.keys().cloned().collect(),
            rails_inputs: project
                .rails_inputs
                .map(|m| m.as_str().to_owned())
                .unwrap_or_default(),
            ignored_inputs: project.ignored_inputs.clone(),
        },
        manifest,
    })
}

/// `vci run`'s line (once per project) saying which inputs it leaves out:
/// `files` paths (the autoload lookup records aside) matched the globs of
/// [`Project::ignored_inputs`] in `matched`.
fn ignored_note(project: &Project, files: usize, matched: &BTreeSet<&str>) -> String {
    // In the list's order.
    let names: Vec<&str> = project
        .ignored_inputs
        .iter()
        .map(String::as_str)
        .filter(|g| matched.contains(g))
        .collect();
    let label = if project.name.is_empty() {
        String::new()
    } else {
        format!("{}: ", project.name)
    };
    match project.rails_inputs {
        Some(crate::config::RailsInputs::Loose) => format!(
            "{label}rails inputs are loose: {files} boot-time files are not inputs ({}); set rails_inputs = \"strict\" to record them",
            names.join(", ")
        ),
        _ => format!(
            "{label}ignore_inputs: {files} files are not inputs ({})",
            names.join(", ")
        ),
    }
}

/// Directory names never walked for declared inputs (the tree snapshot does
/// not track them either).
const EXTRA_SKIP: &[&str] = &[".git", "node_modules", ".venv"];

/// Observations for `[[inputs]] extra` globs (relative to `project_dir`):
/// a glob without wildcards names a file (read), a directory (walked) or a
/// missing path (probe); otherwise the directory before the first wildcard
/// is walked, every directory in it is a listing (so a new matching file is
/// noticed) and every matching file a read.
pub fn expand_extra_inputs(
    root: &Utf8Path,
    project_dir: &Utf8Path,
    globs: &[String],
    scratch: &[Utf8PathBuf],
) -> Result<Vec<(RepoPath, Observation)>, String> {
    let mut out: Vec<(Utf8PathBuf, Observation)> = Vec::new();
    for g in globs {
        let comps: Vec<&str> = g
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .collect();
        let fixed: Vec<&str> = comps
            .iter()
            .take_while(|c| !c.contains(['*', '?', '[', '{']))
            .copied()
            .collect();
        let base = fixed.iter().fold(project_dir.to_owned(), |p, c| p.join(c));
        let literal = fixed.len() == comps.len();
        let meta = std::fs::symlink_metadata(&base);
        match meta {
            Err(_) => out.push((base, Observation::Probe)),
            Ok(m) if !m.is_dir() => out.push((base, Observation::Read)),
            Ok(_) => {
                let mut stack = vec![base.clone()];
                while let Some(d) = stack.pop() {
                    if scratch.iter().any(|s| d.starts_with(s)) {
                        continue;
                    }
                    let inside = d.strip_prefix(root).unwrap_or(&d);
                    if inside
                        .components()
                        .any(|c| EXTRA_SKIP.contains(&c.as_str()))
                    {
                        return Err(format!(
                            "declared input {g:?} reaches {d}, which vci does not hash"
                        ));
                    }
                    out.push((d.clone(), Observation::ReadDir));
                    let rd = d
                        .read_dir_utf8()
                        .map_err(|e| format!("declared input {g:?}: listing {d}: {e}"))?;
                    for ent in rd.flatten() {
                        let p = ent.path().to_owned();
                        let is_dir = ent.file_type().map(|t| t.is_dir()).unwrap_or(false);
                        if is_dir {
                            if EXTRA_SKIP.contains(&ent.file_name()) {
                                continue;
                            }
                            stack.push(p);
                            continue;
                        }
                        let rel = p
                            .strip_prefix(project_dir)
                            .map(|r| r.as_str())
                            .unwrap_or("");
                        if literal || crate::util::glob_match(g, rel) {
                            out.push((p, Observation::Read));
                        }
                    }
                }
            }
        }
    }
    out.into_iter()
        .map(|(p, o)| {
            RepoPath::from_abs(root, &p)
                .map(|rp| (rp, o))
                .map_err(|_| format!("declared input {p} is outside the repository"))
        })
        .collect()
}

/// Is `rp` covered by the manifest: recorded itself (a directory listing
/// only when everything below it is recorded too), or absent with its
/// parent's listing recorded (so creating it is noticed)?
fn covered(root: &Utf8Path, m: &InputManifest, rp: &RepoPath) -> bool {
    use vci_core::EntryKind;
    let kinds: BTreeMap<&str, EntryKind> = m
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e.kind))
        .collect();
    let abs = rp.to_abs(root);
    match kinds.get(rp.as_str()) {
        Some(EntryKind::DirListing) => {
            let mut stack = vec![abs];
            while let Some(d) = stack.pop() {
                let Ok(rd) = d.read_dir_utf8() else {
                    return false;
                };
                for ent in rd.flatten() {
                    let Ok(r) = RepoPath::from_abs(root, ent.path()) else {
                        return false;
                    };
                    let is_dir = ent.file_type().map(|t| t.is_dir()).unwrap_or(false);
                    match kinds.get(r.as_str()) {
                        Some(EntryKind::DirListing) if is_dir => stack.push(ent.path().to_owned()),
                        Some(_) if !is_dir => {}
                        _ => return false,
                    }
                }
            }
            true
        }
        // Build output is never an input.
        Some(EntryKind::Excluded) => false,
        Some(_) => true,
        None => {
            !abs.exists()
                && rp
                    .parent()
                    .is_some_and(|p| kinds.get(p.as_str()) == Some(&EntryKind::DirListing))
        }
    }
}

/// Recorded inputs that git ignores: a fresh checkout (CI) does not have
/// them, so the attestation will not match there.
/// A Rails credentials key file (`config/master.key`,
/// `config/credentials/<env>.key`), relative to the repository root.
fn is_rails_key_file(p: &str) -> bool {
    let in_config =
        |rest: &str| p == format!("config/{rest}") || p.ends_with(&format!("/config/{rest}"));
    in_config("master.key")
        || p.rsplit_once("/").is_some_and(|(dir, f)| {
            f.ends_with(".key")
                && (dir == "config/credentials" || dir.ends_with("/config/credentials"))
        })
}

/// The git-ignored children of every directory `observed` lists (a `ReadDir`,
/// or a `Read` of a directory), as `Exclude` observations: build outputs,
/// caches and editor files (`dist/`, `node_modules/`, `__pycache__/`,
/// `.DS_Store`) that a fresh checkout does not have and every machine has
/// differently, so that a listing records what the repository holds and an
/// attestation made on one machine verifies on another (since 2.0.3). A
/// child that is itself observed stays an input of its own.
pub(crate) fn ignored_children(
    checkout: &Checkout<'_>,
    observed: &[(RepoPath, Observation)],
) -> Vec<(RepoPath, Observation)> {
    let seen: BTreeSet<&str> = observed.iter().map(|(p, _)| p.as_str()).collect();
    let mut candidates: Vec<String> = Vec::new();
    for (p, o) in observed {
        if !matches!(o, Observation::ReadDir | Observation::Read) {
            continue;
        }
        let Some(names) = checkout.child_names(p) else {
            continue;
        };
        for name in names.iter() {
            let child = if p.is_root() {
                name.clone()
            } else {
                format!("{}/{name}", p.as_str())
            };
            if !seen.contains(child.as_str()) {
                candidates.push(child);
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    checkout
        .git_ignored(&candidates)
        .into_iter()
        .filter_map(|c| RepoPath::new(&c).ok())
        .map(|p| (p, Observation::Exclude))
        .collect()
}

/// The git-ignored children, present now, of every directory `m` records a
/// listing of, minus `m`'s own entries: what a verification leaves out of
/// the listings it rehashes (see [`ignored_children`]).
pub(crate) fn ignored_listing_children(
    checkout: &Checkout<'_>,
    m: &InputManifest,
) -> Vec<RepoPath> {
    let seen: BTreeSet<&str> = m.entries.iter().map(|e| e.path.as_str()).collect();
    let mut candidates: Vec<String> = Vec::new();
    for e in &m.entries {
        if e.kind != vci_core::EntryKind::DirListing {
            continue;
        }
        let Some(names) = checkout.child_names(&e.path) else {
            continue;
        };
        for name in names.iter() {
            let child = if e.path.is_root() {
                name.clone()
            } else {
                format!("{}/{name}", e.path.as_str())
            };
            if !seen.contains(child.as_str()) {
                candidates.push(child);
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    checkout
        .git_ignored(&candidates)
        .into_iter()
        .filter_map(|c| RepoPath::new(&c).ok())
        .collect()
}

fn ignored_inputs(checkout: &Checkout<'_>, m: &InputManifest) -> Vec<String> {
    let paths: Vec<String> = m
        .entries
        .iter()
        .filter(|e| {
            !matches!(
                e.kind,
                vci_core::EntryKind::Absent | vci_core::EntryKind::Excluded
            ) && !e.path.is_root()
        })
        .map(|e| e.path.as_str().to_owned())
        .collect();
    checkout.git_ignored(&paths)
}

/// The repo-relative `paths` git ignores (`git check-ignore`); any error
/// means none (so nothing is treated as ignored).
pub(crate) fn git_ignored(root: &Utf8Path, paths: &[String]) -> Vec<String> {
    git_check_ignore(root, paths).0
}

/// [`git_ignored`], and whether git answered (exited 0 or 1: some or none
/// ignored); an answer git did not give is not one to keep.
pub(crate) fn git_check_ignore(root: &Utf8Path, paths: &[String]) -> (Vec<String>, bool) {
    use std::io::Write as _;
    if paths.is_empty() {
        return (vec![], true);
    }
    let child = std::process::Command::new("git")
        .args(["-C", root.as_str(), "check-ignore", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        return (vec![], false);
    };
    if let Some(mut i) = child.stdin.take() {
        let _ = i.write_all(paths.join("\n").as_bytes());
        let _ = i.write_all(b"\n");
    }
    let Ok(out) = child.wait_with_output() else {
        return (vec![], false);
    };
    let lines = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    (lines, matches!(out.status.code(), Some(0 | 1)))
}

/// How [`check_one`] reads the checkout: directly, or (once a project's
/// tests have finished, when the tree no longer changes) through caches
/// shared by every unit of the run, so that a path's contents, a
/// directory's children and git's answer about a path are read once
/// however many units name them. Nothing invalidates the caches: each unit
/// still compares its entries with the snapshot taken before the run
/// ([`TreeStat`]) after its manifest is captured, so a value read once is
/// vouched for by every unit that uses it, as one read per unit was.
pub(crate) struct Checkout<'a> {
    root: &'a Utf8Path,
    cache: Option<Caches>,
}

struct Caches {
    files: vci_core::CheckoutCache,
    /// `read_dir` of a directory (followed if a symlink, as [`ignored_children`]
    /// lists it): the UTF-8 names, `None` when it cannot be listed.
    children: std::sync::Mutex<std::collections::HashMap<Utf8PathBuf, Option<Arc<Vec<String>>>>>,
    /// `git check-ignore` per repo-relative path.
    ignored: std::sync::Mutex<std::collections::HashMap<String, bool>>,
    /// The paths git tracks (`git ls-files`), read once: never ignored, so
    /// never asked about (2.7.32: every unit's warnings asked about its
    /// 150 own input paths, one `git check-ignore` per unit, 36
    /// thread-seconds of a full vex run).
    tracked: std::sync::OnceLock<Option<std::collections::HashSet<String>>>,
}

fn locked<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl<'a> Checkout<'a> {
    /// Every read goes to the checkout (and to git).
    pub(crate) fn direct(root: &'a Utf8Path) -> Self {
        Checkout { root, cache: None }
    }

    /// Every path read once, for a checkout that does not change while this
    /// is used.
    pub(crate) fn cached(root: &'a Utf8Path) -> Self {
        Checkout {
            root,
            cache: Some(Caches {
                files: vci_core::CheckoutCache::new(root),
                children: Default::default(),
                ignored: Default::default(),
                tracked: Default::default(),
            }),
        }
    }

    /// [`git_ignored`]: the `paths` git ignores, in their order.
    pub(crate) fn git_ignored(&self, paths: &[String]) -> Vec<String> {
        let Some(c) = &self.cache else {
            return git_ignored(self.root, paths);
        };
        let tracked = c.tracked.get_or_init(|| {
            let out = std::process::Command::new("git")
                .args(["-C", self.root.as_str(), "ls-files", "-z"])
                .stderr(std::process::Stdio::null())
                .output()
                .ok()?;
            out.status.success().then(|| {
                out.stdout
                    .split(|b| *b == 0)
                    .filter(|p| !p.is_empty())
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect()
            })
        });
        let mut ask: Vec<String> = {
            let known = locked(&c.ignored);
            paths
                .iter()
                .filter(|p| !known.contains_key(p.as_str()))
                .filter(|p| !tracked.as_ref().is_some_and(|t| t.contains(p.as_str())))
                .cloned()
                .collect()
        };
        ask.sort();
        ask.dedup();
        let (found, answered) = if ask.is_empty() {
            (vec![], true)
        } else {
            git_check_ignore(self.root, &ask)
        };
        if !answered {
            // git stopped before answering about every path (it exits 128 on
            // a path inside a submodule or beyond a symbolic link, after
            // printing what it found before it): nothing is kept, and the
            // answer is the one git gives for `paths` alone, as before 2.1,
            // whatever other units asked first.
            return if ask == paths {
                found
            } else {
                git_ignored(self.root, paths)
            };
        }
        let found: BTreeSet<&str> = found.iter().map(String::as_str).collect();
        let mut known = locked(&c.ignored);
        for p in &ask {
            known.insert(p.clone(), found.contains(p.as_str()));
        }
        paths
            .iter()
            .filter(|p| known.get(p.as_str()).copied().unwrap_or(false))
            .cloned()
            .collect()
    }

    /// The UTF-8 names in the directory `p` (`read_dir`, which follows a
    /// symlink); `None` when it cannot be listed.
    fn child_names(&self, p: &RepoPath) -> Option<Arc<Vec<String>>> {
        let abs = p.to_abs(self.root);
        let read = |abs: &Utf8Path| {
            std::fs::read_dir(abs).ok().map(|rd| {
                Arc::new(
                    rd.flatten()
                        .filter_map(|e| e.file_name().into_string().ok())
                        .collect::<Vec<_>>(),
                )
            })
        };
        let Some(c) = &self.cache else {
            return read(&abs);
        };
        if let Some(n) = locked(&c.children).get(&abs) {
            return n.clone();
        }
        let n = read(&abs);
        locked(&c.children).insert(abs, n.clone());
        n
    }

    /// [`InputManifest::capture_with_env`] (through the cache when there is
    /// one).
    fn capture<F>(
        &self,
        observed: &[(RepoPath, Observation)],
        externals: Vec<External>,
        env_keys: &[String],
        env: F,
    ) -> Result<InputManifest, vci_core::ManifestError>
    where
        F: Fn(&str) -> Option<std::ffi::OsString> + Sync,
    {
        match &self.cache {
            None => InputManifest::capture_with_env(self.root, observed, externals, env_keys, env),
            Some(c) => InputManifest::capture_cached(&c.files, observed, externals, env_keys, env),
        }
    }
}

struct PredicateBase {
    repo_id: String,
    commit: String,
    dirty: bool,
    /// HEAD's tree, when the working tree is clean.
    tree: Option<String>,
    issued: i64,
    ttl: i64,
}

/// The absolute paths CLI unit arguments name (a cargo `<dir>#<target>`
/// names `<dir>`), or `None` when one cannot be resolved (then every project
/// is listed and [`resolve_files`] reports the problem).
fn unit_paths(args: &[String]) -> Option<Vec<camino::Utf8PathBuf>> {
    let cwd = crate::ctx::cwd().ok()?;
    args.iter()
        .map(|a| {
            cwd.join(a).canonicalize_utf8().ok().or_else(|| {
                let (dir, _) = a.rsplit_once('#')?;
                let dir = if dir.is_empty() { "." } else { dir };
                cwd.join(dir).canonicalize_utf8().ok()
            })
        })
        .collect()
}

/// Resolve CLI file arguments (relative to cwd) to indexes into `files`
/// (every project that lists the file).
fn resolve_files(args: &[String], files: &[TestFile]) -> Result<BTreeSet<usize>> {
    let cwd = crate::ctx::cwd()?;
    let mut out = BTreeSet::new();
    for a in args {
        // Cargo units: `<package dir>#<target>`, or a package dir for all of
        // its units.
        let hits: Vec<usize> = match cwd.join(a).canonicalize_utf8() {
            Ok(abs) => {
                let exact: Vec<usize> = files
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| f.abs == abs)
                    .map(|(i, _)| i)
                    .collect();
                if exact.is_empty() && abs.is_dir() {
                    let prefix = format!("{abs}#");
                    files
                        .iter()
                        .enumerate()
                        .filter(|(_, f)| f.abs.as_str().starts_with(&prefix))
                        .map(|(i, _)| i)
                        .collect()
                } else {
                    exact
                }
            }
            Err(e) => match a.rsplit_once('#') {
                Some((dir, target)) => {
                    let dir = if dir.is_empty() { "." } else { dir };
                    let abs = cwd
                        .join(dir)
                        .canonicalize_utf8()
                        .with_context(|| format!("test {a}"))?;
                    let want = format!("{abs}#{target}");
                    files
                        .iter()
                        .enumerate()
                        .filter(|(_, f)| f.abs.as_str() == want)
                        .map(|(i, _)| i)
                        .collect()
                }
                None => return Err(e).with_context(|| format!("test file {a}")),
            },
        };
        if hits.is_empty() {
            bail!("{a} is not a test file of any project (not listed by the test runner)");
        }
        out.extend(hits);
    }
    Ok(out)
}

/// `vci run <units>` when some projects that could hold a requested unit
/// (`unlisted`: label, listing error) could not be listed: when every
/// requested unit resolved (`resolved`) to a unit of a project that was
/// listed, the run goes on without the others (one warning each); when one
/// did not, the error also names the listing failures, which are likely
/// why.
fn settle_unlisted(
    resolved: Result<BTreeSet<usize>>,
    unlisted: &[(String, anyhow::Error)],
) -> Result<(BTreeSet<usize>, Vec<String>)> {
    match resolved {
        Ok(selected) => {
            let warnings = unlisted
                .iter()
                .map(|(label, e)| {
                    format!(
                        "listing the test files of {label} failed: {e:#}; none of the requested units is in it"
                    )
                })
                .collect();
            Ok((selected, warnings))
        }
        Err(e) if unlisted.is_empty() => Err(e),
        Err(e) => {
            let why: Vec<String> = unlisted
                .iter()
                .map(|(label, e)| format!("listing the test files of {label} failed: {e:#}"))
                .collect();
            bail!(
                "{e:#} (it may be in a project that could not be listed: {})",
                why.join("; ")
            )
        }
    }
}

/// How [`run_units`] signs.
pub enum Signing<'a> {
    /// An SSH key: `--key`, else discovered ([`keys::discover`]).
    Key(Option<&'a Utf8Path>),
    /// Keyless, with the job's OIDC token (`--oidc`).
    Oidc(&'a KeylessSigner),
}

/// A resolved signer.
enum Signer<'a> {
    /// The key, and it read once for every signature of the run.
    Ssh(keys::SigningKey, vci_attest::SshSigner),
    Keyless(&'a KeylessSigner),
}

impl Signer<'_> {
    /// The signer id in store keys.
    fn signer_id(&self) -> String {
        match self {
            Signer::Ssh(k, _) => k.signer_id(),
            Signer::Keyless(k) => k.signer_id(),
        }
    }

    /// Sign `stmt`; the bytes to store (the envelope JSON, plus the
    /// Sigstore bundle's material for a keyless signature).
    fn sign(&self, stmt: &Statement) -> Result<Vec<u8>> {
        match self {
            Signer::Ssh(key, signer) => signer
                .sign_statement(stmt)
                .map(|env| env.to_json())
                .with_context(|| format!("signing with {}", key.path)),
            Signer::Keyless(k) => k
                .sign_statement(stmt)
                .map(|(env, m)| vci_attest::keyless::to_stored_json(&env, &m))
                .context("signing keylessly (OIDC)"),
        }
    }

    /// Sign a format-3 statement's bytes exactly as they are (STORE-V2
    /// section 1.1: the writer's bytes are what the signature covers and
    /// what the store holds) and frame the signature with the unit's
    /// descriptor (section 1.2): the record before its text encoding.
    fn sign_frame(&self, statement: Vec<u8>, descriptor: Vec<u8>) -> Result<Frame> {
        let framed = |r: Result<Frame, vci_core::FrameError>| {
            r.map_err(|e| anyhow::anyhow!("framing the signature: {e}"))
        };
        match self {
            Signer::Ssh(key, signer) => {
                let env = signer
                    .sign_payload(&statement)
                    .with_context(|| format!("signing with {}", key.path))?;
                framed(Frame::from_envelope(&env, descriptor))
            }
            Signer::Keyless(k) => {
                let (env, m) = k
                    .sign_payload(&statement)
                    .context("signing keylessly (OIDC)")?;
                framed(Frame::from_keyless(&env, &m, descriptor))
            }
        }
    }
}

/// `--oidc [INSTANCE]`: a keyless signer for the job's identity (fails
/// before anything runs when the job has no OIDC token).
pub fn keyless_signer(instance: &str) -> Result<KeylessSigner> {
    let i = vci_attest::keyless::Instance::named(instance).map_err(anyhow::Error::msg)?;
    let k = KeylessSigner::new(i).context("--oidc")?;
    eprintln!(
        "vci: signing keylessly as {} (Sigstore: {}, {})",
        k.identity().describe(),
        k.instance().fulcio,
        k.instance().tsa
    );
    Ok(k)
}

/// Which units [`run_units`] runs.
pub enum Selection {
    /// `vci run`'s arguments (paths relative to the current directory,
    /// `<package dir>#<target>`); empty: every unit of every project.
    Args(Vec<String>),
    /// Per project (index into the configuration's projects): `None` runs
    /// every unit of the project, `Some(ids)` the units with these test ids
    /// (each must be listed by the project). Projects not named are not run.
    Units(BTreeMap<usize, Option<BTreeSet<String>>>),
}

/// A unit [`run_units`] attested.
#[derive(Debug, Clone)]
pub struct AttestedUnit {
    pub test_id: String,
    /// `[[projects]]` name; empty in the single-project form.
    pub project: String,
    /// Whether its attestation was stored: false when the run only signed
    /// ([`StoreMode::SignOnly`]).
    pub stored: bool,
}

/// What [`run_units`] did.
#[derive(Default)]
pub struct RunOutcome {
    /// Non-zero when a test failed (refusals to attest do not count).
    pub exit: i32,
    pub attested: Vec<AttestedUnit>,
    /// Problems that did not stop the other projects or units (a project
    /// that could not be listed or run, a unit that could not be signed or
    /// stored), in order. Once a test has run, [`run_units`] reports a
    /// problem here instead of failing, so what it already signed and
    /// stored is always in [`RunOutcome::attested`].
    pub errors: Vec<String>,
    /// Units signed but not stored because the store cannot be used (it
    /// could not be selected, opened or reached, is not set up, or refuses
    /// this writer), in order. Like refusals, and unlike
    /// [`RunOutcome::errors`], they leave `vci run`'s exit code to the
    /// tests (docs/STORE-BACKENDS.md section 10); `vci ci` reports them
    /// with the errors.
    pub store_failures: Vec<String>,
    /// Projects (indexes into the configuration's projects) whose tests did
    /// not run because listing or starting them failed: no verdict, nothing
    /// attested. `vci ci` runs them without attesting.
    pub unrun: BTreeSet<usize>,
}

pub fn run(args: RunArgs) -> Result<i32> {
    let (repo, root) = open_repo()?;
    let config = working_tree_config(&root)?;
    for w in config.warnings(crate::config::CONFIG_FILE) {
        eprintln!("vci: warning: {w}");
    }
    let keyless = args.oidc.as_deref().map(keyless_signer).transpose()?;
    let signing = match &keyless {
        Some(k) => Signing::Oidc(k),
        None => Signing::Key(args.key.as_deref()),
    };
    let out = run_units(
        repo,
        root,
        config,
        Selection::Args(args.files),
        signing,
        &args.ttl,
        args.summary.as_deref(),
        StoreMode::Write,
    )?;
    if !out.errors.is_empty() {
        bail!(
            "{} problem(s) during the run (the rest ran): {}",
            out.errors.len(),
            out.errors.join("; ")
        );
    }
    Ok(out.exit)
}

/// `vci run`'s work, for `vci run` and `vci ci --key`: run `selection` with
/// the collectors (one process per unit where the adapter does so), record
/// each unit's inputs, and sign and store an attestation for every unit that
/// passed and is provably attestable. `config` decides the projects (`vci
/// run`: the working tree's; `vci ci`: the one its plan was made from).
/// `mode` says whether the attestations are stored ([`StoreMode`]).
#[allow(clippy::too_many_arguments)]
pub fn run_units(
    repo: vci_git::Repo,
    root: Utf8PathBuf,
    config: crate::config::Config,
    selection: Selection,
    signing: Signing<'_>,
    ttl_arg: &str,
    summary: Option<&Utf8Path>,
    mode: StoreMode,
) -> Result<RunOutcome> {
    let ttl = parse_duration(ttl_arg).context("--ttl")?;
    let ctx = Ctx::new(repo, root.clone(), config)?;
    let key = match signing {
        Signing::Key(k) => {
            let key = keys::discover(k, &root)?;
            // Signatures by the key the signer id names, and no other: a
            // private key whose .pub is another key's goes to ssh-keygen,
            // which refuses it, instead of being stored under that other
            // key's signer id.
            let signer = vci_attest::SshSigner::load_for(&key.path, &key.blob);
            Signer::Ssh(key, signer)
        }
        Signing::Oidc(k) => Signer::Keyless(k),
    };
    let signer = key.signer_id();

    let base = PredicateBase {
        repo_id: ctx
            .repo
            .repo_id()
            .context("repo id (needs at least one commit)")?,
        commit: ctx.repo.head_commit()?,
        dirty: ctx.repo.is_dirty()?,
        tree: None,
        issued: now_unix(),
        ttl,
    };
    let base = PredicateBase {
        tree: (!base.dirty).then(|| ctx.repo.head_tree().ok()).flatten(),
        ..base
    };
    let children: Vec<ChildEnvMap> = ctx.projects.iter().map(|p| p.child_env()).collect();
    let locks: Vec<_> = ctx
        .projects
        .iter()
        .map(|p| crate::externals::uv_lock_packages(&p.dir, &ctx.root))
        .collect();
    // With explicit units, only projects whose directory can hold one of
    // them are listed (a project only ever lists units below its own
    // directory), so another project's missing toolchain does not matter.
    // Projects nested in each other are all listed, so a unit two projects
    // list is still found ambiguous.
    let wanted = match &selection {
        Selection::Args(a) if !a.is_empty() => unit_paths(a),
        _ => None,
    };
    let mut files: Vec<TestFile> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut store_failures: Vec<String> = Vec::new();
    let mut unrun: BTreeSet<usize> = BTreeSet::new();
    let listing: Vec<bool> = ctx
        .projects
        .iter()
        .enumerate()
        .map(|(i, p)| {
            if let Selection::Units(u) = &selection
                && !u.contains_key(&i)
            {
                return false;
            }
            if let Some(paths) = &wanted {
                let dir = p
                    .adapter
                    .project_dir()
                    .canonicalize_utf8()
                    .unwrap_or_else(|_| p.adapter.project_dir().to_owned());
                if !paths.iter().any(|a| a.starts_with(&dir)) {
                    return false;
                }
            }
            true
        })
        .collect();
    // Every project is listed at once (listing shells out), in order after.
    let listings: Vec<Option<Result<Vec<TestFile>>>> = std::thread::scope(|s| {
        let handles: Vec<_> = ctx
            .projects
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let (listing, children) = (&listing, &children);
                s.spawn(move || {
                    listing[i].then(|| {
                        p.adapter
                            .list_test_files(&children[i].to_child_env())
                            .map_err(anyhow::Error::from)
                            .and_then(|l| p.test_files(i, l))
                    })
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
            .collect()
    });
    // `vci run <units>`: projects that could not be listed, settled once the
    // units are resolved (see [`settle_unlisted`]).
    let mut unlisted: Vec<(String, anyhow::Error)> = Vec::new();
    for (i, listed) in listings.into_iter().enumerate() {
        let Some(listed) = listed else { continue };
        let label = ctx.projects[i].label();
        match listed {
            Ok(f) => files.extend(f),
            // `vci ci`: one project that cannot be listed does not stop the
            // others from being attested (it runs without attesting).
            Err(e) if matches!(selection, Selection::Units(_)) => {
                let msg = format!("listing the test files of {label}: {e:#}");
                eprintln!("vci: error: {msg}");
                errors.push(msg);
                unrun.insert(i);
            }
            Err(e) if matches!(&selection, Selection::Args(a) if !a.is_empty()) => {
                unlisted.push((label, e));
            }
            Err(e) => return Err(e.context(format!("listing the test files of {label}"))),
        }
    }
    mark_cross_project_ambiguity(&mut files);
    let selected: BTreeSet<usize> = match &selection {
        Selection::Args(a) if a.is_empty() => (0..files.len()).collect(),
        Selection::Args(a) => {
            let (selected, warnings) = settle_unlisted(resolve_files(a, &files), &unlisted)?;
            for w in warnings {
                eprintln!("vci: warning: {w}");
            }
            selected
        }
        Selection::Units(u) => {
            let listed: BTreeMap<usize, Option<BTreeSet<String>>> = u
                .iter()
                .filter(|(i, _)| !unrun.contains(i))
                .map(|(i, ids)| (*i, ids.clone()))
                .collect();
            select_units(&ctx, &listed, &files)?
        }
    };
    if selected.is_empty() {
        if let Selection::Units(_) = selection {
            return Ok(RunOutcome {
                exit: 0,
                attested: vec![],
                errors,
                store_failures,
                unrun,
            });
        }
        bail!("no test files to run");
    }
    let involved: BTreeSet<usize> = selected.iter().map(|&i| files[i].project).collect();
    // The longest `max_ttl` of the involved projects: how long a record of
    // this run can live, which a store that keeps deletion records for its
    // replicas purges them after (STORE-V2 section 2.1).
    let mut max_ttl_secs: i64 = 0;
    for &pi in &involved {
        let p = &ctx.projects[pi];
        let max = p.policy.max_ttl_secs()?;
        if ttl > max {
            bail!(
                "--ttl {} exceeds policy.max_ttl {} of {}; such attestations would be rejected",
                ttl_arg,
                p.policy.max_ttl,
                p.label()
            );
        }
        max_ttl_secs = max_ttl_secs.max(max);
    }
    for &i in &selected {
        let f = &files[i];
        for s in ctx.projects[f.project]
            .file_env(&f.project_rel)
            .secret_like()
        {
            eprintln!(
                "vci: warning: hashed env var {s} looks like a secret; its hash is published in attestations. Put it in [env] ignore instead."
            );
        }
    }
    // The toolchain of every involved project (probed at once; Rails also
    // boots the application, which must report the toolchain read without
    // booting it), checked and reported in order.
    let probed: Vec<(usize, Result<vci_adapter::ToolVersions>, Vec<String>)> =
        std::thread::scope(|s| {
            let handles: Vec<_> = involved
                .iter()
                .map(|&pi| {
                    let (p, env) = (&ctx.projects[pi], children[pi].to_child_env());
                    s.spawn(move || {
                        let v = p
                            .adapter
                            .tool_versions_with_env(&env)
                            .and_then(|v| p.adapter.check_run_environment(&env).map(|()| v))
                            .with_context(|| format!("tool versions of {}", p.label()));
                        let warnings = if v.is_ok() {
                            p.adapter.warnings(&env)
                        } else {
                            vec![]
                        };
                        (pi, v, warnings)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
                .collect()
        });
    let mut versions = BTreeMap::new();
    for (pi, v, warnings) in probed {
        versions.insert(pi, v?);
        for w in warnings {
            eprintln!("vci: warning: {w}");
        }
    }

    // Before the run: tree metadata and global inputs (build output
    // directories such as Cargo's target dir are not inputs).
    let scratch: Vec<Utf8PathBuf> = involved
        .iter()
        .flat_map(|&pi| {
            ctx.projects[pi]
                .adapter
                .scratch_dirs_with_env(&children[pi].to_child_env())
        })
        .filter(|d| d.starts_with(&root))
        .collect();
    let pre_stat = TreeStat::snapshot_skipping(&root, &scratch)?;
    let mut pre_global = BTreeMap::new();
    for &i in &selected {
        let f = &files[i];
        let r = global_manifest(&ctx, &ctx.projects[f.project], &children[f.project], &f.abs)
            .map(|m| m.root())
            .map_err(|e| format!("{e:#}"));
        pre_global.insert(f.test_id.as_str().to_owned(), r);
    }

    let store = crate::store::for_repo(&ctx.repo);
    let store = &*store;
    store.set_max_ttl(std::time::Duration::from_secs(
        u64::try_from(max_ttl_secs).unwrap_or(0),
    ));
    // What this run writes: format-3 records with the run's objects
    // (STORE-V2 section 1.4) on a store that keeps objects, else format 1
    // as 2.8 wrote (`[store] record_format = 1`, or a store without them).
    let settings = RecordSettings::of(&ctx.repo);
    let format3 = settings.format3(store);
    let selected_ids: Vec<&str> = selected
        .iter()
        .map(|&i| files[i].test_id.as_str())
        .collect();
    // [lazy metadata] Supersession below reads these units' stored
    // attestations: fetch the values not fetched yet, in one batch (best
    // effort: one not fetched is kept, never superseded).
    let _ = store.prefetch(Prefetch::Units {
        test_ids: &selected_ids,
        choose: None,
    });
    // What the units took last time (any signer's newest attestation), to
    // hand the runner the longest first; with it, on a store with columns,
    // every stored record's columns and the platform of every hdr they
    // name, for supersession (one listing, one columns round trip and one
    // objects read for the run, not one per unit).
    let t = std::time::Instant::now();
    let UnitRecords {
        durations,
        columns: unit_columns,
        hdrs: unit_hdrs,
        window: unit_window,
    } = last_durations(store, &selected_ids);
    let hdr_platforms = HdrPlatforms::default();
    hdr_platforms.preload(store, unit_hdrs.iter().map(String::as_str));
    crate::plan::timing(
        &format!(
            "read the last duration of {} unit(s) ({} recorded)",
            selected.len(),
            durations.len()
        ),
        t,
    );
    let mut attested = 0;
    let mut refused = 0;
    let mut superseded = 0usize;
    let mut signed_only = 0usize;
    // Supersession's answers per earlier commit, and the input roots of the
    // attestations it deleted.
    let moved_on = MovedOn::default();
    // The trees every ref's tip has now: an attestation made on one of them
    // is never superseded, whatever its commit (vci 2.1.12).
    let live_trees: BTreeSet<String> = ctx.repo.live_trees().unwrap_or_default();
    let mut dropped_roots = BTreeSet::new();
    let mut dropped_objects = BTreeSet::new();
    let mut outcomes: Vec<UnitOutcome> = Vec::new();
    let mut exit: Option<i32> = Some(0);
    let jobs = check_jobs();
    for &pi in &involved {
        let project = &ctx.projects[pi];
        let child = &children[pi];
        let mine: Vec<&TestFile> = selected
            .iter()
            .map(|&i| &files[i])
            .filter(|f| f.project == pi)
            .collect();
        // Longest first (the runner's parallelism ends sooner); lines,
        // summary and the store keep the listing's order.
        let rels: Vec<String> = longest_first(&mine, |f| f.test_id.as_str(), &durations)
            .iter()
            .map(|f| f.project_rel.clone())
            .collect();
        // The same durations by project-relative path, for the runner.
        let last_ms: BTreeMap<String, u64> = mine
            .iter()
            .filter_map(|f| {
                durations
                    .get(f.test_id.as_str())
                    .map(|d| (f.project_rel.clone(), *d))
            })
            .collect();
        if ctx.projects.len() > 1 {
            eprintln!(
                "vci: running {} test file(s) of {} ({})",
                rels.len(),
                project.label(),
                project.adapter.name()
            );
        }
        // Go's test log does not report removals, renames or new
        // directories: any change to the repository during the run refuses
        // every package of the run (the change cannot be attributed).
        let started = (|| -> Result<_> {
            let go_tree = if project.adapter.name() == "go" {
                Some(TreeStat::snapshot(&root)?)
            } else {
                None
            };
            let out = project.adapter.run_collect_timed(
                &rels,
                &child.to_child_env(),
                &vci_adapter::RunHints {
                    last_ms: last_ms.clone(),
                    rails_autoload_lookups: project.autoload_lookups(),
                },
            )?;
            Ok((go_tree, out))
        })();
        // A project whose run could not be started or collected has no
        // verdict: the other projects still run and are attested (what was
        // signed and stored is reported), and `vci ci` runs this one without
        // attesting.
        let (go_tree, out) = match started {
            Ok(x) => x,
            Err(e) => {
                let msg = format!(
                    "running the tests of {} with the collectors: {e:#}",
                    project.label()
                );
                eprintln!("vci: error: {msg}");
                errors.push(msg);
                unrun.insert(pi);
                let why = "the run with the collectors could not be started or collected";
                for f in &mine {
                    refused += 1;
                    outcomes.push(UnitOutcome::refused(
                        f.test_id.as_str(),
                        project,
                        why.to_owned(),
                        vec![why.to_owned()],
                    ));
                }
                continue;
            }
        };
        let tree_changed: Option<String> = match &go_tree {
            None => None,
            Some(t) => match t.changes() {
                Ok(c) if c.is_empty() => None,
                Ok(c) => Some(format!(
                    "the repository changed during the run: {}{}",
                    c.iter().take(10).cloned().collect::<Vec<_>>().join(", "),
                    if c.len() > 10 { ", ..." } else { "" }
                )),
                Err(e) => Some(format!("checking the repository after the run: {e:#}")),
            },
        };
        match (exit, out.exit_code) {
            (Some(0), c) => exit = c,
            (Some(_), None) => exit = None,
            _ => {}
        }
        let by_id: BTreeMap<&str, &TestFile> =
            mine.iter().map(|f| (f.test_id.as_str(), *f)).collect();
        let mut seen = BTreeSet::new();
        // vci's own collector files are tooling, not inputs, however the
        // process reached them (a symlinked install prefix).
        let collector_dirs = project.adapter.collector_dirs();
        // Each output's unit and the name it is reported under, in order.
        let units: Vec<(&Observed, Option<&TestFile>, String)> = out
            .files
            .iter()
            .map(|o| {
                let id = project
                    .test_id(&o.test_id)
                    .map(|p| p.as_str().to_owned())
                    .ok();
                let file = id.as_ref().and_then(|id| by_id.get(id.as_str()).copied());
                let label = id.unwrap_or_else(|| o.test_id.clone());
                seen.insert(label.clone());
                (o, file, label)
            })
            .collect();
        // The tests have finished, so the checkout no longer changes: every
        // unit reads it through one cache (see [`Checkout`]).
        let checkout = Checkout::cached(&ctx.root);
        let t_check = std::time::Instant::now();
        // Thread-nanoseconds per part of this phase (`VCI_TIMING=1`).
        let tm_check = std::sync::atomic::AtomicU64::new(0);
        let tm_warn = std::sync::atomic::AtomicU64::new(0);
        let tm_sign = std::sync::atomic::AtomicU64::new(0);
        let tm_supersede = std::sync::atomic::AtomicU64::new(0);
        let add = |f: &std::sync::atomic::AtomicU64, since: std::time::Instant| {
            f.fetch_add(
                since.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        };
        // Checked and signed `jobs` units at a time; reported and stored in
        // order, one after the other.
        let verdict = |(o, file, label): &(&Observed, Option<&TestFile>, String)| {
            if let Some(why) = &tree_changed {
                return Verdict::Refused {
                    reason: why.clone(),
                    reasons: vec![refusal_key(why)],
                    taints: vec![],
                };
            }
            let filtered;
            let o: &Observed = if collector_dirs.is_empty() {
                o
            } else {
                let mut c = (*o).clone();
                c.drop_collector_paths(&ctx.root, &collector_dirs);
                filtered = c;
                &filtered
            };
            let t = std::time::Instant::now();
            let checked = check_one(
                &ctx,
                project,
                o,
                *file,
                &versions[&pi],
                child,
                &pre_stat,
                &pre_global,
                &base,
                &locks[pi],
                &scratch,
                &checkout,
            );
            add(&tm_check, t);
            match checked {
                Err(reason) => {
                    let (reasons, taints) = match file {
                        Some(f) if reason.starts_with("tainted: ") => {
                            let declared = project.extra_inputs(&f.project_rel);
                            let (_, taints) = split_waived(project, &declared, o);
                            (
                                group_taints(&taints).into_iter().map(|g| g.0).collect(),
                                taints.into_iter().cloned().collect(),
                            )
                        }
                        _ => (vec![refusal_key(&reason)], vec![]),
                    };
                    Verdict::Refused {
                        reason,
                        reasons,
                        taints,
                    }
                }
                Ok(a) => {
                    let t = std::time::Instant::now();
                    let warnings = attested_warnings(&checkout, project, label, &a);
                    add(&tm_warn, t);
                    // A format-1 record is signed here; a format-3 one once
                    // the run's objects are built below, since its
                    // statement names them.
                    let signed = (!format3).then(|| {
                        let t = std::time::Instant::now();
                        let signed = sign_predicate(&key, &a.predicate).map(|record| Signed {
                            record,
                            columns: None,
                        });
                        add(&tm_sign, t);
                        signed
                    });
                    // What it supersedes is found when it is made ready to
                    // store, while the writer stores the units before it.
                    Verdict::Attestable {
                        warnings,
                        signed,
                        a: Box::new(a),
                    }
                }
            }
        };
        // Every unit's verdict first (checked and signed), in parallel; then
        // the manifest base (the entries all signed units share, stored
        // once: vci 2.1.8), which the units' manifests are encoded on, so
        // nothing is stored before every unit is signed; then each unit
        // stored and reported in order.
        let mut verdicts: Vec<Option<Verdict>> = (0..units.len()).map(|_| None).collect();
        in_order(&units, jobs, verdict, |i, v| verdicts[i] = Some(v));
        // Format 3: the run's objects over every attestable unit (STORE-V2
        // section 1.4 steps 1 and 2), then each unit signed on the pool
        // (step 3), so nothing is stored before every unit is signed.
        let run3: Option<Run3> = if format3 {
            let t = std::time::Instant::now();
            let attestable: Vec<(usize, &Attestable, String)> = verdicts
                .iter()
                .enumerate()
                .filter_map(|(i, v)| match v {
                    Some(Verdict::Attestable { a, .. }) => {
                        Some((i, a.as_ref(), group_key(units[i].0)))
                    }
                    _ => None,
                })
                .collect();
            let built = build_run3(&attestable, settings.explain_hashes);
            crate::plan::timing(
                &format!(
                    "{}: build the run's format-3 objects over {} unit(s)",
                    project.label(),
                    attestable.len()
                ),
                t,
            );
            match built {
                Ok(run) => {
                    let indices: Vec<usize> = run.units.keys().copied().collect();
                    let mut signed: BTreeMap<usize, Result<Signed>> = BTreeMap::new();
                    let sign = |&i: &usize| {
                        let t = std::time::Instant::now();
                        let r = match &verdicts[i] {
                            Some(Verdict::Attestable { a, .. }) => {
                                sign_format3(&key, a, &run, &run.units[&i])
                            }
                            _ => Err(anyhow::anyhow!("not attestable")),
                        };
                        add(&tm_sign, t);
                        r
                    };
                    in_order(&indices, jobs, sign, |k, r| {
                        signed.insert(indices[k], r);
                    });
                    for (i, why) in &run.failed {
                        signed.insert(*i, Err(anyhow::anyhow!("{why}")));
                    }
                    for (i, r) in signed {
                        if let Some(Verdict::Attestable { signed, .. }) = &mut verdicts[i] {
                            *signed = Some(r);
                        }
                    }
                    Some(run)
                }
                Err(e) => {
                    // No unit of the project is stored: each is refused
                    // with why, as a unit that could not be signed.
                    for v in verdicts.iter_mut().flatten() {
                        if let Verdict::Attestable { signed, .. } = v {
                            *signed = Some(Err(anyhow::anyhow!("{e}")));
                        }
                    }
                    None
                }
            }
        } else {
            None
        };
        let t = std::time::Instant::now();
        let mut manifest_bases = if format3 {
            BTreeMap::new()
        } else {
            shared_manifest_bases(&verdicts, &units)
        };
        if !manifest_bases.is_empty() && mode == StoreMode::Write {
            // A base the store refused is not relied on: its units' manifests
            // are encoded whole instead (each then stored, or refused with
            // its unit, on its own), so no unit is attested on a manifest
            // that cannot be read back.
            let mut stored_roots = BTreeSet::new();
            let mut refused = BTreeSet::new();
            for b in manifest_bases.values() {
                let root = b.root();
                if !stored_roots.insert(root.clone()) {
                    continue;
                }
                if let Err(e) = store.put_manifest(&root, b.to_compact().as_bytes()) {
                    eprintln!(
                        "vci: warning: storing the units' shared input manifest: {e}; storing each unit's input manifest whole instead"
                    );
                    refused.insert(root);
                }
            }
            manifest_bases.retain(|_, b| !refused.contains(&b.root()));
            let sizes: Vec<usize> = manifest_bases.values().map(|b| b.entries.len()).collect();
            crate::plan::timing(
                &format!(
                    "{}: shared input manifests: {} group(s) of units, {} to {} entries each stored once",
                    project.label(),
                    manifest_bases.len(),
                    sizes.iter().min().copied().unwrap_or(0),
                    sizes.iter().max().copied().unwrap_or(0)
                ),
                t,
            );
        }
        // Each unit made ready to store on the pool (what it supersedes
        // found, its manifest encoded on its group's shared one) and handed
        // in unit order to one writer
        // thread, which stores it in the project's write batch (one
        // transaction) as soon as it and every unit before it are ready,
        // and reports it.
        let verdicts: Vec<std::sync::Mutex<Option<Verdict>>> =
            verdicts.into_iter().map(std::sync::Mutex::new).collect();
        let indices: Vec<usize> = (0..units.len()).collect();
        let prepare = |&i: &usize| -> Option<Job> {
            let v = verdicts[i].lock().ok()?.take()?;
            let label = units[i].2.clone();
            Some(match v {
                Verdict::Refused {
                    reason,
                    reasons,
                    taints,
                } => Job::Refused {
                    label,
                    reason,
                    reasons,
                    taints,
                },
                Verdict::Attestable {
                    a,
                    warnings,
                    signed,
                } => {
                    let signed = signed.unwrap_or_else(|| Err(anyhow::anyhow!("not signed")));
                    let t = std::time::Instant::now();
                    // The same signer's stored attestations of the unit it
                    // supersedes, removed once it is stored; signing only,
                    // nothing is superseded, nothing is superseded.
                    let doomed = if signed.is_ok() && mode == StoreMode::Write {
                        superseded_by(
                            store,
                            &ctx.repo,
                            &a.predicate,
                            &a.manifest,
                            &signer,
                            &moved_on,
                            &live_trees,
                            &unit_columns,
                            unit_window,
                            &hdr_platforms,
                        )
                    } else {
                        Vec::new()
                    };
                    add(&tm_supersede, t);
                    let doomed_objects: BTreeMap<String, Vec<String>> = doomed
                        .iter()
                        .filter(|d| !d.objects.is_empty())
                        .map(|d| (d.env.key.clone(), d.objects.clone()))
                        .collect();
                    let doomed: Vec<StoredEnvelope> = doomed.into_iter().map(|d| d.env).collect();
                    let p = &a.predicate;
                    let unit = match signed {
                        Err(e) => Err((label, e)),
                        Ok(Signed { record, columns }) => Ok(Box::new(ToStore {
                            // A format-1 record's manifest, encoded on its
                            // group's shared one; a format-3 record has
                            // none (its inputs are in the run's objects).
                            manifest: match (mode, &columns) {
                                (StoreMode::SignOnly, _) | (StoreMode::Write, Some(_)) => None,
                                (StoreMode::Write, None) => {
                                    Some(match manifest_bases.get(&group_key(units[i].0)) {
                                        Some(b) => a.manifest.to_compact_on(b),
                                        None => a.manifest.to_compact(),
                                    })
                                }
                            },
                            entries: a.manifest.entries.len(),
                            label,
                            test_id: p.core.test_id.clone(),
                            input_root: p.core.input_root.clone(),
                            storage_key: storage_key(&vci_core::ResolvedPredicate::v1(p)),
                            hint: crate::util::parse_rfc3339(&p.core.issued_at).ok().map(
                                |issued| KeyHint {
                                    issued,
                                    tree: p
                                        .core
                                        .tree
                                        .as_ref()
                                        .map(|t| t.chars().take(16).collect()),
                                },
                            ),
                            envelope: record,
                            columns,
                            doomed,
                            doomed_objects,
                            waived: p.waived.clone(),
                        })),
                    };
                    Job::Attestable { warnings, unit }
                }
            })
        };
        let (signer_id, owner) = (signer.as_str(), Owner::of(project));
        let done = std::thread::scope(|scope| {
            let (tx, rx) = std::sync::mpsc::channel::<Job>();
            let run3 = run3.as_ref();
            let writer = scope.spawn(move || {
                let mut say = |l: &str| eprintln!("{l}");
                let mut stores = StoreLoop::new(store, mode, signer_id, owner, &mut say);
                // The run's objects before any record that names them.
                if let Some(r) = run3 {
                    stores.put_objects(&r.objects);
                }
                for job in rx {
                    stores.apply(job);
                }
                stores.finish()
            });
            in_order(&indices, jobs, prepare, |_, job| {
                if let Some(job) = job {
                    let _ = tx.send(job);
                }
            });
            drop(tx);
            writer
                .join()
                .unwrap_or_else(|p| std::panic::resume_unwind(p))
        });
        attested += done.attested;
        refused += done.refused;
        superseded += done.superseded;
        signed_only += done.signed_only;
        outcomes.extend(done.outcomes);
        errors.extend(done.errors);
        store_failures.extend(done.store_failures);
        dropped_roots.extend(done.dropped_roots);
        dropped_objects.extend(done.dropped_objects);
        if let Some(r) = &run3 {
            crate::plan::timing(
                &format!(
                    "{}: format-3 run: {} hdr, {} tables, 1 shape, {} state object(s) over {} unit(s); objects {} bytes put, records {} bytes stored, {} batch(es)",
                    project.label(),
                    r.headers.len(),
                    r.tables.len(),
                    usize::from(r.state.is_some()),
                    r.units.len(),
                    done.objects_bytes,
                    done.records_bytes,
                    done.batches
                ),
                t_check,
            );
        }
        crate::plan::timing(
            &format!(
                "check, sign and store {} unit(s) of {} ({jobs} at a time)",
                units.len(),
                project.label()
            ),
            t_check,
        );
        if vci_core::metrics::on() {
            let g = |f: &std::sync::atomic::AtomicU64| {
                f.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1e9
            };
            vci_core::timing_line!(
                "{}: thread-seconds: check (capture inputs, tree, taints) {:.1}, warnings {:.1}, sign {:.1}, find superseded {:.1}; store and remove superseded (one writer thread, one batch) {:.1} (manifests {:.1}, removals {:.1})",
                project.label(),
                g(&tm_check),
                g(&tm_warn),
                g(&tm_sign),
                g(&tm_supersede),
                done.store_secs,
                done.manifest_secs,
                done.remove_secs
            );
            for line in store.timing_report() {
                vci_core::timing_line!("{}: {line}", project.label());
            }
            let ns =
                |i: usize| SUPERSEDE_NS[i].load(std::sync::atomic::Ordering::Relaxed) as f64 / 1e9;
            vci_core::timing_line!(
                "{}: supersession thread-seconds: list {:.1}, read payloads {:.1}, moved on {:.1}, manifests or headers {:.1}; {} earlier commit(s) asked about",
                project.label(),
                ns(0),
                ns(1),
                ns(2),
                ns(3),
                moved_on.commits.lock().map(|c| c.len()).unwrap_or(0)
            );
        }
        for f in &mine {
            if !seen.contains(f.test_id.as_str()) {
                refused += 1;
                let why = "the collector produced no output for it";
                eprintln!("vci: not attesting {}: {why}", f.test_id);
                outcomes.push(UnitOutcome::refused(
                    f.test_id.as_str(),
                    project,
                    why.to_owned(),
                    vec![why.to_owned()],
                ));
            }
        }
    }
    if signed_only > 0 {
        eprintln!(
            "vci: not storing {signed_only} attestation(s): the {} store is shared and vci ci was not given --push",
            store.kind()
        );
    }
    eprintln!("vci: {attested} attested, {refused} not attested");
    if superseded > 0 {
        eprintln!(
            "vci: removed {superseded} superseded attestation(s) (earlier ones of the same units by the same signer and platform, made on a commit this one descends from that no other branch or tag contains, of files the tree no longer has)"
        );
        let orphans = drop_orphan_manifests(store, &dropped_roots);
        if orphans > 0 {
            eprintln!(
                "vci: removed {orphans} input manifest(s) no attestation references any more"
            );
        }
        let orphans = drop_orphan_objects(store, &dropped_objects);
        if orphans > 0 {
            eprintln!("vci: removed {orphans} object(s) no attestation references any more");
        }
    }
    if format3 && mode == StoreMode::Write {
        let aged = prune_state_objects(store, settings.explain_hashes_days);
        if aged > 0 {
            eprintln!(
                "vci: removed {aged} state object(s) older than {} day(s) ([store] explain_hashes_days)",
                settings.explain_hashes_days
            );
        }
    }
    let counts = reason_counts(&outcomes);
    if !counts.is_empty() {
        eprintln!("vci: why not attested (files per reason; a file can have several):");
        let w = counts.first().map_or(1, |c| c.1.to_string().len());
        for (reason, n) in &counts {
            eprintln!("vci:   {n:>w$} {reason}");
        }
    }
    if let Some(path) = summary {
        let mut text = serde_json::to_string_pretty(&summary_json(&outcomes))?;
        text.push('\n');
        std::fs::write(path, text).with_context(|| format!("writing --summary {path}"))?;
    }
    Ok(RunOutcome {
        exit: exit.unwrap_or(1),
        errors,
        store_failures,
        unrun,
        attested: outcomes
            .into_iter()
            .filter(|o| o.attested)
            .map(|o| AttestedUnit {
                test_id: o.test_id,
                project: o.project.unwrap_or_default(),
                stored: o.stored,
            })
            .collect(),
    })
}

/// The same signer's stored attestations of a unit that storing the new one
/// (`p`, `manifest`) supersedes: made on a commit this line of history has
/// moved on from ([`vci_git::Repo::moved_on`]: `new commit` descends from
/// it and no other branch or tag still contains it, or it was rebased or
/// amended away), with a manifest whose entries differ from the new one's.
/// The signer re-attesting is the newest truth for that line, so the
/// published tree keeps one attestation per unit and signer as commits go
/// by, without a separate `vci prune --superseded`. Kept: one made on the
/// same commit (work in progress: an edit may be reverted), on a commit
/// another ref still contains (`main` under a feature branch: every branch
/// made from it needs it; a sibling branch or pull request), one issued
/// later than this one (another machine with the same key), one for another
/// OS or architecture (a CI matrix sharing a key: platform-specific files
/// differ), one with the same entries (another environment or toolchain on
/// this tree), and one whose payload or manifest cannot be read. Read only
/// (several units at once); [`remove_superseded`] deletes them once the new
/// one is stored. `moved_on` caches git's answer per earlier commit. Kept
/// too (since 2.1.12): one made on a tree some ref's tip still has
/// (`live_trees`): a pull request's merge commit is on no ref once the pull
/// request is squash-merged, yet master's tip has its tree, and master's
/// next run skips with it; another pull request's run must not delete it.
/// What supersession learns about commits during a run: whether each
/// earlier commit was moved on from (asked once per commit, other threads
/// waiting for the answer), and the commits only the run's commit holds
/// ([`vci_git::Repo::only_on`]), found once, when first needed.
#[derive(Default)]
struct MovedOn {
    commits: std::sync::Mutex<BTreeMap<String, std::sync::Arc<std::sync::OnceLock<bool>>>>,
    only_on: std::sync::OnceLock<Option<BTreeSet<String>>>,
}

/// Where supersession spends its time (`VCI_TIMING=1`), nanoseconds summed
/// over threads: listing a unit's attestations, reading their payloads,
/// asking git whether their commits were moved on from, and decoding their
/// manifests.
static SUPERSEDE_NS: [std::sync::atomic::AtomicU64; 4] = [
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
];

fn supersede_add(i: usize, t: std::time::Instant) {
    SUPERSEDE_NS[i].fetch_add(
        t.elapsed().as_nanos() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// An earlier record [`superseded_by`] found, with the object ids it names
/// (its listing columns' and, for a format-3 record, its statement's hdr
/// and tables and its descriptor's shape), removed under the orphan rule
/// once the run has stored ([`drop_orphan_objects`]).
struct Doomed {
    env: StoredEnvelope,
    objects: Vec<String>,
}

/// What supersession reads from an old record of either format: the v1
/// fields of [`crate::cmds::EnvelopeMeta`], or the format-3 statement's
/// ([`frame_meta`]) with the platform resolved through its hdr object.
struct OldRecord {
    test_id: String,
    commit: String,
    os: String,
    arch: String,
    issued_at: i64,
    tree: Option<String>,
    files: OldFiles,
}

/// How an old record names its files, for supersession's "same files"
/// test.
enum OldFiles {
    /// Format 1: by its manifest (`manifestRef`, or inline before 1.9.0).
    Manifest(Option<String>),
    /// Format 3: by its signed `entriesRoot`.
    EntriesRoot(String),
}

/// The same signer's stored records of the unit that the new record
/// supersedes, with the object ids each names. `columns` are the
/// listing columns of the unit's records as [`last_durations`] fetched
/// them for the whole run, by key; a record not in them (stored since) is
/// read as if it had none.
#[allow(clippy::too_many_arguments)]
fn superseded_by(
    store: &dyn AttestationStore,
    repo: &vci_git::Repo,
    p: &VciPredicate,
    manifest: &InputManifest,
    signer: &str,
    moved_on: &MovedOn,
    live_trees: &BTreeSet<String>,
    columns: &BTreeMap<String, Columns>,
    window: bool,
    hdrs: &HdrPlatforms,
) -> Vec<Doomed> {
    let issued = crate::util::parse_rfc3339(&p.core.issued_at).ok();
    let tc = &p.core.toolchain;
    let platform = format!("{}-{}", tc.os, tc.arch);
    let mut entries: Vec<&vci_core::InputEntry> = manifest.entries.iter().collect();
    entries.sort();
    // The new manifest's entries root, for a format-3 old record's "same
    // files" test (STORE-V2 section 1.4 step 5), computed when first met.
    let entries_root = std::sync::OnceLock::new();
    // Whether its commit was moved on from: one answer per commit (two
    // threads may ask about the same commit at once; same answer), so
    // before reading its manifest (2.3.1: decoding every older
    // attestation's manifest first took about 215 thread-seconds of a
    // full vex job, where most were made on commits others contain).
    // Asked once per commit: a thread that finds another asking waits
    // for its answer (16 threads used to ask about the same commits at
    // once, each walking every ref's history).
    let moved = |commit: &str| -> bool {
        let cell = moved_on
            .commits
            .lock()
            .map(|mut c| c.entry(commit.to_owned()).or_default().clone())
            .unwrap_or_default();
        let t = std::time::Instant::now();
        let moved = *cell.get_or_init(|| {
            let only = moved_on.only_on.get_or_init(|| {
                let t = std::time::Instant::now();
                let wrote = repo.ensure_commit_graph();
                let graph = t.elapsed().as_secs_f64();
                let t = std::time::Instant::now();
                let only = repo.only_on(&p.core.commit).ok();
                if vci_core::metrics::on() {
                    vci_core::timing_line!(
                        "supersession: {} commit-graph {graph:.2}s; {} commit(s) only this run's commit holds: {:.2}s",
                        if wrote { "wrote a" } else { "no new" },
                        only.as_ref().map_or_else(|| "?".to_owned(), |o| o.len().to_string()),
                        t.elapsed().as_secs_f64()
                    );
                }
                only
            });
            let t = std::time::Instant::now();
            let moved = match only {
                Some(only) => repo.moved_on_given(commit, &p.core.commit, only),
                None => repo.moved_on(commit, &p.core.commit),
            }
            .unwrap_or(false);
            if vci_core::metrics::on() {
                vci_core::timing_line!(
                    "supersession: whether {} was moved on from ({moved}): {:.2}s",
                    &commit[..commit.len().min(12)],
                    t.elapsed().as_secs_f64()
                );
            }
            moved
        });
        supersede_add(2, t);
        moved
    };
    // The record's facts, from its signed statement (unverified, as
    // today: the key's signer segment and the columns only chose it); a
    // format-3 record's platform through its hdr object, which must decode
    // to its signed id. `None` keeps the record.
    let old_record = |e: &StoredEnvelope| -> Option<(OldRecord, Vec<String>)> {
        match decode_record(&e.bytes).ok()? {
            Record::FormatOne(bytes) => {
                let m = crate::cmds::envelope_meta(bytes)?;
                let old = OldRecord {
                    test_id: m.test_id,
                    commit: m.commit,
                    os: m.os,
                    arch: m.arch,
                    issued_at: m.issued_at,
                    tree: m.tree,
                    files: OldFiles::Manifest(m.manifest_ref),
                };
                Some((old, Vec::new()))
            }
            Record::FormatThree(frame) => {
                let m = frame_meta(&frame)?;
                let t = std::time::Instant::now();
                let found = hdrs.of(store, &m.hdr);
                supersede_add(3, t);
                let (os, arch) = found?;
                let mut objects = vec![m.hdr.clone(), m.tables.clone()];
                if let Ok(shape) = vci_core::Descriptor::shape_id(&frame.descriptor) {
                    objects.push(vci_core::objects::hex32(&shape));
                }
                let old = OldRecord {
                    test_id: m.test_id,
                    commit: m.commit,
                    os,
                    arch,
                    issued_at: m.issued_at,
                    tree: m.tree,
                    files: OldFiles::EntriesRoot(m.entries_root),
                };
                Some((old, objects))
            }
        }
    };
    // Whether the new record supersedes this old one: `None` keeps it,
    // `Some(ids)` dooms it with the object ids it names.
    let judge = |e: &StoredEnvelope, c: &Columns| -> Option<Vec<String>> {
        if e.error.is_some() {
            return None;
        }
        let (m, mut objects) = old_record(e)?;
        if m.test_id != p.core.test_id
            || m.commit == p.core.commit
            || m.os != tc.os
            || m.arch != tc.arch
            || issued.is_none_or(|i| m.issued_at > i)
            || m.tree.as_deref().is_some_and(|t| live_trees.contains(t))
            || !moved(&m.commit)
        {
            return None;
        }
        let same_files = match &m.files {
            OldFiles::EntriesRoot(r) => *r == *entries_root.get_or_init(|| manifest.entries_root()),
            // The same root: the same inputs.
            OldFiles::Manifest(Some(r)) if *r == p.core.input_root => true,
            OldFiles::Manifest(r) => {
                let t = std::time::Instant::now();
                let old = match r {
                    Some(r) => store
                        .manifest_decoded(r)
                        .ok()
                        .flatten()
                        .and_then(Result::ok)
                        .filter(|o| o.root() == *r),
                    None => crate::cmds::envelope_inline_manifest(&e.bytes),
                };
                supersede_add(3, t);
                let old = old?;
                let mut old_entries: Vec<&vci_core::InputEntry> = old.entries.iter().collect();
                old_entries.sort();
                old_entries == entries
            }
        };
        if same_files {
            return None;
        }
        objects.extend(c.object_ids().map(str::to_owned));
        objects.sort_unstable();
        objects.dedup();
        Some(objects)
    };
    let test_id = p.core.test_id.as_str();
    let cannot_read = |e: &StoreError| {
        eprintln!(
            "vci: warning: {test_id}: cannot read its stored attestations to supersede them: {e}"
        );
        Vec::new()
    };
    // The same signer's records of the unit, read. On a store with listing
    // columns (STORE-V2 section 1.4 step 5) the columns, fetched once for
    // the run's units, pre-filter which to read: one made at the same
    // commit or for another platform is skipped without a read (a column
    // that lies costs one read, never a deletion: every fact below comes
    // from the signed statement), except while the store holds a manifest
    // (`window`: a 2.8 value under a frame's columns is read like any
    // other). Without them (git-meta), the backend's own targeted read of
    // the unit.
    let t = std::time::Instant::now();
    let mut candidates: Vec<(StoredEnvelope, Columns)> = if store.caps().columns {
        let mine: Vec<StoredEnvelope> = match store.list_units(&[test_id]) {
            Ok(mut units) => units.pop().unwrap_or_default(),
            Err(e) => return cannot_read(&e),
        }
        .into_iter()
        .filter(|e| e.signer == signer)
        .collect();
        supersede_add(0, t);
        let mut chosen = old_records_to_read(mine, columns, &p.core.commit, &platform, window);
        let t = std::time::Instant::now();
        let mut refs: Vec<&mut StoredEnvelope> = chosen.iter_mut().map(|(e, _)| e).collect();
        if let Err(e) = store.read_values(&mut refs) {
            return cannot_read(&e);
        }
        supersede_add(1, t);
        chosen
    } else {
        let mine = match store.read_units(&[test_id]) {
            Ok(mut units) => units.pop().unwrap_or_default(),
            Err(e) => return cannot_read(&e),
        };
        supersede_add(1, t);
        mine.into_iter()
            .filter(|e| e.signer == signer)
            .map(|e| (e, Columns::default()))
            .collect()
    };
    candidates
        .drain(..)
        .filter_map(|(e, c)| {
            let objects = judge(&e, &c)?;
            Some(Doomed { env: e, objects })
        })
        .collect()
}

/// Delete what [`superseded_by`] found, once the new attestation is stored.
/// Failing to delete is only a warning (added to `warnings`): a kept
/// attestation is verified like any other. Returns how many were deleted,
/// and adds the input roots they referenced to `dropped_roots`.
fn remove_superseded(
    store: &dyn AttestationStore,
    test_id: &str,
    doomed: Vec<StoredEnvelope>,
    doomed_objects: &BTreeMap<String, Vec<String>>,
    dropped_roots: &mut BTreeSet<String>,
    dropped_objects: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> usize {
    if doomed.is_empty() {
        return 0;
    }
    match store.remove(doomed) {
        Ok(removed) => {
            for e in &removed {
                if let Some(ids) = doomed_objects.get(&e.key) {
                    dropped_objects.extend(ids.iter().cloned());
                }
                if let Ok(Record::FormatOne(bytes)) = decode_record(&e.bytes)
                    && let Some(r) = crate::cmds::envelope_meta(bytes).and_then(|m| m.manifest_ref)
                {
                    dropped_roots.insert(r);
                }
            }
            removed.len()
        }
        Err(e) => {
            warnings.push(format!(
                "vci: warning: {test_id}: cannot remove superseded attestations: {e}"
            ));
            0
        }
    }
}

/// The group a unit's manifest shares a base with: the units whose
/// outputs shared lines (a Rails slot's or boot's), else the run.
fn group_key(o: &Observed) -> String {
    o.shared_group.clone().unwrap_or_default()
}

/// The input manifest bases of a run (vci 2.1.8), by group: for the units
/// of each group (see [`group_key`]) with two or more attestable, signed
/// units, the entries they all have, as one plain manifest (no externals,
/// no env), stored once; each unit's manifest is then stored as the
/// entries it adds (`InputManifest::to_compact_on`). A Rails slot's files
/// share the boot's and the slot's observations, most of each manifest.
/// Units outside any group share the run's, when two or more of them have
/// entries in common.
fn shared_manifest_bases(
    verdicts: &[Option<Verdict>],
    units: &[(&Observed, Option<&TestFile>, String)],
) -> BTreeMap<String, InputManifest> {
    let mut shared: BTreeMap<String, (usize, BTreeSet<&vci_core::InputEntry>)> = BTreeMap::new();
    for (i, v) in verdicts.iter().enumerate() {
        let Some(Verdict::Attestable {
            a,
            signed: Some(Ok(_)),
            ..
        }) = v
        else {
            continue;
        };
        let mine: BTreeSet<&vci_core::InputEntry> = a.manifest.entries.iter().collect();
        let key = group_key(units[i].0);
        match shared.get_mut(&key) {
            None => {
                shared.insert(key, (1, mine));
            }
            Some((n, s)) => {
                *n += 1;
                *s = s.intersection(&mine).copied().collect();
            }
        }
    }
    shared
        .into_iter()
        .filter(|(_, (n, s))| *n >= 2 && !s.is_empty())
        .map(|(k, (_, s))| {
            (
                k,
                InputManifest {
                    entries: s.into_iter().cloned().collect(),
                    externals: Vec::new(),
                    env: Vec::new(),
                },
            )
        })
        .collect()
}

/// The last recorded duration (`result.durationMs`) of each of these units:
/// its newest stored attestation's, by any signer, when one records it.
/// On a store with listing columns ([`vci_store::Caps::columns`]) from the
/// columns (`duration_ms`, and `issued` from the key), without a value
/// read; a unit none of whose records has the column (format-1 rows, as
/// 2.8 and `record_format = 1` write them) is read and decoded by its
/// first byte, as every unit is on a store without columns. Best effort: a
/// unit that cannot be read has none. The columns fetched (one round trip
/// for every unit's records) come back by key for supersession.
fn last_durations(store: &dyn AttestationStore, test_ids: &[&str]) -> UnitRecords {
    let mut out = UnitRecords::default();
    let newest_read = |cands: &[StoredEnvelope]| -> Option<u64> {
        cands
            .iter()
            .filter(|e| e.error.is_none())
            .filter_map(|e| record_duration(&e.bytes))
            .max_by_key(|(issued, _)| *issued)
            .map(|(_, d)| d)
    };
    if !store.caps().columns {
        let Ok(units) = store.read_units(test_ids) else {
            return out;
        };
        for (id, cands) in test_ids.iter().zip(units) {
            if let Some(d) = newest_read(&cands) {
                out.durations.insert((*id).to_owned(), d);
            }
            out.hdrs.extend(
                cands
                    .iter()
                    .filter(|e| e.error.is_none())
                    .filter_map(|e| hdr_named(&e.bytes)),
            );
        }
        return out;
    }
    out.window = store.manifest_roots().map_or(true, |r| !r.is_empty());
    let Ok(units) = store.list_units(test_ids) else {
        return out;
    };
    // One columns round trip for every unit's records.
    let refs: Vec<&StoredEnvelope> = units.iter().flatten().collect();
    let columns = store
        .columns(&refs)
        .ok()
        .filter(|c| c.len() == refs.len())
        .unwrap_or_else(|| vec![Columns::default(); refs.len()]);
    let mut columns = columns.into_iter();
    let mut to_read: Vec<(usize, StoredEnvelope)> = Vec::new();
    for (ui, (id, cands)) in test_ids.iter().zip(units).enumerate() {
        let cols: Vec<Columns> = columns.by_ref().take(cands.len()).collect();
        let newest = cands
            .iter()
            .zip(&cols)
            .filter_map(|(e, c)| c.duration_ms.map(|d| (e.issued.unwrap_or(0), d)))
            .max_by_key(|(issued, _)| *issued);
        for (e, c) in cands.iter().zip(&cols) {
            if !c.is_empty() {
                out.columns.insert(e.key.clone(), c.clone());
            }
            out.hdrs.extend(c.hdr.clone());
        }
        match newest {
            Some((_, d)) => {
                out.durations.insert((*id).to_owned(), d);
            }
            None => to_read.extend(cands.into_iter().map(|e| (ui, e))),
        }
    }
    if to_read.is_empty() {
        return out;
    }
    {
        let mut refs: Vec<&mut StoredEnvelope> = to_read.iter_mut().map(|(_, e)| e).collect();
        if store.read_values(&mut refs).is_err() {
            return out;
        }
    }
    let mut by_unit: BTreeMap<usize, Vec<StoredEnvelope>> = BTreeMap::new();
    for (ui, e) in to_read {
        by_unit.entry(ui).or_default().push(e);
    }
    for (ui, cands) in by_unit {
        if let Some(d) = newest_read(&cands) {
            out.durations.insert(test_ids[ui].to_owned(), d);
        }
        out.hdrs.extend(
            cands
                .iter()
                .filter(|e| e.error.is_none())
                .filter_map(|e| hdr_named(&e.bytes)),
        );
    }
    out
}

/// What [`last_durations`] read of the selected units' stored records: the
/// last duration of each unit, and on a store with columns every listed
/// record's columns by key (those that are not empty), which supersession
/// takes from here instead of asking the store per unit (STORE-V2 section
/// 3 budgets a run's supersession no request but the doomed records'
/// reads).
#[derive(Default)]
struct UnitRecords {
    durations: BTreeMap<String, u64>,
    columns: BTreeMap<String, Columns>,
    /// The hdr objects the units' format-3 records name (by their columns,
    /// or by the statements of the records read on a store without
    /// columns), for [`HdrPlatforms::preload`].
    hdrs: BTreeSet<String>,
    /// The store still holds an input manifest (the migration window of
    /// STORE-V2 section 5, or a writer on `record_format = 1`): a 2.8
    /// writer's upsert sets a slot's key and value alone, so a format-1
    /// value may sit beside a frame's stale columns, whose commit and
    /// platform are not its own; supersession then reads every record of
    /// the unit instead of pre-filtering by the columns
    /// ([`old_records_to_read`]). `true` when the store could not say.
    window: bool,
}

/// The hdr id a stored value names when it is a format-3 record with a v2
/// statement (unverified, as everything [`last_durations`] reads).
fn hdr_named(bytes: &[u8]) -> Option<String> {
    match decode_record(bytes) {
        Ok(Record::FormatThree(frame)) => frame_meta(&frame).map(|m| m.hdr),
        _ => None,
    }
}

/// A stored record's issue time and recorded duration, by its first byte
/// (unverified): a format-1 envelope's `issuedAt` and `result.durationMs`,
/// a format-3 statement's.
fn record_duration(bytes: &[u8]) -> Option<(i64, u64)> {
    match decode_record(bytes).ok()? {
        Record::FormatOne(b) => {
            let m = crate::cmds::envelope_meta(b)?;
            Some((m.issued_at, m.duration_ms?))
        }
        Record::FormatThree(f) => {
            let m = frame_meta(&f)?;
            Some((m.issued_at, m.duration_ms))
        }
    }
}

// ---------------------------------------------------------------- format 3

/// What `[store]` says `vci run` writes (STORE-V2 sections 1.3 and 5): the
/// record format, whether the run's state object is written, and how long
/// a state object is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecordSettings {
    format: u8,
    explain_hashes: bool,
    explain_hashes_days: u32,
}

impl RecordSettings {
    /// The settings the repository's store was opened with
    /// ([`crate::store::selection_of`]), else the defaults (a store that
    /// could not be selected is one nothing is written to).
    fn of(repo: &vci_git::Repo) -> Self {
        match crate::store::selection_of(repo) {
            Some(s) => RecordSettings {
                format: s.record_format.value,
                explain_hashes: s.explain_hashes.value,
                explain_hashes_days: s.explain_hashes_days.value,
            },
            None => RecordSettings {
                format: vci_store::select::DEFAULT_RECORD_FORMAT,
                explain_hashes: true,
                explain_hashes_days: vci_store::select::DEFAULT_EXPLAIN_HASHES_DAYS,
            },
        }
    }

    /// Whether this run writes format-3 records: `record_format = 3` on a
    /// store that keeps objects ([`vci_store::Caps::objects`]); otherwise
    /// format 1, exactly as 2.8 wrote it.
    fn format3(&self, store: &dyn AttestationStore) -> bool {
        self.format == 3 && store.caps().objects
    }
}

/// One of a run's format-3 objects, encoded, in the order they are put.
struct RunObject {
    kind: ObjectKind,
    bytes: Vec<u8>,
    id: vci_core::ObjectId,
}

/// What one attestable unit takes from a built run: its header group, its
/// descriptor and waived ids, and its manifest's entries root.
struct Unit3 {
    header: usize,
    record: UnitRecord,
    entries_root: String,
}

/// A run's format-3 objects (STORE-V2 section 1.4 steps 1 and 2) and each
/// attestable unit's part of them (step 3), built once per project after
/// the tests: the hdr per header group (content-addressed, so a run at the
/// same toolchain and global inputs names the one before), the tables per
/// header group, the shape over every unit (its groups today's shared
/// bases) and the state over every entry (unless `explain_hashes =
/// false`).
struct Run3 {
    /// In put order: the hdr objects, the tables, the shape, the state.
    objects: Vec<RunObject>,
    /// Per header group: the hdr id and the tables id.
    headers: Vec<(vci_core::ObjectId, vci_core::ObjectId)>,
    tables: Vec<Encoded<Tables>>,
    /// The shape's id, hex.
    shape: String,
    /// The state object's id, hex, when it is written.
    state: Option<String>,
    /// By unit index.
    units: BTreeMap<usize, Unit3>,
    /// Units whose header object could not be made, with why: refused.
    failed: BTreeMap<usize, String>,
}

/// Build the run over `units` (unit index, the unit, its shared-base group
/// key). Fails as a whole when the shape, state or a tables object cannot
/// be encoded.
fn build_run3(
    units: &[(usize, &Attestable, String)],
    explain_hashes: bool,
) -> Result<Run3, String> {
    let mut header_of: BTreeMap<String, usize> = BTreeMap::new();
    let mut hdrs: Vec<RunObject> = Vec::new();
    let mut inputs: Vec<UnitInputs<'_>> = Vec::with_capacity(units.len());
    let mut indices: Vec<usize> = Vec::with_capacity(units.len());
    let mut entries_roots: Vec<String> = Vec::with_capacity(units.len());
    let mut failed = BTreeMap::new();
    for (i, a, group) in units {
        let bytes = a
            .predicate
            .hdr()
            .map_err(|e| e.to_string())
            .and_then(|h| h.encode().map_err(|e| e.to_string()));
        let bytes = match bytes {
            Ok(b) => b,
            Err(e) => {
                failed.insert(*i, format!("encoding the run's header object: {e}"));
                continue;
            }
        };
        let id = vci_core::object_id(&bytes);
        let hex = vci_core::objects::hex32(&id);
        let header = match header_of.get(&hex) {
            Some(h) => *h,
            None => {
                let h = hdrs.len();
                header_of.insert(hex, h);
                hdrs.push(RunObject {
                    kind: ObjectKind::Hdr,
                    bytes,
                    id,
                });
                h
            }
        };
        inputs.push(UnitInputs {
            header,
            group: Some(group.as_str()),
            manifest: &a.manifest,
            waived: &a.predicate.waived,
        });
        indices.push(*i);
        entries_roots.push(a.manifest.entries_root());
    }
    let run =
        vci_core::Run::build(&inputs).map_err(|e| format!("building the run's objects: {e}"))?;
    let vci_core::Run {
        shape,
        state,
        tables,
        units: records,
    } = run;
    let headers: Vec<(vci_core::ObjectId, vci_core::ObjectId)> = hdrs
        .iter()
        .zip(&tables)
        .map(|(h, t)| (h.id, t.id))
        .collect();
    let mut objects = hdrs;
    objects.extend(tables.iter().map(|t| RunObject {
        kind: ObjectKind::Tables,
        bytes: t.bytes.clone(),
        id: t.id,
    }));
    objects.push(RunObject {
        kind: ObjectKind::Shape,
        bytes: shape.bytes,
        id: shape.id,
    });
    let state_id = explain_hashes.then(|| {
        objects.push(RunObject {
            kind: ObjectKind::State,
            bytes: state.bytes,
            id: state.id,
        });
        vci_core::objects::hex32(&state.id)
    });
    let units: BTreeMap<usize, Unit3> = indices
        .into_iter()
        .zip(inputs)
        .zip(records)
        .zip(entries_roots)
        .map(|(((i, u), record), entries_root)| {
            (
                i,
                Unit3 {
                    header: u.header,
                    record,
                    entries_root,
                },
            )
        })
        .collect();
    Ok(Run3 {
        objects,
        headers,
        tables,
        shape: vci_core::objects::hex32(&shape.id),
        state: state_id,
        units,
        failed,
    })
}

/// Sign unit `u` of a built run as a format-3 record (STORE-V2 section 1.4
/// step 3): the v2 statement (the hdr and tables ids, the entries root,
/// the waived ids) as compact sorted-key JSON, signed over those bytes
/// exactly as a format-1 statement is signed, the descriptor, the text
/// frame; with the listing columns copied from what was signed.
fn sign_format3(key: &Signer<'_>, a: &Attestable, run: &Run3, u: &Unit3) -> Result<Signed> {
    let (hdr, tables_id) = &run.headers[u.header];
    let tables = &run.tables[u.header].value;
    let p = &a.predicate;
    let v2 = p
        .to_v2(hdr, tables_id, tables, &u.entries_root)
        .map_err(|e| anyhow::anyhow!("the v2 statement: {e}"))?;
    let mut digest = BTreeMap::new();
    digest.insert("blake3".to_owned(), p.core.input_root.clone());
    let stmt = Statement::new(
        vec![Subject {
            name: p.core.test_id.clone(),
            digest,
        }],
        PREDICATE_TYPE_V2,
        serde_json::to_value(&v2)?,
    );
    let statement = sorted_compact_json(&stmt)?.into_bytes();
    let descriptor = u
        .record
        .descriptor
        .encode(tables)
        .map_err(|e| anyhow::anyhow!("encoding the descriptor: {e}"))?;
    let frame = key.sign_frame(statement, descriptor)?;
    let record = frame
        .encode()
        .map_err(|e| anyhow::anyhow!("encoding the record: {e}"))?;
    let columns = columns_for(p, &v2, &run.shape, run.state.as_deref());
    Ok(Signed {
        record: record.into_bytes(),
        columns: Some(columns),
    })
}

/// A format-3 record's listing columns (STORE-V2 section 2.1), copied from
/// the statement it signs and the hdr it names; the state object is the
/// writer's alone to say.
fn columns_for(p: &VciPredicate, v2: &VciPredicateV2, shape: &str, state: Option<&str>) -> Columns {
    let tc = &p.core.toolchain;
    Columns {
        format: Some(3),
        commit: Some(v2.commit.clone()),
        platform: Some(format!("{}-{}", tc.os, tc.arch)),
        state: Some(v2.result.state.clone()),
        duration_ms: Some(v2.result.duration_ms),
        expires: crate::util::parse_rfc3339(&v2.expires_at).ok(),
        hdr: Some(v2.hdr.clone()),
        tables: Some(v2.tables.clone()),
        shape: Some(shape.to_owned()),
        state_obj: state.map(str::to_owned),
    }
}

/// Of the unit's listed records, those supersession reads, each with its
/// listing columns from `columns` (by key; [`Columns::default`] for a
/// record not in them): the columns leave out a record made at `commit` or
/// for another platform than `platform` without a read, except while the
/// store still holds an input manifest (`window`, [`UnitRecords::window`]):
/// a 2.8 writer may then have left its format-1 value under a frame's
/// columns, and every record is read, as `vci prune` reads them.
fn old_records_to_read(
    mine: Vec<StoredEnvelope>,
    columns: &BTreeMap<String, Columns>,
    commit: &str,
    platform: &str,
    window: bool,
) -> Vec<(StoredEnvelope, Columns)> {
    mine.into_iter()
        .map(|e| {
            let c = columns.get(&e.key).cloned().unwrap_or_default();
            (e, c)
        })
        .filter(|(_, c)| {
            window
                || (c.commit.as_deref() != Some(commit)
                    && !c.platform.as_deref().is_some_and(|pl| pl != platform))
        })
        .collect()
}

/// What supersession and [`last_durations`] read from a format-3 record's
/// signed statement (unverified, as [`crate::cmds::envelope_meta`] is for a
/// format-1 one: nothing here decides a verdict). `None` for a statement
/// that is not a v2 predicate.
struct FrameMeta {
    test_id: String,
    issued_at: i64,
    commit: String,
    tree: Option<String>,
    entries_root: String,
    hdr: String,
    tables: String,
    duration_ms: u64,
}

fn frame_meta(frame: &Frame) -> Option<FrameMeta> {
    let v: serde_json::Value = serde_json::from_slice(&frame.statement).ok()?;
    if v["predicateType"].as_str() != Some(PREDICATE_TYPE_V2) {
        return None;
    }
    let p: VciPredicateV2 = serde_json::from_value(v["predicate"].clone()).ok()?;
    Some(FrameMeta {
        test_id: p.test_id,
        issued_at: crate::util::parse_rfc3339(&p.issued_at).ok()?,
        commit: p.commit,
        tree: p.tree,
        entries_root: p.entries_root,
        hdr: p.hdr,
        tables: p.tables,
        duration_ms: p.result.duration_ms,
    })
}

/// The platform (`toolchain.os`, `toolchain.arch`) of each hdr object
/// supersession met this run, by id: the ones the units' listing columns
/// name read in one `get_objects` before the units run
/// ([`HdrPlatforms::preload`]), any other once when met, the id
/// recomputed over the bytes and the object decoded; `None` for one the
/// store lacks or that does not decode to its id (its records are kept).
#[derive(Default)]
struct HdrPlatforms(std::sync::Mutex<BTreeMap<String, Option<(String, String)>>>);

impl HdrPlatforms {
    /// The platforms of these hdr ids (the ones the units' records name,
    /// distinct), read in one `get_objects` before the per-unit pass (on a
    /// store whose values a fetch leaves out, git-meta's blobless clone,
    /// after one `Prefetch::Objects`: `get_objects` fetches nothing, and
    /// without it a clone that never read the hdr would keep every old
    /// record as made for an unknown platform); an id the store lacks is
    /// remembered as such.
    fn preload<'a>(&self, store: &dyn AttestationStore, ids: impl Iterator<Item = &'a str>) {
        let ids: BTreeSet<&str> = ids.filter(|id| vci_store::key::is_object_id(id)).collect();
        if ids.is_empty() {
            return;
        }
        let ids: Vec<&str> = ids.into_iter().collect();
        if store.caps().lazy_values {
            // A failure leaves the objects missing: their records are kept.
            let _ = store.prefetch(Prefetch::Objects { ids: &ids });
        }
        let Ok(objects) = store.get_objects(&ids) else {
            return;
        };
        let mut found: BTreeMap<String, Option<(String, String)>> =
            ids.iter().map(|id| ((*id).to_owned(), None)).collect();
        for o in objects {
            if found.contains_key(&o.id) {
                found.insert(o.id.clone(), Self::platform_of(&o.id, &o.bytes));
            }
        }
        if let Ok(mut m) = self.0.lock() {
            m.extend(found);
        }
    }

    /// The platform of the hdr `bytes` claim to be `id`: the id recomputed
    /// over the bytes and the object decoded.
    fn platform_of(id: &str, bytes: &[u8]) -> Option<(String, String)> {
        if vci_core::objects::hex32(&vci_core::object_id(bytes)) != id {
            return None;
        }
        Hdr::decode(bytes)
            .ok()
            .map(|h| (h.toolchain.os, h.toolchain.arch))
    }

    fn of(&self, store: &dyn AttestationStore, id: &str) -> Option<(String, String)> {
        if let Some(known) = self.0.lock().ok().and_then(|m| m.get(id).cloned()) {
            return known;
        }
        if store.caps().lazy_values {
            let _ = store.prefetch(Prefetch::Objects { ids: &[id] });
        }
        let found = store
            .get_objects(&[id])
            .ok()
            .and_then(|objects| objects.into_iter().find(|o| o.id == id))
            .and_then(|o| Self::platform_of(&o.id, &o.bytes));
        if let Ok(mut m) = self.0.lock() {
            m.insert(id.to_owned(), found.clone());
        }
        found
    }
}

/// After supersession, on a store with listing columns: remove the objects
/// the superseded records named that no record references any more
/// ([`AttestationStore::remove_objects`]: the orphan rule, with its hour
/// of grace), once per run. On git-meta, whose referrer scan reads every
/// value, they are left to `vci prune` (STORE-V2 section 2.2). Returns how
/// many were removed.
fn drop_orphan_objects(store: &dyn AttestationStore, ids: &BTreeSet<String>) -> usize {
    if ids.is_empty() || !store.caps().columns {
        return 0;
    }
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    match store.remove_objects(&ids) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("vci: warning: cannot remove the unreferenced objects: {e}");
            0
        }
    }
}

/// The state TTL of `vci run`'s orphan pass (STORE-V2 section 1.3): state
/// objects put more than `days` days ago are removed whether or not a
/// record references one (the records stay valid; `vci explain` then
/// prints the observed value without the attested hash). Returns how many
/// were removed.
fn prune_state_objects(store: &dyn AttestationStore, days: u32) -> usize {
    let older_than = std::time::Duration::from_secs(u64::from(days) * 86_400);
    match store.prune_state_objects(older_than) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("vci: warning: cannot remove the run's aged state objects: {e}");
            0
        }
    }
}

/// `items` for the runner: those without a recorded duration first, in
/// the given order (a new file may be long), then the rest longest first
/// (ties in the given order), so that a runner that takes several at once
/// does not end on its longest file.
fn longest_first<'a, T>(
    items: &[&'a T],
    key: impl Fn(&T) -> &str,
    durations: &BTreeMap<String, u64>,
) -> Vec<&'a T> {
    let mut out: Vec<&'a T> = items
        .iter()
        .copied()
        .filter(|t| !durations.contains_key(key(t)))
        .collect();
    let mut known: Vec<(usize, &'a T)> = items
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, t)| durations.contains_key(key(t)))
        .collect();
    known.sort_by(|(ia, a), (ib, b)| durations[key(b)].cmp(&durations[key(a)]).then(ia.cmp(ib)));
    out.extend(known.into_iter().map(|(_, t)| t));
    out
}

/// After supersession: delete the stored input manifests in `roots` that no
/// attestation left in the store references (git-meta: a tombstone each,
/// published by the next `vci push`), so the published tree does not keep
/// one orphan manifest per changed unit and commit. None is deleted when
/// what an attestation references is unknown (its value or payload cannot
/// be read), except one not fetched yet in a lazy clone, which is fetched
/// first when it could reference one of them
/// ([`AttestationStore::orphan_manifests`]). A clone that still holds an
/// attestation referencing one of them (made, or fetched, before it sees
/// the deletion) puts the manifest back when it merges the deletion in (see
/// `vci fetch`). Returns how many were deleted.
fn drop_orphan_manifests(store: &dyn AttestationStore, roots: &BTreeSet<String>) -> usize {
    if roots.is_empty() {
        return 0;
    }
    let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
    let orphans = match store.orphan_manifests(&roots) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("vci: warning: cannot read the store to remove unreferenced manifests: {e}");
            return 0;
        }
    };
    let orphans: Vec<&str> = orphans.iter().map(String::as_str).collect();
    // One session for all of them: a Rails run that superseded 2,400
    // attestations took a minute deleting their manifests one by one.
    match store.remove_manifests(&orphans) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("vci: warning: cannot remove the unreferenced input manifests: {e}");
            0
        }
    }
}

/// The units [`Selection::Units`] names, as indexes into `files`. A test id
/// the project does not list is an error: the caller planned to run it, and
/// it must not silently go unrun.
fn select_units(
    ctx: &Ctx,
    units: &BTreeMap<usize, Option<BTreeSet<String>>>,
    files: &[TestFile],
) -> Result<BTreeSet<usize>> {
    let mut out = BTreeSet::new();
    for (&pi, ids) in units {
        let Some(project) = ctx.projects.get(pi) else {
            bail!("no project #{pi} in the configuration");
        };
        let mine = files.iter().enumerate().filter(|(_, f)| f.project == pi);
        match ids {
            None => out.extend(mine.map(|(i, _)| i)),
            Some(ids) => {
                let hits: BTreeMap<&str, usize> =
                    mine.map(|(i, f)| (f.test_id.as_str(), i)).collect();
                for id in ids {
                    match hits.get(id.as_str()) {
                        Some(&i) => {
                            out.insert(i);
                        }
                        None => bail!(
                            "{id} is not a test unit of {} (not listed by the test runner)",
                            project.label()
                        ),
                    }
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defined_names_are_every_constant_path_after_defined() {
        let src = b"x = defined?(::Agent::Swarms::LandingHolds) && y\nreturn unless defined? SignalIntegration\nz = defined?(@ivar) || defined?(foo)\n";
        assert_eq!(
            scan_defined_names(src),
            ["agent", "landingholds", "signalintegration", "swarms"]
        );
    }

    #[test]
    fn longest_first_puts_unknown_then_longest() {
        let items = ["a", "b", "c", "d", "e"];
        let refs: Vec<&&str> = items.iter().collect();
        let d: BTreeMap<String, u64> = [("a", 5), ("c", 90), ("d", 5), ("e", 20)]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        let got: Vec<&str> = longest_first(&refs, |t| t, &d)
            .into_iter()
            .copied()
            .collect();
        assert_eq!(got, ["b", "c", "e", "a", "d"]);
        let none = BTreeMap::new();
        let got: Vec<&str> = longest_first(&refs, |t| t, &none)
            .into_iter()
            .copied()
            .collect();
        assert_eq!(got, items);
    }

    fn write(root: &Utf8Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    /// `vci run <units>` with a project that could not be listed: fail open
    /// when every unit resolved elsewhere, else the error names the listing
    /// failure too.
    #[test]
    fn unlisted_projects_fail_open_only_when_every_unit_resolved() {
        let unlisted = || {
            vec![(
                "rust".to_owned(),
                anyhow::anyhow!("cargo metadata failed").context("could not parse cargo workspace"),
            )]
        };
        let (selected, warnings) =
            settle_unlisted(Ok(BTreeSet::from([0, 2])), &unlisted()).unwrap();
        assert_eq!(selected, BTreeSet::from([0, 2]));
        assert_eq!(
            warnings,
            [
                "listing the test files of rust failed: could not parse cargo workspace: cargo metadata failed; none of the requested units is in it"
            ]
        );
        let e = settle_unlisted(
            Err(anyhow::anyhow!(
                "src/x.rs is not a test file of any project (not listed by the test runner)"
            )),
            &unlisted(),
        )
        .unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "src/x.rs is not a test file of any project (not listed by the test runner) (it may be in a project that could not be listed: listing the test files of rust failed: could not parse cargo workspace: cargo metadata failed)"
        );
        // Nothing failed to list: the result is unchanged.
        let (selected, warnings) = settle_unlisted(Ok(BTreeSet::from([1])), &[]).unwrap();
        assert_eq!((selected, warnings.len()), (BTreeSet::from([1]), 0));
        let e = settle_unlisted(Err(anyhow::anyhow!("x is not a test file")), &[]).unwrap_err();
        assert_eq!(format!("{e:#}"), "x is not a test file");
    }

    #[test]
    fn similar_taints_are_summarized() {
        let mut t: Vec<String> = vec![r#"native:FFI ffi_lib(["vips.42"])"#.into()];
        for i in 0..300 {
            t.push(format!(
                r#"native:FFI attach_function([:vips_f{i}, [:pointer]])"#
            ));
        }
        t.push("process:backtick".into());
        t.push("process:system".into());
        t.push("process:system".into());
        let refs: Vec<&String> = t.iter().collect();
        assert_eq!(
            summarize_taints(&refs),
            r#"native:FFI ffi_lib(["vips.42"]) (+300 more native:FFI), process:system (+1 more process:system), process:backtick"#
        );
        // Every reason is listed (no cap), most frequent first.
        let mut many: Vec<String> = (0..20).map(|i| format!("cat{i}:x {i}")).collect();
        many.push("cat19:x again".into());
        let refs: Vec<&String> = many.iter().collect();
        let s = summarize_taints(&refs);
        assert!(
            s.starts_with("cat19:x 19 (+1 more cat19:x), cat0:x 0, "),
            "{s}"
        );
        for i in 0..19 {
            assert!(s.contains(&format!("cat{i}:x {i}")), "{s}");
        }
    }

    #[test]
    fn taint_and_refusal_keys_are_stable_categories() {
        for (t, k) in [
            (
                r#"native:FFI attach_function([:vips_f0, [:pointer]])"#,
                "native:FFI",
            ),
            (r#"native:FFI::DynamicLibrary.open("x")"#, "native:FFI"),
            (
                "native:Fiddle::Function (C code called through Fiddle)",
                "native:Fiddle",
            ),
            ("native:libxml2:XSLT (xsl:include)", "native:libxml2"),
            ("cargo:process: Command::new in src/lib.rs", "cargo:process"),
            ("go:source: a.go uses Environ", "go:source"),
            ("go:net: net/http in the closure", "go:net"),
            (
                "vci:not-hooked:ffi (loaded where vci could not hook it)",
                "vci:not-hooked",
            ),
            (
                "vci:process-exit:2 (the process exited 2)",
                "vci:process-exit",
            ),
            (
                "external-without-version:/abs/x.js",
                "external-without-version",
            ),
            ("process:backtick", "process:backtick"),
            (
                "ruby:read-outside-bundle:stat /x (under a gem directory)",
                "ruby:read-outside-bundle",
            ),
            (
                "pytest:random-order(pytest-randomly)",
                "pytest:random-order",
            ),
            ("fs.readdir.recursive", "fs.readdir.recursive"),
            ("cargo: cannot list /x", "cargo"),
            ("exec: /bin/sh", "exec"),
            // vci's own refusals that ignore_taints can waive.
            (
                "outside-repository:/proc/sys/net/core/somaxconn",
                "outside-repository",
            ),
            ("outside-repository:/etc/lsb-release", "outside-repository"),
            (
                "wrote-inside-repository: web/node_modules/other.txt, out-dir",
                "wrote-inside-repository",
            ),
            ("result:skipped:1 of 4", "result:skipped"),
        ] {
            assert_eq!(taint_key(t), k, "{t}");
        }
        for (m, k) in [
            // The refusals ignore_taints waives: keyed by the pattern.
            (
                "input outside the repository: /etc/hosts",
                "outside-repository",
            ),
            ("result failed (1 failed of 3)", "result failed"),
            (
                "result passed (0 failed, 1 skipped or xfailed of 2; a skipped test did not run)",
                "result:skipped",
            ),
            (
                "result no-tests (0 tests; no test ran or some were filtered out, so the run cannot vouch for the unit)",
                "result:no-tests",
            ),
            (
                "result filtered (0 tests; no test ran or some were filtered out, so the run cannot vouch for the unit)",
                "result filtered",
            ),
            // A failed result with skips is a failure, never waivable.
            (
                "result failed (1 failed, 1 skipped or xfailed of 3; a skipped test did not run)",
                "result failed",
            ),
            (
                "wrote inside the repository: out.txt",
                "wrote-inside-repository",
            ),
            (
                "platform-specific file outside the repository: /x/y_linux.go",
                "platform-specific file outside the repository",
            ),
            (
                "collector root /x is not the project dir",
                "collector root is not the project dir",
            ),
            (
                "its source refers to /x, outside the repository (seen)",
                "source refers to a path that is not an input",
            ),
            (
                "the collector produced no output for it",
                "the collector produced no output for it",
            ),
            (
                "foo is built from a local directory or file (uv.lock)",
                "external built from a local directory",
            ),
        ] {
            assert_eq!(refusal_key(m), k, "{m}");
        }
    }

    #[test]
    fn summary_lists_every_unit_and_counts_files_per_reason() {
        let unit = |id: &str, attested: bool, reasons: &[&str]| UnitOutcome {
            test_id: id.into(),
            project: None,
            adapter: "rails",
            attested,
            stored: true,
            reasons: reasons.iter().map(|r| (*r).to_owned()).collect(),
            detail: (!attested).then(|| "tainted: ...".to_owned()),
            taints: vec![],
            waived: if attested {
                vec!["process:system".to_owned()]
            } else {
                vec![]
            },
        };
        let outcomes = [
            unit("a", true, &[]),
            unit("b", false, &["native:FFI", "process:system"]),
            unit("c", false, &["native:FFI"]),
            unit("d", false, &["result failed"]),
        ];
        assert_eq!(
            reason_counts(&outcomes),
            [
                ("native:FFI".to_owned(), 2),
                ("process:system".to_owned(), 1),
                ("result failed".to_owned(), 1)
            ]
        );
        let v = summary_json(&outcomes);
        assert_eq!(v["attested"], 1);
        assert_eq!(v["notAttested"], 3);
        assert_eq!(v["units"].as_array().unwrap().len(), 4);
        assert_eq!(v["units"][1]["reasons"][1], "process:system");
        assert_eq!(v["reasons"][0]["reason"], "native:FFI");
        assert_eq!(v["reasons"][0]["files"], 2);
        assert_eq!(v["units"][0]["waived"][0], "process:system");
        assert_eq!(v["units"][1]["waived"].as_array().unwrap().len(), 0);
        // Stored (or refused): no `stored` field, as before.
        assert!(v["units"][0].get("stored").is_none(), "{v}");
        assert!(v["units"][1].get("stored").is_none(), "{v}");
    }

    fn policy(toml: &str) -> crate::config::Policy {
        crate::config::Config::parse(toml).unwrap().project_specs()[0]
            .policy
            .clone()
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn split_waived_by_ignore_taints() {
        let taints = strings(&[
            "process:system",
            "process:backtick",
            "native:FFI attach_function(x)",
            "network:pg client (a database connection the test opened itself)",
            "vci:not-hooked:ffi (x)",
            "external-without-version:/abs/x.js",
        ]);
        let split = |toml: &str, adapter: &str| {
            let p = policy(toml);
            let (w, r) = split_waived_taints(&p, adapter, &[], &taints);
            (
                w.into_iter().cloned().collect::<Vec<_>>(),
                r.into_iter().cloned().collect::<Vec<_>>(),
            )
        };
        // Default: nothing waived.
        let (w, r) = split("[policy]\n", "rails");
        assert!(w.is_empty());
        assert_eq!(r, taints);
        // A glob over the kind, and an exact key.
        let (w, r) = split(
            "[policy]\nignore_taints = [\"process:*\", \"external-without-version\"]\n",
            "rails",
        );
        assert_eq!(
            w,
            strings(&[
                "process:system",
                "process:backtick",
                "external-without-version:/abs/x.js"
            ])
        );
        assert_eq!(r.len(), 3);
        // A category-only pattern.
        let (w, _) = split(
            "[policy]\nignore_taints = [\"native\", \"network\"]\n",
            "rails",
        );
        assert_eq!(w.len(), 2);
        assert!(w[0].starts_with("native:FFI") && w[1].starts_with("network:pg"));
        // A pattern with a kind matches that kind only.
        let (w, _) = split("[policy]\nignore_taints = [\"process:system\"]\n", "rails");
        assert_eq!(w, ["process:system"]);
        // "*" waives everything but vci's own taints.
        let (w, r) = split("[policy]\nignore_taints = [\"*\"]\n", "rails");
        assert_eq!(w.len(), 5);
        assert_eq!(r, ["vci:not-hooked:ffi (x)"]);
    }

    /// vci's own refusals that are taints: waived by their key (or a
    /// category pattern, or "*"), never by another key.
    #[test]
    fn split_waived_outside_writes_and_skips() {
        let taints = strings(&[
            "outside-repository:/proc/self/exe",
            "outside-repository:/etc/alpine-release",
            "wrote-inside-repository: web/node_modules/other.txt",
            "result:skipped:1 of 4",
        ]);
        let waived = |toml: &str| {
            let p = policy(toml);
            split_waived_taints(&p, "node-test", &[], &taints)
                .0
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        assert!(waived("[policy]\n").is_empty());
        assert_eq!(
            waived("[policy]\nignore_taints = [\"outside-repository\"]\n"),
            &taints[..2]
        );
        assert_eq!(
            waived("[policy]\nignore_taints = [\"wrote-inside-repository\"]\n"),
            &taints[2..3]
        );
        assert_eq!(
            waived("[policy]\nignore_taints = [\"result:skipped\"]\n"),
            &taints[3..]
        );
        // The category pattern "result" is result:* (only skips are taints).
        assert_eq!(
            waived("[policy]\nignore_taints = [\"result\"]\n"),
            &taints[3..]
        );
        assert_eq!(waived("[policy]\nignore_taints = [\"*\"]\n"), taints);
        // The key is the category: patterns are not matched against paths.
        assert!(waived("[policy]\nignore_taints = [\"outside-repository:/proc/*\"]\n").is_empty());
        assert!(waived("[policy]\nignore_taints = [\"wrote-inside\"]\n").is_empty());
    }

    #[test]
    fn tool_caches_under_node_modules_are_not_writes() {
        for w in [
            "node_modules/.vite",
            "node_modules/.vite/deps_temp_1a2b/react.js",
            "vex-web/node_modules/.vite-temp",
            "vex-web/node_modules/.vite-temp/vite.config.ts.timestamp-1.mjs",
            "a/b/node_modules/.cache/babel-loader/x.json",
        ] {
            assert!(is_tool_cache_write(w), "{w}");
        }
        for w in [
            "node_modules/other.txt",
            "node_modules/.vitest/x",
            "node_modules/pkg/.cache/x",
            ".vite/x",
            "src/node_modules.vite",
            "out.txt",
        ] {
            assert!(!is_tool_cache_write(w), "{w}");
        }
    }

    #[test]
    fn outside_paths_are_found_once_and_pruned() {
        let root = Utf8Path::new("/r");
        let mut o = Observed::default();
        o.reads.insert("/etc/hosts".into());
        o.reads.insert("/r/a.txt".into());
        o.stats.insert("/etc/hosts".into());
        o.probes.insert("/proc/self/exe".into());
        o.readdirs.insert("/r/out".into());
        o.reads.insert("/r/out/x".into());
        let out: Vec<&str> = outside_repository(root, &o)
            .into_iter()
            .map(|p| p.as_str())
            .collect();
        assert_eq!(out, ["/etc/hosts", "/proc/self/exe"]);
        let pruned = without_paths(
            &o,
            &[
                "/etc/hosts".into(),
                "/proc/self/exe".into(),
                "/r/out".into(),
            ],
        );
        assert!(outside_repository(root, &pruned).is_empty());
        assert_eq!(
            pruned.reads.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
            ["/r/a.txt"]
        );
        assert!(pruned.readdirs.is_empty() && pruned.stats.is_empty());
    }

    #[test]
    fn go_allow_net_is_ignore_taints_go_net() {
        let taints = strings(&[
            "go:net: the test links package net (...)",
            "go:syscall: x imports syscall",
            "exec: /bin/sh",
        ]);
        let waived = |toml: &str| {
            let p = policy(toml);
            split_waived_taints(&p, "go", &[], &taints)
                .0
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        let by_flag = waived("adapter = \"go\"\n[policy]\ngo_allow_net = true\n");
        let by_key = waived("adapter = \"go\"\n[policy]\nignore_taints = [\"go:net\"]\n");
        assert_eq!(by_flag, ["go:net: the test links package net (...)"]);
        assert_eq!(by_flag, by_key);
        assert_eq!(
            waived("adapter = \"go\"\n[policy]\nignore_taints = [\"go\", \"exec\"]\n").len(),
            3
        );
        assert!(waived("adapter = \"go\"\n").is_empty());
        // go_allow_net only concerns Go units.
        let p = policy("[policy]\ngo_allow_net = true\n");
        assert!(split_waived_taints(&p, "vitest", &[], &taints).0.is_empty());
    }

    #[test]
    fn cargo_declared_inputs_still_waive_undeclared_reads() {
        let taints = strings(&["cargo:undeclared-reads (x)", "cargo:process: Command::new"]);
        let p = policy("adapter = \"cargo\"\n");
        let declared = strings(&["testdata/**"]);
        let (w, r) = split_waived_taints(&p, "cargo", &declared, &taints);
        assert_eq!((w.len(), r.len()), (1, 1));
        let (w, _) = split_waived_taints(&p, "cargo", &[], &taints);
        assert!(w.is_empty());
        let p = policy("adapter = \"cargo\"\n[policy]\nignore_taints = [\"cargo:*\"]\n");
        let (w, r) = split_waived_taints(&p, "cargo", &[], &taints);
        assert_eq!((w.len(), r.len()), (2, 0));
    }

    #[test]
    fn in_order_sinks_every_result_in_the_items_order() {
        // Later items finish first; each is sunk once, in order, on the
        // calling thread, whatever the number of jobs.
        let items: Vec<u64> = (0..40).collect();
        let me = std::thread::current().id();
        for jobs in [1, 3, 8, 64] {
            let mut got = Vec::new();
            in_order(
                &items,
                jobs,
                |&i| {
                    std::thread::sleep(std::time::Duration::from_millis((40 - i) % 7));
                    i * 10
                },
                |i, r| {
                    assert_eq!(std::thread::current().id(), me);
                    got.push((i, r));
                },
            );
            let want: Vec<(usize, u64)> = (0..40).map(|i| (i as usize, i * 10)).collect();
            assert_eq!(got, want, "jobs {jobs}");
        }
        // One job: each result is sunk before the next item is worked on.
        let worked = std::sync::atomic::AtomicUsize::new(0);
        in_order(
            &items,
            1,
            |_| worked.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            |i, n| {
                assert_eq!(n, i);
                assert_eq!(worked.load(std::sync::atomic::Ordering::SeqCst), i + 1);
            },
        );
        in_order(&[] as &[u64], 4, |_| 0, |_, _: u64| panic!("no items"));
    }

    #[test]
    fn cached_checkout_answers_as_the_direct_one() {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(dir.path()).unwrap().to_owned();
        let git = |args: &[&str]| {
            let st = std::process::Command::new("git")
                .arg("-C")
                .arg(root.as_str())
                .args(args)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(st.success(), "git {args:?}");
        };
        git(&["init", "-q"]);
        write(&root, ".gitignore", "*.log\nbuild/\n");
        write(&root, "src/a.rb", "a");
        write(&root, "src/b.log", "b");
        write(&root, "build/out.txt", "o");
        let direct = Checkout::direct(&root);
        let cached = Checkout::cached(&root);
        let paths: Vec<String> = [
            "src/a.rb",
            "src/b.log",
            "build",
            "build/out.txt",
            "nope.log",
        ]
        .iter()
        .map(|p| (*p).to_owned())
        .collect();
        let want = direct.git_ignored(&paths);
        assert_eq!(want, ["src/b.log", "build", "build/out.txt", "nope.log"]);
        // Asked twice (the second time from the cache), and in parts.
        assert_eq!(cached.git_ignored(&paths), want);
        assert_eq!(cached.git_ignored(&paths), want);
        assert_eq!(cached.git_ignored(&paths[1..3]), want[..2]);
        let observed = vec![
            (RepoPath::new("src").unwrap(), Observation::ReadDir),
            (RepoPath::new("src/a.rb").unwrap(), Observation::Read),
        ];
        assert_eq!(
            ignored_children(&cached, &observed),
            ignored_children(&direct, &observed)
        );
        assert_eq!(
            ignored_children(&cached, &observed),
            [(RepoPath::new("src/b.log").unwrap(), Observation::Exclude)]
        );
        let mut obs = observed.clone();
        obs.extend(ignored_children(&direct, &observed));
        let m = direct.capture(&obs, vec![], &[], |_: &str| None).unwrap();
        assert_eq!(
            cached.capture(&obs, vec![], &[], |_: &str| None).unwrap(),
            m
        );
        assert_eq!(
            cached.capture(&obs, vec![], &[], |_: &str| None).unwrap(),
            m
        );
        assert_eq!(
            ignored_listing_children(&cached, &m),
            ignored_listing_children(&direct, &m)
        );
        assert!(junk_in_listings(&cached, &m).is_empty());
        // Not a repository: git answers nothing, and nothing is kept.
        let plain = tempfile::tempdir().unwrap();
        let proot = Utf8Path::from_path(plain.path()).unwrap();
        let c = Checkout::cached(proot);
        assert!(c.git_ignored(&paths).is_empty());
        assert!(locked(&c.cache.as_ref().unwrap().ignored).is_empty());
    }

    #[test]
    fn waived_note_names_the_first_key_and_counts_the_others() {
        assert_eq!(waived_note(&[]), "");
        assert_eq!(
            waived_note(&strings(&["child_process.execSync"])),
            "child_process.execSync"
        );
        assert_eq!(
            waived_note(&strings(&[
                "process:spawn",
                "process:system",
                "process:system",
                "native:FFI a",
                "fetch"
            ])),
            "process:system, +3"
        );
    }

    #[test]
    fn rails_key_files() {
        for p in [
            "config/master.key",
            "app/config/master.key",
            "config/credentials/test.key",
            "shop/config/credentials/production.key",
        ] {
            assert!(is_rails_key_file(p), "{p}");
        }
        for p in [
            "config/master.key.bak",
            "lib/config/credentials/x/test.key",
            "config/credentials/test.yml.enc",
            "notconfig/master.key",
            "master.key",
        ] {
            assert!(!is_rails_key_file(p), "{p}");
        }
    }

    /// `[[inputs]] extra` globs: a literal file, a missing path, and a glob
    /// whose fixed prefix is walked (listings for new files, matching files
    /// read); coverage of paths a unit's source names.
    #[test]
    fn declared_inputs_expand_and_cover() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        write(&root, "rs/shared/x.json", "{}");
        write(&root, "rs/data/a.txt", "a");
        write(&root, "rs/data/sub/b.txt", "b");
        write(&root, "rs/data/sub/c.bin", "c");
        write(&root, "rs/target/debug/out.txt", "o");
        let proj = root.join("rs");
        let globs = [
            "shared/x.json".to_owned(),
            "missing.txt".to_owned(),
            "data/**/*.txt".to_owned(),
        ];
        let obs = expand_extra_inputs(&root, &proj, &globs, &[proj.join("target")]).unwrap();
        let get = |p: &str| obs.iter().find(|(rp, _)| rp.as_str() == p).map(|(_, o)| *o);
        assert_eq!(get("rs/shared/x.json"), Some(Observation::Read));
        assert_eq!(get("rs/missing.txt"), Some(Observation::Probe));
        assert_eq!(get("rs/data"), Some(Observation::ReadDir));
        assert_eq!(get("rs/data/sub"), Some(Observation::ReadDir));
        assert_eq!(get("rs/data/a.txt"), Some(Observation::Read));
        assert_eq!(get("rs/data/sub/b.txt"), Some(Observation::Read));
        assert_eq!(get("rs/data/sub/c.bin"), None, "does not match the glob");
        let all =
            expand_extra_inputs(&root, &proj, &["**".to_owned()], &[proj.join("target")]).unwrap();
        assert!(
            !all.iter().any(|(p, _)| p.as_str().starts_with("rs/target")),
            "{all:?}"
        );
        let m = InputManifest::capture(&root, &obs, vec![], &[]).unwrap();
        let rp = |p: &str| RepoPath::new(p).unwrap();
        assert!(covered(&root, &m, &rp("rs/shared/x.json")));
        assert!(covered(&root, &m, &rp("rs/missing.txt")));
        assert!(
            covered(&root, &m, &rp("rs/data/new.txt")),
            "absent, parent listed"
        );
        assert!(!covered(&root, &m, &rp("rs/data")), "c.bin is not recorded");
        assert!(
            !covered(&root, &m, &rp("rs/shared/other.json")),
            "its directory is not listed"
        );
        assert!(!covered(&root, &m, &rp("elsewhere/x")));
        std::fs::remove_file(root.join("rs/data/sub/c.bin")).unwrap();
        assert!(
            covered(&root, &m, &rp("rs/data")),
            "everything below is recorded"
        );
    }

    /// Regression: resolution driven by package.json (`imports`, a workspace
    /// package's `main`/`exports`) and per-directory tsconfig files were not
    /// inputs, so changing them left the test skipped.
    #[test]
    fn modules_bring_their_package_json_and_tsconfig() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        write(&root, "package.json", "{}");
        write(
            &root,
            "packages/lib/package.json",
            r#"{"name":"@me/lib","main":"./a.js"}"#,
        );
        write(&root, "packages/lib/a.js", "export default 'a';\n");
        write(
            &root,
            "src/atk/pkgimp/package.json",
            r##"{"imports":{"#dep":"./dep-a.ts"}}"##,
        );
        write(&root, "src/atk/pkgimp/imp.test.ts", "import '#dep';\n");
        write(
            &root,
            "src/atk/tsc/tsconfig.json",
            r#"{"extends":"../base.json"}"#,
        );
        write(&root, "src/atk/base.json", "{}");
        write(&root, "src/atk/tsc/cls.ts", "export class A {}\n");
        write(&root, "src/atk/x.ts", "export {};\n");
        let o = Observed {
            shared_group: None,
            modules: [
                "packages/lib/a.js",
                "src/atk/pkgimp/imp.test.ts",
                "src/atk/tsc/cls.ts",
                "src/atk/x.ts",
            ]
            .iter()
            .map(|p| root.join(p))
            .collect(),
            ..Default::default()
        };
        let obs = observations(&root, &o).unwrap();
        let get = |p: &str| obs.iter().find(|(rp, _)| rp.as_str() == p).map(|(_, o)| *o);
        for (p, want) in [
            ("packages/lib/package.json", Observation::Read),
            ("src/atk/pkgimp/package.json", Observation::Read),
            ("src/atk/tsc/package.json", Observation::Probe),
            ("src/atk/package.json", Observation::Probe),
            ("src/package.json", Observation::Probe),
            ("package.json", Observation::Read),
            ("src/atk/tsc/tsconfig.json", Observation::Read),
            ("src/atk/base.json", Observation::Read),
            ("src/atk/tsconfig.json", Observation::Probe),
        ] {
            assert_eq!(get(p), Some(want), "{p}: {obs:?}");
        }
    }

    // ---- the store loop (deferred batches, the publication gate) ----------

    const SIGNER: &str = "0123456789abcdef";

    fn owner() -> Owner {
        Owner {
            project: None,
            adapter: "go",
        }
    }

    fn root(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn unit(label: &str, manifest: &InputManifest, root: &str) -> ToStore {
        ToStore {
            label: label.to_owned(),
            test_id: label.to_owned(),
            input_root: root.to_owned(),
            entries: manifest.entries.len(),
            manifest: Some(manifest.to_compact()),
            storage_key: "abcd".to_owned(),
            hint: Some(KeyHint {
                issued: 7,
                tree: None,
            }),
            envelope: format!("{{\"unit\":\"{label}\"}}").into_bytes(),
            columns: None,
            doomed: vec![],
            doomed_objects: BTreeMap::new(),
            waived: vec![],
        }
    }

    /// An earlier attestation of `label` in `s`, by the same signer, for a
    /// unit to supersede.
    fn earlier(s: &crate::store::mem::MemStore, label: &str) -> StoredEnvelope {
        s.put_for_test(label, SIGNER, "ef01", None, b"old").unwrap()
    }

    /// The lines a store loop says, collected.
    #[derive(Default)]
    struct Said(std::cell::RefCell<Vec<String>>);

    impl Said {
        fn lines(&self) -> Vec<String> {
            self.0.borrow().clone()
        }
    }

    /// With a deferred batch, nothing is reported before the batch
    /// finishes; then every unit is, in unit order (warnings, refusals and
    /// stored units alike, as an immediate batch says them), with what it
    /// superseded, and the refusals keep their place in the outcomes.
    #[test]
    fn a_deferred_batch_reports_in_order_once_it_finishes() {
        let s = crate::store::mem::MemStore::new().deferred(true);
        let old = earlier(&s, "src/a.test.ts");
        let m = InputManifest::default();
        let (ra, rc) = (root('a'), root('c'));
        let said = Said::default();
        let mut say = |l: &str| said.0.borrow_mut().push(l.to_owned());
        let mut sl = StoreLoop::new(&s, StoreMode::Write, SIGNER, owner(), &mut say);
        let mut a = unit("src/a.test.ts", &m, &ra);
        a.doomed = vec![old.clone()];
        sl.attest(a);
        sl.refuse(
            "src/b.test.ts",
            "result failed".into(),
            vec!["result failed".into()],
            vec![],
        );
        sl.apply(Job::Attestable {
            warnings: vec!["vci: warning: src/c.test.ts: w".into()],
            unit: Ok(Box::new(unit("src/c.test.ts", &m, &rc))),
        });
        // Not stored yet, so nothing is reported yet.
        assert_eq!(s.keys(), std::slice::from_ref(&old.key));
        assert!(said.lines().is_empty(), "{:?}", said.lines());
        let done = sl.finish();
        assert_eq!((done.attested, done.refused, done.superseded), (2, 1, 1));
        assert!(done.errors.is_empty());
        let lines = said.lines();
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert_eq!(lines[1], "vci: not attesting src/b.test.ts: result failed");
        assert_eq!(lines[2], "vci: warning: src/c.test.ts: w");
        assert!(
            lines[0].starts_with(&format!(
                "vci: attested src/a.test.ts (0 inputs, root {}) as memory path:src/a.test.ts vci:attestation:",
                &ra[..16]
            )),
            "{lines:?}"
        );
        assert!(
            lines[3].starts_with("vci: attested src/c.test.ts "),
            "{lines:?}"
        );
        let ids: Vec<(&str, bool)> = done
            .outcomes
            .iter()
            .map(|o| (o.test_id.as_str(), o.attested))
            .collect();
        assert_eq!(
            ids,
            [
                ("src/a.test.ts", true),
                ("src/b.test.ts", false),
                ("src/c.test.ts", true)
            ]
        );
        // Both stored, the superseded one removed, the manifests first.
        let keys = s.keys();
        assert_eq!(keys.len(), 2, "{keys:?}");
        assert!(!keys.contains(&old.key));
        assert_eq!(s.roots(), [ra, rc]);
    }

    /// A batch whose writes were stored and whose end then failed (git-meta
    /// re-stamping its log after the commit) refuses nothing: every unit is
    /// attested and reported, and the failure is a warning after them, not
    /// an error of the run.
    #[test]
    fn a_failure_after_the_batch_stored_its_writes_is_a_warning() {
        let s = crate::store::mem::MemStore::new()
            .deferred(true)
            .warning(Some(
                "stamping the 2 write(s) of the batch after its commit: refused",
            ));
        let m = InputManifest::default();
        let (ra, rc) = (root('a'), root('c'));
        let said = Said::default();
        let mut say = |l: &str| said.0.borrow_mut().push(l.to_owned());
        let mut sl = StoreLoop::new(&s, StoreMode::Write, SIGNER, owner(), &mut say);
        sl.attest(unit("src/a.test.ts", &m, &ra));
        sl.attest(unit("src/c.test.ts", &m, &rc));
        let done = sl.finish();
        assert_eq!((done.attested, done.refused), (2, 0));
        assert!(done.errors.is_empty(), "{:?}", done.errors);
        assert!(done.store_failures.is_empty(), "{:?}", done.store_failures);
        assert!(done.outcomes.iter().all(|o| o.attested && o.stored));
        let lines = said.lines();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(
            lines[0].starts_with("vci: attested src/a.test.ts "),
            "{lines:?}"
        );
        assert!(
            lines[1].starts_with("vci: attested src/c.test.ts "),
            "{lines:?}"
        );
        assert_eq!(
            lines[2],
            "vci: warning: stamping the 2 write(s) of the batch after its commit: refused"
        );
        assert_eq!(s.keys().len(), 2);
    }

    /// A deferred batch that fails stored nothing: every unit it held is
    /// refused, the counts say so, the summary claims none of them, and
    /// what they would have superseded stays. (A store that went away is
    /// one that cannot be used: a store failure, not an error of the run.)
    #[test]
    fn a_failed_deferred_batch_refuses_every_unit_it_held() {
        let s = crate::store::mem::MemStore::new()
            .deferred(true)
            .failing(Some("the server went away"));
        let old = earlier(&s, "src/a.test.ts");
        let m = InputManifest::default();
        let (ra, rc) = (root('a'), root('c'));
        let said = Said::default();
        let mut say = |l: &str| said.0.borrow_mut().push(l.to_owned());
        let mut sl = StoreLoop::new(&s, StoreMode::Write, SIGNER, owner(), &mut say);
        let mut a = unit("src/a.test.ts", &m, &ra);
        a.doomed = vec![old.clone()];
        sl.attest(a);
        sl.refuse(
            "src/b.test.ts",
            "result failed".into(),
            vec!["result failed".into()],
            vec![],
        );
        sl.attest(unit("src/c.test.ts", &m, &rc));
        let done = sl.finish();
        assert_eq!((done.attested, done.refused, done.superseded), (0, 3, 0));
        assert!(done.errors.is_empty(), "{:?}", done.errors);
        assert_eq!(done.store_failures.len(), 2, "{:?}", done.store_failures);
        assert!(done.dropped_roots.is_empty());
        let why = "storing the batch: memory store unavailable: the server went away";
        assert_eq!(done.store_failures[0], format!("src/a.test.ts: {why}"));
        let lines = said.lines();
        assert!(
            lines.iter().all(|l| !l.starts_with("vci: attested")),
            "{lines:?}"
        );
        assert!(
            lines.contains(&format!(
                "vci: not attesting src/c.test.ts: signing or storing failed: {why}"
            )),
            "{lines:?}"
        );
        let v = summary_json(&done.outcomes);
        assert_eq!(v["attested"], 0);
        assert_eq!(v["notAttested"], 3);
        let units = v["units"].as_array().unwrap();
        assert!(units.iter().all(|u| u["attested"] == false), "{v}");
        assert_eq!(units[0]["testId"], "src/a.test.ts");
        assert_eq!(
            units[0]["detail"],
            format!("signing or storing failed: {why}")
        );
        assert_eq!(units[0]["reasons"][0], "signing or storing failed");
        // Nothing of the batch stored; the earlier attestation kept.
        assert_eq!(s.keys(), [old.key]);
        assert!(s.roots().is_empty());
    }

    /// A deferred batch that lost one unit's writes and stored the rest
    /// (the libSQL store writes a batch as several short transactions)
    /// refuses that unit alone: the others are attested and reported, and
    /// what the lost one would have superseded stays.
    #[test]
    fn a_batch_that_loses_one_unit_refuses_it_alone() {
        let s = crate::store::mem::MemStore::new()
            .deferred(true)
            .losing(Some("src/a.test.ts"));
        let old = earlier(&s, "src/a.test.ts");
        let m = InputManifest::default();
        let (ra, rc) = (root('a'), root('c'));
        let said = Said::default();
        let mut say = |l: &str| said.0.borrow_mut().push(l.to_owned());
        let mut sl = StoreLoop::new(&s, StoreMode::Write, SIGNER, owner(), &mut say);
        let mut a = unit("src/a.test.ts", &m, &ra);
        a.doomed = vec![old.clone()];
        sl.attest(a);
        sl.attest(unit("src/c.test.ts", &m, &rc));
        let done = sl.finish();
        assert_eq!((done.attested, done.refused, done.superseded), (1, 1, 0));
        assert!(done.errors.is_empty(), "{:?}", done.errors);
        assert_eq!(done.store_failures.len(), 1, "{:?}", done.store_failures);
        let why = "storing the batch: memory store unavailable: a write timed out";
        assert_eq!(done.store_failures[0], format!("src/a.test.ts: {why}"));
        let lines = said.lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(
            lines[0],
            format!("vci: not attesting src/a.test.ts: signing or storing failed: {why}")
        );
        assert!(
            lines[1].starts_with("vci: attested src/c.test.ts "),
            "{lines:?}"
        );
        let ids: Vec<(&str, bool)> = done
            .outcomes
            .iter()
            .map(|o| (o.test_id.as_str(), o.attested))
            .collect();
        assert_eq!(ids, [("src/a.test.ts", false), ("src/c.test.ts", true)]);
        // c stored, a's earlier attestation kept.
        let keys = s.keys();
        assert_eq!(keys.len(), 2, "{keys:?}");
        assert!(keys.contains(&old.key));
    }

    /// A store that cannot be used refuses its units without failing the
    /// run; any other failure to sign or store (git-meta's own errors,
    /// signing) is an error of the run, as before.
    #[test]
    fn failures_of_a_store_that_cannot_be_used_keep_the_exit_code() {
        let s = crate::store::mem::MemStore::new();
        let said = Said::default();
        let mut say = |l: &str| said.0.borrow_mut().push(l.to_owned());
        let mut sl = StoreLoop::new(&s, StoreMode::Write, SIGNER, owner(), &mut say);
        let unusable = [
            StoreError::unavailable("postgres", "not implemented yet"),
            StoreError::Config("no URL".into()),
            StoreError::Denied {
                backend: "postgres",
                operation: "write",
                detail: "read-only role".into(),
            },
        ];
        for e in unusable {
            sl.failed(
                "src/a.test.ts",
                &anyhow::Error::from(e).context("storing the input manifest"),
            );
        }
        sl.failed("src/b.test.ts", &anyhow::anyhow!("ssh-keygen failed"));
        sl.failed(
            "src/c.test.ts",
            &anyhow::Error::from(StoreError::Other("git-meta store: locked".into())),
        );
        sl.failed(
            "src/d.test.ts",
            &anyhow::Error::from(StoreError::invalid("signer_id", "x", "bad")),
        );
        let lines = said.lines();
        let done = sl.finish();
        assert_eq!(done.refused, 6);
        assert_eq!(done.store_failures.len(), 3, "{:?}", done.store_failures);
        assert_eq!(done.errors.len(), 3, "{:?}", done.errors);
        assert_eq!(
            lines[0],
            "vci: not attesting src/a.test.ts: signing or storing failed: storing the input manifest: postgres store unavailable: not implemented yet"
        );
        assert_eq!(
            lines[3],
            "vci: error: not attesting src/b.test.ts: ssh-keygen failed"
        );
        assert!(
            done.outcomes
                .iter()
                .all(|o| o.reasons == ["signing or storing failed"])
        );
    }

    /// With an immediate batch (git-meta's), each unit is stored and
    /// reported at once, as before.
    #[test]
    fn an_immediate_batch_reports_each_unit_as_it_is_stored() {
        let s = crate::store::mem::MemStore::new();
        let m = InputManifest::default();
        let ra = root('a');
        let said = Said::default();
        let mut say = |l: &str| said.0.borrow_mut().push(l.to_owned());
        let mut sl = StoreLoop::new(&s, StoreMode::Write, SIGNER, owner(), &mut say);
        sl.attest(unit("src/a.test.ts", &m, &ra));
        assert_eq!(s.keys().len(), 1);
        assert_eq!(said.lines().len(), 1);
        assert!(said.lines()[0].starts_with("vci: attested src/a.test.ts "));
        let done = sl.finish();
        assert_eq!((done.attested, done.refused), (1, 0));
        assert!(done.outcomes[0].stored);
    }

    /// Signing only (`vci ci` without --push on a shared store): no write
    /// method is called and no batch opened; the units count as attested,
    /// not stored, and nothing claims they were.
    #[test]
    fn signing_only_writes_nothing() {
        let s = crate::store::mem::MemStore::new()
            .shared(true)
            .deferred(true);
        let m = InputManifest::default();
        let (ra, rc) = (root('a'), root('c'));
        let said = Said::default();
        let mut say = |l: &str| said.0.borrow_mut().push(l.to_owned());
        let mut sl = StoreLoop::new(&s, StoreMode::SignOnly, SIGNER, owner(), &mut say);
        sl.attest(unit("src/a.test.ts", &m, &ra));
        sl.refuse(
            "src/b.test.ts",
            "result failed".into(),
            vec!["result failed".into()],
            vec![],
        );
        let mut c = unit("src/c.test.ts", &m, &rc);
        c.doomed = vec![
            StoredEnvelope::from_key(
                "path:src/c.test.ts",
                &vci_store::attestation_key(&vci_core::test_key("src/c.test.ts"), SIGNER, "ef01"),
            )
            .unwrap(),
        ];
        sl.attest(c);
        let done = sl.finish();
        assert_eq!(s.writes(), 0, "no write method and no batch");
        assert!(s.keys().is_empty() && s.roots().is_empty());
        assert_eq!(
            (
                done.attested,
                done.signed_only,
                done.refused,
                done.superseded
            ),
            (2, 2, 1, 0)
        );
        assert!(
            said.lines().iter().all(|l| !l.starts_with("vci: attested")),
            "{:?}",
            said.lines()
        );
        let v = summary_json(&done.outcomes);
        assert_eq!(v["units"][0]["attested"], true);
        assert_eq!(v["units"][0]["stored"], false);
        assert!(v["units"][1].get("stored").is_none());
        assert_eq!(v["units"][2]["stored"], false);
    }

    // ---- format 3 ------------------------------------------------------

    /// A unit as `check_one` makes one, over `files` (its own entries),
    /// `globals` (its global manifest's) and `waived`: a go unit on linux,
    /// passed in 42 ms.
    fn sample_attestable(
        test_id: &str,
        globals: &[&str],
        files: &[&str],
        waived: &[&str],
    ) -> Attestable {
        let entry = |p: &str| vci_core::InputEntry {
            path: RepoPath::new(p).unwrap(),
            kind: vci_core::EntryKind::File,
            exec: false,
            size: 3,
            hash: vci_core::blake3_hex(p.as_bytes()),
        };
        let gm = InputManifest {
            entries: globals.iter().map(|p| entry(p)).collect(),
            externals: vec![],
            env: vec![],
        };
        let manifest = InputManifest {
            entries: files.iter().map(|p| entry(p)).collect(),
            externals: vec![External {
                name: crate::ctx::CONFIG_EXTERNAL.to_owned(),
                version: "cfg".to_owned(),
            }],
            env: vec![vci_core::EnvEntry {
                key: "TZ".to_owned(),
                hash: vci_core::ABSENT_HASH.to_owned(),
            }],
        };
        let core = Predicate {
            tool_version: TOOL_VERSION.to_owned(),
            adapter: "go".to_owned(),
            test_id: test_id.to_owned(),
            argv: vec!["go".to_owned(), "test".to_owned()],
            repo_id: "r".repeat(64),
            commit: "c".repeat(40),
            tree_dirty: false,
            tree: Some("d".repeat(40)),
            toolchain: Toolchain {
                os: "linux".to_owned(),
                arch: "x86_64".to_owned(),
                go: "1.26.0".to_owned(),
                ..Default::default()
            },
            global_input_root: gm.root(),
            input_root: manifest.root(),
            manifest: None,
            manifest_ref: Some(manifest.root()),
            global_manifest: gm,
            result: vci_core::TestResult {
                state: "passed".to_owned(),
                tests: 2,
                failed: 0,
                skipped: 0,
                duration_ms: 42,
            },
            tainted: vec![],
            issued_at: rfc3339(1_800_000_000),
            expires_at: rfc3339(1_800_000_000 + 86_400),
        };
        Attestable {
            predicate: VciPredicate {
                core,
                env_config_digest: "e".repeat(64),
                project_dir: String::new(),
                runner_project: String::new(),
                project_name: String::new(),
                platform_specific: vec![],
                arch_specific: vec![],
                waived: waived.iter().map(|w| (*w).to_owned()).collect(),
                cfg_predicates: vec![],
                declared_inputs: vec![],
                env_set: vec![],
                rails_inputs: String::new(),
                ignored_inputs: vec![],
            },
            manifest,
        }
    }

    /// A throwaway ed25519 key, as `--key` loads it.
    fn ssh_signer(dir: &Utf8Path) -> (Signer<'static>, String) {
        let path = dir.join("key");
        let st = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "t", "-f"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(st.success());
        let key = keys::discover(Some(&path), dir).unwrap();
        let public = key.public.clone();
        let signer = vci_attest::SshSigner::load_for(&key.path, &key.blob);
        (Signer::Ssh(key, signer), public)
    }

    /// A format-3 record whose statement is a v2 predicate with these
    /// facts, framed with a synthetic signature (for what reads the
    /// statement without verifying it).
    fn frame_with(
        test_id: &str,
        issued_at: &str,
        duration_ms: u64,
        predicate_type: &str,
    ) -> Vec<u8> {
        let stmt = serde_json::json!({
            "_type": vci_attest::STATEMENT_TYPE,
            "subject": [{"name": test_id, "digest": {"blake3": "1".repeat(64)}}],
            "predicateType": predicate_type,
            "predicate": {
                "argv": ["go", "test"],
                "commit": "c".repeat(40),
                "entriesRoot": "2".repeat(64),
                "expiresAt": "2027-01-02T00:00:00Z",
                "hdr": "a".repeat(64),
                "issuedAt": issued_at,
                "result": {"state": "passed", "tests": 1, "failed": 0, "skipped": 0, "durationMs": duration_ms},
                "tables": "b".repeat(64),
                "testId": test_id,
                "tree": "d".repeat(40),
                "treeDirty": false,
                "waived": [0]
            }
        });
        let frame = Frame {
            statement: sorted_compact_json(&stmt).unwrap().into_bytes(),
            keyid: "SHA256:x".to_owned(),
            sig: vci_core::FrameSig::SshSig(vec![1, 2, 3]),
            descriptor: vec![0; 33],
        };
        frame.encode().unwrap().into_bytes()
    }

    /// A format-1 record (a DSSE envelope, unsigned) with these facts.
    fn envelope_with(test_id: &str, issued_at: &str, duration_ms: u64) -> Vec<u8> {
        let stmt = serde_json::json!({
            "_type": vci_attest::STATEMENT_TYPE,
            "subject": [{"name": test_id, "digest": {"blake3": "1".repeat(64)}}],
            "predicateType": PREDICATE_TYPE,
            "predicate": {
                "testId": test_id,
                "issuedAt": issued_at,
                "expiresAt": "2027-01-02T00:00:00Z",
                "commit": "c".repeat(40),
                "toolchain": {"os": "linux", "arch": "x86_64"},
                "manifestRef": "3".repeat(64),
                "result": {"state": "passed", "tests": 1, "failed": 0, "skipped": 0, "durationMs": duration_ms}
            }
        });
        vci_attest::Envelope {
            payload_type: vci_attest::PAYLOAD_TYPE.to_owned(),
            payload: vci_core::frame::b64_encode(serde_json::to_vec(&stmt).unwrap().as_slice()),
            signatures: vec![],
        }
        .to_json()
    }

    /// The run's objects are built per header group (STORE-V2 section 1.4
    /// steps 1 and 2): units at the same global inputs share one hdr and
    /// one tables object, the shape spans every unit with the shared-base
    /// group as an index list, and the state is left out under
    /// `explain_hashes = false`. Each unit's record (step 3) is a frame
    /// whose statement names its hdr and tables and carries its entries
    /// root and waived ids, signed over the exact bytes so that today's
    /// verification accepts the rebuilt envelope, whose descriptor resolves
    /// to the unit's manifest, and whose columns are copied from it.
    #[test]
    fn a_format_3_run_is_built_per_header_group_and_each_unit_signed_as_a_frame() {
        let t = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        let (signer, public) = ssh_signer(&dir);
        let a = sample_attestable(
            "a",
            &["go.mod"],
            &["a/a.go", "a/a_test.go", "lib/common.go"],
            &["go:net dial", "go:env HOME"],
        );
        let b = sample_attestable("b", &["go.mod"], &["b/b.go", "lib/common.go"], &[]);
        let c = sample_attestable(
            "c",
            &["go.mod", "go.sum"],
            &["c/c.go", "lib/common.go"],
            &[],
        );
        let units = [
            (0, &a, String::new()),
            (1, &b, String::new()),
            (2, &c, String::new()),
        ];
        let run = build_run3(&units, true).unwrap();
        assert!(run.failed.is_empty());
        assert_eq!(
            run.headers.len(),
            2,
            "a and b share their hdr; c has its own"
        );
        assert_eq!(run.tables.len(), 2);
        let kinds: Vec<ObjectKind> = run.objects.iter().map(|o| o.kind).collect();
        assert_eq!(
            kinds,
            [
                ObjectKind::Hdr,
                ObjectKind::Hdr,
                ObjectKind::Tables,
                ObjectKind::Tables,
                ObjectKind::Shape,
                ObjectKind::State
            ]
        );
        assert!(run.state.is_some());
        assert_eq!(run.units[&0].header, run.units[&1].header);
        assert_ne!(run.units[&0].header, run.units[&2].header);
        for o in &run.objects {
            assert_eq!(vci_core::object_id(&o.bytes), o.id, "content-addressed");
        }
        let shape = vci_core::Shape::decode(&run.objects[4].bytes).unwrap();
        assert_eq!(
            shape.entries.len(),
            5,
            "the distinct paths of the three units"
        );
        assert_eq!(shape.groups.len(), 1, "the three units' common entry");
        assert_eq!(shape.groups[0].len(), 1);
        assert_eq!(
            run.tables[run.units[&0].header].value.waivers,
            ["go:env HOME", "go:net dial"]
        );
        let lean = build_run3(&units, false).unwrap();
        assert_eq!(lean.objects.len(), 5);
        assert!(lean.state.is_none());
        assert_eq!(lean.shape, run.shape, "the same shape without the state");

        let allowed = vci_attest::AllowedSigners::parse(&format!(
            "t@example.com namespaces=\"vci-attest\" {public}\n"
        ))
        .unwrap();
        for (i, u) in [(0usize, &a), (1, &b), (2, &c)] {
            let unit = &run.units[&i];
            let signed = sign_format3(&signer, u, &run, unit).unwrap();
            let Ok(Record::FormatThree(frame)) = decode_record(&signed.record) else {
                panic!("a frame: {:?}", String::from_utf8_lossy(&signed.record));
            };
            // The statement: compact, sorted keys, the v2 predicate.
            let stmt: Statement = serde_json::from_slice(&frame.statement).unwrap();
            assert_eq!(stmt.predicate_type, PREDICATE_TYPE_V2);
            assert_eq!(
                sorted_compact_json(&stmt).unwrap().as_bytes(),
                &frame.statement[..]
            );
            assert_eq!(stmt.subject[0].name, u.predicate.core.test_id);
            assert_eq!(stmt.subject[0].digest["blake3"], u.manifest.root());
            let (hdr, tables) = &run.headers[unit.header];
            let m = frame_meta(&frame).unwrap();
            assert_eq!(m.test_id, u.predicate.core.test_id);
            assert_eq!(m.hdr, vci_core::objects::hex32(hdr));
            assert_eq!(m.tables, vci_core::objects::hex32(tables));
            assert_eq!(m.entries_root, u.manifest.entries_root());
            assert_eq!(m.duration_ms, 42);
            assert_eq!(m.commit, "c".repeat(40));
            let waived = &stmt.predicate["waived"];
            if i == 0 {
                assert_eq!(waived, &serde_json::json!([0, 1]));
            } else {
                assert!(waived.is_null(), "{waived}");
            }
            // Signed over those bytes: today's verification accepts the
            // envelope rebuilt from the frame.
            let env = vci_attest::Envelope::from_frame(&frame);
            let v = vci_attest::verify_envelope(&env, &allowed, 1_800_000_100).unwrap();
            assert_eq!(v.payload, frame.statement);
            // The descriptor resolves to the unit's manifest.
            let tables_obj = &run.tables[unit.header].value;
            let d = vci_core::Descriptor::decode(&frame.descriptor, tables_obj).unwrap();
            assert_eq!(d.shape, vci_core::objects::parse_hex32(&run.shape).unwrap());
            assert_eq!(
                d.resolve(&shape, tables_obj).unwrap(),
                vci_core::ResolvedManifest::of(&u.manifest)
            );
            // The columns, from what was signed.
            assert_eq!(
                signed.columns,
                Some(Columns {
                    format: Some(3),
                    commit: Some("c".repeat(40)),
                    platform: Some("linux-x86_64".to_owned()),
                    state: Some("passed".to_owned()),
                    duration_ms: Some(42),
                    expires: Some(1_800_000_000 + 86_400),
                    hdr: Some(m.hdr.clone()),
                    tables: Some(m.tables.clone()),
                    shape: Some(run.shape.clone()),
                    state_obj: run.state.clone(),
                })
            );
            // The storage key is the one the v1 view gives.
            assert_eq!(
                storage_key(&vci_core::ResolvedPredicate::v1(&u.predicate)).len(),
                64
            );
        }
    }

    /// A format-3 unit is stored after the run's objects, inside the same
    /// deferred batch, with its columns and without a manifest; what it
    /// supersedes is removed and the object ids the old record named are
    /// collected for the orphan pass, which removes only what no record
    /// references any more.
    #[test]
    fn a_format_3_unit_is_stored_after_the_runs_objects_with_its_columns() {
        use vci_store::conformance::scenarios::Run3 as Sample;
        let s = crate::store::mem::MemStore::new()
            .objects(true)
            .deferred(true);
        let old = earlier(&s, "a");
        let run = Sample::build(&["a/a.go"]);
        let objects: Vec<RunObject> = run
            .objects
            .iter()
            .map(|(k, b)| RunObject {
                kind: *k,
                bytes: b.clone(),
                id: vci_core::object_id(b),
            })
            .collect();
        let (frame, columns) = run.record("a", 1, 3);
        let said = Said::default();
        let mut say = |l: &str| said.0.borrow_mut().push(l.to_owned());
        let mut sl = StoreLoop::new(&s, StoreMode::Write, SIGNER, owner(), &mut say);
        sl.put_objects(&objects);
        assert!(s.object_ids().is_empty(), "deferred");
        let mut u = unit("a", &InputManifest::default(), &root('a'));
        u.manifest = None;
        u.envelope = frame.clone();
        u.columns = Some(columns.clone());
        u.doomed = vec![old.clone()];
        u.doomed_objects = BTreeMap::from([(old.key.clone(), vec!["f".repeat(64)])]);
        sl.attest(u);
        let done = sl.finish();
        assert_eq!((done.attested, done.refused, done.superseded), (1, 0, 1));
        assert!(done.errors.is_empty(), "{:?}", done.errors);
        assert_eq!(done.dropped_objects, BTreeSet::from(["f".repeat(64)]));
        assert!(done.dropped_roots.is_empty());
        let bytes: usize = run.objects.iter().map(|(_, b)| b.len()).sum();
        assert_eq!(
            (done.objects_bytes, done.records_bytes, done.batches),
            (bytes, frame.len(), 1)
        );
        assert_eq!(s.object_ids().len(), 4);
        assert!(s.roots().is_empty(), "no manifest for a format-3 record");
        let keys = s.keys();
        assert_eq!(keys.len(), 1, "{keys:?}");
        assert_ne!(keys[0], old.key);
        assert_eq!(s.value_of(&keys[0]), Some(frame));
        assert_eq!(s.columns_of(&keys[0]), Some(columns));
        let lines = said.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("vci: attested a (0 inputs, root aaaaaaaaaaaaaaaa) as memory project vci:attestation:"), "{lines:?}");

        // The orphan pass: another run's shape and state (its hdr and
        // tables are the same objects) are unreferenced and go; this
        // run's shape, which the record's columns name, stays.
        let other = Sample::build(&["b/b.go"]);
        assert_eq!(s.put_objects(&other.new_objects()).unwrap(), 2);
        assert_eq!(s.object_ids().len(), 6);
        let ids: BTreeSet<String> = [
            other.ids.shape.clone(),
            other.ids.state.clone(),
            run.ids.shape.clone(),
        ]
        .into_iter()
        .collect();
        assert_eq!(drop_orphan_objects(&s, &ids), 2);
        let left = s.object_ids();
        assert_eq!(left.len(), 4);
        assert!(left.contains(&run.ids.shape));
        assert!(!left.contains(&other.ids.shape));
        // Without columns, the pass is left to `vci prune`.
        let no_columns = crate::store::mem::MemStore::new();
        assert_eq!(drop_orphan_objects(&no_columns, &ids), 0);
    }

    /// A store that refuses the run's objects refuses every format-3 unit
    /// (its record would name objects the store does not hold), each as a
    /// store failure when the store cannot be used, while a format-1 unit
    /// of the same loop is stored as before.
    #[test]
    fn objects_the_store_refuses_refuse_the_format_3_units_only() {
        use vci_store::conformance::scenarios::Run3 as Sample;
        let s = crate::store::mem::MemStore::new();
        let run = Sample::build(&["a/a.go"]);
        let objects: Vec<RunObject> = run
            .objects
            .iter()
            .map(|(k, b)| RunObject {
                kind: *k,
                bytes: b.clone(),
                id: vci_core::object_id(b),
            })
            .collect();
        let (frame, columns) = run.record("a", 1, 3);
        let said = Said::default();
        let mut say = |l: &str| said.0.borrow_mut().push(l.to_owned());
        let mut sl = StoreLoop::new(&s, StoreMode::Write, SIGNER, owner(), &mut say);
        sl.put_objects(&objects);
        let mut a = unit("a", &InputManifest::default(), &root('a'));
        a.manifest = None;
        a.envelope = frame;
        a.columns = Some(columns);
        sl.attest(a);
        sl.attest(unit("b", &InputManifest::default(), &root('b')));
        let done = sl.finish();
        assert_eq!((done.attested, done.refused), (1, 1));
        assert!(done.errors.is_empty(), "{:?}", done.errors);
        assert_eq!(done.store_failures.len(), 1, "{:?}", done.store_failures);
        let lines = said.lines();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert_eq!(
            lines[0],
            "vci: warning: storing the run's 4 object(s) in the memory store: the memory store does not support format-3 objects"
        );
        assert_eq!(
            lines[1],
            "vci: not attesting a: signing or storing failed: storing the run's objects: memory store unavailable: the memory store does not support format-3 objects"
        );
        assert!(lines[2].starts_with("vci: attested b "), "{lines:?}");
        assert_eq!(s.keys().len(), 1);
        assert!(s.object_ids().is_empty());
        // Signing only puts nothing and refuses nothing.
        let s = crate::store::mem::MemStore::new().shared(true);
        let said = Said::default();
        let mut say = |l: &str| said.0.borrow_mut().push(l.to_owned());
        let mut sl = StoreLoop::new(&s, StoreMode::SignOnly, SIGNER, owner(), &mut say);
        sl.put_objects(&objects);
        assert!(sl.objects_failed.is_none());
        assert_eq!(s.writes(), 0);
    }

    /// What supersession and `last_durations` read from a record of either
    /// format, by its first byte: a v2 statement's facts from a frame, a v1
    /// predicate's from an envelope; nothing from a value that is neither
    /// or whose statement is not a v2 predicate.
    #[test]
    fn frame_meta_and_record_duration_read_either_format() {
        let f = frame_with("src/a.go", "2026-05-01T00:00:00Z", 55, PREDICATE_TYPE_V2);
        let Ok(Record::FormatThree(frame)) = decode_record(&f) else {
            panic!("a frame");
        };
        let m = frame_meta(&frame).unwrap();
        assert_eq!(m.test_id, "src/a.go");
        assert_eq!(
            m.issued_at,
            crate::util::parse_rfc3339("2026-05-01T00:00:00Z").unwrap()
        );
        assert_eq!(m.commit, "c".repeat(40));
        assert_eq!(m.tree.as_deref(), Some("d".repeat(40).as_str()));
        assert_eq!(m.entries_root, "2".repeat(64));
        assert_eq!((m.hdr, m.tables), ("a".repeat(64), "b".repeat(64)));
        assert_eq!(m.duration_ms, 55);
        assert_eq!(record_duration(&f), Some((m.issued_at, 55)));
        let v1_in_a_frame = frame_with("src/a.go", "2026-05-01T00:00:00Z", 55, PREDICATE_TYPE);
        let Ok(Record::FormatThree(frame)) = decode_record(&v1_in_a_frame) else {
            panic!("a frame");
        };
        assert!(frame_meta(&frame).is_none());
        assert_eq!(record_duration(&v1_in_a_frame), None);
        let e = envelope_with("src/a.go", "2026-04-01T00:00:00Z", 66);
        assert_eq!(
            record_duration(&e),
            Some((
                crate::util::parse_rfc3339("2026-04-01T00:00:00Z").unwrap(),
                66
            ))
        );
        assert_eq!(record_duration(b"xyz"), None);
        assert_eq!(record_duration(b""), None);
    }

    /// `last_durations` takes the newest duration from the listing columns
    /// where a store keeps them, reads the units none of whose records has
    /// one (format-1 rows), and on a store without columns reads every
    /// unit, decoding each value by its first byte.
    #[test]
    fn last_durations_take_columns_first_and_read_the_rest() {
        let s = crate::store::mem::MemStore::new().objects(true);
        let with = |d: u64| Columns {
            format: Some(3),
            duration_ms: Some(d),
            ..Columns::default()
        };
        let put = |id: &str, sk: &str, issued: i64, value: &[u8], c: Option<&Columns>| {
            let hint = KeyHint { issued, tree: None };
            let mut att = NewAttestation::for_test(id, SIGNER, sk, Some(&hint), value);
            if let Some(c) = c {
                att = att.with_columns(c);
            }
            s.put(&att).unwrap();
        };
        let old_frame = frame_with("a", "2026-01-01T00:00:00Z", 30, PREDICATE_TYPE_V2);
        let new_frame = frame_with("a", "2026-02-01T00:00:00Z", 40, PREDICATE_TYPE_V2);
        put("a", "ab", 10, &old_frame, Some(&with(30)));
        put("a", "cd", 20, &new_frame, Some(&with(40)));
        let envelope = envelope_with("b", "2026-03-01T00:00:00Z", 70);
        put("b", "ab", 30, &envelope, None);
        put("d", "ab", 40, b"garbage", None);
        let got = last_durations(&s, &["a", "b", "c", "d"]);
        assert_eq!(
            got.durations,
            BTreeMap::from([("a".to_owned(), 40), ("b".to_owned(), 70)])
        );
        // One columns request for every unit's records, which come back
        // by key (the format-1 rows, which have none, left out).
        assert_eq!(s.columns_calls(), 1);
        let a_tk = vci_store::key::test_key("a");
        let keys = s.keys();
        let a_keys: Vec<&String> = keys
            .iter()
            .filter(|k| vci_store::key::parse_key(k).is_some_and(|(tk, _, _)| tk == a_tk))
            .collect();
        assert_eq!(a_keys.len(), 2);
        assert_eq!(got.columns.len(), 2, "{:?}", got.columns.keys());
        for k in a_keys {
            assert!(got.columns.contains_key(k), "{k}");
        }
        // Without columns: every value read.
        let s = crate::store::mem::MemStore::new();
        s.put_for_test("a", SIGNER, "ab", None, &old_frame).unwrap();
        s.put_for_test("a", SIGNER, "cd", None, &new_frame).unwrap();
        s.put_for_test("b", SIGNER, "ab", None, &envelope).unwrap();
        let got = last_durations(&s, &["a", "b", "c"]);
        assert_eq!(
            got.durations,
            BTreeMap::from([("a".to_owned(), 40), ("b".to_owned(), 70)])
        );
        assert!(got.columns.is_empty());
    }

    /// Supersession's pre-filter takes the columns [`last_durations`]
    /// fetched for the run, by key, and asks the store for none: a record
    /// made at the new record's commit or for another platform is left
    /// out without a read, one without columns (stored since, or a
    /// format-1 row) is read, and the platform of every hdr the columns
    /// name is read in one `get_objects` before the units run.
    #[test]
    fn supersession_takes_the_columns_and_hdr_platforms_fetched_once_for_the_run() {
        let s = crate::store::mem::MemStore::new().objects(true);
        let commit = "c".repeat(40);
        let hdr = Hdr {
            toolchain: vci_core::Toolchain {
                os: "linux".into(),
                arch: "x86_64".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let hdr_bytes = hdr.encode().unwrap();
        let hdr_id = vci_core::objects::hex32(&vci_core::object_id(&hdr_bytes));
        s.put_objects(&[NewObject::new(ObjectKind::Hdr, &hdr_bytes)])
            .unwrap();
        let with = |commit: &str, platform: &str| Columns {
            format: Some(3),
            commit: Some(commit.to_owned()),
            platform: Some(platform.to_owned()),
            duration_ms: Some(5),
            hdr: Some(hdr_id.clone()),
            ..Columns::default()
        };
        let frame = frame_with("a", "2026-01-01T00:00:00Z", 30, PREDICATE_TYPE_V2);
        let put = |sk: &str, issued: i64, c: Option<&Columns>| {
            let hint = KeyHint { issued, tree: None };
            let mut att = NewAttestation::for_test("a", SIGNER, sk, Some(&hint), &frame);
            if let Some(c) = c {
                att = att.with_columns(c);
            }
            s.put(&att).unwrap().key
        };
        let same_commit = put("ab", 10, Some(&with(&commit, "linux-x86_64")));
        let other_platform = put("cd", 20, Some(&with(&"d".repeat(40), "darwin-arm64")));
        let older = put("ef", 30, Some(&with(&"d".repeat(40), "linux-x86_64")));
        let bare = put("ee", 40, None);
        let records = last_durations(&s, &["a"]);
        assert_eq!(s.columns_calls(), 1);
        assert_eq!(records.columns.len(), 3);
        assert_eq!(
            records.hdrs,
            BTreeSet::from([hdr_id.clone()]),
            "the hdr the columns name, once"
        );
        let hdrs = HdrPlatforms::default();
        hdrs.preload(&s, records.hdrs.iter().map(String::as_str));
        assert_eq!(s.object_reads(), 1, "one read for the distinct hdr ids");
        assert!(!records.window, "no manifest: the columns pre-filter");
        let mine = s.list_units(&["a"]).unwrap().remove(0);
        let chosen = old_records_to_read(
            mine,
            &records.columns,
            &commit,
            "linux-x86_64",
            records.window,
        );
        let keys: BTreeSet<&str> = chosen.iter().map(|(e, _)| e.key.as_str()).collect();
        assert_eq!(
            keys,
            BTreeSet::from([older.as_str(), bare.as_str()]),
            "{keys:?}"
        );
        assert!(!keys.contains(same_commit.as_str()) && !keys.contains(other_platform.as_str()));
        let bare_columns = &chosen.iter().find(|(e, _)| e.key == bare).unwrap().1;
        assert_eq!(
            *bare_columns,
            Columns::default(),
            "a record without columns is read"
        );
        assert_eq!(
            hdrs.of(&s, &hdr_id),
            Some(("linux".to_owned(), "x86_64".to_owned()))
        );
        assert_eq!(s.columns_calls(), 1, "no columns request per unit");
        assert_eq!(s.object_reads(), 1, "no hdr read per unit");

        // While the store holds a manifest (a 2.8 writer may have put its
        // format-1 value under a frame's stale columns), every record of
        // the unit is read: the same-commit and other-platform columns
        // leave nothing out.
        s.put_manifest(&"9".repeat(64), b"{}").unwrap();
        let records = last_durations(&s, &["a"]);
        assert!(records.window, "a manifest exists: the window is open");
        let mine = s.list_units(&["a"]).unwrap().remove(0);
        let chosen = old_records_to_read(
            mine,
            &records.columns,
            &commit,
            "linux-x86_64",
            records.window,
        );
        let keys: BTreeSet<&str> = chosen.iter().map(|(e, _)| e.key.as_str()).collect();
        assert_eq!(
            keys,
            BTreeSet::from([
                same_commit.as_str(),
                other_platform.as_str(),
                older.as_str(),
                bare.as_str()
            ]),
            "{keys:?}"
        );
    }

    /// `[store]` decides the format: 3 on a store that keeps objects, else
    /// 1 (a store without objects, or `record_format = 1`).
    #[test]
    fn the_record_format_is_3_only_on_a_store_with_objects() {
        let s3 = RecordSettings {
            format: 3,
            explain_hashes: true,
            explain_hashes_days: 2,
        };
        let s1 = RecordSettings { format: 1, ..s3 };
        let with = crate::store::mem::MemStore::new().objects(true);
        let without = crate::store::mem::MemStore::new();
        assert!(s3.format3(&with));
        assert!(!s3.format3(&without));
        assert!(!s1.format3(&with));
    }
}
