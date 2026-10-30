//! `vci plan` / `vci explain` / `vci ci`: the verification algorithm.
//!
//! Default verdict is RUN. A test file is skipped only when one stored
//! candidate passes every check below, in order. Every error is caught per
//! candidate (or, for errors that affect everything, turns into "run all").

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::Serialize;
use vci_attest::keyless::{IDENTITIES_FILE, Identities, TRUSTED_ROOT_FILE, TrustedRoot};
use vci_attest::{AllowedSigners, Envelope, Frame, VerifyError, verify_envelope};
use vci_core::objects::{hex32, parse_hex32};
use vci_core::{
    CheckoutCache, Descriptor, EntryKind, Hdr, InputEntry, InputManifest, Mismatch, ObjectKind,
    Observation, PREDICATE_TYPE, PREDICATE_TYPE_V2, RepoPath, ResolvedPredicate, Shape, ShapeEntry,
    State, Tables, VciPredicateV2, env_value_hash, object_id,
};
use vci_git::Repo;
use vci_store::{
    AttestationStore, Choose, Prefetch, Record, StoreError, StoreStatus, StoredEnvelope,
    StoredManifest, ValueState, decode_record,
};

use crate::config::{ALLOWED_SIGNERS_FILE, CONFIG_FILE, Config, Libraries, Platform};
use crate::ctx::{Ctx, Project, TestFile, VciPredicate, mark_cross_project_ambiguity, open_repo};
use crate::envpolicy::{ChildEnvMap, lookup};
use crate::util::{glob_match, now_unix, parse_rfc3339};

/// Allowed clock skew for `issued_at` in the future.
const CLOCK_SKEW_SECS: i64 = 300;

/// Prefix of the refusal `policy.rails_allow_db` waived before vci 1.4.0 (a
/// Rails test database server), as recorded in an attestation's `waived`.
/// Such an attestation is never accepted now.
const LEGACY_RAILS_NETWORK_DB_WAIVER: &str = "rails:network-db:";

/// One failed check, with expected vs actual for `explain`.
///
/// Convention for every check: `expected` is what the attestation recorded or
/// claims, `actual` is what CI computes from its own checkout, clock, policy
/// and environment now.
#[derive(Debug, Clone, Serialize)]
pub struct Failure {
    pub check: &'static str,
    /// Position of the check in the algorithm (higher = got further).
    #[serde(skip)]
    pub rank: u8,
    pub details: Vec<Detail>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Detail {
    pub what: String,
    pub expected: String,
    pub actual: String,
}

impl Failure {
    fn one(
        check: &'static str,
        rank: u8,
        what: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self {
            check,
            rank,
            details: vec![Detail {
                what: what.into(),
                expected: expected.into(),
                actual: actual.into(),
            }],
        }
    }

    pub fn summary(&self) -> String {
        match self.details.first() {
            Some(d) if self.details.len() > 1 => {
                format!(
                    "{}: {} (+{} more)",
                    self.check,
                    d.what,
                    self.details.len() - 1
                )
            }
            Some(d) => format!("{}: {}", self.check, d.what),
            None => self.check.to_owned(),
        }
    }
}

/// Signer and time information for a candidate that got past the signature.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CandidateInfo {
    /// git-meta target the envelope was read from (`path:<p>` or `project`).
    pub target: String,
    /// git-meta key it was stored under (unverified, like the target).
    pub meta_key: String,
    pub principal: Option<String>,
    pub fingerprint: Option<String>,
    pub issued_at: Option<String>,
    pub expires_at: Option<String>,
    /// Differences the checks accepted only because of
    /// `policy.libraries = "any"` (a native library matched by library name,
    /// library versions not compared), for `explain`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub accepted_by_policy: Vec<String>,
    /// Rails: the `rails_inputs` the attestation records (empty: made
    /// before 2.7.36, every input recorded), for `explain`.
    #[serde(skip)]
    pub rails_inputs: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    #[serde(flatten)]
    pub info: CandidateInfo,
    /// `None` = passed every check.
    pub failure: Option<Failure>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileVerdict {
    pub test_id: String,
    /// Relative to the project dir (what to pass to the runner).
    pub file: String,
    /// `[[projects]]` name; omitted in the single-project form.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub project: String,
    pub skip: bool,
    pub reason: String,
    /// The base policy's `libraries` for this file (omitted when "exact").
    #[serde(skip_serializing_if = "is_exact")]
    pub libraries: Libraries,
    /// Rails: the base vci.toml's `rails_inputs` and the globs it leaves
    /// out of manifests, for `explain`.
    #[serde(skip)]
    pub rails_inputs: Option<(crate::config::RailsInputs, Vec<String>)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<CandidateInfo>,
    #[serde(skip)]
    pub candidates: Vec<Candidate>,
    /// Index into [`PlanResult::projects`].
    #[serde(skip)]
    pub project_idx: usize,
}

/// Per-project part of a plan (what `vci ci` needs to run the remainder).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectPlan {
    /// Empty in the single-project form.
    pub name: String,
    /// Project dir relative to the repo root.
    pub path: String,
    pub adapter: String,
    /// Set when every test file of this project must run; the reason.
    pub run_all: Option<String>,
    /// The current ref matched `policy.no_skip_refs` and the policy names
    /// principals in `no_skip_refs_except`: only their attestations skip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_skip_ref: Option<String>,
    /// The base policy's `no_skip_refs` match the current ref (whatever
    /// `no_skip_refs_except` says); `false` when the base policy could not be
    /// read. `vci ci --key` uses it to decide whether it may attest.
    #[serde(skip)]
    pub on_no_skip_ref: bool,
    /// The base policy's `no_skip_refs_except` (empty when the base policy
    /// could not be read).
    #[serde(skip)]
    pub no_skip_refs_except: Vec<String>,
    /// The base policy's `attest_on_any_ref` (empty when the base policy
    /// could not be read).
    #[serde(skip)]
    pub attest_on_any_ref: Vec<String>,
    #[serde(skip)]
    pub dir: camino::Utf8PathBuf,
    #[serde(skip)]
    pub child_env: Option<ChildEnvMap>,
    /// Policy settings the adapter runs tests with (`vci ci`).
    #[serde(skip)]
    pub adapter_options: vci_adapter::AdapterOptions,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanResult {
    pub base_ref: Option<String>,
    pub base_commit: Option<String>,
    /// Set when everything (every project) must run; the reason.
    pub run_all: Option<String>,
    /// Configuration problems that do not change the verdicts (also printed
    /// to stderr).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub projects: Vec<ProjectPlan>,
    pub files: Vec<FileVerdict>,
    /// The `[[projects]]` form is in use.
    #[serde(skip)]
    pub multi: bool,
    /// The configuration [`PlanResult::projects`] were made from (the base
    /// commit's, or the working tree's when the base policy could not be
    /// read), in the same order: what `vci ci --key` runs and attests with.
    #[serde(skip)]
    pub config: Option<Config>,
    /// The base commit's allowed_signers, when they could be read: whom
    /// `vci ci --key`'s key signs as.
    #[serde(skip)]
    pub allowed: Option<AllowedSigners>,
    /// `--fetch` failed (the remote and why): only attestations already
    /// stored locally were used.
    #[serde(skip)]
    pub fetch_failed: Option<String>,
    /// [`AttestationStore::kind`] of the store the candidates were read
    /// from, for `explain`.
    #[serde(skip)]
    pub store_kind: &'static str,
}

impl PlanResult {
    pub fn skipped(&self) -> impl Iterator<Item = &FileVerdict> {
        self.files.iter().filter(|f| f.skip)
    }
    pub fn to_run(&self) -> impl Iterator<Item = &FileVerdict> {
        self.files.iter().filter(|f| !f.skip)
    }
}

pub struct PlanOptions {
    pub base_ref: Option<String>,
    /// Only verify this test (explain).
    pub only: Option<String>,
    /// Fetch attestations first, as `vci fetch` does (`Some(None)`: the
    /// default remote), while the projects are probed; fail-open.
    pub fetch: Option<Option<String>>,
    /// `--project`: only these `[[projects]]` (empty: every project). The
    /// others are not listed, probed or verified.
    pub projects: Vec<String>,
}

/// Resolve the base ref: explicit, `$VCI_BASE_REF`, `$GITHUB_BASE_REF`
/// (as `origin/<ref>` or `<ref>`), else `origin/HEAD`, `origin/main`,
/// `origin/master`, `main`, `master`.
pub(crate) fn resolve_base(
    repo: &Repo,
    explicit: Option<&str>,
) -> Result<(String, String), String> {
    let mut tries: Vec<String> = Vec::new();
    if let Some(r) = explicit {
        tries.push(r.to_owned());
    } else if let Ok(r) = std::env::var("VCI_BASE_REF").map(|s| s.trim().to_owned())
        && !r.is_empty()
    {
        tries.push(r);
    } else {
        if let Ok(r) = std::env::var("GITHUB_BASE_REF").map(|s| s.trim().to_owned())
            && !r.is_empty()
        {
            tries.push(format!("origin/{r}"));
            tries.push(r);
        }
        for r in [
            "origin/HEAD",
            "origin/main",
            "origin/master",
            "main",
            "master",
        ] {
            tries.push(r.to_owned());
        }
    }
    let mut last = String::new();
    for r in &tries {
        match repo.resolve(r) {
            Ok(sha) => return Ok((r.clone(), sha)),
            Err(e) => last = e.to_string(),
        }
    }
    Err(format!(
        "no base ref could be resolved (tried {}): {last}",
        tries.join(", ")
    ))
}

/// Trust comes from the base commit. When the base is HEAD itself or contains
/// it (e.g. `--base-ref HEAD`, or the pull request's head or merge commit), the
/// commit under test supplies its own `allowed_signers` and policy.
fn self_referential_base(repo: &Repo, base_ref: &str, base: &str) -> Option<String> {
    let head = repo.head_commit().ok()?;
    let contains_head =
        head == base || repo.merge_base(&head, base).ok().as_deref() == Some(head.as_str());
    contains_head.then(|| {
        format!(
            "the base commit {base} ({base_ref}) is HEAD or contains it, so allowed_signers and policy come from the commit under test and a change to them there would be trusted. In CI pass the target branch's commit (e.g. github.event.pull_request.base.sha) as --base-ref."
        )
    })
}

/// Keyless trust from the base commit: `.vci/identities.toml` and the
/// Sigstore trust root (`.vci/sigstore-trusted-root.json`).
pub(crate) struct KeylessTrust {
    pub identities: Result<Identities, String>,
    pub root: Result<TrustedRoot, String>,
}

/// Read keyless trust from `base`: `None` without an identities.toml there.
/// A file that is invalid or unreadable is a warning, and every keyless
/// candidate then fails (its unit runs) naming it.
fn load_keyless(repo: &Repo, base: &str, warnings: &mut Vec<String>) -> Option<KeylessTrust> {
    let read = |file: &str| -> Result<Option<String>, String> {
        match repo.show_file(base, file) {
            Ok(Some(b)) => String::from_utf8(b)
                .map(Some)
                .map_err(|_| format!("{file} at base is not UTF-8")),
            Ok(None) => Ok(None),
            Err(e) => Err(format!("reading {file} at base: {e}")),
        }
    };
    let identities = match read(IDENTITIES_FILE) {
        Ok(None) => return None,
        Ok(Some(t)) => {
            Identities::parse(&t).map_err(|e| format!("{IDENTITIES_FILE} at base is invalid: {e}"))
        }
        Err(e) => Err(e),
    };
    let root = match read(TRUSTED_ROOT_FILE) {
        Ok(None) => Err(format!(
            "{TRUSTED_ROOT_FILE} is missing at the base commit (write it with `gh attestation trusted-root > {TRUSTED_ROOT_FILE}`, or `vci init --oidc`)"
        )),
        Ok(Some(t)) => TrustedRoot::parse(&t)
            .map_err(|e| format!("{TRUSTED_ROOT_FILE} at base is invalid: {e}")),
        Err(e) => Err(e),
    };
    for e in [identities.as_ref().err(), root.as_ref().err()]
        .into_iter()
        .flatten()
    {
        let w = format!("{e}: attestations signed keylessly (vci --oidc) are not trusted");
        eprintln!("vci: warning: {w}");
        warnings.push(w);
    }
    Some(KeylessTrust { identities, root })
}

fn current_refs(repo: &Repo) -> Vec<String> {
    let mut refs = Vec::new();
    if let Ok(r) = std::env::var("GITHUB_REF")
        && !r.is_empty()
    {
        refs.push(r);
    }
    if let Ok(out) = std::process::Command::new("git")
        .args(["-C", repo.root().as_str(), "symbolic-ref", "-q", "HEAD"])
        .output()
        && out.status.success()
    {
        let r = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !r.is_empty() {
            refs.push(r);
        }
    }
    refs
}

/// Everything computed once per project.
struct Verifier<'a> {
    ctx: &'a Ctx,
    /// Where the candidates and their input manifests are stored.
    store: &'a dyn AttestationStore,
    /// This checkout's tree (clean checkout), to check candidates made on
    /// it first.
    head_tree: Option<String>,
    project: &'a Project,
    allowed: &'a AllowedSigners,
    /// Keyless trust from the base commit (`None`: no identities.toml).
    keyless: Option<&'a KeylessTrust>,
    now: i64,
    max_ttl: i64,
    repo_id: String,
    versions: vci_adapter::ToolVersions,
    child: ChildEnvMap,
    /// The current ref matched `policy.no_skip_refs`: only principals in
    /// `policy.no_skip_refs_except` are accepted.
    no_skip_ref: Option<String>,
    /// pytest: installed distributions and the uv.lock pins.
    python_externals: Option<PythonExternals>,
    /// Go: the build list (`go list -m -json all`).
    go_modules: Option<Result<vci_adapter::InstalledExternals, String>>,
    /// Cargo: the packages Cargo.lock pins.
    cargo_lock: Option<Result<vci_adapter::InstalledExternals, String>>,
    /// Rails: the gems of the bundle Bundler resolves in this checkout.
    rails_gems: Option<Result<vci_adapter::InstalledExternals, String>>,
    /// Rails: the native libraries the application opens through FFI when it
    /// boots, resolved only when a candidate records one (the plan's only
    /// boot of the application: once per project, and none when no candidate
    /// records a native library).
    natives: std::sync::OnceLock<Result<vci_adapter::InstalledExternals, String>>,
    /// The input manifests candidates reference, read from the local store.
    manifests: ManifestLoader,
    /// The format-3 objects (hdr, tables, shape; state for the failure text)
    /// the plan's candidates name, loaded once for the whole plan.
    objects: &'a ObjectLoader,
    /// The checks of each hdr object that depend on nothing but the hdr and
    /// the checkout (its global manifest's root and rehash), made once per
    /// hdr id for this project (STORE-V2 section 1.5 step 6).
    hdr_checks: Mutex<HashMap<String, Result<(), Failure>>>,
    /// The checkout, each path observed once for the whole plan.
    checkout: &'a CheckoutCache,
    /// The git-ignored children of listed directories, found once per plan.
    ignored: &'a IgnoredChildren,
    /// The current global manifest per set of global observations (one set
    /// for every file of most projects): captured once.
    #[allow(clippy::type_complexity)]
    globals: Mutex<HashMap<Vec<(RepoPath, Observation)>, Result<Arc<InputManifest>, String>>>,
    /// Whether a manifest's paths collide under case folding, per input root
    /// (a manifest is used only once its root is the signed one).
    collisions: Mutex<HashMap<String, Result<(), String>>>,
    /// The checks of each shared base manifest, made once (see [`BaseCheck`]).
    base_checks: Mutex<HashMap<String, Arc<BaseCheck>>>,
    /// The case-folded prefixes and collisions of each shape group, made
    /// once per `(shape id, group)` (see [`GroupCase`]).
    group_cases: Mutex<HashMap<(String, u8), Arc<GroupCase>>>,
    /// Where the verdicts phase spends its time (`VCI_TIMING=1`).
    timers: Timers,
}

/// Nanoseconds spent in each part of checking candidates, summed over
/// threads (so the sum can exceed the wall time), and counts; printed with
/// `VCI_TIMING=1` after the verdicts phase.
#[derive(Default)]
pub(crate) struct Timers {
    candidates: std::sync::atomic::AtomicU64,
    rehashed: std::sync::atomic::AtomicU64,
    signature: std::sync::atomic::AtomicU64,
    globals: std::sync::atomic::AtomicU64,
    manifest_read: std::sync::atomic::AtomicU64,
    manifest_decode: std::sync::atomic::AtomicU64,
    collisions: std::sync::atomic::AtomicU64,
    ignored: std::sync::atomic::AtomicU64,
    rehash: std::sync::atomic::AtomicU64,
    externals: std::sync::atomic::AtomicU64,
    envs: std::sync::atomic::AtomicU64,
}

impl Timers {
    fn add(field: &std::sync::atomic::AtomicU64, since: std::time::Instant) {
        field.fetch_add(
            since.elapsed().as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    fn count(field: &std::sync::atomic::AtomicU64) {
        field.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn report(&self, label: &str) {
        if !vci_core::metrics::on() {
            return;
        }
        let g = |f: &std::sync::atomic::AtomicU64| {
            f.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1e9
        };
        vci_core::timing_line!(
            "{label}: {} candidate(s) checked, {} rehashed; thread-seconds: signature {:.1}, globals {:.1}, manifest read {:.1}, manifest decode {:.1}, case collisions {:.1}, ignored children {:.1}, rehash {:.1}, externals {:.1}, env {:.1}",
            self.candidates.load(std::sync::atomic::Ordering::Relaxed),
            self.rehashed.load(std::sync::atomic::Ordering::Relaxed),
            g(&self.signature),
            g(&self.globals),
            g(&self.manifest_read),
            g(&self.manifest_decode),
            g(&self.collisions),
            g(&self.ignored),
            g(&self.rehash),
            g(&self.externals),
            g(&self.envs),
        );
    }
}

/// Why a referenced input manifest cannot be used, as the `what` and
/// `actual` of a failed check's detail.
pub(crate) type ManifestUnavailable = (String, String);

/// Decode the input manifest an attestation references (`manifestRef`)
/// from what `store` returned for it. Its root is not checked here: the
/// caller compares it with the signed `inputRoot`.
pub(crate) fn load_manifest(
    store: &dyn AttestationStore,
    root: &str,
    stored: Result<Option<StoredManifest>, StoreError>,
    base: impl FnOnce(&str) -> Result<Option<StoredManifest>, StoreError>,
) -> Result<InputManifest, ManifestUnavailable> {
    match stored {
        Err(e) => Err((
            format!("manifest {root} cannot be read from the store"),
            e.to_string(),
        )),
        // A lazy store may hold it elsewhere: `vci fetch` brings it.
        Ok(None) if store.caps().lazy_values => Err((
            format!("manifest {root} not in the store: run `vci fetch`"),
            format!("missing from the local {} store", store.kind()),
        )),
        Ok(None) => Err((
            format!("manifest {root} not in the store"),
            format!("missing from the {} store", store.kind()),
        )),
        Ok(Some(m)) => match m.error {
            Some(e) => Err((format!("manifest {root} unreadable"), e)),
            None => InputManifest::from_compact_with(&m.bytes, |b| match base(b) {
                Ok(Some(s)) if s.error.is_none() => Ok(s.bytes),
                Ok(Some(s)) => Err(vci_core::ManifestError::Compact(format!(
                    "base manifest {b} unreadable: {}",
                    s.error.unwrap_or_default()
                ))),
                Ok(None) => Err(vci_core::ManifestError::MissingBase(b.to_owned())),
                Err(e) => Err(vci_core::ManifestError::Compact(format!(
                    "base manifest {b}: {e}"
                ))),
            })
            .map_err(|e| (format!("manifest {root} corrupt"), e.to_string())),
        },
    }
}

/// Reads (once each) the input manifests a project's candidates reference.
/// The verifying threads read them from the store at once: the store is
/// called from many threads (git-meta keeps a reader per concurrent caller:
/// a manifest of a large application is megabytes, and reading them one at
/// a time behind one reader serialized the plan; 2.1.0: on vex's runners,
/// 2,004 manifests of 1.9 MB took 1,124 s under one lock).
#[derive(Default)]
struct ManifestLoader {
    #[allow(clippy::type_complexity)]
    cache: Mutex<BTreeMap<String, Result<Arc<InputManifest>, ManifestUnavailable>>>,
    /// Roots (a manifest's, or its base's) a read found not fetched yet: the
    /// plan fetches them after its first pass and checks their units again
    /// (see `hydrate_for_plan`).
    not_fetched: Mutex<BTreeSet<String>>,
    /// Base manifests as read from the store, by root: a base is shared by
    /// a run's units, so every candidate of a full vex plan read the same
    /// few bases again (2.3.3: half of 150 to 270 thread-seconds of
    /// manifest reads).
    #[allow(clippy::type_complexity)]
    bases: Mutex<BTreeMap<String, Result<Option<StoredManifest>, String>>>,
    /// Each manifest's base root, as read (2.7.30).
    base_of: Mutex<HashMap<String, String>>,
    /// The bases decoded on their own, for [`BaseCheck`].
    decoded_bases: Mutex<HashMap<String, Arc<InputManifest>>>,
}

impl ManifestLoader {
    /// The base manifest `root`, read once (`read` reads it from the store).
    fn base(
        &self,
        root: &str,
        read: impl FnOnce() -> Result<Option<StoredManifest>, StoreError>,
    ) -> Result<Option<StoredManifest>, StoreError> {
        if let Some(b) = self
            .bases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(root)
        {
            return b.clone().map_err(StoreError::Other);
        }
        let got = read();
        // A base not fetched yet is read again after the plan fetches it.
        let keep = !matches!(&got, Ok(Some(m)) if m.not_fetched());
        if keep {
            self.bases.lock().unwrap_or_else(|p| p.into_inner()).insert(
                root.to_owned(),
                got.as_ref().map(Clone::clone).map_err(ToString::to_string),
            );
        }
        got
    }

    /// The roots reads found not fetched since the last call.
    /// The root of the base manifest `root`'s manifest shares, once read.
    fn base_root_of(&self, root: &str) -> Option<String> {
        self.base_of
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(root)
            .cloned()
    }

    /// The base manifest `root`, decoded on its own (once).
    fn base_manifest(&self, root: &str) -> Option<Arc<InputManifest>> {
        if let Some(m) = self
            .decoded_bases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(root)
        {
            return Some(m.clone());
        }
        let bytes = match self
            .bases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(root)
        {
            Some(Ok(Some(s))) if s.error.is_none() => s.bytes.clone(),
            _ => return None,
        };
        let m = InputManifest::from_compact_with(&bytes, |b| {
            Err(vci_core::ManifestError::NeedsBase(b.to_owned()))
        })
        .ok()?;
        if m.root() != root {
            return None;
        }
        let m = Arc::new(m);
        self.decoded_bases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(root.to_owned(), m.clone());
        Some(m)
    }

    fn take_not_fetched(&self) -> BTreeSet<String> {
        std::mem::take(&mut *self.not_fetched.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Forget every read that failed: the next read goes to the store
    /// again (after a round fetched more values).
    fn evict_errors(&self) {
        self.bases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, b| matches!(b, Ok(Some(m)) if m.error.is_none()));
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache.retain(|_, r| r.is_ok());
    }

    /// Forget what was read for these roots (and for the manifests whose
    /// base is one of them): the next read goes to the store again.
    fn evict(&self, roots: &BTreeSet<String>) {
        self.bases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|root, _| !roots.contains(root));
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache.retain(|root, r| {
            !roots.contains(root)
                && !matches!(r, Err((_, detail)) if roots.iter().any(|b| detail.contains(b.as_str())))
        });
    }

    /// The manifest is read from `store` and decoded with the cache
    /// unlocked (files are verified in parallel); two threads asking for the
    /// same root at once both read it, and the first decoding wins.
    fn load(
        &self,
        store: &dyn AttestationStore,
        root: &str,
        timers: &Timers,
    ) -> Result<Arc<InputManifest>, ManifestUnavailable> {
        if let Some(r) = self
            .cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(root)
        {
            return r.clone();
        }
        let t_read = std::time::Instant::now();
        // The base too (vci 2.1.8).
        let stored = store.manifest(root).map(|m| {
            let base = m
                .as_ref()
                .filter(|m| m.error.is_none())
                .and_then(|m| InputManifest::compact_base(&m.bytes).ok().flatten())
                .map(|b| {
                    let got = self.base(&b, || store.manifest(&b));
                    (b, got)
                });
            (m, base)
        });
        Timers::add(&timers.manifest_read, t_read);
        let t_decode = std::time::Instant::now();
        let (stored, base) = match stored {
            Ok((m, base)) => (Ok(m), base),
            Err(e) => (Err(e), None),
        };
        if let Some((b, _)) = &base {
            self.base_of
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(root.to_owned(), b.clone());
        }
        {
            let mut missing = Vec::new();
            if let Ok(Some(m)) = &stored
                && m.not_fetched()
            {
                missing.push(root.to_owned());
            }
            if let Some((b, Ok(Some(s)))) = &base
                && s.not_fetched()
            {
                missing.push(b.clone());
            }
            if !missing.is_empty() {
                self.not_fetched
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .extend(missing);
            }
        }
        let r = load_manifest(store, root, stored, |b| match base {
            Some((root, stored)) if root == b => stored,
            _ => Ok(None),
        })
        .map(Arc::new);
        Timers::add(&timers.manifest_decode, t_decode);
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache.entry(root.to_owned()).or_insert(r).clone()
    }
}

/// The verdict-object byte cap of a plan (STORE-V2 section 1.5): the hdr,
/// tables and shape objects its candidates name are loaded in
/// candidate-priority order up to this many bytes, and a candidate whose
/// objects would pass it fails `inputs` (the count is logged).
const VERDICT_OBJECT_BYTES: usize = 16 << 20;

/// How many state objects a plan loads for its failure text (section 1.5
/// step 9): they are explain-only and the largest objects, so past this
/// count a failing entry is reported without its attested hash.
const STATE_OBJECTS: usize = 16;

/// A decoded format-3 object, shared by every candidate naming it.
#[derive(Clone)]
enum Object {
    Hdr(Arc<Hdr>),
    Tables(Arc<Tables>),
    Shape(Arc<Shape>),
    State(Arc<State>),
}

impl Object {
    fn kind(&self) -> ObjectKind {
        match self {
            Object::Hdr(_) => ObjectKind::Hdr,
            Object::Tables(_) => ObjectKind::Tables,
            Object::Shape(_) => ObjectKind::Shape,
            Object::State(_) => ObjectKind::State,
        }
    }
}

/// Why a format-3 object a candidate names is not at hand, as the `what`
/// and `actual` of the failed check's detail (`statement` for a hdr or
/// tables object, `inputs` for a shape).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjectUnavailable {
    what: String,
    actual: String,
    /// The object was not loaded because the plan's verdict-object byte cap
    /// was reached before it (counted in the plan's metrics line).
    past_cap: bool,
}

#[derive(Default)]
struct ObjectCache {
    /// By id: the decoded object, or why it is not at hand. An id is decoded
    /// once for the whole plan; a candidate naming it with another kind than
    /// it decoded to fails on that (the kind byte inside the bytes decides).
    by_id: HashMap<String, Result<Object, ObjectUnavailable>>,
    /// The bytes of the hdr, tables and shape objects loaded so far, against
    /// [`VERDICT_OBJECT_BYTES`].
    verdict_bytes: usize,
    /// How many objects of each kind were loaded and decoded.
    loaded: [usize; 4],
    /// How many times object bytes were hashed and decoded: once per
    /// `(kind, id)` a round loads, however many candidates name it.
    #[cfg_attr(not(test), allow(dead_code))]
    decodes: usize,
    /// Every shape id a candidate named, loaded or not: the distinct runs
    /// the plan's candidates come from.
    shapes_named: BTreeSet<String>,
    /// How many state objects were loaded, against [`STATE_OBJECTS`].
    states: usize,
    /// The state object each read format-3 candidate's listing column
    /// names, by record key: fetched in one `columns` call per round
    /// beside the verdict objects ([`preload_objects`]), so that a failing
    /// candidate costs no store request for its text.
    state_by_key: HashMap<String, String>,
}

/// Loads (once each) the format-3 objects a plan's candidates name
/// (STORE-V2 section 1.5 steps 5 and 9): the hdr and tables objects a
/// statement names and the shape its descriptor names, in one
/// `get_objects` per round ([`preload_objects`]), and on demand for an id
/// that was not in the round's batch; the state object of a run only for
/// the failure text of a candidate that failed on an entry, up to
/// [`STATE_OBJECTS`] of them. Every object's BLAKE3 is recomputed and must
/// be its id; a mismatch, a missing object or a decode failure is kept as
/// the reason every candidate naming the object fails. Nothing here is
/// trusted beyond that: a store's kind column or key segment never chooses
/// a decoder (the kind byte inside the hashed bytes does), and a listing
/// column only says which state object to load for the text.
#[derive(Default)]
struct ObjectLoader {
    cache: Mutex<ObjectCache>,
    /// Candidates that failed because an object they name is past the
    /// verdict-object cap.
    past_cap: std::sync::atomic::AtomicUsize,
}

impl ObjectLoader {
    fn lock(&self) -> std::sync::MutexGuard<'_, ObjectCache> {
        self.cache.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Decode `bytes` as the object `id` of `kind` and keep it (or why not).
    /// The id is checked first; then the decoder of the kind the caller
    /// expects, which refuses an object of another kind (bounded by the
    /// kind's size limit, outside the lock); then, for a verdict object,
    /// the byte cap. A later insert of an id already kept as loaded is a
    /// no-op, found before the bytes are hashed or decoded; one kept as
    /// unavailable is replaced (a round that fetched more may make it
    /// readable).
    fn insert(&self, kind: ObjectKind, id: &str, bytes: &[u8]) {
        {
            let mut c = self.lock();
            if matches!(c.by_id.get(id), Some(Ok(_))) {
                return;
            }
            c.decodes += 1;
        }
        let found = hex32(&object_id(bytes));
        let decoded: Result<Object, ObjectUnavailable> = if found != id {
            Err(ObjectUnavailable {
                what: format!("{kind} object {id} corrupt"),
                actual: format!("its BLAKE3 is {found}, not its id"),
                past_cap: false,
            })
        } else {
            let malformed = |e: vci_core::DecodeError| ObjectUnavailable {
                what: format!("{kind} object {id} malformed"),
                actual: e.to_string(),
                past_cap: false,
            };
            match kind {
                ObjectKind::Hdr => Hdr::decode(bytes).map(|h| Object::Hdr(Arc::new(h))),
                ObjectKind::Tables => Tables::decode(bytes).map(|t| Object::Tables(Arc::new(t))),
                ObjectKind::Shape => Shape::decode(bytes).map(|s| Object::Shape(Arc::new(s))),
                ObjectKind::State => State::decode(bytes).map(|s| Object::State(Arc::new(s))),
            }
            .map_err(malformed)
        };
        let mut c = self.lock();
        if matches!(c.by_id.get(id), Some(Ok(_))) {
            return;
        }
        let decoded = match decoded {
            Ok(o) if kind != ObjectKind::State => {
                if c.verdict_bytes + bytes.len() > VERDICT_OBJECT_BYTES {
                    Err(ObjectUnavailable {
                        what: format!("{kind} object {id} not loaded"),
                        actual: format!(
                            "{} bytes would pass the plan's verdict-object cap of {} bytes ({} loaded)",
                            bytes.len(),
                            VERDICT_OBJECT_BYTES,
                            c.verdict_bytes
                        ),
                        past_cap: true,
                    })
                } else {
                    c.verdict_bytes += bytes.len();
                    c.loaded[kind as usize - 1] += 1;
                    Ok(o)
                }
            }
            Ok(o) => {
                c.loaded[kind as usize - 1] += 1;
                Ok(o)
            }
            Err(e) => Err(e),
        };
        c.by_id.insert(id.to_owned(), decoded);
    }

    /// Load the objects of `wanted` not loaded yet, in one `get_objects`
    /// (after a `Prefetch::Objects` on a lazy store), keeping each in the
    /// order given: the caller orders them by candidate priority, so that
    /// the byte cap falls on the least likely candidates. `wanted` names an
    /// object once per candidate (a run's 1,000 units name its one shape
    /// 1,000 times); each `(kind, id)` is decoded at its first place in the
    /// order only, which is where the cap is decided: a repeat of the same
    /// bytes under the same kind would decode to the same result, and the
    /// cap, which only grows, would refuse it again.
    fn load(&self, store: &dyn AttestationStore, timers: &Timers, wanted: &[(ObjectKind, String)]) {
        let mut ids: Vec<&str> = Vec::new();
        let mut asked: HashSet<&str> = HashSet::new();
        {
            let mut c = self.lock();
            for (kind, id) in wanted {
                if *kind == ObjectKind::Shape && !c.shapes_named.contains(id) {
                    c.shapes_named.insert(id.clone());
                }
                if !matches!(c.by_id.get(id), Some(Ok(_))) && asked.insert(id.as_str()) {
                    ids.push(id);
                }
            }
        }
        if ids.is_empty() {
            return;
        }
        let t_read = std::time::Instant::now();
        if store.caps().lazy_values {
            // A failure here leaves the objects missing: their candidates
            // fail, and a later round asks again.
            let _ = store.prefetch(Prefetch::Objects { ids: &ids });
        }
        let got = store.get_objects(&ids);
        Timers::add(&timers.manifest_read, t_read);
        let t_decode = std::time::Instant::now();
        match got {
            Ok(objects) => {
                let by_id: HashMap<&str, &[u8]> = objects
                    .iter()
                    .map(|o| (o.id.as_str(), o.bytes.as_slice()))
                    .collect();
                let mut decoded: HashSet<(ObjectKind, &str)> = HashSet::new();
                for (kind, id) in wanted {
                    if !asked.contains(id.as_str()) || !decoded.insert((*kind, id.as_str())) {
                        continue;
                    }
                    match by_id.get(id.as_str()) {
                        Some(bytes) => self.insert(*kind, id, bytes),
                        None => {
                            let what = if store.caps().lazy_values {
                                format!("{kind} object {id} not in the store: run `vci fetch`")
                            } else {
                                format!("{kind} object {id} not in the store")
                            };
                            let mut c = self.lock();
                            if !matches!(c.by_id.get(id), Some(Ok(_))) {
                                c.by_id.insert(
                                    id.clone(),
                                    Err(ObjectUnavailable {
                                        what,
                                        actual: format!("missing from the {} store", store.kind()),
                                        past_cap: false,
                                    }),
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                let mut c = self.lock();
                for (kind, id) in wanted {
                    if !matches!(c.by_id.get(id), Some(Ok(_))) {
                        c.by_id.insert(
                            id.clone(),
                            Err(ObjectUnavailable {
                                what: format!("{kind} object {id} cannot be read from the store"),
                                actual: e.to_string(),
                                past_cap: false,
                            }),
                        );
                    }
                }
            }
        }
        Timers::add(&timers.manifest_decode, t_decode);
    }

    /// The object `id`, expected to be of `kind`: from the cache, else
    /// loaded now (an id the round's batch did not name).
    fn get(
        &self,
        store: &dyn AttestationStore,
        timers: &Timers,
        kind: ObjectKind,
        id: &str,
    ) -> Result<Object, ObjectUnavailable> {
        let not_hex = || ObjectUnavailable {
            what: format!("{kind} object id {id:?}"),
            actual: "not 64 lowercase hex digits".to_owned(),
            past_cap: false,
        };
        if parse_hex32(id).is_none() {
            return Err(not_hex());
        }
        let cached = self.lock().by_id.get(id).cloned();
        let r = match cached {
            Some(r) => r,
            None => {
                self.load(store, timers, &[(kind, id.to_owned())]);
                self.lock()
                    .by_id
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| Err(not_hex()))
            }
        };
        match r {
            Ok(o) if o.kind() == kind => Ok(o),
            Ok(o) => Err(ObjectUnavailable {
                what: format!("{kind} object {id} is of another kind"),
                actual: format!("a {} object", o.kind()),
                past_cap: false,
            }),
            Err(e) => {
                if e.past_cap {
                    self.past_cap
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(e)
            }
        }
    }

    fn hdr(
        &self,
        store: &dyn AttestationStore,
        timers: &Timers,
        id: &str,
    ) -> Result<Arc<Hdr>, ObjectUnavailable> {
        match self.get(store, timers, ObjectKind::Hdr, id)? {
            Object::Hdr(h) => Ok(h),
            _ => unreachable!("get checks the kind"),
        }
    }

    fn tables(
        &self,
        store: &dyn AttestationStore,
        timers: &Timers,
        id: &str,
    ) -> Result<Arc<Tables>, ObjectUnavailable> {
        match self.get(store, timers, ObjectKind::Tables, id)? {
            Object::Tables(t) => Ok(t),
            _ => unreachable!("get checks the kind"),
        }
    }

    fn shape(
        &self,
        store: &dyn AttestationStore,
        timers: &Timers,
        id: &str,
    ) -> Result<Arc<Shape>, ObjectUnavailable> {
        match self.get(store, timers, ObjectKind::Shape, id)? {
            Object::Shape(s) => Ok(s),
            _ => unreachable!("get checks the kind"),
        }
    }

    /// The state object of the run the record `s` belongs to, for the
    /// failure text of a candidate that failed on an entry: named by the
    /// record's listing column on a store that keeps columns (the state id
    /// is in no signed field, so only the writer can say it, and what it
    /// says is labelled unsigned), which the round's one `columns` call
    /// fetched ([`preload_objects`]); loaded up to [`STATE_OBJECTS`] per
    /// plan, the cap checked before the store is asked. `None` when the
    /// store keeps no columns, the column is empty, the cap is reached, or
    /// the object is missing or malformed: the text then says the attested
    /// hash was not loaded. No verdict reads it.
    fn state_for(
        &self,
        store: &dyn AttestationStore,
        timers: &Timers,
        s: &StoredEnvelope,
    ) -> Option<Arc<State>> {
        let (id, cached) = {
            let c = self.lock();
            let id = c.state_by_key.get(&s.key)?.clone();
            let cached = c.by_id.get(&id).cloned();
            (id, cached)
        };
        let r = match cached {
            Some(r) => r,
            None => {
                {
                    let mut c = self.lock();
                    if c.states >= STATE_OBJECTS {
                        return None;
                    }
                    c.states += 1;
                }
                self.load(store, timers, &[(ObjectKind::State, id.clone())]);
                self.lock().by_id.get(&id).cloned()?
            }
        };
        match r {
            Ok(Object::State(st)) => Some(st),
            _ => None,
        }
    }

    /// Remember which state object each of these read format-3 records'
    /// listing columns names (one `columns` call, on a store that keeps
    /// them), for [`Self::state_for`]. A column that names no object, or
    /// not a well-formed id, names none.
    fn note_state_objects(&self, store: &dyn AttestationStore, cands: &[&StoredEnvelope]) {
        if cands.is_empty() || !store.caps().columns {
            return;
        }
        let Ok(columns) = store.columns(cands) else {
            return;
        };
        let mut c = self.lock();
        for (s, col) in cands.iter().zip(columns) {
            if let Some(id) = col.state_obj
                && parse_hex32(&id).is_some()
            {
                c.state_by_key.insert(s.key.clone(), id);
            }
        }
    }

    /// The plan's metrics line (`VCI_TIMING=1`): objects loaded per kind,
    /// their bytes, the candidates past the cap and the distinct runs the
    /// candidates named.
    fn report(&self) {
        if !vci_core::metrics::on() {
            return;
        }
        let c = self.lock();
        vci_core::timing_line!(
            "objects: {} hdr, {} tables, {} shape, {} state, {} bytes, {} candidate(s) past the cap, {} distinct run(s)",
            c.loaded[0],
            c.loaded[1],
            c.loaded[2],
            c.loaded[3],
            c.verdict_bytes,
            self.past_cap.load(std::sync::atomic::Ordering::Relaxed),
            c.shapes_named.len()
        );
    }
}

/// The object ids one candidate names, with its rank in the verdict's order.
type RankedIds = ((bool, Option<i64>), Vec<(ObjectKind, String)>);

/// The verdict objects (hdr, tables, shape) the format-3 candidates among
/// `cands` name, in candidate-priority order (the order [`Verifier::verdict`]
/// tries candidates: made on this checkout's tree first, then newest
/// issued), loaded in one batch (section 1.5 step 5), and the state object
/// each of those candidates' listing columns names, in one `columns` call
/// (for the failure text, step 9). Only values that were read and decode
/// as frames name anything; a candidate whose statement or descriptor does
/// not parse is left to its check.
fn preload_objects<'a>(
    store: &dyn AttestationStore,
    objects: &ObjectLoader,
    timers: &Timers,
    cands: impl Iterator<Item = &'a StoredEnvelope>,
    head_tree: Option<&str>,
) {
    let head16: Option<String> = head_tree.map(|t| t.chars().take(16).collect());
    let mut ranked: Vec<RankedIds> = Vec::new();
    let mut frames: Vec<&StoredEnvelope> = Vec::new();
    for s in cands {
        if s.error.is_some() {
            continue;
        }
        let Ok(Record::FormatThree(frame)) = decode_record(&s.bytes) else {
            continue;
        };
        frames.push(s);
        let mut ids = Vec::with_capacity(3);
        if let Ok(st) = serde_json::from_slice::<vci_attest::Statement>(&frame.statement)
            && let Ok(p) = serde_json::from_value::<VciPredicateV2>(st.predicate)
        {
            ids.push((ObjectKind::Hdr, p.hdr));
            ids.push((ObjectKind::Tables, p.tables));
        }
        if let Ok(shape) = Descriptor::shape_id(&frame.descriptor) {
            ids.push((ObjectKind::Shape, hex32(&shape)));
        }
        let same_tree = s.tree.is_some() && s.tree == head16;
        ranked.push(((same_tree, issued_hint(s)), ids));
    }
    if ranked.is_empty() {
        return;
    }
    objects.note_state_objects(store, &frames);
    ranked.sort_by_key(|(rank, _)| std::cmp::Reverse(*rank));
    let wanted: Vec<(ObjectKind, String)> = ranked.into_iter().flat_map(|(_, ids)| ids).collect();
    objects.load(store, timers, &wanted);
}

/// The signer id ([`crate::keys::signer_id`]: the first 16 hex digits of
/// SHA-256 over the public key blob) of the key an SSHSIG verification
/// reports by its `SHA256:` fingerprint, which is the base64 of that same
/// digest: the key's signer segment in a store key must equal it (STORE-V2
/// section 1.5 step 4). `None` for a fingerprint of another form.
fn signer_id_of_fingerprint(fingerprint: &str) -> Option<String> {
    use base64::Engine as _;
    let b64 = fingerprint.strip_prefix("SHA256:")?;
    let digest = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(b64)
        .ok()?;
    if digest.len() != 32 {
        return None;
    }
    Some(hex::encode(digest)[..16].to_owned())
}

/// What an entry's kind is called in the failure text when only the shape
/// is at hand (no attested size or hash).
fn kind_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Symlink => "symlink",
        EntryKind::Absent => "absent",
        EntryKind::DirListing => "dirListing",
        EntryKind::Dir => "directory",
        EntryKind::Excluded => "excluded",
        EntryKind::AutoloadMiss => "autoload lookup",
        EntryKind::AutoloadDir => "autoload directory",
    }
}

/// An entry as `vci explain` prints it (`expected`/`actual` of an
/// `entry:` detail): what [`InputManifest::diff_against_cache`] prints for
/// a format-1 record, so that the texts match where the state is loaded.
fn describe_entry(e: &InputEntry) -> String {
    match e.kind {
        EntryKind::Absent => "absent".to_owned(),
        EntryKind::File => format!("file exec={} size={} blake3={}", e.exec, e.size, e.hash),
        EntryKind::Symlink => format!("symlink size={} blake3={}", e.size, e.hash),
        EntryKind::DirListing => format!("dirListing entries={} blake3={}", e.size, e.hash),
        EntryKind::Dir => "directory".to_owned(),
        EntryKind::Excluded => "excluded (build output, not an input)".to_owned(),
        EntryKind::AutoloadDir => "an autoload directory (its listing is not an input)".to_owned(),
        EntryKind::AutoloadMiss if e.size == 0 => {
            "no file or directory defines the constant".to_owned()
        }
        EntryKind::AutoloadMiss => format!(
            "{} file(s) or directories define the constant, blake3={}",
            e.size, e.hash
        ),
    }
}

/// The label of a hash the failure text prints from a state object, which
/// nothing the signer signed binds (STORE-V2 section 1.5 step 9).
const UNSIGNED_LABEL: &str = "attested (unsigned, from the run's state object)";
/// The text when the attested hash is not at hand (no state object, or
/// past the count cap).
const HASH_NOT_LOADED: &str = "attested hash not loaded";

/// The `entry:` mismatches of a format-3 candidate whose observed root is
/// not the signed one (section 1.5 step 9): with the run's state object,
/// every observed entry whose attested value (by path) is not the observed
/// one, the attested value labelled [`UNSIGNED_LABEL`]; without it, every
/// entry whose observed kind or exec bit is not the shape's, and when no
/// entry differs that way one line saying the entries changed and the
/// attested hash was not loaded. Never empty: the root differs, so the
/// candidate fails `inputs` on an entry, which round 2 keys on.
fn entry_mismatches(
    set: &[ShapeEntry],
    observed: &InputManifest,
    state: Option<&State>,
    input_root: &str,
) -> Vec<Mismatch> {
    let compared = |kind: EntryKind| !matches!(kind, EntryKind::AutoloadDir | EntryKind::Excluded);
    let mut out = Vec::new();
    match state {
        Some(st) => {
            for o in &observed.entries {
                if !compared(o.kind) {
                    continue;
                }
                let attested = st.lookup(&o.path);
                let same = |a: &InputEntry| {
                    a.kind == o.kind && a.exec == o.exec && a.size == o.size && a.hash == o.hash
                };
                if attested.is_empty() {
                    out.push(Mismatch {
                        what: format!("entry:{}", o.path),
                        expected: format!("changed ({HASH_NOT_LOADED}: the run's state object does not list the path)"),
                        actual: describe_entry(o),
                    });
                } else if !attested.iter().any(same) {
                    let values: Vec<String> = attested.iter().map(describe_entry).collect();
                    out.push(Mismatch {
                        what: format!("entry:{}", o.path),
                        expected: format!("{} ({UNSIGNED_LABEL})", values.join(" or ")),
                        actual: describe_entry(o),
                    });
                }
            }
        }
        None => {
            let by_path: HashMap<&str, &ShapeEntry> =
                set.iter().map(|e| (e.path.as_str(), e)).collect();
            for o in &observed.entries {
                if !compared(o.kind) {
                    continue;
                }
                if let Some(a) = by_path.get(o.path.as_str())
                    && (a.kind != o.kind || a.exec != o.exec)
                {
                    let exec = if a.kind == EntryKind::File {
                        format!(" exec={}", a.exec)
                    } else {
                        String::new()
                    };
                    out.push(Mismatch {
                        what: format!("entry:{}", o.path),
                        expected: format!(
                            "{}{exec} changed ({HASH_NOT_LOADED})",
                            kind_label(a.kind)
                        ),
                        actual: describe_entry(o),
                    });
                }
            }
        }
    }
    if out.is_empty() {
        out.push(Mismatch {
            what: format!("entry: changed ({HASH_NOT_LOADED})"),
            expected: format!("input root {input_root}"),
            actual: format!(
                "input root {} (recomputed from the files at HEAD; which entries changed is known only from the run's state object, which is not at hand)",
                observed.root()
            ),
        });
    }
    out
}

/// The children git ignores of the directories input manifests list, found
/// once per directory for the whole plan: what
/// [`crate::run::ignored_listing_children`] finds for one manifest (a
/// child the manifest names is never left out), with one `git check-ignore`
/// for the directories a manifest lists that no manifest listed before,
/// instead of one per manifest. The checkout does not change during a plan.
/// `None` for a directory git could not answer about (it exits 128 on a
/// child inside a submodule): a manifest that lists one is asked about as
/// before, alone.
#[derive(Default)]
struct IgnoredChildren(Mutex<HashMap<RepoPath, Option<Arc<Vec<String>>>>>);

fn child_path(dir: &RepoPath, name: &str) -> String {
    if dir.is_root() {
        name.to_owned()
    } else {
        format!("{}/{name}", dir.as_str())
    }
}

impl IgnoredChildren {
    /// The children of `m`'s listed directories that git ignores and `m`
    /// does not name: left out of the listings when `m` is rehashed.
    fn of(&self, cache: &CheckoutCache, m: &InputManifest) -> Vec<RepoPath> {
        let dirs: Vec<&RepoPath> = m
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::DirListing)
            .map(|e| &e.path)
            .collect();
        if dirs.is_empty() {
            return vec![];
        }
        let ignored: Option<Vec<Arc<Vec<String>>>> = {
            let mut known = self.0.lock().unwrap_or_else(|p| p.into_inner());
            let mut missing: Vec<&RepoPath> = dirs
                .iter()
                .copied()
                .filter(|d| !known.contains_key(*d))
                .collect();
            missing.sort();
            missing.dedup();
            if !missing.is_empty() {
                match Self::ask(cache, &missing) {
                    Some(found) => {
                        for (d, names) in missing.into_iter().zip(found) {
                            known.insert(d.clone(), Some(Arc::new(names)));
                        }
                    }
                    // Git stopped at a child of one of them: each directory
                    // on its own, so that only those git cannot answer about
                    // are asked about per manifest.
                    None => {
                        for d in missing {
                            let names = Self::ask(cache, &[d])
                                .and_then(|f| f.into_iter().next())
                                .map(Arc::new);
                            known.insert(d.clone(), names);
                        }
                    }
                }
            }
            dirs.iter()
                .map(|d| known.get(*d).cloned().flatten())
                .collect()
        };
        let Some(ignored) = ignored else {
            // As before 2.1: one `git check-ignore` for this manifest's
            // children, and what git printed before it stopped.
            return crate::run::ignored_listing_children(
                &crate::run::Checkout::direct(cache.root()),
                m,
            );
        };
        let seen: HashSet<&str> = m.entries.iter().map(|e| e.path.as_str()).collect();
        let mut out: Vec<RepoPath> = dirs
            .iter()
            .zip(ignored)
            .flat_map(|(d, names)| names.iter().map(|n| child_path(d, n)).collect::<Vec<_>>())
            .filter(|c| !seen.contains(c.as_str()))
            .filter_map(|c| RepoPath::new(&c).ok())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// [`IgnoredChildren::of`] for the directories listed by the entries
    /// from index `from` on (a manifest's own, after a shared base's, whose
    /// part the caller has): what `m` names is never left out.
    fn of_from(&self, cache: &CheckoutCache, m: &InputManifest, from: usize) -> Vec<RepoPath> {
        let dirs: Vec<&RepoPath> = m.entries[from.min(m.entries.len())..]
            .iter()
            .filter(|e| e.kind == EntryKind::DirListing)
            .map(|e| &e.path)
            .collect();
        if dirs.is_empty() {
            return vec![];
        }
        let ignored: Option<Vec<Arc<Vec<String>>>> = {
            let mut known = self.0.lock().unwrap_or_else(|p| p.into_inner());
            let mut missing: Vec<&RepoPath> = dirs
                .iter()
                .copied()
                .filter(|d| !known.contains_key(*d))
                .collect();
            missing.sort();
            missing.dedup();
            if !missing.is_empty() {
                match Self::ask(cache, &missing) {
                    Some(found) => {
                        for (d, names) in missing.into_iter().zip(found) {
                            known.insert(d.clone(), Some(Arc::new(names)));
                        }
                    }
                    None => {
                        for d in missing {
                            let names = Self::ask(cache, &[d])
                                .and_then(|f| f.into_iter().next())
                                .map(Arc::new);
                            known.insert(d.clone(), names);
                        }
                    }
                }
            }
            dirs.iter()
                .map(|d| known.get(*d).cloned().flatten())
                .collect()
        };
        let Some(ignored) = ignored else {
            return self.of(cache, m);
        };
        let seen: HashSet<&str> = m.entries.iter().map(|e| e.path.as_str()).collect();
        let mut out: Vec<RepoPath> = dirs
            .iter()
            .zip(ignored)
            .flat_map(|(d, names)| names.iter().map(|n| child_path(d, n)).collect::<Vec<_>>())
            .filter(|c| !seen.contains(c.as_str()))
            .filter_map(|c| RepoPath::new(&c).ok())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// The names git ignores among the children of each of `dirs`, in one
    /// `git check-ignore`; `None` when git did not answer (exit 0 or 1).
    fn ask(cache: &CheckoutCache, dirs: &[&RepoPath]) -> Option<Vec<Vec<String>>> {
        let mut owner: HashMap<String, (usize, String)> = HashMap::new();
        for (i, d) in dirs.iter().enumerate() {
            for name in cache.child_names(d) {
                owner.insert(child_path(d, &name), (i, name));
            }
        }
        let mut paths: Vec<String> = owner.keys().cloned().collect();
        paths.sort();
        let (ignored, answered) = crate::run::git_check_ignore(cache.root(), &paths);
        if !answered {
            return None;
        }
        let mut found = vec![Vec::new(); dirs.len()];
        for p in ignored {
            if let Some((i, name)) = owner.get(&p) {
                found[*i].push(name.clone());
            }
        }
        Some(found)
    }
}

/// The failure a file's reason names when no candidate passes: the one that
/// got furthest, and of several that got as far, the last in the store's
/// order (`failed` is each failure with its candidate's place in it), as
/// before 2.1, when candidates were checked in the store's order.
fn best_failure<'a>(failed: impl IntoIterator<Item = (usize, &'a Failure)>) -> Option<&'a Failure> {
    let mut failed: Vec<(usize, &Failure)> = failed.into_iter().collect();
    failed.sort_by_key(|(i, _)| *i);
    failed.into_iter().map(|(_, f)| f).max_by_key(|f| f.rank)
}

/// When a candidate says it was issued, read from its payload before any
/// check, only to check the newest candidates first (each is still checked
/// in full); `None` when it cannot be read.
fn issued_hint(s: &StoredEnvelope) -> Option<i64> {
    if let Some(i) = s.issued {
        return Some(i);
    }
    #[derive(serde::Deserialize)]
    struct Statement {
        predicate: Issued,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Issued {
        issued_at: String,
    }
    if s.error.is_some() {
        return None;
    }
    let st: Statement = match decode_record(&s.bytes).ok()? {
        Record::FormatOne(bytes) => {
            let payload = Envelope::from_json(bytes).ok()?.payload_bytes().ok()?;
            serde_json::from_slice(&payload).ok()?
        }
        Record::FormatThree(frame) => serde_json::from_slice(&frame.statement).ok()?,
    };
    parse_rfc3339(&st.predicate.issued_at).ok()
}

/// Run `f` (which verifies files in parallel) on `VCI_JOBS` threads, by
/// default one per CPU; on the global pool if a pool cannot be made.
fn in_plan_pool<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    let jobs = std::env::var("VCI_JOBS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    match rayon::ThreadPoolBuilder::new().num_threads(jobs).build() {
        Ok(pool) => pool.install(f),
        Err(_) => f(),
    }
}

impl Verifier<'_> {
    /// [`Verifier::natives`], from the booted application.
    fn natives(&self) -> &Result<vci_adapter::InstalledExternals, String> {
        self.natives.get_or_init(|| {
            self.store.set_flag(&natives_flag(&self.project.name));
            self.project
                .adapter
                .native_externals(&self.child.to_child_env())
                .map_err(|e| e.to_string())
                .and_then(|o| o.ok_or_else(|| "not enumerable".to_owned()))
        })
    }

    /// The current global manifest of `f` (`run::global_manifest`), captured
    /// through the plan's checkout cache once per set of global observations.
    /// `ignored`: leave out what the project's `rails_inputs`/`ignore_inputs`
    /// leave out (as `vci run` does since 2.7.36); without, every global
    /// input (as `vci run` recorded them before).
    fn global_now(&self, f: &TestFile, ignored: bool) -> Result<Arc<InputManifest>, String> {
        let mut obs =
            crate::global::observations(&self.ctx.root, self.project.adapter.as_ref(), &f.abs)
                .map_err(|e| format!("{e:#}"))?;
        if ignored {
            obs.retain(|(p, _)| self.project.ignored_input(p.as_str()).is_none());
        }
        if let Some(g) = self
            .globals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&obs)
        {
            return g.clone();
        }
        let g = InputManifest::capture_cached(
            self.checkout,
            &obs,
            vec![],
            &crate::run::global_env_keys(self.project.adapter.name()),
            lookup(&self.child),
        )
        .and_then(|m| m.check_case_collisions().map(|()| Arc::new(m)))
        .map_err(|e| format!("{:#}", anyhow::Error::from(e)));
        self.globals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(obs)
            .or_insert(g)
            .clone()
    }

    /// [`InputManifest::check_case_collisions`] of a manifest whose root is
    /// `root`, once per root.
    fn case_collisions(&self, root: &str, m: &InputManifest) -> Result<(), String> {
        if let Some(r) = self
            .collisions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(root)
        {
            return r.clone();
        }
        let r = m.check_case_collisions().map_err(|e| e.to_string());
        self.collisions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(root.to_owned(), r.clone());
        r
    }
}

/// The checks of a shared base manifest, made once for every unit sharing
/// it (2.7.30): a vex unit's manifest is 2,700 shared entries and about 150
/// of its own, and every check walked all of them for each of 4,000
/// candidates (about 100 thread-seconds a plan). A unit's verdict checks
/// its own entries and combines them with these. Anything unusual (a base
/// that cannot be decoded, an own entry that shadows a base path) falls
/// back to the full check or runs the unit.
struct BaseCheck {
    /// The base's entries (an own entry is never one of them).
    set: HashSet<vci_core::InputEntry>,
    /// The base's entries that differ from the checkout (`entry:` ones).
    mismatches: Vec<vci_core::Mismatch>,
    /// What git ignores under the base's listed directories.
    extra: Vec<RepoPath>,
    /// The base's case-folded prefixes ([`InputManifest::case_prefix_index`]).
    prefixes: BTreeMap<String, String>,
    /// The base's own case collisions.
    collisions: Result<(), String>,
}

impl Verifier<'_> {
    /// The checks of base manifest `root`, made once (see [`BaseCheck`]);
    /// `None` when the base is not at hand (the full checks run).
    fn base_check(&self, root: &str) -> Option<Arc<BaseCheck>> {
        if let Some(b) = self
            .base_checks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(root)
        {
            return Some(b.clone());
        }
        let base = self.manifests.base_manifest(root)?;
        let extra = self.ignored.of(self.checkout, &base);
        let mismatches: Vec<vci_core::Mismatch> = base
            .diff_against_cache(self.checkout, lookup(&self.child), &extra)
            .ok()?
            .into_iter()
            .filter(|m| m.what.starts_with("entry:"))
            .collect();
        let bc = Arc::new(BaseCheck {
            set: base.entries.iter().cloned().collect(),
            mismatches,
            extra,
            prefixes: base.case_prefix_index(),
            collisions: base.check_case_collisions().map_err(|e| e.to_string()),
        });
        self.base_checks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(root.to_owned(), bc.clone());
        Some(bc)
    }
}

/// The case-collision check of a shape group, made once for every format-3
/// candidate whose descriptor extends it (STORE-V2 section 1.5 step 8; the
/// format-3 counterpart of [`BaseCheck`]'s prefixes): a vex unit's set is
/// ~2,700 group entries and ~150 of its own, and folding every path of
/// every candidate cost 1.5 ms of the 2.9 ms a candidate's step 8 takes
/// (`tests/replay.rs`, the synthetic vex unit). A candidate folds its own
/// entries against these; a collision among them or with the group falls
/// back to the full check over its whole set.
struct GroupCase {
    /// The group's case-folded prefixes ([`InputManifest::case_prefix_index`]).
    prefixes: BTreeMap<String, String>,
    /// The group's own case collisions.
    collisions: Result<(), String>,
}

impl Verifier<'_> {
    /// The case-collision check of group `g` of the shape `shape_id`, made
    /// once (see [`GroupCase`]); `None` for a group the shape does not have.
    fn group_case(&self, shape_id: &str, g: u8, shape: &Shape) -> Option<Arc<GroupCase>> {
        let key = (shape_id.to_owned(), g);
        if let Some(c) = self
            .group_cases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
        {
            return Some(c.clone());
        }
        let group = shape.groups.get(g as usize)?;
        let paths = InputManifest {
            entries: group
                .iter()
                .filter_map(|&i| shape.entries.get(i))
                .map(path_entry)
                .collect(),
            externals: vec![],
            env: vec![],
        };
        let gc = Arc::new(GroupCase {
            prefixes: paths.case_prefix_index(),
            collisions: paths.check_case_collisions().map_err(|e| e.to_string()),
        });
        self.group_cases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key, gc.clone());
        Some(gc)
    }
}

/// A shape entry as an entry of a manifest of paths only (no attested size
/// or hash), for the checks that look at paths and kinds.
fn path_entry(e: &ShapeEntry) -> InputEntry {
    InputEntry {
        path: e.path.clone(),
        kind: e.kind,
        exec: e.exec,
        size: 0,
        hash: String::new(),
    }
}

/// What CI resolves Python externals against: the distributions installed in
/// the `uv run --locked` environment, and the `uv.lock` pins.
type PythonExternals = (
    Result<vci_adapter::InstalledExternals, String>,
    Result<Option<crate::externals::LockedPackages>, String>,
);

fn is_exact(l: &Libraries) -> bool {
    *l == Libraries::Exact
}

fn verdict_run(f: &TestFile, reason: &str) -> FileVerdict {
    FileVerdict {
        test_id: f.test_id.as_str().to_owned(),
        file: f.project_rel.clone(),
        project: String::new(),
        skip: false,
        reason: reason.to_owned(),
        libraries: Libraries::Exact,
        rails_inputs: None,
        by: None,
        candidates: vec![],
        project_idx: f.project,
    }
}

/// Top-level plan. Never fails: problems become `run_all` (for everything,
/// or for one project).
pub fn plan(opts: &PlanOptions) -> Result<PlanResult> {
    let t_plan = std::time::Instant::now();
    let r = plan_timed(opts);
    timing("plan total", t_plan);
    r
}

fn plan_timed(opts: &PlanOptions) -> Result<PlanResult> {
    let (repo, root) = open_repo()?;
    let store = crate::store::for_repo(&repo);
    store.warm();
    let mut res = PlanResult {
        base_ref: None,
        base_commit: None,
        run_all: None,
        warnings: vec![],
        projects: vec![],
        files: vec![],
        multi: false,
        config: None,
        allowed: None,
        fetch_failed: None,
        store_kind: store.kind(),
    };
    // The store selection's warnings (printed when it was opened).
    res.warnings.extend(crate::store::warnings_of(&repo));
    // `--fetch`: fetch attestations while the projects are probed; joined
    // before the store is read (and before returning, whatever happens).
    // A store without an exchange has nothing to fetch.
    let mut fetch = match (opts.fetch.clone(), store.exchange().is_some()) {
        (Some(remote), true) => {
            let (store, from) = (store.clone(), remote.clone());
            let handle = std::thread::spawn(move || {
                let t = std::time::Instant::now();
                let r = crate::cmds::fetch_messages(&*store, from.as_deref());
                timing("fetch attestations (--fetch, in the background)", t);
                r
            });
            Some((remote, handle))
        }
        (Some(Some(remote)), false) => {
            let w = format!(
                "the {} store has no remote: --fetch {} is ignored",
                store.kind(),
                crate::cmds::redact_userinfo(&remote)
            );
            eprintln!("vci: warning: {w}");
            res.warnings.push(w);
            None
        }
        (_, false) | (None, true) => None,
    };
    let out = plan_with(opts, repo, root, &*store, &mut res, &mut fetch);
    join_fetch(&mut fetch, &mut res);
    out.map(|()| res)
}

/// A `--fetch` running in the background: the remote asked for and the
/// thread fetching from it (its messages for stderr, or the error).
type PendingFetch = Option<(Option<String>, std::thread::JoinHandle<Result<Vec<String>>>)>;

/// Wait for a pending `--fetch` and report it as `vci fetch` does; a failure
/// is a warning (only attestations already stored locally are used).
fn join_fetch(fetch: &mut PendingFetch, res: &mut PlanResult) {
    let Some((remote, handle)) = fetch.take() else {
        return;
    };
    let outcome = handle
        .join()
        .unwrap_or_else(|p| std::panic::resume_unwind(p));
    match outcome {
        Ok(lines) => {
            for l in lines {
                eprintln!("{l}");
            }
        }
        Err(e) => {
            let from = remote
                .as_deref()
                .map(|r| format!(" from {}", crate::cmds::redact_userinfo(r)))
                .unwrap_or_default();
            let w = format!(
                "could not fetch attestations{from}: {e:#}; only attestations already stored locally are used"
            );
            eprintln!("vci: warning: {w}");
            res.warnings.push(w.clone());
            res.fetch_failed = Some(w);
        }
    }
}

/// What one project needs before its files are verified, decided before the
/// projects are probed.
struct ProjectStart {
    child: ChildEnvMap,
    run_all: Option<String>,
    no_skip_ref: Option<String>,
    on_no_skip_ref: bool,
    /// Lines for stderr, printed in project order.
    notes: Vec<String>,
}

/// What probing one project found: its test files, its warnings, and (when
/// its files are to be verified) the toolchain and externals CI resolves.
struct Probed {
    files: Result<Vec<TestFile>, String>,
    warnings: Vec<String>,
    resolved: Option<Result<Resolved, String>>,
}

/// The per-project part of a [`Verifier`] that shells out.
struct Resolved {
    repo_id: String,
    versions: vci_adapter::ToolVersions,
    max_ttl: i64,
    python_externals: Option<PythonExternals>,
    go_modules: Option<Result<vci_adapter::InstalledExternals, String>>,
    cargo_lock: Option<Result<vci_adapter::InstalledExternals, String>>,
    rails_gems: Option<Result<vci_adapter::InstalledExternals, String>>,
}

/// `VCI_TIMING=1`: print how long a phase of the plan took, on stderr.
pub(crate) fn timing(what: &str, since: std::time::Instant) {
    if vci_core::metrics::on() {
        vci_core::timing_line!("{what}: {:.2}s", since.elapsed().as_secs_f64());
    }
}

/// The attestations a plan remembered passing on `head`'s tree, else on
/// `base`'s (test key -> attestation key; see
/// [`AttestationStore::passing_on`]).
fn passing_memos(
    store: &dyn AttestationStore,
    head: Option<&str>,
    base: Option<&str>,
) -> BTreeMap<String, String> {
    let first16 = |t: &str| -> String { t.chars().take(16).collect() };
    let mut memos = base
        .map(|b| store.passing_on(&first16(b)))
        .unwrap_or_default();
    if let Some(h) = head {
        memos.extend(store.passing_on(&first16(h)));
    }
    memos
}

/// How many of a unit's newest candidates a plan reads before its first
/// verdict, besides the ones `choose_candidates` picks.
const READ_FIRST: usize = 2;

/// The store flag saying a plan of `project` compared native libraries.
fn natives_flag(project: &str) -> String {
    format!("plan:natives:{project}")
}

/// List a project's test files and, with `resolve`, resolve its toolchain
/// and externals at the same time (both may shell out: uv, go, cargo, ruby;
/// pytest and Minitest files are listed without a process).
fn probe_project(
    ctx: &Ctx,
    store: &dyn AttestationStore,
    idx: usize,
    project: &Project,
    child: &ChildEnvMap,
    resolve: bool,
    repo_id: &Result<String, String>,
) -> Probed {
    let env = child.to_child_env();
    std::thread::scope(|s| {
        let resolving = resolve.then(|| {
            s.spawn(|| {
                let t = std::time::Instant::now();
                let r = resolve_project(ctx, project, &env, repo_id);
                timing(
                    &format!("{}: resolve toolchain and externals", project.name),
                    t,
                );
                r
            })
        });
        // 2.7.22: a plan that compared native libraries last time booted the
        // application for them in the verdicts (about 3 s on vex), with
        // every verdict thread waiting; the boot is started here, beside
        // the fetch, and not waited for (2.7.26): the verdicts that need it
        // wait for what is left of it.
        if resolve && project.adapter.name() == "rails" && store.flag(&natives_flag(&project.name))
        {
            project.adapter.start_native_externals(&env);
        }
        let t = std::time::Instant::now();
        let files = project
            .adapter
            .list_test_files(&env)
            .map_err(anyhow::Error::from)
            .and_then(|l| project.test_files(idx, l))
            .map_err(|e| format!("listing test files failed: {e:#}"));
        timing(&format!("{}: list test files", project.name), t);
        // What the project's configuration leaves out (Rails: test files of
        // the runner `runner` does not select), as `vci run` prints it.
        let warnings = project.adapter.warnings(&env);
        let resolved = resolving.map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)));
        Probed {
            files,
            warnings,
            resolved,
        }
    })
}

/// The toolchain and the installed externals of a project, as CI resolves
/// them now.
fn resolve_project(
    ctx: &Ctx,
    project: &Project,
    env: &vci_adapter::ChildEnv,
    repo_id: &Result<String, String>,
) -> Result<Resolved, String> {
    (|| -> Result<Resolved> {
        let repo_id = repo_id.clone().map_err(anyhow::Error::msg)?;
        let versions = project.adapter.tool_versions_with_env(env)?;
        let max_ttl = project.policy.max_ttl_secs()?;
        let python_externals = if project.adapter.name() == "pytest" {
            Some((
                project
                    .adapter
                    .installed_externals(env)
                    .map_err(|e| e.to_string())
                    .and_then(|o| o.ok_or_else(|| "not enumerable".to_owned())),
                crate::externals::uv_lock_packages(&project.dir, &ctx.root),
            ))
        } else {
            None
        };
        let listed = |name: &str| {
            (project.adapter.name() == name).then(|| {
                project
                    .adapter
                    .installed_externals(env)
                    .map_err(|e| e.to_string())
                    .and_then(|o| o.ok_or_else(|| "not enumerable".to_owned()))
            })
        };
        Ok(Resolved {
            repo_id,
            versions,
            max_ttl,
            python_externals,
            go_modules: listed("go"),
            cargo_lock: listed("cargo"),
            rails_gems: listed("rails"),
        })
    })()
    .map_err(|e| format!("{e:#}"))
}

fn plan_with(
    opts: &PlanOptions,
    repo: Repo,
    root: camino::Utf8PathBuf,
    store: &dyn AttestationStore,
    res: &mut PlanResult,
    fetch: &mut PendingFetch,
) -> Result<()> {
    // 1. Policy and trust roots from the BASE commit.
    let t_base = std::time::Instant::now();
    let (base_ref, base) = match resolve_base(&repo, opts.base_ref.as_deref()) {
        Ok(x) => x,
        Err(e) => {
            res.run_all = Some(e);
            return fallback_listing(opts, res, repo, root);
        }
    };
    if let Some(w) = self_referential_base(&repo, &base_ref, &base) {
        eprintln!("vci: warning: {w}");
        res.warnings.push(w);
    }
    res.base_ref = Some(base_ref);
    res.base_commit = Some(base.clone());
    let config = match repo.show_file(&base, CONFIG_FILE) {
        Ok(Some(bytes)) => match std::str::from_utf8(&bytes)
            .map_err(anyhow::Error::from)
            .and_then(Config::parse)
        {
            Ok(c) => c,
            Err(e) => {
                res.run_all = Some(format!("{CONFIG_FILE} at base is invalid: {e:#}"));
                return fallback_listing(opts, res, repo, root);
            }
        },
        Ok(None) => {
            res.run_all = Some(format!("{CONFIG_FILE} is missing at the base commit"));
            return fallback_listing(opts, res, repo, root);
        }
        Err(e) => {
            res.run_all = Some(format!("reading {CONFIG_FILE} at base: {e}"));
            return fallback_listing(opts, res, repo, root);
        }
    };
    for w in config.warnings(&format!("{CONFIG_FILE} at the base commit")) {
        eprintln!("vci: warning: {w}");
        res.warnings.push(w);
    }
    // `--project`: the other projects are not listed, probed or verified
    // (their toolchains may be missing in this job).
    let mut config = config;
    config.select_projects(&opts.projects, &format!("{CONFIG_FILE} at the base commit"))?;
    // Keyless trust (identities and the Sigstore trust root) from the base
    // commit too; without identities.toml there is none.
    let keyless = load_keyless(&repo, &base, &mut res.warnings);
    let allowed = match repo.show_file(&base, ALLOWED_SIGNERS_FILE) {
        Ok(Some(bytes)) => match std::str::from_utf8(&bytes)
            .map_err(|e| e.to_string())
            .and_then(|t| AllowedSigners::parse(t).map_err(|e| e.to_string()))
        {
            Ok(a) => Some(a),
            Err(e) => {
                res.run_all = Some(format!("{ALLOWED_SIGNERS_FILE} at base is invalid: {e}"));
                None
            }
        },
        // Keyless signers only: no SSH key is trusted.
        Ok(None) if keyless.as_ref().is_some_and(|k| k.identities.is_ok()) => None,
        Ok(None) => {
            res.run_all = Some(format!(
                "{ALLOWED_SIGNERS_FILE} is missing at the base commit"
            ));
            None
        }
        Err(e) => {
            res.run_all = Some(format!("reading {ALLOWED_SIGNERS_FILE} at base: {e}"));
            None
        }
    };
    let refs = current_refs(&repo);
    res.multi = config.is_multi();
    res.allowed = allowed.clone();
    // Someone is trusted: an SSH key or a CI identity.
    let trusted = allowed.is_some() || keyless.as_ref().is_some_and(|k| k.identities.is_ok());
    timing("read the base commit's policy and signers", t_base);
    let no_ssh_signers = AllowedSigners::default();

    // 2. Projects (base config), their test files and, for the projects
    // whose files are verified, the toolchain and externals CI resolves now.
    // Listing and resolving shell out (uv, go, cargo, ruby): every project is
    // probed at once (listing and resolving at the same time), while
    // `--fetch` runs; what they print is printed in project order.
    res.config = Some(config.clone());
    let ctx = match Ctx::new(repo, root.clone(), config) {
        Ok(c) => c,
        Err(e) => {
            res.run_all = Some(format!("{e:#}"));
            return Ok(());
        }
    };
    let multi_project = ctx.projects.len() > 1;
    let starts: Vec<ProjectStart> = ctx
        .projects
        .iter()
        .map(|p| {
            let mut start = ProjectStart {
                child: p.child_env(),
                run_all: res.run_all.clone(),
                no_skip_ref: None,
                on_no_skip_ref: false,
                notes: vec![],
            };
            let matched = refs
                .iter()
                .find(|r| p.policy.no_skip_refs.iter().any(|g| glob_match(g, r)));
            start.on_no_skip_ref = matched.is_some();
            if start.run_all.is_none()
                && let Some(r) = matched
            {
                if p.policy.no_skip_refs_except.is_empty() {
                    start.run_all = Some(format!("policy.no_skip_refs matches {r}"));
                } else {
                    start.notes.push(format!(
                        "vci: note: {}policy.no_skip_refs matches {r}: only attestations by {} (policy.no_skip_refs_except) can skip",
                        if multi_project {
                            format!("{}: ", p.label())
                        } else {
                            String::new()
                        },
                        p.policy.no_skip_refs_except.join(", ")
                    ));
                    start.no_skip_ref = Some(r.clone());
                }
            }
            start
        })
        .collect();
    let repo_id = ctx.repo.repo_id().map_err(|e| format!("{e:#}"));
    let probed: Vec<Probed> = std::thread::scope(|s| {
        let handles: Vec<_> = ctx
            .projects
            .iter()
            .zip(&starts)
            .enumerate()
            .map(|(i, (p, start))| {
                let resolve = start.run_all.is_none() && trusted;
                let (ctx, repo_id) = (&ctx, &repo_id);
                s.spawn(move || probe_project(ctx, store, i, p, &start.child, resolve, repo_id))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
            .collect()
    });
    let mut files: Vec<TestFile> = Vec::new();
    let mut resolved: Vec<Option<Result<Resolved, String>>> = Vec::new();
    for ((p, start), probed) in ctx.projects.iter().zip(starts).zip(probed) {
        for n in &start.notes {
            eprintln!("{n}");
        }
        let mut run_all = start.run_all;
        match probed.files {
            Ok(f) => files.extend(f),
            Err(e) => run_all = Some(e),
        }
        for w in probed.warnings {
            let w = if multi_project {
                format!("{}: {w}", p.label())
            } else {
                w
            };
            eprintln!("vci: warning: {w}");
            res.warnings.push(w);
        }
        resolved.push(probed.resolved);
        res.projects.push(ProjectPlan {
            name: p.name.clone(),
            path: p.rel.clone(),
            adapter: p.adapter.name().to_owned(),
            run_all,
            no_skip_ref: start.no_skip_ref,
            on_no_skip_ref: start.on_no_skip_ref,
            no_skip_refs_except: p.policy.no_skip_refs_except.clone(),
            attest_on_any_ref: p.policy.attest_on_any_ref.clone(),
            dir: p.dir.clone(),
            child_env: Some(start.child),
            adapter_options: p.adapter_options.clone(),
        });
    }
    mark_cross_project_ambiguity(&mut files);
    if let Some(id) = &opts.only {
        files.retain(|f| f.test_id.as_str() == id);
    }

    // 3. Stored candidates from the store (git-meta: the local store, which
    // `vci fetch`, or `--fetch` above, materializes the remote's into),
    // looked up per unit, then per project: toolchain, repo identity, and
    // the checks.
    join_fetch(fetch, res);
    let mut by_id: BTreeMap<String, Vec<StoredEnvelope>> = BTreeMap::new();
    // The candidates read only for the units the first pass cannot skip
    // (`hydrate_more`), by unit.
    let mut set_aside = SetAside::new();
    // The format-3 objects the candidates name, loaded once per plan.
    let objects = ObjectLoader::default();
    let load_timers = Timers::default();
    if !res.projects.iter().all(|p| p.run_all.is_some()) {
        // A fetch downloads keys, not values: fetch the values this plan
        // reads (the candidates of the units it verifies, then the input
        // manifests they reference) in one batch each.
        hydrate_for_plan(store, &ctx.repo, &files, res);
        let t_lookup = std::time::Instant::now();
        let looked_up = (|| -> Result<BTreeMap<String, Vec<StoredEnvelope>>, StoreError> {
            if let StoreStatus::Absent { advice } = store.status()? {
                let w = absent_warning(store, &advice);
                eprintln!("vci: warning: {w}");
                res.warnings.push(w);
            }
            // Keys first; the values in one batch below (2.7.23).
            let mut seen = BTreeSet::new();
            let ids: Vec<&str> = files
                .iter()
                .map(|f| f.test_id.as_str())
                .filter(|id| seen.insert(*id))
                .collect();
            let listed = store.list_units(&ids)?;
            Ok(ids.into_iter().map(str::to_owned).zip(listed).collect())
        })();
        timing("look up the candidates", t_lookup);
        let looked_up = looked_up.and_then(|mut m| {
            let t = std::time::Instant::now();
            // Only the candidates the verdict checks first are read (the
            // ones `hydrate_for_plan` chose); the rest are marked not read,
            // and `hydrate_more` reads them for the units not skipped
            // (2.7.23: a vex store held 18,700 fetched candidates, 340 MB,
            // for 4,100 the verdicts needed).
            let head = ctx.repo.head_tree().ok();
            let base = res
                .base_commit
                .as_deref()
                .and_then(|b| ctx.repo.tree_of(b).ok());
            let memos = passing_memos(store, head.as_deref(), base.as_deref());
            // On a server, only the candidates the prefetch read (2.8.2):
            // the newest few of every unit were a second request of 1,200
            // to 1,500 values (30 to 45 MB on vex's Turso) per plan, for the
            // few units whose first choice fails, which the next round reads
            // (`hydrate_more`, newer candidates first after an inputs
            // failure).
            let read_first = if store.caps().remote_reads {
                0
            } else {
                READ_FIRST
            };
            let mut read: Vec<&mut StoredEnvelope> = Vec::new();
            for (id, cands) in m.iter_mut() {
                let memo = cands
                    .first()
                    .and_then(|c| memos.get(&c.test_key))
                    .map(String::as_str);
                let mut chosen: BTreeSet<usize> =
                    choose_candidates(cands, head.as_deref(), base.as_deref(), memo)
                        .into_iter()
                        .collect();
                // And the few newest after them: when the newest fails (a
                // pull request attested the file on its own tree), the
                // one before it usually passes, without a second round.
                let mut by_age: Vec<usize> = (0..cands.len()).collect();
                by_age.sort_by_key(|&i| std::cmp::Reverse(cands[i].issued));
                chosen.extend(by_age.into_iter().take(read_first));
                for (i, c) in cands.iter_mut().enumerate() {
                    if chosen.contains(&i) {
                        read.push(c);
                    } else {
                        c.mark_not_fetched();
                        set_aside
                            .entry(id.clone())
                            .or_default()
                            .insert(c.key.clone());
                    }
                }
            }
            store.read_values(&mut read)?;
            timing("read the candidates", t);
            // The verdict objects of the format-3 candidates just read, in
            // one batch (STORE-V2 section 1.5 step 5).
            let t = std::time::Instant::now();
            preload_objects(
                store,
                &objects,
                &load_timers,
                m.values().flatten(),
                head.as_deref(),
            );
            timing("load the verdict objects", t);
            Ok(m)
        });
        match looked_up {
            Ok(m) => by_id = m,
            Err(e) => {
                set_aside.clear();
                let e = format!("reading attestations from {}: {e:#}", store.kind());
                for p in res.projects.iter_mut() {
                    p.run_all.get_or_insert_with(|| e.clone());
                }
            }
        }
    }
    let now = now_unix();
    // The checkout does not change during a plan: each path is observed once
    // for every candidate of every file (and every project).
    let checkout = CheckoutCache::new(&ctx.root);
    let ignored = IgnoredChildren::default();
    let head_tree = ctx.repo.head_tree().ok();
    let verifiers: Vec<Result<Verifier<'_>, String>> = ctx
        .projects
        .iter()
        .zip(resolved)
        .enumerate()
        .map(
            |(pi, (project, resolved))| match (&res.projects[pi].run_all, trusted, resolved) {
                (Some(r), _, _) => Err(r.clone()),
                (None, false, _) => Err("no trusted signers".to_owned()),
                (None, true, None) => Err("internal: the project was not resolved".to_owned()),
                (None, true, Some(r)) => r.map(|r| Verifier {
                    ctx: &ctx,
                    store,
                    head_tree: head_tree.clone(),
                    project,
                    allowed: allowed.as_ref().unwrap_or(&no_ssh_signers),
                    keyless: keyless.as_ref(),
                    now,
                    max_ttl: r.max_ttl,
                    repo_id: r.repo_id,
                    versions: r.versions,
                    child: res.projects[pi].child_env.clone().unwrap_or_default(),
                    no_skip_ref: res.projects[pi].no_skip_ref.clone(),
                    python_externals: r.python_externals,
                    go_modules: r.go_modules,
                    cargo_lock: r.cargo_lock,
                    rails_gems: r.rails_gems,
                    natives: std::sync::OnceLock::new(),
                    manifests: ManifestLoader::default(),
                    objects: &objects,
                    hdr_checks: Mutex::default(),
                    checkout: &checkout,
                    ignored: &ignored,
                    globals: Mutex::default(),
                    collisions: Mutex::default(),
                    base_checks: Mutex::default(),
                    group_cases: Mutex::default(),
                    timers: Timers::default(),
                }),
            },
        )
        .collect();
    // Every project's files at once, and each project's files in parallel
    // (`VCI_JOBS` threads; the checks rehash the checkout through the cache
    // and may boot a Rails application, once per project, for the native
    // libraries a candidate records), collected in project and file order.
    let t_verdicts = std::time::Instant::now();
    let verdicts: Vec<Vec<FileVerdict>> = in_plan_pool(|| {
        verifiers
            .par_iter()
            .enumerate()
            .map(|(pi, verifier)| {
                let mine: Vec<&TestFile> = files.iter().filter(|f| f.project == pi).collect();
                match verifier {
                    Err(r) => mine.iter().map(|f| verdict_run(f, r)).collect::<Vec<_>>(),
                    Ok(v) => mine
                        .par_iter()
                        .map(|f| {
                            // A test id listed by two projects: both see the
                            // same candidates (they are ambiguous and run
                            // anyway).
                            let cands = by_id
                                .get(f.test_id.as_str())
                                .map(Vec::as_slice)
                                .unwrap_or_default();
                            v.verdict(f, cands)
                        })
                        .collect(),
                }
            })
            .collect()
    });
    timing("verdicts (rehash inputs, check candidates)", t_verdicts);
    let mut verdicts = verdicts;
    let t = std::time::Instant::now();
    // A plan that verifies no project reads nothing from the store (its
    // memos would go unused), so it never connects, nor runs a [store]
    // token_command.
    let memos = if verifiers.iter().any(Result::is_ok) {
        let base = res
            .base_commit
            .as_deref()
            .and_then(|b| ctx.repo.tree_of(b).ok());
        passing_memos(store, head_tree.as_deref(), base.as_deref())
    } else {
        BTreeMap::new()
    };
    hydrate_more(
        store,
        &files,
        &verifiers,
        &by_id,
        set_aside,
        &memos,
        &mut verdicts,
        res,
    );
    timing("verdicts again for what was fetched meanwhile", t);
    objects.report();
    // What passed on this tree, for the plans whose base commit it is
    // (2.7.29; see `passing_memos`).
    if let Some(head) = head_tree.as_deref() {
        let t = std::time::Instant::now();
        let passed: Vec<(String, String)> = verdicts
            .iter()
            .flatten()
            .filter(|v| v.skip)
            .filter_map(|v| {
                v.by.as_ref()
                    .map(|b| (vci_core::test_key(&v.test_id), b.meta_key.clone()))
            })
            .collect();
        let n = passed.len();
        let head16: String = head.chars().take(16).collect();
        store.remember_passing(&head16, &passed);
        timing(
            &format!("remember the {n} attestation(s) that passed on this tree"),
            t,
        );
    }
    for (pi, (verifier, verdicts)) in verifiers.iter().zip(verdicts).enumerate() {
        match verifier {
            Err(r) => {
                res.projects[pi].run_all.get_or_insert_with(|| r.clone());
            }
            Ok(v) => v
                .timers
                .report(&format!("{}: verdicts", res.projects[pi].name)),
        }
        res.files.extend(verdicts);
    }
    finish(res);
    Ok(())
}

/// The warning for a store that does not exist yet (`advice`: what creates
/// it). A lazy store's (git-meta's) is the one vci always printed.
fn absent_warning(store: &dyn AttestationStore, advice: &str) -> String {
    let kind = store.kind();
    if store.caps().lazy_values {
        format!(
            "no {kind} store in this repository: no attestations are available ({advice} first)"
        )
    } else {
        format!("no attestations are available in the {kind} store ({advice})")
    }
}

/// Fetch the stored values a plan of `files` reads that were not fetched yet
/// (lazy metadata: `vci fetch` downloads the keys only): the candidates of
/// the units of every project that is verified, and the manifests they
/// reference. A failure is a warning: the values not fetched read as such,
/// and their units run.
fn hydrate_for_plan(
    store: &dyn AttestationStore,
    repo: &Repo,
    files: &[TestFile],
    res: &mut PlanResult,
) {
    let t = std::time::Instant::now();
    let ids: Vec<&str> = files
        .iter()
        .filter(|f| {
            res.projects
                .get(f.project)
                .is_some_and(|p| p.run_all.is_none())
        })
        .map(|f| f.test_id.as_str())
        .collect();
    // The envelopes and manifests of each unit's likeliest attestation(s)
    // only, chosen from the keys (vci 2.2 keys say when an attestation was
    // issued and on which tree): one made on this checkout's tree, else the
    // newest; keys without a hint (older) are fetched too. The verdict
    // checks those first and the plan fetches the rest only for the units
    // it could not skip (`hydrate_more`).
    let head = repo.head_tree().ok();
    let base = res
        .base_commit
        .as_deref()
        .and_then(|b| repo.tree_of(b).ok());
    let memos = passing_memos(store, head.as_deref(), base.as_deref());
    let choose = move |cands: &[StoredEnvelope]| -> Vec<usize> {
        let memo = cands
            .first()
            .and_then(|c| memos.get(&c.test_key))
            .map(String::as_str);
        choose_candidates(cands, head.as_deref(), base.as_deref(), memo)
    };
    let warning = match store.prefetch(Prefetch::Units {
        test_ids: &ids,
        choose: Some(&choose),
    }) {
        Ok(h) => h.error.map(|e| {
            format!(
                "could not fetch {} stored attestation value(s): {e}; their units run",
                h.unresolved
            )
        }),
        Err(e) => Some(format!(
            "could not fetch the stored attestation values this plan reads: {e:#}; units whose values were not fetched run"
        )),
    };
    if let Some(w) = warning {
        eprintln!("vci: warning: {w}");
        res.warnings.push(w);
    }
    timing("fetch the stored values the plan reads", t);
}

/// The candidates a plan set aside after its lookup
/// ([`StoredEnvelope::mark_not_fetched`]): it checks a unit's likeliest
/// candidates first and reads the others only for the units it cannot skip
/// (`hydrate_more`). Test id -> the keys set aside and not read yet.
type SetAside = BTreeMap<String, BTreeSet<String>>;

/// The rounds after the first pass (2, then at most 3), for the units it
/// could not skip. A round fetches what a lazy store does not hold here yet
/// (every candidate of a unit with one not fetched, and the input manifests
/// and bases the checks found not fetched; one batch each), reads again the
/// candidates without a value (the ones the plan set aside, and the ones
/// just fetched), and checks those units again. A unit whose newest
/// attestations fail and an older one matches (an input edited and
/// reverted, a branch rebased onto what was attested) is then skipped as
/// with every value read, whether the older value had to be fetched or was
/// here all along (a git-meta clone with its values fetched, SQLite,
/// PostgreSQL: 2.8.0; before, a round that fetched nothing ended the plan,
/// and those units ran). A unit whose newest attestation matches never gets
/// here. Bounded: a round that fetched nothing and whose read made no
/// candidate readable ends it.
#[allow(clippy::too_many_arguments)]
fn hydrate_more(
    store: &dyn AttestationStore,
    files: &[TestFile],
    verifiers: &[Result<Verifier<'_>, String>],
    by_id: &BTreeMap<String, Vec<StoredEnvelope>>,
    mut set_aside: SetAside,
    memos: &BTreeMap<String, String>,
    verdicts: &mut [Vec<FileVerdict>],
    res: &mut PlanResult,
) {
    // A unit whose remembered attestation (the one that passed on the base
    // commit's tree, see `passing_memos`) was read and failed on its inputs
    // has changed inputs: it runs, and no older attestation is fetched or
    // read for it (2.7.32; a run's units not skipped cost 5-17 s of fetching
    // here for the rare reverted input). Units without a remembered
    // attestation are fetched for and read as before.
    let inputs_changed = |f: &TestFile, out: &FileVerdict| -> bool {
        let Some(k) = memos.get(&vci_core::test_key(f.test_id.as_str())) else {
            return false;
        };
        out.candidates.iter().any(|c| {
            c.info.meta_key == *k
                && c.failure.as_ref().is_some_and(|fl| {
                    fl.check == "inputs" && fl.details.iter().any(|d| d.what.starts_with("entry:"))
                })
        })
    };
    // The remembered attestation of a unit whose inputs changed, as read:
    // its key and when it was issued.
    let remembered = |f: &TestFile, cands: &[StoredEnvelope]| -> Option<Option<i64>> {
        let k = memos.get(&vci_core::test_key(f.test_id.as_str()))?;
        cands.iter().find(|c| c.key == *k).map(|c| c.issued)
    };
    // The keys never read for that reason: a unit whose inputs changed
    // since its remembered attestation reads only the candidates issued
    // after it (2.8.2), which a pull request's earlier push or another
    // branch made on the changed inputs, never the older ones.
    let mut older: BTreeSet<String> = BTreeSet::new();
    // The candidates as last read (the store's rows are re-read for the
    // units a round read again).
    let mut current: BTreeMap<String, Vec<StoredEnvelope>> = BTreeMap::new();
    for round in 2..=3 {
        // The units the first pass could not skip that have a candidate
        // without its value: set aside by the plan, or not fetched by a lazy
        // store. Every candidate of theirs is fetched (envelopes, manifests,
        // bases) in one batch each. A unit whose candidates were all read
        // needs only the manifests (or bases) its check found not fetched
        // (`roots`): reading every candidate's manifest again to look for
        // them took 13 s on a full vex run with nothing to fetch.
        let mut ids: BTreeSet<&str> = BTreeSet::new();
        let mut unread: BTreeSet<&str> = BTreeSet::new();
        for (pi, verdicts) in verdicts.iter().enumerate() {
            if verifiers[pi].is_err() {
                continue;
            }
            let mine: Vec<&TestFile> = files.iter().filter(|f| f.project == pi).collect();
            for (f, out) in mine.iter().zip(verdicts.iter()) {
                if out.skip || out.candidates.is_empty() {
                    continue;
                }
                let id = f.test_id.as_str();
                let cands = current
                    .get(id)
                    .or_else(|| by_id.get(id))
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                if inputs_changed(f, out) {
                    // Only the candidates issued after the remembered one
                    // (none when it says nothing of when it was issued).
                    let since = remembered(f, cands).flatten();
                    let newer = |c: &StoredEnvelope| matches!((c.issued, since), (Some(i), Some(m)) if i > m);
                    older.extend(cands.iter().filter(|c| !newer(c)).map(|c| c.key.clone()));
                    let pending = cands.iter().any(|c| {
                        newer(c)
                            && (c.not_fetched()
                                || set_aside.get(id).is_some_and(|s| s.contains(&c.key)))
                    });
                    if !pending {
                        continue;
                    }
                }
                ids.insert(id);
                if set_aside.contains_key(id) || cands.iter().any(StoredEnvelope::not_fetched) {
                    unread.insert(id);
                }
            }
        }
        let roots: BTreeSet<String> = verifiers
            .iter()
            .flatten()
            .flat_map(|v| v.manifests.take_not_fetched())
            .collect();
        if ids.is_empty() || (unread.is_empty() && roots.is_empty()) {
            return;
        }
        let t = std::time::Instant::now();
        let unread_ids: Vec<&str> = unread.iter().copied().collect();
        let root_ids: Vec<&str> = roots.iter().map(String::as_str).collect();
        let skip_older = |cands: &[StoredEnvelope]| -> Vec<usize> {
            (0..cands.len())
                .filter(|&i| !older.contains(&cands[i].key))
                .collect()
        };
        let h = store
            .prefetch(Prefetch::Units {
                test_ids: &unread_ids,
                choose: (!older.is_empty()).then_some(&skip_older as Choose<'_>),
            })
            .and_then(|mut h| {
                h.add(store.prefetch(Prefetch::Manifests { roots: &root_ids })?);
                Ok(h)
            });
        let warning = match &h {
            Ok(h) => h.error.as_ref().map(|e| {
                format!(
                    "could not fetch {} stored attestation value(s) (round {round}): {e}; their units run",
                    h.unresolved
                )
            }),
            Err(e) => Some(format!(
                "could not fetch the stored attestation values the plan reads (round {round}): {e:#}; their units run"
            )),
        };
        if let Some(w) = warning {
            eprintln!("vci: warning: {w}");
            res.warnings.push(w);
        }
        let resolved = h.map(|h| h.resolved).unwrap_or(0);
        if resolved > 0 {
            for v in verifiers.iter().flatten() {
                v.manifests.evict(&roots);
                v.manifests.evict_errors();
            }
        }
        // Read again: after a fetch, every candidate without a value of the
        // units fetched for; with nothing fetched, the candidates the plan
        // set aside and has not read yet. A store that holds every value
        // here fetches nothing, and `resolved` counts only values that were
        // not fetched before (`Hydration`), so nothing fetched does not mean
        // nothing more is readable.
        let again: Vec<&str> = unread
            .iter()
            .copied()
            .filter(|id| resolved > 0 || set_aside.contains_key(*id))
            .collect();
        let only = (resolved == 0).then_some(&set_aside);
        let readable = read_again(store, &again, only, &older, by_id, &mut current, round);
        for id in &again {
            set_aside.remove(*id);
        }
        if resolved == 0 && readable == 0 {
            timing(
                &format!(
                    "round {round}: nothing more to fetch for {} unit(s) not skipped",
                    ids.len()
                ),
                t,
            );
            return;
        }
        // The verdict objects of the candidates of the units checked again
        // (the ones just read, and the ones whose objects a round could not
        // load before), in one batch.
        if let Some(v) = verifiers.iter().flatten().next() {
            let cands = ids.iter().flat_map(|id| {
                current
                    .get(*id)
                    .or_else(|| by_id.get(*id))
                    .map(Vec::as_slice)
                    .unwrap_or_default()
            });
            preload_objects(store, v.objects, &v.timers, cands, v.head_tree.as_deref());
        }
        // Checked again with every candidate readable.
        let fresh = &current;
        let mut rechecked = 0usize;
        in_plan_pool(|| {
            verifiers
                .par_iter()
                .zip(verdicts.par_iter_mut())
                .enumerate()
                .for_each(|(pi, (verifier, verdicts))| {
                    let Ok(v) = verifier else { return };
                    let mine: Vec<&TestFile> = files.iter().filter(|f| f.project == pi).collect();
                    mine.par_iter()
                        .zip(verdicts.par_iter_mut())
                        .filter(|(f, out)| !out.skip && ids.contains(f.test_id.as_str()))
                        .for_each(|(f, out)| {
                            let cands = fresh
                                .get(f.test_id.as_str())
                                .or_else(|| by_id.get(f.test_id.as_str()))
                                .map(Vec::as_slice)
                                .unwrap_or_default();
                            *out = v.verdict(f, cands);
                        });
                });
        });
        for (pi, verdicts) in verdicts.iter().enumerate() {
            if verifiers[pi].is_ok() {
                rechecked += verdicts
                    .iter()
                    .filter(|o| !o.skip && !o.candidates.is_empty())
                    .count();
            }
        }
        let what = if resolved > 0 {
            format!("fetch {resolved} more value(s)")
        } else {
            format!("read {readable} candidate(s) set aside")
        };
        timing(
            &format!(
                "round {round}: {what} for {} unit(s) not skipped, check them again ({rechecked} still not)",
                ids.len()
            ),
            t,
        );
    }
}

/// Read again, in one batch (2.7.23: one unit at a time took 9 s for 2,000
/// units on a laptop), the candidates of the units `ids` that hold no value
/// (as last read: `current`, else the lookup's `by_id`), only the ones
/// `only` holds for their unit when given, never the keys in `never`, and
/// keep them in `current`. Returns how many became readable: none when the
/// store cannot be read (those units' verdicts stand, and they run).
fn read_again(
    store: &dyn AttestationStore,
    ids: &[&str],
    only: Option<&SetAside>,
    never: &BTreeSet<String>,
    by_id: &BTreeMap<String, Vec<StoredEnvelope>>,
    current: &mut BTreeMap<String, Vec<StoredEnvelope>>,
    round: usize,
) -> usize {
    let t = std::time::Instant::now();
    let mut again: Vec<(String, Vec<StoredEnvelope>)> = ids
        .iter()
        .filter_map(|id| {
            current
                .get(*id)
                .or_else(|| by_id.get(*id))
                .map(|c| ((*id).to_owned(), c.clone()))
        })
        .collect();
    let readable = |c: &StoredEnvelope| matches!(c.state(), ValueState::Read(_));
    let count = |again: &[(String, Vec<StoredEnvelope>)]| -> usize {
        again
            .iter()
            .flat_map(|(_, c)| c)
            .filter(|c| readable(c))
            .count()
    };
    let before = count(&again);
    let mut refs: Vec<&mut StoredEnvelope> = again
        .iter_mut()
        .flat_map(|(id, c)| {
            let keys = only.map(|o| o.get(id.as_str()));
            c.iter_mut().filter(move |c| {
                !readable(c)
                    && !never.contains(&c.key)
                    && keys.is_none_or(|k| k.is_some_and(|k| k.contains(&c.key)))
            })
        })
        .collect();
    if refs.is_empty() {
        return 0;
    }
    let asked = refs.len();
    let read = store.read_values(&mut refs);
    drop(refs);
    timing(
        &format!(
            "round {round}: read {asked} candidate value(s) of {} unit(s) again",
            again.len()
        ),
        t,
    );
    if read.is_err() {
        return 0;
    }
    let after = count(&again);
    current.extend(again);
    after.saturating_sub(before)
}

/// A candidate in the order it is checked: (made on this checkout's tree,
/// issued), its place in the store's order, the envelope.
type RankedCandidate<'a> = ((bool, Option<i64>), usize, &'a StoredEnvelope);

/// Which of a unit's stored attestations a plan reads first (by index): the
/// ones whose key says they were made on `head` (this checkout's tree),
/// else the newest by the key's issue time (ties: all), plus every key
/// without a hint. A unit with no hinted key reads them all, as before 2.2.
fn choose_candidates(
    cands: &[StoredEnvelope],
    head: Option<&str>,
    base: Option<&str>,
    memo: Option<&str>,
) -> Vec<usize> {
    let first16 = |t: &str| -> String { t.chars().take(16).collect() };
    // The attestation a plan on this tree (or the base commit's) found
    // passing (2.7.29): read first, and alone among the hinted ones.
    if let Some(k) = memo
        && let Some(i) = cands.iter().position(|c| c.key == k)
    {
        let mut out: Vec<usize> = (0..cands.len())
            .filter(|&i| cands[i].issued.is_none())
            .collect();
        out.push(i);
        out.sort_unstable();
        out.dedup();
        return out;
    }
    let on_tree = |tree: Option<&str>| -> Vec<usize> {
        let Some(t16) = tree.map(first16) else {
            return Vec::new();
        };
        (0..cands.len())
            .filter(|&i| {
                cands[i].issued.is_some() && cands[i].tree.as_deref() == Some(t16.as_str())
            })
            .collect()
    };
    let mut out: Vec<usize> = (0..cands.len())
        .filter(|&i| cands[i].issued.is_none())
        .collect();
    let same_head = on_tree(head);
    // 2.7.27: a pull request's likeliest attestation is the one made on
    // its base commit's tree (master's), not the newest, which another
    // branch made on its own tree: a vex plan fetched 2,000 of those first,
    // then 6,000 more values in a second round (25 s).
    let same_base = if same_head.is_empty() {
        on_tree(base)
    } else {
        Vec::new()
    };
    if !same_head.is_empty() {
        out.extend(same_head);
    } else if !same_base.is_empty() {
        out.extend(same_base);
    } else if let Some(max) = cands.iter().filter_map(|c| c.issued).max() {
        out.extend((0..cands.len()).filter(|&i| cands[i].issued == Some(max)));
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Fill in project names on verdicts; set the top-level `run_all` when every
/// project runs everything.
fn finish(res: &mut PlanResult) {
    for f in res.files.iter_mut() {
        if let Some(p) = res.projects.get(f.project_idx) {
            f.project = p.name.clone();
        }
    }
    if res.run_all.is_none()
        && !res.projects.is_empty()
        && res.projects.iter().all(|p| p.run_all.is_some())
    {
        res.run_all = res.projects[0].run_all.clone();
    }
    if let Some(r) = &res.run_all {
        for p in res.projects.iter_mut() {
            p.run_all.get_or_insert_with(|| r.clone());
        }
    }
}

/// When policy can't be read, still try to list files so the output names
/// them (everything runs).
fn fallback_listing(
    opts: &PlanOptions,
    res: &mut PlanResult,
    repo: Repo,
    root: camino::Utf8PathBuf,
) -> Result<()> {
    let reason = res.run_all.clone().unwrap_or_default();
    let mut config = crate::ctx::working_tree_config(&root).unwrap_or_default();
    config.select_projects(
        &opts.projects,
        &format!("{CONFIG_FILE} in the working tree"),
    )?;
    res.multi = config.is_multi();
    res.config = Some(config.clone());
    if let Ok(ctx) = Ctx::new(repo, root, config) {
        let mut files = Vec::new();
        for (i, p) in ctx.projects.iter().enumerate() {
            let child = p.child_env();
            if let Ok(f) = p
                .adapter
                .list_test_files(&child.to_child_env())
                .map_err(anyhow::Error::from)
                .and_then(|l| p.test_files(i, l))
            {
                files.extend(f);
            }
            res.projects.push(ProjectPlan {
                name: p.name.clone(),
                path: p.rel.clone(),
                adapter: p.adapter.name().to_owned(),
                run_all: Some(reason.clone()),
                no_skip_ref: None,
                on_no_skip_ref: false,
                no_skip_refs_except: vec![],
                attest_on_any_ref: vec![],
                dir: p.dir.clone(),
                child_env: Some(child),
                adapter_options: p.adapter_options.clone(),
            });
        }
        res.files = files.iter().map(|f| verdict_run(f, &reason)).collect();
    }
    finish(res);
    Ok(())
}

/// The current global manifest of a file, with every global input (what an
/// attestation made before 2.7.36 recorded) and without what the project's
/// `rails_inputs`/`ignore_inputs` leave out (the same when nothing is).
struct GlobalsNow {
    all: Result<Arc<InputManifest>, String>,
    ignored: Result<Arc<InputManifest>, String>,
}

impl Verifier<'_> {
    fn verdict(&self, f: &TestFile, cands: &[StoredEnvelope]) -> FileVerdict {
        let mut out = verdict_run(f, "");
        out.libraries = self.project.policy.libraries_for(&f.project_rel);
        out.rails_inputs = self
            .project
            .rails_inputs
            .map(|m| (m, self.project.ignored_inputs.clone()));
        if f.ambiguous {
            out.reason =
                "listed under more than one runner project (or by more than one vci project)"
                    .into();
            return out;
        }
        if let Some(g) = self.project.policy.never_skip_match(&f.project_rel) {
            out.reason = format!("policy.never_skip matches {g:?}");
            return out;
        }
        if cands.is_empty() {
            out.reason = "no attestation".into();
            return out;
        }
        // Current global inputs are the same for every candidate: all of
        // them for an attestation made before 2.7.36, and without what the
        // project leaves out for one that records `rails_inputs`.
        let t = std::time::Instant::now();
        let all = self.global_now(f, false);
        let global_now = GlobalsNow {
            ignored: if self.project.ignored_inputs.is_empty() {
                all.clone()
            } else {
                self.global_now(f, true)
            },
            all,
        };
        Timers::add(&self.timers.globals, t);
        // Newest first (by the issuedAt each says, unread ones last; ties
        // in store order): the first that passes is used, and a newer
        // attestation is the likelier to match this checkout.
        let head16: Option<String> = self
            .head_tree
            .as_deref()
            .map(|t| t.chars().take(16).collect());
        let mut cands: Vec<RankedCandidate<'_>> = cands
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let same_tree = s.tree.is_some() && s.tree == head16;
                ((same_tree, issued_hint(s)), i, s)
            })
            .collect();
        cands.sort_by_key(|(t, _, _)| std::cmp::Reverse(*t));
        // Each checked candidate's place in the store's order.
        let mut stored_at = Vec::with_capacity(cands.len());
        for (_, i, s) in cands {
            let mut info = CandidateInfo {
                target: s.target.clone(),
                meta_key: s.key.clone(),
                ..Default::default()
            };
            // Catch panics too: a bug in a check must never become a skip.
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.check(f, s, &global_now, &mut info)
            }))
            .unwrap_or_else(|_| Err(Failure::one("internal", 0, "panic while checking", "", "")));
            let passed = r.is_ok();
            stored_at.push(i);
            out.candidates.push(Candidate {
                info: info.clone(),
                failure: r.err(),
            });
            if passed {
                out.skip = true;
                out.reason = format!(
                    "attested by {} ({})",
                    info.principal.clone().unwrap_or_default(),
                    info.fingerprint.clone().unwrap_or_default()
                );
                if !info.accepted_by_policy.is_empty() {
                    out.reason.push_str(&format!(
                        "; policy.libraries = \"any\" accepted {} difference(s)",
                        info.accepted_by_policy.len()
                    ));
                }
                out.by = Some(info);
                return out;
            }
        }
        let best = best_failure(
            stored_at
                .iter()
                .zip(&out.candidates)
                .filter_map(|(i, c)| c.failure.as_ref().map(|f| (*i, f))),
        )
        .map(Failure::summary)
        .unwrap_or_default();
        out.reason = format!(
            "no valid attestation ({} candidates; best failed {best})",
            out.candidates.len()
        );
        out
    }

    /// A keyless envelope: certificate chain and timestamp against the base
    /// trust root, signature, and identity against the base identities.toml.
    fn verify_keyless(
        &self,
        env: &Envelope,
        m: &vci_attest::keyless::SigstoreMaterial,
    ) -> Result<vci_attest::keyless::KeylessVerified, Failure> {
        const EXPECTED: &str = "a Sigstore signature, certified and timestamped by an authority of base .vci/sigstore-trusted-root.json, by an identity in base .vci/identities.toml";
        let trust = self.keyless.ok_or_else(|| {
            Failure::one(
                "signer",
                3,
                format!("a keyless signature, and {IDENTITIES_FILE} is missing at the base commit"),
                EXPECTED,
                "no CI identity is trusted",
            )
        })?;
        let ids = trust
            .identities
            .as_ref()
            .map_err(|e| Failure::one("signer", 3, e.clone(), EXPECTED, e.clone()))?;
        let root = trust
            .root
            .as_ref()
            .map_err(|e| Failure::one("signer", 3, e.clone(), EXPECTED, e.clone()))?;
        vci_attest::keyless::verify_keyless(env, m, ids, root, self.now).map_err(|e| {
            let (check, rank, what) = match &e {
                VerifyError::Malformed(_) | VerifyError::WrongPayloadType(_) => {
                    ("envelope", 1, "envelope".to_owned())
                }
                VerifyError::UnknownIdentity(m) => ("signer", 3, m.clone()),
                VerifyError::Untrusted(m) => ("signature", 2, m.clone()),
                _ => ("signature", 2, "signature verification".to_owned()),
            };
            Failure::one(check, rank, what, EXPECTED, e.to_string())
        })
    }

    /// The checks of a hdr object's global manifest that depend on nothing
    /// but the hdr and the checkout (STORE-V2 section 1.5 step 6): its
    /// root is the attested `globalInputRoot`, and every entry rehashes
    /// the same at HEAD. Made once per hdr id for this project; a format-1
    /// candidate (no hdr id) runs them itself, as before.
    fn global_check(
        &self,
        hdr_id: Option<&str>,
        gm: &InputManifest,
        global_input_root: &str,
    ) -> Result<(), Failure> {
        if let Some(id) = hdr_id
            && let Some(r) = self
                .hdr_checks
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(id)
        {
            return r.clone();
        }
        let r = (|| {
            if gm.root() != global_input_root {
                return Err(Failure::one(
                    "global-inputs",
                    14,
                    "globalInputRoot",
                    global_input_root.to_owned(),
                    format!("{} (recomputed from the attested manifest)", gm.root()),
                ));
            }
            let gextra = self.ignored.of(self.checkout, gm);
            let gdiff = gm
                .diff_against_cache(self.checkout, lookup(&self.child), &gextra)
                .map_err(|e| {
                    Failure::one("global-inputs", 14, "rehash", "re-hashable", e.to_string())
                })?;
            if !gdiff.is_empty() {
                return Err(Failure {
                    check: "global-inputs",
                    rank: 14,
                    details: gdiff
                        .into_iter()
                        .map(|m| Detail {
                            what: m.what,
                            expected: m.expected,
                            actual: m.actual,
                        })
                        .collect(),
                });
            }
            Ok(())
        })();
        if let Some(id) = hdr_id {
            self.hdr_checks
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(id.to_owned(), r.clone());
        }
        r
    }

    /// The per-file inputs of a format-1 candidate: the manifest inline, or
    /// the stored one the attestation references (trusted only through the
    /// signed root), rehashed against the checkout. Returns the manifest
    /// and every mismatch (`entry:` and `env:`), as before store format 3.
    fn inputs_v1(&self, p: &VciPredicate) -> Result<(Arc<InputManifest>, Vec<Mismatch>), Failure> {
        let m: Arc<InputManifest> = match (&p.core.manifest, &p.core.manifest_ref) {
            (Some(m), _) => Arc::new(m.clone()),
            (None, Some(r)) => {
                self.manifests
                    .load(self.store, r, &self.timers)
                    .map_err(|(what, actual)| {
                        Failure::one(
                            "inputs",
                            15,
                            what,
                            format!(
                                "the input manifest, {} project {}",
                                self.store.kind(),
                                vci_store::manifest_key(r)
                            ),
                            actual,
                        )
                    })?
            }
            (None, None) => {
                return Err(Failure::one(
                    "statement",
                    4,
                    "manifest / manifestRef",
                    "neither",
                    "exactly one of manifest and manifestRef",
                ));
            }
        };
        if m.root() != p.core.input_root {
            return Err(Failure::one(
                "inputs",
                15,
                "inputRoot",
                p.core.input_root.clone(),
                format!("{} (recomputed from the attested manifest)", m.root()),
            ));
        }
        // Lookups instead of listings (2.5.0) only where the base policy
        // accepts what they leave out.
        self.autoload_policy(m.entries.iter().map(|e| e.kind))?;
        // The shared base's part of the checks, made once (2.7.30, see
        // `BaseCheck`); the entries after the base's are this unit's own.
        let base_check = self
            .manifests
            .base_root_of(&p.core.input_root)
            .and_then(|b| self.base_check(&b));
        let own_from = base_check
            .as_ref()
            .map(|bc| m.entries.iter().take_while(|e| bc.set.contains(e)).count())
            .unwrap_or(0);
        let t = std::time::Instant::now();
        let collisions = match &base_check {
            Some(bc) if bc.collisions.is_err() => bc.collisions.clone(),
            Some(bc) if !m.prefixes_collide_with(own_from, &bc.prefixes) => Ok(()),
            _ => self.case_collisions(&p.core.input_root, &m),
        };
        Timers::add(&self.timers.collisions, t);
        collisions.map_err(|e| Failure::one("inputs", 15, "case collisions", "none", e))?;
        let t = std::time::Instant::now();
        // (The base's part is borrowed: cloning its thousand paths for each
        // of 4,000 candidates cost more than the check.)
        let extra: std::borrow::Cow<'_, [RepoPath]> = match &base_check {
            Some(bc) => {
                let own = self.ignored.of_from(self.checkout, &m, own_from);
                if own.is_empty() {
                    std::borrow::Cow::Borrowed(&bc.extra)
                } else {
                    let mut e = bc.extra.clone();
                    e.extend(own);
                    e.sort();
                    e.dedup();
                    std::borrow::Cow::Owned(e)
                }
            }
            None => std::borrow::Cow::Owned(self.ignored.of(self.checkout, &m)),
        };
        Timers::add(&self.timers.ignored, t);
        Timers::count(&self.timers.rehashed);
        let t = std::time::Instant::now();
        let mut diff = m
            .diff_against_cache_from(self.checkout, lookup(&self.child), &extra, own_from)
            .map_err(|e| Failure::one("inputs", 15, "rehash", "re-hashable", e.to_string()))?;
        if let Some(bc) = &base_check {
            // The base's differences, except at paths this unit's own
            // entries took over.
            let own: HashSet<&str> = m.entries[own_from..]
                .iter()
                .map(|e| e.path.as_str())
                .collect();
            diff.extend(
                bc.mismatches
                    .iter()
                    .filter(|mm| {
                        mm.what
                            .strip_prefix("entry:")
                            .is_none_or(|p| !own.contains(p))
                    })
                    .cloned(),
            );
        }
        Timers::add(&self.timers.rehash, t);
        Ok((m, diff))
    }

    /// The per-file inputs of a format-3 candidate (STORE-V2 section 1.5
    /// step 8): the record's descriptor resolved against its tables object
    /// and the shape it names (a shape missing, mismatched or malformed, an
    /// index past either, fails `inputs`), its paths checked as a manifest's
    /// are (autoload lookups the policy forbids, case collisions, the
    /// children git ignores), every path observed at HEAD through the
    /// checkout cache, and the manifest of the observation with the
    /// attested externals and env, whose root must be the signed subject
    /// digest: the files are then exactly the attested ones. Returns that
    /// manifest and every mismatch: the `entry:` ones when the root
    /// differs (from the run's state object where it is at hand, section
    /// 1.5 step 9) and the `env:` ones of the attested env against the
    /// child environment.
    fn inputs_v2(
        &self,
        s: &StoredEnvelope,
        frame: &Frame,
        tables: &Tables,
        input_root: &str,
    ) -> Result<(Arc<InputManifest>, Vec<Mismatch>), Failure> {
        let inputs = |what: String, expected: String, actual: String| {
            Failure::one("inputs", 15, what, expected, actual)
        };
        let shape_id = Descriptor::shape_id(&frame.descriptor).map_err(|e| {
            inputs(
                "descriptor".into(),
                "a descriptor naming the run's shape object".into(),
                e.to_string(),
            )
        })?;
        let shape_id = hex32(&shape_id);
        let shape = self
            .objects
            .shape(self.store, &self.timers, &shape_id)
            .map_err(|u| {
                inputs(
                    u.what,
                    format!("the shape object {shape_id} the descriptor names"),
                    u.actual,
                )
            })?;
        let descriptor = Descriptor::decode(&frame.descriptor, tables).map_err(|e| {
            inputs(
                "descriptor".into(),
                "a descriptor over the record's tables object".into(),
                e.to_string(),
            )
        })?;
        let resolved = descriptor.resolve(&shape, tables).map_err(|e| {
            inputs(
                "descriptor".into(),
                format!("a descriptor over the shape object {shape_id} and the tables object"),
                e.to_string(),
            )
        })?;
        // Lookups instead of listings (2.5.0) only where the base policy
        // accepts what they leave out.
        self.autoload_policy(resolved.set.iter().map(|e| e.kind))?;
        // The whole set as a manifest of paths, for a check that needs all
        // of them (made only then: it is ~2,850 clones on vex).
        let all_paths = || InputManifest {
            entries: resolved.set.iter().map(path_entry).collect(),
            externals: vec![],
            env: vec![],
        };
        // Case collisions: the group's part once per (shape, group), the
        // own entries folded against it (see `GroupCase`); without a
        // group, or on a collision, the whole set.
        let t = std::time::Instant::now();
        let group_case = descriptor
            .group
            .and_then(|g| self.group_case(&shape_id, g, &shape));
        let collisions = match &group_case {
            Some(gc) if gc.collisions.is_err() => gc.collisions.clone(),
            Some(gc) => {
                let own = InputManifest {
                    entries: descriptor
                        .own
                        .iter()
                        .filter_map(|&i| shape.entries.get(i))
                        .map(path_entry)
                        .collect(),
                    externals: vec![],
                    env: vec![],
                };
                if own.entries.len() == descriptor.own.len()
                    && !own.prefixes_collide_with(0, &gc.prefixes)
                {
                    Ok(())
                } else {
                    self.case_collisions(input_root, &all_paths())
                }
            }
            None => self.case_collisions(input_root, &all_paths()),
        };
        Timers::add(&self.timers.collisions, t);
        collisions.map_err(|e| Failure::one("inputs", 15, "case collisions", "none", e))?;
        // The children git ignores under the listed directories (what the
        // listing hashes leave out): asked about the listings alone.
        let t = std::time::Instant::now();
        let listings = InputManifest {
            entries: resolved
                .set
                .iter()
                .filter(|e| e.kind == EntryKind::DirListing)
                .map(path_entry)
                .collect(),
            externals: vec![],
            env: vec![],
        };
        let extra = self.ignored.of(self.checkout, &listings);
        Timers::add(&self.timers.ignored, t);
        Timers::count(&self.timers.rehashed);
        let t = std::time::Instant::now();
        let observed = InputManifest::observe(&resolved.set, self.checkout, &extra)
            .map_err(|e| Failure::one("inputs", 15, "rehash", "re-hashable", e.to_string()))?;
        let m =
            InputManifest::from_observed(&resolved.set, observed, resolved.externals, resolved.env)
                .map_err(|e| Failure::one("inputs", 15, "rehash", "re-hashable", e.to_string()))?;
        let mut diff = Vec::new();
        if m.root() != input_root {
            let state = self.objects.state_for(self.store, &self.timers, s);
            diff = entry_mismatches(&resolved.set, &m, state.as_deref(), input_root);
        }
        Timers::add(&self.timers.rehash, t);
        // The attested env against the child environment, as the format-1
        // rehash compares it.
        let env = lookup(&self.child);
        for e in &m.env {
            let act = env_value_hash(env(&e.key).as_deref());
            if act != e.hash {
                let show = |h: &str| {
                    if h == vci_core::ABSENT_HASH {
                        "unset".to_owned()
                    } else {
                        format!("blake3={h}")
                    }
                };
                diff.push(Mismatch {
                    what: format!("env:{}", e.key),
                    expected: show(&e.hash),
                    actual: show(&act),
                });
            }
        }
        Ok((Arc::new(m), diff))
    }

    /// Lookups instead of listings (2.5.0) only where the base policy
    /// accepts what they leave out.
    fn autoload_policy(&self, kinds: impl IntoIterator<Item = EntryKind>) -> Result<(), Failure> {
        if !self.project.policy.rails_autoload_lookups
            && kinds
                .into_iter()
                .any(|k| matches!(k, EntryKind::AutoloadMiss | EntryKind::AutoloadDir))
        {
            return Err(Failure::one(
                "inputs",
                15,
                "autoload lookups",
                "directory listings (policy.rails_autoload_lookups = true in the base branch's vci.toml accepts lookups)",
                "the attestation records the constants its tests looked up in autoload directories, not their listings",
            ));
        }
        Ok(())
    }

    fn check(
        &self,
        f: &TestFile,
        s: &StoredEnvelope,
        globals_now: &GlobalsNow,
        info: &mut CandidateInfo,
    ) -> Result<(), Failure> {
        // A value the store could not read (e.g. a blob missing from the
        // object database) only fails its own candidate.
        if let Some(e) = &s.error {
            return Err(Failure::one(
                "envelope",
                1,
                format!("value in the {} store", self.store.kind()),
                format!("unreadable: {e}"),
                "a readable DSSE envelope",
            ));
        }
        // The record's format, by its first byte: `{` a DSSE envelope JSON
        // (format 1), `v` a text frame (format 3, decoded under the rules
        // of STORE-V2 section 1.6); the store's columns never choose.
        let record = decode_record(&s.bytes).map_err(|e| {
            Failure::one(
                "envelope",
                1,
                "record",
                format!("unparseable: {e}"),
                "a DSSE envelope (format 1) or a vci3 frame (format 3)",
            )
        })?;
        // Envelope shape, and for a keyless envelope (a `sigstore` member)
        // its material: certificate, timestamp, signature and identity are
        // checked against the base identities.toml and trust root.
        let (env, material, frame) = match &record {
            Record::FormatOne(bytes) => {
                let env = Envelope::from_json(bytes).map_err(|e| {
                    Failure::one(
                        "envelope",
                        1,
                        "envelope JSON",
                        format!("unparseable: {e}"),
                        "a DSSE envelope",
                    )
                })?;
                let material = vci_attest::keyless::material_from_json(bytes).map_err(|e| {
                    Failure::one(
                        "envelope",
                        1,
                        "envelope JSON",
                        format!("unparseable: {e}"),
                        "a DSSE envelope",
                    )
                })?;
                (env, material, None)
            }
            Record::FormatThree(frame) => (
                Envelope::from_frame(frame),
                frame.sigstore().cloned(),
                Some(frame),
            ),
        };
        Timers::count(&self.timers.candidates);
        let t_sig = std::time::Instant::now();
        // Signature over the statement bytes exactly as stored, and the
        // signer id the verified key or identity has.
        let (verified, signer_id) = match material {
            Some(m) => {
                let k = self.verify_keyless(&env, &m)?;
                let id = k.identity.signer_id();
                (k.verified, Some(id))
            }
            // Signature, namespace, signer trust (base allowed_signers).
            None => {
                let v = verify_envelope(&env, self.allowed, self.now).map_err(|e| {
                    let (check, rank) = match &e {
                        VerifyError::Malformed(_) | VerifyError::WrongPayloadType(_) => {
                            ("envelope", 1)
                        }
                        VerifyError::BadSignature(_) | VerifyError::NoSignatures => {
                            ("signature", 2)
                        }
                        VerifyError::WrongNamespace(_) => ("signature", 2),
                        VerifyError::UnknownSigner(_) | VerifyError::CertAuthorityRejected(_) => {
                            ("signer", 3)
                        }
                        VerifyError::SignerNotValidNow(_) => ("signer", 3),
                        VerifyError::Untrusted(_) => ("signature", 2),
                        VerifyError::UnknownIdentity(_) => ("signer", 3),
                    };
                    Failure::one(
                        check,
                        rank,
                        "signature verification",
                        "a valid signature by a key in base allowed_signers",
                        e.to_string(),
                    )
                })?;
                let id = signer_id_of_fingerprint(&v.fingerprint);
                (v, id)
            }
        };
        Timers::add(&self.timers.signature, t_sig);
        info.principal = Some(verified.principal.clone());
        info.fingerprint = Some(verified.fingerprint.clone());
        // The key's signer segment must be the verified key's signer id
        // (STORE-V2 section 1.5 step 4): a record copied under another
        // signer's slot is not that signer's, and would otherwise stay
        // there until that signer's history deleted it.
        let Some(signer_id) = signer_id else {
            // Unreachable with ssh-key's `SHA256:` fingerprints; a later
            // vci-attest that reports another form fails closed here, with
            // the fingerprint named rather than an empty expected id.
            return Err(Failure::one(
                "signer",
                3,
                "signer id (the store key's signer segment)",
                s.signer.clone(),
                format!(
                    "no signer id can be derived from fingerprint {}",
                    verified.fingerprint
                ),
            ));
        };
        if s.signer != signer_id {
            return Err(Failure::one(
                "signer",
                3,
                "signer id (the store key's signer segment)",
                s.signer.clone(),
                format!("{signer_id} (the signer id of the verified key)"),
            ));
        }
        if let Some(r) = &self.no_skip_ref
            && !self
                .project
                .policy
                .skips_on_no_skip_ref(&verified.principal)
        {
            return Err(no_skip_ref_failure(
                r,
                &verified.principal,
                &self.project.policy.no_skip_refs_except,
            ));
        }

        // Statement / predicate shape: the v1 predicate in a format-1
        // record, the v2 predicate (its hdr and tables objects by signed
        // id, STORE-V2 section 1.5 step 5) in a format-3 record.
        let st = &verified.statement;
        let predicate_type = if frame.is_some() {
            PREDICATE_TYPE_V2
        } else {
            PREDICATE_TYPE
        };
        if st.predicate_type != predicate_type {
            return Err(Failure::one(
                "statement",
                4,
                "predicateType",
                st.predicate_type.clone(),
                predicate_type,
            ));
        }
        let unparseable = |e: serde_json::Error| {
            Failure::one(
                "statement",
                4,
                "predicate",
                format!("unparseable: {e}"),
                "a vci test predicate",
            )
        };
        /// The predicate as parsed, with the objects a v2 one names.
        enum Owned {
            V1(Box<VciPredicate>),
            V2(Box<VciPredicateV2>, Arc<Hdr>, Arc<Tables>),
        }
        let input_root: String;
        let owned: Owned = match frame {
            None => {
                let p: VciPredicate =
                    serde_json::from_value(st.predicate.clone()).map_err(unparseable)?;
                // The input manifest: inline (before vci 1.9.0) or by
                // reference to the signed input root, exactly one of them.
                match (&p.core.manifest, &p.core.manifest_ref) {
                    (Some(_), None) => {}
                    (None, Some(r)) if *r == p.core.input_root => {}
                    (None, Some(r)) => {
                        return Err(Failure::one(
                            "statement",
                            4,
                            "manifestRef",
                            r.clone(),
                            format!("{} (inputRoot)", p.core.input_root),
                        ));
                    }
                    (m, r) => {
                        return Err(Failure::one(
                            "statement",
                            4,
                            "manifest / manifestRef",
                            format!(
                                "{} and {}",
                                if m.is_some() {
                                    "manifest"
                                } else {
                                    "no manifest"
                                },
                                if r.is_some() {
                                    "manifestRef"
                                } else {
                                    "no manifestRef"
                                }
                            ),
                            "exactly one of manifest and manifestRef",
                        ));
                    }
                }
                let subject_ok = st.subject.len() == 1
                    && st.subject[0].name == p.core.test_id
                    && st.subject[0].digest.get("blake3") == Some(&p.core.input_root);
                if !subject_ok {
                    return Err(Failure::one(
                        "statement",
                        4,
                        "subject",
                        format!("{:?}", st.subject),
                        format!("{} blake3={}", p.core.test_id, p.core.input_root),
                    ));
                }
                input_root = p.core.input_root.clone();
                Owned::V1(Box::new(p))
            }
            Some(_) => {
                let p: VciPredicateV2 =
                    serde_json::from_value(st.predicate.clone()).map_err(unparseable)?;
                // The subject names the unit and its input root (a v2
                // statement carries the root nowhere else).
                let digest = (st.subject.len() == 1 && st.subject[0].name == p.test_id)
                    .then(|| st.subject[0].digest.get("blake3"))
                    .flatten()
                    .filter(|d| parse_hex32(d).is_some());
                let Some(digest) = digest else {
                    return Err(Failure::one(
                        "statement",
                        4,
                        "subject",
                        format!("{:?}", st.subject),
                        format!("{} blake3=<64 lowercase hex digits>", p.test_id),
                    ));
                };
                input_root = digest.clone();
                let object = |what: &'static str, id: &str, u: ObjectUnavailable| {
                    Failure::one(
                        "statement",
                        4,
                        u.what,
                        format!("the {what} object {id} the statement names"),
                        u.actual,
                    )
                };
                let hdr = self
                    .objects
                    .hdr(self.store, &self.timers, &p.hdr)
                    .map_err(|u| object("hdr", &p.hdr, u))?;
                let tables = self
                    .objects
                    .tables(self.store, &self.timers, &p.tables)
                    .map_err(|u| object("tables", &p.tables, u))?;
                Owned::V2(Box::new(p), hdr, tables)
            }
        };
        let p: ResolvedPredicate<'_> = match &owned {
            Owned::V1(p) => ResolvedPredicate::v1(p),
            Owned::V2(p, hdr, tables) => ResolvedPredicate::v2(p, &input_root, hdr, tables)
                .map_err(|e| {
                    Failure::one(
                        "statement",
                        4,
                        "waived",
                        format!("{:?}", p.waived),
                        format!("sorted distinct ids into the tables object's waiver table: {e}"),
                    )
                })?,
        };
        info.issued_at = Some(p.issued_at().to_owned());
        info.expires_at = Some(p.expires_at().to_owned());
        info.rails_inputs = p.rails_inputs().to_owned();
        let global_now = if p.rails_inputs().is_empty() {
            &globals_now.all
        } else {
            &globals_now.ignored
        };

        // Expiry and TTL policy.
        let issued = parse_rfc3339(p.issued_at()).map_err(|e| {
            Failure::one(
                "expiry",
                5,
                "issuedAt",
                p.issued_at(),
                format!("RFC 3339 required ({e})"),
            )
        })?;
        let expires = parse_rfc3339(p.expires_at()).map_err(|e| {
            Failure::one(
                "expiry",
                5,
                "expiresAt",
                p.expires_at(),
                format!("RFC 3339 required ({e})"),
            )
        })?;
        if issued > self.now + CLOCK_SKEW_SECS {
            return Err(Failure::one(
                "expiry",
                5,
                "issuedAt",
                p.issued_at(),
                format!(
                    "now is {} (issuedAt must not be later)",
                    crate::util::rfc3339(self.now)
                ),
            ));
        }
        if expires <= self.now {
            return Err(Failure::one(
                "expiry",
                5,
                "expiresAt",
                p.expires_at(),
                format!(
                    "now is {} (expiresAt must be later)",
                    crate::util::rfc3339(self.now)
                ),
            ));
        }
        if expires - issued > self.max_ttl || expires < issued {
            return Err(Failure::one(
                "expiry",
                5,
                "ttl",
                format!("{}s", expires - issued),
                format!("<= {}s (policy.max_ttl)", self.max_ttl),
            ));
        }

        // Identity: repo, test, adapter, argv.
        if p.repo_id() != self.repo_id {
            return Err(Failure::one(
                "repo",
                6,
                "repoId",
                p.repo_id(),
                self.repo_id.clone(),
            ));
        }
        if p.test_id() != f.test_id.as_str() {
            return Err(Failure::one(
                "test-id",
                7,
                "testId",
                p.test_id(),
                f.test_id.as_str(),
            ));
        }
        let adapter = self.project.adapter.as_ref();
        if p.adapter() != adapter.name() {
            return Err(Failure::one(
                "adapter",
                8,
                "adapter",
                p.adapter(),
                adapter.name(),
            ));
        }
        let argv = adapter.canonical_argv(&self.project.rel, &f.project_rel);
        if p.argv() != argv
            || p.project_dir() != self.project.rel
            || p.runner_project() != f.runner_project
            || p.project_name() != self.project.name
        {
            return Err(Failure::one(
                "argv",
                9,
                "argv / project",
                format!(
                    "{:?} project {:?} runner project {:?} vci project {:?}",
                    p.argv(),
                    p.project_dir(),
                    p.runner_project(),
                    p.project_name()
                ),
                format!(
                    "{argv:?} project {:?} runner project {:?} vci project {:?}",
                    self.project.rel, f.runner_project, self.project.name
                ),
            ));
        }

        // Toolchain (adapter-specific tools; see Toolchain::diff).
        let tc = p.toolchain();
        let now_tc = crate::run::toolchain_for(adapter.name(), &self.versions);
        let libraries = self.project.policy.libraries_for(&f.project_rel);
        let mut tdiff = toolchain_diff(&self.project.policy, libraries, tc, &now_tc);
        info.accepted_by_policy
            .extend(libraries_accepted(libraries, tc, &now_tc));
        let platform = self.project.policy.platform_for(&f.project_rel);
        tdiff.extend(platform_diff(
            platform,
            &tc.os,
            &tc.arch,
            p.platform_specific(),
            std::env::consts::OS,
            std::env::consts::ARCH,
        ));
        if p.adapter() == "go" {
            tdiff.extend(go_arch_diff(
                platform,
                &tc.arch,
                p.arch_specific(),
                std::env::consts::ARCH,
            ));
        }
        // Cargo: target-dependent cfg predicates of the unit's code must
        // evaluate here as they did on the attesting host.
        if !p.cfg_predicates().is_empty() && tc.rust_cfg != now_tc.rust_cfg {
            for pred in p.cfg_predicates() {
                let differs =
                    vci_adapter::cfg_predicate_differs(pred, &tc.rust_cfg, &now_tc.rust_cfg)
                        .unwrap_or(true);
                if differs {
                    tdiff.push((
                        "cfg (code for another platform)",
                        format!("cfg({pred}) as on {}", tc.rust_host),
                        format!("evaluates differently on {}", now_tc.rust_host),
                    ));
                }
            }
        }
        if !tdiff.is_empty() {
            return Err(Failure {
                check: "toolchain",
                rank: 10,
                details: tdiff
                    .into_iter()
                    .map(|(w, e, a)| Detail {
                        what: w.into(),
                        expected: e,
                        actual: a,
                    })
                    .collect(),
            });
        }

        // Env configuration digest (base config).
        let fenv = self.project.file_env(&f.project_rel);
        let env_config_digest = p.env_config_digest();
        if *env_config_digest != *fenv.digest() {
            return Err(Failure::one(
                "env-config",
                11,
                "envConfigDigest (the [env] lists of the base vci.toml, or vci's built-in lists, differ from the attestation's; attestations made before vci 1.6.0 all differ once)",
                env_config_digest.into_owned(),
                fenv.digest(),
            ));
        }

        // Result. A pass with skipped tests counts only when the attestation
        // recorded the skips as waived (`result:skipped`), which the base
        // policy must still waive (below).
        let r = p.result();
        let waived = p.waived();
        let skips_waived = r.state == "passed"
            && r.failed == 0
            && waived
                .iter()
                .any(|w| w.starts_with(crate::run::RESULT_SKIPPED_TAINT));
        let no_tests_waived = r.state == "no-tests"
            && r.failed == 0
            && waived.contains(&crate::run::RESULT_NO_TESTS_TAINT);
        if !(r.is_pass() || skips_waived || no_tests_waived) || !p.tainted().is_empty() {
            return Err(Failure::one(
                "result",
                12,
                "result",
                format!(
                    "{} failed={} skipped={} tainted={:?}",
                    r.state,
                    r.failed,
                    r.skipped,
                    p.tainted()
                ),
                "passed, untainted (required; skipped tests only with policy.ignore_taints waiving result:skipped)",
            ));
        }
        // Declared inputs (`[[inputs]]`) must be exactly the base config's:
        // a declaration added later names files the attestation never hashed.
        let declared = self.project.extra_inputs(&f.project_rel);
        if p.declared_inputs() != declared.as_slice() {
            return Err(Failure::one(
                "inputs-config",
                12,
                "declared inputs ([[inputs]] extra)",
                format!("{:?}", p.declared_inputs()),
                format!("{declared:?} (base vci.toml)"),
            ));
        }
        // Taints waived by policy when the attestation was made must all
        // still be waived by the base commit's policy.
        let not_waived = not_waived(
            &self.project.policy,
            self.project.adapter.name(),
            &declared,
            &waived,
        );
        if !not_waived.is_empty() {
            return Err(Failure {
                check: "waived",
                rank: 12,
                details: not_waived,
            });
        }
        if p.tree_dirty() && !self.project.policy.allow_dirty {
            return Err(Failure::one(
                "dirty",
                13,
                "treeDirty",
                "true",
                "false required (policy.allow_dirty = false)",
            ));
        }

        // Global inputs: attested manifest is self-consistent, still matches
        // the checkout (once per hdr for a format-3 record), and the current
        // global input set is the same.
        let gm = p.global_manifest();
        let global_input_root = p.global_input_root();
        self.global_check(p.hdr_id(), &gm, &global_input_root)?;
        match global_now {
            Ok(now) if now.root() == *global_input_root => {}
            Ok(now) => {
                let attested: BTreeSet<&str> = gm.entries.iter().map(|e| e.path.as_str()).collect();
                let current: BTreeSet<&str> = now.entries.iter().map(|e| e.path.as_str()).collect();
                let added: Vec<&&str> = current.difference(&attested).collect();
                let removed: Vec<&&str> = attested.difference(&current).collect();
                return Err(Failure::one(
                    "global-inputs",
                    14,
                    format!("global input set (new: {added:?}, gone: {removed:?})"),
                    global_input_root.into_owned(),
                    now.root(),
                ));
            }
            Err(e) => {
                return Err(Failure::one(
                    "global-inputs",
                    14,
                    "computing current global inputs",
                    global_input_root.into_owned(),
                    format!("error: {e}"),
                ));
            }
        }

        // Per-file inputs: the manifest inline or by reference (format 1),
        // or the descriptor resolved and observed at HEAD (format 3); then
        // the mismatches of its files and its env.
        let (m, diff) = match (&owned, frame) {
            (Owned::V1(p1), _) => self.inputs_v1(p1)?,
            (Owned::V2(_, _, tables), Some(frame)) => {
                self.inputs_v2(s, frame, tables, &input_root)?
            }
            (Owned::V2(..), None) => unreachable!("a v2 predicate comes from a frame"),
        };
        let m: &InputManifest = &m;
        let (env_diff, file_diff): (Vec<_>, Vec<_>) =
            diff.into_iter().partition(|m| m.what.starts_with("env:"));
        // An attestation made before 2.0.2 recorded reads of built-in ignore
        // variables (PATH, HOME, VCI_*); those are not inputs under the base
        // policy now, so a difference in one is no difference.
        let required = fenv.required_keys(&self.child);
        let env_diff: Vec<_> = env_diff
            .into_iter()
            .filter(|m| {
                m.what
                    .strip_prefix("env:")
                    .is_none_or(|k| fenv.hashed_when_read(k) || required.contains(k))
            })
            .collect();
        if !file_diff.is_empty() {
            return Err(Failure {
                check: "inputs",
                rank: 15,
                details: file_diff
                    .into_iter()
                    .map(|m| Detail {
                        what: m.what,
                        expected: m.expected,
                        actual: m.actual,
                    })
                    .collect(),
            });
        }
        if adapter.name() == "pytest" {
            let shadows = foreign_extension_shadows(&self.ctx.root, m);
            if !shadows.is_empty() {
                return Err(Failure {
                    check: "inputs",
                    rank: 15,
                    details: shadows,
                });
            }
        }

        // Externals: every attested package version must be what resolves now.
        let t_ext = std::time::Instant::now();
        let mut ext_diff = vec![];
        for e in &m.externals {
            if e.name == crate::ctx::CONFIG_EXTERNAL {
                if e.version != self.project.config_hash {
                    ext_diff.push(Detail {
                        what: format!("external:{}", e.name),
                        expected: e.version.clone(),
                        actual: format!(
                            "{} (this project's settings in vci.toml changed: path, adapter, env or [[inputs]])",
                            self.project.config_hash
                        ),
                    });
                }
                continue;
            }
            let found = match (
                &self.python_externals,
                &self.go_modules,
                &self.cargo_lock,
                &self.rails_gems,
            ) {
                (Some((installed, locked)), _, _, _) => {
                    crate::externals::python_installed(installed, locked, &e.name, &e.version)
                }
                (None, Some(list), _, _) => {
                    crate::externals::go_installed(list, &e.name, &e.version)
                }
                (None, None, Some(lock), _) => {
                    crate::externals::cargo_locked(lock, &e.name, &e.version)
                }
                (None, None, None, Some(_))
                    if e.name.starts_with(crate::externals::NATIVE_PREFIX) =>
                {
                    crate::externals::rails_native(self.natives(), &e.name, &e.version, libraries)
                        .map(|note| {
                            if let Some(n) = note {
                                info.accepted_by_policy
                                    .push(format!("external:{}: {n}", e.name));
                            }
                        })
                }
                (None, None, None, Some(bundle)) => {
                    crate::externals::rails_bundled(bundle, &e.name, &e.version)
                }
                (None, None, None, None) => {
                    crate::externals::installed(&self.project.dir, &e.name, &e.version)
                }
            };
            match found {
                Ok(()) => {}
                Err(actual) => ext_diff.push(Detail {
                    what: format!("external:{}", e.name),
                    expected: e.version.clone(),
                    actual,
                }),
            }
        }
        if !ext_diff.is_empty() {
            return Err(Failure {
                check: "externals",
                rank: 16,
                details: ext_diff,
            });
        }

        Timers::add(&self.timers.externals, t_ext);
        let t_env = std::time::Instant::now();
        // Env: values, and declared variables present now but not attested.
        // Name the variable and its class under the base policy.
        let classed = |what: &str| match what.strip_prefix("env:") {
            Some(k) => format!("{what} ({})", fenv.classify(k).label()),
            None => what.to_owned(),
        };
        if !env_diff.is_empty() {
            return Err(Failure {
                check: "env",
                rank: 17,
                details: env_diff
                    .into_iter()
                    .map(|m| Detail {
                        what: classed(&m.what),
                        expected: m.expected,
                        actual: m.actual,
                    })
                    .collect(),
            });
        }
        let attested_keys: BTreeSet<&str> = m.env.iter().map(|e| e.key.as_str()).collect();
        let missing: Vec<String> = fenv
            .required_keys(&self.child)
            .into_iter()
            .filter(|k| !attested_keys.contains(k.as_str()))
            .collect();
        if !missing.is_empty() {
            return Err(Failure {
                check: "env",
                rank: 17,
                details: missing
                    .into_iter()
                    .map(|k| Detail {
                        what: classed(&format!("env:{k}")),
                        expected: "not hashed".into(),
                        actual: "must be hashed (env config)".into(),
                    })
                    .collect(),
            });
        }
        Timers::add(&self.timers.envs, t_env);
        Ok(())
    }
}

/// OS/arch differences the platform policy does not accept, as
/// `(what, expected, actual)`. An attestation with platform-specific files
/// (Go files built only for some GOOS/GOARCH) needs the same OS and
/// architecture whatever the policy: another platform compiles other code.
pub fn platform_diff(
    platform: Platform,
    attested_os: &str,
    attested_arch: &str,
    platform_specific: &[String],
    os: &str,
    arch: &str,
) -> Vec<(&'static str, String, String)> {
    let mut out = Vec::new();
    let files = platform_specific.join(" ");
    let specific = !platform_specific.is_empty();
    if attested_os != os {
        if platform >= Platform::SameOs {
            out.push(("os", attested_os.to_owned(), os.to_owned()));
        } else if specific {
            out.push((
                "os (platform-specific files)",
                format!("{attested_os} ({files})"),
                os.to_owned(),
            ));
        }
    }
    if attested_arch != arch {
        if platform >= Platform::Exact {
            out.push(("arch", attested_arch.to_owned(), arch.to_owned()));
        } else if specific {
            out.push((
                "arch (platform-specific files)",
                format!("{attested_arch} ({files})"),
                arch.to_owned(),
            ));
        }
    }
    out
}

/// Architectures (Rust's names) with 64-bit pointers and `int` and
/// little-endian byte order: a Go test's integer arithmetic, `unsafe`
/// layouts and byte order are the same on each of them.
const GO_LE64: &[&str] = &["x86_64", "aarch64", "riscv64", "loongarch64"];

/// Go: architecture differences the policy would accept but that can change
/// a test's result: another word size or byte order, or floating-point code
/// in the test's closure (`arch_specific`), which the compiler may evaluate
/// differently per architecture (arm64 fuses `x*y + z`, amd64 does not).
pub fn go_arch_diff(
    platform: Platform,
    attested_arch: &str,
    arch_specific: &[String],
    arch: &str,
) -> Vec<(&'static str, String, String)> {
    if attested_arch == arch || platform >= Platform::Exact {
        // Same architecture, or `platform_diff` already requires it.
        return vec![];
    }
    if !(GO_LE64.contains(&attested_arch) && GO_LE64.contains(&arch)) {
        return vec![(
            "arch (Go: word size or byte order may differ)",
            attested_arch.to_owned(),
            arch.to_owned(),
        )];
    }
    if !arch_specific.is_empty() {
        return vec![(
            "arch (floating-point code)",
            format!("{attested_arch} ({})", arch_specific.join("; ")),
            arch.to_owned(),
        )];
    }
    vec![]
}

/// File name suffixes of native extension modules on any platform.
const NATIVE_EXT: &[&str] = &[".so", ".pyd", ".dylib", ".sl"];

/// Native extension modules that another platform's interpreter would import
/// instead of an attested module (or that would satisfy an import that was
/// probed as missing).
///
/// The collector probes only the running interpreter's extension suffixes
/// (`x.cpython-314-darwin.so`, `x.abi3.so`, `x.so`), but CPython on Linux
/// tries `x.cpython-314-x86_64-linux-gnu.so` first, Windows `x.cp314-win_amd64.pyd`,
/// and so on. For every probed extension candidate, any file in that
/// directory named `<stem>.<anything>.so|.pyd` (or `<stem>.so|.pyd`) fails
/// the check.
pub fn foreign_extension_shadows(root: &camino::Utf8Path, m: &InputManifest) -> Vec<Detail> {
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut out = Vec::new();
    for e in &m.entries {
        if e.kind != vci_core::EntryKind::Absent {
            continue;
        }
        let p = e.path.as_str();
        let (dir, name) = match p.rsplit_once('/') {
            Some((d, n)) => (d.to_owned(), n),
            None => (String::new(), p),
        };
        if !NATIVE_EXT.iter().any(|x| name.ends_with(x)) {
            continue;
        }
        let Some((stem, _)) = name.split_once('.') else {
            continue;
        };
        if !seen.insert((dir.clone(), stem.to_owned())) {
            continue;
        }
        let abs = if dir.is_empty() {
            root.to_owned()
        } else {
            root.join(&dir)
        };
        let Ok(rd) = std::fs::read_dir(&abs) else {
            continue;
        };
        let prefix = format!("{stem}.");
        let mut found: Vec<String> = rd
            .flatten()
            .filter_map(|d| d.file_name().into_string().ok())
            .filter(|n| n.starts_with(&prefix) && NATIVE_EXT.iter().any(|x| n.ends_with(x)))
            .collect();
        found.sort();
        for n in found {
            let rel = if dir.is_empty() {
                n.clone()
            } else {
                format!("{dir}/{n}")
            };
            out.push(Detail {
                what: format!("entry:{rel}"),
                expected: format!(
                    "no native extension named {stem} (an import of it was looked up here)"
                ),
                actual: "exists: another platform's interpreter would import it".into(),
            });
        }
    }
    out
}

/// A candidate signed by a trusted principal that the base policy does not
/// accept on the current ref (`policy.no_skip_refs` matches it and the
/// principal is not in `policy.no_skip_refs_except`).
fn no_skip_ref_failure(r: &str, principal: &str, except: &[String]) -> Failure {
    Failure::one(
        "signer",
        3,
        format!(
            "policy.no_skip_refs matches {r} and signer {principal} is not in no_skip_refs_except"
        ),
        format!("signed by {principal}"),
        format!(
            "on {r} only attestations by {} are accepted (policy.no_skip_refs_except in the base branch's vci.toml)",
            except.join(", ")
        ),
    )
}

/// Load the plan and print it in `format`.
pub fn print(res: &PlanResult, format: &str) -> Result<()> {
    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(res)?);
        }
        "github" => {
            // Single project: files relative to the project dir (what the
            // runner takes). Several projects: repo-relative test ids, plus
            // `run_<name>=` per project with project-relative files.
            let name = |f: &FileVerdict| {
                if res.multi {
                    f.test_id.clone()
                } else {
                    f.file.clone()
                }
            };
            let run: Vec<String> = res.to_run().map(name).collect();
            let skip: Vec<String> = res.skipped().map(name).collect();
            for f in res.skipped() {
                println!("::notice title=vci skip::{} {}", f.test_id, f.reason);
            }
            if let Some(r) = &res.run_all {
                println!("::warning title=vci::running everything: {r}");
            }
            let mut lines = format!(
                "run_all={}\nrun={}\nskip={}\n",
                res.run_all.is_some(),
                run.join(" "),
                skip.join(" ")
            );
            if res.multi {
                for (i, p) in res.projects.iter().enumerate() {
                    let files: Vec<&str> = res
                        .to_run()
                        .filter(|f| f.project_idx == i)
                        .map(|f| f.file.as_str())
                        .collect();
                    lines.push_str(&format!(
                        "run_all_{0}={1}\nrun_{0}={2}\n",
                        p.name,
                        p.run_all.is_some(),
                        files.join(" ")
                    ));
                }
            }
            print!("{lines}");
            if let Ok(p) = std::env::var("GITHUB_OUTPUT")
                && !p.is_empty()
            {
                use std::io::Write as _;
                let mut fh = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&p)
                    .with_context(|| format!("opening GITHUB_OUTPUT {p}"))?;
                fh.write_all(lines.as_bytes())?;
            }
        }
        _ => {
            match (&res.base_ref, &res.base_commit) {
                (Some(r), Some(c)) => println!("base: {r} ({c})"),
                _ => println!("base: none"),
            }
            if let Some(r) = &res.run_all {
                println!("running everything: {r}");
            } else if res.multi {
                for p in &res.projects {
                    if let Some(r) = &p.run_all {
                        println!("running everything in {}: {r}", p.name);
                    }
                }
            }
            for f in &res.files {
                let project = if res.multi {
                    format!(" [{}]", f.project)
                } else {
                    String::new()
                };
                println!(
                    "{} {}{project}  ({})",
                    if f.skip { "SKIP" } else { "RUN " },
                    f.test_id,
                    f.reason
                );
            }
            println!("{}", summary_line(res));
        }
    }
    Ok(())
}

/// The last line of the text plan. When a project runs everything (its
/// listing failed, a policy says so), the counts of listed files do not say
/// what runs, so the summary says it: `0 to skip, 0 to run` after a failed
/// listing would read as "nothing runs" although `vci ci` runs everything.
fn summary_line(res: &PlanResult) -> String {
    let skip = res.skipped().count();
    let run = res.to_run().count();
    if res.run_all.is_some() {
        return format!("{skip} to skip, running everything ({run} test files listed)");
    }
    let all: Vec<&str> = res
        .projects
        .iter()
        .filter(|p| p.run_all.is_some())
        .map(|p| {
            if p.name.is_empty() {
                p.path.as_str()
            } else {
                p.name.as_str()
            }
        })
        .collect();
    if all.is_empty() {
        format!("{skip} to skip, {run} to run")
    } else {
        format!(
            "{skip} to skip, {run} to run, and everything in {}",
            all.join(", ")
        )
    }
}

/// `vci explain`: every candidate and its first failed check.
pub fn explain(res: &PlanResult, test_id: &str) -> Result<i32> {
    if let (Some(r), Some(c)) = (&res.base_ref, &res.base_commit) {
        println!("base: {r} ({c})");
    }
    if let Some(r) = &res.run_all {
        println!("{test_id}: RUN, running everything: {r}");
        return Ok(0);
    }
    let Some(f) = res.files.iter().find(|f| f.test_id == test_id) else {
        println!("{test_id}: not a listed test file");
        return Ok(1);
    };
    println!(
        "{}: {} ({})",
        f.test_id,
        if f.skip { "SKIP" } else { "RUN" },
        f.reason
    );
    if f.libraries == Libraries::Any {
        println!("{LIBRARIES_ANY_POLICY_LINE}");
    }
    if let Some((mode, ignored)) = &f.rails_inputs {
        println!("{}", rails_inputs_line(*mode, ignored));
    }
    for (i, c) in f.candidates.iter().enumerate() {
        println!(
            "candidate {}: {} {} {}",
            i + 1,
            res.store_kind,
            c.info.target,
            c.info.meta_key
        );
        if let Some(p) = &c.info.principal {
            println!(
                "  signer: {p} {}",
                c.info.fingerprint.clone().unwrap_or_default()
            );
        }
        if let (Some(a), Some(b)) = (&c.info.issued_at, &c.info.expires_at) {
            println!("  issued {a}, expires {b}");
        }
        for a in &c.info.accepted_by_policy {
            println!("  accepted by policy.libraries = \"any\": {a}");
        }
        if f.rails_inputs.is_some() && c.info.issued_at.is_some() {
            if c.info.rails_inputs.is_empty() {
                println!(
                    "  recorded before rails_inputs (vci < 2.7.36): every file Rails read at boot is an input"
                );
            } else {
                println!("  recorded with rails_inputs = {:?}", c.info.rails_inputs);
            }
        }
        match &c.failure {
            None => println!("  all checks passed"),
            Some(fl) => {
                println!("  failed check: {}", fl.check);
                println!(
                    "    (expected: recorded in the attestation; actual: this checkout / CI now)"
                );
                for d in &fl.details {
                    println!("    {}", d.what);
                    println!("      expected: {}", d.expected);
                    println!("      actual:   {}", d.actual);
                }
            }
        }
    }
    Ok(0)
}

/// The taints an attestation recorded as waived (`waived`) that the base
/// policy no longer waives, one detail each: `policy.ignore_taints` (or Go's
/// `policy.go_allow_net`) must match it, or for Cargo's
/// `cargo:undeclared-reads` the unit must still declare `[[inputs]]`. One
/// recorded under the removed `policy.rails_allow_db` never is.
fn not_waived<S: AsRef<str>>(
    policy: &crate::config::Policy,
    adapter: &str,
    declared: &[String],
    waived: &[S],
) -> Vec<Detail> {
    let mut out = Vec::new();
    for w in waived {
        let w = w.as_ref();
        let key = crate::run::taint_key(w);
        let why = if w.starts_with(LEGACY_RAILS_NETWORK_DB_WAIVER) {
            // Written by vci before 1.4.0 under policy.rails_allow_db (and by
            // a collector older than 0.5.0, whose version the toolchain no
            // longer matches anyway).
            "policy.rails_allow_db was removed in vci 1.4.0: attest the file again".to_owned()
        } else if (w.starts_with(vci_adapter::CARGO_UNDECLARED_TAINT) && !declared.is_empty())
            || policy.taint_waiver(adapter, w).is_some()
        {
            continue;
        } else if key == "vci" || key.starts_with("vci:") {
            format!("{key}: vci's own taints are never waived")
        } else {
            let mut why = format!(
                "not waived by the base policy: no policy.ignore_taints pattern matches {key} (ignore_taints = {:?})",
                policy.ignore_taints
            );
            if w.starts_with(vci_adapter::GO_NET_TAINT) {
                why.push_str(", and policy.go_allow_net = false");
            }
            if w.starts_with(vci_adapter::CARGO_UNDECLARED_TAINT) {
                why.push_str(", and no [[inputs]] declared for this unit in the base vci.toml");
            }
            why
        };
        out.push(Detail {
            what: format!("waived taint {key}"),
            expected: w.to_owned(),
            actual: why,
        });
    }
    out
}

/// The `vci explain` line for a Rails test file: the base vci.toml's
/// `rails_inputs` and what it leaves out of manifests.
pub fn rails_inputs_line(mode: crate::config::RailsInputs, ignored: &[String]) -> String {
    let list = if ignored.is_empty() {
        "nothing".to_owned()
    } else {
        ignored.join(", ")
    };
    match mode {
        crate::config::RailsInputs::Loose => format!(
            "inputs: rails_inputs = \"loose\" (base vci.toml; the default): not inputs: {list} (a change to them runs no test again here; a run that skips nothing runs them)"
        ),
        crate::config::RailsInputs::Strict => format!(
            "inputs: rails_inputs = \"strict\" (base vci.toml): every file the test's process read is an input; not inputs (ignore_inputs): {list}"
        ),
    }
}

/// The `vci explain` line for a test file whose base policy sets
/// `libraries = "any"`.
pub const LIBRARIES_ANY_POLICY_LINE: &str = "policy: libraries = \"any\" (base vci.toml): native libraries match by library name (it must be loaded here; file name and hash not compared), and the library versions of the toolchain (ruby: sqlite, yaml, tz; python: sqlite, openssl) are not compared (each must still be loaded on both sides or on neither)";

/// `ruby_libs` items that are library versions (`policy.libraries = "any"`
/// does not compare them). The others (`encoding`, `collector`, any new key)
/// are always compared.
const RUBY_LIBRARY_KEYS: &[&str] = &["sqlite", "yaml", "tz"];
/// `python_libs` items that are library versions.
const PYTHON_LIBRARY_KEYS: &[&str] = &["sqlite", "openssl"];

/// The `;`-separated `key=value` items of a `ruby_libs`/`python_libs` value
/// whose key is (`keep_library = true`) or is not in `keys`.
fn lib_items(libs: &str, keys: &[&str], keep_library: bool) -> String {
    libs.split(';')
        .filter(|i| !i.is_empty())
        .filter(|i| {
            let k = i.split_once('=').map_or(*i, |(k, _)| k);
            keys.contains(&k) == keep_library
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// Each library key of `keys` in a `ruby_libs`/`python_libs` value, as
/// `key=<version>` when the library is loaded, or `key not loaded` when the
/// item is absent (Ruby: `SQLite3`/`Psych` not loaded), empty (Ruby's `tz=`
/// without TZInfo) or `none` (the pytest probe's failed `import sqlite3` /
/// `import ssl`). `policy.libraries = "any"` accepts another version, not a
/// missing library: the presence part of this is compared under "any" too.
fn lib_presence(libs: &str, keys: &[&str]) -> Vec<(bool, String)> {
    keys.iter()
        .map(|k| {
            let v = libs
                .split(';')
                .find_map(|i| i.split_once('=').filter(|(ik, _)| ik == k).map(|(_, v)| v));
            match v {
                Some(v) if !v.is_empty() && v != "none" => (true, format!("{k}={v}")),
                _ => (false, format!("{k} not loaded")),
            }
        })
        .collect()
}

/// Whether the same libraries of `keys` are loaded in `a` and `b` (their
/// versions aside).
fn same_libs_loaded(a: &str, b: &str, keys: &[&str]) -> bool {
    let (pa, pb) = (lib_presence(a, keys), lib_presence(b, keys));
    pa.iter().map(|p| p.0).eq(pb.iter().map(|p| p.0))
}

fn presence_str(libs: &str, keys: &[&str]) -> String {
    lib_presence(libs, keys)
        .into_iter()
        .map(|p| p.1)
        .collect::<Vec<_>>()
        .join(";")
}

/// A toolchain row `policy.libraries = "any"` relaxes.
struct LibRow<'a> {
    /// The row of `Toolchain::diff`.
    row: &'static str,
    /// The row reported for the non-library items, which are still compared.
    rest_row: &'static str,
    /// The row reported for a library loaded on one side only.
    loaded_row: &'static str,
    /// The library keys.
    keys: &'static [&'static str],
    /// Attested value.
    a: &'a str,
    /// Current value.
    b: &'a str,
}

/// The toolchain rows `policy.libraries = "any"` relaxes.
fn library_rows<'a>(
    tc: &'a vci_core::Toolchain,
    now_tc: &'a vci_core::Toolchain,
) -> [LibRow<'a>; 2] {
    [
        LibRow {
            row: vci_core::RUBY_LIBS_DIFF,
            rest_row: "ruby libraries except sqlite, yaml, tz (compared under policy.libraries = \"any\" too)",
            loaded_row: "ruby libraries: sqlite, yaml, tz loaded or not (policy.libraries = \"any\" accepts another version, not a missing library)",
            keys: RUBY_LIBRARY_KEYS,
            a: &tc.ruby_libs,
            b: &now_tc.ruby_libs,
        },
        LibRow {
            row: vci_core::PYTHON_LIBS_DIFF,
            rest_row: "python libraries except sqlite, openssl (compared under policy.libraries = \"any\" too)",
            loaded_row: "python libraries: sqlite, openssl loaded or not (policy.libraries = \"any\" accepts another version, not a missing library)",
            keys: PYTHON_LIBRARY_KEYS,
            a: &tc.python_libs,
            b: &now_tc.python_libs,
        },
    ]
}

/// Library version differences `policy.libraries = "any"` accepts, for
/// `explain` (empty under "exact").
pub(crate) fn libraries_accepted(
    libraries: Libraries,
    tc: &vci_core::Toolchain,
    now_tc: &vci_core::Toolchain,
) -> Vec<String> {
    if libraries != Libraries::Any {
        return vec![];
    }
    library_rows(tc, now_tc)
        .into_iter()
        .filter_map(|r| {
            // A library loaded on one side only is refused, not accepted.
            if !same_libs_loaded(r.a, r.b, r.keys) {
                return None;
            }
            let (a, b) = (lib_items(r.a, r.keys, true), lib_items(r.b, r.keys, true));
            (a != b).then(|| format!("{}: attested {a}, here {b} (versions not compared)", r.row))
        })
        .collect()
}

/// What the toolchain check compares, under the base `policy`: the tool
/// fields of [`vci_core::Toolchain::diff`], the exact Node version with
/// `policy.node_exact`, and the tests' privileges unless
/// `policy.allow_superuser_mismatch` (a privileges difference names that
/// key, so `vci plan` and `vci explain` say how it could be accepted).
/// Under `libraries` = "any" (the base policy for the file) the library
/// versions of `ruby libraries` and `python libraries` are not compared, but
/// whether each library is loaded is; their other items (encoding, collector
/// version) are compared exactly.
pub(crate) fn toolchain_diff(
    policy: &crate::config::Policy,
    libraries: Libraries,
    tc: &vci_core::Toolchain,
    now_tc: &vci_core::Toolchain,
) -> Vec<(&'static str, String, String)> {
    let mut tdiff = tc.diff(now_tc);
    if libraries == Libraries::Any {
        for r in library_rows(tc, now_tc) {
            if let Some(i) = tdiff.iter().position(|d| d.0 == r.row) {
                tdiff.remove(i);
                // Another version is accepted; a library loaded on one side
                // only (`sqlite=none`, a missing item, an empty `tz=`) is not.
                if !same_libs_loaded(r.a, r.b, r.keys) {
                    tdiff.push((
                        r.loaded_row,
                        presence_str(r.a, r.keys),
                        presence_str(r.b, r.keys),
                    ));
                }
                let (a, b) = (lib_items(r.a, r.keys, false), lib_items(r.b, r.keys, false));
                if a != b {
                    tdiff.push((r.rest_row, a, b));
                }
            }
        }
    }
    for d in &mut tdiff {
        if d.0 == vci_core::PRIVILEGES_DIFF {
            d.0 = "privileges (policy.allow_superuser_mismatch = true in the base branch's vci.toml accepts this; risky for tests that depend on file permissions)";
        }
    }
    if policy.allow_superuser_mismatch {
        tdiff.retain(|d| !d.0.starts_with(vci_core::PRIVILEGES_DIFF));
    }
    // policy.node_exact: the exact Node version, not only its major.
    if policy.node_exact && !tc.node.is_empty() && tc.node != now_tc.node {
        tdiff.push((
            "node (policy.node_exact)",
            tc.node.clone(),
            now_tc.node.clone(),
        ));
    }
    tdiff
}

#[cfg(test)]
mod tests {
    use super::*;
    use vci_core::{Observation, RepoPath};

    fn policy(toml: &str) -> crate::config::Policy {
        Config::parse(toml).unwrap().project_specs()[0]
            .policy
            .clone()
    }

    #[test]
    fn waived_taints_need_the_base_policy() {
        let waived: Vec<String> = ["child_process.execSync", "child_process.spawn", "fetch"]
            .map(String::from)
            .to_vec();
        let p = policy(
            "adapter = \"node-test\"\n[policy]\nignore_taints = [\"child_process.*\", \"fetch\"]\n",
        );
        assert!(not_waived(&p, "node-test", &[], &waived).is_empty());
        let p = policy("adapter = \"node-test\"\n[policy]\nignore_taints = [\"*\"]\n");
        assert!(not_waived(&p, "node-test", &[], &waived).is_empty());
        // The base dropped one pattern: that taint is named.
        let p =
            policy("adapter = \"node-test\"\n[policy]\nignore_taints = [\"child_process.*\"]\n");
        let d = not_waived(&p, "node-test", &[], &waived);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].what, "waived taint fetch");
        assert_eq!(d[0].expected, "fetch");
        assert!(
            d[0].actual
                .contains("no policy.ignore_taints pattern matches fetch"),
            "{}",
            d[0].actual
        );
        // No policy at all: every one.
        assert_eq!(
            not_waived(
                &policy("adapter = \"node-test\"\n"),
                "node-test",
                &[],
                &waived
            )
            .len(),
            3
        );
    }

    /// vci's own refusals recorded as waived: each by its key.
    #[test]
    fn outside_writes_and_skips_need_the_base_policy() {
        let waived: Vec<String> = [
            "outside-repository:/proc/sys/net/core/somaxconn",
            "wrote-inside-repository: web/node_modules/other.txt",
            "result:skipped:1 of 4",
        ]
        .map(String::from)
        .to_vec();
        let p = policy(
            "adapter = \"pytest\"\n[policy]\nignore_taints = [\"outside-repository\", \"wrote-inside-repository\", \"result:skipped\"]\n",
        );
        assert!(not_waived(&p, "pytest", &[], &waived).is_empty());
        let p = policy("adapter = \"pytest\"\n[policy]\nignore_taints = [\"*\"]\n");
        assert!(not_waived(&p, "pytest", &[], &waived).is_empty());
        let p =
            policy("adapter = \"pytest\"\n[policy]\nignore_taints = [\"outside-repository\"]\n");
        let d = not_waived(&p, "pytest", &[], &waived);
        let what: Vec<&str> = d.iter().map(|d| d.what.as_str()).collect();
        assert_eq!(
            what,
            [
                "waived taint wrote-inside-repository",
                "waived taint result:skipped"
            ]
        );
        assert_eq!(d[1].expected, "result:skipped:1 of 4");
    }

    #[test]
    fn go_net_is_waived_by_either_key_and_legacy_rails_never() {
        let net = vec!["go:net: the test links package net (...)".to_owned()];
        for toml in [
            "adapter = \"go\"\n[policy]\ngo_allow_net = true\n",
            "adapter = \"go\"\n[policy]\nignore_taints = [\"go:net\"]\n",
            "adapter = \"go\"\n[policy]\nignore_taints = [\"go\"]\n",
        ] {
            assert!(
                not_waived(&policy(toml), "go", &[], &net).is_empty(),
                "{toml}"
            );
        }
        let d = not_waived(&policy("adapter = \"go\"\n"), "go", &[], &net);
        assert!(
            d[0].actual.contains("policy.go_allow_net = false"),
            "{}",
            d[0].actual
        );
        let legacy = vec!["rails:network-db:postgresql".to_owned()];
        let all = policy("adapter = \"rails\"\n[policy]\nignore_taints = [\"*\"]\n");
        let d = not_waived(&all, "rails", &[], &legacy);
        assert!(
            d[0].actual.contains("rails_allow_db was removed"),
            "{}",
            d[0].actual
        );
        // vci's own taints are never waived (an attestation cannot carry one
        // vci wrote, but the check does not trust that).
        let d = not_waived(&all, "rails", &[], &["vci:missing-result".to_owned()]);
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn cargo_undeclared_reads_by_declaration_or_ignore_taints() {
        let w = vec!["cargo:undeclared-reads (x)".to_owned()];
        let none = policy("adapter = \"cargo\"\n");
        assert!(not_waived(&none, "cargo", &["testdata/**".to_owned()], &w).is_empty());
        let d = not_waived(&none, "cargo", &[], &w);
        assert!(
            d[0].actual.contains("no [[inputs]] declared"),
            "{}",
            d[0].actual
        );
        let ign =
            policy("adapter = \"cargo\"\n[policy]\nignore_taints = [\"cargo:undeclared-reads\"]\n");
        assert!(not_waived(&ign, "cargo", &[], &w).is_empty());
    }

    /// A CI runner that runs as root never accepted a laptop's attestation
    /// (`toolchain: privileges`); `policy.allow_superuser_mismatch` in the
    /// base vci.toml accepts that one difference and nothing else, and the
    /// failure names the key.
    #[test]
    fn superuser_mismatch_is_accepted_only_by_the_policy_key() {
        let laptop = vci_core::Toolchain {
            ruby: "3.4.9p82".into(),
            os: "macos".into(),
            arch: "aarch64".into(),
            ..Default::default()
        };
        let mut runner = laptop.clone();
        runner.superuser = true;
        let mut policy = crate::config::Policy::default();
        let d = toolchain_diff(&policy, Libraries::Exact, &laptop, &runner);
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(
            d[0].0.contains("policy.allow_superuser_mismatch = true"),
            "{d:?}"
        );
        assert_eq!(d[0].1, "not root");
        assert_eq!(d[0].2, "root (effective uid 0)");
        policy.allow_superuser_mismatch = true;
        assert!(toolchain_diff(&policy, Libraries::Exact, &laptop, &runner).is_empty());
        assert!(toolchain_diff(&policy, Libraries::Exact, &runner, &laptop).is_empty());
        // Every other field is still compared.
        runner.ruby = "3.4.8p1".into();
        let d = toolchain_diff(&policy, Libraries::Exact, &laptop, &runner);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].0, "ruby");
    }

    fn rails_tc(libs: &str) -> vci_core::Toolchain {
        vci_core::Toolchain {
            ruby: "3.4.9p82".into(),
            ruby_engine: "ruby 3.4.9".into(),
            rails: "8.1.3.1".into(),
            bundler: "4.0.9".into(),
            ruby_test: "minitest 6.0.6".into(),
            ruby_libs: libs.into(),
            ruby_db: "sqlite3".into(),
            os: "macos".into(),
            arch: "aarch64".into(),
            ..Default::default()
        }
    }

    /// `policy.libraries = "any"`: Homebrew's and apt's builds (other SQLite,
    /// libyaml, zoneinfo) are accepted; everything else in the toolchain is
    /// still compared, and so are the non-library items of `ruby_libs`.
    #[test]
    fn libraries_any_drops_only_the_library_versions_ruby() {
        let policy = crate::config::Policy::default();
        let mac =
            rails_tc("sqlite=3.53.2;yaml=0.2.5;tz=zoneinfo 2025b;encoding=UTF-8/none;collector=42");
        let linux = vci_core::Toolchain {
            ruby_libs:
                "sqlite=3.45.1;yaml=0.2.2;tz=zoneinfo 2024a;encoding=UTF-8/none;collector=42".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            ..mac.clone()
        };
        let d = toolchain_diff(&policy, Libraries::Exact, &mac, &linux);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].0, "ruby libraries");
        assert!(toolchain_diff(&policy, Libraries::Any, &mac, &linux).is_empty());
        assert!(toolchain_diff(&policy, Libraries::Any, &linux, &mac).is_empty());
        let acc = libraries_accepted(Libraries::Any, &mac, &linux);
        assert_eq!(
            acc,
            [
                "ruby libraries: attested sqlite=3.53.2;yaml=0.2.5;tz=zoneinfo 2025b, here sqlite=3.45.1;yaml=0.2.2;tz=zoneinfo 2024a (versions not compared)"
            ]
        );
        assert!(libraries_accepted(Libraries::Exact, &mac, &linux).is_empty());
        assert!(libraries_accepted(Libraries::Any, &mac, &mac).is_empty());
        // Another Ruby: refused under both.
        let mut other = mac.clone();
        other.ruby = "3.4.8p72".into();
        for l in [Libraries::Exact, Libraries::Any] {
            let d = toolchain_diff(&policy, l, &mac, &other);
            assert_eq!(d.len(), 1, "{d:?}");
            assert_eq!(d[0].0, "ruby");
        }
        // Rails, Bundler, the database, the bundle: still compared.
        let mut other = linux.clone();
        other.rails = "8.1.3".into();
        other.ruby_db = "postgresql".into();
        other.ruby_gems.push("pg==1.6.0".into());
        let whats: Vec<&str> = toolchain_diff(&policy, Libraries::Any, &mac, &other)
            .iter()
            .map(|d| d.0)
            .collect();
        assert_eq!(whats, ["rails", "database", "gems (bundle)"]);
        // The encoding and the collector version are not libraries.
        for (k, v) in [
            ("encoding=UTF-8/none", "encoding=US-ASCII/none"),
            ("collector=42", "collector=43"),
        ] {
            let other = vci_core::Toolchain {
                ruby_libs: linux.ruby_libs.replace(k, v),
                ..linux.clone()
            };
            let d = toolchain_diff(&policy, Libraries::Any, &mac, &other);
            assert_eq!(d.len(), 1, "{d:?}");
            assert!(
                d[0].0.starts_with("ruby libraries except sqlite, yaml, tz"),
                "{d:?}"
            );
            assert!(d[0].1.contains(k) && d[0].2.contains(v), "{d:?}");
            assert!(!d[0].1.contains("sqlite"), "{d:?}");
        }
    }

    #[test]
    fn libraries_any_drops_only_the_library_versions_python() {
        let policy = crate::config::Policy::default();
        let brew = vci_core::Toolchain {
            python: "3.14.4".into(),
            implementation: "cpython".into(),
            pytest: "9.1.1".into(),
            python_libs: "sqlite=3.50.4;openssl=OpenSSL 3.5.1".into(),
            python_dists: vec!["pytest==9.1.1".into()],
            os: "macos".into(),
            arch: "aarch64".into(),
            ..Default::default()
        };
        let apt = vci_core::Toolchain {
            python_libs: "sqlite=3.45.1;openssl=OpenSSL 3.0.13".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            ..brew.clone()
        };
        let d = toolchain_diff(&policy, Libraries::Exact, &brew, &apt);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].0, "python libraries");
        assert!(toolchain_diff(&policy, Libraries::Any, &brew, &apt).is_empty());
        assert_eq!(libraries_accepted(Libraries::Any, &brew, &apt).len(), 1);
        // Another Python, another distribution set: refused under both.
        let mut other = apt.clone();
        other.python = "3.14.3".into();
        for l in [Libraries::Exact, Libraries::Any] {
            assert_eq!(toolchain_diff(&policy, l, &brew, &other)[0].0, "python");
        }
        let mut other = apt.clone();
        other.python_dists.push("six==1.17.0".into());
        let d = toolchain_diff(&policy, Libraries::Any, &brew, &other);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].0, "python distributions");
    }

    /// `policy.libraries = "any"` accepts another library version, not a
    /// library that is missing on one side: a Python built without `_sqlite3`
    /// or `_ssl` (`sqlite=none`, `openssl=none`), a Ruby process without
    /// SQLite3 (no `sqlite` item) or TZInfo (`tz=`), in either direction.
    #[test]
    fn libraries_any_still_requires_the_same_libraries_loaded() {
        let policy = crate::config::Policy::default();
        let py = |libs: &str| vci_core::Toolchain {
            python: "3.14.4".into(),
            implementation: "cpython".into(),
            pytest: "9.1.1".into(),
            python_libs: libs.into(),
            python_dists: vec!["pytest==9.1.1".into()],
            ..Default::default()
        };
        let dev = py("sqlite=3.50.4;openssl=OpenSSL 3.5.1");
        let ci = py("sqlite=none;openssl=none");
        for (a, b) in [(&dev, &ci), (&ci, &dev)] {
            let d = toolchain_diff(&policy, Libraries::Any, a, b);
            assert_eq!(d.len(), 1, "{d:?}");
            assert!(
                d[0].0
                    .starts_with("python libraries: sqlite, openssl loaded or not"),
                "{d:?}"
            );
            assert!(libraries_accepted(Libraries::Any, a, b).is_empty());
        }
        let d = toolchain_diff(&policy, Libraries::Any, &dev, &ci);
        assert_eq!(d[0].1, "sqlite=3.50.4;openssl=OpenSSL 3.5.1");
        assert_eq!(d[0].2, "sqlite not loaded;openssl not loaded");
        // Only one of them missing.
        let half = py("sqlite=3.45.1;openssl=none");
        let d = toolchain_diff(&policy, Libraries::Any, &dev, &half);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].2, "sqlite=3.45.1;openssl not loaded");
        // Missing on both sides: nothing to compare.
        assert!(toolchain_diff(&policy, Libraries::Any, &ci, &ci.clone()).is_empty());

        let mac =
            rails_tc("sqlite=3.53.2;yaml=0.2.5;tz=zoneinfo 2025b;encoding=UTF-8/none;collector=42");
        for libs in [
            // SQLite3 not loaded: no `sqlite` item; TZInfo not loaded: `tz=`.
            "tz=;encoding=UTF-8/none;collector=42",
            "yaml=0.2.2;tz=zoneinfo 2024a;encoding=UTF-8/none;collector=42",
            "sqlite=3.45.1;yaml=0.2.2;tz=;encoding=UTF-8/none;collector=42",
        ] {
            let other = rails_tc(libs);
            for (a, b) in [(&mac, &other), (&other, &mac)] {
                let d = toolchain_diff(&policy, Libraries::Any, a, b);
                assert_eq!(d.len(), 1, "{libs}: {d:?}");
                assert!(
                    d[0].0
                        .starts_with("ruby libraries: sqlite, yaml, tz loaded or not"),
                    "{d:?}"
                );
                assert!(libraries_accepted(Libraries::Any, a, b).is_empty());
            }
        }
        let d = toolchain_diff(
            &policy,
            Libraries::Any,
            &mac,
            &rails_tc("tz=;encoding=UTF-8/none;collector=42"),
        );
        assert_eq!(d[0].1, "sqlite=3.53.2;yaml=0.2.5;tz=zoneinfo 2025b");
        assert_eq!(d[0].2, "sqlite not loaded;yaml not loaded;tz not loaded");
        // Not loaded on either side, other versions of the rest: accepted.
        let a = rails_tc("yaml=0.2.5;tz=;encoding=UTF-8/none;collector=42");
        let b = rails_tc("yaml=0.2.2;tz=;encoding=UTF-8/none;collector=42");
        assert!(toolchain_diff(&policy, Libraries::Any, &a, &b).is_empty());
        assert_eq!(libraries_accepted(Libraries::Any, &a, &b).len(), 1);
    }

    /// Go: an attestation made on macOS arm64 is accepted on Linux x86_64
    /// under `platform = "any"` only when none of the test's repository files
    /// is built for specific platforms (`b_linux.go`, `//go:build darwin`).
    #[test]
    fn go_floating_point_and_word_size_need_the_same_architecture() {
        let none: Vec<String> = vec![];
        let fp = vec!["example.com/m/fm: floating point in fm.go".to_owned()];
        // No floating point: macOS arm64 -> Linux x86_64 is accepted.
        assert!(go_arch_diff(Platform::Any, "aarch64", &none, "x86_64").is_empty());
        let x = go_arch_diff(Platform::Any, "aarch64", &fp, "x86_64");
        assert_eq!(x.len(), 1, "{x:?}");
        assert_eq!(x[0].0, "arch (floating-point code)");
        assert!(x[0].1.contains("fm.go"), "{x:?}");
        assert!(!go_arch_diff(Platform::SameOs, "aarch64", &fp, "x86_64").is_empty());
        // Same architecture (another OS): fine.
        assert!(go_arch_diff(Platform::Any, "aarch64", &fp, "aarch64").is_empty());
        // Exact already demands the architecture (platform_diff reports it).
        assert!(go_arch_diff(Platform::Exact, "aarch64", &fp, "x86_64").is_empty());
        // 32-bit or big-endian on one side: never across architectures.
        assert!(!go_arch_diff(Platform::Any, "aarch64", &none, "x86").is_empty());
        assert!(!go_arch_diff(Platform::Any, "s390x", &none, "x86_64").is_empty());
    }

    #[test]
    fn platform_specific_go_files_need_the_same_platform() {
        let none: Vec<String> = vec![];
        let files = vec!["b/b_linux.go".to_owned()];
        let d = |p, f: &[String], os, arch| platform_diff(p, "macos", "aarch64", f, os, arch);
        assert!(d(Platform::Any, &none, "linux", "x86_64").is_empty());
        let x = d(Platform::Any, &files, "linux", "x86_64");
        assert_eq!(x.len(), 2, "{x:?}");
        assert_eq!(x[0].0, "os (platform-specific files)");
        assert!(x[0].1.contains("b/b_linux.go"), "{x:?}");
        assert_eq!(x[1].0, "arch (platform-specific files)");
        assert!(d(Platform::Any, &files, "macos", "aarch64").is_empty());
        // Same OS, other architecture: still refused for platform files.
        assert_eq!(d(Platform::Any, &files, "macos", "x86_64").len(), 1);
        assert!(d(Platform::Any, &none, "macos", "x86_64").is_empty());
        // Policies that already demand it report it once, as before.
        assert_eq!(d(Platform::SameOs, &files, "linux", "aarch64")[0].0, "os");
        assert_eq!(d(Platform::Exact, &none, "macos", "x86_64")[0].0, "arch");
        assert_eq!(d(Platform::SameOs, &none, "linux", "x86_64").len(), 1);
    }

    /// Regression: a failed listing (a broken member `Cargo.toml`) made the
    /// text plan end with `0 to skip, 0 to run` although everything runs.
    #[test]
    fn summary_says_everything_runs_when_listing_failed() {
        let project = |run_all: Option<&str>| ProjectPlan {
            name: String::new(),
            path: ".".into(),
            adapter: "cargo".into(),
            run_all: run_all.map(str::to_owned),
            no_skip_ref: None,
            on_no_skip_ref: false,
            no_skip_refs_except: vec![],
            attest_on_any_ref: vec![],
            dir: camino::Utf8PathBuf::from("/r"),
            child_env: None,
            adapter_options: Default::default(),
        };
        let mut res = PlanResult {
            base_ref: Some("main".into()),
            base_commit: Some("c".into()),
            run_all: Some("listing test files failed: could not parse cargo workspace".into()),
            warnings: vec![],
            projects: vec![project(Some("listing test files failed"))],
            files: vec![],
            multi: false,
            config: None,
            allowed: None,
            fetch_failed: None,
            store_kind: "git-meta",
        };
        let line = summary_line(&res);
        assert!(line.contains("running everything"), "{line}");
        assert!(!line.contains("0 to run"), "{line}");
        res.run_all = None;
        res.projects = vec![project(None)];
        assert_eq!(summary_line(&res), "0 to skip, 0 to run");
        res.multi = true;
        res.projects = vec![
            project(None),
            ProjectPlan {
                name: "rs".into(),
                ..project(Some("listing failed"))
            },
        ];
        assert!(summary_line(&res).contains("everything in rs"));
    }

    /// Regression: a macOS attestation probes `b.cpython-314-darwin.so`, but a
    /// Linux interpreter imports `b.cpython-314-x86_64-linux-gnu.so` before
    /// `b.py`; such a file must make the test run.
    #[test]
    fn foreign_platform_extensions_are_detected() {
        let t = tempfile::tempdir().unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        std::fs::create_dir_all(root.join("src/pkg")).unwrap();
        std::fs::write(root.join("src/b.py"), "").unwrap();
        let obs: Vec<(RepoPath, Observation)> = [
            "src/b.cpython-314-darwin.so",
            "src/b.abi3.so",
            "src/pkg/__init__.cpython-314-darwin.so",
            "src/c.py",
        ]
        .iter()
        .map(|p| (RepoPath::new(p).unwrap(), Observation::Probe))
        .collect();
        let m = InputManifest::capture(&root, &obs, vec![], &[]).unwrap();
        assert!(foreign_extension_shadows(&root, &m).is_empty());
        std::fs::write(root.join("src/b.cpython-314-x86_64-linux-gnu.so"), "").unwrap();
        std::fs::write(root.join("src/pkg/__init__.cp314-win_amd64.pyd"), "").unwrap();
        std::fs::write(root.join("src/bb.cpython-314-x86_64-linux-gnu.so"), "").unwrap();
        let d = foreign_extension_shadows(&root, &m);
        let whats: Vec<&str> = d.iter().map(|d| d.what.as_str()).collect();
        assert_eq!(
            whats,
            [
                "entry:src/b.cpython-314-x86_64-linux-gnu.so",
                "entry:src/pkg/__init__.cp314-win_amd64.pyd"
            ]
        );
    }

    /// A git repository at a temp dir with `files` committed on `main`.
    fn commit_repo(files: &[(&str, &str)]) -> (tempfile::TempDir, camino::Utf8PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        for (rel, body) in files {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .current_dir(&root)
                .args([
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@example.com",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "init.defaultBranch=main",
                ])
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?}: {out:?}");
        };
        git(&["init", "-q"]);
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "base"]);
        (t, root)
    }

    fn plan_in(root: &camino::Utf8Path, projects: &[&str]) -> Result<PlanResult> {
        let opts = PlanOptions {
            base_ref: Some("HEAD".into()),
            only: None,
            fetch: None,
            projects: projects.iter().map(|p| p.to_string()).collect(),
        };
        let mut res = PlanResult {
            base_ref: None,
            base_commit: None,
            run_all: None,
            warnings: vec![],
            projects: vec![],
            files: vec![],
            multi: false,
            config: None,
            allowed: None,
            fetch_failed: None,
            store_kind: "git-meta",
        };
        let repo = Repo::discover(root).unwrap();
        let store = crate::store::for_repo(&repo);
        plan_with(&opts, repo, root.to_owned(), &*store, &mut res, &mut None).map(|()| res)
    }

    /// `--project b` of three projects: only b is listed and planned (a, a
    /// Cargo project whose Cargo.toml is invalid, is never touched); an
    /// unknown name names the configured projects; the single-project form
    /// has no names. (No allowed_signers: nothing is resolved, everything
    /// runs, which is all this needs.)
    #[test]
    fn plan_with_project_lists_only_that_project() {
        let toml = r#"[[projects]]
name = "a"
path = "a"
adapter = "cargo"

[[projects]]
name = "b"
path = "b"
adapter = "pytest"

[[projects]]
name = "c"
path = "c"
adapter = "pytest"
"#;
        let (_t, root) = commit_repo(&[
            ("vci.toml", toml),
            ("a/Cargo.toml", "[package\nthis is not toml\n"),
            ("a/tests/it.rs", "#[test]\nfn t() {}\n"),
            ("b/pytest.ini", "[pytest]\n"),
            ("b/tests/test_b1.py", "def test_b1():\n    pass\n"),
            ("b/tests/test_b2.py", "def test_b2():\n    pass\n"),
            ("c/pytest.ini", "[pytest]\n"),
            ("c/tests/test_c.py", "def test_c():\n    pass\n"),
        ]);
        let res = plan_in(&root, &["b"]).unwrap();
        assert!(res.multi);
        let names: Vec<&str> = res.projects.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["b"]);
        let ids: Vec<&str> = res.files.iter().map(|f| f.test_id.as_str()).collect();
        assert_eq!(ids, ["b/tests/test_b1.py", "b/tests/test_b2.py"]);
        assert!(
            res.files
                .iter()
                .all(|f| f.project == "b" && f.project_idx == 0)
        );
        assert!(
            !res.warnings
                .iter()
                .any(|w| w.contains("a:") || w.contains("cargo")),
            "{:?}",
            res.warnings
        );
        // What `vci ci --key` runs and attests with is the same selection.
        let cfg = res.config.as_ref().unwrap();
        assert_eq!(cfg.projects.len(), 1);
        assert_eq!(cfg.projects[0].name, "b");
        let text = {
            let mut lines: Vec<String> = res
                .files
                .iter()
                .map(|f| format!("{} [{}]", f.test_id, f.project))
                .collect();
            lines.push(summary_line(&res));
            lines.join("\n")
        };
        assert!(!text.contains("[a]") && !text.contains("[c]"), "{text}");

        // Without --project every project is planned (a's listing fails).
        let res = plan_in(&root, &[]).unwrap();
        let names: Vec<&str> = res.projects.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"]);

        let e = plan_in(&root, &["b", "web"]).err().unwrap().to_string();
        assert_eq!(
            e,
            "--project web: no such project in vci.toml at the base commit (its projects: a, b, c)"
        );

        let (_t, single) = commit_repo(&[
            ("vci.toml", "project = \".\"\nadapter = \"pytest\"\n"),
            ("tests/test_x.py", "def test_x():\n    pass\n"),
        ]);
        let e = plan_in(&single, &["b"]).err().unwrap().to_string();
        assert!(
            e.starts_with("--project b: vci.toml at the base commit has the single-project form"),
            "{e}"
        );
        assert_eq!(plan_in(&single, &[]).unwrap().projects.len(), 1);
    }

    #[test]
    fn a_signer_outside_no_skip_refs_except_names_itself_and_the_key() {
        let f = no_skip_ref_failure("refs/heads/main", "dev", &["github-actions".to_owned()]);
        assert_eq!(f.check, "signer");
        assert_eq!(
            f.summary(),
            "signer: policy.no_skip_refs matches refs/heads/main and signer dev is not in no_skip_refs_except"
        );
        assert!(f.details[0].actual.contains("github-actions"));
    }

    /// On a store that holds every value (nothing for a prefetch to fetch),
    /// the candidates the plan set aside are read again and counted as made
    /// readable; a key removed meanwhile reads as gone and counts for
    /// nothing; values already read are not read again; with the set-aside
    /// keys given, no other candidate is read; without them, every candidate
    /// without a value is.
    #[test]
    fn set_aside_candidates_are_read_again() {
        use vci_store::KeyHint;
        let store = crate::store::mem::MemStore::new();
        let id = "src/a.test.ts";
        for (issued, sk) in [(1, "aa"), (2, "bb"), (3, "cc"), (4, "dd")] {
            let hint = KeyHint { issued, tree: None };
            let envelope = format!("{{\"n\":{issued}}}");
            store
                .put_for_test(id, "0123456789abcdef", sk, Some(&hint), envelope.as_bytes())
                .unwrap();
        }
        // The two newest read (the older of them then unreadable), the two
        // oldest set aside.
        let mut listed = store.list_units(&[id]).unwrap().remove(0);
        assert_eq!(listed.len(), 4);
        let mut set_aside = SetAside::new();
        for (i, c) in listed.iter_mut().enumerate() {
            if i < 2 {
                c.mark_not_fetched();
                set_aside
                    .entry(id.to_owned())
                    .or_default()
                    .insert(c.key.clone());
            } else {
                store.read_values(&mut [c]).unwrap();
            }
        }
        listed[2].set_error("a blob missing");
        let gone = listed[1].clone();
        assert_eq!(store.remove(vec![gone.clone()]).unwrap().len(), 1);
        let by_id = BTreeMap::from([(id.to_owned(), listed)]);
        let mut current = BTreeMap::new();
        let read = |only, current: &mut BTreeMap<String, Vec<StoredEnvelope>>| {
            read_again(&store, &[id], only, &BTreeSet::new(), &by_id, current, 2)
        };
        assert_eq!(
            read_again(
                &store,
                &[],
                Some(&set_aside),
                &BTreeSet::new(),
                &by_id,
                &mut current,
                2
            ),
            0
        );
        assert!(current.is_empty());
        assert_eq!(read(Some(&set_aside), &mut current), 1);
        let states = |current: &BTreeMap<String, Vec<StoredEnvelope>>| -> Vec<String> {
            current[id]
                .iter()
                .map(|c| format!("{:?}", c.state()))
                .collect()
        };
        assert_eq!(
            states(&current),
            [
                format!("{:?}", ValueState::Read(b"{\"n\":1}")),
                format!("{:?}", ValueState::Unreadable(vci_store::GONE)),
                format!("{:?}", ValueState::Unreadable("a blob missing")),
                format!("{:?}", ValueState::Read(b"{\"n\":4}")),
            ]
        );
        assert_eq!(current[id][1].key, gone.key);
        // From what was last read, every candidate without a value: the
        // unreadable one reads now, the gone one is still gone.
        assert_eq!(read(None, &mut current), 1);
        assert_eq!(
            states(&current)[1..3],
            [
                format!("{:?}", ValueState::Unreadable(vci_store::GONE)),
                format!("{:?}", ValueState::Read(b"{\"n\":3}")),
            ]
        );
        assert_eq!(read(None, &mut current), 0);
    }

    /// The signer id the plan compares the key's signer segment with is
    /// derived from the SSHSIG verification's `SHA256:` fingerprint, and is
    /// `keys::signer_id` of the same key blob (both are SHA-256 of it).
    #[test]
    fn signer_id_follows_from_the_fingerprint() {
        use base64::Engine as _;
        use sha2::Digest as _;
        let blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 0123456789abcdef0123456789abcdef";
        let digest = sha2::Sha256::digest(blob);
        let fp = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
        );
        assert_eq!(
            signer_id_of_fingerprint(&fp).as_deref(),
            Some(crate::keys::signer_id(blob).as_str())
        );
        assert_eq!(signer_id_of_fingerprint("MD5:aa:bb"), None);
        assert_eq!(signer_id_of_fingerprint("SHA256:AAAA"), None);
        assert_eq!(signer_id_of_fingerprint("oidc repo:a/b"), None);
    }

    /// An object is kept only under the id its bytes hash to, decoded by
    /// the kind byte inside them (a candidate expecting another kind fails),
    /// counted against the verdict-object cap unless it is a state object,
    /// and asked of the store once a candidate names it (a store without
    /// objects answers with its error).
    #[test]
    fn objects_are_checked_by_id_kind_and_cap() {
        use std::sync::atomic::Ordering;
        let loader = ObjectLoader::default();
        let timers = Timers::default();
        let store = crate::store::mem::MemStore::new();
        let tables = Tables {
            waivers: vec!["rails:net".into()],
            env_names: vec![],
            externals: vec![],
        };
        let bytes = tables.encode().unwrap();
        let id = hex32(&object_id(&bytes));
        loader.insert(ObjectKind::Tables, &id, &bytes);
        assert_eq!(
            loader.tables(&store, &timers, &id).unwrap().waivers,
            tables.waivers
        );
        let e = loader.hdr(&store, &timers, &id).unwrap_err();
        assert!(e.what.contains("is of another kind"), "{e:?}");
        assert_eq!(e.actual, "a tables object");
        // Under a wrong id: corrupt, whatever the bytes.
        let wrong = hex32(&[7; 32]);
        loader.insert(ObjectKind::Tables, &wrong, &bytes);
        let e = loader.tables(&store, &timers, &wrong).unwrap_err();
        assert!(
            e.what.contains("corrupt") && e.actual.contains(&id),
            "{e:?}"
        );
        // Bytes that do not decode under their own id: malformed.
        let junk = b"vo\x02\x01junk";
        let jid = hex32(&object_id(junk));
        loader.insert(ObjectKind::Tables, &jid, junk);
        let e = loader.tables(&store, &timers, &jid).unwrap_err();
        assert!(e.what.contains("malformed"), "{e:?}");
        // An id no round named: asked of the store now, which keeps none.
        let missing = hex32(&[9; 32]);
        let e = loader.tables(&store, &timers, &missing).unwrap_err();
        assert!(e.what.contains("cannot be read from the store"), "{e:?}");
        assert!(e.actual.contains("format-3 objects"), "{e:?}");
        let e = loader.tables(&store, &timers, "nope").unwrap_err();
        assert!(e.actual.contains("64 lowercase hex"), "{e:?}");
        // The cap: a verdict object past it is not kept, and the candidate
        // naming it is counted; a state object is outside the cap.
        let sb = Shape::default().encode().unwrap();
        let sid = hex32(&object_id(&sb));
        loader.lock().verdict_bytes = VERDICT_OBJECT_BYTES - sb.len() + 1;
        loader.insert(ObjectKind::Shape, &sid, &sb);
        let e = loader.shape(&store, &timers, &sid).unwrap_err();
        assert!(e.past_cap && e.what.contains("not loaded"), "{e:?}");
        assert_eq!(loader.past_cap.load(Ordering::Relaxed), 1);
        let stb = State::default().encode().unwrap();
        let stid = hex32(&object_id(&stb));
        loader.insert(ObjectKind::State, &stid, &stb);
        assert!(matches!(
            loader.lock().by_id.get(&stid),
            Some(Ok(Object::State(_)))
        ));
        assert_eq!(loader.lock().loaded, [0, 1, 0, 1]);
        // An unavailable object is replaced by a later load; a loaded one
        // stays.
        loader.lock().verdict_bytes = 0;
        loader.insert(ObjectKind::Shape, &sid, &sb);
        assert!(loader.shape(&store, &timers, &sid).is_ok());
        loader.insert(ObjectKind::Shape, &sid, b"vo\x03\x01junk");
        assert!(loader.shape(&store, &timers, &sid).is_ok());
        assert_eq!(loader.lock().verdict_bytes, sb.len());
    }

    /// A round's candidates name their run's objects once each (a run of
    /// 1,000 units names its one shape 1,000 times): each `(kind, id)` is
    /// hashed and decoded once, at its first place in the candidate order,
    /// and a later round naming it again decodes nothing. An id named under
    /// two kinds is still tried under each (the kind byte inside decides
    /// which loads), and an object past the cap at its first place stays
    /// out at its repeats.
    #[test]
    fn objects_named_by_many_candidates_are_decoded_once() {
        use vci_store::conformance::scenarios::Run3;
        let s = crate::store::mem::MemStore::new().objects(true);
        let run = Run3::build(&["src/a.ts", "src/b.ts"]);
        s.put_objects(&run.new_objects()).unwrap();
        let id = |i: usize| hex32(&object_id(&run.objects[i].1));
        let (hdr, tables, shape) = (id(0), id(1), id(2));
        let mut wanted = Vec::new();
        for _ in 0..1000 {
            wanted.push((ObjectKind::Hdr, hdr.clone()));
            wanted.push((ObjectKind::Tables, tables.clone()));
            wanted.push((ObjectKind::Shape, shape.clone()));
        }
        let timers = Timers::default();
        let loader = ObjectLoader::default();
        let reads = s.object_reads();
        loader.load(&s, &timers, &wanted);
        assert_eq!(s.object_reads(), reads + 1, "one read for the round");
        assert_eq!(loader.lock().decodes, 3);
        assert_eq!(loader.lock().loaded, [1, 1, 1, 0]);
        assert!(loader.hdr(&s, &timers, &hdr).is_ok());
        assert!(loader.tables(&s, &timers, &tables).is_ok());
        assert!(loader.shape(&s, &timers, &shape).is_ok());
        loader.load(&s, &timers, &wanted);
        assert_eq!(loader.lock().decodes, 3, "loaded already: nothing decoded");
        assert_eq!(s.object_reads(), reads + 1, "nor read");

        // The tables object named as a hdr first (a decode failure kept),
        // then as tables: tried under both kinds, once each.
        let loader = ObjectLoader::default();
        let twice = [
            (ObjectKind::Hdr, tables.clone()),
            (ObjectKind::Hdr, tables.clone()),
            (ObjectKind::Tables, tables.clone()),
            (ObjectKind::Tables, tables.clone()),
        ];
        loader.load(&s, &timers, &twice);
        assert_eq!(loader.lock().decodes, 2);
        assert!(loader.tables(&s, &timers, &tables).is_ok());

        // The cap decided at the shape's first place holds at its repeats.
        let loader = ObjectLoader::default();
        let shape_len = run.objects[2].1.len();
        loader.lock().verdict_bytes = VERDICT_OBJECT_BYTES - shape_len + 1;
        loader.load(
            &s,
            &timers,
            &[
                (ObjectKind::Shape, shape.clone()),
                (ObjectKind::Shape, shape.clone()),
            ],
        );
        assert_eq!(loader.lock().decodes, 1);
        let e = loader.shape(&s, &timers, &shape).unwrap_err();
        assert!(e.past_cap, "{e:?}");
    }

    /// The `entry:` text of a format-3 candidate whose observed root is not
    /// the signed one: from the run's state object, each entry whose
    /// attested value (any of them, when the run saw several) is not the
    /// observed one, labelled unsigned; without it, the entries whose kind
    /// or exec bit changed, else one line saying the entries changed; a
    /// state object that does not list a path says so. Never empty.
    #[test]
    fn entry_text_from_the_state_object_or_without_it() {
        let path = |p: &str| RepoPath::new(p).unwrap();
        let file = |p: &str, hash: &str| InputEntry {
            path: path(p),
            kind: EntryKind::File,
            exec: false,
            size: 3,
            hash: hash.into(),
        };
        let set: Vec<ShapeEntry> = ["a.txt", "b.txt"]
            .iter()
            .map(|p| ShapeEntry {
                path: path(p),
                kind: EntryKind::File,
                exec: false,
            })
            .collect();
        let observed = InputManifest {
            entries: vec![file("a.txt", "aa"), file("b.txt", "bb")],
            externals: vec![],
            env: vec![],
        };
        let state = State {
            entries: vec![
                file("a.txt", "aa"),
                file("b.txt", "b0"),
                file("b.txt", "b1"),
            ],
        };
        let got = entry_mismatches(&set, &observed, Some(&state), "root");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].what, "entry:b.txt");
        assert_eq!(
            got[0].expected,
            format!(
                "file exec=false size=3 blake3=b0 or file exec=false size=3 blake3=b1 ({UNSIGNED_LABEL})"
            )
        );
        assert_eq!(got[0].actual, "file exec=false size=3 blake3=bb");
        let got = entry_mismatches(&set, &observed, None, "root");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].what, "entry: changed (attested hash not loaded)");
        assert_eq!(got[0].expected, "input root root");
        assert!(
            got[0]
                .actual
                .starts_with(&format!("input root {}", observed.root()))
        );
        let mut gone = observed.clone();
        gone.entries[1] = InputEntry::absent(path("b.txt"));
        let got = entry_mismatches(&set, &gone, None, "root");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].what, "entry:b.txt");
        assert_eq!(
            got[0].expected,
            "file exec=false changed (attested hash not loaded)"
        );
        assert_eq!(got[0].actual, "absent");
        let got = entry_mismatches(&set, &gone, Some(&State::default()), "root");
        assert_eq!(got.len(), 2);
        assert!(
            got[0].expected.contains("does not list the path"),
            "{got:?}"
        );
        assert!(got.iter().all(|m| m.what.starts_with("entry:")));
    }

    /// The state objects for the failure text are named by one `columns`
    /// call per round, made with the verdict objects' load, and loaded
    /// one at a time up to the cap, which is checked before the store is
    /// asked: a plan with many entry-failing candidates sends the store
    /// no request per candidate (STORE-V2 section 1.5 step 9, section 3).
    #[test]
    fn state_objects_are_named_by_one_columns_call_per_round_and_capped_before_any_read() {
        use vci_store::conformance::scenarios::Run3;
        use vci_store::{KeyHint, NewAttestation};
        let s = crate::store::mem::MemStore::new().objects(true);
        let run = Run3::build(&["src/a.ts", "src/b.ts"]);
        s.put_objects(&run.new_objects()).unwrap();
        let signer = "2".repeat(16);
        let mut stored = Vec::new();
        for (i, unit) in ["src/a.ts", "src/b.ts", "src/c.ts"].iter().enumerate() {
            let (bytes, mut columns) = run.record(unit, 1, 1);
            if i == 2 {
                // A column naming no state object: none for the text.
                columns.state_obj = None;
            }
            let hint = KeyHint {
                issued: 10 + i as i64,
                tree: None,
            };
            let att = NewAttestation::for_test(unit, &signer, "ab", Some(&hint), &bytes)
                .with_columns(&columns);
            let mut e = s.put(&att).unwrap();
            e.set_value(bytes);
            stored.push(e);
        }
        let objects = ObjectLoader::default();
        let timers = Timers::default();
        preload_objects(&s, &objects, &timers, stored.iter(), None);
        assert_eq!(s.columns_calls(), 1, "one columns call for the round");
        let reads = s.object_reads();
        assert!(objects.state_for(&s, &timers, &stored[0]).is_some());
        assert_eq!(s.object_reads(), reads + 1, "the state object, once");
        assert!(objects.state_for(&s, &timers, &stored[1]).is_some());
        assert_eq!(
            s.object_reads(),
            reads + 1,
            "the same run's state object: cached"
        );
        assert!(objects.state_for(&s, &timers, &stored[2]).is_none());
        assert_eq!(s.columns_calls(), 1, "no columns call per candidate");
        // Past the cap: no read at all.
        objects.lock().states = STATE_OBJECTS;
        objects.lock().by_id.clear();
        assert!(objects.state_for(&s, &timers, &stored[0]).is_none());
        assert_eq!(s.object_reads(), reads + 1);
        assert_eq!(s.columns_calls(), 1);
    }

    /// Candidates are checked newest first since 2.1, but the reason still
    /// names what it named before: the furthest failure, and of several as
    /// far, the last in the store's order.
    #[test]
    fn best_failure_ties_go_to_the_last_in_store_order() {
        let f = |rank, what: &str| Failure::one("inputs", rank, what, "", "");
        let (old, new, sig) = (f(13, "entry:old"), f(13, "entry:new"), f(2, "sig"));
        // Checked newest first: `new` (stored second), `old` (stored first),
        // `sig` (stored third).
        let checked = [(1, &new), (0, &old), (2, &sig)];
        assert_eq!(best_failure(checked).unwrap().details[0].what, "entry:new");
        let checked = [(0, &new), (1, &old), (2, &sig)];
        assert_eq!(best_failure(checked).unwrap().details[0].what, "entry:old");
        assert!(best_failure([]).is_none());
    }
}
