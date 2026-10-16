//! `vci plan` / `vci explain` / `vci ci`: the verification algorithm.
//!
//! Default verdict is RUN. A test file is skipped only when one stored
//! candidate passes every check below, in order. Every error is caught per
//! candidate (or, for errors that affect everything, turns into "run all").

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::Serialize;
use vci_attest::{AllowedSigners, Envelope, VerifyError, verify_envelope};
use vci_core::{InputManifest, PREDICATE_TYPE};
use vci_git::{AttestStore, Repo, StoredEnvelope};

use crate::config::{ALLOWED_SIGNERS_FILE, CONFIG_FILE, Config, Libraries, Platform};
use crate::ctx::{Ctx, Project, TestFile, VciPredicate, mark_cross_project_ambiguity, open_repo};
use crate::envpolicy::{ChildEnvMap, lookup};
use crate::run::global_manifest;
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
    project: &'a Project,
    allowed: &'a AllowedSigners,
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
}

impl Verifier<'_> {
    /// [`Verifier::natives`], from the booted application.
    fn natives(&self) -> &Result<vci_adapter::InstalledExternals, String> {
        self.natives.get_or_init(|| {
            self.project
                .adapter
                .native_externals(&self.child.to_child_env())
                .map_err(|e| e.to_string())
                .and_then(|o| o.ok_or_else(|| "not enumerable".to_owned()))
        })
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
    // `--fetch`: fetch attestations while the projects are probed; joined
    // before the store is read (and before returning, whatever happens).
    let mut fetch = opts.fetch.clone().map(|remote| {
        let (repo, from) = (repo.clone(), remote.clone());
        let handle = std::thread::spawn(move || {
            let t = std::time::Instant::now();
            let r = crate::cmds::fetch_messages(&repo, from.as_deref());
            timing("fetch attestations (--fetch, in the background)", t);
            r
        });
        (remote, handle)
    });
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
    };
    let out = plan_with(opts, repo, root, &mut res, &mut fetch);
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
    if std::env::var_os("VCI_TIMING").is_some() {
        eprintln!("vci: timing: {what}: {:.2}s", since.elapsed().as_secs_f64());
    }
}

/// List a project's test files and, with `resolve`, resolve its toolchain
/// and externals at the same time (both may shell out: uv, go, cargo, ruby;
/// pytest and Minitest files are listed without a process).
fn probe_project(
    ctx: &Ctx,
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
    res: &mut PlanResult,
    fetch: &mut PendingFetch,
) -> Result<()> {
    // 1. Policy and trust roots from the BASE commit.
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
                let resolve = start.run_all.is_none() && allowed.is_some();
                let (ctx, repo_id) = (&ctx, &repo_id);
                s.spawn(move || probe_project(ctx, i, p, &start.child, resolve, repo_id))
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
            dir: p.dir.clone(),
            child_env: Some(start.child),
            adapter_options: p.adapter_options.clone(),
        });
    }
    mark_cross_project_ambiguity(&mut files);
    if let Some(id) = &opts.only {
        files.retain(|f| f.test_id.as_str() == id);
    }

    // 3. Stored candidates from the local git-meta store (`vci fetch`, or
    // `--fetch` above, materializes the remote's), looked up per unit, then
    // per project: toolchain, repo identity, and the checks.
    join_fetch(fetch, res);
    let mut by_id: BTreeMap<String, Vec<StoredEnvelope>> = BTreeMap::new();
    if !res.projects.iter().all(|p| p.run_all.is_some()) {
        let looked_up = AttestStore::new(&ctx.repo).reader().and_then(|r| {
        if !r.has_store() {
            let w = "no git-meta store in this repository: no attestations are available (run `vci fetch` first)".to_owned();
            eprintln!("vci: warning: {w}");
            res.warnings.push(w);
        }
        let mut m = BTreeMap::new();
        for f in &files {
            let id = f.test_id.as_str();
            if !m.contains_key(id) {
                m.insert(id.to_owned(), r.candidates(id)?);
            }
        }
        Ok(m)
    });
        match looked_up {
            Ok(m) => by_id = m,
            Err(e) => {
                let e = format!("reading attestations from git-meta: {e:#}");
                for p in res.projects.iter_mut() {
                    p.run_all.get_or_insert_with(|| e.clone());
                }
            }
        }
    }
    let now = now_unix();
    let verifiers: Vec<Result<Verifier<'_>, String>> = ctx
        .projects
        .iter()
        .zip(resolved)
        .enumerate()
        .map(
            |(pi, (project, resolved))| match (&res.projects[pi].run_all, &allowed, resolved) {
                (Some(r), _, _) => Err(r.clone()),
                (None, None, _) => Err("no trusted signers".to_owned()),
                (None, Some(_), None) => Err("internal: the project was not resolved".to_owned()),
                (None, Some(allowed), Some(r)) => r.map(|r| Verifier {
                    ctx: &ctx,
                    project,
                    allowed,
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
                }),
            },
        )
        .collect();
    // Every project's files at once (the checks rehash the checkout and may
    // boot a Rails application, once per project, for the native libraries a
    // candidate records), in project order.
    let t_verdicts = std::time::Instant::now();
    let verdicts: Vec<Vec<FileVerdict>> = std::thread::scope(|s| {
        let handles: Vec<_> = verifiers
            .iter()
            .enumerate()
            .map(|(pi, verifier)| {
                let (files, by_id) = (&files, &by_id);
                s.spawn(move || {
                    let mine = files.iter().filter(|f| f.project == pi);
                    match verifier {
                        Err(r) => mine.map(|f| verdict_run(f, r)).collect::<Vec<_>>(),
                        Ok(v) => mine
                            .map(|f| {
                                // A test id listed by two projects: both see
                                // the same candidates (they are ambiguous and
                                // run anyway).
                                let cands = by_id
                                    .get(f.test_id.as_str())
                                    .map(Vec::as_slice)
                                    .unwrap_or_default();
                                v.verdict(f, cands)
                            })
                            .collect(),
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
            .collect()
    });
    timing("verdicts (rehash inputs, check candidates)", t_verdicts);
    for (pi, (verifier, verdicts)) in verifiers.iter().zip(verdicts).enumerate() {
        if let Err(r) = verifier {
            res.projects[pi].run_all.get_or_insert_with(|| r.clone());
        }
        res.files.extend(verdicts);
    }
    finish(res);
    Ok(())
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

impl Verifier<'_> {
    fn verdict(&self, f: &TestFile, cands: &[StoredEnvelope]) -> FileVerdict {
        let mut out = verdict_run(f, "");
        out.libraries = self.project.policy.libraries_for(&f.project_rel);
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
        // Current global inputs are the same for every candidate.
        let global_now = global_manifest(self.ctx, self.project, &self.child, &f.abs)
            .map_err(|e| format!("{e:#}"));
        for s in cands {
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
        let best = out
            .candidates
            .iter()
            .filter_map(|c| c.failure.as_ref())
            .max_by_key(|f| f.rank)
            .map(Failure::summary)
            .unwrap_or_default();
        out.reason = format!(
            "no valid attestation ({} candidates; best failed {best})",
            out.candidates.len()
        );
        out
    }

    fn check(
        &self,
        f: &TestFile,
        s: &StoredEnvelope,
        global_now: &Result<InputManifest, String>,
        info: &mut CandidateInfo,
    ) -> Result<(), Failure> {
        // A value the store could not read (e.g. a blob missing from the
        // object database) only fails its own candidate.
        if let Some(e) = &s.error {
            return Err(Failure::one(
                "envelope",
                1,
                "value in the git-meta store",
                format!("unreadable: {e}"),
                "a readable DSSE envelope",
            ));
        }
        // Envelope shape.
        let env = Envelope::from_json(&s.bytes).map_err(|e| {
            Failure::one(
                "envelope",
                1,
                "envelope JSON",
                format!("unparseable: {e}"),
                "a DSSE envelope",
            )
        })?;

        // Signature, namespace, signer trust (base allowed_signers).
        let verified = verify_envelope(&env, self.allowed, self.now).map_err(|e| {
            let (check, rank) = match &e {
                VerifyError::Malformed(_) | VerifyError::WrongPayloadType(_) => ("envelope", 1),
                VerifyError::BadSignature(_) | VerifyError::NoSignatures => ("signature", 2),
                VerifyError::WrongNamespace(_) => ("signature", 2),
                VerifyError::UnknownSigner(_) | VerifyError::CertAuthorityRejected(_) => {
                    ("signer", 3)
                }
                VerifyError::SignerNotValidNow(_) => ("signer", 3),
            };
            Failure::one(
                check,
                rank,
                "signature verification",
                "a valid signature by a key in base allowed_signers",
                e.to_string(),
            )
        })?;
        info.principal = Some(verified.principal.clone());
        info.fingerprint = Some(verified.fingerprint.clone());
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

        // Statement / predicate shape.
        let st = &verified.statement;
        if st.predicate_type != PREDICATE_TYPE {
            return Err(Failure::one(
                "statement",
                4,
                "predicateType",
                st.predicate_type.clone(),
                PREDICATE_TYPE,
            ));
        }
        let p: VciPredicate = serde_json::from_value(st.predicate.clone()).map_err(|e| {
            Failure::one(
                "statement",
                4,
                "predicate",
                format!("unparseable: {e}"),
                "a vci test predicate",
            )
        })?;
        info.issued_at = Some(p.core.issued_at.clone());
        info.expires_at = Some(p.core.expires_at.clone());
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

        // Expiry and TTL policy.
        let issued = parse_rfc3339(&p.core.issued_at).map_err(|e| {
            Failure::one(
                "expiry",
                5,
                "issuedAt",
                p.core.issued_at.clone(),
                format!("RFC 3339 required ({e})"),
            )
        })?;
        let expires = parse_rfc3339(&p.core.expires_at).map_err(|e| {
            Failure::one(
                "expiry",
                5,
                "expiresAt",
                p.core.expires_at.clone(),
                format!("RFC 3339 required ({e})"),
            )
        })?;
        if issued > self.now + CLOCK_SKEW_SECS {
            return Err(Failure::one(
                "expiry",
                5,
                "issuedAt",
                p.core.issued_at.clone(),
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
                p.core.expires_at.clone(),
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
        if p.core.repo_id != self.repo_id {
            return Err(Failure::one(
                "repo",
                6,
                "repoId",
                p.core.repo_id.clone(),
                self.repo_id.clone(),
            ));
        }
        if p.core.test_id != f.test_id.as_str() {
            return Err(Failure::one(
                "test-id",
                7,
                "testId",
                p.core.test_id.clone(),
                f.test_id.as_str(),
            ));
        }
        let adapter = self.project.adapter.as_ref();
        if p.core.adapter != adapter.name() {
            return Err(Failure::one(
                "adapter",
                8,
                "adapter",
                p.core.adapter.clone(),
                adapter.name(),
            ));
        }
        let argv = adapter.canonical_argv(&self.project.rel, &f.project_rel);
        if p.core.argv != argv
            || p.project_dir != self.project.rel
            || p.runner_project != f.runner_project
            || p.project_name != self.project.name
        {
            return Err(Failure::one(
                "argv",
                9,
                "argv / project",
                format!(
                    "{:?} project {:?} runner project {:?} vci project {:?}",
                    p.core.argv, p.project_dir, p.runner_project, p.project_name
                ),
                format!(
                    "{argv:?} project {:?} runner project {:?} vci project {:?}",
                    self.project.rel, f.runner_project, self.project.name
                ),
            ));
        }

        // Toolchain (adapter-specific tools; see Toolchain::diff).
        let tc = &p.core.toolchain;
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
            &p.platform_specific,
            std::env::consts::OS,
            std::env::consts::ARCH,
        ));
        if p.core.adapter == "go" {
            tdiff.extend(go_arch_diff(
                platform,
                &tc.arch,
                &p.arch_specific,
                std::env::consts::ARCH,
            ));
        }
        // Cargo: target-dependent cfg predicates of the unit's code must
        // evaluate here as they did on the attesting host.
        if !p.cfg_predicates.is_empty() && tc.rust_cfg != now_tc.rust_cfg {
            for pred in &p.cfg_predicates {
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
        if p.env_config_digest != fenv.digest() {
            return Err(Failure::one(
                "env-config",
                11,
                "envConfigDigest (the [env] lists of the base vci.toml, or vci's built-in lists, differ from the attestation's; attestations made before vci 1.6.0 all differ once)",
                p.env_config_digest.clone(),
                fenv.digest(),
            ));
        }

        // Result.
        if !p.core.result.is_pass() || !p.core.tainted.is_empty() {
            return Err(Failure::one(
                "result",
                12,
                "result",
                format!(
                    "{} failed={} tainted={:?}",
                    p.core.result.state, p.core.result.failed, p.core.tainted
                ),
                "passed, untainted (required)",
            ));
        }
        // Declared inputs (`[[inputs]]`) must be exactly the base config's:
        // a declaration added later names files the attestation never hashed.
        let declared = self.project.extra_inputs(&f.project_rel);
        if p.declared_inputs != declared {
            return Err(Failure::one(
                "inputs-config",
                12,
                "declared inputs ([[inputs]] extra)",
                format!("{:?}", p.declared_inputs),
                format!("{declared:?} (base vci.toml)"),
            ));
        }
        // Refusals waived by policy when the attestation was made must still
        // be waived by the base commit's policy.
        for w in &p.waived {
            let (allowed, why) = if w.starts_with(vci_adapter::CARGO_UNDECLARED_TAINT) {
                (
                    !declared.is_empty(),
                    "no [[inputs]] declared for this unit in the base vci.toml",
                )
            } else if w.starts_with(LEGACY_RAILS_NETWORK_DB_WAIVER) {
                // Written by vci before 1.4.0 under policy.rails_allow_db
                // (and by a collector older than 0.5.0, whose version the
                // toolchain no longer matches anyway).
                (
                    false,
                    "policy.rails_allow_db was removed in vci 1.4.0: attest the file again",
                )
            } else {
                (
                    w.starts_with(vci_adapter::GO_NET_TAINT) && self.project.policy.go_allow_net,
                    "not waived by the base policy (policy.go_allow_net = false)",
                )
            };
            if !allowed {
                return Err(Failure::one("result", 12, "waived refusal", w.clone(), why));
            }
        }
        if p.core.tree_dirty && !self.project.policy.allow_dirty {
            return Err(Failure::one(
                "dirty",
                13,
                "treeDirty",
                "true",
                "false required (policy.allow_dirty = false)",
            ));
        }

        // Global inputs: attested manifest is self-consistent, still matches
        // the checkout, and the current global input set is the same.
        let gm = &p.core.global_manifest;
        if gm.root() != p.core.global_input_root {
            return Err(Failure::one(
                "global-inputs",
                14,
                "globalInputRoot",
                p.core.global_input_root.clone(),
                format!("{} (recomputed from the attested manifest)", gm.root()),
            ));
        }
        let gdiff = gm
            .diff_against_checkout_with_env(&self.ctx.root, lookup(&self.child))
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
        match global_now {
            Ok(now) if now.root() == p.core.global_input_root => {}
            Ok(now) => {
                let attested: BTreeSet<&str> = gm.entries.iter().map(|e| e.path.as_str()).collect();
                let current: BTreeSet<&str> = now.entries.iter().map(|e| e.path.as_str()).collect();
                let added: Vec<&&str> = current.difference(&attested).collect();
                let removed: Vec<&&str> = attested.difference(&current).collect();
                return Err(Failure::one(
                    "global-inputs",
                    14,
                    format!("global input set (new: {added:?}, gone: {removed:?})"),
                    p.core.global_input_root.clone(),
                    now.root(),
                ));
            }
            Err(e) => {
                return Err(Failure::one(
                    "global-inputs",
                    14,
                    "computing current global inputs",
                    p.core.global_input_root.clone(),
                    format!("error: {e}"),
                ));
            }
        }

        // Per-file inputs.
        let m = &p.core.manifest;
        if m.root() != p.core.input_root {
            return Err(Failure::one(
                "inputs",
                15,
                "inputRoot",
                p.core.input_root.clone(),
                format!("{} (recomputed from the attested manifest)", m.root()),
            ));
        }
        m.check_case_collisions()
            .map_err(|e| Failure::one("inputs", 15, "case collisions", "none", e.to_string()))?;
        let diff = m
            .diff_against_checkout_with_env(&self.ctx.root, lookup(&self.child))
            .map_err(|e| Failure::one("inputs", 15, "rehash", "re-hashable", e.to_string()))?;
        let (env_diff, file_diff): (Vec<_>, Vec<_>) =
            diff.into_iter().partition(|m| m.what.starts_with("env:"));
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
        let mut ext_diff = vec![];
        for e in &m.externals {
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
    for (i, c) in f.candidates.iter().enumerate() {
        println!(
            "candidate {}: git-meta {} {}",
            i + 1,
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
        };
        let repo = Repo::discover(root).unwrap();
        plan_with(&opts, repo, root.to_owned(), &mut res, &mut None).map(|()| res)
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
}
