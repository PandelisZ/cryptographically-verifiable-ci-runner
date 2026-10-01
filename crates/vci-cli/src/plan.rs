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

use crate::config::{ALLOWED_SIGNERS_FILE, CONFIG_FILE, Config, Platform};
use crate::ctx::{Ctx, Project, TestFile, VciPredicate, mark_cross_project_ambiguity, open_repo};
use crate::envpolicy::{ChildEnvMap, lookup};
use crate::run::global_manifest;
use crate::util::{glob_match, now_unix, parse_rfc3339};

/// Allowed clock skew for `issued_at` in the future.
const CLOCK_SKEW_SECS: i64 = 300;

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
}

/// Resolve the base ref: explicit, `$VCI_BASE_REF`, `$GITHUB_BASE_REF`
/// (as `origin/<ref>` or `<ref>`), else `origin/HEAD`, `origin/main`,
/// `origin/master`, `main`, `master`.
fn resolve_base(repo: &Repo, explicit: Option<&str>) -> Result<(String, String), String> {
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
    /// pytest: installed distributions and the uv.lock pins.
    python_externals: Option<PythonExternals>,
    /// Go: the build list (`go list -m -json all`).
    go_modules: Option<Result<vci_adapter::InstalledExternals, String>>,
    /// Cargo: the packages Cargo.lock pins.
    cargo_lock: Option<Result<vci_adapter::InstalledExternals, String>>,
    /// Rails: the gems of the bundle Bundler resolves in this checkout.
    rails_gems: Option<Result<vci_adapter::InstalledExternals, String>>,
}

/// What CI resolves Python externals against: the distributions installed in
/// the `uv run --locked` environment, and the `uv.lock` pins.
type PythonExternals = (
    Result<vci_adapter::InstalledExternals, String>,
    Result<Option<crate::externals::LockedPackages>, String>,
);

fn verdict_run(f: &TestFile, reason: &str) -> FileVerdict {
    FileVerdict {
        test_id: f.test_id.as_str().to_owned(),
        file: f.project_rel.clone(),
        project: String::new(),
        skip: false,
        reason: reason.to_owned(),
        by: None,
        candidates: vec![],
        project_idx: f.project,
    }
}

/// Top-level plan. Never fails: problems become `run_all` (for everything,
/// or for one project).
pub fn plan(opts: &PlanOptions) -> Result<PlanResult> {
    let (repo, root) = open_repo()?;
    let mut res = PlanResult {
        base_ref: None,
        base_commit: None,
        run_all: None,
        warnings: vec![],
        projects: vec![],
        files: vec![],
        multi: false,
    };

    // 1. Policy and trust roots from the BASE commit.
    let (base_ref, base) = match resolve_base(&repo, opts.base_ref.as_deref()) {
        Ok(x) => x,
        Err(e) => {
            res.run_all = Some(e);
            return Ok(fallback_listing(res, repo, root));
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
                return Ok(fallback_listing(res, repo, root));
            }
        },
        Ok(None) => {
            res.run_all = Some(format!("{CONFIG_FILE} is missing at the base commit"));
            return Ok(fallback_listing(res, repo, root));
        }
        Err(e) => {
            res.run_all = Some(format!("reading {CONFIG_FILE} at base: {e}"));
            return Ok(fallback_listing(res, repo, root));
        }
    };
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

    // 2. Projects (base config) and their test files.
    let ctx = match Ctx::new(repo, root.clone(), config) {
        Ok(c) => c,
        Err(e) => {
            res.run_all = Some(format!("{e:#}"));
            return Ok(res);
        }
    };
    let mut files: Vec<TestFile> = Vec::new();
    for (i, p) in ctx.projects.iter().enumerate() {
        let child = p.child_env();
        let mut run_all = res.run_all.clone();
        if run_all.is_none()
            && let Some(r) = refs
                .iter()
                .find(|r| p.policy.no_skip_refs.iter().any(|g| glob_match(g, r)))
        {
            run_all = Some(format!("policy.no_skip_refs matches {r}"));
        }
        match p
            .adapter
            .list_test_files(&child.to_child_env())
            .map_err(anyhow::Error::from)
            .and_then(|l| p.test_files(i, l))
        {
            Ok(f) => files.extend(f),
            Err(e) => run_all = Some(format!("listing test files failed: {e:#}")),
        }
        res.projects.push(ProjectPlan {
            name: p.name.clone(),
            path: p.rel.clone(),
            adapter: p.adapter.name().to_owned(),
            run_all,
            dir: p.dir.clone(),
            child_env: Some(child),
            adapter_options: vci_adapter::AdapterOptions {
                rails_allow_db: p.policy.rails_allow_db,
            },
        });
    }
    mark_cross_project_ambiguity(&mut files);
    if let Some(id) = &opts.only {
        files.retain(|f| f.test_id.as_str() == id);
    }

    // 3. Stored candidates from the local git-meta store (`vci fetch`
    // materializes the remote's), looked up per unit, then per project:
    // toolchain, repo identity, and the checks.
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
    for (pi, project) in ctx.projects.iter().enumerate() {
        let mine: Vec<&TestFile> = files.iter().filter(|f| f.project == pi).collect();
        let verifier = match (&res.projects[pi].run_all, &allowed) {
            (Some(r), _) => Err(r.clone()),
            (None, None) => Err("no trusted signers".to_owned()),
            (None, Some(allowed)) => {
                let child = res.projects[pi].child_env.clone().unwrap_or_default();
                let env = child.to_child_env();
                (|| -> Result<Verifier<'_>> {
                    let repo_id = ctx.repo.repo_id()?;
                    let versions = project.adapter.tool_versions_with_env(&env)?;
                    let max_ttl = project.policy.max_ttl_secs()?;
                    let python_externals = if project.adapter.name() == "pytest" {
                        Some((
                            project
                                .adapter
                                .installed_externals(&env)
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
                                .installed_externals(&env)
                                .map_err(|e| e.to_string())
                                .and_then(|o| o.ok_or_else(|| "not enumerable".to_owned()))
                        })
                    };
                    let go_modules = listed("go");
                    let cargo_lock = listed("cargo");
                    let rails_gems = listed("rails");
                    Ok(Verifier {
                        ctx: &ctx,
                        project,
                        allowed,
                        now,
                        max_ttl,
                        repo_id,
                        versions,
                        child,
                        python_externals,
                        go_modules,
                        cargo_lock,
                        rails_gems,
                    })
                })()
                .map_err(|e| format!("{e:#}"))
            }
        };
        match verifier {
            Err(r) => {
                res.projects[pi].run_all.get_or_insert_with(|| r.clone());
                for f in mine {
                    res.files.push(verdict_run(f, &r));
                }
            }
            Ok(v) => {
                for f in mine {
                    // A test id listed by two projects: both see the same
                    // candidates (they are ambiguous and run anyway).
                    let cands = by_id
                        .get(f.test_id.as_str())
                        .map(Vec::as_slice)
                        .unwrap_or_default();
                    res.files.push(v.verdict(f, cands));
                }
            }
        }
    }
    finish(&mut res);
    Ok(res)
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
fn fallback_listing(mut res: PlanResult, repo: Repo, root: camino::Utf8PathBuf) -> PlanResult {
    let reason = res.run_all.clone().unwrap_or_default();
    let config = crate::ctx::working_tree_config(&root).unwrap_or_default();
    res.multi = config.is_multi();
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
                dir: p.dir.clone(),
                child_env: Some(child),
                adapter_options: vci_adapter::AdapterOptions {
                    rails_allow_db: p.policy.rails_allow_db,
                },
            });
        }
        res.files = files.iter().map(|f| verdict_run(f, &reason)).collect();
    }
    finish(&mut res);
    res
}

impl Verifier<'_> {
    fn verdict(&self, f: &TestFile, cands: &[StoredEnvelope]) -> FileVerdict {
        let mut out = verdict_run(f, "");
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
        let mut tdiff = tc.diff(&now_tc);
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
                "envConfigDigest",
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
            } else if w.starts_with(vci_adapter::RAILS_NETWORK_DB_TAINT) {
                (
                    p.core.adapter == "rails" && self.project.policy.rails_allow_db,
                    "not waived by the base policy (policy.rails_allow_db = false)",
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
        if !env_diff.is_empty() {
            return Err(Failure {
                check: "env",
                rank: 17,
                details: env_diff
                    .into_iter()
                    .map(|m| Detail {
                        what: m.what,
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
                        what: format!("env:{k}"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use vci_core::{Observation, RepoPath};

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
}
