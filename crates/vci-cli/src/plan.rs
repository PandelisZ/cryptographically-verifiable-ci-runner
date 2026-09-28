//! `vci plan` / `vci explain` / `vci ci`: the verification algorithm.
//!
//! Default verdict is RUN. A test file is skipped only when one stored
//! candidate passes every check below, in order. Every error is caught per
//! candidate (or, for errors that affect everything, turns into "run all").

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::Serialize;
use vci_adapter::Adapter;
use vci_attest::{AllowedSigners, Envelope, VerifyError, verify_envelope};
use vci_core::{InputManifest, PREDICATE_TYPE, test_key};
use vci_git::{AttestStore, Repo, StoredEnvelope};

use crate::config::{ALLOWED_SIGNERS_FILE, CONFIG_FILE, Config, Platform};
use crate::ctx::{Ctx, TestFile, VciPredicate, open_repo};
use crate::envpolicy::{ChildEnvMap, FileEnv, build_child_env, lookup};
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
    pub signer_ref: String,
    pub storage_key: String,
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
    pub skip: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<CandidateInfo>,
    #[serde(skip)]
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanResult {
    pub base_ref: Option<String>,
    pub base_commit: Option<String>,
    /// Set when everything must run; the reason.
    pub run_all: Option<String>,
    /// Configuration problems that do not change the verdicts (also printed
    /// to stderr).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub files: Vec<FileVerdict>,
    #[serde(skip)]
    pub project_dir: Option<camino::Utf8PathBuf>,
    #[serde(skip)]
    pub child_env: Option<ChildEnvMap>,
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

/// Everything computed once per plan.
struct Verifier<'a> {
    ctx: &'a Ctx,
    allowed: AllowedSigners,
    now: i64,
    max_ttl: i64,
    repo_id: String,
    versions: vci_adapter::ToolVersions,
    child: ChildEnvMap,
}

/// Top-level plan. Never fails: problems become `run_all`.
pub fn plan(opts: &PlanOptions) -> Result<PlanResult> {
    let (repo, root) = open_repo()?;
    let mut res = PlanResult {
        base_ref: None,
        base_commit: None,
        run_all: None,
        warnings: vec![],
        files: vec![],
        project_dir: None,
        child_env: None,
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
    if res.run_all.is_none() {
        let refs = current_refs(&repo);
        if let Some(r) = refs
            .iter()
            .find(|r| config.policy.no_skip_refs.iter().any(|g| glob_match(g, r)))
        {
            res.run_all = Some(format!("policy.no_skip_refs matches {r}"));
        }
    }

    // 2. List test files (with the base project dir).
    let ctx = match Ctx::new(repo, root.clone(), config) {
        Ok(c) => c,
        Err(e) => {
            res.run_all = Some(format!("{e:#}"));
            return Ok(res);
        }
    };
    let child = build_child_env(
        &ctx.config.env,
        ctx.adapter.inferred_env_patterns(),
        std::env::vars_os(),
    );
    res.project_dir = Some(ctx.project_dir.clone());
    res.child_env = Some(child.clone());
    let files = match ctx
        .adapter
        .list_test_files(&child.to_child_env())
        .map_err(anyhow::Error::from)
        .and_then(|l| ctx.test_files(l))
    {
        Ok(f) => f,
        Err(e) => {
            res.run_all = Some(format!("listing test files failed: {e:#}"));
            return Ok(res);
        }
    };
    let files: Vec<TestFile> = match &opts.only {
        Some(id) => files
            .into_iter()
            .filter(|f| f.test_id.as_str() == id)
            .collect(),
        None => files,
    };
    let mark_all = |res: &mut PlanResult, files: &[TestFile], reason: &str| {
        res.files = files
            .iter()
            .map(|f| FileVerdict {
                test_id: f.test_id.as_str().to_owned(),
                file: f.project_rel.clone(),
                skip: false,
                reason: reason.to_owned(),
                by: None,
                candidates: vec![],
            })
            .collect();
    };
    if let Some(r) = res.run_all.clone() {
        mark_all(&mut res, &files, &r);
        return Ok(res);
    }
    let allowed = allowed.expect("checked above");

    // 3. Toolchain, repo identity, stored candidates.
    let setup = (|| -> Result<(String, vci_adapter::ToolVersions, i64, Vec<StoredEnvelope>)> {
        let repo_id = ctx.repo.repo_id()?;
        let versions = ctx.adapter.tool_versions()?;
        let max_ttl = ctx.config.policy.max_ttl_secs()?;
        let stored = AttestStore::new(&ctx.repo).list(None)?;
        Ok((repo_id, versions, max_ttl, stored))
    })();
    let (repo_id, versions, max_ttl, stored) = match setup {
        Ok(x) => x,
        Err(e) => {
            let r = format!("{e:#}");
            res.run_all = Some(r.clone());
            mark_all(&mut res, &files, &r);
            return Ok(res);
        }
    };
    let mut by_key: BTreeMap<String, Vec<StoredEnvelope>> = BTreeMap::new();
    for s in stored {
        by_key.entry(s.test_key.clone()).or_default().push(s);
    }
    let v = Verifier {
        ctx: &ctx,
        allowed,
        now: now_unix(),
        max_ttl,
        repo_id,
        versions,
        child,
    };

    // 4./5. Per test file, per candidate.
    for f in &files {
        let cands = by_key
            .remove(&test_key(f.test_id.as_str()))
            .unwrap_or_default();
        res.files.push(v.verdict(f, &cands));
    }
    Ok(res)
}

/// When policy can't be read, still try to list files so the output names
/// them (everything runs).
fn fallback_listing(mut res: PlanResult, repo: Repo, root: camino::Utf8PathBuf) -> PlanResult {
    let reason = res.run_all.clone().unwrap_or_default();
    let config = crate::ctx::working_tree_config(&root).unwrap_or_default();
    if let Ok(ctx) = Ctx::new(repo, root, config) {
        let child = build_child_env(
            &ctx.config.env,
            ctx.adapter.inferred_env_patterns(),
            std::env::vars_os(),
        );
        res.project_dir = Some(ctx.project_dir.clone());
        if let Ok(files) = ctx
            .adapter
            .list_test_files(&child.to_child_env())
            .map_err(anyhow::Error::from)
            .and_then(|l| ctx.test_files(l))
        {
            res.files = files
                .iter()
                .map(|f| FileVerdict {
                    test_id: f.test_id.as_str().to_owned(),
                    file: f.project_rel.clone(),
                    skip: false,
                    reason: reason.clone(),
                    by: None,
                    candidates: vec![],
                })
                .collect();
        }
        res.child_env = Some(child);
    }
    res
}

fn node_major(v: &str) -> &str {
    v.split('.').next().unwrap_or(v)
}

impl Verifier<'_> {
    fn verdict(&self, f: &TestFile, cands: &[StoredEnvelope]) -> FileVerdict {
        let mut out = FileVerdict {
            test_id: f.test_id.as_str().to_owned(),
            file: f.project_rel.clone(),
            skip: false,
            reason: String::new(),
            by: None,
            candidates: vec![],
        };
        if f.ambiguous {
            out.reason = "listed under more than one runner project".into();
            return out;
        }
        if cands.is_empty() {
            out.reason = "no attestation".into();
            return out;
        }
        // Current global inputs are the same for every candidate.
        let global_now =
            global_manifest(self.ctx, &self.child, &f.abs).map_err(|e| format!("{e:#}"));
        for s in cands {
            let mut info = CandidateInfo {
                signer_ref: s.signer_ref.clone(),
                storage_key: s.input_root.clone(),
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
        let verified = verify_envelope(&env, &self.allowed, self.now).map_err(|e| {
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
        if p.core.adapter != self.ctx.adapter.name() {
            return Err(Failure::one(
                "adapter",
                8,
                "adapter",
                p.core.adapter.clone(),
                self.ctx.adapter.name(),
            ));
        }
        let argv = self
            .ctx
            .adapter
            .canonical_argv(&self.ctx.project_rel, &f.project_rel);
        if p.core.argv != argv
            || p.project_dir != self.ctx.project_rel
            || p.runner_project != f.runner_project
        {
            return Err(Failure::one(
                "argv",
                9,
                "argv / project",
                format!(
                    "{:?} project {:?} runner project {:?}",
                    p.core.argv, p.project_dir, p.runner_project
                ),
                format!(
                    "{argv:?} project {:?} runner project {:?}",
                    self.ctx.project_rel, f.runner_project
                ),
            ));
        }

        // Toolchain.
        let tc = &p.core.toolchain;
        let mut tdiff = vec![];
        if node_major(&tc.node) != node_major(&self.versions.node) {
            tdiff.push((
                "node major",
                node_major(&tc.node).to_owned(),
                node_major(&self.versions.node).to_owned(),
            ));
        }
        if tc.vitest != self.versions.runner {
            tdiff.push(("vitest", tc.vitest.clone(), self.versions.runner.clone()));
        }
        if tc.vite != self.versions.bundler {
            tdiff.push(("vite", tc.vite.clone(), self.versions.bundler.clone()));
        }
        let platform = self.ctx.config.policy.platform_for(&f.project_rel);
        let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
        if platform >= Platform::SameOs && tc.os != os {
            tdiff.push(("os", tc.os.clone(), os.to_owned()));
        }
        if platform >= Platform::Exact && tc.arch != arch {
            tdiff.push(("arch", tc.arch.clone(), arch.to_owned()));
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
        let fenv = FileEnv::for_file(
            &self.ctx.config.env,
            self.ctx.adapter.inferred_env_patterns(),
            &f.project_rel,
        );
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
        if p.core.tree_dirty && !self.ctx.config.policy.allow_dirty {
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

        // Externals: every attested package version must be what resolves now.
        let mut ext_diff = vec![];
        for e in &m.externals {
            match crate::externals::installed(self.ctx.adapter.project_dir(), &e.name, &e.version) {
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

/// Load the plan and print it in `format`.
pub fn print(res: &PlanResult, format: &str) -> Result<()> {
    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(res)?);
        }
        "github" => {
            let run: Vec<&str> = res.to_run().map(|f| f.file.as_str()).collect();
            let skip: Vec<&str> = res.skipped().map(|f| f.file.as_str()).collect();
            for f in res.skipped() {
                println!("::notice title=vci skip::{} {}", f.test_id, f.reason);
            }
            if let Some(r) = &res.run_all {
                println!("::warning title=vci::running everything: {r}");
            }
            let lines = format!(
                "run_all={}\nrun={}\nskip={}\n",
                res.run_all.is_some(),
                run.join(" "),
                skip.join(" ")
            );
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
            }
            for f in &res.files {
                println!(
                    "{} {}  ({})",
                    if f.skip { "SKIP" } else { "RUN " },
                    f.test_id,
                    f.reason
                );
            }
            println!(
                "{} to skip, {} to run",
                res.skipped().count(),
                res.to_run().count()
            );
        }
    }
    Ok(())
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
            "candidate {}: {} key {}",
            i + 1,
            c.info.signer_ref,
            c.info.storage_key
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
