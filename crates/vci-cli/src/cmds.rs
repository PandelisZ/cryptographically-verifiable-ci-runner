//! `ci`, `verify`, `init`, `push`, `fetch`, `prune`.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde_json::json;
use vci_adapter::Adapter;
use vci_attest::{AllowedSigners, Envelope, verify_envelope};
use vci_git::{AttestStore, SETUP_FILE};

use crate::config::{ALLOWED_SIGNERS_FILE, CONFIG_FILE, template_for};
use crate::ctx::{VciPredicate, open_repo};
use crate::plan::{PlanOptions, plan, print};
use crate::util::{now_unix, parse_rfc3339, rfc3339};

pub const CI_SNIPPET: &str = include_str!("../../../examples/github-actions.yml");
pub const CI_SNIPPET_PYTEST: &str = include_str!("../../../examples/github-actions-pytest.yml");
pub const CI_SNIPPET_GO: &str = include_str!("../../../examples/github-actions-go.yml");
pub const CI_SNIPPET_CARGO: &str = include_str!("../../../examples/github-actions-cargo.yml");
pub const CI_SNIPPET_RAILS: &str = include_str!("../../../examples/github-actions-rails.yml");
pub const CI_SNIPPET_NODE_TEST: &str =
    include_str!("../../../examples/github-actions-node-test.yml");

/// `vci ci`'s options.
pub struct CiArgs {
    pub base_ref: Option<String>,
    pub audit_log: Option<Utf8PathBuf>,
    /// Attest what runs (as `vci run --key`).
    pub key: Option<Utf8PathBuf>,
    pub ttl: String,
    /// Publish the attestations afterwards (as `vci push`).
    pub push: bool,
    pub remote: Option<String>,
    /// Fetch attestations first (`--fetch [REMOTE]`; `Some(None)`: the
    /// default remote), while the projects are probed.
    pub fetch: Option<Option<String>>,
    /// `--project`: only these `[[projects]]` are planned and run (empty:
    /// every project).
    pub projects: Vec<String>,
}

pub fn ci(args: CiArgs) -> Result<i32> {
    let res = plan(&PlanOptions {
        base_ref: args.base_ref.clone(),
        only: None,
        fetch: args.fetch.clone(),
        projects: args.projects.clone(),
    })?;
    if let Some(w) = &res.fetch_failed {
        github_warning(w);
    }
    print(&res, "text")?;
    let (repo, root) = open_repo()?;
    let mut attested: Vec<crate::run::AttestedUnit> = Vec::new();
    let mut attest_errors: Vec<String> = Vec::new();
    // Why nothing was attested on purpose (and nothing is pushed).
    let mut not_attested: Option<String> = None;
    let code = match &args.key {
        None => run_plain(&res, &root, None)?,
        Some(key) => match run_attested(&res, key, &args.ttl) {
            Ok(Attempt::Ran(out)) => {
                for e in &out.errors {
                    github_warning(&format!("attesting: {e}"));
                }
                let mut code = out.exit;
                // Projects whose tests did not run with the collectors (no
                // verdict yet): run them, and only them, without attesting.
                // What already ran is neither run again nor forgotten.
                if !out.unrun.is_empty() {
                    let c = run_plain(&res, &root, Some(&out.unrun))?;
                    if code == 0 {
                        code = c;
                    }
                }
                attested = out.attested;
                attest_errors = out.errors;
                code
            }
            Ok(Attempt::NotAttested(why)) => {
                github_warning(&format!("not attesting: {why}"));
                not_attested = Some(why);
                run_plain(&res, &root, None)?
            }
            // Nothing has run yet (run_units reports what fails after a test
            // ran in RunOutcome::errors instead).
            Err(e) => {
                let msg = format!(
                    "could not run the tests with attestation ({e:#}); running them without attesting"
                );
                github_warning(&msg);
                attest_errors.push(format!("{e:#}"));
                not_attested = Some(msg);
                run_plain(&res, &root, None)?
            }
        },
    };
    let push_wanted = args.push && not_attested.is_none();
    if args.key.is_some() {
        eprintln!(
            "vci ci: {} unit(s) attested{}",
            attested.len(),
            if push_wanted {
                ""
            } else if args.push {
                " (nothing to push)"
            } else {
                " (stored locally; publish with `vci push`)"
            }
        );
    }
    let pushed = if push_wanted {
        // Best effort: CI's result is the tests', never the publication's.
        match push(args.remote.as_deref(), false) {
            Ok(_) => Some(true),
            Err(e) => {
                github_warning(&format!(
                    "could not push attestations{}: {e:#}",
                    args.remote
                        .as_deref()
                        .map(|r| format!(" to {}", redact_userinfo(r)))
                        .unwrap_or_default()
                ));
                Some(false)
            }
        }
    } else {
        None
    };

    let now = now_unix();
    let log = json!({
        "time": rfc3339(now),
        "head": repo.head_commit().ok(),
        "baseRef": res.base_ref,
        "baseCommit": res.base_commit,
        "runAll": res.run_all,
        "warnings": res.warnings,
        "projects": res.projects,
        "skipped": res.skipped().map(|f| json!({
            "testId": f.test_id,
            "project": f.project,
            "reason": f.reason,
            "by": f.by,
        })).collect::<Vec<_>>(),
        "ran": res.to_run().map(|f| json!({"testId": f.test_id, "project": f.project, "reason": f.reason})).collect::<Vec<_>>(),
        "attested": attested.iter().map(|a| json!({"testId": a.test_id, "project": a.project})).collect::<Vec<_>>(),
        "attestErrors": attest_errors,
        "notAttested": not_attested,
        "pushed": pushed,
        "exitCode": code,
    });
    let path = args
        .audit_log
        .unwrap_or_else(|| root.join(format!(".vci/out/audit-{now}.json")));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&log)?)?;
    eprintln!("vci ci: audit log written to {path}");
    Ok(code)
}

/// A warning for the log and, on GitHub Actions, an annotation (a workflow
/// command: one line, `%`, CR and LF escaped).
fn github_warning(msg: &str) {
    let escaped = msg
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A");
    println!("::warning title=vci::{escaped}");
}

/// The label `vci ci` prints for a project of a multi-project plan.
fn job_label(p: &crate::plan::ProjectPlan) -> String {
    if p.name.is_empty() {
        p.path.clone()
    } else {
        p.name.clone()
    }
}

/// What [`run_attested`] did.
enum Attempt {
    /// The tests ran with the collectors (`RunOutcome::unrun`: those that
    /// could not).
    Ran(crate::run::RunOutcome),
    /// Nothing ran: attesting is not possible or not allowed here (why).
    NotAttested(String),
}

/// `vci ci --key`: run what the plan leaves through `vci run`'s code path
/// (collectors on, inputs recorded, attestations signed and stored). Every
/// unit of a project that runs everything (`run_all`) is attested: that is
/// the run the next commit's plan reuses. An `Err` means nothing ran.
fn run_attested(res: &crate::plan::PlanResult, key: &Utf8Path, ttl: &str) -> Result<Attempt> {
    let Some(config) = res.config.clone().filter(|_| !res.projects.is_empty()) else {
        return Ok(Attempt::NotAttested("no project could be read".into()));
    };
    // A key that cannot be read fails before anything runs.
    let signing = crate::keys::load(key).with_context(|| format!("--key {key}"))?;
    if let Some(why) = attest_refusal(res, &signing.blob) {
        return Ok(Attempt::NotAttested(why));
    }
    let multi = res.projects.len() > 1;
    let mut units: std::collections::BTreeMap<usize, Option<std::collections::BTreeSet<String>>> =
        Default::default();
    for (i, p) in res.projects.iter().enumerate() {
        let what = if multi {
            format!(" of {} ({})", job_label(p), p.adapter)
        } else {
            String::new()
        };
        if res.run_all.is_some() || p.run_all.is_some() {
            eprintln!("vci ci: running all tests{what} (attesting)");
            units.insert(i, None);
            continue;
        }
        let ids: std::collections::BTreeSet<String> = res
            .to_run()
            .filter(|f| f.project_idx == i)
            .map(|f| f.test_id.clone())
            .collect();
        if ids.is_empty() {
            eprintln!(
                "vci ci: every test file{what} is covered by a valid attestation; nothing to run"
            );
        } else {
            eprintln!(
                "vci ci: running {} test file(s){what} (attesting)",
                ids.len()
            );
            units.insert(i, Some(ids));
        }
    }
    if units.is_empty() {
        return Ok(Attempt::Ran(Default::default()));
    }
    let (repo, root) = open_repo()?;
    crate::run::run_units(
        repo,
        root,
        config,
        crate::run::Selection::Units(units),
        Some(key),
        ttl,
        None,
    )
    .map(Attempt::Ran)
}

/// Why `vci ci --key` must not attest here, if it must not: the key signs as
/// a principal that `policy.no_skip_refs_except` lets skip on
/// `policy.no_skip_refs` (main), and the current ref does not match
/// `no_skip_refs` (a pull request, a feature branch). Such a run executes
/// code main never ran (the branch's tests, dependencies, workflow), and
/// main would skip those units after a merge on the strength of it. Also
/// refused off those refs when the base commit's allowed_signers cannot be
/// read (whom the key signs as is unknown).
///
/// `policy.attest_on_any_ref` names the principals this does not apply to:
/// a pull request's run then attests with them, and the protected refs
/// skip what it ran (the repository's own pull requests, a repository
/// secret forks never get, authors trusted with that).
///
/// This is a guard against a misconfigured workflow, not a security
/// boundary: a branch that can read the key can sign anything with it. The
/// boundary is not handing the key to such runs (a secret of a GitHub
/// Environment restricted to the default branch).
fn attest_refusal(res: &crate::plan::PlanResult, key_blob: &[u8]) -> Option<String> {
    let off: Vec<&crate::plan::ProjectPlan> =
        res.projects.iter().filter(|p| !p.on_no_skip_ref).collect();
    if off.is_empty() {
        return None;
    }
    let Some(allowed) = &res.allowed else {
        return Some(
            "the current ref does not match policy.no_skip_refs and the base commit's allowed_signers could not be read, so whom the key signs as is unknown".into(),
        );
    };
    let principals: Vec<&str> = allowed
        .entries()
        .iter()
        .filter(|e| !e.cert_authority && e.key.to_bytes().is_ok_and(|b| b == key_blob))
        .map(|e| e.principals.as_str())
        .collect();
    for p in off {
        if let Some(principal) = principals.iter().find(|pr| {
            p.no_skip_refs_except.iter().any(|x| x == *pr)
                && !p.attest_on_any_ref.iter().any(|x| x == *pr)
        }) {
            return Some(format!(
                "the key signs as {principal}, which policy.no_skip_refs_except{} lets skip on policy.no_skip_refs (e.g. main), but the current ref does not match policy.no_skip_refs: attestations made here would let main skip tests that never ran on main. Pass this key only to runs on main (a GitHub Environment secret restricted to the default branch), or give other refs a key whose principal is not in no_skip_refs_except",
                if res.multi {
                    format!(" of {}", job_label(p))
                } else {
                    String::new()
                }
            ));
        }
    }
    None
}

/// `vci ci` without `--key`: run what the plan leaves with the adapters'
/// plain runs (no collectors, nothing signed); with `only`, of those
/// projects only. Returns the exit code.
fn run_plain(
    res: &crate::plan::PlanResult,
    root: &Utf8Path,
    only: Option<&std::collections::BTreeSet<usize>>,
) -> Result<i32> {
    // What to run, per project. With no project information at all (the
    // repository layout could not be read), run the default project.
    // (label, adapter, child env, files to run; None = everything)
    type Job = (
        String,
        Box<dyn Adapter>,
        vci_adapter::ChildEnv,
        Option<Vec<String>>,
    );
    let mut jobs: Vec<Job> = Vec::new();
    if res.projects.is_empty() && only.is_none() {
        let adapter = vci_adapter::adapter_for("vitest", root)?;
        jobs.push(("default project".into(), adapter, None, None));
    }
    for (i, p) in res.projects.iter().enumerate() {
        if only.is_some_and(|o| !o.contains(&i)) {
            continue;
        }
        let adapter = vci_adapter::adapter_for_with(&p.adapter, &p.dir, &p.adapter_options)?;
        let env = p.child_env.as_ref().and_then(|c| c.to_child_env());
        let label = job_label(p);
        let files = if res.run_all.is_some() || p.run_all.is_some() {
            None
        } else {
            let run: Vec<String> = res
                .to_run()
                .filter(|f| f.project_idx == i)
                .map(|f| f.file.clone())
                .collect();
            // node-test: when nothing of the project is skipped, its test
            // script runs as is (its own file set, `npm run test`).
            if p.adapter == "node-test"
                && !run.is_empty()
                && !res.skipped().any(|f| f.project_idx == i)
            {
                None
            } else {
                Some(run)
            }
        };
        jobs.push((label, adapter, env, files));
    }
    let mut code: Option<i32> = Some(0);
    let multi = jobs.len() > 1 || res.projects.len() > 1;
    for (label, adapter, env, files) in &jobs {
        let what = if multi {
            format!(" of {label} ({})", adapter.name())
        } else {
            String::new()
        };
        let c = match files {
            None => {
                eprintln!("vci ci: running all tests{what}");
                adapter.run_plain(&[], env)?
            }
            Some(run) if run.is_empty() => {
                eprintln!(
                    "vci ci: every test file{what} is covered by a valid attestation; nothing to run"
                );
                Some(0)
            }
            Some(run) => {
                eprintln!("vci ci: running {} test file(s){what}", run.len());
                adapter.run_plain(run, env)?
            }
        };
        match (code, c) {
            (Some(0), c) => code = c,
            (Some(_), None) => code = None,
            _ => {}
        }
    }
    Ok(code.unwrap_or(1))
}

/// `vci verify`: the envelope's signature against the trust root, its
/// predicate, expiry, and the input manifest it records: inline (before vci
/// 1.9.0) or the one it references, read from `--manifest FILE` or else
/// from the local git-meta store, whose recomputed root must be the signed
/// input root.
pub fn verify(
    envelope_path: &Utf8Path,
    allowed_signers: Option<&Utf8Path>,
    base_ref: Option<&str>,
    manifest_file: Option<&Utf8Path>,
) -> Result<i32> {
    let bytes = if envelope_path == "-" {
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut v)?;
        v
    } else {
        std::fs::read(envelope_path).with_context(|| format!("reading {envelope_path}"))?
    };
    let (text, source) = match allowed_signers {
        Some(p) => (
            std::fs::read_to_string(p).with_context(|| format!("reading {p}"))?,
            p.to_string(),
        ),
        None => {
            let (repo, _) = open_repo()?;
            let rev = base_ref.unwrap_or("HEAD");
            let sha = repo.resolve(rev)?;
            let b = repo
                .show_file(&sha, ALLOWED_SIGNERS_FILE)?
                .with_context(|| format!("{ALLOWED_SIGNERS_FILE} is missing at {rev}"))?;
            (
                String::from_utf8(b)?,
                format!("{ALLOWED_SIGNERS_FILE} at {rev} ({sha})"),
            )
        }
    };
    let allowed = AllowedSigners::parse(&text)?;
    let env = Envelope::from_json(&bytes)?;
    let now = now_unix();
    match verify_envelope(&env, &allowed, now) {
        Err(e) => {
            println!("INVALID: {e}");
            println!("  trust root: {source}");
            Ok(1)
        }
        Ok(v) => {
            println!("VALID signature by {} ({})", v.principal, v.fingerprint);
            println!("  trust root: {source}");
            println!("  predicateType: {}", v.statement.predicate_type);
            match serde_json::from_value::<VciPredicate>(v.statement.predicate.clone()) {
                Ok(p) => {
                    println!("  test: {}", p.core.test_id);
                    println!("  repo id: {}", p.core.repo_id);
                    println!("  commit: {} (dirty: {})", p.core.commit, p.core.tree_dirty);
                    println!(
                        "  result: {} ({} tests)",
                        p.core.result.state, p.core.result.tests
                    );
                    println!("  input root: {}", p.core.input_root);
                    let manifest_ok = match verify_manifest(&p, manifest_file) {
                        Ok(line) => {
                            println!("  manifest: {line}");
                            true
                        }
                        Err(line) => {
                            println!("  manifest: INVALID: {line}");
                            false
                        }
                    };
                    let expired = parse_rfc3339(&p.core.expires_at)
                        .map(|e| e <= now)
                        .unwrap_or(true);
                    println!(
                        "  issued {}, expires {}{}",
                        p.core.issued_at,
                        p.core.expires_at,
                        if expired { " (EXPIRED)" } else { "" }
                    );
                    Ok(if expired || !manifest_ok { 1 } else { 0 })
                }
                Err(e) => {
                    println!("  predicate is not a vci test predicate: {e}");
                    Ok(1)
                }
            }
        }
    }
}

/// The input manifest of a verified predicate, as one line for `vci
/// verify`: what it holds and where it came from, or why it is not usable.
fn verify_manifest(p: &VciPredicate, file: Option<&Utf8Path>) -> Result<String, String> {
    let (m, source) = match (&p.core.manifest, &p.core.manifest_ref) {
        (Some(m), None) => (m.clone(), "inline".to_owned()),
        (None, Some(r)) if *r != p.core.input_root => {
            return Err(format!(
                "manifestRef {r} is not the input root {}",
                p.core.input_root
            ));
        }
        (None, Some(r)) => match file {
            Some(f) => {
                let bytes = std::fs::read(f).map_err(|e| format!("reading {f}: {e}"))?;
                let m = vci_core::InputManifest::from_compact(&bytes)
                    .or_else(|e| serde_json::from_slice(&bytes).map_err(|_| e))
                    .map_err(|e| format!("{f}: {e}"))?;
                (m, f.to_string())
            }
            None => {
                let (repo, _) = open_repo().map_err(|e| {
                    format!("manifest {r} is stored in the repository's git-meta store, and {e:#} (pass --manifest FILE)")
                })?;
                let stored = AttestStore::new(&repo).manifest(r);
                let m = crate::plan::load_manifest(r, stored)
                    .map_err(|(what, actual)| format!("{what} ({actual})"))?;
                (m, format!("git-meta project {}", vci_git::manifest_key(r)))
            }
        },
        (Some(_), Some(_)) => return Err("both manifest and manifestRef are set".to_owned()),
        (None, None) => return Err("neither manifest nor manifestRef is set".to_owned()),
    };
    let root = m.root();
    if root != p.core.input_root {
        return Err(format!(
            "{source}: its root {root} is not the signed input root {}",
            p.core.input_root
        ));
    }
    Ok(format!(
        "{} entries, {} externals, {} env (root verified; {source})",
        m.entries.len(),
        m.externals.len(),
        m.env.len()
    ))
}

pub fn init(
    key: Option<&Utf8Path>,
    principal: Option<String>,
    project: Option<String>,
    adapter_name: Option<String>,
    install: bool,
    meta_url: Option<String>,
) -> Result<i32> {
    let (repo, root) = open_repo()?;
    let cfg_path = root.join(CONFIG_FILE);
    let adapter_name = adapter_name.unwrap_or_else(|| "vitest".into());
    if !vci_adapter::ADAPTERS.contains(&adapter_name.as_str()) {
        bail!("unsupported adapter {adapter_name:?}");
    }
    if cfg_path.exists() {
        eprintln!("vci init: {cfg_path} exists, leaving it alone");
    } else {
        let mut text = template_for(&adapter_name).to_owned();
        if let Some(p) = &project {
            text = text.replace("project = \".\"", &format!("project = {}", toml_str(p)));
        }
        crate::config::Config::parse(&text)?;
        std::fs::write(&cfg_path, text)?;
        eprintln!("vci init: wrote {cfg_path}");
    }
    let signers = root.join(ALLOWED_SIGNERS_FILE);
    std::fs::create_dir_all(signers.parent().expect("has parent"))?;
    let mut existing = std::fs::read_to_string(&signers).unwrap_or_default();
    if existing.is_empty() {
        existing.push_str("# principal namespaces=\"vci-attest\" key-type base64-key\n");
    }
    if let Some(k) = key {
        let sk = crate::keys::load(k)?;
        let principal = match principal {
            Some(p) => p,
            None => git_email(&root).unwrap_or_else(|| "vci@localhost".into()),
        };
        if principal.chars().any(char::is_whitespace) {
            bail!("principal must not contain whitespace");
        }
        if existing.contains(&sk.public) {
            eprintln!("vci init: key already in {signers}");
        } else {
            existing.push_str(&format!(
                "{principal} namespaces=\"vci-attest\" {}\n",
                sk.public
            ));
            eprintln!("vci init: added {principal} to {signers}");
        }
    }
    std::fs::write(&signers, existing)?;
    setup_git_meta(&repo, &root, meta_url.as_deref())?;

    let config = crate::ctx::working_tree_config(&root)?;
    let specs = config.project_specs();
    if specs.iter().any(|s| s.adapter == "pytest") {
        for s in specs.iter().filter(|s| s.adapter == "pytest") {
            let dir = root.join(&s.rel);
            if let Err(e) = vci_adapter::find_py_plugin(&dir) {
                eprintln!("vci init: note: {e}");
            }
        }
        if std::process::Command::new("uv")
            .arg("--version")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            eprintln!(
                "vci init: note: the pytest adapter runs tests with `uv run --locked`; install uv"
            );
        }
    }
    if specs.iter().any(|s| s.adapter == "go")
        && std::process::Command::new(
            std::env::var_os(vci_adapter::GO_BIN_ENV)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "go".into()),
        )
        .arg("version")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!(
            "vci init: note: the go adapter runs `go test`; install Go or set {} to the go binary",
            vci_adapter::GO_BIN_ENV
        );
    }
    if specs.iter().any(|s| s.adapter == "cargo")
        && std::process::Command::new(
            std::env::var_os(vci_adapter::CARGO_BIN_ENV)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "cargo".into()),
        )
        .arg("--version")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!(
            "vci init: note: the cargo adapter runs `cargo test`; install Rust or set {} to the cargo binary",
            vci_adapter::CARGO_BIN_ENV
        );
    }
    if specs.iter().any(|s| s.adapter == "rails") {
        for s in specs.iter().filter(|s| s.adapter == "rails") {
            let dir = root.join(&s.rel);
            if let Err(e) = vci_adapter::find_ruby_collector(&dir) {
                eprintln!("vci init: note: {e}");
            }
            if !dir.join("bin/rails").is_file() && !dir.join("spec").is_dir() {
                eprintln!(
                    "vci init: note: {} has no bin/rails; the rails adapter's project must be the Rails application root (or a Ruby project with RSpec and a spec/ directory)",
                    dir
                );
            }
            // Which runner: the setting, else detected (see the template).
            let opts = s.adapter_options();
            let adapter = vci_adapter::RailsAdapter::new(&dir).with_runner(opts.rails_runner);
            let has = |p: &str| adapter.runner_of(p);
            let runners = match (has("test/x_test.rb"), has("spec/x_spec.rb")) {
                (
                    Some(vci_adapter::RailsRunner::Minitest),
                    Some(vci_adapter::RailsRunner::Rspec),
                ) => "Minitest (test/**/*_test.rb) and RSpec (every other file RSpec lists)",
                (_, Some(vci_adapter::RailsRunner::Rspec)) => "RSpec",
                _ => "Minitest",
            };
            eprintln!(
                "vci init: {}: the rails adapter will run {runners} (set runner = \"minitest\" or \"rspec\" in vci.toml to choose)",
                s.rel
            );
        }
        if std::process::Command::new(
            std::env::var_os(vci_adapter::RUBY_BIN_ENV)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "ruby".into()),
        )
        .arg("--version")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
        {
            eprintln!(
                "vci init: note: the rails adapter runs `ruby bin/rails test` and RSpec with Ruby; install the Ruby in .ruby-version or set {} to the ruby binary",
                vci_adapter::RUBY_BIN_ENV
            );
        }
    }
    for s in specs.iter().filter(|s| s.adapter == "node-test") {
        let dir = root.join(&s.rel);
        if let Err(e) = vci_adapter::find_node_test_collector(&dir) {
            eprintln!("vci init: note: {e} (needed by `vci run`, not by `vci ci`)");
        }
        let adapter = vci_adapter::NodeTestAdapter::new(&dir).with_options(s.node_test.clone());
        match adapter.invocation() {
            Ok(inv) => eprintln!(
                "vci init: {}: tests from {}: {}{}",
                s.rel,
                inv.source,
                inv.command_line(),
                if inv.patterns.is_empty() {
                    " (node:test's default patterns)"
                } else {
                    ""
                }
            ),
            Err(e) => eprintln!(
                "vci init: warning: {}: {e}; set test_script, or test_globs and node_args, in vci.toml",
                s.rel
            ),
        }
    }
    let vitest: Vec<_> = specs.iter().filter(|s| s.adapter == "vitest").collect();
    if vitest.is_empty() {
        let snippet = if specs.iter().all(|s| s.adapter == "node-test") {
            CI_SNIPPET_NODE_TEST
        } else if specs.iter().all(|s| s.adapter == "go") {
            CI_SNIPPET_GO
        } else if specs.iter().all(|s| s.adapter == "cargo") {
            CI_SNIPPET_CARGO
        } else if specs.iter().all(|s| s.adapter == "rails") {
            CI_SNIPPET_RAILS
        } else {
            CI_SNIPPET_PYTEST
        };
        println!("{COMMIT_HINT} GitHub Actions example:\n");
        println!("{snippet}");
        return Ok(0);
    }
    let project_dir = root.join(&vitest[0].rel);
    if install {
        let spec = std::env::var(vci_adapter::JS_PLUGIN_ENV)
            .ok()
            .filter(|s| !s.is_empty())
            .map(|p| format!("file:{p}"))
            .unwrap_or_else(|| "@vci/vitest".into());
        eprintln!("vci init: npm install --save-dev {spec} (in {project_dir})");
        match std::process::Command::new("npm")
            .args(["install", "--save-dev", &spec])
            .current_dir(&project_dir)
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => {
                eprintln!("vci init: warning: npm install failed ({s}); install {spec} yourself")
            }
            Err(e) => {
                eprintln!("vci init: warning: could not run npm ({e}); install {spec} yourself")
            }
        }
    }
    if vci_adapter::find_js_plugin(&project_dir).is_err() {
        eprintln!(
            "vci init: note: @vci/vitest not found; set {} or install it",
            vci_adapter::JS_PLUGIN_ENV
        );
    }
    println!("{COMMIT_HINT} GitHub Actions example:\n");
    println!("{CI_SNIPPET}");
    Ok(0)
}

const COMMIT_HINT: &str = "Commit vci.toml, .vci/allowed_signers and .git-meta.";

/// Point git-meta at the metadata remote: write `.git-meta` (the file
/// `git meta setup` reads) if there is none, and configure the local
/// metadata remote. Attestations are exchanged there on `refs/meta/main`.
fn setup_git_meta(repo: &vci_git::Repo, root: &Utf8Path, meta_url: Option<&str>) -> Result<()> {
    let file = root.join(SETUP_FILE);
    let existing = vci_git::meta::read_setup_url(&file)?;
    let origin = std::process::Command::new("git")
        .args(["-C", root.as_str(), "config", "--get", "remote.origin.url"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|s| !s.is_empty());
    match (
        &existing,
        meta_url.map(str::to_owned).or_else(|| origin.clone()),
    ) {
        (Some(u), _) => eprintln!("vci init: {file} exists (url: {u}), leaving it alone"),
        (None, Some(u)) => {
            std::fs::write(&file, format!("url: {u}\n"))?;
            eprintln!("vci init: wrote {file} (git-meta metadata remote: {u})");
        }
        (None, None) => {
            eprintln!(
                "vci init: note: no origin remote and no --meta-url; attestations stay local until a git-meta remote is configured (`git meta remote add <url>`)"
            );
            return Ok(());
        }
    }
    let store = AttestStore::new(repo);
    let before = store.remote_names().unwrap_or_default();
    match store.ensure_remote(meta_url) {
        Ok(name) => {
            eprintln!(
                "vci init: git-meta remote {name:?} configured; `vci push` / `vci fetch` (or `git meta push` / `git meta pull`) exchange attestations on refs/meta/main"
            );
            if !before.contains(&name)
                && let Some(note) = shared_config_note(repo, &name)
            {
                eprintln!("{note}");
            }
        }
        Err(e) => eprintln!("vci init: note: could not configure a git-meta remote: {e}"),
    }
    Ok(())
}

/// In a linked git worktree, a remote is written to the repository's shared
/// config (git keeps one `config` for all worktrees of a repository unless
/// `extensions.worktreeConfig` is used, and remotes are never per-worktree).
/// That is git's behaviour, but `vci init` run in a worktree then changes
/// the main checkout too: say so.
fn shared_config_note(repo: &vci_git::Repo, name: &str) -> Option<String> {
    let common = repo.linked_worktree_common_dir()?;
    Some(format!(
        "vci init: note: this is a linked git worktree: the remote {name:?} was added to the repository's shared config ({}), so every worktree of this repository (the main checkout included) now has it",
        common.join("config")
    ))
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

fn git_email(root: &Utf8Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["-C", root.as_str(), "config", "--get", "user.email"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (out.status.success() && !s.is_empty()).then_some(s)
}

fn print_exchange_messages(warnings: &[String], notes: &[String]) {
    for n in notes {
        eprintln!("vci: note: {n}");
    }
    for w in warnings {
        eprintln!("vci: warning: {w}");
    }
}

/// Say which URL a metadata remote resolved without `--remote` points at:
/// it may come from `.git-meta` in the checkout.
fn print_default_remote(store: &AttestStore, remote: Option<&str>, name: &str) {
    if remote.is_none()
        && let Ok(Some(url)) = store.remote_url(name)
    {
        eprintln!("vci: git-meta remote {name} is {}", redact_userinfo(&url));
    }
}

/// `scheme://user:secret@host/...` without the credentials.
pub(crate) fn redact_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let host_end = rest.find('/').unwrap_or(rest.len());
    match rest[..host_end].rfind('@') {
        Some(at) => format!("{scheme}://***@{}", &rest[at + 1..]),
        None => url.to_owned(),
    }
}

pub fn push(remote: Option<&str>, rewrite_history: bool) -> Result<i32> {
    let (repo, _) = open_repo()?;
    let store = AttestStore::new(&repo);
    let out = if rewrite_history {
        store.push_rewriting_history(remote)?
    } else {
        store.push(remote)?
    };
    print_default_remote(&store, remote, &out.remote);
    print_exchange_messages(&out.warnings, &out.notes);
    match out.status {
        vci_git::PushStatus::Pushed => {
            eprintln!(
                "vci: pushed git-meta metadata (refs/meta/main) to {}",
                out.remote
            )
        }
        vci_git::PushStatus::UpToDate => eprintln!(
            "vci: nothing to push: {}'s refs/meta/main already has every local attestation",
            out.remote
        ),
        vci_git::PushStatus::NothingStored => eprintln!(
            "vci: nothing to push: no attestations are stored locally (run `vci run` first)"
        ),
    }
    Ok(0)
}

pub fn fetch(remote: Option<&str>) -> Result<i32> {
    let (repo, _) = open_repo()?;
    for l in fetch_messages(&repo, remote)? {
        eprintln!("{l}");
    }
    Ok(0)
}

/// `vci fetch`'s work (also `vci plan --fetch` and `vci ci --fetch`): fetch
/// and materialize the remote's attestations; what `vci fetch` prints, as
/// lines for stderr.
pub fn fetch_messages(repo: &vci_git::Repo, remote: Option<&str>) -> Result<Vec<String>> {
    let store = AttestStore::new(repo);
    let out = store.fetch(remote)?;
    let mut lines = Vec::new();
    if remote.is_none()
        && let Ok(Some(url)) = store.remote_url(&out.remote)
    {
        lines.push(format!(
            "vci: git-meta remote {} is {}",
            out.remote,
            redact_userinfo(&url)
        ));
    }
    lines.extend(out.notes.iter().map(|n| format!("vci: note: {n}")));
    lines.extend(out.warnings.iter().map(|w| format!("vci: warning: {w}")));
    let n = store.list(None)?.len();
    if out.found {
        lines.push(format!(
            "vci: fetched git-meta metadata from {} ({n} attestations stored locally)",
            out.remote
        ));
    } else {
        lines.push(format!(
            "vci: {} has no git-meta metadata yet (refs/meta/main); {n} attestations stored locally",
            out.remote
        ));
    }
    Ok(lines)
}

/// `vci prune`: delete attestations that have expired (git-meta tombstones,
/// published by the next `vci push`). Only the claimed expiry is read; an
/// envelope that cannot be parsed is left alone. Then delete the stored input
/// manifests no remaining attestation references (`manifestRef`; one with
/// its manifest inline references none), unless an attestation's value, or
/// the `manifestRef` of one left alone, cannot be read (what it references
/// is then unknown).
pub fn prune(dry_run: bool, superseded: bool) -> Result<i32> {
    let (repo, _) = open_repo()?;
    let store = AttestStore::new(&repo);
    let now = now_unix();
    let (mut expired, mut kept, mut unreadable, mut older) = (0usize, 0usize, 0usize, 0usize);
    // Of a unit's attestations by one signer, the one issued last: an older
    // one vouches for inputs that tree no longer has (or soon will not).
    let mut newest: BTreeMap<(String, String), (i64, String)> = BTreeMap::new();
    let mut current = Vec::new();
    // Manifests the remaining attestations reference; `None` once one of
    // them cannot be read.
    let mut referenced: Option<BTreeSet<String>> = Some(BTreeSet::new());
    for e in store.list(None)? {
        if e.error.is_some() {
            referenced = None;
        }
        match envelope_meta(&e.bytes) {
            Some(m) if m.expires_at <= now => {
                expired += 1;
                if dry_run {
                    println!("would remove {} {}", e.target, e.key);
                } else {
                    store.remove(&e)?;
                    println!("removed {} {}", e.target, e.key);
                }
            }
            Some(m) => {
                kept += 1;
                if !superseded && let (Some(r), Some(set)) = (&m.manifest_ref, referenced.as_mut())
                {
                    set.insert(r.clone());
                }
                if superseded {
                    let slot = newest
                        .entry((m.test_id.clone(), e.signer.clone()))
                        .or_insert((m.issued_at, e.key.clone()));
                    if (m.issued_at, &e.key) > (slot.0, &slot.1) {
                        *slot = (m.issued_at, e.key.clone());
                    }
                    current.push((m, e));
                }
            }
            None => {
                unreadable += 1;
                // Left alone, so whatever it references stays: the
                // manifest it names when that much can be read, else none
                // is removed.
                let r = envelope_statement(&e.bytes).and_then(|v| {
                    v["predicate"]["manifestRef"]
                        .as_str()
                        .filter(|r| {
                            vci_git::parse_manifest_key(&vci_git::manifest_key(r)).is_some()
                        })
                        .map(str::to_owned)
                });
                match (r, referenced.as_mut()) {
                    (Some(r), Some(set)) => {
                        set.insert(r);
                    }
                    (Some(_), None) => {}
                    (None, _) => referenced = None,
                }
            }
        }
    }
    for (m, e) in current {
        if newest
            .get(&(m.test_id.clone(), e.signer.clone()))
            .map(|n| &n.1)
            == Some(&e.key)
        {
            if let (Some(r), Some(set)) = (&m.manifest_ref, referenced.as_mut()) {
                set.insert(r.clone());
            }
            continue;
        }
        older += 1;
        kept -= 1;
        if dry_run {
            println!("would remove {} {} (superseded)", e.target, e.key);
        } else {
            store.remove(&e)?;
            println!("removed {} {} (superseded)", e.target, e.key);
        }
    }
    let mut manifests = 0usize;
    match &referenced {
        Some(set) => {
            for root in store.manifests()? {
                if set.contains(&root) {
                    continue;
                }
                manifests += 1;
                let key = vci_git::manifest_key(&root);
                if dry_run {
                    println!("would remove project {key} (unreferenced manifest)");
                } else {
                    store.remove_manifest(&root)?;
                    println!("removed project {key} (unreferenced manifest)");
                }
            }
        }
        None => eprintln!(
            "vci prune: an attestation could not be read (run `vci fetch`), so no input manifest is removed"
        ),
    }
    eprintln!(
        "vci prune: {expired} expired{}{}, {kept} current, {unreadable} unreadable (left alone)",
        if superseded {
            format!(", {older} superseded")
        } else {
            String::new()
        },
        if dry_run { " (dry run)" } else { "" }
    );
    eprintln!(
        "vci prune: {manifests} unreferenced input manifest(s){}",
        if dry_run { " (dry run)" } else { " removed" }
    );
    if expired + older + manifests > 0 && !dry_run {
        eprintln!(
            "vci prune: run `vci push` to publish the deletions (`vci push --rewrite-history` also drops the deleted values from what a fetch downloads)"
        );
    }
    Ok(0)
}

/// What `prune` (and supersession on store) reads from an envelope's
/// payload (unverified).
pub(crate) struct EnvelopeMeta {
    pub test_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    /// `commit` (empty when absent).
    pub commit: String,
    /// `toolchain.os` / `toolchain.arch` (empty when absent).
    pub os: String,
    pub arch: String,
    /// The input manifest it references (`manifestRef`; `None` for an
    /// attestation with its manifest inline, made before vci 1.9.0).
    pub manifest_ref: Option<String>,
}

/// An envelope's statement (unverified).
fn envelope_statement(bytes: &[u8]) -> Option<serde_json::Value> {
    use base64::Engine as _;
    let env = Envelope::from_json(bytes).ok()?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&env.payload)
        .ok()?;
    serde_json::from_slice(&payload).ok()
}

/// The inline input manifest of an envelope made before vci 1.9.0
/// (unverified).
pub(crate) fn envelope_inline_manifest(bytes: &[u8]) -> Option<vci_core::InputManifest> {
    let mut v = envelope_statement(bytes)?;
    serde_json::from_value(v["predicate"]["manifest"].take()).ok()
}

pub(crate) fn envelope_meta(bytes: &[u8]) -> Option<EnvelopeMeta> {
    let v = envelope_statement(bytes)?;
    let p = &v["predicate"];
    let s = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_owned();
    Some(EnvelopeMeta {
        test_id: p["testId"].as_str()?.to_owned(),
        issued_at: parse_rfc3339(p["issuedAt"].as_str()?).ok()?,
        expires_at: parse_rfc3339(p["expiresAt"].as_str()?).ok()?,
        commit: s(&p["commit"]),
        os: s(&p["toolchain"]["os"]),
        arch: s(&p["toolchain"]["arch"]),
        manifest_ref: p["manifestRef"].as_str().map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_printed_without_credentials() {
        assert_eq!(
            redact_userinfo("https://x-access-token:ghs_secret@github.com/o/r.git"),
            "https://***@github.com/o/r.git"
        );
        assert_eq!(
            redact_userinfo("https://github.com/o/r.git"),
            "https://github.com/o/r.git"
        );
        assert_eq!(
            redact_userinfo("git@github.com:o/r.git"),
            "git@github.com:o/r.git"
        );
    }

    /// Every CI snippet `vci init` prints installs a vci pinned to a release tag
    /// (the verifier must not move under a workflow), never a branch head.
    #[test]
    fn ci_snippets_pin_vci_to_a_release() {
        for (name, s) in [
            ("vitest", CI_SNIPPET),
            ("pytest", CI_SNIPPET_PYTEST),
            ("go", CI_SNIPPET_GO),
            ("cargo", CI_SNIPPET_CARGO),
            ("rails", CI_SNIPPET_RAILS),
            ("node-test", CI_SNIPPET_NODE_TEST),
        ] {
            let install: Vec<&str> = s
                .lines()
                .filter(|l| {
                    l.contains("cryptographically-verifiable-ci-runner")
                        && !l.trim_start().starts_with('#')
                })
                .collect();
            assert!(!install.is_empty(), "{name}: no vci install step");
            for l in &install {
                assert!(
                    !l.contains("--depth"),
                    "{name}: shallow clone of a branch: {l}"
                );
                if l.contains("cargo install") {
                    assert!(l.contains("--tag v1.0.0"), "{name}: {l}");
                } else if l.contains("git clone") {
                    // A release tag: `v1` (moved only by scripts/publish-release.sh,
                    // to a commit whose manifest names its own binaries) or `v1.x.y`.
                    assert!(
                        s.contains("--detach v1"),
                        "{name}: clone without a pinned checkout"
                    );
                } else if l.contains("uses:") {
                    assert!(l.contains("@v1"), "{name}: {l}");
                }
            }
        }
    }
}
