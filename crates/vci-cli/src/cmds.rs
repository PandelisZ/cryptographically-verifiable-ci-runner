//! `ci`, `verify`, `init`, `push`, `fetch`, `prune`.

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

pub fn ci(base_ref: Option<String>, audit_log: Option<Utf8PathBuf>) -> Result<i32> {
    let res = plan(&PlanOptions {
        base_ref,
        only: None,
    })?;
    print(&res, "text")?;
    let (repo, root) = open_repo()?;
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
    if res.projects.is_empty() {
        let adapter = vci_adapter::adapter_for("vitest", &root)?;
        jobs.push(("default project".into(), adapter, None, None));
    }
    for (i, p) in res.projects.iter().enumerate() {
        let adapter = vci_adapter::adapter_for_with(&p.adapter, &p.dir, &p.adapter_options)?;
        let env = p.child_env.as_ref().and_then(|c| c.to_child_env());
        let label = if p.name.is_empty() {
            p.path.clone()
        } else {
            p.name.clone()
        };
        let files = if res.run_all.is_some() || p.run_all.is_some() {
            None
        } else {
            Some(
                res.to_run()
                    .filter(|f| f.project_idx == i)
                    .map(|f| f.file.clone())
                    .collect(),
            )
        };
        jobs.push((label, adapter, env, files));
    }
    let mut code: Option<i32> = Some(0);
    let multi = jobs.len() > 1;
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
    let code = code.unwrap_or(1);

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
        "exitCode": code,
    });
    let path = audit_log.unwrap_or_else(|| root.join(format!(".vci/out/audit-{now}.json")));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&log)?)?;
    eprintln!("vci ci: audit log written to {path}");
    Ok(code)
}

pub fn verify(
    envelope_path: &Utf8Path,
    allowed_signers: Option<&Utf8Path>,
    base_ref: Option<&str>,
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
                    let expired = parse_rfc3339(&p.core.expires_at)
                        .map(|e| e <= now)
                        .unwrap_or(true);
                    println!(
                        "  issued {}, expires {}{}",
                        p.core.issued_at,
                        p.core.expires_at,
                        if expired { " (EXPIRED)" } else { "" }
                    );
                    Ok(if expired { 1 } else { 0 })
                }
                Err(e) => {
                    println!("  predicate is not a vci test predicate: {e}");
                    Ok(1)
                }
            }
        }
    }
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
    let vitest: Vec<_> = specs.iter().filter(|s| s.adapter == "vitest").collect();
    if vitest.is_empty() {
        let snippet = if specs.iter().all(|s| s.adapter == "go") {
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
    match AttestStore::new(repo).ensure_remote(meta_url) {
        Ok(name) => eprintln!(
            "vci init: git-meta remote {name:?} configured; `vci push` / `vci fetch` (or `git meta push` / `git meta pull`) exchange attestations on refs/meta/main"
        ),
        Err(e) => eprintln!("vci init: note: could not configure a git-meta remote: {e}"),
    }
    Ok(())
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
fn redact_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let host_end = rest.find('/').unwrap_or(rest.len());
    match rest[..host_end].rfind('@') {
        Some(at) => format!("{scheme}://***@{}", &rest[at + 1..]),
        None => url.to_owned(),
    }
}

pub fn push(remote: Option<&str>) -> Result<i32> {
    let (repo, _) = open_repo()?;
    let store = AttestStore::new(&repo);
    let out = store.push(remote)?;
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
    let store = AttestStore::new(&repo);
    let out = store.fetch(remote)?;
    print_default_remote(&store, remote, &out.remote);
    print_exchange_messages(&out.warnings, &out.notes);
    let n = store.list(None)?.len();
    if out.found {
        eprintln!(
            "vci: fetched git-meta metadata from {} ({n} attestations stored locally)",
            out.remote
        );
    } else {
        eprintln!(
            "vci: {} has no git-meta metadata yet (refs/meta/main); {n} attestations stored locally",
            out.remote
        );
    }
    Ok(0)
}

/// `vci prune`: delete attestations that have expired (git-meta tombstones,
/// published by the next `vci push`). Only the claimed expiry is read; an
/// envelope that cannot be parsed is left alone.
pub fn prune(dry_run: bool) -> Result<i32> {
    let (repo, _) = open_repo()?;
    let store = AttestStore::new(&repo);
    let now = now_unix();
    let (mut expired, mut kept, mut unreadable) = (0usize, 0usize, 0usize);
    for e in store.list(None)? {
        match envelope_expiry(&e.bytes) {
            Some(t) if t <= now => {
                expired += 1;
                if dry_run {
                    println!("would remove {} {}", e.target, e.key);
                } else {
                    store.remove(&e)?;
                    println!("removed {} {}", e.target, e.key);
                }
            }
            Some(_) => kept += 1,
            None => unreadable += 1,
        }
    }
    eprintln!(
        "vci prune: {expired} expired{}, {kept} current, {unreadable} unreadable (left alone)",
        if dry_run { " (dry run)" } else { "" }
    );
    if expired > 0 && !dry_run {
        eprintln!("vci prune: run `vci push` (or `git meta push`) to publish the deletions");
    }
    Ok(0)
}

/// The `expiresAt` an envelope claims (unverified), as Unix seconds.
fn envelope_expiry(bytes: &[u8]) -> Option<i64> {
    use base64::Engine as _;
    let env = Envelope::from_json(bytes).ok()?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&env.payload)
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    parse_rfc3339(v["predicate"]["expiresAt"].as_str()?).ok()
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

    /// Every CI snippet `vci init` prints installs a vci pinned to a commit
    /// (the verifier must not move under a workflow), never a branch head.
    #[test]
    fn ci_snippets_pin_vci_to_a_commit() {
        for (name, s) in [
            ("vitest", CI_SNIPPET),
            ("pytest", CI_SNIPPET_PYTEST),
            ("go", CI_SNIPPET_GO),
            ("cargo", CI_SNIPPET_CARGO),
            ("rails", CI_SNIPPET_RAILS),
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
                    assert!(l.contains("--rev <commit-sha>"), "{name}: {l}");
                } else if l.contains("git clone") {
                    assert!(
                        s.contains("checkout --detach <commit-sha>"),
                        "{name}: clone without a pinned checkout"
                    );
                } else if l.contains("uses:") {
                    assert!(l.contains("@<commit-sha>"), "{name}: {l}");
                }
            }
        }
    }
}
