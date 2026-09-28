//! `ci`, `verify`, `init`, `push`, `fetch`.

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde_json::json;
use vci_adapter::{Adapter, VitestAdapter};
use vci_attest::{AllowedSigners, Envelope, verify_envelope};
use vci_git::AttestStore;

use crate::config::{ALLOWED_SIGNERS_FILE, CONFIG_FILE, TEMPLATE};
use crate::ctx::{VciPredicate, open_repo};
use crate::plan::{PlanOptions, plan, print};
use crate::util::{now_unix, parse_rfc3339, rfc3339};

pub const CI_SNIPPET: &str = include_str!("../../../examples/github-actions.yml");

pub fn ci(base_ref: Option<String>, audit_log: Option<Utf8PathBuf>) -> Result<i32> {
    let res = plan(&PlanOptions {
        base_ref,
        only: None,
    })?;
    print(&res, "text")?;
    let (repo, root) = open_repo()?;
    let project_dir = res.project_dir.clone().unwrap_or_else(|| root.clone());
    let adapter = VitestAdapter::new(&project_dir);
    let env = res.child_env.as_ref().and_then(|c| c.to_child_env());
    let run: Vec<String> = res.to_run().map(|f| f.file.clone()).collect();
    let code = if res.run_all.is_some() {
        eprintln!("vci ci: running all tests");
        adapter.run_plain(&[], &env)?
    } else if run.is_empty() {
        eprintln!("vci ci: every test file is covered by a valid attestation; nothing to run");
        Some(0)
    } else {
        eprintln!("vci ci: running {} test file(s)", run.len());
        adapter.run_plain(&run, &env)?
    };
    let code = code.unwrap_or(1);

    let now = now_unix();
    let log = json!({
        "time": rfc3339(now),
        "head": repo.head_commit().ok(),
        "baseRef": res.base_ref,
        "baseCommit": res.base_commit,
        "runAll": res.run_all,
        "skipped": res.skipped().map(|f| json!({
            "testId": f.test_id,
            "reason": f.reason,
            "by": f.by,
        })).collect::<Vec<_>>(),
        "ran": res.to_run().map(|f| json!({"testId": f.test_id, "reason": f.reason})).collect::<Vec<_>>(),
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
    install: bool,
) -> Result<i32> {
    let (_repo, root) = open_repo()?;
    let cfg_path = root.join(CONFIG_FILE);
    if cfg_path.exists() {
        eprintln!("vci init: {cfg_path} exists, leaving it alone");
    } else {
        let mut text = TEMPLATE.to_owned();
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

    let config = crate::ctx::working_tree_config(&root)?;
    let project_dir = root.join(config.project_rel());
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
    let adapter = VitestAdapter::new(&project_dir);
    if vci_adapter::find_js_plugin(adapter.project_dir()).is_err() {
        eprintln!(
            "vci init: note: @vci/vitest not found; set {} or install it",
            vci_adapter::JS_PLUGIN_ENV
        );
    }
    println!("Commit {CONFIG_FILE} and {ALLOWED_SIGNERS_FILE}. GitHub Actions example:\n");
    println!("{CI_SNIPPET}");
    Ok(0)
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

pub fn push(remote: &str) -> Result<i32> {
    let (repo, _) = open_repo()?;
    AttestStore::new(&repo).push(remote)?;
    eprintln!("vci: pushed attestation refs to {remote}");
    Ok(0)
}

pub fn fetch(remote: &str) -> Result<i32> {
    let (repo, _) = open_repo()?;
    AttestStore::new(&repo).fetch(remote)?;
    let n = AttestStore::new(&repo).list(None)?.len();
    eprintln!("vci: fetched attestation refs from {remote} ({n} envelopes stored locally)");
    Ok(0)
}
