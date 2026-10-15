//! The CI signing key (whose principal `policy.no_skip_refs_except` trusts on
//! main) must never reach a pull request's run: a `pull_request` run uses the
//! branch's own workflow file, so only a GitHub Environment restricted to
//! the default branch keeps the secret from it. Checks this repository's
//! workflow and the documented example (a regression: the demo job passed
//! `secrets.VCI_SIGNING_KEY` to pull request runs).

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_owned()
}

/// The jobs of a workflow (`jobs:` children at two spaces), as (name, body).
fn jobs(yaml: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut in_jobs = false;
    for line in yaml.lines() {
        if line.starts_with("jobs:") {
            in_jobs = true;
            continue;
        }
        if !in_jobs {
            continue;
        }
        if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('#') {
            break;
        }
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if indent == 2 && !trimmed.starts_with('#') && trimmed.ends_with(':') {
            out.push((trimmed.trim_end_matches(':').to_owned(), String::new()));
        } else if let Some((_, body)) = out.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

/// Every job that can see the signing key runs only on pushes to main and
/// takes it from an environment.
fn assert_key_only_on_main(what: &str, yaml: &str) {
    let jobs = jobs(yaml);
    assert!(!jobs.is_empty(), "{what}: no jobs found");
    let mut signing = 0;
    for (name, body) in &jobs {
        let code: String = body
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        if !code.contains("VCI_SIGNING_KEY") && !code.contains("signing-key") {
            continue;
        }
        signing += 1;
        assert!(
            code.lines().any(|l| l.trim()
                == "if: github.event_name == 'push' && github.ref == 'refs/heads/main'"),
            "{what}: job {name} passes the signing key but does not run only on pushes to main"
        );
        assert!(
            code.lines()
                .any(|l| l.trim_start().starts_with("environment:")),
            "{what}: job {name} passes the signing key without an environment (a repository secret reaches pull request runs)"
        );
    }
    assert!(signing > 0, "{what}: no job passes the signing key");
}

#[test]
fn this_repositorys_workflow_gives_the_key_to_main_only() {
    let yaml = std::fs::read_to_string(workspace_root().join(".github/workflows/ci.yml")).unwrap();
    assert_key_only_on_main("ci.yml", &yaml);
    // The pull request job neither signs nor may push.
    let jobs = jobs(&yaml);
    let (_, pr) = jobs.iter().find(|(n, _)| n == "demo").unwrap();
    assert!(!pr.contains("contents: write"), "{pr}");
    assert!(!pr.contains("environment:"), "{pr}");
}

#[test]
fn the_documented_workflow_gives_the_key_to_main_only() {
    let doc = std::fs::read_to_string(workspace_root().join("docs/GITHUB_ACTIONS.md")).unwrap();
    let section = doc
        .split("## Attesting in CI")
        .nth(1)
        .unwrap()
        .split("\n## ")
        .next()
        .unwrap();
    let yaml = section
        .split("```yaml\n")
        .nth(1)
        .and_then(|s| s.split("```").next())
        .unwrap();
    assert_key_only_on_main("docs/GITHUB_ACTIONS.md", yaml);
}

#[test]
fn the_job_parser_finds_a_key_given_to_pull_requests() {
    let bad = "on:\n  pull_request:\njobs:\n  demo:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./\n        with:\n          signing-key: ${{ secrets.VCI_SIGNING_KEY }}\n";
    let r = std::panic::catch_unwind(|| assert_key_only_on_main("bad", bad));
    assert!(r.is_err());
}
