//! CI attests what it runs (`vci ci --key --push`), so the next commit's CI
//! skips every unit whose inputs did not change, on a ref where
//! `policy.no_skip_refs` applies and `policy.no_skip_refs_except` names the
//! CI key's principal.
//!
//! Runs against a copy of `fixtures/vitest-abcd` in throwaway git repos with
//! throwaway SSH keys and a local bare remote. Needs `node`, `git` and
//! `ssh-keygen` on PATH, and the fixture's `node_modules` installed (`npm ci`
//! in fixtures/vitest-abcd).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use assert_cmd::cargo::CommandCargoExt;
use serde_json::Value;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_owned()
}

const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";
const D: &str = "src/d.test.ts";

/// The CI key's principal in allowed_signers.
const CI_PRINCIPAL: &str = "github-actions";
/// A developer's key: trusted, but not on main.
const DEV_PRINCIPAL: &str = "dev@example.com";

const MAIN: &str = "refs/heads/main";

fn vci_toml(except: &[&str]) -> String {
    format!(
        r#"project = "."

[policy]
platform = "any"
max_ttl = "30d"
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
no_skip_refs_except = [{}]

[env]
hash = ["NODE_ENV"]
"#,
        except
            .iter()
            .map(|p| format!("{p:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Two Vitest projects, p1 and p2 (copies of the fixture).
fn vci_toml_multi() -> String {
    r#"[policy]
platform = "any"
max_ttl = "30d"
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
no_skip_refs_except = ["github-actions"]

[env]
hash = ["NODE_ENV"]

[[projects]]
name = "p1"
path = "p1"
adapter = "vitest"

[[projects]]
name = "p2"
path = "p2"
adapter = "vitest"
"#
    .to_owned()
}

/// The projects of a multi-project world.
const PROJECTS: [&str; 2] = ["p1", "p2"];

fn keygen(path: &Path, comment: &str) {
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(path)
        .status()
        .unwrap();
    assert!(st.success());
}

fn pubkey(path: &Path) -> String {
    let t = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    t.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

fn cp(from: &Path, to: &Path) {
    let st = Command::new("cp")
        .arg("-R")
        .arg(from)
        .arg(to)
        .status()
        .unwrap();
    assert!(st.success());
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' && it.peek() == Some(&'[') {
            for d in it.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

struct World {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    /// The developer's clone (pushes commits to main).
    dev: PathBuf,
    remote: PathBuf,
    ci_key: PathBuf,
    dev_key: PathBuf,
    gitconfig: PathBuf,
    /// p1 and p2 instead of one project at the root. Only p1 has the JS
    /// collector installed (node_modules/@vci/vitest); VCI_JS_PLUGIN is not
    /// set, so p2's run with the collectors fails while its listing works.
    multi: bool,
}

#[derive(Debug)]
struct Plan {
    skip: BTreeSet<String>,
    run: BTreeSet<String>,
    run_all: Option<String>,
    reasons: Vec<(String, String)>,
}

impl Plan {
    fn reason(&self, id: &str) -> &str {
        self.reasons
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, r)| r.as_str())
            .unwrap_or_default()
    }
}

struct Ci {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    log: Value,
}

impl Ci {
    fn attested(&self) -> BTreeSet<String> {
        ids(&self.log["attested"])
    }
}

fn ids(v: &Value) -> BTreeSet<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s["testId"].as_str().unwrap().to_owned())
        .collect()
}

impl World {
    fn new() -> Self {
        Self::build(false)
    }

    fn build(multi: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let keys = base.join("keys");
        std::fs::create_dir(&keys).unwrap();
        let gitconfig = base.join("gitconfig");
        std::fs::write(
            &gitconfig,
            "[user]\n\tname = Test\n\temail = test@example.com\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n",
        )
        .unwrap();
        let w = World {
            dev: base.join("dev"),
            remote: base.join("remote.git"),
            ci_key: keys.join("ci"),
            dev_key: keys.join("dev"),
            gitconfig,
            base,
            _tmp: tmp,
            multi,
        };
        keygen(&w.ci_key, "vci-github-actions");
        keygen(&w.dev_key, "dev");
        w.git(&w.base, &["init", "-q", "--bare", "remote.git"]);

        // Commit A on main.
        let dir = &w.dev;
        let fx = workspace_root().join("fixtures/vitest-abcd");
        w.git(&w.base, &["init", "-q", dir.to_str().unwrap()]);
        let project_dirs: Vec<PathBuf> = if multi {
            PROJECTS.iter().map(|p| dir.join(p)).collect()
        } else {
            vec![dir.clone()]
        };
        for pd in &project_dirs {
            std::fs::create_dir_all(pd).unwrap();
            for name in [
                "src",
                "fixtures",
                "package.json",
                "package-lock.json",
                "vitest.config.ts",
            ] {
                cp(&fx.join(name), &pd.join(name));
            }
        }
        w.install_node_modules(dir);
        std::fs::write(dir.join("README.md"), "# fixture\n").unwrap();
        std::fs::write(dir.join(".gitignore"), "node_modules/\n.vci/out/\n").unwrap();
        std::fs::write(
            dir.join("vci.toml"),
            if multi {
                vci_toml_multi()
            } else {
                vci_toml(&[CI_PRINCIPAL])
            },
        )
        .unwrap();
        std::fs::create_dir_all(dir.join(".vci")).unwrap();
        std::fs::write(
            dir.join(".vci/allowed_signers"),
            format!(
                "{DEV_PRINCIPAL} namespaces=\"vci-attest\" {}\n{CI_PRINCIPAL} namespaces=\"vci-attest\" {}\n",
                pubkey(&w.dev_key),
                pubkey(&w.ci_key),
            ),
        )
        .unwrap();
        w.git(dir, &["add", "-A"]);
        w.git(dir, &["commit", "-q", "-m", "commit A"]);
        w.git(
            dir,
            &["remote", "add", "origin", w.remote.to_str().unwrap()],
        );
        w.git(dir, &["push", "-q", "origin", "main"]);
        w
    }

    fn install_node_modules(&self, dir: &Path) {
        let from = workspace_root().join("fixtures/vitest-abcd/node_modules");
        if !self.multi {
            cp(&from, &dir.join("node_modules"));
            return;
        }
        for p in PROJECTS {
            cp(&from, &dir.join(p).join("node_modules"));
        }
        // The collector, installed in p1 only.
        let vci = dir.join("p1/node_modules/@vci");
        std::fs::create_dir_all(&vci).unwrap();
        std::os::unix::fs::symlink(
            workspace_root().join("js/vitest-plugin"),
            vci.join("vitest"),
        )
        .unwrap();
    }

    fn git(&self, dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// Commit a change on main in the developer's clone and push it.
    fn commit_on_main(&self, rel: &str, content: &str, message: &str) {
        std::fs::write(self.dev.join(rel), content).unwrap();
        self.git(&self.dev, &["add", "-A"]);
        self.git(&self.dev, &["commit", "-q", "-m", message]);
        self.git(&self.dev, &["push", "-q", "origin", "main"]);
    }

    /// A fresh clone of the remote's main, as a CI runner checks it out.
    fn ci_clone(&self, name: &str) -> PathBuf {
        let dir = self.base.join(name);
        self.git(
            &self.base,
            &[
                "clone",
                "-q",
                self.remote.to_str().unwrap(),
                dir.to_str().unwrap(),
            ],
        );
        self.install_node_modules(&dir);
        dir
    }

    /// `vci` in `dir` with `GITHUB_REF` set to `git_ref` (as on a runner).
    fn vci(&self, dir: &Path, git_ref: &str, args: &[&str]) -> Output {
        let mut cmd = Command::cargo_bin("vci").unwrap();
        cmd.current_dir(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("NO_COLOR", "1");
        for k in [
            "VCI_BASE_REF",
            "GITHUB_BASE_REF",
            "GITHUB_OUTPUT",
            "VCI_SIGNING_KEY",
            "VCI_OUT",
            "NODE_OPTIONS",
        ] {
            cmd.env_remove(k);
        }
        if self.multi {
            cmd.env_remove("VCI_JS_PLUGIN");
        } else {
            cmd.env("VCI_JS_PLUGIN", workspace_root().join("js/vitest-plugin"));
        }
        cmd.env("GITHUB_REF", git_ref);
        let out = cmd.output().unwrap();
        eprintln!(
            "$ GITHUB_REF={git_ref} vci {}\n{}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    fn vci_ok(&self, dir: &Path, git_ref: &str, args: &[&str]) -> String {
        let out = self.vci(dir, git_ref, args);
        assert!(
            out.status.success(),
            "vci {args:?} exited {:?}",
            out.status.code()
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn plan(&self, dir: &Path, git_ref: &str) -> Plan {
        let out = self.vci_ok(
            dir,
            git_ref,
            &["plan", "--base-ref", "HEAD", "--format", "json"],
        );
        let v: Value = serde_json::from_str(&out).unwrap();
        let mut p = Plan {
            skip: BTreeSet::new(),
            run: BTreeSet::new(),
            run_all: v["runAll"].as_str().map(str::to_owned),
            reasons: vec![],
        };
        for f in v["files"].as_array().unwrap() {
            let id = f["testId"].as_str().unwrap().to_owned();
            p.reasons
                .push((id.clone(), f["reason"].as_str().unwrap().to_owned()));
            if f["skip"].as_bool().unwrap() {
                p.skip.insert(id);
            } else {
                p.run.insert(id);
            }
        }
        p
    }

    /// `vci ci --base-ref HEAD --key <ci key>` (the action on a push to
    /// main: the base is the pushed commit) plus `extra`.
    fn ci(&self, dir: &Path, name: &str, extra: &[&str]) -> Ci {
        self.ci_at(dir, name, MAIN, "HEAD", &self.ci_key, extra)
    }

    /// `vci ci --base-ref <base> --key <key>` with `GITHUB_REF=<git_ref>`.
    fn ci_at(
        &self,
        dir: &Path,
        name: &str,
        git_ref: &str,
        base: &str,
        key: &Path,
        extra: &[&str],
    ) -> Ci {
        let audit = self.base.join(format!("audit-{name}.json"));
        let mut args = vec![
            "ci",
            "--base-ref",
            base,
            "--audit-log",
            audit.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        let out = self.vci(dir, git_ref, &args);
        Ci {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: strip_ansi(&String::from_utf8_lossy(&out.stderr)),
            log: serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap(),
        }
    }

    /// The principals of the attestations a fresh clone fetches from the
    /// remote's refs/meta/main, by unit (`vci plan` on a feature branch,
    /// where no_skip_refs does not apply).
    fn published(&self, name: &str) -> BTreeSet<String> {
        let dir = self.ci_clone(name);
        self.git(&dir, &["checkout", "-q", "-b", "feature"]);
        self.vci_ok(&dir, "refs/heads/feature", &["fetch", "--remote", "origin"]);
        self.plan(&dir, "refs/heads/feature").skip
    }

    fn remote_has_meta(&self) -> bool {
        Command::new("git")
            .arg("--git-dir")
            .arg(&self.remote)
            .args(["rev-parse", "-q", "--verify", "refs/meta/main"])
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap()
            .status
            .success()
    }
}

/// a-c: commit A attests everything on main and publishes it; commit B
/// (one source file) runs only its unit; commit C (README only) runs nothing.
#[test]
fn ci_attests_on_main_and_the_next_commit_skips_what_did_not_change() {
    let w = World::new();
    let all = set(&[A, B, C, D]);

    // a. Commit A, nothing attested anywhere: everything runs, every unit
    // is attested by the CI key and pushed to the remote.
    let ci_a = w.ci_clone("ci-a");
    w.vci_ok(&ci_a, MAIN, &["fetch", "--remote", "origin"]);
    let p = w.plan(&ci_a, MAIN);
    assert_eq!(p.run, all, "{p:?}");
    assert!(p.run_all.is_none(), "{p:?}");
    assert!(!w.remote_has_meta());
    let r = w.ci(&ci_a, "a", &["--push", "--remote", "origin"]);
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(r.stderr.contains("running 4 test file(s)"), "{}", r.stderr);
    assert!(
        r.stderr.contains("Test Files  4 passed (4)"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("vci: pushed git-meta"), "{}", r.stderr);
    assert_eq!(r.attested(), all, "{}", r.stderr);
    assert_eq!(r.log["pushed"], true);
    assert_eq!(r.log["exitCode"], 0);
    assert_eq!(ids(&r.log["ran"]), all);
    assert!(w.remote_has_meta(), "refs/meta/main was pushed");
    assert_eq!(w.published("check-a"), all);

    // b. Commit B changes src/b.ts, which only B imports: a fresh CI clone
    // skips A, C and D on main (attested by the CI key) and runs B.
    w.commit_on_main(
        "src/b.ts",
        "import { readFileSync } from \"node:fs\";\n\n// commit B\nexport const loadGreeting = (path: string): string =>\n  JSON.parse(readFileSync(path, \"utf8\")).greeting;\n",
        "commit B",
    );
    let ci_b = w.ci_clone("ci-b");
    w.vci_ok(&ci_b, MAIN, &["fetch", "--remote", "origin"]);
    let p = w.plan(&ci_b, MAIN);
    assert_eq!(p.skip, set(&[A, C, D]), "{p:?}");
    assert_eq!(p.run, set(&[B]), "{p:?}");
    assert!(
        p.reason(A).contains(&format!("attested by {CI_PRINCIPAL}")),
        "{p:?}"
    );
    let r = w.ci(&ci_b, "b", &["--push", "--remote", "origin"]);
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(r.stderr.contains("running 1 test file(s)"), "{}", r.stderr);
    assert_eq!(r.attested(), set(&[B]), "{}", r.stderr);
    assert_eq!(ids(&r.log["skipped"]), set(&[A, C, D]));
    assert_eq!(r.log["pushed"], true);

    // c. Commit C changes only the README, which no test reads: everything
    // is skipped and the test runner is not started.
    w.commit_on_main("README.md", "# fixture\n\nMore words.\n", "commit C");
    let ci_c = w.ci_clone("ci-c");
    w.vci_ok(&ci_c, MAIN, &["fetch", "--remote", "origin"]);
    let p = w.plan(&ci_c, MAIN);
    assert_eq!(p.skip, all, "{p:?}");
    let r = w.ci(&ci_c, "c", &[]);
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stderr
            .contains("every test file is covered by a valid attestation; nothing to run"),
        "{}",
        r.stderr
    );
    assert!(
        !r.stderr.contains("Test Files"),
        "runner started: {}",
        r.stderr
    );
    assert!(!r.stderr.contains("vci ci: running"), "{}", r.stderr);
    assert!(r.attested().is_empty());
    assert!(r.log["pushed"].is_null(), "no --push");
    assert!(ids(&r.log["ran"]).is_empty());
}

/// d-e: a trusted signer outside no_skip_refs_except does not skip on main
/// (explain names the signer and the policy key), with the list empty main
/// runs everything as before, and a failed push is a warning only.
#[test]
fn other_signers_run_on_main_and_a_failed_push_is_only_a_warning() {
    let w = World::new();

    // A developer attests A and B from their own clone and publishes.
    for f in [A, B] {
        w.vci_ok(
            &w.dev,
            "refs/heads/dev",
            &["run", f, "--key", w.dev_key.to_str().unwrap()],
        );
    }
    w.vci_ok(&w.dev, "refs/heads/dev", &["push", "--remote", "origin"]);

    let ci = w.ci_clone("ci");
    w.vci_ok(&ci, MAIN, &["fetch", "--remote", "origin"]);
    // Off main the developer's attestations skip.
    w.git(&ci, &["checkout", "-q", "-b", "feature"]);
    let p = w.plan(&ci, "refs/heads/feature");
    assert_eq!(p.skip, set(&[A, B]), "{p:?}");
    w.git(&ci, &["checkout", "-q", "main"]);
    // On main they do not: only no_skip_refs_except's principals skip.
    let p = w.plan(&ci, MAIN);
    assert!(p.skip.is_empty(), "{p:?}");
    assert!(p.run_all.is_none(), "{p:?}");
    let why = format!(
        "policy.no_skip_refs matches {MAIN} and signer {DEV_PRINCIPAL} is not in no_skip_refs_except"
    );
    assert!(p.reason(A).contains(&why), "{p:?}");
    let ex = w.vci_ok(&ci, MAIN, &["explain", A, "--base-ref", "HEAD"]);
    assert!(ex.contains("failed check: signer"), "{ex}");
    assert!(ex.contains(&why), "{ex}");
    assert!(ex.contains(&format!("signer: {DEV_PRINCIPAL}")), "{ex}");

    // e. Pushing to a remote that does not exist (a clone whose first
    // git-meta remote is that URL): a GitHub warning, and the exit code is
    // the tests' (they passed).
    let ci_e = w.ci_clone("ci-e");
    let missing = w.base.join("missing/remote.git");
    let r = w.ci(
        &ci_e,
        "e",
        &["--push", "--remote", missing.to_str().unwrap()],
    );
    assert_eq!(r.code, Some(0), "{}{}", r.stdout, r.stderr);
    assert!(
        r.stdout
            .contains("::warning title=vci::could not push attestations to"),
        "{}",
        r.stdout
    );
    assert_eq!(r.log["pushed"], false);
    assert_eq!(r.log["exitCode"], 0);
    assert_eq!(r.attested(), set(&[A, B, C, D]), "{}", r.stderr);
    assert_eq!(
        w.published("check-e"),
        set(&[A, B]),
        "nothing new published"
    );

    // With no_skip_refs_except empty, main runs everything (the old rule),
    // whoever attested.
    std::fs::write(ci.join("vci.toml"), vci_toml(&[])).unwrap();
    w.git(&ci, &["commit", "-q", "-am", "no exceptions"]);
    let p = w.plan(&ci, MAIN);
    assert_eq!(
        p.run_all.as_deref(),
        Some("policy.no_skip_refs matches refs/heads/main"),
        "{p:?}"
    );
    assert!(p.skip.is_empty(), "{p:?}");
    let ex = w.vci_ok(&ci, MAIN, &["explain", A, "--base-ref", "HEAD"]);
    assert!(
        ex.contains("RUN, running everything: policy.no_skip_refs matches refs/heads/main"),
        "{ex}"
    );
    // run_all with --key attests every unit: the run the next commit reuses.
    let r = w.ci(&ci, "run-all", &[]);
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(r.stderr.contains("running all tests"), "{}", r.stderr);
    assert_eq!(r.attested(), set(&[A, B, C, D]), "{}", r.stderr);
}

/// A failing test still fails CI with --key; the units that passed are
/// attested and published.
#[test]
fn a_failing_test_fails_ci_and_the_rest_is_attested() {
    let w = World::new();
    w.commit_on_main(
        "src/a.test.ts",
        "import { expect, test } from \"vitest\";\nimport { add } from \"./a\";\n\ntest(\"add\", () => {\n  expect(add(1, 2)).toBe(4);\n});\n",
        "break A",
    );
    let ci = w.ci_clone("ci");
    let r = w.ci(&ci, "fail", &["--push", "--remote", "origin"]);
    assert_ne!(r.code, Some(0), "{}", r.stderr);
    assert_eq!(r.attested(), set(&[B, C, D]), "{}", r.stderr);
    assert_eq!(r.log["pushed"], true);
    assert_eq!(w.published("check"), set(&[B, C, D]));
}

/// Without --key, `vci ci` neither attests nor pushes, and --push needs --key.
#[test]
fn ci_without_a_key_attests_nothing() {
    let w = World::new();
    let ci = w.ci_clone("ci");
    let audit = w.base.join("audit.json");
    let out = w.vci(
        &ci,
        MAIN,
        &[
            "ci",
            "--base-ref",
            "HEAD",
            "--audit-log",
            audit.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    let log: Value = serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
    assert!(log["attested"].as_array().unwrap().is_empty());
    assert!(log["pushed"].is_null());
    let repo = vci_git::Repo::discover(camino::Utf8Path::from_path(&ci).unwrap()).unwrap();
    assert!(
        vci_git::AttestStore::new(&repo)
            .list(None)
            .unwrap_or_default()
            .is_empty()
    );
    let out = w.vci(&ci, MAIN, &["ci", "--push"]);
    assert_eq!(out.status.code(), Some(2), "clap usage error");
}

/// A pull request's run (here a branch of the repository, as with
/// `GITHUB_REF=refs/pull/1/merge`) that is handed the main-trusted CI key
/// attests nothing and pushes nothing, so after the merge main still runs the
/// unit only the pull request ran (regression: it was attested, pushed, and
/// skipped on main). A key whose principal is not in no_skip_refs_except
/// still attests there, and main does not skip on its word.
#[test]
fn a_pull_request_run_with_the_main_key_attests_nothing() {
    let w = World::new();
    let all = set(&[A, B, C, D]);
    let main_a = w.git(&w.dev, &["rev-parse", "HEAD"]);

    // Main's CI on commit A attests everything and publishes it.
    let ci_a = w.ci_clone("ci-a");
    let r = w.ci(&ci_a, "a", &["--push", "--remote", "origin"]);
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert_eq!(r.attested(), all, "{}", r.stderr);

    // Branch pr1 changes src/b.ts (only B imports it).
    w.git(&w.dev, &["checkout", "-q", "-b", "pr1"]);
    std::fs::write(
        w.dev.join("src/b.ts"),
        "import { readFileSync } from \"node:fs\";\n\n// pr1\nexport const loadGreeting = (path: string): string =>\n  JSON.parse(readFileSync(path, \"utf8\")).greeting;\n",
    )
    .unwrap();
    w.git(&w.dev, &["commit", "-q", "-am", "pr1"]);
    w.git(&w.dev, &["push", "-q", "origin", "pr1"]);
    let pr = w.ci_clone("ci-pr");
    w.git(&pr, &["checkout", "-q", "pr1"]);
    w.vci_ok(&pr, "refs/pull/1/merge", &["fetch", "--remote", "origin"]);

    // The pull request's CI with the main key: B runs, nothing is attested
    // or pushed, and the job says why.
    let r = w.ci_at(
        &pr,
        "pr-ci-key",
        "refs/pull/1/merge",
        &main_a,
        &w.ci_key,
        &["--push", "--remote", "origin"],
    );
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stderr.contains("Test Files  1 passed (1)"),
        "{}",
        r.stderr
    );
    assert!(r.attested().is_empty(), "{}", r.stderr);
    assert!(
        r.stdout
            .contains("::warning title=vci::not attesting: the key signs as github-actions"),
        "{}",
        r.stdout
    );
    assert!(
        r.log["notAttested"]
            .as_str()
            .unwrap()
            .contains("does not match policy.no_skip_refs"),
        "{}",
        r.log
    );
    assert!(r.log["pushed"].is_null(), "nothing pushed: {}", r.log);
    let repo = vci_git::Repo::discover(camino::Utf8Path::from_path(&pr).unwrap()).unwrap();
    let local = vci_git::AttestStore::new(&repo)
        .list(None)
        .unwrap_or_default();
    assert_eq!(local.len(), 4, "only commit A's attestations: {local:?}");

    // A pull request key (trusted, not in no_skip_refs_except) attests B
    // there and publishes it.
    let r = w.ci_at(
        &pr,
        "pr-dev-key",
        "refs/pull/1/merge",
        &main_a,
        &w.dev_key,
        &["--push", "--remote", "origin"],
    );
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert_eq!(r.attested(), set(&[B]), "{}", r.stderr);
    assert_eq!(r.log["pushed"], true);

    // Merge pr1 into main: main runs B (only the pull request ran it, and
    // its signer is not in no_skip_refs_except) and skips the rest.
    w.git(&w.dev, &["checkout", "-q", "main"]);
    w.git(&w.dev, &["merge", "-q", "--ff-only", "pr1"]);
    w.git(&w.dev, &["push", "-q", "origin", "main"]);
    let ci_m = w.ci_clone("ci-merged");
    w.vci_ok(&ci_m, MAIN, &["fetch", "--remote", "origin"]);
    let p = w.plan(&ci_m, MAIN);
    assert_eq!(p.run, set(&[B]), "{p:?}");
    assert_eq!(p.skip, set(&[A, C, D]), "{p:?}");
    // Off main, the pull request key's attestation of B does skip.
    w.git(&ci_m, &["checkout", "-q", "-b", "feature"]);
    let p = w.plan(&ci_m, "refs/heads/feature");
    assert_eq!(p.skip, all, "{p:?}");
    assert!(
        p.reason(B)
            .contains(&format!("attested by {DEV_PRINCIPAL}")),
        "{p:?}"
    );
}

/// One project whose run with the collectors fails (p2: the JS collector is
/// not installed) does not throw away the other's attested run: p1 runs once
/// (its failing test fails CI, not hidden by a second run), its attestations
/// are in the audit log and published, and p2 alone runs without attesting.
/// Regression: the whole plan ran again without attesting, the exit code was
/// the second run's, and the audit log said nothing was attested although
/// p1's attestations were stored and pushed.
#[test]
fn a_project_that_cannot_run_attested_runs_alone_and_the_rest_is_kept() {
    let w = World::build(true);
    // p1/src/f.test.ts fails on its first run only.
    let marker = w.base.join("flaky-ran-once");
    w.commit_on_main(
        "p1/src/f.test.ts",
        &format!(
            "import {{ existsSync, writeFileSync }} from \"node:fs\";\nimport {{ expect, test }} from \"vitest\";\n\ntest(\"flaky\", () => {{\n  const m = {:?};\n  const before = existsSync(m);\n  writeFileSync(m, \"x\");\n  expect(before).toBe(true);\n}});\n",
            marker.to_str().unwrap()
        ),
        "flaky test",
    );
    let ci = w.ci_clone("ci");
    let r = w.ci(&ci, "multi", &["--push", "--remote", "origin"]);
    let p1 = set(&[
        "p1/src/a.test.ts",
        "p1/src/b.test.ts",
        "p1/src/c.test.ts",
        "p1/src/d.test.ts",
    ]);
    assert_ne!(r.code, Some(0), "the flaky failure counts: {}", r.stderr);
    assert_eq!(r.log["exitCode"], r.code.unwrap());
    assert_eq!(
        r.stderr.matches("Test Files ").count(),
        2,
        "p1 once with the collectors, p2 once without: {}",
        r.stderr
    );
    assert!(
        r.stderr
            .contains("vci ci: running all tests of p2 (vitest)")
            || r.stderr
                .contains("vci ci: running 4 test file(s) of p2 (vitest)"),
        "{}",
        r.stderr
    );
    assert_eq!(r.attested(), p1, "{}", r.stderr);
    let errors = r.log["attestErrors"].as_array().unwrap();
    assert_eq!(errors.len(), 1, "{}", r.log);
    assert!(errors[0].as_str().unwrap().contains("p2"), "{}", r.log);
    assert!(
        r.stdout
            .contains("::warning title=vci::attesting: running the tests of p2"),
        "{}",
        r.stdout
    );
    assert!(r.log["notAttested"].is_null());
    assert_eq!(r.log["pushed"], true);
    assert_eq!(w.published("check"), p1);
}

/// `vci ci --fetch` and `vci plan --fetch` fetch the attestations themselves
/// (what the action's separate `vci fetch` step did), while the projects are
/// probed: a fresh clone skips what main attested. A remote that cannot be
/// fetched is a warning, never a failure: only attestations already stored
/// locally are used (none in a fresh clone, so everything runs).
#[test]
fn fetch_while_planning_and_fail_open() {
    let w = World::new();
    let all = set(&[A, B, C, D]);
    let ci_a = w.ci_clone("fetch-a");
    let r = w.ci(
        &ci_a,
        "fetch-a",
        &["--fetch", "origin", "--push", "--remote", "origin"],
    );
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stderr.contains("has no git-meta metadata yet"),
        "fetched before anything was published: {}",
        r.stderr
    );
    assert_eq!(r.attested(), all, "{}", r.stderr);

    // A fresh clone: `vci ci --fetch` (bare: the default remote, origin's
    // URL from .git-meta or origin) skips everything, as fetch + ci did.
    let ci_b = w.ci_clone("fetch-b");
    let r = w.ci(&ci_b, "fetch-b", &["--fetch"]);
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stderr.contains("vci: fetched git-meta metadata from "),
        "{}",
        r.stderr
    );
    assert_eq!(ids(&r.log["skipped"]), all, "{}", r.stderr);
    assert!(ids(&r.log["ran"]).is_empty());
    assert!(r.stdout.contains("4 to skip, 0 to run"), "{}", r.stdout);

    // `vci plan --fetch REMOTE`, JSON on stdout.
    let ci_c = w.ci_clone("fetch-c");
    let out = w.vci_ok(
        &ci_c,
        MAIN,
        &[
            "plan",
            "--fetch",
            "origin",
            "--base-ref",
            "HEAD",
            "--format",
            "json",
        ],
    );
    let v: Value = serde_json::from_str(&out).unwrap();
    let skipped: BTreeSet<String> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["skip"] == true)
        .map(|f| f["testId"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(skipped, all);

    // An unreachable remote: a warning (stderr, an annotation on stdout,
    // the audit log), and the plan goes on with what is stored locally.
    let ci_d = w.ci_clone("fetch-d");
    let missing = w.base.join("no-such-remote.git");
    let missing = missing.to_str().unwrap();
    let out = w.vci(
        &ci_d,
        MAIN,
        &[
            "plan",
            "--fetch",
            missing,
            "--base-ref",
            "HEAD",
            "--format",
            "json",
        ],
    );
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!(
            "vci: warning: could not fetch attestations from {missing}: "
        )),
        "{stderr}"
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("stdout stays JSON");
    assert!(
        v["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["skip"] == false)
    );
    let r = w.ci_at(
        &ci_d,
        "fetch-d",
        MAIN,
        "HEAD",
        &w.ci_key,
        &["--fetch", missing],
    );
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stdout
            .contains("::warning title=vci::could not fetch attestations from "),
        "{}",
        r.stdout
    );
    assert!(
        r.log["warnings"].as_array().unwrap().iter().any(|w| w
            .as_str()
            .unwrap()
            .starts_with("could not fetch attestations")),
        "{}",
        r.log
    );
    assert_eq!(ids(&r.log["ran"]), all);
}
