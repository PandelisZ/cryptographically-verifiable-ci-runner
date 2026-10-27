//! Choosing the attestation store, end to end (docs/STORE-BACKENDS.md
//! section 9): `VCI_STORE`, `VCI_STORE_URL` and `[store]` in the working
//! tree's `vci.toml` select it; a store that cannot be selected or opened
//! fails open (plans run everything, runs refuse to store, the commands
//! that manage the store exit 2); and a store's secrets reach no test
//! process and no output.
//!
//! A copy of `fixtures/go-abcd` in a throwaway git repository, plus a Go
//! package whose test writes its environment to a file outside the
//! repository. Needs `go`, `git` and `ssh-keygen` on PATH; every test
//! prints `SKIPPED:` and returns early when `go` is not installed or cannot
//! download the fixture's modules.

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

fn go_available() -> bool {
    match Command::new("go").arg("version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!(
                "SKIPPED: `go` is not installed; the store selection tests need the Go toolchain on PATH"
            );
            false
        }
    }
}

const VCI_TOML: &str = r#"project = "."
adapter = "go"

[policy]
platform = "any"
max_ttl = "30d"
no_skip_refs = ["refs/heads/release/*"]
"#;

/// Variables removed from every `vci` and `go` invocation so the host
/// environment cannot change the outcome (the store's own are added from
/// [`vci_store::select::ENV_VARS`]).
const SCRUB: &[&str] = &[
    "VCI_E2E_BIN",
    "VCI_BASE_REF",
    "GITHUB_BASE_REF",
    "GITHUB_REF",
    "GITHUB_OUTPUT",
    "GITHUB_ACTIONS",
    "VCI_SIGNING_KEY",
    "VCI_GO",
    "VCI_JOBS",
    "VCI_GO_TESTLOG",
    "VCI_TIMING",
    "GOFLAGS",
    "GOWORK",
    "GOOS",
    "GOARCH",
    "CGO_ENABLED",
    "GOEXPERIMENT",
    "GODEBUG",
    "GOTOOLCHAIN",
    "NODE_OPTIONS",
    "CI",
    "GOMAXPROCS",
];

/// The fixture's packages, plus the one that dumps its environment.
const UNITS: &[&str] = &["a", "b", "c", "d", "envdump"];

/// The units a run attests (the envdump package writes outside the
/// repository, which may refuse it).
const ATTESTABLE: &[&str] = &["a", "b", "c", "d"];

/// A password planted in a URL: it must appear in no output.
const SECRET: &str = "s3cret";
const URL: &str = "postgres://u:s3cret@127.0.0.1:1/x";

struct World {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    work: PathBuf,
    remote: PathBuf,
    key: PathBuf,
    gitconfig: PathBuf,
    /// Where the envdump package's test writes its environment.
    dump: PathBuf,
    metrics: PathBuf,
}

fn keygen(path: &Path) {
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "trusted", "-f"])
        .arg(path)
        .status()
        .unwrap();
    assert!(st.success());
}

fn pubkey(path: &Path) -> String {
    let t = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    t.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

fn go(dir: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new("go");
    cmd.args(args).current_dir(dir);
    for k in SCRUB.iter().chain(vci_store::select::ENV_VARS) {
        cmd.env_remove(k);
    }
    cmd.output().unwrap()
}

/// A test that writes `os.Getenv("VCI_STORE_URL")` and its whole
/// environment to `dump`.
fn envdump_test(dump: &Path) -> String {
    format!(
        r#"package envdump

import (
	"os"
	"strings"
	"testing"
)

func TestDumpEnvironment(t *testing.T) {{
	text := "getenv:" + os.Getenv("VCI_STORE_URL") + "\n" + strings.Join(os.Environ(), "\n") + "\n"
	if err := os.WriteFile({dump:?}, []byte(text), 0o644); err != nil {{
		t.Fatal(err)
	}}
}}
"#,
        dump = dump.to_str().unwrap()
    )
}

impl World {
    /// `None` (test skipped) when go is unavailable.
    fn new() -> Option<Self> {
        if !go_available() {
            return None;
        }
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let gitconfig = base.join("gitconfig");
        std::fs::write(
            &gitconfig,
            "[user]\n\tname = Test\n\temail = test@example.com\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n",
        )
        .unwrap();
        let w = World {
            work: base.join("work"),
            remote: base.join("remote.git"),
            key: base.join("trusted"),
            dump: base.join("env-dump.txt"),
            metrics: base.join("metrics.jsonl"),
            gitconfig,
            base,
            _tmp: tmp,
        };
        keygen(&w.key);
        w.git(&w.base, &["init", "-q", "--bare", "remote.git"]);
        w.git(&w.base, &["init", "-q", w.work.to_str().unwrap()]);
        let fx = workspace_root().join("fixtures/go-abcd");
        for name in ["go.mod", "go.sum", "a", "b", "c", "d", "internal"] {
            let st = Command::new("cp")
                .arg("-R")
                .arg(fx.join(name))
                .arg(w.work.join(name))
                .status()
                .unwrap();
            assert!(st.success());
        }
        w.put("envdump/envdump_test.go", &envdump_test(&w.dump));
        w.put(".gitignore", ".vci/out/\n");
        w.put("vci.toml", VCI_TOML);
        w.put(
            ".vci/allowed_signers",
            &format!(
                "trusted@example.com namespaces=\"vci-attest\" {}\n",
                pubkey(&w.key)
            ),
        );
        w.git(&w.work, &["add", "-A"]);
        w.git(&w.work, &["commit", "-q", "-m", "base commit"]);
        w.git(
            &w.work,
            &["remote", "add", "origin", w.remote.to_str().unwrap()],
        );
        w.git(&w.work, &["push", "-q", "origin", "main"]);
        w.git(&w.work, &["checkout", "-q", "-b", "feature"]);
        let out = go(&w.work, &["mod", "download"]);
        if !out.status.success() {
            eprintln!(
                "SKIPPED: `go mod download` failed for the Go fixture (offline without a module cache?): {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return None;
        }
        Some(w)
    }

    fn put(&self, rel: &str, content: &str) {
        let p = self.work.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
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

    /// Commit the working tree's `vci.toml` as `text` on the branch.
    fn commit_vci_toml(&self, text: &str) {
        self.put("vci.toml", text);
        self.git(&self.work, &["commit", "-q", "-am", "vci.toml"]);
    }

    /// `vci <args>` in the repository, with `env` added to a scrubbed
    /// environment (metrics go to the world's own log).
    fn vci(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::cargo_bin("vci").unwrap();
        cmd.current_dir(&self.work)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("NO_COLOR", "1")
            .env("VCI_METRICS", &self.metrics);
        for k in SCRUB.iter().chain(vci_store::select::ENV_VARS) {
            cmd.env_remove(k);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        eprintln!(
            "$ vci {} {env:?} -> {:?}\n{}{}",
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// `vci run --key` of every unit, with `env`.
    fn run(&self, env: &[(&str, &str)]) -> Output {
        let key = self.key.to_str().unwrap().to_owned();
        self.vci(&["run", "--key", &key], env)
    }

    /// `vci plan` as JSON: the units skipped and run, and the warnings.
    fn plan(&self, env: &[(&str, &str)]) -> (Plan, Output) {
        let out = self.vci(&["plan", "--base-ref", "main", "--format", "json"], env);
        assert_eq!(out.status.code(), Some(0), "vci plan fails open");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        let mut p = Plan::default();
        for f in v["files"].as_array().unwrap() {
            let id = f["testId"].as_str().unwrap().to_owned();
            if f["skip"].as_bool().unwrap() {
                p.skip.insert(id);
            } else {
                p.run.insert(id);
            }
        }
        p.warnings = v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap().to_owned())
            .collect();
        (p, out)
    }
}

#[derive(Debug, Default)]
struct Plan {
    skip: BTreeSet<String>,
    run: BTreeSet<String>,
    warnings: Vec<String>,
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| (*s).to_owned()).collect()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Every unit attested and stored in git-meta, so that a plan that can
/// read the store skips them all.
fn attested_world() -> Option<World> {
    let w = World::new()?;
    let out = w.run(&[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let (plan, _) = w.plan(&[]);
    assert!(plan.skip.is_superset(&set(ATTESTABLE)), "{plan:?}");
    Some(w)
}

/// A store that cannot be selected or opened: the plan runs every unit
/// (exit 0) and warns about the store; fetch, push, prune and `store
/// info` exit 2. Returns every output.
fn fails_open(w: &World, env: &[(&str, &str)], says: &str) -> Vec<Output> {
    let (plan, out) = w.plan(env);
    assert!(plan.skip.is_empty(), "{plan:?}");
    assert_eq!(plan.run, set(UNITS));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(err.contains("vci: warning: "), "{err}");
    assert!(
        err.contains(says),
        "the plan's warning says {says:?}: {err}"
    );
    let mut outs = vec![out];
    for args in [
        &["fetch"][..],
        &["push"],
        &["prune", "--dry-run"],
        &["store", "info"],
        &["store", "info", "--format", "json"],
    ] {
        let out = w.vci(args, env);
        assert_eq!(out.status.code(), Some(2), "vci {args:?}: {}", text(&out));
        assert!(text(&out).contains(says), "vci {args:?}: {}", text(&out));
        outs.push(out);
    }
    outs
}

/// 1. Nothing configured: git-meta, from the default, and `vci push`
///    still publishes `refs/meta/main`.
#[test]
fn nothing_configured_is_git_meta() {
    let Some(w) = World::new() else { return };
    let out = w.vci(&["store", "info"], &[]);
    let info = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(info.starts_with("store: git-meta\n"), "{info}");
    assert!(
        info.contains("  backend: git-meta (the default)\n"),
        "{info}"
    );
    assert!(
        info.contains("status: absent: nothing is stored yet (run `vci fetch`)"),
        "{info}"
    );
    assert!(info.contains("exchange: vci fetch and vci push, on refs/meta/main"));

    let out = w.run(&[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    // One-letter units file under `project` (target_label).
    assert!(
        text(&out).contains(" as git-meta project vci:attestation:"),
        "{}",
        text(&out)
    );
    let attested = text(&out).matches("vci: attested ").count();
    assert!(attested >= ATTESTABLE.len(), "{}", text(&out));
    let out = w.vci(&["push"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let remote = w.remote.to_str().unwrap();
    w.git(
        &w.base,
        &["--git-dir", remote, "rev-parse", "refs/meta/main"],
    );

    let out = w.vci(&["store", "info", "--format", "json"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["kind"], "git-meta");
    assert_eq!(v["status"], "ready");
    assert_eq!(v["count"], attested);
    assert_eq!(v["settings"][0]["name"], "backend");
    assert_eq!(v["settings"][0]["source"], "the default");
    assert_eq!(v["caps"]["lazyValues"], true);
    assert_eq!(v["exchange"], "refs/meta/main");
    assert!(v["error"].is_null());
    // The metrics log names the store's kind.
    let log = std::fs::read_to_string(&w.metrics).unwrap();
    let last: Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    assert_eq!(last["cmd"], "store");
    assert_eq!(last["store"], "git-meta");
}

/// 2. An unknown backend: the plan fails open, and the commands that
///    manage the store exit 2, naming it.
#[test]
fn an_unknown_store_fails_open() {
    let Some(w) = attested_world() else { return };
    fails_open(&w, &[("VCI_STORE", "nope")], "\"nope\"");
}

/// 3. postgres without `VCI_STORE_URL`: the plan fails open, and `vci
///    store info` says that the URL is needed.
#[test]
fn postgres_without_a_url_fails_open() {
    let Some(w) = attested_world() else { return };
    let outs = fails_open(&w, &[("VCI_STORE", "postgres")], "VCI_STORE_URL");
    let info = text(&outs[4]);
    assert!(
        info.contains("the postgres store needs $VCI_STORE_URL"),
        "{info}"
    );
}

/// 4. A URL in `VCI_STORE`, which names a backend: refused, as in (2),
///    and its password is printed nowhere.
#[test]
fn a_url_in_vci_store_is_refused_and_never_printed() {
    let Some(w) = attested_world() else { return };
    let outs = fails_open(&w, &[("VCI_STORE", URL)], "VCI_STORE_URL");
    for out in &outs {
        assert!(!text(out).contains(SECRET), "{}", text(out));
    }
    let log = std::fs::read_to_string(&w.metrics).unwrap();
    assert!(!log.contains(SECRET));
}

/// 5. `VCI_STORE_URL` is in no environment vci builds for a test (vci
///    takes it out of its own at start-up), nor in any output. The store cannot
///    be used here, so the run refuses to store, saying why, and its exit
///    code stays the tests'.
#[test]
fn the_store_url_reaches_no_test_and_no_output() {
    let Some(w) = World::new() else { return };
    let env = [("VCI_STORE_URL", URL)];
    let out = w.run(&env);
    let all = text(&out);
    assert_eq!(out.status.code(), Some(0), "the tests passed: {all}");
    assert!(!all.contains(SECRET), "{all}");
    assert!(!all.contains("vci: attested"), "{all}");
    for u in ATTESTABLE {
        assert!(
            all.contains(&format!(
                "vci: not attesting {u}: signing or storing failed: "
            )),
            "{u}: {all}"
        );
    }
    assert!(all.contains("postgres store"), "{all}");
    let dump = std::fs::read_to_string(&w.dump).expect("the envdump test ran");
    assert!(dump.starts_with("getenv:\n"), "{dump}");
    assert!(
        !dump.lines().any(|l| l.starts_with("VCI_STORE_URL=")),
        "{dump}"
    );
    assert!(!dump.contains(SECRET), "{dump}");
    // Nor any other command's output, nor the metrics log.
    let (plan, out) = w.plan(&env);
    assert_eq!(plan.run, set(UNITS));
    assert!(!text(&out).contains(SECRET));
    for args in [
        &["store", "info"][..],
        &["store", "info", "--format", "json"],
    ] {
        let out = w.vci(args, &env);
        assert_eq!(out.status.code(), Some(2), "{}", text(&out));
        assert!(!text(&out).contains(SECRET), "{}", text(&out));
        assert!(text(&out).contains("postgres"), "{}", text(&out));
    }
    let log = std::fs::read_to_string(&w.metrics).unwrap();
    assert!(!log.contains(SECRET), "{log}");
    assert!(log.contains("\"store\":\"postgres\""), "{log}");
}

/// 6. Connection settings in `vci.toml` are refused, by key and never by
///    value: the plan fails open and `vci store info` exits 2.
#[test]
fn a_password_in_vci_toml_is_refused_and_never_printed() {
    let Some(w) = attested_world() else { return };
    w.commit_vci_toml(&format!(
        "{VCI_TOML}\n[store.postgres]\npassword = \"planted\"\n"
    ));
    let (plan, out) = w.plan(&[]);
    assert!(plan.skip.is_empty(), "{plan:?}");
    assert_eq!(plan.run, set(UNITS));
    let mut outs = vec![out];
    for args in [
        &["store", "info"][..],
        &["store", "info", "--format", "json"],
    ] {
        let out = w.vci(args, &[]);
        assert_eq!(out.status.code(), Some(2), "{}", text(&out));
        assert!(
            text(&out).contains("store.postgres.password"),
            "{}",
            text(&out)
        );
        outs.push(out);
    }
    outs.push(w.run(&[]));
    for out in &outs {
        assert!(!text(out).contains("planted"), "{}", text(out));
    }
}

/// 7. The environment wins over `vci.toml`, with a warning: `[store]
///    backend = "sqlite"` overridden by `VCI_STORE=git-meta` uses git-meta.
#[test]
fn the_environment_overrides_vci_toml_with_a_warning() {
    let Some(w) = attested_world() else { return };
    w.commit_vci_toml(&format!("{VCI_TOML}\n[store]\nbackend = \"sqlite\"\n"));
    let env = [("VCI_STORE", "git-meta")];
    let (plan, out) = w.plan(&env);
    let warning =
        "vci.toml [store] backend = \"sqlite\" is overridden: using git-meta (from $VCI_STORE)";
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(&format!("vci: warning: {warning}")), "{err}");
    assert_eq!(err.matches(warning).count(), 1, "printed once: {err}");
    assert!(plan.warnings.iter().any(|w| w == warning), "{plan:?}");
    // git-meta, which holds the attestations: every attested unit skips.
    assert!(plan.skip.is_superset(&set(ATTESTABLE)), "{plan:?}");
    let out = w.vci(&["store", "info"], &env);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let info = String::from_utf8_lossy(&out.stdout);
    assert!(info.starts_with("store: git-meta\n"), "{info}");
    assert!(
        info.contains("  backend: git-meta ($VCI_STORE)\n"),
        "{info}"
    );
}

/// 9. A local file's URL (`file:` for libsql, `sqlite:`) holding a query or
///    a fragment, either of which may carry a token (`?authToken=…`,
///    `#authToken=…`), is refused: the plan fails open, the commands that
///    manage the store exit 2, no output shows the token, and no file is
///    made under that name.
#[test]
fn a_local_file_url_with_a_query_is_refused_and_never_printed() {
    const TOKEN: &str = "fileTokS3cr3tZulu";
    let Some(w) = attested_world() else { return };
    for (backend, url) in [
        (Some("libsql"), format!("file:local.db?authToken={TOKEN}")),
        (Some("sqlite"), format!("sqlite:local.db?authToken={TOKEN}")),
        (Some("libsql"), format!("file:local.db#authToken={TOKEN}")),
        (Some("sqlite"), format!("file:local.db#authToken={TOKEN}")),
        (Some("sqlite"), format!("sqlite:local.db#authToken={TOKEN}")),
        (None, format!("sqlite:local.db#authToken={TOKEN}")),
    ] {
        let mut env = vec![("VCI_STORE_URL", url.as_str())];
        env.extend(backend.map(|b| ("VCI_STORE", b)));
        let mut outs = fails_open(&w, &env, "query");
        let out = w.run(&env);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        outs.push(out);
        for out in &outs {
            assert!(!text(out).contains(TOKEN), "{url}: {}", text(out));
        }
        for dir in [w.work.join(".git"), w.work.clone()] {
            let made: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains("local.db"))
                .collect();
            assert!(made.is_empty(), "{url}: {made:?} in {}", dir.display());
        }
    }
    let log = std::fs::read_to_string(&w.metrics).unwrap();
    assert!(!log.contains(TOKEN), "{log}");
}
