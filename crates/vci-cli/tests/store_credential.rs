//! `[store] token_command`, end to end (docs/STORE-BACKENDS.md section 9):
//! a `vci.toml` that names a libSQL server and how to fetch its token, the
//! way vex keeps its attestations in Turso,
//!
//! ```toml
//! [store]
//! backend = "libsql"
//! url = "libsql://127.0.0.1:<port>?tls=0"
//! token_command = ["<helper>", "secrets", "get", "vci-store-token", "--org", "vex"]
//! ```
//!
//! against a throwaway `sqld` that checks tokens (a JWT signed by a key made
//! for these tests), with a helper script standing in for `com secrets get`
//! that prints a made-up token. The token reaches the server, the helper
//! runs once per process and never when the environment gives a token, an
//! environment token is never sent to a URL from `vci.toml`, the helper
//! gets none of `VCI_STORE_URL`, `VCI_STORE_TOKEN` and `VCI_STORE`, a
//! helper that fails makes the store fail open, and the token appears in no
//! output and reaches no test.
//!
//! A copy of `fixtures/go-abcd` in a throwaway git repository, plus a Go
//! package whose test writes its environment to a file outside the
//! repository. Needs `go`, `git`, `ssh-keygen`, and `sqld` on PATH or
//! Docker; every test prints `SKIPPED:` and returns early without them (a
//! failure under `VCI_TEST_LIBSQL=require` when the server is what is
//! missing).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use assert_cmd::cargo::CommandCargoExt;
use serde_json::Value;
use vci_store_libsql::testkit as libsql_kit;

/// The public key `sqld` checks tokens with: Ed25519, from the seed of
/// 32 bytes of 11, URL-safe base64 (as `vci-store-libsql`'s token tests
/// make theirs).
const JWT_PUBLIC_KEY: &str = "Zr5-Myx6RTMyvZ0Kf32wVfXF7xoGraZtmLOftoEMRzo";

/// A made-up token that server accepts: a JWT with no claims (full access,
/// no expiry), signed by that key.
const TOKEN: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.e30.J8t5Xlr8lmJGDG-zf596UBBuk8AFU_5II6-4Kq_rDF0AOjS3alx9SCj7sjRLpvSprv5At_REbpuz7jS2UdBVDQ";

/// Its signature: the part no other token shares (every one of these JWTs
/// starts with the same header).
const TOKEN_SIG: &str =
    "J8t5Xlr8lmJGDG-zf596UBBuk8AFU_5II6-4Kq_rDF0AOjS3alx9SCj7sjRLpvSprv5At_REbpuz7jS2UdBVDQ";

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
                "SKIPPED: `go` is not installed; the token_command tests need the Go toolchain on PATH"
            );
            false
        }
    }
}

/// A `sqld` that checks tokens, shared by this file's tests (each in a
/// namespace of its own): `sqld` from PATH, else the Docker image; `None`
/// without either.
fn server() -> Option<u16> {
    static SERVER: OnceLock<Result<libsql_kit::Process, String>> = OnceLock::new();
    let s = SERVER.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("vci-cred-jwt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let key = dir.join("jwt.key");
        std::fs::write(&key, JWT_PUBLIC_KEY).map_err(|e| e.to_string())?;
        libsql_kit::start_sqld(&["--auth-jwt-key-file".to_owned(), key.display().to_string()])
            .or_else(|e| {
                libsql_kit::start_docker_with_env(&[("SQLD_AUTH_JWT_KEY", JWT_PUBLIC_KEY)])
                    .map_err(|d| format!("{e}; docker: {d}"))
            })
    });
    match s {
        Ok(p) => Some(p.port()),
        Err(why) => {
            if std::env::var(libsql_kit::REQUIRE_VAR).as_deref() == Ok("require") {
                panic!(
                    "{}=require, but there is no sqld: {why}",
                    libsql_kit::REQUIRE_VAR
                );
            }
            eprintln!("SKIPPED: no sqld or Docker to check tokens with: {why}");
            None
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

struct World {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    work: PathBuf,
    key: PathBuf,
    gitconfig: PathBuf,
    /// Where the envdump package's test writes its environment.
    dump: PathBuf,
    metrics: PathBuf,
    /// One line per run of a helper: its arguments.
    runs: PathBuf,
    /// The environment the helper last ran with.
    helper_env: PathBuf,
    /// The sqld's port, and this world's namespace on it.
    port: u16,
    ns: String,
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

/// A test that writes its whole environment to `dump`.
fn envdump_test(dump: &Path) -> String {
    format!(
        r#"package envdump

import (
	"os"
	"strings"
	"testing"
)

func TestDumpEnvironment(t *testing.T) {{
	text := strings.Join(os.Environ(), "\n") + "\n"
	if err := os.WriteFile({dump:?}, []byte(text), 0o644); err != nil {{
		t.Fatal(err)
	}}
}}
"#,
        dump = dump.to_str().unwrap()
    )
}

impl World {
    /// `None` (test skipped) when go or sqld is unavailable.
    fn new() -> Option<Self> {
        if !go_available() {
            return None;
        }
        let port = server()?;
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let gitconfig = base.join("gitconfig");
        std::fs::write(
            &gitconfig,
            "[user]\n\tname = Test\n\temail = test@example.com\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n",
        )
        .unwrap();
        std::fs::create_dir(base.join("helpers")).unwrap();
        let w = World {
            work: base.join("work"),
            key: base.join("trusted"),
            dump: base.join("env-dump.txt"),
            metrics: base.join("metrics.jsonl"),
            runs: base.join("helper-runs.txt"),
            helper_env: base.join("helper-env.txt"),
            gitconfig,
            port,
            ns: libsql_kit::namespace(),
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
        let remote = w.base.join("remote.git");
        w.git(
            &w.work,
            &["remote", "add", "origin", remote.to_str().unwrap()],
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

    /// A helper script, outside the repository, standing in for `com
    /// secrets get`: it records its arguments and environment, then runs
    /// `body`. Its path.
    fn helper(&self, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt as _;
        let p = self.base.join("helpers").join(name);
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\necho \"$*\" >> {runs:?}\nenv > {env:?}\n{body}\n",
                runs = self.runs.to_str().unwrap(),
                env = self.helper_env.to_str().unwrap()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.to_str().unwrap().to_owned()
    }

    /// The server's URL as `vci.toml` names it.
    fn url(&self) -> String {
        format!("libsql://127.0.0.1:{}?tls=0", self.port)
    }

    /// Commit a `vci.toml` whose store is the server, its token from
    /// `program secrets get vci-store-token --org vex`.
    fn use_store(&self, program: &str) {
        let text = format!(
            "{VCI_TOML}\n[store]\nbackend = \"libsql\"\nurl = \"{url}\"\ntoken_command = [\"{program}\", \"secrets\", \"get\", \"vci-store-token\", \"--org\", \"vex\"]\n\n[store.libsql]\nnamespace = \"{ns}\"\n",
            url = self.url(),
            ns = self.ns
        );
        self.put("vci.toml", &text);
        self.git(&self.work, &["commit", "-q", "-am", "vci.toml: the store"]);
    }

    /// How many times a helper has run.
    fn helper_runs(&self) -> usize {
        std::fs::read_to_string(&self.runs)
            .map(|s| s.lines().count())
            .unwrap_or(0)
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
        // No warnings, no key.
        p.warnings = v["warnings"]
            .as_array()
            .map(|a| a.iter().map(|w| w.as_str().unwrap().to_owned()).collect())
            .unwrap_or_default();
        (p, out)
    }

    /// The token appears in no output, nor the metrics log, nor any test's
    /// environment.
    fn assert_no_token(&self, outs: &[Output]) {
        for out in outs {
            let t = text(out);
            assert!(!t.contains(TOKEN_SIG), "{t}");
        }
        let log = std::fs::read_to_string(&self.metrics).unwrap_or_default();
        assert!(!log.contains(TOKEN_SIG), "{log}");
        if let Ok(dump) = std::fs::read_to_string(&self.dump) {
            assert!(!dump.contains(TOKEN_SIG), "{dump}");
        }
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

/// A store that cannot be used: the plan runs every unit (exit 0) and
/// warns, saying `says`; fetch, push, prune and `store info` exit 2 saying
/// it too. Returns every output.
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

/// 1. vex's set-up on a developer's machine: nothing exported, the server
///    and the token command in `vci.toml`. The token reaches the server
///    (`vci run` stores, the plan then skips), the helper runs once per vci
///    process and only in a command that reads the store (not in a plan
///    that never reads it, whose warm-up would leave it unwaited, nor
///    under `VCI_STORE=git-meta`), `vci store
///    info` names the command and never the token, and neither any output
///    nor any test sees the token. With `VCI_STORE_URL` and `VCI_STORE`
///    exported, the helper still runs (no token in the environment), and
///    gets neither variable.
#[test]
fn the_token_command_supplies_the_token_and_nothing_else_sees_it() {
    let Some(w) = World::new() else { return };
    let com = w.helper("com", &format!("printf '%s\\n' '{TOKEN}'"));
    w.use_store(&com);
    assert_eq!(w.helper_runs(), 0);

    let run = w.run(&[]);
    let all = text(&run);
    assert_eq!(run.status.code(), Some(0), "{all}");
    for u in ATTESTABLE {
        assert!(all.contains(&format!("vci: attested {u} ")), "{u}: {all}");
    }
    assert!(all.contains(" as libsql "), "{all}");
    assert_eq!(w.helper_runs(), 1, "one run for the whole of vci run");
    assert_eq!(
        std::fs::read_to_string(&w.runs).unwrap(),
        "secrets get vci-store-token --org vex\n"
    );
    let dump = std::fs::read_to_string(&w.dump).expect("the envdump test ran");
    assert!(!dump.contains(TOKEN_SIG), "{dump}");

    let (plan, out) = w.plan(&[]);
    assert!(plan.skip.is_superset(&set(ATTESTABLE)), "{plan:?}");
    assert!(plan.warnings.is_empty(), "{plan:?}");
    assert_eq!(w.helper_runs(), 2);

    let info = w.vci(&["store", "info"], &[]);
    assert_eq!(info.status.code(), Some(0), "{}", text(&info));
    let stdout = String::from_utf8_lossy(&info.stdout).into_owned();
    for line in [
        "store: libsql\n".to_owned(),
        "  backend: libsql (vci.toml [store])\n".to_owned(),
        format!("  url: {} (vci.toml [store])\n", w.url()),
        "  mode: remote (vci.toml [store])\n".to_owned(),
        format!(
            "  token: (from token_command: {com} secrets get vci-store-token --org vex) (vci.toml [store])\n"
        ),
        format!("  namespace: {} (vci.toml [store])\n", w.ns),
        "status: ready".to_owned(),
    ] {
        assert!(stdout.contains(&line), "{line:?} in {stdout}");
    }
    assert_eq!(w.helper_runs(), 3, "store info reads the store");
    let json = w.vci(&["store", "info", "--format", "json"], &[]);
    assert_eq!(json.status.code(), Some(0), "{}", text(&json));
    let v: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert!(
        v["settings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["name"] == "token"
                && s["value"]
                    == format!(
                        "(from token_command: {com} secrets get vci-store-token --org vex)"
                    )
                && s["source"] == "vci.toml [store]")
    );

    // Commands that do not reach the store never run it, nor does a plan
    // that never reads it (no base ref: everything runs), whose warm-up
    // must not start the command on a thread nobody waits for.
    let mut outs = vec![run, out, info, json];
    for args in [
        &["--version"][..],
        &["env"],
        &["plan", "--base-ref", "doesnotexist", "--format", "json"],
    ] {
        let out = w.vci(args, &[]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        outs.push(out);
    }
    // In a checkout not yet reviewed, VCI_STORE=git-meta ignores the url
    // and the command, saying so, and never runs it.
    let (plan, out) = w.plan(&[("VCI_STORE", "git-meta")]);
    for says in [
        "vci.toml [store] url (",
        "vci.toml [store] token_command is ignored (not run)",
    ] {
        assert!(
            plan.warnings.iter().any(|w| w.starts_with(says)),
            "{says}: {plan:?}"
        );
    }
    outs.push(out);
    // A command a warm-up thread started would record its run after vci
    // exits.
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(w.helper_runs(), 4);

    // With the server exported (and VCI_STORE), but no token: the command
    // supplies it, and is given neither variable.
    let url = w.url();
    let env = [("VCI_STORE_URL", url.as_str()), ("VCI_STORE", "libsql")];
    let (plan, out) = w.plan(&env);
    assert!(plan.skip.is_superset(&set(ATTESTABLE)), "{plan:?}");
    assert_eq!(w.helper_runs(), 5);
    let helper_env = std::fs::read_to_string(&w.helper_env).unwrap();
    for name in ["VCI_STORE_URL=", "VCI_STORE_TOKEN=", "VCI_STORE="] {
        assert!(
            !helper_env.lines().any(|l| l.starts_with(name)),
            "{name} in {helper_env}"
        );
    }
    assert!(
        helper_env.lines().any(|l| l.starts_with("PATH=")),
        "{helper_env}"
    );
    outs.push(out);
    w.assert_no_token(&outs);
}

/// 2. The trust rule: a token from the environment (CI's secret) with the
///    URL from `vci.toml` (which a pull request can change) is refused,
///    saying to set `VCI_STORE_URL` too, also when the environment chooses
///    the backend (`VCI_STORE`, as CI may set it beside the token): the
///    store fails open, the helper never runs, nothing reaches the server
///    (the store holds nothing afterwards), and the token is printed
///    nowhere. With `VCI_STORE_URL` as well, as CI sets both, the token is
///    used and the helper still never runs, nor with an `authToken` in
///    `VCI_STORE_URL` alone.
#[test]
fn an_environment_token_is_never_sent_to_a_url_from_vci_toml() {
    let Some(w) = World::new() else { return };
    let com = w.helper("com", &format!("printf '%s\\n' '{TOKEN}'"));
    w.use_store(&com);
    let mut outs = Vec::new();
    for env in [
        &[("VCI_STORE_TOKEN", TOKEN)][..],
        &[("VCI_STORE", "libsql"), ("VCI_STORE_TOKEN", TOKEN)],
    ] {
        outs.extend(fails_open(&w, env, "set $VCI_STORE_URL as well"));
        let out = w.run(env);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        assert!(!text(&out).contains("vci: attested"), "{}", text(&out));
        outs.push(out);
        assert_eq!(w.helper_runs(), 0, "the token command never runs");
    }

    let url = w.url();
    let env = [("VCI_STORE_TOKEN", TOKEN), ("VCI_STORE_URL", url.as_str())];
    // Nothing was stored by the runs refused above: the namespace is still
    // empty.
    let (plan, plan_out) = w.plan(&env);
    assert!(plan.skip.is_empty(), "{plan:?}");
    assert_eq!(
        plan.warnings,
        ["no attestations are available in the libsql store (the first `vci run` creates it)"],
        "{plan:?}"
    );
    outs.push(plan_out);
    let out = w.run(&env);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("vci: attested a "), "{}", text(&out));
    let (plan, plan_out) = w.plan(&env);
    assert!(plan.skip.is_superset(&set(ATTESTABLE)), "{plan:?}");
    let info = w.vci(&["store", "info"], &env);
    assert_eq!(info.status.code(), Some(0), "{}", text(&info));
    assert!(
        String::from_utf8_lossy(&info.stdout).contains("  token: (set) ($VCI_STORE_TOKEN)\n"),
        "{}",
        text(&info)
    );
    assert_eq!(w.helper_runs(), 0, "the environment's token wins");
    outs.extend([out, plan_out, info]);

    // So does an authToken in VCI_STORE_URL, without VCI_STORE_TOKEN (a CI
    // job may keep the whole URL in one secret).
    let with_token = format!("{url}&authToken={TOKEN}");
    let env = [("VCI_STORE_URL", with_token.as_str())];
    let (plan, plan_out) = w.plan(&env);
    assert!(plan.skip.is_superset(&set(ATTESTABLE)), "{plan:?}");
    let info = w.vci(&["store", "info"], &env);
    assert_eq!(info.status.code(), Some(0), "{}", text(&info));
    assert!(
        String::from_utf8_lossy(&info.stdout)
            .contains("  token: (the URL's authToken) ($VCI_STORE_URL)\n"),
        "{}",
        text(&info)
    );
    assert_eq!(w.helper_runs(), 0, "the URL's token wins");
    outs.extend([plan_out, info]);

    // vci.toml may name the server, never hold its token: refused, and
    // printed nowhere.
    w.put(
        "vci.toml",
        &format!(
            "{VCI_TOML}\n[store]\nbackend = \"libsql\"\nurl = \"{}&authToken={TOKEN}\"\n",
            w.url()
        ),
    );
    w.git(
        &w.work,
        &["commit", "-q", "-am", "vci.toml: a token in the URL"],
    );
    outs.extend(fails_open(
        &w,
        &[],
        "vci.toml [store] url carries a credential in its query",
    ));
    w.assert_no_token(&outs);
}

/// 3. A helper that cannot give a token (it fails, prints nothing, prints
///    two lines, or is not there): the plan runs everything with a warning
///    saying why, the commands that manage the store exit 2 saying it, the
///    run keeps the tests' exit code and attests nothing, and whatever the
///    helper printed on standard output is shown nowhere.
#[test]
fn a_token_command_that_fails_fails_open() {
    let Some(w) = World::new() else { return };
    let cases = [
        (
            w.helper(
                "com-denied",
                &format!("printf '%s\\n' '{TOKEN}'\necho 'com: not an admin of vex' >&2\nexit 3"),
            ),
            "exited 3: com: not an admin of vex".to_owned(),
        ),
        (
            w.helper("com-empty", "true"),
            "printed nothing on standard output".to_owned(),
        ),
        (
            w.helper("com-lines", &format!("echo '{TOKEN}'\necho '{TOKEN}'")),
            "printed more than one line on standard output (not printed)".to_owned(),
        ),
        (
            // JSON (a secrets CLI without its raw flag), the token echoed on
            // standard error (debug logging).
            w.helper(
                "com-json",
                &format!(
                    "printf '{{\\n  \"value\": \"%s\"\\n}}\\n' '{TOKEN}'\necho \"debug: decrypted {TOKEN}\" >&2"
                ),
            ),
            "printed more than one line on standard output (not printed): it must print the credential alone: debug: decrypted ***".to_owned(),
        ),
        (
            // A sentence that ends right after the token, which standard
            // error echoes.
            w.helper(
                "com-sentence",
                &format!(
                    "printf 'Your token: %s.\\n' '{TOKEN}'\necho \"debug: fetched {TOKEN} from vault\" >&2\nexit 1"
                ),
            ),
            "exited 1: debug: fetched *** from vault".to_owned(),
        ),
        (
            w.base
                .join("helpers/com-missing")
                .to_str()
                .unwrap()
                .to_owned(),
            "was not found".to_owned(),
        ),
    ];
    let mut outs = Vec::new();
    for (program, says) in &cases {
        w.use_store(program);
        let says =
            format!("the token_command ({program} secrets get vci-store-token --org vex) {says}");
        let before = w.helper_runs();
        outs.extend(fails_open(&w, &[], &says));
        let out = w.run(&[]);
        let all = text(&out);
        assert_eq!(out.status.code(), Some(0), "the tests passed: {all}");
        assert!(!all.contains("vci: attested"), "{all}");
        assert!(all.contains(&says), "{all}");
        outs.push(out);
        if !program.ends_with("com-missing") {
            // Once per process: the plan, the five commands, the run.
            assert_eq!(w.helper_runs(), before + 7, "{program}");
        }
    }
    w.assert_no_token(&outs);
}

/// 4. A helper that hangs is stopped after a minute, with what it started
///    (its process group is killed: here a program it runs without
///    `exec`), and the store fails open.
#[test]
fn a_token_command_that_hangs_is_stopped_and_fails_open() {
    let Some(w) = World::new() else { return };
    let pid_file = w.base.join("hung.pid");
    let com = w.helper(
        "com-hangs",
        &format!(
            "echo '{TOKEN}'\nsh -c 'echo $$ > {:?}; exec sleep 600'",
            pid_file.to_str().unwrap()
        ),
    );
    w.use_store(&com);
    let started = Instant::now();
    let (plan, out) = w.plan(&[]);
    let took = started.elapsed();
    assert!(plan.skip.is_empty(), "{plan:?}");
    assert_eq!(plan.run, set(UNITS));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!(
            "the token_command ({com} secrets get vci-store-token --org vex) did not finish within 60 s (it was stopped)"
        )),
        "{err}"
    );
    assert!(
        took >= Duration::from_secs(60) && took < Duration::from_secs(150),
        "{took:?}"
    );
    assert_eq!(w.helper_runs(), 1);
    // The program the helper ran is gone too.
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    let pid = pid.trim();
    let until = Instant::now() + Duration::from_secs(10);
    let alive = loop {
        let alive = Command::new("kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        if !alive || Instant::now() >= until {
            break alive;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if alive {
        // Not left behind by this test either: by its own pid.
        let _ = Command::new("kill").args(["-KILL", pid]).status();
    }
    assert!(!alive, "the helper's sleep ({pid}) outlived it");
    w.assert_no_token(&[out]);
}
