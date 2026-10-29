//! The command line on each attestation store backend, end to end
//! (docs/STORE-BACKENDS.md sections 7, 9, 10, 16, 17 and 18): `vci run`,
//! `vci plan`, `vci explain`, supersession, `vci prune`, `vci fetch`, `vci
//! push` and `vci ci` on SQLite (`VCI_STORE=sqlite`), PostgreSQL
//! (`VCI_STORE_URL`) and libSQL (`VCI_STORE=libsql`: its local file, a
//! server, and a replica of one), the publication gate of a shared store,
//! failing open when a store cannot be used, git-meta when nothing is
//! configured, and a vci 2.8 binary (`VCI_TEST_VCI_2_8`) on a SQLite file
//! and on a git-meta store this vci wrote.
//!
//! A copy of `fixtures/go-abcd` in a throwaway git repository. Needs `go`,
//! `git` and `ssh-keygen` on PATH; every test prints `SKIPPED:` and returns
//! early when `go` is not installed or cannot download the fixture's
//! modules. The PostgreSQL tests take their server from
//! [`vci_store_postgres::testkit::pg`] (`VCI_TEST_POSTGRES_URL`, else a
//! throwaway cluster started with `initdb`), each in a schema of its own
//! named in the world's `vci.toml`, with `VCI_STORE_NAMESPACE=test`. They
//! skip without a server, and fail under `VCI_TEST_POSTGRES=require`.
//! The libSQL server tests take theirs from
//! [`vci_store_libsql::testkit::server`] (`VCI_TEST_LIBSQL_URL`, else a
//! throwaway `sqld`), each in a namespace of its own; they skip without one,
//! and fail under `VCI_TEST_LIBSQL=require`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use assert_cmd::cargo::CommandCargoExt;
use serde_json::Value;
use vci_store::conformance::scenarios::Run3;
use vci_store::{AttestationStore, Columns, NewAttestation, Record, decode_record};
use vci_store_libsql::testkit as libsql_kit;
use vci_store_postgres::testkit::{self, PgDb};
use vci_store_sqlite::{SqliteOptions, SqliteStore};

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
                "SKIPPED: `go` is not installed; the store backend tests need the Go toolchain on PATH"
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
    "VCI_STORE_SYNC",
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

/// The fixture's packages; a run attests every one of them.
const UNITS: &[&str] = &["a", "b", "c", "d"];

/// A password planted in a URL: it must appear in no output.
const SECRET: &str = "s3cret";

/// The shape of an attestation key (docs/STORE-BACKENDS.md section 2), with
/// the hint every key vci writes since 2.2 carries: `vci:attestation:<test
/// key>:<signer>:<storage key>:<issued hex>.<tree16>`.
fn key_has_vci_shape(key: &str) -> bool {
    let hex = |s: &str, min: usize, max: usize| {
        (min..=max).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let seg: Vec<&str> = key.split(':').collect();
    let [vci, kind, tk, signer, sk, hint] = seg[..] else {
        return false;
    };
    let Some((issued, tree)) = hint.split_once('.') else {
        return false;
    };
    vci == "vci"
        && kind == "attestation"
        && hex(tk, 64, 64)
        && hex(signer, 16, 16)
        && hex(sk, 2, 128)
        && hex(issued, 1, 16)
        && (tree == "-" || hex(tree, 16, 16))
}

/// The slot of a key (`vci:attestation:<test key>:<signer>:<storage key>`)
/// and the tree of its hint: what two stores holding the same attestation
/// agree on (the issue time differs between two runs).
fn slot_and_tree(key: &str) -> (String, String) {
    let (slot, hint) = key.rsplit_once(':').unwrap();
    let tree = hint.split_once('.').unwrap().1;
    (slot.to_owned(), tree.to_owned())
}

/// The store a world's `vci` commands use.
struct Backend {
    kind: &'static str,
    /// Whether every write is shared at once (`Caps::shared_writes`): the
    /// publication gate applies, and unreferenced manifests are kept for an
    /// hour.
    shared: bool,
    /// The libSQL store's mode (`local`, `remote`, `replica`); empty for
    /// the others.
    mode: &'static str,
    /// The libSQL server's URL and the namespace (remote and replica).
    server: Option<(String, String)>,
    /// Added to the environment of every `vci` command of the world.
    env: Vec<(String, String)>,
    /// Added to the base commit's `vci.toml`.
    toml: String,
    /// The PostgreSQL schema's owner: dropping it drops the schema.
    db: Option<PgDb>,
}

impl Backend {
    /// Nothing configured: git-meta.
    fn git_meta() -> Self {
        Backend {
            kind: "git-meta",
            shared: false,
            mode: "",
            server: None,
            env: Vec::new(),
            toml: String::new(),
            db: None,
        }
    }

    /// SQLite at its default path, `.git/vci-store.sqlite`.
    fn sqlite() -> Self {
        Backend {
            kind: "sqlite",
            shared: false,
            mode: "",
            server: None,
            env: vec![("VCI_STORE".into(), "sqlite".into())],
            toml: String::new(),
            db: None,
        }
    }

    /// PostgreSQL from the testkit, in a schema of its own; `None` (test
    /// skipped) without a server.
    fn postgres() -> Option<Self> {
        let db = testkit::pg()?;
        Some(Backend {
            kind: "postgres",
            shared: true,
            mode: "",
            server: None,
            env: vec![
                ("VCI_STORE_URL".into(), db.url.clone()),
                ("VCI_STORE_NAMESPACE".into(), "test".into()),
            ],
            toml: format!("\n[store.postgres]\nschema = \"{}\"\n", db.schema),
            db: Some(db),
        })
    }

    /// libSQL's local file at its default path, `.git/vci-store.libsql`.
    fn libsql() -> Self {
        Backend {
            kind: "libsql",
            shared: false,
            mode: "local",
            server: None,
            env: vec![("VCI_STORE".into(), "libsql".into())],
            toml: String::new(),
            db: None,
        }
    }

    /// libSQL on the testkit's server, in a namespace of its own: every
    /// read and write on the server, or (`replica`) reads from a replica
    /// at `.git/vci-store.libsql`. `None` (test skipped) without a server.
    fn libsql_server(replica: bool) -> Option<Self> {
        if !libsql_kit::available() {
            return None;
        }
        let server = libsql_kit::server().ok()?;
        let ns = libsql_kit::namespace();
        let mut env: Vec<(String, String)> = vec![
            ("VCI_STORE".into(), "libsql".into()),
            ("VCI_STORE_URL".into(), server.url.clone()),
            ("VCI_STORE_NAMESPACE".into(), ns.clone()),
        ];
        if let Some(t) = &server.token {
            env.push(("VCI_STORE_TOKEN".into(), t.clone()));
        }
        if replica {
            env.push(("VCI_STORE_SYNC".into(), "replica".into()));
        }
        Some(Backend {
            kind: "libsql",
            shared: true,
            mode: if replica { "replica" } else { "remote" },
            server: Some((server.url.clone(), ns)),
            env,
            toml: String::new(),
            db: None,
        })
    }
}

struct World {
    backend: Backend,
    _tmp: tempfile::TempDir,
    base: PathBuf,
    work: PathBuf,
    remote: PathBuf,
    key: PathBuf,
    gitconfig: PathBuf,
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

/// A Go test that writes `os.Getenv("VCI_STORE_URL")` and its whole
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

/// What a JSON plan says.
#[derive(Debug, Default)]
struct Plan {
    skip: BTreeSet<String>,
    run: BTreeSet<String>,
    /// Of each skipped unit: `by.metaKey`, `by.target`.
    by: BTreeMap<String, (String, String)>,
    warnings: Vec<String>,
    /// Why every unit runs, if so.
    run_all: Option<String>,
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

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The keys of `vci: attested <unit> (…) as <kind> <target> <key>` lines,
/// by unit.
fn attested_keys(out: &Output, kind: &str) -> BTreeMap<String, String> {
    let mut keys = BTreeMap::new();
    for line in stderr(out).lines() {
        let Some(rest) = line.strip_prefix("vci: attested ") else {
            continue;
        };
        let unit = rest.split_whitespace().next().unwrap().to_owned();
        let (_, tail) = rest
            .split_once(&format!(") as {kind} "))
            .unwrap_or_else(|| panic!("attested as {kind}: {line}"));
        let key = tail.split_whitespace().nth(1).unwrap().to_owned();
        keys.insert(unit, key);
    }
    keys
}

impl World {
    /// `None` (test skipped) when go is unavailable.
    fn new(backend: Backend) -> Option<Self> {
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
            metrics: base.join("metrics.jsonl"),
            gitconfig,
            base,
            backend,
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
        w.put(".gitignore", ".vci/out/\n");
        w.put("vci.toml", &format!("{VCI_TOML}{}", w.backend.toml));
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

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.work.join(rel)).unwrap()
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

    /// Commit every change in the working tree.
    fn commit(&self, msg: &str) {
        self.git(&self.work, &["add", "-A"]);
        self.git(&self.work, &["commit", "-q", "-m", msg]);
    }

    /// Append a comment to `rel` (its tests still pass; its inputs change).
    fn touch(&self, rel: &str, note: &str) {
        let src = self.read(rel);
        self.put(rel, &format!("{src}\n// {note}\n"));
    }

    /// `vci <args>` in the repository on the world's store, with `env`
    /// added (metrics go to the world's own log).
    fn vci(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut all: Vec<(&str, &str)> = self
            .backend
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        all.extend_from_slice(env);
        self.vci_bare(args, &all)
    }

    /// `vci <args>` with only `env` added to a scrubbed environment: no
    /// store configured unless `env` configures one.
    fn vci_bare(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        self.command(Command::cargo_bin("vci").unwrap(), args, env)
    }

    /// `vci <args>` of another build of vci, `bin`, on the world's store.
    fn vci_other(&self, bin: &Path, args: &[&str]) -> Output {
        let env: Vec<(&str, &str)> = self
            .backend
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.command(Command::new(bin), args, &env)
    }

    /// `cmd <args>` in the repository with `env` added to a scrubbed
    /// environment (metrics go to the world's own log).
    fn command(&self, mut cmd: Command, args: &[&str], env: &[(&str, &str)]) -> Output {
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
            "$ {} {} {env:?} -> {:?}\n{}{}",
            Path::new(cmd.get_program())
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// `vci run --key` of `units` (every unit when empty); it must exit 0.
    fn run(&self, units: &[&str]) -> Output {
        self.run_env(units, &[])
    }

    /// [`World::run`] with `env` set (`VCI_STORE_RECORD_FORMAT=1` for a
    /// run that stores format-1 records and their manifests, as 2.8 did).
    fn run_env(&self, units: &[&str], env: &[(&str, &str)]) -> Output {
        let key = self.key.to_str().unwrap().to_owned();
        let mut args = vec!["run"];
        args.extend_from_slice(units);
        args.extend(["--key", &key]);
        let out = self.vci(&args, env);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        out
    }

    /// `vci ci --key` with an audit log, which it returns.
    fn ci(&self, extra: &[&str], env: &[(&str, &str)], log: &str) -> (Output, Value) {
        let key = self.key.to_str().unwrap().to_owned();
        let log = self.base.join(log);
        let mut args = vec![
            "ci",
            "--base-ref",
            "main",
            "--key",
            &key,
            "--audit-log",
            log.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        let out = self.vci(&args, env);
        let audit: Value = serde_json::from_slice(
            &std::fs::read(&log).unwrap_or_else(|e| panic!("audit log: {e}\n{}", text(&out))),
        )
        .unwrap();
        (out, audit)
    }

    /// `vci plan` as JSON, with `env`; it must exit 0.
    fn plan(&self, env: &[(&str, &str)]) -> (Plan, Output) {
        let out = self.vci(&["plan", "--base-ref", "main", "--format", "json"], env);
        (parse_plan(&out), out)
    }

    /// `vci explain <unit>` (stdout); it must exit 0.
    fn explain(&self, unit: &str) -> String {
        let out = self.vci(&["explain", unit, "--base-ref", "main"], &[]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        stdout(&out)
    }

    /// `vci store info --format json`; it must exit 0.
    fn info(&self) -> Value {
        let out = self.vci(&["store", "info", "--format", "json"], &[]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// Whether the bare remote has `refs/meta/main`.
    fn remote_has_meta(&self) -> bool {
        Command::new("git")
            .args(["--git-dir"])
            .arg(&self.remote)
            .args(["rev-parse", "--verify", "-q", "refs/meta/main"])
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap()
            .status
            .success()
    }
}

fn parse_plan(out: &Output) -> Plan {
    assert_eq!(
        out.status.code(),
        Some(0),
        "vci plan fails open: {}",
        text(out)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut p = Plan::default();
    for f in v["files"].as_array().unwrap() {
        let id = f["testId"].as_str().unwrap().to_owned();
        if f["skip"].as_bool().unwrap() {
            let key = f["by"]["metaKey"].as_str().unwrap().to_owned();
            let target = f["by"]["target"].as_str().unwrap().to_owned();
            p.by.insert(id.clone(), (key, target));
            p.skip.insert(id);
        } else {
            p.run.insert(id);
        }
    }
    // Absent when there are none.
    p.warnings = v["warnings"]
        .as_array()
        .map(|a| a.iter().map(|w| w.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default();
    p.run_all = v["runAll"].as_str().map(str::to_owned);
    p
}

/// Every unit attested and stored in the world's store, and a plan that
/// skips every one of them; returns the run's output.
fn attest_all(w: &World) -> Output {
    let out = w.run(&[]);
    assert_eq!(
        attested_keys(&out, w.backend.kind).len(),
        UNITS.len(),
        "{}",
        text(&out)
    );
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.skip, set(UNITS), "{plan:?}");
    out
}

/// A port on 127.0.0.1 that nothing listens on.
fn closed_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------
// 1. Run, plan and explain.

/// `vci run` then `vci plan` skips every unit; `vci explain` names the
/// store's kind; the plan's `by.metaKey` and `by.target` have git-meta's
/// shape: the same slot, tree and target as git-meta stores for the same
/// run of the same commit.
fn run_plan_explain(backend: Backend) {
    let kind = backend.kind;
    let Some(w) = World::new(backend) else { return };
    let run = attest_all(&w);
    let keys = attested_keys(&run, kind);
    let (plan, _) = w.plan(&[]);
    for u in UNITS {
        let (key, target) = &plan.by[*u];
        assert!(key_has_vci_shape(key), "{u}: {key}");
        assert_eq!(key, &keys[*u], "the plan skips with the stored key");
        assert_eq!(target, "project", "one-letter units file under project");
    }
    let info = w.info();
    assert_eq!(info["kind"], kind);
    assert_eq!(info["status"], "ready");
    assert_eq!(info["count"], UNITS.len());
    assert!(info["exchange"].is_null(), "{info}");
    let ex = w.explain("a");
    assert!(ex.contains("a: SKIP"), "{ex}");
    let (key, _) = &plan.by["a"];
    assert!(
        ex.contains(&format!("\ncandidate 1: {kind} project {key}\n")),
        "{ex}"
    );

    // git-meta, for the same commit in the same clone: the same slots,
    // trees and targets.
    assert!(
        !w.work.join(".git/git-meta.sqlite").exists(),
        "the {kind} store left git-meta alone"
    );
    let out = w.vci_bare(&["run", "--key", w.key.to_str().unwrap()], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let gm = parse_plan(&w.vci_bare(&["plan", "--base-ref", "main", "--format", "json"], &[]));
    assert_eq!(gm.skip, set(UNITS), "{gm:?}");
    for u in UNITS {
        let (key, target) = &plan.by[*u];
        let (gm_key, gm_target) = &gm.by[*u];
        assert!(key_has_vci_shape(gm_key), "{u}: {gm_key}");
        assert_eq!(slot_and_tree(key), slot_and_tree(gm_key), "{u}");
        assert_eq!(target, gm_target, "{u}");
    }
}

#[test]
fn sqlite_runs_plans_and_explains() {
    run_plan_explain(Backend::sqlite());
}

#[test]
fn postgres_runs_plans_and_explains() {
    let Some(b) = Backend::postgres() else { return };
    run_plan_explain(b);
}

#[test]
fn libsql_runs_plans_and_explains() {
    run_plan_explain(Backend::libsql());
}

#[test]
fn libsql_remote_runs_plans_and_explains() {
    let Some(b) = Backend::libsql_server(false) else {
        return;
    };
    run_plan_explain(b);
}

#[test]
fn libsql_replica_runs_plans_and_explains() {
    let Some(b) = Backend::libsql_server(true) else {
        return;
    };
    run_plan_explain(b);
}

// ---------------------------------------------------------------------------
// 2. An edit, supersession, orphan manifests and prune.

/// What `vci prune --dry-run` lists on stdout, and its summary on stderr.
fn prune_dry_run(w: &World) -> (Vec<String>, String) {
    let out = w.vci(&["prune", "--dry-run"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    (
        stdout(&out).lines().map(str::to_owned).collect(),
        stderr(&out),
    )
}

/// Edit a file: the plan runs that unit only. Its second attestation on
/// this branch supersedes the first; a format-3 run (the default) stores
/// no manifest, and the superseded run's objects are within their hour of
/// grace, so `vci prune --dry-run` lists nothing. On a shared store
/// (PostgreSQL, a libSQL server) the same again with `record_format = 1`,
/// as 2.8 wrote: the superseded attestation's manifest, which nothing
/// references any more, is kept by the run (`manifest_grace`: put less
/// than an hour ago) and removed by `vci prune`, which lists nothing else.
fn edit_supersede_prune(backend: Backend) {
    let kind = backend.kind;
    let shared = backend.shared;
    let Some(w) = World::new(backend) else { return };
    attest_all(&w);

    // An attestation on a commit of this branch only.
    w.touch("a/a.go", "edit 1");
    w.commit("edit a");
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.run, set(&["a"]), "{plan:?}");
    assert_eq!(plan.skip, set(&["b", "c", "d"]), "{plan:?}");
    let out = w.run(&["a"]);
    assert!(!stderr(&out).contains("superseded"), "{}", text(&out));
    let first = attested_keys(&out, kind)["a"].clone();
    assert_eq!(w.info()["count"], UNITS.len() + 1);
    let (listed, _) = prune_dry_run(&w);
    assert!(
        listed.is_empty(),
        "every manifest is referenced: {listed:?}"
    );

    // The branch moves on: the new attestation supersedes it.
    w.touch("a/a.go", "edit 2");
    w.commit("edit a again");
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.run, set(&["a"]), "{plan:?}");
    let out = w.run(&["a"]);
    assert!(
        stderr(&out).contains("vci: removed 1 superseded attestation(s) "),
        "{}",
        text(&out)
    );
    let second = attested_keys(&out, kind)["a"].clone();
    assert_ne!(first, second);
    assert_eq!(w.info()["count"], UNITS.len() + 1, "one in, one out");
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.skip, set(UNITS), "{plan:?}");
    assert_eq!(plan.by["a"].0, second);
    let ex = w.explain("a");
    assert!(!ex.contains(&first), "the superseded one is gone: {ex}");
    assert!(ex.contains(&second), "{ex}");

    let (listed, summary) = prune_dry_run(&w);
    assert!(
        summary.contains(&format!(
            "vci prune: 0 expired (dry run), {} current, 0 unreadable (left alone)",
            UNITS.len() + 1
        )),
        "{summary}"
    );
    assert!(
        listed.is_empty(),
        "a format-3 run stores no manifest, and the superseded run's objects are within their grace: {listed:?}"
    );
    if shared {
        // The same with format-1 records: the first one's manifest is
        // the orphan. Within the grace period, the run kept it; prune (no
        // grace) removes it, and only it.
        let f1 = [("VCI_STORE_RECORD_FORMAT", "1")];
        w.touch("a/a.go", "edit 3");
        w.commit("edit a a third time");
        let out = w.run_env(&["a"], &f1);
        assert!(
            stderr(&out).contains("vci: removed 1 superseded attestation(s) "),
            "{}",
            text(&out)
        );
        let first_root = stderr(&out)
            .lines()
            .find(|l| l.starts_with("vci: attested a ("))
            .and_then(|l| l.split(", root ").nth(1))
            .map(|r| r[..16].to_owned())
            .unwrap();
        let (listed, _) = prune_dry_run(&w);
        assert!(listed.is_empty(), "its manifest is referenced: {listed:?}");
        w.touch("a/a.go", "edit 4");
        w.commit("edit a a fourth time");
        let out = w.run_env(&["a"], &f1);
        assert!(
            stderr(&out).contains("vci: removed 1 superseded attestation(s) "),
            "{}",
            text(&out)
        );
        assert_eq!(w.info()["count"], UNITS.len() + 1, "one in, one out");
        let (listed, summary) = prune_dry_run(&w);
        assert!(
            summary.contains(&format!(
                "vci prune: 0 expired (dry run), {} current, 0 unreadable (left alone)",
                UNITS.len() + 1
            )),
            "{summary}"
        );
        assert_eq!(listed.len(), 1, "{listed:?}");
        let prefix = format!("would remove project vci:manifest:{first_root}");
        assert!(listed[0].starts_with(&prefix), "{listed:?}");
        assert!(
            listed[0].ends_with(" (unreferenced manifest)"),
            "{listed:?}"
        );
        let out = w.vci(&["prune"], &[]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        assert_eq!(
            stdout(&out),
            format!("{}\n", listed[0].replacen("would remove", "removed", 1))
        );
        let (listed, _) = prune_dry_run(&w);
        assert!(listed.is_empty(), "{listed:?}");
    }
    assert!(
        summary.contains("unreferenced input manifest(s) (dry run)"),
        "{summary}"
    );
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.skip, set(UNITS), "pruning removed nothing in use");
}

#[test]
fn sqlite_supersedes_and_prunes() {
    edit_supersede_prune(Backend::sqlite());
}

#[test]
fn postgres_supersedes_and_prunes() {
    let Some(b) = Backend::postgres() else { return };
    edit_supersede_prune(b);
}

#[test]
fn libsql_supersedes_and_prunes() {
    edit_supersede_prune(Backend::libsql());
}

#[test]
fn libsql_remote_supersedes_and_prunes() {
    let Some(b) = Backend::libsql_server(false) else {
        return;
    };
    edit_supersede_prune(b);
}

#[test]
fn libsql_replica_supersedes_and_prunes() {
    let Some(b) = Backend::libsql_server(true) else {
        return;
    };
    edit_supersede_prune(b);
}

// ---------------------------------------------------------------------------
// 3. The plan reads the candidates it set aside (A6) on SQLite.

/// Package d attested at three tagged states S0, S1 and S2; then d is back
/// at S0 while another file changed. The two newest candidates fail on
/// their inputs and the oldest passes: the plan reads the set-aside one in
/// its second round, with nothing to fetch (every value is local), and
/// skips d with S0's attestation.
#[test]
fn sqlite_reads_the_candidates_it_set_aside() {
    let Some(w) = World::new(Backend::sqlite()) else {
        return;
    };
    let src = w.read("d/d.go");
    let state = |n: usize| format!("{src}\n// state {n}\n");
    let mut keys = Vec::new();
    for n in 0..3 {
        if n > 0 {
            // A key's hint has whole seconds; the plan reads the newest by
            // them, all of them on a tie.
            std::thread::sleep(Duration::from_millis(1100));
        }
        w.put("d/d.go", &state(n));
        w.commit(&format!("S{n}"));
        w.git(&w.work, &["tag", &format!("s{n}")]);
        let out = w.run(&["d"]);
        keys.push(attested_keys(&out, "sqlite")["d"].clone());
    }
    assert_eq!(w.info()["count"], 3, "the tags keep every state");

    w.put("d/d.go", &state(0));
    w.touch("a/a.go", "unrelated");
    w.commit("d as at S0, a edited");

    let (plan, out) = w.plan(&[("VCI_TIMING", "1")]);
    let err = stderr(&out);
    assert!(
        plan.skip.contains("d"),
        "d skips through S0: {plan:?}\n{err}"
    );
    assert_eq!(plan.by["d"].0, keys[0]);
    assert!(
        err.contains("round 2: read 1 candidate(s) set aside"),
        "S0 is read in the second round: {err}"
    );

    let ex = w.explain("d");
    assert!(ex.contains("d: SKIP"), "{ex}");
    let candidates: Vec<&str> = ex.split("\ncandidate ").skip(1).collect();
    assert_eq!(candidates.len(), 3, "{ex}");
    for (block, n) in candidates.iter().zip([2, 1, 0]) {
        assert!(
            block.contains(&format!(": sqlite project {}", keys[n])),
            "newest first: S{n}\n{ex}"
        );
        if n == 0 {
            assert!(block.contains("all checks passed"), "{ex}");
        } else {
            assert!(block.contains("failed check: inputs"), "{ex}");
            assert!(block.contains("entry:d/d.go"), "{ex}");
        }
    }
}

/// On a server (libSQL's remote mode) a plan reads only the candidates it
/// checks first (2.8.2: not each unit's newest two besides, a second
/// request of 30 to 45 MB per vex plan). A pull request's second push:
/// d's attestation remembered passing on main fails on d's edited inputs,
/// so the plan reads, in its second round, only the candidates issued
/// after it (the pull request's first push attested d as it is now) and
/// skips d with that one, never reading the older one from before main's.
#[test]
fn libsql_remote_reads_newer_candidates_after_an_inputs_failure() {
    let Some(b) = Backend::libsql_server(false) else {
        return;
    };
    let Some(w) = World::new(b) else {
        return;
    };
    let src = w.read("d/d.go");
    let state = |s: &str| format!("{src}\n// {s}\n");
    w.git(&w.work, &["checkout", "-q", "main"]);
    let mut keys = Vec::new();
    for s in ["old", "base"] {
        w.put("d/d.go", &state(s));
        w.commit(s);
        keys.push(attested_keys(&w.run(&["d"]), "libsql")["d"].clone());
        // A key's hint has whole seconds.
        std::thread::sleep(Duration::from_millis(1100));
    }
    // A plan of main remembers what passed on its tree.
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.by["d"].0, keys[1], "{plan:?}");

    w.git(&w.work, &["checkout", "-q", "-b", "pr"]);
    w.put("d/d.go", &state("pr"));
    w.commit("pr: d edited");
    keys.push(attested_keys(&w.run(&["d"]), "libsql")["d"].clone());
    w.touch("a/a.go", "unrelated");
    w.commit("pr: a edited");

    let (plan, out) = w.plan(&[("VCI_TIMING", "1")]);
    let err = stderr(&out);
    assert!(plan.skip.contains("d"), "{plan:?}\n{err}");
    assert_eq!(plan.by["d"].0, keys[2], "the pull request's own: {err}");
    assert!(
        err.contains("round 2: read 1 candidate(s) set aside"),
        "the newer one alone, in the second round: {err}"
    );
}

// ---------------------------------------------------------------------------
// 4. Fetch and push on a store without an exchange.

/// `vci fetch` and `vci push` say that there is nothing to exchange and
/// exit 0; `--remote` and `--rewrite-history` exit 2; nothing reaches the
/// git remote.
fn fetch_and_push(backend: Backend) {
    let kind = backend.kind;
    let Some(w) = World::new(backend) else { return };
    attest_all(&w);
    let reach = if w.backend.shared { "shared" } else { "local" };
    let location = w.info()["location"].as_str().unwrap().to_owned();

    let out = w.vci(&["fetch"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        stderr(&out),
        format!(
            "vci: the {kind} store at {location} is {reach}: nothing to fetch ({} attestations stored)\n",
            UNITS.len()
        )
    );
    let out = w.vci(&["push"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        stderr(&out),
        format!(
            "vci: nothing to push: the {kind} store is {reach}; attestations were stored when vci run made them\n"
        )
    );
    for (args, says) in [
        (&["fetch", "--remote", "x"][..], "a remote"),
        (&["push", "--remote", "x"], "a remote"),
        (&["push", "--rewrite-history"], "rewriting history"),
    ] {
        let out = w.vci(args, &[]);
        assert_eq!(out.status.code(), Some(2), "vci {args:?}: {}", text(&out));
        assert_eq!(
            stderr(&out),
            format!("vci: error: the {kind} store does not support {says}\n"),
            "vci {args:?}"
        );
    }
    assert!(!w.remote_has_meta(), "nothing was pushed to git");
    assert_eq!(w.info()["count"], UNITS.len());
    let file = |name: &str| w.work.join(".git").join(name).display().to_string();
    match (kind, w.backend.mode, &w.backend.server) {
        ("postgres", _, _) => {
            let db = w.backend.db.as_ref().unwrap();
            assert!(
                location.contains(&format!(" schema {} namespace test", db.schema)),
                "{location}"
            );
        }
        ("libsql", "local", _) => {
            assert_eq!(location, format!("{} (local)", file("vci-store.libsql")));
        }
        ("libsql", "remote", Some((url, ns))) => {
            assert_eq!(location, format!("{url} namespace {ns} (remote)"));
        }
        ("libsql", "replica", Some((url, ns))) => {
            assert_eq!(
                location,
                format!(
                    "{} (replica of {url} namespace {ns})",
                    file("vci-store.libsql")
                )
            );
        }
        _ => assert_eq!(location, file("vci-store.sqlite")),
    }
}

#[test]
fn sqlite_has_nothing_to_fetch_or_push() {
    fetch_and_push(Backend::sqlite());
}

#[test]
fn postgres_has_nothing_to_fetch_or_push() {
    let Some(b) = Backend::postgres() else { return };
    fetch_and_push(b);
}

#[test]
fn libsql_has_nothing_to_fetch_or_push() {
    fetch_and_push(Backend::libsql());
}

#[test]
fn libsql_remote_has_nothing_to_fetch_or_push() {
    let Some(b) = Backend::libsql_server(false) else {
        return;
    };
    fetch_and_push(b);
}

#[test]
fn libsql_replica_has_nothing_to_fetch_or_push() {
    let Some(b) = Backend::libsql_server(true) else {
        return;
    };
    fetch_and_push(b);
}

// ---------------------------------------------------------------------------
// 5. The publication gate of a shared store.

/// `vci ci` without `--push` on a shared store signs but stores nothing,
/// and says so; with `--push` it stores.
fn ci_stores_only_with_push(b: Backend) {
    let kind = b.kind;
    let Some(w) = World::new(b) else { return };
    let before = w.info();
    assert_eq!(before["status"], "absent", "{before}");
    assert_eq!(before["count"], 0, "{before}");

    let (out, audit) = w.ci(&[], &[], "audit-1.json");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let err = stderr(&out);
    assert!(
        err.contains(&format!(
            "vci: not storing {} attestation(s): the {kind} store is shared and vci ci was not given --push\n",
            UNITS.len()
        )),
        "{err}"
    );
    assert!(
        err.contains(&format!(
            "vci ci: {} unit(s) attested (not stored: the {kind} store is shared and --push was not given)\n",
            UNITS.len()
        )),
        "{err}"
    );
    assert!(!err.contains("vci: attested "), "{err}");
    let attested = audit["attested"].as_array().unwrap();
    assert_eq!(attested.len(), UNITS.len(), "{audit:#}");
    assert!(attested.iter().all(|a| a["stored"] == false), "{audit:#}");
    assert_eq!(audit["pushed"], false, "{audit:#}");
    assert_eq!(audit["exitCode"], 0, "{audit:#}");
    let after = w.info();
    assert_eq!(after["count"], 0, "nothing stored: {after}");
    assert_eq!(after["status"], "absent", "nothing written: {after}");
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.run, set(UNITS), "{plan:?}");

    let (out, audit) = w.ci(&["--push"], &[], "audit-2.json");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let err = stderr(&out);
    assert!(!err.contains("not storing"), "{err}");
    assert_eq!(attested_keys(&out, kind).len(), UNITS.len(), "{err}");
    assert!(
        err.contains(&format!("vci ci: {} unit(s) attested\n", UNITS.len())),
        "{err}"
    );
    let attested = audit["attested"].as_array().unwrap();
    assert_eq!(attested.len(), UNITS.len(), "{audit:#}");
    assert!(
        attested.iter().all(|a| a.get("stored").is_none()),
        "{audit:#}"
    );
    assert_eq!(audit["pushed"], true, "{audit:#}");
    let after = w.info();
    assert_eq!(after["count"], UNITS.len(), "{after}");
    assert_eq!(after["status"], "ready", "{after}");
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.skip, set(UNITS), "{plan:?}");
}

#[test]
fn postgres_ci_stores_only_with_push() {
    let Some(b) = Backend::postgres() else { return };
    ci_stores_only_with_push(b);
}

#[test]
fn libsql_remote_ci_stores_only_with_push() {
    let Some(b) = Backend::libsql_server(false) else {
        return;
    };
    ci_stores_only_with_push(b);
}

#[test]
fn libsql_replica_ci_stores_only_with_push() {
    let Some(b) = Backend::libsql_server(true) else {
        return;
    };
    ci_stores_only_with_push(b);
}

// ---------------------------------------------------------------------------
// 6. PostgreSQL that cannot be reached.

/// A PostgreSQL URL with a password on a closed port: the plan exits 0
/// quickly and runs everything; the password appears in no output, log or
/// test environment.
#[test]
fn unreachable_postgres_fails_open_and_keeps_its_secret() {
    let Some(w) = World::new(Backend::git_meta()) else {
        return;
    };
    let dump = w.base.join("env-dump.txt");
    w.put("envdump/envdump_test.go", &envdump_test(&dump));
    w.commit("envdump");
    let all = set(&["a", "b", "c", "d", "envdump"]);
    let url = format!("postgres://u:{SECRET}@127.0.0.1:{}/x", closed_port());
    let env = [("VCI_STORE_URL", url.as_str())];

    let t = Instant::now();
    let (plan, out) = w.plan(&env);
    let took = t.elapsed();
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert_eq!(plan.run, all, "{plan:?}");
    assert!(plan.skip.is_empty());
    let err = stderr(&out);
    assert!(err.contains("vci: warning: "), "{err}");
    assert!(err.contains("postgres"), "{err}");
    let mut outs = vec![out];

    // The run: the tests run (exit 0), nothing is stored, and the test
    // process never sees the URL.
    let key = w.key.to_str().unwrap().to_owned();
    let out = w.vci(&["run", "--key", &key], &env);
    assert_eq!(
        out.status.code(),
        Some(0),
        "the tests' exit code: {}",
        text(&out)
    );
    for u in UNITS {
        assert!(
            stderr(&out).contains(&format!(
                "vci: not attesting {u}: signing or storing failed: "
            )),
            "{u}: {}",
            text(&out)
        );
    }
    assert!(!stderr(&out).contains("vci: attested "), "{}", text(&out));
    outs.push(out);
    let dumped = std::fs::read_to_string(&dump).expect("the envdump test ran");
    assert!(dumped.starts_with("getenv:\n"), "{dumped}");
    assert!(
        !dumped.lines().any(|l| l.starts_with("VCI_STORE_URL=")),
        "{dumped}"
    );
    assert!(!dumped.contains(SECRET), "{dumped}");

    let (out, audit) = w.ci(&[], &env, "audit.json");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(audit["exitCode"], 0);
    let audit_text = serde_json::to_string(&audit).unwrap();
    assert!(!audit_text.contains(SECRET), "{audit_text}");
    assert!(
        audit_text.contains("postgres"),
        "the errors say why: {audit_text}"
    );
    outs.push(out);
    for args in [
        &["env"][..],
        &["store", "info"],
        &["store", "info", "--format", "json"],
        &["fetch"],
        &["push"],
    ] {
        outs.push(w.vci(args, &env));
    }
    for out in &outs {
        assert!(!text(out).contains(SECRET), "{}", text(out));
    }
    let log = std::fs::read_to_string(&w.metrics).unwrap();
    assert!(!log.contains(SECRET), "{log}");
    assert!(log.contains("\"store\":\"postgres\""), "{log}");
    assert!(!w.remote_has_meta());
}

/// A port on 127.0.0.1 where something accepts connections and never
/// answers (a frozen server, a stuck proxy).
fn silent_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for c in l.incoming() {
            held.push(c);
        }
    });
    port
}

/// A PostgreSQL URL whose server accepts and never answers: every command
/// gives up within the connect timeout. The plan exits 0 and runs
/// everything, `vci run` runs the tests and refuses to store, and store
/// info, fetch, push and prune exit 2; no output shows the password.
#[test]
fn a_postgres_server_that_never_answers_fails_open_in_time() {
    let Some(w) = World::new(Backend::git_meta()) else {
        return;
    };
    let url = format!(
        "postgres://u:{SECRET}@127.0.0.1:{}/x?sslmode=disable",
        silent_port()
    );
    let mut outs = Vec::new();
    // The default connect timeout (5 s).
    let env = [("VCI_STORE_URL", url.as_str())];
    let t = Instant::now();
    let (plan, out) = w.plan(&env);
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    assert_eq!(plan.run, set(UNITS), "{plan:?}");
    assert!(stderr(&out).contains("postgres"), "{}", text(&out));
    outs.push(out);
    // The rest with a 1 s timeout, to keep the test short.
    let env = [
        ("VCI_STORE_URL", url.as_str()),
        ("VCI_STORE_CONNECT_TIMEOUT_SECS", "1"),
    ];
    let key = w.key.to_str().unwrap().to_owned();
    let t = Instant::now();
    let out = w.vci(&["run", "--key", &key], &env);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    for u in UNITS {
        assert!(
            stderr(&out).contains(&format!(
                "vci: not attesting {u}: signing or storing failed: "
            )),
            "{u}: {}",
            text(&out)
        );
    }
    assert!(t.elapsed() < Duration::from_secs(60), "{:?}", t.elapsed());
    outs.push(out);
    for args in [
        &["store", "info"][..],
        &["store", "info", "--format", "json"],
        &["fetch"],
        &["push"],
        &["prune"],
    ] {
        let t = Instant::now();
        let out = w.vci(args, &env);
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "{args:?}: {:?}",
            t.elapsed()
        );
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out));
        outs.push(out);
    }
    for out in &outs {
        assert!(!text(out).contains(SECRET), "{}", text(out));
    }
}

/// A libSQL server on a closed port, with a token in the URL and another
/// in `VCI_STORE_TOKEN`, used remotely and through a replica: the plan
/// exits 0 within seconds and runs everything; `vci run` runs the tests
/// (exit 0) and stores nothing; neither token, nor the URL, reaches any
/// output, the audit log, the metrics log or a test's environment. `vci
/// store info`, `fetch`, `push` and `prune` exit 2, remote and replica (a
/// replica the plan reads as it is, with a warning, is not read for them);
/// the replica is not created.
#[test]
fn unreachable_libsql_fails_open_and_keeps_its_tokens() {
    const IN_URL: &str = "s3cretUrlTok";
    const IN_ENV: &str = "s3cretEnvTok";
    let Some(w) = World::new(Backend::git_meta()) else {
        return;
    };
    let dump = w.base.join("env-dump.txt");
    w.put("envdump/envdump_test.go", &envdump_test(&dump));
    w.commit("envdump");
    let all = set(&["a", "b", "c", "d", "envdump"]);
    let url = format!(
        "libsql://127.0.0.1:{}/?tls=0&authToken={IN_URL}",
        closed_port()
    );
    let key = w.key.to_str().unwrap().to_owned();
    for (i, replica) in [false, true].into_iter().enumerate() {
        let mut env = vec![
            ("VCI_STORE_URL", url.as_str()),
            ("VCI_STORE_TOKEN", IN_ENV),
            ("VCI_STORE_NAMESPACE", "ns"),
        ];
        if replica {
            env.push(("VCI_STORE_SYNC", "replica"));
        }
        let mut outs = Vec::new();
        let t = Instant::now();
        let (plan, out) = w.plan(&env);
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        assert_eq!(plan.run, all, "{plan:?}");
        assert!(stderr(&out).contains("libsql"), "{}", text(&out));
        outs.push(out);

        let _ = std::fs::remove_file(&dump);
        let out = w.vci(&["run", "--key", &key], &env);
        assert_eq!(
            out.status.code(),
            Some(0),
            "the tests' exit code: {}",
            text(&out)
        );
        for u in UNITS {
            assert!(
                stderr(&out).contains(&format!(
                    "vci: not attesting {u}: signing or storing failed: "
                )),
                "{u}: {}",
                text(&out)
            );
        }
        assert!(!stderr(&out).contains("vci: attested "), "{}", text(&out));
        outs.push(out);
        let dumped = std::fs::read_to_string(&dump).expect("the envdump test ran");
        assert!(dumped.starts_with("getenv:\n"), "{dumped}");
        for name in ["VCI_STORE_URL=", "VCI_STORE_TOKEN=", "VCI_STORE="] {
            assert!(!dumped.lines().any(|l| l.starts_with(name)), "{dumped}");
        }
        assert!(!dumped.contains("s3cret"), "{dumped}");

        let (out, audit) = w.ci(&[], &env, &format!("audit-libsql-{i}.json"));
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        assert_eq!(audit["exitCode"], 0);
        let audit_text = serde_json::to_string(&audit).unwrap();
        assert!(!audit_text.contains("s3cret"), "{audit_text}");
        outs.push(out);
        for args in [
            &["env"][..],
            &["store", "info"],
            &["store", "info", "--format", "json"],
            &["fetch"],
            &["push"],
            &["prune"],
            &["prune", "--dry-run"],
        ] {
            let t = Instant::now();
            let out = w.vci(args, &env);
            assert!(t.elapsed() < Duration::from_secs(10), "{args:?}");
            if args[0] != "env" {
                assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out));
                if replica {
                    assert!(
                        text(&out).contains("cannot sync the replica "),
                        "{args:?}: {}",
                        text(&out)
                    );
                }
            }
            outs.push(out);
        }
        for out in &outs {
            assert!(!text(out).contains("s3cret"), "{}", text(out));
        }
        assert!(!w.work.join(".git/vci-store.libsql").exists());
        assert!(!w.work.join(".git/vci-store.libsql.sync").exists());
    }
    let log = std::fs::read_to_string(&w.metrics).unwrap();
    assert!(!log.contains("s3cret"), "{log}");
    assert!(log.contains("\"store\":\"libsql\""), "{log}");
    assert!(!w.remote_has_meta());
}

/// A libSQL server that accepts and never answers (a frozen server, a
/// stuck proxy) over plain HTTP, used remotely and through a replica: with
/// the default timeouts the plan exits 0 within the connect timeout (5 s)
/// and runs everything, `vci run` runs the tests and refuses to store, and
/// store info, fetch, push and prune (whose requests may take ten
/// minutes) exit 2 within the connect timeout; no output shows a token.
#[test]
fn a_libsql_server_that_never_answers_fails_open_in_time() {
    const TOKEN: &str = "s3cretSilentTok";
    let Some(w) = World::new(Backend::git_meta()) else {
        return;
    };
    let url = format!("libsql://127.0.0.1:{}?tls=0", silent_port());
    let key = w.key.to_str().unwrap().to_owned();
    for replica in [false, true] {
        let mut env = vec![
            ("VCI_STORE_URL", url.as_str()),
            ("VCI_STORE_TOKEN", TOKEN),
            ("VCI_STORE_NAMESPACE", "ns"),
        ];
        if replica {
            env.push(("VCI_STORE_SYNC", "replica"));
        }
        let mut outs = Vec::new();
        let t = Instant::now();
        let (plan, out) = w.plan(&env);
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        assert_eq!(plan.run, set(UNITS), "{plan:?}");
        assert!(stderr(&out).contains("libsql"), "{}", text(&out));
        outs.push(out);
        let t = Instant::now();
        let out = w.vci(&["run", "--key", &key], &env);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        for u in UNITS {
            assert!(
                stderr(&out).contains(&format!(
                    "vci: not attesting {u}: signing or storing failed: "
                )),
                "{u}: {}",
                text(&out)
            );
        }
        assert!(t.elapsed() < Duration::from_secs(60), "{:?}", t.elapsed());
        outs.push(out);
        for args in [
            &["store", "info"][..],
            &["store", "info", "--format", "json"],
            &["fetch"],
            &["push"],
            &["prune"],
            &["prune", "--dry-run"],
        ] {
            let t = Instant::now();
            let out = w.vci(args, &env);
            assert!(
                t.elapsed() < Duration::from_secs(10),
                "{args:?}: {:?}",
                t.elapsed()
            );
            assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out));
            outs.push(out);
        }
        for out in &outs {
            assert!(!text(out).contains(TOKEN), "{}", text(out));
        }
    }
}

/// A port where a server answers every request with `response` (a whole
/// HTTP response), then closes the connection.
fn canned_port(response: Vec<u8>) -> u16 {
    use std::io::{Read as _, Write as _};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let response = response.clone();
            std::thread::spawn(move || {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).to_ascii_lowercase();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if got.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                let _ = c.write_all(&response);
            });
        }
    });
    port
}

/// A proxy whose error page is not UTF-8 text (a Latin-1 502), on which
/// libsql 0.10.0 panics: the plan exits 0 and runs everything, `vci run`
/// runs the tests (exit 0) and refuses to store, store info and prune exit
/// 2; nothing panics, remote and replica.
#[test]
fn a_libsql_error_page_the_client_cannot_read_fails_open() {
    let Some(w) = World::new(Backend::git_meta()) else {
        return;
    };
    let body: &[u8] = b"<html>Mauvaise passerelle \xe9t\xe9</html>";
    let mut response = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html; charset=iso-8859-1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    let url = format!("libsql://127.0.0.1:{}?tls=0", canned_port(response));
    let key = w.key.to_str().unwrap().to_owned();
    for replica in [false, true] {
        let mut env = vec![
            ("VCI_STORE_URL", url.as_str()),
            ("VCI_STORE_TOKEN", "tok"),
            ("VCI_STORE_NAMESPACE", "ns"),
        ];
        if replica {
            env.push(("VCI_STORE_SYNC", "replica"));
        }
        let (plan, out) = w.plan(&env);
        assert_eq!(plan.run, set(UNITS), "{plan:?}");
        let mut outs = vec![out];
        let out = w.vci(&["run", "--key", &key], &env);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        for u in UNITS {
            assert!(
                stderr(&out).contains(&format!(
                    "vci: not attesting {u}: signing or storing failed: "
                )),
                "{u}: {}",
                text(&out)
            );
        }
        outs.push(out);
        for args in [&["store", "info"][..], &["prune"]] {
            let out = w.vci(args, &env);
            assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out));
            outs.push(out);
        }
        for out in &outs {
            assert!(!text(out).contains("panicked"), "{}", text(out));
        }
    }
}

/// A token in `VCI_STORE_URL` under any query key, as a bare key, or in
/// the path, and one under a misspelled key of `vci.toml`'s `[store]`, is
/// in no output of `vci store info` (text and JSON), `vci env`, `vci run`
/// or `vci plan`. No server is needed: every URL is refused, or
/// unreachable.
#[test]
fn a_libsql_token_anywhere_in_the_settings_is_never_printed() {
    const TOKEN: &str = "eyJhbGciOiJFZERTQSJ9.s3cretTokBody.s1gnature";
    let Some(w) = World::new(Backend::git_meta()) else {
        return;
    };
    let port = closed_port();
    let urls = [
        format!("libsql://127.0.0.1:{port}?tls=0&token={TOKEN}"),
        format!("libsql://127.0.0.1:{port}?tls=0&jwt={TOKEN}"),
        format!("libsql://127.0.0.1:{port}?tls=0&Auth-Token={TOKEN}"),
        format!("libsql://127.0.0.1:{port}?{TOKEN}"),
        format!("libsql://127.0.0.1:{port}?authToken%3D{TOKEN}"),
        format!("libsql://127.0.0.1:{port}/{TOKEN}?tls=0"),
    ];
    let key = w.key.to_str().unwrap().to_owned();
    let mut outs = Vec::new();
    for url in &urls {
        let env = [
            ("VCI_STORE_URL", url.as_str()),
            ("VCI_STORE_NAMESPACE", "s7"),
        ];
        for args in [
            &["store", "info"][..],
            &["store", "info", "--format", "json"],
            &["env"],
        ] {
            outs.push(w.vci(args, &env));
        }
        let (plan, out) = w.plan(&env);
        assert_eq!(plan.run, set(UNITS), "{plan:?}");
        outs.push(out);
    }
    // The run, once (the rest is the same selection).
    let env = [
        ("VCI_STORE_URL", urls[0].as_str()),
        ("VCI_STORE_NAMESPACE", "s7"),
    ];
    outs.push(w.vci(&["run", "--key", &key], &env));
    // A token under a key `[store.libsql]` does not have.
    let toml = w.read("vci.toml");
    w.put(
        "vci.toml",
        &format!(
            "{toml}
[store.libsql]
authtoken = \"{TOKEN}\"\n"
        ),
    );
    w.commit("a misspelled token key");
    for env in [
        &[("VCI_STORE", "libsql")][..],
        &[("VCI_STORE_URL", urls[0].as_str())],
        &[],
    ] {
        for args in [&["run", "--key", &key][..], &["env"], &["store", "info"]] {
            let out = w.vci(args, env);
            assert_ne!(out.status.code(), Some(0), "{args:?}: {}", text(&out));
            outs.push(out);
        }
    }
    for out in &outs {
        assert!(!text(out).contains("s3cretTokBody"), "{}", text(out));
    }
}

/// A connection string put in `VCI_STORE` by mistake is refused, never
/// printed (in any output, the plan, the audit log) and never reaches a
/// test process.
#[test]
fn a_connection_string_in_vci_store_reaches_no_test_and_no_output() {
    let Some(w) = World::new(Backend::git_meta()) else {
        return;
    };
    let dump = w.base.join("env-dump.txt");
    w.put("envdump/envdump_test.go", &envdump_test(&dump));
    w.commit("envdump");
    let all = set(&["a", "b", "c", "d", "envdump"]);
    let key = w.key.to_str().unwrap().to_owned();
    for (i, value) in [
        format!("postgres://vci:{SECRET}@127.0.0.1:{}/x", closed_port()),
        format!("host=127.0.0.1 password = '{SECRET} x'"),
    ]
    .iter()
    .enumerate()
    {
        let env = [("VCI_STORE", value.as_str())];
        let mut outs = Vec::new();
        let (plan, out) = w.plan(&env);
        assert_eq!(plan.run, all, "{plan:?}");
        outs.push(out);
        let _ = std::fs::remove_file(&dump);
        let out = w.vci(&["run", "--key", &key], &env);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        outs.push(out);
        let dumped = std::fs::read_to_string(&dump).expect("the envdump test ran");
        assert!(
            !dumped.lines().any(|l| l.starts_with("VCI_STORE=")),
            "{dumped}"
        );
        assert!(!dumped.contains(SECRET), "{dumped}");
        let (out, audit) = w.ci(&[], &env, &format!("audit-{i}.json"));
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        let audit_text = serde_json::to_string(&audit).unwrap();
        assert!(!audit_text.contains(SECRET), "{audit_text}");
        outs.push(out);
        for args in [
            &["store", "info"][..],
            &["store", "info", "--format", "json"],
            &["fetch"],
        ] {
            let out = w.vci(args, &env);
            assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out));
            outs.push(out);
        }
        for out in &outs {
            assert!(!text(out).contains(SECRET), "{}", text(out));
        }
    }
}

/// With git-meta selected, a libpq `VCI_STORE_URL` is ignored with a
/// warning that shows no part of its password, however the string writes
/// it (spaces around `=`, quotes), in any output, the plan or the audit
/// log.
#[test]
fn a_password_git_meta_ignores_is_never_printed() {
    let Some(w) = World::new(Backend::git_meta()) else {
        return;
    };
    let key = w.key.to_str().unwrap().to_owned();
    for (i, url) in [
        "host=db.example password = Gm3taLeakQ",
        "host=db.example password='Gm3taLeakQ x'",
        "postgress://u:Gm3ta/LeakQ@db.example/x",
    ]
    .iter()
    .enumerate()
    {
        let env = [("VCI_STORE_URL", *url)];
        let mut outs = Vec::new();
        let (plan, out) = w.plan(&env);
        assert!(
            plan.warnings
                .iter()
                .any(|m| m.contains("is ignored by the git-meta store")),
            "{plan:?}"
        );
        outs.push(out);
        let out = w.vci(&["run", "--key", &key], &env);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        outs.push(out);
        let (out, audit) = w.ci(&[], &env, &format!("audit-{i}.json"));
        let audit_text = serde_json::to_string(&audit).unwrap();
        assert!(!audit_text.contains("Gm3ta"), "{audit_text}");
        assert!(!audit_text.contains("LeakQ"), "{audit_text}");
        outs.push(out);
        for args in [
            &["store", "info"][..],
            &["store", "info", "--format", "json"],
        ] {
            outs.push(w.vci(args, &env));
        }
        for out in &outs {
            assert!(!text(out).contains("Gm3ta"), "{}", text(out));
            assert!(!text(out).contains("LeakQ"), "{}", text(out));
        }
    }
}

// ---------------------------------------------------------------------------
// 7. SQLite that cannot be used.

/// What a store that cannot be used does: the plan runs everything (exit
/// 0), saying `says_plan` in a warning or as the reason it runs everything
/// (`runAll`), and `vci run` refuses to store
/// each unit saying `says_run`, with the tests' exit code.
fn sqlite_fails_open(w: &World, env: &[(&str, &str)], says_plan: &str, says_run: &str) {
    let (plan, out) = w.plan(env);
    assert_eq!(plan.run, set(UNITS), "{plan:?}");
    assert!(plan.skip.is_empty());
    let said = format!("{}{}", stderr(&out), plan.run_all.unwrap_or_default());
    assert!(said.contains(says_plan), "{says_plan:?}: {said}");
    let key = w.key.to_str().unwrap().to_owned();
    let out = w.vci(&["run", "--key", &key], env);
    assert_eq!(
        out.status.code(),
        Some(0),
        "the tests' exit code: {}",
        text(&out)
    );
    for u in UNITS {
        let line = stderr(&out)
            .lines()
            .find(|l| l.starts_with(&format!("vci: not attesting {u}: ")))
            .unwrap_or_else(|| panic!("{u} refused: {}", text(&out)))
            .to_owned();
        assert!(line.contains("signing or storing failed: "), "{line}");
        assert!(line.contains(says_run), "{says_run:?}: {line}");
    }
    assert!(!stderr(&out).contains("vci: attested "), "{}", text(&out));
    assert!(!stderr(&out).contains("vci: error"), "{}", text(&out));
}

/// A file that is not a database at the configured path: every use fails
/// at once, and the file is left as it was.
#[test]
fn sqlite_on_a_garbage_file_fails_open() {
    let Some(w) = World::new(Backend::sqlite()) else {
        return;
    };
    let path = w.work.join(".git/vci-store.sqlite");
    let garbage =
        b"this is not a database, but it is long enough to look like one maybe\n".repeat(64);
    std::fs::write(&path, &garbage).unwrap();
    sqlite_fails_open(
        &w,
        &[],
        "reading attestations from sqlite: sqlite store unavailable: ",
        "sqlite store unavailable: ",
    );
    let out = w.vci(&["store", "info"], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert_eq!(std::fs::read(&path).unwrap(), garbage, "left untouched");
}

/// A store in a directory vci may not write: reads find nothing (an
/// absent store), and the first write is refused.
#[test]
fn sqlite_in_an_unwritable_directory_fails_open() {
    if testkit::running_as_root() {
        eprintln!("SKIPPED: running as root, which may write anywhere");
        return;
    }
    let Some(w) = World::new(Backend::git_meta()) else {
        return;
    };
    let dir = w.base.join("read-only");
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("store.sqlite");
    let url = format!("sqlite:{}", file.to_str().unwrap());
    let set_mode = |mode: u32| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    set_mode(0o555);
    let env = [("VCI_STORE_URL", url.as_str())];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sqlite_fails_open(
            &w,
            &env,
            "no attestations are available in the sqlite store (the first `vci run` creates it)",
            "sqlite store refused to create the store",
        );
        assert!(!file.exists(), "nothing was created");
    }));
    set_mode(0o755);
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

// ---------------------------------------------------------------------------
// 8. Nothing configured.

/// With no store configured the store is git-meta: `vci run` stores there,
/// `vci push` publishes `refs/meta/main`, and no other store's file
/// appears.
#[test]
fn nothing_configured_is_git_meta_and_pushes() {
    let Some(w) = World::new(Backend::git_meta()) else {
        return;
    };
    let out = w.vci(&["store", "info"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).starts_with("store: git-meta\n"),
        "{}",
        text(&out)
    );
    attest_all(&w);
    let out = w.vci(&["push"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(w.remote_has_meta(), "refs/meta/main was pushed");
    let info = w.info();
    assert_eq!(info["kind"], "git-meta");
    assert_eq!(info["exchange"], "refs/meta/main");
    assert_eq!(info["count"], UNITS.len());
    assert!(w.work.join(".git/git-meta.sqlite").exists());
    assert!(!w.work.join(".git/vci-store.sqlite").exists());
    assert!(!w.work.join(".git/vci-store.libsql").exists());
    let log = std::fs::read_to_string(&w.metrics).unwrap();
    let last: Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    assert_eq!(last["store"], "git-meta");
}

// ---------------------------------------------------------------------------
// A store that refuses some writes.

/// A libSQL server that takes no more writes (`sqld`'s write block, what a
/// Turso database over its quota gets): `vci run`, remote and through a
/// replica, runs the tests, refuses to store each unit saying why, and
/// exits as the tests did, not 2; the plan still reads the store. On a
/// `sqld` of the test's own (the block holds for the whole server).
#[test]
fn a_libsql_server_that_blocks_writes_keeps_the_tests_exit_code() {
    let Some(w) = World::new(Backend::git_meta()) else {
        return;
    };
    let (server, admin) = match libsql_kit::start_sqld_with_admin() {
        Ok(s) => s,
        Err(why) => {
            eprintln!("SKIPPED: no sqld to block writes on: {why}");
            return;
        }
    };
    let url = server.url();
    let key = w.key.to_str().unwrap().to_owned();
    let env = [
        ("VCI_STORE", "libsql"),
        ("VCI_STORE_URL", url.as_str()),
        ("VCI_STORE_NAMESPACE", "quota"),
    ];
    let out = w.vci(&["run", "--key", &key], &env);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        attested_keys(&out, "libsql").len(),
        UNITS.len(),
        "{}",
        text(&out)
    );
    libsql_kit::set_config(
        admin,
        &serde_json::json!({"block_writes": true, "block_reason": "storage quota exceeded"}),
    )
    .unwrap();
    for (i, replica) in [false, true].into_iter().enumerate() {
        w.touch("a/a.go", &format!("blocked {i}"));
        w.touch("b/b.go", &format!("blocked {i}"));
        w.commit(&format!("blocked {i}"));
        let mut env = env.to_vec();
        if replica {
            env.push(("VCI_STORE_SYNC", "replica"));
        }
        let out = w.vci(&["run", "--key", &key], &env);
        let all = text(&out);
        assert_eq!(out.status.code(), Some(0), "the tests' exit code: {all}");
        for u in UNITS {
            assert!(
                stderr(&out).contains(&format!(
                    "vci: not attesting {u}: signing or storing failed: "
                )),
                "{u}: {all}"
            );
        }
        assert!(all.contains("storage quota exceeded"), "{all}");
        assert!(!all.contains("problem(s)"), "{all}");
        assert!(!stderr(&out).contains("vci: attested "), "{all}");
        // Reads go on: the units left alone still skip.
        let (plan, _) = w.plan(&env);
        assert_eq!(plan.skip, set(&["c", "d"]), "{plan:?}");
        assert_eq!(plan.run, set(&["a", "b"]), "{plan:?}");
    }
    drop(server);
}

/// A shared input manifest the store refuses (here a trigger refuses every
/// manifest that lists no test file, which only the units' shared base
/// does; on a libSQL server a base of 5,000,000 bytes or more is refused
/// the same way) is not relied on: each unit's manifest is stored whole
/// instead, so every unit `vci run` reports attested verifies, and the
/// next plan skips it. A format-1 run (`record_format = 1`): a format-3
/// run stores no manifest.
#[test]
fn a_shared_input_manifest_the_store_refuses_is_not_relied_on() {
    use vci_store::AttestationStore as _;
    let Some(b) = Backend::libsql_server(false) else {
        return;
    };
    let ns = b.server.as_ref().unwrap().1.clone();
    let Some(w) = World::new(b) else { return };
    // The namespace's tables, then the trigger on its manifests.
    let s = libsql_kit::open_remote(&ns).unwrap();
    let e = s
        .put_for_test("src/setup.test.ts", "1111111111111111", "00", None, b"{}")
        .unwrap();
    s.remove(vec![e]).unwrap();
    let p = vci_store_libsql::table_prefix(&ns);
    s.__execute_for_test(&[format!(
        "CREATE TRIGGER {p}no_bases BEFORE INSERT ON {p}manifests \
         WHEN instr(CAST(NEW.value AS TEXT), '_test.go') = 0 \
         BEGIN SELECT RAISE(ABORT, 'no shared manifests here'); END"
    )])
    .unwrap();
    let key = w.key.to_str().unwrap().to_owned();
    let out = w.vci(&["run", "--key", &key], &[("VCI_STORE_RECORD_FORMAT", "1")]);
    let all = text(&out);
    assert!(
        all.contains("vci: warning: storing the units' shared input manifest: ")
            && all.contains("no shared manifests here"),
        "the base was refused: {all}"
    );
    let attested = attested_keys(&out, "libsql");
    assert_eq!(attested.len(), UNITS.len(), "{all}");
    assert_eq!(out.status.code(), Some(0), "{all}");
    let (plan, _) = w.plan(&[]);
    assert_eq!(
        plan.skip,
        set(UNITS),
        "every unit attested verifies: {plan:?}"
    );
    let ex = w.explain("a");
    assert!(ex.contains("a: SKIP"), "{ex}");
}

// ---------------------------------------------------------------------------
// 9. A vci 2.8 binary on a SQLite file and a git-meta store this vci wrote.

/// The vci 2.8 binary `VCI_TEST_VCI_2_8` names, or `None` (the test is
/// skipped, with a message) when it is unset. What it names must say it
/// is a 2.8 when asked `--version`, and must not be this build's own vci
/// (whose version is still a 2.8.x while this branch is unreleased, so
/// the version alone cannot tell them apart): with the branch's binary the
/// test below would pass without a 2.8 involved, since its plan and run
/// are still the format-1 paths at M2.
fn vci_2_8() -> Option<PathBuf> {
    let Some(p) = std::env::var_os("VCI_TEST_VCI_2_8") else {
        eprintln!("SKIPPED: VCI_TEST_VCI_2_8 names no vci 2.8 binary");
        return None;
    };
    let p = PathBuf::from(p);
    let out = Command::new(&p)
        .arg("--version")
        .output()
        .unwrap_or_else(|e| panic!("VCI_TEST_VCI_2_8={}: {e}", p.display()));
    let v = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    assert!(
        v.starts_with("vci 2.8."),
        "VCI_TEST_VCI_2_8={} says {v:?}, not a vci 2.8",
        p.display()
    );
    let ours = Path::new(env!("CARGO_BIN_EXE_vci"));
    let same = std::fs::read(&p).unwrap_or_default() == std::fs::read(ours).unwrap_or_default();
    assert!(
        !same,
        "VCI_TEST_VCI_2_8={} is this build's own vci ({}), not a 2.8: build one from a 2.8 commit (e6244e7)",
        p.display(),
        ours.display()
    );
    Some(p)
}

/// A vci 2.8 binary on the SQLite file this vci wrote (STORE-V2 section 5,
/// gate 2): `vci run` laid out the format-3 columns and the `objects`
/// table, stored the run's four objects and, for every unit, a format-3
/// frame with its columns. 2.8 plans with no error: it lists the keys
/// (which did not change), reads values it cannot parse and runs every
/// unit (fail open); its `vci explain` and `vci prune --dry-run` exit 0
/// too; and its own `vci run a` stores a format-1 value, which this vci
/// reads (every unit skipped, a on 2.8's row) beside the objects 2.8 never
/// saw. 2.8 writes into the slot a's frame holds (same inputs, same
/// storage key; the key's hint is its own) and its upsert sets the key and
/// the value alone: the frame's columns stay beside the format-1 value,
/// which every reader of the columns treats as a pre-filter confirmed by a
/// read (`decode_record` goes by the value's first byte), so that the only
/// effect is that the frame's objects stay referenced while the row lives.
/// Were 2.8 to take another slot, the frame would stay as it was.
#[test]
fn a_2_8_binary_fails_open_on_a_format_3_sqlite_file() {
    let Some(old) = vci_2_8() else {
        return;
    };
    let Some(w) = World::new(Backend::sqlite()) else {
        return;
    };
    let out = attest_all(&w);
    let keys = attested_keys(&out, "sqlite");
    let file = w.work.join(".git/vci-store.sqlite");

    // What this vci wrote, through the trait: frames with columns naming
    // the run's objects, which are stored.
    let (columns, ids) = {
        let s = SqliteStore::open_path(&file, SqliteOptions::default());
        let caps = s.caps();
        assert!(
            caps.objects && caps.columns,
            "the file this vci wrote has the format-3 layout: {caps:?}"
        );
        let all = s.read_all().unwrap();
        assert_eq!(all.len(), UNITS.len());
        let columns = s.columns(&all.iter().collect::<Vec<_>>()).unwrap();
        let mut ids: BTreeSet<String> = BTreeSet::new();
        for (e, c) in all.iter().zip(&columns) {
            assert!(
                matches!(decode_record(&e.bytes), Ok(Record::FormatThree(_))),
                "{}: a format-3 frame",
                e.key
            );
            assert_eq!(c.format, Some(3), "{}: {c:?}", e.key);
            ids.extend(c.object_ids().map(str::to_owned));
        }
        assert_eq!(ids.len(), 4, "hdr, tables, shape, state: {ids:?}");
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        assert_eq!(s.get_objects(&refs).unwrap().len(), 4);
        let a = all
            .iter()
            .position(|e| e.key == keys["a"])
            .expect("a's record");
        (columns[a].clone(), ids)
    };
    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();

    // 2.8 plans: exit 0, nothing it calls an error, every unit runs.
    let out = w.vci_other(&old, &["plan", "--base-ref", "main", "--format", "json"]);
    let plan = parse_plan(&out);
    assert_eq!(plan.run, set(UNITS), "{plan:?}");
    assert!(plan.skip.is_empty(), "{plan:?}");
    assert!(
        !stderr(&out).contains("error"),
        "2.8 reports no error:\n{}",
        stderr(&out)
    );
    let out = w.vci_other(&old, &["explain", "a", "--base-ref", "main"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = w.vci_other(&old, &["prune", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    {
        let s = SqliteStore::open_path(&file, SqliteOptions::default());
        assert_eq!(
            s.list_all().unwrap().len(),
            UNITS.len(),
            "2.8 removed nothing"
        );
        assert_eq!(s.get_objects(&id_refs).unwrap().len(), 4);
    }

    // 2.8 runs a and stores it as it always did.
    let key_path = w.key.to_str().unwrap().to_owned();
    let out = w.vci_other(&old, &["run", "a", "--key", &key_path]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let new_keys = attested_keys(&out, "sqlite");
    assert_eq!(new_keys.len(), 1, "{}", text(&out));
    let new_key = &new_keys["a"];

    // This vci skips every unit, a on 2.8's row.
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.skip, set(UNITS), "{plan:?}");
    assert_eq!(plan.by["a"].0, *new_key, "{plan:?}");
    let s = SqliteStore::open_path(&file, SqliteOptions::default());
    let all = s.read_all().unwrap();
    let row = all.iter().find(|e| e.key == *new_key).expect("2.8's row");
    assert!(
        matches!(decode_record(&row.bytes), Ok(Record::FormatOne(_))),
        "a format-1 value"
    );
    let got = s.columns(&[row]).unwrap().remove(0);
    if slot_and_tree(new_key).0 == slot_and_tree(&keys["a"]).0 {
        assert_ne!(*new_key, keys["a"], "2.8's own hint");
        assert_eq!(
            got, columns,
            "2.8 wrote into the frame's slot and set the key and the value alone: the frame's columns stay"
        );
    } else {
        assert_eq!(got, Columns::default(), "a new row has no columns");
        let f = all
            .iter()
            .find(|e| e.key == keys["a"])
            .expect("the frame is still there when 2.8 took another slot");
        assert!(matches!(
            decode_record(&f.bytes),
            Ok(Record::FormatThree(_))
        ));
        assert_eq!(s.columns(&[f]).unwrap(), vec![columns]);
    }
    assert_eq!(
        s.get_objects(&id_refs).unwrap().len(),
        4,
        "the objects are untouched"
    );
    // 2.8's explain of a reads its own row.
    let out = w.vci_other(&old, &["explain", "a", "--base-ref", "main"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(stdout(&out).contains("a: SKIP"), "{}", text(&out));
    // This vci's prune reads the value under the frame's columns (the
    // store holds a manifest: the migration window) and finds its
    // manifest referenced: nothing is listed, nothing removed.
    let roots = s.manifest_roots().unwrap();
    assert!(!roots.is_empty(), "2.8 stored a's manifest");
    let (listed, summary) = prune_dry_run(&w);
    assert!(listed.is_empty(), "{listed:?}\n{summary}");
    let out = w.vci(&["prune"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out), "", "{}", text(&out));
    assert_eq!(s.manifest_roots().unwrap(), roots);
    assert_eq!(s.list_all().unwrap().len(), UNITS.len());
    // 2.8's own prune on the mixed store removes no manifest (STORE-V2
    // section 5 step 3: a record it cannot read keeps every manifest).
    let out = w.vci_other(&old, &["prune", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        !stdout(&out).contains("vci:manifest:"),
        "2.8 would remove no manifest: {}",
        text(&out)
    );
    let out = w.vci_other(&old, &["prune"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        s.manifest_roots().unwrap(),
        roots,
        "2.8 removed no manifest"
    );
    assert_eq!(s.list_all().unwrap().len(), UNITS.len());
    assert_eq!(s.get_objects(&id_refs).unwrap().len(), 4);
}

/// A vci 2.8 binary on the git-meta store this vci wrote (STORE-V2 section
/// 5, gate 5): it lists the attestation keys it knows (unchanged), ignores
/// the `vci:object:` keys, reads frames it cannot parse and runs every
/// unit (fail open) with no error; its `vci prune` deletes nothing (a
/// record it cannot read keeps every manifest, and it never deletes a key
/// it does not parse); its own `vci run a` stores a format-1 value, which
/// this vci reads beside the objects, every unit skipped.
#[test]
fn a_2_8_binary_fails_open_on_a_format_3_git_meta_store() {
    let Some(old) = vci_2_8() else {
        return;
    };
    let Some(w) = World::new(Backend::git_meta()) else {
        return;
    };
    attest_all(&w);
    assert_eq!(w.info()["count"], UNITS.len());

    // 2.8 plans: exit 0, nothing it calls an error, every unit runs.
    let out = w.vci_other(&old, &["plan", "--base-ref", "main", "--format", "json"]);
    let plan = parse_plan(&out);
    assert_eq!(plan.run, set(UNITS), "{plan:?}");
    assert!(plan.skip.is_empty(), "{plan:?}");
    assert!(
        !stderr(&out).contains("error"),
        "2.8 reports no error:\n{}",
        stderr(&out)
    );
    let out = w.vci_other(&old, &["explain", "a", "--base-ref", "main"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    // 2.8's prune: nothing listed, nothing deleted; this vci still skips.
    let out = w.vci_other(&old, &["prune", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out), "", "{}", text(&out));
    let out = w.vci_other(&old, &["prune"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out), "", "{}", text(&out));
    assert_eq!(w.info()["count"], UNITS.len(), "2.8 removed nothing");
    let (plan, _) = w.plan(&[]);
    assert_eq!(
        plan.skip,
        set(UNITS),
        "the frames and their objects are intact: {plan:?}"
    );

    // 2.8 runs a and stores it as it always did; this vci skips every
    // unit, a on 2.8's row.
    let key_path = w.key.to_str().unwrap().to_owned();
    let out = w.vci_other(&old, &["run", "a", "--key", &key_path]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let new_keys = attested_keys(&out, "git-meta");
    assert_eq!(new_keys.len(), 1, "{}", text(&out));
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.skip, set(UNITS), "{plan:?}");
    assert_eq!(plan.by["a"].0, new_keys["a"], "{plan:?}");
    assert_eq!(w.info()["count"], UNITS.len());
    // 2.8's prune on the mixed store: a's manifest is referenced, the
    // frames keep the rest; nothing goes.
    let out = w.vci_other(&old, &["prune"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out), "", "{}", text(&out));
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.skip, set(UNITS), "{plan:?}");
}

// ---------------------------------------------------------------------------
// 10. `vci store upgrade` and `vci prune` on store format 3 (M3, STORE-V2
// sections 2.1 "Prune" and 5).

/// A format-3 frame of `run` for unit `a` whose statement carries these
/// RFC 3339 times, with the columns a writer copies out of it (`expires`
/// as `column_expires`, which a test may set apart from the statement):
/// the fixture's descriptor and signature, a statement shaped as `vci run`
/// signs one.
fn frame_of(run: &Run3, issued: i64, expires: i64, column_expires: i64) -> (Vec<u8>, Columns) {
    let (bytes, mut columns) = run.record("a", 2, 1);
    let Ok(Record::FormatThree(mut frame)) = decode_record(&bytes) else {
        panic!("the fixture's record is a frame")
    };
    let rfc = |t: i64| {
        jiff::Timestamp::from_second(t)
            .unwrap()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    };
    frame.statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "a", "digest": {"blake3": "9".repeat(64)}}],
        "predicateType": vci_core::PREDICATE_TYPE_V2,
        "predicate": {
            "argv": [], "commit": "c".repeat(40), "entriesRoot": "0".repeat(64),
            "expiresAt": rfc(expires), "hdr": run.ids.hdr, "issuedAt": rfc(issued),
            "result": {"state": "passed", "tests": 1, "failed": 0, "skipped": 0, "durationMs": 10},
            "tables": run.ids.tables, "testId": "a", "treeDirty": false,
        },
    })
    .to_string()
    .into_bytes();
    columns.expires = Some(column_expires);
    (frame.encode().unwrap().into_bytes(), columns)
}

/// `vci store upgrade --begin` is idempotent on the SQLite file this vci's
/// first write laid out; `--finish` is refused with the count while a
/// format-1 attestation remains (exit 1; counted by the value, so a run
/// with `record_format = 1` counts), and once only format-3 records
/// remain it drops the manifests and sets schema version 2, which `vci
/// store info` then reports and a second `--finish` finds done. Neither
/// flag is a usage error; git-meta has no schema to upgrade.
#[test]
fn sqlite_store_upgrade_begins_and_finishes() {
    let Some(w) = World::new(Backend::sqlite()) else {
        return;
    };
    let key = w.key.to_str().unwrap().to_owned();
    let out = w.vci(&["run", "--key", &key], &[("VCI_STORE_RECORD_FORMAT", "1")]);
    assert_eq!(
        attested_keys(&out, "sqlite").len(),
        UNITS.len(),
        "{}",
        text(&out)
    );
    let file = w.work.join(".git/vci-store.sqlite");

    let out = w.vci(&["store", "upgrade", "--begin"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).contains("the format-3 columns and tables are present"),
        "the first write laid them out: {}",
        text(&out)
    );
    let out = w.vci(&["store", "upgrade", "--finish"], &[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stdout(&out).contains(&format!(
            "not finished: {} attestation(s) are not format-3 records",
            UNITS.len()
        )),
        "{}",
        text(&out)
    );
    assert_eq!(w.info()["schemaVersion"], 1);

    // Only format-3 records remain: a run's objects and one frame.
    let run = Run3::build(&["a/a.go", "a/a_test.go"]);
    let (frame, columns) = frame_of(&run, 1_700_000_000, 1_900_000_000, 1_900_000_000);
    {
        let s = SqliteStore::open_path(&file, SqliteOptions::default());
        let all = s.list_all().unwrap();
        assert_eq!(s.remove(all).unwrap().len(), UNITS.len());
        assert_eq!(s.put_objects(&run.new_objects()).unwrap(), 4);
        let hint = vci_store::KeyHint {
            issued: 1_700_000_000,
            tree: None,
        };
        s.put(
            &NewAttestation::for_test("a", &"3".repeat(16), "aa", Some(&hint), &frame)
                .with_columns(&columns),
        )
        .unwrap();
    }
    let out = w.vci(&["store", "upgrade", "--finish"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).contains("upgraded to schema version 2"),
        "{}",
        text(&out)
    );
    assert_eq!(w.info()["schemaVersion"], 2);
    assert_eq!(w.info()["count"], 1);
    let out = w.vci(&["store", "upgrade", "--finish"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).contains("at schema version 2 already"),
        "{}",
        text(&out)
    );
    let out = w.vci(&["store", "upgrade", "--begin"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = w.vci(&["store", "upgrade"], &[]);
    assert_eq!(out.status.code(), Some(2), "a usage error: {}", text(&out));
    // The frame and its objects are still read.
    let s = SqliteStore::open_path(&file, SqliteOptions::default());
    assert_eq!(s.get_objects(&run.id_refs()).unwrap().len(), 4);
    assert_eq!(s.list_all().unwrap().len(), 1);

    // git-meta: nothing to upgrade.
    let out = w.vci_bare(&["store", "upgrade", "--begin"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).contains("git-meta has no schema"),
        "{}",
        text(&out)
    );
}

/// `vci prune` on a SQLite file with format-3 records (STORE-V2 section
/// 2.1 "Prune"): the listing's columns name the expired candidates
/// without a value read, and a candidate goes only when its signed
/// statement confirms the column (a record whose `expires` column lies is
/// read once and left alone); the run's objects stay while a record
/// references them, the state object goes at `--older-than 0` whether or
/// not one does, and the orphans go once their hour of grace has passed
/// (aged here behind the store's back), on `--objects` alone, which
/// leaves every attestation as it is. The world's own format-3 rows are
/// described by their columns and kept without a read; its run's state
/// object goes with the test's at `--older-than 0`, its other objects stay
/// referenced.
#[test]
fn sqlite_prunes_format_3_records_by_columns_confirmed_by_the_statement() {
    let Some(w) = World::new(Backend::sqlite()) else {
        return;
    };
    attest_all(&w);
    let file = w.work.join(".git/vci-store.sqlite");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let run = Run3::build(&["a/a.go", "a/a_test.go"]);
    // expired: signed and column agree; lying: the column says expired,
    // the statement says a year from now; current: both a year from now.
    let expired = frame_of(&run, now - 7_200, now - 3_600, now - 3_600);
    let lying = frame_of(&run, now - 7_000, now + 31_000_000, now - 3_600);
    let current = frame_of(&run, now - 6_000, now + 31_000_000, now + 31_000_000);
    let signer = "4".repeat(16);
    // The key and the target label the store files it under.
    let put = |s: &SqliteStore, sk: &str, issued: i64, (frame, columns): &(Vec<u8>, Columns)| {
        let hint = vci_store::KeyHint { issued, tree: None };
        let e = s
            .put(
                &NewAttestation::for_test("a", &signer, sk, Some(&hint), frame)
                    .with_columns(columns),
            )
            .unwrap();
        (e.key, e.target)
    };
    let ((k_expired, target), (k_lying, _), (k_current, _)) = {
        let s = SqliteStore::open_path(&file, SqliteOptions::default());
        assert_eq!(s.put_objects(&run.new_objects()).unwrap(), 4);
        (
            put(&s, "e1", now - 7_200, &expired),
            put(&s, "e2", now - 7_000, &lying),
            put(&s, "e3", now - 6_000, &current),
        )
    };
    let keys = |s: &SqliteStore| -> BTreeSet<String> {
        s.list_all().unwrap().into_iter().map(|e| e.key).collect()
    };
    // The state TTL compares whole seconds: a put this second is not yet
    // older than `now`.
    std::thread::sleep(Duration::from_millis(1_100));

    let (listed, summary) = prune_dry_run(&w);
    assert_eq!(
        listed,
        vec![format!("would remove {target} {k_expired}")],
        "{summary}"
    );
    assert!(
        summary.contains(&format!(
            "vci prune: 1 expired (dry run), {} current, 0 unreadable (left alone), 1 unconfirmed (left alone)",
            UNITS.len() + 2
        )),
        "{summary}"
    );
    assert!(
        summary.contains(&format!("vci prune: {target} {k_lying}: left alone")),
        "{summary}"
    );
    assert!(
        summary.contains("vci prune: 0 unreferenced object(s) (dry run)"),
        "{summary}"
    );
    assert!(
        summary.contains("state objects older than 2 day(s): removed on a run without --dry-run"),
        "{summary}"
    );
    let s = SqliteStore::open_path(&file, SqliteOptions::default());
    assert_eq!(keys(&s).len(), UNITS.len() + 3, "a dry run removes nothing");

    let out = w.vci(&["prune"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out), format!("removed {target} {k_expired}\n"));
    let err = stderr(&out);
    assert!(
        err.contains("vci prune: 0 unreferenced object(s) removed")
            && err.contains("vci prune: 0 state object(s) older than 2 day(s) removed"),
        "{err}"
    );
    let left = keys(&s);
    assert!(!left.contains(&k_expired) && left.contains(&k_lying) && left.contains(&k_current));
    assert_eq!(left.len(), UNITS.len() + 2);
    assert_eq!(
        s.get_objects(&run.id_refs()).unwrap().len(),
        4,
        "referenced"
    );

    // The state object alone, at once; the attestations untouched.
    let out = w.vci(&["prune", "--objects", "--older-than", "0"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out), "");
    assert!(
        stderr(&out).contains("vci prune: 2 state object(s) older than 0 day(s) removed"),
        "the test's run's and the world's own run's: {}",
        text(&out)
    );
    assert!(!stderr(&out).contains(" expired"), "{}", text(&out));
    assert_eq!(s.get_objects(&run.id_refs()).unwrap().len(), 3);
    assert_eq!(keys(&s).len(), UNITS.len() + 2);

    // Nothing references the run any more: within the grace hour the
    // objects stay; aged past it they go.
    let doomed: Vec<_> = s
        .list_all()
        .unwrap()
        .into_iter()
        .filter(|e| e.key == k_lying || e.key == k_current)
        .collect();
    assert_eq!(s.remove(doomed).unwrap().len(), 2);
    let out = w.vci(&["prune", "--objects", "--dry-run"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stderr(&out).contains("vci prune: 0 unreferenced object(s) (dry run)"),
        "{}",
        text(&out)
    );
    drop(s);
    {
        let db = rusqlite::Connection::open(&file).unwrap();
        db.execute("UPDATE objects SET put_at = put_at - 7200", [])
            .unwrap();
    }
    let out = w.vci(&["prune", "--objects"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let mut lines: Vec<String> = stdout(&out).lines().map(str::to_owned).collect();
    lines.sort();
    let mut want: Vec<String> = run
        .named()
        .iter()
        .map(|id| format!("removed project object {id} (unreferenced object)"))
        .collect();
    want.sort();
    assert_eq!(lines, want);
    assert!(
        stderr(&out).contains("vci prune: 3 unreferenced object(s) removed"),
        "{}",
        text(&out)
    );
    let s = SqliteStore::open_path(&file, SqliteOptions::default());
    assert!(s.get_objects(&run.id_refs()).unwrap().is_empty());
    assert_eq!(
        keys(&s).len(),
        UNITS.len(),
        "the world's own rows are untouched"
    );
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.skip, set(UNITS), "{plan:?}");
}

/// During the migration window (STORE-V2 section 5) a vci 2.8 that reuses
/// a frame's slot leaves the frame's columns (`format = 3`, its expiry and
/// object ids) beside its format-1 value, whose `manifestRef` names a
/// stored manifest. `vci prune` never takes a column for the row's format:
/// while the store holds an input manifest every row is read, the value
/// under the stale columns is a format-1 record that references its
/// manifest, and the manifest is neither listed nor removed. Here the
/// slot is reused by this vci with `record_format = 1` and the frame's
/// columns put back behind the store's back, as 2.8's upsert leaves them.
#[test]
fn sqlite_prune_reads_a_format_1_value_under_a_frames_columns_before_counting_manifests() {
    let Some(w) = World::new(Backend::sqlite()) else {
        return;
    };
    let out = attest_all(&w);
    let keys = attested_keys(&out, "sqlite");
    let file = w.work.join(".git/vci-store.sqlite");
    let out = w.run_env(&["a"], &[("VCI_STORE_RECORD_FORMAT", "1")]);
    let a_key = attested_keys(&out, "sqlite")["a"].clone();
    assert_eq!(
        slot_and_tree(&a_key).0,
        slot_and_tree(&keys["a"]).0,
        "the same inputs: the same slot"
    );
    {
        let db = rusqlite::Connection::open(&file).unwrap();
        let n = db
            .execute(
                "UPDATE attestations SET format = 3,
                   expires = (SELECT expires FROM attestations WHERE key = ?2),
                   hdr = (SELECT hdr FROM attestations WHERE key = ?2),
                   tables_id = (SELECT tables_id FROM attestations WHERE key = ?2),
                   shape = (SELECT shape FROM attestations WHERE key = ?2),
                   state_obj = (SELECT state_obj FROM attestations WHERE key = ?2)
                 WHERE key = ?1",
                rusqlite::params![a_key, keys["b"]],
            )
            .unwrap();
        assert_eq!(n, 1);
    }
    let roots = {
        let s = SqliteStore::open_path(&file, SqliteOptions::default());
        let all = s.read_all().unwrap();
        let row = all.iter().find(|e| e.key == a_key).expect("a's row");
        assert!(
            matches!(decode_record(&row.bytes), Ok(Record::FormatOne(_))),
            "a format-1 value"
        );
        assert_eq!(
            s.columns(&[row]).unwrap()[0].format,
            Some(3),
            "under the frame's columns"
        );
        let roots = s.manifest_roots().unwrap();
        assert!(!roots.is_empty(), "its manifest is stored");
        roots
    };
    let (listed, summary) = prune_dry_run(&w);
    assert!(
        listed.is_empty(),
        "the value under the frame's columns references its manifest: {listed:?}\n{summary}"
    );
    assert!(
        summary.contains(&format!(
            "vci prune: 0 expired (dry run), {} current, 0 unreadable (left alone)",
            UNITS.len()
        )) && summary.contains("vci prune: 0 unreferenced input manifest(s) (dry run)"),
        "{summary}"
    );
    let out = w.vci(&["prune"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out), "", "{}", text(&out));
    assert!(
        stderr(&out).contains("vci prune: 0 unreferenced input manifest(s) removed"),
        "{}",
        text(&out)
    );
    let s = SqliteStore::open_path(&file, SqliteOptions::default());
    assert_eq!(s.manifest_roots().unwrap(), roots, "every manifest stays");
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.skip, set(UNITS), "{plan:?}");
}

/// `vci prune --superseded` (and `--keep`) on a store with columns orders
/// a unit's records by the hint in their keys only to choose which units
/// to read: a unit with a record beyond `keep` by the hints has its
/// records read, and the signed `issuedAt` decides which are the newest.
/// A key hint edited to make an older record the newest costs the unit's
/// reads and never the deletion of the genuinely newer record.
#[test]
fn sqlite_prune_keep_orders_a_unit_by_the_signed_issue_time_not_by_the_key_hint() {
    let Some(w) = World::new(Backend::sqlite()) else {
        return;
    };
    attest_all(&w);
    let file = w.work.join(".git/vci-store.sqlite");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let run = Run3::build(&["a/a.go", "a/a_test.go"]);
    let older = frame_of(&run, now - 7_200, now + 31_000_000, now + 31_000_000);
    let newer = frame_of(&run, now - 3_600, now + 31_000_000, now + 31_000_000);
    let signer = "4".repeat(16);
    let put = |s: &SqliteStore, sk: &str, issued: i64, (frame, columns): &(Vec<u8>, Columns)| {
        let hint = vci_store::KeyHint { issued, tree: None };
        let e = s
            .put(
                &NewAttestation::for_test("a", &signer, sk, Some(&hint), frame)
                    .with_columns(columns),
            )
            .unwrap();
        (e.key, e.target)
    };
    let ((k_older, target), (k_newer, _)) = {
        let s = SqliteStore::open_path(&file, SqliteOptions::default());
        assert_eq!(s.put_objects(&run.new_objects()).unwrap(), 4);
        (
            put(&s, "e1", now - 7_200, &older),
            put(&s, "e2", now - 3_600, &newer),
        )
    };
    // The older record's key hint edited to say it was issued just now.
    let lying = vci_store::key::attestation_key_hinted(
        &vci_store::key::test_key("a"),
        &signer,
        "e1",
        &vci_store::KeyHint {
            issued: now,
            tree: None,
        },
    );
    {
        let db = rusqlite::Connection::open(&file).unwrap();
        let n = db
            .execute(
                "UPDATE attestations SET key = ?2, issued = ?3 WHERE key = ?1",
                rusqlite::params![k_older, lying, now],
            )
            .unwrap();
        assert_eq!(n, 1);
    }
    let out = w.vci(&["prune", "--superseded"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        stdout(&out),
        format!("removed {target} {lying} (superseded)\n"),
        "the record whose signed issuedAt is older goes, whatever its hint says: {}",
        text(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains(&format!(
            "vci prune: {target} {k_newer}: left alone: its signed statement does not confirm the store's columns"
        )) && err.contains(&format!(
            "vci prune: 0 expired, 1 superseded, {} current, 0 unreadable (left alone), 1 unconfirmed (left alone)",
            UNITS.len() + 1
        )),
        "{err}"
    );
    let s = SqliteStore::open_path(&file, SqliteOptions::default());
    let left: BTreeSet<String> = s.list_all().unwrap().into_iter().map(|e| e.key).collect();
    assert!(
        left.contains(&k_newer) && !left.contains(&lying),
        "{left:?}"
    );
    assert_eq!(left.len(), UNITS.len() + 1);
    let (plan, _) = w.plan(&[]);
    assert_eq!(plan.skip, set(UNITS), "{plan:?}");
}

/// `vci store upgrade --begin` and `--finish` on PostgreSQL (STORE-V2
/// section 5 step 4), as on SQLite: `--finish` is refused with the count
/// while a format-1 attestation remains, and once only format-3 records
/// remain it drops the manifests and sets schema version 2, which `vci
/// store info` reports and a second `--finish` finds done; the frame and
/// its objects are still read.
#[test]
fn postgres_store_upgrade_begins_and_finishes() {
    let Some(b) = Backend::postgres() else { return };
    let Some(w) = World::new(b) else { return };
    let key = w.key.to_str().unwrap().to_owned();
    let out = w.vci(&["run", "--key", &key], &[("VCI_STORE_RECORD_FORMAT", "1")]);
    assert_eq!(
        attested_keys(&out, "postgres").len(),
        UNITS.len(),
        "{}",
        text(&out)
    );
    let out = w.vci(&["store", "upgrade", "--begin"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).contains("the format-3 columns and tables are present"),
        "{}",
        text(&out)
    );
    let out = w.vci(&["store", "upgrade", "--finish"], &[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stdout(&out).contains(&format!(
            "not finished: {} attestation(s) are not format-3 records",
            UNITS.len()
        )),
        "{}",
        text(&out)
    );
    assert_eq!(w.info()["schemaVersion"], 1);

    // Only format-3 records remain: a run's objects and one frame.
    let run = Run3::build(&["a/a.go", "a/a_test.go"]);
    let (frame, columns) = frame_of(&run, 1_700_000_000, 1_900_000_000, 1_900_000_000);
    let s = w.backend.db.as_ref().unwrap().open();
    let all = s.list_all().unwrap();
    assert_eq!(s.remove(all).unwrap().len(), UNITS.len());
    assert_eq!(s.put_objects(&run.new_objects()).unwrap(), 4);
    let hint = vci_store::KeyHint {
        issued: 1_700_000_000,
        tree: None,
    };
    s.put(
        &NewAttestation::for_test("a", &"3".repeat(16), "aa", Some(&hint), &frame)
            .with_columns(&columns),
    )
    .unwrap();
    let out = w.vci(&["store", "upgrade", "--finish"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).contains("upgraded to schema version 2"),
        "{}",
        text(&out)
    );
    assert_eq!(w.info()["schemaVersion"], 2);
    assert_eq!(w.info()["count"], 1);
    let out = w.vci(&["store", "upgrade", "--finish"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).contains("at schema version 2 already"),
        "{}",
        text(&out)
    );
    let out = w.vci(&["store", "upgrade", "--begin"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let s = w.backend.db.as_ref().unwrap().open();
    assert_eq!(s.get_objects(&run.id_refs()).unwrap().len(), 4);
    assert_eq!(s.list_all().unwrap().len(), 1);
    let (listed, summary) = prune_dry_run(&w);
    assert!(listed.is_empty(), "{listed:?}");
    assert!(
        summary.contains("vci prune: 0 expired (dry run), 1 current, 0 unreadable (left alone)"),
        "{summary}"
    );
}
