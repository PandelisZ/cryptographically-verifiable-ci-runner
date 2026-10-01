//! End-to-end verification for the Cargo adapter, mirroring `e2e_pytest.rs`
//! and `e2e_go.rs`: a copy of `fixtures/cargo-abcd` in a throwaway git repo
//! (the base commit holds `.vci/allowed_signers` and `vci.toml`), throwaway
//! SSH keys and a local bare remote.
//!
//! Needs `cargo`, `git` and `ssh-keygen` on PATH. Every test prints
//! `SKIPPED:` and returns early when cargo is not installed or the fixture's
//! crate (`hex`) cannot be fetched (offline without a registry cache).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use assert_cmd::cargo::CommandCargoExt;
use base64::Engine as _;
use camino::Utf8Path;
use serde_json::Value;
use vci_git::{AttestStore, Repo};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_owned()
}

fn cargo_available() -> bool {
    match Command::new("cargo").arg("--version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!(
                "SKIPPED: `cargo` is not installed; the Cargo end-to-end tests need the Rust toolchain on PATH"
            );
            false
        }
    }
}

const VCI_TOML: &str = r#"project = "."
adapter = "cargo"

[policy]
platform = "any"
max_ttl = "30d"
no_skip_refs = ["refs/heads/release/*"]

[env]
mode = "strict"
global = ["APP_MODE"]
"#;

/// Variables removed from every `vci` and `cargo` invocation so the host
/// environment cannot change the outcome (CARGO_TARGET_DIR too: the tests
/// use the default target dir inside the repository, which vci must not
/// treat as an input).
const SCRUB: &[&str] = &[
    "VCI_E2E_BIN",
    "VCI_BASE_REF",
    "GITHUB_BASE_REF",
    "GITHUB_REF",
    "GITHUB_OUTPUT",
    "VCI_SIGNING_KEY",
    "VCI_CARGO",
    "VCI_JOBS",
    "APP_MODE",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
    "RUSTC",
    "RUSTC_BOOTSTRAP",
    "RUST_TEST_THREADS",
    "NODE_OPTIONS",
    "CI",
];

/// Offline, so the tests never reach the network once `cargo fetch` worked.
const OFFLINE: (&str, &str) = ("CARGO_NET_OFFLINE", "true");

struct World {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    work: PathBuf,
    remote: PathBuf,
    trusted: PathBuf,
    untrusted: PathBuf,
    gitconfig: PathBuf,
    /// Extra env for every vci and cargo invocation.
    env: Vec<(String, String)>,
}

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

/// Copy the Cargo fixture into `dir`.
fn copy_cargo_fixture(dir: &Path) {
    let fx = workspace_root().join("fixtures/cargo-abcd");
    std::fs::create_dir_all(dir).unwrap();
    for name in ["Cargo.toml", "Cargo.lock", "a", "b", "c", "d", "shared"] {
        cp(&fx.join(name), &dir.join(name));
    }
}

impl World {
    /// `None` (test skipped) when cargo is unavailable.
    fn new() -> Option<Self> {
        Self::build(VCI_TOML, copy_cargo_fixture, &[])
    }

    /// A repo whose base commit holds the tree `layout` writes, `vci_toml`
    /// and allowed_signers; `cargo fetch` runs in the project dir.
    fn build(vci_toml: &str, layout: impl FnOnce(&Path), env: &[(&str, &str)]) -> Option<Self> {
        if !cargo_available() {
            return None;
        }
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
        let mut w = World {
            work: base.join("work"),
            remote: base.join("remote.git"),
            trusted: keys.join("trusted"),
            untrusted: keys.join("untrusted"),
            gitconfig,
            base,
            _tmp: tmp,
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        };
        keygen(&w.trusted, "trusted");
        keygen(&w.untrusted, "untrusted");
        w.git(&w.base, &["init", "-q", "--bare", "remote.git"]);
        w.git(&w.base, &["init", "-q", w.work.to_str().unwrap()]);
        layout(&w.work);
        std::fs::write(w.work.join(".gitignore"), ".vci/out/\ntarget/\n").unwrap();
        std::fs::write(w.work.join("vci.toml"), vci_toml).unwrap();
        std::fs::create_dir_all(w.work.join(".vci")).unwrap();
        std::fs::write(
            w.work.join(".vci/allowed_signers"),
            format!(
                "trusted@example.com namespaces=\"vci-attest\" {}\n",
                pubkey(&w.trusted)
            ),
        )
        .unwrap();
        w.git(&w.work, &["add", "-A"]);
        w.git(&w.work, &["commit", "-q", "-m", "base commit"]);
        w.git(
            &w.work,
            &["remote", "add", "origin", w.remote.to_str().unwrap()],
        );
        w.git(&w.work, &["push", "-q", "origin", "main"]);
        // Work happens on a PR branch; `main` is the base.
        w.git(&w.work, &["checkout", "-q", "-b", "feature"]);
        // Fetch the crates this host builds (from the local cache if
        // possible).
        let rustc = Command::new("rustc").arg("-vV").output().unwrap();
        let host = String::from_utf8_lossy(&rustc.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("host: ").map(str::to_owned))
            .unwrap_or_default();
        let fetch = ["fetch", "--locked", "--target", host.as_str()];
        let offline = w.cargo(&w.work, &fetch);
        if !offline.status.success() {
            let online = w.cargo_raw(&w.work, &fetch, false);
            if !online.status.success() {
                eprintln!(
                    "SKIPPED: `cargo fetch` failed for the Cargo fixture (offline without a registry cache?): {}",
                    String::from_utf8_lossy(&online.stderr)
                );
                return None;
            }
        }
        w.env.push((OFFLINE.0.into(), OFFLINE.1.into()));
        Some(w)
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

    fn cargo_raw(&self, dir: &Path, args: &[&str], offline: bool) -> Output {
        let mut cmd = Command::new("cargo");
        cmd.args(args).current_dir(dir);
        for k in SCRUB {
            cmd.env_remove(k);
        }
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        if offline {
            cmd.env(OFFLINE.0, OFFLINE.1);
        }
        cmd.output().unwrap()
    }

    fn cargo(&self, dir: &Path, args: &[&str]) -> Output {
        self.cargo_raw(dir, args, true)
    }

    fn vci_env(&self, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        // `VCI_E2E_BIN` runs another vci binary (e.g. a build from before a
        // fix, to see a regression test fail).
        let mut cmd = match std::env::var_os("VCI_E2E_BIN") {
            Some(b) => Command::new(b),
            None => Command::cargo_bin("vci").unwrap(),
        };
        cmd.current_dir(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("NO_COLOR", "1");
        for k in SCRUB {
            cmd.env_remove(k);
        }
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        eprintln!(
            "$ vci {} {env:?}\n{}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    fn vci(&self, dir: &Path, args: &[&str]) -> Output {
        self.vci_env(dir, args, &[])
    }

    fn vci_ok(&self, dir: &Path, args: &[&str]) -> String {
        let out = self.vci(dir, args);
        assert!(
            out.status.success(),
            "vci {args:?} exited {:?}",
            out.status.code()
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// `vci run <units> --key K`; returns stderr.
    fn run(&self, dir: &Path, units: &[&str], key: &Path) -> String {
        let mut args = vec!["run"];
        args.extend(units);
        args.extend(["--key", key.to_str().unwrap()]);
        let out = self.vci(dir, &args);
        assert!(
            out.status.success(),
            "vci run {units:?} exited {:?}",
            out.status.code()
        );
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    fn plan_env(&self, dir: &Path, base: &str, env: &[(&str, &str)]) -> Plan {
        let out = self.vci_env(dir, &["plan", "--base-ref", base, "--format", "json"], env);
        assert!(out.status.success(), "vci plan failed");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        Plan::from_json(&v)
    }

    fn plan(&self, dir: &Path, base: &str) -> Plan {
        self.plan_env(dir, base, &[])
    }

    fn explain(&self, dir: &Path, unit: &str, base: &str) -> String {
        self.vci_ok(dir, &["explain", unit, "--base-ref", base])
    }

    fn put(&self, rel: &str, content: &str) {
        let p = self.work.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.work.join(rel)).unwrap()
    }

    /// Add a library crate `name` to the workspace (and to Cargo.lock).
    fn add_crate(&self, name: &str, lib_rs: &str) {
        self.put(
            &format!("{name}/Cargo.toml"),
            &format!(
                "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n[lib]\ndoctest = false\n"
            ),
        );
        self.put(&format!("{name}/src/lib.rs"), lib_rs);
        let ws = self.read("Cargo.toml");
        self.put(
            "Cargo.toml",
            &ws.replace("members = [", &format!("members = [\"{name}\", ")),
        );
        let out = self.cargo(&self.work, &["metadata", "--format-version", "1"]);
        assert!(
            out.status.success(),
            "updating Cargo.lock: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Add a package `name` (a workspace member) whose manifest ends with
    /// `manifest_rest` (after `[package]`), with `files` relative to its
    /// directory, and update Cargo.lock.
    fn add_pkg(&self, name: &str, manifest_rest: &str, files: &[(&str, &str)]) {
        self.put(
            &format!("{name}/Cargo.toml"),
            &format!(
                "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n{manifest_rest}"
            ),
        );
        for (rel, body) in files {
            self.put(&format!("{name}/{rel}"), body);
        }
        let ws = self.read("Cargo.toml");
        self.put(
            "Cargo.toml",
            &ws.replace("members = [", &format!("members = [\"{name}\", ")),
        );
        let out = self.cargo(&self.work, &["metadata", "--format-version", "1"]);
        assert!(
            out.status.success(),
            "updating Cargo.lock: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// `vci run <units>` with extra env; returns (exit code, stderr).
    fn run_env(&self, units: &[&str], env: &[(&str, &str)]) -> (Option<i32>, String) {
        let mut args = vec!["run"];
        args.extend(units);
        args.extend(["--key", self.trusted.to_str().unwrap()]);
        let out = self.vci_env(&self.work, &args, env);
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// The paths of the attested manifest entries of `test_id` (first
    /// stored predicate).
    fn entries(&self, test_id: &str) -> Vec<String> {
        self.predicates(test_id)[0]["manifest"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap().to_owned())
            .collect()
    }

    /// The predicates stored for `test_id`.
    fn predicates(&self, test_id: &str) -> Vec<Value> {
        let repo = store_for(&self.work);
        let b64 = base64::engine::general_purpose::STANDARD;
        AttestStore::new(&repo)
            .list(Some(test_id))
            .unwrap()
            .iter()
            .map(|s| {
                let env: Value = serde_json::from_slice(&s.bytes).unwrap();
                let payload = b64.decode(env["payload"].as_str().unwrap()).unwrap();
                let st: Value = serde_json::from_slice(&payload).unwrap();
                st["predicate"].clone()
            })
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Plan {
    skip: BTreeSet<String>,
    run: BTreeSet<String>,
    run_all: bool,
}

impl Plan {
    fn from_json(v: &Value) -> Self {
        let mut p = Plan {
            skip: BTreeSet::new(),
            run: BTreeSet::new(),
            run_all: !v["runAll"].is_null(),
        };
        for f in v["files"].as_array().unwrap() {
            let id = f["testId"].as_str().unwrap().to_owned();
            if f["skip"].as_bool().unwrap() {
                p.skip.insert(id);
            } else {
                p.run.insert(id);
            }
        }
        p
    }
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn store_for(dir: &Path) -> Repo {
    Repo::discover(Utf8Path::from_path(dir).unwrap()).unwrap()
}

const A_LIB: &str = "a#lib";
const A_DOC: &str = "a#doc";
const B: &str = "b#test:b";
const C: &str = "c#lib";
const D: &str = "d#lib";

/// The line `vci run` printed for `id` when it refused it.
fn refusal<'a>(stderr: &'a str, id: &str) -> &'a str {
    stderr
        .lines()
        .find(|l| l.starts_with(&format!("vci: not attesting {id}:")))
        .unwrap_or_else(|| panic!("{id} was not refused:\n{stderr}"))
}

#[test]
fn cargo_end_to_end_verification_steps() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();

    // Step 1: attest b's integration test, then plan: skip only that unit.
    // Units are every target `cargo test --workspace` runs; b's library has
    // test = false, c and d have doctest = false.
    w.run(&work, &[B], &w.trusted);
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[B]), "step 1");
    assert_eq!(p.run, set(&[A_LIB, A_DOC, C, D]), "step 1");
    assert!(!p.run_all);
    let pred = &w.predicates(B)[0];
    assert_eq!(
        pred["argv"],
        serde_json::json!([
            "cargo",
            "test",
            "--locked",
            "--manifest-path",
            "b/Cargo.toml",
            "--test",
            "b"
        ])
    );
    let entries: Vec<&str> = pred["manifest"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    for want in [
        "b",
        "b/Cargo.toml",
        "b/src/lib.rs",
        "b/tests/b.rs",
        "b/tests/data",
        "b/tests/data/b.json",
    ] {
        assert!(
            entries.contains(&want),
            "{want} must be an input: {entries:?}"
        );
    }
    assert!(
        !entries.iter().any(|e| e.starts_with("target")),
        "the target dir is not an input: {entries:?}"
    );

    // Step 2: edit the file b's test reads at run time -> b runs; explain
    // names the file and both hashes.
    let original = w.read("b/tests/data/b.json");
    w.put("b/tests/data/b.json", "{ \"greeting\": \"hi\" }\n");
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(B),
        "step 2: b must run after its data changed"
    );
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(ex.contains("entry:b/tests/data/b.json"), "{ex}");
    assert!(
        ex.contains(&vci_core::blake3_hex(original.as_bytes())),
        "{ex}"
    );
    assert!(
        ex.contains(&vci_core::blake3_hex(
            w.read("b/tests/data/b.json").as_bytes()
        )),
        "{ex}"
    );
    w.put("b/tests/data/b.json", &original);
    assert_eq!(w.plan(&work, "main").skip, set(&[B]), "step 2: restored");

    // Step 3: a new file anywhere in b's package directory -> b runs.
    w.put("b/tests/data/new.json", "{}\n");
    assert!(w.plan(&work, "main").run.contains(B), "step 3");
    assert!(w.explain(&work, B, "main").contains("entry:b/tests/data\n"));
    std::fs::remove_file(work.join("b/tests/data/new.json")).unwrap();
    assert_eq!(w.plan(&work, "main").skip, set(&[B]), "step 3: restored");

    // Step 4: attest d (it builds crate a and the external hex). Editing a
    // runs d and a's units, b stays skipped.
    w.run(&work, &[D], &w.trusted);
    let pred = &w.predicates(D)[0];
    let ext = &pred["manifest"]["externals"];
    assert_eq!(ext[0]["name"], "hex", "{ext}");
    assert!(
        ext[0]["version"]
            .as_str()
            .unwrap()
            .starts_with("0.4.3 registry+https://github.com/rust-lang/crates.io-index "),
        "{ext}"
    );
    assert_eq!(w.plan(&work, "main").skip, set(&[B, D]), "step 4");
    let a_src = w.read("a/src/lib.rs");
    w.put("a/src/lib.rs", &a_src.replace("x + y", "y + x"));
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[B]), "step 4: {p:?}");
    assert!(p.run.contains(D) && p.run.contains(A_LIB), "step 4: {p:?}");
    assert!(w.explain(&work, D, "main").contains("entry:a/src/lib.rs"));
    w.put("a/src/lib.rs", &a_src);
    assert_eq!(w.plan(&work, "main").skip, set(&[B, D]), "step 4: restored");

    // Step 4b: a's unit tests (one of them #[ignore]d) and its doctests are
    // units of their own; editing a doctest runs both (same source file).
    let out = w.run(&work, &[A_LIB, A_DOC], &w.trusted);
    assert!(out.contains("vci: attested a#lib "), "{out}");
    assert!(out.contains("vci: attested a#doc "), "{out}");
    assert_eq!(
        w.predicates(A_LIB)[0]["result"]["tests"],
        2,
        "the ignored test is counted"
    );
    assert_eq!(
        w.predicates(A_DOC)[0]["argv"],
        serde_json::json!([
            "cargo",
            "test",
            "--locked",
            "--manifest-path",
            "a/Cargo.toml",
            "--doc"
        ])
    );
    assert_eq!(
        w.plan(&work, "main").skip,
        set(&[A_LIB, A_DOC, B, D]),
        "step 4b"
    );
    w.put(
        "a/src/lib.rs",
        &a_src.replace("add(1, 2), 3", "add(2, 1), 3"),
    );
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[B]), "step 4b: {p:?}");
    w.put("a/src/lib.rs", &a_src);

    // Step 5: attest c. Its include_str! target and the file its build
    // script declares (both outside its package directory) are inputs; an
    // unrelated file next to them is not.
    w.run(&work, &[C], &w.trusted);
    assert_eq!(
        w.plan(&work, "main").skip,
        set(&[A_LIB, A_DOC, B, C, D]),
        "step 5"
    );
    for (file, edited) in [
        ("shared/c.txt", "welcome back\n"),
        ("shared/c-build.txt", "slow\n"),
    ] {
        let before = w.read(file);
        w.put(file, edited);
        let p = w.plan(&work, "main");
        assert!(p.run.contains(C), "step 5: {file}: {p:?}");
        assert_eq!(p.skip, set(&[A_LIB, A_DOC, B, D]), "step 5: {file}");
        assert!(
            w.explain(&work, C, "main")
                .contains(&format!("entry:{file}")),
            "step 5: {file}"
        );
        w.put(file, &before);
    }
    w.put("shared/other.txt", "edited\n");
    assert_eq!(
        w.plan(&work, "main").skip,
        set(&[A_LIB, A_DOC, B, C, D]),
        "step 5: unrelated file"
    );

    // Step 6: a crate version change in Cargo.lock -> everything runs
    // (Cargo.lock is a global input; the externals check would catch it too).
    let lock = w.read("Cargo.lock");
    w.put(
        "Cargo.lock",
        &lock
            .replace("version = \"0.4.3\"", "version = \"0.4.4\"")
            .replace(
                "7f24254aa9a54b5c858eaee2f5bccdb46aaf0e486a595ed5fd8f86ba55232a70",
                &"1".repeat(64),
            ),
    );
    let p = w.plan(&work, "main");
    assert!(p.skip.is_empty(), "step 6: {p:?}");
    let ex = w.explain(&work, D, "main");
    assert!(
        ex.contains("failed check: global-inputs") && ex.contains("entry:Cargo.lock"),
        "{ex}"
    );
    w.put("Cargo.lock", &lock);
    assert_eq!(
        w.plan(&work, "main").skip,
        set(&[A_LIB, A_DOC, B, C, D]),
        "step 6: restored"
    );

    // Step 7: a rust-toolchain.toml appears -> everything runs.
    let rustc = String::from_utf8_lossy(&Command::new("rustc").arg("-V").output().unwrap().stdout)
        .split_whitespace()
        .nth(1)
        .unwrap_or("stable")
        .to_owned();
    w.put(
        "rust-toolchain.toml",
        &format!("[toolchain]\nchannel = \"{rustc}\"\n"),
    );
    let p = w.plan(&work, "main");
    assert!(p.skip.is_empty(), "step 7: {p:?}");
    if !p.run_all {
        assert!(
            w.explain(&work, B, "main")
                .contains("entry:rust-toolchain.toml"),
            "step 7"
        );
    }
    std::fs::remove_file(work.join("rust-toolchain.toml")).unwrap();
    assert_eq!(
        w.plan(&work, "main").skip,
        set(&[A_LIB, A_DOC, B, C, D]),
        "step 7: restored"
    );

    // Step 8: flip a byte in b's payload -> rejected at the signature check.
    let repo = store_for(&work);
    let store = AttestStore::new(&repo);
    let stored = store.list(Some(B)).unwrap();
    assert!(!stored.is_empty());
    for s in &stored {
        let mut env: Value = serde_json::from_slice(&s.bytes).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut payload = b64.decode(env["payload"].as_str().unwrap()).unwrap();
        let pos = payload
            .windows(9)
            .position(|x| x == b"\"tests\":1")
            .expect("payload contains the test count");
        payload[pos + 8] = b'2';
        env["payload"] = Value::String(b64.encode(&payload));
        store
            .put(
                B,
                &s.signer,
                &s.storage_key,
                &serde_json::to_vec(&env).unwrap(),
            )
            .unwrap();
    }
    assert!(w.plan(&work, "main").run.contains(B), "step 8");
    assert!(
        w.explain(&work, B, "main")
            .contains("failed check: signature")
    );
    for s in &stored {
        store.put(B, &s.signer, &s.storage_key, &s.bytes).unwrap();
    }
    assert!(w.plan(&work, "main").skip.contains(B), "step 8: restored");

    // Step 9: a key that is not in allowed_signers -> rejected. Edit d's
    // input first so the trusted attestation no longer applies.
    let d_src = w.read("d/src/lib.rs");
    w.put("d/src/lib.rs", &format!("{d_src}\n// untrusted run\n"));
    w.run(&work, &[D], &w.untrusted);
    assert!(w.plan(&work, "main").run.contains(D), "step 9");
    let ex = w.explain(&work, D, "main");
    assert!(ex.contains("failed check: signer"), "{ex}");
    assert!(ex.contains("not in allowed_signers"), "{ex}");

    // Step 10: that key added to allowed_signers on the PR branch only ->
    // still rejected.
    let mut signers = w.read(".vci/allowed_signers");
    signers.push_str(&format!(
        "untrusted@example.com namespaces=\"vci-attest\" {}\n",
        pubkey(&w.untrusted)
    ));
    w.put(".vci/allowed_signers", &signers);
    w.git(&work, &["commit", "-q", "-am", "PR: trust my own key"]);
    assert!(w.plan(&work, "main").run.contains(D), "step 10");
    assert!(w.explain(&work, D, "main").contains("failed check: signer"));
    // Control: with the PR commit as the (wrong) trust root, d would be skipped.
    assert!(w.plan(&work, "HEAD").skip.contains(D), "step 10 control");

    // Step 11: a variable declared in [env] global with a different value in
    // CI forces a run (it was unset when b was attested).
    let p = w.plan_env(&work, "main", &[("APP_MODE", "ci")]);
    assert!(p.run.contains(B), "step 11: {p:?}");
    let out = w.vci_env(
        &work,
        &["explain", B, "--base-ref", "main"],
        &[("APP_MODE", "ci")],
    );
    let ex = String::from_utf8_lossy(&out.stdout);
    assert!(
        ex.contains("failed check: env") && ex.contains("env:APP_MODE"),
        "{ex}"
    );
    let out = w.vci_env(
        &work,
        &["run", B, "--key", w.trusted.to_str().unwrap()],
        &[("APP_MODE", "ci")],
    );
    assert!(out.status.success());
    assert!(
        w.plan_env(&work, "main", &[("APP_MODE", "ci")])
            .skip
            .contains(B)
    );
    assert!(
        w.plan_env(&work, "main", &[("APP_MODE", "other")])
            .run
            .contains(B)
    );

    // Step 12: a rustc flag in the environment (hashed whenever present,
    // removed in strict mode unless declared) is compared too.
    let p = w.plan_env(&work, "main", &[("RUSTFLAGS", "-Copt-level=1")]);
    assert!(
        p.skip.contains(B),
        "strict mode removes an undeclared RUSTFLAGS: {p:?}"
    );
}

#[test]
fn cargo_run_refuses_unattestable_units() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let crates: &[(&str, &str)] = &[
        (
            "spawn",
            "#[test]\nfn runs_rustc() {\n    let out = std::process::Command::new(\"rustc\").arg(\"-V\").output().unwrap();\n    assert!(out.status.success());\n}\n",
        ),
        (
            "fail",
            "#[test]\nfn fails() {\n    assert_eq!(1 + 1, 3);\n}\n",
        ),
        (
            "envall",
            "#[test]\nfn lists_env() {\n    assert!(std::env::vars().count() > 0);\n}\n",
        ),
        (
            "netio",
            "#[test]\nfn binds() {\n    let l = std::net::TcpListener::bind(\"127.0.0.1:0\").unwrap();\n    drop(l);\n}\n",
        ),
        ("notests", "pub fn nothing() {}\n"),
        (
            "outside",
            "#[test]\nfn reads_shared() {\n    let s = std::fs::read_to_string(\"../shared/other.txt\").unwrap();\n    assert!(!s.is_empty());\n}\n",
        ),
        (
            "ffi",
            "unsafe extern \"C\" {\n    fn abs(x: i32) -> i32;\n}\n#[test]\nfn calls_c() {\n    assert_eq!(unsafe { abs(-1) }, 1);\n}\n",
        ),
    ];
    for (name, lib) in crates {
        w.add_crate(name, lib);
    }
    let ids: Vec<String> = crates.iter().map(|(n, _)| format!("{n}#lib")).collect();
    let mut args = vec!["run"];
    args.extend(ids.iter().map(String::as_str));
    args.extend(["--key", w.trusted.to_str().unwrap()]);
    let out = w.vci(&work, &args);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_ne!(
        out.status.code(),
        Some(0),
        "the failing test makes vci run fail"
    );
    for (id, why) in [
        ("spawn#lib", "cargo:process"),
        ("spawn#lib", "spawn/src/lib.rs mentions `Command::new`"),
        ("fail#lib", "result failed"),
        ("envall#lib", "cargo:env-enumeration"),
        ("netio#lib", "cargo:net"),
        ("notests#lib", "result no-tests"),
        ("outside#lib", "shared/other.txt"),
        ("outside#lib", "declare it in vci.toml"),
        ("ffi#lib", "cargo:native"),
    ] {
        let line = refusal(&stderr, id);
        assert!(line.contains(why), "{id}: expected {why:?} in {line:?}");
    }
    assert!(
        stderr.contains("vci: 0 attested, 7 not attested"),
        "{stderr}"
    );
    let stored = AttestStore::new(&store_for(&work)).list(None).unwrap();
    assert!(stored.is_empty(), "nothing may be stored: {stored:?}");
    let p = w.plan(&work, "main");
    for id in &ids {
        assert!(p.run.contains(id), "{id} must run: {p:?}");
    }

    // Declaring the file the unit reads makes it attestable; the declared
    // file is then an input, and the declaration must still be the base
    // config's.
    let toml = format!(
        "{VCI_TOML}\n[[inputs]]\nmatch = [\"outside#*\"]\nextra = [\"shared/other.txt\"]\n"
    );
    w.put("vci.toml", &toml);
    w.git(&work, &["add", "-A"]);
    w.git(&work, &["commit", "-q", "-m", "declare what outside reads"]);
    let declared_base = w.git(&work, &["rev-parse", "HEAD"]);
    w.run(&work, &["outside#lib"], &w.trusted);
    let pred = &w.predicates("outside#lib")[0];
    assert_eq!(
        pred["declaredInputs"],
        serde_json::json!(["shared/other.txt"])
    );
    assert!(w.plan(&work, &declared_base).skip.contains("outside#lib"));
    let ex = w.explain(&work, "outside#lib", "main");
    assert!(ex.contains("failed check: "), "{ex}");
    w.put("shared/other.txt", "changed\n");
    assert!(w.plan(&work, &declared_base).run.contains("outside#lib"));
    assert!(
        w.explain(&work, "outside#lib", &declared_base)
            .contains("entry:shared/other.txt")
    );

    // Loose env mode: the cargo adapter does not attest (a Rust test's
    // environment reads are not observed).
    w.put(
        "vci.toml",
        &toml.replace("mode = \"strict\"", "mode = \"loose\""),
    );
    let out = w.vci(&work, &["run", A_LIB, "--key", w.trusted.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(refusal(&stderr, A_LIB).contains("loose"), "{stderr}");
}

#[test]
fn cargo_push_fetch_fresh_clone_and_ci() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.run(&work, &[B, C], &w.trusted);
    let before = w.plan(&work, "main");
    assert_eq!(before.skip, set(&[B, C]));
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push", "--remote", "origin"]);

    let fresh = w.base.join("fresh");
    w.git(
        &w.base,
        &[
            "clone",
            "-q",
            w.remote.to_str().unwrap(),
            fresh.to_str().unwrap(),
        ],
    );
    w.git(&fresh, &["checkout", "-q", "feature"]);
    assert!(
        w.plan(&fresh, "main").skip.is_empty(),
        "nothing before fetch"
    );
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    assert_eq!(w.plan(&fresh, "main"), before, "same plan in a fresh clone");

    // `vci ci` runs only the remainder, one `cargo test` per unit, and writes
    // an audit log.
    let audit = w.base.join("audit.json");
    let ci = |dir: &Path| {
        w.vci(
            dir,
            &[
                "ci",
                "--base-ref",
                "main",
                "--audit-log",
                audit.to_str().unwrap(),
            ],
        )
    };
    let out = ci(&fresh);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("running 3 test file(s)"), "{stderr}");
    for want in [
        "cargo test --locked --manifest-path a/Cargo.toml --lib",
        "cargo test --locked --manifest-path a/Cargo.toml --doc",
        "cargo test --locked --manifest-path d/Cargo.toml --lib",
        "test tests::sums ... ok",
    ] {
        assert!(stderr.contains(want), "{want}: {stderr}");
    }
    assert!(
        !stderr.contains("greets_from_the_data_file"),
        "b must not run: {stderr}"
    );
    let log: Value = serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
    let skipped: BTreeSet<String> = log["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["testId"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(skipped, set(&[B, C]));
    assert_eq!(log["exitCode"], 0);

    // A failing unit among the remainder makes `vci ci` exit non-zero.
    let d_src = std::fs::read_to_string(fresh.join("d/src/lib.rs")).unwrap();
    std::fs::write(
        fresh.join("d/src/lib.rs"),
        d_src.replace("\"00000003\"", "\"00000004\""),
    )
    .unwrap();
    let out = ci(&fresh);
    assert_ne!(
        out.status.code(),
        Some(0),
        "a failing test must fail vci ci"
    );
    let log: Value = serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
    assert_ne!(log["exitCode"], 0);
    std::fs::write(fresh.join("d/src/lib.rs"), d_src).unwrap();

    // Policy: nothing is skipped on refs listed in no_skip_refs.
    w.git(&fresh, &["checkout", "-q", "-b", "release/1"]);
    let p = w.plan(&fresh, "main");
    assert!(p.run_all && p.skip.is_empty(), "{p:?}");
    w.git(&fresh, &["checkout", "-q", "feature"]);

    // No Cargo.lock: everything runs.
    std::fs::rename(fresh.join("Cargo.lock"), fresh.join("Cargo.lock.bak")).unwrap();
    let out = w.vci(&fresh, &["plan", "--base-ref", "main", "--format", "json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["runAll"].as_str().unwrap_or("").contains("Cargo.lock"),
        "{v}"
    );
    std::fs::rename(fresh.join("Cargo.lock.bak"), fresh.join("Cargo.lock")).unwrap();

    // cargo missing in CI: everything runs (never a false skip).
    let out = w.vci_env(
        &fresh,
        &["plan", "--base-ref", "main", "--format", "json"],
        &[("VCI_CARGO", "/nonexistent/cargo")],
    );
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["runAll"].as_str().unwrap_or("").contains("cargo"), "{v}");
}

/// Code behind a target cfg is recorded; on this host it evaluates as
/// attested, so the unit is skipped; the attestation lists the predicate so
/// another platform can decide. A unit that checks the platform at run time
/// is pinned to this OS and architecture.
#[test]
fn cargo_platform_dependent_code_is_recorded() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.add_crate(
        "plat",
        "#[cfg(target_os = \"linux\")]\npub fn os() -> &'static str { \"linux\" }\n#[cfg(not(target_os = \"linux\"))]\npub fn os() -> &'static str { \"other\" }\n\n#[test]\n#[cfg_attr(windows, ignore)]\nfn has_os() {\n    assert!(!os().is_empty());\n}\n",
    );
    w.add_crate(
        "runtime",
        "#[test]\nfn knows_os() {\n    assert!(!std::env::consts::OS.is_empty());\n}\n",
    );
    w.git(&work, &["add", "-A"]);
    w.git(&work, &["commit", "-q", "-m", "platform crates"]);
    w.run(&work, &["plat#lib", "runtime#lib"], &w.trusted);
    let pred = &w.predicates("plat#lib")[0];
    let preds: Vec<&str> = pred["cfgPredicates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        preds,
        [
            "not(target_os = \"linux\")",
            "target_os = \"linux\"",
            "windows"
        ]
    );
    assert!(pred.get("platformSpecific").is_none(), "{pred}");
    assert!(pred["toolchain"]["rustCfg"].as_array().unwrap().len() > 5);
    let pred = &w.predicates("runtime#lib")[0];
    assert_eq!(
        pred["platformSpecific"],
        serde_json::json!(["runtime/src/lib.rs"])
    );
    let p = w.plan(&work, "main");
    assert!(
        p.skip.contains("plat#lib") && p.skip.contains("runtime#lib"),
        "{p:?}"
    );

    // What a Linux x86_64 runner decides (its cfg set from rustc, which
    // prints it for any target without the target installed): plat's
    // target_os predicates evaluate differently there, crate a's none do.
    let linux = Command::new("rustc")
        .args(["--print", "cfg", "--target", "x86_64-unknown-linux-gnu"])
        .output()
        .unwrap();
    if !linux.status.success() {
        eprintln!("SKIPPED (part): rustc cannot print the cfg of x86_64-unknown-linux-gnu");
        return;
    }
    let linux: Vec<String> = String::from_utf8_lossy(&linux.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    let pred = &w.predicates("plat#lib")[0];
    let attested: Vec<String> = pred["toolchain"]["rustCfg"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    let on_linux = |p: &str| vci_adapter::cfg_predicate_differs(p, &attested, &linux).unwrap();
    let host_os = std::env::consts::OS;
    assert_eq!(on_linux("target_os = \"linux\""), host_os != "linux");
    assert!(!on_linux("windows"));
    assert!(!on_linux("all(unix, not(windows))"));
    assert_eq!(on_linux("unix"), !cfg!(unix));
}

/// `vci init --adapter cargo` writes a Cargo vci.toml and prints the Cargo
/// workflow.
#[test]
fn cargo_init_writes_config_and_prints_the_cargo_workflow() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().canonicalize().unwrap();
    let st = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&dir)
        .status()
        .unwrap();
    assert!(st.success());
    let key = dir.join("k");
    keygen(&key, "k");
    let out = Command::cargo_bin("vci")
        .unwrap()
        .current_dir(&dir)
        .args([
            "init",
            "--adapter",
            "cargo",
            "--project",
            "rs",
            "--principal",
            "me@example.com",
            "--key",
            key.with_extension("pub").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let toml = std::fs::read_to_string(dir.join("vci.toml")).unwrap();
    assert!(toml.contains("adapter = \"cargo\""), "{toml}");
    assert!(toml.contains("project = \"rs\""), "{toml}");
    assert!(toml.contains("mode = \"strict\""), "{toml}");
    let signers = std::fs::read_to_string(dir.join(".vci/allowed_signers")).unwrap();
    assert!(signers.contains("me@example.com namespaces=\"vci-attest\" ssh-ed25519 "));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("dtolnay/rust-toolchain"), "{stdout}");
    assert!(stdout.contains("vci ci --base-ref"), "{stdout}");
}

/// vci's own repository is a cargo workspace: vci attests (and then skips)
/// the unit tests of vci-core, and refuses units whose code starts processes
/// (vci-git runs `git`; the vci-cli end-to-end tests run `vci`).
#[test]
fn cargo_attests_vci_itself() {
    let root = workspace_root();
    let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("vci-self-target");
    let Some(w) = World::build(
        &VCI_TOML.replace("global = [\"APP_MODE\"]", "global = []"),
        |d| {
            for name in ["Cargo.toml", "Cargo.lock", "crates", "examples"] {
                cp(&root.join(name), &d.join(name));
            }
            // Only sources: a stale build dir inside the copy is not wanted.
            let _ = std::fs::remove_dir_all(d.join("target"));
        },
        &[("CARGO_TARGET_DIR", target.to_str().unwrap())],
    ) else {
        return;
    };
    let work = w.work.clone();
    let stderr = w.run(
        &work,
        &["crates/vci-core#lib", "crates/vci-git#test:repo"],
        &w.trusted,
    );
    assert!(
        stderr.contains("vci: attested crates/vci-core#lib "),
        "{stderr}"
    );
    let line = refusal(&stderr, "crates/vci-git#test:repo");
    assert!(
        line.contains("cargo:process") && line.contains("crates/vci-git/src/cmd.rs"),
        "{line}"
    );
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&["crates/vci-core#lib"]), "{p:?}");
    for unit in [
        "crates/vci-cli#test:e2e",
        "crates/vci-cli#test:e2e_cargo",
        "crates/vci-cli#bin:vci",
        "crates/vci-git#test:repo",
    ] {
        assert!(p.run.contains(unit), "{unit}: {p:?}");
    }
    // vci-core's tests only use cfg(unix)/cfg(not(unix)): the same on macOS
    // and Linux.
    let pred = &w.predicates("crates/vci-core#lib")[0];
    assert!(pred.get("platformSpecific").is_none(), "{pred}");
    // Editing a file vci-core does not build from leaves it skipped; editing
    // its sources runs it.
    let git_src = w.read("crates/vci-git/src/lib.rs");
    w.put(
        "crates/vci-git/src/lib.rs",
        &format!("{git_src}\n// edited\n"),
    );
    assert!(w.plan(&work, "main").skip.contains("crates/vci-core#lib"));
    let core = w.read("crates/vci-core/src/hash.rs");
    w.put(
        "crates/vci-core/src/hash.rs",
        &format!("{core}\n// edited\n"),
    );
    assert!(w.plan(&work, "main").run.contains("crates/vci-core#lib"));
}

/// Another rustc/cargo never matches: here rustup's cargo proxy with another
/// installed toolchain (`RUSTUP_TOOLCHAIN` is pass-through). Skipped without
/// rustup or a second toolchain whose release differs.
#[test]
fn cargo_other_toolchain_runs() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let Some(rustup) = std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join("rustup"))
            .find(|p| p.is_file())
    }) else {
        eprintln!("SKIPPED: rustup is not installed");
        return;
    };
    let proxy = rustup.with_file_name("cargo");
    let ours = String::from_utf8_lossy(&Command::new("rustc").arg("-V").output().unwrap().stdout)
        .into_owned();
    let list = Command::new(&rustup)
        .args(["toolchain", "list"])
        .output()
        .unwrap();
    let other = String::from_utf8_lossy(&list.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
        .find(|t| {
            Command::new(&rustup)
                .args(["run", t, "rustc", "-V"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .is_some_and(|o| String::from_utf8_lossy(&o.stdout) != ours)
        });
    let Some(other) = other else {
        eprintln!("SKIPPED: no rustup toolchain other than {ours}");
        return;
    };
    w.run(&work, &[B], &w.trusted);
    assert!(w.plan(&work, "main").skip.contains(B));
    let env = [
        ("VCI_CARGO", proxy.to_str().unwrap()),
        ("RUSTUP_TOOLCHAIN", other.as_str()),
    ];
    let p = w.plan_env(&work, "main", &env);
    assert!(p.run.contains(B), "{env:?}: {p:?}");
    if p.run_all {
        eprintln!("SKIPPED (part): {env:?} could not be used: {p:?}");
        return;
    }
    let out = w.vci_env(&work, &["explain", B, "--base-ref", "main"], &env);
    let ex = String::from_utf8_lossy(&out.stdout);
    assert!(ex.contains("failed check: toolchain"), "{ex}");
    assert!(
        ex.contains("    rustc\n") && ex.contains("    cargo\n"),
        "{ex}"
    );
}

/// The host triple of the `rustc` on PATH.
fn host_triple() -> String {
    let rustc = Command::new("rustc").arg("-vV").output().unwrap();
    String::from_utf8_lossy(&rustc.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(str::to_owned))
        .unwrap_or_default()
}

/// Regression (adversarial findings): cargo decides freshness by
/// modification times and declared build script inputs, vci by content, so
/// `vci run` attested stale builds: a build script reading a file of its
/// package it does not declare, a build script reading a declared (hashed)
/// variable without `rerun-if-env-changed`, a proc macro reading one at
/// expansion, and a source file restored with an older mtime (`cp -p`,
/// `tar`, `rsync -t`). The repository's crates are now rebuilt from their
/// sources in every `vci run`, so each of these fails and is not attested.
#[test]
fn cargo_rebuilds_repository_crates_before_attesting() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.add_pkg(
        "stale",
        "",
        &[
            (
                "build.rs",
                "fn main() {\n    println!(\"cargo::rerun-if-changed=build.rs\");\n    let m = std::fs::read_to_string(\"mode.txt\").unwrap();\n    let out = std::env::var(\"OUT_DIR\").unwrap();\n    std::fs::write(format!(\"{out}/mode.rs\"), format!(\"pub const EXTRA: &str = {:?};\\n\", m.trim())).unwrap();\n}\n",
            ),
            ("mode.txt", "good\n"),
            (
                "src/lib.rs",
                "include!(concat!(env!(\"OUT_DIR\"), \"/mode.rs\"));\n\n#[test]\nfn extra_is_good() {\n    assert_eq!(EXTRA, \"good\");\n}\n",
            ),
        ],
    );
    w.add_pkg(
        "envst",
        "",
        &[
            (
                "build.rs",
                "fn main() {\n    println!(\"cargo::rerun-if-changed=build.rs\");\n    let m = std::env::var(\"APP_MODE\").unwrap_or_default();\n    let out = std::env::var(\"OUT_DIR\").unwrap();\n    std::fs::write(format!(\"{out}/mode.rs\"), format!(\"pub const MODE: &str = {m:?};\\n\")).unwrap();\n}\n",
            ),
            (
                "src/lib.rs",
                "include!(concat!(env!(\"OUT_DIR\"), \"/mode.rs\"));\n\n#[test]\nfn mode_is_ok() {\n    assert_eq!(MODE, \"ok\");\n}\n",
            ),
        ],
    );
    w.add_pkg(
        "pm",
        "\n[lib]\nproc-macro = true\ntest = false\ndoctest = false\n",
        &[(
            "src/lib.rs",
            "use proc_macro::TokenStream;\n\n/// The value of APP_MODE when the macro is expanded, as a string literal.\n#[proc_macro]\npub fn mode(_: TokenStream) -> TokenStream {\n    format!(\"{:?}\", std::env::var(\"APP_MODE\").unwrap_or_default())\n        .parse()\n        .unwrap()\n}\n",
        )],
    );
    w.add_pkg(
        "pmuse",
        "\n[lib]\ndoctest = false\n\n[dependencies]\npm = { path = \"../pm\" }\n",
        &[(
            "src/lib.rs",
            "#[test]\nfn mode_is_ok() {\n    assert_eq!(pm::mode!(), \"ok\");\n}\n",
        )],
    );
    w.git(&work, &["add", "-A"]);
    w.git(
        &work,
        &["commit", "-q", "-m", "crates with undeclared build inputs"],
    );
    let ok = [("APP_MODE", "ok")];
    let units = ["stale#lib", "envst#lib", "pmuse#lib", A_LIB];
    let (code, stderr) = w.run_env(&units, &ok);
    assert_eq!(code, Some(0), "{stderr}");
    for u in units {
        assert!(
            stderr.contains(&format!("vci: attested {u} ")),
            "{u}: {stderr}"
        );
    }
    let p = w.plan_env(&work, "main", &ok);
    for u in units {
        assert!(p.skip.contains(u), "{u}: {p:?}");
    }

    // (a) The build script's undeclared file changes: the unit runs again
    // from a fresh build, fails, and is not attested.
    w.put("stale/mode.txt", "bad\n");
    let (code, stderr) = w.run_env(&["stale#lib"], &ok);
    assert_ne!(code, Some(0), "{stderr}");
    assert!(
        refusal(&stderr, "stale#lib").contains("result failed"),
        "{stderr}"
    );
    assert!(w.plan_env(&work, "main", &ok).run.contains("stale#lib"));
    assert!(
        stderr.contains("cargo clean --locked --target-dir"),
        "the repository's crates are cleaned first: {stderr}"
    );
    w.put("stale/mode.txt", "good\n");

    // (b), (c) A declared variable read by a build script without
    // rerun-if-env-changed, and by a proc macro.
    let broken = [("APP_MODE", "broken")];
    let (code, stderr) = w.run_env(&["envst#lib", "pmuse#lib"], &broken);
    assert_ne!(code, Some(0), "{stderr}");
    for u in ["envst#lib", "pmuse#lib"] {
        assert!(
            refusal(&stderr, u).contains("result failed"),
            "{u}: {stderr}"
        );
    }
    let p = w.plan_env(&work, "main", &broken);
    assert!(
        p.run.contains("envst#lib") && p.run.contains("pmuse#lib"),
        "{p:?}"
    );

    // (d) An edit restored with an older modification time.
    let src = w.read("a/src/lib.rs");
    w.put("a/src/lib.rs", &src.replace("add(2, 2), 4", "add(2, 2), 5"));
    let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(946_684_800);
    std::fs::File::options()
        .write(true)
        .open(work.join("a/src/lib.rs"))
        .unwrap()
        .set_modified(old)
        .unwrap();
    let (code, stderr) = w.run_env(&[A_LIB], &ok);
    assert_ne!(code, Some(0), "{stderr}");
    assert!(
        refusal(&stderr, A_LIB).contains("result failed"),
        "{stderr}"
    );
    assert!(w.plan_env(&work, "main", &ok).run.contains(A_LIB));
}

/// Regression: only `.rs` files of the dep-info were scanned, so a README
/// included as documentation (`#![doc = include_str!("../README.md")]`, whose
/// doctests run), `include!` of a file with another extension, and code a
/// build script generates into OUT_DIR bypassed every static check.
#[test]
fn cargo_scans_every_file_rustc_reads() {
    let Some(w) = World::new() else { return };
    w.add_pkg(
        "rd",
        "",
        &[
            (
                "src/lib.rs",
                "#![doc = include_str!(\"../README.md\")]\n\npub fn one() -> u8 {\n    1\n}\n",
            ),
            (
                "README.md",
                "# rd\n\n```\nlet out = std::process::Command::new(\"cat\").arg(\"../shared/other.txt\").output().unwrap();\nassert!(out.status.success());\n```\n",
            ),
        ],
    );
    w.add_pkg(
        "inc",
        "\n[lib]\ndoctest = false\n",
        &[
            ("src/lib.rs", "include!(\"tests.inc\");\n"),
            (
                "src/tests.inc",
                "#[test]\nfn reads_shared() {\n    let s = std::fs::read_to_string(\"../shared/other.txt\").unwrap();\n    assert!(!s.is_empty());\n}\n",
            ),
        ],
    );
    w.add_pkg(
        "gen",
        "\n[lib]\ndoctest = false\n",
        &[
            (
                "build.rs",
                "fn main() {\n    println!(\"cargo::rerun-if-changed=build.rs\");\n    // Spelled in pieces so this file does not mention it itself.\n    let spawn = [\"std::process::Comm\", \"and::new\"].concat();\n    let out = std::env::var(\"OUT_DIR\").unwrap();\n    std::fs::write(\n        format!(\"{out}/gen_tests.rs\"),\n        format!(\"#[test]\\nfn spawns() {{\\n    assert!({spawn}(\\\"true\\\").status().unwrap().success());\\n}}\\n\"),\n    )\n    .unwrap();\n}\n",
            ),
            (
                "src/lib.rs",
                "include!(concat!(env!(\"OUT_DIR\"), \"/gen_tests.rs\"));\n",
            ),
        ],
    );
    let (_, stderr) = w.run_env(&["rd#doc", "inc#lib", "gen#lib"], &[]);
    let line = refusal(&stderr, "rd#doc");
    assert!(
        line.contains("cargo:process") && line.contains("rd/README.md"),
        "{line}"
    );
    let line = refusal(&stderr, "inc#lib");
    assert!(
        line.contains("shared/other.txt") && line.contains("declare it"),
        "{line}"
    );
    let line = refusal(&stderr, "gen#lib");
    assert!(
        line.contains("cargo:process") && line.contains("gen_tests.rs"),
        "{line}"
    );
    assert!(
        stderr.contains("vci: 0 attested, 3 not attested"),
        "{stderr}"
    );
}

/// Regression: repository cargo config that names programs vci does not
/// hash (a test runner, a rustc wrapper, also as `RUSTC_WRAPPER`) was
/// accepted, and target-specific tables (which apply only on the matching
/// host) were neither recorded nor applied to the cfg probe.
#[test]
fn cargo_repository_config_that_differs_per_platform() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let host = host_triple();
    let script = "#!/bin/sh\nexec \"$@\"\n";
    w.put("tools/run.sh", script);
    w.put("tools/wrap.sh", script);
    for f in ["tools/run.sh", "tools/wrap.sh"] {
        let st = Command::new("chmod")
            .arg("+x")
            .arg(work.join(f))
            .status()
            .unwrap();
        assert!(st.success());
    }
    let refused = |config: Option<&str>, env: &[(&str, &str)], why: &str| {
        match config {
            Some(c) => w.put(".cargo/config.toml", c),
            None => {
                let _ = std::fs::remove_file(work.join(".cargo/config.toml"));
            }
        }
        let (_, stderr) = w.run_env(&[A_LIB], env);
        let line = refusal(&stderr, A_LIB);
        assert!(line.contains(why), "{config:?} {env:?}: {line}");
    };
    refused(
        Some(&format!("[target.{host}]\nrunner = \"tools/run.sh\"\n")),
        &[],
        "cargo:config",
    );
    refused(
        Some("[target.'cfg(unix)']\nrunner = \"tools/run.sh\"\n"),
        &[],
        "runner",
    );
    refused(
        Some("[build]\nrustc-wrapper = \"tools/wrap.sh\"\n"),
        &[],
        "cargo:wrapper",
    );
    let wrap = work.join("tools/wrap.sh");
    refused(
        None,
        &[("RUSTC_WRAPPER", wrap.to_str().unwrap())],
        "cargo:wrapper",
    );

    // A cfg table: attested, with its predicate recorded and its flags in
    // the recorded cfg set.
    w.put(
        ".cargo/config.toml",
        "[target.'cfg(target_os = \"macos\")']\nrustflags = [\"--cfg\", \"on_mac\"]\n[target.'cfg(target_os = \"linux\")']\nrustflags = [\"--cfg\", \"on_linux\"]\n",
    );
    w.run(&work, &[A_LIB], &w.trusted);
    let pred = w
        .predicates(A_LIB)
        .into_iter()
        .find(|p| p.get("cfgPredicates").is_some())
        .expect("an attestation with cfg predicates");
    let preds: Vec<&str> = pred["cfgPredicates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(preds.contains(&"target_os = \"macos\""), "{preds:?}");
    assert!(preds.contains(&"target_os = \"linux\""), "{preds:?}");
    let rust_cfg: Vec<String> = pred["toolchain"]["rustCfg"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    let flag = if cfg!(target_os = "macos") {
        "on_mac"
    } else {
        "on_linux"
    };
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        assert!(rust_cfg.iter().any(|c| c == flag), "{rust_cfg:?}");
    }
    let linux = Command::new("rustc")
        .args(["--print", "cfg", "--target", "x86_64-unknown-linux-gnu"])
        .output()
        .unwrap();
    if linux.status.success() && cfg!(target_os = "macos") {
        let linux: Vec<String> = String::from_utf8_lossy(&linux.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        assert!(
            vci_adapter::cfg_predicate_differs("target_os = \"macos\"", &rust_cfg, &linux).unwrap(),
            "a Linux runner does not apply the macOS table: the unit runs there"
        );
    }

    // A table for this host's triple: pinned to this OS and architecture.
    w.put(
        ".cargo/config.toml",
        &format!("[target.{host}]\nrustflags = [\"--cfg\", \"on_host\"]\n"),
    );
    w.run(&work, &[A_LIB], &w.trusted);
    let pred = w
        .predicates(A_LIB)
        .into_iter()
        .find(|p| p.get("platformSpecific").is_some())
        .expect("a platform-specific attestation");
    assert_eq!(
        pred["platformSpecific"],
        serde_json::json!([".cargo/config.toml"])
    );
    assert!(
        pred["toolchain"]["rustCfg"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "on_host"),
        "{pred}"
    );
}

/// Regression: `std::env::consts::DLL_SUFFIX` (and the other consts) in a
/// test, and a build script that emits a custom cfg after checking
/// `std::env::consts::OS`, were accepted on another platform.
#[test]
fn cargo_platform_constants_and_build_script_checks_pin_the_platform() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.add_crate(
        "e",
        "pub fn lib_name(n: &str) -> String {\n    format!(\"{}{}{}\", std::env::consts::DLL_PREFIX, n, std::env::consts::DLL_SUFFIX)\n}\n\n#[test]\nfn names() {\n    assert!(lib_name(\"x\").contains('x'));\n}\n",
    );
    w.add_pkg(
        "f",
        "\n[lib]\ndoctest = false\n",
        &[
            (
                "build.rs",
                "fn main() {\n    println!(\"cargo::rustc-check-cfg=cfg(host_is_mac)\");\n    if std::env::consts::OS == \"macos\" {\n        println!(\"cargo::rustc-cfg=host_is_mac\");\n    }\n}\n",
            ),
            (
                "src/lib.rs",
                "#[cfg(host_is_mac)]\npub fn flavour() -> &'static str {\n    \"mac\"\n}\n#[cfg(not(host_is_mac))]\npub fn flavour() -> &'static str {\n    \"other\"\n}\n\n#[test]\nfn has_flavour() {\n    assert!(!flavour().is_empty());\n}\n",
            ),
        ],
    );
    w.run(&work, &["e#lib", "f#lib"], &w.trusted);
    assert_eq!(
        w.predicates("e#lib")[0]["platformSpecific"],
        serde_json::json!(["e/src/lib.rs"])
    );
    assert_eq!(
        w.predicates("f#lib")[0]["platformSpecific"],
        serde_json::json!(["f/build.rs"])
    );
    let p = w.plan(&work, "main");
    assert!(
        p.skip.contains("e#lib") && p.skip.contains("f#lib"),
        "{p:?}"
    );
}

/// Regressions of the package directory walk: a symlinked directory's
/// contents were not hashed (only its listing); any directory named `.git`
/// or ending in `.vci/out` was skipped anywhere in a package.
#[cfg(unix)]
#[test]
fn cargo_package_directory_walk() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put("shared/dir/x.json", "{\"v\": 1}\n");
    std::os::unix::fs::symlink("../../shared/dir", work.join("b/tests/linkdir")).unwrap();
    w.put(
        "b/tests/link.rs",
        "#[test]\nfn reads_through_the_link() {\n    let s = std::fs::read_to_string(\"tests/linkdir/x.json\").unwrap();\n    assert!(s.contains('1'));\n}\n",
    );
    w.put("b/tests/fixtures/.vci/out/b.json", "{\"n\": 1}\n");
    w.put(
        "b/tests/nested.rs",
        "#[test]\nfn reads_the_fixture() {\n    let s = std::fs::read_to_string(\"tests/fixtures/.vci/out/b.json\").unwrap();\n    assert!(s.contains('1'));\n}\n",
    );
    w.git(&work, &["add", "-A", "-f"]);
    w.git(&work, &["commit", "-q", "-m", "linked and nested fixtures"]);
    w.run(&work, &["b#test:link", "b#test:nested"], &w.trusted);
    let entries = w.entries("b#test:link");
    for want in ["b/tests/linkdir", "shared/dir", "shared/dir/x.json"] {
        assert!(entries.iter().any(|e| e == want), "{want}: {entries:?}");
    }
    assert!(
        w.entries("b#test:nested")
            .iter()
            .any(|e| e == "b/tests/fixtures/.vci/out/b.json")
    );
    let p = w.plan(&work, "main");
    assert!(
        p.skip.contains("b#test:link") && p.skip.contains("b#test:nested"),
        "{p:?}"
    );
    w.put("shared/dir/x.json", "{\"v\": 2}\n");
    assert!(w.plan(&work, "main").run.contains("b#test:link"));
    assert!(
        w.explain(&work, "b#test:link", "main")
            .contains("entry:shared/dir/x.json")
    );
    w.put("b/tests/fixtures/.vci/out/b.json", "{\"n\": 2}\n");
    assert!(w.plan(&work, "main").run.contains("b#test:nested"));

    // Another repository inside a package directory: refused.
    w.put("c/vendor/.git/HEAD", "ref: refs/heads/main\n");
    let (_, stderr) = w.run_env(&[C], &[]);
    assert!(
        refusal(&stderr, C).contains("git repository inside a package directory"),
        "{stderr}"
    );
}

/// Regression: a package at the repository root listed the local `target/`
/// directory (absent in a fresh checkout, so the unit never matched there),
/// and its first `vci run` was refused because `target/` was created in the
/// root during the run.
#[test]
fn cargo_package_at_the_repository_root() {
    let fx = workspace_root().join("fixtures/cargo-abcd");
    let Some(w) = World::build(
        VCI_TOML,
        |d| {
            std::fs::create_dir_all(d.join("src")).unwrap();
            cp(&fx.join("a"), &d.join("a"));
            std::fs::write(
                d.join("Cargo.toml"),
                "[package]\nname = \"rootp\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n[lib]\ndoctest = false\n\n[workspace]\nmembers = [\"a\"]\n",
            )
            .unwrap();
            std::fs::write(
                d.join("src/lib.rs"),
                "#[test]\nfn works() {\n    assert_eq!(1 + 1, 2);\n}\n",
            )
            .unwrap();
            let st = Command::new("cargo")
                .args(["generate-lockfile", "--offline"])
                .current_dir(d)
                .env_remove("CARGO_TARGET_DIR")
                .status()
                .unwrap();
            assert!(st.success());
        },
        &[],
    ) else {
        return;
    };
    let work = w.work.clone();
    assert!(!work.join("target").exists());
    let stderr = w.run(&work, &[".#lib"], &w.trusted);
    assert!(stderr.contains("vci: attested .#lib "), "{stderr}");
    assert!(work.join("target").is_dir(), "the build created target/");
    let entries = w.entries(".#lib");
    assert!(entries.iter().any(|e| e == "target"), "{entries:?}");
    assert!(w.plan(&work, "main").skip.contains(".#lib"));
    // A fresh checkout has no target/ (and a local vci ci may leave
    // .vci/out behind): still skipped.
    std::fs::rename(work.join("target"), w.base.join("target-moved")).unwrap();
    w.put(".vci/out/audit-1.json", "{}\n");
    let p = w.plan(&work, "main");
    assert!(p.skip.contains(".#lib"), "{p:?}");
    // Any other new file in the root still runs it.
    w.put("notes.txt", "x\n");
    assert!(w.plan(&work, "main").run.contains(".#lib"));
}

/// Regression: paths held in a `const` and used with a file API, and a path
/// the source names in another letter case than the file (found on a
/// case-insensitive filesystem only), were attested.
#[test]
fn cargo_paths_in_consts_and_letter_case() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.add_crate(
        "rds",
        "const ROOT: &str = \"../shared/other.txt\";\n\n#[test]\nfn reads_through_a_const() {\n    assert!(!std::fs::read_to_string(ROOT).unwrap().is_empty());\n}\n",
    );
    w.add_crate(
        "cs",
        "#[test]\nfn reads_in_another_case() {\n    assert!(!std::fs::read_to_string(\"tests/Data/B.json\").unwrap().is_empty());\n}\n",
    );
    w.put("cs/tests/data/b.json", "{}\n");
    let (_, stderr) = w.run_env(&["rds#lib", "cs#lib"], &[]);
    let line = refusal(&stderr, "rds#lib");
    assert!(
        line.contains("shared/other.txt") && line.contains("declare it"),
        "{line}"
    );
    let line = refusal(&stderr, "cs#lib");
    if work.join("CS/TESTS/DATA/B.JSON").exists() {
        assert!(line.contains("cargo:path-case"), "{line}");
    } else {
        assert!(line.contains("result failed"), "{line}");
    }
}

/// The sources of the crates `$CARGO_HOME` holds for this cargo.
fn cargo_home() -> PathBuf {
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cargo"))
}

/// Regression: an out-of-repository `[source]` replacement (listed as
/// harmless) served an edited `hex` with a `.cargo-checksum.json` claiming
/// the Cargo.lock checksum, and it was attested as that version.
#[test]
fn cargo_source_replacement_outside_the_repository_is_refused() {
    let Some(w) = World::new() else { return };
    let Some(hex_src) = std::fs::read_dir(cargo_home().join("registry/src"))
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path().join("hex-0.4.3"))
        .find(|p| p.is_dir())
    else {
        eprintln!("SKIPPED: hex-0.4.3 is not extracted in $CARGO_HOME/registry/src");
        return;
    };
    let vendor = w.base.join("vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    cp(&hex_src, &vendor.join("hex"));
    let _ = std::fs::remove_file(vendor.join("hex/.cargo-ok"));
    std::fs::write(
        vendor.join("hex/.cargo-checksum.json"),
        "{\"files\":{},\"package\":\"7f24254aa9a54b5c858eaee2f5bccdb46aaf0e486a595ed5fd8f86ba55232a70\"}",
    )
    .unwrap();
    std::fs::create_dir_all(w.base.join(".cargo")).unwrap();
    std::fs::write(
        w.base.join(".cargo/config.toml"),
        format!(
            "[source.crates-io]\nreplace-with = \"vend\"\n\n[source.vend]\ndirectory = \"{}\"\n",
            vendor.display()
        ),
    )
    .unwrap();
    let (_, stderr) = w.run_env(&[D], &[]);
    let line = refusal(&stderr, D);
    assert!(
        line.contains("cargo:source") && line.contains("source replacement"),
        "{line}"
    );
}

/// Regression: a git dependency's checkout in `$CARGO_HOME` edited in
/// place was attested as the locked commit.
#[test]
fn cargo_git_checkouts_must_match_the_locked_commit() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("SKIPPED: git is not installed");
        return;
    }
    let outer = tempfile::tempdir().unwrap();
    let outer_p = outer.path().canonicalize().unwrap();
    let dep = outer_p.join("gd");
    let home = outer_p.join("cargohome");
    std::fs::create_dir_all(dep.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        dep.join("Cargo.toml"),
        "[package]\nname = \"gd\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    std::fs::write(dep.join("src/lib.rs"), "pub fn v() -> u8 {\n    1\n}\n").unwrap();
    let g = |args: &[&str]| {
        let st = Command::new("git")
            .current_dir(&dep)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "{}",
            String::from_utf8_lossy(&st.stderr)
        );
    };
    g(&["init", "-q", "-b", "main"]);
    g(&["add", "-A"]);
    g(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@e",
        "commit",
        "-q",
        "-m",
        "gd",
    ]);
    let url = format!("file://{}", dep.display());
    let Some(w) = World::build(
        VCI_TOML,
        |d| {
            std::fs::create_dir_all(d.join("u/src")).unwrap();
            std::fs::write(
                d.join("Cargo.toml"),
                "[workspace]\nresolver = \"3\"\nmembers = [\"u\"]\n",
            )
            .unwrap();
            std::fs::write(
                d.join("u/Cargo.toml"),
                format!(
                    "[package]\nname = \"u\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n[lib]\ndoctest = false\n\n[dependencies]\ngd = {{ git = \"{url}\", branch = \"main\" }}\n"
                ),
            )
            .unwrap();
            std::fs::write(
                d.join("u/src/lib.rs"),
                "#[test]\nfn uses_gd() {\n    assert_eq!(gd::v(), 1);\n}\n",
            )
            .unwrap();
            let st = Command::new("cargo")
                .args(["generate-lockfile"])
                .current_dir(d)
                .env("CARGO_HOME", &home)
                .env_remove("CARGO_TARGET_DIR")
                .status()
                .unwrap();
            assert!(st.success());
        },
        &[("CARGO_HOME", home.to_str().unwrap())],
    ) else {
        return;
    };
    let work = w.work.clone();
    let stderr = w.run(&work, &["u#lib"], &w.trusted);
    assert!(stderr.contains("vci: attested u#lib "), "{stderr}");
    // Edit the checkout (and the test to match), rebuild from scratch.
    let checkout = std::fs::read_dir(home.join("git/checkouts"))
        .unwrap()
        .flatten()
        .flat_map(|d| std::fs::read_dir(d.path()).unwrap().flatten())
        .map(|e| e.path())
        .find(|p| p.join("src/lib.rs").is_file())
        .expect("a checkout of gd");
    std::fs::write(
        checkout.join("src/lib.rs"),
        "pub fn v() -> u8 {\n    2\n}\n",
    )
    .unwrap();
    w.put(
        "u/src/lib.rs",
        "#[test]\nfn uses_gd() {\n    assert_eq!(gd::v(), 2);\n}\n",
    );
    let _ = std::fs::remove_dir_all(work.join("target"));
    let (_, stderr) = w.run_env(&["u#lib"], &[]);
    let line = refusal(&stderr, "u#lib");
    assert!(
        line.contains("cargo:source") && line.contains("differs from commit"),
        "{line}"
    );
}
