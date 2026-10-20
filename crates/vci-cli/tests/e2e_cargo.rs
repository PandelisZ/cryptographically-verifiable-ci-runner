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

mod env_common;
mod store_common;

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
hash = ["APP_MODE"]
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
                store_common::inline_manifest(&repo, st["predicate"].clone())
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

    // Step 11: a variable listed in [env] hash with a different value in
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

    // Step 12: a rustc flag in the environment (built-in hash: it reaches the
    // build and is hashed whenever present) runs the unit; an undeclared
    // variable outside the built-in lists is removed, so it changes nothing.
    let p = w.plan_env(&work, "main", &[("RUSTFLAGS", "-Copt-level=1")]);
    assert!(p.run.contains(B), "RUSTFLAGS is built-in hash: {p:?}");
    let p = w.plan_env(&work, "main", &[("CARGO_SOMETHING_ELSE", "1")]);
    assert!(p.skip.contains(B), "removed: {p:?}");
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
        ("outside#lib", "shared/other.txt"),
        ("outside#lib", "declare it in vci.toml"),
        ("ffi#lib", "cargo:native"),
    ] {
        let line = refusal(&stderr, id);
        assert!(line.contains(why), "{id}: expected {why:?} in {line:?}");
    }
    // A target without tests passes with 0 tests (since 1.9.1): cargo
    // filters nothing, and it stays empty wherever the same sources build.
    assert!(stderr.contains("vci: attested notests#lib ("), "{stderr}");
    assert!(
        stderr.contains("vci: 1 attested, 6 not attested"),
        "{stderr}"
    );
    let stored = AttestStore::new(&store_for(&work)).list(None).unwrap();
    assert_eq!(
        stored.len(),
        1,
        "only the target without tests may be stored: {stored:?}"
    );
    let p = w.plan(&work, "main");
    for id in &ids {
        if id.as_str() == "notests#lib" {
            assert!(p.skip.contains(id), "{id} skips: {p:?}");
        } else {
            assert!(p.run.contains(id), "{id} must run: {p:?}");
        }
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
        &toml.replace("[env]\n", "[env]\nmode = \"loose\"\n"),
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
    assert!(toml.contains("set = { TZ = \"UTC\" }"), "{toml}");
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
        &VCI_TOML.replace("hash = [\"APP_MODE\"]", "hash = []"),
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
    // The policy can waive the undeclared path (`cargo:undeclared-reads`):
    // the unit is attested with it recorded as waived, and the base policy
    // must still waive it for the plan to skip the unit.
    let toml = w.read("vci.toml");
    w.put(
        "vci.toml",
        &toml.replace(
            "[policy]\n",
            "[policy]\nignore_taints = [\"cargo:undeclared-reads\"]\n",
        ),
    );
    w.git(&work, &["add", "-A"]);
    w.git(&work, &["commit", "-q", "-m", "waive undeclared reads"]);
    let waiving_base = w.git(&work, &["rev-parse", "HEAD"]);
    let (_, stderr) = w.run_env(&["rds#lib"], &[]);
    assert!(stderr.contains("vci: attested rds#lib"), "{stderr}");
    let waived = w.predicates("rds#lib")[0]["waived"].clone();
    assert!(
        waived.to_string().contains("cargo:undeclared-reads"),
        "{waived}"
    );
    let p = w.plan(&work, &waiving_base);
    assert!(
        p.skip.contains("rds#lib"),
        "{p:?}\n{}",
        w.explain(&work, "rds#lib", &waiving_base)
    );
    // `main` (the base without the waiver) does not accept it.
    let ex = w.explain(&work, "rds#lib", "main");
    assert!(ex.contains("waived taint cargo:undeclared-reads"), "{ex}");
    assert!(w.plan(&work, "main").run.contains("rds#lib"));
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

/// Regression: `RUST_BACKTRACE`, `RUST_LIB_BACKTRACE` and `RUST_LOG` were
/// built-in ignore (visible, never hashed), but std and dependency crates read
/// them where the source scan does not see it, so a test that depends on one
/// was attested where it is unset and skipped where it is set (and fails
/// there). They are removed unless vci.toml lists them, as in vci 1.5: the
/// test sees them unset under vci whatever the machine has.
#[test]
fn cargo_backtrace_and_log_variables_do_not_reach_the_tests() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.add_crate(
        "bt",
        r#"#[cfg(test)]
mod tests {
    #[test]
    fn backtraces_are_off() {
        use std::backtrace::{Backtrace, BacktraceStatus};
        assert_eq!(Backtrace::capture().status(), BacktraceStatus::Disabled);
        assert!(std::env::var_os("RUST_LOG").is_none());
    }
}
"#,
    );
    let set = [
        ("RUST_BACKTRACE", "1"),
        ("RUST_LIB_BACKTRACE", "1"),
        ("RUST_LOG", "debug"),
    ];
    let (code, stderr) = w.run_env(&["bt#lib"], &set);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.contains("vci: attested bt#lib "), "{stderr}");
    let p = w.plan_env(&work, "main", &set);
    assert!(p.skip.contains("bt#lib"), "{p:?}");
    let out = w.vci_env(&work, &["env"], &set);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text
            .lines()
            .any(|l| l.contains("RUST_BACKTRACE") && l.contains("ignore")),
        "{text}"
    );
}

/// The `[env]` lists end to end (tests/env_common): a `set` variable reaches
/// the test and is the same on every machine, a `hash` variable's change
/// re-runs, an `ignore` variable's does not, an undeclared variable never
/// reaches the test, `vci env` shows it all, and the old key names still work.
#[test]
fn cargo_env_set_hash_ignore_and_strip() {
    let Some(w) = World::build(
        &env_common::with_env(VCI_TOML, env_common::ENV_NEW),
        copy_cargo_fixture,
        &[],
    ) else {
        return;
    };
    w.add_crate(
        "envp",
        r#"#[cfg(test)]
mod tests {
    #[test]
    fn env() {
        assert_eq!(std::env::var("APP_SET").as_deref(), Ok("declared"));
        assert_eq!(std::env::var("TZ").as_deref(), Ok("UTC"));
        assert!(std::env::var("APP_HASH").is_ok());
        assert!(std::env::var("APP_IGNORE").is_ok());
        assert!(std::env::var_os("APP_UNDECLARED").is_none());
    }
}
"#,
    );
    let vci = |args: &[&str], env: &[(&'static str, String)]| {
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        w.vci_env(&w.work, args, &env)
    };
    let git = |dir: &Path, args: &[&str]| w.git(dir, args);
    env_common::check_env_lists(
        &env_common::Ops {
            work: &w.work,
            scratch: &w.base,
            vci: &vci,
            git: &git,
            key: w.trusted.to_str().unwrap(),
        },
        "envp#lib",
        &["envp#lib"],
    );
}

/// The execution pool runs several units' test executables at once: two
/// units that each sleep 1.5 s run at the same time in one `vci run` (each
/// writes when it ran next to its own TMPDIR, which is where `vci` makes
/// every unit's TMPDIR), every unit of the run is attested, doctests
/// included, and each unit's output is printed as one block. The tests also
/// check some of what `cargo test` gives a test process: the package
/// directory as working directory and the `CARGO_PKG_*` variables.
#[test]
fn cargo_runs_units_in_parallel() {
    let Some(w) = World::new() else { return };
    let slow = |name: &str| {
        format!(
            r#"#[cfg(test)]
mod tests {{
    use std::time::{{Duration, SystemTime, UNIX_EPOCH}};

    #[test]
    fn takes_a_while() {{
        let now = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), env!("CARGO_PKG_NAME"));
        assert_eq!(std::env::var("CARGO_PKG_VERSION").unwrap(), "0.1.0");
        assert!(std::path::Path::new("src/lib.rs").is_file(), "runs in its package directory");
        let start = now();
        std::thread::sleep(Duration::from_millis(1500));
        let end = now();
        let tag = std::env::var("APP_MODE").unwrap();
        let dir = std::env::temp_dir();
        let out = dir.parent().unwrap().join(format!("{{tag}}-{name}"));
        std::fs::write(out, format!("{{start}} {{end}}")).unwrap();
    }}
}}
"#
        )
    };
    w.add_crate("slowa", &slow("slowa"));
    w.add_crate("slowb", &slow("slowb"));
    let tag = format!(
        "vci-e2e-parallel-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let units = ["slowa#lib", "slowb#lib", A_LIB, A_DOC, B, C, D];
    let (code, stderr) = w.run_env(
        &units,
        &[("APP_MODE", tag.as_str()), ("VCI_CARGO_JOBS", "4")],
    );
    assert_eq!(code, Some(0), "{stderr}");
    for u in units {
        assert!(
            stderr.contains(&format!("vci: attested {u} ")),
            "{u}: {stderr}"
        );
    }
    assert!(
        stderr.contains("vci: warm-up build: "),
        "one warm-up build: {stderr}"
    );
    let span = |name: &str| -> (u128, u128) {
        let p = std::env::temp_dir().join(format!("{tag}-{name}"));
        let t = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        let _ = std::fs::remove_file(&p);
        let (a, b) = t.split_once(' ').unwrap();
        (a.parse().unwrap(), b.parse().unwrap())
    };
    let (a0, a1) = span("slowa");
    let (b0, b1) = span("slowb");
    assert!(
        a0 < b1 && b0 < a1,
        "the two units ran one after the other: slowa {a0}..{a1}, slowb {b0}..{b1}"
    );
    // Each unit's output is one block: its test lines follow its own header.
    for name in ["slowa", "slowb"] {
        let at = stderr
            .find(&format!("/{name}) "))
            .unwrap_or_else(|| panic!("no block for {name}: {stderr}"));
        let block = &stderr[at..];
        let block = &block[..block[1..].find("\nvci: ").map_or(block.len(), |i| i + 1)];
        assert!(
            block.contains("test tests::takes_a_while ... ok"),
            "{name}: {block}"
        );
    }
    for u in ["slowa#lib", "slowb#lib"] {
        let ms = w.predicates(u)[0]["result"]["durationMs"].as_u64().unwrap();
        assert!(ms >= 1500, "{u}: {ms} ms");
    }
}

/// Regression: a test that deletes an untracked nested git repository in
/// its package directory (the repository root) changed the tree it ran in.
/// The nested repository was left out of the tree snapshot, so the unit was
/// attested (for a tree without it, where its test fails); and run with
/// another unit of the same package, whose analysis walked the package
/// directory before the test ran, it was refused for another reason. Every
/// unit is analysed once every test has run, and the removal is a change.
#[test]
fn cargo_test_deleting_a_nested_repository_is_refused() {
    let Some(w) = World::build(
        VCI_TOML,
        |d| {
            std::fs::create_dir_all(d.join("src")).unwrap();
            std::fs::write(
                d.join("Cargo.toml"),
                "[package]\nname = \"rootp\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
            )
            .unwrap();
            std::fs::write(
                d.join("src/lib.rs"),
                "/// ```\n/// assert_eq!(rootp::two(), 2);\n/// ```\npub fn two() -> i32 {\n    2\n}\n\n#[test]\nfn removes_inner() {\n    assert!(std::path::Path::new(\"inner/.git\").exists());\n    std::fs::remove_dir_all(\"inner\").unwrap();\n}\n",
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
    let inner = work.join("inner");
    let make_inner = || {
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("README"), "r\n").unwrap();
        w.git(&inner, &["init", "-q"]);
        w.git(&inner, &["add", "-A"]);
        w.git(&inner, &["commit", "-q", "-m", "inner"]);
    };
    for units in [&[".#lib"][..], &[".#doc", ".#lib"]] {
        make_inner();
        let (_, stderr) = w.run_env(units, &[]);
        assert!(!inner.exists(), "the test ran: {stderr}");
        let line = refusal(&stderr, ".#lib");
        assert!(
            line.contains("input changed during the run: .: modified during the run"),
            "{units:?}: {line}"
        );
    }
}

/// The warm-up builds each package alone, as its units' own builds do: a
/// package whose dependency's features another package unifies (`fb`
/// enables `fa/x`) is not compiled again by its units' builds.
#[test]
fn cargo_warm_up_unifies_features_like_the_units() {
    let Some(w) = World::new() else { return };
    w.add_pkg(
        "fa",
        "\n[lib]\ndoctest = false\n\n[features]\nx = []\n",
        &[(
            "src/lib.rs",
            "pub fn x() -> bool {\n    cfg!(feature = \"x\")\n}\n\n#[test]\nfn plain() {\n    assert!(!x());\n}\n",
        )],
    );
    w.add_pkg(
        "fb",
        "\n[lib]\ndoctest = false\n\n[dependencies]\nfa = { path = \"../fa\", features = [\"x\"] }\n",
        &[(
            "src/lib.rs",
            "#[test]\nfn unified() {\n    assert!(fa::x());\n}\n",
        )],
    );
    let (code, stderr) = w.run_env(&["fa#lib", "fb#lib"], &[]);
    assert_eq!(code, Some(0), "{stderr}");
    for u in ["fa#lib", "fb#lib"] {
        assert!(stderr.contains(&format!("vci: attested {u} ")), "{stderr}");
    }
    for pkg in ["fa", "fb"] {
        assert!(
            stderr.contains(&format!(
                "vci: warm-up build: cargo test --locked --no-run --manifest-path {pkg}/Cargo.toml"
            )),
            "{stderr}"
        );
        let head = format!("--manifest-path {pkg}/Cargo.toml --lib --no-run");
        let at = stderr
            .find(&head)
            .unwrap_or_else(|| panic!("no build of {pkg}#lib: {stderr}"));
        let block = &stderr[at..];
        let block = &block[..block.find("\nvci: ").unwrap_or(block.len())];
        assert!(
            !block.contains("Compiling"),
            "{pkg}#lib compiled after the warm-up: {block}"
        );
    }
}

/// A package with a binary: `cargo test --test <t>` also builds the binary
/// (for `CARGO_BIN_EXE_<name>`), uplifted to `<target>/debug/<name>` where
/// no dep-info sits next to it. Its dep-info is found through the
/// `deps/<name>-<hash>` build it copies, so the integration tests are
/// attested (1.7.1 refused every one of them with "no dep-info file").
#[test]
fn cargo_integration_tests_of_a_package_with_a_binary_are_attested() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.add_pkg(
        "withbin",
        "",
        &[
            ("src/lib.rs", "pub fn two() -> u32 {\n    2\n}\n"),
            (
                "src/main.rs",
                "fn main() {\n    println!(\"{}\", withbin::two());\n}\n",
            ),
            (
                "tests/pure.rs",
                "#[test]\nfn lib_works() {\n    assert_eq!(withbin::two(), 2);\n}\n",
            ),
        ],
    );
    w.git(&work, &["add", "-A"]);
    w.git(&work, &["commit", "-q", "-m", "a package with a binary"]);
    let stderr = w.run(&work, &["withbin#test:pure"], &w.trusted);
    assert!(
        stderr.contains("vci: attested withbin#test:pure"),
        "{stderr}"
    );
    let entries = w.entries("withbin#test:pure");
    assert!(
        entries.iter().any(|e| e == "withbin/src/main.rs"),
        "the binary's sources are inputs: {entries:?}"
    );
    let p = w.plan(&work, "main");
    assert!(p.skip.contains("withbin#test:pure"), "{p:?}");
}

/// A file rustc reads through a symlinked directory (`sl/docs -> ../shared`,
/// `include_str!("../docs/x.md")`): the link and the file at its real path
/// are the inputs, and the unit is attested (the pre-run snapshot holds no
/// entry for the spelling through the link).
#[test]
fn cargo_dep_info_through_a_symlinked_directory_is_attested() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put("shared/docs/x.md", "# x\n");
    w.add_crate(
        "sl",
        "pub const DOC: &str = include_str!(\"../docs/x.md\");\n\n#[test]\nfn has_doc() {\n    assert!(DOC.starts_with(\"# x\"));\n}\n",
    );
    std::os::unix::fs::symlink("../shared/docs", work.join("sl/docs")).unwrap();
    w.git(&work, &["add", "-A"]);
    w.git(
        &work,
        &["commit", "-q", "-m", "a crate reading through a symlink"],
    );
    let stderr = w.run(&work, &["sl#lib"], &w.trusted);
    assert!(stderr.contains("vci: attested sl#lib"), "{stderr}");
    let entries = w.entries("sl#lib");
    for want in ["sl/docs", "shared/docs/x.md"] {
        assert!(entries.iter().any(|e| e == want), "{want}: {entries:?}");
    }
    assert!(
        !entries.iter().any(|e| e == "sl/docs/x.md"),
        "not the spelling through the link: {entries:?}"
    );
    w.put("shared/docs/x.md", "# changed\n");
    w.git(&work, &["commit", "-qam", "edit through the target"]);
    assert!(w.plan(&work, "main").run.contains("sl#lib"));
}

/// A `$CARGO_HOME` inside the repository (CI mounting the registry under the
/// checkout): its extracted crates are external packages, not repository
/// crates to clean, rebuild and hash, and the snapshot leaves it alone.
#[test]
fn cargo_home_inside_the_repository_is_not_part_of_it() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let home = work.join(".cargo-home");
    std::fs::create_dir_all(&home).unwrap();
    w.put(".gitignore", ".vci/out/\ntarget/\n.cargo-home/\n");
    w.git(&work, &["commit", "-qam", "ignore the cargo home"]);
    let fetched = Command::new("cargo")
        .current_dir(&work)
        .env("CARGO_HOME", &home)
        .args(["fetch", "--locked"])
        .output()
        .unwrap();
    if !fetched.status.success() {
        eprintln!(
            "SKIPPED: cargo fetch into a fresh CARGO_HOME failed (offline?): {}",
            String::from_utf8_lossy(&fetched.stderr)
        );
        return;
    }
    let (_, stderr) = w.run_env(&[D], &[("CARGO_HOME", home.to_str().unwrap())]);
    assert!(stderr.contains("vci: attested d#lib"), "{stderr}");
    assert!(
        !stderr.contains("cargo reused"),
        "registry crates are not repository crates to rebuild: {stderr}"
    );
    let entries = w.entries(D);
    assert!(
        !entries.iter().any(|e| e.starts_with(".cargo-home/")),
        "{entries:?}"
    );
    assert!(entries.iter().any(|e| e == "d/src/lib.rs"), "{entries:?}");
}

/// `vci prune --superseded` keeps, per unit and signer, the attestation
/// issued last; `vci push --rewrite-history` publishes the metadata as one
/// commit, so a fresh clone downloads only the current values, and a clone
/// holding the old history merges onto the new one at its next fetch.
#[test]
fn cargo_prune_superseded_and_rewrite_history() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.run(&work, &[B], &w.trusted);
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    // An old clone that fetches the first publication (since vci 2.0 a
    // clone's first fetch takes the tip commit only) and the second one.
    let old = w.base.join("old-clone");
    w.git(
        &w.base,
        &["clone", "-q", w.remote.to_str().unwrap(), "old-clone"],
    );
    w.git(&old, &["checkout", "-q", "feature"]);
    w.vci_ok(&old, &["fetch", "--remote", "origin"]);
    w.put(
        "b/tests/data/b.json",
        "{\"greeting\": \"hello\", \"v\": 2}\n",
    );
    w.git(&work, &["commit", "-qam", "b's data changes"]);
    w.run(&work, &[B], &w.trusted);
    assert_eq!(w.predicates(B).len(), 2, "two attestations of b");
    let listed = w.vci_ok(&work, &["prune", "--superseded", "--dry-run"]);
    assert_eq!(
        listed.lines().filter(|l| l.contains("superseded")).count(),
        1,
        "{listed}"
    );
    assert_eq!(w.predicates(B).len(), 2, "a dry run deletes nothing");
    w.vci_ok(&work, &["prune", "--superseded"]);
    let left = w.predicates(B);
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(
        w.plan(&work, "main").skip.contains(B),
        "the newest one is kept"
    );
    w.git(&work, &["push", "-q", "origin", "feature"]);
    // The second publication (the new attestation and the deletion), then
    // the old clone holds the history before the rewrite.
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    w.git(&old, &["fetch", "-q", "origin"]);
    w.git(&old, &["merge", "-q", "--ff-only", "origin/feature"]);
    w.vci_ok(&old, &["fetch", "--remote", "origin"]);
    // A clone's fetched metadata is its tracking ref; the bare remote holds
    // refs/meta/main itself.
    let history = |dir: &Path, refname: &str| {
        w.git(dir, &["rev-list", "--count", refname])
            .trim()
            .parse::<u32>()
            .unwrap()
    };
    const TRACKING: &str = "refs/meta/remotes/main";
    assert!(history(&old, TRACKING) > 1, "the clone fetched the history");
    w.vci_ok(&work, &["push", "--remote", "origin", "--rewrite-history"]);
    let bare = w.remote.clone();
    assert_eq!(
        history(&bare, "refs/meta/main"),
        1,
        "one commit on the remote"
    );
    // A fresh clone sees the pruned store and skips b.
    let fresh = w.base.join("fresh-clone");
    w.git(
        &w.base,
        &["clone", "-q", w.remote.to_str().unwrap(), "fresh-clone"],
    );
    w.git(&fresh, &["checkout", "-q", "feature"]);
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    assert!(w.plan(&fresh, "main").skip.contains(B));
    assert_eq!(history(&fresh, TRACKING), 1);
    // The old clone merges onto the new history and still skips b.
    w.vci_ok(&old, &["fetch", "--remote", "origin"]);
    assert!(w.plan(&old, "main").skip.contains(B));
    // And can publish on top of it: attest c there, push, fresh fetches it.
    w.run(&old, &[C], &w.trusted);
    w.vci_ok(&old, &["push", "--remote", "origin"]);
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    let p = w.plan(&fresh, "main");
    assert!(p.skip.contains(B) && p.skip.contains(C), "{p:?}");
}

// ---- lazy metadata (vci 2.0) ------------------------------------------------

/// The blob ids of `test_id`'s stored attestations and of the manifests
/// they reference, as the remote's refs/meta/main holds them.
fn value_blobs(w: &World, work: &Path, test_id: &str) -> BTreeSet<String> {
    let repo = store_for(work);
    let st = AttestStore::new(&repo);
    let at = |path: String| w.git(&w.remote, &["rev-parse", &format!("refs/meta/main:{path}")]);
    let mut out = BTreeSet::new();
    for (e, statement) in raw_statements(work, test_id) {
        let target = git_meta_lib::Target::parse(&e.target).unwrap();
        out.insert(at(
            git_meta_lib::tree_paths::tree_path(&target, &e.key).unwrap()
        ));
        if let Some(root) = statement["predicate"]["manifestRef"].as_str() {
            out.insert(at(git_meta_lib::tree_paths::tree_path(
                &git_meta_lib::Target::project(),
                &vci_git::manifest_key(root),
            )
            .unwrap()));
        }
    }
    assert!(!st.list(Some(test_id)).unwrap().is_empty());
    out
}

/// Whether `dir`'s object database holds `oid` (never fetching it).
fn has_object(dir: &Path, oid: &str) -> bool {
    Command::new("git")
        .current_dir(dir)
        .args(["cat-file", "-e", oid])
        .env("GIT_NO_LAZY_FETCH", "1")
        .status()
        .unwrap()
        .success()
}

/// A CI clone of a remote that serves partial clones (as GitHub does):
/// `vci fetch` downloads the metadata's keys, a plan fetches the values it
/// reads (and only those), the plan is the same as with every value, a push
/// publishes without fetching the others, and values that cannot be fetched
/// (offline) make their units run.
#[test]
fn cargo_blobless_clone_fetches_only_what_the_plan_reads() {
    let Some(w) = World::new() else { return };
    w.git(&w.remote, &["config", "uploadpack.allowFilter", "true"]);
    let work = w.work.clone();
    w.run(&work, &[B, C], &w.trusted);
    let before = w.plan(&work, "main");
    assert_eq!(before.skip, set(&[B, C]));
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    let (b_blobs, c_blobs) = (value_blobs(&w, &work, B), value_blobs(&w, &work, C));

    // `--no-local`: a clone of a local path would hard-link every object of
    // the remote, metadata included.
    let clone = |name: &str| {
        let dir = w.base.join(name);
        w.git(
            &w.base,
            &[
                "clone",
                "-q",
                "--no-local",
                w.remote.to_str().unwrap(),
                dir.to_str().unwrap(),
            ],
        );
        w.git(&dir, &["checkout", "-q", "feature"]);
        dir
    };
    let fresh = clone("fresh");
    let out = w.vci(&fresh, &["fetch", "--remote", "origin"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("(2 attestations stored locally)"),
        "rows are counted without reading values: {stderr}"
    );
    assert_eq!(
        w.git(&fresh, &["rev-parse", "--is-shallow-repository"]),
        "false",
        "a metadata fetch never makes the repository shallow"
    );
    for oid in b_blobs.iter().chain(&c_blobs) {
        assert!(!has_object(&fresh, oid), "{oid} downloaded by the fetch");
    }

    // Explaining b reads b's values only.
    let text = w.explain(&fresh, B, "main");
    assert!(text.contains("SKIP"), "{text}");
    for oid in &b_blobs {
        assert!(has_object(&fresh, oid), "b's {oid} not fetched");
    }
    for oid in c_blobs.difference(&b_blobs) {
        assert!(!has_object(&fresh, oid), "c's {oid} fetched for b");
    }
    // The whole plan reads (and fetches) the rest: the same plan as with
    // every value.
    assert_eq!(w.plan(&fresh, "main"), before);
    for oid in &c_blobs {
        assert!(has_object(&fresh, oid), "c's {oid} not fetched");
    }

    // Two attestations of b, the newer for inputs the checkout no longer
    // has (an edit attested, then reverted): a fresh clone's plan fetches
    // the manifest of b's newest attestation first, finds it does not
    // match, fetches the older's in a second round and skips b.
    let b_src = std::fs::read_to_string(work.join("b/src/lib.rs")).unwrap();
    std::fs::write(work.join("b/src/lib.rs"), format!("{b_src}\n// edited\n")).unwrap();
    w.run(&work, &[B], &w.trusted);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    std::fs::write(work.join("b/src/lib.rs"), &b_src).unwrap();
    let again = clone("again");
    w.vci_ok(&again, &["fetch", "--remote", "origin"]);
    let out = w.vci_env(
        &again,
        &["plan", "--base-ref", "main", "--format", "json"],
        &[("VCI_TIMING", "1")],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    // vci 2.2: the key says which attestation was made on this checkout's
    // tree, so that one is read first and matches: no second round.
    assert!(
        !stderr.contains("round 2: fetch "),
        "the same-tree attestation is chosen first: {stderr}"
    );
    let p = Plan::from_json(&serde_json::from_slice(&out.stdout).unwrap());
    assert_eq!(p.skip, set(&[B, C]), "{stderr}");
    // A unit that runs with every candidate read and no manifest missing
    // has nothing for a second round to fetch: none is attempted (2.2.13:
    // looking for one read every candidate's manifest again, 13 s on vex).
    std::fs::write(again.join("b/src/lib.rs"), format!("{b_src}\n// new\n")).unwrap();
    w.vci_ok(&again, &["plan", "--base-ref", "main"]);
    let out = w.vci_env(
        &again,
        &["plan", "--base-ref", "main", "--format", "json"],
        &[("VCI_TIMING", "1")],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(!stderr.contains("round 2"), "{stderr}");
    let p = Plan::from_json(&serde_json::from_slice(&out.stdout).unwrap());
    assert_eq!(p.skip, set(&[C]), "{stderr}");
    std::fs::write(again.join("b/src/lib.rs"), &b_src).unwrap();

    // Attest and publish from the blobless clone; the first clone reads it.
    w.run(&fresh, &[D], &w.trusted);
    w.vci_ok(&fresh, &["push", "--remote", "origin"]);
    w.vci_ok(&work, &["fetch", "--remote", "origin"]);
    assert_eq!(w.plan(&work, "main").skip, set(&[B, C, D]));

    // Offline: values that cannot be fetched make their units run (never an
    // error), and explain says why.
    let offline = clone("offline");
    w.vci_ok(&offline, &["fetch", "--remote", "origin"]);
    w.git(
        &offline,
        &["config", "remote.meta.url", "/nonexistent/remote.git"],
    );
    let out = w.vci(
        &offline,
        &["plan", "--base-ref", "main", "--format", "json"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("could not fetch"), "{stderr}");
    let p = Plan::from_json(&serde_json::from_slice(&out.stdout).unwrap());
    assert!(p.skip.is_empty(), "{p:?}");
    let text = w.explain(&offline, B, "main");
    assert!(
        text.contains("value not fetched: run `vci fetch` online"),
        "{text}"
    );
}

/// Supersession in a blobless clone: the earlier attestation (fetched for
/// the run) is deleted and so is the manifest only it referenced, although
/// other units' attestations were never fetched.
#[test]
fn cargo_supersession_in_a_blobless_clone_removes_the_orphan_manifest() {
    let Some(w) = World::new() else { return };
    w.git(&w.remote, &["config", "uploadpack.allowFilter", "true"]);
    let work = w.work.clone();
    w.put(
        "b/tests/data/b.json",
        "{\"greeting\": \"hello\", \"v\": 2}\n",
    );
    w.git(&work, &["commit", "-qam", "b's data changes"]);
    w.run(&work, &[B, C], &w.trusted);
    // An attestation of a unit no project lists any more: no plan or run
    // reads (or fetches) it.
    AttestStore::new(&store_for(&work))
        .put(
            "gone#lib",
            "0123456789abcdef",
            &"ab".repeat(32),
            br#"{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}"#,
        )
        .unwrap();
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    let old_root = raw_statements(&work, B)[0].1["predicate"]["inputRoot"]
        .as_str()
        .unwrap()
        .to_owned();

    let fresh = w.base.join("fresh");
    w.git(
        &w.base,
        &[
            "clone",
            "-q",
            "--no-local",
            w.remote.to_str().unwrap(),
            fresh.to_str().unwrap(),
        ],
    );
    w.git(&fresh, &["checkout", "-q", "feature"]);
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    std::fs::write(
        fresh.join("b/tests/data/b.json"),
        "{\"greeting\": \"hello\", \"v\": 3}\n",
    )
    .unwrap();
    w.git(&fresh, &["commit", "-qam", "b's data changes again"]);
    let err = w.run(&fresh, &[B], &w.trusted);
    assert!(
        err.contains("vci: removed 1 superseded attestation(s)"),
        "{err}"
    );
    assert!(
        err.contains("vci: removed 1 input manifest(s) no attestation references any more"),
        "{err}"
    );
    let store_repo = store_for(&fresh);
    let store = AttestStore::new(&store_repo);
    let stored = store.manifests().unwrap();
    assert!(!stored.contains(&old_root), "{stored:?}");
    assert!(
        store.list(Some("gone#lib")).unwrap()[0].not_fetched(),
        "an attestation that could not reference it is not fetched"
    );
    w.vci_ok(&fresh, &["push", "--remote", "origin"]);
    w.vci_ok(&work, &["fetch", "--remote", "origin"]);
    assert!(
        !AttestStore::new(&store_for(&work))
            .manifests()
            .unwrap()
            .contains(&old_root)
    );
}

/// Two blobless clones that supersede the same older attestation and push
/// one after the other (vex, 2.1.13: two branches' jobs re-attested the
/// same files; the second to push lost its attestations to `could not
/// fetch <the first's deletion record> from promisor remote`). The second
/// clone fetches the first's tip at its push, merges the first's deletion
/// record it never fetched into its tree, and must still push.
#[test]
fn cargo_two_blobless_clones_supersede_the_same_attestation_and_both_push() {
    let Some(w) = World::new() else { return };
    w.git(&w.remote, &["config", "uploadpack.allowFilter", "true"]);
    let work = w.work.clone();
    // feature's tree must differ from main's: an attestation made on a tree
    // some ref still has is never superseded (2.1.12).
    w.put(
        "b/tests/data/b.json",
        "{\"greeting\": \"hello\", \"v\": 2}\n",
    );
    w.git(&work, &["commit", "-qam", "b's data changes"]);
    w.run(&work, &[B, C], &w.trusted);
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push", "--remote", "origin"]);

    let clone = |name: &str| {
        let dir = w.base.join(name);
        w.git(
            &w.base,
            &[
                "clone",
                "-q",
                "--no-local",
                w.remote.to_str().unwrap(),
                dir.to_str().unwrap(),
            ],
        );
        w.git(&dir, &["checkout", "-q", "feature"]);
        w.vci_ok(&dir, &["fetch", "--remote", "origin"]);
        dir
    };
    // Both clones fetch before either pushes.
    let f1 = clone("f1");
    let f2 = clone("f2");
    for (dir, v) in [(&f1, 3), (&f2, 4)] {
        std::fs::write(
            dir.join("b/tests/data/b.json"),
            format!("{{\"greeting\": \"hello\", \"v\": {v}}}\n"),
        )
        .unwrap();
        w.git(dir, &["commit", "-qam", "b's data changes"]);
        let err = w.run(dir, &[B], &w.trusted);
        assert!(
            err.contains("vci: removed 1 superseded attestation(s)"),
            "{err}"
        );
    }
    w.vci_ok(&f1, &["push", "--remote", "origin"]);
    let out = w.vci_env(&f2, &["push", "--remote", "origin"], &[("VCI_TIMING", "1")]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "the second push failed: {stderr}");
    assert!(stderr.contains("pushed git-meta metadata"), "{stderr}");
    // The remote holds both new attestations and neither the old one nor
    // its manifest.
    w.vci_ok(&work, &["fetch", "--remote", "origin"]);
    let repo = store_for(&work);
    let st = AttestStore::new(&repo);
    let b: Vec<_> = st.list(Some(B)).unwrap();
    assert_eq!(b.len(), 2, "{b:?}");
}

/// `vci prune --keep N` (vci 2.2) keeps a unit's N newest attestations by
/// a signer, and any made on a tree some ref still has at its tip: three
/// attestations of b on three branches stay while the branches do, become
/// two once the oldest branch is gone, then one with `--superseded` once
/// the next is, and the manifests only they referenced go with them.
#[test]
fn cargo_prune_keeps_the_newest_n_per_signer() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    for v in [2, 3, 4] {
        w.git(&work, &["checkout", "-q", "-b", &format!("b{v}"), "main"]);
        w.put(
            "b/tests/data/b.json",
            &format!("{{\"greeting\": \"hello\", \"v\": {v}}}\n"),
        );
        w.git(&work, &["commit", "-qam", "b's data changes"]);
        let err = w.run(&work, &[B], &w.trusted);
        assert!(!err.contains("superseded"), "{err}");
        // issuedAt has second resolution: the next one is newer.
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }
    assert_eq!(raw_statements(&work, B).len(), 3);
    // Every tree is at a branch tip: nothing to prune.
    let removals = |out: &str| {
        out.lines()
            .filter(|l| l.starts_with("would remove") && l.contains("vci:attestation"))
            .count()
    };
    let out = w.vci_ok(&work, &["prune", "--dry-run"]);
    assert_eq!(removals(&out), 0, "{out}");
    w.git(&work, &["branch", "-D", "b2"]);
    let out = w.vci_ok(&work, &["prune", "--dry-run"]);
    assert_eq!(removals(&out), 1, "{out}");
    w.vci_ok(&work, &["prune"]);
    let left = raw_statements(&work, B);
    assert_eq!(left.len(), 2, "{left:?}");
    let roots: Vec<String> = left
        .iter()
        .map(|(_, st)| st["predicate"]["inputRoot"].as_str().unwrap().to_owned())
        .collect();
    let store_repo = store_for(&work);
    let st = AttestStore::new(&store_repo);
    let manifests = st.manifests().unwrap();
    assert!(roots.iter().all(|r| manifests.contains(r)), "{manifests:?}");
    assert_eq!(
        manifests.len(),
        2,
        "the pruned attestation's manifest went: {manifests:?}"
    );
    // `--keep 1` keeps b3's too while its branch is there; `--superseded`
    // keeps only the newest, whatever the branch.
    w.vci_ok(&work, &["prune", "--keep", "1"]);
    assert_eq!(raw_statements(&work, B).len(), 2);
    w.vci_ok(&work, &["prune", "--superseded"]);
    assert_eq!(raw_statements(&work, B).len(), 1);
    assert_eq!(st.manifests().unwrap().len(), 1);
}

// ---- manifests by reference (vci 1.9.0) -----------------------------------

/// The stored statements of `test_id`, as signed (no manifest inlined).
fn raw_statements(work: &Path, test_id: &str) -> Vec<(vci_git::StoredEnvelope, Value)> {
    let b64 = base64::engine::general_purpose::STANDARD;
    AttestStore::new(&store_for(work))
        .list(Some(test_id))
        .unwrap()
        .into_iter()
        .map(|s| {
            let env: Value = serde_json::from_slice(&s.bytes).unwrap();
            let payload = b64.decode(env["payload"].as_str().unwrap()).unwrap();
            let st: Value = serde_json::from_slice(&payload).unwrap();
            (s, st)
        })
        .collect()
}

/// The git-meta tree of a ref, as `(path, size)` per blob.
fn meta_blobs(w: &World, dir: &Path, refname: &str) -> Vec<(String, u64)> {
    w.git(dir, &["ls-tree", "-r", "-l", "--full-tree", refname])
        .lines()
        .filter_map(|l| {
            let (meta, path) = l.split_once('\t')?;
            let size = meta.split_whitespace().nth(3)?.parse().ok()?;
            Some((path.to_owned(), size))
        })
        .collect()
}

/// An attestation carries `manifestRef` (its input root) instead of the
/// manifest; the manifest is stored once under `project`
/// `vci:manifest:<root>` in its compact encoding, however many units and
/// attestations share it, and published with the attestations.
#[test]
fn cargo_manifests_are_stored_once_by_reference() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let units = [A_LIB, A_DOC, B, C, D];
    w.run(&work, &units, &w.trusted);
    let p = w.plan(&work, "main");
    for u in units {
        assert!(p.skip.contains(u), "{u}: {p:?}");
    }
    let mut roots = BTreeSet::new();
    for u in units {
        let stmts = raw_statements(&work, u);
        assert_eq!(stmts.len(), 1, "{u}");
        let pred = &stmts[0].1["predicate"];
        assert!(pred.get("manifest").is_none(), "{u}: {pred}");
        assert_eq!(pred["manifestRef"], pred["inputRoot"], "{u}");
        assert!(pred["globalManifest"]["entries"].is_array(), "{u}");
        roots.insert(pred["inputRoot"].as_str().unwrap().to_owned());
    }
    let store_repo = store_for(&work);
    let store = AttestStore::new(&store_repo);
    let stored: BTreeSet<String> = store.manifests().unwrap().into_iter().collect();
    // One manifest per distinct input root, plus, when the run's units
    // share entries (vci 2.1.8; these packages share none: their common
    // inputs are global), one base nothing references by `manifestRef`.
    let bases: BTreeSet<String> = stored.difference(&roots).cloned().collect();
    assert!(bases.len() <= 1, "{stored:?} against {roots:?}");
    assert!(roots.is_subset(&stored), "{stored:?} against {roots:?}");
    // Two units of the same package share their manifest: it is stored once.
    assert!(roots.len() < units.len(), "{roots:?}");
    for b in &bases {
        let bytes = store.manifest(b).unwrap().unwrap().bytes;
        assert!(
            String::from_utf8_lossy(&bytes).starts_with(r#"{"v":2,"entries":[["#),
            "the base is a plain manifest"
        );
    }
    for r in &roots {
        let m = store.manifest(r).unwrap().unwrap();
        let text = String::from_utf8(m.bytes).unwrap();
        match bases.iter().next() {
            Some(base) => assert!(
                text.starts_with(&format!(r#"{{"v":2,"base":"{base}","entries":["#)),
                "{text}"
            ),
            None => assert!(text.starts_with(r#"{"v":2,"entries":[["#), "{text}"),
        }
        assert_eq!(
            store.manifest_decoded(r).unwrap().unwrap().unwrap().root(),
            *r
        );
    }
    // Attesting again stores the same keys and values; the only value it
    // may add is this run's base (two units with the same entries share
    // them all, and a base has no externals, so it is its own value).
    w.run(&work, &[A_LIB, A_DOC], &w.trusted);
    let again: BTreeSet<String> = store.manifests().unwrap().into_iter().collect();
    assert!(again.is_superset(&stored), "{again:?}");
    assert!(again.len() <= stored.len() + 1, "{again:?}");
    let stored = again;
    // Published once each, next to the attestations.
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    let tree = meta_blobs(&w, &w.remote, "refs/meta/main");
    let manifests: Vec<&(String, u64)> = tree
        .iter()
        .filter(|(p, _)| p.starts_with("project/vci/manifest/") && p.ends_with("/__value"))
        .collect();
    assert_eq!(manifests.len(), stored.len(), "{tree:?}");
    let attestations = tree
        .iter()
        .filter(|(p, _)| p.contains("/vci/attestation/") && p.ends_with("/__value"))
        .count();
    assert_eq!(attestations, units.len(), "{tree:?}");
    // A fresh clone fetches both and skips every unit.
    let fresh = w.base.join("fresh-clone");
    w.git(
        &w.base,
        &["clone", "-q", w.remote.to_str().unwrap(), "fresh-clone"],
    );
    w.git(&fresh, &["checkout", "-q", "feature"]);
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    let p = w.plan(&fresh, "main");
    for u in units {
        assert!(p.skip.contains(u), "{u}: {p:?}");
    }
}

/// An attestation made before vci 1.9.0 (the manifest inline, no
/// `manifestRef`) still verifies and skips, with no stored manifest.
#[test]
fn cargo_inline_manifest_attestation_still_verifies() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.run(&work, &[B], &w.trusted);
    let store_repo = store_for(&work);
    let store = AttestStore::new(&store_repo);
    let (stored, mut st) = raw_statements(&work, B).remove(0);
    let root = st["predicate"]["inputRoot"].as_str().unwrap().to_owned();
    let m = store.manifest(&root).unwrap().unwrap();
    let m = vci_core::InputManifest::from_compact(&m.bytes).unwrap();
    // The pre-1.9 predicate: `manifest` inline, in its JSON form, and no
    // `manifestRef`; signed with the same key, as vci 1.8 signed it.
    let pred = st["predicate"].as_object_mut().unwrap();
    pred.remove("manifestRef");
    pred.insert("manifest".into(), serde_json::to_value(&m).unwrap());
    pred.insert("toolVersion".into(), "1.8.2".into());
    let stmt: vci_attest::Statement = serde_json::from_value(st).unwrap();
    let key = Utf8Path::from_path(&w.trusted).unwrap();
    let env = vci_attest::sign_statement(&stmt, key).unwrap();
    store
        .put(B, &stored.signer, &stored.storage_key, &env.to_json())
        .unwrap();
    assert!(store.remove_manifest(&root).unwrap());
    assert!(store.manifest(&root).unwrap().is_none());
    let (_, st) = raw_statements(&work, B).remove(0);
    assert!(st["predicate"]["manifest"]["entries"].is_array());
    assert!(st["predicate"].get("manifestRef").is_none());
    assert!(w.plan(&work, "main").skip.contains(B), "inline manifest");
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("all checks passed"), "{ex}");
    let file = w.base.join("old.dsse.json");
    std::fs::write(&file, env.to_json()).unwrap();
    let out = w.vci_ok(
        &work,
        &["verify", file.to_str().unwrap(), "--base-ref", "main"],
    );
    assert!(
        out.contains("VALID signature by trusted@example.com"),
        "{out}"
    );
    assert!(out.contains("(root verified; inline)"), "{out}");
    // It still fails like any attestation when an input changes.
    w.put(
        "b/tests/data/b.json",
        "{\"greeting\": \"hello\", \"v\": 2}\n",
    );
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("entry:b/tests/data/b.json"), "{ex}");
}

/// A referenced manifest that is missing, unreadable or forged fails its
/// candidate (the unit runs), with the reason named by `vci explain`;
/// `vci verify` reads it from the store or from `--manifest FILE`.
#[test]
fn cargo_missing_or_forged_manifest_makes_the_unit_run() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.run(&work, &[B, C], &w.trusted);
    assert!(w.plan(&work, "main").skip.contains(B));
    let store_repo = store_for(&work);
    let store = AttestStore::new(&store_repo);
    let (stored, st) = raw_statements(&work, B).remove(0);
    let root = st["predicate"]["inputRoot"].as_str().unwrap().to_owned();
    let good = store.manifest(&root).unwrap().unwrap().bytes;
    let file = w.base.join("b.dsse.json");
    std::fs::write(&file, &stored.bytes).unwrap();
    let out = w.vci_ok(
        &work,
        &["verify", file.to_str().unwrap(), "--base-ref", "main"],
    );
    assert!(
        out.contains("(root verified; git-meta project vci:manifest:"),
        "{out}"
    );

    // Missing (deleted, or never fetched).
    assert!(store.remove_manifest(&root).unwrap());
    let p = w.plan(&work, "main");
    assert!(p.run.contains(B), "{p:?}");
    assert!(p.skip.contains(C), "only B's manifest is gone: {p:?}");
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(
        ex.contains(&format!(
            "manifest {root} not in the store: run `vci fetch`"
        )),
        "{ex}"
    );
    let out = w.vci(
        &work,
        &["verify", file.to_str().unwrap(), "--base-ref", "main"],
    );
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("VALID signature"), "{text}");
    assert!(text.contains("manifest: INVALID"), "{text}");
    assert!(text.contains("not in the store"), "{text}");
    // `--manifest FILE` instead of the store.
    let mfile = w.base.join("b.manifest.json");
    std::fs::write(&mfile, &good).unwrap();
    let out = w.vci_ok(
        &work,
        &[
            "verify",
            file.to_str().unwrap(),
            "--base-ref",
            "main",
            "--manifest",
            mfile.to_str().unwrap(),
        ],
    );
    assert!(out.contains("root verified"), "{out}");

    // Corrupt: not a compact manifest.
    store.put_manifest(&root, b"{\"v\":3}").unwrap();
    assert!(w.plan(&work, "main").run.contains(B));
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains(&format!("manifest {root} corrupt")), "{ex}");

    // Forged: a valid manifest (C's) under B's root. The signed root does
    // not match it.
    let c_root = raw_statements(&work, C).remove(0).1["predicate"]["inputRoot"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(c_root, root);
    let c_manifest = store.manifest(&c_root).unwrap().unwrap().bytes;
    store.put_manifest(&root, &c_manifest).unwrap();
    assert!(w.plan(&work, "main").run.contains(B));
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("inputRoot"), "{ex}");
    assert!(ex.contains("recomputed from the attested manifest"), "{ex}");
    let out = w.vci(
        &work,
        &["verify", file.to_str().unwrap(), "--base-ref", "main"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("is not the signed input root"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Restored: B skips again.
    store.put_manifest(&root, &good).unwrap();
    assert!(w.plan(&work, "main").skip.contains(B));
}

/// An attestation made on a commit no ref contains is kept while some ref's
/// tip still has that commit's tree (vci 2.1.12): a pull request's merge
/// commit after a squash merge, whose tree is master's. Once no tip has
/// the tree, it is superseded as before.
#[test]
fn cargo_supersession_keeps_an_attestation_whose_tree_a_ref_still_has() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    // A detached commit with main's tree, like a pull request's merge
    // commit: attested there; `keep` points at a commit with that tree.
    w.git(&work, &["branch", "keep", "main"]);
    w.git(&work, &["checkout", "-q", "--detach", "main"]);
    w.git(
        &work,
        &["commit", "-q", "--allow-empty", "-m", "same tree, no ref"],
    );
    let detached = w.git(&work, &["rev-parse", "HEAD"]);
    w.run(&work, &[B], &w.trusted);
    let stmts = raw_statements(&work, B);
    assert_eq!(stmts.len(), 1);
    assert_eq!(stmts[0].1["predicate"]["commit"], detached.trim());
    assert_eq!(
        stmts[0].1["predicate"]["tree"],
        w.git(&work, &["rev-parse", "HEAD^{tree}"]).trim()
    );
    // On a branch whose tree differs: the detached commit is on no ref,
    // but `keep`'s tip has its tree, so the attestation stays.
    w.git(&work, &["checkout", "-q", "feature"]);
    w.put(
        "b/tests/data/b.json",
        "{\"greeting\": \"hello\", \"v\": 2}\n",
    );
    w.git(&work, &["commit", "-qam", "b's data changes"]);
    let err = w.run(&work, &[B], &w.trusted);
    assert!(!err.contains("superseded"), "{err}");
    assert_eq!(raw_statements(&work, B).len(), 2);
    // No tip has that tree any more (`keep` goes; `main`, here and on
    // origin, moves on to feature's commit): the detached one is
    // superseded on the next run; feature's earlier one stays, since
    // `main` now contains its commit.
    w.git(&work, &["branch", "-D", "keep"]);
    w.git(&work, &["branch", "-f", "main", "feature"]);
    w.git(&work, &["push", "-q", "-f", "origin", "main"]);
    w.put(
        "b/tests/data/b.json",
        "{\"greeting\": \"hello\", \"v\": 3}\n",
    );
    w.git(&work, &["commit", "-qam", "b's data changes again"]);
    let err = w.run(&work, &[B], &w.trusted);
    assert!(
        err.contains("vci: removed 1 superseded attestation(s)"),
        "{err}"
    );
    let left = raw_statements(&work, B);
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(
        left.iter()
            .all(|(_, v)| v["predicate"]["commit"] != detached.trim()),
        "the detached one is gone: {left:?}"
    );
}

/// Supersession on store: re-attesting a unit on a later commit of the same
/// line of work deletes the signer's earlier attestation of it (same
/// platform) and the manifest only it referenced, so the store keeps one
/// attestation per unit and signer; another signer's are kept, and so is
/// one made on a commit another branch still contains (`main`'s).
#[test]
fn cargo_supersession_keeps_one_attestation_per_unit_and_signer() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    // On the base commit, which `main` contains: never superseded from a
    // feature branch.
    w.run(&work, &[B], &w.trusted);
    w.run(&work, &[B], &w.untrusted);
    assert_eq!(w.predicates(B).len(), 2, "one per signer");
    let on_main = raw_statements(&work, B);
    let keys = |v: &[(vci_git::StoredEnvelope, Value)]| -> BTreeSet<String> {
        v.iter().map(|(s, _)| s.key.clone()).collect()
    };
    let root_of = |v: &(vci_git::StoredEnvelope, Value)| {
        v.1["predicate"]["inputRoot"].as_str().unwrap().to_owned()
    };
    w.put(
        "b/tests/data/b.json",
        "{\"greeting\": \"hello\", \"v\": 2}\n",
    );
    w.git(&work, &["commit", "-qam", "b's data changes"]);
    let err = w.run(&work, &[B], &w.trusted);
    assert!(!err.contains("superseded"), "main still needs it: {err}");
    assert_eq!(raw_statements(&work, B).len(), 3);
    // Pushed: `origin/feature` is this branch's own line, not another.
    w.git(&work, &["push", "-q", "origin", "feature"]);
    let f1: Vec<_> = raw_statements(&work, B)
        .into_iter()
        .filter(|(s, _)| !keys(&on_main).contains(&s.key))
        .collect();
    assert_eq!(f1.len(), 1);
    let f1_root = root_of(&f1[0]);
    w.put(
        "b/tests/data/b.json",
        "{\"greeting\": \"hello\", \"v\": 3}\n",
    );
    w.git(&work, &["commit", "-qam", "b's data changes again"]);
    let err = w.run(&work, &[B], &w.trusted);
    assert!(
        err.contains("vci: removed 1 superseded attestation(s)"),
        "{err}"
    );
    assert!(
        err.contains("vci: removed 1 input manifest(s) no attestation references any more"),
        "{err}"
    );
    let now = raw_statements(&work, B);
    assert_eq!(now.len(), 3, "main's two and the new one: {now:?}");
    assert!(keys(&on_main).is_subset(&keys(&now)));
    assert!(!keys(&now).contains(&f1[0].0.key));
    let store_repo = store_for(&work);
    let store = AttestStore::new(&store_repo);
    let stored = store.manifests().unwrap();
    assert!(!stored.contains(&f1_root), "{stored:?}");
    for st in &now {
        assert!(stored.contains(&root_of(st)), "{stored:?}");
    }
    assert!(w.plan(&work, "main").skip.contains(B));
    // The other signer on this line: its `main` one is kept too.
    let err = w.run(&work, &[B], &w.untrusted);
    assert!(!err.contains("superseded"), "{err}");
    assert_eq!(raw_statements(&work, B).len(), 4);
    // Work in progress on the same commit supersedes nothing: reverting the
    // edit skips again with the commit's attestation.
    let committed = w.read("b/tests/data/b.json");
    w.put(
        "b/tests/data/b.json",
        "{\"greeting\": \"hello\", \"v\": 4}\n",
    );
    let err = w.run(&work, &[B], &w.trusted);
    assert!(!err.contains("superseded"), "{err}");
    assert_eq!(raw_statements(&work, B).len(), 5);
    w.put("b/tests/data/b.json", &committed);
    assert!(w.plan(&work, "main").skip.contains(B));
}

/// Supersession never deletes an attestation another branch still needs: a
/// run on a sibling branch (another pull request) keeps the one made on this
/// branch, which still skips when this branch is checked out again.
#[test]
fn cargo_supersession_keeps_other_branches_attestations() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put("README.md", "feature work\n");
    w.git(&work, &["add", "README.md"]);
    w.git(&work, &["commit", "-qm", "feature work"]);
    w.run(&work, &[B], &w.trusted);
    assert!(w.plan(&work, "main").skip.contains(B));
    w.git(&work, &["checkout", "-q", "-b", "other", "main"]);
    w.put(
        "b/tests/data/b.json",
        "{\"greeting\": \"hello\", \"v\": 2}\n",
    );
    w.git(&work, &["commit", "-qam", "b changes on other"]);
    let err = w.run(&work, &[B], &w.trusted);
    assert!(!err.contains("superseded"), "{err}");
    assert_eq!(raw_statements(&work, B).len(), 2);
    w.git(&work, &["checkout", "-q", "feature"]);
    let p = w.plan(&work, "main");
    assert!(p.skip.contains(B), "{p:?}");
    w.git(&work, &["checkout", "-q", "other"]);
    assert!(w.plan(&work, "main").skip.contains(B));
}

/// `vci prune` deletes the stored manifests no remaining attestation
/// references (a dry run lists them), and publishes the deletion.
#[test]
fn cargo_prune_deletes_unreferenced_manifests() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.run(&work, &[B, C], &w.trusted);
    let store_repo = store_for(&work);
    let store = AttestStore::new(&store_repo);
    let old_root = raw_statements(&work, B).remove(0).1["predicate"]["inputRoot"]
        .as_str()
        .unwrap()
        .to_owned();
    w.put(
        "b/tests/data/b.json",
        "{\"greeting\": \"hello\", \"v\": 2}\n",
    );
    w.git(&work, &["commit", "-qam", "b's data changes"]);
    w.run(&work, &[B], &w.trusted);
    // The first attestation (made on `main`'s commit, which supersession
    // keeps) goes away, as an expired one would.
    let (old, new): (Vec<_>, Vec<_>) = raw_statements(&work, B)
        .into_iter()
        .partition(|(_, st)| st["predicate"]["inputRoot"] == old_root.as_str());
    assert_eq!((old.len(), new.len()), (1, 1));
    assert!(store.remove(&old[0].0).unwrap());
    let new_root = new[0].1["predicate"]["inputRoot"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(old_root, new_root);
    let before = store.manifests().unwrap();
    assert!(before.contains(&old_root) && before.contains(&new_root));
    let out = w.vci(&work, &["prune", "--dry-run"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains(&format!(
            "would remove project vci:manifest:{old_root} (unreferenced manifest)"
        )),
        "{stdout}"
    );
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(
        stderr.contains("vci prune: 1 unreferenced input manifest(s) (dry run)"),
        "{stderr}"
    );
    assert_eq!(
        store.manifests().unwrap(),
        before,
        "a dry run deletes nothing"
    );
    let out = w.vci(&work, &["prune"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("vci prune: 1 unreferenced input manifest(s) removed"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = store.manifests().unwrap();
    assert_eq!(after.len(), before.len() - 1);
    assert!(!after.contains(&old_root) && after.contains(&new_root));
    let p = w.plan(&work, "main");
    assert!(p.skip.contains(B) && p.skip.contains(C), "{p:?}");
    // Nothing more to prune.
    let out = w.vci(&work, &["prune"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("0 unreferenced input manifest(s)"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The deletion is published.
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    let tree: Vec<String> = meta_blobs(&w, &w.remote, "refs/meta/main")
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    assert!(
        !tree
            .iter()
            .any(|p| p == &format!("project/vci/manifest/{old_root}/__value")),
        "{tree:?}"
    );
    assert!(
        tree.iter()
            .any(|p| p.starts_with("project/__tombstones/vci/manifest/") && p.contains(&old_root)),
        "{tree:?}"
    );
}

// ---- exchanging manifests and merging fetched tips (vci 1.9.0) -------------

/// A clone of the world's remote on `branch`.
fn clone_on(w: &World, name: &str, branch: &str) -> PathBuf {
    let dir = w.base.join(name);
    w.git(
        &w.base,
        &[
            "clone",
            "-q",
            w.remote.to_str().unwrap(),
            dir.to_str().unwrap(),
        ],
    );
    w.git(&dir, &["checkout", "-q", branch]);
    dir
}

/// One commit on `feature` that `main` does not contain.
fn feature_commit(w: &World) {
    w.put("README.md", "feature work\n");
    w.git(&w.work, &["add", "README.md"]);
    w.git(&w.work, &["commit", "-qm", "feature work"]);
}

/// What a clone's git-meta store holds, for comparing two merges: values
/// (without their write time), deletion records (a time at or after `since`
/// is the merge's own, shown as `now`), and the local metadata commit.
type Rows = (Vec<String>, Vec<String>, String);

fn store_rows(w: &World, dir: &Path, since: i64) -> Rows {
    let s = git_meta_lib::Session::open(dir).unwrap();
    let values = s
        .store()
        .get_all_metadata()
        .unwrap()
        .into_iter()
        .map(|e| {
            format!(
                "{:?} {} {} {:?} {} {}",
                e.target_type, e.target_value, e.key, e.value_type, e.is_git_ref, e.value
            )
        })
        .collect();
    let tombs = s
        .store()
        .get_all_tombstones()
        .unwrap()
        .into_iter()
        .map(|t| {
            let ts = if t.timestamp >= since {
                "now".to_owned()
            } else {
                t.timestamp.to_string()
            };
            format!(
                "{:?} {} {} {ts} {}",
                t.target_type, t.target_value, t.key, t.email
            )
        })
        .collect();
    drop(s);
    let local = w.git(dir, &["rev-parse", "refs/meta/local/main"]);
    (values, tombs, local)
}

const MAIN_MARKER: &str = ".git/vci-materialized-refs_meta_remotes_main";

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Fetch `dir` from `remote` (from the trees' paths) and, first, a copy of it
/// without the `marker` with git-meta's full merge (`VCI_MATERIALIZE=full`).
/// Returns the fetch's stderr and both stores.
fn fetch_both(
    w: &World,
    dir: &Path,
    tag: &str,
    remote: &str,
    marker: &str,
) -> (String, Rows, Rows, PathBuf) {
    let full = w.base.join(format!("full-{tag}"));
    cp(dir, &full);
    std::fs::remove_file(full.join(marker)).unwrap();
    let since = now_ms();
    let a = w.vci_env(dir, &["fetch", "--remote", remote], &[("VCI_TIMING", "1")]);
    assert!(a.status.success());
    let b = w.vci_env(
        &full,
        &["fetch", "--remote", remote],
        &[("VCI_TIMING", "1"), ("VCI_MATERIALIZE", "full")],
    );
    assert!(b.status.success());
    let eb = String::from_utf8_lossy(&b.stderr);
    assert!(eb.contains("materialize (full)"), "{eb}");
    (
        String::from_utf8_lossy(&a.stderr).into_owned(),
        store_rows(w, dir, since),
        store_rows(w, &full, since),
        full,
    )
}

/// A clone that fetched before merges each later tip by what changed, with
/// the store git-meta's full merge gives (values, deletion records with the
/// tree's time and email, local ref), also on the fetch after one that
/// deleted values; after the remote's history is rewritten it merges the
/// two histories from the trees' paths (git-meta's merge without a common
/// ancestor), and fast-forwards again from the next tip on.
#[test]
fn cargo_incremental_fetch_matches_a_full_merge() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    feature_commit(&w);
    w.run(&work, &[B, C], &w.trusted);
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    let b = clone_on(&w, "b", "feature");
    w.vci_ok(&b, &["fetch", "--remote", "origin"]);
    let step = |tag: &str, merged: bool| {
        let (e, inc, full, _) = fetch_both(&w, &b, tag, "origin", MAIN_MARKER);
        assert!(e.contains("materialize (from paths"), "{tag}: {e}");
        assert_eq!(e.contains("from paths, a merge"), merged, "{tag}: {e}");
        assert_eq!(inc, full, "{tag}");
    };

    // B superseded (an attestation and its manifest deleted, a new one).
    w.put(
        "b/tests/data/b.json",
        "{\"greeting\": \"hello\", \"v\": 2}\n",
    );
    w.git(&work, &["commit", "-qam", "b changes"]);
    w.git(&work, &["push", "-q", "origin", "feature"]);
    let err = w.run(&work, &[B], &w.trusted);
    assert!(err.contains("removed 1 superseded"), "{err}");
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    step("1", false);
    // An unrelated attestation: the deletion records the previous merge
    // stamped are the tree's again, as after git-meta's merge.
    w.run(&work, &[D], &w.trusted);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    step("2", false);
    w.run(&work, &[A_LIB], &w.trusted);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    step("3", false);
    // The remote's history rewritten: a merge, and the local ref is the new
    // tip (nothing local is missing from it).
    w.vci_ok(&work, &["push", "--remote", "origin", "--rewrite-history"]);
    step("4", true);
    assert_eq!(
        w.git(&b, &["rev-parse", "refs/meta/local/main"]),
        w.git(&b, &["rev-parse", "refs/meta/remotes/main"])
    );
    let out = w.vci(&b, &["push", "--remote", "origin"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("vci: nothing to push"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    w.run(&work, &[A_DOC], &w.trusted);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    step("5", false);
    w.git(&b, &["fetch", "-q", "origin"]);
    w.git(&b, &["merge", "-q", "--ff-only", "origin/feature"]);
    let p = w.plan(&b, "main");
    for u in [A_LIB, A_DOC, B, C, D] {
        assert!(p.skip.contains(u), "{u}: {p:?}");
    }
}

/// A side metadata remote (`remote.<name>.metaside`) is merged the way
/// git-meta merges it, never incrementally: its values are imported (not
/// published by a push to the primary) and the local ref stays.
#[test]
fn cargo_side_remote_fetch_is_not_merged_into_the_local_ref() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.run(&work, &[B], &w.trusted);
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    let side = w.base.join("side.git");
    w.git(
        &w.base,
        &[
            "clone",
            "-q",
            "--mirror",
            w.remote.to_str().unwrap(),
            side.to_str().unwrap(),
        ],
    );
    let side_url = side.to_str().unwrap().to_owned();
    let b = clone_on(&w, "b", "feature");
    w.vci_ok(&b, &["fetch", "--remote", "origin"]);
    w.vci_ok(&b, &["fetch", "--remote", &side_url]);
    let markers: Vec<String> = std::fs::read_dir(b.join(".git"))
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| {
            n.starts_with("vci-materialized-") && n != "vci-materialized-refs_meta_remotes_main"
        })
        .collect();
    assert_eq!(markers.len(), 1, "{markers:?}");
    let marker = format!(".git/{}", markers[0]);
    let local = w.git(&b, &["rev-parse", "refs/meta/local/main"]);
    // Another clone publishes C's attestation to the side remote only.
    let s = clone_on(&w, "s", "feature");
    w.vci_ok(&s, &["fetch", "--remote", &side_url]);
    w.run(&s, &[C], &w.trusted);
    w.vci_ok(&s, &["push", "--remote", &side_url]);
    let (e, inc, full, full_dir) = fetch_both(&w, &b, "side", &side_url, &marker);
    assert!(!e.contains("materialize (from paths"), "{e}");
    assert_eq!(inc, full);
    assert_eq!(inc.2, local, "the local ref stays");
    assert!(w.plan(&b, "main").skip.contains(C));
    // A push to the primary does not publish the side remote's values.
    let attestations = || {
        w.git(
            &w.remote,
            &["ls-tree", "-r", "--full-tree", "refs/meta/main"],
        )
        .lines()
        .filter(|l| l.contains("/vci/attestation/") && l.ends_with("/__value"))
        .count()
    };
    for dir in [&b, &full_dir] {
        let tip = w.git(&w.remote, &["rev-parse", "refs/meta/main"]);
        w.vci_ok(dir, &["push", "--remote", "origin"]);
        assert_eq!(attestations(), 1);
        assert_eq!(w.git(&w.remote, &["rev-parse", "refs/meta/main"]), tip);
    }
}

/// An input manifest deleted by one clone (supersession, `vci prune`)
/// while another clone references it is put back by the merge that brings
/// the two together, so it is never lost: when the deleting clone pushes
/// after the other published its attestation, and when the other clone
/// pushes an attestation it made before it saw the deletion.
#[test]
fn cargo_a_manifest_another_clone_references_is_never_lost() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    feature_commit(&w);
    w.run(&work, &[A_LIB, C], &w.trusted);
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    let root_of = |dir: &Path, id: &str| {
        raw_statements(dir, id).remove(0).1["predicate"]["inputRoot"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let r = root_of(&work, A_LIB);
    let rc = root_of(&work, C);
    let x = clone_on(&w, "x", "feature");
    w.vci_ok(&x, &["fetch", "--remote", "origin"]);
    w.run(&x, &[A_DOC], &w.trusted);
    assert_eq!(root_of(&x, A_DOC), r, "a#lib and a#doc share a manifest");
    w.vci_ok(&x, &["push", "--remote", "origin"]);
    // x also attests C with another key, and does not publish it yet.
    w.run(&x, &[C], &w.untrusted);

    // work, without fetching, supersedes a#lib and C: their manifests are
    // referenced by nothing work knows of, and are deleted.
    let lib = w.read("a/src/lib.rs");
    w.put("a/src/lib.rs", &format!("{lib}\n// change\n"));
    let c = w.read("c/src/lib.rs");
    w.put("c/src/lib.rs", &format!("{c}\n// change\n"));
    w.git(&work, &["commit", "-qam", "a and c change"]);
    let err = w.run(&work, &[A_LIB, C], &w.trusted);
    assert!(err.contains("removed 2 superseded"), "{err}");
    assert!(err.contains("removed 2 input manifest(s)"), "{err}");
    let manifest_value = |root: &str| {
        w.git(
            &w.remote,
            &[
                "ls-tree",
                "-r",
                "--name-only",
                "--full-tree",
                "refs/meta/main",
            ],
        )
        .lines()
        .any(|p| p == format!("project/vci/manifest/{root}/__value"))
    };
    // work's push merges x's a#doc in, and puts its manifest back.
    let out = w.vci(&work, &["push", "--remote", "origin"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("put back 1 input manifest(s)"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(manifest_value(&r), "a#doc's manifest is published");
    assert!(
        !manifest_value(&rc),
        "C's is deleted: nothing published uses it"
    );
    // x merges the deletion of C's manifest, which its own C attestation
    // references: the merge puts it back, and x's push publishes it.
    let out = w.vci(&x, &["fetch", "--remote", "origin"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("put back 1 input manifest(s)"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let p = w.plan(&x, "main");
    assert!(p.skip.contains(A_DOC), "{p:?}");
    w.vci_ok(&x, &["push", "--remote", "origin"]);
    assert!(manifest_value(&rc));
    let fresh = clone_on(&w, "fresh", "feature");
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    let store_repo = store_for(&fresh);
    let stored = AttestStore::new(&store_repo).manifests().unwrap();
    assert!(stored.contains(&r) && stored.contains(&rc), "{stored:?}");
}

/// `vci prune` keeps the manifest an attestation it leaves alone (one whose
/// payload it cannot parse, as a later vci might write) references.
#[test]
fn cargo_prune_keeps_the_manifest_of_an_unparsable_attestation() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.run(&work, &[B], &w.trusted);
    let repo = store_for(&work);
    let store = AttestStore::new(&repo);
    let (stored, mut st) = raw_statements(&work, B).remove(0);
    let root = st["predicate"]["inputRoot"].as_str().unwrap().to_owned();
    st["predicate"]["issuedAt"] = "2026-10-16T21:20:19.5+00:00 (a later format)".into();
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut env: Value = serde_json::from_slice(&stored.bytes).unwrap();
    env["payload"] = b64.encode(serde_json::to_vec(&st).unwrap()).into();
    store
        .put(
            B,
            &stored.signer,
            &"ee".repeat(32),
            serde_json::to_string(&env).unwrap().as_bytes(),
        )
        .unwrap();
    assert!(store.remove(&stored).unwrap());
    let out = w.vci(&work, &["prune", "--dry-run"]);
    assert!(out.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!text.contains(&format!("vci:manifest:{root}")), "{text}");
    assert!(text.contains("1 unreadable (left alone)"), "{text}");
    assert!(text.contains("0 unreferenced input manifest(s)"), "{text}");
    // An unparsable payload that names no manifest: none is removed.
    st["predicate"]
        .as_object_mut()
        .unwrap()
        .remove("manifestRef");
    env["payload"] = b64.encode(serde_json::to_vec(&st).unwrap()).into();
    store
        .put(
            B,
            &stored.signer,
            &"ee".repeat(32),
            serde_json::to_string(&env).unwrap().as_bytes(),
        )
        .unwrap();
    store
        .put_manifest(
            &"ab".repeat(32),
            b"{\"v\":2,\"entries\":[],\"externals\":[],\"env\":[]}",
        )
        .unwrap();
    let out = w.vci(&work, &["prune", "--dry-run"]);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("no input manifest is removed"), "{text}");
}

/// The partition (1-based) of `count` that `vci ci --partition` gives a
/// unit: the first 8 bytes of its storage key (BLAKE3 of the test id),
/// big-endian, modulo `count`, plus one.
fn partition_of(test_id: &str, count: u64) -> u32 {
    let key = vci_core::test_key(test_id);
    (u64::from_str_radix(&key[..16], 16).unwrap() % count) as u32 + 1
}

/// The test ids of an audit log array of `{testId}` objects.
fn ids_of(v: &Value) -> BTreeSet<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x["testId"].as_str().unwrap().to_owned())
        .collect()
}

/// Three CI jobs, `vci ci --partition I/3 --key --push` from three clones at
/// once: each builds and runs (and attests) the units its partition owns,
/// together exactly the plan's units; afterwards a plan skips them all. A
/// project whose units cannot be listed runs whole in every partition that
/// cannot list it, also when another partition listed it.
#[test]
fn cargo_ci_partitions_cover_every_unit_once() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.git(&work, &["push", "-q", "origin", "feature"]);
    let all = set(&[A_LIB, A_DOC, B, C, D]);
    assert_eq!(w.plan(&work, "main").run, all);
    let clone = |name: &str| {
        let dir = w.base.join(name);
        w.git(
            &w.base,
            &[
                "clone",
                "-q",
                w.remote.to_str().unwrap(),
                dir.to_str().unwrap(),
            ],
        );
        w.git(&dir, &["checkout", "-q", "feature"]);
        dir
    };
    let clones: Vec<PathBuf> = (1..=3).map(|i| clone(&format!("job{i}"))).collect();
    let trusted = w.trusted.to_str().unwrap().to_owned();
    let outs: Vec<(Output, Value)> = std::thread::scope(|s| {
        let handles: Vec<_> = clones
            .iter()
            .enumerate()
            .map(|(i, dir)| {
                let (w, trusted) = (&w, &trusted);
                s.spawn(move || {
                    let part = format!("{}/3", i + 1);
                    let audit = w.base.join(format!("audit-{}.json", i + 1));
                    let out = w.vci(
                        dir,
                        &[
                            "ci",
                            "--fetch",
                            "origin",
                            "--base-ref",
                            "main",
                            "--partition",
                            &part,
                            "--key",
                            trusted,
                            "--push",
                            "--remote",
                            "origin",
                            "--audit-log",
                            audit.to_str().unwrap(),
                        ],
                    );
                    let log: Value =
                        serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
                    (out, log)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut union = BTreeSet::new();
    for (i, (out, log)) in outs.iter().enumerate() {
        let index = i as u32 + 1;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{index}/3: {stderr}");
        let mine: BTreeSet<String> = all
            .iter()
            .filter(|id| partition_of(id, 3) == index)
            .cloned()
            .collect();
        // With this fixture every partition has a unit.
        assert!(!mine.is_empty(), "{index}/3");
        assert!(
            stdout.contains(&format!(
                "partition {index}/3: {} of 5 units to run",
                mine.len()
            )),
            "{stdout}"
        );
        assert!(
            stderr.contains(&format!(
                "running {} of 5 test file(s) (partition {index}/3, attesting)",
                mine.len()
            )),
            "{stderr}"
        );
        // Only this partition's units are tested (one `cargo test` each).
        for id in &all {
            let (dir, target) = id.split_once('#').unwrap();
            let flag = match target {
                "lib" => "--lib".to_owned(),
                "doc" => "--doc".to_owned(),
                t => format!("--test {}", t.trim_start_matches("test:")),
            };
            let line = format!("--manifest-path {dir}/Cargo.toml {flag}");
            assert_eq!(
                stderr.contains(&line),
                mine.contains(id),
                "{index}/3, {id} ({line}): {stderr}"
            );
        }
        assert_eq!(ids_of(&log["attested"]), mine, "{index}/3 attested");
        assert_eq!(ids_of(&log["ran"]), mine, "{index}/3 ran");
        assert_eq!(log["partition"]["units"], mine.len());
        assert_eq!(log["partition"]["total"], 5);
        assert_eq!(log["pushed"], true, "{index}/3: {stderr}");
        assert!(union.is_disjoint(&mine), "{index}/3 overlaps");
        union.extend(mine);
    }
    assert_eq!(union, all, "every unit in exactly one partition");

    let fresh = clone("fresh");
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    let p = w.plan(&fresh, "main");
    assert_eq!(p.skip, all, "{p:?}");
    assert!(p.run.is_empty(), "{p:?}");

    // cargo cannot list the units in any job: every partition runs
    // everything (here it fails: cargo is missing) and says so in a
    // `::warning`; none can know whether another listed them.
    for index in 1..=3u32 {
        let part = format!("{index}/3");
        let audit = w.base.join("audit-unlisted.json");
        let out = w.vci_env(
            &fresh,
            &[
                "ci",
                "--base-ref",
                "main",
                "--partition",
                &part,
                "--audit-log",
                audit.to_str().unwrap(),
            ],
            &[("VCI_CARGO", "/nonexistent/cargo")],
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stdout.contains(&format!("partition {part}: 0 of 0 units to run")),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!(
                "::warning title=vci::partition {part}: the project runs everything and its test files could not be listed: it runs whole in this partition"
            )),
            "{stdout}"
        );
        assert!(stderr.contains("vci ci: running all tests"), "{stderr}");
        assert!(!stderr.contains("not running"), "{stderr}");
        // (cargo missing is an error before any audit log is written, as
        // without `--partition`.)
        assert_ne!(out.status.code(), Some(0), "{stderr}");
    }

    // Listing fails in some jobs only (a transient `cargo metadata`
    // failure): partition 1 lists and runs its share; partitions 2 and 3
    // cannot list and run the whole project, so the units hashed to them
    // still run (and pass).
    let Some(real_cargo) = std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join("cargo"))
            .find(|p| p.is_file())
    }) else {
        eprintln!("SKIPPED (part): cargo is not a file on PATH");
        return;
    };
    let unfetched = clone("unfetched");
    assert_eq!(w.plan(&unfetched, "main").run, all);
    let flaky = |index: u32| {
        // Fails the first `cargo metadata` (the plan's listing) only.
        let script = w.base.join(format!("flaky-cargo-{index}"));
        let mark = w.base.join(format!("flaky-cargo-{index}.failed"));
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nif [ \"$1\" = metadata ] && [ ! -e '{}' ]; then : > '{}'; echo 'flaky: cargo metadata failed' >&2; exit 101; fi\nexec '{}' \"$@\"\n",
                mark.display(),
                mark.display(),
                real_cargo.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    };
    let scripts: Vec<Option<PathBuf>> = (1..=3u32).map(|i| (i > 1).then(|| flaky(i))).collect();
    let mut covered = BTreeSet::new();
    for index in 1..=3u32 {
        let part = format!("{index}/3");
        let audit = w.base.join(format!("audit-flaky-{index}.json"));
        let env: Vec<(&str, &str)> = scripts[index as usize - 1]
            .iter()
            .map(|s| ("VCI_CARGO", s.to_str().unwrap()))
            .collect();
        let out = w.vci_env(
            &unfetched,
            &[
                "ci",
                "--base-ref",
                "main",
                "--partition",
                &part,
                "--audit-log",
                audit.to_str().unwrap(),
            ],
            &env,
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{part}: {stderr}");
        let log: Value = serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
        if index == 1 {
            let mine: BTreeSet<String> = all
                .iter()
                .filter(|id| partition_of(id, 3) == 1)
                .cloned()
                .collect();
            assert!(!stdout.contains("::warning"), "{stdout}");
            assert_eq!(ids_of(&log["ran"]), mine, "{part} ran");
            assert_eq!(log["partition"]["unlisted"], serde_json::json!([]));
            covered.extend(mine);
        } else {
            assert!(stdout.contains("flaky: cargo metadata failed"), "{stdout}");
            assert!(
                stdout.contains(&format!(
                    "::warning title=vci::partition {part}: the project runs everything and its test files could not be listed: it runs whole in this partition"
                )),
                "{stdout}"
            );
            assert!(stderr.contains("vci ci: running all tests"), "{stderr}");
            assert!(
                stderr.contains("test --locked --workspace"),
                "{part}: {stderr}"
            );
            assert_eq!(log["partition"]["unlisted"], serde_json::json!(["."]));
            covered.extend(all.iter().cloned());
        }
    }
    assert_eq!(covered, all, "every unit runs in some job");
}

/// The metrics log (2.5.0): every command appends a line with its steps'
/// times, its flags by name only, and how it ended; `vci metrics`
/// summarizes them and logs nothing itself; `VCI_METRICS=0` writes nothing.
#[test]
fn every_command_appends_its_steps_to_the_metrics_log() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let log = w.base.join("metrics.jsonl");
    let env = [("VCI_METRICS", log.to_str().unwrap())];
    w.run(&work, &[B], &w.trusted);
    let key = w.trusted.to_str().unwrap().to_owned();
    let out = w.vci_env(&work, &["run", B, "--key", &key], &env);
    assert!(out.status.success());
    let out = w.vci_env(&work, &["plan", "--base-ref", "main"], &env);
    assert!(out.status.success());
    let text = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert_eq!(lines[0]["cmd"], "run");
    assert_eq!(lines[0]["flags"], serde_json::json!(["--key"]));
    assert!(!text.contains(&key), "a flag's value is never recorded");
    assert_eq!(lines[0]["exit"], 0);
    assert!(
        lines[0]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["step"]
                .as_str()
                .unwrap()
                .starts_with("check, sign and store")),
        "{text}"
    );
    assert_eq!(lines[1]["cmd"], "plan");
    assert!(text.contains("\"plan total\""), "{text}");
    let out = w.vci_env(&work, &["metrics"], &env);
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{report}");
    assert!(
        report.contains("2 run(s)") && report.contains("plan total"),
        "{report}"
    );
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 2);
    let off = [("VCI_METRICS", "0")];
    assert!(
        w.vci_env(&work, &["plan", "--base-ref", "main"], &off)
            .status
            .success()
    );
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 2);
}
