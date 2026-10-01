//! End-to-end verification for the pytest adapter, mirroring `e2e.rs`: a
//! copy of `fixtures/pytest-abcd` in a throwaway git repo (base commit holds
//! `.vci/allowed_signers` and `vci.toml`), throwaway SSH keys and a local bare
//! remote.
//!
//! Needs `uv`, `git` and `ssh-keygen` on PATH. Every test prints `SKIPPED:`
//! and returns early when `uv` is not installed or cannot set up the
//! fixture's environment (for example offline without a uv cache).

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

fn uv_available() -> bool {
    match Command::new("uv").arg("--version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!(
                "SKIPPED: `uv` is not installed; the pytest end-to-end tests need uv on PATH (https://docs.astral.sh/uv/)"
            );
            false
        }
    }
}

const VCI_TOML: &str = r#"project = "."
adapter = "pytest"

[policy]
platform = "any"
max_ttl = "30d"
no_skip_refs = ["refs/heads/release/*"]

[env]
mode = "strict"
global = ["APP_MODE"]
"#;

/// Variables removed from every `vci` invocation so the host environment
/// cannot change the outcome.
const SCRUB: &[&str] = &[
    "VCI_BASE_REF",
    "GITHUB_BASE_REF",
    "GITHUB_REF",
    "GITHUB_OUTPUT",
    "VCI_SIGNING_KEY",
    "VCI_OUT",
    "VCI_UV",
    "VCI_JOBS",
    "APP_MODE",
    "PYTHONPATH",
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
    "VIRTUAL_ENV",
    "NODE_OPTIONS",
    "CI",
];

struct World {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    work: PathBuf,
    remote: PathBuf,
    trusted: PathBuf,
    untrusted: PathBuf,
    gitconfig: PathBuf,
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

/// Copy the pytest fixture's sources (not its venv or caches) into `dir`.
fn copy_pytest_fixture(dir: &Path) {
    let fx = workspace_root().join("fixtures/pytest-abcd");
    std::fs::create_dir_all(dir).unwrap();
    for name in [
        "src",
        "tests",
        "fixtures",
        "pyproject.toml",
        "uv.lock",
        ".python-version",
    ] {
        cp(&fx.join(name), &dir.join(name));
    }
    for pc in [
        "src/__pycache__",
        "src/pkg/__pycache__",
        "tests/__pycache__",
    ] {
        let _ = std::fs::remove_dir_all(dir.join(pc));
    }
}

/// `uv sync --locked` in `dir`; false (with a SKIPPED message) if uv cannot
/// set the environment up.
fn uv_sync(dir: &Path) -> bool {
    let out = Command::new("uv")
        .args(["sync", "--locked", "--quiet"])
        .current_dir(dir)
        .env_remove("VIRTUAL_ENV")
        .output()
        .unwrap();
    if !out.status.success() {
        eprintln!(
            "SKIPPED: `uv sync --locked` failed for the pytest fixture (offline without a uv cache?): {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.status.success()
}

impl World {
    /// `None` (test skipped) when uv is unavailable.
    fn new() -> Option<Self> {
        Self::build(VCI_TOML, copy_pytest_fixture, &["."])
    }

    /// A repo whose base commit holds the tree `layout` writes, `vci_toml`
    /// and allowed_signers; `uv sync` runs in each of `uv_dirs`.
    fn build(vci_toml: &str, layout: impl FnOnce(&Path), uv_dirs: &[&str]) -> Option<Self> {
        if !uv_available() {
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
        let w = World {
            work: base.join("work"),
            remote: base.join("remote.git"),
            trusted: keys.join("trusted"),
            untrusted: keys.join("untrusted"),
            gitconfig,
            base,
            _tmp: tmp,
        };
        keygen(&w.trusted, "trusted");
        keygen(&w.untrusted, "untrusted");
        w.git(&w.base, &["init", "-q", "--bare", "remote.git"]);
        w.git(&w.base, &["init", "-q", w.work.to_str().unwrap()]);
        layout(&w.work);
        std::fs::write(
            w.work.join(".gitignore"),
            ".venv/\n.pytest_cache/\n__pycache__/\n.vci/out/\nnode_modules/\n",
        )
        .unwrap();
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
        for d in uv_dirs {
            if !uv_sync(&w.work.join(d)) {
                return None;
            }
        }
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

    fn vci_env(&self, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::cargo_bin("vci").unwrap();
        cmd.current_dir(dir)
            .args(args)
            .env("VCI_PY_PLUGIN", workspace_root().join("py/pytest-plugin"))
            .env("VCI_JS_PLUGIN", workspace_root().join("js/vitest-plugin"))
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("NO_COLOR", "1");
        for k in SCRUB {
            cmd.env_remove(k);
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

    fn run(&self, dir: &Path, file: &str, key: &Path) {
        self.vci_ok(dir, &["run", file, "--key", key.to_str().unwrap()]);
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

    fn explain(&self, dir: &Path, file: &str, base: &str) -> String {
        self.vci_ok(dir, &["explain", file, "--base-ref", base])
    }

    fn put(&self, rel: &str, content: &str) {
        let p = self.work.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.work.join(rel)).unwrap()
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

fn store_for(dir: &Path) -> Repo {
    Repo::discover(Utf8Path::from_path(dir).unwrap()).unwrap()
}

const A: &str = "tests/test_a.py";
const B: &str = "tests/test_b.py";
const C: &str = "tests/test_c.py";
const D: &str = "tests/test_d.py";

#[test]
fn pytest_end_to_end_verification_steps() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();

    // Step 1: attest B, then plan: skip B; run A, C, D.
    w.run(&work, B, &w.trusted);
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[B]), "step 1");
    assert_eq!(p.run, set(&[A, C, D]), "step 1");
    assert!(!p.run_all);

    // Step 2: edit fixtures/b.json -> B runs; explain names the file and both hashes.
    let original = w.read("fixtures/b.json");
    w.put("fixtures/b.json", "{ \"greeting\": \"hello, world\" }\n");
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(B),
        "step 2: B must run after its fixture changed"
    );
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(ex.contains("entry:fixtures/b.json"), "{ex}");
    assert!(
        ex.contains(&vci_core::blake3_hex(original.as_bytes())),
        "{ex}"
    );
    assert!(
        ex.contains(&vci_core::blake3_hex(w.read("fixtures/b.json").as_bytes())),
        "{ex}"
    );
    w.put("fixtures/b.json", &original);
    assert_eq!(w.plan(&work, "main").skip, set(&[B]), "step 2: restored");

    // Step 3: attest C; editing the target of its computed import -> C runs.
    w.run(&work, C, &w.trusted);
    assert_eq!(w.plan(&work, "main").skip, set(&[B, C]), "step 3");
    let impl_x = w.read("src/pkg/impl_x.py");
    w.put("src/pkg/impl_x.py", "NAME = \"x\"  # edited\n");
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(C),
        "step 3: C must run after impl_x.py changed"
    );
    assert!(p.skip.contains(B), "step 3: B unaffected");
    assert!(
        w.explain(&work, C, "main")
            .contains("entry:src/pkg/impl_x.py")
    );
    w.put("src/pkg/impl_x.py", &impl_x);
    // A package that would shadow `pkg` (tests/ is first on sys.path) was
    // probed as absent: creating it invalidates C.
    w.put("tests/pkg/__init__.py", "");
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(C),
        "step 3: a shadowing tests/pkg must invalidate C"
    );
    std::fs::remove_dir_all(work.join("tests/pkg")).unwrap();
    assert_eq!(w.plan(&work, "main").skip, set(&[B, C]), "step 3: restored");

    // Step 4: attest everything; editing conftest.py -> everything runs.
    w.run(&work, A, &w.trusted);
    w.run(&work, D, &w.trusted);
    assert_eq!(w.plan(&work, "main").skip, set(&[A, B, C, D]), "step 4");
    let conftest = w.read("tests/conftest.py");
    w.put("tests/conftest.py", &format!("{conftest}\n# edited\n"));
    let p = w.plan(&work, "main");
    assert!(
        p.skip.is_empty(),
        "step 4: conftest.py change must run everything: {p:?}"
    );
    assert!(
        w.explain(&work, B, "main")
            .contains("failed check: global-inputs")
    );
    w.put("tests/conftest.py", &conftest);
    // A new conftest.py in a directory on the test's path is also global.
    w.put("conftest.py", "");
    assert!(
        w.plan(&work, "main").skip.is_empty(),
        "step 4: new root conftest.py"
    );
    std::fs::remove_file(work.join("conftest.py")).unwrap();
    assert_eq!(
        w.plan(&work, "main").skip,
        set(&[A, B, C, D]),
        "step 4: restored"
    );

    // Step 5: edit a file only A uses -> A runs, B (and C, D) stay skipped.
    let a_src = w.read("src/a.py");
    w.put(
        "src/a.py",
        "def add(x: int, y: int) -> int:\n    return y + x\n",
    );
    let p = w.plan(&work, "main");
    assert_eq!(p.run, set(&[A]), "step 5");
    assert_eq!(p.skip, set(&[B, C, D]), "step 5");
    w.put("src/a.py", &a_src);

    // Step 6: uv.lock and dependency changes -> everything runs.
    let lock = w.read("uv.lock");
    w.put("uv.lock", &format!("{lock}\n# changed\n"));
    let p = w.plan(&work, "main");
    assert!(
        p.skip.is_empty(),
        "step 6: uv.lock change must run everything: {p:?}"
    );
    w.put("uv.lock", &lock);
    let pyproject = w.read("pyproject.toml");
    w.put(
        "pyproject.toml",
        &pyproject.replace("\"idna==3.20\"", "\"idna==3.19\""),
    );
    let p = w.plan(&work, "main");
    assert!(
        p.skip.is_empty(),
        "step 6: a dependency version change must run everything: {p:?}"
    );
    w.put("pyproject.toml", &pyproject);
    assert_eq!(
        w.plan(&work, "main").skip,
        set(&[A, B, C, D]),
        "step 6: restored"
    );

    // Step 7: flip a byte in B's payload -> rejected at the signature check.
    let repo = store_for(&work);
    let store = AttestStore::new(&repo);
    let stored = store.list(Some(B)).unwrap();
    assert_eq!(stored.len(), 1);
    let good = stored[0].clone();
    let mut env: Value = serde_json::from_slice(&good.bytes).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut payload = b64.decode(env["payload"].as_str().unwrap()).unwrap();
    let pos = payload
        .windows(9)
        .position(|x| x == b"\"tests\":1")
        .expect("payload contains the test count");
    payload[pos + 8] = b'2';
    env["payload"] = Value::String(b64.encode(&payload));
    let tampered = serde_json::to_vec(&env).unwrap();
    store
        .put(B, &good.signer, &good.storage_key, &tampered)
        .unwrap();
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(B),
        "step 7: tampered attestation must not skip B"
    );
    assert!(
        w.explain(&work, B, "main")
            .contains("failed check: signature")
    );
    store
        .put(B, &good.signer, &good.storage_key, &good.bytes)
        .unwrap();
    assert!(w.plan(&work, "main").skip.contains(B), "step 7: restored");

    // Step 8: a key that is not in allowed_signers -> rejected. Edit D's
    // input first so the trusted attestation no longer applies.
    let d_src = w.read("src/d.py");
    w.put("src/d.py", &format!("{d_src}\n# untrusted run\n"));
    w.run(&work, D, &w.untrusted);
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(D),
        "step 8: untrusted signer must not skip D"
    );
    let ex = w.explain(&work, D, "main");
    assert!(ex.contains("failed check: signer"), "{ex}");
    assert!(ex.contains("not in allowed_signers"), "{ex}");

    // Step 9: add that key to allowed_signers on the PR branch only -> still rejected.
    let mut signers = w.read(".vci/allowed_signers");
    signers.push_str(&format!(
        "untrusted@example.com namespaces=\"vci-attest\" {}\n",
        pubkey(&w.untrusted)
    ));
    w.put(".vci/allowed_signers", &signers);
    w.git(&work, &["commit", "-q", "-am", "PR: trust my own key"]);
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(D),
        "step 9: key added on the PR branch must not be trusted"
    );
    assert!(w.explain(&work, D, "main").contains("failed check: signer"));
    // Control: with the PR commit as the (wrong) trust root, D would be skipped.
    assert!(w.plan(&work, "HEAD").skip.contains(D), "step 9 control");

    // Step 10: a variable declared in [env] global with a different value in
    // CI forces a run (it was unset when B was attested).
    let p = w.plan_env(&work, "main", &[("APP_MODE", "ci")]);
    assert!(
        p.run.contains(B),
        "step 10: APP_MODE=ci must invalidate B: {p:?}"
    );
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
    // Attested with a value, the same value skips and a different one runs.
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
}

#[test]
fn pytest_run_refuses_unattestable_test_files() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let files: &[(&str, &str)] = &[
        (
            "tests/test_spawn.py",
            "import subprocess, sys\n\ndef test_spawn():\n    out = subprocess.run([sys.executable, '-c', 'print(1)'], capture_output=True, text=True)\n    assert out.stdout.strip() == '1'\n",
        ),
        (
            "tests/test_fail.py",
            "def test_fails():\n    assert 1 == 2\n",
        ),
        (
            "tests/test_write.py",
            "from pathlib import Path\n\ndef test_write():\n    p = Path(__file__).resolve().parent.parent / 'fixtures' / 'out.txt'\n    p.write_text('x')\n    p.unlink()\n",
        ),
        (
            "tests/test_envall.py",
            "import os\n\ndef test_env():\n    assert 'PATH' in dict(os.environ)\n",
        ),
        (
            "tests/test_outside.py",
            "import os\n\ndef test_outside():\n    with open(os.environ['VCI_E2E_OUTSIDE']) as f:\n        assert f.read()\n",
        ),
    ];
    for (rel, body) in files {
        w.put(rel, body);
    }
    let outside = w.base.join("outside.txt");
    std::fs::write(&outside, "outside the repository").unwrap();
    let mut args = vec!["run"];
    args.extend(files.iter().map(|(rel, _)| *rel));
    args.extend(["--key", w.trusted.to_str().unwrap()]);
    // VCI_* is built-in pass-through, so the outside path reaches the test.
    let out = w.vci_env(
        &work,
        &args,
        &[("VCI_E2E_OUTSIDE", outside.to_str().unwrap())],
    );
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert_ne!(
        out.status.code(),
        Some(0),
        "the failing test makes vci run fail"
    );
    let refused = |id: &str, why: &str| {
        let line = stderr
            .lines()
            .find(|l| l.starts_with(&format!("vci: not attesting {id}:")))
            .unwrap_or_else(|| panic!("{id} was not refused:\n{stderr}"));
        assert!(line.contains(why), "{id}: expected {why:?} in {line:?}");
    };
    refused("tests/test_spawn.py", "subprocess.Popen");
    refused("tests/test_fail.py", "result failed");
    refused(
        "tests/test_write.py",
        "wrote inside the repository: fixtures/out.txt",
    );
    refused("tests/test_envall.py", "env:enumerated");
    refused("tests/test_outside.py", "input outside the repository");
    assert!(
        stderr.contains("vci: 0 attested, 5 not attested"),
        "{stderr}"
    );
    let stored = AttestStore::new(&store_for(&work)).list(None).unwrap();
    assert!(stored.is_empty(), "nothing may be stored: {stored:?}");
    let p = w.plan(&work, "main");
    for (rel, _) in files {
        assert!(p.run.contains(*rel), "{rel} must run: {p:?}");
    }
}

#[test]
fn pytest_push_fetch_fresh_clone_and_ci() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.run(&work, B, &w.trusted);
    w.run(&work, C, &w.trusted);
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
    let p = w.plan(&fresh, "main");
    assert!(p.skip.is_empty(), "nothing is attested before fetch");
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    let after = w.plan(&fresh, "main");
    assert_eq!(
        after, before,
        "same plan after push + fetch in a fresh clone"
    );

    // `vci ci` runs only the remainder (one pytest process per file, the
    // isolation the attestations were made with) and writes an audit log of
    // the skips.
    let audit = w.base.join("audit.json");
    let out = w.vci(
        &fresh,
        &[
            "ci",
            "--base-ref",
            "main",
            "--audit-log",
            audit.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(stderr.contains("running 2 test file(s)"), "{stderr}");
    assert_eq!(
        stderr.matches("1 passed").count(),
        2,
        "A and D pass, each in its own process: {stderr}"
    );
    assert!(stderr.contains("pytest tests/test_a.py"), "{stderr}");
    assert!(stderr.contains("pytest tests/test_d.py"), "{stderr}");
    assert!(!stderr.contains("test_b.py"), "B must not run: {stderr}");
    let log: Value = serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
    let skipped: BTreeSet<String> = log["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["testId"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(skipped, set(&[B, C]));
    assert_eq!(log["exitCode"], 0);

    // A failing test among the remainder makes `vci ci` exit non-zero.
    std::fs::write(
        fresh.join("tests/test_zfail.py"),
        "def test_fails():\n    assert False\n",
    )
    .unwrap();
    let out = w.vci(
        &fresh,
        &[
            "ci",
            "--base-ref",
            "main",
            "--audit-log",
            audit.to_str().unwrap(),
        ],
    );
    assert_ne!(
        out.status.code(),
        Some(0),
        "a failing test must fail vci ci"
    );
    let log: Value = serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
    assert_ne!(log["exitCode"], 0);
    std::fs::remove_file(fresh.join("tests/test_zfail.py")).unwrap();

    // Policy: nothing is skipped on refs listed in no_skip_refs, and a
    // collection error means everything runs.
    w.git(&fresh, &["checkout", "-q", "-b", "release/1"]);
    let p = w.plan(&fresh, "main");
    assert!(p.run_all && p.skip.is_empty(), "{p:?}");
    w.git(&fresh, &["checkout", "-q", "feature"]);
    std::fs::write(
        fresh.join("tests/test_broken.py"),
        "import does_not_exist\n",
    )
    .unwrap();
    let out = w.vci(&fresh, &["plan", "--base-ref", "main", "--format", "json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["runAll"]
            .as_str()
            .unwrap_or("")
            .contains("listing test files failed"),
        "{v}"
    );
}

#[test]
fn pytest_without_uv_or_plugin_runs_everything() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.run(&work, B, &w.trusted);
    // uv missing in CI: listing fails, everything runs (never a false skip).
    let out = w.vci_env(
        &work,
        &["plan", "--base-ref", "main", "--format", "json"],
        &[("VCI_UV", "/nonexistent/uv")],
    );
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["runAll"].as_str().unwrap_or("").contains("uv"), "{v}");
    // The collector cannot be found: `vci run` fails with a clear error.
    let out = w.vci_env(
        &work,
        &["run", B, "--key", w.trusted.to_str().unwrap()],
        &[("VCI_PY_PLUGIN", w.base.to_str().unwrap())],
    );
    assert_ne!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("VCI_PY_PLUGIN") && err.contains("vci_pytest"),
        "{err}"
    );
}

const MULTI_TOML: &str = r#"[policy]
platform = "any"
max_ttl = "30d"

[env]
mode = "strict"
global = ["NODE_ENV"]

[[projects]]
name = "web"
path = "web"
adapter = "vitest"

[[projects]]
name = "py"
path = "py"
adapter = "pytest"
[projects.env]
global = ["APP_MODE"]
"#;

/// One repository with a Vitest project and a pytest project.
#[test]
fn multi_project_vitest_and_pytest() {
    let vfx = workspace_root().join("fixtures/vitest-abcd");
    if !vfx.join("node_modules").is_dir() {
        eprintln!(
            "SKIPPED: fixtures/vitest-abcd/node_modules is missing (run `npm ci` there) for the multi-project test"
        );
        return;
    }
    let layout = |dir: &Path| {
        copy_pytest_fixture(&dir.join("py"));
        std::fs::create_dir_all(dir.join("web")).unwrap();
        for name in [
            "src",
            "fixtures",
            "package.json",
            "package-lock.json",
            "vitest.config.ts",
            "node_modules",
        ] {
            cp(&vfx.join(name), &dir.join("web").join(name));
        }
    };
    let Some(w) = World::build(MULTI_TOML, layout, &["py"]) else {
        return;
    };
    let work = w.work.clone();
    let (pb, pa, wb, wa) = (
        "py/tests/test_b.py",
        "py/tests/test_a.py",
        "web/src/b.test.ts",
        "web/src/a.test.ts",
    );
    let out = w.vci(
        &work,
        &["run", pb, wb, "--key", w.trusted.to_str().unwrap()],
    );
    assert!(out.status.success());
    let out = w.vci_ok(&work, &["plan", "--base-ref", "main", "--format", "json"]);
    let v: Value = serde_json::from_str(&out).unwrap();
    let p = Plan::from_json(&v);
    assert_eq!(p.skip, set(&[pb, wb]), "{p:?}");
    assert!(p.run.contains(pa) && p.run.contains(wa), "{p:?}");
    assert_eq!(
        p.run.len() + p.skip.len(),
        8,
        "four files per project: {p:?}"
    );
    // Every verdict names its project; projects are listed with their adapter.
    for f in v["files"].as_array().unwrap() {
        let id = f["testId"].as_str().unwrap();
        let want = if id.starts_with("py/") { "py" } else { "web" };
        assert_eq!(f["project"], want, "{f}");
    }
    let adapters: Vec<&str> = v["projects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["adapter"].as_str().unwrap())
        .collect();
    assert_eq!(adapters, ["vitest", "pytest"]);

    // Editing the pytest fixture only reruns the pytest B.
    let orig = w.read("py/fixtures/b.json");
    w.put("py/fixtures/b.json", "{ \"greeting\": \"changed\" }\n");
    let p = w.plan(&work, "main");
    assert!(p.run.contains(pb) && p.skip.contains(wb), "{p:?}");
    assert!(
        w.explain(&work, pb, "main")
            .contains("entry:py/fixtures/b.json")
    );
    w.put("py/fixtures/b.json", &orig);
    // The per-project env override applies to the pytest project only.
    let p = w.plan_env(&work, "main", &[("APP_MODE", "x")]);
    assert!(p.run.contains(pb) && p.skip.contains(wb), "{p:?}");
    let p = w.plan_env(&work, "main", &[("NODE_ENV", "x")]);
    assert!(p.run.contains(wb) && p.skip.contains(pb), "{p:?}");

    // `vci ci` runs the remainder of both projects.
    let audit = w.base.join("audit.json");
    let out = w.vci(
        &work,
        &[
            "ci",
            "--base-ref",
            "main",
            "--audit-log",
            audit.to_str().unwrap(),
        ],
    );
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("running 3 test file(s) of web (vitest)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("running 3 test file(s) of py (pytest)"),
        "{stderr}"
    );
    let log: Value = serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
    let skipped: BTreeSet<String> = log["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["testId"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(skipped, set(&[pb, wb]));

    // `vci run FILE` lists only the projects that can hold FILE, so the
    // Vitest project's missing node_modules does not stop attesting a pytest
    // file (it did: "listing the test files of web: vitest is not
    // installed").
    let nm = work.join("web/node_modules");
    let aside = w.base.join("node_modules-aside");
    std::fs::rename(&nm, &aside).unwrap();
    let key = w.trusted.to_str().unwrap();
    let out = w.vci(&work, &["run", pa, "--key", key]);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let failed_web = w.vci(&work, &["run", wa, "--key", key]);
    std::fs::rename(&aside, &nm).unwrap();
    assert!(out.status.success(), "{err}");
    assert!(!failed_web.status.success(), "web still needs vitest");
    let p = w.plan(&work, "main");
    assert!(p.skip.contains(pa), "{p:?}");
}

/// uv's variables are pass-through (not hashed), so a CI that selects another
/// interpreter (`UV_PYTHON`) must be caught by the toolchain check: the
/// Python version has to match exactly.
#[test]
fn pytest_other_python_version_runs() {
    let Some(w) = World::new() else { return };
    let found = Command::new("uv")
        .args(["python", "find", "3.12"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !found {
        eprintln!("SKIPPED: no Python 3.12 interpreter known to uv for the toolchain check");
        return;
    }
    let work = w.work.clone();
    w.run(&work, B, &w.trusted);
    assert!(w.plan(&work, "main").skip.contains(B));
    let venv = w.base.join("venv312");
    let env = [
        ("UV_PYTHON", "3.12"),
        ("UV_PROJECT_ENVIRONMENT", venv.to_str().unwrap()),
    ];
    let p = w.plan_env(&work, "main", &env);
    if p.run_all {
        eprintln!("SKIPPED: uv could not set up a 3.12 environment (offline?): {p:?}");
        return;
    }
    assert!(
        p.run.contains(B),
        "another Python version must not skip B: {p:?}"
    );
    let out = w.vci_env(&work, &["explain", B, "--base-ref", "main"], &env);
    let ex = String::from_utf8_lossy(&out.stdout);
    assert!(ex.contains("failed check: toolchain"), "{ex}");
    assert!(ex.contains("    python\n") && ex.contains("3.12."), "{ex}");
}

/// Regressions from adversarial verification, each a false skip before:
/// a test reading a built-in pass-through variable (CI), a file with a
/// conditionally skipped test, a Linux-only native extension next to an
/// attested module, and a package installed outside uv.lock.
#[test]
fn pytest_environment_skips_and_foreign_extensions_fail_open() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put(
        "tests/test_ci_value.py",
        "import os\n\ndef test_ci():\n    assert os.environ.get('CI') != 'true'\n",
    );
    w.put(
        "tests/test_ci_skip.py",
        "import os\nimport pytest\n\ndef test_ok():\n    pass\n\n@pytest.mark.skipif(not os.environ.get('CI'), reason='CI only')\ndef test_in_ci():\n    assert False\n",
    );
    w.put(
        "tests/test_optdep.py",
        "try:\n    import click\nexcept ImportError:\n    click = None\n\ndef test_no_click():\n    assert click is None\n",
    );
    let out = w.vci(
        &work,
        &[
            "run",
            "tests/test_ci_value.py",
            "tests/test_ci_skip.py",
            "tests/test_optdep.py",
            B,
            "--key",
            w.trusted.to_str().unwrap(),
        ],
    );
    assert!(out.status.success());
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    // A skipped test did not run: the file is not attested.
    let line = stderr
        .lines()
        .find(|l| l.starts_with("vci: not attesting tests/test_ci_skip.py:"))
        .unwrap_or_else(|| panic!("test_ci_skip.py must be refused:\n{stderr}"));
    assert!(line.contains("1 skipped"), "{line}");
    let p = w.plan(&work, "main");
    assert!(p.run.contains("tests/test_ci_skip.py"), "{p:?}");
    assert!(p.skip.contains("tests/test_ci_value.py"), "{p:?}");
    assert!(p.skip.contains("tests/test_optdep.py"), "{p:?}");
    assert!(p.skip.contains(B), "{p:?}");

    // CI=true in CI: the test that read CI runs (it would fail there).
    let p = w.plan_env(&work, "main", &[("CI", "true")]);
    assert!(p.run.contains("tests/test_ci_value.py"), "{p:?}");
    assert!(p.skip.contains(B), "B never read CI: {p:?}");
    let out = w.vci_env(
        &work,
        &["explain", "tests/test_ci_value.py", "--base-ref", "main"],
        &[("CI", "true")],
    );
    let ex = String::from_utf8_lossy(&out.stdout);
    assert!(
        ex.contains("failed check: env") && ex.contains("env:CI"),
        "{ex}"
    );

    // A native extension only a Linux (or Windows) interpreter would import
    // instead of src/b.py.
    w.put("src/b.cpython-314-x86_64-linux-gnu.so", "");
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(B),
        "a foreign-platform b extension must run B: {p:?}"
    );
    let ex = w.explain(&work, B, "main");
    assert!(
        ex.contains("entry:src/b.cpython-314-x86_64-linux-gnu.so"),
        "{ex}"
    );
    std::fs::remove_file(work.join("src/b.cpython-314-x86_64-linux-gnu.so")).unwrap();
    assert!(w.plan(&work, "main").skip.contains(B));

    // A package installed outside uv.lock (a CI step's `uv pip install`):
    // every uv run is exact, so it is removed before anything runs and the
    // test sees what it saw when it was attested.
    let inst = Command::new("uv")
        .args([
            "pip",
            "install",
            "--offline",
            "--quiet",
            "--python",
            ".venv",
            "click",
        ])
        .current_dir(&work)
        .env_remove("VIRTUAL_ENV")
        .output()
        .unwrap();
    if inst.status.success() {
        let has_click = || {
            std::fs::read_dir(work.join(".venv/lib"))
                .unwrap()
                .flatten()
                .any(|py| py.path().join("site-packages/click").is_dir())
        };
        assert!(has_click());
        let p = w.plan(&work, "main");
        assert!(!has_click(), "vci plan must sync the environment exactly");
        assert!(p.skip.contains("tests/test_optdep.py"), "{p:?}");
        let out = w.vci(&work, &["ci", "--base-ref", "main"]);
        assert_eq!(out.status.code(), Some(0));
    } else {
        eprintln!(
            "SKIPPED (part): `uv pip install --offline click` failed: {}",
            String::from_utf8_lossy(&inst.stderr)
        );
    }
}

/// `policy.never_skip` (from the base commit) makes matching files always run.
#[test]
fn pytest_never_skip_policy() {
    let toml = VCI_TOML.replace(
        "no_skip_refs = [\"refs/heads/release/*\"]",
        "no_skip_refs = [\"refs/heads/release/*\"]\nnever_skip = [\"tests/test_b.py\"]",
    );
    let Some(w) = World::build(&toml, copy_pytest_fixture, &["."]) else {
        return;
    };
    let work = w.work.clone();
    w.run(&work, B, &w.trusted);
    w.run(&work, A, &w.trusted);
    let p = w.plan(&work, "main");
    assert!(p.run.contains(B) && p.skip.contains(A), "{p:?}");
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("policy.never_skip"), "{ex}");
}
