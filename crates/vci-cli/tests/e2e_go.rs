//! End-to-end verification for the Go adapter, mirroring `e2e_pytest.rs`: a
//! copy of `fixtures/go-abcd` in a throwaway git repo (base commit holds
//! `.vci/allowed_signers` and `vci.toml`), throwaway SSH keys and a local bare
//! remote.
//!
//! Needs `go`, `git` and `ssh-keygen` on PATH. Every test prints `SKIPPED:`
//! and returns early when `go` is not installed or cannot download the
//! fixture's modules (for example offline without a module cache).

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

fn go_available() -> bool {
    match Command::new("go").arg("version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!(
                "SKIPPED: `go` is not installed; the Go end-to-end tests need the Go toolchain on PATH"
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

[env]
mode = "strict"
global = ["APP_MODE"]
"#;

/// Variables removed from every `vci` and `go` invocation so the host
/// environment cannot change the outcome.
const SCRUB: &[&str] = &[
    "VCI_E2E_BIN",
    "VCI_BASE_REF",
    "GITHUB_BASE_REF",
    "GITHUB_REF",
    "GITHUB_OUTPUT",
    "VCI_SIGNING_KEY",
    "VCI_GO",
    "VCI_JOBS",
    "VCI_GO_TESTLOG",
    "APP_MODE",
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

/// Copy the Go fixture into `dir`.
fn copy_go_fixture(dir: &Path) {
    let fx = workspace_root().join("fixtures/go-abcd");
    std::fs::create_dir_all(dir).unwrap();
    for name in ["go.mod", "go.sum", "a", "b", "c", "d", "internal"] {
        cp(&fx.join(name), &dir.join(name));
    }
}

fn go(dir: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new("go");
    cmd.args(args).current_dir(dir);
    for k in SCRUB {
        cmd.env_remove(k);
    }
    cmd.output().unwrap()
}

/// `go mod download` in `dir`; false (with a SKIPPED message) if the modules
/// cannot be fetched.
fn go_mod_download(dir: &Path) -> bool {
    let out = go(dir, &["mod", "download"]);
    if !out.status.success() {
        eprintln!(
            "SKIPPED: `go mod download` failed for the Go fixture (offline without a module cache?): {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.status.success()
}

impl World {
    /// `None` (test skipped) when go is unavailable.
    fn new() -> Option<Self> {
        Self::build(VCI_TOML, copy_go_fixture, &["."])
    }

    /// A repo whose base commit holds the tree `layout` writes, `vci_toml`
    /// and allowed_signers; `go mod download` runs in each of `go_dirs`.
    fn build(vci_toml: &str, layout: impl FnOnce(&Path), go_dirs: &[&str]) -> Option<Self> {
        if !go_available() {
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
        std::fs::write(w.work.join(".gitignore"), ".vci/out/\n").unwrap();
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
        for d in go_dirs {
            if !go_mod_download(&w.work.join(d)) {
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

    fn run(&self, dir: &Path, pkg: &str, key: &Path) {
        self.vci_ok(dir, &["run", pkg, "--key", key.to_str().unwrap()]);
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

    fn explain(&self, dir: &Path, pkg: &str, base: &str) -> String {
        self.vci_ok(dir, &["explain", pkg, "--base-ref", base])
    }

    fn put(&self, rel: &str, content: &str) {
        let p = self.work.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.work.join(rel)).unwrap()
    }

    /// The predicates stored for `test_id`.
    fn predicates(&self, test_id: &str) -> Vec<Value> {
        let repo = store_for(&self.work);
        let b64 = base64::engine::general_purpose::STANDARD;
        AttestStore::new(&repo)
            .list(Some(&vci_core::test_key(test_id)))
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

const A: &str = "a";
const B: &str = "b";
const C: &str = "c";
const D: &str = "d";

#[test]
fn go_end_to_end_verification_steps() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();

    // Step 1: attest b, then plan: skip b; run a, c, d. Packages without
    // test files (internal/text) are not units.
    w.run(&work, B, &w.trusted);
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[B]), "step 1");
    assert_eq!(p.run, set(&[A, C, D]), "step 1");
    assert!(!p.run_all);

    // Step 2: edit b's testdata -> b runs; explain names the file and both
    // hashes.
    let original = w.read("b/testdata/b.json");
    w.put("b/testdata/b.json", "{ \"greeting\": \"hi\" }\n");
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(B),
        "step 2: b must run after its testdata changed"
    );
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(ex.contains("entry:b/testdata/b.json"), "{ex}");
    assert!(
        ex.contains(&vci_core::blake3_hex(original.as_bytes())),
        "{ex}"
    );
    assert!(
        ex.contains(&vci_core::blake3_hex(
            w.read("b/testdata/b.json").as_bytes()
        )),
        "{ex}"
    );
    w.put("b/testdata/b.json", &original);
    assert_eq!(w.plan(&work, "main").skip, set(&[B]), "step 2: restored");

    // Step 3: a file read while the test package is initialised (before
    // testing.M.Run, which go test's own test log misses) is an input too.
    let golden = w.read("b/testdata/golden.txt");
    w.put("b/testdata/golden.txt", "HI!\n");
    assert!(w.plan(&work, "main").run.contains(B), "step 3");
    assert!(
        w.explain(&work, B, "main")
            .contains("entry:b/testdata/golden.txt")
    );
    w.put("b/testdata/golden.txt", &golden);

    // Step 4: edit a file only a uses -> b stays skipped.
    let a_src = w.read("a/a.go");
    w.put("a/a.go", &a_src.replace("return x + y", "return y + x"));
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[B]), "step 4");
    assert_eq!(p.run, set(&[A, C, D]), "step 4");
    w.put("a/a.go", &a_src);

    // Step 5: a new .go file in b's package directory changes the build ->
    // b runs (the directory listing is an input).
    w.put("b/extra.go", "package b\n\nconst Extra = 1\n");
    assert!(w.plan(&work, "main").run.contains(B), "step 5");
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("entry:b\n") || ex.contains("entry:b "), "{ex}");
    std::fs::remove_file(work.join("b/extra.go")).unwrap();
    assert_eq!(w.plan(&work, "main").skip, set(&[B]), "step 5: restored");

    // Step 6: change a package of the repository b imports -> b runs.
    let text = w.read("internal/text/text.go");
    w.put("internal/text/text.go", &text.replace("\"!\"", "\"!!\""));
    assert!(w.plan(&work, "main").run.contains(B), "step 6");
    assert!(
        w.explain(&work, B, "main")
            .contains("entry:internal/text/text.go")
    );
    w.put("internal/text/text.go", &text);

    // Step 7: attest c. A new file matching its go:embed pattern -> c runs;
    // the file it picks by name at run time -> c runs.
    w.run(&work, C, &w.trusted);
    assert_eq!(w.plan(&work, "main").skip, set(&[B, C]), "step 7");
    w.put("c/data/new.txt", "new\n");
    let p = w.plan(&work, "main");
    assert!(p.run.contains(C) && p.skip.contains(B), "step 7: {p:?}");
    assert!(w.explain(&work, C, "main").contains("entry:c/data"));
    std::fs::remove_file(work.join("c/data/new.txt")).unwrap();
    let impl_x = w.read("c/testdata/impl-x.txt");
    w.put("c/testdata/impl-x.txt", "implementation x, edited\n");
    assert!(
        w.plan(&work, "main").run.contains(C),
        "step 7: runtime file"
    );
    assert!(
        w.explain(&work, C, "main")
            .contains("entry:c/testdata/impl-x.txt")
    );
    w.put("c/testdata/impl-x.txt", &impl_x);
    assert_eq!(w.plan(&work, "main").skip, set(&[B, C]), "step 7: restored");

    // Step 8: a build-constrained file (//go:build linux) is hashed although
    // this platform does not compile it: adding it runs b. Attested with it,
    // b is marked platform-specific and only ever skipped on this OS and
    // architecture.
    w.put(
        "b/b_linux.go",
        "//go:build linux\n\npackage b\n\nconst OnLinux = true\n",
    );
    assert!(w.plan(&work, "main").run.contains(B), "step 8");
    w.run(&work, B, &w.trusted);
    let with_linux: Vec<Value> = w
        .predicates(B)
        .into_iter()
        .filter(|p| p["platformSpecific"].is_array())
        .collect();
    assert_eq!(with_linux.len(), 1, "step 8");
    assert_eq!(with_linux[0]["platformSpecific"][0], "b/b_linux.go");
    assert!(
        with_linux[0]["manifest"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == "b/b_linux.go" && e["kind"] == "file"),
        "the ignored file is hashed"
    );
    assert!(
        w.plan(&work, "main").skip.contains(B),
        "step 8: same platform"
    );
    let b_linux = w.read("b/b_linux.go");
    w.put("b/b_linux.go", &b_linux.replace("true", "false"));
    assert!(w.plan(&work, "main").run.contains(B), "step 8: edited");
    std::fs::remove_file(work.join("b/b_linux.go")).unwrap();
    assert!(w.plan(&work, "main").skip.contains(B), "step 8: removed");

    // Step 9: attest a and d; a module version change in go.mod/go.sum ->
    // everything runs.
    w.run(&work, A, &w.trusted);
    w.run(&work, D, &w.trusted);
    assert_eq!(w.plan(&work, "main").skip, set(&[A, B, C, D]), "step 9");
    let (gomod, gosum) = (w.read("go.mod"), w.read("go.sum"));
    let up = go(&work, &["get", "golang.org/x/sync@v0.22.0"]);
    if up.status.success() {
        let p = w.plan(&work, "main");
        assert!(
            p.skip.is_empty(),
            "step 9: a module bump runs everything: {p:?}"
        );
        assert!(
            w.explain(&work, D, "main")
                .contains("failed check: global-inputs")
        );
    } else {
        eprintln!(
            "SKIPPED (part): `go get golang.org/x/sync@v0.22.0` failed: {}",
            String::from_utf8_lossy(&up.stderr)
        );
    }
    // go.sum alone is enough.
    w.put(
        "go.sum",
        &format!("{gosum}example.com/x v1.0.0/go.mod h1:AAAA\n"),
    );
    w.put("go.mod", &gomod);
    assert!(w.plan(&work, "main").skip.is_empty(), "step 9: go.sum");
    w.put("go.sum", &gosum);
    assert_eq!(
        w.plan(&work, "main").skip,
        set(&[A, B, C, D]),
        "step 9: restored"
    );

    // Step 10: flip a byte in b's payload -> rejected at the signature check.
    let repo = store_for(&work);
    let store = AttestStore::new(&repo);
    let tk = vci_core::test_key(B);
    let stored = store.list(Some(&tk)).unwrap();
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
        let signer = s.signer_ref.strip_prefix(vci_git::REF_PREFIX).unwrap();
        store
            .put(
                signer,
                &tk,
                &s.input_root,
                &serde_json::to_vec(&env).unwrap(),
            )
            .unwrap();
    }
    assert!(w.plan(&work, "main").run.contains(B), "step 10");
    assert!(
        w.explain(&work, B, "main")
            .contains("failed check: signature")
    );
    for s in &stored {
        let signer = s.signer_ref.strip_prefix(vci_git::REF_PREFIX).unwrap();
        store.put(signer, &tk, &s.input_root, &s.bytes).unwrap();
    }
    assert!(w.plan(&work, "main").skip.contains(B), "step 10: restored");

    // Step 11: a key that is not in allowed_signers -> rejected. Edit d's
    // input first so the trusted attestation no longer applies.
    let d_src = w.read("d/d.go");
    w.put("d/d.go", &format!("{d_src}\n// untrusted run\n"));
    w.run(&work, D, &w.untrusted);
    assert!(w.plan(&work, "main").run.contains(D), "step 11");
    let ex = w.explain(&work, D, "main");
    assert!(ex.contains("failed check: signer"), "{ex}");
    assert!(ex.contains("not in allowed_signers"), "{ex}");

    // Step 12: that key added to allowed_signers on the PR branch only ->
    // still rejected.
    let mut signers = w.read(".vci/allowed_signers");
    signers.push_str(&format!(
        "untrusted@example.com namespaces=\"vci-attest\" {}\n",
        pubkey(&w.untrusted)
    ));
    w.put(".vci/allowed_signers", &signers);
    w.git(&work, &["commit", "-q", "-am", "PR: trust my own key"]);
    assert!(w.plan(&work, "main").run.contains(D), "step 12");
    assert!(w.explain(&work, D, "main").contains("failed check: signer"));
    // Control: with the PR commit as the (wrong) trust root, d would be skipped.
    assert!(w.plan(&work, "HEAD").skip.contains(D), "step 12 control");

    // Step 13: a variable declared in [env] global with a different value in
    // CI forces a run (it was unset when b was attested).
    let p = w.plan_env(&work, "main", &[("APP_MODE", "ci")]);
    assert!(p.run.contains(B), "step 13: {p:?}");
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
}

#[test]
fn go_run_refuses_unattestable_packages() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let pkgs: &[(&str, &str)] = &[
        (
            "spawn/spawn_test.go",
            "package spawn\n\nimport (\n\t\"os/exec\"\n\t\"testing\"\n)\n\nfunc TestExec(t *testing.T) {\n\tif err := exec.Command(\"go\", \"version\").Run(); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n",
        ),
        (
            "fail/fail_test.go",
            "package fail\n\nimport \"testing\"\n\nfunc TestFail(t *testing.T) { t.Fatal(\"no\") }\n",
        ),
        (
            "skip/skip_test.go",
            "package skip\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestOK(t *testing.T) {}\n\nfunc TestInCI(t *testing.T) {\n\tif os.Getenv(\"CI\") == \"\" {\n\t\tt.Skip(\"CI only\")\n\t}\n}\n",
        ),
        (
            "netpkg/net_test.go",
            "package netpkg\n\nimport (\n\t\"net/http\"\n\t\"testing\"\n)\n\nfunc TestStatus(t *testing.T) {\n\tif http.StatusOK != 200 {\n\t\tt.Fatal()\n\t}\n}\n",
        ),
        (
            "environ/environ_test.go",
            "package environ\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestEnv(t *testing.T) {\n\tif len(os.Environ()) == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
        ),
        (
            "outside/outside_test.go",
            "package outside\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestOutside(t *testing.T) {\n\tif _, err := os.ReadFile(os.Getenv(\"VCI_E2E_OUTSIDE\")); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n",
        ),
        (
            "sys/sys_test.go",
            "package sys\n\nimport (\n\t\"syscall\"\n\t\"testing\"\n)\n\nfunc TestPid(t *testing.T) {\n\tif syscall.Getpid() <= 0 {\n\t\tt.Fatal()\n\t}\n}\n",
        ),
    ];
    for (rel, body) in pkgs {
        w.put(rel, body);
    }
    let outside = w.base.join("outside.txt");
    std::fs::write(&outside, "outside the repository").unwrap();
    let mut args = vec!["run"];
    let dirs: Vec<&str> = pkgs
        .iter()
        .map(|(rel, _)| rel.split('/').next().unwrap())
        .collect();
    args.extend(&dirs);
    args.extend(["--key", w.trusted.to_str().unwrap()]);
    // VCI_* is built-in pass-through, so the outside path reaches the test.
    let out = w.vci_env(
        &work,
        &args,
        &[("VCI_E2E_OUTSIDE", outside.to_str().unwrap())],
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
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
    refused("spawn", "exec: ");
    refused("spawn", "os.StartProcess");
    refused("fail", "result failed");
    refused("skip", "1 skipped");
    refused("netpkg", "go:net:");
    refused("environ", "os.Environ");
    refused("outside", "input outside the repository");
    refused("sys", "go:syscall:");
    assert!(
        stderr.contains("vci: 0 attested, 7 not attested"),
        "{stderr}"
    );
    let stored = AttestStore::new(&store_for(&work)).list(None).unwrap();
    assert!(stored.is_empty(), "nothing may be stored: {stored:?}");
    let p = w.plan(&work, "main");
    for d in &dirs {
        assert!(p.run.contains(*d), "{d} must run: {p:?}");
    }

    // A test that changes the repository (package os does not log removals):
    // nothing of that run is attested.
    w.put(
        "writes/writes_test.go",
        "package writes\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestWrite(t *testing.T) {\n\tif err := os.Remove(\"../a/stale.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n",
    );
    w.put("a/stale.txt", "x");
    let out = w.vci(
        &work,
        &["run", "writes", A, "--key", w.trusted.to_str().unwrap()],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    for id in ["writes", A] {
        let line = stderr
            .lines()
            .find(|l| l.starts_with(&format!("vci: not attesting {id}:")))
            .unwrap_or_else(|| panic!("{id} was not refused:\n{stderr}"));
        assert!(line.contains("repository changed during the run"), "{line}");
        assert!(line.contains("a/stale.txt"), "{line}");
    }
}

/// `policy.go_allow_net` waives the `net` refusal; the attestation records
/// the waiver and is only accepted while the base commit's policy has it.
#[test]
fn go_allow_net_is_the_base_policys_decision() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put(
        "netpkg/net_test.go",
        "package netpkg\n\nimport (\n\t\"net/http\"\n\t\"testing\"\n)\n\nfunc TestStatus(t *testing.T) {\n\tif http.StatusOK != 200 {\n\t\tt.Fatal()\n\t}\n}\n",
    );
    w.put(
        "vci.toml",
        &VCI_TOML.replace(
            "platform = \"any\"",
            "platform = \"any\"\ngo_allow_net = true",
        ),
    );
    w.git(&work, &["add", "-A"]);
    w.git(&work, &["commit", "-q", "-m", "allow net"]);
    w.run(&work, "netpkg", &w.trusted);
    let pred = &w.predicates("netpkg")[0];
    assert!(
        pred["waived"][0].as_str().unwrap().starts_with("go:net:"),
        "{pred}"
    );
    // main's policy does not allow it.
    let ex = w.explain(&work, "netpkg", "main");
    assert!(ex.contains("waived refusal"), "{ex}");
    assert!(w.plan(&work, "main").run.contains("netpkg"));
    // A base that allows it (the commit that set it) accepts it.
    let allow = w.git(&work, &["rev-parse", "HEAD"]);
    assert!(w.plan(&work, &allow).skip.contains("netpkg"));
}

#[test]
fn go_push_fetch_fresh_clone_and_ci() {
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
    assert!(
        w.plan(&fresh, "main").skip.is_empty(),
        "nothing before fetch"
    );
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    assert_eq!(w.plan(&fresh, "main"), before, "same plan in a fresh clone");

    // `vci ci` runs only the remainder with go test and writes an audit log.
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
    assert!(stderr.contains("running 2 test file(s)"), "{stderr}");
    assert!(
        stderr.contains("go test -count=1 -json ./a ./d"),
        "{stderr}"
    );
    assert!(stderr.contains("--- PASS: TestAdd"), "{stderr}");
    assert!(stderr.contains("--- PASS: TestSum"), "{stderr}");
    assert!(!stderr.contains("TestGreet"), "b must not run: {stderr}");
    let log: Value = serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
    let skipped: BTreeSet<String> = log["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["testId"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(skipped, set(&[B, C]));
    assert_eq!(log["exitCode"], 0);

    // A failing package among the remainder makes `vci ci` exit non-zero.
    std::fs::create_dir_all(fresh.join("zfail")).unwrap();
    std::fs::write(
        fresh.join("zfail/zfail_test.go"),
        "package zfail\n\nimport \"testing\"\n\nfunc TestFail(t *testing.T) { t.Fatal(\"no\") }\n",
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
    std::fs::remove_dir_all(fresh.join("zfail")).unwrap();

    // Policy: nothing is skipped on refs listed in no_skip_refs.
    w.git(&fresh, &["checkout", "-q", "-b", "release/1"]);
    let p = w.plan(&fresh, "main");
    assert!(p.run_all && p.skip.is_empty(), "{p:?}");
    w.git(&fresh, &["checkout", "-q", "feature"]);
    // A package that does not build runs (and fails); the others keep their
    // verdicts.
    std::fs::create_dir_all(fresh.join("broken")).unwrap();
    std::fs::write(
        fresh.join("broken/broken_test.go"),
        "package broken\n\nimport \"example.com/abcd/does/not/exist\"\n",
    )
    .unwrap();
    let p = w.plan(&fresh, "main");
    assert!(p.run.contains("broken") && p.skip == set(&[B, C]), "{p:?}");
    std::fs::remove_dir_all(fresh.join("broken")).unwrap();
    // go list cannot load the module at all: everything runs.
    let gomod = std::fs::read_to_string(fresh.join("go.mod")).unwrap();
    std::fs::write(fresh.join("go.mod"), format!("{gomod}\nnot a directive\n")).unwrap();
    let out = w.vci(&fresh, &["plan", "--base-ref", "main", "--format", "json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["runAll"]
            .as_str()
            .unwrap_or("")
            .contains("listing test files failed"),
        "{v}"
    );
    std::fs::write(fresh.join("go.mod"), gomod).unwrap();

    // go missing in CI: everything runs (never a false skip).
    let out = w.vci_env(
        &fresh,
        &["plan", "--base-ref", "main", "--format", "json"],
        &[("VCI_GO", "/nonexistent/go")],
    );
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["runAll"].as_str().unwrap_or("").contains("go"), "{v}");
}

/// Test ids are repo-relative package directories: a module in a
/// subdirectory, next to a pytest-free root.
#[test]
fn go_project_in_a_subdirectory() {
    let toml = VCI_TOML.replace("project = \".\"", "project = \"svc\"");
    let Some(w) = World::build(&toml, |d| copy_go_fixture(&d.join("svc")), &["svc"]) else {
        return;
    };
    let work = w.work.clone();
    w.run(&work, "svc/b", &w.trusted);
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&["svc/b"]), "{p:?}");
    assert_eq!(p.run, set(&["svc/a", "svc/c", "svc/d"]), "{p:?}");
    // Running from inside the project dir names the same package.
    w.run(&work.join("svc"), "c", &w.trusted);
    assert_eq!(w.plan(&work, "main").skip, set(&["svc/b", "svc/c"]));
    let text = w.read("svc/internal/text/text.go");
    w.put("svc/internal/text/text.go", &format!("{text}\n// edited\n"));
    let p = w.plan(&work, "main");
    assert!(p.run.contains("svc/b") && p.skip.contains("svc/c"), "{p:?}");
    assert!(
        w.explain(&work, "svc/b", "main")
            .contains("entry:svc/internal/text/text.go")
    );
}

/// `vci init --adapter go` writes a Go vci.toml and prints the Go workflow.
#[test]
fn go_init_writes_config_and_prints_the_go_workflow() {
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
            "go",
            "--project",
            "svc",
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
    assert!(toml.contains("adapter = \"go\""), "{toml}");
    assert!(toml.contains("project = \"svc\""), "{toml}");
    assert!(toml.contains("go_allow_net = false"), "{toml}");
    let signers = std::fs::read_to_string(dir.join(".vci/allowed_signers")).unwrap();
    assert!(signers.contains("me@example.com namespaces=\"vci-attest\" ssh-ed25519 "));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("actions/setup-go"), "{stdout}");
    assert!(stdout.contains("vci ci --base-ref"), "{stdout}");
}

/// Another Go version never matches: through another go binary (`VCI_GO`),
/// or through a declared `GOTOOLCHAIN` that makes the go command switch.
/// Uses a toolchain already in the module cache (no download); skipped
/// without one.
#[test]
fn go_other_go_version_runs() {
    let toml = VCI_TOML.replace(
        "global = [\"APP_MODE\"]",
        "global = [\"APP_MODE\", \"GOTOOLCHAIN\"]",
    );
    let Some(w) = World::build(&toml, copy_go_fixture, &["."]) else {
        return;
    };
    let work = w.work.clone();
    let env_of = |k: &str| {
        String::from_utf8_lossy(&go(&work, &["env", k]).stdout)
            .trim()
            .to_owned()
    };
    let (ours, modcache) = (env_of("GOVERSION"), env_of("GOMODCACHE"));
    let suffix = format!(".{}-{}", env_of("GOOS"), env_of("GOARCH"));
    let other = std::fs::read_dir(Path::new(&modcache).join("golang.org"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let v = name
                .strip_prefix("toolchain@v0.0.1-")?
                .strip_suffix(&suffix)?
                .to_owned();
            let bin = e.path().join("bin/go");
            (v != ours && bin.is_file()).then_some((v, bin))
        })
        .next();
    let Some((version, bin)) = other else {
        eprintln!("SKIPPED: no other Go toolchain for this platform in the module cache");
        return;
    };
    w.run(&work, B, &w.trusted);
    assert!(w.plan(&work, "main").skip.contains(B));
    for env in [
        [("VCI_GO", bin.to_str().unwrap())],
        [("GOTOOLCHAIN", version.as_str())],
    ] {
        let p = w.plan_env(&work, "main", &env);
        assert!(p.run.contains(B), "{env:?}: {p:?}");
        if p.run_all {
            eprintln!("SKIPPED (part): {env:?} could not be used: {p:?}");
            continue;
        }
        let out = w.vci_env(&work, &["explain", B, "--base-ref", "main"], &env);
        let ex = String::from_utf8_lossy(&out.stdout);
        assert!(ex.contains("failed check: toolchain"), "{env:?}: {ex}");
        assert!(
            ex.contains("    go\n") && ex.contains(&version),
            "{env:?}: {ex}"
        );
    }
}

// ---------------------------------------------------------------------------
// Regression tests for adversarial findings against the Go adapter. Each one
// was a false skip (or an over-invalidation) before the fix.

impl World {
    /// `vci run <pkgs> --key trusted` with `env`: (exit ok, stderr).
    fn run_pkgs(&self, pkgs: &[&str], env: &[(&str, &str)]) -> (bool, String) {
        let mut args = vec!["run"];
        args.extend(pkgs);
        args.extend(["--key", self.trusted.to_str().unwrap()]);
        let out = self.vci_env(&self.work, &args, env);
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// Point `rel` (a symlink, replaced if present) at `target`.
    fn link(&self, target: &str, rel: &str) {
        let p = self.work.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let _ = std::fs::remove_file(&p);
        std::os::unix::fs::symlink(target, p).unwrap();
    }
}

fn attested(stderr: &str, id: &str) {
    assert!(
        stderr
            .lines()
            .any(|l| l.starts_with(&format!("vci: attested {id} ("))),
        "{id} was not attested:\n{stderr}"
    );
}

fn refused(stderr: &str, id: &str, why: &str) {
    let line = stderr
        .lines()
        .find(|l| l.starts_with(&format!("vci: not attesting {id}:")))
        .unwrap_or_else(|| panic!("{id} was not refused:\n{stderr}"));
    assert!(line.contains(why), "{id}: expected {why:?} in {line:?}");
}

const RL_TEST: &str = r#"package rl

import (
	"io/fs"
	"os"
	"testing"
)

func TestLink(t *testing.T) {
	got, err := fs.ReadLink(os.DirFS("testdata"), "link")
	if err != nil {
		t.Fatal(err)
	}
	if got != "a.txt" {
		t.Fatalf("link -> %q", got)
	}
}
"#;

const RR_TEST: &str = r#"package rr

import (
	"io/fs"
	"os"
	"testing"
)

func TestRootLink(t *testing.T) {
	r, err := os.OpenRoot("testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := fs.ReadLink(r.FS(), "link")
	if err != nil {
		t.Fatal(err)
	}
	if got != "a.txt" {
		t.Fatalf("link -> %q", got)
	}
}
"#;

const CP_TEST: &str = r#"package cp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopy(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("testdata")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "current.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "fast\n" {
		t.Fatalf("current.conf = %q", b)
	}
}
"#;

const RV_TEST: &str = r#"package rv

import (
	"os"
	"testing"
)

var readlink = os.Readlink

func TestLink(t *testing.T) {
	got, err := readlink("testdata/link")
	if err != nil {
		t.Fatal(err)
	}
	if got != "a.txt" {
		t.Fatalf("link -> %q", got)
	}
}
"#;

/// io/fs.ReadLink over os.DirFS or an os.Root, os.CopyFS of a fixture with a
/// symlink, and os.Readlink through a function value: the link targets are
/// inputs (retargeting a link runs the package).
#[test]
fn go_symlink_targets_read_through_the_standard_library_are_inputs() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    for (pkg, src) in [("rl", RL_TEST), ("rr", RR_TEST), ("rv", RV_TEST)] {
        w.put(&format!("{pkg}/{pkg}_test.go"), src);
        w.put(&format!("{pkg}/testdata/a.txt"), "a\n");
        w.put(&format!("{pkg}/testdata/b.txt"), "b\n");
        w.link("a.txt", &format!("{pkg}/testdata/link"));
    }
    w.put("cp/cp_test.go", CP_TEST);
    w.put("cp/testdata/fast.conf", "fast\n");
    w.put("cp/testdata/slow.conf", "slow\n");
    w.link("fast.conf", "cp/testdata/current.conf");
    let pkgs = ["rl", "rr", "rv", "cp"];
    let (ok, stderr) = w.run_pkgs(&pkgs, &[]);
    assert!(ok, "{stderr}");
    for p in pkgs {
        attested(&stderr, p);
    }
    assert!(w.plan(&work, "main").skip.is_superset(&set(&pkgs)));
    for (pkg, link, other) in [
        ("rl", "rl/testdata/link", "b.txt"),
        ("rr", "rr/testdata/link", "b.txt"),
        ("rv", "rv/testdata/link", "b.txt"),
        ("cp", "cp/testdata/current.conf", "slow.conf"),
    ] {
        let before = std::fs::read_link(work.join(link)).unwrap();
        w.link(other, link);
        let p = w.plan(&work, "main");
        assert!(
            p.run.contains(pkg),
            "{pkg} must run after {link} was retargeted: {p:?}"
        );
        let ex = w.explain(&work, pkg, "main");
        assert!(ex.contains(&format!("entry:{link}")), "{ex}");
        w.link(before.to_str().unwrap(), link);
        assert!(w.plan(&work, "main").skip.contains(pkg), "{pkg}: restored");
    }
}

const EN_TEST: &str = r#"package en

import (
	"os"
	"strings"
	"testing"
)

var environ = os.Environ

func TestNotOnCI(t *testing.T) {
	for _, e := range environ() {
		if strings.HasPrefix(e, "CI=") {
			t.Fatal("CI is set")
		}
	}
}
"#;

const CE_TEST: &str = r#"package ce

import (
	"os/exec"
	"testing"
)

func TestEnv(t *testing.T) {
	if len(exec.Command("true").Environ()) == 0 {
		t.Fatal("no environment")
	}
}
"#;

const SY_TEST: &str = r#"package sy

import (
	"os"
	"path/filepath"
	"testing"
)

var symlink = os.Symlink

func TestThroughLink(t *testing.T) {
	abs, err := filepath.Abs("testdata/x.txt")
	if err != nil {
		t.Fatal(err)
	}
	l := filepath.Join(t.TempDir(), "l")
	if err := symlink(abs, l); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(l)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "x\n" {
		t.Fatalf("got %q", b)
	}
}
"#;

const HL_TEST: &str = r#"package hl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestThroughHardLink(t *testing.T) {
	l := filepath.Join(t.TempDir(), "l")
	if err := os.Link("testdata/x.txt", l); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(l); err != nil {
		t.Fatal(err)
	}
}
"#;

/// Symlinks inside the temp dir only: nothing outside it is reached.
const ST_TEST: &str = r#"package st

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTmpLink(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "f"), []byte("f"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(d, "l")); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(d, "l")); err != nil || string(b) != "f" {
		t.Fatal(b, err)
	}
}
"#;

/// os.Environ as a function value, exec.Cmd.Environ, and os.Symlink /
/// os.Link to a repository file (read back through the link in the temp
/// dir) are refused; a symlink within the temp dir is fine.
#[test]
fn go_environ_and_links_out_of_the_temp_dir_are_refused() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put("en/en_test.go", EN_TEST);
    w.put("ce/ce_test.go", CE_TEST);
    w.put("sy/sy_test.go", SY_TEST);
    w.put("sy/testdata/x.txt", "x\n");
    w.put("hl/hl_test.go", HL_TEST);
    w.put("hl/testdata/x.txt", "x\n");
    w.put("st/st_test.go", ST_TEST);
    let (_, stderr) = w.run_pkgs(&["en", "ce", "sy", "st"], &[]);
    refused(&stderr, "en", "Environ");
    refused(&stderr, "ce", "Environ");
    refused(&stderr, "sy", "created a link to");
    refused(&stderr, "sy", "sy/testdata/x.txt");
    attested(&stderr, "st");
    // A hard link to a repository file: refused as a link out of the temp
    // dir, and it changes the file's ctime and link count (so every package
    // of that run is refused as "repository changed"): run on its own.
    let (_, stderr) = w.run_pkgs(&["hl"], &[]);
    refused(&stderr, "hl", "");
    let p = w.plan_env(&work, "main", &[("CI", "true")]);
    for id in ["en", "ce", "sy", "hl"] {
        assert!(p.run.contains(id), "{id}: {p:?}");
    }
}

/// A module served from a local file:// GOPROXY; `None` (with a SKIPPED
/// message) when `zip` is missing.
fn file_proxy(dir: &Path, module: &str, version: &str, files: &[(&str, &str)]) -> Option<()> {
    let stage = dir.join("stage");
    let root = stage.join(format!("{module}@{version}"));
    for (rel, text) in files {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
    let at = dir.join("proxy").join(module).join("@v");
    std::fs::create_dir_all(&at).unwrap();
    std::fs::write(at.join("list"), format!("{version}\n")).unwrap();
    std::fs::write(
        at.join(format!("{version}.info")),
        format!("{{\"Version\":\"{version}\"}}\n"),
    )
    .unwrap();
    let gomod = files
        .iter()
        .find(|(n, _)| *n == "go.mod")
        .map(|(_, t)| *t)
        .unwrap();
    std::fs::write(at.join(format!("{version}.mod")), gomod).unwrap();
    let st = Command::new("zip")
        .args(["-qrD"])
        .arg(at.join(format!("{version}.zip")))
        .arg(".")
        .current_dir(&stage)
        .status();
    match st {
        Ok(s) if s.success() => Some(()),
        _ => {
            eprintln!("SKIPPED: `zip` is needed to build a module for the file:// GOPROXY");
            None
        }
    }
}

/// `var environ = os.Environ` inside a third-party module (module cache,
/// identified by version) is refused.
#[test]
fn go_third_party_environ_function_value_is_refused() {
    let layout = |d: &Path| {
        std::fs::write(d.join("go.mod"), "module example.com/abcd\n\ngo 1.25.0\n").unwrap();
        std::fs::create_dir_all(d.join("te2")).unwrap();
        std::fs::write(
            d.join("te2/te2_test.go"),
            "package te2\n\nimport (\n\t\"testing\"\n\n\t\"example.org/tp\"\n)\n\nfunc TestNotOnCI(t *testing.T) {\n\tif tp.OnCI() {\n\t\tt.Fatal(\"CI\")\n\t}\n}\n",
        )
        .unwrap();
    };
    let Some(w) = World::build(VCI_TOML, layout, &["."]) else {
        return;
    };
    let work = w.work.clone();
    let gp = w.base.join("goproxy");
    let tp = "package tp\n\nimport (\n\t\"os\"\n\t\"strings\"\n)\n\nvar environ = os.Environ\n\n// OnCI reports whether CI is set.\nfunc OnCI() bool {\n\tfor _, e := range environ() {\n\t\tif strings.HasPrefix(e, \"CI=\") {\n\t\t\treturn true\n\t\t}\n\t}\n\treturn false\n}\n";
    if file_proxy(
        &gp,
        "example.org/tp",
        "v1.0.0",
        &[
            ("go.mod", "module example.org/tp\n\ngo 1.25.0\n"),
            ("tp.go", tp),
        ],
    )
    .is_none()
    {
        return;
    }
    let modcache = w.base.join("modcache");
    let proxy = format!("file://{}", gp.join("proxy").display());
    let genv: Vec<(&str, &str)> = vec![
        ("GOPROXY", proxy.as_str()),
        ("GOMODCACHE", modcache.to_str().unwrap()),
        ("GOSUMDB", "off"),
    ];
    let mut get = Command::new("go");
    get.args(["get", "example.org/tp@v1.0.0"])
        .current_dir(&work);
    for k in SCRUB {
        get.env_remove(k);
    }
    for (k, v) in &genv {
        get.env(k, v);
    }
    let out = get.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (_, stderr) = w.run_pkgs(&["te2"], &genv);
    refused(&stderr, "te2", "Environ");
    let _ = Command::new("go")
        .args(["clean", "-modcache"])
        .env("GOMODCACHE", &modcache)
        .current_dir(&work)
        .output();
}

const AS_GO: &str = "//go:build arm64 || amd64\n\npackage as\n\n// Answer is implemented in assembly.\nfunc Answer() int64\n";
const AS_ARM64: &str = "#include \"textflag.h\"\n#include \"../shared/consts.h\"\n\nTEXT ·Answer(SB), NOSPLIT, $0-8\n\tMOVD $ANSWER, R0\n\tMOVD R0, ret+0(FP)\n\tRET\n";
const AS_AMD64: &str = "#include \"textflag.h\"\n#include \"../shared/consts.h\"\n\nTEXT ·Answer(SB), NOSPLIT, $0-8\n\tMOVQ $ANSWER, AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n";
const AS_TEST: &str = "//go:build arm64 || amd64\n\npackage as\n\nimport \"testing\"\n\nfunc TestAnswer(t *testing.T) {\n\tif Answer() != 42 {\n\t\tt.Fatal(Answer())\n\t}\n}\n";

/// A header an assembly file includes from outside the package directory
/// is an input.
#[test]
fn go_assembly_include_outside_the_package_is_an_input() {
    if !cfg!(any(target_arch = "aarch64", target_arch = "x86_64")) {
        eprintln!("SKIPPED: the assembly fixture is for arm64 and amd64");
        return;
    }
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put("as/as.go", AS_GO);
    w.put("as/as_arm64.s", AS_ARM64);
    w.put("as/as_amd64.s", AS_AMD64);
    w.put("as/as_test.go", AS_TEST);
    w.put("shared/consts.h", "#define ANSWER 42\n");
    let (ok, stderr) = w.run_pkgs(&["as"], &[]);
    assert!(ok, "{stderr}");
    attested(&stderr, "as");
    let entries = &w.predicates("as")[0]["manifest"]["entries"];
    assert!(
        entries
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == "shared/consts.h" && e["kind"] == "file"),
        "{entries}"
    );
    assert!(w.plan(&work, "main").skip.contains("as"));
    w.put("shared/consts.h", "#define ANSWER 41\n");
    let p = w.plan(&work, "main");
    assert!(p.run.contains("as"), "{p:?}");
    assert!(
        w.explain(&work, "as", "main")
            .contains("entry:shared/consts.h")
    );
}

/// A runtime platform check in the repository's code (runtime.GOOS, an
/// aliased runtime.GOARCH) pins the attestation to the attesting OS and
/// architecture; floating-point code pins it to the architecture.
#[test]
fn go_runtime_platform_checks_and_floating_point_pin_the_attestation() {
    let Some(w) = World::new() else { return };
    w.put(
        "pg/pg_test.go",
        "package pg\n\nimport (\n\t\"os\"\n\t\"runtime\"\n\t\"strings\"\n\t\"testing\"\n)\n\nfunc TestByOS(t *testing.T) {\n\tb, err := os.ReadFile(\"testdata/\" + runtime.GOOS + \".txt\")\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif strings.TrimSpace(string(b)) != \"expected\" {\n\t\tt.Fatalf(\"%s: got %q\", runtime.GOOS, b)\n\t}\n}\n",
    );
    for os in ["darwin", "linux"] {
        w.put(&format!("pg/testdata/{os}.txt"), "expected\n");
    }
    w.put(
        "pa/pa.go",
        "package pa\n\nimport rt \"runtime\"\n\n// Wide reports whether this is a 64-bit ARM machine.\nfunc Wide() bool { return rt.GOARCH == \"arm64\" }\n",
    );
    w.put(
        "pa/pa_test.go",
        "package pa\n\nimport \"testing\"\n\nfunc TestWide(t *testing.T) { _ = Wide() }\n",
    );
    w.put(
        "fm/fm.go",
        "package fm\n\n// Residual is x*y + z (fused into one instruction on arm64).\nfunc Residual(x, y, z float64) float64 { return x*y + z }\n",
    );
    w.put(
        "fm/fm_test.go",
        "package fm\n\nimport \"testing\"\n\nfunc TestResidual(t *testing.T) {\n\tif r := Residual(0.1, 10, -1); r < 0 || r > 1e-15 {\n\t\tt.Fatal(r)\n\t}\n}\n",
    );
    let (ok, stderr) = w.run_pkgs(&["pg", "pa", "fm", A], &[]);
    assert!(ok, "{stderr}");
    for id in ["pg", "pa", "fm", A] {
        attested(&stderr, id);
    }
    let pred = |id: &str| w.predicates(id).into_iter().next().unwrap();
    assert_eq!(pred("pg")["platformSpecific"][0], "pg/pg_test.go");
    assert_eq!(pred("pa")["platformSpecific"][0], "pa/pa.go");
    let fm = pred("fm");
    assert!(fm["platformSpecific"].is_null(), "{fm}");
    assert!(
        fm["archSpecific"][0]
            .as_str()
            .unwrap()
            .contains("floating point in fm.go"),
        "{fm}"
    );
    let a = pred(A);
    assert!(
        a["platformSpecific"].is_null() && a["archSpecific"].is_null(),
        "{a}"
    );
    // On this machine all of them are skipped.
    assert!(
        w.plan(&w.work, "main")
            .skip
            .is_superset(&set(&["pg", "pa", "fm", A]))
    );
}

/// A package where no test ran (TestMain exits before m.Run, no test
/// functions, a TestMain that filters the tests) is not attested.
#[test]
fn go_package_where_not_every_test_ran_is_refused() {
    let Some(w) = World::new() else { return };
    w.put(
        "tx/tx_test.go",
        "package tx\n\nimport (\n\t\"fmt\"\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) {\n\tfmt.Println(\"skipping package: these tests need root\")\n\tos.Exit(0)\n}\n\nfunc TestNeedsRoot(t *testing.T) { t.Fatal(\"not root\") }\n",
    );
    w.put(
        "t0/t0_test.go",
        "package t0\n\nfunc helper() int { return 1 }\n\nvar _ = helper\n",
    );
    w.put(
        "tf/tf_test.go",
        "package tf\n\nimport (\n\t\"flag\"\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) {\n\t_ = flag.Set(\"test.run\", \"^TestA$\")\n\tos.Exit(m.Run())\n}\n\nfunc TestA(t *testing.T) {}\n\nfunc TestB(t *testing.T) { t.Fatal(\"filtered out\") }\n",
    );
    let (_, stderr) = w.run_pkgs(&["tx", "t0", "tf"], &[]);
    refused(&stderr, "tx", "no test ran");
    refused(&stderr, "t0", "no test ran");
    refused(&stderr, "tf", "declared tests did not run: TestB");
}

/// GOFLAGS naming a program or files vci does not hash (-toolexec) stops
/// `vci run`.
#[test]
fn go_goflags_toolexec_is_refused() {
    let toml = VCI_TOML.replace(
        "global = [\"APP_MODE\"]",
        "global = [\"APP_MODE\", \"GOFLAGS\"]",
    );
    let Some(w) = World::build(&toml, copy_go_fixture, &["."]) else {
        return;
    };
    let wrap = w.base.join("wrap.sh");
    std::fs::write(&wrap, "#!/bin/sh\nexec \"$@\"\n").unwrap();
    std::fs::set_permissions(&wrap, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let flags = format!("-toolexec={}", wrap.display());
    let (ok, stderr) = w.run_pkgs(&[A], &[("GOFLAGS", flags.as_str())]);
    assert!(!ok, "{stderr}");
    assert!(stderr.contains("-toolexec"), "{stderr}");
    assert!(
        AttestStore::new(&store_for(&w.work))
            .list(None)
            .unwrap()
            .is_empty()
    );
}

/// File.Readdir of a directory opened by a relative name before a chdir:
/// package os logs the entries relative to the new working directory, so
/// the package is refused instead of recording the wrong paths.
#[test]
fn go_readdir_after_chdir_is_refused() {
    let Some(w) = World::new() else { return };
    w.put(
        "cf/cf_test.go",
        "package cf\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestSizes(t *testing.T) {\n\tf, err := os.Open(\"testdata\")\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tdefer f.Close()\n\tt.Chdir(t.TempDir())\n\tinfos, err := f.Readdir(-1)\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tfor _, fi := range infos {\n\t\tif fi.Name() == \"x.txt\" && fi.Size() != 2 {\n\t\t\tt.Fatal(fi.Size())\n\t\t}\n\t}\n}\n",
    );
    w.put("cf/testdata/x.txt", "x\n");
    // Control: a plain relative read after t.Chdir is resolved like the
    // kernel resolves it, and recorded.
    w.put(
        "cg/cg_test.go",
        "package cg\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestRead(t *testing.T) {\n\tt.Chdir(\"testdata\")\n\tif b, err := os.ReadFile(\"x.txt\"); err != nil || string(b) != \"x\\n\" {\n\t\tt.Fatal(b, err)\n\t}\n}\n",
    );
    w.put("cg/testdata/x.txt", "x\n");
    let (_, stderr) = w.run_pkgs(&["cf", "cg"], &[]);
    refused(&stderr, "cf", "working directory changed");
    attested(&stderr, "cg");
    w.put("cg/testdata/x.txt", "y\n");
    assert!(w.plan(&w.work, "main").run.contains("cg"));
}

/// A dependency's `_test.go` files are not compiled into a dependent's test:
/// editing them runs the dependency, not the dependent.
#[test]
fn go_dependency_test_files_do_not_invalidate_dependents() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put(
        "u/u.go",
        "package u\n\nimport \"example.com/abcd/a\"\n\n// Twice adds x to itself.\nfunc Twice(x int) int { return a.Add(x, x) }\n",
    );
    w.put(
        "u/u_test.go",
        "package u\n\nimport \"testing\"\n\nfunc TestTwice(t *testing.T) {\n\tif Twice(2) != 4 {\n\t\tt.Fatal()\n\t}\n}\n",
    );
    let (ok, stderr) = w.run_pkgs(&["u", A], &[]);
    assert!(ok, "{stderr}");
    let a_test = w.read("a/a_test.go");
    w.put("a/a_test.go", &format!("{a_test}// x\n"));
    let p = w.plan(&work, "main");
    assert!(p.skip.contains("u"), "u must stay skipped: {p:?}");
    assert!(p.run.contains(A), "{p:?}");
    // a's own code still invalidates u.
    w.put("a/a_test.go", &a_test);
    let a_src = w.read("a/a.go");
    w.put("a/a.go", &format!("{a_src}// y\n"));
    assert!(w.plan(&work, "main").run.contains("u"));
}

const TZ_TEST: &str = "package tz\n\nimport (\n\t\"testing\"\n\t\"time\"\n)\n\nfunc TestZone(t *testing.T) {\n\tif name, _ := time.Now().Zone(); name == \"\" {\n\t\tt.Fatal(\"no zone name\")\n\t}\n}\n";

/// The local time zone comes from /etc/localtime unless TZ is set: a test
/// that uses it is refused without TZ, and attested (TZ hashed) with a
/// declared TZ.
#[test]
fn go_local_time_zone_needs_a_declared_tz() {
    let Some(w) = World::new() else { return };
    w.put("tz/tz_test.go", TZ_TEST);
    let (_, stderr) = w.run_pkgs(&["tz", B], &[]);
    refused(&stderr, "tz", "local time zone");
    // b does not use the local zone.
    attested(&stderr, B);

    let toml = VCI_TOML.replace("global = [\"APP_MODE\"]", "global = [\"APP_MODE\", \"TZ\"]");
    let Some(w) = World::build(&toml, copy_go_fixture, &["."]) else {
        return;
    };
    let work = w.work.clone();
    w.put("tz/tz_test.go", TZ_TEST);
    let (ok, stderr) = w.run_pkgs(&["tz"], &[("TZ", "UTC")]);
    assert!(ok, "{stderr}");
    attested(&stderr, "tz");
    assert!(
        w.plan_env(&work, "main", &[("TZ", "UTC")])
            .skip
            .contains("tz")
    );
    assert!(w.plan(&work, "main").run.contains("tz"), "TZ unset");
    assert!(
        w.plan_env(&work, "main", &[("TZ", "America/New_York")])
            .run
            .contains("tz")
    );
}

/// Regression: `NODE_OPTIONS` and the user's `VCI_*` variables are built-in
/// pass-through (they reach the test), but reads of them were never hashed,
/// so a Go test that fails when one is set was skipped where it is set.
#[test]
fn go_reads_of_node_options_and_vci_variables_are_hashed() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put(
        "ve/ve_test.go",
        "package ve\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestUnset(t *testing.T) {\n\tif os.Getenv(\"NODE_OPTIONS\") != \"\" || os.Getenv(\"VCI_BASE_REF\") != \"\" {\n\t\tt.Fatal(\"set\")\n\t}\n}\n",
    );
    let (ok, stderr) = w.run_pkgs(&["ve"], &[]);
    assert!(ok, "{stderr}");
    attested(&stderr, "ve");
    assert!(w.plan(&work, "main").skip.contains("ve"));
    for env in [
        ("NODE_OPTIONS", "--max-old-space-size=4096"),
        ("VCI_BASE_REF", "main"),
    ] {
        let p = w.plan_env(&work, "main", &[env]);
        assert!(p.run.contains("ve"), "{env:?}: {p:?}");
    }
}
