//! End-to-end verification (docs/PLAN.md, "End-to-end verification"), run
//! against a copy of `fixtures/vitest-abcd` in a throwaway git repo with
//! throwaway SSH keys and a local bare remote.
//!
//! Needs `node`, `git` and `ssh-keygen` on PATH, and the fixture's
//! `node_modules` installed (`npm ci` in fixtures/vitest-abcd).

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

struct World {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    work: PathBuf,
    remote: PathBuf,
    trusted: PathBuf,
    untrusted: PathBuf,
    gitconfig: PathBuf,
}

const VCI_TOML: &str = r#"project = "."

[policy]
platform = "any"
max_ttl = "30d"
no_skip_refs = ["refs/heads/release/*"]

[env]
mode = "strict"
global = ["NODE_ENV"]
"#;

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

impl World {
    fn new() -> Self {
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
        w.make_project(&w.work, "base commit");
        w.git(
            &w.work,
            &["remote", "add", "origin", w.remote.to_str().unwrap()],
        );
        w.git(&w.work, &["push", "-q", "origin", "main"]);
        // Work happens on a PR branch; `main` is the base.
        w.git(&w.work, &["checkout", "-q", "-b", "feature"]);
        w
    }

    /// Like [`World::new`], with extra files and a different vci.toml in the
    /// base commit.
    fn new_with(extra: &[(&str, &str)], vci_toml: &str) -> Self {
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
        w.make_project_with(&w.work, "base commit", extra, vci_toml);
        w.git(
            &w.work,
            &["remote", "add", "origin", w.remote.to_str().unwrap()],
        );
        w.git(&w.work, &["push", "-q", "origin", "main"]);
        w.git(&w.work, &["checkout", "-q", "-b", "feature"]);
        w
    }

    /// Copy the fixture into `dir`, add vci.toml and allowed_signers, commit.
    fn make_project(&self, dir: &Path, message: &str) {
        self.make_project_with(dir, message, &[], VCI_TOML);
    }

    fn make_project_with(&self, dir: &Path, message: &str, extra: &[(&str, &str)], toml: &str) {
        let fx = workspace_root().join("fixtures/vitest-abcd");
        self.git(&self.base, &["init", "-q", dir.to_str().unwrap()]);
        for name in [
            "src",
            "fixtures",
            "package.json",
            "package-lock.json",
            "vitest.config.ts",
        ] {
            cp(&fx.join(name), &dir.join(name));
        }
        self.install_node_modules(dir);
        for (rel, body) in extra {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        std::fs::write(dir.join(".gitignore"), "node_modules/\n.vci/out/\n").unwrap();
        std::fs::write(dir.join("vci.toml"), toml).unwrap();
        std::fs::create_dir_all(dir.join(".vci")).unwrap();
        std::fs::write(
            dir.join(".vci/allowed_signers"),
            format!(
                "trusted@example.com namespaces=\"vci-attest\" {}\n",
                pubkey(&self.trusted)
            ),
        )
        .unwrap();
        self.git(dir, &["add", "-A"]);
        self.git(dir, &["commit", "-q", "-m", message]);
    }

    fn install_node_modules(&self, dir: &Path) {
        cp(
            &workspace_root().join("fixtures/vitest-abcd/node_modules"),
            &dir.join("node_modules"),
        );
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

    fn vci(&self, dir: &Path, args: &[&str]) -> Output {
        let mut cmd = Command::cargo_bin("vci").unwrap();
        cmd.current_dir(dir)
            .args(args)
            .env("VCI_JS_PLUGIN", workspace_root().join("js/vitest-plugin"))
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("NO_COLOR", "1");
        for k in [
            "VCI_BASE_REF",
            "GITHUB_BASE_REF",
            "GITHUB_REF",
            "GITHUB_OUTPUT",
            "VCI_SIGNING_KEY",
            "VCI_OUT",
            "NODE_OPTIONS",
        ] {
            cmd.env_remove(k);
        }
        let out = cmd.output().unwrap();
        eprintln!(
            "$ vci {}\n{}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
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

    /// Publish `dir`'s attestations (`vci push`) to a new bare repository,
    /// returned for `vci fetch --remote`.
    fn publish(&self, dir: &Path, name: &str) -> PathBuf {
        let bare = self.base.join(format!("{name}.git"));
        self.git(
            &self.base,
            &["init", "-q", "--bare", bare.to_str().unwrap()],
        );
        self.vci_ok(dir, &["push", "--remote", bare.to_str().unwrap()]);
        bare
    }

    fn run(&self, dir: &Path, file: &str, key: &Path) {
        let out = self.vci_ok(dir, &["run", file, "--key", key.to_str().unwrap()]);
        let _ = out;
    }

    fn plan(&self, dir: &Path, base: &str) -> Plan {
        let out = self.vci_ok(dir, &["plan", "--base-ref", base, "--format", "json"]);
        let v: Value = serde_json::from_str(&out).unwrap();
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

    fn explain(&self, dir: &Path, file: &str, base: &str) -> String {
        self.vci_ok(dir, &["explain", file, "--base-ref", base])
    }

    fn write(&self, rel: &str, content: &str) {
        std::fs::write(self.work.join(rel), content).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.work.join(rel)).unwrap()
    }
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

fn cp(from: &Path, to: &Path) {
    let st = Command::new("cp")
        .arg("-R")
        .arg(from)
        .arg(to)
        .status()
        .unwrap();
    assert!(st.success());
}

#[derive(Debug, PartialEq, Eq)]
struct Plan {
    skip: BTreeSet<String>,
    run: BTreeSet<String>,
    run_all: bool,
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";
const D: &str = "src/d.test.ts";

fn store_for(dir: &Path) -> Repo {
    Repo::discover(Utf8Path::from_path(dir).unwrap()).unwrap()
}

/// The blake3 hex of a file, as printed by explain.
fn blake3_of(bytes: &[u8]) -> String {
    vci_core::blake3_hex(bytes)
}

#[test]
fn end_to_end_verification_steps() {
    let w = World::new();
    let work = w.work.clone();

    // Step 1: attest B, then plan: skip B; run A, C, D.
    w.run(&work, B, &w.trusted);
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[B]), "step 1");
    assert_eq!(p.run, set(&[A, C, D]), "step 1");
    assert!(!p.run_all);

    // Step 2: edit fixtures/b.json -> B runs; explain names the file and both hashes.
    let original = w.read("fixtures/b.json");
    w.write("fixtures/b.json", "{ \"greeting\": \"hello, world\" }\n");
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(B),
        "step 2: B must run after its fixture changed"
    );
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(ex.contains("entry:fixtures/b.json"), "{ex}");
    assert!(
        ex.contains(&blake3_of(original.as_bytes())),
        "expected hash missing: {ex}"
    );
    assert!(
        ex.contains(&blake3_of(w.read("fixtures/b.json").as_bytes())),
        "actual hash missing: {ex}"
    );
    w.write("fixtures/b.json", &original);
    assert_eq!(w.plan(&work, "main").skip, set(&[B]), "step 2: restored");

    // Step 3: attest C, edit impl-x.ts (reached only via a computed import) -> C runs.
    w.run(&work, C, &w.trusted);
    assert_eq!(w.plan(&work, "main").skip, set(&[B, C]), "step 3");
    let impl_x = w.read("src/impl-x.ts");
    w.write("src/impl-x.ts", "export const name = \"x\"; // edited\n");
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(C),
        "step 3: C must run after impl-x.ts changed"
    );
    assert!(p.skip.contains(B), "step 3: B unaffected");
    let ex = w.explain(&work, C, "main");
    assert!(ex.contains("entry:src/impl-x.ts"), "{ex}");
    w.write("src/impl-x.ts", &impl_x);
    // A new candidate for the computed import changes the directory listing.
    w.write("src/impl-y.ts", "export const name = \"y\";\n");
    let p = w.plan(&work, "main");
    assert!(p.run.contains(C), "step 3: new impl-y.ts must invalidate C");
    assert!(p.skip.contains(B));
    std::fs::remove_file(work.join("src/impl-y.ts")).unwrap();
    assert_eq!(w.plan(&work, "main").skip, set(&[B, C]), "step 3: restored");

    // Step 4: flip a byte in B's payload -> rejected at the signature check.
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
        "step 4: tampered attestation must not skip B"
    );
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("failed check: signature"), "{ex}");
    let tampered_file = w.base.join("tampered.dsse.json");
    std::fs::write(&tampered_file, &tampered).unwrap();
    let out = w.vci(
        &work,
        &[
            "verify",
            tampered_file.to_str().unwrap(),
            "--base-ref",
            "main",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("INVALID"));
    let good_file = w.base.join("good.dsse.json");
    std::fs::write(&good_file, &good.bytes).unwrap();
    let out = w.vci_ok(
        &work,
        &["verify", good_file.to_str().unwrap(), "--base-ref", "main"],
    );
    assert!(
        out.contains("VALID signature by trusted@example.com"),
        "{out}"
    );
    store
        .put(B, &good.signer, &good.storage_key, &good.bytes)
        .unwrap();
    assert!(w.plan(&work, "main").skip.contains(B), "step 4: restored");

    // Step 5: sign D with a key that is not in allowed_signers -> rejected.
    w.run(&work, D, &w.untrusted);
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(D),
        "step 5: untrusted signer must not skip D"
    );
    let ex = w.explain(&work, D, "main");
    assert!(ex.contains("failed check: signer"), "{ex}");
    assert!(ex.contains("not in allowed_signers"), "{ex}");

    // Step 6: add that key to allowed_signers on the PR branch only -> still rejected.
    let mut signers = w.read(".vci/allowed_signers");
    signers.push_str(&format!(
        "untrusted@example.com namespaces=\"vci-attest\" {}\n",
        pubkey(&w.untrusted)
    ));
    w.write(".vci/allowed_signers", &signers);
    w.git(&work, &["commit", "-q", "-am", "PR: trust my own key"]);
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(D),
        "step 6: key added on the PR branch must not be trusted"
    );
    assert!(w.explain(&work, D, "main").contains("failed check: signer"));
    // Control: with the PR commit as the (wrong) trust root, D would be skipped,
    // so the base-commit trust root is the only thing stopping it.
    assert!(w.plan(&work, "HEAD").skip.contains(D), "step 6 control");

    // Step 7: create a file that B probed as absent (.env) -> B runs.
    w.write(".env", "GREETING=hi\n");
    let p = w.plan(&work, "main");
    assert!(p.run.contains(B), "step 7: new .env must invalidate B");
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("entry:.env"), "{ex}");
    assert!(ex.contains("expected: absent"), "{ex}");
    std::fs::remove_file(work.join(".env")).unwrap();
    assert!(w.plan(&work, "main").skip.contains(B), "step 7: restored");

    // Step 8: edit a file only A depends on -> A runs, B (and C) stay skipped.
    w.run(&work, A, &w.trusted);
    assert_eq!(w.plan(&work, "main").skip, set(&[A, B, C]));
    w.write(
        "src/a.ts",
        "export const add = (x: number, y: number) => y + x;\n",
    );
    let p = w.plan(&work, "main");
    assert!(p.run.contains(A), "step 8: A must run");
    assert!(p.skip.contains(B), "step 8: B must stay skipped");
    assert!(p.skip.contains(C), "step 8: C must stay skipped");

    // Global inputs: a lockfile change invalidates everything.
    w.write(
        "src/a.ts",
        "export const add = (x: number, y: number) => x + y;\n",
    );
    let lock = w.read("package-lock.json");
    w.write("package-lock.json", &format!("{lock}\n"));
    let p = w.plan(&work, "main");
    assert!(
        p.skip.is_empty(),
        "lockfile change must invalidate every attestation: {p:?}"
    );
    assert!(
        w.explain(&work, B, "main")
            .contains("failed check: global-inputs")
    );
    w.write("package-lock.json", &lock);

    // Strict env: a declared variable with a different value invalidates.
    let mut cmd = Command::cargo_bin("vci").unwrap();
    let out = cmd
        .current_dir(&work)
        .args(["plan", "--base-ref", "main", "--format", "json"])
        .env("VCI_JS_PLUGIN", workspace_root().join("js/vitest-plugin"))
        .env("GIT_CONFIG_GLOBAL", &w.gitconfig)
        .env("NODE_ENV", "something-else-entirely")
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let skipped: Vec<&Value> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["skip"].as_bool() == Some(true))
        .collect();
    if std::env::var("NODE_ENV").as_deref() != Ok("something-else-entirely") {
        assert!(skipped.is_empty(), "changed NODE_ENV must invalidate: {v}");
    }
}

#[test]
fn expired_and_foreign_repo_attestations_are_rejected() {
    let w = World::new();
    let work = w.work.clone();

    // Expired.
    w.vci_ok(
        &work,
        &[
            "run",
            A,
            "--key",
            w.trusted.to_str().unwrap(),
            "--ttl",
            "1s",
        ],
    );
    std::thread::sleep(std::time::Duration::from_millis(2500));
    let p = w.plan(&work, "main");
    assert!(p.run.contains(A), "expired attestation must not skip A");
    let ex = w.explain(&work, A, "main");
    assert!(ex.contains("failed check: expiry"), "{ex}");
    assert!(ex.contains("expiresAt"), "{ex}");

    // A TTL above policy is refused up front.
    let out = w.vci(
        &work,
        &[
            "run",
            A,
            "--key",
            w.trusted.to_str().unwrap(),
            "--ttl",
            "60d",
        ],
    );
    assert_eq!(out.status.code(), Some(2));

    // Different repo (different root commit), identical content and signer.
    let other = w.base.join("other");
    w.make_project(&other, "an unrelated root commit");
    assert_ne!(
        w.git(&other, &["rev-list", "--max-parents=0", "HEAD"]),
        w.git(&work, &["rev-list", "--max-parents=0", "HEAD"])
    );
    w.run(&other, B, &w.trusted);
    // Sanity: the attestation is valid in its own repo.
    assert!(w.plan(&other, "main").skip.contains(B));
    let published = w.publish(&other, "other");
    w.vci_ok(&work, &["fetch", "--remote", published.to_str().unwrap()]);
    assert_eq!(
        AttestStore::new(&store_for(&work))
            .list(Some(B))
            .unwrap()
            .len(),
        1,
        "the foreign attestation was fetched"
    );
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(B),
        "attestation from another repo must not skip B"
    );
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("failed check: repo"), "{ex}");
}

#[test]
fn push_fetch_fresh_clone_and_ci() {
    let w = World::new();
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
    w.install_node_modules(&fresh);
    w.git(&fresh, &["checkout", "-q", "feature"]);
    let p = w.plan(&fresh, "main");
    assert!(p.skip.is_empty(), "nothing is attested before fetch");
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    let after = w.plan(&fresh, "main");
    assert_eq!(
        after, before,
        "same plan after push + fetch in a fresh clone"
    );

    // `vci ci` runs only the remainder and writes an audit log of the skips.
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
    // Strict env mode does not pass NO_COLOR through, so strip ANSI codes.
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(stderr.contains("running 2 test file(s)"), "{stderr}");
    assert!(stderr.contains("Test Files  2 passed (2)"), "{stderr}");
    let log: Value = serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
    let skipped: BTreeSet<String> = log["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["testId"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(skipped, set(&[B, C]));
    assert_eq!(log["exitCode"], 0);
    assert!(
        log["skipped"][0]["by"]["principal"]
            .as_str()
            .unwrap()
            .contains("trusted@example.com")
    );

    // Policy: nothing is skipped on refs listed in no_skip_refs.
    w.git(&fresh, &["checkout", "-q", "-b", "release/1"]);
    let p = w.plan(&fresh, "main");
    assert!(p.run_all && p.skip.is_empty(), "{p:?}");

    // Missing policy at the base commit means everything runs.
    let p = w.plan(&fresh, "HEAD~0");
    assert!(p.run_all, "no_skip_refs still applies");
    w.git(&fresh, &["checkout", "-q", "feature"]);
    w.git(&fresh, &["rm", "-q", "vci.toml"]);
    w.git(&fresh, &["commit", "-q", "-m", "drop policy"]);
    let p = w.plan(&fresh, "HEAD");
    assert!(
        p.run_all && p.skip.is_empty(),
        "missing vci.toml at base: {p:?}"
    );
}

#[test]
fn run_refuses_unattestable_test_files() {
    let w = World::new();
    let work = w.work.clone();
    let files: &[(&str, &str)] = &[
        (
            "src/spawn.test.ts",
            "import { expect, test } from 'vitest';\nimport { execFileSync } from 'node:child_process';\n\
             test('spawn', () => { expect(execFileSync(process.execPath, ['-e', 'process.stdout.write(\"1\")']).toString()).toBe('1'); });\n",
        ),
        (
            "src/fail.test.ts",
            "import { expect, test } from 'vitest';\ntest('fails', () => { expect(1).toBe(2); });\n",
        ),
        (
            "src/outside.test.ts",
            "import { expect, test } from 'vitest';\nimport { readFileSync } from 'node:fs';\n\
             test('outside', () => { expect(readFileSync(process.env.VCI_E2E_OUTSIDE ?? '/etc/hosts', 'utf8').length).toBeGreaterThan(0); });\n",
        ),
        (
            "src/mutate.test.ts",
            "import { expect, test } from 'vitest';\nimport { readFileSync, writeFileSync } from 'node:fs';\n\
             test('mutate', () => {\n  const p = new URL('../fixtures/m.txt', import.meta.url);\n  const orig = readFileSync(p, 'utf8');\n\
               writeFileSync(p, 'changed');\n  writeFileSync(p, orig);\n  expect(orig).toBe('m');\n});\n",
        ),
        (
            "src/snap.test.ts",
            "import { expect, test } from 'vitest';\ntest('snap', () => { expect({ a: 1 }).toMatchSnapshot(); });\n",
        ),
    ];
    for (rel, body) in files {
        w.write(rel, body);
    }
    w.write("fixtures/m.txt", "m");
    let outside = w.base.join("outside.txt");
    std::fs::write(&outside, "outside the repository").unwrap();

    let mut args = vec!["run"];
    args.extend(files.iter().map(|(rel, _)| *rel));
    args.extend(["--key", w.trusted.to_str().unwrap()]);
    let mut cmd = Command::cargo_bin("vci").unwrap();
    // VCI_* is built-in pass-through, so the outside path reaches the test.
    let out = cmd
        .current_dir(&work)
        .args(&args)
        .env("VCI_JS_PLUGIN", workspace_root().join("js/vitest-plugin"))
        .env("GIT_CONFIG_GLOBAL", &w.gitconfig)
        .env("VCI_E2E_OUTSIDE", &outside)
        .env_remove("VCI_OUT")
        .output()
        .unwrap();
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    eprintln!("{stderr}");
    assert_ne!(
        out.status.code(),
        Some(0),
        "the failing test makes vitest fail"
    );
    let refused = |id: &str, why: &str| {
        let line = stderr
            .lines()
            .find(|l| l.starts_with(&format!("vci: not attesting {id}:")))
            .unwrap_or_else(|| panic!("{id} was not refused:\n{stderr}"));
        assert!(line.contains(why), "{id}: expected {why:?} in {line:?}");
    };
    refused("src/spawn.test.ts", "tainted: child_process");
    refused("src/fail.test.ts", "result failed");
    refused("src/outside.test.ts", "input outside the repository");
    refused(
        "src/mutate.test.ts",
        "input changed during the run: fixtures/m.txt",
    );
    refused("src/snap.test.ts", "snapshot:written");
    assert!(
        stderr.contains("vci: 0 attested, 5 not attested"),
        "{stderr}"
    );
    let stored = AttestStore::new(&store_for(&work)).list(None).unwrap();
    assert!(stored.is_empty(), "nothing may be stored: {stored:?}");
}

#[test]
fn init_writes_policy_and_trust_root() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let key = base.join("k");
    keygen(&key, "k");
    let st = Command::new("git")
        .args(["init", "-q"])
        .arg(base.join("repo"))
        .status()
        .unwrap();
    assert!(st.success());
    let repo = base.join("repo");
    let out = Command::cargo_bin("vci")
        .unwrap()
        .current_dir(&repo)
        .args(["init", "--key", key.with_extension("pub").to_str().unwrap()])
        .args(["--principal", "dev@example.com", "--no-install"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("vci ci --base-ref"));
    let toml = std::fs::read_to_string(repo.join("vci.toml")).unwrap();
    assert!(toml.contains("platform = \"any\""));
    let signers = std::fs::read_to_string(repo.join(".vci/allowed_signers")).unwrap();
    let parsed = vci_attest::AllowedSigners::parse(&signers).unwrap();
    assert_eq!(parsed.entries().len(), 1);
    assert_eq!(parsed.entries()[0].principals, "dev@example.com");
    assert!(parsed.entries()[0].allows_namespace("vci-attest"));
    assert!(signers.contains(&pubkey(&key)));
}

// ---------------------------------------------------------------------------
// Regressions found by adversarial verification. Each case attests, changes a
// real dependency the collectors used to miss, and requires `vci plan` to RUN
// the file again (or `vci run` to refuse it). Failures are collected so one run
// reports every gap.

/// Soft assertions: collect every failure, report them together.
#[derive(Default)]
struct Checks(Vec<String>);

impl Checks {
    fn check(&mut self, ok: bool, what: impl Into<String>) {
        if !ok {
            let w = what.into();
            eprintln!("CHECK FAILED: {w}");
            self.0.push(w);
        }
    }

    fn finish(self) {
        assert!(
            self.0.is_empty(),
            "{} check(s) failed:\n  {}",
            self.0.len(),
            self.0.join("\n  ")
        );
    }
}

impl World {
    fn vci_env(&self, dir: &Path, args: &[&str], env: &[(&str, Option<&str>)]) -> Output {
        let mut cmd = Command::cargo_bin("vci").unwrap();
        cmd.current_dir(dir)
            .args(args)
            .env("VCI_JS_PLUGIN", workspace_root().join("js/vitest-plugin"))
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("NO_COLOR", "1");
        for k in [
            "VCI_BASE_REF",
            "GITHUB_BASE_REF",
            "GITHUB_REF",
            "GITHUB_OUTPUT",
            "VCI_SIGNING_KEY",
            "VCI_OUT",
            "NODE_OPTIONS",
        ] {
            cmd.env_remove(k);
        }
        for (k, v) in env {
            match v {
                Some(v) => cmd.env(k, v),
                None => cmd.env_remove(k),
            };
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

    fn plan_env(&self, dir: &Path, env: &[(&str, Option<&str>)]) -> Plan {
        let out = self.vci_env(
            dir,
            &["plan", "--base-ref", "main", "--format", "json"],
            env,
        );
        assert!(out.status.success());
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
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

    fn put(&self, rel: &str, content: &str) {
        let p = self.work.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn remove(&self, rel: &str) {
        std::fs::remove_file(self.work.join(rel)).unwrap();
    }

    #[cfg(unix)]
    fn symlink(&self, target: &str, rel: &str) {
        let p = self.work.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let _ = std::fs::remove_file(&p);
        std::os::unix::fs::symlink(target, p).unwrap();
    }

    /// Apply `mutate`, require every id in `ids` to RUN, then `restore` and
    /// require them to SKIP again.
    fn expect_rerun(
        &self,
        c: &mut Checks,
        what: &str,
        ids: &[&str],
        env: &[(&str, Option<&str>)],
        mutate: impl FnOnce(&World),
        restore: impl FnOnce(&World),
    ) {
        mutate(self);
        let p = self.plan_env(&self.work, env);
        for id in ids {
            c.check(
                p.run.contains(*id),
                format!("{what}: {id} must RUN, plan {p:?}"),
            );
        }
        restore(self);
        let p = self.plan_env(&self.work, env);
        for id in ids {
            c.check(
                p.skip.contains(*id),
                format!("{what} (restored): {id} must SKIP again, plan {p:?}"),
            );
        }
    }
}

fn make_sqlite_db(path: &Path, value: &str) {
    let _ = std::fs::remove_file(path);
    let st = Command::new("node")
        .args([
            "-e",
            "const { DatabaseSync } = require('node:sqlite'); const db = new DatabaseSync(process.argv[1]); db.exec(\"create table t (v text)\"); db.prepare('insert into t values (?)').run(process.argv[2]); db.close();",
        ])
        .arg(path)
        .arg(value)
        .status()
        .unwrap();
    assert!(st.success());
}

#[cfg(unix)]
#[test]
fn collector_gaps_found_by_adversarial_verification_run_again() {
    let w = World::new();
    let work = w.work.clone();
    let files: &[(&str, &str)] = &[
        // Symlinked source module.
        ("shared/real-a.ts", "export const v = 'A';\n"),
        ("shared/real-b.ts", "export const v = 'B';\n"),
        (
            "src/atk/symlink.test.ts",
            "import { expect, test } from 'vitest';\nimport { v } from './link';\ntest('s', () => { expect(v).toBe('A'); });\n",
        ),
        // Higher-priority resolution candidates.
        ("src/atk/ext.ts", "export const kind = 'ts';\n"),
        ("src/atk/dirmod/index.ts", "export const kind = 'index';\n"),
        (
            "src/atk/resolve.test.ts",
            "import { expect, test } from 'vitest';\nimport { kind as e } from './ext';\nimport { kind as d } from './dirmod';\n\
             test('r', () => { expect(e).toBe('ts'); expect(d).toBe('index'); });\n",
        ),
        // package.json `imports` of a nested package.
        (
            "src/atk/pkgimp/package.json",
            "{ \"imports\": { \"#dep\": \"./dep-a.ts\" } }\n",
        ),
        ("src/atk/pkgimp/dep-a.ts", "export default 'a';\n"),
        ("src/atk/pkgimp/dep-b.ts", "export default 'b';\n"),
        (
            "src/atk/pkgimp/imp.test.ts",
            "import { expect, test } from 'vitest';\nimport dep from '#dep';\ntest('i', () => { expect(dep).toBe('a'); });\n",
        ),
        // Workspace package reached through a node_modules symlink.
        (
            "packages/lib/package.json",
            "{ \"name\": \"@me/lib\", \"version\": \"1.0.0\", \"type\": \"module\", \"main\": \"./a.js\" }\n",
        ),
        ("packages/lib/a.js", "export default 'a';\n"),
        ("packages/lib/b.js", "export default 'b';\n"),
        (
            "src/atk/ws.test.ts",
            "import { expect, test } from 'vitest';\nimport lib from '@me/lib';\ntest('w', () => { expect(lib).toBe('a'); });\n",
        ),
        // Nested tsconfig, and a root tsconfig extending a workspace package.
        (
            "src/atk/tsc/tsconfig.json",
            "{ \"compilerOptions\": { \"useDefineForClassFields\": true } }\n",
        ),
        ("src/atk/tsc/cls.ts", "export class A { x?: number }\n"),
        (
            "src/atk/tsc.test.ts",
            "import { expect, test } from 'vitest';\nimport { A } from './tsc/cls';\ntest('t', () => { expect(Object.hasOwn(new A(), 'x')).toBe(true); });\n",
        ),
        (
            "tsconfig.json",
            "{ \"extends\": \"@me/tsconfig/base.json\" }\n",
        ),
        (
            "packages/tsconfig/package.json",
            "{ \"name\": \"@me/tsconfig\", \"version\": \"1.0.0\" }\n",
        ),
        (
            "packages/tsconfig/base.json",
            "{ \"compilerOptions\": { \"strict\": true } }\n",
        ),
        // toMatchFileSnapshot.
        ("src/atk/__file_snapshots__/out.txt", "hello\n"),
        (
            "src/atk/filesnap.test.ts",
            "import { expect, test } from 'vitest';\ntest('f', async () => { await expect('hello\\n').toMatchFileSnapshot('./__file_snapshots__/out.txt'); });\n",
        ),
        // Fixtures copied / linked into a temp dir, openAsBlob, promises cp.
        ("data/proj/cfg.txt", "c1"),
        ("data/sl.txt", "sl"),
        ("data/hl.txt", "hl"),
        ("data/blob.txt", "b1"),
        ("data/p3.txt", "p3"),
        (
            "src/atk/tmpcopy.test.ts",
            "import { expect, test } from 'vitest';\nimport fs from 'node:fs';\nimport { tmpdir } from 'node:os';\nimport path from 'node:path';\n\
             const data = (p: string) => path.join(process.cwd(), 'data', p);\n\
             test('cp', () => { const t = fs.mkdtempSync(path.join(tmpdir(), 'a-')); fs.cpSync(data('proj'), path.join(t, 'proj'), { recursive: true }); expect(fs.readFileSync(path.join(t, 'proj', 'cfg.txt'), 'utf8')).toBe('c1'); });\n\
             test('sl', () => { const t = fs.mkdtempSync(path.join(tmpdir(), 'a-')); fs.symlinkSync(data('sl.txt'), path.join(t, 'x')); expect(fs.readFileSync(path.join(t, 'x'), 'utf8')).toBe('sl'); });\n\
             test('blob', async () => { expect(await (await fs.openAsBlob(data('blob.txt'))).text()).toBe('b1'); });\n",
        ),
        // A hard link changes the source's inode (link count, ctime): the
        // source is an input now, so the file is refused (fail open).
        (
            "src/atk/hardlink.test.ts",
            "import { expect, test } from 'vitest';\nimport fs from 'node:fs';\nimport { tmpdir } from 'node:os';\nimport path from 'node:path';\n\
             test('hl', () => { const t = fs.mkdtempSync(path.join(tmpdir(), 'a-')); fs.linkSync(path.join(process.cwd(), 'data', 'hl.txt'), path.join(t, 'x')); expect(fs.readFileSync(path.join(t, 'x'), 'utf8')).toBe('hl'); });\n",
        ),
        (
            "src/atk/promcp.test.ts",
            "import { expect, test } from 'vitest';\nimport { cp, mkdtemp, readFile } from 'node:fs/promises';\nimport { tmpdir } from 'node:os';\nimport path from 'node:path';\n\
             test('p', async () => { const d = await mkdtemp(path.join(tmpdir(), 't3-')); await cp(path.join(process.cwd(), 'data', 'p3.txt'), path.join(d, 'x.txt')); expect(await readFile(path.join(d, 'x.txt'), 'utf8')).toBe('p3'); });\n",
        ),
        // Native reads.
        ("data/app.env", "APP_MODE=alpha\n"),
        (
            "src/atk/native.test.ts",
            "import { expect, test } from 'vitest';\nimport path from 'node:path';\nimport { createRequire } from 'node:module';\n\
             test('env file', () => { process.loadEnvFile(path.join(process.cwd(), 'data', 'app.env')); expect(process.env.APP_MODE).toBe('alpha'); });\n\
             test('sqlite', () => { const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite'); const db = new DatabaseSync(path.join(process.cwd(), 'data', 't.db'), { readOnly: true }); expect(db.prepare('select v from t').get().v).toBe('one'); db.close(); });\n",
        ),
        // statSync(p, { throwIfNoEntry: false }) on a missing file.
        (
            "src/atk/exists.test.ts",
            "import { expect, test } from 'vitest';\nimport fs from 'node:fs';\nimport path from 'node:path';\n\
             test('e', () => { expect(fs.statSync(path.join(process.cwd(), 'data', 'maybe3.txt'), { throwIfNoEntry: false })).toBeUndefined(); });\n",
        ),
        // Sockets created with the constructor.
        (
            "src/atk/sock.test.ts",
            "import { expect, test } from 'vitest';\nimport net from 'node:net';\n\
             test('s', async () => { const s = new net.Socket(); const r = await new Promise((res) => { s.once('connect', () => { s.destroy(); res('c'); }); s.once('error', () => res('e')); s.connect(1, '127.0.0.1'); }); expect(r).toMatch(/c|e/); });\n",
        ),
    ];
    for (rel, body) in files {
        w.put(rel, body);
    }
    w.symlink("../../shared/real-a.ts", "src/atk/link.ts");
    w.symlink("../../packages/lib", "node_modules/@me/lib");
    w.symlink("../../packages/tsconfig", "node_modules/@me/tsconfig");
    make_sqlite_db(&work.join("data/t.db"), "one");

    let out = w.vci(&work, &["run", "--key", w.trusted.to_str().unwrap()]);
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    let mut c = Checks::default();
    c.check(
        out.status.code() == Some(0),
        format!("vci run must pass: {stderr}"),
    );
    let sock_line = stderr
        .lines()
        .find(|l| l.starts_with("vci: not attesting src/atk/sock.test.ts:"));
    c.check(
        sock_line.is_some_and(|l| l.contains("tainted: net.Socket")),
        format!("new net.Socket().connect must taint: {sock_line:?}"),
    );

    let hl_line = stderr
        .lines()
        .find(|l| l.starts_with("vci: not attesting src/atk/hardlink.test.ts:"));
    c.check(
        hl_line.is_some_and(|l| l.contains("input changed during the run: data/hl.txt")),
        format!("a hard-linked source must be refused: {hl_line:?}"),
    );
    let attested = [
        "src/atk/symlink.test.ts",
        "src/atk/resolve.test.ts",
        "src/atk/pkgimp/imp.test.ts",
        "src/atk/ws.test.ts",
        "src/atk/tsc.test.ts",
        "src/atk/filesnap.test.ts",
        "src/atk/tmpcopy.test.ts",
        "src/atk/promcp.test.ts",
        "src/atk/native.test.ts",
        "src/atk/exists.test.ts",
        A,
        B,
    ];
    let p = w.plan(&work, "main");
    for id in attested {
        c.check(
            p.skip.contains(id),
            format!("{id} must be attested and SKIP: {p:?}"),
        );
    }
    c.check(p.run.contains("src/atk/sock.test.ts"), "sock must RUN");
    c.check(
        p.run.contains("src/atk/hardlink.test.ts"),
        "hardlink must RUN",
    );

    let none: &[(&str, Option<&str>)] = &[];
    w.expect_rerun(
        &mut c,
        "retarget symlinked module",
        &["src/atk/symlink.test.ts"],
        none,
        |w| w.symlink("../../shared/real-b.ts", "src/atk/link.ts"),
        |w| w.symlink("../../shared/real-a.ts", "src/atk/link.ts"),
    );
    w.expect_rerun(
        &mut c,
        "create ext.js beside ext.ts",
        &["src/atk/resolve.test.ts"],
        none,
        |w| w.put("src/atk/ext.js", "export const kind = 'js';\n"),
        |w| w.remove("src/atk/ext.js"),
    );
    w.expect_rerun(
        &mut c,
        "create dirmod.ts beside dirmod/index.ts",
        &["src/atk/resolve.test.ts"],
        none,
        |w| w.put("src/atk/dirmod.ts", "export const kind = 'file';\n"),
        |w| w.remove("src/atk/dirmod.ts"),
    );
    w.expect_rerun(
        &mut c,
        "package.json imports mapping",
        &["src/atk/pkgimp/imp.test.ts"],
        none,
        |w| {
            w.put(
                "src/atk/pkgimp/package.json",
                "{ \"imports\": { \"#dep\": \"./dep-b.ts\" } }\n",
            )
        },
        |w| {
            w.put(
                "src/atk/pkgimp/package.json",
                "{ \"imports\": { \"#dep\": \"./dep-a.ts\" } }\n",
            )
        },
    );
    let lib_pj = w.read("packages/lib/package.json");
    w.expect_rerun(
        &mut c,
        "workspace package main",
        &["src/atk/ws.test.ts"],
        none,
        |w| {
            w.put(
                "packages/lib/package.json",
                &lib_pj.replace("./a.js", "./b.js"),
            )
        },
        |w| w.put("packages/lib/package.json", &lib_pj),
    );
    w.expect_rerun(
        &mut c,
        "nested tsconfig",
        &["src/atk/tsc.test.ts"],
        none,
        |w| {
            w.put(
                "src/atk/tsc/tsconfig.json",
                "{ \"compilerOptions\": { \"useDefineForClassFields\": false } }\n",
            )
        },
        |w| {
            w.put(
                "src/atk/tsc/tsconfig.json",
                "{ \"compilerOptions\": { \"useDefineForClassFields\": true } }\n",
            )
        },
    );
    w.expect_rerun(
        &mut c,
        "toMatchFileSnapshot file",
        &["src/atk/filesnap.test.ts"],
        none,
        |w| w.put("src/atk/__file_snapshots__/out.txt", "HELLO\n"),
        |w| w.put("src/atk/__file_snapshots__/out.txt", "hello\n"),
    );
    for (rel, orig) in [
        ("data/proj/cfg.txt", "c1"),
        ("data/sl.txt", "sl"),
        ("data/blob.txt", "b1"),
    ] {
        w.expect_rerun(
            &mut c,
            &format!("edit {rel}"),
            &["src/atk/tmpcopy.test.ts"],
            none,
            |w| w.put(rel, "changed"),
            |w| w.put(rel, orig),
        );
    }
    w.expect_rerun(
        &mut c,
        "promises cp source",
        &["src/atk/promcp.test.ts"],
        none,
        |w| w.put("data/p3.txt", "changed"),
        |w| w.put("data/p3.txt", "p3"),
    );
    w.expect_rerun(
        &mut c,
        "loadEnvFile file",
        &["src/atk/native.test.ts"],
        none,
        |w| w.put("data/app.env", "APP_MODE=beta\n"),
        |w| w.put("data/app.env", "APP_MODE=alpha\n"),
    );
    let db = std::fs::read(work.join("data/t.db")).unwrap();
    w.expect_rerun(
        &mut c,
        "sqlite database",
        &["src/atk/native.test.ts"],
        none,
        |w| make_sqlite_db(&w.work.join("data/t.db"), "two"),
        |w| std::fs::write(w.work.join("data/t.db"), &db).unwrap(),
    );
    w.expect_rerun(
        &mut c,
        "create a file stat'ed with throwIfNoEntry: false",
        &["src/atk/exists.test.ts"],
        none,
        |w| w.put("data/maybe3.txt", "now here"),
        |w| w.remove("data/maybe3.txt"),
    );
    w.expect_rerun(
        &mut c,
        "tsconfig extended through a workspace package",
        &[A, B],
        none,
        |w| {
            w.put(
                "packages/tsconfig/base.json",
                "{ \"compilerOptions\": { \"strict\": false } }\n",
            )
        },
        |w| {
            w.put(
                "packages/tsconfig/base.json",
                "{ \"compilerOptions\": { \"strict\": true } }\n",
            )
        },
    );
    c.finish();
}

const MAIN_PROCESS_CONFIG: &str = r#"import { defineConfig } from "vitest/config";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const here = path.dirname(fileURLToPath(import.meta.url));
export default defineConfig({
  define: { __FLAG__: JSON.stringify(process.env.ATK_FLAG || "off") },
  resolve: { alias: { "@p": path.join(process.cwd(), "src", "w", "plug") } },
  plugins: [{
    name: "virtual-data",
    resolveId(id) { return id === "virtual:data" ? "\0virtual:data" : null; },
    load(id) {
      if (id !== "\0virtual:data") return null;
      return "export default " + JSON.stringify(readFileSync(path.join(here, "data", "virt.txt"), "utf8"));
    },
  }],
  test: {
    include: ["src/**/*.test.ts"],
    globalSetup: [path.join(process.cwd(), "tools", "gsetup.ts")],
    resolveSnapshotPath: (testPath, ext) => path.join(process.cwd(), "snaps", path.basename(testPath) + ext),
  },
});
"#;

const SNAPR: &str = "// Vitest Snapshot v1, https://vitest.dev/guide/snapshot.html\n\nexports[`custom snapshot path 1`] = `\n{\n  \"a\": 1,\n}\n`;\n";

#[test]
fn main_process_inputs_and_loose_env_run_again() {
    let toml = VCI_TOML.replace("mode = \"strict\"", "mode = \"loose\"");
    let w = World::new_with(
        &[
            ("vitest.config.ts", MAIN_PROCESS_CONFIG),
            ("data/g.txt", "g1"),
            ("data/virt.txt", "v1"),
            (
                "tools/gsetup.ts",
                "import { readFileSync } from 'node:fs';\nimport path from 'node:path';\n\
                 export default function ({ provide }: any) { provide('g', readFileSync(path.join(process.cwd(), 'data', 'g.txt'), 'utf8')); }\n",
            ),
            (
                "src/main/m.test.ts",
                "import { expect, inject, test } from 'vitest';\nimport virt from 'virtual:data';\ndeclare const __FLAG__: string;\n\
                 test('m', () => { expect(inject('g' as never)).toBe('g1'); expect(virt).toBe('v1'); expect(__FLAG__).toBe('off'); });\n",
            ),
            ("src/w/plug/one.ts", "export default 'one';\n"),
            (
                "src/w/alias.test.ts",
                "import { expect, test } from 'vitest';\n\
                 test('a', async () => { const n = ['la', 'te'].join(''); let got = 'none'; try { got = (await import(`@p/${n}.ts`)).default; } catch {} expect(got).toBe('none'); });\n",
            ),
            (
                "src/w/snapr.test.ts",
                "import { expect, test } from 'vitest';\ntest('custom snapshot path', () => { expect({ a: 1 }).toMatchSnapshot(); });\n",
            ),
            ("snaps/snapr.test.ts.snap", SNAPR),
            (
                "src/w/tz.test.ts",
                "import { expect, test } from 'vitest';\ntest('tz', () => { expect(new Date(0).getHours()).toBe(new Date(0).getUTCHours()); });\n",
            ),
        ],
        &toml,
    );
    let work = w.work.clone();
    let utc: &[(&str, Option<&str>)] = &[("TZ", Some("UTC")), ("ATK_FLAG", None)];
    let out = w.vci_env(&work, &["run", "--key", w.trusted.to_str().unwrap()], utc);
    let mut c = Checks::default();
    c.check(out.status.code() == Some(0), "vci run must pass");
    let ids = [
        "src/main/m.test.ts",
        "src/w/alias.test.ts",
        "src/w/snapr.test.ts",
        "src/w/tz.test.ts",
    ];
    let p = w.plan_env(&work, utc);
    for id in ids {
        c.check(
            p.skip.contains(id),
            format!("{id} must be attested and SKIP: {p:?}"),
        );
    }
    let m = &["src/main/m.test.ts"];
    w.expect_rerun(
        &mut c,
        "file read by globalSetup",
        m,
        utc,
        |w| w.put("data/g.txt", "g2"),
        |w| w.put("data/g.txt", "g1"),
    );
    let gsetup = w.read("tools/gsetup.ts");
    w.expect_rerun(
        &mut c,
        "globalSetup file named by a computed path",
        m,
        utc,
        |w| {
            w.put(
                "tools/gsetup.ts",
                &gsetup.replace(
                    "provide('g', readFileSync",
                    "provide('g', 'x' + readFileSync",
                ),
            )
        },
        |w| w.put("tools/gsetup.ts", &gsetup),
    );
    w.expect_rerun(
        &mut c,
        "file read by a config plugin",
        m,
        utc,
        |w| w.put("data/virt.txt", "v2"),
        |w| w.put("data/virt.txt", "v1"),
    );
    let p = w.plan_env(&work, &[("TZ", Some("UTC")), ("ATK_FLAG", Some("on"))]);
    c.check(
        p.run.contains("src/main/m.test.ts"),
        format!("env read by the config (loose): m must RUN: {p:?}"),
    );
    w.expect_rerun(
        &mut c,
        "create the target of an aliased template import",
        &["src/w/alias.test.ts"],
        utc,
        |w| w.put("src/w/plug/late.ts", "export default 'late';\n"),
        |w| w.remove("src/w/plug/late.ts"),
    );
    w.expect_rerun(
        &mut c,
        "snapshot at a custom resolveSnapshotPath",
        &["src/w/snapr.test.ts"],
        utc,
        |w| {
            w.put(
                "snaps/snapr.test.ts.snap",
                &SNAPR.replace("\"a\": 1", "\"a\": 2"),
            )
        },
        |w| w.put("snaps/snapr.test.ts.snap", SNAPR),
    );
    let p = w.plan_env(&work, &[("TZ", None), ("ATK_FLAG", None)]);
    c.check(
        p.run.contains("src/w/tz.test.ts"),
        format!("TZ unset (loose): tz must RUN: {p:?}"),
    );
    c.finish();
}

#[test]
fn explain_shows_attested_as_expected_and_checkout_as_actual() {
    let w = World::new();
    let work = w.work.clone();
    let mut c = Checks::default();

    // Inputs: expected = attested content, actual = checkout.
    w.run(&work, B, &w.trusted);
    let original = w.read("fixtures/b.json");
    w.write("fixtures/b.json", "{ \"greeting\": \"changed\" }\n");
    let ex = w.explain(&work, B, "main");
    let line = |ex: &str, label: &str| {
        ex.lines()
            .find(|l| l.trim_start().starts_with(label))
            .unwrap_or_default()
            .to_owned()
    };
    c.check(
        line(&ex, "expected:").contains(&blake3_of(original.as_bytes())),
        format!("inputs: expected must be the attested hash: {ex}"),
    );
    c.check(
        line(&ex, "actual:").contains(&blake3_of(w.read("fixtures/b.json").as_bytes())),
        format!("inputs: actual must be the checkout hash: {ex}"),
    );
    w.write("fixtures/b.json", &original);

    // Repo: expected = the attestation's repo id, actual = this repo's.
    let other = w.base.join("other");
    w.make_project(&other, "an unrelated root commit");
    w.run(&other, C, &w.trusted);
    let published = w.publish(&other, "other");
    w.vci_ok(&work, &["fetch", "--remote", published.to_str().unwrap()]);
    let ex = w.explain(&work, C, "main");
    let other_root = w.git(&other, &["rev-list", "--max-parents=0", "HEAD"]);
    let work_root = w.git(&work, &["rev-list", "--max-parents=0", "HEAD"]);
    c.check(ex.contains("failed check: repo"), ex.clone());
    c.check(
        line(&ex, "expected:").contains(&other_root),
        format!("repo: expected must be the attested repo id {other_root}: {ex}"),
    );
    c.check(
        line(&ex, "actual:").contains(&work_root),
        format!("repo: actual must be this repo's id {work_root}: {ex}"),
    );
    c.finish();
}

#[test]
fn plan_warns_when_the_base_is_the_commit_under_test() {
    let w = World::new();
    let work = w.work.clone();
    // A pull request commit (e.g. one that adds its author's key).
    w.write("src/pr.ts", "export const pr = 1;\n");
    w.git(&work, &["add", "-A"]);
    w.git(&work, &["commit", "-q", "-m", "PR commit"]);
    let warned = |base: &str| {
        let out = w.vci(&work, &["plan", "--base-ref", base]);
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stderr).contains("warning: the base commit")
    };
    assert!(warned("HEAD"), "--base-ref HEAD must warn");
    assert!(!warned("main"), "a real base must not warn");
}

// ---------------------------------------------------------------------------
// The git-meta store holds hints only: whatever ends up under a unit's keys
// (garbage, another unit's envelope, a tombstone), the unit runs unless a
// valid envelope for exactly this unit is there; and a valid envelope counts
// however it got there.

/// The `git-meta` CLI, when installed (`$VCI_TEST_GIT_META` or on PATH).
fn git_meta_bin() -> Option<String> {
    let bin = std::env::var("VCI_TEST_GIT_META")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "git-meta".to_owned());
    Command::new(&bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        .then_some(bin)
}

#[test]
fn git_meta_values_are_hints_only() {
    let w = World::new();
    let work = w.work.clone();
    w.run(&work, B, &w.trusted);
    w.run(&work, C, &w.trusted);
    assert_eq!(w.plan(&work, "main").skip, set(&[B, C]));
    let repo = store_for(&work);
    let store = AttestStore::new(&repo);
    let b = store.list(Some(B)).unwrap().remove(0);
    let c = store.list(Some(C)).unwrap().remove(0);
    assert_eq!(b.target, format!("path:{B}"));

    // Overwritten with garbage: B runs.
    store
        .put(B, &b.signer, &b.storage_key, b"{\"not\":\"an envelope\"}")
        .unwrap();
    let p = w.plan(&work, "main");
    assert!(p.run.contains(B) && p.skip.contains(C), "{p:?}");
    assert!(
        w.explain(&work, B, "main")
            .contains("failed check: envelope")
    );
    // Overwritten with another unit's valid envelope: B runs.
    store.put(B, &b.signer, &b.storage_key, &c.bytes).unwrap();
    let p = w.plan(&work, "main");
    assert!(p.run.contains(B) && p.skip.contains(C), "{p:?}");
    assert!(
        w.explain(&work, B, "main")
            .contains("failed check: test-id")
    );
    store.put(B, &b.signer, &b.storage_key, &b.bytes).unwrap();
    assert_eq!(w.plan(&work, "main").skip, set(&[B, C]), "restored");

    // Published, then fetched into a fresh clone: same plan.
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push"]);
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
    w.install_node_modules(&fresh);
    w.git(&fresh, &["checkout", "-q", "feature"]);
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    assert_eq!(w.plan(&fresh, "main").skip, set(&[B, C]));

    // Tombstoned by another user (here: a deletion in the first clone,
    // pushed): B runs everywhere once fetched; C is untouched.
    assert!(store.remove(&b).unwrap());
    let p = w.plan(&work, "main");
    assert!(p.run.contains(B) && p.skip.contains(C), "{p:?}");
    w.vci_ok(&work, &["push"]);
    w.vci_ok(&fresh, &["fetch"]);
    let p = w.plan(&fresh, "main");
    assert!(p.run.contains(B) && p.skip.contains(C), "{p:?}");
    let ex = w.explain(&fresh, B, "main");
    assert!(ex.contains("no attestation"), "{ex}");

    // A valid envelope written by hand with git-meta itself, under a key vci
    // never wrote (another storage key): accepted.
    let tk = vci_core::test_key(B);
    let key = format!("vci:attestation:{tk}:{}:{}", b.signer, "ab".repeat(32));
    let envelope = String::from_utf8(b.bytes.clone()).unwrap();
    let session = git_meta_lib::Session::open(&work).unwrap();
    session
        .target(&git_meta_lib::Target::path(B))
        .set(&key, envelope.as_str())
        .unwrap();
    drop(session);
    assert_eq!(w.plan(&work, "main").skip, set(&[B, C]), "library-written");

    // The same with the stock CLI in the fresh clone, when it is installed.
    match git_meta_bin() {
        None => eprintln!("skipping the git meta CLI part: not installed"),
        Some(bin) => {
            let key = format!("vci:attestation:{tk}:{}:{}", b.signer, "cd".repeat(32));
            let out = Command::new(&bin)
                .current_dir(&fresh)
                .args(["set", &format!("path:{B}"), &key, &envelope])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(w.plan(&fresh, "main").skip, set(&[B, C]), "git meta set");
            // And `git meta rm` (a tombstone) makes it run again.
            let out = Command::new(&bin)
                .current_dir(&fresh)
                .args(["rm", &format!("path:{B}"), &key])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(w.plan(&fresh, "main").run.contains(B), "git meta rm");
        }
    }
}

#[test]
fn prune_removes_expired_attestations() {
    let w = World::new();
    let work = w.work.clone();
    let key = w.trusted.to_str().unwrap();
    w.vci_ok(&work, &["run", A, "--key", key, "--ttl", "1s"]);
    w.run(&work, B, &w.trusted);
    std::thread::sleep(std::time::Duration::from_millis(2500));
    let store_repo = store_for(&work);
    let store = AttestStore::new(&store_repo);
    assert_eq!(store.list(None).unwrap().len(), 2);
    let dry = w.vci_ok(&work, &["prune", "--dry-run"]);
    assert!(dry.contains("would remove path:src/a.test.ts"), "{dry}");
    assert_eq!(
        store.list(None).unwrap().len(),
        2,
        "dry run removes nothing"
    );
    let out = w.vci_ok(&work, &["prune"]);
    assert!(out.contains("removed path:src/a.test.ts"), "{out}");
    let left = store.list(None).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].target, format!("path:{B}"));
    assert!(w.plan(&work, "main").skip.contains(B));
    // The deletion is published by push.
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    let tree = w.git(
        &w.remote,
        &["ls-tree", "-r", "--name-only", "refs/meta/main"],
    );
    assert!(
        !tree.contains("path/src/a.test.ts/__target__/vci"),
        "{tree}"
    );
    assert!(
        tree.contains("path/src/a.test.ts/__target__/__tombstones/vci"),
        "{tree}"
    );
    assert!(
        tree.contains("path/src/b.test.ts/__target__/vci/attestation"),
        "{tree}"
    );
}

#[test]
fn init_configures_git_meta() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let repo = base.join("repo");
    let git = |args: &[&str]| {
        let st = Command::new("git")
            .current_dir(&base)
            .args(args)
            .status()
            .unwrap();
        assert!(st.success());
    };
    git(&["init", "-q", "--bare", "remote.git"]);
    git(&["init", "-q", "repo"]);
    git(&[
        "-C",
        "repo",
        "remote",
        "add",
        "origin",
        base.join("remote.git").to_str().unwrap(),
    ]);
    let out = Command::cargo_bin("vci")
        .unwrap()
        .current_dir(&repo)
        .args(["init", "--no-install", "--adapter", "pytest"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains(".git-meta"));
    let file = std::fs::read_to_string(repo.join(".git-meta")).unwrap();
    assert_eq!(
        file,
        format!("url: {}\n", base.join("remote.git").display())
    );
    let cfg = |k: &str| {
        let o = Command::new("git")
            .current_dir(&repo)
            .args(["config", "--get", k])
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_owned()
    };
    assert_eq!(cfg("remote.meta.meta"), "true");
    assert_eq!(
        cfg("remote.meta.url"),
        base.join("remote.git").to_str().unwrap()
    );
    assert_eq!(
        cfg("remote.meta.fetch"),
        "+refs/meta/main:refs/meta/remotes/main"
    );
}

// ---------------------------------------------------------------------------
// Regression tests for adversarial findings against the git-meta exchange.

impl World {
    fn fresh_clone(&self, name: &str) -> PathBuf {
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
        self.git(&dir, &["checkout", "-q", "feature"]);
        dir
    }

    fn stderr_of(&self, dir: &Path, args: &[&str]) -> String {
        let out = self.vci(dir, args);
        assert!(
            out.status.success(),
            "vci {args:?} exited {:?}",
            out.status.code()
        );
        String::from_utf8_lossy(&out.stderr).into_owned()
    }
}

/// A linked worktree, or a clone whose `.git/git-meta.sqlite` was deleted,
/// starts with a store that does not hold what the shared
/// `refs/meta/local/main` holds. Fetching sees the published attestations,
/// and attesting and pushing from there never deletes them for everyone.
#[test]
fn worktrees_and_lost_stores_keep_published_attestations() {
    let w = World::new();
    let work = w.work.clone();
    for f in [B, C, D] {
        w.run(&work, f, &w.trusted);
    }
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push", "--remote", "origin"]);

    let wt = w.base.join("wt2");
    w.git(
        &work,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "wt-branch",
            wt.to_str().unwrap(),
        ],
    );
    w.install_node_modules(&wt);
    let err = w.stderr_of(&wt, &["fetch"]);
    assert!(err.contains("(3 attestations stored locally)"), "{err}");
    assert_eq!(w.plan(&wt, "main").skip, set(&[B, C, D]));
    w.run(&wt, A, &w.trusted);
    let err = w.stderr_of(&wt, &["push"]);
    assert!(err.contains("vci: pushed"), "{err}");

    let fresh = w.fresh_clone("fresh");
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    assert_eq!(w.plan(&fresh, "main").skip, set(&[A, B, C, D]));

    // The main worktree's store is deleted; `vci run` makes a new one and
    // `vci push` publishes it without deleting anything.
    for s in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(work.join(format!(".git/git-meta.sqlite{s}")));
    }
    w.run(&work, A, &w.trusted);
    w.vci_ok(&work, &["push"]);
    w.vci_ok(&fresh, &["fetch"]);
    assert_eq!(w.plan(&fresh, "main").skip, set(&[A, B, C, D]));
    assert_eq!(w.plan(&work, "main").skip, set(&[A, B, C, D]));
}

/// One value whose blob is missing makes only its own unit run, and `vci
/// plan` reads the store from a read-only `.git`.
#[test]
fn an_unreadable_value_runs_only_its_unit_and_plan_reads_a_read_only_git_dir() {
    let w = World::new();
    let work = w.work.clone();
    w.run(&work, B, &w.trusted);
    w.run(&work, C, &w.trusted);
    w.git(&work, &["push", "-q", "origin", "feature"]);
    w.vci_ok(&work, &["push", "--remote", "origin"]);
    let fresh = w.fresh_clone("fresh");
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    assert_eq!(w.plan(&fresh, "main").skip, set(&[B, C]));

    // Values over 1 KiB are blob references in a fetched store. Keep C's
    // blob, lose B's.
    let tree = w.git(&fresh, &["ls-tree", "-r", "refs/meta/remotes/main"]);
    let blob_for = |unit: &str| {
        tree.lines()
            .find(|l| l.contains(&format!("path/{unit}/__target__/")))
            .and_then(|l| l.split_whitespace().nth(2))
            .unwrap()
            .to_owned()
    };
    let c_blob = blob_for(C);
    let _ = blob_for(B);
    for r in w
        .git(
            &fresh,
            &["for-each-ref", "--format=%(refname)", "refs/meta"],
        )
        .lines()
    {
        w.git(&fresh, &["update-ref", "-d", r]);
    }
    w.git(&fresh, &["update-ref", "refs/keep/c", &c_blob]);
    w.git(&fresh, &["reflog", "expire", "--expire=now", "--all"]);
    w.git(&fresh, &["gc", "-q", "--prune=now"]);
    let out = w.vci(&fresh, &["plan", "--base-ref", "main"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("running everything"), "{err}");
    let p = w.plan(&fresh, "main");
    assert_eq!(p.skip, set(&[C]), "{p:?}");
    assert!(!p.run_all);
    let ex = w.explain(&fresh, B, "main");
    assert!(ex.contains("unreadable") && ex.contains("missing"), "{ex}");

    // A read-only .git (and a lock file left behind) do not stop `vci plan`.
    let chmod = |mode: &str| {
        let st = Command::new("chmod")
            .args(["-R", mode])
            .arg(fresh.join(".git"))
            .status()
            .unwrap();
        assert!(st.success());
    };
    chmod("a-w");
    let out = w.vci(&fresh, &["plan", "--base-ref", "main", "--format", "json"]);
    chmod("u+w");
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["runAll"].is_null(), "{v}");
    let skipped: Vec<&str> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["skip"].as_bool().unwrap())
        .map(|f| f["testId"].as_str().unwrap())
        .collect();
    assert_eq!(skipped, [C]);
}

/// `vci push` says when nothing was sent; a `.git-meta` URL that names a
/// remote helper (`fd::`, `ext::`) is refused instead of used.
#[test]
fn push_reports_no_ops_and_fetch_refuses_remote_helper_urls() {
    let w = World::new();
    let work = w.work.clone();
    let err = w.stderr_of(&work, &["push", "--remote", "origin"]);
    assert!(err.contains("nothing to push: no attestations"), "{err}");
    w.run(&work, B, &w.trusted);
    let err = w.stderr_of(&work, &["push"]);
    assert!(err.contains("vci: pushed"), "{err}");
    let err = w.stderr_of(&work, &["push"]);
    assert!(
        err.contains("nothing to push") && !err.contains("vci: pushed"),
        "{err}"
    );

    // A pull request sets `.git-meta` to read a file descriptor.
    std::fs::write(work.join(".git-meta"), "url: fd::3\n").unwrap();
    w.git(&work, &["add", ".git-meta"]);
    w.git(&work, &["commit", "-q", "-m", "metadata elsewhere"]);
    w.git(&work, &["push", "-q", "origin", "feature"]);
    let fresh = w.fresh_clone("fresh");
    let out = w.vci(&fresh, &["fetch"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("remote helpers"), "{err}");
    // `--remote origin` (what the action runs) ignores the file.
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    assert_eq!(w.plan(&fresh, "main").skip, set(&[B]));
}
