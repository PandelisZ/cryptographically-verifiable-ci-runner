//! End-to-end verification for the node:test adapter (`adapter =
//! "node-test"`), run against a copy of `fixtures/node-test-abcd` (and the
//! pnpm workspace `fixtures/node-test-pnpm`) in a throwaway git repo with
//! throwaway SSH keys and a local bare remote; mirrors `e2e.rs`.
//!
//! Needs `node` (22.15 or later), `npm`, `git` and `ssh-keygen` on PATH, and
//! `fixtures/vitest-abcd/node_modules` installed (`npm ci` there): the `ms`
//! package is copied from it.

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

const VCI_TOML: &str = r#"project = "."
adapter = "node-test"

[policy]
platform = "any"
max_ttl = "30d"
no_skip_refs = ["refs/heads/release/*"]

[env]
mode = "strict"
global = ["APP_MODE", "TZ"]
"#;

const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.mjs";
const C: &str = "src/c.test.mjs";
const D: &str = "src/d.test.mjs";

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

fn ms_package() -> PathBuf {
    let p = workspace_root().join("fixtures/vitest-abcd/node_modules/ms");
    assert!(
        p.join("package.json").is_file(),
        "run `npm ci` in fixtures/vitest-abcd first (the ms package is copied from it)"
    );
    p
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[derive(Debug, PartialEq, Eq)]
struct Plan {
    skip: BTreeSet<String>,
    run: BTreeSet<String>,
    run_all: Option<String>,
}

/// Which fixture a world is made from.
#[derive(Clone, Copy)]
enum Fixture {
    Abcd,
    Pnpm,
}

struct World {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    work: PathBuf,
    remote: PathBuf,
    trusted: PathBuf,
    untrusted: PathBuf,
    gitconfig: PathBuf,
    fixture: Fixture,
}

impl World {
    fn new() -> Self {
        Self::new_with(Fixture::Abcd, &[], VCI_TOML)
    }

    fn new_with(fixture: Fixture, extra: &[(&str, &str)], vci_toml: &str) -> Self {
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
            fixture,
        };
        keygen(&w.trusted, "trusted");
        keygen(&w.untrusted, "untrusted");
        w.git(&w.base, &["init", "-q", "--bare", "remote.git"]);
        w.make_project(&w.work, "base commit", extra, vci_toml);
        w.git(
            &w.work,
            &["remote", "add", "origin", w.remote.to_str().unwrap()],
        );
        w.git(&w.work, &["push", "-q", "origin", "main"]);
        w.git(&w.work, &["checkout", "-q", "-b", "feature"]);
        w
    }

    fn make_project(&self, dir: &Path, message: &str, extra: &[(&str, &str)], toml: &str) {
        self.git(&self.base, &["init", "-q", dir.to_str().unwrap()]);
        match self.fixture {
            Fixture::Abcd => {
                let fx = workspace_root().join("fixtures/node-test-abcd");
                for name in [
                    "src",
                    "fixtures",
                    "test",
                    "package.json",
                    "package-lock.json",
                ] {
                    cp(&fx.join(name), &dir.join(name));
                }
            }
            Fixture::Pnpm => {
                let fx = workspace_root().join("fixtures/node-test-pnpm");
                for name in [
                    "apps",
                    "packages",
                    "package.json",
                    "pnpm-lock.yaml",
                    "pnpm-workspace.yaml",
                ] {
                    cp(&fx.join(name), &dir.join(name));
                }
            }
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

    /// npm layout for the A-D fixture; pnpm's layout (virtual store, links
    /// to it and to the workspace package) for the pnpm fixture.
    fn install_node_modules(&self, dir: &Path) {
        match self.fixture {
            Fixture::Abcd => {
                std::fs::create_dir_all(dir.join("node_modules")).unwrap();
                cp(&ms_package(), &dir.join("node_modules/ms"));
            }
            Fixture::Pnpm => {
                let store = dir.join("node_modules/.pnpm/ms@2.1.3/node_modules");
                std::fs::create_dir_all(&store).unwrap();
                cp(&ms_package(), &store.join("ms"));
                let web = dir.join("apps/web/node_modules");
                std::fs::create_dir_all(web.join("@fx")).unwrap();
                std::os::unix::fs::symlink(
                    "../../../node_modules/.pnpm/ms@2.1.3/node_modules/ms",
                    web.join("ms"),
                )
                .unwrap();
                std::os::unix::fs::symlink("../../../../packages/lib", web.join("@fx/lib"))
                    .unwrap();
            }
        }
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
            "NODE_ENV",
            "APP_MODE",
            "TEST_CONCURRENCY",
        ] {
            cmd.env_remove(k);
        }
        // An unset TZ (the machine's zone) refuses every file.
        cmd.env("TZ", "UTC");
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

    /// `vci run` of `files`; returns stderr.
    fn run(&self, dir: &Path, files: &[&str], key: &Path) -> String {
        let mut args = vec!["run"];
        args.extend(files);
        args.extend(["--key", key.to_str().unwrap()]);
        let out = self.vci(dir, &args);
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    fn plan_env(&self, dir: &Path, base: &str, env: &[(&str, Option<&str>)]) -> Plan {
        let out = self.vci_env(dir, &["plan", "--base-ref", base, "--format", "json"], env);
        assert!(out.status.success());
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        let mut p = Plan {
            skip: BTreeSet::new(),
            run: BTreeSet::new(),
            run_all: v["runAll"].as_str().map(str::to_owned),
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

    fn plan(&self, dir: &Path, base: &str) -> Plan {
        self.plan_env(dir, base, &[])
    }

    fn explain(&self, dir: &Path, file: &str, base: &str) -> String {
        self.vci_ok(dir, &["explain", file, "--base-ref", base])
    }

    fn write(&self, rel: &str, content: &str) {
        let p = self.work.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.work.join(rel)).unwrap()
    }

    fn remove(&self, rel: &str) {
        std::fs::remove_file(self.work.join(rel)).unwrap();
    }
}

fn store_for(dir: &Path) -> Repo {
    Repo::discover(Utf8Path::from_path(dir).unwrap()).unwrap()
}

fn blake3_of(bytes: &[u8]) -> String {
    vci_core::blake3_hex(bytes)
}

fn refused_line<'a>(stderr: &'a str, id: &str) -> &'a str {
    stderr
        .lines()
        .find(|l| l.starts_with(&format!("vci: not attesting {id}:")))
        .unwrap_or_else(|| panic!("{id} was not refused:\n{stderr}"))
}

#[test]
fn end_to_end_verification_steps() {
    let w = World::new();
    let work = w.work.clone();

    // Step 1: attest B, then plan: skip B only.
    let out = w.run(&work, &[B], &w.trusted);
    assert!(out.contains("vci: 1 attested, 0 not attested"), "{out}");
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[B]), "step 1");
    assert_eq!(p.run, set(&[A, C, D]), "step 1");
    assert!(p.run_all.is_none());

    // Step 2: edit fixtures/b.json -> B runs; explain names the file and both hashes.
    let original = w.read("fixtures/b.json");
    w.write("fixtures/b.json", "{ \"greeting\": \"hello, world\" }\n");
    assert!(w.plan(&work, "main").run.contains(B), "step 2");
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(ex.contains("entry:fixtures/b.json"), "{ex}");
    assert!(ex.contains(&blake3_of(original.as_bytes())), "{ex}");
    w.write("fixtures/b.json", &original);
    assert_eq!(w.plan(&work, "main").skip, set(&[B]), "step 2: restored");

    // Step 3: a new file B probed as absent (its local override) -> B runs.
    w.write("fixtures/b.local.json", "{ \"greeting\": \"hello\" }\n");
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(B),
        "step 3: a new probed file must invalidate B"
    );
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("entry:fixtures/b.local.json"), "{ex}");
    assert!(ex.contains("expected: absent"), "{ex}");
    w.remove("fixtures/b.local.json");
    assert_eq!(w.plan(&work, "main").skip, set(&[B]), "step 3: restored");

    // Step 4: attest A, C, D. Editing the computed import target runs C only.
    let out = w.run(&work, &[A, C, D], &w.trusted);
    assert!(out.contains("vci: 3 attested, 0 not attested"), "{out}");
    assert_eq!(w.plan(&work, "main").skip, set(&[A, B, C, D]), "step 4");
    let impl_x = w.read("src/impl-x.mjs");
    w.write("src/impl-x.mjs", "export const name = \"x\"; // edited\n");
    let p = w.plan(&work, "main");
    assert_eq!(p.run, set(&[C]), "step 4: only C imports impl-x.mjs");
    assert!(w.explain(&work, C, "main").contains("entry:src/impl-x.mjs"));
    w.write("src/impl-x.mjs", &impl_x);
    // C imports `./c` without an extension; the user's hook tries `.ts`
    // first, so a new src/c.ts would be what C runs.
    w.write(
        "src/c.ts",
        "export const loadImpl = async () => ({ name: 'y' });\n",
    );
    assert_eq!(w.plan(&work, "main").run, set(&[C]), "step 4: new src/c.ts");
    w.remove("src/c.ts");
    // A's own module (through the `@/` alias of the hook).
    w.write(
        "src/a.ts",
        "export const add = (x: number, y: number): number => y + x;\n",
    );
    assert_eq!(w.plan(&work, "main").run, set(&[A]), "step 4: src/a.ts");
    w.git(&work, &["checkout", "--", "src/a.ts"]);
    assert_eq!(
        w.plan(&work, "main").skip,
        set(&[A, B, C, D]),
        "step 4: restored"
    );

    // Step 5: edit the --import hooks file -> everything runs.
    let hooks = w.read("test/register-hooks.mjs");
    w.write("test/register-hooks.mjs", &format!("{hooks}\n// edited\n"));
    let p = w.plan(&work, "main");
    assert!(
        p.skip.is_empty(),
        "step 5: hooks file is an input of every file: {p:?}"
    );
    let ex = w.explain(&work, D, "main");
    assert!(ex.contains("test/register-hooks.mjs"), "{ex}");
    w.write("test/register-hooks.mjs", &hooks);
    // A change to the test script (another flag) runs everything too.
    let pj = w.read("package.json");
    w.write(
        "package.json",
        &pj.replace(
            "--experimental-strip-types",
            "--experimental-strip-types --enable-source-maps",
        ),
    );
    let p = w.plan(&work, "main");
    assert!(p.skip.is_empty(), "step 5: changed script: {p:?}");
    w.write("package.json", &pj);
    // The lockfile is a global input.
    let lock = w.read("package-lock.json");
    w.write("package-lock.json", &format!("{lock}\n"));
    assert!(w.plan(&work, "main").skip.is_empty(), "step 5: lockfile");
    w.write("package-lock.json", &lock);
    assert_eq!(
        w.plan(&work, "main").skip,
        set(&[A, B, C, D]),
        "step 5: restored"
    );

    // Step 6: the external package's installed version is checked.
    let ms_pj = w.read("node_modules/ms/package.json");
    w.write(
        "node_modules/ms/package.json",
        &ms_pj.replace("\"version\": \"2.1.3\"", "\"version\": \"2.1.2\""),
    );
    let p = w.plan(&work, "main");
    assert_eq!(p.run, set(&[D]), "step 6: only D uses ms");
    assert!(w.explain(&work, D, "main").contains("external:ms"));
    w.write("node_modules/ms/package.json", &ms_pj);

    // Step 7: declared env (APP_MODE) differs -> everything runs; the
    // script's own NODE_ENV=test wins over the environment's, and
    // TEST_CONCURRENCY only changes a flag vci drops: both still skip.
    let p = w.plan_env(&work, "main", &[("APP_MODE", Some("other"))]);
    assert!(p.skip.is_empty(), "step 7: APP_MODE: {p:?}");
    let p = w.plan_env(
        &work,
        "main",
        &[
            ("NODE_ENV", Some("production")),
            ("TEST_CONCURRENCY", Some("4")),
        ],
    );
    assert_eq!(
        p.skip,
        set(&[A, B, C, D]),
        "step 7: NODE_ENV/TEST_CONCURRENCY"
    );
    let p = w.plan_env(
        &work,
        "main",
        &[("NODE_OPTIONS", Some("--max-old-space-size=4096"))],
    );
    assert!(
        p.skip.is_empty(),
        "step 7: NODE_OPTIONS is a global input: {p:?}"
    );
    // TEST_CONCURRENCY that smuggles in a refused option: nothing can be listed.
    let p = w.plan_env(
        &work,
        "main",
        &[("TEST_CONCURRENCY", Some("1 --test-only"))],
    );
    assert!(p.skip.is_empty() && p.run_all.is_some(), "{p:?}");

    // Step 8: tampered payload -> signature check fails.
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
    assert!(w.plan(&work, "main").run.contains(B), "step 8");
    assert!(
        w.explain(&work, B, "main")
            .contains("failed check: signature")
    );
    store
        .put(B, &good.signer, &good.storage_key, &good.bytes)
        .unwrap();
    assert!(w.plan(&work, "main").skip.contains(B), "step 8: restored");

    // Step 9: a key that is not in allowed_signers -> rejected, also when
    // the PR adds it to allowed_signers.
    let d_stored = store.list(Some(D)).unwrap();
    for s in &d_stored {
        store.remove(s).unwrap();
    }
    let out = w.run(&work, &[D], &w.untrusted);
    assert!(out.contains("1 attested"), "{out}");
    assert!(w.plan(&work, "main").run.contains(D), "step 9");
    let ex = w.explain(&work, D, "main");
    assert!(ex.contains("failed check: signer"), "{ex}");
    let mut signers = w.read(".vci/allowed_signers");
    signers.push_str(&format!(
        "untrusted@example.com namespaces=\"vci-attest\" {}\n",
        pubkey(&w.untrusted)
    ));
    w.write(".vci/allowed_signers", &signers);
    w.git(&work, &["commit", "-q", "-am", "PR: trust my own key"]);
    assert!(
        w.plan(&work, "main").run.contains(D),
        "step 9: PR-only signer"
    );
    assert!(w.plan(&work, "HEAD").skip.contains(D), "step 9 control");
}

#[test]
fn run_refuses_unattestable_test_files() {
    let w = World::new();
    let work = w.work.clone();
    let files: &[(&str, &str)] = &[
        (
            "src/skip.test.mjs",
            "import { test } from 'node:test';\ntest('a', () => {});\ntest('b', { skip: true }, () => {});\n",
        ),
        (
            "src/todo.test.mjs",
            "import { test } from 'node:test';\ntest('a', () => {});\ntest.todo('b');\n",
        ),
        (
            "src/suite.test.mjs",
            "import { describe, it } from 'node:test';\ndescribe.skip('s', () => { it('x', () => {}); });\nit('y', () => {});\n",
        ),
        (
            "src/only.test.mjs",
            "import { test } from 'node:test';\ntest.only('a', () => {});\ntest('b', () => {});\n",
        ),
        (
            "src/fail.test.mjs",
            "import assert from 'node:assert';\nimport { test } from 'node:test';\ntest('a', () => { assert.equal(1, 2); });\n",
        ),
        (
            "src/spawn.test.mjs",
            "import { test } from 'node:test';\nimport { execFileSync } from 'node:child_process';\ntest('a', () => { execFileSync(process.execPath, ['-e', '1']); });\n",
        ),
        (
            "src/exit.test.mjs",
            "import { test } from 'node:test';\ntest('a', () => {});\ntest('b', () => { process.exit(0); });\n",
        ),
        ("src/none.test.mjs", "export const nothing = 1;\n"),
        (
            "src/write.test.mjs",
            "import { test } from 'node:test';\nimport fs from 'node:fs';\ntest('a', () => { fs.writeFileSync(new URL('../out.txt', import.meta.url), 'x'); });\n",
        ),
        (
            "src/outside.test.mjs",
            "import { test } from 'node:test';\nimport fs from 'node:fs';\ntest('a', () => { fs.readFileSync(process.env.VCI_E2E_OUTSIDE); });\n",
        ),
    ];
    for (rel, body) in files {
        w.write(rel, body);
    }
    let outside = w.base.join("outside.txt");
    std::fs::write(&outside, "outside the repository").unwrap();
    let mut args = vec!["run"];
    args.extend(files.iter().map(|(rel, _)| *rel));
    args.extend(["--key", w.trusted.to_str().unwrap()]);
    let out = w.vci_env(
        &work,
        &args,
        &[("VCI_E2E_OUTSIDE", Some(outside.to_str().unwrap()))],
    );
    assert_ne!(out.status.code(), Some(0), "the failing test fails the run");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    for (id, why) in [
        ("src/skip.test.mjs", "skipped"),
        ("src/todo.test.mjs", "skipped"),
        ("src/suite.test.mjs", "skipped"),
        ("src/only.test.mjs", "node-test:only"),
        // Regression: the message named skips that did not happen.
        ("src/fail.test.mjs", "result failed (1 failed of 1)"),
        ("src/spawn.test.mjs", "tainted: child_process"),
        ("src/exit.test.mjs", "process.exit"),
        ("src/none.test.mjs", "no-tests"),
        ("src/write.test.mjs", "wrote inside the repository: out.txt"),
        ("src/outside.test.mjs", "input outside the repository"),
    ] {
        let line = refused_line(&stderr, id);
        assert!(line.contains(why), "{id}: expected {why:?} in {line:?}");
    }
    assert!(
        stderr.contains("vci: 0 attested, 10 not attested"),
        "{stderr}"
    );
    assert!(
        AttestStore::new(&store_for(&work))
            .list(None)
            .unwrap()
            .is_empty()
    );
}

/// Test commands vci cannot vouch for: nothing is attested, `vci plan` runs
/// everything, and `vci ci` runs the package.json script itself.
#[test]
fn unsupported_test_commands_run_everything() {
    let w = World::new();
    let work = w.work.clone();
    let pj = w.read("package.json");
    for (script, why) in [
        ("node --test --test-only 'src/**/*.test.mjs'", "--test-only"),
        (
            "node --test --test-name-pattern=add 'src/**/*.test.mjs'",
            "filters",
        ),
        (
            "node --test --test-isolation=none 'src/**/*.test.mjs'",
            "--test-isolation=none",
        ),
        (
            "node --loader ./x.mjs --test 'src/**/*.test.mjs'",
            "--loader",
        ),
        ("node --test --watch 'src/**/*.test.mjs'", "watch"),
        (
            "npm run build && node --test 'src/**/*.test.mjs'",
            "operator",
        ),
    ] {
        let v: Value = serde_json::from_str(&pj).unwrap();
        let mut v = v.clone();
        v["scripts"]["test"] = Value::String(script.into());
        w.write("package.json", &serde_json::to_string_pretty(&v).unwrap());
        let out = w.vci(&work, &["run", B, "--key", w.trusted.to_str().unwrap()]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_ne!(out.status.code(), Some(0), "{script}: {stderr}");
        assert!(stderr.contains(why), "{script}: {stderr}");
        let p = w.plan(&work, "main");
        assert!(p.skip.is_empty(), "{script}: {p:?}");
    }
    w.write("package.json", &pj);
    assert!(
        AttestStore::new(&store_for(&work))
            .list(None)
            .unwrap()
            .is_empty()
    );

    // A script that is not `node --test` at all: `vci ci` runs it with npm.
    let mut v: Value = serde_json::from_str(&pj).unwrap();
    v["scripts"]["test"] = Value::String("node --version".into());
    w.write("package.json", &serde_json::to_string_pretty(&v).unwrap());
    let p = w.plan(&work, "main");
    assert!(
        p.run_all.as_deref().is_some_and(|r| r.contains("listing")),
        "{p:?}"
    );
    let out = w.vci(
        &work,
        &[
            "ci",
            "--base-ref",
            "main",
            "--audit-log",
            w.base.join("a.json").to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("running all tests"), "{stderr}");
}

#[test]
fn push_fetch_fresh_clone_and_ci() {
    let w = World::new();
    let work = w.work.clone();
    let out = w.run(&work, &[B, C], &w.trusted);
    assert!(out.contains("2 attested"), "{out}");
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
    assert!(
        w.plan(&fresh, "main").skip.is_empty(),
        "nothing before fetch"
    );
    w.vci_ok(&fresh, &["fetch", "--remote", "origin"]);
    assert_eq!(
        w.plan(&fresh, "main"),
        before,
        "same plan after push + fetch"
    );

    // `vci ci` runs only A and D, one `node --test` process each.
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
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("running 2 test file(s)"), "{stderr}");
    assert!(
        stderr.contains("add") && stderr.contains("uses an external package"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("reads fixture"),
        "B must not run: {stderr}"
    );
    let log: Value = serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
    let skipped: BTreeSet<String> = log["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["testId"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(skipped, set(&[B, C]));

    // A failing remainder fails `vci ci`.
    std::fs::write(
        fresh.join("src/a.ts"),
        "export const add = (x: number, y: number): number => x - y;\n",
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
    assert_ne!(out.status.code(), Some(0));

    // Policy: nothing is skipped on refs listed in no_skip_refs.
    w.git(&fresh, &["checkout", "-q", "--", "src/a.ts"]);
    w.git(&fresh, &["checkout", "-q", "-b", "release/1"]);
    let p = w.plan(&fresh, "main");
    assert!(p.run_all.is_some() && p.skip.is_empty(), "{p:?}");
}

/// A pnpm workspace: the project is apps/web; a workspace package
/// (node_modules/@fx/lib -> packages/lib) is repository content, and a
/// package from the virtual store is identified by name and version.
#[test]
fn pnpm_workspace_packages_are_inputs() {
    let toml = r#"[policy]
no_skip_refs = ["refs/heads/release/*"]

[[projects]]
name = "web"
path = "apps/web"
adapter = "node-test"

[env]
global = ["TZ"]
"#;
    let w = World::new_with(Fixture::Pnpm, &[], toml);
    let work = w.work.clone();
    let lib = "apps/web/src/lib.test.ts";
    let ms = "apps/web/src/ms.test.ts";
    let out = w.run(&work, &[lib, ms], &w.trusted);
    assert!(out.contains("vci: 2 attested, 0 not attested"), "{out}");
    assert_eq!(w.plan(&work, "main").skip, set(&[lib, ms]));

    // The workspace package's source is an input of the file that uses it.
    let src = w.read("packages/lib/src/index.ts");
    w.write("packages/lib/src/index.ts", &format!("{src}// edited\n"));
    let p = w.plan(&work, "main");
    assert_eq!(p.run, set(&[lib]), "{p:?}");
    assert!(
        w.explain(&work, lib, "main")
            .contains("entry:packages/lib/src/index.ts")
    );
    w.write("packages/lib/src/index.ts", &src);
    // So is its package.json (exports decide what resolves).
    let pj = w.read("packages/lib/package.json");
    w.write(
        "packages/lib/package.json",
        &pj.replace("\"0.0.0\"", "\"0.0.1\""),
    );
    assert_eq!(w.plan(&work, "main").run, set(&[lib]));
    w.write("packages/lib/package.json", &pj);
    // The workspace lockfile at the repository root is a global input.
    let lock = w.read("pnpm-lock.yaml");
    w.write("pnpm-lock.yaml", &format!("{lock}\n"));
    assert!(w.plan(&work, "main").skip.is_empty());
    w.write("pnpm-lock.yaml", &lock);
    assert_eq!(w.plan(&work, "main").skip, set(&[lib, ms]));

    // A new test file matched by the script's (shell) glob is listed.
    w.write(
        "apps/web/src/new.test.ts",
        "import { test } from 'node:test';\ntest('n', () => {});\n",
    );
    let p = w.plan(&work, "main");
    assert!(p.run.contains("apps/web/src/new.test.ts"), "{p:?}");
}

/// The command from vci.toml (`test_globs` + `node_args`) instead of a
/// package.json script.
#[test]
fn test_globs_and_node_args_from_vci_toml() {
    let toml = r#"adapter = "node-test"
test_globs = ["src/**/*.test.mjs"]
node_args = ["--import", "./test/register-hooks.mjs"]

[policy]
no_skip_refs = ["refs/heads/release/*"]

[env]
global = ["TZ"]
"#;
    let w = World::new_with(Fixture::Abcd, &[], toml);
    let work = w.work.clone();
    let out = w.run(&work, &[C], &w.trusted);
    assert!(out.contains("1 attested"), "{out}");
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[C]));
    assert_eq!(p.run, set(&[B, D]), "a.test.ts is not matched");
    // The package.json script is not used, so changing it changes no argv
    // (package.json is still a global input).
    let ex = w.explain(&work, C, "main");
    assert!(ex.contains("SKIP"), "{ex}");
}

#[test]
fn init_writes_a_node_test_config() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let key = base.join("k");
    keygen(&key, "k");
    let repo = base.join("repo");
    let st = Command::new("git")
        .args(["init", "-q"])
        .arg(&repo)
        .status()
        .unwrap();
    assert!(st.success());
    cp(
        &workspace_root().join("fixtures/node-test-abcd/package.json"),
        &repo.join("package.json"),
    );
    let out = Command::cargo_bin("vci")
        .unwrap()
        .current_dir(&repo)
        .args(["init", "--adapter", "node-test", "--key"])
        .arg(key.with_extension("pub"))
        .args(["--principal", "dev@example.com"])
        .env("VCI_JS_PLUGIN", workspace_root().join("js/vitest-plugin"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    // The command as sh reads it: assignments kept, globs quoted.
    assert!(
        stderr.contains("tests from package.json script \"test\": NODE_ENV=test node --experimental-strip-types --import=./test/register-hooks.mjs --test 'src/**/*.test.ts' 'src/**/*.test.mjs'"),
        "{stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("node:test files"), "{stdout}");
    let toml = std::fs::read_to_string(repo.join("vci.toml")).unwrap();
    assert!(toml.contains("adapter = \"node-test\""), "{toml}");
}

/// Sets `scripts.<name>` (None removes it) in `rel` of `w.work`.
fn set_script(w: &World, rel: &str, name: &str, cmd: Option<&str>) {
    let mut v: Value = serde_json::from_str(&w.read(rel)).unwrap();
    match cmd {
        Some(c) => v["scripts"][name] = Value::String(c.into()),
        None => {
            v["scripts"].as_object_mut().unwrap().remove(name);
        }
    }
    w.write(rel, &serde_json::to_string_pretty(&v).unwrap());
}

/// Regressions: what `npm test` does around or before the script that vci's
/// per-file runs would not do (a `pretest`, `.npmrc` node-options, install
/// scripts), and a listing without files, are never "nothing to run": `vci
/// plan` runs everything and `vci ci` runs the script.
#[test]
fn npm_behaviour_vci_does_not_reproduce_runs_everything() {
    let w = World::new();
    let work = w.work.clone();
    let audit = w.base.join("a.json");
    let ci = |w: &World| {
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
        String::from_utf8_lossy(&out.stderr).into_owned()
    };

    // pretest builds the test files into an ignored dist/: the listing at
    // plan time is empty, and npm test would run pretest first.
    w.write(
        "build.mjs",
        "import fs from 'node:fs';\nfs.mkdirSync('dist', { recursive: true });\nfor (const f of ['b.test.mjs']) fs.copyFileSync(`src/${f}`, `dist/${f}`);\n",
    );
    w.write(".gitignore", "node_modules/\n.vci/out/\ndist/\n");
    set_script(&w, "package.json", "pretest", Some("node build.mjs"));
    set_script(
        &w,
        "package.json",
        "test",
        Some("node --test 'dist/**/*.test.mjs'"),
    );
    let p = w.plan(&work, "main");
    assert!(
        p.run_all
            .as_deref()
            .is_some_and(|r| r.contains("\"pretest\"")),
        "{p:?}"
    );
    let out = w.run(&work, &["dist/b.test.mjs"], &w.trusted);
    assert!(out.contains("pretest"), "{out}");
    let e = ci(&w);
    assert!(e.contains("running all tests"), "{e}");
    // Without the pretest: an empty listing still runs the script.
    set_script(&w, "package.json", "pretest", None);
    std::fs::remove_dir_all(work.join("dist")).ok();
    let p = w.plan(&work, "main");
    assert!(
        p.run_all
            .as_deref()
            .is_some_and(|r| r.contains("no test file matches")),
        "{p:?}"
    );
    let e = ci(&w);
    assert!(e.contains("running all tests"), "{e}");
    assert!(!e.contains("nothing to run"), "{e}");
    set_script(
        &w,
        "package.json",
        "test",
        Some("node --test 'src/**/*.test.mjs'"),
    );

    // .npmrc node-options: npm passes them to the script as NODE_OPTIONS.
    w.write(".npmrc", "node-options=--require ./setup.cjs\n");
    w.write("setup.cjs", "globalThis.MODE = 'npm-setup';\n");
    let out = w.run(&work, &[B], &w.trusted);
    assert!(out.contains("node-options"), "{out}");
    let p = w.plan(&work, "main");
    assert!(
        p.run_all
            .as_deref()
            .is_some_and(|r| r.contains("node-options")),
        "{p:?}"
    );
    w.remove(".npmrc");

    // An install script that patches node_modules (identified by version).
    set_script(
        &w,
        "package.json",
        "postinstall",
        Some("node scripts/apply-patches.mjs"),
    );
    let out = w.run(&work, &[B], &w.trusted);
    assert!(out.contains("install script"), "{out}");
    let p = w.plan(&work, "main");
    assert!(
        p.run_all
            .as_deref()
            .is_some_and(|r| r.contains("postinstall")),
        "{p:?}"
    );
    // patch-package is accepted: its patches/ are a global input.
    set_script(&w, "package.json", "postinstall", Some("patch-package"));
    let out = w.run(&work, &[B], &w.trusted);
    assert!(out.contains("1 attested"), "{out}");
    assert!(w.plan(&work, "main").skip.contains(B));
    w.write(
        "patches/ms+2.1.3.patch",
        "--- a/node_modules/ms/index.js\n+++ b/node_modules/ms/index.js\n",
    );
    assert!(!w.plan(&work, "main").skip.contains(B));
    assert!(
        AttestStore::new(&store_for(&work))
            .list(None)
            .unwrap()
            .len()
            == 1,
        "only the patch-package run was attested"
    );
}

/// Regressions: the environment that reaches node besides the command line.
/// An unset TZ (each machine's own zone) and NODE_OPTIONS from an
/// `--env-file` (it can filter tests or preload code before the collector)
/// refuse the file.
#[test]
fn environment_reaching_node_is_checked() {
    let w = World::new();
    let work = w.work.clone();
    let out = w.vci_env(
        &work,
        &["run", B, "--key", w.trusted.to_str().unwrap()],
        &[("TZ", None)],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        refused_line(&stderr, B).contains("node-test:TZ-unset"),
        "{stderr}"
    );

    w.write(".env.test", "NODE_OPTIONS=--test-name-pattern=good\n");
    w.write(
        "src/x.test.mjs",
        "import assert from 'node:assert';\nimport { test } from 'node:test';\ntest('good', () => {});\ntest('bad', () => { assert.fail('bad'); });\n",
    );
    set_script(
        &w,
        "package.json",
        "test",
        Some("node --env-file=.env.test --test 'src/**/*.test.mjs'"),
    );
    let stderr = w.run(&work, &["src/x.test.mjs"], &w.trusted);
    assert!(
        refused_line(&stderr, "src/x.test.mjs")
            .contains("node-test:NODE_OPTIONS:--test-name-pattern=good"),
        "{stderr}"
    );
    assert!(
        AttestStore::new(&store_for(&work))
            .list(None)
            .unwrap()
            .is_empty()
    );
}
