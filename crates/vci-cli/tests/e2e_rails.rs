//! End-to-end verification for the Rails adapter, mirroring `e2e_pytest.rs`:
//! a copy of `fixtures/rails-abcd` (a Rails 8 application with SQLite) in a
//! throwaway git repo (the base commit holds `.vci/allowed_signers` and
//! `vci.toml`), throwaway SSH keys and a local bare remote.
//!
//! Needs `git`, `ssh-keygen` and the Ruby the fixture pins in `.ruby-version`
//! with its bundle installed: `$VCI_TEST_RUBY_BIN` (a directory holding
//! `ruby` and `bundle`), else `mise where ruby@<version>`, else `ruby` on PATH
//! if it is that version. Every test prints `SKIPPED:` and returns early when
//! no such Ruby is found or `bundle check` fails for the fixture (the gems are
//! not installed for it: `bundle install` in `fixtures/rails-abcd`).

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

fn fixture() -> PathBuf {
    workspace_root().join("fixtures/rails-abcd")
}

fn ruby_version_of(bin: &Path) -> Option<String> {
    let out = Command::new(bin.join("ruby"))
        .args(["-e", "print RUBY_VERSION"])
        .env_remove("RUBYOPT")
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The bin directory of the Ruby `.ruby-version` pins, or `None` (with a
/// SKIPPED message).
fn ruby_bin() -> Option<PathBuf> {
    let want = std::fs::read_to_string(fixture().join(".ruby-version"))
        .unwrap()
        .trim()
        .to_owned();
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(d) = std::env::var_os("VCI_TEST_RUBY_BIN").filter(|v| !v.is_empty()) {
        candidates.push(PathBuf::from(d));
    }
    if let Ok(out) = Command::new("mise")
        .args(["where", &format!("ruby@{want}")])
        .output()
        && out.status.success()
    {
        let d = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !d.is_empty() {
            candidates.push(Path::new(&d).join("bin"));
        }
    }
    if let Ok(out) = Command::new("ruby")
        .args(["-e", "print RbConfig.ruby"])
        .env_remove("RUBYOPT")
        .output()
        && out.status.success()
        && let Some(d) = Path::new(String::from_utf8_lossy(&out.stdout).trim()).parent()
    {
        candidates.push(d.to_owned());
    }
    for c in candidates {
        if ruby_version_of(&c).as_deref() == Some(want.as_str()) && c.join("bundle").exists() {
            return Some(c);
        }
    }
    eprintln!(
        "SKIPPED: Ruby {want} (fixtures/rails-abcd/.ruby-version) with bundler was not found: set VCI_TEST_RUBY_BIN, or install it with mise (`mise install ruby@{want}`)"
    );
    None
}

/// Variables removed from every `vci` and Ruby invocation so the host
/// environment cannot change the outcome.
const SCRUB: &[&str] = &[
    "VCI_BASE_REF",
    "GITHUB_BASE_REF",
    "GITHUB_REF",
    "GITHUB_OUTPUT",
    "VCI_SIGNING_KEY",
    "VCI_OUT",
    "VCI_RUBY",
    "VCI_JOBS",
    "APP_MODE",
    "RUBYOPT",
    "RUBYLIB",
    "GEM_HOME",
    "GEM_PATH",
    "BUNDLE_GEMFILE",
    "BUNDLE_PATH",
    "BUNDLE_APP_CONFIG",
    "RAILS_ENV",
    "RACK_ENV",
    "DATABASE_URL",
    "NODE_OPTIONS",
    "CI",
    "TZ",
];

const VCI_TOML: &str = r#"project = "."
adapter = "rails"

[policy]
platform = "any"
max_ttl = "30d"
no_skip_refs = ["refs/heads/release/*"]

[env]
mode = "strict"
global = ["APP_MODE", "TZ"]
"#;

struct World {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    work: PathBuf,
    remote: PathBuf,
    trusted: PathBuf,
    untrusted: PathBuf,
    gitconfig: PathBuf,
    ruby_bin: PathBuf,
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

/// Copy the fixture's sources (not its installed gems, logs, temp files or
/// databases) into `dir`.
fn copy_rails_fixture(dir: &Path) {
    let fx = fixture();
    std::fs::create_dir_all(dir).unwrap();
    for name in [
        ".gitignore",
        ".ruby-version",
        "Gemfile",
        "Gemfile.lock",
        "Rakefile",
        "config.ru",
        "app",
        "bin",
        "config",
        "db",
        "lib",
        "test",
    ] {
        cp(&fx.join(name), &dir.join(name));
    }
    for d in ["log", "tmp", "storage", "vendor"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
        std::fs::write(dir.join(d).join(".keep"), "").unwrap();
    }
    for junk in ["db/test.sqlite3", "db/development.sqlite3"] {
        let _ = std::fs::remove_file(dir.join(junk));
    }
}

impl World {
    /// `None` (test skipped) when the fixture's Ruby or bundle is missing.
    fn new() -> Option<Self> {
        Self::build(VCI_TOML, copy_rails_fixture)
    }

    fn build(vci_toml: &str, layout: impl FnOnce(&Path)) -> Option<Self> {
        let ruby_bin = ruby_bin()?;
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
            ruby_bin,
        };
        keygen(&w.trusted, "trusted");
        keygen(&w.untrusted, "untrusted");
        w.git(&w.base, &["init", "-q", "--bare", "remote.git"]);
        w.git(&w.base, &["init", "-q", w.work.to_str().unwrap()]);
        layout(&w.work);
        let mut ignore = std::fs::read_to_string(w.work.join(".gitignore")).unwrap_or_default();
        ignore.push_str("/.vci/out/\n");
        std::fs::write(w.work.join(".gitignore"), ignore).unwrap();
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
        w.git(&w.work, &["checkout", "-q", "-b", "feature"]);
        if !w.bundle_check(&w.work) {
            return None;
        }
        Some(w)
    }

    fn path_env(&self) -> std::ffi::OsString {
        let mut paths = vec![self.ruby_bin.clone()];
        if let Some(p) = std::env::var_os("PATH") {
            paths.extend(std::env::split_paths(&p));
        }
        std::env::join_paths(paths).unwrap()
    }

    /// `bundle check` in `dir`: false (with a SKIPPED message) if the
    /// fixture's gems are not installed for this Ruby.
    fn bundle_check(&self, dir: &Path) -> bool {
        let mut cmd = Command::new(self.ruby_bin.join("bundle"));
        cmd.arg("check")
            .current_dir(dir)
            .env("PATH", self.path_env());
        for k in SCRUB {
            cmd.env_remove(k);
        }
        let out = cmd.output().unwrap();
        if !out.status.success() {
            eprintln!(
                "SKIPPED: `bundle check` failed for the Rails fixture (run `bundle install` in fixtures/rails-abcd with Ruby {}): {}{}",
                ruby_version_of(&self.ruby_bin).unwrap_or_default(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        out.status.success()
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
            .env(
                "VCI_RUBY_COLLECTOR",
                workspace_root().join("ruby/vci-collector"),
            )
            .env("PATH", self.path_env())
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

    fn run(&self, dir: &Path, files: &[&str], key: &Path) -> String {
        let mut args = vec!["run"];
        args.extend(files);
        args.extend(["--key", key.to_str().unwrap()]);
        let out = self.vci(dir, &args);
        assert!(out.status.success(), "vci run {files:?} failed");
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

/// a: a pure-Ruby lib (lib/calc.rb, autoloaded); b: models and fixtures in
/// the database; c: a file chosen at run time and a view template; d: an
/// integration test of a route, using the hashids gem.
const A: &str = "test/lib/a_test.rb";
const B: &str = "test/models/b_test.rb";
const C: &str = "test/views/c_test.rb";
const D: &str = "test/controllers/d_test.rb";
const ALL: &[&str] = &[A, B, C, D];

#[test]
fn rails_end_to_end_verification_steps() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();

    // Step 1: attest B, then plan: skip B; run A, C, D.
    w.run(&work, &[B], &w.trusted);
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[B]), "step 1");
    assert_eq!(p.run, set(&[A, C, D]), "step 1");
    assert!(!p.run_all);
    // The test database was prepared fresh in a temp dir, not in db/.
    assert!(!work.join("db/test.sqlite3").exists());

    // Step 2: edit a fixture yml -> B runs; explain names the file and both
    // hashes.
    let original = w.read("test/fixtures/widgets.yml");
    w.put(
        "test/fixtures/widgets.yml",
        "small:\n  name: sprocket\n  size: 3\n",
    );
    assert!(
        w.plan(&work, "main").run.contains(B),
        "step 2: B must run after its fixture changed"
    );
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(ex.contains("entry:test/fixtures/widgets.yml"), "{ex}");
    assert!(
        ex.contains(&vci_core::blake3_hex(original.as_bytes())),
        "{ex}"
    );
    w.put("test/fixtures/widgets.yml", &original);
    assert_eq!(w.plan(&work, "main").skip, set(&[B]), "step 2: restored");

    // Step 3: attest everything.
    w.run(&work, &[A, C, D], &w.trusted);
    assert_eq!(w.plan(&work, "main").skip, set(ALL), "step 3");

    // Step 4: a model only B uses -> B runs, A, C and D stay skipped.
    let gadget = w.read("app/models/gadget.rb");
    w.put("app/models/gadget.rb", &format!("{gadget}# edited\n"));
    let p = w.plan(&work, "main");
    assert_eq!(p.run, set(&[B]), "step 4");
    assert_eq!(p.skip, set(&[A, C, D]), "step 4");
    assert!(
        w.explain(&work, B, "main")
            .contains("entry:app/models/gadget.rb")
    );
    w.put("app/models/gadget.rb", &gadget);

    // Step 5: the view template -> C runs, nothing else.
    let tpl = w.read("app/views/reports/show.text.erb");
    w.put("app/views/reports/show.text.erb", &format!("{tpl}!"));
    let p = w.plan(&work, "main");
    assert_eq!(p.run, set(&[C]), "step 5");
    assert!(
        w.explain(&work, C, "main")
            .contains("entry:app/views/reports/show.text.erb")
    );
    w.put("app/views/reports/show.text.erb", &tpl);
    // The file C reads is chosen at run time: the one it did not read does
    // not matter, the one it did does.
    w.put("test/fixtures/files/beta.txt", "Beta title, edited\n");
    assert_eq!(w.plan(&work, "main").skip, set(ALL), "step 5: beta.txt");
    w.put("test/fixtures/files/alpha.txt", "Alpha title, edited\n");
    assert_eq!(w.plan(&work, "main").run, set(&[C]), "step 5: alpha.txt");
    w.git(&work, &["checkout", "--", "test/fixtures/files"]);

    // Step 6: config/routes.rb -> D (which draws the routes) runs.
    let routes = w.read("config/routes.rb");
    w.put("config/routes.rb", &format!("{routes}# edited\n"));
    let p = w.plan(&work, "main");
    assert!(p.run.contains(D), "step 6: {p:?}");
    assert!(
        w.explain(&work, D, "main")
            .contains("entry:config/routes.rb")
    );
    w.put("config/routes.rb", &routes);
    assert_eq!(w.plan(&work, "main").skip, set(ALL), "step 6: restored");

    // Step 7: a new file in an autoload directory that changes what a
    // constant resolves to (app/models comes before lib, so this Calc wins)
    // -> A runs. Zeitwerk's listing of app/models is an input.
    w.put(
        "app/models/calc.rb",
        "module Calc\n  def self.add(a, b) = a - b\nend\n",
    );
    let p = w.plan(&work, "main");
    assert!(p.run.contains(A), "step 7: {p:?}");
    assert!(
        w.explain(&work, A, "main").contains("entry:app/models"),
        "step 7: the listing"
    );
    std::fs::remove_file(work.join("app/models/calc.rb")).unwrap();
    assert_eq!(w.plan(&work, "main").skip, set(ALL), "step 7: restored");

    // Step 8: db/schema.rb -> every test that uses the database runs (all of
    // them: test_helper loads every fixture, and Rails checks the schema).
    let schema = w.read("db/schema.rb");
    w.put("db/schema.rb", &format!("{schema}# edited\n"));
    let p = w.plan(&work, "main");
    assert!(p.skip.is_empty(), "step 8: {p:?}");
    assert!(
        w.explain(&work, B, "main").contains("entry:db/schema.rb"),
        "step 8"
    );
    w.put("db/schema.rb", &schema);

    // Step 9: a gem version bump in Gemfile.lock -> everything runs.
    let lock = w.read("Gemfile.lock");
    w.put(
        "Gemfile.lock",
        &lock.replace("hashids (1.0.6)", "hashids (1.0.5)"),
    );
    let p = w.plan(&work, "main");
    assert!(p.skip.is_empty(), "step 9: {p:?}");
    w.put("Gemfile.lock", &lock);

    // Step 10: .ruby-version -> everything runs: another version (Bundler
    // then refuses to load the bundle, so the plan runs everything), and
    // even an equivalent spelling (a global input).
    let rv = w.read(".ruby-version");
    w.put(".ruby-version", "3.4.8\n");
    let p = w.plan(&work, "main");
    assert!(p.skip.is_empty(), "step 10: {p:?}");
    w.put(".ruby-version", &format!("ruby-{rv}"));
    let p = w.plan(&work, "main");
    assert!(p.skip.is_empty() && !p.run_all, "step 10: {p:?}");
    let ex = w.explain(&work, A, "main");
    assert!(ex.contains("failed check: global-inputs"), "{ex}");
    assert!(ex.contains("entry:.ruby-version"), "{ex}");
    w.put(".ruby-version", &rv);
    assert_eq!(w.plan(&work, "main").skip, set(ALL), "step 10: restored");

    // Step 11: flip a byte in B's payload -> rejected at the signature check.
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
        .position(|x| x == b"\"tests\":2")
        .expect("payload contains the test count");
    payload[pos + 8] = b'3';
    env["payload"] = Value::String(b64.encode(&payload));
    store
        .put(
            B,
            &good.signer,
            &good.storage_key,
            &serde_json::to_vec(&env).unwrap(),
        )
        .unwrap();
    assert!(w.plan(&work, "main").run.contains(B), "step 11");
    assert!(
        w.explain(&work, B, "main")
            .contains("failed check: signature")
    );
    store
        .put(B, &good.signer, &good.storage_key, &good.bytes)
        .unwrap();
    assert!(w.plan(&work, "main").skip.contains(B), "step 11: restored");

    // Step 12: an unknown signer -> rejected; adding it to allowed_signers on
    // the PR branch only -> still rejected.
    let calc = w.read("lib/calc.rb");
    w.put("lib/calc.rb", &format!("{calc}# untrusted run\n"));
    w.run(&work, &[A], &w.untrusted);
    assert!(w.plan(&work, "main").run.contains(A), "step 12");
    let ex = w.explain(&work, A, "main");
    assert!(ex.contains("failed check: signer"), "{ex}");
    let mut signers = w.read(".vci/allowed_signers");
    signers.push_str(&format!(
        "untrusted@example.com namespaces=\"vci-attest\" {}\n",
        pubkey(&w.untrusted)
    ));
    w.put(".vci/allowed_signers", &signers);
    w.git(&work, &["commit", "-q", "-am", "PR: trust my own key"]);
    assert!(
        w.plan(&work, "main").run.contains(A),
        "step 12: a key added on the PR branch must not be trusted"
    );
    assert!(
        w.plan(&work, "HEAD").skip.contains(A),
        "step 12 control: with the PR commit as the (wrong) trust root"
    );

    // Step 13: a variable declared in [env] global with another value in CI
    // forces a run.
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
}

#[test]
fn rails_run_refuses_unattestable_test_files() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let t = |name: &str, body: &str| {
        format!(
            "require \"test_helper\"\n\nclass {name}Test < ActiveSupport::TestCase\n{body}end\n"
        )
    };
    let files: Vec<(String, String)> = vec![
        (
            "test/refuse/backtick_test.rb".into(),
            t(
                "Backtick",
                "  test \"shells out\" do\n    assert_equal \"hi\\n\", `echo hi`\n  end\n",
            ),
        ),
        (
            "test/refuse/system_test.rb".into(),
            t(
                "System",
                "  test \"runs a command\" do\n    assert system(\"true\")\n  end\n",
            ),
        ),
        (
            "test/refuse/fail_test.rb".into(),
            t(
                "Fail",
                "  test \"fails\" do\n    assert_equal 1, 2\n  end\n",
            ),
        ),
        (
            "test/refuse/skip_test.rb".into(),
            t(
                "Skip",
                "  test \"skips\" do\n    skip \"elsewhere\"\n  end\n\n  test \"passes\" do\n    assert true\n  end\n",
            ),
        ),
        (
            "test/refuse/noassert_test.rb".into(),
            t(
                "Noassert",
                "  test \"asserts nothing\" do\n    Calc.add(1, 2)\n  end\n",
            ),
        ),
        (
            "test/refuse/envall_test.rb".into(),
            t(
                "Envall",
                "  test \"enumerates ENV\" do\n    assert ENV.to_h.key?(\"PATH\")\n  end\n",
            ),
        ),
        (
            "test/refuse/write_test.rb".into(),
            t(
                "Write",
                "  test \"writes into app/\" do\n    File.write(Rails.root.join(\"app/out.txt\"), \"x\")\n    File.delete(Rails.root.join(\"app/out.txt\"))\n    assert true\n  end\n",
            ),
        ),
        (
            "test/refuse/outside_test.rb".into(),
            t(
                "Outside",
                "  test \"reads outside the repository\" do\n    assert File.read(ENV.fetch(\"VCI_E2E_OUTSIDE\")).size > 0\n  end\n",
            ),
        ),
        (
            "test/refuse/socket_test.rb".into(),
            t(
                "Socket",
                "  test \"opens a socket\" do\n    require \"socket\"\n    assert_raises(SystemCallError) { TCPSocket.new(\"127.0.0.1\", 1) }\n  end\n",
            ),
        ),
    ];
    for (rel, body) in &files {
        w.put(rel, body);
    }
    // Allowed: writing to (and reading back from) the git-ignored tmp/
    // (attested on its own below: the files above change the repository
    // while they run, which refuses whatever runs beside them).
    w.put(
        "test/refuse/scratch_test.rb",
        &t(
            "Scratch",
            "  test \"uses tmp\" do\n    p = Rails.root.join(\"tmp/scratch.txt\")\n    File.write(p, \"ok\")\n    assert_equal \"ok\", File.read(p)\n  end\n",
        ),
    );
    let outside = w.base.join("outside.txt");
    std::fs::write(&outside, "outside the repository").unwrap();
    let mut args = vec!["run"];
    args.extend(files.iter().map(|(rel, _)| rel.as_str()));
    args.extend(["--key", w.trusted.to_str().unwrap()]);
    let out = w.vci_env(
        &work,
        &args,
        &[("VCI_E2E_OUTSIDE", outside.to_str().unwrap())],
    );
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert_ne!(out.status.code(), Some(0), "the failing test fails vci run");
    let refused = |id: &str, why: &str| {
        let line = stderr
            .lines()
            .find(|l| l.starts_with(&format!("vci: not attesting {id}:")))
            .unwrap_or_else(|| panic!("{id} was not refused:\n{stderr}"));
        assert!(line.contains(why), "{id}: expected {why:?} in {line:?}");
    };
    refused("test/refuse/backtick_test.rb", "process:backtick");
    refused("test/refuse/system_test.rb", "process:system");
    refused("test/refuse/fail_test.rb", "result failed");
    refused("test/refuse/skip_test.rb", "1 skipped");
    refused("test/refuse/noassert_test.rb", "no-assertions");
    refused("test/refuse/envall_test.rb", "env:enumerated");
    refused(
        "test/refuse/write_test.rb",
        "wrote inside the repository: app/out.txt",
    );
    refused(
        "test/refuse/outside_test.rb",
        "input outside the repository",
    );
    refused("test/refuse/socket_test.rb", "network:TCPSocket.new");
    assert!(
        stderr.contains("vci: 0 attested, 9 not attested"),
        "{stderr}"
    );
    let stored = AttestStore::new(&store_for(&work)).list(None).unwrap();
    assert!(stored.is_empty(), "nothing may be stored: {stored:?}");
    let scratch = w.run(&work, &["test/refuse/scratch_test.rb"], &w.trusted);
    assert!(scratch.contains("1 attested, 0 not attested"), "{scratch}");
    assert!(work.join("tmp/scratch.txt").exists());
    let p = w.plan(&work, "main");
    for (rel, _) in &files {
        assert!(p.run.contains(rel.as_str()), "{rel} must run: {p:?}");
    }
    assert!(p.skip.contains("test/refuse/scratch_test.rb"), "{p:?}");
    // Running it again (tmp/scratch.txt now exists, and is truncated before
    // it is read) attests the same inputs.
    let again = w.run(&work, &["test/refuse/scratch_test.rb"], &w.trusted);
    assert!(again.contains("1 attested, 0 not attested"), "{again}");
    assert_eq!(
        AttestStore::new(&store_for(&work))
            .list(Some("test/refuse/scratch_test.rb"))
            .unwrap()
            .len(),
        1,
        "the same inputs, the same key"
    );
}

/// A database server is refused unless `policy.rails_allow_db` is set at the
/// base commit. The "server" here is SQLite registered under another adapter
/// name (`vcifake`), which vci cannot tell from PostgreSQL or MySQL, with its
/// file in the process's fresh temp dir (a SQLite file anywhere else would be
/// refused as a database vci did not prepare).
#[test]
fn rails_database_server_needs_the_base_policy_waiver() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put(
        "config/initializers/vcifake.rb",
        "require \"active_record/tasks/database_tasks\"\nActiveRecord::ConnectionAdapters.register(\"vcifake\", \"ActiveRecord::ConnectionAdapters::SQLite3Adapter\", \"active_record/connection_adapters/sqlite3_adapter\")\nActiveRecord::Tasks::DatabaseTasks.register_task(/vcifake/, \"ActiveRecord::Tasks::SQLiteDatabaseTasks\")\n",
    );
    let db = w.read("config/database.yml");
    w.put(
        "config/database.yml",
        &db.replace(
            "test:\n  <<: *default\n  database: db/test.sqlite3",
            "test:\n  adapter: vcifake\n  database: <%= File.join(Dir.tmpdir, \"vcifake.sqlite3\") %>",
        ),
    );
    let out = w.vci(&work, &["run", B, "--key", w.trusted.to_str().unwrap()]);
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        stderr.contains("rails:network-db:vcifake"),
        "refused without the policy: {stderr}"
    );
    // With the policy in the working tree, the file is attested with the
    // refusal waived and the server version in the toolchain...
    let toml = w.read("vci.toml");
    w.put(
        "vci.toml",
        &toml.replace(
            "platform = \"any\"",
            "platform = \"any\"\nrails_allow_db = true",
        ),
    );
    let stderr = w.run(&work, &[B], &w.trusted);
    assert!(stderr.contains("1 attested"), "{stderr}");
    let stored = AttestStore::new(&store_for(&work)).list(Some(B)).unwrap();
    let env: Value = serde_json::from_slice(&stored[0].bytes).unwrap();
    let payload = base64::engine::general_purpose::STANDARD
        .decode(env["payload"].as_str().unwrap())
        .unwrap();
    let st: Value = serde_json::from_slice(&payload).unwrap();
    assert!(
        st["predicate"]["waived"][0]
            .as_str()
            .unwrap()
            .starts_with("rails:network-db:vcifake"),
        "{}",
        st["predicate"]["waived"]
    );
    assert!(
        st["predicate"]["toolchain"]["rubyDb"]
            .as_str()
            .unwrap()
            .starts_with("vcifake "),
        "the server version is part of the toolchain"
    );
    // ...but it is only accepted while the BASE commit's policy waives it.
    w.git(&work, &["add", "-A"]);
    w.git(
        &work,
        &["commit", "-q", "-m", "PR: allow the test database"],
    );
    assert!(
        w.plan(&work, "main").run.contains(B),
        "main does not allow it"
    );
    assert!(
        w.plan(&work, "HEAD").skip.contains(B),
        "control: a base that allows it"
    );
}

#[test]
fn rails_push_fetch_fresh_clone_and_ci() {
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
    assert_eq!(w.plan(&fresh, "main"), before, "same plan after fetch");

    // `vci ci` runs only A and D, each in its own `bin/rails test` process
    // with a fresh database, and writes an audit log of the skips.
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
    assert!(
        stderr.contains("bin/rails test test/lib/a_test.rb"),
        "{stderr}"
    );
    assert!(
        stderr.contains("bin/rails test test/controllers/d_test.rb"),
        "{stderr}"
    );
    assert!(!stderr.contains("b_test.rb"), "B must not run: {stderr}");
    assert!(
        !fresh.join("db/test.sqlite3").exists(),
        "the database is prepared in a temp dir"
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

    // A failing test among the remainder makes `vci ci` exit non-zero.
    std::fs::write(
        fresh.join("test/zfail_test.rb"),
        "require \"test_helper\"\n\nclass ZfailTest < ActiveSupport::TestCase\n  test \"fails\" do\n    assert false\n  end\nend\n",
    )
    .unwrap();
    let out = w.vci(&fresh, &["ci", "--base-ref", "main"]);
    assert_ne!(out.status.code(), Some(0), "a failing test fails vci ci");
    std::fs::remove_file(fresh.join("test/zfail_test.rb")).unwrap();

    // Nothing is skipped on refs in no_skip_refs.
    w.git(&fresh, &["checkout", "-q", "-b", "release/1"]);
    let p = w.plan(&fresh, "main");
    assert!(p.run_all && p.skip.is_empty(), "{p:?}");
}

/// False skips found by adversarial review, in a real Rails app under
/// Bundler (Ruby 3.4's bundled_gems.rb redefines `require` there): each file
/// is either refused, or attested with the input that decides it, so
/// changing that input runs it.
#[test]
fn rails_inputs_that_used_to_be_missed() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let t = |name: &str, body: &str| {
        format!(
            "require \"test_helper\"\n\nclass {name}Test < ActiveSupport::TestCase\n  test \"it\" do\n{body}  end\nend\n"
        )
    };
    // Attested; each must run once the input it depends on changes.
    w.put("ext1/.keep", "");
    w.put("ext2/feat.rb", "FEAT = \"ext2\"\n");
    w.put(
        "test/attack/shadow_test.rb",
        &t(
            "Shadow",
            "    $LOAD_PATH.unshift(Rails.root.join(\"ext2\").to_s)\n    $LOAD_PATH.unshift(Rails.root.join(\"ext1\").to_s)\n    require \"feat\"\n    assert_equal \"ext2\", FEAT\n",
        ),
    );
    w.put("d3/dopen/a", "");
    w.put("d3/dopen/b", "");
    w.put(
        "test/attack/dir_open_test.rb",
        &t(
            "DirOpen",
            "    assert_equal %w[a b], Dir.open(Rails.root.join(\"d3/dopen\")) { |d| d.children.sort }\n    assert_raises(Errno::ENOENT) { Dir.open(Rails.root.join(\"d3/nodir\")) }\n",
        ),
    );
    // Refused.
    let refused_files = [
        (
            "test/attack/pty_test.rb",
            t(
                "Pty",
                "    require \"pty\"\n    PTY.spawn(\"true\") { |_r, _w, pid| Process.wait(pid) }\n    assert true\n",
            ),
            "process:PTY.spawn",
        ),
        (
            "test/attack/fiddle_test.rb",
            t(
                "Fiddle",
                "    require \"fiddle\"\n    assert Fiddle.dlopen(nil)\n",
            ),
            "native:Fiddle",
        ),
        (
            "test/attack/mtime_test.rb",
            t(
                "Mtime",
                "    assert File.mtime(Rails.root.join(\"data/mt_new\")) >= File.mtime(Rails.root.join(\"data/mt_old\"))\n",
            ),
            "ruby:file-metadata:File.mtime of data/mt_new",
        ),
        (
            "test/attack/leak_test.rb",
            t(
                "Leak",
                "    m = Rails.root.join(\"tmp/marker\")\n    prev = File.exist?(m) ? File.read(m) : \"none\"\n    File.write(m, \"seen\")\n    assert_equal \"seen\", prev\n",
            ),
            "tmp/marker",
        ),
        (
            "test/attack/atomic_leak_test.rb",
            t(
                "AtomicLeak",
                "    m = Rails.root.join(\"tmp/amarker\")\n    prev = File.exist?(m) ? File.read(m) : \"none\"\n    File.atomic_write(m) { |f| f.write(\"seen\") }\n    assert_equal \"seen\", prev\n",
            ),
            "tmp/amarker",
        ),
    ];
    w.put("data/mt_old", "o");
    w.put("data/mt_new", "n");
    // Left by an earlier run (git-ignored): the leak test passes only
    // because of it.
    w.put("tmp/marker", "seen");
    w.put("tmp/amarker", "seen");
    // Git-ignored, read by Active Record at boot when present.
    w.put("config/master.key", "0123456789abcdef0123456789abcdef");
    for (rel, body, _) in &refused_files {
        w.put(rel, body);
    }

    let mut args = vec!["run"];
    args.extend(refused_files.iter().map(|(rel, _, _)| *rel));
    args.extend(["--key", w.trusted.to_str().unwrap()]);
    let out = w.vci(&work, &args);
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    for (rel, _, why) in &refused_files {
        let line = stderr
            .lines()
            .find(|l| l.starts_with(&format!("vci: not attesting {rel}:")))
            .unwrap_or_else(|| panic!("{rel} was not refused:\n{stderr}"));
        assert!(line.contains(why), "{rel}: expected {why:?} in {line:?}");
    }
    assert!(
        AttestStore::new(&store_for(&work))
            .list(None)
            .unwrap()
            .is_empty()
    );

    // Writing and reading back its own scratch file (File.atomic_write
    // copies permissions from a probe file it deletes) is fine.
    w.put(
        "test/attack/atomic_own_test.rb",
        &t(
            "AtomicOwn",
            "    p = Rails.root.join(\"tmp/own_atomic.txt\")\n    File.atomic_write(p) { |f| f.write(\"x\") }\n    assert_equal \"x\", File.read(p)\n",
        ),
    );
    let ok = w.run(
        &work,
        &[
            "test/attack/shadow_test.rb",
            "test/attack/dir_open_test.rb",
            "test/attack/atomic_own_test.rb",
        ],
        &w.trusted,
    );
    assert!(ok.contains("3 attested, 0 not attested"), "{ok}");
    assert!(
        ok.contains("it read config/master.key, Rails' credentials key"),
        "the master.key hint: {ok}"
    );
    let p = w.plan(&work, "main");
    assert!(p.skip.contains("test/attack/shadow_test.rb"), "{p:?}");
    assert!(p.skip.contains("test/attack/dir_open_test.rb"), "{p:?}");

    w.put("ext1/feat.rb", "FEAT = \"ext1\"\n");
    w.put("d3/dopen/c", "");
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains("test/attack/shadow_test.rb"),
        "a file shadowing the required one runs it: {p:?}"
    );
    assert!(
        p.run.contains("test/attack/dir_open_test.rb"),
        "a new entry in a directory read through Dir.open runs it: {p:?}"
    );
    std::fs::remove_file(work.join("ext1/feat.rb")).unwrap();
    std::fs::remove_file(work.join("d3/dopen/c")).unwrap();
    std::fs::create_dir_all(work.join("d3/nodir")).unwrap();
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains("test/attack/dir_open_test.rb"),
        "a directory Dir.open found absent runs it once it exists: {p:?}"
    );
}

#[test]
fn rails_init_writes_the_rails_template() {
    let Some(w) = World::new() else { return };
    let dir = w.base.join("initme");
    copy_rails_fixture(&dir);
    w.git(&w.base, &["init", "-q", dir.to_str().unwrap()]);
    w.git(&dir, &["add", "-A"]);
    w.git(&dir, &["commit", "-q", "-m", "app"]);
    let key = format!("{}.pub", w.trusted.display());
    let out = w.vci_ok(
        &dir,
        &["init", "--adapter", "rails", "--key", &key, "--no-install"],
    );
    assert!(
        out.contains("ruby/setup-ruby"),
        "the Rails CI snippet: {out}"
    );
    let toml = std::fs::read_to_string(dir.join("vci.toml")).unwrap();
    assert!(toml.contains("adapter = \"rails\""), "{toml}");
    assert!(toml.contains("rails_allow_db = false"), "{toml}");
    let signers = std::fs::read_to_string(dir.join(".vci/allowed_signers")).unwrap();
    assert!(signers.contains(&pubkey(&w.trusted)), "{signers}");
}
