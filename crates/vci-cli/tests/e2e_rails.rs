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

    /// A command of the fixture's Ruby (`ruby`, `bundle`) in `dir`, with the
    /// scrubbed environment.
    fn ruby_cmd(&self, dir: &Path, tool: &str, args: &[&str]) -> Output {
        let mut cmd = Command::new(self.ruby_bin.join(tool));
        cmd.args(args).current_dir(dir).env("PATH", self.path_env());
        for k in SCRUB {
            cmd.env_remove(k);
        }
        cmd.output().unwrap()
    }

    /// Install the bundle inside the repository copy, as ruby/setup-ruby's
    /// `bundler-cache` does on GitHub Actions (`BUNDLE_PATH=vendor/bundle`):
    /// `bundle config set --local path vendor/bundle` (in the git-ignored
    /// `.bundle/config`), then `bundle install --local` from the `.gem`
    /// archives this Ruby already has (copied into `vendor/cache`, removed
    /// afterwards), else `bundle install` from rubygems.org. false (with a
    /// SKIPPED message) when neither works (offline, no archives).
    fn bundle_into_vendor(&self, dir: &Path) -> bool {
        let out = self.ruby_cmd(
            dir,
            "bundle",
            &["config", "set", "--local", "path", "vendor/bundle"],
        );
        assert!(out.status.success(), "{out:?}");
        let copy = r##"require "fileutils"
want = File.read("Gemfile.lock").scan(/^    (\S+) \(([^)]+)\)$/).map { |n, v| "#{n}-#{v}" }
FileUtils.mkdir_p("vendor/cache")
Gem.path.each do |p|
  Dir[File.join(p, "cache", "*.gem")].each do |g|
    b = File.basename(g, ".gem")
    FileUtils.cp(g, "vendor/cache") if want.any? { |n| b == n || b.start_with?("#{n}-") }
  end
end"##;
        let out = self.ruby_cmd(dir, "ruby", &["-e", copy]);
        assert!(out.status.success(), "{out:?}");
        let mut out = self.ruby_cmd(dir, "bundle", &["install", "--local"]);
        if !out.status.success() {
            out = self.ruby_cmd(dir, "bundle", &["install"]);
        }
        let _ = std::fs::remove_dir_all(dir.join("vendor/cache"));
        if !out.status.success() {
            eprintln!(
                "SKIPPED: could not install the bundle into vendor/bundle (offline?): {}{}",
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

/// Two self-signed CA certificates (valid until 2126).
const CA_0: &str = "-----BEGIN CERTIFICATE-----
MIIBYTCCAQegAwIBAgIBATAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAx2Y2kgZTJl
IENBIDAwIBcNMjYwMTAxMDAwMDAwWhgPMjEyNjAxMDEwMDAwMDBaMBcxFTATBgNV
BAMMDHZjaSBlMmUgQ0EgMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEPN+Ma3
XiBRJma9xCZvozbHL3JPkG2ihfRcVzucNCT1hWSkkY/sxswA7vWmjfmGugzi4tzd
eezmovCDu1BKhHCjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEG
MB0GA1UdDgQWBBRwmR0IRySHH6Ew44dNXqIrxfrI/DAKBggqhkjOPQQDAgNIADBF
AiA4YDPVwBaEgX3f+SWIhCwT2agy8+jSOD3f7bg/5E+ntgIhALj9KRZxIGw2wnoe
g7LxE+voXybAqPVCTb1XrkTk+bB2
-----END CERTIFICATE-----
";
const CA_1: &str = "-----BEGIN CERTIFICATE-----
MIIBYjCCAQegAwIBAgIBAjAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAx2Y2kgZTJl
IENBIDEwIBcNMjYwMTAxMDAwMDAwWhgPMjEyNjAxMDEwMDAwMDBaMBcxFTATBgNV
BAMMDHZjaSBlMmUgQ0EgMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ6URxhu
momt+7WLZTfwFuMPQLBSSibmYklkV5m5VW765r4kJJI9lnmunUcXuld21QXQ9Ybs
B+l2GITnYEBTtbWjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEG
MB0GA1UdDgQWBBRnlRC7OGj3WChzscKRdlsHX7CJtzAKBggqhkjOPQQDAgNJADBG
AiEAmfymMNZTvFZDmGxdu2JShhmeRD+IcuNVRTsSzoQDYywCIQCz5LDvTQMD+aHK
7am63QbWXz8PjOM2IU1U2wNe+YVuJw==
-----END CERTIFICATE-----
";

/// Regressions (false skips): files named "~note.txt" or "|pipe.txt" read
/// with File (opened literally, never recorded); a certificate file
/// OpenSSL reads in C (`X509::Store#add_file`); a repository directory read
/// through a symlink in vci's temp dir that the test removes. Each is
/// attested with its file as an input, and changing the file runs it.
/// Verifying against OpenSSL's default paths and reading the uid are
/// refused.
#[test]
fn rails_files_named_oddly_read_in_c_or_through_links() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let t = |name: &str, body: &str| {
        format!(
            "require \"test_helper\"\n\nclass {name}Test < ActiveSupport::TestCase\n  test \"it\" do\n{body}  end\nend\n"
        )
    };
    const TILDE: &str = "test/odd/tilde_test.rb";
    const PIPE: &str = "test/odd/pipe_test.rb";
    const OSSL: &str = "test/odd/ossl_store_test.rb";
    const LINK: &str = "test/odd/tmp_link_test.rb";
    w.put("~note.txt", "hello");
    w.put("|pipe.txt", "p");
    w.put("certs/ca.pem", CA_0);
    w.put("certs/ca_copy.pem", CA_0);
    w.put("data/dirx/x.txt", "x");
    w.put(
        TILDE,
        &t(
            "Tilde",
            "    assert_equal \"hello\", File.read(\"~note.txt\")\n",
        ),
    );
    w.put(
        PIPE,
        &t(
            "Pipe",
            "    assert_equal \"p\", File.open(\"|pipe.txt\", &:read)\n",
        ),
    );
    w.put(
        OSSL,
        &t(
            "OsslStore",
            "    require \"openssl\"\n    st = OpenSSL::X509::Store.new\n    st.add_file(\"certs/ca.pem\")\n    assert st.verify(OpenSSL::X509::Certificate.new(File.binread(\"certs/ca_copy.pem\")))\n",
        ),
    );
    // VciCollector::TMP: the temp dir vci gave the process (ENV["TMPDIR"]
    // would be an env input whose value differs per run).
    w.put(
        LINK,
        &t(
            "TmpLink",
            "    link = File.join(VciCollector::TMP, \"fx\")\n    File.symlink(Rails.root.join(\"data/dirx\").to_s, link)\n    body = File.read(File.join(link, \"x.txt\"))\n    File.unlink(link)\n    assert_equal \"x\", body\n",
        ),
    );
    let refused_files = [
        (
            "test/odd/ossl_default_test.rb",
            t(
                "OsslDefault",
                "    require \"openssl\"\n    st = OpenSSL::X509::Store.new\n    st.set_default_paths\n    refute st.verify(OpenSSL::X509::Certificate.new(File.binread(\"certs/ca_copy.pem\")))\n",
            ),
            "native:openssl:X509::Store#verify",
        ),
        (
            "test/odd/identity_test.rb",
            t("Identity", "    assert Process.uid >= 0\n"),
            "ruby:process-identity:Process.uid",
        ),
    ];
    for (rel, body, _) in &refused_files {
        w.put(rel, body);
    }
    let mut files = vec![TILDE, PIPE, OSSL, LINK];
    files.extend(refused_files.iter().map(|(rel, _, _)| *rel));
    let stderr = strip_ansi(&w.run(&work, &files, &w.trusted));
    assert!(
        stderr.contains("vci: 4 attested, 2 not attested"),
        "{stderr}"
    );
    for (rel, _, why) in &refused_files {
        let line = stderr
            .lines()
            .find(|l| l.starts_with(&format!("vci: not attesting {rel}:")))
            .unwrap_or_else(|| panic!("{rel} was not refused:\n{stderr}"));
        assert!(line.contains(why), "{rel}: expected {why:?} in {line:?}");
    }
    for (id, input) in [
        (TILDE, "~note.txt"),
        (PIPE, "|pipe.txt"),
        (OSSL, "certs/ca.pem"),
        (LINK, "data/dirx/x.txt"),
    ] {
        let entries = stored_predicate(&work, id)["manifest"]["entries"].clone();
        assert!(
            entries
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["path"] == input),
            "{id}: {input} not in {entries}"
        );
    }
    let p = w.plan(&work, "main");
    for id in [TILDE, PIPE, OSSL, LINK] {
        assert!(p.skip.contains(id), "{id}: {p:?}");
    }
    w.put("~note.txt", "CHANGED");
    w.put("|pipe.txt", "CHANGED");
    w.put("certs/ca.pem", CA_1);
    w.put("data/dirx/x.txt", "CHANGED");
    let p = w.plan(&work, "main");
    for id in [TILDE, PIPE, OSSL, LINK] {
        assert!(
            p.run.contains(id),
            "{id} must run once its input changed: {p:?}"
        );
    }
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

/// The predicate stored for `id` (the newest one).
fn stored_predicate(work: &Path, id: &str) -> Value {
    let stored = AttestStore::new(&store_for(work)).list(Some(id)).unwrap();
    let env: Value = serde_json::from_slice(&stored.last().unwrap().bytes).unwrap();
    let payload = base64::engine::general_purpose::STANDARD
        .decode(env["payload"].as_str().unwrap())
        .unwrap();
    let st: Value = serde_json::from_slice(&payload).unwrap();
    st["predicate"].clone()
}

/// A Minitest file that never loads Rails (it requires only minitest and a
/// plain Ruby file) is attested and skipped. Regression: its collector
/// reported the Rails version as "" and the file was refused ("toolchain
/// seen by the collector (... rails , ...) differs from the project's").
#[test]
fn rails_minitest_file_that_never_loads_rails() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let plain = "test/lib/plain_test.rb";
    w.put(
        plain,
        "require \"minitest\"\nrequire_relative \"../../lib/calc\"\n\nclass PlainTest < Minitest::Test\n  def test_add\n    assert_equal 3, Calc.add(1, 2)\n  end\nend\n",
    );
    w.git(&work, &["add", "-A"]);
    w.git(&work, &["commit", "-q", "-m", "plain test"]);
    let stderr = w.run(&work, &[plain], &w.trusted);
    assert!(
        stderr.contains("vci: 1 attested, 0 not attested"),
        "{stderr}"
    );
    assert_eq!(
        stored_predicate(&work, plain)["toolchain"]["rails"],
        "8.1.3.1",
        "the bundle's railties"
    );
    assert!(w.plan(&work, "main").skip.contains(plain));
    w.put(
        "lib/calc.rb",
        &format!("{}# edited\n", w.read("lib/calc.rb")),
    );
    assert!(w.plan(&work, "main").run.contains(plain));
}

/// The Ruby collector reached through a symlinked install prefix (Homebrew's
/// `opt/vci` -> `Cellar/vci/<version>`), given as `VCI_RUBY_COLLECTOR` and
/// found next to the executable: its own file is never an input.
#[test]
fn rails_collector_behind_a_symlinked_install_prefix() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let prefix = w.base.join("Cellar/vci/1.1.0");
    let share = prefix.join("share/vci/ruby-collector");
    std::fs::create_dir_all(&share).unwrap();
    std::fs::copy(
        workspace_root().join("ruby/vci-collector/vci_collector.rb"),
        share.join("vci_collector.rb"),
    )
    .unwrap();
    std::fs::create_dir_all(prefix.join("bin")).unwrap();
    std::fs::copy(assert_cmd::cargo::cargo_bin("vci"), prefix.join("bin/vci")).unwrap();
    std::fs::create_dir_all(w.base.join("opt")).unwrap();
    std::os::unix::fs::symlink("../Cellar/vci/1.1.0", w.base.join("opt/vci")).unwrap();
    let linked = w.base.join("opt/vci/share/vci/ruby-collector");
    let out = w.vci_env(
        &work,
        &["run", A, "--key", w.trusted.to_str().unwrap()],
        &[("VCI_RUBY_COLLECTOR", linked.to_str().unwrap())],
    );
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(err.contains("vci: 1 attested, 0 not attested"), "{err}");
    let mut cmd = Command::new(w.base.join("opt/vci/bin/vci"));
    cmd.current_dir(&work)
        .args(["run", B, "--key", w.trusted.to_str().unwrap()])
        .env("PATH", w.path_env())
        .env("GIT_CONFIG_GLOBAL", &w.gitconfig)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("VCI_RUBY_COLLECTOR");
    for k in SCRUB {
        cmd.env_remove(k);
    }
    let out = cmd.output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(err.contains("vci: 1 attested, 0 not attested"), "{err}");
}

/// Copy `fixtures/rails-vips` (Active Storage with image_processing and
/// ruby-vips in the bundle) into `dir`.
fn copy_vips_fixture(dir: &Path) {
    let fx = workspace_root().join("fixtures/rails-vips");
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
}

/// A 5x4 PNG (the fixture image is 3x2).
const PNG_5X4: &str = "iVBORw0KGgoAAAANSUhEUgAAAAUAAAAECAAAAABjWKqcAAAAtGVYSWZJSSoACAAAAAYAEgEDAAEAAAABAAAAGgEFAAEAAABWAAAAGwEFAAEAAABeAAAAKAEDAAEAAAACAAAAEwIDAAEAAAABAAAAaYcEAAEAAABmAAAAAAAAADhjAADoAwAAOGMAAOgDAAAGAACQBwAEAAAAMDIxMAGRBwAEAAAAAQIDAACgBwAEAAAAMDEwMAGgAwABAAAA//8AAAKgBAABAAAABQAAAAOgBAABAAAABAAAAAAAAAAvTK8RAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAADklEQVQImWNgBAEGDBIAAQgAFaqiGn4AAAAASUVORK5CYII=";

/// Active Storage loads ruby-vips at boot, and ruby-vips opens libvips
/// through FFI. Loading a library is not a read of test inputs (the library
/// is recorded as a `native:` external, hashed); calling into it is, unless
/// the collector sees the files at the Ruby level, as it does for ruby-vips:
/// (a) a model test that never touches storage is attested; (b) a test that
/// attaches a fixture image and analyses it through Active Storage is
/// attested with the image as an input, and editing the image runs it;
/// (c) a test that calls a C function through FFI is refused.
/// Regression: every test that booted Rails was refused (`native:FFI
/// ffi_lib(["vips.42"]) ...`). Skipped where libvips is not installed.
#[test]
fn rails_active_storage_with_libvips() {
    let Some(w) = World::build(VCI_TOML, copy_vips_fixture) else {
        return;
    };
    let vips = Command::new(w.ruby_bin.join("bundle"))
        .args(["exec", "ruby", "-e", "require 'vips'"])
        .current_dir(&w.work)
        .env("PATH", w.path_env())
        .env_remove("RUBYOPT")
        .output()
        .unwrap();
    if !vips.status.success() {
        eprintln!(
            "SKIPPED: libvips is not installed (`brew install vips`): {}",
            String::from_utf8_lossy(&vips.stderr)
        );
        return;
    }
    let work = w.work.clone();
    const CAPTION: &str = "test/models/caption_test.rb";
    const IMAGE: &str = "test/models/image_test.rb";
    const FFI_CALL: &str = "test/lib/ffi_call_test.rb";
    let stderr = w.run(&work, &[CAPTION, IMAGE, FFI_CALL], &w.trusted);
    assert!(
        stderr.contains("vci: 2 attested, 1 not attested"),
        "{stderr}"
    );
    let refused = stderr
        .lines()
        .find(|l| l.starts_with(&format!("vci: not attesting {FFI_CALL}:")))
        .unwrap_or_else(|| panic!("{stderr}"));
    assert!(refused.contains("native:FFI call Libc.getpid"), "{refused}");
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[CAPTION, IMAGE]));
    assert_eq!(p.run, set(&[FFI_CALL]));

    // Both attestations record libvips (by content) as an external.
    for id in [CAPTION, IMAGE] {
        let pred = stored_predicate(&work, id);
        let externals = pred["manifest"]["externals"].as_array().unwrap();
        assert!(
            externals.iter().any(|e| {
                e["name"].as_str().unwrap().starts_with("native:libvips")
                    && e["version"].as_str().unwrap().starts_with("sha256:")
            }),
            "{id}: {externals:?}"
        );
    }
    // (b): the fixture image is an input of the test that analyses it.
    let image = "test/fixtures/files/pixel.png";
    let entries = stored_predicate(&work, IMAGE)["manifest"]["entries"].clone();
    assert!(
        entries
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == image),
        "{entries}"
    );
    let original = std::fs::read(work.join(image)).unwrap();
    std::fs::write(
        work.join(image),
        base64::engine::general_purpose::STANDARD
            .decode(PNG_5X4)
            .unwrap(),
    )
    .unwrap();
    let p = w.plan(&work, "main");
    assert_eq!(
        p.run,
        set(&[IMAGE, FFI_CALL]),
        "editing the image runs (b) only"
    );
    assert!(
        w.explain(&work, IMAGE, "main")
            .contains(&format!("entry:{image}"))
    );
    std::fs::write(work.join(image), original).unwrap();
    assert_eq!(w.plan(&work, "main").skip, set(&[CAPTION, IMAGE]));
}

/// `policy.libraries = "any"` at the base commit: a file that loads libvips
/// through FFI (Active Storage boots ruby-vips) is attested exactly as under
/// "exact" (libvips recorded as `native:<file name>` with its hash) and
/// skipped where a libvips is loaded; `vci plan` and `vci explain` name the
/// policy. Matching another file name and hash by library name (macOS
/// `libvips.42.dylib` vs Linux `libvips.so.42`) is covered by the unit
/// tests of `externals::rails_native`. Skipped where libvips is not
/// installed.
#[test]
fn rails_libraries_any_with_libvips() {
    let toml = VCI_TOML.replace(
        "platform = \"any\"",
        "platform = \"any\"\nlibraries = \"any\"",
    );
    assert!(toml.contains("libraries = \"any\""));
    let Some(w) = World::build(&toml, copy_vips_fixture) else {
        return;
    };
    let vips = Command::new(w.ruby_bin.join("bundle"))
        .args(["exec", "ruby", "-e", "require 'vips'"])
        .current_dir(&w.work)
        .env("PATH", w.path_env())
        .env_remove("RUBYOPT")
        .output()
        .unwrap();
    if !vips.status.success() {
        eprintln!(
            "SKIPPED: libvips is not installed (`brew install vips`): {}",
            String::from_utf8_lossy(&vips.stderr)
        );
        return;
    }
    let work = w.work.clone();
    const CAPTION: &str = "test/models/caption_test.rb";
    let stderr = w.run(&work, &[CAPTION], &w.trusted);
    assert!(
        stderr.contains("vci: 1 attested, 0 not attested"),
        "{stderr}"
    );
    // What is recorded does not depend on the policy.
    let pred = stored_predicate(&work, CAPTION);
    let native = pred["manifest"]["externals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"].as_str().unwrap().starts_with("native:libvips"))
        .unwrap_or_else(|| panic!("{pred}"))
        .clone();
    assert!(
        native["version"].as_str().unwrap().starts_with("sha256:"),
        "{native}"
    );
    assert!(!pred["toolchain"]["rubyLibs"].as_str().unwrap().is_empty());

    let p = w.plan(&work, "main");
    assert!(p.skip.contains(CAPTION), "{p:?}");
    let out = w.vci_ok(&work, &["plan", "--base-ref", "main", "--format", "json"]);
    let v: Value = serde_json::from_str(&out).unwrap();
    let f = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["testId"] == CAPTION)
        .unwrap();
    assert_eq!(f["libraries"], "any", "{f}");
    assert_eq!(f["skip"], true, "{f}");
    let ex = w.explain(&work, CAPTION, "main");
    assert!(
        ex.contains(&format!("{CAPTION}: SKIP (attested by")),
        "{ex}"
    );
    assert!(
        ex.contains(
            "policy: libraries = \"any\" (base vci.toml): native libraries match by library name"
        ),
        "{ex}"
    );
    assert!(ex.contains("all checks passed"), "{ex}");
    // Same machine, same libvips: nothing needed the policy.
    assert!(!ex.contains("accepted by policy.libraries"), "{ex}");

    // An edited input of the file still runs it under "any".
    let model = "app/models/photo.rb";
    let original = w.read(model);
    w.put(model, &format!("{original}\n# edited\n"));
    let p = w.plan(&work, "main");
    assert!(p.run.contains(CAPTION), "{p:?}");
    let ex = w.explain(&work, CAPTION, "main");
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(ex.contains("policy: libraries = \"any\""), "{ex}");
    w.put(model, &original);
    assert!(w.plan(&work, "main").skip.contains(CAPTION));
}

/// The bundle installed inside the repository, as ruby/setup-ruby's
/// `bundler-cache: true` does on GitHub Actions (`BUNDLE_PATH=vendor/bundle`,
/// gems under `vendor/bundle/ruby/<abi>`). Regression: every file was
/// refused with `ruby:read-outside-bundle:stat .../vendor/bundle/ruby/3.4.0`
/// (+50 more: RubyGems' and Bundler's checks of the bundle's directories and
/// reads of its `.gemspec`s, and `realpath`'s checks of each directory above
/// a gem, which Rails::Engine.find_root makes). The bundle's directories are
/// not inputs and gems stay externals, so the files attest and are skipped;
/// a file there that belongs to no gem of the bundle is still refused, also
/// when a test has RubyGems or Bundler read, list or evaluate it for it
/// (`Gem.read_binary`, `Bundler.read_file`, `Gem::Util.glob_files_in_dir`,
/// `Gem::Specification.load`: they attested, and stayed skipped after the
/// file changed), and so are a test's own checks of where the bundle is
/// installed (`File.directory?("vendor/bundle")`, `File.realpath` of a gem's
/// directory: they attested with no record of it).
#[test]
fn rails_bundle_installed_in_the_repository() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    if !w.bundle_into_vendor(&work) {
        return;
    }
    let scopes: Vec<String> = std::fs::read_dir(work.join("vendor/bundle/ruby"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(scopes.len(), 1, "{scopes:?}");
    let gems = format!("vendor/bundle/ruby/{}", scopes[0]);
    assert!(work.join(&gems).join("gems/hashids-1.0.6").is_dir());
    // Something installed there that is not in the bundle: a gem directory
    // and its gemspec (RubyGems reads the stub line of every gemspec there
    // at boot: that is its bookkeeping, not an input), and another Ruby's
    // gems.
    let stray = format!("{gems}/gems/notinbundle-1.0/lib/notinbundle_x.rb");
    w.put(&stray, "NOTINBUNDLE_X = 1\n");
    let stray_code = format!("{gems}/gems/notinbundle-1.0/lib/notinbundle_g.rb");
    w.put(&stray_code, "$notinbundle_g = 1\n");
    let stray_spec = format!("{gems}/specifications/notinbundle-1.0.gemspec");
    w.put(
        &stray_spec,
        "# -*- encoding: utf-8 -*-\n# stub: notinbundle 1.0 ruby lib\n\n$notinbundle_spec = 1\nGem::Specification.new do |s|\n  s.name = \"notinbundle\"\n  s.version = \"1.0\"\n  s.summary = \"x\"\n  s.authors = [\"x\"]\n  s.require_paths = [\"lib\"]\n  s.files = [\"lib/notinbundle_x.rb\"]\nend\n",
    );
    w.put("vendor/bundle/ruby/0.0.0/gems/old-1.0/README", "old\n");
    let t = |name: &str, body: &str| {
        format!(
            "require \"test_helper\"\n\nclass {name}Test < ActiveSupport::TestCase\n  test \"x\" do\n{body}  end\nend\n"
        )
    };
    let gem_read = "test/lib/gem_read_test.rb";
    w.put(
        gem_read,
        &t(
            "GemRead",
            "    spec = Gem.loaded_specs.fetch(\"hashids\")\n    assert_includes spec.full_gem_path, \"/vendor/bundle/\"\n    assert_includes File.read(File.join(spec.full_gem_path, \"lib/hashids.rb\")), \"class Hashids\"\n",
        ),
    );
    let stray_abs = format!("Rails.root.join(\"{stray}\").to_s");
    let refused: Vec<(&str, String, &str)> = vec![
        (
            "test/refuse/require_stray_test.rb",
            t(
                "RequireStray",
                &format!("    require {stray_abs}\n    assert_equal 1, NOTINBUNDLE_X\n"),
            ),
            "ruby:gem-outside-bundle:",
        ),
        (
            "test/refuse/read_stray_test.rb",
            t(
                "ReadStray",
                &format!("    assert_equal \"NOTINBUNDLE_X = 1\\n\", File.read({stray_abs})\n"),
            ),
            "ruby:read-outside-bundle:read ",
        ),
        (
            "test/refuse/stat_stray_test.rb",
            t(
                "StatStray",
                &format!("    assert File.exist?({stray_abs})\n"),
            ),
            "ruby:read-outside-bundle:stat ",
        ),
        (
            "test/refuse/read_binary_test.rb",
            t(
                "ReadBinary",
                &format!(
                    "    assert_equal \"NOTINBUNDLE_X = 1\\n\", Gem.read_binary({stray_abs})\n"
                ),
            ),
            "ruby:read-outside-bundle:read ",
        ),
        (
            "test/refuse/bundler_read_test.rb",
            t(
                "BundlerRead",
                &format!(
                    "    assert_equal \"NOTINBUNDLE_X = 1\\n\", Bundler.read_file({stray_abs})\n"
                ),
            ),
            "ruby:read-outside-bundle:read ",
        ),
        (
            "test/refuse/glob_stray_test.rb",
            t(
                "GlobStray",
                &format!(
                    "    names = Gem::Util.glob_files_in_dir(\"**/*\", Rails.root.join(\"{gems}/gems/notinbundle-1.0\").to_s)\n    assert_includes names.map {{ |f| File.basename(f) }}, \"notinbundle_x.rb\"\n"
                ),
            ),
            "ruby:read-outside-bundle:readdir ",
        ),
        (
            "test/refuse/eval_stray_test.rb",
            t(
                "EvalStray",
                &format!(
                    "    Gem::Specification.load(Rails.root.join(\"{stray_code}\").to_s)\n    assert_equal 1, $notinbundle_g\n"
                ),
            ),
            "ruby:read-outside-bundle:read ",
        ),
        (
            "test/refuse/eval_stray_gemspec_test.rb",
            t(
                "EvalStrayGemspec",
                &format!(
                    "    Gem::Specification.load(Rails.root.join(\"{stray_spec}\").to_s)\n    assert_equal 1, $notinbundle_spec\n"
                ),
            ),
            "ruby:read-outside-bundle:read ",
        ),
        (
            "test/refuse/bundle_dir_test.rb",
            t(
                "BundleDir",
                "    assert File.directory?(Rails.root.join(\"vendor/bundle\"))\n",
            ),
            "ruby:read-outside-bundle:stat ",
        ),
        (
            "test/refuse/realpath_gem_test.rb",
            t(
                "RealpathGem",
                "    assert_includes File.realpath(Gem.loaded_specs.fetch(\"hashids\").full_gem_path), \"/vendor/bundle/\"\n",
            ),
            "ruby:read-outside-bundle:stat ",
        ),
        (
            "test/refuse/other_ruby_test.rb",
            t(
                "OtherRuby",
                "    assert_includes File.read(Rails.root.join(\"vendor/bundle/ruby/0.0.0/gems/old-1.0/README\")), \"old\"\n",
            ),
            "ruby:read-outside-bundle:read ",
        ),
    ];
    for (rel, body, _) in &refused {
        w.put(rel, body);
    }
    w.git(&work, &["add", "test"]);
    w.git(
        &work,
        &["commit", "-q", "-m", "tests of the in-repository bundle"],
    );
    assert_eq!(
        w.git(&work, &["status", "--porcelain"]),
        "",
        "vendor/bundle and .bundle are git-ignored"
    );

    let mut files: Vec<&str> = ALL.to_vec();
    files.push(gem_read);
    let stderr = w.run(&work, &files, &w.trusted);
    assert!(
        stderr.contains("vci: 5 attested, 0 not attested"),
        "{stderr}"
    );
    let p = w.plan(&work, "main");
    for f in &files {
        assert!(p.skip.contains(*f), "{f} must be skipped: {p:?}");
    }

    // Nothing under vendor/bundle is an input; gems of the bundle are
    // externals (hashids: required by D, read by gem_read).
    for id in [D, gem_read] {
        let pred = stored_predicate(&work, id);
        let entries = pred["manifest"]["entries"].as_array().unwrap().clone();
        let inside: Vec<&Value> = entries
            .iter()
            .filter(|e| e["path"].as_str().unwrap().starts_with("vendor/bundle"))
            .collect();
        assert!(inside.is_empty(), "{id}: {inside:?}");
        let externals = pred["manifest"]["externals"].as_array().unwrap();
        assert!(
            externals
                .iter()
                .any(|e| e["name"] == "hashids" && e["version"] == "1.0.6"),
            "{id}: {externals:?}"
        );
    }
    // What else is installed there is not an input either.
    w.put(
        &format!("{gems}/gems/notinbundle-1.0/lib/notinbundle_y.rb"),
        "Y = 1\n",
    );
    w.put("vendor/bundle/ruby/0.0.0/gems/old-1.0/README", "older\n");
    let p = w.plan(&work, "main");
    for f in &files {
        assert!(p.skip.contains(*f), "{f} must still be skipped: {p:?}");
    }

    // Code, content and checks of what is not in the bundle are refused.
    let ids: Vec<&str> = refused.iter().map(|(rel, _, _)| *rel).collect();
    let mut args = vec!["run"];
    args.extend(&ids);
    args.extend(["--key", w.trusted.to_str().unwrap()]);
    let out = w.vci(&work, &args);
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    for (rel, _, why) in &refused {
        let line = stderr
            .lines()
            .find(|l| l.starts_with(&format!("vci: not attesting {rel}:")))
            .unwrap_or_else(|| panic!("{rel} was not refused:\n{stderr}"));
        assert!(line.contains(why), "{rel}: expected {why:?} in {line:?}");
        assert!(line.contains("/vendor/bundle"), "{rel}: {line:?}");
        assert!(
            !line.contains("result "),
            "{rel}: the test itself passes: {line:?}"
        );
    }
    assert!(
        stderr.contains(&format!("vci: 0 attested, {} not attested", refused.len())),
        "{stderr}"
    );
}
