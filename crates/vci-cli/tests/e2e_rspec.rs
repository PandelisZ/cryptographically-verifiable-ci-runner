//! End-to-end verification for RSpec under the Rails adapter, mirroring
//! `e2e_rails.rs`: a copy of `fixtures/rails-rspec-abcd` (a Rails 8
//! application with rspec-rails, factory_bot_rails and SQLite) in a
//! throwaway git repo (the base commit holds `.vci/allowed_signers` and
//! `vci.toml`), throwaway SSH keys and a local bare remote.
//!
//! Needs `git`, `ssh-keygen` and the Ruby the fixture pins in `.ruby-version`
//! with its bundle installed: `$VCI_TEST_RUBY_BIN` (a directory holding
//! `ruby` and `bundle`), else `mise where ruby@<version>`, else `ruby` on PATH
//! if it is that version. Every test prints `SKIPPED:` and returns early when
//! no such Ruby is found or `bundle check` fails for the fixture (the gems are
//! not installed for it: `bundle install` in `fixtures/rails-rspec-abcd`).

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
    workspace_root().join("fixtures/rails-rspec-abcd")
}

fn minitest_fixture() -> PathBuf {
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
        "SKIPPED: Ruby {want} (fixtures/rails-rspec-abcd/.ruby-version) with bundler was not found: set VCI_TEST_RUBY_BIN, or install it with mise (`mise install ruby@{want}`)"
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
    "SPEC_OPTS",
    "XDG_CONFIG_HOME",
];

const VCI_TOML: &str = r#"project = "."
adapter = "rails"

[policy]
platform = "any"
max_ttl = "30d"
no_skip_refs = ["refs/heads/release/*"]

[env]
mode = "strict"
global = ["APP_MODE", "TZ", "SPEC_OPTS"]
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

/// Copy a Rails fixture's sources (not its installed gems, logs, temp files,
/// databases or example status file) into `dir`.
fn copy_app(fx: &Path, dir: &Path, names: &[&str]) {
    std::fs::create_dir_all(dir).unwrap();
    for name in names {
        cp(&fx.join(name), &dir.join(name));
    }
    for d in ["log", "tmp", "storage", "vendor"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
        std::fs::write(dir.join(d).join(".keep"), "").unwrap();
    }
    for junk in [
        "db/test.sqlite3",
        "db/development.sqlite3",
        "spec/examples.txt",
    ] {
        let _ = std::fs::remove_file(dir.join(junk));
    }
}

const APP_FILES: &[&str] = &[
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
];

fn copy_rspec_fixture(dir: &Path) {
    let mut names = APP_FILES.to_vec();
    names.extend([".rspec", "spec"]);
    copy_app(&fixture(), dir, &names);
}

fn copy_minitest_fixture(dir: &Path) {
    let mut names = APP_FILES.to_vec();
    names.push("test");
    copy_app(&minitest_fixture(), dir, &names);
}

impl World {
    /// `None` (test skipped) when the fixture's Ruby or bundle is missing.
    fn new() -> Option<Self> {
        Self::build(VCI_TOML, copy_rspec_fixture, &["."])
    }

    fn build(vci_toml: &str, layout: impl FnOnce(&Path), bundles: &[&str]) -> Option<Self> {
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
        for b in bundles {
            if !w.bundle_check(&w.work.join(b)) {
                return None;
            }
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
                "SKIPPED: `bundle check` failed in {} (run `bundle install` in fixtures/rails-rspec-abcd and fixtures/rails-abcd with Ruby {}): {}{}",
                dir.display(),
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

    fn run_env(&self, dir: &Path, files: &[&str], key: &Path, env: &[(&str, &str)]) -> String {
        let mut args = vec!["run"];
        args.extend(files);
        args.extend(["--key", key.to_str().unwrap()]);
        let out = self.vci_env(dir, &args, env);
        assert!(out.status.success(), "vci run {files:?} failed");
        strip_ansi(&String::from_utf8_lossy(&out.stderr))
    }

    fn run(&self, dir: &Path, files: &[&str], key: &Path) -> String {
        self.run_env(dir, files, key, &[])
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

    /// `ruby -e <RSpec's runner>` the way `bundle exec rspec` runs, without
    /// vci (no collector, no `--options`): what the user's own option files
    /// do to a plain run.
    fn plain_rspec(&self, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(self.ruby_bin.join("ruby"));
        cmd.current_dir(dir)
            .args(["-e", vci_adapter_rspec_script(), "--"])
            .args(args)
            .env("PATH", self.path_env())
            .env("BUNDLE_GEMFILE", dir.join("Gemfile"))
            .env("RAILS_ENV", "test")
            .env("DISABLE_SPRING", "1")
            .env("DISABLE_BOOTSNAP", "1");
        for k in SCRUB {
            if *k != "BUNDLE_GEMFILE" && *k != "RAILS_ENV" {
                cmd.env_remove(k);
            }
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }
}

fn vci_adapter_rspec_script() -> &'static str {
    "require \"bundler/setup\"; require \"rspec/core\"; $0 = \"rspec\"; RSpec::Core::Runner.invoke"
}

#[derive(Debug, PartialEq, Eq)]
struct Plan {
    skip: BTreeSet<String>,
    run: BTreeSet<String>,
    run_all: bool,
    run_all_reason: String,
}

impl Plan {
    fn from_json(v: &Value) -> Self {
        let mut p = Plan {
            skip: BTreeSet::new(),
            run: BTreeSet::new(),
            run_all: !v["runAll"].is_null(),
            run_all_reason: v["runAll"].as_str().unwrap_or_default().to_owned(),
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

/// The `vci: not attesting <id>: ...` line of `id`, or a panic.
fn refusal<'a>(stderr: &'a str, id: &str) -> &'a str {
    stderr
        .lines()
        .find(|l| l.starts_with(&format!("vci: not attesting {id}:")))
        .unwrap_or_else(|| panic!("{id} was not refused:\n{stderr}"))
}

/// a: a pure-Ruby lib spec (spec_helper only, no Rails); b: a model spec
/// using the database through a factory and a fixture, a shared example and
/// a custom matcher from spec/support; c: a view spec rendering a template
/// with a file chosen at run time through file_fixture; d: a request spec
/// of a route (hashids).
const A: &str = "spec/lib/a_spec.rb";
const B: &str = "spec/models/b_spec.rb";
const C: &str = "spec/views/c_spec.rb";
const D: &str = "spec/requests/d_spec.rb";
const ALL: &[&str] = &[A, B, C, D];
const RAILS_SPECS: &[&str] = &[B, C, D];

#[test]
fn rspec_end_to_end_verification_steps() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();

    // Step 1: attest B, then plan: skip B; run A, C, D. The database was
    // prepared fresh in a temp dir, and the example status file
    // (spec_helper sets spec/examples.txt) was never written.
    let out = w.run(&work, &[B], &w.trusted);
    assert!(out.contains("3 examples, 0 failures"), "{out}");
    assert!(
        out.contains("--options .rspec spec/models/b_spec.rb"),
        "{out}"
    );
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[B]), "step 1");
    assert_eq!(p.run, set(&[A, C, D]), "step 1");
    assert!(!p.run_all);
    assert!(!work.join("db/test.sqlite3").exists());
    assert!(!work.join("spec/examples.txt").exists());
    // The runner is in the attestation: argv and the toolchain.
    let stored = AttestStore::new(&store_for(&work)).list(Some(B)).unwrap();
    let env: Value = serde_json::from_slice(&stored[0].bytes).unwrap();
    let payload = base64::engine::general_purpose::STANDARD
        .decode(env["payload"].as_str().unwrap())
        .unwrap();
    let st: Value = serde_json::from_slice(&payload).unwrap();
    let argv: Vec<&str> = st["predicate"]["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        argv,
        [
            "rails",
            "rspec",
            "--root",
            ".",
            "--options",
            ".rspec",
            "--default-seed",
            "0",
            B
        ]
    );
    let runner = st["predicate"]["toolchain"]["rubyTest"].as_str().unwrap();
    for g in [
        "rspec-core 3.13.6",
        "rspec-expectations 3.13.5",
        "rspec-mocks 3.13.8",
        "rspec-rails 8.0.4",
    ] {
        assert!(runner.contains(g), "{runner}");
    }
    assert_eq!(
        st["predicate"]["result"]["tests"], 3,
        "{}",
        st["predicate"]["result"]
    );

    // Step 2: edit the factory -> B runs; explain names the file.
    let factory = w.read("spec/factories/gadgets.rb");
    w.put(
        "spec/factories/gadgets.rb",
        &factory.replace("\"bolt\"", "\"nut\""),
    );
    assert!(w.plan(&work, "main").run.contains(B), "step 2");
    let ex = w.explain(&work, B, "main");
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(ex.contains("entry:spec/factories/gadgets.rb"), "{ex}");
    assert!(
        ex.contains(&vci_core::blake3_hex(factory.as_bytes())),
        "{ex}"
    );
    w.put("spec/factories/gadgets.rb", &factory);
    assert_eq!(w.plan(&work, "main").skip, set(&[B]), "step 2: restored");
    // The fixture B loads (`fixtures :widgets`, from config.fixture_paths).
    let yml = w.read("spec/fixtures/widgets.yml");
    w.put(
        "spec/fixtures/widgets.yml",
        &yml.replace("size: 2", "size: 3"),
    );
    assert!(
        w.explain(&work, B, "main")
            .contains("entry:spec/fixtures/widgets.yml"),
        "step 2: the fixture"
    );
    w.put("spec/fixtures/widgets.yml", &yml);

    // Step 3: attest everything.
    w.run(&work, &[A, C, D], &w.trusted);
    assert_eq!(w.plan(&work, "main").skip, set(ALL), "step 3");

    // Step 4: a NEW file in spec/support (rails_helper requires every file
    // its glob finds) -> every spec that loads rails_helper runs; A (spec_helper
    // only) stays skipped.
    w.put("spec/support/extra.rb", "# a new support file\n");
    let p = w.plan(&work, "main");
    assert_eq!(p.run, set(RAILS_SPECS), "step 4");
    assert_eq!(p.skip, set(&[A]), "step 4");
    assert!(
        w.explain(&work, B, "main").contains("entry:spec/support"),
        "step 4: the listing"
    );
    std::fs::remove_file(work.join("spec/support/extra.rb")).unwrap();
    assert_eq!(w.plan(&work, "main").skip, set(ALL), "step 4: restored");

    // Step 5: a new factory file (FactoryBot finds definitions by scanning
    // spec/factories) -> B runs; A stays skipped.
    w.put("spec/factories/sprockets.rb", "FactoryBot.define do\nend\n");
    let p = w.plan(&work, "main");
    assert!(p.run.contains(B), "step 5: {p:?}");
    assert!(p.skip.contains(A), "step 5: {p:?}");
    assert!(
        w.explain(&work, B, "main").contains("entry:spec/factories"),
        "step 5"
    );
    std::fs::remove_file(work.join("spec/factories/sprockets.rb")).unwrap();

    // Step 6: the shared example B uses -> B runs; A stays skipped.
    let shared = w.read("spec/support/shared_examples/labelled_record.rb");
    w.put(
        "spec/support/shared_examples/labelled_record.rb",
        &format!("{shared}# edited\n"),
    );
    let p = w.plan(&work, "main");
    assert!(p.run.contains(B) && p.skip.contains(A), "step 6: {p:?}");
    assert!(
        w.explain(&work, B, "main")
            .contains("entry:spec/support/shared_examples/labelled_record.rb")
    );
    w.put("spec/support/shared_examples/labelled_record.rb", &shared);

    // Step 7: .rspec (a global input of every spec) -> everything runs.
    let rspec = w.read(".rspec");
    w.put(".rspec", &format!("{rspec}--format progress\n"));
    let p = w.plan(&work, "main");
    assert!(p.skip.is_empty() && !p.run_all, "step 7: {p:?}");
    let ex = w.explain(&work, A, "main");
    assert!(ex.contains("failed check: global-inputs"), "{ex}");
    assert!(ex.contains("entry:.rspec"), "{ex}");
    w.put(".rspec", &rspec);
    assert_eq!(w.plan(&work, "main").skip, set(ALL), "step 7: restored");

    // Step 8: the view template -> C runs, nothing else. Of the two files
    // C could read through file_fixture, only the one it read matters.
    let tpl = w.read("app/views/reports/show.text.erb");
    w.put("app/views/reports/show.text.erb", &format!("{tpl}!"));
    let p = w.plan(&work, "main");
    assert_eq!(p.run, set(&[C]), "step 8");
    assert!(
        w.explain(&work, C, "main")
            .contains("entry:app/views/reports/show.text.erb")
    );
    w.put("app/views/reports/show.text.erb", &tpl);
    w.put("spec/fixtures/files/beta.txt", "Beta title, edited\n");
    assert_eq!(w.plan(&work, "main").skip, set(ALL), "step 8: beta.txt");
    w.put("spec/fixtures/files/alpha.txt", "Alpha title, edited\n");
    assert_eq!(w.plan(&work, "main").run, set(&[C]), "step 8: alpha.txt");
    w.git(&work, &["checkout", "--", "spec/fixtures/files"]);

    // Step 9: config/routes.rb -> D (which draws the routes) runs; A (no
    // Rails) stays skipped.
    let routes = w.read("config/routes.rb");
    w.put("config/routes.rb", &format!("{routes}# edited\n"));
    let p = w.plan(&work, "main");
    assert!(p.run.contains(D) && p.skip.contains(A), "step 9: {p:?}");
    assert!(
        w.explain(&work, D, "main")
            .contains("entry:config/routes.rb")
    );
    w.put("config/routes.rb", &routes);

    // Step 10: a new spec file elsewhere in spec/ does not run the others
    // (rspec-rails' boot-time listing of spec/**/*_spec.rb for `rails stats`
    // is not an input).
    w.put(
        "spec/jobs/new_spec.rb",
        "require \"rails_helper\"\n\nRSpec.describe \"new\" do\n  it { expect(1).to eq(1) }\nend\n",
    );
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(ALL), "step 10: {p:?}");
    assert_eq!(p.run, set(&["spec/jobs/new_spec.rb"]), "step 10");
    std::fs::remove_dir_all(work.join("spec/jobs")).unwrap();

    // Step 11: an rspec-core bump in Gemfile.lock -> everything runs.
    let lock = w.read("Gemfile.lock");
    assert!(lock.contains("    rspec-core (3.13.6)"));
    w.put(
        "Gemfile.lock",
        &lock.replace("rspec-core (3.13.6)", "rspec-core (3.13.5)"),
    );
    let p = w.plan(&work, "main");
    assert!(p.skip.is_empty(), "step 11: {p:?}");
    w.put("Gemfile.lock", &lock);
    assert_eq!(w.plan(&work, "main").skip, set(ALL), "step 11: restored");

    // Step 12: SPEC_OPTS (declared in [env] global) set differently in CI
    // -> everything runs.
    let p = w.plan_env(&work, "main", &[("SPEC_OPTS", "--format documentation")]);
    assert!(p.skip.is_empty(), "step 12: {p:?}");
    let out = w.vci_env(
        &work,
        &["explain", A, "--base-ref", "main"],
        &[("SPEC_OPTS", "--format documentation")],
    );
    let ex = String::from_utf8_lossy(&out.stdout);
    assert!(
        ex.contains("failed check: env") && ex.contains("env:SPEC_OPTS"),
        "{ex}"
    );

    // Step 13: flip a byte in B's payload -> rejected at the signature check.
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
        .position(|x| x == b"\"tests\":3")
        .expect("payload contains the example count");
    payload[pos + 8] = b'4';
    env["payload"] = Value::String(b64.encode(&payload));
    store
        .put(
            B,
            &good.signer,
            &good.storage_key,
            &serde_json::to_vec(&env).unwrap(),
        )
        .unwrap();
    assert!(w.plan(&work, "main").run.contains(B), "step 13");
    assert!(
        w.explain(&work, B, "main")
            .contains("failed check: signature")
    );
    store
        .put(B, &good.signer, &good.storage_key, &good.bytes)
        .unwrap();
    assert!(w.plan(&work, "main").skip.contains(B), "step 13: restored");

    // Step 14: an unknown signer -> rejected; adding it to allowed_signers on
    // the PR branch only -> still rejected.
    let calc = w.read("lib/calc.rb");
    w.put("lib/calc.rb", &format!("{calc}# untrusted run\n"));
    w.run(&work, &[A], &w.untrusted);
    assert!(w.plan(&work, "main").run.contains(A), "step 14");
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
        "step 14: a key added on the PR branch must not be trusted"
    );
    assert!(
        w.plan(&work, "HEAD").skip.contains(A),
        "step 14 control: with the PR commit as the (wrong) trust root"
    );
}

/// Option files outside the repository (`~/.rspec`,
/// `$XDG_CONFIG_HOME/rspec/options`) and the usually git-ignored
/// `.rspec-local` are never read under vci: a plain run with them is
/// filtered or broken, vci's run and plan are unchanged.
#[test]
fn rspec_option_files_outside_the_repository_are_not_read() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let home = w.base.join("home");
    std::fs::create_dir_all(home.join(".config/rspec")).unwrap();
    std::fs::write(home.join(".rspec"), "--tag focus\n").unwrap();
    let xdg = w.base.join("xdg");
    std::fs::create_dir_all(xdg.join("rspec")).unwrap();
    std::fs::write(xdg.join("rspec/options"), "--require does_not_exist\n").unwrap();
    // .rspec-local is git-ignored here, as it usually is.
    let mut ignore = w.read(".gitignore");
    ignore.push_str("/.rspec-local\n");
    w.put(".gitignore", &ignore);
    w.git(&work, &["commit", "-q", "-am", "ignore .rspec-local"]);

    // They have teeth in a plain run (what `bundle exec rspec` reads).
    let home_s = home.to_str().unwrap();
    let xdg_s = xdg.to_str().unwrap();
    let out = w.plain_rspec(&work, &[A], &[("HOME", home_s)]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("include {focus: true}") && text.contains("0 examples"),
        "~/.rspec filters a plain run: {text}"
    );
    let out = w.plain_rspec(&work, &[A], &[("HOME", home_s), ("XDG_CONFIG_HOME", xdg_s)]);
    assert!(
        !out.status.success(),
        "the XDG options file breaks a plain run: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    w.put(".rspec-local", "--tag slow\n");
    let out = w.plain_rspec(&work, &[A], &[]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("include {slow: true}"),
        ".rspec-local filters a plain run"
    );

    // Under vci none of them is read: attested with the home and XDG files
    // present, skipped by a plan that has them, and attested again with the
    // same inputs (the same storage key) without them.
    let env = [("HOME", home_s), ("XDG_CONFIG_HOME", xdg_s)];
    let out = w.run_env(&work, &[A, B], &w.trusted, &env);
    assert!(out.contains("2 attested, 0 not attested"), "{out}");
    assert_eq!(w.plan_env(&work, "main", &env).skip, set(&[A, B]));
    assert_eq!(w.plan(&work, "main").skip, set(&[A, B]));
    std::fs::remove_file(work.join(".rspec-local")).unwrap();
    assert_eq!(w.plan(&work, "main").skip, set(&[A, B]), "not an input");
    let again = w.run(&work, &[A], &w.trusted);
    assert!(again.contains("1 attested"), "{again}");
    assert_eq!(
        AttestStore::new(&store_for(&work))
            .list(Some(A))
            .unwrap()
            .len(),
        1,
        "the same inputs, the same key"
    );
}

#[test]
fn rspec_run_refuses_unattestable_spec_files() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let spec = |desc: &str, body: &str| {
        format!("require \"spec_helper\"\n\nRSpec.describe \"{desc}\" do\n{body}end\n")
    };
    let rails_spec = |desc: &str, body: &str| {
        format!("require \"rails_helper\"\n\nRSpec.describe \"{desc}\" do\n{body}end\n")
    };
    let files: Vec<(&str, String, &str)> = vec![
        (
            "spec/refuse/pending_spec.rb",
            spec(
                "pending",
                "  it \"is pending\" do\n    pending \"not yet\"\n    expect(1).to eq(2)\n  end\n\n  it \"passes\" do\n    expect(1).to eq(1)\n  end\n",
            ),
            "1 skipped",
        ),
        (
            "spec/refuse/xit_spec.rb",
            spec(
                "xit",
                "  xit \"is skipped\" do\n    expect(1).to eq(1)\n  end\n\n  it \"passes\" do\n    expect(1).to eq(1)\n  end\n",
            ),
            "1 skipped",
        ),
        (
            "spec/refuse/xdescribe_spec.rb",
            "require \"spec_helper\"\n\nRSpec.xdescribe \"skipped group\" do\n  it \"is skipped\" do\n    expect(1).to eq(1)\n  end\nend\n".to_owned(),
            "1 skipped",
        ),
        (
            // spec_helper has `filter_run_when_matching :focus`: only the
            // focused example runs.
            "spec/refuse/focus_spec.rb",
            spec(
                "focus",
                "  fit \"is focused\" do\n    expect(1).to eq(1)\n  end\n\n  it \"is filtered out\" do\n    expect(1).to eq(2)\n  end\n",
            ),
            "rspec:filtered:1 of 2 examples did not run (inclusion filter {focus: true})",
        ),
        (
            "spec/refuse/fdescribe_spec.rb",
            "require \"spec_helper\"\n\nRSpec.fdescribe \"focused group\" do\n  it \"runs\" do\n    expect(1).to eq(1)\n  end\nend\n\nRSpec.describe \"other group\" do\n  it \"is filtered out\" do\n    expect(1).to eq(1)\n  end\nend\n".to_owned(),
            "rspec:filtered:1 of 2 examples did not run",
        ),
        (
            "spec/refuse/tag_spec.rb",
            "require \"spec_helper\"\n\nRSpec.configure { |c| c.filter_run_excluding :slow }\n\nRSpec.describe \"tags\" do\n  it \"is slow\", :slow do\n    expect(1).to eq(2)\n  end\n\n  it \"runs\" do\n    expect(1).to eq(1)\n  end\nend\n".to_owned(),
            "rspec:filtered:1 of 2 examples did not run (exclusion filter {slow: true})",
        ),
        (
            "spec/refuse/fail_spec.rb",
            spec("fail", "  it \"fails\" do\n    expect(1).to eq(2)\n  end\n"),
            "result failed (1 failed",
        ),
        (
            "spec/refuse/aggregate_spec.rb",
            spec(
                "aggregate",
                "  it \"fails twice\", :aggregate_failures do\n    expect(1).to eq(2)\n    expect(3).to eq(4)\n  end\n",
            ),
            "result failed (1 failed",
        ),
        (
            "spec/refuse/load_error_spec.rb",
            "require \"spec_helper\"\nrequire \"no_such_library\"\n\nRSpec.describe \"load error\" do\n  it \"never runs\" do\n    expect(1).to eq(1)\n  end\nend\n".to_owned(),
            "rspec:error-outside-examples:An error occurred while loading ./spec/refuse/load_error_spec.rb.",
        ),
        (
            "spec/refuse/after_context_spec.rb",
            spec(
                "after(:context) error",
                "  after(:context) { raise \"boom\" }\n\n  it \"passes\" do\n    expect(1).to eq(1)\n  end\n",
            ),
            "rspec:error-outside-examples:An error occurred in an `after(:context)` hook.",
        ),
        (
            "spec/refuse/before_suite_spec.rb",
            "require \"spec_helper\"\n\nRSpec.configure { |c| c.before(:suite) { raise \"boom in before(:suite)\" } }\n\nRSpec.describe \"before(:suite) error\" do\n  it \"never runs\" do\n    expect(1).to eq(1)\n  end\nend\n".to_owned(),
            "rspec:error-outside-examples:An error occurred in a `before(:suite)` hook.",
        ),
        (
            "spec/refuse/empty_spec.rb",
            "require \"spec_helper\"\n\nRSpec.describe \"no examples\" do\nend\n".to_owned(),
            "result no-tests (0 tests",
        ),
        (
            "spec/refuse/shell_spec.rb",
            spec(
                "shell",
                "  it \"shells out\" do\n    expect(`echo hi`).to eq(\"hi\\n\")\n  end\n",
            ),
            "process:backtick",
        ),
        (
            "spec/refuse/system_spec.rb",
            spec(
                "system",
                "  it \"runs a command\" do\n    expect(system(\"true\")).to be(true)\n  end\n",
            ),
            "process:system",
        ),
        (
            "spec/refuse/retry_spec.rb",
            spec(
                "retry",
                "  module ::RSpec::Retry; end\n\n  it \"passes\" do\n    expect(1).to eq(1)\n  end\n",
            ),
            "rspec:retry",
        ),
        (
            "spec/refuse/parallel_spec.rb",
            spec(
                "parallel_tests",
                "  module ::ParallelTests; end\n\n  it \"passes\" do\n    expect(1).to eq(1)\n  end\n",
            ),
            "rspec:parallel-tests",
        ),
        (
            "spec/refuse/stats_spec.rb",
            rails_spec(
                "code statistics",
                "  it \"reads the stats directories\" do\n    require \"rails/code_statistics\"\n    expect(Rails::CodeStatistics.directories.map(&:first)).to include(\"Model specs\")\n  end\n",
            ),
            "rails:code-statistics:directories",
        ),
        (
            "spec/refuse/write_spec.rb",
            rails_spec(
                "write",
                "  it \"writes into app/\" do\n    File.write(Rails.root.join(\"app/out.txt\"), \"x\")\n    File.delete(Rails.root.join(\"app/out.txt\"))\n    expect(1).to eq(1)\n  end\n",
            ),
            "wrote inside the repository: app/out.txt",
        ),
    ];
    for (rel, body, _) in &files {
        w.put(rel, body);
    }
    let mut args = vec!["run"];
    args.extend(files.iter().map(|(rel, _, _)| *rel));
    args.extend(["--key", w.trusted.to_str().unwrap()]);
    let out = w.vci(&work, &args);
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert_ne!(out.status.code(), Some(0), "the failing specs fail vci run");
    for (rel, _, why) in &files {
        let line = refusal(&stderr, rel);
        assert!(line.contains(why), "{rel}: expected {why:?} in {line:?}");
    }
    assert!(
        stderr.contains(&format!("vci: 0 attested, {} not attested", files.len())),
        "{stderr}"
    );
    assert!(
        AttestStore::new(&store_for(&work))
            .list(None)
            .unwrap()
            .is_empty(),
        "nothing may be stored"
    );
    let p = w.plan(&work, "main");
    for (rel, _, _) in &files {
        assert!(p.run.contains(*rel), "{rel} must run: {p:?}");
    }
    for (rel, _, _) in &files {
        std::fs::remove_file(work.join(rel)).unwrap();
    }

    // RSpec options that do not run the file's examples as such, from
    // SPEC_OPTS (declared in [env] global, so it reaches RSpec).
    for (opts, why) in [
        ("--dry-run", "rspec:dry-run"),
        (
            "--bisect",
            "rspec:invocation:RSpec::Core::Invocations::Bisect",
        ),
    ] {
        let out = w.vci_env(
            &work,
            &["run", A, "--key", w.trusted.to_str().unwrap()],
            &[("SPEC_OPTS", opts)],
        );
        let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
        assert!(refusal(&stderr, A).contains(why), "{opts}: {stderr}");
    }
    // `--fail-fast` and a tag filter that leaves every example in are
    // fine.
    let out = w.run_env(
        &work,
        &[A],
        &w.trusted,
        &[("SPEC_OPTS", "--fail-fast --tag ~slow")],
    );
    assert!(out.contains("1 attested"), "{out}");
}

/// RSpec reported a pass, then an at_exit handler failed the process
/// (SimpleCov's `minimum_coverage` exits 2 this way; minitest/autorun loaded
/// into an RSpec process exits 1 when it rejects RSpec's arguments; a
/// test's own `at_exit { exit 1 }`): a plain run fails, so the file is
/// refused and runs in CI.
#[test]
fn rspec_exit_code_set_after_the_run_refuses() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let files: Vec<(&str, &str)> = vec![
        (
            "spec/exit/at_exit_spec.rb",
            "require \"spec_helper\"\n\nat_exit { exit 1 }\n\nRSpec.describe \"at_exit\" do\n  it \"passes\" do\n    expect(1).to eq(1)\n  end\nend\n",
        ),
        (
            // What SimpleCov's minimum_coverage check does after the run.
            "spec/exit/coverage_spec.rb",
            "require \"spec_helper\"\n\nat_exit do\n  warn \"Line coverage (80.00%) is below the expected minimum coverage (100.00%).\"\n  exit 2\nend\n\nRSpec.describe \"coverage\" do\n  it \"passes\" do\n    expect(1).to eq(1)\n  end\nend\n",
        ),
        (
            "spec/exit/minitest_autorun_spec.rb",
            "require \"spec_helper\"\nrequire \"minitest/autorun\"\n\nRSpec.describe \"minitest/autorun\" do\n  it \"passes\" do\n    expect(1).to eq(1)\n  end\nend\n",
        ),
    ];
    for (rel, body) in &files {
        w.put(rel, body);
        let out = w.plain_rspec(&work, &["--options", ".rspec", rel], &[]);
        assert!(!out.status.success(), "{rel}: a plain run fails");
    }
    let mut args = vec!["run"];
    args.extend(files.iter().map(|(rel, _)| *rel));
    args.extend(["--key", w.trusted.to_str().unwrap()]);
    let out = w.vci(&work, &args);
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert_ne!(out.status.code(), Some(0));
    for (rel, why) in [
        (files[0].0, "vci:process-exit:1"),
        (files[1].0, "vci:process-exit:2"),
        (files[2].0, "vci:process-exit:1"),
    ] {
        let line = refusal(&stderr, rel);
        assert!(line.contains(why), "{rel}: expected {why:?} in {line:?}");
    }
    assert!(
        AttestStore::new(&store_for(&work))
            .list(None)
            .unwrap()
            .is_empty(),
        "nothing may be stored"
    );
    let p = w.plan(&work, "main");
    for (rel, _) in &files {
        assert!(p.run.contains(*rel), "{rel} must run: {p:?}");
    }
}

/// A spec that sets ENV["TMPDIR"] (to "/" here) does not hide its reads
/// under that directory: the collector's own temp dir was fixed when it
/// loaded. A read outside the repository is refused as always.
#[test]
fn rspec_tmpdir_set_by_a_spec_hides_no_reads() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let outside = w.base.join("outside.txt");
    std::fs::write(&outside, "outside v1\n").unwrap();
    const T: &str = "spec/tmp/tmpdir_spec.rb";
    for dir in ["/", w.base.to_str().unwrap()] {
        w.put(
            T,
            &format!(
                "require \"spec_helper\"\n\nRSpec.describe \"TMPDIR\" do\n  it \"reads a file outside the repository\" do\n    ENV[\"TMPDIR\"] = {dir:?}\n    expect(File.read({:?})).to eq(\"outside v1\\n\")\n  end\nend\n",
                outside.to_str().unwrap()
            ),
        );
        let out = w.vci(&work, &["run", T, "--key", w.trusted.to_str().unwrap()]);
        let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
        assert!(stderr.contains("1 example, 0 failures"), "{stderr}");
        let line = refusal(&stderr, T);
        assert!(
            line.contains("input outside the repository") && line.contains("outside.txt"),
            "TMPDIR={dir}: {line}"
        );
        assert!(w.plan(&work, "main").run.contains(T));
    }
}

/// Prism's file APIs (parse_file, parse_file_success?, lex_file, ...) read
/// the source in C; the collector records the read, so editing the file
/// runs the spec.
#[test]
fn rspec_prism_file_reads_are_inputs() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put("spec/data/prism1.rb", "X = 1\n");
    w.put("spec/data/prism2.rb", "Y = 1\n");
    w.put("spec/data/prism3.rb", "Z = 1\n");
    const P: &str = "spec/cr/prism_spec.rb";
    w.put(
        P,
        "require \"spec_helper\"\nrequire \"prism\"\n\nRSpec.describe \"Prism\" do\n  it \"parses a file\" do\n    expect(Prism.parse_file(\"spec/data/prism1.rb\").value.statements.body.size).to eq(1)\n  end\n\n  it \"checks a file\" do\n    expect(Prism.parse_file_success?(\"spec/data/prism2.rb\")).to eq(true)\n  end\n\n  it \"lexes a file\" do\n    expect(Prism.lex_file(\"spec/data/prism3.rb\").value.size).to eq(5)\n  end\nend\n",
    );
    let out = w.run(&work, &[P], &w.trusted);
    assert!(out.contains("1 attested, 0 not attested"), "{out}");
    assert!(w.plan(&work, "main").skip.contains(P));
    for (rel, edited) in [
        ("spec/data/prism1.rb", "X = 1; Y = 2\n"),
        ("spec/data/prism2.rb", "X = (\n"),
        ("spec/data/prism3.rb", "Z = 1 + 2\n"),
    ] {
        let before = w.read(rel);
        w.put(rel, edited);
        let p = w.plan(&work, "main");
        assert!(p.run.contains(P), "editing {rel} must run {P}: {p:?}");
        let ex = w.explain(&work, P, "main");
        assert!(ex.contains(&format!("entry:{rel}")), "{rel}: {ex}");
        w.put(rel, &before);
    }
    assert!(w.plan(&work, "main").skip.contains(P));
}

/// A failure that something clears before the example finishes, or that a
/// reporter override reports as a pass, is refused: a home-grown retry in
/// an around hook (as rspec-retry does, without its constant), a prepended
/// Example#finish that drops the exception, a Reporter#example_failed that
/// calls example_passed.
#[test]
fn rspec_cleared_or_swallowed_failures_are_refused() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let files: Vec<(&str, &str, &[&str])> = vec![
        (
            "spec/adv/retry_spec.rb",
            "require \"spec_helper\"\n\n$attempt = 0\n\nRSpec.configure do |c|\n  c.around(:each) do |ex|\n    3.times do\n      ex.example.instance_variable_set(:@exception, nil)\n      ex.run\n      break unless ex.example.exception\n    end\n  end\nend\n\nRSpec.describe \"retry\" do\n  it \"is flaky\" do\n    $attempt += 1\n    expect($attempt).to eq(2)\n  end\nend\n",
            &["rspec:failure-cleared:"],
        ),
        (
            "spec/adv/reporter_swallow_spec.rb",
            "require \"spec_helper\"\n\nRSpec::Core::Reporter.prepend(Module.new { def example_failed(ex) = example_passed(ex) })\n\nRSpec.describe \"reporter\" do\n  it \"fails\" do\n    expect(1).to eq(2)\n  end\nend\n",
            &["rspec:failure-cleared:", "rspec:status-mismatch"],
        ),
        (
            "spec/adv/finish_override_spec.rb",
            "require \"spec_helper\"\n\nRSpec::Core::Example.prepend(Module.new { def finish(reporter); @exception = nil; super; end })\n\nRSpec.describe \"finish\" do\n  it \"fails\" do\n    expect(1).to eq(2)\n  end\nend\n",
            &["rspec:failure-cleared:"],
        ),
    ];
    for (rel, body, _) in &files {
        w.put(rel, body);
    }
    let mut args = vec!["run"];
    args.extend(files.iter().map(|(rel, _, _)| *rel));
    args.extend(["--key", w.trusted.to_str().unwrap()]);
    let out = w.vci(&work, &args);
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    for (rel, _, whys) in &files {
        let line = refusal(&stderr, rel);
        for why in *whys {
            assert!(line.contains(why), "{rel}: expected {why:?} in {line:?}");
        }
    }
    assert!(
        stderr.contains(&format!("vci: 0 attested, {} not attested", files.len())),
        "{stderr}"
    );
    let p = w.plan(&work, "main");
    for (rel, _, _) in &files {
        assert!(p.run.contains(*rel), "{rel} must run: {p:?}");
    }
}

/// A pending migration: rails_helper's `maintain_test_schema!` finds it
/// against the schema vci loaded (it never shells out to `bin/rails
/// db:test:prepare`, which would refuse the file) and aborts; refused, and
/// nothing is written in db/.
#[test]
fn rspec_pending_migration_is_refused() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put(
        "db/migrate/20261001120000_add_colour.rb",
        "class AddColour < ActiveRecord::Migration[8.1]\n  def change\n    add_column :widgets, :colour, :string\n  end\nend\n",
    );
    let out = w.vci(&work, &["run", B, "--key", w.trusted.to_str().unwrap()]);
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    let line = refusal(&stderr, B);
    assert!(line.contains("result failed"), "{line}");
    assert!(
        !line.contains("process:system"),
        "no db:test:prepare child: {line}"
    );
    assert!(stderr.contains("Migrations are pending"), "{stderr}");
    let db: Vec<String> = std::fs::read_dir(work.join("db"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        db.into_iter().collect::<BTreeSet<_>>(),
        set(&["migrate", "schema.rb"]),
        "nothing written in db/"
    );
}

/// `config.example_status_persistence_file_path` (spec_helper sets
/// spec/examples.txt): RSpec writes it at exit and reads it at start
/// (`--only-failures`, `last_run_status`). Under vci it is a fresh file in the
/// process's temp dir: nothing is written in the repository, a state file
/// left there by a plain run is not read (not an input), and
/// `--only-failures` therefore runs nothing and is refused.
#[test]
fn rspec_example_status_file_is_neutralised() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    // A plain run writes it.
    let out = w.plain_rspec(&work, &[A], &[]);
    assert!(out.status.success());
    let state = w.read("spec/examples.txt");
    assert!(state.contains("spec/lib/a_spec.rb[1:1]"), "{state}");
    // A spec that depends on the last run's status.
    w.put(
        "spec/state/last_status_spec.rb",
        "require \"spec_helper\"\n\nRSpec.describe \"status\" do\n  it \"sees no earlier run\" do |ex|\n    expect(ex.metadata[:last_run_status]).to eq(\"unknown\")\n  end\nend\n",
    );
    let out = w.run(&work, &[A, "spec/state/last_status_spec.rb"], &w.trusted);
    assert!(out.contains("2 attested, 0 not attested"), "{out}");
    assert_eq!(w.read("spec/examples.txt"), state, "vci never writes it");
    w.put("spec/examples.txt", &state.replace("| passed", "| failed"));
    let p = w.plan(&work, "main");
    assert!(
        p.skip.contains(A) && p.skip.contains("spec/state/last_status_spec.rb"),
        "the state file is not an input: {p:?}"
    );
    std::fs::remove_file(work.join("spec/examples.txt")).unwrap();
    assert!(w.plan(&work, "main").skip.contains(A));
    // --only-failures: no earlier failure is known under vci, so nothing
    // runs; refused.
    let rspec = w.read(".rspec");
    w.put(".rspec", &format!("{rspec}--only-failures\n"));
    let out = w.vci(&work, &["run", A, "--key", w.trusted.to_str().unwrap()]);
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(refusal(&stderr, A).contains("only_failures"), "{stderr}");
    assert!(!work.join("spec/examples.txt").exists());
}

/// rspec-mocks stubs of methods the collector hooks (File.read, ENV[],
/// Kernel.require, File.directory?, Dir.children) change what the test sees,
/// not what is recorded: the real reads made in the same process are
/// inputs, so changing them runs the file.
#[test]
fn rspec_stubs_of_hooked_methods_keep_real_reads() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    w.put("data/real.txt", "real\n");
    w.put("data/opened.txt", "opened\n");
    w.put("data/required.rb", "REQUIRED = 1\n");
    w.put("data/globbed/1.txt", "");
    w.put("data/globbed/2.txt", "");
    const S: &str = "spec/stubs/stubs_spec.rb";
    w.put(
        S,
        r#"require "rails_helper"

RSpec.describe "stubs of hooked methods" do
  it "File.read stubbed for one path: the real read of another is recorded" do
    allow(File).to receive(:read).and_call_original
    allow(File).to receive(:read).with("fake.txt").and_return("fake")
    expect(File.read("fake.txt")).to eq("fake")
    expect(File.read(Rails.root.join("data/real.txt").to_s)).to eq("real\n")
  end

  it "File.read stubbed entirely: a real read through File.open is recorded" do
    allow(File).to receive(:read).and_return("stubbed")
    expect(File.read("anything")).to eq("stubbed")
    expect(File.open(Rails.root.join("data/opened.txt"), &:read)).to eq("opened\n")
  end

  it "ENV[] stubbed for one key: real reads of others are recorded" do
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with("STUBBED_KEY").and_return("x")
    expect(ENV["STUBBED_KEY"]).to eq("x")
    expect(ENV["APP_MODE"]).to eq("attest")
  end

  it "Kernel.require stubbed: a real require is recorded" do
    allow(Kernel).to receive(:require).and_call_original
    allow(Kernel).to receive(:require).with("fake_lib").and_return(true)
    expect(Kernel.require("fake_lib")).to eq(true)
    require Rails.root.join("data/required").to_s
    expect(REQUIRED).to eq(1)
  end

  describe "time helpers" do
    include ActiveSupport::Testing::TimeHelpers

    it "travel_to does not disturb the collector" do
      travel_to(Time.utc(2001, 2, 3)) do
        expect(Time.now.year).to eq(2001)
        expect(File.read(Rails.root.join("data/real.txt").to_s)).to eq("real\n")
      end
    end
  end

  it "File.directory?, File.exist? and Dir.children stubbed: a real glob's listing is recorded" do
    allow(File).to receive(:directory?).and_return(false)
    allow(File).to receive(:exist?).and_return(false)
    allow(Dir).to receive(:children).and_return([])
    expect(Dir.glob(Rails.root.join("data/globbed/*.txt").to_s).size).to eq(2)
  end
end
"#,
    );
    let out = w.run_env(&work, &[S], &w.trusted, &[("APP_MODE", "attest")]);
    assert!(out.contains("6 examples, 0 failures"), "{out}");
    assert!(out.contains("1 attested, 0 not attested"), "{out}");
    let env = [("APP_MODE", "attest")];
    assert!(w.plan_env(&work, "main", &env).skip.contains(S));
    for (rel, content, entry) in [
        ("data/real.txt", "real, edited\n", "entry:data/real.txt"),
        (
            "data/opened.txt",
            "opened, edited\n",
            "entry:data/opened.txt",
        ),
        (
            "data/required.rb",
            "REQUIRED = 1 # edited\n",
            "entry:data/required.rb",
        ),
        ("data/globbed/3.txt", "", "entry:data/globbed"),
    ] {
        let before = std::fs::read_to_string(work.join(rel)).ok();
        w.put(rel, content);
        assert!(
            w.plan_env(&work, "main", &env).run.contains(S),
            "changing {rel} must run the stubbing spec"
        );
        let out = w.vci_env(&work, &["explain", S, "--base-ref", "main"], &env);
        let ex = String::from_utf8_lossy(&out.stdout);
        assert!(ex.contains(entry), "{rel}: {ex}");
        match before {
            Some(b) => w.put(rel, &b),
            None => std::fs::remove_file(work.join(rel)).unwrap(),
        }
    }
    assert!(w.plan_env(&work, "main", &env).skip.contains(S));
    // The ENV read the stub let through is an input.
    let p = w.plan_env(&work, "main", &[("APP_MODE", "ci")]);
    assert!(p.run.contains(S), "{p:?}");
}

#[test]
fn rspec_push_fetch_fresh_clone_and_ci() {
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

    // `vci ci` runs only A and D, each in its own RSpec process with
    // `--options .rspec` and a fresh database, and writes an audit log.
    let audit = w.base.join("audit.json");
    let home = w.base.join("cihome");
    std::fs::create_dir_all(&home).unwrap();
    // A ~/.rspec on the runner changes nothing either.
    std::fs::write(home.join(".rspec"), "--tag focus\n").unwrap();
    let out = w.vci_env(
        &fresh,
        &[
            "ci",
            "--base-ref",
            "main",
            "--audit-log",
            audit.to_str().unwrap(),
        ],
        &[("HOME", home.to_str().unwrap())],
    );
    assert_eq!(out.status.code(), Some(0));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(stderr.contains("running 2 test file(s)"), "{stderr}");
    assert!(
        stderr.contains("--options .rspec spec/lib/a_spec.rb (exit 0)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("--options .rspec spec/requests/d_spec.rb (exit 0)"),
        "{stderr}"
    );
    assert!(!stderr.contains("b_spec.rb"), "B must not run: {stderr}");
    assert!(!fresh.join("db/test.sqlite3").exists());
    assert!(!fresh.join("spec/examples.txt").exists());
    let log: Value = serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
    let skipped: BTreeSet<String> = log["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["testId"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(skipped, set(&[B, C]));
    assert_eq!(log["exitCode"], 0);

    // A failing spec among the remainder makes `vci ci` exit non-zero.
    std::fs::write(
        fresh.join("spec/zfail_spec.rb"),
        "require \"spec_helper\"\n\nRSpec.describe \"z\" do\n  it \"fails\" do\n    expect(1).to eq(2)\n  end\nend\n",
    )
    .unwrap();
    let out = w.vci(&fresh, &["ci", "--base-ref", "main"]);
    assert_ne!(out.status.code(), Some(0), "a failing spec fails vci ci");
    std::fs::remove_file(fresh.join("spec/zfail_spec.rb")).unwrap();

    // Nothing is skipped on refs in no_skip_refs: the whole suite runs in one
    // RSpec process.
    w.git(&fresh, &["checkout", "-q", "-b", "release/1"]);
    let p = w.plan(&fresh, "main");
    assert!(p.run_all && p.skip.is_empty(), "{p:?}");
    let out = w.vci(&fresh, &["ci", "--base-ref", "main"]);
    assert_eq!(out.status.code(), Some(0));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(stderr.contains("6 examples, 0 failures"), "{stderr}");
}

const TWO_PROJECTS: &str = r#"[policy]
platform = "any"

[env]
mode = "strict"
global = ["TZ"]

[[projects]]
name = "mt"
path = "mt"
adapter = "rails"

[[projects]]
name = "rs"
path = "rs"
adapter = "rails"
"#;

/// A Minitest Rails app and an RSpec Rails app in one repository: each
/// project's files run with its own runner, are attested and skipped
/// independently, and `vci ci` runs each project's remainder.
#[test]
fn rails_minitest_and_rspec_projects_in_one_repository() {
    let Some(w) = World::build(
        TWO_PROJECTS,
        |d| {
            copy_minitest_fixture(&d.join("mt"));
            copy_rspec_fixture(&d.join("rs"));
            std::fs::write(d.join(".gitignore"), "/mt/log/*\n/mt/tmp/*\n/mt/db/*.sqlite3*\n/rs/log/*\n/rs/tmp/*\n/rs/db/*.sqlite3*\n/rs/spec/examples.txt\n").unwrap();
        },
        &["mt", "rs"],
    ) else {
        return;
    };
    let work = w.work.clone();
    const MB: &str = "mt/test/models/b_test.rb";
    const MC: &str = "mt/test/views/c_test.rb";
    const RB: &str = "rs/spec/models/b_spec.rb";
    const RC: &str = "rs/spec/views/c_spec.rb";
    let out = w.run(&work, &[MB, MC, RB, RC], &w.trusted);
    assert!(out.contains("4 attested, 0 not attested"), "{out}");
    assert!(
        out.contains("bin/rails test test/models/b_test.rb"),
        "{out}"
    );
    assert!(
        out.contains("--options .rspec spec/models/b_spec.rb"),
        "{out}"
    );
    let p = w.plan(&work, "main");
    assert_eq!(p.skip, set(&[MB, MC, RB, RC]), "{p:?}");
    assert_eq!(p.run.len(), 4, "{p:?}");
    // A view of the RSpec app runs only its c.
    let tpl = w.read("rs/app/views/reports/show.text.erb");
    w.put("rs/app/views/reports/show.text.erb", &format!("{tpl}!"));
    let p = w.plan(&work, "main");
    assert!(p.run.contains(RC) && p.skip.contains(MC), "{p:?}");
    w.put("rs/app/views/reports/show.text.erb", &tpl);
    // The Minitest app's view runs only its c.
    let tpl = w.read("mt/app/views/reports/show.text.erb");
    w.put("mt/app/views/reports/show.text.erb", &format!("{tpl}!"));
    let p = w.plan(&work, "main");
    assert!(p.run.contains(MC) && p.skip.contains(RC), "{p:?}");
    w.put("mt/app/views/reports/show.text.erb", &tpl);

    let out = w.vci(&work, &["ci", "--base-ref", "main"]);
    assert_eq!(out.status.code(), Some(0));
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        stderr.contains("bin/rails test test/lib/a_test.rb"),
        "{stderr}"
    );
    assert!(
        stderr.contains("--options .rspec spec/lib/a_spec.rb"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("b_test.rb") && !stderr.contains("b_spec.rb"),
        "{stderr}"
    );
}

/// One Rails app with both Minitest files and RSpec files: with no runner
/// setting each file runs with its own runner; a pattern under which RSpec
/// would also load Minitest files is refused until the setting decides; the
/// setting (from the base commit) picks one runner.
#[test]
fn rspec_and_minitest_files_in_one_project() {
    let Some(w) = World::new() else { return };
    let work = w.work.clone();
    let mt = minitest_fixture();
    for f in ["test/test_helper.rb", "test/lib/a_test.rb"] {
        w.put(f, &std::fs::read_to_string(mt.join(f)).unwrap());
    }
    const MA: &str = "test/lib/a_test.rb";
    let p = w.plan(&work, "main");
    assert!(
        p.run.contains(MA) && p.run.contains(A),
        "both runners: {p:?}"
    );
    let out = w.run(&work, &[MA, A], &w.trusted);
    assert!(out.contains("2 attested, 0 not attested"), "{out}");
    assert!(out.contains("bin/rails test test/lib/a_test.rb"), "{out}");
    assert!(out.contains("--options .rspec spec/lib/a_spec.rb"), "{out}");
    let p = w.plan(&work, "main");
    assert!(p.skip.contains(MA) && p.skip.contains(A), "{p:?}");

    // RSpec's pattern also matching test/: not clean, everything runs.
    let rspec = w.read(".rspec");
    w.put(
        ".rspec",
        &format!("{rspec}--pattern spec/**/*_spec.rb,test/**/*_test.rb\n"),
    );
    let p = w.plan(&work, "main");
    assert!(p.run_all && p.skip.is_empty(), "{p:?}");
    assert!(
        p.run_all_reason
            .contains("RSpec's file pattern also lists Minitest files")
            && p.run_all_reason.contains("set runner"),
        "{}",
        p.run_all_reason
    );
    w.put(".rspec", &rspec);

    // runner = "rspec" in the base commit: only spec files are listed.
    let toml = w.read("vci.toml");
    w.put(
        "vci.toml",
        &toml.replace(
            "adapter = \"rails\"",
            "adapter = \"rails\"\nrunner = \"rspec\"",
        ),
    );
    w.git(&work, &["add", "-A"]);
    w.git(&work, &["commit", "-q", "-m", "runner = rspec"]);
    let p = w.plan(&work, "HEAD");
    assert!(!p.run.contains(MA) && !p.skip.contains(MA), "{p:?}");
    // (vci.toml is a global input: what was attested before runs.)
    assert!(p.run.contains(A), "{p:?}");
    let out = w.run(&work, &[A], &w.trusted);
    assert!(out.contains("1 attested"), "{out}");
    assert!(
        out.contains("1 Minitest file(s) in test/ are not run by vci"),
        "{out}"
    );
    let out = w.vci(&work, &["run", MA, "--key", w.trusted.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "not a test file of the project any more"
    );
    let p = w.plan(&work, "HEAD");
    assert!(p.skip.contains(A) && !p.run.contains(MA), "{p:?}");
    // `vci plan` and `vci ci` say so too (and the audit log records it): the
    // Minitest file is not run by vci, even when it is broken.
    w.put(
        MA,
        &w.read(MA)
            .replace("assert_equal 3", "assert_equal 4")
            .replace("assert_equal(3", "assert_equal(4"),
    );
    let out = w.vci(&work, &["plan", "--base-ref", "HEAD"]);
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        stderr.contains("vci: warning: 1 Minitest file(s) in test/ are not run by vci"),
        "{stderr}"
    );
    let audit = w.base.join("audit-runner.json");
    let out = w.vci(
        &work,
        &[
            "ci",
            "--base-ref",
            "HEAD",
            "--audit-log",
            audit.to_str().unwrap(),
        ],
    );
    let stderr = strip_ansi(&String::from_utf8_lossy(&out.stderr));
    assert!(
        stderr.contains("vci: warning: 1 Minitest file(s) in test/ are not run by vci"),
        "{stderr}"
    );
    let log: Value = serde_json::from_slice(&std::fs::read(&audit).unwrap()).unwrap();
    assert!(
        log["warnings"].as_array().unwrap().iter().any(|w| w
            .as_str()
            .unwrap_or_default()
            .contains("Minitest file(s) in test/ are not run by vci")),
        "{log}"
    );
    // ...but main (no setting) still lists both.
    let p = w.plan(&work, "main");
    assert!(p.run.contains(MA) || p.skip.contains(MA), "{p:?}");
}

/// A plain Ruby project (no Rails) with RSpec: the same code path, with the
/// bundle as its toolchain.
#[test]
fn rspec_plain_ruby_project() {
    let Some(w) = World::build(
        VCI_TOML,
        |d| {
            std::fs::create_dir_all(d.join("lib")).unwrap();
            std::fs::create_dir_all(d.join("spec")).unwrap();
            std::fs::write(
                d.join(".ruby-version"),
                std::fs::read_to_string(fixture().join(".ruby-version")).unwrap(),
            )
            .unwrap();
            std::fs::write(
                d.join("Gemfile"),
                "source \"https://rubygems.org\"\n\ngem \"rspec-core\", \"3.13.6\"\ngem \"rspec-expectations\", \"3.13.5\"\n",
            )
            .unwrap();
            std::fs::write(d.join(".rspec"), "--require spec_helper\n").unwrap();
            std::fs::write(
                d.join("lib/greeter.rb"),
                "module Greeter\n  def self.hi = \"hi\"\nend\n",
            )
            .unwrap();
            std::fs::write(
                d.join("spec/spec_helper.rb"),
                "RSpec.configure { |c| c.order = :random }\n",
            )
            .unwrap();
            std::fs::write(
                d.join("spec/greeter_spec.rb"),
                "require \"greeter\"\n\nRSpec.describe Greeter do\n  it \"greets\" do\n    expect(Greeter.hi).to eq(\"hi\")\n  end\nend\n",
            )
            .unwrap();
            std::fs::write(d.join(".gitignore"), "").unwrap();
            // A lockfile for gems the Rails fixture's bundle installs, with
            // their checksums from its lockfile (Bundler leaves a complete
            // lockfile alone at setup; `bundle lock --local` writes one it
            // rewrites on every `require "bundler/setup"`, which vci refuses
            // as a write inside the repository).
            let fx_lock = std::fs::read_to_string(fixture().join("Gemfile.lock")).unwrap();
            let sum = |g: &str| {
                fx_lock
                    .lines()
                    .find(|l| l.starts_with(&format!("  {g} (")) && l.contains("sha256="))
                    .unwrap_or_else(|| panic!("no checksum for {g}"))
                    .to_owned()
            };
            std::fs::write(
                d.join("Gemfile.lock"),
                format!(
                    "GEM\n  remote: https://rubygems.org/\n  specs:\n    diff-lcs (1.6.2)\n    rspec-core (3.13.6)\n      rspec-support (~> 3.13.0)\n    rspec-expectations (3.13.5)\n      diff-lcs (>= 1.2.0, < 2.0)\n      rspec-support (~> 3.13.0)\n    rspec-support (3.13.7)\n\nPLATFORMS\n  arm64-darwin\n  ruby\n  x86_64-linux-gnu\n\nDEPENDENCIES\n  rspec-core (= 3.13.6)\n  rspec-expectations (= 3.13.5)\n\nCHECKSUMS\n{}\n{}\n{}\n{}\n\nBUNDLED WITH\n  4.0.9\n",
                    sum("diff-lcs"),
                    sum("rspec-core"),
                    sum("rspec-expectations"),
                    sum("rspec-support")
                ),
            )
            .unwrap();
        },
        &["."],
    ) else {
        return;
    };
    let work = w.work.clone();
    const G: &str = "spec/greeter_spec.rb";
    let out = w.run(&work, &[G], &w.trusted);
    assert!(out.contains("1 attested, 0 not attested"), "{out}");
    assert_eq!(w.plan(&work, "main").skip, set(&[G]));
    let lib = w.read("lib/greeter.rb");
    w.put("lib/greeter.rb", &format!("{lib}# edited\n"));
    let p = w.plan(&work, "main");
    assert!(p.run.contains(G), "{p:?}");
    assert!(w.explain(&work, G, "main").contains("entry:lib/greeter.rb"));
}

#[test]
fn rspec_init_writes_the_rails_template() {
    let Some(w) = World::new() else { return };
    let dir = w.base.join("initme");
    copy_rspec_fixture(&dir);
    w.git(&w.base, &["init", "-q", dir.to_str().unwrap()]);
    w.git(&dir, &["add", "-A"]);
    w.git(&dir, &["commit", "-q", "-m", "app"]);
    let key = format!("{}.pub", w.trusted.display());
    let o = w.vci(
        &dir,
        &["init", "--adapter", "rails", "--key", &key, "--no-install"],
    );
    assert!(o.status.success());
    let out = String::from_utf8_lossy(&o.stdout);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        out.contains("ruby/setup-ruby"),
        "the Rails CI snippet: {out}"
    );
    assert!(out.contains("RSpec"), "the snippet covers RSpec: {out}");
    assert!(
        err.contains("the rails adapter will run RSpec"),
        "the detected runner: {err}"
    );
    assert!(!err.contains("has no bin/rails"), "{err}");
    let toml = std::fs::read_to_string(dir.join("vci.toml")).unwrap();
    assert!(toml.contains("adapter = \"rails\""), "{toml}");
    assert!(toml.contains("# runner = \"rspec\""), "{toml}");
    assert!(toml.contains("\"SPEC_OPTS\""), "{toml}");
    let c = std::fs::read_to_string(dir.join("vci.toml")).unwrap();
    assert!(
        !c.contains("\nrunner ="),
        "the setting is commented out: {c}"
    );
}
