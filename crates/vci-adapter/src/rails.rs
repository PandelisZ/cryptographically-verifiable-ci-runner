//! Rails adapter (Minitest): one `bin/rails test <file>` process per test
//! file, with the `vci_collector` Ruby collector (`ruby/vci-collector`)
//! loaded through `RUBYOPT` before Bundler and Rails boot.
//!
//! ```text
//! RUBYOPT=-r<abs>/vci_collector.rb VCI_RAILS_MODE=collect VCI_OUT=<fresh dir> \
//!   VCI_DB_DIR=<fresh dir> TMPDIR=<fresh dir> RAILS_ENV=test PARALLEL_WORKERS=1 \
//!   DISABLE_SPRING=1 DISABLE_BOOTSNAP=1 BUNDLE_GEMFILE=<project>/Gemfile \
//!   ruby bin/rails test test/models/b_test.rb --seed 0
//! ```
//!
//! The collector redirects the test environment's SQLite databases to fresh
//! files in `VCI_DB_DIR` and loads the schema into them before
//! `rails/test_help` runs, so every file runs against a database built from
//! `db/schema.rb` (or `structure.sql`) and the fixtures, never against data a
//! previous run left behind. `vci ci` runs the remaining files the same way
//! (`VCI_RAILS_MODE=plain`: no recording). Findings: `docs/spike-rails.md`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use camino::{Utf8Path, Utf8PathBuf};
use serde_json::Value;

use crate::pytest::{OneRun, per_file_jobs};
use crate::vitest::{apply_env, describe};
use crate::{
    Adapter, AdapterError, ChildEnv, InstalledExternals, ListedFile, RunOutput, ToolVersions,
    parse_jsonl_dir,
};

/// Env var naming the `ruby` binary (default: `ruby` on PATH).
pub const RUBY_BIN_ENV: &str = "VCI_RUBY";

/// Env var naming the `ruby/vci-collector` directory (the one holding
/// `vci_collector.rb`).
pub const RUBY_COLLECTOR_ENV: &str = "VCI_RUBY_COLLECTOR";

const COLLECTOR_FILE: &str = "vci_collector.rb";

/// The fixed Minitest seed of every run (`--seed`): the order of the tests in
/// a file and `Kernel#rand` (Minitest seeds it) are the same where the file
/// was attested and in `vci ci`.
pub const RAILS_SEED: &str = "0";

/// Taint prefix for a database server (PostgreSQL, MySQL, ...), the one
/// refusal `policy.rails_allow_db` waives.
pub const RAILS_NETWORK_DB_TAINT: &str = "rails:network-db:";

/// Directories of a Rails project (relative to it) that tests may write to:
/// a write there is allowed when git ignores the path (derived state that is
/// never in a checkout). Reading back a file the same process created is not
/// an input; reading one that existed before is (it will not match a fresh
/// checkout, so that file runs in CI).
pub const RAILS_SCRATCH_DIRS: &[&str] = &["log", "tmp", "storage", "coverage"];

/// Variables the child always sees, on top of the global built-in list: where
/// Ruby, RubyGems, Bundler and version managers find things. The gems and
/// Ruby they lead to are checked directly (exact Ruby version, the resolved
/// bundle, every loaded gem's version), so their values are not inputs; like
/// every built-in pass-through variable they are hashed when a test (not
/// RubyGems or Bundler) reads one.
pub const RAILS_PASS_THROUGH: &[&str] = &[
    "GEM_HOME",
    "GEM_PATH",
    "GEM_SPEC_CACHE",
    "BUNDLE_PATH",
    "BUNDLE_APP_CONFIG",
    "BUNDLE_USER_HOME",
    "BUNDLE_USER_CACHE",
    "BUNDLE_USER_CONFIG",
    "BUNDLE_USER_PLUGIN",
    "BUNDLE_CACHE_PATH",
    "BUNDLE_GLOBAL_GEM_CACHE",
    "BUNDLE_BIN",
    "BUNDLE_JOBS",
    "BUNDLE_RETRY",
    "BUNDLE_DEPLOYMENT",
    "BUNDLE_FROZEN",
    "BUNDLE_SILENCE_ROOT_WARNING",
    "MISE_*",
    "__MISE_*",
    "RBENV_*",
    "ASDF_*",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

/// Variables hashed whenever they are present (loose mode, or declared in
/// strict mode, which otherwise removes them): Ruby reads `RUBY*` in C at
/// startup, Bundler takes its settings from every `BUNDLE_*`, and Rails,
/// Rack and Minitest read theirs before or outside anything a test does.
/// `RUBYOPT`, `RAILS_ENV`, `RACK_ENV`, `BUNDLE_GEMFILE`, `PARALLEL_WORKERS`,
/// `DISABLE_SPRING` and `DISABLE_BOOTSNAP` are set by vci.
pub const RAILS_HASHED_ENV: &[&str] = &[
    "RUBY*",
    "!RUBYOPT",
    "RAILS_*",
    "!RAILS_ENV",
    "RACK_*",
    "!RACK_ENV",
    "BUNDLE_*",
    "!BUNDLE_GEMFILE",
    "!BUNDLE_PATH",
    "!BUNDLE_APP_CONFIG",
    "!BUNDLE_USER_*",
    "!BUNDLE_CACHE_PATH",
    "!BUNDLE_GLOBAL_GEM_CACHE",
    "!BUNDLE_BIN",
    "!BUNDLE_JOBS",
    "!BUNDLE_RETRY",
    "!BUNDLE_DEPLOYMENT",
    "!BUNDLE_FROZEN",
    "!BUNDLE_SILENCE_ROOT_WARNING",
    "BUNDLER_*",
    "GEM_*",
    "!GEM_HOME",
    "!GEM_PATH",
    "!GEM_SPEC_CACHE",
    "DATABASE_URL",
    "*_DATABASE_URL",
    "SECRET_KEY_BASE",
    "SECRET_KEY_BASE_DUMMY",
    "MT_*",
    "MINITEST_*",
    "SEED",
    "TESTOPTS",
    "TEST",
    "TESTS",
    "N",
    "DEFAULT_TEST",
    "DEFAULT_TEST_EXCLUDE",
    "SCHEMA",
    "BOOTSNAP_*",
    "SPRING_*",
];

/// Variables vci sets for every Rails test process (never inputs).
pub const RAILS_RUN_VARS: &[&str] = &[
    "RUBYOPT",
    "RAILS_ENV",
    "RACK_ENV",
    "BUNDLE_GEMFILE",
    "PARALLEL_WORKERS",
    "DISABLE_SPRING",
    "DISABLE_BOOTSNAP",
];

/// Files whose content decides how every test of the project boots (global
/// inputs, relative to the project dir; missing ones are recorded as absent).
pub const RAILS_GLOBAL_FILES: &[&str] = &[
    "Gemfile",
    "Gemfile.lock",
    "gems.rb",
    "gems.locked",
    ".ruby-version",
    ".tool-versions",
    "mise.toml",
    ".mise.toml",
    "mise.local.toml",
    ".mise.local.toml",
    ".mise/config.toml",
    ".config/mise.toml",
    "config/application.rb",
    "config/boot.rb",
    "config/environment.rb",
    "config/environments/test.rb",
    "config.ru",
    "bin/rails",
    "test/test_helper.rb",
    "Rakefile",
];

/// What `vci plan` and `vci run` learn by booting the application once.
#[derive(Debug, Clone)]
struct Probe {
    versions: ToolVersions,
    /// gem name -> versions in the bundle.
    gems: InstalledExternals,
}

/// The Rails adapter.
#[derive(Debug)]
pub struct RailsAdapter {
    project_dir: Utf8PathBuf,
    ruby: OsString,
    collector: Option<Utf8PathBuf>,
    allow_db: bool,
    probe: OnceLock<Result<Probe, String>>,
}

fn collector_ok(dir: &Utf8Path) -> bool {
    dir.join(COLLECTOR_FILE).is_file()
}

/// Locate the directory holding `vci_collector.rb`: `$VCI_RUBY_COLLECTOR`,
/// else `ruby/vci-collector` (or `share/vci/ruby-collector`) next to or
/// above the `vci` executable, else `ruby/vci-collector` of the source
/// checkout `vci` was built from, else above the project dir.
pub fn find_ruby_collector(project_dir: &Utf8Path) -> Result<Utf8PathBuf, AdapterError> {
    if let Ok(v) = std::env::var(RUBY_COLLECTOR_ENV)
        && !v.is_empty()
    {
        let p = Utf8PathBuf::from(&v);
        let p = if p.is_absolute() {
            p
        } else {
            Utf8PathBuf::from_path_buf(std::env::current_dir()?)
                .map_err(|p| AdapterError::NotFound(format!("non-UTF-8 cwd {p:?}")))?
                .join(p)
        };
        if !collector_ok(&p) {
            return Err(AdapterError::NotFound(format!(
                "{RUBY_COLLECTOR_ENV}={v} does not contain {COLLECTOR_FILE}; it must name the ruby/vci-collector directory of vci"
            )));
        }
        return Ok(p.canonicalize_utf8()?);
    }
    let mut candidates: Vec<Utf8PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Ok(exe) = exe.canonicalize()
        && let Ok(exe) = Utf8PathBuf::from_path_buf(exe)
    {
        for d in exe.ancestors().skip(1) {
            candidates.push(d.join("ruby/vci-collector"));
            candidates.push(d.join("share/vci/ruby-collector"));
        }
    }
    if let Some(src) = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Utf8Path::parent)
    {
        candidates.push(src.join("ruby/vci-collector"));
    }
    for d in project_dir.ancestors() {
        candidates.push(d.join("ruby/vci-collector"));
    }
    for c in candidates {
        if collector_ok(&c) {
            return Ok(c.canonicalize_utf8()?);
        }
    }
    Err(AdapterError::NotFound(format!(
        "the vci Ruby collector ({COLLECTOR_FILE}) was not found: set {RUBY_COLLECTOR_ENV} to the ruby/vci-collector directory of vci"
    )))
}

fn utf8_tmp(t: &tempfile::TempDir) -> Result<Utf8PathBuf, AdapterError> {
    let p = Utf8Path::from_path(t.path())
        .ok_or_else(|| AdapterError::NotFound("non-UTF-8 temp dir".into()))?;
    Ok(p.canonicalize_utf8().unwrap_or_else(|_| p.to_owned()))
}

/// Fresh temp dirs of one Ruby process.
struct RunDirs {
    _tmp: tempfile::TempDir,
    tmpdir: Utf8PathBuf,
    db: Utf8PathBuf,
    out: Utf8PathBuf,
}

impl RunDirs {
    fn new() -> Result<Self, AdapterError> {
        let t = tempfile::Builder::new().prefix("vci-rails-").tempdir()?;
        let base = utf8_tmp(&t)?;
        let (tmpdir, db, out) = (base.join("tmp"), base.join("db"), base.join("out"));
        for d in [&tmpdir, &db, &out] {
            std::fs::create_dir(d)?;
        }
        Ok(Self {
            _tmp: t,
            tmpdir,
            db,
            out,
        })
    }
}

impl RailsAdapter {
    /// `project_dir` must be absolute (it is canonicalised if possible).
    pub fn new(project_dir: &Utf8Path) -> Self {
        let project_dir = project_dir
            .canonicalize_utf8()
            .unwrap_or_else(|_| project_dir.to_owned());
        let ruby = std::env::var_os(RUBY_BIN_ENV)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "ruby".into());
        Self {
            project_dir,
            ruby,
            collector: None,
            allow_db: false,
            probe: OnceLock::new(),
        }
    }

    /// Use this collector directory instead of looking it up.
    pub fn with_collector(mut self, dir: impl Into<Utf8PathBuf>) -> Self {
        self.collector = Some(dir.into());
        self
    }

    /// `policy.rails_allow_db`: database servers are prepared fresh from the
    /// schema too (their files are attested with the refusal waived).
    pub fn with_allow_db(mut self, allow: bool) -> Self {
        self.allow_db = allow;
        self
    }

    fn collector_file(&self) -> Result<Utf8PathBuf, AdapterError> {
        let dir = match &self.collector {
            Some(p) if collector_ok(p) => p.canonicalize_utf8()?,
            Some(p) => {
                return Err(AdapterError::NotFound(format!(
                    "{p} does not contain {COLLECTOR_FILE}"
                )));
            }
            None => find_ruby_collector(&self.project_dir)?,
        };
        Ok(dir.join(COLLECTOR_FILE))
    }

    /// The repository holding the project (the nearest ancestor with `.git`).
    fn repo_root(&self) -> Utf8PathBuf {
        self.project_dir
            .ancestors()
            .find(|d| d.join(".git").exists())
            .unwrap_or(&self.project_dir)
            .to_owned()
    }

    fn gemfile(&self) -> Utf8PathBuf {
        let gems_rb = self.project_dir.join("gems.rb");
        if !self.project_dir.join("Gemfile").exists() && gems_rb.exists() {
            gems_rb
        } else {
            self.project_dir.join("Gemfile")
        }
    }

    /// `ruby <args>` in the project dir with `env` applied and vci's run
    /// conditions: the collector in `mode`, the test environment, one
    /// process (no parallel workers, no Spring, no Bootsnap caches), the
    /// project's Gemfile, fresh temp and database directories.
    fn ruby_cmd(
        &self,
        env: &ChildEnv,
        mode: &str,
        dirs: &RunDirs,
        collector: &Utf8Path,
    ) -> Command {
        let mut c = Command::new(&self.ruby);
        c.current_dir(&self.project_dir).stdin(Stdio::null());
        apply_env(&mut c, env);
        for k in ["RUBYLIB", "VCI_OUT", "VCI_TEST_ID", "SPRING_SERVER_COMMAND"] {
            c.env_remove(k);
        }
        c.env("RUBYOPT", format!("-r{collector}"))
            .env("VCI_RAILS_MODE", mode)
            .env("VCI_ROOT", self.project_dir.as_str())
            .env("VCI_REPO", self.repo_root().as_str())
            .env("VCI_DB_DIR", dirs.db.as_str())
            .env("TMPDIR", dirs.tmpdir.as_str())
            .env("RAILS_ENV", "test")
            .env("RACK_ENV", "test")
            .env("PARALLEL_WORKERS", "1")
            .env("DISABLE_SPRING", "1")
            .env("DISABLE_BOOTSNAP", "1")
            .env("BUNDLE_GEMFILE", self.gemfile().as_str())
            .env("VCI_RAILS_ALLOW_DB", if self.allow_db { "1" } else { "0" });
        c
    }

    fn not_installed(&self, e: std::io::Error) -> AdapterError {
        if e.kind() == std::io::ErrorKind::NotFound {
            AdapterError::NotFound(format!(
                "`{}` was not found: the rails adapter needs Ruby on PATH (the version in .ruby-version), or {RUBY_BIN_ENV} naming it",
                self.ruby.to_string_lossy()
            ))
        } else {
            AdapterError::Io(e)
        }
    }

    fn probe(&self, env: &ChildEnv) -> Result<Probe, AdapterError> {
        self.probe
            .get_or_init(|| self.run_probe(env).map_err(|e| e.to_string()))
            .clone()
            .map_err(|e| AdapterError::Parse {
                what: "Rails application probe".into(),
                detail: e,
            })
    }

    /// Boot the application (test environment) once with the collector in
    /// probe mode: versions, the resolved bundle, the databases.
    fn run_probe(&self, env: &ChildEnv) -> Result<Probe, AdapterError> {
        let collector = self.collector_file()?;
        let dirs = RunDirs::new()?;
        let mut cmd = self.ruby_cmd(env, "probe", &dirs, &collector);
        cmd.args(["-e", "require File.expand_path(\"config/environment\")"]);
        let out = cmd.output().map_err(|e| self.not_installed(e))?;
        if !out.status.success() {
            return Err(AdapterError::Command {
                cmd: describe(&cmd),
                status: out.status.to_string(),
                stderr: format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                )
                .trim_end()
                .to_owned(),
            });
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let line = stdout
            .lines()
            .rev()
            .find_map(|l| l.strip_prefix("VCI-PROBE "))
            .ok_or_else(|| AdapterError::Parse {
                what: "Rails application probe".into(),
                detail: format!(
                    "no VCI-PROBE line in {stdout:?} (stderr: {})",
                    String::from_utf8_lossy(&out.stderr)
                ),
            })?;
        parse_probe(line, &self.gemfile())
    }

    /// `bin/rails test <file> --seed 0` with the collector on.
    fn run_one(
        &self,
        collector: &Utf8Path,
        file: &str,
        env: &ChildEnv,
    ) -> Result<OneRun, AdapterError> {
        let dirs = RunDirs::new()?;
        let mut cmd = self.ruby_cmd(env, "collect", &dirs, collector);
        cmd.args(["bin/rails", "test"])
            .arg(file_arg(file))
            .args(["--seed", RAILS_SEED])
            .env("VCI_OUT", dirs.out.as_str())
            .env("VCI_TEST_ID", file);
        let out = cmd.output().map_err(|e| self.not_installed(e))?;
        let mut log = format!(
            "vci: {} (exit {})\n",
            describe(&cmd),
            out.status
                .code()
                .map_or_else(|| "signal".to_owned(), |c| c.to_string())
        )
        .into_bytes();
        log.extend_from_slice(&out.stdout);
        log.extend_from_slice(&out.stderr);
        let files = parse_jsonl_dir(&dirs.out)?;
        Ok((out.status.code(), files, log))
    }

    fn run_one_plain(
        &self,
        collector: &Utf8Path,
        file: Option<&str>,
        env: &ChildEnv,
    ) -> Result<OneRun, AdapterError> {
        let dirs = RunDirs::new()?;
        let mut cmd = self.ruby_cmd(env, "plain", &dirs, collector);
        cmd.args(["bin/rails", "test"]);
        if let Some(f) = file {
            cmd.arg(file_arg(f));
        }
        cmd.args(["--seed", RAILS_SEED]);
        let out = cmd.output().map_err(|e| self.not_installed(e))?;
        let mut log = format!(
            "vci: {} (exit {})\n",
            describe(&cmd),
            out.status
                .code()
                .map_or_else(|| "signal".to_owned(), |c| c.to_string())
        )
        .into_bytes();
        log.extend_from_slice(&out.stdout);
        log.extend_from_slice(&out.stderr);
        Ok((out.status.code(), vec![], log))
    }

    /// Parallel processes for `vci run`: `$VCI_JOBS` (default: CPUs up to
    /// 8); one at a time when database servers are attested (every process
    /// purges and reloads the same database).
    fn jobs(&self) -> usize {
        if self.allow_db {
            1
        } else {
            crate::pytest_jobs()
        }
    }
}

/// A test file argument that cannot be mistaken for an option.
fn file_arg(file: &str) -> String {
    if file.starts_with('-') {
        format!("./{file}")
    } else {
        file.to_owned()
    }
}

fn parse_probe(line: &str, gemfile: &Utf8Path) -> Result<Probe, AdapterError> {
    let bad = |d: String| AdapterError::Parse {
        what: "Rails application probe".into(),
        detail: d,
    };
    let v: Value = serde_json::from_str(line).map_err(|e| bad(e.to_string()))?;
    let s = |k: &str| -> String {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    for k in ["ruby", "engine", "rails", "bundler", "runner"] {
        if s(k).is_empty() {
            return Err(bad(format!(
                "missing {k} (is this a Rails application with Minitest?)"
            )));
        }
    }
    if let Some(t) = v.get("taints").and_then(Value::as_array)
        && !t.is_empty()
    {
        let t: Vec<&str> = t.iter().filter_map(Value::as_str).collect();
        return Err(bad(format!(
            "the application cannot be attested: {}",
            t.join(", ")
        )));
    }
    let used = s("gemfile");
    if Utf8Path::new(&used) != gemfile {
        return Err(bad(format!(
            "Bundler used {used}, not the project's {gemfile}"
        )));
    }
    let mut gems: InstalledExternals = BTreeMap::new();
    for g in v
        .get("gems")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("missing gems".into()))?
    {
        let name = g.get("name").and_then(Value::as_str).unwrap_or_default();
        let ver = g.get("version").and_then(Value::as_str).unwrap_or_default();
        if name.is_empty() || ver.is_empty() {
            return Err(bad(format!("bad gem entry {g}")));
        }
        let vs = gems.entry(name.to_owned()).or_default();
        if !vs.iter().any(|x| x == ver) {
            vs.push(ver.to_owned());
        }
    }
    let mut ruby_gems: Vec<String> = gems
        .iter()
        .flat_map(|(n, vs)| vs.iter().map(move |v| format!("{n}=={v}")))
        .collect();
    ruby_gems.sort();
    Ok(Probe {
        versions: ToolVersions {
            runner: s("runner"),
            ruby: s("ruby"),
            ruby_engine: s("engine"),
            rails: s("rails"),
            ruby_bundler: s("bundler"),
            ruby_libs: s("libs"),
            ruby_db: s("db"),
            ruby_gems,
            ..Default::default()
        },
        gems,
    })
}

/// Test files `bin/rails test` runs by default: `test/**/*_test.rb` without
/// `test/{system,dummy,fixtures}/**` (Rails' `DEFAULT_TEST` /
/// `DEFAULT_TEST_EXCLUDE`; system tests drive a browser and are run by
/// `bin/rails test:system`, never by vci). Like `Dir.glob`, `**` does not
/// follow symlinked directories or enter dot directories.
fn list_minitest(project_dir: &Utf8Path) -> Result<Vec<ListedFile>, AdapterError> {
    let test = project_dir.join("test");
    let mut out = Vec::new();
    if !test.is_dir() {
        return Ok(out);
    }
    let mut stack = vec![test.clone()];
    while let Some(d) = stack.pop() {
        for ent in d.read_dir_utf8()? {
            let ent = ent?;
            let name = ent.file_name();
            let ft = ent.file_type()?;
            if name.starts_with('.') {
                continue;
            }
            if ft.is_dir() {
                let rel = ent.path().strip_prefix(&test).map(|r| r.as_str());
                if d == test && matches!(rel, Ok("system" | "dummy" | "fixtures")) {
                    continue;
                }
                stack.push(ent.path().to_owned());
            } else if name.ends_with("_test.rb") && (ft.is_file() || ent.path().is_file()) {
                out.push(ListedFile {
                    abs: ent.path().to_owned(),
                    project: String::new(),
                });
            }
        }
    }
    out.sort_by(|a, b| a.abs.cmp(&b.abs));
    Ok(out)
}

/// RSpec files (`spec/**/*_spec.rb`), which the adapter does not run.
fn rspec_files(project_dir: &Utf8Path) -> usize {
    let spec = project_dir.join("spec");
    let mut n = 0;
    let mut stack = vec![spec];
    while let Some(d) = stack.pop() {
        let Ok(rd) = d.read_dir_utf8() else { continue };
        for ent in rd.flatten() {
            let Ok(ft) = ent.file_type() else { continue };
            if ft.is_dir() && !ent.file_name().starts_with('.') {
                stack.push(ent.path().to_owned());
            } else if ent.file_name().ends_with("_spec.rb") {
                n += 1;
            }
        }
    }
    n
}

impl RailsAdapter {
    /// Not yet supported: RSpec (see README). A project whose only tests are
    /// RSpec files is an error (so `vci ci` fails instead of running no
    /// test); beside Minitest files they are reported and left to the user.
    fn check_rspec(&self, minitest_files: usize) -> Result<Option<String>, AdapterError> {
        let n = rspec_files(&self.project_dir);
        if n == 0 {
            return Ok(None);
        }
        let msg = format!(
            "{n} RSpec file(s) in spec/: the rails adapter runs Minitest files (test/**/*_test.rb) only; RSpec is not supported yet, so run `bundle exec rspec` yourself"
        );
        if minitest_files == 0 {
            return Err(AdapterError::NotFound(msg));
        }
        Ok(Some(msg))
    }
}

impl Adapter for RailsAdapter {
    fn name(&self) -> &'static str {
        "rails"
    }

    fn project_dir(&self) -> &Utf8Path {
        &self.project_dir
    }

    fn list_test_files(&self, _env: &ChildEnv) -> Result<Vec<ListedFile>, AdapterError> {
        if !self.project_dir.join("bin/rails").is_file() {
            return Err(AdapterError::NotFound(format!(
                "{} has no bin/rails: the rails adapter's project dir must be the Rails application root",
                self.project_dir
            )));
        }
        let files = list_minitest(&self.project_dir)?;
        self.check_rspec(files.len())?;
        Ok(files)
    }

    fn warnings(&self, _env: &ChildEnv) -> Vec<String> {
        let n = list_minitest(&self.project_dir)
            .map(|f| f.len())
            .unwrap_or(0);
        match self.check_rspec(n) {
            Ok(Some(w)) => vec![w],
            Ok(None) => vec![],
            Err(e) => vec![e.to_string()],
        }
    }

    fn tool_versions(&self) -> Result<ToolVersions, AdapterError> {
        self.tool_versions_with_env(&None)
    }

    fn tool_versions_with_env(&self, env: &ChildEnv) -> Result<ToolVersions, AdapterError> {
        Ok(self.probe(env)?.versions)
    }

    fn builtin_pass_through(&self) -> &'static [&'static str] {
        RAILS_PASS_THROUGH
    }

    fn hashed_env_patterns(&self) -> &'static [&'static str] {
        RAILS_HASHED_ENV
    }

    fn installed_externals(
        &self,
        env: &ChildEnv,
    ) -> Result<Option<InstalledExternals>, AdapterError> {
        Ok(Some(self.probe(env)?.gems))
    }

    fn canonical_argv(&self, project_dir_rel_to_repo: &str, project_rel: &str) -> Vec<String> {
        vec![
            "rails".into(),
            "test".into(),
            "--root".into(),
            project_dir_rel_to_repo.into(),
            "--seed".into(),
            RAILS_SEED.into(),
            project_rel.into(),
        ]
    }

    fn config_candidates(&self) -> Vec<Utf8PathBuf> {
        RAILS_GLOBAL_FILES
            .iter()
            .map(|n| self.project_dir.join(n))
            .collect()
    }

    fn snapshot_candidates(&self, _test_abs: &Utf8Path) -> Vec<Utf8PathBuf> {
        vec![]
    }

    fn inferred_env_patterns(&self) -> &'static [&'static str] {
        &[]
    }

    fn run_collect(&self, files: &[String], env: &ChildEnv) -> Result<RunOutput, AdapterError> {
        let collector = self.collector_file()?;
        per_file_jobs(files, self.jobs(), |f| self.run_one(&collector, f, env))
    }

    /// With files: one `bin/rails test <file>` process per file, with the run
    /// conditions the attestations were made with (fresh databases loaded
    /// from the schema, one process, the fixed seed). Without: the whole
    /// suite in one process.
    fn run_plain(&self, files: &[String], env: &ChildEnv) -> Result<Option<i32>, AdapterError> {
        let collector = self.collector_file()?;
        if files.is_empty() {
            let n = list_minitest(&self.project_dir)?.len();
            if let Some(w) = self.check_rspec(n)? {
                eprintln!("vci: warning: {w}");
            }
            let (code, _, log) = self.run_one_plain(&collector, None, env)?;
            use std::io::Write as _;
            let _ = std::io::stderr().write_all(&log);
            return Ok(code);
        }
        Ok(per_file_jobs(files, self.jobs(), |f| {
            self.run_one_plain(&collector, Some(f), env)
        })?
        .exit_code)
    }

    /// An in-repository `vendor/bundle` (BUNDLE_PATH) holds installed gems,
    /// which are identified by name and version, never as paths.
    fn scratch_dirs(&self) -> Vec<Utf8PathBuf> {
        vec![self.project_dir.join("vendor/bundle")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_env_lists_and_globals() {
        let a = RailsAdapter::new(Utf8Path::new("/nonexistent/app"));
        assert_eq!(
            a.canonical_argv(".", "test/models/b_test.rb"),
            [
                "rails",
                "test",
                "--root",
                ".",
                "--seed",
                "0",
                "test/models/b_test.rb"
            ]
        );
        assert!(a.builtin_pass_through().contains(&"GEM_HOME"));
        assert!(a.hashed_env_patterns().contains(&"RUBY*"));
        assert!(a.hashed_env_patterns().contains(&"!RUBYOPT"));
        assert!(
            a.config_candidates()
                .iter()
                .any(|p| p.ends_with("Gemfile.lock"))
        );
        assert_eq!(file_arg("-x_test.rb"), "./-x_test.rb");
    }

    #[test]
    fn lists_like_rails_default_test_glob() {
        let t = tempfile::tempdir().unwrap();
        let d = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        for f in [
            "test/models/b_test.rb",
            "test/a_test.rb",
            "test/system/s_test.rb",
            "test/fixtures/f_test.rb",
            "test/dummy/x_test.rb",
            "test/models/helper.rb",
            "test/.hidden/h_test.rb",
            "test/lib/system/inner_test.rb",
        ] {
            let p = d.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "").unwrap();
        }
        let got: Vec<String> = list_minitest(&d)
            .unwrap()
            .into_iter()
            .map(|f| f.abs.strip_prefix(&d).unwrap().to_string())
            .collect();
        assert_eq!(
            got,
            [
                "test/a_test.rb",
                "test/lib/system/inner_test.rb",
                "test/models/b_test.rb"
            ]
        );
    }

    /// RSpec is not supported: a project with only RSpec files is an error
    /// (so `vci plan` runs everything and `vci ci` fails rather than running
    /// no test), and beside Minitest files they are a warning.
    #[test]
    fn rspec_only_projects_are_an_error() {
        let t = tempfile::tempdir().unwrap();
        let d = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        std::fs::create_dir_all(d.join("bin")).unwrap();
        std::fs::write(d.join("bin/rails"), "").unwrap();
        std::fs::create_dir_all(d.join("spec/models")).unwrap();
        std::fs::write(d.join("spec/models/b_spec.rb"), "").unwrap();
        let a = RailsAdapter::new(&d);
        let e = a.list_test_files(&None).unwrap_err().to_string();
        assert!(e.contains("RSpec is not supported yet"), "{e}");
        assert!(a.run_plain(&[], &None).is_err());
        std::fs::create_dir_all(d.join("test")).unwrap();
        std::fs::write(d.join("test/a_test.rb"), "").unwrap();
        assert_eq!(a.list_test_files(&None).unwrap().len(), 1);
        assert!(a.warnings(&None)[0].contains("1 RSpec file(s)"));
    }

    #[test]
    fn probe_output_parses_and_rejects_garbage() {
        let gf = Utf8Path::new("/app/Gemfile");
        let p = parse_probe(
            r#"{"ruby":"3.4.9p82","engine":"ruby 3.4.9","rails":"8.1.3.1","bundler":"4.0.9","runner":"minitest 6.0.6","platform":"arm64-darwin25","libs":"sqlite=3.53.2;tz=tzinfo-data","db":"sqlite3","gems":[{"name":"rack","version":"3.2.7","platform":"ruby","source":""},{"name":"nokogiri","version":"1.19.4","platform":"arm64-darwin","source":""}],"gemfile":"/app/Gemfile","taints":[]}"#,
            gf,
        )
        .unwrap();
        assert_eq!(p.versions.ruby, "3.4.9p82");
        assert_eq!(p.versions.runner, "minitest 6.0.6");
        assert_eq!(p.versions.ruby_gems, ["nokogiri==1.19.4", "rack==3.2.7"]);
        assert_eq!(p.gems["rack"], ["3.2.7"]);
        assert!(parse_probe(r#"{"ruby":"3.4.9p82"}"#, gf).is_err());
        assert!(parse_probe("nope", gf).is_err());
        let other = r#"{"ruby":"3","engine":"r","rails":"8","bundler":"4","runner":"m","gems":[],"gemfile":"/elsewhere/Gemfile","taints":[]}"#;
        assert!(parse_probe(other, gf).is_err(), "another Gemfile");
        let tainted = r#"{"ruby":"3","engine":"r","rails":"8","bundler":"4","runner":"m","gems":[],"gemfile":"/app/Gemfile","taints":["ruby:iseq-cache"]}"#;
        assert!(parse_probe(tainted, gf).is_err());
    }
}
