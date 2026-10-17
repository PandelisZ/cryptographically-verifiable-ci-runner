//! Rails adapter (Minitest and RSpec), with the `vci_collector` Ruby
//! collector (`ruby/vci-collector`) loaded through `RUBYOPT` before Bundler
//! and Rails boot. `vci run` of several files starts one process per runner
//! with the collector in batch mode (`VCI_RAILS_BATCH` names the list of
//! their test ids; see [`RailsAdapter::run_batch`]): it boots once and forks
//! one process per file, each a one-file run of its file; one file, or
//! `VCI_RAILS_PER_FILE=1`, runs one process per file from the start:
//!
//! ```text
//! RUBYOPT=-r<abs>/vci_collector.rb VCI_RAILS_MODE=collect VCI_OUT=<fresh dir> \
//!   TMPDIR=<fresh dir> RAILS_ENV=test PARALLEL_WORKERS=1 \
//!   DISABLE_SPRING=1 DISABLE_BOOTSNAP=1 BUNDLE_GEMFILE=<project>/Gemfile \
//!   ruby bin/rails test test/models/b_test.rb --seed 0
//! # several files: VCI_RAILS_BATCH=<list> ... bin/rails test <files> --seed 0
//! # an RSpec file (VCI_RAILS_RUNNER=rspec):
//!   ruby -e '<RSPEC_RUN_SCRIPT>' -- --options .rspec spec/models/b_spec.rb
//! ```
//!
//! The test database is the test engine's business: vci uses the databases
//! `config/database.yml` configures for the test environment as they are,
//! and Rails' `maintain_test_schema!` (which may run `bin/rails
//! db:test:prepare`), transactional tests and fixtures give each test its
//! starting state, as in a plain `bin/rails test` or `rspec`. What the
//! database holds is not an input (the collector records `db/schema.rb`,
//! `config/database.yml`, the fixture files and the code where Ruby reads
//! them). Because the files of a project share that database, they run one
//! at a time. `vci ci` runs the remaining files of a project in one process
//! per runner (`bin/rails test <files>`, `rspec <files>`;
//! `VCI_RAILS_MODE=plain`: no recording). Findings: `docs/spike-rails.md`.
//!
//! Which runner a project uses: the `runner` setting of its `vci.toml`
//! entry (from the base commit in `vci plan`), else detected: RSpec when
//! `Gemfile.lock` has `rspec-core` and there is a `spec/` directory (or a
//! `.rspec`) but no Minitest file, Minitest when there is no such RSpec
//! setup, and both when both are present (each file runs with its own
//! runner, as long as RSpec's file pattern lists no Minitest file).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use camino::{Utf8Path, Utf8PathBuf};
use serde_json::Value;

use crate::pytest::{OneRun, per_file_jobs};
use crate::vitest::{apply_env, describe};
use crate::{
    Adapter, AdapterError, ChildEnv, InstalledExternals, ListedFile, Observed, RunOutput,
    ToolVersions, parse_jsonl_dir,
};

/// Env var naming the `ruby` binary (default: `ruby` on PATH).
pub const RUBY_BIN_ENV: &str = "VCI_RUBY";

/// Env var naming the `ruby/vci-collector` directory (the one holding
/// `vci_collector.rb`).
pub const RUBY_COLLECTOR_ENV: &str = "VCI_RUBY_COLLECTOR";

const COLLECTOR_FILE: &str = "vci_collector.rb";

/// Set to `1` (in vci's environment): `vci run` runs one process per Rails
/// test file, as before batch mode (for debugging, or to compare).
pub const RAILS_PER_FILE_ENV: &str = "VCI_RAILS_PER_FILE";

/// Env var (of the Ruby process) naming the file that lists the test ids of
/// a batch run, one per line: the collector's batch mode.
const RAILS_BATCH_ENV: &str = "VCI_RAILS_BATCH";

/// The fixed Minitest seed of every run (`--seed`): the order of the tests in
/// a file and `Kernel#rand` (Minitest seeds it) are the same where the file
/// was attested and in `vci ci`.
pub const RAILS_SEED: &str = "0";

/// A test framework of the Rails adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RailsRunner {
    /// `bin/rails test <file>` (`test/**/*_test.rb`).
    Minitest,
    /// `rspec <file>` (the files RSpec's own configuration lists).
    Rspec,
}

impl RailsRunner {
    /// The `runner` value in `vci.toml`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "minitest" => Some(Self::Minitest),
            "rspec" => Some(Self::Rspec),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minitest => "minitest",
            Self::Rspec => "rspec",
        }
    }
}

/// The runners of a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Minitest,
    Rspec,
    /// Minitest files (`test/**/*_test.rb`) with `bin/rails test`, every
    /// other listed file with RSpec.
    Both,
}

/// `rspec` as vci runs it: Bundler first (what `bundle exec` does), then
/// RSpec's own runner with `$0 = "rspec"` (RSpec adds its default path only
/// for that command name). The arguments follow `--`.
pub const RSPEC_RUN_SCRIPT: &str =
    "require \"bundler/setup\"; require \"rspec/core\"; $0 = \"rspec\"; RSpec::Core::Runner.invoke";

/// Lists the files `rspec` would run (`VciCollector::RSpecSupport.list!`).
const RSPEC_LIST_SCRIPT: &str = "require \"bundler/setup\"; require \"rspec/core\"; $0 = \"rspec\"; VciCollector::RSpecSupport.list!(ARGV)";

/// Arguments every RSpec process gets: read the project's `.rspec` and no
/// other options file (`~/.rspec`, `$XDG_CONFIG_HOME/rspec/options` and
/// `.rspec-local` are never read).
pub const RSPEC_ARGS: &[&str] = &["--options", ".rspec"];

/// The seed RSpec defaults to under vci (the collector sets it; RSpec's own
/// default is random). Recorded in the canonical argv.
pub const RSPEC_DEFAULT_SEED: &str = "0";

/// Global inputs of an RSpec file on top of [`RAILS_GLOBAL_FILES`] (without
/// `test/test_helper.rb`): the options file RSpec reads.
pub const RSPEC_GLOBAL_FILES: &[&str] = &[".rspec"];

/// Directories of a Rails project (relative to it) that tests may write to:
/// a write there is allowed when git ignores the path (derived state that is
/// never in a checkout). Reading back a file the same process created is not
/// an input; reading one that existed before is (it will not match a fresh
/// checkout, so that file runs in CI).
pub const RAILS_SCRATCH_DIRS: &[&str] = &["log", "tmp", "storage", "coverage"];

/// Built-in ignore for Rails (docs/ENV.md): where Ruby, RubyGems, Bundler and
/// version managers find things, and the locale. The gems and Ruby they lead
/// to are checked directly (exact Ruby version, the resolved bundle, every
/// loaded gem's version), and so is the default encoding the locale decides
/// (the toolchain's `encoding=`). Reads of them by RubyGems' and Bundler's own code are not
/// observations; a test that reads one gets it hashed.
pub const RAILS_IGNORE: &[&str] = &[
    // The default encoding they decide is recorded in the toolchain.
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
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

/// Hashed whenever present in loose mode (deprecated), where every variable
/// reaches the tests: vci 1.5's list of what the runtime reads where nothing
/// observes it, kept so that loose mode hashes what it did. Strict mode removes
/// these unless they are built-in or vci.toml lists them.
pub const RAILS_LOOSE_HASH: &[&str] = &[
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
    // libvips and GLib read theirs in C when ruby-vips loads (VIPS_CONCURRENCY,
    // VIPS_BLOCK_UNTRUSTED, G_DEBUG, ...).
    "VIPS_*",
    "G_*",
    // RSpec reads its options from SPEC_OPTS too.
    "SPEC_OPTS",
    // OpenSSL reads its configuration file (OPENSSL_CONF), module directory
    // (OPENSSL_MODULES) and the like in C when Ruby's openssl loads.
    // SSL_CERT_FILE and SSL_CERT_DIR are not here: the collector refuses a
    // file that verifies with a store holding OpenSSL's default paths.
    "OPENSSL_*",
];

/// Built-in hash for Rails (docs/ENV.md): what Ruby reads in C at startup
/// (`RUBYLIB`, the VM and GC settings)
/// and the database and secret settings Rails takes from the environment
/// when it boots. Every other variable (`SEED`, `TESTOPTS`, `SPEC_OPTS`,
/// `BUNDLE_WITHOUT`, `RAILS_MASTER_KEY`, ...) is removed unless vci.toml lists
/// it; `RAILS_ENV`, `RACK_ENV` and `RUBYOPT` are vci's ([`RAILS_RUN_VARS`]).
pub const RAILS_HASH: &[&str] = &[
    "RUBYLIB",
    "RUBYGEMS_GEMDEPS",
    "RUBY_YJIT_ENABLE",
    "RUBY_GC_*",
    "RUBY_THREAD_VM_STACK_SIZE",
    "RUBY_THREAD_MACHINE_STACK_SIZE",
    "RUBY_FIBER_VM_STACK_SIZE",
    "RUBY_FIBER_MACHINE_STACK_SIZE",
    "RUBY_FREE_AT_EXIT",
    "RUBY_CRASH_REPORT",
    "RUBY_BOX",
    "RUBY_MN_THREADS",
    "RUBY_MAX_CPU",
    "DATABASE_URL",
    "*_DATABASE_URL",
    "SECRET_KEY_BASE",
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

/// What a probe process reports: the toolchain (`vci plan` and `vci run`
/// read it without booting the application, see [`RailsAdapter::light_probe`])
/// and, from a booted application, the native libraries it opened.
#[derive(Debug, Clone)]
struct Probe {
    versions: ToolVersions,
    /// gem name -> versions in the bundle.
    gems: InstalledExternals,
    /// `native:<file name>` -> versions: the native libraries the process
    /// opened through FFI (a booted application's, for the externals check).
    natives: InstalledExternals,
    /// Set when the probe without booting could not read the test
    /// environment's database adapters (config/database.yml's ERB uses the
    /// application): why.
    db_error: Option<String>,
}

/// The `-e` script of the probe that does not boot the application.
fn light_script(rails_app: bool) -> String {
    format!("require \"bundler/setup\"; VciCollector::Probe.light!({rails_app})")
}

/// The Rails adapter.
#[derive(Debug)]
pub struct RailsAdapter {
    project_dir: Utf8PathBuf,
    ruby: OsString,
    collector: Option<Utf8PathBuf>,
    /// The `runner` setting; `None`: detected (see [`RailsAdapter::mode`]).
    runner: Option<RailsRunner>,
    mode: OnceLock<Result<Mode, String>>,
    /// The probe without booting the application (the toolchain).
    light: OnceLock<Result<Probe, String>>,
    /// The probe of the booted application.
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
    /// Holds `tmp` and `out` (and a batch run's file list).
    base: Utf8PathBuf,
    tmpdir: Utf8PathBuf,
    out: Utf8PathBuf,
}

impl RunDirs {
    fn new() -> Result<Self, AdapterError> {
        let t = tempfile::Builder::new().prefix("vci-rails-").tempdir()?;
        let base = utf8_tmp(&t)?;
        let (tmpdir, out) = (base.join("tmp"), base.join("out"));
        for d in [&tmpdir, &out] {
            std::fs::create_dir(d)?;
        }
        Ok(Self {
            _tmp: t,
            base,
            tmpdir,
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
            runner: None,
            mode: OnceLock::new(),
            light: OnceLock::new(),
            probe: OnceLock::new(),
        }
    }

    /// The project's `runner` setting (`None`: detect it).
    pub fn with_runner(mut self, runner: Option<RailsRunner>) -> Self {
        self.runner = runner;
        self
    }

    /// Which runners the project uses: the setting, else detected from the
    /// checkout (see the module docs).
    fn mode(&self) -> Result<Mode, AdapterError> {
        self.mode
            .get_or_init(|| Ok(self.detect_mode()))
            .clone()
            .map_err(AdapterError::NotFound)
    }

    fn detect_mode(&self) -> Mode {
        match self.runner {
            Some(RailsRunner::Minitest) => Mode::Minitest,
            Some(RailsRunner::Rspec) => Mode::Rspec,
            None => {
                if !self.rspec_set_up() {
                    Mode::Minitest
                } else if list_minitest(&self.project_dir).is_ok_and(|f| f.is_empty()) {
                    Mode::Rspec
                } else {
                    Mode::Both
                }
            }
        }
    }

    /// RSpec is set up: `rspec-core` is in the lockfile and there is a
    /// `spec/` directory or a `.rspec`.
    fn rspec_set_up(&self) -> bool {
        rspec_in_lockfile(&self.project_dir)
            && (self.project_dir.join("spec").is_dir() || self.project_dir.join(".rspec").is_file())
    }

    /// The runner of a project-relative test file (`None`: the project's
    /// runners could not be decided).
    pub fn runner_of(&self, project_rel: &str) -> Option<RailsRunner> {
        match self.mode().ok()? {
            Mode::Minitest => Some(RailsRunner::Minitest),
            Mode::Rspec => Some(RailsRunner::Rspec),
            Mode::Both if is_minitest_path(project_rel) => Some(RailsRunner::Minitest),
            Mode::Both => Some(RailsRunner::Rspec),
        }
    }

    fn runner_of_abs(&self, abs: &Utf8Path) -> Option<RailsRunner> {
        let rel = abs.strip_prefix(&self.project_dir).ok()?;
        self.runner_of(rel.as_str())
    }

    /// Use this collector directory instead of looking it up.
    pub fn with_collector(mut self, dir: impl Into<Utf8PathBuf>) -> Self {
        self.collector = Some(dir.into());
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
    /// project's Gemfile, a fresh temp directory.
    fn ruby_cmd(
        &self,
        env: &ChildEnv,
        mode: &str,
        dirs: &RunDirs,
        collector: &Utf8Path,
    ) -> Command {
        self.ruby_cmd_for(env, mode, dirs, collector, RailsRunner::Minitest)
    }

    /// [`RailsAdapter::ruby_cmd`] for a process of `runner`.
    fn ruby_cmd_for(
        &self,
        env: &ChildEnv,
        mode: &str,
        dirs: &RunDirs,
        collector: &Utf8Path,
        runner: RailsRunner,
    ) -> Command {
        let mut c = Command::new(&self.ruby);
        c.current_dir(&self.project_dir).stdin(Stdio::null());
        apply_env(&mut c, env);
        for k in ["RUBYLIB", "VCI_OUT", "VCI_TEST_ID", "SPRING_SERVER_COMMAND"] {
            c.env_remove(k);
        }
        c.env("RUBYOPT", format!("-r{collector}"))
            .env("VCI_RAILS_MODE", mode)
            .env("VCI_RAILS_RUNNER", runner.as_str())
            .env("VCI_ROOT", self.project_dir.as_str())
            .env("VCI_REPO", self.repo_root().as_str())
            .env("TMPDIR", dirs.tmpdir.as_str())
            .env("RAILS_ENV", "test")
            .env("RACK_ENV", "test")
            .env("PARALLEL_WORKERS", "1")
            .env("DISABLE_SPRING", "1")
            .env("DISABLE_BOOTSNAP", "1")
            .env("BUNDLE_GEMFILE", self.gemfile().as_str());
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

    /// The probe of the booted application (once): `vci run` compares it
    /// with [`RailsAdapter::light_probe`]
    /// ([`Adapter::check_run_environment`]), and `vci plan` reads the native
    /// libraries from it when an attestation records one (the only boot of
    /// the plan).
    fn probe(&self, env: &ChildEnv) -> Result<Probe, AdapterError> {
        self.probe
            .get_or_init(|| self.run_probe(env).map_err(|e| e.to_string()))
            .clone()
            .map_err(|e| AdapterError::Parse {
                what: "Rails application probe".into(),
                detail: e,
            })
    }

    /// The toolchain without booting the application (once): Bundler sets up
    /// the bundle, and the collector loads what booting would load for the
    /// toolchain (`VciCollector::Probe.light!`). Rails' own code reads
    /// config/database.yml for the database adapters; only when that needs
    /// the application (its ERB uses it) is the application booted for them.
    /// A project without Rails is probed this way already (`require
    /// "bundler/setup"`).
    fn light_probe(&self, env: &ChildEnv) -> Result<Probe, AdapterError> {
        self.light
            .get_or_init(|| self.run_light(env).map_err(|e| e.to_string()))
            .clone()
            .map_err(|e| AdapterError::Parse {
                what: "Rails toolchain probe".into(),
                detail: e,
            })
    }

    fn run_light(&self, env: &ChildEnv) -> Result<Probe, AdapterError> {
        let rails_app = !self.plain_ruby();
        let mut p = self.run_probe_script(env, &light_script(rails_app), rails_app)?;
        if let Some(why) = p.db_error.take() {
            let booted = self.probe(env).map_err(|e| AdapterError::NotFound(format!(
                "config/database.yml could not be read without booting the application ({why}), and booting it failed: {e}"
            )))?;
            p.versions.ruby_db = booted.versions.ruby_db;
        }
        Ok(p)
    }

    /// Boot the application (test environment) once with the collector in
    /// probe mode: versions, the resolved bundle, the databases, the native
    /// libraries it opened.
    fn run_probe(&self, env: &ChildEnv) -> Result<Probe, AdapterError> {
        // A plain Ruby project (RSpec without Rails) has no application to
        // boot: its bundle is the toolchain.
        let rails_app = !self.plain_ruby();
        let script = if rails_app {
            "require File.expand_path(\"config/environment\")"
        } else {
            "require \"bundler/setup\""
        };
        self.run_probe_script(env, script, rails_app)
    }

    /// A probe process: `ruby -e <script>` with the collector in probe mode,
    /// which prints the `VCI-PROBE` line at exit.
    fn run_probe_script(
        &self,
        env: &ChildEnv,
        script: &str,
        rails_app: bool,
    ) -> Result<Probe, AdapterError> {
        let collector = self.collector_file()?;
        let dirs = RunDirs::new()?;
        let mut cmd = self.ruby_cmd(env, "probe", &dirs, &collector);
        cmd.args(["-e", script]);
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
        parse_probe(line, &self.gemfile(), rails_app)
    }

    /// The toolchain of the booted application, as [`Adapter::tool_versions`]
    /// reports it without booting it (what `vci run` compares, see
    /// [`Adapter::check_run_environment`]).
    pub fn booted_tool_versions(&self, env: &ChildEnv) -> Result<ToolVersions, AdapterError> {
        Ok(self.probe(env)?.versions)
    }

    /// An RSpec project without Rails (no `config/environment.rb`): a gem
    /// or plain Ruby code with a Gemfile.
    fn plain_ruby(&self) -> bool {
        matches!(self.mode(), Ok(Mode::Rspec))
            && !self.project_dir.join("config/environment.rb").is_file()
    }

    /// The command running test files (none: the whole suite) with
    /// `runner`: `bin/rails test <files> --seed 0`, or `rspec --options
    /// .rspec <files>`.
    fn test_cmd(
        &self,
        env: &ChildEnv,
        mode: &str,
        dirs: &RunDirs,
        collector: &Utf8Path,
        runner: RailsRunner,
        files: &[&str],
    ) -> Command {
        let mut cmd = self.ruby_cmd_for(env, mode, dirs, collector, runner);
        match runner {
            RailsRunner::Minitest => {
                cmd.args(["bin/rails", "test"]);
                cmd.args(files.iter().map(|f| file_arg(f)));
                cmd.args(["--seed", RAILS_SEED]);
            }
            RailsRunner::Rspec => {
                cmd.args(["-e", RSPEC_RUN_SCRIPT, "--"]).args(RSPEC_ARGS);
                cmd.args(files.iter().map(|f| file_arg(f)));
            }
        }
        cmd
    }

    /// The runner of `file`, or an error naming why it cannot be decided.
    fn runner_for_run(&self, file: &str) -> Result<RailsRunner, AdapterError> {
        self.runner_of(file).ok_or_else(|| {
            AdapterError::NotFound(format!(
                "cannot decide whether {file} is a Minitest or an RSpec file"
            ))
        })
    }

    /// One test file with the collector on: `bin/rails test <file> --seed
    /// 0`, or `rspec --options .rspec <file>`.
    fn run_one(
        &self,
        collector: &Utf8Path,
        file: &str,
        env: &ChildEnv,
    ) -> Result<OneRun, AdapterError> {
        let runner = self.runner_for_run(file)?;
        let dirs = RunDirs::new()?;
        let mut cmd = self.test_cmd(env, "collect", &dirs, collector, runner, &[file]);
        cmd.env("VCI_OUT", dirs.out.as_str())
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
        let mut files = parse_jsonl_dir(&dirs.out)?;
        exit_code_must_agree(&mut files, out.status.code());
        Ok((out.status.code(), files, log))
    }

    /// One plain process (no recording) of `runner` for `files` (none: the
    /// whole suite).
    fn run_one_plain(
        &self,
        collector: &Utf8Path,
        runner: RailsRunner,
        files: &[&str],
        env: &ChildEnv,
    ) -> Result<OneRun, AdapterError> {
        let dirs = RunDirs::new()?;
        let mut cmd = self.test_cmd(env, "plain", &dirs, collector, runner, files);
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

    /// Several files of `runner` with the collector in batch mode: `bin/rails
    /// test <files> --seed 0` or `rspec --options .rspec <files>`,
    /// `VCI_RAILS_BATCH` naming the list of their test ids. The process boots
    /// once (per helper the files' first statements require) and forks one
    /// process per file, one at a time, each a one-file run of its file from
    /// then on (see `VciCollector::Batch` in `vci_collector.rb`): each file's
    /// output is the one its one-file run writes, and its exit status is its
    /// own process's ([`read_batch`]). The files the batch could not run
    /// that way are returned to be run again one process per file.
    fn run_batch(
        &self,
        collector: &Utf8Path,
        runner: RailsRunner,
        files: &[&str],
        env: &ChildEnv,
    ) -> Result<BatchRun, AdapterError> {
        let dirs = RunDirs::new()?;
        let list = dirs.base.join("batch-files.txt");
        let mut text = files.join("\n");
        text.push('\n');
        std::fs::write(&list, text)?;
        let mut cmd = self.test_cmd(env, "collect", &dirs, collector, runner, files);
        cmd.env("VCI_OUT", dirs.out.as_str())
            .env(RAILS_BATCH_ENV, list.as_str());
        // macOS's Objective-C runtime kills a forked process that touches a
        // class another thread was initializing at the fork (vex-api's
        // boot: `+[__NSCFConstantString initialize] may have been in
        // progress in another thread when fork() was called`), unless this
        // is set when the process starts (the runtime's own switch for that
        // check). Only the runtime reads it; a lookup from Ruby would be
        // recorded like any other.
        if cfg!(target_os = "macos") {
            cmd.env("OBJC_DISABLE_INITIALIZE_FORK_SAFETY", "YES");
        }
        let out = cmd.output().map_err(|e| self.not_installed(e))?;
        let shown = match runner {
            RailsRunner::Minitest => format!(
                "ruby bin/rails test <{} files> --seed {RAILS_SEED}",
                files.len()
            ),
            RailsRunner::Rspec => format!("rspec --options .rspec <{} files>", files.len()),
        };
        let mut log = format!(
            "vci: {shown}, booted once, one process per file (exit {})\n",
            out.status
                .code()
                .map_or_else(|| "signal".to_owned(), |c| c.to_string())
        )
        .into_bytes();
        log.extend_from_slice(&out.stdout);
        log.extend_from_slice(&out.stderr);
        let (observed, fallback, code) = read_batch(&dirs.out, files)?;
        Ok(BatchRun {
            code,
            files: observed,
            fallback,
            log,
        })
    }

    /// Processes at a time for `vci run`: one. The files of a project share
    /// the test environment's database (as in `bin/rails test`, which runs
    /// them in one process), and Rails' `maintain_test_schema!` may rebuild
    /// it (`bin/rails db:test:prepare`) when it is not current.
    fn jobs(&self) -> usize {
        1
    }

    /// One plain process per `(runner, files)` group, one after the other
    /// (they share the test database); its log goes to stderr. The exit
    /// code: the first non-zero one (`None`: a process died from a signal).
    fn run_plain_groups(
        &self,
        collector: &Utf8Path,
        groups: &[(RailsRunner, Vec<&str>)],
        env: &ChildEnv,
    ) -> Result<Option<i32>, AdapterError> {
        let mut code = Some(0);
        for (r, files) in groups {
            let (c, _, log) = self.run_one_plain(collector, *r, files, env)?;
            use std::io::Write as _;
            let _ = std::io::stderr().write_all(&log);
            match (code, c) {
                (Some(0), c) => code = c,
                (Some(_), None) => code = None,
                _ => {}
            }
        }
        Ok(code)
    }
}

/// Files of a batch run to run again one process per file, with why.
type Fallback = Vec<(String, String)>;

/// What a batch run gave: the exit code of the files it ran (see
/// [`read_batch`]), their observations, the files to run again one process
/// per file, and its log.
struct BatchRun {
    code: Option<i32>,
    files: Vec<Observed>,
    fallback: Fallback,
    log: Vec<u8>,
}

/// A batch run's output in `out`: every file's `<sha256(id)>.jsonl`, written
/// by its own process as a one-file run writes it, and `batch/files.jsonl`
/// with a line per file: `{"id", "exit"}` (its process's exit status, null
/// when a signal killed it) or `{"id", "why"}` (it must run on its own).
/// Each file's [`Observed`] is checked against its own exit status as
/// [`RailsAdapter::run_one`] checks a one-file run's. A file without a line
/// or without output, or every file when there is no `files.jsonl`, falls
/// back. The exit code is the first non-zero one of the files' processes
/// (`None`: one died from a signal), a failed result counting as 1 when its
/// process exited 0 (Minitest without `allow_fork` keeps a forked process's
/// status at 0).
fn read_batch(
    out: &Utf8Path,
    files: &[&str],
) -> Result<(Vec<Observed>, Fallback, Option<i32>), AdapterError> {
    let everyone = |why: String| {
        (
            Vec::new(),
            files
                .iter()
                .map(|f| (f.to_string(), why.clone()))
                .collect::<Vec<_>>(),
            Some(0),
        )
    };
    let text = match std::fs::read_to_string(out.join("batch/files.jsonl")) {
        Ok(t) => t,
        Err(e) => {
            return Ok(everyone(format!(
                "the batch run said nothing of its files ({e})"
            )));
        }
    };
    // id => Ok(exit status) or Err(why it must run on its own).
    let mut said: BTreeMap<String, Result<Option<i32>, String>> = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            return Ok(everyone(format!(
                "the batch run's files.jsonl has a bad line {line:?}"
            )));
        };
        let Some(id) = v.get("id").and_then(Value::as_str) else {
            continue;
        };
        let st = match v.get("why").and_then(Value::as_str) {
            Some(why) => Err(why.to_owned()),
            None => Ok(v
                .get("exit")
                .and_then(Value::as_i64)
                .and_then(|c| i32::try_from(c).ok())),
        };
        said.entry(id.to_owned()).or_insert(st);
    }
    let mut own: BTreeMap<String, Observed> = parse_jsonl_dir(out)?
        .into_iter()
        .map(|o| (o.test_id.clone(), o))
        .collect();
    let mut observed = Vec::new();
    let mut fallback = Vec::new();
    let mut code = Some(0);
    for f in files {
        let c = match said.remove(*f) {
            None => {
                fallback.push((
                    f.to_string(),
                    "the batch run said nothing of it (its boot or the run ended early)".into(),
                ));
                continue;
            }
            Some(Err(why)) => {
                fallback.push((f.to_string(), why));
                continue;
            }
            Some(Ok(c)) => c,
        };
        let Some(mut o) = own.remove(*f) else {
            fallback.push((
                f.to_string(),
                format!(
                    "its process wrote no output (exit {})",
                    c.map_or_else(|| "signal".to_owned(), |c| c.to_string())
                ),
            ));
            continue;
        };
        exit_code_must_agree(std::slice::from_mut(&mut o), c);
        let c = if c == Some(0) && failed(&o) {
            Some(1)
        } else {
            c
        };
        match (code, c) {
            (Some(0), c) => code = c,
            (Some(_), None) => code = None,
            _ => {}
        }
        observed.push(o);
    }
    Ok((observed, fallback, code))
}

/// A result that failed (a test failed or errored).
fn failed(o: &Observed) -> bool {
    o.result
        .as_ref()
        .is_some_and(|r| r.state == "failed" && r.failed > 0)
}

/// Run each file one process per file, never in batch mode (set in vci's
/// environment).
fn per_file_forced() -> bool {
    std::env::var(RAILS_PER_FILE_ENV).is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Taint (prefix of) a passing result whose process did not exit 0.
const RAILS_EXIT_TAINT: &str = "vci:process-exit:";

/// A file whose test framework reported a pass is still refused when its
/// process did not exit 0 (or died from a signal): an `at_exit` handler that
/// ran after the results were reported (SimpleCov's `minimum_coverage`,
/// minitest/autorun loaded into an RSpec process, a test's own `at_exit {
/// exit 1 }`) failed the run, as it fails a plain run. Independent of the
/// exit status the collector records.
fn exit_code_must_agree(files: &mut [Observed], code: Option<i32>) {
    if code == Some(0) {
        return;
    }
    let how = code.map_or_else(
        || "was killed by a signal".to_owned(),
        |c| format!("exited {c}"),
    );
    for o in files.iter_mut() {
        // A pass with skipped tests too: those are attested when the policy
        // waives `result:skipped`.
        if o.result
            .as_ref()
            .is_some_and(|r| r.state == "passed" && r.failed == 0)
        {
            o.taints.push(format!(
                "{RAILS_EXIT_TAINT}{} (the process {how} after the test framework reported a pass: an at_exit handler such as SimpleCov's minimum_coverage failed the run)",
                code.map_or_else(|| "signal".to_owned(), |c| c.to_string())
            ));
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

fn parse_probe(line: &str, gemfile: &Utf8Path, rails_app: bool) -> Result<Probe, AdapterError> {
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
        if k == "rails" && !rails_app {
            continue;
        }
        if s(k).is_empty() {
            return Err(bad(format!(
                "missing {k} (is this a Rails application, or a Ruby project with a Gemfile?)"
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
    // Native libraries the application opened through FFI while it booted
    // (`native:<file name>` -> `sha256:<hex>`): a test file that recorded one
    // is checked against what this process opens, like a gem. Not part of
    // the toolchain's bundle list.
    let mut natives: InstalledExternals = BTreeMap::new();
    if let Some(list) = v.get("natives").and_then(Value::as_array) {
        for n in list {
            let name = n.get("name").and_then(Value::as_str).unwrap_or_default();
            let ver = n.get("version").and_then(Value::as_str).unwrap_or_default();
            if !name.starts_with("native:") || ver.is_empty() {
                return Err(bad(format!("bad native library entry {n}")));
            }
            let vs = natives.entry(name.to_owned()).or_default();
            if !vs.iter().any(|x| x == ver) {
                vs.push(ver.to_owned());
            }
        }
    }
    // The probe without booting reports `"db": null` (and why) when it could
    // not read config/database.yml without the application.
    let db_error = match v.get("db") {
        Some(Value::Null) => Some(
            v.get("dbError")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
        ),
        _ => None,
    };
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
        natives,
        db_error,
    })
}

/// Where the toolchain read without booting the application (`light`)
/// differs from the booted application's (`booted`), as `what: without
/// booting X, booted Y`.
fn probe_differences(light: &Probe, booted: &Probe) -> Vec<String> {
    let (l, b) = (&light.versions, &booted.versions);
    let mut out = Vec::new();
    for (what, x, y) in [
        ("ruby", &l.ruby, &b.ruby),
        ("ruby engine", &l.ruby_engine, &b.ruby_engine),
        ("rails", &l.rails, &b.rails),
        ("bundler", &l.ruby_bundler, &b.ruby_bundler),
        ("test frameworks", &l.runner, &b.runner),
        ("libraries", &l.ruby_libs, &b.ruby_libs),
        ("database adapters", &l.ruby_db, &b.ruby_db),
    ] {
        if x != y {
            out.push(format!("{what}: without booting {x:?}, booted {y:?}"));
        }
    }
    if l.ruby_gems != b.ruby_gems || light.gems != booted.gems {
        let only = |a: &[String], z: &[String]| -> Vec<String> {
            a.iter().filter(|g| !z.contains(g)).cloned().collect()
        };
        out.push(format!(
            "bundle: without booting only {:?}, booted only {:?}",
            only(&l.ruby_gems, &b.ruby_gems),
            only(&b.ruby_gems, &l.ruby_gems)
        ));
    }
    out
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

/// Is a project-relative path one `bin/rails test` runs by default
/// ([`list_minitest`]'s rule: `test/**/*_test.rb` outside
/// `test/{system,dummy,fixtures}` and dot directories)?
fn is_minitest_path(rel: &str) -> bool {
    let comps: Vec<&str> = rel.split('/').collect();
    comps.len() >= 2
        && comps[0] == "test"
        && !matches!(comps[1], "system" | "dummy" | "fixtures")
        && comps.iter().all(|c| !c.is_empty() && !c.starts_with('.'))
        && comps.last().is_some_and(|f| f.ends_with("_test.rb"))
}

/// `rspec-core` is a spec of the project's lockfile (`Gemfile.lock`, or
/// `gems.locked` beside `gems.rb`).
fn rspec_in_lockfile(project_dir: &Utf8Path) -> bool {
    ["Gemfile.lock", "gems.locked"].iter().any(|n| {
        std::fs::read_to_string(project_dir.join(n))
            .is_ok_and(|t| t.lines().any(|l| l.starts_with("    rspec-core (")))
    })
}

/// Files named like RSpec files (`spec/**/*_spec.rb`), counted for the
/// message when the project runs Minitest only.
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
    /// RSpec files in a project that runs Minitest only (the `runner =
    /// "minitest"` setting, or RSpec is not in the lockfile): a project
    /// whose only tests are RSpec files is an error (so `vci ci` fails
    /// instead of running no test); beside Minitest files they are reported
    /// and left to the user.
    fn check_rspec(&self, minitest_files: usize) -> Result<Option<String>, AdapterError> {
        let n = rspec_files(&self.project_dir);
        if n == 0 {
            return Ok(None);
        }
        let why = if self.runner == Some(RailsRunner::Minitest) {
            "the project's runner is \"minitest\" in vci.toml (set runner = \"rspec\", or remove the setting to run both)"
        } else {
            "rspec-core is not in Gemfile.lock, so vci does not run RSpec (add rspec-rails or rspec-core to the Gemfile)"
        };
        let msg = format!(
            "{n} RSpec file(s) in spec/ are not run by vci: {why}; run `bundle exec rspec` yourself"
        );
        if minitest_files == 0 {
            return Err(AdapterError::NotFound(msg));
        }
        Ok(Some(msg))
    }

    fn require_bin_rails(&self) -> Result<(), AdapterError> {
        if !self.project_dir.join("bin/rails").is_file() {
            return Err(AdapterError::NotFound(format!(
                "{} has no bin/rails: the rails adapter's project dir must be the Rails application root",
                self.project_dir
            )));
        }
        Ok(())
    }

    /// The files `rspec` (no file arguments) would run, as RSpec's own
    /// configuration lists them: `.rspec` (only that options file, as in
    /// every run) and `SPEC_OPTS` decide `default_path`, `pattern` and
    /// `exclude_pattern`; files `.rspec` requires are loaded.
    fn list_rspec(&self, env: &ChildEnv) -> Result<Vec<ListedFile>, AdapterError> {
        let collector = self.collector_file()?;
        let dirs = RunDirs::new()?;
        let mut cmd = self.ruby_cmd_for(env, "plain", &dirs, &collector, RailsRunner::Rspec);
        cmd.args(["-e", RSPEC_LIST_SCRIPT, "--"]).args(RSPEC_ARGS);
        let out = cmd.output().map_err(|e| self.not_installed(e))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let fail = |detail: String| AdapterError::Command {
            cmd: describe(&cmd),
            status: out.status.to_string(),
            stderr: detail,
        };
        if !out.status.success() {
            return Err(fail(
                format!("{stdout}{}", String::from_utf8_lossy(&out.stderr))
                    .trim_end()
                    .to_owned(),
            ));
        }
        let line = stdout
            .lines()
            .rev()
            .find_map(|l| l.strip_prefix("VCI-RSPEC-LIST "))
            .ok_or_else(|| {
                fail(format!(
                    "no VCI-RSPEC-LIST line in {stdout:?} (stderr: {})",
                    String::from_utf8_lossy(&out.stderr)
                ))
            })?;
        parse_rspec_list(line, &self.project_dir)
    }

    /// Minitest and RSpec files of a project that runs both: every listed
    /// file must belong to exactly one runner.
    fn list_both(&self, env: &ChildEnv) -> Result<Vec<ListedFile>, AdapterError> {
        let mut files = list_minitest(&self.project_dir)?;
        let rspec = self.list_rspec(env)?;
        let clash: Vec<String> = rspec
            .iter()
            .filter_map(|f| f.abs.strip_prefix(&self.project_dir).ok())
            .filter(|r| is_minitest_path(r.as_str()))
            .map(|r| r.to_string())
            .collect();
        if !clash.is_empty() {
            return Err(AdapterError::NotFound(format!(
                "this project has Minitest files (test/**/*_test.rb) and RSpec files, and RSpec's file pattern also lists Minitest files ({}): set runner = \"minitest\" or runner = \"rspec\" for it in vci.toml",
                clash.join(", ")
            )));
        }
        files.extend(rspec);
        files.sort_by(|a, b| a.abs.cmp(&b.abs));
        Ok(files)
    }
}

/// Parse the `VCI-RSPEC-LIST` line: every file must be inside the project.
fn parse_rspec_list(line: &str, project_dir: &Utf8Path) -> Result<Vec<ListedFile>, AdapterError> {
    let bad = |d: String| AdapterError::Parse {
        what: "RSpec file list".into(),
        detail: d,
    };
    let v: Value = serde_json::from_str(line).map_err(|e| bad(e.to_string()))?;
    let files = v
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| bad(format!("no files in {line}")))?;
    let mut out = Vec::new();
    for f in files {
        let p = f
            .as_str()
            .ok_or_else(|| bad(format!("bad file entry {f}")))?;
        let abs = Utf8PathBuf::from(p);
        let abs = abs.canonicalize_utf8().unwrap_or(abs);
        if !abs.is_absolute() || !abs.starts_with(project_dir) {
            return Err(bad(format!(
                "RSpec lists {p}, outside the project dir {project_dir} (check pattern and default_path in .rspec)"
            )));
        }
        out.push(ListedFile {
            abs,
            project: String::new(),
        });
    }
    out.sort_by(|a, b| a.abs.cmp(&b.abs));
    out.dedup_by(|a, b| a.abs == b.abs);
    Ok(out)
}

impl Adapter for RailsAdapter {
    fn name(&self) -> &'static str {
        "rails"
    }

    fn project_dir(&self) -> &Utf8Path {
        &self.project_dir
    }

    fn list_test_files(&self, env: &ChildEnv) -> Result<Vec<ListedFile>, AdapterError> {
        match self.mode()? {
            Mode::Minitest => {
                self.require_bin_rails()?;
                let files = list_minitest(&self.project_dir)?;
                self.check_rspec(files.len())?;
                Ok(files)
            }
            Mode::Rspec => self.list_rspec(env),
            Mode::Both => {
                self.require_bin_rails()?;
                self.list_both(env)
            }
        }
    }

    fn warnings(&self, _env: &ChildEnv) -> Vec<String> {
        let minitest = list_minitest(&self.project_dir)
            .map(|f| f.len())
            .unwrap_or(0);
        match self.mode() {
            Ok(Mode::Minitest) => match self.check_rspec(minitest) {
                Ok(Some(w)) => vec![w],
                Ok(None) => vec![],
                Err(e) => vec![e.to_string()],
            },
            Ok(Mode::Rspec) if minitest > 0 => vec![format!(
                "{minitest} Minitest file(s) in test/ are not run by vci: the project's runner is \"rspec\" in vci.toml (remove the setting to run both)"
            )],
            _ => vec![],
        }
    }

    fn tool_versions(&self) -> Result<ToolVersions, AdapterError> {
        self.tool_versions_with_env(&None)
    }

    /// Read without booting the application ([`RailsAdapter::light_probe`]),
    /// in `vci plan` and in what `vci run` records alike.
    fn tool_versions_with_env(&self, env: &ChildEnv) -> Result<ToolVersions, AdapterError> {
        Ok(self.light_probe(env)?.versions)
    }

    fn builtin_ignore(&self) -> &'static [&'static str] {
        RAILS_IGNORE
    }

    fn builtin_hash(&self) -> &'static [&'static str] {
        RAILS_HASH
    }

    fn loose_hash(&self) -> &'static [&'static str] {
        RAILS_LOOSE_HASH
    }

    /// The gems of the bundle Bundler resolves (without booting).
    fn installed_externals(
        &self,
        env: &ChildEnv,
    ) -> Result<Option<InstalledExternals>, AdapterError> {
        Ok(Some(self.light_probe(env)?.gems))
    }

    /// The native libraries the booted application opened through FFI (a
    /// project without Rails: what `require "bundler/setup"` opened).
    fn native_externals(&self, env: &ChildEnv) -> Result<Option<InstalledExternals>, AdapterError> {
        let p = if self.plain_ruby() {
            self.light_probe(env)?
        } else {
            self.probe(env)?
        };
        Ok(Some(p.natives))
    }

    /// Boot the application once: it must boot under vci's run conditions
    /// with nothing that makes it unattestable (the probe's checks), and
    /// report exactly the toolchain read without booting it, which is what
    /// attestations record and `vci plan` compares. `vci run` attests
    /// nothing otherwise. (`vci plan` does not boot the application for
    /// this.)
    fn check_run_environment(&self, env: &ChildEnv) -> Result<(), AdapterError> {
        if self.plain_ruby() {
            // Probed the same way either way.
            return Ok(());
        }
        let light = self.light_probe(env)?;
        let booted = self.probe(env)?;
        let diffs = probe_differences(&light, &booted);
        if diffs.is_empty() {
            return Ok(());
        }
        Err(AdapterError::NotFound(format!(
            "the booted application reports another toolchain than vci reads without booting it (what attestations record and `vci plan` compares): {}",
            diffs.join("; ")
        )))
    }

    /// Minitest: `rails test --root <dir> --seed 0 <file>`; RSpec: `rails
    /// rspec --root <dir> --options .rspec --default-seed 0 <file>`. A file
    /// whose runner cannot be decided gets an argv no attestation has.
    fn canonical_argv(&self, project_dir_rel_to_repo: &str, project_rel: &str) -> Vec<String> {
        match self.runner_of(project_rel) {
            Some(RailsRunner::Minitest) => vec![
                "rails".into(),
                "test".into(),
                "--root".into(),
                project_dir_rel_to_repo.into(),
                "--seed".into(),
                RAILS_SEED.into(),
                project_rel.into(),
            ],
            Some(RailsRunner::Rspec) => {
                let mut v: Vec<String> = vec![
                    "rails".into(),
                    "rspec".into(),
                    "--root".into(),
                    project_dir_rel_to_repo.into(),
                ];
                v.extend(RSPEC_ARGS.iter().map(|s| s.to_string()));
                v.extend([
                    "--default-seed".into(),
                    RSPEC_DEFAULT_SEED.into(),
                    project_rel.into(),
                ]);
                v
            }
            None => vec![
                "rails".into(),
                "undecided-runner".into(),
                "--root".into(),
                project_dir_rel_to_repo.into(),
                project_rel.into(),
            ],
        }
    }

    fn config_candidates(&self) -> Vec<Utf8PathBuf> {
        RAILS_GLOBAL_FILES
            .iter()
            .map(|n| self.project_dir.join(n))
            .collect()
    }

    /// Minitest files: [`RAILS_GLOBAL_FILES`]. RSpec files: the same without
    /// `test/test_helper.rb`, plus [`RSPEC_GLOBAL_FILES`] (`.rspec`).
    fn config_candidates_for(&self, test_abs: &Utf8Path) -> Vec<Utf8PathBuf> {
        if self.runner_of_abs(test_abs) == Some(RailsRunner::Rspec) {
            RAILS_GLOBAL_FILES
                .iter()
                .filter(|n| **n != "test/test_helper.rb")
                .chain(RSPEC_GLOBAL_FILES)
                .map(|n| self.project_dir.join(n))
                .collect()
        } else {
            self.config_candidates()
        }
    }

    fn snapshot_candidates(&self, _test_abs: &Utf8Path) -> Vec<Utf8PathBuf> {
        vec![]
    }

    fn collector_dirs(&self) -> Vec<Utf8PathBuf> {
        self.collector_file()
            .ok()
            .and_then(|f| f.parent().map(Utf8Path::to_owned))
            .into_iter()
            .collect()
    }

    /// One file (or `VCI_RAILS_PER_FILE=1`): one process per file. Several:
    /// one batch per runner for all its files, booted once
    /// ([`RailsAdapter::run_batch`]); the files it could not run that way
    /// run again one process per file afterwards (and say so). The exit
    /// code: the first non-zero one of the files' own processes (`None`: one
    /// died from a signal), never that of a batch's own process.
    fn run_collect(&self, files: &[String], env: &ChildEnv) -> Result<RunOutput, AdapterError> {
        let collector = self.collector_file()?;
        if files.len() < 2 || per_file_forced() {
            return per_file_jobs(files, self.jobs(), |f| self.run_one(&collector, f, env));
        }
        let mut groups: Vec<(RailsRunner, Vec<&str>)> = Vec::new();
        for f in files {
            let runner = self.runner_for_run(f)?;
            match groups.iter_mut().find(|(r, _)| *r == runner) {
                Some((_, v)) => v.push(f.as_str()),
                None => groups.push((runner, vec![f.as_str()])),
            }
        }
        let mut exit = Some(0);
        let mut observed = Vec::new();
        let mut again: Vec<String> = Vec::new();
        let join = |exit: &mut Option<i32>, c: Option<i32>| match (*exit, c) {
            (Some(0), c) => *exit = c,
            (Some(_), None) => *exit = None,
            _ => {}
        };
        for (runner, group) in &groups {
            if group.len() < 2 {
                again.extend(group.iter().map(|f| f.to_string()));
                continue;
            }
            let b = self.run_batch(&collector, *runner, group, env)?;
            {
                use std::io::Write as _;
                let _ = std::io::stderr().write_all(&b.log);
            }
            join(&mut exit, b.code);
            observed.extend(b.files);
            if !b.fallback.is_empty() {
                eprintln!(
                    "vci: {} of {} file(s) of the batch run again one process per file:",
                    b.fallback.len(),
                    group.len()
                );
                for (f, why) in b.fallback.iter().take(10) {
                    eprintln!("vci:   {f}: {why}");
                }
                if b.fallback.len() > 10 {
                    eprintln!("vci:   ... and {} more", b.fallback.len() - 10);
                }
                again.extend(b.fallback.into_iter().map(|(f, _)| f));
            }
        }
        if !again.is_empty() {
            let out = per_file_jobs(&again, self.jobs(), |f| self.run_one(&collector, f, env))?;
            join(&mut exit, out.exit_code);
            observed.extend(out.files);
        }
        Ok(RunOutput {
            exit_code: exit,
            files: observed,
        })
    }

    /// With files: one process per runner for all of them (`bin/rails test
    /// <files> --seed 0`, `rspec --options .rspec <files>`), the engine's own
    /// way, with the run conditions the attestations were made with (no
    /// parallel workers, the fixed seed, RSpec's options from `.rspec`
    /// only). Without: the whole suite, one process per runner (`bin/rails
    /// test`, `rspec`).
    fn run_plain(&self, files: &[String], env: &ChildEnv) -> Result<Option<i32>, AdapterError> {
        let collector = self.collector_file()?;
        if files.is_empty() {
            let mode = self.mode()?;
            let runners: &[RailsRunner] = match mode {
                Mode::Minitest => {
                    let n = list_minitest(&self.project_dir)?.len();
                    if let Some(w) = self.check_rspec(n)? {
                        eprintln!("vci: warning: {w}");
                    }
                    &[RailsRunner::Minitest]
                }
                Mode::Rspec => &[RailsRunner::Rspec],
                Mode::Both => &[RailsRunner::Minitest, RailsRunner::Rspec],
            };
            let groups: Vec<(RailsRunner, Vec<&str>)> =
                runners.iter().map(|r| (*r, Vec::new())).collect();
            return self.run_plain_groups(&collector, &groups, env);
        }
        // The files of each runner, in the order given.
        let mut groups: Vec<(RailsRunner, Vec<&str>)> = Vec::new();
        for f in files {
            let runner = self.runner_for_run(f)?;
            match groups.iter_mut().find(|(r, _)| *r == runner) {
                Some((_, v)) => v.push(f.as_str()),
                None => groups.push((runner, vec![f.as_str()])),
            }
        }
        self.run_plain_groups(&collector, &groups, env)
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
        assert!(a.builtin_ignore().contains(&"GEM_HOME"));
        assert!(a.builtin_hash().contains(&"RUBYLIB"));
        // vci sets RUBYOPT, RAILS_ENV and RACK_ENV itself.
        for k in RAILS_RUN_VARS {
            assert!(!a.builtin_hash().contains(k), "{k}");
        }
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

    /// RSpec files the adapter does not run (rspec-core is not in the
    /// lockfile): a project with only such files is an error (so `vci plan`
    /// runs everything and `vci ci` fails rather than running no test), and
    /// beside Minitest files they are a warning.
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
        assert!(e.contains("rspec-core is not in Gemfile.lock"), "{e}");
        assert!(a.run_plain(&[], &None).is_err());
        std::fs::create_dir_all(d.join("test")).unwrap();
        std::fs::write(d.join("test/a_test.rb"), "").unwrap();
        assert_eq!(a.list_test_files(&None).unwrap().len(), 1);
        assert!(a.warnings(&None)[0].contains("1 RSpec file(s)"));
        // `runner = "minitest"` keeps RSpec files out even with rspec-core
        // in the lockfile.
        std::fs::write(d.join("Gemfile.lock"), LOCK_WITH_RSPEC).unwrap();
        let a = RailsAdapter::new(&d).with_runner(Some(RailsRunner::Minitest));
        assert_eq!(a.list_test_files(&None).unwrap().len(), 1);
        assert!(
            a.warnings(&None)[0].contains("runner is \"minitest\""),
            "{:?}",
            a.warnings(&None)
        );
    }

    const LOCK_WITH_RSPEC: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rspec-core (3.13.6)\n      rspec-support (~> 3.13.0)\n    rspec-support (3.13.7)\n\nPLATFORMS\n  ruby\n";

    /// The runner setting, else detection: RSpec when rspec-core is locked
    /// and spec/ (or .rspec) exists with no Minitest file; both when both
    /// are present (by path); Minitest otherwise.
    #[test]
    fn runner_detection_and_per_file_runner() {
        let t = tempfile::tempdir().unwrap();
        let d = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        let mode = |r: Option<RailsRunner>| RailsAdapter::new(&d).with_runner(r).mode().unwrap();
        assert_eq!(mode(None), Mode::Minitest, "nothing at all");
        std::fs::create_dir_all(d.join("spec")).unwrap();
        assert_eq!(
            mode(None),
            Mode::Minitest,
            "spec/ without rspec-core locked"
        );
        std::fs::write(d.join("Gemfile.lock"), LOCK_WITH_RSPEC).unwrap();
        assert_eq!(mode(None), Mode::Rspec);
        assert_eq!(mode(Some(RailsRunner::Minitest)), Mode::Minitest);
        std::fs::create_dir_all(d.join("test/models")).unwrap();
        std::fs::write(d.join("test/models/b_test.rb"), "").unwrap();
        assert_eq!(mode(None), Mode::Both);
        assert_eq!(mode(Some(RailsRunner::Rspec)), Mode::Rspec);
        let a = RailsAdapter::new(&d);
        assert_eq!(
            a.runner_of("test/models/b_test.rb"),
            Some(RailsRunner::Minitest)
        );
        assert_eq!(
            a.runner_of("spec/models/b_spec.rb"),
            Some(RailsRunner::Rspec)
        );
        assert_eq!(
            a.runner_of("test/system/s_test.rb"),
            Some(RailsRunner::Rspec)
        );
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
        assert_eq!(
            a.canonical_argv("app", "spec/models/b_spec.rb"),
            [
                "rails",
                "rspec",
                "--root",
                "app",
                "--options",
                ".rspec",
                "--default-seed",
                "0",
                "spec/models/b_spec.rb"
            ]
        );
        let g = a.config_candidates_for(&d.join("spec/models/b_spec.rb"));
        assert!(g.contains(&d.join(".rspec")), "{g:?}");
        assert!(!g.contains(&d.join("test/test_helper.rb")), "{g:?}");
        let g = a.config_candidates_for(&d.join("test/models/b_test.rb"));
        assert_eq!(g, a.config_candidates(), "Minitest files are unchanged");
        assert!(!g.contains(&d.join(".rspec")));
        for (p, want) in [
            ("test/a_test.rb", true),
            ("test/lib/system/x_test.rb", true),
            ("test/system/x_test.rb", false),
            ("test/fixtures/x_test.rb", false),
            ("test/.hidden/x_test.rb", false),
            ("test/a_spec.rb", false),
            ("spec/a_test.rb", false),
            ("a_test.rb", false),
        ] {
            assert_eq!(is_minitest_path(p), want, "{p}");
        }
    }

    #[test]
    fn rspec_list_parses_and_stays_in_the_project() {
        let t = tempfile::tempdir().unwrap();
        let d = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        std::fs::create_dir_all(d.join("spec")).unwrap();
        std::fs::write(d.join("spec/b_spec.rb"), "").unwrap();
        std::fs::write(d.join("spec/a_spec.rb"), "").unwrap();
        let line = format!(
            r#"{{"files":["{0}/spec/b_spec.rb","{0}/spec/a_spec.rb"],"defaultPath":"spec","pattern":"**{{,/*/**}}/*_spec.rb","excludePattern":""}}"#,
            d
        );
        let got: Vec<String> = parse_rspec_list(&line, &d)
            .unwrap()
            .into_iter()
            .map(|f| f.abs.strip_prefix(&d).unwrap().to_string())
            .collect();
        assert_eq!(got, ["spec/a_spec.rb", "spec/b_spec.rb"]);
        assert!(parse_rspec_list(r#"{"files":["/elsewhere/x_spec.rb"]}"#, &d).is_err());
        assert!(parse_rspec_list("nope", &d).is_err());
    }

    #[test]
    fn a_pass_with_a_non_zero_exit_is_tainted() {
        let pass = |state: &str| Observed {
            result: Some(vci_core::TestResult {
                state: state.into(),
                tests: 1,
                failed: 0,
                skipped: 0,
                duration_ms: 1,
            }),
            ..Default::default()
        };
        let mut files = vec![pass("passed"), pass("failed")];
        exit_code_must_agree(&mut files, Some(0));
        assert!(files.iter().all(|o| o.taints.is_empty()));
        exit_code_must_agree(&mut files, Some(2));
        assert!(files[0].taints[0].starts_with("vci:process-exit:2 (the process exited 2"));
        assert!(files[1].taints.is_empty(), "a failure is reported as such");
        let mut files = vec![pass("passed")];
        exit_code_must_agree(&mut files, None);
        assert!(files[0].taints[0].starts_with("vci:process-exit:signal"));
    }

    /// A batch run's output: each file's own output (written by its own
    /// process) with its own exit status: a pass whose process exited
    /// non-zero is tainted, a failure with exit 0 counts as exit 1, and the
    /// batch's exit code is the files'. A file the collector sends back,
    /// without a line, or without output falls back; no files.jsonl: every
    /// file falls back.
    #[test]
    fn batch_output_is_read_per_file() {
        use sha2::{Digest, Sha256};
        let t = tempfile::tempdir().unwrap();
        let out = Utf8PathBuf::from_path_buf(t.path().to_owned()).unwrap();
        std::fs::create_dir(out.join("batch")).unwrap();
        let name = |id: &str| format!("{}.jsonl", hex::encode(Sha256::digest(id.as_bytes())));
        let write = |path: Utf8PathBuf, lines: &[String]| {
            std::fs::write(path, lines.join("\n") + "\n").unwrap();
        };
        let meta =
            |id: &str| format!(r#"{{"v":1,"kind":"meta","testId":"{id}","adapter":"rails"}}"#);
        let read = |p: &str| format!(r#"{{"kind":"read","path":"/repo/{p}"}}"#);
        let result = |state: &str, failed: u32| {
            format!(
                r#"{{"kind":"result","state":"{state}","tests":1,"failed":{failed},"skipped":0}}"#
            )
        };
        let files = [
            "test/a_test.rb",
            "test/b_test.rb",
            "test/c_test.rb",
            "test/d_test.rb",
            "test/e_test.rb",
        ];
        write(
            out.join(name(files[0])),
            &[
                meta(files[0]),
                read("config/boot.rb"),
                read("test/fixtures/a.yml"),
                result("passed", 0),
            ],
        );
        write(
            out.join(name(files[1])),
            &[meta(files[1]), read("config/boot.rb"), result("passed", 0)],
        );
        write(
            out.join(name(files[2])),
            &[meta(files[2]), result("passed", 0)],
        );
        // files[3]: no output (its process died before writing it);
        // files[4]: no line (the boot died).
        let lines = [
            r#"{"id":"test/a_test.rb","exit":0}"#,
            r#"{"id":"test/b_test.rb","exit":1}"#,
            r#"{"id":"test/c_test.rb","why":"its first statement failed in the batch's boot"}"#,
            r#"{"id":"test/d_test.rb","exit":null}"#,
        ];
        write(
            out.join("batch/files.jsonl"),
            &lines.iter().map(|l| l.to_string()).collect::<Vec<_>>(),
        );
        let reads =
            |o: &Observed| -> Vec<String> { o.reads.iter().map(|p| p.to_string()).collect() };
        let (obs, fallback, code) = read_batch(&out, &files).unwrap();
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[0].test_id, files[0]);
        assert_eq!(
            reads(&obs[0]),
            ["/repo/config/boot.rb", "/repo/test/fixtures/a.yml"]
        );
        assert!(obs[0].taints.is_empty(), "{obs:?}");
        assert_eq!(obs[1].test_id, files[1]);
        assert_eq!(reads(&obs[1]), ["/repo/config/boot.rb"]);
        assert!(
            obs[1]
                .taints
                .iter()
                .any(|t| t.starts_with(RAILS_EXIT_TAINT)),
            "{obs:?}"
        );
        assert_eq!(code, Some(1));
        assert_eq!(
            fallback.iter().map(|(f, _)| f.as_str()).collect::<Vec<_>>(),
            [files[2], files[3], files[4]]
        );
        assert!(fallback[0].1.contains("first statement"));
        assert!(fallback[1].1.contains("no output (exit signal)"));
        assert!(fallback[2].1.contains("said nothing"));

        // A failure explains its own non-zero exit; one reported with exit 0
        // still fails the run.
        write(
            out.join(name(files[1])),
            &[meta(files[1]), result("failed", 1)],
        );
        let (obs, _, code) = read_batch(&out, &files).unwrap();
        assert!(obs.iter().all(|o| o.taints.is_empty()), "{obs:?}");
        assert_eq!(code, Some(1));
        let mut zero = lines;
        zero[1] = r#"{"id":"test/b_test.rb","exit":0}"#;
        write(
            out.join("batch/files.jsonl"),
            &zero.iter().map(|l| l.to_string()).collect::<Vec<_>>(),
        );
        let (_, _, code) = read_batch(&out, &files).unwrap();
        assert_eq!(code, Some(1));
        write(
            out.join(name(files[1])),
            &[meta(files[1]), result("passed", 0)],
        );
        let (_, _, code) = read_batch(&out, &files).unwrap();
        assert_eq!(code, Some(0));

        std::fs::remove_file(out.join("batch/files.jsonl")).unwrap();
        let (obs, fallback, _) = read_batch(&out, &files).unwrap();
        assert!(obs.is_empty());
        assert_eq!(fallback.len(), 5);
        assert!(
            fallback[0].1.contains("said nothing of its files"),
            "{fallback:?}"
        );
    }

    #[test]
    fn probe_output_parses_and_rejects_garbage() {
        let gf = Utf8Path::new("/app/Gemfile");
        let p = parse_probe(
            r#"{"ruby":"3.4.9p82","engine":"ruby 3.4.9","rails":"8.1.3.1","bundler":"4.0.9","runner":"minitest 6.0.6","platform":"arm64-darwin25","libs":"sqlite=3.53.2;tz=tzinfo-data","db":"sqlite3","gems":[{"name":"rack","version":"3.2.7","platform":"ruby","source":""},{"name":"nokogiri","version":"1.19.4","platform":"arm64-darwin","source":""}],"gemfile":"/app/Gemfile","taints":[]}"#,
            gf,
            true,
        )
        .unwrap();
        assert_eq!(p.versions.ruby, "3.4.9p82");
        assert_eq!(p.versions.runner, "minitest 6.0.6");
        assert_eq!(p.versions.ruby_gems, ["nokogiri==1.19.4", "rack==3.2.7"]);
        assert_eq!(p.gems["rack"], ["3.2.7"]);
        assert!(parse_probe(r#"{"ruby":"3.4.9p82"}"#, gf, true).is_err());
        assert!(parse_probe("nope", gf, true).is_err());
        let other = r#"{"ruby":"3","engine":"r","rails":"8","bundler":"4","runner":"m","gems":[],"gemfile":"/elsewhere/Gemfile","taints":[]}"#;
        assert!(parse_probe(other, gf, true).is_err(), "another Gemfile");
        let tainted = r#"{"ruby":"3","engine":"r","rails":"8","bundler":"4","runner":"m","gems":[],"gemfile":"/app/Gemfile","taints":["ruby:iseq-cache"]}"#;
        assert!(parse_probe(tainted, gf, true).is_err());
        // A plain Ruby project (RSpec without Rails) has no Rails version.
        let plain = r#"{"ruby":"3","engine":"r","rails":"","bundler":"4","runner":"rspec-core 3.13.6","gems":[],"gemfile":"/app/Gemfile","taints":[]}"#;
        assert!(parse_probe(plain, gf, true).is_err());
        assert_eq!(parse_probe(plain, gf, false).unwrap().versions.rails, "");
        // Native libraries opened through FFI at boot are installed
        // externals (a file that loaded one is checked against them), not
        // part of the toolchain's bundle.
        let natives = r#"{"ruby":"3","engine":"r","rails":"8","bundler":"4","runner":"m","gems":[{"name":"ruby-vips","version":"2.3.0","platform":"ruby","source":""}],"gemfile":"/app/Gemfile","taints":[],"natives":[{"name":"native:libvips.42.dylib","version":"sha256:ab"}]}"#;
        let p = parse_probe(natives, gf, true).unwrap();
        assert_eq!(p.natives["native:libvips.42.dylib"], ["sha256:ab"]);
        assert!(!p.gems.contains_key("native:libvips.42.dylib"));
        assert_eq!(p.versions.ruby_gems, ["ruby-vips==2.3.0"]);
        assert_eq!(p.db_error, None);
        let bad = r#"{"ruby":"3","engine":"r","rails":"8","bundler":"4","runner":"m","gems":[],"gemfile":"/app/Gemfile","taints":[],"natives":[{"name":"rack","version":"1"}]}"#;
        assert!(
            parse_probe(bad, gf, true).is_err(),
            "a native entry must be native:"
        );
        // The probe without booting could not read config/database.yml.
        let unknown = r#"{"ruby":"3","engine":"r","rails":"8","bundler":"4","runner":"m","gems":[],"gemfile":"/app/Gemfile","taints":[],"db":null,"dbError":"NameError: uninitialized constant Rails"}"#;
        let p = parse_probe(unknown, gf, true).unwrap();
        assert_eq!(
            p.db_error.as_deref(),
            Some("NameError: uninitialized constant Rails")
        );
        assert_eq!(p.versions.ruby_db, "");
    }

    /// `vci run` refuses to attest when the booted application reports
    /// another toolchain than the one read without booting it.
    #[test]
    fn booted_and_boot_free_probes_are_compared_field_by_field() {
        let gf = Utf8Path::new("/app/Gemfile");
        let line = |libs: &str, db: &str, gems: &str| {
            format!(
                r#"{{"ruby":"3.4.9p82","engine":"ruby 3.4.9","rails":"8.1.3.1","bundler":"4.0.9","runner":"minitest 6.0.6","libs":"{libs}","db":"{db}","gems":[{gems}],"gemfile":"/app/Gemfile","taints":[]}}"#
            )
        };
        let rack = r#"{"name":"rack","version":"3.2.7","platform":"ruby","source":""}"#;
        let probe = |l: &str| parse_probe(l, gf, true).unwrap();
        let light = probe(&line("yaml=0.2.5;tz=tzinfo-data", "sqlite3", rack));
        assert!(probe_differences(&light, &light.clone()).is_empty());
        let booted = probe(&line(
            "sqlite=3.53.2;yaml=0.2.5;tz=tzinfo-data",
            "sqlite3",
            rack,
        ));
        let d = probe_differences(&light, &booted);
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(d[0].starts_with("libraries: without booting "), "{d:?}");
        let booted = probe(&line("yaml=0.2.5;tz=tzinfo-data", "postgresql", ""));
        let d = probe_differences(&light, &booted);
        assert_eq!(d.len(), 2, "{d:?}");
        assert!(d[0].starts_with("database adapters"), "{d:?}");
        assert!(
            d[1].contains("without booting only [\"rack==3.2.7\"]"),
            "{d:?}"
        );
    }
}
