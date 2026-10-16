//! Test-runner adapters for `vci`.
//!
//! An [`Adapter`] knows how to list the test files of a project, run a subset
//! of them with dependency collection switched on, and report per-test-file
//! observations. Everything here reports *paths only*; hashing is done by the
//! caller (`vci-core`).
//!
//! Fail-open rule: anything the adapter does not understand becomes a taint on
//! the affected test file (which makes it non-attestable), never a silently
//! dropped record.

mod cargo;
mod golang;
mod jsonl;
mod nodetest;
mod pytest;
mod pytest_list;
mod rails;
mod vitest;

use std::collections::BTreeMap;
use std::ffi::OsString;

use camino::Utf8PathBuf;

pub use cargo::{
    CARGO_BIN_ENV, CARGO_HASH, CARGO_IGNORE, CARGO_LOOSE_HASH, CARGO_UNDECLARED_TAINT,
    CargoAdapter, cfg_predicate_differs, unit_package_dir,
};
pub use golang::{
    GO_ALWAYS_READ_ENV, GO_BIN_ENV, GO_HASH, GO_IGNORE, GO_LOOSE_HASH, GO_NET_TAINT, GoAdapter,
};
pub use jsonl::{Observed, parse_jsonl_dir, parse_jsonl_file};
pub use nodetest::{
    Invocation as NodeTestInvocation, NODE_TEST_HASH, NODE_TEST_LOOSE_HASH, NODE_TEST_RUN_VARS,
    NODE_TEST_TS_LOADERS, NodeTestAdapter, NodeTestOptions, Preload as NodeTestPreload,
    find_node_test_collector, glob_escape as node_test_glob_escape,
    package_manager as node_package_manager, parse_script as parse_node_test_script,
};
pub use pytest::{
    JOBS_ENV, PY_PLUGIN_ENV, PYTEST_CONFIG_NAMES, PYTEST_HASH, PYTEST_IGNORE, PYTEST_LOOSE_HASH,
    PytestAdapter, UV_ENV, UV_RUN_ARGS, find_py_plugin, pytest_jobs,
};
pub use rails::{
    RAILS_GLOBAL_FILES, RAILS_HASH, RAILS_IGNORE, RAILS_LOOSE_HASH, RAILS_RUN_VARS,
    RAILS_SCRATCH_DIRS, RAILS_SEED, RSPEC_GLOBAL_FILES, RUBY_BIN_ENV, RUBY_COLLECTOR_ENV,
    RailsAdapter, RailsRunner, find_ruby_collector,
};
pub use vitest::{JS_PLUGIN_ENV, VITEST_HASH, VITEST_IGNORE, VitestAdapter, find_js_plugin};

/// Built-in ignore for every runner (docs/ENV.md): what any process needs to
/// start and find its tools. They reach the test process and are not a reason
/// to re-run; a test observed reading one gets it hashed (they differ between
/// a laptop and a CI runner by definition).
pub const COMMON_IGNORE: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "TMPDIR",
    "TEMP",
    "TMP",
    "TERM",
    "VCI_*",
    // Needed for processes to start at all on Windows.
    "SYSTEMROOT",
    "SystemRoot",
    "COMSPEC",
    "PATHEXT",
    "WINDIR",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
];

/// Built-in hash for every runner (docs/ENV.md): the local time zone, which
/// every runtime reads natively (ICU, Ruby, Go's package time, libc).
pub const COMMON_HASH: &[&str] = &["TZ"];

/// Adapter names accepted in `vci.toml`.
pub const ADAPTERS: &[&str] = &["vitest", "pytest", "go", "cargo", "rails", "node-test"];

/// Policy settings that change how an adapter runs tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdapterOptions {
    /// Rails: the project's `runner` setting (`None`: detected from the
    /// project, see `RailsAdapter`).
    pub rails_runner: Option<RailsRunner>,
    /// node-test: the test command settings (`test_script`, or `test_globs`
    /// with `node_args`).
    pub node_test: NodeTestOptions,
}

/// Construct the adapter called `name` for `project_dir`.
pub fn adapter_for(
    name: &str,
    project_dir: &camino::Utf8Path,
) -> Result<Box<dyn Adapter>, AdapterError> {
    adapter_for_with(name, project_dir, &AdapterOptions::default())
}

/// [`adapter_for`] with policy settings.
pub fn adapter_for_with(
    name: &str,
    project_dir: &camino::Utf8Path,
    opts: &AdapterOptions,
) -> Result<Box<dyn Adapter>, AdapterError> {
    match name {
        "vitest" => Ok(Box::new(VitestAdapter::new(project_dir))),
        "pytest" => Ok(Box::new(PytestAdapter::new(project_dir))),
        "go" => Ok(Box::new(GoAdapter::new(project_dir))),
        "cargo" => Ok(Box::new(CargoAdapter::new(project_dir))),
        "rails" => Ok(Box::new(
            RailsAdapter::new(project_dir).with_runner(opts.rails_runner),
        )),
        "node-test" => Ok(Box::new(
            NodeTestAdapter::new(project_dir).with_options(opts.node_test.clone()),
        )),
        other => Err(AdapterError::NotFound(format!(
            "unsupported adapter {other:?} (supported: {})",
            ADAPTERS.join(", ")
        ))),
    }
}

/// Errors from running or listing tests.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    NotFound(String),
    #[error("`{cmd}` failed ({status}): {stderr}")]
    Command {
        cmd: String,
        status: String,
        stderr: String,
    },
    #[error("could not parse {what}: {detail}")]
    Parse { what: String, detail: String },
}

/// Environment for a child process. `None` inherits the parent environment;
/// `Some(vars)` clears it and sets exactly `vars` (strict env mode).
pub type ChildEnv = Option<Vec<(OsString, OsString)>>;

/// A test file as reported by the runner's list command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedFile {
    /// Absolute path.
    pub abs: Utf8PathBuf,
    /// Runner project name (Vitest `projects`), empty if none.
    pub project: String,
}

/// Versions of the tools that make up the toolchain digest. Fields an
/// adapter does not use are empty (Vitest: `python`/`implementation`;
/// pytest: `node`/`bundler`, and `runner` is the pytest version; Go: `runner`
/// is `go env GOVERSION` and the `go_*` fields are set).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ToolVersions {
    pub node: String,
    pub runner: String,
    pub bundler: String,
    /// Full Python version (`platform.python_version()`).
    pub python: String,
    /// `sys.implementation.name`.
    pub implementation: String,
    /// Versions of libraries bundled with the interpreter (pytest:
    /// `sqlite=...;openssl=...`).
    pub python_libs: String,
    /// Every installed distribution as sorted `name==version` (pytest).
    pub python_dists: Vec<String>,
    /// Go: effective platform-independent build settings, sorted `KEY=value`
    /// (see `vci_core::Toolchain::go_env`).
    pub go_env: Vec<String>,
    /// Go: `GOAMD64=v1`, `GOARM64=v8.0`, ... for the target `GOARCH`.
    pub go_arch_level: String,
    /// Go: the absolute path of the `go.work` file in use (`go env GOWORK`),
    /// empty or `off` when none is.
    pub go_work: String,
    /// Cargo: `cargo -vV` as `<release> <commit-hash>` (`runner` is rustc's).
    pub cargo: String,
    /// Cargo: the host triple from `rustc -vV`.
    pub rust_host: String,
    /// Cargo: `rustc --print cfg` of the host (with the flags the build
    /// uses), sorted.
    pub rust_cfg: Vec<String>,
    /// Rails: `RUBY_VERSION` + patchlevel (`3.4.9p82`); `runner` names the
    /// bundle's test frameworks (`minitest 6.0.6`, plus `; rspec-core 3.13.6,
    /// rspec-expectations ..., rspec-mocks ..., rspec-rails ..., rspec-support
    /// ...` when the bundle has RSpec).
    pub ruby: String,
    /// Rails: `RUBY_ENGINE RUBY_ENGINE_VERSION`.
    pub ruby_engine: String,
    /// Rails: `Rails::VERSION::STRING`.
    pub rails: String,
    /// Rails: `Bundler::VERSION`.
    pub ruby_bundler: String,
    /// Rails: libraries tests depend on (`sqlite=...;yaml=...;tz=...;encoding=...`).
    pub ruby_libs: String,
    /// Rails: the adapter names of the test environment's databases, sorted
    /// and joined with `;` (`sqlite3`, `mysql2`, `postgresql;sqlite3`); no
    /// server version.
    pub ruby_db: String,
    /// Rails: every gem of the resolved bundle, sorted `name==version`.
    pub ruby_gems: Vec<String>,
}

/// External packages as the test process would resolve them now:
/// normalised name -> every installed version (more than one version means
/// the name is ambiguous and never matches).
pub type InstalledExternals = BTreeMap<String, Vec<String>>;

/// Result of a collecting run.
#[derive(Debug)]
pub struct RunOutput {
    /// Exit code of the runner process (`None` if killed by a signal).
    pub exit_code: Option<i32>,
    /// Per-test-file observations, one per collector output file.
    pub files: Vec<Observed>,
}

/// A test-runner integration.
pub trait Adapter: Send + Sync {
    /// Short adapter name recorded in predicates (`"vitest"`, `"pytest"`).
    fn name(&self) -> &'static str;
    /// Absolute project directory (the runner's root).
    fn project_dir(&self) -> &camino::Utf8Path;
    /// All test files the runner would run, using the user's own config.
    fn list_test_files(&self, env: &ChildEnv) -> Result<Vec<ListedFile>, AdapterError>;
    /// Node / runner / bundler versions as resolved from the project.
    fn tool_versions(&self) -> Result<ToolVersions, AdapterError>;
    /// [`Adapter::tool_versions`] as seen by a child process with `env`
    /// (adapters that ask the interpreter override this).
    fn tool_versions_with_env(&self, env: &ChildEnv) -> Result<ToolVersions, AdapterError> {
        let _ = env;
        self.tool_versions()
    }
    /// Built-in ignore (docs/ENV.md): env var patterns (`!pat` excludes) the
    /// runner needs to work at all (where the toolchain, caches and packages
    /// live), on top of [`COMMON_IGNORE`]. They reach the test process and are
    /// not a reason to re-run; a test observed reading one gets it hashed.
    fn builtin_ignore(&self) -> &'static [&'static str] {
        &[]
    }
    /// Built-in hash (docs/ENV.md): env var patterns (`!pat` excludes) the
    /// runtime reads natively, where no collector sees the read, and that
    /// change test results, on top of [`COMMON_HASH`]. They reach the test
    /// process and are hashed whenever present.
    fn builtin_hash(&self) -> &'static [&'static str] {
        &[]
    }
    /// Env var patterns (`!pat` excludes) hashed whenever present in loose
    /// mode (deprecated) only, on top of the built-in hash: vci 1.5's
    /// per-runner families (`GO*`, `PYTHON*`, `RUBY*`, `NODE_*`, ...), which
    /// the runtime reads where nothing observes it. Loose mode lets every
    /// variable reach the tests, so these must stay inputs there; strict mode
    /// removes the ones that are not built-in or listed.
    fn loose_hash(&self) -> &'static [&'static str] {
        &[]
    }
    /// Env var names declared (hashed, and kept in the child in strict mode)
    /// by the adapter itself, on top of the user's `[env]` (node-test:
    /// `NODE_ENV` and the variables the test script assigns).
    fn declared_env(&self) -> Vec<String> {
        vec![]
    }
    /// Variables the adapter sets for every test process, with their values
    /// (node-test: the test script's leading `NAME=value` assignments). They
    /// are in [`Adapter::declared_env`], so hashed.
    fn forced_env(&self) -> Vec<(String, String)> {
        vec![]
    }
    /// Whether the `tsconfig.json` chain of modules is an input (it decides
    /// how they are transformed). Vitest: always; node-test: only with a
    /// TypeScript loader (Node's own type stripping reads no tsconfig).
    fn tsconfig_is_input(&self) -> bool {
        true
    }
    /// Warnings for `vci run` about the environment the tests run in (e.g. an
    /// interpreter CI cannot reproduce).
    fn warnings(&self, env: &ChildEnv) -> Vec<String> {
        let _ = env;
        vec![]
    }
    /// External packages installed in the environment the tests run in, for
    /// adapters that can enumerate them (pytest). `None` means the caller
    /// looks packages up itself (the npm `node_modules` layout).
    fn installed_externals(
        &self,
        env: &ChildEnv,
    ) -> Result<Option<InstalledExternals>, AdapterError> {
        let _ = env;
        Ok(None)
    }
    /// Native libraries the project's test processes open when they start
    /// (Rails: what the application opens through FFI when it boots), as the
    /// `native:<file name>` externals the collector records. `vci plan` asks
    /// only when an attestation records one. `None`: the adapter records
    /// none.
    fn native_externals(&self, env: &ChildEnv) -> Result<Option<InstalledExternals>, AdapterError> {
        let _ = env;
        Ok(None)
    }
    /// What `vci run` checks before running anything it attests, beyond
    /// [`Adapter::tool_versions_with_env`] (Rails: the application boots
    /// under vci's run conditions, passes the probe's checks and reports the
    /// toolchain read without booting it). `vci plan` does not call it: it
    /// reads the toolchain as recorded (without booting) and compares that.
    fn check_run_environment(&self, env: &ChildEnv) -> Result<(), AdapterError> {
        let _ = env;
        Ok(())
    }
    /// Canonical per-file argv recorded in (and compared against) attestations.
    /// `project_rel` is the test file relative to the project dir.
    fn canonical_argv(&self, project_dir_rel_to_repo: &str, project_rel: &str) -> Vec<String>;
    /// Config files that are global inputs (absolute; existing or not, every
    /// candidate the runner would consider).
    fn config_candidates(&self) -> Vec<Utf8PathBuf>;
    /// [`Adapter::config_candidates`] of one test file, for adapters whose
    /// files run under different runners (Rails: Minitest and RSpec files).
    fn config_candidates_for(&self, test_abs: &camino::Utf8Path) -> Vec<Utf8PathBuf> {
        let _ = test_abs;
        self.config_candidates()
    }
    /// Snapshot files belonging to a test file (absolute; may not exist).
    fn snapshot_candidates(&self, test_abs: &camino::Utf8Path) -> Vec<Utf8PathBuf>;
    /// Run `files` (project-relative) with dependency collection on.
    fn run_collect(&self, files: &[String], env: &ChildEnv) -> Result<RunOutput, AdapterError>;
    /// Run `files` (project-relative; empty = everything) without collection.
    fn run_plain(&self, files: &[String], env: &ChildEnv) -> Result<Option<i32>, AdapterError>;
    /// Directories holding vci's own collector files for this adapter (real
    /// paths): the `@vci/vitest` package, `vci_pytest`, `vci_collector.rb`.
    /// What a test process reads there is vci's tooling (identified by the
    /// collector version), never an input, whichever path (a symlinked
    /// install prefix) reached it. Empty when there is none or it cannot be
    /// found (then nothing is dropped).
    fn collector_dirs(&self) -> Vec<Utf8PathBuf> {
        vec![]
    }
    /// Directories inside the repository that the runner writes build output
    /// to and that are never inputs (Cargo's target directory). `vci run`
    /// does not snapshot them.
    fn scratch_dirs(&self) -> Vec<Utf8PathBuf> {
        vec![]
    }
    /// [`Adapter::scratch_dirs`] as seen with the child environment `env`
    /// (Cargo: also a `$CARGO_HOME` kept inside the repository).
    fn scratch_dirs_with_env(&self, env: &ChildEnv) -> Vec<Utf8PathBuf> {
        let _ = env;
        self.scratch_dirs()
    }
}
