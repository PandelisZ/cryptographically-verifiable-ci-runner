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

mod jsonl;
mod pytest;
mod vitest;

use std::collections::BTreeMap;
use std::ffi::OsString;

use camino::Utf8PathBuf;

pub use jsonl::{Observed, parse_jsonl_dir, parse_jsonl_file};
pub use pytest::{
    JOBS_ENV, PY_PLUGIN_ENV, PYTEST_CONFIG_NAMES, PYTEST_HASHED_ENV, PYTEST_PASS_THROUGH,
    PytestAdapter, UV_ENV, UV_RUN_ARGS, find_py_plugin, pytest_jobs,
};
pub use vitest::{JS_PLUGIN_ENV, VitestAdapter, find_js_plugin};

/// Adapter names accepted in `vci.toml`.
pub const ADAPTERS: &[&str] = &["vitest", "pytest"];

/// Construct the adapter called `name` for `project_dir`.
pub fn adapter_for(
    name: &str,
    project_dir: &camino::Utf8Path,
) -> Result<Box<dyn Adapter>, AdapterError> {
    match name {
        "vitest" => Ok(Box::new(VitestAdapter::new(project_dir))),
        "pytest" => Ok(Box::new(PytestAdapter::new(project_dir))),
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
/// pytest: `node`/`bundler`, and `runner` is the pytest version).
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
    /// Env var patterns that always reach the child process and are never
    /// hashed, in addition to the global built-in list (e.g. what the
    /// runner's launcher needs to work at all in strict mode).
    fn builtin_pass_through(&self) -> &'static [&'static str] {
        &[]
    }
    /// Env var patterns (`!pat` excludes) hashed whenever they are present in
    /// the child environment, without being kept in strict mode (unlike
    /// [`Adapter::inferred_env_patterns`]): variables the runtime reads where
    /// no collector can see it.
    fn hashed_env_patterns(&self) -> &'static [&'static str] {
        &[]
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
    /// Canonical per-file argv recorded in (and compared against) attestations.
    /// `project_rel` is the test file relative to the project dir.
    fn canonical_argv(&self, project_dir_rel_to_repo: &str, project_rel: &str) -> Vec<String>;
    /// Config files that are global inputs (absolute; existing or not, every
    /// candidate the runner would consider).
    fn config_candidates(&self) -> Vec<Utf8PathBuf>;
    /// Snapshot files belonging to a test file (absolute; may not exist).
    fn snapshot_candidates(&self, test_abs: &camino::Utf8Path) -> Vec<Utf8PathBuf>;
    /// Env var patterns the runner exposes implicitly (hashed if present).
    fn inferred_env_patterns(&self) -> &'static [&'static str];
    /// Run `files` (project-relative) with dependency collection on.
    fn run_collect(&self, files: &[String], env: &ChildEnv) -> Result<RunOutput, AdapterError>;
    /// Run `files` (project-relative; empty = everything) without collection.
    fn run_plain(&self, files: &[String], env: &ChildEnv) -> Result<Option<i32>, AdapterError>;
}
