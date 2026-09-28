//! pytest adapter: drives `uv run --locked pytest` with the `vci_pytest`
//! collector plugin (`py/pytest-plugin`), one process per test file.
//!
//! Every command runs with cwd = project dir through
//! `uv run --locked --exact --no-env-file`, so the interpreter and packages
//! are exactly the ones `uv.lock` pins (packages installed by other means are
//! removed) and no `.env` file adds variables behind vci's back. Collection:
//!
//! ```text
//! PYTHONPATH=<abs>/py/pytest-plugin VCI_OUT=<fresh dir> PYTHONPYCACHEPREFIX=<fresh dir> \
//!   uv run --locked --exact --no-env-file pytest -p vci_pytest <tests/test_x.py>
//! ```
//!
//! `PYTHONPATH` holds only the plugin directory (the collector taints any
//! other entry); `-p vci_pytest` is the first `-p` on the command line so
//! the plugin is imported before entry-point plugins, conftest files and
//! test modules (a `-p` in `addopts` comes earlier and taints).
//! `PYTHONPYCACHEPREFIX` points at a fresh directory so every module is
//! compiled from the source that is hashed: bytecode in `__pycache__` can be
//! stale when a source was edited with its size and mtime preserved.
//!
//! One pytest process per test file, for attestation (`run_collect`) and in
//! CI (`run_plain` with files), so both see the same per-file isolation.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use camino::{Utf8Path, Utf8PathBuf};
use serde_json::Value;

use crate::vitest::{apply_env, describe};
use crate::{
    Adapter, AdapterError, ChildEnv, InstalledExternals, ListedFile, Observed, RunOutput,
    ToolVersions, parse_jsonl_dir,
};

/// Env var naming the `py/pytest-plugin` directory (the one containing the
/// `vci_pytest` package).
pub const PY_PLUGIN_ENV: &str = "VCI_PY_PLUGIN";

/// Env var naming the `uv` binary (default: `uv` on PATH).
pub const UV_ENV: &str = "VCI_UV";

/// Env var bounding the number of concurrent pytest processes in `vci run`.
pub const JOBS_ENV: &str = "VCI_JOBS";

const PLUGIN_MODULE: &str = "vci_pytest";

/// Config file names pytest 9 considers when it determines `rootdir` and the
/// ini file, in its lookup order.
pub const PYTEST_CONFIG_NAMES: &[&str] = &[
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
];

/// Variables the child always sees, on top of the global built-in list:
/// what `uv` needs to find its cache, config, interpreters and index in
/// strict mode, and `PYTHONPATH`, which vci sets itself (the user's value
/// never reaches the tests). Like every built-in pass-through variable they
/// are hashed only when a test reads one.
///
/// `PYTEST_*` and `PYTHON*` (other than `PYTHONPATH`) are deliberately not
/// here: they are [`PYTEST_HASHED_ENV`]. In strict mode they are removed
/// unless declared, so they hash as unset on both sides; declare them in
/// `[env] global` to set them.
pub const PYTEST_PASS_THROUGH: &[&str] = &[
    "UV",
    "UV_*",
    "VIRTUAL_ENV",
    "PYTHONPATH",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_BIN_HOME",
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

/// Variables hashed whenever they are present in the child environment
/// (loose mode, or declared in strict mode): the interpreter and pytest read
/// many of them in C before any hook runs (`PYTHON_CPU_COUNT`,
/// `PYTHONBREAKPOINT`, `PYTHON_GIL`, `PYTEST_ADDOPTS`, ...), so a read cannot
/// be observed. `PYTHONPATH` is vci's own.
pub const PYTEST_HASHED_ENV: &[&str] = &["PYTHON*", "PYTEST_*", "!PYTHONPATH"];

/// Arguments of every `uv run`: `--locked` (uv.lock is the truth), `--exact`
/// (packages not in uv.lock are removed, so the attesting machine and CI see
/// the same set; a package a CI step installed would otherwise change what an
/// optional import finds), `--no-env-file` (`UV_ENV_FILE` would add variables
/// after vci computed the environment it hashes).
pub const UV_RUN_ARGS: &[&str] = &["run", "--locked", "--exact", "--no-env-file"];

/// Written to a temp dir and run with the project's interpreter: versions
/// and installed distributions, the same way the collector sees them
/// (`platform.python_version()`, `sys.implementation.name`,
/// `pytest.__version__`, PEP 503 names).
const PROBE_SCRIPT: &str = r#"import importlib.metadata as m, json, platform, re, sys
import pytest
libs = []
try:
    import sqlite3
    libs.append("sqlite=" + sqlite3.sqlite_version)
except Exception:
    libs.append("sqlite=none")
try:
    import ssl
    libs.append("openssl=" + ssl.OPENSSL_VERSION)
except Exception:
    libs.append("openssl=none")
dists = {}
for d in m.distributions():
    try:
        name, ver = d.metadata["Name"], d.version
    except Exception:
        continue
    if not name or not ver:
        continue
    vs = dists.setdefault(re.sub(r"[-_.]+", "-", name).lower(), [])
    if ver not in vs:
        vs.append(ver)
print("VCI-PROBE " + json.dumps({
    "python": platform.python_version(),
    "implementation": sys.implementation.name,
    "pytest": pytest.__version__,
    "dists": dists,
    "libs": ";".join(libs),
    "basePrefix": sys.base_prefix,
}))
"#;

/// Listing helper plugin (loaded with `-p vci_list` from a temp dir): writes
/// the files of the collected items as JSON, independent of the output
/// verbosity the user configured.
const LIST_PLUGIN: &str = r#"import json, os
def pytest_collection_finish(session):
    out = os.environ.get("VCI_LIST_OUT")
    if not out:
        return
    files = set()
    for item in session.items:
        p = getattr(item, "path", None) or getattr(item, "fspath", None)
        if p is not None:
            files.add(os.path.abspath(str(p)))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(sorted(files), f)
"#;

/// Outcome of one collecting pytest process: exit code, parsed collector
/// output, and the process's combined output (for stderr).
pub(crate) type OneRun = (Option<i32>, Vec<Observed>, Vec<u8>);

#[derive(Debug, Clone)]
struct EnvProbe {
    versions: ToolVersions,
    dists: InstalledExternals,
    /// `sys.base_prefix` of the interpreter.
    base_prefix: String,
}

/// The pytest adapter.
#[derive(Debug)]
pub struct PytestAdapter {
    project_dir: Utf8PathBuf,
    uv: OsString,
    plugin: Option<Utf8PathBuf>,
    probe: OnceLock<Result<EnvProbe, String>>,
}

fn utf8_tmp(t: &tempfile::TempDir) -> Result<Utf8PathBuf, AdapterError> {
    Utf8Path::from_path(t.path())
        .map(Utf8Path::to_owned)
        .ok_or_else(|| AdapterError::NotFound("non-UTF-8 temp dir".into()))
}

fn plugin_ok(dir: &Utf8Path) -> bool {
    dir.join(PLUGIN_MODULE).join("__init__.py").is_file()
}

/// Locate the directory that contains the `vci_pytest` package:
/// `$VCI_PY_PLUGIN`, else `py/pytest-plugin` (or `share/vci/pytest-plugin`)
/// next to or above the `vci` executable, else `py/pytest-plugin` of the
/// source checkout `vci` was built from (`cargo install --path` / `--git`),
/// else `py/pytest-plugin` above the project dir. Returns the canonical
/// directory.
pub fn find_py_plugin(project_dir: &Utf8Path) -> Result<Utf8PathBuf, AdapterError> {
    if let Ok(v) = std::env::var(PY_PLUGIN_ENV)
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
        if !plugin_ok(&p) {
            return Err(AdapterError::NotFound(format!(
                "{PY_PLUGIN_ENV}={v} does not contain {PLUGIN_MODULE}/__init__.py; it must name the py/pytest-plugin directory of vci"
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
            candidates.push(d.join("py/pytest-plugin"));
            candidates.push(d.join("share/vci/pytest-plugin"));
        }
    }
    // crates/vci-adapter -> <checkout>/py/pytest-plugin
    if let Some(src) = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Utf8Path::parent)
    {
        candidates.push(src.join("py/pytest-plugin"));
    }
    for d in project_dir.ancestors() {
        candidates.push(d.join("py/pytest-plugin"));
    }
    for c in candidates {
        if plugin_ok(&c) {
            return Ok(c.canonicalize_utf8()?);
        }
    }
    Err(AdapterError::NotFound(format!(
        "the vci pytest collector ({PLUGIN_MODULE}) was not found: set {PY_PLUGIN_ENV} to the py/pytest-plugin directory of vci (searched py/pytest-plugin and share/vci/pytest-plugin above the vci executable, the source checkout vci was built from, and py/pytest-plugin above {project_dir})"
    )))
}

/// Default parallelism of `vci run` for pytest: `$VCI_JOBS`, else the number
/// of CPUs capped at 8.
pub fn pytest_jobs() -> usize {
    if let Ok(v) = std::env::var(JOBS_ENV)
        && let Ok(n) = v.trim().parse::<usize>()
        && n > 0
    {
        return n;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .min(8)
}

impl PytestAdapter {
    /// `project_dir` must be absolute (it is canonicalised if possible).
    pub fn new(project_dir: &Utf8Path) -> Self {
        let project_dir = project_dir
            .canonicalize_utf8()
            .unwrap_or_else(|_| project_dir.to_owned());
        let uv = std::env::var_os(UV_ENV)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "uv".into());
        Self {
            project_dir,
            uv,
            plugin: None,
            probe: OnceLock::new(),
        }
    }

    /// Use this plugin directory instead of looking it up.
    pub fn with_py_plugin(mut self, dir: impl Into<Utf8PathBuf>) -> Self {
        self.plugin = Some(dir.into());
        self
    }

    fn plugin_dir(&self) -> Result<Utf8PathBuf, AdapterError> {
        match &self.plugin {
            Some(p) if plugin_ok(p) => Ok(p.canonicalize_utf8()?),
            Some(p) => Err(AdapterError::NotFound(format!(
                "{p} does not contain {PLUGIN_MODULE}/__init__.py"
            ))),
            None => find_py_plugin(&self.project_dir),
        }
    }

    /// `uv run --locked --exact --no-env-file <args>` in the project dir with
    /// `env` applied, `PYTHONPATH` removed (callers set it when they need it)
    /// and bytecode written to (and read from) `pycache` only.
    fn uv_run(&self, env: &ChildEnv, pycache: &Utf8Path) -> Command {
        let mut c = Command::new(&self.uv);
        c.current_dir(&self.project_dir)
            .args(UV_RUN_ARGS)
            .stdin(Stdio::null());
        apply_env(&mut c, env);
        c.env_remove("PYTHONPATH")
            .env_remove("UV_ENV_FILE")
            .env("UV_NO_ENV_FILE", "1")
            .env("PYTHONPYCACHEPREFIX", pycache.as_str());
        c
    }

    fn not_installed(&self, e: std::io::Error) -> AdapterError {
        if e.kind() == std::io::ErrorKind::NotFound {
            AdapterError::NotFound(format!(
                "`{}` was not found: the pytest adapter needs uv (https://docs.astral.sh/uv/) on PATH, or {UV_ENV} naming it",
                self.uv.to_string_lossy()
            ))
        } else {
            AdapterError::Io(e)
        }
    }

    fn probe(&self, env: &ChildEnv) -> Result<EnvProbe, AdapterError> {
        let r = self
            .probe
            .get_or_init(|| self.run_probe(env).map_err(|e| e.to_string()));
        r.clone().map_err(|e| AdapterError::Parse {
            what: "python environment probe".into(),
            detail: e,
        })
    }

    fn run_probe(&self, env: &ChildEnv) -> Result<EnvProbe, AdapterError> {
        let tmp = tempfile::Builder::new().prefix("vci-probe-").tempdir()?;
        let script = utf8_tmp(&tmp)?.join("vci_probe.py");
        std::fs::write(&script, PROBE_SCRIPT)?;
        let mut cmd = self.uv_run(env, &utf8_tmp(&tmp)?.join("pycache"));
        cmd.arg("python").arg(script.as_str());
        let out = cmd.output().map_err(|e| self.not_installed(e))?;
        if !out.status.success() {
            return Err(AdapterError::Command {
                cmd: describe(&cmd),
                status: out.status.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).trim_end().to_owned(),
            });
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let line = stdout
            .lines()
            .rev()
            .find_map(|l| l.strip_prefix("VCI-PROBE "))
            .ok_or_else(|| AdapterError::Parse {
                what: "python environment probe".into(),
                detail: format!("no VCI-PROBE line in {stdout:?}"),
            })?;
        parse_probe(line)
    }

    fn run_one(
        &self,
        plugin: &Utf8Path,
        file: &str,
        env: &ChildEnv,
        pycache: &Utf8Path,
    ) -> Result<OneRun, AdapterError> {
        let out_dir = tempfile::Builder::new().prefix("vci-out-").tempdir()?;
        let out_p = utf8_tmp(&out_dir)?;
        let mut cmd = self.uv_run(env, pycache);
        cmd.args(["pytest", "-p", PLUGIN_MODULE])
            .arg(file_arg(file))
            .env("PYTHONPATH", plugin.as_str())
            .env("VCI_OUT", out_p.as_str());
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
        let files = parse_jsonl_dir(&out_p)?;
        Ok((out.status.code(), files, log))
    }

    /// `uv run pytest <file>` without collection; output captured.
    fn run_one_plain(
        &self,
        file: &str,
        env: &ChildEnv,
        pycache: &Utf8Path,
    ) -> Result<OneRun, AdapterError> {
        let mut cmd = self.uv_run(env, pycache);
        cmd.arg("pytest").arg(file_arg(file));
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

    /// Warnings about the interpreter (printed by `vci run`).
    fn interpreter_warnings(&self, env: &ChildEnv) -> Vec<String> {
        let Ok(p) = self.probe(env) else {
            return vec![];
        };
        let mut cmd = Command::new(&self.uv);
        cmd.current_dir(&self.project_dir)
            .args(["python", "dir"])
            .stdin(Stdio::null());
        apply_env(&mut cmd, env);
        let managed_dir = cmd
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .filter(|s| !s.is_empty());
        let canon = |s: &str| {
            Utf8Path::new(s)
                .canonicalize_utf8()
                .unwrap_or_else(|_| Utf8PathBuf::from(s))
        };
        let managed = managed_dir
            .as_deref()
            .is_some_and(|d| canon(&p.base_prefix).starts_with(canon(d)));
        if managed {
            return vec![];
        }
        vec![format!(
            "the interpreter ({}, Python {}) is not a uv-managed Python. CI runners (e.g. GitHub's ubuntu-latest with setup-uv) use uv's python-build-standalone builds, and attestations only match the same Python patch version and bundled libraries ({}). Attest with a managed interpreter whose exact version uv also provides for the CI platform: `uv python install <version>`, pin it in .python-version, and set UV_PYTHON_PREFERENCE=only-managed.",
            p.base_prefix, p.versions.python, p.versions.python_libs
        )]
    }
}

/// Run `one` for every file, at most [`pytest_jobs`] at a time, writing
/// each process's output to stderr as one block when it ends. The exit
/// code is 0 only if every process exited 0.
pub(crate) fn per_file<F>(files: &[String], one: F) -> Result<RunOutput, AdapterError>
where
    F: Fn(&str) -> Result<OneRun, AdapterError> + Sync,
{
    let jobs = pytest_jobs().min(files.len()).max(1);
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(usize, Result<OneRun, AdapterError>)>> = Mutex::new(Vec::new());
    let stderr_lock = Mutex::new(());
    std::thread::scope(|s| {
        for _ in 0..jobs {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(file) = files.get(i) else { break };
                    let r = one(file);
                    if let Ok((_, _, log)) = &r {
                        let _g = stderr_lock.lock().unwrap_or_else(|p| p.into_inner());
                        let _ = std::io::stderr().write_all(log);
                    }
                    results
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push((i, r));
                }
            });
        }
    });
    let mut results = results.into_inner().unwrap_or_else(|p| p.into_inner());
    results.sort_by_key(|(i, _)| *i);
    let mut exit = Some(0);
    let mut observed = Vec::new();
    for (_, r) in results {
        let (code, obs, _) = r?;
        match code {
            Some(0) => {}
            None => exit = None,
            Some(c) => {
                if exit == Some(0) {
                    exit = Some(c);
                }
            }
        }
        observed.extend(obs);
    }
    Ok(RunOutput {
        exit_code: exit,
        files: observed,
    })
}

/// A test file argument that pytest cannot mistake for an option.
fn file_arg(file: &str) -> String {
    if file.starts_with('-') {
        format!("./{file}")
    } else {
        file.to_owned()
    }
}

fn parse_probe(line: &str) -> Result<EnvProbe, AdapterError> {
    let bad = |d: String| AdapterError::Parse {
        what: "python environment probe".into(),
        detail: d,
    };
    let v: Value = serde_json::from_str(line).map_err(|e| bad(e.to_string()))?;
    let s = |k: &str| -> Result<String, AdapterError> {
        v.get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| bad(format!("missing {k}")))
    };
    let mut dists = BTreeMap::new();
    for (name, vers) in v
        .get("dists")
        .and_then(Value::as_object)
        .ok_or_else(|| bad("missing dists".into()))?
    {
        let vers: Vec<String> = vers
            .as_array()
            .ok_or_else(|| bad(format!("dists.{name}")))?
            .iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect();
        dists.insert(name.clone(), vers);
    }
    let mut python_dists: Vec<String> = dists
        .iter()
        .flat_map(|(n, vs)| vs.iter().map(move |v| format!("{n}=={v}")))
        .collect();
    python_dists.sort();
    Ok(EnvProbe {
        versions: ToolVersions {
            runner: s("pytest")?,
            python: s("python")?,
            implementation: s("implementation")?,
            python_libs: s("libs")?,
            python_dists,
            ..Default::default()
        },
        dists,
        base_prefix: v
            .get("basePrefix")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}

impl Adapter for PytestAdapter {
    fn name(&self) -> &'static str {
        "pytest"
    }

    fn project_dir(&self) -> &Utf8Path {
        &self.project_dir
    }

    /// `uv run --locked pytest --collect-only -q`, reduced to files by a
    /// helper plugin. Any non-zero exit other than "no tests collected" (a
    /// collection error, a bad config) is an error, which makes `vci plan`
    /// run everything.
    fn list_test_files(&self, env: &ChildEnv) -> Result<Vec<ListedFile>, AdapterError> {
        let tmp = tempfile::Builder::new().prefix("vci-list-").tempdir()?;
        let dir = utf8_tmp(&tmp)?;
        std::fs::write(dir.join("vci_list.py"), LIST_PLUGIN)?;
        let json_path = dir.join("files.json");
        let mut cmd = self.uv_run(env, &dir.join("pycache"));
        cmd.args(["pytest", "--collect-only", "-q", "-p", "vci_list"])
            .env("PYTHONPATH", dir.as_str())
            .env("VCI_LIST_OUT", json_path.as_str());
        let out = cmd.output().map_err(|e| self.not_installed(e))?;
        let code = out.status.code();
        // 5 = no tests collected.
        if code != Some(0) && code != Some(5) {
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
        let text = std::fs::read_to_string(&json_path).map_err(|e| AdapterError::Parse {
            what: "pytest --collect-only".into(),
            detail: format!("the listing plugin wrote nothing ({e})"),
        })?;
        let arr: Vec<String> = serde_json::from_str(&text).map_err(|e| AdapterError::Parse {
            what: "pytest --collect-only".into(),
            detail: e.to_string(),
        })?;
        let mut files = Vec::new();
        for f in arr {
            let p = Utf8PathBuf::from(&f);
            let abs = p.canonicalize_utf8().map_err(|e| AdapterError::Parse {
                what: "pytest --collect-only".into(),
                detail: format!("collected file {f}: {e}"),
            })?;
            if !abs.starts_with(&self.project_dir) {
                return Err(AdapterError::Parse {
                    what: "pytest --collect-only".into(),
                    detail: format!(
                        "collected file {abs} is outside the project dir {}",
                        self.project_dir
                    ),
                });
            }
            files.push(ListedFile {
                abs,
                project: String::new(),
            });
        }
        files.sort_by(|a, b| a.abs.cmp(&b.abs));
        files.dedup();
        Ok(files)
    }

    fn tool_versions(&self) -> Result<ToolVersions, AdapterError> {
        self.tool_versions_with_env(&None)
    }

    fn tool_versions_with_env(&self, env: &ChildEnv) -> Result<ToolVersions, AdapterError> {
        Ok(self.probe(env)?.versions)
    }

    fn builtin_pass_through(&self) -> &'static [&'static str] {
        PYTEST_PASS_THROUGH
    }

    fn hashed_env_patterns(&self) -> &'static [&'static str] {
        PYTEST_HASHED_ENV
    }

    fn warnings(&self, env: &ChildEnv) -> Vec<String> {
        self.interpreter_warnings(env)
    }

    fn installed_externals(
        &self,
        env: &ChildEnv,
    ) -> Result<Option<InstalledExternals>, AdapterError> {
        Ok(Some(self.probe(env)?.dists))
    }

    fn canonical_argv(&self, project_dir_rel_to_repo: &str, project_rel: &str) -> Vec<String> {
        vec![
            "pytest".into(),
            "--rootdir".into(),
            project_dir_rel_to_repo.into(),
            project_rel.into(),
        ]
    }

    fn config_candidates(&self) -> Vec<Utf8PathBuf> {
        PYTEST_CONFIG_NAMES
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

    /// One `pytest` process per file, at most [`pytest_jobs`] at a time,
    /// sharing one fresh bytecode directory. Each process's output is written
    /// to stderr as one block when it ends. The exit code is 0 only if every
    /// process exited 0.
    fn run_collect(&self, files: &[String], env: &ChildEnv) -> Result<RunOutput, AdapterError> {
        let plugin = self.plugin_dir()?;
        let pyc = tempfile::Builder::new().prefix("vci-pyc-").tempdir()?;
        let pyc = utf8_tmp(&pyc)?;
        per_file(files, |f| self.run_one(&plugin, f, env, &pyc))
    }

    /// With files: one `uv run pytest <file>` per file (in parallel, like
    /// `run_collect`), so CI runs each file with the same isolation the
    /// attestations were made with (one file's module-level side effects never
    /// reach another). Without files: the whole suite in one process.
    fn run_plain(&self, files: &[String], env: &ChildEnv) -> Result<Option<i32>, AdapterError> {
        let pyc = tempfile::Builder::new().prefix("vci-pyc-").tempdir()?;
        let pyc = utf8_tmp(&pyc)?;
        if files.is_empty() {
            let mut cmd = self.uv_run(env, &pyc);
            cmd.arg("pytest").stdout(std::io::stderr());
            return Ok(cmd.status().map_err(|e| self.not_installed(e))?.code());
        }
        Ok(per_file(files, |f| self.run_one_plain(f, env, &pyc))?.exit_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_and_candidates() {
        let a = PytestAdapter::new(Utf8Path::new("/nonexistent/proj"));
        assert_eq!(
            a.canonical_argv("py", "tests/test_b.py"),
            ["pytest", "--rootdir", "py", "tests/test_b.py"]
        );
        assert!(
            a.config_candidates()
                .iter()
                .any(|p| p.ends_with("pyproject.toml"))
        );
        assert_eq!(a.config_candidates().len(), PYTEST_CONFIG_NAMES.len());
        assert!(a.snapshot_candidates(Utf8Path::new("/p/t.py")).is_empty());
        assert!(a.builtin_pass_through().contains(&"UV_*"));
        assert!(
            !a.builtin_pass_through()
                .iter()
                .any(|p| p.starts_with("PYTEST"))
        );
        assert_eq!(file_arg("-x.py"), "./-x.py");
        assert!(a.hashed_env_patterns().contains(&"PYTHON*"));
    }

    /// Regressions: `uv run` loaded a `.env` file (`UV_ENV_FILE`) behind vci's
    /// back, kept packages that are not in uv.lock, and let Python use
    /// `__pycache__` bytecode that can be stale.
    #[test]
    fn every_uv_run_is_exact_without_env_files_and_with_fresh_bytecode() {
        let a = PytestAdapter::new(Utf8Path::new("/nonexistent/proj"));
        let env = Some(vec![("UV_ENV_FILE".into(), ".env".into())]);
        let c = a.uv_run(&env, Utf8Path::new("/tmp/pyc"));
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for want in ["--locked", "--exact", "--no-env-file"] {
            assert!(args.contains(&want.to_owned()), "{args:?}");
        }
        let envs: std::collections::BTreeMap<String, Option<String>> = c
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(
            !matches!(envs.get("UV_ENV_FILE"), Some(Some(_))),
            "UV_ENV_FILE must be removed: {envs:?}"
        );
        assert_eq!(envs["UV_NO_ENV_FILE"].as_deref(), Some("1"));
        assert_eq!(envs["PYTHONPYCACHEPREFIX"].as_deref(), Some("/tmp/pyc"));
    }

    #[test]
    fn probe_output_parses_and_rejects_garbage() {
        let p = parse_probe(
            r#"{"python":"3.14.7","implementation":"cpython","pytest":"9.1.1","dists":{"idna":["3.20"],"x":["1","2"]},"libs":"sqlite=3.50.4;openssl=OpenSSL 3.5.1","basePrefix":"/uv/python/cpython-3.14.4"}"#,
        )
        .unwrap();
        assert_eq!(p.versions.python, "3.14.7");
        assert_eq!(p.versions.runner, "9.1.1");
        assert!(p.versions.node.is_empty());
        assert_eq!(p.dists["idna"], ["3.20"]);
        assert_eq!(p.dists["x"].len(), 2);
        assert_eq!(
            p.versions.python_libs,
            "sqlite=3.50.4;openssl=OpenSSL 3.5.1"
        );
        assert_eq!(p.versions.python_dists, ["idna==3.20", "x==1", "x==2"]);
        assert_eq!(p.base_prefix, "/uv/python/cpython-3.14.4");
        assert!(parse_probe(r#"{"python":"3.14.7"}"#).is_err());
        assert!(parse_probe("nope").is_err());
    }

    #[test]
    fn explicit_plugin_dir_must_contain_the_package() {
        let t = tempfile::tempdir().unwrap();
        let d = Utf8PathBuf::from_path_buf(t.path().to_path_buf()).unwrap();
        let a = PytestAdapter::new(&d).with_py_plugin(d.clone());
        let e = a.plugin_dir().unwrap_err().to_string();
        assert!(e.contains("vci_pytest/__init__.py"), "{e}");
        std::fs::create_dir(d.join("vci_pytest")).unwrap();
        std::fs::write(d.join("vci_pytest/__init__.py"), "").unwrap();
        assert!(a.plugin_dir().is_ok());
    }
}
