//! The test files `pytest` (no file arguments, run in the project dir)
//! collects, listed without starting Python: pytest's collection rules
//! (pytest 8 and 9: `_pytest/config/findpaths.py`, `config/__init__.py`,
//! `main.py`, `python.py`, `doctest.py`) applied to the file tree.
//!
//! - The configuration file: the first file holding pytest
//!   configuration in the project dir or the nearest ancestor (the
//!   first of `PYTEST_CONFIG_NAMES` there) (`pytest.ini`
//!   and `pytest.toml` always do; `pyproject.toml` with `[tool.pytest]` or
//!   `[tool.pytest.ini_options]`, `tox.ini` with `[pytest]`, `setup.cfg`
//!   with `[tool:pytest]`). Its directory is pytest's rootdir.
//! - `addopts` (and `PYTEST_ADDOPTS`): `--ignore`, `--ignore-glob`,
//!   `--collect-in-virtualenv`, `--doctest-modules`, `--doctest-glob`,
//!   `-p no:doctest`, `-o`/`--override-ini` and paths given there are
//!   honoured; `--pyargs`, and `-c`/`--config-file`/`--rootdir` or paths in
//!   `PYTEST_ADDOPTS`, are errors (`vci plan` then runs everything).
//! - The starting points: paths in `addopts`, else `testpaths` (globbed,
//!   only when the rootdir is the project dir), else the project dir.
//! - Directories: `__pycache__`, `--ignore`d paths and `--ignore-glob`
//!   matches, virtualenvs (a `pyvenv.cfg` or `conda-meta/history`) and
//!   `norecursedirs` matches (default [`DEFAULT_NORECURSEDIRS`]; a configured
//!   list replaces it) are not entered. Symlinked directories are followed,
//!   as pytest follows them (a file reached outside the project dir is an
//!   error, as before).
//! - Files: `.py` files matching `python_files` (default
//!   [`DEFAULT_PYTHON_FILES`]; a configured list replaces it), and doctest
//!   files (`test*.txt` or `--doctest-glob`, and with `--doctest-modules`
//!   every `.py` file but `setup.py` and `__main__.py`) that hold a `>>>`
//!   example. `__init__.py` is not special.
//!
//! Not seen (the file is listed and run on its own, or not listed): what
//! conftest.py files decide (`collect_ignore`, `collect_ignore_glob`,
//! `pytest_ignore_collect`, `pytest_collect_file`) and what plugins collect.
//! A listed file with no test (no test function, or every test deselected by
//! `-k`/`-m` in `addopts`) runs in its own process and collects nothing,
//! which the adapter counts as passing (see `per_file_pytest`), also when it
//! is the only file run. It is never attested (no test ran), so it runs on
//! every plan.

use std::collections::{BTreeMap, BTreeSet};

use camino::{Utf8Path, Utf8PathBuf};

use crate::pytest::PYTEST_CONFIG_NAMES as CONFIG_NAMES;

/// pytest's default `python_files`.
pub(crate) const DEFAULT_PYTHON_FILES: &[&str] = &["test_*.py", "*_test.py"];

/// pytest's default `norecursedirs`.
pub(crate) const DEFAULT_NORECURSEDIRS: &[&str] = &[
    "*.egg",
    ".*",
    "_darcs",
    "build",
    "CVS",
    "dist",
    "node_modules",
    "venv",
    "{arch}",
];

/// The doctest plugin's default `--doctest-glob`.
const DEFAULT_DOCTEST_GLOB: &str = "test*.txt";

/// Long options of pytest 9 that take no value.
const LONG_FLAGS: &[&str] = &[
    "--cache-clear",
    "--co",
    "--collect-in-virtualenv",
    "--collect-only",
    "--collectonly",
    "--continue-on-collection-errors",
    "--disable-plugin-autoload",
    "--disable-pytest-warnings",
    "--disable-warnings",
    "--doctest-continue-on-failure",
    "--doctest-ignore-import-errors",
    "--doctest-modules",
    "--exitfirst",
    "--failed-first",
    "--ff",
    "--fixtures",
    "--fixtures-per-test",
    "--force-short-summary",
    "--full-trace",
    "--fulltrace",
    "--funcargs",
    "--help",
    "--keep-duplicates",
    "--keepduplicates",
    "--last-failed",
    "--lf",
    "--markers",
    "--new-first",
    "--nf",
    "--no-fold-skipped",
    "--no-header",
    "--no-showlocals",
    "--no-summary",
    "--noconftest",
    "--pdb",
    "--pyargs",
    "--quiet",
    "--runxfail",
    "--setup-only",
    "--setup-plan",
    "--setup-show",
    "--setuponly",
    "--setupplan",
    "--setupshow",
    "--showlocals",
    "--stepwise",
    "--stepwise-reset",
    "--stepwise-skip",
    "--strict",
    "--strict-config",
    "--strict-markers",
    "--sw",
    "--sw-reset",
    "--sw-skip",
    "--trace",
    "--trace-config",
    "--traceconfig",
    "--verbose",
    "--version",
    "--xfail-tb",
    // Common plugins.
    "--no-cov",
    "--no-cov-on-fail",
    "--cov-append",
    "--cov-branch",
    "--reuse-db",
    "--create-db",
    "--nomigrations",
    "--migrations",
    "--looponfail",
    "--benchmark-skip",
    "--benchmark-disable",
    "--benchmark-only",
];

/// Long options of pytest 9 (and of common plugins) that take a value (or
/// an optional one: the next argument that is not an option).
const LONG_VALUES: &[&str] = &[
    "--assert",
    "--basetemp",
    "--cache-show",
    "--capture",
    "--code-highlight",
    "--color",
    "--confcutdir",
    "--config-file",
    "--debug",
    "--deselect",
    "--doctest-glob",
    "--doctest-report",
    "--durations",
    "--durations-min",
    "--ignore",
    "--ignore-glob",
    "--import-mode",
    "--junit-prefix",
    "--junit-xml",
    "--junitprefix",
    "--junitxml",
    "--last-failed-no-failures",
    "--lfnf",
    "--log-auto-indent",
    "--log-cli-date-format",
    "--log-cli-format",
    "--log-cli-level",
    "--log-date-format",
    "--log-disable",
    "--log-file",
    "--log-file-date-format",
    "--log-file-format",
    "--log-file-level",
    "--log-file-mode",
    "--log-format",
    "--log-level",
    "--max-warnings",
    "--maxfail",
    "--override-ini",
    "--pastebin",
    "--pdbcls",
    "--pythonwarnings",
    "--report-chars",
    "--rootdir",
    "--show-capture",
    "--tb",
    "--verbosity",
    // Common plugins: pytest-cov, pytest-xdist, pytest-timeout,
    // pytest-django, pytest-rerunfailures, pytest-html, pytest-randomly,
    // pytest-asyncio.
    "--cov",
    "--cov-report",
    "--cov-config",
    "--cov-fail-under",
    "--cov-context",
    "--numprocesses",
    "--maxprocesses",
    "--max-worker-restart",
    "--dist",
    "--tx",
    "--rsyncdir",
    "--rsyncignore",
    "--timeout",
    "--timeout-method",
    "--ds",
    "--dc",
    "--reruns",
    "--reruns-delay",
    "--only-rerun",
    "--html",
    "--css",
    "--randomly-seed",
    "--asyncio-mode",
];

/// Short options that take no value.
const SHORT_FLAGS: &[char] = &['V', 'h', 'l', 'q', 's', 'v', 'x'];

/// Short options that take a value (`-n`: pytest-xdist).
const SHORT_VALUES: &[char] = &['W', 'c', 'k', 'm', 'o', 'p', 'r', 'n'];

/// A configuration value: a string (ini files, and scalars of
/// `[tool.pytest.ini_options]`), a list, or a value of the wrong type for
/// what it configures (pytest's error, when the option is read).
#[derive(Debug, Clone, PartialEq)]
enum IniValue {
    Str(String),
    List(Vec<String>),
    Bad(String),
}

/// The configuration file pytest uses and its values.
#[derive(Debug, Default)]
struct Config {
    /// pytest's rootdir when a configuration file was found.
    rootdir: Option<Utf8PathBuf>,
    inipath: Option<Utf8PathBuf>,
    values: BTreeMap<String, IniValue>,
}

impl Config {
    /// An option of type `args` (`addopts`, `python_files`,
    /// `norecursedirs`, `testpaths`): a string is split as `shlex.split`
    /// splits it.
    fn args(&self, name: &str) -> Result<Option<Vec<String>>, String> {
        match self.values.get(name) {
            None => Ok(None),
            Some(IniValue::Str(s)) => shlex_split(s)
                .map(Some)
                .map_err(|e| format!("{}: {name}: {e}", self.where_())),
            Some(IniValue::List(l)) => Ok(Some(l.clone())),
            Some(IniValue::Bad(e)) => Err(format!("{}: {name}: {e}", self.where_())),
        }
    }

    fn where_(&self) -> String {
        self.inipath
            .as_ref()
            .map_or_else(|| "-o".to_owned(), ToString::to_string)
    }
}

/// What `addopts` or `PYTEST_ADDOPTS` say about collection.
#[derive(Debug, Default)]
struct Opts {
    ignore: Vec<String>,
    ignore_glob: Vec<String>,
    collect_in_virtualenv: bool,
    doctest_modules: bool,
    doctest_glob: Vec<String>,
    no_doctest: bool,
    overrides: Vec<(String, String)>,
    paths: Vec<String>,
    /// `-c`, `--config-file` or `--rootdir`.
    setup: Option<String>,
}

/// List the test files pytest collects when run without file arguments in
/// `project_dir` (canonical), `pytest_addopts` being `PYTEST_ADDOPTS`.
/// Sorted, deduplicated, canonical; every file inside `project_dir`.
pub(crate) fn list(
    project_dir: &Utf8Path,
    pytest_addopts: Option<&str>,
) -> Result<Vec<Utf8PathBuf>, String> {
    let env = match pytest_addopts.filter(|s| !s.is_empty()) {
        Some(s) => {
            let toks = shlex_split(s).map_err(|e| format!("PYTEST_ADDOPTS: {e}"))?;
            parse_opts(&toks, project_dir, "PYTEST_ADDOPTS")?
        }
        None => Opts::default(),
    };
    if let Some(o) = &env.setup {
        return Err(format!(
            "PYTEST_ADDOPTS sets {o}, which vci's listing of the test files does not follow"
        ));
    }
    if !env.paths.is_empty() {
        return Err(format!(
            "PYTEST_ADDOPTS names paths ({}), which vci's listing of the test files does not follow",
            env.paths.join(" ")
        ));
    }
    let mut config = locate_config(project_dir)?;
    apply_overrides(&mut config, &env.overrides);
    let ini = match config.args("addopts")? {
        Some(toks) => parse_opts(&toks, project_dir, "addopts")?,
        None => Opts::default(),
    };
    apply_overrides(&mut config, &ini.overrides);
    // pytest's argument order: the ini file's addopts, then PYTEST_ADDOPTS.
    let opts = Opts {
        ignore: [ini.ignore, env.ignore].concat(),
        ignore_glob: [ini.ignore_glob, env.ignore_glob].concat(),
        collect_in_virtualenv: ini.collect_in_virtualenv || env.collect_in_virtualenv,
        doctest_modules: ini.doctest_modules || env.doctest_modules,
        doctest_glob: [ini.doctest_glob, env.doctest_glob].concat(),
        no_doctest: ini.no_doctest || env.no_doctest,
        overrides: vec![],
        paths: ini.paths,
        setup: None,
    };
    let python_files = config
        .args("python_files")?
        .unwrap_or_else(|| DEFAULT_PYTHON_FILES.iter().map(|s| s.to_string()).collect());
    let norecursedirs = config.args("norecursedirs")?.unwrap_or_else(|| {
        DEFAULT_NORECURSEDIRS
            .iter()
            .map(|s| s.to_string())
            .collect()
    });
    let testpaths = config.args("testpaths")?.unwrap_or_default();

    // The starting points (`Config._decide_args`).
    let mut args: Vec<Utf8PathBuf> = Vec::new();
    if !opts.paths.is_empty() {
        for p in &opts.paths {
            let file_part = p.split("::").next().unwrap_or(p);
            let abs = absolute(project_dir, file_part);
            if std::fs::symlink_metadata(&abs).is_err() {
                return Err(format!("addopts: file or directory not found: {p}"));
            }
            args.push(abs);
        }
    } else {
        if config.rootdir.as_deref() == Some(project_dir) {
            for t in &testpaths {
                let mut found = py_glob(project_dir, t);
                found.sort();
                args.extend(found);
            }
        }
        if args.is_empty() {
            args.push(project_dir.to_owned());
        }
    }

    let mut w = Walker {
        python_files,
        norecursedirs,
        ignore: opts
            .ignore
            .iter()
            .map(|p| absolute(project_dir, p))
            .collect(),
        ignore_glob: opts
            .ignore_glob
            .iter()
            .map(|g| absolute(project_dir, g).into_string())
            .collect(),
        collect_in_virtualenv: opts.collect_in_virtualenv,
        doctest: !opts.no_doctest,
        doctest_modules: opts.doctest_modules,
        doctest_glob: if opts.doctest_glob.is_empty() {
            vec![DEFAULT_DOCTEST_GLOB.to_owned()]
        } else {
            opts.doctest_glob
        },
        initpaths: args.iter().cloned().collect(),
        found: BTreeSet::new(),
        walking: Vec::new(),
    };
    for a in &args {
        if a.is_dir() {
            w.walk(a)?;
        } else if a.is_file() {
            w.file(a, true)?;
        } else {
            return Err(format!("file or directory not found: {a}"));
        }
    }

    let mut out = BTreeSet::new();
    for f in w.found {
        let abs = f
            .canonicalize_utf8()
            .map_err(|e| format!("collected file {f}: {e}"))?;
        if !abs.starts_with(project_dir) {
            return Err(format!(
                "collected file {abs} is outside the project dir {project_dir}"
            ));
        }
        out.insert(abs);
    }
    Ok(out.into_iter().collect())
}

struct Walker {
    python_files: Vec<String>,
    norecursedirs: Vec<String>,
    ignore: Vec<Utf8PathBuf>,
    ignore_glob: Vec<String>,
    collect_in_virtualenv: bool,
    doctest: bool,
    doctest_modules: bool,
    doctest_glob: Vec<String>,
    /// The starting points (pytest's initial paths).
    initpaths: BTreeSet<Utf8PathBuf>,
    found: BTreeSet<Utf8PathBuf>,
    /// Canonical directories being walked (a symlink back up is not walked
    /// again).
    walking: Vec<Utf8PathBuf>,
}

impl Walker {
    /// `Dir.collect` / `Package.collect`.
    fn walk(&mut self, dir: &Utf8Path) -> Result<(), String> {
        let real = dir.canonicalize_utf8().unwrap_or_else(|_| dir.to_owned());
        if self.walking.contains(&real) {
            return Ok(());
        }
        self.walking.push(real);
        let mut names: Vec<String> = match dir.read_dir_utf8() {
            Ok(rd) => rd
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_owned())
                .collect(),
            Err(_) => vec![],
        };
        names.sort();
        for name in names {
            let path = dir.join(&name);
            // Like `DirEntry.is_dir()` / `is_file()`: symlinks followed.
            if path.is_dir() {
                if !self.is_initpath_or_parent(&path) && self.ignored(&path, true) {
                    continue;
                }
                self.walk(&path)?;
            } else if path.is_file() {
                let init = self.initpaths.contains(&path);
                if !init && self.ignored(&path, false) {
                    continue;
                }
                self.file(&path, init)?;
            }
        }
        self.walking.pop();
        Ok(())
    }

    fn is_initpath_or_parent(&self, path: &Utf8Path) -> bool {
        self.initpaths.iter().any(|i| i.starts_with(path))
    }

    /// `pytest_ignore_collect` without conftest.py files.
    fn ignored(&self, path: &Utf8Path, is_dir: bool) -> bool {
        if path.file_name() == Some("__pycache__") {
            return true;
        }
        if self.ignore.iter().any(|p| p == path) {
            return true;
        }
        if self.ignore_glob.iter().any(|g| fnmatch(g, path.as_str())) {
            return true;
        }
        if !self.collect_in_virtualenv
            && (path.join("pyvenv.cfg").is_file() || path.join("conda-meta/history").is_file())
        {
            return true;
        }
        is_dir && self.norecursedirs.iter().any(|p| fnmatch_ex(p, path))
    }

    /// `pytest_collect_file` of the python and doctest plugins: does `path`
    /// yield a collector that can hold tests?
    fn file(&mut self, path: &Utf8Path, init: bool) -> Result<(), String> {
        let name = path.file_name().unwrap_or_default();
        let ext = path.extension();
        if ext == Some("py") {
            // A test module (`python_files`, or named on the command line),
            // or a module with doctests (`--doctest-modules`).
            let module = init || self.python_files.iter().any(|p| fnmatch_ex(p, path));
            let doctests = || {
                self.doctest
                    && self.doctest_modules
                    && name != "__main__.py"
                    && !is_setup_py(path)
                    && contains(&read(path), b">>>")
            };
            if module || doctests() {
                self.found.insert(path.to_owned());
            }
            return Ok(());
        }
        let doctest_file = self.doctest
            && ((init && matches!(ext, Some("txt" | "rst")))
                || self.doctest_glob.iter().any(|g| fnmatch_ex(g, path)));
        if doctest_file {
            if has_doctest_example(&read(path)) {
                self.found.insert(path.to_owned());
            }
        } else if init {
            return Err(format!("found no collectors for {path}"));
        }
        Ok(())
    }
}

fn read(path: &Utf8Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

/// The doctest plugin's `_is_setup_py`.
fn is_setup_py(path: &Utf8Path) -> bool {
    path.file_name() == Some("setup.py") && {
        let b = read(path);
        contains(&b, b"setuptools") || contains(&b, b"distutils")
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A line doctest's parser takes for an example (`>>>` after indentation).
fn has_doctest_example(text: &[u8]) -> bool {
    text.split(|&b| b == b'\n').any(|l| {
        let t: &[u8] = {
            let i = l
                .iter()
                .position(|&b| b != b' ' && b != b'\t')
                .unwrap_or(l.len());
            &l[i..]
        };
        t.starts_with(b">>>")
    })
}

/// `os.path.abspath(p)` with `cwd` as the working directory: joined and
/// normalized lexically (`.` and `..` removed, no symlink resolved).
fn absolute(cwd: &Utf8Path, p: &str) -> Utf8PathBuf {
    let joined = cwd.join(p);
    let mut out = Utf8PathBuf::from("/");
    for c in joined.components() {
        match c {
            camino::Utf8Component::RootDir | camino::Utf8Component::Prefix(_) => {}
            camino::Utf8Component::CurDir => {}
            camino::Utf8Component::ParentDir => {
                out.pop();
            }
            camino::Utf8Component::Normal(n) => out.push(n),
        }
    }
    out
}

fn apply_overrides(config: &mut Config, overrides: &[(String, String)]) {
    for (k, v) in overrides {
        config.values.insert(k.clone(), IniValue::Str(v.clone()));
    }
}

/// Parse command line options as pytest's argument parser does, keeping
/// what decides which files are collected.
fn parse_opts(toks: &[String], cwd: &Utf8Path, what: &str) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut i = 0;
    let mut only_paths = false;
    // An option vci does not know, followed by an argument: its value, or a
    // path? A path (it exists) is ambiguous.
    let unknown_then = |opt: &str, next: Option<&String>| -> Result<bool, String> {
        match next {
            Some(n) if !n.starts_with('-') => {
                if std::fs::symlink_metadata(absolute(cwd, n.split("::").next().unwrap_or(n)))
                    .is_ok()
                {
                    Err(format!(
                        "{what}: cannot tell whether {n:?} is the value of {opt} (an option vci does not know) or a path to collect"
                    ))
                } else {
                    Ok(true)
                }
            }
            _ => Ok(false),
        }
    };
    while i < toks.len() {
        let t = &toks[i];
        i += 1;
        if only_paths || !t.starts_with('-') || t == "-" {
            o.paths.push(t.clone());
            continue;
        }
        if t == "--" {
            only_paths = true;
            continue;
        }
        if let Some(long) = t.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (format!("--{n}"), Some(v.to_owned())),
                None => (t.clone(), None),
            };
            if LONG_FLAGS.contains(&name.as_str()) {
                match name.as_str() {
                    "--collect-in-virtualenv" => o.collect_in_virtualenv = true,
                    "--doctest-modules" => o.doctest_modules = true,
                    "--pyargs" => {
                        return Err(format!(
                            "{what}: --pyargs is not supported by vci's listing of the test files"
                        ));
                    }
                    _ => {}
                }
                continue;
            }
            let value = if LONG_VALUES.contains(&name.as_str()) {
                match inline {
                    Some(v) => Some(v),
                    None if name == "--cache-show" || name == "--debug" || name == "--cov" => {
                        match toks.get(i) {
                            Some(n) if !n.starts_with('-') => {
                                i += 1;
                                Some(n.clone())
                            }
                            _ => None,
                        }
                    }
                    None => {
                        let v = toks.get(i).cloned();
                        i += 1;
                        v
                    }
                }
            } else {
                if inline.is_none() && unknown_then(&name, toks.get(i))? {
                    i += 1;
                }
                continue;
            };
            let v = value.unwrap_or_default();
            match name.as_str() {
                "--ignore" => o.ignore.push(v),
                "--ignore-glob" => o.ignore_glob.push(v),
                "--doctest-glob" => o.doctest_glob.push(v),
                "--override-ini" => override_(&mut o, &v, what)?,
                "--config-file" | "--rootdir" => o.setup = Some(name.clone()),
                _ => {}
            }
            continue;
        }
        // A cluster of short options: `-vx`, `-k expr`, `-kexpr`, `-pno:x`.
        let chars: Vec<char> = t[1..].chars().collect();
        let mut j = 0;
        while j < chars.len() {
            let c = chars[j];
            j += 1;
            if SHORT_FLAGS.contains(&c) {
                continue;
            }
            let rest: String = chars[j..].iter().collect();
            let attached = rest.strip_prefix('=').unwrap_or(&rest).to_owned();
            if !SHORT_VALUES.contains(&c) {
                if rest.is_empty() && unknown_then(&format!("-{c}"), toks.get(i))? {
                    i += 1;
                }
                break;
            }
            let v = if rest.is_empty() {
                let v = toks.get(i).cloned().unwrap_or_default();
                i += 1;
                v
            } else {
                attached
            };
            match c {
                'p' if v.trim() == "no:doctest" => o.no_doctest = true,
                'o' => override_(&mut o, &v, what)?,
                'c' => o.setup = Some("-c".to_owned()),
                _ => {}
            }
            break;
        }
    }
    Ok(o)
}

fn override_(o: &mut Opts, v: &str, what: &str) -> Result<(), String> {
    let (k, val) = v
        .split_once('=')
        .ok_or_else(|| format!("{what}: -o/--override-ini expects option=value (got {v:?})"))?;
    o.overrides.push((k.to_owned(), val.to_owned()));
    Ok(())
}

/// `locate_config` of pytest 9 with the project dir as the only argument.
fn locate_config(dir: &Utf8Path) -> Result<Config, String> {
    let mut pyproject: Option<Utf8PathBuf> = None;
    for base in dir.ancestors() {
        for name in CONFIG_NAMES {
            let p = base.join(name);
            if !p.is_file() {
                continue;
            }
            if *name == "pyproject.toml" && pyproject.is_none() {
                pyproject = Some(p.clone());
            }
            if let Some(values) = load_config(&p)? {
                return Ok(Config {
                    rootdir: Some(base.to_owned()),
                    inipath: Some(p),
                    values,
                });
            }
        }
    }
    Ok(match pyproject {
        Some(p) => Config {
            rootdir: p.parent().map(Utf8Path::to_owned),
            inipath: Some(p),
            values: BTreeMap::new(),
        },
        None => Config::default(),
    })
}

/// `load_config_dict_from_file`: the pytest configuration in `p`, `None`
/// when it holds none.
fn load_config(p: &Utf8Path) -> Result<Option<BTreeMap<String, IniValue>>, String> {
    let name = p.file_name().unwrap_or_default();
    let text = std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?;
    match p.extension() {
        Some("ini") => {
            let ini = parse_ini(&text).map_err(|e| format!("{p}: {e}"))?;
            Ok(match ini.get("pytest") {
                Some(s) => Some(ini_values(s)),
                None if name == "pytest.ini" || name == ".pytest.ini" => Some(BTreeMap::new()),
                None => None,
            })
        }
        Some("cfg") => {
            let ini = parse_ini(&text).map_err(|e| format!("{p}: {e}"))?;
            if let Some(s) = ini.get("tool:pytest") {
                Ok(Some(ini_values(s)))
            } else if ini.contains_key("pytest") {
                Err(format!(
                    "{p}: [pytest] section in setup.cfg files is no longer supported, change to [tool:pytest] instead"
                ))
            } else {
                Ok(None)
            }
        }
        Some("toml") => {
            let t: toml::Table = toml::from_str(&text).map_err(|e| format!("{p}: {e}"))?;
            if name == "pytest.toml" || name == ".pytest.toml" {
                let values = match t.get("pytest").and_then(toml::Value::as_table) {
                    Some(tbl) => tbl.iter().map(|(k, v)| (k.clone(), toml_mode(v))).collect(),
                    None => BTreeMap::new(),
                };
                return Ok(Some(values));
            }
            let Some(tool) = t
                .get("tool")
                .and_then(toml::Value::as_table)
                .and_then(|t| t.get("pytest"))
                .and_then(toml::Value::as_table)
            else {
                return Ok(None);
            };
            let native: BTreeMap<String, IniValue> = tool
                .iter()
                .filter(|(k, _)| *k != "ini_options")
                .map(|(k, v)| (k.clone(), toml_mode(v)))
                .collect();
            let ini = tool.get("ini_options");
            if !native.is_empty() && ini.is_some() {
                return Err(format!(
                    "{p}: Cannot use both [tool.pytest] (native TOML types) and [tool.pytest.ini_options] (string-based INI format) simultaneously"
                ));
            }
            if !native.is_empty() {
                return Ok(Some(native));
            }
            Ok(ini.map(|v| match v.as_table() {
                Some(tbl) => tbl.iter().map(|(k, v)| (k.clone(), ini_mode(v))).collect(),
                None => BTreeMap::new(),
            }))
        }
        _ => Ok(None),
    }
}

fn ini_values(section: &BTreeMap<String, String>) -> BTreeMap<String, IniValue> {
    section
        .iter()
        .map(|(k, v)| (k.clone(), IniValue::Str(v.clone())))
        .collect()
}

/// `str(v)` of Python for a TOML scalar.
fn py_str(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Boolean(true) => "True".to_owned(),
        toml::Value::Boolean(false) => "False".to_owned(),
        other => other.to_string(),
    }
}

/// `[tool.pytest.ini_options]`: lists stay lists, scalars become strings.
fn ini_mode(v: &toml::Value) -> IniValue {
    match v {
        toml::Value::Array(a) => IniValue::List(a.iter().map(py_str).collect()),
        other => IniValue::Str(py_str(other)),
    }
}

/// `[tool.pytest]` and `pytest.toml`: a list of strings, or the wrong type.
fn toml_mode(v: &toml::Value) -> IniValue {
    match v {
        toml::Value::Array(a) if a.iter().all(toml::Value::is_str) => {
            IniValue::List(a.iter().map(py_str).collect())
        }
        other => IniValue::Bad(format!("expects a list of strings, got {other}")),
    }
}

/// An INI file as `iniconfig.IniConfig(path)` reads it (no inline comments
/// stripped): section -> name -> value.
fn parse_ini(text: &str) -> Result<BTreeMap<String, BTreeMap<String, String>>, String> {
    // (section, name, value) per logical line; name None: a section header.
    let mut toks: Vec<(String, Option<String>, String)> = Vec::new();
    let mut section: Option<String> = None;
    for (n, raw) in text.lines().enumerate() {
        let lineno = n + 1;
        let first = raw.trim_start().chars().next();
        if matches!(first, Some('#' | ';')) {
            continue;
        }
        let line = raw.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut continuation: Option<String> = None;
        if line.starts_with('[') {
            let mut l = line;
            for c in ['#', ';'] {
                l = l.split(c).next().unwrap_or("").trim_end();
            }
            if l.len() >= 2 && l.ends_with(']') {
                let name = &l[1..l.len() - 1];
                if name.is_empty() {
                    return Err(format!("line {lineno}: empty section name"));
                }
                section = Some(name.to_owned());
                toks.push((name.to_owned(), None, String::new()));
                continue;
            }
            continuation = Some(line.trim().to_owned());
        } else if !line.starts_with(char::is_whitespace) {
            let (name, value) = match line.split_once('=') {
                Some((n, v)) if !n.contains(':') => (n, v),
                _ => line
                    .split_once(':')
                    .ok_or_else(|| format!("line {lineno}: unexpected line: {line:?}"))?,
            };
            let Some(sec) = &section else {
                return Err(format!("line {lineno}: no section header defined"));
            };
            toks.push((
                sec.clone(),
                Some(name.trim().to_owned()),
                value.trim().to_owned(),
            ));
            continue;
        }
        let data = continuation.unwrap_or_else(|| line.trim().to_owned());
        match toks.last_mut() {
            Some((_, Some(_), v)) => {
                if v.is_empty() {
                    *v = data;
                } else {
                    v.push('\n');
                    v.push_str(&data);
                }
            }
            _ => return Err(format!("line {lineno}: unexpected value continuation")),
        }
    }
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (sec, name, value) in toks {
        match name {
            None => {
                if out.insert(sec.clone(), BTreeMap::new()).is_some() {
                    return Err(format!("duplicate section {sec:?}"));
                }
            }
            Some(name) => {
                let s = out.entry(sec).or_default();
                if s.insert(name.clone(), value).is_some() {
                    return Err(format!("duplicate name {name:?}"));
                }
            }
        }
    }
    Ok(out)
}

/// `shlex.split(s)` (POSIX mode, no comments).
pub(crate) fn shlex_split(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_tok = false;
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            ' ' | '\t' | '\r' | '\n' => {
                if in_tok {
                    out.push(std::mem::take(&mut cur));
                    in_tok = false;
                }
            }
            '\'' => {
                in_tok = true;
                loop {
                    match it.next() {
                        Some('\'') => break,
                        Some(x) => cur.push(x),
                        None => return Err("No closing quotation".into()),
                    }
                }
            }
            '"' => {
                in_tok = true;
                loop {
                    match it.next() {
                        Some('"') => break,
                        Some('\\') => match it.peek() {
                            Some('"' | '\\') => cur.push(it.next().unwrap_or_default()),
                            Some(_) => cur.push('\\'),
                            None => return Err("No closing quotation".into()),
                        },
                        Some(x) => cur.push(x),
                        None => return Err("No closing quotation".into()),
                    }
                }
            }
            '\\' => {
                in_tok = true;
                match it.next() {
                    Some(x) => cur.push(x),
                    None => return Err("No escaped character".into()),
                }
            }
            x => {
                in_tok = true;
                cur.push(x);
            }
        }
    }
    if in_tok {
        out.push(cur);
    }
    Ok(out)
}

/// pytest's `fnmatch_ex`: a pattern without `/` matches the file name, one
/// with `/` the whole path (`*/` prepended to a relative pattern).
pub(crate) fn fnmatch_ex(pattern: &str, path: &Utf8Path) -> bool {
    if !pattern.contains('/') {
        return fnmatch(pattern, path.file_name().unwrap_or_default());
    }
    if path.is_absolute() && !pattern.starts_with('/') {
        fnmatch(&format!("*/{pattern}"), path.as_str())
    } else {
        fnmatch(pattern, path.as_str())
    }
}

/// Python's `fnmatch.fnmatch` on POSIX: `*` (any string, `/` included), `?`,
/// `[seq]`, `[!seq]`; an unclosed `[` is literal.
pub(crate) fn fnmatch(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = name.chars().collect();
    fn class_end(p: &[char], i: usize) -> Option<usize> {
        // p[i] == '['; Python: j = i+1, skip '!', skip a leading ']'.
        let mut j = i + 1;
        if j < p.len() && p[j] == '!' {
            j += 1;
        }
        if j < p.len() && p[j] == ']' {
            j += 1;
        }
        while j < p.len() && p[j] != ']' {
            j += 1;
        }
        (j < p.len()).then_some(j)
    }
    fn class_matches(set: &[char], c: char) -> bool {
        let (neg, set) = match set.first() {
            Some('!') => (true, &set[1..]),
            _ => (false, set),
        };
        let mut k = 0;
        let mut hit = false;
        while k < set.len() {
            if k + 2 < set.len() && set[k + 1] == '-' {
                if set[k] <= c && c <= set[k + 2] {
                    hit = true;
                }
                k += 3;
            } else {
                if set[k] == c {
                    hit = true;
                }
                k += 1;
            }
        }
        hit != neg
    }
    fn go(p: &[char], s: &[char]) -> bool {
        let (mut pi, mut si) = (0, 0);
        let mut star: Option<(usize, usize)> = None;
        while si < s.len() {
            if pi < p.len() {
                match p[pi] {
                    '*' => {
                        star = Some((pi, si));
                        pi += 1;
                        continue;
                    }
                    '?' => {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                    '[' => {
                        if let Some(end) = class_end(p, pi) {
                            if class_matches(&p[pi + 1..end], s[si]) {
                                pi = end + 1;
                                si += 1;
                                continue;
                            }
                        } else if s[si] == '[' {
                            pi += 1;
                            si += 1;
                            continue;
                        }
                    }
                    c if c == s[si] => {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                    _ => {}
                }
            }
            match star {
                Some((sp, ss)) => {
                    pi = sp + 1;
                    si = ss + 1;
                    star = Some((sp, ss + 1));
                }
                None => return false,
            }
        }
        p[pi..].iter().all(|&c| c == '*')
    }
    go(&p, &s)
}

/// `glob.glob(pattern, recursive=True)` relative to `cwd`, as absolute
/// paths: `*`, `?` and `[...]` within a name (names starting with `.` only
/// when the pattern's name does), `**` for any number of directories.
fn py_glob(cwd: &Utf8Path, pattern: &str) -> Vec<Utf8PathBuf> {
    let has_magic = |s: &str| s.contains(['*', '?', '[']);
    if !has_magic(pattern) {
        let p = absolute(cwd, pattern);
        return if std::fs::symlink_metadata(&p).is_ok() {
            vec![p]
        } else {
            vec![]
        };
    }
    let (start, rest) = match pattern.strip_prefix('/') {
        Some(r) => (Utf8PathBuf::from("/"), r),
        None => (cwd.to_owned(), pattern),
    };
    let comps: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
    let mut out = Vec::new();
    glob_rec(&start, &comps, &mut out, &has_magic);
    out.sort();
    out.dedup();
    out
}

fn sorted_names(dir: &Utf8Path) -> Vec<String> {
    let mut v: Vec<String> = dir
        .read_dir_utf8()
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.file_name().to_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn glob_rec(
    base: &Utf8Path,
    comps: &[&str],
    out: &mut Vec<Utf8PathBuf>,
    has_magic: &dyn Fn(&str) -> bool,
) {
    let Some((c, rest)) = comps.split_first() else {
        out.push(base.to_owned());
        return;
    };
    if *c == "**" {
        // `base` itself, then every non-hidden descendant.
        let mut all = vec![base.to_owned()];
        let mut seen: Vec<Utf8PathBuf> = Vec::new();
        let mut stack = vec![base.to_owned()];
        while let Some(d) = stack.pop() {
            let real = d.canonicalize_utf8().unwrap_or_else(|_| d.clone());
            if seen.contains(&real) {
                continue;
            }
            seen.push(real);
            for n in sorted_names(&d) {
                if n.starts_with('.') {
                    continue;
                }
                let p = d.join(&n);
                if p.is_dir() {
                    stack.push(p.clone());
                }
                all.push(p);
            }
        }
        for p in all {
            if rest.is_empty() {
                if p != base || base.is_dir() {
                    out.push(p);
                }
            } else if p.is_dir() {
                glob_rec(&p, rest, out, has_magic);
            }
        }
    } else if has_magic(c) {
        for n in sorted_names(base) {
            if n.starts_with('.') && !c.starts_with('.') {
                continue;
            }
            if fnmatch(c, &n) {
                let p = base.join(&n);
                if rest.is_empty() {
                    out.push(p);
                } else if p.is_dir() {
                    glob_rec(&p, rest, out, has_magic);
                }
            }
        }
    } else {
        let p = base.join(c);
        if rest.is_empty() {
            if std::fs::symlink_metadata(&p).is_ok() {
                out.push(p);
            }
        } else if p.is_dir() {
            glob_rec(&p, rest, out, has_magic);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "def test_it():\n    assert True\n";

    /// A project dir (canonical) in a temp dir, with `files` written.
    fn project(files: &[(&str, &str)]) -> (tempfile::TempDir, Utf8PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        let dir = root.join("proj");
        std::fs::create_dir_all(&dir).unwrap();
        for (rel, content) in files {
            put(&dir, rel, content);
        }
        (t, dir)
    }

    fn put(dir: &Utf8Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn listed(dir: &Utf8Path, addopts: Option<&str>) -> Vec<String> {
        list(dir, addopts)
            .unwrap()
            .iter()
            .map(|p| p.strip_prefix(dir).unwrap().to_string())
            .collect()
    }

    #[test]
    fn default_python_files_in_nested_dirs_sorted() {
        let (_t, d) = project(&[
            ("tests/test_a.py", T),
            ("tests/b_test.py", T),
            ("tests/sub/deep/test_c.py", T),
            ("tests/helper.py", T),
            ("tests/conftest.py", ""),
            ("tests/pkg/__init__.py", ""),
            ("tests/pkg/test_d.py", T),
            ("test_top.py", T),
            ("tests/test_data.json", "{}"),
            ("tests/testx.py", T),
        ]);
        assert_eq!(
            listed(&d, None),
            [
                "test_top.py",
                "tests/b_test.py",
                "tests/pkg/test_d.py",
                "tests/sub/deep/test_c.py",
                "tests/test_a.py",
            ]
        );
    }

    #[test]
    fn default_norecursedirs_pycache_and_virtualenvs() {
        let mut files = vec![("tests/test_ok.py", T)];
        let dirs = [
            "x.egg",
            ".hidden",
            "_darcs",
            "build",
            "CVS",
            "dist",
            "node_modules",
            "venv",
            "{arch}",
            "tests/__pycache__",
            "tests/.cache",
            "tests/build",
        ];
        let paths: Vec<String> = dirs.iter().map(|d| format!("{d}/test_no.py")).collect();
        files.extend(paths.iter().map(|p| (p.as_str(), T)));
        files.extend([
            ("myenv/pyvenv.cfg", "home = /usr\n"),
            ("myenv/test_no.py", T),
            ("condaenv/conda-meta/history", ""),
            ("condaenv/test_no.py", T),
            ("venvlike/test_yes.py", T),
            ("builder/test_yes.py", T),
        ]);
        let (_t, d) = project(&files);
        assert_eq!(
            listed(&d, None),
            [
                "builder/test_yes.py",
                "tests/test_ok.py",
                "venvlike/test_yes.py"
            ]
        );
        // --collect-in-virtualenv enters virtualenvs (not `venv`, which is
        // in norecursedirs).
        assert_eq!(
            listed(&d, Some("--collect-in-virtualenv")),
            [
                "builder/test_yes.py",
                "condaenv/test_no.py",
                "myenv/test_no.py",
                "tests/test_ok.py",
                "venvlike/test_yes.py"
            ]
        );
    }

    #[test]
    fn configured_norecursedirs_replaces_the_default() {
        let (_t, d) = project(&[
            ("pytest.ini", "[pytest]\nnorecursedirs = build\n  other*\n"),
            (".hidden/test_h.py", T),
            ("venv/test_v.py", T),
            ("dist/test_d.py", T),
            ("build/test_b.py", T),
            ("others/test_o.py", T),
            ("tests/build/test_bb.py", T),
            ("env/pyvenv.cfg", ""),
            ("env/test_e.py", T),
            ("tests/__pycache__/test_c.py", T),
        ]);
        assert_eq!(
            listed(&d, None),
            [".hidden/test_h.py", "dist/test_d.py", "venv/test_v.py"]
        );
        // A pattern with a slash matches the path.
        put(
            &d,
            "pytest.ini",
            "[pytest]\nnorecursedirs = tests/build .*\n",
        );
        assert_eq!(
            listed(&d, None),
            [
                "build/test_b.py",
                "dist/test_d.py",
                "others/test_o.py",
                "venv/test_v.py"
            ]
        );
    }

    #[test]
    fn testpaths_their_globs_and_the_fallback() {
        let (_t, d) = project(&[
            (
                "pyproject.toml",
                "[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n",
            ),
            ("tests/test_a.py", T),
            ("integration/test_i.py", T),
            ("more1/test_m1.py", T),
            ("more2/test_m2.py", T),
            (".more3/test_m3.py", T),
            ("test_top.py", T),
        ]);
        assert_eq!(listed(&d, None), ["tests/test_a.py"]);
        put(
            &d,
            "pyproject.toml",
            "[tool.pytest.ini_options]\ntestpaths = \"tests more*\"\n",
        );
        assert_eq!(
            listed(&d, None),
            ["more1/test_m1.py", "more2/test_m2.py", "tests/test_a.py"]
        );
        // A file given in testpaths is collected whatever its name.
        put(&d, "tests/helper.py", T);
        put(
            &d,
            "pyproject.toml",
            "[tool.pytest.ini_options]\ntestpaths = [\"tests/helper.py\", \"**/test_m1.py\"]\n",
        );
        assert_eq!(listed(&d, None), ["more1/test_m1.py", "tests/helper.py"]);
        // Nothing matches: the project dir.
        put(
            &d,
            "pyproject.toml",
            "[tool.pytest.ini_options]\ntestpaths = [\"nothing*\"]\n",
        );
        let everything = [
            "integration/test_i.py",
            "more1/test_m1.py",
            "more2/test_m2.py",
            "test_top.py",
            "tests/test_a.py",
        ];
        assert_eq!(listed(&d, None), everything);
        // Without a configuration file there is no testpaths.
        std::fs::remove_file(d.join("pyproject.toml")).unwrap();
        assert_eq!(listed(&d, None), everything);
    }

    #[test]
    fn python_files_both_defaults_and_a_configured_list() {
        let (_t, d) = project(&[
            ("tests/test_a.py", T),
            ("tests/a_test.py", T),
            ("tests/check_a.py", T),
            ("tests/a_spec.py", T),
            ("tests/integration/flow.py", T),
        ]);
        assert_eq!(listed(&d, None), ["tests/a_test.py", "tests/test_a.py"]);
        put(
            &d,
            "setup.cfg",
            "[metadata]\nname = x\n\n[tool:pytest]\npython_files = check_*.py\n    *_spec.py\n",
        );
        assert_eq!(listed(&d, None), ["tests/a_spec.py", "tests/check_a.py"]);
        // A pattern with a slash matches the end of the path.
        put(
            &d,
            "setup.cfg",
            "[tool:pytest]\npython_files = integration/*.py\n",
        );
        assert_eq!(listed(&d, None), ["tests/integration/flow.py"]);
        // `-o` overrides the file's value.
        assert_eq!(
            listed(&d, Some("-o python_files=*_test.py")),
            ["tests/a_test.py"]
        );
    }

    #[test]
    fn ignore_and_ignore_glob_in_addopts_and_pytest_addopts() {
        let (_t, d) = project(&[
            (
                "tox.ini",
                "[tox]\nenvlist = py\n\n[pytest]\naddopts = --ignore=tests/slow --ignore tests/test_b.py -ra --tb=short\n",
            ),
            ("tests/test_a.py", T),
            ("tests/test_b.py", T),
            ("tests/slow/test_s.py", T),
            ("tests/fast/test_f.py", T),
            ("tests/fast/test_skip_me.py", T),
        ]);
        assert_eq!(
            listed(&d, None),
            [
                "tests/fast/test_f.py",
                "tests/fast/test_skip_me.py",
                "tests/test_a.py"
            ]
        );
        assert_eq!(
            listed(&d, Some("--ignore-glob=*/test_skip_*.py -q")),
            ["tests/fast/test_f.py", "tests/test_a.py"]
        );
    }

    #[test]
    fn configuration_files_their_precedence_and_ancestors() {
        let (_t, d) = project(&[
            ("tests/test_a.py", T),
            ("other/test_o.py", T),
            ("check_x.py", T),
        ]);
        let all = ["check_x.py", "other/test_o.py", "tests/test_a.py"];
        // pyproject.toml without pytest configuration: none.
        put(&d, "pyproject.toml", "[project]\nname = \"x\"\n");
        assert_eq!(listed(&d, None), all[1..]);
        // tox.ini without [pytest]: none; setup.cfg with [tool:pytest].
        put(&d, "tox.ini", "[tox]\nenvlist = py\n");
        put(&d, "setup.cfg", "[tool:pytest]\ntestpaths = other\n");
        assert_eq!(listed(&d, None), ["other/test_o.py"]);
        // pyproject.toml comes before setup.cfg.
        put(
            &d,
            "pyproject.toml",
            "[tool.pytest]\ntestpaths = [\"tests\"]\n",
        );
        assert_eq!(listed(&d, None), ["tests/test_a.py"]);
        // An empty pytest.ini is the configuration file: nothing configured.
        put(&d, "pytest.ini", "");
        assert_eq!(listed(&d, None), all[1..]);
        // pytest.toml comes first.
        put(
            &d,
            "pytest.toml",
            "[pytest]\npython_files = [\"check_*.py\"]\n",
        );
        assert_eq!(listed(&d, None), ["check_x.py"]);
        for f in [
            "pytest.toml",
            "pytest.ini",
            "pyproject.toml",
            "tox.ini",
            "setup.cfg",
        ] {
            std::fs::remove_file(d.join(f)).unwrap();
        }
        // In a parent directory: its options apply, its testpaths do not
        // (the rootdir is not the project dir).
        put(
            d.parent().unwrap(),
            "pytest.ini",
            "[pytest]\ntestpaths = tests\npython_files = check_*.py test_*.py\n",
        );
        assert_eq!(listed(&d, None), all);
    }

    #[test]
    fn configuration_errors() {
        let (_t, d) = project(&[("tests/test_a.py", T)]);
        put(&d, "setup.cfg", "[pytest]\ntestpaths = tests\n");
        assert!(list(&d, None).unwrap_err().contains("[tool:pytest]"));
        std::fs::remove_file(d.join("setup.cfg")).unwrap();
        put(
            &d,
            "pyproject.toml",
            "[tool.pytest]\naddopts = [\"-q\"]\n[tool.pytest.ini_options]\naddopts = \"-q\"\n",
        );
        assert!(list(&d, None).unwrap_err().contains("simultaneously"));
        // Native TOML wants lists.
        put(
            &d,
            "pyproject.toml",
            "[tool.pytest]\ntestpaths = \"tests\"\n",
        );
        assert!(list(&d, None).unwrap_err().contains("list of strings"));
        put(&d, "pyproject.toml", "[tool.pytest\n");
        assert!(list(&d, None).is_err());
        std::fs::remove_file(d.join("pyproject.toml")).unwrap();
        put(&d, "pytest.ini", "testpaths = tests\n");
        assert!(list(&d, None).unwrap_err().contains("no section header"));
        put(&d, "pytest.ini", "[pytest]\naddopts = --pyargs\n");
        assert!(list(&d, None).unwrap_err().contains("--pyargs"));
        put(&d, "pytest.ini", "[pytest]\naddopts = \"-k x\n");
        assert!(list(&d, None).unwrap_err().contains("No closing quotation"));
        std::fs::remove_file(d.join("pytest.ini")).unwrap();
        assert!(list(&d, Some("--rootdir=/tmp")).is_err());
        assert!(list(&d, Some("-c other.ini")).is_err());
        assert!(list(&d, Some("tests")).is_err());
    }

    #[test]
    fn paths_and_unknown_options_in_addopts() {
        let (_t, d) = project(&[
            ("tests/test_a.py", T),
            ("tests/test_b.py", T),
            ("other/test_o.py", T),
            ("other/helper.py", T),
        ]);
        put(
            &d,
            "pytest.ini",
            "[pytest]\ntestpaths = tests\naddopts = other\n",
        );
        assert_eq!(listed(&d, None), ["other/test_o.py"]);
        put(
            &d,
            "pytest.ini",
            "[pytest]\naddopts = -n 4 --cov src -x tests/test_b.py::test_it other/helper.py\n",
        );
        assert_eq!(listed(&d, None), ["other/helper.py", "tests/test_b.py"]);
        put(&d, "pytest.ini", "[pytest]\naddopts = missing_dir\n");
        assert!(list(&d, None).unwrap_err().contains("not found"));
        // An option vci does not know: its value, unless it names a path.
        put(
            &d,
            "pytest.ini",
            "[pytest]\ntestpaths = tests\naddopts = --plugin-opt fast\n",
        );
        assert_eq!(listed(&d, None), ["tests/test_a.py", "tests/test_b.py"]);
        put(&d, "pytest.ini", "[pytest]\naddopts = --plugin-opt other\n");
        assert!(list(&d, None).unwrap_err().contains("cannot tell"));
    }

    #[test]
    fn doctest_files_and_modules() {
        let (_t, d) = project(&[
            ("pytest.ini", "[pytest]\ntestpaths = tests src\n"),
            ("tests/test_a.py", T),
            ("tests/test_guide.txt", "Guide\n\n    >>> 1 + 1\n    2\n"),
            ("tests/test_notes.txt", "no example\n"),
            ("tests/guide.rst", ">>> 1\n1\n"),
            (
                "src/mod.py",
                "def f():\n    \"\"\"\n    >>> f()\n    1\n    \"\"\"\n    return 1\n",
            ),
            ("src/plain.py", "X = 1\n"),
            ("src/__main__.py", "\"\"\"\n>>> 1\n1\n\"\"\"\n"),
            ("src/setup.py", "import setuptools\n\"\"\">>> 1\"\"\"\n"),
        ]);
        assert_eq!(
            listed(&d, None),
            ["tests/test_a.py", "tests/test_guide.txt"]
        );
        assert_eq!(listed(&d, Some("-p no:doctest")), ["tests/test_a.py"]);
        assert_eq!(
            listed(&d, Some("--doctest-glob=*.rst")),
            ["tests/guide.rst", "tests/test_a.py"]
        );
        assert_eq!(
            listed(&d, Some("--doctest-modules")),
            ["src/mod.py", "tests/test_a.py", "tests/test_guide.txt"]
        );
    }

    #[test]
    fn symlinked_directories_are_followed_inside_the_project() {
        let (t, d) = project(&[("tests/real/test_r.py", T), ("tests/test_a.py", T)]);
        std::os::unix::fs::symlink(d.join("tests/real"), d.join("tests/link")).unwrap();
        // A loop back up is walked once.
        std::os::unix::fs::symlink(d.join("tests"), d.join("tests/real/up")).unwrap();
        assert_eq!(
            listed(&d, None),
            ["tests/real/test_r.py", "tests/test_a.py"]
        );
        // A directory outside the project: an error, as when pytest listed it.
        let outside = Utf8Path::from_path(t.path()).unwrap().join("outside");
        put(&outside, "test_x.py", T);
        std::os::unix::fs::symlink(&outside, d.join("tests/ext")).unwrap();
        assert!(
            list(&d, None)
                .unwrap_err()
                .contains("outside the project dir")
        );
    }

    #[test]
    fn shlex_split_like_python() {
        assert_eq!(
            shlex_split(r#"-k "a and not b" --x='y z' a\ b "q\"r" 'it''s' "\n""#).unwrap(),
            ["-k", "a and not b", "--x=y z", "a b", "q\"r", "its", "\\n"]
        );
        assert_eq!(shlex_split("  a\n\tb  ").unwrap(), ["a", "b"]);
        assert_eq!(shlex_split("#x y").unwrap(), ["#x", "y"]);
        assert!(shlex_split("'a").is_err());
        assert!(shlex_split("a\\").is_err());
    }

    #[test]
    fn fnmatch_like_python() {
        assert!(fnmatch("test_*.py", "test_a.py"));
        assert!(fnmatch("*_test.py", ".x_test.py"));
        assert!(!fnmatch("test_*.py", "test_a.pyc"));
        assert!(fnmatch("*", "a/b"));
        assert!(fnmatch("t?st", "test"));
        assert!(fnmatch("[!a]x", "bx"));
        assert!(!fnmatch("[!a]x", "ax"));
        assert!(fnmatch("[a-c]x", "bx"));
        assert!(fnmatch("[]]x", "]x"));
        assert!(fnmatch("[x", "[x"));
        assert!(fnmatch("{arch}", "{arch}"));
        assert!(fnmatch("*.egg", "x.egg"));
        assert!(fnmatch_ex("tests/*.py", Utf8Path::new("/p/tests/a.py")));
        assert!(!fnmatch_ex("tests/*.py", Utf8Path::new("/p/other/a.py")));
        assert!(fnmatch_ex(".*", Utf8Path::new("/p/.git")));
    }

    #[test]
    fn ini_files_like_iniconfig() {
        let ini = parse_ini(
            "# c\n[pytest]\naddopts = -q ; not a comment\n  -x\n; comment\n\ntestpaths: a\nempty =\n  later\n[other] # c\nk=v\n",
        )
        .unwrap();
        assert_eq!(ini["pytest"]["addopts"], "-q ; not a comment\n-x");
        assert_eq!(ini["pytest"]["testpaths"], "a");
        assert_eq!(ini["pytest"]["empty"], "later");
        assert_eq!(ini["other"]["k"], "v");
        assert!(parse_ini("[a]\n[a]\n").is_err());
        assert!(parse_ini("[a]\nk=1\nk=2\n").is_err());
        assert!(parse_ini("[a]\n  cont\n").is_err());
        assert!(parse_ini("[a]\nnovalue\n").is_err());
    }
}
