//! Cargo adapter: the unit is a cargo test target, run with `cargo test`.
//!
//! Units (test ids are `<package dir>#<target>`, the package dir relative to
//! the repository root, `.` for a package at the root):
//!
//! * `#lib`: the library's unit tests (`cargo test --lib`);
//! * `#doc`: the library's doctests (`cargo test --doc`);
//! * `#bin:<name>`, `#test:<name>`, `#example:<name>`, `#bench:<name>`: that
//!   target's tests (`cargo test --bin <name>`, ...).
//!
//! Every target `cargo test --workspace` would run is a unit (targets with
//! `test = true` and, for doctests, `doctest = true`, whose
//! `required-features` are enabled by default).
//!
//! Rust has no hook for what a test does at run time, so the inputs of a
//! unit are decided conservatively, from `cargo test --no-run
//! --message-format=json` of that unit alone (which reports every crate the
//! unit builds):
//!
//! * every file and directory listing in the package directory of every
//!   crate of the repository the unit builds (the package under test and its
//!   path dependencies), `.gitignore` notwithstanding, except the target dir;
//! * every file in rustc's dep-info for those crates (sources,
//!   `include_str!` targets, `#[path]` files, also outside the package dirs)
//!   and the `env!`/`option_env!` variables it lists;
//! * each build script's `rerun-if-changed` paths and `rerun-if-env-changed`
//!   variables;
//! * external crates as `name` + `version source checksum` (Cargo.lock);
//! * files and variables declared in vci.toml (`[[inputs]]`), handled by
//!   the CLI.
//!
//! and static checks of the repository sources refuse what cannot be
//! observed (processes, sockets, native code, environment enumeration,
//! reads outside the recorded inputs; see [`scan`]).
//!
//! How a run goes (see [`lane`]): a warm-up build of each requested package
//! (alone, so its features are its units') with cargo's full parallelism,
//! then the cargo lane builds each unit alone (`cargo test <unit> --no-run`,
//! so its features and the artifacts it reports are the unit's own) and
//! hands its test executable to the execution pool, which runs several units
//! at once the way `cargo test` runs them ([`exec`]; `VCI_CARGO_JOBS` at a
//! time). Once every test has run, the units are analysed (in parallel, with
//! run-wide caches). Doctests cannot be built without running them: `#doc`
//! units run `cargo test --doc` in the lane.

pub(crate) mod cfgexpr;
pub(crate) mod config;
pub(crate) mod depinfo;
pub(crate) mod exec;
mod lane;
pub(crate) mod scan;
pub(crate) mod sources;

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::hash::Hash;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use serde_json::Value;

use crate::golang::normalise;
use crate::vitest::{apply_env, describe};
use crate::{
    Adapter, AdapterError, ChildEnv, InstalledExternals, ListedFile, Observed, RunOutput,
    ToolVersions,
};

/// Env var naming the `cargo` binary (default: `cargo` on PATH).
pub const CARGO_BIN_ENV: &str = "VCI_CARGO";

/// Taint prefix for units whose source suggests reads outside the package
/// directory that no recorded input covers. Declaring inputs for the unit in
/// vci.toml (`[[inputs]]`) waives it.
pub const CARGO_UNDECLARED_TAINT: &str = "cargo:undeclared-reads";

/// Built-in ignore for Cargo (docs/ENV.md): where toolchains, the registry
/// and the build cache live, how crates are fetched, and wrappers that cache
/// compilation (any wrapper other than sccache refuses the unit).
/// `RUST_BACKTRACE`, `RUST_LIB_BACKTRACE` and `RUST_LOG` are not here: std
/// (`Backtrace::capture`) and dependency crates (`env_logger`, `tracing`'s
/// `EnvFilter`) read them where the source scan cannot see the read, and a
/// test can depend on them, so they are removed unless vci.toml lists them.
pub const CARGO_IGNORE: &[&str] = &[
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "RUSTUP_DIST_SERVER",
    "RUSTUP_UPDATE_ROOT",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET_DIR",
    "CARGO_BUILD_BUILD_DIR",
    "CARGO_BUILD_JOBS",
    "CARGO_NET_*",
    "CARGO_HTTP_*",
    "CARGO_REGISTRIES_*",
    "CARGO_REGISTRY_*",
    "CARGO_TERM_*",
    "CARGO_LOG",
    "CARGO_CACHE_RUSTC_INFO",
    "CARGO_INCREMENTAL",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "SCCACHE_*",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
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
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "SSH_AUTH_SOCK",
];

/// Hashed whenever present in loose mode (deprecated), where every variable
/// reaches the tests: vci 1.5's list of what the runtime reads where nothing
/// observes it, kept so that loose mode hashes what it did. Strict mode removes
/// these unless they are built-in or vci.toml lists them.
pub const CARGO_LOOSE_HASH: &[&str] = &[
    "RUST*",
    "CARGO*",
    "CC",
    "CXX",
    "AR",
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CC_*",
    "CXX_*",
    "AR_*",
    "CFLAGS_*",
    "CXXFLAGS_*",
    "TARGET_CC",
    "TARGET_CXX",
    "TARGET_AR",
    "TARGET_CFLAGS",
    "TARGET_CXXFLAGS",
    "HOST_CC",
    "HOST_CXX",
    "HOST_CFLAGS",
    "PKG_CONFIG*",
    "MACOSX_DEPLOYMENT_TARGET",
    "SDKROOT",
    "!CARGO_HOME",
    "!RUSTUP_*",
    "!CARGO_TARGET_DIR",
    "!CARGO_BUILD_TARGET_DIR",
    "!CARGO_BUILD_BUILD_DIR",
    "!CARGO_BUILD_JOBS",
    "!CARGO_NET_*",
    "!CARGO_HTTP_*",
    "!CARGO_REGISTRIES_*",
    "!CARGO_REGISTRY_*",
    "!CARGO_TERM_*",
    "!CARGO_LOG",
    "!CARGO_CACHE_RUSTC_INFO",
    "!CARGO_INCREMENTAL",
    "!RUSTC_WRAPPER",
    "!RUSTC_WORKSPACE_WRAPPER",
    "!CARGO_BUILD_RUSTC_WRAPPER",
    "!CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
];

/// Built-in hash for Cargo (docs/ENV.md): what changes what is built (the
/// compiler and its flags, profiles, the target, the C toolchain build
/// scripts use) or how the test harness runs, read by cargo, rustc, build
/// scripts or the harness where nothing observes it. Every other `RUST*` and
/// `CARGO*` variable is removed unless vci.toml lists it.
pub const CARGO_HASH: &[&str] = &[
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_RUSTDOCFLAGS",
    "CARGO_BUILD_TARGET",
    "CARGO_TARGET_*_RUSTFLAGS",
    "CARGO_PROFILE_*",
    "RUSTC",
    "RUSTDOC",
    "RUSTC_BOOTSTRAP",
    "RUST_TEST_THREADS",
    "RUST_MIN_STACK",
    "CC",
    "CXX",
    "AR",
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CC_*",
    "CXX_*",
    "AR_*",
    "CFLAGS_*",
    "CXXFLAGS_*",
    "TARGET_CC",
    "TARGET_CXX",
    "TARGET_AR",
    "TARGET_CFLAGS",
    "TARGET_CXXFLAGS",
    "HOST_CC",
    "HOST_CXX",
    "HOST_CFLAGS",
    "PKG_CONFIG*",
    "MACOSX_DEPLOYMENT_TARGET",
    "SDKROOT",
];

/// External crates whose purpose is network I/O or child processes (the
/// unit's tests could use them where nothing observes it), and crates that
/// do so only with some features.
const NET_PROCESS_CRATES: &[&str] = &[
    "reqwest",
    "hyper",
    "hyper-util",
    "h2",
    "ureq",
    "curl",
    "curl-sys",
    "isahc",
    "surf",
    "attohttpc",
    "minreq",
    "awc",
    "actix-web",
    "actix-http",
    "axum",
    "warp",
    "rocket",
    "tide",
    "tonic",
    "tungstenite",
    "tokio-tungstenite",
    "async-tungstenite",
    "socket2",
    "async-std",
    "async-net",
    "async-process",
    "async-io",
    "smol",
    "trust-dns-resolver",
    "hickory-resolver",
    "native-tls",
    "openssl",
    "lettre",
    "redis",
    "postgres",
    "tokio-postgres",
    "sqlx",
    "sqlx-core",
    "mysql",
    "mysql_async",
    "mongodb",
    "rdkafka",
    "assert_cmd",
    "escargot",
    "duct",
    "subprocess",
    "xshell",
    "cmd_lib",
    "portpicker",
    "wiremock",
    "mockito",
    "httpmock",
    "testcontainers",
    "git2",
    "gix",
    "ssh2",
    "pnet",
];

/// Crates that open sockets or start processes only with these features.
const FEATURE_GATED: &[(&str, &[&str])] = &[
    ("tokio", &["net", "process", "full"]),
    ("mio", &["net"]),
    ("rustix", &["net"]),
    ("nix", &["process", "socket", "net"]),
];

/// Directory names vci never walks (the tree snapshot skips them too): a
/// package dir containing one cannot be hashed completely.
const UNWALKED: &[&str] = &["node_modules", ".venv"];

/// Top-level keys a cargo config file outside the repository may set: they
/// change where crates come from (every external crate a unit builds is
/// checked against Cargo.lock when it is attested: see [`sources`]; a
/// directory source replacement outside the repository cannot be and
/// refuses the unit), how output looks, or parallelism, not what is built.
/// `build.rustc-wrapper` is checked separately (only `sccache` is accepted).
const HARMLESS_CONFIG_KEYS: &[&str] = &[
    "net",
    "http",
    "registries",
    "registry",
    "source",
    "credential-alias",
    "term",
    "cargo-new",
    "alias",
    "install",
    "future-incompat-report",
    "cache",
    "gc",
    "resolver",
];

/// `[build]` keys allowed outside the repository.
const HARMLESS_BUILD_KEYS: &[&str] = &[
    "jobs",
    "rustc-wrapper",
    "rustc-workspace-wrapper",
    "target-dir",
    "build-dir",
    "incremental",
    "dep-info-basedir",
    "pipelining",
];

/// Where vci's own builds go, inside cargo's target directory: builds made
/// by vci always use the strict environment, so a build script whose output
/// depends on an undeclared variable is not reused from a build made with
/// another value.
const VCI_TARGET_SUBDIR: &str = "vci";

/// Does `pred` (an attested cfg predicate) evaluate differently on the host
/// whose `rustc --print cfg` is `current` than on the attesting host
/// (`attested`)? `Err` when it cannot be decided (treat as "differs").
pub fn cfg_predicate_differs(
    pred: &str,
    attested: &[String],
    current: &[String],
) -> Result<bool, String> {
    cfgexpr::differs(pred, attested, current)
}

/// The package directory of a unit given as `<package dir>#<target>`.
pub fn unit_package_dir(unit: &Utf8Path) -> Utf8PathBuf {
    match unit.as_str().rsplit_once('#') {
        Some((dir, _)) => Utf8PathBuf::from(dir),
        None => unit.to_owned(),
    }
}

/// The target part of a unit id.
#[derive(Debug, Clone, PartialEq, Eq)]
enum UnitKind {
    Lib,
    Doc,
    Bin(String),
    Test(String),
    Example(String),
    Bench(String),
}

impl UnitKind {
    fn parse(s: &str) -> Option<Self> {
        let named = |p: &str| {
            s.strip_prefix(p)
                .filter(|n| !n.is_empty())
                .map(str::to_owned)
        };
        Some(match s {
            "lib" => Self::Lib,
            "doc" => Self::Doc,
            _ => {
                if let Some(n) = named("bin:") {
                    Self::Bin(n)
                } else if let Some(n) = named("test:") {
                    Self::Test(n)
                } else if let Some(n) = named("example:") {
                    Self::Example(n)
                } else if let Some(n) = named("bench:") {
                    Self::Bench(n)
                } else {
                    return None;
                }
            }
        })
    }

    fn id(&self) -> String {
        match self {
            Self::Lib => "lib".into(),
            Self::Doc => "doc".into(),
            Self::Bin(n) => format!("bin:{n}"),
            Self::Test(n) => format!("test:{n}"),
            Self::Example(n) => format!("example:{n}"),
            Self::Bench(n) => format!("bench:{n}"),
        }
    }

    /// `cargo test` target selection flags.
    fn selector(&self) -> Vec<String> {
        match self {
            Self::Lib => vec!["--lib".into()],
            Self::Doc => vec!["--doc".into()],
            Self::Bin(n) => vec!["--bin".into(), n.clone()],
            Self::Test(n) => vec!["--test".into(), n.clone()],
            Self::Example(n) => vec!["--example".into(), n.clone()],
            Self::Bench(n) => vec!["--bench".into(), n.clone()],
        }
    }
}

/// A unit id relative to the project dir: `crates/a#lib` -> (`crates/a`,
/// Lib); `.#lib` for the package at the project dir.
fn parse_unit(project_rel: &str) -> Option<(String, UnitKind)> {
    let (dir, kind) = project_rel.rsplit_once('#')?;
    let dir = if dir.is_empty() { "." } else { dir };
    Some((dir.to_owned(), UnitKind::parse(kind)?))
}

/// `--manifest-path` value (relative to the project dir) of a package dir.
fn manifest_arg(pkg_rel: &str) -> String {
    if pkg_rel == "." {
        "Cargo.toml".into()
    } else {
        format!("{pkg_rel}/Cargo.toml")
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Target {
    name: String,
    kind: Vec<String>,
    #[serde(default)]
    test: bool,
    #[serde(default)]
    doctest: bool,
    #[serde(default, rename = "required-features")]
    required_features: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Package {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    manifest_path: String,
    #[serde(default)]
    targets: Vec<Target>,
    #[serde(default)]
    features: BTreeMap<String, Vec<String>>,
    /// The fields `cargo test` exports to test processes (`CARGO_PKG_*`).
    #[serde(default)]
    authors: Vec<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    license_file: Option<String>,
    #[serde(default)]
    rust_version: Option<String>,
    #[serde(default)]
    readme: Option<String>,
}

impl Package {
    /// What a test process of this package is told about it.
    fn fields(&self) -> exec::PkgFields {
        exec::PkgFields {
            name: self.name.clone(),
            version: self.version.clone(),
            authors: self.authors.clone(),
            description: self.description.clone(),
            homepage: self.homepage.clone(),
            repository: self.repository.clone(),
            license: self.license.clone(),
            license_file: self.license_file.clone(),
            rust_version: self.rust_version.clone(),
            readme: self.readme.clone(),
            manifest_path: Utf8PathBuf::from(&self.manifest_path),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    workspace_members: Vec<String>,
    workspace_root: String,
    target_directory: String,
}

/// The workspace as `cargo metadata --no-deps` describes it.
#[derive(Debug, Clone)]
struct Workspace {
    meta: Metadata,
    root: Utf8PathBuf,
    target_dir: Utf8PathBuf,
}

#[derive(Debug, Clone)]
struct Probe {
    versions: ToolVersions,
    sysroot: Utf8PathBuf,
    /// The flags cargo passes to rustc (see `config::effective_rustflags`).
    rustflags: Vec<String>,
}

/// A `Cargo.lock` package entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Locked {
    name: String,
    version: String,
    source: String,
    checksum: String,
}

fn parse_lock(text: &str) -> Result<Vec<Locked>, String> {
    let v: toml::Table = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let Some(pkgs) = v.get("package") else {
        return Ok(out);
    };
    for p in pkgs.as_array().ok_or("`package` is not an array")? {
        let s = |k: &str| {
            p.get(k)
                .and_then(toml::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        if s("name").is_empty() || s("version").is_empty() {
            return Err("package without name or version".into());
        }
        out.push(Locked {
            name: s("name"),
            version: s("version"),
            source: s("source"),
            checksum: s("checksum"),
        });
    }
    Ok(out)
}

/// How an external crate is recorded: `version source checksum` (git
/// sources carry the commit in `source`).
fn external_id(version: &str, source: &str, checksum: &str) -> String {
    format!(
        "{version} {source} {}",
        if checksum.is_empty() { "-" } else { checksum }
    )
}

/// Features a package has on by default (the closure of `default`).
fn default_features(p: &Package) -> BTreeSet<String> {
    let mut on: BTreeSet<String> = BTreeSet::new();
    let mut todo = vec!["default".to_owned()];
    while let Some(f) = todo.pop() {
        if !on.insert(f.clone()) {
            continue;
        }
        for item in p.features.get(&f).into_iter().flatten() {
            if item.contains('/') {
                continue;
            }
            todo.push(item.trim_start_matches("dep:").to_owned());
        }
    }
    on
}

/// Target kinds of a library (its `#lib` and `#doc` units).
const LIB_KINDS: &[&str] = &["lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"];

/// Units of the workspace members (what `cargo test --workspace` runs), as
/// (package dir, unit kind).
fn units(meta: &Metadata) -> Vec<(Utf8PathBuf, UnitKind)> {
    let members: BTreeSet<&str> = meta.workspace_members.iter().map(String::as_str).collect();
    let mut out = Vec::new();
    for p in meta
        .packages
        .iter()
        .filter(|p| members.contains(p.id.as_str()))
    {
        let Some(dir) = Utf8Path::new(&p.manifest_path).parent() else {
            continue;
        };
        let defaults = default_features(p);
        for t in &p.targets {
            if !t.required_features.iter().all(|f| defaults.contains(f)) {
                // `cargo test` skips it (its features are off by default).
                continue;
            }
            let is = |k: &str| t.kind.iter().any(|x| x == k);
            let lib_like = LIB_KINDS.iter().any(|k| is(k));
            if lib_like {
                if t.test {
                    out.push((dir.to_owned(), UnitKind::Lib));
                }
                if t.doctest {
                    out.push((dir.to_owned(), UnitKind::Doc));
                }
            } else if t.test {
                let k = if is("bin") {
                    UnitKind::Bin(t.name.clone())
                } else if is("test") {
                    UnitKind::Test(t.name.clone())
                } else if is("example") {
                    UnitKind::Example(t.name.clone())
                } else if is("bench") {
                    UnitKind::Bench(t.name.clone())
                } else {
                    continue;
                };
                out.push((dir.to_owned(), k));
            }
        }
    }
    out
}

/// One `libtest` summary line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Summary {
    ok: bool,
    passed: u32,
    failed: u32,
    ignored: u32,
    filtered: u32,
}

/// `test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; ...`
fn parse_summary(line: &str) -> Option<Summary> {
    let rest = line.trim().strip_prefix("test result: ")?;
    let (status, counts) = rest.split_once(". ")?;
    let mut s = Summary {
        ok: status == "ok",
        ..Default::default()
    };
    if status != "ok" && status != "FAILED" {
        return None;
    }
    let mut seen = 0;
    for part in counts.split(';') {
        let part = part.trim();
        let (n, what) = part.split_once(' ')?;
        let Ok(n) = n.parse::<u32>() else {
            continue;
        };
        match what {
            "passed" => s.passed = n,
            "failed" => s.failed = n,
            "ignored" => s.ignored = n,
            "filtered out" => s.filtered = n,
            _ => {}
        }
        seen += 1;
    }
    (seen >= 5).then_some(s)
}

/// The unit's result from its output and exit code. Only an explicit pass
/// with at least one test run, nothing failed and nothing filtered out is
/// `passed`; `#[ignore]`d tests are counted but do not prevent it (they are
/// fixed at compile time; see the README).
fn unit_result(stdout_text: &str, exit_ok: bool, duration_ms: u64) -> vci_core::TestResult {
    let sums: Vec<Summary> = stdout_text.lines().filter_map(parse_summary).collect();
    let passed: u32 = sums.iter().map(|s| s.passed).sum();
    let failed: u32 = sums.iter().map(|s| s.failed).sum();
    let ignored: u32 = sums.iter().map(|s| s.ignored).sum();
    let filtered: u32 = sums.iter().map(|s| s.filtered).sum();
    let state = if !exit_ok || failed > 0 || sums.iter().any(|s| !s.ok) {
        "failed"
    } else if sums.is_empty() || passed == 0 {
        // No libtest summary (a custom harness), or nothing ran.
        "no-tests"
    } else if filtered > 0 {
        "filtered"
    } else {
        "passed"
    };
    vci_core::TestResult {
        state: state.into(),
        tests: passed + failed + ignored,
        failed: if state == "failed" {
            failed.max(1)
        } else {
            failed
        },
        skipped: 0,
        duration_ms,
    }
}

/// A package as its package id spec describes it
/// (`path+file:///w/a#0.1.0`, `registry+https://...#hex@0.4.3`,
/// `git+https://...?branch=main#name@0.2.0`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PkgId {
    name: String,
    version: String,
    /// `None` for a path package; else the source URL as Cargo.lock spells
    /// it before any `#<commit>`.
    source: Option<String>,
}

fn parse_pkgid(id: &str) -> Option<PkgId> {
    let (url, frag) = id.rsplit_once('#')?;
    let (name, version) = match frag.split_once('@') {
        Some((n, v)) => (n.to_owned(), v.to_owned()),
        None => {
            let path = url.split('?').next().unwrap_or(url);
            (path.rsplit('/').next()?.to_owned(), frag.to_owned())
        }
    };
    if name.is_empty() || version.is_empty() {
        return None;
    }
    let source = if url.starts_with("path+") {
        None
    } else {
        Some(url.to_owned())
    };
    Some(PkgId {
        name,
        version,
        source,
    })
}

/// A `compiler-artifact` message.
#[derive(Debug, Clone)]
struct Artifact {
    package_id: String,
    manifest_path: Utf8PathBuf,
    kind: Vec<String>,
    filenames: Vec<Utf8PathBuf>,
    features: Vec<String>,
    /// Cargo reused it from an earlier build (its mtime-based fingerprint
    /// said so). Absent in the message: treated as reused.
    fresh: bool,
    /// `target.name`.
    target_name: String,
    /// `profile.test`: built as a test harness (`--test`).
    test_profile: bool,
    /// The executable (test harnesses and bins), if any.
    executable: Option<Utf8PathBuf>,
}

/// A `build-script-executed` message.
#[derive(Debug, Clone)]
struct BuildRun {
    package_id: String,
    linked_libs: Vec<String>,
    linked_paths: Vec<String>,
    out_dir: Utf8PathBuf,
    /// `cargo::rustc-env` variables (also set for the package's tests).
    env: Vec<(String, String)>,
}

/// Split cargo's stdout into JSON messages and everything else (the test
/// harness's output).
fn split_messages(stdout: &str) -> (Vec<Artifact>, Vec<BuildRun>, String) {
    let mut arts = Vec::new();
    let mut runs = Vec::new();
    let mut text = String::new();
    for line in stdout.lines() {
        let msg = line
            .starts_with('{')
            .then(|| serde_json::from_str::<Value>(line).ok())
            .flatten()
            .filter(|v| v.get("reason").is_some());
        let Some(v) = msg else {
            text.push_str(line);
            text.push('\n');
            continue;
        };
        let strs = |k: &str| -> Vec<String> {
            v.get(k)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let pid = v
            .get("package_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        match v.get("reason").and_then(Value::as_str) {
            Some("compiler-artifact") => arts.push(Artifact {
                package_id: pid,
                manifest_path: Utf8PathBuf::from(
                    v.get("manifest_path")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ),
                kind: v
                    .pointer("/target/kind")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
                filenames: strs("filenames")
                    .into_iter()
                    .map(Utf8PathBuf::from)
                    .collect(),
                features: strs("features"),
                fresh: v.get("fresh").and_then(Value::as_bool).unwrap_or(true),
                target_name: v
                    .pointer("/target/name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                test_profile: v
                    .pointer("/profile/test")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                executable: v
                    .get("executable")
                    .and_then(Value::as_str)
                    .map(Utf8PathBuf::from),
            }),
            Some("build-script-executed") => runs.push(BuildRun {
                package_id: pid,
                linked_libs: strs("linked_libs"),
                linked_paths: strs("linked_paths"),
                out_dir: Utf8PathBuf::from(
                    v.get("out_dir").and_then(Value::as_str).unwrap_or_default(),
                ),
                env: v
                    .get("env")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|kv| {
                                let kv = kv.as_array()?;
                                Some((
                                    kv.first()?.as_str()?.to_owned(),
                                    kv.get(1)?.as_str()?.to_owned(),
                                ))
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            }),
            _ => {}
        }
    }
    (arts, runs, text)
}

/// `<release> <commit-hash> LLVM <version>` from `rustc -vV` output.
fn rustc_id(vv: &str) -> Option<String> {
    let m: BTreeMap<&str, &str> = vv
        .lines()
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();
    let release = m.get("release").filter(|r| !r.is_empty())?;
    Some(format!(
        "{release} {} LLVM {}",
        m.get("commit-hash").copied().unwrap_or_default(),
        m.get("LLVM version").copied().unwrap_or_default()
    ))
}

/// The rustc cargo used for builds in `target_dir`, from the `rustc -vV`
/// output it caches in `.rustc_info.json` (rewritten whenever the rustc
/// binary changes). `None` when the cache is absent or unreadable
/// (`CARGO_CACHE_RUSTC_INFO=0`).
fn rustc_used(target_dir: &Utf8Path) -> Option<String> {
    let text = std::fs::read_to_string(target_dir.join(".rustc_info.json")).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    v.get("outputs")?
        .as_object()?
        .values()
        .filter_map(|o| o.get("stdout")?.as_str())
        .find(|out| out.contains("\nrelease: "))
        .and_then(rustc_id)
}

/// The sysroot of the rustc cargo used for builds in `target_dir`, from the
/// `--print=sysroot` output it caches in `.rustc_info.json`: the one
/// absolute line naming a directory with a `lib/rustlib`. `None` when the
/// cache is absent or unreadable, or names several.
fn rustc_sysroot(target_dir: &Utf8Path) -> Option<Utf8PathBuf> {
    let text = std::fs::read_to_string(target_dir.join(".rustc_info.json")).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let found: BTreeSet<Utf8PathBuf> = v
        .get("outputs")?
        .as_object()?
        .values()
        .filter_map(|o| o.get("stdout")?.as_str())
        .flat_map(str::lines)
        .map(Utf8Path::new)
        .filter(|p| p.is_absolute() && p.join("lib/rustlib").is_dir())
        .map(canonical)
        .collect();
    let mut it = found.into_iter();
    match (it.next(), it.next()) {
        (Some(s), None) => Some(s),
        _ => None,
    }
}

fn canonical(p: &Utf8Path) -> Utf8PathBuf {
    p.canonicalize_utf8().unwrap_or_else(|_| normalise(p))
}

/// `path` (inside `repo_root`) with every symlinked directory on the way
/// resolved: the symlinks met, in order, and the path through their targets.
/// Unchanged when a link leads outside the repository (the caller's checks
/// then apply to the path as spelled).
fn through_links(path: &Utf8Path, repo_root: &Utf8Path) -> (Vec<Utf8PathBuf>, Utf8PathBuf) {
    let mut links = Vec::new();
    let Ok(rel) = path.strip_prefix(repo_root) else {
        return (links, path.to_owned());
    };
    let comps: Vec<&str> = rel.components().map(|c| c.as_str()).collect();
    let mut cur = repo_root.to_owned();
    for (i, c) in comps.iter().enumerate() {
        cur.push(c);
        if i + 1 == comps.len() {
            break;
        }
        if std::fs::symlink_metadata(&cur).is_ok_and(|m| m.file_type().is_symlink()) {
            let target = canonical(&cur);
            if !target.starts_with(repo_root) {
                return (links, path.to_owned());
            }
            links.push(cur.clone());
            cur = target;
        }
    }
    (links, cur)
}

/// `$CARGO_HOME` (the child's variable, else `~/.cargo`), canonical, when it
/// lies inside `repo_root`; `None` otherwise.
fn cargo_home_inside(
    repo_root: &Utf8Path,
    var: &dyn Fn(&str) -> Option<String>,
) -> Option<Utf8PathBuf> {
    let home = var("CARGO_HOME")
        .filter(|v| !v.is_empty())
        .map(Utf8PathBuf::from)
        .or_else(|| var("HOME").map(|h| Utf8PathBuf::from(h).join(".cargo")))?;
    let home = canonical(&home);
    (home != *repo_root && home.starts_with(repo_root)).then_some(home)
}

/// The directory holding `.git` above (or at) `dir`; `dir` itself if none.
fn repo_root_of(dir: &Utf8Path) -> Utf8PathBuf {
    dir.ancestors()
        .find(|d| d.join(".git").exists())
        .unwrap_or(dir)
        .to_owned()
}

/// Every variable of the child environment.
fn child_vars(env: &ChildEnv) -> Vec<(String, String)> {
    match env {
        Some(vars) => vars
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .collect(),
        None => std::env::vars_os()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .collect(),
    }
}

/// Walks package directories: every file is a read, every directory a
/// listing. Build output and bookkeeping (`excluded`: the target dir, the
/// repository's `.git` and `.vci/out`) are recorded as excluded, not walked
/// and left out of their parent's listing. A symlink to a directory in the
/// repository is walked at its target (the link itself is recorded too, so
/// retargeting it is noticed); one that leaves the repository, a nested
/// `.git` directory (another repository, whose working tree state vci does
/// not track) and [`UNWALKED`] directories are problems.
struct Walker<'a> {
    repo_root: &'a Utf8Path,
    excluded: &'a [Utf8PathBuf],
    /// Canonical directories already walked (symlink cycles, a directory
    /// reached twice).
    visited: BTreeSet<Utf8PathBuf>,
}

impl<'a> Walker<'a> {
    fn new(repo_root: &'a Utf8Path, excluded: &'a [Utf8PathBuf]) -> Self {
        Self {
            repo_root,
            excluded,
            visited: BTreeSet::new(),
        }
    }

    fn walk(&mut self, dir: &Utf8Path, o: &mut Observed, problems: &mut BTreeSet<String>) {
        let mut stack = vec![dir.to_owned()];
        while let Some(d) = stack.pop() {
            if !self.visited.insert(canonical(&d)) {
                continue;
            }
            o.readdirs.insert(d.clone());
            // Present or not (a fresh checkout has no target/, a later
            // `vci ci` may create .vci/out), left out of this listing.
            for x in self.excluded {
                if x.parent() == Some(d.as_path()) {
                    o.excluded.insert(x.clone());
                }
            }
            let rd = match d.read_dir_utf8() {
                Ok(rd) => rd,
                Err(e) => {
                    problems.insert(format!("cargo: cannot list {d}: {e}"));
                    continue;
                }
            };
            for ent in rd.flatten() {
                let p = ent.path().to_owned();
                if self.excluded.contains(&p) {
                    o.excluded.insert(p);
                    continue;
                }
                let Ok(ft) = ent.file_type() else {
                    problems.insert(format!("cargo: cannot inspect {p}"));
                    continue;
                };
                if ft.is_dir() {
                    if ent.file_name() == ".git" {
                        problems.insert(format!(
                            "cargo: {p} is a git repository inside a package directory (its state is not an input vci can hash)"
                        ));
                        continue;
                    }
                    if UNWALKED.contains(&ent.file_name()) {
                        problems.insert(format!(
                            "cargo: {p} is in a package directory, and vci does not hash {} directories (a test could read it)",
                            ent.file_name()
                        ));
                        continue;
                    }
                    stack.push(p);
                    continue;
                }
                // Files, and symlinks (their chain and target are recorded).
                o.modules.insert(p.clone());
                if ft.is_symlink() && std::fs::metadata(&p).is_ok_and(|m| m.is_dir()) {
                    let target = canonical(&p);
                    if !target.starts_with(self.repo_root) {
                        problems.insert(format!(
                            "cargo: symlink {p} leads to {target}, a directory outside the repository"
                        ));
                    } else if self.excluded.iter().any(|x| target.starts_with(x)) {
                        problems.insert(format!(
                            "cargo: symlink {p} leads into build output ({target}), which is not an input"
                        ));
                    } else {
                        stack.push(target);
                    }
                }
            }
        }
    }
}

/// The adapter.
#[derive(Debug)]
pub struct CargoAdapter {
    project_dir: Utf8PathBuf,
    cargo: OsString,
    probe: OnceLock<Result<Probe, String>>,
    workspace: OnceLock<Result<Workspace, String>>,
}

impl CargoAdapter {
    /// `project_dir` must be absolute (it is canonicalised if possible). It
    /// is the workspace root (where `Cargo.lock` lives).
    pub fn new(project_dir: &Utf8Path) -> Self {
        let project_dir = project_dir
            .canonicalize_utf8()
            .unwrap_or_else(|_| project_dir.to_owned());
        let cargo = std::env::var_os(CARGO_BIN_ENV)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "cargo".into());
        Self {
            project_dir,
            cargo,
            probe: OnceLock::new(),
            workspace: OnceLock::new(),
        }
    }

    fn cmd(&self, program: &OsString, env: &ChildEnv) -> Command {
        let mut c = Command::new(program);
        c.current_dir(&self.project_dir).stdin(Stdio::null());
        apply_env(&mut c, env);
        c
    }

    fn cargo_cmd(&self, env: &ChildEnv) -> Command {
        self.cmd(&self.cargo, env)
    }

    fn not_installed(&self, what: &str, e: std::io::Error) -> AdapterError {
        if e.kind() == std::io::ErrorKind::NotFound {
            AdapterError::NotFound(format!(
                "`{what}` was not found: the cargo adapter needs the Rust toolchain (cargo and rustc) on PATH, or {CARGO_BIN_ENV} naming cargo"
            ))
        } else {
            AdapterError::Io(e)
        }
    }

    fn output(&self, cmd: &mut Command, what: &str) -> Result<std::process::Output, AdapterError> {
        let out = cmd.output().map_err(|e| self.not_installed(what, e))?;
        if !out.status.success() {
            return Err(AdapterError::Command {
                cmd: describe(cmd),
                status: out.status.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).trim_end().to_owned(),
            });
        }
        Ok(out)
    }

    /// The rustc cargo will use: `$RUSTC` when set, else the `rustc` next to
    /// the cargo binary (rustup's proxies and distribution packages install
    /// them side by side; a different `rustc` earlier on PATH is not what
    /// cargo runs), else `rustc` on PATH.
    fn rustc_for(&self, env: &ChildEnv) -> OsString {
        if let Some(r) = Self::child_var(env, "RUSTC") {
            return r.into();
        }
        let cargo = Utf8PathBuf::from(self.cargo.to_string_lossy().into_owned());
        let cargo_path = if cargo.components().count() > 1 {
            Some(cargo)
        } else {
            Self::child_var(env, "PATH").and_then(|path| {
                std::env::split_paths(&path)
                    .filter_map(|d| Utf8PathBuf::from_path_buf(d).ok())
                    .map(|d| d.join(&cargo))
                    .find(|p| p.is_file())
            })
        };
        cargo_path
            .and_then(|c| {
                let r = c.with_file_name(if c.extension() == Some("exe") {
                    "rustc.exe"
                } else {
                    "rustc"
                });
                r.is_file().then(|| OsString::from(r.as_str()))
            })
            .unwrap_or_else(|| "rustc".into())
    }

    /// A variable as the child sees it, empty values included.
    fn child_var_raw(env: &ChildEnv, k: &str) -> Option<String> {
        match env {
            Some(vars) => vars
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.to_string_lossy().into_owned()),
            None => std::env::var(k).ok(),
        }
    }

    /// A variable as the child sees it.
    fn child_var(env: &ChildEnv, k: &str) -> Option<String> {
        match env {
            Some(vars) => vars
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.to_string_lossy().into_owned()),
            None => std::env::var(k).ok(),
        }
        .filter(|v| !v.is_empty())
    }

    fn metadata(&self, env: &ChildEnv) -> Result<Metadata, AdapterError> {
        let mut cmd = self.cargo_cmd(env);
        // The members only (`--no-deps`): no dependency is resolved, so
        // nothing needs the network (`--offline`).
        cmd.args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--no-deps",
            "--offline",
        ]);
        let out = self.output(&mut cmd, "cargo")?;
        serde_json::from_slice(&out.stdout).map_err(|e| AdapterError::Parse {
            what: "cargo metadata".into(),
            detail: e.to_string(),
        })
    }

    fn workspace(&self, env: &ChildEnv) -> Result<Workspace, AdapterError> {
        self.workspace
            .get_or_init(|| self.load_workspace(env).map_err(|e| e.to_string()))
            .clone()
            .map_err(|e| AdapterError::Parse {
                what: "cargo workspace".into(),
                detail: e,
            })
    }

    fn load_workspace(&self, env: &ChildEnv) -> Result<Workspace, AdapterError> {
        let meta = self.metadata(env)?;
        let root = canonical(Utf8Path::new(&meta.workspace_root));
        if root != self.project_dir {
            return Err(AdapterError::Parse {
                what: "cargo metadata".into(),
                detail: format!(
                    "the project dir {} is not the workspace root ({root}); set `project` to the directory holding the workspace's Cargo.toml and Cargo.lock",
                    self.project_dir
                ),
            });
        }
        if !root.join("Cargo.lock").is_file() {
            return Err(AdapterError::NotFound(format!(
                "{root}/Cargo.lock is missing: the cargo adapter needs a committed Cargo.lock (tests run with --locked)"
            )));
        }
        let target_dir = canonical(Utf8Path::new(&meta.target_directory));
        Ok(Workspace {
            meta,
            root,
            target_dir,
        })
    }

    fn probe(&self, env: &ChildEnv) -> Result<Probe, AdapterError> {
        self.probe
            .get_or_init(|| self.run_probe(env).map_err(|e| e.to_string()))
            .clone()
            .map_err(|e| AdapterError::Parse {
                what: "rust toolchain".into(),
                detail: e,
            })
    }

    fn run_probe(&self, env: &ChildEnv) -> Result<Probe, AdapterError> {
        let kv = |text: &str| -> BTreeMap<String, String> {
            text.lines()
                .filter_map(|l| l.split_once(": "))
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
                .collect()
        };
        let mut c = self.cargo_cmd(env);
        c.arg("-vV");
        let cargo_v = kv(&String::from_utf8_lossy(
            &self.output(&mut c, "cargo")?.stdout,
        ));
        let rustc = self.rustc_for(env);
        let mut c = self.cmd(&rustc, env);
        c.arg("-vV");
        let rustc_out = String::from_utf8_lossy(&self.output(&mut c, "rustc")?.stdout).into_owned();
        let rustc_v = kv(&rustc_out);
        let runner = rustc_id(&rustc_out);
        let get = |m: &BTreeMap<String, String>, k: &str| m.get(k).cloned().unwrap_or_default();
        if get(&rustc_v, "release").is_empty() || get(&rustc_v, "host").is_empty() {
            return Err(AdapterError::Parse {
                what: "rustc -vV".into(),
                detail: format!("no release/host in {rustc_v:?}"),
            });
        }
        if let Some(t) = Self::child_var(env, "CARGO_BUILD_TARGET") {
            return Err(AdapterError::NotFound(format!(
                "CARGO_BUILD_TARGET={t}: cross-compiled test runs are not supported by the cargo adapter"
            )));
        }
        // The flags cargo passes to rustc change the cfg set (target
        // features, --cfg): from the environment, else the config files'
        // target tables (a `cfg(..)` table matched against the plain cfg
        // set), else `build.rustflags`.
        let print_cfg = |flags: &[String]| -> Result<Vec<String>, AdapterError> {
            let mut c = self.cmd(&rustc, env);
            c.args(["--print", "cfg"]).args(flags);
            let mut v: Vec<String> = String::from_utf8_lossy(&self.output(&mut c, "rustc")?.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect();
            v.sort();
            Ok(v)
        };
        let plain = print_cfg(&[])?;
        // Unfiltered: an empty RUSTFLAGS is set (no flags), which cargo lets
        // override the config's.
        let var = |k: &str| Self::child_var_raw(env, k);
        let flags = config::effective_rustflags(
            &var,
            &self.config_files(env),
            &get(&rustc_v, "host"),
            &plain,
        );
        let rust_cfg = if flags.is_empty() {
            plain
        } else {
            print_cfg(&flags)?
        };
        let rustflags = flags;
        let mut c = self.cmd(&rustc, env);
        c.args(["--print", "sysroot"]);
        let sysroot = canonical(Utf8Path::new(
            String::from_utf8_lossy(&self.output(&mut c, "rustc")?.stdout).trim(),
        ));
        let problems = self.config_problems(env);
        if !problems.is_empty() {
            return Err(AdapterError::NotFound(problems.join("; ")));
        }
        Ok(Probe {
            versions: ToolVersions {
                runner: runner.unwrap_or_default(),
                cargo: format!(
                    "{} {}",
                    get(&cargo_v, "release"),
                    get(&cargo_v, "commit-hash")
                ),
                rust_host: get(&rustc_v, "host"),
                rust_cfg,
                ..Default::default()
            },
            sysroot,
            rustflags,
        })
    }

    /// The cargo config files cargo reads for builds started in the project
    /// dir, highest precedence first: `.cargo/config.toml` and `.cargo/config`
    /// from the project dir up to the filesystem root, then
    /// `$CARGO_HOME/config.toml` (and `config`). Each with whether it is
    /// inside the repository.
    fn config_files(&self, env: &ChildEnv) -> Vec<config::ConfigFile> {
        let repo = repo_root_of(&self.project_dir);
        let mut files: Vec<(Utf8PathBuf, bool)> = Vec::new();
        for d in self.project_dir.ancestors() {
            let inside = d.starts_with(&repo);
            for n in [".cargo/config.toml", ".cargo/config"] {
                files.push((d.join(n), inside));
            }
        }
        let home = Self::child_var(env, "CARGO_HOME")
            .map(Utf8PathBuf::from)
            .or_else(|| Self::child_var(env, "HOME").map(|h| Utf8PathBuf::from(h).join(".cargo")));
        if let Some(h) = home {
            for n in ["config.toml", "config"] {
                files.push((h.join(n), false));
            }
        }
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for (f, inside) in files {
            if !f.is_file() || !seen.insert(canonical(&f)) {
                continue;
            }
            let table = std::fs::read_to_string(&f)
                .map_err(|e| e.to_string())
                .and_then(|t| toml::from_str::<toml::Table>(&t).map_err(|e| e.to_string()));
            out.push(config::ConfigFile {
                path: f,
                inside,
                table,
            });
        }
        out
    }

    /// Cargo config files that change the build but cannot be hashed (outside
    /// the repository), or that make vci's toolchain probe wrong.
    fn config_problems(&self, env: &ChildEnv) -> Vec<String> {
        let mut out = Vec::new();
        for c in self.config_files(env) {
            let f = &c.path;
            let table = match &c.table {
                Ok(t) => t,
                Err(e) => {
                    out.push(format!("cargo config {f} cannot be read: {e}"));
                    continue;
                }
            };
            let build = table.get("build").and_then(toml::Value::as_table);
            if c.inside {
                // Hashed as a global input; only settings that make vci's
                // probe or the unit model wrong are refused here (the rest of
                // what is not the same everywhere: `config::repo_facts`).
                for k in ["rustc", "rustdoc", "target"] {
                    if build.is_some_and(|b| b.contains_key(k)) {
                        out.push(format!(
                            "cargo config {f} sets build.{k}, which the cargo adapter does not support (vci compares the rustc on PATH and runs tests for the host)"
                        ));
                    }
                }
                continue;
            }
            for (k, v) in table {
                if HARMLESS_CONFIG_KEYS.contains(&k.as_str()) {
                    continue;
                }
                if k == "build"
                    && let Some(b) = v.as_table()
                {
                    for bk in b.keys() {
                        if !HARMLESS_BUILD_KEYS.contains(&bk.as_str()) {
                            out.push(format!(
                                "cargo config {f} (outside the repository, not hashed) sets build.{bk}, which changes what is built; move it into the repository's .cargo/config.toml or remove it"
                            ));
                        }
                    }
                    continue;
                }
                out.push(format!(
                    "cargo config {f} (outside the repository, not hashed) sets [{k}], which can change what is built; move it into the repository's .cargo/config.toml or remove it"
                ));
            }
        }
        out
    }

    fn lock(&self) -> Result<Vec<Locked>, String> {
        let p = self.project_dir.join("Cargo.lock");
        let text = std::fs::read_to_string(&p).map_err(|e| format!("reading {p}: {e}"))?;
        parse_lock(&text).map_err(|e| format!("parsing {p}: {e}"))
    }

    fn vci_target_dir(&self, env: &ChildEnv) -> Result<Utf8PathBuf, AdapterError> {
        Ok(self.workspace(env)?.target_dir.join(VCI_TARGET_SUBDIR))
    }

    /// `cargo clean -p <name>@<version>...` in vci's target dir: the next
    /// build of these packages starts from their sources. Cargo decides
    /// whether an artifact is fresh by file modification times and by the
    /// inputs a build script declares, while vci hashes contents (a file
    /// restored with an older mtime, a build script reading a file or a
    /// variable it does not declare, a proc macro reading a variable), so
    /// the repository's crates are never reused from a build made before this
    /// `vci run`. External crates stay cached (their sources are verified
    /// against Cargo.lock instead).
    fn clean(
        &self,
        pkgs: &BTreeSet<(String, String)>,
        env: &ChildEnv,
        ctx: &RunCtx,
    ) -> Result<Vec<u8>, AdapterError> {
        if pkgs.is_empty() {
            return Ok(vec![]);
        }
        let mut cmd = self.cargo_cmd(env);
        cmd.args(["clean", "--locked", "--target-dir"])
            .arg(ctx.target_dir.as_str());
        // By name: cargo ignores a version qualifier here and cleans every
        // version of the name (an external crate of the same name is only
        // rebuilt).
        let names: BTreeSet<&str> = pkgs.iter().map(|(n, _)| n.as_str()).collect();
        for n in names {
            cmd.arg("-p").arg(n);
        }
        let out = self.output(&mut cmd, "cargo")?;
        lock(&ctx.cleaned).extend(pkgs.iter().cloned());
        let mut block = format!("vci: {}\n", describe(&cmd)).into_bytes();
        block.extend_from_slice(&out.stderr);
        Ok(block)
    }

    /// What every unit of a run shares: the toolchain probe, the workspace,
    /// Cargo.lock, the repository's cargo config, the caches.
    fn run_ctx(&self, env: &ChildEnv) -> Result<RunCtx, AdapterError> {
        let probe = self.probe(env)?;
        let ws = self.workspace(env)?;
        let lock = self.lock().map_err(|e| AdapterError::Parse {
            what: "Cargo.lock".into(),
            detail: e,
        })?;
        let repo_root = canonical(&repo_root_of(&self.project_dir));
        let cfg_files = self.config_files(env);
        let mut config = config::repo_facts(&cfg_files);
        let var = |k: &str| Self::child_var(env, k);
        config
            .taints
            .extend(config::wrapper_problems(&var, &cfg_files));
        // `-C linker=<program>` in the flags: a program vci does not hash.
        if let Some(f) = probe.rustflags.iter().find(|f| f.contains("linker=")) {
            config.taints.insert(format!(
                "cargo:config: the rustflags set {f:?}, a linker that is not an input vci hashes (custom linkers are not supported)"
            ));
        }
        for (k, _) in child_vars(env) {
            if k.starts_with("CARGO_TARGET_") && (k.ends_with("_RUNNER") || k.ends_with("_LINKER"))
            {
                config.taints.insert(format!(
                    "cargo:config: ${k} names a program that is not an input vci hashes (custom test runners and linkers are not supported)"
                ));
            }
        }
        let member_ids: BTreeSet<&str> = ws
            .meta
            .workspace_members
            .iter()
            .map(String::as_str)
            .collect();
        let members: BTreeMap<Utf8PathBuf, usize> = ws
            .meta
            .packages
            .iter()
            .enumerate()
            .filter(|(_, p)| member_ids.contains(p.id.as_str()))
            .filter_map(|(i, p)| Some((canonical(Utf8Path::new(&p.manifest_path).parent()?), i)))
            .collect();
        let raw = |k: &str| Self::child_var_raw(env, k);
        let cargo_exe = exec::cargo_exe(&self.cargo, &probe.sysroot, &raw);
        let proxy_env = if cargo_exe.1 {
            exec::proxy_env(self.cargo_cmd(env), raw("PATH"))
        } else {
            vec![]
        };
        let cargo_home = cargo_home_inside(&repo_root, &raw);
        let mut excluded = vec![
            ws.target_dir.clone(),
            repo_root.join(".git"),
            repo_root.join(".vci/out"),
        ];
        excluded.extend(cargo_home.clone());
        Ok(RunCtx {
            target_dir: ws.target_dir.join(VCI_TARGET_SUBDIR),
            excluded,
            cargo_home,
            repo_root,
            config,
            config_env: exec::config_env(&cfg_files),
            cargo_exe,
            proxy_env,
            members,
            cleaned: Mutex::new(BTreeSet::new()),
            caches: Caches::default(),
            probe,
            lock,
            ws,
        })
    }

    /// `cargo test --locked --manifest-path <pkg>/Cargo.toml <target>` for
    /// each unit, one at a time; without units, `cargo test --locked
    /// --workspace`. Output goes to stderr.
    fn run_plain_serial(
        &self,
        files: &[String],
        env: &ChildEnv,
    ) -> Result<Option<i32>, AdapterError> {
        let target = self.vci_target_dir(env)?;
        let mut invocations: Vec<Vec<String>> = Vec::new();
        if files.is_empty() {
            invocations.push(vec!["test".into(), "--locked".into(), "--workspace".into()]);
        } else {
            for f in files {
                let argv = self.canonical_argv("", f);
                if parse_unit(f).is_none() {
                    return Err(AdapterError::NotFound(format!("{f:?} is not a cargo unit")));
                }
                invocations.push(argv[1..].to_vec());
            }
        }
        let mut codes = Vec::new();
        for args in invocations {
            let tmp = tempfile::Builder::new().prefix("vci-cargotmp-").tempdir()?;
            let mut cmd = self.cargo_cmd(env);
            cmd.args(&args)
                .arg("--target-dir")
                .arg(target.as_str())
                .env("TMPDIR", tmp.path())
                .stdout(std::io::stderr())
                .stderr(std::io::stderr());
            let _ = writeln!(std::io::stderr(), "vci: {}", describe(&cmd));
            codes.push(
                cmd.status()
                    .map_err(|e| self.not_installed("cargo", e))?
                    .code(),
            );
        }
        Ok(fold_exit(codes))
    }

    /// Artifacts of crates inside the repository that cargo reused (fresh)
    /// although vci has not built them since it cleaned them in this run:
    /// (name, version) of each.
    fn reused_repo_packages(&self, arts: &[Artifact], ctx: &RunCtx) -> BTreeSet<(String, String)> {
        let cleaned = lock(&ctx.cleaned).clone();
        arts.iter()
            .filter(|a| a.fresh)
            .filter(|a| {
                a.manifest_path
                    .parent()
                    .is_some_and(|d| ctx.in_repo(&ctx.canon(d)))
            })
            .filter_map(|a| parse_pkgid(&a.package_id))
            .map(|p| (p.name, p.version))
            .filter(|k| !cleaned.contains(k))
            .collect()
    }

    /// Everything the unit's build reports -> inputs, externals, taints.
    /// Runs in the execution pool's threads: what does not depend on the
    /// unit (package directory walks, dep-info, source and manifest scans,
    /// external source checks) comes from the run-wide caches in `ctx`.
    fn analyse(&self, o: &mut Observed, arts: &[Artifact], runs: &[BuildRun], ctx: &RunCtx) {
        let mut problems: BTreeSet<String> = BTreeSet::new();
        if arts.is_empty() {
            problems.insert("cargo: the build reported no artifacts".into());
        }
        for (n, v) in self.reused_repo_packages(arts, ctx) {
            problems.insert(format!(
                "cargo: {n}@{v} (in the repository) was reused from a build vci did not make in this run, so it may not match its sources"
            ));
        }
        let target_dir = ctx.ws.target_dir.as_path();
        let mut ids: BTreeSet<&str> = arts.iter().map(|a| a.package_id.as_str()).collect();
        ids.extend(runs.iter().map(|r| r.package_id.as_str()));
        let mut in_repo: BTreeMap<&str, Utf8PathBuf> = BTreeMap::new();
        let mut external_dirs: Vec<Utf8PathBuf> = Vec::new();
        let mut vendored: Vec<Utf8PathBuf> = Vec::new();
        for id in &ids {
            let Some(p) = parse_pkgid(id) else {
                problems.insert(format!("cargo: cannot read package id {id}"));
                continue;
            };
            let Some(manifest) = arts
                .iter()
                .find(|a| a.package_id == *id && !a.manifest_path.as_str().is_empty())
                .map(|a| a.manifest_path.clone())
            else {
                problems.insert(format!("cargo: no manifest path for package {id}"));
                continue;
            };
            let dir = ctx.canon(manifest.parent().unwrap_or(Utf8Path::new("/")));
            match &p.source {
                None => {
                    if ctx.in_repo(&dir) {
                        in_repo.insert(id, dir);
                    } else {
                        problems.insert(format!(
                            "cargo: path dependency {} at {dir} is outside the repository",
                            p.name
                        ));
                    }
                }
                Some(src) => {
                    // Cargo.lock spells a git source with `#<commit>`.
                    let locked = ctx.lock.iter().find(|l| {
                        l.name == p.name
                            && l.version == p.version
                            && l.source.split('#').next()
                                == Some(src.split('#').next().unwrap_or(src))
                    });
                    if src.starts_with("git+") && !locked.is_some_and(|l| l.source.contains('#')) {
                        problems.insert(format!(
                            "cargo: git dependency {} has no locked revision ({src})",
                            p.name
                        ));
                    }
                    match locked {
                        Some(l) => {
                            o.externals.insert((
                                p.name.clone(),
                                external_id(&l.version, &l.source, &l.checksum),
                            ));
                        }
                        None => {
                            problems.insert(format!(
                                "cargo: {} {} ({src}) is not pinned in Cargo.lock",
                                p.name, p.version
                            ));
                        }
                    }
                    let feats: BTreeSet<&str> = arts
                        .iter()
                        .filter(|a| a.package_id == **id)
                        .flat_map(|a| a.features.iter().map(String::as_str))
                        .collect();
                    if NET_PROCESS_CRATES.contains(&p.name.as_str()) {
                        problems.insert(format!(
                            "cargo:crate: the unit builds {} (network I/O or child processes are not observed)",
                            p.name
                        ));
                    }
                    for (name, bad) in FEATURE_GATED {
                        if p.name == *name
                            && let Some(f) = bad.iter().find(|f| feats.contains(*f))
                        {
                            problems.insert(format!(
                                "cargo:crate: the unit builds {} with feature {f:?} (network I/O or child processes are not observed)",
                                p.name
                            ));
                        }
                    }
                    if ctx.in_repo(&dir) {
                        // Vendored into the repository (source replacement):
                        // its files are hashed, since the Cargo.lock
                        // checksum does not cover edits there.
                        vendored.push(dir.clone());
                    } else if let Some(l) = locked {
                        // In $CARGO_HOME: what cargo compiles must be what
                        // Cargo.lock pins (an extracted crate or a checkout
                        // edited in place is not noticed by cargo).
                        let verdict = ctx.verified(&dir, || {
                            if src.starts_with("git+") {
                                sources::verify_git(&dir, &p.name, &l.source)
                            } else if src.starts_with("registry+") || src.starts_with("sparse+") {
                                sources::verify_registry(&dir, &p.name, &p.version, &l.checksum)
                            } else {
                                Err(format!(
                                    "{} {}: source {src} cannot be verified against Cargo.lock",
                                    p.name, p.version
                                ))
                            }
                        });
                        if let Err(e) = verdict {
                            problems.insert(format!("cargo:source: {e}"));
                        }
                    }
                    external_dirs.push(dir);
                }
            }
        }
        // Package directories of the repository's crates: every file and
        // listing. A nested package inside another's directory is included
        // in both (harmless).
        let mut findings = scan::Findings::default();
        for dir in &vendored {
            ctx.walk(dir).merge_into(o, &mut problems);
        }
        for dir in in_repo.values() {
            ctx.walk(dir).merge_into(o, &mut problems);
            let manifest = dir.join("Cargo.toml");
            match &*ctx.manifest_scan(&manifest) {
                Ok(f) => merge_findings(&mut findings, f),
                Err(e) => {
                    problems.insert(e.clone());
                }
            }
        }
        // Dep-info of every artifact built from the repository: every file
        // rustc read for it. Files in the repository are inputs; all of them
        // (sources, `include!`d code of any extension, `#[doc =
        // include_str!("../README.md")]` doctests, data) and the code build
        // scripts generate into OUT_DIR are scanned with the roles of the
        // crate that includes them.
        let mut roles: BTreeMap<Utf8PathBuf, (scan::Roles, Utf8PathBuf)> = BTreeMap::new();
        for a in arts {
            let Some(pkg) = in_repo.get(a.package_id.as_str()) else {
                continue;
            };
            let Some(d) = depinfo::dep_info_for(&a.filenames) else {
                problems.insert(format!(
                    "cargo: no dep-info file for {} (artifacts {:?})",
                    a.package_id, a.filenames
                ));
                continue;
            };
            let info = ctx.dep_info(&d);
            let info = match &*info {
                Ok(i) => i,
                Err(e) => {
                    problems.insert(e.clone());
                    continue;
                }
            };
            for k in &info.env {
                if !scan::is_cargo_set_env(k) {
                    o.env_keys.insert(k.clone());
                }
            }
            let is = |k: &str| a.kind.iter().any(|x| x == k);
            for f in &info.files {
                let f = normalise(f);
                if f.starts_with(&ctx.probe.sysroot) {
                    continue;
                }
                let generated = f.starts_with(target_dir) || ctx.canon(&f).starts_with(target_dir);
                if !generated && !ctx.in_repo(&f) {
                    let real = ctx.canon(&f);
                    if real.starts_with(&ctx.probe.sysroot)
                        || external_dirs.iter().any(|e| real.starts_with(e))
                    {
                        continue;
                    }
                    problems.insert(format!(
                        "cargo: compile-time input outside the repository: {f}"
                    ));
                    continue;
                }
                if !generated {
                    // Reached through a symlinked directory (`jj/cli/docs ->
                    // ../docs`): the links and the file at its real path are
                    // the inputs, not the spelling through the link (which
                    // the pre-run snapshot does not hold).
                    let (links, real) = through_links(&f, &ctx.repo_root);
                    o.modules.extend(links);
                    o.modules.insert(real);
                }
                let e = roles
                    .entry(f)
                    .or_insert_with(|| (scan::Roles::default(), pkg.clone()));
                if is("custom-build") {
                    e.0.build_script = true;
                } else if is("proc-macro") {
                    e.0.proc_macro = true;
                } else {
                    e.0.runtime = true;
                }
            }
        }
        let mut scanned_from: BTreeMap<Utf8PathBuf, Utf8PathBuf> = BTreeMap::new();
        for (f, (r, pkg)) in &roles {
            // Generated code (OUT_DIR) can be rewritten when a package is
            // rebuilt during the run: scanned every time.
            let cacheable = !f.starts_with(target_dir);
            match &*ctx.source_scan(f, *r, pkg, cacheable) {
                Err(e) => {
                    problems.insert(e.clone());
                    continue;
                }
                // Not UTF-8: only `include_bytes!` can have read it (data).
                Ok(None) => continue,
                Ok(Some(found)) => merge_findings(&mut findings, found),
            }
            scanned_from.insert(f.clone(), pkg.clone());
        }
        // Build scripts: declared inputs, and native libraries.
        for r in runs {
            let output = r
                .out_dir
                .parent()
                .map(|d| d.join("output"))
                .unwrap_or_default();
            let decl = match std::fs::read_to_string(&output) {
                Ok(t) => depinfo::parse_build_output(&t),
                Err(e) => {
                    problems.insert(format!("cargo: reading build script output {output}: {e}"));
                    continue;
                }
            };
            for k in decl.rerun_if_env_changed {
                if !scan::is_cargo_set_env(&k) {
                    o.env_keys.insert(k);
                }
            }
            if let Some(pkg) = in_repo.get(r.package_id.as_str()) {
                for p in decl.rerun_if_changed {
                    let abs = normalise(&pkg.join(&p));
                    if abs.starts_with(target_dir) {
                        continue;
                    }
                    if !ctx.in_repo(&abs) {
                        problems.insert(format!(
                            "cargo: build script of {} declares an input outside the repository: {abs}",
                            pkg
                        ));
                        continue;
                    }
                    match std::fs::symlink_metadata(&abs) {
                        Ok(m) if m.is_dir() => ctx.walk(&abs).merge_into(o, &mut problems),
                        Ok(_) => {
                            o.modules.insert(abs);
                        }
                        Err(_) => {
                            o.probes.insert(abs);
                        }
                    }
                }
            }
            if !r.linked_libs.is_empty() {
                let outside: Vec<&str> = r
                    .linked_paths
                    .iter()
                    .map(|p| p.split_once('=').map_or(p.as_str(), |(_, v)| v))
                    .filter(|p| !ctx.canon(Utf8Path::new(p)).starts_with(target_dir))
                    .collect();
                if r.linked_paths.is_empty() || !outside.is_empty() {
                    problems.insert(format!(
                        "cargo:native-lib: {} links {} from outside the build ({}): system libraries are not hashed",
                        r.package_id,
                        r.linked_libs.join(", "),
                        if outside.is_empty() {
                            "the system search path".to_owned()
                        } else {
                            outside.join(", ")
                        }
                    ));
                }
            }
        }
        // Paths the source names inside a package directory must name the
        // file in its exact letter case (macOS opens `Data/B.json` for
        // `data/b.json`; Linux does not).
        for (p, seen) in findings.local_refs.iter().chain(findings.path_refs.iter()) {
            if let Some(actual) = case_mismatch(&ctx.repo_root, p) {
                problems.insert(format!(
                    "cargo:path-case: {seen} names {p}, but the file on disk is {actual}: this filesystem ignores letter case, and Linux's does not"
                ));
            }
        }
        // Repository config that does not apply the same everywhere, and
        // programs around rustc vci does not hash.
        problems.extend(ctx.config.taints.iter().cloned());
        findings
            .cfg_predicates
            .extend(ctx.config.cfg_predicates.iter().cloned());
        findings
            .platform_files
            .extend(ctx.config.platform_files.iter().cloned());
        // Generated code (OUT_DIR) is not in the repository: its platform
        // dependence is recorded on its package's manifest.
        let platform_files: BTreeSet<Utf8PathBuf> = findings
            .platform_files
            .into_iter()
            .map(|f| {
                if ctx.in_repo(&f) {
                    f
                } else {
                    scanned_from
                        .get(&f)
                        .map_or(f.clone(), |pkg| pkg.join("Cargo.toml"))
                }
            })
            .collect();
        // Repository paths in messages are shown relative to the root.
        let prefix = format!("{}/", ctx.repo_root);
        o.taints.extend(
            findings
                .taints
                .into_iter()
                .chain(problems)
                .map(|t| t.replace(&prefix, "")),
        );
        o.env_keys.extend(findings.env_names);
        o.env_keys.retain(|k| !scan::is_cargo_set_env(k));
        o.cfg_predicates = findings.cfg_predicates;
        o.platform_files = platform_files;
        o.path_refs = findings.path_refs;
    }
}

/// Add one file's (or manifest's) findings to a unit's, as scanning it into
/// the unit's findings would have: sets are joined, and a path already
/// recorded keeps where it was seen first (files are merged in path order).
fn merge_findings(into: &mut scan::Findings, from: &scan::Findings) {
    into.taints.extend(from.taints.iter().cloned());
    into.env_names.extend(from.env_names.iter().cloned());
    into.cfg_predicates
        .extend(from.cfg_predicates.iter().cloned());
    into.platform_files
        .extend(from.platform_files.iter().cloned());
    for (k, v) in &from.path_refs {
        into.path_refs.entry(k.clone()).or_insert_with(|| v.clone());
    }
    for (k, v) in &from.local_refs {
        into.local_refs
            .entry(k.clone())
            .or_insert_with(|| v.clone());
    }
}

/// The run's exit code from the units': `None` when one was killed by a
/// signal, else the first non-zero one.
fn fold_exit(codes: impl IntoIterator<Item = Option<i32>>) -> Option<i32> {
    let mut exit = Some(0);
    for code in codes {
        match code {
            Some(0) => {}
            None => exit = None,
            Some(c) => {
                if exit == Some(0) {
                    exit = Some(c);
                }
            }
        }
    }
    exit
}

/// When `path` (inside `repo_root`) does not exist with exactly these
/// letters but a case-insensitive filesystem finds it anyway, the path as it
/// is on disk.
fn case_mismatch(repo_root: &Utf8Path, path: &Utf8Path) -> Option<Utf8PathBuf> {
    let rel = path.strip_prefix(repo_root).ok()?;
    let mut dir = repo_root.to_owned();
    let mut wrong = false;
    for c in rel.components() {
        let name = c.as_str();
        let entries: Vec<String> = dir
            .read_dir_utf8()
            .ok()?
            .flatten()
            .map(|e| e.file_name().to_owned())
            .collect();
        if entries.iter().any(|e| e == name) {
            dir.push(name);
            continue;
        }
        let folded = name.to_lowercase();
        let actual = entries.into_iter().find(|e| e.to_lowercase() == folded)?;
        wrong = true;
        dir.push(actual);
    }
    wrong.then_some(dir)
}

/// Lock a mutex, also after a thread panicked holding it (the data is
/// caches and sets that stay consistent).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What walking one directory recorded ([`Walker`] from that directory
/// alone).
#[derive(Debug, Default)]
struct Walked {
    o: Observed,
    problems: BTreeSet<String>,
}

impl Walked {
    /// Add the walk to a unit's observations. A unit that walks several
    /// directories records the union of their walks: the paths a walk
    /// records are canonical below its start, so a directory reached by two
    /// walks is recorded the same way by both.
    fn merge_into(&self, o: &mut Observed, problems: &mut BTreeSet<String>) {
        o.readdirs.extend(self.o.readdirs.iter().cloned());
        o.excluded.extend(self.o.excluded.iter().cloned());
        o.modules.extend(self.o.modules.iter().cloned());
        problems.extend(self.problems.iter().cloned());
    }
}

/// A scan of one source file: its findings, `None` when it is not UTF-8
/// (data), or why it could not be read.
type SourceScan = Result<Option<scan::Findings>, String>;

/// A run-wide memo: each key's value is computed once, by the first thread
/// that asks for it (others asking meanwhile wait for that value).
struct Memo<K, V>(Mutex<HashMap<K, Arc<OnceLock<V>>>>);

impl<K, V> Default for Memo<K, V> {
    fn default() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl<K: Eq + Hash, V: Clone> Memo<K, V> {
    /// The value of `key`, computed with `f` if nobody has yet.
    fn get<Q>(&self, key: &Q, f: impl FnOnce() -> V) -> V
    where
        K: Borrow<Q>,
        Q: ?Sized + Eq + Hash + ToOwned<Owned = K>,
    {
        let cell = {
            let mut m = lock(&self.0);
            match m.get(key) {
                Some(c) => c.clone(),
                None => {
                    let c = Arc::new(OnceLock::new());
                    m.insert(key.to_owned(), c.clone());
                    c
                }
            }
        };
        cell.get_or_init(f).clone()
    }
}

/// Run-wide caches of what does not depend on the unit. Repository files do
/// not change during a run (`vci run` refuses the run when they do), so
/// each is read, walked and scanned once.
#[derive(Default)]
struct Caches {
    canonical: Memo<Utf8PathBuf, Utf8PathBuf>,
    walks: Memo<Utf8PathBuf, Arc<Walked>>,
    dep_info: Memo<Utf8PathBuf, Arc<Result<depinfo::DepInfo, String>>>,
    sources: Memo<(Utf8PathBuf, scan::Roles, Utf8PathBuf), Arc<SourceScan>>,
    manifests: Memo<Utf8PathBuf, Arc<Result<scan::Findings, String>>>,
    /// External source directories checked against Cargo.lock.
    verified: Memo<Utf8PathBuf, Result<(), String>>,
}

/// Per-run context shared by the units (and the threads of the execution
/// pool).
struct RunCtx {
    probe: Probe,
    ws: Workspace,
    lock: Vec<Locked>,
    repo_root: Utf8PathBuf,
    target_dir: Utf8PathBuf,
    /// Never inputs (and left out of listings): the workspace target dir,
    /// the repository's `.git` and `.vci/out`, and `cargo_home`.
    excluded: Vec<Utf8PathBuf>,
    /// `$CARGO_HOME` when it lies inside the repository (CI mounting it under
    /// the checkout): the registry's extracted crates and git checkouts
    /// there are external packages, not the repository's, and never inputs.
    cargo_home: Option<Utf8PathBuf>,
    /// The repository's cargo config and rustc wrappers, for every unit.
    config: config::ConfigFacts,
    /// The `[env]` table of the cargo configuration (test processes get it).
    config_env: Vec<exec::ConfigEnv>,
    /// `CARGO` for test processes, and whether cargo is rustup's proxy.
    cargo_exe: (String, bool),
    /// What rustup's proxy sets for cargo (see [`exec::proxy_env`]), for
    /// test processes; empty when cargo is not the proxy.
    proxy_env: Vec<(String, String)>,
    /// Workspace members by canonical package directory (index into
    /// `ws.meta.packages`).
    members: BTreeMap<Utf8PathBuf, usize>,
    /// Packages of the repository cleaned from `target_dir` in this run, as
    /// (name, version): every artifact of theirs was built in this run.
    cleaned: Mutex<BTreeSet<(String, String)>>,
    caches: Caches,
}

impl RunCtx {
    /// [`canonical`], once per path.
    fn canon(&self, p: &Utf8Path) -> Utf8PathBuf {
        self.caches.canonical.get(p, || canonical(p))
    }

    /// Whether `p` is part of the repository: under its root and not under a
    /// `$CARGO_HOME` kept there.
    fn in_repo(&self, p: &Utf8Path) -> bool {
        p.starts_with(&self.repo_root)
            && !self.cargo_home.as_ref().is_some_and(|h| p.starts_with(h))
    }

    /// The walk of `dir` (see [`Walker`]), once per directory.
    fn walk(&self, dir: &Utf8Path) -> Arc<Walked> {
        self.caches.walks.get(dir, || {
            let mut w = Walked::default();
            Walker::new(&self.repo_root, &self.excluded).walk(dir, &mut w.o, &mut w.problems);
            Arc::new(w)
        })
    }

    /// The dep-info file `d`, parsed once.
    fn dep_info(&self, d: &Utf8Path) -> Arc<Result<depinfo::DepInfo, String>> {
        self.caches.dep_info.get(d, || {
            Arc::new(
                std::fs::read_to_string(d)
                    .map(|t| depinfo::parse(&t, &self.ws.root))
                    .map_err(|e| format!("cargo: reading {d}: {e}")),
            )
        })
    }

    /// The scan of a package manifest, once per file.
    fn manifest_scan(&self, manifest: &Utf8Path) -> Arc<Result<scan::Findings, String>> {
        self.caches.manifests.get(manifest, || {
            Arc::new(match std::fs::read_to_string(manifest) {
                Ok(t) => {
                    let mut f = scan::Findings::default();
                    f.scan_manifest(manifest, &t);
                    Ok(f)
                }
                Err(e) => Err(format!("cargo: reading {manifest}: {e}")),
            })
        })
    }

    /// The scan of source file `f` with `roles` for the crate in `pkg`;
    /// remembered when `cacheable`.
    fn source_scan(
        &self,
        f: &Utf8Path,
        roles: scan::Roles,
        pkg: &Utf8Path,
        cacheable: bool,
    ) -> Arc<SourceScan> {
        let scan = || {
            Arc::new(match std::fs::read(f) {
                Err(e) => Err(format!("cargo: reading {f}: {e}")),
                Ok(bytes) => match String::from_utf8(bytes) {
                    Err(_) => Ok(None),
                    Ok(t) => {
                        let t = if matches!(f.extension(), Some("md" | "markdown")) {
                            // Documentation included as doc comments (its
                            // doctests run): scanned line by line like `///`
                            // comments.
                            t.lines().map(|l| format!("///{l}\n")).collect::<String>()
                        } else {
                            t
                        };
                        let mut found = scan::Findings::default();
                        found.scan_source(f, &t, roles, pkg);
                        Ok(Some(found))
                    }
                },
            })
        };
        if cacheable {
            self.caches
                .sources
                .get(&(f.to_owned(), roles, pkg.to_owned()), scan)
        } else {
            scan()
        }
    }

    /// Whether the external source directory `dir` is what Cargo.lock pins,
    /// checked once.
    fn verified(
        &self,
        dir: &Utf8Path,
        check: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        self.caches.verified.get(dir, check)
    }

    /// The workspace member whose package directory is `pkg_rel` (relative
    /// to the project dir).
    fn member(&self, project_dir: &Utf8Path, pkg_rel: &str) -> Option<&Package> {
        let dir = self.canon(&project_dir.join(pkg_rel));
        self.members.get(&dir).map(|&i| &self.ws.meta.packages[i])
    }
}

impl Adapter for CargoAdapter {
    fn name(&self) -> &'static str {
        "cargo"
    }

    fn project_dir(&self) -> &Utf8Path {
        &self.project_dir
    }

    /// Units of the workspace members (`cargo metadata --no-deps`). Any
    /// error (no Cargo.lock, not the workspace root) is an error, so
    /// `vci plan` runs everything.
    fn list_test_files(&self, env: &ChildEnv) -> Result<Vec<ListedFile>, AdapterError> {
        let ws = self.workspace(env)?;
        let mut files: Vec<ListedFile> = Vec::new();
        for (dir, kind) in units(&ws.meta) {
            let dir = canonical(&dir);
            if !dir.starts_with(&self.project_dir) {
                return Err(AdapterError::Parse {
                    what: "cargo metadata".into(),
                    detail: format!(
                        "workspace member {dir} is outside the project dir {}",
                        self.project_dir
                    ),
                });
            }
            files.push(ListedFile {
                abs: Utf8PathBuf::from(format!("{dir}#{}", kind.id())),
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

    fn builtin_ignore(&self) -> &'static [&'static str] {
        CARGO_IGNORE
    }

    fn builtin_hash(&self) -> &'static [&'static str] {
        CARGO_HASH
    }

    fn loose_hash(&self) -> &'static [&'static str] {
        CARGO_LOOSE_HASH
    }

    /// Every package Cargo.lock pins: name -> `version source checksum`.
    fn installed_externals(
        &self,
        _env: &ChildEnv,
    ) -> Result<Option<InstalledExternals>, AdapterError> {
        let lock = self.lock().map_err(|e| AdapterError::Parse {
            what: "Cargo.lock".into(),
            detail: e,
        })?;
        let mut out: InstalledExternals = BTreeMap::new();
        for l in lock.into_iter().filter(|l| !l.source.is_empty()) {
            out.entry(l.name.clone()).or_default().push(external_id(
                &l.version,
                &l.source,
                &l.checksum,
            ));
        }
        Ok(Some(out))
    }

    fn canonical_argv(&self, _project_dir_rel_to_repo: &str, project_rel: &str) -> Vec<String> {
        match parse_unit(project_rel) {
            Some((dir, kind)) => {
                let mut v: Vec<String> = vec![
                    "cargo".into(),
                    "test".into(),
                    "--locked".into(),
                    "--manifest-path".into(),
                    manifest_arg(&dir),
                ];
                v.extend(kind.selector());
                v
            }
            None => vec![
                "cargo".into(),
                "test".into(),
                format!("<not a unit: {project_rel}>"),
            ],
        }
    }

    fn config_candidates(&self) -> Vec<Utf8PathBuf> {
        ["Cargo.toml", "Cargo.lock"]
            .iter()
            .map(|n| self.project_dir.join(n))
            .collect()
    }

    fn snapshot_candidates(&self, _test_abs: &Utf8Path) -> Vec<Utf8PathBuf> {
        vec![]
    }

    /// Every unit built alone by the cargo lane (`cargo test <unit> --no-run
    /// --message-format=json`, after one warm-up build), its test executable
    /// run by the execution pool with the environment `cargo test` gives it
    /// and a fresh TMPDIR, several units at once (see [`lane`]). Doctests:
    /// `cargo test --doc` in the lane.
    fn run_collect(&self, files: &[String], env: &ChildEnv) -> Result<RunOutput, AdapterError> {
        let ctx = self.run_ctx(env)?;
        // Every package of the workspace is built from its sources in this
        // run (see `clean`); others found in the repository later are
        // cleaned when first met.
        let members: BTreeSet<&str> = ctx
            .ws
            .meta
            .workspace_members
            .iter()
            .map(String::as_str)
            .collect();
        let pkgs: BTreeSet<(String, String)> = ctx
            .ws
            .meta
            .packages
            .iter()
            .filter(|p| members.contains(p.id.as_str()) && !p.name.is_empty())
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        let block = self.clean(&pkgs, env, &ctx)?;
        let _ = std::io::stderr().write_all(&block);
        let results = self.run_units(files, env, &ctx, true)?;
        let exit = fold_exit(results.iter().map(|(c, _)| *c));
        Ok(RunOutput {
            exit_code: exit,
            files: results.into_iter().map(|(_, o)| o).collect(),
        })
    }

    /// With units: each built by the cargo lane and run by the execution
    /// pool like [`Adapter::run_collect`] (the selection and features the
    /// attestations were made with), without analysis. Without: `cargo test
    /// --locked --workspace`. Output goes to stderr, one block per unit.
    fn run_plain(&self, files: &[String], env: &ChildEnv) -> Result<Option<i32>, AdapterError> {
        if files.is_empty() {
            return self.run_plain_serial(files, env);
        }
        if let Some(f) = files.iter().find(|f| parse_unit(f).is_none()) {
            return Err(AdapterError::NotFound(format!("{f:?} is not a cargo unit")));
        }
        let ctx = match self.run_ctx(env) {
            Ok(c) => c,
            Err(e) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "vci: {e}; running each unit with its own `cargo test`"
                );
                return self.run_plain_serial(files, env);
            }
        };
        let results = self.run_units(files, env, &ctx, false)?;
        Ok(fold_exit(results.iter().map(|(c, _)| *c)))
    }

    fn scratch_dirs(&self) -> Vec<Utf8PathBuf> {
        match self.workspace.get() {
            Some(Ok(ws)) => vec![ws.target_dir.clone()],
            _ => vec![],
        }
    }

    fn scratch_dirs_with_env(&self, env: &ChildEnv) -> Vec<Utf8PathBuf> {
        let mut dirs = self.scratch_dirs();
        let raw = |k: &str| Self::child_var_raw(env, k);
        dirs.extend(cargo_home_inside(
            &canonical(&repo_root_of(&self.project_dir)),
            &raw,
        ));
        dirs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_ids_round_trip_and_select_targets() {
        for (id, sel) in [
            ("crates/a#lib", vec!["--lib"]),
            ("crates/a#doc", vec!["--doc"]),
            ("b#test:b", vec!["--test", "b"]),
            (".#bin:vci", vec!["--bin", "vci"]),
            ("x#example:demo", vec!["--example", "demo"]),
            ("x#bench:speed", vec!["--bench", "speed"]),
        ] {
            let (dir, k) = parse_unit(id).unwrap();
            assert_eq!(format!("{dir}#{}", k.id()), id);
            assert_eq!(k.selector(), sel);
        }
        assert!(parse_unit("crates/a").is_none());
        assert!(parse_unit("crates/a#test:").is_none());
        assert!(parse_unit("crates/a#wat").is_none());
        let a = CargoAdapter::new(Utf8Path::new("/nonexistent/ws"));
        assert_eq!(
            a.canonical_argv(".", "crates/a#test:e2e"),
            [
                "cargo",
                "test",
                "--locked",
                "--manifest-path",
                "crates/a/Cargo.toml",
                "--test",
                "e2e"
            ]
        );
        assert_eq!(
            a.canonical_argv(".", ".#lib")[4],
            "Cargo.toml",
            "a package at the workspace root"
        );
        assert_eq!(
            unit_package_dir(Utf8Path::new("/r/crates/a#test:x")),
            Utf8PathBuf::from("/r/crates/a")
        );
    }

    #[test]
    fn libtest_summaries_decide_the_result() {
        let ok = "running 3 tests\ntest a ... ok\n\ntest result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        let r = unit_result(ok, true, 5);
        assert!(r.is_pass(), "{r:?}");
        assert_eq!((r.tests, r.failed, r.skipped), (3, 0, 0));
        let failed = "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        assert_eq!(unit_result(failed, false, 0).state, "failed");
        assert_eq!(unit_result(ok, false, 0).state, "failed", "exit code wins");
        let zero = "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        assert_eq!(unit_result(zero, true, 0).state, "no-tests");
        let all_ignored = "test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        assert!(!unit_result(all_ignored, true, 0).is_pass());
        assert_eq!(
            unit_result("custom harness output\n", true, 0).state,
            "no-tests"
        );
        let filtered = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s\n";
        assert_eq!(unit_result(filtered, true, 0).state, "filtered");
        // Doctests (merged) print the same summary.
        let doc = "running 1 test\ntest a/src/lib.rs - add (line 3) ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\nall doctests ran in 0.95s; merged doctests compilation took 0.51s\n";
        assert!(unit_result(doc, true, 0).is_pass());
    }

    #[test]
    fn messages_are_separated_from_test_output() {
        let out = r#"{"reason":"compiler-artifact","package_id":"path+file:///w/a#0.1.0","target":{"kind":["lib"],"name":"a"},"filenames":["/t/deps/liba-1.rlib"],"features":["x"],"fresh":true}
{"reason":"build-script-executed","package_id":"path+file:///w/c#0.1.0","linked_libs":[],"linked_paths":[],"cfgs":[],"env":[],"out_dir":"/t/build/c-2/out"}
{"reason":"build-finished","success":true}

running 1 test
{"not":"a message"}
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
"#;
        let (arts, runs, text) = split_messages(out);
        assert_eq!(arts.len(), 1);
        assert_eq!(arts[0].kind, ["lib"]);
        assert_eq!(arts[0].features, ["x"]);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].out_dir, Utf8PathBuf::from("/t/build/c-2/out"));
        assert!(text.contains("{\"not\":\"a message\"}"));
        assert!(text.contains("test result: ok."));
    }

    #[test]
    fn units_follow_cargo_test_defaults() {
        let meta: Metadata = serde_json::from_str(
            r#"{"workspace_root":"/w","target_directory":"/w/target","workspace_members":["m"],"packages":[
            {"id":"m","manifest_path":"/w/m/Cargo.toml",
             "features":{"default":["fast"],"fast":[],"slow":[]},
             "targets":[
               {"name":"m","kind":["lib"],"test":true,"doctest":true},
               {"name":"m","kind":["bin"],"test":true,"doctest":false},
               {"name":"it","kind":["test"],"test":true,"doctest":false},
               {"name":"needs-slow","kind":["test"],"test":true,"doctest":false,"required-features":["slow"]},
               {"name":"needs-fast","kind":["test"],"test":true,"doctest":false,"required-features":["fast"]},
               {"name":"ex","kind":["example"],"test":false,"doctest":false},
               {"name":"build-script-build","kind":["custom-build"],"test":false,"doctest":false}
             ]},
            {"id":"dep","manifest_path":"/reg/dep/Cargo.toml",
             "targets":[{"name":"dep","kind":["lib"],"test":true,"doctest":true}]}
            ]}"#,
        )
        .unwrap();
        let ids: Vec<String> = units(&meta)
            .into_iter()
            .map(|(d, k)| format!("{d}#{}", k.id()))
            .collect();
        assert_eq!(
            ids,
            [
                "/w/m#lib",
                "/w/m#doc",
                "/w/m#bin:m",
                "/w/m#test:it",
                "/w/m#test:needs-fast"
            ]
        );
    }

    #[test]
    fn the_rustc_cargo_used_is_read_from_its_cache() {
        let vv = "rustc 1.96.0 (ac68faa20 2026-05-25)\nbinary: rustc\ncommit-hash: ac68\ncommit-date: 2026-05-25\nhost: aarch64-apple-darwin\nrelease: 1.96.0\nLLVM version: 22.1.6\n";
        assert_eq!(rustc_id(vv).as_deref(), Some("1.96.0 ac68 LLVM 22.1.6"));
        let t = tempfile::tempdir().unwrap();
        let d = Utf8PathBuf::from_path_buf(t.path().to_path_buf()).unwrap();
        assert_eq!(rustc_used(&d), None);
        std::fs::write(
            d.join(".rustc_info.json"),
            serde_json::json!({"rustc_fingerprint": 1, "outputs": {
                "1": {"success": true, "status": "", "code": 0, "stdout": "___\nlib___.rlib\n", "stderr": ""},
                "2": {"success": true, "status": "", "code": 0, "stdout": vv, "stderr": ""}
            }, "successes": {}})
            .to_string(),
        )
        .unwrap();
        assert_eq!(rustc_used(&d).as_deref(), Some("1.96.0 ac68 LLVM 22.1.6"));
    }

    /// The sysroot of the rustc cargo used (rustup's proxied cargo can find
    /// Homebrew's rustc first on PATH): from the `--print=sysroot` line of
    /// its cache, for the library search path of the tests.
    #[test]
    fn the_sysroot_cargo_used_is_read_from_its_cache() {
        let t = tempfile::tempdir().unwrap();
        let d = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        assert_eq!(rustc_sysroot(&d), None);
        let sysroot = d.join("brew/rust/1.96.0");
        std::fs::create_dir_all(sysroot.join("lib/rustlib")).unwrap();
        let info = |sysroots: &[&Utf8Path]| {
            let outputs: serde_json::Map<String, Value> = sysroots
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let out = format!("___\nlib___.rlib\n{s}\noff\n___\ndebug_assertions\n");
                    (
                        i.to_string(),
                        serde_json::json!({"success": true, "stdout": out}),
                    )
                })
                .collect();
            serde_json::json!({"rustc_fingerprint": 1, "outputs": outputs}).to_string()
        };
        std::fs::write(d.join(".rustc_info.json"), info(&[&sysroot])).unwrap();
        assert_eq!(rustc_sysroot(&d), Some(sysroot.clone()));
        let other = d.join("rustup/toolchains/stable");
        std::fs::create_dir_all(other.join("lib/rustlib")).unwrap();
        std::fs::write(d.join(".rustc_info.json"), info(&[&sysroot, &other])).unwrap();
        assert_eq!(rustc_sysroot(&d), None, "two rustcs: not known which");
    }

    /// The run-wide caches compute each key once, also when the execution
    /// pool's threads ask at the same time.
    #[test]
    fn memo_computes_each_key_once() {
        let memo: Memo<Utf8PathBuf, usize> = Memo::default();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for k in ["a", "b"] {
                        let v = memo.get(Utf8Path::new(k), || {
                            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            k.len()
                        });
                        assert_eq!(v, 1);
                    }
                });
            }
        });
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn package_ids_parse() {
        assert_eq!(
            parse_pkgid("path+file:///w/a#0.1.0"),
            Some(PkgId {
                name: "a".into(),
                version: "0.1.0".into(),
                source: None
            })
        );
        assert_eq!(
            parse_pkgid("path+file:///w/crates/core#vci-core@0.1.0")
                .unwrap()
                .name,
            "vci-core"
        );
        let r =
            parse_pkgid("registry+https://github.com/rust-lang/crates.io-index#hex@0.4.3").unwrap();
        assert_eq!(
            (r.name.as_str(), r.version.as_str(), r.source.as_deref()),
            (
                "hex",
                "0.4.3",
                Some("registry+https://github.com/rust-lang/crates.io-index")
            )
        );
        let g = parse_pkgid("git+https://example.com/g?branch=main#g@0.2.0").unwrap();
        assert_eq!(
            g.source.as_deref(),
            Some("git+https://example.com/g?branch=main")
        );
        assert!(parse_pkgid("nonsense").is_none());
    }

    #[test]
    fn cargo_lock_entries_identify_externals() {
        let lock = parse_lock(
            "version = 4\n\n[[package]]\nname = \"a\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"hex\"\nversion = \"0.4.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"7f24\"\n\n[[package]]\nname = \"g\"\nversion = \"0.2.0\"\nsource = \"git+https://example.com/g?branch=main#abc123\"\n",
        )
        .unwrap();
        assert_eq!(lock.len(), 3);
        assert_eq!(lock[1].checksum, "7f24");
        assert_eq!(
            external_id(&lock[1].version, &lock[1].source, &lock[1].checksum),
            "0.4.3 registry+https://github.com/rust-lang/crates.io-index 7f24"
        );
        assert_eq!(
            external_id(&lock[2].version, &lock[2].source, &lock[2].checksum),
            "0.2.0 git+https://example.com/g?branch=main#abc123 -"
        );
        assert!(parse_lock("[[package]]\nname = \"x\"\n").is_err());
    }

    /// No built-in ignore name is matched by a built-in hash pattern (built-in
    /// hash would win, and cargo's locations would re-run every unit).
    #[test]
    fn dep_info_paths_through_symlinked_directories_resolve_to_the_target() {
        let t = tempfile::tempdir().unwrap();
        let root = canonical(Utf8Path::from_path(t.path()).unwrap());
        std::fs::create_dir_all(root.join("jj/docs")).unwrap();
        std::fs::create_dir_all(root.join("jj/cli")).unwrap();
        std::fs::write(root.join("jj/docs/b.md"), "x").unwrap();
        std::os::unix::fs::symlink("../docs", root.join("jj/cli/docs")).unwrap();
        let (links, real) = through_links(&root.join("jj/cli/docs/b.md"), &root);
        assert_eq!(links, [root.join("jj/cli/docs")]);
        assert_eq!(real, root.join("jj/docs/b.md"));
        let plain = root.join("jj/docs/b.md");
        assert_eq!(through_links(&plain, &root), (vec![], plain));
        std::os::unix::fs::symlink("/", root.join("jj/cli/out")).unwrap();
        let outside = root.join("jj/cli/out/etc/hosts");
        assert_eq!(through_links(&outside, &root), (vec![], outside));
    }

    #[test]
    fn ignore_and_hash_lists_are_disjoint() {
        let m = |pat: &str, name: &str| match pat.split_once('*') {
            Some((a, b)) => {
                name.starts_with(a) && name.ends_with(b) && name.len() >= a.len() + b.len()
            }
            None => pat == name,
        };
        for p in CARGO_IGNORE {
            let name = p.trim_end_matches('*');
            assert!(!CARGO_HASH.iter().any(|h| m(h, name)), "{p}");
        }
    }

    #[test]
    fn outside_config_is_checked_inside_config_mostly_hashed() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        let repo = root.join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(repo.join(".cargo")).unwrap();
        std::fs::create_dir_all(root.join(".cargo")).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let a = CargoAdapter::new(&repo);
        let env: ChildEnv = Some(vec![("CARGO_HOME".into(), home.as_str().into())]);
        std::fs::write(
            repo.join(".cargo/config.toml"),
            "[build]\nrustflags = [\"-Dwarnings\"]\n",
        )
        .unwrap();
        std::fs::write(
            root.join(".cargo/config.toml"),
            "[net]\ngit-fetch-with-cli = true\n[build]\njobs = 4\n",
        )
        .unwrap();
        std::fs::write(
            home.join("config.toml"),
            "[registries.x]\nindex = \"sparse+https://x\"\n",
        )
        .unwrap();
        assert!(
            a.config_problems(&env).is_empty(),
            "{:?}",
            a.config_problems(&env)
        );
        std::fs::write(
            root.join(".cargo/config.toml"),
            "[build]\nrustflags = [\"-Ctarget-cpu=native\"]\n",
        )
        .unwrap();
        std::fs::write(home.join("config.toml"), "[env]\nX = \"1\"\n").unwrap();
        let p = a.config_problems(&env);
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p.iter().any(|x| x.contains("build.rustflags")), "{p:?}");
        assert!(p.iter().any(|x| x.contains("[env]")), "{p:?}");
        std::fs::remove_file(root.join(".cargo/config.toml")).unwrap();
        std::fs::remove_file(home.join("config.toml")).unwrap();
        std::fs::write(
            repo.join(".cargo/config.toml"),
            "[build]\ntarget = \"wasm32-unknown-unknown\"\n",
        )
        .unwrap();
        assert_eq!(a.config_problems(&env).len(), 1);
    }
}
