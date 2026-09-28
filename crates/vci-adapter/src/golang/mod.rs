//! Go adapter: the unit is a package (a directory with `_test.go` files),
//! run with `go test`. Test ids are the package directories.
//!
//! What a package's test depends on comes from two sources:
//!
//! * compile time, `go list -e -deps -test -json`: the import closure of the
//!   test variants (see [`golist`]): every file of every package inside the
//!   repository (sources, embedded files, files build constraints exclude
//!   here), the directory listing of each such package and every go:embed
//!   tree, and external modules as `path@version` (the extracted module in
//!   the cache is checked against its go.sum hash first);
//! * run time, the test log of package os: every file opened (a directory
//!   open is a listing) or stat'ed, every environment variable looked up,
//!   every chdir. vci overlays `vci_testlog.go` into the standard library's
//!   internal/testlog (`go test -overlay`), which installs a logger when that
//!   package is initialised, before package os and so before any package
//!   initialiser or TestMain, and records `os.StartProcess` as `exec`. The
//!   same overlay patches a few functions of packages os and time that do not
//!   report to the log ([`hooks`]): symlink reads and creation, hard links,
//!   `os.Environ`, `File.Chdir`, the first use of the local time zone.
//!
//! Collection runs one package per process:
//!
//! ```text
//! TMPDIR=<fresh empty dir> VCI_GO_TESTLOG=<file> \
//!   go test -count=1 -json -overlay=<tmp>/overlay.json ./<pkg>
//! ```
//!
//! `go test` runs the binary in the package directory, as `vci ci` does
//! (`go test -count=1 -json <pkgs>`, output converted back to text).
//! `-count=1` disables go's test cache (a cached result would not run), and
//! `-json` makes both runs verbose (`testing.Verbose()` is true in both).
//! TMPDIR points at a fresh empty directory: what the test finds there
//! (`t.TempDir()`) it created itself, so those files are not inputs.

pub(crate) mod dirhash;
pub(crate) mod golist;
pub(crate) mod hooks;
pub(crate) mod scan;
pub(crate) mod testlog;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead as _, Write as _};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use camino::{Utf8Path, Utf8PathBuf};
use serde_json::Value;

use crate::pytest::{OneRun, per_file};
use crate::vitest::{apply_env, describe};
use crate::{
    Adapter, AdapterError, ChildEnv, InstalledExternals, ListedFile, Observed, RunOutput,
    ToolVersions,
};
pub use golist::GO_NET_TAINT;

/// Env var naming the `go` binary (default: `go` on PATH).
pub const GO_BIN_ENV: &str = "VCI_GO";

/// Env var the overlaid logger writes its records to.
const TESTLOG_ENV: &str = "VCI_GO_TESTLOG";

/// The logger overlaid into internal/testlog.
const TESTLOG_SRC: &str = include_str!("vci_testlog.go");

/// Variables the child always sees (on top of the global built-in list) so
/// that the go command works in strict mode: where modules, the build cache
/// and the toolchain live and how modules are fetched. Like every built-in
/// pass-through variable, they are hashed only when a test reads one.
pub const GO_PASS_THROUGH: &[&str] = &[
    "GOPATH",
    "GOROOT",
    "GOCACHE",
    "GOCACHEPROG",
    "GOMODCACHE",
    "GOENV",
    "GOPROXY",
    "GONOPROXY",
    "GOPRIVATE",
    "GONOSUMDB",
    "GONOSUMCHECK",
    "GOSUMDB",
    "GOINSECURE",
    "GOVCS",
    "GOAUTH",
    "GOTELEMETRY",
    "GOTELEMETRYDIR",
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

/// Variables hashed whenever present (loose mode, or declared in strict
/// mode, which otherwise removes them): they change the build (`GOFLAGS`,
/// `CGO_ENABLED`, `GOEXPERIMENT`, `GOAMD64`, `CGO_CFLAGS`, `GOTOOLCHAIN`, ...)
/// or the runtime (`GODEBUG`, `GOMAXPROCS`, `GOGC`, `GOTRACEBACK`, read by
/// the runtime where no log sees it). The go command's own locations are
/// pass-through instead.
pub const GO_HASHED_ENV: &[&str] = &[
    "GO*",
    "CGO_*",
    "!GOPATH",
    "!GOROOT",
    "!GOCACHE",
    "!GOCACHEPROG",
    "!GOMODCACHE",
    "!GOENV",
    "!GOPROXY",
    "!GONOPROXY",
    "!GOPRIVATE",
    "!GONOSUMDB",
    "!GONOSUMCHECK",
    "!GOSUMDB",
    "!GOINSECURE",
    "!GOVCS",
    "!GOAUTH",
    "!GOTELEMETRY",
    "!GOTELEMETRYDIR",
];

/// Read by package time through syscall.Getenv, which package os does not
/// log: reported as read by every package (hashed, set or not).
pub const GO_ALWAYS_READ_ENV: &[&str] = &["TZ", "ZONEINFO"];

/// Variables `go test` or vci set to per-run values: `PWD` (go test sets it
/// to the package directory; os.Getwd and filepath.Abs read it) and
/// `TMPDIR` (vci's fresh directory). Reads of them are not inputs, like
/// the checkout location in every adapter.
const RUN_SPECIFIC_ENV: &[&str] = &["PWD", "TMPDIR", TESTLOG_ENV];

/// Files outside the repository a test may open without that being an
/// input.
const HARMLESS_OUTSIDE: &[&str] = &["/dev/null"];

/// Every `go env` variable the adapter reads.
const GO_ENV_VARS: &[&str] = &[
    "GOVERSION",
    "GOOS",
    "GOARCH",
    "GOHOSTOS",
    "GOHOSTARCH",
    "GOROOT",
    "GOMOD",
    "GOWORK",
    "GOFLAGS",
    "CGO_ENABLED",
    "GOEXPERIMENT",
    "GOFIPS140",
    "GODEBUG",
    "GOAMD64",
    "GOARM64",
    "GOARM",
    "GO386",
    "GOPPC64",
    "GORISCV64",
    "GOMIPS",
    "GOMIPS64",
    "GOWASM",
];

/// `go env` settings recorded in the toolchain because they change what is
/// built on every platform.
const GO_ENV_RECORDED: &[&str] = &[
    "CGO_ENABLED",
    "GOEXPERIMENT",
    "GOFLAGS",
    "GOFIPS140",
    "GODEBUG",
];

/// The architecture level variable of each GOARCH.
fn arch_level_var(goarch: &str) -> Option<&'static str> {
    Some(match goarch {
        "amd64" => "GOAMD64",
        "arm64" => "GOARM64",
        "arm" => "GOARM",
        "386" => "GO386",
        "ppc64" | "ppc64le" => "GOPPC64",
        "riscv64" => "GORISCV64",
        "mips" | "mipsle" => "GOMIPS",
        "mips64" | "mips64le" => "GOMIPS64",
        "wasm" => "GOWASM",
        _ => return None,
    })
}

#[derive(Debug, Clone)]
struct GoEnv {
    versions: ToolVersions,
    vars: BTreeMap<String, String>,
}

/// The Go adapter.
#[derive(Debug)]
pub struct GoAdapter {
    project_dir: Utf8PathBuf,
    go: OsString,
    probe: OnceLock<Result<GoEnv, String>>,
}

fn utf8_tmp(t: &tempfile::TempDir) -> Result<Utf8PathBuf, AdapterError> {
    let p = t.path().canonicalize()?;
    Utf8PathBuf::from_path_buf(p)
        .map_err(|p| AdapterError::NotFound(format!("non-UTF-8 temp dir {p:?}")))
}

/// `./b` for the package directory `b` (project-relative), `.` for the
/// module root.
fn pkg_arg(rel: &str) -> String {
    if rel == "." || rel.is_empty() {
        ".".to_owned()
    } else {
        format!("./{}", rel.trim_start_matches("./"))
    }
}

/// Lexical path from `base` to `target` (both absolute), with `..` as needed.
fn relative_to(base: &Utf8Path, target: &Utf8Path) -> String {
    let b: Vec<&str> = base.components().map(|c| c.as_str()).collect();
    let t: Vec<&str> = target.components().map(|c| c.as_str()).collect();
    let common = b.iter().zip(&t).take_while(|(x, y)| x == y).count();
    let mut parts: Vec<&str> = vec![".."; b.len() - common];
    parts.extend(&t[common..]);
    if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    }
}

/// Remove `.`/`..` components when that is what the kernel does too: a `..`
/// is only resolved lexically when the directory it leaves is a real
/// directory, not a symlink. Otherwise the path is returned unchanged (and
/// then refused as unrepresentable).
pub(crate) fn normalise(p: &Utf8Path) -> Utf8PathBuf {
    if !p.components().any(|c| {
        matches!(
            c,
            camino::Utf8Component::ParentDir | camino::Utf8Component::CurDir
        )
    }) {
        return p.to_owned();
    }
    let mut out = Utf8PathBuf::new();
    for c in p.components() {
        match c {
            camino::Utf8Component::CurDir => {}
            camino::Utf8Component::ParentDir => {
                match std::fs::symlink_metadata(&out) {
                    Ok(m) if m.is_dir() => {}
                    _ => return p.to_owned(),
                }
                out.pop();
            }
            other => out.push(other.as_str()),
        }
    }
    out
}

impl GoAdapter {
    /// `project_dir` must be absolute (it is canonicalised if possible).
    pub fn new(project_dir: &Utf8Path) -> Self {
        let project_dir = project_dir
            .canonicalize_utf8()
            .unwrap_or_else(|_| project_dir.to_owned());
        let go = std::env::var_os(GO_BIN_ENV)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "go".into());
        Self {
            project_dir,
            go,
            probe: OnceLock::new(),
        }
    }

    /// `go <args>` in the project dir with `env` applied.
    fn go_cmd(&self, env: &ChildEnv) -> Command {
        let mut c = Command::new(&self.go);
        c.current_dir(&self.project_dir).stdin(Stdio::null());
        apply_env(&mut c, env);
        c.env_remove(TESTLOG_ENV);
        c
    }

    fn not_installed(&self, e: std::io::Error) -> AdapterError {
        if e.kind() == std::io::ErrorKind::NotFound {
            AdapterError::NotFound(format!(
                "`{}` was not found: the go adapter needs the Go toolchain on PATH, or {GO_BIN_ENV} naming the go binary",
                self.go.to_string_lossy()
            ))
        } else {
            AdapterError::Io(e)
        }
    }

    fn output(&self, cmd: &mut Command) -> Result<std::process::Output, AdapterError> {
        let out = cmd.output().map_err(|e| self.not_installed(e))?;
        if !out.status.success() {
            return Err(AdapterError::Command {
                cmd: describe(cmd),
                status: out.status.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).trim_end().to_owned(),
            });
        }
        Ok(out)
    }

    fn probe(&self, env: &ChildEnv) -> Result<GoEnv, AdapterError> {
        self.probe
            .get_or_init(|| self.run_probe(env).map_err(|e| e.to_string()))
            .clone()
            .map_err(|e| AdapterError::Parse {
                what: "go env".into(),
                detail: e,
            })
    }

    fn run_probe(&self, env: &ChildEnv) -> Result<GoEnv, AdapterError> {
        let mut cmd = self.go_cmd(env);
        cmd.args(["env", "-json"]).args(GO_ENV_VARS);
        let out = self.output(&mut cmd)?;
        let v: BTreeMap<String, String> =
            serde_json::from_slice(&out.stdout).map_err(|e| AdapterError::Parse {
                what: "go env -json".into(),
                detail: e.to_string(),
            })?;
        let get = |k: &str| v.get(k).cloned().unwrap_or_default();
        let bad = |d: String| AdapterError::Parse {
            what: "go env".into(),
            detail: d,
        };
        if get("GOVERSION").is_empty() {
            return Err(bad("no GOVERSION".into()));
        }
        if get("GOOS") != get("GOHOSTOS") || get("GOARCH") != get("GOHOSTARCH") {
            return Err(bad(format!(
                "GOOS/GOARCH {}/{} differ from the host {}/{}: cross-compiled test runs are not supported",
                get("GOOS"),
                get("GOARCH"),
                get("GOHOSTOS"),
                get("GOHOSTARCH")
            )));
        }
        let gomod = get("GOMOD");
        let want = self.project_dir.join("go.mod");
        let same =
            Utf8Path::new(&gomod).canonicalize_utf8().ok().as_deref() == Some(want.as_path());
        if !same {
            return Err(bad(format!(
                "the project dir {} is not the root of a Go module (go env GOMOD = {gomod:?})",
                self.project_dir
            )));
        }
        let mut go_env: Vec<String> = GO_ENV_RECORDED
            .iter()
            .map(|k| format!("{k}={}", get(k)))
            .collect();
        let work = get("GOWORK");
        let work_rel = if work.is_empty() || work == "off" {
            work.clone()
        } else {
            relative_to(&self.project_dir, Utf8Path::new(&work))
        };
        go_env.push(format!("GOWORK={work_rel}"));
        go_env.sort();
        let go_arch_level = arch_level_var(&get("GOARCH"))
            .map(|k| format!("{k}={}", get(k)))
            .unwrap_or_default();
        Ok(GoEnv {
            versions: ToolVersions {
                runner: get("GOVERSION"),
                go_env,
                go_arch_level,
                go_work: work,
                ..Default::default()
            },
            vars: v,
        })
    }

    /// `go list -e -deps -test -json <patterns>`.
    fn list_deps(
        &self,
        patterns: &[String],
        env: &ChildEnv,
    ) -> Result<Vec<golist::GoPackage>, String> {
        let mut cmd = self.go_cmd(env);
        cmd.args(["list", "-e", "-deps", "-test", "-json"])
            .args(patterns);
        let out = self.output(&mut cmd).map_err(|e| e.to_string())?;
        golist::parse_packages(&String::from_utf8_lossy(&out.stdout))
    }

    /// Run one package's test with the logger; build its [`Observed`].
    fn run_one(
        &self,
        rel: &str,
        env: &ChildEnv,
        overlay: &Utf8Path,
        analysis: Result<(String, golist::Analysis), String>,
        go: &GoEnv,
        hooks: &Result<(), String>,
    ) -> Result<OneRun, AdapterError> {
        let tmp = tempfile::Builder::new().prefix("vci-gotmp-").tempdir()?;
        let tmp_p = utf8_tmp(&tmp)?;
        let logdir = tempfile::Builder::new().prefix("vci-golog-").tempdir()?;
        let log_p = utf8_tmp(&logdir)?.join("testlog.txt");
        let mut cmd = self.go_cmd(env);
        cmd.args(["test", "-count=1", "-json"])
            .arg(format!("-overlay={overlay}"))
            .arg(pkg_arg(rel))
            .env("TMPDIR", tmp_p.as_str())
            .env(TESTLOG_ENV, log_p.as_str());
        let out = cmd.output().map_err(|e| self.not_installed(e))?;
        let (import_path, analysis) = match analysis {
            Ok(x) => (x.0, Ok(x.1)),
            Err(e) => (String::new(), Err(e)),
        };
        let run = testlog::parse_test2json(
            &String::from_utf8_lossy(&out.stdout),
            &import_path,
            out.status.success(),
        );
        let mut block = format!(
            "vci: {} (exit {})\n",
            describe(&cmd),
            out.status
                .code()
                .map_or_else(|| "signal".to_owned(), |c| c.to_string())
        )
        .into_bytes();
        block.extend_from_slice(run.output.as_bytes());
        block.extend_from_slice(&out.stderr);
        let log = std::fs::read_to_string(&log_p).unwrap_or_default();
        let ev = testlog::parse_testlog(&log);
        let mut o = self.observed(rel, analysis, ev, run, &tmp_p, go);
        if let Err(e) = hooks {
            o.taints.push(format!(
                "go: vci's standard library hooks could not be installed for this Go version ({e}); symlink targets, os.Environ and the local time zone would not be observed"
            ));
        }
        Ok((out.status.code(), vec![o], block))
    }

    fn observed(
        &self,
        rel: &str,
        analysis: Result<golist::Analysis, String>,
        ev: testlog::LogEvents,
        run: testlog::TestRun,
        tmp: &Utf8Path,
        go: &GoEnv,
    ) -> Observed {
        let testlog::TestRun { result, passed, .. } = run;
        let passed_all = result.is_pass();
        let mut o = Observed {
            test_id: rel.to_owned(),
            root: self.project_dir.to_string(),
            adapter: "go".into(),
            collector: "vci_testlog.go".into(),
            result: Some(result),
            ..Default::default()
        };
        match analysis {
            Ok(a) => {
                // Every Test/Fuzz function the compiled test files declare
                // must have run: a TestMain that exits before m.Run, or
                // filters with -test.run, runs less than a plain go test
                // elsewhere may (the reason can be an input vci does not see,
                // such as the user id).
                let missing: Vec<&String> = a
                    .declared_tests
                    .iter()
                    .filter(|t| !passed.contains(*t))
                    .collect();
                if passed_all && !missing.is_empty() {
                    o.taints.push(format!(
                        "go: declared tests did not run: {} (a TestMain that exits before m.Run or filters the tests?)",
                        missing
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                o.modules = a.files;
                o.probes = a.probes;
                o.readdirs = a.dirs;
                o.externals = a.externals;
                o.taints.extend(a.taints);
                o.platform_files = a.platform_files;
                o.arch_specific = a.arch_specific;
            }
            Err(e) => o.taints.push(format!("go list: {e}")),
        }
        match ev.starts.first() {
            Some(s) => {
                let mut it = s.split_whitespace();
                o.runner_version = it.next().unwrap_or_default().to_owned();
                let platform = it.last().unwrap_or_default();
                let (os, arch) = platform.split_once('/').unwrap_or((platform, ""));
                o.platform = os.to_owned();
                o.arch = arch.to_owned();
                let want = (go.vars.get("GOOS"), go.vars.get("GOARCH"));
                if want != (Some(&o.platform), Some(&o.arch)) {
                    o.taints.push(format!(
                        "go: the test binary ran as {platform}, go env says {:?}/{:?}",
                        want.0, want.1
                    ));
                }
            }
            None => o.taints.push(
                "vci:no-testlog (the test binary did not start with the vci logger; the overlay did not apply or the build failed)"
                    .into(),
            ),
        }
        o.taints.extend(ev.taints);
        for e in &ev.execs {
            o.taints.push(format!(
                "exec: {e} (os.StartProcess; what a child process reads is not observed)"
            ));
        }
        let tmp_raw = Utf8Path::new(tmp.as_str());
        // A link in the temp dir to a file elsewhere: reads through it are
        // logged under the link's name (ignored) instead of the file's.
        for t in &ev.links {
            let n = normalise(t);
            let lexical = n.components().any(|c| {
                matches!(
                    c,
                    camino::Utf8Component::ParentDir | camino::Utf8Component::CurDir
                )
            });
            if lexical || !n.starts_with(tmp_raw) {
                o.taints.push(format!(
                    "go: created a link to {t} (os.Symlink/os.Link; reads through the link would not be recorded as reads of its target)"
                ));
            }
        }
        let ignored =
            |p: &Utf8Path| p.starts_with(tmp_raw) || HARMLESS_OUTSIDE.contains(&p.as_str());
        let classify = |p: &Utf8Path, o: &mut Observed, stat_only: bool| {
            if !p.is_absolute() {
                o.taints
                    .push(format!("go: relative path in the test log: {p}"));
                return;
            }
            let p = normalise(p);
            if ignored(&p) {
                return;
            }
            match std::fs::metadata(&p) {
                Ok(m) if m.is_dir() && !stat_only => {
                    o.readdirs.insert(p);
                }
                Ok(_) if stat_only => {
                    o.stats.insert(p);
                }
                Ok(_) => {
                    o.reads.insert(p);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    o.probes.insert(p);
                }
                Err(e) => o.taints.push(format!("go: cannot inspect {p}: {e}")),
            }
        };
        for p in &ev.opens {
            classify(p, &mut o, false);
        }
        for p in ev.stats.iter().chain(&ev.chdirs) {
            classify(p, &mut o, true);
        }
        for k in ev.env {
            if !RUN_SPECIFIC_ENV.contains(&k.as_str()) {
                o.env_keys.insert(k);
            }
        }
        for k in GO_ALWAYS_READ_ENV {
            o.env_keys.insert((*k).to_owned());
        }
        o
    }
}

/// Why a `GOFLAGS` setting prevents attestation: `-overlay` (vci needs it
/// for the test log); `-modfile`, `-pgo=<file>`, `-toolexec`, `-exec`,
/// `-pkgdir`, and tool flags that name files or external tools (`-I` search
/// paths, `-importcfg`, `@file` argument files, an external linker): they
/// name programs or files vci would not hash, so a change to them would
/// not invalidate the attestation (only the flag text is compared); a
/// compiler other than gc is not identified by the Go version.
fn unsupported_goflag(goflags: &str) -> Option<&'static str> {
    for f in goflags.split_whitespace() {
        let f = f.strip_prefix('-').unwrap_or(f);
        let f = f.strip_prefix('-').unwrap_or(f);
        let (name, value) = f.split_once('=').unwrap_or((f, ""));
        match name {
            "overlay" => return Some("-overlay is what vci uses for its test log"),
            "modfile" => return Some("-modfile names a module file vci does not hash"),
            "pgo" if !matches!(value, "auto" | "off" | "") => {
                return Some("-pgo names a profile vci does not hash");
            }
            "toolexec" => {
                return Some("-toolexec runs a program vci does not hash around every tool");
            }
            "exec" => {
                return Some("-exec runs the test binary through a program vci does not hash");
            }
            "pkgdir" => return Some("-pkgdir names prebuilt packages vci does not hash"),
            "compiler" if value != "gc" => {
                return Some("-compiler: only the gc toolchain is identified by the Go version");
            }
            "gccgoflags" => return Some("-gccgoflags: only the gc toolchain is supported"),
            "asmflags" | "gcflags" | "ldflags" => {
                const PATHY: &[&str] = &[
                    "/",
                    "-I",
                    "@",
                    "importcfg",
                    "embedcfg",
                    "linkmode",
                    "extld",
                    "extar",
                    "pgoprofile",
                    "-r",
                    "-L",
                    "installsuffix",
                ];
                if value.is_empty() || PATHY.iter().any(|p| value.contains(p)) {
                    return Some(
                        "-asmflags/-gcflags/-ldflags name files, search paths or an external linker that vci does not hash",
                    );
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse `go list -m -json all` into module path -> versions, in the form
/// [`golist::module_id`] records them. A module replaced by a directory maps
/// to `local:<dir>`, which never equals an attested version.
fn parse_modules(text: &str) -> Result<InstalledExternals, String> {
    let mut out: InstalledExternals = BTreeMap::new();
    for m in serde_json::Deserializer::from_str(text).into_iter::<golist::GoModule>() {
        let m = m.map_err(|e| e.to_string())?;
        if m.main {
            continue;
        }
        let v = match golist::module_id(&m) {
            Some((_, v)) => v,
            None => format!(
                "local:{}",
                m.replace
                    .as_deref()
                    .map_or(m.dir.as_str(), |r| r.path.as_str())
            ),
        };
        let vs = out.entry(m.path.clone()).or_default();
        if !vs.contains(&v) {
            vs.push(v);
        }
    }
    Ok(out)
}

impl Adapter for GoAdapter {
    fn name(&self) -> &'static str {
        "go"
    }

    fn project_dir(&self) -> &Utf8Path {
        &self.project_dir
    }

    /// Packages under the project dir with test files (`go list -json ./...`).
    /// Any error (a broken package, no module) is an error, so `vci plan` runs
    /// everything.
    fn list_test_files(&self, env: &ChildEnv) -> Result<Vec<ListedFile>, AdapterError> {
        let mut cmd = self.go_cmd(env);
        cmd.args(["list", "-json", "./..."]);
        let out = self.output(&mut cmd)?;
        let pkgs = golist::parse_packages(&String::from_utf8_lossy(&out.stdout)).map_err(|e| {
            AdapterError::Parse {
                what: "go list -json ./...".into(),
                detail: e,
            }
        })?;
        let mut files = Vec::new();
        for p in pkgs {
            if let Some(e) = &p.error {
                return Err(AdapterError::Parse {
                    what: "go list -json ./...".into(),
                    detail: format!("{}: {}", p.import_path, e.err),
                });
            }
            if !p.has_tests() {
                continue;
            }
            let abs =
                Utf8PathBuf::from(&p.dir)
                    .canonicalize_utf8()
                    .map_err(|e| AdapterError::Parse {
                        what: "go list -json ./...".into(),
                        detail: format!("package dir {}: {e}", p.dir),
                    })?;
            if !abs.starts_with(&self.project_dir) {
                return Err(AdapterError::Parse {
                    what: "go list -json ./...".into(),
                    detail: format!(
                        "package dir {abs} is outside the project dir {}",
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
        GO_PASS_THROUGH
    }

    fn hashed_env_patterns(&self) -> &'static [&'static str] {
        GO_HASHED_ENV
    }

    /// Modules of the build list (`go list -m -json all`), as the module
    /// path and the version (or replacement) the build uses.
    fn installed_externals(
        &self,
        env: &ChildEnv,
    ) -> Result<Option<InstalledExternals>, AdapterError> {
        let mut cmd = self.go_cmd(env);
        cmd.args(["list", "-m", "-json", "all"]);
        let out = self.output(&mut cmd)?;
        parse_modules(&String::from_utf8_lossy(&out.stdout))
            .map(Some)
            .map_err(|e| AdapterError::Parse {
                what: "go list -m -json all".into(),
                detail: e,
            })
    }

    fn canonical_argv(&self, project_dir_rel_to_repo: &str, project_rel: &str) -> Vec<String> {
        vec![
            "go".into(),
            "test".into(),
            "-C".into(),
            project_dir_rel_to_repo.into(),
            "-count=1".into(),
            "-json".into(),
            pkg_arg(project_rel),
        ]
    }

    fn config_candidates(&self) -> Vec<Utf8PathBuf> {
        ["go.mod", "go.sum", "go.work", "go.work.sum"]
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

    /// One `go test` process per package, at most `$VCI_JOBS` at a time,
    /// each with the logger overlay, its own log and a fresh TMPDIR.
    fn run_collect(&self, files: &[String], env: &ChildEnv) -> Result<RunOutput, AdapterError> {
        let go = self.probe(env)?;
        let goflags = go.vars.get("GOFLAGS").cloned().unwrap_or_default();
        if let Some(why) = unsupported_goflag(&goflags) {
            return Err(AdapterError::NotFound(format!(
                "GOFLAGS ({goflags}): {why}; remove it to attest Go tests"
            )));
        }
        let goroot = go.vars.get("GOROOT").cloned().unwrap_or_default();
        if goroot.is_empty() {
            return Err(AdapterError::NotFound("go env GOROOT is empty".into()));
        }
        let otmp = tempfile::Builder::new().prefix("vci-overlay-").tempdir()?;
        let odir = utf8_tmp(&otmp)?;
        let src = odir.join("vci_testlog.go");
        std::fs::write(&src, TESTLOG_SRC)?;
        let target = Utf8Path::new(&goroot).join("src/internal/testlog/vci_testlog.go");
        let mut replace = serde_json::Map::new();
        replace.insert(target.to_string(), src.to_string().into());
        let hooks = hooks::write_overlay(Utf8Path::new(&goroot), &odir).map(|entries| {
            for (k, v) in entries {
                replace.insert(k, v.into());
            }
        });
        let overlay = odir.join("overlay.json");
        std::fs::write(
            &overlay,
            serde_json::to_vec(&serde_json::json!({ "Replace": replace })).map_err(|e| {
                AdapterError::Parse {
                    what: "overlay".into(),
                    detail: e.to_string(),
                }
            })?,
        )?;
        let patterns: Vec<String> = files.iter().map(|f| pkg_arg(f)).collect();
        let pkgs = self.list_deps(&patterns, env);
        let modcheck = golist::ModuleCheck::default();
        per_file(files, |f| {
            let analysis = match &pkgs {
                Ok(pkgs) => {
                    let pat = pkg_arg(f);
                    let ip = pkgs
                        .iter()
                        .find(|p| p.for_test.is_empty() && p.match_.contains(&pat))
                        .map(|p| p.import_path.clone())
                        .unwrap_or_default();
                    Ok((
                        ip,
                        golist::analyse(
                            pkgs,
                            &pat,
                            &self.project_dir,
                            Utf8Path::new(&goroot),
                            &modcheck,
                        ),
                    ))
                }
                Err(e) => Err(e.clone()),
            };
            self.run_one(f, env, &overlay, analysis, &go, &hooks)
        })
    }

    /// `go test -count=1 -json <packages>` (all packages: `./...`) with a
    /// fresh TMPDIR, the same flags and per-package processes the
    /// attestations were made with; the JSON is written to stderr as the text
    /// `go test -v` prints.
    fn run_plain(&self, files: &[String], env: &ChildEnv) -> Result<Option<i32>, AdapterError> {
        let tmp = tempfile::Builder::new().prefix("vci-gotmp-").tempdir()?;
        let tmp_p = utf8_tmp(&tmp)?;
        let mut cmd = self.go_cmd(env);
        cmd.args(["test", "-count=1", "-json"]);
        if files.is_empty() {
            cmd.arg("./...");
        } else {
            cmd.args(files.iter().map(|f| pkg_arg(f)));
        }
        cmd.env("TMPDIR", tmp_p.as_str())
            .stdout(Stdio::piped())
            .stderr(std::io::stderr());
        let _ = writeln!(std::io::stderr(), "vci: {}", describe(&cmd));
        let mut child = cmd.spawn().map_err(|e| self.not_installed(e))?;
        if let Some(out) = child.stdout.take() {
            let mut err = std::io::stderr();
            for line in std::io::BufReader::new(out).lines() {
                let line = line?;
                match serde_json::from_str::<Value>(&line) {
                    Ok(v) => {
                        if let Some(s) = v.get("Output").and_then(Value::as_str) {
                            let _ = err.write_all(s.as_bytes());
                        }
                    }
                    Err(_) => {
                        let _ = writeln!(err, "{line}");
                    }
                }
            }
        }
        Ok(child.wait()?.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_env_and_paths() {
        let a = GoAdapter::new(Utf8Path::new("/nonexistent/proj"));
        assert_eq!(
            a.canonical_argv("go", "b"),
            ["go", "test", "-C", "go", "-count=1", "-json", "./b"]
        );
        assert_eq!(a.canonical_argv(".", ".").last().unwrap(), ".");
        assert_eq!(pkg_arg("b/c"), "./b/c");
        assert!(a.builtin_pass_through().contains(&"GOMODCACHE"));
        assert!(a.hashed_env_patterns().contains(&"GO*"));
        assert!(a.hashed_env_patterns().contains(&"!GOPATH"));
        assert_eq!(
            relative_to(Utf8Path::new("/r/p"), Utf8Path::new("/r/p/go.work")),
            "go.work"
        );
        assert_eq!(
            relative_to(Utf8Path::new("/r/p"), Utf8Path::new("/r/go.work")),
            "../go.work"
        );
        assert_eq!(arch_level_var("amd64"), Some("GOAMD64"));
        assert_eq!(arch_level_var("arm64"), Some("GOARM64"));
    }

    /// Every pass-through name is excluded from the hashed patterns, so
    /// strict mode keeps them and they are hashed only when read.
    #[test]
    fn pass_through_and_hashed_patterns_are_disjoint() {
        for p in GO_PASS_THROUGH.iter().filter(|p| p.starts_with("GO")) {
            assert!(
                GO_HASHED_ENV.contains(&format!("!{p}").as_str()),
                "{p} must be excluded from GO_HASHED_ENV"
            );
        }
    }

    #[test]
    fn normalise_resolves_dotdot_only_through_real_directories() {
        let t = tempfile::tempdir().unwrap();
        let r = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        std::fs::create_dir_all(r.join("a/b")).unwrap();
        std::fs::create_dir_all(r.join("c/d")).unwrap();
        assert_eq!(normalise(&r.join("a/b/../x")), r.join("a/x"));
        assert_eq!(normalise(&r.join("a/./x")), r.join("a/x"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(r.join("c/d"), r.join("a/l")).unwrap();
            // a/l/.. is c, not a: left as is (and then refused).
            assert_eq!(normalise(&r.join("a/l/../x")), r.join("a/l/../x"));
        }
    }

    #[test]
    fn goflags_that_name_unhashed_files_are_refused() {
        assert!(unsupported_goflag("").is_none());
        assert!(unsupported_goflag("-tags=integration -count=1 -pgo=auto -pgo=off").is_none());
        assert!(unsupported_goflag("-overlay=/x.json").is_some());
        assert!(unsupported_goflag("--modfile=alt.mod").is_some());
        assert!(unsupported_goflag("-pgo=prof.pgo").is_some());
        // Programs and files named by flags: only the flag text would be
        // compared, not what it names.
        for f in [
            "-toolexec=/x/wrap.sh",
            "--toolexec=wrap",
            "-exec=/x/run.sh",
            "-pkgdir=/x/pkgs",
            "-compiler=gccgo",
            "-asmflags=-I=/x/inc",
            "-asmflags=all=-Iinc",
            "-gcflags=-importcfg=cfg",
            "-gcflags=@args",
            "-ldflags=-linkmode=external",
            "-ldflags=-extld=clang",
        ] {
            assert!(unsupported_goflag(f).is_some(), "{f}");
        }
        for f in [
            "-gcflags=all=-N",
            "-gcflags=-l",
            "-ldflags=-s",
            "-compiler=gc",
        ] {
            assert!(unsupported_goflag(f).is_none(), "{f}");
        }
    }

    #[test]
    fn build_list_parses() {
        let m = parse_modules(
            r#"{"Path":"example.com/m","Main":true}
{"Path":"golang.org/x/sync","Version":"v0.20.0"}
{"Path":"example.com/lib","Version":"v1.0.0","Replace":{"Path":"../lib","Dir":"/r/lib"}}
{"Path":"example.com/f","Version":"v1.0.0","Replace":{"Path":"example.com/fork","Version":"v1.1.0"}}"#,
        )
        .unwrap();
        assert!(!m.contains_key("example.com/m"));
        assert_eq!(m["golang.org/x/sync"], ["v0.20.0"]);
        assert_eq!(m["example.com/lib"], ["local:../lib"]);
        assert_eq!(m["example.com/f"], ["v1.0.0 => example.com/fork@v1.1.0"]);
        assert!(parse_modules("{").is_err());
    }

    /// The overlaid logger is valid for the internal/testlog package it is
    /// compiled into (checked for real by the fixture tests); here: it uses
    /// the names that package defines and the env var the adapter sets.
    #[test]
    fn testlog_source_matches_the_adapter() {
        assert!(TESTLOG_SRC.contains("package testlog"));
        assert!(TESTLOG_SRC.contains(&format!("\"{TESTLOG_ENV}\"")));
        assert!(TESTLOG_SRC.contains("logger.CompareAndSwap(nil, &impl)"));
        assert!(TESTLOG_SRC.contains("\"os.StartProcess\""));
    }
}
