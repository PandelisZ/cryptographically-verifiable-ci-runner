//! Running a unit's test executable the way `cargo test` runs it.
//!
//! `cargo test` builds and then runs each test executable with the package
//! directory as working directory and an environment it adds to its own
//! (cargo's `core/compiler/compilation.rs`, `fill_env` and
//! `target_process`). vci builds each unit with `cargo test --no-run` in the
//! cargo lane and runs the executable itself, so that several units run at
//! once (cargo holds the build directory lock for the whole of a
//! `cargo test`). [`TestEnv`] is what cargo adds; checked against cargo
//! 1.96's `cargo test` (Homebrew's and rustup's) by dumping the environment a
//! test sees:
//!
//! * `CARGO` (the cargo binary), `CARGO_MANIFEST_DIR`, `CARGO_MANIFEST_PATH`
//!   and the `CARGO_PKG_*` fields of the package;
//! * `CARGO_BIN_EXE_<name>` for every bin target the unit's build reports,
//!   for integration tests and benches only;
//! * `OUT_DIR` and the `cargo::rustc-env` variables of the package's build
//!   script;
//! * the dynamic library search path (`DYLD_FALLBACK_LIBRARY_PATH` on macOS,
//!   `LD_LIBRARY_PATH` elsewhere, `PATH` on Windows): the build scripts'
//!   `rustc-link-search` directories inside the build output, the profile
//!   directory, its `deps`, the sysroot's target library directory, then
//!   what the environment already had (with macOS's defaults when that is
//!   empty);
//! * the `[env]` table of the cargo configuration (a variable already set
//!   wins unless `force = true`);
//! * when cargo is rustup's proxy, what the proxy set for cargo (and cargo
//!   passes on): `CARGO_HOME`, `RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`,
//!   `RUSTUP_TOOLCHAIN_SOURCE`, `RUST_RECURSION_COUNT` ([`proxy_env`]), and
//!   the toolchain's library directory in the library search path.
//!
//! `CARGO_CRATE_NAME` and `CARGO_TARGET_TMPDIR` are compile-time variables
//! only: `cargo test` does not set them for the test process, so vci does
//! not either.

use std::ffi::OsString;
use std::process::{Command, Stdio};

use camino::{Utf8Path, Utf8PathBuf};

use crate::ChildEnv;
use crate::vitest::{apply_env, describe};

/// Env var: how many test executables run at once (default: the number of
/// CPUs).
pub const JOBS_ENV: &str = "VCI_CARGO_JOBS";

/// How many units the execution pool runs at once.
pub(crate) fn pool_size() -> usize {
    std::env::var(JOBS_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
}

/// The package fields cargo exports to a test process (`cargo metadata`
/// carries them).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PkgFields {
    pub name: String,
    pub version: String,
    pub authors: Vec<String>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub license: Option<String>,
    pub license_file: Option<String>,
    pub rust_version: Option<String>,
    pub readme: Option<String>,
    /// Absolute `Cargo.toml` path, as cargo spells it.
    pub manifest_path: Utf8PathBuf,
}

/// A variable of the cargo configuration's `[env]` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigEnv {
    pub name: String,
    pub value: String,
    /// Overrides a variable already in the environment.
    pub force: bool,
}

/// The `[env]` tables of `files` (highest precedence first; the first one
/// that sets a variable wins), with `relative = true` values resolved
/// against the directory holding the file's `.cargo` directory.
pub(crate) fn config_env(files: &[super::config::ConfigFile]) -> Vec<ConfigEnv> {
    let mut out: Vec<ConfigEnv> = Vec::new();
    for c in files {
        let Some(t) = c
            .table
            .as_ref()
            .ok()
            .and_then(|t| t.get("env"))
            .and_then(toml::Value::as_table)
        else {
            continue;
        };
        for (k, v) in t {
            if out.iter().any(|e| &e.name == k) {
                continue;
            }
            let (value, force, relative) = match v {
                toml::Value::String(s) => (s.clone(), false, false),
                toml::Value::Table(t) => {
                    let Some(s) = t.get("value").and_then(toml::Value::as_str) else {
                        continue;
                    };
                    let flag = |n: &str| t.get(n).and_then(toml::Value::as_bool).unwrap_or(false);
                    (s.to_owned(), flag("force"), flag("relative"))
                }
                _ => continue,
            };
            let value = if relative {
                // `<dir>/.cargo/config.toml` -> `<dir>`.
                c.path
                    .parent()
                    .and_then(Utf8Path::parent)
                    .map_or(value.clone(), |d| d.join(&value).into_string())
            } else {
                value
            };
            out.push(ConfigEnv {
                name: k.clone(),
                value,
                force,
            });
        }
    }
    out
}

/// What `cargo test` adds to the environment of one unit's test process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TestEnv {
    /// The cargo binary (`CARGO`).
    pub cargo_exe: String,
    pub pkg: PkgFields,
    /// `CARGO_BIN_EXE_<name>` -> the bin's executable (integration tests and
    /// benches only; empty otherwise).
    pub bins: Vec<(String, Utf8PathBuf)>,
    /// The package's build script output directory (`OUT_DIR`).
    pub out_dir: Option<Utf8PathBuf>,
    /// `cargo::rustc-env` variables of the package's build script.
    pub script_env: Vec<(String, String)>,
    /// `linked_paths` of every build script of the build (`kind=path`).
    pub linked_paths: Vec<String>,
    /// The profile directory (`<target dir>/debug`).
    pub root_output: Utf8PathBuf,
    /// `<sysroot>/lib/rustlib/<host>/lib`.
    pub sysroot_libdir: Utf8PathBuf,
    /// `<sysroot>/lib` when cargo is started through rustup's proxy (rustup
    /// puts it in front of the library search path of what it starts).
    pub rustup_lib: Option<Utf8PathBuf>,
    /// The `[env]` table of the cargo configuration.
    pub config_env: Vec<ConfigEnv>,
    /// What rustup's proxy set for cargo ([`proxy_env`]).
    pub proxy_env: Vec<(String, String)>,
}

/// The library search path variable of `os` (`std::env::consts::OS`).
pub(crate) fn dylib_var(os: &str) -> &'static str {
    match os {
        "macos" | "ios" => "DYLD_FALLBACK_LIBRARY_PATH",
        "windows" => "PATH",
        "aix" => "LIBPATH",
        _ => "LD_LIBRARY_PATH",
    }
}

/// `version` split as semver (`1.2.3-beta.1+meta` -> 1, 2, 3, `beta.1`).
fn version_parts(version: &str) -> (String, String, String, String) {
    let core = version.split_once('+').map_or(version, |(c, _)| c);
    let (nums, pre) = core.split_once('-').unwrap_or((core, ""));
    let mut it = nums.split('.');
    let mut next = || it.next().unwrap_or_default().to_owned();
    let (major, minor, patch) = (next(), next(), next());
    (major, minor, patch, pre.to_owned())
}

impl TestEnv {
    /// The variables to set on top of the child environment, in the order
    /// cargo sets them (a later one wins). `os` is
    /// `std::env::consts::OS`; `var` reads the child environment.
    pub(crate) fn vars(
        &self,
        os: &str,
        var: &dyn Fn(&str) -> Option<String>,
    ) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self.proxy_env.clone();
        let sep = if os == "windows" { ';' } else { ':' };
        // Library search path: build output first, then what is there.
        let mut search: Vec<String> = Vec::new();
        let mut native: Vec<Utf8PathBuf> = self
            .linked_paths
            .iter()
            .map(|p| Utf8PathBuf::from(p.split_once('=').map_or(p.as_str(), |(_, v)| v)))
            .filter(|p| p.starts_with(&self.root_output))
            .collect();
        native.sort();
        native.dedup();
        search.extend(native.into_iter().map(Utf8PathBuf::into_string));
        search.push(self.root_output.to_string());
        search.push(self.root_output.join("deps").into_string());
        search.push(self.sysroot_libdir.to_string());
        let dylib_var = dylib_var(os);
        let mut existing: Vec<String> = var(dylib_var)
            .map(|v| {
                v.split(sep)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let macos_defaults = || {
            let mut d: Vec<String> = Vec::new();
            if let Some(h) = var("HOME") {
                d.push(Utf8Path::new(&h).join("lib").into_string());
            }
            d.push("/usr/local/lib".into());
            d.push("/usr/lib".into());
            d
        };
        if let Some(lib) = &self.rustup_lib {
            // rustup's proxy: its library directory in front (with macOS's
            // defaults when there was nothing).
            if existing.is_empty() && os == "macos" {
                existing = macos_defaults();
            }
            existing.insert(0, lib.to_string());
        }
        if existing.starts_with(&search) {
            search = existing;
        } else {
            let empty = existing.is_empty();
            search.extend(existing);
            if empty && os == "macos" {
                search.extend(macos_defaults());
            }
        }
        out.push((dylib_var.to_owned(), search.join(&sep.to_string())));
        out.extend(self.script_env.iter().cloned());
        if let Some(d) = &self.out_dir {
            out.push(("OUT_DIR".into(), d.to_string()));
        }
        for (name, exe) in &self.bins {
            out.push((format!("CARGO_BIN_EXE_{name}"), exe.to_string()));
        }
        out.push(("CARGO".into(), self.cargo_exe.clone()));
        let p = &self.pkg;
        let dir = p
            .manifest_path
            .parent()
            .map(Utf8Path::to_string)
            .unwrap_or_default();
        let (major, minor, patch, pre) = version_parts(&p.version);
        let opt = |v: &Option<String>| v.clone().unwrap_or_default();
        out.extend([
            ("CARGO_MANIFEST_DIR".to_owned(), dir),
            (
                "CARGO_MANIFEST_PATH".to_owned(),
                p.manifest_path.to_string(),
            ),
            ("CARGO_PKG_VERSION_MAJOR".to_owned(), major),
            ("CARGO_PKG_VERSION_MINOR".to_owned(), minor),
            ("CARGO_PKG_VERSION_PATCH".to_owned(), patch),
            ("CARGO_PKG_VERSION_PRE".to_owned(), pre),
            ("CARGO_PKG_VERSION".to_owned(), p.version.clone()),
            ("CARGO_PKG_NAME".to_owned(), p.name.clone()),
            ("CARGO_PKG_DESCRIPTION".to_owned(), opt(&p.description)),
            ("CARGO_PKG_HOMEPAGE".to_owned(), opt(&p.homepage)),
            ("CARGO_PKG_REPOSITORY".to_owned(), opt(&p.repository)),
            ("CARGO_PKG_LICENSE".to_owned(), opt(&p.license)),
            ("CARGO_PKG_LICENSE_FILE".to_owned(), opt(&p.license_file)),
            ("CARGO_PKG_AUTHORS".to_owned(), p.authors.join(":")),
            ("CARGO_PKG_RUST_VERSION".to_owned(), opt(&p.rust_version)),
            ("CARGO_PKG_README".to_owned(), opt(&p.readme)),
        ]);
        for e in &self.config_env {
            let set = out.iter().any(|(k, _)| k == &e.name) || var(&e.name).is_some();
            if set && !e.force {
                continue;
            }
            out.push((e.name.clone(), e.value.clone()));
        }
        out
    }
}

/// How to start one unit's test executable.
#[derive(Debug, Clone)]
pub(crate) struct Spec {
    pub exe: Utf8PathBuf,
    /// The package directory.
    pub cwd: Utf8PathBuf,
    /// Set on top of the child environment ([`TestEnv::vars`]).
    pub vars: Vec<(String, String)>,
}

/// What running a test executable gave.
#[derive(Debug)]
pub(crate) struct Ran {
    pub success: bool,
    pub stdout: String,
    pub stderr: Vec<u8>,
    pub elapsed_ms: u64,
    /// `vci: <command> (exit N)`.
    pub header: String,
}

/// Run `spec` with the child environment `env` and a fresh empty TMPDIR.
pub(crate) fn run(spec: &Spec, env: &ChildEnv) -> std::io::Result<Ran> {
    let tmp = tempfile::Builder::new().prefix("vci-cargotmp-").tempdir()?;
    let mut cmd = Command::new(spec.exe.as_std_path());
    cmd.current_dir(&spec.cwd).stdin(Stdio::null());
    apply_env(&mut cmd, env);
    for (k, v) in &spec.vars {
        cmd.env(k, v);
    }
    cmd.env("TMPDIR", tmp.path());
    let started = std::time::Instant::now();
    let out = cmd.output()?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let status = out.status.code();
    Ok(Ran {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: out.stderr,
        elapsed_ms,
        header: format!(
            "vci: (in {}) {} (exit {})\n",
            spec.cwd,
            describe(&cmd),
            status.map_or_else(|| "signal".to_owned(), |c| c.to_string())
        ),
    })
}

/// The variables rustup's proxy sets for the toolchain binary it starts
/// (besides the library search path, which [`TestEnv::rustup_lib`] covers);
/// cargo passes them on to the tests it runs.
const PROXY_VARS: &[&str] = &[
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "RUSTUP_TOOLCHAIN_SOURCE",
    "RUST_RECURSION_COUNT",
];

/// The external cargo subcommand [`proxy_env`] runs.
const ENV_SUBCOMMAND: &str = "vci-proxy-env";

/// What rustup's proxy sets ([`PROXY_VARS`]) for the cargo `cmd` starts
/// (`cargo` as the lane starts it, with the child environment): `cmd` runs
/// `cargo vci-proxy-env`, an external subcommand (a script in a temporary
/// directory put in front of `path`, the child's `PATH`) that prints the
/// environment cargo gave it. Empty where that cannot be done (Windows, or
/// it fails): the tests then run without them.
pub(crate) fn proxy_env(mut cmd: Command, path: Option<String>) -> Vec<(String, String)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let Ok(dir) = tempfile::Builder::new().prefix("vci-cargoenv-").tempdir() else {
            return vec![];
        };
        let script = dir.path().join(format!("cargo-{ENV_SUBCOMMAND}"));
        let made = std::fs::write(&script, "#!/bin/sh\nexec /usr/bin/env\n").and_then(|()| {
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        });
        if made.is_err() {
            return vec![];
        }
        let mut dirs = vec![dir.path().to_path_buf()];
        dirs.extend(path.iter().flat_map(std::env::split_paths));
        let Ok(path) = std::env::join_paths(dirs) else {
            return vec![];
        };
        cmd.arg(ENV_SUBCOMMAND).env("PATH", path);
        match cmd.output() {
            Ok(out) if out.status.success() => {
                parse_proxy_env(&String::from_utf8_lossy(&out.stdout))
            }
            _ => vec![],
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (cmd, path);
        vec![]
    }
}

/// The [`PROXY_VARS`] in `env` output (`NAME=value` lines), in that order.
fn parse_proxy_env(text: &str) -> Vec<(String, String)> {
    PROXY_VARS
        .iter()
        .filter_map(|k| {
            let v = text
                .lines()
                .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))?;
            Some(((*k).to_owned(), v.to_owned()))
        })
        .collect()
}

/// The `CARGO` value cargo gives its children: `$CARGO` when set, else the
/// binary that runs (rustup's proxy starts the toolchain's own cargo,
/// `<sysroot>/bin/cargo`; Linux reports the resolved path, macOS the path it
/// was started by). `program` is what vci starts (`cargo` or `$VCI_CARGO`).
/// Also whether it is rustup's proxy.
pub(crate) fn cargo_exe(
    program: &OsString,
    sysroot: &Utf8Path,
    var: &dyn Fn(&str) -> Option<String>,
) -> (String, bool) {
    let program = Utf8PathBuf::from(program.to_string_lossy().into_owned());
    let resolved = if program.components().count() > 1 {
        Some(program.clone())
    } else {
        var("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .filter_map(|d| Utf8PathBuf::from_path_buf(d).ok())
                .map(|d| d.join(&program))
                .find(|p| p.is_file())
        })
    };
    let real = resolved.as_ref().and_then(|p| p.canonicalize_utf8().ok());
    let rustup = real
        .as_ref()
        .and_then(|r| r.file_stem())
        .is_some_and(|s| s == "rustup" || s == "rustup-init");
    if let Some(c) = var("CARGO") {
        return (c, rustup);
    }
    let in_sysroot = sysroot.join(if cfg!(windows) {
        "bin/cargo.exe"
    } else {
        "bin/cargo"
    });
    if rustup && in_sysroot.is_file() {
        return (in_sysroot.into_string(), true);
    }
    let shown = if cfg!(target_os = "linux") {
        real.or(resolved)
    } else {
        resolved
    };
    (
        shown.map_or_else(|| program.to_string(), Utf8PathBuf::into_string),
        rustup,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> TestEnv {
        TestEnv {
            cargo_exe: "/opt/bin/cargo".into(),
            pkg: PkgFields {
                name: "envprobe".into(),
                version: "1.2.3-beta.1+meta".into(),
                authors: vec!["A <a@x>".into(), "B".into()],
                description: Some("probe".into()),
                license: Some("MIT".into()),
                readme: Some("README.md".into()),
                manifest_path: "/w/p/Cargo.toml".into(),
                ..Default::default()
            },
            bins: vec![],
            out_dir: Some("/t/debug/build/p-1/out".into()),
            script_env: vec![("FROM_BUILD".into(), "yes".into())],
            linked_paths: vec![
                "native=/t/debug/build/p-1/out/nat".into(),
                "/usr/local/opt/x/lib".into(),
                "dependency=/t/debug/build/a-2/out".into(),
            ],
            root_output: "/t/debug".into(),
            sysroot_libdir: "/sys/lib/rustlib/host/lib".into(),
            rustup_lib: None,
            config_env: vec![],
            proxy_env: vec![],
        }
    }

    fn get<'a>(vars: &'a [(String, String)], k: &str) -> Option<&'a str> {
        vars.iter()
            .rev()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }

    /// The environment `cargo test` 1.96 gave a test of a package like this
    /// (see the module doc).
    #[test]
    fn test_env_mirrors_cargo_test() {
        let none = |_: &str| None;
        let vars = base().vars("macos", &none);
        for (k, v) in [
            ("CARGO", "/opt/bin/cargo"),
            ("CARGO_MANIFEST_DIR", "/w/p"),
            ("CARGO_MANIFEST_PATH", "/w/p/Cargo.toml"),
            ("CARGO_PKG_NAME", "envprobe"),
            ("CARGO_PKG_VERSION", "1.2.3-beta.1+meta"),
            ("CARGO_PKG_VERSION_MAJOR", "1"),
            ("CARGO_PKG_VERSION_MINOR", "2"),
            ("CARGO_PKG_VERSION_PATCH", "3"),
            ("CARGO_PKG_VERSION_PRE", "beta.1"),
            ("CARGO_PKG_AUTHORS", "A <a@x>:B"),
            ("CARGO_PKG_DESCRIPTION", "probe"),
            ("CARGO_PKG_HOMEPAGE", ""),
            ("CARGO_PKG_REPOSITORY", ""),
            ("CARGO_PKG_LICENSE", "MIT"),
            ("CARGO_PKG_LICENSE_FILE", ""),
            ("CARGO_PKG_RUST_VERSION", ""),
            ("CARGO_PKG_README", "README.md"),
            ("OUT_DIR", "/t/debug/build/p-1/out"),
            ("FROM_BUILD", "yes"),
        ] {
            assert_eq!(get(&vars, k), Some(v), "{k}");
        }
        // Compile-time only.
        for k in ["CARGO_CRATE_NAME", "CARGO_TARGET_TMPDIR"] {
            assert_eq!(get(&vars, k), None, "{k}");
        }
        assert!(!vars.iter().any(|(k, _)| k.starts_with("CARGO_BIN_EXE_")));
        // Build output inside the target dir first (a search path outside
        // it is not added), the profile dir before its deps, the sysroot,
        // then macOS's defaults for an empty variable.
        assert_eq!(
            get(&vars, "DYLD_FALLBACK_LIBRARY_PATH"),
            Some(
                "/t/debug/build/a-2/out:/t/debug/build/p-1/out/nat:/t/debug:/t/debug/deps:/sys/lib/rustlib/host/lib:/usr/local/lib:/usr/lib"
            )
        );
        let home = |k: &str| (k == "HOME").then(|| "/h".to_owned());
        assert!(
            get(&base().vars("macos", &home), "DYLD_FALLBACK_LIBRARY_PATH")
                .unwrap()
                .ends_with(":/sys/lib/rustlib/host/lib:/h/lib:/usr/local/lib:/usr/lib")
        );
        // Linux: what was there follows; no defaults.
        let existing = |k: &str| (k == "LD_LIBRARY_PATH").then(|| "/opt/l:/opt/m".to_owned());
        let vars = base().vars("linux", &existing);
        assert_eq!(get(&vars, "DYLD_FALLBACK_LIBRARY_PATH"), None);
        assert_eq!(
            get(&vars, "LD_LIBRARY_PATH"),
            Some(
                "/t/debug/build/a-2/out:/t/debug/build/p-1/out/nat:/t/debug:/t/debug/deps:/sys/lib/rustlib/host/lib:/opt/l:/opt/m"
            )
        );
        // Already in front (a test started by a test): not repeated.
        let nested = base().vars("linux", &none);
        let inner = get(&nested, "LD_LIBRARY_PATH").unwrap().to_owned();
        let again = move |k: &str| (k == "LD_LIBRARY_PATH").then(|| inner.clone());
        assert_eq!(
            get(&base().vars("linux", &again), "LD_LIBRARY_PATH"),
            get(&nested, "LD_LIBRARY_PATH")
        );
        // rustup's proxy puts the toolchain's lib dir after cargo's.
        let mut e = base();
        e.rustup_lib = Some("/sys/lib".into());
        assert!(
            get(&e.vars("macos", &home), "DYLD_FALLBACK_LIBRARY_PATH")
                .unwrap()
                .ends_with(":/sys/lib/rustlib/host/lib:/sys/lib:/h/lib:/usr/local/lib:/usr/lib")
        );
        assert_eq!(
            get(&e.vars("windows", &none), "PATH"),
            Some(
                "/t/debug/build/a-2/out;/t/debug/build/p-1/out/nat;/t/debug;/t/debug/deps;/sys/lib/rustlib/host/lib;/sys/lib"
            )
        );
    }

    #[test]
    fn bins_and_config_env() {
        let mut e = base();
        e.bins = vec![("tool".into(), "/t/debug/tool".into())];
        e.config_env = vec![
            ConfigEnv {
                name: "APP_LEVEL".into(),
                value: "3".into(),
                force: false,
            },
            ConfigEnv {
                name: "HOME_SET".into(),
                value: "config".into(),
                force: false,
            },
            ConfigEnv {
                name: "FORCED".into(),
                value: "config".into(),
                force: true,
            },
            ConfigEnv {
                name: "CARGO_PKG_NAME".into(),
                value: "nope".into(),
                force: false,
            },
        ];
        let var = |k: &str| matches!(k, "HOME_SET" | "FORCED").then(|| "env".to_owned());
        let vars = e.vars("linux", &var);
        assert_eq!(get(&vars, "CARGO_BIN_EXE_tool"), Some("/t/debug/tool"));
        assert_eq!(get(&vars, "APP_LEVEL"), Some("3"));
        assert_eq!(get(&vars, "HOME_SET"), None, "set in the environment");
        assert_eq!(get(&vars, "FORCED"), Some("config"));
        assert_eq!(get(&vars, "CARGO_PKG_NAME"), Some("envprobe"));
    }

    #[test]
    fn config_env_tables() {
        let file = |path: &str, text: &str| super::super::config::ConfigFile {
            path: path.into(),
            inside: true,
            table: toml::from_str(text).map_err(|e: toml::de::Error| e.to_string()),
        };
        let files = [
            file(
                "/w/.cargo/config.toml",
                "[env]\nA = \"1\"\nB = { value = \"data\", relative = true }\nC = { value = \"x\", force = true }\n",
            ),
            file("/.cargo/config.toml", "[env]\nA = \"outer\"\nD = \"4\"\n"),
        ];
        let e = config_env(&files);
        let find = |n: &str| e.iter().find(|x| x.name == n).cloned();
        assert_eq!(find("A").unwrap().value, "1", "highest precedence wins");
        assert_eq!(find("B").unwrap().value, "/w/data");
        assert!(find("C").unwrap().force);
        assert_eq!(find("D").unwrap().value, "4");
    }

    /// rustup's proxy: what it set for cargo reaches the test (cargo's own
    /// variables still win), read from `env`'s output.
    #[test]
    fn proxy_env_is_passed_on() {
        let text = "PATH=/x\nRUSTUP_TOOLCHAIN=stable-aarch64-apple-darwin\nCARGO_HOME=/h/.cargo\nRUST_RECURSION_COUNT=1\nRUSTUP_HOME=/h/.rustup\nRUSTUP_TOOLCHAIN_SOURCE=default\nCARGO=/t/cargo\nNOT_RUSTUP_HOME=no\n";
        let vars = parse_proxy_env(text);
        assert_eq!(
            vars,
            [
                ("CARGO_HOME", "/h/.cargo"),
                ("RUSTUP_HOME", "/h/.rustup"),
                ("RUSTUP_TOOLCHAIN", "stable-aarch64-apple-darwin"),
                ("RUSTUP_TOOLCHAIN_SOURCE", "default"),
                ("RUST_RECURSION_COUNT", "1"),
            ]
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
        );
        let mut e = base();
        e.proxy_env = vars;
        e.proxy_env.push(("CARGO".into(), "/proxy/cargo".into()));
        let none = |_: &str| None;
        let out = e.vars("macos", &none);
        assert_eq!(
            get(&out, "RUSTUP_TOOLCHAIN"),
            Some("stable-aarch64-apple-darwin")
        );
        assert_eq!(get(&out, "CARGO_HOME"), Some("/h/.cargo"));
        assert_eq!(
            get(&out, "CARGO"),
            Some("/opt/bin/cargo"),
            "cargo's own wins"
        );
    }

    /// The proxy's variables as `cargo` itself reports them to an external
    /// subcommand (rustup's proxy when `VCI_TEST_RUSTUP_CARGO` names one;
    /// skipped otherwise).
    #[test]
    fn proxy_env_from_a_real_proxy() {
        let Ok(cargo) = std::env::var("VCI_TEST_RUSTUP_CARGO") else {
            return;
        };
        let vars = proxy_env(Command::new(cargo), std::env::var("PATH").ok());
        let names: Vec<&str> = vars.iter().map(|(k, _)| k.as_str()).collect();
        for k in [
            "CARGO_HOME",
            "RUSTUP_HOME",
            "RUSTUP_TOOLCHAIN",
            "RUST_RECURSION_COUNT",
        ] {
            assert!(names.contains(&k), "{k}: {vars:?}");
        }
    }

    #[test]
    fn versions_split_like_semver() {
        assert_eq!(
            version_parts("0.10.2"),
            ("0".into(), "10".into(), "2".into(), String::new())
        );
        assert_eq!(version_parts("1.0.0-rc.1+b5").3, "rc.1");
    }
}
