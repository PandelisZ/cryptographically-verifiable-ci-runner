//! `go list -json` output, the import closure of a package's test binary, and
//! what that closure contributes to an attestation: compile-time inputs
//! (every source, embedded and ignored file of every package inside the
//! repository, the directory listings that decide which files are compiled),
//! external modules as `path@version`, and the reasons the test cannot be
//! attested (taints).
//!
//! The closure starts at the test variants of the package (`P [P.test]`,
//! `P_test [P.test]`) and the package itself, not at the generated test main,
//! so packages only the `testing` harness links (`internal/fuzz`, which
//! imports `os/exec`) are not held against the test.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;

use super::{dirhash, scan};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct GoModule {
    pub path: String,
    pub version: String,
    pub main: bool,
    pub dir: String,
    pub go_mod: String,
    pub sum: String,
    pub replace: Option<Box<GoModule>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct GoError {
    pub err: String,
}

/// One package of `go list -json` (the fields vci uses).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct GoPackage {
    pub dir: String,
    pub import_path: String,
    pub name: String,
    pub for_test: String,
    pub standard: bool,
    pub module: Option<GoModule>,
    #[serde(rename = "Match")]
    pub match_: Vec<String>,
    pub go_files: Vec<String>,
    pub cgo_files: Vec<String>,
    #[serde(rename = "CFiles")]
    pub c_files: Vec<String>,
    #[serde(rename = "CXXFiles")]
    pub cxx_files: Vec<String>,
    pub m_files: Vec<String>,
    pub h_files: Vec<String>,
    pub f_files: Vec<String>,
    pub s_files: Vec<String>,
    pub swig_files: Vec<String>,
    #[serde(rename = "SwigCXXFiles")]
    pub swig_cxx_files: Vec<String>,
    pub syso_files: Vec<String>,
    pub test_go_files: Vec<String>,
    pub x_test_go_files: Vec<String>,
    pub ignored_go_files: Vec<String>,
    pub ignored_other_files: Vec<String>,
    pub embed_patterns: Vec<String>,
    pub embed_files: Vec<String>,
    pub test_embed_patterns: Vec<String>,
    pub test_embed_files: Vec<String>,
    pub x_test_embed_patterns: Vec<String>,
    pub x_test_embed_files: Vec<String>,
    pub imports: Vec<String>,
    pub error: Option<GoError>,
    pub deps_errors: Vec<GoError>,
}

impl GoPackage {
    /// Import path without the ` [P.test]` suffix of test variants.
    pub fn base_path(&self) -> &str {
        self.import_path
            .split_once(" [")
            .map_or(self.import_path.as_str(), |(p, _)| p)
    }

    /// True for a package that has test files (a vci unit).
    pub fn has_tests(&self) -> bool {
        !self.test_go_files.is_empty() || !self.x_test_go_files.is_empty()
    }

    /// Every file of the package that the compiler, the assembler, cgo or
    /// go:embed can read, plus the files build constraints exclude here (they
    /// may be compiled on another platform or with other tags). `tests`:
    /// the package under test, whose `_test.go` files and test embeds are
    /// compiled too; a dependency's are not.
    fn all_files(&self, tests: bool) -> impl Iterator<Item = &String> {
        let own = [
            &self.test_go_files,
            &self.x_test_go_files,
            &self.test_embed_files,
            &self.x_test_embed_files,
        ];
        self.build_files()
            .chain(own.into_iter().filter(move |_| tests).flatten())
            .filter(move |f| tests || !f.ends_with("_test.go"))
    }

    /// The files a dependency contributes to the build (no test files).
    fn build_files(&self) -> impl Iterator<Item = &String> {
        [
            &self.go_files,
            &self.cgo_files,
            &self.c_files,
            &self.cxx_files,
            &self.m_files,
            &self.h_files,
            &self.f_files,
            &self.s_files,
            &self.swig_files,
            &self.swig_cxx_files,
            &self.syso_files,
            &self.ignored_go_files,
            &self.ignored_other_files,
            &self.embed_files,
        ]
        .into_iter()
        .flatten()
    }

    /// Source files whose inclusion build constraints decide (Go, assembly,
    /// C and headers, compiled here or excluded here); not embedded files.
    /// `tests` as for [`Self::all_files`].
    fn constrained_sources(&self, tests: bool) -> impl Iterator<Item = &String> {
        [
            &self.go_files,
            &self.cgo_files,
            &self.c_files,
            &self.cxx_files,
            &self.m_files,
            &self.h_files,
            &self.f_files,
            &self.s_files,
            &self.syso_files,
            &self.test_go_files,
            &self.x_test_go_files,
            &self.ignored_go_files,
            &self.ignored_other_files,
        ]
        .into_iter()
        .flatten()
        .filter(move |f| tests || !f.ends_with("_test.go"))
    }

    /// Native code that is compiled or linked into the test binary.
    fn native_files(&self) -> Vec<&String> {
        [
            &self.cgo_files,
            &self.c_files,
            &self.cxx_files,
            &self.m_files,
            &self.f_files,
            &self.swig_files,
            &self.swig_cxx_files,
            &self.syso_files,
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    fn embed_patterns_all(&self, tests: bool) -> impl Iterator<Item = &String> {
        let own = [&self.test_embed_patterns, &self.x_test_embed_patterns];
        self.embed_patterns
            .iter()
            .chain(own.into_iter().filter(move |_| tests).flatten())
    }
}

/// Parse the concatenated JSON objects `go list -json` prints.
pub(crate) fn parse_packages(text: &str) -> Result<Vec<GoPackage>, String> {
    serde_json::Deserializer::from_str(text)
        .into_iter::<GoPackage>()
        .map(|r| r.map_err(|e| e.to_string()))
        .collect()
}

/// Taint prefix for a `net` package in the closure; `policy.go_allow_net`
/// waives exactly these.
pub const GO_NET_TAINT: &str = "go:net:";

/// Standard packages whose presence in the closure makes a test
/// non-attestable, and why.
const STD_REFUSED: &[(&str, &str)] = &[
    (
        "os/user",
        "os/user reads the user database without going through package os (libc on macOS, cgo), so what it returns is not observed",
    ),
    ("plugin", "plugin loads native code at run time"),
    (
        "runtime/cgo",
        "cgo is linked in: C code reads files and the environment without going through package os",
    ),
];

/// Identifiers in the code of a non-standard Go source file (the test's own
/// files, packages of the repository and of external modules) that make the
/// test non-attestable, whether called or not (`var environ = os.Environ`
/// is a function value): things package os does not report to the test
/// log and vci's standard library hooks cannot see either.
const SOURCE_IDENTS: &[(&str, &str)] = &[(
    "Environ",
    "refers to Environ (os.Environ, syscall.Environ, exec.Cmd.Environ enumerate the environment; every variable would be an input)",
)];

/// Text anywhere in a non-standard Go source file (comments included) that
/// makes the test non-attestable.
const SOURCE_TEXT: &[(&str, &str)] = &[(
    "go:linkname",
    "uses //go:linkname (it can call runtime and syscall internals that are not observed)",
)];

/// Standard packages whose results can differ between architectures for the
/// same inputs (floating-point code the compiler may fuse differently); a
/// non-standard package importing one is pinned to the attesting
/// architecture.
const FLOAT_STD: &[&str] = &["math", "math/cmplx", "math/rand", "math/rand/v2"];

/// GOOS values go/build knows (internal/syslist, Go 1.26).
const KNOWN_OS: &[&str] = &[
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "hurd",
    "illumos",
    "ios",
    "js",
    "linux",
    "nacl",
    "netbsd",
    "openbsd",
    "plan9",
    "solaris",
    "wasip1",
    "windows",
    "zos",
];

/// GOARCH values go/build knows (internal/syslist, Go 1.26).
const KNOWN_ARCH: &[&str] = &[
    "386",
    "amd64",
    "amd64p32",
    "arm",
    "armbe",
    "arm64",
    "arm64be",
    "loong64",
    "mips",
    "mipsle",
    "mips64",
    "mips64le",
    "mips64p32",
    "mips64p32le",
    "ppc",
    "ppc64",
    "ppc64le",
    "riscv",
    "riscv64",
    "s390",
    "s390x",
    "sparc",
    "sparc64",
    "wasm",
];

/// Whether a Go source file's inclusion depends on GOOS/GOARCH: a
/// `_GOOS`, `_GOARCH` or `_GOOS_GOARCH` name suffix (go/build's rule), or a
/// `//go:build` / `// +build` line naming an OS, an architecture (including
/// levels such as `amd64.v3`) or `unix`.
pub(crate) fn platform_conditional(name: &str, content: &str) -> bool {
    if platform_file_name(name) {
        return true;
    }
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with("package ") || t == "package" {
            break;
        }
        let expr = if let Some(e) = t.strip_prefix("//go:build") {
            e
        } else if let Some(e) = t.strip_prefix("// +build") {
            e
        } else {
            continue;
        };
        for tok in expr.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')) {
            let tag = tok.split('.').next().unwrap_or("");
            if tag == "unix" || KNOWN_OS.contains(&tag) || KNOWN_ARCH.contains(&tag) {
                return true;
            }
        }
    }
    false
}

fn platform_file_name(name: &str) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    let stem = base.split('.').next().unwrap_or(base);
    let Some(i) = stem.find('_') else {
        return false;
    };
    let mut parts: Vec<&str> = stem[i..].split('_').collect();
    if parts.last() == Some(&"test") {
        parts.pop();
    }
    let n = parts.len();
    (n >= 2 && KNOWN_OS.contains(&parts[n - 2]) && KNOWN_ARCH.contains(&parts[n - 1]))
        || (n >= 1 && (KNOWN_OS.contains(&parts[n - 1]) || KNOWN_ARCH.contains(&parts[n - 1])))
}

/// `(path, version)` identifying an external module, or `None` for a module
/// whose code is a local directory (a `replace` with a path, or no module).
pub(crate) fn module_id(m: &GoModule) -> Option<(String, String)> {
    match &m.replace {
        Some(r) if r.version.is_empty() => None,
        Some(r) => Some((
            m.path.clone(),
            format!("{} => {}@{}", m.version, r.path, r.version),
        )),
        None if m.version.is_empty() => None,
        None => Some((m.path.clone(), m.version.clone())),
    }
}

/// Memoised module cache integrity checks (dirhash of the extracted module
/// against its go.sum hash), shared by the packages of one run.
#[derive(Default)]
pub(crate) struct ModuleCheck {
    done: Mutex<HashMap<String, Result<(), String>>>,
}

impl ModuleCheck {
    fn check(&self, m: &GoModule) -> Result<(), String> {
        let src = m.replace.as_deref().unwrap_or(m);
        let key = format!("{}@{}", src.path, src.version);
        if let Some(r) = self
            .done
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
        {
            return r.clone();
        }
        let r = if src.sum.is_empty() {
            Err(format!("{key} has no go.sum hash"))
        } else if src.dir.is_empty() {
            Err(format!("{key} is not in the module cache"))
        } else {
            match dirhash::hash_dir(Utf8Path::new(&src.dir), &key) {
                Ok(h) if h == src.sum => Ok(()),
                Ok(h) => Err(format!(
                    "{key} in the module cache ({}) does not match go.sum: {h}, want {}",
                    src.dir, src.sum
                )),
                Err(e) => Err(format!("hashing {key} in {}: {e}", src.dir)),
            }
        };
        self.done
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key, r.clone());
        r
    }
}

/// What one package's test contributes to its attestation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Analysis {
    /// Compile-time inputs (read).
    pub files: BTreeSet<Utf8PathBuf>,
    /// Paths looked up and not found at compile time (an assembler
    /// `#include` resolved elsewhere).
    pub probes: BTreeSet<Utf8PathBuf>,
    /// Directory listings (package directories, go:embed trees).
    pub dirs: BTreeSet<Utf8PathBuf>,
    /// External modules as (path, version).
    pub externals: BTreeSet<(String, String)>,
    pub taints: Vec<String>,
    /// Local Go files whose inclusion depends on GOOS/GOARCH, or whose code
    /// refers to `GOOS`/`GOARCH` (`runtime.GOOS`): the test may behave or
    /// read differently on another platform.
    pub platform_files: BTreeSet<Utf8PathBuf>,
    /// Why the test's results may differ on another architecture
    /// (floating-point code in a non-standard package of the closure).
    pub arch_specific: BTreeSet<String>,
    /// `Test*`/`Fuzz*` functions the package's compiled `_test.go` files
    /// declare: each must have run and passed.
    pub declared_tests: BTreeSet<String>,
}

/// Directories an embed pattern can take files from: the static prefix of the
/// pattern and, when that is a directory, every directory below it (a
/// pattern matching a directory embeds its whole tree). Symlinks are not
/// followed (go:embed rejects them).
fn embed_dirs(pkg_dir: &Utf8Path, pattern: &str, out: &mut BTreeSet<Utf8PathBuf>) {
    let pattern = pattern.strip_prefix("all:").unwrap_or(pattern);
    let mut prefix = pkg_dir.to_owned();
    for comp in pattern.split('/') {
        if comp.contains(['*', '?', '[', '\\']) {
            break;
        }
        prefix.push(comp);
    }
    let mut stack = vec![prefix];
    while let Some(d) = stack.pop() {
        match std::fs::symlink_metadata(&d) {
            Ok(m) if m.is_dir() => {}
            _ => continue,
        }
        if let Ok(rd) = d.read_dir_utf8() {
            for e in rd.flatten() {
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(e.path().to_owned());
                }
            }
        }
        out.insert(d);
    }
}

/// Scan one non-standard Go file: refusals (taints), and what its code
/// refers to.
fn scan_source(path: &Utf8Path, taints: &mut Vec<String>) -> Option<scan::GoTokens> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            for (tok, why) in SOURCE_TEXT {
                if text.contains(tok) {
                    taints.push(format!("go:source: {path} {why}"));
                }
            }
            let t = scan::go_tokens(&text);
            for (id, why) in SOURCE_IDENTS {
                if t.idents.contains(*id) {
                    taints.push(format!("go:source: {path} {why}"));
                }
            }
            Some(t)
        }
        Err(e) => {
            taints.push(format!("go:source: cannot read {path}: {e}"));
            None
        }
    }
}

/// The closure of the test of the package matched by `pattern` (as given to
/// `go list`), and what it contributes. `project_dir` decides what is local:
/// packages under it (including `vendor/`) and packages of modules without a
/// version (a `replace` with a directory, go.work members) are hashed file by
/// file; the caller refuses local files outside the repository. `goroot`
/// holds the assembler's shared headers (`pkg/include`).
pub(crate) fn analyse(
    pkgs: &[GoPackage],
    pattern: &str,
    project_dir: &Utf8Path,
    goroot: &Utf8Path,
    modcheck: &ModuleCheck,
) -> Analysis {
    let mut a = Analysis::default();
    let by_path: BTreeMap<&str, &GoPackage> =
        pkgs.iter().map(|p| (p.import_path.as_str(), p)).collect();
    let Some(unit) = pkgs
        .iter()
        .find(|p| p.for_test.is_empty() && p.match_.iter().any(|m| m == pattern))
    else {
        a.taints.push(format!("go list: no package for {pattern}"));
        return a;
    };
    let ip = unit.import_path.as_str();
    let xtest = format!("{ip}_test");
    let unit_dir = Utf8PathBuf::from(&unit.dir);
    for f in unit.test_go_files.iter().chain(&unit.x_test_go_files) {
        match std::fs::read_to_string(unit_dir.join(f)) {
            Ok(text) => a.declared_tests.extend(scan::declared_tests(&text)),
            Err(e) => a
                .taints
                .push(format!("go:source: cannot read {}: {e}", unit_dir.join(f))),
        }
    }
    let mut stack: Vec<&GoPackage> = pkgs.iter().filter(|p| p.for_test == ip).collect();
    stack.push(unit);
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut closure: Vec<&GoPackage> = Vec::new();
    while let Some(p) = stack.pop() {
        if !seen.insert(p.import_path.as_str()) {
            continue;
        }
        closure.push(p);
        for imp in &p.imports {
            if imp == "C" {
                a.taints.push(format!(
                    "go:cgo: {} imports \"C\" (C code reads files and the environment without going through package os)",
                    p.base_path()
                ));
                continue;
            }
            match by_path.get(imp.as_str()) {
                Some(q) => stack.push(q),
                None => a.taints.push(format!(
                    "go list: {} imports {imp}, which is not listed",
                    p.import_path
                )),
            }
        }
    }
    closure.sort_by(|x, y| x.import_path.cmp(&y.import_path));
    for p in closure {
        let base = p.base_path();
        // The package under test (its test variants included) compiles its
        // `_test.go` files; a dependency's are not part of this test.
        let is_unit = base == ip || base == xtest;
        if let Some(e) = &p.error {
            a.taints
                .push(format!("go list: {}: {}", p.import_path, e.err));
        }
        for e in &p.deps_errors {
            a.taints
                .push(format!("go list: {}: {}", p.import_path, e.err));
        }
        let native = p.native_files();
        if p.standard {
            if base == "net" {
                a.taints.push(format!(
                    "{GO_NET_TAINT} the test links package net (network I/O is not observed; set policy.go_allow_net to vouch that these tests use no network)"
                ));
            }
            if let Some((_, why)) = STD_REFUSED.iter().find(|(n, _)| *n == base) {
                a.taints.push(format!("go:{base}: {why}"));
            }
            if !p.cgo_files.is_empty() && base != "runtime/cgo" {
                a.taints.push(format!(
                    "go:cgo: {base} is built with cgo here (C code is not observed)"
                ));
            }
            continue;
        }
        if p.imports.iter().any(|i| i == "syscall") {
            a.taints.push(format!(
                "go:syscall: {base} imports syscall (system calls made directly are not observed)"
            ));
        }
        if base.starts_with("golang.org/x/sys/") && base != "golang.org/x/sys/cpu" {
            a.taints.push(format!(
                "go:x/sys: {base} is linked (system calls made directly are not observed)"
            ));
        }
        if !native.is_empty() {
            a.taints.push(format!(
                "go:native: {base} compiles or links native code ({}) that is not observed",
                native
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if let Some(m) = p.imports.iter().find(|i| FLOAT_STD.contains(&i.as_str())) {
            a.arch_specific
                .insert(format!("{base} imports {m} (floating-point results)"));
        }
        let dir = Utf8PathBuf::from(&p.dir);
        if p.dir.is_empty() || !dir.is_absolute() {
            a.taints
                .push(format!("go list: {} has no directory", p.import_path));
            continue;
        }
        let external = if dir.starts_with(project_dir) {
            None
        } else {
            p.module
                .as_ref()
                .and_then(|m| module_id(m).map(|id| (m, id)))
        };
        for f in [&p.go_files, &p.cgo_files].into_iter().flatten() {
            let path = dir.join(f);
            let Some(t) = scan_source(&path, &mut a.taints) else {
                continue;
            };
            if t.uses_floating_point() {
                a.arch_specific
                    .insert(format!("{base}: floating point in {f}"));
            }
            // A runtime platform check in the repository's own code: the
            // test may take another path (read another file) elsewhere.
            if external.is_none() && t.platform_dependent() {
                a.platform_files.insert(path);
            }
        }
        match external {
            Some((m, id)) => {
                if let Err(e) = modcheck.check(m) {
                    a.taints.push(format!("go:module-cache: {e}"));
                }
                a.externals.insert(id);
            }
            None => {
                a.dirs.insert(dir.clone());
                for f in p.all_files(is_unit) {
                    a.files.insert(dir.join(f));
                }
                for pat in p.embed_patterns_all(is_unit) {
                    embed_dirs(&dir, pat, &mut a.dirs);
                }
                for f in p.constrained_sources(is_unit) {
                    let path = dir.join(f);
                    let text = std::fs::read_to_string(&path).unwrap_or_default();
                    if platform_conditional(f, &text) {
                        a.platform_files.insert(path);
                    }
                }
                if !p.s_files.is_empty() {
                    let inc = scan::follow_includes(&dir, &p.s_files, goroot, super::normalise);
                    a.files.extend(inc.files);
                    a.probes.extend(inc.probes);
                    a.taints.extend(inc.taints);
                }
                // Profile-guided optimisation: `go test` builds the package
                // under test with its default.pgo (-pgo=auto).
                let pgo = dir.join("default.pgo");
                if p.import_path == ip && pgo.is_file() {
                    a.files.insert(pgo);
                }
                if let Some(m) = &p.module {
                    let gomod = m
                        .replace
                        .as_deref()
                        .map_or(m.go_mod.as_str(), |r| r.go_mod.as_str());
                    if !gomod.is_empty() {
                        a.files.insert(Utf8PathBuf::from(gomod));
                    }
                }
            }
        }
    }
    a.taints.sort();
    a.taints.dedup();
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_file_names_follow_go_build() {
        for (name, want) in [
            ("b_linux.go", true),
            ("b_linux_test.go", true),
            ("b_darwin_arm64.go", true),
            ("b_amd64.go", true),
            ("b_amd64_test.go", true),
            ("linux.go", false),
            ("b.go", false),
            ("b_test.go", false),
            ("b_linux.pb.go", true),
            ("b_notanos.go", false),
            ("x/y/b_windows.go", true),
        ] {
            assert_eq!(platform_conditional(name, ""), want, "{name}");
        }
    }

    #[test]
    fn build_constraints_naming_a_platform() {
        let c = |s: &str| platform_conditional("b.go", s);
        assert!(c("//go:build linux\n\npackage b\n"));
        assert!(c(
            "// Copyright\n\n//go:build !windows && cgo\n\npackage b\n"
        ));
        assert!(c("//go:build unix\npackage b\n"));
        assert!(c("//go:build amd64.v3\npackage b\n"));
        assert!(c("// +build darwin\n\npackage b\n"));
        assert!(!c("//go:build integration\n\npackage b\n"));
        assert!(!c("//go:build ignore\npackage b\n"));
        assert!(
            !c("package b\n\n//go:build linux\n"),
            "after the package clause"
        );
        assert!(!c("package b\n"));
    }

    #[test]
    fn module_ids() {
        let m = GoModule {
            path: "golang.org/x/sync".into(),
            version: "v0.20.0".into(),
            ..Default::default()
        };
        assert_eq!(
            module_id(&m),
            Some(("golang.org/x/sync".into(), "v0.20.0".into()))
        );
        let mut r = m.clone();
        r.replace = Some(Box::new(GoModule {
            path: "example.com/fork".into(),
            version: "v1.0.0".into(),
            ..Default::default()
        }));
        assert_eq!(
            module_id(&r).unwrap().1,
            "v0.20.0 => example.com/fork@v1.0.0"
        );
        r.replace = Some(Box::new(GoModule {
            path: "../fork".into(),
            dir: "/x/fork".into(),
            ..Default::default()
        }));
        assert_eq!(module_id(&r), None, "a directory replacement is local code");
        assert_eq!(module_id(&GoModule::default()), None);
    }

    fn pkg(ip: &str, dir: &str, imports: &[&str]) -> GoPackage {
        GoPackage {
            import_path: ip.into(),
            dir: dir.into(),
            imports: imports.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// The closure starts at the test variants, not at the test main: the
    /// harness's own dependencies (os/exec through internal/fuzz, net through
    /// nothing) are not held against the test; `net` reached from the test
    /// is; every local package brings its directory listing and files.
    #[test]
    fn closure_from_the_test_variants() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        std::fs::create_dir_all(root.join("b")).unwrap();
        std::fs::create_dir_all(root.join("lib/data/sub")).unwrap();
        std::fs::write(root.join("b/b.go"), "package b\n").unwrap();
        std::fs::write(root.join("b/b_test.go"), "package b\n").unwrap();
        std::fs::write(root.join("b/b_linux.go"), "package b\n").unwrap();
        std::fs::write(root.join("lib/lib.go"), "package lib\n").unwrap();
        std::fs::write(root.join("lib/data/sub/x.txt"), "x").unwrap();
        let d = |s: &str| root.join(s).to_string();
        let mut b = pkg("m/b", &d("b"), &["m/lib"]);
        b.match_ = vec!["./b".into()];
        b.go_files = vec!["b.go".into()];
        b.ignored_go_files = vec!["b_linux.go".into()];
        let mut bt = pkg("m/b [m/b.test]", &d("b"), &["m/lib", "testing"]);
        bt.for_test = "m/b".into();
        bt.go_files = vec!["b.go".into(), "b_test.go".into()];
        let mut lib = pkg("m/lib", &d("lib"), &["net/http"]);
        lib.go_files = vec!["lib.go".into()];
        lib.embed_patterns = vec!["data".into()];
        let mut net_http = pkg("net/http", "/goroot/src/net/http", &["net"]);
        net_http.standard = true;
        let mut net = pkg("net", "/goroot/src/net", &[]);
        net.standard = true;
        let mut testing = pkg("testing", "/goroot/src/testing", &[]);
        testing.standard = true;
        let mut main = pkg(
            "m/b.test",
            &d("b"),
            &["m/b [m/b.test]", "testing/internal/testdeps"],
        );
        main.name = "main".into();
        let mut deps = pkg("testing/internal/testdeps", "/g", &["os/exec"]);
        deps.standard = true;
        let mut exec = pkg("os/exec", "/g", &[]);
        exec.standard = true;
        let pkgs = vec![b, bt, lib, net_http, net, testing, main, deps, exec];
        let a = analyse(&pkgs, "./b", &root, &root, &ModuleCheck::default());
        assert!(
            a.taints.iter().any(|t| t.starts_with(GO_NET_TAINT)),
            "{:?}",
            a.taints
        );
        assert_eq!(a.taints.len(), 1, "{:?}", a.taints);
        for f in ["b/b.go", "b/b_test.go", "b/b_linux.go", "lib/lib.go"] {
            assert!(a.files.contains(&root.join(f)), "{f}: {:?}", a.files);
        }
        for dir in ["b", "lib", "lib/data", "lib/data/sub"] {
            assert!(a.dirs.contains(&root.join(dir)), "{dir}: {:?}", a.dirs);
        }
        assert_eq!(
            a.platform_files.iter().collect::<Vec<_>>(),
            [&root.join("b/b_linux.go")]
        );
        assert!(a.externals.is_empty());
        let a = analyse(&pkgs, "./nope", &root, &root, &ModuleCheck::default());
        assert!(a.taints[0].contains("no package"), "{:?}", a.taints);
    }

    #[test]
    fn syscall_cgo_and_source_tokens_taint() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        std::fs::create_dir_all(root.join("b")).unwrap();
        std::fs::write(
            root.join("b/b_test.go"),
            "package b\nimport \"os\"\nvar e = os.Environ()\n",
        )
        .unwrap();
        let d = root.join("b").to_string();
        let mut b = pkg("m/b", &d, &[]);
        b.match_ = vec!["./b".into()];
        let mut bt = pkg(
            "m/b [m/b.test]",
            &d,
            &["syscall", "C", "golang.org/x/sys/unix"],
        );
        bt.for_test = "m/b".into();
        bt.go_files = vec!["b_test.go".into()];
        bt.syso_files = vec!["blob.syso".into()];
        let mut sys = pkg("syscall", "/g", &[]);
        sys.standard = true;
        let mut unix = pkg("golang.org/x/sys/unix", "/mod/x/sys/unix", &[]);
        unix.module = Some(GoModule {
            path: "golang.org/x/sys".into(),
            version: "v0.1.0".into(),
            ..Default::default()
        });
        let a = analyse(
            &[b, bt, sys, unix],
            "./b",
            &root,
            &root,
            &ModuleCheck::default(),
        );
        let all = a.taints.join("\n");
        for want in [
            "go:syscall:",
            "go:cgo:",
            "go:x/sys:",
            "go:native:",
            "os.Environ",
            "go:module-cache:",
        ] {
            assert!(all.contains(want), "{want} in {all}");
        }
        assert_eq!(
            a.externals.iter().next().unwrap(),
            &("golang.org/x/sys".to_owned(), "v0.1.0".to_owned())
        );
    }
}
