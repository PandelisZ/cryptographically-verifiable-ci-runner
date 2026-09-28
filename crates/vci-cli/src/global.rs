//! Global inputs of a test file: things every test depends on that the
//! collectors do not report per file (lockfiles, package.json, tsconfig chain,
//! runner config and what it imports, vci.toml) plus the test's own snapshot
//! files. Present files are recorded as reads, missing ones as probes, so that
//! creating one later also changes the global input root.
//!
//! Also the per-module context ([`module_context`]): the nearest
//! `package.json` and `tsconfig.json` of every module a test loaded, which
//! drive how its imports resolve (`imports`, `exports`, `main`, `type`) and
//! how it is transformed.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde_json::Value;
use vci_adapter::Adapter;
use vci_core::{Observation, RepoPath};

use crate::config::CONFIG_FILE;
use crate::util::strip_jsonc;

const PACKAGE_FILES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    ".npmrc",
];

const CODE_EXTS: &[&str] = &[
    ".ts", ".mts", ".cts", ".js", ".mjs", ".cjs", ".tsx", ".jsx", ".json",
];

struct Collector<'a> {
    repo_root: &'a Utf8Path,
    out: BTreeMap<RepoPath, Observation>,
    visited: BTreeSet<Utf8PathBuf>,
}

impl Collector<'_> {
    fn observe(&mut self, abs: &Utf8Path) -> Result<bool> {
        let rp = RepoPath::from_abs(self.repo_root, abs)
            .with_context(|| format!("global input {abs} is outside the repository"))?;
        let exists = abs.exists();
        let obs = if exists {
            Observation::Read
        } else {
            Observation::Probe
        };
        self.out.insert(rp, obs);
        Ok(exists)
    }

    fn tsconfig(&mut self, file: &Utf8Path, depth: usize) -> Result<()> {
        if depth > 16 || !self.visited.insert(file.to_owned()) {
            return Ok(());
        }
        let text = std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?;
        let v: Value = serde_json::from_str(&strip_jsonc(&text))
            .with_context(|| format!("parsing {file} (JSONC)"))?;
        let exts: Vec<String> = match v.get("extends") {
            None => vec![],
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => a
                .iter()
                .map(|x| x.as_str().map(str::to_owned).context("non-string extends"))
                .collect::<Result<_>>()?,
            Some(other) => bail!("{file}: unsupported extends {other}"),
        };
        let dir = file.parent().context("tsconfig without parent")?;
        for e in exts {
            if !(e.starts_with("./") || e.starts_with("../") || e.starts_with('/')) {
                // A package. Installed packages are covered by the lockfile, but
                // a workspace package (a node_modules symlink back into the
                // repository) is repository content: follow it.
                if let Some(p) = self.workspace_extends(dir, &e)
                    && self.observe(&p)?
                {
                    self.tsconfig(&p, depth + 1)?;
                }
                continue;
            }
            // TypeScript resolves `extends` lexically (`../base.json`).
            let mut p = normalize(&dir.join(&e));
            if !p.exists() && !e.ends_with(".json") {
                p = Utf8PathBuf::from(format!("{p}.json"));
            }
            if self.observe(&p)? {
                self.tsconfig(&p, depth + 1)?;
            }
        }
        Ok(())
    }

    /// Resolve a package `extends` the way TypeScript does (node_modules lookup
    /// from `dir` upward; a file, the file plus `.json`, or the package's
    /// `tsconfig` field / `tsconfig.json`). Returns the canonical path only when
    /// it lies in the repository outside any node_modules directory.
    fn workspace_extends(&self, dir: &Utf8Path, spec: &str) -> Option<Utf8PathBuf> {
        let mut d = Some(dir);
        while let Some(cur) = d {
            let base = cur.join("node_modules").join(spec);
            let mut tries = vec![base.clone(), Utf8PathBuf::from(format!("{base}.json"))];
            if base.is_dir() {
                let field = std::fs::read_to_string(base.join("package.json"))
                    .ok()
                    .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                    .and_then(|v| v.get("tsconfig").and_then(Value::as_str).map(str::to_owned));
                if let Some(f) = field {
                    tries.push(base.join(f));
                }
                tries.push(base.join("tsconfig.json"));
            }
            if let Some(found) = tries.into_iter().find(|p| p.is_file()) {
                let real = found.canonicalize_utf8().ok()?;
                let inside = real.starts_with(self.repo_root)
                    && !real
                        .strip_prefix(self.repo_root)
                        .ok()?
                        .components()
                        .any(|c| c.as_str() == "node_modules");
                return inside.then_some(real);
            }
            d = cur.parent();
        }
        None
    }

    /// Follow relative string literals in a config file (over-approximation of
    /// its imports, setup files and other referenced files).
    fn config_refs(&mut self, file: &Utf8Path, depth: usize) -> Result<()> {
        if depth > 8 || !self.visited.insert(file.to_owned()) {
            return Ok(());
        }
        let Ok(text) = std::fs::read_to_string(file) else {
            return Ok(());
        };
        let dir = file.parent().context("config without parent")?;
        for spec in relative_literals(&text) {
            let base = normalize(&dir.join(&spec));
            let mut tries = vec![base.clone()];
            for e in CODE_EXTS {
                tries.push(Utf8PathBuf::from(format!("{base}{e}")));
            }
            if let Some(stem) = spec.strip_suffix(".js") {
                tries.push(dir.join(format!("{stem}.ts")));
            }
            for e in CODE_EXTS {
                tries.push(base.join(format!("index{e}")));
            }
            match tries.iter().find(|p| p.is_file()) {
                Some(found) => {
                    let found = found.clone();
                    self.observe(&found)?;
                    if CODE_EXTS.iter().any(|e| found.as_str().ends_with(e)) {
                        self.config_refs(&found, depth + 1)?;
                    }
                }
                // A directory (an alias root such as `./src`) is not an input:
                // recording its listing would make every new file under it
                // invalidate every attestation. What the tests take from it is
                // recorded per file.
                None if base.is_dir() => {}
                None => {
                    self.observe(&base)?;
                }
            }
        }
        Ok(())
    }
}

/// Lexical normalisation (`a/b/../c` -> `a/c`), as TypeScript and Node's
/// `path.resolve` do.
fn normalize(p: &Utf8Path) -> Utf8PathBuf {
    let mut out = Utf8PathBuf::new();
    for c in p.components() {
        match c {
            camino::Utf8Component::CurDir => {}
            camino::Utf8Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_str()),
        }
    }
    out
}

/// String literal contents starting with `./` or `../` (no globs or templates).
fn relative_literals(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let q = b[i];
        if q == b'"' || q == b'\'' || q == b'`' {
            let start = i + 1;
            let mut j = start;
            while j < b.len() && b[j] != q && b[j] != b'\n' {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            if j < b.len() && b[j] == q {
                let s = &src[start..j];
                if (s.starts_with("./") || s.starts_with("../"))
                    && !s.contains('*')
                    && !s.contains("${")
                    && !s.contains('\\')
                {
                    out.push(s.to_owned());
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// The nearest `package.json` and `tsconfig.json` (with its `extends` chain)
/// of every module under `repo_root` (outside node_modules). Missing files
/// between a module and the nearest one are probes, so adding one is noticed.
pub fn module_context<'a>(
    repo_root: &Utf8Path,
    modules: impl IntoIterator<Item = &'a Utf8Path>,
) -> Result<Vec<(RepoPath, Observation)>> {
    let mut c = Collector {
        repo_root,
        out: BTreeMap::new(),
        visited: BTreeSet::new(),
    };
    // A directory already searched from means the search continued from it
    // upward to the nearest file (or the repo root): nothing more to record.
    let mut pj_done: BTreeSet<Utf8PathBuf> = BTreeSet::new();
    let mut ts_done: BTreeSet<Utf8PathBuf> = BTreeSet::new();
    for m in modules {
        let Ok(rel) = m.strip_prefix(repo_root) else {
            continue;
        };
        if rel.components().any(|x| x.as_str() == "node_modules") {
            continue;
        }
        for (name, done) in [
            ("package.json", &mut pj_done),
            ("tsconfig.json", &mut ts_done),
        ] {
            let mut dir = m.parent();
            while let Some(d) = dir {
                if !d.starts_with(repo_root) || !done.insert(d.to_owned()) {
                    break;
                }
                let f = d.join(name);
                if c.observe(&f)? {
                    if name == "tsconfig.json" {
                        c.tsconfig(&f, 0)?;
                    }
                    break;
                }
                if d == repo_root {
                    break;
                }
                dir = d.parent();
            }
        }
    }
    Ok(c.out.into_iter().collect())
}

/// Python project files looked up from the project dir up to the repo root
/// (a uv workspace keeps `uv.lock` at its root).
const PYTHON_PROJECT_FILES: &[&str] = &["pyproject.toml", "uv.lock", ".python-version", "uv.toml"];

/// Global observations for a pytest test file: `vci.toml`; `pyproject.toml`,
/// `uv.lock`, `.python-version` and `uv.toml` from the project dir up to
/// the repo root; and, in every directory from the test file's directory up
/// to the project dir, every pytest config file name and `conftest.py`.
/// Present files are reads, missing ones probes (so creating a
/// `tests/pytest.ini` that would move pytest's rootdir, or a new
/// `conftest.py`, changes the global input root).
fn pytest_observations(
    c: &mut Collector,
    repo_root: &Utf8Path,
    project_dir: &Utf8Path,
    test_abs: &Utf8Path,
) -> Result<()> {
    let mut dir = Some(project_dir);
    while let Some(d) = dir {
        for n in PYTHON_PROJECT_FILES {
            c.observe(&d.join(n))?;
        }
        if d == repo_root || !d.starts_with(repo_root) {
            break;
        }
        dir = d.parent();
    }
    if !test_abs.starts_with(project_dir) {
        bail!("test file {test_abs} is outside the project dir {project_dir}");
    }
    let mut dir = test_abs.parent();
    while let Some(d) = dir {
        for n in vci_adapter::PYTEST_CONFIG_NAMES {
            c.observe(&d.join(n))?;
        }
        c.observe(&d.join("conftest.py"))?;
        if d == project_dir {
            break;
        }
        dir = d.parent();
    }
    Ok(())
}

/// Module and workspace files looked up from the project dir up to the repo
/// root: the module that is built, its checksums, and a workspace that would
/// change which modules are used.
const GO_PROJECT_FILES: &[&str] = &["go.mod", "go.sum", "go.work", "go.work.sum"];

/// Global observations for a Go package: `vci.toml`; `go.mod`, `go.sum`,
/// `go.work`, `go.work.sum` from the project dir up to the repo root; and
/// `vendor/modules.txt` in the project dir (its presence switches the build
/// to the vendor directory). Present files are reads, missing ones probes.
fn go_observations(c: &mut Collector, repo_root: &Utf8Path, project_dir: &Utf8Path) -> Result<()> {
    let mut dir = Some(project_dir);
    while let Some(d) = dir {
        for n in GO_PROJECT_FILES {
            c.observe(&d.join(n))?;
        }
        if d == repo_root || !d.starts_with(repo_root) {
            break;
        }
        dir = d.parent();
    }
    c.observe(&project_dir.join("vendor/modules.txt"))?;
    Ok(())
}

/// Files looked up from a Cargo project dir up to the repo root: the lock
/// file (it must exist at the workspace root; a missing one elsewhere is
/// recorded as absent), the toolchain rustup picks, and cargo config.
const CARGO_PROJECT_FILES: &[&str] = &[
    "Cargo.lock",
    "rust-toolchain",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    ".cargo/config",
];

/// Global observations for a Cargo unit (`<package dir>#<target>`):
/// `vci.toml`; `Cargo.toml` in every directory from the package dir up to
/// the repo root (cargo walks up to find the workspace); `Cargo.lock`,
/// `rust-toolchain(.toml)` and `.cargo/config(.toml)` from the project dir
/// up to the repo root. Present files are reads, missing ones probes.
fn cargo_observations(
    c: &mut Collector,
    repo_root: &Utf8Path,
    project_dir: &Utf8Path,
    unit_abs: &Utf8Path,
) -> Result<()> {
    let pkg = vci_adapter::unit_package_dir(unit_abs);
    if !pkg.starts_with(project_dir) {
        bail!("package dir {pkg} is outside the project dir {project_dir}");
    }
    let mut dir = Some(pkg.as_path());
    while let Some(d) = dir {
        c.observe(&d.join("Cargo.toml"))?;
        if d == repo_root || !d.starts_with(repo_root) {
            break;
        }
        dir = d.parent();
    }
    let mut dir = Some(project_dir);
    while let Some(d) = dir {
        for n in CARGO_PROJECT_FILES {
            c.observe(&d.join(n))?;
        }
        if d == repo_root || !d.starts_with(repo_root) {
            break;
        }
        dir = d.parent();
    }
    Ok(())
}

/// Global observations for the test file at `test_abs`.
pub fn observations(
    repo_root: &Utf8Path,
    adapter: &dyn Adapter,
    test_abs: &Utf8Path,
) -> Result<Vec<(RepoPath, Observation)>> {
    let project_dir = adapter.project_dir();
    let mut c = Collector {
        repo_root,
        out: BTreeMap::new(),
        visited: BTreeSet::new(),
    };
    c.observe(&repo_root.join(CONFIG_FILE))?;
    match adapter.name() {
        "vitest" => {}
        "pytest" => {
            pytest_observations(&mut c, repo_root, project_dir, test_abs)?;
            return Ok(c.out.into_iter().collect());
        }
        "go" => {
            go_observations(&mut c, repo_root, project_dir)?;
            return Ok(c.out.into_iter().collect());
        }
        "cargo" => {
            cargo_observations(&mut c, repo_root, project_dir, test_abs)?;
            return Ok(c.out.into_iter().collect());
        }
        other => bail!("no global input rules for adapter {other:?}"),
    }

    // Package metadata and lockfiles from the project dir up to the repo root.
    let mut dir = Some(project_dir);
    while let Some(d) = dir {
        for n in PACKAGE_FILES {
            c.observe(&d.join(n))?;
        }
        if d == repo_root {
            break;
        }
        dir = d.parent();
    }

    // Runner config candidates and what they reference.
    for p in adapter.config_candidates() {
        if c.observe(&p)? {
            c.config_refs(&p, 0)?;
        }
    }

    // tsconfig.json from the test's directory up to the repo root, with
    // relative `extends` chains.
    let mut dir = test_abs.parent();
    while let Some(d) = dir {
        let ts = d.join("tsconfig.json");
        if c.observe(&ts)? {
            c.tsconfig(&ts, 0)?;
        }
        if d == repo_root || !d.starts_with(repo_root) {
            break;
        }
        dir = d.parent();
    }

    for s in adapter.snapshot_candidates(test_abs) {
        c.observe(&s)?;
    }
    Ok(c.out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_repo() -> (tempfile::TempDir, Utf8PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        (t, root)
    }

    fn write(root: &Utf8Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn find<'a>(obs: &'a [(RepoPath, Observation)], p: &str) -> Option<&'a Observation> {
        obs.iter().find(|(rp, _)| rp.as_str() == p).map(|(_, o)| o)
    }

    /// Regression: a config literal that names a directory (the common
    /// `new URL('./src', import.meta.url)` alias) made every new file under it
    /// invalidate every attestation. Directories are not global inputs.
    #[test]
    fn config_directory_literal_is_not_a_listing() {
        let (_t, root) = tmp_repo();
        write(
            &root,
            "vitest.config.ts",
            "export default { resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } }, test: { setupFiles: ['./setup'] } };\n",
        );
        write(&root, "setup.ts", "export {};\n");
        write(&root, "src/a.ts", "export {};\n");
        write(&root, "src/a.test.ts", "export {};\n");
        let adapter = vci_adapter::VitestAdapter::new(&root);
        let obs = observations(&root, &adapter, &root.join("src/a.test.ts")).unwrap();
        assert_eq!(find(&obs, "setup.ts"), Some(&Observation::Read));
        assert_eq!(find(&obs, "src"), None, "{obs:?}");
    }

    /// Regression: `extends` naming a package that is a workspace symlink
    /// into the repository was assumed to be covered by the lockfile.
    #[cfg(unix)]
    #[test]
    fn tsconfig_extends_into_a_workspace_package_is_followed() {
        let (_t, root) = tmp_repo();
        write(
            &root,
            "tsconfig.json",
            r#"{ "extends": ["@me/tsconfig/base.json", "@me/tsconfig", "@ext/tsconfig/x.json"] }"#,
        );
        write(
            &root,
            "packages/tsconfig/base.json",
            r#"{ "extends": "./inner.json" }"#,
        );
        write(&root, "packages/tsconfig/inner.json", "{}");
        write(&root, "packages/tsconfig/tsconfig.json", "{}");
        write(
            &root,
            "packages/tsconfig/package.json",
            r#"{"name":"@me/tsconfig"}"#,
        );
        // A real (non-workspace) package: covered by the lockfile, not recorded.
        write(&root, "node_modules/@ext/tsconfig/x.json", "{}");
        std::fs::create_dir_all(root.join("node_modules/@me")).unwrap();
        std::os::unix::fs::symlink(
            "../../packages/tsconfig",
            root.join("node_modules/@me/tsconfig"),
        )
        .unwrap();
        write(&root, "src/a.test.ts", "export {};\n");
        let adapter = vci_adapter::VitestAdapter::new(&root);
        let obs = observations(&root, &adapter, &root.join("src/a.test.ts")).unwrap();
        for p in [
            "packages/tsconfig/base.json",
            "packages/tsconfig/inner.json",
            "packages/tsconfig/tsconfig.json",
        ] {
            assert_eq!(find(&obs, p), Some(&Observation::Read), "{p}: {obs:?}");
        }
        assert!(
            !obs.iter()
                .any(|(p, _)| p.as_str().starts_with("node_modules/")),
            "{obs:?}"
        );
    }

    #[test]
    fn pytest_global_inputs() {
        let (_t, root) = tmp_repo();
        write(&root, "py/pyproject.toml", "[tool.pytest.ini_options]\n");
        write(&root, "py/uv.lock", "version = 1\n");
        write(&root, "py/tests/conftest.py", "\n");
        write(&root, "py/tests/unit/test_x.py", "\n");
        write(&root, "py/conftest.py", "\n");
        let adapter = vci_adapter::PytestAdapter::new(&root.join("py"));
        let obs = observations(&root, &adapter, &root.join("py/tests/unit/test_x.py")).unwrap();
        for (p, want) in [
            ("vci.toml", Observation::Probe),
            ("py/pyproject.toml", Observation::Read),
            ("py/uv.lock", Observation::Read),
            ("py/.python-version", Observation::Probe),
            ("pyproject.toml", Observation::Probe),
            ("uv.lock", Observation::Probe),
            ("py/tests/conftest.py", Observation::Read),
            ("py/conftest.py", Observation::Read),
            ("py/tests/unit/conftest.py", Observation::Probe),
            ("py/tests/unit/pytest.ini", Observation::Probe),
            ("py/tests/setup.cfg", Observation::Probe),
            ("py/tox.ini", Observation::Probe),
        ] {
            assert_eq!(find(&obs, p), Some(&want), "{p}: {obs:?}");
        }
        // Nothing of the Vitest rules (package.json, tsconfig) and nothing
        // above the project dir for pytest config / conftest.
        assert_eq!(find(&obs, "py/package.json"), None);
        assert_eq!(find(&obs, "py/tests/unit/tsconfig.json"), None);
        assert_eq!(find(&obs, "conftest.py"), None);
    }

    #[test]
    fn go_global_inputs() {
        let (_t, root) = tmp_repo();
        write(&root, "go.work", "go 1.25.0\nuse ./svc\n");
        write(&root, "svc/go.mod", "module example.com/svc\n");
        write(&root, "svc/go.sum", "");
        write(&root, "svc/b/b_test.go", "package b\n");
        let adapter = vci_adapter::GoAdapter::new(&root.join("svc"));
        let obs = observations(&root, &adapter, &root.join("svc/b")).unwrap();
        for (p, want) in [
            ("vci.toml", Observation::Probe),
            ("svc/go.mod", Observation::Read),
            ("svc/go.sum", Observation::Read),
            ("svc/go.work", Observation::Probe),
            ("svc/go.work.sum", Observation::Probe),
            ("go.work", Observation::Read),
            ("go.mod", Observation::Probe),
            ("svc/vendor/modules.txt", Observation::Probe),
        ] {
            assert_eq!(find(&obs, p), Some(&want), "{p}: {obs:?}");
        }
        assert_eq!(find(&obs, "svc/package.json"), None);
    }

    #[test]
    fn cargo_global_inputs() {
        let (_t, root) = tmp_repo();
        write(
            &root,
            "rs/Cargo.toml",
            "[workspace]\nmembers = [\"crates/a\"]\n",
        );
        write(&root, "rs/Cargo.lock", "version = 4\n");
        write(&root, "rs/crates/a/Cargo.toml", "[package]\nname = \"a\"\n");
        write(&root, "rs/.cargo/config.toml", "[build]\n");
        write(
            &root,
            "rust-toolchain.toml",
            "[toolchain]\nchannel = \"1.96.0\"\n",
        );
        let adapter = vci_adapter::CargoAdapter::new(&root.join("rs"));
        let obs = observations(&root, &adapter, &root.join("rs/crates/a#lib")).unwrap();
        for (p, want) in [
            ("vci.toml", Observation::Probe),
            ("rs/crates/a/Cargo.toml", Observation::Read),
            ("rs/crates/Cargo.toml", Observation::Probe),
            ("rs/Cargo.toml", Observation::Read),
            ("Cargo.toml", Observation::Probe),
            ("rs/Cargo.lock", Observation::Read),
            ("Cargo.lock", Observation::Probe),
            ("rs/.cargo/config.toml", Observation::Read),
            ("rs/.cargo/config", Observation::Probe),
            ("rust-toolchain.toml", Observation::Read),
            ("rs/rust-toolchain", Observation::Probe),
        ] {
            assert_eq!(find(&obs, p), Some(&want), "{p}: {obs:?}");
        }
        assert_eq!(find(&obs, "rs/crates/a/Cargo.lock"), None);
    }

    #[test]
    fn finds_relative_literals() {
        let src = r#"import a from "./a"; import b from '../b.js'; const g = "./src/**"; const t = `./x-${n}`; x("react")"#;
        assert_eq!(relative_literals(src), ["./a", "../b.js"]);
    }
}
