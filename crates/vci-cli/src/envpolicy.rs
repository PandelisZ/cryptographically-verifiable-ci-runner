//! Environment variable policy (docs/ENV.md): which variables reach the test
//! process, which are hashed, and the per-file env config digest.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;

use vci_core::hash::blake3_hex;

use crate::config::{EnvConfig, EnvMode};
use crate::util::{glob_match, name_match};

/// Always visible to tests, hashed only when a test is seen reading one
/// (except [`NEVER_HASHED`]). These differ between a laptop and a CI runner by
/// definition (`CI`, `HOME`, `USER`, `TMPDIR`, `LANG`, ...), so a test that
/// reads one is only skipped where the value is the same.
pub const BUILTIN_PASS_THROUGH: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_*",
    "TERM",
    "CI",
    "NODE_OPTIONS",
    "VCI_*",
    "VITEST*",
    // Needed for node to start at all on Windows.
    "SYSTEMROOT",
    "SystemRoot",
    "COMSPEC",
    "PATHEXT",
    "WINDIR",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
];

/// Built-in pass-through variables that stay unhashed even when read, when
/// the adapter is not known (the union of [`never_hashed`]'s lists): vci's
/// own plumbing (`VCI_*`; `PYTHONPATH`, which vci sets to its collector for
/// pytest and `vci run` refuses to attest a read of), Vitest's per-worker
/// variables, and `NODE_OPTIONS` (vci sets it for Vitest and hashes the
/// user's value globally).
pub const NEVER_HASHED: &[&str] = &["VCI_*", "VITEST*", "NODE_OPTIONS", "PYTHONPATH"];

/// Variables vci sets itself for one run of the tests (where a collector
/// writes its output): never inputs. Every other `VCI_*` variable
/// (`VCI_BASE_REF`, `VCI_JOBS`, ...) is the user's and reaches the tests as
/// built-in pass-through, so a test that reads one gets it hashed.
const VCI_RUN_VARS: &[&str] = &["VCI_OUT", "VCI_WORKER", "VCI_LIST_OUT", "VCI_GO_TESTLOG"];

/// Built-in pass-through variables an adapter's test process sees with
/// values that are not inputs, so reads of them stay unhashed: vci's per-run
/// plumbing for every adapter; for Vitest also its per-worker `VITEST*`
/// variables and `NODE_OPTIONS` (vci sets it, and hashes the user's value as a
/// global input); for pytest `PYTHONPATH` (vci sets it to its collector, and
/// `vci run` refuses a test that reads it). `NODE_OPTIONS` read by a Go or
/// Rust test, or `VCI_BASE_REF` read by any test, is hashed.
pub fn never_hashed(adapter: &str) -> &'static [&'static str] {
    match adapter {
        "vitest" => &[
            "VCI_OUT",
            "VCI_WORKER",
            "VCI_LIST_OUT",
            "VCI_GO_TESTLOG",
            "VITEST*",
            "NODE_OPTIONS",
        ],
        "pytest" => &[
            "VCI_OUT",
            "VCI_WORKER",
            "VCI_LIST_OUT",
            "VCI_GO_TESTLOG",
            "PYTHONPATH",
        ],
        "go" | "cargo" => VCI_RUN_VARS,
        // vci sets RUBYOPT (the collector), RAILS_ENV, BUNDLE_GEMFILE,
        // PARALLEL_WORKERS, ... for every Rails test process.
        "rails" => RAILS_NEVER_HASHED,
        _ => NEVER_HASHED,
    }
}

/// vci's per-run plumbing plus the variables it sets for every Rails test
/// process ([`vci_adapter::RAILS_RUN_VARS`]).
const RAILS_NEVER_HASHED: &[&str] = &[
    "VCI_OUT",
    "VCI_WORKER",
    "VCI_LIST_OUT",
    "VCI_GO_TESTLOG",
    "VCI_TEST_ID",
    "VCI_DB_DIR",
    "VCI_ROOT",
    "VCI_REPO",
    "VCI_RAILS_MODE",
    "VCI_RAILS_ALLOW_DB",
    "RUBYOPT",
    "RAILS_ENV",
    "RACK_ENV",
    "BUNDLE_GEMFILE",
    "PARALLEL_WORKERS",
    "DISABLE_SPRING",
    "DISABLE_BOOTSNAP",
    // A fresh empty directory for every process (like Go's).
    "TMPDIR",
];

/// Hashed in loose mode even when no read of it is observed (see
/// [`FileEnv::required_keys`]).
const LOOSE_ALWAYS_HASHED: &str = "TZ";

/// Names that look like secrets; declaring them (hashing) triggers a warning.
const SECRET_HINTS: &[&str] = &["*TOKEN*", "*SECRET*", "*PASSWORD*", "*KEY*"];

/// Pattern list semantics: exclusions (`!pat`) win over inclusions.
pub fn list_matches(patterns: &[String], name: &str) -> bool {
    let mut included = false;
    for p in patterns {
        if let Some(ex) = p.strip_prefix('!') {
            if name_match(ex, name) {
                return false;
            }
        } else if name_match(p, name) {
            included = true;
        }
    }
    included
}

/// The effective env configuration for one test file.
#[derive(Debug, Clone)]
pub struct FileEnv {
    pub mode: EnvMode,
    pub declared: Vec<String>,
    pub pass_through: Vec<String>,
    pub inferred: Vec<String>,
    /// Adapter-specific built-in pass-through (`Adapter::builtin_pass_through`),
    /// on top of [`BUILTIN_PASS_THROUGH`]. Fixed by the adapter, so not part
    /// of the digest (the adapter name is checked separately).
    pub builtin: Vec<String>,
    /// The adapter's name (empty: unknown), which decides which read
    /// variables stay unhashed ([`never_hashed`]). Not part of the digest.
    pub adapter: String,
}

impl FileEnv {
    pub fn for_file(cfg: &EnvConfig, inferred: &[&str], project_rel: &str) -> Self {
        let mut declared = cfg.global.clone();
        let mut pass = cfg.pass_through.clone();
        for f in &cfg.files {
            if f.match_.iter().any(|g| glob_match(g, project_rel)) {
                declared.extend(f.env.iter().cloned());
                pass.extend(f.pass_through.iter().cloned());
            }
        }
        declared.sort();
        declared.dedup();
        pass.sort();
        pass.dedup();
        Self {
            mode: cfg.mode,
            declared,
            pass_through: pass,
            inferred: inferred.iter().map(|s| s.to_string()).collect(),
            builtin: vec![],
            adapter: String::new(),
        }
    }

    /// Set the adapter (see [`never_hashed`]).
    pub fn with_adapter(mut self, adapter: &str) -> Self {
        self.adapter = adapter.to_owned();
        self
    }

    /// Add an adapter's built-in pass-through patterns.
    pub fn with_builtin(mut self, builtin: &[&str]) -> Self {
        self.builtin = builtin.iter().map(|s| s.to_string()).collect();
        self
    }

    /// BLAKE3 over the mode and the sorted effective pattern lists.
    pub fn digest(&self) -> String {
        let mut s = String::from("vci/env-config/v1\n");
        s.push_str(match self.mode {
            EnvMode::Strict => "strict",
            EnvMode::Loose => "loose",
        });
        for (name, list) in [
            ("declared", &self.declared),
            ("pass_through", &self.pass_through),
            ("inferred", &self.inferred),
        ] {
            s.push('\n');
            s.push_str(name);
            for p in list {
                s.push('\0');
                s.push_str(p);
            }
        }
        blake3_hex(s.as_bytes())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_pass_through(&self, key: &str) -> bool {
        list_matches(&self.pass_through, key)
            || BUILTIN_PASS_THROUGH.iter().any(|p| name_match(p, key))
            || self.builtin.iter().any(|p| name_match(p, key))
    }

    /// An observed read of `key` is hashed unless it is configured
    /// pass-through (the user's decision) or in the adapter's
    /// [`never_hashed`] list. Built-in
    /// pass-through variables that are read are hashed: they are visible to
    /// tests so that tooling works, not because their values do not matter.
    pub fn hashed_when_read(&self, key: &str) -> bool {
        !list_matches(&self.pass_through, key)
            && !never_hashed(&self.adapter)
                .iter()
                .any(|p| name_match(p, key))
    }

    /// Keys that must be hashed regardless of observation: declared patterns
    /// expanded against `child`, exact declared names even if unset, and
    /// adapter-inferred variables present in `child` (inferred patterns may
    /// exclude with `!pat`).
    pub fn required_keys(&self, child: &ChildEnvMap) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for k in child.keys() {
            if list_matches(&self.declared, k)
                || (list_matches(&self.inferred, k)
                    && !self
                        .declared
                        .iter()
                        .any(|p| p.strip_prefix('!').is_some_and(|x| name_match(x, k))))
            {
                out.insert(k.clone());
            }
        }
        for p in &self.declared {
            if !p.starts_with('!') && !p.contains('*') && list_matches(&self.declared, p) {
                out.insert(p.clone());
            }
        }
        // Loose mode passes TZ through, and ICU reads it natively (never
        // through the process.env proxy), so it is always hashed, set or not.
        if self.mode == EnvMode::Loose
            && !self.declared.iter().any(|p| {
                p.strip_prefix('!')
                    .is_some_and(|x| name_match(x, LOOSE_ALWAYS_HASHED))
            })
        {
            out.insert(LOOSE_ALWAYS_HASHED.to_owned());
        }
        out
    }

    /// The full hashed key set: required keys plus observed reads (see
    /// [`Self::hashed_when_read`]).
    pub fn hashed_keys(&self, child: &ChildEnvMap, observed: &BTreeSet<String>) -> Vec<String> {
        let mut keys = self.required_keys(child);
        for k in observed {
            if self.hashed_when_read(k) {
                keys.insert(k.clone());
            }
        }
        keys.into_iter().collect()
    }

    /// Declared names that look like secrets (for a warning).
    pub fn secret_like(&self) -> Vec<String> {
        self.declared
            .iter()
            .filter(|p| !p.starts_with('!'))
            .filter(|p| {
                SECRET_HINTS
                    .iter()
                    .any(|h| name_match(h, &p.to_uppercase()))
            })
            .cloned()
            .collect()
    }
}

/// UTF-8 keyed view of the child environment used for hashing.
#[derive(Debug, Clone, Default)]
pub struct ChildEnvMap {
    vars: BTreeMap<String, OsString>,
    /// `true` when the child environment was built explicitly (strict mode).
    pub explicit: bool,
}

impl ChildEnvMap {
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.vars.keys()
    }

    pub fn get(&self, k: &str) -> Option<OsString> {
        self.vars.get(k).cloned()
    }

    /// For the adapter: `None` = inherit, `Some` = exactly these vars.
    pub fn to_child_env(&self) -> vci_adapter::ChildEnv {
        if self.explicit {
            Some(
                self.vars
                    .iter()
                    .map(|(k, v)| (OsString::from(k), v.clone()))
                    .collect(),
            )
        } else {
            None
        }
    }
}

/// Build the environment the test process will see. In strict mode only
/// built-in and configured pass-through, declared (for any file) and
/// adapter-inferred variables are kept. In loose mode everything is kept.
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_child_env(
    cfg: &EnvConfig,
    inferred: &[&str],
    parent: impl IntoIterator<Item = (OsString, OsString)>,
) -> ChildEnvMap {
    build_child_env_with(cfg, inferred, &[], parent)
}

/// [`build_child_env`] with an adapter's built-in pass-through patterns
/// (`Adapter::builtin_pass_through`) also kept in strict mode.
pub fn build_child_env_with(
    cfg: &EnvConfig,
    inferred: &[&str],
    builtin: &[&str],
    parent: impl IntoIterator<Item = (OsString, OsString)>,
) -> ChildEnvMap {
    let mut declared_any = cfg.global.clone();
    let mut pass_any = cfg.pass_through.clone();
    for f in &cfg.files {
        declared_any.extend(f.env.iter().cloned());
        pass_any.extend(f.pass_through.iter().cloned());
    }
    let mut vars = BTreeMap::new();
    for (k, v) in parent {
        // Non-UTF-8 names cannot be matched or hashed; drop them (a test
        // could only see them through enumeration, which is a taint).
        let Some(ks) = k.to_str() else { continue };
        let keep = match cfg.mode {
            EnvMode::Loose => true,
            EnvMode::Strict => {
                BUILTIN_PASS_THROUGH.iter().any(|p| name_match(p, ks))
                    || builtin.iter().any(|p| name_match(p, ks))
                    || list_matches(&pass_any, ks)
                    || list_matches(&declared_any, ks)
                    || inferred.iter().any(|p| name_match(p, ks))
            }
        };
        if keep {
            vars.insert(ks.to_owned(), v);
        }
    }
    ChildEnvMap {
        vars,
        explicit: cfg.mode == EnvMode::Strict,
    }
}

pub fn lookup<'a>(child: &'a ChildEnvMap) -> impl Fn(&str) -> Option<OsString> + Sync + 'a {
    move |k| child.get(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EnvFiles;

    fn cfg(mode: EnvMode) -> EnvConfig {
        EnvConfig {
            mode,
            global: vec![
                "NODE_ENV".into(),
                "CI_*".into(),
                "!CI_JOB_*".into(),
                "TZ".into(),
            ],
            pass_through: vec!["GITHUB_TOKEN".into()],
            files: vec![EnvFiles {
                match_: vec!["src/db/**".into()],
                env: vec!["DATABASE_URL".into()],
                pass_through: vec!["PG*".into()],
            }],
        }
    }

    fn parent() -> Vec<(OsString, OsString)> {
        [
            ("PATH", "/bin"),
            ("NODE_ENV", "test"),
            ("CI_REF", "x"),
            ("CI_JOB_ID", "1"),
            ("GITHUB_TOKEN", "secret"),
            ("RANDOM_VAR", "r"),
            ("VITE_API", "u"),
            ("PGHOST", "h"),
            ("DATABASE_URL", "d"),
        ]
        .iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect()
    }

    #[test]
    fn strict_mode_filters_the_child_env() {
        let c = build_child_env(&cfg(EnvMode::Strict), &["VITE_*"], parent());
        let keys: Vec<&String> = c.keys().collect();
        assert_eq!(
            keys,
            [
                "CI_REF",
                "DATABASE_URL",
                "GITHUB_TOKEN",
                "NODE_ENV",
                "PATH",
                "PGHOST",
                "VITE_API"
            ]
        );
        let l = build_child_env(&cfg(EnvMode::Loose), &["VITE_*"], parent());
        assert!(l.get("RANDOM_VAR").is_some());
        assert!(l.to_child_env().is_none());
    }

    #[test]
    fn hashed_keys_follow_env_md() {
        let cf = cfg(EnvMode::Strict);
        let child = build_child_env(&cf, &["VITE_*"], parent());
        let f = FileEnv::for_file(&cf, &["VITE_*"], "src/a.test.ts");
        let observed: BTreeSet<String> = ["GITHUB_TOKEN", "HOME", "UNDECLARED"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let keys = f.hashed_keys(&child, &observed);
        // HOME is built-in pass-through: visible, and hashed because it was read.
        assert_eq!(
            keys,
            ["CI_REF", "HOME", "NODE_ENV", "TZ", "UNDECLARED", "VITE_API"]
        );
        let db = FileEnv::for_file(&cf, &["VITE_*"], "src/db/x.test.ts");
        assert!(
            db.hashed_keys(&child, &BTreeSet::new())
                .contains(&"DATABASE_URL".to_string())
        );
        assert!(db.is_pass_through("PGHOST"));
        assert_ne!(f.digest(), db.digest());
    }

    /// Regression: in loose mode TZ is read natively (ICU), never through the
    /// process.env proxy, so it must always be hashed.
    #[test]
    fn loose_mode_always_hashes_tz() {
        let mut c = cfg(EnvMode::Loose);
        c.global.clear();
        let f = FileEnv::for_file(&c, &[], "src/tz.test.ts");
        let without = build_child_env(&c, &[], parent());
        assert!(f.required_keys(&without).contains("TZ"));
        let mut p = parent();
        p.push(("TZ".into(), "UTC".into()));
        let with = build_child_env(&c, &[], p);
        assert!(
            f.hashed_keys(&with, &BTreeSet::new())
                .contains(&"TZ".to_string())
        );
    }

    /// pytest: uv's variables reach the child in strict mode and are never
    /// hashed; PYTEST_*/PYTHON* (reported as read by the collector) are
    /// hashed, and removed from the child unless declared.
    #[test]
    fn pytest_builtin_pass_through() {
        let c = cfg(EnvMode::Strict);
        let builtin = vci_adapter::PYTEST_PASS_THROUGH;
        let mut p = parent();
        for (k, v) in [
            ("UV_CACHE_DIR", "/c"),
            ("VIRTUAL_ENV", "/v"),
            ("PYTEST_ADDOPTS", "-x"),
            ("PYTHONHASHSEED", "1"),
            ("PYTHONPATH", "/p"),
        ] {
            p.push((k.into(), v.into()));
        }
        let child = build_child_env_with(&c, &[], builtin, p.clone());
        assert!(child.get("UV_CACHE_DIR").is_some());
        assert!(child.get("VIRTUAL_ENV").is_some());
        assert!(child.get("PYTEST_ADDOPTS").is_none());
        assert!(child.get("PYTHONHASHSEED").is_none());
        // Without the adapter list, strict mode drops uv's variables.
        assert!(build_child_env(&c, &[], p).get("UV_CACHE_DIR").is_none());
        let f = FileEnv::for_file(&c, &[], "tests/test_a.py").with_builtin(builtin);
        let observed: BTreeSet<String> = [
            "PYTEST_ADDOPTS",
            "PYTHONHASHSEED",
            "UV_CACHE_DIR",
            "PYTHONPATH",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let keys = f.hashed_keys(&child, &observed);
        assert!(keys.contains(&"PYTEST_ADDOPTS".to_string()));
        assert!(keys.contains(&"PYTHONHASHSEED".to_string()));
        // Read by the test: hashed (built-in pass-through is not a promise
        // that the value does not matter).
        assert!(keys.contains(&"UV_CACHE_DIR".to_string()));
        assert!(!keys.contains(&"PYTHONPATH".to_string()));
        assert_eq!(
            f.digest(),
            FileEnv::for_file(&c, &[], "tests/test_a.py").digest()
        );
    }

    /// Regression (loose mode): the interpreter reads PYTHON* variables in C
    /// (`PYTHON_CPU_COUNT`, `PYTHONBREAKPOINT`, `PYTHON_GIL`, ...) where the
    /// collector cannot see it; every one present must be hashed, and one
    /// present in CI but not at attestation time must be required.
    #[test]
    fn loose_mode_hashes_every_python_and_pytest_variable() {
        let mut c = cfg(EnvMode::Loose);
        c.global.clear();
        let hashed = vci_adapter::PYTEST_HASHED_ENV;
        let mut p = parent();
        for (k, v) in [
            ("PYTHON_CPU_COUNT", "1"),
            ("PYTEST_XDIST_AUTO_NUM_WORKERS", "2"),
            ("PYTHONPATH", "/p"),
        ] {
            p.push((k.into(), v.into()));
        }
        let child = build_child_env_with(&c, &[], vci_adapter::PYTEST_PASS_THROUGH, p);
        let f = FileEnv::for_file(&c, hashed, "tests/test_cpu.py")
            .with_builtin(vci_adapter::PYTEST_PASS_THROUGH);
        let req = f.required_keys(&child);
        assert!(req.contains("PYTHON_CPU_COUNT"), "{req:?}");
        assert!(req.contains("PYTEST_XDIST_AUTO_NUM_WORKERS"), "{req:?}");
        assert!(!req.contains("PYTHONPATH"), "vci sets PYTHONPATH itself");
        // Strict mode: not kept in the child (so hashed as unset on both sides).
        let strict = cfg(EnvMode::Strict);
        let mut p = parent();
        p.push(("PYTHON_CPU_COUNT".into(), "1".into()));
        let child = build_child_env_with(&strict, &[], vci_adapter::PYTEST_PASS_THROUGH, p);
        assert!(child.get("PYTHON_CPU_COUNT").is_none());
    }

    /// Regression: built-in pass-through variables (CI, HOME, USER, TMPDIR,
    /// LANG, ...) read by a test were never hashed, so a test asserting on
    /// `os.environ.get("CI")` attested on a laptop was skipped in CI where it
    /// fails. A read of one is hashed; configured pass-through stays unhashed.
    #[test]
    fn reads_of_builtin_pass_through_variables_are_hashed() {
        let c = cfg(EnvMode::Strict);
        let mut p = parent();
        p.push(("CI".into(), "true".into()));
        p.push(("HOME".into(), "/home/runner".into()));
        p.push(("VCI_OUT".into(), "/tmp/x".into()));
        p.push(("UV_CACHE_DIR".into(), "/c".into()));
        let child = build_child_env_with(&c, &[], vci_adapter::PYTEST_PASS_THROUGH, p);
        let f = FileEnv::for_file(&c, &[], "tests/test_ci.py")
            .with_builtin(vci_adapter::PYTEST_PASS_THROUGH);
        let observed: BTreeSet<String> = [
            "CI",
            "HOME",
            "LANG",
            "UV_CACHE_DIR",
            "GITHUB_TOKEN",
            "VCI_OUT",
            "VITEST_POOL_ID",
            "NODE_OPTIONS",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let keys = f.hashed_keys(&child, &observed);
        for k in ["CI", "HOME", "LANG", "UV_CACHE_DIR"] {
            assert!(
                keys.contains(&k.to_string()),
                "{k} must be hashed: {keys:?}"
            );
        }
        // Configured pass-through (a user decision) and vci's/Vitest's own
        // plumbing are never hashed.
        for k in ["GITHUB_TOKEN", "VCI_OUT", "VITEST_POOL_ID", "NODE_OPTIONS"] {
            assert!(
                !keys.contains(&k.to_string()),
                "{k} must not be hashed: {keys:?}"
            );
        }
    }

    /// Regression: `NODE_OPTIONS` and user `VCI_*` variables (`VCI_BASE_REF`)
    /// are built-in pass-through, so they reach every test process; a Go test
    /// that read one was attested without its value and skipped where the
    /// value differs. Only vci's per-run plumbing, and for Vitest its own
    /// worker variables and `NODE_OPTIONS` (hashed globally), stay unhashed.
    #[test]
    fn never_hashed_reads_are_per_adapter() {
        let c = cfg(EnvMode::Strict);
        let mut p = parent();
        p.push(("NODE_OPTIONS".into(), "--max-old-space-size=4096".into()));
        p.push(("VCI_BASE_REF".into(), "main".into()));
        let child = build_child_env(&c, &[], p);
        assert!(child.get("NODE_OPTIONS").is_some() && child.get("VCI_BASE_REF").is_some());
        let observed: BTreeSet<String> = [
            "NODE_OPTIONS",
            "VCI_BASE_REF",
            "VCI_OUT",
            "VCI_GO_TESTLOG",
            "VITEST_POOL_ID",
            "PYTHONPATH",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let keys = |adapter: &str| {
            FileEnv::for_file(&c, &[], "x")
                .with_adapter(adapter)
                .hashed_keys(&child, &observed)
        };
        for adapter in ["go", "cargo"] {
            let k = keys(adapter);
            for want in [
                "NODE_OPTIONS",
                "VCI_BASE_REF",
                "VITEST_POOL_ID",
                "PYTHONPATH",
            ] {
                assert!(k.contains(&want.to_string()), "{adapter}: {want}: {k:?}");
            }
            for not in ["VCI_OUT", "VCI_GO_TESTLOG"] {
                assert!(!k.contains(&not.to_string()), "{adapter}: {not}: {k:?}");
            }
        }
        let v = keys("vitest");
        assert!(v.contains(&"VCI_BASE_REF".to_string()), "{v:?}");
        for not in ["NODE_OPTIONS", "VITEST_POOL_ID", "VCI_OUT"] {
            assert!(!v.contains(&not.to_string()), "vitest: {not}: {v:?}");
        }
        let py = keys("pytest");
        assert!(py.contains(&"NODE_OPTIONS".to_string()), "{py:?}");
        assert!(!py.contains(&"PYTHONPATH".to_string()), "{py:?}");
        assert!(!py.contains(&"VCI_OUT".to_string()), "{py:?}");
        // The digest does not depend on it.
        assert_eq!(
            FileEnv::for_file(&c, &[], "x").with_adapter("go").digest(),
            FileEnv::for_file(&c, &[], "x").digest()
        );
    }

    /// Rails: what vci sets for every test process (RUBYOPT with the
    /// collector, RAILS_ENV, a fresh TMPDIR, ...) is never an input, so a
    /// read of it is not hashed; other built-in pass-through reads are.
    #[test]
    fn rails_run_variables_are_never_hashed() {
        let c = cfg(EnvMode::Strict);
        let mut p = parent();
        p.push(("TMPDIR".into(), "/var/folders/x".into()));
        p.push(("HOME".into(), "/Users/me".into()));
        let child = build_child_env_with(&c, &[], vci_adapter::RAILS_PASS_THROUGH, p);
        let mut observed: BTreeSet<String> = vci_adapter::RAILS_RUN_VARS
            .iter()
            .map(|s| s.to_string())
            .collect();
        observed.insert("TMPDIR".into());
        observed.insert("HOME".into());
        let keys = FileEnv::for_file(&c, &[], "test/a_test.rb")
            .with_adapter("rails")
            .hashed_keys(&child, &observed);
        for k in vci_adapter::RAILS_RUN_VARS.iter().chain(&["TMPDIR"]) {
            assert!(!keys.contains(&k.to_string()), "{k}: {keys:?}");
        }
        assert!(keys.contains(&"HOME".to_string()), "{keys:?}");
    }

    #[test]
    fn secret_warning() {
        let mut c = cfg(EnvMode::Strict);
        c.global.push("NPM_TOKEN".into());
        let f = FileEnv::for_file(&c, &[], "a.test.ts");
        assert_eq!(f.secret_like(), ["NPM_TOKEN"]);
    }
}
