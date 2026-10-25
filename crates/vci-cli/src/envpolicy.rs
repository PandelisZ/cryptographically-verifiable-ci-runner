//! Environment variable policy (docs/ENV.md): which variables reach the test
//! process, which are hashed, and the per-file env config digest.
//!
//! Every variable is in exactly one class, decided in this order:
//!
//! 1. `set` (vci.toml): vci sets it in every test process, whatever the
//!    machine's value; hashed (its value is the declared one everywhere).
//! 2. `hash` (vci.toml): taken from the machine, visible, hashed.
//! 3. `ignore` (vci.toml): taken from the machine, visible, never hashed.
//! 4. built-in hash (the runner's short list): visible, hashed when present.
//! 5. built-in ignore (the runner's short list): visible, hashed only when a
//!    test is seen reading it.
//! 6. everything else: removed from the test process (strict mode); a test
//!    seen reading one gets it recorded as absent.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;

use serde::Serialize;
use vci_core::hash::blake3_hex;

use crate::config::{EnvConfig, EnvMode};
use crate::util::{glob_match, name_match};

/// Built-in ignore variables that stay unhashed even when read, when the
/// adapter is not known (the union of [`never_hashed`]'s lists): vci's own
/// plumbing (`VCI_*`; `PYTHONPATH`, which vci sets to its collector for
/// pytest and `vci run` refuses to attest a read of), Vitest's per-worker
/// variables, and `NODE_OPTIONS` (vci sets it for Vitest and hashes the
/// user's value).
pub const NEVER_HASHED: &[&str] = &["VCI_*", "VITEST*", "NODE_OPTIONS", "PYTHONPATH"];

/// Variables vci sets itself for one run of the tests (where a collector
/// writes its output): never inputs. Every other `VCI_*` variable
/// (`VCI_BASE_REF`, `VCI_JOBS`, ...) is the user's and reaches the tests as
/// built-in ignore, so a test that reads one gets it hashed.
const VCI_RUN_VARS: &[&str] = &["VCI_OUT", "VCI_WORKER", "VCI_LIST_OUT", "VCI_GO_TESTLOG"];

/// Variables an adapter's test process sees with values that are not
/// inputs, so reads of them stay unhashed: vci's per-run plumbing for every
/// adapter; for Vitest also its per-worker `VITEST*` variables and
/// `NODE_OPTIONS` (vci adds its own options; the user's value is built-in
/// hash); for pytest `PYTHONPATH` (vci sets it to its collector, and `vci run`
/// refuses a test that reads it).
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
        // vci sets VCI_TEST_FILE/VCI_ROOT for its node:test collector and
        // adds its own NODE_OPTIONS.
        "node-test" => &[
            "VCI_OUT",
            "VCI_WORKER",
            "VCI_LIST_OUT",
            "VCI_GO_TESTLOG",
            "VCI_TEST_FILE",
            "VCI_ROOT",
            "NODE_OPTIONS",
        ],
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
    "VCI_ROOT",
    "VCI_REPO",
    "VCI_RAILS_MODE",
    "VCI_RAILS_RUNNER",
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

/// Names that look like secrets; hashing them triggers a warning.
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

/// The class of one variable (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvClass {
    Set,
    Hash,
    Ignore,
    BuiltinHash,
    BuiltinIgnore,
    Stripped,
}

impl EnvClass {
    /// The name `vci env` and `vci explain` print.
    pub fn label(self) -> &'static str {
        match self {
            EnvClass::Set => "set",
            EnvClass::Hash => "hash",
            EnvClass::Ignore => "ignore",
            EnvClass::BuiltinHash => "built-in hash",
            EnvClass::BuiltinIgnore => "built-in ignore",
            EnvClass::Stripped => "stripped",
        }
    }

    /// Whether the machine's value reaches the test process (strict mode).
    pub fn visible(self) -> bool {
        !matches!(self, EnvClass::Stripped)
    }
}

/// The effective env configuration for one test file (or, from
/// [`FileEnv::for_project`], for any file of a project).
#[derive(Debug, Clone)]
pub struct FileEnv {
    pub mode: EnvMode,
    /// `set`: name -> value.
    pub set: BTreeMap<String, String>,
    /// `hash` patterns (vci.toml, the file's `[[env.files]]`, and what the
    /// adapter declares itself: node-test's script assignments), sorted.
    pub hash: Vec<String>,
    /// `ignore` patterns (vci.toml and the file's `[[env.files]]`), sorted.
    pub ignore: Vec<String>,
    /// Built-in hash patterns: [`vci_adapter::COMMON_HASH`] and the
    /// adapter's own (`Adapter::builtin_hash`).
    pub builtin_hash: Vec<String>,
    /// Built-in ignore patterns: [`vci_adapter::COMMON_IGNORE`] and the
    /// adapter's own (`Adapter::builtin_ignore`).
    pub builtin_ignore: Vec<String>,
    /// Loose mode only (deprecated): the adapter's 1.5 families
    /// (`Adapter::loose_hash`), hashed whenever present unless `ignore`d.
    /// Part of the digest in loose mode only.
    pub loose_hash: Vec<String>,
    /// The adapter's name (empty: unknown), which decides which read
    /// variables stay unhashed ([`never_hashed`]). Not part of the digest.
    pub adapter: String,
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

impl FileEnv {
    /// The user's lists for the file `project_rel` (no built-in lists: see
    /// [`Self::with_builtins`]).
    pub fn for_file(cfg: &EnvConfig, project_rel: &str) -> Self {
        Self::from_files(cfg, |m| m.iter().any(|g| glob_match(g, project_rel)))
    }

    /// The user's lists for any file of the project (every `[[env.files]]`
    /// entry applies): what the shared child environment keeps.
    pub fn for_project(cfg: &EnvConfig) -> Self {
        Self::from_files(cfg, |_| true)
    }

    fn from_files(cfg: &EnvConfig, applies: impl Fn(&[String]) -> bool) -> Self {
        let mut hash = cfg.hash.clone();
        let mut ignore = cfg.ignore.clone();
        for f in &cfg.files {
            if applies(&f.match_) {
                hash.extend(f.hash.iter().cloned());
                ignore.extend(f.ignore.iter().cloned());
            }
        }
        Self {
            mode: cfg.mode,
            set: cfg.set.clone(),
            hash: sorted(hash),
            ignore: sorted(ignore),
            builtin_hash: vec![],
            builtin_ignore: vec![],
            loose_hash: vec![],
            adapter: String::new(),
        }
    }

    /// Add the built-in lists: every runner's and the adapter's.
    pub fn with_builtins(mut self, hash: &[&str], ignore: &[&str]) -> Self {
        self.builtin_hash = sorted(
            vci_adapter::COMMON_HASH
                .iter()
                .chain(hash)
                .map(|s| s.to_string())
                .collect(),
        );
        self.builtin_ignore = sorted(
            vci_adapter::COMMON_IGNORE
                .iter()
                .chain(ignore)
                .map(|s| s.to_string())
                .collect(),
        );
        self
    }

    /// Add the adapter's loose-mode list (see [`Self::loose_hash`]).
    pub fn with_loose_hash(mut self, patterns: &[&str]) -> Self {
        self.loose_hash = patterns.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set the adapter (see [`never_hashed`]).
    pub fn with_adapter(mut self, adapter: &str) -> Self {
        self.adapter = adapter.to_owned();
        self
    }

    /// The class of `key`: `set` > `hash` > `ignore` > built-in hash >
    /// built-in ignore > stripped.
    pub fn classify(&self, key: &str) -> EnvClass {
        if self.set.contains_key(key) {
            EnvClass::Set
        } else if list_matches(&self.hash, key) {
            EnvClass::Hash
        } else if list_matches(&self.ignore, key) {
            EnvClass::Ignore
        } else if list_matches(&self.builtin_hash, key) {
            EnvClass::BuiltinHash
        } else if list_matches(&self.builtin_ignore, key) {
            EnvClass::BuiltinIgnore
        } else {
            EnvClass::Stripped
        }
    }

    /// BLAKE3 over the mode, the `set` values and the sorted pattern lists
    /// (built-in ones included: another vci with other built-in lists hashes
    /// other variables). `v2` since vci 1.6.0 (set/hash/ignore).
    pub fn digest(&self) -> String {
        let mut s = String::from("vci/env-config/v2\n");
        s.push_str(match self.mode {
            EnvMode::Strict => "strict",
            EnvMode::Loose => "loose",
        });
        s.push_str("\nset");
        for (k, v) in &self.set {
            s.push('\0');
            s.push_str(k);
            s.push('=');
            s.push_str(v);
        }
        for (name, list) in [
            ("hash", &self.hash),
            ("ignore", &self.ignore),
            ("builtin_hash", &self.builtin_hash),
            ("builtin_ignore", &self.builtin_ignore),
        ] {
            s.push('\n');
            s.push_str(name);
            for p in list {
                s.push('\0');
                s.push_str(p);
            }
        }
        // Only loose mode uses it; strict digests do not depend on it.
        if self.mode == EnvMode::Loose {
            s.push_str("\nloose_hash");
            for p in &self.loose_hash {
                s.push('\0');
                s.push_str(p);
            }
        }
        blake3_hex(s.as_bytes())
    }

    /// An observed read of `key` is hashed unless it is `ignore` (the user's
    /// decision), built-in ignore, or in the adapter's [`never_hashed`]
    /// list. Built-in ignore variables (`PATH`, `HOME`, `TERM`, `VCI_*`,
    /// ...) are visible so that tooling works; until 2.0.2 a read of one was
    /// hashed, and since a test that hands its whole environment to a child
    /// process reads every one of them, an attestation then matched only
    /// the machine, job and runner directory it was made on (on vex, 93 of
    /// 115 re-runs on pull requests). `hash = ["HOME"]` makes a read of one
    /// an input again; stripped ones are recorded as absent.
    pub fn hashed_when_read(&self, key: &str) -> bool {
        !matches!(
            self.classify(key),
            EnvClass::Ignore | EnvClass::BuiltinIgnore
        ) && !never_hashed(&self.adapter)
            .iter()
            .any(|p| name_match(p, key))
    }

    /// Keys hashed whatever the test reads: every `set` name, every `hash` or
    /// built-in hash variable present in `child`, and every exact `hash` name
    /// even if unset. In loose mode also `TZ`, and every variable present in
    /// `child` that matches the adapter's [`Self::loose_hash`] list and is not
    /// `ignore`: loose mode lets them reach the tests, and the runtime reads
    /// them where nothing observes it (vci 1.5 hashed them the same way).
    pub fn required_keys(&self, child: &ChildEnvMap) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = self.set.keys().cloned().collect();
        for k in child.keys() {
            match self.classify(k) {
                EnvClass::Hash | EnvClass::BuiltinHash => {
                    out.insert(k.clone());
                }
                EnvClass::BuiltinIgnore | EnvClass::Stripped
                    if self.mode == EnvMode::Loose && list_matches(&self.loose_hash, k) =>
                {
                    out.insert(k.clone());
                }
                _ => {}
            }
        }
        for p in &self.hash {
            if !p.starts_with('!') && !p.contains('*') && list_matches(&self.hash, p) {
                out.insert(p.clone());
            }
        }
        // Loose mode passes TZ through, and ICU reads it natively (never
        // through the process.env proxy), so it is always hashed, set or not.
        if self.mode == EnvMode::Loose
            && !self.hash.iter().any(|p| {
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

    /// `hash` names that look like secrets (for a warning).
    pub fn secret_like(&self) -> Vec<String> {
        self.hash
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
    /// `true` when the child environment is given explicitly (always, once
    /// built by [`build_child_env`]); `false` (the default, for tests and
    /// fallbacks) inherits vci's environment.
    pub explicit: bool,
}

impl ChildEnvMap {
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.vars.keys()
    }

    pub fn get(&self, k: &str) -> Option<OsString> {
        self.vars.get(k).cloned()
    }

    /// Set a variable the adapter sets for every test process.
    pub fn set(&mut self, k: &str, v: OsString) {
        self.vars.insert(k.to_owned(), v);
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

/// Build the environment the test processes of a project see, from the
/// project-wide policy ([`FileEnv::for_project`] with its built-in lists).
/// Strict mode keeps the variables of every class but stripped; loose mode
/// keeps everything. Then every `set` variable gets its declared value.
/// The store's secrets ([`vci_store::select::NEVER_TO_CHILDREN`],
/// `VCI_STORE_URL`) never reach a test, in either mode: vci removes them
/// from its own environment at start-up, and this drops them again.
pub fn build_child_env(
    policy: &FileEnv,
    parent: impl IntoIterator<Item = (OsString, OsString)>,
) -> ChildEnvMap {
    let mut vars = BTreeMap::new();
    for (k, v) in parent {
        // Non-UTF-8 names cannot be matched or hashed; drop them (a test
        // could only see them through enumeration, which is a taint).
        let Some(ks) = k.to_str() else { continue };
        let keep = match policy.mode {
            EnvMode::Loose => true,
            EnvMode::Strict => policy.classify(ks).visible(),
        };
        if keep {
            vars.insert(ks.to_owned(), v);
        }
    }
    for (k, v) in &policy.set {
        vars.insert(k.clone(), OsString::from(v));
    }
    for k in vci_store::select::NEVER_TO_CHILDREN {
        vars.remove(*k);
    }
    ChildEnvMap {
        vars,
        explicit: true,
    }
}

pub fn lookup<'a>(child: &'a ChildEnvMap) -> impl Fn(&str) -> Option<OsString> + Sync + 'a {
    move |k| child.get(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, EnvFiles};

    fn cfg(mode: EnvMode) -> EnvConfig {
        EnvConfig {
            mode,
            set: [("TZ", "UTC"), ("CI", "true")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            hash: vec!["NODE_ENV".into(), "CI_*".into(), "!CI_JOB_*".into()],
            ignore: vec!["GITHUB_TOKEN".into()],
            files: vec![EnvFiles {
                match_: vec!["src/db/**".into()],
                hash: vec!["DATABASE_URL".into()],
                ignore: vec!["PG*".into()],
                old_env: None,
                old_pass_through: None,
            }],
            ..EnvConfig::default()
        }
    }

    fn parent() -> Vec<(OsString, OsString)> {
        [
            ("PATH", "/bin"),
            ("HOME", "/home/me"),
            ("TZ", "Europe/London"),
            ("CI", "1"),
            ("NODE_ENV", "test"),
            ("CI_REF", "x"),
            ("CI_JOB_ID", "1"),
            ("GITHUB_TOKEN", "secret"),
            ("RANDOM_VAR", "r"),
            ("VITE_API", "u"),
            ("PGHOST", "h"),
            ("DATABASE_URL", "d"),
            ("LANG", "en_GB.UTF-8"),
        ]
        .iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect()
    }

    fn vitest(c: &EnvConfig) -> FileEnv {
        FileEnv::for_project(c)
            .with_builtins(vci_adapter::VITEST_HASH, vci_adapter::VITEST_IGNORE)
            .with_adapter("vitest")
    }

    fn keys(c: &ChildEnvMap) -> Vec<&str> {
        c.keys().map(String::as_str).collect()
    }

    fn strs(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn precedence_set_hash_ignore_builtins_stripped() {
        let mut c = cfg(EnvMode::Strict);
        // A user's hash beats a built-in ignore (HOME), a user's ignore
        // beats a built-in hash (LANG), set beats every list (CI is also
        // matched by nothing else; TZ is built-in hash).
        c.hash.push("HOME".into());
        c.ignore.push("LANG".into());
        c.hash.push("BOTH".into());
        c.ignore.push("BOTH".into());
        c.ignore.push("TZ".into());
        let f = vitest(&c);
        assert_eq!(f.classify("TZ"), EnvClass::Set);
        assert_eq!(f.classify("CI"), EnvClass::Set);
        assert_eq!(f.classify("HOME"), EnvClass::Hash);
        assert_eq!(f.classify("BOTH"), EnvClass::Hash);
        assert_eq!(f.classify("LANG"), EnvClass::Ignore);
        assert_eq!(f.classify("CI_REF"), EnvClass::Hash);
        // `!` excludes from the user's list; the variable falls through.
        assert_eq!(f.classify("CI_JOB_ID"), EnvClass::Stripped);
        assert_eq!(f.classify("VITE_API"), EnvClass::BuiltinHash);
        assert_eq!(f.classify("LC_ALL"), EnvClass::BuiltinHash);
        assert_eq!(f.classify("PATH"), EnvClass::BuiltinIgnore);
        assert_eq!(f.classify("VITEST_POOL_ID"), EnvClass::BuiltinIgnore);
        assert_eq!(f.classify("RANDOM_VAR"), EnvClass::Stripped);
        // [[env.files]] lists apply to the project's child environment.
        assert_eq!(f.classify("DATABASE_URL"), EnvClass::Hash);
        assert_eq!(f.classify("PGHOST"), EnvClass::Ignore);
        // ... but per file only to matching files.
        let file = FileEnv::for_file(&c, "src/a.test.ts")
            .with_builtins(vci_adapter::VITEST_HASH, vci_adapter::VITEST_IGNORE);
        assert_eq!(file.classify("DATABASE_URL"), EnvClass::Stripped);
        let db = FileEnv::for_file(&c, "src/db/x.test.ts");
        assert_eq!(db.classify("DATABASE_URL"), EnvClass::Hash);
    }

    #[test]
    fn strict_child_strips_and_sets() {
        let child = build_child_env(&vitest(&cfg(EnvMode::Strict)), parent());
        assert_eq!(
            keys(&child),
            [
                "CI",
                "CI_REF",
                "DATABASE_URL",
                "GITHUB_TOKEN",
                "HOME",
                "LANG",
                "NODE_ENV",
                "PATH",
                "PGHOST",
                "TZ",
                "VITE_API"
            ]
        );
        // set overrides the machine's value.
        assert_eq!(child.get("TZ").unwrap(), "UTC");
        assert_eq!(child.get("CI").unwrap(), "true");
        // ignore and hash variables keep the machine's value.
        assert_eq!(child.get("GITHUB_TOKEN").unwrap(), "secret");
        assert_eq!(child.get("NODE_ENV").unwrap(), "test");
        assert!(child.to_child_env().is_some());
        // A set variable absent from the machine is added.
        let child = build_child_env(&vitest(&cfg(EnvMode::Strict)), vec![]);
        assert_eq!(keys(&child), ["CI", "TZ"]);
    }

    /// `VCI_STORE_URL` (a store's password) reaches no test, whatever the
    /// mode and even when vci.toml sets it; other `VCI_*` variables pass
    /// through as built-in ignore.
    #[test]
    fn store_secrets_never_reach_a_test() {
        let with_url = || {
            let mut p = parent();
            p.push(("VCI_STORE_URL".into(), "postgres://u:s3cret@h/db".into()));
            p.push(("VCI_STORE".into(), "postgres".into()));
            p
        };
        for mode in [EnvMode::Strict, EnvMode::Loose] {
            let mut c = cfg(mode);
            c.set
                .insert("VCI_STORE_URL".into(), "postgres://u:s3cret@h/db".into());
            c.hash.push("VCI_STORE_URL".into());
            let child = build_child_env(&vitest(&c), with_url());
            assert!(child.get("VCI_STORE_URL").is_none(), "{mode:?}");
            assert_eq!(
                child.get("VCI_STORE").as_deref(),
                Some(std::ffi::OsStr::new("postgres")),
                "{mode:?}"
            );
        }
    }

    #[test]
    fn loose_child_keeps_everything_and_sets() {
        let child = build_child_env(&vitest(&cfg(EnvMode::Loose)), parent());
        assert!(child.get("RANDOM_VAR").is_some());
        assert_eq!(child.get("TZ").unwrap(), "UTC");
        // Explicit, so that the set values reach the runner.
        assert!(child.to_child_env().is_some());
    }

    #[test]
    fn hashed_keys_follow_env_md() {
        let c = cfg(EnvMode::Strict);
        let child = build_child_env(&vitest(&c), parent());
        let f = FileEnv::for_file(&c, "src/a.test.ts")
            .with_builtins(vci_adapter::VITEST_HASH, vci_adapter::VITEST_IGNORE)
            .with_adapter("vitest");
        let observed = strs(&["GITHUB_TOKEN", "HOME", "UNDECLARED", "VITEST_POOL_ID"]);
        assert_eq!(
            f.hashed_keys(&child, &observed),
            [
                // set
                "CI",
                // hash, present
                "CI_REF",
                // (HOME: built-in ignore, read: not hashed since 2.0.2)
                // built-in hash, present
                "LANG",
                "NODE_ENV",
                "TZ",
                // stripped, read (recorded absent)
                "UNDECLARED",
                "VITE_API"
            ]
        );
        // Exact hash names are hashed even if unset; built-in hash ones only
        // when present.
        let empty = build_child_env(&vitest(&c), vec![]);
        let req = f.required_keys(&empty);
        assert!(req.contains("NODE_ENV"), "{req:?}");
        assert!(!req.contains("LANG"), "{req:?}");
        assert!(!req.contains("CI_REF"), "{req:?}");
        let db = FileEnv::for_file(&c, "src/db/x.test.ts");
        assert!(db.required_keys(&child).contains("DATABASE_URL"));
        assert!(!db.hashed_when_read("PGHOST"));
        assert_ne!(f.digest(), db.digest());
    }

    #[test]
    fn digest_covers_set_values_lists_and_builtins() {
        let c = cfg(EnvMode::Strict);
        let base = vitest(&c).digest();
        let mut d = c.clone();
        d.set.insert("TZ".into(), "Asia/Tokyo".into());
        assert_ne!(vitest(&d).digest(), base, "set value");
        let mut d = c.clone();
        d.ignore.push("X".into());
        assert_ne!(vitest(&d).digest(), base, "ignore list");
        let mut d = c.clone();
        d.mode = EnvMode::Loose;
        assert_ne!(vitest(&d).digest(), base, "mode");
        assert_ne!(
            FileEnv::for_project(&c)
                .with_builtins(vci_adapter::GO_HASH, vci_adapter::GO_IGNORE)
                .digest(),
            base,
            "built-in lists"
        );
        // Order and duplicates in vci.toml do not matter; the adapter name
        // alone does not either.
        let mut d = c.clone();
        d.hash.reverse();
        d.hash.push("NODE_ENV".into());
        assert_eq!(vitest(&d).digest(), base);
        assert_eq!(vitest(&c).with_adapter("").digest(), base);
    }

    /// Regression: in loose mode TZ is read natively (ICU), never through the
    /// process.env proxy, so it must always be hashed.
    #[test]
    fn loose_mode_always_hashes_tz() {
        let mut c = cfg(EnvMode::Loose);
        c.hash.clear();
        c.set.clear();
        let f = FileEnv::for_file(&c, "src/tz.test.ts");
        let without = build_child_env(&FileEnv::for_project(&c), vec![]);
        assert!(f.required_keys(&without).contains("TZ"));
        c.hash.push("!TZ".into());
        let f = FileEnv::for_file(&c, "src/tz.test.ts");
        assert!(!f.required_keys(&without).contains("TZ"));
    }

    /// Regression: loose mode (deprecated) lets every variable reach the
    /// tests, but 1.6 hashed only the short built-in hash list there, so a Go
    /// test attested with `GOMAXPROCS=1` was skipped where it is unset (and
    /// fails). Loose mode hashes the adapter's 1.5 families whenever present
    /// again (minus the user's `ignore`); strict mode, which removes them, does
    /// not; and the loose list is part of the loose digest only.
    #[test]
    fn loose_mode_hashes_the_runtime_families_when_present() {
        type Case = (&'static str, Lists, &'static [&'static str], Names, Names);
        type Lists = (&'static [&'static str], &'static [&'static str]);
        type Names = &'static [&'static str];
        let cases: &[Case] = &[
            (
                "go",
                (vci_adapter::GO_HASH, vci_adapter::GO_IGNORE),
                vci_adapter::GO_LOOSE_HASH,
                &["GOMAXPROCS", "GOGC", "GOMEMLIMIT", "GOWORK", "GOFIPS140"],
                &["GOPATH", "GOMODCACHE", "GOPROXY", "PATH"],
            ),
            (
                "pytest",
                (vci_adapter::PYTEST_HASH, vci_adapter::PYTEST_IGNORE),
                vci_adapter::PYTEST_LOOSE_HASH,
                &[
                    "PYTHON_GIL",
                    "PYTHON_CPU_COUNT",
                    "PYTHONBREAKPOINT",
                    "PYTHONMALLOC",
                ],
                &["PYTHONPATH", "PATH"],
            ),
            (
                "node-test",
                (vci_adapter::NODE_TEST_HASH, &[]),
                vci_adapter::NODE_TEST_LOOSE_HASH,
                &["NODE_PATH", "NODE_ICU_DATA", "NODE_EXTRA_CA_CERTS"],
                &["HOME", "PATH"],
            ),
            (
                "rails",
                (vci_adapter::RAILS_HASH, vci_adapter::RAILS_IGNORE),
                vci_adapter::RAILS_LOOSE_HASH,
                &[
                    "BUNDLE_WITHOUT",
                    "MT_CPU",
                    "SEED",
                    "TESTOPTS",
                    "SPEC_OPTS",
                    "RAILS_MASTER_KEY",
                ],
                &["RUBYOPT", "GEM_HOME", "BUNDLE_PATH", "PATH"],
            ),
            (
                "cargo",
                (vci_adapter::CARGO_HASH, vci_adapter::CARGO_IGNORE),
                vci_adapter::CARGO_LOOSE_HASH,
                &["RUST_BACKTRACE", "RUST_LOG", "CARGO_FOO"],
                &["CARGO_HOME", "CARGO_TARGET_DIR", "RUSTC_WRAPPER"],
            ),
        ];
        for (adapter, (bh, bi), loose, hashed, unhashed) in cases {
            let policy = |c: &EnvConfig| {
                FileEnv::for_project(c)
                    .with_builtins(bh, bi)
                    .with_loose_hash(loose)
                    .with_adapter(adapter)
            };
            let parent: Vec<(OsString, OsString)> = hashed
                .iter()
                .chain(*unhashed)
                .chain(&["APP_OTHER"])
                .map(|k| (OsString::from(k), OsString::from("v")))
                .collect();
            let mut c = EnvConfig {
                mode: EnvMode::Loose,
                ..EnvConfig::default()
            };
            let f = policy(&c);
            let child = build_child_env(&f, parent.clone());
            let req = f.required_keys(&child);
            for k in *hashed {
                assert!(child.get(k).is_some(), "{adapter}: {k} reaches the test");
                assert!(req.contains(*k), "{adapter}: {k} must be hashed: {req:?}");
            }
            for k in unhashed.iter().chain(&["APP_OTHER"]) {
                assert!(!req.contains(*k), "{adapter}: {k} not hashed: {req:?}");
            }
            // Absent: nothing to hash (only when present, as in 1.5).
            let empty = build_child_env(&f, vec![]);
            assert!(!f.required_keys(&empty).contains(hashed[0]), "{adapter}");
            // The user's ignore wins.
            c.ignore.push(hashed[0].to_string());
            let f = policy(&c);
            let req = f.required_keys(&build_child_env(&f, parent.clone()));
            assert!(!req.contains(hashed[0]), "{adapter}: {req:?}");
            // Strict mode removes them (unless built-in), so they are neither
            // seen nor hashed; the loose list does not change its digest.
            let strict = EnvConfig::default();
            let f = policy(&strict);
            let child = build_child_env(&f, parent.clone());
            let req = f.required_keys(&child);
            for k in *hashed {
                if f.classify(k) == EnvClass::Stripped {
                    assert!(child.get(k).is_none(), "{adapter}: {k} is removed");
                    assert!(!req.contains(*k), "{adapter}: {k}: {req:?}");
                }
            }
            let plain = FileEnv::for_project(&strict).with_builtins(bh, bi);
            assert_eq!(f.digest(), plain.digest(), "{adapter}: strict digest");
            let loose_cfg = EnvConfig {
                mode: EnvMode::Loose,
                ..EnvConfig::default()
            };
            assert_ne!(
                policy(&loose_cfg).digest(),
                FileEnv::for_project(&loose_cfg)
                    .with_builtins(bh, bi)
                    .digest(),
                "{adapter}: loose digest"
            );
        }
    }

    /// The child environment of every adapter: undeclared variables are
    /// stripped (including ones the runtime reads natively that are not on
    /// the built-in hash list), set variables get their declared value,
    /// ignore, hash and built-in variables keep the machine's value; built-in
    /// hash ones are hashed whenever present, built-in ignore ones never
    /// (since 2.0.2, not even when read; `hash` opts one in).
    #[test]
    fn every_adapters_child_environment() {
        type Lists = (&'static [&'static str], &'static [&'static str]);
        type Names = &'static [&'static str];
        type Case = (&'static str, Lists, Names, Names, Names);
        let cases: &[Case] = &[
            (
                "vitest",
                (vci_adapter::VITEST_HASH, vci_adapter::VITEST_IGNORE),
                &["LANG", "NODE_OPTIONS", "VITE_X"],
                &["VITEST_MAX_THREADS"],
                &["NODE_PATH", "NO_COLOR", "CI"],
            ),
            (
                "node-test",
                (vci_adapter::NODE_TEST_HASH, &[]),
                &["LANG", "LC_ALL", "NODE_OPTIONS", "UV_THREADPOOL_SIZE"],
                &[],
                &["NODE_PATH", "NODE_EXTRA_CA_CERTS", "LC_NUMERIC", "CI"],
            ),
            (
                "pytest",
                (vci_adapter::PYTEST_HASH, vci_adapter::PYTEST_IGNORE),
                &["PYTHONHASHSEED", "PYTEST_ADDOPTS", "PYTHONWARNINGS"],
                &["UV_CACHE_DIR", "VIRTUAL_ENV", "PYTHONPATH"],
                &[
                    "PYTHON_CPU_COUNT",
                    "PYTHONBREAKPOINT",
                    "PYTEST_XDIST_AUTO_NUM_WORKERS",
                    "LANG",
                ],
            ),
            (
                "go",
                (vci_adapter::GO_HASH, vci_adapter::GO_IGNORE),
                &[
                    "GOFLAGS",
                    "CGO_ENABLED",
                    "CGO_CFLAGS",
                    "GODEBUG",
                    "ZONEINFO",
                    "CC",
                ],
                &["GOPATH", "GOMODCACHE", "GOPROXY"],
                &["GOMAXPROCS", "GOGC", "GOWORK", "NODE_OPTIONS", "LANG"],
            ),
            (
                "cargo",
                (vci_adapter::CARGO_HASH, vci_adapter::CARGO_IGNORE),
                &[
                    "RUSTFLAGS",
                    "CARGO_PROFILE_TEST_OPT_LEVEL",
                    "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS",
                    "CC_aarch64_apple_darwin",
                ],
                &[
                    "CARGO_HOME",
                    "CARGO_TARGET_DIR",
                    "RUSTC_WRAPPER",
                    "SCCACHE_DIR",
                ],
                &[
                    "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER",
                    "CARGO_FOO",
                    "RUSTUP_X_UNKNOWN",
                    "LANG",
                    // Read by std (Backtrace::capture) and dependency crates
                    // (env_logger, tracing's EnvFilter), where the source scan
                    // does not see the read: a test can depend on them.
                    "RUST_BACKTRACE",
                    "RUST_LIB_BACKTRACE",
                    "RUST_LOG",
                ],
            ),
            (
                "rails",
                (vci_adapter::RAILS_HASH, vci_adapter::RAILS_IGNORE),
                &[
                    "RUBYLIB",
                    "RUBY_YJIT_ENABLE",
                    "RUBY_GC_HEAP_INIT_SLOTS",
                    "DATABASE_URL",
                    "PRIMARY_DATABASE_URL",
                    "SECRET_KEY_BASE",
                ],
                &[
                    "LANG",
                    "LC_ALL",
                    "GEM_HOME",
                    "BUNDLE_PATH",
                    "MISE_DATA_DIR",
                    "SSL_CERT_FILE",
                ],
                &[
                    "SEED",
                    "TESTOPTS",
                    "SPEC_OPTS",
                    "BUNDLE_WITHOUT",
                    "RAILS_MASTER_KEY",
                    "OPENSSL_CONF",
                    "VIPS_CONCURRENCY",
                    "RUBY_ROOT",
                ],
            ),
        ];
        for (adapter, (bh, bi), hashed, ignored, stripped) in cases {
            let mut c = EnvConfig {
                set: [("TZ", "UTC"), ("APP_SET", "declared")]
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                hash: vec!["APP_HASH".into()],
                ignore: vec!["APP_IGNORE".into()],
                ..EnvConfig::default()
            };
            let policy = |c: &EnvConfig| {
                FileEnv::for_project(c)
                    .with_builtins(bh, bi)
                    .with_adapter(adapter)
            };
            let mut p: Vec<(OsString, OsString)> = [
                ("PATH", "/bin"),
                ("HOME", "/h"),
                ("TZ", "America/New_York"),
                ("APP_SET", "machine"),
                ("APP_HASH", "h"),
                ("APP_IGNORE", "i"),
                ("APP_OTHER", "o"),
            ]
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect();
            for k in hashed.iter().chain(*ignored).chain(*stripped) {
                p.push((k.into(), "v".into()));
            }
            let child = build_child_env(&policy(&c), p.clone());
            assert_eq!(child.get("TZ").unwrap(), "UTC", "{adapter}");
            assert_eq!(child.get("APP_SET").unwrap(), "declared", "{adapter}");
            for k in ["PATH", "HOME", "APP_HASH", "APP_IGNORE"]
                .iter()
                .chain(*hashed)
                .chain(*ignored)
            {
                assert!(child.get(k).is_some(), "{adapter}: {k} must reach the test");
            }
            for k in ["APP_OTHER"].iter().chain(*stripped) {
                assert!(child.get(k).is_none(), "{adapter}: {k} must be stripped");
            }
            let f = policy(&c);
            let req = f.required_keys(&child);
            for k in ["TZ", "APP_SET", "APP_HASH"].iter().chain(*hashed) {
                assert!(req.contains(*k), "{adapter}: {k} must be hashed: {req:?}");
            }
            for k in ["PATH", "APP_IGNORE"].iter().chain(*ignored) {
                assert!(
                    !req.contains(*k),
                    "{adapter}: {k} must not be hashed: {req:?}"
                );
            }
            // Reads: ignore and built-in ignore never hashed (since 2.0.2),
            // stripped hashed as absent (unless vci's own plumbing).
            assert!(!f.hashed_when_read("APP_IGNORE"));
            assert!(f.hashed_when_read("APP_OTHER"));
            assert!(!f.hashed_when_read("HOME"));
            // The user can opt a built-in hash variable out (ignore) and a
            // built-in ignore one in (hash).
            c.ignore.push(hashed[0].to_string());
            c.hash.push("HOME".into());
            let f = policy(&c);
            let child = build_child_env(&f, p);
            let req = f.required_keys(&child);
            assert!(!req.contains(hashed[0]), "{adapter}: {req:?}");
            assert!(req.contains("HOME"), "{adapter}: {req:?}");
        }
    }

    /// No adapter's built-in ignore name is also built-in hash (that would
    /// make it hashed whenever present).
    #[test]
    fn builtin_lists_are_disjoint() {
        for (h, i) in [
            (vci_adapter::VITEST_HASH, vci_adapter::VITEST_IGNORE),
            (vci_adapter::NODE_TEST_HASH, &[][..]),
            (vci_adapter::PYTEST_HASH, vci_adapter::PYTEST_IGNORE),
            (vci_adapter::GO_HASH, vci_adapter::GO_IGNORE),
            (vci_adapter::CARGO_HASH, vci_adapter::CARGO_IGNORE),
            (vci_adapter::RAILS_HASH, vci_adapter::RAILS_IGNORE),
        ] {
            let f = FileEnv::for_project(&EnvConfig::default()).with_builtins(h, i);
            for p in f.builtin_ignore.iter() {
                let name = p.replace('*', "X");
                assert_eq!(
                    f.classify(&name),
                    EnvClass::BuiltinIgnore,
                    "{p} is matched by a built-in hash pattern"
                );
            }
        }
    }

    /// pytest: `PYTHONPATH` (vci's own) and vci's per-run variables are
    /// never hashed when read; the user's VCI_* and NODE_OPTIONS are (Go).
    #[test]
    fn never_hashed_reads_are_per_adapter() {
        let c = EnvConfig::default();
        let observed = strs(&[
            "NODE_OPTIONS",
            "VCI_BASE_REF",
            "VCI_OUT",
            "VCI_GO_TESTLOG",
            "VITEST_POOL_ID",
            "PYTHONPATH",
        ]);
        let child = ChildEnvMap::default();
        let keys = |adapter: &str| {
            FileEnv::for_file(&c, "x")
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
        assert!(!py.contains(&"PYTHONPATH".to_string()), "{py:?}");
    }

    /// Rails: what vci sets for every test process (RUBYOPT with the
    /// collector, RAILS_ENV, a fresh TMPDIR, ...) is never an input, so a
    /// read of it is not hashed; nor is a read of another built-in ignore
    /// variable (since 2.0.2), while a read of a declared `hash` one is.
    #[test]
    fn rails_run_variables_are_never_hashed() {
        let f = FileEnv::for_file(&EnvConfig::default(), "test/a_test.rb")
            .with_builtins(vci_adapter::RAILS_HASH, vci_adapter::RAILS_IGNORE)
            .with_adapter("rails");
        for k in vci_adapter::RAILS_RUN_VARS.iter().chain(&["TMPDIR"]) {
            assert!(!f.hashed_when_read(k), "{k}");
        }
        assert!(!f.hashed_when_read("HOME"));
        let mut c = EnvConfig::default();
        c.hash.push("HOME".into());
        let f = FileEnv::for_file(&c, "test/a_test.rb")
            .with_builtins(vci_adapter::RAILS_HASH, vci_adapter::RAILS_IGNORE)
            .with_adapter("rails");
        assert!(f.hashed_when_read("HOME"));
    }

    #[test]
    fn secret_warning() {
        let mut c = cfg(EnvMode::Strict);
        c.hash.push("NPM_TOKEN".into());
        let f = FileEnv::for_file(&c, "a.test.ts");
        assert_eq!(f.secret_like(), ["NPM_TOKEN"]);
    }

    /// The old key names parse as the new ones, top level, per project and
    /// in [[env.files]], with one warning naming the new keys; giving both
    /// names is an error; `mode = "strict"` is silent, `"loose"` warns.
    #[test]
    fn old_key_names_are_aliases() {
        let c = Config::parse(
            r#"
[env]
mode = "strict"
global = ["NODE_ENV", "FEATURE_*"]
pass_through = ["GITHUB_TOKEN"]
[[env.files]]
match = ["src/db/**"]
env = ["DATABASE_URL"]
pass_through = ["PG*"]

[[projects]]
name = "web"
path = "."
adapter = "vitest"

[[projects]]
name = "py"
path = "."
adapter = "pytest"
[projects.env]
mode = "loose"
pass_through = ["AWS_*"]
"#,
        )
        .unwrap();
        let s = c.project_specs();
        assert_eq!(s[0].env.hash, ["NODE_ENV", "FEATURE_*"]);
        assert_eq!(s[0].env.ignore, ["GITHUB_TOKEN"]);
        assert_eq!(s[0].env.files[0].hash, ["DATABASE_URL"]);
        assert_eq!(s[0].env.files[0].ignore, ["PG*"]);
        // Per-project keys replace the top-level ones; others are inherited.
        assert_eq!(s[1].env.ignore, ["AWS_*"]);
        assert_eq!(s[1].env.hash, ["NODE_ENV", "FEATURE_*"]);
        assert_eq!(s[1].env.mode, EnvMode::Loose);
        let w = c.warnings("vci.toml");
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(
            w[0].contains("env.global -> hash")
                && w[0].contains("env.pass_through -> ignore")
                && w[0].contains("env.files[0].env -> hash")
                && w[0].contains("env.files[0].pass_through -> ignore")
                && w[0].contains("projects.py.env.pass_through -> ignore"),
            "{w:?}"
        );
        assert!(
            w[1].contains("projects.py.env.mode") && w[1].contains("loose"),
            "{w:?}"
        );
        // The same policy, spelt with the new names: same digest.
        let new = Config::parse(
            r#"
[env]
hash = ["NODE_ENV", "FEATURE_*"]
ignore = ["GITHUB_TOKEN"]
[[env.files]]
match = ["src/db/**"]
hash = ["DATABASE_URL"]
ignore = ["PG*"]
"#,
        )
        .unwrap();
        assert!(new.warnings("vci.toml").is_empty());
        assert_eq!(
            FileEnv::for_file(&new.project_specs()[0].env, "src/db/a.ts").digest(),
            FileEnv::for_file(&s[0].env, "src/db/a.ts").digest()
        );
        for both in [
            "[env]\nglobal = [\"A\"]\nhash = [\"B\"]\n",
            "[env]\npass_through = [\"A\"]\nignore = [\"B\"]\n",
            "[[env.files]]\nmatch = [\"x\"]\nenv = [\"A\"]\nhash = [\"B\"]\n",
            "[[projects]]\nname = \"a\"\npath = \".\"\nadapter = \"go\"\n[projects.env]\nglobal = [\"A\"]\nhash = [\"B\"]\n",
        ] {
            let e = Config::parse(both).unwrap_err();
            assert!(format!("{e:#}").contains("old name"), "{both}: {e:#}");
        }
    }

    /// `set` per project replaces the top-level table; names are plain
    /// variable names; values are any string.
    #[test]
    fn set_parsing_and_per_project_replacement() {
        let c = Config::parse(
            r#"
[env]
set = { TZ = "UTC", LANG = "C.UTF-8" }
hash = ["APP_*", "!APP_SECRET"]

[[projects]]
name = "a"
path = "."
adapter = "go"

[[projects]]
name = "b"
path = "."
adapter = "cargo"
[projects.env]
set = { TZ = "Asia/Tokyo" }
"#,
        )
        .unwrap();
        let s = c.project_specs();
        assert_eq!(s[0].env.set.len(), 2);
        assert_eq!(s[1].env.set.len(), 1);
        assert_eq!(s[1].env.set["TZ"], "Asia/Tokyo");
        assert_eq!(s[1].env.hash, ["APP_*", "!APP_SECRET"]);
        let f = FileEnv::for_file(&s[0].env, "x");
        assert_eq!(f.classify("APP_MODE"), EnvClass::Hash);
        assert_eq!(f.classify("APP_SECRET"), EnvClass::Stripped);
        for bad in [
            "\"A*\" = \"x\"",
            "\"!A\" = \"x\"",
            "\"A=B\" = \"x\"",
            "\"\" = \"x\"",
        ] {
            assert!(
                Config::parse(&format!("[env]\nset = {{ {bad} }}\n")).is_err(),
                "{bad}"
            );
        }
        assert!(Config::parse("[env]\nset = { EMPTY = \"\" }\n").is_ok());
        assert!(
            Config::parse("[env]\nset = { N = 1 }\n").is_err(),
            "strings only"
        );
    }
}
