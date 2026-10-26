//! `vci.toml`: project location(s), skip policy and env configuration.
//!
//! Two forms:
//!
//! * single project: top-level `project` (default `"."`) and `adapter`
//!   (default `"vitest"`);
//! * several projects: a `[[projects]]` array with `name`, `path`, `adapter`
//!   and optional `[projects.policy]` / `[projects.env]` tables. Each key
//!   given in a project's table replaces the top-level key of the same name
//!   for that project; keys not given are inherited from `[policy]` / `[env]`.
//!
//! Unknown keys are errors: in `vci plan` a config that cannot be parsed
//! means every test runs.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::util::{glob_match, name_match, parse_duration};

pub const CONFIG_FILE: &str = "vci.toml";
pub const ALLOWED_SIGNERS_FILE: &str = ".vci/allowed_signers";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Project directory relative to the repo root (single-project form).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Adapter (single-project form); default `"vitest"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
    /// Rails adapter (single-project form): the test framework, `"minitest"`
    /// or `"rspec"`; unset: detected (see [`ProjectConfig::runner`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner: Option<String>,
    /// node-test adapter (single-project form): the package.json script
    /// that runs the tests (default `"test"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_script: Option<String>,
    /// node-test adapter: test file globs instead of a script.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_globs: Option<Vec<String>>,
    /// node-test adapter: node options with `test_globs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_args: Option<Vec<String>>,
    /// Rails adapter (single-project form): which of the files Rails reads
    /// while it boots are inputs, `"loose"` (default) or `"strict"`; see
    /// [`RailsInputs`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rails_inputs: Option<RailsInputs>,
    /// Rails adapter (single-project form): more globs (relative to the
    /// project dir) whose files are never inputs; see [`RailsInputs`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore_inputs: Option<Vec<String>>,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub env: EnvConfig,
    /// Multi-project form.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<ProjectConfig>,
    /// Extra inputs declared for test ids (`[[inputs]]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<InputsConfig>,
    /// Deprecated env keys this file used (`env.global`, ...), with their
    /// new names, for the warning ([`Config::warnings`]).
    #[serde(skip)]
    pub env_renamed: Vec<(String, &'static str)>,
    /// Where this file sets `mode = "loose"` (deprecated), for the warning.
    #[serde(skip)]
    pub env_loose: Vec<String>,
}

/// `[[inputs]]`: files a test reads that its adapter cannot see (Cargo: reads
/// outside the package directories). Every file matching an `extra` glob,
/// and the listing of every directory below each glob's fixed prefix, is
/// hashed into the attestation of every test id matching `match`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputsConfig {
    /// Test ids relative to the project dir (globs), e.g. `crates/b#test:*`.
    #[serde(rename = "match")]
    pub match_: Vec<String>,
    /// Globs relative to the project dir, e.g. `data/**`.
    pub extra: Vec<String>,
}

fn default_project() -> String {
    ".".into()
}
fn default_adapter() -> String {
    "vitest".into()
}

/// One entry of `[[projects]]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    /// Unique name (letters, digits, `.`, `_`, `-`); recorded in attestations.
    pub name: String,
    /// Project directory relative to the repo root.
    #[serde(default = "default_project")]
    pub path: String,
    pub adapter: String,
    /// Rails adapter: the test framework, `"minitest"` (`bin/rails test`) or
    /// `"rspec"`. Unset: RSpec when `Gemfile.lock` has `rspec-core` and
    /// there is a `spec/` (or `.rspec`) but no Minitest file, both when both
    /// are present, Minitest otherwise. Read from the base commit in CI.
    #[serde(default)]
    pub runner: Option<String>,
    /// node-test adapter: the package.json script that runs the tests
    /// (default `"test"`); or `test_globs` (+ `node_args`) instead.
    #[serde(default)]
    pub test_script: Option<String>,
    #[serde(default)]
    pub test_globs: Option<Vec<String>>,
    #[serde(default)]
    pub node_args: Option<Vec<String>>,
    /// Rails adapter: `"loose"` (default) or `"strict"`; see [`RailsInputs`].
    #[serde(default)]
    pub rails_inputs: Option<RailsInputs>,
    /// Rails adapter: more globs (relative to the project dir) whose files
    /// are never inputs.
    #[serde(default)]
    pub ignore_inputs: Option<Vec<String>>,
    #[serde(default)]
    pub policy: Option<PolicyOverride>,
    #[serde(default)]
    pub env: Option<EnvOverride>,
    /// Replaces the top-level `[[inputs]]` for this project when given.
    #[serde(default)]
    pub inputs: Option<Vec<InputsConfig>>,
}

/// Per-project policy keys; each one given replaces the top-level key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyOverride {
    pub platform: Option<Platform>,
    pub libraries: Option<Libraries>,
    pub platform_overrides: Option<Vec<PlatformOverride>>,
    pub max_ttl: Option<String>,
    pub allow_dirty: Option<bool>,
    pub no_skip_refs: Option<Vec<String>>,
    pub no_skip_refs_except: Option<Vec<String>>,
    pub attest_on_any_ref: Option<Vec<String>>,
    pub never_skip: Option<Vec<String>>,
    pub go_allow_net: Option<bool>,
    pub ignore_taints: Option<Vec<String>>,
    /// Removed in vci 1.4.0: parsed (so a `vci.toml` that still has it stays
    /// valid) and otherwise ignored; see [`Policy::removed_rails_allow_db`].
    #[serde(default, rename = "rails_allow_db", skip_serializing)]
    pub removed_rails_allow_db: Option<bool>,
    pub node_exact: Option<bool>,
    pub allow_superuser_mismatch: Option<bool>,
    pub rails_autoload_lookups: Option<bool>,
}

/// Per-project env keys; each one given replaces the top-level key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EnvOverride {
    pub mode: Option<EnvMode>,
    pub set: Option<BTreeMap<String, String>>,
    pub hash: Option<Vec<String>>,
    pub ignore: Option<Vec<String>>,
    pub files: Option<Vec<EnvFiles>>,
    /// Old name of `hash` (before vci 1.6.0).
    #[serde(rename = "global", skip_serializing)]
    pub old_global: Option<Vec<String>>,
    /// Old name of `ignore` (before vci 1.6.0).
    #[serde(rename = "pass_through", skip_serializing)]
    pub old_pass_through: Option<Vec<String>>,
}

/// The effective configuration of one project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSpec {
    /// Empty in the single-project form.
    pub name: String,
    /// Normalised project dir relative to the repo root ("." for the root).
    pub rel: String,
    pub adapter: String,
    /// Rails: the `runner` setting (`None`: detected).
    pub runner: Option<String>,
    /// node-test: the test command settings.
    pub node_test: vci_adapter::NodeTestOptions,
    /// Rails: the `rails_inputs` setting (default loose); `None` for the
    /// other adapters.
    pub rails_inputs: Option<RailsInputs>,
    /// Rails: the `ignore_inputs` setting.
    pub ignore_inputs: Vec<String>,
    pub policy: Policy,
    pub env: EnvConfig,
    pub inputs: Vec<InputsConfig>,
}

/// `rails_inputs` (2.7.36): which of the files Rails reads while it boots
/// are inputs of a Rails project's units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RailsInputs {
    /// The default: [`vci_adapter::RAILS_LOOSE_IGNORED_INPUTS`] (routes,
    /// initializers, environments, the boot files, migrations, locales and
    /// the autoload lookup records) and `ignore_inputs` are left out of
    /// every manifest. A change to one of them runs no test again on a pull
    /// request; a run that skips nothing (the default branch's, through
    /// `policy.no_skip_refs`) runs the tests against it.
    #[default]
    Loose,
    /// Everything the test's process read is an input (vci before 2.7.36),
    /// except what `ignore_inputs` names.
    Strict,
}

impl RailsInputs {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loose => "loose",
            Self::Strict => "strict",
        }
    }
}

/// The globs (relative to the project dir) whose paths a Rails project
/// leaves out of its manifests: [`vci_adapter::RAILS_LOOSE_IGNORED_INPUTS`]
/// in loose mode, then `ignore_inputs`, once each. Empty without a mode
/// (the other adapters).
pub fn ignored_inputs(mode: Option<RailsInputs>, ignore_inputs: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if mode == Some(RailsInputs::Loose) {
        out.extend(
            vci_adapter::RAILS_LOOSE_IGNORED_INPUTS
                .iter()
                .map(|g| (*g).to_owned()),
        );
    }
    if mode.is_some() {
        for g in ignore_inputs {
            if !out.contains(g) {
                out.push(g.clone());
            }
        }
    }
    out
}

/// The item of `ignored` (globs relative to the project dir, see
/// [`ignored_inputs`]) that leaves the repository path `path` out of a
/// manifest, if any. `project` is the project dir relative to the
/// repository root (`.` for the root). `dir/**` also matches `dir` (its
/// listing); [`vci_adapter::AUTOLOAD_INPUTS`] matches any path with a
/// `.vci-autoload` component, wherever it is.
pub fn ignored_input<'a>(ignored: &'a [String], project: &str, path: &str) -> Option<&'a str> {
    let rel = if project == "." {
        Some(path)
    } else {
        path.strip_prefix(project).and_then(|r| r.strip_prefix('/'))
    };
    ignored.iter().map(String::as_str).find(|g| {
        if *g == vci_adapter::AUTOLOAD_INPUTS {
            return path.split('/').any(|c| c == vci_adapter::AUTOLOAD_INPUTS);
        }
        let Some(rel) = rel else { return false };
        glob_match(g, rel) || g.strip_suffix("/**").is_some_and(|d| d == rel)
    })
}

impl ProjectSpec {
    /// The globs this project's manifests leave out ([`ignored_inputs`]).
    pub fn ignored_inputs(&self) -> Vec<String> {
        ignored_inputs(self.rails_inputs, &self.ignore_inputs)
    }

    /// The adapter options this project's settings give.
    pub fn adapter_options(&self) -> vci_adapter::AdapterOptions {
        vci_adapter::AdapterOptions {
            rails_runner: self
                .runner
                .as_deref()
                .and_then(vci_adapter::RailsRunner::parse),
            node_test: self.node_test.clone(),
        }
    }
}

impl InputsConfig {
    fn check(&self) -> Result<()> {
        if self.match_.is_empty() || self.extra.is_empty() {
            bail!("[[inputs]] needs non-empty `match` and `extra` lists");
        }
        for g in &self.extra {
            if g.is_empty()
                || g.starts_with('/')
                || g.contains('\\')
                || g.split('/').any(|c| c == "..")
            {
                bail!(
                    "[[inputs]] extra glob {g:?} must be relative to the project dir, without '..'"
                );
            }
        }
        Ok(())
    }
}

/// The sorted, deduplicated `extra` globs declared for a project-relative
/// test id.
pub fn extra_inputs(inputs: &[InputsConfig], project_rel: &str) -> Vec<String> {
    let mut out: Vec<String> = inputs
        .iter()
        .filter(|i| i.match_.iter().any(|g| glob_match(g, project_rel)))
        .flat_map(|i| i.extra.iter().cloned())
        .collect();
    out.sort();
    out.dedup();
    out
}

fn normalise_rel(p: &str) -> String {
    let parts: Vec<&str> = p
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    if parts.is_empty() {
        ".".into()
    } else {
        parts.join("/")
    }
}

fn check_rel(what: &str, p: &str) -> Result<()> {
    if p.is_empty() || p.starts_with('/') || p.contains('\\') || p.split('/').any(|c| c == "..") {
        bail!("{what} must be a relative path inside the repo, got {p:?}");
    }
    Ok(())
}

/// `runner` is only for the Rails adapter, and is "minitest" or "rspec".
fn check_runner(what: &str, adapter: &str, runner: Option<&str>) -> Result<()> {
    let Some(r) = runner else { return Ok(()) };
    if adapter != "rails" {
        bail!("{what}: `runner` is a setting of the rails adapter, not {adapter:?}");
    }
    if vci_adapter::RailsRunner::parse(r).is_none() {
        bail!("{what}: runner must be \"minitest\" or \"rspec\", got {r:?}");
    }
    Ok(())
}

/// `rails_inputs` and `ignore_inputs` are settings of the rails adapter;
/// each glob is relative to the project dir, without `..`.
fn check_rails_inputs(
    what: &str,
    adapter: &str,
    mode: Option<RailsInputs>,
    globs: Option<&[String]>,
) -> Result<()> {
    if mode.is_none() && globs.is_none() {
        return Ok(());
    }
    if adapter != "rails" {
        bail!(
            "{what}: `rails_inputs` and `ignore_inputs` are settings of the rails adapter, not {adapter:?}"
        );
    }
    for g in globs.unwrap_or_default() {
        if g.trim().is_empty()
            || g.starts_with('/')
            || g.contains('\\')
            || g.split('/').any(|c| c == "..")
        {
            bail!(
                "{what}: ignore_inputs glob {g:?} must be relative to the project dir, without '..'"
            );
        }
    }
    Ok(())
}

/// `test_script`, `test_globs` and `node_args` are settings of the
/// node-test adapter; `test_script` and `test_globs` exclude each other, and
/// `node_args` needs `test_globs`.
fn check_node_test(what: &str, adapter: &str, o: &vci_adapter::NodeTestOptions) -> Result<()> {
    if o == &vci_adapter::NodeTestOptions::default() {
        return Ok(());
    }
    if adapter != "node-test" {
        bail!(
            "{what}: `test_script`, `test_globs` and `node_args` are settings of the node-test adapter, not {adapter:?}"
        );
    }
    if o.test_script.is_some() && o.test_globs.is_some() {
        bail!("{what}: set either `test_script` or `test_globs`, not both");
    }
    if o.node_args.is_some() && o.test_globs.is_none() {
        bail!(
            "{what}: `node_args` needs `test_globs` (with a script, its own node options are used)"
        );
    }
    if let Some(sc) = &o.test_script
        && sc.trim().is_empty()
    {
        bail!("{what}: `test_script` is empty");
    }
    if let Some(g) = &o.test_globs {
        if g.is_empty() {
            bail!("{what}: `test_globs` is empty");
        }
        for p in g {
            if p.is_empty()
                || p.starts_with('-')
                || p.starts_with('/')
                || p.split('/').any(|c| c == "..")
            {
                bail!("{what}: test glob {p:?} must be relative to the project dir, without '..'");
            }
        }
    }
    Ok(())
}

fn check_adapter(a: &str) -> Result<()> {
    if !vci_adapter::ADAPTERS.contains(&a) {
        bail!(
            "unsupported adapter {a:?} (supported: {})",
            vci_adapter::ADAPTERS
                .iter()
                .map(|a| format!("{a:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    #[default]
    Any,
    SameOs,
    Exact,
}

/// How native libraries and the interpreter's library versions are compared
/// (`policy.libraries`). Ordered from the loosest to the strictest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Libraries {
    /// Native libraries (`native:<file name>` externals) match by library
    /// name ([`crate::externals::native_stem`]) when one of that name is
    /// loaded where the attestation is checked; the library versions of the
    /// toolchain (`ruby libraries`: sqlite, yaml, tz; `python libraries`:
    /// sqlite, openssl) are not compared.
    Any,
    /// Native libraries by file name and content hash, library versions
    /// exactly.
    #[default]
    Exact,
}

/// `[[policy.platform_overrides]]`: a stricter `platform` and/or
/// `libraries` for the test files matching `match`. At least one is given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformOverride {
    #[serde(rename = "match")]
    pub match_: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub libraries: Option<Libraries>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub platform: Platform,
    /// `"exact"` (default) or `"any"`: see [`Libraries`]. Read from the base
    /// commit, per test file like `platform`.
    #[serde(default)]
    pub libraries: Libraries,
    #[serde(default)]
    pub platform_overrides: Vec<PlatformOverride>,
    /// Longest accepted `expires_at - issued_at`.
    #[serde(default = "default_max_ttl")]
    pub max_ttl: String,
    /// Accept attestations made from a dirty working tree.
    #[serde(default = "default_true")]
    pub allow_dirty: bool,
    /// Refs (globs) on which nothing is ever skipped.
    #[serde(default)]
    pub no_skip_refs: Vec<String>,
    /// `allowed_signers` principals whose attestations may still produce a
    /// SKIP on a ref matching `no_skip_refs` (typically the CI key that
    /// attested the previous commit of the branch). Empty: nothing is
    /// skipped on those refs.
    #[serde(default)]
    pub no_skip_refs_except: Vec<String>,
    /// Principals of `no_skip_refs_except` that `vci ci --key` may attest
    /// as on refs that do not match `no_skip_refs` (a pull request's run):
    /// what such a run ran is then skipped on the protected refs too. Only
    /// for a key that pull requests of the repository itself can use and
    /// forks cannot (a repository secret), where their authors are trusted
    /// with that.
    #[serde(default)]
    pub attest_on_any_ref: Vec<String>,
    /// Test files (project-relative globs) that are never skipped, e.g. files
    /// with dependencies no collector can see (SQLite `ATTACH` behind a
    /// custom authorizer, a C library reading files).
    #[serde(default)]
    pub never_skip: Vec<String>,
    /// Go: attest packages whose test links package `net` (for example
    /// through testify's `net/http` import). vci cannot observe network I/O,
    /// so this is the user's statement that these tests do none; it is read
    /// from the base commit, and attestations that needed it are only
    /// accepted while it is set there.
    #[serde(default)]
    pub go_allow_net: bool,
    /// Taints that do not refuse a unit: globs over a taint's reason key
    /// (`category:kind`, the key of `vci run`'s "why not attested" lines,
    /// [`crate::run::taint_key`]); `*` matches any run of characters, and a
    /// pattern without `:` also matches every key of that category
    /// (`"process"` = `"process:*"`). A waived taint is recorded in the
    /// attestation (`waived`), which `vci plan` accepts only while the base
    /// commit's policy still waives it. The collectors could not record what
    /// such a unit did, so this trades determinism for CI time; `vci:` taints
    /// (vci's own record is incomplete) are never waived. Three of `vci run`'s
    /// own refusals are taints too: `outside-repository` (a read outside the
    /// repository, then not hashed), `wrote-inside-repository` (then the
    /// written paths are not inputs) and `result:skipped` (a pass with skipped
    /// tests); a failed result never is one.
    #[serde(default)]
    pub ignore_taints: Vec<String>,
    /// `rails_allow_db`, removed in vci 1.4.0 (the Rails test database is
    /// the test engine's business: vci neither prepares nor refuses it, and
    /// its contents are not an input). Still parsed, so that a base
    /// `vci.toml` that sets it stays valid (an invalid one runs every test);
    /// it has no effect, and `vci run` and `vci plan` warn about it
    /// ([`Config::removed_keys`]). Never part of the effective policy
    /// ([`Config::project_specs`] leaves it out).
    #[serde(default, rename = "rails_allow_db", skip_serializing)]
    pub removed_rails_allow_db: Option<bool>,
    /// Vitest and node-test: require the exact Node version the attestation
    /// was made with (default: the same major version).
    #[serde(default)]
    pub node_exact: bool,
    /// Accept an attestation made as root where the tests now run as another
    /// user, or the other way round (the toolchain's `superuser` field is
    /// not compared). Risky: permission checks do not apply to root, so a
    /// test whose outcome depends on file permissions (a mode-000 file that
    /// must be unreadable, a read-only directory that must refuse a write)
    /// can pass on one side and fail on the other. For CI runners that run
    /// as root (`container:` jobs) accepting attestations made on laptops.
    /// Read from the base commit.
    #[serde(default)]
    pub allow_superuser_mismatch: bool,
    /// Rails (2.5.0): a directory Zeitwerk lists only to define constants
    /// (to set up autoloads; never to eager load) is not an input as a
    /// listing. What is recorded instead are the constants the test's
    /// process looked up and did not find in that directory's namespace
    /// (`const_missing`, `const_get`, `const_defined?`): the unit runs
    /// again only when the directory gains a file or directory defining one
    /// of them. A namespace whose constants are enumerated
    /// (`Module#constants`) keeps its listings. A file added to an autoload
    /// directory (by the change, or on the base branch since the
    /// attestation) otherwise made every test that booted the application
    /// run again. `defined?(Constant)`, which Ruby answers without any
    /// method vci can see, is found in the source of the repository files
    /// the test loaded (2.6.1); a gem asking that about an application
    /// constant is not, and such a test may pass without having seen a
    /// constant a new file defines. Read from the
    /// base commit, which must allow it for `vci plan` to accept such an
    /// attestation; the collector records lookups only when the policy
    /// `vci run` reads allows it.
    #[serde(default)]
    pub rails_autoload_lookups: bool,
}

fn default_max_ttl() -> String {
    "30d".into()
}
fn default_true() -> bool {
    true
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            platform: Platform::Any,
            libraries: Libraries::Exact,
            platform_overrides: vec![],
            max_ttl: default_max_ttl(),
            allow_dirty: true,
            no_skip_refs: vec![],
            no_skip_refs_except: vec![],
            attest_on_any_ref: vec![],
            never_skip: vec![],
            go_allow_net: false,
            ignore_taints: vec![],
            removed_rails_allow_db: None,
            node_exact: false,
            allow_superuser_mismatch: false,
            rails_autoload_lookups: false,
        }
    }
}

impl Policy {
    pub fn max_ttl_secs(&self) -> Result<i64> {
        parse_duration(&self.max_ttl).context("policy.max_ttl")
    }

    fn check(&self) -> Result<()> {
        self.max_ttl_secs()?;
        for o in &self.platform_overrides {
            if o.platform.is_none() && o.libraries.is_none() {
                bail!(
                    "policy.platform_overrides: an entry (match = {:?}) sets neither `platform` nor `libraries`",
                    o.match_
                );
            }
        }
        for p in &self.no_skip_refs_except {
            if p.is_empty() || p.chars().any(char::is_whitespace) {
                bail!(
                    "policy.no_skip_refs_except: {p:?} is not an allowed_signers principal (non-empty, no whitespace)"
                );
            }
        }
        for p in &self.attest_on_any_ref {
            if p.is_empty() || p.chars().any(char::is_whitespace) {
                bail!(
                    "policy.attest_on_any_ref: {p:?} is not an allowed_signers principal (non-empty, no whitespace)"
                );
            }
            if !self.no_skip_refs_except.contains(p) {
                bail!(
                    "policy.attest_on_any_ref: {p:?} is not in policy.no_skip_refs_except (a key outside that list may attest anywhere already)"
                );
            }
        }
        for p in &self.ignore_taints {
            if p.trim().is_empty() {
                bail!("policy.ignore_taints: an empty pattern matches no taint");
            }
        }
        Ok(())
    }

    /// The policy that waives `taint` of an `adapter` unit, if any:
    /// `policy.go_allow_net` (Go's `go:net:`) or the first matching
    /// `policy.ignore_taints` pattern. `vci:` taints are never waived (they
    /// mean vci's own record of the unit is incomplete or broken).
    pub fn taint_waiver(&self, adapter: &str, taint: &str) -> Option<String> {
        let key = crate::run::taint_key(taint);
        if key == "vci" || key.starts_with("vci:") {
            return None;
        }
        if adapter == "go" && self.go_allow_net && taint.starts_with(vci_adapter::GO_NET_TAINT) {
            return Some("policy.go_allow_net".to_owned());
        }
        self.ignore_taints
            .iter()
            .find(|p| ignore_pattern_matches(p, &key))
            .map(|p| format!("policy.ignore_taints {p:?}"))
    }

    /// On a ref matching `no_skip_refs`, may an attestation by `principal`
    /// still skip?
    pub fn skips_on_no_skip_ref(&self, principal: &str) -> bool {
        self.no_skip_refs_except.iter().any(|p| p == principal)
    }

    /// The `never_skip` glob matching a project-relative test path, if any.
    pub fn never_skip_match(&self, project_rel: &str) -> Option<&str> {
        self.never_skip
            .iter()
            .find(|g| glob_match(g, project_rel))
            .map(String::as_str)
    }

    /// Effective platform policy for a project-relative test path (the
    /// strictest of the default and any matching override).
    pub fn platform_for(&self, project_rel: &str) -> Platform {
        let mut p = self.platform;
        for o in &self.platform_overrides {
            if let Some(v) = o.platform
                && o.match_.iter().any(|g| glob_match(g, project_rel))
            {
                p = p.max(v);
            }
        }
        p
    }

    /// Effective libraries policy for a project-relative test path (the
    /// strictest of the default and any matching override that sets it).
    pub fn libraries_for(&self, project_rel: &str) -> Libraries {
        let mut l = self.libraries;
        for o in &self.platform_overrides {
            if let Some(v) = o.libraries
                && o.match_.iter().any(|g| glob_match(g, project_rel))
            {
                l = l.max(v);
            }
        }
        l
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EnvMode {
    #[default]
    Strict,
    Loose,
}

/// `[env]` (docs/ENV.md): three lists. Every variable none of them (nor a
/// runner's built-in lists) names is removed from the test processes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EnvConfig {
    /// `"strict"` (the default, and the only mode from vci 1.6.0 on) or
    /// `"loose"` (deprecated: every variable reaches the tests).
    #[serde(default)]
    pub mode: EnvMode,
    /// Set by vci in every test process it starts, on every machine,
    /// whatever the machine's value: inputs by construction.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<String, String>,
    /// Taken from the machine, visible to the tests, hashed: another value
    /// (or its absence) re-runs the test. Patterns (`*`, `!` excludes).
    #[serde(default)]
    pub hash: Vec<String>,
    /// Taken from the machine, visible to the tests, never hashed and never a
    /// reason to re-run. Patterns (`*`, `!` excludes).
    #[serde(default)]
    pub ignore: Vec<String>,
    #[serde(default)]
    pub files: Vec<EnvFiles>,
    /// Old name of `hash` (before vci 1.6.0).
    #[serde(default, rename = "global", skip_serializing)]
    pub old_global: Option<Vec<String>>,
    /// Old name of `ignore` (before vci 1.6.0).
    #[serde(default, rename = "pass_through", skip_serializing)]
    pub old_pass_through: Option<Vec<String>>,
}

/// `[[env.files]]`: `hash` and `ignore` patterns for the test files matching
/// `match` only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvFiles {
    #[serde(rename = "match")]
    pub match_: Vec<String>,
    #[serde(default)]
    pub hash: Vec<String>,
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Old name of `hash` (before vci 1.6.0).
    #[serde(default, rename = "env", skip_serializing)]
    pub old_env: Option<Vec<String>>,
    /// Old name of `ignore` (before vci 1.6.0).
    #[serde(default, rename = "pass_through", skip_serializing)]
    pub old_pass_through: Option<Vec<String>>,
}

/// Move an old key's value to its new key (`at` names the table for errors
/// and the deprecation warning).
fn rename_key(
    old: &mut Option<Vec<String>>,
    new: &mut Vec<String>,
    at: &str,
    old_name: &str,
    new_name: &'static str,
    renamed: &mut Vec<(String, &'static str)>,
) -> Result<()> {
    if let Some(v) = old.take() {
        if !new.is_empty() {
            bail!("{at}: `{old_name}` is the old name of `{new_name}`; give only `{new_name}`");
        }
        *new = v;
        renamed.push((format!("{at}.{old_name}"), new_name));
    }
    Ok(())
}

impl EnvFiles {
    fn normalize(&mut self, at: &str, renamed: &mut Vec<(String, &'static str)>) -> Result<()> {
        rename_key(
            &mut self.old_env,
            &mut self.hash,
            at,
            "env",
            "hash",
            renamed,
        )?;
        rename_key(
            &mut self.old_pass_through,
            &mut self.ignore,
            at,
            "pass_through",
            "ignore",
            renamed,
        )
    }
}

/// `set` names: plain variable names (no patterns), values without NUL.
fn check_set(at: &str, set: &BTreeMap<String, String>) -> Result<()> {
    for (k, v) in set {
        if k.is_empty() || k.contains(['=', '\0', '*', '!']) || k.chars().any(char::is_whitespace) {
            bail!("{at}.set: {k:?} is not a variable name (patterns are not allowed in `set`)");
        }
        if v.contains('\0') {
            bail!("{at}.set: the value of {k} contains a NUL byte");
        }
    }
    Ok(())
}

impl EnvConfig {
    /// Move the old key names to the new ones and check `set`.
    fn normalize(
        &mut self,
        at: &str,
        renamed: &mut Vec<(String, &'static str)>,
        loose: &mut Vec<String>,
    ) -> Result<()> {
        rename_key(
            &mut self.old_global,
            &mut self.hash,
            at,
            "global",
            "hash",
            renamed,
        )?;
        rename_key(
            &mut self.old_pass_through,
            &mut self.ignore,
            at,
            "pass_through",
            "ignore",
            renamed,
        )?;
        for (i, f) in self.files.iter_mut().enumerate() {
            f.normalize(&format!("{at}.files[{i}]"), renamed)?;
        }
        if self.mode == EnvMode::Loose {
            loose.push(format!("{at}.mode"));
        }
        check_set(at, &self.set)
    }
}

impl EnvOverride {
    fn normalize(
        &mut self,
        at: &str,
        renamed: &mut Vec<(String, &'static str)>,
        loose: &mut Vec<String>,
    ) -> Result<()> {
        for (old, new, old_name, new_name) in [
            (&mut self.old_global, &mut self.hash, "global", "hash"),
            (
                &mut self.old_pass_through,
                &mut self.ignore,
                "pass_through",
                "ignore",
            ),
        ] {
            if let Some(v) = old.take() {
                if new.is_some() {
                    bail!(
                        "{at}: `{old_name}` is the old name of `{new_name}`; give only `{new_name}`"
                    );
                }
                *new = Some(v);
                renamed.push((format!("{at}.{old_name}"), new_name));
            }
        }
        for (i, f) in self.files.iter_mut().flatten().enumerate() {
            f.normalize(&format!("{at}.files[{i}]"), renamed)?;
        }
        if self.mode == Some(EnvMode::Loose) {
            loose.push(format!("{at}.mode"));
        }
        if let Some(set) = &self.set {
            check_set(at, set)?;
        }
        Ok(())
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let mut c: Config = toml::from_str(text).context("parsing vci.toml")?;
        c.normalize_env()?;
        c.validate()?;
        Ok(c)
    }

    /// Old env key names to new ones (recorded for [`Self::warnings`]).
    fn normalize_env(&mut self) -> Result<()> {
        let (mut renamed, mut loose) = (Vec::new(), Vec::new());
        self.env.normalize("env", &mut renamed, &mut loose)?;
        for p in &mut self.projects {
            if let Some(o) = &mut p.env {
                o.normalize(
                    &format!("projects.{}.env", p.name),
                    &mut renamed,
                    &mut loose,
                )?;
            }
        }
        self.env_renamed = renamed;
        self.env_loose = loose;
        Ok(())
    }

    /// Every warning about this file's keys (removed and deprecated ones),
    /// for the `vci.toml` described by `which`.
    pub fn warnings(&self, which: &str) -> Vec<String> {
        let mut out: Vec<String> = self.removed_keys_warning(which).into_iter().collect();
        if !self.env_renamed.is_empty() {
            let list: Vec<String> = self
                .env_renamed
                .iter()
                .map(|(old, new)| format!("{old} -> {new}"))
                .collect();
            out.push(format!(
                "{which} uses the old env key names, which still work: rename {} (vci 1.6.0 renamed `global`, and `env` in [[env.files]], to `hash`, and `pass_through` to `ignore`; see docs/ENV.md)",
                list.join(", ")
            ));
        }
        if !self.env_loose.is_empty() {
            out.push(format!(
                "{} = \"loose\" in {which} is deprecated: it behaves as before (every variable reaches the tests; ones a test is seen reading are hashed) and will be removed; remove it to get the default, where only the variables vci.toml and the built-in lists name reach the tests (docs/ENV.md)",
                self.env_loose.join(", ")
            ));
        }
        out
    }

    fn validate(&self) -> Result<()> {
        self.policy.check()?;
        for i in &self.inputs {
            i.check()?;
        }
        for p in &self.projects {
            for i in p.inputs.iter().flatten() {
                i.check()?;
            }
        }
        if self.projects.is_empty() {
            let adapter = self.adapter.as_deref().unwrap_or("vitest");
            check_adapter(adapter)?;
            check_runner("vci.toml", adapter, self.runner.as_deref())?;
            check_node_test("vci.toml", adapter, &self.node_test_options())?;
            check_rails_inputs(
                "vci.toml",
                adapter,
                self.rails_inputs,
                self.ignore_inputs.as_deref(),
            )?;
            check_rel("project", self.project.as_deref().unwrap_or("."))?;
            return Ok(());
        }
        if self.project.is_some()
            || self.adapter.is_some()
            || self.runner.is_some()
            || self.node_test_options() != vci_adapter::NodeTestOptions::default()
            || self.rails_inputs.is_some()
            || self.ignore_inputs.is_some()
        {
            bail!(
                "top-level `project`/`adapter`/`runner`/`test_script`/`test_globs`/`node_args`/`rails_inputs`/`ignore_inputs` cannot be combined with [[projects]]; give each project its own"
            );
        }
        let mut names = std::collections::BTreeSet::new();
        let mut dirs = std::collections::BTreeSet::new();
        for p in &self.projects {
            if p.name.is_empty()
                || !p
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
            {
                bail!(
                    "project name {:?} must be non-empty and use only letters, digits, '.', '_' and '-'",
                    p.name
                );
            }
            if !names.insert(p.name.clone()) {
                bail!("duplicate project name {:?}", p.name);
            }
            check_rel(&format!("project {:?} path", p.name), &p.path)?;
            check_adapter(&p.adapter)?;
            check_runner(
                &format!("project {:?}", p.name),
                &p.adapter,
                p.runner.as_deref(),
            )?;
            check_node_test(
                &format!("project {:?}", p.name),
                &p.adapter,
                &vci_adapter::NodeTestOptions {
                    test_script: p.test_script.clone(),
                    test_globs: p.test_globs.clone(),
                    node_args: p.node_args.clone(),
                },
            )?;
            check_rails_inputs(
                &format!("project {:?}", p.name),
                &p.adapter,
                p.rails_inputs,
                p.ignore_inputs.as_deref(),
            )?;
            if !dirs.insert((normalise_rel(&p.path), p.adapter.clone())) {
                bail!(
                    "two projects use adapter {:?} in {:?}; they would list the same test files",
                    p.adapter,
                    normalise_rel(&p.path)
                );
            }
        }
        for s in self.project_specs() {
            s.policy
                .check()
                .with_context(|| format!("project {:?}", s.name))?;
        }
        Ok(())
    }

    /// node-test settings of the single-project form.
    fn node_test_options(&self) -> vci_adapter::NodeTestOptions {
        vci_adapter::NodeTestOptions {
            test_script: self.test_script.clone(),
            test_globs: self.test_globs.clone(),
            node_args: self.node_args.clone(),
        }
    }

    /// Keys this file sets that vci no longer uses (they parse, and have no
    /// effect): `policy.rails_allow_db` (top level or in a project's
    /// `[projects.policy]`), removed in vci 1.4.0.
    pub fn removed_keys(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.policy.removed_rails_allow_db.is_some() {
            out.push("policy.rails_allow_db".to_owned());
        }
        for p in &self.projects {
            if p.policy
                .as_ref()
                .is_some_and(|o| o.removed_rails_allow_db.is_some())
            {
                out.push(format!("projects.{}.policy.rails_allow_db", p.name));
            }
        }
        out
    }

    /// The warning for [`Self::removed_keys`] (`None` when there are none),
    /// for the `vci.toml` described by `which`.
    pub fn removed_keys_warning(&self, which: &str) -> Option<String> {
        let keys = self.removed_keys();
        if keys.is_empty() {
            return None;
        }
        Some(format!(
            "{} in {which} is ignored: rails_allow_db was removed in vci 1.4.0 (vci no longer prepares, purges or refuses the Rails test database; Active Record's configured databases are used as they are, and their contents are not an input). Remove it from vci.toml",
            keys.join(", ")
        ))
    }

    /// Normalised project dir of the single-project form ("." for the root).
    pub fn project_rel(&self) -> String {
        normalise_rel(self.project.as_deref().unwrap_or("."))
    }

    /// True for the `[[projects]]` form.
    pub fn is_multi(&self) -> bool {
        !self.projects.is_empty()
    }

    /// `--project NAME`...: keep only the named `[[projects]]` entries (in
    /// file order), so nothing else is listed, probed, verified or run. No
    /// names keeps every project. An unknown name, and any name in the
    /// single-project form (its project has no name), is an error; `which`
    /// says which vci.toml this is (for the message).
    pub fn select_projects(&mut self, names: &[String], which: &str) -> Result<()> {
        if names.is_empty() {
            return Ok(());
        }
        if !self.is_multi() {
            bail!(
                "--project {}: {which} has the single-project form, whose one project has no name; --project selects [[projects]] entries by name (drop --project)",
                names[0]
            );
        }
        let known: Vec<&str> = self.projects.iter().map(|p| p.name.as_str()).collect();
        if let Some(n) = names.iter().find(|n| !known.contains(&n.as_str())) {
            bail!(
                "--project {n}: no such project in {which} (its projects: {})",
                known.join(", ")
            );
        }
        self.projects.retain(|p| names.contains(&p.name));
        Ok(())
    }

    /// Effective configuration of every project, in file order.
    pub fn project_specs(&self) -> Vec<ProjectSpec> {
        if self.projects.is_empty() {
            return vec![ProjectSpec {
                name: String::new(),
                rel: self.project_rel(),
                adapter: self.adapter.clone().unwrap_or_else(default_adapter),
                runner: self.runner.clone(),
                node_test: self.node_test_options(),
                rails_inputs: rails_mode(
                    self.adapter.as_deref().unwrap_or("vitest"),
                    self.rails_inputs,
                ),
                ignore_inputs: self.ignore_inputs.clone().unwrap_or_default(),
                policy: Policy {
                    removed_rails_allow_db: None,
                    ..self.policy.clone()
                },
                env: self.env.clone(),
                inputs: self.inputs.clone(),
            }];
        }
        self.projects
            .iter()
            .map(|p| {
                let mut policy = Policy {
                    removed_rails_allow_db: None,
                    ..self.policy.clone()
                };
                if let Some(o) = &p.policy {
                    if let Some(v) = o.platform {
                        policy.platform = v;
                    }
                    if let Some(v) = o.libraries {
                        policy.libraries = v;
                    }
                    if let Some(v) = &o.platform_overrides {
                        policy.platform_overrides = v.clone();
                    }
                    if let Some(v) = &o.max_ttl {
                        policy.max_ttl = v.clone();
                    }
                    if let Some(v) = o.allow_dirty {
                        policy.allow_dirty = v;
                    }
                    if let Some(v) = &o.no_skip_refs {
                        policy.no_skip_refs = v.clone();
                    }
                    if let Some(v) = &o.no_skip_refs_except {
                        policy.no_skip_refs_except = v.clone();
                    }
                    if let Some(v) = &o.attest_on_any_ref {
                        policy.attest_on_any_ref = v.clone();
                    }
                    if let Some(v) = &o.never_skip {
                        policy.never_skip = v.clone();
                    }
                    if let Some(v) = o.go_allow_net {
                        policy.go_allow_net = v;
                    }
                    if let Some(v) = &o.ignore_taints {
                        policy.ignore_taints = v.clone();
                    }
                    if let Some(v) = o.node_exact {
                        policy.node_exact = v;
                    }
                    if let Some(v) = o.allow_superuser_mismatch {
                        policy.allow_superuser_mismatch = v;
                    }
                    if let Some(v) = o.rails_autoload_lookups {
                        policy.rails_autoload_lookups = v;
                    }
                }
                let mut env = self.env.clone();
                if let Some(o) = &p.env {
                    if let Some(v) = o.mode {
                        env.mode = v;
                    }
                    if let Some(v) = &o.set {
                        env.set = v.clone();
                    }
                    if let Some(v) = &o.hash {
                        env.hash = v.clone();
                    }
                    if let Some(v) = &o.ignore {
                        env.ignore = v.clone();
                    }
                    if let Some(v) = &o.files {
                        env.files = v.clone();
                    }
                }
                ProjectSpec {
                    name: p.name.clone(),
                    rel: normalise_rel(&p.path),
                    adapter: p.adapter.clone(),
                    runner: p.runner.clone(),
                    node_test: vci_adapter::NodeTestOptions {
                        test_script: p.test_script.clone(),
                        test_globs: p.test_globs.clone(),
                        node_args: p.node_args.clone(),
                    },
                    rails_inputs: rails_mode(&p.adapter, p.rails_inputs),
                    ignore_inputs: p.ignore_inputs.clone().unwrap_or_default(),
                    policy,
                    env,
                    inputs: p.inputs.clone().unwrap_or_else(|| self.inputs.clone()),
                }
            })
            .collect()
    }
}

/// A Rails project's effective `rails_inputs` (the default when unset);
/// `None` for the other adapters.
fn rails_mode(adapter: &str, set: Option<RailsInputs>) -> Option<RailsInputs> {
    (adapter == "rails").then(|| set.unwrap_or_default())
}

/// Does a `policy.ignore_taints` pattern match a taint's reason key
/// (`process:system`, `child_process.execSync`, `go:net`,
/// `external-without-version`)? `*` matches any run of characters (`:`
/// included, so `"*"` matches every key); a pattern without `:` also
/// matches every key of that category (`"go"` matches `go:syscall`).
pub fn ignore_pattern_matches(pattern: &str, key: &str) -> bool {
    let pattern = pattern.trim();
    if name_match(pattern, key) {
        return true;
    }
    !pattern.contains(':')
        && key
            .split_once(':')
            .is_some_and(|(category, _)| name_match(pattern, category))
}

/// Template written by `vci init`.
pub const TEMPLATE: &str = r#"# vci configuration. Policy is read from the BASE commit in CI.

# Project directory (where vitest runs), relative to the repo root.
project = "."
adapter = "vitest"

[policy]
# "any" | "same-os" | "exact": which OS/arch may satisfy CI.
platform = "any"
# "exact" | "any": how native libraries and the interpreter's library versions
# are compared (Rails and pytest; this adapter records none, so no effect here).
# libraries = "any"
# Longest accepted attestation lifetime.
max_ttl = "30d"
# Accept attestations made from a working tree with uncommitted changes.
allow_dirty = true
# Refs on which nothing is ever skipped (globs; "*" stays within a segment).
# Pushes to the default branch and tags run everything.
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
# allowed_signers principals whose attestations still skip on those refs, e.g.
# the CI key that attested the previous commit of main (`vci ci --key`).
# no_skip_refs_except = ["github-actions"]
# Test files (globs) that are never skipped.
never_skip = []
# Taints that do not refuse a file (globs over the reason key that `vci run`'s
# "why not attested" lines print; "*" for all). The file is attested with them
# recorded as waived; vci could not record what it did there, so a skip may
# miss a change: this trades determinism for CI time. Read from the base commit.
# ignore_taints = ["child_process.*", "fetch"]

# [[policy.platform_overrides]]
# match = ["src/native/**"]
# platform = "exact"     # and/or libraries = "exact"

[env]
# Only the variables named here and in vci's short built-in lists reach the
# tests; every other one is removed from the test processes (docs/ENV.md;
# `vci env` prints the effective lists).
# Set by vci in every test process, here and in CI (nothing to export): the
# time zone and the locale ICU formats dates and numbers with.
set = { TZ = "UTC", LANG = "C.UTF-8" }
# Taken from the machine and hashed: another value (or its absence) re-runs
# the test. Patterns allowed ("FEATURE_*").
hash = []
# Taken from the machine, never hashed, never a reason to re-run. Put secrets
# and per-machine settings here.
ignore = []
"#;

/// Template written by `vci init --adapter pytest`.
pub const PYTEST_TEMPLATE: &str = r#"# vci configuration. Policy is read from the BASE commit in CI.

# Project directory (where pyproject.toml and uv.lock live), relative to the repo root.
project = "."
adapter = "pytest"

[policy]
# "any" | "same-os" | "exact": which OS/arch may satisfy CI. The Python
# version (major.minor.patch) and implementation must always match.
platform = "any"
# "exact" | "any": "any" stops comparing the versions of the SQLite and OpenSSL
# the interpreter bundles or links ("python libraries"), which differ between
# builds of one Python version (Homebrew, apt, python-build-standalone).
# libraries = "any"
# Longest accepted attestation lifetime.
max_ttl = "30d"
# Accept attestations made from a working tree with uncommitted changes.
allow_dirty = true
# Refs on which nothing is ever skipped (globs; "*" stays within a segment).
# Pushes to the default branch and tags run everything.
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
# allowed_signers principals whose attestations still skip on those refs, e.g.
# the CI key that attested the previous commit of main (`vci ci --key`).
# no_skip_refs_except = ["github-actions"]
# Test files (project-relative globs) that are never skipped, e.g. files whose
# inputs no collector can see (see "pytest limitations" in docs/REFERENCE.md).
never_skip = []
# Taints that do not refuse a file (globs over the reason key that `vci run`'s
# "why not attested" lines print; "*" for all). The file is attested with them
# recorded as waived; vci could not record what it did there, so a skip may
# miss a change: this trades determinism for CI time. Read from the base commit.
# ignore_taints = ["subprocess.Popen", "socket.*"]

[env]
# Only the variables named here and in vci's short built-in lists reach the
# tests; every other one is removed from the test processes (docs/ENV.md;
# `vci env` prints the effective lists).
# Set by vci in every test process, here and in CI (nothing to export).
set = { TZ = "UTC" }
# Taken from the machine and hashed: another value (or its absence) re-runs
# the test. Patterns allowed ("FEATURE_*").
hash = []
# Taken from the machine, never hashed, never a reason to re-run. Put secrets
# and per-machine settings here.
ignore = []
"#;

/// Template written by `vci init --adapter go`.
pub const GO_TEMPLATE: &str = r#"# vci configuration. Policy is read from the BASE commit in CI.

# Project directory (the Go module root, where go.mod lives), relative to the repo root.
project = "."
adapter = "go"

[policy]
# "any" | "same-os" | "exact": which OS/arch may satisfy CI. The Go version
# (go env GOVERSION) and build settings must always match. A package whose
# own code (or a package of this repository it imports) has files for
# specific platforms (_linux.go, //go:build darwin) is only ever skipped on
# the OS and architecture it was attested on.
platform = "any"
# "exact" | "any": how native libraries and the interpreter's library versions
# are compared (Rails and pytest; this adapter records none, so no effect here).
# libraries = "any"
# Longest accepted attestation lifetime.
max_ttl = "30d"
# Accept attestations made from a working tree with uncommitted changes.
allow_dirty = true
# Refs on which nothing is ever skipped (globs; "*" stays within a segment).
# Pushes to the default branch and tags run everything.
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
# allowed_signers principals whose attestations still skip on those refs, e.g.
# the CI key that attested the previous commit of main (`vci ci --key`).
# no_skip_refs_except = ["github-actions"]
# Packages (project-relative directories, globs) that are never skipped.
never_skip = []
# Attest packages whose tests link package net (testify's assert imports
# net/http). vci cannot see network I/O: set this only if the tests use none.
go_allow_net = false
# Taints that do not refuse a file (globs over the reason key that `vci run`'s
# "why not attested" lines print; "*" for all). The file is attested with them
# recorded as waived; vci could not record what it did there, so a skip may
# miss a change: this trades determinism for CI time. Read from the base commit.
# ignore_taints = ["go:syscall", "exec"]   # "go:net" = go_allow_net

[env]
# Only the variables named here and in vci's short built-in lists reach the
# tests; every other one is removed from the test processes (docs/ENV.md;
# `vci env` prints the effective lists).
# Set by vci in every test process, here and in CI (nothing to export). A
# package that uses the local time zone needs TZ. Add CGO_ENABLED = "0" to
# build without cgo everywhere.
set = { TZ = "UTC" }
# Taken from the machine and hashed: another value (or its absence) re-runs
# the test. Patterns allowed ("FEATURE_*").
hash = []
# Taken from the machine, never hashed, never a reason to re-run. Put secrets
# and per-machine settings here.
ignore = []
"#;

/// Template written by `vci init --adapter cargo`.
pub const CARGO_TEMPLATE: &str = r#"# vci configuration. Policy is read from the BASE commit in CI.

# Project directory (the Cargo workspace root, where Cargo.lock lives), relative to the repo root.
project = "."
adapter = "cargo"

[policy]
# "any" | "same-os" | "exact": which OS/arch may satisfy CI. rustc and cargo
# must always match exactly. Under "any", code behind target cfgs
# (cfg(target_os = "linux")) must evaluate the same on both platforms, and a
# unit whose code checks the platform at run time is only skipped on the OS
# and architecture it was attested on.
platform = "any"
# "exact" | "any": how native libraries and the interpreter's library versions
# are compared (Rails and pytest; this adapter records none, so no effect here).
# libraries = "any"
# Longest accepted attestation lifetime.
max_ttl = "30d"
# Accept attestations made from a working tree with uncommitted changes.
allow_dirty = true
# Refs on which nothing is ever skipped (globs; "*" stays within a segment).
# Pushes to the default branch and tags run everything.
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
# allowed_signers principals whose attestations still skip on those refs, e.g.
# the CI key that attested the previous commit of main (`vci ci --key`).
# no_skip_refs_except = ["github-actions"]
# Units (project-relative ids such as "crates/a#test:it", globs) that are never skipped.
never_skip = []
# Taints that do not refuse a file (globs over the reason key that `vci run`'s
# "why not attested" lines print; "*" for all). The file is attested with them
# recorded as waived; vci could not record what it did there, so a skip may
# miss a change: this trades determinism for CI time. Read from the base commit.
# ignore_taints = ["cargo:process", "cargo:net"]

# Files a unit reads outside its package directory must be declared (vci
# hashes every file in the package directories of the crates the unit
# builds, but cannot see reads elsewhere):
# [[inputs]]
# match = ["crates/b#test:*"]
# extra = ["testdata/**"]

[env]
# Only the variables named here and in vci's short built-in lists reach the
# tests; every other one is removed from the test processes (docs/ENV.md;
# `vci env` prints the effective lists).
# Set by vci in every test process, here and in CI (nothing to export).
set = { TZ = "UTC" }
# Taken from the machine and hashed: another value (or its absence) re-runs
# the test. Patterns allowed ("FEATURE_*").
hash = []
# Taken from the machine, never hashed, never a reason to re-run. Put secrets
# and per-machine settings here.
ignore = []
"#;

/// Template written by `vci init --adapter rails`.
pub const RAILS_TEMPLATE: &str = r#"# vci configuration. Policy is read from the BASE commit in CI.

# Project directory (the Rails application root, where Gemfile and bin/rails
# live), relative to the repo root.
project = "."
adapter = "rails"
# The test framework: "minitest" (bin/rails test, test/**/*_test.rb) or
# "rspec" (the files RSpec's own configuration lists, run with
# `--options .rspec`: ~/.rspec, $XDG_CONFIG_HOME/rspec/options and
# .rspec-local are never read). Unset: RSpec when Gemfile.lock has
# rspec-core and there is a spec/ directory but no Minitest file, both when
# both are present, Minitest otherwise.
# runner = "rspec"
# Which of the files Rails reads while it boots are inputs. "loose" (the
# default): config/routes.rb, config/routes/**, config/initializers/**,
# config/environments/**, config/application.rb, config/boot.rb,
# config/environment.rb, config/puma.rb, config/spring.rb, config.ru,
# db/migrate/**, config/locales/** and the autoload lookup records are not:
# a change to one of them runs no test again on a pull request (a run that
# skips nothing, such as the default branch's, runs every test against it).
# "strict": every file a test's process read is an input.
# rails_inputs = "strict"
# More globs (relative to this directory) that are never inputs.
# ignore_inputs = ["config/credentials/**"]

[policy]
# "any" | "same-os" | "exact": which OS/arch may satisfy CI. Ruby (version and
# patchlevel), Rails, Bundler, Minitest/RSpec, the bundle's gem versions, the SQLite
# library and the time zone data must always match. Native gems (nokogiri,
# sqlite3) are matched by version under "any": their macOS and Linux builds
# are accepted as the same gem.
platform = "any"
# "exact" | "any": "any" matches a native library opened through FFI (libvips,
# for Active Storage) by its library name instead of its file name and hash
# (native:libvips.42.dylib on macOS = native:libvips.so.42 on Linux; it must
# still be loaded where CI checks), and stops comparing the SQLite library,
# libyaml and time zone data versions ("ruby libraries"; the encoding and the
# collector version are still compared). For files attested on macOS and
# skipped on Linux, or the other way round.
# libraries = "any"
# Longest accepted attestation lifetime.
max_ttl = "30d"
# Accept attestations made from a working tree with uncommitted changes.
allow_dirty = true
# Refs on which nothing is ever skipped (globs; "*" stays within a segment).
# Pushes to the default branch and tags run everything.
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
# allowed_signers principals whose attestations still skip on those refs, e.g.
# the CI key that attested the previous commit of main (`vci ci --key`).
# no_skip_refs_except = ["github-actions"]
# Test files (project-relative globs) that are never skipped.
never_skip = []
# Taints that do not refuse a file (globs over the reason key that `vci run`'s
# "why not attested" lines print; "*" for all). The file is attested with them
# recorded as waived; vci could not record what it did there, so a skip may
# miss a change: this trades determinism for CI time. Read from the base commit.
# ignore_taints = ["process:*", "native:FFI"]

[env]
# Only the variables named here and in vci's short built-in lists reach the
# tests; every other one is removed from the test processes (docs/ENV.md;
# `vci env` prints the effective lists).
# Set by vci in every test process, here and in CI (nothing to export): Ruby's
# local time zone otherwise comes from the machine. vci sets RAILS_ENV and
# RACK_ENV to "test" itself. RSpec's SPEC_OPTS and Minitest's SEED/TESTOPTS are
# removed unless listed (hash = ["SPEC_OPTS"] passes it on, hashed).
set = { TZ = "UTC" }
# Taken from the machine and hashed: another value (or its absence) re-runs
# the test. Patterns allowed ("FEATURE_*").
hash = []
# Taken from the machine, never hashed, never a reason to re-run. Put secrets
# and per-machine settings here.
ignore = []
"#;

/// Template written by `vci init --adapter node-test`.
pub const NODE_TEST_TEMPLATE: &str = r#"# vci configuration. Policy is read from the BASE commit in CI.

# Project directory (the package whose package.json script runs `node --test`),
# relative to the repo root.
project = "."
adapter = "node-test"
# The package.json script that runs the tests (default "test"). vci reads its
# command (leading NAME=value assignments, then `node [options] --test
# [patterns]`), lists the files with node:test's own globbing, runs each file
# in its own `node --test` process with the same options, and refuses options
# it cannot vouch for (--test-only, --test-name-pattern, --watch, --loader,
# --test-isolation=none, ...). Or give the command here instead of a script:
# test_script = "test"
# test_globs = ["src/**/*.test.ts"]
# node_args = ["--import", "./test/register-hooks.mjs"]

[policy]
# "any" | "same-os" | "exact": which OS/arch may satisfy CI. The Node major
# version must always match; node_exact = true requires the exact version.
platform = "any"
# "exact" | "any": how native libraries and the interpreter's library versions
# are compared (Rails and pytest; this adapter records none, so no effect here).
# libraries = "any"
# Longest accepted attestation lifetime.
max_ttl = "30d"
# Accept attestations made from a working tree with uncommitted changes.
allow_dirty = true
# Refs on which nothing is ever skipped (globs; "*" stays within a segment).
# Pushes to the default branch and tags run everything.
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
# allowed_signers principals whose attestations still skip on those refs, e.g.
# the CI key that attested the previous commit of main (`vci ci --key`).
# no_skip_refs_except = ["github-actions"]
# Test files (project-relative globs) that are never skipped.
never_skip = []
node_exact = false
# Taints that do not refuse a file (globs over the reason key that `vci run`'s
# "why not attested" lines print; "*" for all). The file is attested with them
# recorded as waived; vci could not record what it did there, so a skip may
# miss a change: this trades determinism for CI time. Read from the base commit.
# ignore_taints = ["child_process.*", "fetch"]

[env]
# Only the variables named here and in vci's short built-in lists reach the
# tests; every other one is removed from the test processes (docs/ENV.md;
# `vci env` prints the effective lists).
# Set by vci in every test process, here and in CI (nothing to export): the
# time zone (with TZ unset every file is refused: the machine's zone is not an
# input) and the locale ICU formats dates and numbers with. NODE_ENV and every
# variable the test script assigns (NODE_ENV=test node --test ...) are hashed
# automatically.
set = { TZ = "UTC", LANG = "C.UTF-8" }
# Taken from the machine and hashed: another value (or its absence) re-runs
# the test. Patterns allowed ("FEATURE_*").
hash = []
# Taken from the machine, never hashed, never a reason to re-run. Put secrets
# and per-machine settings here.
ignore = []
"#;

/// The `vci init` template for `adapter`.
pub fn template_for(adapter: &str) -> &'static str {
    match adapter {
        "pytest" => PYTEST_TEMPLATE,
        "go" => GO_TEMPLATE,
        "cargo" => CARGO_TEMPLATE,
        "rails" => RAILS_TEMPLATE,
        "node-test" => NODE_TEST_TEMPLATE,
        _ => TEMPLATE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: the templates wrote `no_skip_refs = []`, so a push to main
    /// (where the example workflow's base ref is the pushed commit itself)
    /// trusted that commit's own allowed_signers.
    #[test]
    fn templates_never_skip_on_main_and_tags() {
        for t in [
            TEMPLATE,
            PYTEST_TEMPLATE,
            GO_TEMPLATE,
            CARGO_TEMPLATE,
            RAILS_TEMPLATE,
            NODE_TEST_TEMPLATE,
        ] {
            let c = Config::parse(t).unwrap();
            // The new env key names, TZ set by vci (nothing to export).
            assert!(c.warnings("vci.toml").is_empty(), "{t}");
            assert_eq!(c.project_specs()[0].env.set["TZ"], "UTC");
            assert!(!t.contains("global =") && !t.contains("pass_through ="));
            let refs = &c.project_specs()[0].policy.no_skip_refs;
            assert!(
                refs.iter().any(|r| glob_match(r, "refs/heads/main")),
                "{refs:?}"
            );
            assert!(
                refs.iter().any(|r| glob_match(r, "refs/tags/v1.0")),
                "{refs:?}"
            );
            assert!(!refs.iter().any(|r| glob_match(r, "refs/heads/feature")));
            // No exception unless the user names one (commented example).
            assert!(c.project_specs()[0].policy.no_skip_refs_except.is_empty());
            assert!(t.contains("# no_skip_refs_except = [\"github-actions\"]"));
        }
    }

    #[test]
    fn no_skip_refs_except_names_principals_and_can_be_overridden() {
        let c = Config::parse(
            "[policy]\nno_skip_refs = [\"refs/heads/main\"]\nno_skip_refs_except = [\"github-actions\"]\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"pytest\"\n\n[[projects]]\nname = \"b\"\npath = \"b\"\nadapter = \"pytest\"\n[projects.policy]\nno_skip_refs_except = []\n",
        )
        .unwrap();
        let s = c.project_specs();
        assert_eq!(s[0].policy.no_skip_refs_except, ["github-actions"]);
        assert!(s[0].policy.skips_on_no_skip_ref("github-actions"));
        assert!(!s[0].policy.skips_on_no_skip_ref("dev@example.com"));
        assert!(s[1].policy.no_skip_refs_except.is_empty());
        assert!(!s[1].policy.skips_on_no_skip_ref("github-actions"));
        assert!(Config::parse("[policy]\nno_skip_refs_except = [\"a b\"]").is_err());
        assert!(Config::parse("[policy]\nno_skip_refs_except = [\"\"]").is_err());
        assert!(Config::parse("[policy]\nno_skip_ref_except = [\"a\"]").is_err());
        assert!(
            Config::parse(
                "[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"pytest\"\n[projects.policy]\nno_skip_refs_except = [\"a b\"]\n"
            )
            .is_err()
        );
    }

    #[test]
    fn never_skip_globs_and_project_override() {
        let c = Config::parse(
            "[policy]\nnever_skip = [\"tests/test_attach*.py\"]\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"pytest\"\n\n[[projects]]\nname = \"b\"\npath = \"b\"\nadapter = \"pytest\"\n[projects.policy]\nnever_skip = []\n",
        )
        .unwrap();
        let s = c.project_specs();
        assert_eq!(
            s[0].policy.never_skip_match("tests/test_attach_db.py"),
            Some("tests/test_attach*.py")
        );
        assert_eq!(s[0].policy.never_skip_match("tests/test_b.py"), None);
        assert_eq!(
            s[1].policy.never_skip_match("tests/test_attach_db.py"),
            None
        );
    }

    #[test]
    fn pytest_template_parses() {
        let c = Config::parse(PYTEST_TEMPLATE).unwrap();
        let s = c.project_specs();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].adapter, "pytest");
        assert_eq!(s[0].rel, ".");
        assert_eq!(s[0].name, "");
    }

    #[test]
    fn ignore_taints_patterns_match_reason_keys() {
        let m = ignore_pattern_matches;
        // Exact keys and globs over the whole key.
        assert!(m("process:system", "process:system"));
        assert!(!m("process:system", "process:spawn"));
        assert!(m("process:*", "process:spawn"));
        assert!(m("process:*", "process:Kernel"));
        assert!(!m("process:*", "network:pg"));
        assert!(m("child_process.*", "child_process.execSync"));
        assert!(!m("child_process.*", "fs.readdir.recursive"));
        assert!(m("*.enumerate", "process.env.enumerate"));
        assert!(m("external-without-version", "external-without-version"));
        assert!(m(" go:net ", "go:net"));
        // "*" matches every key, ':' included.
        for k in [
            "go:syscall",
            "env:enumerated",
            "fetch",
            "native:FFI",
            "exec",
        ] {
            assert!(m("*", k), "{k}");
        }
        // A pattern without ':' also matches the category of a key.
        assert!(m("process", "process:backtick"));
        assert!(m("go", "go:source"));
        assert!(m("nat*", "native:libxml2"));
        assert!(!m("process", "child_process.execSync"));
        assert!(!m("go", "golang"));
        // A pattern with ':' is matched against the whole key only.
        assert!(!m("go:sys", "go:syscall"));
    }

    #[test]
    fn ignore_taints_waivers_and_go_allow_net_equivalence() {
        let c = Config::parse(
            "[policy]\nignore_taints = [\"process:*\", \"external-without-version\", \"go:syscall\"]\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"rails\"\n\n[[projects]]\nname = \"b\"\npath = \"b\"\nadapter = \"go\"\n[projects.policy]\nignore_taints = [\"go:net\"]\n\n[[projects]]\nname = \"c\"\npath = \"c\"\nadapter = \"go\"\n[projects.policy]\ngo_allow_net = true\nignore_taints = []\n",
        )
        .unwrap();
        let s = c.project_specs();
        let a = &s[0].policy;
        assert_eq!(
            a.taint_waiver("rails", "process:system").as_deref(),
            Some("policy.ignore_taints \"process:*\"")
        );
        assert!(
            a.taint_waiver("vitest", "external-without-version:/abs/x.js")
                .is_some()
        );
        assert!(a.taint_waiver("rails", "native:FFI call x").is_none());
        // The per-project key replaces the top-level list.
        let b = &s[1].policy;
        assert_eq!(b.ignore_taints, ["go:net"]);
        assert!(
            b.taint_waiver("go", "go:syscall: x imports syscall")
                .is_none()
        );
        // go_allow_net is ignore_taints = ["go:net"].
        let net = "go:net: the test links package net (...)";
        assert_eq!(
            b.taint_waiver("go", net).as_deref(),
            Some("policy.ignore_taints \"go:net\"")
        );
        let c3 = &s[2].policy;
        assert_eq!(
            c3.taint_waiver("go", net).as_deref(),
            Some("policy.go_allow_net")
        );
        assert!(
            c3.taint_waiver("go", "go:source: a.go uses Environ")
                .is_none()
        );
        // vci's own taints are never waived, even by "*".
        let all = Config::parse("adapter = \"go\"\n[policy]\nignore_taints = [\"*\"]\n").unwrap();
        let all = &all.project_specs()[0].policy;
        assert!(all.taint_waiver("go", net).is_some());
        assert!(all.taint_waiver("node-test", "fetch").is_some());
        for t in ["vci:missing-result", "vci:not-hooked:ffi (x)", "vci"] {
            assert!(all.taint_waiver("rails", t).is_none(), "{t}");
        }
        // An empty pattern is an error.
        assert!(Config::parse("[policy]\nignore_taints = [\"\"]\n").is_err());
        assert!(Config::parse("[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"go\"\n[projects.policy]\nignore_taints = [\" \"]\n").is_err());
    }

    #[test]
    fn go_template_and_go_allow_net_override() {
        let c = Config::parse(GO_TEMPLATE).unwrap();
        let s = c.project_specs();
        assert_eq!(s[0].adapter, "go");
        assert!(!s[0].policy.go_allow_net);
        let c = Config::parse(
            "[policy]\ngo_allow_net = true\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"go\"\n\n[[projects]]\nname = \"b\"\npath = \"b\"\nadapter = \"go\"\n[projects.policy]\ngo_allow_net = false\n",
        )
        .unwrap();
        let s = c.project_specs();
        assert!(s[0].policy.go_allow_net);
        assert!(!s[1].policy.go_allow_net);
        assert!(Config::parse("adapter = \"go\"").is_ok());
    }

    /// `rails_allow_db` (removed in 1.4.0) still parses, top level and per
    /// project, has no effect on the effective policy, and is reported.
    #[test]
    fn rails_template_and_removed_rails_allow_db() {
        let c = Config::parse(RAILS_TEMPLATE).unwrap();
        assert!(!RAILS_TEMPLATE.contains("rails_allow_db"));
        assert!(c.removed_keys().is_empty());
        assert!(c.removed_keys_warning("vci.toml").is_none());
        let s = c.project_specs();
        assert_eq!(s[0].adapter, "rails");
        assert_eq!(s[0].env.set["TZ"], "UTC");
        assert!(s[0].env.hash.is_empty());
        let plain = Config::parse("[policy]\nmax_ttl = \"30d\"\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"rails\"\n\n[[projects]]\nname = \"b\"\npath = \"b\"\nadapter = \"rails\"\n").unwrap();
        let c = Config::parse(
            "[policy]\nrails_allow_db = true\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"rails\"\n\n[[projects]]\nname = \"b\"\npath = \"b\"\nadapter = \"rails\"\n[projects.policy]\nrails_allow_db = false\n",
        )
        .unwrap();
        assert_eq!(
            c.removed_keys(),
            ["policy.rails_allow_db", "projects.b.policy.rails_allow_db"]
        );
        let w = c.removed_keys_warning("vci.toml").unwrap();
        assert!(w.contains("removed in vci 1.4.0"), "{w}");
        let s = c.project_specs();
        let p = plain.project_specs();
        assert_eq!(s[0].policy, p[0].policy, "no effect on the policy");
        assert_eq!(s[1].policy, p[1].policy, "no effect on the policy");
        assert_eq!(
            s[0].adapter_options(),
            vci_adapter::AdapterOptions {
                rails_runner: None,
                node_test: Default::default(),
            }
        );
        let single =
            Config::parse("adapter = \"rails\"\n[policy]\nrails_allow_db = true\n").unwrap();
        assert_eq!(single.removed_keys(), ["policy.rails_allow_db"]);
        assert_eq!(
            single.project_specs()[0].policy,
            Config::parse("adapter = \"rails\"")
                .unwrap()
                .project_specs()[0]
                .policy
        );
    }

    #[test]
    fn allow_superuser_mismatch_defaults_off_and_overrides_per_project() {
        let c = Config::parse("adapter = \"rails\"").unwrap();
        assert!(!c.project_specs()[0].policy.allow_superuser_mismatch);
        let c = Config::parse(
            "[policy]\nallow_superuser_mismatch = true\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"rails\"\n\n[[projects]]\nname = \"b\"\npath = \"b\"\nadapter = \"go\"\n[projects.policy]\nallow_superuser_mismatch = false\n",
        )
        .unwrap();
        let s = c.project_specs();
        assert!(s[0].policy.allow_superuser_mismatch);
        assert!(!s[1].policy.allow_superuser_mismatch);
    }

    /// `runner` (rails only): top level in the single-project form, per
    /// project otherwise; unset means detected.
    #[test]
    fn rails_runner_setting() {
        use vci_adapter::RailsRunner;
        let c = Config::parse(RAILS_TEMPLATE).unwrap();
        assert_eq!(c.project_specs()[0].adapter_options().rails_runner, None);
        let c = Config::parse("adapter = \"rails\"\nrunner = \"rspec\"\n").unwrap();
        let s = &c.project_specs()[0];
        assert_eq!(s.runner.as_deref(), Some("rspec"));
        assert_eq!(s.adapter_options().rails_runner, Some(RailsRunner::Rspec));
        let c = Config::parse(
            "[[projects]]\nname = \"mt\"\npath = \"mt\"\nadapter = \"rails\"\nrunner = \"minitest\"\n\n[[projects]]\nname = \"rs\"\npath = \"rs\"\nadapter = \"rails\"\n",
        )
        .unwrap();
        let s = c.project_specs();
        assert_eq!(
            s[0].adapter_options().rails_runner,
            Some(RailsRunner::Minitest)
        );
        assert_eq!(s[1].adapter_options().rails_runner, None);
        for bad in [
            "adapter = \"rails\"\nrunner = \"cucumber\"\n",
            "adapter = \"pytest\"\nrunner = \"rspec\"\n",
            "runner = \"rspec\"\n",
            "runner = \"rspec\"\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"rails\"\n",
            "[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"go\"\nrunner = \"minitest\"\n",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }

    /// `rails_inputs` (2.7.36): loose by default for Rails projects, none
    /// for the others; `ignore_inputs` adds to the loose list, and is the
    /// whole list in strict mode. Only the rails adapter takes them.
    #[test]
    fn rails_inputs_setting() {
        let loose: Vec<String> = vci_adapter::RAILS_LOOSE_IGNORED_INPUTS
            .iter()
            .map(|g| g.to_string())
            .collect();
        let c = Config::parse(RAILS_TEMPLATE).unwrap();
        let s = &c.project_specs()[0];
        assert_eq!(s.rails_inputs, Some(RailsInputs::Loose));
        assert_eq!(s.ignored_inputs(), loose);
        let c = Config::parse(
            "adapter = \"rails\"\nignore_inputs = [\"config/credentials/**\", \"config/routes.rb\"]\n",
        )
        .unwrap();
        let mut want = loose.clone();
        want.push("config/credentials/**".into());
        assert_eq!(c.project_specs()[0].ignored_inputs(), want);
        let c = Config::parse(
            "adapter = \"rails\"\nrails_inputs = \"strict\"\nignore_inputs = [\"config/credentials/**\"]\n",
        )
        .unwrap();
        assert_eq!(
            c.project_specs()[0].ignored_inputs(),
            vec!["config/credentials/**".to_owned()]
        );
        let c = Config::parse("adapter = \"rails\"\nrails_inputs = \"strict\"\n").unwrap();
        assert!(c.project_specs()[0].ignored_inputs().is_empty());
        let c = Config::parse(
            "[[projects]]\nname = \"api\"\npath = \"api\"\nadapter = \"rails\"\nrails_inputs = \"strict\"\n\n[[projects]]\nname = \"web\"\npath = \"web\"\nadapter = \"vitest\"\n",
        )
        .unwrap();
        let s = c.project_specs();
        assert_eq!(s[0].rails_inputs, Some(RailsInputs::Strict));
        assert_eq!(s[1].rails_inputs, None);
        assert!(s[1].ignored_inputs().is_empty());
        for bad in [
            "adapter = \"rails\"\nrails_inputs = \"lax\"\n",
            "adapter = \"pytest\"\nrails_inputs = \"loose\"\n",
            "adapter = \"vitest\"\nignore_inputs = [\"x\"]\n",
            "adapter = \"rails\"\nignore_inputs = [\"../x\"]\n",
            "adapter = \"rails\"\nignore_inputs = [\"/abs\"]\n",
            "adapter = \"rails\"\nignore_inputs = [\"\"]\n",
            "rails_inputs = \"strict\"\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"rails\"\n",
            "[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"go\"\nignore_inputs = [\"x\"]\n",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }

    /// The loose list and the filter: boot files, migrations and the
    /// autoload lookup records are left out; models, fixtures, the schema,
    /// the lockfile and the test helper are not; a user glob is honoured;
    /// strict mode keeps everything.
    #[test]
    fn ignored_inputs_filter() {
        let loose = ignored_inputs(Some(RailsInputs::Loose), &[]);
        let dropped = |project: &str, path: &str| ignored_input(&loose, project, path);
        for (path, glob) in [
            ("config/routes.rb", "config/routes.rb"),
            ("config/routes/admin.rb", "config/routes/**"),
            ("config/routes", "config/routes/**"),
            ("config/initializers/cors.rb", "config/initializers/**"),
            ("config/initializers", "config/initializers/**"),
            ("config/initializers/deep/x.rb", "config/initializers/**"),
            ("config/environments/test.rb", "config/environments/**"),
            ("config/application.rb", "config/application.rb"),
            ("config/boot.rb", "config/boot.rb"),
            ("config/environment.rb", "config/environment.rb"),
            ("config/puma.rb", "config/puma.rb"),
            ("config.ru", "config.ru"),
            (
                "db/migrate/20260101000000_create_widgets.rb",
                "db/migrate/**",
            ),
            ("db/migrate", "db/migrate/**"),
            ("config/locales/en.yml", "config/locales/**"),
            (".vci-autoload/sprocket", ".vci-autoload"),
            ("app/models/.vci-autoload", ".vci-autoload"),
        ] {
            assert_eq!(dropped(".", path), Some(glob), "{path}");
        }
        for kept in [
            "app/models/widget.rb",
            "app/services/billing/charge.rb",
            "app/views/reports/show.text.erb",
            "test/fixtures/widgets.yml",
            "test/models/widget_test.rb",
            "test/test_helper.rb",
            "test/support/login.rb",
            "db/schema.rb",
            "db/structure.sql",
            "Gemfile.lock",
            "Gemfile",
            "config/database.yml",
            "config",
            "db",
            "config/routes_helper.rb",
            "lib/config/routes.rb",
        ] {
            assert_eq!(dropped(".", kept), None, "{kept}");
        }
        // Relative to the project dir; autoload records wherever they are.
        assert_eq!(
            dropped("api", "api/config/routes.rb"),
            Some("config/routes.rb")
        );
        assert_eq!(dropped("api", "config/routes.rb"), None);
        assert_eq!(dropped("api", "apix/config/routes.rb"), None);
        assert_eq!(dropped("api", "api/app/models/widget.rb"), None);
        assert_eq!(
            dropped("api", ".vci-autoload/sprocket"),
            Some(".vci-autoload")
        );
        // A user glob, in either mode.
        let user = vec![
            "config/credentials/**".to_owned(),
            "lib/tasks/*.rake".to_owned(),
        ];
        for mode in [RailsInputs::Loose, RailsInputs::Strict] {
            let list = ignored_inputs(Some(mode), &user);
            assert_eq!(
                ignored_input(&list, ".", "config/credentials/test.yml.enc"),
                Some("config/credentials/**")
            );
            assert_eq!(
                ignored_input(&list, ".", "lib/tasks/seed.rake"),
                Some("lib/tasks/*.rake")
            );
            assert_eq!(ignored_input(&list, ".", "app/models/widget.rb"), None);
            assert_eq!(
                ignored_input(&list, ".", "config/routes.rb").is_some(),
                mode == RailsInputs::Loose
            );
        }
        // Strict without a list keeps everything.
        let strict = ignored_inputs(Some(RailsInputs::Strict), &[]);
        for p in ["config/routes.rb", ".vci-autoload/x", "db/migrate/1_a.rb"] {
            assert_eq!(ignored_input(&strict, ".", p), None, "{p}");
        }
        // The other adapters leave nothing out.
        assert!(ignored_inputs(None, &user).is_empty());
    }

    /// node-test settings: top level in the single-project form, per
    /// project otherwise; only for the node-test adapter.
    #[test]
    fn node_test_settings() {
        let c = Config::parse(NODE_TEST_TEMPLATE).unwrap();
        let s = &c.project_specs()[0];
        assert_eq!(s.adapter, "node-test");
        assert_eq!(s.node_test, vci_adapter::NodeTestOptions::default());
        assert!(!s.policy.node_exact);
        let c = Config::parse(
            "adapter = \"node-test\"\ntest_globs = [\"src/**/*.test.ts\"]\nnode_args = [\"--import\", \"./h.mjs\"]\n[policy]\nnode_exact = true\n",
        )
        .unwrap();
        let s = &c.project_specs()[0];
        assert_eq!(
            s.adapter_options().node_test.test_globs.as_deref(),
            Some(&["src/**/*.test.ts".to_owned()][..])
        );
        assert!(s.policy.node_exact);
        let c = Config::parse(
            "[[projects]]\nname = \"web\"\npath = \"web\"\nadapter = \"node-test\"\ntest_script = \"test:unit\"\n[projects.policy]\nnode_exact = true\n",
        )
        .unwrap();
        let s = &c.project_specs()[0];
        assert_eq!(s.node_test.test_script.as_deref(), Some("test:unit"));
        assert!(s.policy.node_exact);
        for bad in [
            "adapter = \"vitest\"\ntest_script = \"test\"\n",
            "adapter = \"node-test\"\ntest_script = \"t\"\ntest_globs = [\"a\"]\n",
            "adapter = \"node-test\"\nnode_args = [\"--import\", \"x\"]\n",
            "adapter = \"node-test\"\ntest_globs = []\n",
            "adapter = \"node-test\"\ntest_globs = [\"../x/*.test.js\"]\n",
            "test_script = \"t\"\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"node-test\"\n",
            "[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"pytest\"\ntest_globs = [\"x\"]\n",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn inputs_are_declared_per_test_id_and_validated() {
        let c = Config::parse(
            "adapter = \"cargo\"\n\n[[inputs]]\nmatch = [\"crates/b#test:*\"]\nextra = [\"testdata/**\", \"shared/x.json\"]\n\n[[inputs]]\nmatch = [\"**\"]\nextra = [\"shared/x.json\"]\n",
        )
        .unwrap();
        let s = &c.project_specs()[0];
        assert_eq!(s.adapter, "cargo");
        assert_eq!(
            extra_inputs(&s.inputs, "crates/b#test:it"),
            ["shared/x.json", "testdata/**"]
        );
        assert_eq!(extra_inputs(&s.inputs, "crates/a#lib"), ["shared/x.json"]);
        for bad in [
            "[[inputs]]\nmatch = [\"x\"]\nextra = [\"../up\"]\n",
            "[[inputs]]\nmatch = [\"x\"]\nextra = [\"/abs\"]\n",
            "[[inputs]]\nmatch = []\nextra = [\"a\"]\n",
            "[[inputs]]\nmatch = [\"x\"]\nextra = [\"a\"]\nother = 1\n",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
        let c = Config::parse(
            "[[inputs]]\nmatch = [\"**\"]\nextra = [\"top\"]\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"cargo\"\n\n[[projects]]\nname = \"b\"\npath = \"b\"\nadapter = \"cargo\"\ninputs = [{ match = [\"**\"], extra = [\"own\"] }]\n",
        )
        .unwrap();
        let s = c.project_specs();
        assert_eq!(extra_inputs(&s[0].inputs, "x#lib"), ["top"]);
        assert_eq!(extra_inputs(&s[1].inputs, "x#lib"), ["own"]);
    }

    #[test]
    fn multi_project_form() {
        let c = Config::parse(
            r#"
[policy]
max_ttl = "20d"
no_skip_refs = ["refs/heads/main"]
[env]
hash = ["NODE_ENV"]

[[projects]]
name = "web"
path = "./web/"
adapter = "vitest"

[[projects]]
name = "py"
path = "py"
adapter = "pytest"
[projects.policy]
platform = "exact"
[projects.env]
hash = ["TZ", "APP_*"]
"#,
        )
        .unwrap();
        assert!(c.is_multi());
        let s = c.project_specs();
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].name.as_str(), s[0].rel.as_str()), ("web", "web"));
        assert_eq!(s[0].env.hash, ["NODE_ENV"]);
        assert_eq!(s[0].policy.platform, Platform::Any);
        assert_eq!(s[1].adapter, "pytest");
        assert_eq!(s[1].policy.platform, Platform::Exact);
        // Inherited keys stay.
        assert_eq!(s[1].policy.max_ttl, "20d");
        assert_eq!(s[1].policy.no_skip_refs, ["refs/heads/main"]);
        assert_eq!(s[1].env.hash, ["TZ", "APP_*"]);
    }

    /// `--project`: only the named `[[projects]]` entries are kept, in file
    /// order; an unknown name names the configured ones; the single-project
    /// form has no names.
    #[test]
    fn select_projects_keeps_the_named_ones() {
        let three = r#"[policy]
max_ttl = "20d"

[[projects]]
name = "a"
path = "a"
adapter = "cargo"

[[projects]]
name = "b"
path = "b"
adapter = "pytest"
[projects.policy]
platform = "exact"

[[projects]]
name = "c"
path = "c"
adapter = "node-test"
"#;
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let c = Config::parse(three).unwrap();
        let mut all = c.clone();
        all.select_projects(&[], "vci.toml").unwrap();
        assert_eq!(all, c, "no --project keeps every project");

        let mut b = c.clone();
        b.select_projects(&names(&["b"]), "vci.toml").unwrap();
        assert!(b.is_multi());
        let s = b.project_specs();
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].name.as_str(), s[0].adapter.as_str()), ("b", "pytest"));
        assert_eq!(s[0].policy.platform, Platform::Exact);
        assert_eq!(s[0].policy.max_ttl, "20d");

        // Repeated: file order, duplicates are harmless.
        let mut ca = c.clone();
        ca.select_projects(&names(&["c", "a", "c"]), "vci.toml")
            .unwrap();
        let got: Vec<String> = ca.project_specs().into_iter().map(|s| s.name).collect();
        assert_eq!(got, ["a", "c"]);

        let e = c
            .clone()
            .select_projects(&names(&["b", "web"]), "vci.toml at the base commit")
            .unwrap_err()
            .to_string();
        assert_eq!(
            e,
            "--project web: no such project in vci.toml at the base commit (its projects: a, b, c)"
        );

        let single = Config::parse("project = \".\"\nadapter = \"pytest\"\n").unwrap();
        let e = single
            .clone()
            .select_projects(&names(&["b"]), "vci.toml")
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("--project b: vci.toml has the single-project form"),
            "{e}"
        );
        let mut kept = single.clone();
        kept.select_projects(&[], "vci.toml").unwrap();
        assert_eq!(kept, single);
    }

    #[test]
    fn multi_project_form_is_validated() {
        let two = |a: &str, b: &str| {
            format!(
                "[[projects]]\nname = \"a\"\npath = \"x\"\nadapter = \"vitest\"\n[[projects]]\n{a}\n{b}\n"
            )
        };
        assert!(
            Config::parse(&two("name = \"a\"\npath = \"y\"", "adapter = \"pytest\"")).is_err(),
            "duplicate name"
        );
        assert!(
            Config::parse(&two("name = \"b\"\npath = \"./x\"", "adapter = \"vitest\"")).is_err(),
            "same dir and adapter"
        );
        assert!(
            Config::parse(&two("name = \"b\"\npath = \"x\"", "adapter = \"pytest\"")).is_ok(),
            "same dir, different adapter"
        );
        assert!(
            Config::parse(&two("name = \"b c\"\npath = \"y\"", "adapter = \"pytest\"")).is_err()
        );
        assert!(
            Config::parse(&two(
                "name = \"b\"\npath = \"../y\"",
                "adapter = \"pytest\""
            ))
            .is_err()
        );
        assert!(Config::parse(&two("name = \"b\"\npath = \"y\"", "adapter = \"jest\"")).is_err());
        assert!(
            Config::parse(&format!(
                "adapter = \"vitest\"\n{}",
                two("name = \"b\"\npath = \"y\"", "adapter = \"pytest\"")
            ))
            .is_err(),
            "mixed forms"
        );
        assert!(
            Config::parse(&two(
                "name = \"b\"\npath = \"y\"\nadapter = \"pytest\"\n[projects.policy]",
                "max_ttl = \"soon\""
            ))
            .is_err()
        );
        assert!(
            Config::parse(&two(
                "name = \"b\"\npath = \"y\"\nadapter = \"pytest\"\n[projects.env]",
                "modes = \"strict\""
            ))
            .is_err(),
            "unknown key in an override"
        );
    }

    #[test]
    fn template_parses_to_defaults() {
        let c = Config::parse(TEMPLATE).unwrap();
        assert_eq!(c.project_rel(), ".");
        assert_eq!(c.policy.platform, Platform::Any);
        assert!(c.policy.allow_dirty);
        assert_eq!(c.env.mode, EnvMode::Strict);
        assert_eq!(c.policy.max_ttl_secs().unwrap(), 30 * 86400);
    }

    #[test]
    fn rejects_unknown_keys_and_bad_values() {
        assert!(Config::parse("projcet = \".\"").is_err());
        assert!(Config::parse("project = \"../x\"").is_err());
        assert!(Config::parse("[policy]\nplatform = \"mars\"").is_err());
        assert!(Config::parse("[policy]\nmax_ttl = \"soon\"").is_err());
        assert!(Config::parse("adapter = \"jest\"").is_err());
        assert!(Config::parse("adapter = \"pytest\"").is_ok());
    }

    #[test]
    fn platform_overrides_take_the_strictest() {
        let c = Config::parse(
            "[policy]\nplatform = \"same-os\"\n[[policy.platform_overrides]]\nmatch = [\"src/native/**\"]\nplatform = \"exact\"\n",
        )
        .unwrap();
        assert_eq!(c.policy.platform_for("src/a.test.ts"), Platform::SameOs);
        assert_eq!(
            c.policy.platform_for("src/native/x.test.ts"),
            Platform::Exact
        );
        assert_eq!(
            Config::parse("project = \"./web/\"").unwrap().project_rel(),
            "web"
        );
    }

    /// `policy.libraries`: "exact" by default, "any" or "exact" at the top
    /// level, per project, and in `platform_overrides` entries (which may set
    /// `platform`, `libraries` or both); anything else is a config error.
    #[test]
    fn libraries_policy_parses_defaults_and_overrides() {
        let c = Config::parse("adapter = \"rails\"").unwrap();
        assert_eq!(c.policy.libraries, Libraries::Exact);
        assert_eq!(
            c.project_specs()[0].policy.libraries_for("test/a_test.rb"),
            Libraries::Exact
        );
        let c = Config::parse("adapter = \"rails\"\n[policy]\nlibraries = \"any\"\n").unwrap();
        assert_eq!(c.policy.libraries, Libraries::Any);
        assert_eq!(c.policy.platform, Platform::Any, "platform unchanged");
        let c = Config::parse("[policy]\nlibraries = \"exact\"\n").unwrap();
        assert_eq!(c.policy.libraries, Libraries::Exact);
        for bad in [
            "[policy]\nlibraries = \"loose\"\n",
            "[policy]\nlibraries = \"same-os\"\n",
            "[policy]\nlibraries = true\n",
            "[[policy.platform_overrides]]\nmatch = [\"x\"]\nlibraries = \"none\"\n",
            "[[policy.platform_overrides]]\nmatch = [\"x\"]\n",
            "[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"rails\"\n[projects.policy]\nlibraries = \"Any\"\n",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
        // Per project: replaces the top-level key; inherited otherwise.
        let c = Config::parse(
            "[policy]\nlibraries = \"any\"\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"rails\"\n\n[[projects]]\nname = \"b\"\npath = \"b\"\nadapter = \"pytest\"\n[projects.policy]\nlibraries = \"exact\"\n\n[[projects]]\nname = \"c\"\npath = \"c\"\nadapter = \"pytest\"\n[projects.policy]\nplatform = \"exact\"\n",
        )
        .unwrap();
        let s = c.project_specs();
        assert_eq!(s[0].policy.libraries, Libraries::Any);
        assert_eq!(s[1].policy.libraries, Libraries::Exact);
        assert_eq!(s[2].policy.libraries, Libraries::Any);
        assert_eq!(s[2].policy.platform, Platform::Exact);
        let c = Config::parse(
            "[policy]\nlibraries = \"exact\"\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"rails\"\n[projects.policy]\nlibraries = \"any\"\n",
        )
        .unwrap();
        assert_eq!(c.project_specs()[0].policy.libraries, Libraries::Any);
        // platform_overrides entries: libraries only, platform only, both.
        let c = Config::parse(
            r#"
[policy]
platform = "any"
libraries = "any"

[[policy.platform_overrides]]
match = ["test/images/**"]
libraries = "exact"

[[policy.platform_overrides]]
match = ["test/native/**"]
platform = "exact"

[[policy.platform_overrides]]
match = ["test/both/**"]
platform = "same-os"
libraries = "exact"
"#,
        )
        .unwrap();
        let p = &c.policy;
        assert_eq!(p.platform_overrides[0].platform, None);
        assert_eq!(p.platform_overrides[0].libraries, Some(Libraries::Exact));
        assert_eq!(p.platform_overrides[1].libraries, None);
        assert_eq!(
            (
                p.platform_for("test/a_test.rb"),
                p.libraries_for("test/a_test.rb")
            ),
            (Platform::Any, Libraries::Any)
        );
        assert_eq!(
            (
                p.platform_for("test/images/x_test.rb"),
                p.libraries_for("test/images/x_test.rb")
            ),
            (Platform::Any, Libraries::Exact)
        );
        assert_eq!(
            (
                p.platform_for("test/native/x_test.rb"),
                p.libraries_for("test/native/x_test.rb")
            ),
            (Platform::Exact, Libraries::Any)
        );
        assert_eq!(
            (
                p.platform_for("test/both/x_test.rb"),
                p.libraries_for("test/both/x_test.rb")
            ),
            (Platform::SameOs, Libraries::Exact)
        );
        // Per-project platform_overrides with libraries.
        let c = Config::parse(
            "[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"rails\"\n[projects.policy]\nlibraries = \"any\"\nplatform_overrides = [{ match = [\"test/x/**\"], libraries = \"exact\" }]\n",
        )
        .unwrap();
        let p = &c.project_specs()[0].policy;
        assert_eq!(p.libraries_for("test/y_test.rb"), Libraries::Any);
        assert_eq!(p.libraries_for("test/x/y_test.rb"), Libraries::Exact);
    }

    /// Like `platform_for`: the strictest of the default and every matching
    /// override wins, so an override can only tighten.
    #[test]
    fn libraries_for_takes_the_strictest() {
        let c = Config::parse(
            "[policy]\nlibraries = \"exact\"\n[[policy.platform_overrides]]\nmatch = [\"test/models/**\"]\nlibraries = \"any\"\n",
        )
        .unwrap();
        assert_eq!(
            c.policy.libraries_for("test/models/a_test.rb"),
            Libraries::Exact,
            "an override cannot loosen the default"
        );
        let c = Config::parse(
            "[policy]\nlibraries = \"any\"\n[[policy.platform_overrides]]\nmatch = [\"test/models/**\"]\nlibraries = \"any\"\n[[policy.platform_overrides]]\nmatch = [\"test/models/image*\"]\nlibraries = \"exact\"\n",
        )
        .unwrap();
        assert_eq!(
            c.policy.libraries_for("test/models/a_test.rb"),
            Libraries::Any
        );
        assert_eq!(
            c.policy.libraries_for("test/models/image_test.rb"),
            Libraries::Exact
        );
        assert_eq!(c.policy.libraries_for("test/lib/a_test.rb"), Libraries::Any);
        assert!(Libraries::Any < Libraries::Exact);
    }

    #[test]
    fn every_template_shows_the_libraries_key() {
        for t in [
            TEMPLATE,
            PYTEST_TEMPLATE,
            GO_TEMPLATE,
            CARGO_TEMPLATE,
            RAILS_TEMPLATE,
            NODE_TEST_TEMPLATE,
        ] {
            assert!(t.contains("\n# libraries = \"any\"\n"), "{t}");
            let c = Config::parse(t).unwrap();
            assert_eq!(c.policy.libraries, Libraries::Exact);
            // Uncommented, it parses.
            let on = t.replace("\n# libraries = \"any\"\n", "\nlibraries = \"any\"\n");
            assert_eq!(Config::parse(&on).unwrap().policy.libraries, Libraries::Any);
        }
    }
}
