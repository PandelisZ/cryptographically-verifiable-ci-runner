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

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::util::{glob_match, parse_duration};

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
    pub platform_overrides: Option<Vec<PlatformOverride>>,
    pub max_ttl: Option<String>,
    pub allow_dirty: Option<bool>,
    pub no_skip_refs: Option<Vec<String>>,
    pub never_skip: Option<Vec<String>>,
    pub go_allow_net: Option<bool>,
    pub rails_allow_db: Option<bool>,
}

/// Per-project env keys; each one given replaces the top-level key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EnvOverride {
    pub mode: Option<EnvMode>,
    pub global: Option<Vec<String>>,
    pub pass_through: Option<Vec<String>>,
    pub files: Option<Vec<EnvFiles>>,
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
    pub policy: Policy,
    pub env: EnvConfig,
    pub inputs: Vec<InputsConfig>,
}

impl ProjectSpec {
    /// The adapter options this project's settings give.
    pub fn adapter_options(&self) -> vci_adapter::AdapterOptions {
        vci_adapter::AdapterOptions {
            rails_allow_db: self.policy.rails_allow_db,
            rails_runner: self
                .runner
                .as_deref()
                .and_then(vci_adapter::RailsRunner::parse),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformOverride {
    #[serde(rename = "match")]
    pub match_: Vec<String>,
    pub platform: Platform,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub platform: Platform,
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
    /// Rails: attest test files whose test environment uses a database
    /// server (PostgreSQL, MySQL, ...) rather than a SQLite file. vci cannot
    /// see what the server holds: this is the user's statement that the test
    /// database holds nothing but what vci loads (the schema, purged and
    /// loaded fresh for every file, then the fixtures). Read from the base
    /// commit; attestations that needed it are only accepted while it is set
    /// there, and the server's version is part of the toolchain.
    #[serde(default)]
    pub rails_allow_db: bool,
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
            platform_overrides: vec![],
            max_ttl: default_max_ttl(),
            allow_dirty: true,
            no_skip_refs: vec![],
            never_skip: vec![],
            go_allow_net: false,
            rails_allow_db: false,
        }
    }
}

impl Policy {
    pub fn max_ttl_secs(&self) -> Result<i64> {
        parse_duration(&self.max_ttl).context("policy.max_ttl")
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
            if o.match_.iter().any(|g| glob_match(g, project_rel)) {
                p = p.max(o.platform);
            }
        }
        p
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EnvMode {
    #[default]
    Strict,
    Loose,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EnvConfig {
    #[serde(default)]
    pub mode: EnvMode,
    #[serde(default)]
    pub global: Vec<String>,
    #[serde(default)]
    pub pass_through: Vec<String>,
    #[serde(default)]
    pub files: Vec<EnvFiles>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvFiles {
    #[serde(rename = "match")]
    pub match_: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub pass_through: Vec<String>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let c: Config = toml::from_str(text).context("parsing vci.toml")?;
        c.validate()?;
        Ok(c)
    }

    fn validate(&self) -> Result<()> {
        self.policy.max_ttl_secs()?;
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
            check_rel("project", self.project.as_deref().unwrap_or("."))?;
            return Ok(());
        }
        if self.project.is_some() || self.adapter.is_some() || self.runner.is_some() {
            bail!(
                "top-level `project`/`adapter`/`runner` cannot be combined with [[projects]]; give each project a path and adapter (and runner)"
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
                .max_ttl_secs()
                .with_context(|| format!("project {:?}", s.name))?;
        }
        Ok(())
    }

    /// Normalised project dir of the single-project form ("." for the root).
    pub fn project_rel(&self) -> String {
        normalise_rel(self.project.as_deref().unwrap_or("."))
    }

    /// True for the `[[projects]]` form.
    pub fn is_multi(&self) -> bool {
        !self.projects.is_empty()
    }

    /// Effective configuration of every project, in file order.
    pub fn project_specs(&self) -> Vec<ProjectSpec> {
        if self.projects.is_empty() {
            return vec![ProjectSpec {
                name: String::new(),
                rel: self.project_rel(),
                adapter: self.adapter.clone().unwrap_or_else(default_adapter),
                runner: self.runner.clone(),
                policy: self.policy.clone(),
                env: self.env.clone(),
                inputs: self.inputs.clone(),
            }];
        }
        self.projects
            .iter()
            .map(|p| {
                let mut policy = self.policy.clone();
                if let Some(o) = &p.policy {
                    if let Some(v) = o.platform {
                        policy.platform = v;
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
                    if let Some(v) = &o.never_skip {
                        policy.never_skip = v.clone();
                    }
                    if let Some(v) = o.go_allow_net {
                        policy.go_allow_net = v;
                    }
                    if let Some(v) = o.rails_allow_db {
                        policy.rails_allow_db = v;
                    }
                }
                let mut env = self.env.clone();
                if let Some(o) = &p.env {
                    if let Some(v) = o.mode {
                        env.mode = v;
                    }
                    if let Some(v) = &o.global {
                        env.global = v.clone();
                    }
                    if let Some(v) = &o.pass_through {
                        env.pass_through = v.clone();
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
                    policy,
                    env,
                    inputs: p.inputs.clone().unwrap_or_else(|| self.inputs.clone()),
                }
            })
            .collect()
    }
}

/// Template written by `vci init`.
pub const TEMPLATE: &str = r#"# vci configuration. Policy is read from the BASE commit in CI.

# Project directory (where vitest runs), relative to the repo root.
project = "."
adapter = "vitest"

[policy]
# "any" | "same-os" | "exact": which OS/arch may satisfy CI.
platform = "any"
# Longest accepted attestation lifetime.
max_ttl = "30d"
# Accept attestations made from a working tree with uncommitted changes.
allow_dirty = true
# Refs on which nothing is ever skipped (globs; "*" stays within a segment).
# Pushes to the default branch and tags run everything.
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
# Test files (globs) that are never skipped.
never_skip = []

# [[policy.platform_overrides]]
# match = ["src/native/**"]
# platform = "exact"

[env]
# "strict": only declared and pass-through variables reach tests.
mode = "strict"
# Hashed into every test file's inputs.
global = ["NODE_ENV", "TZ"]
# Visible to tests, never hashed. Put secrets here.
pass_through = []
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
# Longest accepted attestation lifetime.
max_ttl = "30d"
# Accept attestations made from a working tree with uncommitted changes.
allow_dirty = true
# Refs on which nothing is ever skipped (globs; "*" stays within a segment).
# Pushes to the default branch and tags run everything.
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
# Test files (project-relative globs) that are never skipped, e.g. files whose
# inputs no collector can see (see "pytest limitations" in the README).
never_skip = []

[env]
# "strict": only declared and pass-through variables reach tests.
mode = "strict"
# Hashed into every test file's inputs.
global = ["TZ"]
# Visible to tests, never hashed. Put secrets here.
pass_through = []
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
# Longest accepted attestation lifetime.
max_ttl = "30d"
# Accept attestations made from a working tree with uncommitted changes.
allow_dirty = true
# Refs on which nothing is ever skipped (globs; "*" stays within a segment).
# Pushes to the default branch and tags run everything.
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
# Packages (project-relative directories, globs) that are never skipped.
never_skip = []
# Attest packages whose tests link package net (testify's assert imports
# net/http). vci cannot see network I/O: set this only if the tests use none.
go_allow_net = false

[env]
# "strict": only declared and pass-through variables reach tests.
mode = "strict"
# Hashed into every package's inputs.
global = ["TZ"]
# Visible to tests, never hashed. Put secrets here.
pass_through = []
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
# Longest accepted attestation lifetime.
max_ttl = "30d"
# Accept attestations made from a working tree with uncommitted changes.
allow_dirty = true
# Refs on which nothing is ever skipped (globs; "*" stays within a segment).
# Pushes to the default branch and tags run everything.
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
# Units (project-relative ids such as "crates/a#test:it", globs) that are never skipped.
never_skip = []

# Files a unit reads outside its package directory must be declared (vci
# hashes every file in the package directories of the crates the unit
# builds, but cannot see reads elsewhere):
# [[inputs]]
# match = ["crates/b#test:*"]
# extra = ["testdata/**"]

[env]
# "strict" (required by the cargo adapter): only declared and pass-through
# variables reach tests.
mode = "strict"
# Hashed into every unit's inputs.
global = ["TZ"]
# Visible to tests, never hashed. Put secrets here.
pass_through = []
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

[policy]
# "any" | "same-os" | "exact": which OS/arch may satisfy CI. Ruby (version and
# patchlevel), Rails, Bundler, Minitest/RSpec, the bundle's gem versions, the SQLite
# library and the time zone data must always match. Native gems (nokogiri,
# sqlite3) are matched by version under "any": their macOS and Linux builds
# are accepted as the same gem.
platform = "any"
# Longest accepted attestation lifetime.
max_ttl = "30d"
# Accept attestations made from a working tree with uncommitted changes.
allow_dirty = true
# Refs on which nothing is ever skipped (globs; "*" stays within a segment).
# Pushes to the default branch and tags run everything.
no_skip_refs = ["refs/heads/main", "refs/tags/**"]
# Test files (project-relative globs) that are never skipped.
never_skip = []
# Attest files whose test database is a server (PostgreSQL, MySQL) instead of
# a SQLite file. vci purges it and loads the schema before every file, but
# cannot see what else the server holds or does: set this only if the test
# database is used by nothing but these tests.
rails_allow_db = false

[env]
# "strict": only declared and pass-through variables reach tests.
mode = "strict"
# Hashed into every test file's inputs. Declare TZ and set it (TZ=UTC) on
# both sides: Ruby's local time zone otherwise comes from the machine.
# RSpec reads SPEC_OPTS: strict mode removes it unless you add "SPEC_OPTS"
# here (it is then hashed).
global = ["TZ"]
# Visible to tests, never hashed. Put secrets here.
pass_through = []
"#;

/// The `vci init` template for `adapter`.
pub fn template_for(adapter: &str) -> &'static str {
    match adapter {
        "pytest" => PYTEST_TEMPLATE,
        "go" => GO_TEMPLATE,
        "cargo" => CARGO_TEMPLATE,
        "rails" => RAILS_TEMPLATE,
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
        ] {
            let c = Config::parse(t).unwrap();
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
        }
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

    #[test]
    fn rails_template_and_rails_allow_db_override() {
        let c = Config::parse(RAILS_TEMPLATE).unwrap();
        let s = c.project_specs();
        assert_eq!(s[0].adapter, "rails");
        assert!(!s[0].policy.rails_allow_db);
        assert_eq!(s[0].env.global, ["TZ"]);
        let c = Config::parse(
            "[policy]\nrails_allow_db = true\n\n[[projects]]\nname = \"a\"\npath = \"a\"\nadapter = \"rails\"\n\n[[projects]]\nname = \"b\"\npath = \"b\"\nadapter = \"rails\"\n[projects.policy]\nrails_allow_db = false\n",
        )
        .unwrap();
        let s = c.project_specs();
        assert!(s[0].policy.rails_allow_db);
        assert!(!s[1].policy.rails_allow_db);
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
global = ["NODE_ENV"]

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
global = ["TZ", "APP_*"]
"#,
        )
        .unwrap();
        assert!(c.is_multi());
        let s = c.project_specs();
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].name.as_str(), s[0].rel.as_str()), ("web", "web"));
        assert_eq!(s[0].env.global, ["NODE_ENV"]);
        assert_eq!(s[0].policy.platform, Platform::Any);
        assert_eq!(s[1].adapter, "pytest");
        assert_eq!(s[1].policy.platform, Platform::Exact);
        // Inherited keys stay.
        assert_eq!(s[1].policy.max_ttl, "20d");
        assert_eq!(s[1].policy.no_skip_refs, ["refs/heads/main"]);
        assert_eq!(s[1].env.global, ["TZ", "APP_*"]);
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
}
