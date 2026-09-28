//! `vci.toml`: project location, skip policy and env configuration.
//!
//! Unknown keys are errors: in `vci plan` a config that cannot be parsed
//! means every test runs.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::util::{glob_match, parse_duration};

pub const CONFIG_FILE: &str = "vci.toml";
pub const ALLOWED_SIGNERS_FILE: &str = ".vci/allowed_signers";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Project directory relative to the repo root.
    #[serde(default = "default_project")]
    pub project: String,
    #[serde(default = "default_adapter")]
    pub adapter: String,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub env: EnvConfig,
}

fn default_project() -> String {
    ".".into()
}
fn default_adapter() -> String {
    "vitest".into()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            project: default_project(),
            adapter: default_adapter(),
            policy: Policy::default(),
            env: EnvConfig::default(),
        }
    }
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
        }
    }
}

impl Policy {
    pub fn max_ttl_secs(&self) -> Result<i64> {
        parse_duration(&self.max_ttl).context("policy.max_ttl")
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
        if self.adapter != "vitest" {
            bail!("unsupported adapter {:?} (only \"vitest\")", self.adapter);
        }
        let p = &self.project;
        if p.is_empty() || p.starts_with('/') || p.contains('\\') || p.split('/').any(|c| c == "..")
        {
            bail!("project must be a relative path inside the repo, got {p:?}");
        }
        self.policy.max_ttl_secs()?;
        Ok(())
    }

    /// Normalised project dir relative to the repo root ("." for the root).
    pub fn project_rel(&self) -> String {
        let parts: Vec<&str> = self
            .project
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .collect();
        if parts.is_empty() {
            ".".into()
        } else {
            parts.join("/")
        }
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
no_skip_refs = []

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

#[cfg(test)]
mod tests {
    use super::*;

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
