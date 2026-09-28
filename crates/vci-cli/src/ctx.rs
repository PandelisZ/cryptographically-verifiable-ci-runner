//! Shared context: repository, config, projects (each with its adapter), and
//! the predicate wrapper.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use vci_adapter::Adapter;
use vci_core::{Predicate, RepoPath};
use vci_git::Repo;

use crate::config::{CONFIG_FILE, Config, EnvConfig, InputsConfig, Policy};
use crate::envpolicy::{ChildEnvMap, FileEnv, build_child_env_with};

/// The signed predicate: the `vci-core` [`Predicate`] plus vci-cli fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VciPredicate {
    #[serde(flatten)]
    pub core: Predicate,
    /// BLAKE3 over the effective env configuration for this test file.
    pub env_config_digest: String,
    /// Project dir relative to the repo root.
    pub project_dir: String,
    /// Runner project name (Vitest `projects`), empty if none.
    pub runner_project: String,
    /// `[[projects]]` name in vci.toml; empty (and omitted) in the
    /// single-project form, so those predicates serialise as before.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub project_name: String,
    /// Go: repository files of the test whose inclusion in the build depends
    /// on GOOS/GOARCH. When non-empty the attestation only holds on the
    /// attested OS and architecture, whatever `policy.platform` says.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platform_specific: Vec<String>,
    /// Go: why the test's results may differ on another architecture
    /// (floating-point code: the compiler fuses `x*y + z` on arm64 but not
    /// on amd64). When non-empty the attestation only holds on the attested
    /// architecture, whatever `policy.platform` says (the OS may differ).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arch_specific: Vec<String>,
    /// Refusal reasons a policy waived when this attestation was made
    /// (`go:net:` with `policy.go_allow_net`). `vci plan` accepts the
    /// attestation only while the base commit's policy still waives them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waived: Vec<String>,
    /// Cargo: target-dependent `cfg(...)` predicates in the unit's repository
    /// code and manifests. On another host each must evaluate as it did on
    /// the attesting host (`toolchain.rustCfg`), or the unit runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cfg_predicates: Vec<String>,
    /// The `[[inputs]] extra` globs declared for this test id when it was
    /// attested (they must still be exactly what the base config declares).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_inputs: Vec<String>,
}

/// Storage key for an attestation: everything that must match for two
/// attestations to be interchangeable. Re-running with identical inputs
/// replaces (renews) the stored envelope.
pub fn storage_key(p: &VciPredicate) -> String {
    let tc = &p.core.toolchain;
    let mut parts = vec![
        "vci/storage-key/v1",
        p.core.repo_id.as_str(),
        p.core.test_id.as_str(),
        p.core.input_root.as_str(),
        p.core.global_input_root.as_str(),
        p.env_config_digest.as_str(),
        tc.node.as_str(),
        tc.vitest.as_str(),
        tc.vite.as_str(),
        tc.os.as_str(),
        tc.arch.as_str(),
    ];
    let argv = p.core.argv.join("\0");
    parts.push(&argv);
    // Fields added after v1 only join the key when set, so Vitest keys in the
    // single-project form are unchanged.
    let dists = if tc.python_dists.is_empty() {
        String::new()
    } else {
        vci_core::blake3_hex(tc.python_dists.join("\n").as_bytes())
    };
    let go_env = if tc.go_env.is_empty() {
        String::new()
    } else {
        vci_core::blake3_hex(tc.go_env.join("\n").as_bytes())
    };
    let platform_specific = p.platform_specific.join("\0");
    let arch_specific = p.arch_specific.join("\0");
    let waived = p.waived.join("\0");
    let rust_cfg = if tc.rust_cfg.is_empty() {
        String::new()
    } else {
        vci_core::blake3_hex(tc.rust_cfg.join("\n").as_bytes())
    };
    let cfg_predicates = p.cfg_predicates.join("\0");
    let declared_inputs = p.declared_inputs.join("\0");
    let extra = [
        ("python", tc.python.as_str()),
        ("implementation", tc.implementation.as_str()),
        ("pytest", tc.pytest.as_str()),
        ("python_libs", tc.python_libs.as_str()),
        ("python_dists", &dists),
        ("go", tc.go.as_str()),
        ("go_env", &go_env),
        ("go_arch_level", tc.go_arch_level.as_str()),
        ("platform_specific", &platform_specific),
        ("arch_specific", &arch_specific),
        ("waived", &waived),
        ("rust", tc.rust.as_str()),
        ("cargo", tc.cargo.as_str()),
        ("rust_host", tc.rust_host.as_str()),
        ("rust_cfg", &rust_cfg),
        ("cfg_predicates", &cfg_predicates),
        ("declared_inputs", &declared_inputs),
        ("project", p.project_name.as_str()),
        ("superuser", if tc.superuser { "1" } else { "" }),
        (
            "adapter",
            if p.core.adapter == "vitest" {
                ""
            } else {
                p.core.adapter.as_str()
            },
        ),
    ];
    let extra: Vec<String> = extra
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    for e in &extra {
        parts.push(e);
    }
    vci_core::blake3_hex(parts.join("\n").as_bytes())
}

pub fn cwd() -> Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(std::env::current_dir()?)
        .map_err(|p| anyhow::anyhow!("current directory is not UTF-8: {p:?}"))
}

/// Discover the repository containing the current directory.
pub fn open_repo() -> Result<(Repo, Utf8PathBuf)> {
    let repo = Repo::discover(&cwd()?).context("finding the git repository")?;
    let root = repo
        .root()
        .canonicalize_utf8()
        .with_context(|| format!("canonicalising {}", repo.root()))?;
    Ok((repo, root))
}

/// Read `vci.toml` from the working tree (defaults if missing).
pub fn working_tree_config(root: &Utf8Path) -> Result<Config> {
    let p = root.join(CONFIG_FILE);
    if !p.exists() {
        eprintln!("vci: no {CONFIG_FILE} in {root}; using defaults");
        return Ok(Config::default());
    }
    Config::parse(&std::fs::read_to_string(&p)?).with_context(|| format!("in {p}"))
}

/// A listed test file.
#[derive(Debug, Clone)]
pub struct TestFile {
    /// Repo-relative path: the attestation test id.
    pub test_id: RepoPath,
    /// Relative to the project dir (what the runner is given).
    pub project_rel: String,
    pub abs: Utf8PathBuf,
    pub runner_project: String,
    /// Listed under more than one runner project, or by more than one vci
    /// project: never attestable, never skipped.
    pub ambiguous: bool,
    /// Index into [`Ctx::projects`].
    pub project: usize,
}

/// One project of `vci.toml` with its adapter.
pub struct Project {
    /// `[[projects]]` name; empty in the single-project form.
    pub name: String,
    /// Project dir relative to the repo root ("." for the root).
    pub rel: String,
    /// Canonical absolute project dir.
    pub dir: Utf8PathBuf,
    pub policy: Policy,
    pub env: EnvConfig,
    /// `[[inputs]]` declarations of this project.
    pub inputs: Vec<InputsConfig>,
    pub adapter: Box<dyn Adapter>,
}

impl Project {
    /// Name for messages: the project name, else its directory.
    pub fn label(&self) -> String {
        if self.name.is_empty() {
            self.rel.clone()
        } else {
            self.name.clone()
        }
    }

    /// Repo-relative test id of a project-relative path (`.` names the
    /// project dir itself: a Go module's root package). A Cargo unit
    /// `<package dir>#<target>` keeps its `#<target>` suffix on the
    /// repo-relative package dir (`crates/a#lib`, `.#lib` for a package at
    /// the repository root).
    pub fn test_id(&self, project_rel: &str) -> Result<RepoPath> {
        if self.adapter.name() == "cargo"
            && let Some((dir, target)) = project_rel.rsplit_once('#')
        {
            let dir = self.test_id(if dir.is_empty() { "." } else { dir })?;
            return Ok(RepoPath::new(&format!("{}#{target}", dir.as_str()))?);
        }
        let joined = if project_rel == "." || project_rel.is_empty() {
            self.rel.clone()
        } else if self.rel == "." {
            project_rel.to_owned()
        } else {
            format!("{}/{project_rel}", self.rel)
        };
        Ok(RepoPath::new(&joined)?)
    }

    /// Effective env configuration for a test file of this project.
    pub fn file_env(&self, project_rel: &str) -> FileEnv {
        let inferred: Vec<&str> = self
            .adapter
            .inferred_env_patterns()
            .iter()
            .chain(self.adapter.hashed_env_patterns())
            .copied()
            .collect();
        FileEnv::for_file(&self.env, &inferred, project_rel)
            .with_builtin(self.adapter.builtin_pass_through())
            .with_adapter(self.adapter.name())
    }

    /// `[[inputs]] extra` globs declared for a project-relative test id.
    pub fn extra_inputs(&self, project_rel: &str) -> Vec<String> {
        crate::config::extra_inputs(&self.inputs, project_rel)
    }

    /// The environment this project's test processes get.
    pub fn child_env(&self) -> ChildEnvMap {
        build_child_env_with(
            &self.env,
            self.adapter.inferred_env_patterns(),
            self.adapter.builtin_pass_through(),
            std::env::vars_os(),
        )
    }

    /// Turn the runner's listing into test files of this project (project
    /// index `idx`), one per test id; a file listed under several runner
    /// projects is marked ambiguous.
    pub fn test_files(
        &self,
        idx: usize,
        listed: Vec<vci_adapter::ListedFile>,
    ) -> Result<Vec<TestFile>> {
        let mut by_id: BTreeMap<String, TestFile> = BTreeMap::new();
        for f in listed {
            // A Cargo unit is `<package dir>#<target>`; the package dir may be
            // the project dir itself.
            let rel = match f.abs.strip_prefix(self.adapter.project_dir()) {
                Ok(r) => r.as_str().to_owned(),
                Err(_) => f
                    .abs
                    .as_str()
                    .strip_prefix(self.adapter.project_dir().as_str())
                    .filter(|r| r.starts_with('#'))
                    .map(|r| format!(".{r}"))
                    .with_context(|| format!("listed test {} is outside the project dir", f.abs))?,
            };
            // A Go module's root package is the project dir itself.
            let rel = if rel.is_empty() { ".".to_owned() } else { rel };
            let test_id = self.test_id(&rel)?;
            let key = test_id.as_str().to_owned();
            match by_id.get_mut(&key) {
                Some(existing) => existing.ambiguous = true,
                None => {
                    by_id.insert(
                        key,
                        TestFile {
                            test_id,
                            project_rel: rel,
                            abs: f.abs,
                            runner_project: f.project,
                            ambiguous: false,
                            project: idx,
                        },
                    );
                }
            }
        }
        Ok(by_id.into_values().collect())
    }
}

/// Mark every test id listed by more than one project as ambiguous (in all
/// of them), so test ids stay unambiguous across projects.
pub fn mark_cross_project_ambiguity(files: &mut [TestFile]) {
    let mut seen: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for f in files.iter() {
        seen.entry(f.test_id.as_str().to_owned())
            .or_default()
            .insert(f.project);
    }
    for f in files.iter_mut() {
        if seen.get(f.test_id.as_str()).is_some_and(|s| s.len() > 1) {
            f.ambiguous = true;
        }
    }
}

pub struct Ctx {
    pub repo: Repo,
    pub root: Utf8PathBuf,
    pub projects: Vec<Project>,
}

impl Ctx {
    pub fn new(repo: Repo, root: Utf8PathBuf, config: Config) -> Result<Self> {
        let mut projects = Vec::new();
        for spec in config.project_specs() {
            let dir = if spec.rel == "." {
                root.clone()
            } else {
                root.join(&spec.rel)
            };
            let what = if spec.name.is_empty() {
                "project dir".to_owned()
            } else {
                format!("project {:?} dir", spec.name)
            };
            if !dir.is_dir() {
                bail!("{what} {dir} does not exist");
            }
            let dir = dir.canonicalize_utf8()?;
            if !dir.starts_with(&root) {
                bail!("{what} {dir} is outside the repository {root}");
            }
            let adapter = vci_adapter::adapter_for(&spec.adapter, &dir)?;
            projects.push(Project {
                name: spec.name,
                rel: spec.rel,
                dir,
                policy: spec.policy,
                env: spec.env,
                inputs: spec.inputs,
                adapter,
            });
        }
        Ok(Self {
            repo,
            root,
            projects,
        })
    }
}
