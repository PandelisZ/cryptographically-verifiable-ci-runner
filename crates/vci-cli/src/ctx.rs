//! Shared context: repository, config, adapter, and the predicate wrapper.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use vci_adapter::{Adapter, VitestAdapter};
use vci_core::{Predicate, RepoPath};
use vci_git::Repo;

use crate::config::{CONFIG_FILE, Config};

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
}

/// Storage key for an attestation: everything that must match for two
/// attestations to be interchangeable. Re-running with identical inputs
/// replaces (renews) the stored envelope.
pub fn storage_key(p: &VciPredicate) -> String {
    let tc = &p.core.toolchain;
    let parts = [
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
        &p.core.argv.join("\0"),
    ];
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
    /// Listed under more than one runner project: never attestable.
    pub ambiguous: bool,
}

pub struct Ctx {
    pub repo: Repo,
    pub root: Utf8PathBuf,
    pub config: Config,
    pub project_rel: String,
    pub project_dir: Utf8PathBuf,
    pub adapter: VitestAdapter,
}

impl Ctx {
    pub fn new(repo: Repo, root: Utf8PathBuf, config: Config) -> Result<Self> {
        let project_rel = config.project_rel();
        let project_dir = if project_rel == "." {
            root.clone()
        } else {
            root.join(&project_rel)
        };
        if !project_dir.is_dir() {
            bail!("project dir {project_dir} does not exist");
        }
        let project_dir = project_dir.canonicalize_utf8()?;
        if !project_dir.starts_with(&root) {
            bail!("project dir {project_dir} is outside the repository {root}");
        }
        let adapter = VitestAdapter::new(&project_dir);
        Ok(Self {
            repo,
            root,
            config,
            project_rel,
            project_dir,
            adapter,
        })
    }

    pub fn test_id(&self, project_rel: &str) -> Result<RepoPath> {
        let joined = if self.project_rel == "." {
            project_rel.to_owned()
        } else {
            format!("{}/{project_rel}", self.project_rel)
        };
        Ok(RepoPath::new(&joined)?)
    }

    /// Turn the runner's listing into test files keyed by test id.
    pub fn test_files(&self, listed: Vec<vci_adapter::ListedFile>) -> Result<Vec<TestFile>> {
        let mut by_id: BTreeMap<String, TestFile> = BTreeMap::new();
        for f in listed {
            let rel = f
                .abs
                .strip_prefix(self.adapter.project_dir())
                .with_context(|| format!("listed test {} is outside the project dir", f.abs))?
                .as_str()
                .to_owned();
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
                        },
                    );
                }
            }
        }
        Ok(by_id.into_values().collect())
    }
}
