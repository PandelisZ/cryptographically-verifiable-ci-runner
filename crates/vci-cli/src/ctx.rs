//! Shared context: repository, config, projects (each with its adapter), the
//! predicate and its storage key.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use vci_adapter::Adapter;
use vci_core::{RepoPath, ResolvedPredicate};
use vci_git::Repo;

use crate::config::{CONFIG_FILE, Config, EnvConfig, InputsConfig, Policy};
use crate::envpolicy::{ChildEnvMap, FileEnv, build_child_env};

/// The signed v1 predicate: `vci_core::VciPredicate`, the one definition
/// (vci-cli's own copy, which serialised identically, is gone since the
/// plan reads records of both versions through [`ResolvedPredicate`]).
pub use vci_core::VciPredicate;

/// Storage key for an attestation: everything that must match for two
/// attestations to be interchangeable. Re-running with identical inputs
/// replaces (renews) the stored envelope.
///
/// Computed over the resolved view of either predicate version (STORE-V2
/// section 1.6 rule 7): every value comes from the decoded fields, never
/// from bytes, so a writer's serialisation choices cannot move a slot, and
/// a v1 and a v2 record of the same facts key the same slot. The waived
/// list enters sorted and distinct ([`ResolvedPredicate::waived_canonical`]),
/// the only form a v2 statement can carry; a v1 record whose list repeated
/// a string or was unsorted (most of the Rails sample: 1,163 of 1,175
/// units) therefore keys another slot than vci 2.8 gave it, and its 2.8
/// record stays beside the new one as a second candidate until supersession
/// or expiry removes it (section 5.1; fail-open, one more candidate per
/// such test). Every other part of the key is spelled as 2.8 spelled it.
pub fn storage_key(p: &ResolvedPredicate<'_>) -> String {
    let tc = p.toolchain();
    let global_input_root = p.global_input_root();
    let env_config_digest = p.env_config_digest();
    let mut parts = vec![
        "vci/storage-key/v1",
        p.repo_id(),
        p.test_id(),
        p.input_root(),
        &global_input_root,
        &env_config_digest,
        tc.node.as_str(),
        tc.vitest.as_str(),
        tc.vite.as_str(),
        tc.os.as_str(),
        tc.arch.as_str(),
    ];
    let argv = p.argv().join("\0");
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
    let platform_specific = p.platform_specific().join("\0");
    let arch_specific = p.arch_specific().join("\0");
    let waived = p.waived_canonical().join("\0");
    let rust_cfg = if tc.rust_cfg.is_empty() {
        String::new()
    } else {
        vci_core::blake3_hex(tc.rust_cfg.join("\n").as_bytes())
    };
    let cfg_predicates = p.cfg_predicates().join("\0");
    let ruby_gems = if tc.ruby_gems.is_empty() {
        String::new()
    } else {
        vci_core::blake3_hex(tc.ruby_gems.join("\n").as_bytes())
    };
    let declared_inputs = p.declared_inputs().join("\0");
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
        ("ruby", tc.ruby.as_str()),
        ("ruby_engine", tc.ruby_engine.as_str()),
        ("rails", tc.rails.as_str()),
        ("bundler", tc.bundler.as_str()),
        ("ruby_test", tc.ruby_test.as_str()),
        ("ruby_libs", tc.ruby_libs.as_str()),
        ("ruby_db", tc.ruby_db.as_str()),
        ("ruby_gems", &ruby_gems),
        ("project", p.project_name()),
        ("superuser", if tc.superuser { "1" } else { "" }),
        (
            "adapter",
            if p.adapter() == "vitest" {
                ""
            } else {
                p.adapter()
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
    /// The settings the adapter was made with (`vci ci` makes it again).
    pub adapter_options: vci_adapter::AdapterOptions,
    /// [`Project::config_hash`], computed once.
    pub config_hash: String,
    /// Rails: the `rails_inputs` setting (`None` for the other adapters).
    pub rails_inputs: Option<crate::config::RailsInputs>,
    /// The globs (relative to the project dir) whose paths are left out of
    /// this project's manifests ([`crate::config::ignored_inputs`]).
    pub ignored_inputs: Vec<String>,
    /// Whether `vci run` said which inputs it leaves out (once per project).
    pub ignored_noted: std::sync::atomic::AtomicBool,
}

/// The external a unit's attestation records its project's configuration
/// under (2.7.0), version [`Project::config_hash`].
pub const CONFIG_EXTERNAL: &str = "vci:config";

impl Project {
    /// What of `vci.toml` a test of this project runs under: its directory,
    /// adapter and adapter settings, environment and declared inputs. Not
    /// the policy (who may skip what, read from the base commit at plan
    /// time), not comments or formatting, not other projects. Before 2.7.0
    /// the whole file was an input of every test, so any edit to it ran
    /// every test of every project again.
    ///
    /// Rails' `rails_inputs` and `ignore_inputs` (2.7.36) join it when they
    /// are not the default (`"strict"`, or any `ignore_inputs`): a unit
    /// recorded in another mode, or with another list, is not accepted. The
    /// default leaves the hash as 2.7.33 computed it, so an attestation
    /// made before 2.7.36 (whose manifests keep every input, a superset of
    /// what loose mode records) stays usable until it is attested again.
    pub fn config_hash_of(
        rel: &str,
        adapter: &str,
        options: &vci_adapter::AdapterOptions,
        env: &EnvConfig,
        inputs: &[InputsConfig],
        rails_inputs: Option<crate::config::RailsInputs>,
        ignore_inputs: &[String],
    ) -> String {
        let mut text = format!(
            "vci-config-v1\n{rel}\n{adapter}\n{options:?}\n{}\n{}",
            serde_json::to_string(env).unwrap_or_default(),
            serde_json::to_string(inputs).unwrap_or_default()
        );
        if let Some(mode) = rails_inputs
            && (mode != crate::config::RailsInputs::Loose || !ignore_inputs.is_empty())
        {
            text.push_str(&format!(
                "\nrails_inputs={}\nignore_inputs={}",
                mode.as_str(),
                serde_json::to_string(ignore_inputs).unwrap_or_default()
            ));
        }
        vci_core::blake3_hex(text.as_bytes())
    }
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

    /// The `[env]` configuration plus the variables the adapter declares
    /// itself (node-test: `NODE_ENV` and the test script's assignments), as
    /// `hash` patterns.
    pub fn effective_env(&self) -> EnvConfig {
        let mut env = self.env.clone();
        for k in self.adapter.declared_env() {
            if !env.hash.contains(&k) {
                env.hash.push(k);
            }
        }
        env
    }

    /// Add this project's built-in lists and adapter to a policy.
    fn with_builtins(&self, f: FileEnv) -> FileEnv {
        f.with_builtins(self.adapter.builtin_hash(), self.adapter.builtin_ignore())
            .with_loose_hash(self.adapter.loose_hash())
            .with_adapter(self.adapter.name())
    }

    /// Effective env configuration for a test file of this project.
    pub fn file_env(&self, project_rel: &str) -> FileEnv {
        self.with_builtins(FileEnv::for_file(&self.effective_env(), project_rel))
    }

    /// Effective env configuration for any file of this project (every
    /// `[[env.files]]` entry applies): what decides the child environment.
    pub fn project_env(&self) -> FileEnv {
        self.with_builtins(FileEnv::for_project(&self.effective_env()))
    }

    /// The item of [`Project::ignored_inputs`] that leaves the repository
    /// path `path` out of this project's manifests, if any.
    pub fn ignored_input(&self, path: &str) -> Option<&str> {
        crate::config::ignored_input(&self.ignored_inputs, &self.rel, path)
    }

    /// Whether the collector should record autoload lookups instead of
    /// directory listings: `policy.rails_autoload_lookups`, or the lookup
    /// records are left out anyway (`rails_inputs = "loose"`, or
    /// `.vci-autoload` in `ignore_inputs`), when the listings would be the
    /// only trace of the autoload directories left.
    pub fn autoload_lookups(&self) -> bool {
        self.policy.rails_autoload_lookups
            || self
                .ignored_inputs
                .iter()
                .any(|g| g == vci_adapter::AUTOLOAD_INPUTS)
    }

    /// `[[inputs]] extra` globs declared for a project-relative test id.
    pub fn extra_inputs(&self, project_rel: &str) -> Vec<String> {
        crate::config::extra_inputs(&self.inputs, project_rel)
    }

    /// The environment this project's test processes get.
    pub fn child_env(&self) -> ChildEnvMap {
        let mut child = build_child_env(&self.project_env(), std::env::vars_os());
        // What the adapter sets for every test process is what the tests
        // see, so it is what is hashed (it wins over `set`: the test script's
        // own `NAME=value` assignments are what a plain run sees).
        for (k, v) in self.adapter.forced_env() {
            child.set(&k, v.into());
        }
        child
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
            // A project this checkout does not have (a branch from before
            // the base's config added it) has no test files to run or skip:
            // the others are planned as usual. 2.6.5 ran everything of every
            // project when one directory was missing.
            if !dir.exists() {
                eprintln!(
                    "vci: warning: {what} {dir} is not in this checkout; its tests are not listed"
                );
                continue;
            }
            if !dir.is_dir() {
                bail!("{what} {dir} is not a directory");
            }
            let dir = dir.canonicalize_utf8()?;
            if !dir.starts_with(&root) {
                bail!("{what} {dir} is outside the repository {root}");
            }
            let options = spec.adapter_options();
            let adapter = vci_adapter::adapter_for_with(&spec.adapter, &dir, &options)?;
            let config_hash = Project::config_hash_of(
                &spec.rel,
                &spec.adapter,
                &options,
                &spec.env,
                &spec.inputs,
                spec.rails_inputs,
                &spec.ignore_inputs,
            );
            let ignored_inputs = spec.ignored_inputs();
            projects.push(Project {
                config_hash,
                rails_inputs: spec.rails_inputs,
                ignored_inputs,
                ignored_noted: Default::default(),
                adapter_options: options,
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use vci_attest::{Envelope, Statement};
    use vci_core::{
        EntryKind, InputEntry, InputManifest, Predicate, Tables, TestResult, Toolchain, object_id,
    };

    use super::*;
    use crate::config::RailsInputs;

    /// The storage key as vci 2.8.1 computed it (`ctx.rs` at e6244e7): the
    /// waived list joined as signed, repeats and order kept.
    fn key_2_8_1(p: &VciPredicate) -> String {
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
        let hashed = |list: &[String]| {
            if list.is_empty() {
                String::new()
            } else {
                vci_core::blake3_hex(list.join("\n").as_bytes())
            }
        };
        let dists = hashed(&tc.python_dists);
        let go_env = hashed(&tc.go_env);
        let platform_specific = p.platform_specific.join("\0");
        let arch_specific = p.arch_specific.join("\0");
        let waived = p.waived.join("\0");
        let rust_cfg = hashed(&tc.rust_cfg);
        let cfg_predicates = p.cfg_predicates.join("\0");
        let ruby_gems = hashed(&tc.ruby_gems);
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
            ("ruby", tc.ruby.as_str()),
            ("ruby_engine", tc.ruby_engine.as_str()),
            ("rails", tc.rails.as_str()),
            ("bundler", tc.bundler.as_str()),
            ("ruby_test", tc.ruby_test.as_str()),
            ("ruby_libs", tc.ruby_libs.as_str()),
            ("ruby_db", tc.ruby_db.as_str()),
            ("ruby_gems", &ruby_gems),
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

    /// The key of `p` through its v2 form: the hdr and tables objects of a
    /// run holding this unit (the waiver table its distinct waived
    /// strings), the v2 statement `to_v2` makes, and the view over them.
    fn key_through_v2(p: &VciPredicate) -> String {
        let hdr = p.hdr().expect("hdr");
        let hdr_id = object_id(&hdr.encode().expect("hdr encodes"));
        let mut waivers = p.waived.clone();
        waivers.sort();
        waivers.dedup();
        let tables = Tables {
            waivers,
            env_names: vec![],
            externals: vec![],
        };
        let tables_id = object_id(&tables.encode().expect("tables encode"));
        let v2 = p
            .to_v2(&hdr_id, &tables_id, &tables, &p.core.input_root)
            .expect("to_v2");
        let view = ResolvedPredicate::v2(&v2, &p.core.input_root, &hdr, &tables).expect("view");
        assert_eq!(view.version(), 2);
        storage_key(&view)
    }

    /// Whether the signed waived list is already sorted and distinct (then
    /// the 2.8.1 key and this key agree).
    fn canonical(waived: &[String]) -> bool {
        waived.windows(2).all(|w| w[0] < w[1])
    }

    fn sample_predicate(adapter: &str, waived: &[&str]) -> VciPredicate {
        let manifest = InputManifest {
            entries: vec![InputEntry {
                path: RepoPath::new("test/a_test.rb").unwrap(),
                kind: EntryKind::File,
                exec: false,
                size: 10,
                hash: "ab".repeat(32),
            }],
            ..Default::default()
        };
        VciPredicate {
            core: Predicate {
                tool_version: "2.9.0".into(),
                adapter: adapter.into(),
                test_id: "test/a_test.rb".into(),
                argv: vec!["bin/rails".into(), "test".into()],
                repo_id: "0123456789abcdef0123456789abcdef01234567".into(),
                commit: "2cb18b86448f1a5d47490e33330b721398073236".into(),
                tree_dirty: false,
                tree: None,
                toolchain: Toolchain {
                    ruby: "3.4.1".into(),
                    rails: "8.0.1".into(),
                    os: "linux".into(),
                    arch: "x86_64".into(),
                    ..Default::default()
                },
                global_input_root: manifest.root(),
                input_root: manifest.root(),
                manifest: None,
                manifest_ref: Some(manifest.root()),
                global_manifest: manifest.clone(),
                result: TestResult {
                    state: "passed".into(),
                    tests: 1,
                    failed: 0,
                    skipped: 0,
                    duration_ms: 5,
                },
                tainted: vec![],
                issued_at: "2026-10-28T04:11:29Z".into(),
                expires_at: "2026-11-11T04:11:29Z".into(),
            },
            env_config_digest: vci_core::blake3_hex(b"env config"),
            project_dir: ".".into(),
            runner_project: String::new(),
            project_name: "api".into(),
            platform_specific: vec![],
            arch_specific: vec![],
            waived: waived.iter().map(|w| w.to_string()).collect(),
            cfg_predicates: vec![],
            declared_inputs: vec![],
            env_set: vec![],
            rails_inputs: "loose".into(),
            ignored_inputs: vec![],
        }
    }

    /// The key over the v1 view equals the key over the v2 view of the same
    /// facts (STORE-V2 section 1.6 rule 7), and equals 2.8.1's key exactly
    /// when the signed waived list was already sorted and distinct (section
    /// 5.1's exception), over a synthetic sample that always runs.
    #[test]
    fn storage_key_is_the_same_over_both_views_and_moves_only_for_a_non_canonical_waived_list() {
        for (adapter, waived, moves) in [
            ("rails", &[][..], false),
            ("rails", &["rails:network-db:a"][..], false),
            (
                "cargo",
                &["cargo:undeclared-reads", "cargo:undeclared-reads"][..],
                true,
            ),
            ("rails", &["t:b", "t:a"][..], true),
            ("rails", &["t:a", "t:b", "t:c"][..], false),
            ("go", &["go:net:x", "go:net:x", "go:net:y"][..], true),
        ] {
            let p = sample_predicate(adapter, waived);
            let v1 = storage_key(&ResolvedPredicate::v1(&p));
            assert_eq!(v1, key_through_v2(&p), "{adapter} {waived:?}");
            assert_eq!(v1 != key_2_8_1(&p), moves, "{adapter} {waived:?}");
            assert_eq!(!canonical(&p.waived), moves, "{adapter} {waived:?}");
        }
        // Two lists of the same strings in another order or with repeats
        // key one slot; a list of other strings keys another.
        let a = storage_key(&ResolvedPredicate::v1(&sample_predicate(
            "rails",
            &["t:b", "t:a"],
        )));
        let b = storage_key(&ResolvedPredicate::v1(&sample_predicate(
            "rails",
            &["t:a", "t:b", "t:a"],
        )));
        let c = storage_key(&ResolvedPredicate::v1(&sample_predicate("rails", &["t:a"])));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// The same over the real units of `VCI_PAIRS` (the 1,175-unit sample
    /// STORE-V2 was measured on; skipped without it), and how many of
    /// their keys move from 2.8.1's because the waived list enters sorted
    /// and distinct: STORE-V2-DECISIONS.md says 1,163 of 1,175 (their slots are
    /// re-created once; the old rows expire).
    #[test]
    fn storage_key_over_the_real_sample_matches_both_views_and_counts_the_moved_slots() {
        let Some(path) = std::env::var_os("VCI_PAIRS") else {
            eprintln!("SKIPPED: VCI_PAIRS is not set");
            return;
        };
        let text = std::fs::read_to_string(&path).expect("VCI_PAIRS readable");
        let file: BTreeMap<String, Vec<(String, String, String)>> =
            serde_json::from_str(&text).expect("pairs JSON");
        let pairs = &file["pairs"];
        let (mut moved, mut repeated, mut unsorted) = (0usize, 0usize, 0usize);
        for (i, (env_s, _, _)) in pairs.iter().enumerate() {
            let envelope = Envelope::from_json(env_s.as_bytes()).expect("envelope");
            let payload = envelope.payload_bytes().expect("payload");
            let statement: Statement = serde_json::from_slice(&payload).expect("statement");
            let p: VciPredicate =
                serde_json::from_value(statement.predicate).expect("v1 predicate");
            let v1 = storage_key(&ResolvedPredicate::v1(&p));
            assert_eq!(v1, key_through_v2(&p), "unit {i} ({})", p.core.test_id);
            let old = key_2_8_1(&p);
            assert_eq!(v1 != old, !canonical(&p.waived), "unit {i}");
            if v1 != old {
                moved += 1;
            }
            let mut sorted = p.waived.clone();
            sorted.sort();
            if sorted.windows(2).any(|w| w[0] == w[1]) {
                repeated += 1;
            }
            if sorted != p.waived {
                unsorted += 1;
            }
        }
        eprintln!(
            "storage keys: {moved} of {} v1 records key another slot under 2.9 than under 2.8.1 (the waived list enters sorted and distinct: {repeated} repeat a string, {unsorted} are unsorted); the 2.8 rows stay as second candidates until they expire",
            pairs.len()
        );
        if pairs.len() == 1175 {
            assert_eq!((moved, repeated, unsorted), (1163, 1158, 1163));
        }
    }

    /// `rails_inputs` and `ignore_inputs` join the config hash only when not
    /// the default, so loose mode without a list hashes as 2.7.33 did (its
    /// strict attestations stay usable), and the other settings do not mix.
    #[test]
    fn rails_inputs_join_the_config_hash_unless_default() {
        let opts = vci_adapter::AdapterOptions::default();
        let env = EnvConfig::default();
        let h = |mode: Option<RailsInputs>, list: &[String]| {
            Project::config_hash_of(".", "rails", &opts, &env, &[], mode, list)
        };
        let before = {
            let text = format!(
                "vci-config-v1\n.\nrails\n{opts:?}\n{}\n{}",
                serde_json::to_string(&env).unwrap(),
                serde_json::to_string::<Vec<InputsConfig>>(&vec![]).unwrap()
            );
            vci_core::blake3_hex(text.as_bytes())
        };
        assert_eq!(h(Some(RailsInputs::Loose), &[]), before);
        assert_eq!(h(None, &[]), before);
        let strict = h(Some(RailsInputs::Strict), &[]);
        let listed = h(
            Some(RailsInputs::Loose),
            &["config/credentials/**".to_owned()],
        );
        let strict_listed = h(
            Some(RailsInputs::Strict),
            &["config/credentials/**".to_owned()],
        );
        let all = [before, strict, listed, strict_listed];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
