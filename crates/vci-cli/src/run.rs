//! `vci run`: run tests with collection on, then sign and store an
//! attestation for every test file that is provably attestable.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use vci_adapter::{Adapter, Observed};
use vci_attest::{Statement, Subject, sign_statement};
use vci_core::{
    External, InputManifest, Observation, PREDICATE_TYPE, Predicate, RepoPath, Toolchain, test_key,
};
use vci_git::AttestStore;

use crate::ctx::{Ctx, TestFile, VciPredicate, open_repo, storage_key, working_tree_config};
use crate::envpolicy::{ChildEnvMap, FileEnv, build_child_env, lookup};
use crate::treestat::TreeStat;
use crate::util::{now_unix, parse_duration, rfc3339};
use crate::{global, keys};

pub struct RunArgs {
    pub files: Vec<String>,
    pub key: Option<Utf8PathBuf>,
    pub ttl: String,
}

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Global manifest (per test file): global observations plus NODE_OPTIONS.
pub fn global_manifest(
    ctx: &Ctx,
    child: &ChildEnvMap,
    test_abs: &Utf8Path,
) -> Result<InputManifest> {
    let obs = global::observations(&ctx.root, &ctx.adapter, test_abs)?;
    let m = InputManifest::capture_with_env(
        &ctx.root,
        &obs,
        vec![],
        &["NODE_OPTIONS".to_owned()],
        lookup(child),
    )?;
    m.check_case_collisions()?;
    Ok(m)
}

/// Observations of one test file, as repo paths. Err names the first path
/// outside the repository.
pub fn observations(root: &Utf8Path, o: &Observed) -> Result<Vec<(RepoPath, Observation)>, String> {
    let mut out = Vec::new();
    let groups: [(&BTreeSet<Utf8PathBuf>, Observation); 4] = [
        (&o.modules, Observation::Read),
        (&o.reads, Observation::Read),
        (&o.probes, Observation::Probe),
        (&o.readdirs, Observation::ReadDir),
    ];
    for (set, kind) in groups {
        for p in set {
            match RepoPath::from_abs(root, p) {
                Ok(rp) => out.push((rp, kind)),
                Err(_) => return Err(format!("input outside the repository: {p}")),
            }
        }
    }
    // package.json / tsconfig.json that decide how each module resolves its
    // imports and is transformed.
    let ctx = global::module_context(root, o.modules.iter().map(|p| p.as_path()))
        .map_err(|e| format!("module context: {e:#}"))?;
    out.extend(ctx);
    Ok(out)
}

pub fn toolchain(v: &vci_adapter::ToolVersions) -> Toolchain {
    Toolchain {
        node: v.node.clone(),
        vitest: v.runner.clone(),
        vite: v.bundler.clone(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
    }
}

struct Attestable {
    predicate: VciPredicate,
}

#[allow(clippy::too_many_arguments)]
fn check_one(
    ctx: &Ctx,
    o: &Observed,
    file: Option<&TestFile>,
    versions: &vci_adapter::ToolVersions,
    child: &ChildEnvMap,
    pre_stat: &TreeStat,
    pre_global: &BTreeMap<String, Result<String, String>>,
    base: &PredicateBase,
) -> Result<Attestable, String> {
    let file = file.ok_or_else(|| "not in the runner's test file list".to_owned())?;
    if file.ambiguous {
        return Err("listed under more than one runner project".into());
    }
    if Utf8Path::new(&o.root) != ctx.adapter.project_dir()
        && Utf8Path::new(&o.root).canonicalize_utf8().ok().as_deref()
            != Some(ctx.adapter.project_dir())
    {
        return Err(format!("collector root {} is not the project dir", o.root));
    }
    if !o.taints.is_empty() {
        return Err(format!("tainted: {}", o.taints.join(", ")));
    }
    let result = o.result.clone().ok_or("no result")?;
    if !result.is_pass() {
        return Err(format!(
            "result {} ({} failed of {})",
            result.state, result.failed, result.tests
        ));
    }
    if o.node != versions.node
        || o.runner_version != versions.runner
        || o.bundler_version != versions.bundler
    {
        return Err(format!(
            "toolchain seen by the collector (node {}, vitest {}, vite {}) differs from the project's (node {}, vitest {}, vite {})",
            o.node,
            o.runner_version,
            o.bundler_version,
            versions.node,
            versions.runner,
            versions.bundler
        ));
    }
    let obs = observations(&ctx.root, o)?;
    let fenv = FileEnv::for_file(
        &ctx.config.env,
        ctx.adapter.inferred_env_patterns(),
        &file.project_rel,
    );
    let keys = fenv.hashed_keys(child, &o.env_keys);
    let externals: Vec<External> = o
        .externals
        .iter()
        .map(|(n, v)| External {
            name: n.clone(),
            version: v.clone(),
        })
        .collect();
    let manifest =
        InputManifest::capture_with_env(&ctx.root, &obs, externals, &keys, lookup(child))
            .map_err(|e| format!("capturing inputs: {e}"))?;
    manifest
        .check_case_collisions()
        .map_err(|e| format!("inputs: {e}"))?;
    let gm = global_manifest(ctx, child, &file.abs).map_err(|e| format!("global inputs: {e:#}"))?;
    match pre_global.get(file.test_id.as_str()) {
        Some(Ok(root)) if *root == gm.root() => {}
        Some(Ok(_)) => return Err("global inputs changed during the run".into()),
        Some(Err(e)) => return Err(format!("global inputs before the run: {e}")),
        None => return Err("no pre-run global snapshot".into()),
    }
    for e in manifest.entries.iter().chain(gm.entries.iter()) {
        pre_stat
            .unchanged(e)
            .map_err(|r| format!("input changed during the run: {r}"))?;
    }
    let core = Predicate {
        tool_version: TOOL_VERSION.to_owned(),
        adapter: ctx.adapter.name().to_owned(),
        test_id: file.test_id.as_str().to_owned(),
        argv: ctx
            .adapter
            .canonical_argv(&ctx.project_rel, &file.project_rel),
        repo_id: base.repo_id.clone(),
        commit: base.commit.clone(),
        tree_dirty: base.dirty,
        toolchain: toolchain(versions),
        global_input_root: gm.root(),
        input_root: manifest.root(),
        manifest,
        global_manifest: gm,
        result,
        tainted: vec![],
        issued_at: rfc3339(base.issued),
        expires_at: rfc3339(base.issued + base.ttl),
    };
    Ok(Attestable {
        predicate: VciPredicate {
            core,
            env_config_digest: fenv.digest(),
            project_dir: ctx.project_rel.clone(),
            runner_project: file.runner_project.clone(),
        },
    })
}

struct PredicateBase {
    repo_id: String,
    commit: String,
    dirty: bool,
    issued: i64,
    ttl: i64,
}

/// Resolve CLI file arguments (relative to cwd) to project-relative paths.
fn resolve_files(ctx: &Ctx, args: &[String], files: &[TestFile]) -> Result<Vec<String>> {
    let cwd = crate::ctx::cwd()?;
    let mut out = Vec::new();
    for a in args {
        let abs = cwd.join(a);
        let abs = abs
            .canonicalize_utf8()
            .with_context(|| format!("test file {a}"))?;
        let rel = abs
            .strip_prefix(ctx.adapter.project_dir())
            .with_context(|| format!("{a} is not inside the project dir {}", ctx.project_dir))?
            .as_str()
            .to_owned();
        if !files.iter().any(|f| f.project_rel == rel) {
            bail!("{a} is not a test file of this project (not listed by vitest)");
        }
        out.push(rel);
    }
    Ok(out)
}

pub fn run(args: RunArgs) -> Result<i32> {
    let (repo, root) = open_repo()?;
    let config = working_tree_config(&root)?;
    let ttl = parse_duration(&args.ttl).context("--ttl")?;
    let max = config.policy.max_ttl_secs()?;
    if ttl > max {
        bail!(
            "--ttl {} exceeds policy.max_ttl {}; such attestations would be rejected",
            args.ttl,
            config.policy.max_ttl
        );
    }
    let ctx = Ctx::new(repo, root.clone(), config)?;
    let key = keys::discover(args.key.as_deref(), &root)?;
    let signer = key.signer_id();

    let base = PredicateBase {
        repo_id: ctx
            .repo
            .repo_id()
            .context("repo id (needs at least one commit)")?,
        commit: ctx.repo.head_commit()?,
        dirty: ctx.repo.is_dirty()?,
        issued: now_unix(),
        ttl,
    };
    let child = build_child_env(
        &ctx.config.env,
        ctx.adapter.inferred_env_patterns(),
        std::env::vars_os(),
    );
    let child_env = child.to_child_env();
    let files = ctx.test_files(ctx.adapter.list_test_files(&child_env)?)?;
    let selected: Vec<String> = if args.files.is_empty() {
        files.iter().map(|f| f.project_rel.clone()).collect()
    } else {
        resolve_files(&ctx, &args.files, &files)?
    };
    if selected.is_empty() {
        bail!("no test files to run");
    }
    for f in &files {
        if selected.contains(&f.project_rel) {
            let fe = FileEnv::for_file(
                &ctx.config.env,
                ctx.adapter.inferred_env_patterns(),
                &f.project_rel,
            );
            for s in fe.secret_like() {
                eprintln!(
                    "vci: warning: declared env var {s} looks like a secret; its hash is published in attestations. Put it in pass_through instead."
                );
            }
        }
    }
    let versions = ctx.adapter.tool_versions()?;

    // Before the run: tree metadata and global inputs.
    let pre_stat = TreeStat::snapshot(&root)?;
    let mut pre_global = BTreeMap::new();
    for f in files.iter().filter(|f| selected.contains(&f.project_rel)) {
        let r = global_manifest(&ctx, &child, &f.abs)
            .map(|m| m.root())
            .map_err(|e| format!("{e:#}"));
        pre_global.insert(f.test_id.as_str().to_owned(), r);
    }

    let out = ctx.adapter.run_collect(&selected, &child_env)?;

    let by_id: BTreeMap<&str, &TestFile> = files.iter().map(|f| (f.test_id.as_str(), f)).collect();
    let store = AttestStore::new(&ctx.repo);
    let mut attested = 0;
    let mut refused = 0;
    let mut seen = BTreeSet::new();
    for o in &out.files {
        let id = ctx.test_id(&o.test_id).map(|p| p.as_str().to_owned()).ok();
        let file = id.as_ref().and_then(|id| by_id.get(id.as_str()).copied());
        let label = id.clone().unwrap_or_else(|| o.test_id.clone());
        seen.insert(label.clone());
        match check_one(
            &ctx,
            o,
            file,
            &versions,
            &child,
            &pre_stat,
            &pre_global,
            &base,
        ) {
            Err(reason) => {
                refused += 1;
                eprintln!("vci: not attesting {label}: {reason}");
            }
            Ok(a) => {
                let p = &a.predicate;
                let skey = storage_key(p);
                let value = serde_json::to_value(p)?;
                let mut digest = std::collections::BTreeMap::new();
                digest.insert("blake3".to_owned(), p.core.input_root.clone());
                let stmt = Statement::new(
                    vec![Subject {
                        name: p.core.test_id.clone(),
                        digest,
                    }],
                    PREDICATE_TYPE,
                    value,
                );
                let env = sign_statement(&stmt, &key.path)
                    .with_context(|| format!("signing with {}", key.path))?;
                store.put(&signer, &test_key(&p.core.test_id), &skey, &env.to_json())?;
                attested += 1;
                eprintln!(
                    "vci: attested {label} ({} inputs, root {}) on refs/attest/v1/{signer}",
                    p.core.manifest.entries.len(),
                    &p.core.input_root[..16]
                );
            }
        }
    }
    for f in files.iter().filter(|f| selected.contains(&f.project_rel)) {
        if !seen.contains(f.test_id.as_str()) {
            refused += 1;
            eprintln!(
                "vci: not attesting {}: the collector produced no output for it",
                f.test_id
            );
        }
    }
    eprintln!("vci: {attested} attested, {refused} not attested");
    Ok(out.exit_code.unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Utf8Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    /// Regression: resolution driven by package.json (`imports`, a workspace
    /// package's `main`/`exports`) and per-directory tsconfig files were not
    /// inputs, so changing them left the test skipped.
    #[test]
    fn modules_bring_their_package_json_and_tsconfig() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        write(&root, "package.json", "{}");
        write(
            &root,
            "packages/lib/package.json",
            r#"{"name":"@me/lib","main":"./a.js"}"#,
        );
        write(&root, "packages/lib/a.js", "export default 'a';\n");
        write(
            &root,
            "src/atk/pkgimp/package.json",
            r##"{"imports":{"#dep":"./dep-a.ts"}}"##,
        );
        write(&root, "src/atk/pkgimp/imp.test.ts", "import '#dep';\n");
        write(
            &root,
            "src/atk/tsc/tsconfig.json",
            r#"{"extends":"../base.json"}"#,
        );
        write(&root, "src/atk/base.json", "{}");
        write(&root, "src/atk/tsc/cls.ts", "export class A {}\n");
        write(&root, "src/atk/x.ts", "export {};\n");
        let o = Observed {
            modules: [
                "packages/lib/a.js",
                "src/atk/pkgimp/imp.test.ts",
                "src/atk/tsc/cls.ts",
                "src/atk/x.ts",
            ]
            .iter()
            .map(|p| root.join(p))
            .collect(),
            ..Default::default()
        };
        let obs = observations(&root, &o).unwrap();
        let get = |p: &str| obs.iter().find(|(rp, _)| rp.as_str() == p).map(|(_, o)| *o);
        for (p, want) in [
            ("packages/lib/package.json", Observation::Read),
            ("src/atk/pkgimp/package.json", Observation::Read),
            ("src/atk/tsc/package.json", Observation::Probe),
            ("src/atk/package.json", Observation::Probe),
            ("src/package.json", Observation::Probe),
            ("package.json", Observation::Read),
            ("src/atk/tsc/tsconfig.json", Observation::Read),
            ("src/atk/base.json", Observation::Read),
            ("src/atk/tsconfig.json", Observation::Probe),
        ] {
            assert_eq!(get(p), Some(want), "{p}: {obs:?}");
        }
    }
}
