//! `vci run`: run tests with collection on, then sign and store an
//! attestation for every test file that is provably attestable.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use vci_adapter::Observed;
use vci_attest::{Statement, Subject, sign_statement};
use vci_core::{
    External, InputManifest, Observation, PREDICATE_TYPE, Predicate, RepoPath, Toolchain,
};
use vci_git::AttestStore;

use crate::ctx::{
    Ctx, Project, TestFile, VciPredicate, mark_cross_project_ambiguity, open_repo, storage_key,
    working_tree_config,
};
use crate::envpolicy::{ChildEnvMap, lookup};
use crate::treestat::TreeStat;
use crate::util::{now_unix, parse_duration, rfc3339};
use crate::{global, keys};

pub struct RunArgs {
    pub files: Vec<String>,
    pub key: Option<Utf8PathBuf>,
    pub ttl: String,
}

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Env vars hashed into every test file's global manifest, per adapter.
fn global_env_keys(adapter: &str) -> Vec<String> {
    match adapter {
        // vci sets NODE_OPTIONS itself; a non-empty user value still matters.
        "vitest" => vec!["NODE_OPTIONS".to_owned()],
        // PYTEST_*/PYTHON* are reported per file by the collector.
        _ => vec![],
    }
}

/// Global manifest (per test file): global observations plus the adapter's
/// global env keys (NODE_OPTIONS for Vitest).
pub fn global_manifest(
    ctx: &Ctx,
    project: &Project,
    child: &ChildEnvMap,
    test_abs: &Utf8Path,
) -> Result<InputManifest> {
    let obs = global::observations(&ctx.root, project.adapter.as_ref(), test_abs)?;
    let m = InputManifest::capture_with_env(
        &ctx.root,
        &obs,
        vec![],
        &global_env_keys(project.adapter.name()),
        lookup(child),
    )?;
    m.check_case_collisions()?;
    Ok(m)
}

/// Observations of one test file, as repo paths (Vitest). Err names the
/// first path outside the repository.
#[cfg_attr(not(test), allow(dead_code))]
pub fn observations(root: &Utf8Path, o: &Observed) -> Result<Vec<(RepoPath, Observation)>, String> {
    observations_for(root, o, "vitest")
}

/// Observations of one test file for `adapter`: the collector's paths, plus
/// (Vitest only) the package.json/tsconfig.json context of every module.
pub fn observations_for(
    root: &Utf8Path,
    o: &Observed,
    adapter: &str,
) -> Result<Vec<(RepoPath, Observation)>, String> {
    let mut out = Vec::new();
    let groups: [(&BTreeSet<Utf8PathBuf>, Observation); 6] = [
        (&o.modules, Observation::Read),
        (&o.reads, Observation::Read),
        (&o.probes, Observation::Probe),
        (&o.readdirs, Observation::ReadDir),
        (&o.stats, Observation::Stat),
        (&o.excluded, Observation::Exclude),
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
    if adapter == "vitest" {
        let ctx = global::module_context(root, o.modules.iter().map(|p| p.as_path()))
            .map_err(|e| format!("module context: {e:#}"))?;
        out.extend(ctx);
    }
    Ok(out)
}

/// Whether this process (and so the tests it starts) runs as the superuser:
/// the owner of a file it creates is uid 0 (the effective, or on Linux the
/// filesystem, uid). Permission checks do not apply to root, so a test's
/// result can depend on it (GitHub `container:` jobs run as root). Any error
/// counts as root, so that an attestation made or checked where this cannot
/// be decided only matches another such run.
pub fn running_as_root() -> bool {
    static ROOT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ROOT.get_or_init(|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            tempfile::NamedTempFile::new()
                .and_then(|f| f.as_file().metadata())
                .map(|m| m.uid() == 0)
                .unwrap_or(true)
        }
        #[cfg(not(unix))]
        {
            false
        }
    })
}

/// The toolchain recorded for (and compared against) an attestation.
pub fn toolchain_for(adapter: &str, v: &vci_adapter::ToolVersions) -> Toolchain {
    let mut t = Toolchain {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        superuser: running_as_root(),
        ..Default::default()
    };
    match adapter {
        "pytest" => {
            t.python = v.python.clone();
            t.implementation = v.implementation.clone();
            t.pytest = v.runner.clone();
            t.python_libs = v.python_libs.clone();
            t.python_dists = v.python_dists.clone();
        }
        "go" => {
            t.go = v.runner.clone();
            t.go_env = v.go_env.clone();
            t.go_arch_level = v.go_arch_level.clone();
        }
        "cargo" => {
            t.rust = v.runner.clone();
            t.cargo = v.cargo.clone();
            t.rust_host = v.rust_host.clone();
            t.rust_cfg = v.rust_cfg.clone();
        }
        "rails" => {
            t.ruby = v.ruby.clone();
            t.ruby_engine = v.ruby_engine.clone();
            t.rails = v.rails.clone();
            t.bundler = v.ruby_bundler.clone();
            t.ruby_test = v.runner.clone();
            t.ruby_libs = v.ruby_libs.clone();
            t.ruby_db = v.ruby_db.clone();
            t.ruby_gems = v.ruby_gems.clone();
        }
        _ => {
            t.node = v.node.clone();
            t.vitest = v.runner.clone();
            t.vite = v.bundler.clone();
        }
    }
    t
}

struct Attestable {
    predicate: VciPredicate,
}

/// Collector versions vs the project's, per adapter.
fn collector_toolchain_mismatch(
    adapter: &str,
    o: &Observed,
    v: &vci_adapter::ToolVersions,
) -> Option<String> {
    match adapter {
        "pytest" => (o.python != v.python
            || o.implementation != v.implementation
            || o.runner_version != v.runner)
            .then(|| {
                format!(
                    "toolchain seen by the collector (python {} {}, pytest {}) differs from the project's (python {} {}, pytest {})",
                    o.implementation,
                    o.python,
                    o.runner_version,
                    v.implementation,
                    v.python,
                    v.runner
                )
            }),
        // The test binary reports runtime.Version(); `go env GOVERSION` is
        // what the project resolves (after any GOTOOLCHAIN switch).
        // Only the version token: with GOEXPERIMENT both may carry an
        // ` X:...` suffix (the experiments are compared in the toolchain).
        "go" => (o.runner_version.split_whitespace().next()
            != v.runner.split_whitespace().next())
        .then(|| {
            format!(
                "the test binary was built by {} but the project's go is {}",
                o.runner_version, v.runner
            )
        }),
        // The adapter records the rustc it probed; the build used the same
        // one unless something changed it in between.
        "cargo" => (o.runner_version != v.runner).then(|| {
            format!(
                "rustc changed during the run ({} -> {})",
                v.runner, o.runner_version
            )
        }),
        "rails" => (o.ruby != v.ruby
            || o.ruby_engine != v.ruby_engine
            || o.rails != v.rails
            || o.ruby_bundler != v.ruby_bundler
            || o.runner_version != v.runner)
            .then(|| {
                format!(
                    "toolchain seen by the collector ({} {}, rails {}, bundler {}, {}) differs from the project's ({} {}, rails {}, bundler {}, {})",
                    o.ruby_engine,
                    o.ruby,
                    o.rails,
                    o.ruby_bundler,
                    o.runner_version,
                    v.ruby_engine,
                    v.ruby,
                    v.rails,
                    v.ruby_bundler,
                    v.runner
                )
            }),
        _ => (o.node != v.node || o.runner_version != v.runner || o.bundler_version != v.bundler)
            .then(|| {
                format!(
                    "toolchain seen by the collector (node {}, vitest {}, vite {}) differs from the project's (node {}, vitest {}, vite {})",
                    o.node, o.runner_version, o.bundler_version, v.node, v.runner, v.bundler
                )
            }),
    }
}

/// Names in a directory listing that a fresh CI checkout will not have:
/// OS metadata and bytecode caches.
const CHECKOUT_JUNK: &[&str] = &[".DS_Store", "Thumbs.db", "desktop.ini", "__pycache__"];

/// Warnings for attested directory listings that contain [`CHECKOUT_JUNK`]:
/// the listing will differ in a fresh checkout, so the file will run there
/// (never a false skip, but a lost skip worth knowing about).
fn junk_in_listings(root: &Utf8Path, m: &InputManifest) -> Vec<String> {
    let mut out = Vec::new();
    for e in &m.entries {
        if e.kind != vci_core::EntryKind::DirListing {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(e.path.to_abs(root)) else {
            continue;
        };
        let junk: Vec<String> = rd
            .flatten()
            .filter_map(|d| d.file_name().into_string().ok())
            .filter(|n| CHECKOUT_JUNK.contains(&n.as_str()))
            .collect();
        if !junk.is_empty() {
            let dir = if e.path.as_str().is_empty() {
                "."
            } else {
                e.path.as_str()
            };
            out.push(format!(
                "the listing of {dir} includes {} (not in a fresh checkout, e.g. in CI): this attestation will not match there. Remove {} and run again.",
                junk.join(", "),
                if junk.len() == 1 { "it" } else { "them" }
            ));
        }
    }
    out
}

/// Taints for the refusal line, readable when a library makes hundreds of
/// similar calls (FFI's `attach_function` for every function of libvips):
/// taints that agree up to their first `(` are shown once with a count, and
/// at most [`MAX_TAINT_GROUPS`] groups are listed.
fn summarize_taints(taints: &[&String]) -> String {
    let mut groups: Vec<(&str, &str, usize)> = Vec::new();
    for t in taints {
        let key = t.split_once('(').map_or(t.as_str(), |(k, _)| k);
        match groups.iter_mut().find(|(k, _, _)| *k == key) {
            Some(g) => g.2 += 1,
            None => groups.push((key, t.as_str(), 1)),
        }
    }
    let n = groups.len();
    let mut parts: Vec<String> = groups
        .into_iter()
        .take(MAX_TAINT_GROUPS)
        .map(|(_, first, count)| {
            if count > 1 {
                format!("{first} (+{} more like it)", count - 1)
            } else {
                first.to_owned()
            }
        })
        .collect();
    if n > MAX_TAINT_GROUPS {
        parts.push(format!("and {} more", n - MAX_TAINT_GROUPS));
    }
    parts.join(", ")
}

const MAX_TAINT_GROUPS: usize = 12;

#[allow(clippy::too_many_arguments)]
fn check_one(
    ctx: &Ctx,
    project: &Project,
    o: &Observed,
    file: Option<&TestFile>,
    versions: &vci_adapter::ToolVersions,
    child: &ChildEnvMap,
    pre_stat: &TreeStat,
    pre_global: &BTreeMap<String, Result<String, String>>,
    base: &PredicateBase,
    locked: &Result<Option<crate::externals::LockedPackages>, String>,
    scratch: &[Utf8PathBuf],
) -> Result<Attestable, String> {
    let file = file.ok_or_else(|| "not in the runner's test file list".to_owned())?;
    if file.ambiguous {
        return Err(
            "listed under more than one runner project (or by more than one vci project)".into(),
        );
    }
    let adapter = project.adapter.as_ref();
    if o.adapter != adapter.name() {
        return Err(format!(
            "collector output is for adapter {:?}, not {:?}",
            o.adapter,
            adapter.name()
        ));
    }
    if Utf8Path::new(&o.root) != adapter.project_dir()
        && Utf8Path::new(&o.root).canonicalize_utf8().ok().as_deref() != Some(adapter.project_dir())
    {
        return Err(format!("collector root {} is not the project dir", o.root));
    }
    // Go: `policy.go_allow_net` waives the `net` refusal (recorded in the
    // attestation, which is then only accepted while the base policy agrees).
    // Cargo: declaring inputs for the unit (`[[inputs]]`) waives the
    // "may read outside its package" refusal (the declaration is recorded
    // and must still be the base config's).
    let declared = project.extra_inputs(&file.project_rel);
    let (waived, taints): (Vec<&String>, Vec<&String>) = o.taints.iter().partition(|t| {
        (adapter.name() == "go"
            && project.policy.go_allow_net
            && t.starts_with(vci_adapter::GO_NET_TAINT))
            || (adapter.name() == "cargo"
                && !declared.is_empty()
                && t.starts_with(vci_adapter::CARGO_UNDECLARED_TAINT))
            || (adapter.name() == "rails"
                && project.policy.rails_allow_db
                && t.starts_with(vci_adapter::RAILS_NETWORK_DB_TAINT))
    });
    if !taints.is_empty() {
        return Err(format!("tainted: {}", summarize_taints(&taints)));
    }
    let waived: Vec<String> = waived.into_iter().cloned().collect();
    if adapter.name() == "cargo" && project.env.mode == crate::config::EnvMode::Loose {
        // What a Rust test reads from the environment cannot be observed;
        // only strict mode (undeclared variables removed, so unset on both
        // sides) makes that safe.
        return Err(
            "env mode \"loose\": the cargo adapter only attests in strict mode (a Rust test's environment reads are not observed)"
                .into(),
        );
    }
    if adapter.name() == "go" {
        // A go.work outside the repository decides which module versions
        // are built, but is not an input CI can re-hash.
        let w = versions.go_work.as_str();
        if !w.is_empty() && w != "off" {
            let abs = Utf8Path::new(w);
            let inside = abs.starts_with(&ctx.root)
                || abs
                    .canonicalize_utf8()
                    .is_ok_and(|c| c.starts_with(&ctx.root));
            if !inside {
                return Err(format!(
                    "go.work {w} is outside the repository (set GOWORK=off or move it into the repository)"
                ));
            }
        }
    }
    // Files the test created, changed or deleted inside the repository are
    // outputs that later runs (or other test files) may read: not attestable.
    // Rails: writes to git-ignored paths in the project's log/, tmp/,
    // storage/ and coverage/ are allowed (derived state no checkout has; a
    // later read of such a file that existed before the reading process
    // started is an input, and will not match a fresh checkout).
    let mut written: Vec<String> = o
        .writes
        .iter()
        .filter_map(|p| RepoPath::from_abs(&ctx.root, p).ok())
        .map(|p| p.as_str().to_owned())
        .collect();
    if adapter.name() == "rails" && !written.is_empty() {
        let scratch: Vec<Utf8PathBuf> = vci_adapter::RAILS_SCRATCH_DIRS
            .iter()
            .map(|d| project.dir.join(d))
            .collect();
        let candidates: Vec<String> = written
            .iter()
            .filter(|w| {
                let abs = ctx.root.join(w);
                scratch.iter().any(|d| abs.starts_with(d) && abs != *d)
            })
            .cloned()
            .collect();
        let ignored: BTreeSet<String> = git_ignored(&ctx.root, &candidates).into_iter().collect();
        written.retain(|w| !ignored.contains(w));
    }
    if !written.is_empty() {
        return Err(format!(
            "wrote inside the repository: {}",
            written.join(", ")
        ));
    }
    let result = o.result.clone().ok_or("no result")?;
    if !result.is_pass() && matches!(result.state.as_str(), "no-tests" | "filtered") {
        return Err(format!(
            "result {} ({} tests; no test ran or some were filtered out, so the run cannot vouch for the unit)",
            result.state, result.tests
        ));
    }
    if result.state == "no-assertions" {
        return Err(format!(
            "result no-assertions ({} tests; a test that makes no assertion vouches for nothing)",
            result.tests
        ));
    }
    if !result.is_pass() {
        return Err(format!(
            "result {} ({} failed, {} skipped or xfailed of {}; a skipped test did not run, so it cannot be vouched for elsewhere)",
            result.state, result.failed, result.skipped, result.tests
        ));
    }
    if adapter.name() == "pytest" {
        // The test saw vci's own PYTHONPATH (the collector directory), which
        // differs between machines and is not what a plain run sees.
        if o.env_keys.contains("PYTHONPATH") {
            return Err("read PYTHONPATH, which vci sets to its collector".into());
        }
        // Externals built from the repository itself are not identified by
        // their version.
        match locked {
            Ok(Some(lock)) => {
                for (n, _) in &o.externals {
                    if let Some(why) = crate::externals::local_source_reason(lock, n) {
                        return Err(why);
                    }
                }
            }
            Ok(None) => {}
            Err(e) if !o.externals.is_empty() => return Err(format!("uv.lock: {e}")),
            Err(_) => {}
        }
    }
    if let Some(m) = collector_toolchain_mismatch(adapter.name(), o, versions) {
        return Err(m);
    }
    let mut obs = observations_for(&ctx.root, o, adapter.name())?;
    obs.extend(expand_extra_inputs(
        &ctx.root,
        &project.dir,
        &declared,
        scratch,
    )?);
    let mut platform_specific: Vec<String> = Vec::new();
    for p in &o.platform_files {
        let rp = RepoPath::from_abs(&ctx.root, p)
            .map_err(|_| format!("input outside the repository: {p}"))?;
        platform_specific.push(rp.as_str().to_owned());
    }
    platform_specific.sort();
    let fenv = project.file_env(&file.project_rel);
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
    // Paths the unit's source names outside its package directories must be
    // recorded inputs (declared with `[[inputs]]`).
    for (p, seen) in &o.path_refs {
        let rp = RepoPath::from_abs(&ctx.root, p)
            .map_err(|_| format!("its source refers to {p}, outside the repository ({seen})"))?;
        if !covered(&ctx.root, &manifest, &rp) {
            return Err(format!(
                "its source refers to {} ({seen}), which is not an input; declare it in vci.toml ([[inputs]] match = [{:?}], extra = [...])",
                rp.as_str(),
                file.project_rel
            ));
        }
    }
    let gm = global_manifest(ctx, project, child, &file.abs)
        .map_err(|e| format!("global inputs: {e:#}"))?;
    match pre_global.get(file.test_id.as_str()) {
        Some(Ok(root)) if *root == gm.root() => {}
        Some(Ok(_)) => return Err("global inputs changed during the run".into()),
        Some(Err(e)) => return Err(format!("global inputs before the run: {e}")),
        None => return Err("no pre-run global snapshot".into()),
    }
    let excluded = manifest.excluded_children();
    for e in &manifest.entries {
        pre_stat
            .unchanged_excluding(e, excluded.get(&e.path))
            .map_err(|r| format!("input changed during the run: {r}"))?;
    }
    for e in &gm.entries {
        pre_stat
            .unchanged(e)
            .map_err(|r| format!("input changed during the run: {r}"))?;
    }
    let core = Predicate {
        tool_version: TOOL_VERSION.to_owned(),
        adapter: adapter.name().to_owned(),
        test_id: file.test_id.as_str().to_owned(),
        argv: adapter.canonical_argv(&project.rel, &file.project_rel),
        repo_id: base.repo_id.clone(),
        commit: base.commit.clone(),
        tree_dirty: base.dirty,
        toolchain: toolchain_for(adapter.name(), versions),
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
            project_dir: project.rel.clone(),
            runner_project: file.runner_project.clone(),
            project_name: project.name.clone(),
            platform_specific,
            arch_specific: o.arch_specific.iter().cloned().collect(),
            waived,
            cfg_predicates: o.cfg_predicates.iter().cloned().collect(),
            declared_inputs: declared,
        },
    })
}

/// Directory names never walked for declared inputs (the tree snapshot does
/// not track them either).
const EXTRA_SKIP: &[&str] = &[".git", "node_modules", ".venv"];

/// Observations for `[[inputs]] extra` globs (relative to `project_dir`):
/// a glob without wildcards names a file (read), a directory (walked) or a
/// missing path (probe); otherwise the directory before the first wildcard
/// is walked, every directory in it is a listing (so a new matching file is
/// noticed) and every matching file a read.
pub fn expand_extra_inputs(
    root: &Utf8Path,
    project_dir: &Utf8Path,
    globs: &[String],
    scratch: &[Utf8PathBuf],
) -> Result<Vec<(RepoPath, Observation)>, String> {
    let mut out: Vec<(Utf8PathBuf, Observation)> = Vec::new();
    for g in globs {
        let comps: Vec<&str> = g
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .collect();
        let fixed: Vec<&str> = comps
            .iter()
            .take_while(|c| !c.contains(['*', '?', '[', '{']))
            .copied()
            .collect();
        let base = fixed.iter().fold(project_dir.to_owned(), |p, c| p.join(c));
        let literal = fixed.len() == comps.len();
        let meta = std::fs::symlink_metadata(&base);
        match meta {
            Err(_) => out.push((base, Observation::Probe)),
            Ok(m) if !m.is_dir() => out.push((base, Observation::Read)),
            Ok(_) => {
                let mut stack = vec![base.clone()];
                while let Some(d) = stack.pop() {
                    if scratch.iter().any(|s| d.starts_with(s)) {
                        continue;
                    }
                    let inside = d.strip_prefix(root).unwrap_or(&d);
                    if inside
                        .components()
                        .any(|c| EXTRA_SKIP.contains(&c.as_str()))
                    {
                        return Err(format!(
                            "declared input {g:?} reaches {d}, which vci does not hash"
                        ));
                    }
                    out.push((d.clone(), Observation::ReadDir));
                    let rd = d
                        .read_dir_utf8()
                        .map_err(|e| format!("declared input {g:?}: listing {d}: {e}"))?;
                    for ent in rd.flatten() {
                        let p = ent.path().to_owned();
                        let is_dir = ent.file_type().map(|t| t.is_dir()).unwrap_or(false);
                        if is_dir {
                            if EXTRA_SKIP.contains(&ent.file_name()) {
                                continue;
                            }
                            stack.push(p);
                            continue;
                        }
                        let rel = p
                            .strip_prefix(project_dir)
                            .map(|r| r.as_str())
                            .unwrap_or("");
                        if literal || crate::util::glob_match(g, rel) {
                            out.push((p, Observation::Read));
                        }
                    }
                }
            }
        }
    }
    out.into_iter()
        .map(|(p, o)| {
            RepoPath::from_abs(root, &p)
                .map(|rp| (rp, o))
                .map_err(|_| format!("declared input {p} is outside the repository"))
        })
        .collect()
}

/// Is `rp` covered by the manifest: recorded itself (a directory listing
/// only when everything below it is recorded too), or absent with its
/// parent's listing recorded (so creating it is noticed)?
fn covered(root: &Utf8Path, m: &InputManifest, rp: &RepoPath) -> bool {
    use vci_core::EntryKind;
    let kinds: BTreeMap<&str, EntryKind> = m
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e.kind))
        .collect();
    let abs = rp.to_abs(root);
    match kinds.get(rp.as_str()) {
        Some(EntryKind::DirListing) => {
            let mut stack = vec![abs];
            while let Some(d) = stack.pop() {
                let Ok(rd) = d.read_dir_utf8() else {
                    return false;
                };
                for ent in rd.flatten() {
                    let Ok(r) = RepoPath::from_abs(root, ent.path()) else {
                        return false;
                    };
                    let is_dir = ent.file_type().map(|t| t.is_dir()).unwrap_or(false);
                    match kinds.get(r.as_str()) {
                        Some(EntryKind::DirListing) if is_dir => stack.push(ent.path().to_owned()),
                        Some(_) if !is_dir => {}
                        _ => return false,
                    }
                }
            }
            true
        }
        // Build output is never an input.
        Some(EntryKind::Excluded) => false,
        Some(_) => true,
        None => {
            !abs.exists()
                && rp
                    .parent()
                    .is_some_and(|p| kinds.get(p.as_str()) == Some(&EntryKind::DirListing))
        }
    }
}

/// Recorded inputs that git ignores: a fresh checkout (CI) does not have
/// them, so the attestation will not match there.
/// A Rails credentials key file (`config/master.key`,
/// `config/credentials/<env>.key`), relative to the repository root.
fn is_rails_key_file(p: &str) -> bool {
    let in_config =
        |rest: &str| p == format!("config/{rest}") || p.ends_with(&format!("/config/{rest}"));
    in_config("master.key")
        || p.rsplit_once("/").is_some_and(|(dir, f)| {
            f.ends_with(".key")
                && (dir == "config/credentials" || dir.ends_with("/config/credentials"))
        })
}

fn ignored_inputs(root: &Utf8Path, m: &InputManifest) -> Vec<String> {
    let paths: Vec<String> = m
        .entries
        .iter()
        .filter(|e| {
            !matches!(
                e.kind,
                vci_core::EntryKind::Absent | vci_core::EntryKind::Excluded
            ) && !e.path.is_root()
        })
        .map(|e| e.path.as_str().to_owned())
        .collect();
    git_ignored(root, &paths)
}

/// The repo-relative `paths` git ignores (`git check-ignore`); any error
/// means none (so nothing is treated as ignored).
fn git_ignored(root: &Utf8Path, paths: &[String]) -> Vec<String> {
    use std::io::Write as _;
    if paths.is_empty() {
        return vec![];
    }
    let child = std::process::Command::new("git")
        .args(["-C", root.as_str(), "check-ignore", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        return vec![];
    };
    if let Some(mut i) = child.stdin.take() {
        let _ = i.write_all(paths.join("\n").as_bytes());
        let _ = i.write_all(b"\n");
    }
    let Ok(out) = child.wait_with_output() else {
        return vec![];
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

struct PredicateBase {
    repo_id: String,
    commit: String,
    dirty: bool,
    issued: i64,
    ttl: i64,
}

/// The absolute paths CLI unit arguments name (a cargo `<dir>#<target>`
/// names `<dir>`), or `None` when one cannot be resolved (then every project
/// is listed and [`resolve_files`] reports the problem).
fn unit_paths(args: &[String]) -> Option<Vec<camino::Utf8PathBuf>> {
    let cwd = crate::ctx::cwd().ok()?;
    args.iter()
        .map(|a| {
            cwd.join(a).canonicalize_utf8().ok().or_else(|| {
                let (dir, _) = a.rsplit_once('#')?;
                let dir = if dir.is_empty() { "." } else { dir };
                cwd.join(dir).canonicalize_utf8().ok()
            })
        })
        .collect()
}

/// Resolve CLI file arguments (relative to cwd) to indexes into `files`
/// (every project that lists the file).
fn resolve_files(args: &[String], files: &[TestFile]) -> Result<BTreeSet<usize>> {
    let cwd = crate::ctx::cwd()?;
    let mut out = BTreeSet::new();
    for a in args {
        // Cargo units: `<package dir>#<target>`, or a package dir for all of
        // its units.
        let hits: Vec<usize> = match cwd.join(a).canonicalize_utf8() {
            Ok(abs) => {
                let exact: Vec<usize> = files
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| f.abs == abs)
                    .map(|(i, _)| i)
                    .collect();
                if exact.is_empty() && abs.is_dir() {
                    let prefix = format!("{abs}#");
                    files
                        .iter()
                        .enumerate()
                        .filter(|(_, f)| f.abs.as_str().starts_with(&prefix))
                        .map(|(i, _)| i)
                        .collect()
                } else {
                    exact
                }
            }
            Err(e) => match a.rsplit_once('#') {
                Some((dir, target)) => {
                    let dir = if dir.is_empty() { "." } else { dir };
                    let abs = cwd
                        .join(dir)
                        .canonicalize_utf8()
                        .with_context(|| format!("test {a}"))?;
                    let want = format!("{abs}#{target}");
                    files
                        .iter()
                        .enumerate()
                        .filter(|(_, f)| f.abs.as_str() == want)
                        .map(|(i, _)| i)
                        .collect()
                }
                None => return Err(e).with_context(|| format!("test file {a}")),
            },
        };
        if hits.is_empty() {
            bail!("{a} is not a test file of any project (not listed by the test runner)");
        }
        out.extend(hits);
    }
    Ok(out)
}

pub fn run(args: RunArgs) -> Result<i32> {
    let (repo, root) = open_repo()?;
    let config = working_tree_config(&root)?;
    let ttl = parse_duration(&args.ttl).context("--ttl")?;
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
    let children: Vec<ChildEnvMap> = ctx.projects.iter().map(|p| p.child_env()).collect();
    let locks: Vec<_> = ctx
        .projects
        .iter()
        .map(|p| crate::externals::uv_lock_packages(&p.dir, &ctx.root))
        .collect();
    // With explicit units, only projects whose directory can hold one of
    // them are listed (a project only ever lists units below its own
    // directory), so another project's missing toolchain does not matter.
    // Projects nested in each other are all listed, so a unit two projects
    // list is still found ambiguous.
    let wanted = if args.files.is_empty() {
        None
    } else {
        unit_paths(&args.files)
    };
    let mut files: Vec<TestFile> = Vec::new();
    for (i, p) in ctx.projects.iter().enumerate() {
        if let Some(paths) = &wanted {
            let dir = p
                .adapter
                .project_dir()
                .canonicalize_utf8()
                .unwrap_or_else(|_| p.adapter.project_dir().to_owned());
            if !paths.iter().any(|a| a.starts_with(&dir)) {
                continue;
            }
        }
        let listed = p
            .adapter
            .list_test_files(&children[i].to_child_env())
            .with_context(|| format!("listing the test files of {}", p.label()))?;
        files.extend(p.test_files(i, listed)?);
    }
    mark_cross_project_ambiguity(&mut files);
    let selected: BTreeSet<usize> = if args.files.is_empty() {
        (0..files.len()).collect()
    } else {
        resolve_files(&args.files, &files)?
    };
    if selected.is_empty() {
        bail!("no test files to run");
    }
    let involved: BTreeSet<usize> = selected.iter().map(|&i| files[i].project).collect();
    for &pi in &involved {
        let p = &ctx.projects[pi];
        let max = p.policy.max_ttl_secs()?;
        if ttl > max {
            bail!(
                "--ttl {} exceeds policy.max_ttl {} of {}; such attestations would be rejected",
                args.ttl,
                p.policy.max_ttl,
                p.label()
            );
        }
    }
    for &i in &selected {
        let f = &files[i];
        for s in ctx.projects[f.project]
            .file_env(&f.project_rel)
            .secret_like()
        {
            eprintln!(
                "vci: warning: declared env var {s} looks like a secret; its hash is published in attestations. Put it in pass_through instead."
            );
        }
    }
    let mut versions = BTreeMap::new();
    for &pi in &involved {
        let p = &ctx.projects[pi];
        let v = p
            .adapter
            .tool_versions_with_env(&children[pi].to_child_env())
            .with_context(|| format!("tool versions of {}", p.label()))?;
        versions.insert(pi, v);
        for w in p.adapter.warnings(&children[pi].to_child_env()) {
            eprintln!("vci: warning: {w}");
        }
    }

    // Before the run: tree metadata and global inputs (build output
    // directories such as Cargo's target dir are not inputs).
    let scratch: Vec<Utf8PathBuf> = involved
        .iter()
        .flat_map(|&pi| ctx.projects[pi].adapter.scratch_dirs())
        .filter(|d| d.starts_with(&root))
        .collect();
    let pre_stat = TreeStat::snapshot_skipping(&root, &scratch)?;
    let mut pre_global = BTreeMap::new();
    for &i in &selected {
        let f = &files[i];
        let r = global_manifest(&ctx, &ctx.projects[f.project], &children[f.project], &f.abs)
            .map(|m| m.root())
            .map_err(|e| format!("{e:#}"));
        pre_global.insert(f.test_id.as_str().to_owned(), r);
    }

    let store = AttestStore::new(&ctx.repo);
    let mut attested = 0;
    let mut refused = 0;
    let mut exit: Option<i32> = Some(0);
    for &pi in &involved {
        let project = &ctx.projects[pi];
        let child = &children[pi];
        let mine: Vec<&TestFile> = selected
            .iter()
            .map(|&i| &files[i])
            .filter(|f| f.project == pi)
            .collect();
        let rels: Vec<String> = mine.iter().map(|f| f.project_rel.clone()).collect();
        if ctx.projects.len() > 1 {
            eprintln!(
                "vci: running {} test file(s) of {} ({})",
                rels.len(),
                project.label(),
                project.adapter.name()
            );
        }
        // Go's test log does not report removals, renames or new
        // directories: any change to the repository during the run refuses
        // every package of the run (the change cannot be attributed).
        let go_tree = if project.adapter.name() == "go" {
            Some(TreeStat::snapshot(&root)?)
        } else {
            None
        };
        let out = project.adapter.run_collect(&rels, &child.to_child_env())?;
        let tree_changed: Option<String> = match &go_tree {
            None => None,
            Some(t) => match t.changes() {
                Ok(c) if c.is_empty() => None,
                Ok(c) => Some(format!(
                    "the repository changed during the run: {}{}",
                    c.iter().take(10).cloned().collect::<Vec<_>>().join(", "),
                    if c.len() > 10 { ", ..." } else { "" }
                )),
                Err(e) => Some(format!("checking the repository after the run: {e:#}")),
            },
        };
        match (exit, out.exit_code) {
            (Some(0), c) => exit = c,
            (Some(_), None) => exit = None,
            _ => {}
        }
        let by_id: BTreeMap<&str, &TestFile> =
            mine.iter().map(|f| (f.test_id.as_str(), *f)).collect();
        let mut seen = BTreeSet::new();
        for o in &out.files {
            let id = project
                .test_id(&o.test_id)
                .map(|p| p.as_str().to_owned())
                .ok();
            let file = id.as_ref().and_then(|id| by_id.get(id.as_str()).copied());
            let label = id.clone().unwrap_or_else(|| o.test_id.clone());
            seen.insert(label.clone());
            if let Some(why) = &tree_changed {
                refused += 1;
                eprintln!("vci: not attesting {label}: {why}");
                continue;
            }
            match check_one(
                &ctx,
                project,
                o,
                file,
                &versions[&pi],
                child,
                &pre_stat,
                &pre_global,
                &base,
                &locks[pi],
                &scratch,
            ) {
                Err(reason) => {
                    refused += 1;
                    eprintln!("vci: not attesting {label}: {reason}");
                }
                Ok(a) => {
                    let p = &a.predicate;
                    for w in junk_in_listings(&ctx.root, &p.core.manifest) {
                        eprintln!("vci: warning: {label}: {w}");
                    }
                    if p.core.manifest.env.iter().any(|e| e.key == "CI") {
                        eprintln!(
                            "vci: warning: {label}: it reads CI, which CI runners set (to \"true\"): unless it had that value here, this attestation will not match on a runner{}",
                            if project.adapter.name() == "rails" {
                                "; Rails' generated config/environments/test.rb reads it (config.eager_load = ENV[\"CI\"].present?)"
                            } else {
                                ""
                            }
                        );
                    }
                    if matches!(project.adapter.name(), "cargo" | "rails") {
                        let ignored = ignored_inputs(&ctx.root, &p.core.manifest);
                        if !ignored.is_empty() {
                            let why = if project.adapter.name() == "cargo" {
                                "every file in a package directory is an input"
                            } else {
                                "the test read them; delete them before attesting if they are leftovers"
                            };
                            eprintln!(
                                "vci: warning: {label}: inputs ignored by git (a fresh checkout, e.g. in CI, will not have them, so this attestation will not match there; {why}): {}{}",
                                ignored
                                    .iter()
                                    .take(10)
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                if ignored.len() > 10 { ", ..." } else { "" }
                            );
                            if project.adapter.name() == "rails"
                                && let Some(key) = ignored.iter().find(|p| is_rails_key_file(p))
                            {
                                eprintln!(
                                    "vci: warning: {label}: it read {key}, Rails' credentials key (git-ignored, so never in CI): in an app generated with credentials, Active Record reads it at boot, so no test that boots Rails is skipped in CI. Give the test environment its own credentials with a committed key (`bin/rails credentials:edit --environment test`, then commit config/credentials/test.key and test.yml.enc), or remove config/master.key and the credentials file if the tests need none, or declare RAILS_MASTER_KEY in vci.toml and set it to the same value here and in CI"
                                );
                            }
                        }
                    }
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
                    let stored = store.put(&p.core.test_id, &signer, &skey, &env.to_json())?;
                    attested += 1;
                    eprintln!(
                        "vci: attested {label} ({} inputs, root {}) as git-meta {} {}",
                        p.core.manifest.entries.len(),
                        &p.core.input_root[..16],
                        stored.target,
                        stored.key
                    );
                }
            }
        }
        for f in &mine {
            if !seen.contains(f.test_id.as_str()) {
                refused += 1;
                eprintln!(
                    "vci: not attesting {}: the collector produced no output for it",
                    f.test_id
                );
            }
        }
    }
    eprintln!("vci: {attested} attested, {refused} not attested");
    Ok(exit.unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Utf8Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn similar_taints_are_summarized() {
        let mut t: Vec<String> = vec![r#"native:FFI ffi_lib(["vips.42"])"#.into()];
        for i in 0..300 {
            t.push(format!(
                r#"native:FFI attach_function([:vips_f{i}, [:pointer]])"#
            ));
        }
        t.push("process:backtick".into());
        let refs: Vec<&String> = t.iter().collect();
        assert_eq!(
            summarize_taints(&refs),
            r#"native:FFI ffi_lib(["vips.42"]), native:FFI attach_function([:vips_f0, [:pointer]]) (+299 more like it), process:backtick"#
        );
        let many: Vec<String> = (0..20).map(|i| format!("t{i}")).collect();
        let refs: Vec<&String> = many.iter().collect();
        assert!(summarize_taints(&refs).ends_with("t11, and 8 more"));
    }

    #[test]
    fn rails_key_files() {
        for p in [
            "config/master.key",
            "app/config/master.key",
            "config/credentials/test.key",
            "shop/config/credentials/production.key",
        ] {
            assert!(is_rails_key_file(p), "{p}");
        }
        for p in [
            "config/master.key.bak",
            "lib/config/credentials/x/test.key",
            "config/credentials/test.yml.enc",
            "notconfig/master.key",
            "master.key",
        ] {
            assert!(!is_rails_key_file(p), "{p}");
        }
    }

    /// `[[inputs]] extra` globs: a literal file, a missing path, and a glob
    /// whose fixed prefix is walked (listings for new files, matching files
    /// read); coverage of paths a unit's source names.
    #[test]
    fn declared_inputs_expand_and_cover() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        write(&root, "rs/shared/x.json", "{}");
        write(&root, "rs/data/a.txt", "a");
        write(&root, "rs/data/sub/b.txt", "b");
        write(&root, "rs/data/sub/c.bin", "c");
        write(&root, "rs/target/debug/out.txt", "o");
        let proj = root.join("rs");
        let globs = [
            "shared/x.json".to_owned(),
            "missing.txt".to_owned(),
            "data/**/*.txt".to_owned(),
        ];
        let obs = expand_extra_inputs(&root, &proj, &globs, &[proj.join("target")]).unwrap();
        let get = |p: &str| obs.iter().find(|(rp, _)| rp.as_str() == p).map(|(_, o)| *o);
        assert_eq!(get("rs/shared/x.json"), Some(Observation::Read));
        assert_eq!(get("rs/missing.txt"), Some(Observation::Probe));
        assert_eq!(get("rs/data"), Some(Observation::ReadDir));
        assert_eq!(get("rs/data/sub"), Some(Observation::ReadDir));
        assert_eq!(get("rs/data/a.txt"), Some(Observation::Read));
        assert_eq!(get("rs/data/sub/b.txt"), Some(Observation::Read));
        assert_eq!(get("rs/data/sub/c.bin"), None, "does not match the glob");
        let all =
            expand_extra_inputs(&root, &proj, &["**".to_owned()], &[proj.join("target")]).unwrap();
        assert!(
            !all.iter().any(|(p, _)| p.as_str().starts_with("rs/target")),
            "{all:?}"
        );
        let m = InputManifest::capture(&root, &obs, vec![], &[]).unwrap();
        let rp = |p: &str| RepoPath::new(p).unwrap();
        assert!(covered(&root, &m, &rp("rs/shared/x.json")));
        assert!(covered(&root, &m, &rp("rs/missing.txt")));
        assert!(
            covered(&root, &m, &rp("rs/data/new.txt")),
            "absent, parent listed"
        );
        assert!(!covered(&root, &m, &rp("rs/data")), "c.bin is not recorded");
        assert!(
            !covered(&root, &m, &rp("rs/shared/other.json")),
            "its directory is not listed"
        );
        assert!(!covered(&root, &m, &rp("elsewhere/x")));
        std::fs::remove_file(root.join("rs/data/sub/c.bin")).unwrap();
        assert!(
            covered(&root, &m, &rp("rs/data")),
            "everything below is recorded"
        );
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
