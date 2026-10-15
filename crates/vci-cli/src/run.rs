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
    /// Write a JSON summary of every unit (attested or not, with its
    /// reasons) to this file.
    pub summary: Option<Utf8PathBuf>,
}

/// What `vci run` decided for one unit (for the refusal summary and
/// `--summary`).
struct UnitOutcome {
    test_id: String,
    project: Option<String>,
    adapter: &'static str,
    attested: bool,
    /// Stable reason keys ([`taint_key`], [`refusal_key`]), most frequent
    /// taint first.
    reasons: Vec<String>,
    /// The refusal line's text.
    detail: Option<String>,
    /// Every refusing taint, as the collector reported it.
    taints: Vec<String>,
}

impl UnitOutcome {
    fn refused(test_id: &str, project: &Project, detail: String, reasons: Vec<String>) -> Self {
        Self {
            test_id: test_id.to_owned(),
            project: (!project.name.is_empty()).then(|| project.name.clone()),
            adapter: project.adapter.name(),
            attested: false,
            reasons,
            detail: Some(detail),
            taints: vec![],
        }
    }
}

/// `vci: why not attested` lines: files per reason key, most first.
fn reason_counts(outcomes: &[UnitOutcome]) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for o in outcomes.iter().filter(|o| !o.attested) {
        for r in &o.reasons {
            *counts.entry(r.as_str()).or_default() += 1;
        }
    }
    let mut v: Vec<(String, usize)> = counts.into_iter().map(|(k, n)| (k.to_owned(), n)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

/// The `--summary` document.
fn summary_json(outcomes: &[UnitOutcome]) -> serde_json::Value {
    let attested = outcomes.iter().filter(|o| o.attested).count();
    serde_json::json!({
        "version": 1,
        "attested": attested,
        "notAttested": outcomes.len() - attested,
        "reasons": reason_counts(outcomes)
            .into_iter()
            .map(|(reason, files)| serde_json::json!({"reason": reason, "files": files}))
            .collect::<Vec<_>>(),
        "units": outcomes
            .iter()
            .map(|o| serde_json::json!({
                "testId": o.test_id,
                "project": o.project,
                "adapter": o.adapter,
                "attested": o.attested,
                "reasons": o.reasons,
                "detail": o.detail,
                "taints": o.taints,
            }))
            .collect::<Vec<_>>(),
    })
}

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Env vars hashed into every test file's global manifest, per adapter.
fn global_env_keys(adapter: &str) -> Vec<String> {
    match adapter {
        // vci sets NODE_OPTIONS itself; a non-empty user value still matters.
        "vitest" | "node-test" => vec!["NODE_OPTIONS".to_owned()],
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
    observations_for(root, o, "vitest", true)
}

/// Observations of one test file for `adapter`: the collector's paths, plus
/// (Vitest and node-test) the package.json context of every module and,
/// when `tsconfig` (Vitest; node-test with a TypeScript loader), its
/// tsconfig.json chain.
pub fn observations_for(
    root: &Utf8Path,
    o: &Observed,
    adapter: &str,
    tsconfig: bool,
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
    if adapter == "vitest" || adapter == "node-test" {
        let ctx = global::module_context_with(
            root,
            o.modules.iter().map(|p| p.as_path()),
            adapter == "vitest" || tsconfig,
        )
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
        // node:test is part of Node: the Node version is the runner's.
        "node-test" => {
            t.node = v.node.clone();
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
        "node-test" => (o.node != v.node).then(|| {
            format!(
                "the test ran on node {} but the project's node is {}",
                o.node, v.node
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

/// The stable reason key of a taint: its category, without the paths,
/// arguments and explanations that vary between files. The first segment
/// (up to `:`, a space or `(`), and when it ends in a single `:`, the name
/// that follows (letters, digits, `_`, `-`): `native:FFI attach_function(...)`
/// -> `native:FFI`, `cargo:process: Command::new in ...` -> `cargo:process`,
/// `go:source: a.go uses Environ` -> `go:source`, `vci:not-hooked:ffi (...)` ->
/// `vci:not-hooked`, `external-without-version:/x` ->
/// `external-without-version`, `process:backtick` -> `process:backtick`.
pub fn taint_key(t: &str) -> String {
    let t = t.trim();
    let end = t.find([':', ' ', '(']).unwrap_or(t.len());
    let head = &t[..end];
    let rest = &t[end..];
    let Some(after) = rest.strip_prefix(':') else {
        return head.to_owned();
    };
    if after.starts_with(':') {
        return head.to_owned();
    }
    let name: String = after
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if name.is_empty() {
        head.to_owned()
    } else {
        format!("{head}:{name}")
    }
}

/// The stable reason key of a refusal message that is not a list of taints
/// (those are keyed by [`taint_key`]): the text before the first `:` or
/// `(`, or a fixed key for messages that start with a varying part.
pub fn refusal_key(msg: &str) -> String {
    const FIXED: &[(&str, &str)] = &[
        (
            "collector output is for adapter",
            "collector output is for another adapter",
        ),
        ("collector root ", "collector root is not the project dir"),
        ("go.work ", "go.work outside the repository"),
        (
            "its source refers to ",
            "source refers to a path that is not an input",
        ),
        ("declared input ", "declared input"),
        (
            "listed under more than one",
            "listed by more than one project",
        ),
    ];
    for (prefix, key) in FIXED {
        if msg.starts_with(prefix) {
            return (*key).to_owned();
        }
    }
    if msg.starts_with("result ") && msg.contains(" skipped or xfailed of ") {
        return "result has skipped tests".into();
    }
    if msg.contains(" is built from a local directory") {
        return "external built from a local directory".into();
    }
    let end = msg.find([':', '(']).unwrap_or(msg.len());
    msg[..end].trim().to_owned()
}

/// Taints grouped by [`taint_key`], most frequent first (ties in order of
/// first appearance): `(key, first taint of the group, count)`.
fn group_taints<'a>(taints: &[&'a String]) -> Vec<(String, &'a str, usize)> {
    let mut groups: Vec<(String, &str, usize)> = Vec::new();
    for t in taints {
        let key = taint_key(t);
        match groups.iter_mut().find(|(k, _, _)| *k == key) {
            Some(g) => g.2 += 1,
            None => groups.push((key, t.as_str(), 1)),
        }
    }
    // A stable sort keeps first-appearance order among equal counts.
    groups.sort_by_key(|g| std::cmp::Reverse(g.2));
    groups
}

/// Taints for the refusal line, readable when a library makes hundreds of
/// similar calls (FFI's `attach_function` for every function of libvips):
/// taints with the same [`taint_key`] are shown once, as the first of them
/// with the count of the others, most frequent reason first. Every reason
/// is listed.
fn summarize_taints(taints: &[&String]) -> String {
    group_taints(taints)
        .into_iter()
        .map(|(key, first, count)| {
            if count > 1 {
                format!("{first} (+{} more {key})", count - 1)
            } else {
                first.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The taints of `o` that refuse it, and those a base policy waives (Go's
/// `policy.go_allow_net`, Cargo's declared inputs).
fn split_waived<'a>(
    project: &Project,
    declared: &[String],
    o: &'a Observed,
) -> (Vec<&'a String>, Vec<&'a String>) {
    let name = project.adapter.name();
    o.taints.iter().partition(|t| {
        (name == "go" && project.policy.go_allow_net && t.starts_with(vci_adapter::GO_NET_TAINT))
            || (name == "cargo"
                && !declared.is_empty()
                && t.starts_with(vci_adapter::CARGO_UNDECLARED_TAINT))
    })
}

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
    let (waived, taints) = split_waived(project, &declared, o);
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
        return Err(if result.skipped > 0 {
            format!(
                "result {} ({} failed, {} skipped or xfailed of {}; a skipped test did not run, so it cannot be vouched for elsewhere)",
                result.state, result.failed, result.skipped, result.tests
            )
        } else {
            format!(
                "result {} ({} failed of {})",
                result.state, result.failed, result.tests
            )
        });
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
    let mut obs = observations_for(&ctx.root, o, adapter.name(), adapter.tsconfig_is_input())?;
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

/// Which units [`run_units`] runs.
pub enum Selection {
    /// `vci run`'s arguments (paths relative to the current directory,
    /// `<package dir>#<target>`); empty: every unit of every project.
    Args(Vec<String>),
    /// Per project (index into the configuration's projects): `None` runs
    /// every unit of the project, `Some(ids)` the units with these test ids
    /// (each must be listed by the project). Projects not named are not run.
    Units(BTreeMap<usize, Option<BTreeSet<String>>>),
}

/// A unit [`run_units`] attested.
#[derive(Debug, Clone)]
pub struct AttestedUnit {
    pub test_id: String,
    /// `[[projects]]` name; empty in the single-project form.
    pub project: String,
}

/// What [`run_units`] did.
#[derive(Default)]
pub struct RunOutcome {
    /// Non-zero when a test failed (refusals to attest do not count).
    pub exit: i32,
    pub attested: Vec<AttestedUnit>,
    /// Problems that did not stop the other projects or units (a project
    /// that could not be listed or run, a unit that could not be signed or
    /// stored), in order. Once a test has run, [`run_units`] reports a
    /// problem here instead of failing, so what it already signed and
    /// stored is always in [`RunOutcome::attested`].
    pub errors: Vec<String>,
    /// Projects (indexes into the configuration's projects) whose tests did
    /// not run because listing or starting them failed: no verdict, nothing
    /// attested. `vci ci` runs them without attesting.
    pub unrun: BTreeSet<usize>,
}

pub fn run(args: RunArgs) -> Result<i32> {
    let (repo, root) = open_repo()?;
    let config = working_tree_config(&root)?;
    if let Some(w) = config.removed_keys_warning(crate::config::CONFIG_FILE) {
        eprintln!("vci: warning: {w}");
    }
    let out = run_units(
        repo,
        root,
        config,
        Selection::Args(args.files),
        args.key.as_deref(),
        &args.ttl,
        args.summary.as_deref(),
    )?;
    if !out.errors.is_empty() {
        bail!(
            "{} problem(s) during the run (the rest ran): {}",
            out.errors.len(),
            out.errors.join("; ")
        );
    }
    Ok(out.exit)
}

/// `vci run`'s work, for `vci run` and `vci ci --key`: run `selection` with
/// the collectors (one process per unit where the adapter does so), record
/// each unit's inputs, and sign and store an attestation for every unit that
/// passed and is provably attestable. `config` decides the projects (`vci
/// run`: the working tree's; `vci ci`: the one its plan was made from).
pub fn run_units(
    repo: vci_git::Repo,
    root: Utf8PathBuf,
    config: crate::config::Config,
    selection: Selection,
    key: Option<&Utf8Path>,
    ttl_arg: &str,
    summary: Option<&Utf8Path>,
) -> Result<RunOutcome> {
    let ttl = parse_duration(ttl_arg).context("--ttl")?;
    let ctx = Ctx::new(repo, root.clone(), config)?;
    let key = keys::discover(key, &root)?;
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
    let wanted = match &selection {
        Selection::Args(a) if !a.is_empty() => unit_paths(a),
        _ => None,
    };
    let mut files: Vec<TestFile> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut unrun: BTreeSet<usize> = BTreeSet::new();
    let listing: Vec<bool> = ctx
        .projects
        .iter()
        .enumerate()
        .map(|(i, p)| {
            if let Selection::Units(u) = &selection
                && !u.contains_key(&i)
            {
                return false;
            }
            if let Some(paths) = &wanted {
                let dir = p
                    .adapter
                    .project_dir()
                    .canonicalize_utf8()
                    .unwrap_or_else(|_| p.adapter.project_dir().to_owned());
                if !paths.iter().any(|a| a.starts_with(&dir)) {
                    return false;
                }
            }
            true
        })
        .collect();
    // Every project is listed at once (listing shells out), in order after.
    let listings: Vec<Option<Result<Vec<TestFile>>>> = std::thread::scope(|s| {
        let handles: Vec<_> = ctx
            .projects
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let (listing, children) = (&listing, &children);
                s.spawn(move || {
                    listing[i].then(|| {
                        p.adapter
                            .list_test_files(&children[i].to_child_env())
                            .map_err(anyhow::Error::from)
                            .and_then(|l| p.test_files(i, l))
                            .with_context(|| format!("listing the test files of {}", p.label()))
                    })
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
            .collect()
    });
    for (i, listed) in listings.into_iter().enumerate() {
        let Some(listed) = listed else { continue };
        match listed {
            Ok(f) => files.extend(f),
            // `vci ci`: one project that cannot be listed does not stop the
            // others from being attested (it runs without attesting).
            Err(e) if matches!(selection, Selection::Units(_)) => {
                let msg = format!("{e:#}");
                eprintln!("vci: error: {msg}");
                errors.push(msg);
                unrun.insert(i);
            }
            Err(e) => return Err(e),
        }
    }
    mark_cross_project_ambiguity(&mut files);
    let selected: BTreeSet<usize> = match &selection {
        Selection::Args(a) if a.is_empty() => (0..files.len()).collect(),
        Selection::Args(a) => resolve_files(a, &files)?,
        Selection::Units(u) => {
            let listed: BTreeMap<usize, Option<BTreeSet<String>>> = u
                .iter()
                .filter(|(i, _)| !unrun.contains(i))
                .map(|(i, ids)| (*i, ids.clone()))
                .collect();
            select_units(&ctx, &listed, &files)?
        }
    };
    if selected.is_empty() {
        if let Selection::Units(_) = selection {
            return Ok(RunOutcome {
                exit: 0,
                attested: vec![],
                errors,
                unrun,
            });
        }
        bail!("no test files to run");
    }
    let involved: BTreeSet<usize> = selected.iter().map(|&i| files[i].project).collect();
    for &pi in &involved {
        let p = &ctx.projects[pi];
        let max = p.policy.max_ttl_secs()?;
        if ttl > max {
            bail!(
                "--ttl {} exceeds policy.max_ttl {} of {}; such attestations would be rejected",
                ttl_arg,
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
    // The toolchain of every involved project (probed at once; Rails also
    // boots the application, which must report the toolchain read without
    // booting it), checked and reported in order.
    let probed: Vec<(usize, Result<vci_adapter::ToolVersions>, Vec<String>)> =
        std::thread::scope(|s| {
            let handles: Vec<_> = involved
                .iter()
                .map(|&pi| {
                    let (p, env) = (&ctx.projects[pi], children[pi].to_child_env());
                    s.spawn(move || {
                        let v = p
                            .adapter
                            .tool_versions_with_env(&env)
                            .and_then(|v| p.adapter.check_run_environment(&env).map(|()| v))
                            .with_context(|| format!("tool versions of {}", p.label()));
                        let warnings = if v.is_ok() {
                            p.adapter.warnings(&env)
                        } else {
                            vec![]
                        };
                        (pi, v, warnings)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
                .collect()
        });
    let mut versions = BTreeMap::new();
    for (pi, v, warnings) in probed {
        versions.insert(pi, v?);
        for w in warnings {
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
    let mut outcomes: Vec<UnitOutcome> = Vec::new();
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
        let started = (|| -> Result<_> {
            let go_tree = if project.adapter.name() == "go" {
                Some(TreeStat::snapshot(&root)?)
            } else {
                None
            };
            let out = project.adapter.run_collect(&rels, &child.to_child_env())?;
            Ok((go_tree, out))
        })();
        // A project whose run could not be started or collected has no
        // verdict: the other projects still run and are attested (what was
        // signed and stored is reported), and `vci ci` runs this one without
        // attesting.
        let (go_tree, out) = match started {
            Ok(x) => x,
            Err(e) => {
                let msg = format!(
                    "running the tests of {} with the collectors: {e:#}",
                    project.label()
                );
                eprintln!("vci: error: {msg}");
                errors.push(msg);
                unrun.insert(pi);
                let why = "the run with the collectors could not be started or collected";
                for f in &mine {
                    refused += 1;
                    outcomes.push(UnitOutcome::refused(
                        f.test_id.as_str(),
                        project,
                        why.to_owned(),
                        vec![why.to_owned()],
                    ));
                }
                continue;
            }
        };
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
        // vci's own collector files are tooling, not inputs, however the
        // process reached them (a symlinked install prefix).
        let collector_dirs = project.adapter.collector_dirs();
        for o in &out.files {
            let filtered;
            let o = if collector_dirs.is_empty() {
                o
            } else {
                let mut c = o.clone();
                c.drop_collector_paths(&ctx.root, &collector_dirs);
                filtered = c;
                &filtered
            };
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
                outcomes.push(UnitOutcome::refused(
                    &label,
                    project,
                    why.clone(),
                    vec![refusal_key(why)],
                ));
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
                    let mut out = UnitOutcome::refused(&label, project, reason.clone(), vec![]);
                    match file {
                        Some(f) if reason.starts_with("tainted: ") => {
                            let declared = project.extra_inputs(&f.project_rel);
                            let (_, taints) = split_waived(project, &declared, o);
                            out.reasons = group_taints(&taints).into_iter().map(|g| g.0).collect();
                            out.taints = taints.into_iter().cloned().collect();
                        }
                        _ => out.reasons = vec![refusal_key(&reason)],
                    }
                    outcomes.push(out);
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
                    if matches!(project.adapter.name(), "cargo" | "rails" | "node-test") {
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
                    let signed = (|| -> Result<_> {
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
                        Ok(store.put(&p.core.test_id, &signer, &skey, &env.to_json())?)
                    })();
                    let stored = match signed {
                        Ok(s) => s,
                        Err(e) => {
                            let msg = format!("{label}: {e:#}");
                            eprintln!("vci: error: not attesting {msg}");
                            errors.push(msg);
                            refused += 1;
                            let why = format!("signing or storing failed: {e:#}");
                            outcomes.push(UnitOutcome::refused(
                                &label,
                                project,
                                why,
                                vec!["signing or storing failed".to_owned()],
                            ));
                            continue;
                        }
                    };
                    attested += 1;
                    outcomes.push(UnitOutcome {
                        test_id: label.clone(),
                        project: (!project.name.is_empty()).then(|| project.name.clone()),
                        adapter: project.adapter.name(),
                        attested: true,
                        reasons: vec![],
                        detail: None,
                        taints: vec![],
                    });
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
                let why = "the collector produced no output for it";
                eprintln!("vci: not attesting {}: {why}", f.test_id);
                outcomes.push(UnitOutcome::refused(
                    f.test_id.as_str(),
                    project,
                    why.to_owned(),
                    vec![why.to_owned()],
                ));
            }
        }
    }
    eprintln!("vci: {attested} attested, {refused} not attested");
    let counts = reason_counts(&outcomes);
    if !counts.is_empty() {
        eprintln!("vci: why not attested (files per reason; a file can have several):");
        let w = counts.first().map_or(1, |c| c.1.to_string().len());
        for (reason, n) in &counts {
            eprintln!("vci:   {n:>w$} {reason}");
        }
    }
    if let Some(path) = summary {
        let mut text = serde_json::to_string_pretty(&summary_json(&outcomes))?;
        text.push('\n');
        std::fs::write(path, text).with_context(|| format!("writing --summary {path}"))?;
    }
    Ok(RunOutcome {
        exit: exit.unwrap_or(1),
        errors,
        unrun,
        attested: outcomes
            .into_iter()
            .filter(|o| o.attested)
            .map(|o| AttestedUnit {
                test_id: o.test_id,
                project: o.project.unwrap_or_default(),
            })
            .collect(),
    })
}

/// The units [`Selection::Units`] names, as indexes into `files`. A test id
/// the project does not list is an error: the caller planned to run it, and
/// it must not silently go unrun.
fn select_units(
    ctx: &Ctx,
    units: &BTreeMap<usize, Option<BTreeSet<String>>>,
    files: &[TestFile],
) -> Result<BTreeSet<usize>> {
    let mut out = BTreeSet::new();
    for (&pi, ids) in units {
        let Some(project) = ctx.projects.get(pi) else {
            bail!("no project #{pi} in the configuration");
        };
        let mine = files.iter().enumerate().filter(|(_, f)| f.project == pi);
        match ids {
            None => out.extend(mine.map(|(i, _)| i)),
            Some(ids) => {
                let hits: BTreeMap<&str, usize> =
                    mine.map(|(i, f)| (f.test_id.as_str(), i)).collect();
                for id in ids {
                    match hits.get(id.as_str()) {
                        Some(&i) => {
                            out.insert(i);
                        }
                        None => bail!(
                            "{id} is not a test unit of {} (not listed by the test runner)",
                            project.label()
                        ),
                    }
                }
            }
        }
    }
    Ok(out)
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
        t.push("process:system".into());
        t.push("process:system".into());
        let refs: Vec<&String> = t.iter().collect();
        assert_eq!(
            summarize_taints(&refs),
            r#"native:FFI ffi_lib(["vips.42"]) (+300 more native:FFI), process:system (+1 more process:system), process:backtick"#
        );
        // Every reason is listed (no cap), most frequent first.
        let mut many: Vec<String> = (0..20).map(|i| format!("cat{i}:x {i}")).collect();
        many.push("cat19:x again".into());
        let refs: Vec<&String> = many.iter().collect();
        let s = summarize_taints(&refs);
        assert!(
            s.starts_with("cat19:x 19 (+1 more cat19:x), cat0:x 0, "),
            "{s}"
        );
        for i in 0..19 {
            assert!(s.contains(&format!("cat{i}:x {i}")), "{s}");
        }
    }

    #[test]
    fn taint_and_refusal_keys_are_stable_categories() {
        for (t, k) in [
            (
                r#"native:FFI attach_function([:vips_f0, [:pointer]])"#,
                "native:FFI",
            ),
            (r#"native:FFI::DynamicLibrary.open("x")"#, "native:FFI"),
            (
                "native:Fiddle::Function (C code called through Fiddle)",
                "native:Fiddle",
            ),
            ("native:libxml2:XSLT (xsl:include)", "native:libxml2"),
            ("cargo:process: Command::new in src/lib.rs", "cargo:process"),
            ("go:source: a.go uses Environ", "go:source"),
            ("go:net: net/http in the closure", "go:net"),
            (
                "vci:not-hooked:ffi (loaded where vci could not hook it)",
                "vci:not-hooked",
            ),
            (
                "vci:process-exit:2 (the process exited 2)",
                "vci:process-exit",
            ),
            (
                "external-without-version:/abs/x.js",
                "external-without-version",
            ),
            ("process:backtick", "process:backtick"),
            (
                "ruby:read-outside-bundle:stat /x (under a gem directory)",
                "ruby:read-outside-bundle",
            ),
            (
                "pytest:random-order(pytest-randomly)",
                "pytest:random-order",
            ),
            ("fs.readdir.recursive", "fs.readdir.recursive"),
            ("cargo: cannot list /x", "cargo"),
            ("exec: /bin/sh", "exec"),
        ] {
            assert_eq!(taint_key(t), k, "{t}");
        }
        for (m, k) in [
            (
                "input outside the repository: /etc/hosts",
                "input outside the repository",
            ),
            ("result failed (1 failed of 3)", "result failed"),
            (
                "result passed (0 failed, 1 skipped or xfailed of 2; a skipped test did not run)",
                "result has skipped tests",
            ),
            (
                "wrote inside the repository: out.txt",
                "wrote inside the repository",
            ),
            (
                "collector root /x is not the project dir",
                "collector root is not the project dir",
            ),
            (
                "its source refers to /x, outside the repository (seen)",
                "source refers to a path that is not an input",
            ),
            (
                "the collector produced no output for it",
                "the collector produced no output for it",
            ),
            (
                "foo is built from a local directory or file (uv.lock)",
                "external built from a local directory",
            ),
        ] {
            assert_eq!(refusal_key(m), k, "{m}");
        }
    }

    #[test]
    fn summary_lists_every_unit_and_counts_files_per_reason() {
        let unit = |id: &str, attested: bool, reasons: &[&str]| UnitOutcome {
            test_id: id.into(),
            project: None,
            adapter: "rails",
            attested,
            reasons: reasons.iter().map(|r| (*r).to_owned()).collect(),
            detail: (!attested).then(|| "tainted: ...".to_owned()),
            taints: vec![],
        };
        let outcomes = [
            unit("a", true, &[]),
            unit("b", false, &["native:FFI", "process:system"]),
            unit("c", false, &["native:FFI"]),
            unit("d", false, &["result failed"]),
        ];
        assert_eq!(
            reason_counts(&outcomes),
            [
                ("native:FFI".to_owned(), 2),
                ("process:system".to_owned(), 1),
                ("result failed".to_owned(), 1)
            ]
        );
        let v = summary_json(&outcomes);
        assert_eq!(v["attested"], 1);
        assert_eq!(v["notAttested"], 3);
        assert_eq!(v["units"].as_array().unwrap().len(), 4);
        assert_eq!(v["units"][1]["reasons"][1], "process:system");
        assert_eq!(v["reasons"][0]["reason"], "native:FFI");
        assert_eq!(v["reasons"][0]["files"], 2);
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
