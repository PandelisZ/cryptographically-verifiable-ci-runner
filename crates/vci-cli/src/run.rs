//! `vci run`: run tests with collection on, then sign and store an
//! attestation for every test file that is provably attestable.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use vci_adapter::Observed;
use vci_attest::keyless::KeylessSigner;
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
    /// Sign keylessly with the job's OIDC token, with this Sigstore
    /// instance (`--oidc[=github|public-good]`).
    pub oidc: Option<String>,
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
    /// Attested units: the taints a policy waived (the attestation's
    /// `waived`).
    waived: Vec<String>,
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
            waived: vec![],
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
                "waived": o.waived,
            }))
            .collect::<Vec<_>>(),
    })
}

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Env vars hashed into every test file's global manifest, per adapter.
pub(crate) fn global_env_keys(adapter: &str) -> Vec<String> {
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
    global_manifest_in(&Checkout::direct(&ctx.root), project, child, test_abs)
}

/// [`global_manifest`], reading the checkout through `checkout`.
fn global_manifest_in(
    checkout: &Checkout<'_>,
    project: &Project,
    child: &ChildEnvMap,
    test_abs: &Utf8Path,
) -> Result<InputManifest> {
    let obs = global::observations(checkout.root, project.adapter.as_ref(), test_abs)?;
    let m = checkout.capture(
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
    observations_in(&Checkout::direct(root), o, adapter, tsconfig)
}

/// [`observations_for`], reading the checkout through `checkout`.
fn observations_in(
    checkout: &Checkout<'_>,
    o: &Observed,
    adapter: &str,
    tsconfig: bool,
) -> Result<Vec<(RepoPath, Observation)>, String> {
    let root = checkout.root;
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
    let ignored = ignored_children(checkout, &out);
    out.extend(ignored);
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

/// The paths of `o`'s observations (reads, modules, probes, listings, stats)
/// outside the repository `root`, sorted and once each.
fn outside_repository<'a>(root: &Utf8Path, o: &'a Observed) -> BTreeSet<&'a Utf8PathBuf> {
    [
        &o.modules,
        &o.reads,
        &o.probes,
        &o.readdirs,
        &o.stats,
        &o.excluded,
    ]
    .into_iter()
    .flatten()
    .filter(|p| RepoPath::from_abs(root, p).is_err())
    .collect()
}

/// `o` without the observations of `paths` and of everything under them
/// (waived reads outside the repository, waived writes).
fn without_paths(o: &Observed, paths: &[Utf8PathBuf]) -> Observed {
    let mut o = o.clone();
    let keep = |p: &Utf8PathBuf| !paths.iter().any(|d| p.starts_with(d));
    for set in [
        &mut o.modules,
        &mut o.reads,
        &mut o.probes,
        &mut o.readdirs,
        &mut o.stats,
        &mut o.excluded,
    ] {
        set.retain(keep);
    }
    o
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
    /// The predicate to sign: the manifest by reference (`manifestRef`).
    predicate: VciPredicate,
    /// The input manifest it references, stored on its own.
    manifest: InputManifest,
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

/// Warnings for attested directory listings that contain [`CHECKOUT_JUNK`]
/// git does not ignore (what it ignores is left out of the listing since
/// 2.0.3): the listing will differ in a fresh checkout, so the file will run
/// there (never a false skip, but a lost skip worth knowing about).
fn junk_in_listings(checkout: &Checkout<'_>, m: &InputManifest) -> Vec<String> {
    let mut out = Vec::new();
    for e in &m.entries {
        if e.kind != vci_core::EntryKind::DirListing {
            continue;
        }
        let Some(names) = checkout.child_names(&e.path) else {
            continue;
        };
        let junk: Vec<String> = names
            .iter()
            .filter(|n| CHECKOUT_JUNK.contains(&n.as_str()))
            .cloned()
            .collect();
        let paths: Vec<String> = junk
            .iter()
            .map(|n| {
                if e.path.is_root() {
                    n.clone()
                } else {
                    format!("{}/{n}", e.path.as_str())
                }
            })
            .collect();
        let ignored = checkout.git_ignored(&paths);
        let junk: Vec<String> = junk
            .into_iter()
            .zip(paths)
            .filter(|(_, p)| !ignored.contains(p))
            .map(|(n, _)| n)
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

/// A read outside the repository (not an external, not a path the
/// collectors exempt): `outside-repository:<absolute path>`, key
/// `outside-repository`. It refuses the unit (the file cannot be an input)
/// unless `policy.ignore_taints` waives it; then the path is not hashed, only
/// recorded in the attestation's `waived`.
pub const OUTSIDE_REPOSITORY_TAINT: &str = "outside-repository:";
/// Paths the unit created, changed or deleted inside the repository:
/// `wrote-inside-repository: <path>, <path>` (repository-relative), key
/// `wrote-inside-repository`. Waived, the written paths are neither inputs
/// nor a refusal.
pub const WROTE_INSIDE_REPOSITORY_TAINT: &str = "wrote-inside-repository: ";
/// A passing result with skipped (or xfailed, or todo) tests:
/// `result:skipped:<skipped> of <tests>`, key `result:skipped`. A failed
/// result is never a taint.
pub const RESULT_SKIPPED_TAINT: &str = "result:skipped:";
/// A passing run in which no test ran (every test filtered out, as a
/// benchmark file gated by an environment variable): `result:no-tests`,
/// waivable; a run with tests that were filtered out is not.
pub const RESULT_NO_TESTS_TAINT: &str = "result:no-tests";

/// Directories inside `node_modules` that tools write caches to while tests
/// run (Vite's dependency optimizer, `.vite-temp` for bundled configs, the
/// `.cache` convention of babel-loader, eslint and others): writes there are
/// not outputs of the test, like Rails' log/ and tmp/.
const NODE_MODULES_CACHE_DIRS: &[&str] = &[".vite", ".vite-temp", ".cache"];

/// Is the repository-relative path `rel` (a write) in one of
/// [`NODE_MODULES_CACHE_DIRS`] of any `node_modules` directory (the
/// directory itself included)?
fn is_tool_cache_write(rel: &str) -> bool {
    let comps: Vec<&str> = rel.split('/').collect();
    comps
        .windows(2)
        .any(|w| w[0] == "node_modules" && NODE_MODULES_CACHE_DIRS.contains(&w[1]))
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
    // The refusals `policy.ignore_taints` can waive are keyed by their taint
    // key, the pattern that waives them.
    if msg.starts_with("input outside the repository: ") {
        return taint_key(OUTSIDE_REPOSITORY_TAINT);
    }
    if msg.starts_with("wrote inside the repository: ") {
        return taint_key(WROTE_INSIDE_REPOSITORY_TAINT);
    }
    if msg.starts_with("result passed (0 failed, ") && msg.contains(" skipped or xfailed of ") {
        return taint_key(RESULT_SKIPPED_TAINT);
    }
    if msg.starts_with("result no-tests (") {
        return RESULT_NO_TESTS_TAINT.to_owned();
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

/// The taints of `o` a policy waives, and those that refuse it: `(waived,
/// refusing)`. Waived are those `policy.ignore_taints` matches (by
/// [`taint_key`]), Go's `go:net:` under `policy.go_allow_net`, and Cargo's
/// `cargo:undeclared-reads` when the unit declares `[[inputs]]`.
fn split_waived<'a>(
    project: &Project,
    declared: &[String],
    o: &'a Observed,
) -> (Vec<&'a String>, Vec<&'a String>) {
    split_waived_taints(&project.policy, project.adapter.name(), declared, &o.taints)
}

fn split_waived_taints<'a>(
    policy: &crate::config::Policy,
    adapter: &str,
    declared: &[String],
    taints: &'a [String],
) -> (Vec<&'a String>, Vec<&'a String>) {
    taints.iter().partition(|t| {
        (adapter == "cargo"
            && !declared.is_empty()
            && t.starts_with(vci_adapter::CARGO_UNDECLARED_TAINT))
            || policy.taint_waiver(adapter, t).is_some()
    })
}

/// `process:system, +2` for the `attested` line: the most frequent waived
/// reason key and the number of other keys.
fn waived_note(waived: &[String]) -> String {
    let refs: Vec<&String> = waived.iter().collect();
    let groups = group_taints(&refs);
    match groups.split_first() {
        None => String::new(),
        Some((first, [])) => first.0.clone(),
        Some((first, rest)) => format!("{}, +{}", first.0, rest.len()),
    }
}

/// What [`run_units`] decided for one unit, before storing it: made for
/// several units at once, reported and stored in their order.
enum Verdict {
    /// Not attested: the refusal line's text, the reason keys, the
    /// refusing taints.
    Refused {
        reason: String,
        reasons: Vec<String>,
        taints: Vec<String>,
    },
    /// Attestable: the warnings to print first (whole lines), and the signed
    /// envelope to store, or why it could not be signed.
    Attestable {
        a: Box<Attestable>,
        warnings: Vec<String>,
        signed: Result<Vec<u8>>,
        /// The same signer's stored attestations of the unit it supersedes
        /// (found in parallel; removed, one unit at a time, once it is
        /// stored).
        doomed: Vec<vci_git::StoredEnvelope>,
    },
}

/// How many units [`run_units`] checks and signs at once after their tests
/// ran: `$VCI_JOBS`, else the number of CPUs. Each mostly hashes inputs and
/// waits for `ssh-keygen` or the Sigstore services; the store is written one
/// unit at a time.
fn check_jobs() -> usize {
    std::env::var("VCI_JOBS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
}

/// `work` on every item, `jobs` items at a time (on threads of their own),
/// and `sink` (on the calling thread) on each result in the items' order, as
/// soon as it and every result before it are ready. One job: one item after
/// the other, each sunk before the next is worked on.
fn in_order<T: Sync, R: Send>(
    items: &[T],
    jobs: usize,
    work: impl Fn(&T) -> R + Sync,
    mut sink: impl FnMut(usize, R),
) {
    if jobs <= 1 || items.len() <= 1 {
        for (i, t) in items.iter().enumerate() {
            sink(i, work(t));
        }
        return;
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        let (tx, rx) = std::sync::mpsc::channel();
        for _ in 0..jobs.min(items.len()) {
            let (tx, next, work) = (tx.clone(), &next, &work);
            s.spawn(move || {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(t) = items.get(i) else { break };
                    if tx.send((i, work(t))).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);
        let mut ready = BTreeMap::new();
        let mut due = 0;
        for (i, r) in rx {
            ready.insert(i, r);
            while let Some(r) = ready.remove(&due) {
                sink(due, r);
                due += 1;
            }
        }
    });
}

/// The warnings about an attestable unit's inputs (whole lines): listings
/// with checkout junk, `CI` taken from the machine, inputs git ignores.
fn attested_warnings(
    checkout: &Checkout<'_>,
    project: &Project,
    label: &str,
    a: &Attestable,
) -> Vec<String> {
    let mut out: Vec<String> = junk_in_listings(checkout, &a.manifest)
        .into_iter()
        .map(|w| format!("vci: warning: {label}: {w}"))
        .collect();
    // Stripped (absent on both sides) or set by vci, CI is the same
    // everywhere; taken from the machine, it is not.
    if a.manifest.env.iter().any(|e| e.key == "CI")
        && project.project_env().classify("CI") == crate::envpolicy::EnvClass::Hash
    {
        out.push(format!(
            "vci: warning: {label}: it reads CI, which vci.toml hashes and CI runners set (to \"true\"): unless it had that value here, this attestation will not match on a runner (set it instead: [env] set = {{ CI = \"true\" }}){}",
            if project.adapter.name() == "rails" {
                "; Rails' generated config/environments/test.rb reads it (config.eager_load = ENV[\"CI\"].present?)"
            } else {
                ""
            }
        ));
    }
    if matches!(project.adapter.name(), "cargo" | "rails" | "node-test") {
        let ignored = ignored_inputs(checkout, &a.manifest);
        if !ignored.is_empty() {
            let why = if project.adapter.name() == "cargo" {
                "every file in a package directory is an input"
            } else {
                "the test read them; delete them before attesting if they are leftovers"
            };
            out.push(format!(
                "vci: warning: {label}: inputs ignored by git (a fresh checkout, e.g. in CI, will not have them, so this attestation will not match there; {why}): {}{}",
                ignored
                    .iter()
                    .take(10)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                if ignored.len() > 10 { ", ..." } else { "" }
            ));
            if project.adapter.name() == "rails"
                && let Some(key) = ignored.iter().find(|p| is_rails_key_file(p))
            {
                out.push(format!(
                    "vci: warning: {label}: it read {key}, Rails' credentials key (git-ignored, so never in CI): in an app generated with credentials, Active Record reads it at boot, so no test that boots Rails is skipped in CI. Give the test environment its own credentials with a committed key (`bin/rails credentials:edit --environment test`, then commit config/credentials/test.key and test.yml.enc), or remove config/master.key and the credentials file if the tests need none, or declare RAILS_MASTER_KEY in vci.toml and set it to the same value here and in CI"
                ));
            }
        }
    }
    out
}

/// Sign the statement of an attestable unit: the envelope bytes to store.
fn sign_predicate(key: &Signer<'_>, p: &VciPredicate) -> Result<Vec<u8>> {
    let value = serde_json::to_value(p)?;
    let mut digest = BTreeMap::new();
    digest.insert("blake3".to_owned(), p.core.input_root.clone());
    let stmt = Statement::new(
        vec![Subject {
            name: p.core.test_id.clone(),
            digest,
        }],
        PREDICATE_TYPE,
        value,
    );
    key.sign(&stmt)
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
    checkout: &Checkout<'_>,
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
    // `policy.ignore_taints` (and Go's `policy.go_allow_net`, which is
    // `ignore_taints = ["go:net"]`) waives matching taints (recorded in the
    // attestation, which is then only accepted while the base policy agrees).
    // Cargo: declaring inputs for the unit (`[[inputs]]`) waives the
    // "may read outside its package" refusal (the declaration is recorded
    // and must still be the base config's).
    let declared = project.extra_inputs(&file.project_rel);
    let (waived, taints) = split_waived(project, &declared, o);
    if !taints.is_empty() {
        return Err(format!("tainted: {}", summarize_taints(&taints)));
    }
    let mut waived: Vec<String> = waived.into_iter().cloned().collect();
    // vci's own refusals that are taints too (`outside-repository`,
    // `wrote-inside-repository`, `result:skipped`): waived by the same
    // policy, otherwise the refusal they always were.
    let waives = |taint: &str| project.policy.taint_waiver(adapter.name(), taint).is_some();
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
        let ignored: BTreeSet<String> = checkout.git_ignored(&candidates).into_iter().collect();
        written.retain(|w| !ignored.contains(w));
    }
    // Tool caches under node_modules (Vite's dependency optimizer) are not
    // outputs of the test.
    written.retain(|w| !is_tool_cache_write(w));
    // Waived writes: neither inputs nor a refusal.
    let mut not_inputs: Vec<Utf8PathBuf> = Vec::new();
    if !written.is_empty() {
        let taint = format!("{WROTE_INSIDE_REPOSITORY_TAINT}{}", written.join(", "));
        if !waives(&taint) {
            return Err(format!(
                "wrote inside the repository: {}",
                written.join(", ")
            ));
        }
        waived.push(taint);
        not_inputs.extend(written.iter().map(|w| ctx.root.join(w)));
    }
    let result = o.result.clone().ok_or("no result")?;
    // No test ran: refused unless `result:no-tests` is waived (a file whose
    // tests are all gated by an environment variable); tests filtered out
    // of a run never are.
    let mut no_tests_waived = false;
    if !result.is_pass() && matches!(result.state.as_str(), "no-tests" | "filtered") {
        if result.state == "no-tests" && result.failed == 0 && waives(RESULT_NO_TESTS_TAINT) {
            waived.push(RESULT_NO_TESTS_TAINT.to_owned());
            no_tests_waived = true;
        } else {
            return Err(format!(
                "result {} ({} tests; no test ran or some were filtered out, so the run cannot vouch for the unit)",
                result.state, result.tests
            ));
        }
    }
    if result.state == "no-assertions" {
        return Err(format!(
            "result no-assertions ({} tests; a test that makes no assertion vouches for nothing)",
            result.tests
        ));
    }
    // Passed, with skipped tests: refused unless `result:skipped` is waived
    // (a failed result never is).
    let mut skips_waived = false;
    if !result.is_pass() && result.state == "passed" && result.failed == 0 && result.skipped > 0 {
        let taint = format!(
            "{RESULT_SKIPPED_TAINT}{} of {}",
            result.skipped, result.tests
        );
        if waives(&taint) {
            waived.push(taint);
            skips_waived = true;
        }
    }
    if !result.is_pass() && !skips_waived && !no_tests_waived {
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
    // Reads outside the repository: refused, unless `outside-repository` is
    // waived (then they are not hashed, only recorded in `waived`).
    for p in outside_repository(&ctx.root, o) {
        let taint = format!("{OUTSIDE_REPOSITORY_TAINT}{p}");
        if !waives(&taint) {
            return Err(format!("input outside the repository: {p}"));
        }
        not_inputs.push(p.to_owned());
        waived.push(taint);
    }
    let pruned;
    let o = if not_inputs.is_empty() {
        o
    } else {
        pruned = without_paths(o, &not_inputs);
        &pruned
    };
    let mut obs = observations_in(checkout, o, adapter.name(), adapter.tsconfig_is_input())?;
    obs.extend(expand_extra_inputs(
        &ctx.root,
        &project.dir,
        &declared,
        scratch,
    )?);
    let mut platform_specific: Vec<String> = Vec::new();
    for p in &o.platform_files {
        let rp = RepoPath::from_abs(&ctx.root, p)
            .map_err(|_| format!("platform-specific file outside the repository: {p}"))?;
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
    let manifest = checkout
        .capture(&obs, externals, &keys, lookup(child))
        .map_err(|e| format!("capturing inputs: {e}"))?;
    manifest
        .check_case_collisions()
        .map_err(|e| format!("inputs: {e}"))?;
    // Paths the unit's source names outside its package directories must be
    // recorded inputs (declared with `[[inputs]]`), unless the policy waives
    // `cargo:undeclared-reads` (the path is then recorded as waived).
    for (p, seen) in &o.path_refs {
        let why = match RepoPath::from_abs(&ctx.root, p) {
            Err(_) => format!("its source refers to {p}, outside the repository ({seen})"),
            Ok(rp) if !covered(&ctx.root, &manifest, &rp) => format!(
                "its source refers to {} ({seen}), which is not an input; declare it in vci.toml ([[inputs]] match = [{:?}], extra = [...])",
                rp.as_str(),
                file.project_rel
            ),
            Ok(_) => continue,
        };
        let taint = format!("{}: {why}", vci_adapter::CARGO_UNDECLARED_TAINT);
        if !waives(&taint) {
            return Err(why);
        }
        waived.push(taint);
    }
    let gm = global_manifest_in(checkout, project, child, &file.abs)
        .map_err(|e| format!("global inputs: {e:#}"))?;
    match pre_global.get(file.test_id.as_str()) {
        Some(Ok(root)) if *root == gm.root() => {}
        Some(Ok(_)) => return Err("global inputs changed during the run".into()),
        Some(Err(e)) => return Err(format!("global inputs before the run: {e}")),
        None => return Err("no pre-run global snapshot".into()),
    }
    // What the manifest leaves out of its listings, plus what git ignores
    // in them now: a cache a test wrote into a listed directory during the
    // run (`__pycache__`) is not a change to the listing (since 2.0.3).
    let mut excluded = manifest.excluded_children();
    for p in ignored_listing_children(checkout, &manifest) {
        if let (Some(parent), Some(name)) = (p.parent(), p.components().last()) {
            excluded.entry(parent).or_default().insert(name.to_owned());
        }
    }
    for e in &manifest.entries {
        pre_stat
            .unchanged_excluding(e, excluded.get(&e.path))
            .map_err(|r| r.to_string())?;
    }
    for e in &gm.entries {
        pre_stat.unchanged(e).map_err(|r| r.to_string())?;
    }
    let core = Predicate {
        tool_version: TOOL_VERSION.to_owned(),
        adapter: adapter.name().to_owned(),
        test_id: file.test_id.as_str().to_owned(),
        argv: adapter.canonical_argv(&project.rel, &file.project_rel),
        repo_id: base.repo_id.clone(),
        commit: base.commit.clone(),
        tree_dirty: base.dirty,
        tree: base.tree.clone(),
        toolchain: toolchain_for(adapter.name(), versions),
        global_input_root: gm.root(),
        input_root: manifest.root(),
        manifest: None,
        manifest_ref: Some(manifest.root()),
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
            env_set: fenv.set.keys().cloned().collect(),
        },
        manifest,
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

/// The git-ignored children of every directory `observed` lists (a `ReadDir`,
/// or a `Read` of a directory), as `Exclude` observations: build outputs,
/// caches and editor files (`dist/`, `node_modules/`, `__pycache__/`,
/// `.DS_Store`) that a fresh checkout does not have and every machine has
/// differently, so that a listing records what the repository holds and an
/// attestation made on one machine verifies on another (since 2.0.3). A
/// child that is itself observed stays an input of its own.
pub(crate) fn ignored_children(
    checkout: &Checkout<'_>,
    observed: &[(RepoPath, Observation)],
) -> Vec<(RepoPath, Observation)> {
    let seen: BTreeSet<&str> = observed.iter().map(|(p, _)| p.as_str()).collect();
    let mut candidates: Vec<String> = Vec::new();
    for (p, o) in observed {
        if !matches!(o, Observation::ReadDir | Observation::Read) {
            continue;
        }
        let Some(names) = checkout.child_names(p) else {
            continue;
        };
        for name in names.iter() {
            let child = if p.is_root() {
                name.clone()
            } else {
                format!("{}/{name}", p.as_str())
            };
            if !seen.contains(child.as_str()) {
                candidates.push(child);
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    checkout
        .git_ignored(&candidates)
        .into_iter()
        .filter_map(|c| RepoPath::new(&c).ok())
        .map(|p| (p, Observation::Exclude))
        .collect()
}

/// The git-ignored children, present now, of every directory `m` records a
/// listing of, minus `m`'s own entries: what a verification leaves out of
/// the listings it rehashes (see [`ignored_children`]).
pub(crate) fn ignored_listing_children(
    checkout: &Checkout<'_>,
    m: &InputManifest,
) -> Vec<RepoPath> {
    let seen: BTreeSet<&str> = m.entries.iter().map(|e| e.path.as_str()).collect();
    let mut candidates: Vec<String> = Vec::new();
    for e in &m.entries {
        if e.kind != vci_core::EntryKind::DirListing {
            continue;
        }
        let Some(names) = checkout.child_names(&e.path) else {
            continue;
        };
        for name in names.iter() {
            let child = if e.path.is_root() {
                name.clone()
            } else {
                format!("{}/{name}", e.path.as_str())
            };
            if !seen.contains(child.as_str()) {
                candidates.push(child);
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    checkout
        .git_ignored(&candidates)
        .into_iter()
        .filter_map(|c| RepoPath::new(&c).ok())
        .collect()
}

fn ignored_inputs(checkout: &Checkout<'_>, m: &InputManifest) -> Vec<String> {
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
    checkout.git_ignored(&paths)
}

/// The repo-relative `paths` git ignores (`git check-ignore`); any error
/// means none (so nothing is treated as ignored).
pub(crate) fn git_ignored(root: &Utf8Path, paths: &[String]) -> Vec<String> {
    git_check_ignore(root, paths).0
}

/// [`git_ignored`], and whether git answered (exited 0 or 1: some or none
/// ignored); an answer git did not give is not one to keep.
pub(crate) fn git_check_ignore(root: &Utf8Path, paths: &[String]) -> (Vec<String>, bool) {
    use std::io::Write as _;
    if paths.is_empty() {
        return (vec![], true);
    }
    let child = std::process::Command::new("git")
        .args(["-C", root.as_str(), "check-ignore", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        return (vec![], false);
    };
    if let Some(mut i) = child.stdin.take() {
        let _ = i.write_all(paths.join("\n").as_bytes());
        let _ = i.write_all(b"\n");
    }
    let Ok(out) = child.wait_with_output() else {
        return (vec![], false);
    };
    let lines = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    (lines, matches!(out.status.code(), Some(0 | 1)))
}

/// How [`check_one`] reads the checkout: directly, or (once a project's
/// tests have finished, when the tree no longer changes) through caches
/// shared by every unit of the run, so that a path's contents, a
/// directory's children and git's answer about a path are read once
/// however many units name them. Nothing invalidates the caches: each unit
/// still compares its entries with the snapshot taken before the run
/// ([`TreeStat`]) after its manifest is captured, so a value read once is
/// vouched for by every unit that uses it, as one read per unit was.
pub(crate) struct Checkout<'a> {
    root: &'a Utf8Path,
    cache: Option<Caches>,
}

struct Caches {
    files: vci_core::CheckoutCache,
    /// `read_dir` of a directory (followed if a symlink, as [`ignored_children`]
    /// lists it): the UTF-8 names, `None` when it cannot be listed.
    children: std::sync::Mutex<std::collections::HashMap<Utf8PathBuf, Option<Arc<Vec<String>>>>>,
    /// `git check-ignore` per repo-relative path.
    ignored: std::sync::Mutex<std::collections::HashMap<String, bool>>,
}

fn locked<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl<'a> Checkout<'a> {
    /// Every read goes to the checkout (and to git).
    pub(crate) fn direct(root: &'a Utf8Path) -> Self {
        Checkout { root, cache: None }
    }

    /// Every path read once, for a checkout that does not change while this
    /// is used.
    pub(crate) fn cached(root: &'a Utf8Path) -> Self {
        Checkout {
            root,
            cache: Some(Caches {
                files: vci_core::CheckoutCache::new(root),
                children: Default::default(),
                ignored: Default::default(),
            }),
        }
    }

    /// [`git_ignored`]: the `paths` git ignores, in their order.
    pub(crate) fn git_ignored(&self, paths: &[String]) -> Vec<String> {
        let Some(c) = &self.cache else {
            return git_ignored(self.root, paths);
        };
        let mut ask: Vec<String> = {
            let known = locked(&c.ignored);
            paths
                .iter()
                .filter(|p| !known.contains_key(p.as_str()))
                .cloned()
                .collect()
        };
        ask.sort();
        ask.dedup();
        let (found, answered) = git_check_ignore(self.root, &ask);
        if !answered {
            // git stopped before answering about every path (it exits 128 on
            // a path inside a submodule or beyond a symbolic link, after
            // printing what it found before it): nothing is kept, and the
            // answer is the one git gives for `paths` alone, as before 2.1,
            // whatever other units asked first.
            return if ask == paths {
                found
            } else {
                git_ignored(self.root, paths)
            };
        }
        let found: BTreeSet<&str> = found.iter().map(String::as_str).collect();
        let mut known = locked(&c.ignored);
        for p in &ask {
            known.insert(p.clone(), found.contains(p.as_str()));
        }
        paths
            .iter()
            .filter(|p| known.get(p.as_str()).copied().unwrap_or(false))
            .cloned()
            .collect()
    }

    /// The UTF-8 names in the directory `p` (`read_dir`, which follows a
    /// symlink); `None` when it cannot be listed.
    fn child_names(&self, p: &RepoPath) -> Option<Arc<Vec<String>>> {
        let abs = p.to_abs(self.root);
        let read = |abs: &Utf8Path| {
            std::fs::read_dir(abs).ok().map(|rd| {
                Arc::new(
                    rd.flatten()
                        .filter_map(|e| e.file_name().into_string().ok())
                        .collect::<Vec<_>>(),
                )
            })
        };
        let Some(c) = &self.cache else {
            return read(&abs);
        };
        if let Some(n) = locked(&c.children).get(&abs) {
            return n.clone();
        }
        let n = read(&abs);
        locked(&c.children).insert(abs, n.clone());
        n
    }

    /// [`InputManifest::capture_with_env`] (through the cache when there is
    /// one).
    fn capture<F>(
        &self,
        observed: &[(RepoPath, Observation)],
        externals: Vec<External>,
        env_keys: &[String],
        env: F,
    ) -> Result<InputManifest, vci_core::ManifestError>
    where
        F: Fn(&str) -> Option<std::ffi::OsString> + Sync,
    {
        match &self.cache {
            None => InputManifest::capture_with_env(self.root, observed, externals, env_keys, env),
            Some(c) => InputManifest::capture_cached(&c.files, observed, externals, env_keys, env),
        }
    }
}

struct PredicateBase {
    repo_id: String,
    commit: String,
    dirty: bool,
    /// HEAD's tree, when the working tree is clean.
    tree: Option<String>,
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

/// `vci run <units>` when some projects that could hold a requested unit
/// (`unlisted`: label, listing error) could not be listed: when every
/// requested unit resolved (`resolved`) to a unit of a project that was
/// listed, the run goes on without the others (one warning each); when one
/// did not, the error also names the listing failures, which are likely
/// why.
fn settle_unlisted(
    resolved: Result<BTreeSet<usize>>,
    unlisted: &[(String, anyhow::Error)],
) -> Result<(BTreeSet<usize>, Vec<String>)> {
    match resolved {
        Ok(selected) => {
            let warnings = unlisted
                .iter()
                .map(|(label, e)| {
                    format!(
                        "listing the test files of {label} failed: {e:#}; none of the requested units is in it"
                    )
                })
                .collect();
            Ok((selected, warnings))
        }
        Err(e) if unlisted.is_empty() => Err(e),
        Err(e) => {
            let why: Vec<String> = unlisted
                .iter()
                .map(|(label, e)| format!("listing the test files of {label} failed: {e:#}"))
                .collect();
            bail!(
                "{e:#} (it may be in a project that could not be listed: {})",
                why.join("; ")
            )
        }
    }
}

/// How [`run_units`] signs.
pub enum Signing<'a> {
    /// An SSH key: `--key`, else discovered ([`keys::discover`]).
    Key(Option<&'a Utf8Path>),
    /// Keyless, with the job's OIDC token (`--oidc`).
    Oidc(&'a KeylessSigner),
}

/// A resolved signer.
enum Signer<'a> {
    Ssh(keys::SigningKey),
    Keyless(&'a KeylessSigner),
}

impl Signer<'_> {
    /// The signer id in store keys.
    fn signer_id(&self) -> String {
        match self {
            Signer::Ssh(k) => k.signer_id(),
            Signer::Keyless(k) => k.signer_id(),
        }
    }

    /// Sign `stmt`; the bytes to store (the envelope JSON, plus the
    /// Sigstore bundle's material for a keyless signature).
    fn sign(&self, stmt: &Statement) -> Result<Vec<u8>> {
        match self {
            Signer::Ssh(key) => sign_statement(stmt, &key.path)
                .map(|env| env.to_json())
                .with_context(|| format!("signing with {}", key.path)),
            Signer::Keyless(k) => k
                .sign_statement(stmt)
                .map(|(env, m)| vci_attest::keyless::to_stored_json(&env, &m))
                .context("signing keylessly (OIDC)"),
        }
    }
}

/// `--oidc [INSTANCE]`: a keyless signer for the job's identity (fails
/// before anything runs when the job has no OIDC token).
pub fn keyless_signer(instance: &str) -> Result<KeylessSigner> {
    let i = vci_attest::keyless::Instance::named(instance).map_err(anyhow::Error::msg)?;
    let k = KeylessSigner::new(i).context("--oidc")?;
    eprintln!(
        "vci: signing keylessly as {} (Sigstore: {}, {})",
        k.identity().describe(),
        k.instance().fulcio,
        k.instance().tsa
    );
    Ok(k)
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
    for w in config.warnings(crate::config::CONFIG_FILE) {
        eprintln!("vci: warning: {w}");
    }
    let keyless = args.oidc.as_deref().map(keyless_signer).transpose()?;
    let signing = match &keyless {
        Some(k) => Signing::Oidc(k),
        None => Signing::Key(args.key.as_deref()),
    };
    let out = run_units(
        repo,
        root,
        config,
        Selection::Args(args.files),
        signing,
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
    signing: Signing<'_>,
    ttl_arg: &str,
    summary: Option<&Utf8Path>,
) -> Result<RunOutcome> {
    let ttl = parse_duration(ttl_arg).context("--ttl")?;
    let ctx = Ctx::new(repo, root.clone(), config)?;
    let key = match signing {
        Signing::Key(k) => Signer::Ssh(keys::discover(k, &root)?),
        Signing::Oidc(k) => Signer::Keyless(k),
    };
    let signer = key.signer_id();

    let base = PredicateBase {
        repo_id: ctx
            .repo
            .repo_id()
            .context("repo id (needs at least one commit)")?,
        commit: ctx.repo.head_commit()?,
        dirty: ctx.repo.is_dirty()?,
        tree: None,
        issued: now_unix(),
        ttl,
    };
    let base = PredicateBase {
        tree: (!base.dirty).then(|| ctx.repo.head_tree().ok()).flatten(),
        ..base
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
                    })
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
            .collect()
    });
    // `vci run <units>`: projects that could not be listed, settled once the
    // units are resolved (see [`settle_unlisted`]).
    let mut unlisted: Vec<(String, anyhow::Error)> = Vec::new();
    for (i, listed) in listings.into_iter().enumerate() {
        let Some(listed) = listed else { continue };
        let label = ctx.projects[i].label();
        match listed {
            Ok(f) => files.extend(f),
            // `vci ci`: one project that cannot be listed does not stop the
            // others from being attested (it runs without attesting).
            Err(e) if matches!(selection, Selection::Units(_)) => {
                let msg = format!("listing the test files of {label}: {e:#}");
                eprintln!("vci: error: {msg}");
                errors.push(msg);
                unrun.insert(i);
            }
            Err(e) if matches!(&selection, Selection::Args(a) if !a.is_empty()) => {
                unlisted.push((label, e));
            }
            Err(e) => return Err(e.context(format!("listing the test files of {label}"))),
        }
    }
    mark_cross_project_ambiguity(&mut files);
    let selected: BTreeSet<usize> = match &selection {
        Selection::Args(a) if a.is_empty() => (0..files.len()).collect(),
        Selection::Args(a) => {
            let (selected, warnings) = settle_unlisted(resolve_files(a, &files), &unlisted)?;
            for w in warnings {
                eprintln!("vci: warning: {w}");
            }
            selected
        }
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
                "vci: warning: hashed env var {s} looks like a secret; its hash is published in attestations. Put it in [env] ignore instead."
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
        .flat_map(|&pi| {
            ctx.projects[pi]
                .adapter
                .scratch_dirs_with_env(&children[pi].to_child_env())
        })
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
    // [lazy metadata] Supersession below reads these units' stored
    // attestations: fetch the values not fetched yet, in one batch (best
    // effort: one not fetched is kept, never superseded).
    let _ = store.hydrate_units(selected.iter().map(|&i| files[i].test_id.as_str()));
    // What the units took last time (any signer's newest attestation), to
    // hand the runner the longest first.
    let t = std::time::Instant::now();
    let durations = last_durations(&store, selected.iter().map(|&i| files[i].test_id.as_str()));
    crate::plan::timing(
        &format!(
            "read the last duration of {} unit(s) ({} recorded)",
            selected.len(),
            durations.len()
        ),
        t,
    );
    let mut attested = 0;
    let mut refused = 0;
    let mut superseded = 0usize;
    // Supersession's answers per earlier commit, and the input roots of the
    // attestations it deleted.
    let moved_on = std::sync::Mutex::new(BTreeMap::new());
    // The trees every ref's tip has now: an attestation made on one of them
    // is never superseded, whatever its commit (vci 2.1.12).
    let live_trees: BTreeSet<String> = ctx.repo.live_trees().unwrap_or_default();
    let mut dropped_roots = BTreeSet::new();
    let mut outcomes: Vec<UnitOutcome> = Vec::new();
    let mut exit: Option<i32> = Some(0);
    let jobs = check_jobs();
    for &pi in &involved {
        let project = &ctx.projects[pi];
        let child = &children[pi];
        let mine: Vec<&TestFile> = selected
            .iter()
            .map(|&i| &files[i])
            .filter(|f| f.project == pi)
            .collect();
        // Longest first (the runner's parallelism ends sooner); lines,
        // summary and the store keep the listing's order.
        let rels: Vec<String> = longest_first(&mine, |f| f.test_id.as_str(), &durations)
            .iter()
            .map(|f| f.project_rel.clone())
            .collect();
        // The same durations by project-relative path, for the runner.
        let last_ms: BTreeMap<String, u64> = mine
            .iter()
            .filter_map(|f| {
                durations
                    .get(f.test_id.as_str())
                    .map(|d| (f.project_rel.clone(), *d))
            })
            .collect();
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
            let out = project
                .adapter
                .run_collect_timed(&rels, &child.to_child_env(), &last_ms)?;
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
        // Each output's unit and the name it is reported under, in order.
        let units: Vec<(&Observed, Option<&TestFile>, String)> = out
            .files
            .iter()
            .map(|o| {
                let id = project
                    .test_id(&o.test_id)
                    .map(|p| p.as_str().to_owned())
                    .ok();
                let file = id.as_ref().and_then(|id| by_id.get(id.as_str()).copied());
                let label = id.unwrap_or_else(|| o.test_id.clone());
                seen.insert(label.clone());
                (o, file, label)
            })
            .collect();
        // The tests have finished, so the checkout no longer changes: every
        // unit reads it through one cache (see [`Checkout`]).
        let checkout = Checkout::cached(&ctx.root);
        let t_check = std::time::Instant::now();
        // Thread-nanoseconds per part of this phase (`VCI_TIMING=1`).
        let tm_check = std::sync::atomic::AtomicU64::new(0);
        let tm_warn = std::sync::atomic::AtomicU64::new(0);
        let tm_sign = std::sync::atomic::AtomicU64::new(0);
        let tm_store = std::sync::atomic::AtomicU64::new(0);
        let tm_supersede = std::sync::atomic::AtomicU64::new(0);
        let add = |f: &std::sync::atomic::AtomicU64, since: std::time::Instant| {
            f.fetch_add(
                since.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        };
        // Checked and signed `jobs` units at a time; reported and stored in
        // order, one after the other.
        let verdict = |(o, file, label): &(&Observed, Option<&TestFile>, String)| {
            if let Some(why) = &tree_changed {
                return Verdict::Refused {
                    reason: why.clone(),
                    reasons: vec![refusal_key(why)],
                    taints: vec![],
                };
            }
            let filtered;
            let o: &Observed = if collector_dirs.is_empty() {
                o
            } else {
                let mut c = (*o).clone();
                c.drop_collector_paths(&ctx.root, &collector_dirs);
                filtered = c;
                &filtered
            };
            let t = std::time::Instant::now();
            let checked = check_one(
                &ctx,
                project,
                o,
                *file,
                &versions[&pi],
                child,
                &pre_stat,
                &pre_global,
                &base,
                &locks[pi],
                &scratch,
                &checkout,
            );
            add(&tm_check, t);
            match checked {
                Err(reason) => {
                    let (reasons, taints) = match file {
                        Some(f) if reason.starts_with("tainted: ") => {
                            let declared = project.extra_inputs(&f.project_rel);
                            let (_, taints) = split_waived(project, &declared, o);
                            (
                                group_taints(&taints).into_iter().map(|g| g.0).collect(),
                                taints.into_iter().cloned().collect(),
                            )
                        }
                        _ => (vec![refusal_key(&reason)], vec![]),
                    };
                    Verdict::Refused {
                        reason,
                        reasons,
                        taints,
                    }
                }
                Ok(a) => {
                    let t = std::time::Instant::now();
                    let warnings = attested_warnings(&checkout, project, label, &a);
                    add(&tm_warn, t);
                    let t = std::time::Instant::now();
                    let signed = sign_predicate(&key, &a.predicate);
                    add(&tm_sign, t);
                    let t = std::time::Instant::now();
                    let doomed = if signed.is_ok() {
                        superseded_by(
                            &store,
                            &ctx.repo,
                            &a.predicate,
                            &a.manifest,
                            &signer,
                            &moved_on,
                            &live_trees,
                        )
                    } else {
                        Vec::new()
                    };
                    add(&tm_supersede, t);
                    Verdict::Attestable {
                        warnings,
                        signed,
                        a: Box::new(a),
                        doomed,
                    }
                }
            }
        };
        // Every unit's verdict first, in parallel; then the manifest base
        // (the entries all attestable units share, stored once: vci
        // 2.1.8), then each unit stored and reported in order.
        let mut verdicts: Vec<Option<Verdict>> = (0..units.len()).map(|_| None).collect();
        in_order(&units, jobs, verdict, |i, v| verdicts[i] = Some(v));
        let t = std::time::Instant::now();
        let manifest_bases = shared_manifest_bases(&verdicts, &units);
        if !manifest_bases.is_empty() {
            let mut stored_roots = BTreeSet::new();
            for b in manifest_bases.values() {
                if !stored_roots.insert(b.root()) {
                    continue;
                }
                if let Err(e) = store.put_manifest(&b.root(), b.to_compact().as_bytes()) {
                    eprintln!("vci: warning: storing the units' shared input manifest: {e}");
                }
            }
            let sizes: Vec<usize> = manifest_bases.values().map(|b| b.entries.len()).collect();
            crate::plan::timing(
                &format!(
                    "{}: shared input manifests: {} group(s) of units, {} to {} entries each stored once",
                    project.label(),
                    manifest_bases.len(),
                    sizes.iter().min().copied().unwrap_or(0),
                    sizes.iter().max().copied().unwrap_or(0)
                ),
                t,
            );
        }
        for (i, v) in verdicts.into_iter().enumerate() {
            let Some(v) = v else { continue };
            let label = &units[i].2;
            let (a, signed, doomed) = match v {
                Verdict::Refused {
                    reason,
                    reasons,
                    taints,
                } => {
                    refused += 1;
                    eprintln!("vci: not attesting {label}: {reason}");
                    let mut out = UnitOutcome::refused(label, project, reason, reasons);
                    out.taints = taints;
                    outcomes.push(out);
                    continue;
                }
                Verdict::Attestable {
                    a,
                    warnings,
                    signed,
                    doomed,
                } => {
                    for w in &warnings {
                        eprintln!("{w}");
                    }
                    (a, signed, doomed)
                }
            };
            let p = &a.predicate;
            let skey = storage_key(p);
            let stored = signed.and_then(|env| {
                // The manifest first: an attestation is never stored without
                // the manifest it references.
                let t = std::time::Instant::now();
                let compact = match manifest_bases.get(&group_key(units[i].0)) {
                    Some(b) => a.manifest.to_compact_on(b),
                    None => a.manifest.to_compact(),
                };
                store
                    .put_manifest(&p.core.input_root, compact.as_bytes())
                    .context("storing the input manifest")?;
                let hint = crate::util::parse_rfc3339(&p.core.issued_at)
                    .ok()
                    .map(|issued| vci_git::KeyHint {
                        issued,
                        tree: p.core.tree.as_ref().map(|t| t.chars().take(16).collect()),
                    });
                let stored =
                    store.put_hinted(&p.core.test_id, &signer, &skey, hint.as_ref(), &env)?;
                // Never the one just stored (the same storage key: the same
                // inputs, replaced).
                let doomed: Vec<_> = doomed.into_iter().filter(|e| e.key != stored.key).collect();
                superseded +=
                    remove_superseded(&store, &p.core.test_id, doomed, &mut dropped_roots);
                add(&tm_store, t);
                Ok(stored)
            });
            let stored = match stored {
                Ok(s) => s,
                Err(e) => {
                    let msg = format!("{label}: {e:#}");
                    eprintln!("vci: error: not attesting {msg}");
                    errors.push(msg);
                    refused += 1;
                    let why = format!("signing or storing failed: {e:#}");
                    outcomes.push(UnitOutcome::refused(
                        label,
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
                waived: p.waived.clone(),
            });
            let waived = if p.waived.is_empty() {
                String::new()
            } else {
                format!(" (waived: {})", waived_note(&p.waived))
            };
            eprintln!(
                "vci: attested {label}{waived} ({} inputs, root {}) as git-meta {} {}",
                a.manifest.entries.len(),
                &p.core.input_root[..16],
                stored.target,
                stored.key
            );
        }
        crate::plan::timing(
            &format!(
                "check, sign and store {} unit(s) of {} ({jobs} at a time)",
                units.len(),
                project.label()
            ),
            t_check,
        );
        if std::env::var_os("VCI_TIMING").is_some() {
            let g = |f: &std::sync::atomic::AtomicU64| {
                f.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1e9
            };
            eprintln!(
                "vci: timing: {}: thread-seconds: check (capture inputs, tree, taints) {:.1}, warnings {:.1}, sign {:.1}, find superseded {:.1}; store and remove superseded (one at a time) {:.1}",
                project.label(),
                g(&tm_check),
                g(&tm_warn),
                g(&tm_sign),
                g(&tm_supersede),
                g(&tm_store)
            );
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
    if superseded > 0 {
        eprintln!(
            "vci: removed {superseded} superseded attestation(s) (earlier ones of the same units by the same signer and platform, made on a commit this one descends from that no other branch or tag contains, of files the tree no longer has)"
        );
        let orphans = drop_orphan_manifests(&store, &dropped_roots);
        if orphans > 0 {
            eprintln!(
                "vci: removed {orphans} input manifest(s) no attestation references any more"
            );
        }
    }
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

/// The same signer's stored attestations of a unit that storing the new one
/// (`p`, `manifest`) supersedes: made on a commit this line of history has
/// moved on from ([`vci_git::Repo::moved_on`]: `new commit` descends from
/// it and no other branch or tag still contains it, or it was rebased or
/// amended away), with a manifest whose entries differ from the new one's.
/// The signer re-attesting is the newest truth for that line, so the
/// published tree keeps one attestation per unit and signer as commits go
/// by, without a separate `vci prune --superseded`. Kept: one made on the
/// same commit (work in progress: an edit may be reverted), on a commit
/// another ref still contains (`main` under a feature branch: every branch
/// made from it needs it; a sibling branch or pull request), one issued
/// later than this one (another machine with the same key), one for another
/// OS or architecture (a CI matrix sharing a key: platform-specific files
/// differ), one with the same entries (another environment or toolchain on
/// this tree), and one whose payload or manifest cannot be read. Read only
/// (several units at once); [`remove_superseded`] deletes them once the new
/// one is stored. `moved_on` caches git's answer per earlier commit. Kept
/// too (since 2.1.12): one made on a tree some ref's tip still has
/// (`live_trees`): a pull request's merge commit is on no ref once the pull
/// request is squash-merged, yet master's tip has its tree, and master's
/// next run skips with it; another pull request's run must not delete it.
fn superseded_by(
    store: &AttestStore,
    repo: &vci_git::Repo,
    p: &VciPredicate,
    manifest: &InputManifest,
    signer: &str,
    moved_on: &std::sync::Mutex<BTreeMap<String, bool>>,
    live_trees: &BTreeSet<String>,
) -> Vec<vci_git::StoredEnvelope> {
    let issued = crate::util::parse_rfc3339(&p.core.issued_at).ok();
    let tc = &p.core.toolchain;
    let mut entries: Vec<&vci_core::InputEntry> = manifest.entries.iter().collect();
    entries.sort();
    let keep = |e: &vci_git::StoredEnvelope| {
        if e.error.is_some() {
            return true;
        }
        let Some(m) = crate::cmds::envelope_meta(&e.bytes) else {
            return true;
        };
        if m.test_id != p.core.test_id
            || m.commit == p.core.commit
            || m.os != tc.os
            || m.arch != tc.arch
            || issued.is_none_or(|i| m.issued_at > i)
            || m.tree.as_deref().is_some_and(|t| live_trees.contains(t))
        {
            return true;
        }
        let old = match &m.manifest_ref {
            Some(r) => store
                .manifest_decoded(r)
                .ok()
                .flatten()
                .and_then(Result::ok)
                .filter(|o| o.root() == *r),
            None => crate::cmds::envelope_inline_manifest(&e.bytes),
        };
        let Some(old) = old else {
            return true;
        };
        let mut old_entries: Vec<&vci_core::InputEntry> = old.entries.iter().collect();
        old_entries.sort();
        if old_entries == entries {
            return true;
        }
        // Last, as the only check that runs git: one answer per commit
        // (two threads may ask about the same commit at once; same answer).
        let cached = moved_on
            .lock()
            .map(|c| c.get(&m.commit).copied())
            .unwrap_or(None);
        let moved = cached.unwrap_or_else(|| {
            let moved = repo.moved_on(&m.commit, &p.core.commit).unwrap_or(false);
            if let Ok(mut c) = moved_on.lock() {
                c.insert(m.commit.clone(), moved);
            }
            moved
        });
        !moved
    };
    match store.list(Some(&p.core.test_id)) {
        Ok(all) => all
            .into_iter()
            .filter(|e| e.signer == signer && !keep(e))
            .collect(),
        Err(e) => {
            eprintln!(
                "vci: warning: {}: cannot read its stored attestations to supersede them: {e}",
                p.core.test_id
            );
            Vec::new()
        }
    }
}

/// Delete what [`superseded_by`] found, once the new attestation is stored.
/// Failing to delete is only a warning: a kept attestation is verified like
/// any other. Returns how many were deleted, and adds the input roots they
/// referenced to `dropped_roots`.
fn remove_superseded(
    store: &AttestStore,
    test_id: &str,
    doomed: Vec<vci_git::StoredEnvelope>,
    dropped_roots: &mut BTreeSet<String>,
) -> usize {
    if doomed.is_empty() {
        return 0;
    }
    match store.remove_envelopes(doomed) {
        Ok(removed) => {
            for e in &removed {
                if let Some(r) = crate::cmds::envelope_meta(&e.bytes).and_then(|m| m.manifest_ref) {
                    dropped_roots.insert(r);
                }
            }
            removed.len()
        }
        Err(e) => {
            eprintln!("vci: warning: {test_id}: cannot remove superseded attestations: {e}");
            0
        }
    }
}

/// The group a unit's manifest shares a base with: the units whose
/// outputs shared lines (a Rails slot's or boot's), else the run.
fn group_key(o: &Observed) -> String {
    o.shared_group.clone().unwrap_or_default()
}

/// The input manifest bases of a run (vci 2.1.8), by group: for the units
/// of each group (see [`group_key`]) with two or more attestable, signed
/// units, the entries they all have, as one plain manifest (no externals,
/// no env), stored once; each unit's manifest is then stored as the
/// entries it adds (`InputManifest::to_compact_on`). A Rails slot's files
/// share the boot's and the slot's observations, most of each manifest.
/// Units outside any group share the run's, when two or more of them have
/// entries in common.
fn shared_manifest_bases(
    verdicts: &[Option<Verdict>],
    units: &[(&Observed, Option<&TestFile>, String)],
) -> BTreeMap<String, InputManifest> {
    let mut shared: BTreeMap<String, (usize, BTreeSet<&vci_core::InputEntry>)> = BTreeMap::new();
    for (i, v) in verdicts.iter().enumerate() {
        let Some(Verdict::Attestable {
            a, signed: Ok(_), ..
        }) = v
        else {
            continue;
        };
        let mine: BTreeSet<&vci_core::InputEntry> = a.manifest.entries.iter().collect();
        let key = group_key(units[i].0);
        match shared.get_mut(&key) {
            None => {
                shared.insert(key, (1, mine));
            }
            Some((n, s)) => {
                *n += 1;
                *s = s.intersection(&mine).copied().collect();
            }
        }
    }
    shared
        .into_iter()
        .filter(|(_, (n, s))| *n >= 2 && !s.is_empty())
        .map(|(k, (_, s))| {
            (
                k,
                InputManifest {
                    entries: s.into_iter().cloned().collect(),
                    externals: Vec::new(),
                    env: Vec::new(),
                },
            )
        })
        .collect()
}

/// The last recorded duration (`result.durationMs`) of each of these units:
/// its newest stored attestation's, by any signer, when one records it.
/// Best effort: a unit that cannot be read has none.
fn last_durations<'s>(
    store: &AttestStore,
    test_ids: impl IntoIterator<Item = &'s str>,
) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let Ok(reader) = store.reader() else {
        return out;
    };
    for id in test_ids {
        let Ok(cands) = reader.candidates(id) else {
            continue;
        };
        let newest = cands
            .iter()
            .filter(|e| e.error.is_none())
            .filter_map(|e| crate::cmds::envelope_meta(&e.bytes))
            .filter_map(|m| m.duration_ms.map(|d| (m.issued_at, d)))
            .max_by_key(|(issued, _)| *issued);
        if let Some((_, d)) = newest {
            out.insert(id.to_owned(), d);
        }
    }
    out
}

/// `items` for the runner: those without a recorded duration first, in
/// the given order (a new file may be long), then the rest longest first
/// (ties in the given order), so that a runner that takes several at once
/// does not end on its longest file.
fn longest_first<'a, T>(
    items: &[&'a T],
    key: impl Fn(&T) -> &str,
    durations: &BTreeMap<String, u64>,
) -> Vec<&'a T> {
    let mut out: Vec<&'a T> = items
        .iter()
        .copied()
        .filter(|t| !durations.contains_key(key(t)))
        .collect();
    let mut known: Vec<(usize, &'a T)> = items
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, t)| durations.contains_key(key(t)))
        .collect();
    known.sort_by(|(ia, a), (ib, b)| durations[key(b)].cmp(&durations[key(a)]).then(ia.cmp(ib)));
    out.extend(known.into_iter().map(|(_, t)| t));
    out
}

/// After supersession: delete the stored input manifests in `roots` that no
/// attestation left in the store references (a tombstone each, published by
/// the next `vci push`), so the published tree does not keep one orphan
/// manifest per changed unit and commit. None is deleted when an
/// attestation's value or payload cannot be read (what it references is
/// then unknown), except one not fetched yet in a lazy clone, which is
/// fetched first when it could reference one of them (see
/// `AttestStore::hydrate_manifest_referrers`). A clone that still holds an
/// attestation referencing one of them (made, or fetched, before it sees
/// the deletion) puts the manifest
/// back when it merges the deletion in (see `vci fetch`). Returns how many
/// were deleted.
fn drop_orphan_manifests(store: &AttestStore, roots: &BTreeSet<String>) -> usize {
    if roots.is_empty() {
        return 0;
    }
    // [lazy metadata] Fetch the attestations not fetched yet that could
    // reference these manifests; keep the roots still undecided.
    let undecided = match store.hydrate_manifest_referrers(roots) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("vci: warning: cannot read the store to remove unreferenced manifests: {e}");
            return 0;
        }
    };
    let all = match store.list(None) {
        Ok(all) => all,
        Err(e) => {
            eprintln!("vci: warning: cannot read the store to remove unreferenced manifests: {e}");
            return 0;
        }
    };
    let mut referenced = BTreeSet::new();
    for e in &all {
        if e.not_fetched() {
            // [lazy metadata] It cannot reference a root `undecided` lacks.
            continue;
        }
        if e.error.is_some() {
            return 0;
        }
        match crate::cmds::envelope_meta(&e.bytes) {
            Some(m) => referenced.extend(m.manifest_ref),
            None => return 0,
        }
    }
    let orphans: Vec<&str> = roots
        .difference(&referenced)
        .filter(|r| !undecided.contains(*r))
        .map(String::as_str)
        .collect();
    // One session for all of them: a Rails run that superseded 2,400
    // attestations took a minute deleting their manifests one by one.
    match store.remove_manifests(orphans) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("vci: warning: cannot remove the unreferenced input manifests: {e}");
            0
        }
    }
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

    #[test]
    fn longest_first_puts_unknown_then_longest() {
        let items = ["a", "b", "c", "d", "e"];
        let refs: Vec<&&str> = items.iter().collect();
        let d: BTreeMap<String, u64> = [("a", 5), ("c", 90), ("d", 5), ("e", 20)]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        let got: Vec<&str> = longest_first(&refs, |t| t, &d)
            .into_iter()
            .copied()
            .collect();
        assert_eq!(got, ["b", "c", "e", "a", "d"]);
        let none = BTreeMap::new();
        let got: Vec<&str> = longest_first(&refs, |t| t, &none)
            .into_iter()
            .copied()
            .collect();
        assert_eq!(got, items);
    }

    fn write(root: &Utf8Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    /// `vci run <units>` with a project that could not be listed: fail open
    /// when every unit resolved elsewhere, else the error names the listing
    /// failure too.
    #[test]
    fn unlisted_projects_fail_open_only_when_every_unit_resolved() {
        let unlisted = || {
            vec![(
                "rust".to_owned(),
                anyhow::anyhow!("cargo metadata failed").context("could not parse cargo workspace"),
            )]
        };
        let (selected, warnings) =
            settle_unlisted(Ok(BTreeSet::from([0, 2])), &unlisted()).unwrap();
        assert_eq!(selected, BTreeSet::from([0, 2]));
        assert_eq!(
            warnings,
            [
                "listing the test files of rust failed: could not parse cargo workspace: cargo metadata failed; none of the requested units is in it"
            ]
        );
        let e = settle_unlisted(
            Err(anyhow::anyhow!(
                "src/x.rs is not a test file of any project (not listed by the test runner)"
            )),
            &unlisted(),
        )
        .unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "src/x.rs is not a test file of any project (not listed by the test runner) (it may be in a project that could not be listed: listing the test files of rust failed: could not parse cargo workspace: cargo metadata failed)"
        );
        // Nothing failed to list: the result is unchanged.
        let (selected, warnings) = settle_unlisted(Ok(BTreeSet::from([1])), &[]).unwrap();
        assert_eq!((selected, warnings.len()), (BTreeSet::from([1]), 0));
        let e = settle_unlisted(Err(anyhow::anyhow!("x is not a test file")), &[]).unwrap_err();
        assert_eq!(format!("{e:#}"), "x is not a test file");
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
            // vci's own refusals that ignore_taints can waive.
            (
                "outside-repository:/proc/sys/net/core/somaxconn",
                "outside-repository",
            ),
            ("outside-repository:/etc/lsb-release", "outside-repository"),
            (
                "wrote-inside-repository: web/node_modules/other.txt, out-dir",
                "wrote-inside-repository",
            ),
            ("result:skipped:1 of 4", "result:skipped"),
        ] {
            assert_eq!(taint_key(t), k, "{t}");
        }
        for (m, k) in [
            // The refusals ignore_taints waives: keyed by the pattern.
            (
                "input outside the repository: /etc/hosts",
                "outside-repository",
            ),
            ("result failed (1 failed of 3)", "result failed"),
            (
                "result passed (0 failed, 1 skipped or xfailed of 2; a skipped test did not run)",
                "result:skipped",
            ),
            (
                "result no-tests (0 tests; no test ran or some were filtered out, so the run cannot vouch for the unit)",
                "result:no-tests",
            ),
            (
                "result filtered (0 tests; no test ran or some were filtered out, so the run cannot vouch for the unit)",
                "result filtered",
            ),
            // A failed result with skips is a failure, never waivable.
            (
                "result failed (1 failed, 1 skipped or xfailed of 3; a skipped test did not run)",
                "result failed",
            ),
            (
                "wrote inside the repository: out.txt",
                "wrote-inside-repository",
            ),
            (
                "platform-specific file outside the repository: /x/y_linux.go",
                "platform-specific file outside the repository",
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
            waived: if attested {
                vec!["process:system".to_owned()]
            } else {
                vec![]
            },
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
        assert_eq!(v["units"][0]["waived"][0], "process:system");
        assert_eq!(v["units"][1]["waived"].as_array().unwrap().len(), 0);
    }

    fn policy(toml: &str) -> crate::config::Policy {
        crate::config::Config::parse(toml).unwrap().project_specs()[0]
            .policy
            .clone()
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn split_waived_by_ignore_taints() {
        let taints = strings(&[
            "process:system",
            "process:backtick",
            "native:FFI attach_function(x)",
            "network:pg client (a database connection the test opened itself)",
            "vci:not-hooked:ffi (x)",
            "external-without-version:/abs/x.js",
        ]);
        let split = |toml: &str, adapter: &str| {
            let p = policy(toml);
            let (w, r) = split_waived_taints(&p, adapter, &[], &taints);
            (
                w.into_iter().cloned().collect::<Vec<_>>(),
                r.into_iter().cloned().collect::<Vec<_>>(),
            )
        };
        // Default: nothing waived.
        let (w, r) = split("[policy]\n", "rails");
        assert!(w.is_empty());
        assert_eq!(r, taints);
        // A glob over the kind, and an exact key.
        let (w, r) = split(
            "[policy]\nignore_taints = [\"process:*\", \"external-without-version\"]\n",
            "rails",
        );
        assert_eq!(
            w,
            strings(&[
                "process:system",
                "process:backtick",
                "external-without-version:/abs/x.js"
            ])
        );
        assert_eq!(r.len(), 3);
        // A category-only pattern.
        let (w, _) = split(
            "[policy]\nignore_taints = [\"native\", \"network\"]\n",
            "rails",
        );
        assert_eq!(w.len(), 2);
        assert!(w[0].starts_with("native:FFI") && w[1].starts_with("network:pg"));
        // A pattern with a kind matches that kind only.
        let (w, _) = split("[policy]\nignore_taints = [\"process:system\"]\n", "rails");
        assert_eq!(w, ["process:system"]);
        // "*" waives everything but vci's own taints.
        let (w, r) = split("[policy]\nignore_taints = [\"*\"]\n", "rails");
        assert_eq!(w.len(), 5);
        assert_eq!(r, ["vci:not-hooked:ffi (x)"]);
    }

    /// vci's own refusals that are taints: waived by their key (or a
    /// category pattern, or "*"), never by another key.
    #[test]
    fn split_waived_outside_writes_and_skips() {
        let taints = strings(&[
            "outside-repository:/proc/self/exe",
            "outside-repository:/etc/alpine-release",
            "wrote-inside-repository: web/node_modules/other.txt",
            "result:skipped:1 of 4",
        ]);
        let waived = |toml: &str| {
            let p = policy(toml);
            split_waived_taints(&p, "node-test", &[], &taints)
                .0
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        assert!(waived("[policy]\n").is_empty());
        assert_eq!(
            waived("[policy]\nignore_taints = [\"outside-repository\"]\n"),
            &taints[..2]
        );
        assert_eq!(
            waived("[policy]\nignore_taints = [\"wrote-inside-repository\"]\n"),
            &taints[2..3]
        );
        assert_eq!(
            waived("[policy]\nignore_taints = [\"result:skipped\"]\n"),
            &taints[3..]
        );
        // The category pattern "result" is result:* (only skips are taints).
        assert_eq!(
            waived("[policy]\nignore_taints = [\"result\"]\n"),
            &taints[3..]
        );
        assert_eq!(waived("[policy]\nignore_taints = [\"*\"]\n"), taints);
        // The key is the category: patterns are not matched against paths.
        assert!(waived("[policy]\nignore_taints = [\"outside-repository:/proc/*\"]\n").is_empty());
        assert!(waived("[policy]\nignore_taints = [\"wrote-inside\"]\n").is_empty());
    }

    #[test]
    fn tool_caches_under_node_modules_are_not_writes() {
        for w in [
            "node_modules/.vite",
            "node_modules/.vite/deps_temp_1a2b/react.js",
            "vex-web/node_modules/.vite-temp",
            "vex-web/node_modules/.vite-temp/vite.config.ts.timestamp-1.mjs",
            "a/b/node_modules/.cache/babel-loader/x.json",
        ] {
            assert!(is_tool_cache_write(w), "{w}");
        }
        for w in [
            "node_modules/other.txt",
            "node_modules/.vitest/x",
            "node_modules/pkg/.cache/x",
            ".vite/x",
            "src/node_modules.vite",
            "out.txt",
        ] {
            assert!(!is_tool_cache_write(w), "{w}");
        }
    }

    #[test]
    fn outside_paths_are_found_once_and_pruned() {
        let root = Utf8Path::new("/r");
        let mut o = Observed::default();
        o.reads.insert("/etc/hosts".into());
        o.reads.insert("/r/a.txt".into());
        o.stats.insert("/etc/hosts".into());
        o.probes.insert("/proc/self/exe".into());
        o.readdirs.insert("/r/out".into());
        o.reads.insert("/r/out/x".into());
        let out: Vec<&str> = outside_repository(root, &o)
            .into_iter()
            .map(|p| p.as_str())
            .collect();
        assert_eq!(out, ["/etc/hosts", "/proc/self/exe"]);
        let pruned = without_paths(
            &o,
            &[
                "/etc/hosts".into(),
                "/proc/self/exe".into(),
                "/r/out".into(),
            ],
        );
        assert!(outside_repository(root, &pruned).is_empty());
        assert_eq!(
            pruned.reads.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
            ["/r/a.txt"]
        );
        assert!(pruned.readdirs.is_empty() && pruned.stats.is_empty());
    }

    #[test]
    fn go_allow_net_is_ignore_taints_go_net() {
        let taints = strings(&[
            "go:net: the test links package net (...)",
            "go:syscall: x imports syscall",
            "exec: /bin/sh",
        ]);
        let waived = |toml: &str| {
            let p = policy(toml);
            split_waived_taints(&p, "go", &[], &taints)
                .0
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        let by_flag = waived("adapter = \"go\"\n[policy]\ngo_allow_net = true\n");
        let by_key = waived("adapter = \"go\"\n[policy]\nignore_taints = [\"go:net\"]\n");
        assert_eq!(by_flag, ["go:net: the test links package net (...)"]);
        assert_eq!(by_flag, by_key);
        assert_eq!(
            waived("adapter = \"go\"\n[policy]\nignore_taints = [\"go\", \"exec\"]\n").len(),
            3
        );
        assert!(waived("adapter = \"go\"\n").is_empty());
        // go_allow_net only concerns Go units.
        let p = policy("[policy]\ngo_allow_net = true\n");
        assert!(split_waived_taints(&p, "vitest", &[], &taints).0.is_empty());
    }

    #[test]
    fn cargo_declared_inputs_still_waive_undeclared_reads() {
        let taints = strings(&["cargo:undeclared-reads (x)", "cargo:process: Command::new"]);
        let p = policy("adapter = \"cargo\"\n");
        let declared = strings(&["testdata/**"]);
        let (w, r) = split_waived_taints(&p, "cargo", &declared, &taints);
        assert_eq!((w.len(), r.len()), (1, 1));
        let (w, _) = split_waived_taints(&p, "cargo", &[], &taints);
        assert!(w.is_empty());
        let p = policy("adapter = \"cargo\"\n[policy]\nignore_taints = [\"cargo:*\"]\n");
        let (w, r) = split_waived_taints(&p, "cargo", &[], &taints);
        assert_eq!((w.len(), r.len()), (2, 0));
    }

    #[test]
    fn in_order_sinks_every_result_in_the_items_order() {
        // Later items finish first; each is sunk once, in order, on the
        // calling thread, whatever the number of jobs.
        let items: Vec<u64> = (0..40).collect();
        let me = std::thread::current().id();
        for jobs in [1, 3, 8, 64] {
            let mut got = Vec::new();
            in_order(
                &items,
                jobs,
                |&i| {
                    std::thread::sleep(std::time::Duration::from_millis((40 - i) % 7));
                    i * 10
                },
                |i, r| {
                    assert_eq!(std::thread::current().id(), me);
                    got.push((i, r));
                },
            );
            let want: Vec<(usize, u64)> = (0..40).map(|i| (i as usize, i * 10)).collect();
            assert_eq!(got, want, "jobs {jobs}");
        }
        // One job: each result is sunk before the next item is worked on.
        let worked = std::sync::atomic::AtomicUsize::new(0);
        in_order(
            &items,
            1,
            |_| worked.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            |i, n| {
                assert_eq!(n, i);
                assert_eq!(worked.load(std::sync::atomic::Ordering::SeqCst), i + 1);
            },
        );
        in_order(&[] as &[u64], 4, |_| 0, |_, _: u64| panic!("no items"));
    }

    #[test]
    fn cached_checkout_answers_as_the_direct_one() {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(dir.path()).unwrap().to_owned();
        let git = |args: &[&str]| {
            let st = std::process::Command::new("git")
                .arg("-C")
                .arg(root.as_str())
                .args(args)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(st.success(), "git {args:?}");
        };
        git(&["init", "-q"]);
        write(&root, ".gitignore", "*.log\nbuild/\n");
        write(&root, "src/a.rb", "a");
        write(&root, "src/b.log", "b");
        write(&root, "build/out.txt", "o");
        let direct = Checkout::direct(&root);
        let cached = Checkout::cached(&root);
        let paths: Vec<String> = [
            "src/a.rb",
            "src/b.log",
            "build",
            "build/out.txt",
            "nope.log",
        ]
        .iter()
        .map(|p| (*p).to_owned())
        .collect();
        let want = direct.git_ignored(&paths);
        assert_eq!(want, ["src/b.log", "build", "build/out.txt", "nope.log"]);
        // Asked twice (the second time from the cache), and in parts.
        assert_eq!(cached.git_ignored(&paths), want);
        assert_eq!(cached.git_ignored(&paths), want);
        assert_eq!(cached.git_ignored(&paths[1..3]), want[..2]);
        let observed = vec![
            (RepoPath::new("src").unwrap(), Observation::ReadDir),
            (RepoPath::new("src/a.rb").unwrap(), Observation::Read),
        ];
        assert_eq!(
            ignored_children(&cached, &observed),
            ignored_children(&direct, &observed)
        );
        assert_eq!(
            ignored_children(&cached, &observed),
            [(RepoPath::new("src/b.log").unwrap(), Observation::Exclude)]
        );
        let mut obs = observed.clone();
        obs.extend(ignored_children(&direct, &observed));
        let m = direct.capture(&obs, vec![], &[], |_: &str| None).unwrap();
        assert_eq!(
            cached.capture(&obs, vec![], &[], |_: &str| None).unwrap(),
            m
        );
        assert_eq!(
            cached.capture(&obs, vec![], &[], |_: &str| None).unwrap(),
            m
        );
        assert_eq!(
            ignored_listing_children(&cached, &m),
            ignored_listing_children(&direct, &m)
        );
        assert!(junk_in_listings(&cached, &m).is_empty());
        // Not a repository: git answers nothing, and nothing is kept.
        let plain = tempfile::tempdir().unwrap();
        let proot = Utf8Path::from_path(plain.path()).unwrap();
        let c = Checkout::cached(proot);
        assert!(c.git_ignored(&paths).is_empty());
        assert!(locked(&c.cache.as_ref().unwrap().ignored).is_empty());
    }

    #[test]
    fn waived_note_names_the_first_key_and_counts_the_others() {
        assert_eq!(waived_note(&[]), "");
        assert_eq!(
            waived_note(&strings(&["child_process.execSync"])),
            "child_process.execSync"
        );
        assert_eq!(
            waived_note(&strings(&[
                "process:spawn",
                "process:system",
                "process:system",
                "native:FFI a",
                "fetch"
            ])),
            "process:system, +3"
        );
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
            shared_group: None,
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
