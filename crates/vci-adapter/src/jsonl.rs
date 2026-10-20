//! Parser for the collector JSONL output (`@vci/vitest`, `vci_pytest` and the
//! Rails `vci_collector`).
//!
//! Anything unexpected (unknown record kinds, missing meta or result, bad
//! JSON) is turned into a taint so the file is never attested.
//!
//! pytest-specific records: `meta` carries `adapter`, `python`,
//! `implementation`, `pytest`, `platform`, `arch`; `write` records name
//! paths the test wrote, deleted, renamed or created (the CLI refuses to
//! attest a file that wrote inside the repository); an `env` record with key
//! `*` means the whole environment was enumerated, which is a taint.

use std::collections::{BTreeMap, BTreeSet};

use camino::{Utf8Path, Utf8PathBuf};
use serde_json::Value;
use sha2::{Digest, Sha256};
use vci_core::TestResult;

use crate::AdapterError;

/// Everything the collectors reported for one test file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Observed {
    /// Test id relative to the runner root, `/` separators.
    pub test_id: String,
    /// The group of units whose outputs share lines (a Rails batch's slot
    /// or boot: the name of the shared lines' file), when this one's does
    /// (vci 2.1.8): their manifests are stored on one base, the entries
    /// the group's units share.
    pub shared_group: Option<String>,
    pub project: String,
    /// Runner root reported by the collector (absolute).
    pub root: String,
    pub node: String,
    /// Vitest version, or the pytest version for the pytest collector.
    pub runner_version: String,
    pub bundler_version: String,
    pub collector: String,
    /// `meta.adapter`; `"vitest"` when absent (the Vitest collector does
    /// not emit it).
    pub adapter: String,
    /// pytest collector: full Python version and implementation name.
    pub python: String,
    pub implementation: String,
    /// pytest collector: `sys.platform` and `platform.machine()`.
    pub platform: String,
    pub arch: String,
    /// Paths written, deleted, renamed or created by the test (absolute).
    pub writes: BTreeSet<Utf8PathBuf>,
    /// Module files in the graph (absolute paths).
    pub modules: BTreeSet<Utf8PathBuf>,
    /// Successful reads/stats of files or directories.
    pub reads: BTreeSet<Utf8PathBuf>,
    /// Failed lookups (ENOENT/ENOTDIR).
    pub probes: BTreeSet<Utf8PathBuf>,
    /// Directory listings.
    pub readdirs: BTreeSet<Utf8PathBuf>,
    /// Paths whose type (not contents) was observed (pytest: `realpath()`
    /// walking through a component): a directory is recorded as a directory,
    /// a file like a read.
    pub stats: BTreeSet<Utf8PathBuf>,
    /// External packages as (name, version).
    pub externals: BTreeSet<(String, String)>,
    /// Env var keys read.
    pub env_keys: BTreeSet<String>,
    /// Go: source files inside the repository whose inclusion in the build
    /// depends on GOOS/GOARCH (`_linux.go`, `//go:build darwin`), absolute.
    /// An attestation of such a test only holds on the same OS and
    /// architecture, whatever the platform policy says.
    pub platform_files: BTreeSet<Utf8PathBuf>,
    /// Go: why the test's results may differ on another architecture
    /// (floating-point code, which the compiler may fuse differently per
    /// architecture). An attestation of such a test only holds on the same
    /// architecture, whatever the platform policy says.
    pub arch_specific: BTreeSet<String>,
    /// Cargo: `cfg(...)` predicates in the unit's repository sources and
    /// manifests that depend on the target (`unix`, `target_os = "linux"`),
    /// normalised. An attestation only holds on a platform where each one
    /// evaluates as it did on the attesting host.
    pub cfg_predicates: BTreeSet<String>,
    /// Cargo: paths the unit's source names (string literals used with file
    /// APIs that leave the package directory), absolute, with where they were
    /// seen. Each must be covered by the recorded inputs, or the unit is not
    /// attestable.
    pub path_refs: BTreeMap<Utf8PathBuf, String>,
    /// Cargo: build output and bookkeeping inside a walked package directory
    /// (the target dir, the repository's `.git` and `.vci/out`); Rails: the
    /// test environment's SQLite database files (and their `-wal`, `-shm`,
    /// `-journal` siblings) in a directory whose listing is an input.
    /// Absolute: never inputs, and left out of their parent directory's
    /// listing (a fresh checkout has no `target/` and no test database).
    pub excluded: BTreeSet<Utf8PathBuf>,
    /// Rails collector: Ruby version with patchlevel, engine, Rails and
    /// Bundler versions (`runner_version` is the test framework's).
    pub ruby: String,
    pub ruby_engine: String,
    pub rails: String,
    pub ruby_bundler: String,
    /// Reasons this file is not attestable.
    pub taints: Vec<String>,
    pub result: Option<TestResult>,
    /// Rails, `policy.rails_autoload_lookups` (2.6.0): the directories
    /// Zeitwerk listed only to define constants (absolute; their listings
    /// are not inputs, see `vci_core::EntryKind::AutoloadDir`). A directory
    /// whose namespace's constants were enumerated (`Module#constants`) is
    /// in `readdirs` instead.
    pub autoload_dirs: BTreeSet<Utf8PathBuf>,
    /// The constant names looked up without being loaded, normalized
    /// (`vci_core::autoload_name`; see `vci_core::EntryKind::AutoloadMiss`).
    pub autoload_names: BTreeSet<String>,
    /// Rails batch (2.3.0): this output is shard `.0` of `.1` of its file
    /// (its process ran that share of the file's test methods); vci puts a
    /// file's shards together ([`Observed::merge_shards`]).
    pub shard: Option<(u32, u32)>,
}

impl Observed {
    /// Drop reads, probes, listings and module loads of vci's own collector
    /// files (`collector_dirs`, real paths) that lie outside `repo_root`,
    /// however the collector spelt them: through a symlinked install prefix
    /// (Homebrew's `opt/vci` -> `Cellar/vci/<version>`) a collector file has
    /// two paths, and only one of them starts with the directory vci
    /// resolved. They are vci's tooling, identified by the collector
    /// version, never inputs of a test. Paths inside the repository are
    /// kept (they are hashed like any other input). Returns how many were
    /// dropped.
    ///
    /// A path is judged by where it really leads (its real path, or its
    /// nearest existing ancestor's for an absent path), never by its
    /// spelling: a symlink in the collector directory to a repository
    /// directory (or to anywhere else) reads that file, which is kept (a
    /// repository file the collector reported through the link, or a read
    /// outside the repository, which refuses the file).
    pub fn drop_collector_paths(
        &mut self,
        repo_root: &Utf8Path,
        collector_dirs: &[Utf8PathBuf],
    ) -> usize {
        if collector_dirs.is_empty() {
            return 0;
        }
        let dirs: Vec<Utf8PathBuf> = collector_dirs
            .iter()
            .flat_map(|d| {
                let real = d.canonicalize_utf8().ok();
                std::iter::once(d.clone()).chain(real)
            })
            .collect();
        let own = |p: &Utf8PathBuf| -> bool {
            if p.starts_with(repo_root) {
                return false;
            }
            let r = real_path(p);
            !r.starts_with(repo_root) && dirs.iter().any(|d| r.starts_with(d))
        };
        let mut n = 0;
        for set in [
            &mut self.modules,
            &mut self.reads,
            &mut self.probes,
            &mut self.readdirs,
            &mut self.stats,
        ] {
            let before = set.len();
            set.retain(|p| !own(p));
            n += before - set.len();
        }
        n
    }
}

impl Observed {
    /// One output for a file run as shards (2.3.0: a Rails batch ran its
    /// test methods in `k` processes, `shards` their outputs): what any of
    /// them observed (the union of their inputs, writes and taints) and one
    /// result (passed only when every shard passed; counts and durations
    /// added up). `Err` says why they cannot stand for the file: not
    /// exactly shards `0..k` of one `k`, or outputs that disagree about the
    /// test id or the toolchain.
    pub fn merge_shards(mut shards: Vec<Observed>) -> Result<Observed, String> {
        shards.sort_by_key(|o| o.shard.map(|(s, _)| s));
        let k = match shards.first().and_then(|o| o.shard) {
            Some((_, k)) => k,
            None => return Err("an output without a shard among its shards".into()),
        };
        let got: Vec<Option<(u32, u32)>> = shards.iter().map(|o| o.shard).collect();
        let want: Vec<Option<(u32, u32)>> = (0..k).map(|s| Some((s, k))).collect();
        if got != want {
            return Err(format!(
                "its shards' outputs are {} of {k} (shards {:?})",
                got.len(),
                got.iter()
                    .map(|g| g.map_or_else(|| "none".to_owned(), |(s, k)| format!("{s}/{k}")))
                    .collect::<Vec<_>>()
            ));
        }
        let mut it = shards.into_iter();
        let mut m = it.next().expect("k >= 1 shards");
        for o in it {
            let same = |a: &str, b: &str, what: &str| -> Result<(), String> {
                if a == b {
                    Ok(())
                } else {
                    Err(format!("its shards disagree about {what} ({a:?}, {b:?})"))
                }
            };
            same(&m.test_id, &o.test_id, "the test id")?;
            same(&m.project, &o.project, "the project")?;
            same(&m.root, &o.root, "the root")?;
            same(&m.adapter, &o.adapter, "the adapter")?;
            same(&m.runner_version, &o.runner_version, "the runner version")?;
            same(&m.collector, &o.collector, "the collector")?;
            same(&m.ruby, &o.ruby, "the Ruby version")?;
            same(&m.ruby_engine, &o.ruby_engine, "the Ruby engine")?;
            same(&m.rails, &o.rails, "the Rails version")?;
            same(&m.ruby_bundler, &o.ruby_bundler, "the Bundler version")?;
            same(&m.platform, &o.platform, "the platform")?;
            same(&m.arch, &o.arch, "the architecture")?;
            m.writes.extend(o.writes);
            m.modules.extend(o.modules);
            m.reads.extend(o.reads);
            m.probes.extend(o.probes);
            m.readdirs.extend(o.readdirs);
            m.autoload_dirs.extend(o.autoload_dirs);
            m.autoload_names.extend(o.autoload_names);
            m.stats.extend(o.stats);
            m.externals.extend(o.externals);
            m.env_keys.extend(o.env_keys);
            m.platform_files.extend(o.platform_files);
            m.arch_specific.extend(o.arch_specific);
            m.cfg_predicates.extend(o.cfg_predicates);
            for (p, w) in o.path_refs {
                m.path_refs.entry(p).or_insert(w);
            }
            m.excluded.extend(o.excluded);
            for t in o.taints {
                if !m.taints.contains(&t) {
                    m.taints.push(t);
                }
            }
            m.result = match (m.result.take(), o.result) {
                (Some(a), Some(b)) => Some(TestResult {
                    state: merged_state(&a.state, &b.state),
                    tests: a.tests.saturating_add(b.tests),
                    failed: a.failed.saturating_add(b.failed),
                    skipped: a.skipped.saturating_add(b.skipped),
                    duration_ms: a.duration_ms.saturating_add(b.duration_ms),
                }),
                _ => None,
            };
            if m.shared_group != o.shared_group {
                m.shared_group = None;
            }
        }
        if m.result.is_none() && !m.taints.iter().any(|t| t == "vci:missing-result") {
            m.taints.push("vci:missing-result".into());
        }
        m.shard = None;
        Ok(m)
    }
}

/// The state of two shards' results together: `failed` if either failed;
/// a shard that ran no test method (`no-tests`: its share of the file was
/// empty) counts for nothing; any other state but `passed` (`no-assertions`,
/// which the file run whole would report too) stands over `passed`.
fn merged_state(a: &str, b: &str) -> String {
    let s = match (a, b) {
        ("failed", _) | (_, "failed") => "failed",
        ("no-tests", x) | (x, "no-tests") => x,
        ("passed", x) | (x, "passed") => x,
        (x, _) => x,
    };
    s.to_owned()
}

/// The real path of `p`, or of its nearest existing ancestor joined with
/// the rest (an absent path); `p` itself when nothing resolves.
fn real_path(p: &Utf8Path) -> Utf8PathBuf {
    let mut rest: Vec<&str> = Vec::new();
    let mut cur = Some(p);
    while let Some(c) = cur {
        if let Ok(r) = c.canonicalize_utf8() {
            return rest.iter().rev().fold(r, |acc, x| acc.join(x));
        }
        match c.file_name() {
            Some(name) => rest.push(name),
            None => break,
        }
        cur = c.parent();
    }
    p.to_owned()
}

fn str_field(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_owned)
}

fn u64_field(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(Value::as_u64)
}

/// Parse one collector output file.
pub fn parse_jsonl_file(path: &Utf8Path) -> Result<Observed, AdapterError> {
    let text = std::fs::read_to_string(path)?;
    Ok(parse_jsonl_text(&text, path))
}

/// Parse a collector output's `text`, as if read from the file `path`
/// (whose name must be `sha256(testId).jsonl`).
pub fn parse_jsonl_text(text: &str, path: &Utf8Path) -> Observed {
    let mut o = Observed::default();
    let mut saw_meta = false;
    // Rails autoload records (2.5.0): directory -> namespace, namespace ->
    // missed names, namespaces whose constants were listed.
    let mut autoload_dirs: BTreeMap<Utf8PathBuf, String> = BTreeMap::new();
    let mut autoload_listed: BTreeSet<String> = BTreeSet::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                o.taints.push(format!("vci:bad-jsonl-line:{}:{e}", i + 1));
                continue;
            }
        };
        let kind = v.get("kind").and_then(Value::as_str).unwrap_or("");
        let path_of = |o: &mut Observed| -> Option<Utf8PathBuf> {
            match str_field(&v, "path") {
                Some(p) if Utf8Path::new(&p).is_absolute() => Some(Utf8PathBuf::from(p)),
                other => {
                    o.taints.push(format!("vci:bad-path:{kind}:{other:?}"));
                    None
                }
            }
        };
        match kind {
            "meta" => {
                if v.get("v").and_then(Value::as_u64) != Some(1) {
                    o.taints.push("vci:unsupported-meta-version".into());
                }
                saw_meta = true;
                o.test_id = str_field(&v, "testId").unwrap_or_default();
                o.project = str_field(&v, "project").unwrap_or_default();
                o.root = str_field(&v, "root").unwrap_or_default();
                o.node = str_field(&v, "node").unwrap_or_default();
                o.adapter = str_field(&v, "adapter").unwrap_or_else(|| "vitest".into());
                o.runner_version = match o.adapter.as_str() {
                    "pytest" => str_field(&v, "pytest").unwrap_or_default(),
                    "rails" => str_field(&v, "runner").unwrap_or_default(),
                    // node:test is part of Node.
                    "node-test" => str_field(&v, "node").unwrap_or_default(),
                    _ => str_field(&v, "vitest").unwrap_or_default(),
                };
                o.ruby = str_field(&v, "ruby").unwrap_or_default();
                o.ruby_engine = str_field(&v, "engine").unwrap_or_default();
                o.rails = str_field(&v, "rails").unwrap_or_default();
                o.ruby_bundler = str_field(&v, "bundler").unwrap_or_default();
                o.bundler_version = str_field(&v, "vite").unwrap_or_default();
                o.collector = str_field(&v, "collector").unwrap_or_default();
                o.python = str_field(&v, "python").unwrap_or_default();
                o.implementation = str_field(&v, "implementation").unwrap_or_default();
                o.platform = str_field(&v, "platform").unwrap_or_default();
                o.arch = str_field(&v, "arch").unwrap_or_default();
                if let Some(sh) = v.get("shard") {
                    let n = |i: usize| {
                        sh.get(i)
                            .and_then(Value::as_u64)
                            .and_then(|x| u32::try_from(x).ok())
                    };
                    match (n(0), n(1)) {
                        (Some(s), Some(k)) if s < k => o.shard = Some((s, k)),
                        _ => o.taints.push(format!("vci:bad-shard:{sh}")),
                    }
                }
            }
            "write" => {
                if let Some(p) = path_of(&mut o) {
                    o.writes.insert(p);
                }
            }
            "module" => {
                if let Some(p) = path_of(&mut o) {
                    o.modules.insert(p);
                }
            }
            "read" => {
                if let Some(p) = path_of(&mut o) {
                    o.reads.insert(p);
                }
            }
            "probe" => {
                if let Some(p) = path_of(&mut o) {
                    o.probes.insert(p);
                }
            }
            "readdir" => {
                if let Some(p) = path_of(&mut o) {
                    o.readdirs.insert(p);
                }
            }
            "stat" => {
                if let Some(p) = path_of(&mut o) {
                    o.stats.insert(p);
                }
            }
            // Rails: a path that is never an input and is left out of its
            // parent directory's listing (the test environment's SQLite
            // database files).
            "exclude" => {
                if let Some(p) = path_of(&mut o) {
                    o.excluded.insert(p);
                }
            }
            "external" => match (str_field(&v, "name"), str_field(&v, "version")) {
                (Some(n), Some(ver)) if !n.is_empty() && !ver.is_empty() => {
                    o.externals.insert((n, ver));
                }
                _ => o.taints.push(format!("vci:bad-external:{line}")),
            },
            "env" => match str_field(&v, "key") {
                // The environment was enumerated (dict(os.environ), iteration,
                // len, repr): every variable is an input, which cannot be
                // hashed meaningfully.
                Some(k) if k == "*" => o
                    .taints
                    .push("env:enumerated (the test read the whole environment)".into()),
                Some(k) if !k.is_empty() => {
                    o.env_keys.insert(k);
                }
                _ => o.taints.push(format!("vci:bad-env:{line}")),
            },
            "taint" => {
                o.taints
                    .push(str_field(&v, "reason").unwrap_or_else(|| "unknown".into()));
            }
            "result" => {
                let r = TestResult {
                    state: str_field(&v, "state").unwrap_or_default(),
                    tests: u64_field(&v, "tests").unwrap_or(0).min(u32::MAX as u64) as u32,
                    failed: u64_field(&v, "failed")
                        .unwrap_or(u32::MAX as u64)
                        .min(u32::MAX as u64) as u32,
                    skipped: u64_field(&v, "skipped").unwrap_or(0).min(u32::MAX as u64) as u32,
                    duration_ms: u64_field(&v, "durationMs").unwrap_or(0),
                };
                if o.result.is_some() {
                    o.taints.push("vci:duplicate-result".into());
                }
                o.result = Some(r);
            }
            "autoload_dir" => {
                if let Some(p) = path_of(&mut o) {
                    autoload_dirs.insert(p, str_field(&v, "ns").unwrap_or_default());
                }
            }
            "autoload_miss" => match str_field(&v, "name").map(|n| vci_core::autoload_name(&n)) {
                Some(n) if !n.is_empty() && !n.contains('/') && !n.starts_with('.') => {
                    o.autoload_names.insert(n);
                }
                _ => o.taints.push(format!("vci:bad-autoload:{line}")),
            },
            "autoload_listed" => match str_field(&v, "ns") {
                Some(ns) => {
                    autoload_listed.insert(ns);
                }
                None => o.taints.push(format!("vci:bad-autoload:{line}")),
            },
            other => o.taints.push(format!("vci:unknown-record-kind:{other}")),
        }
    }
    for (dir, ns) in autoload_dirs {
        if autoload_listed.contains(&ns) || o.readdirs.contains(&dir) {
            o.readdirs.insert(dir);
        } else {
            o.autoload_dirs.insert(dir);
        }
    }
    if !saw_meta || o.test_id.is_empty() {
        o.taints.push("vci:missing-meta".into());
    }
    if o.result.is_none() {
        o.taints.push("vci:missing-result".into());
    }
    // The file name must be sha256(testId); anything else is suspicious.
    let mut expected = hex::encode(Sha256::digest(o.test_id.as_bytes()));
    if let Some((s, _)) = o.shard {
        expected.push_str(&format!(".shard-{s}"));
    }
    if path.file_stem() != Some(expected.as_str()) {
        o.taints.push("vci:jsonl-name-mismatch".into());
    }
    o
}

/// Parse every top-level `*.jsonl` in `dir` (worker parts under
/// `.vci-parts/` are ignored).
pub fn parse_jsonl_dir(dir: &Utf8Path) -> Result<Vec<Observed>, AdapterError> {
    let mut out = Vec::new();
    let mut names: Vec<Utf8PathBuf> = Vec::new();
    for ent in dir.read_dir_utf8()? {
        let ent = ent?;
        if ent.file_type()?.is_file() && ent.path().extension() == Some("jsonl") {
            names.push(ent.path().to_owned());
        }
    }
    names.sort();
    for p in names {
        out.push(parse_jsonl_file(&p)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard(s: u32, k: u32, state: &str, tests: u32, read: &str) -> Observed {
        Observed {
            test_id: "test/a_test.rb".into(),
            shard: Some((s, k)),
            reads: [Utf8PathBuf::from(read)].into_iter().collect(),
            result: Some(TestResult {
                state: state.into(),
                tests,
                failed: u32::from(state == "failed"),
                skipped: 0,
                duration_ms: 10,
            }),
            ..Default::default()
        }
    }

    /// A file's shards stand for it only when they are exactly shards
    /// 0..k of one k; together they have every shard's inputs and one
    /// result (a shard with no test method counts for nothing, a failure
    /// fails the file).
    #[test]
    fn shards_merge_only_when_complete() {
        let m = Observed::merge_shards(vec![
            shard(1, 3, "passed", 2, "/r/b"),
            shard(0, 3, "passed", 3, "/r/a"),
            shard(2, 3, "no-tests", 0, "/r/c"),
        ])
        .unwrap();
        assert_eq!(m.reads.len(), 3);
        let r = m.result.unwrap();
        assert_eq!(
            (r.state.as_str(), r.tests, r.duration_ms),
            ("passed", 5, 30)
        );
        assert_eq!(m.shard, None);

        let m = Observed::merge_shards(vec![
            shard(0, 2, "passed", 3, "/r/a"),
            shard(1, 2, "failed", 2, "/r/b"),
        ])
        .unwrap();
        assert_eq!(m.result.unwrap().state, "failed");

        for parts in [
            vec![
                shard(0, 3, "passed", 1, "/r/a"),
                shard(1, 3, "passed", 1, "/r/b"),
            ],
            vec![
                shard(0, 2, "passed", 1, "/r/a"),
                shard(0, 2, "passed", 1, "/r/b"),
            ],
            vec![
                shard(0, 2, "passed", 1, "/r/a"),
                shard(1, 3, "passed", 1, "/r/b"),
            ],
        ] {
            assert!(Observed::merge_shards(parts).is_err());
        }
        let mut other = shard(1, 2, "passed", 1, "/r/b");
        other.ruby = "3.4.1".into();
        assert!(Observed::merge_shards(vec![shard(0, 2, "passed", 1, "/r/a"), other]).is_err());
    }

    /// A collector file reached through a symlinked install prefix is
    /// dropped whichever spelling the collector used; repository files (and
    /// a repository symlink into the collector) are kept.
    #[test]
    fn collector_paths_are_dropped_through_symlinks() {
        let t = tempfile::tempdir().unwrap();
        let base = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        let cellar = base.join("Cellar/vci/1.1.0/share/vci/plugin");
        std::fs::create_dir_all(cellar.join("src")).unwrap();
        std::fs::write(cellar.join("src/late.js"), "").unwrap();
        std::fs::create_dir_all(base.join("opt")).unwrap();
        std::os::unix::fs::symlink(base.join("Cellar/vci/1.1.0"), base.join("opt/vci")).unwrap();
        let repo = base.join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(repo.join("src/a.js"), "").unwrap();
        std::os::unix::fs::symlink(cellar.join("src/late.js"), repo.join("src/link.js")).unwrap();
        let linked = base.join("opt/vci/share/vci/plugin");
        let mut o = Observed {
            shared_group: None,
            modules: [
                linked.join("src/late.js"),
                cellar.join("src/late.js"),
                repo.join("src/a.js"),
                repo.join("src/link.js"),
            ]
            .into_iter()
            .collect(),
            probes: [linked.join("src/late.ts"), base.join("elsewhere.js")]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            o.drop_collector_paths(&repo, std::slice::from_ref(&cellar)),
            3
        );
        assert_eq!(
            o.modules,
            [repo.join("src/a.js"), repo.join("src/link.js")]
                .into_iter()
                .collect()
        );
        assert_eq!(o.probes, [base.join("elsewhere.js")].into_iter().collect());
        assert_eq!(o.drop_collector_paths(&repo, &[]), 0);
    }

    /// Regression: a path that merely starts with the collector directory
    /// was dropped without being resolved, so a directory symlink there
    /// into the repository (or anywhere else) hid the files read through
    /// it. Only paths that really are in the collector directory go.
    #[test]
    fn collector_dir_symlinks_out_of_it_are_kept() {
        let t = tempfile::tempdir().unwrap();
        let base = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        let coll = base.join("share/vci/ruby-collector");
        std::fs::create_dir_all(&coll).unwrap();
        std::fs::write(coll.join("vci_collector.rb"), "").unwrap();
        let repo = base.join("repo");
        std::fs::create_dir_all(repo.join("test/fixtures/dirx")).unwrap();
        std::fs::write(repo.join("test/fixtures/dirx/x.png"), "x").unwrap();
        std::fs::create_dir_all(base.join("elsewhere")).unwrap();
        std::fs::write(base.join("elsewhere/o.txt"), "o").unwrap();
        std::os::unix::fs::symlink(repo.join("test/fixtures/dirx"), coll.join("fx1")).unwrap();
        std::os::unix::fs::symlink(base.join("elsewhere"), coll.join("out1")).unwrap();
        let mut o = Observed {
            shared_group: None,
            reads: [
                coll.join("vci_collector.rb"),
                coll.join("fx1/x.png"),
                coll.join("out1/o.txt"),
            ]
            .into_iter()
            .collect(),
            probes: [coll.join("fx1/absent.png"), coll.join("absent.rb")]
                .into_iter()
                .collect(),
            readdirs: [coll.join("fx1")].into_iter().collect(),
            ..Default::default()
        };
        assert_eq!(
            o.drop_collector_paths(&repo, std::slice::from_ref(&coll)),
            2
        );
        assert_eq!(
            o.reads,
            [coll.join("fx1/x.png"), coll.join("out1/o.txt")]
                .into_iter()
                .collect()
        );
        assert_eq!(
            o.probes,
            [coll.join("fx1/absent.png")].into_iter().collect()
        );
        assert_eq!(o.readdirs, [coll.join("fx1")].into_iter().collect());
    }

    fn write(dir: &Utf8Path, test_id: &str, body: &str) -> Utf8PathBuf {
        let name = hex::encode(Sha256::digest(test_id.as_bytes()));
        let p = dir.join(format!("{name}.jsonl"));
        std::fs::write(&p, body).unwrap();
        p
    }

    fn tmp() -> (tempfile::TempDir, Utf8PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let p = Utf8PathBuf::from_path_buf(t.path().to_path_buf()).unwrap();
        (t, p)
    }

    #[test]
    fn parses_all_record_kinds() {
        let (_t, d) = tmp();
        let body = r#"{"v":1,"kind":"meta","testId":"src/b.test.ts","project":"","vitest":"5.0.2","vite":"8.3.1","node":"26.9.0","root":"/p","collector":"@vci/vitest@0.1.0"}
{"kind":"module","path":"/p/src/b.ts","via":"vite-graph"}
{"kind":"external","name":"ms","version":"2.1.3"}
{"kind":"read","path":"/p/fixtures/b.json"}
{"kind":"probe","path":"/p/.env"}
{"kind":"readdir","path":"/p/src"}
{"kind":"env","key":"TZ"}
{"kind":"result","state":"passed","tests":1,"failed":0,"skipped":0,"durationMs":2}
"#;
        let p = write(&d, "src/b.test.ts", body);
        let o = parse_jsonl_file(&p).unwrap();
        assert_eq!(o.test_id, "src/b.test.ts");
        assert_eq!(o.runner_version, "5.0.2");
        assert!(o.modules.contains(Utf8Path::new("/p/src/b.ts")));
        assert!(o.reads.contains(Utf8Path::new("/p/fixtures/b.json")));
        assert!(o.probes.contains(Utf8Path::new("/p/.env")));
        assert!(o.readdirs.contains(Utf8Path::new("/p/src")));
        assert!(o.externals.contains(&("ms".into(), "2.1.3".into())));
        assert!(o.env_keys.contains("TZ"));
        assert!(o.taints.is_empty(), "{:?}", o.taints);
        assert!(o.result.unwrap().is_pass());
    }

    #[test]
    fn unexpected_input_becomes_taint() {
        let (_t, d) = tmp();
        let p = write(
            &d,
            "x.test.ts",
            "{\"v\":1,\"kind\":\"meta\",\"testId\":\"x.test.ts\"}\n{\"kind\":\"wat\"}\nnot json\n{\"kind\":\"read\",\"path\":\"rel\"}\n",
        );
        let o = parse_jsonl_file(&p).unwrap();
        let t = o.taints.join(",");
        assert!(t.contains("unknown-record-kind:wat"), "{t}");
        assert!(t.contains("bad-jsonl-line"), "{t}");
        assert!(t.contains("bad-path"), "{t}");
        assert!(t.contains("missing-result"), "{t}");
    }

    #[test]
    fn parses_pytest_records() {
        let (_t, d) = tmp();
        let body = r#"{"v":1,"kind":"meta","testId":"tests/test_b.py","adapter":"pytest","python":"3.14.7","implementation":"cpython","pytest":"9.1.1","root":"/R","platform":"darwin","arch":"arm64","collector":"vci_pytest@0.1.0"}
{"kind":"module","path":"/R/src/b.py","via":"finder"}
{"kind":"module","path":"/R/tests/conftest.py","via":"conftest"}
{"kind":"external","name":"pytest","version":"9.1.1"}
{"kind":"read","path":"/R/fixtures/b.json"}
{"kind":"probe","path":"/R/tests/b/__init__.py"}
{"kind":"write","path":"/R/out.txt"}
{"kind":"stat","path":"/R/fixtures"}
{"kind":"env","key":"PYTEST_ADDOPTS"}
{"kind":"result","state":"passed","tests":1,"failed":0,"skipped":0,"durationMs":65,"deselected":0,"exitStatus":0}
"#;
        let p = write(&d, "tests/test_b.py", body);
        let o = parse_jsonl_file(&p).unwrap();
        assert!(o.taints.is_empty(), "{:?}", o.taints);
        assert_eq!(o.adapter, "pytest");
        assert_eq!(o.runner_version, "9.1.1");
        assert_eq!(o.python, "3.14.7");
        assert_eq!(o.implementation, "cpython");
        assert!(o.node.is_empty() && o.bundler_version.is_empty());
        assert!(o.writes.contains(Utf8Path::new("/R/out.txt")));
        assert!(o.modules.contains(Utf8Path::new("/R/tests/conftest.py")));
        assert!(o.env_keys.contains("PYTEST_ADDOPTS"));
        assert!(o.stats.contains(Utf8Path::new("/R/fixtures")));
        assert!(o.result.unwrap().is_pass());
    }

    #[test]
    fn parses_rails_records() {
        let (_t, d) = tmp();
        let body = r#"{"v":1,"kind":"meta","testId":"test/models/b_test.rb","adapter":"rails","ruby":"3.4.9p82","engine":"ruby 3.4.9","rails":"8.1.3.1","bundler":"4.0.9","runner":"minitest 6.0.6","root":"/R","platform":"arm64-darwin25","collector":"vci_collector@0.1.0","db":"sqlite3","tz":"tzinfo-data"}
{"kind":"module","path":"/R/app/models/widget.rb"}
{"kind":"read","path":"/R/test/fixtures/widgets.yml"}
{"kind":"readdir","path":"/R/app/models"}
{"kind":"stat","path":"/R/log"}
{"kind":"write","path":"/R/log/test.log"}
{"kind":"external","name":"nokogiri","version":"1.19.4","platform":"arm64-darwin"}
{"kind":"env","key":"DATABASE_URL","where":"/gems/activerecord/x.rb"}
{"kind":"result","state":"passed","tests":2,"failed":0,"skipped":0,"assertions":4,"noAssertions":0,"durationMs":80,"exitStatus":0}
"#;
        let p = write(&d, "test/models/b_test.rb", body);
        let o = parse_jsonl_file(&p).unwrap();
        assert!(o.taints.is_empty(), "{:?}", o.taints);
        assert_eq!(o.adapter, "rails");
        assert_eq!(o.runner_version, "minitest 6.0.6");
        assert_eq!(o.ruby, "3.4.9p82");
        assert_eq!(o.rails, "8.1.3.1");
        assert_eq!(o.ruby_bundler, "4.0.9");
        assert!(o.externals.contains(&("nokogiri".into(), "1.19.4".into())));
        assert!(o.writes.contains(Utf8Path::new("/R/log/test.log")));
        assert!(o.env_keys.contains("DATABASE_URL"));
        assert!(o.result.unwrap().is_pass());
    }

    #[test]
    fn enumerated_env_is_a_taint_and_vitest_meta_defaults_adapter() {
        let (_t, d) = tmp();
        let p = write(
            &d,
            "tests/test_e.py",
            "{\"v\":1,\"kind\":\"meta\",\"testId\":\"tests/test_e.py\",\"adapter\":\"pytest\"}\n{\"kind\":\"env\",\"key\":\"*\"}\n{\"kind\":\"result\",\"state\":\"passed\",\"failed\":0}\n",
        );
        let o = parse_jsonl_file(&p).unwrap();
        assert!(o.taints.iter().any(|t| t.starts_with("env:enumerated")));
        assert!(!o.env_keys.contains("*"));
        let p = write(
            &d,
            "x.test.ts",
            "{\"v\":1,\"kind\":\"meta\",\"testId\":\"x.test.ts\"}\n{\"kind\":\"result\",\"state\":\"passed\",\"failed\":0}\n",
        );
        assert_eq!(parse_jsonl_file(&p).unwrap().adapter, "vitest");
    }

    #[test]
    fn result_without_failed_count_is_not_a_pass() {
        let (_t, d) = tmp();
        let p = write(
            &d,
            "x.test.ts",
            "{\"v\":1,\"kind\":\"meta\",\"testId\":\"x.test.ts\"}\n{\"kind\":\"result\",\"state\":\"passed\"}\n",
        );
        let o = parse_jsonl_file(&p).unwrap();
        assert!(!o.result.unwrap().is_pass());
    }

    #[test]
    fn misnamed_file_is_tainted_and_dir_skips_parts() {
        let (_t, d) = tmp();
        std::fs::write(
            d.join("deadbeef.jsonl"),
            "{\"v\":1,\"kind\":\"meta\",\"testId\":\"x.test.ts\"}\n{\"kind\":\"result\",\"state\":\"passed\",\"failed\":0}\n",
        )
        .unwrap();
        std::fs::create_dir(d.join(".vci-parts")).unwrap();
        std::fs::write(d.join(".vci-parts/p.jsonl"), "garbage").unwrap();
        let all = parse_jsonl_dir(&d).unwrap();
        assert_eq!(all.len(), 1);
        assert!(all[0].taints.iter().any(|t| t == "vci:jsonl-name-mismatch"));
    }
}
