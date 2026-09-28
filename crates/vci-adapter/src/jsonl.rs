//! Parser for the collector JSONL output (`@vci/vitest` and `vci_pytest`).
//!
//! Anything unexpected (unknown record kinds, missing meta or result, bad
//! JSON) is turned into a taint so the file is never attested.
//!
//! pytest-specific records: `meta` carries `adapter`, `python`,
//! `implementation`, `pytest`, `platform`, `arch`; `write` records name
//! paths the test wrote, deleted, renamed or created (the CLI refuses to
//! attest a file that wrote inside the repository); an `env` record with key
//! `*` means the whole environment was enumerated, which is a taint.

use std::collections::BTreeSet;

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
    /// Reasons this file is not attestable.
    pub taints: Vec<String>,
    pub result: Option<TestResult>,
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
    let mut o = Observed::default();
    let mut saw_meta = false;
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
                o.runner_version = if o.adapter == "pytest" {
                    str_field(&v, "pytest").unwrap_or_default()
                } else {
                    str_field(&v, "vitest").unwrap_or_default()
                };
                o.bundler_version = str_field(&v, "vite").unwrap_or_default();
                o.collector = str_field(&v, "collector").unwrap_or_default();
                o.python = str_field(&v, "python").unwrap_or_default();
                o.implementation = str_field(&v, "implementation").unwrap_or_default();
                o.platform = str_field(&v, "platform").unwrap_or_default();
                o.arch = str_field(&v, "arch").unwrap_or_default();
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
            other => o.taints.push(format!("vci:unknown-record-kind:{other}")),
        }
    }
    if !saw_meta || o.test_id.is_empty() {
        o.taints.push("vci:missing-meta".into());
    }
    if o.result.is_none() {
        o.taints.push("vci:missing-result".into());
    }
    // The file name must be sha256(testId); anything else is suspicious.
    let expected = hex::encode(Sha256::digest(o.test_id.as_bytes()));
    if path.file_stem() != Some(expected.as_str()) {
        o.taints.push("vci:jsonl-name-mismatch".into());
    }
    Ok(o)
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
