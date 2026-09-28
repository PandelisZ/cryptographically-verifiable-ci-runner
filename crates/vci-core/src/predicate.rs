//! Attestation predicate types (the in-toto `predicate` body).

use serde::{Deserialize, Serialize};

use crate::manifest::InputManifest;

/// in-toto `predicateType` for vci test attestations.
pub const PREDICATE_TYPE: &str = "https://vci.dev/test-attestation/v1";

/// Tool versions an attestation was made with.
///
/// Adapter-specific: a Vitest toolchain sets `node`, `vitest` and `vite`; a
/// pytest toolchain sets `python`, `implementation` and `pytest`. Fields an
/// adapter does not use are empty and omitted from the JSON, so Vitest
/// predicates serialise exactly as before these fields existed.
///
/// Comparison rule ([`Toolchain::diff`]): `node` by major version, every
/// other tool field exactly (an empty field only matches an empty field);
/// `os`/`arch` according to the platform policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Toolchain {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vitest: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vite: String,
    /// Full Python version (`major.minor.patch`), pytest adapter.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub python: String,
    /// `sys.implementation.name` (`cpython`, `pypy`), pytest adapter.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub implementation: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pytest: String,
    /// Versions of the libraries bundled with or linked into the interpreter
    /// that tests commonly depend on (`sqlite=...;openssl=...`), pytest
    /// adapter. Two builds of the same Python version can differ here
    /// (Homebrew vs python-build-standalone).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub python_libs: String,
    /// Every distribution installed in the environment the tests ran in, as
    /// sorted `name==version` (PEP 503 names), pytest adapter. An extra
    /// package (installed by a CI step, or only on another platform through a
    /// marker) can change what an optional import finds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub python_dists: Vec<String>,
    pub os: String,
    pub arch: String,
}

fn major(v: &str) -> &str {
    v.split('.').next().unwrap_or(v)
}

impl Toolchain {
    /// Tool fields that differ between `self` (attested) and `now`, as
    /// `(what, expected, actual)`. `os`/`arch` are not compared here (they
    /// depend on the platform policy).
    pub fn diff(&self, now: &Toolchain) -> Vec<(&'static str, String, String)> {
        let mut out = vec![];
        if major(&self.node) != major(&now.node) || self.node.is_empty() != now.node.is_empty() {
            out.push((
                "node major",
                major(&self.node).to_owned(),
                major(&now.node).to_owned(),
            ));
        }
        for (what, a, b) in [
            ("vitest", &self.vitest, &now.vitest),
            ("vite", &self.vite, &now.vite),
            ("python", &self.python, &now.python),
            (
                "python implementation",
                &self.implementation,
                &now.implementation,
            ),
            ("pytest", &self.pytest, &now.pytest),
            ("python libraries", &self.python_libs, &now.python_libs),
        ] {
            if a != b {
                out.push((what, a.clone(), b.clone()));
            }
        }
        if self.python_dists != now.python_dists {
            let a: std::collections::BTreeSet<&String> = self.python_dists.iter().collect();
            let b: std::collections::BTreeSet<&String> = now.python_dists.iter().collect();
            let only = |x: &std::collections::BTreeSet<&String>,
                        y: &std::collections::BTreeSet<&String>| {
                let v: Vec<&str> = x.difference(y).map(|s| s.as_str()).collect();
                if v.is_empty() {
                    "-".to_owned()
                } else {
                    v.join(" ")
                }
            };
            out.push((
                "python distributions",
                format!("only attested: {}", only(&a, &b)),
                format!("only installed now: {}", only(&b, &a)),
            ));
        }
        out
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TestResult {
    /// `"passed"` or `"failed"`.
    pub state: String,
    pub tests: u32,
    pub failed: u32,
    pub skipped: u32,
    pub duration_ms: u64,
}

impl TestResult {
    /// True only for an explicit `"passed"` state with zero failures and zero
    /// skipped tests. A skip (or xfail) is usually conditional (platform,
    /// environment, an optional import); the skipped test did not run, so the
    /// attestation cannot vouch for it anywhere else.
    pub fn is_pass(&self) -> bool {
        self.state == "passed" && self.failed == 0 && self.skipped == 0
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Predicate {
    pub tool_version: String,
    pub adapter: String,
    pub test_id: String,
    pub argv: Vec<String>,
    pub repo_id: String,
    pub commit: String,
    pub tree_dirty: bool,
    pub toolchain: Toolchain,
    pub global_input_root: String,
    pub input_root: String,
    pub manifest: InputManifest,
    pub global_manifest: InputManifest,
    pub result: TestResult,
    pub tainted: Vec<String>,
    /// RFC 3339 UTC.
    pub issued_at: String,
    /// RFC 3339 UTC.
    pub expires_at: String,
}

/// Storage key for a test id: lowercase hex BLAKE3 of the id's UTF-8 bytes.
pub fn test_key(test_id: &str) -> String {
    crate::hash::blake3_hex(test_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntryKind, EnvEntry, External, InputEntry, RepoPath};

    fn sample() -> Predicate {
        let manifest = InputManifest {
            entries: vec![InputEntry {
                path: RepoPath::new("src/b.ts").unwrap(),
                kind: EntryKind::DirListing,
                exec: false,
                size: 2,
                hash: "ab".repeat(32),
            }],
            externals: vec![External {
                name: "ms".into(),
                version: "2.1.3".into(),
            }],
            env: vec![EnvEntry {
                key: "TZ".into(),
                hash: crate::ABSENT_HASH.into(),
            }],
        };
        Predicate {
            tool_version: "0.1.0".into(),
            adapter: "vitest".into(),
            test_id: "src/b.test.ts".into(),
            argv: vec!["vitest".into(), "run".into()],
            repo_id: "r".into(),
            commit: "c".into(),
            tree_dirty: true,
            toolchain: Toolchain {
                node: "26.9.0".into(),
                vitest: "5.0.2".into(),
                vite: "8.0.0".into(),
                os: "macos".into(),
                arch: "aarch64".into(),
                ..Default::default()
            },
            global_input_root: "g".into(),
            input_root: manifest.root(),
            global_manifest: InputManifest::default(),
            manifest,
            result: TestResult {
                state: "passed".into(),
                tests: 1,
                failed: 0,
                skipped: 0,
                duration_ms: 12,
            },
            tainted: vec![],
            issued_at: "2026-09-27T00:00:00Z".into(),
            expires_at: "2026-10-11T00:00:00Z".into(),
        }
    }

    #[test]
    fn json_is_camel_case_and_round_trips() {
        let p = sample();
        let v = serde_json::to_value(&p).unwrap();
        for k in [
            "toolVersion",
            "testId",
            "repoId",
            "treeDirty",
            "globalInputRoot",
            "inputRoot",
            "globalManifest",
            "issuedAt",
            "expiresAt",
        ] {
            assert!(v.get(k).is_some(), "missing {k}");
        }
        assert_eq!(v["result"]["durationMs"], 12);
        assert_eq!(v["manifest"]["entries"][0]["kind"], "dirListing");
        assert_eq!(v["manifest"]["entries"][0]["path"], "src/b.ts");
        let back: Predicate = serde_json::from_value(v).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn rejects_bad_paths_in_manifest() {
        let mut v = serde_json::to_value(sample()).unwrap();
        v["manifest"]["entries"][0]["path"] = "../outside".into();
        assert!(serde_json::from_value::<Predicate>(v).is_err());
    }

    #[test]
    fn test_key_is_blake3_of_id() {
        assert_eq!(
            test_key(""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            test_key("src/b.test.ts"),
            blake3::hash(b"src/b.test.ts").to_hex().to_string()
        );
        assert_ne!(test_key("src/b.test.ts"), test_key("src/a.test.ts"));
        assert_eq!(test_key("x").len(), 64);
    }

    /// A Vitest toolchain serialises with exactly the original five keys, so
    /// attestations made before pytest support still parse and compare.
    #[test]
    fn vitest_toolchain_json_is_unchanged() {
        let tc = sample().toolchain;
        let v = serde_json::to_value(&tc).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        assert_eq!(keys.len(), 5, "{keys:?}");
        for k in ["node", "vitest", "vite", "os", "arch"] {
            assert!(keys.contains(&k), "{keys:?}");
        }
        let old =
            r#"{"node":"26.9.0","vitest":"5.0.2","vite":"8.0.0","os":"macos","arch":"aarch64"}"#;
        assert_eq!(serde_json::from_str::<Toolchain>(old).unwrap(), tc);
    }

    #[test]
    fn toolchain_diff_rules() {
        let v = sample().toolchain;
        let mut v2 = v.clone();
        v2.node = "26.1.0".into();
        assert!(v.diff(&v2).is_empty(), "node compares by major");
        v2.node = "24.0.0".into();
        assert_eq!(v.diff(&v2)[0].0, "node major");
        let py = Toolchain {
            python: "3.14.7".into(),
            implementation: "cpython".into(),
            pytest: "9.1.1".into(),
            os: "macos".into(),
            arch: "aarch64".into(),
            ..Default::default()
        };
        let json = serde_json::to_value(&py).unwrap();
        assert!(json.get("node").is_none() && json.get("vitest").is_none());
        let mut p2 = py.clone();
        p2.python = "3.14.6".into();
        assert_eq!(
            py.diff(&p2),
            [("python", "3.14.7".to_owned(), "3.14.6".to_owned())]
        );
        p2.python = "3.14.7".into();
        p2.implementation = "pypy".into();
        assert_eq!(py.diff(&p2)[0].0, "python implementation");
        // A pytest toolchain never matches a Vitest one.
        assert!(!py.diff(&v).is_empty());
        assert!(!v.diff(&py).is_empty());
    }

    /// Regressions: a different interpreter build (bundled sqlite/OpenSSL) and
    /// an installed package set that differs from the attested one (a package
    /// installed only in CI, or only on Linux through a marker) must not match.
    #[test]
    fn python_libs_and_distributions_must_match() {
        let py = Toolchain {
            python: "3.14.4".into(),
            implementation: "cpython".into(),
            pytest: "9.1.1".into(),
            python_libs: "sqlite=3.50.4;openssl=OpenSSL 3.5.1".into(),
            python_dists: vec!["idna==3.20".into(), "pytest==9.1.1".into()],
            os: "macos".into(),
            arch: "aarch64".into(),
            ..Default::default()
        };
        assert!(py.diff(&py.clone()).is_empty());
        let mut other = py.clone();
        other.python_libs = "sqlite=3.46.0;openssl=OpenSSL 3.0.14".into();
        assert_eq!(py.diff(&other)[0].0, "python libraries");
        let mut other = py.clone();
        other.python_dists.push("six==1.17.0".into());
        let d = py.diff(&other);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].0, "python distributions");
        assert!(d[0].2.contains("six==1.17.0"), "{d:?}");
        // Old pytest attestations (no dists recorded) never match a probe that
        // reports them.
        let mut old = py.clone();
        old.python_dists.clear();
        assert!(!old.diff(&py).is_empty());
    }

    #[test]
    fn is_pass() {
        let mut r = sample().result;
        assert!(r.is_pass());
        r.failed = 1;
        assert!(!r.is_pass());
        r.failed = 0;
        r.state = "failed".into();
        assert!(!r.is_pass());
    }

    /// Regression: a file with a skipped (or xfailed) test was attested as
    /// passed, so a test skipped on the attesting platform (`skipif(sys.platform
    /// == "darwin")`) or outside CI (`skipif(not os.environ.get("CI"))`) never ran
    /// anywhere.
    #[test]
    fn a_skipped_test_is_not_a_pass() {
        let mut r = sample().result;
        r.tests = 2;
        r.skipped = 1;
        assert!(!r.is_pass());
    }
}
