//! Attestation predicate types (the in-toto `predicate` body).

use serde::{Deserialize, Serialize};

use crate::manifest::InputManifest;

/// in-toto `predicateType` for vci test attestations.
pub const PREDICATE_TYPE: &str = "https://vci.dev/test-attestation/v1";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Toolchain {
    pub node: String,
    pub vitest: String,
    pub vite: String,
    pub os: String,
    pub arch: String,
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
    /// True only for an explicit `"passed"` state with zero failures.
    pub fn is_pass(&self) -> bool {
        self.state == "passed" && self.failed == 0
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
}
