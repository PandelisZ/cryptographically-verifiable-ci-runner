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
    /// Go adapter: `go env GOVERSION` (`go1.26.2`), compared exactly.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub go: String,
    /// Go adapter: effective (`go env`) build settings that are the same on
    /// every platform, as sorted `KEY=value` (`CGO_ENABLED`, `GOEXPERIMENT`,
    /// `GOFLAGS`, `GOFIPS140`, `GODEBUG`, `GOWORK` relative to the project
    /// dir), compared exactly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub go_env: Vec<String>,
    /// Go adapter: the architecture level of `GOARCH` (`GOAMD64=v1`,
    /// `GOARM64=v8.0`). Compared only when `arch` is the same (with another
    /// architecture the platform policy decides).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub go_arch_level: String,
    /// Cargo adapter: `rustc -vV` as `<release> <commit-hash> LLVM <version>`,
    /// compared exactly.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rust: String,
    /// Cargo adapter: `cargo -vV` as `<release> <commit-hash>`, compared
    /// exactly.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cargo: String,
    /// Cargo adapter: the host triple (`aarch64-apple-darwin`). Compared only
    /// when `os` and `arch` are the same (otherwise the platform policy
    /// decides).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rust_host: String,
    /// Cargo adapter: `rustc --print cfg` of the host, sorted. Used to decide
    /// whether the attested code's `cfg(...)` predicates evaluate the same on
    /// another platform; compared exactly when `rust_host` is the same.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rust_cfg: Vec<String>,
    /// Rails adapter: Ruby version and patchlevel (`3.4.9p82`), compared
    /// exactly.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ruby: String,
    /// Rails adapter: `RUBY_ENGINE RUBY_ENGINE_VERSION` (`ruby 3.4.9`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ruby_engine: String,
    /// Rails adapter: the Rails version.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rails: String,
    /// Rails adapter: the Bundler version.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bundler: String,
    /// Rails adapter: the bundle's test frameworks and their versions
    /// (`minitest 6.0.6`, or `minitest 6.0.6; rspec-core 3.13.6, ...`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ruby_test: String,
    /// Rails adapter: libraries tests commonly depend on whose version the gem
    /// versions do not fix (`sqlite=<SQLite library>;yaml=<libyaml>;tz=<time
    /// zone data: tzinfo-data, or the system zoneinfo version>;encoding=<default
    /// external/internal>`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ruby_libs: String,
    /// Rails adapter: the database software of the test environment
    /// (`sqlite3`; `postgresql <server version>` under policy.rails_allow_db).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ruby_db: String,
    /// Rails adapter: every gem of the resolved bundle as sorted
    /// `name==version` (no platform: a native gem's builds of one version are
    /// the same gem on every platform).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ruby_gems: Vec<String>,
    /// The tests ran as the superuser (effective uid 0 on Unix): permission
    /// checks do not apply to it (a mode-000 file is readable), so a test's
    /// result can depend on it. Compared exactly; omitted when false, so
    /// attestations made without this field compare as non-root.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub superuser: bool,
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
            ("go", &self.go, &now.go),
            ("rustc", &self.rust, &now.rust),
            ("cargo", &self.cargo, &now.cargo),
            ("ruby", &self.ruby, &now.ruby),
            ("ruby engine", &self.ruby_engine, &now.ruby_engine),
            ("rails", &self.rails, &now.rails),
            ("bundler", &self.bundler, &now.bundler),
            ("ruby test framework", &self.ruby_test, &now.ruby_test),
            ("ruby libraries", &self.ruby_libs, &now.ruby_libs),
            ("database", &self.ruby_db, &now.ruby_db),
        ] {
            if a != b {
                out.push((what, a.clone(), b.clone()));
            }
        }
        // Another OS or architecture has another host triple and cfg set;
        // whether that may match at all is the platform policy's decision
        // (plus the cfg predicates the attestation lists). On the same OS and
        // architecture both must match (gnu vs musl, target features).
        if self.os == now.os && self.arch == now.arch && self.rust_host != now.rust_host {
            out.push(("rust host", self.rust_host.clone(), now.rust_host.clone()));
        }
        if self.rust_host == now.rust_host && self.rust_cfg != now.rust_cfg {
            out.push(("rust cfg", self.rust_cfg.join(" "), now.rust_cfg.join(" ")));
        }
        if self.superuser != now.superuser {
            let who = |r: bool| {
                if r {
                    "root (effective uid 0)"
                } else {
                    "not root"
                }
            };
            out.push((
                "privileges",
                who(self.superuser).to_owned(),
                who(now.superuser).to_owned(),
            ));
        }
        if self.go_env != now.go_env {
            out.push(("go env", self.go_env.join(" "), now.go_env.join(" ")));
        }
        // Another architecture has another level variable (GOAMD64 vs
        // GOARM64); whether that may match at all is the platform policy's
        // decision. On the same architecture the level must match.
        if self.arch == now.arch && self.go_arch_level != now.go_arch_level {
            out.push((
                "go arch level",
                self.go_arch_level.clone(),
                now.go_arch_level.clone(),
            ));
        }
        if self.ruby_gems != now.ruby_gems {
            out.push(set_diff("gems (bundle)", &self.ruby_gems, &now.ruby_gems));
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

/// `(what, "only attested: ...", "only installed now: ...")` for two lists.
fn set_diff(what: &'static str, a: &[String], b: &[String]) -> (&'static str, String, String) {
    let a: std::collections::BTreeSet<&String> = a.iter().collect();
    let b: std::collections::BTreeSet<&String> = b.iter().collect();
    let only = |x: &std::collections::BTreeSet<&String>,
                y: &std::collections::BTreeSet<&String>| {
        let v: Vec<&str> = x.difference(y).map(|s| s.as_str()).collect();
        if v.is_empty() {
            "-".to_owned()
        } else {
            v.join(" ")
        }
    };
    (
        what,
        format!("only attested: {}", only(&a, &b)),
        format!("only installed now: {}", only(&b, &a)),
    )
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

    /// Go: the exact Go version and the effective build settings must match;
    /// the architecture level only on the same architecture; a Go toolchain
    /// never matches a Vitest or pytest one.
    #[test]
    fn go_toolchain_rules() {
        let go = Toolchain {
            go: "go1.26.2".into(),
            go_env: vec!["CGO_ENABLED=1".into(), "GOFLAGS=".into()],
            go_arch_level: "GOARM64=v8.0".into(),
            os: "macos".into(),
            arch: "aarch64".into(),
            ..Default::default()
        };
        assert!(go.diff(&go.clone()).is_empty());
        let json = serde_json::to_value(&go).unwrap();
        assert_eq!(json["goEnv"][0], "CGO_ENABLED=1");
        assert_eq!(json["goArchLevel"], "GOARM64=v8.0");
        let mut other = go.clone();
        other.go = "go1.26.1".into();
        assert_eq!(go.diff(&other)[0].0, "go");
        let mut other = go.clone();
        other.go_env[1] = "GOFLAGS=-tags=integration".into();
        assert_eq!(go.diff(&other)[0].0, "go env");
        let mut other = go.clone();
        other.go_arch_level = "GOARM64=v9.0".into();
        assert_eq!(go.diff(&other)[0].0, "go arch level");
        // CI on another architecture: the level is not comparable.
        other.arch = "x86_64".into();
        other.go_arch_level = "GOAMD64=v1".into();
        assert!(go.diff(&other).is_empty(), "{:?}", go.diff(&other));
        assert!(!go.diff(&sample().toolchain).is_empty());
        assert!(!sample().toolchain.diff(&go).is_empty());
    }

    /// Cargo: rustc and cargo exactly; the host triple and cfg set only where
    /// they are comparable; a Cargo toolchain never matches another adapter's.
    #[test]
    fn cargo_toolchain_rules() {
        let rs = Toolchain {
            rust: "1.96.0 ac68faa2 LLVM 22.1.6".into(),
            cargo: "1.96.0 30a34c68".into(),
            rust_host: "aarch64-apple-darwin".into(),
            rust_cfg: vec!["target_os=\"macos\"".into(), "unix".into()],
            os: "macos".into(),
            arch: "aarch64".into(),
            ..Default::default()
        };
        assert!(rs.diff(&rs.clone()).is_empty());
        let json = serde_json::to_value(&rs).unwrap();
        assert_eq!(json["rustHost"], "aarch64-apple-darwin");
        assert_eq!(json["rustCfg"][1], "unix");
        let mut other = rs.clone();
        other.rust = "1.95.0 x LLVM 21".into();
        assert_eq!(rs.diff(&other)[0].0, "rustc");
        let mut other = rs.clone();
        other.cargo = "1.95.0 y".into();
        assert_eq!(rs.diff(&other)[0].0, "cargo");
        // Same OS and arch, another triple (e.g. musl): mismatch.
        let mut other = rs.clone();
        other.rust_host = "aarch64-apple-darwin-other".into();
        other.rust_cfg = vec!["unix".into()];
        assert_eq!(rs.diff(&other)[0].0, "rust host");
        // Same host, other cfg (target features from flags): mismatch.
        let mut other = rs.clone();
        other.rust_cfg.push("target_feature=\"sve\"".into());
        assert_eq!(rs.diff(&other)[0].0, "rust cfg");
        // Linux CI: host and cfg differ by definition; the platform policy
        // and the attested cfg predicates decide.
        let linux = Toolchain {
            rust_host: "x86_64-unknown-linux-gnu".into(),
            rust_cfg: vec!["target_os=\"linux\"".into(), "unix".into()],
            os: "linux".into(),
            arch: "x86_64".into(),
            ..rs.clone()
        };
        assert!(rs.diff(&linux).is_empty(), "{:?}", rs.diff(&linux));
        assert!(!rs.diff(&sample().toolchain).is_empty());
        assert!(!sample().toolchain.diff(&rs).is_empty());
    }

    /// Rails: Ruby (with patchlevel), engine, Rails, Bundler, the test
    /// framework, the libraries, the database and the bundle exactly; a Rails
    /// toolchain never matches another adapter's.
    #[test]
    fn rails_toolchain_rules() {
        let rb = Toolchain {
            ruby: "3.4.9p82".into(),
            ruby_engine: "ruby 3.4.9".into(),
            rails: "8.1.3.1".into(),
            bundler: "4.0.9".into(),
            ruby_test: "minitest 6.0.6".into(),
            ruby_libs: "sqlite=3.53.2;yaml=0.2.5;tz=tzinfo-data;encoding=UTF-8/UTF-8".into(),
            ruby_db: "sqlite3".into(),
            ruby_gems: vec!["nokogiri==1.19.4".into(), "rack==3.2.7".into()],
            os: "macos".into(),
            arch: "aarch64".into(),
            ..Default::default()
        };
        assert!(rb.diff(&rb.clone()).is_empty());
        // Linux CI with the same versions: only the platform policy decides.
        let linux = Toolchain {
            os: "linux".into(),
            arch: "x86_64".into(),
            ..rb.clone()
        };
        assert!(rb.diff(&linux).is_empty());
        for (what, f) in [
            (
                "ruby",
                (|t: &mut Toolchain| t.ruby = "3.4.8p72".into()) as fn(&mut Toolchain),
            ),
            ("rails", |t| t.rails = "8.1.3".into()),
            ("bundler", |t| t.bundler = "2.6.9".into()),
            ("ruby test framework", |t| {
                t.ruby_test = "minitest 5.25.4".into()
            }),
            ("ruby libraries", |t| t.ruby_libs = "sqlite=3.45.1".into()),
            ("database", |t| t.ruby_db = "postgresql 16.4".into()),
            ("gems (bundle)", |t| t.ruby_gems.push("pg==1.6.0".into())),
        ] {
            let mut other = rb.clone();
            f(&mut other);
            assert_eq!(rb.diff(&other)[0].0, what);
        }
        let v = serde_json::to_value(&rb).unwrap();
        assert_eq!(v["rubyGems"][0], "nokogiri==1.19.4");
        assert!(!rb.diff(&sample().toolchain).is_empty());
        assert!(!sample().toolchain.diff(&rb).is_empty());
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

    /// Regression: a permission test (a mode-000 file must not be readable)
    /// attested as a normal user fails as root (GitHub `container:` jobs run
    /// as root). Running as root on one side only is a toolchain difference;
    /// attestations without the field compare as non-root.
    #[test]
    fn superuser_must_match() {
        let t = sample().toolchain;
        let mut root = t.clone();
        root.superuser = true;
        assert_eq!(t.diff(&root)[0].0, "privileges");
        assert_eq!(root.diff(&t)[0].0, "privileges");
        assert!(root.diff(&root.clone()).is_empty());
        let v = serde_json::to_value(&root).unwrap();
        assert_eq!(v["superuser"], true);
        assert!(serde_json::to_value(&t).unwrap().get("superuser").is_none());
    }
}
