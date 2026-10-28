//! Attestation predicate types (the in-toto `predicate` body).
//!
//! Two predicate versions: v1 ([`Predicate`] plus the vci-cli fields,
//! together [`VciPredicate`]) carries every fact inline; v2
//! ([`VciPredicateV2`], store format 3, `design/STORE-V2.md` section 1.1)
//! carries the unit's own facts and two digests, of a [`Hdr`] object (the
//! facts every run at the same toolchain and global inputs shares) and of a
//! [`Tables`] object (the waiver table its `waived` ids index). A verifier
//! reads both through [`ResolvedPredicate`], which gives the v1 accessors
//! over either, so one `Verifier::check` runs on the view.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::manifest::{InputEntry, InputManifest};
use crate::objects::{DecodeError, Hdr, ObjectId, Tables, hex32, object_id, parse_hex32};

/// in-toto `predicateType` for vci test attestations.
pub const PREDICATE_TYPE: &str = "https://vci.dev/test-attestation/v1";

/// in-toto `predicateType` of a format-3 statement ([`VciPredicateV2`]).
pub const PREDICATE_TYPE_V2: &str = "https://vci.dev/test-attestation/v2";

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
    /// Rails adapter: the adapter names of the test environment's databases
    /// (Active Record's configurations), sorted and joined with `;`
    /// (`sqlite3`, `mysql2`, `postgresql;sqlite3`), compared exactly: a test
    /// that passes on SQLite may fail on MySQL. No server version (what a
    /// server holds or runs is not an input). Attestations made before vci
    /// 1.4.0 may hold `<adapter> <server version>`.
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

/// The `what` of a [`Toolchain::diff`] entry for a superuser difference.
pub const PRIVILEGES_DIFF: &str = "privileges";
/// The `what` of a [`Toolchain::diff`] entry for a `ruby_libs` difference.
pub const RUBY_LIBS_DIFF: &str = "ruby libraries";
/// The `what` of a [`Toolchain::diff`] entry for a `python_libs` difference.
pub const PYTHON_LIBS_DIFF: &str = "python libraries";

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
            (PYTHON_LIBS_DIFF, &self.python_libs, &now.python_libs),
            ("go", &self.go, &now.go),
            ("rustc", &self.rust, &now.rust),
            ("cargo", &self.cargo, &now.cargo),
            ("ruby", &self.ruby, &now.ruby),
            ("ruby engine", &self.ruby_engine, &now.ruby_engine),
            ("rails", &self.rails, &now.rails),
            ("bundler", &self.bundler, &now.bundler),
            ("ruby test framework", &self.ruby_test, &now.ruby_test),
            (RUBY_LIBS_DIFF, &self.ruby_libs, &now.ruby_libs),
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
                PRIVILEGES_DIFF,
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
    /// The git tree id of the checkout the unit ran in, when the working
    /// tree was clean (since vci 2.1.12; informational, like `commit`):
    /// what supersession keeps while any ref's tip still has that tree (a
    /// pull request's merge commit is on no ref once the pull request is
    /// squash-merged, but master's tip has its tree).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree: Option<String>,
    pub toolchain: Toolchain,
    pub global_input_root: String,
    pub input_root: String,
    /// The input manifest, embedded (attestations made before vci 1.9.0).
    /// Exactly one of `manifest` and [`Predicate::manifest_ref`] is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<InputManifest>,
    /// The input manifest by reference (since vci 1.9.0): its input root,
    /// which is `inputRoot`. The manifest is stored once, in its compact
    /// encoding ([`InputManifest::to_compact`]), under git-meta's `project`
    /// target, key `vci:manifest:<root>`, shared by every attestation with
    /// that root; it is trusted only when its recomputed root is the signed
    /// `inputRoot`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_ref: Option<String>,
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

/// The whole v1 predicate as signed: the [`Predicate`] core plus the fields
/// `vci run` adds (vci-cli's `VciPredicate` has the same fields and
/// serialises identically; it reads them from here once the plan runs on
/// [`ResolvedPredicate`]).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VciPredicate {
    #[serde(flatten)]
    pub core: Predicate,
    /// BLAKE3 over the effective env configuration for this test file.
    pub env_config_digest: String,
    /// Project dir relative to the repo root.
    pub project_dir: String,
    /// Runner project name (Vitest `projects`), empty if none.
    pub runner_project: String,
    /// `[[projects]]` name in vci.toml; empty (and omitted) in the
    /// single-project form, so those predicates serialise as before.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub project_name: String,
    /// Go: repository files of the test whose inclusion in the build depends
    /// on GOOS/GOARCH. When non-empty the attestation only holds on the
    /// attested OS and architecture, whatever `policy.platform` says.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platform_specific: Vec<String>,
    /// Go: why the test's results may differ on another architecture. When
    /// non-empty the attestation only holds on the attested architecture.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arch_specific: Vec<String>,
    /// Taints a policy waived when this attestation was made, as the
    /// collector reported them; `vci plan` accepts the attestation only
    /// while the base commit's policy still waives every one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waived: Vec<String>,
    /// Cargo: target-dependent `cfg(...)` predicates in the unit's
    /// repository code and manifests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cfg_predicates: Vec<String>,
    /// The `[[inputs]] extra` globs declared for this test id when it was
    /// attested.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_inputs: Vec<String>,
    /// The env variables vci set itself (vci.toml `[env] set`, since vci
    /// 1.6.0). Informational.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_set: Vec<String>,
    /// Rails (2.7.36): the project's `rails_inputs` when the unit was
    /// recorded, `"loose"` or `"strict"`; empty for the other adapters.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rails_inputs: String,
    /// Rails (2.7.36): the globs whose paths were left out of the unit's
    /// manifests. Informational.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored_inputs: Vec<String>,
}

/// The v2 predicate (store format 3, `design/STORE-V2.md` section 1.1):
/// the unit's own facts, the digests of its [`Hdr`] and [`Tables`] objects,
/// the entries root and its waived taints as ids into the tables' waiver
/// table. The subject carries the test id and the input root, as in v1;
/// everything of v1 that is not here is in the hdr. Fields are declared in
/// the order of their JSON names, and [`Self::to_json`] writes the compact
/// sorted-key form the statement is signed in; an empty list is omitted.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VciPredicateV2 {
    /// Go: see [`VciPredicate::arch_specific`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arch_specific: Vec<String>,
    pub argv: Vec<String>,
    /// Cargo: see [`VciPredicate::cfg_predicates`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cfg_predicates: Vec<String>,
    pub commit: String,
    /// See [`VciPredicate::declared_inputs`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_inputs: Vec<String>,
    /// [`InputManifest::entries_root`] of the unit's manifest, lowercase
    /// hex: supersession's "same files" test.
    pub entries_root: String,
    /// RFC 3339 UTC.
    pub expires_at: String,
    /// The id of the hdr object, 64 lowercase hex digits.
    pub hdr: String,
    /// RFC 3339 UTC.
    pub issued_at: String,
    /// Go: see [`VciPredicate::platform_specific`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platform_specific: Vec<String>,
    pub result: TestResult,
    /// The id of the tables object, 64 lowercase hex digits.
    pub tables: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tainted: Vec<String>,
    pub test_id: String,
    /// See [`Predicate::tree`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree: Option<String>,
    pub tree_dirty: bool,
    /// The waived taints as sorted distinct ids into the tables object's
    /// waiver table (section 1.6 rule 7: an id out of range, a duplicate or
    /// an unsorted list fails `statement`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waived: Vec<u16>,
}

/// `value` as compact JSON with the keys of every object sorted: the one
/// spelling a format-3 statement is signed in (the whole statement, not
/// only its predicate, is written this way).
pub fn sorted_compact_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    fn sorted(v: serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut pairs: Vec<(String, serde_json::Value)> = m.into_iter().collect();
                pairs.sort_by(|a, b| a.0.cmp(&b.0));
                let mut out = serde_json::Map::new();
                for (k, v) in pairs {
                    out.insert(k, sorted(v));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(a) => {
                serde_json::Value::Array(a.into_iter().map(sorted).collect())
            }
            other => other,
        }
    }
    serde_json::to_string(&sorted(serde_json::to_value(value)?))
}

impl VciPredicateV2 {
    /// The predicate as compact JSON with sorted keys ([`sorted_compact_json`]).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        sorted_compact_json(self)
    }

    /// The predicate of a statement's `predicate` member. Unknown members
    /// are ignored, as for v1; a reader never re-serializes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, PredicateError> {
        serde_json::from_slice(bytes).map_err(|e| PredicateError::Json(e.to_string()))
    }
}

/// Why a predicate cannot be resolved or converted. A v2 predicate that
/// fails one of these fails its candidate's `statement` check, and the unit
/// runs.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PredicateError {
    #[error("{field} is not 64 lowercase hex digits: {value:?}")]
    Hex { field: &'static str, value: String },
    #[error("the global manifest has externals or env entries")]
    GlobalManifest,
    #[error("waived {0:?} is not in the waiver table")]
    Waiver(String),
    #[error("waived id {id} is not below the waiver table's length {len}")]
    WaivedId { id: u16, len: usize },
    #[error("waived ids are not strictly increasing")]
    WaivedUnsorted,
    #[error("{what} object: its id {found} is not the statement's {expected}")]
    ObjectId {
        what: &'static str,
        expected: String,
        found: String,
    },
    #[error("{what} object: {source}")]
    Object {
        what: &'static str,
        #[source]
        source: DecodeError,
    },
    #[error("predicate JSON: {0}")]
    Json(String),
}

/// The context of a v2 predicate: what its `hdr` and `tables` objects decode
/// to, checked against the statement's ids ([`Context::decode`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Context {
    pub hdr: Hdr,
    pub tables: Tables,
}

impl Context {
    /// Decodes the bytes the store returned for the predicate's `hdr` and
    /// `tables` ids: an object whose BLAKE3 is not the signed id, or that
    /// breaks a decoder rule, is refused (section 1.5 step 5: the candidate
    /// fails `statement`).
    pub fn decode(
        p: &VciPredicateV2,
        hdr_bytes: &[u8],
        tables_bytes: &[u8],
    ) -> Result<Self, PredicateError> {
        check_id("hdr", &p.hdr, hdr_bytes)?;
        check_id("tables", &p.tables, tables_bytes)?;
        let hdr = Hdr::decode(hdr_bytes).map_err(|source| PredicateError::Object {
            what: "hdr",
            source,
        })?;
        let tables = Tables::decode(tables_bytes).map_err(|source| PredicateError::Object {
            what: "tables",
            source,
        })?;
        Ok(Context { hdr, tables })
    }

    /// The v1 view of `p` over this context; `input_root` is the subject's
    /// digest.
    pub fn resolve<'a>(
        &'a self,
        p: &'a VciPredicateV2,
        input_root: &'a str,
    ) -> Result<ResolvedPredicate<'a>, PredicateError> {
        ResolvedPredicate::v2(p, input_root, &self.hdr, &self.tables)
    }
}

fn check_id(what: &'static str, expected: &str, bytes: &[u8]) -> Result<(), PredicateError> {
    let found = hex32(&object_id(bytes));
    if found != expected {
        return Err(PredicateError::ObjectId {
            what,
            expected: expected.to_owned(),
            found,
        });
    }
    Ok(())
}

/// Sorted distinct ids below the table's length (section 1.6 rule 7).
fn check_waived_ids(ids: &[u16], len: usize) -> Result<(), PredicateError> {
    if let Some(&id) = ids.iter().find(|&&id| usize::from(id) >= len) {
        return Err(PredicateError::WaivedId { id, len });
    }
    if ids.windows(2).any(|w| w[0] >= w[1]) {
        return Err(PredicateError::WaivedUnsorted);
    }
    Ok(())
}

/// A predicate of either version read as the v1 fields: the plan's checks
/// and the storage key take every value from here (decoded values, never
/// bytes), so a v1 and a v2 record of the same facts are checked alike.
#[derive(Debug, Clone, Copy)]
pub enum ResolvedPredicate<'a> {
    V1(&'a VciPredicate),
    V2 {
        statement: &'a VciPredicateV2,
        /// The subject's digest (v2 carries the input root nowhere else).
        input_root: &'a str,
        hdr: &'a Hdr,
        tables: &'a Tables,
    },
}

impl<'a> ResolvedPredicate<'a> {
    pub fn v1(p: &'a VciPredicate) -> Self {
        ResolvedPredicate::V1(p)
    }

    /// The view of a v2 predicate over its decoded objects (the caller
    /// checked their ids, [`Context::decode`]); the waived ids are checked
    /// against the waiver table here, so [`Self::waived`] cannot fail.
    pub fn v2(
        statement: &'a VciPredicateV2,
        input_root: &'a str,
        hdr: &'a Hdr,
        tables: &'a Tables,
    ) -> Result<Self, PredicateError> {
        check_waived_ids(&statement.waived, tables.waivers.len())?;
        Ok(ResolvedPredicate::V2 {
            statement,
            input_root,
            hdr,
            tables,
        })
    }

    /// 1 or 2.
    pub fn version(&self) -> u8 {
        match self {
            ResolvedPredicate::V1(_) => 1,
            ResolvedPredicate::V2 { .. } => 2,
        }
    }

    pub fn tool_version(&self) -> &'a str {
        match self {
            ResolvedPredicate::V1(p) => &p.core.tool_version,
            ResolvedPredicate::V2 { hdr, .. } => &hdr.tool_version,
        }
    }

    pub fn adapter(&self) -> &'a str {
        match self {
            ResolvedPredicate::V1(p) => &p.core.adapter,
            ResolvedPredicate::V2 { hdr, .. } => &hdr.adapter,
        }
    }

    pub fn test_id(&self) -> &'a str {
        match self {
            ResolvedPredicate::V1(p) => &p.core.test_id,
            ResolvedPredicate::V2 { statement, .. } => &statement.test_id,
        }
    }

    pub fn argv(&self) -> &'a [String] {
        match self {
            ResolvedPredicate::V1(p) => &p.core.argv,
            ResolvedPredicate::V2 { statement, .. } => &statement.argv,
        }
    }

    pub fn repo_id(&self) -> &'a str {
        match self {
            ResolvedPredicate::V1(p) => &p.core.repo_id,
            ResolvedPredicate::V2 { hdr, .. } => &hdr.repo_id,
        }
    }

    pub fn commit(&self) -> &'a str {
        match self {
            ResolvedPredicate::V1(p) => &p.core.commit,
            ResolvedPredicate::V2 { statement, .. } => &statement.commit,
        }
    }

    pub fn tree_dirty(&self) -> bool {
        match self {
            ResolvedPredicate::V1(p) => p.core.tree_dirty,
            ResolvedPredicate::V2 { statement, .. } => statement.tree_dirty,
        }
    }

    pub fn tree(&self) -> Option<&'a str> {
        match self {
            ResolvedPredicate::V1(p) => p.core.tree.as_deref(),
            ResolvedPredicate::V2 { statement, .. } => statement.tree.as_deref(),
        }
    }

    pub fn toolchain(&self) -> &'a Toolchain {
        match self {
            ResolvedPredicate::V1(p) => &p.core.toolchain,
            ResolvedPredicate::V2 { hdr, .. } => &hdr.toolchain,
        }
    }

    /// Lowercase hex.
    pub fn global_input_root(&self) -> Cow<'a, str> {
        match self {
            ResolvedPredicate::V1(p) => Cow::Borrowed(&p.core.global_input_root),
            ResolvedPredicate::V2 { hdr, .. } => Cow::Owned(hex32(&hdr.global_input_root)),
        }
    }

    /// Lowercase hex: the subject's digest.
    pub fn input_root(&self) -> &'a str {
        match self {
            ResolvedPredicate::V1(p) => &p.core.input_root,
            ResolvedPredicate::V2 { input_root, .. } => input_root,
        }
    }

    /// The global manifest the plan rehashes (its root must be
    /// [`Self::global_input_root`]).
    pub fn global_manifest(&self) -> Cow<'a, InputManifest> {
        match self {
            ResolvedPredicate::V1(p) => Cow::Borrowed(&p.core.global_manifest),
            ResolvedPredicate::V2 { hdr, .. } => Cow::Owned(hdr.global_manifest()),
        }
    }

    pub fn result(&self) -> &'a TestResult {
        match self {
            ResolvedPredicate::V1(p) => &p.core.result,
            ResolvedPredicate::V2 { statement, .. } => &statement.result,
        }
    }

    pub fn tainted(&self) -> &'a [String] {
        match self {
            ResolvedPredicate::V1(p) => &p.core.tainted,
            ResolvedPredicate::V2 { statement, .. } => &statement.tainted,
        }
    }

    pub fn issued_at(&self) -> &'a str {
        match self {
            ResolvedPredicate::V1(p) => &p.core.issued_at,
            ResolvedPredicate::V2 { statement, .. } => &statement.issued_at,
        }
    }

    pub fn expires_at(&self) -> &'a str {
        match self {
            ResolvedPredicate::V1(p) => &p.core.expires_at,
            ResolvedPredicate::V2 { statement, .. } => &statement.expires_at,
        }
    }

    /// Lowercase hex.
    pub fn env_config_digest(&self) -> Cow<'a, str> {
        match self {
            ResolvedPredicate::V1(p) => Cow::Borrowed(&p.env_config_digest),
            ResolvedPredicate::V2 { hdr, .. } => Cow::Owned(hex32(&hdr.env_config_digest)),
        }
    }

    pub fn project_dir(&self) -> &'a str {
        match self {
            ResolvedPredicate::V1(p) => &p.project_dir,
            ResolvedPredicate::V2 { hdr, .. } => &hdr.project_dir,
        }
    }

    pub fn runner_project(&self) -> &'a str {
        match self {
            ResolvedPredicate::V1(p) => &p.runner_project,
            ResolvedPredicate::V2 { hdr, .. } => &hdr.runner_project,
        }
    }

    pub fn project_name(&self) -> &'a str {
        match self {
            ResolvedPredicate::V1(p) => &p.project_name,
            ResolvedPredicate::V2 { hdr, .. } => &hdr.project_name,
        }
    }

    pub fn platform_specific(&self) -> &'a [String] {
        match self {
            ResolvedPredicate::V1(p) => &p.platform_specific,
            ResolvedPredicate::V2 { statement, .. } => &statement.platform_specific,
        }
    }

    pub fn arch_specific(&self) -> &'a [String] {
        match self {
            ResolvedPredicate::V1(p) => &p.arch_specific,
            ResolvedPredicate::V2 { statement, .. } => &statement.arch_specific,
        }
    }

    /// The waived taint strings: v1's list as signed; v2's ids resolved
    /// through the waiver table (sorted and distinct by construction).
    pub fn waived(&self) -> Vec<&'a str> {
        match self {
            ResolvedPredicate::V1(p) => p.waived.iter().map(String::as_str).collect(),
            ResolvedPredicate::V2 {
                statement, tables, ..
            } => statement
                .waived
                .iter()
                .map(|&i| tables.waivers[usize::from(i)].as_str())
                .collect(),
        }
    }

    pub fn cfg_predicates(&self) -> &'a [String] {
        match self {
            ResolvedPredicate::V1(p) => &p.cfg_predicates,
            ResolvedPredicate::V2 { statement, .. } => &statement.cfg_predicates,
        }
    }

    pub fn declared_inputs(&self) -> &'a [String] {
        match self {
            ResolvedPredicate::V1(p) => &p.declared_inputs,
            ResolvedPredicate::V2 { statement, .. } => &statement.declared_inputs,
        }
    }

    pub fn env_set(&self) -> &'a [String] {
        match self {
            ResolvedPredicate::V1(p) => &p.env_set,
            ResolvedPredicate::V2 { hdr, .. } => &hdr.env_set,
        }
    }

    pub fn rails_inputs(&self) -> &'a str {
        match self {
            ResolvedPredicate::V1(p) => &p.rails_inputs,
            ResolvedPredicate::V2 { hdr, .. } => &hdr.rails_inputs,
        }
    }

    pub fn ignored_inputs(&self) -> &'a [String] {
        match self {
            ResolvedPredicate::V1(p) => &p.ignored_inputs,
            ResolvedPredicate::V2 { hdr, .. } => &hdr.ignored_inputs,
        }
    }

    /// The hdr object's id (v2 only), lowercase hex.
    pub fn hdr_id(&self) -> Option<&'a str> {
        match self {
            ResolvedPredicate::V1(_) => None,
            ResolvedPredicate::V2 { statement, .. } => Some(&statement.hdr),
        }
    }

    /// The tables object's id (v2 only), lowercase hex.
    pub fn tables_id(&self) -> Option<&'a str> {
        match self {
            ResolvedPredicate::V1(_) => None,
            ResolvedPredicate::V2 { statement, .. } => Some(&statement.tables),
        }
    }

    /// The signed entries root (v2 only), lowercase hex.
    pub fn entries_root(&self) -> Option<&'a str> {
        match self {
            ResolvedPredicate::V1(_) => None,
            ResolvedPredicate::V2 { statement, .. } => Some(&statement.entries_root),
        }
    }
}

fn hex_field(field: &'static str, value: &str) -> Result<[u8; 32], PredicateError> {
    parse_hex32(value).ok_or_else(|| PredicateError::Hex {
        field,
        value: value.to_owned(),
    })
}

impl VciPredicate {
    /// The hdr object of this predicate's run (section 1.1: the fields that
    /// moved out of the statement). Every run at the same toolchain and
    /// global inputs makes the same one. The digests must be 64 lowercase
    /// hex digits and the global manifest must be entries only.
    pub fn hdr(&self) -> Result<Hdr, PredicateError> {
        let gm = &self.core.global_manifest;
        if !gm.externals.is_empty() || !gm.env.is_empty() {
            return Err(PredicateError::GlobalManifest);
        }
        let mut global_manifest: Vec<InputEntry> = gm.entries.clone();
        global_manifest.sort();
        global_manifest.dedup();
        Ok(Hdr {
            repo_id: self.core.repo_id.clone(),
            adapter: self.core.adapter.clone(),
            project_name: self.project_name.clone(),
            project_dir: self.project_dir.clone(),
            runner_project: self.runner_project.clone(),
            tool_version: self.core.tool_version.clone(),
            rails_inputs: self.rails_inputs.clone(),
            env_config_digest: hex_field("envConfigDigest", &self.env_config_digest)?,
            global_input_root: hex_field("globalInputRoot", &self.core.global_input_root)?,
            global_manifest,
            ignored_inputs: self.ignored_inputs.clone(),
            env_set: self.env_set.clone(),
            toolchain: self.core.toolchain.clone(),
        })
    }

    /// The v2 predicate of the same facts, for a run whose hdr and tables
    /// objects have the ids `hdr` and `tables_id` and whose tables object
    /// is `tables` (its waiver table must hold every waived string; the ids
    /// are the sorted distinct positions, so repeated strings collapse);
    /// `entries_root` is [`InputManifest::entries_root`] of the unit's
    /// manifest. Used by tests and by `vci run` for the facts it has in v1
    /// form.
    pub fn to_v2(
        &self,
        hdr: &ObjectId,
        tables_id: &ObjectId,
        tables: &Tables,
        entries_root: &str,
    ) -> Result<VciPredicateV2, PredicateError> {
        let mut waived: Vec<u16> = Vec::with_capacity(self.waived.len());
        for w in &self.waived {
            let i = tables
                .waivers
                .binary_search(w)
                .map_err(|_| PredicateError::Waiver(w.clone()))?;
            waived.push(u16::try_from(i).map_err(|_| PredicateError::WaivedId {
                id: u16::MAX,
                len: tables.waivers.len(),
            })?);
        }
        waived.sort_unstable();
        waived.dedup();
        Ok(VciPredicateV2 {
            arch_specific: self.arch_specific.clone(),
            argv: self.core.argv.clone(),
            cfg_predicates: self.cfg_predicates.clone(),
            commit: self.core.commit.clone(),
            declared_inputs: self.declared_inputs.clone(),
            entries_root: entries_root.to_owned(),
            expires_at: self.core.expires_at.clone(),
            hdr: hex32(hdr),
            issued_at: self.core.issued_at.clone(),
            platform_specific: self.platform_specific.clone(),
            result: self.core.result.clone(),
            tables: hex32(tables_id),
            tainted: self.core.tainted.clone(),
            test_id: self.core.test_id.clone(),
            tree: self.core.tree.clone(),
            tree_dirty: self.core.tree_dirty,
            waived,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::Encoded;
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
            tree: None,
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
            manifest: Some(manifest),
            manifest_ref: None,
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
    fn a_manifest_by_reference_omits_the_inline_manifest() {
        let mut p = sample();
        let root = p.input_root.clone();
        p.manifest = None;
        p.manifest_ref = Some(root.clone());
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("manifest").is_none(), "{v}");
        assert_eq!(v["manifestRef"], root.as_str());
        let back: Predicate = serde_json::from_value(v).unwrap();
        assert_eq!(back, p);
        // A pre-1.9 predicate (inline manifest, no manifestRef) still reads.
        let old = serde_json::to_value(sample()).unwrap();
        assert!(old.get("manifestRef").is_none());
        let back: Predicate = serde_json::from_value(old).unwrap();
        assert!(back.manifest.is_some() && back.manifest_ref.is_none());
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
            ("database", |t| t.ruby_db = "mysql2".into()),
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

    // ------------------------------------------------------------ v2 ----

    /// A v1 predicate with every field set, as a Go unit with waivers and
    /// declared inputs would carry it; the lists are sorted and distinct,
    /// as `vci run` writes them.
    fn sample_v1() -> VciPredicate {
        let mut core = sample();
        core.tree = Some("t".repeat(40));
        core.global_input_root = "ab".repeat(32);
        core.global_manifest = InputManifest {
            entries: vec![
                InputEntry {
                    path: RepoPath::new("go.sum").unwrap(),
                    kind: EntryKind::File,
                    exec: false,
                    size: 7,
                    hash: "cd".repeat(32),
                },
                InputEntry {
                    path: RepoPath::new("go.mod").unwrap(),
                    kind: EntryKind::File,
                    exec: true,
                    size: 3,
                    hash: "ef".repeat(32),
                },
            ],
            externals: vec![],
            env: vec![],
        };
        core.tainted = vec!["go:net:dial".into()];
        core.toolchain = Toolchain {
            go: "go1.26.2".into(),
            go_env: vec!["CGO_ENABLED=1".into(), "GOFLAGS=".into()],
            go_arch_level: "GOARM64=v8.0".into(),
            os: "macos".into(),
            arch: "aarch64".into(),
            superuser: true,
            ..Default::default()
        };
        VciPredicate {
            core,
            env_config_digest: "12".repeat(32),
            project_dir: "svc/api".into(),
            runner_project: "unit".into(),
            project_name: "api".into(),
            platform_specific: vec!["a_darwin.go".into()],
            arch_specific: vec!["fma".into()],
            waived: vec!["go:net:dial: a".into(), "go:unsafe: b".into()],
            cfg_predicates: vec!["cfg(x)".into()],
            declared_inputs: vec!["fixtures/**".into()],
            env_set: vec!["TZ".into()],
            rails_inputs: "loose".into(),
            ignored_inputs: vec!["log/**".into()],
        }
    }

    /// The tables object of a run holding `p` and one more unit.
    fn tables_for(p: &VciPredicate) -> Tables {
        let mut waivers = p.waived.clone();
        waivers.push("cargo:undeclared-reads: c".into());
        waivers.sort();
        waivers.dedup();
        Tables {
            waivers,
            env_names: vec!["HOME".into(), "TZ".into()],
            externals: vec![External {
                name: "ms".into(),
                version: "2.1.3".into(),
            }],
        }
    }

    /// `p` as a v2 statement with its hdr and tables encoded, as a run
    /// would write them; the manifest's entries root is of `sample`'s.
    fn convert(p: &VciPredicate) -> (VciPredicateV2, Encoded<Hdr>, Encoded<Tables>) {
        let hdr = p.hdr().unwrap();
        let hdr = Encoded::new(hdr.clone(), hdr.encode().unwrap());
        let tables = tables_for(p);
        let tables = Encoded::new(tables.clone(), tables.encode().unwrap());
        let root = p.core.manifest.as_ref().unwrap().entries_root();
        let v2 = p.to_v2(&hdr.id, &tables.id, &tables.value, &root).unwrap();
        (v2, hdr, tables)
    }

    #[test]
    fn v2_predicate_type_is_the_v2_url() {
        assert_eq!(PREDICATE_TYPE_V2, "https://vci.dev/test-attestation/v2");
        assert_ne!(PREDICATE_TYPE_V2, PREDICATE_TYPE);
    }

    #[test]
    fn v2_json_is_compact_with_sorted_keys_and_round_trips() {
        let (v2, _, _) = convert(&sample_v1());
        let json = v2.to_json().unwrap();
        assert!(!json.contains(' ') && !json.contains('\n'), "{json}");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "{json}");
        assert_eq!(
            keys,
            [
                "archSpecific",
                "argv",
                "cfgPredicates",
                "commit",
                "declaredInputs",
                "entriesRoot",
                "expiresAt",
                "hdr",
                "issuedAt",
                "platformSpecific",
                "result",
                "tables",
                "tainted",
                "testId",
                "tree",
                "treeDirty",
                "waived",
            ]
        );
        // Nested objects are sorted too (TestResult's v1 order is not).
        let result: Vec<&str> = v["result"]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(
            result,
            ["durationMs", "failed", "skipped", "state", "tests"]
        );
        assert_eq!(v["waived"], serde_json::json!([1, 2]));
        assert_eq!(v["hdr"].as_str().unwrap().len(), 64);
        // The whole statement goes through the same writer.
        let stmt = sorted_compact_json(&serde_json::json!({
            "subject": [{"name": "x", "digest": {"blake3": "0"}}],
            "_type": "s",
            "predicateType": PREDICATE_TYPE_V2,
            "predicate": v2,
        }))
        .unwrap();
        assert!(stmt.starts_with("{\"_type\":\"s\",\"predicate\":{\"archSpecific\""));
        assert!(stmt.contains("\"digest\":{\"blake3\":\"0\"},\"name\":\"x\""));
        let back = VciPredicateV2::from_json(json.as_bytes()).unwrap();
        assert_eq!(back, v2);
        assert_eq!(back.to_json().unwrap(), json);
    }

    #[test]
    fn v2_json_omits_empty_lists_and_reads_them_back_empty() {
        let (mut v2, _, _) = convert(&sample_v1());
        v2.arch_specific.clear();
        v2.cfg_predicates.clear();
        v2.declared_inputs.clear();
        v2.platform_specific.clear();
        v2.tainted.clear();
        v2.waived.clear();
        v2.tree = None;
        let json = v2.to_json().unwrap();
        for k in [
            "archSpecific",
            "cfgPredicates",
            "declaredInputs",
            "platformSpecific",
            "tainted",
            "waived",
            "tree",
        ] {
            assert!(!json.contains(&format!("\"{k}\":")), "{k} in {json}");
        }
        for k in [
            "argv",
            "commit",
            "entriesRoot",
            "expiresAt",
            "hdr",
            "issuedAt",
            "result",
            "tables",
            "testId",
            "treeDirty",
        ] {
            assert!(json.contains(&format!("\"{k}\":")), "{k} not in {json}");
        }
        assert_eq!(VciPredicateV2::from_json(json.as_bytes()).unwrap(), v2);
        assert!(matches!(
            VciPredicateV2::from_json(b"{\"argv\":[]}"),
            Err(PredicateError::Json(_))
        ));
        assert!(VciPredicateV2::from_json(b"not json").is_err());
    }

    /// Every accessor of the resolved view gives, for a v1 predicate
    /// converted to v2 with its hdr and tables (both through their encoded
    /// bytes, the v2 through its JSON), what it gives for the v1.
    #[test]
    fn resolved_predicate_parity_between_v1_and_v2() {
        let p = sample_v1();
        let (v2, hdr, tables) = convert(&p);
        let v2 = VciPredicateV2::from_json(v2.to_json().unwrap().as_bytes()).unwrap();
        let ctx = Context::decode(&v2, &hdr.bytes, &tables.bytes).unwrap();
        assert_eq!(ctx.hdr, hdr.value);
        assert_eq!(ctx.tables, tables.value);
        let a = ResolvedPredicate::v1(&p);
        let b = ctx.resolve(&v2, &p.core.input_root).unwrap();
        assert_eq!((a.version(), b.version()), (1, 2));
        assert_eq!(a.tool_version(), b.tool_version());
        assert_eq!(a.adapter(), b.adapter());
        assert_eq!(a.test_id(), b.test_id());
        assert_eq!(a.argv(), b.argv());
        assert_eq!(a.repo_id(), b.repo_id());
        assert_eq!(a.commit(), b.commit());
        assert_eq!(a.tree_dirty(), b.tree_dirty());
        assert_eq!(a.tree(), b.tree());
        assert_eq!(a.toolchain(), b.toolchain());
        assert_eq!(a.global_input_root(), b.global_input_root());
        assert_eq!(a.input_root(), b.input_root());
        // The hdr holds the entries sorted; the root does not depend on the order.
        assert_eq!(a.global_manifest().root(), b.global_manifest().root());
        assert_eq!(
            b.global_manifest().entries,
            p.hdr().unwrap().global_manifest
        );
        assert_eq!(a.result(), b.result());
        assert_eq!(a.tainted(), b.tainted());
        assert_eq!(a.issued_at(), b.issued_at());
        assert_eq!(a.expires_at(), b.expires_at());
        assert_eq!(a.env_config_digest(), b.env_config_digest());
        assert_eq!(a.project_dir(), b.project_dir());
        assert_eq!(a.runner_project(), b.runner_project());
        assert_eq!(a.project_name(), b.project_name());
        assert_eq!(a.platform_specific(), b.platform_specific());
        assert_eq!(a.arch_specific(), b.arch_specific());
        assert_eq!(a.waived(), b.waived());
        assert_eq!(a.cfg_predicates(), b.cfg_predicates());
        assert_eq!(a.declared_inputs(), b.declared_inputs());
        assert_eq!(a.env_set(), b.env_set());
        assert_eq!(a.rails_inputs(), b.rails_inputs());
        assert_eq!(a.ignored_inputs(), b.ignored_inputs());
        assert_eq!(a.hdr_id(), None);
        assert_eq!(b.hdr_id(), Some(v2.hdr.as_str()));
        assert_eq!(b.tables_id(), Some(v2.tables.as_str()));
        assert_eq!(
            b.entries_root().unwrap(),
            p.core.manifest.as_ref().unwrap().entries_root()
        );
        assert_eq!(b.hdr_id().unwrap(), crate::objects::hex32(&hdr.id));
        // The same holds with every optional field empty.
        let mut p = sample_v1();
        p.core.tree = None;
        p.core.tainted.clear();
        p.waived.clear();
        p.platform_specific.clear();
        p.arch_specific.clear();
        p.cfg_predicates.clear();
        p.declared_inputs.clear();
        p.env_set.clear();
        p.ignored_inputs.clear();
        p.rails_inputs.clear();
        p.project_name.clear();
        let (v2, hdr, tables) = convert(&p);
        let b = ResolvedPredicate::v2(&v2, &p.core.input_root, &hdr.value, &tables.value).unwrap();
        let a = ResolvedPredicate::v1(&p);
        assert_eq!(a.tree(), None);
        assert_eq!(b.tree(), None);
        assert!(b.waived().is_empty() && b.tainted().is_empty());
        assert_eq!(a.project_name(), b.project_name());
        assert_eq!(a.rails_inputs(), b.rails_inputs());
        assert_eq!(a.env_set(), b.env_set());
    }

    #[test]
    fn v1_to_hdr_conversion_rules() {
        let p = sample_v1();
        let h = p.hdr().unwrap();
        assert_eq!(h.repo_id, "r");
        assert_eq!(h.adapter, "vitest");
        assert_eq!(h.project_name, "api");
        assert_eq!(h.project_dir, "svc/api");
        assert_eq!(h.runner_project, "unit");
        assert_eq!(h.tool_version, "0.1.0");
        assert_eq!(h.rails_inputs, "loose");
        assert_eq!(h.env_config_digest, [0x12; 32]);
        assert_eq!(h.global_input_root, [0xab; 32]);
        assert_eq!(
            h.global_manifest
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            ["go.mod", "go.sum"],
            "sorted"
        );
        assert_eq!(h.ignored_inputs, ["log/**"]);
        assert_eq!(h.env_set, ["TZ"]);
        assert_eq!(h.toolchain, p.core.toolchain);
        // The hdr round trips through its bytes, so a v1 record's facts
        // name one object.
        assert_eq!(Hdr::decode(&h.encode().unwrap()).unwrap(), h);
        // A duplicate global entry collapses.
        let mut d = p.clone();
        let e = d.core.global_manifest.entries[0].clone();
        d.core.global_manifest.entries.push(e);
        assert_eq!(d.hdr().unwrap(), h);
        // The digests must be lowercase hex.
        let mut bad = p.clone();
        bad.env_config_digest = "AB".repeat(32);
        assert_eq!(
            bad.hdr(),
            Err(PredicateError::Hex {
                field: "envConfigDigest",
                value: "AB".repeat(32),
            })
        );
        let mut bad = p.clone();
        bad.core.global_input_root = "g".into();
        assert!(matches!(
            bad.hdr(),
            Err(PredicateError::Hex {
                field: "globalInputRoot",
                ..
            })
        ));
        // A global manifest with externals or env is not a hdr's.
        let mut bad = p.clone();
        bad.core.global_manifest.env.push(EnvEntry {
            key: "TZ".into(),
            hash: crate::ABSENT_HASH.into(),
        });
        assert_eq!(bad.hdr(), Err(PredicateError::GlobalManifest));
    }

    #[test]
    fn v1_to_v2_waived_ids_are_sorted_distinct_positions_in_the_table() {
        let p = sample_v1();
        let tables = tables_for(&p);
        let id = [7; 32];
        let v2 = p.to_v2(&id, &id, &tables, "e").unwrap();
        assert_eq!(v2.waived, [1, 2]);
        assert_eq!(v2.hdr, "07".repeat(32));
        assert_eq!(v2.entries_root, "e");
        // Repeated and unsorted strings (a v1 unit lists a taint per
        // occurrence) collapse to the set.
        let mut dup = p.clone();
        dup.waived = vec![
            "go:unsafe: b".into(),
            "go:net:dial: a".into(),
            "go:unsafe: b".into(),
        ];
        let d = dup.to_v2(&id, &id, &tables, "e").unwrap();
        assert_eq!(d.waived, [1, 2]);
        let hdr = p.hdr().unwrap();
        let r = ResolvedPredicate::v2(&d, "i", &hdr, &tables).unwrap();
        assert_eq!(r.waived(), ["go:net:dial: a", "go:unsafe: b"]);
        // A string the table lacks cannot be converted.
        let mut missing = p.clone();
        missing.waived.push("rails:network-db: x".into());
        assert_eq!(
            missing.to_v2(&id, &id, &tables, "e"),
            Err(PredicateError::Waiver("rails:network-db: x".into()))
        );
    }

    /// Section 1.6 rule 7: the resolved view refuses an id out of range, a
    /// duplicate and an unsorted list, so `waived()` never indexes past the
    /// table.
    #[test]
    fn resolved_v2_checks_the_waived_ids() {
        let p = sample_v1();
        let (v2, hdr, tables) = convert(&p);
        let ok = |w: Vec<u16>| {
            let mut s = v2.clone();
            s.waived = w;
            ResolvedPredicate::v2(&s, "i", &hdr.value, &tables.value).map(|r| {
                r.waived()
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(ok(vec![]), Ok(vec![]));
        assert_eq!(
            ok(vec![0, 2]),
            Ok(vec![
                "cargo:undeclared-reads: c".to_owned(),
                "go:unsafe: b".to_owned()
            ])
        );
        assert_eq!(ok(vec![3]), Err(PredicateError::WaivedId { id: 3, len: 3 }));
        assert_eq!(
            ok(vec![0, 65535]),
            Err(PredicateError::WaivedId { id: 65535, len: 3 })
        );
        assert_eq!(ok(vec![1, 1]), Err(PredicateError::WaivedUnsorted));
        assert_eq!(ok(vec![2, 1]), Err(PredicateError::WaivedUnsorted));
        let empty = Tables::default();
        let mut s = v2.clone();
        s.waived = vec![0];
        assert_eq!(
            ResolvedPredicate::v2(&s, "i", &hdr.value, &empty).err(),
            Some(PredicateError::WaivedId { id: 0, len: 0 })
        );
    }

    /// Section 1.5 step 5: an object whose id is not the signed one, or
    /// that does not decode, fails the context.
    #[test]
    fn context_decode_checks_ids_and_decoding() {
        let p = sample_v1();
        let (v2, hdr, tables) = convert(&p);
        // The objects swapped: both ids are wrong.
        let e = Context::decode(&v2, &tables.bytes, &hdr.bytes).unwrap_err();
        assert_eq!(
            e,
            PredicateError::ObjectId {
                what: "hdr",
                expected: v2.hdr.clone(),
                found: crate::objects::hex32(&tables.id),
            }
        );
        let e = Context::decode(&v2, &hdr.bytes, &hdr.bytes).unwrap_err();
        assert!(
            matches!(e, PredicateError::ObjectId { what: "tables", .. }),
            "{e}"
        );
        // A statement naming the id of corrupt bytes: the id matches, the
        // decode does not.
        let mut corrupt = hdr.bytes.clone();
        corrupt.push(0);
        let mut s = v2.clone();
        s.hdr = crate::objects::hex32(&crate::objects::object_id(&corrupt));
        let e = Context::decode(&s, &corrupt, &tables.bytes).unwrap_err();
        assert!(
            matches!(
                e,
                PredicateError::Object {
                    what: "hdr",
                    source: DecodeError::Trailing(1)
                }
            ),
            "{e}"
        );
        let mut s = v2.clone();
        s.tables = crate::objects::hex32(&crate::objects::object_id(b"vo"));
        let e = Context::decode(&s, &hdr.bytes, b"vo").unwrap_err();
        assert!(
            matches!(e, PredicateError::Object { what: "tables", .. }),
            "{e}"
        );
        // Upper-case hex in the statement never matches (one spelling).
        let mut s = v2.clone();
        s.hdr = s.hdr.to_uppercase();
        assert!(matches!(
            Context::decode(&s, &hdr.bytes, &tables.bytes),
            Err(PredicateError::ObjectId { what: "hdr", .. })
        ));
        assert!(Context::decode(&v2, &hdr.bytes, &tables.bytes).is_ok());
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
