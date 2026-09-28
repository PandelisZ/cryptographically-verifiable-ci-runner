# Crate contracts

These interfaces are fixed so crates can be built in parallel. Extend them if needed, but don't rename or remove what is listed. Read `docs/PLAN.md` for the full design.

General rules: errors via `thiserror` enums in library crates; hashes are lowercase hex strings; all serde types derive `Serialize, Deserialize, Debug, Clone, PartialEq, Eq`; JSON field names are camelCase.

## vci-core (no dependency on other workspace crates)

```rust
pub struct RepoPath(String);              // repo-relative, '/' separators, no '..', no leading '/'
impl RepoPath {
    pub fn new(s: &str) -> Result<Self, PathError>;
    pub fn from_abs(repo_root: &Utf8Path, abs: &Utf8Path) -> Result<Self, PathError>; // Err if outside repo
    pub fn as_str(&self) -> &str;
}

pub enum EntryKind { File, Symlink, Absent, DirListing }
pub struct InputEntry { pub path: RepoPath, pub kind: EntryKind, pub exec: bool, pub size: u64, pub hash: String }
pub struct External { pub name: String, pub version: String }
pub struct EnvEntry { pub key: String, pub hash: String }   // blake3 of value; ABSENT_HASH if unset

pub enum Observation { Read, Probe, ReadDir }  // what the collector saw

pub struct InputManifest { pub entries: Vec<InputEntry>, pub externals: Vec<External>, pub env: Vec<EnvEntry> }
impl InputManifest {
    /// Build from observations by hashing the working tree. Sorts and dedups.
    pub fn capture(repo_root: &Utf8Path, observed: &[(RepoPath, Observation)], externals: Vec<External>, env_keys: &[String]) -> Result<Self, ManifestError>;
    /// Deterministic blake3 root as described in PLAN.md "Data model".
    pub fn root(&self) -> String;
    /// Re-hash the same paths/kinds/env keys from `repo_root` + current env and list differences. Externals are compared by the caller.
    pub fn diff_against_checkout(&self, repo_root: &Utf8Path) -> Result<Vec<Mismatch>, ManifestError>;
    /// Err if two entry paths collide under case folding.
    pub fn check_case_collisions(&self) -> Result<(), ManifestError>;
}
pub struct Mismatch { pub what: String, pub expected: String, pub actual: String }

pub struct Toolchain { pub node: String, pub vitest: String, pub vite: String, pub os: String, pub arch: String }
pub struct TestResult { pub state: String /* "passed" | "failed" */, pub tests: u32, pub failed: u32, pub skipped: u32, pub duration_ms: u64 }
pub struct Predicate {
    pub tool_version: String, pub adapter: String, pub test_id: String, pub argv: Vec<String>,
    pub repo_id: String, pub commit: String, pub tree_dirty: bool,
    pub toolchain: Toolchain, pub global_input_root: String, pub input_root: String,
    pub manifest: InputManifest, pub global_manifest: InputManifest,
    pub result: TestResult, pub tainted: Vec<String>,
    pub issued_at: String, pub expires_at: String,   // RFC 3339 UTC
}
pub const PREDICATE_TYPE: &str = "https://vci.dev/test-attestation/v1";
pub fn test_key(test_id: &str) -> String;   // blake3 hex of test id, used as storage key
```

## vci-attest (no dependency on other workspace crates; predicate is `serde_json::Value`)

```rust
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const NAMESPACE: &str = "vci-attest";

pub struct Subject { pub name: String, pub digest: BTreeMap<String, String> }
pub struct Statement { pub type_: String /* "_type" */, pub subject: Vec<Subject>, pub predicate_type: String /* "predicateType" */, pub predicate: serde_json::Value }
pub struct Signature { pub keyid: String, pub sig: String }   // sig = base64 of the SSHSIG PEM armor
pub struct Envelope { pub payload_type: String, pub payload: String /* base64 */, pub signatures: Vec<Signature> }

pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8>;
/// Shells out to `ssh-keygen -Y sign -n vci-attest -f <key>`; key may be a private key path or a .pub path whose private half is in ssh-agent.
pub fn sign_statement(statement: &Statement, key_path: &Utf8Path) -> Result<Envelope, SignError>;

pub struct AllowedSigners { /* entries */ }
impl AllowedSigners { pub fn parse(text: &str) -> Result<Self, AllowedSignersError>; }

pub struct Verified { pub principal: String, pub fingerprint: String /* "SHA256:..." */, pub statement: Statement, pub payload: Vec<u8> }
/// Pure Rust. `now` is unix seconds. Checks payload type, SSHSIG over PAE, namespace, hash alg, signer in allowed list with namespaces/valid-after/valid-before honoured, cert-authority entries rejected.
pub fn verify_envelope(envelope: &Envelope, allowed: &AllowedSigners, now: i64) -> Result<Verified, VerifyError>;
```

`VerifyError` variants must be distinguishable: `Malformed`, `WrongPayloadType`, `BadSignature`, `WrongNamespace`, `UnknownSigner`, `SignerNotValidNow`, `NoSignatures`.

## vci-git (no dependency on other workspace crates; shells out to `git`)

```rust
pub struct Repo { /* root path */ }
impl Repo {
    pub fn discover(start: &Utf8Path) -> Result<Self, GitError>;
    pub fn root(&self) -> &Utf8Path;
    pub fn repo_id(&self) -> Result<String, GitError>;        // first root commit sha (sorted, first)
    pub fn head_commit(&self) -> Result<String, GitError>;
    pub fn is_dirty(&self) -> Result<bool, GitError>;
    pub fn resolve(&self, rev: &str) -> Result<String, GitError>;
    pub fn merge_base(&self, a: &str, b: &str) -> Result<String, GitError>;
    /// `git show <rev>:<path>`; Ok(None) if the path doesn't exist at that rev.
    pub fn show_file(&self, rev: &str, path: &str) -> Result<Option<Vec<u8>>, GitError>;
}

pub const REF_PREFIX: &str = "refs/attest/v1/";
pub struct StoredEnvelope { pub signer_ref: String, pub test_key: String, pub input_root: String, pub bytes: Vec<u8> }
pub struct AttestStore<'a> { /* &Repo */ }
impl<'a> AttestStore<'a> {
    pub fn new(repo: &'a Repo) -> Self;
    /// Adds `<test_key[0..2]>/<test_key>/<input_root>.dsse.json` to refs/attest/v1/<signer_id> as a new commit, without touching the index or working tree.
    pub fn put(&self, signer_id: &str, test_key: &str, input_root: &str, bytes: &[u8]) -> Result<(), GitError>;
    pub fn list(&self, test_key: Option<&str>) -> Result<Vec<StoredEnvelope>, GitError>;   // across all signer refs
    pub fn fetch(&self, remote: &str) -> Result<(), GitError>;   // into refs/attest-remote/v1/*, then union-merge into local refs
    pub fn push(&self, remote: &str) -> Result<(), GitError>;    // fetch+merge+push, retry on rejection
}
```

`signer_id` is 16 lowercase hex chars derived by the caller. Use plumbing (`hash-object -w`, `mktree`/temporary index via `GIT_INDEX_FILE`, `commit-tree`, `update-ref`). Set committer identity explicitly via env so it works where no git user is configured.

## js/vitest-plugin (`@vci/vitest`)

Invoked by the Rust adapter as: `VCI_OUT=<dir> npx vitest run --config <wrapper config> <files…>` with cwd = project dir. The package exports a Vite/Vitest plugin as default export from its main entry, and a helper entry that the wrapper config can use. It writes `$VCI_OUT/<sha256 hex of testId>.jsonl`, one JSON object per line:

```
{"v":1,"kind":"meta","testId":"src/b.test.ts","project":"","vitest":"5.0.2","vite":"8.x","node":"26.9.0","root":"/abs/project"}
{"kind":"module","path":"/abs/path/src/b.ts","via":"vite-graph"}
{"kind":"external","name":"ms","version":"2.1.3"}
{"kind":"read","path":"/abs/path"}
{"kind":"probe","path":"/abs/path"}        // stat/exists/read that failed with ENOENT
{"kind":"readdir","path":"/abs/path"}
{"kind":"env","key":"TZ"}
{"kind":"taint","reason":"child_process.spawn"}
{"kind":"result","state":"passed","tests":1,"failed":0,"skipped":0,"durationMs":12}
```

Paths are absolute; `testId` is relative to the project root with '/' separators. Rust normalises and hashes.

## vci-adapter (as built)

```rust
pub type ChildEnv = Option<Vec<(OsString, OsString)>>;   // None = inherit; Some = env_clear + exactly these
pub struct ListedFile { pub abs: Utf8PathBuf, pub project: String }
pub struct ToolVersions { pub node: String, pub runner: String, pub bundler: String }
pub struct Observed {            // one per collector JSONL file; anything unexpected becomes a taint
    pub test_id: String, pub project: String, pub root: String, pub node: String,
    pub runner_version: String, pub bundler_version: String, pub collector: String,
    pub modules, reads, probes, readdirs: BTreeSet<Utf8PathBuf>,
    pub externals: BTreeSet<(String, String)>, pub env_keys: BTreeSet<String>,
    pub taints: Vec<String>, pub result: Option<vci_core::TestResult>,
}
pub struct RunOutput { pub exit_code: Option<i32>, pub files: Vec<Observed> }
pub trait Adapter {
    fn name(&self) -> &'static str;
    fn project_dir(&self) -> &Utf8Path;
    fn list_test_files(&self, env: &ChildEnv) -> Result<Vec<ListedFile>, AdapterError>;   // vitest list --filesOnly --json=<tmp>
    fn tool_versions(&self) -> Result<ToolVersions, AdapterError>;
    fn canonical_argv(&self, project_dir_rel_to_repo: &str, project_rel: &str) -> Vec<String>; // ["vitest","run","--root",dir,file]
    fn config_candidates(&self) -> Vec<Utf8PathBuf>;
    fn snapshot_candidates(&self, test_abs: &Utf8Path) -> Vec<Utf8PathBuf>;
    fn inferred_env_patterns(&self) -> &'static [&'static str];   // ["VITE_*"]
    fn run_collect(&self, files: &[String], env: &ChildEnv) -> Result<RunOutput, AdapterError>;
    fn run_plain(&self, files: &[String], env: &ChildEnv) -> Result<Option<i32>, AdapterError>;
}
pub struct VitestAdapter;  // VitestAdapter::new(project_dir).with_js_plugin(dir)
pub fn find_js_plugin(project_dir: &Utf8Path) -> Result<Utf8PathBuf, AdapterError>; // $VCI_JS_PLUGIN, else node_modules/@vci/vitest
pub fn parse_jsonl_file(path) / parse_jsonl_dir(dir);  // top-level *.jsonl only
```

`run_collect` writes the wrapper config into a fresh temp dir (via `writeWrapperConfig` from `@vci/vitest/wrapper`),
runs `node node_modules/vitest/vitest.mjs run --config <wrapper> <files…>` with `VCI_OUT=<fresh temp dir>` and cwd =
project dir, and sends Vitest's stdout to stderr so the CLI's stdout stays machine-readable.

## vci-cli predicate and storage

The signed predicate is `vci_core::Predicate` flattened, plus `envConfigDigest` (docs/ENV.md), `projectDir` (repo
relative) and `runnerProject` (Vitest project name). Statement subject: `[{ name: testId, digest: { blake3: inputRoot } }]`.
`input_root` is the per-file manifest root; `global_input_root` is the per-file global manifest root (lockfiles,
package.json, `.npmrc`, config candidates and their relative references, tsconfig chain, `vci.toml`, the test's
snapshot file, and the `NODE_OPTIONS` env hash). The store key passed to `AttestStore::put` as `input_root` is
BLAKE3 over repo id, test id, input root, global input root, env config digest, toolchain and argv, so re-running
with identical inputs replaces (renews) the stored envelope.

## Environment variables

See `docs/ENV.md`. It is part of the design: `vci.toml` `[env]` config with strict/loose mode, declared and pass-through patterns, hashed into each test file input root and checked in `vci plan`.
