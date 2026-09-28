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

pub enum EntryKind { File, Symlink, Absent, DirListing, Dir, Excluded }   // Dir: a real directory, type only (hash = blake3("dir"), size 0)
                                                                   // Excluded: build output (never an input; left out of its parent's DirListing; hash = blake3("excluded"), size 0, never compared)
pub struct InputEntry { pub path: RepoPath, pub kind: EntryKind, pub exec: bool, pub size: u64, pub hash: String }
pub struct External { pub name: String, pub version: String }
pub struct EnvEntry { pub key: String, pub hash: String }   // blake3 of value; ABSENT_HASH if unset

pub enum Observation { Read, Probe, ReadDir, Stat, Exclude }  // what the collector saw; Stat: type only (file -> File, dir -> Dir); Exclude -> Excluded

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

pub struct Toolchain {                  // adapter-specific; unused fields are empty and omitted from JSON
    pub node: String, pub vitest: String, pub vite: String,              // Vitest
    pub python: String, pub implementation: String, pub pytest: String,  // pytest (python = major.minor.patch)
    pub python_libs: String,          // pytest: "sqlite=<ver>;openssl=<OPENSSL_VERSION>"
    pub python_dists: Vec<String>,    // pytest: every installed distribution, sorted "name==version"
    pub go: String,                   // Go: go env GOVERSION
    pub go_env: Vec<String>,          // Go: sorted "KEY=value" of effective CGO_ENABLED, GODEBUG, GOEXPERIMENT, GOFIPS140, GOFLAGS, GOWORK (project-relative)
    pub go_arch_level: String,        // Go: "GOARM64=v8.0" / "GOAMD64=v1" ...; compared only when arch is equal
    pub rust: String,                 // Cargo: rustc -vV "<release> <commit-hash> LLVM <version>"
    pub cargo: String,                // Cargo: cargo -vV "<release> <commit-hash>"
    pub rust_host: String,            // Cargo: host triple; compared only when os and arch are equal
    pub rust_cfg: Vec<String>,        // Cargo: sorted `rustc --print cfg` (with the build's rustflags); compared only when rust_host is equal
    pub superuser: bool,              // every adapter: the tests ran as root (effective uid 0); compared exactly; omitted when false
    pub os: String, pub arch: String,
}
impl Toolchain { pub fn diff(&self, now: &Toolchain) -> Vec<(&'static str, String, String)>; } // node by major, go_arch_level on the same arch, rust_host/rust_cfg on the same platform, rest exact
pub struct TestResult { pub state: String /* "passed" | "failed" */, pub tests: u32, pub failed: u32, pub skipped: u32, pub duration_ms: u64 }
// is_pass(): state == "passed" && failed == 0 && skipped == 0 (a skipped or xfailed test did not run)
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
{"kind":"stat","path":"/abs/path"}         // pytest only: type observed (realpath() walking a component)
{"kind":"env","key":"TZ"}
{"kind":"taint","reason":"child_process.spawn"}
{"kind":"result","state":"passed","tests":1,"failed":0,"skipped":0,"durationMs":12}
```

Paths are absolute; `testId` is relative to the project root with '/' separators. Rust normalises and hashes.

## vci-adapter (as built)

```rust
pub type ChildEnv = Option<Vec<(OsString, OsString)>>;   // None = inherit; Some = env_clear + exactly these
pub struct ListedFile { pub abs: Utf8PathBuf, pub project: String }
pub struct ToolVersions { pub node: String, pub runner: String, pub bundler: String, pub python: String, pub implementation: String,
                         pub python_libs: String, pub python_dists: Vec<String>,
                         pub go_env: Vec<String>, pub go_arch_level: String, pub go_work: String /* abs go.work, "" or "off" */,
                         pub cargo: String, pub rust_host: String, pub rust_cfg: Vec<String> /* Cargo; runner = rustc */ }
pub type InstalledExternals = BTreeMap<String, Vec<String>>;   // PEP 503 name -> installed versions
pub struct Observed {            // one per collector JSONL file; anything unexpected becomes a taint
    pub test_id: String, pub project: String, pub root: String, pub node: String,
    pub runner_version: String, pub bundler_version: String, pub collector: String,
    pub adapter: String /* meta.adapter, "vitest" if absent */, pub python: String, pub implementation: String,
    pub platform: String, pub arch: String,
    pub modules, reads, probes, readdirs, stats, writes: BTreeSet<Utf8PathBuf>,
    pub platform_files: BTreeSet<Utf8PathBuf>,   // Go: repository files built only for some GOOS/GOARCH;
                                                 // Cargo: files whose code checks the platform in a way cfg evaluation cannot
    pub cfg_predicates: BTreeSet<String>,        // Cargo: normalised target-dependent cfg predicates of repository code/manifests
    pub path_refs: BTreeMap<Utf8PathBuf, String>, // Cargo: paths the source opens outside the package dirs -> where; must be recorded inputs
    pub excluded: BTreeSet<Utf8PathBuf>,          // Cargo: target dir, repo .git and .vci/out met in a walked dir (Observation::Exclude)
    pub externals: BTreeSet<(String, String)>, pub env_keys: BTreeSet<String>,
    pub taints: Vec<String>, pub result: Option<vci_core::TestResult>,
}
pub struct RunOutput { pub exit_code: Option<i32>, pub files: Vec<Observed> }
pub trait Adapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn project_dir(&self) -> &Utf8Path;
    fn list_test_files(&self, env: &ChildEnv) -> Result<Vec<ListedFile>, AdapterError>;   // vitest list --filesOnly --json=<tmp>
    fn tool_versions(&self) -> Result<ToolVersions, AdapterError>;
    fn tool_versions_with_env(&self, env: &ChildEnv) -> Result<ToolVersions, AdapterError>;  // default: tool_versions()
    fn builtin_pass_through(&self) -> &'static [&'static str];                                // default: []
    fn hashed_env_patterns(&self) -> &'static [&'static str];     // default: []; pytest: PYTHON*, PYTEST_*, !PYTHONPATH (hashed if present, not kept in strict mode)
    fn warnings(&self, env: &ChildEnv) -> Vec<String>;           // default: []; pytest: interpreter not uv-managed
    fn installed_externals(&self, env: &ChildEnv) -> Result<Option<InstalledExternals>, AdapterError>; // default: None
    fn canonical_argv(&self, project_dir_rel_to_repo: &str, project_rel: &str) -> Vec<String>; // ["vitest","run","--root",dir,file]
    fn config_candidates(&self) -> Vec<Utf8PathBuf>;
    fn snapshot_candidates(&self, test_abs: &Utf8Path) -> Vec<Utf8PathBuf>;
    fn inferred_env_patterns(&self) -> &'static [&'static str];   // ["VITE_*"]
    fn run_collect(&self, files: &[String], env: &ChildEnv) -> Result<RunOutput, AdapterError>;
    fn run_plain(&self, files: &[String], env: &ChildEnv) -> Result<Option<i32>, AdapterError>;
    fn scratch_dirs(&self) -> Vec<Utf8PathBuf>;   // default: []; Cargo: the target dir (not snapshotted by `vci run`)
}
pub struct VitestAdapter;  // VitestAdapter::new(project_dir).with_js_plugin(dir)
pub fn find_js_plugin(project_dir: &Utf8Path) -> Result<Utf8PathBuf, AdapterError>; // $VCI_JS_PLUGIN, else node_modules/@vci/vitest
pub struct PytestAdapter;  // PytestAdapter::new(project_dir).with_py_plugin(dir)
pub fn find_py_plugin(project_dir: &Utf8Path) -> Result<Utf8PathBuf, AdapterError>; // $VCI_PY_PLUGIN, else py/pytest-plugin near the exe / build checkout / project
pub struct GoAdapter;      // GoAdapter::new(project_dir); `go` from $VCI_GO
pub struct CargoAdapter;   // CargoAdapter::new(project_dir); `cargo` from $VCI_CARGO
pub fn adapter_for(name: &str, project_dir: &Utf8Path) -> Result<Box<dyn Adapter>, AdapterError>; // "vitest" | "pytest" | "go" | "cargo"
pub const PYTEST_CONFIG_NAMES: &[&str];   // pytest.toml, .pytest.toml, pytest.ini, .pytest.ini, pyproject.toml, tox.ini, setup.cfg
pub const PYTEST_PASS_THROUGH: &[&str];   // UV, UV_*, VIRTUAL_ENV, PYTHONPATH, XDG_*_HOME, SSL_CERT_*, *_PROXY
pub const GO_PASS_THROUGH: &[&str];      // GOPATH, GOROOT, GOCACHE, GOMODCACHE, GOENV, GOPROXY, ..., XDG_*, SSL_CERT_*, *_PROXY
pub const GO_HASHED_ENV: &[&str];        // GO*, CGO_*, minus the pass-through GO* names
pub const GO_ALWAYS_READ_ENV: &[&str];   // TZ, ZONEINFO
pub const GO_NET_TAINT: &str;            // "go:net:" (the only taint policy.go_allow_net waives)
pub const CARGO_PASS_THROUGH: &[&str];   // CARGO_HOME, RUSTUP_*, CARGO_TARGET_DIR, CARGO_NET_*, CARGO_HTTP_*, RUSTC_WRAPPER, SCCACHE_*, ...
pub const CARGO_HASHED_ENV: &[&str];     // RUST*, CARGO*, CC, CFLAGS, ..., minus the pass-through names
pub const CARGO_UNDECLARED_TAINT: &str;  // "cargo:undeclared-reads" (waived by declaring [[inputs]] for the unit)
pub fn cfg_predicate_differs(pred: &str, attested_cfg: &[String], current_cfg: &[String]) -> Result<bool, String>;
pub fn unit_package_dir(unit: &Utf8Path) -> Utf8PathBuf;   // "<dir>#<target>" -> "<dir>"
pub fn parse_jsonl_file(path) / parse_jsonl_dir(dir);  // top-level *.jsonl only
```

`run_collect` writes the wrapper config into a fresh temp dir (via `writeWrapperConfig` from `@vci/vitest/wrapper`),
runs `node node_modules/vitest/vitest.mjs run --config <wrapper> <files…>` with `VCI_OUT=<fresh temp dir>` and cwd =
project dir, and sends Vitest's stdout to stderr so the CLI's stdout stays machine-readable.

### pytest adapter

All commands run with cwd = project dir through `uv run --locked --exact --no-env-file` (`$VCI_UV`, default `uv`;
`UV_RUN_ARGS`), with the child env applied, `UV_ENV_FILE` removed, `UV_NO_ENV_FILE=1`,
`PYTHONPYCACHEPREFIX=<fresh temp dir>` (bytecode is always compiled from the hashed sources) and `PYTHONPATH` removed
unless set below:

- `list_test_files`: `uv run --locked pytest --collect-only -q -p vci_list` with `PYTHONPATH=<tmp>` holding a helper
  plugin that writes the files of the collected items as JSON (independent of the configured verbosity). Exit codes
  other than 0 and 5 (no tests) — e.g. a collection error — are errors, so `vci plan` runs everything.
- `tool_versions_with_env` / `installed_externals`: one `uv run --locked python <tmp>/vci_probe.py` (cached per
  adapter) reporting `platform.python_version()`, `sys.implementation.name`, `pytest.__version__`, the bundled sqlite
  and OpenSSL versions, `sys.base_prefix` and every installed distribution (PEP 503 names).
- `run_collect`: one process per file, `$VCI_JOBS` (default CPUs, max 8) at a time:
  `PYTHONPATH=<plugin dir> VCI_OUT=<fresh dir> uv run --locked pytest -p vci_pytest <file>`; each process's output is
  written to stderr as one block; exit code 0 only if every process exited 0.
- `run_plain`: with files, one `uv run pytest <file>` process per file (`$VCI_JOBS` at a time, output in blocks), the
  isolation attestations are made with; without files, the whole suite in one process.
- `canonical_argv`: `["pytest", "--rootdir", <project dir>, <file>]`; `config_candidates`: the pytest config names
  in the project dir; no snapshot candidates or inferred env patterns; hashed env patterns `PYTHON*`, `PYTEST_*`,
  `!PYTHONPATH`.

Collector records (`docs/spike-pytest.md`): `meta` has `adapter: "pytest"`, `python`, `implementation`, `pytest`,
`platform`, `arch`; `write` records are parsed into `Observed::writes` (the CLI refuses to attest a file with a write
inside the repository); an `env` record with key `*` (environment enumerated) becomes a taint; unknown kinds stay
taints.

### Go adapter

The unit is a package directory with `_test.go` files; `ListedFile::abs` is the package directory and the test id
the directory relative to the repository root (`.` for a module root at the repository root). All commands run
with cwd = project dir (the module root; `go env GOMOD` must be its `go.mod`) and the child env applied:

- `list_test_files`: `go list -json ./...`, packages with `TestGoFiles` or `XTestGoFiles`; a failing `go list` or a
  package `Error` is an error (so `vci plan` runs everything).
- `tool_versions_with_env`: `go env -json GOVERSION GOOS GOARCH GOHOSTOS GOHOSTARCH GOROOT GOMOD GOWORK GOFLAGS
  CGO_ENABLED GOEXPERIMENT GOFIPS140 GODEBUG GOAMD64 GOARM64 ...` (cached per adapter); `runner` = GOVERSION.
  GOOS/GOARCH other than the host's, or a project dir that is not the module root, is an error.
- `installed_externals`: `go list -m -json all`, module path -> `version` (or `version => path@version` for a
  replacement, `local:<dir>` for a directory replacement).
- `run_collect`: `go list -e -deps -test -json <./pkg...>` once, then per package (at most `$VCI_JOBS` at a time)
  `TMPDIR=<fresh> VCI_GO_TESTLOG=<file> go test -count=1 -json -overlay=<json> ./pkg`, where the overlay adds
  `vci_testlog.go` to `$GOROOT/src/internal/testlog`. The log (`start|getenv|open|stat|chdir|exec|taint
  <Go-quoted string>` lines) and the test2json events become one `Observed` per package: `modules` = compile-time
  files, `readdirs` = package and go:embed directories plus directories opened, `reads`/`stats`/`probes` from the
  log (classified by what exists after the run), `externals` = modules as (path, version), `taints` = closure
  analysis, `exec` records and log problems, `env_keys` = looked-up names minus `PWD`/`TMPDIR` plus `TZ`/`ZONEINFO`.
  `GOFLAGS` with `-overlay`, `-modfile` or `-pgo=<file>` is an error.
- `run_plain`: `go test -count=1 -json <./pkg... | ./...>` with a fresh TMPDIR; the events' `Output` is written to
  stderr as text.
- `canonical_argv`: `["go", "test", "-C", <project dir>, "-count=1", "-json", "./<pkg>"]`; `config_candidates`:
  `go.mod`, `go.sum`, `go.work`, `go.work.sum`; no snapshot candidates or inferred patterns; built-in pass-through
  `GO_PASS_THROUGH`; hashed patterns `GO_HASHED_ENV`.

### Cargo adapter

The unit is a cargo test target of a workspace member; `ListedFile::abs` is `<abs package dir>#<target>` and the test id
`<repo-relative package dir>#<target>` (`.#lib` for a package at the repository root), `<target>` one of `lib`, `doc`,
`bin:<name>`, `test:<name>`, `example:<name>`, `bench:<name>`. The project dir must be the workspace root (`cargo
metadata` `workspace_root`) and hold `Cargo.lock`. All commands run with cwd = project dir and the child env applied:

- `list_test_files`: `cargo metadata --format-version 1 --locked --no-deps`, the targets `cargo test --workspace` runs
  (`test`/`doctest` flags, `required-features` on by default). Any error (no Cargo.lock, not the workspace root) is an
  error, so `vci plan` runs everything.
- `tool_versions_with_env` (cached): `cargo -vV`, then the `rustc` next to that cargo (or `$RUSTC`): `rustc -vV`,
  `rustc --print cfg <RUSTFLAGS>`, `rustc --print sysroot`. Errors: `CARGO_BUILD_TARGET` set; a cargo config outside the
  repository with keys that change the build; an in-repository config setting `build.rustc`/`rustdoc`/`target`.
- `installed_externals`: Cargo.lock, name -> `version source checksum` (every locked version).
- `run_collect`: first `cargo clean --locked --target-dir <target dir>/vci -p <every workspace member>` (the
  repository's crates are always rebuilt; a repository crate reported `fresh` that was not cleaned in this run is
  cleaned and its unit run again, once, else the unit is tainted), then per unit, one at a time, `TMPDIR=<fresh> cargo test --locked --manifest-path <pkg>/Cargo.toml
  <--lib|--doc|--bin n|--test n|--example n|--bench n> --message-format=json --target-dir <target dir>/vci`. The JSON
  messages (`compiler-artifact` with `manifest_path`, `filenames`, `features`; `build-script-executed` with `out_dir`,
  `linked_libs`, `linked_paths`) become one `Observed`: `modules` = every file of every repository crate's package dir
  plus dep-info files, `readdirs` = every directory there (symlinked directories walked at their target),
  `excluded` = the target dir / repo `.git` / repo `.vci/out` where a walked directory holds them, `probes` = missing
  `rerun-if-changed` paths, `externals` = (name, `version source checksum`; registry crates checked against their
  `.crate` and the lock checksum, git checkouts against the locked commit, other out-of-repo sources refused),
  `env_keys` = dep-info env deps, `rerun-if-env-changed` and literal `env::var` names, `cfg_predicates` (sources,
  manifests, repository config `[target.'cfg(..)']` tables), `platform_files`, `path_refs`, `taints` = static checks of
  every dep-info file (any extension, OUT_DIR code included), config (runner/linker, wrappers other than sccache) and
  problems. The result:
  `passed` needs exit 0, no failure, nothing filtered out and at least one test (`no-tests`, `filtered`, `failed`
  otherwise); ignored tests count in `tests`, `skipped` is 0.
- `run_plain`: with units, `cargo test --locked --manifest-path ... <target> --target-dir <target dir>/vci` per unit,
  one at a time, fresh TMPDIR, output to stderr; without, `cargo test --locked --workspace`.
- `canonical_argv`: `["cargo", "test", "--locked", "--manifest-path", "<pkg>/Cargo.toml", <selector>...]`;
  `config_candidates`: `Cargo.toml`, `Cargo.lock`; built-in pass-through `CARGO_PASS_THROUGH`; hashed patterns
  `CARGO_HASHED_ENV`; `scratch_dirs`: the target dir.

## vci-cli predicate and storage

The signed predicate is `vci_core::Predicate` flattened, plus `envConfigDigest` (docs/ENV.md), `projectDir` (repo
relative), `runnerProject` (Vitest project name), `projectName` (the `[[projects]]` name; omitted in the
single-project form), and for Go `platformSpecific` (repository files built only for some GOOS/GOARCH, or whose
code refers to `GOOS`/`GOARCH`: the attestation then needs the same OS and architecture), `archSpecific` (why the
results may differ on another architecture, i.e. floating-point code in a non-standard package of the closure: the
attestation then needs the same architecture) and `waived` (refusals waived by `policy.go_allow_net`, which
the base policy must still waive), for Cargo `cfgPredicates` (checked against `toolchain.rustCfg` and the verifying
host's cfg set), and for every adapter `declaredInputs` (the `[[inputs]] extra` globs of the test id, which must equal
the base config's); all omitted when empty. Statement subject: `[{ name: testId, digest: { blake3: inputRoot } }]`.
`input_root` is the per-file manifest root; `global_input_root` is the per-file global manifest root (lockfiles,
package.json, `.npmrc`, config candidates and their relative references, tsconfig chain, `vci.toml`, the test's
snapshot file, and the `NODE_OPTIONS` env hash; for pytest: `vci.toml`, `pyproject.toml`/`uv.lock`/`.python-version`/
`uv.toml` from the project dir up to the repo root, and every pytest config name and `conftest.py` from the test's
directory up to the project dir; for Go: `vci.toml`, `go.mod`/`go.sum`/`go.work`/`go.work.sum` from the project dir
up to the repo root and `vendor/modules.txt` in the project dir; for Cargo: `vci.toml`, `Cargo.toml` from the package dir
up to the repo root, `Cargo.lock`/`rust-toolchain(.toml)`/`.cargo/config(.toml)` from the project dir up to the repo
root). The store key passed to `AttestStore::put` as `input_root` is BLAKE3 over repo id,
test id, input root, global input root, env config digest, toolchain and argv (plus the pytest toolchain fields, the
project name, the Go and Rust toolchain fields, `platformSpecific`, `archSpecific`, `waived`, `cfgPredicates`, `declaredInputs` and a
non-Vitest adapter name when set), so re-running with identical inputs replaces (renews) the
stored envelope.

## Environment variables

See `docs/ENV.md`. It is part of the design: `vci.toml` `[env]` config with strict/loose mode, declared and pass-through patterns, hashed into each test file input root and checked in `vci plan`.
