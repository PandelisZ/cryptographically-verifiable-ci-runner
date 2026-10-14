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
    pub ruby: String, pub ruby_engine: String,   // Rails: "3.4.9p82", "ruby 3.4.9"
    pub rails: String, pub bundler: String,      // Rails: Rails and Bundler versions
    pub ruby_test: String,            // Rails: "minitest 6.0.6" (+ "; rspec-core 3.13.6, rspec-expectations ..., rspec-mocks ..., rspec-rails ..., rspec-support ..." when the bundle has RSpec)
    pub ruby_libs: String,            // Rails: "sqlite=<ver>;yaml=<ver>;tz=<tzinfo-data|zoneinfo ver>;encoding=<ext>/<int>"
    pub ruby_db: String,              // Rails: "sqlite3", or "<adapter> <server version>" with policy.rails_allow_db
    pub ruby_gems: Vec<String>,       // Rails: the resolved bundle, sorted "name==version" (no platform)
    pub superuser: bool,              // every adapter: the tests ran as root (effective uid 0); compared exactly; omitted when false
    pub os: String, pub arch: String,
}
impl Toolchain { pub fn diff(&self, now: &Toolchain) -> Vec<(&'static str, String, String)>; } // node by major, go_arch_level on the same arch, rust_host/rust_cfg on the same platform, rest exact (Rails fields all exact)
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

pub struct StoredEnvelope {
    pub target: String,       // git-meta target: "path:<unit path>" or "project"
    pub key: String,          // "vci:attestation:<test_key>:<signer>:<storage_key>"
    pub test_key: String, pub signer: String, pub storage_key: String,
    pub bytes: Vec<u8>,       // the DSSE envelope, exactly as stored (empty when `error` is set)
    pub error: Option<String>,// the value could not be read (missing blob, unfetched value): fails only this candidate
}
pub struct FetchOutcome { pub remote: String, pub found: bool, pub warnings: Vec<String>, pub notes: Vec<String> }
pub enum PushStatus { Pushed, UpToDate, NothingStored }
pub struct PushOutcome { pub remote: String, pub status: PushStatus, pub warnings: Vec<String>, pub notes: Vec<String> }
pub struct AttestStore<'a> { /* &Repo */ }
impl<'a> AttestStore<'a> {
    pub fn new(repo: &'a Repo) -> Self;
    /// Sets the git-meta string value in the local store (.git/git-meta.sqlite); no serialize, no push,
    /// never touches the index or working tree. Identical bytes: no write.
    pub fn put(&self, test_id: &str, signer: &str, storage_key: &str, bytes: &[u8]) -> Result<StoredEnvelope, GitError>;
    pub fn list(&self, test_id: Option<&str>) -> Result<Vec<StoredEnvelope>, GitError>;
    pub fn reader(&self) -> Result<Reader, GitError>;      // many per-unit lookups; read-only SQLite, no lock, creates nothing
    pub fn remove(&self, e: &StoredEnvelope) -> Result<bool, GitError>;   // git-meta tombstone
    pub fn ensure_remote(&self, spec: Option<&str>) -> Result<String, GitError>;
    pub fn fetch(&self, remote: Option<&str>) -> Result<FetchOutcome, GitError>; // git-meta pull
    pub fn push(&self, remote: Option<&str>) -> Result<PushOutcome, GitError>;   // git-meta push, retried
}
```

Exchange invariants (`fetch`, `push`; both hold one lock per repository, shared by its worktrees, and retry when
another git process wins a ref lock):

- Before serializing, the store is made to cover `refs/<ns>/local/main`: values of that ref the store has no row and
  no deletion record for are copied in, and its deletion records newer than the store's row are applied. (git-meta
  serializes the store alone as a commit on top of that ref; a new, emptied or replaced `.git/git-meta.sqlite`, or a
  linked worktree, whose store is its own while the refs are shared, would otherwise publish deletions.)
- A serialization that drops a value the previous local commit held, without a deletion record in the store, is
  undone and is an error (a `meta:filter` rule excluding or routing the key). A push that drops a value of the remote
  tip that this store did not delete is refused.
- Tree entries git-meta cannot read (names that are not UTF-8, targets it cannot serialize such as a path target
  under 3 bytes) are left out: the fetched tip is replaced by a deterministic commit on top of it without them, which
  a later push publishes. Store rows git-meta cannot serialize are deleted.
- `fetch` and `push` report shared settings that affect attestations (`meta:prune:*`, filter rules) and values the
  remote dropped without a deletion record.
- A `.git-meta` URL (from the checkout) must be an https/http/ssh/git/file URL, an scp-like address or a path; remote
  helpers (`fd::`, `ext::`, `<x>::`) are refused.

Storage is [git-meta](https://git-meta.com/) (`git-meta-lib` 0.1.13, embedded): target `path:<unit path>` (the test id
up to `#`; `project` when git-meta cannot hold it as a path target: `.` or shorter than 3 bytes), key
`vci:attestation:<blake3(test_id)>:<signer>:<storage_key>`, value the envelope. `signer` is 16 lowercase hex chars and
`storage_key` lowercase hex, both validated. Exchange is on `refs/<meta.namespace or meta>/main` with git-meta's merge;
transport is the git CLI with a scrubbed environment; the metadata commit vci rewrites for push uses a fixed
committer identity, so it works where no git user is configured.

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
                         pub cargo: String, pub rust_host: String, pub rust_cfg: Vec<String> /* Cargo; runner = rustc */,
                         pub ruby: String, pub ruby_engine: String, pub rails: String, pub ruby_bundler: String,
                         pub ruby_libs: String, pub ruby_db: String, pub ruby_gems: Vec<String> /* Rails; runner = "minitest <ver>[; rspec-core <ver>, ...]" */ }
pub struct AdapterOptions { pub rails_allow_db: bool, pub rails_runner: Option<RailsRunner> }   // settings that change how an adapter runs tests
pub enum RailsRunner { Minitest, Rspec }   // vci.toml `runner` ("minitest" | "rspec") of a rails project
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
    pub ruby: String, pub ruby_engine: String, pub rails: String, pub ruby_bundler: String,   // Rails collector meta
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
pub fn adapter_for(name: &str, project_dir: &Utf8Path) -> Result<Box<dyn Adapter>, AdapterError>; // "vitest" | "pytest" | "go" | "cargo" | "rails"
pub fn adapter_for_with(name: &str, project_dir: &Utf8Path, opts: &AdapterOptions) -> Result<Box<dyn Adapter>, AdapterError>;
pub struct RailsAdapter;   // RailsAdapter::new(project_dir).with_collector(dir).with_allow_db(bool).with_runner(Option<RailsRunner>); `ruby` from $VCI_RUBY
pub fn find_ruby_collector(project_dir: &Utf8Path) -> Result<Utf8PathBuf, AdapterError>; // $VCI_RUBY_COLLECTOR, else ruby/vci-collector near the exe / build checkout / project
pub const PYTEST_CONFIG_NAMES: &[&str];   // pytest.toml, .pytest.toml, pytest.ini, .pytest.ini, pyproject.toml, tox.ini, setup.cfg
pub const PYTEST_PASS_THROUGH: &[&str];   // UV, UV_*, VIRTUAL_ENV, PYTHONPATH, XDG_*_HOME, SSL_CERT_*, *_PROXY
pub const GO_PASS_THROUGH: &[&str];      // GOPATH, GOROOT, GOCACHE, GOMODCACHE, GOENV, GOPROXY, ..., XDG_*, SSL_CERT_*, *_PROXY
pub const GO_HASHED_ENV: &[&str];        // GO*, CGO_*, minus the pass-through GO* names
pub const GO_ALWAYS_READ_ENV: &[&str];   // TZ, ZONEINFO
pub const GO_NET_TAINT: &str;            // "go:net:" (the only taint policy.go_allow_net waives)
pub const CARGO_PASS_THROUGH: &[&str];   // CARGO_HOME, RUSTUP_*, CARGO_TARGET_DIR, CARGO_NET_*, CARGO_HTTP_*, RUSTC_WRAPPER, SCCACHE_*, ...
pub const CARGO_HASHED_ENV: &[&str];     // RUST*, CARGO*, CC, CFLAGS, ..., minus the pass-through names
pub const CARGO_UNDECLARED_TAINT: &str;  // "cargo:undeclared-reads" (waived by declaring [[inputs]] for the unit)
pub const RAILS_PASS_THROUGH: &[&str];   // GEM_HOME, GEM_PATH, BUNDLE_PATH and Bundler's location/install settings, MISE_*, RBENV_*, ...
pub const RAILS_HASHED_ENV: &[&str];     // RUBY*, RAILS_*, RACK_*, BUNDLE_*, BUNDLER_*, GEM_*, DATABASE_URL, MT_*, ... minus pass-through and vci-set
pub const RAILS_RUN_VARS: &[&str];       // RUBYOPT, RAILS_ENV, RACK_ENV, BUNDLE_GEMFILE, PARALLEL_WORKERS, DISABLE_SPRING, DISABLE_BOOTSNAP
pub const RAILS_NETWORK_DB_TAINT: &str;  // "rails:network-db:" (the only taint policy.rails_allow_db waives)
pub const RAILS_SCRATCH_DIRS: &[&str];   // log, tmp, storage, coverage (git-ignored writes there are allowed)
pub const RAILS_GLOBAL_FILES: &[&str];   // Gemfile, Gemfile.lock, gems.rb, gems.locked, .ruby-version, ..., config/application.rb, bin/rails, test/test_helper.rb
pub const RSPEC_GLOBAL_FILES: &[&str];   // .rspec (RSpec files: RAILS_GLOBAL_FILES without test/test_helper.rb, plus these)
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

### Rails adapter

The unit is a test file of one of two runners. **Minitest**: `test/**/*_test.rb` without
`test/{system,dummy,fixtures}/**`, listed in Rust; the project dir is the application root (it must hold `bin/rails`).
**RSpec**: the files `rspec` would run with no file argument, listed by RSpec itself (see below). Which runner a
project uses: `runner = "minitest" | "rspec"` (top level in the single-project form, or in its `[[projects]]` entry;
read from the base commit in `vci plan`), else detected: RSpec when the lockfile has a `rspec-core` spec and `spec/`
(or `.rspec`) exists with no Minitest file; both when both are present (a file under the Minitest rule is a Minitest
file, every other listed file an RSpec file; if RSpec's listing contains a Minitest file, `list_test_files` is an error
that asks for the setting); Minitest otherwise. With Minitest only, RSpec files (`spec/**/*_spec.rb`) are an error for
`list_test_files` and `run_plain(&[])` when there is no Minitest file, else a warning (likewise Minitest files under
`runner = "rspec"`: a warning). An RSpec project without `config/environment.rb` (a gem) is a plain Ruby project: the
probe only sets up the bundle and the Rails version may be empty.

Every Ruby process runs `ruby <args>` (`$VCI_RUBY`, default `ruby`) with cwd = project dir, the child env applied,
`RUBYLIB` removed, and `RUBYOPT=-r<collector>/vci_collector.rb`, `VCI_RAILS_MODE`, `VCI_RAILS_RUNNER=minitest|rspec`,
`VCI_ROOT` (project), `VCI_REPO` (nearest ancestor with `.git`), `VCI_DB_DIR` and `TMPDIR` (fresh dirs),
`RAILS_ENV=test`, `RACK_ENV=test`, `PARALLEL_WORKERS=1`, `DISABLE_SPRING=1`, `DISABLE_BOOTSNAP=1`,
`BUNDLE_GEMFILE=<project>/Gemfile` (or `gems.rb`), `VCI_RAILS_ALLOW_DB=0|1`:

- `tool_versions_with_env` / `installed_externals` (cached): `ruby -e 'require File.expand_path("config/environment")'`
  (plain Ruby: `require "bundler/setup"`) in mode `probe`; the collector prints `VCI-PROBE {ruby, engine, rails,
  bundler, runner, platform, libs, db, gems: [{name, version, platform, source}], gemfile, taints}` at exit. Taints
  (Bootsnap/Spring active, another Gemfile, load path entries outside the repository/bundle/Ruby) or a Gemfile other
  than the project's are errors. `runner` names the bundle's test frameworks from its specs (`minitest <ver>`, and
  `rspec-core <ver>, rspec-expectations <ver>, ...` when RSpec is in the bundle), the same in every process.
- RSpec listing (`list_test_files`): mode `plain`, `VCI_RAILS_RUNNER=rspec`, `ruby -e 'require "bundler/setup";
  require "rspec/core"; $0 = "rspec"; VciCollector::RSpecSupport.list!(ARGV)' -- --options .rspec`: RSpec's
  `ConfigurationOptions` configure `RSpec.configuration` (default path, pattern, exclude pattern; `.rspec`'s
  `--require`s are loaded) and the collector prints `VCI-RSPEC-LIST {files: [<abs>...], defaultPath, pattern,
  excludePattern}`. A file outside the project dir, or a load error, is an error.
- `run_collect`: per file (`$VCI_JOBS` at a time, default CPUs up to 8, 1 with `rails_allow_db`), mode `collect`,
  `VCI_OUT=<fresh>`, `VCI_TEST_ID=<project-relative file>`: Minitest `ruby bin/rails test <file> --seed 0`; RSpec
  `ruby -e 'require "bundler/setup"; require "rspec/core"; $0 = "rspec"; RSpec::Core::Runner.invoke' -- --options
  .rspec <file>` (`RSPEC_RUN_SCRIPT`, `RSPEC_ARGS`).
- `run_plain`: the same per file in mode `plain` (no output); without files the whole suite, one process per runner
  (`ruby bin/rails test --seed 0`, the RSpec command without a file).
- `canonical_argv`: Minitest `["rails", "test", "--root", <project dir>, "--seed", "0", <file>]`; RSpec `["rails",
  "rspec", "--root", <project dir>, "--options", ".rspec", "--default-seed", "0", <file>]` (a file whose runner cannot
  be decided gets `["rails", "undecided-runner", ...]`, which no attestation has); `config_candidates`:
  `RAILS_GLOBAL_FILES` in the project dir, and `config_candidates_for(<RSpec file>)` the same without
  `test/test_helper.rb` plus `RSPEC_GLOBAL_FILES`; built-in pass-through `RAILS_PASS_THROUGH`; hashed patterns
  `RAILS_HASHED_ENV` (includes `SPEC_OPTS`); `scratch_dirs`: `<project>/vendor/bundle`.

Collector records (`docs/spike-rails.md`): `meta` has `adapter: "rails"`, `ruby`, `engine`, `rails`, `bundler`,
`runner`, `platform`, `db`, `tz`, `collector`; `module` (every Ruby file compiled from disk, loaded native extensions),
`read`, `probe`, `stat`, `readdir`, `write` (inside the repository), `external` (`name`, `version` incl. `git <rev>`
for git sources, plus `platform` and `source`, which the parser ignores), `env` (`where` is informational; key `*` =
enumerated), `taint`, `result`. Minitest `result`: `state` is `passed` only with exit status 0, at least one test, no
failure, error or skip and at least one assertion in every test; also `no-tests`, `no-assertions`, `failed`; extra
`assertions`, `noAssertions`, `exitStatus`. RSpec `result` (from a hook on `RSpec::Core::Reporter`): `tests` = examples
run, `failed` = failed examples plus errors outside examples (load errors, `before`/`after(:suite)` and
`after(:context)` errors), `skipped` = pending and skipped examples; `state` is `passed` only with exit status 0, at
least one example run, none failed, pending or skipped and every declared example run (`filtered` otherwise; also
`no-tests`, `failed`); extra `declared`, `errorsOutsideExamples`, `exitStatus`. RSpec taints: `rspec:option-files`,
`rspec:invocation:<class>` (`--bisect`, `--drb`, `--init`, ...), `rspec:drb`, `rspec:dry-run`, `rspec:error-outside-examples:<context>`, `rspec:filtered:...`,
`rspec:quit-early`, `rspec:retry`, `rspec:failure-cleared:<locations>` (an example's failure, recorded through
`Example#display_exception=`, was later reported as a pass), `rspec:status-mismatch` (more failed or pending
`execution_result` statuses than the reporter heard of), `rspec:parallel-tests`, `rspec:minitest-also-ran`,
`rails:code-statistics:...`. `exitStatus` is the status the process leaves with, read from `$!` as the collector's
`at_exit` handler (the last one to run) starts; a non-zero one after a clean framework report adds the taint
`vci:process-exit:<status>`, and `RailsAdapter::run_one` adds the same taint to a `passed` result whenever the child's
exit code is not 0 (or it died from a signal). The CLI allows `write` records only for git-ignored paths under the project's `RAILS_SCRATCH_DIRS`, and waives
`rails:network-db:` taints when `policy.rails_allow_db` (recorded in `waived`).

## vci-cli predicate and storage

The signed predicate is `vci_core::Predicate` flattened, plus `envConfigDigest` (docs/ENV.md), `projectDir` (repo
relative), `runnerProject` (Vitest project name), `projectName` (the `[[projects]]` name; omitted in the
single-project form), and for Go `platformSpecific` (repository files built only for some GOOS/GOARCH, or whose
code refers to `GOOS`/`GOARCH`: the attestation then needs the same OS and architecture), `archSpecific` (why the
results may differ on another architecture, i.e. floating-point code in a non-standard package of the closure: the
attestation then needs the same architecture) and `waived` (refusals waived by `policy.go_allow_net`, or for Rails by
`policy.rails_allow_db`, which the base policy must still waive), for Cargo `cfgPredicates` (checked against `toolchain.rustCfg` and the verifying
host's cfg set), and for every adapter `declaredInputs` (the `[[inputs]] extra` globs of the test id, which must equal
the base config's); all omitted when empty. Statement subject: `[{ name: testId, digest: { blake3: inputRoot } }]`.
`input_root` is the per-file manifest root; `global_input_root` is the per-file global manifest root (lockfiles,
package.json, `.npmrc`, config candidates and their relative references, tsconfig chain, `vci.toml`, the test's
snapshot file, and the `NODE_OPTIONS` env hash; for pytest: `vci.toml`, `pyproject.toml`/`uv.lock`/`.python-version`/
`uv.toml` from the project dir up to the repo root, and every pytest config name and `conftest.py` from the test's
directory up to the project dir; for Go: `vci.toml`, `go.mod`/`go.sum`/`go.work`/`go.work.sum` from the project dir
up to the repo root and `vendor/modules.txt` in the project dir; for Cargo: `vci.toml`, `Cargo.toml` from the package dir
up to the repo root, `Cargo.lock`/`rust-toolchain(.toml)`/`.cargo/config(.toml)` from the project dir up to the repo
root; for Rails: `vci.toml`, `RAILS_GLOBAL_FILES` in the project dir (RSpec files: without `test/test_helper.rb`,
with `.rspec`), and `.ruby-version`/`.tool-versions`/`mise.toml` variants from the project dir up to the repo root). The store key passed to `AttestStore::put` as `input_root` is BLAKE3 over repo id,
test id, input root, global input root, env config digest, toolchain and argv (plus the pytest toolchain fields, the
project name, the Go, Rust and Rails toolchain fields, `platformSpecific`, `archSpecific`, `waived`, `cfgPredicates`, `declaredInputs` and a
non-Vitest adapter name when set), so re-running with identical inputs replaces (renews) the
stored envelope.

## Environment variables

See `docs/ENV.md`. It is part of the design: `vci.toml` `[env]` config with strict/loose mode, declared and pass-through patterns, hashed into each test file input root and checked in `vci plan`.
