# Environment variables in hashing

Modeled on Turborepo's `env` / `globalEnv` / `passThroughEnv` and strict mode, with one addition: vci also observes which variables a test file actually reads at runtime.

## Config (`vci.toml`)

```toml
[env]
mode = "strict"                         # "strict" (default) | "loose"
global = ["NODE_ENV", "TZ", "CI_*", "!CI_JOB_*"]   # hashed into every test file's input root
pass_through = ["GITHUB_TOKEN", "AWS_*"]          # visible to tests, never hashed

[[env.files]]                           # per-glob additions, like Turborepo task-level env
match = ["src/db/**/*.test.ts"]
env = ["DATABASE_URL"]
pass_through = ["PG*"]
```

Patterns: exact names, `*` wildcards, and a leading `!` to exclude. Exclusions win over inclusions. Matching is case-sensitive.

## Categories

| Category | Visible to test process | Hashed |
|---|---|---|
| Declared (`global`, per-file `env`) | yes | yes |
| Pass-through (`pass_through`) | yes | no (name is recorded if read) |
| Built-in pass-through: `PATH`, `HOME`, `USER`, `SHELL`, `TMPDIR`, `TEMP`, `TMP`, `LANG`, `LC_*`, `TERM`, `CI`, `NODE_OPTIONS`, `VCI_*`, `VITEST*` | yes | **only if the test file was observed reading it** (never vci's per-run `VCI_OUT`, `VCI_WORKER`, `VCI_LIST_OUT`, `VCI_GO_TESTLOG`; for Vitest also never `VITEST*` and `NODE_OPTIONS`, which is hashed globally; the user's `VCI_BASE_REF`, ... and, outside Vitest, `NODE_OPTIONS` are hashed when read) |
| Adapter built-in pass-through, pytest: `UV`, `UV_*`, `VIRTUAL_ENV`, `PYTHONPATH` (set by vci), `XDG_{CACHE,CONFIG,DATA,BIN}_HOME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `HTTP(S)_PROXY`, `ALL_PROXY`, `NO_PROXY` (and lowercase) | yes | **only if the test file was observed reading it** (never `PYTHONPATH`: a test that reads it is not attested) |
| Adapter-inferred: `VITE_*` for Vitest (exposed through `import.meta.env`) | yes | yes |
| Adapter built-in pass-through, Go: `GOPATH`, `GOROOT`, `GOCACHE`, `GOCACHEPROG`, `GOMODCACHE`, `GOENV`, `GOPROXY`, `GONOPROXY`, `GOPRIVATE`, `GONOSUMDB`, `GONOSUMCHECK`, `GOSUMDB`, `GOINSECURE`, `GOVCS`, `GOAUTH`, `GOTELEMETRY`, `GOTELEMETRYDIR`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, the `*_PROXY` variables, `GIT_SSH`, `GIT_SSH_COMMAND`, `SSH_AUTH_SOCK` | yes | **only if the test was observed reading it** |
| Go hashed-if-present: every other `GO*` and `CGO_*` (`GOFLAGS`, `CGO_ENABLED`, `GOEXPERIMENT`, `GODEBUG`, `GOMAXPROCS`, `GOGC`, `GOAMD64`, `GOTOOLCHAIN`, ...) | only if declared (strict) | **yes, whenever present** |
| Go always-read: `TZ`, `ZONEINFO` (package time reads them through `syscall.Getenv`, which is not logged). A package that uses the local time zone with `TZ` unset is refused (it would come from `/etc/localtime`): declare `TZ` and set it (`TZ=UTC`) on both sides | only if declared (strict) | **yes** (reported as read by every package) |
| Adapter built-in pass-through, Cargo: `CARGO_HOME`, `RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`, `RUSTUP_DIST_SERVER`, `RUSTUP_UPDATE_ROOT`, `CARGO_TARGET_DIR`, `CARGO_BUILD_TARGET_DIR`, `CARGO_BUILD_BUILD_DIR`, `CARGO_BUILD_JOBS`, `CARGO_NET_*`, `CARGO_HTTP_*`, `CARGO_REGISTRIES_*`, `CARGO_REGISTRY_*`, `CARGO_TERM_*`, `CARGO_LOG`, `CARGO_CACHE_RUSTC_INFO`, `CARGO_INCREMENTAL`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `CARGO_BUILD_RUSTC_WRAPPER`, `CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER`, `SCCACHE_*`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, the `*_PROXY` variables, `GIT_SSH`, `GIT_SSH_COMMAND`, `SSH_AUTH_SOCK` | yes | **only if the unit's source names it literally** (`env::var("X")`) |
| Cargo hashed-if-present: every other `RUST*` and `CARGO*` (`RUSTFLAGS`, `RUSTDOCFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_PROFILE_*`, `CARGO_BUILD_*`, `RUST_TEST_THREADS`, `RUST_BACKTRACE`, `RUST_LOG`, `RUST_MIN_STACK`, `RUSTC`, `RUSTC_BOOTSTRAP`, ...) and the C toolchain variables build scripts read (`CC`, `CXX`, `AR`, `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LDFLAGS`, `CC_*`, `CXX_*`, `AR_*`, `CFLAGS_*`, `CXXFLAGS_*`, `TARGET_CC`, `HOST_CC`, ..., `PKG_CONFIG*`, `MACOSX_DEPLOYMENT_TARGET`, `SDKROOT`) | only if declared (strict) | **yes, whenever present** |
| Cargo compile-time and declared reads: the `env!`/`option_env!` variables rustc lists in its dep-info, every build script's `rerun-if-env-changed` variables, and variables named literally in `env::var("X")`/`env::var_os("X")` in the unit's repository sources (cargo's own `CARGO_PKG_*`, `CARGO_MANIFEST_DIR`, `OUT_DIR`, `TARGET`, ... and `TMPDIR`/`PWD` excepted) | only if declared or pass-through (strict) | **yes** |
| Go run-specific: `PWD` (go test sets it to the package directory), `TMPDIR` (vci's fresh directory) | yes (set per run) | never (like the checkout location) |
| pytest always-read: `PYTEST_ADDOPTS`, `PYTEST_PLUGINS`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD`, `PYTHONHASHSEED`, `PYTHONWARNINGS`, `PYTHONOPTIMIZE`, `PYTHONDEVMODE`, `PYTHONUTF8`, `PYTHONSAFEPATH`, `PYTHONNOUSERSITE`, `PYTHONUSERBASE`, `PYTHONHOME`, `PYTHONINTMAXSTRDIGITS`, `PYTHONIOENCODING`, `TZ` | only if declared (strict) | **yes** (reported as read by every file) |
| pytest hashed-if-present: every `PYTHON*` and `PYTEST_*` except `PYTHONPATH` (the interpreter reads many in C: `PYTHON_CPU_COUNT`, `PYTHONBREAKPOINT`, `PYTHON_GIL`, ...) | only if declared (strict) | **yes, whenever present** (loose mode, or declared) |
| Undeclared, strict mode | **no** (removed from the child environment) | recorded as absent if read |
| Undeclared, loose mode | yes | yes, **if the test file was observed reading it** |
| `TZ`, loose mode | yes | **always** (set or not): ICU reads it natively, never through the `process.env` proxy |

Reads are observed in the Vitest workers and in the main process: a variable read by the Vitest config file (for
example in `define`), an inline plugin or a globalSetup file counts as read by every test file of the run.

`NO_COLOR` and `FORCE_COLOR` are not built-in pass-through (a test's result can depend on colour output), so strict
mode removes them: add them to `pass_through` or `global` to keep them.

`NODE_OPTIONS` is pass-through because vci sets it, but if the user's value is non-empty it is hashed as part of the toolchain digest.

Built-in pass-through variables are visible so that tooling works, not because their values cannot matter: `CI`,
`HOME`, `USER`, `TMPDIR`, `LANG` differ between a laptop and a CI runner by definition. A test file observed reading
one (`os.environ.get("CI")`, `os.path.expanduser`, `tempfile.gettempdir()`) gets its value hashed, so it is only
skipped where the value is the same (in practice: not on a CI runner when it was attested on a laptop). Reads in C
(`getenv` in a C extension, the `locale` module) are not observed. Configured `pass_through` stays unhashed: that is
the user's decision.

pytest: the interpreter and pytest read `PYTHON*` and `PYTEST_*` before any hook can observe them, so the collector
reports the list above as read by every test file and they are **hashed** (never built-in pass-through). In strict
mode they are removed from the child unless declared, so they hash as unset locally and in CI; declare one in
`global` to set it (its value is then hashed). In loose mode every `PYTHON*`/`PYTEST_*` variable present is hashed
(the pattern list `PYTHON*`, `PYTEST_*`, `!PYTHONPATH` is part of the env config digest), and one present in CI but
not when the file was attested fails the env check. `PYTHONPATH` is the exception: vci always sets it to the collector
directory (and removes it for listing and `vci ci`), so the user's value never reaches the tests and it is built-in
pass-through; `vci run` refuses to attest a file that read it. uv's own variables are built-in pass-through so that
`uv run` works in strict mode; they choose the interpreter and index, which the toolchain (exact Python version,
bundled library versions, the full installed distribution set) and externals (installed version pinned by `uv.lock`)
checks cover. `UV_ENV_FILE` has no effect: every `uv run` gets `--no-env-file` (a `.env` file would add variables
after vci computed the environment it hashes). Reading the whole environment (`dict(os.environ)`, iteration, `len`, `repr`) is recorded as
key `*` and makes the file non-attestable.

Go: the test log records every `os.Getenv`/`os.LookupEnv` (including those made while packages are initialised,
before the test starts). The go command and the runtime read `GO*` variables where no log sees them, so every
`GO*`/`CGO_*` variable that is not one of the go command's locations is treated like pytest's `PYTHON*`: removed in
strict mode unless declared, hashed whenever present. The effective build settings (including values written with
`go env -w`) are also part of the toolchain. `os.Environ` cannot be observed: a test whose code (or a non-standard
package it imports) calls it is not attested.

Cargo: nothing observes what a Rust test reads from the environment at run time. The cargo adapter therefore only
attests in strict mode, where an undeclared variable is removed from the test process and so unset both where the unit
was attested and in CI; built-in pass-through variables (`HOME`, `CI`, `PATH`, ...) stay visible and are hashed only
when the source names them literally (`std::env::var("CI")`), so a computed name (`env::var(name)`) that happens to be
one of them is not seen. `env::vars()`/`env::vars_os()` (enumeration) refuse the unit, like `os.Environ` for Go and
`dict(os.environ)` for pytest. `TMPDIR` is a fresh empty directory for every `cargo test` vci starts, and not an input. The wrapper variables
(`RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER` and their `CARGO_BUILD_` forms) stay pass-through so that `sccache`
works, but any other wrapper refuses every unit of `vci run` (the program is not hashed); a declared
`CARGO_TARGET_<TRIPLE>_RUNNER` or `_LINKER` refuses them too.
Environment reads by external crates are not seen (as with C `getenv` for pytest).

With `[[projects]]` in vci.toml, each project's `env` table replaces the given top-level `[env]` keys for that
project; the digest is computed from the project's effective configuration.

## What goes into the attestation

Values are never stored. For each hashed variable the manifest holds `{ key, hash }` where `hash` is BLAKE3 of the value, or `ABSENT_HASH` if unset.

Per test file the hashed set is:

1. every variable in the environment matching the declared patterns that apply to that file, plus every exact (non-wildcard) declared name even if unset;
2. adapter-inferred variables present in the environment;
3. variables observed being read at runtime, except configured `pass_through`, vci's per-run variables (`VCI_OUT`,
   `VCI_WORKER`, `VCI_LIST_OUT`, `VCI_GO_TESTLOG`) and the adapter's own plumbing (Vitest: `VITEST*`, `NODE_OPTIONS`;
   pytest: `PYTHONPATH`); built-in pass-through variables that are read are hashed (a Go test reading `NODE_OPTIONS`
   or `VCI_BASE_REF`);
4. in loose mode, `TZ` (unless excluded with `!TZ`).

The predicate also records `envConfigDigest`: BLAKE3 over the mode and the sorted effective pattern lists for that file.

## Verification in CI

1. Env config is read from `vci.toml` at the **base commit**, like the rest of policy.
2. `envConfigDigest` must equal the digest computed from the base config for that test file. A different mode or pattern list means RUN.
3. Expand the patterns against CI's own environment. The resulting key set, unioned with the attested observed keys, must equal the attested key set. A variable that matches a pattern in CI but is missing from the attestation means RUN.
4. Every hash must match CI's value. Any mismatch means RUN, and `explain` names the variable (never its value).

`vci ci` runs the remaining tests under the same strict-mode filtering, so local and CI runs see the same environment shape.

## Secrets

A hash of a low-entropy value can be brute-forced by anyone who can read the attestation refs. Put secrets in `pass_through`, not in `env`. `vci run` warns when a declared variable's name matches `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*KEY*`.

## Implementation notes

- Pattern expansion, category resolution and `envConfigDigest` live in `vci-cli` (or a small module in `vci-core`); `InputManifest::capture` already takes the final list of keys to hash and `diff_against_checkout` re-hashes them from the current process environment.
- The Vitest adapter builds the child environment explicitly (`Command::env_clear()` then add) in strict mode.
- The JS collector already emits `{"kind":"env","key":...}` for each read; reads of `import.meta.env.*` must be covered too, or `VITE_*` must always be hashed (the default above).
