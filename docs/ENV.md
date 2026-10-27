# Environment variables

An environment variable can change a test's result, so vci decides, for every variable, whether it reaches the test
processes and whether its value is an input. Since vci 1.6.0 that policy is three short lists in `vci.toml`, plus a
short built-in list per runner. Every other variable is removed from the test processes.

## In one minute

```toml
[env]
set = { TZ = "UTC", LANG = "C.UTF-8", CI = "true" }  # vci sets these, on every machine
hash = ["VEX_TEST_DATABASE_URL", "FEATURE_*"]        # taken from the machine; a change re-runs the test
ignore = ["SCCACHE_*", "MISE_*", "GITHUB_TOKEN"]     # taken from the machine; never a reason to re-run
```

| Class | Reaches the test | Hashed | Use it for |
|---|---|---|---|
| `set` | yes, with the value written here, on every machine (the machine's own value is replaced) | yes, the declared value (so it is the same everywhere) | what must be identical locally and in CI: the time zone, the locale, `CI`, feature switches. Nobody exports anything. |
| `hash` | yes, the machine's value | yes: another value, or its absence, re-runs the test | what legitimately differs between machines and matters: a database URL, a service endpoint |
| `ignore` | yes, the machine's value | never, not even when a test reads it | secrets, caches, tooling locations, anything you decide does not change results |
| built-in hash | yes, the machine's value | when present | the few variables a runtime reads natively (where no collector sees the read) that change results; [tables below](#built-in-lists) |
| built-in ignore | yes, the machine's value | never, not even when a test reads it (since 2.0.2; `hash` opts one in) | what a runner needs to work at all (`PATH`, `HOME`, caches); [tables below](#built-in-lists) |
| everything else (`stripped`) | **no**: removed from every test process vci starts | a test seen reading one gets it recorded as absent | |

**Precedence**, when lists overlap: `set` > `hash` > `ignore` > built-in hash > built-in ignore. So your `ignore`
silences a built-in hash variable (`ignore = ["RUSTFLAGS"]`), your `hash` turns a built-in ignore variable into an
input (`hash = ["HOME"]`), and `set` overrides everything.

**Where `set` applies:** wherever vci starts a test process: `vci run`, `vci ci` (the tests it runs plainly and the
ones it attests with `--key`) and the probes `vci plan` runs. The only values that win over `set` are the ones vci
itself sets for a runner: `RAILS_ENV`/`RACK_ENV=test` and `RUBYOPT` with the collector (Rails), a node:test
script's `NAME=value` assignments, vci's own `NODE_OPTIONS` additions, the fresh `TMPDIR` of every Go, Cargo and
Rails process, and the variables `cargo test` gives a test process (`CARGO_PKG_*`, `OUT_DIR`, ...; see
[Runner notes](#runner-notes)).

**`vci env`** prints the effective policy of each project: every variable in a list, its class, where the rule comes
from, and what it is on this machine. `vci env --base-ref origin/main` also shows where the base commit's policy
differs (CI judges with the base policy). See [`vci env`](#vci-env).

## Config (`vci.toml`)

```toml
[env]
set = { TZ = "UTC" }                      # exact names; string values
hash = ["NODE_ENV", "CI_*", "!CI_JOB_*"]  # patterns
ignore = ["GITHUB_TOKEN", "AWS_*"]        # patterns

[[env.files]]                             # extra lists for the test files matching `match` only
match = ["src/db/**/*.test.ts"]
hash = ["DATABASE_URL"]
ignore = ["PG*"]
```

- **`set`** takes exact variable names (no `*`, `!`, `=` or whitespace) and string values (`set = { N = 1 }` is an
  error; write `"1"`). An empty string is a value: the variable is set, empty. Values are in `vci.toml` in plain text,
  so never put a secret in `set`.
- **`hash` and `ignore`** take patterns: exact names, `*` wildcards (anywhere in the name), and a leading `!` to
  exclude. Within one list an exclusion wins over an inclusion, and an excluded variable falls through to the next
  class. Matching is case-sensitive.
- **`[[env.files]]`** adds `hash` and `ignore` patterns for the test files that match `match` (project-relative
  globs). The variables they name reach every test process of the project (a run shares one environment); only the
  matching files hash them up front, and another file that reads one has the read hashed like any observed read.
- **`[[projects]]`**: each project's `[projects.env]` table replaces the top-level keys it gives (`set`, `hash`,
  `ignore`, `files`) for that project, as a whole: a project's `set` does not merge with the top-level `set`, so repeat
  the variables you want to keep. Keys it does not give are inherited.

node:test adds `NODE_ENV` and every variable its test script assigns (`NODE_ENV=test node --test ...`) to `hash`
itself, with the script's value (`vci env` shows them with the source `test script`).

## Built-in lists

The built-in lists are short on purpose. A built-in hash variable is one the runtime reads natively, before or
outside the collectors, and that changes results; it reaches the tests and is hashed whenever present. A built-in
ignore variable is one the runner needs to work at all; it reaches the tests and is hashed only if a test is seen
reading it (a test that reads `HOME` depends on it). Everything else is removed: unset where the test was attested and
unset in CI, so it cannot make two runs differ.

**Every runner.** Built-in hash: `TZ` (every runtime reads the local time zone natively). Built-in ignore: `PATH`,
`HOME`, `USER`, `SHELL`, `TMPDIR`, `TEMP`, `TMP`, `TERM`, `VCI_*` (your `VCI_BASE_REF`, ...; vci's own per-run
`VCI_OUT`, ... are never hashed), except `VCI_STORE_URL`, `VCI_STORE_TOKEN` and `VCI_STORE`, which vci removes from
its own environment at start-up and which no test process ever sees (since 2.8.0; not even when `set` or `hash` names
them), and on Windows `SYSTEMROOT`, `COMSPEC`, `PATHEXT`, `WINDIR`, `USERPROFILE`,
`APPDATA`, `LOCALAPPDATA`.

### Vitest

| Variable | Class | Why |
|---|---|---|
| `LANG`, `LC_ALL`, `LC_MESSAGES` | hash | ICU's default locale (`Intl`, `toLocaleString`) |
| `NODE_OPTIONS` | hash | reaches every process before the collector (also a global input) |
| `UV_THREADPOOL_SIZE` | hash | libuv's thread pool |
| `VITE_*` | hash | Vite exposes them through `import.meta.env` |
| `VITEST*` | ignore | Vitest's own per-worker variables (never hashed) |

### node:test

| Variable | Class | Why |
|---|---|---|
| `LANG`, `LC_ALL`, `LC_MESSAGES` | hash | ICU's default locale (`de_DE` formats `1234.5` as `1.234,5`) |
| `NODE_OPTIONS` | hash | reaches every process before the collector (also a global input; options other than memory, warning and stack-trace ones refuse every file) |
| `UV_THREADPOOL_SIZE` | hash | libuv's thread pool |

Every other `NODE_*` (`NODE_PATH`, `NODE_EXTRA_CA_CERTS`, ...) is removed unless listed, and so are node:test's own
`NODE_TEST_CONTEXT` and `NODE_TEST_WORKER_ID`. With `TZ` unset every file is refused (the machine's zone is not an
input): the `vci init` template sets it.

### pytest

| Variable | Class | Why |
|---|---|---|
| `PYTHONHASHSEED`, `PYTHONOPTIMIZE`, `PYTHONDEVMODE`, `PYTHONUTF8`, `PYTHONSAFEPATH`, `PYTHONNOUSERSITE`, `PYTHONUSERBASE`, `PYTHONHOME`, `PYTHONIOENCODING`, `PYTHONWARNINGS`, `PYTHONINTMAXSTRDIGITS` | hash | read by the interpreter in C at startup; change hashing order, asserts, imports, encodings, warnings |
| `PYTEST_ADDOPTS`, `PYTEST_PLUGINS`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD` | hash | read by pytest before any hook runs; change options and plugins |
| `UV`, `UV_*`, `VIRTUAL_ENV` | ignore | where uv and the environment are; the interpreter and packages are checked directly |
| `PYTHONPATH` | ignore | vci sets it to its collector; `vci run` refuses a test that reads it |
| `XDG_{CACHE,CONFIG,DATA,BIN}_HOME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `*_PROXY` (and lowercase) | ignore | uv's cache, config and index access |

Every other `PYTHON*`/`PYTEST_*` (`PYTHON_CPU_COUNT`, `PYTHONBREAKPOINT`, ...) and the locale are removed unless
listed.

### Go

| Variable | Class | Why |
|---|---|---|
| `ZONEINFO` | hash | package time reads it through `syscall.Getenv`, which the test log does not see |
| `GOFLAGS`, `GOEXPERIMENT`, `GODEBUG`, `GOTOOLCHAIN` | hash | change the build or the runtime |
| `GOOS`, `GOARCH`, `GOAMD64`, `GOARM`, `GOARM64`, `GO386`, `GOPPC64`, `GORISCV64`, `GOMIPS`, `GOMIPS64`, `GOWASM` | hash | the target and its instruction set level |
| `CGO_*`, `CC`, `CXX`, `AR`, `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LDFLAGS`, `PKG_CONFIG*` | hash | cgo and its C toolchain |
| `GOPATH`, `GOROOT`, `GOCACHE`, `GOCACHEPROG`, `GOMODCACHE`, `GOENV`, `GOPROXY`, `GONOPROXY`, `GOPRIVATE`, `GONOSUMDB`, `GONOSUMCHECK`, `GOSUMDB`, `GOINSECURE`, `GOVCS`, `GOAUTH`, `GOTELEMETRY`, `GOTELEMETRYDIR` | ignore | where modules, caches and the toolchain are; the modules and toolchain are checked directly |
| `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `*_PROXY`, `GIT_SSH`, `GIT_SSH_COMMAND`, `SSH_AUTH_SOCK` | ignore | module downloads |

Every other `GO*` (`GOMAXPROCS`, `GOGC`, `GOWORK`, `GOTMPDIR`, ...) is removed unless listed. `PWD` and `TMPDIR` are
set per run by go test and vci (never inputs).

### Cargo

| Variable | Class | Why |
|---|---|---|
| `RUSTFLAGS`, `RUSTDOCFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_ENCODED_RUSTDOCFLAGS`, `CARGO_BUILD_RUSTFLAGS`, `CARGO_BUILD_RUSTDOCFLAGS`, `CARGO_TARGET_*_RUSTFLAGS` | hash | compiler flags |
| `CARGO_PROFILE_*`, `CARGO_BUILD_TARGET` | hash | profile settings and the target |
| `RUSTC`, `RUSTDOC`, `RUSTC_BOOTSTRAP` | hash | which compiler, and unstable features |
| `RUST_TEST_THREADS`, `RUST_MIN_STACK` | hash | read by the test harness and std |
| `CC`, `CXX`, `AR`, `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LDFLAGS`, `CC_*`, `CXX_*`, `AR_*`, `CFLAGS_*`, `CXXFLAGS_*`, `TARGET_{CC,CXX,AR,CFLAGS,CXXFLAGS}`, `HOST_{CC,CXX,CFLAGS}`, `PKG_CONFIG*`, `MACOSX_DEPLOYMENT_TARGET`, `SDKROOT` | hash | the C toolchain build scripts use |
| `CARGO_HOME`, `RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`, `RUSTUP_DIST_SERVER`, `RUSTUP_UPDATE_ROOT`, `CARGO_TARGET_DIR`, `CARGO_BUILD_TARGET_DIR`, `CARGO_BUILD_BUILD_DIR`, `CARGO_BUILD_JOBS`, `CARGO_NET_*`, `CARGO_HTTP_*`, `CARGO_REGISTRIES_*`, `CARGO_REGISTRY_*`, `CARGO_TERM_*`, `CARGO_LOG`, `CARGO_CACHE_RUSTC_INFO`, `CARGO_INCREMENTAL` | ignore | where toolchains, the registry and the build cache are; rustc and cargo are checked exactly |
| `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER` (and their `CARGO_BUILD_` forms), `SCCACHE_*` | ignore | compilation caches (a wrapper other than sccache refuses every unit) |
| `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `*_PROXY`, `GIT_SSH`, `GIT_SSH_COMMAND`, `SSH_AUTH_SOCK` | ignore | crate downloads |

Every other `RUST*`/`CARGO*` is removed unless listed, including `RUST_BACKTRACE`, `RUST_LIB_BACKTRACE` and
`RUST_LOG`: std (`Backtrace::capture`) and dependency crates (`env_logger`, `tracing`'s `EnvFilter`) read them where
the source scan cannot see it, and a test can depend on them, so they are unset on every machine. To get backtraces
under vci, `set = { RUST_BACKTRACE = "1" }` (the same everywhere); `ignore` lets the machine's value through
unhashed, which is only safe if no test depends on it. A `CARGO_TARGET_<TRIPLE>_RUNNER` or `_LINKER` that reaches
the tests (listed in `hash` or `ignore`) refuses every unit (the program is not hashed).

### Rails (Minitest and RSpec)

| Variable | Class | Why |
|---|---|---|
| `RUBYLIB`, `RUBYGEMS_GEMDEPS` | hash | read at startup, before the collector: change what is loaded |
| `RUBY_YJIT_ENABLE`, `RUBY_GC_*`, `RUBY_THREAD_VM_STACK_SIZE`, `RUBY_THREAD_MACHINE_STACK_SIZE`, `RUBY_FIBER_VM_STACK_SIZE`, `RUBY_FIBER_MACHINE_STACK_SIZE`, `RUBY_FREE_AT_EXIT`, `RUBY_CRASH_REPORT`, `RUBY_BOX`, `RUBY_MN_THREADS`, `RUBY_MAX_CPU` | hash | the VM's settings, read in C at startup |
| `DATABASE_URL`, `*_DATABASE_URL` | hash | which database Active Record connects to (CI usually needs its own) |
| `SECRET_KEY_BASE` | hash | read by Rails when it boots |
| `LANG`, `LC_ALL`, `LC_CTYPE` | ignore | Ruby's default encoding, which the toolchain records (and Rails sets to UTF-8) |
| `GEM_HOME`, `GEM_PATH`, `GEM_SPEC_CACHE`, `BUNDLE_PATH`, `BUNDLE_APP_CONFIG`, `BUNDLE_USER_*`, `BUNDLE_CACHE_PATH`, `BUNDLE_GLOBAL_GEM_CACHE`, `BUNDLE_BIN`, `BUNDLE_JOBS`, `BUNDLE_RETRY`, `BUNDLE_DEPLOYMENT`, `BUNDLE_FROZEN`, `BUNDLE_SILENCE_ROOT_WARNING` | ignore | where gems are; Ruby, the bundle and every loaded gem's version are checked directly |
| `MISE_*`, `__MISE_*`, `RBENV_*`, `ASDF_*`, `XDG_{CACHE,CONFIG,DATA,STATE}_HOME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `*_PROXY` | ignore | version managers and downloads |

Set by vci for every test process (never inputs, and not changeable with `set`): `RUBYOPT` (the collector),
`RAILS_ENV`/`RACK_ENV` (`test`), `BUNDLE_GEMFILE`, `PARALLEL_WORKERS` (`1`), `DISABLE_SPRING`, `DISABLE_BOOTSNAP`,
`TMPDIR`. Every other variable is removed unless listed, including Minitest's `SEED`, `TESTOPTS`, `N`, `MT_*`,
RSpec's `SPEC_OPTS`, `BUNDLE_WITHOUT`, `RAILS_MASTER_KEY`, `BOOTSNAP_*`, `SPRING_*`, `OPENSSL_*`, `VIPS_*`: removed,
they are unset on every machine, so they cannot make two runs differ. List one in `hash` (or `set`) to use it.

## `vci env`

```
vci env [--base-ref REF] [--project NAME] [--format text|json]
```

Prints, per project, the effective policy as vci applies it on this machine: the `vci.toml` of the working tree, the
runner's built-in lists, and what each variable is here. It runs nothing. Warnings about old key names go to stderr.

| Column | What it says |
|---|---|
| `VARIABLE` | a name, or a pattern from a list (`FEATURE_*`), followed by the variables it matches here |
| `CLASS` | `set`, `hash`, `ignore`, `built-in hash`, `built-in ignore` or `stripped` (present here, removed from the tests; a test that reads one gets it recorded as absent) |
| `SOURCE` | `vci.toml set`, `vci.toml hash`, `vci.toml ignore`, `vci.toml [[env.files]] hash`/`ignore`, `vci.toml global (old name of hash)`, `vci.toml pass_through (old name of ignore)`, `test script` (node:test assignments), `built-in (every runner)`, `built-in <adapter>` |
| `HERE` | for `set`, the value vci sets; for hashed classes, `present (<first 12 hex of the hash>)` or `absent`; for ignored ones, `present` or `absent`; for a pattern, how many variables it matches here |
| `BASE` | with `--base-ref` only: `=` when the base commit's policy classifies the variable the same way, else the base's class (`hash`), its `set` value (`set "UTC"`), `not listed` for a pattern the base does not have, or `no such project` |

Built-in variables that are not set here are listed in one line under the table (`built-in, not set here`), and so
are the variables present here that the tests will not see. The header line gives the project's env config digest
(the first 12 hex) and, with `--base-ref`, `base policy differs` or `same as base`: when it differs, every attestation
made under the other policy fails the `env-config` check in CI (see [Verification in CI](#verification-in-ci)).

`--project NAME` keeps one project (its `[[projects]]` name). `--format json` prints an array of
`{ project, adapter, digest, baseDiffers?, rows: [{ variable, class, source, here, base? }] }`, with every row (the
built-in ones not set here included); `class` is `set`, `hash`, `ignore`, `builtin-hash`, `builtin-ignore` or
`stripped`.

## Worked example: a monorepo with node:test and Rails

A repository with a node:test package in `web/` and a Rails app in `api/` (SQLite in tests). The goal: tests
attested on a laptop skip in CI, and nobody exports anything, locally or in the workflow.

```toml
[env]
set = { TZ = "UTC" }      # the same zone everywhere
ignore = ["SCCACHE_*"]    # a cache: visible, never a reason to re-run

[[projects]]
name = "web"
path = "web"
adapter = "node-test"

[projects.env]
set = { TZ = "UTC", LANG = "C.UTF-8" }  # replaces the top-level set: repeat TZ
hash = ["FEATURE_*"]                    # feature switches the tests read

[[projects]]
name = "api"
path = "api"
adapter = "rails"
```

On a laptop with `TZ=Europe/London`, `LANG=en_US.UTF-8`, `CI=true`, `FEATURE_SEARCH=on`, `SCCACHE_DIR` and a
`GITHUB_TOKEN` in the shell, `vci env` prints (the built-in lines shortened):

```
project web (node-test): env config ff29623f04f0
  VARIABLE        CLASS            SOURCE                   HERE
  LANG            set              vci.toml set             "C.UTF-8"
  TZ              set              vci.toml set             "UTC"
  FEATURE_*       hash             vci.toml hash            pattern: 1 here
  FEATURE_SEARCH  hash             vci.toml hash            present (5d2a6bf0fba6)
  NODE_ENV        hash             test script              present (4878ca0425c7)
  SCCACHE_*       ignore           vci.toml ignore          pattern: 1 here
  SCCACHE_DIR     ignore           vci.toml ignore          present
  HOME            built-in ignore  built-in (every runner)  present
  PATH            built-in ignore  built-in (every runner)  present
  built-in, not set here:
    LC_ALL LC_MESSAGES NODE_OPTIONS UV_THREADPOOL_SIZE APPDATA COMSPEC ... VCI_* WINDIR
  present here, removed from the tests (recorded as absent if a test reads one):
    CI GITHUB_TOKEN

project api (rails): env config 3c5a161b8da1
  VARIABLE     CLASS            SOURCE                   HERE
  TZ           set              vci.toml set             "UTC"
  SCCACHE_*    ignore           vci.toml ignore          pattern: 1 here
  SCCACHE_DIR  ignore           vci.toml ignore          present
  HOME         built-in ignore  built-in (every runner)  present
  LANG         built-in ignore  built-in rails           present
  PATH         built-in ignore  built-in (every runner)  present
  built-in, not set here:
    *_DATABASE_URL DATABASE_URL RUBYGEMS_GEMDEPS RUBYLIB RUBY_BOX ... all_proxy http_proxy https_proxy no_proxy
  present here, removed from the tests (recorded as absent if a test reads one):
    CI FEATURE_SEARCH GITHUB_TOKEN
```

What happens:

- **`TZ` and `LANG`**: vci sets them in every test process, on the laptop (whose own `Europe/London` and
  `en_US.UTF-8` never reach a test) and on the runner. They are hashed with the declared value, so they always match.
  The workflow sets neither.
- **`CI`**: removed from both projects' tests, so it is unset on the laptop and on the runner alike. The Rails
  generator's `config.eager_load = ENV["CI"].present?` is therefore false on both sides, and each Rails test keeps
  depending only on the application files it loads.
- **`FEATURE_SEARCH`**: `web` hashes it. A runner without it re-runs the `web` files attested with it set (`vci
  explain` says `env:FEATURE_SEARCH (hash)`, expected `blake3=...`, actual `unset`). Either give it the same value in
  the workflow, or move it to `set` if it should be the same everywhere. `api` does not list it, so its tests never
  see it.
- **`NODE_ENV`**: the `web` test script assigns it (`NODE_ENV=test node --test ...`), so it is hashed with the
  script's value, the same everywhere.
- **`SCCACHE_DIR`**: visible, never hashed: its value on the runner does not matter.
- **`GITHUB_TOKEN`**: removed. A test that reads it sees it unset, here and in CI, and the read is recorded as absent.
- **Rails' `LANG`**: built-in ignore: the default encoding it decides is part of the Ruby toolchain, which is compared.
  If CI's database were a service named by `DATABASE_URL` (built-in hash for Rails), the laptop and the runner would
  need the same URL, for example by putting it in `api`'s `set`.

## Observed reads

The collectors record which variables a test reads (Vitest and node:test through `process.env`, pytest through
`os.environ`, Go through the test log, Rails through a wrapper of `ENV`; Cargo only by the names written literally in
`env::var("X")`, `env!` and `option_env!` and build scripts' `rerun-if-env-changed`). A read is hashed unless the
variable is in `ignore` or is vci's own plumbing; for `ignore` only the fact that the test read it is kept, never the
value. A read of a removed variable is recorded as absent: an input, so a CI whose policy lets the variable through
re-runs the test. Reading the whole environment (`dict(os.environ)`, `os.Environ`, `env::vars()`, `ENV.to_h`)
refuses the test.

Variables the runtime reads before or outside the collectors (the tables' "hash" rows) are reported as read by every
test file by the pytest, Go, node:test and Rails collectors, so they are hashed as set or unset even when absent.

## What goes into the attestation

Values are never stored. The manifest's env section holds `{ key, hash }` per hashed variable, `hash` being BLAKE3 of
the value or `ABSENT_HASH` if unset:

1. every `set` variable, with the declared value (the same on every machine);
2. every `hash` and built-in hash variable present, plus every exact `hash` name even if unset (loose mode also `TZ`,
   and every variable present of the runner's 1.5 families that is not `ignore`);
3. every variable a test was seen reading, except `ignore` and built-in ignore ones (since 2.0.2) and vci's plumbing (removed ones as absent).

The predicate also records:

- `envConfigDigest`: BLAKE3 over `vci/env-config/v2`, the mode, the `set` names and values, and the sorted `hash`,
  `ignore`, built-in hash and built-in ignore lists that apply to the file (in loose mode also the runner's 1.5
  families). Another `set` value, a list entry added or removed, or a vci whose built-in lists differ, changes it.
- `envSet`: the names vci set (so `vci explain` and readers of the attestation can tell a declared value from a
  machine's). Informational, since `envConfigDigest` already covers the values; omitted when empty.

**Format decision (1.6.0).** The attestation format stays compatible: each env entry is still a key and a hash, and
the only new field, `envSet`, is optional and ignored by older vci. The digest's domain moved from `v1` to `v2`,
because the classes and built-in lists changed what is hashed. So every attestation made before 1.6.0 fails the
`env-config` check once (`vci explain` says so) and its test re-runs; the new attestation then skips as usual. No
storage or envelope version changed.

## Verification in CI

1. The env policy is read from `vci.toml` at the **base commit**, like the rest of the policy.
2. `envConfigDigest` must equal the digest of the base policy for that file, else RUN (`env-config`).
3. Every recorded hash must match the value in the environment the tests would get here, with `set` applied (so a
   `set` variable always matches), else RUN. `vci explain` names the variable and its class under the base policy,
   never its value:

   ```
     failed check: env
       env:DATABASE_URL (hash)
         expected: blake3=3d1aba79...
         actual:   unset
   ```

4. Every variable the base policy requires (every `set` name, every `hash`/built-in hash variable present here, every
   exact `hash` name) must be in the attestation, else RUN (`env:NAME (class)`, expected `not hashed`, actual
   `must be hashed (env config)`).

## Old names, and upgrading from 1.5

| vci 1.5 | vci 1.6 |
|---|---|
| `global = [...]` (top level, per project) | `hash = [...]` |
| `pass_through = [...]` (top level, per project, `[[env.files]]`) | `ignore = [...]` |
| `env = [...]` in `[[env.files]]` | `hash = [...]` |
| `mode = "strict"` | (the only mode; accepted silently) |
| `mode = "loose"` | deprecated; still works as before, with a warning |
| a variable in `global` exported with the same value on every machine (`TZ`, `LANG`, `CGO_ENABLED`) | `set = { TZ = "UTC", ... }`, and drop the exports |

The old names still work, top level, per project and in `[[env.files]]`, with one warning that names each old key and
its new name, for example:

```
vci: warning: vci.toml uses the old env key names, which still work: rename env.global -> hash, env.pass_through -> ignore (vci 1.6.0 renamed `global`, and `env` in [[env.files]], to `hash`, and `pass_through` to `ignore`; see docs/ENV.md)
```

`vci run` and `vci env` print it for the working tree's `vci.toml`; `vci plan` prints it for the base commit's
(`vci.toml at the base commit uses the old env key names ...`), and `vci env --base-ref` for the ref it compares with
(`vci.toml at <ref> ...`). Giving both an old and a new name in one table is an error (`` `global` is the old name of
`hash`; give only `hash` ``). A base commit that uses the old names computes the same digest as one with the new
names, so renaming alone re-runs nothing.

`mode = "loose"` keeps vci 1.5's behaviour: every variable reaches the tests, ones a test is seen reading are hashed,
`TZ` always is, and so is every present variable of vci 1.5's per-runner families (`GO*`, `CGO_*`, `PYTHON*`,
`PYTEST_*`, `RUBY*`, `BUNDLE_*`, `RAILS_*`, `MT_*`, `NODE_*`, `RUST*`, `CARGO*`, ..., minus the location variables),
which the runtime reads where nothing observes it; `ignore` opts a variable out. It prints a deprecation warning and
will be removed. The Cargo adapter never attests in loose mode.

What changed in 1.6.0, besides the names:

- The long "hashed whenever present" families (`RUST*`, `CARGO*`, `GO*`, `CGO_*`, `PYTHON*`, `PYTEST_*`, `RUBY*`,
  `BUNDLE_*`, `RAILS_*`, `NODE_*`, ...) are gone. The variables in them that matter are in the short built-in hash
  lists above and reach the tests; the rest are removed.
- `LANG`, `LC_*`, `CI`, `NO_COLOR`, `FORCE_COLOR` and `NODE_OPTIONS` are no longer built in for every runner. `CI` is
  removed unless you list it (`set = { CI = "true" }` gives every test the value CI runners have). The locale variables
  are built-in hash only where a runtime reads them and nothing records the effect (Node's ICU); Rails keeps them as
  built-in ignore, the encoding they decide being part of the toolchain.
- Every attestation made before 1.6.0 re-runs once (the digest's domain changed; see above).

To upgrade: rename the keys, move every variable you exported with the same value everywhere into `set`, delete those
exports from the workflow and from your shell setup, and run `vci env --base-ref origin/main` to see the difference.

## Secrets

A hash of a low-entropy value can be brute-forced by anyone who can read the attestations (git-meta metadata on
`refs/meta/main`, or the store's file or database). Put secrets in `ignore`, never in `hash`: `vci run` warns when a `hash` name matches `*TOKEN*`,
`*SECRET*`, `*PASSWORD*`, `*KEY*`. `set` values are in `vci.toml` in plain text: never put a secret there.
`VCI_STORE_URL` and `VCI_STORE_TOKEN` are the secrets vci itself reads: vci keeps them, and `VCI_STORE`, out of every
environment it builds for a test, probe, hook or token command ([Store selection](#store-selection)). It cannot hide
them from a test that goes looking, though: the environment vci started with, and that of the CI step's shell that
set them, stay readable to every process of the same user (`/proc/<pid>/environ` on Linux, `ps eww` on macOS). A CI
job that runs untrusted pull-request code should therefore hold no store credential, or a read-only one (`turso db
tokens create <db> --read-only`; a PostgreSQL role with `SELECT` only); only trusted jobs (the default branch, or pull
requests from the same repository, whose authors could change the workflow anyway) should hold one that can write
(docs/REFERENCE.md, "What vci cannot hide from a test"). A token `[store] token_command` prints is kept in vci's
memory only: it is never put in any environment, a test's or the command's own.

## Store selection

Since 2.8.0 these choose and tune the attestation store (docs/REFERENCE.md, "Where attestations live" and "Choosing a
store"). The environment wins over `[store]` in the working tree's `vci.toml`; an empty variable counts as unset.

| Variable | Meaning | Default |
|---|---|---|
| `VCI_STORE` | the store: `git-meta`, `sqlite`, `postgres` or `libsql` (also `gitmeta`, `sqlite3`, `postgresql`, `pg`, `turso`). Never a URL: a value with `://`, or one not shaped like a name, is refused and not printed. Like `VCI_STORE_URL` it is in no environment vci builds for a test (since 2.8.0) | the scheme of `VCI_STORE_URL`, else `[store] backend`, else the scheme of `[store] url`, else `git-meta` |
| `VCI_STORE_URL` | where the store is: `postgres://user:password@host:port/database[?sslmode=...&sslrootcert=...]` (or `postgresql://`, or a libpq `key=value` string), `sqlite:<path>` (absolute, or relative to the git common directory; no `?query` or `#fragment`), a libSQL server, `libsql://<database>-<organization>.turso.io` (HTTPS; `?tls=0` for HTTP; it may carry `?authToken=...`) or, with `VCI_STORE=libsql`, `https://...` or `http://...`, or a libSQL file, `file:<path>` (with `VCI_STORE=libsql`; no `?query` or `#fragment`). `postgres://`, `sqlite:` and `libsql://` select their store when `VCI_STORE` is unset. Wins over `[store] url`. **A secret**: vci removes it from its own environment as it starts, so it is in no environment vci builds for a test, probe, hook or token command (a test can still read the environment vci started with: [Secrets](#secrets)), and never prints it (passwords and tokens show as `***`) | `[store] url` (PostgreSQL and a libSQL server need one of them) |
| `VCI_STORE_TOKEN` | libSQL: the server's auth token (a Turso database token: `turso db tokens create <db>` for trusted jobs that store, `--read-only` for the others, and for every job that runs untrusted pull-request code: [Secrets](#secrets)); wins over the URL's `authToken` and over `[store] token_command`, which then never runs. Sent only to a URL from the environment: with the URL from `[store] url` it is refused (set `VCI_STORE_URL` too). **A secret**, like `VCI_STORE_URL`: removed from vci's environment at start-up, never printed (`vci store info` says `token: (set)`) | the URL's `authToken`, else what `[store] token_command` prints |
| `VCI_STORE_REPLICA` | libSQL: read a local replica of the `VCI_STORE_URL` server kept in this file (absolute, or relative to the git common directory), synced when a command first reads it and at its later prefetches | `[store.libsql] path`, else `vci-store.libsql` in the git common directory, when the replica is asked for |
| `VCI_STORE_NAMESPACE` | PostgreSQL and a libSQL server: the namespace of this repository's records. Required in a shallow clone, with the same value wherever the store is shared | `[store.postgres]` or `[store.libsql] namespace`, else the repository id (its first commit) |
| `VCI_STORE_CONNECT_TIMEOUT_SECS` | seconds a connection may take (more than 0, at most 3600) | `[store] connect_timeout`, else 5 |
| `VCI_STORE_TIMEOUT_SECS` | seconds one statement, request or wait may take (more than 0, at most 3600); `vci prune` gives PostgreSQL and a libSQL server ten minutes | `[store] timeout`, else 30 |
| `VCI_STORE_SYNC` | `off`: the SQLite files (git-meta's store, the SQLite store, libSQL's local file and replica) do not sync to disk after a write. `replica`: the libSQL store reads a local replica of its server (as `[store.libsql] replica = true`) | git-meta's store does not sync when `CI` is set; the others sync; libSQL reads its server |

`VCI_STORE_NAMESPACE` and the timeouts are ordinary `VCI_*` variables: they reach the test processes (built-in ignore)
and are never hashed. `VCI_STORE` is removed like `VCI_STORE_URL`, so a connection string put there by mistake is in no
test's environment either. Put `VCI_STORE_URL` (and `VCI_STORE_TOKEN`) in a CI secret; a job without the secret (a pull
request from a fork) cannot reach the store and runs every test, and a job that runs untrusted code with the secret gets
a read-only credential, since its tests can read it ([Secrets](#secrets)). On a developer's machine export nothing:
`[store] url` and `[store] token_command` in `vci.toml` say where the server is and which command prints its token (`com
secrets get …`, `op read …`), run once per vci command that reads the store, in the repository's top level, without the
three variables above (docs/REFERENCE.md, "The credential from a command"). Both come from the checkout, and the token
goes to its url: review a change to either, and set `VCI_STORE=git-meta` in a checkout you have not reviewed, which
makes vci ignore them. `VCI_STORE_REPLICA` and `VCI_STORE_SYNC` are ordinary `VCI_*` variables too. `vci store info`
prints the store and every setting with where it came from. The test suites read `VCI_TEST_POSTGRES_URL`,
`VCI_TEST_POSTGRES=require` and `VCI_TEST_PG_BINDIR`, and `VCI_TEST_LIBSQL_URL`, `VCI_TEST_LIBSQL_TOKEN` and
`VCI_TEST_LIBSQL=require` (docs/REFERENCE.md, "Development").

## Runner notes

Vitest: reads are observed in the workers and in the main process (a variable read by the config file, an inline
plugin or a globalSetup file counts as read by every test file). `NO_COLOR` and `FORCE_COLOR` are removed unless
listed (output colour can change a test's result).

node:test: a `NODE_OPTIONS` value (from the environment, an `--env-file` or a `--require` preload) with anything but
memory, warning and stack-trace options refuses every file; `.npmrc` `node-options` with anything else refuses the
project. Variables a script only expands in its options (`${TEST_CONCURRENCY:+...}`) are not hashed: their effect is
the recorded argv.

pytest: uv's variables are built-in ignore so that `uv run` works; every `uv run` gets `--no-env-file` (a `.env`
file would add variables after vci computed the environment). `PYTHONPATH` is vci's own: the user's value never
reaches the tests.

Go: the test log records every `os.Getenv`/`os.LookupEnv`, including during package initialisation. A package that
uses the local time zone with `TZ` unset is refused (it would come from `/etc/localtime`): `set = { TZ = "UTC" }`. The
effective build settings (`go env`, including `go env -w` values) are part of the toolchain. `set = { CGO_ENABLED =
"0" }` makes `go env` agree whether or not a C compiler is installed.

Cargo: nothing observes what a Rust test reads at run time, so the adapter only attests under the default policy
(not `mode = "loose"`), where every unlisted variable is unset both where the unit was attested and in CI. Built-in
ignore variables are hashed when the source names them literally (`std::env::var("HOME")`); a computed name is not
seen. `TMPDIR` is a fresh directory for every cargo build and every test executable vci starts. vci runs the test
executables itself (`VCI_CARGO_JOBS` at a time) and adds what `cargo test` would: `CARGO`, `CARGO_MANIFEST_DIR`,
`CARGO_MANIFEST_PATH`, `CARGO_PKG_*`, `OUT_DIR` and the build script's `cargo::rustc-env` variables,
`CARGO_BIN_EXE_<name>`, the library search path, the cargo configuration's `[env]` table, and under rustup's proxy
`CARGO_HOME`, `RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`, `RUSTUP_TOOLCHAIN_SOURCE` and `RUST_RECURSION_COUNT` (see
[Quick start (Cargo)](REFERENCE.md#quick-start-cargo)). As under `cargo test`, these win over the policy (`set`
included), except `[env]` entries without `force`; they come from hashed inputs (the manifests, the build, the
repository's cargo config) or name locations.

Rails: reads RubyGems and Bundler make of their own variables while setting up the bundle are not observations (the
bundle they produce is checked). Rails' generated `config/environments/test.rb` reads `CI`
(`config.eager_load = ENV["CI"].present?`): removed by default, it is unset everywhere and nothing is eager-loaded;
`set = { CI = "true" }` makes it the same everywhere but eager-loads every application file in every test process, so
each of them becomes an input of every test; in `hash`, a laptop's attestation will not match a runner's (vci
warns). The option files RSpec would read from `HOME` and `XDG_CONFIG_HOME` are never read
(every RSpec process gets `--options .rspec`).
