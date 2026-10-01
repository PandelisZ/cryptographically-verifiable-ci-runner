# vci: cryptographically verifiable CI test selection

If a developer (or an agent) already ran test file `b.test.ts` (or `test_b.py`, `test/models/b_test.rb` of a Rails
app, Go package `./b`, or the cargo test target `b#test:b`) against exactly the files it depends on, CI should not have
to run it again. `vci` makes that safe:

1. `vci run` runs Vitest, pytest, `go test` or Rails' `bin/rails test` with runtime dependency collectors, hashes
   every file, directory listing, missing-file probe, package version and env var each test file actually used, and
   signs an in-toto attestation with your SSH key. For Rust (`cargo test`), which has no hook for run-time reads, the inputs are decided conservatively
   instead (see [Quick start (Cargo)](#quick-start-cargo)).
2. Attestations are [git-meta](https://git-meta.com/) metadata on the test unit's path (`git meta get
   path:src/b.test.ts`), exchanged on `refs/meta/main` by ordinary git push and fetch (`vci push`, `vci fetch`, or
   `git meta push` / `git meta pull`). vci adds no database or files of its own; git is the transport and the
   authority. See [Where attestations live (git-meta)](#where-attestations-live-git-meta).
3. In CI, `vci plan` checks each attestation against the **base commit's** `.vci/allowed_signers` and `vci.toml`,
   re-hashes every recorded input from CI's own checkout, and skips a test file only when everything matches.
   `vci ci` then runs the rest.

The core rule is **fail open**: the default verdict is RUN. Any error, doubt or unrecognised behaviour means the test runs.

Status: v1, Vitest `>=3.2 <6` (tested on 5.0.2 and 4.1.11), Node 22.15+; pytest 9 (tested on 9.1.1) on CPython
3.11-3.14 through `uv`; Go modules with Go 1.26 (tested on 1.26.2); Cargo workspaces (tested with Rust and cargo
1.96.0); Rails 8 with Minitest on Ruby 3.4 (tested with Rails 8.1.3.1, Minitest 6.0.6, Ruby 3.4.9, SQLite); macOS and
Linux.

## Install

```sh
git clone https://github.com/PandelisZ/cryptographically-verifiable-ci-runner.git ~/.local/share/vci
~/.local/share/vci/scripts/install.sh
export VCI_PY_PLUGIN="$HOME/.local/share/vci/py/pytest-plugin"
export VCI_JS_PLUGIN="$HOME/.local/share/vci/js/vitest-plugin"
export VCI_RUBY_COLLECTOR="$HOME/.local/share/vci/ruby/vci-collector"
```

Full guide: [docs/INSTALL.md](docs/INSTALL.md).

## GitHub Actions

After your toolchain setup steps, add:

```yaml
- uses: PandelisZ/cryptographically-verifiable-ci-runner@<commit-sha>
```

It builds `vci`, fetches attestations, and runs only what is not already attested. Setup, inputs and security rules:
[docs/GITHUB_ACTIONS.md](docs/GITHUB_ACTIONS.md).

## Quick start (Vitest)

Prerequisites: `git`, `node`, `ssh-keygen` (OpenSSH 8.1+), a Rust toolchain to build the CLI.

```sh
cargo install --path crates/vci-cli            # installs the `vci` binary

cd your-project                                # a git repo with at least one commit
npm install --save-dev /path/to/js/vitest-plugin   # the @vci/vitest collectors
#   (or leave it out and set VCI_JS_PLUGIN=/path/to/js/vitest-plugin)

vci init --key ~/.ssh/id_ed25519.pub --no-install  # writes vci.toml, .vci/allowed_signers, .git-meta
git add vci.toml .vci/allowed_signers .git-meta && git commit -m "Enable vci"
# The trust root is read from the base branch, so merge this commit to main first.

vci run src/b.test.ts --key ~/.ssh/id_ed25519   # run, collect, sign, store
vci plan --base-ref origin/main                 # SKIP src/b.test.ts, RUN the rest
vci push                                        # publish attestations (git-meta, refs/meta/main)
```

In CI (see [`examples/github-actions.yml`](examples/github-actions.yml)):

```sh
vci fetch --remote origin                       # git-meta pull: fetch refs/meta/main, materialize it
vci ci --base-ref "$BASE_SHA" --audit-log vci-audit.json
```

## Quick start (pytest)

Prerequisites: `git`, [`uv`](https://docs.astral.sh/uv/), `ssh-keygen` (OpenSSH 8.1+), a Rust toolchain. The project
must be a uv project with a committed `uv.lock` (tests run with `uv run --locked`) and a pytest config file
(`[tool.pytest.ini_options]` in `pyproject.toml`, `pytest.ini`, ...) in the project dir, so pytest's rootdir is the
project dir.

```sh
cargo install --path crates/vci-cli            # the collector (py/pytest-plugin) is found in this checkout,
                                               # or set VCI_PY_PLUGIN=/path/to/py/pytest-plugin
cd your-project                                # a git repo with at least one commit
uv python install 3.14.4                       # a uv-managed build that uv also ships for the CI platform
echo 3.14.4 > .python-version                  # pin the full version: attestations only match the same patch
export UV_PYTHON_PREFERENCE=only-managed       # never pick up Homebrew's or the system's Python
uv lock

vci init --adapter pytest --key ~/.ssh/id_ed25519.pub   # writes vci.toml (adapter = "pytest") and allowed_signers
git add vci.toml .vci/allowed_signers .git-meta uv.lock .python-version && git commit -m "Enable vci"

vci run tests/test_b.py --key ~/.ssh/id_ed25519   # one pytest process per file, collect, sign, store
vci plan --base-ref origin/main                    # SKIP tests/test_b.py, RUN the rest
vci push
```

`vci run` runs `PYTHONPATH=<py/pytest-plugin> VCI_OUT=<tmp> PYTHONPYCACHEPREFIX=<tmp> uv run --locked --exact
--no-env-file pytest -p vci_pytest <file>` once per test file (in parallel, `$VCI_JOBS` at a time, default: CPUs up to
8), so each file's inputs are recorded in isolation. Every `uv run` of vci (listing, probing, `vci ci`) is `--exact`
(packages not in `uv.lock` are removed from the environment first, so pytest must be in the project's default
dependency groups) and `--no-env-file` (`UV_ENV_FILE` is ignored), and bytecode is compiled into a fresh
`PYTHONPYCACHEPREFIX` (a stale `__pycache__` can never run in place of the hashed source). `vci ci` runs each remaining
file in its own `uv run pytest <file>` process, the same isolation the attestations were made with, and exits
non-zero if any fails. **An attestation vouches for the file run on its own**: a module-level side effect of one test
file that breaks another only when both share a process is not reproduced by `vci run` or `vci ci` (it would be by a
plain full-suite `pytest`). CI example: [`examples/github-actions-pytest.yml`](examples/github-actions-pytest.yml).

### Attesting on macOS, verifying on Linux (`platform = "any"`)

Attestations made on a laptop can be accepted by a GitHub Actions `ubuntu-latest` runner when everything the
toolchain check compares is identical there:

- **the Python build**: attest with a uv-managed interpreter (python-build-standalone) whose exact patch version uv
  also ships for `x86_64-linux-gnu` (`uv python list --all-platforms`; e.g. 3.14.4 with uv 0.11.7; Homebrew's 3.14.7
  has no Linux build), pinned in `.python-version`, with `UV_PYTHON_PREFERENCE=only-managed` on both sides. The
  bundled sqlite and OpenSSL versions are compared too (`python libraries`). `vci run` warns when the interpreter is
  not uv-managed;
- **uv**: pin the same uv version locally and in `astral-sh/setup-uv` (`version:`), so both resolve the same builds;
- **the installed distributions**: the full `name==version` set must be equal (`python distributions`). A dependency
  with a platform marker (`sys_platform == 'linux'`) installs only on one side, so every file runs there;
- **directory listings**: a test that lists a directory records every entry, including `.DS_Store` and
  `__pycache__`, which a fresh checkout does not have. `vci run` warns about such listings; delete the junk and attest
  again;
- **environment**: in strict mode only declared variables reach tests. A test that reads `CI`, `HOME`, `USER`,
  `TMPDIR`, `LANG`, ... records their values, so it is skipped only where they are equal (on a runner: never).

Everything else (a different OS, `sys.platform`-dependent code paths in your tests or dependencies) is what
`platform = "any"` accepts; use `platform_overrides` with `"exact"` for files that behave differently per platform.
Files with skipped tests (`skipif(sys.platform == ...)`) are never attested.

## Quick start (Go)

Prerequisites: `git`, `go` (1.26), `ssh-keygen` (OpenSSH 8.1+), a Rust toolchain. The project is a Go module
(`project` is the directory holding `go.mod`); the unit is a **package**: every directory with `_test.go` files.
Test ids are package directories relative to the repository root (`b`, `svc/internal/store`; the module's root
package is its directory, `.` at the repository root).

```sh
cargo install --path crates/vci-cli
cd your-module                                  # a git repo with at least one commit
vci init --adapter go --key ~/.ssh/id_ed25519.pub   # writes vci.toml (adapter = "go") and allowed_signers
git add vci.toml .vci/allowed_signers .git-meta && git commit -m "Enable vci"

vci run ./b --key ~/.ssh/id_ed25519   # package directories (default: every package with tests)
vci plan --base-ref origin/main        # SKIP b, RUN the rest
vci push
```

`vci run` runs one `go test` process per package (`$VCI_JOBS` at a time):

```
TMPDIR=<fresh empty dir> VCI_GO_TESTLOG=<file> go test -count=1 -json -overlay=<tmp>/overlay.json ./b
```

The overlay adds one file to the standard library's `internal/testlog` for this build only: a logger that records
every file package os opens or stats, every environment variable it looks up and every chdir, from the moment the
runtime initialises package os (so package-level `var golden = mustRead("testdata/x")` and `TestMain` are
covered, which `go test`'s own cache misses), and every `os.StartProcess`. `go list -e -deps -test -json` gives the
compile-time inputs. `vci ci` runs the remaining packages with `go test -count=1 -json <pkgs>` (the same flags,
output printed as text, a fresh `TMPDIR`) and exits non-zero if any fails; `-count=1` means Go's own test cache
never stands in for a run. Findings behind this design: [`docs/spike-go.md`](docs/spike-go.md). CI example:
[`examples/github-actions-go.yml`](examples/github-actions-go.yml).

### Attesting on macOS, verifying on Linux (Go)

Under `platform = "any"` a package attested on macOS arm64 is skipped on an ubuntu-latest x86_64 runner when:

- **the Go version is identical** (`go env GOVERSION`; pin it in `actions/setup-go`), and so are the effective
  `CGO_ENABLED`, `GOFLAGS`, `GOEXPERIMENT`, `GOFIPS140`, `GODEBUG` and `GOWORK`. `CGO_ENABLED` defaults to 1 only
  where a C compiler is found (Xcode's command line tools, the runner's gcc; a container without one defaults to 0),
  so the robust setting is to declare it (`[env] global = ["CGO_ENABLED", ...]`) and set `CGO_ENABLED=0` on both
  sides (cgo is refused anyway). The architecture level (`GOARM64`, `GOAMD64`) is compared only between machines of
  the same architecture, and another architecture is accepted only between 64-bit little-endian ones (amd64,
  arm64, riscv64, loong64);
- **no file of the test's own code is platform-specific**: if the package, or any package of the repository it
  imports, has a file whose inclusion depends on GOOS/GOARCH (`b_linux.go`, `x_amd64.s`, `//go:build darwin`,
  `//go:build unix`) **or whose code refers to `GOOS`, `GOARCH` or `Getpagesize`** (`runtime.GOOS`, an aliased
  `rt.GOARCH`, `build.Default.GOOS`, `os.Getpagesize`: a test that reads `testdata/` + `runtime.GOOS` + `.golden`
  only read the macOS file), the
  attestation records those files (`platformSpecific`) and is only accepted on the same OS and architecture,
  whatever the policy says. Files excluded here are hashed anyway (so editing `b_linux.go` on a Mac invalidates the
  attestation). A test that skips itself on some OS with `runtime.GOOS` is pinned too;
- **no floating-point code in the closure**, or the same architecture: the compiler may fuse `x*y + z` into one
  instruction on arm64 but not on amd64, so the same Go code can compute different results. A package whose closure
  has floating-point types or literals in non-standard code (the repository's or an external module's), or a
  non-standard package importing `math`, `math/cmplx`, `math/rand` or `math/rand/v2`, is recorded as
  `archSpecific` and accepted only on the attesting architecture (another OS is fine). This covers modules such as
  go-cmp and testify that mention `float64`; the rest of the standard library is assumed to compute the same on
  every architecture;
- **the local time zone is not used**, or `TZ` is set: a test that uses `time.Local` (`time.Now().Zone()`,
  formatting a local time, `time.Unix`, the `log` package's timestamps) with `TZ` unset reads `/etc/localtime`,
  which is not an input (macOS laptops are rarely on UTC; runners are), and is refused. Declare `TZ` in `[env]
  global` and set the same value on both sides (`TZ=UTC`): it is then hashed;
- the directory listings match (`.DS_Store` in a package directory breaks that; `vci run` warns), and the test
  read no variable whose value differs (`HOME`, `CI`, `USER`, ...).

What is accepted under `any` without a same-platform check: platform-dependent code in the standard library and in
external modules (a module's `_linux.go` file, its `runtime.GOOS` switches, its imports on the other platform), and
behaviour that differs between machines without an input (the number of CPUs, data races that only show under
arm64's weaker memory model). Use `"exact"` (or `platform_overrides`) for packages where that matters.

## Quick start (Cargo)

Prerequisites: `git`, `cargo`/`rustc` (tested with 1.96.0), `ssh-keygen` (OpenSSH 8.1+). The project is a Cargo
workspace (or a single package) with a committed `Cargo.lock`; `project` is the directory holding the workspace's
`Cargo.toml` and `Cargo.lock`. The unit is a **cargo test target** of a workspace member:

| Test id | What `cargo test` runs |
|---|---|
| `<package dir>#lib` | the library's unit tests (`--lib`) |
| `<package dir>#doc` | the library's doctests (`--doc`), a unit of their own |
| `<package dir>#bin:<name>` | a binary's unit tests (`--bin <name>`) |
| `<package dir>#test:<name>` | an integration test file `tests/<name>.rs` (`--test <name>`) |
| `<package dir>#example:<name>`, `#bench:<name>` | examples/benches with `test = true` |

The package dir is relative to the repository root (`crates/vci-core#lib`; `.#lib` for a package at the root). The
units are exactly what `cargo test --workspace` runs: targets with `test = true` (doctests: `doctest = true`) whose
`required-features` are on by default.

```sh
cargo install --path crates/vci-cli
cd your-workspace                                  # a git repo with at least one commit
vci init --adapter cargo --key ~/.ssh/id_ed25519.pub   # writes vci.toml (adapter = "cargo") and allowed_signers
git add vci.toml .vci/allowed_signers .git-meta Cargo.lock && git commit -m "Enable vci"

vci run crates/b#test:b --key ~/.ssh/id_ed25519   # one unit; `vci run crates/b` = every unit of that package;
                                                   # no arguments = every unit
vci plan --base-ref origin/main                    # SKIP crates/b#test:b, RUN the rest
vci explain crates/b#test:b --base-ref origin/main
vci push
```

`vci run` runs one `cargo test` per unit, one at a time (cargo locks the build directory), each with a fresh empty
`TMPDIR`:

```
cargo test --locked --manifest-path crates/b/Cargo.toml --test b --message-format=json --target-dir <target>/vci
```

`--manifest-path` selects the package the way `-p <name>` would (package names can be ambiguous; the path cannot).
vci builds into `<target dir>/vci`, which only ever sees builds made with vci's strict environment, and **rebuilds the
repository's crates in every `vci run`** (`cargo clean -p <every workspace member>` there first; a crate of the
repository found reused later, such as a path dependency outside the workspace, is cleaned and its unit run again):
cargo decides freshness by modification times and by what build scripts declare, vci by content, so a file restored
with an older mtime (`cp -p`, `tar`, `rsync -t`), a build script reading a file or a variable it does not declare, or
a proc macro reading a variable, would otherwise be attested against a stale build. External crates stay cached. `vci ci` runs every
remaining unit with the same command (without `--message-format`), one unit per `cargo test`, so each unit is built
with the features the attestation was made with (Cargo resolves features per selected package); it exits non-zero if
any fails. **An attestation vouches for the unit run on its own**: a plain `cargo test --workspace` can unify features
differently. `cargo test` also compiles examples that are not test targets; `vci ci` does not (the example workflow
keeps a `cargo build --examples` step). CI example: [`examples/github-actions-cargo.yml`](examples/github-actions-cargo.yml).
Findings behind this design: [`docs/spike-cargo.md`](docs/spike-cargo.md).

### What the cargo adapter can and cannot see (read this)

Rust has no hook for what a test reads at run time. The cargo adapter therefore uses a **conservative rule** instead of
observed reads: every file (and every directory listing) in the package directory of the unit's package **and of every
crate of the repository the unit builds** is an input, `.gitignore`d files included (they are not in a fresh checkout,
so a unit whose package directory holds some will run in CI; `vci run` warns). The target dir and the repository's
`.git` and `.vci/out` are not inputs and are left out of their parent's listing (so a package at the repository root
matches a fresh checkout without `target/`); a symlinked directory is walked at its target (inside the repository; one
leading outside refuses the unit); another repository (a `.git` directory) inside a package directory refuses it. A
package at the repository root has every file of the repository below it as input, other packages' included: any
change runs its units (prefer a virtual workspace manifest at the root). **A test that reads files elsewhere in the
repository must declare them** in `vci.toml`:

```toml
[[inputs]]
match = ["crates/b#test:*"]       # unit ids, relative to the project dir (globs)
extra = ["testdata/**", "shared/config.json"]   # files, relative to the project dir (globs)
```

vci looks for such reads in the source (string literals starting with `../` or `/` passed to file APIs, directly or
through a `const`/`static`/`let` binding; paths built from `CARGO_MANIFEST_DIR` with `concat!`/`format!`;
`CARGO_MANIFEST_DIR` combined with `parent()`) and refuses the unit when a path it finds is not a recorded input, but
that is a heuristic: a path built at run time is not seen. **Reads outside the repository cannot be declared**: a
literal one refuses the unit, one built at run time (`$HOME/...`, `std::env::temp_dir()` joined with a name the test
did not create) is not detected. **This guarantee is weaker than the Vitest, pytest and Go
adapters'**, which record what a test actually opened. Everything else the adapter cannot observe (child processes,
sockets, native code, enumerating the environment) is refused by static checks listed under
[When `vci run` refuses to attest](#when-vci-run-refuses-to-attest), which are heuristics too.

### Attesting on macOS, verifying on Linux (Cargo)

Under `platform = "any"` a unit attested on macOS arm64 is skipped on an ubuntu-latest x86_64 runner when:

- **rustc and cargo are identical**: `rustc -vV` release, commit hash and LLVM version, and `cargo -vV` release and
  commit hash. Use rustup on both sides with a pinned toolchain (`rust-toolchain.toml` with `channel = "1.96.0"` and
  `dtolnay/rust-toolchain` in CI). Homebrew's rustc is built against Homebrew's LLVM and can report another LLVM
  version than rustup's build of the same release (Homebrew's 1.96.0 here: LLVM 22.1.6; rustup's 1.95.0: LLVM
  22.1.2), in which case its attestations never match a rustup runner. vci probes the `rustc` next to the `cargo`
  it runs (`$RUSTC` if declared): with Homebrew's `cargo` first on PATH, `rust-toolchain.toml` is ignored, so put
  `~/.cargo/bin` first or set `VCI_CARGO=~/.cargo/bin/cargo`. Checked with rustup's 1.95.0 on macOS arm64 and in a
  `rust:1.95.0` Linux arm64 container: `rustc -vV` (commit `59807616e`, LLVM 22.1.2) and `cargo -vV` are identical, and
  the container, as a non-root user, skipped every attested unit without platform-specific code and ran the others;
- **every target-dependent `cfg` in the unit's repository code evaluates the same there**. vci records each `cfg(...)`,
  `cfg!(...)` and `cfg_attr(<pred>, ...)` predicate of the unit's repository sources and manifests
  (`[target.'cfg(windows)'.dependencies]`) that mentions the target (`unix`, `target_os`, `target_arch`,
  `target_feature`, ...), and the attesting host's `rustc --print cfg`. `vci plan` evaluates each predicate on both
  cfg sets, other atoms (`feature = "x"`, `test`) being the same on both sides: `cfg(unix)` holds on both macOS and
  Linux, so vci's own crates are accepted; `cfg(target_os = "linux")` does not, so the unit runs. A predicate vci
  cannot parse (a macro-built `cfg($meta)`), a runtime check (`std::env::consts::OS`), a build script reading
  `TARGET`/`CARGO_CFG_*`, or a `[target.<triple>]` table pins the unit to the attesting OS and architecture
  (`platformSpecific`);
- **the repository's cargo config applies the same way**: a `[target.'cfg(..)']` table is recorded like a `cfg` in the
  code (a table for `target_os = "macos"` makes the unit run on Linux), a `[target.<triple>]` table pins the unit to
  the attesting OS and architecture, and the flags the build uses (`RUSTFLAGS`, else the matching target tables, else
  `build.rustflags`) are applied to the `rustc --print cfg` probe on both sides;
- **no runtime platform constant**: code of the unit's repository crates (tests, build scripts, proc macros, generated
  `OUT_DIR` code) that uses `std::env::consts` (`OS`, `ARCH`, `FAMILY`, `DLL_PREFIX`, `DLL_SUFFIX`, `DLL_EXTENSION`,
  `EXE_SUFFIX`, `EXE_EXTENSION`), or a floating-point function std takes from the platform's C math library (`sin`,
  `cos`, `tan`, `exp`, `ln`, `log2`, `log10`, `powf`, `powi`, `cbrt`, `hypot`, the hyperbolic and inverse functions),
  pins the unit to the attesting OS and architecture (`platformSpecific`); a build script that emits a custom cfg
  after checking `consts::OS` is pinned the same way;
- **file names match in letter case**: macOS's default filesystem ignores case, Linux's does not. A path literal whose
  case differs from the file on disk (`"tests/Data/B.json"` for `tests/data/b.json`) refuses the unit; a path built at
  run time with the wrong case is not detected;
- **the same privileges**: the tests run as root on one side only (a GitHub `container:` job) is a toolchain
  difference (`superuser`), for every adapter;
- the environment matches (strict mode removes `RUSTFLAGS`, `CARGO_*`, `RUST*` unless declared; declared values must
  be equal) and no input is missing in the checkout (`.DS_Store` in a package directory breaks that).

Accepted under `any` without a check: platform-dependent code **outside the repository** (a crate from crates.io with
`cfg(target_os)` code or target-specific dependencies, its `consts::OS` checks and float math), the C compiler and
system libraries used by build scripts of external crates, the platform's C math library behind the float functions of
external crates, and behaviour that differs without an input (the number of CPUs, the kernel, time). Use `"exact"` (or
`platform_overrides`) where that matters.

## Quick start (Rails)

Prerequisites: `git`, `ssh-keygen` (OpenSSH 8.1+), a Rust toolchain, and the project's Ruby with its bundle installed
(tested with Ruby 3.4.9 through [mise](https://mise.jdx.dev/), Bundler 4.0.9, Rails 8.1.3.1, Minitest 6.0.6, SQLite
through the `sqlite3` gem 2.9.6). The project is a Rails application (`project` is the directory holding `Gemfile` and
`bin/rails`); the unit is a **Minitest test file**, the files `bin/rails test` runs by default (`test/**/*_test.rb`
without `test/system`, `test/dummy` and `test/fixtures`). Test ids are repo-relative paths. **RSpec is not supported
yet** (see the limitations below).

```sh
cargo install --path crates/vci-cli            # the collector (ruby/vci-collector) is found in this checkout,
                                               # or set VCI_RUBY_COLLECTOR=/path/to/ruby/vci-collector
cd your-app                                    # a git repo with at least one commit
bundle lock --add-platform x86_64-linux        # so the CI runner can install the same bundle
vci init --adapter rails --key ~/.ssh/id_ed25519.pub   # writes vci.toml (adapter = "rails") and allowed_signers
git add vci.toml .vci/allowed_signers .git-meta Gemfile.lock && git commit -m "Enable vci"

TZ=UTC vci run test/models/b_test.rb --key ~/.ssh/id_ed25519   # one Ruby process per file, collect, sign, store
TZ=UTC vci plan --base-ref origin/main                          # SKIP test/models/b_test.rb, RUN the rest
vci push
```

`vci run` runs every file in its own process (`$VCI_JOBS` at a time, default: CPUs up to 8; one at a time with
`policy.rails_allow_db`):

```
RUBYOPT=-r<abs>/ruby/vci-collector/vci_collector.rb VCI_RAILS_MODE=collect VCI_OUT=<fresh dir> \
  VCI_DB_DIR=<fresh dir> TMPDIR=<fresh dir> RAILS_ENV=test PARALLEL_WORKERS=1 DISABLE_SPRING=1 \
  DISABLE_BOOTSNAP=1 BUNDLE_GEMFILE=<project>/Gemfile ruby bin/rails test test/models/b_test.rb --seed 0
```

The collector (`ruby/vci-collector/vci_collector.rb`, plain Ruby, nothing is installed into your project) is loaded
through `RUBYOPT` before `bin/rails`, Bundler and Rails. It makes every run start from the same state:

- **a fresh database**: every SQLite database of the test environment (`config/database.yml`, each database of a
  multi-database app) is redirected to a new file in a temp dir, and the schema (`db/schema.rb`, or `db/structure.sql`
  loaded in-process) is loaded into it after Rails initialises and before `rails/test_help` checks it (Rails would
  otherwise run `bin/rails db:test:prepare` as a child process). Fixtures are loaded by Rails as usual. Data left in
  `db/test.sqlite3` by earlier runs is never used, and `db/` is never written;
- **one process**: `PARALLEL_WORKERS=1` (Rails' `parallelize` then runs in-process; a fork is refused), no Spring, no
  Bootsnap caches (`DISABLE_BOOTSNAP=1`, which `bootsnap/setup` honours; a compile or load-path cache still in use,
  such as one an explicit `Bootsnap.setup(...)` in `config/boot.rb` installs whatever the variable says, is refused);
- **a fixed Minitest seed** (`--seed 0`): the order of the tests in the file and `rand` (Minitest seeds it) are the
  same where the file was attested and in CI. (A test that passes only in some orders passes in neither or both.)
- **a fresh local secret**: the development/test `secret_key_base` Rails would keep in `tmp/local_secret.txt` is
  generated in memory for each process, as on a fresh checkout, so its random content is not an input.

`vci ci` runs each remaining file the same way (`VCI_RAILS_MODE=plain`: the same database, process and seed, nothing
recorded) and exits non-zero if any fails. **An attestation vouches for the file run on its own**, like the pytest
adapter: a test that passes only after another file ran in the same process is not reproduced. CI example:
[`examples/github-actions-rails.yml`](examples/github-actions-rails.yml). Findings behind this design:
[`docs/spike-rails.md`](docs/spike-rails.md).

### What the Rails adapter records

Ruby has no audit hook. The collector wraps the Ruby entry points instead (`File`, `FileTest`, `IO`, `Dir`
including `Dir.open`, `File::Stat`, `Pathname` through them, `Kernel#open`/`require`/`load`/`test` and their
`Kernel.require`/`Kernel.load` copies, which every plain `require` goes through under Bundler on Ruby 3.4, `ENV`,
`Process`, sockets), and records per file. Libraries with C entry points it must hook (`PTY`, `Fiddle`, FFI, SQLite,
database clients, Nokogiri, `Zlib`) are hooked when their constants are defined, however they were loaded; one loaded
but never hooked refuses the file (`vci:not-hooked:`).

- **code**: every Ruby file compiled from disk (`require`, `require_relative`, `load`, `autoload`, Zeitwerk), and for
  every `require` of a feature name, each repository `$LOAD_PATH` entry Ruby searched before the one that held it
  (`<entry>/<feature>.rb`, `.so`, `.bundle` as absent), so a file that would shadow it invalidates; a failed `require`
  (an optional dependency, `Bundler.require` of a gem with no file of its name) records every candidate as absent;
- **Zeitwerk**: the listing of every autoload directory it scans (`app/models`, `lib`, ... and namespaces as they
  load). A new file in `app/models` therefore runs every test that boots Rails: whether a new constant changes
  resolution is decided by Zeitwerk at run time, and vci does not model it;
- **files**: every read, existence or type check (absent paths as probes), glob (the listing of every directory the
  pattern reads, and every literal path it checks) and directory listing: `config/database.yml`, initializers, locale
  files, view templates (read when rendered), `test/fixtures` (`fixtures :all` lists the directory and loads every
  `.yml`), files a test picks at run time, `db/schema.rb`. Reading a file after the same process created it (or
  truncated it, or renamed its own file onto it) is not an input; reading or checking it before that is (see the
  writes rule below); deleting, renaming or `chmod`-ing a file records that it existed, and creating one records
  its directory;
- **gems**: every gem of the bundle whose files the test loaded or read, as `name` + `version` (a git source: its
  locked revision too). When the file is attested, each such gem's archive in the RubyGems cache must have the sha256
  `Gemfile.lock` records (`CHECKSUMS`), and every file of the gem the test used must be the archive's copy (a
  hot-patched installed gem refuses the file; a gem without its cached `.gem` is refused as unverifiable). The
  toolchain records the whole resolved bundle (`name==version`);
- **environment**: every variable read through `ENV` (`[]`, `fetch`, `key?`, `values_at`, ...), and always `TZ`,
  `RUBYLIB`, `RUBY_*` variables Ruby reads at startup and `RUBYGEMS_GEMDEPS`. Reads that RubyGems and Bundler make of
  their own variables (`HOME`, `PATH`, `GEM_*`, `BUNDLE_*`, ...) while they set up the bundle are not inputs: their
  outcome, the bundle, is.

Global inputs of every file: `vci.toml`; in the project dir `Gemfile`, `Gemfile.lock` (or `gems.rb`/`gems.locked`),
`config/application.rb`, `config/boot.rb`, `config/environment.rb`, `config/environments/test.rb`, `config.ru`,
`bin/rails`, `test/test_helper.rb` and `Rakefile`; and `.ruby-version`, `.tool-versions`, `mise.toml` (and its
variants) from the project dir up to the repository root. Missing ones are recorded as absent. **Any `Gemfile.lock`
change runs everything.**

Toolchain: Ruby's version and patchlevel (`3.4.9p82`) and engine, Rails, Bundler and Minitest versions, the SQLite
library the `sqlite3` gem loaded, libyaml, the time zone data (the `tzinfo-data` gem, or the system zoneinfo directory
and its version), the default external/internal encodings, the collector's version (`vci_collector.rb`'s
`VERSION`, bumped whenever what it records or refuses changes, so CI must run the same collector: pin the action or
the vci checkout to the commit you attest with), the database (`sqlite3`; a server's name and version with
`policy.rails_allow_db`), the full bundle, and whether the tests ran as root; OS/arch per `policy.platform`.

Test results: a file is attested only when the process exits 0 and every test passed: **any failure, error or skip,
no test at all, or a test that made no assertion** refuses it.

**Writes.** A test may write to git-ignored paths in the project's `log/`, `tmp/`, `storage/` and `coverage/`
(Rails' log, caches, uploads): derived state that no checkout has. Any other write inside the repository (a tracked or
unignored file, `db/`, `app/`, `public/`) refuses the file. Reading back what the same process wrote is not an input;
reading a file there that existed before the process started (a cache a previous run left, `tmp/local_secret.txt`
from a plain `bin/rails test`, a file another test file wrote) is an input, which a fresh CI checkout will not match,
so that file runs in CI (`vci run` warns about recorded inputs git ignores, such as `config/master.key`). This holds
when the process later overwrites that file (`File.write`, `File.atomic_write`, delete and recreate): what it read
first is recorded, and the overwrite then refuses the file as an input changed during the run.

**Credentials.** `config/credentials*.yml.enc` and the key files are recorded when the test reads them (Rails reads
them lazily). `config/master.key` is git-ignored and secret: only its BLAKE3 hash is stored, and a fresh checkout does
not have it, so a test that read it runs in CI. A key given as `RAILS_MASTER_KEY` follows the env policy (strict mode
removes it unless declared; declared, its hash is stored, as for any declared variable).

**In an app generated with credentials (`rails new` writes `config/master.key` and `config/credentials.yml.enc`),
Active Record reads `config/master.key` while Rails boots** (its encryption settings come from the credentials), so
every test that boots Rails reads it and **nothing is ever skipped in CI**: `vci run` warns (`it read
config/master.key, Rails' credentials key`). Nothing is wrong (it fails open), but to get skips, do one of:

- give the test environment its own credentials with a key you commit (it guards nothing secret):
  `bin/rails credentials:edit --environment test`, then commit `config/credentials/test.key` (un-ignore it if
  `.gitignore` lists it) and `config/credentials/test.yml.enc`. Rails then reads those in the test environment
  instead of `config/master.key`;
- remove `config/master.key` and `config/credentials.yml.enc` if nothing needs them;
- or declare `RAILS_MASTER_KEY` (`[env] global = ["RAILS_MASTER_KEY"]`) and set it to the same value where you attest
  and in CI (a secret there): Rails then reads the key from the environment, not the file.

### Databases (read this)

The test database is a hidden input of almost every Rails test: its contents are whatever the last run left. vci
therefore never uses an existing test database:

- **SQLite** files are supported: each process gets a fresh file in a temp dir with the schema loaded (above). The
  configured location (`db/test.sqlite3`, `storage/test.sqlite3`) is never opened. `db/schema.rb` (or
  `structure.sql`), `config/database.yml` and every fixture file the test loads are inputs, and so is the SQLite
  library version. A SQLite file opened anywhere else (`SQLite3::Database.new("db/other.sqlite3")`,
  `establish_connection` to another file, a `DATABASE_URL` naming a file), an in-memory test database in
  `database.yml`, `ATTACH`, and SQLite extensions refuse the file: SQLite reads and writes those files in C, where vci
  cannot see them. (An in-memory database a test opens for itself is fine.)
- **Database servers** (PostgreSQL, MySQL, Trilogy) of the test environment are refused by default; so is any
  database client a test opens itself (`PG.connect`, `Mysql2::Client.new`, Redis or anything over a socket), always.
  `policy.rails_allow_db = true` in the **base commit's** `vci.toml` waives the refusal for the databases
  `config/database.yml` configures for the test environment (Active Record's connections): vci then purges each one and
  loads the schema before every file (so files run one at a time), records the waiver in the attestation (`waived`)
  and the server's name and version in the toolchain, and `vci plan` accepts the attestation only while the base
  policy still sets it and the CI server reports the same version.

  **What the waiver means:** vci sees neither what the server holds nor what else talks to it. With the waiver you
  state that the test database holds nothing but what vci loads (the schema, then fixtures and what the test itself
  creates): no data loaded by other means (a `structure.sql` with `INSERT`s is fine: it is hashed; a database restored
  from a dump, a shared staging database, triggers or extensions installed outside the schema, or another job writing
  to the same database are not), and that server-side state outside the database (configuration, collations, the
  server's time zone) does not change the tests' outcome. The server version is compared; its configuration is not.
  In CI, run the server as a service container with the same major and minor version as locally.

### Attesting on macOS, verifying on Linux (Rails)

Under `platform = "any"` a file attested on macOS arm64 is skipped on an ubuntu-latest x86_64 runner when:

- **Ruby is the same release and patchlevel** (pin it in `.ruby-version` and `ruby/setup-ruby`), and so are Rails,
  Bundler (the lockfile's `BUNDLED WITH`, which `setup-ruby` installs), Minitest, and every gem version of the bundle;
- **`Gemfile.lock` lists both platforms** (`arm64-darwin`, `x86_64-linux`): native gems such as `nokogiri` and
  `sqlite3` are then installed from their precompiled builds for each platform. vci matches a gem by name and version,
  not platform: **the macOS and Linux builds of one version are accepted as the same gem** (their contents differ;
  this is what `platform = "any"` accepts, as for the Python interpreter of the pytest adapter). The SQLite library
  those builds bundle is compared (the `sqlite3` gem 2.9.6 bundles SQLite 3.53.2 in both), and so is libyaml. Gems
  compiled at install time (`bigdecimal`, `json`, `racc`, ...) are matched by version; the compiler and system
  headers are not compared. Use `"same-os"` or `"exact"` (or `platform_overrides`) where a native gem's platform
  build matters;
- **time zone data comes from the `tzinfo-data` gem** (`gem "tzinfo-data"` for every platform, not the generator's
  `platforms: %i[ windows jruby ]`): without it Rails reads the system's zoneinfo, whose version is compared (macOS
  and Ubuntu rarely ship the same one), and nothing is skipped across them. `TZ` is declared and set to the same
  value on both sides (`TZ=UTC`): Ruby's local time zone otherwise comes from the machine (`/etc/localtime`, which
  is not an input);
- **`config/environments/test.rb` does not read `CI`**: the generator writes `config.eager_load = ENV["CI"].present?`,
  which makes every test depend on `CI` (unset on a laptop, `true` on a runner), so nothing is ever skipped there.
  Write `config.eager_load = false` (or declare and set `CI` the same way on both sides);
- **`vendor/` exists in the repository** (`vendor/.keep`, which `rails new` creates): `ruby/setup-ruby`'s
  `bundler-cache` installs gems into `vendor/bundle`, and Rails checks whether `vendor` exists; with it committed only
  its type is recorded. Installed gems themselves are never inputs (they are externals);
- the default external encoding is the same (`LANG=C.UTF-8` on runners, a UTF-8 locale on a Mac), and the tests do
  not read variables whose values differ (`HOME`, `CI`, `USER`, ...);
- **the tests do not read `config/master.key`**, which a generated app's Active Record reads at boot (see
  "Credentials" above: commit test-environment credentials, or drop the credentials, or declare `RAILS_MASTER_KEY`);
- **`config/boot.rb` does not call `Bootsnap.setup(...)` with a compile cache** (the generator's `require
  "bootsnap/setup"` is fine: it honours `DISABLE_BOOTSNAP`).

Checked locally (not on a GitHub runner): `fixtures/rails-abcd` attested on macOS arm64 (mise Ruby 3.4.9) was
skipped entirely by the static Linux `vci` in a `linux/amd64` `ruby:3.4.9` container (as a non-root user, gems
installed into `vendor/bundle` like `bundler-cache` does); editing the view template there ran only the file that
renders it, and another `TZ` ran everything.

**OpenSSL is not compared**: Ruby links the platform's OpenSSL (Homebrew's 3.6 on a Mac, a 3.0 or 3.5 build on Linux),
so comparing it would rule out every cross-platform skip. Algorithms give the same results across these versions; what
differs (which legacy ciphers exist, default security levels) is accepted under `platform = "any"`.

When something is not skipped and you expected it to be:

```sh
vci explain src/b.test.ts --base-ref origin/main
```

```
src/b.test.ts: RUN (no valid attestation (1 candidates; best failed inputs: entry:fixtures/b.json))
candidate 1: git-meta path:src/b.test.ts vci:attestation:3b9f…:b6c35e2a042def43:2002a8ce…
  signer: alice@example.com SHA256:tsNeKgQt70OZTfF07nIc2YrOeC6pHt7EvMF3r8USWEs
  issued 2026-09-28T00:26:18Z, expires 2026-10-12T00:26:18Z
  failed check: inputs
    (expected: recorded in the attestation; actual: this checkout / CI now)
    entry:fixtures/b.json
      expected: file exec=false size=24 blake3=b67128f7…
      actual:   file exec=false size=25 blake3=342a1f57…
```

In every check, `expected` is what the attestation recorded or claims and `actual` is what CI computes from its own
checkout, clock, policy and environment.

## Commands

| Command | Purpose |
|---|---|
| `vci init [--key K] [--principal P] [--project DIR] [--adapter vitest\|pytest\|go\|cargo\|rails] [--no-install] [--meta-url URL]` | Write `vci.toml`, `.vci/allowed_signers` (adding key `K`) and `.git-meta` (`url:` the metadata remote, default origin's URL), configure the git-meta remote, `npm install` `@vci/vitest` (Vitest), print a CI snippet |
| `vci run [FILES…] [--key PATH] [--ttl 14d]` | Run tests with collection on; sign and store an attestation for every attestable file (Go: package directory; Cargo: `<package dir>#<target>` unit, or a package directory for all its units). Exit code is the runner's (non-zero if any pytest, `go test`, `cargo test` or `bin/rails test` process failed) |
| `vci plan [--base-ref R] [--format text\|json\|github]` | Print which test files can be skipped and why the others run |
| `vci ci [--base-ref R] [--audit-log PATH]` | Plan, run the remainder, write a JSON audit log of every skip |
| `vci verify <envelope\|-> [--allowed-signers F] [--base-ref R]` | Verify one DSSE envelope and print its claims |
| `vci push` / `vci fetch` `[--remote R]` | git-meta push / pull of `refs/meta/main` (git-meta's merge; push retried as a single fast-forward commit when the remote moved; `vci push` says `nothing to push` when nothing was sent). `R`: a git-meta remote, or a git remote or URL to use as one; default: the configured git-meta remote, else `.git-meta`'s `url:`, else origin. See "What `vci fetch` and `vci push` guard against" |
| `vci prune [--dry-run]` | Delete attestations whose claimed expiry has passed from the local git-meta store (tombstones; `vci push` publishes them) |
| `vci explain <test-file> [--base-ref R]` | Every candidate attestation and the first check it failed, with expected vs actual |

Signing key: `--key`, else `$VCI_SIGNING_KEY`, else `git config user.signingkey` when `gpg.format = ssh` (a GPG
signing key is never used). Errors name the source the key came from. A `.pub` path works when the private
half is in `ssh-agent` (hardware keys included). The signer id (a segment of the git-meta key) is the first 16 hex chars of SHA-256 over the
public key blob.

Base ref: `--base-ref`, else `$VCI_BASE_REF`, else `origin/$GITHUB_BASE_REF`, else the first of `origin/HEAD`,
`origin/main`, `origin/master`, `main`, `master` that exists. If none resolves, everything runs. The base ref is the
trust boundary: `vci plan` prints a warning (and `--format json` lists it under `warnings`) when the base commit is
HEAD or contains it, because then `allowed_signers` and policy come from the commit under test.

Environment: `VCI_JS_PLUGIN` (path of the `@vci/vitest` package; default `node_modules/@vci/vitest` above the
project), `VCI_NODE` (node binary), `VCI_PY_PLUGIN` (the `py/pytest-plugin` directory holding `vci_pytest`; default:
`py/pytest-plugin` or `share/vci/pytest-plugin` above the `vci` executable, then the source checkout `vci` was built
from, then `py/pytest-plugin` above the project; a clear error names the variable when none is found), `VCI_UV` (uv
binary), `VCI_JOBS` (parallel pytest, `go test` or Rails processes in `vci run`), `VCI_GO` (go binary), `VCI_CARGO` (cargo
binary; rustc is `$RUSTC` when declared, else `rustc` on PATH), `VCI_RUBY` (ruby binary, default `ruby` on PATH),
`VCI_RUBY_COLLECTOR` (the `ruby/vci-collector` directory holding `vci_collector.rb`; looked up like `VCI_PY_PLUGIN`).

Strict env mode removes every variable that is not declared or pass-through from the test process, including
`NO_COLOR` and `FORCE_COLOR`, so `NO_COLOR=1 vci ci` still prints Vitest's colours. Add them to `pass_through` (seen
by tests, not hashed) or `global` (hashed) if you need them; they are not built in because a test's result can
depend on them.

Built-in pass-through variables (`PATH`, `HOME`, `USER`, `TMPDIR`, `LANG`, `LC_*`, `TERM`, `CI`, `NODE_OPTIONS`,
`VCI_*`, ...) are always visible, and **hashed when a test file is observed reading one**: their values differ between a
laptop and a CI runner, so a test that reads `CI` is not skipped on a runner. The exceptions are values vci sets for
the run itself (`VCI_OUT`, `VCI_WORKER`, `VCI_LIST_OUT`, `VCI_GO_TESTLOG`), and for Vitest its `VITEST*` worker
variables and `NODE_OPTIONS` (hashed as a global input instead); a Go, Rust or pytest test that reads `NODE_OPTIONS`
or `VCI_BASE_REF` gets it hashed. Configured
`pass_through` variables stay unhashed (your decision).

pytest adds its own built-in pass-through so that `uv` works in strict mode: `UV`, `UV_*`, `VIRTUAL_ENV`,
`XDG_{CACHE,CONFIG,DATA,BIN}_HOME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, the `*_PROXY` variables, and `PYTHONPATH` (vci
sets it to the collector directory; your value never reaches the tests, and a test that reads it is not attested).
Go adds `GOPATH`, `GOROOT`, `GOCACHE`, `GOMODCACHE`, `GOENV`, `GOPROXY`, `GONOPROXY`, `GOPRIVATE`, `GONOSUMDB`,
`GOSUMDB`, `GOINSECURE`, `GOVCS`, `GOAUTH`, `GOTELEMETRY*`, `GOCACHEPROG`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`,
`SSL_CERT_*`, the `*_PROXY` variables, `GIT_SSH`, `GIT_SSH_COMMAND` and `SSH_AUTH_SOCK` (where the go command finds
its caches and fetches modules). Every other `GO*` and `CGO_*` variable (`GOFLAGS`, `CGO_ENABLED`, `GOEXPERIMENT`,
`GODEBUG`, `GOMAXPROCS`, `GOAMD64`, `GOTOOLCHAIN`, ...) is **hashed whenever present** and removed in strict mode
unless declared (declare it in `[env] global` to set it). `TZ` and `ZONEINFO` are hashed for every package (package
time reads them without the log seeing it). `PWD` (set by `go test` to the package directory) and `TMPDIR` (vci's
fresh directory) are not inputs.

Cargo adds `CARGO_HOME`, `RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`, `CARGO_TARGET_DIR`, `CARGO_BUILD_JOBS`, `CARGO_NET_*`,
`CARGO_HTTP_*`, `CARGO_REGISTRIES_*`, `CARGO_REGISTRY_*`, `CARGO_TERM_*`, `CARGO_INCREMENTAL`, `RUSTC_WRAPPER`,
`RUSTC_WORKSPACE_WRAPPER`, `SCCACHE_*`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `SSL_CERT_*`, the `*_PROXY` variables,
`GIT_SSH`, `GIT_SSH_COMMAND` and `SSH_AUTH_SOCK`. Every other `RUST*` and `CARGO*` variable (`RUSTFLAGS`,
`RUSTDOCFLAGS`, `CARGO_PROFILE_*`, `CARGO_BUILD_*`, `RUST_TEST_THREADS`, `RUST_BACKTRACE`, `RUST_LOG`, `RUSTC_BOOTSTRAP`,
...) and the C toolchain variables build scripts read (`CC`, `CFLAGS`, `CC_*`, `PKG_CONFIG*`, `MACOSX_DEPLOYMENT_TARGET`,
...) are **hashed whenever present** and removed in strict mode unless declared. Also hashed: the variables rustc lists
as `env!`/`option_env!` dependencies, the `rerun-if-env-changed` variables of every build script the unit builds, and
every variable named literally in `env::var("X")`/`env::var_os("X")` in the unit's repository code (a read of `CI` or
`HOME` is compared like an observed read). The cargo adapter only attests in strict mode.

Rails adds what Ruby, RubyGems, Bundler and version managers need to find things: `GEM_HOME`, `GEM_PATH`,
`GEM_SPEC_CACHE`, Bundler's location and install settings (`BUNDLE_PATH`, `BUNDLE_APP_CONFIG`, `BUNDLE_USER_*`,
`BUNDLE_CACHE_PATH`, `BUNDLE_BIN`, `BUNDLE_JOBS`, `BUNDLE_RETRY`, `BUNDLE_DEPLOYMENT`, `BUNDLE_FROZEN`, ...), `MISE_*`,
`RBENV_*`, `ASDF_*`, `XDG_*_HOME`, `SSL_CERT_*` and the `*_PROXY` variables. The Ruby, gems and bundle they lead to
are checked directly. Every other `RUBY*`, `BUNDLE_*` (`BUNDLE_WITHOUT`, `BUNDLE_FORCE_RUBY_PLATFORM`, ...),
`BUNDLER_*`, `GEM_*`, `RAILS_*` (`RAILS_MASTER_KEY`, ...), `RACK_*`, `MT_*`, `MINITEST_*`, `BOOTSNAP_*` and `SPRING_*`
variable, `DATABASE_URL`, `*_DATABASE_URL`, `SECRET_KEY_BASE`, `SEED`, `TESTOPTS`, `TEST`, `TESTS`, `N`,
`DEFAULT_TEST`, `DEFAULT_TEST_EXCLUDE` and `SCHEMA` is **hashed whenever present** and removed in strict mode unless
declared. vci sets `RUBYOPT` (the collector; your value never reaches the tests), `RAILS_ENV`/`RACK_ENV` (`test`),
`BUNDLE_GEMFILE` (the project's), `PARALLEL_WORKERS=1`, `DISABLE_SPRING=1`, `DISABLE_BOOTSNAP=1` and a fresh
`TMPDIR`: none of them is an input. Reads through `ENV` are observed; reading the whole environment (`ENV.to_h`,
`ENV.each`, `ENV.inspect`, ...) refuses the file, except Bundler's own copy it keeps for child processes and its
selection of `BUNDLE_*` settings (both while it sets up the bundle).

`PYTEST_*` and `PYTHON*` are **hashed**: the collector reports `PYTEST_ADDOPTS`, `PYTEST_PLUGINS`,
`PYTEST_DISABLE_PLUGIN_AUTOLOAD`, `PYTHONHASHSEED`, `PYTHONWARNINGS`, `PYTHONOPTIMIZE`, ... and `TZ` as read by every
file (the interpreter and pytest read them before any hook runs), and every `PYTHON*`/`PYTEST_*` variable present
in the test environment is hashed (the interpreter reads `PYTHON_CPU_COUNT`, `PYTHONBREAKPOINT`, `PYTHON_GIL`, ...
in C). Strict mode removes them unless declared, so they hash as unset on both sides; to set one, declare it in
`[env] global` and its value is hashed.

## Where attestations live (git-meta)

vci keeps no storage format of its own. Every attestation is one [git-meta](https://git-meta.com/) string value:

- **target**: the unit's path, `path:<test file>`, `path:<Go package dir>` or `path:<cargo package dir>` (the part of
  a cargo test id before `#`). git-meta cannot hold the repository root (`.`, e.g. a Go module's root package or a
  cargo package at the root) or a path shorter than three bytes (git-meta's minimum target length, e.g. a crate in
  `rs/`) as a path target; such units are stored on the `project` target, with the same key;
- **key**: `vci:attestation:<test key>:<signer id>:<storage key>`. The test key (BLAKE3 of the test id) separates units
  that share a path (the cargo targets of one package); the signer id separates signers, so two signers never write the
  same key; the storage key hashes everything that makes two attestations interchangeable (input root, global inputs,
  toolchain, argv, env configuration, project). Re-attesting the same unit with the same inputs rewrites the same key;
- **value**: the signed DSSE envelope, byte for byte (git-meta keeps values over 1 KiB as blobs; nothing truncates).

```sh
git meta get path:src/b.test.ts             # keys and (abbreviated) envelopes
git meta get path:src/b.test.ts vci:attestation:<test key>:<signer>:<storage key> --json
```

No other fields (signer, expiry, result) are stored next to the envelope: the envelope already carries them, `vci
explain` shows them, and every extra key would count against git-meta's auto-prune limit (`meta:prune:max-keys`,
10000 when a remote was initialized by `git meta setup`). The standard commit-target `attestation` list is not used
either: vci attestations are content-addressed by unit and inputs, not tied to a commit, so they survive rebases and
apply on every branch.

**Exchange.** Metadata lives locally in git-meta's SQLite store (`.git/git-meta.sqlite`, written by `vci run`; your
index, `HEAD` and work tree are never touched) and is exchanged on the remote's `refs/meta/main`:

- `vci fetch` fetches `refs/meta/main` into `refs/meta/remotes/main` (whole trees: `--no-filter`), serializes local
  values and materializes the remote's (git-meta's merge) into the store, like `git meta pull`;
- `vci push` does the same, then rewrites the local metadata commit (`refs/meta/local/main`) as one commit on top of
  the remote tip and pushes it as a fast-forward, retrying from the fetch when the remote moved, like `git meta push`.
  It refuses to push a tree that does not contain the remote tip (that would drop other people's values), and pushes
  only to the primary git-meta remote: a side remote (`remote.<name>.metaside = true`, e.g. `vci fetch --remote <url>`
  for a second URL) is read from, as git-meta does;
- the git-meta remote is the one `git meta remote add` / `git meta setup` configure (`remote.<name>.meta = true`,
  fetch `+refs/meta/main:refs/meta/remotes/main`). `vci init` writes `.git-meta` (`url: <origin's URL>` unless
  `--meta-url`), the file `git meta setup` reads, and configures a remote named `meta`; `vci fetch --remote origin`
  (what the GitHub Action runs) configures one with origin's URL in a fresh clone. With a remote already configured
  under the name `meta`, `git meta setup` refuses ("remote 'meta' already exists"); `git meta pull` and `git meta push`
  work as they are. A plain `vci fetch`/`vci push` with no git-meta remote configured yet takes the URL from
  `.git-meta` **in the checked-out commit** (a pull request can change it) and prints the URL it uses; that URL must
  be an https, http, ssh, git or file URL, an scp-like address or a path (remote helpers such as `fd::3` or
  `ext::<command>` are refused). **CI should always pass `--remote`** (the action passes `--remote origin`), so the
  checkout never chooses where attestations come from. (Even a hostile metadata remote can only make units run: its
  envelopes are verified like any other.)

What `vci fetch` and `vci push` guard against (both take one lock per repository, shared by its worktrees, so
concurrent runs in one clone wait for each other instead of failing on ref locks):

- **A store that does not match the shared metadata ref.** git-meta serializes its SQLite store as a commit on top of
  `refs/meta/local/main`, and that commit is what gets pushed. A store that lacks values the ref holds (a new, deleted
  or emptied `.git/git-meta.sqlite`; a **linked worktree**, which has its own store while the refs are shared; a ref
  fetched by hand) would publish their deletion. vci first copies into the store every value of the ref it has no row
  and no deletion record for (and the ref's deletion records that are newer than the store's row), printing
  `note: restored N entries`. `vci run`, `vci fetch` and `vci push` work in any worktree;
- **a serialization or push that would drop someone's values.** If serializing would drop a value without a deletion
  record in the store (a `meta:filter` / `local:meta:filter` rule that excludes or routes `vci:` keys), vci undoes it
  and stops with an error; a push that would remove a value of the remote tip that this store never deleted is
  refused. Only `vci prune`, `git meta rm` and deletion records fetched from the remote delete anything;
- **entries git-meta cannot read.** One tree entry whose name is not UTF-8, or whose target git-meta cannot serialize
  (a path target under 3 bytes), used to make every fetch and push fail, and the second kind stayed in each clone's
  store. vci leaves such entries out (a deterministic commit on top of the fetched tip without them, which the next
  `vci push` publishes), deletes store rows git-meta cannot serialize, and warns. The stock `git meta pull` still
  fails on such a tree until a vci push removes the entries;
- **shared settings.** git-meta's auto-prune (`meta:prune:max-keys`, `meta:prune:max-size`) and filter rules
  (`meta:filter`) are metadata on the `project` target: **anyone who can push metadata can turn them on for everyone**.
  With auto-prune set, every `git meta serialize`/`git meta push` by anyone drops the least recently written keys,
  attestations included, from the remote, and a fetch then removes them from every store, the signer's own included
  (git-meta applies a drop without a deletion record as a delete). vci's own push never prunes; `vci fetch` and
  `vci push` warn when such a setting is present and when a fetch removed attestations that had no deletion record.
  Pruned attestations only make their units run until they are attested again. To turn it off: `git meta rm project
  meta:prune:max-keys` (and `max-size`), then `git meta push`.

**Merges cannot cost more than a skip.** Two signers, or one signer's two machines attesting different units or
inputs, write different keys, and git-meta's merge keeps keys added on either side (three-way merge: "only in local" /
"only in remote"; baseless two-way merge: union of non-overlapping keys). The one overlap is the same signer attesting
the same unit and inputs on two machines: both envelopes vouch for the same thing, and git-meta keeps one of them. A
deletion (tombstone, `git meta rm`, `vci prune`) loses to a concurrent re-attestation of the same key. A value deleted,
overwritten, pruned by git-meta's auto-prune, or never fetched only means the unit runs. Nothing in the store is
trusted: only an envelope signed by a key in the base commit's `allowed_signers`, for exactly this unit, repository,
toolchain and inputs, skips anything. Anyone with push access to the metadata remote can write or delete metadata,
exactly as with any other ref.

Interoperability, checked by the tests against `git-meta` 0.1.13 when it is installed: values vci pushes are
readable with `git meta pull` + `git meta get`; values set (`git meta set`) or deleted (`git meta rm`) with the CLI and
`git meta push`ed are what `vci fetch` + `vci plan` see.

## `vci.toml`

```toml
project = "."          # project dir (Vitest root / pytest rootdir / Go module root / Cargo workspace root / Rails app root), relative to the repo root
adapter = "vitest"     # or "pytest", "go", "cargo", "rails"

[policy]
platform = "any"       # "any" | "same-os" | "exact": which OS/arch may satisfy CI
max_ttl = "30d"        # longest accepted attestation lifetime
allow_dirty = true     # accept attestations made from an uncommitted working tree
no_skip_refs = ["refs/heads/main", "refs/tags/**"]   # never skip on these refs (the `vci init` default)
never_skip = ["tests/test_attach_db.py"]             # never skip these files (project-relative globs)
go_allow_net = false   # Go: attest packages whose test links package net (see "When vci run refuses")
rails_allow_db = false # Rails: attest files whose test database is a server (see "Databases" under Rails)

[[policy.platform_overrides]]
match = ["src/native/**"]   # project-relative globs
platform = "exact"

[env]                  # see docs/ENV.md
mode = "strict"        # strict: undeclared variables are removed from the test environment
global = ["NODE_ENV", "TZ"]
pass_through = ["GITHUB_TOKEN"]

[[env.files]]
match = ["src/db/**/*.test.ts"]
env = ["DATABASE_URL"]

[[inputs]]             # extra inputs of matching test ids (any adapter; needed by Cargo, see above)
match = ["crates/b#test:*"]
extra = ["testdata/**"]
```

`[[inputs]]` globs are relative to the project dir. A glob without wildcards names a file, a directory (walked) or a
path that must stay absent; otherwise the directory before the first wildcard is walked, every directory in it is a
listing (so a new matching file is noticed) and every matching file is hashed. The declared globs are recorded in the
attestation (`declaredInputs`) and must equal the base commit's declaration for that test id. In the `[[projects]]`
form a project's `inputs = [...]` replaces the top-level list.

Unknown keys are errors. In `vci plan` an unreadable or missing `vci.toml` or `.vci/allowed_signers` at the base
commit means everything runs.

### Several projects in one repository

Instead of `project`/`adapter`, list projects; `[policy]` and `[env]` are shared defaults, and each key given in a
project's `policy`/`env` table replaces the top-level key for that project (keys not given are inherited):

```toml
[policy]
max_ttl = "30d"

[env]
global = ["NODE_ENV"]

[[projects]]
name = "web"           # unique: letters, digits, '.', '_', '-'
path = "web"
adapter = "vitest"

[[projects]]
name = "api"
path = "services/api"
adapter = "pytest"
[projects.policy]
platform = "same-os"
[projects.env]
global = ["TZ", "APP_*"]
```

Test ids stay repo-relative paths (`services/api/tests/test_b.py`), so they are unambiguous across projects; a file
listed by two projects is never attested or skipped. Attestations record the project name and are only accepted for
the same project. `vci run`, `plan`, `ci` and `explain` work across all projects (`vci run FILE…` finds each file's
project, listing only the projects whose directory contains a file it names, so another project's toolchain need not be
installed); `vci plan --format json` names each file's `project` and lists `projects` with a per-project `runAll`, and
`--format github` adds `run_<name>=` per project. `vci ci` runs each project's remainder with its own runner. The
single-project form keeps working unchanged (its attestations carry no project name).

## What is hashed

Per test file (from the `@vci/vitest` collectors, see `js/vitest-plugin/README.md`): every module in the Vite graph
and every module the worker's module runner evaluated (this catches computed `import()`), every file or directory read
or stat'ed, every failed lookup (so creating a file that was probed as absent invalidates), directory listings
(including the static prefix of `import.meta.glob` and template `import()`, aliased prefixes included), external
packages as `name@version`, and env vars (declared patterns, `VITE_*`, and anything read that is not pass-through).
Also:

- the resolution candidates of every relative or absolute import: candidates that do not exist are probes (so an
  `ext.js` created beside `ext.ts`, or a `dirmod.ts` beside `dirmod/index.ts`, invalidates) and existing files or
  symlinks are reads (so retargeting a symlinked module invalidates, not only editing its target);
- the nearest `package.json` of every module (`imports`, `exports`, `main`, `type`; workspace packages reached through
  a `node_modules` symlink included) and its nearest `tsconfig.json` with the `extends` chain;
- snapshot files Vitest reads for the test (`toMatchFileSnapshot` targets, custom `resolveSnapshotPath` locations);
- the sources of `fs.cp`/`cpSync` (whole tree), `link`, `symlink` and `rename`, `fs.openAsBlob`, `fs.watch`,
  `statfs`, `process.loadEnvFile` and `node:sqlite` database files;
- main-process activity, attributed to every test file of the run: reads and env lookups made by the Vitest config
  file (including inline plugins), and the globalSetup files with everything they import and read.

Global inputs of every test file: `package.json`, lockfiles and `.npmrc` from the project dir up to the repo root,
every Vitest config candidate plus files it references by relative path (directories are not inputs), the
`tsconfig.json` chain from the test's directory up to the repo root (following relative `extends`, and package
`extends` that resolve to a workspace package inside the repository), `vci.toml`, the test's
`__snapshots__/<file>.snap`, and `NODE_OPTIONS`. Missing candidates are recorded as absent.

Toolchain: Node major version, Vitest version and Vite version must match; OS/arch per `policy.platform`.

### pytest

Per test file (from the `vci_pytest` collector, see `docs/spike-pytest.md`): every module executed or found by the
import system inside the repository (including `conftest.py` files and modules reached by `importlib.import_module`
with a computed name), every candidate path each import lookup could have used (so a module created later that would
shadow or satisfy an import is noticed: a new `tests/pkg/__init__.py` in front of `src/pkg`), every file opened or
stat'ed, failed lookups, directory listings, installed distributions as `name@version` (PEP 503 names, as in
`uv.lock`), env vars read through `os.environ`/`os.getenv`, and always `PYTEST_*`/`PYTHON*`/`TZ` (see above). Also:

- activity on any thread other than the main one (thread pools, `asyncio.to_thread`, `run_in_executor`) is the
  test's, whatever the stack looks like;
- lazy `parametrize` argvalues and ids (generators, `map`, `Path.glob`, `glob.iglob`) that pytest consumes in its own
  frames are attributed to the test;
- `realpath()`/`Path.resolve()`: every component inside the repository, as a symlink (with its target), a real
  directory (type only: its contents are not an input), a file, or a missing path;
- paths reached through a symlink in a temp dir (`os.symlink(repo_file, tmp_path / "l")`), and the targets of
  `os.symlink`, are recorded as the repository paths they resolve to;
- reads of `.pyc` (or `__pycache__`) files by the test itself; only the import system's own bytecode traffic is
  dropped;
- the modules the collector itself imports (`sqlite3`): the lookups a plain run would make for them through every
  `sys.path` entry in the repository, so a shadowing `src/sqlite3.py` is noticed.

Global inputs of every pytest file: `vci.toml`; `pyproject.toml`, `uv.lock`, `.python-version` and `uv.toml` from the
project dir up to the repo root; and in every directory from the test file up to the project dir, every pytest config
file name (`pytest.toml`, `.pytest.toml`, `pytest.ini`, `.pytest.ini`, `pyproject.toml`, `tox.ini`, `setup.cfg`) and
`conftest.py`. Missing candidates are recorded as absent, so creating a `conftest.py` or a config file that would move
pytest's rootdir invalidates.

Toolchain: the exact Python version (`major.minor.patch`), the implementation (`cpython`, `pypy`), the pytest
version, the interpreter's bundled sqlite and OpenSSL versions, and the complete set of installed distributions
(`name==version`, so a package installed only in CI or only on one platform runs everything) must match; OS/arch per
`policy.platform`. `uv.lock` is a global input, so any lock change runs everything.
Externals are checked against the environment CI runs in: `vci plan` enumerates the distributions installed in the
`uv run --locked` environment, and each attested `name@version` must be installed in exactly that version (a missing
package, a different version or two installed versions is a mismatch) and pinned to it by `uv.lock`. A package that
`uv.lock` builds from a local directory or file (`source = { directory = ... }` / `{ path = ... }`, e.g. an
`editable = false` path dependency) is never matched: its code is in the repository but only its version would be
recorded (`vci run` refuses such files; editable path dependencies are imported from the repository and hashed).
Every file the test used from an installed distribution is checked against the distribution's `RECORD` hash when the
file is attested (a hot-patched `site-packages` file taints).

### Go

Per package, from `go list -e -deps -test -json` over the import closure of the package's test variants (the
package compiled with its `_test.go` files, and its external `_test` package):

- every package **inside the repository** in the closure (including `vendor/`, go.work members and `replace`
  directories): its directory listing (a new `.go` file changes the build), every file `go list` names (`GoFiles`,
  `CgoFiles`, `SFiles`, `HFiles`, ..., `EmbedFiles`; for the package under test also `TestGoFiles`, `XTestGoFiles`
  and the test embeds, which a dependency's test does not compile), the files build constraints exclude on this
  machine (`IgnoredGoFiles`, `IgnoredOtherFiles`: another platform or other tags may compile them), the listing of
  every directory a `go:embed` pattern can take files from (the pattern's static prefix and everything below it, so
  a newly matching file invalidates), its module's `go.mod`, and the package under test's `default.pgo`;
- every header an **assembly file** of such a package `#include`s, resolved as the assembler does (relative to the
  package directory, then `$GOROOT/pkg/include`, whose headers belong to the Go version, and the generated
  `go_asm.h`), headers included by headers too: `#include "../shared/consts.h"` is an input, and a lookup that
  fell through to `$GOROOT/pkg/include` is recorded as absent in the package;
- every package of an **external module**: the module as `path@version` (with its replacement,
  `v1.2.0 => example.com/fork@v1.3.0`). When the attestation is made, the extracted module in the cache must match
  its `go.sum` hash (`h1:`, what `go mod verify` checks), so a hot-patched module cache taints;
- the standard library is covered by the exact Go version.

At run time (the overlaid logger, from package initialisation on): every file opened (a directory open is a
listing) or stat'ed (type and content for files), every failed lookup (so creating a file that was probed as absent
invalidates), every chdir, and every environment variable looked up (`os.Getenv`, `os.LookupEnv`,
`os.ExpandEnv`, `os.UserHomeDir`, ...). The same overlay inserts one call at the top of a few standard library
functions package os does not log (copies of the GOROOT files with the call added; if an insertion point is not
found exactly once, as a future Go version may move it, every package is refused): `os.Readlink` and
`os.Root.Readlink` record a stat of the link, so the link and its target are inputs, whatever reaches them
(`io/fs.ReadLink` over `os.DirFS` or `Root.FS()`, `os.CopyFS`, `filepath.EvalSymlinks`, a function value);
`os.Symlink`, `os.Link` and their `os.Root` forms record the new link's target (see the refusals);
`os.Environ` refuses; `File.Chdir` marks the working directory as changed; and package time's first use of the
local time zone is checked against `TZ`. Paths under vci's fresh `TMPDIR` (`t.TempDir()`) and `/dev/null` are not
inputs; any other path outside the repository refuses the package (with `GOTMPDIR` set, which strict mode removes
unless declared, `t.TempDir()` uses it instead and the package is refused). Fuzz seed corpora (`testdata/fuzz/FuzzX`) are
read through package os and recorded like any other testdata.

### Cargo

Per unit, from `cargo test --locked --message-format=json <unit>` (every crate the unit builds, including build scripts,
proc macros and dev-dependencies, with the features actually enabled):

- **every crate of the repository the unit builds** (the package under test and its path dependencies, workspace
  members or not): every file in its package directory and every directory listing there (a new file anywhere in it
  runs the unit), except the target dir and the repository's `.git` and `.vci/out`, which are recorded as
  `excluded` (not inputs, and left out of their parent's listing whether they exist or not); symlinked directories are
  walked at their target;
- **rustc's dep-info** (`.d` files) of those crates: sources, `include_str!`/`include_bytes!` targets and `#[path]`
  files, including files outside the package directories (`include_str!("../../shared/c.txt")`), and the variables
  `env!`/`option_env!` read (cargo's own `CARGO_PKG_*`, `CARGO_MANIFEST_DIR`, `OUT_DIR`, ... excepted). Generated files
  in the target dir (`OUT_DIR`) are outputs of hashed inputs; files in the toolchain's sysroot are covered by the rustc
  version; any other compile-time input outside the repository refuses the unit;
- **build scripts**: their `rerun-if-changed` paths (files; directories walked; missing paths as absent) and
  `rerun-if-env-changed` variables. A build script without `rerun-if-changed` makes cargo treat its whole package as
  input, which the package directory rule already does;
- **external crates** as `name` + `version source checksum` from `Cargo.lock` (git sources carry the locked commit).
  `vci plan` checks each against the checkout's `Cargo.lock`. When the unit is attested, what cargo compiled must be
  what `Cargo.lock` pins (cargo itself never re-checks an extracted crate): a registry crate's directory in
  `$CARGO_HOME/registry/src` must equal its downloaded `.crate` archive, whose SHA-256 must be the `Cargo.lock`
  checksum; a git dependency's checkout must be clean (untracked and ignored files included) at the locked commit; a
  crate served from anywhere else outside the repository (a `[source]` directory or local-registry replacement)
  refuses the unit. A crate vendored into the repository (source replacement) is hashed file by file instead. (If a
  `.crate` archive is missing, e.g. removed by cargo's cache cleaning, `cargo fetch` downloads it again.)
- **every file rustc read for the repository's crates is also scanned** by the static checks below, whatever its
  extension: `include!`d code, `#[path]` modules, a README included as documentation (`#![doc =
  include_str!("../README.md")]`, whose doctests run), data, and the code build scripts generate into `OUT_DIR`;
- `[[inputs]]` files declared for the unit.

Global inputs of every unit: `vci.toml`; `Cargo.toml` in every directory from the package dir up to the repo root (the
workspace root and its `[workspace.dependencies]`, `[patch]`, `[profile.*]`); `Cargo.lock`, `rust-toolchain`,
`rust-toolchain.toml`, `.cargo/config.toml` and `.cargo/config` from the project dir up to the repo root (missing ones
as absent, so creating one runs everything). **Any `Cargo.lock` change runs everything.** Cargo config files outside the
repository (above it, or in `$CARGO_HOME`) may only set keys that do not change the build (`[net]`, `[http]`,
`[registries]`, `[source]` (the crates it serves are verified, see above), `[alias]`, `[term]`, `build.jobs`,
`build.target-dir`, ...); any other key (`build.rustflags`, `[target]`, `[env]`, `[profile]`, `[patch]`, ...) makes `vci
run` stop and `vci plan` run everything. In-repository config setting `build.rustc`, `build.rustdoc` or `build.target`
is refused the same way. In-repository `[target.*]` tables are recorded or pin the unit (see "Attesting on macOS,
verifying on Linux (Cargo)"); a `runner` or `linker` in one (or `CARGO_TARGET_<TRIPLE>_RUNNER`/`_LINKER`, or `-C
linker=` in the rustflags) refuses every unit: the program it names is not hashed. A rustc wrapper
(`build.rustc-wrapper`/`rustc-workspace-wrapper` in any config, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER` and their
`CARGO_BUILD_` forms) other than `sccache` refuses every unit for the same reason.

The profile (`test`), the enabled features and the compiled code follow from these inputs and the unit's command line,
which is part of the attestation (`argv`); Cargo resolves features for the selected package only, and `vci ci` runs each
unit on its own for that reason.

Toolchain: `rustc -vV` (release, commit hash, LLVM version) and `cargo -vV` (release, commit hash) exactly; the host
triple and `rustc --print cfg` (with the flags the build uses: `CARGO_ENCODED_RUSTFLAGS`/`RUSTFLAGS`, else the
repository config's matching `[target]` tables, else `build.rustflags`) exactly on the same OS and
architecture; on another platform the attested `cfgPredicates` must evaluate the same (see
[Attesting on macOS, verifying on Linux (Cargo)](#attesting-on-macos-verifying-on-linux-cargo)); OS/arch per
`policy.platform`, and exactly when the attestation lists `platformSpecific` files.

**Test results**: a unit passes when `cargo test` exits 0, libtest's summary reports no failures and nothing filtered
out, and **at least one test ran** (a target without tests, or a custom harness that prints no libtest summary, is never
attested and always runs). **`#[ignore]`d tests do not prevent an attestation**, unlike skipped pytest or Go tests:
pytest's `skipif` and Go's `t.Skip` decide at run time (on the platform, `CI`, an optional import), so the skipped test
may run elsewhere. `#[ignore]` is decided at compile time from hashed inputs, so CI's `cargo test` ignores the same tests;
the one exception, `#[cfg_attr(target_os = "linux", ignore)]`, is a target cfg and is checked like any other (the unit
runs where it evaluates differently). A test that returns early based on the environment is covered by the literal
`env::var` rule above.

Global inputs of every Go package: `vci.toml`; `go.mod`, `go.sum`, `go.work` and `go.work.sum` from the project dir
up to the repo root (missing ones as absent, so creating a `go.work` invalidates); `vendor/modules.txt` in the
project dir (present or absent: it switches the build to `vendor/`). A module version change touches `go.mod` and
`go.sum`, so it runs everything.

Toolchain: `go env GOVERSION` exactly (after any `GOTOOLCHAIN` switch; the test binary's `runtime.Version()` must
agree), the effective `CGO_ENABLED`, `GOFLAGS`, `GOEXPERIMENT`, `GOFIPS140`, `GODEBUG` and `GOWORK` (relative to the
project dir; `go env -w` settings included), the architecture level on the same architecture; OS/arch per
`policy.platform`, exactly when the attestation lists `platformSpecific` files, the architecture when it lists
`archSpecific` reasons, and another architecture only between 64-bit little-endian ones. `vci plan` checks every attested
module against the build list (`go list -m -json all`) of the checkout.

### Rails

See [What the Rails adapter records](#what-the-rails-adapter-records) and [Databases](#databases-read-this) under
Quick start (Rails): every Ruby file compiled from disk with the shadowing candidates of each `require`, Zeitwerk's
directory listings, every file read, checked, globbed or listed (fixtures, templates, configuration, the schema), the
loaded gems by version (their installed files checked against their archives when attested), `ENV` reads, and
global inputs (`Gemfile`, `Gemfile.lock`, the boot files, `test/test_helper.rb`, the Ruby version files). Every file
runs against a fresh database loaded from the schema.

## When `vci run` refuses to attest

A test file gets no attestation (and will run in CI) if any of these hold:

- a collector tainted it: child processes, network (including `new net.Socket().connect()` and `dgram` sockets),
  `worker_threads`, `fetch`, enumerating `process.env`, recursive readdir/glob, snapshot writes, `isolate: false`,
  vm/browser pools, experimental module caches, typecheck mode, or any of these done by the Vitest config or a
  globalSetup file in the main process (that taints every file of the run);
- it did not pass (failed, missing result), or **any of its tests was skipped or xfailed**: a skip is usually
  conditional (platform, `CI`, an optional import), and the skipped test did not run, so the attestation cannot
  vouch for it where the condition differs;
- any input lies outside the repository (e.g. a read of `/etc/hosts` or an unowned temp file);
- any input changed during the run: the working tree's metadata (size, mtime, ctime, inode, mode) is snapshotted
  before the run and every attested entry must be untouched afterwards, and the global inputs (including snapshot
  files) are hashed before and after. Hard-linking a repository file (`fs.link`) changes its ctime and link count, so
  a test that links a fixture into a temp dir is refused;
- two inputs collide under case folding, a symlink leaves the repo, the collector's toolchain differs from the
  project's, or the test file is listed under more than one Vitest project (or by more than one vci project).

pytest specifics:

- collector taints: `subprocess`/`os.system`/`os.exec*`/`fork`/`posix_spawn`, sockets and HTTP clients,
  `ctypes.dlopen`, multiprocessing process start, subinterpreters, native extension modules inside the repository,
  reading the pytest cache, `--lf`/`--ff`/`--nf`/`--sw`, xdist, reruns, random ordering without a seed, `sys.path`
  entries outside the repository, a `PYTHONPATH` entry other than the collector, no pytest config file (or a
  `pyproject.toml` without a pytest table), more than one test file or a `file::test` selection in one process;
  a `-p` plugin in `addopts`/`PYTEST_ADDOPTS` (imported before the collector, so what it read then was not seen;
  pytest's own built-in plugins and `-p no:...` are fine); reading the pytest cache (`request.config.cache.get`,
  including `cache/...` keys, or files under `.pytest_cache`); an SQLite database inside the repository (SQLite reads
  and writes it and its `-journal`/`-wal`/`-shm` files in C), `ATTACH`, a connection not made through
  `sqlite3.connect` (so without vci's authorizer), `sqlite3` extension loading; reading a file of the environment
  that belongs to no installed distribution (`.venv/pyvenv.cfg`); a distribution file that no longer matches its
  `RECORD` hash; reading `PYTHONPATH`; a dependency built from a local path (see "What is hashed");
- the test **enumerated the environment** (`dict(os.environ)`, iteration, `len`, `repr`: collector env key `*`);
- the test **wrote inside the repository** (created, modified, deleted, renamed a file or made a directory there;
  collector `write` records). Writes outside the repository (temp dirs, `tmp_path`) are allowed; reading such a file
  back is an input outside the repository and refused;
- pytest's rootdir is not the project dir, or the collector's Python/pytest version differs from the one
  `uv run --locked` resolves.

Go specifics (the log only sees what package os reports; everything else that could reach an input refuses the
package, decided from the import closure of the test and the source of every non-standard package in it):

- **a child process**: `os.StartProcess` (all of `os/exec`) is recorded at run time (`exec: <program>`); the child's
  reads are invisible. Only an actual start refuses: importing `os/exec` is fine;
- **network**: package `net` anywhere in the closure (`net/http`, database drivers, and testify's `assert`, which
  imports `net/http`). vci cannot observe connections, so this is refused by default. `policy.go_allow_net = true`
  is your statement that these tests do no network I/O: the refusal is waived, the attestation records the waiver
  (`waived`), and `vci plan` accepts it only while the **base commit's** policy still sets it. It is the only
  refusal that can be waived;
- **system calls and native code**: a non-standard package that imports `syscall`, any `golang.org/x/sys` package
  other than `cpu`, cgo (`import "C"`, `runtime/cgo` linked, a standard package built with cgo), C/C++/Objective-C/
  Fortran/SWIG files or `.syso` objects; `os/user` (reads the user database outside package os) and `plugin`;
- **source that uses what package os does not log**, in the test's own files and every non-standard package it
  imports: the identifier `Environ` in code (`os.Environ`, `syscall.Environ`, `exec.Cmd.Environ`, whether called or
  used as a function value such as `var environ = os.Environ`; a lexical scan of identifiers outside comments and
  strings, so an aliased import resolves the same way), and `//go:linkname` (a text match, comments included);
- **what the standard library hooks report** (see "What is hashed"): `os.Environ` called at run time (also from a
  third-party module or the standard library), and a symbolic or hard link created with `os.Symlink`, `os.Link` or
  their `os.Root` forms whose target is outside vci's temp dir (a read through `t.TempDir()/link` would be logged
  as a temp file, not as the repository file it reaches); links within the temp dir are fine (`os.CopyFS` of a
  fixture with relative links);
- **a relative name package os built from an earlier open after the working directory changed**: `File.Readdir`,
  `ReadDir` + `DirEntry.Info`, and `os.Root` operations log `<the file's or root's name>/<entry>`; when that name
  is relative and the test has changed directory (`t.Chdir`, `os.Chdir`, `File.Chdir`), it would be resolved
  against the new directory, so the package is refused. Plain relative opens after a chdir are resolved correctly;
- **the local time zone with `TZ` unset** (it comes from `/etc/localtime`, not an input), or a `TZ` that names a
  file;
- **not every test ran**: `go test` reports a package where no test ran as `ok` (a `TestMain` that returns or
  calls `os.Exit(0)` before `m.Run`, perhaps because `os.Getuid() != 0`; a `_test.go` file without tests); vci
  requires at least one test and every `Test*`/`Fuzz*` function of the compiled `_test.go` files (found by a
  line scan for top-level `func Test...(`, `TestMain` excluded) to have run and passed, so a `TestMain` that filters
  with `-test.run` is refused too. Examples are not required individually;
- **an assembler `#include`** that cannot be resolved (only the package directory, `$GOROOT/pkg/include` and
  `go_asm.h` are searched) or that resolves outside the repository;
- **the repository changed during the run** (a file written, removed, renamed; a directory created): package os
  logs writes as opens but not removals, so every package of that `vci run` is refused;
- a skipped test or subtest (`t.Skip`), a failed or unbuilt package (including `go vet` failures, which fail
  `go test`), no log (`vci:no-testlog`: the overlay did not apply), the standard library hooks not installable
  for this Go version, a module cache that does not match `go.sum`, a `go.work` outside the repository;
- `GOFLAGS` naming programs or files vci does not hash (`vci run` stops with an error; only the flag text is
  compared, so a change to what it names would go unnoticed): `-overlay` (vci's own), `-modfile`, `-pgo=<file>`,
  `-toolexec`, `-exec`, `-pkgdir`, `-compiler` other than `gc`, `-gccgoflags`, and `-asmflags`/`-gcflags`/
  `-ldflags` values with a path, an `-I` search path, an `@file` argument file, `-importcfg`/`-embedcfg`, or an
  external linker (`-linkmode`, `-extld`). `GOCACHEPROG` is trusted like the module cache: a cache program that
  returns wrong build results would fool `go test` itself.

Cargo specifics (static checks of every repository source file the unit compiles, comments included since doc
comments hold doctests; a text match, so a mention in a comment refuses too, and an aliased import or a macro that
builds the call evades it):

- **child processes**: `Command::new`, `process::Command`, `CommandExt`, `posix_spawn`, `libc::fork`/`exec`/`system`
  (in test code, build scripts and proc macros). This refuses every unit of vci's own repository except `vci-core`'s:
  `vci-git` runs `git`, `vci-attest` runs `ssh-keygen`, and the `vci-cli` end-to-end tests run `vci`;
- **network**: `TcpStream`, `TcpListener`, `UdpSocket`, `Unix{Stream,Listener,Datagram}`, `ToSocketAddrs`; and building
  a crate whose purpose is network I/O or processes (`reqwest`, `hyper`, `ureq`, `curl`, `socket2`, `async-std`,
  `sqlx`, `postgres`, `redis`, `tonic`, `axum`, `assert_cmd`, `escargot`, `duct`, `git2`, `wiremock`, ..., `tokio`
  with `net`/`process`/`full`, `mio` or `rustix` with `net`, `nix` with `process`/`socket`/`net`). The list is not
  exhaustive, and dev-dependencies count for every test target of their package;
- **native code**: `libc::`, `extern "C" {` blocks, `#[link(`, `asm!`; a build script linking a library from outside
  the build (`cargo:rustc-link-lib` without a search path in the target dir: system libraries such as
  `libsqlite3-sys` without `bundled`);
- **environment enumeration**: `env::vars()`, `env::vars_os()`;
- **reads the rules above do not cover**: a path literal (`"../x"`, `"/etc/hosts"`) used with file APIs that is not a
  recorded input, `include_str!` in a doctest outside the package, `CARGO_MANIFEST_DIR` with `parent()`/`ancestors()`
  (waived by declaring `[[inputs]]` for the unit), and `CARGO_TARGET_TMPDIR` (it persists between runs);
- **procedural macros of the repository** that mention file access (`std::fs`, `File::open`, `read_to_string`, ...):
  what a proc macro reads is invisible to rustc unless it is `include_bytes!`-tracked;
- **a path literal in another letter case than the file** (`cargo:path-case`), a symlinked directory leading outside
  the repository, another git repository inside a package directory;
- **programs vci does not hash**: a test runner or linker in cargo config, a rustc wrapper other than `sccache`
  (`cargo:config`, `cargo:wrapper`);
- **an external crate whose sources are not what Cargo.lock pins** (`cargo:source`, see "What is hashed");
- **a crate of the repository cargo reused from a build vci did not make in this run** (should not happen: vci
  cleans them first and retries once);
- a failed unit, a unit where no test ran, a path dependency or dep-info path outside the repository, a git dependency
  without a locked commit, a crate not in `Cargo.lock`, and env mode `"loose"` (Rust environment reads are not
  observed; in strict mode an undeclared variable is unset both where the unit was attested and in CI).

Rails specifics (collector taints and checks; see [Quick start (Rails)](#quick-start-rails)):

- **child processes**: backticks and `%x`, `system`, `spawn`, `exec` (`Kernel`'s and `Process`'), `IO.popen`, `Open3`,
  `PTY.spawn`, `Kernel#open("|cmd")`, and **any fork** (`fork`, `Process.fork`, `IO.popen("-")`: every one goes through
  `Process._fork`), which is how Rails' parallel test workers would run (vci sets `PARALLEL_WORKERS=1`, so they do not);
- **network**: creating a `TCPSocket`, `UDPSocket`, `UNIXSocket`, a server socket or a `Socket`, `Socket.tcp`, DNS
  lookups (`Addrinfo.getaddrinfo`, `Socket.getaddrinfo`, ...), and therefore `Net::HTTP`, Redis, browsers of system
  tests (also a child process); a database client a test opens itself (`PG.connect`, `Mysql2::Client.new`,
  `Trilogy.new`);
- **the test environment's database is a server** (PostgreSQL, MySQL, ...) unless `policy.rails_allow_db` (the one
  refusal a policy waives; see "Databases"); a SQLite file vci did not prepare fresh, an in-memory test database,
  `ATTACH`, SQLite extensions;
- **native code**: a native extension (`.so`/`.bundle`) inside the repository; Fiddle (`Fiddle.dlopen`, also of
  `nil`, and any `Fiddle::Function`); FFI (`ffi_lib`, `attach_function`, `attach_variable`, `FFI::DynamicLibrary.open`,
  `FFI::Function`); libxml2 (Nokogiri) reading files in C: parse options `NOENT`, `DTDLOAD`, `DTDATTR` or `XINCLUDE`
  (external entities and DTDs), `do_xinclude`, an XSD or RelaxNG schema with includes or imports, `validate` of a file
  by name, any XSLT stylesheet, a SAX parser with `replace_entities` (a SAX `parse_file` records the file it parses);
  a library vci hooks that was loaded but never hooked (`vci:not-hooked:`);
- **file metadata git does not keep** (`ruby:file-metadata:`): a test reading the times of a repository file
  (`File.mtime`/`atime`/`ctime`/`birthtime`, `File#mtime`, `File::Stat#mtime` and friends, comparing `File::Stat`s),
  its permission bits other than the executable bit (`File::Stat#mode`, `world_readable?`, `readable?`,
  `writable?`, `setuid?`, ...) or its owner (`uid`, `gid`, `owned?`). A checkout's times are when it was checked
  out and its modes 644/755, so the attested result is not reproducible. Not refused: the same reads of a file the
  process created, ActiveSupport's file watchers (which compare mtimes only to decide whether to reload), and
  Ruby's standard library reading permission bits for itself (`FileUtils.cp` copying a mode); the executable bit and
  the size are hashed with the content;
- **network**: `Socket.ip_address_list` and `Socket.getifaddrs` (the machine's interfaces);
- **the test enumerated the environment** (`ENV.to_h`, `ENV.each`, `ENV.keys`, `ENV.inspect`, ...);
- **a file descriptor opened where vci cannot see it** (`IO.for_fd`/`IO.new(fd)`/`File.new(fd)` of a file no hooked
  entry point opened), `ARGF`/`gets` reading the files named in `ARGV`;
- **writes inside the repository** outside the git-ignored `log/`, `tmp/`, `storage/` and `coverage/` of the project;
- **gems**: code loaded from an installed gem that is not in the bundle, and any read, existence or type check or
  listing the test (not RubyGems or Bundler) makes under a gem directory outside the bundle (`GEM_PATH`, `Gem.dir`,
  the user gem dir: what is installed there differs between machines), a gem whose installed files differ from its
  cached archive or whose archive does not have `Gemfile.lock`'s checksum, a gem without a cached archive, a path gem
  outside the repository, a git gem without a locked revision, a `$LOAD_PATH` entry outside the repository, the
  bundle, Ruby and RubyGems' directories, a Bundler other than the project's `Gemfile` (`BUNDLE_GEMFILE`), not running
  under Bundler at all;
- **caches and preloaders**: a compiled-code cache (`RubyVM::InstructionSequence.load_iseq` defined, as Bootsnap's
  compile cache does), Bootsnap's YAML or JSON compile cache (`YAML.load_file` answered from `tmp/cache/bootsnap`, read
  in C, not from the file vci hashes), Bootsnap's load-path cache, Spring; `Dir.for_fd`;
- not every test passed (a failure, an error, **a skip**), no test ran, **a test made no assertion**, the process
  exited non-zero, or the collector wrote nothing (a crash, `exit!`); the collector's Ruby, Rails, Bundler or Minitest
  version differs from the project's; reads outside the repository other than the bundle's gems, Ruby's own files,
  vci's temp dirs, `/dev/null`/`/dev/urandom` and the time zone data (the toolchain records which).

## Verification (`vci plan`)

For each listed test file, each stored candidate for its test id is checked in this order; the first candidate that
passes every check means SKIP, otherwise RUN (with the furthest-reaching failure as the reason):

1. **envelope** parses as DSSE with the in-toto payload type;
2. **signature**: SSHSIG over the DSSE PAE of the exact stored payload bytes, namespace `vci-attest`, SHA-2 only;
3. **signer**: the key is in the base commit's `allowed_signers` (`namespaces=`, `valid-after`, `valid-before`
   honoured; `cert-authority` rejected);
4. **statement**: predicate type and subject match;
5. **expiry**: not expired, not issued in the future (5 min skew), lifetime within `max_ttl`;
6. **repo** (root commit), **test-id**, **adapter**, **argv** (including project dir) match;
7. **toolchain**: Node major, Vitest, Vite (pytest: exact Python version, implementation, pytest; Go: exact Go
   version, effective build settings, architecture level; Cargo: exact rustc and cargo, host triple and cfg set on the
   same platform, attested cfg predicates evaluated for this host), whether the tests ran as root (effective uid 0:
   permission checks do not apply to root, so a test that expects a mode-000 file to be unreadable passes only for
   other users), and OS/arch per policy (Go and Cargo: the same OS
   and architecture when the attestation lists platform-specific files; Go: the same architecture when it lists
   arch-specific reasons, and otherwise another architecture only between 64-bit little-endian ones; Rails: Ruby
   version and patchlevel, engine, Rails, Bundler, Minitest, SQLite library, libyaml, time zone data, encodings,
   collector version, database software and the whole bundle, exactly);
8. **env-config**: digest of the effective env configuration (from the base `vci.toml`) matches;
9. **result**: passed and untainted; **inputs-config**: the `[[inputs]]` globs recorded equal the base config's for
   the test id; every waived refusal still waived by the base policy; **dirty** only if `allow_dirty = false`;
10. **global-inputs**: every attested global entry re-hashed from the checkout, and the current global input set
    has the same root;
11. **inputs**: every attested per-file entry re-hashed (files, symlinks, directory listings, directory types,
    absences); pytest: no native extension module for another platform (`b.cpython-314-x86_64-linux-gnu.so`,
    `b.cp314-win_amd64.pyd`) next to a probed extension candidate;
12. **externals**: every `name@version` is what is installed now (pytest: in the `uv run --locked` environment, and
    pinned by `uv.lock`; Go: the module is in the build list in exactly that version and replacement; Cargo: the
    checkout's `Cargo.lock` pins that version, source and checksum; Rails: the gem is in the bundle Bundler resolves in
   this checkout in exactly that version, a git source's revision included);
13. **env**: every hashed variable has the same value, and every variable that matches a declared pattern in CI is
    covered by the attestation.

Before any candidate is checked, a file matching `policy.never_skip` (base commit) runs.

Each candidate is checked inside an error boundary (panics included): an error is a failed check, never a skip.

## Threat model (v1)

Protected against:

- **Forged or tampered attestations**: the signature covers the exact payload bytes; one flipped byte fails.
- **Untrusted signers**, including a pull request that adds its own key to `.vci/allowed_signers`: trust and policy
  come only from the base commit, never from the working tree.
- **Replay** across repositories (root commit), test files, argv/project, toolchains, env configuration, or after
  expiry.
- **Stale inputs**: every recorded input is re-hashed from CI's checkout, including files that must still be absent
  and directory listings.

Not protected against:

- A trusted signer lying, or a stolen signing key. An attestation proves who made a claim, not that the test ran.
  In particular `vci plan` re-hashes only the inputs the signed manifest lists and cannot check that the list is
  complete, so a signer can under-declare inputs and get a changed dependency skipped. Keep `allowed_signers` short,
  use hardware-backed keys, and set `valid-before` on entries. Spot-check re-runs or a second-signer requirement on
  protected refs are possible follow-ups.
- Inputs the collectors cannot see: native addons, time, locale, randomness, network (network use taints the file,
  but only through the patched Node APIs), data captured before the collectors were installed, and the user and group
  the tests run as beyond root versus non-root (which is recorded): file ownership, group membership, capabilities.
- Test code deliberately evading the collectors.
- Malicious `node_modules` that match the lockfile and package versions (packages are identified by version, not by
  file hashes).
- A CI job whose `--base-ref` points at a ref the pull request controls (its head or merge commit, or `HEAD`). Pass
  the base branch's commit (`github.event.pull_request.base.sha`, as in the example workflow). `vci plan` warns when
  the base commit is HEAD or contains it.
- Third-party Vite plugins (code under `node_modules`) reading files in the main process: only their package version
  is an input. Reads by the config file itself, inline plugins and globalSetup files are recorded.
- Timezone and locale in strict mode: `TZ` reaches tests only if declared (then hashed); the system timezone and
  `LANG`/`LC_*` (built-in pass-through) are not hashed. In loose mode `TZ` is always hashed. (Go refuses a package
  that uses the system timezone, see "Go specifics".)

Use `no_skip_refs` to run everything on the default branch and release refs.

pytest limitations (details and the measured audit-hook coverage in `docs/spike-pytest.md`):

- **C extensions and linked libraries opening files themselves** are not seen: OpenSSL `cafile`,
  `lxml.etree.parse(path)`, pyarrow/h5py, `numpy.fromfile`. Installed extensions are covered by their distribution
  version only; `ctypes.dlopen` and native extensions inside the repository taint. SQLite: databases inside the
  repository and `ATTACH` taint; a test that replaces vci's authorizer with its own (`set_authorizer`) hides later
  `ATTACH`es. List such files in `policy.never_skip`.
- **C-level `getenv`** is not seen: `TZ` (hashed always) and the interpreter/pytest variables are handled, but
  `LANG`/`LC_*` read by `locale`, `os.environ._data` and `posix.environ` bypass the collector.
- `posix.stat` called directly, or `os.stat` bound before the plugin loaded; `DirEntry.stat()` after `scandir` (the
  listing is recorded, not sizes); custom meta-path finders and zipimport misses; threads outliving the session;
  `realpath()` of paths outside the repository.
- **Per-file isolation**: attestations and `vci ci` run one file per process. A file whose module-level side effect
  breaks another file only in a shared process (a plain full-suite `pytest` run) is not caught.
- **Interpreter builds**: the Python version, sqlite and OpenSSL versions are compared; other bundled or linked
  libraries (zlib, expat, libffi, readline) and the compiler are not, so under `platform = "any"` a test that depends
  on them is accepted from another build of the same version.
- **Time, randomness, locale and hostname** are not inputs (as on the Vitest side); random-order plugins taint unless
  seeded.
- Platform-specific extension suffixes: attestations probe only the attesting interpreter's suffixes
  (`.cpython-314-darwin.so`); `vci plan` instead rejects any native extension named like a probed module in a probed
  directory (`<name>.*.so`, `<name>.*.pyd`), whatever its platform tag.

Go limitations:

- **Standard library and linked system libraries reading outside package os** are not seen: the zoneinfo files
  package time reads for a `TZ` name or `time.LoadLocation` (`TZ` and `ZONEINFO` are hashed, the tzdata version is
  not; `/etc/localtime` itself is never used by an attested package: with `TZ` unset, using the local zone refuses),
  system certificate roots on macOS (`crypto/x509` asks the Security framework), DNS configuration through libc
  (but `net` is refused anyway), `os.Hostname`, `os.Getuid` and friends. Hardware (`runtime.NumCPU`), time and
  randomness are not inputs, as for the other adapters; whether the tests run as root is recorded (see the
  toolchain check), the user and groups otherwise are not.
- **Platform-dependent code outside the repository** under `platform = "any"`: an external module's `_linux.go`
  file, its `runtime.GOOS` switches, or its imports on the CI platform, are not what ran on the attesting machine;
  the refusal analysis (`syscall`, `net`, source identifiers) also only sees the files compiled on the attesting
  platform. Floating-point code there pins the architecture (`archSpecific`), but the standard library outside
  `math` is assumed to compute the same on every 64-bit little-endian architecture. Use `"exact"` where it matters.
- **Assembly** in the closure is assumed not to make system calls (a `SYSCALL` instruction in a `.s` file would be
  deliberate evasion); cgo, which commonly does I/O, is refused.
- **Module cache contents in CI** are trusted once downloaded and verified by the go command (as `node_modules` is);
  the attesting machine's cache is checked against `go.sum`. `GOCACHEPROG` is trusted the same way. A patched
  GOROOT with an unchanged version string is not noticed.
- Paths: `PWD` and the absolute checkout location are not inputs. The logger records names as package os received
  them, made absolute with the working directory at the time of the call; a relative name package os derived from
  an earlier open is refused after a chdir (see the refusals).
- **Dependencies' directories are listed whole**: a dependency's `_test.go` files and test embeds are not inputs of
  a dependent's test (editing them runs the dependency only), but a **new** file anywhere in a dependency's package
  directory (a new `_test.go`, a new `testdata` directory, a `//go:build ignore` file) changes its listing and runs
  the dependents too. This fails open (an extra run, never a false skip).
- **Tests that run**: examples are not checked one by one (a `TestMain` that filters so that only examples are
  skipped is not noticed if at least one test ran and every `Test*`/`Fuzz*` function did); the line scan for test
  functions can over-count (a `func TestX(` line inside a raw string refuses the package).
- **Package isolation**: `go test` runs every package in its own process in both `vci run` and `vci ci`, so a
  package attested alone behaves as in CI; `vci ci` runs the remaining packages in one `go test` invocation (in
  parallel, sharing one fresh `TMPDIR`).

Cargo limitations (on top of the rule that reads outside the package directories must be declared):

- **Run-time behaviour is not observed at all.** Reads, environment lookups, processes and sockets are inferred from
  the source text; a path, variable name or program built at run time, a call through an alias or a macro, and anything
  an **external crate** does (`dotenvy` reading `.env`, `tempfile` honouring `TMPDIR`, `jiff`/`chrono` reading the time
  zone database, a crate spawning a helper) is not seen. Non-literal `env::var(name)` is accepted: strict mode makes
  undeclared variables unset on both sides, but a computed read of a built-in pass-through variable (`HOME`, `CI`,
  `PATH`) is not hashed.
- **Build scripts and proc macros** may read files or variables they do not declare (`rerun-if-*`). vci rebuilds the
  repository's crates in every `vci run` (in its own target subdirectory, with the strict environment), so what they
  read is read again; but a build script reading a pass-through variable (`HOME`) or a file outside the repository is
  not seen, and neither is a proc macro in an external crate reading files. External crates are reused from earlier
  builds of vci's target subdirectory (cargo identifies them by version): an artifact built from an extracted crate
  that was edited and later restored is not noticed (`cargo clean` if you ever edited `$CARGO_HOME`).
- **C toolchains and system libraries**: build scripts compiling C (`cc`) record neither the compiler version nor
  system headers; system libraries linked by the build are refused, those linked by `#[link]` in external crates'
  sources (libc, macOS frameworks) are not seen.
- **`#[link]`/FFI detection** only looks at repository sources; the platform-cfg evaluation only at repository code and
  manifests (external crates' `cfg(target_os)` code is accepted under `platform = "any"`).
- **Ignored files in package directories** are inputs (a fresh CI checkout does not have them, so such units run in
  CI); `vci run` warns. `node_modules` or `.venv` inside a package directory refuse the unit.
- **Per-unit isolation**: attestations and `vci ci` build each unit with the features its own `cargo test` selection
  resolves; `cargo test --workspace` may build other feature combinations. Examples that are not test targets are not
  built by `vci ci`.
- Cross-compiled test runs (`--target`, `build.target`, `CARGO_BUILD_TARGET`), custom test runners and linkers
  (`target.<triple>.runner`/`linker`) and rustc wrappers other than `sccache` are not supported (refused); vendored
  crates edited without changing their `Cargo.lock` checksum are noticed only because vendored directories are hashed.
  A declared `RUSTC` or `RUSTDOC` is compared by its path (hashed) and, for rustc, its `-vV` output only.
- **Letter case**: a path built at run time that differs in case from the file (found on macOS, missing on Linux) is
  not detected; only literals are checked.

Rails limitations (details and the verified mechanisms in [`docs/spike-rails.md`](docs/spike-rails.md)):

- **C code opening files is not seen**: Ruby has no audit hook, so vci wraps the Ruby entry points. A C extension
  that opens a path itself (ImageMagick or libvips opening an image by path, a database client's certificate files,
  libxml2 through a catalog or an API vci does not hook) reads unseen; installed gems are covered by their version
  (and their loaded files by the archive check), not by what their C code reads. The libxml2 entry points that read
  files (external entities, XInclude, schema includes, XSLT) and Fiddle and FFI are refused (above). SQLite, the
  common case, is handled (above). Neither are reads by the C library of the user database (`Etc.getpwuid`), the
  host name (`Socket.gethostname`), the number of CPUs (`Etc.nprocessors`, which concurrent-ruby and other gems
  read for their own sizing), `/etc/localtime` (declare `TZ`), or reads made through a method captured before the
  collector loaded (nothing of the application loads before it, as it comes first through `RUBYOPT`). A test whose
  result depends on these is not reproduced in CI; they are not refused.
- **What RubyGems and Bundler look up while setting up the bundle** (`HOME`, `PATH`, `GEM_*`, `BUNDLE_*`, `~/.gem`,
  `~/.bundle/config`, `.bundle/config`) is not an input: the bundle it produces is (every gem version, the toolchain's
  gem set, the `Gemfile` used). A setting that changes how a gem was built (`BUNDLE_FORCE_RUBY_PLATFORM`, build flags)
  is not compared. A test that itself calls into RubyGems (`Gem.user_home`) reads those values unrecorded.
- **File metadata**: times, permission bits other than the executable bit, and owners are not inputs; a test reading
  them refuses (above), except ActiveSupport's file watchers' mtimes and Ruby's standard library reading modes for
  itself (`FileUtils.cp` copies a mode: a test asserting the copy's mode is not refused).
- **The type or size of a file is hashed as its content**, and a `File.exist?` of an existing file records the file:
  Rails checks `config/routes.rb` at boot, so a routes change runs every test that boots Rails, not only those that
  draw the routes (it never skips one that does). The same holds for `app/models` (any new file runs every test that
  boots Rails) and `test/fixtures` (`fixtures :all` loads every fixture into every `ActiveSupport::TestCase`).
- **Database servers** are trusted under `policy.rails_allow_db` as described in "Databases": their contents beyond
  the schema vci loads, their configuration and other clients are not inputs.
- **Per-file isolation and order**: one file per process with a fixed seed, as in CI. A file that depends on another
  having run first (in a full `bin/rails test`) is not reproduced; neither is a time-dependent test (time, randomness
  other than `rand`, `SecureRandom`, the number of CPUs are not inputs, as for the other adapters).
- **Background work after the tests** (threads still running when Minitest reports) is recorded only until the
  collector writes its output at exit.
- **OpenSSL** is not compared (see "Attesting on macOS, verifying on Linux (Rails)"), and neither is the C compiler of
  gems built at install time.
- **RSpec is not supported yet**: the adapter runs Minitest files. A project whose tests are all RSpec files is an
  error (`vci plan` runs everything, `vci ci` fails rather than run nothing); beside Minitest files they are reported
  and left to you (`bundle exec rspec`). Supporting it needs a reporter for RSpec's results and expectation counts,
  and handling the options RSpec reads from `~/.rspec` and `$XDG_CONFIG_HOME` (outside the repository).
- **System tests** (`test/system`, driving a browser) are not listed, as `bin/rails test` does not run them; run them
  with `bin/rails test:system`. A test that starts a browser anyway is refused (a child process and sockets).
- Assets: what a test reads from `public/assets`, `app/assets/builds` or `node_modules` is recorded (a fresh checkout
  without them, or with other builds, runs the test); a JavaScript or CSS build step before the tests (`test:prepare`
  hooks of jsbundling/cssbundling) runs only when `bin/rails test` gets no file (`vci ci` when it runs everything,
  never `vci run`), so build assets before `vci run` and `vci ci` if tests need them.

## Layout

```
crates/vci-core       repo paths, input manifests, input roots, predicate types
crates/vci-attest     in-toto Statement, DSSE + PAE, SSHSIG verification, allowed_signers, ssh-keygen signing
crates/vci-git        attestation storage on git-meta (git-meta-lib), base-commit file reads, repo identity
crates/vci-adapter    Adapter trait + Vitest, pytest, Go, Cargo and Rails adapters (list, run, JSONL / go test log
                      parsing; src/golang/vci_testlog.go is the logger overlaid into Go's internal/testlog; src/cargo/
                      reads cargo's JSON messages, rustc dep-info and build script output, and scans sources;
                      src/rails.rs runs bin/rails test with the Ruby collector)
crates/vci-cli        the `vci` binary
js/vitest-plugin      @vci/vitest collectors
py/pytest-plugin      vci_pytest collector (pure stdlib pytest plugin)
ruby/vci-collector    vci_collector.rb, the Rails collector (plain Ruby, loaded through RUBYOPT), and its tests
fixtures/vitest-abcd  Vitest end-to-end fixture
fixtures/pytest-abcd  pytest end-to-end fixture (uv project)
fixtures/go-abcd      Go end-to-end fixture (module using golang.org/x/sync)
fixtures/cargo-abcd   Cargo end-to-end fixture (workspace a, b, c, d; d uses the hex crate)
fixtures/rails-abcd   Rails 8 end-to-end fixture (SQLite; a: lib, b: models and fixtures, c: a view, d: a route
                      using the hashids gem)
docs/                 PLAN.md (design), CONTRACTS.md (interfaces), ENV.md (env vars), spike.md (Vitest findings),
                      spike-pytest.md (pytest findings), spike-go.md (Go findings), spike-cargo.md (Cargo findings),
                      spike-rails.md (Rails findings)
```

## Development

```sh
cargo test --workspace                     # unit + integration + end-to-end (needs node, git, ssh-keygen; uv, go, cargo)
cargo clippy --workspace --all-targets -- -D warnings
(cd fixtures/vitest-abcd && npm ci)        # the fixture's node_modules, used by the e2e tests
(cd js/vitest-plugin && npm test)          # collector tests
uv run --project fixtures/pytest-abcd pytest py/pytest-plugin/tests   # pytest collector tests
(cd fixtures/go-abcd && go mod download)   # the Go fixture's module, used by the Go tests
(cd fixtures/rails-abcd && bundle install) # the Rails fixture's bundle, with its Ruby (.ruby-version, e.g. through mise)
ruby ruby/vci-collector/test/collector_test.rb   # Ruby collector tests (also run by cargo test)
```

The Rails end-to-end tests (`crates/vci-cli/tests/e2e_rails.rs`) copy `fixtures/rails-abcd` into a temporary repository
and print `SKIPPED:` (and pass) when the Ruby of its `.ruby-version` is not found (`$VCI_TEST_RUBY_BIN`, `mise where
ruby@<version>`, or `ruby` on PATH) or `bundle check` fails for it; `crates/vci-adapter/tests/rails_collector.rs` runs
the collector's own tests the same way. They prove: attesting b skips only b, and the database was prepared outside
`db/`; editing the fixture yml runs b and `explain` names it; a model only b uses runs b alone; the view template runs
c alone, and of the two files c could read only the one it read matters; `config/routes.rb` runs d; a new file in
`app/models` that takes over a constant (`Calc`) runs a; `db/schema.rb`, a gem version in `Gemfile.lock` and
`.ruby-version` (another version, and the same one spelled differently) run everything; tampered payloads, unknown
signers and PR-only `allowed_signers` are rejected; a declared env var with another value runs b; each refusal
(backticks, `system`, a failure, a skip, no assertions, `ENV.to_h`, a write into `app/`, a read outside the repository,
a socket) while writing to `tmp/` is attested; a database server (SQLite registered under another adapter name) is
refused, attested with `rails_allow_db`, and skipped only while the base policy allows it; push/fetch into a fresh
clone, `vci ci` running only the rest with exit codes and the audit log, `no_skip_refs`; `vci init --adapter rails`.

The pytest end-to-end tests (`crates/vci-cli/tests/e2e_pytest.rs`, `crates/vci-adapter/tests/pytest_fixture.rs`)
copy `fixtures/pytest-abcd` the same way and print `SKIPPED:` (and pass) when `uv` is not installed or cannot set up
the fixture's environment. They prove the same steps for pytest (fixture edit, computed import target, shadowing
package, `conftest.py`, `uv.lock` and dependency changes, tampering, untrusted and PR-added signers, a declared env
var), each refusal (`subprocess`, failure, writes in the repo, env enumeration, outside reads), push/fetch into a fresh
clone, `vci ci` exit codes, and a repository with a Vitest and a pytest project.

The Go end-to-end tests (`crates/vci-cli/tests/e2e_go.rs`, `crates/vci-adapter/tests/go_fixture.rs`) copy
`fixtures/go-abcd` into a temporary repository and print `SKIPPED:` (and pass) when `go` is not installed or cannot
download the fixture's module (`golang.org/x/sync`). They prove: attesting b skips only b; editing its testdata (and
a file read during package initialisation) runs it and `explain` names the file; a file only a uses leaves b
skipped; a new `.go` file in b's directory, a change to the repository package b imports, a new file matching c's
`go:embed` pattern and the file c picks by name at run time each run the right package; a `//go:build linux` file is
hashed and marks the attestation platform-specific; a module bump in `go.mod`/`go.sum` runs everything; tampered
payloads, unknown signers and PR-only `allowed_signers` are rejected; a declared env var with another value in CI
runs b; each refusal (a child process, `net`, `os.Environ`, `syscall`, a read outside the repository, a failing
test, `t.Skip`, a change to the repository during the run); `go_allow_net` only with the base policy's consent;
push/fetch into a fresh clone, `vci ci` exit codes, a module in a subdirectory, `vci init --adapter go`, and that
another Go version (another go binary, or a `GOTOOLCHAIN` switch to a toolchain already in the module cache) runs
everything. Regression tests for adversarial findings prove: link targets read through `io/fs.ReadLink` (over
`os.DirFS` and `os.Root`), `os.CopyFS` and a `var readlink = os.Readlink` function value are inputs; `os.Environ`
as a function value (in the repository and in a third-party module served from a `file://` GOPROXY),
`exec.Cmd.Environ`, and symbolic or hard links from the temp dir to repository files are refused (a link inside the
temp dir is not); a header an assembly file includes from outside its package is an input; `runtime.GOOS`/an aliased
`GOARCH` pin the attestation to the platform and floating-point code to the architecture; a package where no test or
not every declared test ran is refused; `GOFLAGS=-toolexec=...` stops `vci run`; `File.Readdir` after `t.Chdir` is
refused (a plain relative read after `t.Chdir` is recorded); editing a dependency's `_test.go` leaves its
dependents skipped; the local time zone with `TZ` unset is refused and attested with a declared `TZ`. Cross-platform
acceptance is covered by unit tests of the comparison (`platform_diff`, `go_arch_diff`); a manual run with a
linux/amd64 container (a static musl `vci`, Go 1.26.2 for linux/amd64, attestations made on macOS arm64) skipped
exactly the packages that pass there, and ran the `runtime.GOOS`, floating-point and platform-specific assembly
packages (the first two fail there).

The Cargo end-to-end tests (`crates/vci-cli/tests/e2e_cargo.rs`) copy `fixtures/cargo-abcd` into a temporary
repository (with `CARGO_NET_OFFLINE=true` once `cargo fetch` has the `hex` crate; `SKIPPED:` without cargo or the
crate). They prove: attesting b's integration test skips only it; editing the file it reads at run time runs it and
`explain` names the file; a new file in b's package directory runs it; editing crate a runs d (and a) while b stays
skipped; a's unit tests (with an `#[ignore]`d test) and doctests are separate units; c runs when its `include_str!`
target or its build script's `rerun-if-changed` file (both outside its package) changes, not for a neighbouring file;
a `Cargo.lock` version bump and a new `rust-toolchain.toml` run everything; tampered payloads, unknown signers and
PR-only `allowed_signers` are rejected; a declared env var with another value runs b; each refusal (a child process, a
failing test, `env::vars()`, a socket, no tests, an undeclared read outside the package that `[[inputs]]` then
allows, FFI, loose env mode); push/fetch into a fresh clone, `vci ci` exit codes, a missing `Cargo.lock`, cargo
missing; cfg predicates and runtime platform checks recorded (and evaluated against the real
`x86_64-unknown-linux-gnu` cfg set that rustc prints); `vci init --adapter cargo`; and on a copy of **vci's own
workspace**: `crates/vci-core#lib` is attested and then skipped, `crates/vci-git#test:repo` (runs `git`) is refused,
and editing `vci-core` runs it while editing `vci-git` does not. Regression tests for adversarial findings prove: a
build script's undeclared file, a declared variable read by a build script without `rerun-if-env-changed` or by a
proc macro, and an edit restored with an old mtime are rebuilt (the unit fails and is not attested); a README
doctest, an `include!`d `.inc` file and `OUT_DIR` code are scanned; a runner or rustc wrapper in cargo config and
`RUSTC_WRAPPER` are refused; `[target.'cfg(..)']` tables are recorded (and their flags probed) and `[target.<triple>]`
tables pin the unit; `DLL_SUFFIX` and a build script's `consts::OS` pin it; a symlinked directory's files and a
nested `.vci/out` fixture are inputs, a nested `.git` is refused; a package at the repository root is attested on its
first run and still matches without `target/`; a path in a `const` and a path in the wrong letter case are refused;
an out-of-repository `[source]` replacement and an edited git checkout in `$CARGO_HOME` are refused (an edited
registry crate: unit test). `VCI_E2E_BIN=<vci binary>` runs the end-to-end tests against another build (to see a
regression test fail on a build without the fix).

The end-to-end test (`crates/vci-cli/tests/e2e.rs`) copies `fixtures/vitest-abcd` into a temporary git repo with a
bare remote and throwaway SSH keys and proves every step of "End-to-end verification" in `docs/PLAN.md`, plus
expiry, foreign-repo replay, push/fetch into a fresh clone, `vci ci`, `no_skip_refs`, missing base policy, and each
reason `vci run` refuses to attest. Regression tests for adversarial findings against the git-meta exchange (there and
in `crates/vci-git/tests/store_robustness.rs`) prove: a linked worktree, a deleted or emptied
`.git/git-meta.sqlite` and a hand-fetched `refs/meta/local/main` see what was published and never delete it when they
push; a filter rule hiding `vci:` keys makes the push fail instead of deleting them; a non-UTF-8 entry and a 2-byte
path target on the remote are ignored, and a store poisoned by an earlier fetch recovers; a missing blob runs only its
unit; `vci plan` reads a read-only `.git`; concurrent pushes in one clone (with a git-meta writer alongside) all
succeed; shared auto-prune and the attestations it dropped are reported; `vci push` says when nothing was sent;
`.git-meta` URLs naming remote helpers (`fd::3`, `ext::`) are refused; and `vci run <file>` in a multi-project
repository does not need the other projects' toolchains (`e2e_pytest.rs`).

## Known gaps

- Vitest config imports are found by scanning for relative string literals (per-module `tsconfig.json` files and
  custom snapshot paths are covered by the collectors, see "What is hashed").
- External packages are identified by `name@version`: editing code inside `node_modules` without changing the
  version is not noticed (documented above; hashing reached package directories would be a stricter policy).
- Resolution candidates follow Node's and Vite's default extension lists plus `resolve.extensions`; custom resolvers
  in third-party plugins (e.g. tsconfig `paths` plugins) are covered only through the modules they resolve to.
- `DirListing` includes ignored files, so listings of directories with build output differ between machines (those
  tests run; never a false skip). Only the cargo adapter leaves build output (its target dir, `.vci/out`, the
  repository's `.git`) out of a listing, as `excluded` entries.
- The externals check understands npm layouts (`node_modules` lookup plus npm's hidden lockfile); other layouts make
  tests with nested externals run.
- Attestation metadata grows; `vci prune` deletes expired attestations (tombstones), and git-meta's own auto-prune
  (`meta:prune:max-keys`) may drop the least recently written keys (those units then run). No spot-check re-runs or
  transparency log.
- git-meta keeps its store per git directory: in a linked worktree (`git worktree add`), `vci run` writes the
  worktree's own `.git/worktrees/<name>/git-meta.sqlite`, while the `refs/meta/*` refs are shared by all worktrees.
  `vci fetch`/`vci push` copy what the shared ref holds into the worktree's store first (see "What `vci fetch` and
  `vci push` guard against"), so pushing from any worktree publishes the union. Attestations made in one worktree
  are visible in another only after a `vci fetch` (or `vci push`) there.
- git-meta's auto-prune and filter rules are shared settings any metadata writer can change (see above): vci warns,
  but cannot stop another client's `git meta push` from pruning attestations (their units then run until re-attested).
  A manual `git meta prune` rewrites only the serialized tree; while the store still holds the values, the next `vci
  push` publishes them again (vci serializes the whole store). Delete attestations with `vci prune` (deletion records).
- A tree entry git-meta cannot read is left out and warned about; if a non-git-meta writer keeps such an entry on the
  remote while moving it, the merge can still need the old commit and fail (an error: everything runs).
- `vci plan` reads `.git/git-meta.sqlite` read-only (a read-only `.git` works; when SQLite cannot open it in WAL mode
  without writing, the file is read as it is, so changes still only in its `-wal` file are not seen: those units
  run). A value that cannot be read (its blob missing from the object database) fails only its own candidate.
- `vci fetch` into a repository whose metadata history was earlier fetched blobless by `git meta pull` (a promisor
  remote) needs the blobs git-meta's merge reads; if one is missing the fetch fails (an error, so everything runs)
  rather than skipping anything.
- pytest: the adapter requires uv (`uv run --locked --exact`, which removes packages not in `uv.lock` from the
  project environment and syncs only the default dependency groups, so pytest must be in them); plain virtualenvs or
  Poetry are not supported yet. The `vci_pytest` version is not part of the attestation (as with `@vci/vitest`), so a
  collector fix does not by itself invalidate older attestations (the toolchain fields added with this version do:
  older pytest attestations never match). `vci plan` imports every test module (`pytest --collect-only`) to list
  files; a collection error runs everything.
- Go: the adapter needs a module (GOPATH mode is not supported) and runs tests natively (`GOOS`/`GOARCH` must be
  the host's). The overlaid logger compiles for Unix only (it uses `syscall.Open` with an `int` descriptor): on
  Windows every package fails to build under `vci run` and is refused. Its source is not part of the attestation,
  like the other collectors. Test ids are package directories, so `vci run`/`explain` take directories, not files.
- Cargo: the adapter decides inputs conservatively and refuses from source text (see "Cargo limitations"); test ids
  are `<package dir>#<target>`, so `vci run`/`explain` take unit ids or package directories, not files.
- Rails: Minitest only (RSpec is not supported yet); the unit is a test file, so `vci run`/`explain` take files. The
  collector's source is not part of the attestation, like the other collectors.
- Only tested on macOS arm64 (Node 26, git 2.54, OpenSSH 10.3; CPython 3.14.7, uv 0.11.7; Go 1.26.2; Rust 1.96.0
  from Homebrew; Ruby 3.4.9 through mise), plus a `linux/amd64` container check of Rails attestations. Windows paths
  compile but are untested.

## License

Apache License 2.0. See [LICENSE](LICENSE).
