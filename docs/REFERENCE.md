# vci reference

The complete reference: every runner, everything that is hashed, every refusal, the verification algorithm, the threat model and known gaps. For an overview start with the [README](../README.md) or the [docs site](https://pandelisz.github.io/cryptographically-verifiable-ci-runner/).

If a developer (or an agent) already ran test file `b.test.ts` (or `test_b.py`, `test/models/b_test.rb` or
`spec/models/b_spec.rb` of a Rails app, Go package `./b`, or the cargo test target `b#test:b`) against exactly the files it depends on, CI should not have
to run it again. `vci` makes that safe:

1. `vci run` runs Vitest, `node --test`, pytest, `go test`, Rails' `bin/rails test` or RSpec with runtime dependency collectors, hashes
   every file, directory listing, missing-file probe, package version and env var each test file actually used, and
   signs an in-toto attestation with your SSH key. For Rust (`cargo test`), which has no hook for run-time reads, the inputs are decided conservatively
   instead (see [Quick start (Cargo)](#quick-start-cargo)).
2. Attestations are [git-meta](https://git-meta.com/) metadata on the test unit's path (`git meta get
   path:src/b.test.ts`), exchanged on `refs/meta/main` by ordinary git push and fetch (`vci push`, `vci fetch`, or
   `git meta push` / `git meta pull`). vci adds no database or files of its own; git is the transport and the
   authority. See [Where attestations live (git-meta)](#where-attestations-live-git-meta).
3. In CI, `vci plan` checks each attestation against the **base commit's** `.vci/allowed_signers` (SSH keys) or
   `.vci/identities.toml` (CI jobs that sign keylessly with their OIDC token, since 2.0) and `vci.toml`, re-hashes
   every recorded input from CI's own checkout, and skips a test file only when everything matches.
   `vci ci` then runs the rest.

The core rule is **fail open**: the default verdict is RUN. Any error, doubt or unrecognised behaviour means the test runs.

Status: 2.0, Vitest `>=3.2 <6` (tested on 5.0.2 and 4.1.11), Node 22.15+; Node's built-in test runner
(`node --test`, tested on Node 22.23, 24.13 and 26.9); pytest 9 (tested on 9.1.1) on CPython
3.11-3.14 through `uv`; Go modules with Go 1.26 (tested on 1.26.2); Cargo workspaces (tested with Rust and cargo
1.96.0); Rails 8 with Minitest or RSpec on Ruby 3.4 (tested with Rails 8.1.3.1, Minitest 6.0.6, rspec-core 3.13.6 with
rspec-rails 8.0.4 and factory_bot_rails 6.5.1, Ruby 3.4.9, SQLite), and RSpec in plain Ruby projects; macOS and Linux.

## Install

```sh
brew install pandelisz/tap/vci                   # macOS and Linux: prebuilt binary, collectors included
```

Or, without Homebrew, the install script clones the repository to `~/.local/share/vci` and builds with cargo:

```sh
curl -fsSL https://raw.githubusercontent.com/PandelisZ/cryptographically-verifiable-ci-runner/main/scripts/install.sh | sh
```

`vci update` keeps either install current (see [Commands](#commands)). Full guide: [INSTALL.md](INSTALL.md).

## GitHub Actions

After your toolchain setup steps, add:

```yaml
- uses: PandelisZ/cryptographically-verifiable-ci-runner@v2
```

(`@v2` follows the latest 2.x release; `@v1` stays on 1.9.2.) It builds `vci`, fetches attestations, and runs only
what is not already attested. Setup, inputs and security rules: [docs/GITHUB_ACTIONS.md](GITHUB_ACTIONS.md).

With a `signing-key`, or with `oidc: true` and no secret at all (the job's OIDC token, since 2.0), CI attests what it
runs too, so the next commit skips every unit whose inputs did not change: see [CI attests its own
runs](#ci-attests-its-own-runs) and [Keyless signing (OIDC)](#keyless-signing-oidc).

## Quick start (Vitest)

Prerequisites: `git`, `node`, `ssh-keygen` (OpenSSH 8.1+), a Rust toolchain to build the CLI, and an `origin` remote
(where attestations are pushed; without one pass `vci init --meta-url URL`, or `.git-meta` is not written).

```sh
cargo install --path crates/vci-cli            # installs the `vci` binary

cd your-project                                # a git repo with at least one commit and an origin remote
npm install --save-dev /path/to/js/vitest-plugin   # the @vci/vitest collectors
#   (or leave it out and set VCI_JS_PLUGIN=/path/to/js/vitest-plugin)

vci init --key ~/.ssh/id_ed25519.pub --no-install  # writes vci.toml, .vci/allowed_signers, .git-meta
git add vci.toml .vci/allowed_signers .git-meta && git commit -m "Enable vci"
git push origin main
# The trust root is read from the base branch, so merge this commit to main first.

git checkout -b my-change                       # main itself never skips (no_skip_refs in vci.toml)
vci run src/b.test.ts --key ~/.ssh/id_ed25519   # run, collect, sign, store
vci plan --base-ref origin/main                 # SKIP src/b.test.ts, RUN the rest
vci push                                        # publish attestations (git-meta, refs/meta/main)
```

In CI (see [`examples/github-actions.yml`](../examples/github-actions.yml)):

```sh
vci fetch --remote origin                       # git-meta pull: fetch refs/meta/main, materialize it
vci ci --base-ref "$BASE_SHA" --audit-log vci-audit.json
```

## Quick start (node:test)

For projects whose tests run with Node's built-in test runner, `node --test`, usually through a package.json script:

```json
"scripts": {
  "test": "NODE_ENV=test node --import ./test/register-hooks.mjs --test 'src/**/*.test.ts' 'server/**/*.test.ts'"
}
```

Prerequisites: `git`, `node` 22.15 or later (`module.registerHooks`), `ssh-keygen` (OpenSSH 8.1+), a Rust toolchain,
and an `origin` remote (without one pass `vci init --meta-url URL`, or `.git-meta` is not written). The project dir is
the package whose `package.json` holds the script (in a pnpm/npm workspace, one `[[projects]]` entry per package).
`TZ` must reach the tests: the template sets it (`[env] set = { TZ = "UTC", LANG = "C.UTF-8" }`, applied by vci
where it runs and in CI); with `TZ` unset every file is refused, since the machine's own zone is not an input.
`LANG`/`LC_ALL`/`LC_MESSAGES` (ICU's default locale) are inputs of every file: `set` gives them the same value on both
sides.

```sh
cargo install --path crates/vci-cli            # the collector (js/vitest-plugin/src/node-test) is found in this
                                               # checkout, or set VCI_JS_PLUGIN=/path/to/js/vitest-plugin
cd your-project                                # a git repo with at least one commit and an origin remote
vci init --adapter node-test --key ~/.ssh/id_ed25519.pub   # writes vci.toml (adapter = "node-test"), allowed_signers,
                                               # .git-meta; prints the test command it read from the script
git add vci.toml .vci/allowed_signers .git-meta && git commit -m "Enable vci"
git push origin main                           # the trust root is read from the base branch

git checkout -b my-change                      # main itself never skips (no_skip_refs in vci.toml)
vci run src/b.test.ts --key ~/.ssh/id_ed25519  # one `node --test` process per file, collect, sign, store
vci plan --base-ref origin/main                # SKIP src/b.test.ts, RUN the rest
vci push
```

**The command.** `vci.toml` names the script (`test_script`, default `"test"`), or gives the command itself
(`test_globs = ["src/**/*.test.ts"]`, `node_args = ["--import", "./test/register-hooks.mjs"]`). vci reads the script
as `sh -c` would, with a strict subset of `sh`: quotes, `$VAR`/`${VAR}`/`${VAR:-word}`/`${VAR:+word}` (expanded from
vci's own environment, as `npm run` would), field splitting and `sh` globbing of unquoted words (`src/*.test.ts`; no
`**` globstar), leading `NAME=value` assignments, and a `cross-env`/`env` prefix. Pipes, `&&`, redirections, command
substitution, brace and tilde expansion are refused. Every node option is classified:

- **kept** and recorded in the attestation's argv (compared exactly in CI): `--import`, `--require`/`-r`,
  `--conditions`/`-C`, `--env-file`, `--env-file-if-exists`, `--experimental-strip-types` (and `--no-` / transform
  variants), `--experimental-test-module-mocks`, `--experimental-test-snapshots`, `--experimental-vm-modules`, other
  module-format switches, `--test-timeout`, `--test-force-exit`, `--enable-source-maps`, warning and deprecation
  switches, `--preserve-symlinks`, and the V8 memory/stack options (`--max-old-space-size=N`, `--stack-trace-limit=N`);
- **dropped** (per-run plumbing): `--test-concurrency` (each file has its own process; its value still bounds how
  many files vci runs at once, so a suite that needs `--test-concurrency=1` keeps running one file at a time), `--test-reporter`,
  `--test-reporter-destination`, `--test-isolation=process` (the default);
- **refused** (nothing is attested; CI runs everything): `--test-only`, `--test-name-pattern`, `--test-skip-pattern`,
  `--experimental-test-tag-filter`, `--test-shard` (a filtered run cannot vouch for the file),
  `--test-isolation=none`, `--watch`, `--test-update-snapshots`, `--test-randomize`, `--test-rerun-failures`,
  coverage options, `--experimental-config-file`/`--experimental-default-config-file`, `--loader` (off-thread hooks:
  use `--import` with `module.registerHooks`), `--test-global-setup`, `--inspect*`, the permission model, and every
  option vci does not know.

What `npm run`/`pnpm run` do besides the script is not something vci's per-file runs reproduce, so these projects are
refused as a whole (nothing is attested, `vci plan` runs everything, `vci ci` runs the script with the package
manager): a `pre<script>`/`post<script>` script (`pretest`, `posttest`); `node-options` other than memory, warning and
stack-trace options in an `.npmrc` (from the project dir up to the repository root, the user's `~/.npmrc` or
`$NPM_CONFIG_USERCONFIG`, npm's global `<prefix>/etc/npmrc` or `$NPM_CONFIG_GLOBALCONFIG`, pnpm's `rc` files) or in
`npm_config_node_options`, which npm hands the script as `NODE_OPTIONS`; and **install lifecycle scripts**
(`preinstall`, `install`, `postinstall`, `prepare`, ...) in the package.json files from the project dir up to the
repository root or in a workspace package linked into their `node_modules`, since what they change in `node_modules`
(packages are identified by version) or in the repository is not an input. Accepted install scripts: git hook
installers (`husky`, `husky install [dir]`, `is-ci || husky`, `simple-git-hooks`, `lefthook install`) and
`patch-package` (every `patches/` directory from the project dir up to the repository root is a global input). A
listing that matches no file (a build step may create the test files) runs the script too, never "nothing to run".

`NODE_ENV` and every variable the script assigns (`NODE_ENV=test node ...`) are declared automatically: vci sets the
script's value for the test processes and hashes it. The test files are listed with node:test's own rules (Node's
glob from the project dir, `node_modules` excluded; without a pattern node:test's default pattern, with TypeScript
extensions when type stripping is on) by the project's `node` with the script's type-stripping options. A pattern
that names a directory is refused (Node 26 searches it, older versions do not).

`vci run` runs `node --require <collector> <the script's options> --import <late hooks> --test-reporter=<vci reporter>
--test-reporter=spec --test <file>` once per file (in parallel, `$VCI_JOBS` at a time, default: CPUs up to 8), with
the script's assignments set. node:test starts a child process for the file, which inherits the options: the
collector is installed there before any of your `--require`/`--import` preloads, and a second set of module hooks
after them sees every resolution and load of the whole hook chain, including what your hooks answer themselves (an
`@/` alias, extensionless imports, `?raw` loads). The reporter counts the file's tests from node:test's events.
`vci ci --key` runs the remaining files the same way (one process per file, recorded and attested). `vci ci` without
`--key` records nothing, so it runs the remaining files in **one** `node --test` process, the script restricted to
them: from the project dir, with the script's assignments, `node <every option of the script> --test <files>` (the
options a recording run drops are kept: `--test-concurrency`, `--test-reporter[-destination]`; `--test-reporter=spec`
is added when the script names no reporter; each file is a literal glob). It prints the command (`vci: node-test:
NODE_ENV=test node --experimental-strip-types --import=./test/hooks.mjs --test-reporter=spec --test src/a.test.ts
...`, the first 20 files) and its exit code is node's. When nothing of the project is skipped, or everything must
run, it runs the script itself with the project's package manager (`pnpm run test`; detected from `packageManager`,
then the nearest lockfile); when everything is skipped nothing starts. CI example:
[`examples/github-actions-node-test.yml`](../examples/github-actions-node-test.yml). **An attestation vouches for the
file run on its own** (node:test's default process isolation already does that).

### What the node:test adapter records

Per test file, from the collector (`js/vitest-plugin/src/node-test/`, the `@vci/vitest` package's node:test
entries): every module resolved or loaded through Node's module hooks (`import`, `require`, `import()` with a
computed specifier, `import.meta.resolve`; your hook files and what they import), the candidates of every relative
resolution (a missing candidate is a probe, so creating `src/c.ts` beside the `src/c.mjs` an extensionless import
reached is noticed; an existing one is a read), files read, stat'ed, listed or probed through `node:fs` (sync,
callback and promise APIs, by the test, your hooks or packages), packages under `node_modules` as `name@version` (a
**linked workspace package**, `node_modules/@acme/lib -> packages/lib`, is repository content: its files are hashed,
never identified by version, also with `--preserve-symlinks`), the nearest `package.json` of every module, env vars
read, snapshot files node:test reads (`t.assert.snapshot`, custom `snapshot.setResolveSnapshotPath` paths,
`t.assert.fileSnapshot`), `--env-file` contents (as a global input), `TZ`, `LANG`, `LC_ALL` and `LC_MESSAGES` (read
natively by ICU) as env reads, and what your `--require` preloads do in the `node --test` process itself before it
starts the file's process (files read and every module loaded there, through module hooks, so a computed
`require(path.join(__dirname, ...))` is an input). A bare or aliased specifier that Node resolves to a file of the
repository (a workspace package without `exports`, a legacy `main` naming a directory, a `Module._resolveFilename`
alias) also records the candidates Node would have tried first (`util`, `util.js`, ... before `util/index.js`), so
creating one of them is noticed. A package that is a **copy of a repository directory** (pnpm's
`node_modules/.pnpm/<name>@file+...` store entries of `file:` and injected dependencies, or a real
`node_modules/<name>` directory that the package.json beside it declares as `file:<dir>`, as npm with
`install-links` and yarn 1 install them) is not identified by its version: the file is refused
(`external-local-directory:<name>`).

Global inputs of every file: the project's settings in `vci.toml` (the `vci:config` external, 2.7.0); `package.json`, lockfiles (`package-lock.json`, `pnpm-lock.yaml`,
`yarn.lock`, `bun.lock`), `pnpm-workspace.yaml`, `.npmrc` and every `patches/` directory (its listing and files:
what patch-package applies to installed packages) from the project dir up to the repository root; the
`--import`/`--require` files of the command, with the files they name by relative path; the `--env-file`s; the test's
default snapshot file (`<file>.snapshot`, absent recorded as absent); with a TypeScript loader preloaded (`tsx`,
`ts-node`, `@swc-node/register`, `amaro`, `@esbuild-kit/esm-loader`, `esbuild-register`) the `tsconfig.json` chain
from the test's directory up (Node's own type stripping reads no tsconfig, so without a loader tsconfig is not an
input); and `NODE_OPTIONS`.

Toolchain: the Node version, compared by major version (`policy.node_exact = true`: the exact version). node:test is
part of Node, so a minor Node release can change its behaviour: set `node_exact` if you pin Node exactly on both sides.
External packages are checked as installed now: `node_modules/<name>/package.json` from the project dir up, npm's
hidden lockfile, or pnpm's virtual store (`node_modules/.pnpm/<name>@<version>.../node_modules/<name>`).

Refusals specific to node:test (on top of those of every adapter, see below): a skipped or todo test or suite
(`{ skip }`, `t.skip()`, `describe.skip`, `test.todo`); a test that uses `only`; a failing test, a failure outside tests (a load error,
`process.exitCode`, asynchronous activity after a test ended, a cancelled test); **no per-file summary** (node:test
reports none for a file without tests, `no-tests`, or when the process ended early: `process.exit()` in a test is
also tainted `process.exit`); counts that disagree with node:test's summary; a non-zero exit of the `node --test`
process (`vci:process-exit:<code>`); writes inside the repository (`write` records, as for pytest); child processes,
network, `worker_threads`, `fetch`, enumerating `process.env`, recursive readdir and `fs.glob` (as for Vitest);
`process.binding`/`process._linkedBinding` (`process.binding:<name>`: `process.binding('fs')` reads files natively);
node:sqlite SQL that opens or writes another file natively, `ATTACH`, `VACUUM INTO`, `load_extension()`
(`sqlite:<what>`, through `exec`, `prepare` and tag stores), and `loadExtension`/`enableLoadExtension(true)` (a
database the constructor opens, also as a `file:` URI relative to the working directory, is recorded as read);
`module.register` hooks (they run on another thread where reads are not seen) except from `ts-node` and `amaro`,
which only map extensions and strip types (`module.register:<specifier>`; tsx, `@swc-node/register` and
`@esbuild-kit/esm-loader` resolve tsconfig `paths` on that thread, trying targets in an order vci cannot see);
`NODE_OPTIONS` with anything but memory, warning and stack-trace options, as vci's environment holds it and as each
process sees it (`node-test:NODE_OPTIONS:<option>`: from an `--env-file`, or set by a `--require` preload of the `node
--test` process for the file's process, it reaches the process before the collector); **`TZ` unset** in the test
process (`node-test:TZ-unset`: ICU then takes the machine's zone, which is not an input; macOS laptops are rarely on
UTC, runners are) or naming a zoneinfo file (`node-test:TZ-file`); a package copied from a repository directory
(`external-local-directory:<name>`); a missing collector (`vci:collector-missing`, `vci:late-hooks-missing`,
`vci:parent-collector-missing`, Node older than 22.15: `vci:module-hooks-unavailable`).

A test that uses `only` (`test.only`, `{ only: true }`) taints its file (`node-test:only`): without `--test-only`
(refused) Node 22 to 26 still run every test, but the file asks for a filtered run, which a later Node or a
`--test-only` run would honour. Set the time zone in vci.toml (`[env] set = { TZ = "UTC" }`, as the `vci init` template does: vci sets it here and
in CI), or in the script (`TZ=UTC node --test ...`: an assignment there is hashed).

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
plain full-suite `pytest`). CI example: [`examples/github-actions-pytest.yml`](../examples/github-actions-pytest.yml).

**Which files are test files.** `vci plan`, `vci ci` and `vci run` (without file arguments) list the files a plain
`pytest` in the project dir collects without starting Python, by pytest's documented collection rules: the
configuration file (the first of `pytest.toml`, `.pytest.toml`, `pytest.ini`, `.pytest.ini`, `pyproject.toml` with
`[tool.pytest]` or `[tool.pytest.ini_options]`, `tox.ini` with `[pytest]`, `setup.cfg` with `[tool:pytest]`, in the
project dir or the nearest parent holding one), `testpaths` (globs included; used only when that file is in the
project dir, as pytest uses it only from its rootdir; default: the project dir), paths given in `addopts`,
`python_files` (default `test_*.py *_test.py`), `norecursedirs` (default `*.egg .* _darcs build CVS dist node_modules
venv {arch}`; a configured list replaces it), `__pycache__` and virtualenvs (a `pyvenv.cfg` or `conda-meta/history`,
unless `--collect-in-virtualenv`), `--ignore` and `--ignore-glob` in `addopts` or `PYTEST_ADDOPTS`, `-o`/
`--override-ini`, and doctest files (`test*.txt` or `--doctest-glob`, and every module with `--doctest-modules`) that
hold a `>>>` example. Symlinked directories are followed, as pytest follows them (a file reached outside the project
dir runs everything). `__init__.py` packages change nothing. **What conftest.py files and plugins decide is not
seen**: `collect_ignore` and `collect_ignore_glob` are not honoured (such files are listed and each runs on its own:
it fails open, so a file that only imports on another Python version fails its run), and neither are
`pytest_ignore_collect`/`pytest_collect_file` hooks or files a plugin collects (pytest-mypy, pytest-ruff and the like:
not listed, not run by `vci ci`). A listed file with no test, or whose tests `-k`/`-m` in `addopts` all deselect,
collects nothing when it runs (pytest's exit code 5), which counts as passing as in a whole-suite run, also when it is
the only file `vci ci` runs. No test ran, so `vci run` does not attest it: it runs (one short pytest process) on every
`vci ci`. `--pyargs`, and `-c`/`--config-file`/`--rootdir` or paths in `PYTEST_ADDOPTS`, are not followed: the
listing fails and the project runs everything, as does a configuration file pytest cannot read.

### Attesting on macOS, verifying on Linux (`platform = "any"`)

Attestations made on a laptop can be accepted by a GitHub Actions `ubuntu-latest` runner when everything the
toolchain check compares is identical there:

- **the Python build**: attest with a uv-managed interpreter (python-build-standalone) whose exact patch version uv
  also ships for `x86_64-linux-gnu` (`uv python list --all-platforms`; e.g. 3.14.4 with uv 0.11.7; Homebrew's 3.14.7
  has no Linux build), pinned in `.python-version`, with `UV_PYTHON_PREFERENCE=only-managed` on both sides. The
  bundled sqlite and OpenSSL versions are compared too (`python libraries`). `vci run` warns when the interpreter is
  not uv-managed. Or set `policy.libraries = "any"` in the base `vci.toml`: the SQLite and OpenSSL versions are then
  not compared (the Python version, implementation and installed distributions still are);
- **uv**: pin the same uv version locally and in `astral-sh/setup-uv` (`version:`), so both resolve the same builds;
- **the installed distributions**: the full `name==version` set must be equal (`python distributions`). A dependency
  with a platform marker (`sys_platform == 'linux'`) installs only on one side, so every file runs there;
- **directory listings**: a test that lists a directory records its entries without the ones git ignores
  (`.DS_Store`, `__pycache__`, `dist/`, `node_modules/`: build outputs and junk a fresh checkout does not have and
  every machine has differently; since 2.0.3, as `Excluded` entries of the manifest), and a verification leaves
  what git ignores there out of the listing too. An ignored file a test reads directly is still an input, and
  `vci run` warns that a fresh checkout will not have it;
- **environment**: only the variables `[env]` and the built-in lists name reach tests (docs/ENV.md). A test that
  reads `HOME`, `USER`, `TMPDIR`, ... records their values, so it is skipped only where they are equal (on a runner:
  never); `set` gives a variable the same value everywhere.

Everything else (a different OS, `sys.platform`-dependent code paths in your tests or dependencies) is what
`platform = "any"` accepts; use `platform_overrides` with `"exact"` for files that behave differently per platform.
Files with skipped tests (`skipif(sys.platform == ...)`) are not attested unless the base policy waives
`result:skipped` (see [Waiving taints](#waiving-taints-policyignore_taints)).

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
never stands in for a run. Findings behind this design: [`docs/spike-go.md`](spike-go.md). CI example:
[`examples/github-actions-go.yml`](../examples/github-actions-go.yml).

### Attesting on macOS, verifying on Linux (Go)

Under `platform = "any"` a package attested on macOS arm64 is skipped on an ubuntu-latest x86_64 runner when:

- **the Go version is identical** (`go env GOVERSION`; pin it in `actions/setup-go`), and so are the effective
  `CGO_ENABLED`, `GOFLAGS`, `GOEXPERIMENT`, `GOFIPS140`, `GODEBUG` and `GOWORK`. `CGO_ENABLED` defaults to 1 only
  where a C compiler is found (Xcode's command line tools, the runner's gcc; a container without one defaults to 0),
  so the robust setting is `[env] set = { CGO_ENABLED = "0" }` (vci sets it on both sides; cgo is refused
  anyway). The architecture level (`GOARM64`, `GOAMD64`) is compared only between machines of
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
  which is not an input (macOS laptops are rarely on UTC; runners are), and is refused. Set it in vci.toml
  (`[env] set = { TZ = "UTC" }`, as `vci init` writes): vci sets it on both sides;
- the directory listings match (what git ignores is left out of them since 2.0.3), and the test
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

`vci run` builds and runs the units in three parts (`crates/vci-adapter/src/cargo/lane.rs`):

1. **A warm-up build**: `cargo test --locked --no-run --manifest-path <pkg>/Cargo.toml --message-format=json
   --target-dir <target>/vci` for each package with a requested unit, one package after another, each with cargo's
   full job parallelism. Each package is built alone so that its dependencies' features are unified as they are for
   its units (a build of several packages can turn on more features, and each unit's own build would then compile
   again). A failed warm-up does not stop the run: each unit's own build then compiles what it needs.
2. **The cargo lane**: one thread makes every cargo call of the run, in order (cargo locks the build directory). For
   each unit it runs the unit's own build, the unit alone:

   ```
   cargo test --locked --manifest-path crates/b/Cargo.toml --test b --no-run --message-format=json --target-dir <target>/vci
   ```

   After the warm-up this mostly finds everything fresh. The unit's inputs are derived from this build's messages,
   and the test executable it reports (the unit's package, `profile.test`, the unit's target kind and name) is the
   one that runs, so the artifacts analysed and the binary executed come from the same cargo invocation. `#doc` units
   run `cargo test --locked --manifest-path <pkg>/Cargo.toml --doc --message-format=json --target-dir <target>/vci`
   in the lane instead: doctests cannot be built without running them.
3. **The execution pool**: `VCI_CARGO_JOBS` threads (default: the number of CPUs) run the test executables as the
   lane hands them over, several at a time, each in its package directory, with a fresh empty `TMPDIR` and with what
   `cargo test` adds to a test's environment (below). A unit's output (its cargo calls, then `vci: (in <package dir>)
   <executable> (exit N)` and the test output) is printed as one block when the unit is done: blocks come in the
   order units finish, and nothing is shown while a test runs. A failing test executable counts as exit 101, the
   code `cargo test` exits with.

Once every test of the run has run, the units are analysed, in parallel, with run-wide caches (directory walks,
dep-info, source scans, manifest scans, registry and git source checks); a package directory shared by several units
is walked after all of their tests ran. A unit whose build fails, whose build reports no test executable for it, or
whose executable cannot be started is not attested (the reason says which); the other units go on.

What a test executable gets on top of the run's environment is what cargo adds (`fill_env` in cargo's
`core/compiler/compilation.rs`), compared with the environment a test sees under cargo 1.96's own `cargo test`
(Homebrew's and rustup's, on macOS; Linux and Windows are covered by unit tests only):

- `CARGO` (the cargo binary, as cargo reports it: `$CARGO`, or the toolchain's own cargo under rustup's proxy),
  `CARGO_MANIFEST_DIR`, `CARGO_MANIFEST_PATH`, and the package's `CARGO_PKG_NAME`, `CARGO_PKG_VERSION` (and its
  `_MAJOR`, `_MINOR`, `_PATCH`, `_PRE` parts), `CARGO_PKG_AUTHORS`, `CARGO_PKG_DESCRIPTION`, `CARGO_PKG_HOMEPAGE`,
  `CARGO_PKG_REPOSITORY`, `CARGO_PKG_LICENSE`, `CARGO_PKG_LICENSE_FILE`, `CARGO_PKG_RUST_VERSION`, `CARGO_PKG_README`;
- `CARGO_BIN_EXE_<name>` for each binary of the package (integration tests and benches only);
- `OUT_DIR` and the `cargo::rustc-env` variables of the package's build script;
- the library search path (`DYLD_FALLBACK_LIBRARY_PATH` on macOS, `LD_LIBRARY_PATH` on Linux, `PATH` on Windows):
  the build scripts' link directories inside `<target>/vci/debug`, then `<target>/vci/debug`, its `deps`, and the
  sysroot's `lib/rustlib/<host>/lib`, then the variable's existing value (macOS's defaults when it had none);
- the `[env]` table of the cargo configuration (`force` and `relative` as cargo reads them);
- under rustup's proxy, what the proxy sets for cargo: `CARGO_HOME`, `RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`,
  `RUSTUP_TOOLCHAIN_SOURCE`, `RUST_RECURSION_COUNT`, and `<sysroot>/lib` in front of the library search path.

`CARGO_CRATE_NAME` and `CARGO_TARGET_TMPDIR` are set at compile time only; `cargo test` does not give them to the test
process, so vci does not either.

**Measured** on vex (a workspace of 26 members, 242 units, 955 packages) on a 14-CPU Mac, 2026-10-16, with the
compiler cache (sccache) warm. All 242 units in one `vci run`: 1304 s with nothing built yet (the 26 warm-up builds
took 684 s of that; the units' own builds, the tests, the analysis and the signing the remaining 10 minutes), and
653 s with the dependencies already in `target/vci`. The units' own builds after the warm-up were 247 cargo steps
totalling 218 s (median 0.5 s), 36 of which compiled something again (a build script that hashes a directory it
rewrites). `cargo nextest run --workspace --exclude vex-jj` on the same machine, with the same compiler cache: 440 s
(83 s of compilation, 254 s of tests). Six units alone: 39.6 s against 109.4 s for vci 1.7.1 with the dependencies
built (182.0 s cold), both attesting the same three with byte-identical attestations. What the 242-unit run attested
with `ignore_taints = ["*"]`: 172 units (91 of them through a waived `cargo:undeclared-reads`; the 72 units of
the package whose build script embeds a prebuilt UI bundle needed that bundle's path ignored in `[env]`, else the
script rebuilt the bundle during the run and changed its own inputs), with 64 refused for having no tests (23 doctest
units, 23 binaries, 12 integration tests, 6 libraries) and 6 failing on that machine. Before 1.8.0 the same workspace
attested 13 of 242: integration tests of packages with a binary (107 units) were refused for a missing dep-info
file, every unit building jj-lib for a glob pattern taken as a path, and every vex-cli unit for a file reached
through a symlinked directory (`jj/cli/docs -> ../docs`), which 1.8.0 records at its real path.

A `$CARGO_HOME` inside the repository (CI mounting `.cargo-home/` under the checkout) is not part of it: the
registry crates and git checkouts there are external packages, verified against Cargo.lock, never walked or
cleaned, and left out of the pre-run snapshot (since 1.8.1).

`--manifest-path` selects the package the way `-p <name>` would (package names can be ambiguous; the path cannot). vci
builds into `<target dir>/vci`, which only ever sees builds made with vci's environment policy, and **rebuilds the
repository's crates in every `vci run`** (`cargo clean -p <every workspace member>` there first; a crate of the
repository found reused later, such as a path dependency outside the workspace, is cleaned and its unit run again):
cargo decides freshness by modification times and by what build scripts declare, vci by content, so a file restored with
an older mtime (`cp -p`, `tar`, `rsync -t`), a build script reading a file or a variable it does not declare, or a proc
macro reading a variable, would otherwise be attested against a stale build. External crates stay cached. `vci ci` runs
every remaining unit the same way (warm-up, lane and pool, without the clean and without analysis), so each unit is
still built alone, with the features the attestation was made with (Cargo resolves features per selected package); it
exits non-zero if any fails. If it cannot set that up (the toolchain probe, `cargo metadata` or `Cargo.lock` fails), it
runs each unit with its own `cargo test --locked --manifest-path <pkg>/Cargo.toml <selector> --target-dir <target>/vci`,
one at a time, as before. **An attestation vouches for the unit run on its own**: a plain `cargo test --workspace` can
unify features differently. `cargo test` also compiles examples that are not test targets; the warm-up compiles those of
the packages it builds, but not of a package with no unit left to run, and a failed warm-up does not fail `vci ci` (the
example workflow keeps a `cargo build --examples` step). CI example:
[`examples/github-actions-cargo.yml`](../examples/github-actions-cargo.yml). Findings behind this design:
[`docs/spike-cargo.md`](spike-cargo.md).

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
  difference (`superuser`), for every adapter, unless the base branch sets `policy.allow_superuser_mismatch = true`
  (see [`vci.toml`](#vcitoml));
- the environment matches (`RUSTFLAGS`, `CARGO_PROFILE_*`, the C toolchain variables and the other built-in hash
  variables are hashed when present, other `RUST*`/`CARGO*` variables are removed unless listed; see docs/ENV.md) and no input is missing in the checkout (`.DS_Store` in a package directory breaks that).

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
without `test/system`, `test/dummy` and `test/fixtures`), or an **RSpec spec file** (see
[Quick start (RSpec)](#quick-start-rspec)). Test ids are repo-relative paths.

```sh
cargo install --path crates/vci-cli            # the collector (ruby/vci-collector) is found in this checkout,
                                               # or set VCI_RUBY_COLLECTOR=/path/to/ruby/vci-collector
cd your-app                                    # a git repo with at least one commit and an origin remote
bundle lock --add-platform x86_64-linux        # so the CI runner can install the same bundle
vci init --adapter rails --key ~/.ssh/id_ed25519.pub   # writes vci.toml (adapter = "rails"), allowed_signers, .git-meta
git add vci.toml .vci/allowed_signers .git-meta Gemfile.lock && git commit -m "Enable vci"
# .git-meta is written only when the repository has an origin remote (or with --meta-url <url>); without one,
# leave it out of `git add`. The trust root is read from the base branch: push or merge this commit to main first.

vci run test/models/b_test.rb --key ~/.ssh/id_ed25519   # collect, sign, store (several files: one boot)
vci plan --base-ref origin/main                          # SKIP test/models/b_test.rb, RUN the rest
vci push
```

`vci run` (and `vci ci --key`) of several files starts **one process per runner**, as `bin/rails test` does, with
the collector in batch mode (vci 2.0): it boots the application once, then forks one process per file, one at a time
(the files of a project share the test database), each of which runs that file alone. One file, or
`VCI_RAILS_PER_FILE=1` in vci's environment, runs one process per file from the start:

```
RUBYOPT=-r<abs>/ruby/vci-collector/vci_collector.rb VCI_RAILS_MODE=collect VCI_OUT=<fresh dir> \
  TMPDIR=<fresh dir> RAILS_ENV=test PARALLEL_WORKERS=1 DISABLE_SPRING=1 \
  DISABLE_BOOTSNAP=1 BUNDLE_GEMFILE=<project>/Gemfile ruby bin/rails test test/models/b_test.rb --seed 0
# several files: VCI_RAILS_BATCH=<list of their test ids> ... ruby bin/rails test <files> --seed 0
```

In batch mode the process waits until the test runner asks for the first test file (Rails' `Runner.load_tests`,
RSpec's `load_spec_files`), loads none of them, and forks: once per group of files whose first statement requires the
same helper (`require "test_helper"`, `require "rails_helper"`), a process that requires it (the boot), and from it
one process per file, which skips the runner's requests for the other files, loads its own, runs its tests and writes
its output as a one-file run does. Each file's inputs, result and exit status are therefore those of a run of that
file on its own, with the boot observed once: nothing one file's code defines, patches, caches or loads reaches
another file's process, and what a file's process leaves in vci's temp dir is removed before the next one starts. A
file whose first statement is not such a require boots in its own process. What the batch cannot run this way (a helper
that fails in the boot, a process that writes no output, a runner whose loader vci does not know) runs again one
process per file, and `vci run` says so. Since 2.1.5 so does a file whose process fails in a slot (below): an earlier
file of the slot may have left rows its tests collide with, as in a Rails worker, so it runs again on its own from a
fresh boot and database, and the retry's result is the file's (a failure on its own fails the run as before). Details
and measurements: [`docs/spike-rails.md`](spike-rails.md) ("Batch mode").

**Slots (vci 2.1).** When the project runs its tests in Rails' parallel worker processes (`parallelize` in
`test_helper.rb`, with processes, as `rails new` writes it), a group's files run W at a time: W is `VCI_RAILS_JOBS`,
else `PARALLEL_WORKERS` above 1 (in vci's environment; the test processes still get 1), else `VCI_JOBS` or the
number of CPUs, at most as many as `parallelize(workers: n)` asks for, and at most one per piece of work (a file, or
each shard of a file that runs as shards; before 2.7.34, one per file: a job with 8 files, four of them 3 to 5 shards
each, ran its 20 pieces on 8 slots). `PARALLEL_WORKERS=1`
in vci's environment or `parallelize(workers: 1)` turns Rails' workers off, and the slots with them. A group whose
files' first statement is not a require of a shared helper has no boot and runs one file at a time. After the boot, vci forks one process per slot and sets it up exactly as Rails
sets up a parallel worker: Rails' before-fork hooks once, then in each slot `parallel_worker_id = i` and every
after-fork hook (Rails' own creates and loads the database `<database>_<i>`, as `bin/rails test` does with workers;
`parallelize_setup` blocks; Oaken's seed load). Each slot then forks one process per file, as above, against its own
database, which a file's process does not seed again (Minitest's executor answers `should_parallelize?` as in a
worker), and runs `parallelize_teardown` at its end. Files share a slot's database with the files the slot ran
before them, as tests share a worker's: what the database holds is not an input either way. `VCI_RAILS_JOBS` set to
a number applies to any project (`1`: one file at a time, as in vci 2.0); without `parallelize` and without it, a
batch runs one file at a time. RSpec has no parallel workers: slots there share the test database (set
`VCI_RAILS_JOBS` only if your specs can share it). Details: [`docs/spike-rails.md`](spike-rails.md) ("Slots").

Autoload lookups (since 2.6, opt-in): with `rails_autoload_lookups = true` in `[policy]` (or a project's), a directory Zeitwerk lists only to set up autoloads (never to eager load) is not an input as a listing. vci records instead the constant names the test's process looked up without loading them: a miss (`const_missing`, which a plain reference, `const_get`, `constantize` and `safe_constantize` reach), and `const_defined?` answering false, or true for an autoload not loaded yet. A unit then runs again only when one of its autoload directories gains, loses or renames a child whose name matches one of those names (`html_parser.rb` matches `HTMLParser`; names compare without underscores or case, and in any autoload directory, whatever namespace asked). A file added to an autoload directory (by the change, or on the base branch since the attestation) otherwise runs every test that booted the application again. A namespace whose constants are enumerated (`Module#constants`) keeps its directories' listings. Ruby answers `defined?(Constant)` without a method vci can hook, so (since 2.6.1) the constant paths after `defined?` in every repository Ruby file the test loaded are names it looked up too. What remains unseen is a gem's own code asking `defined?` about one of the application's constants: a test may then pass without having seen a constant a new file defines. The base commit's policy must set it for `vci plan` to accept such an attestation; the collector records lookups when the policy `vci run` or `vci ci` reads sets it. Since 2.7.36 `rails_inputs = "loose"` (the default) records lookups too and leaves the records out of the manifest, so the lookups no longer decide anything there: with loose inputs, a new file in an autoload directory runs nothing again (see [Boot-time files are not inputs](#boot-time-files-are-not-inputs-rails_inputs-since-2734)); this policy matters with `rails_inputs = "strict"`.

Long files run as shards (since 2.3): when slots run a Minitest file whose last attested run took at least twice
`VCI_RAILS_SHARD_SECONDS` (default 30; `0` turns it off), the file runs as `ceil(duration / that)` processes, at most
one per slot, each forked as a file's process is and running a share of the file's test methods (of each class,
every k-th method of its sorted list, so each method runs once between them), as Rails' parallel workers split
tests by method. The file is attested from its shards together: every shard's inputs, one result (passed only when
every shard passed). A shard that failed, or did not run, makes the file run again whole on its own.

**Shared output (vci 2.1).** Most of what a file's process records is its boot's (on vex-api about 14,400 of 14,500
lines). The boot (or each slot, after its setup) writes those lines once, before any file's process forks from it;
each file's process then writes only the lines that are not among them, and names the shared lines it does not have
(a path it wrote that the boot found absent, an environment variable read from another place too). vci reads the two
together: the same lines a file's process writes when nothing is shared, so the attestations are the same.
`VCI_RAILS_SHARED_OUTPUT=0` (in vci's environment) makes each file's process write all of its output. Details:
[`docs/spike-rails.md`](spike-rails.md) ("Shared output").

The collector (`ruby/vci-collector/vci_collector.rb`, plain Ruby, nothing is installed into your project) is loaded
through `RUBYOPT` before `bin/rails`, Bundler and Rails. It sets these run conditions:

- **the database is the test engine's**: vci does not manage it. It uses the databases `config/database.yml`
  configures for the test environment as they are (`db/test.sqlite3`, Rails 8's `storage/test.sqlite3`, a MySQL or
  PostgreSQL server). Rails gives each test its starting state the way it does in a plain `bin/rails test`:
  `rails/test_help`'s `maintain_test_schema!` loads the schema when it is not current (on a fresh checkout it creates
  the database through `bin/rails db:test:prepare`, a child process of Active Record's that vci does not refuse), then
  fixtures and transactional tests. What the database holds is **not an input** (see
  [vci does not manage the database](#vci-does-not-manage-the-database-read-this));
- **one process**: `PARALLEL_WORKERS=1` (Rails' `parallelize` then runs in-process; a fork is refused), no Spring, no
  Bootsnap caches (`DISABLE_BOOTSNAP=1`, which `bootsnap/setup` honours; a compile or load-path cache still in use,
  such as one an explicit `Bootsnap.setup(...)` in `config/boot.rb` installs whatever the variable says, is refused);
- **a fixed Minitest seed** (`--seed 0`): the order of the tests in the file and `rand` (Minitest seeds it) are the
  same where the file was attested and in CI. (A test that passes only in some orders passes in neither or both.)
- **a fresh local secret**: the development/test `secret_key_base` Rails would keep in `tmp/local_secret.txt` is
  generated in memory for each process, as on a fresh checkout, so its random content is not an input.

`vci ci` runs the remaining files of a project the engine's own way, in **one process per runner**
(`bin/rails test <files> --seed 0`, `rspec --options .rspec <files>`; `VCI_RAILS_MODE=plain`: the same run conditions,
nothing recorded), and exits non-zero if any fails. **An attestation vouches for the file's result with the inputs
recorded for it**, as a run of that file on its own gives them (in batch mode too); what the database holds is not an
input (one file's leftovers there can reach the next file, as with one process per file). CI example:
[`examples/github-actions-rails.yml`](../examples/github-actions-rails.yml). Findings behind this design:
[`docs/spike-rails.md`](spike-rails.md).

### What the Rails adapter records

Ruby has no audit hook. The collector wraps the Ruby entry points instead (`File`, `FileTest`, `IO`, `Dir`
including `Dir.open`, `File::Stat`, `Pathname` through them, `Kernel#open`/`require`/`load`/`test` and their
`Kernel.require`/`Kernel.load` copies, which every plain `require` goes through under Bundler on Ruby 3.4, `ENV`,
`Process`, sockets), and records per file. Libraries with C entry points it must hook (`PTY`, `Fiddle`, FFI, SQLite,
database clients, Nokogiri, `Zlib`, Prism's `parse_file`/`lex_file`/... and `RubyVM::InstructionSequence.compile_file`,
which read a source file in C) are hooked when their constants are defined, however they were loaded; one loaded but
never hooked refuses the file (`vci:not-hooked:`).

Paths under the fresh temp dirs vci gives the process are not inputs. The collector fixes them when it loads: a test
that sets `ENV["TMPDIR"]` (to `/tmp`, `HOME`, `/`) moves its own temp files, not what the collector ignores, so its
reads there are still recorded (outside the repository: refused). This and every other exemption (Ruby's own library
directories, the zone database, vci's collector directory) holds for where a path really leads, not how it is spelt:
a path outside the repository is resolved when it is used (a symlink may be gone when the process exits), so a read
through a symlink there into the repository is a read of that repository file, and one leading anywhere else is a
read outside the repository (refused). File names are taken as Ruby's `File`, `Dir` and `IO` entry points take them:
`File.read("~note.txt")` and `File.open("|x")` open files of those names in the working directory (only `Kernel#open`
and `IO.read`/`readlines`/`foreach`/`write` called on `IO` run a command for `"|cmd"`, which is refused); a name the
collector cannot resolve refuses the file (`vci:unresolvable-path:`). `/etc/resolv.conf`, read by Ruby's `resolv` while
it loads (`require "net/http"` does that), is not an input; any other read of it is.

- **code**: every Ruby file compiled from disk (`require`, `require_relative`, `load`, `autoload`, Zeitwerk), and for
  every `require` of a feature name, each repository `$LOAD_PATH` entry Ruby searched before the one that held it
  (`<entry>/<feature>.rb`, `.so`, `.bundle` as absent), so a file that would shadow it invalidates; a failed `require`
  (an optional dependency, `Bundler.require` of a gem with no file of its name) records every candidate as absent;
- **Zeitwerk**: the listing of every autoload directory it scans (`app/models`, `lib`, ... and namespaces as they
  load). A new file in `app/models` therefore runs every test that boots Rails: whether a new constant changes
  resolution is decided by Zeitwerk at run time, and vci does not model it. With `rails_inputs = "loose"` (the
  default since 2.7.36, below) the collector records autoload lookups instead and leaves them out: a new file there
  runs nothing again;
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

Global inputs of every file: the project's settings in `vci.toml` (the `vci:config` external, 2.7.0); in the project dir `Gemfile`, `Gemfile.lock` (or `gems.rb`/`gems.locked`),
`config/application.rb`, `config/boot.rb`, `config/environment.rb`, `config/environments/test.rb`, `config.ru`,
`bin/rails`, `test/test_helper.rb` and `Rakefile`; and `.ruby-version`, `.tool-versions`, `mise.toml` (and its
variants) from the project dir up to the repository root. Missing ones are recorded as absent. **Any `Gemfile.lock`
change runs everything.** With `rails_inputs = "loose"` (the default since 2.7.36) the boot files among them
(`config/application.rb`, `config/boot.rb`, `config/environment.rb`, `config/environments/test.rb`, `config.ru`) are
not global inputs.

### Boot-time files are not inputs (`rails_inputs`, since 2.7.36)

Rails reads its routes, initializers, environment files, migrations and translations while it boots, and Zeitwerk
lists every autoload directory. Recorded, each of them is an input of every test file of the project, so a pull
request that adds a route, an initializer or a model file ran the whole suite again. Since 2.7.36 a Rails project
(Minitest and RSpec alike) leaves them out of its manifests by default:

```toml
adapter = "rails"
rails_inputs = "loose"                        # the default; "strict": every file a test's process read is an input
ignore_inputs = ["config/credentials/**"]     # more globs, relative to the project dir (in either mode)
```

In `[[projects]]` both go in the project's own table, next to `adapter` and `runner`. In loose mode these are never
inputs (globs relative to the Rails root; `dir/**` covers the directory's listing too):

| Glob | What |
| --- | --- |
| `config/application.rb`, `config/boot.rb`, `config/environment.rb` | the boot files |
| `config/environments/**` | per-environment settings (`test.rb`) |
| `config/initializers/**` | initializers |
| `config/routes.rb`, `config/routes/**` | routes (and `draw`n route files) |
| `config/locales/**` | translations |
| `config/puma.rb`, `config/spring.rb`, `config.ru` | server and preloader configuration |
| `db/migrate/**` | migrations (the schema they produce, `db/schema.rb`/`db/structure.sql`, stays an input) |
| `.vci-autoload` | the autoload lookup records (`<dir>/.vci-autoload`, `.vci-autoload/<name>`): in loose mode the collector records lookups instead of autoload directory listings, as `policy.rails_autoload_lookups` does, and leaves them out, so a file added to `app/models` (or any autoload directory) runs nothing again |

What stays an input: `Gemfile`, `Gemfile.lock` and the gems (a gem change runs everything), `db/schema.rb` and
`db/structure.sql`, `config/database.yml`, `test/test_helper.rb`, `test/support/**`, `spec/*_helper.rb`,
`spec/support/**`, the Ruby version files, and every file the test's process read that is not in the list: models,
services, controllers, views, fixtures, the test file itself. `ignore_inputs` adds to the list (in strict mode it is
the whole list); `.vci-autoload` in it leaves out the lookup records in strict mode too.

**The trade-off, plainly:** a change to a boot file no longer runs any test again on a pull request. A test whose
outcome depends on a route, an initializer, a migration, a translation or which constants exist can pass on the pull
request's branch with a skip it should not have had. A run that skips nothing catches it: the default branch's
(`policy.no_skip_refs` covers it in the `vci init` template), whose full run then attests every unit again. Set
`rails_inputs = "strict"` where that is not acceptable.

The filter is applied when a unit is recorded: a loose attestation's manifests simply do not contain those paths, and
its predicate says so (`railsInputs`, `"loose"` or `"strict"`, and `ignoredInputs`, the globs left out). `vci plan`
re-checks what an attestation records, as always, and leaves the base vci.toml's list out of the current global inputs
only for an attestation that records `railsInputs`. An attestation made before 2.7.36 records every input: it stays
usable (loose mode's default settings do not change the `vci:config` external) and keeps running again on a change
to a boot file until the unit is attested in loose mode, which the default branch's first full run after the upgrade
does. `rails_inputs = "strict"` or any `ignore_inputs` is part of `vci:config`, so an attestation made in the other mode
or with another list is not accepted. `vci run` says once per project what it left out (`vci: rails inputs are loose:
N boot-time files are not inputs (config/routes.rb, ...); set rails_inputs = "strict" to record them`), and
`vci explain` prints the base vci.toml's mode and list, and the mode each candidate was recorded with.

Toolchain: Ruby's version and patchlevel (`3.4.9p82`) and engine, Rails (`Rails::VERSION`, or the bundle's `railties`
for a test file that never loads Rails, such as a Minitest file under `test/lib` that requires only `minitest` and
plain Ruby, or a spec that loads only `spec_helper`: both runners report what the probe reports), Bundler and Minitest
versions, the SQLite library the `sqlite3` gem loaded, libyaml, the time zone data (the
`tzinfo-data` gem, or the system zoneinfo directory and its version), the default external/internal encodings, the
collector's version (`vci_collector.rb`'s `VERSION`, bumped whenever what it records or refuses changes, so CI must run
the same collector: pin the action or the vci checkout to the commit you attest with; vci 1.4.0 ships 0.5.0), the
database adapters of the test environment (`rubyDb`: the adapter names of Active Record's test configurations,
`DATABASE_URL` included, such as `sqlite3`, `mysql2`, `trilogy` or `postgresql`; sorted and joined with `;` for
several, such as `postgresql;sqlite3`; compared exactly, as a test that passes on SQLite may fail on MySQL; no server
version), the full bundle, and whether the tests ran as root (unless `policy.allow_superuser_mismatch`); OS/arch per
`policy.platform`. Under `policy.libraries = "any"` the versions of the SQLite library, libyaml and the
time zone data are not compared (whether each is loaded still is).

vci reads this toolchain without booting the application, in `vci plan` and in what `vci run` records alike: one
Ruby process sets up the bundle (Bundler fails there, as every test process would, when the bundle is not installed),
loads YAML and TZInfo as every booted Rails application does, `sqlite3` when `Bundler.require(*Rails.groups)` would
require it, sets both default encodings to UTF-8 as Rails' `config.encoding` does, and reads the test environment's
database adapters from `config/database.yml` as Rails reads it (ERB, `shared`, `DATABASE_URL`). Only when that file's
ERB needs the application (`Rails.root`, credentials) is the application booted for it. `vci run` also boots the
application once and refuses to attest when it does not boot (a native extension of the bundle that fails to load),
when the booted application reports anything else (a custom `config.encoding`, a gem that loads `sqlite3` itself), or
when the boot finds a reason the application cannot be attested. `vci plan` does not: it compares the toolchain read
without booting with what the attestation recorded, and boots the application only for the native libraries an
attestation records (once per project, and only when a candidate attestation lists one: see "Native libraries" below).
The trade-off: an application that cannot boot where the plan runs, for a reason outside its recorded inputs and
toolchain (a corrupt native extension of an unchanged gem version, a system library removed from the runner), is not
detected by the plan, which skips what was attested. The attested run booted it, and CI's own full runs (on
`policy.no_skip_refs`) still boot it.

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
not have it, so a test that read it runs in CI. A key given as `RAILS_MASTER_KEY` follows the env policy (removed unless listed;
listed in `hash`, its hash is stored, as for any hashed variable).

**In an app generated with credentials (`rails new` writes `config/master.key` and `config/credentials.yml.enc`),
Active Record reads `config/master.key` while Rails boots** (its encryption settings come from the credentials), so
every test that boots Rails reads it and **nothing is ever skipped in CI**: `vci run` warns (`it read
config/master.key, Rails' credentials key`). Nothing is wrong (it fails open), but to get skips, do one of:

- give the test environment its own credentials with a key you commit (it guards nothing secret):
  `bin/rails credentials:edit --environment test`, then commit `config/credentials/test.key` (un-ignore it if
  `.gitignore` lists it) and `config/credentials/test.yml.enc`. Rails then reads those in the test environment
  instead of `config/master.key`;
- remove `config/master.key` and `config/credentials.yml.enc` if nothing needs them;
- or list `RAILS_MASTER_KEY` (`[env] hash = ["RAILS_MASTER_KEY"]`) and set it to the same value where you attest
  and in CI (a secret there): Rails then reads the key from the environment, not the file.

**Native libraries (FFI) and Active Storage's libvips.** Opening a library through FFI (`ffi_lib`,
`FFI::DynamicLibrary.open`) is not a read of test inputs: the collector records the library as an external,
`native:<file name>` (`native:libvips.42.dylib`), whose version is the sha256 of the file FFI resolved it to (or
`unresolved` when FFI gave no path, such as a system library in macOS's shared cache). `vci plan` compares it with
the library the booted application opens where the attestation is checked (`vci plan` boots the application for this
once per project, only when a candidate attestation records a native library), like a gem: a
different libvips build, another platform's, or none at all runs the file (with `policy.libraries = "any"` in the base
`vci.toml`, a libvips of any file name and build is accepted, as long as one is loaded: see `policy.libraries` under
"`vci.toml`" and "Attest on macOS, skip on Linux"). Finding the library (FFI's search of `LD_LIBRARY_PATH`, its
library directories) is not an input; the file it found is. A failed `ffi_lib` (an optional
library that is not installed, a `LoadError` the caller rescues) records nothing and refuses nothing. (Opening a
library also runs its initialisers, C code vci does not see; that is accepted as part of loading the library, which is
identified by its file.) What the library's C code may read is reached by **calling** it, so:

- **every call of a function attached with `attach_function`** (and `attach_variable`'s accessors, an
  `FFI::Function` called directly, a `VariadicInvoker` invoked directly, a function attached by hand with
  `Function#attach`)
  **refuses the file** (`native:FFI call Libc.getpid (C code of libc.dylib: ...)`), unless the library has explicit
  hooks. Loading a gem that attaches functions without calling them is attestable; SQLite through `ffi`, libxml
  through `ffi` or any other FFI binding stays refused as soon as it is used;
- **ruby-vips has explicit hooks** (the modules `Vips`, `GLib` and `GObject`, attached in ruby-vips' own installed
  files over libvips, GLib or GObject). libvips reads and writes files only through operations whose file names
  ruby-vips passes from Ruby, so the collector hooks `Vips::Operation.call` (which `Vips::Image.new_from_file`,
  `.thumbnail`, `.new_from_buffer`, `.new_from_source`, `#write_to_file`, `#write_to_buffer`, `#write_to_target`
  and every image method go through) and the libvips functions ruby-vips attaches:

  | What | Under vci |
  |---|---|
  | loaders and savers of a file of a single-file format: `jpeg`, `png`, `webp`, `gif`, `tiff`, `heif`, `jp2k`, `jxl`, `rad`, `ppm`, `csv`, `matrix` (`pngload`, `jpegsave`, ...), and `thumbnail` | the file is recorded: a read (an input, like any file a test reads), or a write (refused inside the repository except in the git-ignored `log/`, `tmp/`, `storage/`, `coverage/`) |
  | `vips_foreign_find_load` (the format sniffer `new_from_file` calls; it reads the file's header), `Vips::Source.new_from_file`, `Vips::Target.new_to_file` | a read / a write of that file |
  | the same formats' `_buffer`, `_source`, `_target` and `_mime` variants, `thumbnail_buffer`, `thumbnail_source`, `thumbnail_image`; memory sources and targets; custom sources and targets (their data passes through Ruby, which the collector sees) | allowed |
  | every other operation (`resize`, `crop`, `autorot`, `avg`, ...) and the libvips/GLib functions that only work on memory (`vips_init`, `vips_image_get`, `g_object_set_property`, ...) | allowed |
  | loaders and savers of other formats (PDF, SVG, ImageMagick, OpenSlide, FITS, `vipsload`, `dzsave`, ...: they may read further files), `text` (fonts), `system` | refused (`native:vips:<operation>`) |
  | an ICC profile that is a file (`icc_transform("x.icc")`, `input_profile:`, `import_profile:`, `export_profile:`, a saver's `profile=`) or a `filename`/`font` option, in arguments or an option string (`"x.jpg[...]"`) | refused; the built-in profiles `srgb`, `cmyk`, `p3` (and `none`) are fine |
  | a file loader or saver built anywhere but inside `Vips::Operation.call` for itself (`Vips::Operation.new("pngload")` then `#build`, a direct `Vips.vips_cache_operation_build`), descriptor sources and targets, a libvips function this list does not name (a newer ruby-vips attaching something new) | refused |

  An operation is classified by the nickname of the operation libvips builds for the name given: libvips finds it
  with `vips_type_find`, which compares nicknames and class names without regard to case, so `"PNGLOAD"`, `"PngLoad"`
  and `"VipsForeignLoadPngFile"` are `pngload` and `"SYSTEM"` is `system` (the collector asks libvips the same way);
  a name libvips does not resolve is refused.

  `VIPS_*` and `G_*` variables (read by libvips and GLib in C) are removed from the test processes unless
  listed in `[env]` (then hashed, or ignored).

**Active Storage** loads ruby-vips at boot whenever it is in the bundle (`image_processing`, which `rails new` adds,
depends on it). With these rules, on a machine with libvips installed:

- a test that never touches storage (a model test) is attested; libvips is an external of it;
- a test that attaches an image and analyses it (`blob.analyze`, which runs the Vips analyzer:
  `Vips::Image.new_from_file` of a copy of the blob in the process's temp dir) is attested with the image as an
  input: the fixture file is read by Ruby (`file_fixture("x.png").open`), its copies in `tmp/storage` and the temp dir
  are the process's own output, and editing the fixture runs the test. Variants (`image_processing`'s `thumbnail`,
  `#write_to_file`) are recorded the same way;
- previewers (PDF and video) run `mutool`, `pdftoppm` or `ffmpeg`, child processes: refused;
- a test that calls a C function through FFI itself is refused.

The check on an attached function replaces FFI's method in place (it is not a prepended module), so
`method(:f).super_method` cannot reach the C function past it. The collector runs inside the test process, so a test
that sets out to defeat it (calling `VciCollector.quiet`, removing its hooks, reaching FFI's internals through
`ObjectSpace`) is outside what it defends against: vci attests honest tests, it does not sandbox hostile ones (see
"Threat model").

**OpenSSL** (Ruby's `openssl` extension) reads certificates and its configuration in C. `X509::Store#add_file` and an
`SSLContext`'s `ca_file` are recorded as reads of the file named, `OpenSSL::Config.new(file)` and
`Random.load_random_file` too (a configuration with `.include` directives is refused). A store given
`set_default_paths` (as `SSLContext::DEFAULT_CERT_STORE` is when `openssl/ssl` loads) or `add_path` reads the system
CA certificates, `SSL_CERT_FILE` and `SSL_CERT_DIR` (a directory by certificate hash, on demand): verifying with such a
store (`Store#verify`, `StoreContext.new`, a TLS handshake that verifies) refuses the file, as does an `SSLContext`
with `ca_path` and loading an OpenSSL provider or engine. `OPENSSL_*` variables (`OPENSSL_CONF`, read when the library
loads) are hashed whenever present.

What is accepted by this rule (stated here so it can be judged): the libraries libvips links (GLib, libjpeg, libpng,
libheif, its loadable modules) are identified only through libvips' own file hash, so a Homebrew upgrade of libjpeg
alone does not run the tests that decoded a JPEG; and libvips' operation cache keeps an image loaded within one
process. Checked locally on macOS with Rails 8.1.3.1, image_processing 1.14.0, ruby-vips 2.3.0, ffi 1.17.4 and Homebrew
libvips 8.18 (`fixtures/rails-vips`, `rails_active_storage_with_libvips` in the e2e tests, skipped where libvips is not
installed). A runner without libvips runs every file that recorded it (Active Storage then sets `VIPS_AVAILABLE` to
false, which a test could observe), and so does a runner whose libvips is another build: to skip there, attest where
the same libvips file is installed, set `policy.libraries = "any"` (the libvips of the runner's platform is then
accepted by name), or remove `image_processing` and `ruby-vips` if the app does not process images.

### vci does not manage the database (read this)

The test database is **the test engine's business**, as it is when you run `bin/rails test` or `rspec` yourself. vci
does not redirect, create, prepare, purge or load any database. It uses the databases `config/database.yml` configures
for the test environment as they are: every entry of `test` (with `DATABASE_URL` merged in, as Rails reads it),
including each database of a multi-database app such as Rails 8's `storage/test_cache.sqlite3`. Rails gives each test
its starting state: `maintain_test_schema!` (`rails/test_help`, or rspec-rails' `rails_helper`) loads the schema when
it is not current by running `bin/rails db:test:prepare` (on a fresh checkout, this creates `db/test.sqlite3`); then
fixtures and transactional tests do the rest.

**What is an input.** What the database holds is **never an input** and is never hashed: rows written into
`db/test.sqlite3` (or into a MySQL or PostgreSQL test database) behind the tests' back, a database an earlier run left,
or no database at all change no verdict and no attestation. vci records what it can see in Ruby: `config/database.yml`,
every fixture file a test loads, and the code. The schema file of every database of the test environment
(`db/schema.rb` or `db/structure.sql`, and in a multi-database app `db/cache_schema.rb`, `db/queue_schema.rb` and the
like; none for a database with `schema_dump: false`) is an input of every test that loads Active Record, whether or not
the test process read it (on a fresh database `bin/rails db:test:prepare` reads them, not the test process): a change to
any of them runs those tests. The adapter names of the test environment are part of the toolchain (`sqlite3`, `mysql2`,
`trilogy`, `postgresql`; sorted and joined with `;` for several), compared exactly: a test that passes on SQLite may
fail on MySQL. No server version is recorded. The SQLite library version stays in `ruby libraries` (subject to
`policy.libraries`).

**What an attestation no longer promises.** Before vci 1.4.0 an attestation also meant "this test passed on a database
built from the schema and nothing else". It no longer does: **vci promises what CI promises, that the test passed on a
database the engine set up.** A test whose outcome depends on rows left behind (a test that commits outside its
transaction, `use_transactional_tests = false` without cleanup, data loaded by hand, another process writing to a
shared server) can pass where it was attested and fail on a fresh database, or the other way round, and vci will not
notice. Keep tests independent of leftover data, as you would for `bin/rails test`.

The rules:

- **The test environment's SQLite files** (every SQLite database `config/database.yml` configures for `test`) and their
  `-wal`, `-shm` and `-journal` files: no read, stat, existence check or write of them is recorded, and opening them is
  accepted, although they are inside the repository, as long as what is there is a SQLite database (a file that starts
  with SQLite's header; an absent or empty one is only exempt from existence checks, not from reads of its content).
  Any other file an entry names (`database: data/ref.yml` under an entry with `database_tasks: false`, which Rails never
  opens) is recorded like any file. A listing of the directory holding one (`Dir.children("db")`) is still an input,
  without them (they are recorded as `excluded`), so a fresh checkout, which has no database, matches. No other
  manifest entry names them.
- **The working tree**: these files are written during every run. Keep them git-ignored, as Rails generates
  (`/storage/*` in Rails 8; `/db/*.sqlite3*` for databases in `db/`): then they never make the tree dirty and are never
  a written or modified input. A committed test database, or an untracked one that is not ignored, makes the working
  tree dirty.
- **An in-memory test database** in `database.yml` (`database: ":memory:"`) is accepted: there is nothing to hash. Only
  `:memory:` (plain or as a `file:` URI's path) and a `file:` URI whose `mode` parameter is `memory` are in memory, as
  SQLite reads them; any other name opens a file (`file::memory:x` is a file named `:memory:x`, and a name that merely
  contains `mode=memory` is a file too).
- **Database servers** (`mysql2`, `trilogy`, `postgresql`) configured for the test environment are accepted with no
  policy: Active Record's own connections are the engine's when they reach one of the test environment's databases
  (the same host, address, port, socket and database as an entry of `config/database.yml` for `test`, with
  `DATABASE_URL` merged in as Rails read it at boot). Active Record connecting anywhere else is refused like a socket:
  `establish_connection` to another host, port or database (another environment's, the server's `mysql` database), a
  raw client made through an adapter's `new_client`, or a `DATABASE_URL` the test changes.
- **Still refused**: a SQLite file that is not one of the test environment's configured databases
  (`SQLite3::Database.new("db/other.sqlite3")`, `establish_connection` to another file, a `DATABASE_URL` naming another
  file, another environment's database: `rails:sqlite-file:<path>`), `ATTACH`, SQLite extensions (SQLite reads and
  writes those files in C, where vci cannot see them; an in-memory database or a file in vci's temp dir a test opens for
  itself is fine), and any database client a test opens itself (`PG.connect`, `Mysql2::Client.new`, `Trilogy.new`:
  `network:<adapter> client`; Redis, anything over a socket).
- **Child processes**: the one Active Record's schema maintenance starts (`ActiveRecord::Migration.load_schema!` in the
  bundle's activerecord gem, which `rails/test_help` and rspec-rails' `maintain_test_schema!` call, running exactly
  `bin/rails db:test:prepare` from the project dir) is the engine's and is not refused: it runs with
  `VCI_RAILS_MODE=engine`, in which the collector records nothing, and its only effect is the database's state. Every
  other child process a test starts is refused, including the same command run by the test itself.
- **One file at a time, or one slot's database each**: the files of a project share the database, as in `bin/rails
  test`, so `vci run` runs them one after another, unless the project runs Rails' parallel workers (or
  `VCI_RAILS_JOBS` asks): then each slot has a database of its own, as each worker has (see "Slots" above;
  `PARALLEL_WORKERS=1` as always inside each process). `vci ci` runs the remaining files of a
  project the engine's own way, in one `bin/rails test <files> --seed 0` (or `rspec --options .rspec <files>`) process
  per runner: the files share one process and one order, so a file that passes only on its own can fail there, the
  verdict a plain `bin/rails test` gives. `vci ci --key` runs each file it attests on its own, as `vci run` does.

**MySQL and PostgreSQL need nothing but the normal test database**: no policy and no vci setting. Run the same adapter
where you attest and in CI (a service container; see [`docs/GITHUB_ACTIONS.md`](GITHUB_ACTIONS.md)), and create the
test database before the tests as any Rails CI job does (`bin/rails db:test:prepare`; SQLite needs no step, the engine
creates the file). The server's version and configuration are not compared. `config/database.yml` is an input, and so
is `DATABASE_URL` (built-in hash: it reaches the tests and is hashed whenever present): name the same host, port and
database on both sides, and put a password `database.yml` reads from the environment in `[env] ignore`.

**Collector 0.5.0.** The collector's version is part of the toolchain, and vci 1.4.0 changes it (0.4.2 to 0.5.0): every
Rails and RSpec attestation made with an earlier vci runs once more in CI, and is skipped again once attested anew.

`policy.rails_allow_db` was **removed in vci 1.4.0**. It is a deprecated no-op kept for compatibility: a `vci.toml`
that still sets it (top level or in a project's `policy`) parses, so a base commit that has it does not make every file
run; it has no effect, and `vci run` and `vci plan` print one warning (`vci: warning: policy.rails_allow_db in vci.toml
is ignored: rails_allow_db was removed in vci 1.4.0 (...). Remove it from vci.toml`; `vci plan` names `vci.toml at the
base commit`). An attestation made under it (its `waived` lists `rails:network-db:`) is not accepted
(`policy.rails_allow_db was removed in vci 1.4.0: attest the file again`).
### Attesting on macOS, verifying on Linux (Rails)

Under `platform = "any"` a file attested on macOS arm64 is skipped on an ubuntu-latest x86_64 runner when:

- **Ruby is the same release and patchlevel** (pin it in `.ruby-version` and `ruby/setup-ruby`), and so are Rails,
  Bundler (the lockfile's `BUNDLED WITH`, which `setup-ruby` installs), Minitest, and every gem version of the bundle;
- **`Gemfile.lock` lists both platforms** (`arm64-darwin`, `x86_64-linux`): native gems such as `nokogiri` and
  `sqlite3` are then installed from their precompiled builds for each platform. vci matches a gem by name and version,
  not platform: **the macOS and Linux builds of one version are accepted as the same gem** (their contents differ;
  this is what `platform = "any"` accepts, as for the Python interpreter of the pytest adapter). The SQLite library
  those builds bundle is compared (the `sqlite3` gem 2.9.6 bundles SQLite 3.53.2 in both), and so is libyaml (unless
  `policy.libraries = "any"`: see "Attest on macOS, skip on Linux" below). Gems
  compiled at install time (`bigdecimal`, `json`, `racc`, ...) are matched by version; the compiler and system
  headers are not compared. Use `"same-os"` or `"exact"` (or `platform_overrides`) where a native gem's platform
  build matters;
- **time zone data comes from the `tzinfo-data` gem** (`gem "tzinfo-data"` for every platform, not the generator's
  `platforms: %i[ windows jruby ]`): without it Rails reads the system's zoneinfo, whose version is compared (macOS
  and Ubuntu rarely ship the same one), and nothing is skipped across them (under `policy.libraries = "any"` the
  version is not compared, but the zone rules then are those of each machine). `TZ` is set in vci.toml
  (`[env] set = { TZ = "UTC" }`, vci applies it on both sides): Ruby's local time zone otherwise comes from the machine (`/etc/localtime`, which
  is not an input);
- **`CI` is the same on both sides**: the generator writes `config.eager_load = ENV["CI"].present?` in
  `config/environments/test.rb`, which makes every test depend on `CI`. Since vci 1.6.0 `CI` is removed from the test
  processes unless vci.toml lists it, so it is unset on both sides and this is fine; listing it in `[env] hash` would
  make nothing skip on a runner (unset on a laptop, `true` there). `[env] set = { CI = "true" }` gives both sides
  eager loading, which loads every application file in every test process (each becomes an input of every test), so
  leave `CI` out;
- **`vendor/` exists in the repository** (`vendor/.keep`, which `rails new` creates): `ruby/setup-ruby`'s
  `bundler-cache` installs gems into `vendor/bundle`, and Rails checks whether `vendor` exists; with it committed only
  its type is recorded. A bundle installed inside the repository this way (`BUNDLE_PATH=vendor/bundle`) is handled
  like any other bundle: nothing under `vendor/bundle` is an input, the gems there are externals by version, and
  RubyGems' and Bundler's own bookkeeping there (checks of its directories, the listing and the `.gemspec`s of its
  `specifications/`) is not recorded, nor are the checks `realpath` makes of each directory above a gem of the bundle
  when a gem resolves its own root (`Rails::Engine.find_root`). Collector 0.4.1 refused every file there with
  `ruby:read-outside-bundle:stat .../vendor/bundle/ruby/3.4.0`; 0.4.2 attests them, and its new version fails the
  `toolchain` check of every older Rails and RSpec attestation, so CI runs each file once more. Still refused,
  wherever the bundle is installed: loading code from, reading, listing or evaluating a file there that belongs to no
  gem of the bundle (another gem, another Ruby's `vendor/bundle/ruby/<abi>`: `ruby:gem-outside-bundle`,
  `ruby:read-outside-bundle`), also through RubyGems' and Bundler's helpers (`Gem.read_binary`, `Bundler.read_file`,
  `Gem::Util.glob_files_in_dir`, `Gem::Specification.load`), and a test's own check of where gems are installed
  (`File.directory?("vendor/bundle")`, `File.realpath` of a gem's directory), which no input records;
- the default external encoding is the same (`LANG=C.UTF-8` on runners, a UTF-8 locale on a Mac), and the tests do
  not read variables whose values differ (`HOME`, `CI`, `USER`, ...);
- **the tests do not read `config/master.key`**, which a generated app's Active Record reads at boot (see
  "Credentials" above: commit test-environment credentials, or drop the credentials, or declare `RAILS_MASTER_KEY`);
- **`config/boot.rb` does not call `Bootsnap.setup(...)` with a compile cache** (the generator's `require
  "bootsnap/setup"` is fine: it honours `DISABLE_BOOTSNAP`).

Checked locally (not on a GitHub runner): `fixtures/rails-abcd` attested on macOS arm64 (mise Ruby 3.4.9) was
skipped entirely by the static Linux `vci` in a `linux/amd64` `ruby:3.4.9` container (as a non-root user, gems
installed into `vendor/bundle` like `bundler-cache` does); editing the view template there ran only the file that
renders it, and another `TZ` ran everything. The same holds for `fixtures/rails-rspec-abcd`'s spec files, and `vci
ci` there ran the remaining spec files with RSpec (a `~/.rspec` in the container changed nothing).

**OpenSSL is not compared**: Ruby links the platform's OpenSSL (Homebrew's 3.6 on a Mac, a 3.0 or 3.5 build on Linux),
so comparing it would rule out every cross-platform skip. Algorithms give the same results across these versions; what
differs (which legacy ciphers exist, default security levels) is accepted under `platform = "any"`.

### Attest on macOS, skip on Linux (`libraries = "any"`)

Even with everything above in place, two things bind a file to the platform it was attested on: a native library
opened through FFI is recorded by file name and hash (`native:libvips.42.dylib` from Homebrew on a Mac,
`native:libvips.so.42` from apt on the runner), and the versions of the SQLite library, libyaml and the time zone data
are compared (`ruby libraries`), which Homebrew and apt build differently. A file that loaded libvips (every file that
boots an app with Active Storage and `image_processing`) then runs on every runner. To skip it there, set in the base
`vci.toml`:

```toml
[policy]
platform = "any"
libraries = "any"   # native libraries by name, library versions not compared
```

and install the library on the runner too (`sudo apt-get install -y libvips-dev` pulls it in): under `"any"` libvips
is matched by library name, but one must still be loaded where CI checks (otherwise `native library libvips:
not loaded here (looked for a native library named libvips, policy.libraries = "any")`). The same key lets a pytest
file through when the SQLite or OpenSSL of the interpreter differs (`python libraries`). Nothing changes in what `vci
run` records, so attestations already made are accepted once the key is on the base branch.

**Still compared, exactly:** the Ruby release and patchlevel (pin it in `.ruby-version`, used by mise locally and by
`ruby/setup-ruby` in CI), Rails, Bundler, the test frameworks and every gem of the bundle (through `Gemfile.lock`, with
both platforms listed), the default encodings, the collector version, the database adapters, root or not; every input
file; the hashed environment variables (`TZ`, which vci sets) and the `[env]` configuration. For pytest: the Python version and
implementation, pytest and the installed distributions. Whether each library is loaded at all is compared too: a
Python without `_sqlite3`, or a Ruby process that loaded no SQLite where the attestation did, runs the file.

**What you state by setting it:** that the library's behaviour is the same on both platforms for these tests, so a
test that passed with Homebrew's libvips (or SQLite, libyaml, time zone data, OpenSSL) on a Mac would pass with the
runner's build. vci does not check that; it shows what it accepted (`vci explain` prints `policy: libraries = "any"
(base vci.toml): ...` and, under each candidate, `accepted by policy.libraries = "any": ...` for every difference let
through), and the full run on the default branch (`no_skip_refs`) is where a difference would show. Keep the files
where it does not hold (pixel-exact image comparisons, SQL that depends on the SQLite version, zone rules of a recent
change) on `"exact"`:

```toml
[[policy.platform_overrides]]
match = ["test/images/**"]
libraries = "exact"
```

## Quick start (RSpec)

RSpec runs under the Rails adapter (`adapter = "rails"`), with the same collector, run conditions and checks as
Minitest files (everything in [Quick start (Rails)](#quick-start-rails) applies) plus what this section adds. Tested
with rspec-core 3.13.6, rspec-expectations 3.13.5, rspec-mocks 3.13.8, rspec-rails 8.0.4, factory_bot_rails 6.5.1,
Rails 8.1.3.1 and Ruby 3.4.9 through mise; the fixture is `fixtures/rails-rspec-abcd`.

```sh
cd your-app                                    # Gemfile.lock has rspec-core (through rspec-rails), and spec/;
                                               # a git repo with an origin remote
bundle lock --add-platform x86_64-linux
vci init --adapter rails --key ~/.ssh/id_ed25519.pub   # writes vci.toml (adapter = "rails"; runner is detected)
git add vci.toml .vci/allowed_signers .git-meta Gemfile.lock && git commit -m "Enable vci"
# .git-meta is written only with an origin remote (or --meta-url <url>); without one, leave it out of `git add`.
# The trust root is read from the base branch: push or merge this commit to main first.

vci run spec/models/b_spec.rb --key ~/.ssh/id_ed25519   # one RSpec process per spec file
vci plan --base-ref origin/main                          # SKIP spec/models/b_spec.rb, RUN the rest
vci push
```

**A stock `rails new` app with rspec-rails** needs these edits before anything is skipped (all but the pending specs
apply to Minitest too; each is explained under [Quick start (Rails)](#quick-start-rails)):

- replace the generator's `pending "add some examples to (or delete) ..."` specs with real examples (or delete them):
  a pending example refuses its file;
- `CI` left out of `[env]` (removed, it is unset on both sides, so the generator's `config.eager_load =
  ENV["CI"].present?` is false everywhere), or `config.eager_load = false` in `config/environments/test.rb`;
- credentials: commit test-environment credentials and their key, drop `config/master.key` and
  `config/credentials.yml.enc`, or declare `RAILS_MASTER_KEY` (otherwise every file reads `config/master.key`);
- `gem "tzinfo-data"` for every platform (not `platforms: %i[ windows jruby ]`), and `TZ` set (`[env] set = { TZ = "UTC" }`);
- `image_processing` on a machine with libvips installed: attested, with libvips recorded by its file hash (see
  "Native libraries (FFI) and Active Storage's libvips" under the Rails section), so CI skips only where the same
  libvips file is installed, or any libvips under `policy.libraries = "any"` (see "Attest on macOS, skip on Linux");
- `vendor/.keep` committed (the generator creates it).

Nothing is needed for the database: the generator's `config/database.yml` (`storage/test.sqlite3`) and `.gitignore`
(`/storage/*`) are what vci expects, and Rails creates the test database on the first run.

Capybara in the `:test` group is fine: `rack_test` feature specs are attested; specs that drive a browser are refused.

**Which runner.** `runner = "minitest"` or `runner = "rspec"` in `vci.toml` (top level next to `adapter`, or in the
project's `[[projects]]` entry; like all policy, `vci plan` reads it from the base commit). Without it vci detects:

| The project has | Runner |
|---|---|
| `rspec-core` in `Gemfile.lock` (rspec-rails brings it), a `spec/` directory (or `.rspec`), no `test/**/*_test.rb` | RSpec |
| both that and Minitest files | both: a file under the Minitest rule (`test/**/*_test.rb`, not `test/system`, ...) runs with `bin/rails test`, every other file RSpec lists runs with RSpec. If RSpec's own pattern also lists a Minitest file, the project's files are not listed (`vci plan` runs everything, `vci ci` fails) until `runner` decides |
| anything else | Minitest (as before; RSpec files are reported, and a project with only RSpec files and no `rspec-core` in the lockfile is an error) |

With `runner` set while the project also has the other runner's files, those files are **not run by vci at all**
(neither `vci run` nor `vci ci`, broken or not): `vci run`, `vci plan` and `vci ci` print a warning (`N Minitest
file(s) in test/ are not run by vci`), and `vci ci` records it under `warnings` in the audit log. Run them some other
way in CI, or remove the setting so each file runs with its own runner.

The runner of a file is part of its attestation: its argv (`rails rspec --root . --options .rspec --default-seed 0
spec/models/b_spec.rb`) and the toolchain's test framework field (`minitest 6.0.6; rspec-core 3.13.6, rspec-expectations
3.13.5, rspec-mocks 3.13.8, rspec-rails 8.0.4, rspec-support 3.13.7`) are compared by `vci plan`. The RSpec gems are
also part of the bundle, which is compared exactly, and are externals of every spec that loaded them: bumping
`rspec-core` in `Gemfile.lock` runs everything.

**What vci runs.** The unit is a spec file: the files `rspec` with no argument would run, **as RSpec's own
configuration lists them** (`default_path`, `pattern`, `exclude_pattern` from `.rspec` and `SPEC_OPTS`; a custom
pattern is honoured). Shared examples, support files and factories are not units. Every file runs in its own process,
one at a time (they share the test database):

```
RUBYOPT=-r<abs>/ruby/vci-collector/vci_collector.rb VCI_RAILS_RUNNER=rspec VCI_RAILS_MODE=collect ... \
  ruby -e 'require "bundler/setup"; require "rspec/core"; $0 = "rspec"; RSpec::Core::Runner.invoke' \
  -- --options .rspec spec/models/b_spec.rb
```

(what `bundle exec rspec` does, without a `bin/rspec` binstub or Spring, which stay disabled). `vci ci` runs the
remaining files in one `rspec ... <files>` process (`VCI_RAILS_MODE=plain`) and exits non-zero if any fails; with
nothing attestable at all (`no_skip_refs`, an unreadable base policy) it runs the whole suite in one `rspec` process.

**Option sources.** RSpec reads options from several places; each one is either an input or never read, on both
sides:

| Source | Under vci |
|---|---|
| `.rspec` in the project | read (vci passes `--options .rspec`), and a **global input** of every spec file: any edit runs everything |
| `~/.rspec`, `$XDG_CONFIG_HOME/rspec/options` (`~/.config/rspec/options`) | **never read**: `--options` replaces every options file, so the laptop's and the runner's are both ignored (nothing to configure in CI) |
| `.rspec-local` | **never read**, for the same reason: it is usually git-ignored, so CI could not have the same one. Put options vci should use in `.rspec` |
| `SPEC_OPTS` | the env policy: removed unless listed (`[env] hash = ["SPEC_OPTS"]`, then its value must match; or `set`) |
| the command line | vci's: `--options .rspec <file>` and nothing else |

A plain `bundle exec rspec` still reads all of them; only vci's runs do not.

**Run conditions** (installed by the collector in `vci run` and `vci ci` alike):

- **the seed**: RSpec's default seed is random; under vci it is 0, so `config.order = :random` and `Kernel.srand
  config.seed` give the same order where the file was attested and in CI (the counterpart of Minitest's `--seed 0`).
  Defined order stays defined; a seed you set (`--seed` in `.rspec` or `SPEC_OPTS`, `config.seed =`) is used and is
  an input like the rest of the file;
- **the example status file** (`config.example_status_persistence_file_path`, typically `spec/examples.txt`): RSpec
  reads it at start (for `--only-failures`, `--next-failure` and `example.metadata[:last_run_status]`) and rewrites it
  at exit. vci points it at a fresh file in the process's temp dir: nothing is written in the repository and no earlier
  run's statuses are read, so `--only-failures` runs nothing (refused) and `last_run_status` is always `"unknown"`;
- **the database**: as for Minitest, the test environment's configured database is used as it is:
  `rails_helper`'s `ActiveRecord::Migration.maintain_test_schema!` loads the schema when it is not current (through
  `bin/rails db:test:prepare`, Active Record's child process, which is not refused), and a pending migration makes it
  abort (the file is refused as a failure). `config.use_transactional_fixtures` works as usual. Its contents are not an
  input (see [vci does not manage the database](#vci-does-not-manage-the-database-read-this));
- **SimpleCov**: in an RSpec process its results (and the earlier results it would merge, `.last_run.json`) are
  written to the process's temp dir instead of `coverage/`, and its configuration files outside the repository
  (`~/.simplecov`, `.simplecov` in directories above the repository, which its upward search would try) look absent.
  A `.simplecov` in the project is read (an input). So a coverage run of your own is not affected, and vci's runs
  neither leave reports nor read old ones. `SimpleCov.minimum_coverage` is checked per file: a file whose own run is
  below it exits 2 and is refused (`vci:process-exit:2`, see "Results"). (Minitest processes keep SimpleCov's own
  directory: writes to the git-ignored `coverage/` are allowed there.)

**What is recorded** for a spec file, on top of the Rails list: `.rspec` (global), `spec/spec_helper.rb` and
`spec/rails_helper.rb` when loaded (with their `require`/`require_relative` lookups); the **listing** of every
directory `rails_helper`'s `Rails.root.glob("spec/support/**/*.rb")` reads and every file it loads (a new support file
runs every spec that loads `rails_helper`, not those that only load `spec_helper`); shared examples, shared contexts and
custom matchers as the files that define them; FactoryBot's definitions (factory_bot_rails loads them at boot by
scanning `spec/factories`, `test/factories` and `factories`: those listings and files are inputs of every spec that
boots Rails, so a new factory file runs them); fixtures (`config.fixture_paths`, `fixtures :all` lists the directory);
files read through `file_fixture`; templates rendered by view and request specs. rspec-rails 8 globs
`spec/**/*_spec.rb` at boot to register `bin/rails stats` directories: that listing is **not** an input (otherwise every
new spec file would run every spec that boots Rails); a spec that reads `Rails::CodeStatistics`' directories is
refused instead.

**Results.** A reporter hook (independent of your formatters) counts the examples. A file is attested only when
the **process** exits 0, at least one example ran, none failed, none is pending or skipped (`pending`, `skip`, `xit`,
`xdescribe`, `skip: true`), no error happened outside an example (a load error, an error in `before(:suite)`,
`after(:suite)` or `after(:context)`), and **every example the file declares ran**: a run filtered by
`filter_run_when_matching :focus` with `fit`/`fdescribe`, by a tag filter (`--tag`, `filter_run`,
`filter_run_excluding`), by `--only-failures` or `--example`, or stopped by `--fail-fast`, is refused (`rspec:filtered`).
A failing `aggregate_failures` block is one failed example. Unlike Minitest, an example without expectations passes
(RSpec does not count expectations; vci does not either).

The exit code is checked after every `at_exit` handler ran, not only RSpec's: SimpleCov's `minimum_coverage` check
(exit 2), `minitest/autorun` loaded into the RSpec process (its handler rejects RSpec's arguments and exits 1), or a
test's own `at_exit { exit 1 }` fail a plain `rspec` run, so they refuse the file (`vci:process-exit:N`), however
cleanly RSpec reported. Every example's failure is tracked where RSpec records it (`Example#set_exception`): one that
is cleared before the example finishes and then reported as passed is refused (`rspec:failure-cleared`): a home-grown
retry (an `around` hook that clears `@exception` and runs the example again, which is also how rspec-retry works; the
gem itself was not tried), a prepended `Example#finish` that drops the exception, and a reporter override that reports
a failure as a pass. The reporter's counts are also checked against RSpec's per-example statuses
(`rspec:status-mismatch`). Support code that swallows a failure before RSpec records it (rescuing it inside the
example, or prepending over `Example#set_exception` itself) is not detected; a plain `rspec` run passes too.

**Refused** (on top of the Rails refusals: child processes, sockets, writes, ...):

- `--bisect`, `--drb`, `--init`, `--version`, `--help` (from `.rspec` or `SPEC_OPTS`; `rspec:invocation`), `--dry-run`
  (`rspec:dry-run`), a run without vci's `--options` (`rspec:option-files`);
- **rspec-retry** (and rspec-rebound) loaded: a flaky example that failed and then passed is reported as passed
  (`rspec:retry`); a retry without those gems is caught by the failure that was cleared (`rspec:failure-cleared`,
  above);
- **parallel_tests / turbo_tests** loaded (`rspec:parallel-tests`; vci runs one file per process itself). Loading them
  through `Bundler.require` counts: use `require: false` in the Gemfile;
- **Spring** (`spring-commands-rspec`, a `bin/rspec` binstub): vci never runs binstubs and sets `DISABLE_SPRING=1`; Spring
  loaded anyway is refused;
- **system and feature specs that drive a browser** (Capybara with Selenium or Cuprite): the browser and its driver are
  child processes and sockets, refused like Minitest system tests. Unlike Minitest's `test/system`, RSpec's
  `spec/system` and `spec/features` files are listed (RSpec runs them); a feature spec on Capybara's `rack_test`
  driver that opens no socket and starts no process is attested like any other spec (checked locally, not in the e2e
  tests: a stock `rails new` app with capybara 3.40.0 and selenium-webdriver 4.50.0 in its `:test` group, a model
  spec and a `type: :feature` spec visiting `/up` were both attested and then skipped). With Capybara in the bundle
  rspec-rails requires `capybara/rspec` at boot, which loads `net/http` and Ruby's `resolv`; `resolv` reads
  `/etc/resolv.conf` while it loads. That one read is not an input (the DNS settings only matter to lookups, which
  open sockets and are refused); a test that reads the file itself (`Resolv::DNS::Config`) still refuses;
- Minitest tests that also ran in the RSpec process (`rspec:minitest-also-ran`).

**Mocks and time helpers.** rspec-mocks needs nothing special: `allow(File).to receive(:read)` (or `ENV`'s `[]`,
`Kernel.require`, `File.exist?`, `File.directory?`, `Dir.children`, `File.expand_path`) changes what the spec sees, not
what vci records. A stubbed call that returns a canned value reads nothing; `and_call_original` reaches vci's hooks;
real reads elsewhere in the process (through `File.open`, an unstubbed key, a `Dir.glob`) are recorded; and the
collector's own file system checks use the methods captured before anything could stub them (a stubbed
`File.directory?` would otherwise hide a real glob's listing). `travel_to` and other time helpers do not affect
recording. (The e2e tests prove each of these with a changed input that then runs the spec.)

**Plain Ruby projects.** The same code path works without Rails: a project with a `Gemfile`, `Gemfile.lock` (with
`rspec-core`) and `spec/`, but no `config/environment.rb`, is a plain Ruby project. `adapter = "rails"` (the name is
historical) with `runner = "rspec"` or detection; the probe only sets up the bundle, the Rails version is empty, and
everything else (the bundle as toolchain, option sources, results, refusals) is the same. Tested with a small project
of `rspec-core` and `rspec-expectations` (`rspec_plain_ruby_project` in the e2e tests).

**RSpec limitations** (on top of the Rails ones):

- `.rspec-local`, `~/.rspec` and the XDG options file are ignored under vci, so a `vci run` can differ from your plain
  `rspec` run (fail open: a spec that needs them fails under vci and is not attested);
- every example must run: a deliberately excluded tag (`filter_run_excluding :slow`) refuses every file with such an
  example. Run those files without vci, or move the examples;
- `rails_helper`'s support glob and FactoryBot's definitions are loaded by every spec that boots Rails, so editing any
  support file or factory runs all of them; whether a spec actually used a factory or shared example is not modelled;
- an example's expectations are not counted (see "Results"): `it("does nothing") { }` is attested. It passes in
  every run, so this is not a wrong skip, but it vouches for nothing (Minitest refuses a test with no assertion);
- **per-file isolation**: one spec file per process, as in CI; a spec that passes only after another file ran first
  (in a full `rspec` run) is not reproduced; neither is the random seed of a plain run;
- SimpleCov's reports from vci processes are not kept (they live in the process's temp dir); collect coverage with a
  plain `rspec` run.

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
| `vci init [--key K] [--principal P] [--project DIR] [--adapter vitest\|pytest\|go\|cargo\|rails\|node-test] [--no-install] [--meta-url URL] [--oidc]` | Write `vci.toml`, `.vci/allowed_signers` (adding key `K`) and `.git-meta` (`url:` the metadata remote, default origin's URL), configure the git-meta remote, `npm install` `@vci/vitest` (Vitest; node-test prints the test command it read instead), print a CI snippet. `--oidc` (since 2.0) also writes `.vci/identities.toml`, trusting pushes to origin's default branch by the repository's workflow (its only file under `.github/workflows`, else `*`, to narrow) as principal `github-actions` (an existing file is left alone), and `.vci/sigstore-trusted-root.json` from `gh attestation trusted-root` (refreshed each time; without `gh`, a note says to write it): see [Keyless signing (OIDC)](#keyless-signing-oidc) |
| `vci run [FILES…] [--key PATH \| --oidc[=github\|public-good]] [--ttl 14d] [--summary FILE]` | Run tests with collection on; sign and store an attestation for every attestable file (Go: package directory; Cargo: `<package dir>#<target>` unit, or a package directory for all its units). Exit code is the runner's (non-zero if any pytest, `go test`, `cargo test`, `bin/rails test` or `rspec` process failed). Prints one line per unit not attested and a count of files per reason (see below); `--summary FILE` writes every unit with its reasons as JSON. Since 1.9.0 each distinct input manifest is stored once, as its own value (`vci:manifest:<input root>`), and the attestation references it; storing an attestation deletes the same signer's attestations of that unit it supersedes (an earlier commit of this line of history, other files: see "Where attestations live (git-meta)"), printing `vci: removed N superseded attestation(s) ...` and how many manifests nothing references any more (since 2.0 it first fetches, in one batch, the stored attestations of those units that were not fetched yet; one that cannot be fetched is kept). `--oidc` (since 2.0; GitHub Actions with `permissions: id-token: write`) signs keylessly with the job's OIDC token instead of a key, through GitHub's Sigstore instance or, with `--oidc=public-good`, sigstore.dev's; the instance needs the `=` (`vci run --oidc a_test.go` runs `a_test.go`). See [Keyless signing (OIDC)](#keyless-signing-oidc). Since 2.1, once a project's tests have finished, its units are checked and signed in parallel (`$VCI_JOBS` at a time, default one per CPU; `ssh-keygen` processes, or keyless signatures, several at once), and each path of the checkout is read once for the whole run (its contents hash, a directory's children, git's answer to whether it is ignored), since the tree no longer changes (each unit still compares its inputs with the snapshot taken before the tests ran); the lines, `--summary` and the exit code are as before, in the units' order, and the store is written one unit at a time in that order. Since 2.1.3 the units are handed to the runner longest first, by the duration their newest stored attestation records (units without one first, in the listing's order), so that a runner that takes several at once does not end on its longest file; the lines, summary and store keep the listing's order. The attestations a new one supersedes are found in parallel too, and removed as it is stored. `VCI_TIMING=1` prints `read the last duration of N unit(s)`, `check, sign and store N unit(s) of P (J at a time)` and the thread-seconds of each part |
| `vci plan [--base-ref R] [--format text\|json\|github] [--fetch [R]] [--project NAME]...` | Print which test files can be skipped and why the others run. `--fetch` first fetches attestations as `vci fetch [--remote R]` does, while the projects are probed; a failed fetch is a warning (stderr; a `::warning title=vci::` line unless the format is `json`) and the plan uses what is stored locally. `--project NAME` (repeatable) plans only those `[[projects]]` entries (by `name`, as the base commit's vci.toml names them): the other projects are not listed, probed or verified (their toolchains need not be installed) and are absent from the output. An unknown name is an error (exit 2) naming the configured projects; the single-project form has no names, so `--project` is an error there. Since 2.1 files are verified in parallel (`$VCI_JOBS` threads, default one per CPU), each file's candidates newest first, and each path of the checkout is read once per plan (see [Verification](#verification-vci-plan), "Cost") |
| `vci ci [--base-ref R] [--audit-log PATH] [--fetch [R]] [--project NAME]... [--partition I/N] [--key PATH \| --oidc[=INSTANCE] [--ttl 14d] [--push [--remote R]]]` | `--fetch` as for `vci plan` (a failed fetch is also in the audit log's `warnings`). `--project` as for `vci plan`: only those projects are planned, run (and with `--key` attested), and only they appear in the printed plan and in the audit log's `projects`, `skipped` and `ran`; one CI job per suite (`vci ci --fetch origin --base-ref "$BASE" --project web`). `--partition I/N` (since 2.0; `1 <= I <= N`, anything else is a usage error, exit 2) splits a suite over N jobs: of the units the plan runs (for a project that runs everything, every unit it lists), this job runs only those in partition I. Since 2.4, a project whose units are all files is split by size: every unit it lists, skipped or not, largest file first, goes to the partition with the fewest bytes so far (ties: the lowest partition, then the smaller test id), so the jobs get about the same amount of tests (a file's size stands for how long it takes; vex's two Rails jobs had 2,762 and 3,231 s of tests split by test id, 3,047 and 2,946 s by size). Any other project (a unit that is not a file, such as a cargo unit), and every project with `VCI_PARTITION_BY=hash`, is split by test id: the first 8 bytes of the unit's storage key, BLAKE3 of the test id, big-endian, modulo N, plus one. Either way the split depends only on the checkout, never on what the plan skips or on the order or the other jobs, so every unit runs in exactly one partition, and a job run again after the others pushed agrees with them. What the plan skips is skipped in every partition. A project that runs everything and whose units cannot be listed runs whole in every partition that cannot list it, with a `::warning` (each job lists on its own and cannot know whether another listed it, so such a project may run in more than one job, never in none); without any readable project every partition runs the default project. After the plan it prints `partition 2/3: 41 of 120 units to run`; the exit code is this partition's tests'; the audit log's `ran` holds this partition's units and `partition` is `{index, count, units, total, unlisted}` (`units`: this partition's, `total`: all partitions', `unlisted`: projects this partition runs whole because it could not list them), `null` without the flag. With `--key --push` each job attests and publishes its own share (concurrent pushes merge and retry), so the next plan skips every partition's units: `vci ci --fetch origin --base-ref "$BASE" --project rust --partition ${{ matrix.part }}/3 --key ci-key --push --remote origin`. `--partition 1/1` runs what `vci ci` without it runs. Plan, run the remainder, write a JSON audit log of every skip. With `--key`, the remainder runs as `vci run --key` runs it (collectors on, inputs recorded, an attestation signed and stored for every unit that passed and is attestable; a unit that refuses still runs, and only test failures make the exit code non-zero); when the plan runs everything (`policy.no_skip_refs`, an unreadable base policy), every unit is attested: the run the next commit's plan reuses. `--push` then publishes as `vci push --remote R` does, whatever the tests did; a failed push prints a `::warning title=vci::` line and does not change the exit code. When a project cannot be listed or run with the collectors, the others are still run and attested and that project alone runs without attesting (a `::warning`); nothing that ran is run again, and the exit code is every test's. When nothing can be attested (the key cannot be read, the run cannot be prepared) everything runs without attesting. `--key` attests nothing (a `::warning`; the tests still run, nothing is pushed) when its principal is in `policy.no_skip_refs_except` and the current ref does not match `policy.no_skip_refs` (or the base `allowed_signers` cannot be read there): such a run, e.g. a pull request's, would let main skip code only it ran; give other refs a key outside that list, or name the principal in `policy.attest_on_any_ref` (since 1.9.2) to let pull requests attest with it on purpose. `--oidc[=INSTANCE]` (since 2.0) attests as `--key` does, keylessly as `vci run --oidc` signs, and refuses on the same terms with the principals of the base `.vci/identities.toml` entries the job's identity matches (or when that file cannot be read there); a job without a token (no `permissions: id-token: write`) fails before anything runs, and an identity that matches no entry attests with a `::warning` that nothing will trust it. `--key` and `--oidc` exclude each other; `--ttl` and `--push` need one of them. The audit log lists `attested` units, `attestErrors` (units or projects that could not be attested or run with the collectors), `notAttested` (why nothing was attested, or `null`) and `pushed` (`true`, `false`, or `null` without `--push` or when nothing was attested on purpose) |
| `vci verify <envelope\|-> [--allowed-signers F] [--identities F --trusted-root F] [--base-ref R] [--manifest FILE]` | Verify one DSSE envelope against `.vci/allowed_signers` (SSH-signed) or `.vci/identities.toml` and `.vci/sigstore-trusted-root.json` (keyless) at `--base-ref` or HEAD, or against the files given: once any trust file is given, an envelope whose kind needs one that was not is INVALID (the repository's files are then not used). It prints its claims, including the input manifest: inline (before 1.9.0) or the one it references, read from `--manifest FILE` (its compact encoding, as `git meta get project vci:manifest:<root>` prints it) or else from the git-meta store of the repository it runs in (since 2.0 fetched from the metadata remote when it was not fetched yet); its root must be the signed input root (exit 1 otherwise, or when it is not available). A keyless envelope prints the identity, the principal it matched, the timestamp authority and the run URL |
| `vci push [--rewrite-history]` / `vci fetch` `[--remote R]` | git-meta push / pull of `refs/meta/main` (git-meta's merge; push retried as a single fast-forward commit when the remote moved; `vci push` says `nothing to push` when nothing was sent). `R`: a git-meta remote, or a git remote or URL to use as one; default: the configured git-meta remote, else `.git-meta`'s `url:`, else origin. `--rewrite-history` (since 1.8.2) publishes the metadata as one commit without parents (with a lease on the tip just fetched): what a fetch downloads is then the attestations the tree holds, not every version ever published; other clones merge onto it at their next fetch. Use it after `vci prune`, whose deletions otherwise leave the deleted values in the history. Since 1.9.0 a fetched tip that the local metadata commit is an ancestor of is merged by applying only the tree entries that changed; since 2.0 a fetch downloads keys, not values (blobless; values are fetched when a plan, verify, run or prune reads them), and every merge is done from the trees' paths (`VCI_TIMING=1` prints `materialize (from paths, N changed entries, M not fetched)` or `materialize (full)`); and every merge puts back the input manifests an attestation in the store still references that a prune or supersession elsewhere deleted (`put back N input manifest(s) ...`; the next push publishes them). See "What `vci fetch` and `vci push` guard against". Since 2.1.3 `VCI_TIMING=1` prints a push's parts: fetch and materialize the remote's metadata, check what the push would delete and what it sends, put the local metadata on top of the remote's, `git push`. Since 2.1.11 the values a plan or run reads are fetched by several `git fetch` processes at once, `VCI_FETCH_JOBS` of them (default 4; `1` fetches one batch after the other): a plan's 16,000 values came in 20 s instead of 37 on one laptop. Since 2.7.34 (2.7.35 on git 2.43, which merges commits only) a merge whose only paths changed on both sides are deletion records (a run's two jobs deleting the same superseded attestations) writes ours into the tip's tree before `git merge-tree` merges, with `-X no-renames`, so a blobless clone merges trees alone instead of failing on a missing blob and falling back to git-meta's merge of three listed trees (20 to 120 s on vex) |
| `vci prune [--dry-run] [--superseded] [--keep N]` | Delete attestations whose claimed expiry has passed from the local git-meta store (tombstones; `vci push` publishes them), and (since 2.2) per unit and signer every attestation but the `N` issued last (default 2; `--superseded`, since 1.8.2, is `--keep 1`), except one made on a tree some branch, remote-tracking branch or tag still has at its tip (2.1.12's rule): an older one vouches for inputs the tree no longer has, or soon will not, and every stored attestation costs each plan a download. Since 1.9.0 it then deletes the stored input manifests (`vci:manifest:<root>`) no remaining attestation references (none while an attestation, or the manifest reference of one it leaves alone, cannot be read), and prints how many (since 2.1.8 the base manifests the kept manifests list their entries on top of count as referenced, and a kept manifest that cannot be read keeps every manifest). Since 2.0 it reads every attestation, so it first fetches the ones a blobless fetch left out (one batch; on a large store most of what a fetch downloaded before 2.0); one that cannot be fetched is left alone, with a warning |
| `vci explain <test-file> [--base-ref R]` | Every candidate attestation checked (newest first since 2.1, up to the first that passes) and the first check it failed, with expected vs actual (an env failure names the variable and its class under the base policy, `env:DATABASE_URL (hash)`, never its value). It plans as `vci plan` does, fetching the values it reads; one that could not be fetched fails its candidate's `envelope` check with ``unreadable: value not fetched: run `vci fetch` online`` |
| `vci env [--base-ref R] [--project NAME] [--format text\|json]` | Print the effective environment policy of each project: every variable `[env]` and the runner's built-in lists name, its class (`set`, `hash`, `ignore`, `built-in hash`, `built-in ignore`, `stripped`), where the rule comes from (`vci.toml set`, `vci.toml hash`, an old key name, `built-in <adapter>`, `test script`) and what it is here (the value vci sets; `present (<hash prefix>)` or `absent`); variables present here that the tests will not see are listed as removed. With `--base-ref`, a `BASE` column says where the base commit's policy differs (CI judges with it). Runs nothing (docs/ENV.md, "vci env") |
| `vci update [--check] [--version X.Y.Z] [--keep-old]` (alias `vci upgrade`) | Since 2.7.33: install the latest release the way this `vci` was installed. The latest release is where `https://github.com/PandelisZ/cryptographically-verifiable-ci-runner/releases/latest` redirects (one request through `curl`, no API call, no token; curl's proxy variables apply); when it is the running version, it prints `vci: 2.7.33 is the latest release` and exits 0. Otherwise, by the running executable's real path: under `Cellar/vci/` (or `$HOMEBREW_PREFIX/opt/vci`) it runs `brew update` and `brew upgrade pandelisz/tap/vci`, showing their output; in `$CARGO_HOME/bin` (`~/.cargo/bin`), or with `VCI_HOME` set or `~/.local/share/vci/.git` present, it runs that clone's `scripts/install.sh` with `VCI_REF=vX.Y.Z`, or prints the `curl ... install.sh \| VCI_REF=vX.Y.Z sh` command when there is no clone (exit 1); beside cargo's `.fingerprint` (built in a checkout) it refuses; anywhere else it downloads `vci-<target>.tar.gz` and `SHA256SUMS-<target>` from the release, checks the SHA-256 (a mismatch changes nothing), unpacks the binary, runs its `--version` (it must name the release), writes it to a temporary file in the executable's directory and renames it over the executable. A directory it cannot write to is refused with the `sudo <path> update` command to run; `--keep-old` keeps the replaced binary as `vci.old`; collectors in a `share/vci` above the binary are not updated, and it says so. `--check` only prints both versions: exit 0 when current, 1 when there is an update. `--version X.Y.Z` installs that release (a release binary, or the install script at its tag; Homebrew installs only the tap's version). A failed lookup or download is an error (exit 2). `VCI_UPDATE_REPO=owner/name` reads another repository's releases; `VCI_UPDATE_BASE_URL` replaces `https://github.com/<repo>/releases` (`<base>/latest`, `<base>/download/<tag>/<asset>`; http and `file://` allowed; a `latest` without a redirect may hold the tag or the API's JSON) |

Signing key: `--key`, else `$VCI_SIGNING_KEY`, else `git config user.signingkey` when `gpg.format = ssh` (a GPG
signing key is never used). Errors name the source the key came from. A `.pub` path works when the private
half is in `ssh-agent` (hardware keys included). The signer id (a segment of the git-meta key) is the first 16 hex chars of SHA-256 over the
public key blob. Keyless (since 2.0): `--oidc` instead of a key, in a GitHub Actions job with `permissions: id-token:
write`; the signer id is then the first 16 hex chars of SHA-256 over the job's identity claims (see [Keyless signing
(OIDC)](#keyless-signing-oidc)).

Base ref: `--base-ref`, else `$VCI_BASE_REF`, else `origin/$GITHUB_BASE_REF`, else the first of `origin/HEAD`,
`origin/main`, `origin/master`, `main`, `master` that exists. If none resolves, everything runs. The base ref is the
trust boundary: `vci plan` prints a warning (and `--format json` lists it under `warnings`) when the base commit is
HEAD or contains it, because then `allowed_signers` and policy come from the commit under test.

Environment: `VCI_JS_PLUGIN` (path of the `@vci/vitest` package; default `node_modules/@vci/vitest` above the
project; for node:test, then `js/vitest-plugin` or `share/vci/vitest-plugin` above the `vci` executable), `VCI_NODE` (node binary), `VCI_PY_PLUGIN` (the `py/pytest-plugin` directory holding `vci_pytest`; default:
`py/pytest-plugin` or `share/vci/pytest-plugin` above the `vci` executable, then the source checkout `vci` was built
from, then `py/pytest-plugin` above the project; a clear error names the variable when none is found), `VCI_UV` (uv
binary), `VCI_JOBS` (parallel pytest or `go test` processes in `vci run`, and the units `vci run` checks and signs at once after the tests (since 2.1, default one per CPU); the files `vci plan` verifies at once (since 2.1, default one per CPU); for Rails, the slots of a batch when neither `VCI_RAILS_JOBS` nor `PARALLEL_WORKERS` sets them), `VCI_RAILS_JOBS` (the slots of a Rails batch: files at once, each slot with a database of its own as Rails' parallel workers have; `1`: one at a time; default: `PARALLEL_WORKERS` above 1, `VCI_JOBS`, or the number of CPUs, capped by `parallelize(workers:)`, for projects that call Rails' `parallelize`; `PARALLEL_WORKERS=1` or `workers: 1` turns them off), `VCI_METRICS` (since 2.5: every vci command appends one JSON line to `<git common dir>/vci-metrics.jsonl` with its version, command, flag names (never their values), exit code, duration, machine (OS, architecture, CPUs, CI or not) and every step it timed, the lines `VCI_TIMING` prints; `vci metrics [--last N] [--command C] [--format json]` gives each step's median, 95th percentile and maximum over recent commands; `VCI_METRICS=<file>` writes elsewhere, `VCI_METRICS=0` writes nothing; in GitHub Actions `vci ci` also adds its slowest steps to the job's step summary; the log keeps about its last 4 MB), `VCI_RAILS_SHARD_SECONDS` (a Minitest file whose last run took at least twice this many seconds runs as shards of about this long, one process each, in a batch's slots; default 30, `0`: off; since 2.3), `VCI_RAILS_FILE_TIMEOUT` (seconds a Rails test file's process may run, in a batch's slot or on its own, before it is stopped; default 600, `0`: no limit; a stopped file fails, is not attested and is not run again, and a file still running after two minutes is named on stderr; since 2.7.2), `VCI_RAILS_PER_FILE` (`1`: `vci run` starts one Ruby process per Rails file instead of booting once per runner and forking one process per file), `VCI_RAILS_SHARED_OUTPUT` (`0`: in a Rails batch, each file's process writes all of its output instead of only what it does not share with the other files of its boot), `VCI_RAILS_PROFILE` (`1`, since 2.7.34: each Rails file's process prints one `vci-profile` line with its top-level requires' time and count, the routes' first draw, the garbage collector's time and count, and its own time from the fork; the batch's output carries them), `VCI_RAILS_EXPERIMENT` (since 2.7.34, measurement switches of a Rails batch, comma separated, each measured on vex's runners and found not to change a file's process beyond noise: `eager` eager-loads the application and draws its routes in the batch's process before the slots fork, so every file records them as inputs; `routes` draws the routes only; `warmup` calls `Process.warmup` in each slot once it is set up; `iseq` keeps each source file's compiled instruction sequence under this run's output directory, keyed by path, size and mtime, so a batch compiles a file once instead of once per process), `VCI_GO`
(go binary), `VCI_CARGO` (cargo binary; rustc is `$RUSTC` when declared, else `rustc` on PATH), `VCI_CARGO_JOBS` (Cargo test
executables run at once in `vci run` and `vci ci`; default: the number of CPUs; cargo itself runs one build at a
time), `VCI_RUBY` (ruby binary, default `ruby` on PATH), `VCI_RUBY_COLLECTOR` (the `ruby/vci-collector` directory
holding `vci_collector.rb`; looked up like `VCI_PY_PLUGIN`).

Every collector directory is resolved to its real path before use, and what a test process reads of vci's own
collector files is never an input, whichever path reached them: Homebrew installs them in
`Cellar/vci/<version>/share/vci` and its formula passes `opt/vci/share/vci/vitest-plugin` (a symlink) as
`VCI_JS_PLUGIN`, and pnpm links `node_modules/@vci/vitest`. (Each adapter drops reads, listings and module loads
outside the repository whose real path lies in its collector directory; inside the repository they are hashed like any
file. The Go adapter's standard library hooks are compiled into `vci` and written to a fresh temp dir for each run.)
The collectors are vci's tooling: the Ruby collector's `VERSION` is part of the Rails toolchain; the versions of the
JavaScript and Python collectors are not compared by `vci plan`, so pin the vci you attest with in CI (the action's
`@v2`, the same Homebrew version).

**Refusal summary.** After the per-unit lines (`vci: not attesting <unit>: <why>`, unchanged), `vci run` prints how
many files each reason refused, most first, every reason listed:

```
vci: 3 attested, 5 not attested
vci: why not attested (files per reason; a file can have several):
vci:   4 native:FFI
vci:   1 process:system
vci:   1 result failed
```

A reason is a stable key: for a taint, its category (the text up to the first `:`, space or `(`, plus the name after
a single `:`: `native:FFI attach_function(...)` -> `native:FFI`, `cargo:process: Command::new in ...` ->
`cargo:process`, `go:source: ...` -> `go:source`, `vci:not-hooked:ffi (...)` -> `vci:not-hooked`); for the three
refusals `policy.ignore_taints` can waive that are not collector taints, the key that waives them
(`outside-repository`, `wrote-inside-repository`, `result:skipped`); for any other refusal, its text up to the first
`:` or `(` (`result failed`, `no result`). On a unit's line, taints that share a key are shown once, as the first of them with the number of the
others (`native:FFI call Vips.vips_init (...) (+129 more native:FFI)`), most frequent first. `--summary FILE` writes:

```json
{
  "version": 1,
  "attested": 3,
  "notAttested": 5,
  "reasons": [{ "reason": "native:FFI", "files": 4 }, { "reason": "process:system", "files": 1 }],
  "units": [
    { "testId": "test/models/b_test.rb", "project": null, "adapter": "rails", "attested": false,
      "reasons": ["native:FFI", "process:system"], "detail": "tainted: ...", "taints": ["native:FFI call ...", "..."],
      "waived": [] }
  ]
}
```

(`project` is the `[[projects]]` name, `null` in the single-project form; `taints` lists every refusing taint as the
collector reported it; `waived`, for an attested unit, the taints `policy.ignore_taints` or `go_allow_net` waived,
which the `attested` line summarises as `(waived: process:system, +2)`.)

The environment policy is three lists in `[env]` (docs/ENV.md has the details and the built-in table per runner):
`set` (vci sets the variable in every test process, on every machine, so it is the same everywhere), `hash` (taken
from the machine, hashed: another value re-runs the test) and `ignore` (taken from the machine, never hashed). A short
built-in list per runner adds the variables the runtime reads natively that change results (built-in hash: `TZ`
everywhere; `NODE_OPTIONS` and ICU's `LANG`/`LC_ALL`/`LC_MESSAGES` for Node; `RUSTFLAGS`, `CARGO_PROFILE_*`, the C
toolchain for Cargo; `GOFLAGS`, `GODEBUG`, `CGO_*` for Go; `PYTHONHASHSEED`, `PYTEST_ADDOPTS`, ... for pytest;
`RUBYLIB`, `RUBY_YJIT_ENABLE`, `DATABASE_URL` for Rails) and what the runner needs to work (built-in ignore: `PATH`,
`HOME`, caches, version managers; never hashed, since 2.0.2 not even when a test reads one: `hash` opts one in). Every other variable is removed from the test
processes, including `CI`, `NO_COLOR` and `FORCE_COLOR` (so `NO_COLOR=1 vci ci` still prints Vitest's colours): list
one to keep it. `vci env` prints the effective lists per project and what each variable is on this machine.

Reads are observed (Vitest, node:test, pytest, Go, Rails; Cargo by the names written literally in the source): a
read of a variable is hashed unless it is in `ignore` or is vci's own plumbing (`VCI_OUT`, `VCI_WORKER`,
`VCI_LIST_OUT`, `VCI_GO_TESTLOG`; Vitest's `VITEST*`; pytest's `PYTHONPATH`, which vci sets to its collector and a
test that reads it is not attested; what vci sets for every Rails process: `RUBYOPT`, `RAILS_ENV`/`RACK_ENV`,
`BUNDLE_GEMFILE`, `PARALLEL_WORKERS=1`, `DISABLE_SPRING=1`, `DISABLE_BOOTSNAP=1`, a fresh `TMPDIR`); a read of a
removed variable is recorded as absent. Reading the whole environment (`dict(os.environ)`, `os.Environ`,
`env::vars()`, `ENV.to_h`, ...) refuses the test, except Bundler's own copy for child processes and its selection of
`BUNDLE_*` settings while it sets up the bundle. The cargo adapter does not attest under the deprecated
`mode = "loose"`.

The old key names `global` (now `hash`), `pass_through` (now `ignore`) and `env` in `[[env.files]]` (now `hash`) still
work, with one warning naming each key to rename; `mode = "strict"` is accepted silently and `mode = "loose"` with a
deprecation warning. Attestations made before vci 1.6.0 re-run once: the env config digest changed (docs/ENV.md).

## Where attestations live (git-meta)

vci keeps no storage format of its own. Every attestation is one [git-meta](https://git-meta.com/) string value:

- **target**: the unit's path, `path:<test file>`, `path:<Go package dir>` or `path:<cargo package dir>` (the part of
  a cargo test id before `#`). git-meta cannot hold the repository root (`.`, e.g. a Go module's root package or a
  cargo package at the root) or a path shorter than three bytes (git-meta's minimum target length, e.g. a crate in
  `rs/`) as a path target; such units are stored on the `project` target, with the same key;
- **key**: `vci:attestation:<test key>:<signer id>:<storage key>[:<hint>]`. The test key (BLAKE3 of the test id) separates units
  that share a path (the cargo targets of one package); the signer id separates signers, so two signers never write the
  same key; the storage key hashes everything that makes two attestations interchangeable (input root, global inputs,
  toolchain, argv, env configuration, project). Re-attesting the same unit with the same inputs rewrites the same key
  (whatever the hint). Since 2.2 the key ends with a hint, `<issuedAt in seconds, hex>.<the first 16 hex digits of the
  tree the attestation records, or ->`: a plan reads from the keys which candidate of each unit to download first (one
  made on this checkout's tree, else the newest) instead of downloading every candidate to find out (on vex, 10,500
  envelopes a job for 2,000 units), and fetches the others only for the units it could not skip. A vci before 2.2 does
  not read hinted keys: such a unit runs there (fail open), and a push from it never deletes them;
- **value**: the signed DSSE envelope, byte for byte (git-meta keeps values over 1 KiB as blobs; nothing truncates).

Since vci 1.9.0 the envelope does not embed the unit's input manifest (every path, hash, external and env hash it
recorded): its predicate carries `manifestRef`, the input root, and the manifest is a value of its own on the
`project` target, key `vci:manifest:<input root>`, in a compact JSON encoding (`{"v":2,"entries":[[path,kind,size,
hash,exec?],...],"externals":[...],"env":[...]}`). It is written once per distinct manifest and shared by every
attestation, unit and signer with that root (the cargo targets of one package often share one). The signed root
makes it tamper-evident: `vci plan` recomputes the stored manifest's root and uses it only when it is the root the
attestation signed; a manifest missing from the store (``manifest <root> not in the store: run `vci fetch` `` in `vci
explain`), unreadable or forged makes the unit run. Attestations made before 1.9.0, with the manifest inline, verify
as before; vci before 1.9.0 cannot read a new attestation (the unit runs there).

Since 2.1.8 a run stores the entries every unit it attests shares (a Rails batch's files share the boot's
observations, most of each manifest) once, as a plain manifest under its own root, and each unit's manifest is stored
on top of it: `{"v":2,"base":"<base root>","entries":[<the unit's own entries>],...}`. Reading it puts the base's
entries back, and the result's root is still the signed one; the base is fetched with the manifests that name it (a
blobless clone's plan fetches the attestations, their manifests, then the bases). A base nothing names any more is
deleted by `vci prune` with the other unreferenced manifests; `vci run`'s supersession never deletes one. vci before
2.1.8 cannot read a manifest on a base (the unit runs there), and `vci prune` before 2.1.8 would delete the bases,
so every clone that prunes must be on 2.1.8 or later.

`vci run` (and `vci ci --key`) deletes the signer's earlier attestations of a unit it re-attests (same OS and
architecture) when their files differ from the new one's and they were made on an earlier commit of the same line of
history that nothing else still contains: the new commit descends from it, and every branch, remote-tracking branch
and tag containing it contains the new commit too (`origin/<branch>` of the branch being worked on counts as the same
line); or, since 2.1.3, a commit on no branch, remote-tracking branch or tag at all (rebased or amended away, or one
a full clone does not have: no name can check its files out), as a pull request's earlier pushes are after a rebase.
Kept: one made on a sibling branch or pull request, on a commit `main` (or a tag, or another branch) still
contains, such as an attestation of `main`'s tip when a feature branch re-attests the unit, one made on the same
commit (work in progress), one of the same files under another environment or toolchain, one on a commit a shallow
clone does not have, and (since 2.1.12) one made on a tree some branch, remote-tracking branch or tag still has at its
tip, whatever its commit (an attestation records the checkout's git tree when the working tree was clean): a pull
request's merge commit is on no ref once the pull request is squash-merged, yet master's tip has its tree and master's
next run skips with it, so another pull request's run must not delete it. The published tree so keeps one attestation per unit and signer as a line of work moves on,
without deleting what other branches still use (`vci prune --superseded` keeps only the newest, whatever the branch).
The manifests only the deleted attestations referenced are deleted with them, and `vci prune` deletes the stored
manifests no remaining attestation references. A clone that still references a deleted manifest (it attested, or
fetched an attestation, before it saw the deletion) puts it back when it merges the deletion in, and its next push
publishes it again: a deletion never takes the manifest of an attestation another clone holds.

```sh
git meta get path:src/b.test.ts             # keys and (abbreviated) envelopes
git meta get path:src/b.test.ts vci:attestation:<test key>:<signer>:<storage key> --json
git meta get project vci:manifest:<input root>  # a stored input manifest (vci 1.9.0+), compact JSON
```

No other fields (signer, expiry, result) are stored next to the envelope: the envelope already carries them, `vci
explain` shows them, and every extra key would count against git-meta's auto-prune limit (`meta:prune:max-keys`, 10000
when a remote was initialized by `git meta setup`; the stored input manifests count too, one key per distinct
manifest, and one it prunes makes every unit whose attestation references it run). The standard commit-target
`attestation` list is not used either: vci attestations are content-addressed by unit and inputs, not tied to a
commit, so they survive rebases and apply on every branch.

**One store per repository.** Since 2.7.33 the store is `<common git dir>/git-meta.sqlite`: in the main worktree (and
any clone without linked worktrees) `.git/git-meta.sqlite`, the path it always was, and a linked worktree (`git
worktree add`) uses that same file instead of one of its own in `.git/worktrees/<name>/`, as it already shared the
`refs/meta/*` refs. (vci opens git-meta's session on the common git directory, so git-meta's own files, such as its
history-index checkpoint, are the shared ones too; the stock `git meta` CLI run in a linked worktree still uses that
worktree's own file.) What `vci run` stores in one worktree is read by `vci plan` in every other at once, with nothing
pushed or fetched (the attestations are signed and every plan re-hashes its inputs, so this is as safe as reading a
fetched one), one `vci fetch` serves them all, and `vci push` from any of them publishes everything stored. The lock
taken while git-meta opens the store (`git-meta.sqlite.vci-lock`) sits next to it, and fetches and pushes take the
repository's exchange lock (`git-meta.vci-exchange.lock`) as before. A linked worktree's own store left by an earlier
vci (`.git/worktrees/<name>/git-meta.sqlite`) is handled by the first vci command run there: when the repository has
no shared store yet, it becomes the shared one (moved, under the exchange lock, when no process has it open; vci then
prints `vci: note: moved this worktree's git-meta store ...`); when it is in use, or a shared store exists already,
it is left where it is, unused and never deleted, and vci prints once `vci: note: <path> is no longer used: every
worktree of this repository now shares the git-meta store <path>; the old file (with its -wal and -shm files) can be
deleted`. Attestations only that old file held (made in that worktree and never pushed) are not read any more; `vci
run` makes them again. A shared store made anew gets what `refs/meta/local/main` holds the way any new store does
(see "A store that does not match the shared metadata ref" below).

**Exchange.** Metadata lives locally in git-meta's SQLite store (`.git/git-meta.sqlite`, one per repository, written
by `vci run`; your index, `HEAD` and work tree are never touched) and is exchanged on the remote's `refs/meta/main`:

- `vci fetch` fetches `refs/meta/main` into `refs/meta/remotes/main`, serializes local values and materializes the
  remote's (git-meta's merge) into the store, like `git meta pull`. Since 2.0 it downloads keys, not values: `git
  fetch --filter=blob:none` (commits and trees), and for the first fetch of `refs/meta/remotes/main` `--filter=tree:0`
  (every commit of the metadata history, no tree) followed by the tip's tree alone, fetched by object id (and, since 2.1.15, the subtrees that fetch left out, by id, in up to five more rounds: GitHub served vex's 108,000-subtree tip without 12 of them), so a fresh
  clone's download does not grow with the length of the history; later fetches take the commits since, with their
  trees, so merges keep their base (a merge base whose tree was never fetched gets it first). The repository is never
  made shallow. A tree's paths are its
  keys, so the store gets a row per key without reading a value: a value whose blob is already here is stored as a
  reference to it, any other one as a git-meta *promised* row (not fetched). Only deletion records (tiny) are
  downloaded and read. `vci plan` (and `vci ci`, `vci explain`) then fetches the values it reads in one `git fetch
  --stdin` of blob ids each: the attestations of the units it verifies, then the input manifests of each unit's
  newest attestation (since 2.1.13; every candidate's before, six times as many on vex), and after its first pass,
  in one more batch, the manifests of the other attestations of the units it could not skip, which are checked
  again (`VCI_TIMING=1` prints `round 2: fetch N more manifest(s)`). The store's promised rows and the local
  metadata tree are listed once for all of a plan's batches (2.1.13: listing them for each took 12 of a vex job's 24 s);
  `vci verify` fetches the one manifest it reads, `vci run` the attestations of the units it attests (supersession
  reads them), and `vci prune` every attestation (on a large store, what a fetch downloaded before 2.0). A value that
  cannot be fetched (offline) reads as ``value not fetched: run `vci fetch` online`` and makes its unit run (a
  warning, never an error); a vci before 2.0 reading such a row reports it unreadable and runs the unit too. On vex
  (4,540 entries, 1,257 values, 38.6 MiB packed, 24 commits; a local copy of the remote) a fresh clone's fetch went
  from 40.6 MB in 5.5 s to 1.8 MB in 1.0 s, and a plan of one project then fetched 1.4 MB (621 values) in 0.5 s; on a
  later copy (6,006 entries, 85 commits) the fetch is 2.1 MB, of which the 84 earlier commits are 36 KB (their trees
  would be 2 MB more). The merge is done from the trees' paths too, with
  the result git-meta's gives: a fetched tip the local metadata commit is an ancestor of is merged by applying what
  `git diff-tree` reports between the two trees (new and changed values and deletion records, git-meta's delete for
  values the tip no longer has, the local ref moved to the tip); local metadata commits not yet pushed are merged by
  git-meta's three-way merge (two-way without a common history) of the trees' entries, blob ids standing in for the
  values (its rules only compare them), as a merge commit; a clone's first fetch takes the tip's entries. A side
  remote, and any entry it does not read the way git-meta does (a set or list value, an unexpected path or mode: a
  `vci: note:` says so), go through git-meta's full merge after fetching every value of the trees it reads
  (`VCI_TIMING=1` prints `materialize (from paths, ...)` or `materialize (full)`, and since 2.1.14 each step before it: `fetch: git fetch (commits and trees)`, `complete the tip's tree`, `list the tip's keys`, `cover the local ref`, `serialize the local metadata`). A serialization rebuilds a changed
  target's subtree from the values it holds and puts the values not fetched back at the blob ids the previous commit
  held, so a push from such a clone sends only what it wrote (a pack that is not thin, `git push --no-thin`: a thin
  one would be deltified against the remote's values, which the clone does not have); a value whose blob the clone
  never fetched that a merge would keep although the tip no longer holds it (the remote's history rewritten or
  forced back without it) takes the tip's state instead, since no push could publish it, and a push that finds such
  a value in the local metadata commit (made by a 2.0 pre-release) fetches it, or deletes it when the remote says it
  does not have it any more. `--rewrite-history` sends the whole tree, so from such a clone it fetches every value
  first. When a merge's tree is exactly the tip's (after the
  remote's history was rewritten), the local ref is pointed at the tip, so the next fetch is a fast-forward again;
- `vci push` does the same, then rewrites the local metadata commit (`refs/meta/local/main`) as one commit on top of
  the remote tip and pushes it as a fast-forward, retrying from the fetch when the remote moved, like `git meta push`.
  It refuses to push a tree that does not contain the remote tip (that would drop other people's values), and pushes
  only to the primary git-meta remote: a side remote (`remote.<name>.metaside = true`, e.g. `vci fetch --remote <url>`
  for a second URL) is read from, as git-meta does;
- the git-meta remote is the one `git meta remote add` / `git meta setup` configure (`remote.<name>.meta = true`,
  fetch `+refs/meta/main:refs/meta/remotes/main`). `vci init` writes `.git-meta` (`url: <origin's URL>` unless
  `--meta-url`), the file `git meta setup` reads, and configures a remote named `meta` (in a linked worktree,
  `git worktree add`, git writes remotes to the repository's shared `.git/config`, so the main checkout and every
  other worktree get it too; `vci init` prints a note saying so); `vci fetch --remote origin`
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
  or emptied `.git/git-meta.sqlite`; before 2.7.33 a **linked worktree**, which had its own store while the refs are
  shared; a ref fetched by hand) would publish their deletion. vci first copies into the store every value of the ref it has no row
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
trusted: only an envelope signed by a key in the base commit's `allowed_signers` (or keylessly, by an identity of its
`identities.toml`), for exactly this unit, repository, toolchain and inputs, skips anything. Anyone with push access
to the metadata remote can write or delete metadata, exactly as with any other ref.

Interoperability, checked by the tests against `git-meta` 0.1.13 when it is installed: values vci pushes are
readable with `git meta pull` + `git meta get`; values set (`git meta set`) or deleted (`git meta rm`) with the CLI and
`git meta push`ed are what `vci fetch` + `vci plan` see.

## CI attests its own runs

Without a key, `vci ci` only consumes attestations, so a commit whose only change is a README still runs every unit
nobody attested on a laptop, and every push to main runs the whole suite. With `--key`, CI leaves attestations of its
own behind, and the next commit's CI skips every unit whose inputs did not change:

1. **Commit A** is pushed to main. Nothing is attested yet, so every unit runs. `vci ci --key ci-key --push --remote
   origin` runs them as `vci run --key` does (collectors on, inputs recorded, one process per unit), signs an
   attestation for every unit that passed and is attestable, stores them locally and publishes them on
   `refs/meta/main`.
2. **Commit B** changes `src/b.ts`, which only `src/b.test.ts` reads. Its CI fetches A's attestations. They are keyed
   by unit, signer and input root, not by commit (see [Where attestations live
   (git-meta)](#where-attestations-live-git-meta)), so every unit whose recorded inputs hash the same in B's checkout
   skips. `src/b.test.ts` fails the `inputs` check (`entry:src/b.ts`), runs, is attested and pushed.
3. **Commit C** changes only `README.md`, which no test reads. Every unit skips: `vci ci` prints `vci ci: every test
   file is covered by a valid attestation; nothing to run` and exits 0 without starting the test runner. The job
   costs the fetch and the verification, about ten seconds. `--push` then finds `nothing to push`.

Pull requests use the same attestations: a branch made from B skips every unit it did not change, whether or not
anyone attested it locally.

**What a run attests.** The units the plan says to RUN. When the plan runs everything (`running everything:
policy.no_skip_refs matches ...` with an empty `no_skip_refs_except`, an unreadable base `vci.toml` or
`allowed_signers`, a project that could not be listed), every unit of every project: that full run is the one the
next commit reuses. A unit that fails or that `vci run` refuses (see [When `vci run` refuses to
attest](#when-vci-run-refuses-to-attest)) still runs and is not attested, so it runs on the next commit too; only test
failures make the exit code non-zero. The run uses the configuration the plan was made from (the base commit's
`vci.toml`, or the working tree's when that cannot be read), so the attested test ids are the plan's. Attestations
expire after `--ttl` (default `14d`, at most `policy.max_ttl`): a unit skipped for that long fails `expiry`, runs
again and is attested again, so every unit still gets a real run at least once per `ttl`.

**Flags** (`vci ci`; without `--key` or `--oidc` nothing changes):

| Flag | Meaning |
|---|---|
| `--key PATH` | Run the remainder as `vci run --key` does and attest it with this SSH key (a private key, or a `.pub` with the private half in `ssh-agent`) |
| `--oidc[=INSTANCE]` | Since 2.0: attest as `--key` does, keylessly, with the GitHub Actions job's OIDC token (`permissions: id-token: write`) and no secret; `github` (the default) or `public-good`. See [Keyless signing (OIDC)](#keyless-signing-oidc) |
| `--ttl DURATION` | Lifetime of those attestations, default `14d`; only with `--key` or `--oidc` |
| `--push` | After the run, whatever the tests did, publish as `vci push` does (only passing units have attestations, so pushing after a failure is right). A failed push prints `::warning title=vci::could not push attestations ...` and does not change the exit code; only with `--key` or `--oidc` |
| `--remote R` | Where `--push` pushes, as `vci push --remote R`; only with `--push`. CI should pass it (the action passes `origin`) |

The audit log adds `attested` (`[{testId, project}]`), `attestErrors`, `notAttested` and `pushed` (`true`, `false`,
or `null` without `--push` or when nothing was attested on purpose). When attesting cannot start (the key cannot be
read, a collector is missing), `vci ci` prints a `::warning`, runs everything it would have run without attesting
and pushes nothing; the Commands table above has the remaining cases.

**On main: `policy.no_skip_refs_except`.** `no_skip_refs` makes main run everything, CI's attestations included, so
on its own it would keep every push to main at full cost. `no_skip_refs_except = ["github-actions"]` (per project,
default `[]`) names the principals whose attestations may still skip on a ref matching `no_skip_refs`: the one on
the `allowed_signers` line that verified the signature, or, for a keyless attestation (since 2.0), the one of the first
`[[identity]]` in `.vci/identities.toml` its certificate matches. On such a ref
`vci plan` prints `vci: note: policy.no_skip_refs matches refs/heads/main: only attestations by github-actions
(policy.no_skip_refs_except) can skip`, and every other signer's candidate fails the `signer` check; `vci explain`
shows `policy.no_skip_refs matches refs/heads/main and signer dev@example.com is not in no_skip_refs_except`. With the
list empty, those refs run everything with `policy.no_skip_refs matches <ref>`, as before. On other refs (pull
requests, feature branches) the list changes nothing. Like every policy key it is read from the base commit, and
values are principals: non-empty, without whitespace.

`vci ci --key` attests nothing (a `::warning`, recorded under `notAttested`; the tests still run and nothing is
pushed) when the key signs as a principal in `no_skip_refs_except` and the current ref does not match `no_skip_refs`,
or the base `allowed_signers` cannot be read there: attestations made by a pull request's run would let main skip
code that only that branch ran. That is a guard against a misconfigured workflow. The boundary is not giving such
runs the key at all (see [docs/GITHUB_ACTIONS.md](GITHUB_ACTIONS.md#attesting-in-ci)). To attest pull request runs
too, give them a different key whose principal is not in the list: pull requests then skip on its word, main never
does.

**What trusting CI's key means.** Its attestations replace the full run on main that was the backstop against a
trusted signer's false claim, so treat the key as the most powerful signer in `allowed_signers`:

- **Whoever holds it can make main and every pull request skip any unit** until its line is removed. Keep it out of
  every run but pushes to the default branch: a secret of a GitHub Environment restricted to that branch, never a
  repository or organization secret, which a `pull_request` run (using the branch's own copy of the workflow) can
  read. Every process of that job (the tests, their dependencies, other steps) can read the key file, so it is
  shared with every locked dependency of the job.
- **Scope it per repository**: one key and one principal per repository. Attestations name the repository's root
  commit and never replay across repositories, but one key trusted in several repositories leaks from all of them
  at once.
- **Rotate** by replacing its line in `.vci/allowed_signers` on the default branch (a new key under the same
  principal), then the secret. Attestations signed by the old key stop counting at once; the next push to main runs,
  and attests, everything again. Keep `ttl` short, and rotate whenever a dependency of the attested job is found
  compromised.
- **List only CI's own principal in `no_skip_refs_except`.** Developers' and agents' attestations keep skipping on
  pull requests; main runs whatever only they vouched for.
- **Inputs no collector sees** (see [Threat model (v1)](#threat-model-v1)) now go untested on main for as long as the
  recorded inputs do not change, up to `ttl`. List such tests in `policy.never_skip`.

`vci ci --oidc` replaces the key with the job's identity: there is no secret to keep out of other runs, and the
`[[identity]]` whose principal main skips on takes its place. It must match only main's runs: see [Keyless signing
(OIDC)](#keyless-signing-oidc).

## Keyless signing (OIDC)

Since 2.0 a CI job can attest without a key: `vci ci --oidc` (the action's `oidc: true`) and `vci run --oidc` prove
the job's identity with the OIDC token GitHub Actions gives a job that has `permissions: id-token: write`, and sign
through [Sigstore](https://www.sigstore.dev/) the way `npm publish --provenance` and `actions/attest` do. Trust is a
policy on the job's identity (repository, workflow file, ref, event, environment), committed on the base branch next
to `allowed_signers`. Laptops keep SSH keys; both kinds of attestation live in the same store under the same key
layout and go through the same policy. Research, endpoints and the CI run that proved it:
[docs/spike-oidc.md](spike-oidc.md); the workflow recipe:
[docs/GITHUB_ACTIONS.md](GITHUB_ACTIONS.md#keyless-attestation-oidc).

**Signing.** Once per job: an ephemeral ECDSA P-256 key, held in memory only; the job's token (`GET
$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore`, or a ready token in `$SIGSTORE_ID_TOKEN`); a certificate for the key
from Fulcio, valid ten minutes, requested again when less than a minute is left. Per attestation: an ECDSA-SHA256
signature over the DSSE PAE and an RFC 3161 timestamp of that signature from the instance's timestamp authority (about
0.1 s each on a GitHub-hosted runner). The instance is GitHub's (`--oidc`, `--oidc=github`: `fulcio.githubapp.com`,
`timestamp.githubapp.com`), for public repositories too, so no public transparency log entry names the repository and
workflow of every unit; `--oidc=public-good` uses `fulcio.sigstore.dev` and `timestamp.sigstore.dev`, also without a
Rekor entry. Neither needs `attestations: write` or a GitHub API call. HTTP goes through `curl` (every GitHub-hosted
runner has it), with the tokens on its standard input, never on a command line. Without a token `--oidc` fails before
any test runs (`no OIDC token: the job needs permissions: id-token: write ...`). `vci run` prints whom it signs as:
`vci: signing keylessly as repo:owner/name workflow:.github/workflows/ci.yml ref:refs/heads/main event:push (Sigstore:
...)`.

**Stored form.** The DSSE envelope JSON as for an SSH signature (one signature, `keyid` empty, `sig` the DER ECDSA
signature), plus a top-level `sigstore` member: the verification material of a Sigstore v0.3 bundle (the leaf
certificate and the timestamp); with `dsseEnvelope` added from the envelope's fields it is a standard bundle
(docs/CONTRACTS.md). An SSH envelope is stored byte for byte as before. The git-meta key layout is unchanged: the
signer id is the first 16 hex chars of SHA-256 over the identity claims an `[[identity]]` can match (issuer,
repository, workflow file, ref, event, environment, runner environment), with a pull request's number
(`refs/pull/12/merge` is `refs/pull/*/merge`) and a merge queue entry folded, so all pull requests are one signer, as
one pull request key would be. Main's runs and pull requests' runs of the same workflow file are different signers:
supersession never lets one replace the other's attestation.

**Trust: `.vci/identities.toml`**, read from the base commit like `allowed_signers`:

```toml
[[identity]]
principal = "github-actions"                           # the name policy lists use
issuer = "https://token.actions.githubusercontent.com" # exactly
repository = "owner/name"                              # exactly (ASCII case-insensitive); no glob
workflow = ".github/workflows/ci.yml"                  # glob: the file the signing job is defined in
ref = "refs/heads/main"                                # glob
event = "push"                                         # optional, glob
environment = "vci-attest"                             # optional, glob: the job's GitHub Environment
runner_environment = "github-hosted"                   # optional, glob: or "self-hosted"
```

Every field present must match what Fulcio wrote into the certificate from the token (`*` and `?` do not cross `/`,
`**` does, as in `no_skip_refs`). `workflow` is the path in the repository, or `owner/name/<path>` for a reusable
workflow of another repository (the job's `job_workflow_ref` without `@ref`). The first matching entry names the
principal. Unknown keys, a principal that is empty or has whitespace, an issuer that is not an https URL and a
repository that is not `owner/name` make the file invalid. A principal from identities.toml behaves exactly like one
from `allowed_signers` in `policy.no_skip_refs_except` and `policy.attest_on_any_ref`: name it in
`no_skip_refs_except` for main to skip on CI's attestations. With identities.toml at the base commit,
`.vci/allowed_signers` may be absent (no SSH key is then trusted); with neither, everything runs.

**The trust root: `.vci/sigstore-trusted-root.json`**, read from the base commit too: what `gh attestation
trusted-root` prints (JSON Lines: the certificate and timestamp authorities of GitHub's instance and of the public-good
one). It is the trust anchor, as `allowed_signers` is: vci runs no TUF update and checks no transparency log or SCT.
GitHub renews its Fulcio and timestamp intermediates yearly (the current one is valid until 12 June 2027 and is
published in GitHub's TUF repository weeks before use). A committed copy then goes stale: attestations certified under
the new intermediate fail the `signature` check (their units run; `vci explain` names the issuer) until the file is
refreshed on the default branch with the same command. `vci init --oidc` writes both files.

**Verification** (`vci plan`, `vci explain`, `vci verify`), offline: exactly one signature; the leaf certificate's key
verifies it over the PAE; an RFC 3161 timestamp of the signature verifies with a timestamp authority of the trust
root (its certificate and `validFor` at that time); that time is within the leaf's ten minutes and at most five minutes
in the future; the leaf is issued by a certificate authority of the trust root, at that time within the authority's
`validFor` and every chain certificate's validity, for code signing; its repository and workflow URIs are https URLs
on the issuer's host (`github.com` for `https://token.actions.githubusercontent.com`, `<name>.ghe.com` for GHE.com's
`https://token.actions.<name>.ghe.com`, else the issuer's own host); and its identity matches an `[[identity]]`. The
attestation's own expiry, subject and every later check are as for an SSH signature. A failure is the `signature`
check (chain, timestamp, signature: ``the certificate's issuer (...) is no certificate authority of the trust root
(refresh .vci/sigstore-trusted-root.json with `gh attestation trusted-root`)``, `signed at ..., outside the
certificate's validity ...`) or the `signer` check (`identity repo:owner/name workflow:.github/workflows/ci.yml
ref:refs/pull/12/merge event:pull_request (issuer ...) matches no [[identity]] in .vci/identities.toml`, or a principal
not in `no_skip_refs_except` on such a ref). Without identities.toml at the base commit every keyless candidate fails
(`a keyless signature, and .vci/identities.toml is missing at the base commit`); an invalid one, or a missing or
invalid trust root, does too, with a warning (`... attestations signed keylessly (vci --oidc) are not trusted`): those
units run. `vci plan` names the signer as `github-actions (oidc repo:... workflow:... ref:... event:...)`. vci before
2.0 cannot verify a keyless attestation, and runs its unit.

**The action.** `oidc: true` (or `github`, `public-good`) runs `vci ci --oidc=<instance>` where `signing-key` would
run `vci ci --key`, with `ttl` and `push` as for a key; setting both is an error. The job needs `permissions: id-token:
write` (and `contents: write` to push). [docs/GITHUB_ACTIONS.md](GITHUB_ACTIONS.md#keyless-attestation-oidc) has the
workflow.

**What it trusts.** The certificate binds a signature to the job's identity at the time a timestamp authority vouches
for, not to possession of a file: there is nothing secret to store, rotate or leak, and a certificate is useless ten
minutes after it was issued. What does not change: any step of the attesting job (the tests, their dependencies) can
request a token while the job runs and sign as its identity. So the rules for CI's key hold for the identity main
skips on: it must match only runs on main (pin `ref` and `event`, and best an `environment` restricted to the default
branch), and its principal alone goes in `no_skip_refs_except`. A second identity for pull requests (`ref =
"refs/pull/*/merge"`, `event = "pull_request"`) under a principal outside that list lets pull requests skip on each
other's runs; listing that principal in `policy.attest_on_any_ref` too (with `no_skip_refs_except`) lets main skip what
they ran, with 1.9.2's trade-off. `vci ci --oidc` refuses to attest when the job's identity signs as a principal of
`no_skip_refs_except` on a ref `no_skip_refs` does not match, exactly as for `--key`.

## `vci.toml`

```toml
project = "."          # project dir (Vitest root / pytest rootdir / Go module root / Cargo workspace root / Rails app root), relative to the repo root
adapter = "vitest"     # or "pytest", "go", "cargo", "rails", "node-test"
# runner = "rspec"     # rails only: "minitest" or "rspec" (unset: detected, see Quick start (RSpec)); in [[projects]] per project
# rails_inputs = "strict"  # rails only: "loose" (default since 2.7.36: routes, initializers, boot files, migrations, locales,
                           # autoload records are not inputs) or "strict"; in [[projects]] per project
# ignore_inputs = ["config/credentials/**"]  # rails only: more globs (relative to the project dir) that are never inputs
# test_script = "test" # node-test only: the package.json script that runs `node --test` (default "test"); or instead:
# test_globs = ["src/**/*.test.ts"]                  # node-test only: test file globs (node:test's glob syntax)
# node_args = ["--import", "./test/hooks.mjs"]       # node-test only, with test_globs: node options

[policy]
platform = "any"       # "any" | "same-os" | "exact": which OS/arch may satisfy CI
libraries = "exact"    # "exact" | "any": native libraries (FFI) by file and hash, interpreter library versions (see below)
max_ttl = "30d"        # longest accepted attestation lifetime
allow_dirty = true     # accept attestations made from an uncommitted working tree
no_skip_refs = ["refs/heads/main", "refs/tags/**"]   # never skip on these refs (the `vci init` default)
no_skip_refs_except = ["github-actions"]             # ...except attestations by these principals (allowed_signers or
                                                      # .vci/identities.toml; default [])
attest_on_any_ref = []                                # of those, principals `vci ci --key` (or `--oidc`) may attest as off
                                                      # no_skip_refs: a pull request's run then attests, and main skips what
                                                      # it ran (since 1.9.2; only for a key the repository's own pull
                                                      # requests get and forks never do)
never_skip = ["tests/test_attach_db.py"]             # never skip these files (project-relative globs)
go_allow_net = false   # Go: attest packages whose test links package net (see "When vci run refuses"); = ignore_taints = ["go:net"]
ignore_taints = []     # taints that do not refuse a unit (globs over reason keys, "*" = all; see "Waiving taints: policy.ignore_taints")
node_exact = false     # Vitest and node-test: require the exact Node version (default: the same major)
allow_superuser_mismatch = false # accept attestations made as root where CI is not, or the other way round (risky: see below)

[[policy.platform_overrides]]
match = ["src/native/**"]   # project-relative globs
platform = "exact"          # an entry sets platform, libraries, or both
# libraries = "exact"

[env]                  # see docs/ENV.md; every variable not named here or built in is removed
set = { TZ = "UTC" }   # vci sets these in every test process, on every machine (exact names, string values)
hash = ["NODE_ENV"]    # taken from the machine and hashed: another value re-runs (patterns: *, !exclude)
ignore = ["GITHUB_TOKEN"]  # taken from the machine, never hashed (patterns)
# Precedence: set > hash > ignore > built-in hash > built-in ignore. Old names: global = hash, pass_through = ignore.

[[env.files]]          # extra lists for the matching test files (project-relative globs)
match = ["src/db/**/*.test.ts"]
hash = ["DATABASE_URL"]
ignore = ["PGPASSWORD"]

[[inputs]]             # extra inputs of matching test ids (any adapter; needed by Cargo, see above)
match = ["crates/b#test:*"]
extra = ["testdata/**"]
```

**`policy.allow_superuser_mismatch`** (default `false`). Every toolchain records whether the tests ran as root
(`superuser`), and `vci plan` normally requires the same: a CI job that runs as root (a GitHub `container:` job, many
self-hosted runners) never accepts an attestation made on a laptop, and fails the toolchain check with `privileges`.
Setting this key in the **base branch's** `vci.toml` (top level or a project's `policy`) stops comparing that one
field; every other toolchain field is still compared. `vci plan` and `vci explain` name the key when the check fails
on it. **Why it is risky:** permission checks do not apply to root, and root is another user. A test whose outcome
depends on file permissions (it expects a mode-000 file to be unreadable, a read-only directory to refuse a write,
`File.writable?` to be false, `EACCES` from an `open`) or on who runs it (the uid, the user name, the home directory
from the password database) can pass as one user and fail as the other, and the attestation then vouches for a result
CI would not reproduce. Set it only when no test depends on permissions or identity (or such tests are in
`never_skip`). The Rails collector refuses a test that reads the uid or the user's identity whatever this key says
(`ruby:process-identity:`); the other adapters do not observe it.

**`policy.libraries`** (`"exact"` | `"any"`, default `"exact"`). Two things bind a Rails or pytest attestation to
the platform it was made on even under `platform = "any"`: native libraries opened through FFI, recorded as
`native:<file name>` with the file's sha256 (`native:libvips.42.dylib` on macOS, `native:libvips.so.42` on Linux;
see "Native libraries (FFI) and Active Storage's libvips"), and the versions of the libraries the interpreter bundles
or links, which Homebrew, apt and python-build-standalone build differently (`ruby libraries`: the SQLite library,
libyaml, the time zone data; `python libraries`: SQLite, OpenSSL). Under `"exact"` both must be identical. Under
`"any"`:

- a `native:` external matches by **library name**: the file name up to its first `.` (`libvips.42.dylib`,
  `libvips.so.42` and `libvips.so` are all `libvips`; `libglib-2.0.0.dylib` and `libglib-2.0.so.0` are both
  `libglib-2`). A library of that name must still be among those the probe's process loads where the attestation is
  checked (otherwise the file runs: `native library libvips: not loaded here (looked for a native library named
  libvips, policy.libraries = "any")`); its file name and hash are not compared;
- the versions in the `sqlite`, `yaml` and `tz` items of `ruby libraries` and the `sqlite` and `openssl` items of
  `python libraries` are not compared. Whether each library is loaded still is: a Python without `_sqlite3` or `_ssl`
  (`sqlite=none`, `openssl=none`), a Ruby process without SQLite3, Psych's libyaml or TZInfo (no `sqlite` item, an
  empty `tz=`) does not match an attestation where it was loaded (`ruby libraries: sqlite, yaml, tz loaded or not`,
  `python libraries: sqlite, openssl loaded or not`), and the reverse. The other items of `ruby libraries` (the
  default encodings, the collector version: `ruby libraries except sqlite, yaml, tz`) and everything else in the
  toolchain (Ruby, Rails, Bundler, the test frameworks, the database adapters, the bundle; Python, its implementation,
  pytest, the installed distributions; root or not) still are, exactly.

Like `platform` it is read from the **base commit**, decided per test file (a `[[policy.platform_overrides]]` entry
may set `libraries`, and the strictest of the default and every matching entry applies, so an entry can only make a
file `"exact"`), and set per project in `[[projects]]`. Nothing changes in what `vci run` records, so attestations
made before the key existed verify under it. `vci explain` prints `policy: libraries = "any" (base vci.toml): ...`
for such a file, and under each candidate every difference the key accepted (`accepted by policy.libraries = "any":
external:native:libvips.42.dylib: native library libvips: loaded here as native:libvips.so.42 sha256:...`); a skip
that needed it says so in `vci plan` (`; policy.libraries = "any" accepted 1 difference(s)`; `--format json` gives the
file `"libraries": "any"` and the candidate `acceptedByPolicy`, both left out under `"exact"`). Under `"exact"`, a
native library loaded here under another file name is named in the failure (`not loaded here under this file name;
loaded here: native:libvips.so.42 sha256:... (policy.libraries = "any" would match native library libvips by name)`).
**What it accepts:** another build of the library (another version, other patches, other dependencies of its own:
libvips' libjpeg, libpng, ...), and another SQLite, libyaml, OpenSSL or zoneinfo (not a missing one), whose behaviour
can differ (SQLite's query planner and its JSON functions, the zone rules of a recent change). Use it where these
differences do not reach the tests (or set `"exact"` for the files they reach with `platform_overrides`); the setup
is in "Attest on macOS, skip on Linux" under Quick start (Rails).

`[[inputs]]` globs are relative to the project dir. A glob without wildcards names a file, a directory (walked) or a
path that must stay absent; otherwise the directory before the first wildcard is walked, every directory in it is a
listing (so a new matching file is noticed) and every matching file is hashed. The declared globs are recorded in the
attestation (`declaredInputs`) and must equal the base commit's declaration for that test id. In the `[[projects]]`
form a project's `inputs = [...]` replaces the top-level list.

Unknown keys are errors, with one exception: `rails_allow_db` (top level or in a project's `policy`), removed in vci
1.4.0, is a deprecated no-op kept for compatibility. It still parses, so a base `vci.toml` that sets it stays valid
(an invalid one would run every file); it has no effect, and `vci run` and `vci plan` warn once (see "vci does not
manage the database" under Quick start (Rails)). In `vci plan` an unreadable or missing `vci.toml` or
`.vci/allowed_signers` at the base commit means everything runs (a missing `allowed_signers` does not when the base
commit has `.vci/identities.toml`: then only CI identities are trusted, see [Keyless signing
(OIDC)](#keyless-signing-oidc)).

### Several projects in one repository

Instead of `project`/`adapter`, list projects; `[policy]` and `[env]` are shared defaults, and each key given in a
project's `policy`/`env` table replaces the top-level key for that project (keys not given are inherited; a project's
`set` replaces the whole top-level `set` table, it does not merge with it):

```toml
[policy]
max_ttl = "30d"

[env]
hash = ["NODE_ENV"]

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
hash = ["APP_*"]
```

Test ids stay repo-relative paths (`services/api/tests/test_b.py`), so they are unambiguous across projects; a file
listed by two projects is never attested or skipped. Attestations record the project name and are only accepted for
the same project. `vci run`, `plan`, `ci` and `explain` work across all projects (`vci run FILE…` finds each file's
project, listing only the projects whose directory contains a file it names, so another project's toolchain need not be
installed); `vci plan --format json` names each file's `project` and lists `projects` with a per-project `runAll`, and
`--format github` adds `run_<name>=` per project. `vci ci` runs each project's remainder with its own runner.
`vci plan --project NAME` and `vci ci --project NAME` (repeatable) work on the named projects only, so a job that owns
one suite needs only that project's toolchain: the others are not listed, probed, verified or run, and are absent from
the plan and the audit log. The single-project form keeps working unchanged (its attestations carry no project name).

## What is hashed

Per test file (from the `@vci/vitest` collectors, see `js/vitest-plugin/README.md`): every module in the Vite graph
and every module the worker's module runner evaluated (this catches computed `import()`), every file or directory read
or stat'ed, every failed lookup (so creating a file that was probed as absent invalidates), directory listings
(including the static prefix of `import.meta.glob` and template `import()`, aliased prefixes included), external
packages as `name@version`, and env vars (`set` and `hash` variables, built-in hash ones such as `VITE_*`, and anything read that is not `ignore`).
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

### node:test

See [What the node:test adapter records](#what-the-nodetest-adapter-records): per file the modules resolved or loaded
through Node's module hooks with the candidates of relative resolutions, `node:fs` reads, stats, listings and probes,
packages as `name@version` (linked workspace packages as files), each module's `package.json`, env vars read and
snapshot files; globally `package.json`, lockfiles and `.npmrc` up to the repository root, the preloaded files and
`--env-file`s of the command, `<file>.snapshot`, the tsconfig chain only with a TypeScript loader, and `NODE_OPTIONS`.
Toolchain: the Node major version (`policy.node_exact`: the exact version), and the command's node options in the
attestation's argv.

### pytest

Per test file (from the `vci_pytest` collector, see `docs/spike-pytest.md`): every module executed or found by the
import system inside the repository (including `conftest.py` files and modules reached by `importlib.import_module`
with a computed name), every candidate path each import lookup could have used (so a module created later that would
shadow or satisfy an import is noticed: a new `tests/pkg/__init__.py` in front of `src/pkg`), every file opened or
stat'ed, failed lookups, directory listings, installed distributions as `name@version` (PEP 503 names, as in
`uv.lock`), env vars read through `os.environ`/`os.getenv`, and always `TZ` and the variables pytest and the interpreter read before the plugin loads (`PYTEST_ADDOPTS`,
`PYTEST_PLUGINS`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD`, `PYTHONHASHSEED`, `PYTHONWARNINGS`, ...: pytest's built-in hash
list, docs/ENV.md). Also:

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

Global inputs of every pytest file: the project's settings in `vci.toml` (the `vci:config` external, 2.7.0); `pyproject.toml`, `uv.lock`, `.python-version` and `uv.toml` from the
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
inputs; any other path outside the repository refuses the package (with `GOTMPDIR` set, which is removed
unless `[env]` lists it, `t.TempDir()` uses it instead and the package is refused). Fuzz seed corpora (`testdata/fuzz/FuzzX`) are
read through package os and recorded like any other testdata.

### Cargo

Per unit, from the unit's own `cargo test --locked --no-run --message-format=json <unit>` (`--doc` instead of `--no-run`
for doctests; see [Quick start (Cargo)](#quick-start-cargo)), which reports every crate the unit builds, including
build scripts, proc macros and dev-dependencies, with the features actually enabled:

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

Global inputs of every unit: the project's settings in `vci.toml` (the `vci:config` external, 2.7.0); `Cargo.toml` in every directory from the package dir up to the repo root (the
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
out. A target without tests (`0 passed; 0 failed`, no doctests) passes with 0 tests since 1.9.1: cargo filters nothing,
so it stays empty wherever the same sources build, and skipping it saves its build. A custom harness that prints no
libtest summary, or a target whose every test is `#[ignore]`d, is never attested and always runs. **`#[ignore]`d tests do not prevent an attestation**, unlike skipped pytest or Go tests:
pytest's `skipif` and Go's `t.Skip` decide at run time (on the platform, `CI`, an optional import), so the skipped test
may run elsewhere. `#[ignore]` is decided at compile time from hashed inputs, so CI's `cargo test` ignores the same tests;
the one exception, `#[cfg_attr(target_os = "linux", ignore)]`, is a target cfg and is checked like any other (the unit
runs where it evaluates differently). A test that returns early based on the environment is covered by the literal
`env::var` rule above.

Global inputs of every Go package: the project's settings in `vci.toml` (the `vci:config` external, 2.7.0); `go.mod`, `go.sum`, `go.work` and `go.work.sum` from the project dir
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

See [What the Rails adapter records](#what-the-rails-adapter-records) and
[vci does not manage the database](#vci-does-not-manage-the-database-read-this) under Quick start (Rails): every Ruby
file compiled from disk with the shadowing candidates of each `require`, Zeitwerk's directory listings, every file read,
checked, globbed or listed (fixtures, templates, configuration, the schema files of every test database), the loaded
gems by version (their installed files checked against their archives when attested), `ENV` reads, and global inputs
(`Gemfile`, `Gemfile.lock`, the boot files, `test/test_helper.rb` for Minitest files and `.rspec` for RSpec files, the
Ruby version files). Except with `rails_inputs = "strict"`, what Rails reads while it boots (routes, initializers,
environments, the boot files, migrations, locales, the autoload records) is left out: see
[Boot-time files are not inputs](#boot-time-files-are-not-inputs-rails_inputs-since-2734). The test database is the engine's and its contents are not an input. RSpec files also record
`spec_helper`/`rails_helper`, the `spec/support` glob's listings, FactoryBot's definition directories and everything
else under [Quick start (RSpec)](#quick-start-rspec).

## When `vci run` refuses to attest

A test file gets no attestation (and will run in CI) if any of these hold. The collector taints below (every reason
`vci run` prints as `tainted: ...`) can be waived with `policy.ignore_taints` (see [Waiving taints](#waiving-taints-policyignore_taints)
at the end of this section), and since vci 1.7.1 so can three of vci's own refusals, by their key: a passing file
with skipped tests (`result:skipped`), a read outside the repository (`outside-repository`) and a write inside it
(`wrote-inside-repository`). The other refusals (a failed test, an input changed during the run, a toolchain
mismatch, ...) cannot.

- a collector tainted it: child processes, network (including `new net.Socket().connect()` and `dgram` sockets),
  `worker_threads`, `fetch`, enumerating `process.env`, recursive readdir/glob, snapshot writes, `isolate: false`,
  vm/browser pools, experimental module caches, typecheck mode, or any of these done by the Vitest config or a
  globalSetup file in the main process (that taints every file of the run);
- it did not pass (failed, missing result), or **any of its tests was skipped or xfailed**: a skip is usually
  conditional (platform, `CI`, an optional import), and the skipped test did not run, so the attestation cannot
  vouch for it where the condition differs (`vci: not attesting <unit>: result passed (0 failed, 1 skipped or
  xfailed of 4; a skipped test did not run, so it cannot be vouched for elsewhere)`, key `result:skipped`; waivable,
  recorded as `result:skipped:1 of 4`; a failed result never is. Since 2.1.7 Minitest and RSpec report a skipped
  or pending test the same way, so the waiver applies to them too; before, as a failed result, which no policy
  waived). A run in which no test ran (`result no-tests`) is refused unless `result:no-tests` is waived (2.1.7);
- any input lies outside the repository (e.g. a read of `/etc/hosts`, `/proc/sys/net/core/somaxconn`,
  `/etc/lsb-release` or an unowned temp file): `vci: not attesting <unit>: input outside the repository: <path>`,
  key `outside-repository`; waivable, and then the path is not hashed, only recorded as
  `outside-repository:<path>`;
- the test wrote inside the repository (below; every runner whose collector records writes: node:test, pytest,
  Rails): `vci: not attesting <unit>: wrote inside the repository: <paths>`, key `wrote-inside-repository`;
  waivable, and then the written paths are neither inputs nor a refusal, recorded as
  `wrote-inside-repository: <paths>`. Writes to tool caches under any `node_modules` directory (`node_modules/.vite`,
  `node_modules/.vite-temp`, `node_modules/.cache`: Vite's dependency optimizer and bundled config, babel-loader and
  the like) are never writes, with or without a policy, as Rails' `log/` and `tmp/` are not;
- any input changed during the run: the working tree's metadata (size, mtime, ctime, inode, mode) is snapshotted
  before the run and every attested entry must be untouched afterwards, and the global inputs (including snapshot
  files) are hashed before and after. Hard-linking a repository file (`fs.link`) changes its ctime and link count, so
  a test that links a fixture into a temp dir is refused;
- two inputs collide under case folding (since 2.1.7 not when nothing exists under either: two absent probes such as
  `public/ACME` and `public/acme` are no file to be the same one), a symlink leaves the repo, the collector's toolchain differs from the
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

node:test specifics (details in [What the node:test adapter records](#what-the-nodetest-adapter-records)):

- a skipped or todo test or suite, a test that uses `only`, a failure anywhere in the file (load errors, `process.exitCode`, asynchronous
  activity after a test ended, cancelled tests), no per-file summary from node:test (no tests, or the process ended
  early: `process.exit()` in a test is tainted `process.exit`), counts that disagree with that summary, or a non-zero
  exit of the `node --test` process;
- a write inside the repository; `module.register` hooks other than `ts-node`'s and `amaro`'s; `NODE_OPTIONS` with
  anything but memory, warning and stack-trace options (from the environment, an `--env-file`, or a preload of the
  `node --test` process); `TZ` unset; `process.binding`; SQLite `ATTACH`/`VACUUM INTO`/extensions; a package copied
  from a repository directory;
- a test command vci does not accept (a filtering, watching, coverage, config-file or loader option, an unknown
  option, `--test-isolation=none`, shell operators in the script), a `pre`/`post` script around it, `.npmrc`
  `node-options`, an install lifecycle script other than a git hook installer or `patch-package`, or a listing that
  matches no file: nothing of the project is attested, `vci plan` runs everything.

Go specifics (the log only sees what package os reports; everything else that could reach an input refuses the
package, decided from the import closure of the test and the source of every non-standard package in it):

- **a child process**: `os.StartProcess` (all of `os/exec`) is recorded at run time (`exec: <program>`); the child's
  reads are invisible. Only an actual start refuses: importing `os/exec` is fine;
- **network**: package `net` anywhere in the closure (`net/http`, database drivers, and testify's `assert`, which
  imports `net/http`). vci cannot observe connections, so this is refused by default. `policy.go_allow_net = true`
  is your statement that these tests do no network I/O: the refusal is waived, the attestation records the waiver
  (`waived`), and `vci plan` accepts it only while the **base commit's** policy still sets it. It is the same as
  `ignore_taints = ["go:net"]`, and either one in the base policy accepts an attestation made under the other; the
  other Go refusals below are waived only by `ignore_taints` (`go:syscall`, `go:source`, `exec`, ...);
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
- a skipped test or subtest (`t.Skip`; waivable as `result:skipped`), a failed or unbuilt package (including `go vet` failures, which fail
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
  without a locked commit, a crate not in `Cargo.lock`, and the deprecated env mode `"loose"` (Rust environment reads
  are not observed; under the default policy a variable no list names is unset both where the unit was attested and
  in CI).

Rails specifics (collector taints and checks; see [Quick start (Rails)](#quick-start-rails)):

- **child processes**: backticks and `%x`, `system`, `spawn`, `exec` (`Kernel`'s and `Process`'), `IO.popen`, `Open3`,
  `PTY.spawn`, `Kernel#open("|cmd")` (except the `bin/rails db:test:prepare` Active Record's schema maintenance runs,
  see "vci does not manage the database"), and **any fork** (`fork`, `Process.fork`, `IO.popen("-")`: every one goes
  through `Process._fork`), which is how Rails' parallel test workers would run (vci sets `PARALLEL_WORKERS=1`, so
  they do not);
- **network**: creating a `TCPSocket`, `UDPSocket`, `UNIXSocket`, a server socket or a `Socket`, `Socket.tcp`, DNS
  lookups (`Addrinfo.getaddrinfo`, `Socket.getaddrinfo`, ...), and therefore `Net::HTTP`, Redis, browsers of system
  tests (also a child process); a database client a test opens itself (`PG.connect`, `Mysql2::Client.new`,
  `Trilogy.new`: `network:<adapter> client`), and Active Record connecting to a server or database that is not one of
  the test environment's (`network:<adapter> (an Active Record connection to ...)`);
- **a SQLite file that is not one of the test environment's databases** in `config/database.yml`
  (`rails:sqlite-file:<path>`), `ATTACH` (`rails:sqlite-attach`), SQLite extensions (`rails:sqlite-load-extension`).
  The test environment's configured databases (SQLite files, in-memory ones and servers) are accepted with no policy,
  and their contents are not an input (see "vci does not manage the database"). Only `policy.ignore_taints` waives a
  Rails taint (`network:postgresql`, `rails:sqlite-file`, ...);
- **native code**: a native extension (`.so`/`.bundle`) inside the repository; Fiddle (`Fiddle.dlopen`, also of
  `nil`, and any `Fiddle::Function`); FFI: a **call** of an attached function or variable, an `FFI::Function` or
  `VariadicInvoker` invoked directly (`native:FFI`; opening a library is recorded, not refused, and a failed `ffi_lib`
  is nothing), and for ruby-vips the operations and functions its hooks cannot see through (`native:vips:`, see
  "Native libraries (FFI) and Active Storage's libvips" under Quick start (Rails)); libxml2 (Nokogiri) reading files in C: parse options `NOENT`, `DTDLOAD`, `DTDATTR` or `XINCLUDE`
  (external entities and DTDs), `do_xinclude`, an XSD or RelaxNG schema with includes or imports, `validate` of a file
  by name, any XSLT stylesheet, a SAX parser with `replace_entities` (a SAX `parse_file` records the file it parses);
  OpenSSL verifying with a store that holds its default paths or a certificate directory, an `SSLContext` with
  `ca_path`, a configuration file with `.include`, loading a provider or engine (`native:openssl:`, see "OpenSSL"
  under Quick start (Rails)); a library vci hooks that was loaded but never hooked (`vci:not-hooked:`);
- **who the process runs as** (`ruby:process-identity:`): `Process.uid`/`euid`/`gid`/`egid`/`groups`,
  `Process::UID`, `Process::GID`, `Process::Sys`, `Etc.getlogin`/`getpwuid`/`getpwnam`/`getgrgid`/`getgrnam`/
  `passwd`/`group`, read by the test (not by RubyGems, Bundler or Ruby's standard library for itself): the user a laptop
  runs as is not CI's, and nothing records it;
- a file name the collector cannot resolve (`vci:unresolvable-path:`);
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
  listing the test makes under a gem directory of something that is not a gem of the bundle (`GEM_PATH`, `Gem.dir`,
  the user gem dir, Bundler's install path such as `vendor/bundle`: what is installed there differs between machines),
  also through RubyGems' and Bundler's helpers (only their own bookkeeping is not: their checks, and their reads of
  `specifications/`), a gem whose installed files differ from its cached archive or whose archive does not have
  `Gemfile.lock`'s checksum, a gem without a cached archive, a path gem outside the repository, a git gem without a
  locked revision, a `$LOAD_PATH` entry outside the repository, the bundle, Ruby and RubyGems' directories, a Bundler
  other than the project's `Gemfile` (`BUNDLE_GEMFILE`), not running under Bundler at all;
- **caches and preloaders**: a compiled-code cache (`RubyVM::InstructionSequence.load_iseq` defined, as Bootsnap's
  compile cache does), Bootsnap's YAML or JSON compile cache (`YAML.load_file` answered from `tmp/cache/bootsnap`, read
  in C, not from the file vci hashes), Bootsnap's load-path cache, Spring; `Dir.for_fd`;
- not every test passed (a failure, an error, **a skip**), no test ran, **a test made no assertion** (Minitest), the
  process exited non-zero (also after the framework reported a pass: an `at_exit` handler such as SimpleCov's
  `minimum_coverage`, `vci:process-exit:N`), or the collector wrote nothing (a crash, `exit!`); the collector's Ruby, Rails, Bundler or
  test framework versions differ from the project's;
- **RSpec**: a failed, pending or skipped example, an error outside an example (a load error, a `before`/`after(:suite)`
  or `after(:context)` error: `rspec:error-outside-examples`), no example, an example the file declares that did not run (`fit`/`fdescribe` with
  `filter_run_when_matching :focus`, tag filters, `--only-failures`, `--example`, `--fail-fast`), `--dry-run`,
  `--bisect`/`--drb`/`--init` (`rspec:invocation`), rspec-retry or parallel_tests/turbo_tests loaded, an example
  whose failure was cleared or reported as a pass (`rspec:failure-cleared`, `rspec:status-mismatch`), a run without
  vci's `--options .rspec`, a spec reading `Rails::CodeStatistics`' directories (see
  [Quick start (RSpec)](#quick-start-rspec)); reads outside the repository other than the bundle's gems, Ruby's own files,
  vci's temp dirs, `/dev/null`/`/dev/urandom` and the time zone data (the toolchain records which).

### Waiving taints: `policy.ignore_taints`

Since vci 1.7.0 a project can attest units the collectors would refuse. `ignore_taints` (top level in `[policy]` or
in a project's `policy`, default `[]`) lists glob patterns over a taint's **reason key**, the same `category:kind`
key the "why not attested" lines print (`process:system`, `native:FFI`, `go:syscall`, `cargo:process`,
`network:postgresql`; node:test and Vitest report the API they saw, `child_process.execSync`, `fetch`,
`process.env.enumerate`, `fs.readdir.recursive`; pytest its audit event, `subprocess.Popen`, `socket.connect`;
`external-without-version` for a module read outside the repository that no package version identifies):

```toml
[policy]
ignore_taints = ["process:*", "child_process.*", "fetch", "go:syscall", "external-without-version"]
# ignore_taints = ["*"]   # every taint
```

- `*` matches any run of characters, `:` included, so `"*"` matches every key; a pattern without `:` also matches
  every key of that category (`"process"` is `"process:*"`, `"go"` every `go:` key). Patterns are matched against
  the key, not the full text (`process:system`, not `process:system at app/x.rb:3`).
- A unit whose every taint matches is attested: `vci run` prints `vci: attested <unit> (waived: process:system, +2)
  (...)` (the most frequent waived key and the number of other keys), the taints are recorded, as the collector
  reported them, in the attestation's `waived` list, `--summary` lists them under the unit's `waived`, and the "why
  not attested" lines no longer count them. A unit with one taint no pattern matches is refused as before, and its
  refusal line names only the taints that refused it.
- `vci plan` accepts such an attestation only while the **base commit's** policy still waives every recorded taint
  (its `ignore_taints`, or `go_allow_net` for `go:net`, or for Cargo's `cargo:undeclared-reads` the unit's declared
  `[[inputs]]` or, since 1.8.0, an `ignore_taints` pattern matching that key: the undeclared path is then recorded as
  waived instead of refusing the unit); otherwise the candidate fails the `waived` check and `vci explain` names each taint that is no longer
  waived (`waived taint child_process.execSync`, `not waived by the base policy: no policy.ignore_taints pattern
  matches child_process.execSync`). Removing a pattern from the default branch's `vci.toml` therefore re-runs every
  unit attested under it.
- `vci:` taints (vci's own record of the unit is incomplete: a missing result, a collector hook that failed, an
  unparsable line) are never waived, `"*"` included. Neither is a failed result. Other refusals that are not taints
  (an input changed during the run, a toolchain mismatch, Go's "the repository changed during the run") are not
  affected.
- Since vci 1.7.1 three of vci's own refusals are taints too, waived the same way and recorded the same way:

  | Key | Refusal without the waiver | Recorded in `waived` | Waived, the unit is attested and |
  | --- | --- | --- | --- |
  | `outside-repository` | `input outside the repository: /proc/sys/net/core/somaxconn` | `outside-repository:/proc/sys/net/core/somaxconn`, one per path | the path is not hashed |
  | `wrote-inside-repository` | `wrote inside the repository: web/node_modules/other.txt` | `wrote-inside-repository: web/node_modules/other.txt` (every path, comma-separated) | the written paths are not inputs |
  | `result:skipped` | `result passed (0 failed, 1 skipped or xfailed of 4; ...)` | `result:skipped:1 of 4` | `vci plan` accepts the passed-with-skips result |
  | `result:no-tests` (since 2.1.7) | `result no-tests (0 tests; no test ran ...)` | `result:no-tests` | `vci plan` accepts the result in which no test ran (a file whose tests are all gated by an environment variable); a run with tests filtered out (`result filtered`) is never waived |

  The key is the category: `ignore_taints = ["outside-repository"]` waives every read outside the repository, and
  a path pattern such as `"outside-repository:/proc/*"` matches nothing (patterns match the key, never the path).
  `"result"` is `"result:*"`: `result:skipped` and `result:no-tests`. `"*"` waives them all. Writes to `node_modules/.vite`,
  `node_modules/.vite-temp` and `node_modules/.cache` need no waiver (tool caches, never writes).
- `go_allow_net = true` is the same waiver as `ignore_taints = ["go:net"]`.

**The trade-off, plainly.** A taint means the collector saw the unit do something whose effect it cannot record: a
child process's reads, a network response, the whole environment, a directory listed recursively, a native call. A
waived unit's attestation therefore vouches only for what was observed; the inputs the taint stands for are not in
it, so a change to them (the program a child process runs, a server's answer, an undeclared environment variable)
does not re-run the unit, and a skip can hide a failure CI would have seen. The same holds for vci's own refusals:
with `["*"]`, a unit that read a kernel parameter (`/proc/sys/net/core/somaxconn`), the OS release file
(`/etc/lsb-release`, `/etc/alpine-release`) or `/proc/self/exe` is attested although that file is not hashed, and a
different value on a runner does not re-run it; a skipped test (`skipif(sys.platform == "darwin")`, `t.Skip` without
a database) is vouched for where it never ran, and on a platform where it runs it may fail; a written file is no
input, so a test that depends on what it wrote earlier is not re-run when that changes. The attestation records each
of them as waived, and `vci plan` re-checks them against the base policy. That is the intended exchange: "it's fine
if it's not 100% deterministic, the important thing is optimising for CI cost". The attestation says what was
observed and what could not be recorded (`waived`), and the decision is the base branch's (the policy is read from the
base commit, like every other key), so a pull request cannot widen it for itself. Keep `refs/heads/main` in
`no_skip_refs` so the default branch still runs everything, and list units whose waived behaviour does matter in
`never_skip`. Agents must not add `ignore_taints` to a repository's policy on their own: it is the maintainers'
decision.

### What of `vci.toml` is an input

Since 2.7.0 a unit's attestation records its project's settings as one external, `vci:config`: a hash of the
project's directory, adapter and adapter settings (`runner`, the node:test command), its effective `[env]` and its
`[[inputs]]`, and (since 2.7.36) Rails' `rails_inputs` and `ignore_inputs` when they are not the default (`"strict"`,
or any `ignore_inputs`; the default leaves the hash as 2.7.33 computed it, so earlier attestations, which record every
input, stay usable). Nothing else of the file is an input: not `[policy]` (read from the base commit when planning), not
comments or formatting, not other projects. Before 2.7.0 the whole file was a global input of every unit, so any
edit to it ran every unit of every project again. A project whose directory the checkout does not have is left out
with a warning (2.7.0; it has no units), instead of every project running.

## Verification (`vci plan`)

For each listed test file, each stored candidate for its test id is checked in this order; the first candidate that
passes every check means SKIP, otherwise RUN (with the furthest-reaching failure as the reason; of several that
reach as far, the last in the store's order). Since 2.1 the
candidates are checked newest first, by the `issuedAt` each one's payload states (read before its signature only to
order them; a candidate whose payload cannot be read comes last, ties keep the store's order), so when several pass,
the plan names the newest, and `vci explain` lists them newest first. The cheap checks come first and the rehashing of
the checkout (global inputs, then inputs) last:

1. **envelope** parses as DSSE with the in-toto payload type;
2. **signature**: SSHSIG over the DSSE PAE of the exact stored payload bytes, namespace `vci-attest`, SHA-2 only; for a
   keyless attestation (since 2.0), the certificate's ECDSA signature over the PAE, an RFC 3161 timestamp of it by an
   authority of the base `.vci/sigstore-trusted-root.json` within the certificate's validity, and the certificate
   issued by a certificate authority of that trust root (see [Keyless signing (OIDC)](#keyless-signing-oidc));
3. **signer**: the key is in the base commit's `allowed_signers` (`namespaces=`, `valid-after`, `valid-before`
   honoured; `cert-authority` rejected), or the keyless certificate's identity matches an `[[identity]]` of the base
   `.vci/identities.toml`; on a ref matching `policy.no_skip_refs`, its principal is in `no_skip_refs_except`;
4. **statement**: predicate type and subject match, and the predicate has exactly one of `manifest` (the input
   manifest inline: attestations made before 1.9.0) and `manifestRef`, which must be the input root;
5. **expiry**: not expired, not issued in the future (5 min skew), lifetime within `max_ttl`;
6. **repo** (root commit), **test-id**, **adapter**, **argv** (including project dir) match;
7. **toolchain**: Node major, Vitest, Vite (pytest: exact Python version, implementation, pytest; Go: exact Go
   version, effective build settings, architecture level; Cargo: exact rustc and cargo, host triple and cfg set on the
   same platform, attested cfg predicates evaluated for this host), whether the tests ran as root (unless the base
   policy sets `allow_superuser_mismatch`; effective uid 0:
   permission checks do not apply to root, so a test that expects a mode-000 file to be unreadable passes only for
   other users), and OS/arch per policy (Go and Cargo: the same OS
   and architecture when the attestation lists platform-specific files; Go: the same architecture when it lists
   arch-specific reasons, and otherwise another architecture only between 64-bit little-endian ones; Rails: Ruby
   version and patchlevel, engine, Rails, Bundler, the test frameworks (Minitest, and rspec-core, -expectations,
   -mocks, -rails, -support), SQLite library, libyaml, time zone data, encodings, collector version, database adapters
   and the whole bundle, exactly; under the base policy's `libraries = "any"` for the file, the SQLite/libyaml/time
   zone data versions of Rails and the SQLite/OpenSSL versions of pytest are not compared, whether each is loaded is);
8. **env-config**: digest of the effective env configuration (the base `vci.toml`'s `set` values and `hash`/`ignore`
   lists, and this vci's built-in lists) matches; attestations made before vci 1.6.0 fail it once;
9. **result**: passed and untainted (passed with skipped tests only when the attestation recorded `result:skipped`
   as waived, which the waived check then requires the base policy to waive); **inputs-config**: the `[[inputs]]` globs recorded equal the base config's for
   the test id; **waived**: every taint recorded in `waived` still waived by the base policy (`ignore_taints`,
   `go_allow_net`, or for `cargo:undeclared-reads` declared `[[inputs]]`; one recorded under the removed
   `rails_allow_db` never is); **dirty** only if `allow_dirty = false`;
10. **global-inputs**: every attested global entry re-hashed from the checkout, and the current global input set
    has the same root;
11. **inputs**: the input manifest is the inline one or the stored one `manifestRef` names, whose recomputed root
    must be the signed input root (otherwise ``manifest <root> not in the store: run `vci fetch` ``, `... unreadable`,
    `... corrupt`, or `inputRoot` against the root recomputed from it); every attested per-file entry re-hashed (files,
    symlinks, directory listings, directory types, absences); pytest: no native extension module for another platform (`b.cpython-314-x86_64-linux-gnu.so`,
    `b.cp314-win_amd64.pyd`) next to a probed extension candidate;
12. **externals**: every `name@version` is what is installed now (pytest: in the `uv run --locked` environment, and
    pinned by `uv.lock`; Go: the module is in the build list in exactly that version and replacement; Cargo: the
    checkout's `Cargo.lock` pins that version, source and checksum; Rails: the gem is in the bundle Bundler resolves in
   this checkout in exactly that version, a git source's revision included; a native library opened through FFI,
   `native:<file name>`, must be loaded by the probe's process with the same file name and sha256, or under
   `policy.libraries = "any"` one of the same library name);
13. **env**: every hashed variable has the same value in the environment the tests get here (with `set` applied, so a
    `set` variable always matches), and every variable the base policy requires (every `set` name, every `hash` or
    built-in hash variable present here, every exact `hash` name) is covered by the attestation; `vci explain` names
    the variable and its class (`env:FEATURE_X (hash)`, expected `blake3=...`, actual `unset`).

Before any candidate is checked, a file matching `policy.never_skip` (base commit) runs.

Each candidate is checked inside an error boundary (panics included): an error is a failed check, never a skip.

**Cost** (since 2.1). The test files are verified in parallel (`$VCI_JOBS` threads, default one per CPU; the result
keeps the listing's order), and the checkout is read once per plan, not once per candidate: each path's type, a
file's contents hash, a symlink's target and a directory's children are read the first time any candidate names
them and shared by every other candidate of every file; a directory's listing hash is computed once per set of
children left out, and which children of a listed directory git ignores (left out of its listing since 2.0.3) is
asked once per directory, in one `git check-ignore` for the directories a manifest lists that no other manifest
listed before. The current global input manifest is captured once per distinct set of global observations (a Rails
project has one per runner, Minitest or RSpec; pytest and Vitest one per conftest or tsconfig chain). Nothing invalidates
these: the checkout must not change while the plan runs (a change during a plan could already be half-seen before;
now the first observation of a path is the one every candidate is compared with). A path whose observation fails (an
I/O error) is read again by the next candidate, and fails it as before. `git check-ignore` stops with an error on
some paths (a path inside a submodule, or beyond a symbolic link) after printing what it found before them; a directory
git cannot answer about this way is not cached, and a manifest that lists one is asked about as before 2.1, in one
`git check-ignore` of its own whose partial answer counts, so verdicts do not depend on which file was verified
first. `vci run` does the same: when git stops, a unit's answer is git's for that unit's paths alone. `VCI_TIMING=1`
prints the phase as `verdicts (rehash inputs, check candidates)`.

Since 2.0 `vci fetch` downloads the store's keys, not its values (see [Where attestations live
(git-meta)](#where-attestations-live-git-meta)). Before the checks, the plan fetches the values it reads that are not
here yet: the candidates of every unit of the projects it verifies (not of projects that run everything), in one `git
fetch` of blob ids, then the input manifests they reference, in a second. A fetch that fails is a warning (`could not
fetch N stored attestation value(s): ...; their units run`); a value that still cannot be read fails only its own
candidate, at the `envelope` check (``unreadable: value not fetched: run `vci fetch` online``), or, for a manifest,
the `inputs` check.

## Threat model (v1)

Protected against:

- **Forged or tampered attestations**: the signature covers the exact payload bytes; one flipped byte fails. A stored
  input manifest (since 1.9.0 a value of its own, outside the signed payload) is used only when its recomputed root is
  the input root the payload signed: a forged or swapped manifest makes the unit run.
- **Untrusted signers**, including a pull request that adds its own key to `.vci/allowed_signers`, or its own
  identity to `.vci/identities.toml` or authority to `.vci/sigstore-trusted-root.json`: trust and policy come only
  from the base commit, never from the working tree.
- **A stolen CI signing credential, with keyless signing**: there is no key file; the ephemeral key never leaves the
  job's memory and its certificate is valid for ten minutes.
- **Replay** across repositories (root commit), test files, argv/project, toolchains, env configuration, or after
  expiry.
- **Stale inputs**: every recorded input is re-hashed from CI's checkout, including files that must still be absent
  and directory listings.

Not protected against:

- A trusted signer lying, or a stolen signing key. An attestation proves who made a claim, not that the test ran.
  With keyless signing, any process of a job whose identity is trusted can request the job's token while it runs
  and sign as that identity; and a certificate or timestamp authority of the committed trust root issuing a false
  certificate or time is not detected (vci checks no transparency log).
  In particular `vci plan` re-hashes only the inputs the signed manifest lists and cannot check that the list is
  complete, so a signer can under-declare inputs and get a changed dependency skipped. Keep `allowed_signers` short,
  use hardware-backed keys, and set `valid-before` on entries. Spot-check re-runs or a second-signer requirement on
  protected refs are possible follow-ups.
- Inputs the collectors cannot see: native addons, time, locale, randomness, network (network use taints the file,
  but only through the patched Node APIs), data captured before the collectors were installed, and the user and group
  the tests run as beyond root versus non-root (which is recorded; the Rails collector refuses a test that reads the
  uid or the user's identity): file ownership, group membership, capabilities.
- What a Rails test database holds: the database is the test engine's, and its contents are not an input (see "vci
  does not manage the database"). A Rails attestation does not show that the test was independent of rows left
  behind; it shows what CI shows, that the test passed on a database the engine set up.
- Test code deliberately evading the collectors (the collectors run inside the test process: code that undoes their
  hooks, calls their own quiet paths or reaches the original methods through reflection is not defended against).
- Malicious `node_modules` that match the lockfile and package versions (packages are identified by version, not by
  file hashes).
- A CI job whose `--base-ref` points at a ref the pull request controls (its head or merge commit, or `HEAD`). Pass
  the base branch's commit (`github.event.pull_request.base.sha`, as in the example workflow). `vci plan` warns when
  the base commit is HEAD or contains it.
- Third-party Vite plugins (code under `node_modules`) reading files in the main process: only their package version
  is an input. Reads by the config file itself, inline plugins and globalSetup files are recorded.
- Timezone and locale: `TZ`, `LANG`, `LC_ALL` and `LC_MESSAGES` are built-in hash for Vitest (hashed when
  present; the `vci init` template sets `TZ` and `LANG` with `[env] set`, so both sides get the same values); with
  `TZ` unset the system timezone is not hashed. In the deprecated loose mode `TZ` is always hashed. (Go refuses a package
  that uses the system timezone, see "Go specifics"; node:test refuses every file when `TZ` is unset and records
  `LANG`, `LC_ALL` and `LC_MESSAGES` as read by every file.)

Use `no_skip_refs` to run everything on the default branch and release refs. To keep that backstop and still
skip on main what CI itself already ran, give CI its own key (`vci ci --key`, the action's `signing-key`) or identity
(`vci ci --oidc`, the action's `oidc`) and name its principal in `no_skip_refs_except`: on a ref matching
`no_skip_refs`, only attestations whose signature verifies against an `allowed_signers` line, or whose certificate
matches an `[[identity]]`, of one of those principals can skip; every other signer's candidate
fails the `signer` check (`vci explain`: `policy.no_skip_refs matches refs/heads/main and signer dev@example.com is
not in no_skip_refs_except`). With the list empty (the default), those refs run everything, as before. Like every
policy key it is read from the base commit, per project in `[[projects]]`. See [CI attests its own
runs](#ci-attests-its-own-runs) for what trusting CI's key means.

pytest limitations (details and the measured audit-hook coverage in `docs/spike-pytest.md`):

- **C extensions and linked libraries opening files themselves** are not seen: OpenSSL `cafile`,
  `lxml.etree.parse(path)`, pyarrow/h5py, `numpy.fromfile`. Installed extensions are covered by their distribution
  version only; `ctypes.dlopen` and native extensions inside the repository taint. SQLite: databases inside the
  repository and `ATTACH` taint; a test that replaces vci's authorizer with its own (`set_authorizer`) hides later
  `ATTACH`es. List such files in `policy.never_skip`.
- **C-level `getenv`** is not seen: `TZ` (hashed always) and the interpreter/pytest variables are handled, but
  `LANG`/`LC_*` read by `locale`, `os.environ._data` and `posix.environ` bypass the collector (`LANG`/`LC_*` are
  removed from pytest's tests unless `[env]` lists them; `set` gives them the same value on both sides).
- `posix.stat` called directly, or `os.stat` bound before the plugin loaded; `DirEntry.stat()` after `scandir` (the
  listing is recorded, not sizes); custom meta-path finders and zipimport misses; threads outliving the session;
  `realpath()` of paths outside the repository.
- **Per-file isolation**: attestations and `vci ci` run one file per process. A file whose module-level side effect
  breaks another file only in a shared process (a plain full-suite `pytest` run) is not caught.
- **Interpreter builds**: the Python version, sqlite and OpenSSL versions are compared (sqlite and OpenSSL only
  whether they are loaded under `policy.libraries = "any"`); other bundled or linked libraries (zlib, expat, libffi,
  readline) and the compiler are not, so under `platform = "any"` a test that depends on them is accepted from another
  build of the same version.
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
  zone database, a crate spawning a helper) is not seen. Non-literal `env::var(name)` is accepted: variables no list
  names are removed on both sides, but a computed read of a built-in ignore variable (`HOME`,
  `PATH`) is not hashed.
- **Build scripts and proc macros** may read files or variables they do not declare (`rerun-if-*`). vci rebuilds the
  repository's crates in every `vci run` (in its own target subdirectory, with vci's environment policy), so what they
  read is read again; but a build script reading a built-in ignore variable (`HOME`) or a file outside the repository is
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

Rails limitations (details and the verified mechanisms in [`docs/spike-rails.md`](spike-rails.md)):

- **C code opening files is not seen**: Ruby has no audit hook, so vci wraps the Ruby entry points. A C extension
  that opens a path itself (ImageMagick or libvips opening an image by path, a database client's certificate files,
  libxml2 through a catalog or an API vci does not hook) reads unseen; installed gems are covered by their version
  (and their loaded files by the archive check), not by what their C code reads. The libxml2 entry points that read
  files (external entities, XInclude, schema includes, XSLT) and Fiddle and FFI are refused (above). SQLite, the
  common case, is handled (above). Neither are reads by the C library of the user database (`Etc.getpwuid`), the
  host name (`Socket.gethostname`), the number of CPUs (`Etc.nprocessors`, which concurrent-ruby and other gems
  read for their own sizing), `/etc/localtime` (set `TZ`), or reads made through a method captured before the
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
- **The test database's contents** are not inputs (see "vci does not manage the database"): a test whose outcome
  depends on rows left behind (by earlier runs, by hand, by another process writing to a shared server) can pass where
  it was attested and fail on a fresh database. vci promises what CI promises: the test passed on a database the engine
  set up. Neither the server's version nor its configuration is compared.
- **Per-file isolation and order**: `vci run` runs one file per process with a fixed seed; `vci ci` runs the remaining
  files of a project together (`bin/rails test <files> --seed 0`). A file that depends on another having run first is
  not reproduced; neither is a time-dependent test (time, randomness other than `rand`, `SecureRandom`, the number of
  CPUs are not inputs, as for the other adapters).
- **Background work after the tests** (threads still running when Minitest reports) is recorded only until the
  collector writes its output at exit.
- **OpenSSL** is not compared (see "Attesting on macOS, verifying on Linux (Rails)"), and neither is the C compiler of
  gems built at install time.
- **Whether the application boots where `vci plan` runs** is not checked (unless an attestation records a native
  library): the plan reads the toolchain without booting it. An application that boots where it was attested but not
  on the verifier, for a reason outside its recorded inputs and toolchain (a corrupt native extension of an unchanged
  gem version, a missing system library), has its attested files skipped there. `vci run` boots it before attesting
  anything, and CI's own full runs (`policy.no_skip_refs`) boot it.
- **RSpec**: supported (see [Quick start (RSpec)](#quick-start-rspec) and its limitations). A project with RSpec files
  but no `rspec-core` in `Gemfile.lock`, or with `runner = "minitest"`, runs its Minitest files only: an RSpec-only
  one is an error (`vci plan` runs everything, `vci ci` fails rather than run nothing), beside Minitest files the RSpec
  files are reported and left to you.
- **System tests** (`test/system`, driving a browser) are not listed, as `bin/rails test` does not run them; run them
  with `bin/rails test:system`. A test that starts a browser anyway is refused (a child process and sockets).
- Assets: what a test reads from `public/assets`, `app/assets/builds` or `node_modules` is recorded (a fresh checkout
  without them, or with other builds, runs the test); a JavaScript or CSS build step before the tests (`test:prepare`
  hooks of jsbundling/cssbundling) runs only when `bin/rails test` gets no file (`vci ci` when it runs everything,
  never `vci run`), so build assets before `vci run` and `vci ci` if tests need them.

## Layout

```
crates/vci-core       repo paths, input manifests, input roots, predicate types
crates/vci-attest     in-toto Statement, DSSE + PAE, SSHSIG verification, allowed_signers, ssh-keygen signing;
                      src/keyless/: keyless (Sigstore) signing through curl, offline verification of the certificate,
                      RFC 3161 timestamp and identity, identities.toml, the trust root
crates/vci-git        attestation storage on git-meta (git-meta-lib): blobless fetch, values fetched on demand,
                      merges from paths; base-commit file reads, repo identity
crates/vci-adapter    Adapter trait + Vitest, node:test, pytest, Go, Cargo and Rails adapters (list, run, JSONL / go test log
                      parsing; src/golang/vci_testlog.go is the logger overlaid into Go's internal/testlog; src/cargo/
                      reads cargo's JSON messages, rustc dep-info and build script output, and scans sources;
                      src/rails.rs runs bin/rails test and RSpec with the Ruby collector; src/nodetest/ reads
                      package.json test scripts and runs `node --test` per file)
crates/vci-cli        the `vci` binary
js/vitest-plugin      @vci/vitest collectors (Vitest; src/node-test/ for node:test)
py/pytest-plugin      vci_pytest collector (pure stdlib pytest plugin)
ruby/vci-collector    vci_collector.rb, the Rails collector (plain Ruby, loaded through RUBYOPT), and its tests
fixtures/vitest-abcd  Vitest end-to-end fixture
fixtures/node-test-abcd  node:test end-to-end fixture (the shape of a real script: NODE_ENV=test, an --import hooks
                      file with an `@/` alias and extensionless imports, --experimental-strip-types, quoted globs;
                      a: TypeScript, b: reads fixtures/b.json, c: computed import(), d: the ms package)
fixtures/node-test-pnpm  a pnpm workspace: apps/web (unquoted `src/*.test.ts`) uses the workspace package
                      packages/lib and ms from pnpm's virtual store (node_modules is made by the test)
fixtures/pytest-abcd  pytest end-to-end fixture (uv project)
fixtures/go-abcd      Go end-to-end fixture (module using golang.org/x/sync)
fixtures/cargo-abcd   Cargo end-to-end fixture (workspace a, b, c, d; d uses the hex crate)
fixtures/rails-abcd   Rails 8 end-to-end fixture (SQLite; a: lib, b: models and fixtures, c: a view, d: a route
                      using the hashids gem)
fixtures/rails-rspec-abcd  the same app with rspec-rails and factory_bot_rails (a: lib spec with spec_helper only,
                      b: model spec with a factory, a fixture and a shared example, c: view spec with file_fixture,
                      d: request spec)
fixtures/rails-vips   Rails 8.1 with Active Storage, image_processing and ruby-vips (a model test that never touches
                      storage, one that attaches and analyses test/fixtures/files/pixel.png, one that calls C through FFI)
docs/                 PLAN.md (design), CONTRACTS.md (interfaces), ENV.md (env vars), spike.md (Vitest findings),
                      spike-pytest.md (pytest findings), spike-go.md (Go findings), spike-cargo.md (Cargo findings),
                      spike-rails.md (Rails findings), spike-oidc.md (keyless signing findings)
```

## Development

```sh
cargo test --workspace                     # unit + integration + end-to-end (needs node, git, ssh-keygen; uv, go, cargo)
cargo clippy --workspace --all-targets -- -D warnings
(cd fixtures/vitest-abcd && npm ci)        # the fixture's node_modules, used by the e2e tests
(cd js/vitest-plugin && npm test)          # collector tests (Vitest and node:test)
uv run --project fixtures/pytest-abcd pytest py/pytest-plugin/tests   # pytest collector tests
(cd fixtures/go-abcd && go mod download)   # the Go fixture's module, used by the Go tests
(cd fixtures/rails-abcd && bundle install) # the Rails fixture's bundle, with its Ruby (.ruby-version, e.g. through mise)
(cd fixtures/rails-rspec-abcd && bundle install) # the RSpec fixture's bundle (rspec-rails, factory_bot_rails)
(cd fixtures/rails-vips && bundle install) # Active Storage with image_processing/ruby-vips (libvips: brew install vips)
ruby ruby/vci-collector/test/collector_test.rb   # Ruby collector tests (also run by cargo test)
```

Every runner's end-to-end suite (`e2e.rs` for Vitest, `e2e_node_test.rs`, `e2e_pytest.rs`, `e2e_go.rs`,
`e2e_cargo.rs`, `e2e_rails.rs`, `e2e_rspec.rs`) has one environment policy test built on
`crates/vci-cli/tests/env_common/mod.rs`. It proves: a `set` variable reaches the test, and an attestation made where
the machine has another value still skips for a verifier with a third value; a `hash` variable's change re-runs and
`vci explain` names it with its class (`env:APP_HASH (hash)`); an `ignore` variable's change and an undeclared
variable's change both skip, and the undeclared variable is absent in the test; `vci ci`, plain and with `--key`,
applies `set`; the `vci env` rows for the `vci.toml` variables are exactly as expected; and a base commit that still
uses `global`/`pass_through` verifies the same attestation, with one deprecation warning and the same digest.

The Rails end-to-end tests (`crates/vci-cli/tests/e2e_rails.rs`) copy `fixtures/rails-abcd` into a temporary repository
and print `SKIPPED:` (and pass) when the Ruby of its `.ruby-version` is not found (`$VCI_TEST_RUBY_BIN`, `mise where
ruby@<version>`, or `ruby` on PATH) or `bundle check` fails for it; `crates/vci-adapter/tests/rails_collector.rs` runs
the collector's own tests the same way. They prove: attesting b skips only b, and Rails created the configured
`db/test.sqlite3` itself (`bin/rails db:test:prepare`, not refused); editing the fixture yml runs b and `explain` names
it; a model only b uses runs b alone; the view template runs c alone, and of the two files c could read only the one it
read matters; `config/routes.rb` runs d; a new file in
`app/models` that takes over a constant (`Calc`) runs a; `db/schema.rb`, a gem version in `Gemfile.lock` and
`.ruby-version` (another version, and the same one spelled differently) run everything; tampered payloads, unknown
signers and PR-only `allowed_signers` are rejected; a `hash` env var with another value runs b; each refusal
(backticks, `system`, a failure, a skip, no assertions, `ENV.to_h`, a write into `app/`, a read outside the repository,
a socket) while writing to `tmp/` is attested; rows written into `db/test.sqlite3` directly, its journal files, a
database in `storage/` and a fresh checkout without any database change no verdict, no manifest names them (a listing of
`db/` leaves them out), and a base `vci.toml` that still sets `rails_allow_db` parses and warns once; another SQLite
file, `ATTACH`, a `file:` name that merely contains `mode=memory`, and a database client a test opens itself
(`Mysql2::Client`, `PG::Connection`) are refused; a database server (SQLite registered under another adapter name) is
attested with no policy and `rubyDb` is its adapter name; in a multi-database app both schema files are inputs on a
fresh database (`db/cache_schema.rb` runs the test that uses it) and a non-SQLite file an entry names is an input; with
docker, a MySQL 8.0 test database (mysql2) is attested with no policy, `rubyDb` is `mysql2`, rows written into the
server and removing the server change nothing, and `establish_connection` or `new_client` to another server or
database is refused (`SKIPPED:` without docker); push/fetch into a fresh clone, `vci ci` running only the rest in one
`bin/rails test` process with exit codes and the audit log, `no_skip_refs`; `vci init --adapter rails`.
With the bundle installed into `vendor/bundle` inside the copy (`bundle install --local` from the archives this Ruby
already has, else from rubygems.org; `SKIPPED:` when neither works), every file attests and is skipped with nothing
under `vendor/bundle` as an input and the gem it read as an external, a stray file there changes nothing, and code,
reads, existence checks, `Gem.read_binary`, `Bundler.read_file`, a glob and `Gem::Specification.load` of what belongs
to no gem of the bundle, another Ruby's gems, and a test's check of `vendor/bundle` or of a gem's real path are
refused.

The node:test end-to-end tests (`crates/vci-cli/tests/e2e_node_test.rs`) copy `fixtures/node-test-abcd` (with `ms` from
`fixtures/vitest-abcd/node_modules`) and `fixtures/node-test-pnpm` into temporary repositories. They prove: attesting b
skips only b; editing `fixtures/b.json` runs b and `explain` names it with both hashes; creating the
`fixtures/b.local.json` b probed runs b; editing the computed import's target runs c alone, and so does creating the
`src/c.ts` the hook would resolve first; `src/a.ts` (reached through the hook's `@/` alias) runs a alone; the `--import`
hooks file, an option added to the script and the lockfile run everything; another installed `ms` version runs d; a
`hash` variable with another value and `NODE_OPTIONS` run everything, while the environment's `NODE_ENV` (the script
sets it) and `TEST_CONCURRENCY` (it only sets a dropped option) skip as before, and a `TEST_CONCURRENCY` that smuggles
in `--test-only` runs everything; tampered payloads, unknown signers and PR-only `allowed_signers` are rejected; each
refusal (a skipped or todo test, `describe.skip`, `test.only`, a failure, a child process, `process.exit`, no tests, a
write inside the repository, a read outside it) and each refused script (`--test-only`, `--test-name-pattern`,
`--test-isolation=none`, `--loader`, `--watch`, `&&`) attests nothing, and a script that is not `node --test` makes `vci
ci` run it with the package manager; push/fetch into a fresh clone gives the same plan, `vci ci` runs only the rest (and
fails when it fails), `no_skip_refs`; in the pnpm workspace, editing the workspace package's source or `package.json`
runs the file that uses it, the root `pnpm-lock.yaml` runs everything, and a new file matching the script's shell glob
is listed; `test_globs`/`node_args` in vci.toml replace the script; `vci init --adapter node-test` (printing the
command as `sh` reads it); a `pretest` that builds the test files, a listing without files, `.npmrc` `node-options` and
a `postinstall` script run everything (`vci ci` runs the script), while `patch-package` is accepted and a new file in
`patches/` runs the attested file; an unset `TZ` and an `--env-file` setting `NODE_OPTIONS=--test-name-pattern=...`
refuse the file.

The RSpec end-to-end tests (`crates/vci-cli/tests/e2e_rspec.rs`) copy `fixtures/rails-rspec-abcd` the same way (and
print `SKIPPED:` the same way, also when `bundle check` fails for it). They prove: attesting b skips only b (argv and
toolchain name RSpec and its gem versions), with the database prepared outside `db/` and no `spec/examples.txt`
written; editing b's factory runs b and `explain` names it, and so does its fixture yml; a new file in `spec/support`
runs every spec that loads `rails_helper` while a (`spec_helper` only) stays skipped; a new factory file runs b; the
shared example runs b; `.rspec` runs everything; the view runs c alone (and only the `file_fixture` it read matters);
`config/routes.rb` runs d; a new spec file elsewhere in `spec/` runs only itself; an `rspec-core` bump in
`Gemfile.lock` and `SPEC_OPTS` (declared) with another value run everything; tampered payloads, unknown signers and
PR-only `allowed_signers` are rejected. `~/.rspec`, `$XDG_CONFIG_HOME/rspec/options` and `.rspec-local` filter or break
a plain run but change nothing under vci (`vci run`, `plan`, `ci`). Each refusal: pending, `xit`, `xdescribe`, `fit`
and `fdescribe` with `filter_run_when_matching :focus`, an excluded tag, a failing example, a failing
`aggregate_failures` block, a load error, `before(:suite)` and `after(:context)` errors, no examples, backticks,
`system`, rspec-retry, parallel_tests, reading `Rails::CodeStatistics`, a write into `app/`, `--dry-run` and `--bisect`
from `SPEC_OPTS`; a pending migration is refused as a failure (the `db:test:prepare` child that loads the schema into
the configured database is Active Record's, not refused), and nothing but the test database is written in `db/`; rows
written into the test database directly change no verdict and no manifest names it; a
non-zero exit after RSpec's report (`at_exit { exit 1 }`, an `exit 2` like SimpleCov's, `minitest/autorun`); a retry
in an `around` hook, a prepended `Example#finish` and a reporter override that turn a failure into a pass. A spec that
sets `ENV["TMPDIR"]` still has its reads outside the repository refused, and Prism's `parse_file`,
`parse_file_success?` and `lex_file` reads are inputs (editing each file runs the spec). The
example status file is never written or read (`--only-failures` is refused). A spec stubbing `File.read`, `ENV[]`,
`Kernel.require`, `File.directory?`, `File.exist?` and `Dir.children` (and using `travel_to`) is attested with its
real reads, each of which then runs it. Push/fetch into a fresh clone and `vci ci` (only the rest, in one RSpec
process, non-zero on a failure, the whole suite on `no_skip_refs`); a Minitest app and an RSpec app in one
`vci.toml`; Minitest and RSpec files in one app (each with its own runner; a pattern overlap runs everything; `runner =
"rspec"` from the base commit lists only spec files, and `vci plan`/`ci` warn that the Minitest files are not run, also
in the audit log); a plain Ruby project with RSpec; `vci init --adapter rails`; the bundle installed into
`vendor/bundle` inside the copy (spec files attest and are skipped, nothing there is an input, and a stray file's
code, content, `Gem.read_binary` and a spec's check of `vendor/bundle` are refused).

The pytest end-to-end tests (`crates/vci-cli/tests/e2e_pytest.rs`, `crates/vci-adapter/tests/pytest_fixture.rs`)
copy `fixtures/pytest-abcd` the same way and print `SKIPPED:` (and pass) when `uv` is not installed or cannot set up
the fixture's environment. They prove the same steps for pytest (fixture edit, computed import target, shadowing
package, `conftest.py`, `uv.lock` and dependency changes, tampering, untrusted and PR-added signers, a `hash` env
var), each refusal (`subprocess`, failure, writes in the repo, env enumeration, outside reads), push/fetch into a fresh
clone, `vci ci` exit codes, and a repository with a Vitest and a pytest project.

The Go end-to-end tests (`crates/vci-cli/tests/e2e_go.rs`, `crates/vci-adapter/tests/go_fixture.rs`) copy
`fixtures/go-abcd` into a temporary repository and print `SKIPPED:` (and pass) when `go` is not installed or cannot
download the fixture's module (`golang.org/x/sync`). They prove: attesting b skips only b; editing its testdata (and
a file read during package initialisation) runs it and `explain` names the file; a file only a uses leaves b
skipped; a new `.go` file in b's directory, a change to the repository package b imports, a new file matching c's
`go:embed` pattern and the file c picks by name at run time each run the right package; a `//go:build linux` file is
hashed and marks the attestation platform-specific; a module bump in `go.mod`/`go.sum` runs everything; tampered
payloads, unknown signers and PR-only `allowed_signers` are rejected; a `hash` env var with another value in CI
runs b; each refusal (a child process, `net`, `os.Environ`, `syscall`, a read outside the repository, a failing
test, `t.Skip`, a change to the repository during the run); `go_allow_net` and `ignore_taints` (`go:net` and `go:syscall`) only with the base policy's consent;
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
PR-only `allowed_signers` are rejected; a `hash` env var with another value runs b; each refusal (a child process, a
failing test, `env::vars()`, a socket, no tests, an undeclared read outside the package that `[[inputs]]` then
allows, FFI, loose env mode); push/fetch into a fresh clone, `vci ci` exit codes, a missing `Cargo.lock`, cargo
missing; cfg predicates and runtime platform checks recorded (and evaluated against the real
`x86_64-unknown-linux-gnu` cfg set that rustc prints); `vci init --adapter cargo`; and on a copy of **vci's own
workspace**: `crates/vci-core#lib` is attested and then skipped, `crates/vci-git#test:repo` (runs `git`) is refused,
and editing `vci-core` runs it while editing `vci-git` does not. Regression tests for adversarial findings prove: a
build script's undeclared file, a listed variable read by a build script without `rerun-if-env-changed` or by a
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

The blobless exchange (since 2.0) has its own suite, `crates/vci-git/tests/store_lazy.rs`, which counts the objects in
each clone. It proves: a fresh clone fetches keys only and reads exactly the values it fetches; a push from a blobless
clone downloads nothing and drops nothing; a second fetch takes only what changed; diverged clones merge from paths
and push the union; `--rewrite-history` from a blobless clone keeps every value; offline, values read as not fetched;
a full clone and a server without filter support keep working, as does one refusing tree filters; set and list values
fall back to git-meta's full merge; the code repository is never made a partial or shallow clone; a merge base fetched
without its tree is completed; a stale blobless clone pushes after a prune, a history rewrite and a gc elsewhere; and
supersession fetches the attestations that could still reference a manifest before deleting it.
`e2e_cargo.rs` repeats the fetch and the plan in a blobless clone through the CLI, and the orphan manifest removal.

Keyless signing is tested offline (`crates/vci-attest/tests/keyless.rs`, the unit tests in
`crates/vci-attest/src/keyless/`, `crates/vci-cli/tests/e2e_keyless.rs`) against an envelope a GitHub Actions job of
this repository signed with `fulcio.githubapp.com` and `timestamp.githubapp.com`
(`crates/vci-attest/tests/fixtures/keyless/`), real responses of both timestamp authorities and the trust root `gh
attestation trusted-root` printed on 2026-10-16. They prove: the real envelope verifies and names the principal; a
tampered payload, signature or timestamp, an expired certificate, a timestamp in the future or of other data, a trust
root without the authority (or an intermediate with the same name and another key) and repository URIs on another host
all fail; an identity outside identities.toml is named; SSH verification rejects a keyless envelope; `vci verify` with
trust pinned on the command line does not use the repository's; and `vci run --oidc` without a token fails before
anything runs. The end-to-end proof (a job that attests with only `id-token: write`, then a plan that skips on its
word) is the `demo-oidc` job of `.github/workflows/ci.yml`.

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
- The externals check understands npm layouts (`node_modules` lookup plus npm's hidden lockfile) and pnpm's virtual
  store (`node_modules/.pnpm`); other layouts (Yarn Plug'n'Play) make tests with nested externals run.
- node:test: vci reads the test script with a subset of `sh` and refuses the rest (`&&`, pipes, substitutions): such
  projects set `test_globs`/`node_args`. What the collector cannot see: reads by the `module.register` hooks of
  `ts-node` and `amaro` (their configuration, `tsconfig.json`, is a global input instead), and native addons that open
  files themselves. Node's ICU takes the default locale from `LANG`/`LC_ALL`/`LC_MESSAGES` (recorded as env reads, so
  hashed) and nothing else; an unset `TZ` is refused. npm's builtin config file (`<npm dir>/npmrc`) is not read for
  `node-options`, and yarn Plug'n'Play layouts are not supported. Each file runs in its own `node --test` process, as node:test's default process isolation does; the
  `@vci/vitest` version is not part of the attestation (like the other collectors).
- Attestation metadata grows; `vci prune` deletes expired attestations (`--superseded`: and those a newer one of the
  same unit by the same signer replaced) and, since 1.9.0, the input manifests nothing references any more; `vci run`
  deletes the attestations a re-attestation supersedes on the same line of history (see "Where attestations live
  (git-meta)"); `vci push --rewrite-history` drops what was deleted from the published history, and git-meta's own auto-prune (`meta:prune:max-keys`) may drop the least recently written keys (those units
  then run). No spot-check re-runs or transparency log.
- What `vci fetch` and `vci push` read: since 1.8.2 the keys of a metadata tree come from its paths, and the fetched
  tree is materialized into the store only when its tip changed since the last time (recorded in the git directory),
  and the store is serialized only when it holds modified rows, so with nothing new neither reads a single
  attestation. Measured on a 1.8 GB store (3980 attestations) against a local copy of the remote: a fetch with
  nothing new took 51 s with 1.8.1 and takes 3 s; a push with nothing new, 206 s and 1.4 s. Since 1.9.0 a fetch whose
  tip did change applies only the tree entries that changed (when the local metadata commit is an ancestor of the
  tip): on a copy of that store (3805 attestations) with one attestation added, one deleted and one deletion record
  published, such a fetch took 31 s with 1.8.2 and takes 3.4 s (the merge itself 0.04 s), leaving a store identical
  to git-meta's full merge. The first fetch of a clone still parses the whole tree once (52 s on that store). Not
  fixed yet: once the local metadata tree holds a deletion record (a published `vci prune` or supersession), the
  check that the store covers `refs/meta/local/main` parses the whole tree in every fetch and push, tip changed or
  not: 11.8 s on that store, with 1.8.2 and 1.9.0 alike.
- Attestation size: since 1.9.0 an attestation references its input manifest instead of embedding it, and each
  distinct manifest is stored once. Measured on 10 cargo units of the same workspace attested into a scratch
  metadata remote: the attestation values went from 667,512 to 92,104 bytes (6 to 20 KB each instead of 14 to 241
  KB), the whole tree with the 7 distinct manifests they reference (303,655 bytes; the three test targets of one
  package share one) from 667,512 to 395,759 bytes (-41%), and a fresh clone's `vci fetch` downloaded 127,055 bytes
  instead of 184,800 (-31%). On a store that small, fetch and plan take 0.2 to 0.3 s with either version. What is
  left in an attestation is mostly `toolchain` (about 1.6 KB), `globalManifest` (1.3 KB), `waived` (up to 10 KB) and
  the signature; a manifest repeats each external crate's full source string. Attestations already published keep
  their inline manifest until the unit is re-attested (or `vci prune --superseded` and `vci push --rewrite-history`
  shed them).
- git-meta keeps its store per git directory; before 2.7.33 a linked worktree (`git worktree add`) therefore had its
  own `.git/worktrees/<name>/git-meta.sqlite`, each a full copy of the metadata paying its own fetch and merge (one
  laptop had 145 of them). Since 2.7.33 vci opens it on the common git directory, so all worktrees share one store
  (see "One store per repository"); the stock `git meta` CLI run in a linked worktree still uses that worktree's own
  file, which vci does not read.
- git-meta's auto-prune and filter rules are shared settings any metadata writer can change (see above): vci warns,
  but cannot stop another client's `git meta push` from pruning attestations (their units then run until re-attested).
  A manual `git meta prune` rewrites only the serialized tree; while the store still holds the values, the next `vci
  push` publishes them again (vci serializes the whole store). Delete attestations with `vci prune` (deletion records).
- A tree entry git-meta cannot read is left out and warned about; if a non-git-meta writer keeps such an entry on the
  remote while moving it, the merge can still need the old commit and fail (an error: everything runs).
- `vci plan` reads `.git/git-meta.sqlite` read-only (a read-only `.git` works; when SQLite cannot open it in WAL mode
  without writing, the file is read as it is, so changes still only in its `-wal` file are not seen: those units
  run). A value that cannot be read (its blob missing from the object database) fails only its own candidate.
- `vci fetch` and `vci push` need the remote to serve partial clones (`uploadpack.allowFilter`, as GitHub does); a
  server that ignores the filter sends every value, which then reads as before 2.0 (one that refuses tree filters
  gets `--filter=blob:none` for the first fetch too). Values, and a tip's tree, are fetched by object id from the
  primary git-meta remote, which must allow that (protocol v2 servers do for reachable objects). Promised rows `git
  meta pull` writes for keys of earlier commits (its history index) stay not fetched: vci fetches the values of the
  local metadata commit's tree only.
- What a blobless metadata fetch changes in the repository (since 2.0): git accepts objects left out of a fetch
  (`git gc`, `git fsck`, connectivity checks) only with a *promisor* remote configured, and asks a promisor remote
  for any object it misses, code included, with that object's whole history. vci therefore never records the
  metadata remote as one (its own fetches say so on their command line, `-c remote.<name>.promisor=true`); it
  configures `remote.vci-no-lazy-fetch.promisor = true`, a remote without a URL (`skipFetchAll`,
  `skipDefaultUpdate`: `git fetch --all` and `git remote update` leave it alone; `git remote` lists it). A git
  command that looks up an object this clone lacks (a commit outside a shallow checkout, a metadata value) then fails
  at once, as before 2.0, after git tries that remote (`fatal: 'vci-no-lazy-fetch' does not appear to be a git
  repository`), instead of downloading it; vci's own commit lookups (the base ref, supersession's ancestry checks)
  also set `GIT_NO_LAZY_FETCH=1` (git 2.45 and later, and the 2024 security releases 2.39.4 to 2.44.1, honour it; with an
  older git they rely on that remote failing). Reading the metadata history's values with plain git (`git log --all -p`,
  `git show refs/meta/...:<path>`) fails for values never fetched. The repository is never made shallow by vci:
  `.git/shallow`, `git rev-parse --is-shallow-repository` and `git fetch --unshallow` only ever concern the code.
  `core.repositoryformatversion` is left alone.
- Moving a clone to 2.0 is one way: a vci before 2.0 run in a clone 2.0 fetched into fails its fetch and push
  (`git-meta: An object with id ... could not be found`: git-meta reads every value of the trees it merges) and
  runs every unit in a plan. To go back, push what is stored with 2.0, then download every value as a 1.9 fetch
  would and rebuild the store from the local metadata commit:
  `git fetch --refetch <metadata remote> '+refs/meta/main:refs/meta/remotes/main'` (git 2.36 or later; the whole
  metadata history, values included) and `rm -f .git/git-meta.sqlite* .git/vci-materialized-*`; `git config
  --remove-section remote.vci-no-lazy-fetch` is then optional. Checked on the vex copy above: 1.9.2's fetch restores
  every entry and its plan matches 2.0's, and `git gc` and `git fsck` pass with and without that remote. Fresh CI
  clones are not affected.
- pytest: the adapter requires uv (`uv run --locked --exact`, which removes packages not in `uv.lock` from the
  project environment and syncs only the default dependency groups, so pytest must be in them); plain virtualenvs or
  Poetry are not supported yet. The `vci_pytest` version is not part of the attestation (as with `@vci/vitest`), so a
  collector fix does not by itself invalidate older attestations (the toolchain fields added with this version do:
  older pytest attestations never match). `vci plan` lists the test files from pytest's collection rules without
  starting Python (see "Which files are test files" under the pytest quick start): what conftest.py files and plugins
  decide about collection is not seen, and a file that fails to import is listed and fails its own run (it no longer
  makes the plan run everything).
- Go: the adapter needs a module (GOPATH mode is not supported) and runs tests natively (`GOOS`/`GOARCH` must be
  the host's). The overlaid logger compiles for Unix only (it uses `syscall.Open` with an `int` descriptor): on
  Windows every package fails to build under `vci run` and is refused. Its source is not part of the attestation,
  like the other collectors. Test ids are package directories, so `vci run`/`explain` take directories, not files.
- Cargo: the adapter decides inputs conservatively and refuses from source text (see "Cargo limitations"); test ids
  are `<package dir>#<target>`, so `vci run`/`explain` take unit ids or package directories, not files.
- Rails: Minitest and RSpec; the unit is a test or spec file, so `vci run`/`explain` take files (not directories). The
  collector's source is not part of the attestation, like the other collectors (its version is). RSpec under vci
  never reads `.rspec-local`, `~/.rspec` or the XDG options file, and requires every declared example of a file to
  run (see "RSpec limitations"); an RSpec example without expectations is attested. An explicit `runner` leaves the
  other runner's files unrun by vci (`vci run`, `plan` and `ci` warn). C code a test calls that opens files itself is
  not seen, apart from the libraries the collector hooks (and refuses when it cannot): of Ruby's own extensions,
  `openssl`, `zlib`, `etc`, `pty`, `fiddle`, `socket` and `RubyVM::InstructionSequence.compile_file` are hooked;
  `io/console` (`IO.console` opens the terminal) and `Etc.uname`/`Etc.sysconf` (the machine) are not.
- Other adapters' collectors (Vitest, node:test, pytest) report paths as spelt; vci drops their reads of its own
  collector directory only when the real path is there, but a symlink in that directory created and removed by a test
  can no longer be resolved after the run (the Rails collector resolves paths when they are used).
- Only tested on macOS arm64 (Node 26, git 2.54, OpenSSH 10.3; CPython 3.14.7, uv 0.11.7; Go 1.26.2; Rust 1.96.0
  from Homebrew; Ruby 3.4.9 through mise), plus a `linux/amd64` container check of Rails attestations (Minitest and
  RSpec: `docs/spike-rails.md` F14, R14). Not run on a GitHub Actions runner. Windows paths compile but are untested.

## License

MIT License. See [LICENSE](../LICENSE).
