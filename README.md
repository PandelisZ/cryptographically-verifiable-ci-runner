# vci: cryptographically verifiable CI test selection

If a developer (or an agent) already ran test file `b.test.ts` (or `test_b.py`) against exactly the files it depends
on, CI should not have to run it again. `vci` makes that safe:

1. `vci run` runs Vitest or pytest with runtime dependency collectors, hashes every file, directory listing,
   missing-file probe, package version and env var each test file actually used, and signs an in-toto attestation with
   your SSH key.
2. Attestations are stored content-addressed in git refs (`refs/attest/v1/<signer>`) and shared with `vci push`.
3. In CI, `vci plan` checks each attestation against the **base commit's** `.vci/allowed_signers` and `vci.toml`,
   re-hashes every recorded input from CI's own checkout, and skips a test file only when everything matches.
   `vci ci` then runs the rest.

The core rule is **fail open**: the default verdict is RUN. Any error, doubt or unrecognised behaviour means the test runs.

Status: v1, Vitest `>=3.2 <6` (tested on 5.0.2 and 4.1.11), Node 22.15+; pytest 9 (tested on 9.1.1) on CPython
3.11-3.14 through `uv`; macOS and Linux.

## Quick start (Vitest)

Prerequisites: `git`, `node`, `ssh-keygen` (OpenSSH 8.1+), a Rust toolchain to build the CLI.

```sh
cargo install --path crates/vci-cli            # installs the `vci` binary

cd your-project                                # a git repo with at least one commit
npm install --save-dev /path/to/js/vitest-plugin   # the @vci/vitest collectors
#   (or leave it out and set VCI_JS_PLUGIN=/path/to/js/vitest-plugin)

vci init --key ~/.ssh/id_ed25519.pub --no-install  # writes vci.toml and .vci/allowed_signers
git add vci.toml .vci/allowed_signers && git commit -m "Enable vci"
# The trust root is read from the base branch, so merge this commit to main first.

vci run src/b.test.ts --key ~/.ssh/id_ed25519   # run, collect, sign, store
vci plan --base-ref origin/main                 # SKIP src/b.test.ts, RUN the rest
vci push                                        # share attestations (refs/attest/v1/*)
```

In CI (see [`examples/github-actions.yml`](examples/github-actions.yml)):

```sh
vci fetch --remote origin
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
git add vci.toml .vci/allowed_signers uv.lock .python-version && git commit -m "Enable vci"

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

When something is not skipped and you expected it to be:

```sh
vci explain src/b.test.ts --base-ref origin/main
```

```
src/b.test.ts: RUN (no valid attestation (1 candidates; best failed inputs: entry:fixtures/b.json))
candidate 1: refs/attest/v1/b6c35e2a042def43 key 2002a8ce…
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
| `vci init [--key K] [--principal P] [--project DIR] [--adapter vitest\|pytest] [--no-install]` | Write `vci.toml` and `.vci/allowed_signers` (adding key `K`), `npm install` `@vci/vitest` (Vitest), print a CI snippet |
| `vci run [FILES…] [--key PATH] [--ttl 14d]` | Run tests with collection on; sign and store an attestation for every attestable file. Exit code is the runner's (non-zero if any pytest process failed) |
| `vci plan [--base-ref R] [--format text\|json\|github]` | Print which test files can be skipped and why the others run |
| `vci ci [--base-ref R] [--audit-log PATH]` | Plan, run the remainder, write a JSON audit log of every skip |
| `vci verify <envelope\|-> [--allowed-signers F] [--base-ref R]` | Verify one DSSE envelope and print its claims |
| `vci push` / `vci fetch` `[--remote origin]` | Sync `refs/attest/v1/*` (union merge, retried on races) |
| `vci explain <test-file> [--base-ref R]` | Every candidate attestation and the first check it failed, with expected vs actual |

Signing key: `--key`, else `$VCI_SIGNING_KEY`, else `git config user.signingkey` when `gpg.format = ssh` (a GPG
signing key is never used). Errors name the source the key came from. A `.pub` path works when the private
half is in `ssh-agent` (hardware keys included). The signer id (ref name) is the first 16 hex chars of SHA-256 over the
public key blob.

Base ref: `--base-ref`, else `$VCI_BASE_REF`, else `origin/$GITHUB_BASE_REF`, else the first of `origin/HEAD`,
`origin/main`, `origin/master`, `main`, `master` that exists. If none resolves, everything runs. The base ref is the
trust boundary: `vci plan` prints a warning (and `--format json` lists it under `warnings`) when the base commit is
HEAD or contains it, because then `allowed_signers` and policy come from the commit under test.

Environment: `VCI_JS_PLUGIN` (path of the `@vci/vitest` package; default `node_modules/@vci/vitest` above the
project), `VCI_NODE` (node binary), `VCI_PY_PLUGIN` (the `py/pytest-plugin` directory holding `vci_pytest`; default:
`py/pytest-plugin` or `share/vci/pytest-plugin` above the `vci` executable, then the source checkout `vci` was built
from, then `py/pytest-plugin` above the project; a clear error names the variable when none is found), `VCI_UV` (uv
binary), `VCI_JOBS` (parallel pytest processes in `vci run`).

Strict env mode removes every variable that is not declared or pass-through from the test process, including
`NO_COLOR` and `FORCE_COLOR`, so `NO_COLOR=1 vci ci` still prints Vitest's colours. Add them to `pass_through` (seen
by tests, not hashed) or `global` (hashed) if you need them; they are not built in because a test's result can
depend on them.

Built-in pass-through variables (`PATH`, `HOME`, `USER`, `TMPDIR`, `LANG`, `LC_*`, `TERM`, `CI`, ...) are always
visible, and **hashed when a test file is observed reading one** (except `VCI_*`, `VITEST*`, `NODE_OPTIONS`): their
values differ between a laptop and a CI runner, so a test that reads `CI` is not skipped on a runner. Configured
`pass_through` variables stay unhashed (your decision).

pytest adds its own built-in pass-through so that `uv` works in strict mode: `UV`, `UV_*`, `VIRTUAL_ENV`,
`XDG_{CACHE,CONFIG,DATA,BIN}_HOME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, the `*_PROXY` variables, and `PYTHONPATH` (vci
sets it to the collector directory; your value never reaches the tests, and a test that reads it is not attested).
`PYTEST_*` and `PYTHON*` are **hashed**: the collector reports `PYTEST_ADDOPTS`, `PYTEST_PLUGINS`,
`PYTEST_DISABLE_PLUGIN_AUTOLOAD`, `PYTHONHASHSEED`, `PYTHONWARNINGS`, `PYTHONOPTIMIZE`, ... and `TZ` as read by every
file (the interpreter and pytest read them before any hook runs), and every `PYTHON*`/`PYTEST_*` variable present
in the test environment is hashed (the interpreter reads `PYTHON_CPU_COUNT`, `PYTHONBREAKPOINT`, `PYTHON_GIL`, ...
in C). Strict mode removes them unless declared, so they hash as unset on both sides; to set one, declare it in
`[env] global` and its value is hashed.

## `vci.toml`

```toml
project = "."          # project dir (Vitest root / pytest rootdir), relative to the repo root
adapter = "vitest"     # or "pytest"

[policy]
platform = "any"       # "any" | "same-os" | "exact": which OS/arch may satisfy CI
max_ttl = "30d"        # longest accepted attestation lifetime
allow_dirty = true     # accept attestations made from an uncommitted working tree
no_skip_refs = ["refs/heads/main", "refs/tags/**"]   # never skip on these refs (the `vci init` default)
never_skip = ["tests/test_attach_db.py"]             # never skip these files (project-relative globs)

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
```

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
project); `vci plan --format json` names each file's `project` and lists `projects` with a per-project `runAll`, and
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
7. **toolchain**: Node major, Vitest, Vite (pytest: exact Python version, implementation, pytest), and OS/arch per
   policy;
8. **env-config**: digest of the effective env configuration (from the base `vci.toml`) matches;
9. **result**: passed and untainted; **dirty** only if `allow_dirty = false`;
10. **global-inputs**: every attested global entry re-hashed from the checkout, and the current global input set
    has the same root;
11. **inputs**: every attested per-file entry re-hashed (files, symlinks, directory listings, directory types,
    absences); pytest: no native extension module for another platform (`b.cpython-314-x86_64-linux-gnu.so`,
    `b.cp314-win_amd64.pyd`) next to a probed extension candidate;
12. **externals**: every `name@version` is what is installed now (pytest: in the `uv run --locked` environment, and
    pinned by `uv.lock`);
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
  but only through the patched Node APIs), data captured before the collectors were installed.
- Test code deliberately evading the collectors.
- Malicious `node_modules` that match the lockfile and package versions (packages are identified by version, not by
  file hashes).
- A CI job whose `--base-ref` points at a ref the pull request controls (its head or merge commit, or `HEAD`). Pass
  the base branch's commit (`github.event.pull_request.base.sha`, as in the example workflow). `vci plan` warns when
  the base commit is HEAD or contains it.
- Third-party Vite plugins (code under `node_modules`) reading files in the main process: only their package version
  is an input. Reads by the config file itself, inline plugins and globalSetup files are recorded.
- Timezone and locale in strict mode: `TZ` reaches tests only if declared (then hashed); the system timezone and
  `LANG`/`LC_*` (built-in pass-through) are not hashed. In loose mode `TZ` is always hashed.

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

## Layout

```
crates/vci-core       repo paths, input manifests, input roots, predicate types
crates/vci-attest     in-toto Statement, DSSE + PAE, SSHSIG verification, allowed_signers, ssh-keygen signing
crates/vci-git        attestation refs (plumbing only), base-commit file reads, repo identity
crates/vci-adapter    Adapter trait + Vitest and pytest adapters (list, run, JSONL parsing)
crates/vci-cli        the `vci` binary
js/vitest-plugin      @vci/vitest collectors
py/pytest-plugin      vci_pytest collector (pure stdlib pytest plugin)
fixtures/vitest-abcd  Vitest end-to-end fixture
fixtures/pytest-abcd  pytest end-to-end fixture (uv project)
docs/                 PLAN.md (design), CONTRACTS.md (interfaces), ENV.md (env vars), spike.md (Vitest findings),
                      spike-pytest.md (pytest findings)
```

## Development

```sh
cargo test --workspace                     # unit + integration + end-to-end (needs node, git, ssh-keygen)
cargo clippy --workspace --all-targets -- -D warnings
(cd fixtures/vitest-abcd && npm ci)        # the fixture's node_modules, used by the e2e tests
(cd js/vitest-plugin && npm test)          # collector tests
uv run --project fixtures/pytest-abcd pytest py/pytest-plugin/tests   # pytest collector tests
```

The pytest end-to-end tests (`crates/vci-cli/tests/e2e_pytest.rs`, `crates/vci-adapter/tests/pytest_fixture.rs`)
copy `fixtures/pytest-abcd` the same way and print `SKIPPED:` (and pass) when `uv` is not installed or cannot set up
the fixture's environment. They prove the same steps for pytest (fixture edit, computed import target, shadowing
package, `conftest.py`, `uv.lock` and dependency changes, tampering, untrusted and PR-added signers, a declared env
var), each refusal (`subprocess`, failure, writes in the repo, env enumeration, outside reads), push/fetch into a fresh
clone, `vci ci` exit codes, and a repository with a Vitest and a pytest project.

The end-to-end test (`crates/vci-cli/tests/e2e.rs`) copies `fixtures/vitest-abcd` into a temporary git repo with a
bare remote and throwaway SSH keys and proves every step of "End-to-end verification" in `docs/PLAN.md`, plus
expiry, foreign-repo replay, push/fetch into a fresh clone, `vci ci`, `no_skip_refs`, missing base policy, and each
reason `vci run` refuses to attest.

## Known gaps

- Vitest config imports are found by scanning for relative string literals (per-module `tsconfig.json` files and
  custom snapshot paths are covered by the collectors, see "What is hashed").
- External packages are identified by `name@version`: editing code inside `node_modules` without changing the
  version is not noticed (documented above; hashing reached package directories would be a stricter policy).
- Resolution candidates follow Node's and Vite's default extension lists plus `resolve.extensions`; custom resolvers
  in third-party plugins (e.g. tsconfig `paths` plugins) are covered only through the modules they resolve to.
- `DirListing` includes ignored files, so listings of directories with build output differ between machines (those
  tests run; never a false skip).
- The externals check understands npm layouts (`node_modules` lookup plus npm's hidden lockfile); other layouts make
  tests with nested externals run.
- Attestation refs grow; there is no `vci prune` yet. No spot-check re-runs or transparency log.
- pytest: the adapter requires uv (`uv run --locked --exact`, which removes packages not in `uv.lock` from the
  project environment and syncs only the default dependency groups, so pytest must be in them); plain virtualenvs or
  Poetry are not supported yet. The `vci_pytest` version is not part of the attestation (as with `@vci/vitest`), so a
  collector fix does not by itself invalidate older attestations (the toolchain fields added with this version do:
  older pytest attestations never match). `vci plan` imports every test module (`pytest --collect-only`) to list
  files; a collection error runs everything.
- Only tested on macOS arm64 (Node 26, git 2.54, OpenSSH 10.3; CPython 3.14.7, uv 0.11.7). Windows paths compile
  but are untested.
