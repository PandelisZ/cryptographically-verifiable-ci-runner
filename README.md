# vci: cryptographically verifiable CI test selection

If a developer (or an agent) already ran test file `b.test.ts` against exactly the files it depends on, CI should not
have to run it again. `vci` makes that safe:

1. `vci run` runs Vitest with runtime dependency collectors, hashes every file, directory listing, missing-file probe,
   package version and env var each test file actually used, and signs an in-toto attestation with your SSH key.
2. Attestations are stored content-addressed in git refs (`refs/attest/v1/<signer>`) and shared with `vci push`.
3. In CI, `vci plan` checks each attestation against the **base commit's** `.vci/allowed_signers` and `vci.toml`,
   re-hashes every recorded input from CI's own checkout, and skips a test file only when everything matches.
   `vci ci` then runs the rest.

The core rule is **fail open**: the default verdict is RUN. Any error, doubt or unrecognised behaviour means the test runs.

Status: v1, Vitest `>=3.2 <6` (tested on 5.0.2 and 4.1.11), Node 22.15+, macOS and Linux.

## Quick start

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
| `vci init [--key K] [--principal P] [--project DIR] [--no-install]` | Write `vci.toml` and `.vci/allowed_signers` (adding key `K`), `npm install` `@vci/vitest`, print a CI snippet |
| `vci run [FILES…] [--key PATH] [--ttl 14d]` | Run tests with collection on; sign and store an attestation for every attestable file. Exit code is Vitest's |
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
project), `VCI_NODE` (node binary).

Strict env mode removes every variable that is not declared or pass-through from the test process, including
`NO_COLOR` and `FORCE_COLOR`, so `NO_COLOR=1 vci ci` still prints Vitest's colours. Add them to `pass_through` (seen
by tests, not hashed) or `global` (hashed) if you need them; they are not built in because a test's result can
depend on them.

## `vci.toml`

```toml
project = "."          # Vitest project dir, relative to the repo root
adapter = "vitest"

[policy]
platform = "any"       # "any" | "same-os" | "exact": which OS/arch may satisfy CI
max_ttl = "30d"        # longest accepted attestation lifetime
allow_dirty = true     # accept attestations made from an uncommitted working tree
no_skip_refs = ["refs/heads/main", "refs/tags/**"]   # never skip on these refs

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

## When `vci run` refuses to attest

A test file gets no attestation (and will run in CI) if any of these hold:

- a collector tainted it: child processes, network (including `new net.Socket().connect()` and `dgram` sockets),
  `worker_threads`, `fetch`, enumerating `process.env`, recursive readdir/glob, snapshot writes, `isolate: false`,
  vm/browser pools, experimental module caches, typecheck mode, or any of these done by the Vitest config or a
  globalSetup file in the main process (that taints every file of the run);
- it did not pass (failed, skipped, missing result);
- any input lies outside the repository (e.g. a read of `/etc/hosts` or an unowned temp file);
- any input changed during the run: the working tree's metadata (size, mtime, ctime, inode, mode) is snapshotted
  before the run and every attested entry must be untouched afterwards, and the global inputs (including snapshot
  files) are hashed before and after. Hard-linking a repository file (`fs.link`) changes its ctime and link count, so
  a test that links a fixture into a temp dir is refused;
- two inputs collide under case folding, a symlink leaves the repo, the collector's toolchain differs from the
  project's, or the test file is listed under more than one Vitest project.

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
7. **toolchain**: Node major, Vitest, Vite, and OS/arch per policy;
8. **env-config**: digest of the effective env configuration (from the base `vci.toml`) matches;
9. **result**: passed and untainted; **dirty** only if `allow_dirty = false`;
10. **global-inputs**: every attested global entry re-hashed from the checkout, and the current global input set
    has the same root;
11. **inputs**: every attested per-file entry re-hashed (files, symlinks, directory listings, absences);
12. **externals**: every `name@version` is what is installed now;
13. **env**: every hashed variable has the same value, and every variable that matches a declared pattern in CI is
    covered by the attestation.

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

## Layout

```
crates/vci-core       repo paths, input manifests, input roots, predicate types
crates/vci-attest     in-toto Statement, DSSE + PAE, SSHSIG verification, allowed_signers, ssh-keygen signing
crates/vci-git        attestation refs (plumbing only), base-commit file reads, repo identity
crates/vci-adapter    Adapter trait + Vitest adapter (list, wrapper config, run, JSONL parsing)
crates/vci-cli        the `vci` binary
js/vitest-plugin      @vci/vitest collectors
fixtures/vitest-abcd  end-to-end fixture
docs/                 PLAN.md (design), CONTRACTS.md (interfaces), ENV.md (env vars), spike.md (Vitest findings)
```

## Development

```sh
cargo test --workspace                     # unit + integration + end-to-end (needs node, git, ssh-keygen)
cargo clippy --workspace --all-targets -- -D warnings
(cd fixtures/vitest-abcd && npm ci)        # the fixture's node_modules, used by the e2e tests
(cd js/vitest-plugin && npm test)          # collector tests
```

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
- Only tested on macOS arm64 (Node 26, git 2.54, OpenSSH 10.3). Windows paths compile but are untested.
