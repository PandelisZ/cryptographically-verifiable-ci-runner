---
name: vci
description: Run tests locally with vci (cryptographically verifiable CI), sign an attestation of exactly what they depended on, push it through git, and let CI skip those tests. Use when the user or an agent wants to run tests with proof, attest tests, skip already-run tests in CI, speed up CI for a pull request, or set up vci / verifiable CI (vci init, allowed_signers, the PandelisZ/cryptographically-verifiable-ci-runner GitHub Action), and when diagnosing why vci did not skip a test or refused to attest one. Covers Vitest, pytest (uv), Go, Cargo, Rails Minitest and RSpec. Triggers include "vci", "attest", "attestation", "verifiable CI", "skip tests in CI", "vci.toml", "allowed_signers", "identities.toml", "vci --oidc", "refs/meta/main".
license: MIT
compatibility: Needs the vci CLI (brew install pandelisz/tap/vci), git, ssh-keygen (OpenSSH 8.1+) and the project's test toolchain, on macOS or Linux.
metadata:
  homepage: https://github.com/PandelisZ/cryptographically-verifiable-ci-runner
  vci-version: "2.0.0"
---

# vci: run tests once, prove it, let CI skip them

vci runs a project's tests with a collector attached, records every input each test unit actually used, signs that
record with an SSH key, and stores it in git (git-meta on `refs/meta/main`). In CI, the vci GitHub Action checks each
record against the base branch's trusted keys and policy, re-hashes every input from its own checkout, and skips a
unit only when everything matches. Everything else runs.

## When to use this skill

- After you change code in a repository that has a `vci.toml` at its root: attest the tests that cover the change so
  CI can skip them.
- The user asks to "run the tests with proof", "attest", "make CI skip these", "set up vci", or asks why a test was
  not skipped or not attested.
- Not for repositories without `vci.toml`, unless the user asks to set vci up (see "Set up a repository").

## Mental model

1. **Unit**: the smallest skippable thing: a test file (Vitest, pytest, Minitest, RSpec), a Go package directory, a
   cargo test target (`crates/x#lib`, `crates/x#test:name`).
2. **`vci run <units>`** runs each unit in its own process, records what it read, and signs an attestation; only
   units whose tests all ran and passed, with nothing unobservable going on, are attested.
3. **`vci push`** publishes attestations on `refs/meta/main`; there is no server.
4. **Trust and policy come from the base branch** (`.vci/allowed_signers`, `vci.toml` at the PR's base commit, and
   for CI jobs that sign keylessly with their OIDC token `.vci/identities.toml` and `.vci/sigstore-trusted-root.json`),
   never from the pull request.
5. **Fail open**: any mismatch means the unit runs. A mistake can only cost a skip, never cause a wrong one.

## Before you start

Run these once per session and stop to tell the user if something is missing:

```sh
vci --version                                   # installed? (brew install pandelisz/tap/vci)
git rev-parse --show-toplevel                   # run vci from the repository root
test -f vci.toml && sed -n '1,40p' vci.toml     # set up? which adapter(s) and project dirs, [env] set/hash/ignore
git branch --show-current                       # must not be the default branch (see below)
git fetch origin                                # so origin/main is the real base
echo "${VCI_SIGNING_KEY:-unset}"                # signing key, or pass --key
```

- **Signing key**: `--key <path>`, else `$VCI_SIGNING_KEY`, else `git config user.signingkey` when
  `gpg.format = ssh`. Use the key the user gave you. Never generate a key and start using it silently.
- **Is the key trusted?** Compare its public key with the base branch's trust file:
  `git show origin/main:.vci/allowed_signers` and `ssh-keygen -y -f "$VCI_SIGNING_KEY"` (or the `.pub`). If it is not
  listed, attestations still work locally but CI will reject them (`failed check: signer`). Tell the user; do not
  edit `allowed_signers` yourself.
- **Default branch**: `vci init` puts `refs/heads/main` in `policy.no_skip_refs`, so on `main` `vci plan` prints
  `running everything: policy.no_skip_refs matches refs/heads/main` (or, when `policy.no_skip_refs_except` names
  CI's own key, skips only what that key attested). Work on a feature branch.
- **Environment**: only the variables `[env]` and the runner's short built-in lists name reach tests (`vci env` lists
  them). `[env] set` values (commonly `TZ`, `CGO_ENABLED`) are set by vci on both sides; nothing to export. Every
  variable in `[env] hash` must have the same value locally as in CI.

## Workflow after a code change

Do this after your last edit to anything the tests read. An edit after `vci run` invalidates the attestation
(`failed check: inputs`), so re-run then.

### 1. Find the units that cover the change

Use the helper script in this skill's directory (it reads `vci.toml`, diffs against the merge base with
`origin/main`, and maps changed files to units per runner):

```sh
<skill-dir>/scripts/units-for-change.sh            # units on stdout, reasons on stderr
<skill-dir>/scripts/units-for-change.sh --base origin/develop
<skill-dir>/scripts/units-for-change.sh path/to/changed_file.py   # explicit files instead of git diff
```

A stderr line `ALL <project>: <file> ...` means a global input changed (lockfile, runner config, `vci.toml`,
`Gemfile.lock`, `config/**` in Rails): every unit of that project depends on it, so attest all of them
(`vci run` with no arguments attests every unit of every project; it can take as long as the full suite, so say so).
`no unit found by name or import` means the file may be read through a computed path: consider the whole project.

The script is a heuristic. Use your own knowledge of the code too. Suggesting too much only costs local time;
missing a unit only means CI runs it. Unit ids by runner:

| Runner | Pass to `vci run` | Notes |
|---|---|---|
| Vitest | `src/b.test.ts` | test files; a changed source file → the test files that import it |
| pytest | `tests/test_b.py` | test files; `conftest.py` → every test file under it |
| Go | `svc/store` or `./svc/store` | package directories with `_test.go`, never `.go` files; include packages that import the changed one |
| Cargo | `'crates/b#test:it'`, `crates/b#lib`, or `crates/b` (all units) | include workspace crates that depend on the changed crate |
| Rails | `test/models/b_test.rb`, `spec/models/b_spec.rb` | files, never directories |

Paths are relative to the current directory; the script prints repo-relative ids, so run from the repository root.
Any argument that is not a listed unit aborts the whole run (`... is not a test file of any project`).

### 2. Run and attest

```sh
cd "$(git rev-parse --show-toplevel)"
vci run tests/test_orders.py tests/test_pricing.py --key ~/.ssh/vci-agent   # or with VCI_SIGNING_KEY set
```

Read every line of the output, not only the exit code:

- `vci: attested <unit> (<n> inputs, root <hash>) as git-meta ...`: signed and stored locally.
- `vci: not attesting <unit>: <reason>`: no attestation; CI will run it. See [refusals](references/refusals.md).
- `vci: warning: ...`: often means "this will not match in CI" (reads `CI`, `.DS_Store` in a listing, git-ignored
  inputs). Act on it or report it.
- Last line: `vci: <a> attested, <r> not attested`. The exit code is the test runner's: non-zero if any test failed.
  A refused unit can still exit 0.

If tests fail: fix the code and run again. If a refusal is caused by your change (a new subprocess call, a write
inside the repository, a skipped test), fix that if appropriate; otherwise leave the unit unattested and report why.

### 3. Check what CI will do

```sh
vci plan --base-ref origin/main
```

Each attested unit should show `SKIP <unit> (attested by <you> (...))`. For any unit you expected to skip that shows
`RUN`, run `vci explain <unit> --base-ref origin/main` (see "Diagnose" below). Units listed as `RUN (no attestation)`
that you did not touch are normal: CI runs them.

To list only what CI will run:

```sh
vci plan --base-ref origin/main --format json \
  | python3 -c 'import json,sys; [print(f["testId"]) for f in json.load(sys.stdin)["files"] if not f["skip"]]'
```

### 4. Share

```sh
vci push        # publishes attestations (git-meta push of refs/meta/main); "nothing to push" is fine
git push        # the branch, as usual
```

Push only when the user wants the branch pushed (or it is the agreed workflow). Push the attestations before or
together with the branch: CI fetches `refs/meta/main` when the job starts. `vci push` needs push access to the
metadata remote; if it is refused, report it (the user may need to grant the agent access to `refs/meta/main`).
`vci push` goes to the configured git-meta remote, else the URL in the committed `.git-meta` file: in a scratch clone
or fork that is still the upstream repository, so never run it from a throwaway checkout.

### 5. Report

Tell the user, briefly: which units were attested, which were refused and why (one line each), the `vci plan`
summary line (`N to skip, M to run`), and whether attestations and the branch were pushed.

## Set up a repository

Only when the user asks. Full steps, workflow YAML for every runner and the security rules:
[references/ci-setup.md](references/ci-setup.md).

```sh
vci init --adapter pytest --key ~/.ssh/id_ed25519.pub --principal you@example.com   # vitest | pytest | go | cargo | rails
# writes vci.toml, .vci/allowed_signers, .git-meta; review them with the user
git add vci.toml .vci/allowed_signers .git-meta && git commit -m "Enable vci"
# then merge to the default branch: trust and policy are read from there
```

In the workflow, after checkout (`fetch-depth: 0`) and the toolchain setup steps:

```yaml
- uses: PandelisZ/cryptographically-verifiable-ci-runner@v2
```

Remind the user to: add each signer (agents with their own key and a `valid-before` expiry) to
`.vci/allowed_signers` on the default branch; pin toolchain versions identically locally and in CI
([runners](references/runners.md)); keep `refs/heads/main` in `no_skip_refs`; never use `pull_request_target` or a
`container:` job for this.

Optionally, CI can attest its own runs: with a key of its own (the action's `signing-key`, `vci ci --key K --push
--remote origin`), each push to main attests what it ran and the next commit skips every unit whose inputs did not
change. It needs a key the user creates, its line in `allowed_signers`, `no_skip_refs_except = ["<its principal>"]`
in `vci.toml`, a GitHub Environment secret limited to the default branch, and a main-only job with
`permissions: contents: write`. Since vci 2.0 it can do without a key: the action's `oidc: true` (`vci ci --oidc`)
signs with the job's OIDC token through Sigstore (`permissions: id-token: write`, no secret), trusted through
`.vci/identities.toml` and the trust root that `vci init --oidc` writes. Steps for both:
[references/ci-setup.md](references/ci-setup.md) ("Let CI attest its own runs"). Propose it; do not set it up
unasked.

## Diagnose "not skipped"

```sh
vci fetch                                      # get attestations others pushed (CI fetches them itself)
vci explain <unit> --base-ref origin/main
```

Since vci 2.0 `vci fetch` downloads the keys of the metadata, not its values; `plan` and `explain` fetch the values
they read from the metadata remote. Offline, those candidates fail `envelope` with ``unreadable: value not fetched:
run `vci fetch` online``: run again with network access.

`explain` prints every candidate attestation and the first check it failed, with `expected` (recorded) and `actual`
(this checkout). Most common:

| `failed check:` | Usual cause | Action |
|---|---|---|
| `inputs` | A file changed after attesting (`entry:<path>` names it) | Re-run `vci run <unit>` |
| `toolchain` | Different Python/Node/Go/rustc/Ruby/bundle/package versions, or OS/arch under the policy | Pin versions (runners.md); report to the user |
| `signer` | Key not in the base branch's `allowed_signers`, or expired; for CI's keyless attestations, an identity in no `[[identity]]` of the base `identities.toml`; on main, a signer not in `no_skip_refs_except` | The user adds the key or identity on the default branch; on main this is expected |
| `signature` (CI's keyless attestations) | The base `.vci/sigstore-trusted-root.json` is missing or stale (GitHub renews its intermediate yearly) | Report to the user: refresh it with `gh attestation trusted-root` on the default branch |
| `expiry` | Attestation expired (default TTL 14 days, policy max 30) | Re-attest |
| `global-inputs`, `externals` | Lockfile, runner config or dependency versions changed | Re-attest after the change |
| `env` | A hashed variable differs; explain names it and its class (`env:DATABASE_URL (hash)`, `env:HOME (built-in ignore)` for one the test read) | Report to the user: same value on both sides, or a move to `[env] set` (a vci.toml change); units that read `HOME`/`USER` never skip on runners |
| `env-config` | The base `[env]` lists or vci's built-in lists differ from the attestation's (every attestation from before vci 1.6.0, once) | Re-attest; `vci env --base-ref origin/main` shows the difference |

Plan-wide: `running everything: policy.no_skip_refs matches ...` (you are on main or a tag), `vci.toml is missing at
the base commit` (setup not merged yet), and the warning `no git-meta store ... run vci fetch first`. Full list:
[references/refusals.md](references/refusals.md).

## Refusals in one paragraph

`vci run` will not attest a unit that failed, skipped, xfailed or filtered any test; started a child process; used
the network or a database client of its own (the test environment's database is fine); ran native code that can read
files unseen; read the whole environment; wrote inside the repository; read outside the repository; or whose inputs
changed during the run. These are by design: the unit simply runs in CI. Explain the reason to the user instead of
working around it. Details and fixes per message: [references/refusals.md](references/refusals.md).

## Per-runner notes

Short version (details in [references/runners.md](references/runners.md)):

- **Vitest**: Node major, Vitest and Vite versions must match CI; `package.json`, lockfiles, Vitest/Vite config and
  `tsconfig.json` changes invalidate every test file. Snapshot updates (`-u`) are refused.
- **pytest**: uv project with `uv.lock`; uv-managed Python pinned to the full version in `.python-version`, the same
  uv version in CI, `UV_PYTHON_PREFERENCE=only-managed` on both sides. Any skipped test refuses its file. The
  interpreter's SQLite and OpenSSL versions are compared unless the user sets `policy.libraries = "any"`.
- **Go**: units are package directories; exact Go version on both sides; `[env] set = { TZ = "UTC", CGO_ENABLED = "0" }`
  (vci sets them on both sides). Package `net` in the closure (including testify) is refused unless the user
  sets `go_allow_net`. Platform-specific or floating-point code pins the unit to the attesting OS/arch.
- **Cargo**: ids `<package dir>#<target>`; every file of the package and its in-repo dependencies is an input; reads
  elsewhere must be declared under `[[inputs]]` (a vci.toml change for the user). Exact rustc/cargo via rustup and
  `rust-toolchain.toml` (Homebrew's rustc never matches a rustup runner). Each unit is rebuilt: slower than
  `cargo test`.
- **Rails (Minitest/RSpec)**: files only, run one at a time (`vci ci` runs the rest in one process); vci does not
  manage the test database: Rails sets it up, its contents are not an input, and SQLite or a server needs no policy
  (`rails_allow_db` was removed in 1.4.0; a leftover key only warns). Exact Ruby patchlevel; `Gemfile.lock` with
  `x86_64-linux`; `gem "tzinfo-data"`; `[env] set = { TZ = "UTC" }` (vci sets it; no export); UTF-8 locale on both
  sides; `CI` left out of `[env]` (removed, so `config.eager_load = ENV["CI"].present?` is false on both sides).
  Changing `Gemfile.lock`, `config/**` or `spec/support`
  affects everything. libvips (Active Storage) is matched by file hash, so macOS attestations never skip on Linux
  unless the user sets `policy.libraries = "any"` (by library name, with libvips installed in CI; it also ignores
  the SQLite, libyaml and tz data versions).
- **All**: `TZ` (and for Node `LANG`) in `[env] set`, never exported by hand; delete `.DS_Store`/`__pycache__` junk from
  directories tests list; run CI jobs on the hosted runner, not as root.

## Safety rules (must follow)

1. **Never attest tests you did not run in this state.** Only `vci run` creates attestations; never craft, copy,
   edit or re-sign envelopes, and never write to `refs/meta/*` except through `vci push`.
2. **Never attest failing, skipped or filtered tests**, and never add skips, filters, retries, or delete or weaken
   tests to get a unit attested or green.
3. **Never touch trust**: do not add your key (or any key) to `.vci/allowed_signers`, an identity to
   `.vci/identities.toml` or an authority to `.vci/sigstore-trusted-root.json`, on a PR branch or anywhere, unless the
   user explicitly asks; changes there only take effect on the default branch, which the user merges.
4. **Never weaken policy** without the user: do not change `platform`, `libraries`, `platform_overrides`,
   `never_skip`, `no_skip_refs`, `no_skip_refs_except` (never add your own principal), `max_ttl`, `allow_dirty`,
   `go_allow_net`, `ignore_taints`, `[env]` (`set`, `hash`, `ignore`, `mode`), or `[[inputs]]`. Propose the change and let the
   user decide.
5. **Never change the CI wiring to skip more**: do not alter `base-ref`, switch to `pull_request_target`, unpin the
   action, or build vci from the PR checkout.
6. **Use the key you were given.** Do not create keys or read other people's keys; do not print private key
   material. Never use CI's own key (the GitHub secret behind the action's `signing-key`): it skips on main. Never
   sign with `--oidc` (`vci run --oidc`, `vci ci --oidc`), even inside a CI job: it signs as the workflow's identity.
7. **Re-attest after editing**: if you change any file the tests read after `vci run`, run it again before pushing.
8. **Report honestly**: list refused units and failed checks; never claim CI will skip something `vci plan` shows as
   `RUN`.

## Reference files

- [references/commands.md](references/commands.md): verbatim `vci --help` for every subcommand, with notes on
  arguments, output, exit codes and environment variables.
- [references/runners.md](references/runners.md): unit ids, inputs, refusals and version pins per runner.
- [references/refusals.md](references/refusals.md): every `not attesting` reason and `failed check`, what it means,
  what to do.
- [references/ci-setup.md](references/ci-setup.md): install, `vci init`, `allowed_signers`, GitHub Actions workflows
  per runner, action inputs, security rules, CI troubleshooting.
- `scripts/units-for-change.sh`: changed files to candidate units (bash 3.2+, git; uses `go`, `cargo` and `python3`
  for package graphs when present). `--help` for usage.
- Full upstream documentation: docs/REFERENCE.md in
  https://github.com/PandelisZ/cryptographically-verifiable-ci-runner.
