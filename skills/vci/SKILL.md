---
name: vci
description: Run tests locally with vci (cryptographically verifiable CI), sign an attestation of exactly what they depended on, push it through git, and let CI skip those tests. Use when the user or an agent wants to run tests with proof, attest tests, skip already-run tests in CI, speed up CI for a pull request, or set up vci / verifiable CI (vci init, allowed_signers, the PandelisZ/cryptographically-verifiable-ci-runner GitHub Action), and when diagnosing why vci did not skip a test or refused to attest one, or setting up its attestation store (git-meta, SQLite, PostgreSQL, Turso). Covers Vitest, pytest (uv), Go, Cargo, Rails Minitest and RSpec. Triggers include "vci", "attest", "attestation", "verifiable CI", "skip tests in CI", "vci.toml", "allowed_signers", "identities.toml", "vci --oidc", "refs/meta/main", "vci store", "VCI_STORE_URL", "token_command", "Turso".
license: MIT
compatibility: Needs the vci CLI (brew install pandelisz/tap/vci), git, ssh-keygen (OpenSSH 8.1+) and the project's test toolchain, on macOS or Linux.
metadata:
  homepage: https://github.com/PandelisZ/cryptographically-verifiable-ci-runner
  vci-version: "2.0.0"
---

# vci: run tests once, prove it, let CI skip them

vci runs a project's tests with a collector attached, records every input each test unit actually used, signs that
record with an SSH key, and stores it: by default in git (git-meta on `refs/meta/main`), since vci 2.8.0 optionally in
a SQLite file, on PostgreSQL or in a libSQL database such as Turso (see "Attestation stores"). In CI, the vci GitHub Action checks each
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
3. **`vci push`** publishes attestations on `refs/meta/main` (git-meta, the default; no server). On a shared store
   (PostgreSQL, Turso) `vci run` stores them on the server at once and `vci push` has nothing to do.
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
git symbolic-ref --short refs/remotes/origin/HEAD   # the default branch (origin/main, origin/master); if it fails, ask
echo "${VCI_SIGNING_KEY:-unset}"                # signing key, or pass --key
```

This skill writes `origin/main`; use the default branch the command above printed. None of these commands reads the
attestation store. Before any that does, check whose `[store]` this is:

- **Whose `[store]`?** Every vci command but `vci --version`, `vci init`, `vci env`, `vci metrics` and `vci update`
  reads the attestation store (`vci store info`, `plan`, `run`, `ci`, `explain`, `verify`, `fetch`, `push`, `prune`),
  and reading it runs `[store] token_command` and sends what it prints, the user's credential, to `[store] url`. Both
  come from this checkout's `vci.toml`, the top-level one whatever the current directory. So first run this as a
  command of its own and read its output:

  ```sh
  git diff origin/main -- :/vci.toml    # the default branch; :/ is the top level from any directory
  ```

  Check that the checkout is the user's own work and that the diff changes neither `url` nor `token_command` (nor,
  for a `token_command` that is a path in the repository such as `scripts/vci-token`, that file), unless the user
  made that change. Otherwise (someone else's pull request, a clone the user has not reviewed, a branch that changes
  either), or if the diff fails (no such branch, no `origin`), run every vci command with `VCI_STORE=git-meta` in
  front, which ignores both and never runs the command, and tell the user why.
- **Which store**: then, as a step of its own, `vci store info` (`VCI_STORE=git-meta vci store info` in a checkout
  the user has not reviewed). What it prints never holds a secret, so it is safe to show.
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

On SQLite, PostgreSQL or a libSQL server, `vci run` already stored the attestations and `vci push` prints `vci:
nothing to push: the <kind> store is local|shared; attestations were stored when vci run made them`. Running it is
harmless.

Push only when the user wants the branch pushed (or it is the agreed workflow). Push the attestations before or
together with the branch: CI fetches `refs/meta/main` when the job starts. `vci push` needs push access to the
metadata remote; if it is refused, report it (the user may need to grant the agent access to `refs/meta/main`).
`vci push` goes to the configured git-meta remote, else the URL in the committed `.git-meta` file: in a scratch clone
or fork that is still the upstream repository, so never run it from a throwaway checkout.

### 5. Report

Tell the user, briefly: which units were attested, which were refused and why (one line each), the `vci plan`
summary line (`N to skip, M to run`), and whether attestations and the branch were pushed.

## Attestation stores

Since vci 2.8.0 attestations live in one of four stores: git-meta (the default), SQLite (`.git/vci-store.sqlite`),
PostgreSQL, or libSQL (Turso, or a `sqld`; remote, through a local replica, or a local file). No store is trusted:
the plan verifies every record against the base branch, so a store can only make a unit run, never skip. Full guide:
https://pandelisz.github.io/cryptographically-verifiable-ci-runner/stores.html.

- **Which store**: run `vci store info` (`--format json` for scripts), after the check in "Whose `[store]`?". It names
  the store, where each setting came from, its status and its count, and never prints a secret (`token: (set)`,
  `postgres://***@…`), so its output is safe to show the user. Chosen from `VCI_STORE`, else the scheme of
  `VCI_STORE_URL`, else `[store]` in the working tree's `vci.toml`, else git-meta.
- **Never print a store credential.** Do not echo, log, paste or commit `VCI_STORE_URL`, `VCI_STORE_TOKEN`, or
  anything a `[store] token_command` prints. No `env`, `printenv` or `set` dumps in a shell that has them. To check
  whether one is set without showing it: `echo "${VCI_STORE_TOKEN:+set}"`.
- **Never write a credential into `vci.toml`** or any committed file: `[store] url` names the server only
  (`libsql://vci-acme.aws-eu-west-1.turso.io`, `postgres://vci_writer@db.example.com/ci`), and the credential comes
  from the environment (CI) or `[store] token_command` (laptops). vci refuses a `[store] url` with a password, token or
  `authToken`, and refuses `VCI_STORE_TOKEN` paired with a URL from `vci.toml`.
- **A failing `token_command`: never run it yourself**, nor any other command that reads a secret (`op read`,
  `com secrets get`, `gh auth token`, `security find-generic-password`), not even with its output discarded: its
  standard error can hold the token too (a wrapper script run with `sh -x` prints each line it runs, the token's
  included, and `jq` quotes the value it could not parse). Tell the user what failed, as vci's message says it
  (`exited 1`, `was not found`, `printed nothing on standard output`, ...), and the command it names, and ask them to
  run that command in their own terminal, from the repository root, with its standard output discarded
  (`com secrets get vci-store-token --org vex > /dev/null`). Since vci 2.8.1 the message ends `run the command
  yourself with its standard output discarded (> /dev/null) to see why` and quotes the command for a shell. vci
  2.8.0's ends `run the command yourself to see why` and leaves arguments holding `&`, `;`, `|`, `#`, `<`, `(`, glob
  characters and others unquoted, so with 2.8.0 give the user the command from `vci.toml`'s `token_command` with
  every argument in single quotes: `'com' 'secrets' 'get' 'vci-store-token' '--org' 'vex' > /dev/null`. A string
  `token_command` runs with `sh -c`, so give it as `sh -c '<the string>' > /dev/null` (each `'` in it written `'\''`):
  bare, `a || b > /dev/null` discards only what `b` prints. Usual causes: the user is not signed in on their own
  machine (`com login`, `op signin`: ask them), the command tried to prompt, or the user is not allowed to read the
  secret (`com secrets get` reads an organization's secret for its admins only).
- **In a sandbox, a token of its own.** `token_command` is for a person's own machine, signed in as that person. Never
  sign a sandbox or any other machine of your own in to `com` or 1Password (`com login`, `op signin`), and never ask
  the user to: every command you run there, the checkout's tests included, could then read every secret the account
  can, the token that can write included. If the sandbox should read the store, ask the user to set `VCI_STORE_URL`
  and a token made for that database alone (`--read-only` unless your `vci run` should store) in the sandbox's secret
  settings. Until then a plan there that needs the token fails open and runs everything.
- **Failing open is safe.** When the store cannot be used (no token, a refused token, a server down, a failing token
  command), `vci plan` warns and prints `running everything: reading attestations from <kind>: …`: every test runs and
  nothing is skipped by mistake. `vci run` still runs the tests, refuses each unit with `signing or storing failed: …`
  and keeps the tests' exit code. Report the reason; do not work around it by switching stores or finding another
  credential.
- **When to push.** git-meta: `vci push` after `vci run`. SQLite, PostgreSQL, libSQL: `vci run` stored them; nothing
  to push. `vci ci --push` is what stores on a shared store in CI, and only trusted CI jobs (the default branch, with
  CI's key or OIDC) run it: never run `vci ci --push` yourself.
- **Store format 3 (vci 2.9).** vci 2.9 reads two record formats and writes the new one: a text frame (`vci3`, the
  signed statement, the signature, a descriptor) whose statement names two per-run objects by digest, the descriptor
  a third, and the attested file hashes a fourth, the **state object**, which only `vci explain` reads and which is
  removed after `[store] explain_hashes_days` (2) even while records reference it (the records stay valid; `explain`
  then prints `(attested hash not loaded)`), or never written under `[store] explain_hashes = false`: both are the
  user's policy choice, never yours. A vci before 2.9 reads a format-3 record as one it cannot parse and runs the
  unit (fail-open), so a mixed fleet loses skips, never gains wrong ones. The migration order, which the user
  decides and runs: `vci store upgrade --begin` once on a SQLite, PostgreSQL or libSQL store before the first 2.9
  job (optional and idempotent; 2.9's first `vci run` does it otherwise, in a request of its own), then every
  runner and developer on 2.9 (the action pinned in one change; `[store] record_format = 1` keeps writing the old
  format meanwhile), then a 2.9 `vci prune` once during the window (a 2.8 prune stops collecting manifests once a
  format-3 record exists), and `vci store upgrade --finish` only once no format-1 record remains and where the
  backend allows it (SQLite and PostgreSQL), after which a 2.8 vci fails open on that store for good: **never run
  `--finish` unasked**, and report its refusal rather than working around it: `not finished: N attestation(s) are
  not format-3 records` (exit 1), or on libSQL at zero `vci: error: the libsql store does not support finishing the
  format-3 upgrade (dropping the manifests table and the change log): a later vci does it` (exit 2), which means the
  migration on libSQL ends at the prune in this release: the namespace stays at schema version 1, a 2.8 writer is
  never turned away (the user's guard is to rotate the Turso write token or `vci update` every machine that
  writes), and each 2.8 write re-opens the manifest-collection path until a 2.9 prune removes its manifest; libSQL's
  `--finish` lands in 2.10. `vci prune --objects [--older-than DAYS]` removes the objects no record references and the aged
  state objects without touching attestations. Diagnosing: a 2.8 vci shows a format-3 record as `failed check:
  envelope` (upgrade it); `failed check: signer` with `signer id (the store key's signer segment)` means the record
  sits under another signer's slot (re-attest); `statement` naming a hdr or tables object means the run's objects
  are missing or altered in the store (re-attest; `vci prune --dry-run` lists what the store holds).
- **SQLite and libSQL's local file stay on this machine.** CI sees what they hold only if it shares the file (a cache of
  `.git/vci-store.sqlite`, say). A local `SKIP` there says nothing about CI: never tell the user that CI will skip a
  unit on that basis (rule 8). `vci store info` shows which: `store: sqlite`, or `store: libsql` with `(local)` after
  its location.
- **Read-only tokens.** `libsql store refused to write: … the token may not write` (or `postgres store refused to
  write`) means the credential can only read: the plan works, nothing is stored. Tell the user; it is how pull-request
  jobs are meant to be set up.
- **Someone else's checkout**: `VCI_STORE=git-meta` in front of every vci command (see "Whose `[store]`?" under "Before
  you start"). Never change `[store]` without the user.
- **Setting up Turso, when the user asks.** Follow the steps at
  https://pandelisz.github.io/cryptographically-verifiable-ci-runner/stores.html#turso, with one database per
  repository, or per group of repositories with the same readers: a token reads and writes every repository in its
  database. Tokens go straight from
  `turso db tokens create` into `gh secret set` on standard input, never as `--body` or any other argument, and never
  on screen: `turso db tokens create <db> --read-only | gh secret set VCI_STORE_TOKEN` for pull-request jobs,
  `turso db tokens create <db> | gh secret set VCI_STORE_TOKEN --env vci-attest` for the main-branch job,
  `turso db show <db> --url | gh secret set VCI_STORE_URL`. The token laptops and agents read through
  `[store] token_command` goes into that tool the same way, from standard input
  (`turso db tokens create <db> | com secrets set vci-store-token --org <org> --from-stdin --env-key VCI_STORE_TOKEN`;
  never `--value`). Run each command that creates a database, a token, an environment or a secret only with the user's
  go-ahead. `turso db tokens create` prints a new token, so run it only with its standard output piped straight into
  `gh secret set` or `com secrets set ... --from-stdin`: never on its own, into a file or a variable, or through
  anything that prints it. That is the only command handling a token you run; never read one back to check it
  (`com secrets get`, `op read`), since `vci store info` and the next plan show whether it works. Give anything else,
  such as the site's 1Password pipeline, to the user to run. Propose the workflow `env:` lines and the `[store]` table
  as a diff, and add `[store]` to `vci.toml` only once every runner and developer has vci 2.8.0 or later. Steps for
  CI: [references/ci-setup.md](references/ci-setup.md) ("Use a shared store").

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
| `inputs` | A file changed after attesting (`entry:<path>` names it, with both hashes, or since vci 2.9 with expected `<kind> exec=<bool> changed (attested hash not loaded)` for a kind or exec difference; `entry: changed (attested hash not loaded)` with both roots names none, when the run's state object was removed or not loaded) | Re-run `vci run <unit>` |
| `toolchain` | Different Python/Node/Go/rustc/Ruby/bundle/package versions, or OS/arch under the policy | Pin versions (runners.md); report to the user |
| `signer` | Key not in the base branch's `allowed_signers`, or expired; for CI's keyless attestations, an identity in no `[[identity]]` of the base `identities.toml`; on main, a signer not in `no_skip_refs_except`; since vci 2.9, `signer id (the store key's signer segment)`: the record sits under another signer's slot | The user adds the key or identity on the default branch; on main this is expected; a wrong slot: re-attest |
| `signature` (CI's keyless attestations) | The base `.vci/sigstore-trusted-root.json` is missing or stale (GitHub renews its intermediate yearly) | Report to the user: refresh it with `gh attestation trusted-root` on the default branch |
| `expiry` | Attestation expired (default TTL 14 days, policy max 30) | Re-attest |
| `global-inputs`, `externals` | Lockfile, runner config or dependency versions changed | Re-attest after the change |
| `env` | A hashed variable differs; explain names it and its class (`env:DATABASE_URL (hash)`, `env:HOME (built-in ignore)` for one the test read) | Report to the user: same value on both sides, or a move to `[env] set` (a vci.toml change); units that read `HOME`/`USER` never skip on runners |
| `env-config` | The base `[env]` lists or vci's built-in lists differ from the attestation's (every attestation from before vci 1.6.0, once) | Re-attest; `vci env --base-ref origin/main` shows the difference |

Plan-wide: `running everything: policy.no_skip_refs matches ...` (you are on main or a tag), `vci.toml is missing at
the base commit` (setup not merged yet), `running everything: reading attestations from <kind>: ...` (the store cannot
be used; `vci store info` says why), and the warnings `no git-meta store ... run vci fetch first` or `no attestations
are available in the <kind> store` (a new store: nothing stored yet). Full list:
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
9. **Never expose a store credential**: never print, paste or commit `VCI_STORE_URL`, `VCI_STORE_TOKEN` or a
   `token_command`'s output, never put a credential in `vci.toml`, never run a token command or any other command
   that reads a secret yourself, not even with its output discarded (tell the user what failed and the command),
   create a token only piped straight into `gh secret set` or `com secrets set --from-stdin` and with the user's
   go-ahead, and never let a checkout you have not reviewed choose the store (see "Before you start" and "Attestation
   stores").

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
