# Setting up a repository and GitHub Actions

Sources: docs/INSTALL.md and docs/GITHUB_ACTIONS.md in the vci repository. Every step that changes trust or policy is
the user's decision: propose it, show the diff, and let them commit and merge it.

## Install vci

```sh
brew install pandelisz/tap/vci          # macOS and Linux; prebuilt, collectors included
# or, builds from source with cargo (Rust 1.85+):
curl -fsSL https://raw.githubusercontent.com/PandelisZ/cryptographically-verifiable-ci-runner/main/scripts/install.sh | sh
export VCI_PY_PLUGIN="$HOME/.local/share/vci/py/pytest-plugin"       # not needed with Homebrew
export VCI_JS_PLUGIN="$HOME/.local/share/vci/js/vitest-plugin"
export VCI_RUBY_COLLECTOR="$HOME/.local/share/vci/ruby/vci-collector"
vci --version
```

Requirements: `git`, `ssh-keygen` (OpenSSH 8.1+), an Ed25519 SSH key, and the runner's toolchain.

## Set up the repository (once)

1. Create the config and trust file (pick the adapter):

   ```sh
   vci init --adapter pytest --key ~/.ssh/id_ed25519.pub --principal you@example.com
   # vitest (default; --no-install to skip npm install of @vci/vitest), go, cargo, rails
   # --project <dir> for a project in a subdirectory
   ```

   It writes `vci.toml`, `.vci/allowed_signers`, and `.git-meta` (when there is an origin remote or `--meta-url`),
   configures a git-meta remote, and prints a CI example. Several projects in one repository use `[[projects]]`
   entries (`name`, `path`, `adapter`) instead of `project`/`adapter`; see this repository's own `vci.toml`.

2. Add every person or agent that may attest to `.vci/allowed_signers`, one line each:

   ```
   alice@example.com namespaces="vci-attest" ssh-ed25519 AAAAC3Nza...
   build-agent namespaces="vci-attest",valid-before="20270101" ssh-ed25519 AAAAC3Nza...
   ```

   Agents get their own key (not a person's) with an expiry (`valid-before`). Generate one with
   `ssh-keygen -t ed25519 -f ~/.ssh/vci-agent -N "" -C build-agent` and give the agent
   `VCI_SIGNING_KEY=~/.ssh/vci-agent`. Adding a line is the user's decision.

3. Commit `vci.toml`, `.vci/allowed_signers`, `.git-meta` (plus lockfiles and version pins) and **merge to the
   default branch**. CI reads both files from the base commit only, so nothing skips until they are on `main`.

4. Pin toolchains so local and CI runs match (see runners.md): `.python-version` + `uv.lock` + uv version +
   `UV_PYTHON_PREFERENCE=only-managed`; Node major + `package-lock.json`; exact Go version; `rust-toolchain.toml`
   (rustup build); exact Ruby + `Gemfile.lock` with `x86_64-linux` + `tzinfo-data`. Variables that must be equal on
   both sides go in `vci.toml`'s `[env] set` (`vci init` writes `TZ = "UTC"`; Go: add `CGO_ENABLED = "0"`; Vitest and
   node:test: `LANG = "C.UTF-8"`): vci sets them in every test process, so neither the laptop nor the workflow exports
   them. `vci env --base-ref origin/main` shows the policy CI will apply.

5. Give whoever attests push access to `refs/meta/main` on the metadata remote (usually the repository itself).

## GitHub Actions

After checkout and toolchain setup:

```yaml
- uses: PandelisZ/cryptographically-verifiable-ci-runner@v2
```

Complete workflow (Vitest; swap the toolchain steps for other runners):

```yaml
name: test
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # the base commit must be available
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - uses: PandelisZ/cryptographically-verifiable-ci-runner@v2
```

Toolchain steps per runner:

```yaml
# pytest: also add UV_PYTHON_PREFERENCE: only-managed to the workflow's env:
      - uses: astral-sh/setup-uv@v6
        with:
          version: "0.11.7"       # same uv version as locally
      - run: uv sync --locked
# Go: nothing to export (TZ and CGO_ENABLED come from vci.toml's [env] set)
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26.2"    # exact version used locally
      - run: go mod download
# Rust:
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: "1.95.0"     # same release as rust-toolchain.toml
      - run: cargo fetch --locked
# Rails (Minitest or RSpec): nothing to export (TZ comes from vci.toml's [env] set)
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: "3.4.9"   # exact Ruby used locally; omit to use .ruby-version
          bundler-cache: true
# Rails with MySQL or PostgreSQL only: the job's usual database service (same adapter, the host and port
# config/database.yml names for the test environment), then create the test database as any Rails CI job does:
#     - run: bin/rails db:test:prepare
```

Rails databases: vci does not manage them. The test database is the engine's (Rails sets it up; SQLite needs no
step), its contents are not an input, and no policy is needed for a database server. `vci ci` runs a project's
remaining Rails files in one `bin/rails test` (or `rspec`) process. `rails_allow_db` was removed in 1.4.0: if the
user's `vci.toml` still sets it, it is a no-op that warns; suggest removing it. The collector moved to 0.5.0 in
1.4.0, so existing Rails attestations run once more in CI.

What the action does: installs the published `vci` release binary (about a second; checksum pinned in the action; it
never compiles `vci`), fetches attestations as `vci fetch --remote origin` would (`vci ci --fetch origin`), writes
`vci plan` to the job summary, then runs `vci ci` (runs every unit not skipped, fails the job if any fails, writes
`vci-audit.json`).

Inputs (all optional): `base-ref` (default: the PR base commit, or the pushed commit), `command` (`ci` or `plan`),
`remote` (`origin`), `audit-log` (`vci-audit.json`), `working-directory` (`.`), `build-from-source` (`false`), `token`,
`signing-key` (`""`: contents of CI's own SSH private key; see below), `oidc` (`false`; `true`, `github` or
`public-good`: attest keylessly with the job's OIDC token instead, since 2.0; see below), `ttl` (`14d`), `push`
(`true`; with `signing-key` or `oidc`, needs `permissions: contents: write`). Outputs: `skipped`, `run`, `attested`. `prebuilt` is a
deprecated alias (`false` compiles). Never set `build-from-source: true` in a user's workflow: it exists for vci's
own development. If the action fails with `this commit of the action (...) has no published binary`, the workflow
pins a branch or a commit that is not a release: change it to `@v2` (or the full SHA `v2` points to, from
`git ls-remote https://github.com/PandelisZ/cryptographically-verifiable-ci-runner refs/tags/v2`).

## Let CI attest its own runs (optional)

With a key of its own, CI attests what it runs on main and pushes it, so the next commit (main or a pull request)
skips every unit whose inputs did not change; a README-only commit runs nothing CI already ran. Propose it; the key,
`allowed_signers`, policy and secret are all the user's to create and merge. Full text: "Attesting in CI" in
docs/GITHUB_ACTIONS.md.

1. The user makes a key for CI (not in `~/.ssh`, never an agent's or person's key):
   `ssh-keygen -t ed25519 -N "" -C vci-github-actions -f vci-github-actions`.
2. Its public half goes in `.vci/allowed_signers` under its own principal:
   `github-actions namespaces="vci-attest" ssh-ed25519 AAAA...`.
3. `vci.toml` `[policy]` (or each project's `policy`): keep `no_skip_refs` and add
   `no_skip_refs_except = ["github-actions"]`. Only that principal's attestations then skip on main; every other
   signer fails `signer` there (`policy.no_skip_refs matches refs/heads/main and signer <p> is not in
   no_skip_refs_except`). Default `[]`: main runs everything, as before.
4. The user creates a GitHub Environment (e.g. `vci-attest`) limited to the default branch and stores the private key
   as its secret: `gh secret set VCI_SIGNING_KEY --env vci-attest < vci-github-actions`, then deletes the local copy.
   Never a repository secret: pull request runs can read those.
5. Merge 2 and 3 to the default branch, then split the workflow: the pull request job unchanged (no key), plus a job
   for pushes to main:

   ```yaml
     test-main:
       runs-on: ubuntu-latest
       if: github.event_name == 'push' && github.ref == 'refs/heads/main'
       environment: vci-attest
       permissions:
         contents: write             # --push writes refs/meta/main
       steps:
         # ...the same checkout (fetch-depth: 0) and toolchain steps...
         - uses: PandelisZ/cryptographically-verifiable-ci-runner@v2
           with:
             signing-key: ${{ secrets.VCI_SIGNING_KEY }}
   ```

   and `if: github.event_name == 'pull_request'` on the existing job. The action runs `vci ci --key ... --ttl 14d
   --push --remote origin`; a failed push is a `::warning`, only test failures fail the job, and the audit log lists
   `attested` units and `pushed`. Without the action: `vci ci --base-ref <sha> --audit-log vci-audit.json --key <file>
   --push --remote origin` in that job.

Never print, copy or use the CI key yourself, and never add an agent's or person's principal to
`no_skip_refs_except`.

### Keyless instead of a key (vci 2.0, GitHub Actions)

The same, with no key and no secret: the main-branch job proves who it is with its OIDC token and signs through
Sigstore (an ephemeral key, a ten-minute certificate from Fulcio, a timestamp per attestation). Full text: "Keyless
attestation (OIDC)" in docs/GITHUB_ACTIONS.md. Propose it as above; the trust files are the user's to review and
merge.

1. `vci init --oidc` (or by hand) writes `.vci/identities.toml` and the trust root
   (`gh attestation trusted-root > .vci/sigstore-trusted-root.json`):

   ```toml
   [[identity]]
   principal = "github-actions"
   issuer = "https://token.actions.githubusercontent.com"
   repository = "owner/name"
   workflow = ".github/workflows/test.yml"   # the file of the attesting job (glob)
   ref = "refs/heads/main"                   # glob
   event = "push"                            # optional, as are environment and runner_environment
   ```

   The identity must match only runs on main: any step of the attesting job can request its token.
2. `no_skip_refs_except = ["github-actions"]`, as for a key. Merge the three files to the default branch.
3. The main-branch job gets `permissions: id-token: write` (and `contents: write`) instead of the secret:

   ```yaml
         - uses: PandelisZ/cryptographically-verifiable-ci-runner@v2
           with:
             oidc: true
   ```

   The action then runs `vci ci --oidc=github ... --push --remote origin`. `signing-key` and `oidc` together are an
   error.

Never run `vci run --oidc` or `vci ci --oidc` yourself, even inside a CI job: it signs as the workflow's identity.
GitHub renews its Sigstore intermediates yearly; when `vci explain` says the certificate's issuer is no authority of
the trust root, the user refreshes `.vci/sigstore-trusted-root.json` on the default branch.

## Use a shared store (Turso, PostgreSQL)

Optional, since vci 2.8.0, and only when the user asks: attestations live in a database every machine reads at once,
instead of on `refs/meta/main`. Full guide with every command:
https://pandelisz.github.io/cryptographically-verifiable-ci-runner/stores.html. Ask before each command that creates a
database, a token, an environment or a secret. Run `turso db tokens create` only piped straight into `gh secret set` or
`com secrets set ... --from-stdin`, as below, and never a command that reads a secret back (SKILL.md, rule 9); give
the user anything else that handles a token, such as the site's 1Password pipeline or the PostgreSQL password lines.

1. Turso: `turso db create <db>` (an ordinary database: not `--tursodb`, whose `turso://` URL vci does not accept).
   PostgreSQL: a database and the roles `vci_owner`, `vci_writer`, `vci_reader`, created and granted as
   https://pandelisz.github.io/cryptographically-verifiable-ci-runner/stores.html#postgresql says (the grants in
   database `ci`, once `vci_owner`'s first `vci run` created schema `vci`). A token or role reads, and if it can
   write deletes, every repository in its database (or schema), so use one per repository, or per group of
   repositories with the same readers.
2. Secrets, read from standard input so no token is ever on screen or on a command line, the read-only token for
   pull-request jobs and the other for the main-branch job:

   ```sh
   turso db show <db> --url | gh secret set VCI_STORE_URL
   turso db tokens create <db> --read-only | gh secret set VCI_STORE_TOKEN
   turso db tokens create <db> | gh secret set VCI_STORE_TOKEN --env vci-attest
   ```

   The environment's secret wins over the repository's in jobs that use the environment. `vci-attest` is the
   environment limited to the default branch (as for CI's signing key). For PostgreSQL the password is in
   `VCI_STORE_URL` (a `vci_reader` URL for the repository, a `vci_writer` one for the environment); there is no token.
   Never put a password in SQL text or on a command line: the site's PostgreSQL steps use psql's `\password` and build
   the URL with the shell's `printf` piped into `gh secret set`.
3. On the vci step of each job (not the job: the setup steps before it then never see the token), with `fetch-depth: 0`
   on the checkout (a shallow clone has no repository id and needs `VCI_STORE_NAMESPACE`):

   ```yaml
         - uses: PandelisZ/cryptographically-verifiable-ci-runner@v2
           env:
             VCI_STORE_URL: ${{ secrets.VCI_STORE_URL }}
             VCI_STORE_TOKEN: ${{ secrets.VCI_STORE_TOKEN }}
   ```

   Set both: a token from the environment is never sent to `vci.toml`'s `[store] url` (vci refuses the pair). Without
   the action, remove any `vci fetch --remote origin` step (the workflow `vci init` prints has one): on any store but
   git-meta it exits 2 (`the libsql store does not support a remote`) and the job stops before a test runs.
   `vci ci --fetch origin` only warns.
4. Only the main-branch job stores: on a shared store `vci ci` stores only with `--push`, which the action passes with
   `signing-key` or `oidc` (and `push: true`, the default). It writes to the database, not to git, so it needs no
   `contents: write`. Pull-request jobs read and store nothing.
5. Laptops: `[store]` in `vci.toml` with `url` (never a credential) and `token_command` (a command that prints the
   token, e.g. `["com", "secrets", "get", "vci-store-token", "--org", "acme"]` or `["op", "read", "op://..."]`).
   First store a token that can write where the command reads it, from standard input:
   `turso db tokens create <db> | com secrets set vci-store-token --org <org> --from-stdin --env-key VCI_STORE_TOKEN`
   (never `--value`; without `--ci`, which would expose it to CI runners). `com secrets get` reads an organization's
   secret for its admins only: for developers who are not admins, use a source they can read (a shared 1Password
   vault). A machine that should only plan, an agent's sandbox, or any machine that runs code nobody has reviewed gets
   `VCI_STORE_URL` and a token made for that database alone (read-only unless it should store) in its own environment
   instead, from the person or the sandbox's secret settings, or from a 1Password service account limited to a vault
   holding only that token; they win over `[store]`. Never sign such a machine in to `com` or a person's 1Password
   account: every secret the account can read, the token that can write included, would be open to the code it runs.
   Commit `[store]` only once every runner and developer has vci 2.8.0: an older vci rejects it and runs every test.
6. Check with `vci store info` (an uncommitted `[store]` in the working tree is enough). The store starts empty: every
   unit runs until the main-branch job's next full run (or a developer's `vci run`) stores attestations. Nothing is
   copied from `refs/meta/main`.
7. Check CI after the first push to main: its log has `vci ci: N unit(s) attested` without `(not stored: ...)` at the
   end, and the next pull request's plan has `SKIP` lines and no `running everything: reading attestations from
   <kind>`. Nothing in CI shows whether the repository's token is read-only (pull-request jobs never write); if unsure,
   `turso db tokens invalidate <db>` and set the secrets again.
8. Store format 3 (vci 2.9): a store written by 2.9 holds a new record format a 2.8 vci cannot read (it runs those
   units, never skips them wrongly), so upgrade in this order, each step with the user's go-ahead: the action pinned
   to 2.9 and every developer on 2.9 in one change (`[store] record_format = 1` in `vci.toml`, or
   `VCI_STORE_RECORD_FORMAT=1` on the vci step, keeps the old format while that takes longer); `vci store upgrade
   --begin` once on the shared store before the first 2.9 job (idempotent; the first 2.9 `vci run` does it otherwise,
   in a request of its own); a 2.9 `vci prune` once during the window, since a 2.8 prune stops collecting input
   manifests as soon as one new record exists; and `vci store upgrade --finish`, by the user, only once no old record
   remains (it is refused with the count until then; on libSQL it is refused in this release even at zero), after
   which a 2.8 vci fails open on that store for good. A libSQL replica (`VCI_STORE_SYNC=replica`) synced by 2.8 is
   synced in full once by 2.9, and keeps no objects: cut off from its server it verifies no format-3 record.

A job that runs untrusted code (a fork's, or any job you would not hand a write credential) gets a read-only token or
none: its tests can read the token from the environment the job's shell or vci started with, whatever vci removes.

## Security rules (do not relax them)

- Pin the action (`@v2`, or the full commit SHA `v2` points to; `@v1` stays on 1.9.2); never a branch, and not
  `@v1.0.0` to `@v1.4.0` (those tags compile `vci` instead of downloading it). Never build `vci` from the pull request's own checkout.
- Leave `base-ref` at its default. Use `pull_request`, not `pull_request_target`.
- Keep `refs/heads/main` in `policy.no_skip_refs` (the `vci init` default): pushes to main run everything, the
  backstop against a trusted signer's false claim. `no_skip_refs_except` names only CI's own principal, if anything.
- CI's signing key lives only in an Environment limited to the default branch and reaches only the main-branch job;
  one key per repository; rotate by replacing its `allowed_signers` line (then the secret). Whoever holds it can make
  main skip anything. Keyless: the `[[identity]]` main skips on pins `ref`, `event` and best an `environment` limited
  to the default branch; `id-token: write` only in the jobs that attest.
- Run on the hosted runner, not in a `container:` job (root on one side is a toolchain difference).
- Revoke a signer by removing their line from `.vci/allowed_signers` (or its `[[identity]]` from
  `.vci/identities.toml`) on the default branch.
- Without the action, on git-meta, always pass `--remote` to `vci fetch` (on any other store leave the step out), and
  pass `--base-ref "${{ github.event.pull_request.base.sha || github.sha }}"` to `vci ci`.
- Anyone with push access can write or delete `refs/meta/main`; that can only make units run. Limit writers with a
  ruleset on `refs/meta/**` if wanted.

## Troubleshooting CI

| Symptom | Likely cause |
|---|---|
| Everything runs on a pull request | `vci.toml` or `.vci/allowed_signers` not on the base branch; or attestations not pushed (`git ls-remote origin refs/meta/main` is empty) |
| `failed check: toolchain` | Python, Node, uv, Go, Rust, Ruby, Bundler or package versions differ between laptop and runner |
| `failed check: inputs` | A file changed after it was attested; `vci explain` names it |
| `failed check: env` | A hashed variable differs on the runner; `vci explain` names it and its class (`env:X (hash)`): same value on both sides, or move it to `[env] set` |
| `failed check: env-config` | The base `[env]` lists (or vci's built-in lists) differ from the attestation's; attestations made before vci 1.6.0 fail this once; `vci env --base-ref origin/main` |
| `failed check: signer` | Key not in the base commit's `allowed_signers`, or expired; a keyless attestation whose identity matches no `[[identity]]` (or no `identities.toml` on the base branch); on main, a signer not in `no_skip_refs_except` |
| `failed check: signature` on CI's keyless attestations | The base `.vci/sigstore-trusted-root.json` is missing, invalid or stale (GitHub renewed its intermediate): refresh it with `gh attestation trusted-root` on the default branch |
| ``unreadable: value not fetched: run `vci fetch` online`` | vci 2.0 fetches values when a plan reads them; that fetch failed (network, or the metadata remote refuses fetching by object id). The unit runs; re-run online |
| Every push to main still runs everything | `no_skip_refs_except` empty or not merged; CI key not in main's `allowed_signers`; last push's attestations not published (`pushed` in the audit log; job lacks `contents: write`) |
| `::warning title=vci::not attesting: the key signs as ...` | CI's key reached a non-main run (a pull request): pass it only from the main-only job with the environment |
| A Go package or cargo target never skips on the runner | Platform-specific code (`_linux.go`, `cfg(target_os)`, `runtime.GOOS`, float maths): accepted only on the same OS/arch |
| A test reads `HOME` or `TMPDIR`, or a variable in `[env] hash` such as `CI` | Values differ on a runner; that unit always runs there (`CI` is removed unless listed) |
| `running everything: reading attestations from libsql: ...` (or `postgres`) | The store cannot be used: a missing secret (fork pull requests get none, and Dependabot's only Dependabot secrets, so both fall back to `vci.toml`; check the vci step's `env:`), a refused or expired token, a server that does not answer. Every test ran; `vci store info` run with the same variables says why |
| `$VCI_STORE_TOKEN is set but the store's URL comes from vci.toml [store] url` | The job sets the token but not `VCI_STORE_URL`: set both from secrets |
| `the token_command (...) was not found` in a CI job | The job's `VCI_STORE_TOKEN` is empty, so vci ran `vci.toml`'s `token_command`: a fork's pull request (no secrets: everything runs, by design), a Dependabot pull request (it gets only Dependabot secrets: set the two there too, the token read-only, with `gh secret set ... --app dependabot`, if its jobs should skip), a repository secret never set, or the variables not on the vci step. Not a laptop problem: do not run the command |
| `vci: error: the libsql store does not support a remote` (or `sqlite`, `postgres`), exit 2 | A `vci fetch --remote origin` step on a store other than git-meta: remove it |
| `libsql store refused to write: ... the token may not write` in the main-branch job | It got the read-only token: the `vci-attest` environment lacks its own `VCI_STORE_TOKEN`, or the job does not name the environment |
| `vci: not storing N attestation(s): the <kind> store is shared and vci ci was not given --push`, or `vci ci: N unit(s) attested (not stored: ...)` | The job attested (it has `signing-key` or `oidc`) but stored nothing: the action's `push: false`, or, without the action, `vci ci` without `--push`. A job without a key or OIDC attests nothing and prints neither line |
| No Rails file ever skips | `config/environments/test.rb` reads `ENV["CI"]` and `CI` is in `[env] hash` (leave it out of `[env]`); Ruby patchlevel, Bundler, SQLite or tz data differ; `Gemfile.lock` lacks `x86_64-linux`; the app loads libvips (Active Storage), whose Homebrew file never matches the runner's (`policy.libraries = "any"` matches it by name, with libvips installed on the runner; also stops comparing the SQLite, libyaml and tz data versions) |
