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
   `UV_PYTHON_PREFERENCE=only-managed`; Node major + `package-lock.json`; exact Go version + `CGO_ENABLED=0` + `TZ=UTC`;
   `rust-toolchain.toml` (rustup build); exact Ruby + `Gemfile.lock` with `x86_64-linux` + `tzinfo-data` + `TZ=UTC`.

5. Give whoever attests push access to `refs/meta/main` on the metadata remote (usually the repository itself).

## GitHub Actions

After checkout and toolchain setup:

```yaml
- uses: PandelisZ/cryptographically-verifiable-ci-runner@v1
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
      - uses: PandelisZ/cryptographically-verifiable-ci-runner@v1
```

Toolchain steps per runner:

```yaml
# pytest: also add UV_PYTHON_PREFERENCE: only-managed to the workflow's env:
      - uses: astral-sh/setup-uv@v6
        with:
          version: "0.11.7"       # same uv version as locally
      - run: uv sync --locked
# Go: also add CGO_ENABLED: "0" and TZ: UTC to the job's env:
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26.2"    # exact version used locally
      - run: go mod download
# Rust:
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: "1.95.0"     # same release as rust-toolchain.toml
      - run: cargo fetch --locked
# Rails (Minitest or RSpec): also add TZ: UTC to the job's env:
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: "3.4.9"   # exact Ruby used locally; omit to use .ruby-version
          bundler-cache: true
```

What the action does: installs a prebuilt `vci` (checksum pinned in the action) or builds it, runs
`vci fetch --remote origin`, writes `vci plan` to the job summary, then runs `vci ci` (runs every unit not skipped,
fails the job if any fails, writes `vci-audit.json`).

Inputs (all optional): `base-ref` (default: the PR base commit, or the pushed commit), `command` (`ci` or `plan`),
`remote` (`origin`), `audit-log` (`vci-audit.json`), `working-directory` (`.`), `prebuilt` (`true`), `token`,
`signing-key` (`""`: contents of CI's own SSH private key; see below), `ttl` (`14d`), `push` (`true`; with
`signing-key`, needs `permissions: contents: write`). Outputs: `skipped`, `run`, `attested`.

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
         - uses: PandelisZ/cryptographically-verifiable-ci-runner@v1
           with:
             signing-key: ${{ secrets.VCI_SIGNING_KEY }}
   ```

   and `if: github.event_name == 'pull_request'` on the existing job. The action runs `vci ci --key ... --ttl 14d
   --push --remote origin`; a failed push is a `::warning`, only test failures fail the job, and the audit log lists
   `attested` units and `pushed`. Without the action: `vci ci --base-ref <sha> --audit-log vci-audit.json --key <file>
   --push --remote origin` in that job.

Never print, copy or use the CI key yourself, and never add an agent's or person's principal to
`no_skip_refs_except`.

## Security rules (do not relax them)

- Pin the action (`@v1`, `@v1.0.0` or a full commit SHA); never a branch. Never build `vci` from the pull request's
  own checkout.
- Leave `base-ref` at its default. Use `pull_request`, not `pull_request_target`.
- Keep `refs/heads/main` in `policy.no_skip_refs` (the `vci init` default): pushes to main run everything, the
  backstop against a trusted signer's false claim. `no_skip_refs_except` names only CI's own principal, if anything.
- CI's signing key lives only in an Environment limited to the default branch and reaches only the main-branch job;
  one key per repository; rotate by replacing its `allowed_signers` line (then the secret). Whoever holds it can make
  main skip anything.
- Run on the hosted runner, not in a `container:` job (root on one side is a toolchain difference).
- Revoke a signer by removing their line from `.vci/allowed_signers` on the default branch.
- Without the action, always pass `--remote` to `vci fetch`, and pass
  `--base-ref "${{ github.event.pull_request.base.sha || github.sha }}"` to `vci ci`.
- Anyone with push access can write or delete `refs/meta/main`; that can only make units run. Limit writers with a
  ruleset on `refs/meta/**` if wanted.

## Troubleshooting CI

| Symptom | Likely cause |
|---|---|
| Everything runs on a pull request | `vci.toml` or `.vci/allowed_signers` not on the base branch; or attestations not pushed (`git ls-remote origin refs/meta/main` is empty) |
| `failed check: toolchain` | Python, Node, uv, Go, Rust, Ruby, Bundler or package versions differ between laptop and runner |
| `failed check: inputs` | A file changed after it was attested; `vci explain` names it |
| `failed check: signer` | Key not in the base commit's `allowed_signers`, or expired; on main, a signer not in `no_skip_refs_except` |
| Every push to main still runs everything | `no_skip_refs_except` empty or not merged; CI key not in main's `allowed_signers`; last push's attestations not published (`pushed` in the audit log; job lacks `contents: write`) |
| `::warning title=vci::not attesting: the key signs as ...` | CI's key reached a non-main run (a pull request): pass it only from the main-only job with the environment |
| A Go package or cargo target never skips on the runner | Platform-specific code (`_linux.go`, `cfg(target_os)`, `runtime.GOOS`, float maths): accepted only on the same OS/arch |
| A test reads `CI`, `HOME` or `TMPDIR` | Values differ on a runner; that unit always runs there |
| No Rails file ever skips | `config/environments/test.rb` reads `ENV["CI"]`; Ruby patchlevel, Bundler, SQLite or tz data differ; `Gemfile.lock` lacks `x86_64-linux` |
