# GitHub Actions setup

Add one step to your workflow. It skips every test that a trusted person or agent already ran against the same code,
and runs the rest. The docs site has the same guide with tabs:
[GitHub Actions](https://pandelisz.github.io/cryptographically-verifiable-ci-runner/github-actions.html).

## The one line

Put this after your checkout and toolchain setup steps:

```yaml
- uses: PandelisZ/cryptographically-verifiable-ci-runner@v1
```

Terms used below:

- **Unit**: the smallest thing vci can skip. A test file for Vitest, pytest, Minitest and RSpec; a package for Go; a
  test target for Rust.
- **Attestation**: a record, signed with an SSH key, that says "this unit passed against exactly these inputs".
- **Base branch**: the branch a pull request merges into, usually `main`. CI reads the trusted keys and the policy
  from its commit, never from the pull request.

`@v1` follows the latest tested 1.x release. See [Pinning](#pinning) for stricter options.

## Before you start

1. `vci.toml` and `.vci/allowed_signers` are merged to your default branch ([install guide](INSTALL.md)).
2. `.git-meta` (written by `vci init`) is committed.
3. Attestations are pushed with `vci push` (or `git meta push`) before, or together with, the branch. With a
   `signing-key`, CI also attests and pushes what it runs (see [Attesting in CI](#attesting-in-ci)).

## A complete workflow

Save as `.github/workflows/test.yml`. This one is for Vitest; for other runners, swap the toolchain steps for the
ones in the next section.

```yaml
name: test

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read            # read-only is enough

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # the base commit must be available

      # Your toolchain, at the same version as locally
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci

      - uses: PandelisZ/cryptographically-verifiable-ci-runner@v1
```

Run the job on the hosted runner directly, not in a `container:` job: attestations made as a normal user are not
accepted by a verifier running as root (unless the base branch sets `policy.allow_superuser_mismatch = true`, which is
risky for tests that depend on file permissions: see the [reference](REFERENCE.md#vcitoml)).

## Setup steps for each runner

Pin the same versions you use locally: an attestation only counts where the toolchain matches.

**pytest (uv).** Add `UV_PYTHON_PREFERENCE: only-managed` to the workflow's top-level `env:`, then:

```yaml
      - uses: astral-sh/setup-uv@v6
        with:
          version: "0.11.7"     # same uv version as locally
      - run: uv sync --locked
```

**Go.** Add `CGO_ENABLED: "0"` and `TZ: UTC` to the job's `env:` (same values as locally; both are declared in
`vci.toml` `[env] global`), then:

```yaml
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26.2"  # exact version used locally
      - run: go mod download
```

**Rust.**

```yaml
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: "1.95.0"   # same release as rust-toolchain.toml
      - run: cargo fetch --locked
```

**Rails (Minitest or RSpec).** Add `TZ: UTC` to the job's `env:` (declared in `[env] global`, set the same way
locally), then:

```yaml
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: "3.4.9" # exact Ruby and patchlevel used locally; omit to use .ruby-version
          bundler-cache: true   # bundle install of Gemfile.lock into vendor/bundle
```

- `Gemfile.lock` must list the runner's platform (`bundle lock --add-platform x86_64-linux`). The Bundler version in
  its `BUNDLED WITH` is what `setup-ruby` installs, and it is compared.
- `bundler-cache` installs the gems inside the repository (`vendor/bundle`). That bundle is handled like one installed
  anywhere else: its gems are externals by version and nothing under `vendor/bundle` is an input. Collector 0.4.1
  refused every file there with `ruby:read-outside-bundle:stat .../vendor/bundle/ruby/3.4.0`.
- `vci ci` runs each remaining Minitest file in its own `bin/rails test <file>`, and each remaining RSpec file in its
  own `rspec --options .rspec <file>`, with a fresh SQLite database loaded from `db/schema.rb`.
- RSpec reads only the repository's `.rspec`. `~/.rspec`, `$XDG_CONFIG_HOME/rspec/options` and `.rspec-local` are
  never read, on the runner or the laptop. `SPEC_OPTS` reaches RSpec only if declared in `[env] global` (then set it
  to the same value on both sides).
- A database server needs `policy.rails_allow_db = true` and a service container (see [the reference](REFERENCE.md)).
- Full example: [`examples/github-actions-rails.yml`](../examples/github-actions-rails.yml).

**Several languages in one job.** Set up every toolchain, then call the action once. This repository's own
[workflow](../.github/workflows/ci.yml) does that for Python, Go, Rust and Rails.

## What the action does

1. Installs `vci`: a prebuilt binary whose checksum is recorded in the pinned action, or a build from source (cached).
2. Runs `vci fetch --remote origin`. Attestations are [git-meta](https://git-meta.com/) metadata on `refs/meta/main`.
   The fetch configures a git-meta remote named `meta` with origin's URL, so the checkout's credentials apply and a
   read-only `contents: read` token is enough. It fetches every blob (no partial clone) and builds a new
   `.git/git-meta.sqlite`. If the fetch fails, the action warns and every test runs.
3. Runs `vci plan` and writes the plan to the job summary.
4. Runs `vci ci`: it runs every unit that was not skipped and writes an audit log. The job fails if any test fails.
5. With `signing-key`: `vci ci --key` runs those units the way `vci run` does and attests every one that passed (on
   a push to main, which runs everything, every unit), then `--push` publishes them on `refs/meta/main`. The next
   commit's CI skips each unit whose inputs did not change. See [Attesting in CI](#attesting-in-ci).

`fetch-depth: 0` is needed for the base commit, not for the metadata: `refs/meta/main` is not a branch, so
`actions/checkout` never fetches it.

## Inputs and outputs

Every input is optional.

| Input | Default | Meaning |
|---|---|---|
| `base-ref` | PR base commit, or the pushed commit | Commit that policy and trusted signers are read from |
| `command` | `ci` | `ci` plans and runs the rest; `plan` only decides |
| `remote` | `origin` | Git remote name or URL whose `refs/meta/main` holds the attestations |
| `audit-log` | `vci-audit.json` | JSON record of what was skipped, by whom, and what ran |
| `working-directory` | `.` | Directory to run `vci` from |
| `prebuilt` | `true` | Download the release binary; `false` always builds from source |
| `token` | `github.token` | Token used to download the release binary |
| `signing-key` | `""` | Contents of an SSH private key, from an environment secret limited to the default branch. `vci ci` then attests what it runs. Its public half must be in `.vci/allowed_signers` on the base branch, under a principal listed in `policy.no_skip_refs_except` for main to skip on it. See [Attesting in CI](#attesting-in-ci) |
| `ttl` | `14d` | Lifetime of those attestations (at most `policy.max_ttl`) |
| `push` | `true` | With `signing-key`: push the attestations to `remote` (needs `permissions: contents: write`); a failed push is a warning. Nothing is pushed when `vci ci` attested nothing on purpose (see [Attesting in CI](#attesting-in-ci)) |

| Output | Meaning |
|---|---|
| `skipped` | Number of test units skipped |
| `run` | Number of test units that ran |
| `attested` | Number of test units attested with `signing-key` |

## Attesting in CI

Without a key, CI only consumes attestations. With one, it leaves its own behind: a push to main runs what is not
attested (the first time, everything) and attests every unit that passed and can be attested, so the next commit (on
main or on a pull request) skips each unit whose inputs did not change. When every unit was attested, a commit that
only changes a README runs no tests at all: the job prints `nothing to run` after fetching and verifying.

### Set it up

1. Make a key for CI, outside `~/.ssh` (it is not yours), and trust it under its own principal:

   ```sh
   ssh-keygen -t ed25519 -N "" -C vci-github-actions -f vci-github-actions
   echo "github-actions namespaces=\"vci-attest\" $(cut -d' ' -f1,2 vci-github-actions.pub)" >> .vci/allowed_signers
   ```

2. In `vci.toml`, keep `no_skip_refs` and name that principal in `no_skip_refs_except`, so main skips what CI
   attested and still runs everything any other signer claims:

   ```toml
   [policy]
   no_skip_refs = ["refs/heads/main", "refs/tags/**"]
   no_skip_refs_except = ["github-actions"]
   ```

3. Create a GitHub Environment (here `vci-attest`) whose deployment branches are limited to the default branch, and
   store the private key as that environment's secret `VCI_SIGNING_KEY`. In Settings → Environments, or:

   ```sh
   gh api -X PUT 'repos/{owner}/{repo}/environments/vci-attest' \
     -F 'deployment_branch_policy[protected_branches]=false' \
     -F 'deployment_branch_policy[custom_branch_policies]=true'
   gh api -X POST 'repos/{owner}/{repo}/environments/vci-attest/deployment-branch-policies' -f name=main
   gh secret set VCI_SIGNING_KEY --env vci-attest < vci-github-actions
   rm vci-github-actions      # the secret is now the only copy; keep the .pub
   ```

   Not `gh secret set VCI_SIGNING_KEY` without `--env`: a repository secret reaches every pull request run from a
   branch of the repository (see [why](#why-an-environment)).

4. Commit steps 1 and 2 to the default branch: trust and policy come from the base commit. A push to main reads them
   from the pushed commit itself, so the push that adds them already runs, attests and publishes everything.

5. Pass the key only from a job that runs on pushes to the default branch, names the environment and may write
   (`permissions: contents: write`: `vci ci --push` publishes `refs/meta/main` with the checkout's credentials).
   Pull requests run a job without the key and only consume attestations. A complete workflow (Vitest; swap the
   toolchain steps for [other runners](#setup-steps-for-each-runner)):

```yaml
name: test

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  # Pull requests: skip what is attested, run the rest. No key, read-only.
  test:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0      # the base commit must be available
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - uses: PandelisZ/cryptographically-verifiable-ci-runner@v1

  # Pushes to main: run what is not attested, attest it, publish it.
  test-main:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    environment: vci-attest   # the only place VCI_SIGNING_KEY exists
    permissions:
      contents: write         # git-meta pushes refs/meta/main with the checkout's credentials
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - uses: PandelisZ/cryptographically-verifiable-ci-runner@v1
        with:
          signing-key: ${{ secrets.VCI_SIGNING_KEY }}
          # ttl: 14d          # lifetime of CI's attestations (at most policy.max_ttl)
          # push: true        # publish them on refs/meta/main (a failed push is a warning)
```

With `signing-key`, the action writes the key to `$RUNNER_TEMP/vci-key` (mode 600, never printed), runs
`vci ci --key "$RUNNER_TEMP/vci-key" --ttl 14d --push --remote origin`, removes the key file, and sets the output
`attested`. The audit log lists the units under `attested` and whether the push worked under `pushed`. A unit that
fails or that `vci run` would refuse still runs and is not attested; only test failures fail the job, and a failed
push is a `::warning`, never a failure. Each attestation expires after `ttl`, after which its unit runs, and is
attested, again. Details: [CI attests its own runs](REFERENCE.md#ci-attests-its-own-runs).

### Why an environment

A `pull_request` run uses the branch's own copy of the workflow, so an `if:` or
`github.event_name == 'push' && secrets.VCI_SIGNING_KEY || ''` in the workflow cannot keep a repository secret from
anyone who can push a branch; the environment's branch rule is enforced by GitHub, outside the workflow. Otherwise a
branch's run would sign as `github-actions` and, after a merge, main would skip units whose code only that branch's
run executed. As a second line, `vci ci --key` refuses to attest (a `::warning`, the tests still run, nothing is
pushed) when the key's principal is in `no_skip_refs_except` and the current ref does not match `no_skip_refs`; that
guards against a misconfigured workflow, not against a branch that changes it. To attest pull request runs too,
give them a different key whose principal is not in `no_skip_refs_except`: main never skips on its word. Fork pull
requests get no secrets.

### What the key is shared with

It is written to `$RUNNER_TEMP` (mode 600) for the run and removed afterwards, but every process of the job runs as
the same user (with passwordless `sudo` on GitHub-hosted runners), so the tests, every test dependency (npm, PyPI,
gem and crate packages, build scripts) and every other step of that job can read it, and no step split inside one
job changes that. Whoever copies it can sign as `github-actions` and make main skip any unit until its line is
removed from `.vci/allowed_signers`. So treat it as a credential your locked dependencies share:

- keep it in the restricted environment, and use one key per repository, never an organization secret;
- keep `ttl` short;
- rotate by replacing its line in `.vci/allowed_signers` on the default branch (a new key under the same principal),
  then the secret, and do so whenever a dependency of the attested job is found compromised. Attestations it signed
  stop counting the moment the line is gone, and the next push to main runs and attests everything again;
- list no developer or agent principal in `no_skip_refs_except`.

## Pinning

The action is the verifier, so choose how far it may move:

| Reference | Moves? | Use when |
|---|---|---|
| `@v1` | only to tested 1.x releases | the default |
| `@v1.0.0` | never | you want a specific release |
| `@<full commit SHA>` | never | strictest pinning; the SHA is on each [release page](https://github.com/PandelisZ/cryptographically-verifiable-ci-runner/releases) |

Never reference a branch.

## Prebuilt binaries

By default the action downloads a release binary, which takes a few seconds instead of about two minutes of
compiling. It uses the download only when the pinned action's `release/manifest.txt` names a release built from
exactly the action's own sources, a binary exists for the runner (Linux or macOS, x86_64 or arm64), and its SHA-256
equals the checksum in that manifest. Otherwise it builds from source and caches the result; because the checksums
are part of the pinned action, replacing a release asset cannot change what runs.

## Security rules

CI takes its rules (trusted keys and policy) from the base branch, and only code and attestations from the pull
request. The diagram is on the [docs site](https://pandelisz.github.io/cryptographically-verifiable-ci-runner/github-actions.html#security-rules).

- **Pin the action.** It is the verifier (see [Pinning](#pinning)).
- **Never build `vci` from the pull request's own checkout.** The pull request could change the verifier that checks
  it. This repository's own workflow does so only because it is the demo for the action itself.
- **Leave `base-ref` at its default**, unless you know the ref is outside the pull request's control. `vci` warns
  when the base commit is, or contains, the commit under test.
- **Keep `refs/heads/main` in `policy.no_skip_refs`** (the `vci init` default). Pushes to the default branch then run
  everything: the backstop against a trusted signer making a false claim. `policy.no_skip_refs_except` lets only CI's
  own key skip there (see [Attesting in CI](#attesting-in-ci)); list no developer or agent principal in it.
- **Use `pull_request`, not `pull_request_target`.** Fork pull requests cannot push attestations to your repository,
  so every test runs for them.
- **Revoke a signer** by removing their line from `.vci/allowed_signers` on the default branch. Their attestations
  stop being accepted at once.
- **Without the action, always pass `--remote`** to `vci fetch`. Without it, a clone with no git-meta remote takes the
  URL from `.git-meta` in the checked-out commit, which a pull request controls. vci refuses remote-helper URLs such as
  `fd::3`, and a foreign remote can only make tests run, but the checkout should not choose where attestations come
  from.

## Who can push attestations

`vci push` (like `git meta push`) writes `refs/meta/main`. Anyone with push access to the repository can write,
overwrite or delete metadata there.

That is safe by design. An attestation only counts when its signature verifies against a key in the base commit's
`.vci/allowed_signers`, and it matches the unit, repository, toolchain and inputs exactly. A deleted or overwritten
attestation only makes its unit run.

git-meta's auto-prune (`meta:prune:max-keys`, `meta:prune:max-size`) and filter rules (`meta:filter`) are themselves
metadata on the `project` target, so anyone who can push metadata can turn them on for everyone. With auto-prune on,
any `git meta push` drops the least recently written attestations from the remote; their units then run until
attested again. `vci fetch` warns when such a setting is present, and when a fetch removed attestations without a
deletion record (the warning shows in the action's log).

To limit who may write, add a repository ruleset on `refs/meta/**`; when CI attests its own runs, let the main-branch
job's token through it. If your metadata lives in a separate repository (`.git-meta` names another URL), pass that
URL as `remote` and make sure the job can read it (and, to push CI's attestations, write to it).

## Without the action

```yaml
      - name: Install vci
        run: |
          git clone \
            https://github.com/PandelisZ/cryptographically-verifiable-ci-runner \
            "$RUNNER_TEMP/vci"
          git -C "$RUNNER_TEMP/vci" checkout v1.0.0
          cargo install --locked --path "$RUNNER_TEMP/vci/crates/vci-cli"
          echo "VCI_PY_PLUGIN=$RUNNER_TEMP/vci/py/pytest-plugin" >> "$GITHUB_ENV"
          echo "VCI_JS_PLUGIN=$RUNNER_TEMP/vci/js/vitest-plugin" >> "$GITHUB_ENV"
          echo "VCI_RUBY_COLLECTOR=$RUNNER_TEMP/vci/ruby/vci-collector" >> "$GITHUB_ENV"

      - run: vci fetch --remote origin

      - run: |
          vci ci \
            --base-ref "${{ github.event.pull_request.base.sha || github.sha }}" \
            --audit-log vci-audit.json
```

To attest CI's runs without the action, do it only in a job like `test-main` [above](#attesting-in-ci) (pushes to
main, the `vci-attest` environment, `contents: write`):

```yaml
      - name: Run what is not attested, attest it, publish it
        env:
          KEY: ${{ secrets.VCI_SIGNING_KEY }}
        run: |
          trap 'rm -f "$RUNNER_TEMP/vci-key"' EXIT
          (umask 077 && printf '%s\n' "$KEY" > "$RUNNER_TEMP/vci-key")
          vci ci --base-ref "${{ github.sha }}" --audit-log vci-audit.json \
            --key "$RUNNER_TEMP/vci-key" --ttl 14d --push --remote origin
```

## Troubleshooting

Run `vci explain <file> --base-ref origin/main` locally for the full reason a unit ran.

| Symptom | Likely cause |
|---|---|
| Everything runs on a pull request | `vci.toml` or `.vci/allowed_signers` is not on the base branch yet; or attestations were not pushed (`git ls-remote origin refs/meta/main` is empty) |
| `failed check: toolchain` | Python, Node, uv, Ruby, Bundler or package versions differ between the laptop and the runner |
| `failed check: inputs` | A file the test depends on changed after it was attested; `vci explain` names it |
| `failed check: signer` | The signing key is not in the base commit's `allowed_signers`, or it has expired |
| `failed check: signer` on main, `... is not in no_skip_refs_except` | Expected: on a ref in `policy.no_skip_refs` only the principals in `policy.no_skip_refs_except` (CI's key) can skip |
| Every push to main still runs everything | `no_skip_refs_except` is empty or not on main yet, the CI key's line is not in main's `allowed_signers`, the previous push's attestations were not published (see `pushed` in the audit log and the `could not push attestations` warning: the job needs `contents: write`), or the key changed |
| `::warning title=vci::not attesting: the key signs as github-actions ...` | The CI key reached a run on a ref outside `no_skip_refs` (a pull request): pass it only from the main-branch job with the environment |
| A Go package or cargo target never skips on the runner | Its code depends on the platform (build tags, `_linux.go` files, `cfg(target_os)`, `runtime.GOOS`, floating-point maths): such units are only accepted on the same OS and architecture |
| A test reads `CI`, `HOME` or `USER` | Those values differ on a runner, so that file always runs there |
| No Rails test file ever skips on the runner | `config/environments/test.rb` reads `ENV["CI"]` (the generator's `config.eager_load = ENV["CI"].present?`); the Ruby patchlevel, Bundler, SQLite library or time zone data differ (`failed check: toolchain`; use `gem "tzinfo-data"`); or `Gemfile.lock` lacks the runner's platform |
| An RSpec file is never attested | An example is pending, skipped or filtered out (`fit` with `filter_run_when_matching :focus`, an excluded tag), rspec-retry / parallel_tests is loaded, a failure was retried away (`rspec:failure-cleared`), or the process exited non-zero after RSpec's report (SimpleCov's `minimum_coverage`: `vci:process-exit:2`). `vci run` prints the reason (`rspec:filtered:...`, `rspec:retry`, ...) |
| Every Rails test is refused on a Mac with `/etc/resolv.conf`, `native:FFI ffi_lib(["vips.42"])` or `config/master.key` | An older collector (`resolv.conf`, read when Capybara loads `net/http`; `ffi_lib`, which collector 0.4.0 records instead of refusing, so `image_processing`/`ruby-vips` with Homebrew libvips is attested), or the generator's credentials: see "What the Rails adapter records" in [the reference](REFERENCE.md#what-the-rails-adapter-records) |
| Every Rails test is refused on the runner with `ruby:read-outside-bundle:stat .../vendor/bundle/ruby/3.4.0` | Collector 0.4.1, which took the bundle `bundler-cache` installs inside the repository for gems outside the bundle. Collector 0.4.2 attests these files; its new version makes existing Rails attestations run once more |
| Minitest files never run with `runner = "rspec"` | An explicit runner leaves the other runner's files to you: `vci plan`/`ci` warn and the audit log lists it under `warnings` |

## For maintainers: cutting a release

```sh
git tag v1.1.0 && git push origin v1.1.0      # the release workflow builds and publishes the binaries
scripts/update-release-manifest.sh v1.1.0     # after it finishes: records tag, source fingerprint and checksums
git add release/manifest.txt && git commit -m "Record release v1.1.0" && git push
git tag -f v1 && git push -f origin v1         # move the major tag to the commit that carries the manifest
```

`@v1` therefore always points at a commit whose `release/manifest.txt` matches the published binaries. Any later change
under `crates/`, `Cargo.toml` or `Cargo.lock` makes the action build from source again until the next release.
