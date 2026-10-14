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
3. Attestations are pushed with `vci push` (or `git meta push`) before, or together with, the branch.

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

| Output | Meaning |
|---|---|
| `skipped` | Number of test units skipped |
| `run` | Number of test units that ran |

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
  everything: the backstop against a trusted signer making a false claim.
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

To limit who may write, add a repository ruleset on `refs/meta/**`. If your metadata lives in a separate repository
(`.git-meta` names another URL), pass that URL as `remote` and make sure the job can read it.

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

## Troubleshooting

Run `vci explain <file> --base-ref origin/main` locally for the full reason a unit ran.

| Symptom | Likely cause |
|---|---|
| Everything runs on a pull request | `vci.toml` or `.vci/allowed_signers` is not on the base branch yet; or attestations were not pushed (`git ls-remote origin refs/meta/main` is empty) |
| `failed check: toolchain` | Python, Node, uv, Ruby, Bundler or package versions differ between the laptop and the runner |
| `failed check: inputs` | A file the test depends on changed after it was attested; `vci explain` names it |
| `failed check: signer` | The signing key is not in the base commit's `allowed_signers`, or it has expired |
| A Go package or cargo target never skips on the runner | Its code depends on the platform (build tags, `_linux.go` files, `cfg(target_os)`, `runtime.GOOS`, floating-point maths): such units are only accepted on the same OS and architecture |
| A test reads `CI`, `HOME` or `USER` | Those values differ on a runner, so that file always runs there |
| No Rails test file ever skips on the runner | `config/environments/test.rb` reads `ENV["CI"]` (the generator's `config.eager_load = ENV["CI"].present?`); the Ruby patchlevel, Bundler, SQLite library or time zone data differ (`failed check: toolchain`; use `gem "tzinfo-data"`); or `Gemfile.lock` lacks the runner's platform |
| An RSpec file is never attested | An example is pending, skipped or filtered out (`fit` with `filter_run_when_matching :focus`, an excluded tag), rspec-retry / parallel_tests is loaded, a failure was retried away (`rspec:failure-cleared`), or the process exited non-zero after RSpec's report (SimpleCov's `minimum_coverage`: `vci:process-exit:2`). `vci run` prints the reason (`rspec:filtered:...`, `rspec:retry`, ...) |
| Every Rails test is refused on a Mac with `/etc/resolv.conf`, `native:FFI ffi_lib(["vips.42"])` or `config/master.key` | An older collector (`resolv.conf`, read when Capybara loads `net/http`; `ffi_lib`, which collector 0.4.0 records instead of refusing, so `image_processing`/`ruby-vips` with Homebrew libvips is attested), or the generator's credentials: see "What the Rails adapter records" in [the reference](REFERENCE.md#what-the-rails-adapter-records) |
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
