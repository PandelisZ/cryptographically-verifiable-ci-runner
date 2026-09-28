# GitHub Actions setup

The repository ships a composite action that builds `vci`, fetches attestations, prints the plan, and runs only the
tests that are not covered by a valid attestation.

## Before you start

1. `vci.toml` and `.vci/allowed_signers` are merged to your default branch ([install guide](INSTALL.md)).
2. Attestations are pushed with `vci push` before or together with the branch.

## Workflow

Save as `.github/workflows/test.yml`. Set up your language toolchain first, then call the action.

### pytest (uv)

```yaml
name: test

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

env:
  UV_PYTHON_PREFERENCE: only-managed

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0            # the base commit must be available

      - uses: astral-sh/setup-uv@v6
        with:
          version: "0.11.7"         # same uv version as used locally

      - run: uv sync --locked

      - uses: PandelisZ/cryptographically-verifiable-ci-runner@<commit-sha>
```

### Vitest

```yaml
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: 22          # same Node major version as used locally
          cache: npm

      - run: npm ci

      - uses: PandelisZ/cryptographically-verifiable-ci-runner@<commit-sha>
```

### Go

```yaml
    env:
      CGO_ENABLED: "0"              # same values as used locally; both are declared in vci.toml [env] global
      TZ: UTC
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version: "1.26.2"      # exact version used locally

      - run: go mod download

      - uses: PandelisZ/cryptographically-verifiable-ci-runner@<commit-sha>
```

### Rust

```yaml
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: "1.95.0"       # same release as rust-toolchain.toml

      - run: cargo fetch --locked

      - uses: PandelisZ/cryptographically-verifiable-ci-runner@<commit-sha>
```

Run the job on the hosted runner directly, not in a `container:` job: attestations made as a normal user are not
accepted by a verifier running as root.

### Several languages in one job

Set up every toolchain, then call the action once. This repository's own
[workflow](../.github/workflows/ci.yml) does that for Python, Go and Rust.

Replace `<commit-sha>` with a full commit SHA of this repository.

## Inputs and outputs

| Input | Default | Meaning |
|---|---|---|
| `base-ref` | PR base commit, or the pushed commit | Commit that policy and trusted signers are read from |
| `command` | `ci` | `ci` plans and runs the rest; `plan` only decides |
| `remote` | `origin` | Remote that holds `refs/attest/v1/*` |
| `audit-log` | `vci-audit.json` | JSON record of what was skipped, by whom, and what ran |
| `working-directory` | `.` | Directory to run `vci` from |
| `prebuilt` | `true` | Download the release binary instead of compiling; `false` always builds from source |
| `token` | `github.token` | Token used to download the release binary |

| Output | Meaning |
|---|---|
| `skipped` | Number of test units skipped |
| `run` | Number of test units that ran |

The plan is also written to the job summary.

## Prebuilt binaries

The action downloads a release binary instead of compiling `vci`, which takes a few seconds instead of about two
minutes. It does so only when all of these hold:

- `release/manifest.txt` in the pinned action names a release that was built from exactly the action's own sources;
- a binary exists for the runner (Linux and macOS, x86_64 and arm64);
- the download's SHA-256 equals the checksum in `release/manifest.txt`.

Otherwise it builds from source and caches the result. The checksums are part of the pinned action, so replacing
a release asset cannot change what runs.

### Cutting a release

```sh
git tag v0.2.0 && git push origin v0.2.0      # the release workflow builds and publishes the binaries
scripts/update-release-manifest.sh v0.2.0     # after it finishes: records tag, source fingerprint and checksums
git add release/manifest.txt && git commit -m "Record release v0.2.0" && git push
```

Pin the action to that last commit. Any later change under `crates/`, `Cargo.toml` or `Cargo.lock` makes the action
build from source again until the next release.

## Security rules

- **Pin the action to a commit SHA.** The action is the verifier. A branch or tag reference can move.
- **Never build `vci` from the pull request's own checkout.** A pull request could change the verifier that checks
  it. This repository's own workflow does so only because it is the demo for the action itself.
- **Leave `base-ref` at its default** unless you know the ref is outside the pull request's control. `vci` warns
  when the base commit is, or contains, the commit under test.
- **Keep `refs/heads/main` in `policy.no_skip_refs`** (the `vci init` default), so pushes to the default branch run
  everything. That full run is the backstop against a trusted signer making a false claim.
- **Use `pull_request`, not `pull_request_target`.** Pull requests from forks cannot push attestation refs to your
  repository, so they get no skips and every test runs.
- **Revoke by removing the line** from `.vci/allowed_signers` on the default branch. Attestations by that key stop
  being accepted at once.

## Who can push attestations

`vci push` writes to `refs/attest/v1/<signer>`. Anyone with push access to the repository can write those refs, but
an attestation only counts when its signature verifies against a key in the base commit's `.vci/allowed_signers`.
A repository ruleset on `refs/attest/**` can further restrict who may write them.

## Without the action

```yaml
      - name: Install vci
        run: |
          git clone https://github.com/PandelisZ/cryptographically-verifiable-ci-runner "$RUNNER_TEMP/vci"
          git -C "$RUNNER_TEMP/vci" checkout <commit-sha>
          cargo install --locked --path "$RUNNER_TEMP/vci/crates/vci-cli"
          echo "VCI_PY_PLUGIN=$RUNNER_TEMP/vci/py/pytest-plugin" >> "$GITHUB_ENV"
          echo "VCI_JS_PLUGIN=$RUNNER_TEMP/vci/js/vitest-plugin" >> "$GITHUB_ENV"

      - run: vci fetch --remote origin

      - run: vci ci --base-ref "${{ github.event.pull_request.base.sha || github.sha }}" --audit-log vci-audit.json
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Everything runs on a pull request | `vci.toml` or `.vci/allowed_signers` is not on the base branch yet; or attestations were not pushed |
| `failed check: toolchain` | Python, Node, uv or package versions differ between the laptop and the runner |
| `failed check: inputs` | A file the test depends on changed after it was attested; `vci explain` names it |
| `failed check: signer` | The signing key is not in the base commit's `allowed_signers`, or it has expired |
| A Go package or cargo target never skips on the runner | Its code depends on the platform (build tags, `_linux.go` files, `cfg(target_os)`, `runtime.GOOS`, floating-point maths): such units are only accepted on the same OS and architecture |
| A test reads `CI`, `HOME` or `TMPDIR` | Those values differ on a runner, so that file always runs there |

Run `vci explain <file> --base-ref origin/main` locally for the full reason.
