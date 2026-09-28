# GitHub Actions setup

The repository ships a composite action that builds `vci`, fetches attestations, prints the plan, and runs only the
tests that are not covered by a valid attestation.

## Before you start

1. `vci.toml` and `.vci/allowed_signers` are merged to your default branch ([install guide](INSTALL.md)).
2. Attestations are pushed with `vci push` before or together with the branch.
3. While this repository is private, allow other repositories to use its action: in this repository go to
   **Settings → Actions → General → Access** and choose *Accessible from repositories owned by the user*.
   Public repositories cannot use an action from a private one.

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

Replace `<commit-sha>` with a full commit SHA of this repository.

## Inputs and outputs

| Input | Default | Meaning |
|---|---|---|
| `base-ref` | PR base commit, or the pushed commit | Commit that policy and trusted signers are read from |
| `command` | `ci` | `ci` plans and runs the rest; `plan` only decides |
| `remote` | `origin` | Remote that holds `refs/attest/v1/*` |
| `audit-log` | `vci-audit.json` | JSON record of what was skipped, by whom, and what ran |
| `working-directory` | `.` | Directory to run `vci` from |

| Output | Meaning |
|---|---|
| `skipped` | Number of test units skipped |
| `run` | Number of test units that ran |

The plan is also written to the job summary.

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

Cloning a private repository from another repository's workflow needs a token with read access to it.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Everything runs on a pull request | `vci.toml` or `.vci/allowed_signers` is not on the base branch yet; or attestations were not pushed |
| `failed check: toolchain` | Python, Node, uv or package versions differ between the laptop and the runner |
| `failed check: inputs` | A file the test depends on changed after it was attested; `vci explain` names it |
| `failed check: signer` | The signing key is not in the base commit's `allowed_signers`, or it has expired |
| A test reads `CI`, `HOME` or `TMPDIR` | Those values differ on a runner, so that file always runs there |

Run `vci explain <file> --base-ref origin/main` locally for the full reason.
