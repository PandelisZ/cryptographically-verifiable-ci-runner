# Install and run

## Requirements

| Tool | Needed for |
|---|---|
| `git` | everything |
| Rust toolchain (`cargo`, 1.85+) | building the `vci` binary |
| `ssh-keygen` (OpenSSH 8.1+) and an Ed25519 SSH key | signing attestations |
| Node 22.15+ and Vitest `>=3.2 <6` | Vitest projects |
| [`uv`](https://docs.astral.sh/uv/) and pytest 9 | pytest projects |
| Go (tested with 1.26.2) | Go projects |
| `cargo`/`rustc` installed through `rustup` | Rust projects |

macOS and Linux are supported.

## Install

With the install script (clones to `~/.local/share/vci` and builds with cargo):

```sh
curl -fsSL https://raw.githubusercontent.com/PandelisZ/cryptographically-verifiable-ci-runner/main/scripts/install.sh | sh
```

While the repository is private, the raw URL needs authentication, so clone and run the script instead:

```sh
gh repo clone PandelisZ/cryptographically-verifiable-ci-runner ~/.local/share/vci
~/.local/share/vci/scripts/install.sh
```

Or by hand:

```sh
git clone https://github.com/PandelisZ/cryptographically-verifiable-ci-runner.git ~/.local/share/vci
cargo install --locked --path ~/.local/share/vci/crates/vci-cli
```

Then tell `vci` where its collectors live (add to your shell profile):

```sh
export VCI_PY_PLUGIN="$HOME/.local/share/vci/py/pytest-plugin"
export VCI_JS_PLUGIN="$HOME/.local/share/vci/js/vitest-plugin"
```

Check the install:

```sh
vci --version
```

To pin a version, set `VCI_REF` to a tag or commit before running the script.

## Set up a repository (once)

Run these in the repository you want to speed up.

1. **Create the config and trust file.**

   ```sh
   vci init --adapter pytest --project . --key ~/.ssh/id_ed25519.pub --principal you@example.com
   # or: vci init --adapter vitest --key ~/.ssh/id_ed25519.pub --no-install
   # or: vci init --adapter go     --key ~/.ssh/id_ed25519.pub
   # or: vci init --adapter cargo  --key ~/.ssh/id_ed25519.pub
   ```

   This writes `vci.toml` (policy and env config) and `.vci/allowed_signers` (who may attest).

2. **Add every person or agent who may attest** to `.vci/allowed_signers`, one line each:

   ```
   alice@example.com namespaces="vci-attest" ssh-ed25519 AAAAC3Nza...
   build-agent namespaces="vci-attest",valid-before="20270101" ssh-ed25519 AAAAC3Nza...
   ```

   Give agents their own key, not a person's key, and an expiry.

3. **Merge both files to your default branch.** CI reads them from the base commit, never from the pull request, so
   they have no effect until they are on `main`.

4. **Pin toolchains** so local and CI runs match (see the README section "Attesting on macOS, verifying on Linux"):

   | Runner | Pin |
   |---|---|
   | pytest | full Python version in `.python-version` (a uv-managed build such as `3.14.4`), `uv.lock`, the uv version, `UV_PYTHON_PREFERENCE=only-managed` |
   | Vitest | Node major version, `package-lock.json` |
   | Go | exact Go version (`go version` must print the same on both sides), `go.sum`, `CGO_ENABLED=0` and `TZ=UTC` declared in `[env] global` and set on both sides |
   | Rust | exact release in `rust-toolchain.toml` (a `rustup` build, not Homebrew's), `Cargo.lock`, `[env] mode = "strict"` |

   One repository can hold several projects with different adapters: see "Several projects in one repository" in
   the README, and this repository's own [`vci.toml`](../vci.toml).

## What a test unit is

| Adapter | Unit | Written as |
|---|---|---|
| `vitest` | test file | `src/b.test.ts` |
| `pytest` | test file | `tests/test_b.py` |
| `go` | package | `./b` (package directory) |
| `cargo` | test target | `crates/b#lib`, `crates/b#test:name`, `crates/b#doc` |

How inputs are found differs by adapter. Vitest, pytest and Go record what each unit actually read while it ran.
Rust has no such hook, so the cargo adapter treats every file in the package directory and its in-repo dependencies
as an input; files read from elsewhere in the repository must be declared. See "What the cargo adapter can and
cannot see" in the README.

## Daily use

```sh
# Run some tests locally and sign what was run. Paths are relative to the current directory.
vci run tests/test_b.py tests/test_c.py --key ~/.ssh/id_ed25519

# See what CI would do.
vci plan --base-ref origin/main

# Share the attestations. Push your branch as usual.
vci push
git push
```

For Go and Rust:

```sh
vci run ./b ./d --key ~/.ssh/id_ed25519                   # Go packages
vci run 'crates/b#test:b' crates/a --key ~/.ssh/id_ed25519  # one cargo target; every target of a package
```

`vci run` with no paths runs and attests every unit.

When a test is not skipped and you expected it to be:

```sh
vci explain tests/test_b.py --base-ref origin/main
```

It prints each candidate attestation and the first check that failed, with the expected and actual values.

## For agents

An agent uses the same commands. Give it:

- its own Ed25519 key, listed in `.vci/allowed_signers` on the default branch;
- `VCI_PY_PLUGIN` / `VCI_JS_PLUGIN` in its environment;
- push access to `refs/attest/v1/*` on the remote.

Set `VCI_SIGNING_KEY=/path/to/key` so `--key` can be left out.

## Commands

| Command | Purpose |
|---|---|
| `vci init` | Write `vci.toml` and `.vci/allowed_signers` |
| `vci run [FILES…]` | Run tests, collect inputs, sign, store attestations |
| `vci plan` | Decide which test files can be skipped |
| `vci ci` | Plan, run the rest, write an audit log |
| `vci explain <file>` | Show why a file was not skipped |
| `vci push` / `vci fetch` | Sync attestation refs with a remote |
| `vci verify <envelope>` | Verify one attestation |

Next: [set up GitHub Actions](GITHUB_ACTIONS.md).
