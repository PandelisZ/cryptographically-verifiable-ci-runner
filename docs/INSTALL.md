# Install and run

vci skips CI tests that a trusted person or agent already ran against identical inputs. This guide installs `vci`,
sets up one repository, and shows the commands you use every day. The docs site has the same guide:
[Get started](https://pandelisz.github.io/cryptographically-verifiable-ci-runner/get-started.html).

Terms used below:

- **Unit**: the smallest thing vci can skip: a test file, a Go package or a Cargo test target ([table](#what-a-test-unit-is)).
- **Attestation**: a record, signed with your SSH key, that says "this unit passed against exactly these inputs".
- **Collector**: the part of vci that runs inside the test runner and records every file and variable a unit reads.
- **Base branch**: the branch a pull request merges into, usually `main`. CI reads trusted keys and policy from it,
  never from the pull request.

## Requirements

| Tool | Needed for |
|---|---|
| `git` | everything |
| `ssh-keygen` (OpenSSH 8.1+) and an Ed25519 SSH key | signing attestations |
| Rust toolchain (`cargo`, 1.85+) | building the `vci` binary (not needed with Homebrew) |
| Node 22.15+ and Vitest `>=3.2 <6` | Vitest projects |
| [`uv`](https://docs.astral.sh/uv/) and pytest 9 | pytest projects |
| Go (tested with 1.26.2) | Go projects |
| `cargo`/`rustc` installed through `rustup` | Rust projects |
| Ruby (the exact version in `.ruby-version`; tested with 3.4.9 through mise), Bundler, Rails 8 with Minitest or RSpec (rspec-core 3.13, rspec-rails 8) | Rails projects (and plain Ruby projects with RSpec) |

macOS and Linux are supported.

## Install

### 1. Homebrew (recommended)

macOS and Linux. Installs a prebuilt binary with the collectors included, so there is nothing else to set up:

```sh
brew install pandelisz/tap/vci
```

Upgrade with `vci update` (it runs `brew update` and `brew upgrade pandelisz/tap/vci`), or `brew upgrade vci`.

### 2. Install script

Builds from source, so it needs `git`, `cargo` and `ssh-keygen`:

```sh
curl -fsSL \
  https://raw.githubusercontent.com/PandelisZ/cryptographically-verifiable-ci-runner/main/scripts/install.sh \
  | sh
```

The script:

- clones the repository to `~/.local/share/vci` (or updates the clone already there);
- installs `vci` with `cargo install`, to `~/.cargo/bin`;
- prints the three collector paths to add to your shell profile (below).

To pin a version, set `VCI_REF` to a tag or commit before running it (default: `main`). `VCI_HOME` changes where the
sources are kept.

### 3. By hand

```sh
git clone https://github.com/PandelisZ/cryptographically-verifiable-ci-runner.git \
  ~/.local/share/vci
cargo install --locked --path ~/.local/share/vci/crates/vci-cli
```

### Collector paths (script and by hand only)

Tell `vci` where its collectors live. Add this to your shell profile; Homebrew does not need it:

```sh
export VCI_PY_PLUGIN="$HOME/.local/share/vci/py/pytest-plugin"
export VCI_JS_PLUGIN="$HOME/.local/share/vci/js/vitest-plugin"
export VCI_RUBY_COLLECTOR="$HOME/.local/share/vci/ruby/vci-collector"
```

### Check the install

```sh
vci --version
```

### Keep it current

```sh
vci update           # install the latest release the way vci was installed
vci update --check   # only compare: exit 0 when current, 1 when there is an update
```

`vci update` uses Homebrew for a Homebrew install and re-runs the install script at the release's tag for the
script's install. A release binary downloaded by hand is replaced in place after its SHA-256 is checked; collectors
installed beside it are not updated.

## Set up a repository (once)

Run these in the repository you want to speed up.

- [ ] **Create the config and trust file.** Pick your adapter:

  ```sh
  vci init --adapter vitest --key ~/.ssh/id_ed25519.pub --no-install
  vci init --adapter pytest --key ~/.ssh/id_ed25519.pub
  vci init --adapter go     --key ~/.ssh/id_ed25519.pub
  vci init --adapter cargo  --key ~/.ssh/id_ed25519.pub
  vci init --adapter rails  --key ~/.ssh/id_ed25519.pub   # Rails, and RSpec (the runner is detected)
  ```

  This writes `vci.toml` (policy and env config), `.vci/allowed_signers` (who may attest, with your key first) and
  `.git-meta` (where attestations are exchanged). Add `--project DIR` when the project is not at the repository
  root, and `--principal you@example.com` to name the key's owner.

- [ ] **Add every person or agent who may attest** to `.vci/allowed_signers`, one line each:

  ```
  alice@example.com namespaces="vci-attest" ssh-ed25519 AAAAC3Nza...
  build-agent namespaces="vci-attest",valid-before="20270101" ssh-ed25519 AAAAC3Nza...
  ```

  Give agents their own key, not a person's key, and an expiry.

- [ ] **Merge the files to your default branch.** CI reads them from the base commit, never from the pull request,
  so nothing is skipped until they are on `main`.

  ```sh
  git add vci.toml .vci/allowed_signers .git-meta
  git commit -m "Enable vci"
  ```

  `.git-meta` is written only when the repository has an origin remote (or with `--meta-url <url>`); without one,
  leave it out of `git add`.

- [ ] **Pin toolchains** so local and CI runs match. An attestation only counts where the toolchain is the same (see
  "Attesting on macOS, verifying on Linux" in [the reference](REFERENCE.md)):

  | Runner | Pin |
  |---|---|
  | Vitest | Node major version, `package-lock.json` |
  | pytest | full Python version in `.python-version` (a uv-managed build such as `3.14.4`), `uv.lock`, the uv version, `UV_PYTHON_PREFERENCE=only-managed` |
  | Go | exact Go version (`go version` must print the same on both sides), `go.sum`, `[env] set = { TZ = "UTC", CGO_ENABLED = "0" }` in vci.toml (vci sets them on both sides) |
  | Rust | exact release in `rust-toolchain.toml` (a `rustup` build, not Homebrew's), `Cargo.lock`, no `mode = "loose"` in `[env]` (the default policy) |
  | Rails | exact Ruby in `.ruby-version` (and `ruby-version:` in `ruby/setup-ruby`), `Gemfile.lock` with the `x86_64-linux` platform (`bundle lock --add-platform x86_64-linux`), `gem "tzinfo-data"` for time zone data, `[env] set = { TZ = "UTC" }` in vci.toml, and `CI` left out of `[env]` (removed, so the generator's `config.eager_load = ENV["CI"].present?` is false on both sides) |
  | RSpec | everything in the Rails row, plus options in `.rspec` (vci never reads `~/.rspec`, `$XDG_CONFIG_HOME/rspec/options` or `.rspec-local`), and `SPEC_OPTS` listed in `[env] hash` (or `set`) if you use it |

- [ ] **Add the GitHub Action** after your toolchain setup: [GitHub Actions setup](GITHUB_ACTIONS.md).

One repository can hold several projects with different adapters: see "Several projects in one repository" in
[the reference](REFERENCE.md), and this repository's own [`vci.toml`](../vci.toml).

## What a test unit is

| Adapter | Unit | Written as |
|---|---|---|
| `vitest` | test file | `src/b.test.ts` |
| `pytest` | test file | `tests/test_b.py` |
| `go` | package | `./b` (package directory) |
| `cargo` | test target | `crates/b#lib`, `crates/b#test:name`, `crates/b#doc` |
| `rails` | Minitest test file or RSpec spec file, each in its own process | `test/models/b_test.rb`, `spec/models/b_spec.rb` |

For `rails`, `runner = "minitest"` or `"rspec"` in `vci.toml` picks the runner; without it, the runner is detected.
Each Minitest file runs in its own `bin/rails test <file>`, each spec file in its own `rspec --options .rspec <file>`.

How inputs are found differs by adapter:

- **Vitest, pytest and Go** record what each unit actually read while it ran.
- **Rust** has no such hook. The cargo adapter treats every file in the package directory and its in-repo
  dependencies as an input; files read from elsewhere in the repository must be declared. See "What the cargo
  adapter can and cannot see" in [the reference](REFERENCE.md).
- **Ruby** has no audit hook either. The Rails adapter's collector wraps Ruby's file, directory, environment, require
  and process entry points; the test database is the engine's (Rails sets it up as in a plain `bin/rails test`, and its
  contents are not an input). See "Quick start (Rails)"
  and "Quick start (RSpec)" in [the reference](REFERENCE.md) for what that covers and what it refuses.

## Daily use

```sh
# Run some tests locally and sign what was run. Paths are relative to the current directory.
vci run tests/test_b.py tests/test_c.py --key ~/.ssh/id_ed25519

# See what CI would do.
vci plan --base-ref origin/main

# Share the attestations (git-meta metadata on refs/meta/main), then push your branch as usual.
vci push                   # or: git meta push
git push
```

For Go and Rust, pass packages and targets:

```sh
vci run ./b ./d --key ~/.ssh/id_ed25519                     # Go packages
vci run 'crates/b#test:b' crates/a --key ~/.ssh/id_ed25519  # one cargo target; every target of a package
```

`vci run` with no paths runs and attests every unit. Set `VCI_SIGNING_KEY=/path/to/key` to leave out `--key`.

### When a test is not skipped

```sh
vci explain tests/test_b.py --base-ref origin/main
```

It prints each candidate attestation and the first check that failed, with the expected and actual values.

## For agents

An agent uses the same commands. Give it:

- [ ] its own Ed25519 key, listed in `.vci/allowed_signers` on the default branch (with an expiry);
- [ ] `VCI_PY_PLUGIN` / `VCI_JS_PLUGIN` / `VCI_RUBY_COLLECTOR` in its environment (not needed with Homebrew);
- [ ] `VCI_SIGNING_KEY` pointing at its key, so `--key` can be left out;
- [ ] push access to `refs/meta/main` on the metadata remote (git-meta; usually the repository itself).

## Commands

| Command | Purpose |
|---|---|
| `vci init` | Write `vci.toml`, `.vci/allowed_signers` and `.git-meta`; configure the git-meta remote |
| `vci run [FILES…]` | Run tests, collect inputs, sign, store attestations |
| `vci plan` | Decide which test files can be skipped |
| `vci ci` | Plan, run the rest, write an audit log |
| `vci explain <file>` | Show why a file was not skipped |
| `vci push` / `vci fetch` | git-meta push / pull of the attestations (`refs/meta/main`) |
| `vci prune` | Delete expired attestations (publish with `vci push`) |
| `vci verify <envelope>` | Verify one attestation |
| `vci update [--check]` | Install the latest release the way vci was installed; `--check` only compares |

Every flag: [CLI reference](https://pandelisz.github.io/cryptographically-verifiable-ci-runner/cli.html).

Next: [set up GitHub Actions](GITHUB_ACTIONS.md).
