# vci

**Stop paying CI to re-run tests you already ran.** Up to 90% less CI time per pull request, with a signed proof behind every skipped test.

vci is a command-line tool and a GitHub Action. A developer or an AI agent runs some tests on their own machine; vci records exactly what those tests depended on, signs that record, and stores it in git. When the pull request reaches CI, vci checks each record and runs only the tests nobody has already run against the same inputs.

```
$ vci plan --base-ref origin/main
SKIP spec/models/order_spec.rb     (attested by alice@example.com (SHA256:tsNeKgQt…))
SKIP services/pricing              (attested by build-agent (SHA256:RASHZ3Nm…))
RUN  spec/requests/orders_spec.rb  (no attestation)
RUN  services/billing              (no valid attestation (1 candidates; best failed inputs: entry:services/billing/rates.json))
2 to skip, 2 to run
```

Works with **Vitest, node:test (`node --test`), pytest, Go, Cargo, Rails (Minitest) and RSpec**, on macOS and Linux. MIT.

![A change made in an agent's sandbox is attested, pushed through git, verified and skipped by CI](site/assets/walkthrough.gif)

<sub>The same animation, with controls, is on the <a href="https://pandelisz.github.io/cryptographically-verifiable-ci-runner/">docs site</a>.</sub>

Docs: [pandelisz.github.io/cryptographically-verifiable-ci-runner](https://pandelisz.github.io/cryptographically-verifiable-ci-runner/) · [Examples with real output](https://pandelisz.github.io/cryptographically-verifiable-ci-runner/examples.html) · [Full reference](docs/REFERENCE.md)

## The problem: CI is the bottleneck now

For twenty years CI was sized for human output: a few pull requests per engineer per week, one pipeline run each. Coding agents broke that arithmetic, and the teams that hit it first have written it down.

- Anthropic, September 2026: *"Writing code is no longer the constraint, and once PR review gets accelerated, CI starts feeling the pressure."* Engineers ship 8× as much code per quarter as in 2021–2025, Claude writes 80% of it, tests grew 10×, and CI jobs grew **25× in six months**. ([source](https://claude.com/blog/agentic-coding-is-straining-ci-heres-how-we-scaled-test-impact-analysis-at-anthropic))
- Anthropic, October 2026: *"The bottleneck, now, is all of the developer infrastructure built for human scale: source control, builds, and CI."* ([source](https://www.anthropic.com/engineering/redesigning-source-control))
- Linear: *"AI coding has made CI a bottleneck"*; their suite nearly quadrupled in a year and grows by ~2,000 tests a week. ([source](https://linear.app/now/ci-bottleneck-reworked))
- CircleCI, 28 million workflows: throughput up 59%, main-branch success down to 70.8%, a five-year low. ([source](https://www.oreilly.com/radar/coding-was-never-a-bottleneck/))

Agents removed the cost of producing a change. They did not remove the cost of knowing whether to trust it, so that cost lands on CI, all at once.

And every one of those pipelines still re-runs tests the author ran minutes earlier on the same code. An agent edits a model, runs the three specs that cover it, sees them pass, opens a PR; CI runs those three again, plus everything else. The work was done and the result thrown away, because CI had no reason to believe it.

The obvious fix, "trust the pull request when it says the tests passed", is not safe. A claim is not a proof: the code may have changed since the run, a dependency may differ, the agent may be wrong or malicious, and the CI machine is not the laptop. vci makes the claim checkable.

## What vci does

vci turns "I ran the tests" into something CI can check.

1. **Record.** `vci run` executes the tests with a collector attached to the test runner. The collector observes every file the test read, every file it looked for and did not find, every directory it listed, every package it loaded and every environment variable it consulted. vci hashes all of it.
2. **Sign.** The result (what ran, against which hashes, with which toolchain, by whom) is signed with the developer's or agent's SSH key as an [in-toto](https://in-toto.io/) attestation.
3. **Share.** The attestation is stored as [git-meta](https://git-meta.com/) metadata on the test's path and pushed with `vci push`. It travels through git; there is no server and no database.
4. **Verify.** In CI, `vci ci` reads the trusted keys and policy from the *base* branch, checks each signature, re-hashes every recorded input from CI's own checkout, and skips a test only when everything matches. Then it runs the rest.

## Why it is safe

- **Fail open.** The default is to run. Any mismatch, missing key, expired attestation, unreadable record or unexpected behaviour means the test runs. A mistake can only cost a skip, never cause one.
- **Observed inputs, not guesses.** Dependencies are recorded from what the test actually did at run time, not inferred from imports. A fixture file read with `open()`, a template rendered on demand, a module loaded by name: all recorded. Anything the collector cannot see, such as a child process or a network call, makes the test ineligible.
- **Trust comes from the base branch.** The list of accepted keys and the policy are read from the commit the pull request targets, so a pull request cannot add its own key or loosen the rules.
- **Signed by identity, checked by content.** Each attestation names who signed it, and CI re-derives every hash itself. Nothing in the stored record is trusted on its own.

What vci does not do: it cannot tell whether a trusted signer lied. Keep the signer list short, give agents their own keys with expiry dates, and let only CI's own key skip anything on your default branch. The [threat model](docs/REFERENCE.md#threat-model-v1) has the details.

## What it saves

![CI time for one pull request, full suite versus vci, in five cases](site/assets/savings.svg)

The saving is exactly the tests that were attested and still match; the cost is about ten seconds to fetch and verify. When nothing was attested, when the toolchain differs from CI, or on your default branch when CI does not attest its own runs, the suite runs in full as before. Compute minutes follow the same proportions as time.

## Install

vci runs on macOS and Linux and needs `git` and `ssh-keygen` (OpenSSH 8.1+). Pick one:

**Homebrew** (macOS and Linux; prebuilt binary, collectors included, nothing else to set up):

```sh
brew install pandelisz/tap/vci
```

**Install script** (builds from source with cargo; needs a Rust toolchain 1.85+):

```sh
curl -fsSL https://raw.githubusercontent.com/PandelisZ/cryptographically-verifiable-ci-runner/main/scripts/install.sh | sh
```

It clones to `~/.local/share/vci` and installs `vci` to `~/.cargo/bin`. Set `VCI_REF` to a tag or commit to pin a version. Then add the collector paths it prints to your shell profile:

```sh
export VCI_PY_PLUGIN="$HOME/.local/share/vci/py/pytest-plugin"
export VCI_JS_PLUGIN="$HOME/.local/share/vci/js/vitest-plugin"
export VCI_RUBY_COLLECTOR="$HOME/.local/share/vci/ruby/vci-collector"
```

**From a checkout** (for working on vci itself):

```sh
git clone https://github.com/PandelisZ/cryptographically-verifiable-ci-runner.git
cd cryptographically-verifiable-ci-runner
cargo install --locked --path crates/vci-cli
```

A `vci` built this way finds the pytest and Ruby collectors in the checkout it was built from; for Vitest, set `VCI_JS_PLUGIN` to the checkout's `js/vitest-plugin`.

Check it worked with `vci --version`. Upgrade with `brew upgrade vci`, or by re-running the install script. vci is not published to crates.io. Prebuilt binaries for each release are on the [releases page](https://github.com/PandelisZ/cryptographically-verifiable-ci-runner/releases).

You also need the toolchain for the test runner you use (Node and Vitest, uv and pytest, Go, rustup, or Ruby and Bundler): see [Install and run](docs/INSTALL.md) for versions.

## Quick start

In your repository, once:

```sh
vci init --adapter pytest --key ~/.ssh/id_ed25519.pub   # or vitest, node-test, go, cargo, rails
git add vci.toml .vci/allowed_signers .git-meta && git commit -m "Enable vci"
# Merge this to your default branch: trust is read from there.
```

Every day:

```sh
vci run tests/test_orders.py --key ~/.ssh/id_ed25519   # run, record, sign
vci plan --base-ref origin/main                         # what CI will skip
vci push && git push                                    # share the attestation and your branch
```

In GitHub Actions, after your toolchain setup steps:

```yaml
- uses: PandelisZ/cryptographically-verifiable-ci-runner@v1
```

The action downloads the published `vci` release binary (about a second, checksum pinned in the action), fetches the attestations, prints the plan in the job summary, runs what is left, and fails the job if any of it fails. It never compiles `vci` in your CI: pinned to a commit that has no published binary, it fails at once and says to use `@v1`. Setup and security notes: [docs/GITHUB_ACTIONS.md](docs/GITHUB_ACTIONS.md).

CI can attest its own runs too. Give the action a signing key of its own, kept as a secret that only pushes to your default branch can read, and each push to main records what it ran and passed. The next commit then skips every test whose inputs did not change, on main as well as on pull requests, so a commit that only touches the docs runs nothing CI already ran. Setup, and what trusting that key means: [Attesting in CI](docs/GITHUB_ACTIONS.md#attesting-in-ci).

## Test runners

| Adapter | Unit that can be skipped | Inputs found by |
|---|---|---|
| `vitest` | test file | observing the module graph, file and env reads |
| `node-test` | test file (`node --test`, options read from the package.json script) | Node's module hooks, file and env reads |
| `pytest` | test file | Python audit hooks and the import system |
| `go` | package | `go list` plus a logger built into the test binary |
| `cargo` | test target (`crates/x#lib`, `#test:name`) | conservative: every file of the crate and its in-repo dependencies |
| `rails` | Minitest or RSpec file | a Ruby collector wrapping file, env and process entry points |

Each adapter runs every unit in its own process, prepares fresh state (vci does not manage a Rails test database: Rails sets it up as in a plain `bin/rails test`, and what it holds is not an input), and refuses to attest a unit whose test was skipped, failed, or did something the collector cannot follow. Toolchain versions must match between the machine that attested and CI; the docs say what to pin for each runner.

Environment variables follow three short lists in `vci.toml`: `set` (vci sets them in every test process, on the laptop and in CI alike, so nobody exports `TZ=UTC`), `hash` (taken from the machine; another value re-runs the test) and `ignore` (visible, never hashed). Every other variable is removed from the test processes, apart from a short built-in list per runner. `vci env` prints the effective policy; details in [docs/ENV.md](docs/ENV.md).

## How a skip is decided

```
laptop / agent                              CI (pull request)
──────────────                              ─────────────────
vci run tests/test_b.py                     vci ci --base-ref <base>
  run test with collector                     read allowed_signers + vci.toml from <base>
  hash 318 inputs → root 21ff5d…              fetch refs/meta/main
  sign with ~/.ssh/id_ed25519                 for tests/test_b.py:
  store on path:tests/test_b.py                 signature by a key in allowed_signers?  ✓
vci push  ──── refs/meta/main ────▶             not expired, same toolchain?            ✓
                                                re-hash all 318 inputs here: same root? ✓
                                              → SKIP. Everything else → RUN.
```

If a test is not skipped and you expected it to be, `vci explain <unit> --base-ref origin/main` names the first check that failed and, for inputs, the file and both hashes.

## Use vci from an AI agent

[`skills/vci`](skills/vci/SKILL.md) is an agent skill that teaches Claude Code, Codex, Cursor and other agents the vci workflow: after a change, find the units that cover it, `vci run` them with the agent's own key, read what was attested or refused, check `vci plan`, and `vci push`. It also covers setup and `vci explain`, and forbids touching `allowed_signers`, weakening policy or attesting failing tests.

Two skills ship in this repository: `vci` (the workflow) and `vci-setup` (gets one engineer ready: CLI, trusted key, environment, first plan). Install both into every agent you use with the [skills CLI](https://github.com/vercel-labs/skills), which writes them where Claude Code, Codex, Cursor and the others look:

```sh
npx skills add PandelisZ/cryptographically-verifiable-ci-runner
```

Or per tool:

- **Claude Code** (plugin; the skills are also slash commands, `/vci-setup`):

  ```sh
  claude plugin marketplace add PandelisZ/cryptographically-verifiable-ci-runner
  claude plugin install vci@pandelisz
  ```

- **Codex**: in a session, `$skill-installer install https://github.com/PandelisZ/cryptographically-verifiable-ci-runner/tree/main/skills/vci`, or copy `skills/vci` and `skills/vci-setup` to `~/.agents/skills/` (yours) or a repository's `.agents/skills/`. A clone of this repository already offers them (`.agents/skills/`).

**Distribute to your org**: commit the skill into your monorepo once, at `.agents/skills/vci` (Codex) with a `.claude/skills/vci` symlink to it (Claude Code), and add your repository's facts and a setup script, as the vex monorepo does; every engineer's agent then has it. Every route, the org setup, and what was tested: [docs/AGENT-SKILL.md](docs/AGENT-SKILL.md).

## Learn more

| | |
|---|---|
| [Get started](https://pandelisz.github.io/cryptographically-verifiable-ci-runner/get-started.html) | Requirements, install, repository setup, agents |
| [Examples](https://pandelisz.github.io/cryptographically-verifiable-ci-runner/examples.html) | A full round trip with real output; setup per runner; what refusals look like |
| [Test runners](https://pandelisz.github.io/cryptographically-verifiable-ci-runner/adapters.html) | What each adapter records, refuses and needs pinned |
| [How it works](https://pandelisz.github.io/cryptographically-verifiable-ci-runner/security.html) | Attestations, verification, threat model |
| [Reference](docs/REFERENCE.md) | Everything, in one long document |
| [Design notes](docs/PLAN.md) | The original plan and the research behind it |

This repository is also the demo: `demo/` holds a project for every adapter, and [the CI workflow](.github/workflows/ci.yml) runs them through the action on each pull request. [Pull request 9](https://github.com/PandelisZ/cryptographically-verifiable-ci-runner/pull/9) shows units attested on a Mac being skipped on a Linux runner.

## Status

Version 1.0. Each adapter has an end-to-end test suite and has been verified against adversarial tests that try to produce a false skip; findings and remaining limits are listed under [Known gaps](docs/REFERENCE.md#known-gaps). Verification of a trusted signer's honesty (random re-runs in CI) is planned, not built.

## License

MIT License. See [LICENSE](LICENSE).
