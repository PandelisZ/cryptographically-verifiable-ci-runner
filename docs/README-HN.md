# vci, written for Hacker News

This is the README voice to use for the Show HN: first person, factual, peer to peer, technical details included,
limits stated. Replace the bracketed parts with your own words before posting. The second section is the Show HN
text itself (the first comment under the post).

---

## vci: skip the CI tests that were already run, with signed input hashes

I run tests before I push. Then CI runs the same tests on the same code and I wait for it. With coding agents
making many small pull requests, the waiting multiplied: an agent runs the tests that cover its change, pushes, and
CI runs all of them again plus everything else.

The obvious fix, trusting the pull request when it says the tests passed, isn't safe. A claim isn't a proof: the code
may have changed since the run, a dependency may differ, the agent may be wrong, and the CI machine isn't the laptop.

vci is my attempt at making the claim checkable. It is a Rust CLI and a GitHub Action, MIT licensed.

### What it does

1. **Record.** `vci run tests/test_orders.py` runs the test with a collector attached to the test runner. The
   collector observes every file the test read, every file it looked for and didn't find, every directory it listed,
   every package it loaded and every environment variable it consulted. vci hashes all of it (BLAKE3) into one root.
2. **Sign.** The record (what ran, against which hashes, with which toolchain, by whom) is signed with the
   developer's or agent's SSH key as an in-toto attestation, in the same SSHSIG format `git commit -S` uses.
3. **Share.** The attestation is stored as [git-meta](https://git-meta.com/) metadata on the test's path and pushed
   with `vci push`. It travels through git on `refs/meta/main`. There is no server and no database.
4. **Verify.** In CI, `vci ci` reads the trusted keys and policy from the *base* branch, checks each signature,
   re-hashes every recorded input from CI's own checkout, and skips a test only when everything matches. Then it
   runs the rest.

```
$ vci plan --base-ref origin/main
SKIP spec/models/order_spec.rb     (attested by alice@example.com (SHA256:tsNeKgQt…))
SKIP services/pricing              (attested by build-agent (SHA256:RASHZ3Nm…))
RUN  spec/requests/orders_spec.rb  (no attestation)
RUN  services/billing              (no valid attestation (1 candidates; best failed inputs: entry:services/billing/rates.json))
2 to skip, 2 to run
```

The default is to run. Any mismatch, missing key, expired record, unreadable metadata or unexpected behaviour means
the test runs. A mistake can only cost a skip, never cause one.

### Try it in two minutes

```sh
brew install pandelisz/tap/vci                 # macOS and Linux; or scripts/install.sh
cd your-project                                # a git repo with tests
vci init --adapter pytest --key ~/.ssh/id_ed25519.pub   # or vitest, go, cargo, rails
git add vci.toml .vci/allowed_signers .git-meta && git commit -m "Enable vci"   # merge to main: trust is read from there
vci run tests/test_orders.py --key ~/.ssh/id_ed25519
vci plan --base-ref origin/main
```

In GitHub Actions, after your toolchain setup: `- uses: PandelisZ/cryptographically-verifiable-ci-runner@v1`.

### How dependencies are actually found

Static import graphs miss too much (computed imports, fixture files, env vars), so every adapter observes the test
at run time:

| Runner | Unit | How inputs are observed |
|---|---|---|
| Vitest | test file | Vite module graph plus patched `fs` and `process.env` in the worker |
| pytest | test file | `sys.addaudithook` plus the import system; one process per file |
| Go | package | a logger overlaid into the standard library for the test build, so it sees package init too |
| Cargo | test target | no runtime hook exists, so every file of the crate and its in-repo deps counts (weaker, and documented) |
| Rails / RSpec | test file | a Ruby collector wrapping file, env and process entry points; a fresh SQLite database per file |

Each unit runs in its own process. If a test does something the collector cannot follow (spawns a process, opens a
socket, enumerates the environment, reads through a C extension), it is refused and simply runs in CI as before.

Environment variables are handled Turborepo-style: strict mode removes undeclared variables from the test process,
declared ones are hashed into the inputs, pass-through ones are visible but never hashed.

### What it does not protect against

A signature proves who claimed a result, not that they are honest. If a key in `allowed_signers` lies, vci believes
it. Mitigations: keep the list short, give agents their own keys with expiry dates, keep full runs on the default
branch (the `vci init` default). Random re-execution of attested tests in CI is the planned next step; it is not
built.

The adversarial testing was done with the question "can I get a false skip?" against every adapter. The rounds found
about forty ways (fixtures copied into temp dirs, stale bytecode, worker-thread reads, pending RSpec examples counted
as passes, …); all are now refusals or inputs. I'm sure there are more, and that is the main thing I want to hear
about.

### Status

v1.0.0. Six runners. Each has an end-to-end test suite that drives the real CLI against a bare git remote. The
repository is its own demo: the open demo PRs show units attested on a Mac being skipped by the Linux runner, and
re-running when an input changes. The "up to 90%" figure on the site is a model (whole suite attested before the
push), not a measurement; the measured part is the ~10 s verification step.

There is no company behind this. [Say here how you'd think about money, or that you don't know yet.]

- Repo: https://github.com/PandelisZ/cryptographically-verifiable-ci-runner
- Docs: https://pandelisz.github.io/cryptographically-verifiable-ci-runner/
- Full reference, including every refusal and known gap: docs/REFERENCE.md

---

## The Show HN text (first comment)

Hi HN, I'm [name]. vci lets CI skip the tests that someone already ran on the same code, by checking a signed record
of exactly what those tests depended on.

The itch: [one or two sentences on where you hit this: agents opening many PRs, a slow suite, paying twice]. Trusting
"the tests passed on my machine" isn't safe, so I wanted something CI could check rather than believe.

How it works: `vci run` executes a test with a collector attached and records every file read, probed or listed,
every package loaded and every env var consulted, then hashes them and signs the record with your SSH key. The
record is stored as git-meta metadata on `refs/meta/main`, so it travels with `git push`. In CI, the action reads the
trusted keys from the base branch, re-hashes every input from its own checkout, and skips only on an exact match.
Everything else runs; the default is always to run.

The collectors are the interesting part. Vitest, pytest, Go and Rails/RSpec all observe the test at run time
(audit hooks, patched fs/env, a logger built into Go's test binary). Rust has no such hook, so the cargo adapter uses
a conservative file-set rule and says so. Anything the collector can't follow (subprocess, sockets, C-level reads)
makes the test ineligible rather than guessed at.

What it can't do: a trusted key can lie. CI re-derives every hash, so the only lie available is about the result,
and only to keys listed on the base branch. Spot-check re-runs are the next step. The "90%" on the site is a model,
not a benchmark; the measured bit is the ~10 s verification step.

I'd like to hear how you handle this today, what would make you trust an agent's test run, and especially any way
you can think of to get a false skip out of it.
