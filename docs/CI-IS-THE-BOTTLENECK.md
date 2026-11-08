# CI is the bottleneck now. vci lets CI skip what was already run, with proof.

*The project, written for Hacker News readers: the problem, where the numbers come from, how it works, and where it
falls short.*

## Coding stopped being the constraint

For twenty years CI was sized for human output: a few pull requests per engineer per week, one pipeline run each.
That arithmetic broke in 2025–2026, and the people who broke it first have written down what happened.

Anthropic, September 2026, on scaling its test-selection service ([Malhotra][1]):

> Writing code is no longer the constraint, and once PR review gets accelerated, CI starts feeling the pressure.

The same post gives the numbers: engineers there "ship 8x as much code per quarter as they did from 2021-2025",
"Claude authors 80% of that code", "the amount of tests across our codebase grew 10x and we added a nominal amount of
engineers", and "this all led to a 25x increase in CI jobs over a six month period". The service that decided which
tests to run on each PR was patched three times (a bigger machine, sharding, daily restarts) before being rebuilt.
The advice at the end: "assume your architecture will be at a 25x load within two quarters."

A month later, in a post about replacing git for their monorepo ([Anthropic, October 2026][2]):

> At Anthropic, coding is no longer the bottleneck to building systems or doing research. […] The bottleneck, now, is
> all of the developer infrastructure built for human scale: source control, builds, and CI.

and, further down:

> What does CI even mean when hundreds or even thousands of changes can merge while tests are running?

It is not only Anthropic. Boris Cherny, who leads Claude Code, [wrote on X][3] in January 2026 that his own code had
been "100% for two+ months now, I don't even make small edits by hand. I shipped 22 PRs yesterday and 27 the day
before, each one 100% written by Claude." Linear titled its September 2026 engineering post
["AI coding has made CI a bottleneck, so we reworked ours to keep up"][4]: their test suite nearly quadrupled in a
year and grows by about 2,000 tests a week. Spotify's engineering blog reported [76% more PRs to review][5] after
rolling out agents. CircleCI's 2026 report, across 28 million workflows, found workflow throughput up 59% while
[main-branch success rates fell to 70.8%][6], a five-year low: more code than ever, and less of it getting through.

The pattern in all of these is the same. Agents removed the cost of producing a change. They did not remove the cost
of knowing whether to trust it. That cost now lands on review and on CI, and it lands all at once.

## The part nobody can skip

The industry answer so far is to make CI faster: better runners, caching, sharding, and *test impact analysis*, which
picks the tests a change could affect and runs only those. Anthropic's post is about exactly that service. Linear's
is about shaving setup time and sharding smarter. These help, and they are necessary.

But look at what every one of those pipelines still does: it re-runs tests that the person or agent who made the
change ran minutes earlier, on the same code. An agent edits a model, runs the three specs that cover it, sees them
pass, and opens a PR. CI then runs those three specs again, plus everything else. The work was done; the result was
thrown away because CI had no reason to believe it.

That is the gap vci is aimed at. Not "run fewer tests" in the test-impact-analysis sense, which guesses from history
and dependency graphs which tests *might* matter. Rather: "don't run a test twice", with a record CI can check rather
than believe.

## What vci does

vci is a Rust CLI and a GitHub Action. It makes "I ran the tests" into something CI can verify.

1. **Record.** `vci run tests/test_orders.py` runs the test with a collector attached to the test runner. The
   collector observes every file the test read, every file it looked for and didn't find, every directory it listed,
   every package it loaded and every environment variable it consulted. vci hashes all of it (BLAKE3) into one root.
2. **Sign.** The record, meaning what ran, against which hashes, with which toolchain, by whom, is signed with the
   developer's or agent's SSH key as an [in-toto](https://in-toto.io/) attestation, in the SSHSIG format that
   `git commit -S` already uses. A CI job can sign keylessly instead, with its GitHub OIDC token through Sigstore.
3. **Share.** The attestation is stored as [git-meta](https://git-meta.com/) metadata on the test's path and pushed
   with `vci push`. It travels through git on `refs/meta/main`. There is no server and no database. (A SQLite,
   PostgreSQL or libSQL store can be used instead; the numbers below are all from git-meta.)
4. **Verify.** In CI, `vci ci` reads the trusted keys and policy from the *base* branch (never from the pull
   request), checks each signature, re-hashes every recorded input from CI's own checkout, and skips a test only when
   everything matches. Then it runs the rest.

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

## Why observed inputs, not a dependency graph

Test impact analysis works from what a change *could* affect: an import graph, a package map, or a history of which
tests failed when which files changed. Those are guesses, and they are the reason such systems are tuned for "run a
bit too much" rather than "run exactly enough". Anthropic describes theirs as choosing "based on past performance and
package relevance"; when its listener lagged, the symptom was "running tests that were already super flaky or
widespread-failing across the board".

vci records what a test *did*. The adapters hook the runner at run time:

| Runner | Unit | How inputs are observed |
|---|---|---|
| Vitest | test file | Vite module graph plus patched `fs` and `process.env` in the worker |
| node:test | test file | Node's module hooks plus patched `node:fs` and `process.env` in the test process |
| pytest | test file | `sys.addaudithook` plus the import system; one process per file |
| Go | package | a logger overlaid into the standard library for the test build, so it sees package init too |
| Cargo | test target | no runtime hook exists, so every file of the crate and its in-repo deps counts (weaker, and documented) |
| Rails, RSpec | test file | a Ruby collector wrapping file, env and process entry points; the test database is the engine's |

A fixture read with `open()`, a template rendered on demand, a module loaded by name, a file that was looked for and
not found: all recorded, all hashed. Each unit runs in its own process. Anything the collector cannot follow (a child
process, a socket, an `ENV` enumeration, a read through a C extension) makes the test ineligible rather than guessed
at; it simply runs in CI as before.

Environment variables are three short lists in `vci.toml`: `set` (vci sets them, the same everywhere), `hash`
(taken from the machine and hashed) and `ignore` (visible, never hashed); every other variable is removed from the
test process.

## Why a signature, and why trust comes from the base branch

A cache keyed by input hash, which is what Turborepo, Nx and Bazel remote caches are, trusts whoever can write to
the cache. Nx's CVE-2025-36852 ("CREEP") was that trust being abused: a poisoned entry from a PR served to main.

vci has no shared cache to poison. Every attestation names its signer; CI re-derives every hash itself; and the list
of accepted keys plus the policy come from the commit the PR targets, so a PR cannot add its own key or loosen the
rules. Metadata on its own is never trusted: anyone with push access can delete or overwrite it, and the only effect
is that a test runs.

## What it does not protect against

A signature proves who claimed a result, not that they were honest. If a key listed in `allowed_signers` lies about
a test passing, vci believes it. Mitigations today: keep that list short, give agents their own keys with expiry
dates, and keep full runs on the default branch (the `vci init` default), so a false claim is caught at merge.
Random re-execution of attested tests in CI is the planned next step; it is not built.

Other limits, stated plainly: Rust has no runtime read hook, so the cargo adapter is conservative rather than
precise; reads inside C extensions (some SQLite paths, lxml, libvips) are invisible and cause refusals; a test that
reads `CI` or `HOME` will never match between a laptop and a runner; toolchains must match exactly (same Python
build, same Go version, same rustc), which takes some pinning to get right across macOS and Linux.

Every adapter was tested adversarially with the question "can I get a false skip?". Those rounds found about forty
ways (fixtures copied into temp dirs, stale bytecode, worker-thread reads, pending RSpec examples counted as passes,
…); all are now refusals or recorded inputs. There are surely more, and that is the most useful thing to hear about.

## Try it in two minutes

```sh
brew install pandelisz/tap/vci                 # macOS and Linux; or scripts/install.sh
cd your-project                                # a git repo with tests
vci init --adapter pytest --key ~/.ssh/id_ed25519.pub   # or vitest, go, cargo, rails
git add vci.toml .vci/allowed_signers .git-meta && git commit -m "Enable vci"   # merge to main: trust is read from there
vci run tests/test_orders.py --key ~/.ssh/id_ed25519
vci plan --base-ref origin/main
```

In GitHub Actions, after your toolchain setup: `- uses: PandelisZ/cryptographically-verifiable-ci-runner@v2`.
The action downloads a prebuilt binary, fetches the attestations, prints the plan in the job summary, and runs the
rest. The repository is its own demo: the open demo PRs show units attested on a Mac being skipped by the Linux
runner, and re-running when an input changes.

## What it did to one real CI

These numbers are from production, not a benchmark. They cover every Rails job of [ComposalAI/vex][7]'s pull
requests, read from GitHub Actions: the jobs API for when each job started and ended, and each job's log for vci's
plan (`N to skip, M to run`) and its `VCI_TIMING` lines. vex is a monorepo. Its Rails suite is 2,350 test files,
split over two CI jobs per pull request on 8-core runners with SQLite.

**On vci 2.10.0, from 08:00 UTC on 7 November to 02:00 UTC on 8 November 2026,** 87 pull-request runs asked for
204,405 test-file runs, and vci skipped 155,803 of them (76%). In 64 of the 87 runs, 90% or more of the suite was
skipped, because those tests had already passed on exactly the same inputs.

On vex, nearly all of that duplicate work is CI's own. In eight job logs sampled from the window, almost every skip
was attested by the pull-request CI key: an earlier push of the same pull request, or another pull request on the
same files, had already run the test. At most seven skips per job came from a developer's laptop. Running tests
locally and pushing the attestations, the case this post opened with, is a small share here. Most of the saving
is CI not repeating CI.

The fair comparison is the same day on the same runners:

| A Rails job, 7–8 November (vci 2.10.0, 8-core runners) | Jobs | Median job | Its `rails test` step |
|---|---|---|---|
| 90% or more of the files skipped | 129 | 2 min 18 s | 29 s |
| more than 90% of the files ran | 38 | 5 min 37 s | 3 min 33 s |
| every pull-request job | 174 | 2 min 36 s | 36 s |

The 174 jobs took 9.3 hours of runner time between them. Had each cost what that day's run-everything jobs cost,
they would have taken 16.3 hours: 43% less, or seven runner-hours in under a day, on one test suite.

What vci costs per job (medians, p90 in brackets):

| Step | Time |
|---|---|
| install, fetch the attestations, plan | 11 s (18 s) |
| restore the attestation store from cache | 4 s (12 s) |
| sign and publish the new attestations | 7 s (11 s) |

The plan alone has a median of 9.7 s. It is under 10 s in 95 of the 174 jobs, and the p90 is 16.2 s.

A job that runs everything costs more with vci than without. Each file runs in its own process so that its inputs
can be recorded, and the results are signed and pushed. On vex's runners on 26 October, the application half of
the suite (1,072 files) took 344 s under plain `bin/rails test` and 360 to 404 s under vci: 5 to 17% more, before
the fixed cost in the table above.

The full re-runs are correct, not misses. In 15 of the 19 pull-request runs that ran everything, the input the plan
named most often was `db/schema.rb`, which every Rails test loads. The other four named a core model (`user.rb`,
`organization.rb`, `organization_membership.rb`). The plan's output says which file did it:

```
changed inputs, by the units each made run (top 5 of 124):
    37  vex-api/db/schema.rb
    29  vex-api/app/models/persistent_agents/task_approval_wait.rb
    28  vex-api/app/models/repository.rb
```

### How it got there

The same measurement a day and a half earlier shows what the last two releases fixed.

| Rails pull-request jobs | Jobs | Median job | Test-file runs skipped | Runner time against running everything | Plan, median |
|---|---|---|---|---|---|
| 6 November, vci 2.9.0 | 414 | 4 min 59 s | 50% | 23% less | 15.6 s |
| 7 November 01:00 to 07:31 UTC, vci 2.9.1 | 78 | 3 min 2 s | 80% | 42% less | 10.9 s |
| 7 to 8 November, vci 2.10.0 | 174 | 2 min 36 s | 76% | 43% less | 9.7 s |

How much is skipped depends on what the pull requests changed: 22% of the 2.10.0 window's runs ran everything,
against 15% of 2.9.1's. Two fixes made the rest of the difference.

**Pull-request jobs were deleting each other's attestations.** Since 2.1.3, when `vci run` re-attested a unit, it
deleted the same signer's earlier attestations of that unit made on commits it took to be rebased away. A pull
request's CI checkout never has another pull request's merge commit. Every pull-request job signed with the same
key, so each job deleted the other pull requests' attestations of every unit it ran. On 6 November the
pull-request key published 138,019 Rails attestations, and 133,397 of them were deleted that way. 2.9.1 stopped
drawing conclusions from a commit the clone does not have.

**The shared store had grown too large.** vex prunes its attestations on an hourly schedule, but the metadata on
`refs/meta/main` still grew to about 195,000 entries and 7,700 commits of history in three weeks. Two thirds of the
entries were deletion records. The plan fetches and merges that metadata in the background while it starts. That
fetch had a median of 6.9 s on 6 November (p75 22 s) and 4.3 s on 2.9.1. 2.10.0's prune keeps deletion records for
6 hours instead of 24 and publishes a history longer than 2,000 commits as one commit. The first prune took the
store to 91,000 entries and one commit, and the fetch's median is now 3.6 s.

The October numbers are not comparable. On 16 and 17 October, before vci skipped anything, vex's Rails jobs had a
median of 4 min 29 s (406 jobs). That was a smaller suite (about 1,980 files) on 16-core runners with MySQL.
vex moved these tests to SQLite on 8-core runners on 26 October, so the same-day comparison above is the
like-for-like one. An earlier version of this post compared against a 3.5-minute plain job. That figure could not
be reproduced from the jobs API and has been dropped.

vex also tried a hosted libSQL store (Turso) for a week. Writes kept timing out, and it went back to git-meta on 1
November.

The same monorepo's other suites, in the same 2.10.0 window: 79% of vex-web's node:test file runs were skipped (62
jobs), and 78% of the Rust test targets (179 jobs). I have no same-day baseline for those jobs, so their time saved
is not given here.

The October measurements, release by release, are on the [benchmarks page][8].

## Status and what it costs

v2.10.0, MIT. Six runners: Vitest, node:test, pytest, Go, Cargo, and Rails with RSpec. Each has an end-to-end suite
that drives the real CLI against a bare git remote. On vex's 2,350-file Rails suite, vci adds about 22 seconds to a
job (medians: 11 s to install, fetch and plan, 4 s to restore its store, 7 s to publish). What you save beyond that
is every test that already ran on the same inputs. What you pay beyond that, when nothing ran before, is one process
per test file plus signing and pushing.

There is no company behind this. It is a tool for a problem that the people with the most agents hit first and that
the rest of us are about to.

- Repo: https://github.com/PandelisZ/cryptographically-verifiable-ci-runner
- Docs: https://pandelisz.github.io/cryptographically-verifiable-ci-runner/
- Full reference, including every refusal and known gap: [REFERENCE.md](REFERENCE.md)

[1]: https://claude.com/blog/agentic-coding-is-straining-ci-heres-how-we-scaled-test-impact-analysis-at-anthropic "Agentic coding is straining CI. Here's how we scaled test impact analysis at Anthropic (Sachin Malhotra, 14 Sep 2026)"
[2]: https://www.anthropic.com/engineering/redesigning-source-control "Redesigning source control at Anthropic (13 Oct 2026)"
[3]: https://fortune.com/2026/01/29/100-percent-of-code-at-anthropic-and-openai-is-now-ai-written-boris-cherny-roon/ "Boris Cherny's post on X, as reported by Fortune (29 Jan 2026)"
[4]: https://linear.app/now/ci-bottleneck-reworked "AI coding has made CI a bottleneck, so we reworked ours to keep up (Linear, 21 Sep 2026)"
[5]: https://engineering.atspotify.com/2026/6/code-with-claude-coding-is-no-longer-the-constraint "Coding Is No Longer the Constraint (Spotify Engineering, Jun 2026)"
[6]: https://www.oreilly.com/radar/coding-was-never-a-bottleneck/ "Coding Was Never a Bottleneck (O'Reilly Radar, Jul 2026), citing CircleCI's 2026 State of Software Delivery report"
[7]: https://github.com/ComposalAI/vex "ComposalAI/vex, the Rails application the numbers come from"
[8]: https://pandelisz.github.io/cryptographically-verifiable-ci-runner/benchmarks.html#vex-rails "vex's Rails suite in production"
