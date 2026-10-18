# vex Rails rollout on vci 2.1: design, measurements, cost

Date: 2026-10-18. Status: designed and measured, **not merged**. The vex change is a patch outside this repository,
in the session's scratchpad: `vex-rails-rollout-on-1668.patch`, on the head of vex PR #1668 (`vci-rust-partition`,
`e5d0edf5d1`), is the final form; `vex-rails-rollout.patch`, against vex master `3738f8486d`, is the first version.
The final form's `rails-tests.yml` timeout comment states the re-measured costs, and the timeout is now 30 minutes
(it was 45).
Nothing was pushed to vex and nothing was published with `vci push`.

**Verdict, plainly** (re-measured with this tree: the per-plan checkout cache, units checked and signed in
parallel, and the two collector fixes; "Cost model, re-measured" below). The plan and the checking and signing no
longer decide the cost:

- Both plans a job pays take 9 to 11 s together (4.2 to 6.1 s each, warm, against a store of 2,784 Rails
  attestations). Before, they took 6 to 16 minutes.
- Checking and signing takes 0.04 to 0.09 s a file in a full share. Before, it took 1.15 s.

On this Mac, one job (partition 1 of 4) of a pull request on an attested base costs, with ~70 s of job setup:

| change | per job | today's job |
|---|---|---|
| test-only | 2.9 min | 4.8 min |
| median | 3.9 min | 4.8 min |
| mean | 4.2 min | 4.8 min |
| an input of every file (base attested) | 5.1 min | 4.8 min |
| full share, nothing attested | 6.3 min (partition 1), 8.5 min (partition 2) | 4.8 min |

- **At or below today's 4.8 minutes a job:** for changes up to about the mean, yes; for a change of an input of
  every file, about the same; for a full run, no.
- **The targets:** the plan under 20 s is met. A median change under 2 minutes is not (3.9 min). A full share
  under 5 minutes with 4 jobs is not (6.3 and 8.5 min).
- **What is left:** a fixed cost in every job (~70 s of job setup plus 40 to 100 s of boot and slot setup) and the
  Ruby batch itself, whose slowest files set the end of a full share.
- **Runner time:** four jobs cost more than today's two at every row: about 12 runner-minutes for a test-only
  change and about 30 for a full run, against 9.7.
- **Blocking:** one test still fails under vci and would turn partition 1 red on every pull request.
  `test/config/solid_queue_shutdown_test.rb` fails in every slot batch since f165f67 (see "Found while measuring").
  It is never attested, so it runs every time.

The verdict before these changes: 13 to 16 minutes a share, plus 3 to 8 minutes of plan that grew with the store
("Cost model before the plan cache").

## What the patch changes (vex)

| file | change |
|---|---|
| `.github/workflows/rails-tests.yml` | The `application`/`services` matrix becomes `part: [1, 2, 3, 4]`, named `rails test (vci I/4)`. Each job runs on `composal-x64-16x` with the MySQL 8.0.46 service and `VCI_RAILS_JOBS=16`, and has `contents: write`. It installs the pull request key (`VCI_PR_SIGNING_KEY`; forks only plan), then runs the action `@v2` with `command: plan`, then `vci ci --base-ref <base> --project vex-api --partition I/4 --audit-log ... ${VCI_ATTEST_ARGS:-}`. This is the pattern of PR #1668's Rust jobs. Partition 1 also runs `CI=true bin/rails zeitwerk:check`. Manual and profiling runs (`workflow_dispatch`), and a job whose vci step failed, run their share of both groups with the plain `bin/rails test` (`RAILS_TEST_SHARD`/`RAILS_TEST_SHARDS` of `rails-test-group.rb`, 16 workers, eager loading). The timeout goes from 10 to 45 minutes. The gem cache is saved by partition 1 only, and the audit log is kept per job. |
| `.github/workflows/vci.yml` | New job `attest-rails`: the master backstop. Hourly (`schedule: '17 * * * *'`) and on `workflow_dispatch`, never per push. It runs on `composal-x64-16x` with the same MySQL service and env, `environment: vci-attest`, `continue-on-error`. It runs `vci ci --base-ref $GITHUB_SHA --project vex-api --key <CI key>`, then `vci prune` and `vci push`. Three comments are updated: the header names both partitioned suites (Rust `I/3`, Rails `I/4`) and the master Rails backstop, and `attest` points at `attest-rails`. The other two jobs stay push-only (`if: github.event_name == 'push'`). |
| `vci.toml` (vex-api) | `CI` is no longer declared, so files run without eager loading (see below); the comment says why. |
| `vex-api/test/test_helper.rb` | The per-worker roots move from `tmp/storage/worker-<pid>` to `Dir.tmpdir/vex-test-worker-<pid>`: the Active Storage disk services (`test`, `tigris_agent_sessions`), and also `blob_artefacts`/`tigris_artefacts` and `VEX_TRANSCRIPT_ARCHIVE_TMPDIR`. Teardown removes that one directory. |
| `docs/agents/vci.md` | The Rails bullets of "What CI does with vci" describe the above, next to #1668's Rust bullet. The vci-skip bullet becomes the Rails jobs' fail-open rule (a `continue-on-error` action step, the plain runner when vci is missing) and says that no workflow calls `scripts/ci/vci-skip.py` any more. |
| `docs/agents/vci-benchmarks.md` | "Known costs that remain": the "Rails files are attested only from laptops" bullet (#1668's) is replaced by what the Rails jobs and the backstop pay; their times are to be recorded once they run. |

Why the test helper changes: vci hashes a file's inputs after the batch. Three things under the repository's `tmp/`
refused files:

- Lane A's 34 files: the teardown removed `tmp/storage/worker-<pid>` before vci hashed it.
- In a fresh checkout (no `tmp/`), a first full run here refused another 17: `tmp/transcript-archives` and
  `tmp/artefacts` were created during the run by another slot's file (`input changed during the run: ... not found
  under this spelling before the run`).

Reads under vci's temp dir are not inputs, and a slot's `TMPDIR` is its own and cleaned after each file. With the
roots moved there, all 51 of those files are attested, and the plain run is unaffected (`/tmp` per worker). The
artefact config test that uploads through `tigris_artefacts` and reads back passes.

Partitions replace the groups. The groups balanced two runners and kept `queue_result_reuse_test.rb` and
`batch_queue_result_reuse_test.rb` (which requires the first) in one process. Under vci every file runs in a
process of its own, so the second file runs the base's cases inside its own process whichever partition the base
lands in (as in a one-file run), and the hash partition covers every file once. The groups stay only for the plain
fallback.

The first version applied cleanly to vex master `3738f8486d` and conflicted with PR #1668 (`vci-rust-partition`, not
merged; it moves every workflow to the action's `@v2` and runs the Rust jobs through `vci ci --partition I/3`). The
final form is that patch rebased onto #1668's head `e5d0edf5d1` (`git apply -3` in a `--shared` clone of vex-git, then
`git diff --cached e5d0edf5d1`):

- `rails-tests.yml`'s `@v1` → `@v2` line merged by itself: the patch replaces that step, already with `@v2`.
- `vci.yml`'s header comment: each side had moved its own suite to `vci ci` and left the other on
  `scripts/ci/vci-skip.py`; it now reads that rust-tests.yml (`vci ci --partition I/3`, root workspace and vex-roder)
  and rails-tests.yml (`vci ci --partition I/4`, vex-api) both attest on pull requests. Its first line also names the
  hourly Rails files.
- `docs/agents/vci.md`: #1668's Rust bullet and this patch's Rails bullet are kept. Both sides' "<suite> asks
  vci-skip.py" bullet is replaced by the Rails jobs' fail-open rule, since no workflow calls `vci-skip.py` now
  (`rails-tests.sh` still would with `VCI_BASE` set; the fallback clears it). Of the "only skipped when an engineer
  attested them locally" bullet, #1668 kept Rails and this patch kept Rust; both are now attested in CI, so only this
  patch's sentence about `attest-rails` remains.
- Not a conflict: #1668's `docs/agents/vci-benchmarks.md` says Rails is attested only from laptops; updated (table
  above).

`git apply --check` of the final patch passes on a fresh clone at `e5d0edf5d1` (and the applied tree equals the
resolved one), and on #1668's head merged with today's vex master `1211d6a1a6` (`git merge-tree`, no conflict; no
master commit since `3738f8486d` touches the patched files). The old patch still applies to `3738f8486d`.

It needs vci 2.1 released and `v2` moved to it: slots, shared output, and the two batch fixes of Lane A.
`actionlint` (on `rails-tests.yml` and `vci.yml`) reports nothing new against #1668's head beyond one more Composal
`parallel:` step (`attest-rails`), which it already flags in the existing jobs. `ruby -c` of the test helper, YAML
loads of both workflows and a TOML load of `vci.toml` pass. The vex scripts' tests pass in the patched clone of #1668
(mise's Ruby 3.4.9, Python 3.15.0): `rails-test-group-test.rb` (4 runs, 25 assertions, 0 failures),
`rails-test-shard-test.rb` (2 runs, 10 assertions, 0 failures), `typescript-workflow-test.rb` (passes),
`docker-selection-test.py` (102 tests, OK), `test-selection-test.py` (22 tests, OK) and `vci-skip-test.py` (11 tests,
OK).

## Eager loading: decided against (lazy loading under vci, one eager-load check per run)

vex-api sets `config.eager_load = ENV["CI"].present?`, and vci.toml used to declare `CI = "true"`. Eager loading
makes every file under `app/` an input of every test that boots Rails.

- **Lazy:** vci.toml leaves `CI` undeclared. vci removes undeclared variables from the tests, so `CI=true` on the
  runner never reaches them, and a file's inputs are what it loads.
- **What still eager-loads:**
  - partition 1's `CI=true bin/rails zeitwerk:check` (7.4 s here; it failed as it should for a misnamed file, *expected
    file app/models/zz_broken.rb to define constant ZzBroken*, and for a `NameError` at load time);
  - manual and profiling runs, and the plain fallback;
  - production boot.
- **What the plain eager run caught that lazy runs do not:** load errors in files no test loads (zeitwerk:check covers
  these), and behaviour that depends on every class being loaded (`descendants`, STI subclasses).
- **Lazy loading changed no result.** On the measured group, lazy and eager runs attested the same 929 files and
  refused the same 10. No file failed only lazily.

### Measurements

Setup:

- vci was built from this tree: a snapshot of HEAD `fc36f28` plus Lane A's and Lane B's uncommitted changes, release
  build, with the snapshot's collector.
- vex-api came from a `git clone --no-local --depth 1` of vex-git master `3738f8486d`, with the remote removed and
  `.git-meta` pointed at a nonexistent URL. On top of it, in the clone only:
  - the test-helper change;
  - its own database `vex_lanec` (slots `vex_lanec_0..`);
  - a throwaway signer `measure` in `.vci/allowed_signers`.
- Branch `eager` keeps `CI = "true"`; branch `lazy` drops it.
- Before each run, the clone's git-ignored `tmp/`, `log/` and `storage/` were removed and the slot databases dropped,
  as on a fresh runner.
- The machine is this Mac: 14 cores, MySQL 8 in Docker. It was not isolated: another session ran the collector's
  tests during the first run, with a load average of about 11.

Each run was `/usr/bin/time -l env VCI_RAILS_JOBS=8 VCI_TIMING=1 mise exec -- vci run <939 files of the application
group> --key <throwaway>`. The application group is `scripts/ci/rails-test-group.rb application` of every
`test/**/*_test.rb`. The Ruby/check split was read from a poll of the log every 5 s: the result lines appear only
after the batch.

| run | wall | Ruby batch | check + sign | user + sys | inputs per file (median) | attested / refused |
|---|---|---|---|---|---|---|
| eager, storage root fixed only | 1527.0 s | 624 s | 905 s | 1789 + 1244 s | — | 912 / 27 (17 the `tmp/` directories above) |
| eager, helper as in the patch | 1529.3 s | 593 s | 940 s | 1832 + 1260 s | 13,855 | 929 / 10 |
| lazy, helper as in the patch | 1701.5 s | 583 s | 1121 s | 2365 + 531 s | 2,548 | 929 / 10, the same 10 |

The 10 refused files:

- 6 have a skipped test;
- 2 have no tests;
- 2 probe request paths that collide under case folding (`organizations/ACME` and `organizations/acme`).

None of these is caused by slots or by lazy loading. The lazy run's longer check and sign is not explained by its
smaller manifests; the machine was shared. Slot setup took 47.5 s at most (eager) and 56.3 s at most
(lazy). A file's process took 2.0 s on average eager and 2.5 s lazy, and wrote its output in 0.15 s and 0.25 s.

**Skip rates.** Each change was measured with `vci plan` in a fresh clone (no `tmp/`), with the clone's store copied
in and one comment line appended to one file: `vci plan --base-ref HEAD --project vex-api --format json`, counted
over the 939 application-group files. The 10 refused files always run, so 929 skips is the most possible.

| change | eager: skip / run | lazy: skip / run |
|---|---|---|
| none | 929 / 10 (98.9%) | 929 / 10 (98.9%) |
| `app/models/user.rb` (seeded, so loaded in every slot) | 12 / 927 (1.3%) | 12 / 927 (1.3%) |
| `app/models/agent_action.rb` | 12 / 927 (1.3%) | 896 / 43 (95.4%) |
| `app/models/signup_invite_code_redemption.rb` (the median model) | 12 / 927 (by replay) | 909 / 30 (96.8%) |
| `app/models/agent_integration_admission.rb` (a leaf) | 12 / 927 (by replay) | 928 / 11 (98.8%) |
| `test/models/agent_connection_access_test.rb` | 928 / 11 (98.8%) | 928 / 11 (98.8%) |
| `test/test_helper.rb` | 0 / 939 | 0 / 939 |

The rows marked "by replay" are computed from the manifests. A replay that counts a file as re-run when a changed path
is one of its content inputs (or, for an added or removed file, its listed directory or absent probe) gave exactly
the plan's numbers in all ten measured cases. It extends the table:

- **Every model changed alone** (546 files): eager re-runs 917 of 929 files for every model the boot loads, a 1.3%
  skip rate. Lazy re-runs a median of 20 files, a 97.8% skip rate (mean 90.8%). 420 of the 546 models re-run 50
  files or fewer, 18 re-run none, and 32 re-run every file. Those 32 are `application_record.rb`, `user.rb`,
  `organization.rb`, `billing/*` and others that the boot or Oaken's seeds load: the seeds load in each slot before a
  file forks.
- **Every test file of the group changed alone:** 1 re-run (at most 2, for a file another requires), in both modes.
  A `test/support/` file: median 3 re-runs, at most 76 (`project_domain_support.rb`).
- **The last 14 days of vex master** (1318 commits; 671 touch `vex-api/`), each commit's diff replayed against the
  attested group:

  | | eager | lazy |
  |---|---|---|
  | commits that re-run 90% or more | 627 of 671 | 268 of 671 |
  | median re-runs per vex-api commit | 917 | 117 |
  | mean re-runs per vex-api commit | 857 | 404 |
  | skip rate if each vex-api commit were a pull request on an attested base: median | 1.3% | 87.4% |
  | the same: mean | 7.7% | 56.5% |

  In lazy mode, what makes a commit re-run everything (a commit can have several causes):

  | cause | commits |
  |---|---|
  | `db/schema.rb` | 109 |
  | `db/migrate` (whose listing every file reads) | 109 |
  | `app/services`: a file added or removed (Zeitwerk lists the autoload directories at boot), or a changed file the boot or seeds load (25 of them) | 91 |
  | a seeded or boot-loaded model | 86 |
  | `config/routes.rb` | 69 |
  | `app/jobs`, `app/resources`, `app/controllers`: the same as `app/services` | 58, 37, 18 |
  | `config/initializers` | 20 |

## Cost model, re-measured (plan cache, parallel check and sign, collector fixes)

Setup:

- vci was a release build (`cargo build --release -p vci-cli`) of a snapshot of this working tree: f165f67 plus
  Lanes P, R and K, uncommitted. The collector came from the same snapshot.
- The vex-api clone is the `lazy` branch of the clone above, at `442f6014`, with the throwaway key.
- `VCI_RAILS_JOBS=14`, `VCI_TIMING=1`, with fresh scratch state each time (git-ignored `tmp/`, `log/` and
  `storage/` removed, slot databases dropped).
- The machine was this Mac, shared with other sessions' builds and test runs, at load averages of 5 to 25 (noted
  per run).
- The scripts and logs are in the session scratchpad's `lanec/`: `partition_run.sh` (now taking `VCI_BIN`,
  `VCI_COLL` and `VCI_CLONE`), `row_run.sh`, `plan_both.sh`, `plan_count.sh`, and the `ci-lazy-p{1,2}of4-w14-cost`,
  `row-*` and `planboth-*` logs.

**Full shares, nothing attested** (`partition_run.sh <I>/4 14`: a fresh clone without a store, `vci ci --base-ref HEAD
--project vex-api --partition I/4 --key <throwaway>`):

| partition | files | `vci ci` wall | Ruby batch (boot and slot setup included) | slot setup | check, sign and store | attested / not | load |
|---|---|---|---|---|---|---|---|
| 1/4 | 499 | 298.0 s (before: 781.5 s) | ~256 s (before: 212 s) | 102.0 s | 42.4 s, 0.085 s a file (before: 574 s) | 494 / 5, exit 1 | 16 to 25 |
| 2/4 | 534 | 430.7 s (before: 973.3 s) | ~412 s (before: 363 s) | 93.6 s | 22.4 s, 0.042 s a file (before: 613 s) | 531 / 3, exit 0 | 10 to 11 |

The Ruby batch's length is read from a 5 s poll of the log. A file's process took 3.1 s (1/4) and 3.6 s (2/4) on
average. The slowest took 95.3 s and 123.5 s.

- `manual_image_deploy_service_test.rb` (partition 1) is now attested (2,734 inputs).
- Partition 1's exit 1 is `solid_queue_shutdown_test.rb` (below). Its other four refusals are skipped tests and a
  file with no tests, as before.

**The two plans a job pays**, against the 2,784-attestation store (`plan_both.sh`, on `plan-cost`, an APFS copy of
`plan-p`, load 5 to 8):

- First, the action's plan step, `vci plan --base-ref HEAD --project vex-api`: plan total 4.27 to 6.07 s (wall 4.32
  to 6.30 s), of which verdicts take 3.64 to 4.63 s.
- Then `vci ci --partition 1/4`'s own plan, stopped at its partition line: plan total 4.24 to 4.25 s, 4.4 s to that
  line. It skips 929 and runs 1,063, the same as `vci plan`.
- Lane P measured 16.3 s for one plan with the store not in the page cache.
- Before these changes, one plan took 486 to 495 s against this store.

**The four rows, measured.** Each row ran on `ci-cost`, the clone of partition 1's full run, whose store holds
partition 1's 494 attestations of the unchanged tree; the store was restored before each row (`row_run.sh`). Each
row changed one path by appending a comment line, then ran what a job runs: the action's `vci plan`, then
`vci ci --partition 1/4 --key`. Each path was picked with `vci plan` to re-run about as many of partition 1's files
as the model's row:

- test-only: `test/models/agent_connection_access_test.rb`;
- median: `app/models/concerns/project_archivable.rb` (57 files; the model's row is ~63);
- mean: `app/models/hosted_app.rb` (195 files; the model's row is ~215);
- every file: `test/test_helper.rb`.

F counts partition 1's 5 files that are never attested (4 refusals and `solid_queue_shutdown_test.rb`), which run in
every row.

| row | F | action's `vci plan` | `vci ci` wall (its plan; slot setup; check and sign) | per job: + ~70 s setup | before (model, plan excluded / with plans) |
|---|---|---|---|---|---|
| test-only change | 6 | 5.4 s | 98.0 s (3.9 s; 37.2 s, 6 slots; 0.8 s) | 173 s = **2.9 min** | 2.9 / 9–19 min |
| median change | 57 | 4.9 s | 161.5 s (3.8 s; 91.8 s; 3.0 s) | 236 s = **3.9 min** | 4.4 / 11–21 min |
| mean change | 195 | 7.8 s | 176.4 s (3.7 s; 72.5 s; 9.8 s) | 254 s = **4.2 min** | 8.2 / 15–25 min |
| input of every file | 499 | 0.9 s | 236.4 s (0.6 s; 75.3 s; 17.3 s) | 307 s = **5.1 min** | 15.3 / 22–32 min |
| full share, nothing attested | 499 / 534 | ~5 s | 298.0 s / 430.7 s (+ ~4 s of plan with a store) | ~377 s = **6.3 min** / ~510 s = **8.5 min** | 14.0–17.4 / 20–34 min |

The arithmetic against today's job (median 284 s application, 298 s services, so ~4.8 minutes; 2 jobs, 9.7
runner-minutes):

- **Per job:** setup ~70 s + both plans 9 to 11 s + `vci ci`'s boot and slot setup 37 to 102 s + the Ruby of
  F files + F × 0.04–0.09 s of check and sign. Partition 1 also runs `zeitwerk:check` (7.4 s).
  - A test-only change: 70 + 5 + 98 ≈ 173 s, 1.9 minutes under today's job.
  - A median change: 70 + 5 + 161 ≈ 236 s, 0.9 minutes under.
  - A mean change: 70 + 8 + 176 ≈ 254 s, 0.6 minutes under.
  - An input of every file: 70 + 1 + 236 ≈ 307 s, about today's job (0.3 minutes over).
  - A full share: 6.3 and 8.5 minutes, 1.5 and 3.7 minutes over.
- **Runner time** (4 jobs, partition 1's cost taken for every job): about 4 × 2.9 ≈ 12 runner-minutes for a
  test-only change, ≈ 16 for a median change, ≈ 17 for a mean one, and 25 to 34 for a full run, against 9.7 today.
- **Where a small change's minutes go:** the 70 s of job setup, then slot setup. That was 37 s for 6 files on 6
  slots, and 72 to 92 s for 14 slots under load. Then the slowest files, up to 48 to 64 s each. Checking, signing
  and the plans together are under 20 s.
- **Where a full share's minutes go:** the Ruby batch. Partition 2's 534 files averaged 3.6 s a process, which is
  ~137 s of work per slot on 14 slots plus 94 s of slot setup if spread evenly. The batch took ~412 s. The slowest
  file (123.5 s) and the order the files were started in set its end.
- **CI's runners** have 16 cores and 16 slots, and ran the plain suite at ~3.4 core-seconds a file against ~5.1
  here. The Ruby part there may be about 0.6× of this Mac's. That would bring the full shares to about 4.5 to 6
  minutes a job and the small rows down by up to a minute. This is not measured.
- **The master backstop** (an estimate, not measured): partitions 1 and 2 spent ~0.46 s of batch a file beyond slot
  setup ((256 − 102 + 412 − 94) s over 1,033 files).
  - The whole project with nothing attested, in one job: 1,992 × 0.46 + ~100 s of setup + ~80 s of check and
    sign ≈ 18 minutes.
  - The mean vex-api commit (~860 files): about 9 minutes.
  - Both fit in the hourly schedule. Before, the estimates were 51 and 23 minutes.

## Cost model before the plan cache and parallel check and sign (2.0.4 plus slots)

**Today**, from 20 successful pull-request runs of `rails-tests.yml` (2026-10-18, `gh api .../actions/runs/<id>/jobs`):

| job | job wall, median (min–max) | `rails test` step, median |
|---|---|---|
| `application` | 284 s (253–313) | 200 s |
| `services` | 298 s (263–332) | 220 s |

The steps outside `rails test` take about 80 s, including 19 s for the vci plan step. A run is 2 jobs × ~4.8 minutes ≈
9.7 runner-minutes on 16-core runners.

**Each job's share of a full run with vci** (nothing attested, lazy, the whole project). Each of the four
partitions was measured as its job runs it, in a fresh clone without a store: `/usr/bin/time -l env VCI_RAILS_JOBS=14
mise exec -- vci ci --base-ref HEAD --project vex-api --partition I/4 --key <throwaway>`, with 14 slots (this Mac's
cores). Planning took 0.8 s (empty store).

| partition | files | wall | Ruby batch (boot and slot setup included) | slot setup | check + sign | attested / refused |
|---|---|---|---|---|---|---|
| 1/4 | 499 | 781.5 s | 212 s | 81.6 s | 574 s (1.15 s a file) | 494 / 5 |
| 2/4 | 534 | 973.3 s | 363 s | 91.3 s | 613 s (1.15 s a file) | 531 / 3 |
| 3/4 | 473 | 769.5 s | 227 s | 78.5 s | 547 s (1.16 s a file) | 468 / 5 |
| 4/4 | 486 | 865.1 s | 307 s | 78.3 s | 558 s (1.15 s a file) | 484 / 2 |

The four jobs together: 1,992 files, 1,977 attested and 15 refused. Of the refused, 9 skip a test, 2 have no tests,
2 are the case-folding collision, and 2 are the collector bugs below. Partitions 1 and 3 exited 1 because of those
two bugs. Check and sign took more than half of every job.

Per job, about: 70 s of setup + 2 × plan (the action's plan step, then `vci ci`'s own) + ~100 s of boot and slot
setup + F × (0.35 s of Ruby + 1.15 s of check and sign), for F files to run. The partitions' Ruby was 0.22 to 0.49 s
a file beyond the first 100 s.

**The plan is the large unknown.** Its "verdicts" phase checks every stored candidate attestation against the
checkout, and its cost grows with the store:

| attestations in the store | plan (one) |
|---|---|
| about 1,870 | 187 to 199 s |
| 2,784 (eager and lazy versions of the group) | 486 to 495 s (`vci: timing: verdicts (rehash inputs, check candidates): 483.93s`, 466 s user) |
| any number, when `test/test_helper.rb` changed | 2.8 s |

In CI the store keeps every pull request's and every backstop's Rails attestations for 14 days. It would hold many
versions of each file's attestation, so this cost, minutes per job already, would keep growing.

Per job with N = 4, on this Mac's per-file costs (CI's cores ran the plain suite at ~3.4 core-seconds a file against
~5.1 here, so these are, if anything, high):

| pull request | files to run per job (F) | per job, plan excluded | with today's plan cost (2 × 190–490 s) |
|---|---|---|---|
| test-only change, base attested | ~1 | ~2.9 min | 9–19 min |
| median vex-api change (lazy replay: 117 of 929, both groups ≈ 250, /4) | ~63 | ~4.4 min | 11–21 min |
| mean vex-api change (404 of 929 → ~215) | ~215 | ~8.2 min | 15–25 min |
| change of a global input (40% of vex-api commits lazy, 93% eager) | ~499 | ~15.3 min (measured: 14.0–17.4 min with 70 s of setup) | 22–32 min |

Today's job is ~4.8 minutes.

- **Lazy:** a pull request's cost is at or below today's only for the smallest changes, and only once planning is
  cheap.
- **Eager:** almost every vex-api change is a full run.
- **Runner cost:** four jobs instead of two, so even the small-change row is ~12 runner-minutes against today's 9.7.

These rows assume the pull request's base was already attested. With no merge queue (no `merge_group` runs in the
last 200) and ~94 master commits a day, a base is attested when another pull request ran on the same or an
equivalent base, or when the hourly backstop did. About 20% of all master commits (268 of 1318) re-run everything
lazily, so a base one or two commits past the last attested state is often a full run. A rough estimate: about half
of vex-api pull requests pay the full-run row.

**The master backstop** (lazy): per vex-api commit, a mean of 404 of 929 application files, about 860 of the
project's 1,992 files. At today's per-file cost that is about 860 × 1.5 s + 100 s ≈ 23 minutes on one 16-core
runner, and there are ~48 vex-api commits a day. Per push it could not keep up, which is why the patch runs it
hourly: up to ~24 runs a day. A full run of 1,992 files in one job is about 1,992 × 1.5 + 100 ≈ 51 minutes, inside
the 90-minute timeout. That is up to ~20 hours a day of a 16-core runner, until the per-file check and sign cost
falls. Eager: every vex-api commit but a few is a full run.

## What else is needed

Items 1, 2 and 4 are done in this tree (uncommitted): see "Cost model, re-measured". What is left, most important
first:

- **`solid_queue_shutdown_test.rb` in a slot batch (vci, blocking):** see "Found while measuring".
- **The fixed cost of a small change.** Each job pays ~70 s of setup, then 40 to 100 s to boot and set up 14
  slots, before its first file. Some options, none measured:
  - start files as soon as the first slot is ready instead of after all of them;
  - set up fewer slots for a few dozen files;
  - fewer partitions, since each job pays this cost.
- **The batch's tail.** Partition 2's batch took about twice what its files' average would give spread evenly.
  Starting the longest files first (from the previous attestation's `durationMs`) would shorten it.
- **Item 3 below** (shared inputs): this decides how often a pull request pays the full-share row.

The original list:

1. **Plan cost (vci, blocking).** Done (Lane P): 4.2 to 6.1 s a plan against 2,784 attestations. Verdicts must not scale with stored attestations × manifest size. Options: hash each
   checkout path once per plan and compare manifests against that cache; index candidates by unit and check the
   newest first, stopping at the first that matches; read the shared lines of a boot once (Lane B's file already
   identifies them); `vci prune --superseded` in the backstop. Target: under 20 s. This alone puts the
   small-change rows under 5 minutes.
2. **Check and sign in parallel (vci).** Done (Lane R): 0.04 to 0.09 s a file. `run_units` checks and signs one file after another (`check_one`, about
   1.0–1.2 s a file here). On 16 cores this becomes ~0.07 s a file, and a full share is ~70 + 20 + 100 + 499 × 0.42
   ≈ 400 s (~6.6 minutes) at N = 4, or ~5.5 minutes at N = 6. A full run of vci's per-file processes is then
   comparable in cost to the plain run: the partitions used 2.7 to 3.1 CPU-seconds a file (user + sys), while the
   plain run occupied ~5.1 core-seconds of wall time a file here (the spike's B5: 925 files, 14 workers, 336 s) and
   ~3.4 on CI.
3. **Fewer inputs every file shares (vci and vex).**
   - Every file reads `db/migrate`'s listing and `db/schema.rb` (`maintain_test_schema!`, 109 commits).
   - Every file reads the autoload directories' listings: a new file anywhere under `app/` re-runs everything (the
     spike's "precise Zeitwerk modelling" item).
   - `config/routes.rb` is recorded by content (the spike's "type-only record" item).
   - Models that Oaken's seeds load are inputs of every slot's files; vex could seed less, or vci could attribute
     slot-setup reads more narrowly. That would be a soundness question.
4. **The two collector bugs below must be fixed before rollout**, or vex's jobs fail on every run that includes
   those files. Done (Lane K).
5. With 1 and 2 done, N = 4 gives a full share of about 6.6 minutes and a typical pull request (median change)
   about 3.6 minutes. Measured: 6.3 and 8.5 minutes for a full share, 3.9 minutes for a median change. N = 6 brings the full share near 5 minutes, at 6 jobs' fixed cost on every pull request.

## Found while measuring

- **A slot batch fails `test/config/solid_queue_shutdown_test.rb` (vci 2.1 slots since f165f67, blocking).**
  - **What fails:** its second test spawns `bin/rails runner`, which starts a SolidQueue supervisor in fork mode
    against the slot's database (`vex_lanec_0`). In a slot batch, the forked worker's job fails in
    `RepositoryEvent.create!` (`Vcs::RepositoryMutationLeaseOwner#record_acquisition!`) with
    `ActiveRecord::ConnectionFailed (Mysql2::Error::ConnectionError: Lost connection to MySQL server during query)`.
    The test then waits 45 s for `held` and fails with `Timeout::Error` (`solid_queue_shutdown_test.rb:132`).
  - **Where it fails:**
    - every slot batch measured here: full partition 1 and all four rows;
    - a 2-slot batch of it and one other file, at load 4 to 6;
    - with the HEAD collector and with Lane K's collector;
    - Lane R's runs of f165f67, before and after its change.
  - **Where it passes:**
    - one file in a process of its own (`vci run` of that file alone: 2 runs, 0 failures, attested);
    - in the same 2-slot batch with the pre-f165f67 build (`target-design-vex-rollout`) and its collector;
    - in the runs before f165f67 (`lazy-app-w8`, the first partition 1/4).
  - **Why it matters:** the file is never attested, so it runs, and fails, in partition 1 on every pull request.
  - **Not found:** the cause. The failure is in a grandchild process of the file's process (runner → forked
    worker), which suggests something a slot gives its files that the child processes inherit. It needs a fix in
    vci, not in vex.
- **A collector bug fails a passing test (all modes, blocking). Fixed (Lane K):** attested in partition 1 above;
  `ruby/vci-collector` `VciCollector::Redefined`, spike B8. `test/services/hosting/manual_image_deploy_service_test.rb`
  (`services` group, never run under vci before) does this:

  ```ruby
  original_env = ENV.method(:[])
  ENV.stub(:[], ->(key) { ...; original_env.call(key) }, &block)
  ```

  Under the collector, `ENV.method(:[])` is `EnvHooks#[]`, prepended to `ENV`'s singleton class. The stub's
  `define_method(:[])` on that singleton class becomes `EnvHooks#[]`'s `super`, which calls the captured method
  again, without end. The run then fails with `SystemStackError: 10279 -> 41` in 5 of its 35 tests.
  - It reproduces one process per file: `vci run` of that file alone.
  - It passes plain: `PARALLEL_WORKERS=1 bin/rails test <file>` gives 35 runs, 0 failures.
  - B6's `AliasGuard` covers `alias_method`, not a `Method` object captured before the stub.
  - A fix in `EnvHooks`: when it is re-entered from its own `super` on the same thread, call the original method
    saved at hook time instead of `super`.
- **A batch file's child Ruby prints to stderr (batch mode, blocking). Fixed (Lane K):** a batch file's child
  process runs without the collector (spike B9). Lane K measured it attested in a 2-slot batch. Partition 3 was not
  re-run here.
  `test/services/vcs/merge_queue/reconciliation/batch_interaction_test.rb` runs `Open3.capture3(RbConfig.ruby, "-e",
  ...)` and asserts that stderr is empty. In the batch (partition 3/4) the child inherits `RUBYOPT` (the collector)
  but no test id: the batch sets the file's test id in the process, and Lane A's fix removes `VCI_RAILS_BATCH`. At
  exit the child prints `vci_collector: VCI_OUT or VCI_TEST_ID not set; nothing written`, and the test fails with
  *Expected "vci_collector: VCI_OUT or VCI_TEST_ID not set; nothing written\n" to be empty*. One process per file it
  passes and is attested (`vci run` of that file alone: `waived: process:spawn`, 2,773 inputs). Fix: the collector
  must say nothing in a child process of a batch file (for example, export the file's id to the environment when
  its process starts, as a one-file run has it, or stay quiet when `VCI_OUT` is set without a test id).
- The 51 `tmp/` refusals above are fixed in vex's helper (the patch). Two kinds of refusal are left that the patch
  does not touch: the case-folding collision of request paths (2 files) and skipped tests (6 files).
- `bazel/blob_store.rb` writes `tmp/bazel-blobs` shared by every slot. Lane A saw one refusal from it (two slots wrote
  one path); none was seen here.

## Not done

- No GitHub Actions run of the patch: the measurements are this Mac's. Slots on the Ubuntu runners, against the
  MySQL service container, are untested.
- The `services` group was run only lazily (the four partitions), not in eager mode, and its skip rates were not
  measured: the skip tables cover the `application` group.
- One mistake while measuring: a `vci run` with an empty file list (the list file had not been written) started
  every unit of the clone at 07:52 and was stopped at 08:02. It ran cargo warm-up builds and attested 57 cargo
  units, with the throwaway key, in the clone's local store only (nothing pushed). Its builds went to
  `/Users/pz/.cargo-target.noindex/vci` (the inherited `CARGO_TARGET_DIR`), whose `cargo clean -p` of the workspace
  crates removed 0 files.
- The pull-request skip estimate for unattested bases (about half full runs) is a model, not a measurement.
- The plan cost was measured with this tree's build only, on stores of up to 2,784 attestations.
- The re-measured cost model:
  - Only partitions 1 and 2 were re-run in full; partitions 3 and 4 were not.
  - The four rows were measured on partition 1 only, against a store of partition 1's own attestations (the plans
    against the large store were measured separately), with one changed path each, close to but not exactly the
    model's F.
  - Each number is one run on a shared machine (load 5 to 25).
  - True cold page cache was not measured (`sudo purge` needs a password).
  - The 70 s of job setup is today's CI figure, not measured with vci's binary install.
  - The cause of the `solid_queue_shutdown_test.rb` failure was not found.
