# vex's Rails jobs: where the minutes go, what was changed, what it measured to

Date: 25 to 26 October 2026 (measurements), vci 2.7.32 measured, 2.7.34 and 2.7.35 released from this work. Status: in progress;
the "After" section is filled in once the release has run on vex's pull requests.

Everything below is read from GitHub Actions on `ComposalAI/vex`, `rails-tests.yml`: the jobs API for each step's
start and end (`gh api repos/ComposalAI/vex/actions/runs/<id>/jobs`), and each job's log for vci's `VCI_TIMING`
lines. The suite is 2,078 test files (2,230 by 25 October), two jobs per pull request, 16 slots per job, a seeded
MySQL database per slot.

## The plain job, from the logs

The post said a plain `bin/rails test` job took 3.5 minutes (769 jobs, the week before vci). The jobs API gives
this for the plain jobs, before vci took them over on 18 October:

| days | jobs | job wall, median (p25 to p75) | `rails test` step, median | container init |
|---|---|---|---|---|
| 16 to 17 October | 341 (application 171, services 166) | 272 s: application 261 (245 to 283), services 284 (265 to 296) | 186 s / 204 s | 20 s |
| 18 October | 73 | 304 s / 318 s | 206 s / 219 s | 19 s |

So the honest plain figure is **4.5 to 5.3 minutes a job**, container start to job end; the 3.5 could not be
reproduced. Two things changed under everyone since: the `mysql:8.0.46` service image is pulled on every job now
("Downloaded newer image"), so container init is 48 s instead of 20; and the suite grew.

## Two kinds of runner

The `composal-x64-16x` pool answers with two kinds of host, told apart by the memory `scripts/ci/runner-setup.sh`
prints:

| host | memory | a vex-api file's process, 16 slots | slot setup (database, schema, seeds) |
|---|---|---|---|
| fast | 94,750 MiB | 4 to 5 s | 44 to 50 s |
| slow | 257,583 MiB | 9 to 12 s | 13 to 16 s |

The slow kind runs Ruby at about half the speed (its disk is faster: slot setup, which is DDL and fsync, takes a
third) and took 25 of the 82 full re-runs on 25 October. A plain job on it is slower too. Every median below is
per kind; a comparison that mixes them compares runner luck.

## 25 October, vci 2.7.32: 143 jobs

| case (files this job ran) | fast runners: job, vci step | slow runners: job, vci step |
|---|---|---|
| little, 60 or fewer | 437 s, 297 s (10 jobs) | 686 s, 348 s (10) |
| a shared file, 61 to 900 | 472 s, 261 s (31) | 1,133 s, 686 s (9) |
| everything, more than 900 | 682 s, 534 s (57) | 1,423 s, 999 s (25) |

Against the plain 272 to 318 s, a vci job was longer in every case on 25 October. The "little" case is not the
cheap one it should be: the files that still run after a small change are mostly the long `persistent_agents`
tests (90 to 280 s each, run as shards), so its Ruby batch still took 186 s.

Where a full re-run's 534 s go on a fast runner (medians): plan 23 s; the Ruby batch 406 s (boot 2 s, slot setup
45 s, then 1,100 files at 4.7 s a process on 16 slots); check, sign and store 13 s; push 49 s. Reading the plain
step the same way (206 s for about 1,040 files: boot and 16 workers' setup, then the files) gives about 2.2 s a
file-worker, eager-loaded. The batch is the cost; a file's process costs about twice what the plain run pays per
file.

Where the plan's 25 s go (medians, p90 46 s): fetching and merging what master pushed 11.7 s (`git fetch` 2.3,
completing the local and the tip's trees 2.1, listing the tip's keys 1.0, materializing 1.7, the rest in a dozen
smaller steps), the stored values the verdicts read 4.0 (three blob fetches in a row: envelopes, manifests, base
manifests), the candidates 0.8, the verdicts 1.8, the second round for units not skipped 3.7.

Where the push's 49 s go: 57 of the 143 jobs ran a `git merge-tree` that took 8 to 55 s and failed with "lazy
fetching disabled", then git-meta's own merge of three listed trees, 10 to 67 s. The cause, reproduced on a
blobless clone: when both sides changed one path (the deletion records of the same superseded attestation, which
the run's two jobs stamp differently), git merges by content and needs the tip's blob, which the clone never
fetched. The rest of a push is the fetch and merge round (git fetch 2 to 7 s, serializing the run's attestations
through fast-import 3 to 5 s), the pre-push checks 2 s, the pack's missing objects 4 s, `git push` 4 to 7 s.

## The same suite, plain and with vci, on the same day

The plain step of 18 October is not today's suite. A manual workflow on a vex branch
(`pz/vci-rails-cost-experiment`, `.github/workflows/vci-rails-cost.yml`) ran the `application` group (1,072 files,
6,463 tests) on the runners on 26 October, one variant per job, with a vci built from this branch, no store, no
push, no shards (a store with no recorded durations shards nothing):

| variant | runner | what it measures | result |
|---|---|---|---|
| plain, eager-loaded (`CI=true`, 16 workers, as CI runs it) | fast | `bin/rails test` of the 1,072 files | `Finished in` 340, 341, 344, 346 s (four jobs); step 347 to 351 s |
| plain, lazily loaded (`CI` unset) | slow | the same, loaded as vci loads | `Finished in 638 s`, step 643 s |
| `vci run`, 16 slots (lazy, as shipped) | fast | the Ruby batch | 372 and 384 s (two jobs); slot setup 48 s; a process 3.1 to 3.2 s on average, 295 to 308 s at most (unsharded; a slot's files add up to 335 s at most and 194 s at least, so the slowest file ends the batch) |
| the same | slow | | 674 and 696 s; slot setup 14 to 18 s; a process 6.5 s on average (requires 0.33 s of it, routes 0.17 s, GC 0.46 s, 69 requires) |
| the same with the application eager-loaded and routes drawn before the slots fork (`VCI_RAILS_EXPERIMENT=eager`) | slow | what lazy loading costs a process | 798 s; a process 7.9 s (requires 0.05 s): slower, not faster |
| the same with a run-private compile cache (`iseq`) | slow | what parsing and compiling cost | 676 s; a process 6.0 s (requires 0.31 s; 1,294 cache hits and 1,831 misses a process) |
| the same with `Process.warmup` in each slot (`warmup`) | fast | copy-on-write after the fork | 360 s; a process 3.0 s |
| the same with the routes drawn before the fork (`routes`) | fast | the routes' first draw | 404 s; a process 3.5 s |

What this says:

- **On the same runner, vci's batch costs about what the plain run costs.** On the fast kind, the plain run's 340
  to 346 s against 372 and 384 s for the shipped vci (and 360 and 404 s for two variants that moved nothing), all
  without shards: the slowest file ran 284 to 319 s in one process and ended every vci batch, where the plain run
  spreads its tests over the workers. The 2.2 s a
  file-worker read from the 18 October step was the October 18 suite; the same group takes 344 s plain today
  because the suite gained the long `persistent_agents` tests, which the plain run spreads over 16 workers test by
  test and vci can only shard.
- **Lazy loading is not the cost.** A process spends 0.3 s of its 5.5 to 6.5 s in requires (autoloads included)
  and 0.17 s drawing routes; eager-loading everything before the fork made processes slower (bigger heap to copy
  on write and to collect), and the compile cache moved requires from 0.33 to 0.31 s.
- **The slow runner kind is the slow runner kind**: plain lazy 638 s there against 344 s eager on the fast kind is
  mostly the host, not the loading.
- `Process.warmup` hung a batch for four hours on macOS (a slot's process never ended; the file watchdog did not
  stop it) and changed nothing measurable on Linux: not shipped, left as a switch.

**Slot setup** (the per-slot database, schema and seeds; 45 s on the fast kind, 13 s on the slow kind, paid by vci's
slots and by plain's workers alike) is bound by fsync: on this Mac, `bin/rails db:test:prepare` against the same
`mysql:8.0.46` container took 25 to 45 s with the data directory on disk and 5.5 to 10.5 s on a tmpfs
(`--tmpfs /var/lib/mysql`). That is vex's `services.mysql.options` to change, for the plain and the vci jobs
alike; not done here.

## What was changed (2.7.34)

1. **The merge of a fetched tip** (vci-git; 2.7.34, finished in 2.7.35): every path both sides changed is put
   back to the base's state in the tip's tree before git merges, so each is a change on ours' side only and
   `git merge-tree` merges trees alone, reading no blob, with `-X no-renames` besides. The result is what
   git-meta's merge gives (ours wins a deletion record both wrote differently; a value both deleted stays deleted;
   a record both added once). A push whose other job deleted the same superseded attestations no longer pays a
   failed merge-tree (8 to 55 s) and git-meta's merge (10 to 67 s). 2.7.34 edited only the records that differed,
   through a gix tree editor, and passed trees to merge-tree: on git 2.43 (Ubuntu 24.04's, the runners') that
   git takes commits only and reads the base's blob of a path both sides deleted whenever both also added a path,
   so every merge there still took the slow path (found by running the store's tests in an Ubuntu 24.04
   container; they run there now). 2.7.35 edits through git's index (`read-tree`, `update-index --index-info`,
   `write-tree --missing-ok`, which take an object id the clone lacks) and commits the edited tree. Tests:
   `two_blobless_clones_deleting_the_same_value_both_push` asserts the merge went through git.
2. **One slot per piece of work** (the collector): a batch that runs few files, some as shards, opens one slot per
   file or shard instead of one per file (a job that ran 8 files, four of them as 3 to 5 shards, ran its 20 pieces
   on 8 of 16 slots).
3. **Measurement switches**, off: `VCI_RAILS_PROFILE=1` prints one `vci-profile` line per process (requires,
   routes, GC, process time); `VCI_RAILS_EXPERIMENT` takes `eager`, `routes`, `warmup`, `iseq` (above).

Measured and not changed: lazy loading, the compile cache and `Process.warmup` (above); the plan's three
dependent blob fetches (envelopes, manifests, base manifests: about 4 s a plan, a round trip each, each needing
the previous one's answer unless remembered from an earlier plan).

## The job changed under this work

At 00:30 UTC on 26 October vex merged #2128, "Use SQLite for fast Rails tests and reduce CI resources": a pull
request's Rails jobs now run on `composal-x64-4x` (4 cores), with file-backed SQLite instead of the seeded MySQL
service, 4 slots, and only the files the SQLite lane runs (809 per shard, 1,618 of 2,232; the 613 MySQL-dependent
files are an optional local task), through `scripts/ci/rails-db-tests.sh`: the action's `plan` step, then
`vci-skip.py` drops the attested files and `vci run` runs the rest, then a separate "Publish Rails attestations"
step pushes (best effort, two minutes at most). The pull request's own numbers for a cold run of that lane: the test
step took 12 min 28 s and 12 min 42 s per shard on four cores. The 16-slot MySQL job the measurements above
describe no longer runs on pull requests, so the three cases cannot be re-measured on it; what follows is the new
job on 2.7.35, by the same cases, and the parts of a job the fixes touch (the plan, the push) are comparable
across shapes.

## After: the new job on 2.7.35, and the push

Pull requests that ran on 2.7.35 between its publication (04:46 UTC) and 2.7.36's (about 05:25 UTC), six jobs of
four pull requests, SQLite lane, 4 slots on a 4-core runner (the jobs API for the steps, the logs for vci's lines):

| case (files this job ran) | jobs | job wall | plan step | `vci run` step | publish step |
|---|---|---|---|---|---|
| little (3 to 21 files) | 4 | 96, 137, 178, 225 s | 9 to 17 s (one 61 s) | 17 to 103 s | 15 to 54 s |
| a shared file (46 ran) | 1 | 584 s | 18 s | 475 s (batch 449 s: the files that ran took 23 s a process, 63 s at most) | 17 s |
| everything (816 ran) | 1 | 786 s | 19 s | 683 s (batch 604 s: 2.8 s a process on 4 slots; check, sign and store 16 s) | 26 s |

The first two 2.7.36 jobs (808 files each, nothing attested after the change to loose inputs) took 334 and 371 s
with batches of 200 and 233 s on 8 slots.

**The push fix, measured.** On 25 October 57 of 143 jobs pushed through a `git merge-tree` that failed after 8 to
55 s and git-meta's merge of 10 to 67 s. In the six 2.7.35 jobs no merge-tree failed; the job whose other job had
pushed first (the full re-run, 809 attestations) merged "220 path(s) both sides changed take ours (110 deletion
record(s) they wrote differently)" in a 2.4 s merge commit, its push round's fetch and merge taking 14.6 s in all
and `git push` 6.1 s; the other five merged in 0.5 s and pushed in 4 to 16 s. A push's fetch-and-merge round was
6.6 to 14.6 s against 7 to 51 s the day before (the 50.7 s round of the long job in "Where the push's 49 s go"
was 25.5 s of failing merge-tree and 31.2 s of git-meta's merge). Rails jobs are not the only ones that push:
every vex job that attests pays this merge when the other job of its run pushed first.

What the new numbers do not show: the three cases against the plain job of the same shape (the pull request that
made it measured its cold run at 12 min 28 s and 12 min 42 s a shard on four cores against 10 to 11 min with vci
here, nothing attested); and medians, with six jobs. The script that reads these from the logs is in the session's
scratchpad (`measure_new.sh`, `parse_logs.py`); more pull requests on 2.7.36 and later will refine them, by case
and by version, and 2.7.36's loose inputs are expected to move most pull requests into the "little" row.
