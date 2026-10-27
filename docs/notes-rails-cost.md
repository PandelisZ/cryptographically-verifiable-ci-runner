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

## After: the new job on 2.7.35 and 2.7.36, and the push

Every pull-request Rails job completed between 2.7.35's publication (04:46 UTC) and 17:45 UTC on 26 October: 32
jobs, 8 on 2.7.35 and 24 on 2.7.36 (the other session's release of the same morning, Rails inputs loose by
default). SQLite lane, 4 or 8 slots. At 05:46 UTC vex #2139 moved the jobs from `composal-x64-4x` to
`composal-x64-8x` (8 CPUs), so most jobs that finished before 06:00 ran on 4 cores and every later one on 8. The
jobs API gives the steps; the logs give vci's lines.
"Files ran" is the count after `vci-skip.py` dropped the attested ones; the cases are the same as above.

| version | case (files ran) | jobs | job wall, median (range) | `vci run` step | Ruby batch | plan step | publish step |
|---|---|---|---|---|---|---|---|
| 2.7.35 | little (3 to 25) | 6 | 202 s (96 to 907) | 66 s | 50 s | 18 s | 22 s |
| 2.7.35 | a shared file (276) | 1 | 1,742 s | 1,237 s | 1,179 s (the files that ran took 15 s a process, 149 s at most) | 44 s | 67 s |
| 2.7.35 | everything (816) | 1 | 786 s | 683 s | 604 s (2.8 s a process on 4 slots) | 19 s | 26 s |
| 2.7.36 | little (5 to 24) | 8 | 598 s (451 to 644) | 182 s | 20 s | 22 s | 24 s |
| 2.7.36 | a shared file (195 to 197) | 2 | 635 s (510 to 760) | 218 s | 77 s | 22 s | 38 s |
| 2.7.36 | everything (808 to 832) | 14 | 742 s (334 to 1,173) | 406 s | 317 s (2.8 s a process; 8 slots in 12 of the 14) | 22 s | 27 s |

Three things in these numbers are not vci's doing, and they dominate the medians:

- **GitHub's cache restores crawled again** from about noon UTC: `jdx/mise-action`, the gems restore and the
  attestation-store restore took about 140 s each (they take 3 to 5 s when the cache is well). The part of a job
  outside vci's three steps was a median of 72 s on the 2.7.35 jobs (55 to 394) and **358 s** on the 2.7.36
  jobs (53 to 416; above 300 s in 14 of 24). That is the whole of the "little" row's rise from 202 to 598 s.
- **Pull requests with failing tests.** A file whose process fails in a slot runs again on its own, to tell a slot
  effect from a real failure, one process at a time (about 10 s each on this runner). Two 2.7.36 pull requests had
  13 and 16 files failing for real under SQLite; their jobs ran 20 s of batch and then 130 to 160 s of such
  re-runs, which is most of the "little" row's 182 s `vci run` step. A cheaper rule for a file whose own tests
  failed (as opposed to its process dying) is a candidate change, not made here.
- **Most 2.7.36 jobs re-ran everything** (14 of 24) because master had not been attested in loose mode yet when
  they ran, and because the SQLite lane's attestations were new (the first jobs on the lane attested it from
  nothing). Those full re-runs are the honest cost of a suite nobody had run yet: 317 s of batch for about 820
  files on 8 slots, 406 s of `vci run` step with the check, sign and store, against the lane's own cold plain
  run of 12 min 28 s and 12 min 42 s a shard on 4 workers (vex #2128's measurement).

**The push fix, measured.** On 25 October 57 of 143 jobs pushed through a `git merge-tree` that failed after 8 to
55 s and git-meta's merge of 10 to 67 s. In the 32 jobs since, **no merge-tree failed**; the seven jobs whose
other job had pushed first merged "N path(s) both sides changed take ours" in 0.5 to 2.4 s (the largest: 220
paths, 110 deletion records written differently). A push's fetch-and-merge round was a median of 11.8 s on 2.7.35
and 14.2 s on 2.7.36, against 7 to 51 s the day before (the 50.7 s round of the long job in "Where the push's
49 s go" was 25.5 s of failing merge-tree and 31.2 s of git-meta's merge). The publish step as a whole, which
also serializes the run's attestations and pushes, took a median of 22 to 27 s. Every vex job that attests pays
this merge whenever the other job of its run pushed first, so the saving is not the Rails jobs' alone.

**The plan** on the new job: the action's plan step 18 to 22 s median (vci's own `plan total` 4.6 to 4.8 s; the
rest is installing vci and the store's warm-up), then `vci-skip.py`'s second plan of about 5 s.

What the new numbers do not show: the three cases against a plain job of the same shape on the same day (vex
#2128's cold run is the only plain measurement of the SQLite lane). The scripts that read these from the logs are
`measure_new.sh` and `parse_logs.py` in the session's scratchpad; the per-job table is `new/parsed.tsv` there.
