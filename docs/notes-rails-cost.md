# vex's Rails jobs: where the minutes go, what was changed, what it measured to

Date: 25 October 2026 (measurements), vci 2.7.32 measured, 2.7.34 released from this work. Status: in progress;
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

## What was changed

1. **The merge of a fetched tip** (vci-git, 2.7.34): the deletion records both sides wrote differently take ours
   *before* git merges, written into the tip's tree, so no path differs on both sides and `git merge-tree` merges
   trees alone, with `-X no-renames` so it never looks for where a deleted path went (that reads blobs too). A
   push whose other job deleted the same superseded attestations no longer pays a failed merge-tree and
   git-meta's merge. Measured: see "After".

(to be continued)
