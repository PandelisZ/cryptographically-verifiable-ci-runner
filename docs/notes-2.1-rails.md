# vci 2.1 (Rails): release notes in progress

Not released; no version bump yet. Findings and measurements: [`docs/spike-rails.md`](spike-rails.md), "Slots"
(S1 to S8).

## Slots: a Rails batch runs its files in parallel, one database per slot

- `vci run` (and `vci ci --key`) of several Rails files now runs them **W at a time** when the project runs its tests
  in Rails' parallel worker processes (`parallelize` in `test_helper.rb`, with processes, as `rails new` writes it). W
  is `VCI_RAILS_JOBS`, else `PARALLEL_WORKERS` above 1 in vci's environment, else `VCI_JOBS` or the number of CPUs
  capped by `parallelize(workers: n)` (at most one per file). `PARALLEL_WORKERS=1` in vci's environment or
  `parallelize(workers: 1)` (tests that must not run at once) turns the slots off. Each slot is set up as Rails sets up a worker: before-fork hooks once, then in each slot
  `parallel_worker_id = i` and every after-fork hook (Rails' own creates and loads `<database>_<i>`;
  `parallelize_setup`; Oaken's seed load), and `parallelize_teardown` at its end. Each file still runs in a process
  of its own, forked from its slot: its inputs, result and exit status are its own, as in vci 2.0's batch.
- **Not deterministic at the database level, by decision**: a file starts from its slot's seeded database as the
  slot's earlier files left it, as a test in a Rails worker does. What the database holds was never an input.
- A file's process does not seed again: Minitest's executor answers `should_parallelize?` as in a worker (Oaken
  reseeds otherwise). On vex-api the 50 files' processes spent 1,126 s in their tests one at a time and 63.6 s in
  slots.
- `VCI_RAILS_JOBS=1` runs one file at a time (vci 2.0's batch); `VCI_RAILS_JOBS=<n>` applies slots to any project
  (Minitest: each slot still gets Active Record's database per worker, which `rails/test_help` registers; RSpec has
  no workers: its slots share the test database). A project without `parallelize` and without `VCI_RAILS_JOBS` runs
  one file at a time, as before, and so do files without a boot (their first statement is not a require of a shared
  helper: nothing would give their slots a database each).
- Fails open: a slot whose setup raises takes no file (the others run them; if none can, the files run one process
  per file); a change in vci's temp dir outside the slots' own sends the group back, also one undone before the
  slots end (a write a slot's process makes there is noted when it happens); each slot has its own temp dir, and
  what a group leaves in vci's temp dir is removed before the next group boots;
  `VCI_RAILS_PER_FILE=1` still runs one process per file. A slot's setup may connect to the configured database
  server without a database (to create or purge `<database>_<i>`); nothing else may.
- Manifests in slots: a file's one-file entries, plus what its slot's setup recorded before the file's process forked
  (`absent` load-path lookups of Active Record's schema and database-task files in `lib/` and `vendor/`, `VERBOSE`
  absent); never fewer.
- `vci run` logs `..., booted once, one process per file (exit 0), 8 slots at once` and `vci: slots set up in 70.9 s at
  most; a file's process took 5.5 s on average, 12.1 s at most`. `batch/files.jsonl` lines carry `slot` and `ms`.

## Fixed (vci 2.0's batch mode had both)

- A child Ruby process a test starts (`ruby bin/rails runner ...`) inherited the batch's list and, at its exit, sent
  every file of the batch back to run one process per file (vex-api's `config/solid_queue_shutdown_test.rb`). The
  first process to load the collector names itself in `VCI_RAILS_BATCH_PID`; a process with another id is not the
  batch (a runner that execs Ruby again keeps its id, and the batch).
- What one helper group's boot left in vci's temp dir was there for the next group's files (not for a one-file
  run, which gets a fresh one). It is now removed after each group.
- A file whose first statement requires another test file of the batch (`require_relative "queue_result_reuse_test"`)
  made its group's process drive the whole batch again. Such a boot now loads as a plain require.

## Measurements (vex-api, this Mac: 14 cores; MySQL 8 in Docker; a clone of vex-git master `3738f8486d`, no remote)

`/usr/bin/time -l env VCI_RAILS_JOBS=<W> mise exec -- vci run <files> --key <throwaway key>`:

| | wall | per file | attested / refused |
|---|---|---|---|
| 50 files of the `application` group, W=1 (vci 2.0's batch) | 1432.9 s | 28.7 s | 47 / 3 |
| the same 50 files, W=8 | 167.6 s | 3.4 s | 47 / 3 (the same) |
| the `application` group, 939 files, W=8 | 1890.8 s (about 950 s of tests in slots, about 940 s of checking and signing afterwards) | 2.0 s | 894 / 45 |

Of the 45, 34 are a slot effect on vex-api: its `parallelize_teardown` removes the per-worker Active Storage root
(`tmp/storage/worker-<pid>`) the files read, before vci hashes their inputs (refused: `capturing inputs`); one file
saw another slot's file write the same path under `tmp/` (refused: `input changed during the run`). The rest are
skipped tests, files without tests and a case-folding collision of request paths, as one at a time.

Projected at 16 slots (vex's CI runners): about 380 s of Ruby, plus about 940 s of checking and signing one file after
another unless that is made parallel or cheaper: about 22 minutes for the group in one job (vex's plain run with 16
workers: 5 minutes). Next costs: signing and checking per file (one after another, ~1 s a file), and the collector's
per-file output (~3.3 s of each file's 5.5 s).

## Shared output: a file's process writes only what it does not share with its boot

- In a batch, the lines every file of a boot (or slot) shares, ~14,400 of each file's ~14,500 on vex-api, are written
  once, by a child of the process the files fork from, before the first fork (`batch/shared-<pid>.jsonl`). Each
  file's process still makes all of its lines at exit, reusing the boot's classification of each path and its
  comparison of each gem file with the gem's archive, and writes only the lines that are not shared plus the shared
  lines that are not its own (`{"kind":"shared","base","sha256","drop"}`). vci reads the two together: the same
  `Observed` as a whole output, so check, manifests and the store are unchanged. Details: `docs/spike-rails.md`
  ("Shared output", O1 to O7).
- A file's output: 3.50 s a file before, **0.17 s** after (W=1, 50 vex-api files, average; 0.13 s at W=8). The 50
  files at W=1: 1004.96 s before, 851.58 s after, CPU 299 s before and 150 s after; the same 47 attested and 3 refused.
- Checked on five vex-api files at W=1 and W=3: the split output read with its shared lines is, sorted, byte for byte
  the whole output, which is line for line vci 2.0's (but the result's `durationMs`); Rust's `Observed` of the two is
  equal.
- Fails open: if the shared lines cannot be written, every file writes all of its output; if a file's shared lines
  cannot be read as named (missing, another sha256, a bad index), that file runs again one process per file.
  `VCI_RAILS_SHARED_OUTPUT=0` turns sharing off.
- `vci run` logs `vci: a file's process wrote its output in 0.17 s on average, 1.42 s at most (what the files of a boot
  share written 1 time(s), in 3.6 s at most)`; the timings are in `batch/output.jsonl`.
- Next cost: vci checking and signing each result after the batch, one after another (~1 s a file), and parsing and
  hashing each file's ~14,500 inputs separately.
