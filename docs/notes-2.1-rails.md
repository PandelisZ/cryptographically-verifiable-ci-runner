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

## The plan: one observation per path, files in parallel

- `vci plan` (and so `vci ci` and `vci explain`) reads the checkout once per plan instead of once per candidate: a
  path's type, a file's hash, a symlink's target and a directory's children are read the first time a candidate names
  them and shared by every other candidate of every file (`vci_core::CheckoutCache`); which children of a listed
  directory git ignores is asked once per directory instead of one `git check-ignore` per manifest; the current global
  manifest is captured once per set of global observations. The checkout must not change while the plan runs.
- Files are verified in parallel (`VCI_JOBS` threads, default one per CPU); the output keeps the listing's order.
- Each file's candidates are checked newest first (by the `issuedAt` their payload states); the first that passes is
  used, as before, so when several pass the plan now names the newest. `vci explain` lists them in that order (and
  so, when the newest passes, no longer shows the older ones that fail). When none passes, the reason names what it
  named before: the furthest failure, of several as far the last in the store's order.
- `git check-ignore` stops (exit 128) on a path inside a submodule or beyond a symbolic link, after printing what it
  found before it. Both the plan and `vci run` give such a manifest or unit the answer it got before 2.1 (git's for
  its own paths alone, partial answer included) and cache nothing from the failed call, so neither a verdict nor an
  input root depends on which file or unit came first or on `VCI_JOBS` (an e2e with a submodule checks both).
- Same verdicts: on vex-api (1,992 files, 2,784 attestations) every file's verdict, reason and `by` were identical
  before and after, unchanged and with `app/models/user.rb` changed.
- Measured (`VCI_TIMING=1 vci plan --base-ref HEAD --project vex-api`, this Mac, a shared machine): the verdicts phase
  went from 513 to 613 s to 4.6 to 5.7 s warm (plan total 6.1 to 7.3 s), 10.1 s (total 16.3 s) with the 8 GB store
  not in the page cache; with `user.rb` changed, 508.4 s to 3.2 s. The demo projects' plans are unchanged (0.8 to
  0.9 s). Details: [`docs/spike-plan-cost.md`](spike-plan-cost.md).


## `vci run`: units checked and signed in parallel, the checkout read once per run

- Once a project's tests have finished, `vci run` (and `vci ci --key`) checks and signs its units in parallel
  (`VCI_JOBS` at a time, default one per CPU), and reports and stores them in their order: the lines, `--summary`,
  the exit code and the store's keys are those of a run one unit at a time (an e2e compares the two). The store is
  written one unit at a time, as before. Keyless signing is parallel too: its one piece of shared state (the Fulcio
  certificate, renewed a minute before it expires) is behind a lock; timestamps are requested concurrently.
- Each path of the checkout is read once for the whole run instead of once per unit: a file's hash, a directory's
  children (`vci_core::CheckoutCache`, the plan's cache), and git's answer to whether a path is ignored (one
  `git check-ignore` per path instead of several per unit over every child of every listed directory). The tree no
  longer changes after the tests; each unit still compares its inputs with the snapshot taken before the run.
- Where the time went: sampling the old `vci run` during its post-run phase on vex-api, about 95% of the main thread
  was `git check-ignore` (listing children for the manifest, for its listings, and the inputs-ignored warning), not
  hashing or `ssh-keygen`.
- Measured on vex-api's application group (939 files, `VCI_RAILS_JOBS=14`, lazy loading, a fresh clone state, this
  Mac, shared with other work, load average 8 to 46): from the batch's end to `N attested`, **1154 s (1.23 s a file)
  before, 37.8 s (0.040 s a file) after** (`vci: timing: check, sign and store 939 unit(s) of vex-api (14 at a time):
  37.78s`). Whole run 1825 s before, 704 s after. Verdicts: 928/11 and 926/13 attested/not; the difference is two
  request tests that failed under load in the second run (`result failed`), not a check.
- The input roots of request and controller tests differ between two runs of the same tree with either binary (30
  of 30 sampled files differed between two runs of the old binary); an old-binary `vci plan` skips all 926 files the
  new binary attested, so the cached manifests are what the uncached checks see.

## Load path probes recorded as one listing

- Rails puts `lib/` and `vendor/` on `$LOAD_PATH` ahead of the gems, so every `require` stats
  `lib/<feature>.{rb,so,bundle}` and `vendor/<feature>.{rb,so,bundle}` first, each an `absent` entry: on vex-api in CI
  ~10,000 of a file's ~13,800 entries (1.9 MB a manifest, a 5 GB store for 2,850 attestations, 13,800 entries checked
  per candidate in every plan).
- The collector now records 50 or more absent paths under one directory D (the deepest real directory above each, the
  path's component just below D absent) as D's listing instead. Sound (fails open): making any of them exist creates a
  new name in D. Left as probes: fewer than 50; a path through a file or symlink; D under vci's temp dirs, written by
  the process, or holding one of its test files (`spec/` under RSpec, unless already listed); a child git ignores (vci
  leaves those out of listings); everything when `git check-ignore` does not answer. Collector version unchanged
  (0.5.0): the inputs mean more, never less. Details: `docs/spike-rails.md`, "Load path probes folded into a listing".
- Cost: a new name directly in such a D runs the tests that list it. vex-api's `lib/` was already listed (Zeitwerk);
  `vendor/` becomes a listing (it holds `.keep`).
- Measured on vex-api (5 model tests, lazy loading, W=4): 2,285 to 2,343 inputs a file before, **453 to 473** after;
  manifest 305 to 312 KB before, **59 to 61 KB** after; all five attested both times; the plan skips them, runs them
  when `lib/zz_probe_test.rb` or `vendor/abstract_controller/base.rb` (an old probe) is added, and skips again once
  removed. A CI (eager-loading) manifest folded the same way offline: 13,848 entries and 1.88 MB to 3,875 entries and
  0.52 MB.
