# The plan's cost: one observation per path, files in parallel (vci 2.1, unreleased)

Date: 2026-10-18. Status: implemented in `crates/vci-cli/src/plan.rs` and `crates/vci-core/src/manifest.rs`, measured
on vex-api; not released. The user-facing description is in [REFERENCE.md](REFERENCE.md), "Verification (`vci
plan`)", "Cost".

## Why the plan took minutes

[notes-rails-rollout.md](notes-rails-rollout.md) measured `vci plan` of vex-api at 187 to 495 s, growing with the
store. Each of the ~1,000 files with attestations has about three stored candidates (2,784 attestations: the lazy and
eager versions of the `application` group), and each candidate's check did all of this on its own:

- rehashed every entry of its global and input manifests against the checkout (2,548 entries a lazy manifest, 13,855
  eager): one `lstat`, `open`, read and BLAKE3 per entry, the same few thousand paths for every candidate;
- for both manifests, listed every directory the manifest lists and started a `git check-ignore` process with the
  children it does not name (the git-ignored children are left out of listings since 2.0.3): up to two git
  processes per candidate (about 5,600 for 2,784 candidates), each matching thousands of paths against vex's
  `.gitignore`s;
- recaptured the current global manifest once per file.

A sample of the running plan (macOS `sample`, 3 s) showed the verifying thread blocked in `write` to `git
check-ignore`'s stdin (`run::git_ignored` under `run::ignored_listing_children`) and in `posix_spawn`, not hashing:
`/usr/bin/time` gave 482 to 512 s of user time for a 509 to 614 s plan, nearly all of it in the git children. Files
were verified one after another (one thread per project).

## What changed

- **A checkout cache** (`vci_core::CheckoutCache`): each path's `lstat` result, a file's contents hash and exec bit, a
  symlink's target and a directory's children are read once per plan, the first time any candidate names the path,
  and shared by every candidate of every file. A directory's listing hash is computed from its cached children once
  per set of children left out. `InputManifest::diff_against_cache` and `InputManifest::capture_cached` observe
  through it exactly as `diff_against_checkout_excluding` and `capture_with_env` observe the filesystem (same entry
  for every state, same errors); a failed observation is not kept. Sharded locks (64 shards); a path is observed by one
  thread while the others wait for it. Nothing invalidates it: the checkout does not change during a plan.
- **The ignored children once per directory** (`plan::IgnoredChildren`): which children of a listed directory git
  ignores is asked once per directory, in one `git check-ignore` for the directories a manifest lists that no manifest
  listed before; per manifest, the ignored children it does not name are left out, as before. When that
  `git check-ignore` stops with an error (exit 128: a child inside a submodule or beyond a symbolic link, after
  printing what it found before it), each of those directories is asked about alone; one git still cannot answer
  about is not cached, and a manifest that lists it gets the answer it got before 2.1, from one `git check-ignore` of
  its own children (`run::ignored_listing_children`), partial answer included. (A first version cached the failed
  batch's partial answer for every directory in it, so a file's verdict depended on which file reached a directory
  first.)
- **Files in parallel**: each project's files are verified on a rayon pool of `VCI_JOBS` threads (default: one per
  CPU), collected in the listing's order. The input-manifest loader reads the store under its lock and decodes outside
  it.
- **The current global manifest once per set of global observations** (memoized by the observation list; a Rails
  project has one per runner), and the case-collision check once per input root.
- **Newest candidate first**: candidates are ordered by the `issuedAt` their payload states (read before the
  signature, only to order them; unreadable ones last, ties in store order). The checks and their order are
  unchanged: envelope, signature, signer, statement, expiry, identity, toolchain, env-config, result, waived, dirty,
  then global inputs, inputs (the rehash), externals, env. The first that passes is used, as before; when several
  pass, the plan now names the newest (before: the first in key order, which is the signer's fingerprint and the
  storage key). `vci explain` lists the candidates in this order. When none passes, the reason still names the
  failure that got furthest and, of several as far, the last in the store's order, as before (not the oldest
  candidate's, which the new order would otherwise give).

## Measurements

Machine: this Mac (14 cores), shared with other sessions running builds and test suites (load averages 5 to 44 during
the runs; given per run below). vci built in release mode from `f165f67` (before) and from `f165f67` plus only these
changes (after), each in its own snapshot and target directory.

Repository: `lanec/plan-p`, a `git clone --no-local -b lazy` of the measurement clone of vex-git `3738f8486d` (the
lazy rollout branch: `CI` not declared), with the `plan-lazy` attestation store copied in by `cp -c` (8.0 GB of
SQLite, 2,784 attestations). Command, from that clone:

```
/usr/bin/time -l env VCI_TIMING=1 VCI_RUBY_COLLECTOR=<lanec>/src/ruby/vci-collector \
  mise exec -- <vci> plan --base-ref HEAD --project vex-api --format json
```

The plan lists 1,992 files (both groups); 929 skip (the `application` group's 929 attested files; the `services`
group has no attestations in this store).

| run | load (1 min) | verdicts phase | plan total | wall | user + sys | max RSS (MiB) |
|---|---|---|---|---|---|---|
| before, store just copied (its pages not cached) | 14 → 18 | 612.54 s | 614.09 s | 614.42 s | 512.35 + 94.88 s | 561 |
| before, warm | 19 → 6 | 513.49 s | 515.46 s | 518.09 s | 482.87 + 95.55 s | 558 |
| after, warm (right after the first before) | 17 | 5.65 s | 7.30 s | 7.62 s | 8.34 + 2.53 s | 597 |
| after, store just copied again (its pages not cached) | 25 → 20 | 10.07 s | 16.25 s | 16.95 s | 8.67 + 2.51 s | 596 |
| after, warm | 6 | 4.61 s | 6.13 s | 6.24 s | 8.43 + 1.97 s | 598 |
| after, warm, `VCI_JOBS=1` | 6 | 7.71 s | 8.36 s | 8.42 s | 6.97 + 1.29 s | 574 |

With `vex-api/app/models/user.rb` changed by one comment line (12 of the 939 `application` files skip; every other
candidate is rehashed in full and fails at `inputs`, the most expensive path):

| run | load (1 min) | verdicts phase | plan total | wall |
|---|---|---|---|---|
| before | 5 → 18 | 508.43 s | 509.24 s | 509.31 s |
| after | 18 | 3.15 s | 4.72 s | 4.98 s |

Same results: every after plan above gave exactly the before plan's verdicts, file by file (same order, same skip,
same reason, same `by`), compared by a script over the JSON (`1992 files: identical 1992`), for the unchanged and the
`user.rb` checkouts, and for `VCI_JOBS=1`. The newest-first order changed no file's `by` in this store.

The cold case is "the store's pages not in the page cache" (a fresh APFS clone of the SQLite file), not a cold
checkout: `sudo purge` was not available. The 6 s between "plan total" and the phases it prints in that run are the
per-unit candidate lookups in the cold 8 GB SQLite file, before the verdicts phase.

What is left of the warm verdicts phase (`sample` of the after plan): the threads wait mostly for the plan's one
Rails boot (the native libraries a candidate records, `RailsAdapter::run_probe_script`, once per project, as
before), and for the batches of `git check-ignore` for directories not seen yet (one at a time, under one lock).

**`vci ci`** calls the same `plan::plan` with the same options as `vci plan` (`cmds::ci`); the action's plan step is
`vci plan --fetch ... --base-ref ... --format text`. A vex Rails job that runs both pays the plan twice: about 2 × 6
to 17 s on this Mac instead of 2 × 510 to 615 s. `vci ci` itself was not run here: on vex-api it would go on to run the
1,063 files the plan runs, in the slot databases other measurements were using.

**The demo projects** (this repository's `vci.toml`, five projects, 21 units attested with a throwaway key in a
scratch clone, the action's plan as `vci plan --base-ref HEAD --format json` under `mise exec ruby@3.4.9`), three runs
each, before then after:

| checkout | before: verdicts / total | after: verdicts / total |
|---|---|---|
| unchanged (21 of 21 skip) | 0.11–0.12 s / 0.85–0.88 s | 0.11–0.12 s / 0.82–0.88 s |
| `demo/pytest-app/src/b.py` and `demo/rails-app/app/models/widget.rb` changed (16 of 21 skip) | 0.10–0.11 s / 0.81–0.83 s | 0.11 s / 0.81–0.84 s |

Same verdicts before and after (`21 files: identical 21`). Small plans are not slower: making the thread pool is
noise next to the projects' toolchain probes.

## Not done

- No run on a CI runner, and no true cold page cache (no `sudo purge`).
- `vci ci` was not run end to end on vex-api (see above).
- The store measured holds about three candidates a file. A store with many more versions of each file's attestation
  costs, per extra candidate, a signature check and, when it reaches the rehash, the comparison of its entries with
  cached observations (no I/O for paths already seen).
