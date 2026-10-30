# The two fixed costs of RESULTS.md, removed and re-measured (30 Oct 2026)

Same machine (Apple M3 Max, 14 CPUs), same local sqld 0.24.32 on 127.0.0.1:18181, the same
1,175 real vex units re-signed by `harness/meas_plan_v2.rs` into `meas3c` (format 3) and `meas1c`
(format 1), rebuilt from scratch for this run (new throwaway key, new throwaway checkout commit
`d73a75f2`, tree `8c73b914`, on vex `5eb73122`; `config2.json`, `harness-2.log`: 904 of 904 roots
reconstructed, 581,180 entries observed). Binaries:

- `before`: store-v2 at `86bd306` (release, `meas-v2/vci-before`)
- `fix1`: + `eaa13b3` (decode each verdict object once per round)
- `after`: + `a397027` (the Rails boot started early, killed when unused)
- `281`: vci 2.8.1 (`/opt/homebrew/bin/vci`)

`measure2.sh` (round-robin over the configs, 7 rounds), `parse2.py` -> `results2.json`, every run in
`runs2/` (plan JSON, stderr with `VCI_TIMING=1`, `/usr/bin/time -l`; the raw runs stayed on the measurement host,
`results2.json` holds what was parsed from each). The scripts here are the ones that took these runs with
their paths made arguments (see "Rebuilding" at the end): `parse2.py` over `runs2/` gives this file's table and
`results2.json` again (the same table, the same JSON). Variants: `api` = `--project
vex-api` with the namespace's `plan:natives:vex-api` flag set (every plan after a store's first: the
steady state in CI); `api-first` = the same with that flag deleted first (a store's first plan);
`all` = vex-api, vex-web, rust, vex-roder, flag set. Memo tables emptied before every run, as in
RESULTS.md.

## The table (medians of 7; wall = the `vci plan` process; seconds)

| binary | variant | wall median (min..max) | plan total | resolve toolchain | fetch values | load verdict objects | verdicts | CPU user | store req | store MB | skip/run | RSS MB |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| before-f3 | api | **2.77** (2.7..3.0) | 2.71 | 0.57 | 0.05 | **1.46** | 0.41 | **3.96** | 9 | 2.9 | 1156/905 | 192 |
| fix1-f3 | api | **2.61** (2.3..4.4) | 2.55 | 0.58 | 0.05 | **0.03** | 1.70 | **2.57** | 9 | 2.9 | 1156/905 | 191 |
| after-f3 | api | **2.60** (2.4..5.4) | 2.54 | 0.59 | 0.05 | 0.03 | 1.64 | 2.58 | 9 | 2.9 | 1156/905 | 193 |
| before-f1 | api | 2.65 (2.4..4.2) | 2.58 | 0.55 | 0.18 | 0.00 | 1.58 | 2.87 | 7 | 43.3 | 1155/906 | 284 |
| after-f1 | api | 2.62 (2.3..12.9) | 2.56 | 0.57 | 0.07 | 0.00 | 1.58 | 2.86 | 7 | 43.3 | 1155/906 | 287 |
| 281-f1 | api | 2.60 (2.5..5.6) | 2.52 | 0.56 | 0.10 | - | 1.64 | 2.84 | 4 | (not printed) | 1155/906 | 281 |
| before-f3 | api-first | **4.66** (4.5..5.6) | 4.60 | 0.48 | 0.07 | 1.47 | 2.43 | 3.99 | 9 | 2.9 | 1156/905 | 191 |
| fix1-f3 | api-first | **2.98** (2.9..8.5) | 2.92 | 0.47 | 0.05 | 0.03 | 2.18 | 2.55 | 9 | 2.9 | 1156/905 | 191 |
| after-f3 | api-first | **3.16** (2.7..5.1) | 3.09 | 0.48 | 0.05 | 0.03 | 2.35 | 2.54 | 9 | 2.9 | 1156/905 | 191 |
| before-f1 | api-first | 2.98 (2.8..4.2) | 2.91 | 0.47 | 0.08 | 0.00 | 2.07 | 2.79 | 7 | 43.3 | 1155/906 | 283 |
| after-f1 | api-first | 3.32 (2.8..3.5) | 3.22 | 0.46 | 0.08 | 0.00 | 2.34 | 2.85 | 7 | 43.3 | 1155/906 | 283 |
| 281-f1 | api-first | 3.25 (2.9..4.5) | 3.16 | 0.50 | 0.10 | - | 2.28 | 2.80 | 4 | (not printed) | 1155/906 | 281 |
| before-f3 | all | 3.04 (2.9..3.3) | 2.98 | 0.60 | 0.05 | 1.47 | 0.50 | 4.38 | 9 | 3.3 | 1164/1375 | 193 |
| fix1-f3 | all | 2.90 (2.3..4.2) | 2.84 | 0.57 | 0.05 | 0.03 | 1.96 | 2.89 | 9 | 3.3 | 1164/1375 | 192 |
| after-f3 | all | 3.14 (2.7..5.0) | 3.05 | 0.61 | 0.04 | 0.04 | 2.08 | 2.93 | 9 | 3.3 | 1164/1375 | 192 |
| before-f1 | all | 2.82 (2.3..5.5) | 2.75 | 0.60 | 0.10 | 0.00 | 1.63 | 3.24 | 7 | 44.2 | 1163/1376 | 297 |
| after-f1 | all | 2.95 (2.5..4.3) | 2.85 | 0.63 | 0.07 | 0.00 | 1.99 | 3.26 | 7 | 44.1 | 1163/1376 | 296 |
| 281-f1 | all | 2.80 (2.3..3.4) | 2.60 | 0.60 | 0.10 | - | 1.55 | 3.22 | 4 | (not printed) | 1163/1376 | 290 |

vex-api verdict thread-seconds (medians; signature / globals / manifest decode / case collisions /
ignored children / rehash / **externals**):

| | api | api-first | all |
|---|---|---|---|
| before-f3 | 0.1 / 0.3 / 0 / 0.1 / 3.0 / 1.8 / **0** | 0.1 / 0.3 / 0 / 0.1 / 3.0 / 1.2 / **28.6** | 0.1 / 0.3 / 0 / 0 / 4.1 / 1.3 / **0** |
| fix1-f3 | 0.1 / 0.3 / 0 / 0.1 / 3.1 / 1.6 / **18.6** | 0.1 / 0.3 / 0 / 0.1 / 3.0 / 1.2 / **24.7** | 0.1 / 0.3 / 0 / 0 / 4.1 / 1.2 / **14.6** |
| after-f3 | 0.1 / 0.3 / 0 / 0 / 3.0 / 1.6 / **17.6** | 0.1 / 0.3 / 0 / 0.1 / 3.0 / 1.5 / **27.0** | 0.1 / 0.3 / 0 / 0 / 3.7 / 1.6 / **21.3** |
| before-f1 | 0.1 / 0.3 / 0.4 / 0 / 1.6 / 0.4 / **17.3** | 0.1 / 0.3 / 0.3 / 0 / 1.4 / 0.4 / **24.6** | 0.1 / 0.2 / 0.3 / 0 / 1.6 / 0.4 / **16.7** |
| after-f1 | 0.1 / 0.3 / 0.3 / 0 / 1.2 / 0.9 / **17.9** | 0.1 / 0.3 / 0.3 / 0 / 1.6 / 0.6 / **26.6** | 0.1 / 0.2 / 0.3 / 0 / 1.3 / 0.8 / **20.2** |
| 281-f1 | 0.1 / 0.3 / 0.3 / 0 / 1.5 / 0.4 / **18.8** | 0.1 / 0.2 / 0.3 / 0 / 1.2 / 0.8 / **27.7** | 0.1 / 0.3 / 0.4 / 0 / 1.5 / 1.1 / **15.1** |

## What each fix found and did

**1. "load the verdict objects" (1.46 s -> 0.03 s, 1.4 s of CPU per format-3 plan).** Profiled in a
release build with timers around each step of `preload_objects`: for 1,156 candidates (1.27 MB of
statements) `decode_record` took 1 ms, the `Statement` parse 2-4 ms, `from_value` to
`VciPredicateV2` 0-2 ms, `Descriptor::shape_id` 0-2 ms, `issued_hint` 0 ms, `note_state_objects` (one
`columns` request) 15-22 ms, and `ObjectLoader::load` 1.43-1.52 s, of which `get_objects` was 3 ms.
The 1.4 ms per candidate was not the candidate at all: `load` passed `insert` every `(kind, id)` of
the candidate-ordered list (3 x 1,156 = 3,468 entries for 5 distinct objects), and `insert` hashed
and decoded the bytes before checking whether the id was already loaded, so the 125 KB shape of the
973-unit run was decoded 973 times (and the 185-unit run's 30 KB shape 185 times), ~1 ms each
(`profile-inserts.txt`). The fix (commit `eaa13b3`): `insert` returns before hashing for an id
already loaded; `load` decodes each `(kind, id)` at its first place only (the cap's
candidate-priority order is unchanged: it is decided at the first place, and a repeat of the same
bytes under the same kind decodes the same and meets a cap that only grows). Ids are still only
used to fetch; every object is still checked against its BLAKE3 id and every statement still parsed
and checked in `Verifier::check`. The candidate decode was left as it is (8 ms serial: not worth a
second copy of the parsed statements or the pool).

Wall effect: **first plan 4.66 -> 2.98 s (-1.7 s)**; steady state (flag set) 2.77 -> 2.61 s only,
because the 1.46 s used to overlap the Rails boot that the flag starts at ~+0.15 s: the verdicts now
reach the externals check sooner and wait for the boot instead (externals 0 -> 17.6-18.6
thread-s). CPU user time drops 3.96 -> 2.57 s on every format-3 plan either way, which on a
4-CPU runner is wall.

**2. The Rails boot probe.** RESULTS.md's premise ("starts on the first externals check") holds only
for a store's first plan. Since 2.7.26, `probe_project` reads the store flag
`plan:natives:<project>` (set by any plan that compared native libraries) and, when set, starts the
boot at once, beside the light probe; the measured namespaces had the flag, since `measure.sh`
emptied only the memo tables. What delayed that start in RESULTS.md's runs (light probe at +0.15 s,
boot at +0.7-0.9 s, then +1.4 s) was the flag read: the store's first connection, which ran vex's
`[store] token_command` (see caveats), 0.56-0.72 s. With a placeholder token the flag read is
4 ms and the boot starts at +0.16 s together with the light probe (`tl-flag-after.err`).

Commit `a397027`: (a) the flag is read on a scoped thread of its own, so the listing no longer
waits for the store's first answer (a token command, a TLS handshake to Turso); (b) a plan without
the flag starts the boot after the round's verdict objects load, before the verdicts, when a read
format-3 candidate of the Rails project names a tables object listing a `native:` external
(`start_native_boots`); format 1 keeps natives in manifests the verdicts load, so it still boots at
the first check; (c) a boot no probe took is **killed and reaped** when the adapter is dropped at the
end of the plan (`StartedProbe`'s `Drop`). Killed, not awaited: awaiting would hold the plan's exit
for the rest of a boot nobody reads (2-8 s); left alone (as before) it outlived vci: a flagged plan
whose candidates all failed before externals (`--base-ref HEAD~1`, signer check) exited at +5.1 s
with the boot still running until +9.6 s (it then failed, its run directory removed under it); with
fix 1 alone the same plan exits at 1.2 s leaving 1 orphaned boot, with fix 2 at 1.0 s leaving none.
The result is the same boot result through the same `natives()` OnceLock;
`rails_plan_boots_the_application_once` (one boot) and
`rails_native_libraries_boot_the_application_only_when_attested` (no boot when nothing records a
native library: why an unconditional start at resolve time is not allowed) pass.

Wall effect of fix 2 here: none measurable (after-f3 vs fix1-f3: 2.60 vs 2.61 s steady, 3.16 vs
2.98 s first plan, inside the 2.3-8.5 s spread). After fix 1 the first externals check comes ~0.1 s
after the verdicts start, so (b) moves the first plan's boot start by ~0.05-0.1 s (+1.21 s -> +1.25
s in two timelines, noise); (a) matters only where the flag read is slow (a token command, Turso),
not on loopback.

## Where the time goes now

A vex-api plan on this machine is now the Rails boot: the boot starts at +0.15 s (flag) and takes
1.7-4.1 s (2.2 s typical, `tl-*.err`), and the plan ends ~0.2-0.3 s after it; the verdict threads
spend 17-19 thread-s (steady) or 25-28 (first plan) waiting in `natives()` on both formats and on
2.8.1. Everything else of a format-3 plan is ~1.1 s of CPU-bound work on 14 CPUs (resolve 0.5-0.6
s concurrent with the boot, fetch 0.05 s, objects 0.03 s, verdicts' own work ~5 thread-s). What
would take the boot off the critical path is not starting it earlier (it already starts with the
toolchain resolve) but making the verdicts not block on it (check every candidate up to externals,
then compare the natives once the boot is in), worth ~0.1-0.3 s here, or not booting at all (the
natives the boot reports, cached per toolchain + Gemfile.lock + bundle digest).

## Caveats

- **vex's `[store] token_command` ran in RESULTS.md's runs and in my first ~10 exploratory plans
  here.** With `VCI_STORE_URL` set and `VCI_STORE_TOKEN` unset, vci runs `[store] token_command`
  (`com secrets get vci-store-token --org vex`) at the first connection (conn.rs: "never run when
  either of the others is there"); `com` is on `PATH.txt`'s PATH. Confirmed with a shim `com` that
  logs and exits 1 (it logged `secrets get vci-store-token ...`, and the plan warned that the
  token_command exited 1 and could not read the store; that log was then cleared). Its output went
  only into the Authorization header of loopback requests to the local sqld (no auth), was never
  printed, and nothing went to Turso; but `com` itself fetched the secret over the network on every
  plan (~0.5-0.7 s, which RESULTS.md's walls include, delaying the flag read and so the boot start).
  Every run in this file instead uses `VCI_STORE_URL=http://127.0.0.1:18181?authToken=placeholder-not-a-credential`
  (a dummy string; with a URL token the command is never run) and has the logging/exit-1 `com` shim
  first on PATH (`comshim/log` was never written again after the switch: no call). So this file's walls are 0.5-1.5 s
  lower than RESULTS.md's and are not comparable with them; compare within this file.
- The `api` rows were re-taken in a second batch (09:0x UTC) after a first batch whose `api-first`
  runs emptied every namespace's flags, which made `before-f3 api` rounds 2-7 first plans
  (`runs2-api-contaminated/`, kept, not used); the `all` and `api-first` rows are from the first
  batch. Another session's processes (vex-roder, a puma) ran on the host throughout.
- One candidate per unit, every one skips (as in RESULTS.md): rounds 2-3 and state objects are not
  exercised; the cap is never reached (188-210 KB of verdict objects).
- The probe-left-after-exit count in `runs2/*.time` is 0 everywhere, as every matrix plan used its
  boot; the orphan case is shown by the `--base-ref HEAD~1` plans above (`orphan-*.err`).

## Rebuilding

Everything above can be rebuilt from the inputs of [../../README.md](../../README.md) (`MEAS_ROOT`: `wr/pairs.json`,
the local copy of the production `manifests` table in `wr/sqld/data.sqld/dbs/default/`, `meas-v2/plan/PATH.txt`)
and a vex clone (`VEX_GIT`, holding `5eb73122`):

```sh
MEAS_ROOT=... VEX_GIT=... ./setup2.sh up WORK 18193      # copies, a fresh 0600 key, the checkout and its signer
                                                       # commit, sqld, config.json (mkconfig.py with that commit
                                                       # and tree), the harness's records, the natives flags
MEAS_ROOT=... ./measure2.sh WORK WORK/runs 7             # never overwrites a run; VARIANTS / CONFIGS narrow it
python3 -I parse2.py WORK/runs WORK/results.json         # never overwrites RESULTS
MEAS_ROOT=... VEX_GIT=... ./setup2.sh down WORK          # sqld stopped, checkout, key and copies removed
```

`setup2.sh` was run end to end on 30 October after the review (port 18193, a new key and signer commit): the
harness recomputed 904 of 904 signed roots, the warm-up plans listed 1164/1375 (format 3) and 1163/1376 (format
1) skip/run as above and set `plan:natives:vex-api` in both namespaces, and one round of `after-f3` and `281-f1`
gave 2.69 / 2.44 s (`api`) and 3.10 / 3.01 s (`api-first`), inside this table's spreads. `mkconfig.py` without
options still writes 28 October's `config.json` (commit `47bb7b8f`, tree `42505257`) and with `--commit d73a75f2...
--tree 8c73b914...` this run's `config2.json`, identical to the ones used. `measure2.sh` warms a namespace up again
(one unrecorded plan) before an `api` or `all` run whose flag is missing, so its round 1 on a fresh store is not a
first plan; an `api-first` run sets the flag again itself, since its verdicts compare libvips.

## After the review of these fixes

Three changes followed on store-v2, none of which moves this table's numbers (the matrix's plans compare
libvips and exit normally):

- The boot started ahead of time now has a stdin pipe vci holds (`VCI_RAILS_PROBE_PIPE`); when vci ends without
  dropping the adapter (a SIGTERM or SIGKILL, which run no destructor), the collector removes the boot's run
  directory and ends it. Before, a `kill -TERM` of `vci plan` while the boot ran left the boot running with parent
  pid 1 and its `vci-rails-*` directory behind (`e2e_rails.rs`: `rails_plan_boot_ends_with_a_signalled_vci`).
- A plan whose hinted boot no verdict read (every candidate failed before the externals check, so the natives
  flag stays unset) sets `plan:natives-hint-unused:<project>`, and the plans after it on that store boot at their
  first externals check as before 2.9: one unused boot per store instead of one per plan
  (`rails_plan_pays_for_an_unused_boot_hint_once`: boots per plan 1, 0, 0, where they were 1, 1, 1). The flag is
  read on the probe thread only when the natives flag is not set, from the same flags read on libSQL and
  PostgreSQL.
- `ObjectLoader::load` decodes each `(kind, id)` once and keeps that result again at every later place, with the
  cap checked there, so what it keeps (objects, bytes, counts, and the reason of an id's last place, with
  `past_cap`) is what an insert at every place keeps (`a_round_keeps_what_an_insert_at_every_place_keeps`, every
  round of three places over three ids and three kinds from four caps); fix 1 alone kept the reason of the id's
  last distinct kind at its first place, which could report a decode failure where the cap was the reason.

