# The plan side at vex scale: store-v2 (format 3) against vci 2.8.1 (format 1)

Measured 2026-10-29 03:46-03:52 UTC on an Apple M3 Max (14 CPUs, 36 GB), macOS, against a local
sqld 0.24.32 on 127.0.0.1:18181. Everything here is in
`docs/design/measure/sqld/plan/` (the scripts, `results.json` and this file; the per-run files stayed on the measurement host): `measure.sh` (the runs), `parse.py` (the table), `results.json`
(every run, parsed), `runs/` (each run's plan JSON, stderr with `VCI_TIMING=1`, `/usr/bin/time -l`),
`harness/meas_plan_v2.rs` (the records' writer), `mkconfig.py` + `config.json` (its configuration),
`harness-out-3c.json` / `harness-out-1c.json` (what it wrote), `plan0*.json/.err` to `plan3.*` (the
exploratory plans that led to the harness's overrides), `build*.log`, `PATH.txt`.

## The table (medians over 7 runs each; wall = the whole `vci plan` process)

| binary / records | projects planned | wall s median (min..max) | plan total | resolve toolchain (Ruby probe) | fetch values | load verdict objects | verdicts | store requests | store MB | skip / run | RSS MB |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **store-v2 (release) on format 3** | vex-api | **4.79** (3.1..11.4) | 4.70 | 0.97 | 0.07 | **1.61** | 0.84 | 14 | **2.9** | **1156** / 905 | 192 |
| store-v2 (release) on format 1 | vex-api | 5.27 (3.4..6.1) | 5.18 | 1.03 | 0.10 | 0.00 | 2.64 | 12 | 43.3 | 1155 / 906 | 283 |
| **vci 2.8.1 on format 1** | vex-api | **4.29** (3.2..10.2) | 4.04 | 0.92 | 0.15 | - | 2.73 | 4 | (43 MB, not printed by 2.8.1) | 1155 / 906 | 280 |
| vci 2.8.1 on format 3 (fail-open) | vex-api | 1.25 (1.0..2.2) | 1.18 | 0.84 | 0.07 | - | 0.07 | 4 | 2.6 | **0** / 2061 | 53 |
| store-v2 (release) on format 3 | vex-api, vex-web, rust, vex-roder | 3.84 (3.3..7.9) | 3.78 | 0.66 | 0.06 | 1.52 | 1.19 | 14 | 3.3 | 1164 / 1375 | 191 |
| store-v2 (release) on format 1 | the four | 4.79 (3.1..8.0) | 4.73 | 0.98 | 0.17 | 0.00 | 3.03 | 12 | 44.2 | 1163 / 1376 | 291 |
| vci 2.8.1 on format 1 | the four | 5.07 (3.2..9.1) | 4.97 | 0.94 | 0.14 | - | 2.78 | 4 | (44 MB) | 1163 / 1376 | 287 |
| vci 2.8.1 on format 3 (fail-open) | the four | 1.40 (1.1..8.4) | 1.34 | 0.98 | 0.08 | - | 0.07 | 4 | 2.7 | 0 / 2539 | 69 |

Columns are the `vci: timing:` lines: `fetch values` = "fetch the stored values the plan reads"
(the listing plus the prefetch of every candidate value), `load verdict objects` = "load the verdict
objects" (format 3 only: the hdr/tables/shape objects, and the decode of every candidate's frame
and statement to find their ids), `verdicts` = "verdicts (rehash inputs, check candidates)". Store
MB is what the libSQL store printed it received (2.8.1 prints no bytes; its format-1 reads are the
same 43-44 MB that store-v2's format-1 path prints). skip/run are the plan JSON's counts.

The verdict thread-seconds (`vex-api: verdicts:` line, medians): store-v2 on format 3: signature
0.2, globals 0.4, case collisions 0.1, ignored children 4.0, rehash 2.8, externals 16.2 (the
`natives` wait, below); store-v2 on format 1: signature 0.1, globals 0.3, manifest decode 0.4,
ignored children 1.8, rehash 1.4, externals 32.6; 2.8.1 on format 1: signature 0.2, globals 0.4,
manifest decode 0.5, ignored children 1.3, rehash 1.5, externals 32.4. The debug build of store-v2
(`target-v2/debug/vci`, `plan2.err`) takes 28.7 s on format 3 (load verdict objects 14.1 s,
verdicts 10.6 s): the per-candidate decode is 10x slower unoptimized, so the release build is what
the table compares with the release 2.8.1 at `/opt/homebrew/bin/vci`.

**What the local sqld removes.** Every store request here is a loopback HTTP round trip to a
sqld on the same machine (0.02-0.17 s for the listing and prefetch, 0.00 s for the objects); in
production the same requests go to Turso in eu-west-1 from the runners: `prodlogs/rails.json`
(164 Rails jobs of 27 Oct, 2.8.1, plan 1 median): listing + prefetch of 643 values 1.31 s median,
20.9 s max; "fetch the stored values" 5.46 s median, 32 s max; the candidates' reads 1.94 s median
(976 values), 17.4 s max; the memo write 0.81 s median, 30 s max; plan total 13.12 s median,
74.3 s max. To put the network back: format 3 moves 2.9 MB in 14 requests (list 1, prefetch 12
of ~0.25 MB, objects 1 of 0.3 MB) where format 1 moves 43 MB in 4 (2.8.1) or 12 (store-v2)
requests, so with ~30 ms RTT and the production throughput implied by 35 MB in 5.5 s
(~6-7 MB/s), the format-3 fetch is ~0.5-0.9 s of network against the 5.5 s median and 20-30 s
tails of today (the tails are the 6-8 MB responses that time out; a 0.25 MB request has no such
tail). Nothing else in the plan talks to the store except the memo write (unchanged, one
statement). So the local figure plus ~1 s of network is the expectation for format 3 on Turso:
**~5-6 s median for a vex-api plan**, against 13.1 s today, with the 20-30 s stalls gone. That is
inside the design's expected range (section 3 said ~8-10 s, the task's brief 5-9 s), and the
reason it is not lower is that the plan's remaining time is not the store at all (next section).

## Where the time goes now (and what the design did not count)

With the store out of the way, a vex-api plan on this machine is:

1. **Ruby, twice.** "resolve toolchain and externals" (0.7-1.5 s: the light Rails probe, `ruby`
   with Bundler, no boot) runs concurrently with the listing; then, in the verdicts phase, the first
   candidate that reaches the externals check calls `Verifier::natives()`
   (`plan.rs:1549`, a `OnceLock`), which runs the adapter's `native_externals`, and for a Rails
   project that is **the booted application probe** (`rails.rs:2394-2401`: `self.probe(env)`),
   1.5-8 s depending on bootsnap's cache state. Every other verdict thread blocks on the lock
   meanwhile, which is what the "externals 16-40 thread-seconds" is: not CPU, the pool waiting.
   This is the whole of the run-to-run variance (verdicts 0.77 s to 7.82 s across the 7 runs,
   `runs/v2-f3-api-*.err`) and most of a warm plan's wall. It is unchanged from 2.8.1 (same
   waits there: externals 32 thread-s), so the design's "verdicts 0.81 s median" production figure
   is a plan where few candidates reached the externals check (most failed `inputs` earlier),
   while a plan whose candidates skip pays the booted probe once. The probe could start with the
   toolchain resolve instead of on first use; that is ~2-4 s of wall off every skipping plan,
   for both formats.
2. **`load the verdict objects`: 1.5-1.6 s on format 3, a new fixed cost.** The store side of it
   is 0.00 s (5-28 objects, 0.3-0.6 MB, 2 requests; the `columns` query for 1,156 keys answers in
   0.05 s, `parse.py`'s probe), and it does not grow with the objects (5 objects: 1.61 s; 28
   objects: 1.52 s). It is `preload_objects` (`plan.rs:1141-1179`) decoding every candidate's
   frame and parsing its statement to `VciPredicateV2`, serially, ~1.4 ms per candidate, before the
   verdicts decode them again on the pool. Parallelizing or keeping the decoded statement would
   remove it; the design's section 3 did not count it ("reads ... a few hundred ms").
3. **Verdicts: 0.84 s wall on format 3 against 2.7 s on format 1** (same machine, same
   candidates): the per-candidate inputs check through the shape (`rehash 2.8` thread-s for
   1,156 candidates of ~500 entries, 581,180 observed entries in all) plus the one-per-run
   `ignored children` work (4.0 thread-s: `git check-ignore` of the listed directories' children,
   more than format 1's 1.8 because a shape group is asked about once per `(shape, group)` and
   the own entries per candidate), signature 0.2 (1,156 SSHSIG checks: not a cost, as the design
   said), globals 0.4. Format 1 spends its verdicts on manifest decode (0.4-0.5 thread-s) and the
   same rehash, but the wall is dominated by the natives wait in both.
4. RSS: 192 MB on format 3 against 280-291 MB on format 1 (the 43 MB of envelopes and manifests,
   base64 and decoded).

**2.8.1 on a format-3 namespace fails open as the design says** (section 5): it lists the keys
with its own parser, reads every value (1,156 values, 2.6 MB, 4 requests), fails each candidate's
`envelope` check ("envelope JSON"), reports every unit as `no valid attestation (1 candidates; best
failed envelope: envelope JSON)` and runs everything, in 1.25 s. No error, no crash; the namespace
(schema version 1 with the format-3 columns and the `objects` table, `vci_schema` row as the
design's migration window has it) reads fine. 2.8.1 on the format-1 namespace that store-v2's
backend created (same schema) plans normally: 1,155 skips, identical to store-v2's own format-1
path (one unit of the 1,156 fails `inputs: inputRoot` on both: the harness's format-1 encoding of
one unit's manifest does not round-trip its root; the format-3 record of the same unit skips).

## Method, exactly

**The checkout.** The 973-unit run attests vex commit `2cb18b86448f1a5d47490e33330b721398073236`
(and the sample's other runs `90ce3d34`, `3603e2ba`, `f3c0a5cc`, `b50b9ac1`, `14d59b4a`); none of
those six commits is in the local vex clone (pull-request heads that were never fetched; the
clone has `remote.vci-no-lazy-fetch.promisor=true`, so a plain `git cat-file` on them hangs on a
lazy fetch; `GIT_NO_LAZY_FETCH=1` makes it fail at once), and fetching them would be a network
download, so the checkout is `origin/master` as fetched, `5eb73122037c6d01da60551f3df9f716af599d1c`
(28 Oct 19:23 -0700, ~15 hours after the sample's runs), as a throwaway worktree
a throwaway vex worktree with one commit on top on a throwaway branch
(`47bb7b8f318f9bffe2c95b367e65a40be7ca187c`, tree `4250525740c7b5ab...`): the fresh ed25519 key
(`ssh-keygen -t ed25519`, kept 0600 under `meas-v2/key/`, deleted at the end) appended to
`.vci/allowed_signers` as `vci-meas-v2 namespaces="vci-attest" ...`. The plan runs with
`--base-ref HEAD` (vex's own docs run `vci plan --base-ref HEAD` locally; CI passes the base sha),
so trust and `[policy]` come from that commit: `platform = "any"`, `libraries = "any"` for
vex-api, `allow_superuser_mismatch = true`, `ignore_taints = ["*"]`, `max_ttl = "14d"`,
`rails_autoload_lookups = true`, the `[store]` table naming vex's Turso URL (overridden by
`VCI_STORE_URL=http://127.0.0.1:18181`, `VCI_STORE=libsql`, `VCI_STORE_NAMESPACE`, and
`VCI_STORE_TOKEN` unset, so `token_command` never runs and nothing touches Turso).

Since the records attest the tree the plan runs at, every unit's record says commit `47bb7b8f`,
tree `42505257`, so the candidates are "made on HEAD's tree" and the key hints carry that tree,
as a `vci run` at that commit would have written them. Units whose test file is not in the
checkout any more are listed by nobody (905 of the 2,061 vex-api files at HEAD have no record:
the sample covers 1,158 Rails units of 2,324; 2 of the sample's Rails files are gone at HEAD, so
1,156 candidates).

**The toolchain.** The plan's Rails probe fails on this machine when `ruby` resolves to the rbenv
shim (`ruby:load-path-outside-repository:.../rbenv.d/exec/gem-rehash`, the reason every unit got
in `plan0.json` and in the earlier `meas/plan1.json`), and `mise exec` did not put its Ruby first
on PATH here, so every plan runs with `PATH.txt`: mise's ruby 3.4.9 and node 26.12.1 first, the
rbenv and mise shims removed, `RUBYLIB`/`RUBYOPT` unset. vex-api's bundle is installed for that
Ruby (`bundle check` passes). The harness rewrites each statement's toolchain to what this machine
has: `os`/`arch` to `macos`/`aarch64`, `superuser` false, and per project the overrides
`mkconfig.py` builds from what the plan's `explain` reported against the attested values
(`plan1.err`, `plan2.err`): vex-api `rubyGems` = the attested list plus `aws-sdk-sns==1.121.0` and
`aws-sdk-sqs==1.122.0` (installed here, not attested); the two cargo projects `rust` =
`1.99.1 58cf8f9c... LLVM 23.1.3` (23.1.1 attested), `rustHost = aarch64-apple-darwin`, `rustCfg` =
`rustc --print cfg` here, sorted bytewise (the hdr encoder refuses an unsorted list). `ruby`,
`rails`, `bundler`, `rubyEngine`, `rubyTest`, `rubyDb`, `node` and `cargo` are equal on both sides
and were kept; `rubyLibs` is not compared under `libraries = "any"`. The global manifest is the
attested global path set (25 paths for Rails: mise files, `.ruby-version`, `Gemfile`,
`Gemfile.lock`, `Rakefile`, `bin/rails`, `test/test_helper.rb`...) observed at the checkout, with
the attested global externals and env (`NODE_OPTIONS` for node: without it the global root
differed, `plan1.err`); `envConfigDigest` was left as attested and the plan accepted it (the
`[env]` tables did not change between the sample's commit and master).

**The records.** `harness/meas_plan_v2.rs` (a test file placed in `crates/vci-cli/tests/` for the
run and removed afterwards; gated on `VCI_MEAS_CONFIG`) parses the 1,175 pairs, takes each unit's
own entries from its compact manifest and its base's entries from a local SQLite copy of the
production `manifests` table (`wr/sqld`'s data, copied to `meas-v2/proddb/`; 6 of the sample's 10
base roots are in it, including 4 of the 5 bases of the 973-unit run; the 4 missing bases, 82 Rails
units of the 973-run, the 185-run's two, and the rust run's one, are substituted by the largest
found base of the same project or adapter, so those units carry a realistic but not their own
shared set), and checks the reconstruction: **904 of the 904 units with their real base recompute
the signed input root from base + own entries** (`harness-out-*.json` `reconstruction_root_ok`),
which is the evidence that the sets are the attested ones. Each unit's full `(path, kind, exec)`
set (mean 495 entries; 581,180 in all) is then observed at the checkout through vci-core's
`CheckoutCache` with `InputManifest::observe` and `from_observed`, the plan's own code, with the
git-ignored children of listed directories computed as the plan's `IgnoredChildren` does
(`git check-ignore --stdin` per directory), so the signed root is the one the plan recomputes at
that tree; the attested externals and env hashes are kept (the policy sets the same env values).
Units are grouped into the sample's 9 runs (commit, issuedAt, project, adapter); per run,
`VciPredicate::hdr()`, `Run::build` (the shape with the bases as groups, the state, one tables
object per header group), `to_v2`, `sorted_compact_json`, `SshSigner::sign_payload` over the
statement bytes, `Frame::from_envelope`, `encode`, the listing columns as `run.rs::columns_for`
fills them, and the slot key `storage_key` copied from `ctx.rs` (over the resolved v1 view, waived
list sorted and distinct; the same key for both formats). Writes go through the store trait
(`LibsqlStore::open` on the selection `testkit::selection` builds for the URL and namespace): one
deferred batch per run, `put_objects` first, then `put` with columns and the key hint. Format 1 is
the same statements as v1 (`PREDICATE_TYPE`, `toolVersion` 2.8.1, `manifestRef` = the root), signed
with `sign_statement` into DSSE envelopes, the observed base manifests put under their roots and
each unit's manifest `to_compact_on` its base, as `run.rs` 2.8.1 stores them. Sizes written
(`harness-out-3c.json`, `harness-out-1c.json`): format 3, 1,175 records, 2.10 MB (1,784 B mean, 1,760 B p50, 3,385 B max: the rewritten gem and cfg
lists are longer than the sample's), 54 objects (18 hdr, 18 tables, 9 shapes, 9 states; 0.97 MB) (973-run: shape 125,053 B, state 284,937 B,
tables 19,387 B; as the design's section 3 measured); format 1: envelopes 24.9 MB, manifests 17.8
MB, bases 0.43 MB (36.7 KB per unit, the design's "today"). The format-3 namespace is `meas3c`,
the format-1 one `meas1c`, both created by store-v2's libSQL backend (schema version 1 with the
format-3 columns, `objects` and `gone` tables).

**The runs.** `measure.sh`: 4 configurations x 2 variants x 7 rounds, interleaved (round-robin, so
drift hits every configuration alike); before every run the memo tables of every namespace are
emptied (`DELETE FROM ..._memo` over Hrana), so every run is a "plan 1" with no memo of a previous
plan on that tree, as the production figure is; `VCI_TIMING=1`, `/usr/bin/time -l`, the plan JSON
kept. The `api` variant is `--project vex-api`, what a Rails job's `vci ci --partition I/2` plans
(production's plan 1 is that: one project, one partition's listing); `all` adds vex-web, rust and
vex-roder, every project the sample has units for. Note that one plan here reads 1,156 Rails
values where a production partition reads 643 median (half the files, each with ~1.9 candidates)
and 1,644 in the design's full-plan model with candidates from 4-59 runs: this namespace holds
exactly one record per unit from 9 runs (2 Rails runs, so 2 hdr/tables/shape sets for vex-api,
"2 distinct run(s)", 0.19 MB of verdict objects against the design's 1.35-1.9 MB at the production
spread of 45-59 runs: the objects' cost here is the floor, not the production figure; at 0.00 s for
0.6 MB on loopback and ~0.25 MB per request on Turso it stays small).

**What was and was not exercised.** Rails (vex-api): fully, through the real adapter: the Rails
probe listed the 2,061 test files at HEAD and resolved the toolchain, 1,156 candidates went
through signature, signer, statement, expiry, repo, toolchain (gems included), env-config, result,
dirty-tree, global-inputs, the inputs rehash of every entry against the checkout (1,156 rehashed),
externals (the bundle and the native libraries from the booted probe) and env, and **1,156 of 1,156
skip** on format 3 (1,155 on format 1). cargo (rust, vex-roder): the 5 units' candidates pass every
check and skip (cargo adapter, `Cargo.lock` as the externals source). node-test (vex-web): 12
records of 6 files in the sample (each attested in two runs; the later put takes the slot), all 6
listed at HEAD; 3 skip and 3 fail `externals` (`@tanstack/history
... not installed`): the checkout has no `node_modules` (installing them needs the network;
`pnpm install --offline` found the store incomplete, `pnpm-offline.log`), so the node externals
check cannot pass for the 3 units that record packages; the store side (records, objects,
read, decode, signature, statement, inputs) was exercised for all 6. The plan was never run with
the Rails tests, only the plan (`vci plan`), which is what a job's `vci ci` does before deciding
what to run; nothing was attested by running tests.

**Differences from the production situation that the reader should keep in mind:** (a) the store is
on loopback (above); (b) one candidate per unit instead of ~1.9 (fewer values to read, and the
candidate order's effect on fail-open rounds is not exercised: every candidate here skips, so
rounds 2-3 and the state objects for failure text never run: "0 state" objects loaded); (c) the
checkout is one commit later than the attested one and the records were re-observed at it, so the
inputs check passes by construction for every unit whose set is still observable: this measures
the cost of a plan where the files did not change, the skip case, which is the one the plan's
cost matters for; (d) macOS on an M3 Max with 14 CPUs against the runners' 4-8 x86 CPUs: the
thread-seconds (rehash 2.8, ignored children 4.0, the serial 1.6 s preload) translate to more wall
there; (e) the memo write is one statement in both and was not on Turso.

## Numbers against the design (STORE-V2 sections 0 and 3)

| | design (section 3) | measured here |
|---|---:|---:|
| record | 1,783 B mean, p50 1,760, max 2,707 | 1,784 B mean, p50 1,760, max 3,385 (`harness-out-3c.json`; the rewritten toolchain lists are longer) |
| 973-unit run: tables / shape / state | 19,387 / 123,264 / 285,128 B | 19,387 / 125,053 / 284,937 B (the shape 1.5% larger: 4 of 5 real bases, one substituted group) |
| plan reads | 2.93 MB of values for 1,644, 4.7-16 MB total | 2.6-2.7 MB for 1,156-1,167 values + 0.3-0.6 MB objects, 12 + 1 + 2 requests (prefetch chunks of ~0.25 MB) |
| plan reads today | 59.7 MB + bases | 43.3-44.2 MB in 4 (2.8.1) / 12 (store-v2) requests |
| signature checks | 0.3 thread-s | 0.2 thread-s for 1,156 |
| global-inputs once per hdr | ~11 hdr per plan | 1-11 hdr, globals 0.3-0.4 thread-s (format 1 also 0.3-0.4 here: the 25-entry global set is cheap when the checkout cache is warm) |
| expected plan 1 | ~8-10 s median (section 3), 5-9 s (task) | 4.8 s median local (3.1 s best) + ~1 s of Turso round trips ≈ 5-6 s |
| what the design did not count | | the booted Rails probe on first externals check (1.5-8 s, both formats), the serial candidate decode of `preload_objects` (1.6 s, format 3) |

Compared with 2.8.1 on the same machine and the same loopback store, format 3 is not faster in
wall (4.79 s against 4.29 s median, both within the probe's noise band of 3-11 s) because the
loopback store makes the 43 MB of format 1 cost 0.15 s; what format 3 removes is the 40 MB per
plan (15x), 90-100 MB of RSS, and 1.9 s of verdict wall (0.84 against 2.73 s), and what it adds
is the 1.6 s serial preload. On Turso, where the 43 MB is the 5.5 s median and the 20-30 s tails
of today, the 15x matters and the 1.6 s is the next thing to remove.

## Caveats on the runs themselves

- Another session's measurement (`meas-v2/writes/`, `meas-v2/sqld-data/`: the write side, with its
  own sqld) ran on this host during the same window; the interleaved rounds spread any contention
  over every configuration alike, but the absolute walls carry it, which is one reason to read the
  minima (3.1-3.4 s for store-v2 on format 3) beside the medians.
- The local sqld (0.24.32) exited silently twice (once between rounds, once after the last run;
  `sqld.log`, `sqld-1.log` show no error); the first time the loop was restarted and all 7 rounds
  were taken against the restarted server with the same data; no run in `runs/` was taken against
  a dead server (every `.err` shows the listing and the prefetch answered).
- The debug build (`target-v2/debug/vci`) was used for the exploratory plans `plan0*`-`plan2`; the
  table is the release build.
- The harness file was removed from the worktree after the runs (nothing committed; the branch
  store-v2 is as it was); the copy is `harness/meas_plan_v2.rs`.
