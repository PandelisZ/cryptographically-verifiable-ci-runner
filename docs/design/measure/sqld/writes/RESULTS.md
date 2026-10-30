# The write side at vex scale on a local sqld: store format 3 against format 1

Measured 29 October 2026 (03:57-04:28 UTC, tag `m3`) on a 14-CPU, 36 GiB Mac (macOS 27.0.1), against
`/opt/homebrew/bin/sqld` 0.24.32 on 127.0.0.1 with a throwaway data directory, every writer process behind a
counting TCP proxy of its own. No network store was touched; no token was set.

## What was run

- **Units:** the 973 units of the largest run in `wr/pairs.json` (commit 2cb18b86, vex-api, rails, 28 Oct 04:11 UTC),
  extracted in file order to `pairs-run.json` (`mkpairs.py`). Writer process `i` takes 800 of them from offset
  `i x 390` (wrapping), named `w<i>/<test_id>`, so three processes write 2,400 distinct units into one namespace,
  as vex's three partitions do.
- **store-v2, format 3** (`f3`): `crates/vci-store-libsql/examples/replay3.rs` (committed with these files as a measurement tool;
  measured at 69b70f2), built `--release` into `target-v2`. It builds the run's objects
  and records exactly as `an_800_unit_partition_is_a_few_transactions` in `tests/format3.rs` does (`Run::build`,
  `to_v2`, the frame with the real envelope's signature and the descriptor, the listing columns), then drives the
  store's batch as `run.rs` does: `put_objects` first, then one `put` with columns per unit, `finish_partial`.
- **store-v2, format 1** (`f1`): the same binary with `VCI_STORE_RECORD_FORMAT=1`, writing what the CLI writes under
  that setting: `put_manifest` (the compact manifest of the pair, as the fx3 replays did) then `put` of the real
  envelope, per unit, in the batch. The 9 shared base manifests of a run (~450 KB) are not written, as in fx3.
- **vci 2.8.1 store** (`h281`): `fx3/bin/replay-head batch`, the libSQL store of the 2.8.1 tree in `fx3/src`
  (version 2.8.1 with the turso-reads short-transaction change: `TX_BYTES` 1 MiB, `FLUSH_BYTES` 4 MiB, as store-v2
  has), pointed at the local sqld. The released 2.8.1 binary's write path is `vci run` only and cannot be driven from
  `pairs.json`; the design's "5 batches of 6.6-8 MiB" is that binary, and is not reproduced here.
- **The second run** (`supersede`, f3 and f1): the same 800 units per process at a "moved-on" commit: every 50th
  file entry's hash changed (format 3's state object differs, the shape does not; format 1's manifest root and the
  envelope's `manifestRef` are renamed), new storage keys. The process does what `run.rs` does for a run: one
  `list_units` of its 800 units, `columns`, `get_objects` of the hdr ids (format 3), `read_values` of the old
  records it confirms, then in the batch the new put and `remove` of the old record per unit, then the orphan pass
  (`remove_objects` of the ids the removed records named and `prune_state_objects(2 days)`; or `orphan_manifests`
  + `remove_manifests`). The first run's objects and manifests were backdated by 7,200 s in SQL first, since both
  keep an hour of grace and a real moved-on commit comes later than that.
- **Counts:** transactions, literal bytes and SQL bytes from `LibsqlStore::written()`; TCP bytes from the proxy;
  rows and bytes at rest by `SELECT count(*), sum(length(...))` over every table of the namespace (`atrest.py`, Hrana
  pipeline, no token); process wall time around the whole process (loading the 37 MB pairs file included).
- Everything: `run.sh` (one configuration), `matrix.sh` / `matrix2.sh` (the matrix), `summarize.py` ->
  `results.json` + `tables.md`, raw files in `out/` (`m3-<cfg>-<P>-<rep><attempt>-<phase>-<i>.{json,err}`,
  `-proxy.json`, `-wall.json`, `-atrest.json`, `-backdate.json`, `matrix-m3.log`, `matrix2-m3.log`, `stalls.log`,
  `sqld-restarts.log`). `m1` and `m2` in `out/` are earlier passes under which the harness was still being fixed
  (a wrong sqld PID, no wait after a restart); their clean rows agree with `m3` and are not used below.

## Results against STORE-V2 section 3 (one 800-unit partition, one writer)

| | STORE-V2 section 3 | measured, format 3 (store-v2) | measured, format 1 (store-v2, `VCI_STORE_RECORD_FORMAT=1`) | measured, 2.8.1 store (fx3 replay-head) |
|---|---:|---:|---:|---:|
| record | 1,783 B (p50 1,760) | 1,774 B mean (1,419,469 B / 800) | 21,774 B envelope + 13,419 B manifest | same bytes |
| per-run objects | hdr 4,489; tables 19,387; shape 123,264; state 285,128 B (973 units) | hdr 5,988; tables 24,900; shape 122,304; state 286,076 B as base64 at rest (329,446 B raw in all, 800 units) | - | - |
| on the libSQL wire | **2.43 MB** (1.75 MB without state) | **2.59 MB** of SQL (1.87 MB of literals; 2.68 MB on TCP) | 30.24 MB of SQL (28.18 MB of literals; 31.21 MB on TCP) | 31.03 MB on TCP |
| transactions | **2-3 of <= 1 MiB**, 2 flushes, 2,724 writes | **2**, 1 flush (804 writes < `FLUSH_WRITES`), longest 0.07-0.09 s here | 33, 7 flushes | 33, 7 flushes (the released 2.8.1: 5 batches of 6.6-8 MiB) |
| at rest | **2.18 MB, 804 rows** | **2.46 MB, 806 rows** (attestations 2.02 MB = 2,529 B/row with key and columns; objects 0.44 MB base64; 2 log rows) | 28.86 MB, 3,233 rows (800 + 800 manifests + 1,633 log) | 28.82 MB, 3,233 rows |
| "today" | 29.5 MB, 1,609 rows, 5 batches, 27 s median | | | |
| ratio today / format 3 | 13.5x wire, 13.5x at rest | 11.7x wire (30.24 / 2.59), 11.7x at rest (28.86 / 2.46), 16x transactions (33 / 2) | | |
| store write time, local | | 0.15 s (0.14-0.15) | 0.86 s (0.76-0.93) | 0.69 s (0.65-0.73) |
| units lost | none | 0 of 800 in 3 of 3 | 0 in 3 of 3 | 0 in 3 of 3 |

The measured wire figure is 6.6% above the design's 2.43 MB and the at-rest figure 13% above 2.18 MB: the design
counted the record and object bytes; the store sends and keeps the objects as base64 (+33% on 329 KB) and each row
carries its key and nine listing columns (~750 B over the 1,774 B record). Both ratios come out at 11.7x against
format 1 written through the same store (the design's 13.5x counts 9 base manifests per run that neither replay
writes). The transaction count is 2 rather than 3 because 804 writes are one flush, and the 1.87 MB of literals fit two
1 MiB transactions.

## Three writers at once (vex's partitions)

| | format 3 (store-v2) | format 1 (store-v2) | 2.8.1 store |
|---|---|---|---|
| clean attempts | **4 of 4**: 12 of 12 processes stored 800 of 800; 2-3 transactions each, 2.59-2.73 MB of SQL, store write 0.17-0.39 s, process wall 0.65-1.07 s, 0 resends, 4-9 requests; 7.60 MB and 2,417 rows at rest for 2,400 units. In 1 of the 4, sqld's lock stalled after the writers were done (every unit stored; the second run could not follow and the attempt was run again). | **0 of 13** | **0 of 12** |
| what a stalled attempt looks like | | each process: 1-10 transactions committed (one to two 4 MiB flushes), then a request that sqld never answers (30 s timeout, sent again, 30 s again: 60-91 s of wall), 2-129 units of that flush reported not stored, and the process stops; 140-698 of the 2,400 records in the namespace | the same: 2-18 transactions, 171-1,038 of 2,400 records, 60-91 s per process |

`sqld` 0.24.32's write lock stalls for good under concurrent writers (documented in `docs/STORE-BACKENDS.md` section
21, item 17: a stress test stalled it in every run with four writers; three stalled it when readers held snapshots).
Here three writers of 33 one-MiB transactions each (the format-1 shape, ~100 commits in all) stalled it in 25 of 25
attempts, within the first flush; three writers of 2-3 transactions each (format 3, 6-9 commits in all) stalled it
once in 4 attempts, and then only after every unit was stored. So the three-writer "today" case has no clean local
number: on Turso the same replay (fx3, 28 Oct, `fx3/r5.log`, three 800-unit processes) took 155-181 s per process
with 23-26 transactions and a retry each under zstd, none lost, and under raw values timed out at 188 s with 11-14
transactions and 660-690 of 800 units lost per process. The server restarts between attempts are in
`sqld-restarts.log` (the harness probes it with a 5 s write before each phase and starts a fresh one when the probe
hangs).

## The second run at a moved-on commit: supersession and the orphan pass

| | format 3, 1 writer | format 3, 3 writers (per process) | format 1, 1 writer |
|---|---|---|---|
| finding what to supersede (listing, columns, hdr objects, old values) | 0.06 s, 15 requests, 1.42 MB of old values read (design: ~2.7 MB incl. the listing) | 0.06-0.17 s, 15 requests, 1.42-1.45 MB | 0.09 s, 13 requests, **17.42 MB** of old envelopes read |
| the batch: 800 puts + 800 removals | 0.14 s, 2 transactions, 3.05 MB of SQL (3.51 MB TCP), 800 of 800 removed | 0.18-0.71 s, 2-3 transactions, 3.05-3.20 MB, 800 of 800 removed | 0.96 s, 33 transactions, 31.31 MB of SQL (32.77 MB TCP), 800 of 800 removed; the batch itself removed the 800 superseded manifests in the same transactions (2.8.2's `superseded_manifests`) |
| the orphan pass | 4 ms, 5 requests: 1 object removed of the 4 the old records named (the old state object; hdr, tables and shape are shared with the new run, since the shape is unchanged at a moved-on commit); `prune_state_objects` 0 | 3-181 ms, 5 requests, 1 object per process | 20 ms, 4 requests: `orphan_manifests` found the 800 old roots, `remove_manifests` removed 0 (already gone) |
| at rest after | 2.76 MB, 2,409 rows: 800 records, 4 objects, 804 log rows, 801 `gone` rows | 8.51 MB, 7,228 rows for 2,400 units | 29.40 MB, 7,266 rows: 800 records, 800 manifests, 4,866 log rows, 800 `gone` rows |
| units lost | 0 (3 of 3) | 0 (3 of 3) | 0 (3 of 3) |

The design's "a dead run leaves 4 objects, collected by `vci run`'s orphan pass" holds when nothing of the run
survives; here the next run of the same units shares hdr, tables and shape, so one object (the state, 286 KB) is
what the pass collects per superseded run, as section 1.3 intends (the state is the only per-commit object).

## Caveats

- Local loopback and a 14-CPU host: the times are the store's own cost without the link or Turso's lock waits
  (compare `fx3/r5.log`: 155-188 s per 800-unit process on Turso); transactions, bytes and rows carry over.
- The records are built by the example, not by `vci run` (`run.rs`'s signing, observation and verdicts are not in
  the times); the format-3 statements are signed with the real envelope's signature frame over a statement the
  signature does not cover, which no write-path check reads. The second run's format-1 envelopes carry a renamed
  `manifestRef` for the same reason.
- `h281` is 2.8.1's store with the turso-reads short transactions, not the released 2.8.1 binary (5 batches of
  6.6-8 MiB); its supersession path (per-unit `remove`, then `drop_orphan_manifests`) was not driven, which would need
  a binary built against 2.8.1's crates. Format 1 through store-v2 is the stand-in: the same envelopes and manifests,
  the same `put_manifest` + `put`, the same per-unit `remove`.
- Format 1 writes no base manifests (9 x ~50 KB per run), so its "today" figures are ~0.45 MB short per run.
- The hour of grace on objects and manifests was skipped by backdating `put_at` in SQL.
- The units of writer 1 and 2 overlap writer 0's by test id (offsets 390 and 780 of 973, under distinct names), so
  the three per-run shape and state objects are more alike than three real partitions' would be; each process's own
  bytes are what one partition writes.

## The generated tables (summarize.py m3; medians with min-max over clean repetitions x processes)

### The first run (the namespace empty before it)

Per writer process, median (min-max) over the clean repetitions x processes; at rest: the namespace after all P processes wrote, median over repetitions.

| store | writers | runs clean+stalled | store write s | process wall s | transactions | flushes | longest tx s | SQL on the wire MB | TCP bytes to sqld MB | requests / resends | units lost | rows at rest | bytes at rest | attestations rows / MB | manifests rows / MB | objects rows / MB | log rows |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| store-v2, format 3 | 1 | 3+0 | 0.15 (0.14-0.15) | 0.60 (0.58-0.65) | 2 (2-2) | 1 (1-1) | 0.09 (0.07-0.09) | 2.59 (2.59-2.59) | 2.68 (2.68-2.68) | 6 (6-6) / 0 (0-0) | 0 (0-0) | 806 | 2.46 MB | 800 / 2.02 | 0 / 0.00 | 4 / 0.44 | 2 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 1 | 3+0 | 0.86 (0.76-0.93) | 1.23 (1.07-1.26) | 33 (33-33) | 7 (7-7) | 0.06 (0.04-0.10) | 30.24 (30.24-30.24) | 31.21 (31.21-31.21) | 37 (37-37) / 0 (0-0) | 0 (0-0) | 3233 | 28.86 MB | 800 / 17.82 | 800 / 10.85 | 0 / 0.00 | 1633 |
| vci 2.8.1 store (fx3 replay-head) | 1 | 3+0 | 0.69 (0.65-0.73) | 0.77 (0.72-0.80) | 33 (33-33) | 7 (7-7) | 0.04 (0.04-0.04) | - | 31.03 (31.03-31.03) | 38 (38-38) / 0 (0-0) | 0 (0-0) | 3233 | 28.82 MB | 800 / 17.78 | 800 / 10.85 | - / - | 1633 |
| store-v2, format 3 | 3 | 4+0 | 0.33 (0.17-0.39) | 0.85 (0.65-1.06) | 2 (2-3) | 1 (1-1) | 0.17 (0.10-0.27) | 2.68 (2.59-2.73) | 2.76 (2.68-2.81) | 6 (4-9) / 0 (0-0) | 0 (0-0) | 2417 | 7.60 MB | 2400 / 6.12 | 0 / 0.00 | 10 / 1.49 | 7 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | (no clean run) |
| vci 2.8.1 store (fx3 replay-head) | 3 | (no clean run) |

### The second run at a moved-on commit (the same 800 units per process, files changed: supersession and the orphan pass)

| store | writers | runs | find: s | find: requests | find: old values read MB | store write s (puts + removals) | transactions | SQL on the wire MB | TCP bytes to sqld MB | records removed | orphan pass s | orphan pass requests | orphan pass removed | units lost | rows at rest after | bytes at rest after | attestations rows | manifests rows | objects rows / MB | log rows | gone rows |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|---|--:|--:|--:|--:|--:|--:|--:|--:|
| store-v2, format 3 | 1 | 3 | 0.06 (0.06-0.07) | 15 (15-15) | 1.42 (1.42-1.42) | 0.14 (0.13-0.15) | 2 (2-2) | 3.05 (3.05-3.05) | 3.51 (3.51-3.51) | 800 (800-800) of 800 (800-800) | 0.004 (0.003-0.004) | 5 (5-5) | 1 (1-1) objects of 4 (4-4) named; state pruned 0 (0-0) | 0 (0-0) | 2409 | 2.76 MB | 800 | 0 | 4 / 0.45 | 804 | 801 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 1 | 3 | 0.09 (0.08-0.10) | 13 (13-13) | 17.42 (17.42-17.42) | 0.96 (0.90-1.29) | 33 (33-33) | 31.31 (31.31-31.31) | 32.77 (32.77-32.77) | 800 (800-800) of 800 (800-800) | 0.020 (0.016-0.022) | 4 (4-4) | 0 (0-0) manifests by the pass of 800 (800-800) found, 800 (800-800) roots | 0 (0-0) | 7266 | 29.40 MB | 800 | 800 | 0 / 0.00 | 4866 | 800 |
| store-v2, format 3 | 3 | 3 | 0.10 (0.06-0.17) | 15 (15-15) | 1.43 (1.42-1.45) | 0.50 (0.18-0.71) | 3 (2-3) | 3.14 (3.05-3.20) | 3.61 (3.51-3.66) | 800 (800-800) of 800 (800-800) | 0.012 (0.003-0.181) | 5 (5-5) | 1 (1-1) objects of 4 (4-4) named; state pruned 0 (0-0) | 0 (0-0) | 7228 | 8.51 MB | 2400 | 0 | 10 / 1.54 | 2415 | 2403 |

### Attempts under which sqld's write lock stalled (docs/STORE-BACKENDS.md section 21, item 17)

Per writer process of each stalled attempt: what the store got committed before it gave up. A stall 'after write' left every unit stored and only the second run could not follow.

| store | writers | attempt | phase | process | transactions committed | units lost in the flush that failed (the process then stopped) | longest request s | process wall s | TCP bytes to sqld MB | records in the namespace after (all processes, of P x 800) |
|---|--:|---|---|--:|--:|--:|--:|--:|--:|--:|
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1a | write | 0 | 2 | 69 | 30.05 | 60.59 | 4.55 | 140 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1a | write | 1 | 1 | 89 | 30.03 | 60.59 | 3.42 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1a | write | 2 | 2 | 45 | 30.04 | 60.59 | 4.43 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1b | write | 0 | 2 | 69 | 30.00 | 60.60 | 4.55 | 168 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1b | write | 1 | 2 | 61 | 30.01 | 60.60 | 4.59 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1b | write | 2 | 2 | 45 | 30.00 | 60.60 | 4.45 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1c | write | 0 | 8 | 36 | 30.02 | 61.56 | 12.62 | 634 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1c | write | 1 | 10 | 102 | 30.01 | 61.76 | 11.46 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1c | write | 2 | 9 | 126 | 30.01 | 61.88 | 12.41 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1d | write | 0 | 3 | 36 | 30.01 | 90.83 | 4.60 | 173 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1d | write | 1 | 1 | 89 | 30.01 | 60.91 | 3.42 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1d | write | 2 | 2 | 45 | 30.01 | 60.91 | 4.43 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1e | write | 0 | 10 | 129 | 30.02 | 61.55 | 11.54 | 698 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1e | write | 1 | 9 | 3 | 30.02 | 61.55 | 9.28 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1e | write | 2 | 10 | 95 | 30.01 | 61.55 | 12.45 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1f | write | 0 | 2 | 69 | 30.01 | 60.66 | 4.55 | 168 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1f | write | 1 | 2 | 61 | 30.01 | 60.66 | 4.57 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1f | write | 2 | 2 | 45 | 30.01 | 60.66 | 4.43 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1g | write | 0 | 7 | 68 | 30.04 | 61.23 | 9.15 | 446 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1g | write | 1 | 4 | 2 | 30.07 | 61.17 | 4.67 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1g | write | 2 | 7 | 44 | 30.03 | 61.35 | 8.99 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1h | write | 0 | 2 | 69 | 30.01 | 60.90 | 4.55 | 162 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1h | write | 1 | 1 | 89 | 30.01 | 60.90 | 3.44 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1h | write | 2 | 3 | 23 | 30.02 | 60.90 | 5.55 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 2x | write | 0 | 2 | 69 | 30.06 | 60.80 | 4.55 | 168 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 2x | write | 1 | 2 | 61 | 30.08 | 60.80 | 4.57 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 2x | write | 2 | 2 | 45 | 30.08 | 60.80 | 4.43 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 2y | write | 0 | 7 | 68 | 30.10 | 61.13 | 9.16 | 481 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 2y | write | 1 | 7 | 58 | 30.09 | 61.13 | 9.05 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 2y | write | 2 | 6 | 65 | 30.08 | 61.13 | 7.86 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 3x | write | 0 | 2 | 69 | 30.07 | 60.72 | 4.55 | 168 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 3x | write | 1 | 2 | 61 | 30.08 | 60.72 | 4.57 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 3x | write | 2 | 2 | 45 | 30.08 | 60.72 | 4.45 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 3y | write | 0 | 2 | 69 | 30.07 | 61.26 | 4.55 | 168 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 3y | write | 1 | 2 | 61 | 30.05 | 61.26 | 4.57 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 3y | write | 2 | 2 | 45 | 30.07 | 61.26 | 4.44 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1a | write | 0 | 6 | 100 | 30.01 | 60.89 | 8.02 | 472 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1a | write | 1 | 7 | 58 | 30.03 | 60.89 | 9.10 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1a | write | 2 | 7 | 42 | 30.04 | 60.89 | 8.90 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1b | write | 0 | 2 | 69 | 30.10 | 60.70 | 4.52 | 171 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1b | write | 1 | 2 | 59 | 30.10 | 60.70 | 4.51 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1b | write | 2 | 2 | 44 | 30.08 | 60.70 | 4.41 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1c | write | 0 | 2 | 69 | 30.05 | 60.41 | 4.52 | 171 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1c | write | 1 | 2 | 59 | 30.05 | 60.41 | 4.51 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1c | write | 2 | 2 | 44 | 30.01 | 60.41 | 4.41 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1d | write | 0 | 4 | 3 | 30.05 | 60.79 | 4.70 | 280 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1d | write | 1 | 2 | 59 | 30.21 | 60.79 | 4.50 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1d | write | 2 | 5 | 86 | 30.08 | 60.79 | 6.70 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1e | write | 0 | 10 | 129 | 30.02 | 61.19 | 11.49 | 694 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1e | write | 1 | 10 | 77 | 30.01 | 61.19 | 12.44 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1e | write | 2 | 10 | 126 | 30.07 | 91.34 | 10.11 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1f | write | 0 | 4 | 3 | 30.01 | 60.52 | 4.70 | 336 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1f | write | 1 | 4 | 2 | 30.02 | 60.52 | 4.64 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1f | write | 2 | 4 | 2 | 30.02 | 60.52 | 4.55 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1g | write | 0 | 9 | 2 | 30.32 | 61.65 | 11.51 | 1038 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1g | write | 1 | 16 | 50 | 30.32 | 61.65 | 18.04 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1g | write | 2 | 18 | 34 | 30.29 | 61.65 | 19.20 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1h | write | 0 | 13 | 35 | 30.08 | 61.45 | 14.90 | 955 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1h | write | 1 | 13 | 2 | 30.11 | 61.46 | 13.69 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1h | write | 2 | 13 | 34 | 30.09 | 61.48 | 14.59 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 2x | write | 0 | 4 | 3 | 30.02 | 60.44 | 4.70 | 336 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 2x | write | 1 | 4 | 2 | 30.00 | 60.44 | 4.64 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 2x | write | 2 | 4 | 2 | 30.01 | 60.44 | 4.55 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 2y | write | 0 | 2 | 69 | 30.01 | 60.38 | 4.52 | 171 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 2y | write | 1 | 2 | 59 | 30.00 | 60.38 | 4.50 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 2y | write | 2 | 2 | 44 | 30.00 | 60.38 | 4.41 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 3x | write | 0 | 2 | 69 | 30.01 | 60.36 | 4.52 | 171 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 3x | write | 1 | 2 | 59 | 30.02 | 60.36 | 4.51 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 3x | write | 2 | 2 | 44 | 30.01 | 60.36 | 4.41 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 3y | write | 0 | 4 | 3 | 30.02 | 60.52 | 4.69 | 336 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 3y | write | 1 | 4 | 2 | 30.01 | 60.52 | 4.64 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 3y | write | 2 | 4 | 2 | 30.01 | 60.52 | 4.55 |  |

stalls.log (every matrix run on this host, with the time of day):

    STALL: f1 write P=3 rep=1a 03:43:50
    STALL: f1 supersede P=1 rep=2a 03:45:34
    STALL: f3 after write (the lock stalled once the writers were done) P=3 rep=1a 03:58:09
    STALL: f1 write P=3 rep=1a 03:59:21
    STALL: f1 write P=3 rep=1b 04:00:29
    STALL: f1 write P=3 rep=1c 04:01:40
    STALL: f1 write P=3 rep=1d 04:03:19
    STALL: f1 write P=3 rep=1e 04:04:29
    STALL: f1 write P=3 rep=1f 04:05:38
    STALL: f1 write P=3 rep=1g 04:06:47
    STALL: f1 write P=3 rep=1h 04:07:56
    STALL: h281 write P=3 rep=1a 04:09:05
    STALL: h281 write P=3 rep=1b 04:10:14
    STALL: h281 write P=3 rep=1c 04:11:23
    STALL: h281 write P=3 rep=1d 04:12:32
    STALL: h281 write P=3 rep=1e 04:14:12
    STALL: h281 write P=3 rep=1f 04:15:21
    STALL: h281 write P=3 rep=1g 04:16:31
    STALL: h281 write P=3 rep=1h 04:17:41
    STALL: f1 write P=3 rep=2x 04:20:34
    STALL: f1 write P=3 rep=2y 04:21:44
    STALL: f1 write P=3 rep=3x 04:22:53
    STALL: f1 write P=3 rep=3y 04:24:03
    STALL: h281 write P=3 rep=2x 04:25:11
    STALL: h281 write P=3 rep=2y 04:26:19
    STALL: h281 write P=3 rep=3x 04:27:27
    STALL: h281 write P=3 rep=3y 04:28:36

