# DECISIONS: what the critiques changed in STORE-V2.md, and why

Written by the Amend step on 28 October 2026. Each entry names the change made to `design/STORE-V2.md`, the
finding of `design/CRITIQUE.md` it answers (S = security review, P = performance and operations review, the
headings as numbered there in order), and the reason. The fourteen decisions the orchestrator took ahead of the
step are marked **[taken]** and applied as given; where a number in a decision did not follow from the script, the
script's figure is used and the difference is said. Numbers come from `design/final/measure.py` (run as
`python3 -I measure.py ../../wr/pairs.json ../../prodlogs/rails.json ../../meas/keys.json ../../wr/txsize.json .`,
output `design/final/numbers.json` and `measure-output.txt`) and from `design/final/gitmeta.py` (output
`design/final/gitmeta.txt`, `git-text/gitmeta.json`); the previous script is kept as
`design/final/measure-binary-frame.py` and its output is in `design/review-perf-ops/measure-rerun.txt`.

## Code facts checked in the `turso-reads` worktree before changing anything

- `crates/vci-store-libsql/src/conn.rs:1826` `blob()`: a value that is valid UTF-8 without NUL travels as
  `CAST('…' AS BLOB)`, the same bytes; anything else as `X'…'`, twice the bytes. `text()` at 1802 doubles
  apostrophes. P1's premise holds for the binary frame.
- `conn.rs:1747-1767` `send_batch`: a batch is one SQL string (`BEGIN IMMEDIATE; …; COMMIT`) sent through
  `execute_batch`; every value is a literal built by `text()`/`blob()` (`batch.rs:1306-1367`). There is no
  hrana-argument path, so decision 2's "check whether the batch can carry blob arguments as base64 args" is
  answered no without a rewrite of the batch.
- `batch.rs:95-110`: `FLUSH_WRITES` 2,000 (attestations + emptied + removals), `FLUSH_BYTES` 4 MiB (not the 8 MiB
  of the 2.8.1 docs the draft cited), `TX_BYTES` 1 MiB, `TX_UNITS` 64; a queue is sent as whole-unit transactions
  of at most 1 MiB as sent (2.8.2's short transactions). `batch.rs:845-860`: today's log rows are an `INSERT` in
  the same transaction as the removals.
- `remote.rs:111` `LOG_KEEP_SECS` 30 d; `remote.rs:1674-1701` `remember_passing` is one multi-row `upsert_memo`
  with `MEMO_KEEP_SECS` 7 d (`vci-store-sqlite/src/sql.rs:24`). P5's premise holds.
- `run.rs:3309` is the only supersession use of the key's signer segment (a filter); `keys.rs:27` `signer_id` is
  the 16-hex SHA-256 of the key blob the check of S2 compares against. `cmds.rs:1703-1722`: a record
  `envelope_meta` cannot parse makes prune set `referenced = None` and remove no manifest (P9).
- `config.rs:596` `default_max_ttl` (the policy default S4 names); vex's `max_ttl` is 14 d.

## Changes

1. **The record frame is UTF-8 text** (`vci3 LF statement LF base64(sig frame) LF base64(descriptor)`), not a
   binary frame, section 1.2. **[taken, decision 1]** Answers P1 (hex on the libSQL wire doubled every record)
   and the judges' git-meta binary-values flaw, and removes the bytes read path from sections 2.2 and 6, which
   was the design's top risk. The grammar is pinned (first line, three LF, canonical base64, the sig frame and
   descriptor byte layouts); a future compressed record takes another first line (`vci3z`) in place of the
   binary frame's encoding byte. Measured: 1,783 B mean (p50 1,760, p90 1,917, max 2,707), of which 173 B is
   base64 over the binary frame of the same content (1,610 B) and 76 B is the second digest of change 3; the
   decision's "~1.7 KB: +170 B" was for one digest. No sample record holds an apostrophe (the five v1 payloads
   that did had it in a cargo `waived` string, now in the tables object), so the libSQL literal is exactly 1:1.
2. **Objects stay binary in memory and in BLOB/BYTEA columns on SQLite and PostgreSQL; base64 text on git-meta
   and on libSQL**, section 2.1 "Object bytes per backend". **[taken, decision 2]** The batch cannot carry hrana
   arguments (code fact above), so base64 in a TEXT column (1.33x) replaces hex (2x) without a rewrite; the id is
   of the decoded bytes on every backend. Wire bytes per 800-unit partition on libSQL: 2.43 MB (records 1.42 MB
   1:1 + objects 1.00 MB base64), 1.75 MB without the state object. Answers P1.
3. **The ctx is split into `hdr` (toolchain, global manifest, env-config digest, global input root, repo id,
   adapter, project scalars, ignored inputs, Rails inputs, env set) and `tables` (waiver table, env names,
   externals)**, two signed digests in the statement, sections 1.1, 1.3, 1.4, 1.5. **[taken, decision 3]**
   Answers P10 (ctx objects never deduplicated because their content address held the run's unions) and the
   second half of P3. Measured: hdr 4,494 B for every Rails unit, 11 distinct across the sample's 9 runs and 18
   header groups; tables 19,387 B (973 units) and 9,313 B (185 units). The per-hdr checks (repo, adapter,
   project, env config, toolchain, global inputs) are memoized per `(project, hdr id)`, which also answers S7.
   At the production spread (45-59 runs) the hdr costs 49 KB and the tables 0.50-0.66 MB where one ctx per run
   cost 0.70-0.92 MB. The cargo finding moved: the 67-75 KB cargo ctx was mostly the externals table (the crate
   list), which stays per run (open question 8 rewritten).
4. **The state object has its own retention**: `[store] explain_hashes_days = 2` (prune, and `vci run`'s orphan
   pass, delete a state object older than two days even while referenced; the records stay valid; `explain`
   prints the observed value and `attested hash not loaded`), and `[store] explain_hashes = false` stops writing
   it, sections 1.3, 2.1. **[taken, decision 4]** Answers P3 (two thirds of the per-run object bytes at steady
   state were explain-only state kept 14 days). The steady-state table is rebuilt: state 85 MB at 2 days against
   594 MB at 14. The orphan pass applying the TTL too is an addition of this step, so that a namespace without a
   prune job (vex's Rails jobs never prune) is bounded as well.
5. **Verdict objects are capped by bytes**, 16 MiB per plan, loaded in candidate-priority order, a candidate past
   the cap failing `inputs` with the count logged; state objects keep the count cap of 16 for explain only,
   sections 1.5, 4. **[taken, decision 5]** Answers P4: the 64-shape count cap was within one order of the 59
   runs observed 0.3 days into a window; the measured need is 1.35-2.13 MB, 7.9x under the byte cap.
6. **`memo2` is deleted; today's memo table and its one-statement write stay**, section 2.1 "Memo". **[taken,
   decision 6]** Answers P5: `remember_passing` is already one multi-row upsert; its 0.8 s median and 30 s
   maximum are the single writer's queue behind 6.6-8 MiB batches, and `memo2` would have tripled the bytes
   `passing_on` reads. The `memo` table also survives `--finish` (section 5.4).
7. **DDL runs in a request of its own**, before any batch: `vci store upgrade --begin`, or 2.9's first write
   sends it alone, sections 2.1, 5.2. **[taken, decision 7]** Answers P9's second wrinkle (DDL inside a 30 s
   batch request that a 2-4 MB transaction already takes 5-10 s of).
8. **Supersession and prune take commit, platform, `issuedAt` and `entriesRoot` from the old record's signed
   statement**; the columns only pre-filter which old records to read, sections 1.4 step 5, 2.1 "Prune", 4, and
   the invariant for CONTRACTS.md. **[taken, decision 8]** Answers S3 (1.4 said column-driven, 4 said
   statement-confirmed). **The plan compares the key's signer segment with the verified key's signer id after
   signature verification and fails `signer` on a mismatch**, one string compare per candidate, said to be new in
   2.9, sections 1.5 step 4, 4, 5.8, 6. Answers S2 (the claim in section 4 was not true of 2.8.1 or of the
   draft).
9. **`gone` rows are purged after max(30 days, the policy `max_ttl`); a replica whose cursor is older than the
   purge horizon does a full resync; the PostgreSQL `seq` counter serialises a namespace's writers for the
   length of a transaction**, sections 2.1, 5.7. **[taken, decision 9]** Answers S4. The cost is stated from the
   production removal rate: 64k rows and 13.8 MB a day (214 B a row), 1.93 M rows and 413 MB at 30 days, the
   largest table at rest and six times fewer rows than today's log (open question 9).
10. **A "decoder rules" subsection (1.6)** pins: the frame and canonical base64; minimal LEB128; the delta base
    (first index absolute, then previous + 1 + delta); bounded indices and bits; a refused env override whose
    bitmap bit is clear (and a refused `ABSENT_HASH` override); canonical `RepoPath` only and the autoload-miss
    form; strictly increasing distinct entries and groups; 255 groups with 0xff = none; the `objects.kind` column
    ignored for decoding; `storage_key` from decoded values; the bounds. One line is given for CONTRACTS.md.
    **[taken, decision 10]** Answers S5 and the refuted S6's "make the RepoPath validation explicit"; the
    harness's ten mutations become M1's negative test vectors (S1's suggested fix), section 6.
11. **`explain` labels a hash from the state object `attested (unsigned, from the run's state object)`**, and
    the per-hdr memo is per project, sections 1.5 steps 6 and 9, 4, 5.8. **[taken, decision 11]** Answers S6
    (a forged state object can only mislabel this text) and S7. Binding the state id into the statement is
    named and not done, with the reason (two-day object, no trust decision on the label).
12. **Section 3's per-day and steady-state rows are rebuilt from `rails.json`**: 164 Rails runs a day (a job is
    one partition), 76,725 units attempted (mean 540, max 972) and 46,644 attested (mean 328; the decision said
    327, the script's mean is 328.5), per-run objects from a measured curve of random subsets of the 973-unit
    run: 201 MB a day (158 without state) against 2.79 GB; the 800-unit case is kept as the partition maximum
    class and 970 added as the production maximum. The write model is 1 + 2 x 1.2 writes per record (2,724 for
    800 units, 3,302 for 970), `gone` ~64k rows a day, the libSQL wire bytes (text 1:1, objects base64) and the
    lock-hold time from `txsize.json` (1 MB 1.8-3.7 s, 2 MB 2.5-10.6 s, 4 MB 5-10 s) per 1 MiB transaction are
    given, sections 0, 1.4, 2.1, 3. **[taken, decision 12]** Answers P6, P7 and the rest of P3 and P1. One
    number differs from the decision: at 3.4 writes per record a queue of 2,000 writes is reached at ~587 units
    (4 + 3.4 x 587 = 2,000), not ~830 (which is 2,000 / 2.4, the rate without the record's own put); 83 of the
    142 jobs with a count were above 587 on 27 October, so most Rails partitions are two flushes. The draft's
    "8 MiB flush" is corrected to the 4 MiB of `batch.rs:98`, and 2.9 is said to drop the 64-attestation
    transaction share (`TX_UNITS`, sized for 36 KB units) so that transactions are sized by bytes alone.
13. **Section 2.2 (git-meta) is rewritten from the measured 2.4x bytes and 18% fewer objects**, trees per record
    unchanged, the two-level fan-out of the key path a 2.10 question. **[taken, decision 13]** Answers P2. The
    experiment was re-run with the text frame and base64 objects (`design/final/gitmeta.py`, output
    `gitmeta.txt`): a 185-unit push is 0.272 MB against 0.643 MB today (2.37x; the binary frame gave 0.258 MB,
    2.48x, `design/review-perf-ops/gitmeta.txt`), 1,762 objects against 2,141 (17.7% fewer), the repacked
    repository 1.58 MB against 4.47 MB; per 800-unit push ~1.2 MB against ~2.8 MB; the 1.8 GB pack would have
    been ~0.65-0.75 GB. The ~750k new tree objects a day and `meta.rs:717`'s pack-index cost are named as not
    addressed by 2.9.
14. **Section 9 gets a row per critique finding** (eight security, ten performance) saying where each is
    resolved; **section 7's open questions are updated**: the git-meta bytes path is closed (question 4 now
    names the key-path fan-out), runs per plan is "measured once" with the dashboard to watch it, state policy
    is the two-day default with the PR-signer switch as the open choice, cargo is about the externals table,
    and three new questions are added: the size of `gone` at rest, the re-run of `txsize.py` with real
    format-3 values before 2.9.0 (P1's "re-run with real frames"), and the distinct-hdr count in production.
    **[taken, decision 14]**

## Other changes the critiques caused

- Section 0's summary table: every row recomputed (record 20x, at rest 11.7x / 13.1x, partition 13.5x / 17.7x,
  plan 13x / 10x / 8x and 15x at the production spread, per day 13.9x / 17.6x, log rows 6x, memo rows 1x, and a
  git-meta row from the experiment). The "bytes per day" row no longer doubles the run count (P7).
- Section 1.1's statement table: `hdr` and `tables` rows; 1,100 B mean; the storage key is said to use decoded
  values (S5 item 7).
- Section 1.2's descriptor bitmaps are sized by the tables object's lengths (no count prefix), as the script
  measured them (272 B mean), and the group byte's 255 limit is stated (S5 item 4).
- Section 1.4 step 4 describes the libSQL send as 2.8.2's whole-unit transactions and says the ordering
  argument holds per transaction, with the object puts in the first (P6's note that one transaction no longer
  covers a partition).
- Section 2.1's schema: `hdr`, `tables_id` columns and indexes, object ids as 64-hex text everywhere (they index
  as text and travel 1:1), the `objects_kind_put` index for the state TTL, `memo2` removed, no `encoding` column
  (nothing is compressed in 2.9).
- Section 3's steady-state paragraph became a table with ceilings and the measured 59-run point, and says the
  draft's "12.7x at rest" was a write-snapshot ratio (P3).
- Section 4: the harness's evidence is summarised (how `root()` and the observer make every mutation change the
  root), the slot-overwrite note of S8, the stale-replica reasoning of S4, the outside-repository oracle of S6,
  and the bounds now include hdr and tables objects and the per-plan byte cap. Rule 3 of STORE-BACKENDS.md stands
  unchanged (the draft changed it to "values are bytes").
- Section 5: the DDL step (5.2), 2.8's prune behaviour and the advice to keep the window short (5.3, P9), the
  2.8 replica lag (5.7, P9), the `signer` check's new failure text (5.8), git-meta without a bytes path (5.5).
- Section 6: the base64 codec replaces the bytes path in `vci-git`; the DDL request, the purge horizon and the
  byte-only transaction sizing in `vci-store-libsql`; the `signer` check, the hdr memo, the byte cap and the
  metrics line in `plan.rs`; `prune_state_objects` in the trait; the negative test vectors and new end-to-end
  cases; the order of risk no longer names the bytes path and names the Turso transaction re-measurement.
- Section 8: dedup's "raw statement plus binary SSHSIG frame" and "memo collapsed to one row per plan" are listed
  as not taken after the critique; radical's columns are said to serve `last_durations` only, since supersession
  and prune read statements.

## Not changed, and why

- The per-unit signature, the keys, the slots, `storage_key`, `root()`, `Verifier::check`'s order and the
  fail-open rule: no finding asked for a change, and the harness confirmed the trust path.
- The state object is not bound into the statement (S6's alternative): the label and the two-day TTL answer the
  finding without a statement change.
- The memo is not replaced by the `tree16` column (judge 2, open question 5): P5 asked to keep the memo.
- Key paths on git-meta (P2's suggested fix): out of scope for 2.9 by decision 13; measured as a 2.10 question.
- The 800-unit partition stays in the tables as the partition maximum class, with 970 as the production
  maximum (P7 asked that it be a maximum only, not the per-day multiplier).
