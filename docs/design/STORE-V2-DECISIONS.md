# STORE-V2 decisions: what the critiques changed in STORE-V2.md, and why

Written by the Amend step on 28 October 2026. Each entry names the change made to [STORE-V2.md](STORE-V2.md), the
finding of the critique (not in the repository) it answers (S = security review, P = performance and operations review, the
headings as numbered there in order), and the reason. The fourteen decisions the orchestrator took ahead of the
step are marked **[taken]** and applied as given; where a number in a decision did not follow from the script, the
script's figure is used and the difference is said. Numbers come from `docs/design/measure/measure.py` (run as
`python3 -I measure.py <pairs.json> <rails.json> <keys.json> <txsize.json> <out dir>` over the private inputs
STORE-V2.md's preamble names, none of which is in the repository; output `docs/design/measure/numbers.json` and
`measure-output.txt`) and from `docs/design/measure/gitmeta.py` (output `docs/design/measure/gitmeta.txt`,
`git-text/gitmeta.json`); the previous script is kept as `docs/design/measure/measure-binary-frame.py` (its
re-run output stayed with the performance review, outside the repository).

## Code facts checked in the `turso-reads` branch before changing anything

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
    experiment was re-run with the text frame and base64 objects (`docs/design/measure/gitmeta.py`, output
    `gitmeta.txt`): a 185-unit push is 0.272 MB against 0.643 MB today (2.37x; the binary frame gave 0.258 MB,
    2.48x, in the performance review), 1,762 objects against 2,141 (17.7% fewer), the repacked
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

## Changes the M1 code review caused (28 October 2026, branch `store-v2`)

The review of the M1 commits (`vci-core::objects`, `predicate`, `manifest`, `vci-attest::frame`, the replay and
the adversarial tests) found the design and the code apart in these places; each is settled in both.

- **The ten mutations are one test** (section 1.6's last paragraph, section 6 M1's tests row):
  `manifest_tests.rs::the_security_harness_mutations_each_move_the_root_or_fail_a_decoder_rule` builds a run of
  two units over a checkout of every entry kind with `Run::build`, decodes the shape, tables and descriptor, and
  applies the harness's ten mutations to the decoded objects, each through the encoders and decoders again and
  then `resolve`, `observe` at HEAD and `from_observed`. The env bit cleared under a kept override is refused by
  `Descriptor::decode` and by `resolve`; an equal shape row twice by `Shape::encode` (and by the decoder in
  `tests/adversarial.rs`); the other eight move the root. The exec-bit vector is stated as the change at HEAD
  the flipped label would hide, because the observer reports HEAD's mode and kind, never the shape's label: the
  label alone leaves the root of an unchanged file equal, which the harness's last line already said. Section
  1.6 now says so, so that "each must change the root" is not read as a claim about the label.
- **What the replay can check on this sample** (section 6 M1's tests row): `pairs.json` holds each unit's delta
  manifest and not the 11 base manifests the deltas name, so `root()` of the resolved set with the state's values
  is compared with the root of the unit's own entries and with the signed `entriesRoot` for all 1,175 units and
  with the signed subject digest for the three base-less units only. The row says this and gives the full-set
  check against the subject digest for every unit to M3's end-to-end fixture, where the bases are in the store.
  The bases are not fetched here: the sample is what the measurement step exported, and no store is read.
- **`waived` enters the storage key sorted and distinct for both versions** (sections 1.1, 1.6 rule 7, 5.1,
  6 M3): a v2 statement carries sorted distinct ids, so a v1 list's order and repeats cannot come back through
  the view, and `ResolvedPredicate::waived_canonical()` is the list both paths key on. Counted with
  `python3 -I` over the private sample's `pairs.json`: 1,158 of 1,175 units repeat a waived string and 1,163 are not sorted, so
  for those units 2.9's key differs from 2.8's and the 2.8 record stays as a second candidate until supersession
  or expiry (fail-open; one more candidate per such test). The alternative, keeping v1's as-signed list in the
  key, would give a v1 and a v2 record of the same facts different slots for the same units, so nothing is
  gained by it. The replay's accessor parity (check c) is stated over the canonical list.
- **The hdr is the whole global manifest** (sections 1.1, 1.3, 3): `Hdr::encode` writes the global manifest's
  externals and env after its entries (the twelve node units' global manifests hold `NODE_OPTIONS`), and the
  toolchain's four lists in the fixed order `goEnv`, `pythonDists`, `rubyGems`, `rustCfg` without names. The
  text now lists the sections in the order the bytes have them and gives the measured sizes (4,489 B Rails,
  796-813 B node: +51 B over the model, which left the global env entry out). `measure.py`'s `encode_hdr` is
  left as the model that was measured; the replay's figures are the code's.
- **An inline external the tables hold is refused whether or not its bit is set** (section 1.6 rule 3):
  `Descriptor::resolve` looked only for an adjacent equal pair after merging, so a pair in the table with its
  bit clear could also be spelled inline; it now refuses any extra `tables.externals` holds, one encoding per
  externals list, and the test covers the clear-bit case.
- **The v2 view has one constructor** (section 1.6 rule 7): `ResolvedPredicate::V2` holds a `V2View` whose
  fields are private, so a view whose waived ids were never checked against the waiver table cannot be built
  outside `ResolvedPredicate::v2` (a `compile_fail` doctest pins it); `waived()` indexes the table on that
  invariant.
- **The replay test writes nothing unless `VCI_REPLAY_OUT` names the file**; `docs/design/measure/replay-numbers.json`
  is regenerated by passing it. Its per-run `hdr_bytes` is the sorted distinct sizes, the statistic
  `measure.py` writes, so the two 5-unit node runs compare at +6.8% (the +51 B per hdr) instead of a spurious
  +33.8% from summing five sizes against four.

### Not changed after the M1 review, and why

- A kind-2 (Sigstore bundle) signature frame's JSON accepts trailing whitespace, so the frame has more than one
  spelling. Nothing is keyed on the signature frame (the record is keyed by slot, the statement and payload are
  unchanged, verification sees the same envelope) and the encoder writes compact JSON only; the reviewer's own
  fix is "no change needed for 2.9". Left as is, with the adversarial test that documents it.
- `Descriptor::resolve` clones each group and own `ShapeEntry`; the cost is O(own + group) per candidate as the
  design asks, and `ResolvedManifest { set: Vec<ShapeEntry> }` is the design's own signature. A borrowing set is
  an M3 change if the plan's profile shows it.

## Changes the M2 code review caused (28 October 2026, branch `store-v2`)

The review of the M2 commits (the trait, the four backends, the parity suite, the 2.8 binary test) found these;
each is settled in the code and the design.

- **`--finish` counts format-1 rows by the value, on every SQL backend** (section 5 steps 4 and 9): PostgreSQL
  counted `format IS DISTINCT FROM 3` and libSQL `format IS NOT 3`, SQLite the value's first byte. The column is
  store data a 2.8 writer leaves stale (its upsert sets the key and the value alone, which
  `a_2_8_binary_fails_open_on_a_format_3_sqlite_file` asserts), so a 2.8 run during the window could leave
  `format = 3` beside a format-1 value and `--finish` would drop `manifests` under it; and a frame put without
  columns (`NewAttestation::copy_of`, every copy out of git-meta) had NULL and held the window open for good. Now
  PostgreSQL counts `substring(value from 1 for 1) <> '\x76'` and libSQL `encoding <> 0 OR hex(substr(value, 1,
  1)) <> '76'`; a test on each puts a format-1 value under a frame's columns (refused, 1) and a frame without
  columns (not counted).
- **A libSQL frame is never stored compressed** (section 2.1): the first byte is what the server-side count and the
  replica's sync by `seq` read, and a frame is under 2 kB of mostly base64, which zstd barely shrinks. A compressed
  row is therefore always a format-1 row (`encoding <> 0` counts), and `Row::is_format_three` (the old-log row for
  2.8 replicas, the `TX_UNITS` count) is by the value too, so a frame put without columns is treated as a frame.
- **A libSQL batch sends its objects again with every transaction until one stores them** (section 6, the batch
  contract): the objects went in the first transaction alone when they filled one (~1.0 MB for an 800-unit partition
  with its state object), and losing it was a warning while the later transactions stored every record, so the
  server could hold 800 rows naming objects it never received. Now `write_all` keeps the queued objects until a
  transaction that carries them commits, adds them to every transaction built before that (an upsert that refreshes
  `put_at` at most), and hands those never stored back to the open batch for its next write; a transaction of
  objects alone that was lost is no warning unless no later one stored them. A proxy that misspells the first
  transaction's `BEGIN IMMEDIATE` (the server refuses it) shows the records' transaction carrying the objects, and
  four refusals in a row (the records' transaction is split to its units, each refused) show every unit lost and
  nothing stored. The alternative, copying the objects into every unit's transaction, would send the state object
  with every unit.
- **libSQL `remove_objects` inside a batch is queued after the batch's removals**, as PostgreSQL's (section 2.1 "The
  write per partition", section 6 M2's row): it was applied at once, so the superseded records (still queued) kept
  their objects and a run's orphan pass removed none until `vci prune`. The ids go in `Pending::object_removals`,
  left in the queue by an early write, emitted as the last statements of the queue's last transaction (the rule in
  the SQL, a `gone` row each), the batch's own objects left out; the handle's object cache forgets the ids asked
  about (whether each went is the server's to say). git-meta keeps its as-committed scan (the trait allows either),
  and the parity script's batch step calls `remove_objects` of every id with b's shape aged first: gone on every
  backend after the finish, the referenced and the batch's own kept; an object only the batch's own removal frees is
  backend-defined and stays out of the script.
- **git-meta's orphan scan reads every value; `vci run` does not call it there** (section 2.2, the trait's
  `remove_objects` and `orphan_objects` docs): the design's "the referrer scan `orphan_manifests` does today, over
  ~4 roots per run" was wrong, since a manifest's referrers are on the paths it lists and an object's can be any
  record; a scoped scan does not exist, and recording each record's object ids at put and merge time in
  `git-meta.sqlite` is more than 2.9 needs. The cost is `vci prune`'s (43 MB on vex), which read every value
  already; M3's run.rs calls `remove_objects` after supersession only on a store with `Caps::columns`.
- **The libSQL replica serves objects and columns from the server in 2.9.0** (section 2.1 "libSQL replica log",
  section 5 step 7, section 6 M2's row): the design said the replica syncs `objects WHERE seq > ?`; the code and
  `docs/STORE-BACKENDS.md` section 18 never did, and the design now says what the code does and what it costs (a
  replica plan reads 1.4-1.9 MB of verdict objects from the server; a replica cut off from the server runs every
  format-3 unit). Syncing the objects, the object ids of `gone` and the columns into the file is 2.9.x work with no
  change to the server's tables; the sync by `seq` now takes only frames (`hex(substr(value, 1, 1)) = '76'`), since a
  format-1 row this vci writes is in the old log and was synced twice.
- **The vci 2.8 binary test rejects this build's own binary**: `VCI_TEST_VCI_2_8` naming the branch's `vci`
  (`--version` still says 2.8.1) passed every assertion, since plan and run are format-1 paths at M2. The guard now
  compares the bytes with `CARGO_BIN_EXE_vci` and fails, not skips. The workspace version is not bumped here (a
  release decision, M4), and building e6244e7 in CI so the test is not opt-in is left open.
- **The conformance worlds' `age_objects` check that every id was there** (libSQL's local file, git-meta: one row
  under exactly one kind), as the SQLite and PostgreSQL worlds did.

## Not changed, and why

- The per-unit signature, the keys, the slots, `storage_key`, `root()`, `Verifier::check`'s order and the
  fail-open rule: no finding asked for a change, and the harness confirmed the trust path.
- The state object is not bound into the statement (S6's alternative): the label and the two-day TTL answer the
  finding without a statement change.
- The memo is not replaced by the `tree16` column (judge 2, open question 5): P5 asked to keep the memo.
- Key paths on git-meta (P2's suggested fix): out of scope for 2.9 by decision 13; measured as a 2.10 question.
- The 800-unit partition stays in the tables as the partition maximum class, with 970 as the production
  maximum (P7 asked that it be a maximum only, not the per-day multiplier).

## Changes the M3 code review caused (28 October 2026, branch `store-v2`)

The review of the M3 commits (run, plan, prune, the upgrade command, the suites) found these; each is settled in
the code and the design, or refuted with the test that holds it.

- **`vci prune` never takes a column for a row's format** (section 2.1 "Prune", section 5 step 3): on a store
  with columns it counted every row with `format = 3` current without a read and let no manifest be referenced
  by it, so a 2.8 writer's format-1 value in a frame's slot (its columns left beside it, M2 fact 1) had its
  manifest reported removed; only the backends' own referrer rule kept it. Now every row is read while the store
  holds an input manifest (the migration window; what 2.8 read anyway), and the columns describe the format-3
  rows only once no manifest remains, when nothing a column could hide references anything.
  `sqlite_prune_reads_a_format_1_value_under_a_frames_columns_before_counting_manifests` and the 2.8-binary
  test's prune hold it. `prune_manifests` counts and prints a removal only when the backend removed it, else says
  the backend kept it.
- **`--keep` orders a unit by the signed `issuedAt`, not the key hint** (section 2.1 "Prune"): the hints chose
  which records were beyond `keep` and the confirming read only checked the candidate's own hint, so a hint
  edited to make an older record the newest deleted the genuinely newer one. Now a unit and signer with a record
  beyond `keep` by the hints (or with a row the columns do not describe) has every described record read, and the
  signed `issuedAt` and `tree` order the group as the values path does; a record the hints doomed that the
  statements keep is counted unconfirmed. `sqlite_prune_keep_orders_a_unit_by_the_signed_issue_time_not_by_the_key_hint`.
- **The plan names the state objects in one `columns` call per round** (section 1.5 step 9): `state_for` asked
  the store for one record's columns per entry-failing candidate, before the 16-object cap, hundreds of requests
  on Turso after a broad edit. `preload_objects` now fetches the round's read frames' columns with the verdict
  objects' load and keeps the state id by record key; `state_for` checks the cap before any store request.
  `state_objects_are_named_by_one_columns_call_per_round_and_capped_before_any_read` counts the calls on the
  memory store.
- **Supersession takes the columns and the hdr platforms fetched once for the run** (section 1.4 steps 5 and 6):
  `superseded_by` asked `columns` per unit on the pool threads (~800 requests a partition on Turso, where the
  design budgets none) and read each hdr from inside the per-unit closure. `last_durations` now returns the
  columns of every selected unit's records by key (`UnitRecords`), `HdrPlatforms::preload` reads the distinct hdr
  ids they name in one `get_objects`, and `old_records_to_read` pre-filters from the map (a record not in it is
  read). `supersession_takes_the_columns_and_hdr_platforms_fetched_once_for_the_run`.
- **The group's case-collision check is memoized per `(shape id, group)`** (section 1.5 step 8), as `BaseCheck`
  memoizes it per base root, and the git-ignored children are asked about the listed directories alone. The
  reviewer's "O(set) per candidate" was measured before deciding (the measurement stays in `tests/replay.rs`
  under `VCI_PAIRS`): the sample's own entries cost 0.4 ms a candidate; a synthetic vex unit of 2,700 group and
  150 own entries 2.9 ms, of which the case collisions 1.5 ms (now memoized), observing the cached paths 0.7 ms
  and the manifest with its root 0.6 ms, which stay per candidate because the root is over the whole set by
  design: 4.8 thread-seconds at 1,644 candidates, 11.7 at 4,000, under a second of wall on the plan's pool. Not
  the 100 thread-seconds of 2.7.30, whose cost was rehashing files per candidate, which the `CheckoutCache`
  answers once per path.
- **REFERENCE.md and step 6 say what the hdr memo covers**: the global manifest's root and rehash per `(project,
  hdr id)`; the scalar hdr checks run per candidate. Narrowed rather than memoized: a scalar compare per
  candidate costs nothing and its failure names the candidate.
- **The suites written against format-1 writes run with `record_format = 1`** where that is their premise
  (`e2e_format3.rs`'s World, the refused-base test, the shared-store manifest branch of
  `edit_supersede_prune`, which now checks the format-3 run first and then the format-1 orphan manifest), and the
  prune-by-columns test counts the world's own state object. `adversarial_plan.rs`'s signer test asserts the
  check's text (`signer id (the store key's signer segment)`).
- **Migration gates 5 and `--finish` on PostgreSQL have tests**: `a_2_8_binary_fails_open_on_a_format_3_git_meta_store`
  (2.8 plans every frame's unit, prunes nothing, writes its own row beside the objects) and
  `postgres_store_upgrade_begins_and_finishes`, which found that PostgreSQL's second `--finish` re-ran the drop
  and reported an upgrade: `PgStore::upgrade_finish` now answers `Finish::Already` at version 2, as SQLite does.
- **"Cancelled-run partial write" is held where the cut happens, not by killing a process**: a cancel between a
  libSQL batch's transactions is what `a_batch_stores_no_record_without_its_objects` and the stalled-proxy batch
  of `vci-store-libsql/tests/libsql.rs` produce deterministically (the first transaction's units stay with their
  objects, every later transaction re-sends the unstored objects), a cancel inside a transaction is a rollback on
  every SQL backend, and `e2e_m3.rs` (c) keeps the records of the units a failing one leaves. A SIGKILL timed
  after the first `attested` line on the four-unit fixture would land before any flush (the batch commits at
  1 MiB or at the end) and assert an empty store; section 6's row now names the tests that hold the property.
- **Supersession prefetches the hdr objects on a lazy store** (section 1.4 step 6, section 2.2): running the whole
  of `vci-cli`'s suites for the M3 fixes found `cargo_two_blobless_clones_supersede_the_same_attestation_and_both_push`
  and `cargo_supersession_in_a_blobless_clone_removes_the_orphan_manifest` superseding nothing under the format-3
  default. git-meta's `get_objects` fetches nothing (`Prefetch::Objects` first, as the plan does), so in a blobless
  clone the old frame's hdr was missing, its platform `None`, and the record kept as made for an unknown platform.
  `last_durations` now also returns the hdr ids the records name (`UnitRecords::hdrs`: the columns' on a SQL
  store, the read statements' on git-meta) and `HdrPlatforms::preload` and `::of` issue one `Prefetch::Objects`
  on a store with `lazy_values` before `get_objects`. The two-clones test stays on the default and holds it (it
  failed before, passes after); the orphan-manifest one and ten other `e2e_cargo.rs` tests whose premise is a
  stored manifest or the per-entry explain text on git-meta, and `e2e.rs`'s `end_to_end_verification_steps`
  (B and C), run with `record_format = 1` through a `run_format1` helper, as f7e7444 did for the three it found.
