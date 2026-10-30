# STORE-V2: store format 3, predicate v2

The final design for vci's store, built from four drafts (design-dedup, design-manifest, design-radical,
design-tree), three judges' reviews, and revised after a security review and a performance/operations review
(collected as the critique; every change and its reason is in
[STORE-V2-DECISIONS.md](STORE-V2-DECISIONS.md)). The drafts, the judges' reviews and the critique are not in the
repository; where this text cites them it says what they found. Base: **design-dedup** (per-unit
signature over a small statement, per-run context by signed digest, trust model unchanged). Grafted: the
manifest/radical split of the observation *set* from its *values* (the per-unit record names paths and kinds; file
hashes move to one per-run object that only `explain` reads), tree's index columns and v1/v2 coexistence flag,
radical's idempotent one-queue write and rejection of directory objects, manifest's signed files root for
supersession. Not taken: a per-run (Merkle) signature in the first release, directory-union objects, the
dependency-set-without-attested-values gate, trained zstd dictionaries, tree seals, git-meta checkpoints. Section 9
says where each judge's flaw and each critique finding is resolved.

Numbers come from the measurement scripts in [docs/design/measure/](measure/): `measure.py` run on the private
1,175-unit vex sample (`pairs.json`: the envelope, compact manifest and root of 1,175 real vex units of 28 October
2026), on the 27 October production logs (`rails.json`: 164 Rails jobs), on a production listing of vex-api of
27 October 15:20 (`keys.json`: 3,833 keys) and on the Turso transaction timings by size (`txsize.json`), none of
which is in the repository (vex's data); its output is `measure/numbers.json`, printed as
`measure/measure-output.txt`. The git-meta figures are from `measure/gitmeta.py` (a real-git experiment, output
`measure/gitmeta.txt`); the replay check's figures (`crates/vci-cli/tests/replay.rs` over the same sample) are
`measure/replay-numbers.json`; the local `sqld` measurements of section 10 are under `measure/sqld/`.
File:line references are to vci 2.8.1 (the `v2.8.1` tag) unless they name the `turso-reads` branch (2.8.1 plus
the libSQL write and read fixes: `crates/vci-store-libsql/src/batch.rs`, `conn.rs`). Vocabulary as in
docs/CONTRACTS.md: unit, candidate, slot `(test key, signer, storage key)`, root (`InputManifest::root()`,
`manifest.rs:1130`), global manifest, run (one `vci run` of one project: one partition; a vex Rails job is one
partition, `cmds.rs:49-72`).

## 0. Summary

| | today (2.8.1) | format 3 | ratio |
|---|---:|---:|---:|
| one unit's record (envelope + manifest / record) | 21,166 + 15,154 B | 1,783 B (p50 1,760, max 2,707) | 20x |
| one unit at rest, amortized over the 1,175 sample units, per-run objects and estimated groups included | 36,320 B | 3,108 B (2,773 B without the state object) | 11.7x (13.1x) |
| one 800-unit partition's `vci run` writes | 29.5 MB, 1,609 rows, 5 libSQL batches of 6.6-8 MiB, 27 s median, timeouts | 2.18 MB at rest, 2.43 MB on the libSQL wire (1.67 / 1.75 MB without the state object), 804 rows, 2,724 writes in 2 flushes, sent as 3 transactions of at most 1 MiB (1.8-3.7 s of lock each) | 13.5x (17.7x) |
| one plan reads (2,305 units listed, 1,644 values, candidates from 4 / 10 / 20 runs) | 62 / 65 / 70 MB in 8-10 requests | 4.7 / 6.2 / 8.7 MB in 3-4 requests; 5.1-5.9 MB at the production spread of 45-59 runs | 13x / 10x / 8x |
| bytes written per day at vex (164 Rails runs, 76,725 units attempted, mean 540, max 972) | 2.79 GB | 201 MB (158 MB without the state object) | 13.9x (17.6x) |
| libSQL log rows per day / memo rows per day | ~400k / ~189k | 64k `gone` rows / ~189k (the memo is unchanged) | 6x / 1x |
| per-run objects a dead run leaves behind | 9 bases, ~450 KB, never collected by `vci run` | 4 objects, ~0.75 MB for two days then ~0.25 MB, collected by `vci run`'s orphan pass | |
| git-meta: one 800-unit push, objects per push | 2.78 MB, 11.6 objects per record | 1.17 MB, 9.5 objects per record (trees unchanged) | 2.4x, 18% fewer objects |

What changes: the statement (`predicateType` v2) carries the unit's own facts and two digests, of a `hdr` object
(toolchain, global manifest, project scalars: shared by every run at the same toolchain and global inputs) and of a
per-run `tables` object (waiver table, env names, externals); the manifest table and base manifests go; a unit's
manifest becomes a ~272 B descriptor (index lists into a per-run `shape` object of paths and kinds) inside its
record; file hashes live in a per-run `state` object that no verdict reads and that lives two days; the record is a
UTF-8 text frame: the statement bytes as they are, then the signature frame and the descriptor as base64. What
does not change: one SSHSIG (or Sigstore bundle) per unit over the exact statement bytes, the keys, the slots,
`storage_key`, `root()`, `Verifier::check`'s checks and their order, the per-entry explain text, fail-open, rule 3 of
`docs/STORE-BACKENDS.md` (values are UTF-8), today's memo table and its one-statement write.

## 1. Record formats and what is signed

### 1.1 The statement (signed)

An in-toto Statement v1, `predicateType` `https://vci.dev/test-attestation/v2`, compact JSON with sorted keys.
The writer's bytes are what the signature covers and what the store holds; a reader never re-serializes.
Measured 1,100 B mean (p50 1,100, max 1,601: a cargo unit with `cfgPredicates`).

| field | bytes | what it binds |
|---|---:|---|
| `subject[0].name` = testId, `subject[0].digest.blake3` = inputRoot | ~160 | the unit and its input set (unchanged: `plan.rs:2523-2534`) |
| `predicate.hdr` (64 hex) | 72 | the header object: repo id, adapter, project name and dir, runner project, tool version, `envConfigDigest`, `globalInputRoot`, the whole `globalManifest` (entries, externals, env), `ignoredInputs`, `railsInputs`, `envSet`, `toolchain` (gem/dist/cfg lists included). Content-addressed, so every run at the same toolchain and global inputs names the same one (11 distinct across the sample's 9 runs and 18 header groups; one per base tree for Rails) |
| `predicate.tables` (64 hex) | 76 | the per-run tables object: the waiver table, the env-name table, the externals table (unions over the units of the run that share the hdr) |
| `predicate.testId`, `predicate.argv` | ~165 | no replay across units or argv (`plan.rs:2588-2631`; argv kept inline because the plan compares it and it is 100 B) |
| `predicate.commit`, `tree`, `treeDirty` | ~100 | supersession, prune, choosing |
| `predicate.issuedAt`, `expiresAt` | ~60 | expiry, `max_ttl` (`plan.rs:2536-2585`) |
| `predicate.result` {state, tests, failed, skipped, durationMs} | ~70 | only a pass skips (`plan.rs:2710-2733`); `durationMs` for `vci run`'s ordering |
| `predicate.entriesRoot` (64 hex) | 80 | BLAKE3(`vci/entries-root/v1` ‖ the entries section exactly as `root()` encodes it): supersession's "same files" test (`run.rs:3270-3290`) without decoding manifests |
| `predicate.waived` (sorted u16 ids into `tables.waiverTable`), `tainted`, `declaredInputs`, `platformSpecific`, `archSpecific`, `cfgPredicates` (each omitted when empty) | ~130 | policy at the base commit still waives/declares the same (`plan.rs:2737-2765`); the waived *check* reads only each string's `category:kind` key, resolved through the tables object; an id out of range fails `statement` |
| `_type`, `predicateType`, member names | ~190 | shape |

Moved into `hdr` and bound through its digest: `repoId`, `adapter`, `projectName`, `projectDir`,
`runnerProject`, `toolVersion`, `envConfigDigest`, `globalInputRoot`, `globalManifest`, `ignoredInputs`,
`railsInputs`, `envSet`, `toolchain`. Moved into `tables`: the waiver strings (ids instead), the env-name and
externals tables the descriptor indexes. Dropped: `manifestRef` (it always equalled `inputRoot`), base64 of the
payload, the armored signature. The split of the old single `ctx` into `hdr` and `tables` costs 76 B per statement
(the second digest) and makes the 4.5 KB header shared across runs and its checks memoizable per project
(section 1.5 step 6), where one ctx per run never deduplicated (its content address included the run's unions).

The storage key (`ctx.rs:88-176`) is computed over the same values as today, read through the resolved view
(statement fields plus hdr fields, decoded values, never bytes), so a slot's identity is the same function of the
same facts: the same signer re-attesting the same inputs, toolchain and waived set overwrites its record; a
different waived set is another slot. One value changes form: `waived` enters the key **sorted and distinct**
(`ResolvedPredicate::waived_canonical()`, the same for a v1 and a v2 record), because a v2 statement carries
ids that are sorted and distinct and so cannot reproduce a v1 list's order or repeats; 2.8 joined the list as
signed, and 1,158 of the 1,175 sample units repeat a waived string (1,163 are unsorted), so for those units
2.9's key is not 2.8's (section 5.1).

### 1.2 The record frame (the slot's value)

The record is UTF-8 text without NUL, so that rule 3 of `docs/STORE-BACKENDS.md` ("values are UTF-8") stands,
git-meta stores it as the string value it already handles (no bytes read path, section 2.2), and the libSQL store
sends it 1:1 as a text literal (`turso-reads` `conn.rs:1826` `blob()`: UTF-8 without NUL travels as
`CAST('…' AS BLOB)`, the same bytes; anything else as a hex literal, twice the bytes).

```
record     = "vci3" LF statement LF sig LF descriptor
statement  = the statement JSON exactly as signed: compact serde_json output, which holds no LF and no NUL
             (JSON escapes both inside strings; the serializer writes no whitespace); it starts with '{'
sig        = base64(sig_frame)
descriptor = base64(descriptor_bytes)
base64     = RFC 4648 section 4 alphabet, '=' padding, no line breaks, canonical (section 1.6)

sig_frame        = u8 sig_kind (1 = SSHSIG, 2 = Sigstore bundle)
                   uv keyid_len; bytes keyid   today's `keyid` ("SHA256:<b64 of the key blob hash>", or the keyless signer id)
                   uv sig_len;   bytes sig     the SSHSIG binary blob (180 B for ed25519; today 404 B of base64-of-PEM-of-base64), or the bundle JSON
descriptor_bytes = 32 B shape id              the run's shape object (section 1.3)
                   u8   group                 index into shape.groups, 0xff = none (today's `base`); a shape holds at most 255 groups
                   uv n; n x uv               the unit's own entries as sorted indices into shape.entries, delta-coded (section 1.6)
                   uv k; k x (uv idx, 32 B)   env variables with a value: index into tables.envNames and the attested BLAKE3 of the value
                   bitmap(tables.envNames)    1 bit per name, ceil(len/8) bytes: the unit read it (hash ABSENT_HASH unless listed above)
                   bitmap(tables.externals)   1 bit per (name, version) pair of the tables object
                   uv m; m x (str name, str v) externals not in the table (never by construction; the decoder accepts them)
```

`uv` is an unsigned LEB128 varint (minimal, section 1.6); strings are `uv len + UTF-8`. A record's first byte
tells the format: `{` is format 1 (an envelope JSON), `v` is format 3 and its first line must be exactly `vci3`;
anything else fails `envelope`. A compressed record, should 2.10 want one, takes another first line (`vci3z`),
which 2.9 refuses: this replaces the binary frame's encoding byte, and 2.9 never decompresses anything.

Measured over 1,175 units: statement 1,100 B + LF + base64 of the 234 B signature frame 312 B + LF + base64 of
the descriptor 363 B mean (raw 272 B mean, p50 247, max 957: a node unit with 762 own entries) + the 5 B first
line = **1,783 B mean, p50 1,760, p90 1,917, max 2,707**. Rails 1,780 B, cargo 2,255 B, node 1,816 B. The binary
frame of the earlier draft would be 1,610 B with the same two digests; the text frame costs 173 B of base64 per
record (+11%) and buys the 1:1 wire on libSQL and the unchanged git-meta value path. No record of the sample holds
an apostrophe, which the libSQL text literal would double (the five v1 payloads that had one had it in a cargo
`waived` string, which now lives in the tables object).

A record decodes to exactly today's `Envelope` (statement bytes, signature) and, through its shape and tables, to
today's `InputManifest` shape minus attested file hashes (section 1.5). `vci verify --envelope` and `vci explain
--json` print a DSSE JSON envelope rebuilt from the frame (statement bytes unchanged, signature re-armored), so
in-toto tooling verifies the same bytes it verifies today.

### 1.3 Objects: `hdr`, `tables`, `shape`, `state`

An object is bytes; its id is the 32-byte BLAKE3 of the bytes (hex in statements, columns and keys). Readers
recompute the id of every object they load; a mismatch fails every candidate naming it. Objects are immutable, a
put is idempotent, and they are binary in memory and in the SQL stores' BLOB columns (SQLite, PostgreSQL); on
git-meta and on libSQL they are stored as base64 text (section 2). Canonical encoding: `magic "vo"`, `u8 kind`,
`u8 version`, body; sorted lists of paths are prefix-coded (`uv shared-with-previous`, `uv suffix-len`, suffix).
The encoding is hand-written (`vci-core::objects`, ~150 lines of encode/decode) because prefix coding of sorted
paths is the whole gain (46 B mean path to 18.6 B per shape entry including its kind byte) and a generic
serializer would not do it.

**`hdr` (kind 1).** `repoId`, `adapter`, `projectName`, `projectDir`, `runnerProject`, `toolVersion`,
`railsInputs`, `envConfigDigest` (32 B), `globalInputRoot` (32 B), then the **whole global manifest**: its
entries (sorted distinct; prefix-coded path, kind byte with the exec bit, `uv size`, 32 B hash except for the
constant-hash kinds absent/excluded/autoload-dir), its externals (sorted distinct `(name, version)` pairs, names
prefix-coded; none in the sample) and its env (sorted distinct keys, prefix-coded, each with a 32 B value hash,
`ABSENT_HASH` for an unset variable: `NODE_OPTIONS` for the twelve node units, `vci-cli`'s `global_env_keys`),
so that `Hdr::global_manifest().root()` is the `globalInputRoot` the plan checks per hdr; then `ignoredInputs`,
`envSet`, and `toolchain` (the scalar fields as compact sorted-key JSON, then `goEnv`, `pythonDists`,
`rubyGems`, `rustCfg` as prefix-coded sorted lists in that fixed order, without names). Content-addressed by
what is in it, so it is **shared across runs**: measured 4,489 B for every Rails unit of the sample (one hdr for
the 973-unit and the 185-unit runs each; they differ by base tree), 796-813 B for node (the model's 745-762 B
left the global env entry out: +51 B), 955-1,098 B for cargo; 11 distinct hdr objects across the 9 runs and 18
header groups of the sample.

**`tables` (kind 2).** Per run and header group: `waiverTable` (sorted distinct waived strings of the units
sharing the hdr), `envNames` (sorted union of env keys any of those units read, prefix-coded), `externals` (sorted
union of `(name, version)` pairs, names prefix-coded). Measured: 19,387 B for the 973-unit Rails run, 9,313 B for
the 185-unit run, 184-661 B for node, 22-74 KB for cargo (the externals table is the crate list with versions;
open question 8).

**`shape` (kind 3).** `entries`: the sorted distinct `(path, kind, exec)` over every unit of the run,
prefix-coded, one kind byte each (kinds `f l a d t x m u`, `manifest.rs:104-120`; bit 7 = exec). `groups`:
today's shared bases (`shared_manifest_bases`, `run.rs:3357`), each a delta-coded sorted index list into
`entries`, at most 255 of them. Measured: 123,264 B for the 973-unit run (6,639 entries, 18.6 B each; 36.7 KB
zstd), 24,662 B for 185 units. No sizes, no hashes: nothing in a shape depends on file content, so a `(path, kind)`
has one entry per run and there is nothing to conflict.

**`state` (kind 4).** The sorted list of `(path, kind, exec, size, hash)` over every entry of every unit of the
run (groups included), prefix-coded, 32 B hash except for constant-hash kinds. Duplicates of a `(path, kind)`
with different values (a file written during the run) are kept side by side, in sorted order. **No verdict reads
it**: it exists so `vci explain` and the plan's failure text can print the attested `expected` hash and size next
to the observed one, as today. Measured: 285,128 B for the 973-unit run (6,639 entries, 43 B each; 194 KB zstd:
the hashes are 75% of it and do not compress). It is the largest object (two thirds of a run's object bytes) and
the least needed, so it has its own retention: `[store] explain_hashes_days = 2` (default) lets `vci prune` and
`vci run`'s orphan pass delete a state object older than two days even while records reference it (the records
stay valid; `explain` then prints the observed value and `attested hash not loaded`), and `[store] explain_hashes
= false` stops writing it (the run writes three objects; the plan says `entry: <path> changed` without the
attested hash). The attested hash matters in the days right after a run, when someone asks why a unit ran.

**Groups are estimated.** `pairs.json` holds no base manifest. A group of ~440 entries (`run.rs:2895-2925`
"424 to 444 entries each") costs ~660 B of indices in the shape, plus the entries themselves if no unit lists
them on its own: 8.2 KB (one shared set of 440) to 73.5 KB (nine disjoint sets) in the shape, 19-170 KB in the
state. Every total in this document uses the high figure. Measure on the first real run (section 7).

### 1.4 How `vci run` builds a run

Per project, after the tests (`run_units`, `run.rs:2406`):

1. Group the attestable units by header tuple (`repoId`, `adapter`, project fields, `toolVersion`,
   `envConfigDigest`, `globalInputRoot`, `globalManifest`, `ignoredInputs`, `railsInputs`, `envSet`,
   `toolchain`). Rails: one group per run (checked: one value of each in the 973-unit run). cargo and node:
   several (`globalManifest` differs per unit in those adapters: 2 groups for the 3-unit cargo run, 5 for the
   5-unit node run); the record's statement names the hdr and the tables its unit belongs to.
2. Build the hdr per group (content-addressed: the put is a no-op when the previous run at the same base tree
   wrote it), the tables per group (waiver table, env names and externals are the union over the group's units),
   the shape over all units of the run (its `groups` from `shared_manifest_bases`, intersection of `(path,
   kind)`), the state over all units' entries (unless `explain_hashes = false`).
3. Per unit: the statement (with `hdr` and `tables` ids, `entriesRoot`, waived ids), sign it exactly as today
   (`SshSigner` in process, `ssh-keygen -Y sign`, or keyless), the descriptor, the text frame.
4. One deferred `WriteBatch`, queued in this order so a reader never sees a record whose objects are missing:
   `put_objects([hdr..., tables..., shape, state])`, then per unit `put_for_test`, then that unit's supersession
   removals, then (libSQL/PostgreSQL) their `gone` rows. The batch is idempotent: objects by id, records by slot
   (a retry re-sends the same signed bytes), removals by key. On libSQL the queue is sent as 2.8.2's whole-unit
   transactions of at most `TX_BYTES` (1 MiB as sent, `turso-reads` `batch.rs:106`), the object puts in the first
   one, so the ordering argument holds per transaction: a unit's put and its removals commit together, after its
   objects. 2.9 drops the 64-attestation share of a transaction (`TX_UNITS`, `batch.rs:110`, sized for 36 KB
   units) in favour of the byte bound alone, else an 800-unit partition would go in 13 transactions of 114 KB.
   The write-count model (section 2.1): 1 record put + 1.2 removals + 1.2 `gone` rows per record written, so a
   queue flushes early (`FLUSH_WRITES` 2,000, `batch.rs:95`) above ~587 units and a 970-unit partition is two
   flushes; a flush cut between units is harmless (`Pending::take_whole_units`).
5. Supersession (`superseded_by`, `run.rs:3189-3309`): the same rule as today. The old records of the unit and
   signer are **read** (1.8 KB each; today 21 KB plus a manifest decode) and `commit`, the platform
   (`toolchain.os`/`arch` through the hdr), `issuedAt` and `entriesRoot` come from each old record's **signed
   statement**; "same files" compares the two statements' `entriesRoot`. The listing columns (commit, platform,
   issued, tree16) only pre-filter which old records to read (an old record whose columns say "other platform" or
   "same commit" is skipped without a read; a column edited to say "moved on" costs one read, not a deletion).
   *Amended after the whole-branch review:* not while the store holds an input manifest (section 5 step 3): a 2.8
   writer's upsert sets a slot's key and value alone, so its format-1 value can sit beside a frame's columns naming
   another commit, and the pre-filter would leave a record the run should supersede unread (a missed deletion,
   never a wrong one); `last_durations` asks `manifest_roots` once a run and every record of the unit is read
   while one remains, as prune reads every row then.
   The columns come from `last_durations`' one `columns` round trip for every selected unit's records, by record
   key (a record stored since is read as if it had none), and the platforms of the hdr ids they name from one
   `get_objects` before the units run, so that supersession sends the store nothing per unit but the doomed
   records' reads (M3 review: it asked `columns` per unit, ~800 requests a partition on Turso). On a store without
   columns the hdr ids come from the statements `last_durations` read, and on one whose values a fetch leaves out
   (git-meta's blobless clone, section 2.2) the preload issues one `Prefetch::Objects` for them before
   `get_objects`, which fetches nothing: without it a clone that had never read the hdr kept every old record as
   made for an unknown platform and superseded nothing
   (`cargo_two_blobless_clones_supersede_the_same_attestation_and_both_push`, which 2.8 passed with format 1).
   Then `remove_objects` with the orphan rule (section 2) for the superseded records' `hdr`, `tables`, `shape` and
   `state` ids.
6. `last_durations` (`run.rs:3400`): `duration_ms` and `issued` from the listing columns on SQL stores; on
   git-meta a value read of 1.8 KB per unit (815 units: 1.45 MB, today 17 MB).

A partial or cancelled job stores what it signed: every unit is its own record, as today.

### 1.5 How a verifier checks a skip

`Verifier::check` (`plan.rs:2377-3093`) keeps its order; what changes is where a value comes from. Per plan
(`plan_with`, `plan.rs:1341`):

1. Trust and policy from the base commit: unchanged (`plan.rs:1363-1420`).
2. `list_units(ids)`: keys only, today's shape and parser. Choose candidates as today (memo, HEAD tree, base
   tree, newest, `READ_FIRST`).
3. `read_values` of the chosen candidates: ~1,644 frames of 1.8 KB. First byte `{`: today's path. `v`: the
   frame decoder (fallible; rules in section 1.6, bounds in section 4).
4. **signature**: SSHSIG or bundle over `pae("application/vnd.in-toto+json", stmt)` against the base commit's
   signers, unchanged (`plan.rs:2420-2445`). **signer** (new in 2.9): the key's signer segment (the 16 hex of
   `vci:attestation:<tk>:<signer>:…`) must equal the signer id of the verified public key (`keys.rs:27`
   `signer_id`, SHA-256 of the key blob) or of the keyless certificate's identity; a mismatch fails `signer`. One
   string compare per candidate. 2.8.1 never compared the segment (its only uses are supersession's filter,
   `run.rs:3309`, and prune's grouping, `cmds.rs:1698`), so a record copied under another signer's slot stayed
   there until that signer's history deleted it; the check makes the segment mean what the key says.
5. **statement**: predicate type v2, `VciPredicateV2` deserialization, subject = (unit, inputRoot). Collect the
   `hdr` and `tables` ids from the statement and the `shape` id from the descriptor across the round's
   candidates; one `get_objects(ids)` (deduplicated: a vex plan names ~11 hdr, ~45-59 tables and shapes).
   Recompute each object's BLAKE3; a mismatch, a missing object or a decode failure fails the candidates naming
   it (`statement` for hdr and tables, `inputs` for shape).
6. **Per distinct hdr, once per project per plan** (memoized by `(project, hdr id)`: the `Verifier` is per
   project, `plan.rs:2255-2268`, and a hdr validated for vex-web says nothing about a vex-api unit naming it):
   repo id, adapter, project, `envConfigDigest` against the base policy, `Toolchain::diff` and platform policy,
   `globalManifest.root() == globalInputRoot`, rehash every global entry, compare the current global set's root
   (`plan.rs:2633-2830`). Today this runs per candidate (25 global entries x 1,644); here per hdr, ~11 times per
   plan at the production spread (one per base tree the live candidates were made at), where one ctx per run
   would have run it 45-59 times. (M3: what the code memoizes per `(project, hdr id)` is the global manifest's
   root check and the rehash of its entries, the parts that cost; repo id, adapter, project, `envConfigDigest`,
   toolchain and platform are scalar compares that still run per candidate over the resolved view.)
7. **Per candidate**: expiry, test id, argv, result, waived ids (resolved through the tables object, re-matched
   against the base policy by key), declared inputs, dirty tree: scalars from the statement, unchanged checks.
8. **inputs**: resolve the descriptor against its tables object and shape: paths and kinds =
   `shape.entries[groups[g]] ∪ shape.entries[own indices]` (an index past the shape's length fails `inputs`), env
   entries = names from the bitmap with `ABSENT_HASH`, overridden by the `(idx, hash)` list, externals = pairs
   from the bitmap plus inline extras. Refuse autoload lookups the policy forbids, check case collisions and
   git-ignored children on the paths as today (`plan.rs:2869-2905`); the case-collision check of a shape group is
   made once per `(shape id, group)` (as `BaseCheck` does per base root) and a candidate folds its own entries
   against it, and the git-ignored children are asked about the listed directories alone (memoized per
   directory). The rest is per candidate, and measured: on the pairs replay with a synthetic vex unit of 2,700
   group and 150 own entries, step 8 cost 2.9 ms per candidate before the memo (1.5 ms of it the case
   collisions; observing 2,850 cached paths 0.7 ms; the manifest and its root 0.6 ms), 4.8 thread-seconds at
   1,644 candidates and 11.7 at 4,000, under a second of wall on the plan's pool (`tests/replay.rs`, M3 review). **Observe every path at HEAD** through the
   per-plan `CheckoutCache` (`manifest.rs:1469`: kind, exec, size, hash; listing hashes for `d` minus the
   manifest's `x` entries; autoload misses through the `u` dirs); env keys re-hashed from the child environment.
   Build the `InputManifest` from the observed entries, the attested externals and the attested env, and require
   `root() == subject.digest.blake3`. Equal means: the observed `(path, kind, exec, size, hash)` sequence is the
   attested one (BLAKE3 second preimage otherwise), which is what `same_state` per entry decides today
   (`manifest.rs:221-226`). Then run the **externals** (`plan.rs:2994-3052`) and **env** (`plan.rs:3056-3092`)
   checks unchanged on the attested lists against the resolved bundle and the child environment, with their
   policy leniencies (`libraries = "any"`, the 2.0.2 rule that drops mismatches on keys the base policy no
   longer hashes): they never enter the root recomputation, because the root is computed with the attested
   externals and env, so root equality tests the files only.
9. A failing `inputs` candidate is reported as today (`entry: <path> changed`, expected/actual) once the plan
   has the run's `state` object; the plan loads state objects for the runs of entry-failing candidates up to a
   count (`plan.state_objects = 16`, ~5 MB) in candidate-priority order (the state id is the record's listing
   column, fetched in one `columns` call per round beside the verdict objects' load, and the count cap is checked
   before the store is asked) and prints `entry: <path> changed
   (attested hash not loaded)` past it or when the object was pruned (section 1.3). A hash printed from a state
   object is labelled `attested (unsigned, from the run's state object)`, because the object is bound by nothing
   the signer signed: a store writer who replaces it can only mislabel this text, never a verdict. This is
   presentation; no verdict depends on it. Round 2's rule ("units whose candidate did not fail on an entry
   difference") keys on the `inputs` check outcome, not on the text.
10. Verdict order, rounds 2-3, flags, memo write: unchanged in meaning (`plan.rs:2235-2310`, `1855-2098`).

**Verdict objects are capped by bytes.** The plan loads hdr, tables and shape objects in candidate-priority order
(the order `Verifier::verdict` tries candidates: made on HEAD's tree, then newest issued) up to **16 MiB** of
decoded verdict objects per plan; a candidate whose objects would pass the cap fails `inputs` and the plan logs
`objects: N hdr, M tables, K shape, B bytes, C candidates past the cap`. The production spread of vex-api (live
candidates from 59 runs, the newest per unit and signer from 45; 32 of the 45 runs hold five units or fewer) needs
1.9-2.1 MB (section 3), 7.9x under the cap; a count cap of 64 runs, which the earlier draft had, would already be
within one order of the 59 observed 0.3 days into a `max_ttl` window. State objects keep a count cap (16) because
they are explain-only and the largest.

Binding table: everything the plan compares against HEAD is either in the signed statement or reached from a
digest in it (`hdr` and `tables` by id; the descriptor and shape through `root()`; `waived` ids through the signed
id list and the tables object). The store contributes paths, kinds, ids and bits; the verifier recomputes every
digest.

### 1.6 Decoder rules

These rules make two writers produce the same bytes for the same content and one id per content, and make the
decoders refuse what the harness of the security review (its attack run, not in the repository) showed
changes the root anyway. They go into `docs/CONTRACTS.md` as one paragraph under "Manifests by reference" (the
line: *a format-3 record and its objects are decoded under the rules of STORE-BACKENDS.md section N; a value or
object that breaks one fails the candidate's `envelope`, `statement` or `inputs` check, and the unit runs*).

1. **Frame.** First line exactly `vci3`; exactly three LF in the record; the statement is the bytes between the
   first and second LF, non-empty, first byte `{`; the two base64 fields are canonical: length a multiple of 4,
   the alphabet of RFC 4648 section 4, padding only at the end, unused trailing bits zero, no whitespace. Anything
   else fails `envelope`. The signature is checked over the statement bytes as found, never re-serialized.
2. **Varints.** `uv` is minimal LEB128: no continuation byte followed by a zero byte, at most 10 bytes, values
   past `u64::MAX` refused. A non-minimal encoding would give one content two ids (and an idempotent put by id
   would store both).
3. **Delta-coded indices.** The first index is absolute (`prev = -1`, so the first delta is the index itself);
   each next index is `previous + 1 + delta`. Entries are therefore strictly increasing and distinct by
   construction; every index must be below the shape's entry count, every env index below the tables' env-name
   count, every externals bit within the table, and `group` below the shape's group count or `0xff`. An inline
   external the tables object holds is refused whether or not its bit is set (a pair in the table is a bit), so
   an externals list has one encoding; the inline list is itself strictly increasing.
4. **Env overrides.** An `(idx, hash)` override whose bitmap bit is clear is refused; so is an override listing
   `ABSENT_HASH` (the bitmap already says it) and a duplicate or unsorted `idx` list. The root would be the
   same either way for a well-formed descriptor; the rule keeps one encoding per content.
5. **Paths.** Every path in a shape, a state, a `globalManifest` and an inline external is a canonical `RepoPath`
   (`RepoPath::new`'s rules: relative, no empty, `.` or `..` component, no NUL, no trailing slash); an autoload-miss
   entry (`u`) must have the `<AUTOLOAD_MARK>/<const>` form `autoload_miss` requires (`manifest.rs:529`). The entry
   lists of shape and state are strictly increasing in `(path, kind, exec)` and distinct; `groups` lists are
   strictly increasing and in range; a shape has at most 255 groups.
6. **Kinds.** The kind byte's low 7 bits must name one of `f l a d t x m u`; bit 7 is exec. The `objects.kind`
   column (and the key's `<kind>` segment on git-meta) is store data used only to choose which table or path to
   read; the decoder trusts the kind byte inside the hashed bytes and refuses an object whose inner kind is not
   the one the statement or descriptor expects.
7. **Statement values.** `waived` ids are sorted, distinct, below the waiver table's length (checked where the
   view is made, `ResolvedPredicate::v2`, the only constructor of the v2 view, so no view with an unchecked id
   exists); `storage_key` is computed from the decoded values of the resolved view (`ctx.rs:88-176`), never
   from bytes, so a writer's serialization choices cannot move a slot, and over the waived list sorted and
   distinct (`waived_canonical()`) for both versions, since a v2 statement carries no other form (section 1.1).
8. **Bounds** (section 4): the counts in every list are checked against the bytes remaining before anything is
   allocated; a record over 1 MiB, a hdr over 1 MiB, a tables over 4 MiB, a shape over 8 MiB, a state over 16 MiB
   or a `get_objects` answer over 64 MiB is refused.

The ten store-side mutations the harness ran against `root()` on unit #896 (kind relabel, index swap, omitted
entry, env override and bitmap, externals pair, an `x` under a `d`, exec bit, section confusion, duplicate rows)
are M1's negative test vectors (section 6,
`manifest_tests.rs::the_security_harness_mutations_each_move_the_root_or_fail_a_decoder_rule`): each is applied
to the decoded shape, tables or descriptor of a run built by `Run::build` over a checkout of every entry kind,
and either a decoder refuses it (the env bit cleared under a kept override; an equal shape row twice) or the
set observed at HEAD through the `CheckoutCache` has another `root()` than the signed one. A file's kind and
exec bit enter the root as the observer finds them at HEAD, never as the shape labels them, so the exec-bit
vector is the change at HEAD the flipped label would hide (the label alone changes nothing on an unchanged
file, which is the harness's last line). The observe-then-root refactor therefore cannot regress into
comparing values the store supplied.

## 2. Per-backend layout

### 2.1 SQLite, libSQL/Turso, PostgreSQL

Schema stays **version 1** while a format-1 row can exist (section 5); the additions are nullable columns and
new tables, and a `vci_schema.v2 = 1` row says they are present. The DDL runs **in a request of its own**, before
any write batch: 2.9's first write on a namespace sends it alone (a few hundred ms), or `vci store upgrade --begin`
does it ahead of the rollout; it is never part of a batch request, whose 30 s deadline a 2-4 MB transaction already
uses a third of (`txsize.json`: 4 MB in 5-10 s).

```sql
ALTER TABLE attestations ADD COLUMN format INTEGER;        -- NULL/1: envelope JSON (manifests row); 3: frame
ALTER TABLE attestations ADD COLUMN commit_id TEXT;        -- from the signed statement, filled by the writer
ALTER TABLE attestations ADD COLUMN platform TEXT;         -- "<os>-<arch>" from hdr.toolchain
ALTER TABLE attestations ADD COLUMN state INTEGER;         -- result.state
ALTER TABLE attestations ADD COLUMN duration_ms INTEGER;
ALTER TABLE attestations ADD COLUMN expires INTEGER;
ALTER TABLE attestations ADD COLUMN hdr TEXT;              -- 64-hex object ids, for the orphan queries
ALTER TABLE attestations ADD COLUMN tables_id TEXT;
ALTER TABLE attestations ADD COLUMN shape TEXT;
ALTER TABLE attestations ADD COLUMN state_obj TEXT;
ALTER TABLE attestations ADD COLUMN seq INTEGER;           -- libSQL/PostgreSQL: replica log position
CREATE INDEX attestations_hdr    ON attestations (hdr)       WHERE hdr       IS NOT NULL;
CREATE INDEX attestations_tables ON attestations (tables_id) WHERE tables_id IS NOT NULL;
CREATE INDEX attestations_shape  ON attestations (shape)     WHERE shape     IS NOT NULL;
CREATE INDEX attestations_state  ON attestations (state_obj) WHERE state_obj IS NOT NULL;
CREATE INDEX attestations_seq    ON attestations (seq);
CREATE TABLE objects (id TEXT PRIMARY KEY, kind INTEGER NOT NULL, put_at INTEGER NOT NULL, seq INTEGER,
                      bytes BLOB NOT NULL);                 -- libSQL: bytes TEXT NOT NULL, base64
CREATE INDEX objects_seq ON objects (seq);
CREATE INDEX objects_kind_put ON objects (kind, put_at);   -- the state TTL
CREATE TABLE gone (seq INTEGER PRIMARY KEY, key TEXT, object TEXT, at INTEGER NOT NULL);   -- deletions, for replicas
```

`value` stays the last column; `list_units` selects the key and the hint columns and never `value`.
`issued` and `tree16` already exist (the hint). The key string is unchanged; the SQL backends build it from
`issued`/`tree16` as they do today, and the new columns are filled by the writer from the statement it signed.
Object ids are 64-hex text in every column and key, so they travel 1:1 everywhere and index as text. PostgreSQL:
the same in schema `vci`, `COLLATE "C"` on text, `BYTEA` for `objects.bytes`, `unnest` batches.

**Object bytes per backend.** SQLite and PostgreSQL store the binary object in a BLOB/BYTEA column. git-meta
stores base64 text (section 2.2). libSQL stores base64 text too: the store sends a batch as one SQL string
(`turso-reads` `conn.rs:1747-1767` `send_batch`: `BEGIN IMMEDIATE; …; COMMIT` through `execute_batch`, every value
a literal built by `text()`/`blob()`), so there are no hrana arguments to carry a blob as base64 outside the SQL
text, and a binary object would go as a hex literal at twice its bytes; base64 in a TEXT column is 1.33x and needs
no change to the batch. The reader base64-decodes before recomputing the id (the id is of the decoded bytes on
every backend); `vci store copy` converts between the two forms. On the wire, an 800-unit partition's objects are
1.00 MB of base64 (0.33 MB without the state object) on libSQL against 0.75 MB (0.24 MB) at rest.

Statements: `get_objects` = `SELECT id, kind, bytes FROM objects WHERE id IN (...)` (tens of ids);
`put_objects` = `INSERT ... ON CONFLICT (id) DO UPDATE SET put_at = excluded.put_at`; `remove_objects(ids)` =
`DELETE FROM objects WHERE id = ?1 AND put_at < now - grace AND NOT EXISTS (SELECT 1 FROM attestations WHERE
hdr = ?1 OR tables_id = ?1 OR shape = ?1 OR state_obj = ?1)` (the manifest rule, `docs/STORE-BACKENDS.md` 324-329,
one hour of grace); `orphan_objects()` for `vci prune` is the same predicate over the table; the state TTL is
`DELETE FROM objects WHERE kind = 4 AND put_at < now - explain_hashes_days`, run by `vci prune` and by `vci run`'s
orphan pass, with a `gone` row per object so replicas drop it too.

**The write per partition** is one deferred `WriteBatch` of 4 object puts + N record upserts + 1.2 N removals +
1.2 N `gone` rows (production 27 Oct: 64,383 removals for 53,650 records attempted, `rails.json` `wb` columns; a
removal is a slot whose files changed at a commit that moved on). Writes = 4 + 3.4 N: an 800-unit partition is
2,724 writes and 2.18 MB at rest (2.43 MB on the libSQL wire), the 970-unit maximum 3,302 writes and 2.41 MB
(2.64 MB); the queue flushes early at 2,000 writes (`FLUSH_WRITES`, `turso-reads` `batch.rs:95`; the 4 MiB
`FLUSH_BYTES` never triggers), so a run above ~587 units is two flushes: 83 of the 142 jobs of 27 October with a
count (mean 540 attempted, max 972) are, and none reaches the 1,175 units a third flush would take. Each flush is
sent as transactions of at most 1 MiB as sent (`TX_BYTES`,
section 1.4): three for 800 units with the state object, two without, each holding the single writer's lock for
the 1.8-3.7 s `txsize.json` measured for 1 MB (0.5 MB: 1.5-1.7 s; 2 MB: 2.5-10.6 s; 4 MB: 5.0-10.2 s; 8 MB:
33.6-36.8 s, which is what today's 6.6-8 MiB batches met at the 30 s timeout, 30,118 units lost in 164 jobs). 51%
of plans overlap another job (up to 4, `rails.json` `p1.conc`), so a partition's 4-11 s of lock is taken in 1 MiB
slices other writers interleave with, and a job's memo write queues for a slice, not for a 15-37 s batch. The batch
sets `seq` on every row it touches from a counter in `vci_schema`, inside the transaction: on PostgreSQL the
counter row's lock is held to commit, which hands out `seq` in commit order and serialises the writers of a
namespace for the length of a transaction (an ordering cost, not a safety one); on libSQL there is one writer.

**libSQL replica log.** The per-slot, per-root `log` table (`remote.rs:112`, ~400k rows/day) is not written for
format-3 records. A replica syncs `attestations WHERE seq > ?` (the frames: a format-1 row this vci writes is in
the old log and is synced by it, once) and `gone WHERE seq > ?`; a first sync reads the namespace (one listing,
the values). **In 2.9.0 the replica file keeps no objects and no columns**: a replica's `get_objects`, `columns`,
`prefetch(Objects)`, `orphan_objects`, `remove_objects` and `prune_state_objects` ask the server (as
`orphan_manifests` does), and a write's objects and columns are not written through (M2 review, STORE-V2-DECISIONS.md). What
that costs: a replica plan reads its verdict objects from the server, 1.4-1.9 MB per plan at vex (section 3), and
a replica cut off from the server verifies no format-3 candidate (every such unit runs: fail-open). Syncing
`objects WHERE seq > ?` (base64 text decoded into the file's BLOB column), the object ids of `gone` and the columns
is a 2.9.x change, with no change to the server's tables. `gone` grows by the removals: ~64k
rows and 13.8 MB a day at vex (214 B a row: the key, `seq`, `at`, the object id when it is an object), purged
after **max(30 days, the policy's `max_ttl`)**, so that no record a replica could still serve outlives the
deletion it would have synced (a `gone` row younger than every unexpired record it could affect); 1.93 M rows and
413 MB at 30 days, six times fewer rows than today's log. A replica whose cursor is older than the purge horizon
does a **full resync** instead of an incremental one (the horizon is stored in `vci_schema`, so the replica can
tell). Format-1 rows written by a 2.8 client during the window keep using the old log, and a 2.9 replica reads
both; a 2.8 replica syncing the old log never learns of format-3 deletions and keeps superseded rows until they
expire (fail-open: their inputs mismatch at HEAD; section 5).

**Memo.** Unchanged: today's `memo` table, `remember_passing` as one multi-row upsert per plan
(`turso-reads` `remote.rs:1674-1701`, `upsert_memo` with the rows joined; `sql.rs:259`), `MEMO_KEEP_SECS` of 7
days. Its 0.8 s median and 30 s maximum in production (`rails.json` `memo`) track the write-batch times (`wb` p50
3.1 s, p90 19.8 s, max 30 s): it is the single writer's queue behind 6.6-8 MiB batches, not the statement, and
shrinks with them. The earlier draft's `memo2` (one row per plan holding the passed keys) is dropped: it solved a
problem the current code does not have and would have tripled the bytes `passing_on` reads (109 KB per plan row
mean, 309 KB max, up to 24 rows per tree with 12 shards). The memo stays optional: nothing about trust depends on
it, and with `tree16` a column the chooser works without it (open question 5).

**Prune** (`cmds.rs:1637-1800`): `list_all` with the hint columns gives expiry, issued, tree, unit, signer per
key without values; the expired candidates are then **read** (1.8 KB each) and deleted only when the signed
`expiresAt` has passed; a unit and signer with a record beyond `keep` by the hints has every described record
read, and the signed `issuedAt` and `tree` order the group as they do on a store without columns (a record the
hints put beyond `keep` that the statements keep is left alone as unconfirmed). So a store writer who edits a
column or a key's hint can cause extra value reads (the row's, or its unit's), not a wrong deletion. While the
store holds an input manifest (the migration window, section 5 step 3: a 2.8 writer that reuses a frame's slot
leaves the frame's columns beside its format-1 value, and only the value says what the row is and which manifest
it references) every row is read, as 2.8 read them; once no manifest remains the columns describe the format-3
rows and nothing a column could hide references anything. A manifest the backend keeps against the delete (a
referrer stored since the listing, or a shared store's grace) is said so and not counted. Then `orphan_objects()`
and the state TTL. `vci prune --objects --older-than <days>` overrides `explain_hashes_days` for one run.

### 2.2 git-meta (`refs/meta/main`)

Records keep their keys and paths: `vci:attestation:<tk>:<signer>:<sk>:<issued hex>.<tree16>`, filed under
`path:<unit>` or `project` as today (`meta.rs:1307-1311`); the exchange, tombstones, blobless fetch, lazy blob
batches (`FETCH_BLOB_BATCH`), incremental merge and `hydrate_units_choosing` are untouched. The hint keeps its
two fields: the key is public output (`by.metaKey`), and the SQL stores carry the extra columns instead. What
git-meta pays for that: `vci run`'s `last_durations` and supersession read values (1.8 KB each, ~1.5 + ~2.7 MB
per 800-unit partition, today 17 MB + 45 MB) and `vci prune` reads every value (24,000 x 1.8 KB = 43 MB, today
870 MB).

Objects: keys `vci:object:<kind>:<id hex>` under target `project`, paths `vci/object/<kind>/<id>/__value`: four
blobs and a few trees per run (today: 800 manifest blobs and 9 bases per run, ~1,600 trees). `prefetch(Objects
{ids})` fetches their blobs in the existing batch path. `orphan_objects` and `remove_objects` **read every
value**: any record on any target can name an object, so there is no scoped referrer scan like
`hydrate_manifest_referrers`' (a manifest's referrers are on the paths it lists), and the scan fetches every
attestation not fetched yet (`hydrate_attestations`) and reads each value once. That is `vci prune`'s cost (24,000 x
1.8 KB = 43 MB on vex, above), not a per-run one: `vci run` calls `remove_objects` after supersession only on a
store with columns (SQLite, PostgreSQL, libSQL), and on git-meta leaves the superseded run's objects to `vci
prune`, which has read every value already; the per-partition budget above holds. (M2 review, STORE-V2-DECISIONS.md.) The
merge-time "put back a manifest another clone
references" rule (`docs/CONTRACTS.md` "A clone deletes a manifest knowing only its own attestations") applies to
objects as written, by id. `meta:prune:max-keys` counts objects as keys: a few per run instead of 800.

**Values stay strings.** The record is UTF-8 text (section 1.2) and an object is stored as base64 text (1.33x of
its bytes: 0.33 MB per 800-unit partition, 1.0 MB with the state object), decoded in `get_objects`. The git-meta
`Reader` reads values through `String::from_utf8_lossy` (`meta.rs:1021`) and rule 3 of `docs/STORE-BACKENDS.md`
says UTF-8 only; both stand, and `vci-git` gets no bytes read path, no change to `materialize`, `fast-import` or
the `git-meta.sqlite` `value` column. The earlier draft's bytes path was the plan's top risk and is gone.

**Pack growth, measured** (`docs/design/measure/gitmeta.py`: git-meta's tree layout built from the 973-unit run as commit
A and the 185-unit run pushed as commit B, today's values against text frames and base64 objects, real `git
pack-objects --thin` and `git repack -adf`): today's push of B is 0.643 MB (3.47 KB per unit), 1,761 trees + 379
blobs; format 3's is 0.272 MB (1.47 KB per unit), 1,573 trees + 188 blobs; the pack of A alone 3.88 MB against
1.34 MB, the repacked A+B 4.47 MB against 1.58 MB. So an 800-unit push is **~2.8 MB today and ~1.2 MB in format 3:
2.4x fewer bytes and 18% fewer objects**, not the 9x the earlier draft estimated, because git already deltas
today's envelopes (90% shared text) about 9x inside a pack, and **trees per record are unchanged** (7-8.5 per
record: the 7-segment key path; trees are 89% of a format-3 push's objects and 23% of its bytes). The 1.8 GB pack
of the task description would have been ~0.65-0.75 GB over the same period. The text frame costs 5% over the
binary frame on git-meta (0.272 against 0.258 MB per push; the base64 does not delta). To move the git-meta
number further, the tree count per record has to drop: filing records under `project` or a two-level fan-out of
the key path (`vci/attestation/<tk[:2]>/<tk>/…`) cuts the chain, but changing key paths changes `by.metaKey` and
every clone's layout and is **a 2.10 question**, out of scope for 2.9; at 164 pushes a day of 540 units that is
~750k new tree objects a day either way, and `meta.rs:717`'s pack-index read time and repack cost are not changed
by this design.

## 3. Measured numbers

Script: `docs/design/measure/measure.py` (`python3 -I measure.py <pairs.json> <rails.json> <keys.json>
<txsize.json> <out dir>`, the private inputs of the preamble), output `numbers.json` and `measure-output.txt`. Bases/groups are
estimated (section 1.3) and every total uses the high estimate; "today" is the file's own envelopes and manifests
plus 9 bases of 50 KB per run where a run is counted. Per-run objects for a run of N units come from the measured
curve of random N-unit subsets of the 973-unit run (`numbers.json` `curve_hdr_tables_shape_state_entries`), groups
scaled by N/800.

| | today | format 3 | note |
|---|---:|---:|---|
| statement (signed) | 15,461 B decoded, 20,616 B base64 | 1,100 B (p50 1,100, max 1,601) | +76 B for the second digest |
| signature | 477 B JSON field | 234 B frame (180 B SSHSIG + keyid), 312 B as base64 | |
| manifest / descriptor | 15,154 B (p50 11,372, max 98,539) | 272 B (p50 247, max 957), 363 B as base64 | |
| **record** | **36,320 B** | **1,783 B** (p50 1,760, p90 1,917, max 2,707; binary frame would be 1,610) | 20x |
| hdr, shared across runs | (in every envelope: 14.1 KB x N) | 4,489 B Rails; 0.8 KB node; 1.0-1.1 KB cargo | 11 distinct / 9 runs |
| tables per run | (in every envelope and manifest) | 19,387 B (973 units); 9,313 B (185 units); 0.2-0.7 KB node; 22-74 KB cargo | the externals list |
| shape per run | (in every manifest) | 123,264 B / 6,639 entries (973 units); 24,662 B (185 units) | 18.6 B/entry |
| state per run (explain only, 2 days) | (in every manifest) | 285,128 B (973 units); 60,758 B (185 units) | 43 B/entry; 1.5x under zstd |
| groups per run (estimated) | 9 x ~50 KB | +8-74 KB shape, +19-170 KB state | high figure used below |
| at rest, 1,175 units, 9 runs | 42.68 MB | records 2.09 MB + hdr 0.01 + tables 0.26 + shape 0.17 + groups 0.72 + state 0.39 = **3.65 MB, 3,108 B/unit** | 11.7x; 13.1x without state |
| 516-unit half of the 973-unit run (a partition) | 20.2 MB, 1,041 rows | records 0.93 MB + hdr 4 KB + tables 19 KB + shape 91 KB + groups 79 KB + state 218 KB = **1.34 MB, 520 rows** | 14.7x |
| **800-unit partition, scaled** | **29.5 MB, 1,609 rows, 5 batches** | **2.18 MB at rest, 2.43 MB on the libSQL wire, 804 rows, 2,724 writes, 2 flushes, 3 transactions ≤ 1 MiB** (1.67 / 1.75 MB, 2 transactions without state) | 13.5x (17.7x) |
| 970-unit partition (production maximum) | ~35.7 MB | 2.41 MB at rest, 2.64 MB wire, 974 rows, 3,302 writes, 2 flushes, 3 transactions | |
| 540-unit partition (mean attempted) / 328 (mean attested) | 20.1 / 12.4 MB | 1.45 MB at rest, 1.62 MB wire, 1,840 writes, 1 flush, 2 transactions / 0.93 MB, 1.04 MB wire, 1,119 writes, 1 flush, 1 transaction | |
| libSQL lock held per partition (`txsize.json`) | 5 x 6.6-8 MiB batches, 33.6-36.8 s each at 8 MB, timeouts | 2-3 transactions of ≤ 1 MiB at 1.8-3.7 s each: 4-11 s in slices | |
| plan: listing (2,305 units x 1.9 x 190 B) | 0.83 MB | 0.83 MB (+60 B/row of columns on SQL, read with the listing) | unchanged |
| plan: 1,644 values | 59.7 MB (+bases) | 2.93 MB | 20x |
| plan: per-run verdict objects (tables + shape + groups), plus hdr once per base tree | ~450 KB of bases per run | 240 KB per 800-unit run; 2-9 KB per run of ≤ 5 units; hdr 4.5 KB each, ~11 per plan | |
| **plan total, candidates from 4 / 10 / 20 / 50 runs** (today: 1,644 values + 9 bases of 50 KB per run; format 3 at the ceiling of one hdr per run) | 62 / 65 / 70 / 83 MB | **4.7 / 6.2 / 8.7 / 16.0 MB**; +0.5 MB per run whose state object is loaded for failure text (capped at 16) | 13x / 10x / 8x / 5x |
| **plan total at the production spread** (`keys.json`: live candidates from 59 runs, the newest per unit and signer from 45) | ~81-87 MB | **5.1 MB (45 runs) to 5.7 MB (59 runs)** expected with 11 hdr; 5.3-5.9 MB at the one-hdr-per-run ceiling; verdict objects 1.35-1.91 MB (ceiling 1.50-2.13 MB), 7.9x under the 16 MiB cap | 15x |
| plan requests (libSQL) | list 1, prefetch 4, manifests 1-2, memo 2-3 | list 1, read_values 1-2, get_objects 1, columns 1 (per round, for the state ids), state 0-1, memo 1-2 | |
| signature checks per plan | 1,644 | 1,644 (0.3 thread-s measured; not a cost) + 1,644 signer-segment compares | |
| per day at vex (`rails.json`: 164 Rails jobs = 164 runs, 76,725 units attempted, mean 540, max 972) | 2.79 GB written | records 137 MB + hdr ≤ 0.6 + tables 2.4 + shape 18.8 + state 42.4 = **201 MB** (158 MB without state) | 13.9x (17.6x) |
| per day at the attested count (46,644 units, mean 328) | 1.69 GB | 123 MB (97 MB without state) | 13.7x |
| libSQL log rows / `gone` rows / memo rows per day | ~400k / - / ~189k | 0 / ~64k (13.8 MB) / ~189k | |
| `vci run`: last_durations, supersession reads | 17 MB + 45 MB | 0 + ~2.7 MB (SQL; 800 units x 1.9 old records x 1.8 KB; one listing, one `columns` and one `get_objects` of the hdr ids for the run, no request per unit), 1.45 + ~2.7 MB (git-meta) | |
| `vci prune` reads | every value, ~870 MB at 24k records | columns + ~1.8 KB per doomed record (SQL); 43 MB (git-meta) | |
| a dead run (every record superseded) | 800 manifests + 9 bases, never collected by `vci run` | 4 objects, 0.75 MB (0.25 MB after the state's two days), collected by `vci run`'s orphan pass or `vci prune` | |
| cross-commit stability (6 units at 2 commits) | | same `(path, kind)` set 6/6; same root 0/6; 804 of 813 entries common to the two largest runs keep size and hash | why hashes left the record |

The alternative of writing the own `(path, kind)` set inline in each record instead of as indices into a shape
(the manifest/radical layout) measured 2,610 B per binary record (manifest part 1,348 B mean, 850 p50) and 2.69
MB per partition in the earlier draft: 0.7 MB more per partition and 1.7 MB more per plan than the shape, for no
object fewer (the groups are per run either way). The shape wins because 88.8% of a run's delta entries are
copies of another unit's.

**Steady state on the hosted service** (from the 27 October rates; ceilings assume every run of the last 14 days,
vex's `max_ttl`, keeps one live record, which the orphan rule requires before its objects go; a record of an
unchanged unit lives until `max_ttl` because supersession removes only a record whose files changed at a commit
that moved on, `run.rs:3189-3309`):

| | bytes | note |
|---|---:|---|
| live records: 2,305 units x 1.9 candidates x signers ≈ 4,400-24,000 rows | 8-43 MB | at 1.78 KB |
| hdr objects | ≤ 9 MB | ceiling: one per run for 14 days; expected a few hundred KB (one per base tree per project) |
| tables + shape objects | ≤ 296 MB ceiling | 14 days x 21.1 MB/day; the listing of 27 Oct 15:20 shows 59 live runs for vex-api ≈ 1.9 MB, 0.3 days after a full re-attestation; a dashboard count of live runs per namespace is in section 7 |
| state objects at the 2-day default | 85 MB | 2 x 42.4 MB/day; it would be 594 MB at 14 days, which is why the TTL is 2 days; 0 with `explain_hashes = false` |
| `gone` rows | 413 MB, 1.93 M rows | 30 days x 64k x 214 B; today's log is ~12 M rows over the same window |
| **total ceiling** | **~850 MB** | today ~0.9-1.6 GB; the expected figure is a few hundred MB, most of it the `gone` log, not the objects. The earlier draft's "12.7x at rest" was the write-snapshot ratio, not this |

Expected plan time (production medians, `rails.json`: plan 1 13.1 s, max 74 s): `pf` 1.3 s median / 21 s max
for ~35 MB becomes ~3-6 MB; `reads` 1.5-2 s of base64 + JSON + manifest decode becomes a few hundred ms; the
memo write (0.8 s median / 30 s max) is the same statement behind a lock that is now held in 1 MiB slices; the
global-inputs rehash runs per hdr (~11), not per candidate (1,644). Unchanged: `git fetch`, toolchain resolve
(0.85 s), Rails boot, the checkout rehash (3,184-5,191 entries). A fair expectation is plan 1 at ~8-10 s median
with the 20-30 s store stalls gone.

## 4. Security argument

Against `docs/CONTRACTS.md` "vci-cli predicate and storage" and "Manifests by reference", and
`docs/STORE-BACKENDS.md` section 1 ("The store is never trusted", rules 1-4). The security review's harness
(a program run outside the repository) ran vci 2.8.1's real
`InputManifest::root()` on a real vex unit against ten store-side mutations and found no wrong skip; its findings
were documentation accuracy and spec tightening, resolved below and in section 1.6.

**What is trusted**: the base commit's signer files; a signature over the exact statement bytes by a key or
identity those files trust; digests the verifier recomputes. Everything else (keys, hint and index columns,
descriptors, objects, memo, flags) orders reads or is checked against a signed digest. The statement binds, as
today, the unit (`subject`, `testId`, `argv`), repo/adapter/project/toolchain/env-config/global inputs (now
through `hdr`'s signed id), the tables (through `tables`' signed id), times, result, taint, waived (ids, signed)
and declared sets, commit and tree.

**An attacker who can write to the store** (a read-write Turso token, a push to `refs/meta/main`):

- Delete or corrupt records, objects, columns, hints: units run. Same as today.
- Replace a descriptor, a shape, or which shape a record names: the resolved `(path, kind)` set is re-observed
  at HEAD and `root()` over the observation must equal the signed subject digest; naming fewer, more or other
  paths changes the hashed sequence. Producing another set whose observation at HEAD hashes to the signed root
  is a second preimage of BLAKE3. This is the bound `manifestRef == root()` gives today (`plan.rs:2838-2864`),
  with HEAD's values standing in for the attested ones, which is what today's per-entry `same_state` compares
  anyway. `root()` (`manifest.rs:1130`) is BLAKE3 over a domain tag and u64-length-prefixed fields with
  per-section counts (`hash.rs:27-50`), so no partition of (entries, externals, env) or relabelling of a kind can
  alias, and the observer (`observe_as`, `manifest.rs:402`; `CheckoutCache::observe`, 799) reports HEAD's actual
  type, size and hash, using the attested kind only to choose type-only versus listing for directories: the
  harness's kind relabel, index swap, omitted entry, env override and bitmap flip, externals pair, hidden `x`
  under a `d`, exec bit, section confusion and duplicate rows all changed the root. A sanity check the
  implementation keeps: the candidate's env/externals bitmaps and the tables are attested data and enter the
  root, so a store cannot move a mismatch from the files to a lenient class.
- Replace a hdr or a tables object: its BLAKE3 must equal the signed id. A waiver table with more or other
  strings changes the id; the signed ids resolve against the signed table or fail.
- Replace a state object: nothing reads it for a verdict; a wrong one mislabels `explain`'s expected hash, which
  is why that text says `attested (unsigned, from the run's state object)` (section 1.5 step 9). Binding the
  state id into the statement (32 B) would make the label trustworthy and is not done in 2.9: the object is
  pruned after two days by default, and a label on an explain line is not a trust decision.
- Replay a record under another unit, slot or signer: `testId` and `subject` are signed and compared with the
  unit (`plan.rs:2523-2631`); the hdr binds repo and project; the per-hdr memo is per project (section 1.5 step
  6), so a hdr validated for one project of a plan is validated again for another, and argv's `--root
  <projectDir>` still separates projects whose test ids coincide (node). The key's signer segment is **checked
  against the verified key** (section 1.5 step 4, new in 2.9): 2.8.1 verified the SSHSIG's embedded key against
  the allowed signers and accepted the record under whichever signer's slot it sat in, which let a store writer
  move a record out of its signer's namespace so that signer's next run no longer superseded it (availability
  only: policy decisions use `verified.principal`, `plan.rs:2447`, never the segment). In 2.9 such a record fails
  `signer` and the unit runs.
- Edit the index columns (commit, platform, duration, expires): they choose, order and pre-filter; supersession
  and prune take commit, platform, `issuedAt` and `entriesRoot` from the old record's signed statement before
  deleting (sections 1.4 step 5, 2.1); a column edited to lure a read costs one 1.8 KB read; a wrong
  `duration_ms` reorders a run. Availability effects a deleter already has.
- Serve a stale but unexpired record after supersession: possible today; `max_ttl` bounds it. A stale replica
  (one that missed `gone` rows) keeps a superseded record, whose inputs mismatch at HEAD unless the files were
  reverted, in which case the skip is correct; the purge horizon of `gone` is at least `max_ttl` and a replica
  past it resyncs in full (section 2.1), so no deletion is silently missed.
- Overwrite a slot with an older record (a delayed retry of job A after job B wrote the same slot): the same slot
  means the same storage key, hence the same input root, toolchain, argv and waived set, and `vci run` never
  stores a non-pass (`run.rs:1504`; `pairs.json` holds 1,173 passed and 2 no-tests), so the overwrite exchanges
  two passes on identical inputs and hides nothing.
- Oversized or malformed values and objects: every decoder is fallible with declared bounds (section 1.6):
  record ≤ 1 MiB (largest real 2.7 KB), hdr ≤ 1 MiB (75 KB today's largest ctx), tables ≤ 4 MiB (74 KB), shape ≤ 8
  MiB (123 KB), state ≤ 16 MiB (285 KB), a `get_objects` answer ≤ 64 MiB, verdict objects ≤ 16 MiB per plan,
  state objects ≤ 16 per plan, counts checked against the remaining bytes before allocation. No compression: no
  decompression amplification (a `vci3z` first line is refused by 2.9 and fails the candidate).
- Serve many forged records: each is verified on its own as today; the per-hdr memo is keyed by `(project, id)`,
  so a forged hdr costs one object decode per project.
- Name a path outside the repository in a shape (`../../.ssh/id_ed25519`), hoping the failure text prints its
  size and hash: `RepoPath::new` refuses `..`, absolute and empty paths (the harness checked) and the decoder
  resolves to `RepoPath` only (section 1.6 rule 5).

**A compromised signer** can sign a statement that claims a pass for any unit of any repository with inputs of
its choosing, as today; the hdr and tables indirection does not widen it (both ids are signed, and an object is
only as trusted as the statements that name it). Revocation is per signer in the base commit's files, as today.

**Shared objects across signers**: a shape written by a pull-request signer and named by a master signer's
descriptor is fine; the master record's root binds the content, not the writer. A PR writer deleting or pruning
objects master's records name makes units run, as deleting manifests does today.

**What is not signed and why that is acceptable**: the descriptor (bound by the root), the hdr, tables and shape
bytes (bound by id and root), the state object (never decides, labelled unsigned), the hint and columns (choose
and pre-filter only). No Merkle tree, no new hash construction and no new policy surface on the trust path; the
one new domain tag is `entriesRoot`, which decides only what `vci run` deletes.

**New invariant for CONTRACTS.md**: *a v2 predicate's `hdr` and `tables` name objects whose BLAKE3 is that id,
and the candidate's manifest is the descriptor resolved against the tables and the shape it names, observed at
HEAD, whose `root()` with the attested externals and env equals the subject digest; a predicate whose hdr,
tables or shape is missing, mismatched or malformed under the decoder rules fails `statement` or `inputs` and the
unit runs; the key's signer segment equals the verified key's signer id or the candidate fails `signer`;
supersession and prune delete on the signed statement's values only.* Rules 1 (identical keys), 2 (foreign keys
ignored), 3 (values are UTF-8) and 4 (bytewise order) of STORE-BACKENDS.md hold unchanged.

## 5. Migration and compatibility

Version gates, in order:

1. **vci 2.9.0** reads format 1 and 3, writes format 3 (`[store] record_format = 1` keeps writing format 1 for
   one release, for fleets that cannot upgrade every reader at once). Detection is by the value's first byte
   (`{` vs `v`); keys and slots are shared, so a format-3 record overwrites the format-1 record of its slot
   and vice versa, with one exception: a unit whose 2.8 record's `waived` list repeated a string or was unsorted
   (almost every Rails unit of the sample) keys another slot under 2.9, since the key now takes the list sorted
   and distinct (section 1.1); the 2.8 record then stays beside the new one as a second candidate until
   supersession or expiry removes it, which is fail-open and costs one more candidate per such test.
   `VciPredicate` (v1) and `ManifestLoader` stay for v1 records; v1 and v2 meet at
   `ResolvedPredicate` and the resolved manifest, and `Verifier::check` runs on the view.
2. **SQL schema, DDL first**: `vci_schema.version` stays 1 while the migration window is open. The nullable
   columns, the `objects` and `gone` tables and the `v2 = 1` flag row are added by `vci store upgrade --begin`
   (2.9, idempotent, `ALTER TABLE ADD COLUMN`, `CREATE TABLE IF NOT EXISTS`) or, on a namespace that lacks them,
   by 2.9's first write **in a request of its own before its batch** (never inside a batch request: a 2-4 MB
   transaction already takes 5-10 s of the 30 s deadline, `txsize.json`). A **2.8 binary** on such a namespace
   sees version 1, lists keys with its own parser (the keys are unchanged), reads a format-3 value it cannot
   parse and fails `envelope`: the unit runs; it keeps planning on any format-1 rows until they expire; its own
   writes are format-1 rows with NULL in the new columns, which 2.9 reads through the v1 path. Nothing breaks,
   skips are lost per unit until the binary is upgraded. vex pins the action and binary in every workflow; the
   upgrade is one PR and the skip rate dips for at most one `max_ttl` window, in practice one job per partition.
3. **2.8's `vci prune` during the window** stops collecting manifests once one format-3 record exists: for a
   record `envelope_meta` cannot parse it sets `referenced = None` (`cmds.rs:1703-1722`) and then removes no
   manifest at all, by design (it cannot know what the unreadable record references). vex's master attest jobs
   run `vci prune` after every project with the pinned binary (`vci.yml:203`), and the orphan pile grew by up to
   16,231 manifests an hour at peak (a production query of 27 October), so the window should be short: land the action pin before
   the next master push, or run 2.9's `prune` (which collects both) once during the window. 2.9's `prune` reads
   every record while the store holds an input manifest (a 2.8 writer may have left its format-1 value, with its
   `manifestRef`, under a frame's columns: M2 fact 1), and once none remains treats a format-3 record through its
   columns and confirming read.
4. **`vci store upgrade --finish`** (2.9, manual, on SQLite and PostgreSQL; 2.10 on libSQL, and 2.10 automatic
   when no format-1 row remains): drops `manifests` and the libSQL `log`, sets `vci_schema.version = 2`; from then
   on a 2.8 binary reports "store schema too new" and fails open as it does today for unknown versions. The `memo`
   table stays. *Amended after the whole-branch review:* on libSQL every statement that names `manifests` and the
   log has to branch on version 2 first, which 2.9.0 does not carry, so its `--finish` is refused with the count
   while a format-1 row remains and at zero prints `vci: error: the libsql store does not support finishing the
   format-3 upgrade (dropping the manifests table and the change log): a later vci does it` (exit 2); a libSQL
   namespace stays at version 1 for the whole of 2.9, the "too new" guard against a 2.8 writer never arrives there
   (the operator rotates the write token or runs `vci update` on every machine that writes), and each 2.8 write
   re-opens the window of step 3 until a 2.9 prune or supersession removes its manifest.
5. **git-meta**: no schema; a 2.8 clone reads keys it knows and values it cannot parse (fail open), ignores
   `vci:object:` keys (rule 2), and never deletes keys it does not parse. A 2.8 client reading a `vci3` record
   through `from_utf8_lossy` gets the text and fails `envelope` (it is not JSON). No bytes path, no value-type
   change in `git-meta.sqlite`.
6. **Existing records** keep working until they expire (`max_ttl` 14 d on vex) or are superseded by the next
   run; no re-signing (a format-1 statement's bytes are what was signed and stay readable). `vci prune` then
   drops the `manifests` rows. `vci store copy` between backends copies format-3 values byte for byte and objects
   decoded (BLOB on SQLite/PostgreSQL, base64 on libSQL and git-meta), objects before records.
7. **Replicas**: a 2.9 libSQL replica syncs the old log for format-1 rows and `seq`/`gone` for format-3 (its
   objects and columns come from the server in 2.9.0, section 2.1); a replica file of a 2.8 namespace does one full resync (1.4-4.4 s today for 1,600-6,500 records, less with 13x
   fewer bytes), as does a 2.9 replica whose cursor is older than the `gone` purge horizon. A 2.8 replica syncs
   format-1 only and never sees format-3 deletions: it keeps superseded rows until their signed `expiresAt`
   (fail-open, their inputs mismatch at HEAD); the replica file should be upgraded with the binary.
8. **Plan JSON and `vci explain`**: same keys, targets and check names plus the `signer` check's new failure
   text; `by.metaKey` byte-identical (the key did not change). `expected`/`actual` texts unchanged in content
   where the state object is loaded, labelled `attested (unsigned, from the run's state object)`; otherwise the
   observed value and `(attested hash not loaded)`. `vci verify --envelope` prints the rebuilt DSSE envelope;
   `--manifest FILE` accepts the compact JSON of the resolved manifest (`to_compact`) for a format-3 record.
9. **Rollback**: 2.9 with `record_format = 1` writes what 2.8 writes; a store that already holds format-3 rows
   serves them to 2.8 as fail-open units. Downgrading the binary after `--finish` is not supported (the
   `manifests` table is gone); `--finish` is refused while a format-1 row exists and prints the count. The count is by the value's first
   byte on every SQL backend (a frame starts with `v` and is never stored compressed), never by the `format`
   column: a 2.8 writer's upsert sets the key and the value alone, so a format-1 value it writes into a frame's
   slot sits beside the frame's `format = 3`, and a frame put without columns (a copy out of git-meta) has NULL.

## 6. Implementation plan by crate

Three releases: 2.9.0 (read both, write format 3), 2.9.x (dashboards, the live-runs count), 2.10 (`--finish`
automatic, format-1 read path kept but untested against new fixtures, the key-path fan-out question). ~5,400 lines
of code, ~1,900 of tests and docs.

| milestone | crate / file | change | size |
|---|---|---|---|
| **M1 core (pure, no store)** | `vci-core/src/objects.rs` (new) | `uv`, strings, prefix coding, canonical base64; `Hdr`, `Tables`, `Shape`, `State` encode/decode/id with bounds and the decoder rules of section 1.6; `Descriptor` encode and `resolve(&Shape, &Tables) -> ResolvedManifest { set: Vec<(RepoPath, EntryKind, exec)>, externals, env }`; `groups` | ~850 + 400 tests |
| | `vci-core/src/predicate.rs` | `VciPredicateV2 { own, hdr: Hex32, tables: Hex32 }`, `Header` (from hdr), `Tables`, `ResolvedPredicate<'a>` giving the v1 accessors; `Toolchain` to/from the hdr encoding; waived ids | ~350 + 150 tests |
| | `vci-core/src/manifest.rs` | `entries_root()`; `InputManifest::from_observed(resolved, observed entries)`; `to_compact` for export; `observe(set, &CheckoutCache)` factored out of `diff_against_cache_from` | ~200 + 100 tests |
| | `vci-attest/src/lib.rs` | text record frame (`Envelope::from_frame`/`to_frame`, the `vci3` first line, canonical base64), raw SSHSIG in/out of armor, bundle kind, rebuild to DSSE JSON | ~250 + 100 tests |
| | tests | round-trip and golden vectors from `pairs.json`-shaped fixtures; the replay check (`vci-cli/tests/replay.rs`, in vci-cli because it needs vci-attest's frame beside vci-core, and a dev-dependency of vci-core on vci-attest would put vci-attest's sources among the inputs of `vci attest crates/vci-core#lib`, which `e2e_cargo.rs` checks are clean): for all 1,175 sample units the descriptor resolves to the manifest's set, externals and env, and `root()` of the resolved set with the attested hashes equals the root of the unit's own entries and `entriesRoot` equals the signed one; the signed subject digest is reproduced for the three base-less units only, since the sample holds the deltas and not the 11 base manifests they reference (the full-set check against the subject digest for every unit is M3's end-to-end fixture, where the bases are in the store); the security harness's ten mutations as negative cases (each changes the root or fails a decoder rule, `manifest_tests.rs`); bounds and malformed-object cases; non-minimal varints, non-canonical base64, a clear-bit env override, a 256th group, a `..` path | |
| **M2 store trait and backends** | `vci-store/src/lib.rs` | `get_objects`, `put_objects`, `remove_objects`, `orphan_objects`, `prune_state_objects(older_than)`, `Prefetch::Objects`; `StoredEnvelope` listing columns (optional, `None` on git-meta); `decode_record` over both formats; `WriteBatch` object puts and `gone`; conformance cases c-objects-1..n (idempotent put, orphan rule with grace, state TTL, bounds, ordering visible to readers, columns match the statement, base64 and BLOB forms read back equal) | ~600 + 500 tests |
| | `vci-store-sqlite` | columns, `objects`, `gone`, `v2` flag; `vci store upgrade --begin` / `--finish` | ~400 |
| | `vci-store-postgres` | same, `BYTEA`, `unnest` puts, the `seq` counter row lock noted in the docs | ~300 |
| | `vci-store-libsql` | same with `objects.bytes TEXT` base64; the DDL request before the first batch; `seq` counter in the batch; replica sync of `attestations`/`gone` by `seq` alongside the old log (objects and columns from the server in 2.9.0, section 2.1), the purge horizon and the full-resync rule; transactions sized by bytes only (`TX_UNITS` dropped for format-3 queues); a batch's objects sent again with every transaction until one stores them, and its `remove_objects` queued after its removals as on PostgreSQL | ~600 |
| | `vci-git/src/meta.rs`, `store.rs` | object keys and paths, blob fetch for objects, base64 codec in `get_objects`/`put_objects`, orphan scan over objects, put-back rule by id, state TTL in the orphan scan | ~400 |
| | tests | the four-backend parity suite extended with objects and mixed format rows; a 2.8 binary against a 2.9 SQLite file (fail open, no error); replica resync, including a cursor past the purge horizon; a batch whose queue flushes twice | |
| **M3 commands** | `vci-cli/src/run.rs` | header grouping, hdr/tables/shape/state construction (replacing `shared_manifest_bases`' output, keeping its grouping), descriptors, one batch; supersession from the old records' signed statements with column pre-filter + `entriesRoot`; `last_durations` from columns; orphan objects (`remove_objects` of the superseded run's ids on a store with columns; on git-meta left to `vci prune`, section 2.2) and state TTL | ~650 |
| | `vci-cli/src/plan.rs` | `Verifier` over `ResolvedPredicate`; the `signer` segment check; hdr memo per `(project, id)`; `ObjectLoader` beside `ManifestLoader` with the 16 MiB verdict-object cap in candidate order; observe-then-root for `inputs`; state count cap and the unsigned label; plan metrics lines (`objects: N hdr, M tables, K shape, S state, B bytes, C past cap, R distinct runs`) | ~750 |
| | `vci-cli/src/ctx.rs`, `cmds.rs` | `storage_key` over the resolved view with `waived_canonical()` (same string for the same facts in either version; tested against v1 on the sample over the canonical list, and the units whose 2.8 key differs counted); prune from columns with confirmation reads (every row read while a manifest remains; a unit beyond `keep` by the hints read whole and ordered by the signed `issuedAt`), `--objects --older-than`; `vci store upgrade --begin/--finish` (PostgreSQL's `Finish::Already` at version 2); export/verify forms | ~350 |
| | docs | STORE-BACKENDS.md sections 2-4 and 15-18 (the frame grammar, the decoder rules, object forms per backend, the write model, `gone`), CONTRACTS.md (predicate v2, objects, the new invariant, the supersession paragraph), REFERENCE.md (`explain_hashes`, `explain_hashes_days`, `record_format`, `vci store upgrade`), PLAN.md, the agent skill | ~750 |
| | tests | end-to-end fixture at two commits (same set, different root: the record is new, the shape is new, the hdr is shared, the plan skips the unchanged unit and names the changed entry); mixed v1/v2 plan; cancelled-run partial write (held at the batch level, where the cut happens: libSQL's `a_batch_stores_no_record_without_its_objects` and the stalled-proxy batch in `vci-store-libsql/tests/libsql.rs` show a batch cut between transactions keeping the first transaction's units with their objects and re-sending the objects with every later one, SQLite's one transaction leaves nothing or everything, and `e2e_m3.rs` (c) a unit refused mid-run keeps the others' records); cargo/node multi-hdr run; a record moved under another signer's slot fails `signer` (`adversarial_plan.rs`, `e2e_format3.rs`); a 2.8 binary on a git-meta store and `--finish` on PostgreSQL (`store_backends.rs`); `explain` snapshots with the unsigned label, the pruned-state text and the past-the-cap text | |
| **M4 rollout at vex** | | `record_format = 3` default; `vci store upgrade --begin` on vex's namespaces, then the action pinned in one PR before the next master push; dashboards: per-plan objects fetched and bytes, distinct runs per plan, per-partition flushes, transactions and wire bytes, live runs per namespace, state objects pruned, `gone` rows | |
| **M5 (optional, later)** | `vci-core/src/merkle.rs`, `run.rs`, `plan.rs` | one signed statement per run over an RFC 6962 tree of the units' statement digests (leaf = BLAKE3(0x00 ‖ stmt bytes), node = BLAKE3(0x01 ‖ l ‖ r), proof from (index, leafCount) and never from side tags in the record); per-unit records keep their statement bytes and gain `(run id, index, proof)` instead of a per-unit signature; the per-unit view keeps `Verifier::check` unchanged; `[attest] signature = "unit" \| "run"`. Only worth doing if keyless signing cost (one Fulcio cert and one TSA request per unit today) or signature CPU shows in a measurement; it changes the statement, not the store, because the objects already exist | ~1,200 |

Order of risk: the observe-then-root refactor of `diff_against_cache_from` (M1/M3, covered by the 1,175-unit
replay check and the harness's negative cases), the libSQL `seq` replica path with its purge horizon (M2,
separable: the old log can stay for one release at two rows per unit), the transaction sizing on Turso (M2: re-run
the Turso transaction-size measurement (`txsize.py`, outside the repository) with real text frames and base64 objects before 2.9.0; the 1 MiB figures above are for
JSON values of the same byte count). The git-meta bytes path, the earlier draft's top risk, no longer exists.

## 7. Open questions

1. **Groups are estimated.** Everything above uses nine disjoint 440-entry groups (the worst case). The first
   real run should log the shape and state sizes with and without groups; if the groups overlap as expected the
   per-run objects are ~100-150 KB smaller than stated.
2. **Runs per plan is measured once, not continuously.** The listing of 27 October 15:20 gives 45-59 runs
   behind vex-api's live candidates (1.35-1.91 MB of verdict objects, 7.9x under the cap); the plan logs the
   distinct-run count and the bytes, and the dashboard of M4 watches them. If production shows the cap being
   reached, the remedies are the per-unit inline set (measured: +1 KB per record, no per-run shape) behind a
   writer option, or M5's run statement which makes a run's objects worth fetching once per plan regardless.
3. **State object policy.** The default is two days (`explain_hashes_days = 2`) and `explain_hashes = true`.
   Whether vex wants `explain_hashes = false` for pull-request signers (keeping it for master, where a human
   asks why a unit ran), or a longer window on git-meta where the object costs a blob and no row, is a policy
   choice; both are one line of config.
4. **git-meta key paths.** Closed for 2.9: values stay strings and the measured gain is 2.4x bytes, 18% objects.
   Trees per record (7-8.5) are what remains; a two-level fan-out of the key path or filing under `project`
   changes `by.metaKey` and every clone's layout and is a 2.10 question, to be measured with
   `docs/design/measure/gitmeta.py` before it is claimed.
5. **Memo.** Kept as it is. If the `tree16` column proves enough for the chooser in production (skip rate
   unchanged with the memo off for a day), drop it in 2.10.
6. **`entriesRoot` domain and encoding** must be pinned in CONTRACTS.md before M1 ships (proposed: the entries
   section of `root()`'s encoding under `vci/entries-root/v1`).
7. **Keyless signers** still mint one certificate and one timestamp per unit; M5 is the answer if that cost
   matters. Sigstore bundles are stored as JSON inside the signature frame (`sig_kind` 2), base64 in the record;
   their size (~3-4 KB, 4-5.3 KB as base64) is unchanged in substance by this design.
8. **cargo tables objects are 22-74 KB** (the externals table: the crate list with versions) and a cargo run
   writes one per header group. The hdr split moved the toolchain and `rustCfg` (~1 KB) out of it, so the big
   part is now the per-run union of crates. Not pursued because the cargo projects have single-digit units;
   a content-addressed externals table of its own (a third digest) is the remedy if a cargo project with
   hundreds of units appears.
9. **`gone` is the largest table at rest** (1.93 M rows, 413 MB at the 30-day purge, against ~450 MB of
   everything else at the ceiling). A row could shrink to `(seq, test_key, signer, storage_key)` (~150 B), or
   the purge could key on the oldest unexpired record instead of a fixed horizon; both are 2.10 questions, and
   either way it is six times fewer rows than today's log.
10. **Transaction sizing on Turso** is from JSON values (`txsize.json`); text frames and base64 objects of the
    same byte count should behave the same, but the 1 MiB transaction and the time per megabyte need a re-run of
    `txsize.py` with real format-3 values before 2.9.0 (section 6).
11. **Distinct hdr objects in production** are not measured: the sample has 11 over 9 runs and 6 commits. The
    expectation is one per base tree per project (the global manifest changes with lockfiles and boot files, the
    toolchain with the image), so a few per day; the plan metric of M3 counts them.

## 8. What was taken from each design, and what was not

- **dedup** (base): per-run context by signed digest (now split into a shared hdr and a per-run tables object),
  waived as ids, the raw statement bytes plus the signature frame (text, not binary: section 1.2), per-run
  objects with index-list descriptors, NOT-EXISTS-plus-grace object GC, in-place column additions, `seq`/`gone`
  replica log, first-byte format detection, `record_format = 1` escape hatch, `vci store upgrade --finish`, no
  compression in 2.9 with a first line reserved for it. Not taken after the critique: the memo collapsed to one
  row per plan (today's memo stays), the binary frame, the git-meta bytes path.
- **manifest**: the split of the observation set from its values (paths and kinds decide; hashes are for
  explain), the signed files root for supersession, the explicit "entries vs externals vs env" attribution. Not
  taken: recomputing externals and env at HEAD into the root (it breaks `libraries = "any"` and the 2.0.2 env
  rule: here attested externals and env enter the root and their checks run as today), per-unit `ds`/`ek`/`xs`/
  `wv` objects and the refs table (per-run objects only), trained zstd dictionaries, the storage-key and
  key-shape changes, `git diff` as the source of explain's paths.
- **tree**: real index columns on SQL stores, `vci_schema.version` staying 1 with a `v2` flag so 2.8 clients keep
  planning, the per-unit view that keeps `Verifier::check` byte-for-byte, the per-run statement spec kept for
  M5 with (index, leafCount) proofs. Not taken: directory-union objects (20 of 205 directories identical across
  the two largest commits; 804 of 813 entries identical: the granularity is wrong, not the data), the commit
  seal fast path (tree equality says nothing about env, untracked inputs or the bundle).
- **radical**: the one-queue idempotent write per partition (sent as 2.8.2's whole-unit transactions on libSQL),
  the measurement that rejects directory chunks (kept as a regression check in M3's tests), the duplicate-leaf
  rule for M5, the observation that columns carrying commit/platform/issued/state/duration let `last_durations`
  read no values (supersession and prune still read the doomed records' statements: 1.8 KB each, section 1.4).
  Not taken: whole-run records as the unit of read (a candidate from a run the plan did not otherwise need would
  cost 123-300 KB), git-meta checkpoints and the replay fold, removing the memo and the per-unit record, the
  one-way migration that leaves 2.8 clients with no attestations at all.

## 9. The judges' flaws, the critiques' findings, and where each is resolved

| flaw (judge) | resolution |
|---|---|
| dedup: snapshot sized per base group, not per partition (1, 3) | shape and state measured per run (973 units: 123 KB + 285 KB) and scaled to 800 with groups at the high estimate; section 3 |
| dedup: a candidate from an old run drags a 200-350 KB snapshot; distinct snapshots per plan unbounded (1, 2) | the verdict needs hdr + tables + shape (~240 KB per 800-unit run, 2-9 KB per small run), not the hashes; capped at 16 MiB of verdict objects per plan in candidate order (candidates past the cap fail `inputs`, logged); state objects capped at 16 and never on the verdict path; the inline-set fallback is measured and named (open question 2) |
| dedup: `extra`/conflict resolution order unspecified (1) | no shared hashes on the verdict path, so no conflicts; the state object keeps duplicates in sorted order and is explain-only; the decoder rules of section 1.6 pin every other ambiguity |
| dedup: unsigned hint fields and prune by hint expiry (1) | columns choose and pre-filter; prune and supersession read the signed statement before deleting (sections 1.4, 2.1) |
| dedup: git-meta binary values (1, 2, 3) | values are text: the record is a UTF-8 frame, objects are base64 on git-meta; no bytes path (section 2.2) |
| dedup: no cross-run reuse (2) | the hdr (4.5 KB) is shared across runs by content address; the per-run part is ~260 KB of tables + shape + state per 800-unit partition against 1.4 MB of records; the alternative (per-unit content-addressed sets) costs a per-unit object and a reference graph for ~1 KB per record |
| dedup: 800 signatures per partition, keyless TSA round trips (2, 3) | kept in 2.9 (0.3 thread-s per plan; vex signs with SSH); M5 specifies the per-run signature as a statement change when keyless cost is measured |
| dedup: six-field hint, key is public output (2, 3) | keys unchanged; SQL columns instead; git-meta reads 1.8 KB values for durations and supersession |
| dedup: ctx per run carries the run's waiver union (3) | the per-run unions are the tables object; the header is its own shared object; per-hdr checks run once per project per plan |
| manifest: r-gate at HEAD drops env/externals leniencies (1, 2, 3) | attested externals and env enter the root; their checks run unchanged |
| manifest: object sprawl, refs table, leaf-scanning prune (2) | four per-run object kinds, one of them shared; GC by NOT EXISTS over four columns |
| manifest: zstd dictionaries, decompression surface (1, 2) | no compression; bounds per object kind |
| manifest/radical: explain depends on `git diff` and the attested tree (1, 2, 3) | the state object keeps attested hashes per run for two days; explain text unchanged in content while it is loaded, labelled unsigned |
| tree/radical: non-Rails adapters have per-unit globalManifest/argv (1, 2) | argv stays in the per-unit statement; hdr and tables are per header tuple, several per run for cargo/node (measured 2 and 5) |
| tree/radical: cancelled job stores nothing (1, 2) | per-unit records; a partial batch stores what it signed |
| tree: directory objects do not dedupe (1, 2, 3) | not used |
| radical: scenario B reads whole run records; no decompression bound; checkpoints (1, 2) | per-unit records; no compression; no checkpoints |
| all: bases estimated (1, 2, 3) | still estimated; the high figure is used everywhere and the first real run logs it (open question 1) |

| finding (security review) | resolution |
|---|---|
| store-controlled descriptor/shape/ctx cannot produce a wrong skip (refuted, no fix needed) | the invariant stands (section 4); the harness's ten mutations are M1's negative test vectors (sections 1.6, 6) |
| the key's signer segment is not checked by 2.8.1 and the design did not add the check | added: after signature verification the segment must equal the verified key's or identity's signer id, else `signer` fails; said to be new in 2.9 (sections 1.5 step 4, 4, 5.8) |
| supersession on SQL stores driven by unsigned columns (1.4) while section 4 says statement-confirmed | 1.4 step 5 takes commit, platform, `issuedAt` and `entriesRoot` from the old record's signed statement; columns only pre-filter the reads; the invariant says so for CONTRACTS.md (section 4) |
| `gone` purge horizon equals the default `max_ttl`; no forced full resync; PostgreSQL `seq` serialisation | purge after max(30 d, policy `max_ttl`); a replica whose cursor is older than the horizon does a full resync; the PostgreSQL counter-row lock is noted (sections 2.1, 5.7) |
| frame and object encodings leave decoder rules unstated | section 1.6: frame and canonical base64, minimal varints, the delta base, bounded indices, refused env override with a clear bit, canonical `RepoPath` and strictly increasing distinct entries, 255 groups, the `objects.kind` column ignored, `storage_key` from decoded values; one line for CONTRACTS.md |
| a forged state object mislabels explain's expected hash; the outside-repository oracle refuted | the printed hash is labelled `attested (unsigned, from the run's state object)` (sections 1.5 step 9, 4, 5.8); the `RepoPath` rule is explicit (section 1.6 rule 5) |
| the per-ctx memo must be per project, not per plan | the per-hdr memo is keyed by `(project, hdr id)` (section 1.5 step 6, section 4) |
| supersession races and delayed retries cannot hide a failure (refuted) | noted in section 4: a slot overwrite exchanges two passes on identical inputs because failures are never stored |

| finding (performance and operations review) | resolution |
|---|---|
| the libSQL batch travels as hex (4 MB on the wire, 5-10 s of lock, 16-30 s for 12 shards) | the record is a UTF-8 text frame and travels 1:1 (`conn.rs:1826`); objects go as base64 text on libSQL (1.33x) because the batch is one SQL string without hrana arguments (`conn.rs:1747-1767`); the state object has a 2-day TTL and an off switch; wire bytes 2.43 MB (1.75 MB without state) per 800-unit partition, sent as 2.8.2's ≤ 1 MiB transactions at 1.8-3.7 s each (sections 1.2, 1.4, 2.1, 3); `txsize.py` to be re-run with real frames (open question 10) |
| git-meta gain is 2.5x / 18%, not 9x; trees untouched | section 2.2 rewritten from the real-git experiment re-run with the text frame (`docs/design/measure/gitmeta.txt`: 2.4x bytes, 18% fewer objects, trees unchanged); the 1.8 GB pack ~0.65-0.75 GB; the two-level fan-out is a 2.10 question (open question 4) |
| at steady state the per-run objects are ~1 GB, two thirds explain-only state; "~50 live runs, 38 MB" unsupported | section 3's steady-state table rebuilt from the 164-run day: state at 2 days 85 MB (594 MB at 14), tables + shape ≤ 296 MB ceiling with the measured 59-run point, hdr shared, `gone` 413 MB, total ceiling ~850 MB; the live-runs count is an M3 plan metric and an M4 dashboard |
| the 64-shape cap would be hit (59 runs observed 0.3 days into a window) | cap by bytes, 16 MiB of verdict objects per plan in candidate order (7.9x the measured 2.13 MB ceiling); the distinct-run count is logged; state keeps its count cap (sections 1.5, 4) |
| memo2 is built on a misdiagnosis; one row per plan triples the bytes read | memo2 deleted; today's memo table and one-statement write kept; its lock wait shrinks with the batches (section 2.1) |
| supersession removes 1.2 records per record; a full partition is 2,700-3,300 writes, two flushes; `gone` grows 64k rows/day | the write model is 1 + 2 x 1.2 writes per record: 2,724 writes for 800 units, 3,302 for 970, a second flush above ~587 units; `gone` sized at 64k rows and 13.8 MB a day, 1.93 M rows at 30 days (sections 1.4, 2.1, 3) |
| per-day totals double count (164 runs/day, 327-540 units, not 328 x 800) | section 3's per-day rows rebuilt from `rails.json`: 164 runs, 76,725 units attempted (mean 540, max 972), 46,644 attested (mean 328): 201 MB/day (158 without state) against 2.79 GB; the 800-unit case is the partition maximum class only |
| migration wrinkles: 2.8 prune stops manifest GC, DDL inside a 30 s request, 2.8 replicas never see `gone` | DDL in a request of its own or `vci store upgrade --begin` (sections 2.1, 5.2); the prune behaviour and the short-window advice (section 5.3); the 2.8 replica lag (section 5.7) |
| ctx objects never dedupe across runs; 45-59 of them cost 0.7-0.9 MB per plan | the ctx is split into a shared hdr (4.5 KB, 11 distinct in the sample) and a per-run tables object (9-19 KB for Rails); per-hdr checks memoized per `(project, hdr id)`; 45-59 runs cost 49 KB of hdr plus 0.50-0.66 MB of tables instead of 0.70-0.92 MB of ctx (sections 1.1, 1.3, 1.5, 3) |

## 10. Measured on a local sqld

Two measurements of the implementation (branch store-v2 at 69b70f2, release builds) against a local `sqld`
0.24.32 on 127.0.0.1, on a 14-CPU Mac (29 October 2026), and the plans again on 30 October after two fixes
(section 10.2, "Re-measured"). Everything is labelled **sqld**: the store's own cost on
loopback, without the link to Turso or Turso's lock waits, so the transactions, bytes and rows carry over and the
times do not. The scripts, their `results.json` / `results2.json` and the measurers' full write-ups (`RESULTS.md`,
`RESULTS-2.md`) are in
[measure/sqld/writes/](measure/sqld/writes/) and [measure/sqld/plan/](measure/sqld/plan/); the write side's records
are built by `crates/vci-store-libsql/examples/replay3.rs`, the plan side's by
`measure/sqld/plan/meas_plan_v2.rs` (a test file placed in `crates/vci-cli/tests/` for the run).

### 10.1 Writes: one writer, 800 real Rails units

Medians of 3 clean repetitions; the 800 units are the first of the 973-unit run of the private sample.

| | section 3 (design) | format 3 (store-v2), sqld | format 1 (store-v2, `VCI_STORE_RECORD_FORMAT=1`), sqld | 2.8.1's store (2.8.1 + turso-reads), sqld |
|---|---:|---:|---:|---:|
| record | 1,783 B | 1,774 B mean | envelope 21,774 B + manifest 13,419 B | same bytes |
| per-run objects (as base64 at rest) | hdr 4,489, tables 19,387, shape 123,264, state 285,128 B (973 units) | hdr 5,988, tables 24,900, shape 122,304, state 286,076 B (329,446 B raw) | - | - |
| transactions | 2-3 of <= 1 MiB | **2** of <= 1 MiB in 1 flush, longest 0.09 s | 33 in 7 flushes | 33 in 7 flushes |
| on the wire | 2.43 MB | **2.59 MB** of SQL (1.87 MB of literals; 2.68 MB on TCP): +6.6% | 30.24 MB of SQL (28.18 MB literals; 31.21 MB TCP) | 31.03 MB TCP |
| store write / process wall | | 0.15 s / 0.60 s | 0.86 s / 1.23 s | 0.69 s / 0.77 s |
| at rest | 2.18 MB, 804 rows | **2.46 MB, 806 rows**: +13% (800 attestation rows 2.02 MB = 2,529 B a row around a 1,774 B record; 4 objects 0.44 MB as base64; 2 log rows) | 28.86 MB, 3,233 rows (800 envelopes 17.82 MB, 800 manifests 10.85 MB, 1,633 log rows) | 28.82 MB, 3,233 rows |
| units lost | | 0 | 0 | 0 |

Ratios, today against format 3: **11.7x on the wire, 11.7x at rest, 16x the transactions** (the design said 13.5x;
it counts the 9 base manifests of ~50 KB per run that neither replay writes, ~0.45 MB a run). The wire and at-rest
figures are above the design's because it counted the record and object bytes, where the store sends and keeps the
objects as base64 (+33% on 329 KB) and each row carries its key and nine listing columns (~750 B). The transaction
count is 2 rather than 3 because 804 writes are one flush.

The second run of the same 800 units at a moved-on commit (supersession and the orphan pass), format 3: finding what
to supersede 0.06 s, 15 requests, 1.42 MB of old values read (design: ~2.7 MB with the listing; format 1: 17.42 MB);
the batch of 800 puts and 800 removals 2 transactions, 3.05 MB of SQL, 0.14 s (format 1: 33 transactions, 31.31 MB,
0.96 s); the orphan pass removed the old state object, the hdr, tables and shape being shared with the new run.

**Three writers at once** (vex's partitions): format 3 stored 800 of 800 in 12 of 12 processes over 4 attempts, 2-3
transactions each, store write 0.17-0.39 s, 7.60 MB and 2,417 rows at rest for 2,400 units; sqld's write lock stalled
once, after every unit was stored. Format 1 (store-v2 and 2.8.1's store) has **no clean local number**: `sqld`
0.24.32's write lock stalled for good in 25 of 25 attempts within the first flush (the documented stall,
docs/STORE-BACKENDS.md section 21 item 17), each process losing the flush it was sending; the stalled attempts'
partial numbers are in the write-up.

Caveats: the records are built by the measurement example, not by `vci run`, so signing, observation and verdicts are
outside the times, and the format-3 statements carry the real envelope's signature frame over a statement that
signature does not cover (nothing on the write path checks it; the second run's format-1 envelopes have a renamed
`manifestRef` for the same reason). 2.8.1's store is the libSQL store of 2.8.1 plus the turso-reads short
transactions (1 MiB transactions, 4 MiB flushes), not the released 2.8.1 binary whose 5 batches of 6.6-8 MiB section
3 cites (that binary writes only through `vci run`); its supersession path was not driven, format 1 through store-v2
standing in. The hour of grace on objects and manifests was skipped by backdating `put_at` by 7,200 s before the
second run, so `prune_state_objects(2 days)` removed nothing. Writers 1 and 2 take their 800 units from offsets 390
and 780 of the 973 under distinct names, so their shape and state objects overlap writer 0's more than three real
partitions' would; each process's own bytes are one partition's.

### 10.2 Plans: vex-api, 1,156 candidates

Medians over 7 runs, interleaved; vex-api at vex's `origin/master` of 28 October with the sample's units re-observed
at that checkout (so every candidate whose files are still there skips), 2,061 files listed; the release store-v2
binary against the released vci 2.8.1; each run a first plan with an empty memo. These walls include 0.5-0.7 s
of vex's `[store] token_command` per plan, which the 30 October runs found had run (see "Re-measured" below): compare
them with each other, not with the re-measured ones.

| binary on records | wall, median (min..max) | fetch values | load verdict objects | verdicts | store requests | read | skip / run | RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| store-v2 on format 3 | **4.79 s** (3.1..11.4) | 0.07 s | 1.61 s | 0.84 s | 14 | **2.9 MB** | 1156 / 905 | 192 MB |
| store-v2 on format 1 | 5.27 s (3.4..6.1) | 0.10 s | - | 2.64 s | 12 | 43.3 MB | 1155 / 906 | 283 MB |
| vci 2.8.1 on format 1 | 4.29 s (3.2..10.2) | 0.15 s | - | 2.73 s | 4 | ~43 MB | 1155 / 906 | 280 MB |
| vci 2.8.1 on format 3 | 1.25 s | 0.07 s | - | 0.07 s | 4 | 2.6 MB | **0** / 2061 (every candidate `envelope: envelope JSON`: fail-open) | 53 MB |

With vex-web, rust and vex-roder added: store-v2 on format 3 3.84 s (3.3..7.9), 3.3 MB, 1164 skips; on format 1 4.79 s,
44.2 MB; 2.8.1 on format 1 5.07 s; 2.8.1 on format 3 1.40 s. **Bytes a plan reads: 2.9 MB against 43 MB, 15x**
(section 3 said 2.93 MB of values plus the objects against 59.7 MB). The verdicts' thread-seconds on format 3:
signature 0.2, globals 0.4, ignored children 4.0, rehash 2.8, and "externals" 16.2, which is the verdict threads
waiting on the booted Rails probe that runs once a project on the first externals check (1.5-8 s of wall, in both
formats: 32 thread-seconds on format 1). On loopback format 1's 43 MB cost 0.15 s, so format 3 is not faster in wall
here; what it removes is the 40 MB a plan, 90 MB of RSS and 1.9 s of verdict wall, and what it adds is
`load verdict objects`, ~1.4 ms a candidate that section 3 did not count: not the candidate's own decode (8 ms
for all 1,156) but the run's shape decoded again for every candidate naming it (the 125 KB shape 973 times),
removed since (below). Production's figure for comparison (2.8.1 on Turso, the 164 Rails jobs of 27 October, plan 1
medians): 13.12 s in all, of which fetching the stored values 5.46 s; the measurers' estimate for format 3 on Turso is
the local figure plus ~1 s of round trips, 5-6 s, an estimate and not a measurement.

The differences from production: one candidate per unit instead of ~1.9 (rounds 2-3 and the state objects for
failure text never ran), loopback, a checkout re-observed so the inputs check passes by construction, and 14 Apple
CPUs against the runners' 4-8 x86 ones.

**Re-measured (30 October; `measure/sqld/plan/RESULTS-2.md`).** The same records rebuilt from scratch (a new key and
checkout commit), every plan with a placeholder token in the store URL so that vex's `token_command` never runs (it
had run in every plan above), medians of 7, seconds; `before` is store-v2 at 86bd306, `fix 1` adds eaa13b3 (each
verdict object decoded once per round), `after` adds a397027 (the Rails boot started as soon as something says it is
needed, and killed when unused); "flag set" is every plan after a store's first, "first plan" a store's first:

| binary on records | wall, flag set | wall, first plan | load verdict objects | verdicts (flag set) | CPU user | requests | read |
|---|---:|---:|---:|---:|---:|---:|---:|
| store-v2 before, format 3 | 2.77 (2.7..3.0) | **4.66** (4.5..5.6) | **1.46** | 0.41 | **3.96** | 9 | 2.9 MB |
| store-v2 fix 1, format 3 | 2.61 (2.3..4.4) | **2.98** (2.9..8.5) | **0.03** | 1.70 | **2.57** | 9 | 2.9 MB |
| store-v2 after, format 3 | **2.60** (2.4..5.4) | **3.16** (2.7..5.1) | 0.03 | 1.64 | 2.58 | 9 | 2.9 MB |
| store-v2 after, format 1 | 2.62 (2.3..12.9) | 3.32 (2.8..3.5) | - | 1.58 | 2.86 | 7 | 43.3 MB |
| vci 2.8.1, format 1 | 2.60 (2.5..5.6) | 3.25 (2.9..4.5) | - | 1.64 | 2.84 | 4 | ~43 MB |

The decode fix takes 1.4 s of CPU off every format-3 plan (3.96 to 2.57 s of user time, which on a 4-CPU runner is
wall) and 1.7 s off a store's first plan; with the flag set the wall moves only 0.16 s, since the 1.46 s used to
overlap the Rails boot the flag starts at +0.15 s, and the verdicts now wait in "externals" for that boot (17.6-18.6
thread-seconds) instead. A vex-api plan here is now the boot (1.7-4.1 s, 2.2 s typical) plus ~0.2-0.3 s; everything
else of a format-3 plan is ~1.1 s of CPU-bound work, and format 3 is level with 2.8.1 on loopback (2.60 against
2.60 s, first plan 3.16 against 3.25 s) while reading 2.9 MB against 43 MB with 90 MB less RSS. With the four projects
(flag set): 3.14 s after, format 3, 2.95 s format 1, 2.80 s 2.8.1. Starting the boot from the round's tables objects
on a first plan moved its start by 0.05-0.1 s (noise here); its worth is where the flag read is slow (a token
command, Turso), and a store whose candidates keep failing before the externals check pays for one unused boot
(`plan:natives-hint-unused:<project>`), not one per plan.
