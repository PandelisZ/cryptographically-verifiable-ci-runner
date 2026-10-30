# Attestation store backends

This document is the design of vci's attestation-store abstraction and the guide for anyone implementing a backend.
The contract is the crate `vci-store` (`crates/vci-store/src/lib.rs`). Its rustdoc is authoritative for signatures
and for each method's rules; this document covers the reasons, the semantics across backends, how the command line
uses a store, and each backend's design.

## Status

Built and in use (vci 2.8.0):

- **The trait and its types**, in the crate `vci-store`: `AttestationStore`, `Exchange`, the records, `StoreError`,
  `FailedStore`, the factory registry (`BackendFactory`, `OpenContext`, `MissingBackend`, `open`), `select`, `timing`
  and the conformance suite (feature `conformance`).
- **git-meta as an implementation of the trait**: `vci_git::GitMetaStore` and `vci_git::GitMetaFactory` (section 15).
  git-meta is the default store. Its output is byte-identical to vci 2.7.32 on an output-diff harness (run, plan,
  explain and push in one clone; fetch, plan, prune and verify in a second) and on every end-to-end suite. 2.8.0 also
  carries what 2.7.33 to 2.7.36 changed in git-meta: one store per repository, shared by its linked worktrees, which
  `GitMetaStore` opens like every other git-meta command (section 15), and the merge of a fetched tip through `git
  merge-tree`.
- **The SQLite backend** (`vci-store-sqlite`, section 16): one file in the git common directory, selected with
  `VCI_STORE=sqlite`.
- **The PostgreSQL backend** (`vci-store-postgres`, section 17): a shared server, selected with a `postgres://`
  `VCI_STORE_URL`.
- **The libSQL backend** (`vci-store-libsql`, section 18): a local file (`VCI_STORE=libsql`), a libSQL server such as
  Turso (a `libsql://` `VCI_STORE_URL`, its token in `VCI_STORE_TOKEN`; or `[store] url` in `vci.toml`, its token
  printed by `[store] token_command`), or a local replica of one (`VCI_STORE_SYNC=replica`). The three backends are
  in vci-cli's default features, so the release binaries carry them (section 17, "Crate"; section 18, "Crate").
- **The command line on the trait** (section 13): every command reaches the store through one
  `Arc<dyn AttestationStore>` per repository, selected from the environment and `[store]` (section 9). Deferred write
  batches are reported only once they finish (section 6), `vci ci` has the publication gate for shared stores
  (section 7), `vci store info` exists, and none of `VCI_STORE_URL`, `VCI_STORE_TOKEN` and `VCI_STORE` reaches a
  child process.
- **The plan reads the candidates it set aside** even when a round fetched nothing (section 5).
- **The conformance suite** (section 14): its 42 scenarios, run against git-meta, SQLite, PostgreSQL and libSQL (in
  each of its three modes) from each backend's `tests/conformance.rs`.
- **The trait's format-3 side** (2.9, STORE-V2 M2): the object methods (`get_objects`, `put_objects`,
  `remove_objects`, `orphan_objects`, `prune_state_objects`), `Prefetch::Objects`, the listing `Columns` carried by a
  put and answered by `columns`, `decode_record` over both formats, the batch order (objects, manifests, records,
  removals) and the objects scenarios c35 to c42 (section 2, "Format-3 records", section 4, "Objects and columns",
  section 6, section 14). Every object method has a default that returns `Unsupported`, so a backend is on format 3
  once it sets `Caps::objects` (and `Caps::columns`) and overrides them; which backends have is in their sections.
- **The commands on format 3** (2.9, STORE-V2 M3): `vci run` writes format-3 records and a run's four objects on a
  store that keeps objects (format 1, as 2.8 wrote it, on one that does not or under `[store] record_format = 1`),
  supersedes from the old records' signed statements with the listing columns as a pre-filter (none while the store
  holds an input manifest: every record of the unit is read then, as prune reads every row), and removes the
  superseded run's unreferenced objects and the aged state objects; the plan tells a value's format by its first
  byte, verifies a frame as the DSSE envelope rebuilt from it, resolves its descriptor against the run's objects
  and observes the resolved set at HEAD; `vci prune` reads only what its columns and the signed statements confirm
  and collects objects (`--objects`, `--older-than`); `vci store upgrade --begin` and `--finish`, `vci verify
  --envelope` and `--manifest FILE` for a frame (section 2, "The frame and the decoder rules", "Migration from
  format 1"; section 13).
- **The temporary-PostgreSQL test helper** (`vci_store_postgres::testkit`, section 14), the temporary libSQL server
  (`vci_store_libsql::testkit`, section 18) and the CI jobs that run all of the above (`store-stock-git`,
  `store-docs`, `store-cli`, `store-pg-initdb` in `.github/workflows/ci.yml`; the libSQL server is the
  `libsql-server` image as a service container).

Not built yet: `vci store init`, `vci store copy`, `vci init --store`, and the action inputs `store` and `store-url`
(section 9). The questions still open are in section 21.

Contents

1. What a store is
2. Data model and key layout
3. The API at a glance
4. Operation contracts
5. Value states, lazy values and `read_values`
6. Batches and transactions
7. What fetch and push mean per backend kind
8. Hints: the memo and flags
9. Configuration
10. Errors, failing open and bounded time
11. Threads
12. Timing and observability
13. The command line on the trait
14. The conformance suite
15. Backend: git-meta
16. Backend: SQLite
17. Backend: PostgreSQL
18. Backend: libSQL (Turso)
19. Notes for an HTTP or gRPC backend
20. Decisions and why
21. Decided questions, and what is still open

---

## 1. What a store is

`vci run` signs one attestation per unit that passed (a DSSE envelope) and stores it, together with the input
manifest the attestation's `manifestRef` names. `vci plan` lists the stored attestations of every unit, verifies
the ones it chooses, and skips a unit when one of them proves the inputs unchanged. The **store** is where those two
kinds of records live. git-meta is the default store: `<git common dir>/git-meta.sqlite` (`.git/git-meta.sqlite`, one
per repository and shared by its linked worktrees since 2.7.33), mirrored into `refs/meta/main` trees and exchanged
with `vci fetch` and `vci push`. It is one implementation of the trait
`vci_store::AttestationStore`. SQLite (a local file) and PostgreSQL (a shared server) are the other two (sections 16
and 17), libSQL (a local file, a Turso or `sqld` server, or a local replica of one; section 18) is a fourth, and an
HTTP or gRPC service can follow (section 19).

### The store is never trusted

`vci plan` verifies every envelope's signature against the **base commit's** allowed signers and keyless
identities, and recomputes every manifest's root. A record that is forged, altered, replayed, reordered, duplicated
or missing can therefore only make a unit **run**. It can never make a unit skip. Every design choice below rests on
this:

- **Write access is an availability privilege, not an integrity one.** This covers push rights on
  `refs/meta/main`, a PostgreSQL role with INSERT and DELETE, and write permission on a SQLite file. A writer can make
  CI slower, by deleting records or by adding records the plan must read and reject. It cannot make CI skip a test it
  should run.
- **Read access reveals** test ids, signer ids and input manifests (paths and content hashes). Grant it to whoever
  may read the repository.
- **The signer id in a key is the writer's claim**, checked only for its shape. A backend never filters, ranks or
  repairs by signer.
- **Every backend may fail open**: any store error means "run the test".

### Who reads and writes

| command | reads | writes |
|---|---|---|
| `vci plan`, `vci explain` | status; key-only listing of every unit; the chosen values in one batch; about 2,000 manifests from many threads; memo and flags | memo, flags |
| `vci run` (and `vci ci`) | each attested unit's earlier attestations with values (supersession, from worker threads); last durations | manifests, attestations, removals of superseded attestations, orphan manifests (nothing in `vci ci` without `--push` on a shared store) |
| `vci fetch`, `vci push` | status (store without an exchange), count, location | the exchange (git-meta only) |
| `vci prune` | status; every attestation with values; every manifest root; the referenced manifests | removals |
| `vci verify` (an envelope with a `manifestRef`) | one manifest and its base | none |
| `vci store info` | settings, caps, status, count, location | none |

The hot path is `vci plan` on CI. It must list the candidates of about 4,000 units without downloading every value,
read only the chosen values in one batch, read about 2,000 manifests concurrently, and never block on the store.

---

## 2. Data model and key layout

### Attestations

```
key:    vci:attestation:<test key>:<signer>:<storage key>[:<issued hex>.<tree16 | ->]
target: path:<unit path> | project
value:  the DSSE envelope, UTF-8 JSON, byte for byte
```

- `<test key>` is BLAKE3 of the test id, 64 lowercase hex (`vci_core::test_key`).
- `<signer>` is 16 lowercase hex naming the signing key. It is a hint and is never verified by the store.
- `<storage key>` is 2 to 128 lowercase hex characters. It hashes everything that makes two attestations
  interchangeable: input root, global inputs, toolchain, argv, env configuration and project.
- The **hint**, added in vci 2.2, is `<issuedAt seconds, lowercase hex, at least 0>.<the first 16 hex digits of the
  tree the attestation records, or ->`. A plan picks which candidates to read from keys alone. Keys written before
  2.2 have no hint.
- The separator is `:`. Only git-meta turns segments into tree directories (`.../vci/attestation/<tk>/<signer>/<sk>/__value`),
  so `/` appears only in git-meta tree paths. Every other backend stores the key as one string.
- `(test key, signer, storage key)` is the attestation's **slot**. A slot holds at most one record. Putting the same
  slot again replaces the earlier record, whatever its hint.
- The **target** is `key::target_label(test_id)`: `path:<the test id before its first #>` when that is a relative
  path of at least 3 bytes with no NUL and no empty, `.` or `..` segment; otherwise `project`. git-meta files the
  record under this target. Every other backend stores it only as display data, because plan JSON prints it as
  `by.target`. The key alone identifies the record. A parity test in vci-git (`target_label_parity`) checks that
  `target_label` matches git-meta's `Target` label.

### Input manifests

```
key:    vci:manifest:<input root>
target: project
value:  the compact encoding, UTF-8 JSON ({"v":2,"entries":[...],"externals":[...],"env":[...], "base": "<root>"?})
```

Manifests are content-addressed, written once, and shared by every attestation, unit and signer with that root. Since
2.1.8 a manifest may list its entries on top of a **base** manifest, which is stored the same way.
`vci_core::InputManifest::compact_base(bytes)` names the base without decoding the rest. `vci_store::decode_manifest`
resolves it through the store.

### Format-3 records, their columns and objects (vci 2.9, STORE-V2)

The design this section implements, with every decision the reviews changed and the scripts behind its numbers, is
[docs/design/STORE-V2.md](design/STORE-V2.md) (cited below as STORE-V2), its decisions
[docs/design/STORE-V2-DECISIONS.md](design/STORE-V2-DECISIONS.md), and the measurement scripts and their outputs
[docs/design/measure/](design/measure/).

From vci 2.9 an attestation's value may be a **text frame** instead of an envelope JSON, under the same key, target
and slot:

```
value:   "vci3" LF <the signed statement bytes> LF base64(signature frame) LF base64(descriptor)
columns: format, commit, platform, state, duration_ms, expires, hdr, tables, shape, state_obj   (nullable; the SQL stores)
objects: id (64 hex, BLAKE3 of the bytes) -> kind (1 hdr, 2 tables, 3 shape, 4 state), put_at, bytes
```

- A value's **first byte** says its format: `{` is a format-1 envelope, `v` a format-3 frame. `vci_store::decode_record`
  tells them apart and every reader goes through it; a frame is decoded under the rules below ("The frame and the
  decoder rules") and bounded at 1 MiB (`vci_core::MAX_RECORD`); an envelope is parsed exactly as before. The frame
  is UTF-8 without NUL, so rule 3 stands and a frame travels through git-meta's string values and the libSQL text
  literal unchanged. A column never chooses the parser: a 2.8 writer that reuses a slot holding a frame sets the key
  and the value alone and leaves the frame's columns beside its envelope, so the columns pre-filter and order reads
  and nothing more, and whatever deletes confirms from the decoded signed statement.
- A frame's manifest is its **descriptor**, inside the record, which indexes into per-run **objects**: `hdr` (shared
  by every run at the same toolchain and global inputs), `tables` (the waiver table, env names and externals of a
  run's header group), `shape` (the paths and kinds of every unit of the run) and `state` (the attested sizes and
  hashes, read only by `vci explain`). The statement names the hdr and the tables by id, the descriptor names the
  shape; the state object is in no signed field (STORE-V2 section 4). `key::record_object_refs` reads those three ids
  from a value, as `envelope_manifest_ref` reads a format-1 value's `manifestRef`; a frame's `ManifestRef` is `Inline`
  (it names no stored manifest), so manifest collection goes on while both formats coexist.
- Objects are **binary** (`vo`, a kind byte, a version, the body; the state object holds raw 32-byte hashes). SQLite
  and PostgreSQL store them in a BLOB/BYTEA column; git-meta and libSQL store `object_to_base64` of the bytes in a
  string value (keys `vci:object:<kind>:<id>` on git-meta, `key::object_key`) and decode on read, so `get_objects`
  answers the same bytes on every backend and the reader recomputes the id of each. Puts are idempotent by id. An
  object outlives its last referrer by a grace period (`OBJECT_GRACE`, one hour), and a state object is deleted after
  `[store] explain_hashes_days` even while referenced.
- The **columns** (`Columns`) are what the writer copies out of the statement it signed: the format, the commit, the
  platform (`<os>-<arch>` from the hdr's toolchain), the result state and duration, the expiry, and the four object
  ids. They pre-filter which old records supersession and prune read (while no input manifest remains in the store;
  with one, a 2.8 writer may have left its format-1 value under a frame's stale columns, and every record is read:
  prune every row, supersession every record of the unit), give `last_durations` its numbers without a
  value read, and let the orphan queries find an object's referrers. They are store data: supersession and prune
  confirm them against the signed statement before a delete, and no verdict reads them. git-meta keeps none (its
  hint is the key); the SQL stores keep them as nullable columns, `NULL` on a format-1 row. A backend says what it
  keeps with `Caps::objects` and `Caps::columns`.

### The frame and the decoder rules (format 3)

The record is UTF-8 text without NUL (`vci_core::Frame`, `crates/vci-core/src/frame.rs`):

```
record     = "vci3" LF statement LF sig LF descriptor
statement  = the in-toto Statement exactly as signed: compact JSON with every object's keys sorted
             (`vci_core::sorted_compact_json`), predicateType https://vci.dev/test-attestation/v2; it holds no LF
             and no NUL (JSON escapes both inside strings, the serializer writes no whitespace) and starts with `{`
sig        = base64(sig_frame)
descriptor = base64(descriptor_bytes)
base64     = RFC 4648 section 4, `=` padding, no line breaks, canonical (rule 1)

sig_frame        = u8 sig_kind (1 = SSHSIG, 2 = Sigstore bundle)
                   uv keyid_len, keyid       the envelope's `keyid` (`SHA256:<b64 of the key blob hash>`, or the keyless
                                             signer id): a hint, never trusted
                   uv sig_len, sig           kind 1: the SSHSIG blob, the bytes inside the PEM armor (180 B for ed25519);
                                             kind 2: `{"sig": <signatures[0].sig>, "sigstore": <the stored envelope's
                                             sigstore member>}`
descriptor_bytes = 32 B shape id              the run's shape object
                   u8 group                   index into shape.groups; 0xff = none (what 2.8 called the base)
                   uv n; n x uv               the unit's own entries: sorted indices into shape.entries, delta-coded (rule 3)
                   uv k; k x (uv idx, 32 B)   env variables with a value: index into tables.envNames, the attested BLAKE3
                   bitmap(tables.envNames)    one bit per name, ceil(len/8) bytes: the unit read it (ABSENT_HASH unless above)
                   bitmap(tables.externals)   one bit per (name, version) pair of the tables object
                   uv m; m x (str, str)       externals not in the table (never written; accepted, rule 3)
```

`uv` is an unsigned LEB128 varint, strings are `uv len` + UTF-8. The statement is the v2 predicate (`VciPredicateV2`:
the unit's `testId`, `argv`, `commit`, `tree`, `treeDirty`, `issuedAt`, `expiresAt`, `result`, `tainted`,
`entriesRoot`, `waived` as sorted distinct u16 ids into the tables object's waiver table, `declaredInputs`,
`platformSpecific`, `archSpecific`, `cfgPredicates`, and the two object ids `hdr` and `tables`) under the subject
`[{name: testId, digest: {blake3: inputRoot}}]`, as docs/CONTRACTS.md says. A frame decodes to exactly a format-1
`Envelope` (the statement bytes, the signature re-armored: `Frame::to_stored_json`, which `vci verify --envelope
<record>` prints) and, through its objects, to the format-1 manifest's set minus the attested file hashes.

**Objects** are bytes whose id is the BLAKE3 of them (`vci_core::object_id`; 64 lowercase hex in statements, columns
and keys), encoded as the magic `vo`, a kind byte, a version byte and the body (`crates/vci-core/src/objects.rs`);
sorted path lists are prefix-coded (`uv` bytes shared with the previous path, `uv` suffix length, the suffix), which
is the whole gain (a 46 B mean path costs 18.6 B per shape entry, kind byte included), so the encoding is written by
hand rather than by a serializer.

- **hdr** (kind 1, at most 1 MiB): `repoId`, `adapter`, `projectName`, `projectDir`, `runnerProject`, `toolVersion`,
  `railsInputs`, `envConfigDigest`, `globalInputRoot`, the **whole global manifest** (entries with kind, exec bit,
  size and hash; externals; env with each value's hash), `ignoredInputs`, `envSet` and the toolchain (its scalar
  fields as sorted compact JSON, then `goEnv`, `pythonDists`, `rubyGems`, `rustCfg` as prefix-coded lists in that
  order). Content-addressed by what is in it, so every run at the same toolchain and global inputs names the same
  one and the plan checks it once per project.
- **tables** (kind 2, at most 4 MiB): per run and header group, the `waiverTable` (sorted distinct waived strings),
  `envNames` (the sorted union of env keys the group's units read) and `externals` (the sorted union of `(name,
  version)` pairs) the statements' ids and the descriptors' bits index.
- **shape** (kind 3, at most 8 MiB): `entries`, the sorted distinct `(path, kind, exec)` over every unit of the run,
  one kind byte each (`f l a d t x m u`, bit 7 the exec bit); `groups`, the run's shared bases (2.8's
  `shared_manifest_bases`), each a delta-coded sorted index list into `entries`, at most 255. No sizes and no hashes:
  nothing in a shape depends on file content.
- **state** (kind 4, at most 16 MiB): the sorted `(path, kind, exec, size, hash)` over every entry of every unit of
  the run, duplicates of a `(path, kind)` with different values (a file written during the run) side by side. **No
  verdict reads it**: it exists so that `vci explain` and the plan's failure text can print the attested size and
  hash beside the observed one, which is why it has its own retention (`[store] explain_hashes_days`, 2 by default)
  and its own switch (`[store] explain_hashes = false` writes three objects per run).

**The decoder rules.** They make two writers produce the same bytes for the same content and one id per content, and
make the decoders refuse what the security review's harness showed changes the root anyway. A value or object that
breaks one fails the candidate's `envelope`, `statement` or `inputs` check and the unit runs.

1. **Frame.** The first line is exactly `vci3`; exactly three LF in the record; the statement is the bytes between
   the first and second LF, non-empty, first byte `{`; the two base64 fields are canonical: a length that is a
   multiple of 4, the alphabet of RFC 4648 section 4, padding only at the end, unused trailing bits zero, no
   whitespace. Anything else fails `envelope`. The signature is checked over the statement bytes as found, never
   re-serialized. A compressed record, should a later release want one, takes another first line (`vci3z`), which
   2.9 refuses: 2.9 never decompresses anything.
2. **Varints.** `uv` is minimal LEB128: no continuation byte followed by a zero byte, at most 10 bytes, values past
   `u64::MAX` refused. A non-minimal encoding would give one content two ids, and an idempotent put by id would
   store both.
3. **Delta-coded indices.** The first index is absolute; each next one is `previous + 1 + delta`, so a list is
   strictly increasing and distinct by construction. Every entry index is below the shape's entry count, every env
   index below the tables' env-name count, every externals bit within the table, and `group` below the shape's
   group count or `0xff`. An inline external the tables object holds is refused whether or not its bit is set (a
   pair in the table is a bit), so an externals list has one encoding; the inline list is itself strictly
   increasing.
4. **Env overrides.** An `(idx, hash)` whose bitmap bit is clear is refused; so is one listing `ABSENT_HASH` (the
   bitmap says it already) and a duplicate or unsorted `idx` list.
5. **Paths.** Every path in a shape, a state, a global manifest and an inline external is a canonical `RepoPath`
   (relative; no empty, `.` or `..` component; no NUL; no trailing slash); an autoload-miss entry (`u`) has the
   `<AUTOLOAD_MARK>/<const>` form. The entry lists of shape and state are strictly increasing in `(path, kind, exec)`
   and distinct; `groups` lists are strictly increasing and in range; a shape has at most 255 groups.
6. **Kinds.** A kind byte's low 7 bits name one of `f l a d t x m u`; bit 7 is exec. The `objects.kind` column (and
   the key's `<kind>` segment on git-meta) is store data used only to choose which table or path to read: the
   decoder trusts the kind byte inside the hashed bytes and refuses an object whose inner kind is not the one the
   statement or descriptor expects.
7. **Statement values.** `waived` ids are sorted, distinct and below the waiver table's length, checked where the
   resolved view is made (`ResolvedPredicate::v2`, its only constructor). The storage key is computed from the
   decoded values of the resolved view, never from bytes, and over the waived list sorted and distinct
   (`waived_canonical`) for both predicate versions, so a writer's serialization choices cannot move a slot.
8. **Bounds.** The counts in every list are checked against the bytes remaining before anything is allocated; a
   record over 1 MiB, a hdr over 1 MiB, a tables over 4 MiB, a shape over 8 MiB, a state over 16 MiB or a
   `get_objects` answer over 64 MiB is refused.

The ten store-side mutations the security review ran against `root()` (a kind relabel, an index swapped to another
unit's path, an omitted entry, an env override and a bitmap flip, an externals pair, an `x` hidden under a `d`, the
exec bit, section confusion, duplicate rows) are negative test vectors in vci-core
(`manifest_tests.rs::the_security_harness_mutations_each_move_the_root_or_fail_a_decoder_rule`): each is refused by
a decoder or gives the set observed at HEAD another root than the signed one. A file's kind and exec bit enter the
root as the observer finds them at HEAD, never as the shape labels them.

### Measured (format 3)

The replay check (`crates/vci-cli/tests/replay.rs`, with `VCI_PAIRS` naming the 1,175 real vex units of 28 October
2026: 9 runs, 18 header groups, 1,158 Rails, 12 node and 5 cargo units; its figures as it writes them to
[`docs/design/measure/replay-numbers.json`](design/measure/replay-numbers.json)) builds every unit's format-3 record and its run's objects from the sample's envelopes and
manifests, and checks what the design claims: for all 1,175 units the descriptor resolves to the manifest's set,
externals and env, `entriesRoot` is reproduced, and every v1 accessor of the resolved view answers what the v1
predicate did (1,175 of 1,175 each); the 47 object ids are recomputed; the signed subject digest is reproduced for the
3 units that list no base manifest (the sample holds the deltas and not the 11 bases they reference; the full check
is the end-to-end suites' job, where the bases are in the store); no state object held a conflicting duplicate.

| | format 1 (the sample's own values) | format 3 (replayed) |
|---|---:|---:|
| statement, signed | inside the envelope: 21,166 B mean, p50 21,742, max 24,574 (the payload as base64, the armored signature, the keyid) | 1,100 B mean, p50 1,099, p90 1,142, max 1,591 (a cargo unit) |
| signature | inside the envelope | 234 B frame (312 B as base64) |
| manifest / descriptor | 15,154 B mean (p50 11,372, max 98,539) | 271 B mean, p50 247, p90 361, max 957 (a node unit with 762 own entries) |
| **record** | **36,320 B** per unit (envelope + manifest) | **1,782 B mean, p50 1,760, p90 1,917, max 2,707**; Rails 1,780 B, node 1,804 B, cargo 2,245 B |
| hdr, shared across runs | (in every envelope) | 11 distinct over the 9 runs, 13,296 B in all; 4,489 B for both Rails runs, 796-813 B node, 951-1,094 B cargo |
| tables, per run and group | (in every envelope and manifest) | 10 objects, 261,948 B: 19,387 B for the 973-unit Rails run, 9,313 B for the 185-unit one, 184-661 B node, 69,000-74,319 B cargo (the crate list with versions) |
| shape, per run | (in every manifest) | 173,195 B: 123,265 B for 973 units (6,639 entries, 18.6 B each), 24,674 B for 185 |
| state, per run (explain only) | (in every manifest) | 393,597 B: 285,128 B for 973 units (43 B an entry), 60,758 B for 185 |
| **at rest, 1,175 units, 9 runs** | **42,676,097 B** | **2,936,328 B, 2,499 B a unit: 14.5x**; 2,542,731 B and 16.8x without the state objects |

The sample holds no base manifest, so the shape and state above carry no groups (one run had one group of 7
entries); the design's model added nine disjoint groups of ~440 entries per run as a worst case (3,651,600 B at
rest, 11.7x), which the first real run should measure (STORE-V2 section 7). The other numbers of the design are
estimates from that model and from vex's production logs, not measurements of this code: the 800-unit partition's
2.18 MB at rest and 2.43 MB on the libSQL wire in three transactions of at most 1 MiB (13.5x), a plan's reads of
5.1-5.9 MB against 81-87 MB at vex's spread of 45-59 runs behind the live candidates (15x), 201 MB a day written at
vex against 2.79 GB (13.9x), and the git-meta push of 1.2 MB against 2.8 MB for 800 units (2.4x, 18% fewer objects:
from a real-git experiment on the sample's two largest runs). What the code has been measured at, all against a
local `sqld` on loopback (section 18, "Measured"; STORE-V2 section 10): one 800-unit partition in the test suite (4
objects of 329,446 B and 800 records of 1,417,069 B, written in 2 transactions and 0.18 s; the superseding run in 2
transactions and 0.20 s); 800 real Rails units written as a run writes them, **2 transactions and 2.59 MB of SQL
against 33 transactions and 30.24 MB for format 1 (11.7x), 2.46 MB at rest against 28.86 MB (11.7x)**; and a vex-api
plan of 1,156 candidates reading **2.9 MB against 43 MB (15x)**, 4.79 s median wall against 2.8.1's 4.29 s on the same
loopback store, where the 43 MB cost 0.15 s. **No format-3 write or plan has been measured against Turso's hosted
service yet**; the transaction sizing of 1 MiB and the 1.8-3.7 s of lock per
transaction come from 2.8.2's measurements with JSON values of the same byte count (section 18), and are to be
re-run with real frames and base64 objects before the first production rollout.

### Migration from format 1

The gates, in order (STORE-V2 section 5):

1. **vci 2.9.0 reads format 1 and 3 and writes format 3** on a store that keeps objects; `[store] record_format = 1`
   (or `VCI_STORE_RECORD_FORMAT=1`) keeps writing format 1 for one release, for fleets that cannot upgrade every
   reader at once. The value's first byte says its format; keys and slots are shared, so a format-3 record
   overwrites the format-1 record of its slot and vice versa, with one exception: a unit whose 2.8 record's `waived`
   list repeated a string or was unsorted (1,158 of the sample's 1,175 units repeat one and 1,163 are unsorted,
   STORE-V2 section 1.1) keys
   another slot under 2.9, since the key now takes the list sorted and distinct, and its 2.8 record stays beside the
   new one as a second candidate until supersession or expiry removes it: fail-open, one more candidate per such
   unit.
2. **The SQL schema, DDL first.** `vci_schema.version` stays 1 while a format-1 row can exist; the nullable columns,
   the `objects` and `gone` tables and the `v2 = 1` row are added by `vci store upgrade --begin` (idempotent, ahead of
   a rollout) or by 2.9's first write on a namespace that lacks them, in a request of its own before its batch
   (sections 16 to 18). A **2.8 binary** on such a store sees version 1, lists keys with its own parser (the keys are
   unchanged), reads a frame it cannot parse and fails `envelope`: the unit runs; it keeps planning on any format-1
   rows until they expire; its own writes are format-1 rows with NULL in the new columns, which 2.9 reads through the
   v1 path. Nothing breaks; skips are lost per unit until the binary is upgraded, so pin the action and the binary in
   one change and expect the skip rate to dip for at most one `max_ttl` window.
3. **2.8's `vci prune` during the window** stops collecting manifests once one frame exists: a record it cannot
   parse sets its referenced set to unknown, and it then removes no manifest at all (it cannot know what the
   unreadable record names). Keep the window short, or run 2.9's `vci prune` once during it: it collects both,
   reading every record while a manifest remains (a 2.8 writer may have left a format-1 value, with its
   `manifestRef`, under a frame's columns) and, once none does, a format-3 record through its columns and a
   confirming read.
4. **`vci store upgrade --finish`**, manual, once no format-1 row remains: drops `manifests` (SQLite and PostgreSQL)
   and sets `vci_schema.version = 2`, after which a 2.8 binary reports the store as too new and fails open (checked:
   2.8.1's `vci store info` exits 2 with `schema version 2 is newer than this vci reads`, its plan runs every unit,
   its run attests nothing). It is refused, with the count, while a format-1 row exists; the count is by the
   value's first byte, never by the `format` column (a 2.8 writer's upsert leaves the column stale, and a frame copied
   in without columns has NULL). **On libSQL this release ends the migration here, at gate 3**: every statement that
   names `manifests` and the change log has to branch on version 2 first, and that is 2.10's work (STORE-V2 section 5
   step 4, section 21 below). `--finish` on a libSQL namespace is refused with the count while a format-1 row
   remains (exit 1) and at zero prints `vci: error: the libsql store does not support finishing the format-3 upgrade
   (dropping the manifests table and the change log): a later vci does it` and exits 2 (run it to read the count all
   the same). The namespace stays at version 1, which 2.8 reads, so the `too new` guard never arrives there: a 2.8
   binary that still holds a write token (a developer's stale install using `token_command`, a workflow left at 2.8)
   keeps writing format-1 rows and manifests, and the operator's substitute guard is to rotate the Turso write token
   or run `vci update` on every machine that writes. Each such write re-opens the migration window: prune and
   supersession go back to reading every row while a manifest exists (gate 3), and every batch carries the
   superseded-manifest statements again (section 18 measured them at 1.1 MB of SQL per 800 removals), until a 2.9
   `vci prune` or supersession removes the manifest.
5. **git-meta** has no schema: a 2.8 clone reads the keys it knows and the values it cannot parse (fail open),
   ignores `vci:object:` keys (rule 2), and never deletes a key it does not parse. No bytes path and no value-type
   change in `git-meta.sqlite`.
6. **Existing records** keep working until they expire or are superseded by the next run; nothing is re-signed (a
   format-1 statement's bytes are what was signed and stay readable). `vci prune` then drops the `manifests` rows.
7. **Replicas.** A 2.9 libSQL replica syncs the old log for format-1 rows and `seq`/`gone` for frames; its objects
   and columns come from the server in 2.9.0 (section 18). A replica file a 2.8 synced is synced in full once, as is a
   2.9 replica whose cursor is older than the `gone` purge horizon. A 2.8 replica syncs format-1 rows only and never
   sees a format-3 deletion: it keeps superseded rows until their signed expiry (fail-open: their inputs mismatch at
   HEAD), so upgrade the replica's binary with the rest.
8. **Plan JSON and `vci explain`**: the same keys, targets and check names, plus the `signer` check's new failure
   text; `by.metaKey` byte-identical. `expected`/`actual` texts unchanged in content where the run's state object is
   loaded, labelled `attested (unsigned, from the run's state object)`; otherwise the observed value and `(attested
   hash not loaded)`.
9. **Rollback.** 2.9 with `record_format = 1` writes what 2.8 writes; a store that already holds frames serves them
   to 2.8 as fail-open units. Downgrading the binary after `--finish` is not supported (the `manifests` table is
   gone).

### Hints

- **Memo**: `(tree16, test key) -> attestation key`, meaning "this attestation passed on that tree".
- **Flags**: a set of names, for example `plan:natives:<project>`.

Both are best effort. They only order reads or start work early, and nothing about trust depends on them.

### Rules every backend keeps

1. **Identical key strings.** Build and parse keys only with `vci_store::key`. Keys appear in plan JSON
   (`by.metaKey`), the audit log, `vci explain`, run and prune output, and the memo. Using the same strings
   everywhere also lets a copy between backends (a later `vci store copy`) move records unchanged.
2. **Foreign keys are ignored, not errors.** A key that `parse_key` rejects never appears in a listing or a count.
3. **UTF-8 only.** `put` and `put_manifest` reject other bytes, so any record can be copied into git-meta, which
   stores strings. A format-3 frame is UTF-8 by construction. Objects (2.9) are the one binary value: a backend
   that stores strings files them as base64 (`object_to_base64`) and decodes on read, so `get_objects` answers the
   same bytes everywhere.
4. **Bytewise order.** A unit's listing is sorted by key. `list_all` is sorted by (target, key). `manifest_roots`
   is sorted and deduplicated. SQLite's default `BINARY` collation is bytewise. PostgreSQL needs `COLLATE "C"`,
   because a linguistic collation such as en_US ignores `:`, `.` and `-` at its first level and would reorder hinted
   keys. The plan picks candidates by index into the listing, and its verdict reasons ("best failure: last in store
   order") depend on the order.

---

## 3. The API at a glance

The API is one object-safe trait, `AttestationStore: Send + Sync`. The command line holds one
`Arc<dyn AttestationStore>` per repository per process. Ten methods are required. Every other method has a default
that is correct for a backend whose values are always present and whose writes are durable when the call returns.

| group | method | required | default | used by (vci-cli) |
|---|---|---|---|---|
| identity | `kind() -> &'static str` | yes | | every message that names the store; the metrics log |
| | `location() -> String` | | `kind()` | `vci fetch` without an exchange, `vci store info` |
| | `caps() -> Caps` | | `Caps::LOCAL` | `vci ci` publication gate; wording of plan, prune, fetch and push; `vci store info` |
| | `status() -> Result<StoreStatus>` | | `Ready` | plan's "no attestations" warning; `vci store info`; prune, and fetch and push without an exchange (exit 2 on `Err`) |
| reads | `list_units(&[&str]) -> Vec<Vec<StoredEnvelope>>` (keys only) | yes | | plan lookup |
| | `list_all() -> Vec<StoredEnvelope>` (keys only) | yes | | the defaults of `read_all`, `count` and `orphan_manifests` |
| | `read_values(&mut [&mut StoredEnvelope])` | yes | | plan rounds 1-3 |
| | `manifest(root) -> Option<StoredManifest>` | yes | | ManifestLoader, verify, prune |
| | `manifest_roots() -> Vec<String>` | yes | | prune |
| | `read_units(&[&str])` (with values) | | list + read_values | supersession, last durations |
| | `read_all()` | | list_all + read_values | prune |
| | `count()` | | `list_all().len()` | fetch messages, `vci store info` |
| | `manifests(&[&str])` | | one `manifest` per root | no command yet (a copy between stores) |
| | `manifest_decoded(root)` | | manifest + base | supersession |
| | `orphan_manifests(&[&str])` | | reads every value | run after supersession |
| writes | `put(&NewAttestation)` | yes | | run (through `put_for_test`) |
| | `put_manifest(root, bytes) -> bool` | yes | | run |
| | `remove(Vec<StoredEnvelope>) -> Vec<StoredEnvelope>` | yes | | supersession, prune |
| | `remove_manifests(&[&str]) -> usize` | yes | | orphan GC, prune |
| | `put_for_test(test_id, signer, sk, hint, bytes)` | | `put(NewAttestation::for_test(..))` | run |
| | `batch() -> WriteBatch` | | `WriteBatch::none()` | run's store loop |
| objects (2.9) | `get_objects(&[&str]) -> Vec<StoredObject>` | | `Unsupported` | plan (hdr, tables and shape objects, then state objects), explain, verify |
| | `put_objects(&[NewObject]) -> usize` | | `Unsupported` | run (the run's four objects, before its records) |
| | `remove_objects(&[&str]) -> usize` (the orphan rule, one hour of grace) | | `Unsupported` | run after supersession, prune |
| | `orphan_objects() -> Vec<String>` | | `Unsupported` | prune |
| | `prune_state_objects(Duration) -> usize` | | `Unsupported` | prune, run's orphan pass |
| columns (2.9) | `columns(&[&StoredEnvelope]) -> Vec<Columns>` | | every field `None` | supersession, last durations, prune |
| prefetch | `prefetch(Prefetch)` (`Units`, `Manifests`, `Attestations`, `Objects`) | | no-op | plan, run, verify, prune |
| | `warm()` | | no-op | plan start |
| hints | `passing_on`, `remember_passing`, `flag`, `set_flag` | | keep nothing | plan |
| reporting | `timing_report() -> Vec<String>` | | none | run |
| exchange | `exchange() -> Option<&dyn Exchange>` | | `None` | fetch, push, ci (`--push` and its "attested" line), plan `--fetch`, `vci store info` |

`Exchange: Send + Sync` is the optional git-style sync: `exchange_point()`, `remote_location(remote)`,
`fetch(remote)` and `push(remote, PushMode)`. Locks, cover and complete markers, and tombstones belong to git-meta's
implementation and never appear in the trait.

Supporting types:

- `StoredEnvelope`, `StoredManifest` and `KeyHint`. Their fields are unchanged from vci-git, and `state()` derives a
  `ValueState`.
- `NewAttestation` is a keyed write input carrying the target and test key, so a copy can re-put a record it knows
  only by key (`NewAttestation::copy_of`).
- `Hydration`, `FetchOutcome`, `PushOutcome`, `PushStatus` and `PushMode`. `PushStatus` and `PushMode` are
  `#[non_exhaustive]`, so other crates match them with a wildcard arm.
- `Caps { shared_writes, lazy_values, keeps_hints, remote_reads }`, which is non-exhaustive: build it from
  `Caps::LOCAL` with the `with_*` methods. `remote_reads` (2.8.2, the libSQL store's remote mode) says that every value
  read comes over the network, its bytes and requests costing time: the plan then reads only the candidates it checks
  first (section 5).
- `StoreStatus`, `Prefetch` (non-exhaustive) and `WriteBatch` (with `BatchEnd`). `WriteBatch::finish_partial` (2.8.2)
  returns a `Finished`: the warnings, and the keys of the attestations the batch did not store, each with its error
  (`Finished::lost`), every other write being durable; a backend that writes a batch as several transactions
  overrides `BatchEnd::finish_partial` (the libSQL store), and the default is `finish`'s answer with nothing lost.
  `vci run` refuses only the units named there; `finish` (and every other caller) still treats any loss as the whole
  batch's.
- `StoreError` (non-exhaustive).
- Format 3 (2.9): `Columns` (a plain struct of `Option` fields, built as `Columns { format: Some(3),
  ..Columns::default() }`; the default is "none"), carried by `NewAttestation::columns`
  (`with_columns`) and answered by `columns`; `StoredObject` and `NewObject` (`validate` computes the id); `Record`
  and `decode_record` with `RecordError`; `ObjectRefs` and `key::record_object_refs`; `key::object_key`,
  `parse_object_key`, `check_object_id` and `OBJECT_PREFIX`; `object_kind`, `object_to_base64` and
  `object_from_base64`; `OBJECT_GRACE` and `MAX_OBJECTS_ANSWER`. `Caps::objects` and `Caps::columns` say what a
  backend keeps.
- `FailedStore`, which stands in for a store that could not be selected or opened.
- `BackendFactory`, `OpenContext`, `MissingBackend` and `open()`, the registry. A new backend is a new crate plus one
  registration line in vci-cli's `store::factories`.
- `select`: settings, resolution, `Secret` and `redact`.
- `timing::Step`.
- `conformance`, behind a feature.

There is deliberately **no Reader trait**. The command line never relies on snapshot isolation between a listing and
a read: `read_values` opens its own reader. The per-thread readers the plan's ManifestLoader had in 2.7 existed only
because git-meta's `Reader` is `!Sync`, since it owns a SQLite connection and a `git cat-file` process. That pool now
lives inside `GitMetaStore`, and the trait has one thread-safe object for every backend to implement.

---

## 4. Operation contracts

In every contract below:

- "Fail open" says what the caller does on `Err`, as the command line does it today.
- "Cost" is the expectation a backend must meet for the plan to stay fast.
- **Every call is bounded in time** (section 10).

### `kind`, `location`, `caps`, `status`

- `kind()` is a static short name: `git-meta`, `sqlite`, `postgres`, `libsql`. Messages print it ("attested … as `<kind>`
  `<target>` `<key>`", "candidate 1: `<kind>` …"), so git-meta's output stays byte-identical. A `FailedStore` reports
  the kind that was asked for, or `unknown` (section 10).
- `location()` is human text and never carries a password. Examples: `.git/git-meta.sqlite (exchanged on
  refs/meta/main)` (git-meta's, whatever `meta.namespace` is set to; in a linked worktree, `<common git
  dir>/git-meta.sqlite, shared by every worktree of the repository (exchanged on refs/meta/main)`),
  `/repo/.git/vci-store.sqlite`,
  `postgres://***@db.internal:5432/ci schema vci namespace <repo id>`, `libsql://ci-acme.turso.io namespace <repo
  id> (remote)`. A `FailedStore`'s is
  `<kind> (unavailable: <why>)`.
- `caps()` is cheap and does no I/O.
- `status()` returns `Absent{advice}` when nothing exists yet (no file, no schema) and creates nothing to find out.
  It returns `Ready{schema_version}` otherwise, and `Err(Incompatible)` when the schema is newer than this vci reads.
  - Fail open: when `vci plan` sees `Absent`, it warns and reads on (the listing is empty, so everything runs). The
    warning of a lazy store keeps vci 2.7's text, ``no git-meta store in this repository: no attestations are
    available (run `vci fetch` first)``. Any other store's reads `no attestations are available in the <kind> store
    (<advice>)`. When `status()` is `Err`, the plan runs every test of every project with the reason `reading
    attestations from <kind>: <error>`.
  - `vci prune` calls `status()` first and exits 2 on `Err`, before reading anything. So do `vci fetch` and `vci push`
    on a store without an exchange.
  - git-meta's advice is ``run `vci fetch` ``.

### `list_units(test_ids) -> Vec<Vec<StoredEnvelope>>`

- **Input**: test ids, possibly thousands, possibly with duplicates. The plan passes each unit's id once.
- **Output**: one list per input id, in input order. Each list holds the unit's records whose key starts with
  `key::unit_prefix(test_key)` and parses. Each list is sorted bytewise by key and is identical on every call while
  nothing is written. An unknown unit gets an empty list.
- **Values are not read.** Entries are in `ValueState::Unread` (`bytes` empty, `error` `None`), with `target`,
  `issued` and `tree` filled from the key. A lazy backend still returns its promised entries as `Unread`.
  `read_values` then reports them as `NOT_FETCHED`.
- **Errors**: `Err` only when the store cannot be listed.
- **Fail open**: the plan runs every test of every project ("reading attestations from `<kind>`: …").
- **Cost**: one round trip for any number of units, or served from the prefetch cache.
  - git-meta: one pooled reader, one indexed SQLite query per unit (vci 2.7's loop).
  - SQLite: one indexed seek per unit on one connection inside one read transaction.
  - PostgreSQL: `test_key = ANY($2)`.
  - libSQL on a server: `test_key IN (SELECT value FROM json_each(?1))`, one request.

### `list_all() -> Vec<StoredEnvelope>`

Every record, keys only, sorted bytewise by (target, key). The command line never calls it directly: it serves the
defaults of `read_all` (prune), `count` and `orphan_manifests`. It is not on the plan's hot path.

### `read_values(&mut [&mut StoredEnvelope])`

- **Input**: entries as listed, possibly already read or marked. git-meta files records by target, so it matches
  `(target, key)`; pass entries with the target they were listed with.
- **Effect**: each entry is matched **by key** and read again. It ends with one of:
  - `set_value(bytes)`: the stored bytes, exactly as put. Empty bytes become `EMPTY_VALUE`.
  - `set_error(GONE)`: the key was removed since it was listed.
  - `set_error(NOT_FETCHED)`: a lazy backend does not hold the value here.
  - `set_error(<reason>)`: anything else (a missing blob, a corrupt row).

  Every entry ends with either bytes or an error, never both: git-meta's implementation clears the bytes of an entry
  with an error and marks an empty value `EMPTY_VALUE`.
- **Errors**: `Err` only when the store as a whole cannot be read. One bad value never fails the call.
- **Snapshot**: none is required between the listing and the read.
- **Fail open**: the plan runs everything on `Err` in round 1. In rounds 2 and 3 an `Err` leaves those units'
  verdicts as they were, so they run. A per-entry error fails only that candidate ("unreadable: …").
- **Cost**: a bounded number of round trips whatever the length.
  - git-meta: one scan of the attestation rows plus one `cat-file` batch, as in 2.7.
  - SQL backends: `key = ANY(…)` in chunks.

### `manifest(root) -> Option<StoredManifest>`

- `Ok(None)` means the manifest is not stored or `root` is not a hex id.
- `Ok(Some)` carries either `bytes` or `error` (`NOT_FETCHED` for a lazy one). The base is not resolved;
  `manifest_decoded` resolves it.
- **Concurrency**: called from every verifying rayon thread, about 2,000 times in a large plan.
- **Fail open**: only the candidate that needed the manifest fails. On a lazy store an absent manifest reads
  ``manifest <root> not in the store: run `vci fetch` `` (`missing from the local <kind> store`), as in 2.7; on any
  other store `manifest <root> not in the store` (`missing from the <kind> store`). An `Err` reads `manifest <root>
  cannot be read from the store`.
- **Cost**:
  - git-meta: a pooled reader per concurrent caller, an indexed lookup plus maybe one `cat-file` read.
  - SQLite: one indexed lookup.
  - PostgreSQL: a cache hit after prefetch, else one single-row query.

### `manifest_roots() -> Vec<String>`

Every stored manifest root, sorted and deduplicated, with no values read. Used by prune.

### `put(&NewAttestation) -> StoredEnvelope`

1. `NewAttestation::validate()` runs first, with vci-git's `what` strings: `signer_id` (exactly 16 lowercase hex),
   `storage_key` and `test_key` (lowercase hex, 2 to 128), `target` (`project` or `path:<relative path>`),
   `envelope` (non-empty, UTF-8). Nothing is written on failure.
2. The key is the hinted key. Without a hint, it is the existing key of the same slot (a rewrite in place), else the
   plain key.
3. Every other key of the same slot is removed and this value is written. SQLite and PostgreSQL do both **in one
   atomic step** (an upsert on the slot), so concurrent puts of one slot leave exactly one record. git-meta does not:
   as in 2.7, it lists the slot, removes the other keys, then sets the new one, so puts of one slot racing in one
   repository (threads on one handle, or two `vci run`s) can leave several records, and so can merging two peers'
   writes. Readers tolerate duplicates (every record is verified), and the next put of that slot collapses them.
4. Identical bytes under the same key are a no-op: no write, no timestamp, no log entry.
5. Outside a deferred batch, the write is durable and visible to this store's later reads when the call returns.
   With `Caps::shared_writes`, it is visible to every reader.
6. **Manifest and objects first.** The caller stores the referenced manifest, and for a format-3 record the objects
   its statement and descriptor name (`put_objects`), before the attestation (run.rs does). A backend keeps that
   order visible, so no reader sees an attestation without its manifest or its objects. In a deferred batch, `finish`
   writes objects, then manifests, first.
7. **Columns** (2.9). `NewAttestation::columns` is kept with the record where `Caps::columns` and given back by
   `columns`; elsewhere it is ignored. `validate` checks its object ids (`what` = `object id`) before anything is
   written.

- **Returns** `NewAttestation::stored(key)`: `bytes` set, `issued` and `tree` from the key.
- **Fail open**: the run refuses that unit ("signing or storing failed: …"), and the test result stands. The exit
  code of `vci run` stays the tests' when the error says the store cannot be used; any other error makes `vci run`
  exit 2 after the run (section 10).

### `put_manifest(root, bytes) -> bool`

- **Validation**: `root` must be a hex id (`what` = `input root`). `bytes` must be non-empty UTF-8 (`what` =
  `manifest`). git-meta's trait method checks both; its inherent `AttestStore::put_manifest` accepts empty bytes, as
  in 2.7.
- **Effect**: writes unless exactly these bytes are stored, and returns whether the stored bytes changed. Inside a
  deferred batch it returns whether they will change, and may report `true`.
- A lazy store's not-fetched row counts as different, so storing the same bytes makes it readable.
- A backend that removes manifests by age refreshes `put_at` even when the bytes are identical. This closes the race
  with another run's orphan collection.
- The caller guarantees the bytes decode to a manifest with this root. Readers recompute the root anyway.
- **Fail open**: a unit's own manifest that cannot be stored refuses the unit ("signing or storing failed: storing
  the input manifest: …"). A shared base manifest that cannot be stored is a warning (`vci: warning: storing the
  units' shared input manifest: …; storing each unit's input manifest whole instead`), and it is not relied on: the
  units of its group encode their manifests whole, without the base, and each is stored, or refused with its unit,
  on its own. No unit is reported attested on a base that is not stored (encoded on it, they would never verify, and
  would run every time).

### `remove(doomed) -> removed`

- **Input**: entries (matched by key).
- **Output**: the ones that existed, **with the bytes the caller gave**, because callers read the removed values'
  `manifestRef` to collect orphans. Inside a deferred batch it may return every entry it was asked to remove.
- **Visibility**: afterwards no read of this store returns them. For an exchanged store, other clones see the removal
  after `push` here and `fetch` there. For a shared store, everyone sees it at once.
- **Re-attestation wins**: a key written again after its removal is live again, including across a merge.
- **Fail open**: supersession warns (`vci: warning: <unit>: cannot remove superseded attestations: …`) and moves on.
  Prune exits 2.

### `remove_manifests(roots) -> usize`

- **Validation**: every root is checked before anything is removed.
- **Output**: how many existed and were removed.
- **Concurrent writers**: a backend with concurrent writers keeps a root, and does not count it, when any of these
  holds:
  - a stored attestation references it (`manifest_ref`);
  - another manifest names it as its base;
  - it was put within the grace period (PostgreSQL, default 1 h).

  Deleting such a root would only make some unit run, but keeping it is cheap.
- git-meta removes exactly the roots it is given. Its merge puts back manifests that a local attestation references.
- **Fail open**: orphan collection after supersession warns (`vci: warning: cannot remove the unreferenced input
  manifests: …`). Prune exits 2.
- `vci prune` passes one root per call and prints `removed project vci:manifest:<root> (unreferenced manifest)` for
  each root it asked to remove, whatever the count returned. That is exact for git-meta; see section 21 for stores
  that keep roots.

### Objects and columns (format 3, vci 2.9)

Every method here has a default: the five object methods return `StoreError::Unsupported` (`"format-3 objects"`)
after validating their arguments, and `columns` answers `Columns::default()` per entry. A backend that keeps
objects sets `Caps::objects` (and `Caps::columns` when it keeps the columns) and overrides them all; until then a
writer stays on format 1 and the objects scenarios of the conformance suite skip. The contracts, as the trait docs
state them:

- **`get_objects(ids) -> Vec<StoredObject>`**: the objects stored under these ids, in the order asked, **leaving
  out** the ids the store does not hold (the caller matches by id; a missing object fails the candidates naming it)
  and answering a repeated id once. `bytes` are the object itself, base64-decoded on a text backend (a text that does
  not decode is left out too), so `vci_core::object_id(&bytes)` is the id on every backend and the reader recomputes
  it. Every id is validated first (`check_object_id`, `what` = `object id`). An answer that would pass
  `MAX_OBJECTS_ANSWER` (64 MiB) is refused as `Invalid` (`what` = `objects`) before it is allocated. A lazy store
  answers from what it holds here: `prefetch(Prefetch::Objects { ids })` first. Cost: one round trip for tens of ids.
- **`put_objects(objects) -> usize`**: each under the BLAKE3 of its bytes, **idempotent by id**: an id already stored
  is not written again but its `put_at` is refreshed, so a concurrent writer's objects (queued before its records)
  start their grace at its own put. `NewObject::validate` first (non-empty, within the kind's bound, headed by the
  magic `vo` and the kind byte, `what` = `object`); nothing is written on failure. Returns how many were not stored
  before (inside a deferred batch, possibly every one).
- **`remove_objects(ids) -> usize`**: the **orphan rule**. An object goes only when no stored attestation references
  it (its `hdr`, `tables`, `shape` or `state_obj` column; without columns, the ids its records' statements and
  descriptors name, `key::record_object_refs`) and it was put more than `OBJECT_GRACE` (one hour) ago. Every id is
  validated first. Returns how many were removed. A **state object on a store without columns** has no visible
  referrer (its id is in no signed field), so such a store keeps it, counts it nowhere, and leaves it to
  `prune_state_objects`. Removing an object still referenced only makes its units run. Inside a deferred batch a
  backend may queue the removal after the batch's removals and apply the rule at `finish` (PostgreSQL, libSQL), or
  apply it at once (SQLite, inside its transaction; git-meta, on the store as committed before the batch): the
  batch's own objects are within their grace either way. On a store with lazy values (git-meta) this and
  `orphan_objects` fetch every attestation value not fetched yet and read every value (any record on any target
  can name an object), so `vci run` calls `remove_objects` after supersession only on a store with
  `Caps::columns` and leaves git-meta's to `vci prune`, which has read every value already.
- **`orphan_objects() -> Vec<String>`**: the ids `remove_objects` would remove now, sorted; state objects left out on
  a store without columns. A store with columns reads no value; one without reads every value and answers empty
  when any record's references are unknown (`ObjectRefs::Unknown`), as `orphan_manifests` does.
- **`prune_state_objects(older_than) -> usize`**: every state object (kind 4) put more than `older_than` ago,
  **whether or not a record references it** (`[store] explain_hashes_days`): the records stay valid and `vci explain`
  prints the observed value without the attested hash. Other kinds are never touched. A backend with deletion
  records for replicas (`gone` rows) writes one per removal.
- **`columns(envs) -> Vec<Columns>`**: the listing columns of these listed records, one per entry in input order,
  matched by key; `Columns::default()` for a record stored without them, a format-1 row, a key no longer stored, and
  everything on a store without `Caps::columns`. Values are not read. Cost: one round trip whatever the length, or
  the listing's own cache. A put without columns on a store that keeps them clears the slot's columns; a put of the
  same bytes with other columns replaces them (the bytes being a no-op does not make the columns one).
- **Fail open**: a plan whose `get_objects` fails runs the candidates that needed them; `vci run` warns on a failed
  `remove_objects` or `prune_state_objects` as it does on a failed manifest collection; prune exits 2.

### Provided reads

- **`read_units(ids)`**: `list_units` followed by one `read_values`.
  - **git-meta overrides it**. Its `read_values` scans every attestation row and starts a `cat-file`, and run's
    supersession calls `read_units(&[id])` once per unit from worker threads. The override uses one pooled reader per
    call and `candidates_reading(id, |_| true)`, the targeted query `AttestStore::list(Some(id))` uses.
  - `last_durations` calls it once with every selected unit. A store-level `Err` loses every recorded duration
    (the runner then keeps its own order); in 2.7 a failure lost one unit's.
  - Measured on a synthetic store of 600 Go units with three attestations each: the supersession "list"
    thread-seconds fell from 1.1-1.2 to 0.1-0.2, because pooled readers are reused instead of opened per call.
- **`read_all()`**: `list_all` followed by `read_values`. git-meta serves it in one pass (`AttestStore::list(None)`).
- **`count()`**: values are not read, and promised values count.
- **`manifests(roots)`**: the batch form. No command calls it yet. git-meta answers it on one pooled reader, SQLite
  on one connection, PostgreSQL with `root = ANY` (cache first).
- **`manifest_decoded(root)`**: returns `None`, `Some(Err(why))` or `Some(Ok(manifest))`, with the base read from
  this store. The nested shape is that of vci-git's `AttestStore::manifest_decoded`, which the e2e helper
  `store_common::inline_manifest` calls.
- **`orphan_manifests(roots)`**: the roots no stored attestation references. If what any attestation references is
  unknown (`ManifestRef::Unknown`: an unparseable value or a `manifestRef` that is not a hex id; and, where the store
  recorded no reference when it stored the value, an unreadable or not-fetched value), the answer is **empty**,
  unless the backend can tell that attestation cannot reference these roots. Removing a manifest still referenced
  only makes its unit run.
  - The default reads every value.
  - git-meta overrides it: `hydrate_manifest_referrers` first (the roots it cannot decide are kept), then the scan
    that skips values still not fetched. This is vci 2.7's `drop_orphan_manifests` moved into the store, with one
    difference: it reads `manifestRef` with `vci_store::envelope_manifest_ref`, where 2.7 required a complete vci
    predicate. They differ only on malformed envelopes: one without `testId` or its times but with a hex
    `manifestRef` now counts as referencing that root (2.7 emptied the answer), and a `manifestRef` that is not hex
    now empties the answer (2.7 counted it as a reference to nothing).
  - git-meta waits only for the not-fetched values that could reference a root: those on the `project` target or on
    a path target that is a path the manifest lists or a directory above one (a unit's manifest lists its own path).
    A not-fetched value elsewhere does not empty the answer; offline, the answer is empty.
  - The SQL backends override it with one indexed query (no value is read) and answer empty if any row has
    `ref_state = 0` (unknown). The reference is recorded when the value is stored, so a value that became unreadable
    later (an unknown `encoding`) still counts as the reference it was stored with.
  - Fail open: the run warns (`vci: warning: cannot read the store to remove unreferenced manifests: …`) and removes
    nothing.

### `prefetch(what) -> Hydration`

`Prefetch::Units{test_ids, choose}`, `Prefetch::Manifests{roots}` or `Prefetch::Attestations`.

- **Effect**: makes the named data cheap to read next.
  - A lazy store downloads it (git-meta's `hydrate_*`).
  - A network store loads listings, chosen values, their manifests and bases into a per-handle cache in a few round
    trips.
  - A store that always holds its values does nothing.
- **Snapshot**: after a prefetch, reads may be served from a snapshot taken at prefetch time. That snapshot **always
  reflects this handle's own later writes and removals**: a put updates or evicts what it touches, including a
  cached "no such manifest". Other writers' changes may be missed until the next prefetch of the same data, which
  must pick them up (PostgreSQL lists the units again and asks again about roots it found absent). That is safe,
  because a stale record only makes a unit run.
- **Errors**: partial failure goes in `Hydration.error` and `unresolved`, and those units run. `Err` is for a store
  that cannot be used. Callers warn on both and read afterwards anyway (`vci run` and `vci verify` ignore both).
- `Hydration.resolved` counts only values that went from not-fetched to readable. A non-lazy store returns zeros, so
  callers **never** read `resolved == 0` as "nothing more is readable" (section 5).
- **Callers**: the plan (round 1 with `choose`, rounds 2 and 3 with `choose: None` and `Manifests`), the run (every
  selected unit with `choose: None`, before supersession), `vci verify` (`Manifests`) and `vci prune`
  (`Attestations`, then `Manifests`).

### `warm()`

Starts background work that makes the first reads fast: git-meta reads its store file through once on a
thread (`warm_in_background`); SQLite reads its file through once on a thread, into the page cache; PostgreSQL opens
its first connection and TLS session on a thread; libSQL reads its local file through, or on a thread asks a server
for its schema version (opening the connection and TLS session), or syncs its replica. It never blocks and never
fails. The plan calls it first, and never joins those threads, so a network backend whose credential is a `[store]
token_command` that has not run yet (`Credential::pending`) does nothing: the command runs at the first real read,
on a thread that waits for it (section 9).

---

## 5. Value states, lazy values and `read_values`

`StoredEnvelope::state()` derives the state from `bytes` and `error`. There is no separate field to keep in step, and
no existing struct literal breaks.

| state | bytes | error | how it arises |
|---|---|---|---|
| `Unread` | empty | `None` | a listing |
| `Read(bytes)` | the value | `None` | `read_values` |
| `NotFetched` | empty | `NOT_FETCHED` | a lazy backend lacks the value, or the plan set the candidate aside (`mark_not_fetched`) |
| `Unreadable(why)` | empty | `why` | `GONE`, `EMPTY_VALUE`, a missing blob, a corrupt row |

`NOT_FETCHED` keeps its exact text, ``value not fetched: run `vci fetch` online (a git-meta promised entry; its blob
is not in this clone yet)``, because tests and users match it. A non-lazy backend never produces it from the store;
only the plan's `mark_not_fetched` does.

### The plan's three rounds

1. **Round 1.**
   - `prefetch(Units{ids, choose})` for the units of every project that is verified. `choose` picks, from the keys
     alone, every key without a hint and: the memo's key, when the memo (the attestation a plan found passing on the
     head or base tree) names a listed one; else the keys made on the head tree; else those made on the base commit's
     tree; else the newest.
   - `status()`, then `list_units(ids)` for every unit.
   - For each unit the plan reads the same choice plus its two newest candidates (`READ_FIRST`), and calls
     `mark_not_fetched` on the rest. It records the keys it set aside, per unit (`SetAside`): the plan never infers
     them from the error text. One `read_values` reads the chosen ones. On a store whose reads go over the network
     (`Caps::remote_reads`, 2.8.2) it reads the choice alone: the newest two were a second request of 1,170 to 1,462
     values (30 to 45 MB) per vex plan on Turso, for the few units whose first choice fails, which round 2 reads.
2. **Round 2** (`hydrate_more`), for the units the first pass did not skip that have candidates. A unit whose
   memo-named candidate was read and failed on its inputs (an `entry:` difference) has changed inputs: no candidate
   issued before that one is read for it (2.7.32), and only those issued after it are, when some were set aside or
   not fetched (2.8.2: the attestation a pull request's earlier push made on the changed inputs, which `READ_FIRST`
   used to read in round 1); without such a candidate it runs, as before. The keys never read are kept for the later
   rounds and the reads (`older`); round 2's prefetch then names the others (`choose`).
   - `unread`: the units with keys set aside, or with a candidate a lazy store reports not fetched. `roots`: the
     manifests and bases the checks found not fetched. With neither, the plan is done.
   - `prefetch(Units{unread, choose: None})` and `prefetch(Manifests{roots})`. A fetch that resolved values evicts
     the manifest loader's cached failures.
   - **Read again**, in one `read_values`: after a fetch that resolved values, every candidate without a value of
     the `unread` units; when nothing was resolved, only the keys set aside for them that were not read yet. Either
     way those units' set-aside keys are then forgotten, so round 3 does not read them again.
   - The round ends the plan when the prefetch resolved nothing **and** the read made no candidate newly readable.
     Otherwise every unit not skipped is checked again with the candidates as last read.
3. **Round 3** repeats round 2 once.

**Why a round does not end on `resolved == 0` alone.** In vci 2.7 `hydrate_more` returned as soon as the prefetch
resolved nothing, because `resolved` counts only values that were newly downloaded. Whenever the set-aside candidates
were already present locally they were never read: on a developer's fully fetched clone, after a CI cache restore,
and on every non-lazy store. A unit whose two newest candidates fail but whose older candidate passes (an input edited
and reverted, a branch rebased onto what was attested) then ran. vci 2.8.0 reads them, and such a unit is skipped.
The e2e test `deferred_candidates_are_read_when_present_locally` (e2e_go) attests a package at three states, reverts
it to the first, and checks that the plan skips it through the oldest candidate; it fails with the previous binary.

**Cost.** One more `read_values` per round, only for units not skipped whose memo did not show changed inputs. On a
synthetic fully fetched store of 600 Go units with three attestations each (debug build), the added read took
0.02-0.03 s and the whole round, which re-checks the units not skipped, 0.16-0.21 s, with plan totals within noise.
On a large monorepo each re-checked candidate also loads its own manifest, so the round costs more there; it has not
been measured on one yet.

---

## 6. Batches and transactions

`batch()` opens a `WriteBatch` on the calling thread (the batch is `!Send`). There are two kinds:

- **`WriteBatch::immediate(end)`**: each write is durable when its call returns, and `finish` only releases what the
  writes shared. No backend uses it since 2.8 (git-meta and SQLite did, each write committing on its own).
- **`WriteBatch::deferred(end)`**: writes become durable only when `finish` returns `Ok`. Every backend uses this kind
  since 2.8.
- `finish` returns `Ok(warnings)`: what failed once the writes were durable and lost none of them (2.8). Only git-meta
  has any: the re-stamp of its log after the commit (below). `vci run` prints each as `vci: warning: …` after the
  project's lines and reports every unit as stored.
- **git-meta** (2.8): the batch shares one git-meta session and one connection to git-meta's SQLite store, and its
  writes are one `BEGIN IMMEDIATE` transaction on that connection, begun by the first write and committed by
  `finish`; each write is a savepoint in it, so a write that fails leaves the others. Inside the batch vci writes
  git-meta's tables itself, with the statements git-meta-lib 0.1.13 (pinned exactly) runs for `set` of a string and
  for `remove`, keys checked with its `validate_key`; outside one, writes go through git-meta as before.
  `a_batch_stores_what_the_calls_store_one_by_one` (vci-git) compares the rows, log entries and deletion records
  either way. The written keys' log entries are stamped once the commit is done (`stamp_written`); stamping is a
  transaction of its own, so when it fails the writes are stored and `finish` returns a warning, not an error. A
  SQLite error of a write inside the batch, or of its commit, reads as the same write through git-meta reads
  (`git-meta: database is locked`, 2.7's text). A batch opened inside the batch joins it. Writes on the batch's thread read the batch's own writes (the slot's keys, whether a
  value is already there); other readers see none of them before `finish`, which the trait allows. Storing 1,200
  units was 4,800 commits on two connections (0.7 s) before. The batch's connection keeps its savepoints' journal in
  memory (`temp_store = MEMORY`) and a 64 MiB page cache: with a temporary file per savepoint and the default cache
  spilling into the WAL, 1,200 units' writes took 0.5 s of the batch; with them, 0.05 s. The session and the
  connection are the repository's one store (`AttestStore::store_path`, `<git common dir>/git-meta.sqlite` since
  2.7.33; section 15), so a batch in a linked worktree writes the file every worktree reads, and the batches of two
  worktrees take turns on its write lock (at most the 5 s busy timeout), as two runs in one worktree do. After the
  stamp, `finish` empties the WAL (`PRAGMA wal_checkpoint(TRUNCATE)`, best effort, 100 ms busy wait, as the SQLite
  store does when it closes): the one transaction writes every page it changes to the WAL (20 MB for 1,200 units),
  and the trait store's pooled reader is a read-only connection, which cannot checkpoint when it closes last, so the
  file stayed and the next command to open the store read all of it first (a plan's "fetch the stored values" 0.04
  to 0.10 s instead of 0.02 to 0.03). On 1,200 Go units (release build) a run left a WAL of 22 to 31 MB before and
  none after (5 runs each), the next plan's line took 0.03 to 0.07 s before and 0.02 to 0.03 s after, and the
  checkpoint itself took 5 to 7 ms (the commit's own checkpoint has already written the pages back).
  `a_finished_batch_leaves_no_write_ahead_log` (vci-git) holds a pooled reader across a batch of 200 units and finds
  no WAL left.
- **SQLite** (2.8): the batch pins one pooled connection to the thread; the first write begins `BEGIN IMMEDIATE` on
  it, each write is a savepoint, and `finish` commits (a dropped batch commits too). Reads on that thread use the
  pinned connection inside the transaction, so they see the batch's writes; other connections see them after
  `finish`, and another writer waits for it (at most the busy timeout). As git-meta's, the connections keep
  savepoint journals in memory, and the batch raises the pinned connection's page cache to 64 MiB until `finish`.
  When SQLite ends the transaction itself (an I/O error, a full disk) or the connection is lost, the batch is broken:
  later writes and `finish` fail.
- **PostgreSQL**:
  - `put`, `put_manifest`, `remove` and (2.9) `put_objects` and `remove_objects` are queued so that `finish` reaches
    the state the same calls made one by one would: per id each object; per slot the last put (it replaces every
    stored key of its slot), whether a later removal took that put's own key away (the slot then ends empty), and
    the keys removed otherwise; per root the last manifest; the object ids to remove under the orphan rule.
  - `finish` flushes them in **one transaction**, in the format-3 order below: objects (one UNNEST upsert),
    manifests (one UNNEST upsert), attestations (one UNNEST upsert), the removed keys (one `DELETE … = ANY`, a `gone`
    row each), the emptied slots (one `DELETE`, only when there are some, `gone` rows too), the queued object removals
    (one `DELETE` under the orphan rule, `gone` rows), then one statement that numbers every row written from the
    namespace's `seq` counter (section 17, "Objects, columns, `seq` and `gone`").
  - A large batch flushes early at 2,000 attestations and removals or 32 MiB (manifests count only toward the bytes),
    so 1,000 units with their manifests stay one transaction. Each flush is its own transaction, and a failed flush
    fails `finish`.
  - Inside a deferred batch, `put` returns the entry it will store. An unhinted put first looks up the slot's existing
    key (one read). `vci run` always passes a hint.
- **Format 3 (2.9), every backend**: a deferred batch's `finish` applies its writes **in this order**, atomically or
  as transactions each cut between whole units: the object puts (`put_objects`), then the manifests, then the
  attestations, then the removals with the deletion records a backend keeps for its replicas (`gone` rows), then any
  `remove_objects` queued in the batch. So no reader, on the store or on a replica syncing it by `seq`, sees a
  record whose objects or manifest are missing, or a unit with neither its old nor its new record. On libSQL, whose
  batch is several transactions, the objects go in the first and again in every later one until a transaction that
  carries them commits (section 18), so a lost first transaction never leaves a stored record without its objects. A `put_objects`
  inside a deferred batch may count every object as new. The write model per 800-unit partition is 4 object puts,
  N record puts, ~1.2 N removals and their `gone` rows (STORE-V2 section 2.1), flushed early at the backend's write
  count and sent on libSQL as transactions bounded by bytes.

**How `vci run` stores a project's units** (`StoreLoop` in run.rs):

1. Every unit's verdict is decided first, in parallel: checked and signed. The shared base manifests (vci 2.1.8) are
   the entries every signed unit of a group shares, so they are known only once every unit is signed.
2. The shared base manifests are stored with `put_manifest`, outside the batch. A failure is a warning, and that
   base is dropped: its group's units encode their manifests whole (section 4, `put_manifest`).
3. (2.8) On the check pool, each unit is made ready to store: the supersession reads (`read_units`) of what it
   supersedes, and its manifest encoded on its base. Each is handed in unit order to one writer thread, which opens
   the batch (`store.batch().ok()`: an `Err` from `batch()` is ignored, and the writes go unbatched) and, as soon as
   a unit and every unit before it are ready, refuses or stores it: its manifest, its attestation (`put_for_test`),
   then the removal of what it supersedes. Readers on the pool see the store as it was before the batch.
4. The batch is finished right after the project's units, before the project's timing lines.

**Reporting rule.**

- For an immediate batch each unit is reported as it is stored, as in 2.7: the `vci: attested …` line and
  `UnitOutcome{attested: true}`. A failure to finish is a warning (`vci: warning: ending the <kind> store's write
  batch: …`), because every write was durable already.
- For a deferred batch, the loop holds each stored unit's line, outcome, supersession count and dropped manifest roots
  until `finish`, and (2.8) every other line of the loop too (a unit's warnings, refusals, failed removals), so the
  report comes out in unit order, as git-meta's and SQLite's did when their batches were immediate. (PostgreSQL's
  refusals and warnings came first before 2.8.)
  - `Ok` prints and records them in unit order.
  - `Err` turns every held unit into a refusal, `signing or storing failed: storing the batch: <error>`, and rolls back
    the attested, refused and superseded counts and the dropped roots. The summary JSON, the audit log's `attested`
    list and `vci ci`'s output therefore never claim a unit that was not stored.
  - Units whose flush did commit before a later flush failed are reported as not stored. They are stored and will
    verify; this is the safe direction.
- Supersession removals are queued in the same batch after their unit's put. Because `finish` writes attestations
  before removals, a reader never sees a unit with neither its old nor its new attestation.
- Orphan-manifest collection runs once, after every project's batch has finished, and only when something was
  superseded.

The in-memory `MemStore` in vci-cli's tests (`store::mem`) has deferred, failing and warning batches; the unit tests
`a_deferred_batch_reports_in_order_once_it_finishes`, `a_failed_deferred_batch_refuses_every_unit_it_held`,
`a_failure_after_the_batch_stored_its_writes_is_a_warning` and `an_immediate_batch_reports_each_unit_as_it_is_stored`
(run.rs) hold the rule.

---

## 7. What fetch and push mean per backend kind

| kind | example | `exchange()` | `vci fetch` | `vci push` | `vci plan --fetch` | `vci ci --push` |
|---|---|---|---|---|---|---|
| replicated | git-meta | `Some` | merge the remote's metadata into the local store (blobless: keys and trees, no values) | publish local writes and deletion records | fetch on a background thread while projects are probed | push; a failure becomes a GitHub warning |
| local file | SQLite, libSQL's local file | `None` | says the store is local, prints the count, exits 0 | says there is nothing to push, exits 0 | nothing (`warm` only) | succeeds; `pushed: true` means "stored" |
| shared server | PostgreSQL, libSQL on a server (remote or replica) | `None` | says the store is shared, prints the count, exits 0 | says writes were stored when `vci run` made them, exits 0 | nothing | succeeds; see the publication gate |
| remote service | HTTP/gRPC | `None` (writes are global) | as shared | as shared | nothing | as shared |

The messages for a store without an exchange, as printed:

- `vci fetch`: `vci: the <kind> store at <location> is local|shared: nothing to fetch (N attestations stored)`.
- `vci push`: `vci: nothing to push: the <kind> store is local|shared; attestations were stored when vci run made
  them`.
- "local" or "shared" follows `Caps::shared_writes`.
- Both call `status()` first: a store that cannot be used exits 2 with its error.

Further rules:

- A `--remote` given to `vci fetch` or `vci push` on a store without an exchange exits 2 with
  `Unsupported{operation: "a remote"}` (`vci: error: the <kind> store does not support a remote`). On
  `vci plan --fetch <remote>` (and `vci ci --fetch <remote>`) the remote is ignored with `vci: warning: the <kind>
  store has no remote: --fetch <remote> is ignored`, also in the plan's warnings. On `vci ci --push --remote <remote>`
  it is ignored with `vci: warning: the <kind> store has no remote: --remote <remote> is ignored`. A CI workflow that
  switches backend therefore keeps working. Remotes in these warnings have their userinfo replaced by `***`.
- `vci push --rewrite-history` on a store without an exchange exits 2 with `Unsupported{operation: "rewriting
  history"}`. On git-meta it is `push(remote, PushMode::RewriteHistory)`.
- A replicated store's removals travel as deletion records. A later value beats an older record (re-attestation
  wins).
- A shared store's removals are a global, immediate DELETE with no records.
- A local file store has no propagation. Sharing it between machines is up to the operator, for example through a CI
  cache of the file, with last-writer-wins across parallel jobs.
- After its tests, an attesting `vci ci` prints `vci ci: N unit(s) attested`. Without `--push` the line goes on with
  "(stored locally; publish with `vci push`)" on a store with an exchange, and "(stored in the `<kind>` store)" on one
  without. With `--push` it ends there, or goes on with "(nothing to push)" when the run did not attest.

### The publication gate for shared stores

With git-meta, nothing leaves a CI job unless `vci ci --push` runs. Pull-request jobs typically do not push. That
covers new attestations and also supersession deletions, which are decided from the job's possibly partial refs
(`moved_on`, `live_trees`). A shared database would make every write and DELETE global at once.

So on a store with `Caps::shared_writes` (`cmds::store_mode(shared_writes, push)`):

- **`vci ci` without `--push`** signs (`StoreMode::SignOnly`) but stores nothing:
  - it opens no batch and calls no write method: no shared base manifest, no unit manifest, no attestation;
  - it reads no supersession candidates and removes nothing, and collects no orphan manifests;
  - it prints no per-unit `vci: attested …` line. Once per run, when at least one unit was signed, it prints `vci:
    not storing N attestation(s): the <kind> store is shared and vci ci was not given --push`, before `vci: N
    attested, M not attested`;
  - the units count as attested, with `stored: false`. That field is serialized only when false (the audit log's
    `attested` entries and `--summary` units), so git-meta output is unchanged;
  - the audit log records `pushed: false`, and `vci ci`'s "attested" line goes on with "(not stored: the `<kind>`
    store is shared and --push was not given)".
- **`vci ci --push`** stores directly, and the audit log's `pushed: true` means "stored in the shared store".
- **Plain `vci run`** always stores (`StoreMode::Write`): a developer publishing directly.
- Operators who do not want developers or pull-request jobs to publish give them a read-only role (section 17).
  The memo and flags then fail silently; they are hints. A job that runs untrusted pull-request code must hold a
  read-only credential (or none) whatever it runs: its tests can read the credential from the environment vci or
  the step's shell started with (section 9, "What this cannot hide"), and the gate does not stop them using it.
- A later option, if the gate proves too coarse, is a **Staged** wrapper: a local SQLite outbox over a shared
  backend, read as an overlay and published by `vci push`. The trait allows it, but it is not in v1.

---

## 8. Hints: the memo and flags

`passing_on`, `remember_passing`, `flag` and `set_flag` are optional capabilities (`Caps::keeps_hints`).

- **Never fail.** Any problem (no store, a read-only file, an unreachable server, a role without INSERT) makes reads
  return empty or `false` and makes writes do nothing.
- **Bounded time.** Hints use the backend's normal timeouts, and the circuit breaker cuts them off. On a libSQL server
  (2.8.2) a hint's write waits at most 5 s (or the request timeout, if shorter) behind other writers for the server's
  one write lock, is never sent again, and never latches the breaker: nothing waits for it to be stored.
- **Only what is new.** The libSQL store's `set_flag` sends nothing for a flag it read as set, and `remember_passing`
  writes only the entries `passing_on` did not return for that tree: a second plan of the same tree writes none.
- **Never trusted.** The memo only orders reads. Every candidate is still verified. Flags only start the Rails boot
  early.
- **Stored keys must match listings**, which is why key strings are identical across backends.
- **Retention.** `remember_passing` may forget entries older than 7 days.

Per backend:

- git-meta uses `vci_memo` and `vci_flags` in its store (`.git/git-meta.sqlite`, shared by the worktrees). A CI
  cache carries them, as in 2.7.
- SQLite uses `memo` and `flags` tables in its file; hint writes do nothing while the file does not exist.
- PostgreSQL uses server-side tables per namespace, and never creates the schema for a hint. A pull-request plan then reads master's memo with no
  cache, and flags become shared facts about the repository (a global `plan:natives:<project>` flag is acceptable).
- libSQL keeps them as SQLite does in its local mode, and as PostgreSQL does on a server (tables of the namespace,
  never created for a hint) in its remote and replica modes.
- A backend that keeps no hints leaves the defaults: plans still work, just without the memo's head start.
- A `FailedStore` keeps no hints.

---

## 9. Configuration

### Selection and precedence

The backend, highest precedence first:

1. **`VCI_STORE`**: a backend name: `git-meta`, `sqlite`, `postgres`, `libsql`, or another registered backend. It is
   trimmed and lowercased, and `postgresql` and `pg` mean postgres, `sqlite3` means sqlite, `turso` means libsql,
   `gitmeta` and `git_meta` mean git-meta. A name is a lowercase letter followed by letters, digits and `-`, at most 32 bytes. **Never a URL.** A
   value containing `://` is refused with "put the URL in $VCI_STORE_URL", and the value is not printed.
2. **The scheme of `VCI_STORE_URL`**: `postgres://` and `postgresql://` mean postgres; `sqlite:` means sqlite;
   `libsql://` means libsql. Any other scheme selects nothing: an `https://` or `http://` URL may be a libSQL server
   or anything else, so it needs `VCI_STORE=libsql` (or `[store] backend = "libsql"`), and `file:` too.
3. **`[store] backend`** in the **working tree's** `vci.toml`.
4. **The scheme of `[store] url`**, read as for `VCI_STORE_URL` (`libsql://`, `postgres://`, `postgresql://`), when
   `VCI_STORE_URL` is unset.
5. **`git-meta`**. With nothing configured, behaviour is exactly as in 2.7.

Empty variables count as unset. Every other setting comes from the environment, then `vci.toml`, then the default.
`vci store info` prints each setting with its source (`Sourced<T>`).

The server is `VCI_STORE_URL`, else `[store] url` (`Selection::url`, its `source` saying which). `VCI_STORE_URL` wins
over `[store] url` whatever either names. `[store] url` is used only by a store that takes a server: when the backend
comes from `[store] backend` and the url's scheme names another, the file contradicts itself (`vci.toml [store] url is
a libsql location but [store] backend is postgres`, an error); when it comes from `VCI_STORE` (a developer opting out
with `VCI_STORE=git-meta`), or git-meta or SQLite is chosen another way, the url is ignored with a warning. A
PostgreSQL store needs a `postgres://` or `postgresql://` url there (an `https://` one is an error).

Resolution happens once per repository per process, in `crate::store::for_repo` in vci-cli, before `vci plan` spawns
its `--fetch` thread. It reads the working tree's `[store]` (`config::working_tree_store`), calls
`vci_store::select::resolve(env, file)`, prints the selection's warnings, and opens the store with
`vci_store::open(factories, &sel, &cx)`. The result is memoized by the repository root, so `vci ci`'s plan and run
share one handle, one pool and one circuit breaker. On any error, selecting or opening, the handle is a `FailedStore`
(section 10).

### Environment

| variable | meaning | default |
|---|---|---|
| `VCI_STORE` | backend name | (see precedence) |
| `VCI_STORE_URL` | location: `postgres://user[:password]@host[:port]/db[?sslmode=…&sslrootcert=…]`, `sqlite:<path>` (absolute, or relative to the git common directory; no query), a libSQL server (`libsql://host[:port][/path][?authToken=…&tls=0]`, `https://…`, `http://…`) or file (`file:<path>`, no query). Wins over `[store] url`. **A secret.** | `[store] url` |
| `VCI_STORE_TOKEN` | a libSQL server's auth token (a Turso database token); wins over the URL's `authToken` and over `[store] token_command`, which is then never run. Sent only to a URL from the environment: with the URL from `[store] url` it is refused. **A secret**, redacted whole | the URL's `authToken`, else `[store] token_command` |
| `VCI_STORE_REPLICA` | the libSQL store's replica file (absolute, or relative to the git common directory); setting it asks for the replica mode | `[store.libsql] path`, else `vci-store.libsql` |
| `VCI_STORE_NAMESPACE` | a shared server's namespace (PostgreSQL, libSQL) | `[store.postgres]` or `[store.libsql] namespace`, else the repository id (smallest root commit) |
| `VCI_STORE_CONNECT_TIMEOUT_SECS` | bound on connecting, in seconds (a number, more than 0 and at most 3600) | 5 |
| `VCI_STORE_TIMEOUT_SECS` | bound on one statement or request, same form | 30 (a network backend lifts it to 10 min for `vci prune`, `OpenContext::long_running`) |
| `VCI_STORE_SYNC` | `off` disables SQLite `synchronous`, in git-meta's store (which also turns it off when `CI` is set) and in the SQLite backend and libSQL's files (which do not look at `CI`); `replica` asks the libSQL store for its replica mode | unchanged |
| unchanged, git-meta only | `VCI_FETCH_JOBS`, `VCI_LOCK_TIMEOUT_SECS`, `VCI_DELETION_RECORDS_DROP_AT`, `VCI_DELETION_RECORDS_KEEP_SECS` | |
| tests only | `VCI_TEST_POSTGRES_URL`, `VCI_TEST_POSTGRES=require`, `VCI_TEST_PG_BINDIR` (section 14); `VCI_TEST_LIBSQL_URL`, `VCI_TEST_LIBSQL_TOKEN`, `VCI_TEST_LIBSQL=require` (section 18) | |

`vci_store::select::ENV_VARS` lists the eight `VCI_STORE*` variables `resolve` reads (`VCI_STORE_SYNC` since the
libSQL replica). Every e2e
harness removes them from the environment of the commands it starts, so a developer's exported store never reaches
the git-specific assertions.

**Secrets model.**

- **Only `VCI_STORE_URL` carries a credential in a connection string, and only `VCI_STORE_TOKEN` a token apart from
  it.** `vci.toml` may say where the server is (`[store] url`, without a credential) and how to fetch its credential
  (`[store] token_command`, below), never the credential.
- **A credential from the environment is only ever sent to a URL from the environment.** `VCI_STORE_TOKEN` with the
  URL from `[store] url` is refused (`$VCI_STORE_TOKEN is set but the store's URL comes from vci.toml [store] url: …;
  set $VCI_STORE_URL as well …`): `vci.toml` is in every pull request, which could otherwise point CI's secret at a
  server of its own. (`VCI_STORE_URL` always wins over `[store] url`, so an `authToken` in it never meets a URL from
  the file.) CI therefore sets both, and a developer neither.
- `VCI_*` variables are built-in *ignore*: they reach every test process (`COMMON_IGNORE` in vci-adapter/src/lib.rs).
  Pull-request code runs in those tests, so vci-cli's `main` handles the URL specially. Its first statement is
  `unsafe { store::take_secrets() }`: it reads every name in `select::NEVER_TO_CHILDREN` (`VCI_STORE_URL`,
  `VCI_STORE_TOKEN`, and `VCI_STORE`, where a connection string may be put by mistake),
  keeps the values in a process-wide map of `Secret`s (a value that is not UTF-8 is kept lossily), and removes them
  from its own environment (`std::env::remove_var`, sound while the process has one thread). No test, adapter probe,
  hook, git command or token command it starts inherits them.
- **What this cannot hide.** `remove_var` changes the environment vci's own code and its children see, not the one
  the process started with: that stays readable to every process of the same user (`/proc/<pid>/environ` on Linux,
  `ps eww` and `KERN_PROCARGS2` on macOS), as does the CI step's shell, which set the variables. A test that goes
  looking reads the URL and the token there. Starting vci again with a clean environment would not help while the
  shell holds them, so vci does not try; the defence is the credential's scope, and the user docs say so
  (REFERENCE.md, "What vci cannot hide from a test"): a CI job that runs untrusted pull-request code holds no store
  credential or a read-only one (`turso db tokens create <db> --read-only`; a PostgreSQL role with `SELECT` only),
  and only trusted jobs (the default branch, or same-repository pull requests, whose authors could change the
  workflow anyway) hold one that can write. A token `[store] token_command` printed is in vci's memory only, never in
  an environment.
- `envpolicy::build_child_env` also drops those names, in loose mode too and even when `[env] set` names them, as
  defence in depth.
- The env closure passed to `resolve` (`store::env_lookup`) answers `VCI_STORE_URL`, `VCI_STORE_TOKEN` and
  `VCI_STORE` from the kept copies.
- `Secret`'s `Debug` and `Display` print it redacted, and `Secret::scrub` removes the URL and its password (raw and
  percent-decoded) from every library error. A token is a `Secret::opaque`: redacted whole (`***`), and scrubbed raw,
  percent-encoded and percent-decoded. `authToken` (and `auth_token`) is a secret query key, like `password`.
- `select::redact` masks a URL's userinfo as everything between `//` and the **last** `@`, so a password holding an
  unencoded `@`, `/` or `?`, in any order, is masked whole; where a path or query holds an `@` instead, more is
  masked than needed, never less. A secret query value that runs past that `@` (`?password=a@b`) is masked with it.
  The PostgreSQL client library ends a password at the *first* `@` and takes what follows, up to `/` or `?`, for the
  host (`postgres://u:pa@ss@host/db` connects to host `ss@host`), so for a URL with more than one `@`
  `Secret::scrub` also removes every `@`-, `/`- and `?`-separated piece of the password, the host and database that
  client would read, and each `@`-separated piece of a secret query value. Strings under 3 bytes are left (they would
  scrub ordinary words); the whole secret still goes.
- The metrics log records only the store kind (`"store": "<kind>"`, or `null` when the command opened no store), never
  the location.
- The CLI test `store_select::the_store_url_reaches_no_test_and_no_output` runs a Go test that writes
  `os.Getenv("VCI_STORE_URL")` and `os.Environ()` to a file outside the repository, and checks that neither the
  variable nor its password reaches it, nor any output or the metrics log. vci 2.7.32 passes the URL through.
  `store_credential` does the same for a token a `token_command` printed, and checks that nothing a failing command
  printed (a canary on its standard error, beside the token, in each frame below) reaches any output, a plan's JSON
  or GitHub output, its warnings, `vci ci`'s audit log or the metrics log.

### `vci.toml`

```toml
[store]
backend = "postgres"          # "git-meta" (default) | "sqlite" | "postgres" | "libsql" | another registered backend
url = "postgres://vci@db.internal:5432/ci?sslmode=verify-full"  # the server, never a credential; VCI_STORE_URL wins
token_command = ["op", "read", "op://ci/vci-store/password"]    # prints the credential (below); VCI_STORE_TOKEN wins
connect_timeout = "5s"        # overridden by VCI_STORE_CONNECT_TIMEOUT_SECS
timeout = "30s"               # one statement or request; overridden by VCI_STORE_TIMEOUT_SECS
compress = "off"              # 2.8.2, libSQL only: "zstd" stores format-1 values compressed; VCI_STORE_COMPRESS wins
record_format = 3             # 2.9: 3 (default) writes format-3 records on a store that keeps objects; 1 writes the
                              # envelope JSON a vci 2.8 reads, for one release; VCI_STORE_RECORD_FORMAT wins
explain_hashes = true         # 2.9: write the run's state object (the attested hashes `vci explain` prints; no verdict
                              # reads it); false writes three objects a run; VCI_STORE_EXPLAIN_HASHES wins
explain_hashes_days = 2       # 2.9: a state object older than this is removed even while referenced, by `vci run`'s
                              # orphan pass and `vci prune` (0 to 365; 0 writes the run's state object and removes it
                              # at the end of the same run: use explain_hashes = false instead); every writer applies
                              # its own working tree's setting to the shared store; VCI_STORE_EXPLAIN_HASHES_DAYS wins

[store.sqlite]
path = "vci-store.sqlite"     # relative to the git common directory, no `..`; absolute only via VCI_STORE_URL

[store.postgres]              # tuning only: the address is [store] url, never a credential
schema = "vci"                # [a-z_][a-z0-9_]*, at most 63 bytes
namespace = "acme-monorepo"   # VCI_STORE_NAMESPACE overrides; default: the repository id
pool = 8                      # connections per vci process, 1..=64
manifest_grace = "1h"         # an unreferenced manifest put more recently is kept; at most 30 days

[store.libsql]                # never an address or a token ([store] url, [store] token_command)
path = "vci-store.libsql"     # the local file or the replica, relative to the git common directory, no `..`
replica = true                # read a local replica of the VCI_STORE_URL server (VCI_STORE_SYNC=replica too)
namespace = "acme-monorepo"   # VCI_STORE_NAMESPACE overrides; default: the repository id

[store.options]               # non-secret strings for backends vci-store does not describe (HTTP, gRPC)
# region = "eu"
```

- Durations in `vci.toml` are `"500ms"`, `"5s"`, `"2m"`, `"1h"`, `"1d"` or a bare number of seconds. The environment
  variables take a number of seconds only.
- **`[store] url`** is the one place for the address (`url`, `host`, `user`, `password` and `dbname` in
  `[store.postgres]`, and `url`, `token` and `authToken` in `[store.libsql]`, stay **refused**). It must be a server's
  URL (`libsql://`, `https://`, `http://`, `postgres://`, `postgresql://`; a local file is `[store.sqlite] path` or
  `[store.libsql] path`) and carry **no credential**: a userinfo is refused (a user alone is allowed for PostgreSQL,
  which needs one), and so are a password or `authToken` in the query (any case, percent-encoded or not: the keys of
  `select::is_secret_key`, and any key that says token, pass, secret, key, jwt, pwd or auth), any query parameter of a
  libSQL server but `tls`, a fragment, a space or a control character (`select::check_file_url`). Every checkout, a
  pull request's included, carries `vci.toml`, so a credential there would be public. The errors name the key and
  never the value (`vci.toml [store] url carries a password (it was not printed): …`); the value is kept as a `Secret`
  until it is checked, so no `Debug` of the settings prints it, and it is never serialized back. A refused per-backend
  key deserializes into a value-less marker (`select::Refused`).
- A pull request that changes `[store] url` can point its own CI jobs at a server it controls, but never CI's
  credential (the rule above): the most it can do there is read records it wrote itself, which are verified like any
  other, or make its units run. **On a developer's or agent's machine it is different**: the credential there comes
  from `[store] token_command`, and is sent to whatever `[store] url` names, so the same change, with the command left
  alone, has that user's token sent to the pull request's server by any vci command that reads the store in its
  checkout, `vci plan` included, before any test runs. A change to `[store] url` needs the review a change to
  `token_command` gets (its **Trust**, below).
- `[store]` is **never an input**. It is not part of `Project::config_hash`, so switching backend invalidates no
  attestation.
- The base-commit `Config` (deny_unknown_fields) has `pub store: Option<vci_store::select::StoreSettings>`, so a base
  `vci.toml` with `[store]` still parses for policy. Unknown keys inside `[store]` are errors there, as everywhere in
  `vci.toml`.
- Selection reads the **working tree's** `[store]` through a lenient struct (`struct OnlyStore { #[serde(default)]
  store: Option<StoreSettings> }` with no `deny_unknown_fields` at the top level). A broken `[policy]` in the working
  tree therefore cannot stop the store from being chosen. A broken `[store]`, or a working-tree `vci.toml` that is not
  TOML at all, makes the store a `FailedStore`. In that last case `vci plan` runs everything and `vci fetch`, `vci
  push` and `vci prune` exit 2, where 2.7 used the base configuration and git-meta (`vci run` already failed on such
  a file). The message is `<path> (line N): [store] cannot be read[: unknown field …] (its values are not printed)`:
  serde's other messages quote values, so they are dropped.
- The base-commit and working-tree `Config` (the one `vci run`, `vci env` and the policy read) reports an error
  located in `[store]` or a table below it, or on a `store.` key or `store = {…}` inline table, the same way
  (`parsing vci.toml (line N): [store] cannot be read[: unknown field …] (its values are not printed)`): toml's own
  message quotes the source line, which would print a token put under a misspelled key (`[store.libsql] authtoken =
  "…"`), a duplicated one, or one on a line with an unterminated string. Errors elsewhere keep toml's message.

**Why the working tree, not the base commit.**

- The store is untrusted (section 1), so a pull request that switches backend can only make its own units run.
- It cannot redirect CI's credentials: one from the environment goes only to a URL from the environment. It can
  redirect the token a developer's `token_command` prints (the url and the command are both the checkout's), as it
  can change the command itself: running vci in a checkout takes the trust of running its tests (**Trust**, below).
- The working tree is available before base-ref resolution, which is when `--fetch` starts.
- Plan and run inside `vci ci` then agree on one store.

**Rollout rule.**

- vci builds older than 2.8.0 reject a `vci.toml` with `[store]` (deny_unknown_fields) and therefore run every test.
- `[store]` acceptance and the backends ship together, in 2.8.0. Introduce a backend with `VCI_STORE` and
  `VCI_STORE_URL` first; add `[store]` only once every runner and developer runs a vci that accepts it.
- The user docs say so next to the example.

### The credential from a command: `[store] token_command`

So that developers and agents need not export anything, `vci.toml` may say how to fetch the server's credential:

```toml
[store]
backend = "libsql"
url = "libsql://vci-vex-composal.aws-eu-west-1.turso.io"
token_command = ["com", "secrets", "get", "vci-store-token", "--org", "vex"]
```

- **What it supplies.** A libSQL server's token (remote and replica modes), and PostgreSQL's password when the
  connection string has none (`tokio-postgres`'s `Config::password`, set on each host's attempt). A store that takes
  no credential (git-meta, SQLite, libSQL's local mode) ignores it with a warning and never runs it.
- **Precedence.** `VCI_STORE_TOKEN`, then the URL's own credential (an `authToken` in `VCI_STORE_URL`, a password in
  a PostgreSQL connection string), then the command. When the environment gives a token the command is never run:
  in CI, which sets `VCI_STORE_URL` and `VCI_STORE_TOKEN` from secrets, it never runs. (With `VCI_STORE_URL` set and
  no token, the command supplies the token for that URL: the developer's own credential, for a URL the developer's
  environment names.)
- **When.** `resolve` only records the command (`Selection::token_command`); `Selection::token_credential(cx)` makes a
  lazy `credential::Credential` that the backend asks for when it **first connects** (libSQL's `Conn::database`,
  PostgreSQL's `Conn::connect`), never at selection or at `open`, and never from `warm()` (section 4): while the
  credential is a command not yet run (`Credential::pending`), a backend's `warm` does nothing, since its thread is
  never joined and a command it started could outlive vci and its timeout; the command then runs on the thread of the
  first real read, which waits for it. A command that does not reach the store (`vci --version`, `vci init`, `vci
  update`, `vci env`), or a plan that never reads it (no base ref resolved: everything runs), never runs it. It runs **at most once
  per vci process** for a command and directory: the result, a failure too, is kept in memory
  (`credential::FETCHED`, one `OnceLock` per command and directory; other threads wait for the run), never on disk.
- **How.** An array is the program and its arguments, run directly, with no shell; a string is run with `sh -c`, for a
  pipeline (the array is preferred). The working directory is the repository's top level (`OpenContext::repo_root`), and
  a relative program path holding a `/` (`["scripts/vci-token"]`) is the checkout's. stdin is `/dev/null`. The
  environment is vci's own, which `take_secrets` already emptied of `NEVER_TO_CHILDREN`; the command removes them again
  (`env_remove`), so `VCI_STORE_URL`, `VCI_STORE_TOKEN` and `VCI_STORE` are not in its environment. stdout is captured,
  at most 64 KiB (more is read and dropped, and refused); stderr is a pipe read on a thread of its own and dropped
  (`credential::discard`), so the command never blocks on it and nothing it wrote there is kept. Once the command exits,
  what it wrote on stdout is read within a second, even when a process it started (a secrets tool's daemon) keeps the
  pipe open. On unix the command leads a process group of its own (`process_group(0)`): after 60 s (or the connect
  timeout, when longer, `Credential::timeout`) the whole group is killed (`kill -KILL -<pgid>`, as the Rails adapter
  stops a test file, since the crate has no unsafe code to call `kill(2)`), so a wrapper script's program or each stage
  of a `sh -c` pipeline is stopped with it, and the command is waited for. Two consequences: outside the terminal's
  foreground group the command cannot prompt there (the system stops a process that reads the terminal, until the
  timeout), so sign in beforehand (`com login`, `op signin`, `ssh-add`); and a Ctrl-C that stops vci does not reach it,
  so a command still running then ends on its own (its output goes nowhere).
- **What it prints.** UTF-8, surrounding whitespace trimmed, not empty, one line, no control character: the token,
  kept as a `Secret::opaque` (redacted everywhere, scrubbed from every message the backend passes through
  `Conn::scrub` once it is known).
- **Failure** is `StoreError::Unavailable` for the backend, saying what happened and naming the command as `vci.toml`
  gives it (`TokenCommand::display`, quoted for sh, bash and zsh since 2.8.1, so that the command can be pasted with
  `> /dev/null` after it; not a secret), then `credential::HINT`, and never anything the command printed,
  on stdout or stderr: `the token_command (<command>) exited 3; vci shows none of its output, which may hold the
  credential: run the command yourself with its standard output discarded (> /dev/null) to see why` (since 2.8.1;
  2.8.0 said to run it, which prints the credential of a command that works into the terminal; standard error still
  shows, and can hold it too, so the agent skill tells agents never to run the command), and in place of `exited 3`: `was not found (…)`, `could not be started (…)`, `was killed by signal 9`, `did not finish within 60 s (it was stopped)`, `printed nothing on standard
  output`, `printed more than one line on standard output: it must print the credential alone`, `printed something
  that is not UTF-8 text on standard output`, `printed a control character on standard output`, `printed more than
  64 KiB on standard output`. A first version, never released, showed the end of stderr scrubbed of every piece of
  what stdout held; three reviews each found a frame the scrubbing missed, since stderr may hold the credential in a
  form stdout never showed: a pipeline whose last stage echoes its input when it cannot parse it and prints nothing
  (`jq: error … (while parsing '<token>')`), a wrapper that logs the token, stdout framed as `key=<token>&…` or
  `k=<token>!`, a passphrase with spaces. Hence no stderr at all (decision 19 in section 20). As for a store that
  cannot be reached: `vci plan` runs everything with the warning, `vci run` keeps the tests' exit code and stores
  nothing, and `vci fetch`, `vci push`, `vci prune` and `vci store info` exit 2. A token the server refuses says `the
  server refused the token from [store] token_command (<command>)`.
- **`vci store info`** names the command and never the token: `token: (from token_command: com secrets get
  vci-store-token --org vex) (vci.toml [store])` for libSQL, `password: (from token_command: …)` for PostgreSQL. It
  runs the command only because it reads the store (its status and count), as it always connected.
- **Trust.** The command, and the URL what it prints is sent to, both come from the checkout's `vci.toml`. Any vci
  command that reads the store runs the command with the user's own privileges, `vci plan` included (for Go, a plan
  otherwise runs only `go list`), and sends its token to the checkout's `[store] url`: running vci in a checkout takes
  the trust of running its tests, and a pull request that changes only the url, leaving the command alone, has the
  user's token sent to its server. A change to `[store] url` or `token_command` needs the review a change to a test
  helper gets. In a checkout not yet reviewed (someone else's pull request, an agent's sandbox), `VCI_STORE=git-meta`
  makes vci ignore both, with a warning, and never run the command. The command is never given a credential from the
  environment, and a credential from the environment is never sent to a URL from `vci.toml`, so in CI, where the
  environment's secrets win, none of this applies.
- **Examples.**
  - The Composal CLI (each read audited, admins only): `token_command = ["com", "secrets", "get", "vci-store-token",
    "--org", "vex"]`.
  - 1Password: `token_command = ["op", "read", "op://Engineering/vci-store/credential"]`.
  - A file: `token_command = ["cat", "/Users/me/.config/vci/store-token"]`. Weaker: the token sits on disk, readable by
    anything running as the user, and is neither audited nor revoked by a sign-out.
  - A pipeline (a string, `sh -c`): `token_command = "pass show vci/store | head -n 1"`.
- **A fork's pull request** in CI gets no secrets: the command runs there, fails (the program is not installed, or
  not signed in), and the plan runs everything, as it did without a store.

### Validation (`StoreError::Config`) and warnings

Errors (each displayed as `attestation store: <message>`):

- connection keys in `vci.toml` (`store.postgres.url`, `.host`, `.user`, `.password`, `.dbname`, `store.libsql.url`,
  `.token`, `.auth_token`);
- a `[store] url` that is not a server's URL or that carries a credential (above), a `[store] url` whose scheme
  contradicts `[store] backend`, and a non-`postgres://` one for PostgreSQL;
- `VCI_STORE_TOKEN` with the URL from `[store] url` (the trust rule);
- an empty `[store] token_command`, or one holding a NUL byte;
- a URL in `VCI_STORE`;
- a malformed backend name;
- an unknown backend (`unknown store backend "x" (from $VCI_STORE); this vci has: git-meta, sqlite, postgres,
  libsql`, from `vci_store::open`);
- a backend built out (`this vci was built without the postgres store (cargo feature `postgres`)`, from
  `MissingBackend`);
- `VCI_STORE` disagreeing with the scheme of `VCI_STORE_URL`;
- postgres without `VCI_STORE_URL` or `[store] url` (the message adds that GitHub does not pass secrets to pull requests
  from forks);
- a `sqlite:` `VCI_STORE_URL` without a path, or whose path holds `://` (another scheme's URL, which may carry a
  password, is never printed as a path), a query or a fragment (`sqlite:x.db?authToken=…`,
  `sqlite:x.db#authToken=…`, with `VCI_STORE` unset or `sqlite`: it would be taken whole as the file's name and
  printed as one; not printed);
- for libsql, a `VCI_STORE_URL` that is neither a server (`libsql://`, `https://`, `http://`) nor `file:<path>` (not
  printed), a `file:` URL with a query or a fragment (as for `sqlite:`, not printed), and, when the store opens, a
  server URL with a user or password, a fragment or a query parameter other than `authToken` and `tls` (not printed,
  nor the parameter's name: a token may be either), or the remote modes without a URL;
- a timeout outside (0, 1 h];
- a bad schema name or namespace (a namespace is 1 to 128 of `A-Z a-z 0-9 . _ : / @ -`);
- a pool outside 1..=64;
- a grace over 30 days;
- a SQLite or libSQL path in `vci.toml` that is absolute or contains `..`, or that holds a URL (`://` or `?`: a
  server's URL put there by mistake, which may carry a token, is neither taken as a file name nor printed);
- a working-tree `[store]` that cannot be read (above).

Warnings, printed once per process as `vci: warning:` lines when the store is opened, and added to the plan JSON's
warnings:

- `[store] backend` overridden by the environment (`vci.toml [store] backend = "sqlite" is overridden: using git-meta
  (from $VCI_STORE)`);
- `[store.sqlite]`, `[store.postgres]` or `[store.libsql]` ignored because another backend is selected;
- `VCI_STORE_URL` set (with a scheme that selects no backend) while the backend is git-meta;
- `VCI_STORE_TOKEN` set while no libSQL server is used (`$VCI_STORE_TOKEN is ignored: the store is sqlite (from
  $VCI_STORE)`, or `… libsql in local mode …`);
- `[store] url` ignored because `VCI_STORE` chose another backend, or git-meta or SQLite is the store (`vci.toml [store]
  url (libsql://db.turso.io) is ignored: it is a libsql location and the store is git-meta (from $VCI_STORE)`);
- `[store] token_command` ignored, never run, for a store that takes no credential (`vci.toml [store] token_command
  is ignored (not run): the store is sqlite (from $VCI_STORE), which takes no credential`);
- a libSQL replica asked for while `VCI_STORE_URL` names no server (`the libsql replica (from $VCI_STORE_SYNC) is
  ignored: … so the store is a local file`).

### Command-line surface

- **`vci store info [--format text|json]`** prints which store the repository uses and how it is set up, on stdout.
  - Text:

    ```
    store: git-meta
    location: .git/git-meta.sqlite (exchanged on refs/meta/main)
    settings:
      backend: git-meta (the default)
      connect_timeout: 5s (the default)
      timeout: 30s (the default)
    capabilities: shared writes no, lazy values yes, keeps hints yes
    exchange: vci fetch and vci push, on refs/meta/main
    status: ready
    attestations: 12
    ```

    The settings are `Selection::describe()` (secrets redacted; the backend-specific ones for sqlite, postgres and
    libsql: its `mode`, `path` or `replica`, whether a `token` is set and where, `(from token_command: <command>)`
    when a command supplies it, PostgreSQL's `password` likewise, and its `namespace`),
    or `settings: not resolved (see the error)`. The status is `ready`, `ready (schema version N)`, `absent: nothing
    is stored yet (<advice>)` or `unavailable`.
  - JSON: `kind`, `location`, `settings` (`[{name, value, source}]`), `caps` (`sharedWrites`, `lazyValues`,
    `keepsHints`), `exchange` (the exchange point or `null`), `status` (`ready`, `absent` or `unavailable`), `advice`,
    `schemaVersion`, `count`, `error` (`{code, transient, message}` or `null`) and `warnings`.
  - It exits 0 when the store can be read (ready or absent). Otherwise it prints what it knows, then fails with
    `vci: error: <error>` and exit 2. Run it first when a plan says "reading attestations from postgres: …".
- `vci fetch`, `vci push`, `vci ci --push` and `vci plan --fetch` behave per section 7.
- `vci init` sets up `.git-meta` and the meta remote only when the selected kind is `git-meta`. It calls vci-git
  directly (`AttestStore::new(repo)`).
- Later: `vci store init` (create or migrate a SQL schema with an owner role), `vci store copy --from <backend>`
  (section 20), `vci init --store <backend>`, and the action inputs `store` and `store-url` (the latter masked with
  `::add-mask::`).

---

## 10. Errors, failing open and bounded time

`StoreError` (non-exhaustive):

| variant | meaning | display |
|---|---|---|
| `Invalid{what, value, reason}` | an argument failed validation; nothing written | `invalid <what>: "<value>": <reason>` (vci-git's text) |
| `Config(String)` | selection or settings are wrong | `attestation store: <message>` |
| `Unavailable{backend, detail}` | cannot reach or open; the circuit breaker repeats it | `<backend> store unavailable: <detail>` |
| `Timeout{backend, operation, after}` | a bounded wait ran out | `<backend> store: <operation> timed out after <after>` |
| `NotInitialized{backend, advice}` | no schema, and this role cannot create it | `<backend> store is not set up: <advice>` |
| `Incompatible{backend, found, supported}` | schema newer than this vci | `… is newer than this vci reads (up to N): upgrade vci` |
| `Denied{backend, operation, detail}` | lacking privilege | `<backend> store refused to <operation>: <detail>` |
| `Unsupported{backend, operation}` | not offered by this backend | `the <backend> store does not support <operation>` |
| `Backend(Box<dyn Error + Send + Sync>)` | the backend's own error, displayed exactly; `downcast_backend::<GitError>()` recovers it | the error's own |
| `Other(String)` | anything else; replaces the CLI's own `GitError::Store(String)` constructions in plan.rs | the text |

`is_transient()` (`Unavailable`, `Timeout`) and `code()` exist for logs and `vci store info --format json`.
**Callers fail open on every variant.** The variants decide messages and exit codes, never whether a unit runs.

What each command does on a store error:

| command | on `Err` or `FailedStore` |
|---|---|
| `vci plan`, `vci explain` | a warning; every test of every project runs; exit 0 |
| `vci run`, `vci ci` | each unit that cannot be stored is refused with the reason; the tests still run (see below for the exit code) |
| hints | nothing happens |
| supersession, orphan GC | a warning |
| `vci ci --push` | a GitHub warning, `pushed: false`, exit code unaffected |
| `vci fetch`, `vci push`, `vci prune`, `vci store info` | exit 2 with the message |

**`vci run`'s exit code** depends on the variant (`store_unusable` in run.rs):

- When the store **cannot be used**, `Config`, `Unavailable`, `Timeout`, `NotInitialized`, `Incompatible`, `Denied`
  or `Unsupported`, the unit is refused with `vci: not attesting <unit>: signing or storing failed: <error>`, the
  failure goes to `RunOutcome::store_failures`, and the exit code stays the tests'. A `FailedStore`'s `Unavailable`
  is one of them.
- Any other error, `Invalid`, `Backend` or `Other` (every error git-meta returns), is a problem of the run, as in 2.7:
  `vci: error: not attesting <unit>: <error>`, and after the run `vci run` fails (exit 2) with `N problem(s) during
  the run (the rest ran): …`.
- `vci ci` reports both kinds as GitHub `::warning` lines (`attesting: …`) and in the audit log's `attestErrors`;
  its exit code is the tests'.
- A backend must therefore report "this store cannot be used here" (an unreachable server, a file that is not a
  database, a read-only role or file, a missing schema) with those variants, never as `Backend`: SQLite's garbage file
  is `Unavailable`, an unwritable directory `Denied` or `Unavailable`; PostgreSQL's unreachable server `Unavailable` or
  `Timeout`, a read-only role `Denied`, no schema `NotInitialized`; libSQL's unreachable server, refused token or
  missing database `Unavailable` or `Timeout`, a read-only token or a server that takes no more writes (a database
  over its quota, at its size limit) `Denied`, a token that may not create the tables `NotInitialized`, a record
  larger than the server takes `Unsupported` (for its unit alone).

**`FailedStore`.** When selection or opening fails, `for_repo` returns `FailedStore::for_request(factories, wanted,
&err)`. Its kind is the requested backend's when a registered factory has that name, else `unknown`. When the
working tree's `[store]` cannot be read, the kind is `unknown` unless `VCI_STORE` or `VCI_STORE_URL` names a backend.
Every read and write, and `status`, `batch` and `prefetch`, return `Unavailable{backend: kind, detail: <the error's
text>}`. `for_repo` prints nothing for a failed store; the failure shows where the store is used (the plan's
warnings and its `run_all` reason, run's refusals, the exit 2 of fetch, push, prune and store info).

**Bounded time.** A hung store would block `vci plan`; an erroring one only makes units run. Every backend therefore
bounds every wait:

- PostgreSQL: connect (5 s per host named, the whole connection: TCP, TLS, startup and authentication; each host
  tried in turn within its share), statement (30 s; 600 s
  for `vci prune`), lock (10 s), idle-in-transaction (60 s), TCP
  keepalives and `tcp_user_timeout` (30 s), and a pool checkout bounded by the connect timeout.
- SQLite (and libSQL's local and replica files): `busy_timeout`, the store timeout (30 s).
- libSQL on a server: connect (5 s, TCP and TLS), the server's first answer (the connect timeout: a handle's first
  request is a statement's description, so a server or proxy that accepts and never answers costs 5 s, not 30 s or
  ten minutes), each later request (30 s; 600 s for `vci prune`), retries of a busy server within the request's
  deadline, a request whose connection was lost under it (a keep-alive connection the server or a proxy closed while
  it sat idle, a reset) sent again on a new connection at once, then after 100 ms and 500 ms, within the same
  deadline, once the server has answered the handle (before that, such a loss latches at once, within the first
  answer's bound), a pool checkout bounded by the connect timeout; a replica's sync is one request under the same
  bounds, and a failed one falls back to the replica as it is for the plan and the run, and fails `vci store info`,
  fetch, push and prune (section 18).
- git-meta: `VCI_LOCK_TIMEOUT_SECS`.

**Circuit breaker** (network backends). After the first `Unavailable` or `Timeout` of reaching the server, a network
backend latches it, and every later call of that handle returns `Unavailable` at once (PostgreSQL's handle is the
CLI's one per repository, so in practice per process). A store that is down costs one timeout per
command, not one per call (4,000 listings would otherwise each wait). Conformance scenario c16 checks that the first
failure takes at most the connect timeout plus 1 s and the next 40 calls take under 2 s. A connection lost under a
request, once the server has answered the handle, is not yet such a failure: libSQL sends the request again on a new
connection first (section 18, "Lost connections"), since a keep-alive connection a server closed while it sat idle is
found out only that way, and a store that latched on it refused every later write of the job. Only when the request
sent again fails too, or a new connection cannot be made (refused at once when the server went away), is the breaker
latched. Before the server has answered the handle, no connection was kept alive to be lost: a server that accepts
and closes without answering latches the breaker at once, within the first answer's bound, as an unreachable one.

**git-meta's documented exception.** Its prefetch takes the per-repository exchange lock and may wait up to
`VCI_LOCK_TIMEOUT_SECS` (default 600 s) behind another vci's fetch or push in the same repository, as in 2.7. A
shorter deadline for plan-time prefetch is out of scope here (section 21).

---

## 11. Threads

The store is called concurrently by:

- the `--fetch` thread (an `Arc` clone);
- the project probe threads (`flag`);
- the plan's `VCI_JOBS` verifying threads (`manifest`, `set_flag`);
- the run's supersession workers (`read_units`, `manifest_decoded`).

Hence `AttestationStore: Send + Sync`.

- **Non-`Sync` resources are pooled inside the backend.** git-meta pools `Reader`s (section 15). SQLite pools
  `rusqlite::Connection`s (`Send`, not `Sync`), libSQL its Hrana connections (on one current-thread tokio runtime per
  handle, driven by `block_on` from the calling thread), and PostgreSQL `postgres::Client`s (`Send`, not `Sync`; each runs
  a private current-thread tokio runtime that is invisible to vci). The pool hands one resource to each concurrent
  caller and takes it back afterwards, so concurrency matches the per-thread readers of 2.7.
- **`WriteBatch` is `!Send`.** It ends on the thread that opened it, and only that thread's writes join it.
- **The code base stays synchronous.** The trait has no async methods, and the sync `postgres` crate hides its
  runtime.
- **Closing.** `store::close_all()` drops every memoized store at the end of `main`, before the metrics line is
  written, so pooled SQLite connections and `git cat-file` processes end with the command, as in 2.7.

---

## 12. Timing and observability

- **Backend timing lines.** Backends time their steps with `vci_store::timing::Step::start(kind)`, then `.lap(label)`
  or `.done(label)`. This emits `store: <kind>: <step>: <secs>s` through `vci_core::timing_line!`, so the line is
  recorded in the metrics log (`vci metrics` groups steps with numbers replaced by `#`) and printed under
  `VCI_TIMING`. Labels carry counts, never paths, test ids, hosts or URLs, and stay stable because metric history is
  keyed by them. SQLite, PostgreSQL and libSQL use `Step`; git-meta keeps its own lines.
- **git-meta** keeps every line it printed in 2.7 (`fetch: …`, `hydrate: …`, `read values: …`, `push: …`).
- **`put_manifest` seconds.** The static `AttestStore::put_manifest_seconds()` call in run.rs became
  `timing_report()`. git-meta returns `"put_manifest seconds: session …, read current …, set …, stamp …"`, and run.rs
  prints each line as `<project>: <line>`, so the line and its metric key are unchanged.
- **The plan's rounds** (section 5) time the re-read as `round N: read K candidate value(s) of U unit(s) again`. A
  round that fetched values keeps 2.7's line, `round N: fetch K more value(s) for U unit(s) not skipped, check them
  again (R still not)`; one that fetched nothing but read set-aside candidates prints `round N: read K candidate(s)
  set aside for U unit(s) not skipped, check them again (R still not)`; `round N: nothing more to fetch for U unit(s)
  not skipped` is unchanged.
- **SQLite** prints `store: sqlite: list N unit(s)`, `store: sqlite: read N value(s)` and, when a batch finishes,
  `store: sqlite: write N record(s)`; its `timing_report()` adds the handle's total, `store: sqlite: N write(s): S s`.
- **PostgreSQL** labels include statement counts (`store: postgres: prefetch N unit(s), M value(s), K statement(s)`,
  `prefetch N manifest(s), K statement(s)`, `write batch: N manifest(s), M attestation(s), K removal(s), S
  statement(s)`, `list N unit(s)`, `read N value(s)`). It also exposes an inherent `PgStore::statements()` counter for tests, and sets
  `application_name` to `vci <version> <command>` so `pg_stat_activity` shows which command each connection serves.
- **libSQL** prints its local and replica files' SQLite lines under `store: libsql: …`, and on a server labels with
  request counts (`store: libsql: prefetch N unit(s), M value(s), K request(s)`, `prefetch N manifest(s), K
  request(s)`, `write batch: N manifest(s), M attestation(s), K removal(s), R request(s)`, `list N unit(s)`, `read N
  value(s)`, `sync replica: N attestation(s), M manifest(s), everything|changes`). `LibsqlStore::requests()` counts
  requests for tests.
- **The metrics log** has `"store": "<kind>"` (the first store the command opened), or `null`.

---

## 13. The command line on the trait

**`crates/vci-cli/src/store.rs`** holds:

- `unsafe fn take_secrets()`, called first in `main` (section 9);
- `env_lookup(name)`: the kept copy for secret names, otherwise `std::env::var`;
- `set_command(&'static str)`: `main` names the running command (`Cmd::name()`) for `OpenContext::command`;
- `factories(&Repo) -> Vec<Box<dyn BackendFactory>>`: `GitMetaFactory::new(repo.clone())`, then `SqliteFactory` or
  `MissingBackend{kind: "sqlite", feature: "sqlite"}`, then `PostgresFactory` or `MissingBackend{kind: "postgres",
  feature: "postgres"}`, then `LibsqlFactory` or `MissingBackend{kind: "libsql", feature: "libsql"}`, by cargo
  feature (all on by default);
- `open_context(&Repo, command) -> OpenContext`:
  - `git_dir` is `repo.git_dir()` (`<root>/.git` if that fails);
  - `git_common_dir` is the directory `<git_dir>/commondir` names, git's own rule for linked worktrees, else
    `git_dir`;
  - `repo_id` is computed on first call and memoized (`Repo::repo_id`, the smallest root commit);
  - `jobs` is `VCI_JOBS`, else the number of CPUs;
  - `long_running` is true for `prune`;
- `for_repo(&Repo) -> Arc<dyn AttestationStore>`: memoized by `repo.root()` (git's absolute top level) in a static
  map, opened exactly once under its lock, printing the selection's warnings once. It never fails: an error gives a
  `FailedStore`;
- `selection_of(&Repo)` and `warnings_of(&Repo)` (for `vci store info` and the plan's warnings), and `used_kind()`
  (for the metrics log);
- `close_all()`, called in `main` before the metrics line;
- `#[cfg(test)] mod mem`: `MemStore`, an in-memory store whose batches can be deferred or failing and whose caps can
  claim shared writes, for unit tests of run.rs, cmds.rs and plan.rs.

**What changed in the commands**:

- Every `AttestStore::new(&repo)` call site of 2.7 (plan.rs, cmds.rs, run.rs) became `store::for_repo(&repo)`,
  except `vci init`'s git-meta set-up (below).
- Plan:
  - `store.warm()` at the start; the `--fetch` thread gets an `Arc` clone and calls `exchange().fetch`;
  - the lookup is `status()` plus `list_units(&ids)`, then one `read_values` (section 5);
  - `hydrate_for_plan` and `hydrate_more` call `prefetch`, and `hydrate_more` reads the set-aside candidates
    (section 5);
  - ManifestLoader dropped its per-thread reader slots and calls `store.manifest(root)` and `store.manifest(base)`;
  - `load_manifest(store, root, stored, base)` and the base cache take `StoreError`; the CLI's
    `GitError::Store(String)` constructions became `StoreError::Other`. A cached failed base read is now shown once,
    where 2.7 printed `git-meta store: git-meta store: …`;
  - messages use `kind()` and `caps().lazy_values`; `PlanResult` carries `store_kind` (not serialized) for `vci
    explain`'s `candidate N: <kind> <target> <key>`;
  - `plan_with` takes the store, and `Verifier` holds it.
- Run:
  - `prefetch(Units{choose: None})` before supersession; `last_durations` and `superseded_by` use `read_units`;
  - `put_hinted` became `put_for_test`, `remove_envelopes` became `remove`;
  - `drop_orphan_manifests` is `orphan_manifests` plus `remove_manifests`, with 2.7's two warnings;
  - the store loop is `StoreLoop` (section 6), with `StoreMode { Write, SignOnly }` as the last argument of
    `run_units`; `RunOutcome` gained `store_failures` and `AttestedUnit` gained `stored`;
  - the `put_manifest seconds` line comes from `timing_report()`; the attested line says `as <kind> …`.
- Commands (cmds.rs):
  - fetch, push, `vci ci --push` and `plan --fetch` branch on `exchange()` and use `remote_location` and
    `exchange_point` (section 7). `vci ci --push` calls the same `push_with` as `vci push` with the ci's repository;
  - push uses `PushMode`; `PushStatus` matches have a `_` arm (`vci: push to <remote> finished`, which git-meta never
    reaches);
  - prune uses `status()`, `prefetch(Attestations)`, `read_all`, `remove(vec![e])`, `prefetch(Manifests)`,
    `manifest`, `manifest_roots` and `remove_manifests(&[root])`; its "(run `vci fetch`)" hints appear only when
    `caps().lazy_values`;
  - verify uses `prefetch(Manifests)` and `manifest`. Its message for an envelope verified outside a repository, `…
    is stored in the repository's git-meta store …`, stays literal, because no store could be opened there;
  - `vci init` keeps `setup_git_meta` on vci-git, guarded by `kind() == "git-meta"`;
  - `vci ci` applies the publication gate (`store_mode`) and `vci store info` is new.
- **Format 3 (2.9)** on the trait:
  - `vci run` (run.rs) groups the attestable units by header tuple, builds the run's hdr per group, tables per group,
    one shape and one state (`vci_core::Run::build`; no state under `explain_hashes = false`), signs each unit's v2
    statement as it signs a v1 one, and queues one deferred batch: `put_objects` first, then per unit `put` with its
    `Columns`, then its supersession removals. Supersession reads the old records' signed statements (`commit`, the
    platform through the hdr, `issuedAt`, `entriesRoot` for "same files"), the columns only pre-filtering which old
    records to read, and none while the store holds a manifest (`UnitRecords::window`, one `manifest_roots` read a
    run); `last_durations` reads the columns on a store that keeps them and the values on git-meta. After
    the batch, on a store with `Caps::columns`, `remove_objects` of the superseded records' object ids once per run
    (git-meta's referrer scan reads every value, so its orphans are left to `vci prune`), then
    `prune_state_objects(explain_hashes_days)` on every format-3 write run; `set_max_ttl` is passed the largest
    `policy.max_ttl` of the projects involved (the libSQL `gone` purge horizon). A store without `Caps::objects`, and
    a `FailedStore`, is written in format 1, as `record_format = 1` is;
  - the plan (plan.rs) tells a value's format with `decode_record`, verifies a frame as the envelope rebuilt from it,
    compares the key's signer segment with the verified key's signer id (`signer`), loads the hdr, tables and shape
    objects its format-3 candidates name through one `get_objects` per round in candidate-priority order
    (`Prefetch::Objects` first on a lazy store) under a 16 MiB verdict-object cap, recomputes each id, checks the hdr
    once per `(project, hdr id)`, resolves the descriptor and observes the resolved set at HEAD (`inputs`), and loads
    at most 16 state objects, named by the records' `state_obj` column, for the failure text;
  - prune (cmds.rs) lists with `list_all` and `columns` on a store that keeps them, reads the expired candidates,
    the records of a unit with one beyond `keep` by the hints, the rows the columns do not describe, and every row
    while a manifest remains (`manifest_roots`), confirms each delete from the signed statement (expiry; the
    unit's order by the signed `issuedAt`), then `orphan_objects`, `remove_objects` and `prune_state_objects` (`--objects` runs only these,
    `--older-than DAYS` sets the state age for one run); git-meta's prune reads every value as before;
  - `vci store upgrade --begin` and `--finish` reach `SqliteStore`, `PgStore` and `LibsqlStore` directly (the trait
    has no upgrade method: the DDL is an operator action on one concrete backend); `vci verify` decodes a frame to
    its envelope (`--envelope` prints it and verifies nothing), resolves the set from the run's objects and checks the
    root only against `--manifest FILE`.
- `envpolicy::build_child_env` drops `NEVER_TO_CHILDREN`; `metrics::write` takes the store kind.
- **e2e harnesses** remove `vci_store::select::ENV_VARS`: the scrub loops of e2e_cargo, e2e_go, e2e_pytest, e2e_rails
  and e2e_rspec chain them, the `env_remove` lists of e2e, e2e_chain and e2e_node_test too, and ad-hoc `vci` commands
  in e2e, e2e_cargo, e2e_go, e2e_node_test and e2e_keyless go through a `vci_cmd()` helper. `action_contract` clears
  the environment and `workflow_key` starts no vci, so they are unchanged. `tests/store_common` still uses vci-git's
  `AttestStore`.
- **`tests/store_select.rs`** (a copy of `fixtures/go-abcd`, skipped without `go`) checks selection end to end:
  nothing configured is git-meta and pushes `refs/meta/main`; an unknown store, postgres without a URL, a URL in
  `VCI_STORE` and a password in `vci.toml` all fail open (plan exits 0 and runs everything; fetch, push, prune and
  store info exit 2) without printing the secret; `VCI_STORE_URL` is in no test's environment; the environment
  overrides `vci.toml` with a warning.

---

## 14. The conformance suite

The suite lives in vci-store behind feature `conformance`: `src/conformance/scenarios.rs`, plus `StoreFactory`,
`World`, `fixtures` and the macro in lib.rs. Each backend runs it from its own test binary:

```rust
// crates/vci-store-sqlite/tests/conformance.rs
vci_store::conformance_suite!(Some(Box::new(SqliteWorlds) as Box<dyn vci_store::conformance::StoreFactory>));
// crates/vci-store-postgres/tests/conformance.rs
vci_store::conformance_suite!(testkit::available().then(|| Box::new(PgWorlds) as Box<dyn StoreFactory>));
// crates/vci-git/tests/conformance.rs
vci_store::conformance_suite!(Some(Box::new(GitMetaWorlds) as Box<dyn StoreFactory>));
// crates/vci-store-libsql/tests/conformance.rs: once per mode, in modules local, remote and replica
vci_store::conformance_suite!(testkit::available().then(|| Box::new(Worlds) as Box<dyn StoreFactory>));
```

Run it with:

```sh
cargo test --locked -p vci-git --test conformance
cargo test --locked -p vci-store-sqlite --test conformance
VCI_TEST_POSTGRES=require cargo test --locked -p vci-store-postgres --test conformance   # a server from the testkit
VCI_TEST_LIBSQL=require cargo test --locked -p vci-store-libsql --test conformance       # sqld, turso dev or Docker
```

The macro expands to one `#[test]` per scenario, so failures are named and run in parallel, each in its own world. A
factory of `None` makes every test say `skipping <name>: this backend is not available here` and pass.

The table below is what each scenario checks. Three of the worlds (libSQL's are in section 18):

| | git-meta (`GitMetaWorlds`) | SQLite (`SqliteWorlds`) | PostgreSQL (`PgWorlds`) |
|---|---|---|---|
| world | a bare remote serving partial clones | a temporary directory with one store file | a schema of its own, namespace `test` |
| peers | `--no-local` clones with a metadata remote for `origin` | separate handles on the file | separate `PgStore`s (own pools and caches) |
| `sync` | push from one peer, fetch into the others | nothing | nothing |
| `backing_exists` | `.git/git-meta.sqlite` exists | the file exists | the schema exists |
| `unreachable` + `secret` | a clone whose metadata remote is `https://vci-user:<secret>@127.0.0.1:1/meta.git` | a file that is not a database (no secret) | a closed port with a password, connect timeout 1 s |
| `read_only` | `chmod -R a-w .git` (undone on drop) | `chmod 0444` the file, a new handle | a role with USAGE, SELECT, and INSERT and UPDATE on memo and flags |
| `inject_raw` | a `git_meta_lib::Session` | a raw INSERT | a raw INSERT |
| `make_unreadable` | the row points at a blob the object database does not hold | `encoding = 99` | `encoding = 99` |
| `failing_batches` | none (no way to make the transaction fail from outside) | none (no way to make the transaction fail from outside) | a role without INSERT on attestations (INSERT on manifests) |
| `age_objects` (2.9) | `last_timestamp` of the object rows in `.git/git-meta.sqlite` moved back | `UPDATE objects SET put_at = put_at - ?` on the file | `UPDATE objects SET put_at = put_at - make_interval(secs => ?)` in the schema |

What the scenarios can and cannot check through the trait:

- **c24** checks `location`, every error and outcome, fetch and push output and `remote_location`, but not `Debug`:
  `dyn AttestationStore` has no `Debug`, so each backend's own tests check that (PostgreSQL test 1).
- **c17** requires `Denied` or `Unavailable` from a store without an exchange. git-meta reports its own errors as
  `StoreError::Backend` (section 10), so for a store with an exchange any error passes. A removal through a
  read-only handle may also succeed having removed nothing.
- **c08** removes an unreferenced root only on a store that is not shared; a shared store keeps a root put within its
  grace period, which **c29** checks. With the default grace of an hour, c29 cannot tell a root kept because it is
  referenced or a base from one kept because it is recent; PostgreSQL's own test 11 checks those with grace 0.
- **c16** bounds the first failure at 4 s (worlds configure a connect timeout of at most 3 s) and 40 more calls at 2 s.
  With an exchange the first failing call is `fetch`, since reads of the local store still work.
- **c29** is skipped by every store that is not shared (git-meta, SQLite, libSQL's local file), **c30** by every one
  without a failing batch hook (all but PostgreSQL and libSQL's remote mode), and **c14** by every backend but git-meta
  (no exchange). A skipped part says so on stderr.

- **Branching.** Scenarios branch only on `Caps` and on `exchange().is_some()`.
- **Optional hooks.** `World` hooks that return `None` or `false` skip that part of a scenario and say so on stderr:
  `backing_exists`, `unreachable` with `secret`, `read_only`, `inject_raw`, `make_unreadable`, `failing_batches`,
  and (2.9) `age_objects(i, ids, by)`, which moves peer `i`'s objects' `put_at` back by `by` behind the backend's
  back, so that c37, c38 and c42 can cross the one-hour grace and the state TTL without waiting (`UPDATE objects SET
  put_at = put_at - ?` on a SQL store; on git-meta `UPDATE metadata SET last_timestamp = last_timestamp - ?` for the
  object's key of each kind in `.git/git-meta.sqlite`).
- **Objects (2.9).** c35 to c39 and c42 run only on a store whose `Caps::objects` is set and skip otherwise, after c35
  has checked that every object method of such a store is `Unsupported`; c36's validation and c40's and c41's
  format-3 records run everywhere (a store without `Caps::columns` answers none in c40 and skips its second half).
  The fixtures are `conformance::scenarios::Run3` (a run's four objects built with vci-core's encoders, their ids, and
  format-3 records with the columns a writer would copy from their statements) and `RunIds`.
- **Environment.** The suite never sets environment variables (unsafe in Rust 2024, and racy). Each backend runs it
  in its own test binary.

Fixtures match the git-meta tests (`conformance::fixtures`): signers `S1` and `S2`, `hex64(seed)` storage keys, units
`src/a.test.ts`, `src/b.test.ts`, `rust/core#test:it` and `.`, the tree prefix `TREE_HEAD`, and DSSE-shaped envelopes
whose base64 payload carries `predicate.manifestRef`.

| # | scenario | checks |
|---|---|---|
| c01 | round_trip_exact_bytes | 5 KB and 200 KB values, tabs and newlines, byte-exact; an unknown unit lists empty; an identical re-put writes nothing; new bytes replace |
| c02 | reading_creates_nothing | status, list, manifest, count and hints on an absent store create no file or schema |
| c03 | invalid_arguments_write_nothing | `Invalid` with what = signer_id, storage_key, test_key, target, envelope (non-UTF-8, empty), input root, manifest; count stays 0 |
| c04 | same_inputs_replace_whatever_the_hint | a newer hint replaces the slot; an unhinted put keeps the key; another signer has its own slot |
| c05 | listing_is_key_only_and_byte_ordered | `Unread` entries; keys chosen so bytewise and en_US order differ (`aa:ff.-` vs `aaf0:1.-`); the same listing twice; list_all by (target, key) |
| c06 | list_units_answers_each_id_in_order | duplicates, unknown ids, `project` target, cargo `#` ids; equals one-by-one listing |
| c07 | read_values_reports_each_record | a key removed after listing gets `GONE`, the others `Read`, the call `Ok` |
| c08 | manifests_and_bases | the put_manifest flag; manifest, manifests (order and `None`), manifest_roots; manifest_decoded through a base; a missing base gives "not in the store"; remove_manifests validates first |
| c09 | remove_returns_what_existed | the caller's bytes returned; a second remove returns nothing; count |
| c10 | deletion_reaches_peers_and_reattestation_wins | through `sync` for an exchange, at once otherwise |
| c11 | union_after_sync | both peers hold both writes |
| c12 | concurrent_writers_lose_nothing | 8 threads × 5 puts through one handle, plus across peers |
| c13 | same_key_from_two_peers_converges | the peers agree on one value |
| c14 | fetch_and_push_say_what_happened | exchange: NothingStored, then Pushed, then UpToDate, and `found`; none: `exchange()` is `None` |
| c15 | prefetch_makes_chosen_values_readable | chosen values and their manifests readable after one prefetch; non-lazy stores return `Hydration::default()` |
| c16 | an_unreachable_store_fails_fast | first failure within connect timeout + 1 s; 40 more calls under 2 s; hints empty, never panic |
| c17 | read_only_store_reads | reads work; writes are `Err` (Denied or Unavailable), never a panic |
| c18 | hints_round_trip | with `keeps_hints`, remember then recall and set then get; otherwise empty |
| c19 | batch_writes_are_durable | immediate: visible inside the batch; deferred: visible after `finish`, to another peer too |
| c20 | many_values | 1,200 units listed, prefetched and read |
| c21 | concurrent_first_writes_create_the_store_once | 6 handles write first at once (catches schema-creation races) |
| c22 | one_unreadable_value_hides_only_itself | via `make_unreadable` |
| c23 | foreign_keys_are_ignored | via `inject_raw`: listings and count skip them |
| c24 | errors_never_show_secrets | Debug, location, errors and fetch output of the unreachable handle never contain `secret()` |
| c25 | reads_see_this_handles_writes_after_a_prefetch | put, remove and put_manifest after a prefetch are seen at once, including a manifest the prefetch found absent |
| c26 | status_and_count | Absent or Ready, then Ready after a write; manifests not counted |
| c27 | read_units_matches_list_then_read | the override and the default agree |
| c28 | orphan_manifests_keeps_what_is_referenced_or_unknown | referenced roots kept; an `Unknown` payload makes the answer empty |
| c29 | remove_manifests_keeps_referenced_and_recent | when shared: referenced, base-of-another and within-grace roots kept and not counted |
| c30 | failed_batch_reports_and_loses | via `failing_batches`: `finish` is `Err` and the writes are not visible |
| c31 | failed_store_fails_every_call | `FailedStore`: every read and write `Unavailable`, hints empty |
| c32 | concurrent_readers_and_writer | 16 threads of list_units, manifest and read_values while one writer puts and removes: no `Err`, no torn values |
| c33 | key_and_target_parity | stored keys and targets equal `key::attestation_key_hinted` and `key::target_label` |
| c34 | copy_keeps_keys_and_targets | `put(NewAttestation::copy_of(..))` into a second world keeps keys, targets and bytes |
| c35 | objects_round_trip_and_idempotent_put | (2.9) a run's four objects read back byte for byte with their kinds and ids (the binary state object through a text backend's base64); a re-put stores nothing new; unknown ids left out, duplicates answered once; another peer reads them; without `Caps::objects` every object method is `Unsupported` |
| c36 | objects_are_validated_and_bounded | `Invalid` object id (not 64 lowercase hex) and object (empty, over its kind's bound, not headed by `vo` and the kind byte); one bad object among good writes none; a put whose columns name a bad id writes nothing |
| c37 | orphan_rule_keeps_referenced_and_recent_objects | via `age_objects`: nothing within the grace goes; past it only an unreferenced object; a put, identical bytes included, restarts the grace; without the record its objects are orphans, the state object excepted on a store without columns |
| c38 | state_objects_expire_even_while_referenced | via `age_objects`: `prune_state_objects` removes an aged state object a record still references and no other kind; the record stays readable |
| c39 | objects_are_visible_before_their_record | in a batch, a reader on another handle that sees the record gets its objects; after `finish` both are there, on another peer too |
| c40 | columns_match_the_put | `columns` gives back what the put passed, in input order; none for a format-1 record, a put without them, a removed key, and everything without `Caps::columns`; a re-put without columns clears them, with others replaces them; a copy with `with_columns` keeps them |
| c41 | mixed_formats_in_one_namespace | an envelope and a frame of one unit side by side: key order, byte-exact reads, `decode_record` tells them apart, the frame's `ManifestRef` is `Inline` so `orphan_manifests` goes on, `record_object_refs` names its objects; `count` sees both |
| c42 | object_deletions_reach_peers | objects and a frame reach another peer (a replica, by `seq`), and so do the record's removal and, aged past the grace, the objects' (`gone` rows): the peer lists nothing, reads the stale entry as `GONE`, gets no object |

Backends keep their own tests for what is theirs:

- git-meta keeps its 62 store tests (`store`, `store_deletion_records`, `store_lazy`, `store_robustness`), unchanged
  by the trait work (2.7.33 and 2.7.34 added assertions of their own), plus `store_worktrees.rs` for the store its
  worktrees share and `store_trait.rs` for the trait implementation (section 15).
- SQLite adds its own tests for the WAL checkpoint, the read-only fallback, `application_id` and `user_version`.
- PostgreSQL adds its own tests for advisory-lock migrations, the statement timeout, the role and RLS recipes,
  namespace isolation, batch deduplication and the round-trip budget.
- libSQL adds its own for the local file's format, the request budget, tokens, deadlines and the replica's sync
  (section 18).
- vci-store's own `tests/keys.rs` (the key format and its edge cases, `ManifestRef`, `StoredEnvelope::from_key` and
  `state()`, `NOT_FETCHED` byte for byte, `StoreError` display, `FailedStore`) and `tests/select.rs` (the precedence
  matrix, refused keys, timeouts and bounds, `redact` and `Secret::scrub`, libSQL's modes and tokens).

### The temporary-PostgreSQL test helper

`vci-store-postgres/src/testkit.rs` is a `#[doc(hidden)]` module for tests only. It is always compiled, so
integration tests (the crate's own, and vci-cli's through a dev-dependency) need no feature. `pg()` finds a server
once per test process (a `OnceLock`):

1. **`VCI_TEST_POSTGRES_URL`**, if set: CI's `services: postgres`, or any server where the role may create schemas,
   roles and databases. `sslmode=prefer` is appended when the URL names none, since vci requires TLS for a host that is
   not this machine and a service container has none.
2. **Otherwise, one throwaway cluster.**
   - `initdb` and `pg_ctl` are looked for in `VCI_TEST_PG_BINDIR`, then `PATH`, then `pg_config --bindir`, then the
     newest `/usr/lib/postgresql/*/bin`, `/opt/homebrew/opt/postgresql@*/bin` and `/usr/local/opt/postgresql@*/bin`.
   - It runs `initdb -U vci -A trust -E UTF8 --no-sync --locale=en_US.UTF-8`, so a missing `COLLATE "C"` fails c05,
     falling back to `--locale=C`.
   - `postgresql.conf` gets TCP only on 127.0.0.1 with `unix_socket_directories=''` (macOS caps socket paths at about
     104 bytes), `fsync`, `synchronous_commit` and `full_page_writes` off, and `max_connections=300`.
   - It starts on a free port with `pg_ctl -w -t 60`, retrying up to 5 ports, with `LC_ALL` set to the locale (the
     macOS postmaster refuses to start without it: "postmaster became multithreaded during startup").
   - Before `initdb` runs, a watcher is spawned: `/bin/sh` in its own process group, ignoring INT and HUP, running
     `cat >/dev/null; pg_ctl stop -m immediate; rm -rf <dir>`. The test process holds its stdin pipe in a static and
     never writes it, so when the process ends for any reason (exit, panic, abort, SIGKILL) the watcher stops and
     deletes the cluster. A failed `initdb` or start is cleaned up the same way.
   - The admin URL is `postgres://vci@127.0.0.1:<port>/postgres?sslmode=disable`.
3. **Otherwise, skip** with a message on stderr, or **panic under `VCI_TEST_POSTGRES=require`** (set in CI).
   `available()` follows the same rules.

Other rules:

- `initdb` refuses to run as root, which is detected (`id -u`) and skipped. CI's root container job
  (`store-stock-git`) uses a service container; `store-pg-initdb` runs the initdb path as the runner user.
- Each `PgDb` has a schema of its own, `vci_t_<pid>_<n>` (not created until a store writes), and drops it with the
  roles (`role(suffix, grants)`) and databases (`database(suffix, options)`) it made, on drop.
- `PgDb` also has `selection()` (namespace `test`), `open()`, `open_with(f)`, `open_as(url)`, `sql`, `query`, `count` and
  `schema_exists()`; free functions `cx()`, `cx_for(command, long_running)`, `selection(url, schema, ns)`,
  `with_user` and `with_database`; and introspection for its own tests (`clusters_started()`, `cluster_data_dir()`,
  `cluster_port()`, `cluster_locale()`, `bindir()`, `running_as_root()`).
- `tests/testkit.rs` checks one cluster per process, the dropped schemas and roles, and that a child test process
  that panics or is killed leaves no postmaster and no directory behind within 10 s.
- Under cargo-nextest (one process per test), set `VCI_TEST_POSTGRES_URL`; otherwise every test starts a cluster
  (about a second each on a laptop).

---

## 15. Backend: git-meta

The crate is `vci-git`. `crates/vci-git/src/store.rs` holds:

```rust
pub struct GitMetaStore { repo: Repo, readers: Mutex<Pool> }   // Pool { generation: u64, readers: Vec<Reader> }
pub struct GitMetaFactory { repo: Repo }                        // kind "git-meta"
impl AttestationStore for GitMetaStore { … }   // delegates to the unchanged AttestStore::new(&self.repo)
impl Exchange for GitMetaStore { … }
impl From<GitError> for StoreError { … }
```

`GitMetaStore::new(repo)` opens nothing until it is used. It also has `repo()`, `attest_store() -> AttestStore<'_>`
(for `vci init`'s remote set-up and the e2e helpers), and a `#[doc(hidden)] pooled_readers()` for tests.
`GitMetaFactory::new(repo)` opens a `GitMetaStore` of that repository and ignores the selection's other settings.

**Identity**:

- `kind` is `"git-meta"`.
- `location` is `".git/git-meta.sqlite (exchanged on refs/meta/main)"`, whatever `meta.namespace` is set to; in a
  linked worktree, `"<common git dir>/git-meta.sqlite, shared by every worktree of the repository (exchanged on
  refs/meta/main)"`, by the absolute path git gives (`Repo::common_git_dir`).
- `caps` is `LOCAL.with_lazy_values(true).with_hints(true).with_objects(true)` (2.9: objects kept, no columns).
- `status` is `Reader::has_store` on a pooled reader, mapped to ``Absent{advice: "run `vci fetch`"}`` or
  `Ready{None}`.
- `count` is `Reader::count`.

**Where the store is** (2.7.33). `AttestStore::store_path()` is `<common git dir>/git-meta.sqlite`, one store per
repository: `.git/git-meta.sqlite` in the main worktree (or a clone without linked worktrees), the path it always
was, and the same file for every linked worktree (`git worktree add`), which before 2.7.33 had its own
`.git/worktrees/<name>/git-meta.sqlite` while the `refs/meta/*` refs were shared. git-meta keeps its store in the git
directory of the repository it opens, so in a linked worktree `AttestStore::session()` opens git-meta on the common
git directory, under the session lock `git-meta.sqlite.vci-lock` beside the store; the exchange lock
(`git-meta.vci-exchange.lock`), the materialization markers (`vci-materialized-*`) and git-meta's history-index
checkpoint (`git-meta-index.json`) live there too. Every reader (`Reader::open`) and the batch's connection
(`db_rw`) open `store_path()`, so everything `GitMetaStore` does (reads, writes, a batch's in-process statements,
hints, fetch and push) uses the shared file, and what `vci run` stores in one worktree `vci plan` reads in every
other with nothing pushed or fetched. A linked worktree's own store left by an earlier vci is taken over by the first
command run there when the repository has no shared store yet and no connection has the old one open (under the
exchange lock and both session locks: an exclusive lock on the old file and a WAL checkpoint, then a hard link, or a
rename; `vci: note: moved this worktree's git-meta store …`); otherwise it is left as it is, unused, and a note says once that it
can be deleted (a `git-meta.sqlite.vci-unused` marker beside it). The stock `git meta` CLI run in a linked worktree
still uses that worktree's own file. `crates/vci-git/tests/store_worktrees.rs` covers it, through the trait too.

**Reads**:

- `list_units`: one pooled reader, then `candidates_reading(id, |_| false)` per id. This is the plan loop of 2.7 at
  the same cost.
- `list_all`: `Reader::all_reading(|_| false)`, the same query as `all()` without reading values.
- `read_values`: `AttestStore::read_values`, unchanged, then each entry is settled to bytes or an error (an error
  clears the bytes; empty bytes become `EMPTY_VALUE`). `AttestStore` itself leaves an empty value as empty bytes; vci
  never writes one.
- `read_units` **override**: one pooled reader, then `candidates_reading(id, |_| true)` per id, settled the same way.
  This is the targeted query; the default's full scan plus `cat-file` per call is never used. A thread-local query
  counter (`#[doc(hidden)] vci_git::meta::reader_queries()`) lets `store_trait` check that N units cost N queries.
- `read_all` override: `AttestStore::list(None)`, one pass, settled.
- `manifest`: a pooled `Reader::manifest`. `manifests`: one pooled reader for every root. `manifest_roots`:
  `Reader::manifest_roots`.

**Reader pool rules**:

- The pool hands one reader to each concurrent caller and reuses it, at the same concurrency and with the same number
  of `cat-file` processes as ManifestLoader's slots in 2.7.
- **A reader whose `has_store()` is false is never returned to the pool**, nor is one whose call failed. A reader
  opened before the database existed keeps `db = None` forever; without this rule a `vci plan --fetch` on a fresh
  clone would read nothing after the fetch.
- The pool is **emptied** after `Exchange::fetch` (including the plan's `--fetch` thread), after `push`, after every
  `prefetch` and after `orphan_manifests`' hydration. A reader caches `present` and a `cat-file` process from before
  the download. Emptying starts a new generation: a reader in use while the pool is emptied is dropped when it comes
  back, not pooled.

**Writes**:

- `put`: `NewAttestation::validate()`, then the internal `AttestStore::put_keyed(target: &Target, test_key, signer,
  storage_key, hint, bytes)`. `put_hinted` is a thin wrapper over it with an unchanged signature, so the 62 existing
  tests prove the refactor. `put` returns `NewAttestation::stored(key)`, so `issued` and `tree` come from the stored
  key; `put_hinted` still returns them from the hint it was given (for an unhinted put that kept a hinted key, `issued`
  is `None` there). Keys, targets and stored contents are identical.
- `put_manifest`: `key::check_hex("input root", root)`, empty bytes refused as `Invalid{manifest, "must not be
  empty"}`, then `AttestStore::put_manifest` (which checks UTF-8).
- `remove` (`remove_envelopes`) and `remove_manifests` are unchanged.
- `batch`: `WriteBatch::deferred(Box::new(GitBatch(AttestStore::batch()?)))` (2.8; immediate before). `finish`
  commits the batch's transaction, stamps its writes and drops the thread-local guard (section 6).

**Prefetch**:

| `Prefetch` | maps to |
|---|---|
| `Units{choose: Some}` | `hydrate_units_choosing` |
| `Units{choose: None}` | `hydrate_units` |
| `Manifests` | `hydrate_manifests` |
| `Attestations` | `hydrate_attestations` |
| `Objects{ids}` | `hydrate_objects` (2.9): the promised rows of `vci:object:<kind>:<id>` for any kind and an id in `ids`, their blobs in one `git fetch --stdin` of object ids (`FETCH_BLOB_BATCH`), as the manifests' |
| a future variant | `Hydration::default()` |

Every call then empties the reader pool.

**`orphan_manifests`**: `hydrate_manifest_referrers(roots)` gives the undecided roots (and empties the pool). Then
`AttestStore::list(None)`, skipping values still not fetched. On any other unreadable value or `ManifestRef::Unknown`
the answer is empty. Otherwise it returns the roots minus the referenced ones minus the undecided ones (section 4 on
how it differs from 2.7 for malformed envelopes).

**Objects (format 3, vci 2.9; STORE-V2 section 2.2).** An object is a string value of the `project` target under the
key `vci:object:<kind>:<id>` (`key::object_key`: the kind as its byte in decimal, the id 64 lowercase hex), so its tree
path is `project/vci/object/<kind>/<id>/__value`: four blobs and a few trees per run where format 1 filed ~800
manifest blobs. The value is `object_to_base64` of the bytes (rule 3 stands: a git-meta value is UTF-8, and the state
object holds raw hashes), decoded in `get_objects`; a format-3 record is the text frame, stored like any other
attestation value and read through the same lossy-UTF-8 path, which leaves it byte-identical. Nothing changed in the
`git-meta.sqlite` `value` column, `materialize` or fast-import. The row's `last_timestamp` is the object's `put_at`:
the time it was last put here, or fetched (the merge marks a fetched row with the merge's time).

- `put_objects`: `NewObject::validate` on each (the id comes from the bytes), then `AttestStore::put_objects` with the
  base64 text: inside a batch on its connection (`current_is`, then `set` or, for identical bytes, an `UPDATE` of the
  row's `last_timestamp` to now, so that the grace restarts), outside one through git-meta's `set` and the same
  `UPDATE`. Returns how many were not stored before, exact inside a batch too.
- `get_objects`: ids validated and made distinct in the order asked; on a pooled reader `Reader::objects`: one range
  query of the object keys (`key >= 'vci:object:' AND key < 'vci:object;'` on the `project` target, values not read)
  to find each id's kind, then one indexed lookup per object held, its value through `value_bytes` (inline, a blob
  through `cat-file`, or not fetched). A promised row, a missing blob or a text that is not base64 is **left out**
  (prefetch `Objects` first); the answer is refused as `Invalid{objects}` once the decoded sizes would pass
  `MAX_OBJECTS_ANSWER`, before that decode.
- `remove_objects` and `orphan_objects` apply the orphan rule at once, as the referrer scan `orphan_manifests` is:
  `hydrate_attestations` first (every attestation not fetched yet is fetched: a run's records are on every path target,
  so any of them could name an object; `vci prune` has prefetched them already), the pool emptied, then
  `AttestStore::referenced_objects` reads every attestation value once (`AttestStore::list(None)`) and collects the ids
  `key::record_object_refs` names (the statement's hdr and tables, the descriptor's shape; a format-1 envelope names
  none). A value still not fetched (offline), unreadable, or a record whose statement or descriptor does not parse makes
  the answer empty (nothing removed): it might name any object. Otherwise an object of kind 1, 2 or 3 that no record
  names and whose `last_timestamp` is more than `OBJECT_GRACE` ago is an orphan; `remove_objects` deletes the orphans
  among its ids (tombstones, published by the next push; `remove_project_keys`, the path `remove_manifests` takes) and
  `orphan_objects` lists them all, sorted. **State objects are never orphans here**: git-meta keeps no columns, and a
  state object's id is in no signed field, so nothing can name it; `prune_state_objects` is what removes them. Inside a
  batch the scan reads the store as committed before the batch, so a record the batch removed still counts as a
  referrer and its objects go at a later call. Both calls read every value (there is no scoped referrer scan for
  objects: a manifest's referrers are on the paths it lists, an object's can be any record), which is `vci prune`'s
  cost and not a per-run one: `vci run` does not call them on a store without columns (section 4).
- `prune_state_objects(older_than)`: the object rows of kind 4 whose `last_timestamp` is older than that, deleted
  whatever names them (values not read).
- `columns` is the default: `Columns::default()` for every entry (the hint is the key; the columns a put passes are
  ignored).
- **The merge's put-back rule applies to objects by id** (`restore_referenced_objects`, beside
  `restore_referenced_manifests`): after a fetch merged a tip that deleted an object, the deletion records of object
  keys the store held before the merge or the tip holds are candidates; the ones a local attestation names
  (`referenced_objects`; every candidate when one cannot be read; a promised row, never relied on here, is skipped)
  are put back from the tip's blob or the local commit before the merge (`project/vci/object` listed once), when the
  blob's base64 decodes to bytes whose BLAKE3 is the id, and stamped as written for the next push. A state object is
  never put back: its deletion was a `prune_state_objects` or an orphan collection. The fetch's notes say `put back N
  object(s) that attestations here reference, …`.
- **git-meta's auto-prune** (`meta:prune:max-keys`, `meta:prune:max-size`, which vci warns about) counts an object as
  one key: a few per run instead of ~800 manifests.
- **A vci before 2.9** on the same metadata lists neither objects (its listings take the `vci:attestation:` prefix;
  `count`, `list_all` and `manifest_roots` are unchanged by them) nor deletes them (it never deletes a key it does not
  parse), and reads a frame as text that is not an envelope: `Envelope::from_json` (a serde_json parse) fails without a
  panic, the `envelope` check fails, and the unit runs (STORE-V2 section 5, rule 5). Its manifest collector then keeps
  every manifest, since it cannot tell what the frame names.

**Other provided methods**:

- `warm` is `warm_in_background`.
- The hints use `vci_memo` and `vci_flags` (`AttestStore::passing_on`, `remember_passing`, `flag`, `set_flag`).
- `timing_report` gives the `put_manifest seconds: …` line, from `AttestStore::put_manifest_seconds()`.

**Exchange**:

- `exchange_point` is `"refs/meta/main"`.
- `remote_location(name)` is `remote_url(name)` passed through `select::redact_credentials`, the part of
  `select::redact` for a URL that names no store (`redact` shows a libSQL server's `https://` URL as its host alone,
  which would hide a git remote's path: `https://***@github.com/<path>`). On ordinary remote URLs that is the text
  2.7's `redact_userinfo` gave. They differ when the authority ends at `?` rather than `/`, and when the path or
  query holds an `@` (it masks up to the last `@`), and it also masks `password=`, `sslpassword=`, `sslkey=` and
  `authToken=` values in a query. `redact_userinfo` is still used for remotes the user typed, in warnings.
- `fetch` is `AttestStore::fetch`.
- `push(Merge)` is `push`, and `push(RewriteHistory)` is `push_rewriting_history`. A future `PushMode` is
  `Unsupported{git-meta, "this kind of push"}`.

**Errors**: `From<GitError>` (in store.rs) maps `Invalid{what, value, reason}` field for field. Every other variant
becomes `StoreError::Backend(Box<GitError>)`, so the display text is byte-identical and `downcast_backend::<GitError>()`
recovers, for example, `NoMetaRemote`. In `vci run` they are therefore problems of the run (exit 2), as in 2.7.

**What moved to vci-store.** These are re-exported from `vci_git::meta` (and the ones vci-git re-exported before,
from `vci_git`), so every import path still compiles: `KEY_PREFIX`, `MANIFEST_PREFIX`, `KeyHint`, `attestation_key`,
`attestation_key_hinted`, `parse_key`, `parse_key_hint`, `manifest_key`, `parse_manifest_key`, `NOT_FETCHED`,
`StoredEnvelope`, `StoredManifest`, `Hydration`, `FetchOutcome`, `PushOutcome` and `PushStatus`.

- `validate.rs` keeps its `GitError` wording: `is_hex_id` delegates to `vci_store::key::is_hex_id`, and
  `is_signer_id`, which nothing called once key parsing moved, is gone. The unit tests `target_label_parity` and
  `invalid_wording_parity` in meta.rs pin that both crates agree.
- `meta.rs` keeps `pub fn decode_manifest(&Reader, bytes)` (over `vci_store::decode_manifest`, reader errors mapped to
  `StoreError::backend`, so the text is unchanged) and a private `envelope_manifest_ref(bytes) -> Option<String>`
  (`Root(r)` is `Some(r)`, anything else `None`), so its internals and unit tests compile unchanged.
- The key unit tests moved to `crates/vci-store/tests/keys.rs`. One of them, `manifest_refs_of_envelopes`, now expects
  `ManifestRef::Inline` for a predicate without `manifestRef`.
- `PushStatus` is `#[non_exhaustive]` for other crates; meta.rs still matches it exhaustively.

**What stays in vci-git as public, concrete API**:

- `AttestStore<'a>`, with every inherent method returning `GitError`. The 62 store tests and the e2e helpers use it.
  Inherent methods take precedence over trait methods, so nothing changes for them.
- `Reader`, `BatchGuard`, `target_for` and `target_label(&Target)`.
- `SETUP_FILE`, `DEFAULT_REMOTE_NAME`, `NO_LAZY_FETCH_REMOTE`, `read_setup_url`, `ensure_remote`, `remote_names`,
  `remote_url`, `push_with_hook`, `push_rewriting_history` and `put_manifest_seconds`.
- All exchange machinery: tombstones, cover and complete markers, the exchange and session locks, `vci_blob_ref`,
  `vci_tree_listing`, fast-import, materialize, push repair and `stamp_written`.
- The file `.git/git-meta.sqlite`, its tables and `refs/meta/*` keep their names; tests and the demo-oidc job read
  them directly.

`AttestStore::remove_for_signer` has no caller. Delete it in a follow-up.

**Tests.** `crates/vci-git/tests/store_worktrees.rs` (8 tests) checks the shared store: its path with and without
linked worktrees, a put (and a trait batch) in one worktree read in another and in the main one, a fetch in one serving
a plan in another, concurrent writers in two worktrees, and an old worktree store taken over, left in use, or left
unused. `crates/vci-git/tests/store_trait.rs` (15 tests) checks the implementation against `AttestStore` on lazy
worlds with hinted, unhinted, promised and missing-blob entries: listings match, `read_values` matches, `read_units` is
targeted and equal to the default, error mapping, the pool seeing a store created later and being refreshed after a
prefetch, `orphan_manifests` against a re-implementation of 2.7's logic, the batch (one transaction since 2.8, the
same rows as its calls one by one, a failed stamp after its commit a warning, a refused write in git-meta's text),
the timing line, `put` keeping `put_hinted`'s keys, and the factory. `crates/vci-git/tests/store_objects.rs` (6 tests,
2.9) checks what the objects scenarios cannot see: the base64 value at `project/vci/object/<kind>/<id>/__value` in the
remote's tree and the older listings that never see it, a frame read back byte for byte through the lossy path and
refused by a serde_json envelope parse without an error (and `Inline` for manifest collection), promised object rows
fetched by one `Prefetch::Objects` (4 resolved, 4 blobs) and left out before it, the merge putting back the three named
objects another clone deleted (not the state object) and publishing them, the orphan scan keeping every object while
the record cannot be fetched and fetching it once online, and an idempotent put inside a batch restarting the grace.
The conformance world's `age_objects` moves `last_timestamp` in `.git/git-meta.sqlite`, so c35 to c42 run in full
(c40's columns half skips: git-meta keeps none).

---

## 16. Backend: SQLite

`vci-store-sqlite` holds `SqliteFactory` (kind `sqlite`, registered under vci-cli's cargo feature `sqlite`, on by
default; `SqliteFactory::path(sel, cx)` says which file a selection names), `SqliteStore` (`open_path(path,
SqliteOptions)`, which opens nothing until the first call; `path()`, `options()`; (2.9) `upgrade_begin()` and
`upgrade_finish() -> Finish` behind `vci store upgrade --begin` and `--finish`, below) and `SqliteOptions {
busy_timeout, sync_off, read_only, kind }` (default 30 s, false, false, `sqlite`). Its tests are `tests/sqlite.rs`
(the design's fourteen cases plus a read-only file beside a live WAL, readers racing a writer, a lock held past the
busy timeout, an unwritable directory and a copy between two files; 1,200 units of 18 KB listed and read in about 8 ms
in a release build; and (2.9) the format-3 side the conformance suite cannot see: a file vci 2.8 wrote given the
additions by the first write in a transaction committed before the write's batch, `upgrade_begin` and
`upgrade_finish` with their refusals, the objects as BLOBs and the columns on the row, the 64 MiB answer cap, foreign
object rows, each of the four referrer columns keeping its object, and an object removal applied inside a batch) and
the conformance suite, every objects scenario included (`age_objects` moves `objects.put_at` back with SQL).

**Format 3 (2.9).** `caps` is `LOCAL.with_hints(true).with_objects(true).with_columns(true)`: the store keeps the
objects in an `objects` table (`bytes BLOB`, filed under the BLAKE3 of them) and a record's listing columns on its
row, and implements the whole objects section of the trait (section 4). There is no `gone` table and no `seq` column:
nothing syncs from a SQLite file (STORE-V2 section 2.1 lists them for the stores with replicas), and the state TTL
and the orphan rule delete outright. A file has no `vci_schema` table either: its version is `PRAGMA user_version`,
and whether the additions are there is read from `sqlite_master` (the `objects` table, created in the one
transaction that adds the columns).

**Crate.** `vci-store-sqlite` depends on `vci-store`, `vci-core`, `serde_json` and `rusqlite = { version = "=0.39.0",
default-features = false, features = ["bundled"] }`.

- The version must be exactly 0.39.0 because `libsqlite3-sys` declares `links = "sqlite3"`, so the workspace can
  link only one copy, and git-meta-lib resolves to 0.39.0.
- `bundled` is enabled explicitly so `cargo test -p vci-store-sqlite` builds without git-meta-lib in the graph.

**What the command line relies on**:

- `status()` is ``Absent{advice: "the first `vci run` creates it"}`` when there is no file; the plan then warns `no
  attestations are available in the sqlite store (the first `vci run` creates it)`.
- `exchange()` is `None` (`vci fetch`: `vci: the sqlite store at <location> is local: nothing to fetch (N
  attestations stored)`).
- `prefetch` is the default; the plan's round 2 reads the set-aside candidates anyway (section 5).
- Conditions that mean the store cannot be used are `Unavailable`, `Denied`, `Incompatible`, `Timeout` or `Config`,
  never `Backend` (section 10). The backend returns no other variant.

**File.**

- The default is `<git common dir>/vci-store.sqlite` (`OpenContext::git_common_dir`). Linked worktrees share it,
  which is their only way to share a local store. It is never `.git/git-meta.sqlite`.
- `[store.sqlite] path` is relative to the git common directory. `VCI_STORE_URL=sqlite:<path>` may be absolute
  (`Selection::sqlite.path`).
- The store keeps one repository per file, so it has no namespace column.
- Docs warn against network file systems (WAL needs shared memory).

**Opening.**

- Lazy, on first use.
- A missing file reads as empty (`Absent`) and creates nothing.
- The first write creates the file and schema under `BEGIN IMMEDIATE`, which serializes concurrent creators (c21).
- Pragmas: `journal_mode=WAL`, `busy_timeout = timeout` (default 30 s; writes commit one by one, so waits are
  milliseconds), `synchronous=NORMAL` (`OFF` under `VCI_STORE_SYNC=off`, read once by the factory),
  `foreign_keys=OFF`.
- `PRAGMA application_id = 0x76636931` ('vci1') and `PRAGMA user_version = 1`, or `2` past `vci store upgrade
  --finish` (2.9). A file this vci creates is at version 1 with the format-3 additions, so that a 2.8 binary sharing
  it (a CI cache) still reads it; `status()` reports the file's version.
- The schema's state (application id, user version, tables, and since 2.9 whether `objects` is among them) is read
  in one read transaction: read as three statements, it raced a concurrent creator (c21 and the crate's test 10
  caught it). Each connection learns it once and passes it to every read and write, so a query touches only the
  tables and columns the file has: a version-1 file from before 2.9 answers no object and no columns until a write
  adds them, and a version-2 file is asked for no manifest.
- A newer `user_version` with application id 'vci1' gives `Incompatible{found, supported: 2}`.
- **An older file's first write** (2.9): a write on a version-1 file without the additions (one vci 2.8 wrote) first
  adds the columns the table lacks (`PRAGMA table_info`, then `ALTER TABLE ADD COLUMN` each; the DDL is not `IF NOT
  EXISTS` for columns) and the `objects` table with its indexes, in one `BEGIN IMMEDIATE` transaction of its own,
  committed before the write's transaction, or before the batch's, which its first write begins afterwards
  (STORE-V2 section 2.1: the DDL is never part of a batch request). `SqliteStore::upgrade_begin()` runs the same
  ahead of a rollout (`vci store upgrade --begin`; it creates a missing file with the additions, returns whether it
  added them now, and is `Denied` on a read-only handle).
- **`SqliteStore::upgrade_finish()`** (`vci store upgrade --finish`, STORE-V2 section 5 step 4): in one `BEGIN
  IMMEDIATE` transaction, make sure the additions are there, count the attestations whose value does not start with
  `v` (`hex(substr(value, 1, 1)) <> '76'`: format-1 rows, and anything that is not a frame, since a reader of them
  needs the manifests), and when there are none `DROP TABLE manifests` and set `user_version = 2`
  (`Finish::Finished`); `Finish::FormatOneRows(n)` leaves the file at version 1 with its manifests (the additions,
  if made here, are kept); `Finish::AlreadyFinished` at version 2; `Unavailable` when there is no file (nothing is
  created); `Denied` on a read-only handle. At version 2 a vci before 2.9 reports the schema too new and fails
  open; this vci reads manifests as none (`manifest`, `manifests`, `manifest_roots` empty, `orphan_manifests` every
  given root, `remove_manifests` 0) and refuses `put_manifest` with `Unsupported` (``"format-1 manifests after `vci
  store upgrade --finish`"``), while records of either format, hints, objects and columns go on as before. The CLI
  (M3) reaches both through `SqliteStore` (opened with `SqliteFactory::path`), since the trait has no upgrade
  method.
- **Files it refuses.** A file with tables but `user_version` 0, or another `application_id`, is
  `Unavailable("<path>: not a vci store: …")` and is never written: pointing the store at `.git/git-meta.sqlite` fails
  this way and leaves the file untouched. SQLite's NOTADB or CORRUPT is `Unavailable` at once, without trying the
  other opens.
- **Open fallbacks**, each probed with `SELECT count(*) FROM sqlite_master`: a plain read-write open of the path, then
  `file:<percent-encoded path>?mode=ro`, then `?immutable=1` (a read-only directory), as git-meta's Reader does.
- **Errors.** BUSY or LOCKED is `Timeout{operation: "waiting for another writer", after: busy_timeout}`; READONLY,
  PERM or AUTH is `Denied{operation: "write" | "create the schema" | "remember a hint"}`; the first write in a
  directory that cannot be written (CANTOPEN on create, or `create_dir_all` refused) is `Denied{operation: "create
  the store"}`; anything else is `Unavailable("<path>: <sqlite message>")`. A handle opened with `read_only` returns
  `Denied` before it opens anything.
- Connections live in a `Mutex<Vec<Connection>>` pool. Statements are prepared once per call and reused for each row
  of it: `prepare_cached` needs rusqlite's `cache` feature, which only git-meta-lib turns on, so this crate built on
  its own does not have it.

**Schema v1.**

```sql
CREATE TABLE attestations (
  key          TEXT    NOT NULL PRIMARY KEY,
  test_key     TEXT    NOT NULL,
  signer       TEXT    NOT NULL,
  storage_key  TEXT    NOT NULL,
  target       TEXT    NOT NULL,
  issued       INTEGER,
  tree16       TEXT,
  manifest_ref TEXT,                 -- unverified, from the payload at put time
  ref_state    INTEGER NOT NULL,     -- 0 unknown, 1 root, 2 inline (ManifestRef)
  stored_at    INTEGER NOT NULL,     -- unix seconds
  encoding     INTEGER NOT NULL DEFAULT 0,  -- 0 raw; reserved for compression
  value        BLOB    NOT NULL,     -- last column: key-only reads never touch overflow pages
  UNIQUE (test_key, signer, storage_key)
);
CREATE INDEX attestations_unit ON attestations (test_key, key, target);
CREATE INDEX attestations_all  ON attestations (target, key);
CREATE INDEX attestations_ref  ON attestations (manifest_ref) WHERE manifest_ref IS NOT NULL;
CREATE INDEX attestations_unknown_ref ON attestations (ref_state) WHERE ref_state = 0;
CREATE TABLE manifests (
  root     TEXT    NOT NULL PRIMARY KEY,
  base     TEXT,                     -- InputManifest::compact_base at put time
  put_at   INTEGER NOT NULL,
  encoding INTEGER NOT NULL DEFAULT 0,
  value    BLOB    NOT NULL
);
CREATE INDEX manifests_base ON manifests (base) WHERE base IS NOT NULL;
CREATE TABLE memo  (tree16 TEXT NOT NULL, test_key TEXT NOT NULL, key TEXT NOT NULL, at INTEGER NOT NULL,
                    PRIMARY KEY (tree16, test_key)) WITHOUT ROWID;
CREATE TABLE flags (name TEXT NOT NULL PRIMARY KEY, at INTEGER NOT NULL) WITHOUT ROWID;
```

The default `BINARY` collation is bytewise, as the contract requires.

**The format-3 additions (2.9, `sql::COLUMNS_V2` and `Sql::ddl_v2`)**, on a version-1 file from before 2.9 added
behind `value` by `ALTER TABLE` (a row that carries them is a frame of about 2 KB, which overflows no page; a
format-1 row carries `NULL`s, which cost no read):

```sql
ALTER TABLE attestations ADD COLUMN format INTEGER;        -- 3 for a frame; NULL on a format-1 row or a put without columns
ALTER TABLE attestations ADD COLUMN commit_id TEXT;
ALTER TABLE attestations ADD COLUMN platform TEXT;
ALTER TABLE attestations ADD COLUMN state TEXT;            -- `passed` / `failed`, as Columns::state is
ALTER TABLE attestations ADD COLUMN duration_ms INTEGER;
ALTER TABLE attestations ADD COLUMN expires INTEGER;
ALTER TABLE attestations ADD COLUMN hdr TEXT;              -- 64-hex object ids, for the orphan queries
ALTER TABLE attestations ADD COLUMN tables_id TEXT;
ALTER TABLE attestations ADD COLUMN shape TEXT;
ALTER TABLE attestations ADD COLUMN state_obj TEXT;
CREATE TABLE objects (id TEXT NOT NULL PRIMARY KEY, kind INTEGER NOT NULL, put_at INTEGER NOT NULL, bytes BLOB NOT NULL);
CREATE INDEX objects_kind_put     ON objects (kind, put_at);               -- the state TTL
CREATE INDEX attestations_hdr     ON attestations (hdr)       WHERE hdr       IS NOT NULL;
CREATE INDEX attestations_tables  ON attestations (tables_id) WHERE tables_id IS NOT NULL;
CREATE INDEX attestations_shape   ON attestations (shape)     WHERE shape     IS NOT NULL;
CREATE INDEX attestations_state   ON attestations (state_obj) WHERE state_obj IS NOT NULL;
```

Schema version 2 is this without the `manifests` table. The libSQL store shares `Names`, `Sql::ddl_v2`,
`Sql::add_column` and the object statements for its namespaces as it shares the version-1 SQL.

**Reads.**

- `list_units`: `SELECT key, target FROM attestations WHERE test_key = ?1 ORDER BY key`, once per id, on one
  connection inside one read transaction. It is an index-only seek; about 4,000 units take tens of milliseconds.
  Entries are built with `StoredEnvelope::from_key`.
- `list_all`: `ORDER BY target, key`.
- `read_values`: `SELECT value, encoding FROM attestations WHERE key = ?1` per entry inside one transaction. A
  missing key gets `GONE` and an unknown encoding is unreadable. `NOT_FETCHED` never occurs.
- `read_units`: the default (list, then read), which is already a targeted read here. `list_units` answers a
  duplicate id with a copy of its first answer (one index seek per distinct unit).
- `manifest`: `SELECT value FROM manifests WHERE root = ?1`. `manifest_roots`: `ORDER BY root`. `count`: a key-only
  scan counting the keys `parse_key` accepts, not `count(*)`, so a foreign row (c23) is not counted.
- A missing file reads as empty everywhere; `orphan_manifests` on it returns every given root, sorted and
  deduplicated.
- `orphan_manifests`: empty if any row has `ref_state = 0`; otherwise the given roots with no row where
  `manifest_ref = root`.
- (2.9) `get_objects`: every id validated, then in one read transaction `SELECT kind, length(bytes) FROM objects
  WHERE id = ?1` per distinct id (the sizes come from the record header, so no blob is read) summed against
  `MAX_OBJECTS_ANSWER`, refused as `Invalid{what: "objects"}` past it before a byte is read, then `SELECT kind,
  bytes` per id, in the order asked; a missing id, a row whose `kind` names no kind, and a row whose `bytes` is not a
  BLOB are left out. Timing line `store: sqlite: read N object(s)`. Nothing is read on a file without the additions.
- (2.9) `orphan_objects`: `SELECT id FROM objects WHERE put_at < now - 3600 AND NOT EXISTS (SELECT 1 FROM
  attestations WHERE hdr = objects.id OR tables_id = objects.id OR shape = objects.id OR state_obj = objects.id)
  ORDER BY id` (the four partial indexes), ids that are not object ids (a foreign row) left out; no value read.
- (2.9) `columns`: `SELECT format, commit_id, platform, state, duration_ms, expires, hdr, tables_id, shape,
  state_obj FROM attestations WHERE key = ?1` per entry in one read transaction; a missing key, and a column that is
  `NULL` or of another type, gives `None`.

**Writes.** Each write is one `BEGIN IMMEDIATE` transaction.

- `put` validates, then computes `ref = envelope_manifest_ref(bytes)`. With a hint:

  ```sql
  INSERT INTO attestations (key, test_key, signer, storage_key, target, issued, tree16, manifest_ref, ref_state, stored_at, value)
  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
  ON CONFLICT (test_key, signer, storage_key) DO UPDATE SET
    key = excluded.key, target = excluded.target, issued = excluded.issued, tree16 = excluded.tree16,
    manifest_ref = excluded.manifest_ref, ref_state = excluded.ref_state, stored_at = excluded.stored_at,
    encoding = 0, value = excluded.value
  WHERE attestations.key IS NOT excluded.key OR attestations.value IS NOT excluded.value
     OR attestations.encoding <> 0
  RETURNING key;
  ```

  - The UNIQUE constraint enforces one record per slot, so git-meta's list-then-delete step disappears.
  - A conflict on the primary key alone implies the same slot, because the key encodes the slot.
  - Without a hint, the update keeps `key`, `issued` and `tree16`. When nothing changed (no row returned), the stored
    key is read back.
  - `encoding <> 0` lets a put of identical bytes repair a row this vci cannot read; otherwise identical bytes under
    the same key change nothing, `stored_at` included.
  - (2.9) The ten format-3 columns are in the row list (`?12` to `?21`; `?10` to `?19` without a hint), from the
    put's `Columns` or `NULL` each without them, and in the `DO UPDATE SET`; the `WHERE` gains `OR attestations.c IS
    NOT excluded.c` for each, so the same bytes put with other columns, or without them, replace the columns (and
    `stored_at`), as c40 requires.
- `put_manifest`: compares inside SQL (`SELECT value = ?2 AND encoding = 0`), then only refreshes `put_at` when equal
  or upserts the value otherwise, in the same transaction, and returns whether the value changed. `base` comes from
  `compact_base`, kept only when it is a hex id.
- `remove`: `DELETE FROM attestations WHERE key = ?1` per entry, in one transaction, using the changed-row count. It
  returns the entries that existed, with their given bytes. There are no tombstones: nothing propagates.
- Writes that cannot change anything never create the file: `remove` and `remove_manifests` on a missing file return
  nothing, and `remember_passing` and `set_flag` do nothing there. A file without a schema gets one on its first
  write, a hint included.
- `remove_manifests`: validate all roots, then in one `BEGIN IMMEDIATE` transaction delete only roots that no
  attestation references and no manifest uses as its base. SQLite has one writer, so this check is atomic and needs
  no grace period.
- (2.9) `put_objects`: every object validated (`NewObject::validate`, which gives the id), then per object `UPDATE
  objects SET put_at = ?2 WHERE id = ?1` and, when that changed no row, `INSERT INTO objects (id, kind, put_at,
  bytes) VALUES (?1, ?2, ?3, ?4)`; the count of inserts is returned (exact, in a batch too). An empty list writes
  nothing and creates no file.
- (2.9) `remove_objects`: every id validated, then per distinct id `DELETE FROM objects WHERE id = ?1 AND put_at <
  now - 3600 AND NOT EXISTS (… the four columns …)`: the orphan rule is inside the statement, and SQLite has one
  writer, so nothing can come to reference an object between the check and the delete. The sum of the changed-row
  counts is returned. Inside a batch it is applied at once in the batch's transaction (the batch's own objects were
  put at `now`, within their grace). A missing file removes nothing and is not created.
- (2.9) `prune_state_objects(older_than)`: `DELETE FROM objects WHERE kind = 4 AND put_at < now - older_than` on
  the `(kind, put_at)` index, referenced or not; no `gone` row, since nothing syncs from the file. A missing file
  removes nothing and is not created.

**Batch.** `WriteBatch::deferred` (2.8; immediate before): it pins one pooled connection to the thread (a
thread-local keyed by the handle), and its writes are one `BEGIN IMMEDIATE` transaction on it, with a savepoint per
write, committed by `finish` (section 6). `vci run` of 1,200 Go units on a heavily loaded machine wrote its 2,400
records in 4.8 s with a commit each, and in 0.9 s as one transaction. (2.9) Object puts and removals are writes of
the batch like any other, in the order the caller makes them, so the order of section 6 (objects before records)
is the caller's order inside one transaction, and no other connection sees a record before its objects; the
additions' DDL on an older file is committed before the batch's transaction begins (its first write).

**Other methods.**

- `prefetch` is the default (nothing to do).
- `warm` reads the file through once on a thread, into the page cache.
- Hints use the `memo` and `flags` tables; `remember_passing` upserts by `(tree16, test_key)` and deletes memo rows
  older than 7 days. Timestamps are unix seconds.
- `synchronous` is `OFF` only under `VCI_STORE_SYNC=off`, read once at open. Unlike git-meta's store (2.7.27), it does
  not turn syncing off when `CI` is set.
- `exchange` is `None`.
- `caps` is `LOCAL.with_hints(true).with_objects(true).with_columns(true)` (2.9).
- On drop of the last connection, the store runs `PRAGMA wal_checkpoint(TRUNCATE)` (best effort, 100 ms busy wait),
  so a CI cache of the file captures one consistent file without `-wal` and `-shm`. `store::close_all()` drops the
  store at the end of every command. (macOS's `/usr/bin/sqlite3` keeps the WAL files after reading such a file:
  tests that look for them must not use it.)
- Timing lines (section 12): `store: sqlite: list N unit(s)`, `store: sqlite: read N value(s)`, `store: sqlite: read
  N object(s)`, `store: sqlite: write N record(s)` per finished batch, and `timing_report()` with the handle's total
  writes.

**Uses.** Local development loops, single-runner CI with a cache, the reference implementation for new backends
(about 1,500 lines with its schema, reads and writes; no special cases), and a possible later outbox for shared
stores.

---

## 17. Backend: PostgreSQL

`vci-store-postgres` holds `PostgresFactory` (kind `postgres`, registered under vci-cli's cargo feature `postgres`, on
by default), `PgStore` (`open(&Selection, &OpenContext)`, which does no I/O; `Clone`, sharing one handle;
`statements()`, every statement sent including `BEGIN` and `COMMIT`; `schema()`; `namespace()`; doc-hidden
`__sleep_for_test` and `__connection_for_test` for its tests), `PgError` (the payload of `StoreError::Backend` for
unexpected errors, with `message()` and `code()`), (2.9) `Finish` (what `PgStore::upgrade_finish` found) and the
testkit (section 14). The modules are `conn` (URL, TLS, session settings, pool, circuit breaker, error
classification and scrubbing), `schema`, `cache`, `read`, `write`, `batch` and (2.9) `objects` (the objects, the
listing columns, the `seq` counter and the `gone` rows). Its tests are `tests/pg.rs` (an unreachable server failing
fast with no secret shown; a server that never answers given up on in time; no piece of a password holding `@`, `/`
or `?` in `location()`, `Debug` or an error; URL handling; a first host that never answers not blocking a working
second one; round trips and slot replacement; bytewise order, through an ICU linguistic collation when libc's is
bytewise; concurrent first writers creating the schema once; absent, not initialized and incompatible schemas; a
statement timeout latching the breaker; the plan's statement budget; reads after a prefetch seeing the handle's
writes; deferred batches; `remove_manifests` keeping referenced, base and recent roots; `orphan_manifests` with an
unknown reference; namespace isolation; a read-only role; `application_name`; and (2.9) the format-3 side the
conformance suite cannot see: a schema vci 2.8 made reading as a store without columns or objects until a write of
this vci adds the additions in a request of its own, a role that cannot alter it told so, and a handle that saw
the old schema using the additions once there; `seq` handed out in commit order with each batch one block, its
objects then its attestations then its `gone` rows, two concurrent batches never interleaving, and later writes and
removals numbering after; a batch writing its objects first and applying its queued object removals last, in the
same transaction as the record removal that orphans them, `prune_state_objects` applied at once; `upgrade_finish`
refused with the count of rows that are not format-3 records in any namespace, then dropping `manifests` and
setting version 2, which the handle and a fresh one read and after which a manifest cannot be stored; an objects
answer past `MAX_OBJECTS_ANSWER` refused on its first row; `columns` and each object read and put costing one
statement, objects per namespace; and the columns following the last put in and outside a batch, a value no
column can hold reading as none), unit tests in the modules and the conformance suite, every objects scenario
included (42 passed). Two mutation checks showed the tests catch real faults: dropping `COLLATE "C"` fails test 4,
and not caching prefetched values fails test 8.

**Crate.** `vci-store-postgres` depends on `vci-store`, `vci-core`, `serde_json`, and these exact pins (each published
at least two weeks before 25 October 2026; one `rustls` and one `tokio-postgres` resolve, and `cargo tree -i
aws-lc-rs` is empty):

- `postgres = "=0.19.14"`, the sync crate. Each `Client` runs a private current-thread tokio runtime; vci's own code
  stays synchronous;
- `tokio-postgres-rustls = "=0.13.0"` and `rustls = "=0.23.45"` with `default-features = false, features = ["ring",
  "std", "tls12"]`, so static musl builds need no C toolchain beyond what `ring` needs;
- `webpki-roots = "=1.0.9"` for trust roots.

The CLI enables it with feature `postgres`, which is on by default and in the release binaries. A build without it
registers `MissingBackend`. It costs the static x86_64 musl binary about 2.8 MiB: 18,356,448 bytes with the default
features against 15,401,440 with `--no-default-features --features sqlite` (15,179,488 with neither backend);
compressed with `gzip -9`, 7.9 MB against 6.6 MB. (Measured with `cargo zigbuild --release --locked --target
x86_64-unknown-linux-musl`, Rust 1.95.0 and zig 0.16.0 on macOS, not with the release workflow's `musl-gcc`, so the
absolute sizes may differ there.)

**What the command line relies on**:

- `caps()` is `LOCAL.with_shared_writes(true).with_hints(true)` and (2.9) `.with_objects(true).with_columns(true)`,
  so `vci ci` without `--push` signs only (section 7), `exchange()` is `None` (`vci fetch`: `vci: the postgres store
  at <location> is shared: nothing to fetch (N attestations stored)`), and the store keeps a run's objects and a
  record's listing columns.
- (2.9) `vci store upgrade --begin` is `PgStore::upgrade_begin` and `--finish` is `PgStore::upgrade_finish ->
  Finish` (below, "Objects, columns, `seq` and `gone`"); they are methods of `PgStore`, not of the trait.
- `open` does no I/O: a bad setting is `Config` at once, and an unreachable server fails at the first call, bounded
  by the connect timeout, as `Unavailable` or `Timeout`. A read-only role's write is `Denied`, a missing schema on
  write `NotInitialized`, a newer schema `Incompatible`. None of these may be `Backend`, or `vci run` exits 2
  (section 10).
- `batch()` is deferred; `vci run` reports its units only once it finishes (section 6).
- The plan calls `prefetch(Units{choose: Some})` in round 1 and, in round 2, `prefetch(Units{choose: None})` for the
  units with set-aside candidates, then `read_values` of those candidates, then `Manifests` for the roots found not
  fetched; the per-handle cache and the statement budget below must cover that.
- `OpenContext::long_running` is true for `vci prune`, and means a statement timeout of at least 600 s and a manifest
  grace of 0 (no trait change; this settled section 21's question).

### Connection handling

- **Source of the URL.** It comes from `VCI_STORE_URL`, else `[store] url` without a password (`Selection::url`, a
  `Secret`); the messages about it name the one it came from (`select::name_url_source`).
- **The password** is the connection string's, else what `[store] token_command` prints (section 9), fetched before
  the first connection (outside the connect deadline) and set on each host's attempt (`Config::password`); its value
  is scrubbed from every message (`Conn::error_text`). The connection string's password wins: the command is then
  never run. `VCI_STORE_TOKEN` is not PostgreSQL's (ignored with a warning), but it still keeps the command from
  running.
- **What vci strips before parsing.** vci removes `sslrootcert`, which it handles itself, and maps `sslmode`, before
  handing the rest to `postgres::Config::from_str`. In a URL the query starts where the client library starts it, at
  the first `?` after the first `@`, so a `?` in a password does not hide `sslmode`. In a libpq `key=value` string
  only unquoted `sslrootcert=` and `sslmode=` tokens are rewritten; a quoted `sslrootcert` reaches the client library
  and is a `Config` error. A parse error becomes `Config` **without the string**, not even redacted (libpq quoting
  such as `password='a b'` could defeat `select::redact`): only the scrubbed client-library message is shown, and not
  even that when it quotes text from the string (an unknown option's name, an unexpected character), which may be a
  piece of a password the library split differently.
- **TLS.**
  - Without an `sslmode` in the URL, vci uses `require`. For hosts `localhost`, `127.0.0.1`, `::1` and unix sockets
    it uses `prefer`. `verify-ca` and `verify-full` map to `require`, `allow` to `prefer`.
  - With TLS, certificates are always verified (rustls with the `ring` provider, the webpki roots, plus `sslrootcert`
    when given). So `prefer` against a TLS server whose certificate cannot be verified fails the connection instead of
    falling back to plain text as libpq's `prefer` would: a local server with a self-signed certificate needs
    `sslrootcert` or `sslmode=disable`.
  - The TLS configuration is built at the first connection, so `open` reads no file; a bad `sslrootcert` is a
    `Config` error on the first call, cached for every later one.
- **Session settings.**
  - `connect_timeout` from the selection, unless the URL sets one. The client library applies it to the TCP connect
    only, so vci connects on a thread of its own and gives up when the whole connection (TLS request, startup and
    authentication included) has taken too long: `Timeout{operation: "connecting"}`, latched. A thread given up on
    ends with its socket and drops a connection that arrives too late.
  - **Several hosts** (`postgres://u:p@h1:1,h2:5432/db`). The deadline is the connect timeout for each host named.
    vci tries the hosts one at a time, in order, each with every other setting of the URL and on a thread of its own,
    and gives each the time left divided by the hosts left (never less than 1 s, or the connect timeout if that is
    shorter). A first host that accepts the TCP connection and never answers is therefore given up on after its
    share, and the next is still tried; the last host's error is the result. With `load_balance_hosts=random` the
    client library shuffles the hosts itself and tries them within one attempt bounded by the whole deadline, so
    there a host that hangs can use up the time of the others.
  - TCP keepalives on (idle 10 s), and `tcp_user_timeout` 30 s unless the URL sets one.
  - `application_name = 'vci <version> <command>'`.
  - `options = "-c statement_timeout=<timeout> -c lock_timeout=10s -c idle_in_transaction_session_timeout=60s"`,
    appended to any options the URL gives. For `long_running` commands the statement timeout is 600 s.
- **Encoding.** Values are `bytea`, so the server encoding does not matter.
- **Pool.** A `Mutex<Vec<Client>>` plus a `Condvar`, with at most `pool` clients (default 8) and checkout bounded by
  the connect timeout. A client returned after an error is dropped if `is_closed()`.
- **Circuit breaker.** Per handle, not a process-wide static (tests in one process must stay independent; the CLI
  memoizes one handle per repository, so it acts per process there). The first failure to reach the server is latched
  in a `OnceLock<String>`: a connection failure, an authentication error, a missing database, SQLSTATE classes 08 and
  57P, 53300, a statement timeout (57014) and a lock timeout (55P03). Every later call then returns `Unavailable` with
  "… (failed earlier in this process; not retried)" at once. Not latched: a pool checkout that waited too long
  (`Timeout{operation: "a connection from the pool"}`), 40001 and 40P01 after their retries, 53100 and 53200
  (`Unavailable`), `Denied`, `Config` and `Backend`.
- **Retries.** A lost connection once, on a new connection; serialization failure (40001) and deadlock (40P01) up to
  twice; a unique violation (23505) up to three times for puts and batch flushes, because concurrent first inserts of
  one key can collide on the primary key `(ns, key)`, which is not the upsert's arbiter.
- **Errors.** No privilege is `Denied` (`operation` "read" on a read, "write" on a write); a missing schema on a write
  by a role that cannot create it is `NotInitialized`; a newer schema `Incompatible`; anything unexpected
  `Backend(PgError)`.
- **Redaction.** Every error message passes through `Secret::scrub`. Nothing the client library parsed from a URL
  with a userinfo section is ever printed: it ends a password at the first `@`, so for `postgres://u:pa@ss@host/db`
  its host is `ss@host`, a piece of the password. `location()` (and `Debug`, and "cannot connect to …") is then
  the URL as written, passed through `select::redact` (userinfo masked up to the last `@`) and without its query:
  `postgres://***@host[:port]/db schema <s> namespace <ns>`. A URL without userinfo, and a libpq `key=value` string
  (whose quoting the client library parses exactly), are described from the parsed configuration:
  `postgres://[***@]host:port/db …`, the port showing even when the string left it out.
- **Namespace.** Every row carries `ns`. Its value is `VCI_STORE_NAMESPACE`, else `[store.postgres] namespace`, else
  `OpenContext::repo_id()`, the smallest root commit, computed lazily. Forks and mirrors share it, and unrelated
  repositories never do. Without a namespace, `vci prune` in one repository would delete another repository's rows,
  because none of their trees are live in the first. In a shallow clone with no root commit there is no repository
  id: the store then requires an explicit namespace, and the plan fails open with a message naming
  `VCI_STORE_NAMESPACE`. As built, `Repo::repo_id()` does not fail in a shallow clone (it returns the commit where the
  clone was cut, which differs by depth), so the backend refuses the default namespace itself whenever
  `<git common dir>/shallow` exists.
- **Schema name.** The schema name is validated as `[a-z_][a-z0-9_]{0,62}` and always quoted. Every value is a bound
  parameter; `search_path` is never relied on. One schema per server deployment; v1 has no row-level security per
  namespace.

### Schema v1 (in schema `vci` by default)

```sql
CREATE SCHEMA IF NOT EXISTS vci;
CREATE TABLE vci.schema_version (
  id          boolean     PRIMARY KEY DEFAULT true CHECK (id),
  version     integer     NOT NULL,
  vci_version text        NOT NULL,
  migrated_at timestamptz NOT NULL DEFAULT now(),
  migrated_by text        NOT NULL DEFAULT session_user
);
CREATE TABLE vci.attestations (
  ns           text        NOT NULL,
  key          text        COLLATE "C" NOT NULL,   -- bytewise order: required by the contract
  test_key     text        COLLATE "C" NOT NULL,
  signer       text        COLLATE "C" NOT NULL,
  storage_key  text        COLLATE "C" NOT NULL,
  target       text        COLLATE "C" NOT NULL,
  issued       bigint,
  tree16       text,
  manifest_ref text        COLLATE "C",            -- unverified, from the payload at put time
  ref_state    smallint    NOT NULL,               -- 0 unknown, 1 root, 2 inline
  encoding     smallint    NOT NULL DEFAULT 0,     -- 0 raw; reserved for zstd
  value        bytea       NOT NULL,               -- TOAST-compressed
  stored_at    timestamptz NOT NULL DEFAULT now(),
  stored_by    text        NOT NULL DEFAULT session_user,
  PRIMARY KEY (ns, key),
  UNIQUE (ns, test_key, signer, storage_key)
);
CREATE INDEX attestations_unit ON vci.attestations (ns, test_key, key) INCLUDE (target);
CREATE INDEX attestations_all  ON vci.attestations (ns, target, key);
CREATE INDEX attestations_ref  ON vci.attestations (ns, manifest_ref) WHERE manifest_ref IS NOT NULL;
CREATE INDEX attestations_unknown_ref ON vci.attestations (ns) WHERE ref_state = 0;
CREATE TABLE vci.manifests (
  ns       text        NOT NULL,
  root     text        COLLATE "C" NOT NULL,
  base     text        COLLATE "C",                -- compact_base at put time
  encoding smallint    NOT NULL DEFAULT 0,
  value    bytea       NOT NULL,
  put_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ns, root)
);
CREATE INDEX manifests_base ON vci.manifests (ns, base) WHERE base IS NOT NULL;
CREATE TABLE vci.memo  (ns text NOT NULL, tree16 text NOT NULL, test_key text NOT NULL,
                        key text COLLATE "C" NOT NULL, at timestamptz NOT NULL DEFAULT now(),
                        PRIMARY KEY (ns, tree16, test_key));
CREATE TABLE vci.flags (ns text NOT NULL, name text NOT NULL, at timestamptz NOT NULL DEFAULT now(),
                        PRIMARY KEY (ns, name));
```

There are deliberately **no foreign keys**. They would be stricter than git-meta (an attestation whose manifest is
missing would be refused) and would add a retry path. Ordering, grace and NOT EXISTS checks give the same safety.

**The format-3 additions (2.9, STORE-V2 section 2.1)**, in the same DDL text after the tables above, every statement
`IF NOT EXISTS`, so that a new schema has them from its first write and a schema vci 2.8 made gets them from this
vci's first write on it:

```sql
ALTER TABLE vci.attestations
  ADD COLUMN IF NOT EXISTS format smallint,          -- NULL or 1: an envelope JSON; 3: a frame
  ADD COLUMN IF NOT EXISTS commit_id text, ADD COLUMN IF NOT EXISTS platform text,
  ADD COLUMN IF NOT EXISTS state text, ADD COLUMN IF NOT EXISTS duration_ms bigint,
  ADD COLUMN IF NOT EXISTS expires bigint,
  ADD COLUMN IF NOT EXISTS hdr text COLLATE "C", ADD COLUMN IF NOT EXISTS tables_id text COLLATE "C",
  ADD COLUMN IF NOT EXISTS shape text COLLATE "C", ADD COLUMN IF NOT EXISTS state_obj text COLLATE "C",
  ADD COLUMN IF NOT EXISTS seq bigint;                -- the namespace's write counter, commit order
CREATE INDEX attestations_hdr    ON vci.attestations (ns, hdr)       WHERE hdr       IS NOT NULL;
CREATE INDEX attestations_tables ON vci.attestations (ns, tables_id) WHERE tables_id IS NOT NULL;
CREATE INDEX attestations_shape  ON vci.attestations (ns, shape)     WHERE shape     IS NOT NULL;
CREATE INDEX attestations_state  ON vci.attestations (ns, state_obj) WHERE state_obj IS NOT NULL;
CREATE INDEX attestations_seq    ON vci.attestations (ns, seq);
CREATE TABLE vci.namespaces (ns text PRIMARY KEY, seq bigint NOT NULL DEFAULT 0);   -- the counter row
CREATE TABLE vci.gone (ns text NOT NULL, seq bigint, key text COLLATE "C", object text COLLATE "C",
                       at timestamptz NOT NULL DEFAULT now());                        -- a deletion, for replicas
CREATE INDEX gone_seq ON vci.gone (ns, seq);
CREATE TABLE vci.objects (ns text NOT NULL, id text COLLATE "C" NOT NULL, kind smallint NOT NULL,
                          put_at timestamptz NOT NULL DEFAULT now(), seq bigint, bytes bytea NOT NULL,
                          PRIMARY KEY (ns, id));
CREATE INDEX objects_seq      ON vci.objects (ns, seq);
CREATE INDEX objects_kind_put ON vci.objects (ns, kind, put_at);                       -- the state TTL
```

Objects are per namespace (`vci prune` and the orphan rule are per namespace, as every row is), so one object two
repositories share is stored twice. `gone` has no primary key: a deferred batch inserts its rows with `seq` NULL and
numbers them before `COMMIT` (below). The counter lives in `namespaces` (the design's `vci_schema` row per
namespace); `schema_version` stays one row for the schema, and whether the additions are there is read with the
version in one statement, `SELECT version, to_regclass('"<s>".objects') IS NOT NULL FROM "<s>".schema_version`
(the DDL is one transaction, so the `objects` table stands for all of it). A handle remembers both; one that found
the additions missing asks again at its next check, since any writer may add them.

**Migrations.**

- The first write creates or upgrades the schema in one transaction, under `SELECT
  pg_advisory_xact_lock(hashtext('vci-store:' || <schema>))`. Concurrent `CREATE … IF NOT EXISTS` otherwise races on
  `pg_type`.
- (2.9) A schema that lacks the format-3 additions gets them from the first write of this vci (`put`, `remove`, the
  object writes, a batch's `finish`; not `put_manifest` or `remove_manifests`, which touch nothing new) **in a
  request of its own before the write**, the same DDL transaction under the same lock, so a batch's transaction never
  carries DDL (STORE-V2 section 2.1: a 2-4 MB batch already uses a third of its deadline). `PgStore::upgrade_begin`
  (`vci store upgrade --begin`) runs it ahead of a rollout. Until then the schema reads as a store without columns or
  objects: `columns` answers none (one statement, the check), `get_objects` and `orphan_objects` answer empty (the
  table is missing: 42P01 reads as absent). A role that may write the rows but not alter the tables gets
  `NotInitialized{advice: "schema <s> lacks the format-3 tables (vci 2.9): the first vci run with a role allowed to
  alter it adds them"}` from every such write, removals included (a removal needs the `gone` table), so nothing is
  half done. A `GRANT … ON ALL TABLES IN SCHEMA` given before the upgrade does not cover the new tables: the role
  recipe is run again after it (below, "Roles").
- (2.9) The version stays **1** while a format-1 row can exist, so a 2.8 vci keeps reading the rows it parses and
  writing rows with NULL in the new columns. `PgStore::upgrade_finish` (`vci store upgrade --finish`) ends the
  window: under the advisory lock it counts the rows of the schema, **in every namespace**, whose value does not
  start with `v` (`substring(value from 1 for 1) <> '\x76'`: format-1 rows, and anything that is not a frame; never
  the `format` column, which a 2.8 writer's upsert leaves as it was beside the format-1 value it writes into a
  frame's slot, and which a frame put without columns, a copy out of git-meta, lacks), and with any returns
  `Finish::FormatOneRows(n)` and changes nothing; with none it drops `manifests` and sets
  `schema_version.version = 2` (`vci_version`, `migrated_at` and `migrated_by` updated), which this vci reads
  (`SUPPORTED` is 2; a new schema is created at 1) and a 2.8 vci refuses as newer than it. Idempotent: at version 2
  already it answers `Finish::Already` and changes nothing (`vci store upgrade --finish` then says so, as on
  SQLite). After it a manifest read answers none, `remove_manifests` 0, and `put_manifest` `NotInitialized` (a batch holding one fails
  the same way): not undone.
- **Reads never run DDL.** A missing relation (SQLSTATE 42P01 or 3F000) reads as an empty store, `Absent{advice:
  "the first vci run with a role allowed to create schema <s> creates it"}`, so a SELECT-only role works.
- A `schema_version.version` above the supported one gives `Incompatible`, and the plan fails open.
- A write that cannot create the schema (42501) gives `NotInitialized`. A write refused by privileges gives `Denied`.
- A `schema_version` table without its row counts as absent: a migration has not committed yet.
- Hints never create the schema: `remember_passing` and `set_flag` do nothing while it is absent.

### Reads and the per-handle cache

The cache lives in memory and is never persisted. It holds listings by `test_key`, attestation values by key, and
manifests by root, including negative entries.

- **Only `prefetch` and `read_values`' manifest read-ahead fill it.** `list_units` and `manifest` misses are not
  cached.
- **Writes through the handle keep it current.** A put updates its unit's listing and value only when that listing
  is cached. A remove drops the entry. A `put_manifest` replaces a root only when it was cached (an absent answer
  too), and `remove_manifests` marks removed roots absent.
- **Values move out on read.** An attestation value leaves the cache on its first read, because the caller keeps it.
  Listings and manifests stay: bases are shared and re-read.
- **Size cap.** The cache is capped at 256 MiB. Above that, nothing more is cached and reads go to the server.

Each read is served from the cache when it can be, and otherwise:

| method | statement on a cache miss |
|---|---|
| `list_units` | `SELECT test_key, key, target FROM vci.attestations WHERE ns=$1 AND test_key = ANY($2) ORDER BY test_key, key`, regrouped into input order (one round trip, index-only) |
| `read_values` | `SELECT key, value, encoding FROM … WHERE ns=$1 AND key = ANY($2)`, in chunks of 5,000 keys; a key not returned gets `GONE` |
| `manifest` | a single-row query |
| `manifests` | `root = ANY($2)` |
| `columns` (2.9) | `SELECT key, format, commit_id, platform, state, duration_ms, expires, hdr, tables_id, shape, state_obj FROM … WHERE ns=$1 AND key = ANY($2)`, in chunks of 5,000 keys, never cached; none for a key not returned, a NULL column, or a value no column can hold (a negative `format` or `duration_ms`) |
| `get_objects` (2.9) | `SELECT id, kind, bytes, sum(octet_length(bytes)) OVER () FROM vci.objects WHERE ns=$1 AND id = ANY($2)`, distinct ids in chunks of 5,000, the answer put back in the order asked; the window sum rides on every row, so an answer past `MAX_OBJECTS_ANSWER` is refused on its first row with the rest read off the connection and dropped; a `kind` no kind has is a foreign row, left out; never cached (`Prefetch::Objects` does nothing) |

The rest go to the server directly:

- `list_all`: `ORDER BY target, key`.
- `read_all`: streamed with `query_raw`.
- `manifest_roots`: `ORDER BY root`.
- `count`: reads every key of the namespace and counts those `parse_key` accepts, not `count(*)`, so foreign keys
  (c23) are not counted.
- `read_units` is overridden: fully cached units are answered from the cache, which keeps their values (`vci run`
  reads its units twice, for the last durations and then for supersession, so supersession costs no statement after
  run's prefetch); misses take one statement with values (`test_key = ANY`).
- `read_values`, for the values it had to read from the server, reads ahead in one more statement the manifests and
  bases they reference: the plan reads the newest candidates beyond `choose`, whose manifests `prefetch` did not
  cover, and each verifying thread would otherwise issue single-row manifest statements.
- `orphan_manifests`: one statement, answering empty if `EXISTS (… ref_state = 0)`, otherwise `SELECT r FROM
  unnest($2::text[]) r WHERE NOT EXISTS (SELECT 1 FROM vci.attestations a WHERE a.ns=$1 AND a.manifest_ref=r) ORDER
  BY r COLLATE "C"`.
- `orphan_objects` (2.9): one statement, the orphan rule over the table, `SELECT o.id FROM vci.objects o WHERE o.ns=$1
  AND o.put_at < now() - make_interval(secs => <OBJECT_GRACE>) AND NOT EXISTS (SELECT 1 FROM vci.attestations x WHERE
  x.ns=$1 AND (x.hdr = o.id OR x.tables_id = o.id OR x.shape = o.id OR x.state_obj = o.id)) ORDER BY o.id` (the four
  partial indexes, one BitmapOr); no value is read.

**`prefetch(Units{ids, choose})`** takes three round trips:

1. The listing query for every id.
2. `choose` runs locally, then the chosen values are read: `key = ANY`.
3. Their manifests and those manifests' bases, in one statement: `WHERE ns=$1 AND (root = ANY($refs) OR root IN
   (SELECT base FROM vci.manifests WHERE ns=$1 AND root = ANY($refs)))`, where `$refs` comes from the chosen rows'
   `manifest_ref` column.

`prefetch(Manifests)` reads roots and bases in one statement. `prefetch(Attestations)` does nothing. Prefetch returns
`Hydration::default()`: nothing was ever "not fetched". Every prefetch of units lists them from the server again,
even when their listings are cached: that is where other writers' changes are picked up, as the trait promises (a
cached value whose key is no longer listed is dropped). It reads only values and stored manifests not cached (a key
names one attestation, a root one manifest; a root cached as absent is asked for again), so round 2 costs three
statements (listing, values, manifests), and a second prefetch of the same units in `vci ci`'s run costs one
listing statement.

**The plan's round-trip budget**:

| step | round trips |
|---|---|
| connect (warmed in the background) | 1 |
| status | 1 |
| flags (every flag of the namespace, cached) | 1 |
| memo (base and head trees) | 2 |
| round 1 prefetch | 3 |
| round 2 (the set-aside units' listings again, their values and manifests) | 3 |
| remember_passing (plus the 7-day memo prune, once per handle) | 1-2 |

That is **about a dozen in total, independent of the number of units**. The 4,000 listings, the batch read and the
2,000 `manifest()` calls are cache hits. Gate: at most 15 statements for 1,200 units (`PgStore::statements()`);
measured: 14 for a plan-shaped run of 1,200 units (13 before round 2 listed again), and 0 more for 1,200 manifest
reads from 8 threads.

**Bytes per plan** (DECISIONS item 10), measured with a byte-counting TCP proxy and `pg_stat_statements` on a
synthetic world of 600 Go units attested at three commits (1,800 attestations of about 3,100 bytes, 5.5 MB; 1,801
manifests of about 490 bytes), one connection, debug build, two runs with identical bytes:

| plan | client to server | server to client | statements | rows |
|---|---|---|---|---|
| unchanged (all 600 skip) | 510,857 B | 5,380,920 B (5.13 MiB, about 9.0 KB a unit) | 9 | 4,803 |
| every unit edited (all run) | 741,399 B | 11,916,040 B (11.36 MiB, about 19.9 KB a unit) | 10 | 6,604 |
| reverted to the oldest (all skip in round 2) | 897,879 B | 11,916,148 B | 12 | 7,204 |

The unchanged plan reads the 1,800 listing rows, 1,200 values (the 600 `choose` picked, then the second-newest 600)
and 1,202 manifests. When every unit runs, 3,000 value rows are sent for 1,800 distinct values: round 2's
`prefetch(Units{choose: None})` fetches all 1,800 again because `read_values` moved the first 1,200 out of the cache
(about 3.8 MB, a third of the bytes; section 21). The synthetic manifests are tiny; on a real repository input
manifests, often megabytes, dominate. Not measured on vex.

### Writes

**`put`** is one statement. The slot replacement is atomic, and concurrent writers of one slot leave one row:

```sql
WITH s AS (INSERT INTO vci.namespaces AS n (ns, seq) SELECT $1, 1
           ON CONFLICT (ns) DO UPDATE SET seq = n.seq + EXCLUDED.seq RETURNING seq),       -- (2.9) one number
up AS (
  INSERT INTO vci.attestations AS a
    (ns, key, test_key, signer, storage_key, target, issued, tree16, manifest_ref, ref_state, value,
     format, commit_id, platform, state, duration_ms, expires, hdr, tables_id, shape, state_obj, seq)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
          $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, (SELECT seq FROM s))
  ON CONFLICT (ns, test_key, signer, storage_key) DO UPDATE SET
    key = EXCLUDED.key, target = EXCLUDED.target, issued = EXCLUDED.issued, tree16 = EXCLUDED.tree16,
    manifest_ref = EXCLUDED.manifest_ref, ref_state = EXCLUDED.ref_state, encoding = 0, value = EXCLUDED.value,
    format = EXCLUDED.format, …, state_obj = EXCLUDED.state_obj, seq = EXCLUDED.seq,
    stored_at = now(), stored_by = session_user
  WHERE (a.key, a.value, a.encoding) IS DISTINCT FROM (EXCLUDED.key, EXCLUDED.value, EXCLUDED.encoding)
     OR (a.format, …, a.state_obj) IS DISTINCT FROM (EXCLUDED.format, …, EXCLUDED.state_obj)
  RETURNING a.key)
SELECT key FROM up
UNION ALL
SELECT key FROM vci.attestations
WHERE ns = $1 AND test_key = $3 AND signer = $4 AND storage_key = $5 AND NOT EXISTS (SELECT 1 FROM up);
```

A conflict on `(ns, key)` implies the same slot. The unhinted variant keeps `key`, `issued` and `tree16` and compares
`(value, encoding)` and the columns only. Both read the kept key back in the same statement, so a put is one round
trip (a second only in a concurrent race); comparing `encoding` lets identical bytes repair a row this vci cannot
read. (2.9) The ten listing columns (`$12` to `$21`) are the `Columns` given, every one NULL without, and the row
comparison (`IS DISTINCT FROM` treats two NULLs as equal) makes the same bytes put with other columns, or without
them, replace them while the bytes stay a no-op; a put takes one `seq` number whether or not it changes the row
(gaps are nothing to a replica). Concurrent first inserts of one key can collide on the primary key `(ns, key)`,
which is not the arbiter, so a unique violation is retried (up to three times).

**`put_manifest`** always refreshes `put_at` and reports a change. The CTE reads the snapshot before the upsert:

```sql
WITH old AS (SELECT value, encoding FROM vci.manifests WHERE ns=$1 AND root=$2)
INSERT INTO vci.manifests AS m (ns, root, base, value) VALUES ($1, $2, $3, $4)
ON CONFLICT (ns, root) DO UPDATE SET
  value = CASE WHEN m.value IS DISTINCT FROM EXCLUDED.value OR m.encoding <> 0 THEN EXCLUDED.value ELSE m.value END,
  base = EXCLUDED.base, encoding = 0, put_at = now()
RETURNING COALESCE((SELECT value FROM old) IS DISTINCT FROM $4 OR (SELECT encoding FROM old) <> 0, true) AS changed;
```

**`remove`**: `WITH d AS (DELETE FROM vci.attestations WHERE ns=$1 AND key = ANY($2) RETURNING key), s AS (<n
numbers, n = count(*) FROM d, none when nothing went>), g AS (INSERT INTO vci.gone (ns, seq, key) SELECT $1, <the
i-th number>, key FROM d) SELECT key FROM d`: immediate and global, a `gone` row per key that existed (2.9). On a
schema that lacks the `gone` table the removal first adds the format-3 tables (a request of its own); on a missing
schema it removes nothing and creates nothing.

**`remove_manifests`** validates every root first, then:

```sql
DELETE FROM vci.manifests m
WHERE m.ns=$1 AND m.root = ANY($2) AND m.put_at <= now() - make_interval(secs => $3)
  AND NOT EXISTS (SELECT 1 FROM vci.attestations a WHERE a.ns=$1 AND a.manifest_ref = m.root)
  AND NOT EXISTS (SELECT 1 FROM vci.manifests b WHERE b.ns=$1 AND b.base = m.root)
RETURNING root;
```

The grace period (`manifest_grace`, default 1 h, at most 30 days) must exceed the longest gap between a run's
`put_manifest` and the `finish` of its batch. Another run's `put_manifest` either re-inserts the root or refreshes
`put_at` before its attestation commits, so the root is never deleted from under it. A handle opened with
`OpenContext::long_running` (`vci prune`) uses grace 0; `manifest_grace = "0s"` does too. The comparison is `<=`, so
grace 0 also removes a root put in the same instant. Referenced roots and other manifests' bases are kept whatever
the grace, and not counted.

**`batch`** is write-behind (`WriteBatch::deferred`), with `finish` flushing as section 6 describes:

- (2.9) the objects first: `INSERT INTO vci.objects (ns, id, kind, bytes) SELECT … FROM unnest($ids, $kinds, $bytes)
  ON CONFLICT (ns, id) DO UPDATE SET put_at = now()`, `seq` left NULL (an object stored already keeps its number);
- `INSERT … SELECT * FROM unnest($roots, $bases, $values) ON CONFLICT DO UPDATE …` for the manifests;
- then the attestation upsert from unnest arrays, one row per slot, because `ON CONFLICT` cannot touch one row twice
  in one statement, with the ten column arrays (`$12` to `$21`) and `seq` NULL on every row it inserts or changes;
- then `DELETE … = ANY` of the removed keys and a `DELETE … USING unnest(...)` of the slots a removal emptied (a put
  whose own key was removed afterwards in the same batch), each a CTE whose deleted keys become `gone` rows (`seq`
  NULL). Removals after the upsert, as section 6 orders them: a put queued in a removed key's slot replaced the slot
  whatever its key, and an emptied slot has no put, so the end state is the same either way;
- then the queued `remove_objects`, under the orphan rule as outside a batch (so the objects of a record this batch
  removes go with it, in the same transaction), `gone` rows for what went;
- then **the stamp**, one statement right before `COMMIT`: it counts the objects and the `gone` rows of the namespace
  whose `seq` is NULL (only this transaction's are visible so), takes that many numbers plus one per attestation put
  from the counter, and sets `seq` on the objects (by id), the attestations (by key, so a row the upsert left as it
  was is numbered again) and the `gone` rows (by `ctid`), in that order. The counter's row lock is therefore held
  from the stamp to the commit, not for the whole flush.

Measured: a 1,000-unit batch takes 6 statements (gate 6), the schema check, `BEGIN`, the stamp and `COMMIT` included,
instead of about 3,000 round trips; a batch of objects, records, removals and object removals 7 plus `BEGIN` and
`COMMIT` (gate 8 with an unhinted put's slot read). Inside a deferred batch:

- `put_objects` queues (validated first) and counts the objects the batch did not hold yet; `remove_objects` queues
  the ids (validated first, those the batch itself puts left out: they are within their grace) and counts nothing,
  since what goes is known only at `finish`; `get_objects` and `orphan_objects` read the server, where neither is
  visible yet; `prune_state_objects` is applied at once;
- `put_manifest` returns `true` unless the batch already holds the same bytes;
- `remove` returns every entry asked for, deduplicated by key;
- an unhinted put looks up the slot's key: queued first; the plain key when the batch empties the slot or removes the
  stored key; else stored (one read), else the plain key;
- `remove_manifests` (not queued) keeps the roots the batch will write or reference (its attestations' manifests, its
  manifests and their bases), whatever the grace, because the server cannot see them yet;
- dropping the batch without `finish` also flushes it.

### Objects, columns, `seq` and `gone` (2.9)

The `objects` module. Every method validates its arguments first, as section 4 says, and writes nothing on failure.

- **`put_objects`** (outside a batch): one statement, `WITH s AS (<n numbers, n = cardinality($ids)>), up AS (INSERT
  INTO vci.objects AS o (ns, id, kind, seq, bytes) SELECT $1, u.id, u.kind, <the i-th number>, u.bytes FROM
  unnest($ids, $kinds, $bytes) WITH ORDINALITY AS u(id, kind, bytes, i) ON CONFLICT (ns, id) DO UPDATE SET put_at =
  now() RETURNING (xmax = 0) AS inserted) SELECT count(*) FILTER (WHERE inserted) FROM up`: idempotent by id, the
  grace restarted on a re-put, the count of the rows inserted (`xmax = 0` on a returned row of an upsert means
  inserted, not updated); an id repeated in one call is put once. The bytes go as `bytea` parameters, binary.
- **`remove_objects`** (outside a batch): one statement, `WITH d AS (DELETE FROM vci.objects AS o WHERE o.id =
  ANY($ids) AND o.ns=$1 AND o.put_at < now() - make_interval(secs => <OBJECT_GRACE>) AND NOT EXISTS (<a referrer in
  hdr, tables_id, shape or state_obj>) RETURNING o.id), s AS (<count(*) FROM d numbers>), g AS (INSERT INTO vci.gone
  (ns, seq, object) …) SELECT count(*) FROM d`. The grace is always `OBJECT_GRACE` (one hour; the manifest grace of
  the selection and `long_running`'s zero do not apply, as the trait fixes it).
- **`prune_state_objects(older_than)`**: the same shape over `kind = 4 AND put_at < now() - make_interval(secs =>
  $2)`, whatever references them, on the `(ns, kind, put_at)` index; a `gone` row each.
- **`orphan_objects`**, **`get_objects`** and **`columns`**: above, "Reads and the per-handle cache".
- **The `seq` counter.** `namespaces.seq` per namespace, the design's `vci_schema` counter. A statement that needs
  numbers takes them with `INSERT INTO vci.namespaces AS n (ns, seq) SELECT $1, <n> ON CONFLICT (ns) DO UPDATE SET
  seq = n.seq + EXCLUDED.seq RETURNING seq` as a CTE (the last number taken; the i-th is `seq - n + i`), and the
  counter row's lock is held to the end of the transaction, so the next transaction of the namespace gets its block
  only once this one has committed or rolled back: **`seq` is in commit order**, each transaction one block of its
  own, and the writers of a namespace queue behind each other for the length of that lock (an ordering cost, not a
  safety one; STORE-V2 section 2.1). Outside a batch that is one autocommit statement. In a deferred batch it is
  the stamp before `COMMIT`, so a flush of several seconds holds the lock only for the stamp and the commit; a writer
  that waits longer than `lock_timeout` (10 s) for it fails as `Timeout{operation: "a lock"}`, latched, like any
  lock wait that runs out. A put that changes nothing, an object stored already and a removal of nothing take
  numbers nobody uses; gaps are nothing to a replica. Rows a 2.8 vci wrote keep `seq` NULL for good, and an object
  put inside a batch and found already stored keeps its number. Nothing syncs from PostgreSQL today; `seq` and
  `gone` are the same data libSQL's replica reads, kept so that `vci store copy` and a future replica see one model.
- **`gone`.** One row per removal: `key` for an attestation, `object` for an object, `at` the time, `seq` as above.
  Never read by this backend; purged by nothing yet (STORE-V2 section 2.1's horizon is the libSQL replica's: open).
- **`upgrade_begin` and `upgrade_finish`**: above, "Migrations".

### fetch, push, hints, roles

- **`exchange` and `caps`.** `exchange()` is `None`. `caps` is `LOCAL.with_shared_writes(true).with_hints(true)` and
  (2.9) `.with_objects(true).with_columns(true)`.
- **`vci fetch`** prints `vci: the postgres store at <location> is shared: nothing to fetch (N attestations stored)`.
- **`vci push`** prints `vci: nothing to push: the postgres store is shared; attestations were stored when vci run
  made them`.
- **`--rewrite-history`** and **`--remote`** exit 2.
- **Hints.** Hints live server-side per namespace. `passing_on` results are memoized per tree per handle, and the
  flags are loaded once per handle (every flag of the namespace). `remember_passing` is one UNNEST upsert; the 7-day
  memo prune is a statement of its own, once per handle, with its errors ignored (a single CTE would make a role
  without DELETE on memo lose the upsert too). Every hint error is swallowed, and hints never create the schema.
- **Roles** (the recipe is in docs/REFERENCE.md, "PostgreSQL", and was checked against a server: a writer before the
  schema exists gets `NotInitialized`, a reader's write `Denied`).
  - `vci_owner` runs DDL (`CREATE` on the database; its first write creates the schema, later `vci store init`).
  - `vci_writer` has USAGE on the schema and SELECT, INSERT, UPDATE and DELETE on its tables, for protected-branch CI.
  - `vci_reader` has USAGE and SELECT, plus INSERT and UPDATE on memo and flags, for pull-request jobs and
    developers.
  - (2.9) `vci store upgrade --begin` (or the owner's first write with this vci) adds the `objects`, `gone` and
    `namespaces` tables; a `GRANT … ON ALL TABLES IN SCHEMA vci` given before it does not cover them, so the two
    GRANT lines are run again afterwards (or `ALTER DEFAULT PRIVILEGES` set beforehand). Until then `vci_writer`'s
    writes, removals included, fail as `Denied` on the new tables, and on a schema that still lacks them as
    `NotInitialized` naming the schema.
  - Optional RLS: `CREATE POLICY own_rows ON vci.attestations FOR ALL TO vci_writer USING (stored_by = session_user)
    WITH CHECK (stored_by = session_user)` plus a read-all SELECT policy, so a role can delete or replace only its own
    rows.
- **Operations.**
  - Backups: `pg_dump -n vci`.
  - Monitoring: `pg_stat_activity WHERE application_name LIKE 'vci %'`.
  - Retention: `vci prune` with `long_running`.

---

## 18. Backend: libSQL (Turso)

`vci-store-libsql` holds `LibsqlFactory` (kind `libsql`, registered under vci-cli's cargo feature `libsql`, on by
default), `LibsqlStore` (`open(&Selection, &OpenContext)`, which does no I/O; `mode()`, `path()`, `namespace()`,
`requests()`, every HTTP request sent, `retries()`, those sent again (a busy server, a stream the server no
longer knew, a connection lost under the request, a deadline that ran out), and `received()`, the bytes of values
read, as stored; doc-hidden `__execute_for_test`, `__query_for_test` and `__compress_for_test`), `LibsqlError` (the payload of `StoreError::Backend` for unexpected
errors), `table_prefix(namespace)` and the testkit (below). The modules are `conn` (the URL and the token, the TLS
connector, the runtime, the pool, the circuit breaker, deadlines, error classification and scrubbing, the guard
against the client's panics, SQL literals), `remote` (the tables of a namespace, reads, prefetch, hints), `cache`,
`batch` and `replica`. One store, three modes, chosen from the selection (section 9):

| mode | selected by | reads | writes | `caps` |
|---|---|---|---|---|
| local | `VCI_STORE=libsql` with no `VCI_STORE_URL`, or `VCI_STORE_URL=file:<path>` | a file, `<git common dir>/vci-store.libsql` by default | the file | the SQLite store's (`LOCAL.with_hints(true).with_objects(true).with_columns(true)`, section 16) |
| remote | a `libsql://` `VCI_STORE_URL` (or `https://`/`http://` with `VCI_STORE=libsql`) | the server, through a per-handle cache | the server, a batch as transactions of whole units of at most 1 MiB, one request each | `with_shared_writes(true).with_hints(true).with_remote_reads(true).with_objects(true).with_columns(true)` |
| replica | remote, plus `VCI_STORE_SYNC=replica`, `VCI_STORE_REPLICA=<path>` or `[store.libsql] replica = true` | a local file synced from the server at its first use and at each later prefetch; objects and columns from the server | the server, then written through to the file | `with_shared_writes(true).with_hints(true).with_objects(true).with_columns(true)` |

**Crate.** `vci-store-libsql` depends on `vci-store`, `vci-core`, `vci-store-sqlite` (the schema SQL and the file
format), `serde_json`, `libsql = { version = "=0.10.0", default-features = false, features = ["remote"] }` (the Hrana
client: HTTP, in Rust), and, for the connector it hands libsql, `hyper` 0.14 (`client`, `http1`, `tcp`; the version
libsql's connector trait is written against), `http` 0.2, `tower-service` 0.3, `tokio` (`rt`, `time`, `net`),
`tokio-rustls` 0.26 and the PostgreSQL store's pins `rustls = "=0.23.45"` (`ring`, `std`, `tls12`) and
`webpki-roots = "=1.0.9"`, and `zstd = "=0.13.3"` without its optional features (2.8.2: values stored compressed,
below; the reference C library, built with the C compiler the bundled SQLite already needs). One `rustls` resolves and `cargo tree -i aws-lc-rs` is empty. libsql 0.10.0 was published
on 13 October 2026, twelve days before it was pinned, not the two weeks decision 13 asks for; it is the version the
work was specified against. Two of libsql's features are left off on purpose:

- **`core`** (libsql's local engine, which its `replication` and `sync` features, the embedded replicas, build on)
  compiles libSQL's SQLite fork with the ordinary `sqlite3_*` symbols, which rusqlite's bundled SQLite (git-meta-lib's
  and the SQLite store's) exports too. Checked with a binary holding both: one copy wins at link time for every caller
  (rusqlite reported SQLite 3.47.0, libSQL's version, not its own), and libsql's first `Database` then panics on its
  start-up assertion (`sqlite3_config` returns 21, `SQLITE_MISUSE`, because the library was initialized already). So
  vci links no libSQL engine: the local mode keeps the SQLite store's file through `vci-store-sqlite`, and the replica
  is vci's own, synced over Hrana (below).
- **`tls`** brings `hyper-rustls` 0.25 and a second `rustls` (0.22). vci gives libsql a connector of its own instead:
  TCP (`TCP_NODELAY`), then rustls with the `ring` provider and the webpki roots, ALPN `http/1.1`.

Each handle owns a current-thread tokio runtime, started on first use, on which every request runs (`block_on` from
the calling thread); the trait stays synchronous. The store costs the release binary about 4.3 MiB: on macOS arm64
(Rust 1.99.1, dynamic), 25,339,616 bytes with the default features against 20,811,120 with `--no-default-features
--features sqlite,postgres` (stripped: 19,912,984 against 16,472,296). Most of it is what libsql's `remote` feature
pulls in: hyper 0.14 with its HTTP/2 stack (`h2`, from libsql's `hyper` features), `tower`, `libsql-hrana`, and
libSQL's SQL parser (`libsql-sqlite3-parser`, with which `execute_batch` splits statements). Not
measured on the static musl build of section 17.

**What the command line relies on**:

- `status()`: local as SQLite's (``Absent{advice: "the first `vci run` creates it"}``); remote ``Absent{advice: "the
  first `vci run` creates it"}`` until the namespace's tables exist, `Ready{schema_version: Some(1)}` after; replica
  ``Absent{advice: "nothing was synced from <url> yet; the first `vci run` stores records there"}`` while its file
  holds nothing.
- `exchange()` is `None`: `vci fetch` says `vci: the libsql store at <location> is local|shared: nothing to fetch (N
  attestations stored)` (local for the local mode, shared for the others) and `vci push` that there is nothing to
  push.
- `location()`: `<file> (local)`, `libsql://<host> namespace <ns> (remote)`, `<file> (replica of libsql://<host>
  namespace <ns>)`. The URL is printed with its scheme, host and port only: a path as `/<path>` (a token could be
  written there), never its query. `vci store info` prints it, and its settings say `url` (`select::redact` shows a
  libSQL server's URL the same way, and of its query only `tls`, `authToken=***`, and `***` for any other parameter,
  its name included, since a token may be either), `mode`, `path` or `replica`, `token` (`(set)`, `(the URL's
  authToken)` or `(none)`, never the value) and `namespace`.
- Conditions that mean the store cannot be used are `Unavailable`, `Timeout`, `Denied` (a read-only token; a server
  that takes no more writes, below), `NotInitialized`, `Incompatible`, `Unsupported` (a record larger than a server
  takes, below) or `Config` (section 10);
  `Backend(LibsqlError)` only for a statement the server refused for a reason vci does not know (a trigger, a
  constraint), which latches nothing: `vci run` then exits 2 after the run, and the handle goes on.
- The publication gate (section 7) applies to the remote and replica modes, not to the local one.

### The local mode

`LibsqlStore` wraps a `vci_store_sqlite::SqliteStore` opened with `SqliteOptions { kind: "libsql", .. }`: the same
file format (`application_id` 'vci1', `user_version` 1, schema v1 of section 16), the same statements, batches, WAL
checkpoint, read-only fallbacks and errors, under the name `libsql` (in `kind()`, errors and timing lines). The file is
`<git common dir>/vci-store.libsql`, `[store.libsql] path` (relative to the git common directory, no `..`) or
`VCI_STORE_URL=file:<path>` (absolute or relative; a `file:` URL with a query, which could hold a token, is refused
without being printed, never taken whole as a file's name). A SQLite store's file can be copied to it and back
unchanged.

### The schema on a server

The SQL of schema v1 lives once, in `vci_store_sqlite::sql` (`Names`, `Sql`, `sql::plain()`): the SQLite store
creates its tables from it, and the libSQL store creates the same tables, indexes and statements under a name prefix
per namespace (`Names::prefixed`). A libSQL database is one SQLite database, so namespaces are table sets:

```sql
CREATE TABLE IF NOT EXISTS vci_schema (
  ns TEXT NOT NULL PRIMARY KEY, prefix TEXT NOT NULL, version INTEGER NOT NULL,
  vci_version TEXT NOT NULL, created_at INTEGER NOT NULL, log_floor INTEGER NOT NULL DEFAULT 0);
-- per namespace, prefix vci_<the first 16 hex digits of BLAKE3(namespace)>_:
--   <prefix>attestations, <prefix>manifests, <prefix>memo, <prefix>flags   (schema v1, section 16)
CREATE TABLE IF NOT EXISTS <prefix>log (seq INTEGER PRIMARY KEY AUTOINCREMENT,
  test_key TEXT, signer TEXT, storage_key TEXT, root TEXT, at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS <prefix>log_at ON <prefix>log (at);
```

- **Created on the first write**, in one transaction (every `CREATE … IF NOT EXISTS`, then `INSERT INTO vci_schema …
  ON CONFLICT (ns) DO NOTHING`), so concurrent first writers are safe (c21). Reads never create anything: a missing
  table (`no such table`) reads as an empty store. Hints never create the tables.
- **Versioned** per namespace (`vci_schema.version`): a version above 1 is `Incompatible`, and every later call of the
  handle says so without a request. A token that may not create tables gets `NotInitialized{advice: "the first vci
  run with a token allowed to create tables creates them"}`.
- **Bytewise order** comes with SQLite's `BINARY` collation, as in section 16.
- **The log** names every slot and root a write touched (a format-1 put, a removal, a manifest), for replicas.
  Entries older than 30 days are deleted once per handle by its first write, which records the newest deleted `seq`
  in `vci_schema.log_floor`: a replica that last synced before it syncs everything. A format-3 put writes no log
  row: a replica syncs it by its `seq` (below).
- **Store format 3** (2.9, STORE-V2 section 2.1). The schema stays version 1; a namespace gains nullable columns and
  two tables, and its `vci_schema` row says so with `v2 = 1`:

  ```sql
  ALTER TABLE vci_schema ADD COLUMN v2 INTEGER NOT NULL DEFAULT 0;         -- the layout below is there
  ALTER TABLE vci_schema ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;        -- the write counter, one step per transaction
  ALTER TABLE vci_schema ADD COLUMN gone_floor INTEGER NOT NULL DEFAULT 0; -- gone rows up to it were purged
  ALTER TABLE <prefix>attestations ADD COLUMN format INTEGER;   -- then commit_id, platform, state TEXT, duration_ms,
                                                               -- expires INTEGER, hdr, tables_id, shape, state_obj TEXT,
                                                               -- seq INTEGER (the Columns of section 2, NULL on a format-1 row)
  CREATE INDEX IF NOT EXISTS <prefix>attestations_hdr ON <prefix>attestations (hdr) WHERE hdr IS NOT NULL;   -- and
    -- _tables (tables_id), _shape (shape), _state (state_obj), _seq (seq)
  CREATE TABLE IF NOT EXISTS <prefix>objects (id TEXT NOT NULL PRIMARY KEY, kind INTEGER NOT NULL,
    put_at INTEGER NOT NULL, seq INTEGER, bytes TEXT NOT NULL);           -- base64 of the object (object_to_base64)
  CREATE INDEX IF NOT EXISTS <prefix>objects_seq ON <prefix>objects (seq);
  CREATE INDEX IF NOT EXISTS <prefix>objects_kind_put ON <prefix>objects (kind, put_at);
  CREATE TABLE IF NOT EXISTS <prefix>gone (seq INTEGER NOT NULL, key TEXT, object TEXT, at INTEGER NOT NULL);
  CREATE INDEX IF NOT EXISTS <prefix>gone_seq ON <prefix>gone (seq);  -- and _at (at)
  ```

  Objects are **base64 text**: a batch is one SQL string of literals, and a blob literal is hex, twice the bytes;
  `get_objects` decodes (a text that is not base64 reads as not stored). A namespace 2.9 creates has the layout from
  its first request (one DDL transaction: the v1 tables, `vci_schema` made with the three columns when it is new, the
  eleven `ALTER TABLE`s on the attestations table just made, the two tables, the row with `v2 = 1`). A namespace a
  2.8 made is **upgraded in a request of its own** before 2.9's first write transaction on it (never inside a
  batch, STORE-V2 section 5: the version query reads `v2` with the version, in one request, so a handle learns the
  layout at no extra cost; a database whose `vci_schema` predates 2.9 answers `no such column` and the version alone
  is asked once more): the columns `vci_schema` and the attestations table have are read (`pragma_table_info`, one
  request) and only what is missing is sent, so the upgrade is idempotent and two writers upgrading at once are
  safe (whoever's `ALTER TABLE` comes second is refused, `duplicate column`, reads the columns again and sends what is
  still missing). `LibsqlStore::upgrade()` (`vci store upgrade --begin`) does the same ahead of a rollout and says
  whether anything was sent; `upgrade_finish()` (`--finish`) counts the rows that are not format-3 records (`encoding <> 0 OR
  hex(substr(value, 1, 1)) <> '76'`: by the value, as the SQLite store counts, since a frame is never stored
  compressed and starts with `v`, and the `format` column is what a 2.8 writer's upsert leaves stale) and is
  refused while one exists, and at zero is `Unsupported` in this release: dropping `manifests` and the change log
  needs every statement that names them branched on a version 2, which a later vci carries. A handle that found a
  namespace without the layout answers no objects and no columns for the rest of the process; a write of its
  upgrades the namespace first. The `gone` table holds the deletions a replica syncs: a row per removed key and per
  removed object, with the removing transaction's `seq`; rows older than the purge horizon, the larger of 30 days
  and the policy's `max_ttl` (`LibsqlStore::set_max_ttl`, which vci-cli passes from the policy; 30 days without it),
  are deleted once per handle by its first write, the newest purged `seq` kept in `vci_schema.gone_floor`.
- **Values compressed** (2.8.2). A value's `encoding` column, there since schema v1 for this, says how its bytes are
  stored: 0 as they are, 1 as one zstd frame (level 6). A format-3 record frame (2.9) is never compressed, whatever
  the setting: its first byte says its format on the server (the `--finish` count, the replica's sync by `seq`), and
  it is under 2 kB of mostly base64. Every reader from 2.8.2 reads both, decompressing at most
  5,000,000 bytes (no value vci stores is larger; past that the value reads as unreadable, its unit runs), and the
  key, the signature and every check cover the bytes as they were, so verification is unchanged. Writers compress
  when `VCI_STORE_COMPRESS=zstd`, else when `vci.toml` says `[store] compress = "zstd"` (the variable wins, `off`
  turning it off for one command; unset and absent: as they are; any other value is a `Config` error; `vci store
  info` shows `compress` and where it came from; another store ignores `[store] compress` with a warning). A vci older
  than 2.8.2 refuses a `vci.toml` with `[store] compress` (an unknown key of `[store]`), which is why it belongs there
  only once every vci that reads the repository is 2.8.2 or later. The schema stays
  version 1, since the tables do not change: a 2.8.1 reader reads a compressed value as one `in an encoding this vci
  cannot read (1)`, so that unit runs (never a wrong skip; a 2.8.1 replica leaves such a value out of its file, and
  2.8.2 syncs a file 2.8.1 synced in full once, see "The replica mode"), and a 2.8.1 writer replaces a compressed row of a slot it
  puts with its own, as it is (its upsert rewrites a row whose encoding is not 0). So a namespace takes compressed
  writes once every reader is 2.8.2 or later; until then the rows written raw and compressed coexist, and rows written
  before stay as they are until a unit is attested again. On vex's values (JSON) zstd stores envelopes and manifests
  about 3x smaller (16.1 MB to 5.45 MB over 825 sampled rows; their reads 2.7x faster from a laptop). A value of an
  encoding above 1 says `a newer vci wrote it`.

### Connection handling

- **The URL** comes from `VCI_STORE_URL`, else `[store] url` (without a token, section 9; messages name the one it came
  from): `libsql://<host>[:<port>][/<path>]` is HTTPS (`?tls=0`: HTTP, as the Turso CLI writes a local server's URL),
  `https://` and `http://` are themselves. Its query may hold `authToken` and
  `tls`; any other parameter (`token=`, `jwt=`, a bare `?<token>`, an `authToken%3D…`), a user or password, or a
  fragment is a `Config` error that prints neither the URL nor the parameter's name.
- **The token** is `VCI_STORE_TOKEN`, else the URL's `authToken`, else what `[store] token_command` prints (section 9),
  run when the first connection is made (`Conn::database`), sent as `Authorization: Bearer`. Both are secrets
  (section 9): `VCI_STORE_TOKEN` is in `NEVER_TO_CHILDREN`, kept as a `Secret::opaque` (redacted whole as `***`), and
  `select::redact` masks a libSQL URL's query and path (above). Every message passes through `Conn::scrub`: the URL's
  secrets (every query value but `tls`'s, a bare query key, a path) and the token, each raw, percent-encoded and
  percent-decoded, JSON-escaped at any depth (any run of backslashes before any of its characters: `\/`, then
  `\\/` when the echoed body is quoted again, and so on) and base64-encoded (standard and URL-safe, at the three
  offsets it can have inside a longer encoded text, such as an echoed `Authorization` header); `location()`, `Debug`
  and `vci store info` never hold either.
- **TLS** is always verified, against the webpki roots; there is no setting for another CA yet (section 21).
- **Bounded time.** The connector gives up on a connection (TCP and TLS) after the connect timeout (5 s). A handle's
  first request is always the description of a statement (Hrana's `describe`, which `prepare` sends once per
  connection and statement: a small request); until the server has answered one, it is given up after the connect
  timeout too, so a server or proxy that accepts and never answers, sends headers and stalls, or trickles bytes costs
  5 s (`Timeout{operation: "the server's first answer"}`), not the request timeout. Every other request is given up
  after the request timeout (`VCI_STORE_TIMEOUT_SECS`, 30 s; ten minutes for `vci prune`,
  `OpenContext::long_running`), and a pool checkout after the connect timeout. A request whose deadline runs out once
  the server has answered the handle (2.8.2) is sent once more, on a new connection, with a deadline of its own
  (counted in `retries()`): a large read answered slowly while other jobs write, or a write that waited for the lock,
  costs that call a second try instead of the handle (`OnTimeout::Resend`). A transaction of a write batch is sent once
  (`WRITE_ONCE`, `Conn::batch_checked`) and, when its deadline runs out (or it waited for the lock until then), first
  asks whether the server committed it (whether the change log holds the transaction's nonce, below, a read that
  needs no write lock, given `Conn::probe_timeout`: a quarter of the request timeout, at most 5 s; unanswered in
  time, it counts as not committed). 2.8.2 as first reviewed gave the question the whole request timeout, so that
  while the server answered nothing one try of a transaction cost two timeouts (60 s), the process's whole time for
  writes that fail, and the transaction was never sent again (the review, behind a proxy that stopped answering:
  `1 transaction(s), 6 request(s), 1.0 MB, longest 60.01s, 96 attestation(s) not stored: 62.41s`;
  `a_write_whose_question_goes_unanswered_is_sent_again`: at a 2 s timeout, the write and its question held, the
  units stored by a second copy, where with the whole timeout for the question all were lost after one try). One the server holds is stored; one it does
  not is the batch's to send again, as it was, within the process's time for writes that fail ("Writes", below),
  latching nothing itself. Since the question does not wait for the lock, a transaction still waiting for it is "not
  committed" and may commit afterwards: on vex's Turso database on 28 October two transactions that ran out of time
  at 30.7 s committed after the question, and a draft of 2.8.2, which then sent them again in halves, applied all 18
  of their slots twice, each copy waiting for the lock again under the very load that made the first late. So each
  transaction of a batch carries a nonce (a random 64-hex root no manifest has, `batch::Tx`), logged with its rows,
  and begins with a guard that fails it with the nonce in the error (`json_extract` of a bad path, run only on a row)
  when the log already holds that nonce at the transaction's time: whichever copy commits second is refused, the
  refusal counts as stored, and the transaction is applied once
  (`a_write_committed_after_the_question_is_applied_once`: a proxy sends the first copy on 3 s late, after the
  second committed; one log row per slot). Only the same
  request out of time again
  (`TRIES_AFTER_TIMEOUT`; counted per request, so that requests sent at once do not use up each other's try) latches
  the breaker;
  a deadline before any answer latches it at once, as before, and a request whose try comes after another latched it
  is not sent again. A hint's write (`Op::hint`: the memo and the flags) has a deadline of
  `HINT_TIMEOUT`, 5 s, or the request timeout if shorter, is never sent again and never latches
  (`OnTimeout::FailAlone`), not even when its connection cannot be made or is lost (the calls that need the server
  find that out themselves); a request of values sent beside others fails alone the same way, and the read sends its
  keys again itself ("Reads", below). While the server answers that the
  database is locked, that it is out of connections (HTTP 429) or that it interrupted the statement, the request is
  tried again with growing pauses until its deadline (`Timeout{operation: "waiting for another writer"}` then). A
  server stream idle for more than 4 s is reset before use (servers expire idle streams after about 10 s), and a
  stream the server no longer knows is replaced once.
- **Lost connections.** hyper keeps a connection alive between requests, and the handle's runtime runs only inside a
  call, so a keep-alive connection that the server, or a proxy in front of it, closed while it sat idle is found out
  only when the next request has gone out on it: `connection closed before message completed` (hyper's
  `IncompleteMessage`, what vex's CI got from Turso after a Go job's tests ran for minutes), or a reset, a broken
  pipe, an aborted connection, an end of file before the answer's end, or a TLS connection closed without its
  `close_notify`, each a transport failure in libsql's words (`Hrana: `http error: …``). Such a request is sent again,
  each time on a new libsql connection, whose new HTTP client opens a new TCP (and TLS) connection (hyper drops the
  failed connection from its pool, but the client may hold others that sat idle as long, and hands out the one used
  last first): at once, then after 100 ms and 500 ms, each only while the request's deadline allows, counted in
  `retries()`. Only when those fail too, or no time is left, is it a latched `Unavailable` (`cannot reach <url>: …`).
  It is sent again only once the server has answered the handle: before that no connection was kept alive to be lost,
  so a server or proxy that accepts and closes without answering (at once, with a reset, or after a wait; a
  `docker-proxy` with nothing behind it) latches at once, within the first answer's bound, as before, and a server
  that accepts and never answers still costs the connect timeout. A connection that cannot be made (`error trying to
  connect`: nothing listening, DNS, TLS, the connect timeout) latches at once, as before, so a server that went away
  costs one more connection attempt, refused at once, and an unreachable one no more than before. An HTTP status (401,
  403, 404, a 5xx) is the server's answer and is never sent again, whatever its body says (a proxy's page that quotes
  an upstream's `http error: connection reset by peer` included), nor is a statement's or a stream's error; the
  exception is a status whose body was cut off before it arrived whole, which looks like a lost connection and is sent
  again as one. A read's
  rows cut off after the server began sending them (`cursor error: …`, reading the answer's body) are not a lost
  connection either, since the connection was alive when the request went out: that read fails and nothing is latched,
  as in 2.8.0, so a server or middlebox that cuts some answer every time fails that read only. Sending a request again
  is safe: a read changes nothing, and a write batch applied twice leaves the rows as applied once but for the change
  log's, though it can undo a write of another handle that followed its first commit ("A batch sent again", below).
  2.8.0 latched the first lost connection, and every later read and write of the process failed with `… (failed
  earlier in this process; not retried)`.
- **Circuit breaker.** Per handle, as PostgreSQL's (section 17): the first connection that cannot be made, or that is
  lost under a request every time the request is sent (or once, before the server has answered the handle; above),
  HTTP 401, or 403 on a read (`the server asks for a token: set $VCI_STORE_TOKEN (or [store] token_command)`, or `the
  server refused the token …`, `… from [store] token_command (<command>)` for the command's), 404 (`no libsql database
  there`), other HTTP error status (a 5xx, a proxy's page), answer the client cannot read, deadline before the server
  first answered, request out of time twice, or a process's writes failing for longer than its time for them
  ("Writes", below) is latched, and every later call of the handle fails at once with `… (failed earlier in this
  process; not retried)`. Busy retries, `Denied`, `Unsupported`, `Backend`, a read whose rows were cut off, one
  deadline that ran out (sent again, above), a write transaction out of time (sent again by its batch) and a hint's
  write are not latched. 2.8.1 latched the first deadline: one vex job's 30 s read made its plan run every unit, and
  one 30 s write lost the run's remaining 800 attestations (44 of 207 vex Rails jobs on 27 October).
- **Statements the server refuses.** `sqld` reports a statement's error (a batch step's as a Hrana API error, a
  cursor step's as `error at step N`) with HTTP 200: the server works, so it is `Backend(LibsqlError)` (`<url>: the
  server refused a statement: …`), not latched; the transaction it was in was rolled back (its stream closes with
  the batch), and the stream is given up. A busy server (`database is locked`, HTTP 429, a connection it could not
  open in time, `Transaction timed out` when it gave up a transaction that waited for the lock, `interrupted` when it
  stopped a statement to let a writer in) is tried again within the request's deadline.
- **Panics in the client.** libsql 0.10.0 panics on an HTTP error whose body is not UTF-8 text
  (`String::from_utf8(…).unwrap()` in its `hrana/hyper.rs`), as a proxy's Latin-1 error page is. Every call into it
  (building the database, connecting, each request, closing streams) runs under `catch_unwind`; such a panic is a
  latched `Unavailable` (`the libsql client failed on the server's answer …`), so the plan fails open and `vci run`
  refuses to store. A panic hook installed once (wrapping the previous one) prints nothing for a panic on a thread
  inside such a call, so the body (which could echo a token) is never printed; every other panic is printed as
  before.
- **Errors.** A write the server refuses (HTTP 403 on a write, as for a read-only token: `Authorization forbidden:
  … doesn't not have Write permission`; or a refusal worded read-only, unauthorized or forbidden) is
  `Denied{operation: "write"}`, not latched: the hints a plan writes and the units `vci run` stores are refused, and
  reads go on, on a new stream (the server closes the refused one; a stream whose baton the server no longer knows is
  replaced and the request tried once more). Creating the tables refused that way is `NotInitialized`.
- **A server that takes no more writes.** `sqld` blocks a database's writes (`Operation was blocked: <reason>`, code
  `BLOCKED`: what a Turso database over its quota gets, and an operator's block) and refuses a write past its size
  limit (`database or disk is full`, `SQLITE_FULL`), both with HTTP 200 while reads go on. Such a refusal is
  `Denied{operation: "write", detail: "<url>: the server takes no more writes (blocked, as a database over its quota
  is, or full): …"}`, not latched: `vci run` refuses each unit it would store (`signing or storing failed: …`) and
  exits as the tests did, the plan reads on, and a namespace whose tables do not exist yet is refused the same way
  (not `NotInitialized`: the token is not the reason). A server that blocks reads too answers a read the same way:
  that is a latched `Unavailable` (the plan fails open). Checked against `sqld`'s own write block and size limit
  (its admin API); Turso's hosted quota answers were not observed (section 21).
- **Pool.** At most `min(VCI_JOBS, 4)` Hrana connections per handle. Each keeps the statements it prepared: Hrana's
  `prepare` asks the server to describe the statement (one request), once per connection and statement. Its HTTP
  connections are hyper's (libsql's client), kept alive between requests, except after a read: libsql 0.10.0 drops
  a read's answer (a cursor) at the end of its statement, before the end of the HTTP body, so hyper closes that
  connection and the next request opens another (TCP, and TLS on `https://`). vci's connector closes its sockets
  with a reset (`SO_LINGER` 0, `TcpStream::set_zero_linger`), so a closed connection leaves no `TIME_WAIT` behind:
  with an ordinary close each read held an ephemeral port for twice the maximum segment lifetime (30 s on macOS, 60 s
  on Linux), and the conformance suite's 5,900 connections a run ran macOS out of its 16,384 when two runs came close
  together or the machine was loaded (`Can't assign requested address`, section 21). Only connections whose answer
  was read, or that were given up, are closed.
- **Namespace.** As PostgreSQL's: `VCI_STORE_NAMESPACE`, else `[store.libsql] namespace`, else the repository id; a
  shallow clone needs an explicit one, and a namespace is 1 to 128 of `A-Z a-z 0-9 . _ : / @ -`.

### Reads (remote mode) and the per-handle cache

The cache is `vci-store-postgres`'s, with the same rules (section 17, "Reads and the per-handle cache"): filled only
by `prefetch` and `read_values`' manifest read-ahead, kept current by this handle's own writes, values moved out on
their first read, capped at 256 MiB. Each read is one statement whatever the number of keys, the keys bound as one
JSON array (`IN (SELECT value FROM json_each(?1))`), 5,000 to a request, but for values (below):

| method | on a cache miss |
|---|---|
| `list_units` | `SELECT test_key, key, target FROM <a> WHERE test_key IN (…) ORDER BY test_key, key` |
| `read_values` | the values of the keys and, in the same statement (`UNION ALL`, `values_with_bases`), the manifests they reference and those manifests' bases, but the bases cached already or brought by an earlier answer of the same read; 100 keys to each of the first requests, later ones sized from the answers; all go to the cache |
| `manifest`, `manifests` | `root = ?1`; `root IN (…)` |
| `read_units` | fully cached units from the cache (values kept); the rest in one statement with values |
| `list_all`, `count`, `manifest_roots`, `read_all` | one statement each, never cached |
| `orphan_manifests` | one statement: empty when a row's `ref_state` is 0, else the roots no row references |

**`prefetch(Units{ids, choose})`** is the listings of every unit in one request (from the server even when cached,
which is where other writers' changes are picked up), then the values `choose` picks that are not cached, with their
manifests and bases, as `read_values` reads them. `prefetch(Manifests)` is one request for the roots not cached as
stored, with their bases.

**Values, in requests sized from the answers** (2.8.2). 2.8.1 read a plan's 1,600 to 2,000 values (60 to 85 MB on
vex's Turso) in one request that took 2 to 22 s, and one request out of time made the whole plan run every unit. Now
the first requests take 100 keys each (`VALUES_PER_REQUEST`, about 4 MB of vex's) and go **as many at once as the
handle sends** (`Conn::max`, `min(VCI_JOBS, 4)`, at most one per request); each later request takes as many keys as
the last answer says fit in `VALUES_TARGET` of the request timeout (15%, 4.5 s at the default 30 s) beyond the wait
every answer has, at most four times the last request and between `VALUES_MIN` (25) and `VALUES_MAX` (400, about 15
MB of vex's) (`next_size`). That wait is the handle's shortest answer (`Conn::fastest`: the time of each successful
try divided by its requests, a statement's description and the statement), once per request the answer took (two
on a connection whose statement was not described yet); the pace is the time beyond it, which grows with the size
on a link whose bandwidth is the limit, and the room is what the target leaves beyond the wait, at least a third of
it. So on a link with a long wait for each answer but bandwidth to spare requests grow and few are sent: vex-api's
1,652 values went in 9 to 10 requests on vex's Turso database from a laptop (four of 100, then larger), in two
rounds behind a proxy that held each answer 1 s (`a_read_of_values_on_a_link_slow_to_answer_takes_few_round_trips`:
four of 100, then three of 400), and in 9 requests with each answer held 3 s
(`a_read_of_values_behind_a_long_wait_for_each_answer_takes_few_rounds`: 1,500 values in 8 requests and 15 s). A
draft of 2.8.2 sized them from the whole time an answer took, so a 3 s wait kept them small: behind that proxy
vex-api's prefetch sent 13 requests in 12.2 to 13.2 s against 2.8.1's 4 in 12.3 to 12.6 s, and the test's read 16
requests in 21 s. After each answer that took more than half of the timeout one fewer request is out at once
(at least one), after each within a third one more: requests sent at once may share a slow link's bandwidth, and then
take as many times longer (behind a proxy limited to 2 MB/s, vex-api's four first requests took 10.3 s each, the
next ones were sized to 43 values and took about 4 s each, and the plan read all 1,652 values in 42 s where 2.8.1's
one request ran out of time at 30 s; see "Measured"). **Each request brings the manifests and bases of its own
values** (`values_with_bases`), but the bases cached already (those an earlier read of the handle found to be bases,
`Remote::bases`) or brought by an answer of the same read before it was sent, bound as a second JSON array (at most
4,096 roots): no request of bases follows the values (the 2.8.2 draft read them in one more request after the
values, a round trip on the plan's path). **The statements are described ahead**: libsql's `prepare` sends Hrana's
`describe` once per statement and connection, one more round trip before a connection's first read; the store's
`warm()` (at the start of a plan) has the listing's and the values' statements described on `Conn::max` connections
at once (`Conn::describe_ahead`), after the status and the flags, and the pool holds one connection more than that,
so the plan's other reads (its memo, say) do not wait for one; a read takes an idle connection that has its statement
described when there is one. A request of values whose deadline runs out
(`OnTimeout::FailAlone`, alone or beside others) fails alone, latching nothing and not sent again whole, and no more
are sent at once: the read sends the keys of that request again, one request at a time and in halves, each half
counting on its own (one answered is kept when the other fails), and the keys never sent at the last size
(`OnTimeout::Latch`: one of those out of time was the second try, and latches the breaker, after which the rest fail
at once) (`a_lone_request_of_values_out_of_time_is_read_again_in_halves`,
`a_read_of_values_out_of_time_keeps_its_halves_and_reads_no_more`).
**The whole read is given two request timeouts** (`VALUES_DEADLINES`, `Conn::query_until`), one more for each 800
values beyond 1,600 (`VALUES_PER_DEADLINE`: about 30 MB of vex's, 1 MB/s at the default 30 s): no request runs past
them (one they cut short fails alone, latching nothing), and the keys not read by then fail as below.
**They are the handle's** (`Remote::values_until`): once a read of values had a request run out of time, every later
read of values by the same handle ends when that read had to, so the keys that failed are not asked for again and a
round's new keys fail at once, their units running. A plan reads values up to five times (the prefetch, its read of
the candidates, then a prefetch and a read again in each of rounds 2 and 3), so a slow link costs a plan one read's
time, as a server that stops answering does, never one per read (2.8.1 gave up after one deadline, and every unit
ran). `a_read_of_values_on_a_slow_link_is_bounded_and_not_sent_at_once` checks the pace behind a proxy limited to 1.7
and 1 MB/s (every value read once at 1.7 MB/s; at 1 MB/s the read stops after its two deadlines, nothing latched),
and `a_large_read_of_values_is_given_a_timeout_per_800_values` the third deadline for 1,700 values. A request that
fails otherwise, or before the read's time ran out, costs only its keys: `prefetch` leaves them uncached, counts them
in `Hydration::unresolved` and warns (`vci: warning: could not prefetch N stored value(s) from <url> namespace <ns>:
…; they are read again when asked for`, or `their units run` once the handle's time for values ran out), and
`read_values` reads them again when asked; a `read_values` request that fails marks its keys `Unreadable("could not be
read from the store: …")`, so their units run, and the call fails only when it could serve no key at all (from the
cache or the server), as a store that cannot be used does. The timing lines carry the bytes read: `prefetch N
unit(s), M value(s), R request(s), X MB` and `read M value(s), R request(s), X MB`.
Hrana's batch could carry several statements in one HTTP request; one statement per read already does, so a plan of
1,200 units is the status, the flags, the memo, two prefetches of two requests and the descriptions of the statements
on each connection: `a_plan_costs_a_handful_of_requests` checks at most 10 requests (8 in 2.8.1, whose values went in
one request) for the status and a prefetch of 300 units, and none for the listings, the batch read and 300 manifest
reads from 8 threads after it.

### Writes (remote and replica modes)

`batch()` is deferred, with PostgreSQL's queue (section 17, "Writes"): per slot the last put, the slots a removal
emptied, the removed keys, per root the last manifest, and `remove_manifests` keeping what the open batch will write
or reference. `finish` writes the queue as **short transactions of whole units** (2.8.2, below), one after the
other; each transaction is **one request**: a Hrana batch of `BEGIN IMMEDIATE`, the statements below and `COMMIT`,
each step run only when the one before it succeeded (libsql's `execute_batch`), with the stream's closing in the same
request, so that a batch that stopped part way is rolled back as the server closes the stream's connection
(a connection libsql still believes in a transaction after such a batch is replaced first, so every batch closes its
stream). Every write vci sends is such a batch, a namespace's first `CREATE TABLE`s included, so each takes the write
lock before its first statement. Under libsql's transactional batch (a deferred `BEGIN`), a namespace's first batch
began by creating `vci_schema`, which exists once any namespace does and so only reads: it held a read snapshot it then
had to promote to the write lock, a promotion that fails at once under concurrent writers (`SQLITE_BUSY_SNAPSHOT`, sent
back as `database is locked`, and vci sent the batch again) and can abort `sqld` 0.24 (section 21, item 17). A
namespace whose `vci_schema` row exists sends no DDL at all (one read per handle). The statements:

0. the transaction's guard (its nonce, below) and the step of the namespace's write counter (`UPDATE vci_schema SET
   seq = seq + 1`, 2.9): every row the transaction writes carries that `seq`, one value per transaction, so a
   replica syncing `seq > cursor` sees a transaction whole or not at all;
1. the format-3 objects (2.9), one multi-row upsert as base64 text: an id stored already keeps its bytes and its
   `seq` and gets its `put_at` refreshed (the grace counts from the latest put). They come first because a record
   is never stored before the objects it names (section 6): a queue's objects go with the writes of no unit, ahead
   of the first unit, and a batch flushed early sends every object queued so far with its first transaction;
2. the manifests, one multi-row upsert (the value and its encoding replaced; `put_at` refreshed);
3. the manifests this write leaves without a reference (2.8.2, `superseded_manifests`): the change log's rows naming
   them, then their deletion, both computed before the attestations change. A manifest goes when an attestation this
   write removes, empties or puts over (by key or by slot) references it, and nothing else does: no other attestation,
   no manifest as its base, nothing this write puts (an attestation's reference, a manifest or its base), no
   attestation of an unknown reference (`ref_state` 0), and it was put before the grace period (an hour; none for `vci
   prune`), the hour another writer has to reference a manifest it put outside its attestation's transaction. 2.8.1
   left them all to `vci prune`: of vex's 49,749 manifests (806 MB) on 27 October only 4,538 (74 MB) were referenced,
   each `vci run` adding one orphan per unit it attested again. Sent only where a manifest may exist (2.9: the
   version query also asks `EXISTS (SELECT 1 FROM <prefix>manifests)`, once per handle, and a handle that puts a
   manifest sends them from then on): the two statements repeat every key and slot of the write twice each, about
   1 MB of SQL for an 800-unit partition with its removals, dead weight on a namespace past the migration window;
4. for each removed key and emptied slot a `gone` row (2.9: `INSERT INTO <prefix>gone (seq, key, at) SELECT …` from
   the rows about to go), then the removed keys (`DELETE … WHERE key IN (…)`) and the emptied slots;
5. the attestations, one multi-row upsert on the slot, replacing the key, the value, its encoding, the listing
   columns (`Columns`, `NULL` each for a put without them) and `seq` when the key, the value, the encoding or any
   column differs: the same bytes put with other columns replace the columns, and the same batch applied again
   rewrites nothing;
6. the log rows of every slot removed or emptied and of every format-1 put (a format-3 put is synced by its `seq`),
   of every root touched and of the nonce, and once per handle (by its first transaction that commits) the log's
   prune and the `gone` purge at the horizon.

A format-3 record is under 2 kB, so `next_group` counts only format-1 attestations against `TX_UNITS`: a
transaction of format-3 records is sized by its bytes alone (200 records of the conformance fixture are one
transaction; `TX_UNITS` would have made four). An object whose base64 would reach a server's row limit (5,000,000
bytes) is refused as `Unsupported` before it is queued, as a record is. `put_objects` outside a batch is a batch of
one (one request asks which ids are stored, for the count); inside a batch it queues, and the count is what the batch
did not hold already. `remove_objects` outside a batch is applied at once, under the orphan rule of section 4 (one
request asks which of the ids are orphans as of now minus the grace, one transaction removes them with the rule
repeated and a `gone` row each); inside a batch on the thread it is queued (`Pending::object_removals`, the ids the
batch itself puts left out: the server does not hold them yet, or holds them with a `put_at` the batch refreshes),
counts nothing, stays queued through an early write, and goes as the last statements of the queue's last
transaction, after the removals of the records that referenced the objects, the rule in the SQL and a `gone` row
each; the handle's object cache then forgets the ids asked about, since whether each went is the server's to say.
A batch's objects are sent in its first transaction and, until a transaction carrying them commits, again in every
later one (`write_all` keeps them aside; an upsert that at most refreshes `put_at` once they are there), so that a
first transaction lost (refused, out of time past the retries) never leaves a stored record without the objects it
names: a transaction of objects alone that was lost is no warning unless no later transaction stored them, and the
objects an early write could not store are queued again for the batch's next write. `prune_state_objects` is the same two requests over `kind = 4 AND put_at <
cut`. `orphan_objects` is one read. `columns` answers what an open batch on the thread queued for a key first, then
one request per 5,000 keys. `get_objects` answers from the handle's object cache (a `prefetch(Objects)`, or its own
writes, which `settle` caches) and asks the server for the rest in one request per 5,000 ids; each id answered leaves
the cache, as a value read does, so the next call sees another writer's removal (c42). The answer is bounded at
`MAX_OBJECTS_ANSWER` while it is decoded.

**Short transactions** (2.8.2). 2.8.1 sent a project's queue in one transaction, flushed early at 8 MiB: on vex's CI
each such request took about 15 s to commit (about 0.5 MB/s) even alone, held the database's one write lock while
it was applied, and every other writer (a job's flags and memo, a shared manifest, its own units) queued behind it
for 10 to 30 s; 44 of 207 Rails jobs on 27 October passed the 30 s deadline and latched the store, losing about 800
attestations each (39% of units not attested, against 2% on git-meta). The time a transaction takes grows faster than
its size: from a laptop to vex's Turso database on 28 October (while vex's CI wrote too), three runs each, a
transaction of 0.25 MB committed in 1.3-2.8 s, 0.5 MB in 1.5-1.7 s, 1 MB in 1.8-3.7 s, 2 MB in 2.5-10.6 s, 4 MB in
5.0-10.2 s and 8 MB in 33.6-36.8 s, and a one-row write sent 3.3 s into an 8 MB one waited until it committed (7.8 s).
So the queue is split by unit (test key): a unit's attestation, the slots it empties, the keys it removes, and the
queued manifests its attestations reference with their queued bases go in the same transaction, so that an
attestation is never stored without its manifest nor a superseded one removed without its successor; manifests no
queued attestation references (and removals of keys that name no unit) go first. Units are packed, in order, into
transactions of at most `Remote::tx_bytes` of values as sent (`TX_BYTES`, 1 MiB, at first; below) and as large a
share of `TX_UNITS` (64) attestations, at least 4, a unit larger than that alone being a transaction of its own; compressed values count at two thirds of their size (zstd makes vex's JSON
about a third as large, and its bytes travel as hex, twice that). A manifest a transaction stored is not sent again
with a later one. The roots the whole queue references are kept by every transaction's `superseded_manifests`, so an
early transaction never removes a manifest a later one references.

A queue written early (2,000 writes or 4 MiB) is cut at a unit's end (`Pending::take_whole_units`): the writes of
the unit queued last stay queued, since `vci run` queues a unit's manifest, then its attestation, then the removals
of what it supersedes, and so do the manifests no attestation taken references (the next unit's, put before its
attestation), with copies of every base and of the manifests the units left queued reference; a manifest an early
write stored is not sent again with the same bytes. A draft of 2.8.2 wrote the whole queue as soon as it was full,
which could cut a unit in two (`an_early_write_of_a_batch_never_splits_a_unit`, against `sqld` with a trigger that
refuses one write): a manifest that filled the queue went in one transaction, refused, while its attestation went in
the next, stored and reported as attested on a manifest never stored (the next plan ran it, unable to read the
manifest); and an attestation that filled the queue went in one transaction, refused, while the removal of the one
it supersedes went in the next and deleted it. Only losses that latch nothing could do this (a refusal, or a
transaction out of time with retry time left).

A write's transactions go one right after the other. A transaction first sent that ran out of time (whether it then
turned out committed or not) makes the next ones half as large, down to `TX_MIN_BYTES` (256 KiB, two halvings, as many
as the process's minute of retries lets come about before it latches), and one that took less than a tenth of the
timeout beyond the handle's fastest transaction twice as large again, up to `TX_BYTES` (`Remote::size_writes_from`,
per handle, so the early writes of a batch carry it to the later ones): behind other writers on vex's Turso database
transactions of about 1 MB took 23 to 31 s, at the edge of the 30 s timeout. Time within the deadline does not shrink
them, and a copy sent again sizes nothing (its guard may refuse it at once, which measures no commit). The third
review's build halved them after any transaction that took more than a third of the timeout; the fourth review found
that most of such time is a wait a smaller transaction pays again (the link, the server's answer, another writer's
lock), so halving only made more transactions: behind a proxy holding each answer 1.1 s at a 3 s timeout, 600 units
of about 25 kB, it stored 122 within the bound in 17 transactions against 503 in 16 at a constant size, and on Turso
under vex's Rails jobs (zstd) one 2.8 MB early write went as 3 transactions in 20.5 s, the next as 5 in 41.1 s and the
next as 11 of about 250 kB in 129.4 s, about 11.8 s each, before the bound lost the rest. Its copy refused by its
guard then doubled the size back. (`a_write_sizes_its_transactions_from_their_commit_times`: each answer held 0.8 s
at a 2 s timeout, the transactions keep 1 MiB, one out of time halves the next, fast ones grow back;
`a_copy_sent_again_does_not_size_a_write`.) Sizing from time per byte would tell a slow commit from a long wait more
finely, but needs transactions of several sizes to compare; it is not done. A draft of 2.8.2 paused between transactions (a quarter
of the last one's time, 200 ms to 2 s, randomized) so that another job's small write waiting for the lock could take
it; that cost a lone writer about 10% (the review: 390 units behind a proxy answering in 0.3 s at 4 MB/s, 11.1 to
11.5 s with the pause and 10.1 to 10.2 s without, three interleaved runs each) and showed no effect on small writes
in any round on Turso ("Measured", below), so it is gone (`a_write_sends_its_transactions_without_a_pause`).

**A failure costs its own units.** A transaction that ran out of time (or waited for the lock until its deadline), or
whose stream the server dropped, is asked about first (`Conn::batch_checked`, "Connection handling" above: committed,
it is stored), then sent again as it was after a pause (250 ms doubling with each try up to 4 s, randomized between
half and one and a half of that, so that jobs that failed together do not come back together), at most `MAX_TRIES`
(4) times for a unit; its guard applies it once whichever copy the server commits (above). A draft of 2.8.2 sent it
again in halves, which a first copy committed late then doubled. A transaction the server refuses (`Backend`, `Unsupported`)
is split in halves down to the unit it refuses (`a_statement_the_server_refuses_latches_nothing`: one unit lost, the
other stored). Whatever still fails loses only its units: `BatchEnd::finish_partial` names their keys
(`vci_store::Finished::lost`), `vci run` refuses those units ("signing or storing failed: storing the batch: …") and
reports the rest as attested, and what a lost unit would have superseded stays. **A process's time for writes that
fail is bounded**: the time of every transaction that failed out of time and of the pauses before sending one again
counts against `WRITE_RETRY_DEADLINES` (2) request timeouts, 60 s at the default, for the handle
(`Remote::spend_on_writes`); past it the breaker latches (`writes kept failing (…), and this process spent the 60s it
may on writes that fail`) and every transaction still queued fails at once, so a server that takes no writes costs a
process about two timeouts, not one per transaction (`writes_out_of_time_are_sent_again_within_a_bounded_time`: a
held transaction sent again and the batch stored whole; a server that stops taking writes after the first
transaction: that transaction's units stored, the rest lost within 9 s at a 2 s timeout, the handle latched). A
server that cannot be reached latches at once, as before; so do a token that may not write and a server that takes
no more writes (`Denied`), which lose every unit still queued with that error. **A process's time for writes in all
is bounded too**: the time of every write (transactions that committed included, and the removal of unreferenced
manifests after `vci run`'s units) counts against `WRITE_TIME_DEADLINES` (6) request timeouts, plus one more for each
`WRITE_TIME_BYTES` (4 MiB) of values its transactions stored, for the handle (`Remote::writing_out_of_time`): 180 s
at the default, and 7.5 s more for each MiB stored, so the bound cuts short a server that stores less than about
140 kB/s over the process's writes, not a large write on one that keeps storing. Once it is spent, before the next
transaction not yet sent, every unit still queued is lost at once (`libsql store: this process's writes (the server
took them too slowly) timed out after …`) and so is every later write's (the removal of unreferenced manifests
refused at once, which `vci run` warns about), latching nothing (reads and hints go on), so that a server that takes
writes slowly costs a job at most that and one transaction more. A transaction out of time that is to be sent again
still goes, as the transaction under way: it may have committed after its question (a read, which does not wait for
the lock), and its copy, or the copy's refusal by the guard, says it is stored; the third review's build lost it
unasked, reporting units the server held as not attested (the fourth review behind a proxy at a 2 s timeout:
`lost 4: … timed out after 12s`, 4 of 4 on the server; `a_write_out_of_time_is_sent_again_past_the_time_bound`).
2.8.2 as first reviewed bounded only the time of writes that failed: three of its processes writing 150 units each
at once took 84.5 to 88.3 s each on vex's database (the review, 08:03 UTC), so a Rails job's 800 units could take
minutes. The third review's build bounded writes at a flat six timeouts, which cut short Rails-sized writes on
Turso in every raw round of the fourth review, quiet or not (0 to 200 of 800 units lost per process on a quiet
database at 187 to 189 s of writes, 294 to 690 while vex's Rails jobs wrote; "Measured", below), and removing
unreferenced manifests afterwards still waited the whole request timeout. (`a_process_writes_for_a_bounded_time_in_all`:
at a 1 s timeout, each answer held 250 ms, 2,560 small units stop after about 6 s with the units stored kept, nothing
latched, and a later batch lost at once; `a_process_that_keeps_storing_writes_past_six_timeouts`: 480 units of about
25 kB, 12 MB, at a 2 s timeout with each answer held 800 ms, all stored in more than 12 s; `removing_manifests_keeps_to_the_time_for_writes`.)
Units lost so run again in the next pipeline, which costs test time but never a wrong skip; the timeout (`[store]
timeout`, `VCI_STORE_TIMEOUT_SECS`) sets the bound. A unit reported lost may still have been stored: a transaction out
of time that is given up (its tries or the minute of retries spent, the breaker latched) can commit afterwards,
which the question cannot see; the store is not trusted, so this costs a warning and a unit reported as not attested
that the next plan finds, never a wrong verification. An early write (a queue of 2,000
writes or 4 MiB, below) loses its units the same way, and `finish` reports them with the rest. The timing line says
what went: `write batch: M manifest(s), A attestation(s), R removal(s), T transaction(s), N request(s), X MB[
compressed], longest Ys[, L attestation(s) not stored]`.

**A batch sent again.** A batch whose connection was lost under it is sent again (above, "Lost connections"), and the
server may have committed it and lost only the answer. A transaction of the store's batches (every `put`,
`put_manifest` and `remove`, in a batch or not) carries its nonce and guard (above), so its second copy is refused
and it is applied once; what follows holds for the other writes (the schema, `remove_manifests`, the flags and the
memo). It is one transaction ending in `COMMIT`, applied whole or not
at all, and its values are literals fixed when it was built (the manifests' `put_at`, the attestations' `stored_at`
and the log's `at` included), so the same text goes again, and applied twice in a row it leaves the rows as applied
once, but for the log's: the upserts of manifests, attestations and the memo write the same rows (the second time
changes nothing), a removal deletes what is already gone, `remove_manifests` deletes only roots still unreferenced,
nobody's base and put before the grace period, the DDL is `IF NOT EXISTS`, the `vci_schema` row and the flags are `ON
CONFLICT DO NOTHING`, and the prunes move `log_floor` up to the same value and delete the same rows. The log's rows
are inserted again, under new `seq`s (a unit put once whose answer was lost has two), which a replica tolerates: a
sync reads the server's current rows of the slots and roots the log names after its last entry (`DISTINCT`), so a
slot named twice is read once, and one named again after a replica synced is read again as it now is.

The batch sent again is applied after whatever the server applied since its first commit, and wins as the last writer
in the order the server applies them: a write of another handle that followed the first commit, and returned, is
undone where the two overlap. Its upserts replace that writer's newer row of the same slot, memo entry or manifest's
`put_at`, and its removals delete a key that writer stored again, or, for a slot the batch emptied (a `DELETE` by test
key, signer and storage key), whatever that writer stored in the slot. A reader can see the batch's rows, then the
other writer's, then the batch's again (a key removed, stored again, then gone), which no order of single applications
gives. The window is from the first commit to the batch sent again (usually a few round trips and well
under a second, at most the request's deadline), vci's removals are of keys superseded and slots emptied, and the store is untrusted (section 1: every
attestation is verified when read), so the worst is a miss, a test that runs again and stores its attestation again,
never a wrong verification (removals conditioned on the row they meant to remove would order them strictly; for a
miss this rare they are not made). Should the server keep the transaction of a request that was cut off open, it
holds the write lock until the server expires its stream, and the batch sent again waits for it as for any other
writer, within its deadline.

Values travel as SQL literals, since the batch takes SQL text only: UTF-8 bytes without NUL as text cast
to a blob (`CAST('…' AS BLOB)`, the same bytes), anything else (a compressed value) as hex. A queue of 2,000 writes or
4 MiB of values (as they are; 8 MiB before 2.8.2) is written early, as transactions of its own (above). A write
outside a batch is a batch of one, with the same retries: `put` one request (an unhinted put first reads its slot's key), `put_manifest` two (it compares the
stored bytes first), `remove` two (it reads which keys exist first). `remove_manifests` reads the removable roots (put
before the grace period, an hour, none for `vci prune`; not referenced; nobody's base), then deletes them with the
same conditions and logs them: two requests.

**A record's size.** `sqld` refuses a row, and any one value or parameter, of 5,000,000 bytes or more (`SQLite error:
string or blob too big`; measured on 0.24.32: a 4,999,000-byte value is stored, 4,999,999 is not, and two 3 MB values
in one row are not), while a statement may be much larger (24 MB of literals in one multi-row insert went through). So
`put` and `put_manifest` refuse a record whose row would reach 5,000,000 bytes (the value, plus an estimate of the
rest of the row from above: its key, slot, target and reference, a few hundred bytes) before anything is queued or
sent, as `Unsupported{operation: "storing a record of 5,000,000 bytes or more on a server …"}`: `vci run` refuses that
unit (`signing or storing failed: …`, keeping the tests' exit code) and stores the rest of the batch, and the handle
goes on. A shared base manifest that large is refused too (a warning); its units' manifests are then encoded whole,
without it (section 4, `put_manifest`), and each unit whose own manifest is that large is refused alone, so no unit
is reported attested on a base that was not stored.
A server with a lower limit refuses the batch as `Unsupported` too, not latched. vex's largest manifest is 1.98 MB.
The SQLite and PostgreSQL stores and git-meta have no such limit, and the local mode, a SQLite file, has none either.

`a_plan_costs_a_handful_of_requests` writes 300 units (600 attestations and 300 manifests) in one request per 64
attestations and the schema's; `a_batch_is_written_as_short_transactions_of_whole_units` writes 120 units of about
40 kB in requests of at most 1.6 MB each (the statements' text and its JSON escapes), every attestation with its
manifest. With 2.8.1 the release-build test `many_units_are_listed_and_read_quickly` (1,200 units of 18 KB against a
local `sqld`) wrote them in 0.64 s and 8 requests (three transactions: the queue flushed at 8 MiB), and listed and
read them on a new handle in 0.10 s and 4 requests (not measured again).

### The replica mode

The replica is a SQLite store file (the local mode's format), by default `<git common dir>/vci-store.libsql`, else
`VCI_STORE_REPLICA` (absolute or relative to the git common directory) or `[store.libsql] path`. Beside it,
`<file>.sync` (JSON: `{"v": 3, "source": "<url> namespace <ns>", "seq": N, "mark": "<at>:<slot or root>", "epoch":
<created_at>, "seq2": M}`) says which server and namespace it copies, up to which log entry, that entry's fingerprint
(when it was written and what it names), when the namespace was created, and (2.9) up to which value of the
namespace's write counter the format-3 rows were synced. `v` (`SYNC_FORMAT`) says which values the vci that synced
the file reads: 1 (2.8.1 and earlier) only values stored as they are, 2 (2.8.2) zstd frames too, 3 (2.9) format-3
records and deletions by `seq`. A sync leaves out a value it cannot read (its unit runs) yet moves the mark past it,
so syncing what changed since never brings it back: a file 2.8.1 synced while another vci wrote compressed values
lacks them after the upgrade, until their slots are written again or the log's floor passes the mark (30 days). A
sidecar whose `v` is older than this vci's (or missing) is therefore synced in full once
(`a_replica_synced_by_an_older_vci_is_synced_in_full_once`). Removing `<file>.sync` forces a full sync with any
version.

**Store format 3** (2.9). A format-3 put writes no log row, so the sync reads, in the same request as the log's rows,
the frames (`hex(substr(value, 1, 1)) = '76'`; a format-1 row this vci wrote has a `seq` too, but the old log names
its slot, so it is synced once) whose `seq` is past `seq2` (each row's slot then ends as the server has it, like a
slot the log names) and the `gone` rows past it (the keys they name leave the file; the object ids are left out, since the file
keeps no objects). The statement with those branches is sent first; a namespace without the layout refuses it (a
column or the `gone` table missing) and the plain statement follows, so a 2.9 replica of a 2.8 namespace costs one
more request a sync until the namespace is upgraded, and one of a 2.9 namespace none. Everything is synced again
when `seq2` is older than `vci_schema.gone_floor` (deletions the file never saw were purged at the horizon, STORE-V2
section 2.1) or past the counter (the namespace was restored to an earlier point), beside the log's own rules. The
sync brings the file **no objects and no columns** in this release (section 16's file could keep them; the sync does
not read them yet): a replica's `get_objects`, `columns`, `orphan_objects`, `remove_objects`, `prune_state_objects`
and `prefetch(Objects)` ask the server, as `orphan_manifests` does, and a write's objects and columns are not written
through. When the sync reads `objects WHERE seq > ?`, the `gone` object rows and the columns, the file can answer.

- **The sync**, the first time the store is read (`warm()` starts it on a thread at the start of a plan), and again
  at each later `prefetch` (the plan's later rounds, `vci run`'s before supersession: section 4's "the next prefetch
  of the same data must pick them up"): one request reads, in one snapshot, the namespace's schema version (a newer
  one is `Incompatible`), the log's high-water mark and floor, the fingerprints of the entry the file was synced to
  and of the last one, when the namespace was created, and every attestation and manifest the log names after `seq`.
  Everything is read when the file is new, copies another source, was synced by an older vci (`v`, above), is older
  than the log floor, or when the log is not
  the one the file was synced from: its high-water mark is below `seq`, the entry at `seq` is not the one recorded,
  or the namespace was created at another time (it was dropped and created again, or restored to an earlier point).
  It is applied to the file in one transaction: each slot and root touched ends as the server has it (keys of the
  slot the server no longer holds removed; after a full sync, every slot and root of the file is reconciled), so a
  reader of the file never sees half of it. When the server holds nothing for the namespace (no tables, or no
  `vci_schema` row), the file is emptied. `<file>.sync` is written before the file is first changed (at entry 0, so
  an interrupted first sync is redone in full) and after the transaction. Timing line: `store: libsql: sync replica: N
  attestation(s), M manifest(s), everything|changes`. A sync of nothing new is one request.
- **A failed sync.** It is bounded by the connect timeout (connecting and the server's first answer) and the request
  timeout (the request), and latches the breaker. For the plan, `vci explain`, `vci run`, `vci ci` and `vci verify`
  it never blocks: `vci: warning: cannot sync the libsql replica <file> from <url>: <error>; reading the replica as
  it is`, and the store reads the file as it was (a stale replica only makes units run); writes then fail at once
  (the breaker), so `vci run` refuses each unit and keeps the tests' exit code. `vci store info`, `vci fetch`, `vci
  push` and `vci prune` are about the store itself, so for them (`OpenContext::command`) a failed sync is
  `Unavailable` (`cannot sync the replica <file> from <url>: …`) and they exit 2 (section 10). So is, for them, a
  replica they cannot keep (`the replica <file> cannot be kept: …`): a directory vci cannot write (probed first, with a
  file made there and removed at once, or in the nearest directory above it when it does not exist yet: nothing else
  is made), whether or not the server holds anything for the namespace yet, or a sync whose changes cannot be written
  to the file; for the plan and the run that is a warning, and the run's writes are refused (below). A sync again at
  a later prefetch that fails is a warning, once.
- **Writes** go to the server as in the remote mode; after each request that stored them they are written to the file
  in one transaction. A write needs a usable replica: a file that is one (below) in a directory vci can write (checked
  once with a probe file, creating nothing); otherwise it is refused as `Unavailable` and nothing reaches the server
  behind the file. A file the sync found nothing for (the server had no tables yet) gets its `<file>.sync`, at entry 0,
  when the first write goes through. A write that cannot be written through (another process holds the file past the
  busy timeout) is a warning, and the handle reads from the server for the rest of the process (with the remote mode's
  cache), so it still reads its own writes; the next sync brings them to the file.
- **Reads** are the SQLite store's on the file (the plan's 4,000 listings, the batch read and the manifests: no
  request). A value this vci cannot read (an unknown `encoding`) is left out of the file, so its unit runs;
  `orphan_manifests` is asked of the server, where that value still counts as the reference it was stored with.
  Hints go to the server, as in the remote mode.
- **Reads before a prefetch.** The file is a snapshot taken at its sync, which section 4 allows after a prefetch.
  Before its caller's first prefetch, `read_values` therefore syncs what changed first (one request when nothing
  did), so a key another writer removed since it was listed reads as `GONE`, as a remote handle's read does; after a
  prefetch it reads the file as that prefetch synced it, with no request, until the next one. The plan (the one
  caller of `read_values`) prefetches before it reads, so this costs it nothing. The other reads before a prefetch
  (`list_units`, `manifest`, `read_units`, ...) read the file as the opening sync left it, at the store's first use
  in the process: they may miss what another writer stored or removed since, which only makes a unit run (a value
  read is verified like any other), and is not worth a request each.
- **A file that is not a replica** (it exists without `<file>.sync`: a local-mode store at the same default path, say),
  or that is not a database, is never read or written: the store is `Unavailable` ("… is not a replica …", "the
  replica … cannot be read …: remove it, or set $VCI_STORE_REPLICA to another file").
- **Costs.** The release-build test above synced 1,200 units of 18 KB into a new replica in 0.41 s (one statement)
  and read them all from it in 11 ms.

This is the on-ramp for CI: no cache of the store to restore or save, and a long-lived machine (a developer's clone, a
self-hosted runner) syncs only what changed since its last command. An ephemeral runner starts without the file and
syncs the whole namespace before it reads locally, more than a remote plan reads (only what it checks), so the vex
pilot found it no faster there ("Measured", below).

### Measured

**Store format 3, one 800-unit partition against a local `sqld`** (2.9; `tests/format3.rs`,
`an_800_unit_partition_is_a_few_transactions` with `VCI_PAIRS` naming the 1,175-unit vex sample, release build,
macOS arm64; Turso's numbers come with the pilot). The largest run's first 800 units make 4 objects (one hdr, one
tables, the shape, the state: 329,446 B at rest, 439 KB as base64) and 800 records (1,417,069 B, 1,771 B each). The
first `vci run`'s batch (the objects, then the records, no removals) is **2 transactions**, 1,869,145 B of values and
objects as literals and 2,581,879 B of SQL in all (the keys, the slot columns, the ten listing columns and the
`seq` subquery add about 890 B a row), 6 requests with the namespace's creation (the version, the DDL, the version
again, two transactions), 0.18 s. A second run of the same units under other storage keys, superseding the first's
(800 records put, the 4 objects re-put, 800 removals with their `gone` rows and log rows): **2 transactions**, the
same 1,869,145 B of literals, 3,029,929 B of SQL, 2 requests, 0.20 s. Against the design's model (STORE-V2 section 3:
2.43 MB on the wire in 3 transactions of at most 1 MiB, with 1.2 N removals): the literals are 1.87 MB, the SQL around
them 0.7 MB for the puts and 0.45 MB for 800 removals, and the two transactions are 0.93 and 0.94 MB. With the
manifest-collection statements (now skipped where the namespace holds no manifest) the second run was 4,152,653 B
of SQL: their four repetitions of 800 keys and 800 slots cost 1.1 MB. **sqld, at vex scale** (STORE-V2 section 10; scripts, `results.json` and write-ups in
[docs/design/measure/sqld/](design/measure/sqld/); 29 October 2026, `sqld` 0.24.32 on 127.0.0.1, 14-CPU Mac,
release builds). *Writes*, one writer, 800 real Rails units, medians of 3 clean repetitions: format 3 is **2
transactions of at most 1 MiB in 1 flush** (longest 0.09 s), **2.59 MB of SQL** (1.87 MB of literals; 2.68 MB on
TCP), store write 0.15 s, process wall 0.60 s, 0 units lost, **2.46 MB and 806 rows at rest** (800 attestation rows of
2.02 MB, 2,529 B a row around a 1,774 B record; 4 objects of 0.44 MB as base64: hdr 5,988, tables 24,900, shape
122,304, state 286,076 B; 2 log rows). STORE-V2 section 3 said 2.43 MB on the wire (+6.6% measured), 2-3
transactions, 2.18 MB and 804 rows at rest (+13%: the objects as base64, the keys and the columns), a 1,783 B record.
Format 1 through the same store (`VCI_STORE_RECORD_FORMAT=1`): 33 transactions in 7 flushes, 30.24 MB of SQL (28.18
MB of literals; 31.21 MB on TCP), 0.86 s, 1.23 s of wall, 0 lost, 28.86 MB and 3,233 rows at rest (800 envelopes of
21,774 B, 800 manifests of 13,419 B, 1,633 log rows); 2.8.1's store (2.8.1 plus the turso-reads 1 MiB transactions,
not the released binary): 33 transactions in 7 flushes, 31.03 MB on TCP, 0.69 s, 28.82 MB and 3,233 rows. Today
against format 3: **11.7x on the wire, 11.7x at rest, 16x the transactions** (the design's 13.5x counts the 9 base
manifests a run writes, which the replays did not). Three format-3 writers at once stored every unit in 4 of 4
attempts; three format-1 writers have no clean local number, since `sqld` 0.24.32's write lock stalled for good in 25
of 25 attempts (section 21, item 17). *Plans*, vex-api, 1,156 candidates, medians of 7 runs: store-v2 on format 3
4.79 s of wall (3.1-11.4), 0.07 s fetching values, 1.61 s loading the verdict objects (a serial decode of every
candidate's frame the design did not count), 0.84 s of verdicts, 14 requests, **2.9 MB read**, 1,156 skips, 192 MB
of RSS; store-v2 on format 1 5.27 s, 43.3 MB, 283 MB; vci 2.8.1 on format 1 4.29 s, 4 requests of ~43 MB, 280 MB;
vci 2.8.1 on format 3 fails open in 1.25 s, every candidate `envelope: envelope JSON`. Production's plan 1 on Turso
(2.8.1, 164 jobs of 27 October) took 13.12 s median. The caveats: on loopback the times are the store's own cost
without the link or Turso's lock waits (transactions, bytes and rows carry over, times do not); the write side's
records are built by `crates/vci-store-libsql/examples/replay3.rs`, not by `vci run`; the plan side has one candidate
per unit and a checkout re-observed so that every candidate skips.

These and the paragraph above are the only format-3 measurements of the store so far, and they are of a local `sqld`
on a laptop: the lock times per transaction (1.8-3.7 s for 1 MiB),
the number of requests a plan makes and the plan's reads against Turso's hosted service are the design's estimates
from 2.8.2's measurements of JSON values and from vex's production logs (section 2, "Measured (format 3)"), to be
measured on Turso before the first production rollout.

On prove-perf's synthetic world (1,200 Go packages, each attested at three commits: 3,600 attestations of about 3 KB
and 3,601 manifests on a local `sqld` 0.24.32, written there by three `vci run`s in the remote mode), release build,
macOS arm64, two repetitions, on a laptop that other work kept at a load average of 35 to 315. Plan totals swung from
14 to 65 s in every mode alike, dominated by rehashing inputs; the store's own timing lines are what compare:

| step | SQLite file (and libSQL local) | libSQL remote | libSQL replica |
|---|---|---|---|
| plan, every unit skips: listings and the chosen values | 0.01 s (1,200 listings, 2,400 values) | `prefetch 1200 unit(s), 1200 value(s), 4 request(s)` 0.42-0.57 s (3.5 s at the worst load), then 1,200 more values in one request, 0.04-0.06 s | the sync, then as SQLite |
| plan, every unit runs (round 2) | 0.01 s | `prefetch 1200 unit(s), 3600 value(s), 2 request(s)` 0.15-0.38 s (1.7 and 3.3 s at the worst load) | as SQLite |
| the replica's sync | | | everything (3,600 + 3,601 records, 7,201 rows written): 0.6-9.3 s, median 3.4 s; nothing new: 0.01-0.04 s |
| `vci run`, 1,200 units edited: the store's writes | 2,400 records in one transaction, 0.20-0.76 s | 1,200 manifests and 1,200 attestations in one request, 0.14-0.25 s | that request, then 2,400 records written through, 0.10-0.11 s |
| `vci run`: "check, sign and store" | 0.47-1.80 s | 0.35-1.11 s (an empty namespace; 1.08-2.37 s into the filled one) | 0.80-1.03 s |

Round 2 reads all 3,600 values again because `read_values` moved the first ones out of the cache, as PostgreSQL does
(section 21, open item 2). Against a server across the internet, a plan pays about a dozen round trips (the status,
the flags, the memo, the prefetches, one read, the memo's write, and the first description of each statement on each
connection) plus the bytes (about 11 MB of values for 3,600 attestations here).

**Turso's hosted service, from vex's runners** (27 October 2026, vci 2.8.0, three workflow runs on
`composal-x64-8x` runners, one runner each, Turso in aws-eu-west-1 about 25 ms of TCP round trip away; runs
[40435874219](https://github.com/ComposalAI/vex/actions/runs/40435874219),
[40436708247](https://github.com/ComposalAI/vex/actions/runs/40436708247) and
[40437939673](https://github.com/ComposalAI/vex/actions/runs/40437939673)). Project vex-api, 2,291 Rails units, each
run in a fresh namespace:

| step | Turso | git-meta, on the same runner label |
|---|---|---|
| plan, 1,638 units skip and 653 run | remote 4.8-10.1 s (`prefetch 2291 unit(s), 1638 value(s), 4 request(s)` 2.5-7.8 s) | a cold fetch and plan without the cache, on the pilot's runners, 86-94 s |
| plan, as vex's pull-request jobs run it (15 to 1,636 units skipped) | | production's path, the 38 pull-request jobs of 27 October 00:12-01:50 UTC: restore the actions cache, put it in place and plan, 44 s median over the 37 with all three steps (51.5 s over the 20 on the pilot's host class) |
| plan, empty namespace | 1.2 s | |
| plan, nothing matches (3,276 attestations read) | remote 4.3-5.2 s | 24.4 s over 26,347 candidates, store up to date |
| replica on a fresh runner | cold sync and plan 4.1-5.1 s (sync 1.4-3.9 s for 1.6k-3.3k records), warm 4.0-4.4 s | |
| `vci run`, about 810 units: check, sign and store | 819 units: 21.6-30.4 s into an empty namespace (three runs), 29.5 and 30.1 s into one holding 819, 41.6 s into one holding 1,638 and 39.8 s into one holding 2,457; each run four requests of 3-12 s, three of 8 MiB of values or more and a smaller last one | 804-811 units on the pilot's host class (seven parts): 9.3-18 s locally, then `vci push` 32-63 s (median 39 s), 43-81 s together; on the 94,750 MiB hosts 3.9-6.6 s, then 15-22 s (19-29 s together) |

The plan gains the most: there is no cache to restore and nothing to fetch. Storing takes longer than into git-meta's
local store but needs no push after it, so on the pilot's host class the write side took about half as long (22-42 s
against 43-81 s); on the 94,750 MiB hosts git-meta's took 19-29 s, and Turso was not measured there. The same
1,638-value prefetch took 2.5 to 7.8 s across four plans, so Turso's latency varied up to 3x. A replica gained nothing
on an ephemeral runner, and its first sync reads the whole namespace (about 0.6-1.2 ms a record), where a remote plan
reads only what it picks. 5,733 attestations (seven runs of 819) were written with none refused. Not measured: a
namespace of git-meta's size (vex's held about 24,000 attestations, and its plans check 3,700 to 26,000 candidates;
the largest pilot namespace held 3,276), a read-only token's refusal, and Turso's quotas. A vex pull request (#2214)
proposes moving its Rails jobs to Turso; it is under review.

**2.8.2 against Turso's hosted service** (28 October 2026, 04:00 to 05:05 UTC, from a laptop in California to vex's
database in aws-eu-west-1, about 0.65 s for a trivial request on a new connection; vex's CI, all on 2.8.1, wrote to
the same database throughout, about 1,400 attestations every ten minutes, so the write lock was contended as in
production). Earlier drafts of 2.8.2 were measured on 27 October; their numbers, in this section's history, are
superseded by these.

*Reads.* `vci plan --project vex-api --base-ref origin/master` in a vex checkout of 17 October, 1,992 Rails units, on
vex's own namespace, read only (every write refused by a measurement build of each version); the laptop cannot run
vex's Rails checks, so this is the plan's first round, where its reads are. Six runs of each, interleaved, 04:54 to
04:56 UTC:

| vci | plan, median (range) | prefetch | the candidates' read | read, as stored | requests of values |
|---|---|---|---|---|---|
| 2.8.1 | 13.2 s (12.1-16.4) | 7.1-9.4 s | 3.2-5.5 s | about 99 MB | 2 |
| 2.8.2 | 7.3 s (6.5-10.1) | 4.2-8.1 s | 0.02-0.05 s | 63.5 MB | 8-9 (9-11 later: below) |

The fourth write review ran the same plans again, interleaved, at 09:18 to 09:21 UTC (one warm run of each first)
with the third review's build (`c26638a`, whose reads are this section's): 9.22, 6.59, 11.55, 7.48 and 7.48 s,
median 7.48 s, its prefetch of 1,654 values in 9 to 11 requests (64.2 MB) taking 4.5 to 9.3 s and the candidates'
read 0.02 s; 2.8.1 18.31, 17.14, 15.36, 29.36 and 34.29 s, median 18.31 s, its prefetch in 4 requests 7.3 to 28.1 s
and the read of 1,384 newest candidates 4.3 to 20.1 s. 2.8.2's plan held its numbers; 2.8.1's was slower under that
hour's load.

An interleaved set 17 minutes earlier, with a build of 2.8.2 that differed in when the statements were described
ahead, the pool's spare connection and the requests' size target, gave 12.9 s (12.5-16.4) against 7.8 s (7.1-8.6).
2.8.2 reads the 1,652 values 2.8.1 prefetches, in requests of 100 four at once and then larger ones, and not the 988
to 1,203 newest candidates 2.8.1 then reads in a second request.

On a copy of vex's namespace (5,728 attestations, copied with their manifests and bases, the memo and the flags) on a
local `sqld`, behind a proxy, five runs of each interleaved (04:48 to 04:52 UTC):

| link | vci | plan, median (range) | prefetch |
|---|---|---|---|
| every answer held 1 s, bandwidth unlimited | 2.8.1 | 13.5 s (10.6-16.6) | 4.2-5.9 s, then the candidates' read 1.2-6.7 s |
| every answer held 1 s, bandwidth unlimited | 2.8.2 | 9.1 s (8.4-9.9) | 3.2-4.6 s, 9 requests |
| 2 MB/s, two runs each | 2.8.1 | 31.2-31.5 s | its one request of values ran out of time (30 s), the store latched, the plan read nothing (every unit would run) |
| 2 MB/s, two runs each | 2.8.2 | 43.9-47.7 s | every value read, 42.4-42.6 s in 37-38 requests (four of 100 at 10.3 s each, then about 43 a request at about 4 s each) |

Across the four interleaved sets run that morning with each answer held 1 s (18 runs of 2.8.1), 2.8.1's plan took
10.5 to 16.6 s (two first, cold runs 22.1 and 25.8 s); 2.8.2 as committed took 8.4 to 9.9 s (the set above). The review of the draft had found 2.8.2 slower there (16.5-17.6 s
against 11-14 s): requests of 100 two at a time, a describe on each new connection, and the bases in one more
request after the values.

*Writes.* A scratch namespace seeded on the server (`INSERT … SELECT`) with vex's 1,200 newest attestations and the
1,176 manifests they reference, then `vci run`'s writes replayed into it by a measurement program that opens the store
as `vci run` does: a batch of units, each one of vex's real attestations (21.2 kB on average) and its real input
manifest (15.2 kB), under a new test id, written with `put_manifest` and `put` and finished. 500 units (16.4 MB) from
one process, or 350 (11.2 to 13.6 MB) from each of three at once; 2.8.1, 2.8.2, and 2.8.2 with
`VCI_STORE_COMPRESS=zstd`, in turn, each at its own time, so that a row compares loads as much as versions (the
interleaved rounds below replace its comparisons):

| run (UTC) | vci | per process | longest request | requests that ran out of time | attestations lost |
|---|---|---|---|---|---|
| one process, 04:16 | 2.8.1 | about 30 s | the first 8 MB, out of time at 30 s | 1, then latched | 500 of 500 |
| one process, 04:23 | 2.8.1 | 45.6 s | 29.1 s (8 MB) | 0 | 0 |
| one process, 04:31 | 2.8.1 | 30.0 s | the first 8 MB, out of time at 30 s | 1, then latched | 500 of 500 |
| one process, 04:17 | 2.8.2 | 213.9 s, 19 transactions | 26.4 s | 0 | 0 |
| one process, 04:32 | 2.8.2 | 145.0 s, 19 transactions | 25.6 s | 0 | 0 |
| one process, 04:21 | 2.8.2 zstd | 30.7 s, 11 transactions | 8.1 s | 0 | 0 |
| one process, 04:35 | 2.8.2 zstd | 19.5 s, 12 transactions | 2.6 s | 0 | 0 |
| three processes, 04:25 | 2.8.1 | 30.0, 30.0, 50.5 s | out of time at 30 s in each | 3, each latched | 1,050 of 1,050 |
| three processes, 04:26 | 2.8.2 | 95.1, 119.9, 132.8 s | 25.9 s | 0 | 0 |
| three processes, 04:29 | 2.8.2 zstd | 28.6, 30.1, 37.8 s | 9.9 s | 0 | 0 |

The time a transaction took swung with vex's CI's own writes: in the run of 04:32 the first two 4.2 MB flushes (five
transactions each) took 82.6 and 51.9 s, the last two 5.6 and 4.9 s. 2.8.1's lost units were not all missing from the server: its
requests that ran out of time were applied after the client gave up (the scratch namespace held about 1,000 of the
attestations 2.8.1 reported lost), but `vci run` cannot know which, and reports them all as not attested.
Compressed, the values travel at about two thirds of their size (zstd's third, sent as hex), and the longest
transaction of a flush took 1.5 to 9.9 s.

*A small write while others write.* A process that started 4 s after the writers put one manifest outside a batch
(`put_manifest`, a transaction of its own) and set a flag (a hint, at most 5 s):

| beside | the manifest | the flag |
|---|---|---|
| 2.8.1 writers (four runs) | 0.53-0.78 s | 0.18-0.22 s |
| 2.8.2 writers (three runs) | 0.96-10.9 s | 5.33-5.36 s: dropped at its deadline each time, nothing latched |
| 2.8.2 writers, zstd (three runs) | 0.90-4.16 s | 0.98-1.21 s |

and a one-row write every 1.2 s for 40 s (05:00 to 05:04 UTC) while one process wrote 150 units: beside 2.8.2, 9 and
18 writes, 0.66 to 16.9 s (all but 5 under 2.2 s); beside 2.8.1, 7 writes of 0.68 to 18.7 s (5 over 2 s) and, in the
run whose 4.8 MB request ran out of time, one write that waited 56 s while the server went on applying it. A write
4 s into 2.8.1's batch arrives while its first 8 MB are still being sent, before the server takes the lock, so the
single small write fared better beside 2.8.1 than beside 2.8.2's stream of 1 MB transactions; once a large request
is applied, every other writer waits for it, up to the 56 s above. Not measured: Rails jobs on vex's runners with
2.8.2 (whose network is faster than this laptop's), and a database whose every writer runs 2.8.2.

*Writes, interleaved* (the write review, 28 October 2026, 07:07 to 07:27 UTC). The review found that the rows above
for 2.8.2 with and without compression came from different times (04:26 and 04:29) under 2.8.1's own writes, and
that in its own interleaved runs the order flipped from round to round, raw 2.8.2 being no faster per process than
2.8.1 on a quiet database. So the writes were measured again after the review's fixes, in rounds: three processes at
once, 100 of vex's units each (3.2 to 4.5 MB as they are), into a fresh scratch namespace, the configurations one
after the other within a round; vex's CI (2.8.1) committed the attestations a minute shown meanwhile (its change
log), in 8 MB requests. Seconds per process; nothing lost unless said:

| round (UTC) | vex's CI a minute | 2.8.2 | 2.8.2 zstd | a draft, zstd | 2.8.1 |
|---|---|---|---|---|---|
| 07:07-07:09 | 4-17 | 10.3, 16.4, 24.2 | 20.2, 20.2, 21.1 | 11.6, 11.4, 13.1 | 7.2, 5.1, 12.5 |
| 07:09-07:12 | 7-369 | 98.4, 34.5, 80.7 (2 out of time, sent again) | 8.2, 10.9, 9.8 | 5.3, 11.0, 10.9 | 28.0, 23.3, 18.7 |
| 07:12-07:17 | 4-909 | 16.3, 15.2, 17.7 | 95.4, 95.6, 104.9 (1 out of time in each) | 42.5, 62.4, 68.6 | 10.3; 30.0 and 30.0, each losing its 100 |

and, against a draft without the pause between transactions (raw both):

| round (UTC) | vex's CI a minute | 2.8.2 | a draft | one-row writes every 0.5 s beside 2.8.2 / the draft |
|---|---|---|---|---|
| 07:18-07:21 | 2-2,073 | 61.5 s each, every unit reported lost (2 out of time in each, the minute of retries spent; 80 committed after the client gave up) | the same (82 committed) | none in time / 19.1 s for the first |
| 07:21-07:24 | 2,027-2,073 | 127.8, 128.4, 132.4 (2 out of time in each, sent again) | 14.5, 13.1, 21.0 | 0.8-46.9 s / 0.7-5.8 s |
| 07:24-07:26 | 784-847 | 12.4, 16.1, 14.5 | 114.6, 115.0, 113.7 (1 out of time in each) | 0.7-3.5 s / 0.7-44.9 s |

What these show: at 100 units a process, the time a write takes is the database's load, not the version's encoding or
pause; compressed and raw trade places from round to round, so at that size compression buys a smaller database, not
faster writes (at 800 units it does write faster: the Rails-sized rounds below). On a quiet database
2.8.2 here wrote slower per process than 2.8.1 (10 to 24 s against 5 to 13 s), and in the review's rounds at 08:03
to 08:13 UTC (three processes of 150 units, 4.8 to 7.2 MB) raw 2.8.2 (`7a973b5`) took 84.5 to 88.3 s and then 15.6
to 30.9 s, 2.8.1 23.3 to 35.4 s (one process losing its 150 units): its gain is the units it no longer loses
(2.8.1 lost 200 of 300 in the third round), and the time it spends on writes that succeed was not bounded (it is
now: above, and the Rails-sized rounds below). When the whole database stalls (every transaction of every process
out of time at the same 30.7 s, a one-row write beside them waiting 19 to 47 s), 2.8.2 gives up within its minute of
retries as 2.8.1 gives up at once, and its timed-out transactions may still commit (reported lost, then stored, which
costs a test run, never a wrong skip). Applied twice: the drafts sent at least 7 transactions again and the server
applied 130 of their units twice (41 and 89, in two rounds); 2.8.2 sent at least 15 again and applied none twice
(the nonce, "Connection handling" above). Small writes 4 s into the writes (a manifest put outside a batch, then a
flag): beside 2.8.2 the manifest 0.5 to 24.7 s and the flag dropped at its deadline in 1 of 6 runs; beside the zstd
draft 1.1 to 17.5 s and 1 of 3; beside 2.8.1 4.1 to 30.3 s. The pause between transactions showed no effect this load
lets one see (it is gone since: above).

*Rails-sized writes* (the third write review's build, `c26638a`, 28 October 2026, 08:27 to 08:42 UTC; the fourth
review's rounds below correct what these led to). Three processes at once, 800 of
vex's units each (28.2 to 30.6 MB as they are, the size of a vex Rails job's), uncompressed, each configuration into
a fresh scratch namespace, in two rounds in opposite orders. vex's CI committed 1 to 2 attestations a minute until
08:37 and 659 to 683 after. Seconds each process spent on writes, nothing lost unless said:

| round (UTC) | vex's CI a minute | `c26638a` (no pause, sized from commit times, a short question, a flat bound in all) | `7a973b5` | 2.8.1 |
|---|---|---|---|---|
| 08:27-08:31 | 1-2 | 99.4, 104.0, 130.5 (longest transaction 5.9 to 13.5 s) | | 3 processes out of time at 30 s; 436 of 2,400 units stored (261, 175, 0) |
| 08:33-08:42 | 2, then 659-683 | 143.5, 143.7, 155.6 (longest 7.9 to 10.0 s) | 200.4, 217.2 (longest 20.2 and 21.6 s), and 310.5: two transactions out of time at 30.7 s, the minute of retries spent, latched, 449 of 800 stored | |

Small writes beside them: a manifest put 20 s into the writes took 1.7 and 2.4 s beside `c26638a`, 2.9 s beside
`7a973b5` and 11.3 s beside 2.8.1; the flag after it 2.0 and 1.1 s, 5.3 s (dropped at its deadline) and 13.7 s
(2.8.1 had no hint deadline); one-row writes every half second a median of 0.9 and 2.0 s (at most 12.4 and 7.8 s)
beside `c26638a`, 0.7 s (at most 33.7 s, one failed) beside `7a973b5`, and 10.0 s (at most 14.7 s) beside 2.8.1.
One round of each order cannot separate the build from the load (`7a973b5` ran while vex's CI was quiet and
`c26638a` while it wrote). These two rounds were the lucky end of what the same build does: the fourth review's
rounds, next, are not.

*Rails-sized writes, again* (the fourth write review, 28 October 2026, 08:52 to 09:28 UTC). The same tooling, units
and sizes (28.2 to 30.6 MB a process as they are, about 32% fewer bytes sent compressed), `c26638a` built in release,
each run into a fresh scratch namespace, a one-row write every 0.5 s and a manifest put and flag 20 s in beside them.
vex's CI's rate is its production change log's attestations a minute, which understates its load: a 2.8.1
transaction that fails never reaches the log, so a round that logged 2 a minute (r5 raw) was among the most
contended. Seconds of writes per process; units lost of 800; longest transaction:

| round (UTC) | vex's CI a minute | raw | zstd | one-row writes, median / most (raw; zstd) |
|---|---|---|---|---|
| r1, 08:52-08:57 | 2-14, no Rails job writing | 187.1, 189.4, 188.0; lost 0, 20, 200 to the bound; one transaction out of time (30.7 s) in each; 29-37 transactions | 58.5, 72.9, 63.9; lost 0; longest 6.4-7.5 s; 21-23 transactions | 1.1 / 30.3 s; 0.77 / 3.3 s |
| r2, 08:58-09:04 | 9-14, Rails jobs running | transactions out of time at 30.7 s, the minute of retries spent, latched: 600 of 2,400 stored | the first transaction in each fresh namespace (creating its tables) took 60.2 s and latched: nothing stored; a manifest put 82 s | 5.2 / 38 s; not recorded |
| r3, 09:04-09:12 | 9-31 (zstd), 438-928 (raw) | 205.1, 205.0, 204.8; lost 294, 410, 378 to the bound; longest 30.7 s | 190.9, 190.7, 191.4; lost 412, 401, 472 to the bound; longest 27 s | 1.6 / 46.5 s; 6.0 / 35.4 s |
| r4, 09:12-09:17 | 928-1,607 | every first transaction 60.2 s, latched: 0 of 2,400 stored | 143, 143 and 83 s, then latched: 441 of 2,400 stored | every one failed; 8.2 / 48 s |
| r5, 09:21-09:28 | 4-621 (zstd), 2 (raw) | 187.6, 187.5, 187.7; lost 678, 660, 690 to the bound | 155.2, 180.4, 161.2; lost 0; longest 30.7 s (one out of time in each) | 12.2 / 50.1 s; 1.08 / 45.3 s |

Raw was lossless in no round, and a flat bound of six timeouts cut it short in every round the server took writes
at all, a quiet one included; zstd was lossless in r1 and r5 (r5's slowest process at the bound's edge). Once the
bound was spent every later early write was lost at once (`0 transaction(s) … 130 attestation(s) not stored:
0.00s`). The manifest put 20 s in took 1.0 s (r1 zstd), 2.3 s (r1 raw), 11.2 and 13.2 s (r3) and 1.1 and 16.0 s (r5,
the flag 5.3 s beside raw). So at Rails size compression writes faster too: in r1 zstd took 58 to 73 s against raw's
187 to 189 s, about 2.5 to 3 times sooner, where at 100 units the two traded places; and one-row writes beside
three Rails-sized writers wait up to 30 to 50 s, not the 12.4 s of the third review's rounds. A transaction of 1 MB
took 15 to 26 s in raw runs without running out of time, not the 1.8 to 3.7 s measured alone. The 60.2 s first
transactions of r2 and r4 are the minute of retries spent on a namespace's first write under that load (section 21,
item 19). This is what changed the bound to grow with what a process stores (above).

With those fixes (the bound growing with what is stored, transactions halved only after one runs out of time, a
copy sent again sizing nothing), one more uncompressed round on 28 October at 09:39 to 09:42 UTC, the same three
processes of 800 units into a fresh scratch namespace, vex's CI logging 14 attestations a minute and then none:
151.5, 147.7 and 142.2 s of writes per process, nothing lost, no transaction out of time (34, 37 and 33
transactions; longest 9.6, 9.3 and 13.2 s); one-row writes beside them a median of 0.96 s and at most 9.9 s (5 of 70
over 5 s), the manifest put 3.2 s and the flag 1.9 s; on the server 2,400 attestations, 1,176 manifests and none
applied twice. Every process stayed under 180 s, so the round shows this build sound at Rails size on a quiet
database, not the larger bound at work; it was not repeated compressed or under load, to keep within the free
plan's rows written.


*Reads behind a 3 s wait* (the write review's fourth finding). On the local copy behind a proxy holding each answer
3 s, three interleaved runs each (07:06 to 07:11 UTC): 2.8.2's plan took 24.5, 24.5 and 25.5 s, its prefetch 9.1 to
10.1 s in 9 requests; the draft's 27.5 to 28.6 s, 12.2 to 13.2 s in 13; 2.8.1's 31.0 to 35.4 s, 12.3 to 12.6 s in 4.

### fetch, push, hints, operations

- `vci fetch`, `vci push`, `--remote` and `--rewrite-history` behave as on any store without an exchange (section 7).
- **Hints** (remote and replica): the memo and the flags are the namespace's tables on the server, as PostgreSQL's:
  every flag read once per handle, `passing_on` memoized per tree, `remember_passing` one request of the entries the
  server does not hold (with the 7-day memo prune, once per handle; none when nothing is new), `set_flag` nothing when
  the flag is set, each write a hint's (5 s, never sent again, never latching), every error swallowed, never creating
  the tables. Local: the file's tables.
- **Turso.** A database per organization or per repository; a full-access token for the trusted jobs that store
  (`vci ci --push` on protected branches, and developers whose `vci run` should store, through `[store]
  token_command`) and a read-only one for pull-request jobs and machines that only plan (`turso db tokens create <db>
  --read-only`): their writes are `Denied`, their plans read. A job that runs untrusted code gets the
  read-only one or none, since its tests can read the token (section 9, "What this cannot hide"). Backups are
  Turso's (point-in-time restore); `vci prune` keeps the tables small.
- **Monitoring.** `LibsqlStore::requests()` counts requests; the timing lines carry them.

### The temporary libSQL server for tests

`vci_store_libsql::testkit` (`#[doc(hidden)]`, always compiled) finds a server once per test process:
`VCI_TEST_LIBSQL_URL` (and `VCI_TEST_LIBSQL_TOKEN`) when set; else a throwaway `sqld` from `PATH` (Homebrew's `libsql`
formula, the release binaries) on a free port of 127.0.0.1, else `turso dev`, else the Docker image
`ghcr.io/tursodatabase/libsql-server:v0.24.32` when Docker is running, each retried on up to five ports. A watcher
process (`/bin/sh` in its own process group, ignoring INT and HUP, reading a pipe only the test process holds) stops
the server and deletes its directory when the test process ends, however it ends. Without a server the tests that need
one say `skipping: no libsql server: …`, or panic under `VCI_TEST_LIBSQL=require`. Tests keep apart by namespace
(`testkit::namespace()`). `testkit::selection` sets a connect timeout of 30 s, since it also bounds the server's first
answer and one test server serves a hundred concurrent tests (the tests of that bound set their own).
`start_sqld(args)` and `start_docker_with_env(env)` start servers of their own (the token test starts one that checks
JWTs), and `start_sqld_with_admin()` one with its admin API, whose database `set_config(admin, patch)` changes (the
tests of a server that takes no more writes block its writes and set its size limit there).

**Tests.** `tests/libsql.rs`: the local file is a SQLite store file; a plan's request budget (requests sent again
while another test's writer held the database, `LibsqlStore::retries()`, not counted); slots, bytewise order,
namespaces and a newer schema; orphans and the grace period; a closed port failing fast with neither token shown; a
keep-alive connection a proxy dropped while it sat idle (closed after the next request was read, or reset) sent
again on a new connection, a write and a read after the idle wait succeeding with `retries()` counting them (2.8.0
latched `connection closed before message completed`); a server gone while the connection sat idle latching at once
(the request sent again is refused) and every later call failing at once; a server that accepts and closes without
ever answering (at once, with a reset, or after a wait) latching at once on its one connection, not sent again; a
read whose rows a proxy cut off failing alone, not sent again, with the next write and read succeeding; an HTTP
status (a 502, a 401) whose body quotes a transport error answered once and latched as that status; a
server that never answers costing the connect timeout (remote, `vci prune`'s handle, and replicas for the plan and
for the store commands); an error page the client cannot read failing without a panic; bad URLs as `Config` errors
without their secrets; tokens (none, wrong, right in either place, read-only: its hints and writes `Denied`, its
reads going on) against a server that checks them, none of them shown; a replica syncing what changed, a replica's
first write, a replica of an unreachable server; a handle reading its own removals after other writers' changes
(remote and replica); a replica picking up other writers at its next prefetch; a replica whose write-through fails
reading its own write; a replica of a namespace dropped and made again; a replica's orphans answered as its
server's; a statement the server refuses latching nothing (remote and replica); a record too large for the server
refused alone; a replica that cannot be used refusing writes; a server that takes no more writes (blocked, full)
refusing them as `Denied`, an empty namespace's included, with reads going on (remote and replica); a replica's
`read_values` before a prefetch reading a key removed since it was listed as gone, and after one sending nothing; the
store commands failing on a replica they cannot keep (an unwritable directory, an empty namespace or not); and,
ignored outside release builds, 1,200 units of 18 KB. `src/conn.rs` checks that the connector's sockets close
without lingering, which errors mean a server takes no more writes, and which mean a connection lost under a request
(sent again) rather than one that could not be made, a read's rows cut off (not latched) or an answer of the server
whatever its body says (not sent again).
`tests/conformance.rs` runs the 34 scenarios in each mode (102 tests); the remote and replica ones need a server and
skip without one. Its worlds:

| | local | remote | replica |
|---|---|---|---|
| world | a temporary directory with one file | a namespace of its own | a namespace, and a directory of replica files |
| peers | handles on the file | handles (own pools and caches) | a replica file each: writes through one handle, every read through a new handle (which syncs) |
| `unreachable` + `secret` | a file that is not a database | a closed port with an `authToken` | none (a replica reads what it has; `tests/libsql.rs` checks it) |
| `read_only` | `chmod 0444` the file | none | none |
| `inject_raw`, `make_unreadable` | SQL on the file | SQL on the server (with a log row) | SQL on the server |
| `failing_batches` | none | a URL with a path the server does not serve (HTTP 404) | none |

The CLI tests (`crates/vci-cli/tests/store_backends.rs`) run run, plan, explain, supersession, prune, fetch, push and
`vci ci`'s gate in the three modes; a server on a closed port, remote and replica, failing open with neither token
reaching any output, log or test, and store info, fetch, push and prune exiting 2; a server that never answers,
remote and replica, within the connect timeout with the default timeouts; an error page the client cannot read; a
token under any query key, as a bare key, in the path, or under a misspelled `[store.libsql]` key, in no output; a
server that blocks writes (a `sqld` of the test's own, through its admin API), remote and replica, keeping the tests'
exit code while the plan reads on; and a shared input manifest the server refuses (a trigger) not relied on, every
unit reported attested skipping on the next plan. `crates/vci-cli/tests/store_select.rs` refuses a `file:` or
`sqlite:` URL holding a token in its query, printing it nowhere and making no file.

---

## 19. Notes for an HTTP or gRPC backend

The trait maps one-to-one onto a wire protocol. Every read has a batch form (`list_units`, `read_values`, `manifests`),
every write is idempotent, and `batch` is a bulk upload.

- **Endpoints.**
  - `POST /v1/list` (ids → keys and targets).
  - `POST /v1/values` (keys → values or per-key errors).
  - `POST /v1/manifests` (roots → values).
  - `POST /v1/bundle` (keys → their values, the manifests they reference and those manifests' bases). `choose` is a
    local closure and cannot travel, so `prefetch` lists (`/v1/list`), chooses locally, then asks for the bundle:
    two round trips, one fewer than PostgreSQL.
  - `PUT /v1/batch` (manifests, attestations and removals applied atomically in that order).
  - `DELETE /v1/manifests` (with the server applying the grace and reference checks).
  - `GET`/`PUT /v1/hints`.
  - `GET /v1/status` (schema or protocol version → `Incompatible`).
- **Kind, caps and exchange.** `kind` is `"http"` or `"grpc"`. `caps` is `shared_writes: true`. `exchange` is `None`.
- **Settings.** Non-secret settings go in `[store.options]` (`Selection::options`); the factory refuses the ones it
  does not know.
- **Authentication.** The token travels in `VCI_STORE_URL` as userinfo, or in a new `VCI_STORE_TOKEN` added to
  `NEVER_TO_CHILDREN`. A GitHub Actions OIDC token is a natural fit: the server can map the token's repository claim
  to a namespace, which removes the shallow-clone and fork questions of `repo_id`.
- **Rules carried over.** A server-side namespace per repository, bytewise ordering, the circuit breaker, timeouts,
  secret scrubbing and the error variants of section 10 all apply unchanged. A crate `vci-store-http` registers an
  `HttpFactory` in `store::factories`, and nothing in vci-store changes.
- **Public read endpoints.** Fork pull requests get no secrets. A public, read-only endpoint (values are signed and
  verified anyway) would let them skip instead of running everything.

---

## 20. Decisions and why

1. **Consumer-first trait.** Every method exists for a vci-cli call site; the "Used by" lines in the rustdoc name it.
   Ten required methods, sensible defaults, and git-only sync behind an optional `Exchange`, so a server backend never
   pretends to push.
2. **No Reader trait, pools inside backends.** Snapshot isolation is not needed. Pooling keeps `Send + Sync` one
   object and removed the reader slots from ManifestLoader.
3. **Keys and targets are identical everywhere.** They are public output and memo identity.
4. **Keyed write input (`NewAttestation`).** `put` takes target plus test key, not the test id, so a copy between
   stores and migrations can re-put records known only by key. `put_for_test` keeps run.rs simple.
5. **`ValueState` is derived, not stored.** No new field to keep in step, and no struct literal breaks. The plan
   tracks its own deferrals (`SetAside`).
6. **Deferred batches report after `finish`.** Output never claims a unit that was not stored. Since 2.8 git-meta and
   SQLite use deferred batches too (one transaction per project); every line of the loop is held, so their output
   keeps its lines and their order.
7. **Secrets only in `VCI_STORE_URL`, removed from vci's own environment at start-up.** `VCI_*` reaches tests.
8. **Working-tree selection, environment-only credentials, connection keys refused in `vci.toml`.** See section 9.
   Since `[store] token_command`, `vci.toml` may name the server (`[store] url`, without a credential) and how to
   fetch its credential, still never the credential, and a credential from the environment goes only to a URL from
   the environment.
9. **A factory registry.** A new backend is a crate plus one line, with no enum in vci-store to edit. `for_repo`
   memoizes one handle per repository per process.
10. **Bounded time plus a circuit breaker on network backends.** Fail open quickly, not slowly.
11. **The `hydrate_more` fix shipped as its own commit** (it changes git-meta behaviour too), with a regression test
    that fails on the previous binary.
12. **The publication gate on shared stores.** `vci ci` without `--push` neither stores nor supersedes.
13. **No foreign keys in PostgreSQL; a grace period plus NOT EXISTS instead.** Same safety, git-meta-compatible
    strictness.
14. **"The store cannot be used" keeps `vci run`'s exit code; a backend's own error does not.** The variants that say
    the store is unreachable, unset, too new or refuses this writer are the operator's business, and the tests passed;
    git-meta's errors kept 2.7's exit 2, so its behaviour did not change.
15. **`vci store copy` (later).**
    - It copies manifests first (bases before the manifests on them), then attestations, keeping keys and targets byte
      for byte. Values are decoded the way `read_values` decodes them.
    - Two keys of one slot (possible in git-meta after a merge, impossible under SQL `UNIQUE`) collapse to the newest
      `issued`, and the collapsed keys are reported.
    - Attestations whose manifest is missing are copied anyway; they simply never verify.
    - It is idempotent and has `--dry-run`. Its source location comes from `VCI_STORE_FROM_URL`, which joins
      `NEVER_TO_CHILDREN`.
16. **libSQL without libSQL's engine.** libsql's local engine cannot share a process with rusqlite's bundled SQLite,
    which git-meta needs (section 18, "Crate"), so vci uses libsql's Hrana client only: the local mode is the SQLite
    store's file under another name, and the replica is a SQLite store file that vci syncs itself from a change log on
    the server. The cost is a log table per namespace and a sync written in vci; the gain is one SQLite in the binary,
    one file format for every local store, and a replica that reads with the SQLite store's code.
17. **A libSQL namespace is a set of tables.** A libSQL database is one SQLite database; the SQLite store's schema
    under a prefix per namespace keeps every statement of `vci_store_sqlite::sql` usable unchanged on the server
    (one copy of the SQL), where a namespace column would have needed a second copy of every statement.
18. **A credential from a command, fetched lazily, once.** Developers and agents should not have to export a secret,
    and a secret written into `vci.toml` would be public, so `vci.toml` says how to fetch it (`[store]
    token_command`, section 9), the way git's credential helpers and Docker's `credsStore` do. It runs at the first
    connection, never at selection, so commands that never read the store cost nothing and audit nothing (`com
    secrets get` logs every read); once per process, so a plan's pool of connections costs one read; kept in memory
    only, so nothing new sits on disk. An array runs without a shell (no quoting to get wrong); a string runs with
    `sh -c` for pipelines. In CI the environment's secrets win and the command never runs; the trust rule keeps a
    pull request's `[store] url` from receiving them. One timeout, 60 s or the connect timeout when longer, with no
    setting of its own: a helper waiting for a human (1Password's unlock) gets time, a stuck one cannot hold a plan
    for long.
19. **Nothing the token command printed is shown, its standard error included.** A scrubber removes only what it can
    recognise, and standard error can hold the credential in a frame standard output never showed (a `jq` stage echoing
    its input, a wrapper's log line, a passphrase cut at its spaces): three reviews of the scrubbed excerpt each found
    one more. A failure says what happened and names the command, which `vci.toml` gives and is not secret, and since
    2.8.1 says to run it with its standard output discarded (`> /dev/null`) to see why, so the credential of a command
    that works is not printed into the terminal (2.8.0 said only to run it). Only standard output is discarded: a
    wrapper or a pipeline stage can still log the credential on standard error, so the docs say to run it in one's own
    terminal and the agent skill tells agents never to run it. Since 2.8.1 the command is shown quoted for a shell:
    2.8.0 left `&`, `;`, `|` and globs bare, so a URL argument with `&` pasted with `> /dev/null` ran in the background
    with its standard output on the terminal. Standard error is still read, and dropped, so the command never blocks on
    a full pipe.
20. **The store's secrets stay out of every environment vci builds, and vci says it cannot do more.** The environment
    a process started with stays readable to its user's other processes, vci's and the CI step shell's alike, and a
    clean re-exec of vci would leave the shell's. The defence is the credential's scope: a job that runs untrusted
    code holds a read-only credential or none (section 9, "What this cannot hide").

---

## 21. Decided questions, and what is still open

Decided on 25 October 2026, before the work was built:

1. **Publication gate scope.** As in section 7: on a store with `shared_writes`, `vci ci` without `--push` signs but
   stores nothing and supersedes nothing, and says so once; plain `vci run` stores.
2. **Default namespace.** The repository id (the root commit), overridable with `VCI_STORE_NAMESPACE`. In a shallow
   clone with no root commit, PostgreSQL requires an explicit namespace (the plan fails open naming
   `VCI_STORE_NAMESPACE`). No row-level security in v1; one schema per server deployment, documented.
3. **Memo and flags on PostgreSQL.** Shared server-side tables, as designed. A global `natives` flag is acceptable.
4. **Selection source.** The working tree's `vci.toml`, for the backend kind only; addresses, credentials and every
   connection key are refused there. The environment wins over the file. A pull request can pick a kind, never an
   address.
5. **Rollout.** One release, 2.8.0: `[store]` acceptance and the backends ship together, git-meta stays the default
   with byte-identical output.
6. **PostgreSQL in the release binaries.** Yes: vci-cli's default features are `["sqlite", "postgres"]` with the
   rustls `ring` provider. The musl binary size with and without `postgres` is recorded in section 17.
7. **The `hydrate_more` fix** ships with the trait work, in 2.8.0, as its own commit (section 5).
8. **Manifest grace.** 1 hour; `remove_manifests` keeps a root put less than an hour ago unless grace 0 is requested
   (prune).
9. **`NOT_FETCHED` wording** stays byte-identical.
10. **git-meta's lock wait during plan-time prefetch** is out of scope and unchanged (tracked separately as speed
    work).
11. **PostgreSQL transfer per plan.** Keep the per-handle cache; the statement-count gates are the bound. The bytes
    were measured (section 17).
12. **SQLite exchange.** None in v1: `vci fetch` and `vci push` print the section 7 "local" messages and exit 0;
    `--remote` and `--rewrite-history` exit 2.
13. **Dependency pins.** Exact pins published at least two weeks before 25 October 2026, `ring` only (section 17).

Decided while building it:

14. **How `vci prune` asks a shared store for grace 0.** `OpenContext::long_running` (true for `vci prune`) means grace
    0 and a statement timeout of at least 600 s on PostgreSQL. No trait change.
15. **The cost of PostgreSQL in the release binaries** (decision 6) is recorded in section 17: about 2.8 MiB of a
    17.5 MiB static x86_64 musl binary.
16. **The default namespace in a shallow clone** is refused by the PostgreSQL backend itself (section 17), because
    `Repo::repo_id()` returns the shallow boundary there instead of failing.
17. **`VCI_STORE` is in no test's environment either.** It is in `NEVER_TO_CHILDREN` with `VCI_STORE_URL`, so a
    connection string put there by mistake is in no environment vci builds for a child (section 9 says what a test
    that goes looking can still read); and a value that is not shaped like a backend name is
    refused without being quoted back.
18. **A PostgreSQL connection is bounded as a whole.** The client library bounds only the TCP connect; a peer that
    accepts and never answers (a frozen or failing-over server, a stuck proxy, another service on the port) would hold
    the TLS request and startup exchange forever. vci connects on a thread of its own and gives up after the connect
    timeout (per host named), which latches the breaker. With several hosts each is tried in turn within its share of
    that deadline, so one that hangs does not keep a working one from being reached (section 17).
19. **A password holding an unencoded `@` leaves no piece behind.** `select::redact` masks up to the last `@`, the
    PostgreSQL store never prints a host or database the client library parsed from a URL with userinfo, and
    `Secret::scrub` removes every reading of such a password (section 9). The client library still connects such a
    URL to the wrong host: percent-encode the `@` as `%40`.
20. **libsql 0.10.0 is pinned twelve days after it was published** (13 October 2026), short of decision 13's two weeks:
    it is the version the libSQL store was specified against.
21. **`https://` selects no backend.** A Turso URL is `libsql://`; an `https://` or `http://` `VCI_STORE_URL` (a
    `sqld` without TLS, a proxy) needs `VCI_STORE=libsql` or `[store] backend = "libsql"`, so a URL meant for some
    other service never sends its token to a libSQL client by accident.
22. **A replica whose server is down is read as it is by the commands that use the store, not by those about it.** The
    plan, `vci explain`, `vci run`, `vci ci` and `vci verify` read the replica with a warning; writes fail at once and
    `vci run` refuses each unit with the tests' exit code. `vci store info`, `vci fetch`, `vci push` and `vci prune`
    exit 2, as on every other store that cannot be reached (section 10).
23. **A server's record limit is the store's.** `sqld` refuses a row of 5,000,000 bytes or more; the libSQL store
    refuses such a record itself, as `Unsupported` for that unit alone, rather than splitting values across rows
    (section 18). A unit whose input manifest is that large is never attested on a libSQL server.
24. **A libSQL server's statement refusals are `Backend`, its HTTP errors `Unavailable`.** Only failures to reach or
    use the server latch the breaker (section 18).
25. **A server that takes no more writes is `Denied`, not `Backend`.** A database over its quota (`sqld`'s write block,
    `Operation was blocked`) or at its size limit (`database or disk is full`) still reads; its refused write keeps
    `vci run`'s exit code the tests' (each unit refused with the reason), latches nothing, and the plan reads on
    (section 18).
26. **A shared base manifest the store refuses is not relied on.** `vci run` encodes that group's units' manifests
    whole instead, so each is stored, or refused with its unit, on its own; no unit is reported attested on a base that
    was not stored (section 4, `put_manifest`). Its cost is the base's bytes once per unit in that run, only when the
    base could not be stored.
27. **A libSQL replica's file is a snapshot taken at its sync.** Before its caller's first prefetch, `read_values`
    syncs first, so a key removed since it was listed reads as gone; the other reads before a prefetch use the
    opening sync's snapshot, which may only make a unit run (section 18, "Reads before a prefetch").
28. **Every libSQL write takes the write lock first.** A batch is `BEGIN IMMEDIATE`, its statements and `COMMIT`
    (section 18, "Writes"), so no batch promotes a read to the write lock, which fails under concurrent writers and
    can abort `sqld` 0.24 (item 17 below); before, a namespace's first batch began by creating `vci_schema`, which
    only reads once it exists. It does not prevent `sqld`'s stalled write lock (item 17), which a stress test brought
    on whatever the transaction began with.
29. **`vci prune`'s push hint is printed only on a store with an exchange** (2.9.0; the second half of what open
    item 1 asked, as the whole-branch review found it firing after an object removal on libSQL): `exchange()` is
    `Some` on git-meta alone, and SQLite, PostgreSQL and libSQL removed their rows at once, so their `vci push` has
    nothing to do. The counts prune prints are still the first half of item 1.
30. **Supersession reads every record of a unit while the store holds an input manifest** (2.9.0, the whole-branch
    review): a 2.8 upsert sets a slot's key and value alone, so a format-1 value written at commit D can sit beside
    a frame's columns saying commit C; the pre-filter by commit and platform would then leave a record of D unread at
    a run on C (a revert), a missed deletion, never a wrong one. `last_durations` asks `manifest_roots` once a run on
    a store with columns and `old_records_to_read` pre-filters only when it came back empty, as `prune_by_columns`
    already keyed on it.

Still open:

1. **`vci prune`'s counts on a store that keeps roots.** Prune removes one manifest root per call and prints
   `removed project vci:manifest:<root> (unreferenced manifest)` whatever `remove_manifests` returns (and `removed
   <target> <key>` whatever `remove` returns). That is exact for git-meta and SQLite; PostgreSQL (grace 0 under
   prune) still keeps a root that became referenced or a base meanwhile and returns 0 for it. Print from the returned
   count (a vci-cli change). The push hint half of this item is decision 29.
1a. **libSQL's `vci store upgrade --finish` lands in 2.10.** The statements of the libSQL store that name `manifests`
   and the change log (the batch's superseded-manifest collection, the replica's sync of the old log, the status
   read's `EXISTS (SELECT 1 FROM manifests)`, prune's manifest reads) each need a version-2 branch before the drop
   can be sent, so 2.9.0 refuses `--finish` at zero on libSQL (gate 4 above; STORE-V2 section 5 step 4) and a Turso
   namespace keeps schema version 1 for the whole release, with the consequences gate 4 lists: no `too new` guard
   against a 2.8 writer, and a re-opened window per 2.8 write. 2.10 adds the branches, the drop of `manifests` and
   the `log`, and `vci_schema.version = 2`.
2. **PostgreSQL re-reads values in round 2.** `read_values` moves values out of the per-handle cache, so a round-2
   `prefetch(Units{choose: None})` fetches them again: a third of a plan's bytes when every unit runs (section 17).
   Keep values handed out in the cache (memory), or let prefetch skip keys this handle already returned.
3. **A PostgreSQL server that stops answering mid-session.** Connecting is bounded (decision 18), but a statement on
   an open connection is bounded by the server's `statement_timeout` and by TCP: a server frozen after the connection
   was made (its kernel still acknowledging) blocks that statement. (`VCI_STORE` in `NEVER_TO_CHILDREN`, once item 3,
   is decision 17.)
4. **Measurements on a large repository.** The supersession and plan timings and PostgreSQL's bytes per plan were
   taken on a synthetic 600-unit store; round 2's added read on a fully fetched vex store, and a vex-scale plan from
   PostgreSQL, have not been measured.
5. **The concrete git-meta API.** Keep `AttestStore` and `Reader` public long-term for the 62 tests and e2e helpers,
   or port the about 20 backend-neutral tests to the conformance suite and mark the concrete API `#[doc(hidden)]`?
6. **Output naming.** Keep `by.metaKey` and `by.target` forever, or add `by.store` and later rename `metaKey` to
   `storeKey` with an alias?
7. **Transfer volume.** A vex-scale plan from PostgreSQL reads about 4,100 envelopes of roughly 18 KB, about 75 MB.
   Is TOAST's compression enough, or should vci use zstd in the reserved `encoding` column, or a persistent local
   read-through cache keyed by key and digest?
8. **SQLite sharing.** Should SQLite later gain an exchange (merging another SQLite file or URL) so that parallel CI
   jobs that carry it in a cache do not lose each other's writes?
9. **Out-of-tree backends.** Is a compiled-in registry enough, or should a subprocess or wire protocol let backends
   live outside vci (section 19)?
10. **The demo-oidc job.** It reads `.git/git-meta.sqlite` from Python. Replace it with a `vci store export <key>`
    subcommand that works on every backend?
11. **Follow-ups.** `vci store init`, `vci store copy`, `vci init --store`, the action inputs `store` and `store-url`
    (exported as `VCI_STORE` and `VCI_STORE_URL`, masked; for stores without an exchange the action drops `--fetch`
    and `--remote`), and deleting `AttestStore::remove_for_signer`.
12. **`Repo::repo_id()` in a shallow clone.** It returns the commit where the clone was cut rather than failing; the
    PostgreSQL backend guards itself (decision 16), and other users of the repository id may need the same guard.
13. **SQLite details.** Whether the SQLite backend should turn syncing off when `CI` is set, as git-meta's store does
    since 2.7.27; and turning on rusqlite's `cache` feature in `vci-store-sqlite` so it can use `prepare_cached`
    (`hashlink` is already in `Cargo.lock` through git-meta-lib).
14. **libSQL on Turso's hosted service.** The store was tested against `sqld` 0.24.32 (the libsql-server image Turso
    publishes, locally and in CI), not against Turso itself: its limits on a request's or a response's size (a
    vex-scale plan reads about 75 MB; a batch request is sent once it holds 2,000 writes or 8 MiB of values, so at
    most 8 MiB plus one record), how a read-only token's write is refused (`sqld` answers HTTP 403, which vci maps to
    `Denied`), and HTTP/1.1 over TLS through vci's own connector are unchecked there.
    How Turso refuses a write over a quota was not observed either: vci recognizes `sqld`'s write block (`Operation
    was blocked`) and size limit (`database or disk is full`), which its hosted service runs on (decision 25); a
    refusal worded otherwise, with HTTP 200, would be `Backend` and make `vci run` exit 2.
    `sqld`'s own response limit (`--max-response-size`, 10 MB by default) refuses a large result of a plain execute
    request (`RESPONSE_TOO_LARGE`), but not the cursor requests vci reads with: a 22 MB read and a 12 MB sync went
    through. Its row limit (5,000,000 bytes, decision 23) is assumed for Turso too; a lower one is refused as
    `Unsupported` per batch. The vex pilot of 27 October 2026 (section 18, "Measured") ran against Turso itself:
    5,733 attestations went in through write requests of 8 MiB of values or more (a smaller last one per run) with
    none refused, and plans and replica syncs of up to 6,546 records read back, over vci's own connector. The
    read-only refusal and the quota answers stay unchecked there.
15. **A CA for a libSQL server.** TLS is verified against the webpki roots only; a self-hosted `sqld` with a private
    certificate needs a setting like PostgreSQL's `sslrootcert`.
16. **The libSQL change log.** Every write logs a row per slot and root it touched, kept 30 days; its size on a busy
    namespace, and whether a shorter retention (a full sync after it) is better, have not been measured. A replica on
    an ephemeral runner syncs everything every time; a cache of the replica file would make that a delta.
17. **The libSQL conformance suite on a loaded machine.** Its intermittent failures had a cause in the client: libsql
    0.10.0 drops each read's answer before the end of its HTTP body, so every read closed its connection, and each
    close held an ephemeral port in `TIME_WAIT` (30 s on macOS); a run opened about 5,900 connections (2,000 in the
    three seconds of one scenario, c32), and two runs close together, or a slow one on a loaded machine, ran out of
    macOS's 16,384 ports (`Can't assign requested address`), after which most scenarios failed: three runs back to
    back on 26 October, at a load average of 12 to 34, reached 16,344 sockets in `TIME_WAIT`, and the second failed 30
    of its 102 tests. The connector now closes its sockets with a reset (section 18, "Pool"): the same three runs
    passed, at most ten sockets in `TIME_WAIT`, in 10 to 11 s each. Still open, and in `sqld`, not in vci: **`sqld`
    0.24.32's write lock stalls for good under concurrent writers.** Every write then waits out its request timeout
    while reads go on, until the server restarts. Against a fresh `sqld` per run (26 October, `RUST_LOG=info`, load
    average 14 to 78 on 14 CPUs), the suite passed 10 of 15 runs; each failed run was this stall (a write sent after
    the run hung for its 20 s), its `sqld` alive. The suspected trigger, a batch that reads before it writes (libsql's
    transactional batch begins with a deferred `BEGIN`, and a namespace's first batch began by creating `vci_schema`,
    which only reads once it exists), is not it: with every batch taking the write lock first (decision 28) the suite
    passed 11 of 15, and with every batch writing first under the deferred `BEGIN` (tried, not kept) 6 of 15, the
    other runs stalling the same way. Run with `--use-custom-wal libsql-wal` (its newer WAL), `sqld` stalled in 3 runs
    of 3. On one `sqld`, its scenarios with the most concurrency each ran 25 times without a stall (c12, 14 writer
    threads on four handles; c32, 16 readers and a writer; c21, six first writes at once), and the replica half of the
    suite 15 times; the remote half stalled it at its eighth run (with the batches before decision 28 as with it), and
    the whole suite with four test threads at its ninth.
    A stress test of `sqld` alone (Python; one fresh server per case; writers sending vci-shaped batches of 50 rows of
    2 KB, `BEGIN IMMEDIATE` first, each request closing its stream; 40 s a case) stalled it in all 8 runs with four
    writers (after 1,016 to 12,425 commits), with eight and with 32, and with three when four readers held snapshots
    (after 5,618); never with one writer (21,612 commits) or two (three runs, up to 18,920 commits); with eight
    writers and four readers after 39 and 40 commits (the readers went on: 32,574 reads in one of those runs); with
    one 10-byte row a transaction, not with four writers or eight with readers (28,872 and 29,529 commits) but with
    32 (twice).
    Holding the lock for 2 s, or past `sqld`'s 5 s transaction timeout, while three or eight writers waited did not
    stall it, nor did its log compactions (96 with two writers; with them turned off, four writers still stalled).
    The transaction's first statement only moves the stall: with a deferred `BEGIN` and a write first (vci's batches
    before decision 28) in 1 of 4 runs with four writers, and in each run with eight (with readers) and 32; with a read
    first, whose waiting writers fail their promotion at once (about 50,000 `database is locked` a run) instead of
    queueing, in none of 4 runs with four writers, and in each with eight (with readers) and 32. With its newer WAL
    the same server took 21,183 commits from 32 writers and four readers without stalling, yet the suite stalled it,
    so what stalls that WAL is not known. What the source of `sqld` 0.24.32's default WAL path shows
    (`libsql-server/src/connection/connection_manager.rs`), which fits the measurements: writers take turns through
    one slot and a queue; `acquire()` queues the connection once per call, with a parker made for that call; it
    returns `SQLITE_BUSY` at the top of its loop when a WAL checkpoint holds the slot, and `SQLITE_BUSY_SNAPSHOT` when
    a `RESTART` or `TRUNCATE` checkpoint changed its sync token, without taking its entry off the queue; for a
    transaction that has not read yet, the busy handler (100 ms on `sqld`'s connections) calls `acquire()` again,
    which queues the connection again; `schedule_next()` hands the slot ("Notified") to the next entry without
    checking that its connection still waits; and a slot Notified to another connection is never taken back (its
    waiters park until its deadline and loop). An entry left behind by a request that has ended (vci's stream closes
    with the batch) thus holds the slot for good. A reviewer's debug log of a stalled server shows that state
    (`Slot { id: 536, …, state: Notified }`, every writer looping on `unparked after before_deadline?: false`); it was
    not traced event by event, since that module's debug log writes about 1.5 GB a minute once the server stalls. The
    same file can also abort `sqld` (`assertion left == right failed` in `release()`, a panic where it cannot unwind):
    `close()` checks that its connection holds the slot, then `release()` takes it, and in between a writer that waited
    15 ms on a slot in `Failure` handed it to the next one. A reviewer's run hit it after 216 failed promotions
    (`Cannot promote read transaction to write transaction`) of namespaces' first batches, each leaving the slot in
    `Failure` until its stream closed; with decision 28 a write whose snapshot went stale while it waited is retried
    inside the server within milliseconds instead. vci cannot prevent the stall from the client; meanwhile it fails
    open (each write is given up at the request timeout, which latches the store, and `vci run` keeps the tests' exit
    code). A `sqld` whose writes stop needs a restart; Turso's hosted service runs its own server, not measured. The
    suite still opens a connection per read (libsql's), and on a server that keeps its namespaces (an external one)
    its scenarios slow as the tables of earlier runs accumulate (four runs in a row took 10, 28, 42 and 50 s; 15 to
    18 s for the remote ones at 7,500 schema objects, against 2.5 to 4.8 s at a few hundred, in an earlier
    measurement).
18. **Compressed values travel as hex.** A libSQL write is SQL text (libsql's `execute_batch` takes no parameters),
    so a zstd frame, which is not UTF-8, is sent as a hex literal, twice its size: vex's values travel at about two
    thirds of their size compressed rather than a third. Parameters (base64 in Hrana's JSON, a third larger) would
    need one request per statement with libsql 0.10.0's API, or a Hrana client of vci's own.
19. **Small writes beside a stream of short transactions.** On 28 October (section 18, "Measured") a flag set 4 s
    into a draft 2.8.2 `vci run`'s writes was dropped at its 5 s deadline in each of three runs, where beside 2.8.1,
    still sending its first 8 MB, it took 0.2 s; a one-row write every 1.2 s waited at most 16.9 s beside 2.8.2 and
    up to 56 s beside 2.8.1. A draft paused between a write's transactions; in interleaved rounds that morning a
    manifest put beside three such writers still took up to 24.7 s and one-row writes up to 46.9 s, as beside a
    draft without the pause, while vex's CI's 8 MB requests set the pace, so the pause is gone. Beside three
    Rails-sized 2.8.2 writers one-row writes took a median of 0.8 to 12.2 s and at most 30 to 50 s in the fourth
    write review's rounds (the third's two rounds had shown at most 12.4 s), and a manifest put up to 16 s; under
    vex's Rails jobs a fresh namespace's first write (which creates its tables) spent the minute of retries at
    60.2 s and latched, in two rounds of five. Making transactions smaller under contention did not help (it made
    more of them, each waiting again: section 18, "Writes"). How small writes fare once every job of a database
    runs 2.8.2, and whether hints, single manifest puts and a namespace's first write need a path of their own, is
    not known.
