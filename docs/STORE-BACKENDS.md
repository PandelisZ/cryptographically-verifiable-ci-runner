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
  explain and push in one clone; fetch, plan, prune and verify in a second) and on every end-to-end suite.
- **The SQLite backend** (`vci-store-sqlite`, section 16): one file in the git common directory, selected with
  `VCI_STORE=sqlite`.
- **The PostgreSQL backend** (`vci-store-postgres`, section 17): a shared server, selected with a `postgres://`
  `VCI_STORE_URL`.
- **The libSQL backend** (`vci-store-libsql`, section 18): a local file (`VCI_STORE=libsql`), a libSQL server such as
  Turso (a `libsql://` `VCI_STORE_URL`, its token in `VCI_STORE_TOKEN`), or a local replica of one
  (`VCI_STORE_SYNC=replica`). The three backends are in vci-cli's default features, so the release binaries carry
  them (section 17, "Crate"; section 18, "Crate").
- **The command line on the trait** (section 13): every command reaches the store through one
  `Arc<dyn AttestationStore>` per repository, selected from the environment and `[store]` (section 9). Deferred write
  batches are reported only once they finish (section 6), `vci ci` has the publication gate for shared stores
  (section 7), `vci store info` exists, and none of `VCI_STORE_URL`, `VCI_STORE_TOKEN` and `VCI_STORE` reaches a
  child process.
- **The plan reads the candidates it set aside** even when a round fetched nothing (section 5).
- **The conformance suite** (section 14): its 34 scenarios, run against git-meta, SQLite, PostgreSQL and libSQL (in
  each of its three modes) from each backend's `tests/conformance.rs`.
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
kinds of records live. git-meta is the default store: `.git/git-meta.sqlite`, mirrored into `refs/meta/main` trees
and exchanged with `vci fetch` and `vci push`. It is one implementation of the trait
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
   stores strings.
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
| prefetch | `prefetch(Prefetch)` | | no-op | plan, run, verify, prune |
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
- `Caps { shared_writes, lazy_values, keeps_hints }`, which is non-exhaustive: build it from `Caps::LOCAL` with the
  `with_*` methods.
- `StoreStatus`, `Prefetch` (non-exhaustive) and `WriteBatch` (with `BatchEnd`).
- `StoreError` (non-exhaustive).
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
  refs/meta/main)` (git-meta's, whatever `meta.namespace` is set to), `/repo/.git/vci-store.sqlite`,
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
6. **Manifest first.** The caller stores the referenced manifest before the attestation (run.rs does). A backend
   keeps that order visible, so no reader sees an attestation without its manifest. In a deferred batch, `finish`
   writes manifests first.

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

Starts background work that makes the first reads fast: git-meta reads `.git/git-meta.sqlite` through once on a
thread (`warm_in_background`); SQLite reads its file through once on a thread, into the page cache; PostgreSQL opens
its first connection and TLS session on a thread. It never blocks and never fails. The plan calls it first.

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
     them from the error text. One `read_values` reads the chosen ones.
2. **Round 2** (`hydrate_more`), for the units the first pass did not skip that have candidates. A unit whose
   memo-named candidate was read and failed on its inputs (an `entry:` difference) is left out: its inputs changed,
   and it runs (2.7.32).
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
- **git-meta** (2.8): the batch shares one git-meta session and one connection to git-meta's SQLite store, and its
  writes are one `BEGIN IMMEDIATE` transaction on that connection, begun by the first write and committed by
  `finish`; each write is a savepoint in it, so a write that fails leaves the others. Inside the batch vci writes
  git-meta's tables itself, with the statements git-meta-lib 0.1.13 (pinned exactly) runs for `set` of a string and
  for `remove`, keys checked with its `validate_key`; outside one, writes go through git-meta as before.
  `a_batch_stores_what_the_calls_store_one_by_one` (vci-git) compares the rows, log entries and deletion records
  either way. The written keys' log entries are stamped once the commit is done (`stamp_written`). A batch opened
  inside the batch joins it. Writes on the batch's thread read the batch's own writes (the slot's keys, whether a
  value is already there); other readers see none of them before `finish`, which the trait allows. Storing 1,200
  units was 4,800 commits on two connections (0.7 s) before.
- **SQLite** (2.8): the batch pins one pooled connection to the thread; the first write begins `BEGIN IMMEDIATE` on
  it, each write is a savepoint, and `finish` commits (a dropped batch commits too). Reads on that thread use the
  pinned connection inside the transaction, so they see the batch's writes; other connections see them after
  `finish`, and another writer waits for it (at most the busy timeout). When SQLite ends the transaction itself (an
  I/O error, a full disk) or the connection is lost, the batch is broken: later writes and `finish` fail.
- **PostgreSQL**:
  - `put`, `put_manifest` and `remove` are queued so that `finish` reaches the state the same calls made one by one
    would: per slot the last put (it replaces every stored key of its slot), whether a later removal took that put's
    own key away (the slot then ends empty), and the keys removed otherwise; per root the last manifest.
  - `finish` flushes them in **one transaction**: manifests (one UNNEST upsert), the removed keys (one `DELETE … =
    ANY`), the emptied slots (one `DELETE`, only when there are some), then attestations (one UNNEST upsert).
  - A large batch flushes early at 2,000 attestations and removals or 32 MiB (manifests count only toward the bytes),
    so 1,000 units with their manifests stay one transaction. Each flush is its own transaction, and a failed flush
    fails `finish`.
  - Inside a deferred batch, `put` returns the entry it will store. An unhinted put first looks up the slot's existing
    key (one read). `vci run` always passes a hint.

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

The in-memory `MemStore` in vci-cli's tests (`store::mem`) has deferred and failing batches; the unit tests
`a_deferred_batch_reports_in_order_once_it_finishes`, `a_failed_deferred_batch_refuses_every_unit_it_held` and
`an_immediate_batch_reports_each_unit_as_it_is_stored` (run.rs) hold the rule.

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
  The memo and flags then fail silently; they are hints.
- A later option, if the gate proves too coarse, is a **Staged** wrapper: a local SQLite outbox over a shared
  backend, read as an overlay and published by `vci push`. The trait allows it, but it is not in v1.

---

## 8. Hints: the memo and flags

`passing_on`, `remember_passing`, `flag` and `set_flag` are optional capabilities (`Caps::keeps_hints`).

- **Never fail.** Any problem (no store, a read-only file, an unreachable server, a role without INSERT) makes reads
  return empty or `false` and makes writes do nothing.
- **Bounded time.** Hints use the backend's normal timeouts, and the circuit breaker cuts them off.
- **Never trusted.** The memo only orders reads. Every candidate is still verified. Flags only start the Rails boot
  early.
- **Stored keys must match listings**, which is why key strings are identical across backends.
- **Retention.** `remember_passing` may forget entries older than 7 days.

Per backend:

- git-meta uses `vci_memo` and `vci_flags` in `.git/git-meta.sqlite`. A CI cache carries them, as in 2.7.
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
4. **`git-meta`**. With nothing configured, behaviour is exactly as in 2.7.

Empty variables count as unset. Every other setting comes from the environment, then `vci.toml`, then the default.
`vci store info` prints each setting with its source (`Sourced<T>`).

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
| `VCI_STORE_URL` | location: `postgres://user[:password]@host[:port]/db[?sslmode=…&sslrootcert=…]`, `sqlite:<path>` (absolute, or relative to the git common directory; no query), a libSQL server (`libsql://host[:port][/path][?authToken=…&tls=0]`, `https://…`, `http://…`) or file (`file:<path>`, no query). **A secret.** | none |
| `VCI_STORE_TOKEN` | a libSQL server's auth token (a Turso database token); wins over the URL's `authToken`. **A secret**, redacted whole | none |
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

- **Only `VCI_STORE_URL` carries a connection string, and only `VCI_STORE_TOKEN` a token apart from it.**
- `VCI_*` variables are built-in *ignore*: they reach every test process (`COMMON_IGNORE` in vci-adapter/src/lib.rs).
  Pull-request code runs in those tests, so vci-cli's `main` handles the URL specially. Its first statement is
  `unsafe { store::take_secrets() }`: it reads every name in `select::NEVER_TO_CHILDREN` (`VCI_STORE_URL`,
  `VCI_STORE_TOKEN`, and `VCI_STORE`, where a connection string may be put by mistake),
  keeps the values in a process-wide map of `Secret`s (a value that is not UTF-8 is kept lossily), and removes them
  from its own environment (`std::env::remove_var`, sound while the process has one thread). No test, adapter probe,
  hook or git command it starts can see the URL.
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

### `vci.toml`

```toml
[store]
backend = "postgres"          # "git-meta" (default) | "sqlite" | "postgres" | "libsql" | another registered backend
connect_timeout = "5s"        # overridden by VCI_STORE_CONNECT_TIMEOUT_SECS
timeout = "30s"               # one statement or request; overridden by VCI_STORE_TIMEOUT_SECS

[store.sqlite]
path = "vci-store.sqlite"     # relative to the git common directory, no `..`; absolute only via VCI_STORE_URL

[store.postgres]              # tuning only: never an address or a credential
schema = "vci"                # [a-z_][a-z0-9_]*, at most 63 bytes
namespace = "acme-monorepo"   # VCI_STORE_NAMESPACE overrides; default: the repository id
pool = 8                      # connections per vci process, 1..=64
manifest_grace = "1h"         # an unreferenced manifest put more recently is kept; at most 30 days

[store.libsql]                # never an address or a token
path = "vci-store.libsql"     # the local file or the replica, relative to the git common directory, no `..`
replica = true                # read a local replica of the VCI_STORE_URL server (VCI_STORE_SYNC=replica too)
namespace = "acme-monorepo"   # VCI_STORE_NAMESPACE overrides; default: the repository id

[store.options]               # non-secret strings for backends vci-store does not describe (HTTP, gRPC)
# region = "eu"
```

- Durations in `vci.toml` are `"500ms"`, `"5s"`, `"2m"`, `"1h"`, `"1d"` or a bare number of seconds. The environment
  variables take a number of seconds only.
- `url` (in `[store]`, `[store.postgres]` or `[store.libsql]`), `host`, `user`, `password` and `dbname` (in
  `[store.postgres]`) and `token` and `authToken` (in `[store.libsql]`) are **refused**. Every checkout, a pull request's included, carries `vci.toml`, so a password there would be public, and
  a host there would let a pull request send CI's credentials to a server it controls. The error names the keys and
  never their values: the refused keys deserialize into a value-less marker (`select::Refused`).
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
- It cannot redirect credentials, which only the environment carries.
- The working tree is available before base-ref resolution, which is when `--fetch` starts.
- Plan and run inside `vci ci` then agree on one store.

**Rollout rule.**

- vci builds older than 2.8.0 reject a `vci.toml` with `[store]` (deny_unknown_fields) and therefore run every test.
- `[store]` acceptance and the backends ship together, in 2.8.0. Introduce a backend with `VCI_STORE` and
  `VCI_STORE_URL` first; add `[store]` only once every runner and developer runs a vci that accepts it.
- The user docs say so next to the example.

### Validation (`StoreError::Config`) and warnings

Errors (each displayed as `attestation store: <message>`):

- connection keys in `vci.toml` (`store.url`, `store.postgres.url`, `.host`, `.user`, `.password`, `.dbname`,
  `store.libsql.url`, `.token`, `.auth_token`);
- a URL in `VCI_STORE`;
- a malformed backend name;
- an unknown backend (`unknown store backend "x" (from $VCI_STORE); this vci has: git-meta, sqlite, postgres,
  libsql`, from `vci_store::open`);
- a backend built out (`this vci was built without the postgres store (cargo feature `postgres`)`, from
  `MissingBackend`);
- `VCI_STORE` disagreeing with the scheme of `VCI_STORE_URL`;
- postgres without `VCI_STORE_URL` (the message adds that GitHub does not pass secrets to pull requests from forks);
- a `sqlite:` `VCI_STORE_URL` without a path, or whose path holds `://` (another scheme's URL, which may carry a
  password, is never printed as a path) or a query (`sqlite:x.db?authToken=…`: it would be taken whole as the file's
  name and printed as one; not printed);
- for libsql, a `VCI_STORE_URL` that is neither a server (`libsql://`, `https://`, `http://`) nor `file:<path>` (not
  printed), a `file:` URL with a query (as for `sqlite:`, not printed), and, when the store opens, a server URL with a
  user or password, a fragment or a query parameter other than `authToken` and `tls` (not printed, nor the
  parameter's name: a token may be either), or the remote modes without a URL;
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
    libsql: its `mode`, `path` or `replica`, whether a `token` is set and where, and its `namespace`),
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
  deadline, a pool checkout bounded by the connect timeout; a replica's sync is one request under the same bounds,
  and a failed one falls back to the replica as it is for the plan and the run, and fails `vci store info`, fetch,
  push and prune (section 18).
- git-meta: `VCI_LOCK_TIMEOUT_SECS`.

**Circuit breaker** (network backends). After the first `Unavailable` or `Timeout` of reaching the server, a network
backend latches it, and every later call of that handle returns `Unavailable` at once (PostgreSQL's handle is the
CLI's one per repository, so in practice per process). A store that is down costs one timeout per
command, not one per call (4,000 listings would otherwise each wait). Conformance scenario c16 checks that the first
failure takes at most the connect timeout plus 1 s and the next 40 calls take under 2 s.

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
- `envpolicy::build_child_env` drops `NEVER_TO_CHILDREN`; `metrics::write` takes the store kind.
- **e2e harnesses** remove `vci_store::select::ENV_VARS`: the scrub loops of e2e_cargo, e2e_go, e2e_pytest, e2e_rails
  and e2e_rspec chain them, the `env_remove` lists of e2e, e2e_chain and e2e_node_test too, and ad-hoc `vci` commands
  in e2e, e2e_cargo, e2e_go, e2e_node_test and e2e_keyless go through a `vci_cmd()` helper. `action_contract` clears
  the environment and `workflow_key` starts no vci, so they are unchanged. `tests/store_common` still uses vci-git's
  `AttestStore`.
- **`tests/store_select.rs`** (a copy of `fixtures/go-abcd`, skipped without `go`) checks selection end to end:
  nothing configured is git-meta and pushes `refs/meta/main`; an unknown store, postgres without a URL, a URL in
  `VCI_STORE` and a password in `vci.toml` all fail open (plan exits 0 and runs everything; fetch, push, prune and
  store info exit 2) without printing the secret; `VCI_STORE_URL` reaches no test; the environment overrides
  `vci.toml` with a warning.

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
  `backing_exists`, `unreachable` with `secret`, `read_only`, `inject_raw`, `make_unreadable`, `failing_batches`.
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

Backends keep their own tests for what is theirs:

- git-meta keeps its 62 store tests (`store`, `store_deletion_records`, `store_lazy`, `store_robustness`), unchanged,
  plus `store_trait.rs` for the trait implementation (section 15).
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
- `location` is `".git/git-meta.sqlite (exchanged on refs/meta/main)"`, whatever `meta.namespace` is set to.
- `caps` is `LOCAL.with_lazy_values(true).with_hints(true)`.
- `status` is `Reader::has_store` on a pooled reader, mapped to ``Absent{advice: "run `vci fetch`"}`` or
  `Ready{None}`.
- `count` is `Reader::count`.

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
| a future variant | `Hydration::default()` |

Every call then empties the reader pool.

**`orphan_manifests`**: `hydrate_manifest_referrers(roots)` gives the undecided roots (and empties the pool). Then
`AttestStore::list(None)`, skipping values still not fetched. On any other unreadable value or `ManifestRef::Unknown`
the answer is empty. Otherwise it returns the roots minus the referenced ones minus the undecided ones (section 4 on
how it differs from 2.7 for malformed envelopes).

**Other provided methods**:

- `warm` is `warm_in_background`.
- The hints use `vci_memo` and `vci_flags` (`AttestStore::passing_on`, `remember_passing`, `flag`, `set_flag`).
- `timing_report` gives the `put_manifest seconds: …` line, from `AttestStore::put_manifest_seconds()`.

**Exchange**:

- `exchange_point` is `"refs/meta/main"`.
- `remote_location(name)` is `remote_url(name)` passed through `select::redact`. On ordinary remote URLs that is the
  text 2.7's `redact_userinfo` gave. They differ when the authority ends at `?` rather than `/`, and when the path or
  query holds an `@` (`redact` masks up to the last `@`), and `redact` also masks `password=`, `sslpassword=` and
  `sslkey=` values in a query. `redact_userinfo` is still used for remotes the
  user typed, in warnings.
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

**Tests.** `crates/vci-git/tests/store_trait.rs` (11 tests) checks the implementation against `AttestStore` on lazy
worlds with hinted, unhinted, promised and missing-blob entries: listings match, `read_values` matches, `read_units` is
targeted and equal to the default, error mapping, the pool seeing a store created later and being refreshed after a
prefetch, `orphan_manifests` against a re-implementation of 2.7's logic, the batch (one transaction since 2.8), the timing line, `put`
keeping `put_hinted`'s keys, and the factory.

---

## 16. Backend: SQLite

`vci-store-sqlite` holds `SqliteFactory` (kind `sqlite`, registered under vci-cli's cargo feature `sqlite`, on by
default; `SqliteFactory::path(sel, cx)` says which file a selection names), `SqliteStore` (`open_path(path,
SqliteOptions)`, which opens nothing until the first call; `path()`, `options()`) and `SqliteOptions { busy_timeout,
sync_off, read_only }` (default 30 s, false, false). Its tests are `tests/sqlite.rs` (the design's fourteen cases
plus a read-only file beside a live WAL, readers racing a writer, a lock held past the busy timeout, an unwritable
directory and a copy between two files; 1,200 units of 18 KB listed and read in about 8 ms in a release build) and the
conformance suite.

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
- `PRAGMA application_id = 0x76636931` ('vci1') and `PRAGMA user_version = 1`.
- The schema's state (application id, user version, tables) is read in one read transaction: read as three
  statements, it raced a concurrent creator (c21 and the crate's test 10 caught it).
- A newer `user_version` with application id 'vci1' gives `Incompatible{found, supported: 1}`.
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

**Batch.** `WriteBatch::deferred` (2.8; immediate before): it pins one pooled connection to the thread (a
thread-local keyed by the handle), and its writes are one `BEGIN IMMEDIATE` transaction on it, with a savepoint per
write, committed by `finish` (section 6). `vci run` of 1,200 Go units on a heavily loaded machine wrote its 2,400
records in 4.8 s with a commit each, and in 0.9 s as one transaction.

**Other methods.**

- `prefetch` is the default (nothing to do).
- `warm` reads the file through once on a thread, into the page cache.
- Hints use the `memo` and `flags` tables; `remember_passing` upserts by `(tree16, test_key)` and deletes memo rows
  older than 7 days. Timestamps are unix seconds.
- `synchronous` is `OFF` only under `VCI_STORE_SYNC=off`, read once at open. Unlike git-meta's store (2.7.27), it does
  not turn syncing off when `CI` is set.
- `exchange` is `None`.
- `caps` is `LOCAL.with_hints(true)`.
- On drop of the last connection, the store runs `PRAGMA wal_checkpoint(TRUNCATE)` (best effort, 100 ms busy wait),
  so a CI cache of the file captures one consistent file without `-wal` and `-shm`. `store::close_all()` drops the
  store at the end of every command. (macOS's `/usr/bin/sqlite3` keeps the WAL files after reading such a file:
  tests that look for them must not use it.)
- Timing lines (section 12): `store: sqlite: list N unit(s)`, `store: sqlite: read N value(s)`, `store: sqlite: write
  N record(s)` per finished batch, and `timing_report()` with the handle's total writes.

**Uses.** Local development loops, single-runner CI with a cache, the reference implementation for new backends
(about 1,500 lines with its schema, reads and writes; no special cases), and a possible later outbox for shared
stores.

---

## 17. Backend: PostgreSQL

`vci-store-postgres` holds `PostgresFactory` (kind `postgres`, registered under vci-cli's cargo feature `postgres`, on
by default), `PgStore` (`open(&Selection, &OpenContext)`, which does no I/O; `Clone`, sharing one handle;
`statements()`, every statement sent including `BEGIN` and `COMMIT`; `schema()`; `namespace()`; doc-hidden
`__sleep_for_test` and `__connection_for_test` for its tests), `PgError` (the payload of `StoreError::Backend` for
unexpected errors, with `message()` and `code()`), and the testkit (section 14). The modules are `conn` (URL, TLS,
session settings, pool, circuit breaker, error classification and scrubbing), `schema`, `cache`, `read`, `write` and
`batch`. Its tests are `tests/pg.rs` (an unreachable server failing fast with no secret shown; a server that never
answers given up on in time; no piece of a password holding `@`, `/` or `?` in `location()`, `Debug` or an error;
URL handling; a first host that never answers not blocking a working second one; round trips and slot replacement; bytewise order, through an ICU linguistic collation when libc's is
bytewise; concurrent first writers creating the schema once; absent, not initialized and incompatible schemas; a
statement timeout latching the breaker; the plan's statement budget; reads after a prefetch seeing the handle's
writes; deferred batches; `remove_manifests` keeping referenced, base and recent roots; `orphan_manifests` with an
unknown reference; namespace isolation; a read-only role; `application_name`), unit tests in the modules and the
conformance suite. Two mutation checks showed the tests
catch real faults: dropping `COLLATE "C"` fails test 4, and not caching prefetched values fails test 8.

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

- `caps()` is `LOCAL.with_shared_writes(true).with_hints(true)`, so `vci ci` without `--push` signs only (section 7),
  and `exchange()` is `None` (`vci fetch`: `vci: the postgres store at <location> is shared: nothing to fetch (N
  attestations stored)`).
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

- **Source of the URL.** It comes only from `VCI_STORE_URL` (`Selection::url`, a `Secret`).
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

**Migrations.**

- The first write creates or upgrades the schema in one transaction, under `SELECT
  pg_advisory_xact_lock(hashtext('vci-store:' || <schema>))`. Concurrent `CREATE … IF NOT EXISTS` otherwise races on
  `pg_type`.
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
WITH up AS (
  INSERT INTO vci.attestations AS a
    (ns, key, test_key, signer, storage_key, target, issued, tree16, manifest_ref, ref_state, value)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
  ON CONFLICT (ns, test_key, signer, storage_key) DO UPDATE SET
    key = EXCLUDED.key, target = EXCLUDED.target, issued = EXCLUDED.issued, tree16 = EXCLUDED.tree16,
    manifest_ref = EXCLUDED.manifest_ref, ref_state = EXCLUDED.ref_state, encoding = 0, value = EXCLUDED.value,
    stored_at = now(), stored_by = session_user
  WHERE (a.key, a.value, a.encoding) IS DISTINCT FROM (EXCLUDED.key, EXCLUDED.value, EXCLUDED.encoding)
  RETURNING a.key)
SELECT key FROM up
UNION ALL
SELECT key FROM vci.attestations
WHERE ns = $1 AND test_key = $3 AND signer = $4 AND storage_key = $5 AND NOT EXISTS (SELECT 1 FROM up);
```

A conflict on `(ns, key)` implies the same slot. The unhinted variant keeps `key`, `issued` and `tree16` and compares
`(value, encoding)` only. Both read the kept key back in the same statement, so a put is one round trip (a second
only in a concurrent race); comparing `encoding` lets identical bytes repair a row this vci cannot read. Concurrent
first inserts of one key can collide on the primary key `(ns, key)`, which is not the arbiter, so a unique
violation is retried (up to three times).

**`put_manifest`** always refreshes `put_at` and reports a change. The CTE reads the snapshot before the upsert:

```sql
WITH old AS (SELECT value, encoding FROM vci.manifests WHERE ns=$1 AND root=$2)
INSERT INTO vci.manifests AS m (ns, root, base, value) VALUES ($1, $2, $3, $4)
ON CONFLICT (ns, root) DO UPDATE SET
  value = CASE WHEN m.value IS DISTINCT FROM EXCLUDED.value OR m.encoding <> 0 THEN EXCLUDED.value ELSE m.value END,
  base = EXCLUDED.base, encoding = 0, put_at = now()
RETURNING COALESCE((SELECT value FROM old) IS DISTINCT FROM $4 OR (SELECT encoding FROM old) <> 0, true) AS changed;
```

**`remove`**: `DELETE FROM vci.attestations WHERE ns=$1 AND key = ANY($2) RETURNING key`. It is immediate and
global, with no records.

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

- `INSERT … SELECT * FROM unnest($roots, $bases, $values) ON CONFLICT DO UPDATE …`;
- then `DELETE … = ANY` of the removed keys, and a `DELETE … USING unnest(...)` of the slots a removal emptied (a put
  whose own key was removed afterwards in the same batch);
- then the attestation upsert from unnest arrays, one row per slot, because `ON CONFLICT` cannot touch one row twice
  in one statement. Removals go first: a put queued after a removal in its slot replaces the slot anyway.

Measured: a 1,000-unit batch takes 5 statements (gate 6), the schema version check, `BEGIN` and `COMMIT` included,
instead of about 3,000 round trips. Inside a deferred batch:

- `put_manifest` returns `true` unless the batch already holds the same bytes;
- `remove` returns every entry asked for, deduplicated by key;
- an unhinted put looks up the slot's key: queued first; the plain key when the batch empties the slot or removes the
  stored key; else stored (one read), else the plain key;
- `remove_manifests` (not queued) keeps the roots the batch will write or reference (its attestations' manifests, its
  manifests and their bases), whatever the grace, because the server cannot see them yet;
- dropping the batch without `finish` also flushes it.

### fetch, push, hints, roles

- **`exchange` and `caps`.** `exchange()` is `None`. `caps` is `LOCAL.with_shared_writes(true).with_hints(true)`.
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
`requests()`, every HTTP request sent, and `retries()`, those sent again while the server was busy; doc-hidden
`__execute_for_test` and `__query_for_test`), `LibsqlError` (the payload of `StoreError::Backend` for unexpected
errors), `table_prefix(namespace)` and the testkit (below). The modules are `conn` (the URL and the token, the TLS
connector, the runtime, the pool, the circuit breaker, deadlines, error classification and scrubbing, the guard
against the client's panics, SQL literals), `remote` (the tables of a namespace, reads, prefetch, hints), `cache`,
`batch` and `replica`. One store, three modes, chosen from the selection (section 9):

| mode | selected by | reads | writes | `caps` |
|---|---|---|---|---|
| local | `VCI_STORE=libsql` with no `VCI_STORE_URL`, or `VCI_STORE_URL=file:<path>` | a file, `<git common dir>/vci-store.libsql` by default | the file | `LOCAL.with_hints(true)` |
| remote | a `libsql://` `VCI_STORE_URL` (or `https://`/`http://` with `VCI_STORE=libsql`) | the server, through a per-handle cache | the server, one request per batch | `with_shared_writes(true).with_hints(true)` |
| replica | remote, plus `VCI_STORE_SYNC=replica`, `VCI_STORE_REPLICA=<path>` or `[store.libsql] replica = true` | a local file synced from the server at its first use and at each later prefetch | the server, then written through to the file | as remote |

**Crate.** `vci-store-libsql` depends on `vci-store`, `vci-core`, `vci-store-sqlite` (the schema SQL and the file
format), `serde_json`, `libsql = { version = "=0.10.0", default-features = false, features = ["remote"] }` (the Hrana
client: HTTP, in Rust), and, for the connector it hands libsql, `hyper` 0.14 (`client`, `http1`, `tcp`; the version
libsql's connector trait is written against), `http` 0.2, `tower-service` 0.3, `tokio` (`rt`, `time`, `net`),
`tokio-rustls` 0.26 and the PostgreSQL store's pins `rustls = "=0.23.45"` (`ring`, `std`, `tls12`) and
`webpki-roots = "=1.0.9"`. One `rustls` resolves and `cargo tree -i aws-lc-rs` is empty. libsql 0.10.0 was published
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
libSQL's SQL parser (`libsql-sqlite3-parser`, with which `execute_transactional_batch` splits statements). Not
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
- **The log** names every slot and root a write touched (a put, a removal, a manifest), for replicas. Entries older
  than 30 days are deleted once per handle by its first write, which records the newest deleted `seq` in
  `vci_schema.log_floor`: a replica that last synced before it syncs everything.

### Connection handling

- **The URL** comes only from `VCI_STORE_URL`: `libsql://<host>[:<port>][/<path>]` is HTTPS (`?tls=0`: HTTP, as the
  Turso CLI writes a local server's URL), `https://` and `http://` are themselves. Its query may hold `authToken` and
  `tls`; any other parameter (`token=`, `jwt=`, a bare `?<token>`, an `authToken%3D…`), a user or password, or a
  fragment is a `Config` error that prints neither the URL nor the parameter's name.
- **The token** is `VCI_STORE_TOKEN`, else the URL's `authToken`, sent as `Authorization: Bearer`. Both are secrets
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
  `OpenContext::long_running`), and a pool checkout after the connect timeout. While the server answers that the
  database is locked, that it is out of connections (HTTP 429) or that it interrupted the statement, the request is
  tried again with growing pauses until its deadline (`Timeout{operation: "waiting for another writer"}` then). A
  server stream idle for more than 4 s is reset before use (servers expire idle streams after about 10 s), and a
  stream the server no longer knows is replaced once.
- **Circuit breaker.** Per handle, as PostgreSQL's (section 17): the first connection failure, HTTP 401, or 403 on a
  read (`the server asks for a token: set $VCI_STORE_TOKEN`, or `the server refused the token …`), 404 (`no libsql
  database there`), other HTTP error status (a 5xx, a proxy's page), answer the client cannot read, or deadline that
  ran out is latched, and every later call of the handle fails at once with `… (failed earlier in this process; not
  retried)`. Busy retries, `Denied`, `Unsupported` and `Backend` are not latched.
- **Statements the server refuses.** `sqld` reports a statement's error (a batch step's as a Hrana API error, a
  cursor step's as `error at step N`) with HTTP 200: the server works, so it is `Backend(LibsqlError)` (`<url>: the
  server refused a statement: …`), not latched; the transactional batch it was in was rolled back, and the stream is
  given up. A busy server (`database is locked`, HTTP 429, a connection it could not open in time, `Transaction timed
  out` when it gave up a transaction that waited for the lock, `interrupted` when it stopped a statement to let a
  writer in) is tried again within the request's deadline.
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
JSON array (`IN (SELECT value FROM json_each(?1))`), 5,000 to a request:

| method | on a cache miss |
|---|---|
| `list_units` | `SELECT test_key, key, target FROM <a> WHERE test_key IN (…) ORDER BY test_key, key` |
| `read_values` | the values of the keys and, in the same statement (`UNION ALL`), the manifests they reference and those manifests' bases, which go to the cache |
| `manifest`, `manifests` | `root = ?1`; `root IN (…)` |
| `read_units` | fully cached units from the cache (values kept); the rest in one statement with values |
| `list_all`, `count`, `manifest_roots`, `read_all` | one statement each, never cached |
| `orphan_manifests` | one statement: empty when a row's `ref_state` is 0, else the roots no row references |

**`prefetch(Units{ids, choose})` is two requests**: the listings of every unit (from the server even when cached, which
is where other writers' changes are picked up), then the values `choose` picks that are not cached, with their
manifests and bases. `prefetch(Manifests)` is one request for the roots not cached as stored, with their bases.
Hrana's batch could carry several statements in one HTTP request; one statement per read already does, so a plan of
1,200 units is the status, the flags, the memo, two prefetches of two requests and the descriptions of the statements
on each connection: `a_plan_costs_a_handful_of_requests` checks at most 8 requests for the status and a prefetch of
300 units, and none for the listings, the batch read and 300 manifest reads from 8 threads after it.

### Writes (remote and replica modes)

`batch()` is deferred, with PostgreSQL's queue (section 17, "Writes"): per slot the last put, the slots a removal
emptied, the removed keys, per root the last manifest, and `remove_manifests` keeping what the open batch will write
or reference. `finish` writes the queue as **one request**, `execute_transactional_batch` (Hrana runs the statements
between `BEGIN` and `COMMIT`, each conditioned on the previous one's success):

1. the manifests, one multi-row upsert (the value replaced only when it differs or is unreadable; `put_at` refreshed);
2. the removed keys (`DELETE … WHERE key IN (…)`) and the emptied slots;
3. the attestations, one multi-row upsert on the slot, replacing the key, the value and the columns derived from them
   when either changed;
4. the log rows of every slot and root touched, and once per handle the log's prune.

Values travel as SQL literals, since the transactional batch takes SQL text only: UTF-8 bytes without NUL as text cast
to a blob (`CAST('…' AS BLOB)`, the same bytes), anything else as hex. A queue of 2,000 writes or 8 MiB is written
early, in a request and transaction of its own (a failed early write fails `finish`). A write outside a batch is a
batch of one: `put` one request (an unhinted put first reads its slot's key), `put_manifest` two (it compares the
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

`a_plan_costs_a_handful_of_requests` writes 300 units (600 attestations and 300 manifests) in at most 6 requests; the
release-build test `many_units_are_listed_and_read_quickly` (1,200 units of 18 KB against a local `sqld`) wrote them
in 0.64 s and 8 requests (three transactions: the queue flushes at 8 MiB), and listed and read them on a new handle in
0.10 s and 4 requests.

### The replica mode

The replica is a SQLite store file (the local mode's format), by default `<git common dir>/vci-store.libsql`, else
`VCI_STORE_REPLICA` (absolute or relative to the git common directory) or `[store.libsql] path`. Beside it,
`<file>.sync` (JSON: `{"v": 1, "source": "<url> namespace <ns>", "seq": N, "mark": "<at>:<slot or root>", "epoch":
<created_at>}`) says which server and namespace it copies, up to which log entry, that entry's fingerprint (when it
was written and what it names) and when the namespace was created.

- **The sync**, the first time the store is read (`warm()` starts it on a thread at the start of a plan), and again
  at each later `prefetch` (the plan's later rounds, `vci run`'s before supersession: section 4's "the next prefetch
  of the same data must pick them up"): one request reads, in one snapshot, the namespace's schema version (a newer
  one is `Incompatible`), the log's high-water mark and floor, the fingerprints of the entry the file was synced to
  and of the last one, when the namespace was created, and every attestation and manifest the log names after `seq`.
  Everything is read when the file is new, copies another source, is older than the log floor, or when the log is not
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
syncs everything once, which is what a remote plan reads anyway, then reads locally.

### Measured

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
(section 21, open item 2). Not measured against Turso's hosted service, where every request crosses the internet:
a plan is then about a dozen round trips (the status, the flags, the memo, the prefetches, one read, the memo's
write, and the first description of each statement on each connection) plus the bytes (about 11 MB of values for
3,600 attestations here).

### fetch, push, hints, operations

- `vci fetch`, `vci push`, `--remote` and `--rewrite-history` behave as on any store without an exchange (section 7).
- **Hints** (remote and replica): the memo and the flags are the namespace's tables on the server, as PostgreSQL's:
  every flag read once per handle, `passing_on` memoized per tree, `remember_passing` one request (with the 7-day memo
  prune, once per handle), every error swallowed, never creating the tables. Local: the file's tables.
- **Turso.** A database per organization or per repository; a full-access token for the jobs that store (`vci ci
  --push` on protected branches) and a read-only one for pull requests and developers (`turso db tokens create <db>
  --read-only`): their writes are `Denied`, their plans read. Backups are Turso's (point-in-time restore); `vci
  prune` keeps the tables small.
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
without lingering and which errors mean a server takes no more writes.
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
17. **`VCI_STORE` never reaches a test either.** It is in `NEVER_TO_CHILDREN` with `VCI_STORE_URL`, so a connection
    string put there by mistake reaches no child process; and a value that is not shaped like a backend name is
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

Still open:

1. **`vci prune`'s messages on a store without an exchange or that keeps roots.** Prune removes one manifest root per
   call and prints `removed project vci:manifest:<root> (unreferenced manifest)` whatever `remove_manifests` returns
   (and `removed <target> <key>` whatever `remove` returns). That is exact for git-meta and SQLite; PostgreSQL (grace
   0 under prune) still keeps a root that became referenced or a base meanwhile and returns 0 for it. Prune also ends
   with ``run `vci push` to publish the deletions`` on every store, though only git-meta has anything to publish.
   Print from the returned count, and the hint only when `exchange()` is `Some` (a vci-cli change).
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
    vex-scale plan reads about 75 MB; a batch request is capped at 8 MiB of values), how a read-only token's write is
    refused (`sqld` answers HTTP 403, which vci maps to `Denied`), and HTTP/1.1 over TLS through vci's own connector are unchecked there.
    How Turso refuses a write over a quota was not observed either: vci recognizes `sqld`'s write block (`Operation
    was blocked`) and size limit (`database or disk is full`), which its hosted service runs on (decision 25); a
    refusal worded otherwise, with HTTP 200, would be `Backend` and make `vci run` exit 2.
    `sqld`'s own response limit (`--max-response-size`, 10 MB by default) refuses a large result of a plain execute
    request (`RESPONSE_TOO_LARGE`), but not the cursor requests vci reads with: a 22 MB read and a 12 MB sync went
    through. Its row limit (5,000,000 bytes, decision 23) is assumed for Turso too; a lower one is refused as
    `Unsupported` per batch.
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
    passed, at most ten sockets in `TIME_WAIT`, in 10 to 11 s each. Still open: a `sqld` 0.24.32 whose writes stall
    while reads go on. At a load average of 60 to 300 (14 CPUs), about one run in four had every write wait out its
    30 s request timeout (the store's first commit too), and after one port-exhausted run a reviewer's `sqld` kept
    answering reads while every write hung for 37 minutes; whether `sqld` stalls on the concurrent `CREATE TABLE`s of
    a hundred namespaces, on the load, or on what a run that ran out of ports left behind, is not known. Four runs in a
    row against one external `sqld` since left it writing. The suite still opens a connection per read (libsql's), and
    on a server that keeps its namespaces (an external one) its scenarios slow as the tables of earlier runs accumulate
    (those four runs took 10, 28, 42 and 50 s; 15 to 18 s for the remote ones at 7,500 schema objects, against 2.5 to
    4.8 s at a few hundred, in an earlier measurement).
