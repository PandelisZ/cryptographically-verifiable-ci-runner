//! The conformance scenarios, one per row of the table in
//! `docs/STORE-BACKENDS.md` section 14. Each builds its own world from the
//! factory it is given, checks one rule every backend keeps, and panics
//! naming what it found when the backend breaks the rule.
//!
//! * Scenarios branch only on [`Caps`](crate::Caps) and on whether
//!   [`AttestationStore::exchange`] is present. A store with an exchange
//!   shows its writes to another peer after [`World::sync`]; any other
//!   store at once.
//! * A store with lazy values ([`Caps::lazy_values`](crate::Caps)) is
//!   prefetched before its values are read, as the command line does.
//! * A [`World`] hook that returns `None` or `false` skips the part of a
//!   scenario that needs it, which says so on stderr.
//! * Time bounds: an unreachable store fails its first call within
//!   `FIRST_FAILURE` (worlds configure a connect timeout of 3 s or less),
//!   and 40 more calls take under `LATER_CALLS` together.
//!
//! The fixtures are [`fixtures`] plus `hex64` storage keys, DSSE-shaped
//! `envelope`s whose payload names a manifest, and input manifests built
//! from paths (`manifest_of`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use base64::Engine as _;

use vci_core::ObjectKind;

use super::StoreFactory;
use super::fixtures::{S1, S2, TREE_HEAD, UNIT_A, UNIT_B, UNIT_CARGO, UNIT_ROOT};
use crate::{
    AttestationStore, Columns, FailedStore, GONE, Hydration, KeyHint, ManifestRef, NewAttestation,
    NewObject, OBJECT_GRACE, ObjectRefs, Prefetch, PushMode, PushStatus, Record, StoreError,
    StoreStatus, StoredEnvelope, StoredObject, ValueState, decode_record, key,
};

/// A unit nothing is ever stored for.
const UNIT_NONE: &str = "src/none.test.ts";

/// How long an unreachable store may take to fail its first call: a
/// connect timeout of at most 3 s, plus 1 s.
pub const FIRST_FAILURE: Duration = Duration::from_secs(4);

/// How long 40 more calls to an unreachable store may take together.
pub const LATER_CALLS: Duration = Duration::from_secs(2);

// ---- fixtures and helpers ------------------------------------------------------

/// A 64-digit storage key (or root) made of one byte repeated, as in the
/// git-meta tests.
pub fn hex64(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

/// A DSSE-shaped envelope whose base64 payload's `predicate.manifestRef` is
/// `manifest_ref` (`null` when `None`), padded with `pad`, as in the
/// git-meta tests.
pub fn envelope(manifest_ref: Option<&str>, pad: &str) -> Vec<u8> {
    let payload = serde_json::json!({
        "predicate": {"manifestRef": manifest_ref},
        "pad": pad,
    });
    serde_json::json!({
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64::engine::general_purpose::STANDARD.encode(payload.to_string()),
        "signatures": [],
    })
    .to_string()
    .into_bytes()
}

/// An input manifest listing these paths as files.
pub fn manifest_of(paths: &[&str]) -> vci_core::InputManifest {
    vci_core::InputManifest {
        entries: paths
            .iter()
            .map(|p| vci_core::manifest::InputEntry {
                path: vci_core::RepoPath::try_from(*p).expect("a repository path"),
                kind: vci_core::manifest::EntryKind::File,
                exec: false,
                size: p.len() as u64,
                hash: vci_core::blake3_hex(p.as_bytes()),
            })
            .collect(),
        externals: vec![],
        env: vec![],
    }
}

/// Exactly `len` bytes of UTF-8 text with tabs, newlines and a two-byte
/// character, starting with `tag`.
fn text_value(tag: &str, len: usize) -> Vec<u8> {
    let line = format!("{tag}\tvalue\twith tabs, a newline and \u{e9}\n");
    let mut out = String::with_capacity(len);
    while out.len() + line.len() <= len {
        out.push_str(&line);
    }
    while out.len() < len {
        out.push('x');
    }
    out.into_bytes()
}

fn hint(issued: i64, tree: Option<&str>) -> KeyHint {
    KeyHint {
        issued,
        tree: tree.map(str::to_owned),
    }
}

/// Say on stderr which part of `scenario` this backend skips, and why.
fn skip(f: &dyn StoreFactory, scenario: &str, why: &str) {
    eprintln!("{scenario} ({}): skipping {why}", f.name());
}

/// `r`'s value, or a panic naming `what` and the error.
fn ok<T>(r: Result<T, StoreError>, what: &str) -> T {
    r.unwrap_or_else(|e| panic!("{what}: {e} ({e:?})"))
}

fn put(
    s: &dyn AttestationStore,
    unit: &str,
    signer: &str,
    storage_key: &str,
    h: Option<&KeyHint>,
    bytes: &[u8],
) -> StoredEnvelope {
    ok(
        s.put_for_test(unit, signer, storage_key, h, bytes),
        &format!("put {unit} {signer} {storage_key}"),
    )
}

fn put_manifest(s: &dyn AttestationStore, m: &vci_core::InputManifest) -> String {
    let root = m.root();
    ok(
        s.put_manifest(&root, m.to_compact().as_bytes()),
        &format!("put_manifest {root}"),
    );
    root
}

/// One unit's key-only listing.
fn listed(s: &dyn AttestationStore, unit: &str) -> Vec<StoredEnvelope> {
    ok(s.list_units(&[unit]), &format!("list_units {unit}"))
        .pop()
        .expect("one list per unit")
}

/// These units with their values read; a lazy store is prefetched first.
fn read(s: &dyn AttestationStore, units: &[&str]) -> Vec<Vec<StoredEnvelope>> {
    if s.caps().lazy_values {
        ok(
            s.prefetch(Prefetch::Units {
                test_ids: units,
                choose: None,
            }),
            "prefetch",
        );
    }
    ok(s.read_units(units), "read_units")
}

fn read_one(s: &dyn AttestationStore, unit: &str) -> Vec<StoredEnvelope> {
    read(s, &[unit]).pop().expect("one list per unit")
}

/// A list of one key.
fn one(k: &str) -> Vec<String> {
    vec![k.to_owned()]
}

fn keys(v: &[StoredEnvelope]) -> Vec<String> {
    v.iter().map(|e| e.key.clone()).collect()
}

/// Key -> value of entries that must all have been read.
fn values(v: &[StoredEnvelope]) -> BTreeMap<String, Vec<u8>> {
    v.iter()
        .map(|e| match e.state() {
            ValueState::Read(b) => (e.key.clone(), b.to_vec()),
            other => panic!("{}: expected its value, got {other:?}", e.key),
        })
        .collect()
}

/// The variants that say a store cannot be used here (they keep
/// `vci run`'s exit code).
fn unusable(e: &StoreError) -> bool {
    matches!(
        e,
        StoreError::Config(_)
            | StoreError::Unavailable { .. }
            | StoreError::Timeout { .. }
            | StoreError::NotInitialized { .. }
            | StoreError::Incompatible { .. }
            | StoreError::Denied { .. }
            | StoreError::Unsupported { .. }
    )
}

/// Make the manifests `roots` readable on a lazy store, as the command line
/// does before it reads them.
fn fetch_manifests(s: &dyn AttestationStore, roots: &[&str]) {
    if s.caps().lazy_values {
        ok(
            s.prefetch(Prefetch::Manifests { roots }),
            "prefetch manifests",
        );
    }
}

// ---- the scenarios ----------------------------------------------------------------

/// c01: 5 KB and 200 KB values, tabs and newlines, read back byte for byte; an
/// unknown unit lists empty; an identical re-put writes nothing; new bytes
/// replace.
pub fn c01_round_trip_exact_bytes(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let small = text_value("small", 5 * 1024);
    let large = text_value("large", 200 * 1024);
    let h = hint(0x6400_0000, Some(TREE_HEAD));
    let a = put(&*s, UNIT_A, S1, &hex64(1), Some(&h), &small);
    let b = put(&*s, UNIT_B, S1, &hex64(2), None, &large);
    assert_eq!(a.state(), ValueState::Read(&small));
    assert_eq!(b.state(), ValueState::Read(&large));

    let got = read(&*s, &[UNIT_A, UNIT_B]);
    assert_eq!(keys(&got[0]), one(&a.key));
    assert_eq!(got[0][0].state(), ValueState::Read(&small), "5 KB value");
    assert_eq!(keys(&got[1]), one(&b.key));
    assert_eq!(got[1][0].state(), ValueState::Read(&large), "200 KB value");
    assert!(listed(&*s, UNIT_NONE).is_empty(), "an unknown unit");
    assert!(ok(s.read_units(&[UNIT_NONE]), "read_units")[0].is_empty());

    // The same bytes again: the same key, nothing else changes.
    let again = put(&*s, UNIT_A, S1, &hex64(1), Some(&h), &small);
    assert_eq!(again.key, a.key);
    let got = read_one(&*s, UNIT_A);
    assert_eq!(keys(&got), one(&a.key));
    assert_eq!(got[0].state(), ValueState::Read(&small));
    assert_eq!(ok(s.count(), "count"), 2);

    // New bytes under the same key replace the old ones.
    let newer = text_value("newer", 5 * 1024 + 1);
    let c = put(&*s, UNIT_A, S1, &hex64(1), Some(&h), &newer);
    assert_eq!(c.key, a.key);
    let got = read_one(&*s, UNIT_A);
    assert_eq!(keys(&got), one(&a.key));
    assert_eq!(got[0].state(), ValueState::Read(&newer), "replaced value");
    assert_eq!(ok(s.count(), "count"), 2);
}

/// c02: Status, listings, manifests, count and hints on an absent store create
/// no file or schema.
pub fn c02_reading_creates_nothing(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let before = w.backing_exists(0);
    match before {
        Some(true) => panic!("peer 0 of a new world already has a store"),
        Some(false) => {}
        None => skip(
            f,
            "c02_reading_creates_nothing",
            "the check that nothing was created: the world cannot tell",
        ),
    }
    match ok(s.status(), "status") {
        StoreStatus::Absent { .. } | StoreStatus::Ready { .. } => {}
    }
    let units = ok(s.list_units(&[UNIT_A, UNIT_B]), "list_units");
    assert!(units.iter().all(Vec::is_empty), "{units:?}");
    assert!(ok(s.list_all(), "list_all").is_empty());
    assert!(ok(s.read_units(&[UNIT_A]), "read_units")[0].is_empty());
    assert!(ok(s.read_all(), "read_all").is_empty());
    let mut probe = StoredEnvelope::from_key(
        key::target_label(UNIT_A),
        &key::attestation_key(&key::test_key(UNIT_A), S1, &hex64(1)),
    )
    .expect("a key with vci's shape");
    ok(s.read_values(&mut [&mut probe]), "read_values");
    assert!(
        matches!(probe.state(), ValueState::Unreadable(_)),
        "a key the store does not hold: {:?}",
        probe.state()
    );
    assert!(ok(s.manifest(&hex64(1)), "manifest").is_none());
    assert_eq!(ok(s.manifests(&[&hex64(1)]), "manifests"), [None]);
    assert!(ok(s.manifest_roots(), "manifest_roots").is_empty());
    assert_eq!(ok(s.count(), "count"), 0);
    ok(
        s.prefetch(Prefetch::Units {
            test_ids: &[UNIT_A],
            choose: None,
        }),
        "prefetch",
    );
    assert!(s.passing_on(TREE_HEAD).is_empty());
    assert!(!s.flag("plan:natives:conformance"));
    if before == Some(false) {
        assert_eq!(
            w.backing_exists(0),
            Some(false),
            "reading created the store"
        );
    }
}

/// c03: `Invalid` with `what` = `signer_id`, `storage_key`, `test_key`,
/// `target`, `envelope` (empty, non-UTF-8), `input root` and `manifest`; the
/// count stays 0.
pub fn c03_invalid_arguments_write_nothing(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let good = envelope(None, "valid");
    let sk = hex64(1);
    fn att<'a>(
        signer: &'a str,
        storage_key: &'a str,
        test_key: &str,
        target: &str,
        envelope: &'a [u8],
    ) -> NewAttestation<'a> {
        NewAttestation {
            target: target.to_owned(),
            test_key: test_key.to_owned(),
            signer,
            storage_key,
            hint: None,
            envelope,
            columns: None,
        }
    }
    let (tk, target) = (key::test_key(UNIT_A), key::target_label(UNIT_A));
    let not_utf8: &[u8] = &[b'{', 0xff, 0xfe, b'}'];
    let cases: Vec<(&str, NewAttestation<'_>)> = vec![
        ("signer_id", att("XYZ", &sk, &tk, &target, &good)),
        (
            "signer_id",
            att("ABCDEF0123456789", &sk, &tk, &target, &good),
        ),
        ("storage_key", att(S1, "z", &tk, &target, &good)),
        ("storage_key", att(S1, "NOTHEX", &tk, &target, &good)),
        ("test_key", att(S1, &sk, "not a test key", &target, &good)),
        ("target", att(S1, &sk, &tk, "path:/absolute", &good)),
        ("target", att(S1, &sk, &tk, "elsewhere", &good)),
        ("envelope", att(S1, &sk, &tk, &target, b"")),
        ("envelope", att(S1, &sk, &tk, &target, not_utf8)),
    ];
    for (what, a) in &cases {
        match s.put(a) {
            Err(StoreError::Invalid { what: got, .. }) if got == *what => {}
            other => panic!("put with a bad {what}: expected Invalid({what}), got {other:?}"),
        }
    }
    let manifests: [(&str, &str, &[u8]); 4] = [
        ("input root", "XYZ", b"{}"),
        ("input root", "", b"{}"),
        ("manifest", &sk, b""),
        ("manifest", &sk, not_utf8),
    ];
    for (what, root, bytes) in manifests {
        match s.put_manifest(root, bytes) {
            Err(StoreError::Invalid { what: got, .. }) if got == what => {}
            other => panic!(
                "put_manifest with a bad {what} ({root:?}): expected Invalid({what}), got {other:?}"
            ),
        }
    }
    assert_eq!(ok(s.count(), "count"), 0);
    assert!(listed(&*s, UNIT_A).is_empty());
    assert!(ok(s.manifest_roots(), "manifest_roots").is_empty());
}

/// c04: A newer hint replaces the slot; an unhinted put keeps the key; another
/// signer has its own slot.
pub fn c04_same_inputs_replace_whatever_the_hint(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let sk = hex64(1);
    let first = put(
        &*s,
        UNIT_A,
        S1,
        &sk,
        Some(&hint(100, Some(TREE_HEAD))),
        &envelope(None, "first"),
    );
    let newer = put(
        &*s,
        UNIT_A,
        S1,
        &sk,
        Some(&hint(200, None)),
        &envelope(None, "newer"),
    );
    assert_ne!(first.key, newer.key);
    assert_eq!(keys(&listed(&*s, UNIT_A)), one(&newer.key));

    // No hint: the slot keeps its key, the value is replaced.
    let unhinted_bytes = envelope(None, "unhinted");
    let unhinted = put(&*s, UNIT_A, S1, &sk, None, &unhinted_bytes);
    assert_eq!(unhinted.key, newer.key);
    let got = read_one(&*s, UNIT_A);
    assert_eq!(keys(&got), one(&newer.key));
    assert_eq!(got[0].state(), ValueState::Read(&unhinted_bytes));

    // Another signer, and other inputs, have their own slots.
    let other_signer = put(
        &*s,
        UNIT_A,
        S2,
        &sk,
        Some(&hint(300, None)),
        &envelope(None, "S2"),
    );
    let other_inputs = put(&*s, UNIT_A, S1, &hex64(2), None, &envelope(None, "sk2"));
    let mut want = vec![newer.key, other_signer.key, other_inputs.key];
    want.sort();
    assert_eq!(keys(&listed(&*s, UNIT_A)), want);
    assert_eq!(ok(s.count(), "count"), 3);
}

/// c05: Listings are `Unread`; keys whose bytewise and en_US orders differ
/// (`aa:ff.-` against `aaf0:1.-`) come back bytewise; the same listing twice;
/// `list_all` by (target, key).
pub fn c05_listing_is_key_only_and_byte_ordered(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    // Written in the order a natural-language collation would list them.
    let late = put(
        &*s,
        UNIT_A,
        S1,
        "aaf0",
        Some(&hint(1, None)),
        &envelope(None, "aaf0"),
    );
    let early = put(
        &*s,
        UNIT_A,
        S1,
        "aa",
        Some(&hint(0xff, None)),
        &envelope(None, "aa"),
    );
    assert!(early.key.ends_with(":aa:ff.-"), "{}", early.key);
    assert!(late.key.ends_with(":aaf0:1.-"), "{}", late.key);
    assert!(early.key < late.key);

    let first = listed(&*s, UNIT_A);
    assert_eq!(keys(&first), [early.key.clone(), late.key.clone()]);
    for (e, issued) in first.iter().zip([0xff, 1]) {
        assert_eq!(e.state(), ValueState::Unread, "{}", e.key);
        assert_eq!(e.target, key::target_label(UNIT_A));
        assert_eq!(e.test_key, key::test_key(UNIT_A));
        assert_eq!(e.signer, S1);
        assert_eq!((e.issued, e.tree.as_deref()), (Some(issued), None));
    }
    assert_eq!(listed(&*s, UNIT_A), first, "the same listing twice");

    let mut written = BTreeSet::from([early.key, late.key]);
    for (unit, sk) in [
        (UNIT_B, hex64(3)),
        (UNIT_ROOT, hex64(4)),
        (UNIT_ROOT, hex64(5)),
        (UNIT_CARGO, hex64(6)),
    ] {
        let e = put(&*s, unit, S2, &sk, None, &envelope(None, unit));
        written.insert(e.key);
    }
    let all = ok(s.list_all(), "list_all");
    let order: Vec<(String, String)> = all
        .iter()
        .map(|e| (e.target.clone(), e.key.clone()))
        .collect();
    let mut sorted = order.clone();
    sorted.sort();
    assert_eq!(order, sorted, "list_all is ordered by (target, key)");
    assert_eq!(
        all.iter().map(|e| e.key.clone()).collect::<BTreeSet<_>>(),
        written
    );
    assert!(all.iter().all(|e| e.state() == ValueState::Unread));
}

/// c06: Duplicates, unknown ids, the `project` target and cargo `#` ids; the
/// batch equals listing one by one.
pub fn c06_list_units_answers_each_id_in_order(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    put(&*s, UNIT_A, S1, &hex64(1), None, &envelope(None, "a1"));
    put(
        &*s,
        UNIT_A,
        S2,
        &hex64(2),
        Some(&hint(2, Some(TREE_HEAD))),
        &envelope(None, "a2"),
    );
    put(&*s, UNIT_B, S1, &hex64(3), None, &envelope(None, "b"));
    put(&*s, UNIT_ROOT, S1, &hex64(4), None, &envelope(None, "root"));
    put(
        &*s,
        UNIT_CARGO,
        S1,
        &hex64(5),
        None,
        &envelope(None, "cargo"),
    );

    let ids = [
        UNIT_A, UNIT_NONE, UNIT_A, UNIT_ROOT, UNIT_CARGO, UNIT_B, UNIT_NONE,
    ];
    let batch = ok(s.list_units(&ids), "list_units");
    assert_eq!(batch.len(), ids.len(), "one list per id");
    for (id, got) in ids.iter().zip(&batch) {
        assert_eq!(got, &listed(&*s, id), "{id}: the batch and one by one");
    }
    assert_eq!(batch[0].len(), 2);
    assert_eq!(batch[0], batch[2], "a duplicate id is answered twice");
    assert!(batch[1].is_empty() && batch[6].is_empty(), "an unknown id");
    assert!(batch[3].iter().all(|e| e.target == key::PROJECT_TARGET));
    assert!(batch[4].iter().all(|e| e.target == "path:rust/core"));
    assert!(batch[5].iter().all(|e| e.target == "path:src/b.test.ts"));
    assert!(ok(s.list_units(&[]), "list_units of nothing").is_empty());
}

/// c07: A key removed after the listing reads as `GONE`, the others as `Read`,
/// and the call is `Ok`.
pub fn c07_read_values_reports_each_record(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let a1 = put(&*s, UNIT_A, S1, &hex64(1), None, &envelope(None, "a1"));
    let a2 = put(&*s, UNIT_A, S2, &hex64(2), None, &envelope(None, "a2"));
    let b = put(&*s, UNIT_B, S1, &hex64(3), None, &envelope(None, "b"));
    let mut entries = ok(s.list_units(&[UNIT_A, UNIT_B]), "list_units").concat();
    assert_eq!(entries.len(), 3);
    ok(s.remove(vec![a1.clone()]), "remove");
    let mut refs: Vec<&mut StoredEnvelope> = entries.iter_mut().collect();
    ok(s.read_values(&mut refs), "read_values after a removal");
    let by_key: BTreeMap<&str, &StoredEnvelope> =
        entries.iter().map(|e| (e.key.as_str(), e)).collect();
    assert_eq!(
        by_key[a1.key.as_str()].state(),
        ValueState::Unreadable(GONE)
    );
    assert_eq!(by_key[a2.key.as_str()].state(), ValueState::Read(&a2.bytes));
    assert_eq!(by_key[b.key.as_str()].state(), ValueState::Read(&b.bytes));
}

/// c08: The `put_manifest` flag; `manifest`, `manifests` (order and `None`) and
/// `manifest_roots`; `manifest_decoded` through a base; a missing base reads as
/// not in the store; `remove_manifests` validates every root first.
pub fn c08_manifests_and_bases(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let base = manifest_of(&["lib/shared.rb", "config/boot.rb"]);
    let full = manifest_of(&["lib/shared.rb", "config/boot.rb", UNIT_A]);
    let (rbase, rfull) = (base.root(), full.root());
    let delta = full.to_compact_on(&base);
    assert!(delta.contains(&rbase), "the delta names its base: {delta}");

    assert!(ok(
        s.put_manifest(&rbase, base.to_compact().as_bytes()),
        "put base"
    ));
    assert!(ok(s.put_manifest(&rfull, delta.as_bytes()), "put delta"));
    assert!(
        !ok(s.put_manifest(&rfull, delta.as_bytes()), "put delta again"),
        "identical bytes change nothing"
    );
    // The same manifest in another encoding is a change, and back again.
    assert!(ok(
        s.put_manifest(&rfull, full.to_compact().as_bytes()),
        "put plain"
    ));
    assert!(ok(
        s.put_manifest(&rfull, delta.as_bytes()),
        "put delta back"
    ));

    let m = ok(s.manifest(&rfull), "manifest").expect("a stored manifest");
    assert_eq!(
        (m.root.as_str(), m.key.clone(), m.bytes.as_slice(), &m.error),
        (
            rfull.as_str(),
            key::manifest_key(&rfull),
            delta.as_bytes(),
            &None
        )
    );
    assert!(ok(s.manifest(&hex64(9)), "manifest").is_none());
    assert!(ok(s.manifest("not hex"), "manifest of a bad root").is_none());
    let many = ok(s.manifests(&[&rbase, &hex64(9), &rfull]), "manifests");
    assert_eq!(many.len(), 3);
    assert_eq!(
        many[0].as_ref().map(|m| m.root.as_str()),
        Some(rbase.as_str())
    );
    assert!(many[1].is_none());
    assert_eq!(
        many[2].as_ref().map(|m| m.root.as_str()),
        Some(rfull.as_str())
    );

    let decoded = ok(s.manifest_decoded(&rfull), "manifest_decoded")
        .expect("stored")
        .unwrap_or_else(|e| panic!("decoding through the base: {e}"));
    assert_eq!(decoded.root(), rfull);
    assert_eq!(decoded.entries.len(), 3);
    assert!(ok(s.manifest_decoded(&hex64(9)), "manifest_decoded").is_none());

    // A manifest whose base is not stored cannot be decoded.
    let lone_base = manifest_of(&["lib/other.rb"]);
    let other = manifest_of(&["lib/other.rb", UNIT_B]);
    let rother = other.root();
    ok(
        s.put_manifest(&rother, other.to_compact_on(&lone_base).as_bytes()),
        "put a delta without its base",
    );
    let why = ok(s.manifest_decoded(&rother), "manifest_decoded")
        .expect("stored")
        .expect_err("its base is missing");
    assert!(
        why.contains(&lone_base.root()) && why.contains("not in the store"),
        "{why}"
    );

    let free = manifest_of(&["free.rb"]);
    let rfree = put_manifest(&*s, &free);
    let mut roots = vec![rbase.clone(), rfull.clone(), rother.clone(), rfree.clone()];
    roots.sort();
    assert_eq!(ok(s.manifest_roots(), "manifest_roots"), roots);

    // Every root is checked before anything is removed.
    match s.remove_manifests(&[&rfree, "XYZ"]) {
        Err(StoreError::Invalid {
            what: "input root", ..
        }) => {}
        other => panic!("remove_manifests with a bad root: {other:?}"),
    }
    assert!(
        ok(s.manifest(&rfree), "manifest").is_some(),
        "nothing removed"
    );
    assert_eq!(
        ok(s.remove_manifests(&[]), "remove_manifests of nothing"),
        0
    );
    if s.caps().shared_writes {
        skip(
            f,
            "c08_manifests_and_bases",
            "removing a root just put: a shared store keeps it for its grace period (c29)",
        );
    } else {
        assert_eq!(ok(s.remove_manifests(&[&rfree]), "remove_manifests"), 1);
        assert!(ok(s.manifest(&rfree), "manifest").is_none());
        assert_eq!(
            ok(s.remove_manifests(&[&rfree]), "remove_manifests again"),
            0
        );
    }
}

/// c09: The caller's bytes come back; a second remove returns nothing; the
/// count follows.
pub fn c09_remove_returns_what_existed(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let a1 = put(&*s, UNIT_A, S1, &hex64(1), None, &envelope(None, "a1"));
    let a2 = put(&*s, UNIT_A, S1, &hex64(2), None, &envelope(None, "a2"));
    put(&*s, UNIT_B, S1, &hex64(3), None, &envelope(None, "b"));
    assert_eq!(ok(s.count(), "count"), 3);

    let mut doomed = a1.clone();
    doomed.bytes = b"what the caller holds".to_vec();
    let ghost = StoredEnvelope::from_key(
        key::target_label(UNIT_A),
        &key::attestation_key(&key::test_key(UNIT_A), S2, &hex64(9)),
    )
    .expect("a key with vci's shape");
    let removed = ok(s.remove(vec![doomed.clone(), ghost]), "remove");
    assert_eq!(keys(&removed), one(&a1.key), "only what existed");
    assert_eq!(removed[0].bytes, doomed.bytes, "with the caller's bytes");
    assert_eq!(keys(&listed(&*s, UNIT_A)), one(&a2.key));
    assert_eq!(ok(s.count(), "count"), 2);
    assert!(ok(s.remove(vec![doomed]), "remove again").is_empty());
    assert_eq!(ok(s.count(), "count"), 2);
    assert!(ok(s.remove(Vec::new()), "remove nothing").is_empty());
}

/// c10: A removal reaches other peers (through `sync` for an exchange, at once
/// otherwise), and a key written again is live again.
pub fn c10_deletion_reaches_peers_and_reattestation_wins(f: &dyn StoreFactory) {
    let w = f.world();
    let (p0, p1) = (w.peer(0), w.peer(1));
    let h = hint(0x10, Some(TREE_HEAD));
    let e = put(
        &*p0,
        UNIT_A,
        S1,
        &hex64(1),
        Some(&h),
        &envelope(None, "first"),
    );
    w.sync(0, &[1]);
    assert_eq!(keys(&listed(&*p1, UNIT_A)), one(&e.key), "peer 1 sees it");

    let removed = ok(p0.remove(vec![e.clone()]), "remove");
    assert_eq!(keys(&removed), one(&e.key));
    assert!(listed(&*p0, UNIT_A).is_empty());
    w.sync(0, &[1]);
    assert!(
        listed(&*p1, UNIT_A).is_empty(),
        "the removal reached peer 1"
    );

    let again_bytes = envelope(None, "again");
    let again = put(&*p0, UNIT_A, S1, &hex64(1), Some(&h), &again_bytes);
    assert_eq!(again.key, e.key);
    w.sync(0, &[1]);
    for (i, p) in [&p0, &p1].into_iter().enumerate() {
        let got = read_one(&**p, UNIT_A);
        assert_eq!(keys(&got), one(&e.key), "peer {i}");
        assert_eq!(got[0].state(), ValueState::Read(&again_bytes), "peer {i}");
    }
}

/// c11: After a sync both peers hold both peers' writes.
pub fn c11_union_after_sync(f: &dyn StoreFactory) {
    let w = f.world();
    let (p0, p1) = (w.peer(0), w.peer(1));
    let e0 = put(
        &*p0,
        UNIT_A,
        S1,
        &hex64(1),
        Some(&hint(1, None)),
        &envelope(None, "zero"),
    );
    let e1 = put(
        &*p1,
        UNIT_B,
        S2,
        &hex64(2),
        Some(&hint(2, None)),
        &envelope(None, "one"),
    );
    w.sync(0, &[1]);
    w.sync(1, &[0]);
    for (i, p) in [&p0, &p1].into_iter().enumerate() {
        let got = read(&**p, &[UNIT_A, UNIT_B]);
        assert_eq!(keys(&got[0]), one(&e0.key), "peer {i}");
        assert_eq!(keys(&got[1]), one(&e1.key), "peer {i}");
        assert_eq!(got[0][0].state(), ValueState::Read(&e0.bytes), "peer {i}");
        assert_eq!(got[1][0].state(), ValueState::Read(&e1.bytes), "peer {i}");
    }
}

/// c12: 8 threads x 5 puts through one handle, and across peers: every write is
/// there.
pub fn c12_concurrent_writers_lose_nothing(f: &dyn StoreFactory) {
    let w = f.world();
    let peers: Vec<Arc<dyn AttestationStore>> = (0..4).map(|i| w.peer(i)).collect();
    let value = |unit: &str, i: usize| envelope(None, &format!("{unit} {i}"));
    // (peer, threads) -> units written; peer 0 writes from 8 threads,
    // peers 1 to 3 from 2 threads each, all at once.
    let plan: Vec<(usize, usize)> = std::iter::repeat_n(0, 8)
        .enumerate()
        .map(|(t, p)| (p, t))
        .chain((1..4).flat_map(|p| (0..2).map(move |t| (p, t))))
        .collect();
    let start = Barrier::new(plan.len());
    let written: Vec<StoredEnvelope> = std::thread::scope(|sc| {
        let handles: Vec<_> = plan
            .iter()
            .map(|&(p, t)| {
                let (store, start) = (&peers[p], &start);
                sc.spawn(move || {
                    let unit = format!("src/c12/p{p}t{t}.test.ts");
                    start.wait();
                    (0..5)
                        .map(|i| {
                            put(
                                &**store,
                                &unit,
                                S1,
                                &format!("{i:02x}"),
                                Some(&hint(i as i64, None)),
                                &value(&unit, i),
                            )
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("a writer thread"))
            .collect()
    });
    assert_eq!(written.len(), 70);
    for p in 1..4 {
        w.sync(p, &[0]);
    }
    let p0 = &peers[0];
    let units: Vec<String> = plan
        .iter()
        .map(|(p, t)| format!("src/c12/p{p}t{t}.test.ts"))
        .collect();
    let ids: Vec<&str> = units.iter().map(String::as_str).collect();
    let got = read(&**p0, &ids);
    let mut want: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for e in &written {
        want.insert(e.key.clone(), e.bytes.clone());
    }
    let have: BTreeMap<String, Vec<u8>> = got.iter().flat_map(|u| values(u)).collect();
    assert_eq!(have.len(), 70, "every write reached peer 0");
    assert_eq!(have, want);
    assert_eq!(ok(p0.count(), "count"), 70);
}

/// c13: The same key written by two peers ends with one value both agree on.
pub fn c13_same_key_from_two_peers_converges(f: &dyn StoreFactory) {
    let w = f.world();
    let (p0, p1) = (w.peer(0), w.peer(1));
    let h = hint(0x20, Some(TREE_HEAD));
    let (v0, v1) = (envelope(None, "peer zero"), envelope(None, "peer one"));
    let e0 = put(&*p0, UNIT_A, S1, &hex64(1), Some(&h), &v0);
    let e1 = put(&*p1, UNIT_A, S1, &hex64(1), Some(&h), &v1);
    assert_eq!(e0.key, e1.key);
    w.sync(0, &[1]);
    w.sync(1, &[0]);
    let a = read_one(&*p0, UNIT_A);
    let b = read_one(&*p1, UNIT_A);
    assert_eq!(keys(&a), one(&e0.key));
    assert_eq!(a, b, "the peers agree");
    let v = values(&a).remove(&e0.key).expect("read");
    assert!(v == v0 || v == v1, "the value is one of the two written");
}

/// c14: With an exchange: `NothingStored`, then `Pushed`, then `UpToDate`, and
/// `found`; without one, `exchange()` is `None`.
pub fn c14_fetch_and_push_say_what_happened(f: &dyn StoreFactory) {
    let w = f.world();
    let p0 = w.peer(0);
    let Some(x0) = p0.exchange() else {
        assert!(w.peer(1).exchange().is_none());
        assert!(w.fresh_peer().exchange().is_none());
        skip(
            f,
            "c14_fetch_and_push_say_what_happened",
            "fetch and push: the store has no exchange",
        );
        return;
    };
    assert!(!x0.exchange_point().is_empty());
    let out = ok(x0.push(None, PushMode::Merge), "push from an empty peer");
    assert_eq!(out.status, PushStatus::NothingStored);
    let p1 = w.peer(1);
    let x1 = p1.exchange().expect("every peer has the exchange");
    assert!(
        !ok(x1.fetch(None), "fetch from an empty remote").found,
        "the remote holds nothing yet"
    );

    let e = put(&*p0, UNIT_A, S1, &hex64(1), None, &envelope(None, "c14"));
    assert_eq!(
        ok(x0.push(None, PushMode::Merge), "push").status,
        PushStatus::Pushed
    );
    assert_eq!(
        ok(x0.push(None, PushMode::Merge), "push again").status,
        PushStatus::UpToDate
    );
    assert!(ok(x1.fetch(None), "fetch").found);
    assert_eq!(keys(&listed(&*p1, UNIT_A)), one(&e.key));
    let fresh = w.fresh_peer();
    let xf = fresh.exchange().expect("every peer has the exchange");
    assert!(ok(xf.fetch(None), "fetch into a fresh peer").found);
    let got = read_one(&*fresh, UNIT_A);
    assert_eq!(keys(&got), one(&e.key));
    assert_eq!(got[0].state(), ValueState::Read(&e.bytes));
}

/// c15: The chosen values and their manifests read after one prefetch; a store
/// that is not lazy returns `Hydration::default()`.
pub fn c15_prefetch_makes_chosen_values_readable(f: &dyn StoreFactory) {
    let w = f.world();
    let p0 = w.peer(0);
    let base = manifest_of(&["lib/c15/shared.rs", "lib/c15/boot.rs"]);
    let full = manifest_of(&["lib/c15/shared.rs", "lib/c15/boot.rs", UNIT_A]);
    let other = manifest_of(&["lib/c15/other.rs"]);
    let (rbase, rfull, rother) = (base.root(), full.root(), other.root());
    put_manifest(&*p0, &base);
    ok(
        p0.put_manifest(&rfull, full.to_compact_on(&base).as_bytes()),
        "put a delta",
    );
    put_manifest(&*p0, &other);
    let a1 = put(
        &*p0,
        UNIT_A,
        S1,
        &hex64(0x11),
        Some(&hint(1, None)),
        &envelope(Some(&rfull), "a1"),
    );
    let a2 = put(
        &*p0,
        UNIT_A,
        S1,
        &hex64(0x22),
        Some(&hint(2, None)),
        &envelope(Some(&rother), "a2"),
    );
    let b1 = put(
        &*p0,
        UNIT_B,
        S2,
        &hex64(0x33),
        None,
        &envelope(Some(&rother), "b1"),
    );
    w.sync(0, &[1]);

    let s = w.peer(1);
    let ids = [UNIT_A, UNIT_B];
    let first =
        |c: &[StoredEnvelope]| -> Vec<usize> { if c.is_empty() { Vec::new() } else { vec![0] } };
    let h = ok(
        s.prefetch(Prefetch::Units {
            test_ids: &ids,
            choose: Some(&first),
        }),
        "prefetch",
    );
    if !s.caps().lazy_values {
        assert_eq!(h, Hydration::default(), "a store that is not lazy");
    }
    let mut units = ok(s.list_units(&ids), "list_units");
    assert_eq!(keys(&units[0]), [a1.key.clone(), a2.key.clone()]);
    assert_eq!(keys(&units[1]), one(&b1.key));
    let mut chosen: Vec<&mut StoredEnvelope> =
        units.iter_mut().filter_map(|u| u.first_mut()).collect();
    ok(s.read_values(&mut chosen), "read_values");
    assert_eq!(chosen[0].state(), ValueState::Read(&a1.bytes));
    assert_eq!(chosen[1].state(), ValueState::Read(&b1.bytes));
    for root in [&rfull, &rbase, &rother] {
        let m = ok(s.manifest(root), "manifest").expect("a stored manifest");
        assert!(m.is_read(), "manifest {root}: {:?}", m.error);
    }
    let decoded = ok(s.manifest_decoded(&rfull), "manifest_decoded")
        .expect("stored")
        .unwrap_or_else(|e| panic!("decoding through the base: {e}"));
    assert_eq!(decoded.root(), rfull);
}

/// c16: The first failure within the connect timeout plus 1 s, 40 more calls
/// under 2 s, hints empty, never a panic. With an exchange, reads and writes
/// of the local store still work: the call that fails is `fetch`, which
/// fails again, each time within [`FIRST_FAILURE`], after the 40 calls.
pub fn c16_an_unreachable_store_fails_fast(f: &dyn StoreFactory) {
    let w = f.world();
    let Some(u) = w.unreachable() else {
        skip(
            f,
            "c16_an_unreachable_store_fails_fast",
            "everything: the world has no unreachable store",
        );
        return;
    };
    let exchange = u.exchange().is_some();
    let t = Instant::now();
    let first = match u.exchange() {
        Some(x) => x.fetch(None).map(drop),
        None => u.list_units(&[UNIT_A]).map(drop),
    };
    let elapsed = t.elapsed();
    let e = first.expect_err("the first call to an unreachable store fails");
    assert!(
        elapsed < FIRST_FAILURE,
        "the first failure took {elapsed:?}: {e}"
    );
    if !exchange {
        assert!(unusable(&e), "the store cannot be used: {e:?}");
    }

    assert!(u.passing_on(TREE_HEAD).is_empty());
    assert!(!u.flag("plan:natives:conformance"));
    let probe = StoredEnvelope::from_key(
        key::target_label(UNIT_A),
        &key::attestation_key(&key::test_key(UNIT_A), S1, &hex64(1)),
    )
    .expect("a key with vci's shape");
    let t = Instant::now();
    for i in 0..40 {
        let r: Result<(), StoreError> = match i % 10 {
            0 => u.status().map(drop),
            1 => u.list_units(&[UNIT_A]).map(drop),
            2 => u.list_all().map(drop),
            3 => u.read_values(&mut [&mut probe.clone()]),
            4 => u.manifest(&hex64(2)).map(drop),
            5 => u.count().map(drop),
            6 => u
                .put_for_test(UNIT_A, S1, &hex64(1), None, &envelope(None, "x"))
                .map(drop),
            7 => u.put_manifest(&hex64(2), b"{}").map(drop),
            8 => u.remove(vec![probe.clone()]).map(drop),
            _ => u.read_units(&[UNIT_A]).map(drop),
        };
        if !exchange {
            let e = r.expect_err("every call to an unreachable store fails");
            assert!(unusable(&e), "call {i}: {e:?}");
        }
    }
    let elapsed = t.elapsed();
    assert!(elapsed < LATER_CALLS, "40 more calls took {elapsed:?}");
    if let Some(x) = u.exchange() {
        for _ in 0..2 {
            let t = Instant::now();
            let e = x
                .fetch(None)
                .expect_err("a fetch from an unreachable remote");
            let elapsed = t.elapsed();
            assert!(
                elapsed < FIRST_FAILURE,
                "a later fetch took {elapsed:?}: {e}"
            );
        }
    }
    u.remember_passing(TREE_HEAD, &[(key::test_key(UNIT_A), probe.key.clone())]);
    u.set_flag("plan:natives:conformance");
    if !exchange {
        assert!(u.passing_on(TREE_HEAD).is_empty());
        assert!(!u.flag("plan:natives:conformance"));
    }
}

/// c17: Reads work; writes are `Err` (`Denied` or `Unavailable`), never a
/// panic.
pub fn c17_read_only_store_reads(f: &dyn StoreFactory) {
    let w = f.world();
    let p0 = w.peer(0);
    let m = manifest_of(&["src/c17/input.rs"]);
    let root = put_manifest(&*p0, &m);
    let e = put(
        &*p0,
        UNIT_A,
        S1,
        &hex64(1),
        Some(&hint(1, Some(TREE_HEAD))),
        &envelope(Some(&root), "c17"),
    );
    let Some(ro) = w.read_only(0) else {
        skip(
            f,
            "c17_read_only_store_reads",
            "everything: the world has no read-only handle",
        );
        return;
    };
    // Reads.
    assert!(matches!(
        ok(ro.status(), "status"),
        StoreStatus::Ready { .. }
    ));
    let got = read_one(&*ro, UNIT_A);
    assert_eq!(keys(&got), one(&e.key));
    assert_eq!(got[0].state(), ValueState::Read(&e.bytes));
    fetch_manifests(&*ro, &[&root]);
    let stored = ok(ro.manifest(&root), "manifest").expect("stored");
    assert_eq!(stored.bytes, m.to_compact().as_bytes());
    assert_eq!(ok(ro.count(), "count"), 1);
    assert_eq!(ok(ro.manifest_roots(), "manifest_roots"), one(&root));

    // Writes are refused.
    let refused = |what: &str, r: Result<(), StoreError>| match r {
        Ok(()) => panic!("{what} through a read-only handle succeeded"),
        Err(e) if ro.exchange().is_none() => assert!(
            matches!(
                e,
                StoreError::Denied { .. } | StoreError::Unavailable { .. }
            ),
            "{what}: expected Denied or Unavailable, got {e:?}"
        ),
        Err(_) => {}
    };
    refused(
        "put",
        ro.put_for_test(UNIT_B, S1, &hex64(2), None, &envelope(None, "ro"))
            .map(drop),
    );
    let other = manifest_of(&["src/c17/other.rs"]);
    refused(
        "put_manifest",
        ro.put_manifest(&other.root(), other.to_compact().as_bytes())
            .map(drop),
    );
    // A removal fails, or removes nothing.
    match ro.remove(vec![e.clone()]) {
        Ok(v) => assert!(v.is_empty(), "remove through a read-only handle: {v:?}"),
        Err(err) => refused("remove", Err(err)),
    }
    match ro.remove_manifests(&[&root]) {
        Ok(n) => assert_eq!(n, 0, "remove_manifests through a read-only handle"),
        Err(err) => refused("remove_manifests", Err(err)),
    }
    ro.remember_passing(TREE_HEAD, &[(key::test_key(UNIT_A), e.key.clone())]);
    ro.set_flag("plan:natives:conformance");
    assert_eq!(keys(&listed(&*ro, UNIT_A)), one(&e.key));
    assert!(listed(&*ro, UNIT_B).is_empty());
    assert!(ok(ro.manifest(&root), "manifest").is_some());
    assert!(ok(ro.manifest(&other.root()), "manifest").is_none());
}

/// c18: With `keeps_hints`: remember then recall, set then get; otherwise
/// empty.
pub fn c18_hints_round_trip(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    // Hints need the store to exist; a write creates it.
    let a = put(&*s, UNIT_A, S1, &hex64(1), None, &envelope(None, "a"));
    let b_key = key::attestation_key(&key::test_key(UNIT_B), S2, &hex64(2));
    let items = vec![
        (key::test_key(UNIT_A), a.key.clone()),
        (key::test_key(UNIT_B), b_key),
    ];
    s.remember_passing(TREE_HEAD, &items);
    s.set_flag("plan:natives:conformance");
    if s.caps().keeps_hints {
        let want: BTreeMap<String, String> = items.into_iter().collect();
        assert_eq!(s.passing_on(TREE_HEAD), want);
        assert!(s.passing_on("fedcba9876543210").is_empty(), "another tree");
        assert!(s.flag("plan:natives:conformance"));
        assert!(!s.flag("plan:natives:other"));
    } else {
        assert!(s.passing_on(TREE_HEAD).is_empty());
        assert!(!s.flag("plan:natives:conformance"));
    }
}

/// c19: Immediate batches: visible inside the batch; deferred ones: visible
/// after `finish`, to another peer too.
pub fn c19_batch_writes_are_durable(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let m = manifest_of(&["src/c19/input.rs"]);
    let root = m.root();
    let batch = ok(s.batch(), "batch");
    let deferred = batch.defers_writes();
    let changed = ok(
        s.put_manifest(&root, m.to_compact().as_bytes()),
        "put_manifest in a batch",
    );
    let e = put(
        &*s,
        UNIT_A,
        S1,
        &hex64(1),
        Some(&hint(1, None)),
        &envelope(Some(&root), "c19"),
    );
    let removed_later = put(&*s, UNIT_B, S1, &hex64(2), None, &envelope(None, "gone"));
    ok(s.remove(vec![removed_later]), "remove in a batch");
    if !deferred {
        assert!(changed);
        assert_eq!(keys(&listed(&*s, UNIT_A)), one(&e.key), "inside the batch");
        assert!(listed(&*s, UNIT_B).is_empty(), "inside the batch");
        assert!(
            ok(s.manifest(&root), "manifest").is_some(),
            "inside the batch"
        );
    }
    ok(batch.finish(), "finish");

    let got = read(&*s, &[UNIT_A, UNIT_B]);
    assert_eq!(keys(&got[0]), one(&e.key));
    assert_eq!(got[0][0].state(), ValueState::Read(&e.bytes));
    assert!(got[1].is_empty(), "the batch's removal");
    assert!(ok(s.manifest(&root), "manifest").is_some());
    w.sync(0, &[1]);
    let p1 = w.peer(1);
    let got = read(&*p1, &[UNIT_A, UNIT_B]);
    assert_eq!(keys(&got[0]), one(&e.key), "another peer");
    assert_eq!(
        got[0][0].state(),
        ValueState::Read(&e.bytes),
        "another peer"
    );
    assert!(got[1].is_empty(), "another peer");
    fetch_manifests(&*p1, &[&root]);
    let stored = ok(p1.manifest(&root), "manifest").expect("another peer");
    assert_eq!(stored.bytes, m.to_compact().as_bytes());
}

/// c20: 1,200 units listed, prefetched and read.
pub fn c20_many_values(f: &dyn StoreFactory) {
    const N: usize = 1200;
    let w = f.world();
    let p0 = w.peer(0);
    let names: Vec<String> = (0..N)
        .map(|i| format!("src/many/u{i:04}.test.ts"))
        .collect();
    let ids: Vec<&str> = names.iter().map(String::as_str).collect();
    let value = |i: usize| envelope(None, &format!("value {i:04}"));
    let batch = ok(p0.batch(), "batch");
    let written: Vec<StoredEnvelope> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            put(
                &*p0,
                id,
                S1,
                &format!("{i:08x}"),
                Some(&hint(i as i64, None)),
                &value(i),
            )
        })
        .collect();
    ok(batch.finish(), "finish");
    w.sync(0, &[1]);

    let s = w.peer(1);
    let mut units = ok(s.list_units(&ids), "list_units");
    assert_eq!(units.len(), N);
    for (u, e) in units.iter().zip(&written) {
        assert_eq!(keys(u), one(&e.key));
    }
    ok(
        s.prefetch(Prefetch::Units {
            test_ids: &ids,
            choose: None,
        }),
        "prefetch",
    );
    let mut refs: Vec<&mut StoredEnvelope> = units.iter_mut().flatten().collect();
    ok(s.read_values(&mut refs), "read_values");
    for (i, u) in units.iter().enumerate() {
        assert_eq!(u[0].state(), ValueState::Read(&value(i)), "{}", ids[i]);
    }
    assert_eq!(ok(s.count(), "count"), N);
    assert_eq!(ok(s.list_all(), "list_all").len(), N);
}

/// c21: Six handles writing first at once (schema-creation races).
pub fn c21_concurrent_first_writes_create_the_store_once(f: &dyn StoreFactory) {
    const HANDLES: usize = 6;
    let w = f.world();
    let peers: Vec<Arc<dyn AttestationStore>> = (0..HANDLES).map(|i| w.peer(i)).collect();
    let start = Barrier::new(HANDLES);
    let written: Vec<StoredEnvelope> = std::thread::scope(|sc| {
        let handles: Vec<_> = peers
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let start = &start;
                sc.spawn(move || {
                    start.wait();
                    put(
                        &**p,
                        &format!("src/first/{i}.test.ts"),
                        S1,
                        &hex64(i as u8 + 1),
                        None,
                        &envelope(None, &format!("first {i}")),
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a writer thread"))
            .collect()
    });
    let names: Vec<String> = (0..HANDLES)
        .map(|i| format!("src/first/{i}.test.ts"))
        .collect();
    let ids: Vec<&str> = names.iter().map(String::as_str).collect();
    let readers: Vec<usize> = if peers[0].exchange().is_some() {
        for i in 1..HANDLES {
            w.sync(i, &[0]);
        }
        vec![0]
    } else {
        (0..HANDLES).collect()
    };
    for i in readers {
        let p = &peers[i];
        assert!(
            matches!(ok(p.status(), "status"), StoreStatus::Ready { .. }),
            "peer {i}"
        );
        let got = read(&**p, &ids);
        for (u, e) in got.iter().zip(&written) {
            assert_eq!(keys(u), one(&e.key), "peer {i}");
            assert_eq!(u[0].state(), ValueState::Read(&e.bytes), "peer {i}");
        }
        assert_eq!(ok(p.count(), "count"), HANDLES, "peer {i}");
    }
}

/// c22: Through `World::make_unreadable`: only that entry is unreadable.
pub fn c22_one_unreadable_value_hides_only_itself(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let a1 = put(&*s, UNIT_A, S1, &hex64(1), None, &envelope(None, "a1"));
    let a2 = put(&*s, UNIT_A, S2, &hex64(2), None, &envelope(None, "a2"));
    let b = put(&*s, UNIT_B, S1, &hex64(3), None, &envelope(None, "b"));
    if !w.make_unreadable(0, &a1.key) {
        skip(
            f,
            "c22_one_unreadable_value_hides_only_itself",
            "everything: the world cannot make a value unreadable",
        );
        return;
    }
    assert_eq!(
        keys(&listed(&*s, UNIT_A)),
        {
            let mut k = vec![a1.key.clone(), a2.key.clone()];
            k.sort();
            k
        },
        "the key is still listed"
    );
    let got = read(&*s, &[UNIT_A, UNIT_B]).concat();
    let mut listed_then_read = ok(s.list_units(&[UNIT_A, UNIT_B]), "list_units").concat();
    let mut refs: Vec<&mut StoredEnvelope> = listed_then_read.iter_mut().collect();
    ok(s.read_values(&mut refs), "read_values");
    for entries in [got, listed_then_read] {
        let by_key: BTreeMap<&str, &StoredEnvelope> =
            entries.iter().map(|e| (e.key.as_str(), e)).collect();
        match by_key[a1.key.as_str()].state() {
            ValueState::Unreadable(why) => assert_ne!(why, GONE),
            other => panic!("the unreadable value: {other:?}"),
        }
        assert_eq!(by_key[a2.key.as_str()].state(), ValueState::Read(&a2.bytes));
        assert_eq!(by_key[b.key.as_str()].state(), ValueState::Read(&b.bytes));
    }
    assert_eq!(ok(s.count(), "count"), 3);
}

/// c23: Through `World::inject_raw`: listings and the count skip keys without
/// vci's shape.
pub fn c23_foreign_keys_are_ignored(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let a = put(&*s, UNIT_A, S1, &hex64(1), None, &envelope(None, "real"));
    let tk = key::test_key(UNIT_A);
    let target = key::target_label(UNIT_A);
    // A key with vci's shape written behind the backend's back is listed.
    let valid = key::attestation_key_hinted(&tk, S2, &hex64(2), &hint(5, None));
    if !w.inject_raw(0, &target, &valid, b"injected") {
        skip(
            f,
            "c23_foreign_keys_are_ignored",
            "everything: the world cannot write raw records",
        );
        return;
    }
    let p = key::unit_prefix(&tk);
    let foreign = [
        format!("{}:{tk}:{S1}", key::KEY_PREFIX),
        format!("{p}NOTHEX0123456789:{}", hex64(3)),
        format!("{p}{S1}:{}:extra:more", hex64(4)),
        format!("{p}{S1}:{}:zz.-", hex64(5)),
        format!("{p}{S1}:XYZ"),
        format!("{}:short", key::KEY_PREFIX),
        "foreign:key".to_owned(),
    ];
    for k in &foreign {
        assert!(w.inject_raw(0, &target, k, b"foreign"), "inject {k}");
    }
    let mut want = vec![a.key.clone(), valid.clone()];
    want.sort();
    assert_eq!(keys(&listed(&*s, UNIT_A)), want);
    let all: BTreeSet<String> = ok(s.list_all(), "list_all")
        .into_iter()
        .map(|e| e.key)
        .collect();
    assert_eq!(all, want.iter().cloned().collect());
    assert_eq!(ok(s.count(), "count"), 2);
    let got = values(&read_one(&*s, UNIT_A));
    assert_eq!(got[&a.key], a.bytes);
    assert_eq!(got[&valid], b"injected");
}

/// c24: `location`, errors, outcomes and fetch output of the unreachable
/// handle never contain [`super::World::secret`] (its `Debug` output is not
/// reachable through the trait object: each backend's tests check it).
pub fn c24_errors_never_show_secrets(f: &dyn StoreFactory) {
    let w = f.world();
    let (Some(u), Some(secret)) = (w.unreachable(), w.secret()) else {
        skip(
            f,
            "c24_errors_never_show_secrets",
            "everything: the world's unreachable store has no secret",
        );
        return;
    };
    // `Debug` of the handle is not reachable through the trait object; each
    // backend's own tests check it.
    let mut texts = vec![u.location()];
    let mut note = |r: Result<String, StoreError>| match r {
        Ok(s) => texts.push(s),
        Err(e) => {
            texts.push(e.to_string());
            texts.push(format!("{e:?}"));
        }
    };
    note(u.status().map(|s| format!("{s:?}")));
    note(u.list_units(&[UNIT_A]).map(|v| format!("{v:?}")));
    note(u.list_all().map(|v| format!("{v:?}")));
    note(u.manifest(&hex64(1)).map(|v| format!("{v:?}")));
    note(u.count().map(|v| format!("{v:?}")));
    note(u.read_units(&[UNIT_A]).map(|v| format!("{v:?}")));
    note(
        u.put_for_test(UNIT_A, S1, &hex64(1), None, &envelope(None, "x"))
            .map(|v| format!("{v:?}")),
    );
    note(u.put_manifest(&hex64(2), b"{}").map(|v| format!("{v:?}")));
    note(
        u.prefetch(Prefetch::Units {
            test_ids: &[UNIT_A],
            choose: None,
        })
        .map(|v| format!("{v:?}")),
    );
    note(u.batch().map(|b| format!("{b:?}")));
    if let Some(x) = u.exchange() {
        note(x.fetch(None).map(|o| format!("{o:?}")));
        note(x.push(None, PushMode::Merge).map(|o| format!("{o:?}")));
        for name in ["origin", "meta"] {
            note(Ok(format!("{:?}", x.remote_location(name))));
        }
    }
    texts.extend(u.timing_report());
    for t in &texts {
        assert!(!t.contains(&secret), "a message shows the secret: {t}");
    }
}

/// c25: Puts, removals and `put_manifest` after a prefetch are seen at once,
/// including a manifest the prefetch found absent.
pub fn c25_reads_see_this_handles_writes_after_a_prefetch(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let m1 = manifest_of(&["src/c25/one.rs"]);
    let r1 = put_manifest(&*s, &m1);
    let a = put(
        &*s,
        UNIT_A,
        S1,
        &hex64(1),
        Some(&hint(1, None)),
        &envelope(Some(&r1), "a"),
    );
    let absent = manifest_of(&["src/c25/absent.rs"]);
    let rabsent = absent.root();
    let ids = [UNIT_A, UNIT_B];
    ok(
        s.prefetch(Prefetch::Units {
            test_ids: &ids,
            choose: None,
        }),
        "prefetch units",
    );
    ok(
        s.prefetch(Prefetch::Manifests {
            roots: &[&r1, &rabsent],
        }),
        "prefetch manifests",
    );
    assert_eq!(keys(&listed(&*s, UNIT_A)), one(&a.key));
    assert!(listed(&*s, UNIT_B).is_empty());
    assert!(ok(s.manifest(&rabsent), "manifest").is_none());

    let b = put(
        &*s,
        UNIT_B,
        S1,
        &hex64(2),
        Some(&hint(2, None)),
        &envelope(None, "b"),
    );
    ok(s.remove(vec![a.clone()]), "remove");
    assert!(ok(
        s.put_manifest(&rabsent, absent.to_compact().as_bytes()),
        "put_manifest"
    ));

    assert_eq!(keys(&listed(&*s, UNIT_B)), one(&b.key));
    let got = read(&*s, &ids);
    assert!(got[0].is_empty(), "the removal is seen");
    assert_eq!(keys(&got[1]), one(&b.key));
    assert_eq!(got[1][0].state(), ValueState::Read(&b.bytes));
    let m = ok(s.manifest(&rabsent), "manifest").expect("the put manifest is seen");
    assert_eq!(m.bytes, absent.to_compact().as_bytes());
    assert!(ok(s.manifest_roots(), "manifest_roots").contains(&rabsent));

    // A newer hint replaces the slot just written, also as seen here.
    let b2_bytes = envelope(None, "b again");
    let b2 = put(&*s, UNIT_B, S1, &hex64(2), Some(&hint(3, None)), &b2_bytes);
    let got = read_one(&*s, UNIT_B);
    assert_eq!(keys(&got), one(&b2.key));
    assert_eq!(got[0].state(), ValueState::Read(&b2_bytes));
    assert_eq!(ok(s.count(), "count"), 1);
}

/// c26: `Absent` or `Ready`, then `Ready` after a write; manifests are not
/// counted.
pub fn c26_status_and_count(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    match ok(s.status(), "status") {
        StoreStatus::Absent { advice } => assert!(!advice.is_empty()),
        StoreStatus::Ready { .. } => {}
    }
    assert_eq!(ok(s.count(), "count"), 0);
    put_manifest(&*s, &manifest_of(&["src/c26/one.rs"]));
    put_manifest(&*s, &manifest_of(&["src/c26/two.rs"]));
    let a = put(&*s, UNIT_A, S1, &hex64(1), None, &envelope(None, "a"));
    put(&*s, UNIT_B, S1, &hex64(2), None, &envelope(None, "b"));
    put(&*s, UNIT_ROOT, S1, &hex64(3), None, &envelope(None, "root"));
    assert!(matches!(
        ok(s.status(), "status"),
        StoreStatus::Ready { .. }
    ));
    assert_eq!(ok(s.count(), "count"), 3, "manifests are not counted");
    ok(s.remove(vec![a]), "remove");
    assert_eq!(ok(s.count(), "count"), 2);
}

/// c27: The backend's `read_units` and the default (list, then read) agree.
pub fn c27_read_units_matches_list_then_read(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    put(&*s, UNIT_A, S1, &hex64(1), None, &envelope(None, "a1"));
    put(
        &*s,
        UNIT_A,
        S2,
        &hex64(2),
        Some(&hint(2, Some(TREE_HEAD))),
        &envelope(None, "a2"),
    );
    put(&*s, UNIT_B, S1, &hex64(3), None, &envelope(None, "b"));
    put(&*s, UNIT_ROOT, S1, &hex64(4), None, &envelope(None, "root"));
    let ids = [UNIT_A, UNIT_NONE, UNIT_B, UNIT_A, UNIT_ROOT];
    let fast = ok(s.read_units(&ids), "read_units");
    let mut slow = ok(s.list_units(&ids), "list_units");
    {
        let mut refs: Vec<&mut StoredEnvelope> = slow.iter_mut().flatten().collect();
        ok(s.read_values(&mut refs), "read_values");
    }
    assert_eq!(fast, slow);
    assert_eq!(
        fast.iter().map(Vec::len).collect::<Vec<_>>(),
        [2, 0, 1, 2, 1]
    );
    for u in &fast {
        values(u);
    }
}

/// c28: Referenced roots are kept; an `Unknown` payload makes the answer empty.
pub fn c28_orphan_manifests_keeps_what_is_referenced_or_unknown(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let r1 = put_manifest(&*s, &manifest_of(&["src/c28/one.rs"]));
    let r2 = put_manifest(&*s, &manifest_of(&["src/c28/two.rs"]));
    let r3 = put_manifest(&*s, &manifest_of(&["src/c28/three.rs"]));
    put(&*s, UNIT_A, S1, &hex64(1), None, &envelope(Some(&r1), "a"));
    put(&*s, UNIT_B, S1, &hex64(2), None, &envelope(None, "inline"));
    let mut want = vec![r2.clone(), r3.clone()];
    want.sort();
    assert_eq!(
        ok(
            s.orphan_manifests(&[&r3, &r1, &r2, &r2]),
            "orphan_manifests"
        ),
        want
    );
    assert!(ok(s.orphan_manifests(&[]), "orphan_manifests of nothing").is_empty());
    // A payload whose manifestRef is not a root: nothing can be removed.
    put(
        &*s,
        UNIT_CARGO,
        S1,
        &hex64(3),
        None,
        &envelope(Some("NOT-A-ROOT"), "unknown"),
    );
    assert!(
        ok(s.orphan_manifests(&[&r2, &r3]), "orphan_manifests").is_empty(),
        "an unknown reference keeps every root"
    );
}

/// c29: On a shared store: referenced, base-of-another and within-grace roots
/// are kept and not counted.
pub fn c29_remove_manifests_keeps_referenced_and_recent(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    if !s.caps().shared_writes {
        skip(
            f,
            "c29_remove_manifests_keeps_referenced_and_recent",
            "everything: the store is not shared",
        );
        return;
    }
    let base = manifest_of(&["lib/c29/shared.rs"]);
    let full = manifest_of(&["lib/c29/shared.rs", UNIT_A]);
    let rbase = put_manifest(&*s, &base);
    let rfull = full.root();
    ok(
        s.put_manifest(&rfull, full.to_compact_on(&base).as_bytes()),
        "put a delta",
    );
    let rref = put_manifest(&*s, &manifest_of(&["lib/c29/referenced.rs"]));
    let rfree = put_manifest(&*s, &manifest_of(&["lib/c29/free.rs"]));
    put(
        &*s,
        UNIT_A,
        S1,
        &hex64(1),
        None,
        &envelope(Some(&rref), "a"),
    );
    assert_eq!(
        ok(
            s.remove_manifests(&[&rbase, &rref, &rfree]),
            "remove_manifests"
        ),
        0,
        "a base, a referenced root and a root just put are all kept"
    );
    for root in [&rbase, &rfull, &rref, &rfree] {
        assert!(ok(s.manifest(root), "manifest").is_some(), "{root} kept");
    }
}

/// c30: Through `World::failing_batches`: `finish` is `Err` and the batch's
/// writes are not visible.
pub fn c30_failed_batch_reports_and_loses(f: &dyn StoreFactory) {
    let w = f.world();
    let p0 = w.peer(0);
    // A store with something in it.
    let a = put(&*p0, UNIT_A, S1, &hex64(1), None, &envelope(None, "a"));
    let Some(h) = w.failing_batches() else {
        skip(
            f,
            "c30_failed_batch_reports_and_loses",
            "everything: the world cannot make a batch fail",
        );
        return;
    };
    let m = manifest_of(&["src/c30/input.rs"]);
    let root = m.root();
    let batch = ok(h.batch(), "batch");
    let deferred = batch.defers_writes();
    let writes = [
        h.put_manifest(&root, m.to_compact().as_bytes()).map(drop),
        h.put_for_test(
            UNIT_B,
            S1,
            &hex64(2),
            Some(&hint(2, None)),
            &envelope(Some(&root), "b"),
        )
        .map(drop),
        h.remove(vec![a.clone()]).map(drop),
    ];
    if deferred {
        for r in writes {
            ok(r, "a write inside a deferred batch");
        }
    }
    let end = batch.finish();
    assert!(end.is_err(), "the batch was to fail: {end:?}");
    assert!(ok(p0.manifest(&root), "manifest").is_none(), "its manifest");
    assert!(listed(&*p0, UNIT_B).is_empty(), "its attestation");
    assert_eq!(keys(&listed(&*p0, UNIT_A)), [a.key], "its removal");
}

/// c31: `FailedStore`: every read and write is `Unavailable`, hints are empty.
pub fn c31_failed_store_fails_every_call(f: &dyn StoreFactory) {
    let s = FailedStore::new("conformance", format!("{} could not be opened", f.name()));
    let unavailable = |what: &str, r: Result<(), StoreError>| match r {
        Err(StoreError::Unavailable {
            backend: "conformance",
            ..
        }) => {}
        other => panic!("{what}: expected Unavailable, got {other:?}"),
    };
    let probe = StoredEnvelope::from_key(
        key::target_label(UNIT_A),
        &key::attestation_key(&key::test_key(UNIT_A), S1, &hex64(1)),
    )
    .expect("a key with vci's shape");
    unavailable("status", s.status().map(drop));
    unavailable("list_units", s.list_units(&[UNIT_A]).map(drop));
    unavailable("list_all", s.list_all().map(drop));
    unavailable("read_values", s.read_values(&mut [&mut probe.clone()]));
    unavailable("read_units", s.read_units(&[UNIT_A]).map(drop));
    unavailable("read_all", s.read_all().map(drop));
    unavailable("count", s.count().map(drop));
    unavailable("manifest", s.manifest(&hex64(1)).map(drop));
    unavailable("manifests", s.manifests(&[&hex64(1)]).map(drop));
    unavailable("manifest_decoded", s.manifest_decoded(&hex64(1)).map(drop));
    unavailable("manifest_roots", s.manifest_roots().map(drop));
    unavailable(
        "orphan_manifests",
        s.orphan_manifests(&[&hex64(1)]).map(drop),
    );
    unavailable(
        "put",
        s.put_for_test(UNIT_A, S1, &hex64(1), None, b"x").map(drop),
    );
    unavailable("put_manifest", s.put_manifest(&hex64(1), b"{}").map(drop));
    unavailable("remove", s.remove(vec![probe]).map(drop));
    unavailable(
        "remove_manifests",
        s.remove_manifests(&[&hex64(1)]).map(drop),
    );
    unavailable("batch", s.batch().map(drop));
    unavailable("prefetch", s.prefetch(Prefetch::Attestations).map(drop));
    s.remember_passing(TREE_HEAD, &[(key::test_key(UNIT_A), hex64(1))]);
    s.set_flag("plan:natives:conformance");
    assert!(s.passing_on(TREE_HEAD).is_empty());
    assert!(!s.flag("plan:natives:conformance"));
    assert!(s.exchange().is_none());
    assert_eq!(s.kind(), "conformance");
    assert!(s.location().contains("could not be opened"));
}

/// c32: 16 threads of `list_units`, `manifest` and `read_values` while one
/// writer puts and removes: no `Err`, no torn value.
pub fn c32_concurrent_readers_and_writer(f: &dyn StoreFactory) {
    const READERS: usize = 16;
    const WRITES: usize = 30;
    let w = f.world();
    let s = w.peer(0);
    // Every value is a function of its storage key, so a reader can tell a
    // torn or mixed-up value from a right one.
    let value_of = |sk: &str| envelope(None, &format!("the value of {sk} ").repeat(20));
    let stable: Vec<String> = (0..4).map(|i| format!("src/c32/r{i}.test.ts")).collect();
    let moving: Vec<String> = (0..3).map(|i| format!("src/c32/w{i}.test.ts")).collect();
    let mut roots = Vec::new();
    for (i, unit) in stable.iter().enumerate() {
        for j in 0..2 {
            let sk = format!("{i:02x}{j:02x}");
            put(&*s, unit, S1, &sk, None, &value_of(&sk));
        }
        let m = manifest_of(&[unit.as_str()]);
        roots.push((put_manifest(&*s, &m), m.to_compact().into_bytes()));
    }
    let ids: Vec<&str> = stable.iter().chain(&moving).map(String::as_str).collect();
    let done = AtomicBool::new(false);
    let rounds = AtomicUsize::new(0);
    let removed = AtomicUsize::new(0);
    std::thread::scope(|sc| {
        let writer = sc.spawn(|| {
            for i in 0..WRITES {
                let unit = &moving[i % moving.len()];
                let sk = format!("{:04x}", 0x100 + i);
                put(
                    &*s,
                    unit,
                    S2,
                    &sk,
                    Some(&hint(i as i64, None)),
                    &value_of(&sk),
                );
                if i % 3 == 2 {
                    let old = listed(&*s, unit);
                    if old.len() > 1 {
                        let gone = ok(s.remove(vec![old[0].clone()]), "remove");
                        removed.fetch_add(gone.len(), Ordering::SeqCst);
                    }
                }
                put_manifest(&*s, &manifest_of(&[&format!("src/c32/m{i}.rs")]));
            }
            done.store(true, Ordering::SeqCst);
        });
        for _ in 0..READERS {
            sc.spawn(|| {
                let mut mine = 0;
                while mine < 2 || !done.load(Ordering::SeqCst) {
                    let mut units = ok(s.list_units(&ids), "list_units");
                    for u in &units[..stable.len()] {
                        assert_eq!(u.len(), 2, "a stable unit");
                    }
                    let mut refs: Vec<&mut StoredEnvelope> = units.iter_mut().flatten().collect();
                    ok(s.read_values(&mut refs), "read_values");
                    for (i, u) in units.iter().enumerate() {
                        for e in u {
                            match e.state() {
                                ValueState::Read(b) => {
                                    assert!(b == value_of(&e.storage_key), "{}: torn", e.key)
                                }
                                ValueState::Unreadable(GONE) if i >= stable.len() => {}
                                other => panic!("{}: {other:?}", e.key),
                            }
                        }
                    }
                    for (root, bytes) in &roots {
                        let m = ok(s.manifest(root), "manifest").expect("a stable manifest");
                        assert_eq!(&m.bytes, bytes, "{root}");
                    }
                    mine += 1;
                    rounds.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
        writer.join().expect("the writer");
    });
    assert!(rounds.load(Ordering::Relaxed) >= READERS * 2);
    let after = read(&*s, &ids);
    for u in &after {
        for e in u {
            assert_eq!(e.state(), ValueState::Read(&value_of(&e.storage_key)));
        }
    }
    let removed = removed.load(Ordering::SeqCst);
    assert!(removed > 0, "the writer removed something");
    assert_eq!(
        after[stable.len()..].iter().map(Vec::len).sum::<usize>(),
        WRITES - removed
    );
}

/// c33: Stored keys and targets equal `key::attestation_key_hinted` and
/// `key::target_label`.
pub fn c33_key_and_target_parity(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let long_tree = format!("{TREE_HEAD}0123456789abcdef01234567");
    let hints = [
        None,
        Some(hint(0, None)),
        Some(hint(0x6543_2100, Some(TREE_HEAD))),
        Some(hint(-5, Some(&long_tree))),
        Some(hint(7, Some("not a tree"))),
    ];
    let units = [
        UNIT_A,
        UNIT_ROOT,
        UNIT_CARGO,
        "x",
        "src/deep/dir/c.test.ts#case one",
    ];
    for (i, (unit, h)) in units.iter().zip(&hints).enumerate() {
        let sk = hex64(i as u8 + 1);
        let tk = key::test_key(unit);
        let want = match h {
            Some(h) => key::attestation_key_hinted(&tk, S1, &sk, h),
            None => key::attestation_key(&tk, S1, &sk),
        };
        let bytes = envelope(None, unit);
        let e = put(&*s, unit, S1, &sk, h.as_ref(), &bytes);
        let parsed = key::parse_key_hint(&want);
        assert_eq!(
            (
                e.key.as_str(),
                e.target.clone(),
                e.test_key.as_str(),
                e.signer.as_str(),
                e.storage_key.as_str()
            ),
            (
                want.as_str(),
                key::target_label(unit),
                tk.as_str(),
                S1,
                sk.as_str()
            ),
            "{unit}"
        );
        assert_eq!(
            (e.issued, e.tree.clone()),
            (
                parsed.as_ref().map(|p| p.issued),
                parsed.and_then(|p| p.tree)
            ),
            "{unit}"
        );
        let got = listed(&*s, unit);
        assert_eq!(got.len(), 1, "{unit}");
        let mut unread = e.clone();
        unread.bytes.clear();
        assert_eq!(got[0], unread, "{unit}: the listing");
    }
}

/// c34: `put(NewAttestation::copy_of(..))` into a second world keeps keys,
/// targets and bytes.
pub fn c34_copy_keeps_keys_and_targets(f: &dyn StoreFactory) {
    let w1 = f.world();
    let src = w1.peer(0);
    put(
        &*src,
        UNIT_A,
        S1,
        &hex64(1),
        Some(&hint(1, Some(TREE_HEAD))),
        &envelope(None, "a1"),
    );
    put(&*src, UNIT_A, S2, &hex64(2), None, &envelope(None, "a2"));
    put(
        &*src,
        UNIT_ROOT,
        S1,
        &hex64(3),
        Some(&hint(3, None)),
        &envelope(None, "root"),
    );
    put(
        &*src,
        UNIT_CARGO,
        S1,
        &hex64(4),
        None,
        &envelope(None, "cargo"),
    );
    put(
        &*src,
        UNIT_B,
        S2,
        &hex64(5),
        Some(&hint(5, Some(TREE_HEAD))),
        &text_value("b", 3000),
    );
    let records = ok(src.read_all(), "read_all");
    assert_eq!(records.len(), 5);
    values(&records);

    let w2 = f.world();
    let dst = w2.peer(0);
    for r in &records {
        let h = key::parse_key_hint(&r.key);
        let got = ok(
            dst.put(&NewAttestation::copy_of(r, h.as_ref())),
            "put a copy",
        );
        assert_eq!((&got.key, &got.target), (&r.key, &r.target));
    }
    assert_eq!(ok(dst.read_all(), "read_all of the copy"), records);
}

// ---- format-3 fixtures (STORE-V2) ----------------------------------------------

/// The ids of a run's four objects, 64 lowercase hex each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunIds {
    /// The hdr object.
    pub hdr: String,
    /// The tables object.
    pub tables: String,
    /// The shape object.
    pub shape: String,
    /// The state object.
    pub state: String,
}

/// A small format-3 run built with vci-core's encoders: one object of each
/// kind over some paths, and records whose statements name the hdr and the
/// tables and whose descriptors name the shape. The state object holds raw
/// 32-byte hashes, so its bytes are not UTF-8: a backend that stores text
/// has to base64 it, and reading it back equal is what the objects
/// scenarios check on every backend.
pub struct Run3 {
    /// The four objects in the order hdr, tables, shape, state.
    pub objects: Vec<(ObjectKind, Vec<u8>)>,
    /// Their ids.
    pub ids: RunIds,
    tables: vci_core::Tables,
}

impl Run3 {
    /// A run whose shape and state list `paths` (sorted) as files.
    pub fn build(paths: &[&str]) -> Run3 {
        let mut sorted: Vec<&str> = paths.to_vec();
        sorted.sort_unstable();
        let m = manifest_of(&sorted);
        let hdr = vci_core::Hdr {
            repo_id: "github.com/example/repo".into(),
            adapter: "vitest".into(),
            project_name: "web".into(),
            project_dir: String::new(),
            runner_project: String::new(),
            tool_version: "2.9.0".into(),
            rails_inputs: String::new(),
            env_config_digest: [7; 32],
            global_input_root: [8; 32],
            global_manifest: manifest_of(&["package.json"]).entries,
            global_externals: vec![],
            global_env: vec![],
            ignored_inputs: vec![],
            env_set: vec![],
            toolchain: vci_core::Toolchain {
                os: "linux".into(),
                arch: "x86_64".into(),
                ..Default::default()
            },
        };
        let tables = vci_core::Tables {
            waivers: vec![],
            env_names: vec!["TZ".into()],
            externals: vec![],
        };
        let shape = vci_core::Shape {
            entries: m.entries.iter().map(vci_core::ShapeEntry::of).collect(),
            groups: vec![],
        };
        let state = vci_core::State {
            entries: m.entries.clone(),
        };
        let objects = vec![
            (ObjectKind::Hdr, hdr.encode().expect("a hdr")),
            (ObjectKind::Tables, tables.encode().expect("a tables")),
            (ObjectKind::Shape, shape.encode().expect("a shape")),
            (ObjectKind::State, state.encode().expect("a state")),
        ];
        let id = |i: usize| vci_core::objects::hex32(&vci_core::object_id(&objects[i].1));
        let ids = RunIds {
            hdr: id(0),
            tables: id(1),
            shape: id(2),
            state: id(3),
        };
        Run3 {
            objects,
            ids,
            tables,
        }
    }

    /// The objects as a put takes them.
    pub fn new_objects(&self) -> Vec<NewObject<'_>> {
        self.objects
            .iter()
            .map(|(k, b)| NewObject::new(*k, b))
            .collect()
    }

    /// The four ids in the order hdr, tables, shape, state.
    pub fn id_refs(&self) -> Vec<&str> {
        vec![
            &self.ids.hdr,
            &self.ids.tables,
            &self.ids.shape,
            &self.ids.state,
        ]
    }

    /// The hdr, tables and shape ids sorted: what
    /// [`key::record_object_refs`] names for a record of this run.
    pub fn named(&self) -> Vec<String> {
        let mut v = vec![
            self.ids.hdr.clone(),
            self.ids.tables.clone(),
            self.ids.shape.clone(),
        ];
        v.sort();
        v
    }

    /// A format-3 record for `unit`: a statement naming the run's hdr and
    /// tables, a synthetic SSHSIG blob, and a descriptor naming the shape
    /// whose first `own` entries are the unit's; with the columns the
    /// writer copies out of that statement. `seed` varies the signed bytes.
    pub fn record(&self, unit: &str, own: usize, seed: u32) -> (Vec<u8>, Columns) {
        let commit = format!("{seed:08x}").repeat(5);
        let expires: i64 = 1_800_000_000 + i64::from(seed);
        let duration_ms = u64::from(seed) * 10;
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": unit, "digest": {"blake3": hex64(9)}}],
            "predicateType": vci_core::PREDICATE_TYPE_V2,
            "predicate": {
                "commit": commit,
                "expiresAt": expires.to_string(),
                "hdr": self.ids.hdr,
                "tables": self.ids.tables,
                "result": {"state": "passed", "tests": 1, "failed": 0, "skipped": 0,
                            "duration_ms": duration_ms},
                "testId": unit,
            },
        });
        let shape = vci_core::objects::parse_hex32(&self.ids.shape).expect("a shape id");
        let descriptor = vci_core::Descriptor {
            shape,
            group: None,
            own: (0..own).collect(),
            env_read: vec![],
            env_values: vec![],
            externals: vec![],
            extras: vec![],
        }
        .encode(&self.tables)
        .expect("a descriptor");
        let record = vci_attest::Frame {
            statement: statement.to_string().into_bytes(),
            keyid: "SHA256:conformance".into(),
            sig: vci_attest::FrameSig::SshSig(vec![0x53, 0x53, 0x48, seed as u8]),
            descriptor,
        }
        .encode()
        .expect("a frame")
        .into_bytes();
        let columns = Columns {
            format: Some(3),
            commit: Some(commit),
            platform: Some("linux-x86_64".into()),
            state: Some("passed".into()),
            duration_ms: Some(duration_ms),
            expires: Some(expires),
            hdr: Some(self.ids.hdr.clone()),
            tables: Some(self.ids.tables.clone()),
            shape: Some(self.ids.shape.clone()),
            state_obj: Some(self.ids.state.clone()),
        };
        (record, columns)
    }
}

fn put3(
    s: &dyn AttestationStore,
    unit: &str,
    signer: &str,
    storage_key: &str,
    record: &[u8],
    columns: &Columns,
) -> StoredEnvelope {
    ok(
        s.put(
            &NewAttestation::for_test(unit, signer, storage_key, None, record)
                .with_columns(columns),
        ),
        &format!("put a format-3 record {unit} {signer} {storage_key}"),
    )
}

fn put_objects(s: &dyn AttestationStore, objects: &[NewObject<'_>]) -> usize {
    ok(s.put_objects(objects), "put_objects")
}

/// These objects, prefetched first on a lazy store.
fn get_objects(s: &dyn AttestationStore, ids: &[&str]) -> Vec<StoredObject> {
    if s.caps().lazy_values {
        ok(s.prefetch(Prefetch::Objects { ids }), "prefetch objects");
    }
    ok(s.get_objects(ids), "get_objects")
}

/// Whether the store keeps objects; says so and returns `false` otherwise.
fn keeps_objects(f: &dyn StoreFactory, scenario: &str, s: &dyn AttestationStore) -> bool {
    if s.caps().objects {
        return true;
    }
    skip(f, scenario, "everything: the store keeps no objects");
    false
}

/// Age `ids` on peer 0 by `by`, or say the world cannot and return `false`.
fn aged(
    f: &dyn StoreFactory,
    scenario: &str,
    w: &dyn super::World,
    ids: &[&str],
    by: Duration,
) -> bool {
    if w.age_objects(0, ids, by) {
        return true;
    }
    skip(f, scenario, "the rest: the world cannot age objects");
    false
}

// ---- the objects scenarios ---------------------------------------------------

/// c35: The four objects of a run read back byte for byte with their kinds
/// and ids (the state object is binary, so a text backend's base64 round
/// trip is checked here); a second put stores nothing new; unknown ids are
/// left out and duplicates answered once; another peer reads them. Without
/// `Caps::objects` every object method is `Unsupported`.
pub fn c35_objects_round_trip_and_idempotent_put(f: &dyn StoreFactory) {
    const C: &str = "c35_objects_round_trip_and_idempotent_put";
    let w = f.world();
    let s = w.peer(0);
    let run = Run3::build(&["src/c35/b.ts", "src/c35/a.ts"]);
    if !s.caps().objects {
        let unsupported = |what: &str, r: Result<(), StoreError>| match r {
            Err(StoreError::Unsupported { .. }) => {}
            other => panic!("{what} without Caps::objects: expected Unsupported, got {other:?}"),
        };
        unsupported("get_objects", s.get_objects(&run.id_refs()).map(drop));
        unsupported("put_objects", s.put_objects(&run.new_objects()).map(drop));
        unsupported("remove_objects", s.remove_objects(&run.id_refs()).map(drop));
        unsupported("orphan_objects", s.orphan_objects().map(drop));
        unsupported(
            "prune_state_objects",
            s.prune_state_objects(Duration::from_secs(1)).map(drop),
        );
        skip(f, C, "the rest: the store keeps no objects");
        return;
    }
    assert!(
        std::str::from_utf8(&run.objects[3].1).is_err(),
        "the state object is binary"
    );
    assert_eq!(put_objects(&*s, &run.new_objects()), 4, "four new objects");
    let got = get_objects(&*s, &run.id_refs());
    assert_eq!(got.len(), 4, "every object, in the order asked");
    for (o, (kind, bytes)) in got.iter().zip(&run.objects) {
        assert_eq!(o.kind, *kind);
        assert_eq!(&o.bytes, bytes, "the {kind} object read back byte for byte");
        assert_eq!(
            o.id,
            vci_core::objects::hex32(&vci_core::object_id(&o.bytes)),
            "filed under the BLAKE3 of its bytes"
        );
    }
    assert_eq!(put_objects(&*s, &run.new_objects()), 0, "already stored");
    assert_eq!(
        get_objects(&*s, &run.id_refs()),
        got,
        "unchanged by the re-put"
    );
    let unknown = hex64(0xee);
    let some = get_objects(&*s, &[&unknown, &run.ids.hdr, &run.ids.hdr]);
    assert_eq!(
        some.len(),
        1,
        "an unknown id is left out, a repeated one answered once"
    );
    assert_eq!(some[0].id, run.ids.hdr);
    assert!(get_objects(&*s, &[]).is_empty());

    w.sync(0, &[1]);
    let p1 = w.peer(1);
    assert_eq!(get_objects(&*p1, &run.id_refs()), got, "another peer");
}

/// c36: Object ids and objects are validated before anything is written:
/// `Invalid` with what = `object id` (not 64 lowercase hex) and `object`
/// (empty, over its kind's bound, or not headed by the magic and the kind
/// byte), one bad object among good ones writes none, and a put whose
/// columns name a bad id writes nothing.
pub fn c36_objects_are_validated_and_bounded(f: &dyn StoreFactory) {
    const C: &str = "c36_objects_are_validated_and_bounded";
    let w = f.world();
    let s = w.peer(0);
    let run = Run3::build(&["src/c36/a.ts"]);
    let invalid = |what: &'static str, r: Result<usize, StoreError>| match r {
        Err(StoreError::Invalid { what: w, .. }) if w == what => {}
        other => panic!("expected Invalid {what}, got {other:?}"),
    };
    let short = &hex64(1)[..62];
    let upper = hex64(0xab).to_uppercase();
    for id in ["NOT-AN-ID", short, &upper, ""] {
        invalid("object id", s.get_objects(&[id]).map(|v| v.len()));
        invalid("object id", s.remove_objects(&[id]));
    }
    invalid(
        "object",
        s.put_objects(&[NewObject::new(ObjectKind::Hdr, b"")]),
    );
    invalid(
        "object",
        s.put_objects(&[NewObject::new(ObjectKind::Tables, &run.objects[0].1)]),
    );
    invalid(
        "object",
        s.put_objects(&[NewObject::new(ObjectKind::Hdr, b"{\"not\": \"an object\"}")]),
    );
    let mut too_big = b"vo\x01\x01".to_vec();
    too_big.resize(ObjectKind::Hdr.max_bytes() + 1, 0);
    invalid(
        "object",
        s.put_objects(&[NewObject::new(ObjectKind::Hdr, &too_big)]),
    );
    let good = run.new_objects();
    invalid(
        "object",
        s.put_objects(&[good[0], NewObject::new(ObjectKind::Hdr, b"")]),
    );
    let bad = Columns {
        hdr: Some("nope".into()),
        ..Columns::default()
    };
    match s.put(
        &NewAttestation::for_test(UNIT_A, S1, &hex64(1), None, &envelope(None, "c36"))
            .with_columns(&bad),
    ) {
        Err(StoreError::Invalid {
            what: "object id", ..
        }) => {}
        other => panic!("a put with a bad object id: expected Invalid, got {other:?}"),
    }
    assert!(
        listed(&*s, UNIT_A).is_empty(),
        "the refused put wrote nothing"
    );
    if !keeps_objects(f, C, &*s) {
        return;
    }
    assert!(
        get_objects(&*s, &[&run.ids.hdr]).is_empty(),
        "the refused puts wrote no object"
    );
    assert_eq!(
        ok(s.remove_objects(&[&run.ids.hdr]), "remove_objects"),
        0,
        "an object never stored"
    );
    assert_eq!(
        ok(s.orphan_objects(), "orphan_objects"),
        Vec::<String>::new()
    );
}

/// c37: Nothing within its grace period is removed, referenced or not; past
/// it only an object no record's columns (or, without columns, no record's
/// statement or descriptor) name goes, and a put, identical bytes included,
/// restarts the grace; once the record is removed its objects are orphans,
/// except the state object on a store without columns, which cannot see
/// its referrers and leaves it to `prune_state_objects`.
pub fn c37_orphan_rule_keeps_referenced_and_recent_objects(f: &dyn StoreFactory) {
    const C: &str = "c37_orphan_rule_keeps_referenced_and_recent_objects";
    let w = f.world();
    let s = w.peer(0);
    if !keeps_objects(f, C, &*s) {
        return;
    }
    let run = Run3::build(&["src/c37/a.ts", "src/c37/b.ts"]);
    let other = Run3::build(&["src/c37/other.ts"]);
    let free_shape = other.new_objects()[2];
    put_objects(&*s, &run.new_objects());
    put_objects(&*s, &[free_shape]);
    let (rec, cols) = run.record(UNIT_A, 2, 37);
    let e = put3(&*s, UNIT_A, S1, &hex64(1), &rec, &cols);
    let mut all = run.id_refs();
    all.push(&other.ids.shape);
    assert_eq!(
        ok(s.remove_objects(&all), "remove_objects"),
        0,
        "within the grace period nothing goes"
    );
    assert!(ok(s.orphan_objects(), "orphan_objects").is_empty());
    assert_eq!(get_objects(&*s, &all).len(), 5);
    if !aged(f, C, &*w, &all, OBJECT_GRACE * 2) {
        return;
    }
    assert_eq!(
        ok(s.orphan_objects(), "orphan_objects"),
        vec![other.ids.shape.clone()],
        "past the grace, only the unreferenced shape"
    );
    assert_eq!(ok(s.remove_objects(&all), "remove_objects"), 1);
    assert!(get_objects(&*s, &[&other.ids.shape]).is_empty());
    assert_eq!(
        get_objects(&*s, &run.id_refs()).len(),
        4,
        "the referenced objects stay"
    );

    // A put restarts the grace: of a new object, and of one already stored.
    assert_eq!(put_objects(&*s, &[free_shape]), 1);
    assert_eq!(
        ok(s.remove_objects(&[&other.ids.shape]), "remove_objects"),
        0,
        "just put"
    );
    assert!(w.age_objects(0, &[&other.ids.shape], OBJECT_GRACE * 2));
    assert_eq!(put_objects(&*s, &[free_shape]), 0, "already stored");
    assert_eq!(
        ok(s.remove_objects(&[&other.ids.shape]), "remove_objects"),
        0,
        "an idempotent put refreshes put_at"
    );
    assert!(w.age_objects(0, &[&other.ids.shape], OBJECT_GRACE * 2));
    assert_eq!(
        ok(s.remove_objects(&[&other.ids.shape]), "remove_objects"),
        1
    );

    // Without the record, its (aged) objects are orphans.
    ok(s.remove(vec![e]), "remove the record");
    let with_columns = s.caps().columns;
    let mut want: Vec<String> = run.id_refs().iter().map(|i| (*i).to_owned()).collect();
    if !with_columns {
        want.retain(|i| *i != run.ids.state);
    }
    want.sort();
    assert_eq!(
        ok(s.orphan_objects(), "orphan_objects"),
        want,
        "columns kept: {with_columns}"
    );
    let expect = if with_columns { 4 } else { 3 };
    assert_eq!(
        ok(s.remove_objects(&run.id_refs()), "remove_objects"),
        expect
    );
    assert_eq!(get_objects(&*s, &run.id_refs()).len(), 4 - expect);
}

/// c38: `prune_state_objects(older_than)` removes a state object older than
/// that even while a record references it, and touches no other kind.
pub fn c38_state_objects_expire_even_while_referenced(f: &dyn StoreFactory) {
    const C: &str = "c38_state_objects_expire_even_while_referenced";
    let w = f.world();
    let s = w.peer(0);
    if !keeps_objects(f, C, &*s) {
        return;
    }
    let run = Run3::build(&["src/c38/a.ts"]);
    put_objects(&*s, &run.new_objects());
    let (rec, cols) = run.record(UNIT_A, 1, 38);
    let e = put3(&*s, UNIT_A, S1, &hex64(1), &rec, &cols);
    let day = Duration::from_secs(24 * 60 * 60);
    assert_eq!(
        ok(s.prune_state_objects(day), "prune_state_objects"),
        0,
        "younger than a day"
    );
    if !aged(f, C, &*w, &run.id_refs(), 3 * day) {
        return;
    }
    assert_eq!(
        ok(s.prune_state_objects(2 * day), "prune_state_objects"),
        1,
        "the referenced state object past its TTL"
    );
    assert!(get_objects(&*s, &[&run.ids.state]).is_empty());
    assert_eq!(
        get_objects(&*s, &[&run.ids.hdr, &run.ids.tables, &run.ids.shape]).len(),
        3,
        "other kinds are not touched, however old"
    );
    let got = read_one(&*s, UNIT_A);
    assert_eq!(keys(&got), one(&e.key), "the record stays");
    assert_eq!(got[0].state(), ValueState::Read(&rec));
    assert_eq!(
        ok(s.prune_state_objects(Duration::ZERO), "prune_state_objects"),
        0
    );
}

/// c39: In a batch the objects go before the record: a reader on another
/// handle that sees the record gets its objects too, and after `finish`
/// both are there, on another peer as well.
pub fn c39_objects_are_visible_before_their_record(f: &dyn StoreFactory) {
    const C: &str = "c39_objects_are_visible_before_their_record";
    let w = f.world();
    let s = w.peer(0);
    if !keeps_objects(f, C, &*s) {
        return;
    }
    let run = Run3::build(&["src/c39/a.ts"]);
    let (rec, cols) = run.record(UNIT_A, 1, 39);
    let old = put(&*s, UNIT_A, S1, &hex64(1), None, &envelope(None, "old"));
    let ids: Vec<String> = run.id_refs().iter().map(|i| (*i).to_owned()).collect();

    let batch = ok(s.batch(), "batch");
    let deferred = batch.defers_writes();
    ok(s.put_objects(&run.new_objects()), "put_objects in a batch");
    let e = put3(&*s, UNIT_A, S1, &hex64(2), &rec, &cols);
    ok(s.remove(vec![old]), "remove in a batch");
    if !deferred {
        assert_eq!(
            get_objects(&*s, &run.id_refs()).len(),
            4,
            "inside the batch"
        );
        assert_eq!(keys(&listed(&*s, UNIT_A)), one(&e.key), "inside the batch");
    }
    let watcher = {
        let p1 = w.peer(1);
        let key = e.key.clone();
        let ids = ids.clone();
        std::thread::spawn(move || {
            let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
            for _ in 0..200 {
                if let Ok(units) = p1.list_units(&[UNIT_A])
                    && units[0].iter().any(|x| x.key == key)
                {
                    return Some(p1.get_objects(&ids).map(|v| v.len()).unwrap_or(0));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            None
        })
    };
    ok(batch.finish(), "finish");
    if let Some(n) = watcher.join().expect("the watcher") {
        assert_eq!(n, 4, "a reader that saw the record saw its objects");
    }
    assert_eq!(keys(&listed(&*s, UNIT_A)), one(&e.key));
    assert_eq!(get_objects(&*s, &run.id_refs()).len(), 4);
    w.sync(0, &[1]);
    let p1 = w.peer(1);
    let got = read_one(&*p1, UNIT_A);
    assert_eq!(keys(&got), one(&e.key), "another peer");
    assert_eq!(got[0].state(), ValueState::Read(&rec), "another peer");
    assert_eq!(get_objects(&*p1, &run.id_refs()).len(), 4, "another peer");
}

/// c40: `columns` gives back what the put passed, in input order, and none
/// for a format-1 record, a record put without them, a key no longer
/// stored, and everything on a store without `Caps::columns`; a put of the
/// same bytes without columns clears them and one with other columns
/// replaces them; a copy with `with_columns` keeps them.
pub fn c40_columns_match_the_put(f: &dyn StoreFactory) {
    const C: &str = "c40_columns_match_the_put";
    let w = f.world();
    let s = w.peer(0);
    let run = Run3::build(&["src/c40/a.ts"]);
    let (rec, cols) = run.record(UNIT_A, 1, 40);
    let e3 = put3(&*s, UNIT_A, S1, &hex64(3), &rec, &cols);
    let e1 = put(
        &*s,
        UNIT_A,
        S1,
        &hex64(1),
        None,
        &envelope(None, "format 1"),
    );
    let l = listed(&*s, UNIT_A);
    assert_eq!(keys(&l), [e1.key.clone(), e3.key.clone()]);
    let got = ok(s.columns(&[&l[0], &l[1]]), "columns");
    assert_eq!(got.len(), 2, "one answer per entry");
    assert_eq!(got[0], Columns::default(), "a format-1 record has none");
    if !s.caps().columns {
        assert_eq!(got[1], Columns::default(), "a store without columns");
        skip(f, C, "the rest: the store keeps no columns");
        return;
    }
    assert_eq!(got[1], cols, "the columns the writer passed");

    let gone = put3(&*s, UNIT_B, S1, &hex64(4), &rec, &cols);
    ok(s.remove(vec![gone.clone()]), "remove");
    assert_eq!(
        ok(s.columns(&[&l[1], &l[0], &gone]), "columns"),
        [cols.clone(), Columns::default(), Columns::default()],
        "input order; a removed key answers none"
    );
    assert!(ok(s.columns(&[]), "columns of nothing").is_empty());

    put(&*s, UNIT_A, S1, &hex64(3), None, &rec);
    let l = listed(&*s, UNIT_A);
    assert_eq!(keys(&l), [e1.key.clone(), e3.key.clone()]);
    assert_eq!(
        ok(s.columns(&[&l[1]]), "columns")[0],
        Columns::default(),
        "the same bytes put without columns clear them"
    );
    let mut cols2 = cols.clone();
    cols2.duration_ms = Some(999);
    cols2.state_obj = None;
    put3(&*s, UNIT_A, S1, &hex64(3), &rec, &cols2);
    assert_eq!(
        ok(s.columns(&[&l[1]]), "columns")[0],
        cols2,
        "the same bytes put with other columns replace them"
    );

    w.sync(0, &[1]);
    let p1 = w.peer(1);
    let l1 = listed(&*p1, UNIT_A);
    assert_eq!(
        ok(p1.columns(&[&l1[1]]), "columns")[0],
        cols2,
        "another peer"
    );

    let src = read_one(&*s, UNIT_A);
    let w2 = f.world();
    let dst = w2.peer(0);
    let h = key::parse_key_hint(&src[1].key);
    ok(
        dst.put(&NewAttestation::copy_of(&src[1], h.as_ref()).with_columns(&cols2)),
        "copy",
    );
    let ld = listed(&*dst, UNIT_A);
    assert_eq!(keys(&ld), one(&e3.key));
    assert_eq!(
        ok(dst.columns(&[&ld[0]]), "columns")[0],
        cols2,
        "a copy keeps them"
    );
}

/// c41: A format-1 envelope and a format-3 frame of one unit live side by
/// side: listed in key order, read byte for byte, told apart by
/// `decode_record`; the frame names no manifest (`ManifestRef::Inline`) so
/// manifest collection goes on, and names its objects
/// (`record_object_refs`); the count sees both.
pub fn c41_mixed_formats_in_one_namespace(f: &dyn StoreFactory) {
    let w = f.world();
    let s = w.peer(0);
    let root = put_manifest(&*s, &manifest_of(&["src/c41/one.rs"]));
    let free = put_manifest(&*s, &manifest_of(&["src/c41/free.rs"]));
    let run = Run3::build(&["src/c41/a.ts"]);
    let (rec3, cols) = run.record(UNIT_A, 1, 41);
    let rec1 = envelope(Some(&root), "format 1");
    let e1 = put(
        &*s,
        UNIT_A,
        S1,
        &hex64(1),
        Some(&hint(1, Some(TREE_HEAD))),
        &rec1,
    );
    let e3 = put3(&*s, UNIT_A, S1, &hex64(3), &rec3, &cols);
    let got = read_one(&*s, UNIT_A);
    assert_eq!(keys(&got), [e1.key.clone(), e3.key.clone()]);
    assert_eq!(got[0].state(), ValueState::Read(&rec1));
    assert_eq!(got[1].state(), ValueState::Read(&rec3));
    assert!(
        matches!(decode_record(&got[0].bytes), Ok(Record::FormatOne(_))),
        "an envelope"
    );
    match decode_record(&got[1].bytes) {
        Ok(Record::FormatThree(frame)) => {
            let shape = vci_core::Descriptor::shape_id(&frame.descriptor).expect("a shape id");
            assert_eq!(vci_core::objects::hex32(&shape), run.ids.shape);
            assert_eq!(frame.keyid, "SHA256:conformance");
        }
        other => panic!("a frame: got {other:?}"),
    }
    assert_eq!(got[0].manifest_ref(), ManifestRef::Root(root.clone()));
    assert_eq!(
        got[1].manifest_ref(),
        ManifestRef::Inline,
        "a frame names no manifest"
    );
    assert_eq!(
        key::record_object_refs(&got[0].bytes),
        ObjectRefs::FormatOne
    );
    assert_eq!(
        key::record_object_refs(&got[1].bytes),
        ObjectRefs::Named(run.named())
    );
    assert_eq!(
        ok(s.orphan_manifests(&[&root, &free]), "orphan_manifests"),
        vec![free.clone()],
        "the frame blocks no manifest's collection"
    );
    assert_eq!(ok(s.count(), "count"), 2);
    assert_eq!(ok(s.list_all(), "list_all").len(), 2);

    ok(s.remove(vec![got[0].clone()]), "remove the envelope");
    let mut both = vec![root.clone(), free.clone()];
    both.sort();
    assert_eq!(
        ok(s.orphan_manifests(&[&root, &free]), "orphan_manifests"),
        both
    );
    let got = read_one(&*s, UNIT_A);
    assert_eq!(keys(&got), one(&e3.key));
    assert_eq!(got[0].state(), ValueState::Read(&rec3));
    w.sync(0, &[1]);
    let got = read_one(&*w.peer(1), UNIT_A);
    assert_eq!(keys(&got), one(&e3.key), "another peer");
    assert_eq!(got[0].state(), ValueState::Read(&rec3), "another peer");
}

/// c42: Objects and a format-3 record reach another peer (a replica syncs
/// them by `seq`), and so do the record's removal and, past the grace, the
/// objects' (its `gone` rows): the peer then lists nothing, reads the stale
/// entry as `GONE`, and gets no object.
pub fn c42_object_deletions_reach_peers(f: &dyn StoreFactory) {
    const C: &str = "c42_object_deletions_reach_peers";
    let w = f.world();
    let (p0, p1) = (w.peer(0), w.peer(1));
    if !keeps_objects(f, C, &*p0) {
        return;
    }
    let run = Run3::build(&["src/c42/a.ts"]);
    put_objects(&*p0, &run.new_objects());
    let (rec, cols) = run.record(UNIT_A, 1, 42);
    let e = put3(&*p0, UNIT_A, S1, &hex64(1), &rec, &cols);
    w.sync(0, &[1]);
    let got = read_one(&*p1, UNIT_A);
    assert_eq!(keys(&got), one(&e.key), "peer 1 sees the record");
    assert_eq!(got[0].state(), ValueState::Read(&rec));
    assert_eq!(
        get_objects(&*p1, &run.id_refs()).len(),
        4,
        "and its objects"
    );
    let mut stale = got;

    ok(p0.remove(vec![e.clone()]), "remove");
    let removed = if w.age_objects(0, &run.id_refs(), OBJECT_GRACE * 2) {
        let n = ok(p0.remove_objects(&run.id_refs()), "remove_objects");
        assert_eq!(n, if p0.caps().columns { 4 } else { 3 });
        n
    } else {
        skip(f, C, "the objects' removal: the world cannot age objects");
        0
    };
    w.sync(0, &[1]);
    assert!(
        listed(&*p1, UNIT_A).is_empty(),
        "the removal reached peer 1"
    );
    let mut refs: Vec<&mut StoredEnvelope> = stale.iter_mut().collect();
    ok(p1.read_values(&mut refs), "read_values of a removed key");
    assert_eq!(stale[0].state(), ValueState::Unreadable(GONE));
    assert_eq!(
        get_objects(&*p1, &run.id_refs()).len(),
        4 - removed,
        "the objects' removal reached peer 1"
    );
}
