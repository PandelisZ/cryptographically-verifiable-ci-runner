//! The SQLite store's own behaviour (`docs/STORE-BACKENDS.md` section 16):
//! round trips, the slot rule, bytewise order, per-entry read errors,
//! manifests and their removal, an absent file, read-only files, files it
//! must not use, concurrent first writers, batches, hints, the WAL
//! checkpoint at the end, the speed of a plan-sized read, and (2.9) the
//! format-3 side the conformance suite cannot see: a version-1 file from
//! before 2.9 given the additions by the first write, in a transaction of
//! its own before the write's batch; `upgrade_begin` and `upgrade_finish`;
//! the objects as BLOBs and the columns on the row; the answer cap;
//! foreign object rows; each of the four referrer columns; and an object
//! removal inside a batch.
//!
//! These tests never set environment variables: options are passed to
//! [`SqliteStore::open_path`].

use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, params};
use vci_store::conformance::scenarios::Run3;
use vci_store::{
    AttestationStore, Columns, GONE, KeyHint, ManifestRef, NewAttestation, OBJECT_GRACE,
    StoreError, StoreStatus, StoredEnvelope, ValueState, key,
};
use vci_store_sqlite::{Finish, SqliteOptions, SqliteStore};

const S1: &str = "1111111111111111";
const S2: &str = "2222222222222222";
const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const CARGO: &str = "rust/core#test:it";
const ROOT_UNIT: &str = ".";
const TREE1: &str = "0123456789abcdef";
const TREE2: &str = "fedcba9876543210";

fn hex64(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

/// Standard base64 with padding (the crate has no base64 dependency).
fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A DSSE-shaped envelope whose payload's `predicate.manifestRef` is
/// `manifest_ref` (`null` when `None`), padded with `pad` bytes.
fn envelope(manifest_ref: Option<&str>, pad: usize) -> Vec<u8> {
    let payload = serde_json::json!({
        "predicate": {"manifestRef": manifest_ref},
        "pad": "p".repeat(pad),
    });
    serde_json::json!({
        "payloadType": "application/vnd.in-toto+json",
        "payload": b64(payload.to_string().as_bytes()),
        "signatures": [],
    })
    .to_string()
    .into_bytes()
}

fn hint(issued: i64, tree: Option<&str>) -> KeyHint {
    KeyHint {
        issued,
        tree: tree.map(str::to_owned),
    }
}

fn opts() -> SqliteOptions {
    SqliteOptions {
        busy_timeout: Duration::from_secs(20),
        ..SqliteOptions::default()
    }
}

fn db_path(dir: &Path) -> PathBuf {
    dir.join("vci-store.sqlite")
}

fn store(dir: &Path) -> SqliteStore {
    SqliteStore::open_path(db_path(dir), opts())
}

/// A connection behind the store's back.
fn raw(path: &Path) -> Connection {
    let c = Connection::open(path).unwrap();
    c.busy_timeout(Duration::from_secs(20)).unwrap();
    c
}

fn put(
    s: &dyn AttestationStore,
    unit: &str,
    signer: &str,
    sk: &str,
    h: Option<&KeyHint>,
    bytes: &[u8],
) -> StoredEnvelope {
    s.put_for_test(unit, signer, sk, h, bytes).unwrap()
}

fn listed(s: &dyn AttestationStore, unit: &str) -> Vec<StoredEnvelope> {
    s.list_units(&[unit]).unwrap().pop().unwrap()
}

fn read_unit(s: &dyn AttestationStore, unit: &str) -> Vec<StoredEnvelope> {
    s.read_units(&[unit]).unwrap().pop().unwrap()
}

fn keys(v: &[StoredEnvelope]) -> Vec<String> {
    v.iter().map(|e| e.key.clone()).collect()
}

fn stored_at(path: &Path, k: &str) -> i64 {
    raw(path)
        .query_row(
            "SELECT stored_at FROM attestations WHERE key = ?1",
            [k],
            |r| r.get(0),
        )
        .unwrap()
}

fn sidecars(path: &Path) -> Vec<PathBuf> {
    ["-wal", "-shm", "-journal"]
        .iter()
        .map(|s| PathBuf::from(format!("{}{s}", path.display())))
        .filter(|p| p.exists())
        .collect()
}

fn manifest_of(paths: &[&str]) -> vci_core::InputManifest {
    vci_core::InputManifest {
        entries: paths
            .iter()
            .map(|p| vci_core::manifest::InputEntry {
                path: vci_core::RepoPath::try_from(*p).unwrap(),
                kind: vci_core::manifest::EntryKind::File,
                exec: false,
                size: 1,
                hash: "ab".repeat(32),
            })
            .collect(),
        externals: vec![],
        env: vec![],
    }
}

fn is_store_unusable(e: &StoreError) -> bool {
    matches!(
        e,
        StoreError::Unavailable { .. }
            | StoreError::Denied { .. }
            | StoreError::Incompatible { .. }
            | StoreError::Timeout { .. }
    )
}

/// The helper's envelopes parse as vci envelopes (so the tests below test
/// the store, not the fixture).
#[test]
fn fixture_envelopes_name_their_manifest() {
    assert_eq!(
        key::envelope_manifest_ref(&envelope(Some(&hex64(7)), 10)),
        ManifestRef::Root(hex64(7))
    );
    assert_eq!(
        key::envelope_manifest_ref(&envelope(None, 11)),
        ManifestRef::Inline
    );
    assert_eq!(b64(b"ab"), "YWI=");
    assert_eq!(b64(b"abc"), "YWJj");
    assert_eq!(b64(b"a"), "YQ==");
}

/// 1. 5 KB and 200 KB values with tabs and newlines come back byte for
///    byte; an identical re-put writes nothing (`stored_at` unchanged); new
///    bytes replace.
#[test]
fn round_trip_exact_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let small = format!("{{\n\t\"v\": \"{}\"\n}}\n", "ab\tc\né\r\n".repeat(560)).into_bytes();
    let big = format!("[\n{}\t]\n", "\tline\twith tabs\n".repeat(12_500)).into_bytes();
    assert!(small.len() > 5_000 && big.len() > 200_000);
    let h = hint(0x6543_2100, Some(TREE1));
    let e = put(&s, A, S1, &hex64(1), Some(&h), &small);
    assert_eq!(e.issued, Some(0x6543_2100));
    assert_eq!(e.tree.as_deref(), Some(TREE1));
    assert_eq!(e.target, "path:src/a.test.ts");
    put(&s, B, S1, &hex64(2), None, &big);

    let a = read_unit(&s, A);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].state(), ValueState::Read(&small));
    assert_eq!(a[0].key, e.key);
    let b = read_unit(&s, B);
    assert_eq!(b[0].bytes, big);
    assert!(listed(&s, "src/unknown.test.ts").is_empty());

    // An identical re-put is a no-op.
    raw(&db_path(dir.path()))
        .execute(
            "UPDATE attestations SET stored_at = 1 WHERE key = ?1",
            [&e.key],
        )
        .unwrap();
    let again = put(&s, A, S1, &hex64(1), Some(&h), &small);
    assert_eq!(again.key, e.key);
    assert_eq!(stored_at(&db_path(dir.path()), &e.key), 1);

    // New bytes under the same key replace.
    let newer = format!("{}\tnew\n", String::from_utf8(small.clone()).unwrap()).into_bytes();
    put(&s, A, S1, &hex64(1), Some(&h), &newer);
    assert!(stored_at(&db_path(dir.path()), &e.key) > 1);
    assert_eq!(read_unit(&s, A)[0].bytes, newer);
    assert_eq!(s.count().unwrap(), 2);
}

/// 2. A hinted put replaces the slot's older key; an unhinted put keeps the
///    key; another signer gets its own row; 16 threads putting one slot at
///    once leave one row.
#[test]
fn slot_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let sk = hex64(3);
    let k1 = put(&s, A, S1, &sk, Some(&hint(100, Some(TREE1))), b"one").key;
    let k2 = put(&s, A, S1, &sk, Some(&hint(200, Some(TREE2))), b"two").key;
    assert_ne!(k1, k2);
    assert_eq!(keys(&listed(&s, A)), vec![k2.clone()]);

    // Unhinted: the slot keeps its key.
    let kept = put(&s, A, S1, &sk, None, b"three");
    assert_eq!(kept.key, k2);
    assert_eq!(kept.issued, Some(200));
    let a = read_unit(&s, A);
    assert_eq!((a.len(), a[0].bytes.as_slice()), (1, &b"three"[..]));
    // Unhinted with identical bytes: nothing changes, the key is read back.
    assert_eq!(put(&s, A, S1, &sk, None, b"three").key, k2);

    // A new slot without a hint gets the plain key.
    let plain = put(&s, A, S1, &hex64(4), None, b"plain");
    assert_eq!(
        plain.key,
        key::attestation_key(&key::test_key(A), S1, &hex64(4))
    );
    assert_eq!(plain.issued, None);

    // Another signer has its own slot.
    let other = put(&s, A, S2, &sk, Some(&hint(100, Some(TREE1))), b"s2");
    let l = listed(&s, A);
    assert_eq!(l.len(), 3);
    assert!(l.iter().any(|e| e.key == other.key && e.signer == S2));
    assert!(l.iter().any(|e| e.key == k2 && e.signer == S1));

    // 16 threads, each with its own handle, put one slot at once.
    let sk = hex64(5);
    let go = Arc::new(Barrier::new(16));
    let threads: Vec<_> = (0..16)
        .map(|i| {
            let go = Arc::clone(&go);
            let path = db_path(dir.path());
            let sk = sk.clone();
            std::thread::spawn(move || {
                let s = SqliteStore::open_path(path, opts());
                let h = hint(1000 + i, Some(TREE1));
                go.wait();
                put(
                    &s,
                    B,
                    S1,
                    &sk,
                    Some(&h),
                    format!("value {}", 1000 + i).as_bytes(),
                )
                .key
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let b: Vec<StoredEnvelope> = read_unit(&s, B)
        .into_iter()
        .filter(|e| e.storage_key == sk)
        .collect();
    assert_eq!(b.len(), 1, "{b:?}");
    let issued = b[0].issued.unwrap();
    assert_eq!(b[0].bytes, format!("value {issued}").into_bytes());
}

/// 3. A unit's listing is in bytewise key order (the c05 keys, which a
///    natural-language collation orders the other way), and `list_all` is
///    in (target, key) order.
#[test]
fn bytewise_order() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let ka = put(&s, A, S1, "aa", Some(&hint(0xff, None)), b"x").key;
    let kb = put(&s, A, S1, "aaf0", Some(&hint(1, None)), b"x").key;
    let kc = put(&s, A, S1, "a0", None, b"x").key;
    let kd = put(&s, A, S2, "aa", Some(&hint(2, Some(TREE1))), b"x").key;
    assert!(ka.ends_with(":aa:ff.-") && kb.ends_with(":aaf0:1.-"));
    let l = keys(&listed(&s, A));
    let mut sorted = l.clone();
    sorted.sort();
    assert_eq!(l, sorted);
    let pos = |k: &str| l.iter().position(|x| x == k).unwrap();
    assert!(pos(&ka) < pos(&kb), "{l:?}");
    assert!(pos(&kc) < pos(&ka) && pos(&kb) < pos(&kd), "{l:?}");
    // The same listing twice.
    assert_eq!(keys(&listed(&s, A)), l);

    for (unit, seed) in [(B, 9), (CARGO, 10), (ROOT_UNIT, 11), ("z/z.test.ts", 12)] {
        put(&s, unit, S1, &hex64(seed), Some(&hint(5, None)), b"x");
    }
    let all = s.list_all().unwrap();
    let got: Vec<(String, String)> = all
        .iter()
        .map(|e| (e.target.clone(), e.key.clone()))
        .collect();
    let mut want = got.clone();
    want.sort();
    assert_eq!(got, want);
    assert_eq!(all.len(), 8);
    let targets: Vec<&str> = all.iter().map(|e| e.target.as_str()).collect();
    assert!(targets.contains(&"project") && targets.contains(&"path:rust/core"));
    assert!(all.iter().all(|e| e.state() == ValueState::Unread));

    // list_units answers each id in order, duplicates and unknown ids too.
    let ids = [B, "nope", A, B, ROOT_UNIT];
    let units = s.list_units(&ids).unwrap();
    assert_eq!(units.len(), 5);
    for (id, unit) in ids.iter().zip(&units) {
        assert_eq!(keys(unit), keys(&listed(&s, id)));
    }
    assert!(units[1].is_empty());
    assert_eq!(units[4][0].target, "project");
}

/// 4. `read_values`: `GONE` for a key removed after the listing; a value of
///    an unknown `encoding` is unreadable; the call is `Ok` either way.
#[test]
fn read_values_reports_each_record() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let a = put(&s, A, S1, &hex64(1), Some(&hint(1, None)), b"aaa");
    let b = put(&s, B, S1, &hex64(2), Some(&hint(2, None)), b"bbb");
    let c = put(&s, B, S1, &hex64(3), Some(&hint(3, None)), b"ccc");
    let mut units = s.list_units(&[A, B]).unwrap();
    assert!(
        units
            .iter()
            .flatten()
            .all(|e| e.state() == ValueState::Unread)
    );
    let removed = s.remove(vec![b.clone()]).unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].bytes, b"bbb");
    raw(&db_path(dir.path()))
        .execute(
            "UPDATE attestations SET encoding = 99 WHERE key = ?1",
            [&c.key],
        )
        .unwrap();
    {
        let mut refs: Vec<&mut StoredEnvelope> = units.iter_mut().flatten().collect();
        s.read_values(&mut refs).unwrap();
    }
    let by_key = |k: &str| units.iter().flatten().find(|e| e.key == k).unwrap();
    assert_eq!(by_key(&a.key).state(), ValueState::Read(b"aaa"));
    assert_eq!(by_key(&b.key).state(), ValueState::Unreadable(GONE));
    match by_key(&c.key).state() {
        ValueState::Unreadable(why) => assert!(why.contains("encoding"), "{why}"),
        other => panic!("expected unreadable, got {other:?}"),
    }
    // Entries already read are read again.
    let mut again = units.concat();
    let mut refs: Vec<&mut StoredEnvelope> = again.iter_mut().collect();
    s.read_values(&mut refs).unwrap();
    assert_eq!(again[0].state(), ValueState::Read(b"aaa"));
    // A put of the same bytes repairs a value this vci could not read.
    put(&s, B, S1, &hex64(3), Some(&hint(3, None)), b"ccc");
    assert!(
        read_unit(&s, B)
            .iter()
            .any(|e| e.state() == ValueState::Read(b"ccc"))
    );
}

/// 5. Manifests: `put_manifest`'s changed flag; `put_at` refreshed when the
///    bytes are identical; `manifest_decoded` through a base;
///    `remove_manifests` validates every root first and keeps a root that
///    is referenced or is another manifest's base.
#[test]
fn manifests_and_their_removal() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let s = store(dir.path());
    let base = manifest_of(&["lib/shared.rb", "config/boot.rb"]);
    let full = manifest_of(&["lib/shared.rb", "config/boot.rb", A]);
    let (rbase, rfull) = (base.root(), full.root());
    let delta = full.to_compact_on(&base);
    assert!(delta.contains(&rbase), "{delta}");
    assert!(
        s.put_manifest(&rbase, base.to_compact().as_bytes())
            .unwrap()
    );
    assert!(s.put_manifest(&rfull, delta.as_bytes()).unwrap());
    // Identical bytes: unchanged, but put_at is refreshed.
    raw(&path)
        .execute("UPDATE manifests SET put_at = 1", [])
        .unwrap();
    assert!(!s.put_manifest(&rfull, delta.as_bytes()).unwrap());
    let put_at: i64 = raw(&path)
        .query_row(
            "SELECT put_at FROM manifests WHERE root = ?1",
            [&rfull],
            |r| r.get(0),
        )
        .unwrap();
    assert!(put_at > 1);
    let base_col: Option<String> = raw(&path)
        .query_row(
            "SELECT base FROM manifests WHERE root = ?1",
            [&rfull],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(base_col.as_deref(), Some(rbase.as_str()));

    // Decoded through its base.
    let decoded = s.manifest_decoded(&rfull).unwrap().unwrap().unwrap();
    assert_eq!(decoded.root(), rfull);
    assert_eq!(s.manifest(&rfull).unwrap().unwrap().bytes, delta.as_bytes());
    assert!(s.manifest(&hex64(9)).unwrap().is_none());
    assert!(s.manifest("not hex").unwrap().is_none());
    let many = s.manifests(&[&rbase, &hex64(9), &rfull]).unwrap();
    assert_eq!(many[0].as_ref().unwrap().root, rbase);
    assert!(many[1].is_none());
    assert_eq!(many[2].as_ref().unwrap().root, rfull);
    let mut roots = vec![rbase.clone(), rfull.clone()];
    roots.sort();
    assert_eq!(s.manifest_roots().unwrap(), roots);

    // A manifest whose base is not stored cannot be decoded.
    let other = manifest_of(&["lib/other.rb", A]);
    let lone_base = manifest_of(&["lib/other.rb"]);
    s.put_manifest(&other.root(), other.to_compact_on(&lone_base).as_bytes())
        .unwrap();
    let why = s
        .manifest_decoded(&other.root())
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(why.contains(&lone_base.root()), "{why}");

    // An unreferenced root, one referenced by an attestation, and the base
    // of a stored manifest.
    let free = manifest_of(&["free.rb"]);
    s.put_manifest(&free.root(), free.to_compact().as_bytes())
        .unwrap();
    let att = put(&s, A, S1, &hex64(1), None, &envelope(Some(&rfull), 50));
    // Every root is validated before anything is removed.
    match s.remove_manifests(&[&free.root(), "XYZ"]) {
        Err(StoreError::Invalid { what, .. }) => assert_eq!(what, "input root"),
        other => panic!("expected Invalid, got {other:?}"),
    }
    assert!(s.manifest(&free.root()).unwrap().is_some());
    assert_eq!(
        s.remove_manifests(&[&rfull, &rbase, &free.root(), &free.root(), &hex64(9)])
            .unwrap(),
        1
    );
    assert!(s.manifest(&free.root()).unwrap().is_none());
    assert!(s.manifest(&rfull).unwrap().is_some());
    assert!(s.manifest(&rbase).unwrap().is_some());
    // Once nothing references them, they go: the manifest, then its base.
    s.remove(vec![att]).unwrap();
    assert_eq!(s.remove_manifests(&[&rbase]).unwrap(), 0);
    assert_eq!(s.remove_manifests(&[&rfull]).unwrap(), 1);
    assert_eq!(s.remove_manifests(&[&rbase]).unwrap(), 1);
    assert_eq!(s.manifest_roots().unwrap(), vec![other.root()]);

    // Validation of put_manifest.
    for (root, bytes, what) in [
        ("XYZ", &b"{}"[..], "input root"),
        (rbase.as_str(), &b""[..], "manifest"),
        (rbase.as_str(), &[0xff, 0xfe][..], "manifest"),
    ] {
        match s.put_manifest(root, bytes) {
            Err(StoreError::Invalid { what: w, .. }) => assert_eq!(w, what),
            other => panic!("expected Invalid {what}, got {other:?}"),
        }
    }
}

/// 6. `orphan_manifests`: the roots no attestation references, sorted; empty
///    while any attestation's reference is unknown.
#[test]
fn orphan_manifests_from_the_index() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let (r1, r2, r3) = (hex64(1), hex64(2), hex64(3));
    put(&s, A, S1, &hex64(10), None, &envelope(Some(&r1), 10));
    put(&s, B, S1, &hex64(11), None, &envelope(Some(&r2), 10));
    put(&s, CARGO, S1, &hex64(12), None, &envelope(None, 10));
    assert_eq!(
        s.orphan_manifests(&[&r3, &r1, &r2, &r3]).unwrap(),
        vec![r3.clone()]
    );
    assert!(s.orphan_manifests(&[]).unwrap().is_empty());
    // An attestation whose payload does not parse: its reference is unknown.
    let junk = put(&s, ROOT_UNIT, S1, &hex64(13), None, b"not an envelope");
    assert!(s.orphan_manifests(&[&r3]).unwrap().is_empty());
    s.remove(vec![junk]).unwrap();
    assert_eq!(s.orphan_manifests(&[&r3, &r1]).unwrap(), vec![r3.clone()]);
    // Superseding the reference to r1 makes it an orphan.
    put(&s, A, S1, &hex64(10), None, &envelope(Some(&r3), 10));
    assert_eq!(s.orphan_manifests(&[&r3, &r1]).unwrap(), vec![r1]);
}

/// 7. Reading a store whose file does not exist answers as an empty store,
///    and the file (and its directory) still do not exist afterwards; so do
///    hints, removals, a batch, and a put that fails validation.
#[test]
fn reading_an_absent_store_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub").join("vci-store.sqlite");
    let s = SqliteStore::open_path(&path, opts());
    assert_eq!(
        s.status().unwrap(),
        StoreStatus::Absent {
            advice: "the first `vci run` creates it".to_owned()
        }
    );
    assert_eq!(s.list_units(&[A, B]).unwrap(), vec![vec![], vec![]]);
    assert!(s.list_all().unwrap().is_empty());
    assert!(s.read_units(&[A]).unwrap()[0].is_empty());
    assert!(s.read_all().unwrap().is_empty());
    assert_eq!(s.count().unwrap(), 0);
    assert!(s.manifest(&hex64(1)).unwrap().is_none());
    assert!(s.manifest_decoded(&hex64(1)).unwrap().is_none());
    assert_eq!(s.manifests(&[&hex64(1)]).unwrap(), vec![None]);
    assert!(s.manifest_roots().unwrap().is_empty());
    let mut e =
        StoredEnvelope::from_key("project", &key::attestation_key(&hex64(1), S1, &hex64(2)))
            .unwrap();
    s.read_values(&mut [&mut e]).unwrap();
    assert_eq!(e.state(), ValueState::Unreadable(GONE));
    assert!(s.remove(vec![e]).unwrap().is_empty());
    assert_eq!(s.remove_manifests(&[&hex64(1)]).unwrap(), 0);
    assert_eq!(s.orphan_manifests(&[&hex64(1)]).unwrap(), vec![hex64(1)]);
    assert!(s.passing_on(TREE1).is_empty());
    s.remember_passing(TREE1, &[(key::test_key(A), "k".to_owned())]);
    s.set_flag("plan:natives:x");
    assert!(!s.flag("plan:natives:x"));
    s.warm();
    s.batch().unwrap().finish().unwrap();
    assert!(s.timing_report().is_empty());
    assert!(matches!(
        s.put_for_test(A, "XYZ", &hex64(1), None, b"x"),
        Err(StoreError::Invalid {
            what: "signer_id",
            ..
        })
    ));
    assert!(matches!(
        s.put_for_test(A, S1, &hex64(1), None, b""),
        Err(StoreError::Invalid {
            what: "envelope",
            ..
        })
    ));
    assert_eq!(
        s.prefetch(vci_store::Prefetch::Attestations).unwrap(),
        Default::default()
    );
    drop(s);
    assert!(!path.exists());
    assert!(!dir.path().join("sub").exists());

    // The first write creates the directory, the file and the schema.
    let s = SqliteStore::open_path(&path, opts());
    put(&s, A, S1, &hex64(1), None, b"first");
    assert_eq!(
        s.status().unwrap(),
        StoreStatus::Ready {
            schema_version: Some(1)
        }
    );
    let c = raw(&path);
    let app: i64 = c
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .unwrap();
    let version: i64 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    let mode: String = c
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!((app, version, mode.as_str()), (0x7663_6931, 1, "wal"));

    // An empty file reads as absent too, and is not touched by a read.
    let empty = dir.path().join("empty.sqlite");
    std::fs::write(&empty, b"").unwrap();
    let s = SqliteStore::open_path(&empty, opts());
    assert!(matches!(s.status().unwrap(), StoreStatus::Absent { .. }));
    assert!(s.list_all().unwrap().is_empty());
    assert_eq!(std::fs::metadata(&empty).unwrap().len(), 0);
    put(&s, A, S1, &hex64(1), None, b"now");
    assert_eq!(s.count().unwrap(), 1);
}

#[cfg(unix)]
struct Restore(Vec<(PathBuf, u32)>);

#[cfg(unix)]
impl Drop for Restore {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        for (p, mode) in self.0.iter().rev() {
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(*mode));
        }
    }
}

/// Make `paths` read-only (restored when the guard drops). `false` when
/// that does not stop this process writing (running as root).
#[cfg(unix)]
fn read_only(dir: &Path, paths: &[(&Path, u32)]) -> (Restore, bool) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut restore = Restore(Vec::new());
    for (p, mode) in paths {
        let old = std::fs::metadata(p).unwrap().permissions().mode();
        restore.0.push((p.to_path_buf(), old));
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(*mode)).unwrap();
    }
    let probe = dir.join("probe");
    let effective = std::fs::write(&probe, b"x").is_err();
    let _ = std::fs::remove_file(&probe);
    (restore, effective)
}

/// 8. A read-only directory holding the file: reads work (through the
///    read-only and then immutable opens), a write is an error and never a
///    panic, hints keep nothing silently. The same for a handle opened
///    read-only on a writable file.
#[cfg(unix)]
#[test]
fn a_read_only_directory_reads() {
    let top = tempfile::tempdir().unwrap();
    let dir = top.path().join("ro");
    std::fs::create_dir(&dir).unwrap();
    let path = db_path(&dir);
    let root = hex64(4);
    {
        let s = store(&dir);
        put(&s, A, S1, &hex64(1), Some(&hint(1, None)), b"kept");
        s.put_manifest(&root, b"{\"v\":2}").unwrap();
        s.set_flag("plan:natives:x");
        s.remember_passing(TREE1, &[(key::test_key(A), "k".to_owned())]);
    }
    assert!(sidecars(&path).is_empty(), "{:?}", sidecars(&path));
    let (guard, effective) = read_only(&dir, &[(&path, 0o444), (&dir, 0o555)]);
    if !effective {
        eprintln!("skipping: permissions do not stop this process (root?)");
        return;
    }
    let s = store(&dir);
    assert_eq!(
        s.status().unwrap(),
        StoreStatus::Ready {
            schema_version: Some(1)
        }
    );
    let a = read_unit(&s, A);
    assert_eq!(a[0].state(), ValueState::Read(b"kept"));
    assert_eq!(s.count().unwrap(), 1);
    assert!(s.manifest(&root).unwrap().unwrap().is_read());
    assert!(s.flag("plan:natives:x"));
    assert_eq!(s.passing_on(TREE1).len(), 1);
    for r in [
        s.put_for_test(B, S1, &hex64(2), None, b"no").map(|_| ()),
        s.put_manifest(&hex64(5), b"{}").map(|_| ()),
        s.remove(a.clone()).map(|_| ()),
        s.remove_manifests(&[&root]).map(|_| ()),
    ] {
        let e = r.unwrap_err();
        assert!(
            matches!(
                e,
                StoreError::Denied { .. } | StoreError::Unavailable { .. }
            ),
            "{e:?}"
        );
    }
    s.set_flag("other");
    s.remember_passing(TREE2, &[(key::test_key(B), "k".to_owned())]);
    assert!(!s.flag("other"));
    assert!(read_unit(&s, A)[0].state() == ValueState::Read(b"kept"));
    drop(s);
    drop(guard);

    // A handle opened read-only on a writable file.
    let s = SqliteStore::open_path(
        &path,
        SqliteOptions {
            read_only: true,
            ..opts()
        },
    );
    assert_eq!(read_unit(&s, A)[0].state(), ValueState::Read(b"kept"));
    assert!(matches!(
        s.put_for_test(B, S1, &hex64(2), None, b"no"),
        Err(StoreError::Denied { .. })
    ));
    s.set_flag("other");
    assert!(!s.flag("other"));
}

/// A directory that cannot be written and holds no file: reads answer as
/// an empty store; the first write is `Denied` (a store that cannot be used
/// here, so `vci run` keeps the tests' exit code).
#[cfg(unix)]
#[test]
fn an_unwritable_directory_refuses_the_first_write() {
    let top = tempfile::tempdir().unwrap();
    let dir = top.path().join("locked");
    std::fs::create_dir(&dir).unwrap();
    let (_guard, effective) = read_only(&dir, &[(&dir, 0o555)]);
    if !effective {
        eprintln!("skipping: permissions do not stop this process (root?)");
        return;
    }
    let s = store(&dir);
    assert!(matches!(s.status().unwrap(), StoreStatus::Absent { .. }));
    match s.put_manifest(&hex64(1), b"{}") {
        Err(StoreError::Denied { operation, .. }) => assert_eq!(operation, "create the store"),
        other => panic!("expected Denied, got {other:?}"),
    }
    let e = s.put_for_test(A, S1, &hex64(1), None, b"x").unwrap_err();
    assert!(e.to_string().contains("sqlite store refused to"), "{e}");
    assert!(!db_path(&dir).exists());
}

/// 9. A newer schema is `Incompatible`, a file that is not a database (or
///    a database that is not a vci store) is `Unavailable`; every read and
///    write is an error, hints are empty, and the file is never changed.
#[test]
fn files_it_cannot_use_fail_every_call() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    {
        let s = store(dir.path());
        put(&s, A, S1, &hex64(1), None, b"x");
        s.set_flag("f");
    }
    raw(&path).pragma_update(None, "user_version", 3).unwrap();
    let newer = store(dir.path());

    let garbage_path = dir.path().join("garbage.sqlite");
    let garbage = "this is not a SQLite database\n".repeat(200);
    std::fs::write(&garbage_path, &garbage).unwrap();
    let not_a_db = SqliteStore::open_path(&garbage_path, opts());

    let foreign_path = dir.path().join("foreign.sqlite");
    raw(&foreign_path)
        .execute_batch("CREATE TABLE metadata (k TEXT); INSERT INTO metadata VALUES ('x');")
        .unwrap();
    let foreign = SqliteStore::open_path(&foreign_path, opts());

    let check = |s: &SqliteStore, ok: &dyn Fn(&StoreError) -> bool| {
        let mut e =
            StoredEnvelope::from_key("project", &key::attestation_key(&hex64(1), S1, &hex64(2)))
                .unwrap();
        let errors = vec![
            s.status().map(|_| ()).unwrap_err(),
            s.list_units(&[A]).map(|_| ()).unwrap_err(),
            s.list_all().map(|_| ()).unwrap_err(),
            s.read_values(&mut [&mut e]).unwrap_err(),
            s.read_units(&[A]).map(|_| ()).unwrap_err(),
            s.manifest(&hex64(1)).map(|_| ()).unwrap_err(),
            s.manifest_roots().map(|_| ()).unwrap_err(),
            s.count().map(|_| ()).unwrap_err(),
            s.orphan_manifests(&[&hex64(1)]).map(|_| ()).unwrap_err(),
            s.put_for_test(B, S1, &hex64(2), None, b"y")
                .map(|_| ())
                .unwrap_err(),
            s.put_manifest(&hex64(3), b"{}").map(|_| ()).unwrap_err(),
            s.remove(vec![e.clone()]).map(|_| ()).unwrap_err(),
            s.remove_manifests(&[&hex64(3)]).map(|_| ()).unwrap_err(),
        ];
        for e in &errors {
            assert!(ok(e), "{e:?}");
            assert!(is_store_unusable(e), "{e:?}");
        }
        assert!(s.passing_on(TREE1).is_empty());
        assert!(!s.flag("f"));
        s.set_flag("g");
        s.remember_passing(TREE1, &[(key::test_key(A), "k".to_owned())]);
    };
    check(&newer, &|e| {
        matches!(
            e,
            StoreError::Incompatible {
                found: 3,
                supported: 2,
                ..
            }
        )
    });
    assert!(
        newer
            .status()
            .unwrap_err()
            .to_string()
            .contains("sqlite store schema version 3 is newer than this vci reads (up to 2)")
    );
    check(&not_a_db, &|e| matches!(e, StoreError::Unavailable { .. }));
    assert!(
        not_a_db
            .status()
            .unwrap_err()
            .to_string()
            .contains("not a database"),
        "{}",
        not_a_db.status().unwrap_err()
    );
    check(&foreign, &|e| matches!(e, StoreError::Unavailable { .. }));
    assert!(
        foreign
            .status()
            .unwrap_err()
            .to_string()
            .contains("not a vci store")
    );
    drop((newer, not_a_db, foreign));

    // Nothing was changed.
    assert_eq!(std::fs::read_to_string(&garbage_path).unwrap(), garbage);
    let c = raw(&path);
    let v: i64 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    let n: i64 = c
        .query_row("SELECT count(*) FROM attestations", [], |r| r.get(0))
        .unwrap();
    let g: Option<String> = c
        .query_row("SELECT name FROM flags WHERE name = 'g'", [], |r| r.get(0))
        .optional()
        .unwrap();
    assert_eq!((v, n, g), (3, 1, None));
    let c = raw(&foreign_path);
    let tables: i64 = c
        .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
        .unwrap();
    let mode: String = c
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!((tables, mode.as_str()), (1, "delete"));
}

/// 10. Six handles writing first at once create one schema, and every
///     write is there.
#[test]
fn concurrent_first_writers_create_the_store_once() {
    for round in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let path = db_path(dir.path());
        let go = Arc::new(Barrier::new(6));
        let threads: Vec<_> = (0..6u8)
            .map(|i| {
                let go = Arc::clone(&go);
                let path = path.clone();
                std::thread::spawn(move || {
                    let s = SqliteStore::open_path(path, opts());
                    go.wait();
                    let root = hex64(100 + i);
                    s.put_manifest(&root, b"{\"v\":2}").unwrap();
                    put(
                        &s,
                        &format!("src/u{i}.test.ts"),
                        S1,
                        &hex64(i + 1),
                        Some(&hint(i64::from(i), None)),
                        &envelope(Some(&root), 100),
                    );
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let s = store(dir.path());
        assert_eq!(s.count().unwrap(), 6, "round {round}");
        assert_eq!(s.manifest_roots().unwrap().len(), 6, "round {round}");
        let c = raw(&path);
        let objects: i64 = c
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let v: i64 = c
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!((objects, v), (5, 1), "round {round}");
    }
}

/// 11. A batch's writes are one transaction: this thread sees them inside
///     the batch, other handles only once `finish()` has committed them; a
///     batch inside the batch joins it, and a dropped batch commits too.
#[test]
fn batch_writes_are_one_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let other = store(dir.path());
    let batch = s.batch().unwrap();
    assert!(batch.defers_writes());
    assert!(!db_path(dir.path()).exists());
    let root = hex64(9);
    assert!(s.put_manifest(&root, b"{\"v\":2}").unwrap());
    let e = put(
        &s,
        A,
        S1,
        &hex64(1),
        Some(&hint(1, None)),
        &envelope(Some(&root), 10),
    );
    assert_eq!(keys(&listed(&s, A)), vec![e.key.clone()]);
    assert!(s.manifest(&root).unwrap().is_some());
    assert!(listed(&other, A).is_empty());
    assert!(other.manifest(&root).unwrap().is_none());
    // A batch inside the batch joins it.
    let inner = s.batch().unwrap();
    put(&s, B, S1, &hex64(2), None, b"b");
    inner.finish().unwrap();
    assert_eq!(other.count().unwrap(), 0);
    put(&s, CARGO, S1, &hex64(3), None, b"c");
    assert_eq!(s.remove(vec![e]).unwrap().len(), 1);
    assert_eq!(s.count().unwrap(), 2);
    assert_eq!(other.count().unwrap(), 0);
    batch.finish().unwrap();
    assert_eq!(other.count().unwrap(), 2);
    assert!(other.manifest(&root).unwrap().is_some());
    assert_eq!(s.timing_report().len(), 1);
    assert!(s.timing_report()[0].starts_with("store: sqlite: "));
    // A dropped batch ends too, and commits.
    let dropped = s.batch().unwrap();
    put(&s, A, S2, &hex64(1), None, b"later");
    drop(dropped);
    assert_eq!(other.count().unwrap(), 3);
    // Writes after the batch commit one by one again.
    put(&s, ROOT_UNIT, S1, &hex64(4), None, b"d");
    assert_eq!(other.count().unwrap(), 4);
}

/// 12. Hints: remember and recall, set and get; memo rows older than a
///     week are forgotten at the next remember.
#[test]
fn hints_round_trip_and_age_out() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let s = store(dir.path());
    put(&s, A, S1, &hex64(1), None, b"x");
    let (ta, tb) = (key::test_key(A), key::test_key(B));
    s.remember_passing(
        TREE1,
        &[(ta.clone(), "ka".into()), (tb.clone(), "kb".into())],
    );
    let memo = s.passing_on(TREE1);
    assert_eq!(memo.get(&ta).map(String::as_str), Some("ka"));
    assert_eq!(memo.get(&tb).map(String::as_str), Some("kb"));
    assert!(s.passing_on(TREE2).is_empty());
    // A later plan on the same tree replaces the unit's key.
    s.remember_passing(TREE1, &[(ta.clone(), "ka2".into())]);
    assert_eq!(s.passing_on(TREE1)[&ta], "ka2");
    assert_eq!(s.passing_on(TREE1)[&tb], "kb");
    // Rows older than seven days go at the next remember.
    raw(&path)
        .execute(
            "UPDATE memo SET at = at - 8 * 24 * 3600 WHERE tree16 = ?1",
            [TREE1],
        )
        .unwrap();
    assert_eq!(s.passing_on(TREE1).len(), 2);
    s.remember_passing(TREE2, &[(ta.clone(), "kt2".into())]);
    assert!(s.passing_on(TREE1).is_empty());
    assert_eq!(s.passing_on(TREE2)[&ta], "kt2");
    s.remember_passing(TREE2, &[]);

    assert!(!s.flag("plan:natives:web"));
    s.set_flag("plan:natives:web");
    s.set_flag("plan:natives:web");
    assert!(s.flag("plan:natives:web"));
    assert!(!s.flag("plan:natives:api"));
    // Another handle sees them.
    let t = store(dir.path());
    assert!(t.flag("plan:natives:web"));
    assert_eq!(t.passing_on(TREE2).len(), 1);
}

/// 13. Once the last handle on the file is dropped, there are no `-wal` or
///     `-shm` files: a cache of the file is the whole store.
#[test]
fn no_wal_files_after_the_last_handle() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let a = store(dir.path());
    let b = store(dir.path());
    let batch = a.batch().unwrap();
    for i in 0..50u8 {
        put(
            &a,
            A,
            S1,
            &hex64(i),
            Some(&hint(i64::from(i), None)),
            &envelope(None, 500),
        );
    }
    batch.finish().unwrap();
    std::thread::scope(|t| {
        for _ in 0..4 {
            t.spawn(|| {
                assert_eq!(read_unit(&b, A).len(), 50);
                b.manifest(&hex64(1)).unwrap();
            });
        }
    });
    b.put_manifest(&hex64(1), b"{\"v\":2}").unwrap();
    b.set_flag("x");
    assert!(!sidecars(&path).is_empty());
    drop(a);
    drop(b);
    assert!(sidecars(&path).is_empty(), "{:?}", sidecars(&path));
    let s = store(dir.path());
    assert_eq!(s.count().unwrap(), 50);
    assert!(s.flag("x"));
}

/// 14. A plan's lookup and batch read of 1,200 units take under 200 ms
///     (release build: `cargo test --release -p vci-store-sqlite -- --ignored`).
#[test]
#[ignore = "timing: run in a release build with --ignored"]
fn twelve_hundred_units_list_and_read_fast() {
    let dir = tempfile::tempdir().unwrap();
    let ids: Vec<String> = (0..1200).map(|i| format!("pkg{i}/x.test.ts")).collect();
    {
        let s = store(dir.path());
        let batch = s.batch().unwrap();
        for (i, id) in ids.iter().enumerate() {
            let root = format!("{:064x}", i + 1);
            s.put_manifest(&root, b"{\"v\":2}").unwrap();
            let sk = format!("{:064x}", i + 10_000);
            put(
                &s,
                id,
                S1,
                &sk,
                Some(&hint(1_700_000_000 + i as i64, Some(TREE1))),
                &envelope(Some(&root), 18_000),
            );
        }
        batch.finish().unwrap();
    }
    let s = store(dir.path());
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let start = Instant::now();
        let mut units = s.list_units(&refs).unwrap();
        let mut all: Vec<&mut StoredEnvelope> = units.iter_mut().flatten().collect();
        assert_eq!(all.len(), 1200);
        s.read_values(&mut all).unwrap();
        assert!(all.iter().all(|e| matches!(e.state(), ValueState::Read(_))));
        best = best.min(start.elapsed());
    }
    eprintln!("list_units + read_values of 1,200 units: {best:?}");
    assert!(best < Duration::from_millis(200), "{best:?}");
}

/// Writes are atomic per call: a put either stores its slot or nothing, and
/// a failing write leaves no transaction open (the next write works).
#[test]
fn a_failed_write_leaves_the_store_usable() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    put(&s, A, S1, &hex64(1), None, b"x");
    // Another connection holds the write lock past the busy timeout.
    let quick = SqliteStore::open_path(
        db_path(dir.path()),
        SqliteOptions {
            busy_timeout: Duration::from_millis(50),
            ..opts()
        },
    );
    let holder = raw(&db_path(dir.path()));
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    let e = quick
        .put_for_test(B, S1, &hex64(2), None, b"y")
        .unwrap_err();
    assert!(matches!(e, StoreError::Timeout { .. }), "{e:?}");
    // Readers do not wait for a writer.
    assert_eq!(quick.count().unwrap(), 1);
    holder.execute_batch("COMMIT").unwrap();
    put(&quick, B, S1, &hex64(2), None, b"y");
    assert_eq!(s.count().unwrap(), 2);
    // NewAttestation::copy_of keeps key and target into another file.
    let copy_dir = tempfile::tempdir().unwrap();
    let copy = store(copy_dir.path());
    for e in s.read_all().unwrap() {
        let h = key::parse_key_hint(&e.key);
        let got = copy.put(&NewAttestation::copy_of(&e, h.as_ref())).unwrap();
        assert_eq!((got.key, got.target), (e.key.clone(), e.target.clone()));
    }
    assert_eq!(
        keys(&copy.list_all().unwrap()),
        keys(&s.list_all().unwrap())
    );
}

/// A file made read-only while a writer's handle is still open (its last
/// writes still in the WAL): a new handle reads them, and its writes are
/// `Denied`.
#[cfg(unix)]
#[test]
fn a_read_only_file_reads_what_the_wal_holds() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let writer = store(dir.path());
    put(&writer, A, S1, &hex64(1), None, b"first");
    put(&writer, B, S1, &hex64(2), None, b"in the wal");
    assert!(!sidecars(&path).is_empty());
    // Only the file is made read-only; the directory stays writable.
    let (_guard, _) = read_only(dir.path(), &[(&path, 0o444)]);
    if std::fs::OpenOptions::new().append(true).open(&path).is_ok() {
        eprintln!("skipping: permissions do not stop this process (root?)");
        return;
    }
    let reader = store(dir.path());
    assert_eq!(
        read_unit(&reader, B)[0].state(),
        ValueState::Read(b"in the wal")
    );
    assert_eq!(reader.count().unwrap(), 2);
    match reader.put_for_test(B, S1, &hex64(3), None, b"no") {
        Err(StoreError::Denied { .. }) => {}
        other => panic!("expected Denied, got {other:?}"),
    }
    reader.set_flag("x");
    assert!(!reader.flag("x"));
}

/// Readers on many threads while one writer puts and removes: no read
/// fails, and every value read is whole.
#[test]
fn concurrent_readers_and_a_writer() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let root = hex64(200);
    s.put_manifest(&root, b"{\"v\":2}").unwrap();
    let units: Vec<String> = (0..20).map(|i| format!("src/r{i}.test.ts")).collect();
    let value = |i: u8| envelope(Some(&root), 3000 + usize::from(i));
    for (i, u) in units.iter().enumerate() {
        put(&s, u, S1, &hex64(i as u8), None, &value(i as u8));
    }
    let done = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|t| {
        for _ in 0..8 {
            t.spawn(|| {
                let ids: Vec<&str> = units.iter().map(String::as_str).collect();
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    let mut listed = s.list_units(&ids).unwrap();
                    let mut refs: Vec<&mut StoredEnvelope> = listed.iter_mut().flatten().collect();
                    s.read_values(&mut refs).unwrap();
                    for e in refs {
                        match e.state() {
                            ValueState::Read(b) => {
                                assert_eq!(
                                    key::envelope_manifest_ref(b),
                                    ManifestRef::Root(root.clone())
                                );
                            }
                            ValueState::Unreadable(why) => assert_eq!(why, GONE),
                            other => panic!("{other:?}"),
                        }
                    }
                    assert!(s.manifest(&root).unwrap().unwrap().is_read());
                }
            });
        }
        let batch = s.batch().unwrap();
        for round in 0..30u8 {
            for (i, u) in units.iter().enumerate() {
                let sk = hex64(i as u8);
                if (usize::from(round) + i) % 3 == 0 {
                    let gone = listed(&s, u);
                    s.remove(gone).unwrap();
                } else {
                    put(
                        &s,
                        u,
                        S1,
                        &sk,
                        Some(&hint(i64::from(round), None)),
                        &value(round),
                    );
                }
            }
        }
        batch.finish().unwrap();
        done.store(true, std::sync::atomic::Ordering::Relaxed);
    });
}

// ---- format 3 (vci 2.9) ---------------------------------------------------------

/// A store file as vci 2.8 left it: schema version 1 without the format-3
/// additions, holding one format-1 record with its manifest.
fn file_of_2_8(path: &Path) -> (StoredEnvelope, String) {
    let c = raw(path);
    c.execute_batch(&vci_store_sqlite::sql::plain().ddl)
        .unwrap();
    c.pragma_update(None, "application_id", 0x7663_6931_i64)
        .unwrap();
    c.pragma_update(None, "user_version", 1).unwrap();
    drop(c);
    assert_eq!(tables(path), ["attestations", "flags", "manifests", "memo"]);
    // The additions are added by a write; a 2.8 file is written through
    // the same store, so make the record with a raw insert instead.
    let root = hex64(0x28);
    let value = envelope(Some(&root), 10);
    let k = key::attestation_key_hinted(&key::test_key(A), S1, &hex64(1), &hint(28, Some(TREE1)));
    let c = raw(path);
    c.execute(
        "INSERT INTO manifests (root, base, put_at, encoding, value) VALUES (?1, NULL, 1, 0, ?2)",
        params![root, b"{\"v\":2}"],
    )
    .unwrap();
    c.execute(
        "INSERT INTO attestations (key, test_key, signer, storage_key, target, issued, tree16,
                                   manifest_ref, ref_state, stored_at, value)
         VALUES (?1, ?2, ?3, ?4, ?5, 28, ?6, ?7, 1, 1, ?8)",
        params![
            k,
            key::test_key(A),
            S1,
            hex64(1),
            "path:src",
            TREE1,
            root,
            value
        ],
    )
    .unwrap();
    let mut e = StoredEnvelope::from_key("path:src", &k).unwrap();
    e.set_value(value);
    (e, root)
}

/// The file's tables, sorted.
fn tables(path: &Path) -> Vec<String> {
    let c = raw(path);
    let mut stmt = c
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap();
    let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
    rows.map(Result::unwrap).collect()
}

/// The attestations table's columns, in order.
fn attestation_columns(path: &Path) -> Vec<String> {
    let c = raw(path);
    let mut stmt = c.prepare("PRAGMA table_info(attestations)").unwrap();
    let rows = stmt.query_map([], |r| r.get::<_, String>(1)).unwrap();
    rows.map(Result::unwrap).collect()
}

fn user_version(path: &Path) -> i64 {
    raw(path)
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap()
}

/// Move these objects' `put_at` back by `secs`, behind the store's back.
fn age(path: &Path, ids: &[&str], secs: i64) {
    let c = raw(path);
    for id in ids {
        assert_eq!(
            c.execute(
                "UPDATE objects SET put_at = put_at - ?2 WHERE id = ?1",
                params![id, secs]
            )
            .unwrap(),
            1,
            "{id}"
        );
    }
}

fn put3(
    s: &dyn AttestationStore,
    unit: &str,
    sk: &str,
    rec: &[u8],
    cols: &Columns,
) -> StoredEnvelope {
    s.put(&NewAttestation::for_test(unit, S1, sk, None, rec).with_columns(cols))
        .unwrap()
}

/// The ten format-3 columns of a row, as SQL gives them.
type RawColumns = (
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn ids_of(got: &[vci_store::StoredObject]) -> Vec<String> {
    got.iter().map(|o| o.id.clone()).collect()
}

/// 15. A file vci 2.8 wrote reads as it did (no object, no columns,
///     version 1) and gets the format-3 columns and the `objects` table
///     from the first write, in a transaction of its own that is committed
///     before the write's batch: another handle sees the additions while
///     the batch is still open and its records only after `finish`. The
///     2.8 record keeps its manifest, reads back and has no columns; the
///     file stays at version 1, so a 2.8 binary still opens it.
#[test]
fn a_file_of_2_8_gets_the_additions_from_the_first_write_before_its_batch() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let (old, root) = file_of_2_8(&path);
    let s = store(dir.path());
    let other = store(dir.path());
    let run = Run3::build(&["src/t15/a.ts"]);
    let (rec, cols) = run.record(A, 1, 15);

    assert_eq!(
        s.status().unwrap(),
        StoreStatus::Ready {
            schema_version: Some(1)
        }
    );
    assert_eq!(keys(&listed(&s, A)), std::slice::from_ref(&old.key));
    assert!(s.get_objects(&run.id_refs()).unwrap().is_empty());
    assert!(s.orphan_objects().unwrap().is_empty());
    assert_eq!(s.columns(&[&old]).unwrap(), [Columns::default()]);
    assert_eq!(tables(&path).len(), 4, "a read adds nothing");

    let batch = s.batch().unwrap();
    assert_eq!(s.put_objects(&run.new_objects()).unwrap(), 4);
    let e = put3(&s, A, &hex64(2), &rec, &cols);
    assert_eq!(s.remove(vec![old.clone()]).unwrap().len(), 1);
    // The DDL is committed; the batch is not.
    assert_eq!(
        tables(&path),
        ["attestations", "flags", "manifests", "memo", "objects"]
    );
    assert!(attestation_columns(&path).ends_with(&[
        "format".to_owned(),
        "commit_id".to_owned(),
        "platform".to_owned(),
        "state".to_owned(),
        "duration_ms".to_owned(),
        "expires".to_owned(),
        "hdr".to_owned(),
        "tables_id".to_owned(),
        "shape".to_owned(),
        "state_obj".to_owned(),
    ]));
    assert_eq!(
        keys(&listed(&other, A)),
        std::slice::from_ref(&old.key),
        "the batch is open"
    );
    assert!(other.get_objects(&run.id_refs()).unwrap().is_empty());
    assert_eq!(
        keys(&listed(&s, A)),
        std::slice::from_ref(&e.key),
        "this thread sees it"
    );
    batch.finish().unwrap();

    assert_eq!(keys(&listed(&other, A)), std::slice::from_ref(&e.key));
    assert_eq!(other.get_objects(&run.id_refs()).unwrap().len(), 4);
    let l = listed(&other, A);
    assert_eq!(
        other.columns(&[&l[0]]).unwrap(),
        std::slice::from_ref(&cols)
    );
    assert_eq!(user_version(&path), 1);
    assert!(other.manifest(&root).unwrap().is_some());
    let got = read_unit(&other, A);
    assert_eq!(got[0].state(), ValueState::Read(&rec));
    // A format-1 record put now has no columns either.
    let e1 = put(&s, B, S1, &hex64(1), None, &envelope(Some(&root), 3));
    assert_eq!(s.columns(&[&e1]).unwrap(), [Columns::default()]);
    let (format, hdr): (Option<i64>, Option<String>) = raw(&path)
        .query_row(
            "SELECT format, hdr FROM attestations WHERE key = ?1",
            [&e1.key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((format, hdr), (None, None));
}

/// 16. `upgrade_begin` adds the additions to a 2.8 file once (true the
///     first time, false after), creates a missing file with them, and is
///     refused on a read-only handle; `upgrade_finish` refuses with the
///     count while a format-1 row remains (the file still at version 1
///     with its manifests), then drops the manifests and sets version 2,
///     after which a vci before 2.9 would report the schema too new,
///     manifests read as none, `put_manifest` is unsupported, records and
///     objects go on, and a second finish says so.
#[test]
fn upgrade_begin_and_finish() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let (old, root) = file_of_2_8(&path);
    let s = store(dir.path());
    assert!(s.upgrade_begin().unwrap(), "added now");
    assert!(!s.upgrade_begin().unwrap(), "there already");
    assert_eq!(tables(&path).len(), 5);
    assert_eq!(user_version(&path), 1);
    let ro = SqliteStore::open_path(
        &path,
        SqliteOptions {
            read_only: true,
            ..opts()
        },
    );
    assert!(matches!(
        ro.upgrade_begin().unwrap_err(),
        StoreError::Denied { .. }
    ));
    assert!(matches!(
        ro.upgrade_finish().unwrap_err(),
        StoreError::Denied { .. }
    ));

    // A missing file is created with the additions by `--begin`, and not
    // by `--finish`.
    let fresh_dir = tempfile::tempdir().unwrap();
    let fresh = store(fresh_dir.path());
    assert!(matches!(
        fresh.upgrade_finish().unwrap_err(),
        StoreError::Unavailable { .. }
    ));
    assert!(!db_path(fresh_dir.path()).exists());
    assert!(!fresh.upgrade_begin().unwrap());
    assert_eq!(tables(&db_path(fresh_dir.path())).len(), 5);
    assert_eq!(fresh.upgrade_finish().unwrap(), Finish::Finished);
    assert_eq!(
        fresh.status().unwrap(),
        StoreStatus::Ready {
            schema_version: Some(2)
        }
    );

    // The 2.8 file: refused while its format-1 record is there.
    let run = Run3::build(&["src/t16/a.ts"]);
    let (rec, cols) = run.record(A, 1, 16);
    s.put_objects(&run.new_objects()).unwrap();
    let e3 = put3(&s, B, &hex64(2), &rec, &cols);
    assert_eq!(s.upgrade_finish().unwrap(), Finish::FormatOneRows(1));
    assert_eq!(user_version(&path), 1);
    assert!(s.manifest(&root).unwrap().is_some());
    assert_eq!(s.remove(vec![old]).unwrap().len(), 1);
    assert_eq!(s.upgrade_finish().unwrap(), Finish::Finished);
    assert_eq!(user_version(&path), 2);
    assert_eq!(
        tables(&path),
        ["attestations", "flags", "memo", "objects"],
        "the manifests are dropped"
    );
    assert_eq!(s.upgrade_finish().unwrap(), Finish::AlreadyFinished);
    assert!(!s.upgrade_begin().unwrap());

    // The handle that finished, and a new one.
    for h in [&s, &store(dir.path())] {
        assert_eq!(
            h.status().unwrap(),
            StoreStatus::Ready {
                schema_version: Some(2)
            }
        );
        assert!(h.manifest(&root).unwrap().is_none());
        assert_eq!(h.manifests(&[&root]).unwrap(), [None]);
        assert!(h.manifest_roots().unwrap().is_empty());
        assert_eq!(
            h.orphan_manifests(&[&root]).unwrap(),
            std::slice::from_ref(&root)
        );
        assert_eq!(h.remove_manifests(&[&root]).unwrap(), 0);
        assert!(matches!(
            h.put_manifest(&root, b"{}").unwrap_err(),
            StoreError::Unsupported { .. }
        ));
        assert_eq!(keys(&read_unit(h, B)), std::slice::from_ref(&e3.key));
        assert_eq!(h.get_objects(&run.id_refs()).unwrap().len(), 4);
        let l = listed(h, B);
        assert_eq!(h.columns(&[&l[0]]).unwrap(), std::slice::from_ref(&cols));
    }
    let (rec2, cols2) = run.record(A, 1, 17);
    let e4 = put3(&s, A, &hex64(3), &rec2, &cols2);
    assert_eq!(keys(&listed(&store(dir.path()), A)), [e4.key]);
    assert_eq!(s.count().unwrap(), 2);
}

/// 17. Objects are BLOBs filed under their id with their kind and
///     `put_at`, which an idempotent put refreshes; the columns of a put
///     are on the record's row, `NULL` where the put had none; an empty
///     put, a removal and a state prune on a missing file create nothing.
#[test]
fn objects_are_blobs_and_columns_are_on_the_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let s = store(dir.path());
    assert_eq!(s.put_objects(&[]).unwrap(), 0);
    assert_eq!(s.remove_objects(&[&hex64(1)]).unwrap(), 0);
    assert_eq!(s.prune_state_objects(Duration::ZERO).unwrap(), 0);
    assert!(s.orphan_objects().unwrap().is_empty());
    assert!(!path.exists(), "nothing to write, nothing created");

    let run = Run3::build(&["src/t17/b.ts", "src/t17/a.ts"]);
    let objects = run.new_objects();
    assert_eq!(
        s.put_objects(&[objects[0], objects[0], objects[1]])
            .unwrap(),
        2
    );
    assert_eq!(s.put_objects(&objects).unwrap(), 2);
    let rows = |id: &str| -> (String, i64, i64, Vec<u8>) {
        raw(&path)
            .query_row(
                "SELECT typeof(bytes), kind, put_at, bytes FROM objects WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap()
    };
    for (i, (kind, bytes)) in run.objects.iter().enumerate() {
        let (ty, k, _, b) = rows(run.id_refs()[i]);
        assert_eq!(
            (ty.as_str(), k, &b),
            ("blob", i64::from(*kind as u8), bytes)
        );
    }
    age(&path, &[&run.ids.hdr], 1000);
    let before = rows(&run.ids.hdr).2;
    assert_eq!(s.put_objects(&objects[..1]).unwrap(), 0);
    assert!(rows(&run.ids.hdr).2 >= before + 1000, "put_at refreshed");

    let (rec, cols) = run.record(A, 2, 17);
    let e = put3(&s, A, &hex64(1), &rec, &cols);
    let row: RawColumns = raw(&path)
        .query_row(
            "SELECT format, commit_id, platform, state, duration_ms, expires, hdr, tables_id,
                    shape, state_obj FROM attestations WHERE key = ?1",
            [&e.key],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        row,
        (
            Some(3),
            cols.commit.clone(),
            cols.platform.clone(),
            cols.state.clone(),
            cols.duration_ms.map(|n| n as i64),
            cols.expires,
            cols.hdr.clone(),
            cols.tables.clone(),
            cols.shape.clone(),
            cols.state_obj.clone()
        )
    );
    let partial = Columns {
        format: Some(3),
        hdr: Some(run.ids.hdr.clone()),
        ..Columns::default()
    };
    put3(&s, A, &hex64(1), &rec, &partial);
    assert_eq!(s.columns(&[&e]).unwrap(), [partial]);
    let (state, shape): (Option<String>, Option<String>) = raw(&path)
        .query_row(
            "SELECT state, shape FROM attestations WHERE key = ?1",
            [&e.key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((state, shape), (None, None));
}

/// 18. An answer past `MAX_OBJECTS_ANSWER` is refused before a byte is
///     read (`Invalid`, what `objects`); each object alone reads. A row
///     whose id is not an object id is foreign: never answered, listed or
///     removed. A row under an object id whose kind column names no kind
///     is not answered (it has no kind), but the orphan rule goes by id
///     and referrers alone, so it is collected like any other.
#[test]
fn the_answer_cap_and_foreign_object_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let s = store(dir.path());
    let run = Run3::build(&["src/t18/a.ts"]);
    s.put_objects(&run.new_objects()).unwrap();
    let big1 = hex64(0xb1);
    let big2 = hex64(0xb2);
    let odd_kind = hex64(0x99);
    let c = raw(&path);
    let now = "strftime('%s', 'now')";
    for id in [&big1, &big2] {
        c.execute(
            &format!(
                "INSERT INTO objects (id, kind, put_at, bytes) VALUES (?1, 4, {now}, zeroblob(40 << 20))"
            ),
            [id],
        )
        .unwrap();
    }
    c.execute(
        &format!("INSERT INTO objects (id, kind, put_at, bytes) VALUES (?1, 9, {now}, X'766f09')"),
        [&odd_kind],
    )
    .unwrap();
    c.execute(
        &format!(
            "INSERT INTO objects (id, kind, put_at, bytes) VALUES ('not-an-id', 1, {now}, X'766f01')"
        ),
        [],
    )
    .unwrap();
    drop(c);
    match s.get_objects(&[&run.ids.hdr, &big1, &big2]) {
        Err(StoreError::Invalid {
            what: "objects", ..
        }) => {}
        other => panic!("{other:?}"),
    }
    let one = s.get_objects(&[&big1, &odd_kind]).unwrap();
    assert_eq!(ids_of(&one), std::slice::from_ref(&big1));
    assert_eq!(one[0].bytes.len(), 40 << 20);
    assert_eq!(
        ids_of(&s.get_objects(&[&odd_kind, &run.ids.hdr]).unwrap()),
        std::slice::from_ref(&run.ids.hdr)
    );
    // Aged, the foreign rows are no orphans; the big ones are.
    assert!(s.orphan_objects().unwrap().is_empty());
    let grace = OBJECT_GRACE.as_secs() as i64 * 2;
    age(&path, &[&run.ids.hdr, &odd_kind, &big1, &big2], grace);
    raw(&path)
        .execute(
            "UPDATE objects SET put_at = put_at - ?1 WHERE id = 'not-an-id'",
            [grace],
        )
        .unwrap();
    let mut want = vec![
        big1.clone(),
        big2.clone(),
        odd_kind.clone(),
        run.ids.hdr.clone(),
    ];
    want.sort();
    assert_eq!(s.orphan_objects().unwrap(), want);
    assert_eq!(s.remove_objects(&[&odd_kind, &big1, &big2]).unwrap(), 3);
    let left: i64 = raw(&path)
        .query_row("SELECT count(*) FROM objects", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 5, "the four of the run and the foreign row");
    assert_eq!(
        s.prune_state_objects(Duration::ZERO).unwrap(),
        1,
        "the run's state object"
    );
}

/// 19. The orphan rule reads each of the four referrer columns: a record
///     naming an object in its `hdr`, `tables`, `shape` or `state_obj`
///     column alone keeps it past the grace, and only its removal frees
///     it; `prune_state_objects` goes by the kind column, not by a referrer.
#[test]
fn each_referrer_column_keeps_its_object() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let s = store(dir.path());
    let run = Run3::build(&["src/t19/a.ts"]);
    s.put_objects(&run.new_objects()).unwrap();
    let (rec, _) = run.record(A, 1, 19);
    let by = |c: Columns| c;
    let referrers = [
        by(Columns {
            hdr: Some(run.ids.hdr.clone()),
            ..Columns::default()
        }),
        by(Columns {
            tables: Some(run.ids.tables.clone()),
            ..Columns::default()
        }),
        by(Columns {
            shape: Some(run.ids.shape.clone()),
            ..Columns::default()
        }),
        by(Columns {
            state_obj: Some(run.ids.state.clone()),
            ..Columns::default()
        }),
    ];
    let records: Vec<StoredEnvelope> = referrers
        .iter()
        .enumerate()
        .map(|(i, c)| put3(&s, A, &hex64(i as u8 + 1), &rec, c))
        .collect();
    age(&path, &run.id_refs(), OBJECT_GRACE.as_secs() as i64 * 2);
    assert!(s.orphan_objects().unwrap().is_empty());
    assert_eq!(s.remove_objects(&run.id_refs()).unwrap(), 0);
    for (i, e) in records.iter().enumerate() {
        s.remove(vec![e.clone()]).unwrap();
        assert_eq!(s.orphan_objects().unwrap(), [run.id_refs()[i].to_owned()]);
        assert_eq!(s.remove_objects(&run.id_refs()).unwrap(), 1);
    }
    assert!(s.get_objects(&run.id_refs()).unwrap().is_empty());
}

/// 20. Inside a batch an object removal is applied at once, in the batch's
///     transaction: this thread no longer reads the object, another handle
///     still does until `finish`; the batch's own objects, just put (an
///     idempotent put of an aged one included), are within their grace and
///     stay.
#[test]
fn an_object_removal_in_a_batch_is_applied_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let s = store(dir.path());
    let other = store(dir.path());
    // Two runs share their hdr and tables (the same toolchain and tables)
    // and differ in shape and state.
    let old = Run3::build(&["src/t20/old.ts"]);
    let new = Run3::build(&["src/t20/new.ts"]);
    assert_eq!(
        (&old.ids.hdr, &old.ids.tables),
        (&new.ids.hdr, &new.ids.tables)
    );
    assert_ne!(old.ids.shape, new.ids.shape);
    s.put_objects(&old.new_objects()).unwrap();
    age(&path, &old.id_refs(), OBJECT_GRACE.as_secs() as i64 * 2);

    let batch = s.batch().unwrap();
    assert_eq!(
        s.put_objects(&new.new_objects()).unwrap(),
        2,
        "the shape and the state"
    );
    let (rec, cols) = new.record(A, 1, 20);
    put3(&s, A, &hex64(1), &rec, &cols);
    let mut all: Vec<&str> = old.id_refs();
    all.extend([new.ids.shape.as_str(), new.ids.state.as_str()]);
    assert_eq!(
        s.remove_objects(&all).unwrap(),
        2,
        "the old shape and state: aged and unreferenced"
    );
    assert_eq!(ids_of(&s.get_objects(&all).unwrap()), new.id_refs());
    assert_eq!(ids_of(&other.get_objects(&all).unwrap()), old.id_refs());
    batch.finish().unwrap();
    assert_eq!(ids_of(&other.get_objects(&all).unwrap()), new.id_refs());
}
