//! The PostgreSQL backend's own tests (store plan step C, tests 1 to 15).
//!
//! Tests 1 and 2 need no server. The others need one
//! (`VCI_TEST_POSTGRES_URL`, see `common`) and are skipped, saying so,
//! without it.

mod common;

use std::sync::Barrier;
use std::time::{Duration, Instant};

use common::{cx, cx_for, pg, selection};
use vci_store::select::{Source, Sourced};
use vci_store::{
    AttestationStore, KeyHint, ManifestRef, Prefetch, StoreError, StoreStatus, StoredEnvelope,
    ValueState, key,
};
use vci_store_postgres::PgStore;

const S1: &str = "1111111111111111";
const S2: &str = "2222222222222222";
const UNIT_A: &str = "src/a.test.ts";
const UNIT_B: &str = "src/b.test.ts";
const UNIT_C: &str = "rust/core#test:it";
const UNIT_ROOT: &str = ".";
const TREE: &str = "0123456789abcdef";

fn hex64(seed: usize) -> String {
    format!("{seed:064x}")
}

fn hint(issued: i64) -> KeyHint {
    KeyHint {
        issued,
        tree: Some(TREE.to_owned()),
    }
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// A DSSE-shaped envelope whose payload references `manifest_root`
/// (`predicate.manifestRef`; `None` writes `null`, an inline manifest).
fn envelope(manifest_root: Option<&str>, pad: usize) -> Vec<u8> {
    let payload = serde_json::json!({
        "predicate": {"manifestRef": manifest_root},
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

/// Compact manifest bytes (only `v` and `base` are read by the store).
fn manifest(tag: &str, base: Option<&str>) -> Vec<u8> {
    let mut m = serde_json::json!({"v": 2, "entries": [], "externals": [], "env": [], "tag": tag});
    if let Some(b) = base {
        m["base"] = serde_json::Value::String(b.to_owned());
    }
    m.to_string().into_bytes()
}

fn keys(l: &[StoredEnvelope]) -> Vec<String> {
    l.iter().map(|e| e.key.clone()).collect()
}

fn read_bytes(s: &PgStore, id: &str) -> Vec<(String, Vec<u8>)> {
    let mut l = s.list_units(&[id]).unwrap().remove(0);
    for e in &l {
        assert_eq!(e.state(), ValueState::Unread, "listings are key-only");
    }
    let mut refs: Vec<&mut StoredEnvelope> = l.iter_mut().collect();
    s.read_values(&mut refs).unwrap();
    l.into_iter().map(|e| (e.key, e.bytes)).collect()
}

fn root_ref(bytes: &[u8]) -> String {
    match key::envelope_manifest_ref(bytes) {
        ManifestRef::Root(r) => r,
        other => panic!("no manifest root: {other:?}"),
    }
}

// ---- 1, 2: no server ---------------------------------------------------------------

/// Test 1: a closed port fails within the connect timeout, then at once,
/// and no text shows the password.
#[test]
fn an_unreachable_server_fails_fast_and_shows_no_secret() {
    let mut sel = selection("postgres://u:s3cret-c@127.0.0.1:1/x", "vci", "t");
    sel.connect_timeout = Sourced {
        value: Duration::from_secs(1),
        source: Source::Env("VCI_STORE_CONNECT_TIMEOUT_SECS"),
    };
    let s = PgStore::open(&sel, &cx()).unwrap();
    let t = Instant::now();
    let first = s.list_units(&[UNIT_A]).unwrap_err();
    assert!(
        matches!(
            first,
            StoreError::Unavailable { .. } | StoreError::Timeout { .. }
        ),
        "{first:?}"
    );
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    let t = Instant::now();
    let mut texts = vec![first.to_string(), format!("{first:?}")];
    for _ in 0..40 {
        let e = s.list_units(&[UNIT_A]).unwrap_err();
        assert!(matches!(e, StoreError::Unavailable { .. }), "{e:?}");
        texts.push(e.to_string());
    }
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert!(s.passing_on(TREE).is_empty());
    assert!(!s.flag("plan:natives:p"));
    s.remember_passing(TREE, &[(key::test_key(UNIT_A), hex64(1))]);
    s.set_flag("plan:natives:p");
    s.warm();
    let env = envelope(None, 10);
    let errors = [
        s.status().map(|_| ()),
        s.list_all().map(|_| ()),
        s.count().map(|_| ()),
        s.manifest(&hex64(1)).map(|_| ()),
        s.manifest_roots().map(|_| ()),
        s.put_for_test(UNIT_A, S1, &hex64(1), Some(&hint(1)), &env)
            .map(|_| ()),
        s.put_manifest(&hex64(1), &manifest("m", None)).map(|_| ()),
        s.remove_manifests(&[&hex64(1)]).map(|_| ()),
        s.orphan_manifests(&[&hex64(1)]).map(|_| ()),
        s.batch().map(|_| ()),
        s.prefetch(Prefetch::Units {
            test_ids: &[UNIT_A],
            choose: None,
        })
        .map(|_| ()),
    ];
    for e in errors {
        let e = e.expect_err("every call fails");
        texts.push(e.to_string());
        texts.push(format!("{e:?}"));
    }
    texts.push(format!("{s:?}"));
    texts.push(s.location());
    for t in &texts {
        assert!(!t.contains("s3cret-c"), "the password shows in {t:?}");
    }
    assert!(
        s.location()
            .starts_with("postgres://***@127.0.0.1:1/x schema vci namespace t")
    );
}

/// Test 2: what vci does to the URL before the client library sees it.
#[test]
fn url_handling() {
    let open = |url: &str| PgStore::open(&selection(url, "vci", "t"), &cx());
    // sslrootcert is vci's to read (the client library refuses it).
    let s = open("postgres://u:pw@db.example:5432/x?sslrootcert=%2Fetc%2Fvci%2Fca.pem").unwrap();
    let c = s.__connection_for_test();
    assert_eq!(
        c.root_cert.as_deref(),
        Some(std::path::Path::new("/etc/vci/ca.pem"))
    );
    assert_eq!(c.ssl_mode, "require");
    // The sslmode default: require, except on this machine.
    for (url, mode) in [
        ("postgres://u@db.example/x", "require"),
        ("postgresql://u@10.0.0.1/x", "require"),
        ("postgres://u@127.0.0.1/x", "prefer"),
        ("postgres://u@localhost:5433/x", "prefer"),
        ("postgres://u@[::1]/x", "prefer"),
        ("postgres://u@db.example/x?sslmode=disable", "disable"),
        ("postgres://u@db.example/x?sslmode=verify-full", "require"),
        ("host=db.example user=u dbname=x", "require"),
        ("host=localhost user=u dbname=x", "prefer"),
    ] {
        assert_eq!(
            open(url).unwrap().__connection_for_test().ssl_mode,
            mode,
            "{url}"
        );
    }
    // vci's session settings follow the URL's own options.
    let c = open("postgres://u@db.example/x?options=-c%20search_path%3Dz")
        .unwrap()
        .__connection_for_test();
    assert!(
        c.options
            .starts_with("-c search_path=z -c statement_timeout=30000 -c lock_timeout=10000"),
        "{}",
        c.options
    );
    // A malformed URL is a Config error that does not show the password.
    for url in [
        "postgres://u:s3cret-c@db.example:notaport/x",
        "postgres://u:s3cret-c@db.example/x?bogus=1",
        "postgres://u:s3cret-c@db.example/x?sslmode=sometimes",
        "postgres://u:s3cret-c@/x",
    ] {
        match open(url) {
            Err(StoreError::Config(m)) => assert!(!m.contains("s3cret-c"), "{m}"),
            Err(e) => panic!("{url}: expected Config, got {e:?}"),
            Ok(_) => panic!("{url}: expected Config, got a store"),
        }
    }
    // A schema that is not a lowercase identifier.
    for schema in ["Vci", "vci-store", "x; DROP TABLE y", "", &"a".repeat(64)] {
        let sel = selection("postgres://u@db.example/x", schema, "t");
        assert!(
            matches!(PgStore::open(&sel, &cx()), Err(StoreError::Config(_))),
            "{schema:?}"
        );
    }
    // A sslrootcert file that cannot be read fails the first call, as a
    // setting does.
    let s =
        open("postgres://u@127.0.0.1:1/x?sslmode=require&sslrootcert=/nonexistent/ca.pem").unwrap();
    match s.status() {
        Err(StoreError::Config(m)) => assert!(m.contains("sslrootcert"), "{m}"),
        other => panic!("expected Config, got {other:?}"),
    }
}

// ---- 3 to 15: with a server ----------------------------------------------------------

/// Test 3: values come back byte for byte; one record per slot.
#[test]
fn round_trip_and_slot_replacement() {
    let Some(db) = pg() else { return };
    let s = db.open();
    assert_eq!(s.list_units(&["no/such.test"]).unwrap(), vec![vec![]]);
    let five_k: Vec<u8> = "a\tb\r\nc ".repeat(800).into_bytes();
    let two_hundred_k: Vec<u8> = "x\ty\n".repeat(50_000).into_bytes();
    let a = s
        .put_for_test(UNIT_A, S1, &hex64(1), Some(&hint(10)), &five_k)
        .unwrap();
    let b = s
        .put_for_test(UNIT_B, S1, &hex64(2), Some(&hint(10)), &two_hundred_k)
        .unwrap();
    assert_eq!(a.bytes, five_k);
    assert_eq!(a.target, "path:src/a.test.ts");
    assert_eq!(
        read_bytes(&s, UNIT_A),
        vec![(a.key.clone(), five_k.clone())]
    );
    assert_eq!(
        read_bytes(&db.open(), UNIT_B),
        vec![(b.key.clone(), two_hundred_k)]
    );
    // The provided read_units agrees with list then read.
    let mut units = s.read_units(&[UNIT_A, UNIT_B, UNIT_A]).unwrap();
    assert_eq!(units.len(), 3);
    assert_eq!(units.remove(0)[0].bytes, five_k);
    // An identical put writes nothing.
    let at = |k: &str| -> String {
        db.query(&format!(
            "SELECT stored_at::text FROM {{schema}}.attestations WHERE key = '{k}'"
        ))[0]
            .get(0)
    };
    let before = at(&a.key);
    std::thread::sleep(Duration::from_millis(20));
    let again = s
        .put_for_test(UNIT_A, S1, &hex64(1), Some(&hint(10)), &five_k)
        .unwrap();
    assert_eq!(again.key, a.key);
    assert_eq!(at(&a.key), before, "an identical put is a no-op");
    // New bytes replace.
    s.put_for_test(UNIT_A, S1, &hex64(1), Some(&hint(10)), b"new")
        .unwrap();
    assert_eq!(
        read_bytes(&db.open(), UNIT_A),
        vec![(a.key.clone(), b"new".to_vec())]
    );
    assert_ne!(at(&a.key), before);
    // A newer hint replaces the slot's record.
    let newer = s
        .put_for_test(UNIT_A, S1, &hex64(1), Some(&hint(20)), b"newer")
        .unwrap();
    assert_ne!(newer.key, a.key);
    assert_eq!(
        keys(&db.open().list_units(&[UNIT_A]).unwrap()[0]),
        vec![newer.key.clone()]
    );
    // An unhinted put keeps the slot's key.
    let kept = s
        .put_for_test(UNIT_A, S1, &hex64(1), None, b"unhinted")
        .unwrap();
    assert_eq!(kept.key, newer.key);
    assert_eq!(kept.issued, Some(20));
    assert_eq!(
        read_bytes(&db.open(), UNIT_A),
        vec![(newer.key.clone(), b"unhinted".to_vec())]
    );
    // An unhinted put of a new slot takes the plain key.
    let plain = s
        .put_for_test(UNIT_A, S1, &hex64(3), None, b"plain")
        .unwrap();
    assert_eq!(
        plain.key,
        key::attestation_key(&key::test_key(UNIT_A), S1, &hex64(3))
    );
    // Another signer has its own slot.
    s.put_for_test(UNIT_A, S2, &hex64(1), Some(&hint(20)), b"s2")
        .unwrap();
    assert_eq!(db.open().list_units(&[UNIT_A]).unwrap()[0].len(), 3);
    // 16 handles putting one slot at once leave one row (different keys,
    // then the same key).
    for same_key in [false, true] {
        let handles: Vec<PgStore> = (0..16).map(|_| db.open()).collect();
        let barrier = Barrier::new(handles.len());
        std::thread::scope(|sc| {
            for (i, h) in handles.iter().enumerate() {
                let barrier = &barrier;
                sc.spawn(move || {
                    let issued = if same_key { 7 } else { 100 + i as i64 };
                    barrier.wait();
                    h.put_for_test(
                        UNIT_C,
                        S1,
                        &hex64(9),
                        Some(&hint(issued)),
                        format!("value {i}").as_bytes(),
                    )
                    .unwrap();
                });
            }
        });
        assert_eq!(
            db.count(&format!(
                "SELECT count(*) FROM {{schema}}.attestations WHERE test_key = '{}'",
                key::test_key(UNIT_C)
            )),
            1,
            "same key: {same_key}"
        );
    }
}

/// Test 4: listings are in bytewise order, also in a database whose
/// collation is en_US.
#[test]
fn listings_are_in_bytewise_order() {
    let Some(db) = pg() else { return };
    let check = |s: &PgStore| {
        let tk = key::test_key(UNIT_A);
        // `…:aa:ff.-` sorts before `…:aaf0:1.-` bytewise, after it in en_US
        // (which skips `:`, `.` and `-` at its first level).
        let k1 = s
            .put_for_test(
                UNIT_A,
                S1,
                "aaf0",
                Some(&KeyHint {
                    issued: 1,
                    tree: None,
                }),
                b"1",
            )
            .unwrap();
        let k2 = s
            .put_for_test(
                UNIT_A,
                S1,
                "aa",
                Some(&KeyHint {
                    issued: 0xff,
                    tree: None,
                }),
                b"2",
            )
            .unwrap();
        assert!(k2.key.ends_with(":aa:ff.-") && k1.key.ends_with(":aaf0:1.-"));
        assert_eq!(
            keys(&s.list_units(&[UNIT_A]).unwrap()[0]),
            vec![k2.key.clone(), k1.key.clone()],
            "unit {tk}"
        );
        for (id, sk) in [(UNIT_ROOT, "bb"), (UNIT_C, "cc"), (UNIT_B, "dd")] {
            s.put_for_test(id, S1, sk, Some(&hint(1)), b"x").unwrap();
        }
        let all: Vec<(String, String)> = s
            .list_all()
            .unwrap()
            .into_iter()
            .map(|e| (e.target, e.key))
            .collect();
        let mut sorted = all.clone();
        sorted.sort();
        assert_eq!(all, sorted, "list_all is by (target, key), bytewise");
        assert_eq!(all.len(), 5);
    };
    check(&db.open());
    // A database whose own collation orders these keys the other way. glibc's
    // en_US does; macOS's libc en_US is bytewise for them, so an ICU en-US
    // database that skips punctuation (`ka-shifted`) stands in there.
    let mut exercised = false;
    for (suffix, options) in [
        (
            "en",
            "LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8' TEMPLATE template0",
        ),
        (
            "icu",
            "LOCALE_PROVIDER icu ICU_LOCALE 'en-US-u-ka-shifted' LOCALE 'en_US.UTF-8' TEMPLATE template0",
        ),
    ] {
        if exercised {
            break;
        }
        let url = match db.database(suffix, options) {
            Ok(url) => url,
            Err(e) => {
                eprintln!("skipping the {suffix} database: {e}");
                continue;
            }
        };
        let mut c = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        let linguistic: bool = c
            .query_one("SELECT 'aa:ff.-' > 'aaf0:1.-'", &[])
            .unwrap()
            .get(0);
        drop(c);
        check(&PgStore::open(&selection(&url, &db.schema, "test"), &cx()).unwrap());
        if linguistic {
            exercised = true;
        } else {
            eprintln!("note: the {suffix} database orders these keys bytewise too");
        }
    }
    if !exercised {
        eprintln!("note: no database here orders these keys linguistically");
    }
}

/// Test 5: twenty handles writing first at once create one schema.
#[test]
fn concurrent_first_writes_create_the_schema_once() {
    let Some(db) = pg() else { return };
    let handles: Vec<PgStore> = (0..20).map(|_| db.open()).collect();
    let barrier = Barrier::new(handles.len());
    std::thread::scope(|sc| {
        for (i, h) in handles.iter().enumerate() {
            let barrier = &barrier;
            sc.spawn(move || {
                barrier.wait();
                h.put_for_test(
                    &format!("src/u{i}.test.ts"),
                    S1,
                    &hex64(i),
                    Some(&hint(1)),
                    &envelope(None, 10),
                )
                .unwrap();
            });
        }
    });
    assert!(db.schema_exists());
    assert_eq!(db.count("SELECT count(*) FROM {schema}.schema_version"), 1);
    assert_eq!(db.count("SELECT count(*) FROM {schema}.attestations"), 20);
    assert_eq!(db.open().count().unwrap(), 20);
}

/// Test 6: a role that cannot create the schema reads an absent store and
/// cannot write; a newer schema is incompatible.
#[test]
fn absent_not_initialized_and_incompatible() {
    let Some(db) = pg() else { return };
    let url = db.role("nocreate", "");
    let s = db.open_as(&url);
    match s.status().unwrap() {
        StoreStatus::Absent { advice } => assert!(advice.contains(&db.schema), "{advice}"),
        other => panic!("expected Absent, got {other:?}"),
    }
    assert_eq!(
        s.list_units(&[UNIT_A, UNIT_B]).unwrap(),
        vec![vec![], vec![]]
    );
    assert!(s.list_all().unwrap().is_empty());
    assert!(s.read_all().unwrap().is_empty());
    assert!(s.read_units(&[UNIT_A]).unwrap()[0].is_empty());
    assert_eq!(s.count().unwrap(), 0);
    assert!(s.manifest(&hex64(1)).unwrap().is_none());
    assert_eq!(s.manifests(&[&hex64(1)]).unwrap(), vec![None]);
    assert!(s.manifest_roots().unwrap().is_empty());
    assert_eq!(s.orphan_manifests(&[&hex64(1)]).unwrap(), vec![hex64(1)]);
    s.prefetch(Prefetch::Units {
        test_ids: &[UNIT_A],
        choose: None,
    })
    .unwrap();
    s.prefetch(Prefetch::Manifests {
        roots: &[&hex64(1)],
    })
    .unwrap();
    assert!(s.passing_on(TREE).is_empty());
    assert!(!s.flag("plan:natives:p"));
    s.remember_passing(TREE, &[(key::test_key(UNIT_A), hex64(1))]);
    s.set_flag("plan:natives:p");
    assert_eq!(s.remove(Vec::new()).unwrap(), Vec::new());
    assert!(!db.schema_exists(), "reading created nothing");
    match s.put_for_test(UNIT_A, S1, &hex64(1), Some(&hint(1)), b"x") {
        Err(StoreError::NotInitialized { advice, .. }) => assert!(advice.contains(&db.schema)),
        other => panic!("expected NotInitialized, got {other:?}"),
    }
    match s.put_manifest(&hex64(1), &manifest("m", None)) {
        Err(StoreError::NotInitialized { .. }) => {}
        other => panic!("expected NotInitialized, got {other:?}"),
    }
    assert!(!db.schema_exists());
    // A schema newer than this vci.
    db.open()
        .put_for_test(UNIT_A, S1, &hex64(1), Some(&hint(1)), b"x")
        .unwrap();
    db.sql("UPDATE {schema}.schema_version SET version = 99");
    let fresh = db.open();
    match fresh.status() {
        Err(StoreError::Incompatible {
            found: 99,
            supported: 1,
            ..
        }) => {}
        other => panic!("expected Incompatible, got {other:?}"),
    }
    assert!(matches!(
        fresh.put_for_test(UNIT_A, S1, &hex64(2), Some(&hint(1)), b"x"),
        Err(StoreError::Incompatible { .. })
    ));
    assert!(matches!(
        fresh.list_units(&[UNIT_A]),
        Err(StoreError::Incompatible { .. })
    ));
    let writer = db.open();
    assert!(matches!(
        writer.put_manifest(&hex64(3), &manifest("m", None)),
        Err(StoreError::Incompatible { .. })
    ));
}

/// Test 7: a statement over the timeout is a Timeout, and later calls fail
/// at once.
#[test]
fn a_statement_timeout_latches_the_breaker() {
    let Some(db) = pg() else { return };
    let s = db.open_with(|sel| {
        sel.timeout = Sourced {
            value: Duration::from_secs(1),
            source: Source::File,
        }
    });
    assert!(
        s.__connection_for_test()
            .options
            .contains("statement_timeout=1000")
    );
    s.status().unwrap();
    let t = Instant::now();
    match s.__sleep_for_test(3.0) {
        Err(StoreError::Timeout {
            operation: "a statement",
            after,
            ..
        }) => assert_eq!(after, Duration::from_secs(1)),
        other => panic!("expected Timeout, got {other:?}"),
    }
    assert!(
        t.elapsed() < Duration::from_millis(2500),
        "{:?}",
        t.elapsed()
    );
    let t = Instant::now();
    for _ in 0..40 {
        assert!(matches!(
            s.list_units(&[UNIT_A]),
            Err(StoreError::Unavailable { .. })
        ));
    }
    assert!(
        t.elapsed() < Duration::from_millis(500),
        "{:?}",
        t.elapsed()
    );
    assert!(s.passing_on(TREE).is_empty());
}

/// Test 8: after the plan's prefetch, its reads cost no statement, and a
/// whole plan-shaped run takes at most 15.
#[test]
fn a_plan_costs_a_bounded_number_of_statements() {
    let Some(db) = pg() else { return };
    const UNITS: usize = 1_200;
    const BASES: usize = 12;
    let ids: Vec<String> = (0..UNITS).map(|i| format!("src/u{i:04}.test.ts")).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let base_root = |j: usize| hex64(900_000 + j);
    let root = |i: usize, k: usize| hex64(1_000_000 + i * 3 + k);
    {
        let seed = db.open();
        let b = seed.batch().unwrap();
        for j in 0..BASES {
            seed.put_manifest(&base_root(j), &manifest(&format!("base {j}"), None))
                .unwrap();
        }
        for (i, id) in ids.iter().enumerate() {
            for k in 0..3 {
                let r = root(i, k);
                seed.put_manifest(&r, &manifest(&r, Some(&base_root(i % BASES))))
                    .unwrap();
                seed.put_for_test(
                    id,
                    S1,
                    &hex64(i * 3 + k),
                    Some(&hint(100 + k as i64)),
                    &envelope(Some(&r), 300),
                )
                .unwrap();
            }
        }
        b.finish().unwrap();
        seed.set_flag("plan:natives:p");
    }
    let p = db.open();
    assert_eq!(p.statements(), 0);
    let newest = |c: &[StoredEnvelope]| -> Vec<usize> {
        (0..c.len())
            .max_by_key(|&i| c[i].issued)
            .into_iter()
            .collect()
    };
    let by_age = |c: &[StoredEnvelope], age: i64| -> usize {
        (0..c.len())
            .find(|&i| c[i].issued == Some(100 + age))
            .unwrap()
    };
    assert!(matches!(p.status().unwrap(), StoreStatus::Ready { .. }));
    assert!(p.flag("plan:natives:p"));
    let _ = p.passing_on("aaaaaaaaaaaaaaaa");
    let _ = p.passing_on(TREE);
    p.prefetch(Prefetch::Units {
        test_ids: &ids,
        choose: Some(&newest),
    })
    .unwrap();
    let after_prefetch = p.statements();
    assert!(after_prefetch <= 7, "{after_prefetch}");
    // The plan's lookup and its read of the chosen: cache hits.
    let mut listed = p.list_units(&ids).unwrap();
    assert!(listed.iter().all(|l| l.len() == 3));
    let mut chosen: Vec<&mut StoredEnvelope> = listed
        .iter_mut()
        .map(|l| {
            let i = newest(l)[0];
            &mut l[i]
        })
        .collect();
    p.read_values(&mut chosen).unwrap();
    let roots: Vec<String> = chosen
        .iter()
        .map(|e| {
            assert!(matches!(e.state(), ValueState::Read(_)));
            root_ref(&e.bytes)
        })
        .collect();
    drop(chosen);
    // Every verifying thread reads a manifest and its base.
    let verify = |roots: &[String]| {
        std::thread::scope(|sc| {
            for part in roots.chunks(roots.len().div_ceil(8)) {
                let p = &p;
                sc.spawn(move || {
                    for r in part {
                        let m = p.manifest(r).unwrap().expect("stored");
                        let base = vci_core::InputManifest::compact_base(&m.bytes)
                            .unwrap()
                            .expect("a base");
                        assert!(p.manifest(&base).unwrap().is_some());
                    }
                });
            }
        });
    };
    verify(&roots);
    assert_eq!(
        p.statements(),
        after_prefetch,
        "the plan's reads add no statement"
    );
    // The plan also reads the next newest of each unit: one read, and one
    // read of their manifests ahead of the verifying threads.
    let mut second: Vec<&mut StoredEnvelope> = listed
        .iter_mut()
        .map(|l| {
            let i = by_age(l, 1);
            &mut l[i]
        })
        .collect();
    p.read_values(&mut second).unwrap();
    let roots2: Vec<String> = second.iter().map(|e| root_ref(&e.bytes)).collect();
    drop(second);
    let before = p.statements();
    verify(&roots2);
    assert_eq!(p.statements(), before);
    assert!(before - after_prefetch <= 2, "{}", before - after_prefetch);
    // Round 2: the set-aside candidates of the units not skipped.
    let unread = &ids[..100];
    p.prefetch(Prefetch::Units {
        test_ids: unread,
        choose: None,
    })
    .unwrap();
    let mut oldest: Vec<&mut StoredEnvelope> = listed[..100]
        .iter_mut()
        .map(|l| {
            let i = by_age(l, 0);
            &mut l[i]
        })
        .collect();
    let before = p.statements();
    p.read_values(&mut oldest).unwrap();
    assert_eq!(
        p.statements(),
        before,
        "round 2 reads from what it prefetched"
    );
    let roots3: Vec<String> = oldest.iter().map(|e| root_ref(&e.bytes)).collect();
    drop(oldest);
    let root_refs: Vec<&str> = roots3.iter().map(String::as_str).collect();
    p.prefetch(Prefetch::Manifests { roots: &root_refs })
        .unwrap();
    verify(&roots3);
    assert_eq!(p.statements(), before);
    let passed: Vec<(String, String)> = listed
        .iter()
        .map(|l| (l[0].test_key.clone(), l[0].key.clone()))
        .collect();
    p.remember_passing(TREE, &passed);
    let total = p.statements();
    eprintln!("a plan-shaped run of {UNITS} units took {total} statement(s)");
    assert!(total <= 15, "{total}");
    // The memo is there for the next plan.
    assert_eq!(db.open().passing_on(TREE).len(), UNITS);
}

/// Test 9: after a prefetch, this handle's own writes are seen at once.
#[test]
fn reads_see_this_handles_writes_after_a_prefetch() {
    let Some(db) = pg() else { return };
    let seed = db.open();
    let r1 = hex64(1);
    seed.put_manifest(&r1, &manifest("r1", None)).unwrap();
    let k1 = seed
        .put_for_test(
            UNIT_A,
            S1,
            &hex64(1),
            Some(&hint(1)),
            &envelope(Some(&r1), 10),
        )
        .unwrap();
    let k2 = seed
        .put_for_test(
            UNIT_A,
            S1,
            &hex64(2),
            Some(&hint(1)),
            &envelope(Some(&r1), 10),
        )
        .unwrap();
    let p = db.open();
    let absent = hex64(77);
    p.prefetch(Prefetch::Units {
        test_ids: &[UNIT_A, UNIT_B],
        choose: None,
    })
    .unwrap();
    p.prefetch(Prefetch::Manifests {
        roots: &[&absent, &r1],
    })
    .unwrap();
    assert!(p.manifest(&absent).unwrap().is_none());
    let n = p.statements();
    assert_eq!(keys(&p.list_units(&[UNIT_A]).unwrap()[0]), {
        let mut v = vec![k1.key.clone(), k2.key.clone()];
        v.sort();
        v
    });
    assert_eq!(p.statements(), n, "served from the prefetch");
    // A put of a unit listed empty.
    let b = p
        .put_for_test(UNIT_B, S1, &hex64(5), Some(&hint(2)), b"b")
        .unwrap();
    assert_eq!(read_bytes(&p, UNIT_B), vec![(b.key.clone(), b"b".to_vec())]);
    // A removal.
    assert_eq!(p.remove(vec![k1.clone()]).unwrap().len(), 1);
    assert_eq!(
        keys(&p.list_units(&[UNIT_A]).unwrap()[0]),
        vec![k2.key.clone()]
    );
    let mut gone = k1.clone();
    p.read_values(&mut [&mut gone]).unwrap();
    assert_eq!(gone.error.as_deref(), Some(vci_store::GONE));
    // A replacement of a slot.
    let k2b = p
        .put_for_test(UNIT_A, S1, &hex64(2), Some(&hint(3)), b"k2b")
        .unwrap();
    assert_eq!(
        read_bytes(&p, UNIT_A),
        vec![(k2b.key.clone(), b"k2b".to_vec())]
    );
    // A manifest the prefetch found absent.
    assert!(p.put_manifest(&absent, &manifest("now", None)).unwrap());
    assert_eq!(
        p.manifest(&absent).unwrap().unwrap().bytes,
        manifest("now", None)
    );
    // Writes of a deferred batch, once it finishes.
    let batch = p.batch().unwrap();
    let c = p
        .put_for_test(UNIT_B, S2, &hex64(6), Some(&hint(4)), b"c")
        .unwrap();
    p.remove(vec![b.clone()]).unwrap();
    batch.finish().unwrap();
    assert_eq!(read_bytes(&p, UNIT_B), vec![(c.key.clone(), b"c".to_vec())]);
    assert_eq!(read_bytes(&db.open(), UNIT_B), vec![(c.key, b"c".to_vec())]);
}

/// Test 10: deferred batches.
#[test]
fn deferred_batches() {
    let Some(db) = pg() else { return };
    db.open()
        .put_manifest(&hex64(1), &manifest("schema", None))
        .unwrap();
    let w = db.open();
    let r = db.open();
    let before = r.count().unwrap();
    let n0 = w.statements();
    let batch = w.batch().unwrap();
    assert!(batch.defers_writes());
    for i in 0..1_000 {
        let root = hex64(10_000 + i);
        assert!(w.put_manifest(&root, &manifest(&root, None)).unwrap());
        w.put_for_test(
            &format!("src/b{i}.test.ts"),
            S1,
            &hex64(i),
            Some(&hint(1)),
            &envelope(Some(&root), 200),
        )
        .unwrap();
    }
    assert_eq!(
        r.count().unwrap(),
        before,
        "nothing is visible before finish"
    );
    assert!(r.manifest(&hex64(10_000)).unwrap().is_none());
    batch.finish().unwrap();
    let used = w.statements() - n0;
    eprintln!("a deferred batch of 1,000 units took {used} statement(s)");
    assert!(used <= 6, "{used} statements");
    assert_eq!(r.count().unwrap(), before + 1_000);
    assert!(r.manifest(&hex64(10_999)).unwrap().is_some());
    // Two puts of one slot in one batch: the last one wins.
    let batch = w.batch().unwrap();
    w.put_for_test(UNIT_A, S1, &hex64(7), Some(&hint(1)), b"one")
        .unwrap();
    let last = w
        .put_for_test(UNIT_A, S1, &hex64(7), Some(&hint(2)), b"two")
        .unwrap();
    w.put_manifest(&hex64(2), b"{\"v\":2}").unwrap();
    assert!(!w.put_manifest(&hex64(2), b"{\"v\":2}").unwrap());
    batch.finish().unwrap();
    let units = r.read_units(&[UNIT_A]).unwrap();
    assert_eq!(units[0].len(), 1);
    assert_eq!(
        (units[0][0].key.clone(), units[0][0].bytes.clone()),
        (last.key, b"two".to_vec())
    );
    // A role that may not insert attestations: finish fails, and the
    // batch's manifests are not written either.
    let url = db.role(
        "noinsert",
        "GRANT USAGE ON SCHEMA {schema} TO {role}; \
         GRANT SELECT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {role}; \
         GRANT INSERT ON {schema}.manifests TO {role}",
    );
    let x = db.open_as(&url);
    let batch = x.batch().unwrap();
    x.put_manifest(&hex64(3), &manifest("x", None)).unwrap();
    x.put_for_test(
        UNIT_B,
        S1,
        &hex64(3),
        Some(&hint(1)),
        &envelope(Some(&hex64(3)), 10),
    )
    .unwrap();
    match batch.finish() {
        Err(StoreError::Denied { .. }) => {}
        other => panic!("expected Denied, got {other:?}"),
    }
    assert!(r.manifest(&hex64(3)).unwrap().is_none());
    assert!(r.list_units(&[UNIT_B]).unwrap()[0].is_empty());
    // A batch dropped without finish still writes (and loses its error).
    let batch = w.batch().unwrap();
    w.put_for_test(UNIT_C, S1, &hex64(8), Some(&hint(1)), b"dropped")
        .unwrap();
    drop(batch);
    assert_eq!(r.list_units(&[UNIT_C]).unwrap()[0].len(), 1);
}

/// Test 11: what `remove_manifests` keeps.
#[test]
fn remove_manifests_keeps_referenced_bases_and_recent_roots() {
    let Some(db) = pg() else { return };
    let z = db.open_with(|s| {
        s.postgres.manifest_grace = Sourced {
            value: Duration::ZERO,
            source: Source::File,
        }
    });
    let (m1, m2, m3, m4) = (hex64(1), hex64(2), hex64(3), hex64(4));
    z.put_manifest(&m1, &manifest("1", None)).unwrap();
    z.put_manifest(&m2, &manifest("2", None)).unwrap();
    z.put_manifest(&m3, &manifest("3", None)).unwrap();
    z.put_manifest(&m4, &manifest("4", Some(&m3))).unwrap();
    z.put_for_test(
        UNIT_A,
        S1,
        &hex64(1),
        Some(&hint(1)),
        &envelope(Some(&m2), 10),
    )
    .unwrap();
    // Every root is checked before anything is removed.
    assert!(matches!(
        z.remove_manifests(&[&m1, "XYZ"]),
        Err(StoreError::Invalid { .. })
    ));
    assert!(z.manifest(&m1).unwrap().is_some());
    // Grace 0: the unreferenced root goes; the referenced one and the base
    // stay, and are not counted.
    assert_eq!(z.remove_manifests(&[&m1, &m2, &m3]).unwrap(), 1);
    assert!(z.manifest(&m1).unwrap().is_none());
    assert!(z.manifest(&m2).unwrap().is_some());
    assert!(z.manifest(&m3).unwrap().is_some());
    assert_eq!(z.remove_manifests(&[&m4]).unwrap(), 1);
    assert_eq!(z.remove_manifests(&[&m3]).unwrap(), 1, "no longer a base");
    // A long-running command (vci prune) removes without grace.
    let prune = PgStore::open(&db.selection(), &cx_for("prune", true)).unwrap();
    assert_eq!(prune.__connection_for_test().manifest_grace, Duration::ZERO);
    let g = db.open();
    assert_eq!(
        g.__connection_for_test().manifest_grace,
        Duration::from_secs(3600)
    );
    let (m5, m6) = (hex64(5), hex64(6));
    g.put_manifest(&m5, &manifest("5", None)).unwrap();
    assert_eq!(prune.remove_manifests(&[&m5]).unwrap(), 1);
    // Grace one hour: a root put just now is kept; putting the same bytes
    // again refreshes its age.
    g.put_manifest(&m6, &manifest("6", None)).unwrap();
    assert_eq!(g.remove_manifests(&[&m6]).unwrap(), 0);
    let age = format!(
        "UPDATE {{schema}}.manifests SET put_at = now() - interval '2 hours' WHERE root = '{m6}'"
    );
    db.sql(&age);
    assert!(!g.put_manifest(&m6, &manifest("6", None)).unwrap());
    assert_eq!(
        db.count(&format!(
            "SELECT count(*) FROM {{schema}}.manifests WHERE root = '{m6}' AND put_at > now() - interval '1 minute'"
        )),
        1,
        "an identical put refreshes put_at"
    );
    assert_eq!(g.remove_manifests(&[&m6]).unwrap(), 0);
    db.sql(&age);
    assert_eq!(g.remove_manifests(&[&m6]).unwrap(), 1);
    assert!(g.manifest(&m6).unwrap().is_none());
}

/// Test 12: `orphan_manifests` answers nothing while what some
/// attestation references is unknown.
#[test]
fn orphan_manifests_with_an_unknown_reference() {
    let Some(db) = pg() else { return };
    let s = db.open();
    let (r1, r3) = (hex64(1), hex64(3));
    s.put_for_test(
        UNIT_A,
        S1,
        &hex64(1),
        Some(&hint(1)),
        &envelope(Some(&r1), 10),
    )
    .unwrap();
    s.put_for_test(UNIT_B, S1, &hex64(2), Some(&hint(1)), &envelope(None, 10))
        .unwrap();
    assert_eq!(
        s.orphan_manifests(&[&r3, &r1, &r3]).unwrap(),
        vec![r3.clone()]
    );
    assert!(s.orphan_manifests(&[]).unwrap().is_empty());
    s.put_for_test(UNIT_C, S1, &hex64(3), Some(&hint(1)), b"not an envelope")
        .unwrap();
    assert_eq!(
        db.count("SELECT count(*) FROM {schema}.attestations WHERE ref_state = 0"),
        1
    );
    assert!(s.orphan_manifests(&[&r3]).unwrap().is_empty());
}

/// Test 13: namespaces in one schema do not see each other.
#[test]
fn namespaces_are_isolated() {
    let Some(db) = pg() else { return };
    let ns = |n: &str| {
        let n = n.to_owned();
        db.open_with(move |s| {
            s.namespace = Some(Sourced {
                value: n,
                source: Source::Env("VCI_STORE_NAMESPACE"),
            })
        })
    };
    let one = ns("one");
    let e = one
        .put_for_test(
            UNIT_A,
            S1,
            &hex64(1),
            Some(&hint(1)),
            &envelope(Some(&hex64(9)), 10),
        )
        .unwrap();
    one.put_manifest(&hex64(9), &manifest("9", None)).unwrap();
    one.remember_passing(TREE, &[(e.test_key.clone(), e.key.clone())]);
    one.set_flag("plan:natives:p");
    let two = ns("two");
    assert!(two.list_units(&[UNIT_A]).unwrap()[0].is_empty());
    assert!(two.list_all().unwrap().is_empty());
    assert_eq!(two.count().unwrap(), 0);
    assert!(two.manifest(&hex64(9)).unwrap().is_none());
    assert!(two.manifest_roots().unwrap().is_empty());
    assert!(two.passing_on(TREE).is_empty());
    assert!(!two.flag("plan:natives:p"));
    assert_eq!(two.remove(vec![e.clone()]).unwrap(), Vec::new());
    assert_eq!(two.orphan_manifests(&[&hex64(9)]).unwrap(), vec![hex64(9)]);
    let one = ns("one");
    assert_eq!(
        keys(&one.list_units(&[UNIT_A]).unwrap()[0]),
        vec![e.key.clone()]
    );
    assert_eq!(one.passing_on(TREE).get(&e.test_key), Some(&e.key));
    assert!(one.flag("plan:natives:p"));
    assert!(one.orphan_manifests(&[&hex64(9)]).unwrap().is_empty());
    // Without a namespace setting, the repository id is the namespace.
    let d = db.open_with(|s| s.namespace = None);
    assert_eq!(
        d.namespace().unwrap(),
        "0123456789abcdef0123456789abcdef01234567"
    );
    assert!(
        d.location()
            .ends_with("namespace 0123456789abcdef0123456789abcdef01234567")
    );
}

/// Test 14: the read-only role of the operator recipe plans, cannot
/// write, and its hints never fail.
#[test]
fn a_read_only_role_reads_and_is_denied_writes() {
    let Some(db) = pg() else { return };
    let owner = db.open();
    let (base, root) = (hex64(1), hex64(2));
    owner.put_manifest(&base, &manifest("base", None)).unwrap();
    owner
        .put_manifest(&root, &manifest("root", Some(&base)))
        .unwrap();
    let e = owner
        .put_for_test(
            UNIT_A,
            S1,
            &hex64(1),
            Some(&hint(1)),
            &envelope(Some(&root), 10),
        )
        .unwrap();
    let url = db.role(
        "reader",
        "GRANT USAGE ON SCHEMA {schema} TO {role}; \
         GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {role}; \
         GRANT INSERT, UPDATE ON {schema}.memo, {schema}.flags TO {role}",
    );
    let r = db.open_as(&url);
    assert!(matches!(
        r.status().unwrap(),
        StoreStatus::Ready {
            schema_version: Some(1)
        }
    ));
    r.prefetch(Prefetch::Units {
        test_ids: &[UNIT_A],
        choose: None,
    })
    .unwrap();
    assert_eq!(
        read_bytes(&r, UNIT_A),
        vec![(e.key.clone(), e.bytes.clone())]
    );
    assert!(r.manifest(&root).unwrap().is_some());
    assert!(r.manifest(&base).unwrap().is_some());
    assert_eq!(r.count().unwrap(), 1);
    assert_eq!(r.read_all().unwrap().len(), 1);
    for err in [
        r.put_for_test(UNIT_B, S1, &hex64(2), Some(&hint(1)), b"x")
            .map(|_| ()),
        r.put_manifest(&hex64(3), &manifest("3", None)).map(|_| ()),
        r.remove(vec![e.clone()]).map(|_| ()),
    ] {
        match err {
            Err(StoreError::Denied {
                operation: "write", ..
            }) => {}
            other => panic!("expected Denied, got {other:?}"),
        }
    }
    let batch = r.batch().unwrap();
    r.put_for_test(UNIT_B, S1, &hex64(2), Some(&hint(1)), b"x")
        .unwrap();
    assert!(matches!(batch.finish(), Err(StoreError::Denied { .. })));
    // Denied is not a store that cannot be reached: reads still work.
    assert_eq!(r.list_units(&[UNIT_A]).unwrap()[0].len(), 1);
    // Hints never fail.
    r.remember_passing(TREE, &[(e.test_key.clone(), e.key.clone())]);
    r.set_flag("plan:natives:p");
    assert_eq!(
        db.open_as(&url).passing_on(TREE).get(&e.test_key),
        Some(&e.key)
    );
    assert!(db.open_as(&url).flag("plan:natives:p"));
    assert_eq!(owner.count().unwrap(), 1);
}

/// Test 15: `pg_stat_activity` shows which command a connection serves.
#[test]
fn application_name_names_vci_and_the_command() {
    let Some(db) = pg() else { return };
    let command = format!("apptest{}", std::process::id());
    let s = PgStore::open(&db.selection(), &cx_for(&command, false)).unwrap();
    s.status().unwrap();
    let rows = db.query(&format!(
        "SELECT application_name FROM pg_stat_activity WHERE application_name LIKE '%{command}'"
    ));
    assert!(!rows.is_empty(), "the connection is in pg_stat_activity");
    for row in rows {
        let name: String = row.get(0);
        assert!(name.starts_with("vci "), "{name}");
        assert_eq!(name, format!("vci {} {command}", env!("CARGO_PKG_VERSION")));
    }
    drop(s);
}
