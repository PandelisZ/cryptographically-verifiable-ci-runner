//! The libSQL store's own tests: what the conformance suite cannot check
//! through the trait (the local file's format, requests per plan, schema
//! states, deadlines, secrets in `Debug`, tokens, the replica's sync).
//! Tests that need a server use [`testkit`] and are skipped without one
//! (a failure under `VCI_TEST_LIBSQL=require`).

use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use vci_store::select::{LibsqlMode, Source, Sourced};
use vci_store::{
    AttestationStore, KeyHint, Prefetch, StoreError, StoreStatus, StoredEnvelope, ValueState,
};
use vci_store_libsql::{LibsqlStore, table_prefix, testkit};
use vci_store_sqlite::{SqliteOptions, SqliteStore};

const S1: &str = "1111111111111111";

fn hex64(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

fn hint(issued: i64) -> KeyHint {
    KeyHint {
        issued,
        tree: Some("0123456789abcdef".to_owned()),
    }
}

/// A DSSE-shaped envelope whose payload names `root`.
fn envelope(root: Option<&str>, pad: &str) -> Vec<u8> {
    let payload = serde_json::json!({"predicate": {"manifestRef": root}, "pad": pad});
    serde_json::json!({
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64::engine::general_purpose::STANDARD.encode(payload.to_string()),
        "signatures": [],
    })
    .to_string()
    .into_bytes()
}

fn manifest(paths: &[&str]) -> vci_core::InputManifest {
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

fn unit(i: usize) -> String {
    format!("src/u{i:05}.test.ts")
}

/// A remote store on the test server in a namespace of its own, or `None`
/// (skipped) without a server.
fn remote() -> Option<(LibsqlStore, String)> {
    if !testkit::available() {
        return None;
    }
    let ns = testkit::namespace();
    Some((testkit::open_remote(&ns)?, ns))
}

fn open(sel: &vci_store::select::Selection) -> LibsqlStore {
    LibsqlStore::open(sel, &testkit::cx()).expect("open")
}

// ---- local --------------------------------------------------------------------------

/// The local mode keeps the SQLite store's file: what one writes, the other
/// reads, byte for byte, under the same keys.
#[test]
fn the_local_file_is_a_sqlite_store_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vci-store.libsql");
    let s = open(&testkit::selection(
        LibsqlMode::Local,
        None,
        None,
        None,
        Some(&path),
    ));
    assert_eq!(s.kind(), "libsql");
    assert!(!s.caps().shared_writes);
    assert!(matches!(s.status().unwrap(), StoreStatus::Absent { .. }));
    assert!(!path.exists(), "reading created the file");
    let m = manifest(&["src/a.rs"]);
    assert!(
        s.put_manifest(&m.root(), m.to_compact().as_bytes())
            .unwrap()
    );
    let e = s
        .put_for_test(
            "src/a.test.ts",
            S1,
            &hex64(1),
            Some(&hint(5)),
            &envelope(Some(&m.root()), "a"),
        )
        .unwrap();
    let sqlite = SqliteStore::open_path(&path, SqliteOptions::default());
    let got = sqlite.read_units(&["src/a.test.ts"]).unwrap().remove(0);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].key, e.key);
    assert_eq!(got[0].state(), ValueState::Read(&e.bytes));
    assert_eq!(
        sqlite.manifest(&m.root()).unwrap().unwrap().bytes,
        m.to_compact().as_bytes()
    );
    assert_eq!(s.location(), format!("{} (local)", path.display()));
    // Errors name the libsql store, not the format's.
    let garbage = dir.path().join("garbage.libsql");
    std::fs::write(&garbage, "not a database\n".repeat(100)).unwrap();
    let g = open(&testkit::selection(
        LibsqlMode::Local,
        None,
        None,
        None,
        Some(&garbage),
    ));
    match g.list_units(&["src/a.test.ts"]) {
        Err(StoreError::Unavailable { backend, .. }) => assert_eq!(backend, "libsql"),
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

// ---- remote: requests, schema, writes -----------------------------------------------

/// A plan-shaped sequence over 300 units costs a handful of requests,
/// whatever the number of units: the status, one prefetch (the listings,
/// then the chosen values with their manifests), and nothing for the
/// listings, the batch read and the manifest reads from eight threads.
#[test]
fn a_plan_costs_a_handful_of_requests() {
    let Some((s, _)) = remote() else { return };
    let n = 300;
    let ids: Vec<String> = (0..n).map(unit).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let mut roots = Vec::new();
    {
        let b = s.batch().unwrap();
        assert!(b.defers_writes());
        for (i, id) in ids.iter().enumerate() {
            let m = manifest(&[id]);
            s.put_manifest(&m.root(), m.to_compact().as_bytes())
                .unwrap();
            for v in 0..2u8 {
                s.put_for_test(
                    id,
                    S1,
                    &hex64(v),
                    Some(&hint(i64::from(v) + 1)),
                    &envelope(Some(&m.root()), &format!("{i}-{v}")),
                )
                .unwrap();
            }
            roots.push(m.root());
        }
        let before = s.requests();
        b.finish().unwrap();
        let used = s.requests() - before;
        assert!(used <= 6, "a batch of {n} units took {used} requests");
    }
    let p = open(&testkit::selection(
        LibsqlMode::Remote,
        Some(&testkit::server().unwrap().url),
        testkit::server().unwrap().token.as_deref(),
        s.namespace().unwrap().ok().as_deref(),
        None,
    ));
    assert!(matches!(p.status().unwrap(), StoreStatus::Ready { .. }));
    let newest = |l: &[StoredEnvelope]| -> Vec<usize> {
        l.iter()
            .enumerate()
            .max_by_key(|(_, e)| e.issued)
            .map(|(i, _)| vec![i])
            .unwrap_or_default()
    };
    p.prefetch(Prefetch::Units {
        test_ids: &ids,
        choose: Some(&newest),
    })
    .unwrap();
    let after_prefetch = p.requests();
    let mut listed = p.list_units(&ids).unwrap();
    assert!(listed.iter().all(|l| l.len() == 2));
    let mut chosen: Vec<&mut StoredEnvelope> = listed
        .iter_mut()
        .map(|l| l.iter_mut().max_by_key(|e| e.issued).unwrap())
        .collect();
    p.read_values(&mut chosen).unwrap();
    assert!(
        chosen
            .iter()
            .all(|e| matches!(e.state(), ValueState::Read(_)))
    );
    let p = Arc::new(p);
    std::thread::scope(|sc| {
        for t in 0..8 {
            let (p, roots) = (Arc::clone(&p), &roots);
            sc.spawn(move || {
                for r in roots.iter().skip(t).step_by(8) {
                    assert!(p.manifest(r).unwrap().unwrap().is_read());
                }
            });
        }
    });
    assert_eq!(
        p.requests(),
        after_prefetch,
        "the listings, the values and the manifests came from the cache"
    );
    assert!(
        after_prefetch <= 8,
        "status and prefetch took {after_prefetch} requests"
    );
}

/// Slots, order and the schema: a newer hint replaces the slot; keys come
/// back bytewise; a namespace's tables are its own; a newer schema is
/// refused.
#[test]
fn slots_order_namespaces_and_schema_versions() {
    let Some((s, ns)) = remote() else { return };
    assert!(matches!(s.status().unwrap(), StoreStatus::Absent { .. }));
    assert!(s.list_units(&["src/a.test.ts"]).unwrap()[0].is_empty());
    s.remember_passing("0123456789abcdef", &[("x".into(), "y".into())]);
    s.set_flag("plan:natives:x");
    assert!(
        matches!(s.status().unwrap(), StoreStatus::Absent { .. }),
        "hints created the tables"
    );
    let a = s
        .put_for_test("src/a.test.ts", S1, &hex64(1), Some(&hint(1)), b"{\"v\":1}")
        .unwrap();
    let b = s
        .put_for_test("src/a.test.ts", S1, &hex64(1), Some(&hint(2)), b"{\"v\":2}")
        .unwrap();
    assert_ne!(a.key, b.key);
    // Bytewise: `aa:ff.-` sorts before `aaf0:1.-`.
    for sk in ["aa", "aaf0"] {
        s.put_for_test(
            "src/a.test.ts",
            S1,
            sk,
            Some(&KeyHint {
                issued: 0xff,
                tree: None,
            }),
            b"{}",
        )
        .unwrap();
    }
    let keys: Vec<String> = s.list_units(&["src/a.test.ts"]).unwrap()[0]
        .iter()
        .map(|e| e.key.clone())
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    assert!(keys.contains(&b.key) && !keys.contains(&a.key));
    // Another namespace sees nothing.
    let other = testkit::open_remote(&testkit::namespace()).unwrap();
    assert!(other.list_units(&["src/a.test.ts"]).unwrap()[0].is_empty());
    assert!(matches!(
        other.status().unwrap(),
        StoreStatus::Absent { .. }
    ));
    // A newer schema version is refused.
    s.__execute_for_test(&[format!(
        "UPDATE vci_schema SET version = 99 WHERE ns = '{ns}'"
    )])
    .unwrap();
    let fresh = testkit::open_remote(&ns).unwrap();
    match fresh.status() {
        Err(StoreError::Incompatible { found: 99, .. }) => {}
        other => panic!("expected Incompatible, got {other:?}"),
    }
    assert!(matches!(
        fresh.list_units(&["src/a.test.ts"]),
        Err(StoreError::Incompatible { .. })
    ));
}

/// Orphans and the grace period: a referenced root is kept, an unknown
/// reference empties the answer, a recent root is kept on a shared server
/// but not by a long-running command.
#[test]
fn orphans_and_the_grace_period() {
    let Some((s, ns)) = remote() else { return };
    let used = manifest(&["src/used.rs"]);
    let free = manifest(&["src/free.rs"]);
    for m in [&used, &free] {
        s.put_manifest(&m.root(), m.to_compact().as_bytes())
            .unwrap();
    }
    s.put_for_test(
        "src/a.test.ts",
        S1,
        &hex64(1),
        None,
        &envelope(Some(&used.root()), "a"),
    )
    .unwrap();
    let (ur, fr) = (used.root(), free.root());
    assert_eq!(s.orphan_manifests(&[&ur, &fr]).unwrap(), vec![fr.clone()]);
    assert_eq!(
        s.remove_manifests(&[&fr]).unwrap(),
        0,
        "within the grace period"
    );
    let server = testkit::server().unwrap();
    let prune = LibsqlStore::open(
        &testkit::selection(
            LibsqlMode::Remote,
            Some(&server.url),
            server.token.as_deref(),
            Some(&ns),
            None,
        ),
        &testkit::cx_in(Path::new("/nonexistent/.git"), true),
    )
    .unwrap();
    assert_eq!(
        prune.remove_manifests(&[&ur, &fr]).unwrap(),
        1,
        "the free one"
    );
    assert!(prune.manifest(&fr).unwrap().is_none());
    assert!(prune.manifest(&ur).unwrap().is_some());
    s.put_for_test("src/b.test.ts", S1, &hex64(2), None, b"not an envelope")
        .unwrap();
    assert!(
        s.orphan_manifests(&[&ur, &fr]).unwrap().is_empty(),
        "an unknown reference"
    );
}

// ---- deadlines and secrets -------------------------------------------------------------

/// A closed port fails the first call within the connect timeout and every
/// later one at once, never showing the URL's token or `VCI_STORE_TOKEN`.
#[test]
fn a_closed_port_fails_fast_and_shows_no_secret() {
    let mut sel = testkit::selection(
        LibsqlMode::Remote,
        Some("libsql://127.0.0.1:1/?tls=0&authToken=s3cret-in-url"),
        Some("s3cret-in-env"),
        Some("ns"),
        None,
    );
    sel.connect_timeout = Sourced {
        value: Duration::from_secs(1),
        source: Source::File,
    };
    let s = open(&sel);
    let t = Instant::now();
    let e = s.list_units(&["src/a.test.ts"]).unwrap_err();
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    assert!(
        matches!(
            e,
            StoreError::Unavailable { .. } | StoreError::Timeout { .. }
        ),
        "{e:?}"
    );
    let t = Instant::now();
    let mut all = format!("{e} {e:?} {s:?} {} {:?}", s.location(), sel);
    for _ in 0..20 {
        let e = s.status().unwrap_err();
        all.push_str(&format!("{e} {e:?}"));
        let e = s
            .put_for_test("src/a.test.ts", S1, "00", None, b"{}")
            .unwrap_err();
        all.push_str(&format!("{e} {e:?}"));
    }
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert!(all.contains("not retried"), "{all}");
    assert!(!all.contains("s3cret"), "{all}");
    assert!(s.passing_on("0123456789abcdef").is_empty());
    assert!(!s.flag("x"));
}

/// A server that accepts the connection and never answers is given up on
/// after the request timeout, and the breaker latches.
#[test]
fn a_server_that_never_answers_is_given_up_on() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let held = std::thread::spawn(move || {
        let mut kept = Vec::new();
        for c in l.incoming().take(4).flatten() {
            kept.push(c);
        }
        std::thread::sleep(Duration::from_secs(5));
    });
    let mut sel = testkit::selection(
        LibsqlMode::Remote,
        Some(&format!("http://127.0.0.1:{port}")),
        None,
        Some("ns"),
        None,
    );
    sel.timeout = Sourced {
        value: Duration::from_secs(1),
        source: Source::File,
    };
    let s = open(&sel);
    let t = Instant::now();
    match s.status() {
        Err(StoreError::Timeout { operation, .. }) => assert_eq!(operation, "a request"),
        other => panic!("expected a Timeout, got {other:?}"),
    }
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    let t = Instant::now();
    assert!(s.list_all().is_err());
    assert!(t.elapsed() < Duration::from_millis(200));
    drop(held);
}

/// URLs vci refuses never quote what they hold.
#[test]
fn bad_urls_are_config_errors_without_their_secrets() {
    for url in [
        "libsql://user:s3cret@db.turso.io",
        "libsql://db.turso.io?password=s3cret",
        "ws://db.turso.io?authToken=s3cret",
        "libsql://db.turso.io#s3cret",
    ] {
        let sel = testkit::selection(LibsqlMode::Remote, Some(url), None, Some("ns"), None);
        match LibsqlStore::open(&sel, &testkit::cx()) {
            Err(StoreError::Config(m)) => assert!(!m.contains("s3cret"), "{url}: {m}"),
            Ok(_) => panic!("{url} was accepted"),
            Err(e) => panic!("{url}: {e:?}"),
        }
    }
}

// ---- tokens --------------------------------------------------------------------------

/// A JWT `sqld` accepts: EdDSA over `claims`.
fn jwt(key: &ed25519_dalek::SigningKey, claims: &serde_json::Value) -> String {
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let head = b64(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let body = b64(claims.to_string().as_bytes());
    let sig = key.sign(format!("{head}.{body}").as_bytes());
    format!("{head}.{body}.{}", b64(&sig.to_bytes()))
}

/// Against a server that checks tokens (a `sqld` from `PATH`, else the
/// Docker image; skipped without either): without one the store says to set
/// `VCI_STORE_TOKEN`; a wrong one is refused; the right one works, from
/// `VCI_STORE_TOKEN` or the URL; a read-only one reads and is denied
/// writes; no message shows a token.
#[test]
fn tokens_are_sent_and_never_shown() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("jwt.key");
    std::fs::write(
        &key_file,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
    )
    .unwrap();
    let public =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
    let server = match testkit::start_sqld(&[
        "--auth-jwt-key-file".to_owned(),
        key_file.display().to_string(),
    ])
    .or_else(|e| {
        testkit::start_docker_with_env(&[("SQLD_AUTH_JWT_KEY", &public)])
            .map_err(|d| format!("{e}; docker: {d}"))
    }) {
        Ok(s) => s,
        Err(why) => {
            eprintln!("skipping: no sqld or Docker to check tokens with: {why}");
            return;
        }
    };
    let url = server.url();
    let ns = testkit::namespace();
    let rw = jwt(&key, &serde_json::json!({}));
    let ro = jwt(&key, &serde_json::json!({"a": "ro"}));
    let wrong = jwt(
        &ed25519_dalek::SigningKey::from_bytes(&[8; 32]),
        &serde_json::json!({}),
    );
    let with = |token: Option<&str>, in_url: bool| {
        let u = match (token, in_url) {
            (Some(t), true) => format!("{url}?authToken={t}"),
            _ => url.clone(),
        };
        open(&testkit::selection(
            LibsqlMode::Remote,
            Some(&u),
            if in_url { None } else { token },
            Some(&ns),
            None,
        ))
    };
    let none = with(None, false);
    let e = none.status().unwrap_err();
    assert!(e.to_string().contains("VCI_STORE_TOKEN"), "{e}");
    for (s, t) in [
        (with(Some(&wrong), false), &wrong),
        (with(Some(&wrong), true), &wrong),
    ] {
        let e = s.status().unwrap_err();
        let all = format!("{e} {e:?} {s:?} {}", s.location());
        assert!(matches!(e, StoreError::Unavailable { .. }), "{all}");
        assert!(!all.contains(t.as_str()), "{all}");
    }
    for in_url in [false, true] {
        let s = with(Some(&rw), in_url);
        s.put_for_test("src/a.test.ts", S1, &hex64(1), None, b"{}")
            .unwrap();
        assert_eq!(s.list_units(&["src/a.test.ts"]).unwrap()[0].len(), 1);
        assert!(!format!("{s:?} {}", s.location()).contains(&rw));
    }
    // A read-only token: hints and writes are refused (Denied, which keeps
    // vci run's exit code), and reads go on in the same handle.
    let r = with(Some(&ro), false);
    r.set_flag("plan:natives:x");
    r.remember_passing("0123456789abcdef", &[("x".into(), "y".into())]);
    assert_eq!(r.list_units(&["src/a.test.ts"]).unwrap()[0].len(), 1);
    match r.put_for_test("src/b.test.ts", S1, &hex64(2), Some(&hint(1)), b"{}") {
        Err(e @ StoreError::Denied { .. }) => {
            eprintln!("a read-only token's write: {e}");
            assert!(!format!("{e} {e:?}").contains(&ro), "{e}");
        }
        other => panic!("a read-only token wrote, or was not refused as Denied: {other:?}"),
    }
    let b = r.batch().unwrap();
    r.put_for_test("src/c.test.ts", S1, &hex64(3), Some(&hint(1)), b"{}")
        .unwrap();
    assert!(matches!(b.finish(), Err(StoreError::Denied { .. })));
    assert_eq!(
        r.list_units(&["src/a.test.ts", "src/b.test.ts"]).unwrap()[0].len(),
        1,
        "a refused write does not stop reads"
    );
}

// ---- the replica ------------------------------------------------------------------------

/// A replica reads what it synced: a new handle syncs what changed (puts,
/// replaced slots, removals, manifests), its own writes go through to the
/// file at once, and a file that is not a replica is never touched.
#[test]
fn a_replica_syncs_what_changed() {
    let Some((w, ns)) = remote() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replica.libsql");
    let m = manifest(&["src/a.rs"]);
    w.put_manifest(&m.root(), m.to_compact().as_bytes())
        .unwrap();
    let a = w
        .put_for_test(
            "src/a.test.ts",
            S1,
            &hex64(1),
            Some(&hint(1)),
            &envelope(Some(&m.root()), "a"),
        )
        .unwrap();
    let gone = w
        .put_for_test(
            "src/b.test.ts",
            S1,
            &hex64(2),
            Some(&hint(1)),
            &envelope(None, "b"),
        )
        .unwrap();

    let r = testkit::open_replica(&ns, &path).unwrap();
    assert_eq!(r.mode(), LibsqlMode::Replica);
    assert!(r.caps().shared_writes);
    let got = r.read_units(&["src/a.test.ts", "src/b.test.ts"]).unwrap();
    assert_eq!(got[0][0].key, a.key);
    assert_eq!(got[1][0].key, gone.key);
    assert!(r.manifest(&m.root()).unwrap().unwrap().is_read());
    let synced = r.requests();
    assert!(synced <= 2, "the first sync took {synced} requests");
    for _ in 0..3 {
        r.read_units(&["src/a.test.ts"]).unwrap();
    }
    assert_eq!(r.requests(), synced, "reads are local");

    // Changes on the server: a newer key in a's slot, b removed.
    let a2 = w
        .put_for_test(
            "src/a.test.ts",
            S1,
            &hex64(1),
            Some(&hint(2)),
            &envelope(Some(&m.root()), "a2"),
        )
        .unwrap();
    w.remove(vec![gone]).unwrap();
    assert_eq!(
        r.list_units(&["src/a.test.ts"]).unwrap()[0][0].key,
        a.key,
        "a replica reads what it synced"
    );
    let r2 = testkit::open_replica(&ns, &path).unwrap();
    let got = r2.read_units(&["src/a.test.ts", "src/b.test.ts"]).unwrap();
    assert_eq!(got[0].len(), 1);
    assert_eq!(got[0][0].key, a2.key);
    assert_eq!(got[0][0].state(), ValueState::Read(&a2.bytes));
    assert!(got[1].is_empty(), "the removal reached the replica");

    // The replica's own writes reach the server and its file.
    let c = r2
        .put_for_test(
            "src/c.test.ts",
            S1,
            &hex64(3),
            Some(&hint(1)),
            &envelope(None, "c"),
        )
        .unwrap();
    let before = r2.requests();
    assert_eq!(r2.list_units(&["src/c.test.ts"]).unwrap()[0][0].key, c.key);
    assert_eq!(r2.requests(), before);
    assert_eq!(w.list_units(&["src/c.test.ts"]).unwrap()[0][0].key, c.key);

    // A local-mode file is not a replica: refused, untouched.
    let local = dir.path().join("local.libsql");
    let l = open(&testkit::selection(
        LibsqlMode::Local,
        None,
        None,
        None,
        Some(&local),
    ));
    l.put_for_test("src/l.test.ts", S1, &hex64(4), None, b"{}")
        .unwrap();
    drop(l);
    let before = std::fs::read(&local).unwrap();
    let wrong = testkit::open_replica(&ns, &local).unwrap();
    match wrong.list_units(&["src/l.test.ts"]) {
        Err(StoreError::Unavailable { detail, .. }) => {
            assert!(detail.contains("not a replica"), "{detail}")
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
    assert_eq!(std::fs::read(&local).unwrap(), before);
}

/// A replica opened before anything was stored (the first `vci run` on a
/// new database: its sync finds no tables) becomes a replica with its first
/// write: the write goes through to the file, and the next handle syncs
/// on top of it.
#[test]
fn the_first_write_makes_the_file_a_replica() {
    let Some((_, ns)) = remote() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replica.libsql");
    let r = testkit::open_replica(&ns, &path).unwrap();
    assert!(matches!(r.status().unwrap(), StoreStatus::Absent { .. }));
    assert!(!path.exists(), "a sync of nothing created the file");
    let b = r.batch().unwrap();
    let a = r
        .put_for_test(
            "src/a.test.ts",
            S1,
            &hex64(1),
            Some(&hint(1)),
            &envelope(None, "a"),
        )
        .unwrap();
    b.finish().unwrap();
    assert!(path.exists(), "the write went through to the file");
    let before = r.requests();
    assert_eq!(r.list_units(&["src/a.test.ts"]).unwrap()[0][0].key, a.key);
    assert_eq!(r.requests(), before, "read from the file");
    drop(r);
    let r2 = testkit::open_replica(&ns, &path).unwrap();
    let got = r2.read_units(&["src/a.test.ts"]).unwrap();
    assert_eq!(got[0].len(), 1, "{got:?}");
    assert_eq!(got[0][0].state(), ValueState::Read(&a.bytes));
}

/// A replica whose server cannot be reached reads what it has.
#[test]
fn a_replica_reads_what_it_has_when_the_server_is_down() {
    let Some((w, ns)) = remote() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replica.libsql");
    let a = w
        .put_for_test(
            "src/a.test.ts",
            S1,
            &hex64(1),
            Some(&hint(1)),
            &envelope(None, "a"),
        )
        .unwrap();
    testkit::open_replica(&ns, &path).unwrap().status().unwrap();
    // The same server and namespace, as the file's sidecar names them, now
    // unreachable: point the URL at a closed port with the same display.
    let side = std::fs::read_to_string(dir.path().join("replica.libsql.sync")).unwrap();
    let server_url = testkit::server().unwrap().url.clone();
    assert!(side.contains(&server_url), "{side}");
    let fake = tempfile::tempdir().unwrap();
    let path2 = fake.path().join("replica.libsql");
    std::fs::copy(&path, &path2).unwrap();
    let closed = "http://127.0.0.1:1";
    std::fs::write(
        fake.path().join("replica.libsql.sync"),
        side.replace(&server_url, closed),
    )
    .unwrap();
    let mut sel = testkit::selection(
        LibsqlMode::Replica,
        Some(closed),
        None,
        Some(&ns),
        Some(&path2),
    );
    sel.connect_timeout = Sourced {
        value: Duration::from_secs(1),
        source: Source::File,
    };
    let r = open(&sel);
    let t = Instant::now();
    let got = r.read_units(&["src/a.test.ts"]).unwrap();
    assert!(t.elapsed() < Duration::from_secs(3));
    assert_eq!(got[0][0].key, a.key, "the stale replica");
    assert!(
        r.put_for_test("src/b.test.ts", S1, &hex64(2), None, b"{}")
            .is_err()
    );
}

// ---- many units (release builds) ------------------------------------------------------------

/// 1,200 units of 18 KB: stored in one batch, listed, prefetched and read,
/// remote and through a replica. Run with `cargo test --release -- --ignored`.
#[test]
#[ignore = "a timing check for release builds"]
fn many_units_are_listed_and_read_quickly() {
    let Some((s, ns)) = remote() else { return };
    let n = 1_200;
    let ids: Vec<String> = (0..n).map(unit).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let pad = "x".repeat(18 * 1024);
    let t = Instant::now();
    let b = s.batch().unwrap();
    for id in &ids {
        s.put_for_test(id, S1, &hex64(1), Some(&hint(1)), &envelope(None, &pad))
            .unwrap();
    }
    b.finish().unwrap();
    let write = t.elapsed();
    let r = testkit::open_remote(&ns).unwrap();
    let t = Instant::now();
    r.prefetch(Prefetch::Units {
        test_ids: &ids,
        choose: None,
    })
    .unwrap();
    let mut units = r.list_units(&ids).unwrap();
    let mut refs: Vec<&mut StoredEnvelope> = units.iter_mut().flatten().collect();
    r.read_values(&mut refs).unwrap();
    let read = t.elapsed();
    assert_eq!(refs.len(), n);
    assert!(
        refs.iter()
            .all(|e| matches!(e.state(), ValueState::Read(_)))
    );
    let dir = tempfile::tempdir().unwrap();
    let rep = testkit::open_replica(&ns, &dir.path().join("r.libsql")).unwrap();
    let t = Instant::now();
    let got = rep.read_units(&ids).unwrap();
    let sync = t.elapsed();
    assert_eq!(got.iter().map(Vec::len).sum::<usize>(), n);
    let t = Instant::now();
    let got = rep.read_units(&ids).unwrap();
    let local = t.elapsed();
    assert_eq!(got.len(), n);
    eprintln!(
        "{n} units of 18 KB: write {write:?} ({} requests), remote read {read:?} ({} requests), replica sync {sync:?}, replica read {local:?}",
        s.requests(),
        r.requests()
    );
    assert!(read < Duration::from_secs(5), "{read:?}");
    assert!(local < Duration::from_secs(1), "{local:?}");
}

/// Tables of the namespace are under its prefix.
#[test]
fn the_prefix_names_the_namespace() {
    assert_eq!(table_prefix("acme"), table_prefix("acme"));
    assert_ne!(table_prefix("acme"), table_prefix("acme2"));
    assert!(table_prefix("acme").starts_with("vci_"));
}
