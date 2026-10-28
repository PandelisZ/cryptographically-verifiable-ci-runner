//! The libSQL store's own tests: what the conformance suite cannot check
//! through the trait (the local file's format, requests per plan, schema
//! states, deadlines, secrets in `Debug`, tokens, the replica's sync).
//! Tests that need a server use [`testkit`] and are skipped without one
//! (a failure under `VCI_TEST_LIBSQL=require`).

use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
        let before = s.requests() - s.retries();
        b.finish().unwrap();
        // Requests sent again while another test's writer held the
        // database are not the batch's own. One transaction (one request)
        // per 64 attestations, and the schema's.
        let used = s.requests() - s.retries() - before;
        assert!(
            used <= (2 * n as u64).div_ceil(64) + 4,
            "a batch of {n} units took {used} requests"
        );
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
    let after_prefetch = p.requests() - p.retries();
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
        p.requests() - p.retries(),
        after_prefetch,
        "the listings, the values and the manifests came from the cache"
    );
    // The status, the listing, three requests of values (100 each, the
    // first ones at once) and the statements' descriptions on each
    // connection.
    assert!(
        after_prefetch <= 10,
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

/// A port where something accepts connections and never answers.
fn silent_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        for c in l.incoming().flatten() {
            kept.push(c);
        }
    });
    port
}

/// A port where a server answers every request with `response` (an HTTP
/// response, whole), then closes the connection.
fn canned_port(response: Vec<u8>) -> u16 {
    use std::io::{Read as _, Write as _};
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let response = response.clone();
            std::thread::spawn(move || {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                // The headers, then as much body as they announce.
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).to_ascii_lowercase();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if got.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                let _ = c.write_all(&response);
            });
        }
    });
    port
}

/// A server that accepts the connection and never answers costs the
/// connect timeout, not the request timeout (30 s; ten minutes for `vci
/// prune`): until the server has answered once, a request is bounded by
/// the connect timeout. The breaker latches; a replica reads what it has,
/// or (for `vci store`, fetch, push and prune) fails.
#[test]
fn a_server_that_never_answers_costs_the_connect_timeout() {
    let port = silent_port();
    let url = format!("http://127.0.0.1:{port}");
    for long_running in [false, true] {
        let mut sel = testkit::selection(LibsqlMode::Remote, Some(&url), None, Some("ns"), None);
        sel.connect_timeout = Sourced {
            value: Duration::from_secs(1),
            source: Source::File,
        };
        let s = LibsqlStore::open(
            &sel,
            &testkit::cx_in(Path::new("/nonexistent/.git"), long_running),
        )
        .unwrap();
        let t = Instant::now();
        match s.status() {
            Err(StoreError::Timeout {
                operation, after, ..
            }) => {
                assert_eq!(operation, "the server's first answer");
                assert_eq!(after, Duration::from_secs(1));
            }
            other => panic!("expected a Timeout, got {other:?}"),
        }
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        let t = Instant::now();
        assert!(s.list_all().is_err());
        assert!(
            s.put_for_test("src/a.test.ts", S1, "00", None, b"{}")
                .is_err()
        );
        assert!(t.elapsed() < Duration::from_millis(200));
    }
    // A replica: the first read reads the (empty) file with a warning
    // within the connect timeout; for the store commands it fails.
    let dir = tempfile::tempdir().unwrap();
    for (command, stale_ok) in [
        ("plan", true),
        ("run", true),
        ("store", false),
        ("prune", false),
    ] {
        let mut sel = testkit::selection(
            LibsqlMode::Replica,
            Some(&url),
            None,
            Some("ns"),
            Some(&dir.path().join(format!("{command}.libsql"))),
        );
        sel.connect_timeout = Sourced {
            value: Duration::from_secs(1),
            source: Source::File,
        };
        let mut cx = testkit::cx();
        cx.command = command.to_owned();
        cx.long_running = command == "prune";
        let r = LibsqlStore::open(&sel, &cx).unwrap();
        let t = Instant::now();
        let status = r.status();
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "{command}: {:?}",
            t.elapsed()
        );
        if stale_ok {
            assert!(
                matches!(status, Ok(StoreStatus::Absent { .. })),
                "{command}: {status:?}"
            );
            assert!(r.list_units(&["src/a.test.ts"]).unwrap()[0].is_empty());
        } else {
            match status {
                Err(StoreError::Unavailable { detail, .. }) => {
                    assert!(
                        detail.contains("cannot sync the replica"),
                        "{command}: {detail}"
                    )
                }
                other => panic!("{command}: expected Unavailable, got {other:?}"),
            }
        }
    }
}

/// A server or proxy whose error page is not UTF-8 text (a Latin-1 502)
/// makes libsql 0.10.0 panic: the store fails instead (a latched
/// `Unavailable`), for every call and on the warming thread.
#[test]
fn an_error_page_the_client_cannot_read_fails_without_a_panic() {
    let body: &[u8] = b"<html>Mauvaise passerelle \xe9t\xe9</html>";
    let mut response = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html; charset=iso-8859-1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    let mut binary =
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\nConnection: close\r\n\r\n"
            .to_vec();
    binary.extend_from_slice(&[0xff, 0xfe, 0x00, 0x80]);
    for response in [response, binary] {
        let port = canned_port(response);
        let sel = testkit::selection(
            LibsqlMode::Remote,
            Some(&format!("libsql://127.0.0.1:{port}?tls=0")),
            Some("s3cretTok"),
            Some("ns"),
            None,
        );
        let s = open(&sel);
        s.warm();
        let e = s.status().unwrap_err();
        assert!(matches!(e, StoreError::Unavailable { .. }), "{e:?}");
        assert!(e.to_string().contains("cannot read"), "{e}");
        let e = s.list_units(&["src/a.test.ts"]).unwrap_err();
        assert!(e.to_string().contains("not retried"), "{e}");
        assert!(!format!("{e} {e:?}").contains("s3cretTok"));
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---- connections dropped while idle ---------------------------------------------------

/// How a [`Proxy`] closes the client's side of a connection it forgot,
/// when the client sends its next request on it.
#[derive(Clone, Copy, Debug)]
enum Close {
    /// The whole request is read, then the connection closed (FIN), with
    /// no answer: hyper's `connection closed before message completed`,
    /// what vex's CI got from Turso.
    Fin,
    /// The connection is closed with the request unread, which resets it
    /// (RST): `connection reset by peer` or `broken pipe`.
    Reset,
}

/// A TCP proxy in front of a server that forgets a connection once it has
/// sat idle for `idle` with no request outstanding, as a load balancer or
/// a NAT does, without telling the client: its connection to the server
/// is closed at once, the client's side only when the client sends its
/// next request on it ([`Close`]), so the client cannot see it coming.
/// [`Proxy::go_away`] makes it stop listening (a new connection is
/// refused) and forget every connection; [`Proxy::cut_cursors`] and
/// [`Proxy::answer_with`] make it cut off a read's answer, or answer every
/// request itself.
struct Proxy {
    port: u16,
    shared: Arc<Shared>,
    listener: Option<std::thread::JoinHandle<()>>,
}

/// What a [`Proxy`] and its connections share.
#[derive(Default)]
struct Shared {
    /// It stopped listening, and forgets every connection.
    gone: AtomicBool,
    /// Connections it forgot.
    forgotten: AtomicUsize,
    /// While set, the answer to a cursor request (`POST /v3/cursor`: a
    /// read's rows) is cut off after its headers and the first bytes of
    /// its body, and the client's connection closed (FIN): an answer the
    /// server began, which ends early.
    cut_cursors: AtomicBool,
    /// Answers it cut off.
    cut: AtomicUsize,
    /// While set, every request is answered with this (an HTTP response,
    /// whole, that closes the connection) instead of being sent on.
    canned: Mutex<Option<Vec<u8>>>,
    /// Requests it answered itself.
    canned_sent: AtomicUsize,
    /// The next this many cursor requests (a read's rows) are never
    /// answered: held until the client gives up and closes.
    stall_cursors: AtomicUsize,
    /// While set, every write (a request holding `BEGIN IMMEDIATE`) is
    /// never answered.
    stall_writes: AtomicBool,
    /// Requests it held unanswered.
    stalled: AtomicUsize,
    /// The next this many cursor requests are cut off (as `cut_cursors`),
    /// after `pass_cursors` more went through.
    cut_next: AtomicUsize,
    /// Cursor requests to let through before `cut_next` applies.
    pass_cursors: AtomicUsize,
    /// The next this many writes are sent on to the server, and its
    /// answer is never passed on: held until the client gives up.
    swallow_writes: AtomicUsize,
    /// The next this many writes are never sent on, nor answered.
    hold_writes: AtomicUsize,
    /// The next this many writes are sent on `late_ms` after they arrived
    /// (once the client gave up on them), and never answered: a write that
    /// waited for the write lock past its deadline and then committed.
    late_writes: AtomicUsize,
    late_ms: AtomicUsize,
    /// Late writes sent on and answered.
    late_done: AtomicUsize,
    /// Writes sent on to the server.
    writes: AtomicUsize,
    /// Bytes a second passed on from the server to the clients, all its
    /// connections together (0: as fast as they come).
    rate: AtomicUsize,
    /// When the bytes passed on so far at `rate` are through.
    rate_next: Mutex<Option<Instant>>,
    /// Bytes passed on from the server to the clients.
    passed: AtomicUsize,
    /// What the next cursor requests get, in order, before any other
    /// setting: `true` never answered (as `stall_cursors`), `false` sent
    /// on.
    schedule: Mutex<std::collections::VecDeque<bool>>,
    /// Cursor requests that reached it.
    cursors: AtomicUsize,
    /// Milliseconds each answer waits before its first byte is passed on
    /// (a server, or a link, slow to answer whatever the answer's size).
    delay_ms: AtomicUsize,
    /// The bytes of each write request sent on (a request holding `BEGIN
    /// IMMEDIATE`), in order.
    write_sizes: Mutex<Vec<usize>>,
    /// When each write request sent on began, and when the last byte of
    /// its answer was passed on, in order.
    write_times: Mutex<Vec<(Instant, Option<Instant>)>>,
}

impl Shared {
    /// Wait until `n` more bytes may go to a client at `rate`.
    fn throttle(&self, n: usize) {
        self.passed.fetch_add(n, Ordering::SeqCst);
        let rate = self.rate.load(Ordering::SeqCst);
        if rate == 0 {
            return;
        }
        let now = Instant::now();
        let at = {
            let mut next = self.rate_next.lock().unwrap();
            let start = next.filter(|t| *t > now).unwrap_or(now);
            let at = start + Duration::from_secs_f64(n as f64 / rate as f64);
            *next = Some(at);
            at
        };
        std::thread::sleep(at.saturating_duration_since(now));
    }
}

/// The test server's `host:port` and token, when it speaks plain HTTP (a
/// throwaway `sqld`, `turso dev`, the CI's service container), for a
/// [`Proxy`] to stand in front of; `None` (the test skipped) otherwise.
fn proxied_server() -> Option<(String, Option<String>)> {
    if !testkit::available() {
        return None;
    }
    let s = testkit::server().ok()?;
    let hostport = s
        .url
        .strip_prefix("http://")
        .map(|r| r.trim_end_matches('/'));
    match hostport {
        Some(h) if !h.contains('/') && !h.contains('?') => Some((h.to_owned(), s.token.clone())),
        _ => {
            eprintln!(
                "skipping: the test server is not plain http://<host>:<port>, which the proxy needs"
            );
            None
        }
    }
}

impl Proxy {
    fn start(upstream: &str, idle: Duration, close: Close) -> Proxy {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let port = l.local_addr().unwrap().port();
        let upstream = upstream.to_owned();
        let shared = Arc::new(Shared::default());
        let sh = shared.clone();
        let listener = std::thread::spawn(move || {
            while !sh.gone.load(Ordering::SeqCst) {
                match l.accept() {
                    Ok((client, _)) => {
                        let (sh, upstream) = (sh.clone(), upstream.clone());
                        std::thread::spawn(move || relay(client, &upstream, idle, close, &sh));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(2)),
                }
            }
            // The listener closes here: a new connection is refused.
        });
        Proxy {
            port,
            shared,
            listener: Some(listener),
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// How many connections it forgot.
    fn forgotten(&self) -> usize {
        self.shared.forgotten.load(Ordering::SeqCst)
    }

    /// Cut off the answers to cursor requests from now on, or stop.
    fn cut_cursors(&self, on: bool) {
        self.shared.cut_cursors.store(on, Ordering::SeqCst);
    }

    /// Never answer the next `n` cursor requests.
    fn stall_cursors(&self, n: usize) {
        self.shared.stall_cursors.store(n, Ordering::SeqCst);
    }

    /// Never answer `n` cursor requests, after `pass` more went through.
    fn stall_after(&self, pass: usize, n: usize) {
        self.shared.pass_cursors.store(pass, Ordering::SeqCst);
        self.shared.stall_cursors.store(n, Ordering::SeqCst);
    }

    /// The next cursor requests, in order: `true` never answered, `false`
    /// sent on.
    fn schedule(&self, next: &[bool]) {
        *self.shared.schedule.lock().unwrap() = next.iter().copied().collect();
    }

    /// How many cursor requests (a read's rows) reached it.
    fn cursors(&self) -> usize {
        self.shared.cursors.load(Ordering::SeqCst)
    }

    /// Never answer a write from now on, or stop.
    fn stall_writes(&self, on: bool) {
        self.shared.stall_writes.store(on, Ordering::SeqCst);
    }

    /// Send the next `n` writes on, and never pass on their answers.
    fn swallow_writes(&self, n: usize) {
        self.shared.swallow_writes.store(n, Ordering::SeqCst);
    }

    /// Never send on, nor answer, the next `n` writes.
    fn hold_writes(&self, n: usize) {
        self.shared.hold_writes.store(n, Ordering::SeqCst);
    }

    /// Send the next `n` writes on `ms` milliseconds late, and never
    /// answer them.
    fn late_writes(&self, n: usize, ms: usize) {
        self.shared.late_ms.store(ms, Ordering::SeqCst);
        self.shared.late_writes.store(n, Ordering::SeqCst);
    }

    /// Hold each answer `ms` milliseconds before passing on its first
    /// byte (0: no wait).
    fn delay_answers(&self, ms: usize) {
        self.shared.delay_ms.store(ms, Ordering::SeqCst);
    }

    /// The size of each write request sent on, in order.
    fn write_sizes(&self) -> Vec<usize> {
        self.shared.write_sizes.lock().unwrap().clone()
    }

    /// The time from the end of each write's answer to the start of the
    /// next write.
    fn write_gaps(&self) -> Vec<Duration> {
        let t = self.shared.write_times.lock().unwrap();
        t.windows(2)
            .filter_map(|w| Some(w[1].0.saturating_duration_since(w[0].1?)))
            .collect()
    }

    /// How many bytes it passed on from the server.
    fn passed(&self) -> usize {
        self.shared.passed.load(Ordering::SeqCst)
    }

    /// How many writes it sent on to the server.
    fn writes(&self) -> usize {
        self.shared.writes.load(Ordering::SeqCst)
    }

    /// Pass on at most `bytes` a second from the server, all connections
    /// together (0: no limit).
    fn limit_rate(&self, bytes: usize) {
        self.shared.rate.store(bytes, Ordering::SeqCst);
    }

    /// How many requests it held unanswered.
    fn stalled(&self) -> usize {
        self.shared.stalled.load(Ordering::SeqCst)
    }

    /// Cut off the answers to `n` cursor requests, after `pass` more went
    /// through.
    fn cut_next(&self, pass: usize, n: usize) {
        self.shared.pass_cursors.store(pass, Ordering::SeqCst);
        self.shared.cut_next.store(n, Ordering::SeqCst);
    }

    /// How many answers it cut off.
    fn cut(&self) -> usize {
        self.shared.cut.load(Ordering::SeqCst)
    }

    /// Answer every request with `response` from now on (`None`: send them
    /// on again).
    fn answer_with(&self, response: Option<Vec<u8>>) {
        *self.shared.canned.lock().unwrap() = response;
    }

    /// How many requests it answered itself.
    fn canned_sent(&self) -> usize {
        self.shared.canned_sent.load(Ordering::SeqCst)
    }

    /// Stop listening, and forget every connection.
    fn go_away(&mut self) {
        self.shared.gone.store(true, Ordering::SeqCst);
        if let Some(l) = self.listener.take() {
            l.join().unwrap();
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.go_away();
    }
}

/// Write all of `b` to a non-blocking socket.
fn send_all(mut to: &std::net::TcpStream, mut b: &[u8]) -> bool {
    use std::io::{ErrorKind, Write as _};
    while !b.is_empty() {
        match to.write(b) {
            Ok(0) => return false,
            Ok(n) => b = &b[n..],
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(_) => return false,
        }
    }
    true
}

/// Read what `from` has (non-blocking): `Some(0)` when it closed, `None`
/// when nothing is there yet.
fn take(mut from: &std::net::TcpStream, buf: &mut [u8]) -> Option<usize> {
    use std::io::{ErrorKind, Read as _};
    match from.read(buf) {
        Ok(n) => Some(n),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => None,
        Err(_) => Some(0),
    }
}

/// Read what `client` still sends (the rest of a request) until it pauses
/// for 50 ms; `false` when it closed.
fn drain(client: &std::net::TcpStream, buf: &mut [u8]) -> bool {
    let mut quiet = Instant::now();
    while quiet.elapsed() < Duration::from_millis(50) {
        match take(client, buf) {
            Some(0) => return false,
            Some(_) => quiet = Instant::now(),
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    }
    true
}

/// Close the client's side of the connection (FIN), then read whatever the
/// client still sends until it closes (at most 5 s).
fn hang_up(client: &std::net::TcpStream, buf: &mut [u8]) {
    let _ = client.shutdown(std::net::Shutdown::Write);
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until && take(client, buf) != Some(0) {
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// One client connection of a [`Proxy`].
fn relay(client: std::net::TcpStream, upstream: &str, idle: Duration, close: Close, sh: &Shared) {
    let Ok(server) = std::net::TcpStream::connect(upstream) else {
        return;
    };
    for s in [&client, &server] {
        s.set_nonblocking(true).unwrap();
        s.set_nodelay(true).unwrap();
    }
    let mut server = Some(server);
    let mut last = Instant::now();
    // A request was sent and its answer has not started: not idle.
    let mut waiting = false;
    // The answer to the request sent is to be cut off: what came of it.
    let mut cutting: Option<Vec<u8>> = None;
    // The answer to the request sent is never passed on.
    let mut swallowing = false;
    // The request sent is a write: its bytes are counted.
    let mut writing = false;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if server.is_some()
            && (sh.gone.load(Ordering::SeqCst) || (!waiting && last.elapsed() > idle))
        {
            // Forgotten: the server's side closes now, the client is not
            // told.
            server = None;
            sh.forgotten.fetch_add(1, Ordering::SeqCst);
        }
        let mut moved = false;
        let Some(s) = &server else {
            // The client's next request on a forgotten connection: one
            // byte of it is read, then the connection is closed.
            match take(&client, &mut buf[..1]) {
                None => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Some(0) => return,
                Some(_) => {}
            }
            // The rest of the request, then a FIN, then whatever the client
            // still does until it closes; Close::Reset: dropped with the
            // rest of the request unread, which resets the connection.
            if let Close::Fin = close
                && drain(&client, &mut buf)
            {
                hang_up(&client, &mut buf);
            }
            return;
        };
        match take(&client, &mut buf) {
            Some(0) => return,
            Some(n) => {
                if !waiting {
                    // A request starts.
                    let canned = sh.canned.lock().unwrap().clone();
                    if let Some(response) = canned {
                        if drain(&client, &mut buf) {
                            sh.canned_sent.fetch_add(1, Ordering::SeqCst);
                            let _ = send_all(&client, &response);
                            hang_up(&client, &mut buf);
                        }
                        return;
                    }
                    let cursor = buf[..n].starts_with(b"POST /v3/cursor");
                    let write = buf[..n].windows(15).any(|w| w == b"BEGIN IMMEDIATE");
                    let take_one = |n: &AtomicUsize| {
                        n.try_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
                            .is_ok()
                    };
                    if cursor {
                        sh.cursors.fetch_add(1, Ordering::SeqCst);
                    }
                    let scheduled = if cursor {
                        sh.schedule.lock().unwrap().pop_front()
                    } else {
                        None
                    };
                    let stall_one = scheduled.unwrap_or_else(|| {
                        cursor
                            && sh.stall_cursors.load(Ordering::SeqCst) > 0
                            && !take_one(&sh.pass_cursors)
                            && take_one(&sh.stall_cursors)
                    });
                    let hold_one = write && take_one(&sh.hold_writes);
                    if write && take_one(&sh.late_writes) {
                        // The whole request, sent on late; its answer
                        // read and dropped.
                        let mut request = buf[..n].to_vec();
                        let mut quiet = Instant::now();
                        while quiet.elapsed() < Duration::from_millis(50) {
                            match take(&client, &mut buf) {
                                Some(0) => break,
                                Some(m) => {
                                    request.extend_from_slice(&buf[..m]);
                                    quiet = Instant::now();
                                }
                                None => std::thread::sleep(Duration::from_millis(1)),
                            }
                        }
                        sh.stalled.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(
                            sh.late_ms.load(Ordering::SeqCst) as u64,
                        ));
                        sh.writes.fetch_add(1, Ordering::SeqCst);
                        if send_all(s, &request) {
                            // Its answer: until it pauses 100 ms once begun.
                            let until = Instant::now() + Duration::from_secs(10);
                            let mut quiet: Option<Instant> = None;
                            while Instant::now() < until
                                && quiet.is_none_or(|q| q.elapsed() < Duration::from_millis(100))
                            {
                                match take(s, &mut buf) {
                                    Some(0) => break,
                                    Some(_) => quiet = Some(Instant::now()),
                                    None => std::thread::sleep(Duration::from_millis(1)),
                                }
                            }
                            sh.late_done.fetch_add(1, Ordering::SeqCst);
                        }
                        return;
                    }
                    if stall_one || hold_one || (write && sh.stall_writes.load(Ordering::SeqCst)) {
                        // Held: read what the client sends until it closes.
                        sh.stalled.fetch_add(1, Ordering::SeqCst);
                        while !sh.gone.load(Ordering::SeqCst) {
                            match take(&client, &mut buf) {
                                Some(0) => return,
                                Some(_) => {}
                                None => std::thread::sleep(Duration::from_millis(2)),
                            }
                        }
                        return;
                    }
                    let cut_one = cursor
                        && sh.cut_next.load(Ordering::SeqCst) > 0
                        && !take_one(&sh.pass_cursors)
                        && take_one(&sh.cut_next);
                    cutting = ((sh.cut_cursors.load(Ordering::SeqCst) && cursor) || cut_one)
                        .then(Vec::new);
                    swallowing = write && take_one(&sh.swallow_writes);
                    writing = write;
                    if write {
                        sh.writes.fetch_add(1, Ordering::SeqCst);
                        sh.write_sizes.lock().unwrap().push(0);
                        sh.write_times.lock().unwrap().push((Instant::now(), None));
                    }
                }
                if writing && let Some(last) = sh.write_sizes.lock().unwrap().last_mut() {
                    *last += n;
                }
                if !send_all(s, &buf[..n]) {
                    return;
                }
                (moved, waiting, last) = (true, true, Instant::now());
            }
            None => {}
        }
        match take(s, &mut buf) {
            Some(0) => {
                // The server closed: the client is told.
                let _ = client.shutdown(std::net::Shutdown::Write);
                return;
            }
            Some(n) => {
                if swallowing {
                    // The server answered; the client never hears it.
                    sh.stalled.fetch_add(1, Ordering::SeqCst);
                    while !sh.gone.load(Ordering::SeqCst) {
                        match take(&client, &mut buf) {
                            Some(0) => return,
                            Some(_) => {}
                            None => std::thread::sleep(Duration::from_millis(2)),
                        }
                    }
                    return;
                }
                if let Some(head) = &mut cutting {
                    // The headers and the first bytes of the body, then a
                    // FIN.
                    head.extend_from_slice(&buf[..n]);
                    if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                        let _ = send_all(&client, &head[..head.len().min(end + 4 + 8)]);
                        sh.cut.fetch_add(1, Ordering::SeqCst);
                        hang_up(&client, &mut buf);
                        return;
                    }
                    (moved, last) = (true, Instant::now());
                } else {
                    let delay = sh.delay_ms.load(Ordering::SeqCst);
                    if waiting && delay > 0 {
                        // The first bytes of an answer.
                        std::thread::sleep(Duration::from_millis(delay as u64));
                    }
                    sh.throttle(n);
                    if !send_all(&client, &buf[..n]) {
                        return;
                    }
                    if writing && let Some(last) = sh.write_times.lock().unwrap().last_mut() {
                        last.1 = Some(Instant::now());
                    }
                    (moved, waiting, last) = (true, false, Instant::now());
                }
            }
            None => {}
        }
        if !moved {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// A keep-alive connection that a server, or a proxy in front of it,
/// closed while it sat idle (vex's CI met it on Turso) is found out only
/// when the next request goes out on it: hyper's `connection closed before
/// message completed`, or a reset. The request is sent again on a new
/// connection, so the write, and every call after it, succeed and nothing
/// is latched (2.8.0 latched `cannot reach` and refused every later write
/// of the process). Reads are sent again the same way.
#[test]
fn a_connection_the_server_dropped_while_idle_is_replaced() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    for close in [Close::Fin, Close::Reset] {
        let proxy = Proxy::start(&server, Duration::from_millis(300), close);
        let s = open(&testkit::selection(
            LibsqlMode::Remote,
            Some(&proxy.url()),
            token.as_deref(),
            Some(&testkit::namespace()),
            None,
        ));
        let put = |n: u8, unit: &str| {
            s.put_for_test(unit, S1, &hex64(n), Some(&hint(1)), &envelope(None, unit))
        };
        put(1, "src/a.test.ts").unwrap_or_else(|e| panic!("{close:?}: the first write: {e}"));
        let before = s.retries();
        // Longer than the proxy keeps an idle connection.
        std::thread::sleep(Duration::from_millis(800));
        put(2, "src/b.test.ts")
            .unwrap_or_else(|e| panic!("{close:?}: the write after an idle wait: {e}"));
        assert!(proxy.forgotten() >= 1, "{close:?}");
        let after_write = s.retries();
        assert!(after_write > before, "{close:?}: no request was sent again");
        std::thread::sleep(Duration::from_millis(800));
        let targets: Vec<String> = s
            .list_all()
            .unwrap_or_else(|e| panic!("{close:?}: the read after an idle wait: {e}"))
            .into_iter()
            .map(|e| e.target)
            .collect();
        assert_eq!(
            targets,
            ["path:src/a.test.ts", "path:src/b.test.ts"],
            "{close:?}"
        );
        assert!(
            s.retries() > after_write,
            "{close:?}: the read was not sent again"
        );
        // Nothing was latched.
        put(3, "src/c.test.ts").unwrap_or_else(|e| panic!("{close:?}: a later write: {e}"));
        s.status().unwrap();
    }
}

/// A server that went away while the handle's connection sat idle: the
/// request sent again finds nothing listening, which latches the breaker
/// at once, as an unreachable server always has; every later call fails
/// at once.
#[test]
fn a_server_gone_while_idle_stays_latched_and_fast() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    for close in [Close::Fin, Close::Reset] {
        let mut proxy = Proxy::start(&server, Duration::from_secs(60), close);
        let s = open(&testkit::selection(
            LibsqlMode::Remote,
            Some(&proxy.url()),
            token.as_deref(),
            Some(&testkit::namespace()),
            None,
        ));
        let put = |n: u8, unit: &str| {
            s.put_for_test(unit, S1, &hex64(n), Some(&hint(1)), &envelope(None, unit))
        };
        put(1, "src/a.test.ts").unwrap();
        // Another test's writer may have kept this one waiting.
        let before = s.retries();
        proxy.go_away();
        let t = Instant::now();
        let e = put(2, "src/b.test.ts").unwrap_err();
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "{close:?}: {:?}",
            t.elapsed()
        );
        assert!(
            matches!(e, StoreError::Unavailable { .. }),
            "{close:?}: {e:?}"
        );
        // Sent again at once, on a new connection, which nothing accepted.
        assert!(e.to_string().contains("cannot reach"), "{close:?}: {e}");
        assert!(
            e.to_string().contains("error trying to connect"),
            "{close:?}: {e}"
        );
        assert_eq!(s.retries() - before, 1, "{close:?}");
        let t = Instant::now();
        for i in 0..40 {
            let e = put(3, &format!("src/c{i}.test.ts")).unwrap_err();
            assert!(e.to_string().contains("not retried"), "{close:?}: {e}");
            assert!(s.list_all().is_err());
        }
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "{close:?}: {:?}",
            t.elapsed()
        );
    }
}

/// How a [`closing_port`] ends each connection it accepts, never
/// answering.
#[derive(Clone, Copy, Debug)]
enum Hangup {
    /// Closed at once (a FIN), before the request: a port that accepts
    /// with nothing behind it (a `docker-proxy` whose container is gone).
    AtOnce,
    /// Closed with the request unread, which resets it (RST).
    Reset,
    /// The whole request read, then closed (a FIN) after this wait.
    After(Duration),
}

/// A port where something accepts connections and closes each without
/// answering ([`Hangup`]), and the number of connections it accepted.
fn closing_port(how: Hangup) -> (u16, Arc<AtomicUsize>) {
    use std::io::Read as _;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let n = accepted.clone();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            n.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                match how {
                    Hangup::AtOnce => {}
                    Hangup::Reset => {
                        let _ = c.read(&mut buf[..1]);
                    }
                    Hangup::After(wait) => {
                        let mut got = Vec::new();
                        // The headers, then as much body as they announce.
                        while let Ok(n) = c.read(&mut buf) {
                            if n == 0 {
                                return;
                            }
                            got.extend_from_slice(&buf[..n]);
                            let text = String::from_utf8_lossy(&got).to_ascii_lowercase();
                            if let Some(end) = text.find("\r\n\r\n") {
                                let len = text
                                    .lines()
                                    .find_map(|l| l.strip_prefix("content-length:"))
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                                    .unwrap_or(0);
                                if got.len() >= end + 4 + len {
                                    break;
                                }
                            }
                        }
                        std::thread::sleep(wait);
                    }
                }
            });
        }
    });
    (port, accepted)
}

/// A handle whose server has never answered cannot have a kept-alive
/// connection to lose, so a server that accepts a connection and closes it
/// without answering (at once, with a reset, or after a wait) is a server
/// out of reach, as in 2.8.0: the first call, a read or a write, fails on
/// the one connection it made, within the wait, and every later call at
/// once. (Sending it again on new connections, each bounded by the first
/// answer's deadline anew, made it four times as long.)
#[test]
fn a_server_that_closes_without_ever_answering_is_not_asked_again() {
    for how in [
        Hangup::AtOnce,
        Hangup::Reset,
        Hangup::After(Duration::from_millis(700)),
    ] {
        for write in [false, true] {
            let (port, accepted) = closing_port(how);
            let mut sel = testkit::selection(
                LibsqlMode::Remote,
                Some(&format!("http://127.0.0.1:{port}")),
                None,
                Some("ns"),
                None,
            );
            sel.connect_timeout = Sourced {
                value: Duration::from_secs(1),
                source: Source::File,
            };
            let s = open(&sel);
            let t = Instant::now();
            let e = if write {
                s.put_for_test("src/a.test.ts", S1, "00", None, b"{}")
                    .unwrap_err()
            } else {
                s.list_units(&["src/a.test.ts"]).unwrap_err()
            };
            let took = t.elapsed();
            assert!(
                matches!(e, StoreError::Unavailable { .. }),
                "{how:?}, write {write}: {e:?}"
            );
            assert_eq!(
                accepted.load(Ordering::SeqCst),
                1,
                "{how:?}, write {write}: {e}"
            );
            assert_eq!(s.retries(), 0, "{how:?}, write {write}");
            assert!(
                took < Duration::from_millis(1500),
                "{how:?}, write {write}: {took:?}"
            );
            let t = Instant::now();
            let e = s.list_all().unwrap_err();
            assert!(e.to_string().contains("not retried"), "{how:?}: {e}");
            assert!(t.elapsed() < Duration::from_millis(200));
            assert_eq!(accepted.load(Ordering::SeqCst), 1, "{how:?}");
        }
    }
}

/// An answer the server began and that was cut off (a read's rows: the
/// headers and a few bytes, then the connection closed) is not a
/// connection lost under the request, which is found out before any
/// answer: the read fails, as in 2.8.0, without being sent again, and
/// nothing is latched, so the next write and read succeed. (Taken for a
/// lost connection, it was sent four times and then latched the breaker,
/// and every later call of the process failed.)
#[test]
fn a_read_whose_answer_is_cut_off_fails_alone() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let s = open(&testkit::selection(
        LibsqlMode::Remote,
        Some(&proxy.url()),
        token.as_deref(),
        Some(&testkit::namespace()),
        None,
    ));
    let put = |n: u8, unit: &str| {
        s.put_for_test(unit, S1, &hex64(n), Some(&hint(1)), &envelope(None, unit))
    };
    put(1, "src/a.test.ts").unwrap();
    proxy.cut_cursors(true);
    let e = s.list_all().unwrap_err();
    assert!(matches!(e, StoreError::Unavailable { .. }), "{e:?}");
    let msg = e.to_string();
    assert!(msg.contains("cursor error"), "{msg}");
    assert!(!msg.contains("cannot reach"), "{msg}");
    assert_eq!(proxy.cut(), 1, "{msg}");
    proxy.cut_cursors(false);
    put(2, "src/b.test.ts").unwrap_or_else(|e| panic!("a write after the cut: {e}"));
    let targets: Vec<String> = s
        .list_all()
        .unwrap_or_else(|e| panic!("a read after the cut: {e}"))
        .into_iter()
        .map(|e| e.target)
        .collect();
    assert_eq!(targets, ["path:src/a.test.ts", "path:src/b.test.ts"]);
    assert_eq!(proxy.cut(), 1);
}

/// An HTTP status is the server's answer and is never sent again, whatever
/// its body says: a proxy's error page that quotes an upstream's transport
/// error (`http error: connection reset by peer`) is answered once, a 502
/// latching the breaker as any 5xx and a 401 as a token refused. (Taken
/// for a lost connection, it was sent four times, a 401 latched as
/// `cannot reach`.)
#[test]
fn an_http_status_is_never_sent_again_whatever_its_body_says() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let body = "upstream: http error: `connection reset by peer`";
    for (status, says) in [
        ("502 Bad Gateway", "status=502"),
        ("401 Unauthorized", "token"),
    ] {
        let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
        let s = open(&testkit::selection(
            LibsqlMode::Remote,
            Some(&proxy.url()),
            token.as_deref(),
            Some(&testkit::namespace()),
            None,
        ));
        let put = |n: u8, unit: &str| {
            s.put_for_test(unit, S1, &hex64(n), Some(&hint(1)), &envelope(None, unit))
        };
        // The server has answered this handle.
        put(1, "src/a.test.ts").unwrap();
        proxy.answer_with(Some(
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        ));
        let e = put(2, "src/b.test.ts").unwrap_err();
        let msg = e.to_string();
        assert!(
            matches!(e, StoreError::Unavailable { .. }),
            "{status}: {e:?}"
        );
        assert_eq!(proxy.canned_sent(), 1, "{status}: {msg}");
        assert!(msg.contains(says), "{status}: {msg}");
        assert!(!msg.contains("cannot reach"), "{status}: {msg}");
        let e = put(3, "src/c.test.ts").unwrap_err();
        assert!(e.to_string().contains("not retried"), "{status}: {e}");
        assert_eq!(proxy.canned_sent(), 1, "{status}");
    }
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

/// A URL from `vci.toml` the store cannot use is named so, not as
/// `$VCI_STORE_URL`.
#[test]
fn a_url_from_vci_toml_is_named_so() {
    let mut s = testkit::selection(
        LibsqlMode::Remote,
        Some("libsql://h%41st.turso.io"),
        None,
        None,
        None,
    );
    s.url.as_mut().unwrap().source = Source::File;
    let e = LibsqlStore::open(&s, &testkit::cx())
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("vci.toml [store] url needs a host name") && !e.contains("$VCI_STORE_URL"),
        "{e}"
    );
    s.url.as_mut().unwrap().source = Source::Env("VCI_STORE_URL");
    let e = LibsqlStore::open(&s, &testkit::cx())
        .unwrap_err()
        .to_string();
    assert!(e.contains("$VCI_STORE_URL needs a host name"), "{e}");
}

/// `[store] token_command` supplies the token when neither
/// `VCI_STORE_TOKEN` nor the URL does: the server gets it (a `sqld` that
/// checks tokens accepts it), the command runs when the store first
/// connects, never when it opens or warms up, and not at all when another
/// token is there (`VCI_STORE_TOKEN`, or an `authToken` in the URL, which
/// the server then gets); a token the server refuses, or a command that fails, makes the
/// store unavailable saying so, and no message shows the token.
#[test]
fn a_token_command_supplies_the_token() {
    use std::os::unix::fs::PermissionsExt as _;
    use vci_store::select::TokenCommand;
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
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
    let good = jwt(&key, &serde_json::json!({}));
    let wrong = jwt(
        &ed25519_dalek::SigningKey::from_bytes(&[10; 32]),
        &serde_json::json!({}),
    );
    let mut cx = testkit::cx();
    cx.repo_root = dir.path().to_owned();
    let counter = dir.path().join("runs");
    // A helper per token, each counting its runs.
    let helper = |name: &str, body: &str| {
        let p = dir.path().join(name);
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\necho run >> {:?}\n{body}\n",
                counter.to_str().unwrap()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        TokenCommand::Argv(vec![p.to_str().unwrap().to_owned()])
    };
    let runs = || {
        std::fs::read_to_string(&counter)
            .map(|s| s.lines().count())
            .unwrap_or(0)
    };
    let with = |cmd: TokenCommand, token: Option<&str>| {
        let mut s = testkit::selection(
            LibsqlMode::Remote,
            Some(&server.url()),
            token,
            Some(&testkit::namespace()),
            None,
        );
        s.token_command = Some(cmd);
        LibsqlStore::open(&s, &cx).expect("open")
    };
    let s = with(helper("good", &format!("echo {good}")), None);
    assert_eq!(runs(), 0, "opening runs nothing");
    s.put_for_test("src/a.test.ts", S1, &hex64(1), None, b"{}")
        .unwrap();
    assert_eq!(s.list_units(&["src/a.test.ts"]).unwrap()[0].len(), 1);
    assert_eq!(runs(), 1, "run once, when the store first connected");
    assert!(!format!("{s:?} {}", s.location()).contains(&good));

    // warm() runs nothing while the command has not run (its thread is
    // never joined, and the plan may never read the store): the first
    // read does.
    let s = with(helper("warm", &format!("echo {good}")), None);
    s.warm();
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(runs(), 1, "warm() ran the token command");
    s.status().unwrap();
    assert_eq!(runs(), 2);
    s.warm();

    // VCI_STORE_TOKEN wins: the command is never run.
    let s = with(helper("unused", "echo unused"), Some(&good));
    s.status().unwrap();
    assert_eq!(runs(), 2);

    // So does an authToken in VCI_STORE_URL (a CI job may set only the
    // URL): the server gets the URL's token, and the command, whose token
    // it would refuse, never runs.
    let mut sel = testkit::selection(
        LibsqlMode::Remote,
        Some(&format!("{}?authToken={good}", server.url())),
        None,
        Some(&testkit::namespace()),
        None,
    );
    sel.token_command = Some(helper("loses", &format!("echo {wrong}")));
    let s = LibsqlStore::open(&sel, &cx).expect("open");
    s.put_for_test("src/a.test.ts", S1, &hex64(2), None, b"{}")
        .unwrap();
    assert_eq!(s.list_units(&["src/a.test.ts"]).unwrap()[0].len(), 1);
    assert_eq!(runs(), 2, "the URL's authToken wins over the command");

    // A token the server refuses: unavailable, naming the command.
    let s = with(helper("wrong", &format!("echo {wrong}")), None);
    let e = s.status().unwrap_err();
    let all = format!("{e} {e:?} {s:?}");
    assert!(matches!(e, StoreError::Unavailable { .. }), "{all}");
    assert!(
        all.contains("the server refused the token from [store] token_command ("),
        "{all}"
    );
    assert!(!all.contains(&wrong), "{all}");

    // A command that fails: unavailable, saying how (never what it wrote
    // on standard error), and never retried.
    let s = with(
        helper(
            "fails",
            &format!("echo {good}\necho denied {good} >&2\nexit 4"),
        ),
        None,
    );
    let before = runs();
    for _ in 0..3 {
        let e = s.status().unwrap_err();
        let all = format!("{e} {e:?}");
        assert!(matches!(e, StoreError::Unavailable { .. }), "{all}");
        assert!(
            all.contains(&format!("exited 4; {}", vci_store::credential::HINT)),
            "{all}"
        );
        assert!(!all.contains(&good) && !all.contains("denied"), "{all}");
    }
    assert_eq!(runs(), before + 1);
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

// ---- contracts the conformance suite cannot reach --------------------------------------

fn keys_of(s: &LibsqlStore, unit: &str) -> Vec<String> {
    s.list_units(&[unit])
        .unwrap()
        .remove(0)
        .into_iter()
        .map(|e| e.key)
        .collect()
}

/// What `read_values` makes of one entry: `read` or the error.
fn read_state(s: &LibsqlStore, e: &StoredEnvelope) -> String {
    let mut e = StoredEnvelope::from_key(e.target.clone(), &e.key).unwrap();
    s.read_values(&mut [&mut e]).unwrap();
    match e.state() {
        ValueState::Read(_) => "read".to_owned(),
        other => format!("{other:?}"),
    }
}

/// A removal outside a batch is read by this handle afterwards, also when
/// another writer removed or replaced the key first (the server then
/// holds nothing to remove): its prefetched cache and a replica's file
/// forget the key all the same.
#[test]
fn a_handle_reads_its_own_removals_after_others_wrote() {
    let Some((a, ns)) = remote() else { return };
    let b = testkit::open_remote(&ns).unwrap();
    let unit = "src/rm.test.ts";
    // Removed by the other writer first.
    let k = a
        .put_for_test(unit, S1, &hex64(1), Some(&hint(1)), &envelope(None, "one"))
        .unwrap();
    a.prefetch(Prefetch::Units {
        test_ids: &[unit],
        choose: None,
    })
    .unwrap();
    assert_eq!(b.remove(vec![k.clone()]).unwrap().len(), 1);
    assert!(
        a.remove(vec![k.clone()]).unwrap().is_empty(),
        "the server held nothing"
    );
    assert!(
        keys_of(&a, unit).is_empty(),
        "this handle still lists what it removed"
    );
    assert!(
        read_state(&a, &k).contains("no longer"),
        "{}",
        read_state(&a, &k)
    );
    // Replaced by the other writer first.
    let k1 = a
        .put_for_test(unit, S1, &hex64(2), Some(&hint(1)), &envelope(None, "two"))
        .unwrap();
    a.prefetch(Prefetch::Units {
        test_ids: &[unit],
        choose: None,
    })
    .unwrap();
    let k2 = b
        .put_for_test(
            unit,
            S1,
            &hex64(2),
            Some(&hint(2)),
            &envelope(None, "three"),
        )
        .unwrap();
    a.remove(vec![k1.clone()]).unwrap();
    assert!(!keys_of(&a, unit).contains(&k1.key));
    assert_eq!(
        keys_of(&testkit::open_remote(&ns).unwrap(), unit),
        vec![k2.key]
    );
    // A replica: removed on the server by another writer, then by the
    // replica's handle.
    let dir = tempfile::tempdir().unwrap();
    let k3 = a
        .put_for_test(
            "src/rm2.test.ts",
            S1,
            &hex64(3),
            Some(&hint(1)),
            &envelope(None, "four"),
        )
        .unwrap();
    let r = testkit::open_replica(&ns, &dir.path().join("r.libsql")).unwrap();
    assert_eq!(keys_of(&r, "src/rm2.test.ts"), vec![k3.key.clone()]);
    b.remove(vec![k3.clone()]).unwrap();
    assert!(r.remove(vec![k3.clone()]).unwrap().is_empty());
    assert!(
        keys_of(&r, "src/rm2.test.ts").is_empty(),
        "the replica still lists what it removed"
    );
}

/// A replica picks up other writers' changes at its next prefetch (`vci
/// run`'s before supersession, the plan's later rounds), as the remote mode
/// does; a key another writer removed then reads as gone.
#[test]
fn a_replica_picks_up_other_writers_at_the_next_prefetch() {
    let Some((w, ns)) = remote() else { return };
    let dir = tempfile::tempdir().unwrap();
    let (u1, u2) = ("src/p1.test.ts", "src/p2.test.ts");
    let k1 = w
        .put_for_test(u1, S1, &hex64(1), Some(&hint(1)), &envelope(None, "one"))
        .unwrap();
    let r = testkit::open_replica(&ns, &dir.path().join("r.libsql")).unwrap();
    r.prefetch(Prefetch::Units {
        test_ids: &[u1, u2],
        choose: None,
    })
    .unwrap();
    let listed = r.list_units(&[u1]).unwrap().remove(0);
    assert_eq!(listed.len(), 1);
    let k2 = w
        .put_for_test(u1, S1, &hex64(2), Some(&hint(2)), &envelope(None, "two"))
        .unwrap();
    let k3 = w
        .put_for_test(u2, S1, &hex64(3), Some(&hint(3)), &envelope(None, "three"))
        .unwrap();
    w.remove(vec![k1.clone()]).unwrap();
    let before = r.requests();
    r.prefetch(Prefetch::Units {
        test_ids: &[u1, u2],
        choose: None,
    })
    .unwrap();
    assert!(
        r.requests() - before <= 2,
        "a sync of changes took {} requests",
        r.requests() - before
    );
    let units = r.read_units(&[u1, u2]).unwrap();
    let seen: Vec<Vec<String>> = units
        .iter()
        .map(|u| u.iter().map(|e| e.key.clone()).collect())
        .collect();
    assert_eq!(seen, vec![vec![k2.key.clone()], vec![k3.key.clone()]]);
    assert!(
        read_state(&r, &listed[0]).contains("no longer"),
        "{}",
        read_state(&r, &listed[0])
    );
}

/// A replica whose write cannot be written through to its file (another
/// process holds the file) reads its own write from the server for the
/// rest of the process; the next handle's sync brings it to the file.
#[test]
fn a_replica_whose_write_through_fails_reads_its_own_write() {
    let Some((w, ns)) = remote() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("r.libsql");
    w.put_for_test(
        "src/a.test.ts",
        S1,
        &hex64(1),
        Some(&hint(1)),
        &envelope(None, "a"),
    )
    .unwrap();
    let server = testkit::server().unwrap();
    let mut sel = testkit::selection(
        LibsqlMode::Replica,
        Some(&server.url),
        server.token.as_deref(),
        Some(&ns),
        Some(&path),
    );
    sel.timeout = Sourced {
        value: Duration::from_secs(1),
        source: Source::File,
    };
    let r = open(&sel);
    assert_eq!(keys_of(&r, "src/a.test.ts").len(), 1);
    let lock = rusqlite::Connection::open(&path).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let k = r
        .put_for_test(
            "src/b.test.ts",
            S1,
            &hex64(2),
            Some(&hint(2)),
            &envelope(None, "b"),
        )
        .unwrap();
    lock.execute_batch("COMMIT").unwrap();
    drop(lock);
    assert_eq!(keys_of(&r, "src/b.test.ts"), vec![k.key.clone()]);
    assert_eq!(read_state(&r, &k), "read");
    assert_eq!(
        keys_of(&r, "src/a.test.ts").len(),
        1,
        "the rest is read too"
    );
    drop(r);
    let r2 = testkit::open_replica(&ns, &path).unwrap();
    assert_eq!(keys_of(&r2, "src/b.test.ts"), vec![k.key]);
}

/// A replica of a namespace that was dropped and made again (a restore, a
/// new database at the same URL) syncs everything: it ends as the server
/// is, without the old records.
#[test]
fn a_replica_of_a_namespace_made_again_syncs_everything() {
    let Some((s, ns)) = remote() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("r.libsql");
    for i in 0..12u8 {
        s.put_for_test(
            &format!("src/old{i}.test.ts"),
            S1,
            &hex64(i + 1),
            Some(&hint(1)),
            &envelope(None, "old"),
        )
        .unwrap();
    }
    assert_eq!(
        testkit::open_replica(&ns, &path).unwrap().count().unwrap(),
        12
    );
    let p = table_prefix(&ns);
    s.__execute_for_test(&[
        format!("DROP TABLE {p}attestations"),
        format!("DROP TABLE {p}manifests"),
        format!("DROP TABLE {p}memo"),
        format!("DROP TABLE {p}flags"),
        format!("DROP TABLE {p}log"),
        format!("DELETE FROM vci_schema WHERE ns = '{ns}'"),
    ])
    .unwrap();
    // Nothing on the server: nothing in the replica.
    assert_eq!(
        testkit::open_replica(&ns, &path).unwrap().count().unwrap(),
        0
    );
    // Made again, with fewer log entries than the replica had synced, then
    // with more.
    let w = testkit::open_remote(&ns).unwrap();
    let fresh = w
        .put_for_test(
            "src/new.test.ts",
            S1,
            &hex64(0x40),
            Some(&hint(2)),
            &envelope(None, "new"),
        )
        .unwrap();
    let r = testkit::open_replica(&ns, &path).unwrap();
    assert_eq!(
        r.read_all()
            .unwrap()
            .into_iter()
            .map(|e| e.key)
            .collect::<Vec<_>>(),
        vec![fresh.key.clone()]
    );
    drop(r);
    // Synced to entry N; the namespace is made again and passes N.
    let path2 = dir.path().join("r2.libsql");
    assert_eq!(
        testkit::open_replica(&ns, &path2).unwrap().count().unwrap(),
        1
    );
    let p = table_prefix(&ns);
    w.__execute_for_test(&[
        format!("DROP TABLE {p}attestations"),
        format!("DROP TABLE {p}manifests"),
        format!("DROP TABLE {p}memo"),
        format!("DROP TABLE {p}flags"),
        format!("DROP TABLE {p}log"),
        format!("DELETE FROM vci_schema WHERE ns = '{ns}'"),
    ])
    .unwrap();
    let w = testkit::open_remote(&ns).unwrap();
    let mut keys = Vec::new();
    for i in 0..3u8 {
        keys.push(
            w.put_for_test(
                &format!("src/again{i}.test.ts"),
                S1,
                &hex64(0x50 + i),
                Some(&hint(3)),
                &envelope(None, "again"),
            )
            .unwrap()
            .key,
        );
    }
    let got: Vec<String> = testkit::open_replica(&ns, &path2)
        .unwrap()
        .read_all()
        .unwrap()
        .into_iter()
        .map(|e| e.key)
        .collect();
    keys.sort();
    let mut got_sorted = got.clone();
    got_sorted.sort();
    assert_eq!(got_sorted, keys, "the replica does not match its server");
}

/// A replica's `orphan_manifests` is its server's: a root referenced by a
/// value this vci cannot read (left out of the file) is still referenced.
#[test]
fn a_replica_answers_orphans_as_its_server() {
    let Some((s, ns)) = remote() else { return };
    let dir = tempfile::tempdir().unwrap();
    let m = manifest(&["src/ref.rs"]);
    let root = m.root();
    s.put_manifest(&root, m.to_compact().as_bytes()).unwrap();
    let k = s
        .put_for_test(
            "src/a.test.ts",
            S1,
            &hex64(1),
            Some(&hint(1)),
            &envelope(Some(&root), "refs"),
        )
        .unwrap();
    let p = table_prefix(&ns);
    s.__execute_for_test(&[format!(
        "UPDATE {p}attestations SET encoding = 99 WHERE key = '{}'",
        k.key
    )])
    .unwrap();
    let r = testkit::open_replica(&ns, &dir.path().join("r.libsql")).unwrap();
    assert!(
        testkit::open_remote(&ns)
            .unwrap()
            .orphan_manifests(&[&root])
            .unwrap()
            .is_empty()
    );
    assert!(r.orphan_manifests(&[&root]).unwrap().is_empty());
}

/// A statement the server refuses (here a trigger's `RAISE`) loses the
/// unit it writes, as `Backend`, and nothing else: the batch's transaction
/// is split down to that unit, the other units are stored, nothing is
/// latched, and the handle's later reads and writes go on, remote and
/// replica.
#[test]
fn a_statement_the_server_refuses_latches_nothing() {
    let Some((s, ns)) = remote() else { return };
    let dir = tempfile::tempdir().unwrap();
    s.put_for_test(
        "src/a.test.ts",
        S1,
        &hex64(1),
        Some(&hint(1)),
        &envelope(None, "kept"),
    )
    .unwrap();
    let p = table_prefix(&ns);
    let bad = hex64(0xbb);
    s.__execute_for_test(&[format!(
        "CREATE TRIGGER {p}boom BEFORE INSERT ON {p}attestations WHEN NEW.storage_key = '{bad}' \
         BEGIN SELECT RAISE(ABORT, 'boom'); END"
    )])
    .unwrap();
    for (i, replica) in [false, true].into_iter().enumerate() {
        let h = if replica {
            testkit::open_replica(&ns, &dir.path().join("r.libsql")).unwrap()
        } else {
            testkit::open_remote(&ns).unwrap()
        };
        h.prefetch(Prefetch::Units {
            test_ids: &["src/a.test.ts"],
            choose: None,
        })
        .unwrap();
        let m = manifest(&[&format!("src/failing{i}.rs")]);
        let b = h.batch().unwrap();
        h.put_manifest(&m.root(), m.to_compact().as_bytes())
            .unwrap();
        h.put_for_test(
            "src/b.test.ts",
            S1,
            &hex64(2),
            Some(&hint(5)),
            &envelope(Some(&m.root()), "good"),
        )
        .unwrap();
        let refused = h
            .put_for_test(
                "src/a.test.ts",
                S1,
                &bad,
                Some(&hint(5)),
                &envelope(None, "bad"),
            )
            .unwrap();
        // The unit whose write the server refuses is lost alone (2.8.1
        // lost the whole batch): the other unit's attestation and manifest
        // are stored.
        let f = b
            .finish_partial()
            .unwrap_or_else(|e| panic!("replica {replica}: {e}"));
        assert_eq!(f.lost_count(), 1, "replica {replica}");
        match f.lost(&refused.key) {
            Some(e @ StoreError::Backend(_)) => assert!(e.to_string().contains("boom"), "{e}"),
            other => panic!("replica {replica}: expected Backend, got {other:?}"),
        }
        let srv = testkit::open_remote(&ns).unwrap();
        assert!(
            srv.manifest(&m.root()).unwrap().is_some(),
            "the stored unit's manifest"
        );
        assert_eq!(
            keys_of(&srv, "src/b.test.ts").len(),
            1,
            "the stored unit's attestation"
        );
        assert_eq!(keys_of(&srv, "src/a.test.ts").len(), 1, "the refused one");
        // The handle goes on.
        assert!(h.manifest(&m.root()).unwrap().is_some());
        h.put_for_test(
            "src/c.test.ts",
            S1,
            &hex64(3 + i as u8),
            Some(&hint(7)),
            &envelope(None, "after"),
        )
        .unwrap();
        assert!(matches!(h.status().unwrap(), StoreStatus::Ready { .. }));
    }
}

/// Every write batch takes the write lock before its first statement
/// (`BEGIN IMMEDIATE`). A namespace's first batch begins by creating
/// `vci_schema`, which exists once any namespace does, so it only reads: under
/// libsql's deferred `BEGIN` it held a read snapshot it must later promote to
/// the write lock, and when another writer committed while it waited for that
/// lock, the promotion failed (`SQLITE_BUSY_SNAPSHOT`) and vci sent the batch
/// again, a failure that can abort `sqld` 0.24 (docs/STORE-BACKENDS.md section
/// 21, item 17). Taking the lock first, the server retries with a fresh
/// snapshot: here, where another connection holds the write lock and commits
/// a write while the first write waits, that write is stored without being
/// sent again. And a batch that stopped part way holds nothing afterwards:
/// two such batches on one connection leave the write lock free for another
/// handle at once. On a `sqld` of the test's own.
#[test]
fn a_write_batch_takes_the_write_lock_before_it_reads() {
    let server = match testkit::start_sqld(&[]) {
        Ok(s) => s,
        Err(why) => {
            eprintln!("skipping: no sqld to hold the write lock on: {why}");
            return;
        }
    };
    let (url, port) = (server.url(), server.port());
    let handle = |ns: &str, timeout: u64| {
        let mut sel = testkit::selection(LibsqlMode::Remote, Some(&url), None, Some(ns), None);
        sel.timeout = Sourced {
            value: Duration::from_secs(timeout),
            source: Source::File,
        };
        open(&sel)
    };
    // Another namespace makes vci_schema exist.
    let first = handle(&testkit::namespace(), 30);
    first
        .put_for_test(
            "src/a.test.ts",
            S1,
            &hex64(1),
            Some(&hint(1)),
            &envelope(None, "first"),
        )
        .unwrap();
    first
        .__execute_for_test(&["CREATE TABLE lock_probe (x)".to_owned()])
        .unwrap();

    // Another connection holds the write lock while a new namespace's first
    // write waits for it, then commits a write of its own.
    let baton = testkit::pipeline(port, None, &["BEGIN IMMEDIATE"], false)
        .unwrap()
        .expect("the holder's stream stays open");
    let ns = testkit::namespace();
    let s = handle(&ns, 30);
    assert!(matches!(s.status().unwrap(), StoreStatus::Absent { .. }));
    let waiting = std::thread::spawn(move || {
        let r = s.put_for_test(
            "src/b.test.ts",
            S1,
            &hex64(2),
            Some(&hint(2)),
            &envelope(None, "second"),
        );
        (r, s.retries())
    });
    std::thread::sleep(Duration::from_secs(1));
    testkit::pipeline(
        port,
        Some(&baton),
        &["INSERT INTO lock_probe VALUES (1)", "COMMIT"],
        true,
    )
    .unwrap();
    let (stored, retries) = waiting.join().unwrap();
    stored.unwrap();
    assert_eq!(
        retries, 0,
        "the first write was sent again: it read before it took the write lock"
    );
    assert_eq!(keys_of(&handle(&ns, 30), "src/b.test.ts").len(), 1);

    // Two batches on one connection, each stopping part way (a table that
    // does not exist): neither keeps the write lock.
    let failing = handle(&ns, 30);
    for (i, missing) in ["absent_a", "absent_b"].into_iter().enumerate() {
        let r = failing.__execute_for_test(&[
            format!("INSERT INTO lock_probe VALUES ({})", 10 + i),
            format!("INSERT INTO {missing} VALUES (1)"),
        ]);
        assert!(r.is_err(), "{missing}: {r:?}");
    }
    handle(&ns, 1)
        .__execute_for_test(&["INSERT INTO lock_probe VALUES (7)".to_owned()])
        .unwrap();
    let rows = first
        .__query_for_test("SELECT group_concat(x) FROM lock_probe")
        .unwrap();
    assert_eq!(
        rows,
        vec![vec!["1,7".to_owned()]],
        "the failed batches wrote nothing"
    );
}

/// A record the server would refuse as too big (`sqld` keeps rows under
/// 5,000,000 bytes) is refused alone, as `Unsupported` (which keeps `vci
/// run`'s exit code), before anything is sent: the rest of its batch is
/// stored and the handle goes on. A value just under the limit is stored.
#[test]
fn a_record_too_large_for_the_server_is_refused_alone() {
    let Some((s, _)) = remote() else { return };
    let pad = |n: usize| {
        format!(
            "{{\"v\":2,\"entries\":[],\"pad\":\"{}\"}}",
            "y".repeat(n - 30)
        )
    };
    let big = pad(5_000_000);
    let root_big = hex64(0x61);
    match s.put_manifest(&root_big, big.as_bytes()) {
        Err(e @ StoreError::Unsupported { .. }) => {
            assert!(e.to_string().contains("5,000,000"), "{e}")
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
    let near = pad(4_990_000);
    let root_near = hex64(0x62);
    assert!(s.put_manifest(&root_near, near.as_bytes()).unwrap());
    assert_eq!(
        s.manifest(&root_near).unwrap().unwrap().bytes.len(),
        near.len()
    );
    let b = s.batch().unwrap();
    let small = manifest(&["src/small.rs"]);
    s.put_manifest(&small.root(), small.to_compact().as_bytes())
        .unwrap();
    assert!(matches!(
        s.put_manifest(&hex64(0x63), big.as_bytes()),
        Err(StoreError::Unsupported { .. })
    ));
    assert!(matches!(
        s.put_for_test(
            "src/big.test.ts",
            S1,
            &hex64(1),
            Some(&hint(1)),
            &envelope(None, &"e".repeat(5_000_000))
        ),
        Err(StoreError::Unsupported { .. })
    ));
    let ok = s
        .put_for_test(
            "src/ok.test.ts",
            S1,
            &hex64(2),
            Some(&hint(1)),
            &envelope(Some(&small.root()), "ok"),
        )
        .unwrap();
    b.finish().unwrap();
    assert_eq!(keys_of(&s, "src/ok.test.ts"), vec![ok.key]);
    assert!(keys_of(&s, "src/big.test.ts").is_empty());
    assert!(s.manifest(&small.root()).unwrap().is_some());
    assert!(matches!(s.status().unwrap(), StoreStatus::Ready { .. }));
}

/// A replica file that is not a database, or one in a directory vci may
/// not write, refuses writes (`Unavailable`) instead of storing on the
/// server behind it.
#[test]
fn a_replica_that_cannot_be_used_refuses_writes() {
    use std::os::unix::fs::PermissionsExt as _;
    let Some((_, ns)) = remote() else { return };
    let dir = tempfile::tempdir().unwrap();
    let garbage = dir.path().join("garbage.libsql");
    std::fs::write(&garbage, "not a database\n".repeat(100)).unwrap();
    std::fs::write(
        dir.path().join("garbage.libsql.sync"),
        "{\"v\":1,\"source\":\"x\",\"seq\":0}",
    )
    .unwrap();
    let ro = dir.path().join("ro");
    std::fs::create_dir(&ro).unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
    for path in [garbage.clone(), ro.join("r.libsql")] {
        let r = testkit::open_replica(&ns, &path).unwrap();
        let put = r.put_for_test("src/w.test.ts", S1, &hex64(1), Some(&hint(1)), b"{}");
        assert!(
            matches!(put, Err(StoreError::Unavailable { .. })),
            "{}: {put:?}",
            path.display()
        );
        assert!(
            matches!(r.batch(), Err(StoreError::Unavailable { .. })),
            "{}",
            path.display()
        );
    }
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        testkit::open_remote(&ns)
            .unwrap()
            .list_units(&["src/w.test.ts"])
            .unwrap()[0]
            .is_empty()
    );
}

// ---- a server that takes no more writes ------------------------------------------------------

/// A server that takes no more writes refuses them as `Denied`, which
/// keeps `vci run`'s exit code the tests' (`docs/STORE-BACKENDS.md`
/// section 10), latches nothing, and lets reads go on: `sqld`'s write
/// block (what a database over its quota gets: `Operation was blocked:
/// <reason>`), and its size limit (`database or disk is full`). In an
/// empty namespace the first write is refused the same way, not as a
/// store that is "not set up". Remote and replica, on a `sqld` of the
/// test's own (the block holds for every namespace of the server).
#[test]
fn a_server_that_blocks_writes_refuses_them_and_reads_go_on() {
    let (server, admin) = match testkit::start_sqld_with_admin() {
        Ok(s) => s,
        Err(why) => {
            eprintln!("skipping: no sqld to block writes on: {why}");
            return;
        }
    };
    let url = server.url();
    let dir = tempfile::tempdir().unwrap();
    let ns = testkit::namespace();
    let empty = testkit::namespace();
    let handle = |mode: LibsqlMode, ns: &str, file: &str| {
        open(&testkit::selection(
            mode,
            Some(&url),
            None,
            Some(ns),
            (mode == LibsqlMode::Replica)
                .then(|| dir.path().join(file))
                .as_deref(),
        ))
    };
    let w = handle(LibsqlMode::Remote, &ns, "");
    let kept = w
        .put_for_test(
            "src/kept.test.ts",
            S1,
            &hex64(1),
            Some(&hint(1)),
            &envelope(None, "kept"),
        )
        .unwrap();
    let blocks = [
        (
            serde_json::json!({"block_writes": true, "block_reason": "storage quota exceeded"}),
            "blocked",
        ),
        (
            serde_json::json!({"block_writes": false, "block_reason": null, "max_db_size": "40KB"}),
            "full",
        ),
    ];
    for (i, (block, says)) in blocks.iter().enumerate() {
        testkit::set_config(admin, block).unwrap();
        for (j, mode) in [LibsqlMode::Remote, LibsqlMode::Replica]
            .into_iter()
            .enumerate()
        {
            let tag = format!("{says} {}", mode.name());
            let s = handle(mode, &ns, &format!("r{i}.libsql"));
            // Hex digits of hashes: as large compressed (half) as not.
            let noise: String = (0..3_200u32)
                .map(|k| vci_core::blake3_hex(&k.to_le_bytes()))
                .collect();
            let big = envelope(None, &noise);
            let n = u8::try_from(2 + i * 4 + j * 2).unwrap();
            let put = s.put_for_test("src/new.test.ts", S1, &hex64(n), Some(&hint(2)), &big);
            match &put {
                Err(e @ StoreError::Denied { operation, .. }) => {
                    assert_eq!(*operation, "write", "{tag}: {e}");
                    assert!(e.to_string().contains(says), "{tag}: {e}");
                }
                other => panic!("{tag}: expected Denied, got {other:?}"),
            }
            // A batch is refused when it finishes, the same way.
            let b = s.batch().unwrap();
            let m = manifest(&[&format!("src/m{n}.rs")]);
            s.put_manifest(&m.root(), m.to_compact().as_bytes())
                .unwrap();
            s.put_for_test("src/new.test.ts", S1, &hex64(n + 1), Some(&hint(3)), &big)
                .unwrap();
            match b.finish() {
                Err(StoreError::Denied { .. }) => {}
                other => panic!("{tag}: the batch: expected Denied, got {other:?}"),
            }
            // Nothing is latched: reads go on.
            assert_eq!(
                keys_of(&s, "src/kept.test.ts"),
                vec![kept.key.clone()],
                "{tag}"
            );
            assert!(keys_of(&s, "src/new.test.ts").is_empty(), "{tag}");
            assert!(
                matches!(s.status(), Ok(StoreStatus::Ready { .. })),
                "{tag}: {:?}",
                s.status()
            );
            // A namespace with no tables yet: its first write creates them,
            // and that is refused the same way.
            let e = handle(mode, &empty, &format!("e{i}{j}.libsql"));
            match e.put_for_test("src/e.test.ts", S1, &hex64(n), None, &big) {
                Err(StoreError::Denied { .. }) => {}
                other => panic!("{tag}: an empty namespace: expected Denied, got {other:?}"),
            }
        }
    }
    testkit::set_config(
        admin,
        &serde_json::json!({"block_writes": false, "max_db_size": "1000PB"}),
    )
    .unwrap();
    w.put_for_test(
        "src/after.test.ts",
        S1,
        &hex64(99),
        Some(&hint(9)),
        &envelope(None, "after"),
    )
    .unwrap();
    drop(server);
}

// ---- a replica's reads before a prefetch ------------------------------------------------------

/// Before its caller's first prefetch, a replica answers `read_values` as
/// the server holds the keys now, as a remote handle does: a key another
/// writer removed since it was listed reads as gone (section 4). After a
/// prefetch, reads come from the file as that prefetch synced it, with no
/// request, until the next prefetch (the snapshot section 4 allows).
#[test]
fn a_replica_reads_a_key_removed_since_it_was_listed_as_gone() {
    let Some((w, ns)) = remote() else { return };
    let dir = tempfile::tempdir().unwrap();
    let u = "src/gone.test.ts";
    let k = w
        .put_for_test(u, S1, &hex64(1), Some(&hint(1)), &envelope(None, "one"))
        .unwrap();
    let r = testkit::open_replica(&ns, &dir.path().join("r.libsql")).unwrap();
    let listed = r.list_units(&[u]).unwrap().remove(0);
    assert_eq!(listed.len(), 1);
    w.remove(vec![k.clone()]).unwrap();
    let state = read_state(&r, &listed[0]);
    assert!(state.contains("no longer"), "{state}");

    // After a prefetch: the file as the prefetch synced it, no request.
    let k2 = w
        .put_for_test(u, S1, &hex64(2), Some(&hint(2)), &envelope(None, "two"))
        .unwrap();
    let r2 = testkit::open_replica(&ns, &dir.path().join("r2.libsql")).unwrap();
    r2.prefetch(Prefetch::Units {
        test_ids: &[u],
        choose: None,
    })
    .unwrap();
    let listed = r2.list_units(&[u]).unwrap().remove(0);
    assert_eq!(listed[0].key, k2.key);
    let before = r2.requests();
    assert_eq!(read_state(&r2, &listed[0]), "read");
    assert_eq!(r2.requests(), before, "reads after a prefetch send nothing");
}

// ---- a replica the store commands cannot keep ---------------------------------------------------

/// `vci store info`, fetch, push and prune (the commands about the store
/// itself) fail on a replica that cannot be kept, as they do when its
/// server cannot be reached: one in a directory vci cannot write, whether
/// or not the namespace holds anything yet. The plan and the run read it
/// as it is (and the run refuses each write).
#[test]
fn the_store_commands_fail_on_a_replica_that_cannot_be_kept() {
    use std::os::unix::fs::PermissionsExt as _;
    let Some((w, filled)) = remote() else { return };
    w.put_for_test(
        "src/f.test.ts",
        S1,
        &hex64(1),
        Some(&hint(1)),
        &envelope(None, "f"),
    )
    .unwrap();
    let empty = testkit::namespace();
    let dir = tempfile::tempdir().unwrap();
    let ro = dir.path().join("ro");
    std::fs::create_dir(&ro).unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
    let server = testkit::server().unwrap();
    let replica = |ns: &str, command: &str| {
        let sel = testkit::selection(
            LibsqlMode::Replica,
            Some(&server.url),
            server.token.as_deref(),
            Some(ns),
            Some(&ro.join("r.libsql")),
        );
        let cx = vci_store::OpenContext {
            command: command.to_owned(),
            ..testkit::cx()
        };
        LibsqlStore::open(&sel, &cx).unwrap()
    };
    for ns in [&empty, &filled] {
        for command in ["store", "fetch", "push", "prune"] {
            match replica(ns, command).status() {
                Err(e @ StoreError::Unavailable { .. }) => {
                    assert!(e.to_string().contains("cannot"), "{command} {ns}: {e}")
                }
                other => panic!("{command} {ns}: expected Unavailable, got {other:?}"),
            }
        }
        let plan = replica(ns, "plan");
        assert!(plan.status().is_ok(), "plan {ns}: {:?}", plan.status());
        assert!(matches!(
            plan.put_for_test("src/w.test.ts", S1, &hex64(2), None, b"{}"),
            Err(StoreError::Unavailable { .. })
        ));
    }
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
}

// ---- 2.8.2: bounded retries, hints, compression, leaner storage ----------------------------

/// A handle through a [`Proxy`] whose requests are given `secs` each.
fn proxied(proxy: &Proxy, token: Option<&str>, ns: &str, secs: u64) -> LibsqlStore {
    let mut sel = testkit::selection(
        LibsqlMode::Remote,
        Some(&proxy.url()),
        token,
        Some(ns),
        None,
    );
    sel.timeout = Sourced {
        value: Duration::from_secs(secs),
        source: Source::File,
    };
    open(&sel)
}

/// A read whose deadline runs out (a large read answered slowly while
/// other jobs write) is sent once more on a new connection, with a
/// deadline of its own: it succeeds, and nothing is latched (2.8.1
/// latched the breaker, and the plan ran every unit). The same read out of
/// time again latches it: the server cannot be used, and every later call
/// fails at once.
#[test]
fn a_read_whose_deadline_runs_out_is_sent_again_once() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let ns = testkit::namespace();
    let s = proxied(&proxy, token.as_deref(), &ns, 2);
    let put = |n: u8, unit: &str| {
        s.put_for_test(unit, S1, &hex64(n), Some(&hint(1)), &envelope(None, unit))
    };
    put(1, "src/a.test.ts").unwrap();
    proxy.stall_cursors(1);
    let before = s.retries();
    let t = Instant::now();
    let all = s.list_all().unwrap_or_else(|e| panic!("sent again: {e}"));
    assert_eq!(all.len(), 1);
    assert!(t.elapsed() >= Duration::from_secs(2), "{:?}", t.elapsed());
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    assert_eq!(proxy.stalled(), 1);
    assert!(s.retries() > before, "the read was sent again");
    put(2, "src/b.test.ts").unwrap_or_else(|e| panic!("nothing latched: {e}"));
    assert_eq!(s.list_all().unwrap().len(), 2);

    proxy.stall_cursors(2);
    let t = Instant::now();
    let e = s.list_all().unwrap_err();
    assert!(matches!(e, StoreError::Timeout { .. }), "{e:?}");
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    assert_eq!(proxy.stalled(), 3);
    proxy.stall_cursors(0);
    let t = Instant::now();
    let e = s.list_all().unwrap_err();
    assert!(e.to_string().contains("not retried"), "{e}");
    assert!(put(3, "src/c.test.ts").is_err());
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
}

/// A hint's write (a memo, a flag) waits at most its own short deadline
/// behind other writers, is never sent again, and latches nothing: the
/// plan goes on reading and writing (2.8.1 waited the request timeout
/// inside the native-library check every verdict thread waits on, then
/// latched the breaker, and the second round and the memo failed).
#[test]
fn a_hint_write_is_dropped_after_its_deadline() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let ns = testkit::namespace();
    let s = proxied(&proxy, token.as_deref(), &ns, 2);
    let e = s
        .put_for_test(
            "src/a.test.ts",
            S1,
            &hex64(1),
            Some(&hint(1)),
            &envelope(None, "a"),
        )
        .unwrap();
    proxy.stall_writes(true);
    let t = Instant::now();
    let before = s.retries();
    s.remember_passing("0123456789abcdef", &[(e.test_key.clone(), e.key.clone())]);
    s.set_flag("plan:natives:x");
    assert!(t.elapsed() < Duration::from_secs(6), "{:?}", t.elapsed());
    assert_eq!(proxy.stalled(), 2, "each sent once");
    assert_eq!(s.retries(), before, "never sent again");
    proxy.stall_writes(false);
    s.status()
        .unwrap_or_else(|e| panic!("nothing latched: {e}"));
    s.put_for_test(
        "src/b.test.ts",
        S1,
        &hex64(2),
        Some(&hint(1)),
        &envelope(None, "b"),
    )
    .unwrap_or_else(|e| panic!("nothing latched: {e}"));
    assert_eq!(s.list_all().unwrap().len(), 2);
}

/// A flag already set sends nothing, and a memo writes only the entries
/// the server does not hold: a second plan of the same tree writes none
/// (2.8.1 rewrote every passing entry, about 1,900 rows per vex plan).
#[test]
fn hints_send_only_what_is_new() {
    let Some((s, ns)) = remote() else { return };
    let mut entries = Vec::new();
    for i in 0..3u8 {
        let e = s
            .put_for_test(
                &unit(usize::from(i)),
                S1,
                &hex64(i),
                Some(&hint(1)),
                &envelope(None, "x"),
            )
            .unwrap();
        entries.push((e.test_key.clone(), e.key.clone()));
    }
    let tree = "0123456789abcdef";
    s.set_flag("plan:natives:x");
    s.remember_passing(tree, &entries[..2]);
    let fresh = || testkit::open_remote(&ns).unwrap();
    let p = fresh();
    assert!(p.flag("plan:natives:x"));
    let n = p.requests();
    p.set_flag("plan:natives:x");
    assert_eq!(p.requests(), n, "a flag set already sends nothing");
    assert_eq!(p.passing_on(tree).len(), 2);
    let n = p.requests();
    p.remember_passing(tree, &entries[..2]);
    assert_eq!(p.requests(), n, "entries held already send nothing");
    p.remember_passing(tree, &entries);
    assert!(p.requests() > n, "a new entry is written");
    let mut changed = entries.clone();
    changed[0].1 = changed[1].1.clone();
    p.remember_passing(tree, &changed);
    let q = fresh();
    let memo = q.passing_on(tree);
    assert_eq!(memo.len(), 3);
    assert_eq!(
        memo[&entries[0].0], entries[1].1,
        "a changed entry is written"
    );
}

/// With `VCI_STORE_COMPRESS=zstd` values go to the server compressed
/// (encoding 1) and come back as they were, to any 2.8.2 handle, whichever
/// way it writes; the same bytes put again change nothing. A value of an
/// encoding this vci does not know, or one that decompresses past the
/// largest record, reads as unreadable: its unit runs.
#[test]
fn values_written_compressed_read_back_as_they_were() {
    let Some((s, ns)) = remote() else { return };
    s.__compress_for_test(true);
    let p = table_prefix(&ns);
    let m = manifest(
        &(0..60)
            .map(|i| format!("src/f{i}.rs"))
            .collect::<Vec<_>>()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let (root, bytes) = (m.root(), m.to_compact());
    assert!(s.put_manifest(&root, bytes.as_bytes()).unwrap());
    assert!(
        !s.put_manifest(&root, bytes.as_bytes()).unwrap(),
        "the same bytes, compressed the same"
    );
    let env = envelope(Some(&root), &"padding ".repeat(2_000));
    let stored = s
        .put_for_test("src/a.test.ts", S1, &hex64(1), Some(&hint(1)), &env)
        .unwrap();
    let rows = s
        .__query_for_test(&format!(
            "SELECT encoding, length(value) FROM {p}attestations \
             UNION ALL SELECT encoding, length(value) FROM {p}manifests"
        ))
        .unwrap();
    assert_eq!(rows.len(), 2);
    for (row, raw) in rows.iter().zip([env.len(), bytes.len()]) {
        assert_eq!(row[0], "1", "{rows:?}");
        let len: usize = row[1].parse().unwrap();
        assert!(len * 2 < raw, "{len} of {raw}");
    }
    // Read by a handle that writes as they are.
    let r = testkit::open_remote(&ns).unwrap();
    r.__compress_for_test(false);
    r.prefetch(Prefetch::Units {
        test_ids: &["src/a.test.ts"],
        choose: None,
    })
    .unwrap();
    let mut l = r.list_units(&["src/a.test.ts"]).unwrap().remove(0);
    r.read_values(&mut l.iter_mut().collect::<Vec<_>>())
        .unwrap();
    assert_eq!(l[0].key, stored.key);
    assert!(matches!(l[0].state(), ValueState::Read(b) if b == env.as_slice()));
    let got = r.manifest(&root).unwrap().unwrap();
    assert_eq!(got.bytes, bytes.as_bytes());
    // It replaces the slot's compressed row with its own, as it is.
    let env2 = envelope(Some(&root), "second");
    r.put_for_test("src/a.test.ts", S1, &hex64(1), Some(&hint(2)), &env2)
        .unwrap();
    let rows = r
        .__query_for_test(&format!("SELECT encoding FROM {p}attestations"))
        .unwrap();
    assert_eq!(rows, vec![vec!["0".to_owned()]]);
    let q = testkit::open_remote(&ns).unwrap();
    let mut l = q.read_units(&["src/a.test.ts"]).unwrap().remove(0);
    assert!(matches!(l.remove(0).state(), ValueState::Read(b) if b == env2.as_slice()));

    // An unknown encoding, and a frame past the largest record.
    let bomb = zstd::bulk::compress(&vec![b'{'; 6_000_000], 3).unwrap();
    let hex: String = bomb.iter().map(|b| format!("{b:02X}")).collect();
    let tk = vci_core::test_key("src/a.test.ts");
    s.__execute_for_test(&[
        format!("UPDATE {p}attestations SET encoding = 2 WHERE test_key = '{tk}'"),
        format!("UPDATE {p}manifests SET encoding = 1, value = X'{hex}'"),
    ])
    .unwrap();
    let q = testkit::open_remote(&ns).unwrap();
    let e = q
        .read_units(&["src/a.test.ts"])
        .unwrap()
        .remove(0)
        .remove(0);
    match e.state() {
        ValueState::Unreadable(why) => assert!(why.contains("newer vci"), "{why}"),
        other => panic!("{other:?}"),
    }
    let m = q.manifest(&root).unwrap().unwrap();
    assert!(!m.is_read(), "{m:?}");
}

/// A write that supersedes attestations removes the manifests only they
/// referenced, in the same transaction (2.8.1 left them for `vci prune`:
/// 90% of vex's manifests were such orphans). A manifest another
/// attestation references, or that is another's base, or that was put
/// within the grace period, stays; the change log names what went.
#[test]
fn superseding_removes_the_manifests_left_without_a_reference() {
    let Some(server) = testkit::server().ok().filter(|_| testkit::available()) else {
        return;
    };
    for grace in [false, true] {
        let ns = testkit::namespace();
        let p = table_prefix(&ns);
        // No grace: a long-running handle (as `vci prune`'s).
        let s = LibsqlStore::open(
            &testkit::selection(
                LibsqlMode::Remote,
                Some(&server.url),
                server.token.as_deref(),
                Some(&ns),
                None,
            ),
            &testkit::cx_in(Path::new("/nonexistent/.git"), !grace),
        )
        .unwrap();
        let ms: Vec<vci_core::InputManifest> = (1..=5)
            .map(|i| manifest(&[&format!("src/m{i}.rs")]))
            .collect();
        let root = |i: usize| ms[i - 1].root();
        for m in &ms {
            s.put_manifest(&m.root(), m.to_compact().as_bytes())
                .unwrap();
        }
        let att = |slot: u8, issued: i64, m: usize| {
            s.put_for_test(
                &format!("src/s{slot}.test.ts"),
                S1,
                &hex64(slot),
                Some(&hint(issued)),
                &envelope(Some(&root(m)), &format!("{slot}-{issued}")),
            )
            .unwrap()
        };
        att(1, 1, 1);
        let a3 = att(3, 1, 3);
        let a4 = att(4, 1, 3);
        let a5 = att(5, 1, 5);
        // A manifest whose base is m5.
        s.__execute_for_test(&[format!(
            "INSERT INTO {p}manifests (root, base, put_at, encoding, value) \
             VALUES ('{}', '{}', 1, 0, CAST('{{}}' AS BLOB))",
            hex64(0xee),
            root(5)
        )])
        .unwrap();
        let b = s.batch().unwrap();
        // Slot 1 put again on m2: m1 loses its only reference.
        att(1, 2, 2);
        s.remove(vec![a3, a5]).unwrap();
        b.finish().unwrap();
        let roots = || -> Vec<String> {
            let mut r: Vec<String> = s
                .__query_for_test(&format!("SELECT root FROM {p}manifests"))
                .unwrap()
                .into_iter()
                .map(|r| r[0].clone())
                .collect();
            r.sort();
            r
        };
        let has = |i: usize| roots().contains(&root(i));
        assert_eq!(!has(1), !grace, "grace {grace}: m1 {:?}", roots());
        assert!(has(2) && has(3) && has(4) && has(5), "{:?}", roots());
        s.remove(vec![a4]).unwrap();
        assert_eq!(!has(3), !grace, "grace {grace}: m3");
        if !grace {
            // Each root: once put, once removed.
            let logged = s
                .__query_for_test(&format!(
                    "SELECT count(*) FROM {p}log WHERE root IN ('{}', '{}') \
                     UNION ALL SELECT count(*) FROM {p}log WHERE root = '{}'",
                    root(1),
                    root(3),
                    root(2)
                ))
                .unwrap();
            assert_eq!(logged[0][0], "4", "the change log names them");
            assert_eq!(logged[1][0], "1", "put only");
        }
    }
}

/// Values are read 100 to a request: a request that fails costs only its
/// own keys. A prefetch says how many it could not read (a warning) and
/// leaves them to be read when asked for; a read that fails
/// for some keys marks only those as unreadable (their units run), never
/// failing the whole call (2.8.1 failed it, and the plan ran every unit).
#[test]
fn a_failed_request_of_values_costs_only_its_own_keys() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let ns = testkit::namespace();
    let w = testkit::open_remote(&ns).unwrap();
    let n = 600;
    let ids: Vec<String> = (0..n).map(unit).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    {
        let b = w.batch().unwrap();
        for (i, id) in ids.iter().enumerate() {
            w.put_for_test(
                id,
                S1,
                &hex64(1),
                Some(&hint(1)),
                &envelope(None, &i.to_string()),
            )
            .unwrap();
        }
        b.finish().unwrap();
    }
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let readable = |l: &[Vec<StoredEnvelope>]| {
        l.iter()
            .flatten()
            .filter(|e| matches!(e.state(), ValueState::Read(_)))
            .count()
    };
    // A prefetch: one request's values not read, then read when asked.
    let r = proxied(&proxy, token.as_deref(), &ns, 30);
    r.status().unwrap();
    // The listing goes through, then one request of values is cut off.
    proxy.cut_next(1, 1);
    let h = r
        .prefetch(Prefetch::Units {
            test_ids: &ids,
            choose: None,
        })
        .unwrap();
    assert_eq!(proxy.cut(), 1);
    assert!(h.error.is_none(), "read again when asked for: {h:?}");
    assert!(
        [250, 100].contains(&h.unresolved),
        "one request's keys: {h:?}"
    );
    let mut listed = r.list_units(&ids).unwrap();
    let mut refs: Vec<&mut StoredEnvelope> = listed.iter_mut().flatten().collect();
    r.read_values(&mut refs).unwrap();
    assert_eq!(readable(&listed), n, "the rest read when asked");

    // A read of values: one request cut off, its keys unreadable alone.
    let r = proxied(&proxy, token.as_deref(), &ns, 30);
    let mut listed = r.list_units(&ids).unwrap();
    proxy.cut_next(0, 1);
    let mut refs: Vec<&mut StoredEnvelope> = listed.iter_mut().flatten().collect();
    r.read_values(&mut refs).unwrap();
    let failed: Vec<&StoredEnvelope> = listed
        .iter()
        .flatten()
        .filter(|e| !matches!(e.state(), ValueState::Read(_)))
        .collect();
    assert!([250, 100].contains(&failed.len()), "{}", failed.len());
    assert_eq!(proxy.cut(), 2);
    for e in failed {
        match e.state() {
            ValueState::Unreadable(why) => {
                assert!(why.contains("could not be read from the store"), "{why}");
            }
            other => panic!("{other:?}"),
        }
    }
    r.status()
        .unwrap_or_else(|e| panic!("nothing latched: {e}"));
}

/// A request of values sent beside others whose deadline runs out (they
/// share the connection's bandwidth) fails alone and latches nothing: the
/// read sends its keys again itself, one request at a time and half as
/// many to a request, and every value is read.
#[test]
fn a_request_of_values_out_of_time_beside_others_is_read_again_alone() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let ns = testkit::namespace();
    let w = testkit::open_remote(&ns).unwrap();
    let n = 600;
    let ids: Vec<String> = (0..n).map(unit).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    {
        let b = w.batch().unwrap();
        for (i, id) in ids.iter().enumerate() {
            w.put_for_test(
                id,
                S1,
                &hex64(1),
                Some(&hint(1)),
                &envelope(None, &i.to_string()),
            )
            .unwrap();
        }
        b.finish().unwrap();
    }
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let r = proxied(&proxy, token.as_deref(), &ns, 2);
    r.status().unwrap();
    // The listing and the first request of values (sent alone) go
    // through, then one of those sent at once is held.
    proxy.stall_after(2, 1);
    let t = Instant::now();
    let h = r
        .prefetch(Prefetch::Units {
            test_ids: &ids,
            choose: None,
        })
        .unwrap();
    assert!(t.elapsed() >= Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(proxy.stalled(), 1);
    assert_eq!(h.unresolved, 0, "{h:?}");
    let n0 = r.requests();
    let mut listed = r.list_units(&ids).unwrap();
    let mut refs: Vec<&mut StoredEnvelope> = listed.iter_mut().flatten().collect();
    r.read_values(&mut refs).unwrap();
    assert_eq!(r.requests(), n0, "every value came from the prefetch");
    assert!(
        listed
            .iter()
            .flatten()
            .all(|e| matches!(e.state(), ValueState::Read(_)))
    );
    r.status()
        .unwrap_or_else(|e| panic!("nothing latched: {e}"));
}

/// On a link whose bandwidth is the limit, requests of values sent at
/// once share it and each takes as much longer: the first request goes
/// alone, and how long it took sets how many go at once, so that none runs
/// out of time beside others (2.8.2 as first written sent four at once,
/// all four ran out of time, and their keys were read again in halves);
/// and the whole read is given two request timeouts, the keys not read by
/// then failed (their units run), nothing latched.
#[test]
fn a_read_of_values_on_a_slow_link_is_bounded_and_not_sent_at_once() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let ns = testkit::namespace();
    let w = testkit::open_remote(&ns).unwrap();
    // As they are (`VCI_STORE_COMPRESS=zstd` would make them small).
    w.__compress_for_test(false);
    // About 7.8 MB of values as they travel.
    let n = 1_250;
    let ids: Vec<String> = (0..n).map(unit).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let pad = "p".repeat(3_000);
    {
        let b = w.batch().unwrap();
        for (i, id) in ids.iter().enumerate() {
            w.put_for_test(
                id,
                S1,
                &hex64(1),
                Some(&hint(1)),
                &envelope(None, &format!("{i}{pad}")),
            )
            .unwrap();
        }
        b.finish().unwrap();
    }
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let prefetch = |rate: usize| {
        let r = proxied(&proxy, token.as_deref(), &ns, 3);
        r.status().unwrap();
        proxy.limit_rate(rate);
        let (t, b) = (Instant::now(), proxy.passed());
        let h = r
            .prefetch(Prefetch::Units {
                test_ids: &ids,
                choose: None,
            })
            .unwrap();
        let (took, bytes) = (t.elapsed(), proxy.passed() - b);
        proxy.limit_rate(0);
        r.status()
            .unwrap_or_else(|e| panic!("nothing latched: {e}"));
        (h, took, bytes)
    };
    let (h, _, all) = prefetch(0);
    assert_eq!(h.unresolved, 0, "{h:?}");
    // About 1 s a request alone: one at a time, about 5 s, every value
    // read once (four at once took 4 s each and ran out of time after 3 s,
    // and their keys were read again).
    let (h, took, bytes) = prefetch(1_700_000);
    assert_eq!(h.unresolved, 0, "{h:?} in {took:?}");
    assert!(took < Duration::from_millis(6_500), "{took:?}");
    assert!(bytes < all + all / 10, "read twice: {bytes} of {all}");
    assert_eq!(proxy.stalled(), 0);
    // About 2 s a request alone: the read stops after two request
    // timeouts (6 s), with the values read by then (it took about 13 s).
    let (h, took, _) = prefetch(1_000_000);
    assert!(h.unresolved > 0 && h.unresolved < n, "{h:?} in {took:?}");
    assert!(took < Duration::from_secs(7), "{took:?}");
}

/// A request of values that ran out of time is read again in halves, and a
/// half that is answered counts though the other is not (2.8.2 as first
/// reviewed dropped the rows of the whole request, and the plan read that
/// half again); and once a read of values ran out of time, the handle's
/// later reads of values end when it did: the keys that failed are not
/// asked for again (2.8.2 as first reviewed gave the plan's read of its
/// candidates, and each round, two more request timeouts each on the same
/// slow link). Nothing is latched.
#[test]
fn a_read_of_values_out_of_time_keeps_its_halves_and_reads_no_more() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let ns = testkit::namespace();
    let w = testkit::open_remote(&ns).unwrap();
    let n = 200;
    let ids: Vec<String> = (0..n).map(unit).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    {
        let b = w.batch().unwrap();
        for (i, id) in ids.iter().enumerate() {
            w.put_for_test(
                id,
                S1,
                &hex64(1),
                Some(&hint(1)),
                &envelope(None, &i.to_string()),
            )
            .unwrap();
        }
        b.finish().unwrap();
    }
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let r = proxied(&proxy, token.as_deref(), &ns, 2);
    r.status().unwrap();
    // The listing goes through; both requests of values (sent at once)
    // are held; then the first half of the first is answered, and its
    // second half held until the read's time runs out.
    proxy.schedule(&[false, true, true, false, true]);
    let t = Instant::now();
    let h = r
        .prefetch(Prefetch::Units {
            test_ids: &ids,
            choose: None,
        })
        .unwrap();
    let took = t.elapsed();
    assert_eq!(proxy.stalled(), 3, "in {took:?}");
    assert_eq!(h.unresolved, 150, "{h:?} in {took:?}");
    assert!(took < Duration::from_secs(6), "{took:?}");
    let c0 = proxy.cursors();
    let t = Instant::now();
    let mut listed = r.list_units(&ids).unwrap();
    let mut refs: Vec<&mut StoredEnvelope> = listed.iter_mut().flatten().collect();
    r.read_values(&mut refs).unwrap();
    assert_eq!(
        proxy.cursors(),
        c0,
        "the keys that failed were asked for again"
    );
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    let read = listed
        .iter()
        .flatten()
        .filter(|e| matches!(e.state(), ValueState::Read(_)))
        .count();
    assert_eq!(read, 50);
    for e in listed.iter().flatten() {
        match e.state() {
            ValueState::Read(_) => {}
            ValueState::Unreadable(why) => {
                assert!(why.contains("could not be read from the store"), "{why}");
            }
            other => panic!("{other:?}"),
        }
    }
    r.status()
        .unwrap_or_else(|e| panic!("nothing latched: {e}"));
}

/// A read of values in one request whose deadline runs out is read again
/// in halves, not sent again whole: on a link too slow for the whole
/// request within the timeout, the first half is read within the read's
/// time (2.8.2 as first reviewed sent it again whole, which ran out of the
/// read's time too, and read nothing).
#[test]
fn a_lone_request_of_values_out_of_time_is_read_again_in_halves() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let ns = testkit::namespace();
    let w = testkit::open_remote(&ns).unwrap();
    let n = 100;
    let ids: Vec<String> = (0..n).map(unit).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let pad = "p".repeat(3_000);
    {
        let b = w.batch().unwrap();
        for (i, id) in ids.iter().enumerate() {
            w.put_for_test(
                id,
                S1,
                &hex64(1),
                Some(&hint(1)),
                &envelope(None, &format!("{i}{pad}")),
            )
            .unwrap();
        }
        b.finish().unwrap();
    }
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let read = |rate: usize| {
        let r = proxied(&proxy, token.as_deref(), &ns, 2);
        r.status().unwrap();
        let mut listed = r.list_units(&ids).unwrap();
        let mut refs: Vec<&mut StoredEnvelope> = listed.iter_mut().flatten().collect();
        proxy.limit_rate(rate);
        let (t, b) = (Instant::now(), proxy.passed());
        let ok = r.read_values(&mut refs);
        let (took, bytes) = (t.elapsed(), proxy.passed() - b);
        proxy.limit_rate(0);
        drop(refs);
        let read = listed
            .iter()
            .flatten()
            .filter(|e| matches!(e.state(), ValueState::Read(_)))
            .count();
        (ok.map(|()| read), took, bytes)
    };
    let (got, _, all) = read(0);
    assert_eq!(got.unwrap(), n);
    // The whole request in 2.5 s (the timeout is 2 s), a half in 1.25 s.
    let (got, took, _) = read(all * 2 / 5);
    let got = got.unwrap_or_else(|e| panic!("nothing read in {took:?}: {e}"));
    assert!(got >= n / 2 && got < n, "{got} in {took:?}");
    assert!(took < Duration::from_secs(5), "{took:?}");
}

/// A large read of values is given one more request timeout for each 800
/// values beyond 1,600: on a link that reads it in about two and a half
/// timeouts, every value is read (2.8.2 as first reviewed gave every read
/// two, and vex-api's 2,195 values took 29.9 to 58.6 s of its 60 s from a
/// laptop).
#[test]
fn a_large_read_of_values_is_given_a_timeout_per_800_values() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let ns = testkit::namespace();
    let w = testkit::open_remote(&ns).unwrap();
    let n = 1_700;
    let ids: Vec<String> = (0..n).map(unit).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let pad = "p".repeat(1_000);
    {
        let b = w.batch().unwrap();
        for (i, id) in ids.iter().enumerate() {
            w.put_for_test(
                id,
                S1,
                &hex64(1),
                Some(&hint(1)),
                &envelope(None, &format!("{i}{pad}")),
            )
            .unwrap();
        }
        b.finish().unwrap();
    }
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let prefetch = |rate: usize| {
        let r = proxied(&proxy, token.as_deref(), &ns, 2);
        r.status().unwrap();
        let mut listed = r.list_units(&ids).unwrap();
        let mut refs: Vec<&mut StoredEnvelope> = listed.iter_mut().flatten().collect();
        proxy.limit_rate(rate);
        let (t, b) = (Instant::now(), proxy.passed());
        r.read_values(&mut refs).unwrap();
        let (took, bytes) = (t.elapsed(), proxy.passed() - b);
        proxy.limit_rate(0);
        drop(refs);
        let read = listed
            .iter()
            .flatten()
            .filter(|e| matches!(e.state(), ValueState::Read(_)))
            .count();
        (read, took, bytes)
    };
    let (read, _, all) = prefetch(0);
    assert_eq!(read, n);
    // All of it in 5 s: two timeouts are 4 s, three 6 s.
    let (read, took, _) = prefetch(all / 5);
    assert_eq!(read, n, "in {took:?}");
    assert!(took < Duration::from_secs(7), "{took:?}");
}

/// A read of values that fits in one request brings the bases of the
/// manifests it references in that request: a small project's prefetch is
/// the listing and one request (2.8.2 as first reviewed read the bases in
/// one more, sequential request).
#[test]
fn a_small_read_of_values_brings_its_bases_in_the_same_request() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let ns = testkit::namespace();
    let p = table_prefix(&ns);
    let w = testkit::open_remote(&ns).unwrap();
    let base = manifest(&["src/base.rs"]);
    w.put_manifest(&base.root(), base.to_compact().as_bytes())
        .unwrap();
    // A manifest on that base.
    let top = hex64(0xee);
    w.__execute_for_test(&[format!(
        "INSERT INTO {p}manifests (root, base, put_at, encoding, value) \
         VALUES ('{top}', '{}', 1, 0, CAST('{{}}' AS BLOB))",
        base.root()
    )])
    .unwrap();
    let ids = ["src/a.test.ts", "src/b.test.ts", "src/c.test.ts"];
    for id in ids {
        w.put_for_test(id, S1, &hex64(1), Some(&hint(1)), &envelope(Some(&top), id))
            .unwrap();
    }
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let r = proxied(&proxy, token.as_deref(), &ns, 30);
    r.status().unwrap();
    let c0 = proxy.cursors();
    let h = r
        .prefetch(Prefetch::Units {
            test_ids: &ids,
            choose: None,
        })
        .unwrap();
    assert_eq!(h.unresolved, 0, "{h:?}");
    assert_eq!(
        proxy.cursors() - c0,
        2,
        "the listing and one request of values"
    );
    assert!(r.manifest(&top).unwrap().unwrap().is_read());
    assert!(r.manifest(&base.root()).unwrap().unwrap().is_read());
    assert_eq!(
        proxy.cursors() - c0,
        2,
        "the manifests came with the values"
    );
}

/// A write whose deadline ran out while the server committed it (it waited
/// for the write lock, and the client gave up first) is not sent again: the
/// client asks the server whether it holds the write's attestation first
/// (it was sent again, waited for the lock again and wrote its change log
/// a second time). One the server never got is sent again, once.
#[test]
fn a_write_out_of_time_is_sent_again_only_when_the_server_lacks_it() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let ns = testkit::namespace();
    let p = table_prefix(&ns);
    let s = proxied(&proxy, token.as_deref(), &ns, 2);
    let put = |n: u8, unit: &str| {
        s.put_for_test(unit, S1, &hex64(n), Some(&hint(1)), &envelope(None, unit))
    };
    put(1, "src/a.test.ts").unwrap();
    let logged = |unit: &str| {
        s.__query_for_test(&format!(
            "SELECT count(*) FROM {p}log WHERE test_key = '{}'",
            vci_core::test_key(unit)
        ))
        .unwrap()[0][0]
            .clone()
    };

    // Committed, its answer lost: asked about, not sent again.
    proxy.swallow_writes(1);
    let (w0, r0) = (proxy.writes(), s.retries());
    let t = Instant::now();
    put(2, "src/b.test.ts").unwrap_or_else(|e| panic!("committed: {e}"));
    assert!(t.elapsed() >= Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(proxy.stalled(), 1);
    assert_eq!(proxy.writes() - w0, 1, "not sent again");
    assert!(s.retries() > r0);
    assert_eq!(logged("src/b.test.ts"), "1");

    // Never reached the server: sent again, once.
    proxy.hold_writes(1);
    let w0 = proxy.writes();
    put(3, "src/c.test.ts").unwrap_or_else(|e| panic!("sent again: {e}"));
    assert_eq!(proxy.stalled(), 2);
    assert_eq!(proxy.writes() - w0, 1, "sent again");
    assert_eq!(logged("src/c.test.ts"), "1");
    assert_eq!(s.list_all().unwrap().len(), 3);
}

/// A replica synced by a vci that could not read some values (2.8.1, while
/// another vci wrote them compressed) left them out yet moved its mark past
/// them, so syncing what changed since never brings them back: a sidecar
/// written by such a vci (its `v` older than this one's) is synced in full
/// once, and the values come back.
#[test]
fn a_replica_synced_by_an_older_vci_is_synced_in_full_once() {
    let Some((w, ns)) = remote() else { return };
    // Values as they are: the test sets their encoding by hand.
    w.__compress_for_test(false);
    let p = table_prefix(&ns);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replica.libsql");
    let side = dir.path().join("replica.libsql.sync");
    let units = ["src/a.test.ts", "src/b.test.ts"];
    for u in units {
        w.put_for_test(u, S1, &hex64(1), Some(&hint(1)), &envelope(None, u))
            .unwrap();
    }
    // b's value in an encoding no vci reads: the sync leaves it out.
    let tk = vci_core::test_key("src/b.test.ts");
    let set = |enc: u8| {
        w.__execute_for_test(&[format!(
            "UPDATE {p}attestations SET encoding = {enc} WHERE test_key = '{tk}'"
        )])
        .unwrap();
    };
    set(9);
    let r = testkit::open_replica(&ns, &path).unwrap();
    let got = r.read_units(&units).unwrap();
    assert_eq!(got[0].len(), 1);
    assert!(got[1].is_empty(), "left out: {:?}", got[1]);
    drop(r);
    // Readable now, with no change in the log: as a value 2.8.1 could not
    // read is to this vci. The sidecar as 2.8.1 wrote it.
    set(0);
    let text = std::fs::read_to_string(&side).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["v"] = serde_json::json!(1);
    std::fs::write(&side, v.to_string()).unwrap();
    let r = testkit::open_replica(&ns, &path).unwrap();
    let got = r.read_units(&units).unwrap();
    assert_eq!(got[1].len(), 1, "synced in full");
    drop(r);
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&side).unwrap()).unwrap();
    assert!(v["v"].as_i64().unwrap() >= 2, "{v}");
}

/// A batch is written as transactions of whole units of about a megabyte
/// each, one after the other, not one request of everything (2.8.1 sent
/// 8 MB, which held Turso's one write lock for 15 to 37 s while every
/// other job's write waited): a unit's attestation and its manifest go in
/// the same transaction, and every unit is stored.
#[test]
fn a_batch_is_written_as_short_transactions_of_whole_units() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let ns = testkit::namespace();
    let s = proxied(&proxy, token.as_deref(), &ns, 30);
    s.status().unwrap();
    // 120 units of about 20 kB of attestation and 20 kB of manifest: 4.8 MB.
    let n = 120;
    let ids: Vec<String> = (0..n).map(unit).collect();
    let pad = "p".repeat(20_000);
    let w0 = proxy.writes();
    {
        let b = s.batch().unwrap();
        for (i, id) in ids.iter().enumerate() {
            let paths: Vec<String> = (0..120).map(|j| format!("src/m{i}/{j}.rs")).collect();
            let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
            let m = manifest(&paths);
            s.put_manifest(&m.root(), m.to_compact().as_bytes())
                .unwrap();
            s.put_for_test(
                id,
                S1,
                &hex64(1),
                Some(&hint(1)),
                &envelope(Some(&m.root()), &format!("{i}{pad}")),
            )
            .unwrap();
        }
        let f = b.finish_partial().unwrap();
        assert_eq!(f.lost_count(), 0);
    }
    let sizes: Vec<usize> = proxy.write_sizes()[w0..].to_vec();
    assert!(sizes.len() >= 4, "{sizes:?}");
    // At most a megabyte of values each, and the request's framing (the
    // JSON escapes of the statements' text).
    assert!(
        sizes.iter().all(|&b| b < 1_600_000),
        "a transaction too large: {sizes:?}"
    );
    let r = testkit::open_remote(&ns).unwrap();
    let all = r.read_all().unwrap();
    assert_eq!(all.len(), n);
    for e in &all {
        let ValueState::Read(v) = e.state() else {
            panic!("unread: {e:?}");
        };
        let root = match vci_store::key::envelope_manifest_ref(v) {
            vci_store::ManifestRef::Root(r) => r,
            other => panic!("{other:?}"),
        };
        assert!(r.manifest(&root).unwrap().is_some(), "its manifest");
    }
}

/// A write transaction that runs out of time and that the server does not
/// hold is sent again after a pause, and the batch is stored whole, with
/// nothing latched (2.8.1 latched the store, and every later write of the
/// process failed: about 800 attestations lost per Rails job on Turso).
/// Writes that keep running out of time cost the process at most about
/// two request timeouts in all: then the breaker latches, the units not
/// stored are lost (and only they: the transactions stored before stay),
/// and every later call fails at once.
#[test]
fn writes_out_of_time_are_sent_again_within_a_bounded_time() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let ns = testkit::namespace();
    // About 0.4 MB an attestation as it travels (as it is, whatever
    // `VCI_STORE_COMPRESS` says): two to a transaction.
    let pad = "p".repeat(300_000);
    let batch = |s: &LibsqlStore, from: usize, to: usize| {
        s.__compress_for_test(false);
        let b = s.batch().unwrap();
        let mut keys = Vec::new();
        for i in from..to {
            keys.push(
                s.put_for_test(
                    &unit(i),
                    S1,
                    &hex64(1),
                    Some(&hint(1)),
                    &envelope(None, &format!("{i}{pad}")),
                )
                .unwrap()
                .key,
            );
        }
        (b.finish_partial().unwrap(), keys)
    };

    // One transaction held: out of time (2 s), not on the server, sent
    // again; all stored.
    let s = proxied(&proxy, token.as_deref(), &ns, 2);
    s.status().unwrap();
    proxy.hold_writes(1);
    let (w0, r0) = (proxy.writes(), s.retries());
    let t = Instant::now();
    let (f, _) = batch(&s, 0, 6);
    assert_eq!(f.lost_count(), 0, "{:?}", f.into_error());
    assert!(t.elapsed() >= Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(proxy.stalled(), 1);
    assert!(s.retries() > r0);
    // 6 units of 0.4 MB: 3 transactions of 2, the held one sent again in
    // halves.
    assert!(proxy.writes() - w0 >= 4, "{}", proxy.writes() - w0);
    s.status()
        .unwrap_or_else(|e| panic!("nothing latched: {e}"));
    assert_eq!(s.list_all().unwrap().len(), 6);

    // A server that takes no writes from the second transaction on: the
    // first is stored, the others lost after about two request timeouts
    // (4 s) of tries, and the handle latched.
    let s = proxied(&proxy, token.as_deref(), &ns, 2);
    s.status().unwrap();
    let held = proxy.stalled();
    let w0 = proxy.writes();
    let stop = std::thread::scope(|sc| {
        sc.spawn(|| {
            while proxy.writes() == w0 {
                std::thread::sleep(Duration::from_millis(1));
            }
            proxy.stall_writes(true);
        });
        let t = Instant::now();
        let (f, keys) = batch(&s, 10, 18);
        (f, keys, t.elapsed())
    });
    proxy.stall_writes(false);
    let (f, keys, took) = stop;
    assert!(took < Duration::from_secs(9), "{took:?}");
    assert!(proxy.stalled() - held >= 2, "{}", proxy.stalled() - held);
    assert_eq!(f.lost_count(), 6, "the first transaction's 2 stored");
    let stored: Vec<&String> = keys.iter().filter(|k| f.lost(k).is_none()).collect();
    assert_eq!(stored.len(), 2);
    let t = Instant::now();
    let e = s.status().unwrap_err();
    assert!(e.to_string().contains("not retried"), "{e}");
    assert!(t.elapsed() < Duration::from_secs(1));
    let r = testkit::open_remote(&ns).unwrap();
    let on_server: Vec<String> = r.list_all().unwrap().into_iter().map(|e| e.key).collect();
    assert_eq!(on_server.len(), 8);
    assert!(stored.iter().all(|k| on_server.contains(k)));
}

/// On a link where each answer waits long for its first byte but bytes
/// then come fast (here 300 ms an answer), a read of values sends its
/// first requests at once, one per connection, and makes the later ones
/// larger: few round trips, with the manifests and their bases in the
/// same requests (2.8.2 as first reviewed sent requests of 100 two at a
/// time and the bases in one more request, slower there than 2.8.1's one
/// request of everything).
#[test]
fn a_read_of_values_on_a_link_slow_to_answer_takes_few_round_trips() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let ns = testkit::namespace();
    let w = testkit::open_remote(&ns).unwrap();
    let n = 1_500;
    let ids: Vec<String> = (0..n).map(unit).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let base = manifest(&["src/base.rs"]);
    w.put_manifest(&base.root(), base.to_compact().as_bytes())
        .unwrap();
    let p = table_prefix(&ns);
    {
        let b = w.batch().unwrap();
        for (i, id) in ids.iter().enumerate() {
            w.put_for_test(
                id,
                S1,
                &hex64(1),
                Some(&hint(1)),
                &envelope(Some(&hex64(0xaa)), &format!("{i}")),
            )
            .unwrap();
        }
        b.finish().unwrap();
    }
    // Every attestation references one manifest on the base.
    w.__execute_for_test(&[format!(
        "INSERT INTO {p}manifests (root, base, put_at, encoding, value) \
         VALUES ('{}', '{}', 1, 0, CAST('{{}}' AS BLOB))",
        hex64(0xaa),
        base.root()
    )])
    .unwrap();
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let r = proxied(&proxy, token.as_deref(), &ns, 30);
    r.status().unwrap();
    proxy.delay_answers(300);
    let c0 = proxy.cursors();
    let t = Instant::now();
    let h = r
        .prefetch(Prefetch::Units {
            test_ids: &ids,
            choose: None,
        })
        .unwrap();
    let took = t.elapsed();
    assert_eq!(h.unresolved, 0, "{h:?}");
    let cursors = proxy.cursors() - c0;
    assert!(r.manifest(&hex64(0xaa)).unwrap().unwrap().is_read());
    assert!(r.manifest(&base.root()).unwrap().unwrap().is_read());
    assert_eq!(proxy.cursors() - c0, cursors, "the manifests came along");
    // The listing, then four requests of 100 at once, then the other
    // 1,100 values in four larger ones at once.
    assert!(cursors <= 9, "{cursors} requests");
    // Each answer waits 300 ms, a statement's first description on a
    // connection one more: the listing (2), the first requests (2), the
    // later ones (1 or 2), with time to spare.
    assert!(took < Duration::from_millis(3_600), "{took:?}");
    let all: Vec<_> = r.list_units(&ids).unwrap().into_iter().flatten().collect();
    assert_eq!(all.len(), n);
}

// ---- 2.8.2: the write review's findings ----------------------------------------------------

/// A batch's queue is written early when it holds 4 MiB, but never in the
/// middle of a unit: a unit's manifest, its attestation and the removal of
/// the attestation it supersedes, queued one after the other, are written
/// in one transaction, so that a write the server refuses loses the whole
/// unit. A draft of 2.8.2 wrote the queue as soon as it was full: (1) a
/// manifest that filled it went in one transaction, refused, while its
/// attestation went in the next, stored and reported as attested on a
/// manifest that was never stored; (2) an attestation that filled it went
/// in one transaction, refused, while the removal of the attestation it
/// supersedes went in the next and deleted it.
#[test]
fn an_early_write_of_a_batch_never_splits_a_unit() {
    let Some((s, ns)) = remote() else { return };
    s.__compress_for_test(false);
    let p = table_prefix(&ns);
    // About 2 MB an envelope (its payload base64): two fill the queue but
    // for 194 kB.
    let fill = "f".repeat(1_500_000);
    let fills = |s: &LibsqlStore, tag: &str| {
        for i in 0..2 {
            s.put_for_test(
                &format!("src/fill-{tag}{i}.test.ts"),
                S1,
                &hex64(9),
                Some(&hint(1)),
                &envelope(None, &format!("{i}{fill}")),
            )
            .unwrap();
        }
    };

    // The tables, and the attestation (2) supersedes.
    let old = s
        .put_for_test(
            "src/u.test.ts",
            S1,
            &hex64(1),
            Some(&hint(1)),
            &envelope(None, "old"),
        )
        .unwrap();

    // (1) The manifest fills the queue; the server refuses it.
    let paths: Vec<String> = (0..2_400).map(|j| format!("src/split/{j}.rs")).collect();
    let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
    let m = manifest(&paths);
    let bytes = m.to_compact();
    assert!(bytes.len() > 200_000, "{}", bytes.len());
    s.__execute_for_test(&[format!(
        "CREATE TRIGGER {p}no_m BEFORE INSERT ON {p}manifests WHEN NEW.root = '{}' \
         BEGIN SELECT RAISE(ABORT, 'mboom'); END",
        m.root()
    )])
    .unwrap();
    let b = s.batch().unwrap();
    fills(&s, "a");
    s.put_manifest(&m.root(), bytes.as_bytes()).unwrap();
    let put = s
        .put_for_test(
            "src/m.test.ts",
            S1,
            &hex64(1),
            Some(&hint(2)),
            &envelope(Some(&m.root()), "m"),
        )
        .unwrap();
    let f = b.finish_partial().unwrap();
    match f.lost(&put.key) {
        Some(e) => assert!(e.to_string().contains("mboom"), "{e}"),
        None => panic!(
            "the unit whose manifest was refused is not lost: {:?}",
            f.warnings
        ),
    }
    assert_eq!(f.lost_count(), 1);
    let srv = testkit::open_remote(&ns).unwrap();
    assert!(srv.manifest(&m.root()).unwrap().is_none());
    assert!(
        keys_of(&srv, "src/m.test.ts").is_empty(),
        "an attestation stored without its manifest"
    );
    assert_eq!(keys_of(&srv, "src/fill-a0.test.ts").len(), 1);
    assert_eq!(keys_of(&srv, "src/fill-a1.test.ts").len(), 1);

    // (2) The attestation fills the queue; the server refuses it, and the
    // attestation it supersedes stays.
    let bad = hex64(0xbb);
    s.__execute_for_test(&[format!(
        "CREATE TRIGGER {p}no_u BEFORE INSERT ON {p}attestations WHEN NEW.storage_key = '{bad}' \
         BEGIN SELECT RAISE(ABORT, 'uboom'); END"
    )])
    .unwrap();
    let b = s.batch().unwrap();
    fills(&s, "b");
    let new = s
        .put_for_test(
            "src/u.test.ts",
            S1,
            &bad,
            Some(&hint(2)),
            &envelope(None, &format!("new{}", "n".repeat(200_000))),
        )
        .unwrap();
    s.remove(vec![old.clone()]).unwrap();
    let f = b.finish_partial().unwrap();
    match f.lost(&new.key) {
        Some(e) => assert!(e.to_string().contains("uboom"), "{e}"),
        None => panic!("the refused unit is not lost"),
    }
    let srv = testkit::open_remote(&ns).unwrap();
    assert_eq!(
        keys_of(&srv, "src/u.test.ts"),
        vec![old.key.clone()],
        "the superseded attestation was removed though its successor was refused"
    );
    assert_eq!(keys_of(&srv, "src/fill-b1.test.ts").len(), 1);
}

/// A write transaction that waits for the write lock past its deadline is
/// asked about (not committed yet: the question is a read, which does not
/// wait for the lock) and sent again, and the first send then commits
/// after all: the transaction is applied once, not twice. A draft of 2.8.2
/// sent it again in halves, and the server applied both (on vex's Turso
/// database the original committed after the question, and every slot of
/// it was written and logged twice). The proxy sends the first send on
/// 3 s late, after the copy (the write's deadline is 2 s); `sqld` itself
/// drops a write that waits for the lock once its client is gone.
#[test]
fn a_write_committed_after_the_question_is_applied_once() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let ns = testkit::namespace();
    let p = table_prefix(&ns);
    let s = proxied(&proxy, token.as_deref(), &ns, 2);
    s.__compress_for_test(false);
    s.put_for_test(
        "src/seed.test.ts",
        S1,
        &hex64(1),
        Some(&hint(1)),
        &envelope(None, "seed"),
    )
    .unwrap();
    let units = [
        "src/a.test.ts",
        "src/b.test.ts",
        "src/c.test.ts",
        "src/d.test.ts",
    ];
    proxy.late_writes(1, 3_000);
    let r0 = s.retries();
    let b = s.batch().unwrap();
    let keys: Vec<String> = units
        .iter()
        .map(|u| {
            s.put_for_test(u, S1, &hex64(2), Some(&hint(2)), &envelope(None, u))
                .unwrap()
                .key
        })
        .collect();
    let f = b.finish_partial().unwrap();
    assert_eq!(f.lost_count(), 0, "{:?}", f.into_error());
    assert_eq!(proxy.stalled(), 1);
    assert!(s.retries() > r0, "it ran out of time and was asked about");
    // The first send reaches the server now.
    let t = Instant::now();
    while proxy.shared.late_done.load(Ordering::SeqCst) == 0
        && t.elapsed() < Duration::from_secs(15)
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(proxy.shared.late_done.load(Ordering::SeqCst), 1);
    let r = testkit::open_remote(&ns).unwrap();
    for (u, k) in units.iter().zip(&keys) {
        assert_eq!(keys_of(&r, u), vec![k.clone()]);
        let logged = r
            .__query_for_test(&format!(
                "SELECT count(*) FROM {p}log WHERE test_key = '{}'",
                vci_core::test_key(u)
            ))
            .unwrap();
        assert_eq!(logged, vec![vec!["1".to_owned()]], "{u} applied twice");
    }
}

/// On a link where every answer waits 3 s for its first byte (and bytes
/// then come fast), the requests of a read of values grow to their most
/// after the first answers: the time beyond the shortest answer is what
/// sizes them, not the whole time an answer took. A draft of 2.8.2 sized
/// them from the whole time, so the 3 s wait kept them at about 150 values
/// and vex-api's prefetch sent 12 to 14 requests where 2.8.1 sent 4.
#[test]
fn a_read_of_values_behind_a_long_wait_for_each_answer_takes_few_rounds() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let ns = testkit::namespace();
    let w = testkit::open_remote(&ns).unwrap();
    let n = 1_500;
    let ids: Vec<String> = (0..n).map(unit).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    {
        let b = w.batch().unwrap();
        for (i, id) in ids.iter().enumerate() {
            w.put_for_test(
                id,
                S1,
                &hex64(1),
                Some(&hint(1)),
                &envelope(None, &format!("{i}")),
            )
            .unwrap();
        }
        b.finish().unwrap();
    }
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    proxy.delay_answers(3_000);
    let r = proxied(&proxy, token.as_deref(), &ns, 30);
    r.status().unwrap();
    let c0 = proxy.cursors();
    let t = Instant::now();
    let h = r
        .prefetch(Prefetch::Units {
            test_ids: &ids,
            choose: None,
        })
        .unwrap();
    let took = t.elapsed();
    assert_eq!(h.unresolved, 0, "{h:?}");
    let cursors = proxy.cursors() - c0;
    // The listing, four requests of 100 at once, then the other 1,100 in
    // three of up to 400 at once: 8 requests in about 15 s, where the
    // draft sent 16 in 21 s (each a statement described, then run, on a
    // new connection: two waits).
    assert!(cursors <= 8, "{cursors} requests in {took:?}");
    assert!(
        took < Duration::from_secs(18),
        "{cursors} requests in {took:?}"
    );
    let all: Vec<_> = r.list_units(&ids).unwrap().into_iter().flatten().collect();
    assert_eq!(all.len(), n);
}

/// A batch of small units written as many transactions.
fn small_batch(
    s: &LibsqlStore,
    tag: &str,
    n: usize,
    pad: usize,
) -> (vci_store::Finished, Vec<String>) {
    s.__compress_for_test(false);
    let pad = "p".repeat(pad);
    let b = s.batch().unwrap();
    let keys = (0..n)
        .map(|i| {
            let u = format!("src/{tag}/{i}.test.ts");
            s.put_for_test(
                &u,
                S1,
                &hex64(1),
                Some(&hint(1)),
                &envelope(None, &format!("{u}{pad}")),
            )
            .unwrap()
            .key
        })
        .collect();
    (b.finish_partial().unwrap(), keys)
}

/// A write that runs out of time while the server answers nothing, not
/// even the question whether it committed, is sent again: the question
/// has a short deadline of its own (a quarter of the request timeout, at
/// most 5 s), so one try costs about one request timeout. 2.8.2 as first
/// reviewed gave the question the whole request timeout: one try cost two
/// (60 s at the default), the whole of the process's retry time, the
/// breaker latched and the units were lost without being sent again.
#[test]
fn a_write_whose_question_goes_unanswered_is_sent_again() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let ns = testkit::namespace();
    // A 2 s request timeout: 4 s of retry time; the question 0.5 s.
    let s = proxied(&proxy, token.as_deref(), &ns, 2);
    // The tables made first.
    let (f, _) = small_batch(&s, "seed", 1, 100);
    assert_eq!(f.lost_count(), 0);
    proxy.hold_writes(1);
    let held = proxy.stalled();
    let (f, keys, took) = std::thread::scope(|sc| {
        // Once the write is held, the question after it goes unanswered too.
        sc.spawn(|| {
            let t = Instant::now();
            while proxy.stalled() == held && t.elapsed() < Duration::from_secs(10) {
                std::thread::sleep(Duration::from_millis(1));
            }
            proxy.stall_cursors(1);
        });
        let t = Instant::now();
        let (f, keys) = small_batch(&s, "q", 4, 100);
        (f, keys, t.elapsed())
    });
    assert_eq!(proxy.stalled() - held, 2, "the write and its question held");
    assert_eq!(f.lost_count(), 0, "sent again: {:?}", f.into_error());
    assert!(took < Duration::from_secs(6), "{took:?}");
    s.status()
        .unwrap_or_else(|e| panic!("nothing latched: {e}"));
    let r = testkit::open_remote(&ns).unwrap();
    let on_server: Vec<String> = r.list_all().unwrap().into_iter().map(|e| e.key).collect();
    assert!(keys.iter().all(|k| on_server.contains(k)));
}

/// A write's transactions go one right after the other: no pause between
/// them. 2.8.2 as first reviewed paused a quarter of each transaction's
/// time (200 ms to 2 s, randomized) for other writers' small writes, which
/// cost a lone writer about 10% of its time and showed no benefit for the
/// small writes on vex's Turso database.
#[test]
fn a_write_sends_its_transactions_without_a_pause() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let ns = testkit::namespace();
    let s = proxied(&proxy, token.as_deref(), &ns, 30);
    s.status().unwrap();
    // 64 attestations a transaction: 10 transactions.
    let (f, _) = small_batch(&s, "gap", 640, 100);
    assert_eq!(f.lost_count(), 0);
    let mut gaps = proxy.write_gaps();
    assert!(gaps.len() >= 9, "{gaps:?}");
    gaps.sort();
    let median = gaps[gaps.len() / 2];
    assert!(median < Duration::from_millis(60), "paused: {gaps:?}");
}

/// A process's writes stop once they took six request timeouts in all,
/// even when every transaction commits in time: the units still queued are
/// lost at once (their units run again next time), the ones stored stay,
/// nothing is latched, and a later write of the process is lost at once
/// too. 2.8.2 as first reviewed bounded only the time of writes that
/// failed, so a Rails job's 800 units, each transaction committing just
/// within the timeout behind other writers, could take minutes.
#[test]
fn a_process_writes_for_a_bounded_time_in_all() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let ns = testkit::namespace();
    // A 1 s request timeout: 6 s of writes in all.
    let s = proxied(&proxy, token.as_deref(), &ns, 1);
    let (f, _) = small_batch(&s, "seed", 1, 100);
    assert_eq!(f.lost_count(), 0);
    // Each answer held 250 ms: within the timeout, and the transactions
    // keep their size (between a tenth and a third of it).
    proxy.delay_answers(250);
    let t = Instant::now();
    // 64 a transaction: 40 transactions, more than 10 s without the bound.
    let (f, keys) = small_batch(&s, "slow", 2_560, 100);
    let took = t.elapsed();
    let lost = f.lost_count();
    assert!(lost > 0 && lost < keys.len(), "lost {lost}");
    assert!(
        took >= Duration::from_secs(6) && took < Duration::from_millis(7_500),
        "{took:?}"
    );
    let why = f.into_error().unwrap().to_string();
    assert!(why.contains("this process's writes"), "{why}");
    // Not latched; a later write of the process is lost at once.
    proxy.delay_answers(0);
    s.status()
        .unwrap_or_else(|e| panic!("nothing latched: {e}"));
    let t = Instant::now();
    let (f, _) = small_batch(&s, "later", 4, 100);
    assert_eq!(f.lost_count(), 4);
    assert!(
        t.elapsed() < Duration::from_millis(500),
        "{:?}",
        t.elapsed()
    );
    let r = testkit::open_remote(&ns).unwrap();
    assert_eq!(r.list_all().unwrap().len(), 1 + keys.len() - lost);
}

/// A write's transactions are made smaller when they commit slowly (more
/// than a third of the request timeout each), down to 128 KiB, and larger
/// again, up to 1 MiB, when they commit fast (less than a tenth): behind
/// other writers on vex's Turso database transactions of about 1 MB took
/// 23 to 31 s, at the edge of the 30 s timeout, where 2.8.2 as first
/// reviewed kept sending 1 MiB.
#[test]
fn a_write_sizes_its_transactions_from_their_commit_times() {
    let Some((server, token)) = proxied_server() else {
        return;
    };
    let proxy = Proxy::start(&server, Duration::from_secs(60), Close::Fin);
    let ns = testkit::namespace();
    let s = proxied(&proxy, token.as_deref(), &ns, 2);
    // The tables made first.
    let (f, _) = small_batch(&s, "seed", 1, 100);
    assert_eq!(f.lost_count(), 0);
    // Each answer held 0.8 s: more than a third of the 2 s timeout.
    proxy.delay_answers(800);
    let w0 = proxy.write_sizes().len();
    // 80 units of about 25 kB as sent: 2 MB, 5 transactions.
    let (f, _) = small_batch(&s, "big", 80, 20_000);
    assert_eq!(f.lost_count(), 0, "{:?}", f.into_error());
    let slow: Vec<usize> = proxy.write_sizes()[w0..].to_vec();
    assert!(slow.len() >= 4, "{slow:?}");
    assert!(slow[0] > 900_000, "{slow:?}");
    assert!(slow[1] < slow[0] * 6 / 10, "halved: {slow:?}");
    assert!(slow[3] < 250_000, "down to 128 KiB: {slow:?}");
    // Fast again: they grow back.
    proxy.delay_answers(0);
    let w1 = proxy.write_sizes().len();
    let (f, _) = small_batch(&s, "fast", 80, 20_000);
    assert_eq!(f.lost_count(), 0);
    let fast: Vec<usize> = proxy.write_sizes()[w1..].to_vec();
    assert!(fast.iter().any(|&b| b > 900_000), "grown back: {fast:?}");
}
