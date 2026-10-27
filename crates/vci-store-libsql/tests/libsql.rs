//! The libSQL store's own tests: what the conformance suite cannot check
//! through the trait (the local file's format, requests per plan, schema
//! states, deadlines, secrets in `Debug`, tokens, the replica's sync).
//! Tests that need a server use [`testkit`] and are skipped without one
//! (a failure under `VCI_TEST_LIBSQL=require`).

use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
        // database are not the batch's own.
        let used = s.requests() - s.retries() - before;
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
/// refused) and forget every connection.
struct Proxy {
    port: u16,
    gone: Arc<AtomicBool>,
    forgotten: Arc<AtomicUsize>,
    listener: Option<std::thread::JoinHandle<()>>,
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
        let gone = Arc::new(AtomicBool::new(false));
        let forgotten = Arc::new(AtomicUsize::new(0));
        let (g, f) = (gone.clone(), forgotten.clone());
        let listener = std::thread::spawn(move || {
            while !g.load(Ordering::SeqCst) {
                match l.accept() {
                    Ok((client, _)) => {
                        let (g, f, upstream) = (g.clone(), f.clone(), upstream.clone());
                        std::thread::spawn(move || relay(client, &upstream, idle, close, &g, &f));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(2)),
                }
            }
            // The listener closes here: a new connection is refused.
        });
        Proxy {
            port,
            gone,
            forgotten,
            listener: Some(listener),
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// How many connections it forgot.
    fn forgotten(&self) -> usize {
        self.forgotten.load(Ordering::SeqCst)
    }

    /// Stop listening, and forget every connection.
    fn go_away(&mut self) {
        self.gone.store(true, Ordering::SeqCst);
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

/// One client connection of a [`Proxy`].
fn relay(
    client: std::net::TcpStream,
    upstream: &str,
    idle: Duration,
    close: Close,
    gone: &AtomicBool,
    forgotten: &AtomicUsize,
) {
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
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if server.is_some() && (gone.load(Ordering::SeqCst) || (!waiting && last.elapsed() > idle))
        {
            // Forgotten: the server's side closes now, the client is not
            // told.
            server = None;
            forgotten.fetch_add(1, Ordering::SeqCst);
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
            if let Close::Fin = close {
                // The rest of the request, then a FIN, then whatever the
                // client still does until it closes.
                let mut quiet = Instant::now();
                while quiet.elapsed() < Duration::from_millis(50) {
                    match take(&client, &mut buf) {
                        Some(0) => return,
                        Some(_) => quiet = Instant::now(),
                        None => std::thread::sleep(Duration::from_millis(1)),
                    }
                }
                let _ = client.shutdown(std::net::Shutdown::Write);
                let until = Instant::now() + Duration::from_secs(5);
                while Instant::now() < until && take(&client, &mut buf) != Some(0) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            // Close::Reset: dropped with the rest of the request unread,
            // which resets the connection.
            return;
        };
        match take(&client, &mut buf) {
            Some(0) => return,
            Some(n) => {
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
                if !send_all(&client, &buf[..n]) {
                    return;
                }
                (moved, waiting, last) = (true, false, Instant::now());
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

/// A statement the server refuses (here a trigger's `RAISE`) fails its
/// batch as `Backend`, writes nothing, and latches nothing: the handle's
/// later reads and writes go on, remote and replica.
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
        h.put_for_test(
            "src/a.test.ts",
            S1,
            &bad,
            Some(&hint(5)),
            &envelope(None, "bad"),
        )
        .unwrap();
        match b.finish() {
            Err(e @ StoreError::Backend(_)) => assert!(e.to_string().contains("boom"), "{e}"),
            other => panic!("replica {replica}: expected Backend, got {other:?}"),
        }
        let srv = testkit::open_remote(&ns).unwrap();
        assert!(
            srv.manifest(&m.root()).unwrap().is_none(),
            "the failed batch's manifest"
        );
        assert!(
            keys_of(&srv, "src/b.test.ts").is_empty(),
            "the failed batch's attestation"
        );
        // The handle goes on.
        assert!(h.manifest(&m.root()).unwrap().is_none());
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
            let big = envelope(None, &"z".repeat(200_000));
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
