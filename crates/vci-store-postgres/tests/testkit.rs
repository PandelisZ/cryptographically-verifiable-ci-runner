//! The temporary-PostgreSQL helper's own tests: one server per process,
//! schemas (and roles) dropped with their `PgDb`, and a throwaway cluster
//! that is stopped and deleted when the test process dies, whether it
//! panics or is killed.
//!
//! Without `VCI_TEST_POSTGRES_URL` these run the initdb path; with it, the
//! first two use that server and the last still starts its own clusters in
//! child processes when `initdb` is available.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vci_store::AttestationStore;
use vci_store_postgres::testkit::{self, REQUIRE_VAR, URL_VAR, pg};

/// Set in a child test process: what the holder test does once it holds a
/// cluster (`panic` or `wait`, to be killed).
const HOLDER_VAR: &str = "VCI_TESTKIT_HOLDER";

fn url_set() -> bool {
    std::env::var(URL_VAR).is_ok_and(|u| !u.trim().is_empty())
}

fn require() -> bool {
    std::env::var(REQUIRE_VAR).as_deref() == Ok("require")
}

#[test]
fn one_server_per_process() {
    if std::env::var_os(HOLDER_VAR).is_some() {
        return;
    }
    let Some(a) = pg() else { return };
    let b = pg().expect("a second pg() in the same process");
    assert!(testkit::available());
    assert_eq!(a.url, b.url, "both come from one server");
    assert_ne!(a.schema, b.schema, "each has its own schema");
    assert!(
        a.schema
            .starts_with(&format!("vci_t_{}_", std::process::id()))
    );
    if url_set() {
        assert_eq!(testkit::clusters_started(), 0);
        return;
    }
    assert_eq!(
        testkit::clusters_started(),
        1,
        "one cluster for the process"
    );
    let port = testkit::cluster_port().expect("a cluster port");
    assert!(a.url.contains(&format!("@127.0.0.1:{port}/")), "{}", a.url);
    // TCP only, on 127.0.0.1, set up for speed.
    let show = |what: &str| -> String { a.query(&format!("SHOW {what}"))[0].get(0) };
    assert_eq!(show("unix_socket_directories"), "");
    assert_eq!(show("listen_addresses"), "127.0.0.1");
    assert_eq!(show("fsync"), "off");
    assert_eq!(show("max_connections"), "300");
    // en_US.UTF-8, or C where that locale is missing.
    let locale = testkit::cluster_locale().expect("a cluster locale");
    let collate: String =
        a.query("SELECT datcollate::text FROM pg_database WHERE datname = 'postgres'")[0].get(0);
    assert_eq!(collate, locale);
    if cfg!(target_os = "macos") {
        assert_eq!(locale, "en_US.UTF-8", "macOS has the en_US locale");
    }
    // The cluster lives under its own directory.
    let data = testkit::cluster_data_dir().expect("a data directory");
    assert!(data.join("PG_VERSION").is_file(), "{}", data.display());
}

#[test]
fn schemas_and_roles_are_dropped() {
    if std::env::var_os(HOLDER_VAR).is_some() {
        return;
    }
    let Some(db) = pg() else { return };
    let schema = db.schema.clone();
    let role = format!("{schema}_r");
    db.role("r", "");
    // A store's first write creates the schema.
    let store = db.open();
    let manifest = br#"{"v":2,"entries":[],"externals":[],"env":[]}"#;
    store
        .put_manifest(&format!("{:064x}", 7), manifest)
        .expect("put a manifest");
    assert!(db.schema_exists());
    drop(store);
    drop(db);

    let other = pg().expect("the server again");
    assert_eq!(
        other.count(&format!(
            "SELECT count(*) FROM pg_namespace WHERE nspname = '{schema}'"
        )),
        0,
        "the schema is dropped with its PgDb"
    );
    assert_eq!(
        other.count(&format!(
            "SELECT count(*) FROM pg_roles WHERE rolname = '{role}'"
        )),
        0,
        "the role is dropped with its PgDb"
    );
}

/// Not a test of its own: in a child process (HOLDER_VAR set) it takes a
/// cluster, says where it is, and then panics or waits to be killed.
#[test]
fn holder() {
    let Some(mode) = std::env::var_os(HOLDER_VAR) else {
        return;
    };
    let db = pg().expect("the throwaway cluster");
    assert_eq!(db.count("SELECT 1::bigint"), 1);
    let data = testkit::cluster_data_dir().expect("a throwaway cluster, not a URL");
    let pid = std::fs::read_to_string(data.join("postmaster.pid"))
        .expect("postmaster.pid")
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    println!("HOLDER data={}", data.display());
    println!("HOLDER pid={pid}");
    use std::io::Write as _;
    std::io::stdout().flush().unwrap();
    if mode == "panic" {
        panic!("the holder panics while it holds a cluster");
    }
    std::thread::sleep(Duration::from_secs(120));
}

/// Runs the holder in a child test process; the cluster's data directory
/// and postmaster pid once the child is gone (panicked or killed).
fn run_holder(mode: &str) -> (PathBuf, String) {
    let exe = std::env::current_exe().expect("the test binary");
    let mut child = Command::new(exe)
        .args(["holder", "--exact", "--nocapture", "--test-threads=1"])
        .env(HOLDER_VAR, mode)
        .env_remove(URL_VAR)
        .env(REQUIRE_VAR, "require")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the holder");
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let (mut data, mut pid) = (None, None);
    let mut seen = String::new();
    let mut line = String::new();
    while data.is_none() || pid.is_none() {
        line.clear();
        if out.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        seen.push_str(&line);
        if let Some(d) = marker(&line, "HOLDER data=") {
            data = Some(PathBuf::from(d));
        } else if let Some(p) = marker(&line, "HOLDER pid=") {
            pid = Some(p.to_owned());
        }
    }
    if mode != "panic" {
        child.kill().expect("kill the holder");
    }
    let mut rest = String::new();
    let _ = out.read_to_string(&mut rest);
    let mut err = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut err);
    let status = child.wait().expect("wait for the holder");
    assert!(!status.success(), "the holder {mode}s: {status}");
    match (data, pid) {
        (Some(d), Some(p)) if !p.is_empty() => (d, p),
        _ => panic!("the holder did not report its cluster:\n{seen}{rest}\n{err}"),
    }
}

fn alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// `pg_ctl status`: true once it reports no server (exit 3), or the data
/// directory is gone (exit 4).
fn no_server(pg_ctl: &Path, data: &Path) -> bool {
    let out = Command::new(pg_ctl)
        .arg("status")
        .arg("-D")
        .arg(data)
        .stdin(Stdio::null())
        .output()
        .expect("run pg_ctl status");
    let text = String::from_utf8_lossy(&out.stdout);
    match out.status.code() {
        Some(3) => text.contains("no server running"),
        Some(4) => !data.exists(),
        _ => false,
    }
}

fn assert_cleaned_up(mode: &str, pg_ctl: &Path, data: &Path, pid: &str) {
    let root = data.parent().expect("the cluster directory").to_owned();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stopped = None;
    while Instant::now() < deadline {
        if stopped.is_none() && !alive(pid) && no_server(pg_ctl, data) {
            stopped = Some(Instant::now());
        }
        if stopped.is_some() && !root.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "after the holder ({mode}): postmaster {pid} alive: {}, pg_ctl says no server: {}, {} exists: {}",
        alive(pid),
        no_server(pg_ctl, data),
        root.display(),
        root.exists()
    );
}

#[test]
fn the_cluster_goes_when_the_process_dies() {
    if std::env::var_os(HOLDER_VAR).is_some() {
        return;
    }
    let Some(bin) = testkit::bindir().filter(|_| !testkit::running_as_root()) else {
        if require() && !url_set() {
            panic!("{REQUIRE_VAR}=require, but initdb cannot run here");
        }
        eprintln!("skipping: initdb cannot run here (not found, or running as root)");
        return;
    };
    let pg_ctl = bin.join("pg_ctl");
    for mode in ["panic", "kill"] {
        let (data, pid) = run_holder(mode);
        assert_cleaned_up(mode, &pg_ctl, &data, &pid);
    }
}

/// What follows `name` on `line` (libtest may print "test holder ... "
/// before it).
fn marker<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.find(name).map(|at| line[at + name.len()..].trim())
}
