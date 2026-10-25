//! A temporary PostgreSQL for tests (test-only by contract; hidden from the
//! docs). It is always compiled, with no feature, so this crate's
//! integration tests and vci-cli's can use it without a self
//! dev-dependency. Beyond `std` and `postgres` it uses only this crate's
//! own [`PgStore`] and vci-store's selection types, for [`PgDb::open`] and
//! [`PgDb::selection`].
//!
//! [`pg`] finds a server once per test process:
//!
//! 1. `VCI_TEST_POSTGRES_URL`, when set: a server where its role may create
//!    schemas, roles and databases (CI's service container).
//! 2. Otherwise a throwaway cluster. `initdb` and `pg_ctl` are looked for in
//!    `VCI_TEST_PG_BINDIR`, then `PATH`, then `pg_config --bindir`, then the
//!    newest of `/usr/lib/postgresql/*/bin`, `/opt/homebrew/opt/postgresql@*/bin`
//!    and `/usr/local/opt/postgresql@*/bin`. The cluster is made with
//!    `initdb -U vci -A trust -E UTF8 --locale=en_US.UTF-8 --no-sync` (or
//!    `--locale=C` when that locale is missing), listens on TCP only on
//!    127.0.0.1 at a free port (retried up to five times), and runs with
//!    `fsync`, `synchronous_commit` and `full_page_writes` off and
//!    `max_connections=300`. A watcher process holds the read end of a pipe
//!    that only this process writes: when this process exits for any reason
//!    (a panic, an abort, SIGKILL) the pipe closes, and the watcher stops
//!    the cluster and deletes its directory. `initdb` refuses to run as
//!    root, so as root there is no throwaway cluster.
//! 3. Otherwise the test is skipped with a message, or, under
//!    `VCI_TEST_POSTGRES=require`, it panics.
//!
//! Each [`PgDb`] is one test's corner of that server: its own schema
//! `vci_t_<pid>_<n>` (created by the first write of a store), plus the roles
//! and databases it made. Dropping it drops them all.

use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use postgres::{Client, NoTls, Row};
use vci_store::OpenContext;
use vci_store::select::{Secret, Selection, Source, Sourced};

use crate::PgStore;

/// The environment variable naming a server to use instead of a
/// throwaway cluster.
pub const URL_VAR: &str = "VCI_TEST_POSTGRES_URL";

/// The environment variable that, set to `require`, turns a skip into a
/// panic.
pub const REQUIRE_VAR: &str = "VCI_TEST_POSTGRES";

/// The environment variable naming the directory that holds `initdb` and
/// `pg_ctl`, searched first.
pub const BINDIR_VAR: &str = "VCI_TEST_PG_BINDIR";

/// The password of every role a test creates.
pub const ROLE_PASSWORD: &str = "vci-test-role-pw";

/// How many times a cluster is started on a fresh port before giving up.
const PORT_ATTEMPTS: usize = 5;

static NEXT: AtomicUsize = AtomicUsize::new(0);
static STARTED: AtomicUsize = AtomicUsize::new(0);
static SERVER: OnceLock<Result<Server, String>> = OnceLock::new();

/// The server this process uses.
struct Server {
    /// The admin URL, with an `sslmode`.
    url: String,
    /// The throwaway cluster, when there is one.
    cluster: Option<Cluster>,
}

/// A throwaway cluster, stopped and deleted by its watcher when this
/// process exits.
struct Cluster {
    /// The cluster's own directory (`data`, `log`, `watcher.log`).
    root: PathBuf,
    port: u16,
    locale: &'static str,
    /// The write end of the watcher's pipe. It is never written and never
    /// closed while this process lives.
    _pipe: Mutex<ChildStdin>,
    _watcher: Mutex<Child>,
}

/// Whether a PostgreSQL server is available to this test process (starting
/// the throwaway cluster if it is the one). Panics under
/// `VCI_TEST_POSTGRES=require` when there is none.
pub fn available() -> bool {
    match server() {
        Ok(_) => true,
        Err(why) => {
            skip_or_panic(why);
            false
        }
    }
}

/// One test's corner of the server, or `None` (the test is skipped, with a
/// message on stderr) when there is no server. Panics under
/// `VCI_TEST_POSTGRES=require` when there is none.
pub fn pg() -> Option<PgDb> {
    let server = match server() {
        Ok(s) => s,
        Err(why) => {
            skip_or_panic(why);
            return None;
        }
    };
    let admin = Client::connect(&server.url, NoTls)
        .unwrap_or_else(|e| panic!("cannot connect to the test PostgreSQL server: {e}"));
    let schema = format!(
        "vci_t_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    );
    Some(PgDb {
        url: server.url.clone(),
        schema,
        admin: Mutex::new(admin),
        roles: Mutex::new(Vec::new()),
        databases: Mutex::new(Vec::new()),
    })
}

/// How many throwaway clusters this process has started (0 or 1).
pub fn clusters_started() -> usize {
    STARTED.load(Ordering::SeqCst)
}

/// The data directory of this process's throwaway cluster, if it uses one.
pub fn cluster_data_dir() -> Option<PathBuf> {
    cluster().map(|c| c.root.join("data"))
}

/// The port of this process's throwaway cluster, if it uses one.
pub fn cluster_port() -> Option<u16> {
    cluster().map(|c| c.port)
}

/// The locale the throwaway cluster was made with (`en_US.UTF-8`, or `C`
/// when that locale is missing), if this process uses one.
pub fn cluster_locale() -> Option<&'static str> {
    cluster().map(|c| c.locale)
}

/// The directory holding `initdb` and `pg_ctl`, searched as the module
/// docs say, without starting anything.
pub fn bindir() -> Option<PathBuf> {
    candidate_bindirs().into_iter().find(|d| has_tools(d))
}

/// Whether this process runs as root (where `initdb` refuses to run).
pub fn running_as_root() -> bool {
    static ROOT: OnceLock<bool> = OnceLock::new();
    *ROOT.get_or_init(|| {
        Command::new("id")
            .arg("-u")
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .is_some_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
    })
}

fn cluster() -> Option<&'static Cluster> {
    SERVER.get()?.as_ref().ok()?.cluster.as_ref()
}

fn server() -> Result<&'static Server, &'static str> {
    SERVER
        .get_or_init(find_server)
        .as_ref()
        .map_err(String::as_str)
}

fn skip_or_panic(why: &str) {
    if std::env::var(REQUIRE_VAR).as_deref() == Ok("require") {
        panic!("{REQUIRE_VAR}=require, but there is no PostgreSQL server: {why}");
    }
    eprintln!("skipping: no PostgreSQL server: {why}");
}

fn find_server() -> Result<Server, String> {
    if let Ok(url) = std::env::var(URL_VAR) {
        let url = url.trim();
        if !url.is_empty() {
            return Ok(Server {
                url: with_sslmode(url),
                cluster: None,
            });
        }
    }
    let cluster = start_cluster()?;
    Ok(Server {
        url: format!(
            "postgres://vci@127.0.0.1:{}/postgres?sslmode=disable",
            cluster.port
        ),
        cluster: Some(cluster),
    })
}

/// `url` with `sslmode=prefer` unless it names one (a CI service container
/// has no TLS, and vci requires it for hosts other than this machine).
fn with_sslmode(url: &str) -> String {
    if url.contains("sslmode=") {
        url.to_owned()
    } else if url.contains('?') {
        format!("{url}&sslmode=prefer")
    } else {
        format!("{url}?sslmode=prefer")
    }
}

fn candidate_bindirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(d) = std::env::var_os(BINDIR_VAR).filter(|d| !d.is_empty()) {
        dirs.push(PathBuf::from(d));
    }
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    if let Ok(o) = Command::new("pg_config")
        .arg("--bindir")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        && o.status.success()
    {
        let d = String::from_utf8_lossy(&o.stdout).trim().to_owned();
        if !d.is_empty() {
            dirs.push(PathBuf::from(d));
        }
    }
    for (parent, prefix, suffix) in [
        ("/usr/lib/postgresql", "", "bin"),
        ("/opt/homebrew/opt", "postgresql@", "bin"),
        ("/usr/local/opt", "postgresql@", "bin"),
    ] {
        let mut found: Vec<(Vec<u64>, PathBuf)> = std::fs::read_dir(parent)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let version = name.strip_prefix(prefix)?;
                let key: Vec<u64> = version
                    .split('.')
                    .map(|p| p.parse().ok())
                    .collect::<Option<_>>()?;
                Some((key, e.path().join(suffix)))
            })
            .collect();
        found.sort();
        dirs.extend(found.into_iter().rev().map(|(_, d)| d));
    }
    dirs
}

fn has_tools(dir: &Path) -> bool {
    dir.join("initdb").is_file() && dir.join("pg_ctl").is_file()
}

fn start_cluster() -> Result<Cluster, String> {
    if running_as_root() {
        return Err(format!(
            "running as root, where initdb refuses to run; set {URL_VAR} to a server"
        ));
    }
    let bin = bindir().ok_or_else(|| {
        format!(
            "no initdb found (looked in {BINDIR_VAR}, PATH, pg_config --bindir and the usual \
             install directories); set {URL_VAR} to a server, or install PostgreSQL"
        )
    })?;
    let root = std::env::temp_dir().join(format!(
        "vci-test-pg-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&root).map_err(|e| format!("cannot create {}: {e}", root.display()))?;
    let data = root.join("data");
    let pg_ctl = bin.join("pg_ctl");

    // The watcher comes first, so that whatever happens from here on, the
    // directory and any server started in it go when this process does.
    let (pipe, watcher) = spawn_watcher(&pg_ctl, &data, &root)?;
    STARTED.fetch_add(1, Ordering::SeqCst);

    let locale = initdb(&bin, &data, &root)?;
    let conf = "\n# vci testkit\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = ''\n\
                fsync = off\nsynchronous_commit = off\nfull_page_writes = off\n\
                max_connections = 300\n";
    append(&data.join("postgresql.conf"), conf)?;

    let mut last = String::new();
    for _ in 0..PORT_ATTEMPTS {
        let port = free_port()?;
        match start(&pg_ctl, &data, &root, port, locale) {
            Ok(()) => {
                return Ok(Cluster {
                    root,
                    port,
                    locale,
                    _pipe: Mutex::new(pipe),
                    _watcher: Mutex::new(watcher),
                });
            }
            Err(e) => last = e,
        }
    }
    Err(format!(
        "the throwaway cluster did not start on {PORT_ATTEMPTS} ports: {last}"
    ))
}

/// A process that waits for the end of its stdin (this process's exit),
/// then stops the cluster at `data` and deletes `root`. It runs in its own
/// process group and ignores SIGINT and SIGHUP, so a Ctrl-C to the test run
/// reaches only the test process, whose exit then sets the watcher off.
fn spawn_watcher(pg_ctl: &Path, data: &Path, root: &Path) -> Result<(ChildStdin, Child), String> {
    let script = r#"trap '' INT HUP
cat >/dev/null
"$0" -D "$1" stop -m immediate -w -t 30 >/dev/null 2>&1
rm -rf "$2""#;
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(script)
        .arg(pg_ctl)
        .arg(data)
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start the cluster's watcher: {e}"))?;
    let pipe = child
        .stdin
        .take()
        .ok_or_else(|| "the cluster's watcher has no stdin".to_owned())?;
    Ok((pipe, child))
}

/// Runs initdb in `data`, with en_US.UTF-8 or else C; the locale used.
fn initdb(bin: &Path, data: &Path, root: &Path) -> Result<&'static str, String> {
    let mut errors = Vec::new();
    for locale in ["en_US.UTF-8", "C"] {
        let _ = std::fs::remove_dir_all(data);
        let out = Command::new(bin.join("initdb"))
            .arg("-D")
            .arg(data)
            .args(["-U", "vci", "-A", "trust", "-E", "UTF8", "--no-sync"])
            .arg(format!("--locale={locale}"))
            .env("LC_ALL", locale)
            .current_dir(root)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run initdb: {e}"))?;
        if out.status.success() {
            return Ok(locale);
        }
        errors.push(format!(
            "initdb --locale={locale}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Err(errors.join("; "))
}

/// Starts the cluster on `port`, waiting until it accepts connections.
fn start(pg_ctl: &Path, data: &Path, root: &Path, port: u16, locale: &str) -> Result<(), String> {
    let log = root.join("log");
    // LC_ALL: on macOS the postmaster refuses to start ("became
    // multithreaded during startup") without a locale in its environment.
    let status = Command::new(pg_ctl)
        .arg("-D")
        .arg(data)
        .arg("-l")
        .arg(&log)
        .args(["-w", "-t", "60", "-o"])
        .arg(format!("-p {port}"))
        .arg("start")
        .env("LC_ALL", locale)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("cannot run pg_ctl: {e}"))?;
    if status.success() {
        return Ok(());
    }
    // A failed start may leave a postmaster behind (a timeout): stop it
    // before the next port is tried.
    let _ = Command::new(pg_ctl)
        .arg("-D")
        .arg(data)
        .args(["stop", "-m", "immediate", "-w"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let tail = std::fs::read_to_string(&log).unwrap_or_default();
    let tail: Vec<&str> = tail.lines().rev().take(5).collect();
    Err(format!(
        "pg_ctl start on port {port}: {status}; log: {}",
        tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
    ))
}

fn free_port() -> Result<u16, String> {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("cannot find a free port: {e}"))?;
    l.local_addr()
        .map(|a| a.port())
        .map_err(|e| format!("cannot find a free port: {e}"))
}

fn append(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// One test's corner of the server: its own schema, plus the roles and
/// databases it made, all dropped when it is.
pub struct PgDb {
    /// The server, as the tests' admin role, with an `sslmode`.
    pub url: String,
    /// This test's schema (not created until a store writes).
    pub schema: String,
    admin: Mutex<Client>,
    roles: Mutex<Vec<String>>,
    databases: Mutex<Vec<String>>,
}

impl std::fmt::Debug for PgDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgDb")
            .field("url", &self.url)
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

/// `url` with this user and password.
pub fn with_user(url: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("a postgres:// URL");
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    format!("{scheme}://{user}:{password}@{host}{tail}")
}

/// `url` naming this database.
pub fn with_database(url: &str, db: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("a postgres:// URL");
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let query = tail.split_once('?').map_or("", |(_, q)| q);
    if query.is_empty() {
        format!("{scheme}://{authority}/{db}")
    } else {
        format!("{scheme}://{authority}/{db}?{query}")
    }
}

/// An open context for tests: command `test`, a fixed repository id.
pub fn cx() -> OpenContext {
    cx_for("test", false)
}

/// An open context naming `command`.
pub fn cx_for(command: &str, long_running: bool) -> OpenContext {
    OpenContext {
        repo_root: "/nonexistent".into(),
        git_dir: "/nonexistent/.git".into(),
        git_common_dir: "/nonexistent/.git".into(),
        repo_id: Arc::new(|| Ok("0123456789abcdef0123456789abcdef01234567".to_owned())),
        jobs: 4,
        command: command.to_owned(),
        long_running,
    }
}

/// A selection of the postgres store at `url`, in `schema`, namespace `ns`.
pub fn selection(url: &str, schema: &str, ns: &str) -> Selection {
    let mut s = Selection::for_backend("postgres");
    s.url = Some(Sourced {
        value: Secret::new(url),
        source: Source::Env("VCI_STORE_URL"),
    });
    s.postgres.schema = Sourced {
        value: schema.to_owned(),
        source: Source::File,
    };
    s.namespace = Some(Sourced {
        value: ns.to_owned(),
        source: Source::Env("VCI_STORE_NAMESPACE"),
    });
    s
}

impl PgDb {
    fn admin(&self) -> MutexGuard<'_, Client> {
        self.admin.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// This test's selection (namespace `test`).
    pub fn selection(&self) -> Selection {
        selection(&self.url, &self.schema, "test")
    }

    /// A new handle on this test's store.
    pub fn open(&self) -> PgStore {
        self.open_with(|_| {})
    }

    /// A new handle on this test's store, with its selection changed by `f`.
    pub fn open_with(&self, f: impl FnOnce(&mut Selection)) -> PgStore {
        let mut s = self.selection();
        f(&mut s);
        PgStore::open(&s, &cx()).expect("open the store")
    }

    /// A new handle as another role (`url` from [`PgDb::role`]).
    pub fn open_as(&self, url: &str) -> PgStore {
        PgStore::open(&selection(url, &self.schema, "test"), &cx()).expect("open the store")
    }

    /// Run SQL as the admin role (`{schema}` names this test's schema).
    pub fn sql(&self, sql: &str) {
        let sql = sql.replace("{schema}", &self.schema);
        self.admin()
            .batch_execute(&sql)
            .unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    }

    /// Query as the admin role (`{schema}` names this test's schema).
    pub fn query(&self, sql: &str) -> Vec<Row> {
        let sql = sql.replace("{schema}", &self.schema);
        self.admin()
            .query(sql.as_str(), &[])
            .unwrap_or_else(|e| panic!("{sql}: {e:?}"))
    }

    /// One `bigint` (or `count(*)`) answer.
    pub fn count(&self, sql: &str) -> i64 {
        self.query(sql)[0].get(0)
    }

    /// Whether this test's schema exists.
    pub fn schema_exists(&self) -> bool {
        self.count("SELECT count(*) FROM pg_namespace WHERE nspname = '{schema}'") == 1
    }

    /// A login role `<schema>_<suffix>` granted `grants` (`{role}` and
    /// `{schema}` are filled in); its URL.
    pub fn role(&self, suffix: &str, grants: &str) -> String {
        let role = format!("{}_{suffix}", self.schema);
        self.sql(&format!(
            "CREATE ROLE \"{role}\" LOGIN PASSWORD '{ROLE_PASSWORD}'"
        ));
        self.roles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(role.clone());
        if !grants.is_empty() {
            self.sql(&grants.replace("{role}", &format!("\"{role}\"")));
        }
        with_user(&self.url, &role, ROLE_PASSWORD)
    }

    /// A database `<schema>_<suffix>` made with `options`; its URL, or the
    /// server's error.
    pub fn database(&self, suffix: &str, options: &str) -> Result<String, String> {
        let name = format!("{}_{suffix}", self.schema);
        self.admin()
            .batch_execute(&format!("CREATE DATABASE \"{name}\" {options}"))
            .map_err(|e| format!("{e:?}"))?;
        self.databases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(name.clone());
        Ok(with_database(&self.url, &name))
    }
}

impl Drop for PgDb {
    fn drop(&mut self) {
        // Let the handles' connections close first.
        std::thread::sleep(Duration::from_millis(20));
        let mut admin = self.admin();
        let _ = admin.batch_execute(&format!(
            "DROP SCHEMA IF EXISTS \"{}\" CASCADE",
            self.schema
        ));
        for d in self
            .databases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            let _ = admin.batch_execute(&format!("DROP DATABASE IF EXISTS \"{d}\" WITH (FORCE)"));
        }
        for r in self
            .roles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            let _ = admin.batch_execute(&format!(
                "DROP OWNED BY \"{r}\" CASCADE; DROP ROLE IF EXISTS \"{r}\""
            ));
        }
    }
}
