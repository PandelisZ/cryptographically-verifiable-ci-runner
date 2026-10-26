//! A libSQL server for tests (test-only by contract; hidden from the
//! docs). It is always compiled, with no feature, so this crate's
//! integration tests and vci-cli's can use it without a self
//! dev-dependency.
//!
//! [`server`] finds one once per test process:
//!
//! 1. `VCI_TEST_LIBSQL_URL` (and `VCI_TEST_LIBSQL_TOKEN`), when set: any
//!    server where the token may create tables (CI's service container, a
//!    Turso database).
//! 2. Otherwise a throwaway `sqld` on a free port of 127.0.0.1 (retried up
//!    to five times): `sqld` on `PATH` (Homebrew's `libsql` formula, or the
//!    release binaries), else `turso dev`, else the Docker image
//!    `ghcr.io/tursodatabase/libsql-server` when Docker is running. A
//!    watcher process holds the read end of a pipe that only this process
//!    writes: when this process exits for any reason the pipe closes, and
//!    the watcher stops the server and deletes its directory.
//! 3. Otherwise the test is skipped with a message, or, under
//!    `VCI_TEST_LIBSQL=require`, it panics.
//!
//! Tests share the server and keep apart by namespace
//! ([`namespace`]): each namespace has tables of its own.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use vci_store::OpenContext;
use vci_store::select::{LibsqlMode, Secret, Selection, Source, Sourced};

use crate::LibsqlStore;

/// The environment variable naming a server to use instead of a throwaway
/// one.
pub const URL_VAR: &str = "VCI_TEST_LIBSQL_URL";

/// The token for [`URL_VAR`]'s server.
pub const TOKEN_VAR: &str = "VCI_TEST_LIBSQL_TOKEN";

/// The environment variable that, set to `require`, turns a skip into a
/// panic.
pub const REQUIRE_VAR: &str = "VCI_TEST_LIBSQL";

/// The Docker image tried when there is no `sqld` or `turso` binary (the
/// release CI's service container runs too).
pub const IMAGE: &str = "ghcr.io/tursodatabase/libsql-server:v0.24.32";

const PORT_ATTEMPTS: usize = 5;

static NEXT: AtomicUsize = AtomicUsize::new(0);
static SERVER: OnceLock<Result<Server, String>> = OnceLock::new();

/// The server this process uses.
pub struct Server {
    /// Its URL (`http://127.0.0.1:<port>` for a throwaway one).
    pub url: String,
    /// Its token, if it needs one.
    pub token: Option<String>,
    /// How it was found: `$VCI_TEST_LIBSQL_URL`, `sqld`, `turso dev` or
    /// `docker`.
    pub how: &'static str,
    _process: Option<Process>,
}

/// A throwaway server, stopped and deleted by its watcher when this
/// process exits (or when this value is dropped).
pub struct Process {
    root: PathBuf,
    port: u16,
    _pipe: Mutex<Option<ChildStdin>>,
    child: Mutex<Option<Child>>,
    _watcher: Mutex<Child>,
}

impl Process {
    /// The port it listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// `http://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Its own directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Ok(mut c) = self.child.lock()
            && let Some(mut c) = c.take()
        {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// The server of this test process, or why there is none.
pub fn server() -> Result<&'static Server, &'static str> {
    SERVER
        .get_or_init(find_server)
        .as_ref()
        .map_err(String::as_str)
}

/// Whether a server is available to this test process (starting the
/// throwaway one if it is the one). Panics under `VCI_TEST_LIBSQL=require`
/// when there is none.
pub fn available() -> bool {
    match server() {
        Ok(_) => true,
        Err(why) => {
            skip_or_panic(why);
            false
        }
    }
}

fn skip_or_panic(why: &str) {
    if std::env::var(REQUIRE_VAR).as_deref() == Ok("require") {
        panic!("{REQUIRE_VAR}=require, but there is no libsql server: {why}");
    }
    eprintln!("skipping: no libsql server: {why}");
}

fn find_server() -> Result<Server, String> {
    if let Ok(url) = std::env::var(URL_VAR) {
        let url = url.trim();
        if !url.is_empty() {
            return Ok(Server {
                url: url.to_owned(),
                token: std::env::var(TOKEN_VAR)
                    .ok()
                    .filter(|t| !t.trim().is_empty()),
                how: "$VCI_TEST_LIBSQL_URL",
                _process: None,
            });
        }
    }
    let mut why = Vec::new();
    for (how, start) in [
        (
            "sqld",
            start_sqld as fn(&[String]) -> Result<Process, String>,
        ),
        ("turso dev", start_turso_dev),
        ("docker", start_docker),
    ] {
        match start(&[]) {
            Ok(p) => {
                return Ok(Server {
                    url: p.url(),
                    token: None,
                    how,
                    _process: Some(p),
                });
            }
            Err(e) => why.push(format!("{how}: {e}")),
        }
    }
    Err(why.join("; "))
}

fn free_port() -> Result<u16, String> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("no free port: {e}"))?;
    l.local_addr()
        .map(|a| a.port())
        .map_err(|e| format!("no free port: {e}"))
}

fn on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

fn temp_root(tag: &str) -> Result<PathBuf, String> {
    let root = std::env::temp_dir().join(format!(
        "vci-libsql-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&root).map_err(|e| format!("cannot create {}: {e}", root.display()))?;
    Ok(root)
}

/// A watcher that runs `stop` and deletes `root` once this process's end of
/// its pipe closes.
fn spawn_watcher(stop: &str, root: &Path) -> Result<(ChildStdin, Child), String> {
    let script = format!("trap '' INT HUP\ncat >/dev/null\n{stop}\nrm -rf \"$0\"");
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(script)
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start the server's watcher: {e}"))?;
    let pipe = child
        .stdin
        .take()
        .ok_or_else(|| "the server's watcher has no stdin".to_owned())?;
    Ok((pipe, child))
}

/// Whether the server at `port` answers `GET /health` (or anything over
/// HTTP).
fn answers(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    if s.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 12];
    matches!(s.read(&mut buf), Ok(n) if n >= 12 && buf.starts_with(b"HTTP/1.1 "))
}

/// Start a server with `command` (given the port and the directory), wait
/// until it answers, and set its watcher up.
fn start_process(
    tag: &str,
    command: &dyn Fn(u16, &Path) -> Command,
    stop: &dyn Fn(u32, u16) -> String,
) -> Result<Process, String> {
    let mut errors = Vec::new();
    for _ in 0..PORT_ATTEMPTS {
        let root = temp_root(tag)?;
        let port = free_port()?;
        let log = std::fs::File::create(root.join("server.log"))
            .map_err(|e| format!("cannot create the server's log: {e}"))?;
        let mut cmd = command(port, &root);
        cmd.stdin(Stdio::null())
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&root);
                return Err(format!("cannot start it: {e}"));
            }
        };
        let (pipe, watcher) = spawn_watcher(&stop(child.id(), port), &root)?;
        let until = Instant::now() + Duration::from_secs(60);
        let mut up = false;
        while Instant::now() < until {
            if answers(port) {
                up = true;
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                errors.push(format!(
                    "it exited ({status}): {}",
                    std::fs::read_to_string(root.join("server.log"))
                        .unwrap_or_default()
                        .lines()
                        .rev()
                        .take(3)
                        .collect::<Vec<_>>()
                        .join(" | ")
                ));
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if up {
            return Ok(Process {
                root,
                port,
                _pipe: Mutex::new(Some(pipe)),
                child: Mutex::new(Some(child)),
                _watcher: Mutex::new(watcher),
            });
        }
        let _ = child.kill();
        let _ = child.wait();
        drop(pipe);
        if errors.is_empty() {
            errors.push("it did not answer within 60 s".to_owned());
        }
    }
    Err(errors.join("; "))
}

/// A throwaway `sqld` from `PATH`, with `extra` arguments (an auth key, say).
pub fn start_sqld(extra: &[String]) -> Result<Process, String> {
    let bin = on_path("sqld").ok_or("no sqld on PATH")?;
    let extra = extra.to_vec();
    start_process(
        "sqld",
        &|port, root| {
            let mut c = Command::new(&bin);
            c.arg("--db-path")
                .arg(root.join("data.sqld"))
                .arg("--http-listen-addr")
                .arg(format!("127.0.0.1:{port}"))
                .arg("--no-welcome")
                .args(&extra)
                .current_dir(root);
            c
        },
        &|pid, _| format!("kill -9 {pid} 2>/dev/null"),
    )
}

/// A throwaway `turso dev` from `PATH` (`extra` is ignored).
fn start_turso_dev(_extra: &[String]) -> Result<Process, String> {
    let bin = on_path("turso").ok_or("no turso on PATH")?;
    start_process(
        "turso",
        &|port, root| {
            let mut c = Command::new(&bin);
            c.arg("dev")
                .arg("--port")
                .arg(port.to_string())
                .arg("--db-file")
                .arg(root.join("dev.db"))
                .current_dir(root);
            c
        },
        &|pid, _| format!("kill -9 {pid} 2>/dev/null"),
    )
}

/// A throwaway container of [`IMAGE`] (`extra` is ignored).
fn start_docker(_extra: &[String]) -> Result<Process, String> {
    start_docker_with_env(&[])
}

/// A throwaway container of [`IMAGE`] with these environment variables
/// (`SQLD_AUTH_JWT_KEY`, say), when Docker is running.
pub fn start_docker_with_env(env: &[(&str, &str)]) -> Result<Process, String> {
    let bin = on_path("docker").ok_or("no docker on PATH")?;
    let running = Command::new(&bin)
        .args(["info", "--format", "{{.ServerVersion}}"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !running {
        return Err("Docker is not running".to_owned());
    }
    let name = format!(
        "vci-libsql-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    );
    let stop_name = name.clone();
    let stop_bin = bin.clone();
    start_process(
        "docker",
        &|port, _| {
            let mut c = Command::new(&bin);
            c.args(["run", "--rm", "--name", &name, "-p"])
                .arg(format!("127.0.0.1:{port}:8080"));
            for (k, v) in env {
                c.arg("-e").arg(format!("{k}={v}"));
            }
            c.arg(IMAGE);
            c
        },
        &|_, _| {
            format!(
                "\"{}\" rm -f {stop_name} >/dev/null 2>&1",
                stop_bin.display()
            )
        },
    )
}

/// A namespace no other test of this process uses.
pub fn namespace() -> String {
    format!(
        "t-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

/// An open context for tests (a repository id, four jobs).
pub fn cx() -> OpenContext {
    cx_in("/nonexistent/.git".as_ref(), false)
}

/// An open context whose git common directory is `dir`.
pub fn cx_in(dir: &Path, long_running: bool) -> OpenContext {
    OpenContext {
        repo_root: "/nonexistent".into(),
        git_dir: dir.to_path_buf(),
        git_common_dir: dir.to_path_buf(),
        repo_id: Arc::new(|| Ok("0123456789abcdef0123456789abcdef01234567".to_owned())),
        jobs: 4,
        command: "test".to_owned(),
        long_running,
    }
}

/// A selection of the libsql store in `mode`: at `url` with `token` and
/// namespace `ns` (remote and replica modes), with the file `path` (local
/// and replica modes; absolute or relative to the git common directory),
/// and a connect timeout of 30 s.
pub fn selection(
    mode: LibsqlMode,
    url: Option<&str>,
    token: Option<&str>,
    ns: Option<&str>,
    path: Option<&Path>,
) -> Selection {
    let env = |v: &'static str| Source::Env(v);
    let mut s = Selection::for_backend("libsql");
    s.url = url.map(|u| Sourced {
        value: Secret::new(u),
        source: env("VCI_STORE_URL"),
    });
    s.token = token.map(|t| Sourced {
        value: Secret::opaque(t),
        source: env("VCI_STORE_TOKEN"),
    });
    s.namespace = ns.map(|n| Sourced {
        value: n.to_owned(),
        source: env("VCI_STORE_NAMESPACE"),
    });
    s.libsql.mode = Sourced {
        value: mode,
        source: env("VCI_STORE_URL"),
    };
    s.libsql.path = path.map(|p| Sourced {
        value: p.display().to_string(),
        source: env("VCI_STORE_REPLICA"),
    });
    // The connect timeout also bounds the server's first answer: a test
    // server shared by a hundred concurrent tests on a loaded machine can
    // take longer than the default 5 s. Tests of the bound set their own.
    s.connect_timeout = Sourced {
        value: Duration::from_secs(30),
        source: env("VCI_STORE_CONNECT_TIMEOUT_SECS"),
    };
    s
}

/// A remote store on this process's server in namespace `ns`.
pub fn open_remote(ns: &str) -> Option<LibsqlStore> {
    let s = server().ok()?;
    Some(
        LibsqlStore::open(
            &selection(
                LibsqlMode::Remote,
                Some(&s.url),
                s.token.as_deref(),
                Some(ns),
                None,
            ),
            &cx(),
        )
        .expect("open the remote store"),
    )
}

/// A replica at `path` of namespace `ns` on this process's server.
pub fn open_replica(ns: &str, path: &Path) -> Option<LibsqlStore> {
    let s = server().ok()?;
    Some(
        LibsqlStore::open(
            &selection(
                LibsqlMode::Replica,
                Some(&s.url),
                s.token.as_deref(),
                Some(ns),
                Some(path),
            ),
            &cx(),
        )
        .expect("open the replica"),
    )
}
