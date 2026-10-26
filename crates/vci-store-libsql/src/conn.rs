//! Talking to a libSQL server (`docs/STORE-BACKENDS.md` section 18): the URL
//! and its token, the TLS connector, the runtime, the pool of connections,
//! the circuit breaker, deadlines, and what an error means.
//!
//! * **The URL** comes only from `VCI_STORE_URL`: `libsql://` (HTTPS, or
//!   HTTP with `?tls=0`), `https://` or `http://`, a host, an optional port
//!   and path, and an optional `authToken` query parameter. A user or
//!   password in it, a fragment, or another query parameter is refused,
//!   without printing it or the parameter's name. The token is
//!   `VCI_STORE_TOKEN`, else `authToken`. Messages show the scheme, host
//!   and port only: a path is shown as `/<path>` (a token could be written
//!   there).
//! * **TLS** is rustls with the `ring` provider and the webpki roots, on the
//!   workspace's one rustls (libsql's own `tls` feature would bring a second).
//! * **Bounded time.** Each connection (TCP and TLS) is given up after the
//!   connect timeout. A handle's first request is always the description
//!   of a statement (a small request, see [`Conn::query`]): until the
//!   server has answered one, it is given up after the connect timeout
//!   too, so a server that accepts and never answers (or answers too
//!   slowly to be used) costs the connect timeout, not the request
//!   timeout. Every other request is given up after the request timeout.
//!   The first failure to reach the server, and the first deadline that
//!   runs out, latch the circuit breaker: every later call of the handle
//!   fails at once.
//! * **Requests.** A read is one prepared statement (the server describes a
//!   statement once per pooled connection; the description is kept) whose
//!   rows come back in one request. A write is one transactional batch: its
//!   statements, values written as literals, travel in one request and
//!   apply atomically. A statement the server refuses is
//!   [`StoreError::Backend`] (or `Unsupported` for a record larger than the
//!   server takes) and latches nothing.
//! * **Panics.** libsql 0.10.0 panics on an HTTP error whose body is not
//!   UTF-8 text; every call into it is guarded (see [`guarded`]): such a
//!   panic is a latched `Unavailable`, and prints nothing.
//! * **Secrets.** Every message passes through [`Conn::scrub`], which
//!   removes the URL's token and `VCI_STORE_TOKEN`; the location never
//!   holds either.

use std::cell::Cell;
use std::collections::HashMap;
use std::error::Error as _;
use std::fmt::Write as _;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Once, OnceLock, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use hyper::client::HttpConnector;
use hyper::client::connect::{Connected, Connection};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use vci_store::StoreError;
use vci_store::select::Secret;

/// The backend's name ([`vci_store::AttestationStore::kind`]).
pub(crate) const KIND: &str = "libsql";

/// The request timeout of a long-running command (`vci prune`).
pub(crate) const LONG_RUNNING_TIMEOUT: Duration = Duration::from_secs(600);

/// The largest record vci sends a server: `sqld` refuses a row (and any
/// one value) of 5,000,000 bytes or more ("string or blob too big", its
/// `SQLITE_LIMIT_LENGTH`).
pub(crate) const MAX_RECORD: usize = 5_000_000;

/// What a record of [`MAX_RECORD`] bytes or more is refused as
/// ([`StoreError::Unsupported`]).
pub(crate) const TOO_BIG: &str = "storing a record of 5,000,000 bytes or more on a server (a libsql server's limit: a unit whose attestation or input manifest is that large is not attested)";

/// What a record the server refused as too big is.
const TOO_BIG_REFUSED: &str =
    "storing a record this large on this server (it refused it as too big)";

/// The most connections one handle opens.
const MAX_POOL: usize = 4;

/// The error of a libSQL request that is not a store error of its own
/// kind (a statement the server refused for a reason vci does not know),
/// with every secret removed: the payload of [`StoreError::Backend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsqlError {
    message: String,
}

impl LibsqlError {
    pub(crate) fn from_text(message: String) -> LibsqlError {
        LibsqlError { message }
    }

    /// The message (scrubbed).
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for LibsqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{KIND} store: {}", self.message)
    }
}

impl std::error::Error for LibsqlError {}

// ---- the URL ----------------------------------------------------------------------

/// Where the server is, parsed from `VCI_STORE_URL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// What the client connects to: `https://` or `http://`, the host and
    /// port, the path; no query.
    pub(crate) url: String,
    /// For messages and `vci store info`: the scheme as written, the host
    /// and port, and `/<path>` for a path; never the path itself (a token
    /// could be written there), a query or a credential.
    pub(crate) display: String,
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(hex) = std::str::from_utf8(&b[i + 1..i + 3])
            && let Ok(v) = u8::from_str_radix(hex, 16)
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn config(m: impl Into<String>) -> StoreError {
    StoreError::Config(m.into())
}

impl Target {
    /// Parse `url` (the secret `VCI_STORE_URL`), and pick the token:
    /// `env_token` (`VCI_STORE_TOKEN`), else the URL's `authToken`. Errors
    /// never quote the URL.
    pub(crate) fn parse(
        url: &Secret,
        env_token: Option<&Secret>,
    ) -> Result<(Target, Option<Secret>), StoreError> {
        let s = url.expose().trim();
        let not_printed = "(it was not printed)";
        let Some((scheme, rest)) = s.split_once("://") else {
            return Err(config(format!(
                "$VCI_STORE_URL is not a libsql server: expected libsql://<database>, https://<host> or http://<host> {not_printed}"
            )));
        };
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "libsql" | "https" | "http") {
            return Err(config(format!(
                "$VCI_STORE_URL is not a libsql server: expected libsql://, https:// or http:// {not_printed}"
            )));
        }
        if rest.contains('#') {
            return Err(config(format!(
                "$VCI_STORE_URL must not have a #fragment {not_printed}"
            )));
        }
        let (before_query, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (authority, path) =
            before_query.split_at(before_query.find('/').unwrap_or(before_query.len()));
        if authority.contains('@') {
            return Err(config(format!(
                "$VCI_STORE_URL must not carry a user or password: pass the database token in $VCI_STORE_TOKEN {not_printed}"
            )));
        }
        let host_ok = !authority.is_empty()
            && authority
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:[]_".contains(&b));
        if !host_ok {
            return Err(config(format!(
                "$VCI_STORE_URL needs a host name (letters, digits, `.`, `-`, `_`, a :port) {not_printed}"
            )));
        }
        let path_ok = path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._~-".contains(&b));
        if !path_ok {
            return Err(config(format!(
                "$VCI_STORE_URL has a path vci does not accept (letters, digits, `/`, `.`, `_`, `~`, `-`) {not_printed}"
            )));
        }
        let path = path.trim_end_matches('/');
        let mut tls: Option<bool> = None;
        let mut query_token = None;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let k = percent_decode(k);
            match k.to_ascii_lowercase().as_str() {
                "authtoken" | "auth_token" => query_token = Some(Secret::opaque(percent_decode(v))),
                "tls" => {
                    tls = Some(match v {
                        "0" | "false" => false,
                        "1" | "true" => true,
                        _ => {
                            return Err(config("$VCI_STORE_URL: tls must be 0 or 1".to_owned()));
                        }
                    })
                }
                _ => {
                    // Neither the parameter nor its name is printed: a
                    // token may be either (`?<token>`, `?token=<token>`).
                    return Err(config(format!(
                        "$VCI_STORE_URL has a query parameter vci does not know (a libsql URL takes authToken and tls; the token belongs in $VCI_STORE_TOKEN) {not_printed}"
                    )));
                }
            }
        }
        let connect_scheme = match (scheme.as_str(), tls) {
            ("libsql", Some(false)) => "http",
            ("libsql", _) => "https",
            ("https", Some(false)) => {
                return Err(config(
                    "$VCI_STORE_URL: an https:// URL with tls=0 (use http://)".to_owned(),
                ));
            }
            ("http", Some(true)) => {
                return Err(config(
                    "$VCI_STORE_URL: an http:// URL with tls=1 (use https://)".to_owned(),
                ));
            }
            (s, _) => {
                if s == "https" {
                    "https"
                } else {
                    "http"
                }
            }
        };
        let token = env_token
            .cloned()
            .or(query_token)
            .filter(|t| !t.expose().is_empty());
        let shown_path = if path.is_empty() { "" } else { "/<path>" };
        Ok((
            Target {
                url: format!("{connect_scheme}://{authority}{path}"),
                display: format!("{scheme}://{authority}{shown_path}"),
            },
            token,
        ))
    }
}

// ---- TLS and the connector ----------------------------------------------------------

/// rustls with the `ring` provider and the webpki roots, speaking HTTP/1.1.
fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A TCP connection, with TLS for `https://`.
pub(crate) enum Socket {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Socket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Socket::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Socket::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Socket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Socket::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Socket::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Socket::Plain(s) => Pin::new(s).poll_flush(cx),
            Socket::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Socket::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Socket::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

impl Connection for Socket {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Makes the client's connections: TCP (`TCP_NODELAY`), then TLS for
/// `https://`, the whole given up after the connect timeout.
#[derive(Clone)]
pub(crate) struct Connector {
    http: HttpConnector,
    tls: Option<tokio_rustls::TlsConnector>,
    timeout: Duration,
}

impl Connector {
    fn new(tls: Option<Arc<rustls::ClientConfig>>, timeout: Duration) -> Connector {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        http.set_connect_timeout(Some(timeout));
        Connector {
            http,
            tls: tls.map(tokio_rustls::TlsConnector::from),
            timeout,
        }
    }
}

impl tower_service::Service<http::Uri> for Connector {
    type Response = Socket;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Socket, BoxError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let mut http = self.http.clone();
        let tls = self.tls.clone();
        let timeout = self.timeout;
        Box::pin(async move {
            let connect = async move {
                let https = uri.scheme_str() == Some("https");
                let host = uri
                    .host()
                    .ok_or("the URL has no host")?
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned();
                let tcp = tower_service::Service::call(&mut http, uri).await?;
                if !https {
                    return Ok::<Socket, BoxError>(Socket::Plain(tcp));
                }
                let tls = tls.ok_or("TLS is not set up")?;
                let name = rustls::pki_types::ServerName::try_from(host)?;
                Ok(Socket::Tls(Box::new(tls.connect(name, tcp).await?)))
            };
            match tokio::time::timeout(timeout, connect).await {
                Ok(r) => r,
                Err(_) => Err(format!("connecting timed out after {timeout:?}").into()),
            }
        })
    }
}

// ---- what a failure means ---------------------------------------------------------

/// What a request is, for the words of its errors.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Op {
    /// The operation a privilege error names ("read", "write").
    pub(crate) verb: &'static str,
}

pub(crate) const READ: Op = Op { verb: "read" };
pub(crate) const WRITE: Op = Op { verb: "write" };

/// Why a call failed: the tables are not there (reads answer as an empty
/// store), or a store error.
#[derive(Debug)]
pub(crate) enum Fail {
    Absent,
    Store(StoreError),
}

impl From<StoreError> for Fail {
    fn from(e: StoreError) -> Self {
        Fail::Store(e)
    }
}

impl Fail {
    /// `absent` when the tables are not there, else the error.
    pub(crate) fn or_absent<T>(
        r: Result<T, Fail>,
        absent: impl FnOnce() -> T,
    ) -> Result<T, StoreError> {
        match r {
            Ok(v) => Ok(v),
            Err(Fail::Absent) => Ok(absent()),
            Err(Fail::Store(e)) => Err(e),
        }
    }
}

/// A failure, and whether it latches the breaker and loses the connection.
struct Class {
    fail: Fail,
    latch: bool,
    lost: bool,
    /// Another writer holds the database, the server is out of
    /// connections, or it interrupted the statement to let a writer in:
    /// tried again until the request's deadline.
    busy: bool,
    /// The server no longer knows the connection's stream (it expired):
    /// tried again once on a new stream.
    stale: bool,
}

impl Class {
    fn fail(fail: Fail, latch: bool, lost: bool) -> Class {
        Class {
            fail,
            latch,
            lost,
            busy: false,
            stale: false,
        }
    }
}

/// How long a connection's server stream may sit idle before the next call
/// starts a new one (servers expire idle streams after about ten seconds).
const STREAM_IDLE: Duration = Duration::from_secs(4);

// ---- panics in the client ---------------------------------------------------------

thread_local! {
    /// How many guarded calls into libsql this thread is in.
    static QUIET: Cell<u32> = const { Cell::new(0) };
}

/// Run `f`, a call into libsql, catching a panic in it. libsql 0.10.0
/// panics on an HTTP error whose body is not UTF-8 text (`String::from_utf8
/// (..).unwrap()` in its `hrana/hyper.rs`), as a proxy's Latin-1 error page
/// is; its message would print the body. The panic hook installed here
/// (once, wrapping the one it replaces) prints nothing for a panic on a
/// thread inside such a call, and hands every other panic on.
fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, ()> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if QUIET.try_with(Cell::get).unwrap_or(0) == 0 {
                previous(info);
            }
        }));
    });
    QUIET.with(|q| q.set(q.get() + 1));
    let r = std::panic::catch_unwind(AssertUnwindSafe(f));
    QUIET.with(|q| q.set(q.get().saturating_sub(1)));
    r.map_err(drop)
}

/// The marker of a first request the server did not answer within the
/// connect timeout (see [`Conn::query`]).
const NO_FIRST_ANSWER: &str = "vci: no first answer within the connect timeout";

/// What a panic in the client means.
const CLIENT_PANICKED: &str = "the libsql client failed on the server's answer (an error response it cannot read: a body that is not UTF-8 text)";

// ---- the pool and the breaker ----------------------------------------------------

/// One connection of the pool, with the statements it prepared (the
/// server described them once).
pub(crate) struct Pooled {
    conn: libsql::Connection,
    stmts: HashMap<String, libsql::Statement>,
    /// When its stream was last used.
    used: Instant,
}

struct Pool {
    idle: Vec<Pooled>,
    open: usize,
}

/// The connections of one store handle.
pub(crate) struct Conn {
    target: Target,
    /// `VCI_STORE_URL`, for scrubbing (its `authToken` included).
    url: Secret,
    token: Option<Secret>,
    connect_timeout: Duration,
    timeout: Duration,
    runtime: OnceLock<Result<tokio::runtime::Runtime, String>>,
    db: OnceLock<Result<libsql::Database, String>>,
    pool: Mutex<Pool>,
    freed: Condvar,
    max: usize,
    broken: OnceLock<String>,
    requests: AtomicU64,
    /// Requests sent again (the server was busy, or had dropped the
    /// stream), counted in `requests` too.
    retries: AtomicU64,
    /// The server has answered a request of this handle: later requests
    /// get the request timeout, not the connect timeout.
    answered: AtomicBool,
}

impl Conn {
    pub(crate) fn new(
        target: Target,
        url: Secret,
        token: Option<Secret>,
        connect_timeout: Duration,
        timeout: Duration,
        jobs: usize,
    ) -> Conn {
        Conn {
            target,
            url,
            token,
            connect_timeout,
            timeout,
            runtime: OnceLock::new(),
            db: OnceLock::new(),
            pool: Mutex::new(Pool {
                idle: Vec::new(),
                open: 0,
            }),
            freed: Condvar::new(),
            max: jobs.clamp(1, MAX_POOL),
            broken: OnceLock::new(),
            requests: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            answered: AtomicBool::new(false),
        }
    }

    pub(crate) fn display(&self) -> &str {
        &self.target.display
    }

    /// HTTP requests sent so far (a statement's first description on a
    /// connection included).
    pub(crate) fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// Of [`Conn::requests`], those sent again because the server was busy
    /// (another writer held the database) or had dropped the stream.
    pub(crate) fn retries(&self) -> u64 {
        self.retries.load(Ordering::Relaxed)
    }

    /// Whether the server has answered a request of this handle.
    pub(crate) fn answered(&self) -> bool {
        self.answered.load(Ordering::Relaxed)
    }

    /// `text` without the URL's token or `VCI_STORE_TOKEN`.
    pub(crate) fn scrub(&self, text: &str) -> String {
        let mut out = self.url.scrub(text);
        if let Some(t) = &self.token {
            out = t.scrub(&out);
        }
        out
    }

    fn lock_pool(&self) -> MutexGuard<'_, Pool> {
        self.pool.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The circuit breaker: after the first failure to reach the server or
    /// a deadline that ran out, every call of this handle fails at once.
    pub(crate) fn check(&self) -> Result<(), StoreError> {
        match self.broken.get() {
            Some(d) => Err(StoreError::unavailable(
                KIND,
                format!("{d} (failed earlier in this process; not retried)"),
            )),
            None => Ok(()),
        }
    }

    fn latch(&self, e: StoreError) -> StoreError {
        let detail = match &e {
            StoreError::Unavailable { detail, .. } => Some(detail.clone()),
            StoreError::Timeout {
                operation, after, ..
            } => Some(format!("{operation} timed out after {after:?}")),
            _ => None,
        };
        if let Some(d) = detail {
            let _ = self.broken.set(d);
        }
        e
    }

    fn runtime(&self) -> Result<&tokio::runtime::Runtime, StoreError> {
        let r = self.runtime.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|e| format!("cannot start the client's runtime: {e}"))
        });
        r.as_ref()
            .map_err(|e| StoreError::unavailable(KIND, e.clone()))
    }

    fn database(&self) -> Result<&libsql::Database, StoreError> {
        let r = self.db.get_or_init(|| {
            let tls = if self.target.url.starts_with("https://") {
                Some(tls_config()?)
            } else {
                None
            };
            let connector = Connector::new(tls, self.connect_timeout);
            let token = self
                .token
                .as_ref()
                .map(|t| t.expose().to_owned())
                .unwrap_or_default();
            let rt = self.runtime().map_err(|e| e.to_string())?;
            guarded(|| {
                rt.block_on(
                    libsql::Builder::new_remote(self.target.url.clone(), token)
                        .connector(connector)
                        .build(),
                )
            })
            .map_err(|()| CLIENT_PANICKED.to_owned())?
            .map_err(|e| self.scrub(&e.to_string()))
        });
        r.as_ref().map_err(|e| {
            StoreError::Config(format!("$VCI_STORE_URL ({}): {e}", self.target.display))
        })
    }

    /// A connection from the pool, a new one when none is idle and the pool
    /// is not full; waiting at most the connect timeout otherwise.
    fn checkout(&self) -> Result<Pooled, StoreError> {
        self.check()?;
        let db = self.database()?;
        let deadline = Instant::now() + self.connect_timeout;
        let mut p = self.lock_pool();
        loop {
            if let Some(c) = p.idle.pop() {
                return Ok(c);
            }
            if p.open < self.max {
                p.open += 1;
                drop(p);
                let connected = guarded(|| db.connect()).unwrap_or_else(|()| {
                    Err(libsql::Error::ConnectionFailed(CLIENT_PANICKED.to_owned()))
                });
                return match connected {
                    Ok(conn) => Ok(Pooled {
                        conn,
                        stmts: HashMap::new(),
                        used: Instant::now(),
                    }),
                    Err(e) => {
                        self.give_back(None);
                        Err(StoreError::unavailable(
                            KIND,
                            format!(
                                "cannot connect to {}: {}",
                                self.target.display,
                                self.scrub(&e.to_string())
                            ),
                        ))
                    }
                };
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(StoreError::Timeout {
                    backend: KIND,
                    operation: "a connection from the pool",
                    after: self.connect_timeout,
                });
            }
            p = self
                .freed
                .wait_timeout(p, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
            self.check()?;
        }
    }

    /// Put `c` back (`None`: it was lost).
    fn give_back(&self, c: Option<Pooled>) {
        let mut p = self.lock_pool();
        match c {
            Some(c) => p.idle.push(c),
            None => p.open = p.open.saturating_sub(1),
        }
        drop(p);
        self.freed.notify_one();
    }

    fn classify(&self, e: &libsql::Error, op: Op) -> Class {
        let mut text = e.to_string();
        let mut src = e.source();
        while let Some(s) = src {
            let more = s.to_string();
            if !text.contains(&more) {
                let _ = write!(text, ": {more}");
            }
            src = s.source();
        }
        let text = self.scrub(&text);
        let lower = text.to_ascii_lowercase();
        let unavailable = |detail: String, latch: bool, lost: bool| {
            Class::fail(
                Fail::Store(StoreError::unavailable(KIND, detail)),
                latch,
                lost,
            )
        };
        let at = &self.target.display;
        if text.contains(NO_FIRST_ANSWER) {
            return Class::fail(
                Fail::Store(StoreError::Timeout {
                    backend: KIND,
                    operation: "the server's first answer",
                    after: self.first_answer_timeout(),
                }),
                true,
                true,
            );
        }
        if lower.contains("no such table") {
            return Class::fail(Fail::Absent, false, false);
        }
        // A busy server: another writer holds the database, no connection
        // is free, it gave up a transaction that waited too long, or it
        // interrupted a statement to let a writer in (`sqld` rolls the
        // transaction back: the whole batch is sent again).
        if lower.contains("database is locked")
            || lower.contains("sqlite_busy")
            || lower.contains("status=429")
            || lower.contains("timed out while opening database connection")
            || lower.contains("transaction timed out")
            || lower.contains("sqlite_interrupt")
            || lower.contains("error: interrupted")
        {
            return Class {
                busy: true,
                ..Class::fail(
                    Fail::Store(StoreError::Timeout {
                        backend: KIND,
                        operation: "waiting for another writer",
                        after: self.timeout,
                    }),
                    false,
                    false,
                )
            };
        }
        // The server no longer knows the stream (it expired, or a refused
        // request closed it): its baton is invalid.
        if lower.contains("baton")
            || (lower.contains("stream")
                && (lower.contains("expired") || lower.contains("not found")))
        {
            return Class {
                stale: true,
                ..unavailable(format!("{at}: {text}"), false, true)
            };
        }
        // A record (a row, or one value) larger than the server takes:
        // `sqld` keeps rows under 5,000,000 bytes (SQLITE_LIMIT_LENGTH).
        // `batch` refuses such a record before sending it; this is a server
        // whose limit is lower. The server works: nothing is latched.
        if lower.contains("string or blob too big") {
            return Class::fail(
                Fail::Store(StoreError::Unsupported {
                    backend: KIND,
                    operation: TOO_BIG_REFUSED,
                }),
                false,
                true,
            );
        }
        if lower.contains("http error") || matches!(e, libsql::Error::ConnectionFailed(_)) {
            return unavailable(format!("cannot reach {at}: {text}"), true, true);
        }
        if lower.contains("status=403") && op.verb == WRITE.verb {
            // A token that may read but not write (a Turso read-only token):
            // this write is refused, and reads go on, on another stream (the
            // server closed this one).
            return Class::fail(
                Fail::Store(StoreError::Denied {
                    backend: KIND,
                    operation: op.verb,
                    detail: format!("{at}: the token may not write ({text})"),
                }),
                false,
                true,
            );
        }
        if lower.contains("status=401") || lower.contains("status=403") {
            let why = if self.token.is_some() {
                "the server refused the token in $VCI_STORE_TOKEN or the URL's authToken"
            } else {
                "the server asks for a token: set $VCI_STORE_TOKEN"
            };
            return unavailable(format!("{at}: {why} ({text})"), true, false);
        }
        if lower.contains("status=404") {
            return unavailable(
                format!("{at}: no libsql database there (HTTP 404)"),
                true,
                false,
            );
        }
        if lower.contains("readonly")
            || lower.contains("read-only")
            || lower.contains("read only")
            || lower.contains("not authorized")
            || lower.contains("forbidden")
            || lower.contains("permission")
            || lower.contains("auth_")
        {
            return Class::fail(
                Fail::Store(StoreError::Denied {
                    backend: KIND,
                    operation: op.verb,
                    detail: text,
                }),
                false,
                false,
            );
        }
        if lower.contains("api error") && lower.contains("status=") {
            // Another HTTP error status (a 5xx, a proxy's page).
            return unavailable(format!("{at}: {text}"), true, false);
        }
        if lower.contains("api error") || lower.contains("error at step") {
            // A statement the server refused (a batch step's error comes as
            // an API error, a cursor step's as `error at step`): the server
            // works, so nothing is latched, and the transaction it was in
            // was rolled back. The stream is given up, to be safe.
            return Class::fail(
                Fail::Store(StoreError::backend(LibsqlError {
                    message: format!("{at}: the server refused a statement: {text}"),
                })),
                false,
                true,
            );
        }
        if lower.contains("stream closed")
            || lower.contains("unexpected response")
            || lower.contains("json error")
            || lower.contains("cursor")
        {
            return unavailable(format!("{at}: {text}"), false, true);
        }
        Class::fail(
            Fail::Store(StoreError::backend(LibsqlError { message: text })),
            false,
            false,
        )
    }

    /// The longest wait for the server's first answer.
    fn first_answer_timeout(&self) -> Duration {
        self.timeout.min(self.connect_timeout)
    }

    /// Run `f` on a pooled connection on the runtime, within the request
    /// timeout; with `bounded_first`, within the connect timeout until the
    /// server has answered once (a request whose first part is not
    /// bounded on its own). A connection whose server stream sat idle
    /// starts a new one (servers expire idle streams). While another writer
    /// holds the database (or the server has no connection free), `f` is
    /// tried again with growing pauses until the deadline; a stream the
    /// server no longer knows is replaced once. A panic in the client is a
    /// latched `Unavailable`.
    fn run<T, F>(&self, op: Op, bounded_first: bool, mut f: F) -> Result<T, Fail>
    where
        F: for<'a> FnMut(
            &'a mut Pooled,
            &'a AtomicU64,
            &'a AtomicBool,
        ) -> Pin<Box<dyn Future<Output = libsql::Result<T>> + 'a>>,
    {
        let rt = self.runtime()?;
        let mut c = self.checkout()?;
        // A server that accepts and never answers (a frozen server, a
        // stuck proxy) costs the connect timeout, not the request timeout.
        let (timeout, operation) = if bounded_first && !self.answered() {
            (self.first_answer_timeout(), "the server's first answer")
        } else {
            (self.timeout, "a request")
        };
        let deadline = Instant::now() + timeout;
        let mut pause = Duration::from_millis(10);
        let mut renewed = false;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let fresh = c.used.elapsed() > STREAM_IDLE;
            // This attempt's requests (other threads send theirs at once).
            let sent = AtomicU64::new(0);
            let r = guarded(|| {
                rt.block_on(async {
                    if fresh {
                        c.conn.reset().await;
                    }
                    tokio::time::timeout(left, f(&mut c, &sent, &self.answered)).await
                })
            });
            let sent = sent.load(Ordering::Relaxed);
            self.requests.fetch_add(sent, Ordering::Relaxed);
            c.used = Instant::now();
            let Ok(r) = r else {
                drop(c);
                self.give_back(None);
                return Err(Fail::Store(self.latch(StoreError::unavailable(
                    KIND,
                    format!("{}: {CLIENT_PANICKED}", self.target.display),
                ))));
            };
            match r {
                Ok(Ok(v)) => {
                    self.answered.store(true, Ordering::Relaxed);
                    self.give_back(Some(c));
                    return Ok(v);
                }
                Ok(Err(e)) => {
                    let class = self.classify(&e, op);
                    if !class.latch {
                        self.answered.store(true, Ordering::Relaxed);
                    }
                    if class.busy && Instant::now() + pause < deadline {
                        self.retries.fetch_add(sent, Ordering::Relaxed);
                        std::thread::sleep(pause);
                        pause = (pause * 2).min(Duration::from_millis(500));
                        if guarded(|| rt.block_on(c.conn.reset())).is_err() {
                            self.give_back(None);
                            return Err(Fail::Store(self.latch(StoreError::unavailable(
                                KIND,
                                CLIENT_PANICKED.to_owned(),
                            ))));
                        }
                        continue;
                    }
                    if class.stale && !renewed {
                        self.retries.fetch_add(sent, Ordering::Relaxed);
                        renewed = true;
                        if guarded(|| rt.block_on(c.conn.reset())).is_err() {
                            self.give_back(None);
                            return Err(Fail::Store(self.latch(StoreError::unavailable(
                                KIND,
                                CLIENT_PANICKED.to_owned(),
                            ))));
                        }
                        continue;
                    }
                    self.give_back((!class.lost).then_some(c));
                    return Err(match class.fail {
                        Fail::Store(e) if class.latch => Fail::Store(self.latch(e)),
                        other => other,
                    });
                }
                Err(_) => {
                    self.give_back(None);
                    return Err(Fail::Store(self.latch(StoreError::Timeout {
                        backend: KIND,
                        operation,
                        after: timeout,
                    })));
                }
            }
        }
    }

    /// The rows of one statement with parameters (`?1`, `?2`, ...).
    ///
    /// A statement not prepared on the connection yet is described first
    /// (a small request): a handle's first request is always such a
    /// description, and until the server has answered one it is given up
    /// after the connect timeout. The statement itself then has the request
    /// timeout (a replica's first sync may be large).
    pub(crate) fn query(
        &self,
        op: Op,
        sql: &str,
        params: Vec<libsql::Value>,
    ) -> Result<Vec<Vec<libsql::Value>>, Fail> {
        let sql = sql.to_owned();
        let first = self.first_answer_timeout();
        self.run(op, false, move |c, n, answered| {
            let (sql, params) = (sql.clone(), params.clone());
            Box::pin(async move {
                if !c.stmts.contains_key(&sql) {
                    n.fetch_add(1, Ordering::Relaxed);
                    let st = if answered.load(Ordering::Relaxed) {
                        c.conn.prepare(&sql).await?
                    } else {
                        match tokio::time::timeout(first, c.conn.prepare(&sql)).await {
                            Ok(st) => st?,
                            Err(_) => {
                                return Err(libsql::Error::ConnectionFailed(
                                    NO_FIRST_ANSWER.to_owned(),
                                ));
                            }
                        }
                    };
                    answered.store(true, Ordering::Relaxed);
                    c.stmts.insert(sql.clone(), st);
                }
                let st = &c.stmts[&sql];
                n.fetch_add(1, Ordering::Relaxed);
                let mut rows = st.query(params).await?;
                let cols = rows.column_count();
                let mut out = Vec::new();
                while let Some(row) = rows.next().await? {
                    let mut v = Vec::with_capacity(usize::try_from(cols).unwrap_or(0));
                    for i in 0..cols {
                        v.push(row.get_value(i)?);
                    }
                    out.push(v);
                }
                Ok(out)
            })
        })
    }

    /// Apply `statements` (literals only, no parameters) in one
    /// transaction, sent as one request.
    pub(crate) fn batch(&self, op: Op, statements: &[String]) -> Result<(), Fail> {
        if statements.is_empty() {
            return Ok(());
        }
        let sql = statements.join(";\n");
        self.run(op, true, move |c, n, _| {
            let sql = sql.clone();
            Box::pin(async move {
                n.fetch_add(1, Ordering::Relaxed);
                c.conn.execute_transactional_batch(&sql).await?;
                Ok(())
            })
        })
    }
}

impl Drop for Conn {
    /// Close the pooled connections' server streams (each holds a database
    /// connection there until it expires): the close requests are sent on
    /// the runtime, waited for at most 250 ms.
    fn drop(&mut self) {
        let idle = std::mem::take(&mut self.lock_pool().idle);
        if idle.is_empty() {
            return;
        }
        let Some(Ok(rt)) = self.runtime.get() else {
            return;
        };
        let handle = rt.handle().clone();
        let _ = guarded(|| {
            rt.block_on(async move {
                drop(idle);
                let until = Instant::now() + Duration::from_millis(250);
                while handle.metrics().num_alive_tasks() > 0 && Instant::now() < until {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
        });
    }
}

// ---- literals -----------------------------------------------------------------------

/// `s` as an SQL string literal (a text value holding NUL as hex, cast).
pub(crate) fn text(s: &str) -> String {
    if s.contains('\0') {
        return format!("CAST({} AS TEXT)", blob_hex(s.as_bytes()));
    }
    format!("'{}'", s.replace('\'', "''"))
}

/// `v` as an SQL text literal, or `NULL`.
pub(crate) fn opt_text(v: Option<&str>) -> String {
    v.map_or_else(|| "NULL".to_owned(), text)
}

fn blob_hex(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 2 + 3);
    out.push_str("X'");
    for x in b {
        let _ = write!(out, "{x:02X}");
    }
    out.push('\'');
    out
}

/// `b` as an SQL blob literal: UTF-8 text without NUL travels as text cast
/// to a blob (the same bytes, half the size of hex), anything else as hex.
pub(crate) fn blob(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) if !s.contains('\0') => format!("CAST({} AS BLOB)", text(s)),
        _ => blob_hex(b),
    }
}

/// `n` as an SQL integer literal, or `NULL`.
pub(crate) fn opt_int(n: Option<i64>) -> String {
    n.map_or_else(|| "NULL".to_owned(), |n| n.to_string())
}

/// A JSON array of strings, as a parameter for `json_each(?)`.
pub(crate) fn json_list<'a>(items: impl IntoIterator<Item = &'a str>) -> libsql::Value {
    let v: Vec<&str> = items.into_iter().collect();
    libsql::Value::Text(serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_owned()))
}

// ---- reading rows -------------------------------------------------------------------

/// Text of a column, `None` for anything else.
pub(crate) fn col_text(v: &libsql::Value) -> Option<String> {
    match v {
        libsql::Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

/// An integer column, `None` for anything else.
pub(crate) fn col_int(v: &libsql::Value) -> Option<i64> {
    match v {
        libsql::Value::Integer(n) => Some(*n),
        _ => None,
    }
}

/// A stored value as it can be read: its bytes when its encoding is raw,
/// else why not.
pub(crate) fn col_value(
    value: &libsql::Value,
    encoding: &libsql::Value,
) -> Result<Vec<u8>, String> {
    match col_int(encoding) {
        Some(0) => {}
        Some(n) => {
            return Err(format!(
                "the {KIND} store holds this value in an encoding this vci cannot read ({n})"
            ));
        }
        None => return Err("the stored value has no valid encoding".to_owned()),
    }
    match value {
        libsql::Value::Blob(b) => Ok(b.clone()),
        libsql::Value::Text(s) => Ok(s.clone().into_bytes()),
        _ => Err("the stored value is not a byte string".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(url: &str, env: Option<&str>) -> Result<(Target, Option<String>), String> {
        let env = env.map(Secret::opaque);
        Target::parse(&Secret::new(url), env.as_ref())
            .map(|(t, k)| (t, k.map(|k| k.expose().to_owned())))
            .map_err(|e| e.to_string())
    }

    #[test]
    fn urls_and_tokens() {
        let (t, k) = parse("libsql://db-org.turso.io?authToken=s3cret-tok", None).unwrap();
        assert_eq!(t.url, "https://db-org.turso.io");
        assert_eq!(t.display, "libsql://db-org.turso.io");
        assert_eq!(k.as_deref(), Some("s3cret-tok"));
        let (t, k) = parse("libsql://127.0.0.1:8080/?tls=0", Some("env-tok")).unwrap();
        assert_eq!(t.url, "http://127.0.0.1:8080");
        assert_eq!(k.as_deref(), Some("env-tok"));
        let (t, k) = parse("HTTPS://db.example:443/base/", None).unwrap();
        assert_eq!(t.url, "https://db.example:443/base");
        assert_eq!(t.display, "https://db.example:443/<path>");
        assert_eq!(k, None);
        // A token written into the path is used, never shown.
        let (t, _) = parse("libsql://db.turso.io/eyJhbGciOiJFZERTQSJ9.s3cret", None).unwrap();
        assert_eq!(t.url, "https://db.turso.io/eyJhbGciOiJFZERTQSJ9.s3cret");
        assert_eq!(t.display, "libsql://db.turso.io/<path>");
        assert_eq!(
            parse("http://[::1]:9/", None).unwrap().0.url,
            "http://[::1]:9"
        );
        for bad in [
            "libsql://u:s3cret@db.turso.io",
            "ws://db.turso.io",
            "libsql://db.turso.io?password=s3cret",
            "libsql://db.turso.io#s3cret",
            "libsql://",
            "https://db.turso.io?tls=0",
            "libsql://db.turso.io/a b",
            // A token under any other key, as a bare key, or with its `=`
            // percent-encoded: neither the value nor the key is quoted.
            "libsql://db.turso.io?tls=0&token=s3cret",
            "libsql://db.turso.io?jwt=s3cret",
            "libsql://db.turso.io?access_token=s3cret",
            "libsql://db.turso.io?Auth-Token=s3cret",
            "libsql://db.turso.io?s3cret",
            "libsql://db.turso.io?s3cret=",
            "libsql://db.turso.io?authToken%3Ds3cret",
        ] {
            let e = parse(bad, None).unwrap_err();
            assert!(!e.contains("s3cret"), "{bad}: {e}");
            assert!(e.starts_with("attestation store: "), "{bad}: {e}");
        }
        let e = parse("libsql://db?Mode=x", None).unwrap_err();
        assert!(!e.contains("Mode"), "{e}");
        assert!(e.contains("authToken and tls"), "{e}");
    }

    #[test]
    fn literals() {
        assert_eq!(text("a'b"), "'a''b'");
        assert_eq!(text("a\0b"), "CAST(X'610062' AS TEXT)");
        assert_eq!(blob(b"{\"x\":'1'}"), "CAST('{\"x\":''1''}' AS BLOB)");
        assert_eq!(blob(&[0xff, 0]), "X'FF00'");
        assert_eq!(opt_int(None), "NULL");
        assert_eq!(opt_text(Some("x")), "'x'");
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%2Fb%20c"), "a/b c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%4"), "%4");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
