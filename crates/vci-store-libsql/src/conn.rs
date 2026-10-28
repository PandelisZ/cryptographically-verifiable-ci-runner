//! Talking to a libSQL server (`docs/STORE-BACKENDS.md` section 18): the URL
//! and its token, the TLS connector, the runtime, the pool of connections,
//! the circuit breaker, deadlines, and what an error means.
//!
//! * **The URL** comes from `VCI_STORE_URL`, else `[store] url`:
//!   `libsql://` (HTTPS, or HTTP with `?tls=0`), `https://` or `http://`, a
//!   host, an optional port and path, and an optional `authToken` query
//!   parameter (never in `[store] url`). A user or password in it, a
//!   fragment, or another query parameter is refused, without printing it
//!   or the parameter's name. The token is `VCI_STORE_TOKEN`, else
//!   `authToken`, else what `[store] token_command` prints, run when the
//!   first connection is made ([`vci_store::credential`]). Messages show
//!   the scheme, host and port only: a path is shown as `/<path>` (a token
//!   could be written there).
//! * **TLS** is rustls with the `ring` provider and the webpki roots, on the
//!   workspace's one rustls (libsql's own `tls` feature would bring a second).
//! * **Bounded time.** Each connection (TCP and TLS) is given up after the
//!   connect timeout. A handle's first request is always the description
//!   of a statement (a small request, see [`Conn::query`]): until the
//!   server has answered one, it is given up after the connect timeout
//!   too, so a server that accepts and never answers (or answers too
//!   slowly to be used) costs the connect timeout, not the request
//!   timeout. Every other request is given up after the request timeout,
//!   and, once the server has answered the handle, sent once more on a new
//!   connection with a deadline of its own (a hint's write, at most
//!   [`HINT_TIMEOUT`], is not; a transaction of a write batch is asked
//!   about and left to its batch to send again, see
//!   [`Conn::batch_checked`]). The first failure to reach the server, a
//!   deadline before the server first answered, and a request out of time
//!   again when sent again ([`TRIES_AFTER_TIMEOUT`]) latch the circuit
//!   breaker: every later call of the handle fails at once.
//! * **Lost connections.** A request whose connection was lost under it
//!   (a keep-alive connection the server, or a proxy, closed while it sat
//!   idle, found out only when the next request went out on it; a reset)
//!   is sent again on a new connection, at once and then after short
//!   pauses, within its deadline ([`RESEND`]); only when those fail too is
//!   the breaker latched. That is done only once the server has answered
//!   the handle: before that no connection was kept alive, and a server
//!   that accepts and closes without answering latches it at once, within
//!   the first answer's bound, as before. A connection that cannot be
//!   made (nothing listening, DNS, TLS, the connect timeout) latches it at
//!   once, as before; an answer of the server (an HTTP status, whatever
//!   its body says) is never sent again, unless its body was cut off
//!   before it arrived whole, which looks like a lost connection and is
//!   sent again as one; an answer cut off after the
//!   server began it (a read's rows) fails that call and latches nothing,
//!   as before. Sending a request again is safe: reads change nothing,
//!   and a write is one transaction whose statements, applied twice,
//!   leave the rows as applied once but for the change log's, though it
//!   can undo a write of another handle that followed its first commit
//!   (see [`Conn::batch`]).
//! * **Requests.** A read is one prepared statement (the server describes a
//!   statement once per pooled connection; the description is kept) whose
//!   rows come back in one request. A write is one transaction that takes
//!   the write lock before its first statement (`BEGIN IMMEDIATE`, see
//!   [`Conn::batch`]): its statements, values written as literals, travel
//!   in one request and apply atomically. A statement the server refuses is
//!   [`StoreError::Backend`] (or `Unsupported` for a record larger than the
//!   server takes, `Denied` for a write to a server that takes no more
//!   writes: blocked over a quota, or full) and latches nothing.
//! * **Connections** are hyper's, kept alive, except after a read: libsql
//!   drops a read's answer before the end of its HTTP body, so hyper closes
//!   that connection. The connector's sockets close with a reset, leaving
//!   no `TIME_WAIT` behind (one per read would exhaust the machine's
//!   ephemeral ports).
//! * **Panics.** libsql 0.10.0 panics on an HTTP error whose body is not
//!   UTF-8 text; every call into it is guarded (see [`guarded`]): such a
//!   panic is a latched `Unavailable`, and prints nothing.
//! * **Secrets.** Every message passes through [`Conn::scrub`], which
//!   removes the URL's token, `VCI_STORE_TOKEN` and the token command's;
//!   the location never holds any.

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
use vci_store::select::{Credential, Secret};

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

/// What a [`StoreError::Denied`] write says when the server takes no more
/// writes for now: blocked (a database over its quota, an operator's
/// block) or full (its size limit, its disk).
pub(crate) const TAKES_NO_WRITES: &str =
    "the server takes no more writes (blocked, as a database over its quota is, or full)";

/// Whether `lower` (an error's text, in lowercase) says that the server
/// takes no more writes: `sqld`'s write block (`Operation was blocked[:
/// <reason>]`, code `BLOCKED`, what a Turso database over its quota gets)
/// or its size limit (`database or disk is full`, `SQLITE_FULL`).
fn takes_no_writes(lower: &str) -> bool {
    lower.contains("operation was blocked")
        || lower.contains("code: \"blocked\"")
        || lower.contains("database or disk is full")
        || lower.contains("sqlite_full")
}

/// Whether `e` is a write refused because the server takes no more writes
/// (see [`TAKES_NO_WRITES`]), not because of the token.
pub(crate) fn is_no_writes(e: &StoreError) -> bool {
    matches!(e, StoreError::Denied { detail, .. } if detail.contains(TAKES_NO_WRITES))
}

/// The most requests one handle sends at once (its pool holds one
/// connection more, see [`Conn::checkout`]).
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
                // Closed with a reset, leaving no TIME_WAIT behind: libsql
                // 0.10.0 drops a read's answer at the end of its statement,
                // before the end of the HTTP body, so hyper cannot reuse
                // the connection and closes it, one per read. With an
                // ordinary close each read would hold an ephemeral port for
                // twice the maximum segment lifetime (30 s on macOS, 60 s
                // on Linux), and thousands of reads (a conformance run's
                // 5,900) run the machine out of ports. Only a connection
                // whose answer was read, or that is given up, is closed.
                let _ = tcp.set_zero_linger();
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

/// What a request is, for the words of its errors and its deadline.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Op {
    /// The operation a privilege error names ("read", "write").
    pub(crate) verb: &'static str,
    /// A hint's write (a memo, a flag): best effort, given at most
    /// [`HINT_TIMEOUT`], never sent again after its deadline, and never
    /// latching the breaker.
    pub(crate) hint: bool,
    /// What a deadline that ran out does, once the server has answered
    /// the handle (before that it latches the breaker).
    pub(crate) on_timeout: OnTimeout,
}

/// See [`Op::on_timeout`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnTimeout {
    /// Sent once more, on a new connection, with a deadline of its own;
    /// out of time again, it latches the breaker.
    Resend,
    /// Fails alone, latching nothing: a hint, or a request of a read of
    /// values (`Remote::query_values`), which may share the connection's
    /// bandwidth with others, so that one out of time may well be in time
    /// alone or at half the size: the read sends its keys again itself, in
    /// halves.
    FailAlone,
    /// Latches the breaker: the request sent again by its caller.
    Latch,
}

pub(crate) const READ: Op = Op {
    verb: "read",
    hint: false,
    on_timeout: OnTimeout::Resend,
};
pub(crate) const WRITE: Op = Op {
    verb: "write",
    hint: false,
    on_timeout: OnTimeout::Resend,
};
/// A hint's write ([`Op::hint`]).
pub(crate) const HINT: Op = Op {
    verb: "write",
    hint: true,
    on_timeout: OnTimeout::FailAlone,
};
/// A request of a read of values, first sent ([`OnTimeout::FailAlone`]).
pub(crate) const READ_SHARED: Op = Op {
    verb: "read",
    hint: false,
    on_timeout: OnTimeout::FailAlone,
};
/// A read sent again by its caller after a [`READ_SHARED`] ran out of
/// time ([`OnTimeout::Latch`]).
pub(crate) const READ_AGAIN: Op = Op {
    verb: "read",
    hint: false,
    on_timeout: OnTimeout::Latch,
};
/// A write transaction of the store's batches, whose caller asks, when
/// its deadline runs out, whether the server committed it, and sends it
/// again itself ([`Conn::batch_checked`]): it fails alone.
const WRITE_ONCE: Op = Op {
    verb: "write",
    hint: false,
    on_timeout: OnTimeout::FailAlone,
};
/// The question whether such a write was committed: unanswered in time,
/// it fails alone (the write is then sent again, which is safe).
const PROBE: Op = Op {
    verb: "read",
    hint: false,
    on_timeout: OnTimeout::FailAlone,
};

/// The longest a hint's write waits ([`Op::hint`]): it waits behind other
/// writers for the server's one write lock, and nothing waits for it to
/// be stored.
pub(crate) const HINT_TIMEOUT: Duration = Duration::from_secs(5);

/// How many times a request whose deadline ran out (once the server has
/// answered the handle) is sent, each on a new connection with a deadline
/// of its own: one slow answer (a large read while other jobs write, a
/// write that waited for the lock) costs that call a second try, not the
/// handle; the same request out of time again means the server cannot be
/// used, and latches the breaker. Counted per request, not per handle, so
/// that the requests a read sends at once do not use up each other's try.
const TRIES_AFTER_TIMEOUT: u32 = 2;

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
    /// The HTTP connection was lost under the request ([`dropped`]): sent
    /// again on a new connection, as [`RESEND`] says.
    dropped: bool,
}

impl Class {
    fn fail(fail: Fail, latch: bool, lost: bool) -> Class {
        Class {
            fail,
            latch,
            lost,
            busy: false,
            stale: false,
            dropped: false,
        }
    }
}

/// How long a connection's server stream may sit idle before the next call
/// starts a new one (servers expire idle streams after about ten seconds).
const STREAM_IDLE: Duration = Duration::from_secs(4);

/// What hyper 0.14 and the system say (in lowercase) when an HTTP
/// connection that was made is lost under a request:
///
/// * hyper's `IncompleteMessage`, the connection closed before the whole
///   answer came: a keep-alive connection that the server, or a proxy in
///   front of it, closed while it sat idle (vex's CI met it on Turso) is
///   found out only when the next request has gone out on it, since the
///   client's runtime runs only inside a call;
/// * hyper's errors reading or writing a body on the connection, a
///   request canceled because its connection closed before it was
///   written (one on a reused connection hyper sends again itself), and a
///   closed connection's channel;
/// * a reset (`ECONNRESET`, `Connection reset by peer`), a broken pipe
///   (`EPIPE`), an aborted connection (`ECONNABORTED`, `Software caused
///   connection abort`), the end of the stream before the answer's
///   (`std::io::ErrorKind::UnexpectedEof`, hyper's `end of file before
///   message length reached`), and a TLS connection closed without its
///   `close_notify` (rustls).
const DROPPED: &[&str] = &[
    "connection closed before message completed",
    "error reading a body from connection",
    "error writing a body to connection",
    "operation was canceled: connection closed",
    "channel closed",
    "connection reset",
    "broken pipe",
    "connection abort",
    "unexpected end of file",
    "end of file before message length reached",
    "close_notify",
];

/// How libsql's text for a request that failed in transport begins, in
/// lowercase: its `HranaError::Http` (hyper's error) as
/// `libsql::Error::Hrana` shows it. Every other text is not a transport
/// failure, whatever words it holds: an answer of the server (`api error`:
/// an HTTP status and its body, or a statement's error; a `stream error`),
/// or a `cursor error`, which comes after the server answered (a read's
/// rows cut off, or an error the server sent among them).
const HTTP_ERROR: &str = "hrana: `http error: ";

/// Whether `lower` (an error's text, in lowercase) is libsql's text for a
/// transport failure of the request ([`HTTP_ERROR`]).
fn transport(lower: &str) -> bool {
    lower.starts_with(HTTP_ERROR)
}

/// Whether `lower` (an error's text, in lowercase) says that an HTTP
/// connection was lost under the request ([`DROPPED`]), as a transport
/// failure ([`transport`]): not an answer the server sent (a refused
/// token, an error page, whatever its body says), not an answer cut off
/// after the server began it (a `cursor error`: the connection was alive
/// when the request went out, so it is not a keep-alive connection closed
/// while idle; that call fails, latching nothing, as in 2.8.0), and not a
/// connection that could not be made (`error trying to connect`: nothing
/// listening, DNS, TLS, the connect timeout), which is a server out of
/// reach.
fn dropped(lower: &str) -> bool {
    transport(lower)
        && !lower.contains("error trying to connect")
        && DROPPED.iter().any(|m| lower.contains(m))
}

/// The pauses before a request whose connection was lost ([`dropped`]) is
/// sent again, each time on a new connection: at once, then after 100 ms
/// and 500 ms, each only while the request's deadline allows. A server
/// that drops every connection costs those 0.6 s of pauses plus four
/// tries, each as long as the server takes to drop it, all within the
/// request's deadline, before the breaker latches; one that went away is
/// refused at the first new connection.
const RESEND: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(100),
    Duration::from_millis(500),
];

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
    /// `VCI_STORE_URL` (or `[store] url`), for scrubbing (its `authToken`
    /// included).
    url: Secret,
    /// How messages name the URL: `$VCI_STORE_URL` or `vci.toml [store]
    /// url`.
    url_name: &'static str,
    /// The token: given, or printed by `[store] token_command` when the
    /// first connection is made ([`Conn::database`]).
    token: Option<Credential>,
    connect_timeout: Duration,
    timeout: Duration,
    runtime: OnceLock<Result<tokio::runtime::Runtime, String>>,
    db: OnceLock<Result<libsql::Database, String>>,
    pool: Mutex<Pool>,
    freed: Condvar,
    max: usize,
    broken: OnceLock<String>,
    requests: AtomicU64,
    /// Requests sent again (the server was busy, had dropped the stream,
    /// or the connection was lost under them), counted in `requests` too.
    retries: AtomicU64,
    /// The server has answered a request of this handle: later requests
    /// get the request timeout, not the connect timeout.
    answered: AtomicBool,
    /// Bytes of the values (and other text and blob columns) read, as
    /// stored (compressed values compressed): what the timing lines show.
    received: AtomicU64,
}

impl Conn {
    pub(crate) fn new(
        target: Target,
        url: Secret,
        url_name: &'static str,
        token: Option<Credential>,
        connect_timeout: Duration,
        timeout: Duration,
        jobs: usize,
    ) -> Conn {
        Conn {
            target,
            url,
            url_name,
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
            received: AtomicU64::new(0),
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
    /// (another writer held the database), had dropped the stream, or the
    /// connection was lost under them.
    pub(crate) fn retries(&self) -> u64 {
        self.retries.load(Ordering::Relaxed)
    }

    /// The most requests this handle sends at once (a read of values); the
    /// pool holds one connection more.
    pub(crate) fn max(&self) -> usize {
        self.max
    }

    /// The request timeout.
    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Bytes of text and blob columns read so far (values as stored).
    pub(crate) fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    /// Whether the server has answered a request of this handle.
    pub(crate) fn answered(&self) -> bool {
        self.answered.load(Ordering::Relaxed)
    }

    /// Whether connecting now would run `[store] token_command`
    /// ([`Credential::pending`]): the store's `warm` then does nothing.
    pub(crate) fn token_pending(&self) -> bool {
        self.token.as_ref().is_some_and(Credential::pending)
    }

    /// `text` without the URL's token, `VCI_STORE_TOKEN`, or the token
    /// command's.
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
        if self.db.get().is_none()
            && let Some(t) = &self.token
        {
            // The token command runs here, when the first connection is
            // made, at most once per process; a failure is the store's
            // (unavailable), every later call too.
            t.get(KIND)?;
        }
        let r = self.db.get_or_init(|| {
            let tls = if self.target.url.starts_with("https://") {
                Some(tls_config()?)
            } else {
                None
            };
            let connector = Connector::new(tls, self.connect_timeout);
            let token = match &self.token {
                Some(t) => t.get(KIND).map_err(|e| e.to_string())?.expose().to_owned(),
                None => String::new(),
            };
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
            StoreError::Config(format!("{} ({}): {e}", self.url_name, self.target.display))
        })
    }

    /// A connection from the pool (one that has `sql` described, when one
    /// that is idle has), a new one when none is idle and the pool is not
    /// full; waiting at most the connect timeout otherwise. The pool holds
    /// one connection more than requests are sent at once ([`Conn::max`]):
    /// the one the plan's other reads use while the others read values or
    /// are described ahead ([`Conn::describe_ahead`]).
    fn checkout(&self, sql: Option<&str>) -> Result<Pooled, StoreError> {
        self.check()?;
        let db = self.database()?;
        let deadline = Instant::now() + self.connect_timeout;
        let mut p = self.lock_pool();
        loop {
            let described = sql.and_then(|s| p.idle.iter().rposition(|c| c.stmts.contains_key(s)));
            if let Some(i) = described {
                return Ok(p.idle.remove(i));
            }
            if let Some(c) = p.idle.pop() {
                return Ok(c);
            }
            if p.open < self.max + 1 {
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
        // The connection was lost under the request (a keep-alive
        // connection closed while it sat idle, a reset): sent again on a
        // new connection once the server has answered the handle; when
        // that fails too, or before any answer, the server is out of reach.
        if dropped(&lower) {
            return Class {
                dropped: true,
                ..unavailable(format!("cannot reach {at}: {text}"), true, true)
            };
        }
        if transport(&lower) || matches!(e, libsql::Error::ConnectionFailed(_)) {
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
            let why = match &self.token {
                Some(t) if t.from_command() => {
                    format!("the server refused the token from {}", t.origin())
                }
                Some(_) => {
                    "the server refused the token in $VCI_STORE_TOKEN or the URL's authToken"
                        .to_owned()
                }
                None => {
                    "the server asks for a token: set $VCI_STORE_TOKEN (or [store] token_command)"
                        .to_owned()
                }
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
        if takes_no_writes(&lower) {
            // The server works but takes no more writes (a database over its
            // quota, at its size limit): a write is refused, which keeps
            // `vci run`'s exit code the tests', and reads go on (nothing is
            // latched). A server that blocks reads as well cannot be used.
            if op.verb == WRITE.verb {
                return Class::fail(
                    Fail::Store(StoreError::Denied {
                        backend: KIND,
                        operation: op.verb,
                        detail: format!("{at}: {TAKES_NO_WRITES}: {text}"),
                    }),
                    false,
                    true,
                );
            }
            return unavailable(
                format!("{at}: the server refused to read: {text}"),
                true,
                true,
            );
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
    /// server no longer knows is replaced once; a request whose connection
    /// was lost under it, once the server has answered the handle, is sent
    /// again on a new connection ([`RESEND`], [`Conn::renew`]), and latches
    /// the breaker only when that fails too or the deadline leaves no time
    /// for it (before any answer, it latches the breaker at once). A panic
    /// in the client is a latched `Unavailable`. With `until`, no try runs
    /// past it: a try it cut short fails alone (latching nothing), and none
    /// is sent again after it.
    fn run<T, F>(
        &self,
        op: Op,
        bounded_first: bool,
        until: Option<Instant>,
        sql: Option<&str>,
        mut f: F,
    ) -> Result<T, Fail>
    where
        F: for<'a> FnMut(
            &'a mut Pooled,
            &'a AtomicU64,
            &'a AtomicBool,
        ) -> Pin<Box<dyn Future<Output = libsql::Result<T>> + 'a>>,
    {
        let rt = self.runtime()?;
        let mut c = self.checkout(sql)?;
        // A server that accepts and never answers (a frozen server, a
        // stuck proxy) costs the connect timeout, not the request timeout.
        let first = bounded_first && !self.answered();
        let (timeout, operation) = if first {
            (self.first_answer_timeout(), "the server's first answer")
        } else if op.hint {
            (self.timeout.min(HINT_TIMEOUT), "a hint's write")
        } else {
            (self.timeout, "a request")
        };
        // This try's deadline, and whether `until` cut it short.
        let bound = |from: Instant| match until {
            Some(u) if u < from + timeout => (u, true),
            _ => (from + timeout, false),
        };
        let mut started = Instant::now();
        let (mut deadline, mut cut_short) = bound(started);
        let mut pause = Duration::from_millis(10);
        let mut renewed = false;
        // Times sent again on a new connection.
        let mut resent = 0;
        // Times its deadline ran out.
        let mut timed_out = 0;
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
                    // Only once the server has answered this handle: before
                    // that, no connection was kept alive to be lost, and a
                    // server that accepts and closes without answering is
                    // out of reach, latched at once and within the first
                    // answer's bound (each request sent again would get a
                    // bound of its own).
                    if class.dropped
                        && self.answered()
                        && let Some(&wait) = RESEND.get(resent)
                        && Instant::now() + wait < deadline
                    {
                        self.retries.fetch_add(sent, Ordering::Relaxed);
                        resent += 1;
                        std::thread::sleep(wait);
                        if let Err(e) = self.renew(rt, &mut c) {
                            self.give_back(None);
                            return Err(Fail::Store(if op.hint { e } else { self.latch(e) }));
                        }
                        continue;
                    }
                    self.give_back((!class.lost).then_some(c));
                    // A hint never latches: nothing waits for it, and the
                    // calls that need the server find out themselves.
                    return Err(match class.fail {
                        Fail::Store(e) if class.latch && !op.hint => Fail::Store(self.latch(e)),
                        other => other,
                    });
                }
                Err(_) => {
                    let e = StoreError::Timeout {
                        backend: KIND,
                        operation: if cut_short {
                            "a request (cut short: the read it is part of ran out of time)"
                        } else {
                            operation
                        },
                        after: if cut_short {
                            deadline.saturating_duration_since(started)
                        } else {
                            timeout
                        },
                    };
                    timed_out += 1;
                    // A hint is dropped (nothing waits for it), a read
                    // beside others is sent again by its caller, and a
                    // request whose caller's time ran out fails alone.
                    if (op.on_timeout == OnTimeout::FailAlone || cut_short)
                        && !first
                        && self.answered()
                    {
                        self.give_back(None);
                        return Err(Fail::Store(e));
                    }
                    // Once the server has answered the handle, a request
                    // whose deadline ran out is sent once more, on a new
                    // connection (the one it went out on is in an unknown
                    // state), with a deadline of its own; reads change
                    // nothing, and a write is safe to send again (see
                    // `Conn::batch`). A server that never answered is out
                    // of reach: latched at once, as before.
                    let answered = self.answered();
                    if !first
                        && op.on_timeout == OnTimeout::Resend
                        && timed_out < TRIES_AFTER_TIMEOUT
                        && answered
                    {
                        // The caller's time ran out: not sent again.
                        if until.is_some_and(|u| Instant::now() >= u) {
                            self.give_back(None);
                            return Err(Fail::Store(e));
                        }
                        self.retries.fetch_add(sent.max(1), Ordering::Relaxed);
                        // Unless another request latched the breaker
                        // meanwhile.
                        if let Err(e) = self.check() {
                            self.give_back(None);
                            return Err(Fail::Store(e));
                        }
                        if let Err(e) = self.renew(rt, &mut c) {
                            self.give_back(None);
                            return Err(Fail::Store(self.latch(e)));
                        }
                        started = Instant::now();
                        (deadline, cut_short) = bound(started);
                        pause = Duration::from_millis(10);
                        continue;
                    }
                    self.give_back(None);
                    return Err(Fail::Store(self.latch(e)));
                }
            }
        }
    }

    /// Give `c` a new libsql connection, after its HTTP connection was lost
    /// under a request: a new HTTP client, so that the request sent again
    /// opens a new TCP (and TLS) connection. hyper takes a connection that
    /// failed out of its pool, but the client may hold others that sat
    /// idle as long, and it hands out the one used last first; a new
    /// client holds none. The old connection's server stream is given up
    /// without a request (whether the server still has it is not known;
    /// it expires it), and the statements prepared on it go with it.
    fn renew(&self, rt: &tokio::runtime::Runtime, c: &mut Pooled) -> Result<(), StoreError> {
        let db = self.database()?;
        let conn = guarded(|| {
            rt.block_on(c.conn.reset());
            db.connect()
        })
        .unwrap_or_else(|()| Err(libsql::Error::ConnectionFailed(CLIENT_PANICKED.to_owned())))
        .map_err(|e| {
            StoreError::unavailable(
                KIND,
                format!(
                    "cannot connect to {}: {}",
                    self.target.display,
                    self.scrub(&e.to_string())
                ),
            )
        })?;
        c.conn = conn;
        c.stmts.clear();
        Ok(())
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
        self.query_until(op, sql, params, None)
    }

    /// [`Conn::query`], given up at `until` at the latest (see
    /// [`Conn::run`]): a try it cuts short fails alone.
    pub(crate) fn query_until(
        &self,
        op: Op,
        sql: &str,
        params: Vec<libsql::Value>,
        until: Option<Instant>,
    ) -> Result<Vec<Vec<libsql::Value>>, Fail> {
        let sql = sql.to_owned();
        let first = self.first_answer_timeout();
        let described = sql.clone();
        let rows = self.run(op, false, until, Some(&described), move |c, n, answered| {
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
        })?;
        let got: usize = rows
            .iter()
            .flatten()
            .map(|x| match x {
                libsql::Value::Blob(b) => b.len(),
                libsql::Value::Text(t) => t.len(),
                _ => 0,
            })
            .sum();
        self.received
            .fetch_add(u64::try_from(got).unwrap_or(u64::MAX), Ordering::Relaxed);
        Ok(rows)
    }

    /// Have the server describe `sqls` on as many connections as requests
    /// go at once ([`Conn::max`]), at once, so that the reads that use them
    /// later send
    /// only their own request (the description, which libsql's statements
    /// need, is one more round trip per statement and connection: about a
    /// second each behind a link that waits that long for every answer).
    /// Done by the store's warm-up, while the command works on other
    /// things; a statement already described on a connection is not sent
    /// again, and a failure only leaves the description to the read.
    pub(crate) fn describe_ahead(&self, sqls: &[&str]) {
        std::thread::scope(|sc| {
            for _ in 0..self.max {
                sc.spawn(|| {
                    // Fails alone: a description out of time latches
                    // nothing (the read describes it again).
                    let _ = self.run(READ_SHARED, false, None, None, |c, n, answered| {
                        let todo: Vec<String> = sqls
                            .iter()
                            .filter(|s| !c.stmts.contains_key(**s))
                            .map(|s| (*s).to_owned())
                            .collect();
                        Box::pin(async move {
                            for sql in todo {
                                n.fetch_add(1, Ordering::Relaxed);
                                let st = c.conn.prepare(&sql).await?;
                                answered.store(true, Ordering::Relaxed);
                                c.stmts.insert(sql, st);
                            }
                            Ok(())
                        })
                    });
                });
            }
        });
    }

    /// Apply `statements` (literals only, no parameters) in one
    /// transaction that takes the write lock before its first statement,
    /// sent as one request.
    ///
    /// The request is a Hrana batch of `BEGIN IMMEDIATE`, the statements and
    /// `COMMIT`, each step run only when the one before it succeeded, and it
    /// closes the stream, so a batch that stopped part way is rolled back as
    /// the server closes the stream's connection. libsql's transactional
    /// batch is not used: its deferred `BEGIN` lets a batch whose first
    /// statements only read (a namespace's first `CREATE TABLE IF NOT
    /// EXISTS` on `vci_schema`, which exists once any namespace does) hold a
    /// read snapshot that it must later promote to the write lock. Under
    /// concurrent writers that promotion fails at once
    /// (`SQLITE_BUSY_SNAPSHOT`, which no busy handler retries; it came back
    /// as `database is locked` and the batch was sent again), and on `sqld`
    /// 0.24 it leaves the write slot failed until the stream closes, a close
    /// that can race another writer taking the slot and abort the server
    /// (docs/STORE-BACKENDS.md section 21, item 17). `BEGIN IMMEDIATE` asks
    /// for the write lock outside any transaction, which the server retries
    /// with a fresh snapshot.
    ///
    /// **Sending a batch again is safe**, which [`Conn::run`] does when the
    /// connection was lost under it: the server may have committed it and
    /// lost only the answer. It is one transaction ending in `COMMIT`, so
    /// the server applied all of it or none. Its values are literals fixed
    /// when the batch was built (`put_at`, `stored_at` and the log's `at`
    /// included), so the same text goes again, and applied twice in a row
    /// it leaves the rows as applied once, but for the change log's: the
    /// manifests, the attestations and the memo are upserts of the same
    /// rows (a no-op the second time), a removal deletes what is already
    /// gone (and `remove_manifests` only what is still unreferenced and
    /// old), the schema's DDL is `IF NOT EXISTS` and its `vci_schema` row
    /// and the flags `ON CONFLICT DO NOTHING`, and the prunes move
    /// `log_floor` up to the same value and delete the same rows. The
    /// change log's rows are inserted again, under new `seq`s, which
    /// replicas tolerate: a replica reads, for the slots and roots the log
    /// names after its last sync (`DISTINCT`), the server's current rows,
    /// so a slot named twice is read once, and one named again after a
    /// replica synced is read again as it now is; it converges.
    ///
    /// The batch sent again is applied after whatever the server applied
    /// since its first commit, and wins as the last writer in the server's
    /// order: a write of another handle that followed the first commit,
    /// and returned, is undone where the two overlap. Its upserts replace
    /// that writer's newer row of the same slot, memo entry or manifest's
    /// `put_at`, and its removals delete a key that writer stored again,
    /// or, for a slot the batch emptied (`DELETE` by test key, signer and
    /// storage key), whatever that writer stored in the slot. A reader can
    /// see the batch's rows, then the other writer's, then the batch's
    /// again (a key removed, stored again, then gone): no order of single
    /// applications gives that. The window is from the first commit to
    /// the batch sent again (usually a few round trips and well under a
    /// second, at most the request's deadline); vci's removals are of keys superseded and slots emptied,
    /// and the store is not trusted (every attestation is verified when
    /// read), so the worst is a miss: a test runs again and its
    /// attestation is stored again, never a wrong verification. Should
    /// the server keep the transaction of a request that was cut off open,
    /// it holds the write lock until the server expires its stream, and the
    /// batch sent again waits for it as for any other writer, within its
    /// deadline.
    pub(crate) fn batch(&self, op: Op, statements: &[String]) -> Result<(), Fail> {
        self.send_batch(op, statements)
    }

    /// A write transaction of the store's batches (`crate::batch`): sent
    /// once, and when its deadline runs out (or it waited for the write
    /// lock until then), `committed` (a read that returns a row only once
    /// the transaction is applied, such as one of its attestations with its
    /// `stored_at`) asks the server whether it committed it: a transaction
    /// that timed out waiting for the lock often commits after the client
    /// gave up, and sending it again would wait for the lock again and
    /// write its change log rows a second time, under the very load that
    /// made it late. One that has committed is `Ok`; one that has not (or
    /// whose question went unanswered) is the timeout, which latches
    /// nothing: the caller sends it again, in halves, within the process's
    /// retry time (`Remote::spend_on_writes`). The server may still commit
    /// the first one after the question was answered: the transaction is
    /// then applied twice, which is safe (see [`Conn::batch`]) and, its
    /// upserts writing only rows that differ, costs little but the log's
    /// rows.
    pub(crate) fn batch_checked(
        &self,
        statements: &[String],
        committed: Option<&str>,
    ) -> Result<(), Fail> {
        let r = self.send_batch(WRITE_ONCE, statements);
        let Some(probe) = committed else {
            return r;
        };
        match r {
            Err(Fail::Store(e @ StoreError::Timeout { .. }))
                if self.answered() && self.check().is_ok() =>
            {
                self.retries.fetch_add(1, Ordering::Relaxed);
                match self.query(PROBE, probe, Vec::new()) {
                    Ok(rows) if !rows.is_empty() => Ok(()),
                    _ => Err(Fail::Store(e)),
                }
            }
            other => other,
        }
    }

    /// Latch the circuit breaker with `e` (a timeout or an unavailable
    /// server) from outside a request: the process's time for writes that
    /// fail ran out (`Remote::spend_on_writes`).
    pub(crate) fn latch_now(&self, e: StoreError) -> StoreError {
        self.latch(e)
    }

    fn send_batch(&self, op: Op, statements: &[String]) -> Result<(), Fail> {
        if statements.is_empty() {
            return Ok(());
        }
        let sql = format!("BEGIN IMMEDIATE;\n{};\nCOMMIT", statements.join(";\n"));
        let db = self.database()?;
        self.run(op, true, None, None, move |c, n, _| {
            let sql = sql.clone();
            // libsql closes the stream with the batch only while it believes
            // the stream is outside a transaction, and a batch that stopped
            // part way leaves it believing otherwise: such a connection is
            // replaced first (a local step, no request), so that every batch
            // closes its stream and no failed one keeps the write lock.
            let renewed = (!c.conn.is_autocommit()).then(|| db.connect());
            Box::pin(async move {
                if let Some(conn) = renewed {
                    c.conn = conn?;
                    c.stmts.clear();
                }
                n.fetch_add(1, Ordering::Relaxed);
                c.conn.execute_batch(&sql).await?;
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

/// The `encoding` of a value stored as it is.
pub(crate) const RAW: i64 = 0;
/// The `encoding` of a value stored as one zstd frame (2.8.2): what a
/// reader decompresses, to at most [`MAX_RECORD`] bytes.
pub(crate) const ZSTD: i64 = 1;

/// The zstd level values are compressed at: about 3x smaller for vex's
/// envelopes and manifests (JSON), a few milliseconds per value.
const ZSTD_LEVEL: i32 = 6;

/// `b` compressed as one zstd frame ([`ZSTD`]); `None` if that fails (the
/// value is then stored as it is).
pub(crate) fn compress(b: &[u8]) -> Option<Vec<u8>> {
    zstd::bulk::compress(b, ZSTD_LEVEL).ok()
}

/// The bytes of one zstd frame, refused when they decompress to more than
/// [`MAX_RECORD`] bytes (no value vci stores is larger).
pub(crate) fn decompress(b: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut out = Vec::new();
    let cap = u64::try_from(MAX_RECORD).unwrap_or(u64::MAX);
    zstd::stream::read::Decoder::with_buffer(b)
        .and_then(|d| d.take(cap + 1).read_to_end(&mut out))
        .map_err(|e| format!("the stored value is not a zstd frame vci can read ({e})"))?;
    if out.len() > MAX_RECORD {
        return Err(format!(
            "the stored value decompresses to more than {MAX_RECORD} bytes"
        ));
    }
    Ok(out)
}

/// A stored value as it can be read: its bytes (decompressed when stored
/// compressed), else why not.
pub(crate) fn col_value(
    value: &libsql::Value,
    encoding: &libsql::Value,
) -> Result<Vec<u8>, String> {
    let enc = match col_int(encoding) {
        Some(n @ (RAW | ZSTD)) => n,
        Some(n) => {
            return Err(format!(
                "the {KIND} store holds this value in an encoding this vci cannot read ({n}): a newer vci wrote it"
            ));
        }
        None => return Err("the stored value has no valid encoding".to_owned()),
    };
    let bytes = match value {
        libsql::Value::Blob(b) => b.as_slice(),
        libsql::Value::Text(s) => s.as_bytes(),
        _ => return Err("the stored value is not a byte string".to_owned()),
    };
    if enc == ZSTD {
        return decompress(bytes);
    }
    Ok(bytes.to_vec())
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

    /// The connector's sockets close with a reset and leave no TIME_WAIT
    /// behind: libsql 0.10.0 drops a read's answer at the end of its
    /// statement, before the end of the HTTP body, so hyper closes that
    /// connection, one per read, and thousands of reads (the conformance
    /// suite's) would hold every ephemeral port of the machine.
    #[test]
    fn connections_close_without_lingering() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut c = Connector::new(None, Duration::from_secs(5));
        let uri: http::Uri = format!("http://127.0.0.1:{port}/").parse().unwrap();
        let s = rt
            .block_on(tower_service::Service::call(&mut c, uri))
            .unwrap();
        match s {
            Socket::Plain(t) => assert_eq!(t.linger().unwrap(), Some(Duration::ZERO)),
            Socket::Tls(_) => panic!("a plain connection"),
        }
    }

    /// A server that takes no more writes: `sqld`'s write block (a
    /// database over its quota) and its size limit, as a batch step's
    /// error, a statement's and a cursor step's.
    #[test]
    fn blocked_and_full_servers_are_recognized() {
        for text in [
            "Hrana: `api error: `Operation was blocked: storage quota exceeded``",
            "Hrana: `stream error: `Error { message: \"Operation was blocked\", code: \"BLOCKED\" }``",
            "Hrana: `api error: `SQLite error: database or disk is full``",
            "Hrana: `cursor error: `error at step 1: (error code: SQLITE_FULL) `SQLite error: database or disk is full```",
        ] {
            assert!(takes_no_writes(&text.to_ascii_lowercase()), "{text}");
        }
        for text in [
            "Hrana: `api error: `SQLite error: UNIQUE constraint failed: t.a``",
            "Hrana: `api error: `boom``",
        ] {
            assert!(!takes_no_writes(&text.to_ascii_lowercase()), "{text}");
        }
    }

    /// A connection lost under a request (libsql's words for hyper's and
    /// the system's errors, on macOS and Linux) is sent again; a
    /// connection that could not be made, an answer cut off after the
    /// server began it, and every answer the server sent (a refused token
    /// included, whatever its body says), is not.
    #[test]
    fn lost_connections_are_told_from_unreachable_servers() {
        let url = Secret::new("http://127.0.0.1:9");
        let (target, _) = Target::parse(&url, None).unwrap();
        let conn = Conn::new(
            target,
            url,
            "$VCI_STORE_URL",
            None,
            Duration::from_secs(5),
            Duration::from_secs(30),
            1,
        );
        let class = |text: &str| conn.classify(&libsql::Error::Hrana(text.into()), WRITE);
        for text in [
            // What vex's CI got from Turso, and what a reset gives.
            "http error: `connection closed before message completed`",
            "http error: `connection error: Connection reset by peer (os error 54)`",
            "http error: `connection error: Connection reset by peer (os error 104)`",
            "http error: `error writing a body to connection: Broken pipe (os error 32)`",
            "http error: `connection error: Software caused connection abort (os error 53)`",
            "http error: `connection error: unexpected end of file`",
            "http error: `connection error: peer closed connection without sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof`",
            "http error: `error reading a body from connection: end of file before message length reached`",
            "http error: `operation was canceled: connection closed`",
            "http error: `channel closed`",
        ] {
            let c = class(text);
            assert!(c.dropped, "{text}");
            assert!(
                c.latch && c.lost,
                "{text}: latched when sending it again fails"
            );
            match &c.fail {
                Fail::Store(e) => {
                    assert!(e.to_string().contains("cannot reach"), "{text}: {e}")
                }
                Fail::Absent => panic!("{text}: absent"),
            }
        }
        for text in [
            "http error: `error trying to connect: tcp connect error: Connection refused (os error 61)`",
            "http error: `error trying to connect: tcp connect error: Connection reset by peer (os error 54)`",
            "http error: `error trying to connect: dns error: failed to lookup address information: nodename nor servname provided, or not known`",
            "http error: `error trying to connect: connecting timed out after 5s`",
            "http error: `error trying to connect: peer closed connection without sending TLS close_notify`",
            "http error: `error trying to connect: invalid peer certificate: UnknownIssuer`",
        ] {
            let c = class(text);
            assert!(!c.dropped, "{text}");
            assert!(c.latch, "{text}: an unreachable server latches at once");
        }
        // An answer the server began (a read's rows) and that was cut off:
        // that read fails, and nothing is latched, as in 2.8.0.
        for text in [
            "cursor error: `error reading a body from connection: Connection reset by peer (os error 54)`",
            "cursor error: `error reading a body from connection: end of file before message length reached`",
            "cursor error: `cursor stream ended prematurely`",
        ] {
            let c = class(text);
            assert!(!c.dropped, "{text}");
            assert!(!c.latch, "{text}: latched");
            match &c.fail {
                Fail::Store(e) => {
                    assert!(!e.to_string().contains("cannot reach"), "{text}: {e}")
                }
                Fail::Absent => panic!("{text}: absent"),
            }
        }
        // Answers of the server, whatever words their bodies hold.
        let says = |text: &str| match class(text) {
            c if c.dropped => panic!("{text}: sent again"),
            Class {
                fail: Fail::Store(e),
                ..
            } => e.to_string(),
            Class { .. } => panic!("{text}: absent"),
        };
        for text in [
            "api error: `status=401 Unauthorized, body={\"error\":\"Unauthorized: `The JWT is invalid`\"}`",
            "api error: `status=502 Bad Gateway, body=upstream connection reset`",
            "api error: `SQLite error: broken pipe`",
            "api error: `SQLite error: http error: connection reset by peer`",
            "stream error: `Error { message: \"SQLite error: database is locked\", code: \"SQLITE_BUSY\" }`",
            "stream error: `Error { message: \"http error: `connection closed before message completed`\", code: \"X\" }`",
        ] {
            says(text);
        }
        for (text, said) in [
            (
                "api error: `status=502 Bad Gateway, body=upstream: http error: `connection reset by peer``",
                "status=502",
            ),
            (
                "api error: `status=503 Service Unavailable, body=http error: `connection closed before message completed``",
                "status=503",
            ),
            (
                "api error: `status=401 Unauthorized, body=http error: `connection reset by peer``",
                "the server asks for a token",
            ),
        ] {
            let e = says(text);
            assert!(e.contains(said), "{text}: {e}");
            assert!(!e.contains("cannot reach"), "{text}: {e}");
        }
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%2Fb%20c"), "a/b c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%4"), "%4");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
