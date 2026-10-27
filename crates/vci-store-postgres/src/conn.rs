//! Connections: the URL, TLS, session settings, the pool, the circuit
//! breaker, error classification, retries and the statement counter
//! (`docs/STORE-BACKENDS.md` section 17, "Connection handling").

use std::error::Error as _;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use postgres::config::{Host, LoadBalanceHosts, SslMode};
use postgres::types::{ToSql, Type};
use postgres::{Client, NoTls, Row, Transaction};
use tokio_postgres_rustls::MakeRustlsConnect;
use vci_store::StoreError;
use vci_store::select::{Credential, Secret};

/// The backend's name in errors and timing lines.
pub(crate) const KIND: &str = "postgres";

/// How long a lock may be waited for (`lock_timeout`).
pub(crate) const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a session may sit idle inside a transaction.
const IDLE_IN_TRANSACTION: Duration = Duration::from_secs(60);

/// The statement timeout of a command that reads or writes the whole store
/// (`OpenContext::long_running`, `vci prune`).
pub(crate) const LONG_RUNNING_TIMEOUT: Duration = Duration::from_secs(600);

/// A PostgreSQL error, as text with every credential removed
/// ([`Secret::scrub`]). [`StoreError::Backend`] carries it for errors that
/// say nothing about whether the store can be used (an unexpected SQLSTATE,
/// a value that does not decode); `StoreError::downcast_backend::<PgError>()`
/// gets it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgError {
    message: String,
    code: Option<String>,
}

impl PgError {
    /// An error with this (already scrubbed) text and no SQLSTATE.
    pub(crate) fn from_text(message: String) -> PgError {
        PgError {
            message,
            code: None,
        }
    }

    /// The message, scrubbed.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The SQLSTATE, when the server sent one.
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
}

impl fmt::Display for PgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "postgres store: {}", self.message)
    }
}

impl std::error::Error for PgError {}

/// One bound parameter of a statement, with its type: statements go out as
/// one round trip each (`query_typed`), never prepared first.
pub(crate) type P<'a> = (&'a (dyn ToSql + Sync), Type);

// ---- the connection string --------------------------------------------------

/// How to connect, parsed once when the store is opened (no I/O).
pub(crate) struct ConnSpec {
    config: postgres::Config,
    /// One configuration per host, tried in order (see [`attempts`]).
    attempts: Vec<postgres::Config>,
    ssl_mode: SslMode,
    root_cert: Option<PathBuf>,
    display: String,
    /// What messages call the URL: `$VCI_STORE_URL`, or `vci.toml [store]
    /// url` when it came from there ([`vci_store::select::url_name`]).
    pub(crate) url_name: &'static str,
    pub(crate) connect_timeout: Duration,
    pub(crate) statement_timeout: Duration,
    options: String,
    application_name: String,
}

/// What [`ConnSpec`] decided, for `PgStore::__connection_for_test`.
pub(crate) struct SpecSummary {
    pub(crate) ssl_mode: &'static str,
    pub(crate) root_cert: Option<PathBuf>,
    pub(crate) application_name: String,
    pub(crate) options: String,
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

/// libpq's `sslmode` names, as the modes the client library knows. vci
/// verifies certificates whenever it uses TLS, so `verify-ca` and
/// `verify-full` are `require`, and `allow` is `prefer`.
fn normalize_ssl_mode(m: &str) -> String {
    match m.trim().to_ascii_lowercase().as_str() {
        "verify-full" | "verify-ca" => "require".to_owned(),
        "allow" => "prefer".to_owned(),
        other => other.to_owned(),
    }
}

/// The connection string without `sslrootcert` (vci reads that file
/// itself), with `sslmode` in the client library's terms.
struct Stripped {
    text: String,
    root_cert: Option<String>,
    ssl_mode_given: bool,
}

fn is_url(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("postgres://") || l.starts_with("postgresql://")
}

fn strip(s: &str) -> Stripped {
    let mut root_cert = None;
    let mut ssl_mode_given = false;
    if is_url(s) {
        // The query starts where the client library starts it: at the
        // first `?` after the first `@` (a password may hold a `?`).
        let from = s.find('@').map_or(0, |a| a + 1);
        let (head, query) = match s[from..].find('?') {
            Some(q) => (&s[..from + q], Some(&s[from + q + 1..])),
            None => (s, None),
        };
        let mut kept: Vec<String> = Vec::new();
        for kv in query.into_iter().flat_map(|q| q.split('&')) {
            if kv.is_empty() {
                continue;
            }
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            match percent_decode(k).as_str() {
                "sslrootcert" => root_cert = Some(percent_decode(v)),
                "sslmode" => {
                    ssl_mode_given = true;
                    kept.push(format!(
                        "sslmode={}",
                        normalize_ssl_mode(&percent_decode(v))
                    ));
                }
                _ => kept.push(kv.to_owned()),
            }
        }
        let text = if kept.is_empty() {
            head.to_owned()
        } else {
            format!("{head}?{}", kept.join("&"))
        };
        Stripped {
            text,
            root_cert,
            ssl_mode_given,
        }
    } else {
        // A libpq key=value string. Only unquoted `sslrootcert=<path>`
        // and `sslmode=<mode>` are recognized here; anything else goes to
        // the client library as written.
        let mut kept: Vec<String> = Vec::new();
        for tok in s.split_whitespace() {
            if let Some(v) = tok.strip_prefix("sslrootcert=") {
                root_cert = Some(v.trim_matches('\'').to_owned());
            } else if let Some(v) = tok.strip_prefix("sslmode=") {
                ssl_mode_given = true;
                kept.push(format!(
                    "sslmode={}",
                    normalize_ssl_mode(v.trim_matches('\''))
                ));
            } else {
                kept.push(tok.to_owned());
            }
        }
        Stripped {
            text: kept.join(" "),
            root_cert,
            ssl_mode_given,
        }
    }
}

/// The text of a client-library error and its causes, with credentials
/// removed.
pub(crate) fn error_text(secret: &Secret, e: &postgres::Error) -> String {
    let text = match e.as_db_error() {
        Some(db) => format!("{} (SQLSTATE {})", db.message(), db.code().code()),
        None => {
            let mut s = e.to_string();
            let mut src = e.source();
            while let Some(x) = src {
                s.push_str(": ");
                s.push_str(&x.to_string());
                src = x.source();
            }
            s
        }
    };
    secret.scrub(&text)
}

fn is_local(h: &Host) -> bool {
    match h {
        Host::Tcp(s) => {
            let s = s.trim_start_matches('[').trim_end_matches(']');
            s.eq_ignore_ascii_case("localhost") || s == "127.0.0.1" || s == "::1"
        }
        #[cfg(unix)]
        Host::Unix(_) => true,
    }
}

fn host_text(h: &Host) -> String {
    match h {
        Host::Tcp(s) if s.contains(':') && !s.starts_with('[') => format!("[{s}]"),
        Host::Tcp(s) => s.clone(),
        #[cfg(unix)]
        Host::Unix(p) => p.display().to_string(),
    }
}

/// Where the server is, never with a credential. A URL with a userinfo
/// section is shown as written, redacted ([`vci_store::select::redact`],
/// which masks up to its last `@`) and without its query: the client
/// library ends the password at the first `@`, so a host it parsed may be
/// a piece of a password holding an unencoded `@`. Anything else is
/// described from the parsed settings ([`display_of`]).
fn display(text: &str, config: &postgres::Config) -> String {
    if is_url(text) && text.contains('@') {
        let r = vci_store::select::redact(text);
        return match r.split_once('?') {
            Some((head, _)) => head.to_owned(),
            None => r,
        };
    }
    display_of(config)
}

/// `postgres://[***@]host[:port][,host[:port]]/db`: built from the parsed
/// settings, so it can never carry a password.
fn display_of(config: &postgres::Config) -> String {
    let user = if config.get_user().is_some() || config.get_password().is_some() {
        "***@"
    } else {
        ""
    };
    let ports = config.get_ports();
    let port_of = |i: usize| -> Option<u16> {
        match ports.len() {
            0 => None,
            1 => Some(ports[0]),
            _ => ports.get(i).copied(),
        }
    };
    let mut hosts: Vec<String> = config.get_hosts().iter().map(host_text).collect();
    if hosts.is_empty() {
        hosts = config
            .get_hostaddrs()
            .iter()
            .map(|a| match a {
                std::net::IpAddr::V6(v6) => format!("[{v6}]"),
                std::net::IpAddr::V4(v4) => v4.to_string(),
            })
            .collect();
    }
    let hp: Vec<String> = hosts
        .iter()
        .enumerate()
        .map(|(i, h)| match port_of(i) {
            Some(p) => format!("{h}:{p}"),
            None => h.clone(),
        })
        .collect();
    format!(
        "postgres://{user}{}/{}",
        hp.join(","),
        config.get_dbname().unwrap_or("")
    )
}

/// One configuration per host named, each with every other setting of
/// `c`, so that each host is tried within a bound of its own: a host that
/// accepts and never answers cannot use up the time of the next. With one
/// host, or with `load_balance_hosts=random` (the client library shuffles
/// the hosts itself), `c` alone.
fn attempts(c: &postgres::Config) -> Vec<postgres::Config> {
    let n = c.get_hosts().len().max(c.get_hostaddrs().len());
    if n <= 1 || matches!(c.get_load_balance_hosts(), LoadBalanceHosts::Random) {
        return vec![c.clone()];
    }
    (0..n)
        .map(|i| {
            let mut o = postgres::Config::new();
            match c.get_hosts().get(i) {
                Some(Host::Tcp(h)) => o.host(h),
                #[cfg(unix)]
                Some(Host::Unix(p)) => o.host_path(p),
                None => &mut o,
            };
            if let Some(a) = c.get_hostaddrs().get(i) {
                o.hostaddr(*a);
            }
            let ports = c.get_ports();
            if let Some(p) = ports.get(i).or(ports.first()) {
                o.port(*p);
            }
            if let Some(v) = c.get_user() {
                o.user(v);
            }
            if let Some(v) = c.get_password() {
                o.password(v);
            }
            if let Some(v) = c.get_dbname() {
                o.dbname(v);
            }
            if let Some(v) = c.get_options() {
                o.options(v);
            }
            if let Some(v) = c.get_application_name() {
                o.application_name(v);
            }
            if let Some(v) = c.get_connect_timeout() {
                o.connect_timeout(*v);
            }
            if let Some(v) = c.get_tcp_user_timeout() {
                o.tcp_user_timeout(*v);
            }
            if let Some(v) = c.get_keepalives_interval() {
                o.keepalives_interval(v);
            }
            if let Some(v) = c.get_keepalives_retries() {
                o.keepalives_retries(v);
            }
            o.ssl_mode(c.get_ssl_mode())
                .ssl_negotiation(c.get_ssl_negotiation())
                .keepalives(c.get_keepalives())
                .keepalives_idle(c.get_keepalives_idle())
                .target_session_attrs(c.get_target_session_attrs())
                .channel_binding(c.get_channel_binding());
            o
        })
        .collect()
}

fn millis(d: Duration) -> u128 {
    d.as_millis().max(1)
}

impl ConnSpec {
    /// Parse `VCI_STORE_URL` and add vci's session settings. No I/O.
    pub(crate) fn parse(
        secret: &Secret,
        connect_timeout: Duration,
        statement_timeout: Duration,
        command: &str,
    ) -> Result<ConnSpec, StoreError> {
        // The string itself is never printed, not even redacted: a libpq
        // `password='a b'` would defeat the redaction.
        let s = strip(secret.expose().trim());
        let mut config: postgres::Config = s.text.parse().map_err(|e: postgres::Error| {
            // The client library quotes text from the string only for an
            // unknown option and an unexpected character, either of which
            // may be a piece of a password it split differently.
            let text = error_text(secret, &e);
            let text = if text.contains("unknown option") {
                "an unknown option (its name is not printed)".to_owned()
            } else if text.contains("unexpected character") {
                "an unexpected character (not printed)".to_owned()
            } else {
                text
            };
            StoreError::Config(format!(
                "$VCI_STORE_URL is not a PostgreSQL connection string (it was not printed): {text}"
            ))
        })?;
        if config.get_hosts().is_empty() && config.get_hostaddrs().is_empty() {
            return Err(StoreError::Config(
                "$VCI_STORE_URL names no host (it was not printed)".to_owned(),
            ));
        }
        let ssl_mode = if s.ssl_mode_given {
            config.get_ssl_mode()
        } else {
            let local = config.get_hosts().iter().all(is_local)
                && config.get_hostaddrs().iter().all(|a| a.is_loopback());
            if local {
                SslMode::Prefer
            } else {
                SslMode::Require
            }
        };
        config.ssl_mode(ssl_mode);
        if config.get_connect_timeout().is_none() {
            config.connect_timeout(connect_timeout);
        }
        config.keepalives(true);
        config.keepalives_idle(Duration::from_secs(10));
        if config.get_tcp_user_timeout().is_none() {
            config.tcp_user_timeout(Duration::from_secs(30));
        }
        let ours = format!(
            "-c statement_timeout={} -c lock_timeout={} -c idle_in_transaction_session_timeout={}",
            millis(statement_timeout),
            millis(LOCK_TIMEOUT),
            millis(IDLE_IN_TRANSACTION)
        );
        let options = match config.get_options() {
            Some(o) if !o.trim().is_empty() => format!("{} {ours}", o.trim()),
            _ => ours,
        };
        config.options(&options);
        let application_name = format!("vci {} {command}", env!("CARGO_PKG_VERSION"));
        config.application_name(&application_name);
        let connect_timeout = config
            .get_connect_timeout()
            .copied()
            .unwrap_or(connect_timeout);
        Ok(ConnSpec {
            url_name: "$VCI_STORE_URL",
            display: display(&s.text, &config),
            attempts: attempts(&config),
            config,
            ssl_mode,
            root_cert: s.root_cert.filter(|p| !p.is_empty()).map(PathBuf::from),
            connect_timeout,
            statement_timeout,
            options,
            application_name,
        })
    }

    /// How long one connection may take in all (TCP, TLS, startup and
    /// authentication): the connect timeout for each host the string names.
    pub(crate) fn connect_deadline(&self) -> Duration {
        let hosts = self
            .config
            .get_hosts()
            .len()
            .max(self.config.get_hostaddrs().len())
            .max(1);
        self.connect_timeout
            .saturating_mul(u32::try_from(hosts).unwrap_or(u32::MAX))
    }

    /// Whether the connection string carries a password (else `[store]
    /// token_command` may supply one).
    pub(crate) fn has_password(&self) -> bool {
        self.config.get_password().is_some()
    }

    /// Where the server is, without credentials.
    pub(crate) fn display(&self) -> &str {
        &self.display
    }

    pub(crate) fn summary(&self) -> SpecSummary {
        SpecSummary {
            ssl_mode: match self.ssl_mode {
                SslMode::Disable => "disable",
                SslMode::Prefer => "prefer",
                SslMode::Require => "require",
                _ => "other",
            },
            root_cert: self.root_cert.clone(),
            application_name: self.application_name.clone(),
            options: self.options.clone(),
        }
    }
}

/// rustls with the `ring` provider, the webpki roots and `sslrootcert`.
fn build_tls(root_cert: Option<&PathBuf>) -> Result<MakeRustlsConnect, String> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(p) = root_cert {
        let pem = std::fs::read(p).map_err(|e| format!("sslrootcert {}: {e}", p.display()))?;
        let mut n = 0;
        for c in CertificateDer::pem_slice_iter(&pem) {
            let c = c.map_err(|e| format!("sslrootcert {}: {e}", p.display()))?;
            roots
                .add(c)
                .map_err(|e| format!("sslrootcert {}: {e}", p.display()))?;
            n += 1;
        }
        if n == 0 {
            return Err(format!(
                "sslrootcert {}: no PEM certificate in the file",
                p.display()
            ));
        }
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

// ---- counting statements ------------------------------------------------------

/// A pooled client that counts every statement it sends.
pub(crate) struct Db<'c> {
    client: &'c mut Client,
    n: &'c AtomicU64,
}

impl Db<'_> {
    pub(crate) fn query(
        &mut self,
        sql: &str,
        params: &[P<'_>],
    ) -> Result<Vec<Row>, postgres::Error> {
        self.n.fetch_add(1, Ordering::Relaxed);
        self.client.query_typed(sql, params)
    }

    pub(crate) fn execute(&mut self, sql: &str, params: &[P<'_>]) -> Result<u64, postgres::Error> {
        self.n.fetch_add(1, Ordering::Relaxed);
        self.client.execute_typed(sql, params)
    }

    /// Stream the rows of `sql` to `each`.
    pub(crate) fn for_each(
        &mut self,
        sql: &str,
        params: &[P<'_>],
        mut each: impl FnMut(Row) -> Result<(), postgres::Error>,
    ) -> Result<(), postgres::Error> {
        use postgres::fallible_iterator::FallibleIterator;
        self.n.fetch_add(1, Ordering::Relaxed);
        let mut it = self.client.query_typed_raw(sql, params.iter().cloned())?;
        while let Some(row) = it.next()? {
            each(row)?;
        }
        Ok(())
    }

    /// `BEGIN` (counted, as its `COMMIT` is).
    pub(crate) fn tx(&mut self) -> Result<Tx<'_>, postgres::Error> {
        self.n.fetch_add(1, Ordering::Relaxed);
        Ok(Tx {
            tx: self.client.transaction()?,
            n: self.n,
        })
    }
}

/// A transaction that counts its statements.
pub(crate) struct Tx<'c> {
    tx: Transaction<'c>,
    n: &'c AtomicU64,
}

impl Tx<'_> {
    pub(crate) fn query(
        &mut self,
        sql: &str,
        params: &[P<'_>],
    ) -> Result<Vec<Row>, postgres::Error> {
        self.n.fetch_add(1, Ordering::Relaxed);
        self.tx.query_typed(sql, params)
    }

    pub(crate) fn execute(&mut self, sql: &str, params: &[P<'_>]) -> Result<u64, postgres::Error> {
        self.n.fetch_add(1, Ordering::Relaxed);
        self.tx.execute_typed(sql, params)
    }

    /// Several statements without parameters, in one round trip (DDL).
    pub(crate) fn batch_execute(&mut self, sql: &str) -> Result<(), postgres::Error> {
        self.n.fetch_add(1, Ordering::Relaxed);
        self.tx.batch_execute(sql)
    }

    pub(crate) fn commit(self) -> Result<(), postgres::Error> {
        self.n.fetch_add(1, Ordering::Relaxed);
        self.tx.commit()
    }
}

// ---- what a failure means -------------------------------------------------------

/// What a statement is, for retries and for the words of its errors.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Op {
    /// The operation a privilege error names ("read", "write").
    pub(crate) verb: &'static str,
    /// Idempotent: retried once on a lost connection, a serialization
    /// failure or a deadlock.
    pub(crate) retry: bool,
    /// An upsert that two writers of one slot may race on: a unique
    /// violation is retried too (the next attempt sees the other row).
    pub(crate) upsert: bool,
}

pub(crate) const READ: Op = Op {
    verb: "read",
    retry: true,
    upsert: false,
};
pub(crate) const WRITE: Op = Op {
    verb: "write",
    retry: true,
    upsert: true,
};

/// Why a call failed: the schema is not there (reads answer as an empty
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
    /// `absent` when the schema is not there, else the error.
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

enum Class {
    /// Try again (on a new connection when `lost`).
    Retry {
        lost: bool,
    },
    Absent,
    /// Fail; latch the circuit breaker when `latch`; drop the connection
    /// when `lost`.
    Fail {
        err: StoreError,
        latch: bool,
        lost: bool,
    },
}

fn io_cause(e: &postgres::Error) -> Option<std::io::ErrorKind> {
    let mut src = e.source();
    while let Some(x) = src {
        if let Some(io) = x.downcast_ref::<std::io::Error>() {
            return Some(io.kind());
        }
        src = x.source();
    }
    None
}

// ---- the pool and the breaker ---------------------------------------------------

struct Pool {
    idle: Vec<Client>,
    open: usize,
}

/// The connections of one store handle.
pub(crate) struct Conn {
    spec: ConnSpec,
    secret: Secret,
    /// The password `[store] token_command` prints, when the connection
    /// string has none: fetched before the first connection.
    password: Option<Credential>,
    tls: OnceLock<Result<MakeRustlsConnect, String>>,
    pool: Mutex<Pool>,
    freed: Condvar,
    max: usize,
    broken: OnceLock<String>,
    statements: AtomicU64,
}

/// A client checked out of the pool; it goes back when dropped, unless its
/// connection was lost.
pub(crate) struct Guard<'a> {
    conn: &'a Conn,
    client: Option<Client>,
    lost: bool,
}

impl Guard<'_> {
    fn db(&mut self) -> Db<'_> {
        Db {
            client: self.client.as_mut().expect("a checked-out client"),
            n: &self.conn.statements,
        }
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let Some(c) = self.client.take() else {
            return;
        };
        let mut p = self.conn.lock_pool();
        if self.lost || c.is_closed() {
            p.open = p.open.saturating_sub(1);
        } else {
            p.idle.push(c);
        }
        drop(p);
        self.conn.freed.notify_one();
    }
}

impl Conn {
    pub(crate) fn new(
        spec: ConnSpec,
        secret: Secret,
        password: Option<Credential>,
        max: usize,
    ) -> Conn {
        Conn {
            spec,
            secret,
            password,
            tls: OnceLock::new(),
            pool: Mutex::new(Pool {
                idle: Vec::new(),
                open: 0,
            }),
            freed: Condvar::new(),
            max: max.max(1),
            broken: OnceLock::new(),
            statements: AtomicU64::new(0),
        }
    }

    pub(crate) fn spec(&self) -> &ConnSpec {
        &self.spec
    }

    /// The text of `e`, without the connection string's password or the
    /// one `[store] token_command` printed.
    pub(crate) fn error_text(&self, e: &postgres::Error) -> String {
        let text = error_text(&self.secret, e);
        match &self.password {
            Some(p) => p.scrub(&text),
            None => text,
        }
    }

    /// Statements sent so far (`BEGIN` and `COMMIT` included).
    pub(crate) fn statements(&self) -> u64 {
        self.statements.load(Ordering::Relaxed)
    }

    fn lock_pool(&self) -> MutexGuard<'_, Pool> {
        self.pool.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The circuit breaker: after the first failure to reach the server or
    /// a wait that ran out, every call of this handle fails at once.
    pub(crate) fn check(&self) -> Result<(), StoreError> {
        match self.broken.get() {
            Some(d) => Err(StoreError::unavailable(
                KIND,
                format!("{d} (failed earlier in this process; not retried)"),
            )),
            None => Ok(()),
        }
    }

    /// Latch `e` when it says the server cannot be used, and return it.
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

    fn tls(&self) -> Result<MakeRustlsConnect, StoreError> {
        match self
            .tls
            .get_or_init(|| build_tls(self.spec.root_cert.as_ref()))
        {
            Ok(t) => Ok(t.clone()),
            Err(e) => Err(StoreError::Config(format!("{}: {e}", self.spec.url_name))),
        }
    }

    /// Connect, bounded as a whole. The client library bounds only the TCP
    /// connect: a peer that accepts and then never answers (a frozen or
    /// failing-over server, a stuck proxy, another service on the port)
    /// would hold the TLS and startup exchange forever, because its kernel
    /// acknowledges every packet. So each host named is tried in turn on a
    /// thread of its own, given up after its share of what is left of the
    /// connect deadline (the connect timeout per host): the time left
    /// divided by the hosts left, never less than 1 s (or the connect
    /// timeout, if shorter). A host that hangs therefore does not keep the
    /// next from being tried. A thread given up on ends with its socket,
    /// and drops a connection that arrives too late. The last host's error
    /// is the result, as with the client library's own failover.
    fn connect(&self) -> Result<Client, StoreError> {
        let tls = match self.spec.ssl_mode {
            SslMode::Disable => None,
            _ => Some(self.tls()?),
        };
        // The token command runs before the first connection, at most once
        // per process, and outside the connect deadline.
        let password = match &self.password {
            Some(p) => Some(p.get(KIND).map_err(|e| self.latch(e))?),
            None => None,
        };
        let deadline = Instant::now() + self.spec.connect_deadline();
        let floor = self.spec.connect_timeout.min(Duration::from_secs(1));
        let n = self.spec.attempts.len();
        let mut last = None;
        for (i, config) in self.spec.attempts.iter().enumerate() {
            let left = u32::try_from(n - i).unwrap_or(u32::MAX);
            let share = deadline.saturating_duration_since(Instant::now()) / left;
            let mut config = config.clone();
            if let Some(p) = &password {
                config.password(p.expose());
            }
            match self.attempt(config, tls.clone(), share.max(floor)) {
                Ok(c) => return Ok(c),
                Err(e) => last = Some(e),
            }
        }
        Err(self.latch(last.expect("at least one host")))
    }

    /// One connection attempt, given up after `bound`.
    fn attempt(
        &self,
        config: postgres::Config,
        tls: Option<MakeRustlsConnect>,
        bound: Duration,
    ) -> Result<Client, StoreError> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let spawned = std::thread::Builder::new()
            .name("vci-postgres-connect".into())
            .spawn(move || {
                let r = match tls {
                    None => config.connect(NoTls),
                    Some(t) => config.connect(t),
                };
                // Nobody waits any more after a timeout: the client is
                // dropped, closing the connection.
                let _ = tx.send(r);
            });
        if let Err(e) = spawned {
            return Err(StoreError::unavailable(
                KIND,
                format!("cannot start a thread to connect: {e}"),
            ));
        }
        let r = match rx.recv_timeout(bound) {
            Ok(r) => r,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Err(StoreError::Timeout {
                    backend: KIND,
                    operation: "connecting",
                    after: bound,
                });
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(StoreError::unavailable(
                    KIND,
                    format!(
                        "cannot connect to {}: the attempt failed",
                        self.spec.display
                    ),
                ));
            }
        };
        r.map_err(|e| {
            let text = self.error_text(&e);
            if io_cause(&e) == Some(std::io::ErrorKind::TimedOut) {
                StoreError::Timeout {
                    backend: KIND,
                    operation: "connecting",
                    after: self.spec.connect_timeout,
                }
            } else {
                StoreError::unavailable(
                    KIND,
                    format!("cannot connect to {}: {text}", self.spec.display),
                )
            }
        })
    }

    /// A client from the pool, connecting when none is idle and the pool
    /// is not full; waiting at most the connect timeout otherwise.
    pub(crate) fn checkout(&self) -> Result<Guard<'_>, StoreError> {
        self.check()?;
        let deadline = Instant::now() + self.spec.connect_timeout;
        let mut p = self.lock_pool();
        loop {
            if let Some(c) = p.idle.pop() {
                return Ok(Guard {
                    conn: self,
                    client: Some(c),
                    lost: false,
                });
            }
            if p.open < self.max {
                p.open += 1;
                drop(p);
                return match self.connect() {
                    Ok(c) => Ok(Guard {
                        conn: self,
                        client: Some(c),
                        lost: false,
                    }),
                    Err(e) => {
                        let mut p = self.lock_pool();
                        p.open = p.open.saturating_sub(1);
                        drop(p);
                        self.freed.notify_one();
                        Err(e)
                    }
                };
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(StoreError::Timeout {
                    backend: KIND,
                    operation: "a connection from the pool",
                    after: self.spec.connect_timeout,
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

    fn classify(&self, e: &postgres::Error, op: Op, attempt: u32) -> Class {
        let text = self.error_text(e);
        let backend = |code: Option<&str>| {
            StoreError::backend(PgError {
                message: text.clone(),
                code: code.map(str::to_owned),
            })
        };
        if let Some(db) = e.as_db_error() {
            let code = db.code().code();
            return match code {
                "42P01" | "3F000" => Class::Absent,
                "40001" | "40P01" if op.retry && attempt < 2 => Class::Retry { lost: false },
                "40001" | "40P01" => Class::Fail {
                    err: StoreError::unavailable(KIND, text),
                    latch: false,
                    lost: false,
                },
                "23505" if op.upsert && attempt < 3 => Class::Retry { lost: false },
                "57014" => Class::Fail {
                    err: StoreError::Timeout {
                        backend: KIND,
                        operation: "a statement",
                        after: self.spec.statement_timeout,
                    },
                    latch: true,
                    lost: false,
                },
                "55P03" => Class::Fail {
                    err: StoreError::Timeout {
                        backend: KIND,
                        operation: "a lock",
                        after: LOCK_TIMEOUT,
                    },
                    latch: true,
                    lost: false,
                },
                "42501" | "25006" => Class::Fail {
                    err: StoreError::Denied {
                        backend: KIND,
                        operation: op.verb,
                        detail: text,
                    },
                    latch: false,
                    lost: false,
                },
                "53100" | "53200" => Class::Fail {
                    err: StoreError::unavailable(KIND, text),
                    latch: false,
                    lost: false,
                },
                c if c.starts_with("08")
                    || c.starts_with("57P")
                    || c.starts_with("28")
                    || c == "53300"
                    || c == "3D000" =>
                {
                    Class::Fail {
                        err: StoreError::unavailable(KIND, text),
                        latch: true,
                        lost: true,
                    }
                }
                c => Class::Fail {
                    err: backend(Some(c)),
                    latch: false,
                    lost: false,
                },
            };
        }
        if e.is_closed() || io_cause(e).is_some() {
            if op.retry && attempt == 0 {
                return Class::Retry { lost: true };
            }
            return Class::Fail {
                err: StoreError::unavailable(KIND, format!("lost the connection: {text}")),
                latch: true,
                lost: true,
            };
        }
        Class::Fail {
            err: backend(None),
            latch: false,
            lost: false,
        }
    }

    /// Run `f` on a pooled client, retrying as `op` allows. A missing
    /// relation or schema is [`Fail::Absent`].
    pub(crate) fn run<T>(
        &self,
        op: Op,
        mut f: impl FnMut(&mut Db<'_>) -> Result<T, postgres::Error>,
    ) -> Result<T, Fail> {
        let mut attempt = 0;
        loop {
            let mut g = self.checkout()?;
            let r = f(&mut g.db());
            match r {
                Ok(v) => return Ok(v),
                Err(e) => match self.classify(&e, op, attempt) {
                    Class::Retry { lost } => {
                        g.lost |= lost;
                        attempt += 1;
                    }
                    Class::Absent => return Err(Fail::Absent),
                    Class::Fail { err, latch, lost } => {
                        g.lost |= lost;
                        drop(g);
                        return Err(Fail::Store(if latch { self.latch(err) } else { err }));
                    }
                },
            }
        }
    }

    /// Whether connecting now would run `[store] token_command`
    /// ([`Credential::pending`]).
    pub(crate) fn password_pending(&self) -> bool {
        self.password.as_ref().is_some_and(Credential::pending)
    }

    /// Open a connection in the background, so the first call finds one
    /// (its TLS session too). Never blocks, never fails.
    pub(crate) fn warm(&self) {
        if let Ok(g) = self.checkout() {
            drop(g);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(url: &str) -> Result<ConnSpec, StoreError> {
        ConnSpec::parse(
            &Secret::new(url),
            Duration::from_secs(5),
            Duration::from_secs(30),
            "test",
        )
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%2Fb%20c"), "a/b c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%4"), "%4");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn sslrootcert_is_stripped_and_sslmode_mapped() {
        let s = strip("postgres://u:p@h/db?sslrootcert=%2Ftmp%2Fca.pem&sslmode=verify-full&x=1");
        assert_eq!(s.text, "postgres://u:p@h/db?sslmode=require&x=1");
        assert_eq!(s.root_cert.as_deref(), Some("/tmp/ca.pem"));
        assert!(s.ssl_mode_given);
        let s = strip("host=h sslrootcert=/ca.pem sslmode=allow user=u");
        assert_eq!(s.text, "host=h sslmode=prefer user=u");
        assert_eq!(s.root_cert.as_deref(), Some("/ca.pem"));
    }

    #[test]
    fn defaults_and_display() {
        let s = spec("postgres://u:pw@db.example:6543/ci").unwrap();
        assert_eq!(s.summary().ssl_mode, "require");
        assert_eq!(s.display(), "postgres://***@db.example:6543/ci");
        let s = spec("postgresql://127.0.0.1/x").unwrap();
        assert_eq!(s.summary().ssl_mode, "prefer");
        // The URL form names the default port.
        assert_eq!(s.display(), "postgres://127.0.0.1:5432/x");
        let s = spec("host=localhost user=u password=pw dbname=d").unwrap();
        assert_eq!(s.summary().ssl_mode, "prefer");
        assert_eq!(s.display(), "postgres://***@localhost/d");
        assert!(spec("postgres:///x").is_err());
    }

    /// A password holding an unencoded `@`: the client library takes the
    /// host to be `Zk9ss@db.example`, a piece of the password, so the
    /// display is the redacted URL, never a parsed host.
    #[test]
    fn a_url_with_userinfo_is_displayed_redacted_never_as_parsed() {
        let s = spec("postgres://u:Xq7pa@Zk9ss@db.example/ci?sslmode=disable").unwrap();
        assert_eq!(s.display(), "postgres://***@db.example/ci");
        let s = spec("postgres://u:Xq7pa?Zk9ss@db.example:6543/ci").unwrap();
        assert_eq!(s.display(), "postgres://***@db.example:6543/ci");
        let s = spec("host=db.example user=u password='Xq7pa@Zk9ss' dbname=ci").unwrap();
        assert_eq!(s.display(), "postgres://***@db.example/ci");
        // The query starts after the first `@`, as the client library
        // reads it: a `?` in the password does not hide `sslmode`.
        let t = strip("postgres://u:Xq7pa?Zk9ss@h/db?sslmode=verify-ca&sslrootcert=%2Fca.pem");
        assert_eq!(t.text, "postgres://u:Xq7pa?Zk9ss@h/db?sslmode=require");
        assert_eq!(t.root_cert.as_deref(), Some("/ca.pem"));
        assert!(t.ssl_mode_given);
    }

    /// Each host of a list is its own attempt, with every other setting.
    #[test]
    fn several_hosts_are_tried_one_by_one() {
        let s = spec("postgres://u:pw@h1:1,h2/ci?sslmode=disable&target_session_attrs=read-write")
            .unwrap();
        assert_eq!(s.connect_deadline(), Duration::from_secs(10));
        assert_eq!(s.attempts.len(), 2);
        for (a, (host, port)) in s.attempts.iter().zip([("h1", 1), ("h2", 5432)]) {
            assert_eq!(a.get_hosts(), &[Host::Tcp(host.to_owned())]);
            assert_eq!(a.get_ports(), &[port]);
            assert_eq!(a.get_user(), Some("u"));
            assert_eq!(a.get_password(), Some(&b"pw"[..]));
            assert_eq!(a.get_dbname(), Some("ci"));
            assert_eq!(a.get_options(), s.config.get_options());
            assert_eq!(a.get_application_name(), s.config.get_application_name());
            assert_eq!(a.get_connect_timeout(), Some(&Duration::from_secs(5)));
            assert_eq!(a.get_tcp_user_timeout(), s.config.get_tcp_user_timeout());
            assert!(matches!(a.get_ssl_mode(), SslMode::Disable));
            assert!(a.get_keepalives());
            assert!(matches!(
                a.get_target_session_attrs(),
                postgres::config::TargetSessionAttrs::ReadWrite
            ));
        }
        assert_eq!(spec("postgres://u@h/ci").unwrap().attempts.len(), 1);
        let random = spec("postgres://u@h1,h2/ci?load_balance_hosts=random").unwrap();
        assert_eq!(random.attempts.len(), 1);
        assert_eq!(random.attempts[0].get_hosts().len(), 2);
    }
}
