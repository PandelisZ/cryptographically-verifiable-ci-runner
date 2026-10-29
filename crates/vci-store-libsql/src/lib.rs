//! # `vci-store-libsql`: attestations in a libSQL database (Turso)
//!
//! A [`vci_store::AttestationStore`] kept in a libSQL database, selected
//! with `VCI_STORE=libsql` or a `libsql://` `VCI_STORE_URL`.
//! `docs/STORE-BACKENDS.md` (section 18) is its design. Three modes:
//!
//! * **Local** (no `VCI_STORE_URL`, or `file:<path>`): one file, by default
//!   `<git common dir>/vci-store.libsql`, in the SQLite store's format and
//!   with its code ([`vci_store_sqlite`]). libSQL's own engine is not linked
//!   in: its bundled SQLite and rusqlite's (git-meta's) export the same C
//!   symbols, and one process cannot hold both.
//! * **Remote** (`VCI_STORE_URL=libsql://<db>-<org>.turso.io`, `https://` or
//!   `http://`, or `[store] url`; the token in `VCI_STORE_TOKEN` or an
//!   `authToken` query parameter, else printed by `[store] token_command`
//!   when the store first connects): every read and write goes to the
//!   server over Hrana (HTTP), through the `libsql` crate. Reads are
//!   served from a per-handle cache that a prefetch fills (values in
//!   requests sized from the answers); writes are batched and sent as
//!   transactions of whole units of about a megabyte, one after the other,
//!   a transaction that fails sent again within the process's time for
//!   that and costing only its own units, values compressed with
//!   `VCI_STORE_COMPRESS=zstd` or `[store] compress`. Each repository's
//!   records live under a namespace (`VCI_STORE_NAMESPACE`, else the
//!   repository id) in tables of their own. Writes are shared at once (the publication gate applies).
//! * **Replica** (a remote URL plus `VCI_STORE_SYNC=replica`,
//!   `VCI_STORE_REPLICA=<path>` or `[store.libsql] replica = true`): reads
//!   come from a local file synced from the server when the store is first
//!   used and at each later prefetch (one request for everything that
//!   changed since the last sync); writes go to the server, then through to
//!   the file. A sync that fails leaves the file as it was: the plan and the
//!   run read it with a warning, `vci store`, fetch, push and prune fail.
//!
//! Every wait is bounded (the connect timeout for a connection and for the
//! server's first answer, the request timeout for a request, sent once
//! more when it runs out; a batch's writes that fail, two request timeouts
//! in all per process), the first failure to reach the server, a request
//! out of time twice, or writes that keep failing past that time latch a
//! circuit breaker, every error is a
//! [`StoreError`] whose message carries neither the URL's token nor
//! `VCI_STORE_TOKEN`, and no error is [`StoreError::Backend`] when the
//! store cannot be used (a statement the server refuses is).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod batch;
mod cache;
mod conn;
mod remote;
mod replica;

#[doc(hidden)]
pub mod testkit;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use vci_store::select::{
    self, Credential, DEFAULT_LIBSQL_FILE, DEFAULT_MANIFEST_GRACE, LibsqlMode, Selection,
};
use vci_store::{
    AttestationStore, BackendFactory, Caps, Columns, Hydration, NewAttestation, NewObject,
    OpenContext, Prefetch, StoreError, StoreStatus, StoredEnvelope, StoredManifest, StoredObject,
    WriteBatch, key,
};
use vci_store_sqlite::{SqliteOptions, SqliteStore};

pub use conn::LibsqlError;
pub use remote::table_prefix;
pub use vci_store_sqlite::Finish;

use conn::{Conn, KIND, LONG_RUNNING_TIMEOUT, Target};
use remote::Remote;
use replica::Replica;

/// `VCI_STORE_SYNC=off`: no `fsync` in the local file (local and replica
/// modes).
const ENV_SYNC: &str = "VCI_STORE_SYNC";

/// `VCI_STORE_COMPRESS=zstd` (or `[store] compress = "zstd"` in
/// `vci.toml`; the variable wins): write values to a server compressed
/// (remote and replica modes). Every vci from 2.8.2 reads them either way;
/// 2.8.1 and earlier read a compressed value as one they cannot read (its
/// unit runs), so it is turned on once every reader of the namespace is
/// 2.8.2 or later. `off` (or unset): as they are.
const ENV_COMPRESS: &str = select::ENV_COMPRESS;

/// Whether values are written compressed: `VCI_STORE_COMPRESS` when set
/// (any value but `zstd` and `off` is refused), else the selection's
/// (`[store] compress`, resolved with the variable by
/// [`select::resolve`]; read here again for a selection built without the
/// environment).
fn compress_setting(sel: &Selection) -> Result<bool, StoreError> {
    match std::env::var(ENV_COMPRESS) {
        Err(_) => Ok(sel.compress.value),
        Ok(v) if v.trim().is_empty() => Ok(sel.compress.value),
        Ok(v) if v.trim().eq_ignore_ascii_case("off") => Ok(false),
        Ok(v) if v.trim().eq_ignore_ascii_case("zstd") => Ok(true),
        Ok(v) => Err(StoreError::Config(format!(
            "${ENV_COMPRESS}={v:?}: expected zstd or off"
        ))),
    }
}

/// Opens the libSQL store (`VCI_STORE=libsql`, or a `libsql://`
/// `VCI_STORE_URL`).
#[derive(Debug, Clone, Copy, Default)]
pub struct LibsqlFactory;

impl BackendFactory for LibsqlFactory {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn summary(&self) -> &'static str {
        "a libSQL database: a local file, a server (Turso, sqld), or a local replica of one"
    }

    fn open(
        &self,
        sel: &Selection,
        cx: &OpenContext,
    ) -> Result<Arc<dyn AttestationStore>, StoreError> {
        Ok(Arc::new(LibsqlStore::open(sel, cx)?))
    }
}

enum Inner {
    Local(SqliteStore),
    Remote(Arc<Remote>),
    Replica(Arc<Replica>),
}

/// The libSQL store of one repository, in one of its three modes (see the
/// crate docs). One value serves every thread of a process.
pub struct LibsqlStore {
    inner: Inner,
}

/// `p` (absolute, or relative to the git common directory), or the default
/// file there.
fn file_path(p: Option<&str>, cx: &OpenContext) -> PathBuf {
    match p {
        None => cx.git_common_dir.join(DEFAULT_LIBSQL_FILE),
        Some(p) if Path::new(p).is_absolute() => PathBuf::from(p),
        Some(p) => cx.git_common_dir.join(p),
    }
}

impl LibsqlStore {
    /// Open the store `sel` describes, as [`LibsqlFactory`] does. Nothing is
    /// connected, read or created here: a bad setting is
    /// [`StoreError::Config`] at once, an unreachable server fails the first
    /// call within the connect timeout.
    ///
    /// The request timeout is the selection's, or ten minutes when
    /// [`OpenContext::long_running`] (`vci prune`), which also removes
    /// unreferenced manifests however recently they were put; otherwise a
    /// manifest put within the last hour is kept.
    pub fn open(sel: &Selection, cx: &OpenContext) -> Result<LibsqlStore, StoreError> {
        let opts = SqliteOptions {
            busy_timeout: sel.timeout.value,
            sync_off: std::env::var_os(ENV_SYNC).is_some_and(|v| v == "off"),
            kind: KIND,
            ..SqliteOptions::default()
        };
        let path = file_path(sel.libsql.path.as_ref().map(|p| p.value.as_str()), cx);
        let mode = sel.libsql.mode.value;
        if mode == LibsqlMode::Local {
            return Ok(LibsqlStore {
                inner: Inner::Local(SqliteStore::open_path(path, opts)),
            });
        }
        let Some(url) = &sel.url else {
            return Err(StoreError::Config(
                "the libsql store's remote and replica modes need $VCI_STORE_URL or [store] url (libsql://<database>-<organization>.turso.io)"
                    .into(),
            ));
        };
        let (target, token) = Target::parse(&url.value, sel.token.as_ref().map(|t| &t.value))
            .map_err(|e| select::name_url_source(e, url.source))?;
        // The token: `VCI_STORE_TOKEN`, else the URL's `authToken`, else
        // what `[store] token_command` prints when the store first
        // connects (never run when either of the others is there).
        let token = match token {
            Some(t) => Some(Credential::given(
                t,
                if sel.token.is_some() {
                    "$VCI_STORE_TOKEN"
                } else {
                    "the URL's authToken"
                },
            )),
            None => sel.token_credential(cx),
        };
        let explicit_namespace = match &sel.namespace {
            Some(n) if !remote::is_namespace(&n.value) => {
                return Err(StoreError::Config(format!(
                    "namespace {:?} (from {}): expected 1 to 128 of A-Z a-z 0-9 . _ : / @ -",
                    n.value, n.source
                )));
            }
            Some(n) => Some(n.value.clone()),
            None => None,
        };
        let timeout = if cx.long_running {
            sel.timeout.value.max(LONG_RUNNING_TIMEOUT)
        } else {
            sel.timeout.value
        };
        let grace = if cx.long_running {
            Duration::ZERO
        } else {
            DEFAULT_MANIFEST_GRACE
        };
        let conn = Conn::new(
            target,
            url.value.clone(),
            select::url_name(url.source),
            token,
            sel.connect_timeout.value,
            timeout,
            cx.jobs,
        );
        let remote = Arc::new(Remote::new(
            conn,
            explicit_namespace,
            Arc::clone(&cx.repo_id),
            cx.git_common_dir.clone(),
            grace,
            compress_setting(sel)?,
        ));
        Ok(LibsqlStore {
            inner: match mode {
                LibsqlMode::Replica => {
                    Inner::Replica(Arc::new(Replica::new(remote, path, opts, &cx.command)))
                }
                _ => Inner::Remote(remote),
            },
        })
    }

    /// Local file, remote server, or replica of one.
    pub fn mode(&self) -> LibsqlMode {
        match &self.inner {
            Inner::Local(_) => LibsqlMode::Local,
            Inner::Remote(_) => LibsqlMode::Remote,
            Inner::Replica(_) => LibsqlMode::Replica,
        }
    }

    fn remote(&self) -> Option<&Arc<Remote>> {
        match &self.inner {
            Inner::Local(_) => None,
            Inner::Remote(r) => Some(r),
            Inner::Replica(r) => Some(&r.remote),
        }
    }

    /// How many HTTP requests this handle has sent to the server (0 in the
    /// local mode), for tests of the request budget.
    pub fn requests(&self) -> u64 {
        self.remote().map_or(0, |r| r.conn.requests())
    }

    /// Of [`LibsqlStore::requests`], those sent again because the server
    /// was busy (another writer held the database), had dropped the
    /// stream, or the connection was lost under them (a keep-alive
    /// connection closed while it sat idle): what a request budget does
    /// not count.
    pub fn retries(&self) -> u64 {
        self.remote().map_or(0, |r| r.conn.retries())
    }

    /// The local file (local mode) or the replica (replica mode).
    pub fn path(&self) -> Option<&Path> {
        match &self.inner {
            Inner::Local(s) => Some(s.path()),
            Inner::Remote(_) => None,
            Inner::Replica(r) => Some(&r.path),
        }
    }

    /// This repository's namespace on the server (the configured one, else
    /// the repository id); `None` in the local mode.
    pub fn namespace(&self) -> Option<Result<String, StoreError>> {
        self.remote().map(|r| r.ns().map(str::to_owned))
    }

    /// Write values compressed from now on (`VCI_STORE_COMPRESS=zstd`), or
    /// not (tests).
    #[doc(hidden)]
    pub fn __compress_for_test(&self, on: bool) {
        if let Some(r) = self.remote() {
            r.set_compress(on);
        }
    }

    /// Bytes of values (and other text and blob columns) read from the
    /// server so far, as stored (tests of what a plan reads).
    pub fn received(&self) -> u64 {
        self.remote().map_or(0, |r| r.conn.received())
    }

    /// Run `statements` on the server in one transaction, behind the
    /// store's back (tests that write raw rows).
    #[doc(hidden)]
    pub fn __execute_for_test(&self, statements: &[String]) -> Result<(), StoreError> {
        let r = self
            .remote()
            .ok_or_else(|| StoreError::other("a local store has no server"))?;
        r.conn.batch(conn::WRITE, statements).map_err(|f| match f {
            conn::Fail::Absent => StoreError::other("no such table"),
            conn::Fail::Store(e) => e,
        })
    }

    /// The rows `sql` returns from the server (tests).
    #[doc(hidden)]
    pub fn __query_for_test(&self, sql: &str) -> Result<Vec<Vec<String>>, StoreError> {
        let r = self
            .remote()
            .ok_or_else(|| StoreError::other("a local store has no server"))?;
        let rows = r
            .conn
            .query(conn::READ, sql, Vec::new())
            .map_err(|f| match f {
                conn::Fail::Absent => StoreError::other("no such table"),
                conn::Fail::Store(e) => e,
            })?;
        Ok(rows
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|v| match v {
                        libsql::Value::Null => "NULL".to_owned(),
                        libsql::Value::Integer(n) => n.to_string(),
                        libsql::Value::Real(f) => f.to_string(),
                        libsql::Value::Text(s) => s,
                        libsql::Value::Blob(b) => String::from_utf8_lossy(&b).into_owned(),
                    })
                    .collect()
            })
            .collect())
    }

    /// `vci store upgrade --begin`: bring the namespace to the format-3
    /// layout (STORE-V2 section 2.1: the nullable columns, the `objects`
    /// and `gone` tables, `vci_schema.v2 = 1`) in one request of its own,
    /// ahead of the first 2.9 write, which would otherwise do the same
    /// before its batch. Idempotent; whether anything was sent. Local: the
    /// file's ([`SqliteStore::upgrade_begin`]).
    pub fn upgrade_begin(&self) -> Result<bool, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.upgrade_begin(),
            Inner::Remote(r) => r.upgrade(),
            Inner::Replica(p) => p.remote.upgrade(),
        }
    }

    /// `vci store upgrade --finish`. Local: the file's
    /// ([`SqliteStore::upgrade_finish`]). On a server: refused with the
    /// count while a row of the namespace is not a format-3 record
    /// ([`Finish::FormatOneRows`], STORE-V2 section 5 step 4); at zero the
    /// step that drops the `manifests` table and the change log is
    /// [`StoreError::Unsupported`] in this release (the statements of a
    /// version-2 namespace are a later vci's), and the namespace stays at
    /// version 1, which every 2.8 and 2.9 reads.
    pub fn upgrade_finish(&self) -> Result<Finish, StoreError> {
        let r = match &self.inner {
            Inner::Local(s) => return s.upgrade_finish(),
            Inner::Remote(r) => r,
            Inner::Replica(p) => &p.remote,
        };
        let n = r.format_one_rows()?;
        if n > 0 {
            return Ok(Finish::FormatOneRows(n));
        }
        Err(StoreError::Unsupported {
            backend: KIND,
            operation: "finishing the format-3 upgrade (dropping the manifests table and the change log): a later vci does it",
        })
    }

    /// The policy's `max_ttl`: the server's `gone` rows (the deletions a
    /// replica syncs) are purged after the larger of it and 30 days, so
    /// that no record a replica could still serve outlives the deletion it
    /// would have synced. Without it, 30 days.
    pub fn set_max_ttl(&self, max_ttl: Duration) {
        if let Some(r) = self.remote() {
            r.set_max_ttl(max_ttl);
        }
    }

    /// Write transactions this handle committed on the server, the bytes
    /// of values and objects sent in them as literals, and the bytes of
    /// their statements in all (tests of the write model; zeros in the
    /// local mode).
    pub fn written(&self) -> (u64, u64, u64) {
        self.remote().map_or((0, 0, 0), |r| r.written())
    }

    /// The local store behind the local mode, or the replica (synced the
    /// first time it is asked for).
    fn local(&self) -> Result<&SqliteStore, StoreError> {
        match &self.inner {
            Inner::Local(s) => Ok(s),
            Inner::Replica(r) => r.local(),
            Inner::Remote(_) => unreachable!("a remote store has no local file"),
        }
    }

    /// Where reads go: the server (the remote mode, and a replica whose
    /// file missed a write of this handle), else the file.
    fn reads_from_server(&self) -> Option<&Remote> {
        match &self.inner {
            Inner::Remote(r) => Some(r),
            Inner::Replica(p) if p.degraded() => Some(&p.remote),
            _ => None,
        }
    }
}

impl fmt::Debug for LibsqlStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let location = match &self.inner {
            Inner::Local(s) => s.path().display().to_string(),
            Inner::Remote(r) => r.location(false),
            Inner::Replica(r) => format!("{} of {}", r.path.display(), r.remote.location(false)),
        };
        f.debug_struct("LibsqlStore")
            .field("mode", &self.mode().name())
            .field("location", &location)
            .field("requests", &self.requests())
            .finish_non_exhaustive()
    }
}

/// Run `$local` on the local file (local and replica modes) or `$remote`
/// on the server (the remote mode, and a replica reading from the server).
macro_rules! by_mode {
    ($self:ident, $s:ident => $local:expr, $r:ident => $remote:expr) => {
        match $self.reads_from_server() {
            Some($r) => $remote,
            None => {
                let $s = $self.local()?;
                $local
            }
        }
    };
}

impl AttestationStore for LibsqlStore {
    fn kind(&self) -> &'static str {
        KIND
    }

    /// `<file> (local)`, `<url> namespace <ns> (remote)` or `<file> (replica
    /// of <url> namespace <ns>)`: the URL without its query or a token.
    fn location(&self) -> String {
        match &self.inner {
            Inner::Local(s) => format!("{} (local)", s.path().display()),
            Inner::Remote(r) => format!("{} (remote)", r.location(true)),
            Inner::Replica(r) => format!(
                "{} (replica of {})",
                r.path.display(),
                r.remote.location(true)
            ),
        }
    }

    /// Local: the SQLite store's (objects and columns as its file keeps
    /// them). Remote and replica: objects and columns on the server (a
    /// replica's file keeps neither; its object and column reads ask the
    /// server, as `orphan_manifests` does).
    fn caps(&self) -> Caps {
        match &self.inner {
            Inner::Local(s) => s.caps(),
            Inner::Remote(_) => Caps::LOCAL
                .with_shared_writes(true)
                .with_hints(true)
                .with_remote_reads(true)
                .with_objects(true)
                .with_columns(true),
            Inner::Replica(_) => Caps::LOCAL
                .with_shared_writes(true)
                .with_hints(true)
                .with_objects(true)
                .with_columns(true),
        }
    }

    /// [`LibsqlStore::set_max_ttl`]: the `gone` purge horizon on a server.
    fn set_max_ttl(&self, max_ttl: Duration) {
        LibsqlStore::set_max_ttl(self, max_ttl);
    }

    fn status(&self) -> Result<StoreStatus, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.status(),
            Inner::Remote(r) => r.status(),
            Inner::Replica(r) if r.degraded() => r.remote.status(),
            Inner::Replica(r) => {
                r.remote.ns()?;
                match r.local()?.status()? {
                    StoreStatus::Absent { .. } => Ok(StoreStatus::Absent {
                        advice: format!(
                            "nothing was synced from {} yet; the first `vci run` stores records there",
                            r.remote.conn.display()
                        ),
                    }),
                    ready => Ok(ready),
                }
            }
        }
    }

    fn list_units(&self, test_ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
        by_mode!(self, s => s.list_units(test_ids), r => r.list_units(test_ids))
    }

    fn list_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
        by_mode!(self, s => s.list_all(), r => r.list_all())
    }

    /// A replica's, before its caller's first prefetch, syncs what changed
    /// first: a key removed since it was listed reads as gone, as on the
    /// server.
    fn read_values(&self, envs: &mut [&mut StoredEnvelope]) -> Result<(), StoreError> {
        match &self.inner {
            Inner::Replica(p) if !p.degraded() => p.current()?.read_values(envs),
            _ => by_mode!(self, s => s.read_values(envs), r => r.read_values(envs)),
        }
    }

    fn manifest(&self, root: &str) -> Result<Option<StoredManifest>, StoreError> {
        by_mode!(self, s => s.manifest(root), r => r.manifest(root))
    }

    fn manifest_roots(&self) -> Result<Vec<String>, StoreError> {
        by_mode!(self, s => s.manifest_roots(), r => r.manifest_roots())
    }

    /// A replica's writes need a usable replica: a file that is one, in a
    /// directory vci can write (a batch checked it when it opened).
    fn put(&self, att: &NewAttestation<'_>) -> Result<StoredEnvelope, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.put(att),
            Inner::Remote(r) if batch::is_open(r) => batch::put(r, att),
            Inner::Remote(r) => batch::put_now(r, att, None),
            Inner::Replica(p) if batch::is_open(&p.remote) => batch::put(&p.remote, att),
            Inner::Replica(p) => {
                p.writable()?;
                batch::put_now(&p.remote, att, Some(&p.after()))
            }
        }
    }

    fn put_manifest(&self, root: &str, bytes: &[u8]) -> Result<bool, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.put_manifest(root, bytes),
            Inner::Remote(r) if batch::is_open(r) => batch::put_manifest(r, root, bytes),
            Inner::Remote(r) => batch::put_manifest_now(r, root, bytes, None),
            Inner::Replica(p) if batch::is_open(&p.remote) => {
                batch::put_manifest(&p.remote, root, bytes)
            }
            Inner::Replica(p) => {
                p.writable()?;
                batch::put_manifest_now(&p.remote, root, bytes, Some(&p.after()))
            }
        }
    }

    fn remove(&self, doomed: Vec<StoredEnvelope>) -> Result<Vec<StoredEnvelope>, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.remove(doomed),
            Inner::Remote(r) if batch::is_open(r) => batch::remove(r, doomed),
            Inner::Remote(r) => batch::remove_now(r, doomed, None),
            Inner::Replica(p) if batch::is_open(&p.remote) => batch::remove(&p.remote, doomed),
            Inner::Replica(p) => {
                p.writable()?;
                batch::remove_now(&p.remote, doomed, Some(&p.after()))
            }
        }
    }

    /// On a server, keeps (and does not count) a root that an attestation
    /// or another manifest (as its base) references, or that was put within
    /// the last hour (no grace for a long-running command such as
    /// `vci prune`). While a batch is open on this thread, the roots it
    /// will write or reference are kept too.
    fn remove_manifests(&self, roots: &[&str]) -> Result<usize, StoreError> {
        let remote = match &self.inner {
            Inner::Local(s) => return s.remove_manifests(roots),
            Inner::Remote(r) => r,
            Inner::Replica(p) => &p.remote,
        };
        for r in roots {
            key::check_hex("input root", r)?;
        }
        let rest: Vec<&str> = match batch::queued_roots(remote) {
            Some(queued) => roots
                .iter()
                .copied()
                .filter(|r| !queued.contains(*r))
                .collect(),
            None => roots.to_vec(),
        };
        let removed = batch::remove_manifests_now(remote, &rest)?;
        if let Inner::Replica(p) = &self.inner
            && !removed.is_empty()
            && !p.degraded()
            && let Ok(local) = p.local()
        {
            let removed: Vec<&str> = removed.iter().map(String::as_str).collect();
            let _ = local.remove_manifests(&removed);
        }
        Ok(removed.len())
    }

    fn read_units(&self, test_ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
        by_mode!(self, s => s.read_units(test_ids), r => r.read_units(test_ids))
    }

    fn read_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
        by_mode!(self, s => s.read_all(), r => r.read_all())
    }

    fn count(&self) -> Result<usize, StoreError> {
        by_mode!(self, s => s.count(), r => r.count())
    }

    fn manifests(&self, roots: &[&str]) -> Result<Vec<Option<StoredManifest>>, StoreError> {
        by_mode!(self, s => s.manifests(roots), r => r.manifests(roots))
    }

    /// A replica asks the server: its file leaves out values this vci
    /// cannot read, which still count as the references they were stored
    /// with (and only the server removes manifests).
    fn orphan_manifests(&self, roots: &[&str]) -> Result<Vec<String>, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.orphan_manifests(roots),
            Inner::Remote(r) => r.orphan_manifests(roots),
            Inner::Replica(p) => p.remote.orphan_manifests(roots),
        }
    }

    /// Local: the file's (one transaction). Remote and replica: deferred,
    /// written in one request when it finishes (a replica's file too).
    fn batch(&self) -> Result<WriteBatch, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.batch(),
            Inner::Remote(r) => batch::open(r, None),
            Inner::Replica(p) => {
                p.writable()?;
                batch::open(&p.remote, Some(p.after()))
            }
        }
    }

    fn prefetch(&self, what: Prefetch<'_>) -> Result<Hydration, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.prefetch(what),
            Inner::Remote(r) => r.prefetch(what),
            Inner::Replica(p) if p.degraded() => p.remote.prefetch(what),
            // A replica's objects are the server's.
            Inner::Replica(p) if matches!(what, Prefetch::Objects { .. }) => {
                p.remote.prefetch(what)
            }
            // The first use syncs; a later prefetch syncs what changed.
            Inner::Replica(p) => {
                p.prefetch()?;
                Ok(Hydration::default())
            }
        }
    }

    // ---- objects and columns (store format 3) ----

    /// Local: the file's. Remote and replica: the server's, the handle's
    /// own writes included (its cache).
    fn get_objects(&self, ids: &[&str]) -> Result<Vec<StoredObject>, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.get_objects(ids),
            Inner::Remote(r) => r.get_objects(ids),
            Inner::Replica(p) => p.remote.get_objects(ids),
        }
    }

    /// Remote and replica: queued in the open batch of this thread (written
    /// before any record of it), else one transaction now.
    fn put_objects(&self, objects: &[NewObject<'_>]) -> Result<usize, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.put_objects(objects),
            Inner::Remote(r) if batch::is_open(r) => batch::put_objects(r, objects),
            Inner::Remote(r) => r.put_objects_now(objects, None),
            Inner::Replica(p) if batch::is_open(&p.remote) => {
                batch::put_objects(&p.remote, objects)
            }
            Inner::Replica(p) => {
                p.writable()?;
                p.remote.put_objects_now(objects, Some(&p.after()))
            }
        }
    }

    /// On a server: inside an open batch of this thread, queued and
    /// applied under the orphan rule after everything else of the batch
    /// (the records it removes no longer reference them) in its last
    /// transaction, counting nothing, as PostgreSQL's batch does; the
    /// objects the batch itself puts are left out (the server does not
    /// hold them yet, or holds them with a `put_at` the batch refreshes).
    /// Outside a batch, applied at once.
    fn remove_objects(&self, ids: &[&str]) -> Result<usize, StoreError> {
        let remote = match &self.inner {
            Inner::Local(s) => return s.remove_objects(ids),
            Inner::Remote(r) => r,
            Inner::Replica(p) => &p.remote,
        };
        if batch::is_open(remote) {
            return batch::remove_objects(remote, ids);
        }
        remote.remove_objects_now(ids, &BTreeSet::new())
    }

    fn orphan_objects(&self) -> Result<Vec<String>, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.orphan_objects(),
            Inner::Remote(r) => r.orphan_objects(),
            Inner::Replica(p) => p.remote.orphan_objects(),
        }
    }

    fn prune_state_objects(&self, older_than: Duration) -> Result<usize, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.prune_state_objects(older_than),
            Inner::Remote(r) => r.prune_state_objects(older_than),
            Inner::Replica(p) => p.remote.prune_state_objects(older_than),
        }
    }

    /// Remote and replica: the server's (what an open batch on this thread
    /// queued for a key first).
    fn columns(&self, envs: &[&StoredEnvelope]) -> Result<Vec<Columns>, StoreError> {
        match &self.inner {
            Inner::Local(s) => s.columns(envs),
            Inner::Remote(r) => r.columns(envs),
            Inner::Replica(p) => p.remote.columns(envs),
        }
    }

    /// Local: the file read through once. Remote: the schema version and
    /// the flags asked for on a thread (which opens the connection and its
    /// TLS session), then the statements of the plan's reads described on
    /// the pool's connections but one (after the flags, which the plan's
    /// first checks wait for). Replica: the sync, on a thread. Neither while the
    /// token is `[store] token_command`'s and the command has not run: a
    /// warm-up thread is never joined, so the command would run for a
    /// command that may never read the store and could outlive vci; it
    /// runs at the first read instead.
    fn warm(&self) {
        match &self.inner {
            Inner::Local(s) => s.warm(),
            Inner::Remote(r) if r.conn.token_pending() => {}
            Inner::Replica(p) if p.remote.conn.token_pending() => {}
            Inner::Remote(r) => {
                let r = Arc::clone(r);
                let _ = std::thread::Builder::new()
                    .name("vci-libsql-warm".into())
                    .spawn(move || {
                        let _ = r.status();
                        let _ = r.flag("");
                        r.describe_ahead();
                    });
            }
            Inner::Replica(p) => {
                let p = Arc::clone(p);
                let _ = std::thread::Builder::new()
                    .name("vci-libsql-warm".into())
                    .spawn(move || {
                        let _ = p.local();
                        let _ = p.remote.flag("");
                    });
            }
        }
    }

    fn passing_on(&self, tree16: &str) -> BTreeMap<String, String> {
        match &self.inner {
            Inner::Local(s) => s.passing_on(tree16),
            Inner::Remote(r) => r.passing_on(tree16),
            Inner::Replica(p) => p.remote.passing_on(tree16),
        }
    }

    fn remember_passing(&self, tree16: &str, items: &[(String, String)]) {
        match &self.inner {
            Inner::Local(s) => s.remember_passing(tree16, items),
            Inner::Remote(r) => r.remember_passing(tree16, items),
            Inner::Replica(p) => p.remote.remember_passing(tree16, items),
        }
    }

    fn flag(&self, name: &str) -> bool {
        match &self.inner {
            Inner::Local(s) => s.flag(name),
            Inner::Remote(r) => r.flag(name),
            Inner::Replica(p) => p.remote.flag(name),
        }
    }

    fn set_flag(&self, name: &str) {
        match &self.inner {
            Inner::Local(s) => s.set_flag(name),
            Inner::Remote(r) => r.set_flag(name),
            Inner::Replica(p) => p.remote.set_flag(name),
        }
    }

    fn timing_report(&self) -> Vec<String> {
        match &self.inner {
            Inner::Local(s) => s.timing_report(),
            Inner::Replica(p) => match p.local() {
                Ok(s) => s.timing_report(),
                Err(_) => Vec::new(),
            },
            Inner::Remote(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vci_store::select::{Secret, Source, Sourced};

    fn cx(long_running: bool) -> OpenContext {
        OpenContext {
            repo_root: "/nonexistent".into(),
            git_dir: "/nonexistent/.git".into(),
            git_common_dir: "/nonexistent/.git".into(),
            repo_id: Arc::new(|| Err("no repository".to_owned())),
            jobs: 1,
            command: "test".to_owned(),
            long_running,
        }
    }

    fn sel(url: Option<&str>, mode: LibsqlMode) -> Selection {
        let mut s = Selection::for_backend("libsql");
        s.url = url.map(|u| Sourced {
            value: Secret::new(u),
            source: Source::Env("VCI_STORE_URL"),
        });
        s.libsql.mode = Sourced {
            value: mode,
            source: Source::Env("VCI_STORE_URL"),
        };
        s
    }

    #[test]
    fn open_does_no_io_and_checks_settings() {
        let f = LibsqlFactory;
        assert_eq!(f.kind(), "libsql");
        let local = LibsqlStore::open(&sel(None, LibsqlMode::Local), &cx(false)).unwrap();
        assert_eq!(local.mode(), LibsqlMode::Local);
        assert_eq!(
            local.path().unwrap(),
            Path::new("/nonexistent/.git/vci-store.libsql")
        );
        assert!(!local.caps().shared_writes && local.caps().keeps_hints);
        assert_eq!(
            local.location(),
            "/nonexistent/.git/vci-store.libsql (local)"
        );
        let remote = LibsqlStore::open(
            &sel(
                Some("libsql://db-org.turso.io?authToken=s3cret"),
                LibsqlMode::Remote,
            ),
            &cx(false),
        )
        .unwrap();
        assert!(remote.caps().shared_writes && remote.caps().keeps_hints);
        assert!(remote.exchange().is_none());
        assert_eq!(
            remote.location(),
            "libsql://db-org.turso.io namespace (none: set $VCI_STORE_NAMESPACE) (remote)"
        );
        assert!(!format!("{remote:?}").contains("s3cret"));
        assert_eq!(remote.requests(), 0);
        match LibsqlStore::open(&sel(None, LibsqlMode::Remote), &cx(false)) {
            Err(StoreError::Config(m)) => assert!(m.contains("VCI_STORE_URL"), "{m}"),
            other => panic!("expected Config, got {:?}", other.map(|_| ())),
        }
    }

    /// `[store] compress` (the selection's) turns compressed writes on;
    /// `VCI_STORE_COMPRESS`, when set, wins.
    #[test]
    fn compression_follows_the_selection_unless_the_variable_says() {
        let mut s = sel(Some("libsql://db-org.turso.io"), LibsqlMode::Remote);
        let on = |s: &Selection| {
            let st = LibsqlStore::open(s, &cx(false)).unwrap();
            st.remote().unwrap().compress()
        };
        let env = std::env::var(ENV_COMPRESS).ok();
        let forced = match env.as_deref().map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("zstd") => Some(true),
            Some(v) if v.eq_ignore_ascii_case("off") => Some(false),
            _ => None,
        };
        assert_eq!(on(&s), forced.unwrap_or(false));
        s.compress = Sourced {
            value: true,
            source: Source::File,
        };
        assert_eq!(on(&s), forced.unwrap_or(true));
    }

    #[test]
    fn without_a_repository_id_the_namespace_must_be_set() {
        let s = LibsqlStore::open(
            &sel(Some("http://127.0.0.1:1"), LibsqlMode::Remote),
            &cx(false),
        )
        .unwrap();
        match s.status() {
            Err(StoreError::Config(m)) => assert!(m.contains("VCI_STORE_NAMESPACE"), "{m}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }
}
