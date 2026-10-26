//! The attestation store a command uses: one [`AttestationStore`] per
//! repository per process, shared by every thread (`vci ci`'s plan and run
//! use the same one).
//!
//! The backends this vci was built with are registered in [`factories`].
//! Which one a repository uses is resolved once per process
//! ([`vci_store::select::resolve`]): `VCI_STORE`, else the scheme of
//! `VCI_STORE_URL`, else `[store] backend` in the working tree's
//! `vci.toml`, else git-meta. A store that cannot be selected or opened is
//! a [`FailedStore`], whose every call fails, so commands fail open
//! through their usual error paths.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use camino::Utf8PathBuf;
use vci_git::{GitMetaFactory, Repo};
use vci_store::select::{self, Secret, Selection};
use vci_store::{AttestationStore, BackendFactory, FailedStore, OpenContext};

/// The values of [`select::NEVER_TO_CHILDREN`] this process was started
/// with, taken out of its environment by [`take_secrets`].
static SECRETS: OnceLock<BTreeMap<&'static str, Secret>> = OnceLock::new();

/// The vci command running (`plan`, `run`, ...), for [`OpenContext::command`].
static COMMAND: OnceLock<&'static str> = OnceLock::new();

/// The store of each repository this process opened, by root.
static STORES: Mutex<BTreeMap<Utf8PathBuf, Opened>> = Mutex::new(BTreeMap::new());

/// The kind of the first store this process opened, for the metrics log.
static USED: OnceLock<&'static str> = OnceLock::new();

/// A repository's store, and the selection it was opened with.
#[derive(Clone)]
struct Opened {
    store: Arc<dyn AttestationStore>,
    /// `None` when the selection could not be resolved (the store is then
    /// a [`FailedStore`]).
    selection: Option<Selection>,
}

/// Take every [`select::NEVER_TO_CHILDREN`] variable (`VCI_STORE`,
/// `VCI_STORE_URL`, `VCI_STORE_TOKEN`) out
/// of this process's environment, keeping its value in memory, so that no
/// test, adapter probe, hook or git command vci starts can see it. Later
/// calls do nothing.
///
/// # Safety
///
/// It changes the process environment ([`std::env::remove_var`]): call it
/// while no other thread exists, first thing in `main`.
pub unsafe fn take_secrets() {
    SECRETS.get_or_init(|| {
        let mut kept = BTreeMap::new();
        for &name in select::NEVER_TO_CHILDREN {
            if let Some(v) = std::env::var_os(name) {
                // SAFETY: the caller guarantees that this process has no
                // other thread yet (this function's contract).
                unsafe { std::env::remove_var(name) };
                let v = v.to_string_lossy();
                kept.insert(
                    name,
                    if name == select::ENV_TOKEN {
                        Secret::opaque(v)
                    } else {
                        Secret::new(v)
                    },
                );
            }
        }
        kept
    });
}

/// The environment as store selection reads it: the variables
/// [`take_secrets`] took out answer from the kept values, every other one
/// from the environment.
pub fn env_lookup(name: &str) -> Option<String> {
    if select::NEVER_TO_CHILDREN.contains(&name) {
        return SECRETS
            .get()
            .and_then(|kept| kept.get(name))
            .map(|s| s.expose().to_owned());
    }
    std::env::var(name).ok()
}

/// Name the running command, for the stores this process opens.
pub fn set_command(name: &'static str) {
    let _ = COMMAND.set(name);
}

/// Every backend this vci can open, git-meta first. One left out of the
/// build (a cargo feature turned off) is a [`vci_store::MissingBackend`],
/// which says so when asked to open.
pub fn factories(repo: &Repo) -> Vec<Box<dyn BackendFactory>> {
    vec![
        Box::new(GitMetaFactory::new(repo.clone())),
        #[cfg(feature = "sqlite")]
        Box::new(vci_store_sqlite::SqliteFactory),
        #[cfg(not(feature = "sqlite"))]
        Box::new(vci_store::MissingBackend {
            kind: "sqlite",
            feature: "sqlite",
        }),
        #[cfg(feature = "postgres")]
        Box::new(vci_store_postgres::PostgresFactory),
        #[cfg(not(feature = "postgres"))]
        Box::new(vci_store::MissingBackend {
            kind: "postgres",
            feature: "postgres",
        }),
        #[cfg(feature = "libsql")]
        Box::new(vci_store_libsql::LibsqlFactory),
        #[cfg(not(feature = "libsql"))]
        Box::new(vci_store::MissingBackend {
            kind: "libsql",
            feature: "libsql",
        }),
    ]
}

/// What a backend may need from `repo` to open its store, for `command`.
/// The repository id is asked of git only when a backend needs it.
pub fn open_context(repo: &Repo, command: &str) -> OpenContext {
    let git_dir: PathBuf = repo
        .git_dir()
        .map(Utf8PathBuf::into_std_path_buf)
        .unwrap_or_else(|_| repo.root().join(".git").into_std_path_buf());
    let git_common_dir = common_dir(&git_dir);
    let id_of = repo.clone();
    let id: Arc<OnceLock<Result<String, String>>> = Arc::default();
    OpenContext {
        repo_root: repo.root().to_path_buf().into_std_path_buf(),
        git_dir,
        git_common_dir,
        repo_id: Arc::new(move || {
            id.get_or_init(|| id_of.repo_id().map_err(|e| e.to_string()))
                .clone()
        }),
        jobs: jobs(),
        command: command.to_owned(),
        long_running: command == "prune",
    }
}

/// The git directory every worktree of the repository shares: for a linked
/// worktree, the one its `commondir` file names (git's own rule), else
/// `git_dir` itself.
fn common_dir(git_dir: &Path) -> PathBuf {
    match std::fs::read_to_string(git_dir.join("commondir")) {
        Ok(s) if !s.trim().is_empty() => {
            let named = Path::new(s.trim_end_matches(['\n', '\r']));
            let dir = if named.is_absolute() {
                named.to_owned()
            } else {
                git_dir.join(named)
            };
            dir.canonicalize().unwrap_or(dir)
        }
        _ => git_dir.to_owned(),
    }
}

/// `VCI_JOBS`, else one per CPU: how many threads use the store at once.
fn jobs() -> usize {
    std::env::var("VCI_JOBS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
}

/// The attestation store of `repo`, opened once per process and shared.
/// Opening never fails: a store that cannot be selected or opened is a
/// [`FailedStore`]. The selection's warnings are printed when it is
/// opened.
pub fn for_repo(repo: &Repo) -> Arc<dyn AttestationStore> {
    opened(repo).store
}

/// The settings `repo`'s store was opened with ([`for_repo`]), with where
/// each came from; `None` when they could not be resolved.
pub fn selection_of(repo: &Repo) -> Option<Selection> {
    opened(repo).selection
}

/// The warnings about `repo`'s store selection (settings overridden or
/// ignored), for the plan's warnings: [`for_repo`] printed them.
pub fn warnings_of(repo: &Repo) -> Vec<String> {
    selection_of(repo).map(|s| s.warnings).unwrap_or_default()
}

/// The kind of the first store this process opened, if it opened one.
pub fn used_kind() -> Option<&'static str> {
    USED.get().copied()
}

fn opened(repo: &Repo) -> Opened {
    let mut stores = STORES.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(o) = stores.get(repo.root()) {
        return o.clone();
    }
    let o = open(repo, &env_lookup);
    for w in o.selection.iter().flat_map(|s| &s.warnings) {
        eprintln!("vci: warning: {w}");
    }
    let _ = USED.set(o.store.kind());
    stores.insert(repo.root().to_owned(), o.clone());
    o
}

/// Resolve `repo`'s store from `env` and the working tree's `[store]`, and
/// open it.
fn open(repo: &Repo, env: &dyn Fn(&str) -> Option<String>) -> Opened {
    // The context first: it asks git for the git directory once, and the
    // factories' copies of `repo` keep the answer.
    let cx = open_context(repo, COMMAND.get().copied().unwrap_or("vci"));
    let factories = factories(repo);
    let factories: Vec<&dyn BackendFactory> = factories.iter().map(AsRef::as_ref).collect();
    let file = crate::config::working_tree_store(repo.root());
    // The backend asked for, to name a store that fails: an unreadable
    // `[store]` names none unless the environment does.
    let wanted = match &file {
        Ok(f) => select::requested_kind(env, f.as_ref()),
        Err(_) => {
            let named = [select::ENV_STORE, select::ENV_STORE_URL]
                .iter()
                .any(|k| env(k).is_some_and(|v| !v.trim().is_empty()));
            if named {
                select::requested_kind(env, None)
            } else {
                "unknown".to_owned()
            }
        }
    };
    let sel = match file.and_then(|f| select::resolve(env, f.as_ref())) {
        Ok(sel) => sel,
        Err(e) => {
            return Opened {
                store: Arc::new(FailedStore::for_request(&factories, &wanted, &e)),
                selection: None,
            };
        }
    };
    let store = vci_store::open(&factories, &sel, &cx)
        .unwrap_or_else(|e| Arc::new(FailedStore::for_request(&factories, &sel.kind.value, &e)));
    Opened {
        store,
        selection: Some(sel),
    }
}

/// Close every store this process opened (their pooled connections and
/// `git cat-file` processes), as vci did before stores were shared: called
/// once the command is done.
pub fn close_all() {
    let stores = std::mem::take(&mut *STORES.lock().unwrap_or_else(|p| p.into_inner()));
    drop(stores);
}

/// An in-memory [`AttestationStore`] for unit tests of the code that uses
/// a store. Its batches can be deferred (writes applied only when the
/// batch finishes, as PostgreSQL's are) and made to fail, and its
/// capabilities can claim shared writes.
#[cfg(test)]
pub mod mem {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use vci_store::{
        AttestationStore, BatchEnd, Caps, GONE, NewAttestation, StoreError, StoredEnvelope,
        StoredManifest, WriteBatch, key,
    };

    /// What the store holds.
    #[derive(Default)]
    struct Data {
        /// Attestations by key: (target, bytes).
        attestations: BTreeMap<String, (String, Vec<u8>)>,
        /// Manifests by root.
        manifests: BTreeMap<String, Vec<u8>>,
    }

    impl Data {
        /// The keys of the slot `key` is in.
        fn same_slot(&self, key: &str) -> Vec<String> {
            let slot = key::parse_key(key);
            self.attestations
                .keys()
                .filter(|k| key::parse_key(k) == slot)
                .cloned()
                .collect()
        }

        fn put(&mut self, key: String, target: String, bytes: Vec<u8>) {
            for k in self.same_slot(&key) {
                self.attestations.remove(&k);
            }
            self.attestations.insert(key, (target, bytes));
        }
    }

    /// A write waiting for its deferred batch to finish.
    enum Op {
        Put(String, String, Vec<u8>),
        Manifest(String, Vec<u8>),
        Remove(String),
    }

    #[derive(Default)]
    struct State {
        data: Mutex<Data>,
        /// The writes of the open deferred batch.
        pending: Mutex<Option<Vec<Op>>>,
        shared: AtomicBool,
        deferred: AtomicBool,
        fail: Mutex<Option<String>>,
        writes: AtomicUsize,
        batches: AtomicUsize,
    }

    impl State {
        /// Queue `op` in the open deferred batch, or give it back.
        fn queue(&self, op: Op) -> Option<Op> {
            match self.pending.lock().unwrap().as_mut() {
                Some(q) => {
                    q.push(op);
                    None
                }
                None => Some(op),
            }
        }

        fn apply(&self, op: Op) {
            let mut d = self.data.lock().unwrap();
            match op {
                Op::Put(k, t, b) => d.put(k, t, b),
                Op::Manifest(r, b) => {
                    d.manifests.insert(r, b);
                }
                Op::Remove(k) => {
                    d.attestations.remove(&k);
                }
            }
        }
    }

    /// The in-memory store. Clones share their contents.
    #[derive(Clone, Default)]
    pub struct MemStore {
        state: Arc<State>,
    }

    impl MemStore {
        /// An empty store: local, immediate batches.
        pub fn new() -> Self {
            Self::default()
        }

        /// Claim [`Caps::shared_writes`] (a shared server).
        pub fn shared(self, v: bool) -> Self {
            self.state.shared.store(v, Ordering::SeqCst);
            self
        }

        /// Make [`AttestationStore::batch`] deferred: writes are applied
        /// when the batch finishes.
        pub fn deferred(self, v: bool) -> Self {
            self.state.deferred.store(v, Ordering::SeqCst);
            self
        }

        /// Make every batch's `finish` fail with `why` (and lose its
        /// writes), or succeed again with `None`.
        pub fn failing(self, why: Option<&str>) -> Self {
            *self.state.fail.lock().unwrap() = why.map(str::to_owned);
            self
        }

        /// How many write methods were called (`put`, `put_manifest`,
        /// `remove`, `remove_manifests`), and batches opened.
        pub fn writes(&self) -> usize {
            self.state.writes.load(Ordering::SeqCst) + self.state.batches.load(Ordering::SeqCst)
        }

        /// The stored attestations' keys.
        pub fn keys(&self) -> Vec<String> {
            let d = self.state.data.lock().unwrap();
            d.attestations.keys().cloned().collect()
        }

        /// The stored manifests' roots.
        pub fn roots(&self) -> Vec<String> {
            let d = self.state.data.lock().unwrap();
            d.manifests.keys().cloned().collect()
        }

        fn wrote(&self) {
            self.state.writes.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The end of a [`MemStore`] batch.
    struct MemBatch(Arc<State>);

    impl BatchEnd for MemBatch {
        fn finish(self: Box<Self>) -> Result<(), StoreError> {
            let Some(ops) = self.0.pending.lock().unwrap().take() else {
                return Ok(());
            };
            if let Some(why) = self.0.fail.lock().unwrap().clone() {
                return Err(StoreError::unavailable("memory", why));
            }
            // Manifests, then attestations, then removals (the contract's
            // order for a deferred batch).
            let (mut manifests, mut puts, mut removals) = (Vec::new(), Vec::new(), Vec::new());
            for op in ops {
                match op {
                    Op::Manifest(..) => manifests.push(op),
                    Op::Put(..) => puts.push(op),
                    Op::Remove(..) => removals.push(op),
                }
            }
            for op in manifests.into_iter().chain(puts).chain(removals) {
                self.0.apply(op);
            }
            Ok(())
        }
    }

    impl AttestationStore for MemStore {
        fn kind(&self) -> &'static str {
            "memory"
        }

        fn caps(&self) -> Caps {
            Caps::LOCAL.with_shared_writes(self.state.shared.load(Ordering::SeqCst))
        }

        fn list_units(&self, test_ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
            let d = self.state.data.lock().unwrap();
            Ok(test_ids
                .iter()
                .map(|id| {
                    let prefix = key::unit_prefix(&key::test_key(id));
                    d.attestations
                        .iter()
                        .filter(|(k, _)| k.starts_with(&prefix))
                        .filter_map(|(k, (t, _))| StoredEnvelope::from_key(t.clone(), k))
                        .collect()
                })
                .collect())
        }

        fn list_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
            let d = self.state.data.lock().unwrap();
            let mut all: Vec<StoredEnvelope> = d
                .attestations
                .iter()
                .filter_map(|(k, (t, _))| StoredEnvelope::from_key(t.clone(), k))
                .collect();
            all.sort_by(|a, b| (&a.target, &a.key).cmp(&(&b.target, &b.key)));
            Ok(all)
        }

        fn read_values(&self, envs: &mut [&mut StoredEnvelope]) -> Result<(), StoreError> {
            let d = self.state.data.lock().unwrap();
            for e in envs.iter_mut() {
                match d.attestations.get(&e.key) {
                    Some((_, b)) => e.set_value(b.clone()),
                    None => e.set_error(GONE),
                }
            }
            Ok(())
        }

        fn manifest(&self, root: &str) -> Result<Option<StoredManifest>, StoreError> {
            let d = self.state.data.lock().unwrap();
            Ok(d.manifests
                .get(root)
                .map(|b| StoredManifest::with_bytes(root, b.clone())))
        }

        fn manifest_roots(&self) -> Result<Vec<String>, StoreError> {
            Ok(self.roots())
        }

        fn put(&self, att: &NewAttestation<'_>) -> Result<StoredEnvelope, StoreError> {
            self.wrote();
            att.validate()?;
            let key = match att.hinted_key() {
                Some(k) => k,
                None => {
                    let d = self.state.data.lock().unwrap();
                    d.same_slot(&att.plain_key())
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| att.plain_key())
                }
            };
            let op = Op::Put(key.clone(), att.target.clone(), att.envelope.to_vec());
            if let Some(op) = self.state.queue(op) {
                self.state.apply(op);
            }
            Ok(att.stored(key))
        }

        fn put_manifest(&self, root: &str, bytes: &[u8]) -> Result<bool, StoreError> {
            self.wrote();
            key::check_hex("input root", root)?;
            let changed =
                self.state.data.lock().unwrap().manifests.get(root) != Some(&bytes.to_vec());
            if let Some(op) = self
                .state
                .queue(Op::Manifest(root.to_owned(), bytes.to_vec()))
            {
                self.state.apply(op);
            }
            Ok(changed)
        }

        fn remove(&self, doomed: Vec<StoredEnvelope>) -> Result<Vec<StoredEnvelope>, StoreError> {
            self.wrote();
            let mut removed = Vec::new();
            for e in doomed {
                let existed = self
                    .state
                    .data
                    .lock()
                    .unwrap()
                    .attestations
                    .contains_key(&e.key);
                let deferred = self.state.queue(Op::Remove(e.key.clone())).is_none();
                if deferred {
                    removed.push(e);
                } else if existed {
                    self.state.apply(Op::Remove(e.key.clone()));
                    removed.push(e);
                }
            }
            Ok(removed)
        }

        fn remove_manifests(&self, roots: &[&str]) -> Result<usize, StoreError> {
            self.wrote();
            let mut d = self.state.data.lock().unwrap();
            Ok(roots
                .iter()
                .filter(|r| d.manifests.remove(**r).is_some())
                .count())
        }

        fn batch(&self) -> Result<WriteBatch, StoreError> {
            self.state.batches.fetch_add(1, Ordering::SeqCst);
            let end = Box::new(MemBatch(self.state.clone()));
            Ok(if self.state.deferred.load(Ordering::SeqCst) {
                *self.state.pending.lock().unwrap() = Some(Vec::new());
                WriteBatch::deferred(end)
            } else {
                WriteBatch::immediate(end)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_repo() -> (tempfile::TempDir, Repo) {
        let t = tempfile::tempdir().unwrap();
        let out = std::process::Command::new("git")
            .args(["init", "-q"])
            .arg(t.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "git init: {out:?}");
        let root = camino::Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        let repo = Repo::discover(&root).unwrap();
        (t, repo)
    }

    /// git-meta is the store, opened once per repository.
    #[test]
    fn the_store_is_git_meta_and_shared() {
        let (_t, repo) = git_repo();
        let a = for_repo(&repo);
        let b = for_repo(&repo.clone());
        assert_eq!(a.kind(), "git-meta");
        assert!(Arc::ptr_eq(&a, &b));
        assert!(a.exchange().is_some());
    }

    #[test]
    fn every_backend_is_registered() {
        let (_t, repo) = git_repo();
        let kinds: Vec<&str> = factories(&repo).iter().map(|f| f.kind()).collect();
        assert_eq!(kinds, ["git-meta", "sqlite", "postgres", "libsql"]);
    }

    #[test]
    fn the_context_names_the_git_directories() {
        let (_t, repo) = git_repo();
        let cx = open_context(&repo, "prune");
        let git_dir = repo.git_dir().unwrap().into_std_path_buf();
        assert_eq!(cx.git_dir, git_dir);
        assert_eq!(cx.git_common_dir, git_dir);
        assert_eq!(cx.repo_root, repo.root().as_std_path());
        assert!(cx.long_running);
        assert_eq!(cx.command, "prune");
        assert!(!open_context(&repo, "plan").long_running);
        // No commit yet: no repository id, asked only now.
        assert!((cx.repo_id)().is_err());
    }

    #[test]
    fn a_linked_worktree_shares_the_common_dir() {
        let t = tempfile::tempdir().unwrap();
        let common = t.path().join("repo/.git");
        let wt = common.join("worktrees/w");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(wt.join("commondir"), "../..\n").unwrap();
        assert_eq!(common_dir(&wt), common.canonicalize().unwrap());
        assert_eq!(common_dir(&common), common);
    }

    /// Variables never taken out read from the environment.
    #[test]
    fn env_lookup_reads_other_variables() {
        assert_eq!(env_lookup("PATH"), std::env::var("PATH").ok());
        assert_eq!(env_lookup("VCI_STORE_URL"), None);
    }

    fn env_of(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: BTreeMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| vars.get(k).cloned()
    }

    /// Selection: the environment over the working tree's `[store]` over
    /// git-meta; what cannot be selected or opened is a failed store that
    /// says why and never prints a URL's password.
    #[test]
    fn the_store_is_selected_from_the_environment_and_vci_toml() {
        let (t, repo) = git_repo();
        let o = open(&repo, &env_of(&[]));
        assert_eq!(o.store.kind(), "git-meta");
        let sel = o.selection.unwrap();
        assert_eq!(sel.kind.source, select::Source::Default);
        assert!(sel.warnings.is_empty());

        let o = open(&repo, &env_of(&[("VCI_STORE", "nope")]));
        assert_eq!(o.store.kind(), "unknown");
        let e = o.store.status().unwrap_err().to_string();
        assert!(
            e.contains("\"nope\"") && e.contains("git-meta, sqlite, postgres, libsql"),
            "{e}"
        );

        // A libsql:// URL selects libsql; neither its token nor
        // VCI_STORE_TOKEN reaches a message.
        let o = open(
            &repo,
            &env_of(&[
                (
                    "VCI_STORE_URL",
                    "libsql://db-org.turso.io?authToken=s3cret-q",
                ),
                ("VCI_STORE_TOKEN", "s3cret-env"),
            ]),
        );
        assert_eq!(o.store.kind(), "libsql");
        let sel = o.selection.unwrap();
        let all = format!("{} {sel:?} {:?}", o.store.location(), sel.describe());
        assert!(!all.contains("s3cret"), "{all}");
        assert!(
            o.store
                .location()
                .starts_with("libsql://db-org.turso.io namespace "),
            "{all}"
        );

        let o = open(&repo, &env_of(&[("VCI_STORE", "postgres")]));
        assert_eq!(o.store.kind(), "postgres");
        assert!(o.selection.is_none());
        let e = o.store.status().unwrap_err().to_string();
        assert!(e.contains("VCI_STORE_URL"), "{e}");

        let url = "postgres://u:s3cret@127.0.0.1:1/x";
        for env in [vec![("VCI_STORE", url)], vec![("VCI_STORE_URL", url)]] {
            let o = open(&repo, &env_of(&env));
            let e = o.store.status().unwrap_err().to_string();
            let all = format!("{e} {} {:?}", o.store.location(), o.selection);
            assert!(!all.contains("s3cret"), "{all}");
        }
        // A libpq string in VCI_STORE is refused without being quoted back.
        let o = open(
            &repo,
            &env_of(&[("VCI_STORE", "host=127.0.0.1 password='s3cret x'")]),
        );
        let e = o.store.status().unwrap_err().to_string();
        assert!(e.contains("not printed") && !e.contains("s3cret"), "{e}");
        // With git-meta selected, the warning about an ignored VCI_STORE_URL
        // shows no part of a password, however the string writes it.
        for url in [
            "host=db.example password = s3cret-kv",
            "host=db.example password='s3cret kv'",
            "postgress://u:s3cr/et@db.example/x",
            "postgress://u:s3cr?et@db.example/x",
        ] {
            let o = open(&repo, &env_of(&[("VCI_STORE_URL", url)]));
            assert_eq!(o.store.kind(), "git-meta");
            let sel = o.selection.unwrap();
            let all = format!("{:?} {sel:?}", sel.warnings);
            assert_eq!(sel.warnings.len(), 1, "{all}");
            for part in ["s3cr", " kv", "et@"] {
                assert!(!all.contains(part), "{part} in {all}");
            }
        }

        std::fs::write(
            t.path().join("vci.toml"),
            "[policy]\nbroken = 1\n\n[store]\nbackend = \"sqlite\"\n",
        )
        .unwrap();
        let o = open(&repo, &env_of(&[("VCI_STORE", "git-meta")]));
        assert_eq!(o.store.kind(), "git-meta");
        let sel = o.selection.unwrap();
        assert_eq!(sel.kind.source, select::Source::Env("VCI_STORE"));
        assert_eq!(sel.warnings.len(), 1, "{:?}", sel.warnings);
        assert!(sel.warnings[0].contains("overridden"), "{:?}", sel.warnings);

        std::fs::write(
            t.path().join("vci.toml"),
            "[store.postgres]\npassword = \"planted\"\n",
        )
        .unwrap();
        let o = open(&repo, &env_of(&[]));
        assert!(o.selection.is_none());
        let e = o.store.status().unwrap_err().to_string();
        assert!(
            e.contains("store.postgres.password") && !e.contains("planted"),
            "{e}"
        );

        std::fs::write(t.path().join("vci.toml"), "[store]\nbackend = 5\n").unwrap();
        let o = open(&repo, &env_of(&[]));
        assert_eq!(o.store.kind(), "unknown");
        let e = o.store.status().unwrap_err().to_string();
        assert!(e.contains("vci.toml (line 2)"), "{e}");
    }

    /// The test store keeps one record per slot, and a deferred batch's
    /// writes appear only when it finishes, or never when it fails.
    #[test]
    fn the_memory_store_defers_and_fails_batches() {
        use vci_store::KeyHint;
        let signer = "0123456789abcdef";
        let h = |issued| KeyHint { issued, tree: None };
        let s = mem::MemStore::new().deferred(true);
        let b = s.batch().unwrap();
        assert!(b.defers_writes());
        s.put_manifest("aa", b"{}").unwrap();
        s.put_for_test("src/a.test.ts", signer, "abcd", Some(&h(1)), b"one")
            .unwrap();
        assert!(s.keys().is_empty() && s.roots().is_empty());
        b.finish().unwrap();
        assert_eq!(s.keys().len(), 1);
        assert_eq!(s.roots(), ["aa"]);
        // The same slot again, with a newer hint: one record.
        s.put_for_test("src/a.test.ts", signer, "abcd", Some(&h(2)), b"two")
            .unwrap();
        assert_eq!(s.keys().len(), 1);
        assert!(s.keys()[0].ends_with(":2.-"), "{:?}", s.keys());

        let s = s.failing(Some("down"));
        let b = s.batch().unwrap();
        s.put_for_test("src/b.test.ts", signer, "abcd", None, b"x")
            .unwrap();
        let e = b.finish().unwrap_err();
        assert_eq!(e.to_string(), "memory store unavailable: down");
        assert_eq!(s.keys().len(), 1, "a failed batch writes nothing");
        assert!(s.writes() > 0);
        assert!(!s.caps().shared_writes);
        assert!(s.shared(true).caps().shared_writes);
    }
}
