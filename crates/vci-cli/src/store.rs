//! The attestation store a command uses: one [`AttestationStore`] per
//! repository per process, shared by every thread (`vci ci`'s plan and run
//! use the same one).
//!
//! The backends this vci was built with are registered in [`factories`].
//! The store is git-meta for now; choosing another backend
//! (`VCI_STORE`, `VCI_STORE_URL`, `[store]` in `vci.toml`) comes later.
//! A store that cannot be opened is a [`FailedStore`], whose every call
//! fails, so commands fail open through their usual error paths.

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
static STORES: Mutex<BTreeMap<Utf8PathBuf, Arc<dyn AttestationStore>>> =
    Mutex::new(BTreeMap::new());

/// Take every [`select::NEVER_TO_CHILDREN`] variable (`VCI_STORE_URL`) out
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
                kept.insert(name, Secret::new(v.to_string_lossy()));
            }
        }
        kept
    });
}

/// The environment as store selection reads it: the variables
/// [`take_secrets`] took out answer from the kept values, every other one
/// from the environment.
#[allow(dead_code)] // store selection reads it once it honours the environment
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
/// Opening never fails: a store that cannot be opened is a
/// [`FailedStore`].
pub fn for_repo(repo: &Repo) -> Arc<dyn AttestationStore> {
    let mut stores = STORES.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(s) = stores.get(repo.root()) {
        return s.clone();
    }
    let store = open(repo);
    stores.insert(repo.root().to_owned(), store.clone());
    store
}

fn open(repo: &Repo) -> Arc<dyn AttestationStore> {
    // The context first: it asks git for the git directory once, and the
    // factories' copies of `repo` keep the answer.
    let cx = open_context(repo, COMMAND.get().copied().unwrap_or("vci"));
    let factories = factories(repo);
    let factories: Vec<&dyn BackendFactory> = factories.iter().map(AsRef::as_ref).collect();
    let sel = Selection::for_backend(select::DEFAULT_BACKEND);
    vci_store::open(&factories, &sel, &cx)
        .unwrap_or_else(|e| Arc::new(FailedStore::for_request(&factories, &sel.kind.value, &e)))
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
        assert_eq!(kinds, ["git-meta", "sqlite", "postgres"]);
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
