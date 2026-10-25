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
}
