//! git-meta ([`GitMetaStore`]) against the conformance suite
//! (`docs/STORE-BACKENDS.md` section 14).
//!
//! A world is a bare remote that serves partial clones (as GitHub does) and
//! its peers are `--no-local` clones of it, each with a metadata remote for
//! `origin` (`AttestStore::ensure_remote`). [`World::sync`] pushes from one
//! peer and fetches into the others, so fetched values are lazy until a
//! prefetch. The unreachable store is a clone whose metadata remote is an
//! HTTPS URL with a password ([`SECRET`]) on a closed local port; the
//! read-only handle reads a clone whose `.git` was made
//! read-only (`chmod -R a-w`, undone on drop); raw records go through a
//! `git_meta_lib::Session`; a value is made unreadable by pointing its row
//! at a blob the object database does not hold. Batches are immediate, so
//! none can be made to fail.

mod common;

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use git_meta_lib::{Session, Target};
use vci_core::ObjectKind;
use vci_git::{AttestStore, GitMetaStore, Repo};
use vci_store::conformance::{StoreFactory, World};
use vci_store::{AttestationStore, PushMode};

struct GitMetaWorlds;

/// The password in the unreachable store's remote URL, which no message may
/// show.
const SECRET: &str = "s3cret-conformance";

impl StoreFactory for GitMetaWorlds {
    fn name(&self) -> &str {
        "git-meta"
    }

    fn world(&self) -> Box<dyn World> {
        Box::new(GitWorld::new())
    }
}

/// A peer: a clone and its store.
struct Peer {
    dir: Utf8PathBuf,
    store: Arc<GitMetaStore>,
}

/// A remote, its clones, and the `.git` directories made read-only.
struct GitWorld {
    remote: common::World,
    peers: Mutex<BTreeMap<usize, Peer>>,
    clones: AtomicUsize,
    read_only: Mutex<Vec<Utf8PathBuf>>,
}

impl GitWorld {
    fn new() -> Self {
        let remote = common::world(0);
        common::git(
            &remote.remote,
            &["config", "uploadpack.allowFilter", "true"],
        );
        GitWorld {
            remote,
            peers: Mutex::new(BTreeMap::new()),
            clones: AtomicUsize::new(0),
            read_only: Mutex::new(Vec::new()),
        }
    }

    /// A new `--no-local` clone with a metadata remote for `origin`; the
    /// metadata remote's name.
    fn clone_peer(&self) -> (Utf8PathBuf, String) {
        let base = self.remote.remote.parent().expect("the world's directory");
        let n = self.clones.fetch_add(1, Ordering::SeqCst);
        let dir = base.join(format!("peer{n}"));
        common::git(
            base,
            &[
                "clone",
                "-q",
                "--no-local",
                self.remote.remote.as_str(),
                dir.as_str(),
            ],
        );
        let repo = Repo::discover(&dir).expect("a repository");
        let name = AttestStore::new(&repo)
            .ensure_remote(Some("origin"))
            .expect("a metadata remote");
        (dir, name)
    }

    fn store(dir: &Utf8Path) -> Arc<GitMetaStore> {
        Arc::new(GitMetaStore::new(
            Repo::discover(dir).expect("a repository"),
        ))
    }

    /// Peer `i`'s clone (made on first use).
    fn dir(&self, i: usize) -> Utf8PathBuf {
        self.peer(i);
        self.peers.lock().unwrap_or_else(PoisonError::into_inner)[&i]
            .dir
            .clone()
    }
}

impl World for GitWorld {
    fn peer(&self, i: usize) -> Arc<dyn AttestationStore> {
        assert!(i < 8, "peer {i}");
        let mut peers = self.peers.lock().unwrap_or_else(PoisonError::into_inner);
        peers
            .entry(i)
            .or_insert_with(|| {
                let (dir, _) = self.clone_peer();
                let store = Self::store(&dir);
                Peer { dir, store }
            })
            .store
            .clone()
    }

    fn fresh_peer(&self) -> Arc<dyn AttestationStore> {
        let (dir, _) = self.clone_peer();
        Self::store(&dir)
    }

    fn sync(&self, from: usize, to: &[usize]) {
        let p = self.peer(from);
        p.exchange()
            .expect("git-meta has an exchange")
            .push(None, PushMode::Merge)
            .unwrap_or_else(|e| panic!("push from peer {from}: {e}"));
        for &t in to {
            self.peer(t)
                .exchange()
                .expect("git-meta has an exchange")
                .fetch(None)
                .unwrap_or_else(|e| panic!("fetch into peer {t}: {e}"));
        }
    }

    fn backing_exists(&self, i: usize) -> Option<bool> {
        Some(self.dir(i).join(".git/git-meta.sqlite").exists())
    }

    fn unreachable(&self) -> Option<Arc<dyn AttestationStore>> {
        let (dir, name) = self.clone_peer();
        let url = format!("https://vci-user:{SECRET}@127.0.0.1:1/meta.git");
        common::git(&dir, &["config", &format!("remote.{name}.url"), &url]);
        Some(Self::store(&dir))
    }

    fn secret(&self) -> Option<String> {
        Some(SECRET.to_owned())
    }

    fn read_only(&self, i: usize) -> Option<Arc<dyn AttestationStore>> {
        let dir = self.dir(i);
        let git_dir = dir.join(".git");
        let ok = Command::new("chmod")
            .args(["-R", "a-w", git_dir.as_str()])
            .status()
            .is_ok_and(|s| s.success());
        self.read_only
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(git_dir.clone());
        if !ok {
            return None;
        }
        if std::fs::File::create(git_dir.join("probe")).is_ok() {
            eprintln!("{git_dir} is still writable (running as root?)");
            let _ = std::fs::remove_file(git_dir.join("probe"));
            return None;
        }
        Some(Self::store(&dir))
    }

    fn inject_raw(&self, i: usize, target: &str, key: &str, value: &[u8]) -> bool {
        let dir = self.dir(i);
        let Ok(text) = std::str::from_utf8(value) else {
            return false;
        };
        let target = match target.strip_prefix("path:") {
            Some(p) => Target::path(p),
            None => Target::project(),
        };
        let Ok(session) = Session::open(dir.as_std_path()) else {
            return false;
        };
        session.target(&target).set(key, text).is_ok()
    }

    fn make_unreadable(&self, i: usize, key: &str) -> bool {
        let db = self.dir(i).join(".git/git-meta.sqlite");
        let Ok(db) = rusqlite::Connection::open(db) else {
            return false;
        };
        // A blob id the object database does not hold, as an interrupted
        // download leaves it.
        db.execute(
            "UPDATE metadata SET value = ?1, is_git_ref = 1, is_promised = 0 WHERE key = ?2",
            rusqlite::params![format!("{:040x}", 0xdead_u32), key],
        )
        .is_ok_and(|n| n == 1)
    }

    /// An object's time of last write is its row's `last_timestamp`
    /// (milliseconds), whatever kind it is filed under.
    fn age_objects(&self, i: usize, ids: &[&str], by: Duration) -> bool {
        let db = self.dir(i).join(".git/git-meta.sqlite");
        let Ok(db) = rusqlite::Connection::open(db) else {
            return false;
        };
        let by = i64::try_from(by.as_millis()).unwrap_or(i64::MAX);
        // Every id must be there, under exactly one kind (the SQLite and
        // PostgreSQL worlds check the same).
        for id in ids {
            let mut moved = 0;
            for kind in [
                ObjectKind::Hdr,
                ObjectKind::Tables,
                ObjectKind::Shape,
                ObjectKind::State,
            ] {
                match db.execute(
                    "UPDATE metadata SET last_timestamp = last_timestamp - ?1
                     WHERE target_type = 'project' AND key = ?2",
                    rusqlite::params![by, vci_store::key::object_key(kind, id)],
                ) {
                    Ok(n) => moved += n,
                    Err(_) => return false,
                }
            }
            if moved != 1 {
                return false;
            }
        }
        true
    }
}

impl Drop for GitWorld {
    fn drop(&mut self) {
        for d in self
            .read_only
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            let _ = Command::new("chmod")
                .args(["-R", "u+w", d.as_str()])
                .status();
        }
    }
}

vci_store::conformance_suite!(Some(Box::new(GitMetaWorlds) as Box<dyn StoreFactory>));
