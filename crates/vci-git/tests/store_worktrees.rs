//! One git-meta store per repository (2.7.33): the main worktree and every
//! linked worktree (`git worktree add`) share `<common git dir>/git-meta.sqlite`,
//! so what one worktree stores another reads without a push, and a linked
//! worktree's own store left by an earlier vci is taken over or left alone.

mod common;

use std::collections::BTreeSet;

use camino::{Utf8Path, Utf8PathBuf};
use common::*;
use git_meta_lib::Session;
use vci_git::meta::{attestation_key, target_for};
use vci_git::{AttestStore, GitMetaStore, Repo};
use vci_store::AttestationStore;

const S1: &str = "0123456789abcdef";
const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";

fn repo(root: &Utf8Path) -> Repo {
    Repo::discover(root).unwrap()
}

/// An envelope-sized value (kept by git-meta as a blob reference).
fn big(tag: &str) -> Vec<u8> {
    let mut v = format!("{{\"payloadType\":\"{tag}\",\"payload\":\"").into_bytes();
    v.extend(std::iter::repeat_n(b'A', 3000));
    v.extend_from_slice(b"\",\"signatures\":[]}");
    v
}

fn ids(st: &AttestStore) -> BTreeSet<String> {
    st.list(None)
        .unwrap()
        .into_iter()
        .map(|e| e.test_key)
        .collect()
}

fn tk(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|i| vci_core::test_key(i)).collect()
}

/// `git worktree add` a new branch at `<parent of root>/<name>`.
fn worktree(root: &Utf8Path, name: &str) -> Utf8PathBuf {
    worktree_at(root, &root.parent().unwrap().join(name), name)
}

fn worktree_at(root: &Utf8Path, wt: &Utf8Path, name: &str) -> Utf8PathBuf {
    let wt = wt.to_owned();
    git(
        root,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            &format!("{name}-branch"),
            wt.as_str(),
        ],
    );
    wt
}

/// The worktree's own git directory (`.git/worktrees/<name>`).
fn own_git_dir(wt: &Utf8Path) -> Utf8PathBuf {
    Utf8PathBuf::from(git(wt, &["rev-parse", "--absolute-git-dir"]))
}

/// A store as a vci before 2.7.33 left it in a linked worktree: git-meta's
/// session opened on the worktree writes `.git/worktrees/<name>/git-meta.sqlite`.
fn old_worktree_store(wt: &Utf8Path, test_id: &str, sk: &str, bytes: &[u8]) {
    let session = Session::open(wt.as_std_path()).unwrap();
    let key = attestation_key(&vci_core::test_key(test_id), S1, sk);
    session
        .target(&target_for(test_id))
        .set(&key, std::str::from_utf8(bytes).unwrap())
        .unwrap();
    drop(session);
    assert!(own_git_dir(wt).join("git-meta.sqlite").exists());
}

fn notes_naming(path: &Utf8Path) -> Vec<String> {
    vci_git::meta::store_notes()
        .into_iter()
        .filter(|n| n.contains(path.as_str()))
        .collect()
}

/// Every `git-meta.sqlite` under `.git/worktrees`.
fn worktree_stores(root: &Utf8Path) -> Vec<Utf8PathBuf> {
    let dir = root.join(".git/worktrees");
    let Ok(rd) = dir.read_dir_utf8() else {
        return Vec::new();
    };
    rd.filter_map(Result::ok)
        .map(|e| e.path().join("git-meta.sqlite"))
        .filter(|p| p.exists())
        .collect()
}

#[test]
fn without_linked_worktrees_the_store_path_is_unchanged() {
    let (_t, root) = init_repo();
    let r = repo(&root);
    let st = AttestStore::new(&r);
    // Byte for byte what it was: the git directory as git reports it.
    let git_dir = git(&root, &["rev-parse", "--absolute-git-dir"]);
    assert_eq!(
        st.store_path().unwrap(),
        format!("{git_dir}/git-meta.sqlite")
    );
    assert_eq!(st.store_path().unwrap(), root.join(".git/git-meta.sqlite"));
    st.put(A, S1, &hex64(1), &big("a")).unwrap();
    assert!(root.join(".git/git-meta.sqlite").exists());
    assert!(root.join(".git/git-meta.sqlite.vci-lock").exists());

    // The main worktree of a repository with linked worktrees: the same.
    // (Not next to the repository: that is the system's temp directory.)
    let elsewhere = tempfile::TempDir::new().unwrap();
    let wt = worktree_at(&root, &utf8(&elsewhere).join("wt1"), "wt1");
    let r = repo(&root);
    assert_eq!(
        AttestStore::new(&r).store_path().unwrap(),
        format!("{git_dir}/git-meta.sqlite")
    );
    // And the linked worktree's store is that file too.
    let rw = repo(&wt);
    let sw = AttestStore::new(&rw);
    assert_eq!(
        sw.store_path().unwrap().canonicalize_utf8().unwrap(),
        root.join(".git/git-meta.sqlite")
            .canonicalize_utf8()
            .unwrap()
    );
    assert_eq!(ids(&sw), tk(&[A]));
    assert!(worktree_stores(&root).is_empty());
}

#[test]
fn a_put_in_one_worktree_is_read_in_another_without_a_push() {
    let w = world(1);
    let main = &w.clones[0];
    let wa = worktree(main, "wa");
    let wb = worktree(main, "wb");
    let (ra, rb) = (repo(&wa), repo(&wb));
    let (sa, sb) = (AttestStore::new(&ra), AttestStore::new(&rb));
    assert_eq!(sa.store_path().unwrap(), sb.store_path().unwrap());

    // What `vci run` stores: the manifest, then the attestation, in a batch.
    let manifest = br#"{"v":2,"entries":[]}"#;
    {
        let _batch = sa.batch().unwrap();
        sa.put_manifest(&hex64(0x33), manifest).unwrap();
        sa.put(A, S1, &hex64(1), &big("from a")).unwrap();
    }
    let reader = sb.reader().unwrap();
    assert!(reader.has_store());
    let mut found = reader.candidates_reading(A, |_| false).unwrap();
    assert_eq!(found.len(), 1);
    sb.read_values(found.iter_mut()).unwrap();
    assert_eq!(found[0].bytes, big("from a"));
    assert_eq!(
        sb.manifest(&hex64(0x33)).unwrap().unwrap().bytes,
        manifest.to_vec()
    );
    // ... and the main worktree reads it too, from the same file.
    assert_eq!(ids(&AttestStore::new(&repo(main))), tk(&[A]));
    assert!(worktree_stores(main).is_empty(), "no per-worktree store");

    // A push from the other worktree publishes it.
    sb.push(Some("origin")).unwrap();
    let reader_clone = w.remote.parent().unwrap().join("reader");
    git(
        w.remote.parent().unwrap(),
        &["clone", "-q", w.remote.as_str(), reader_clone.as_str()],
    );
    let rr = repo(&reader_clone);
    let sr = AttestStore::new(&rr);
    sr.fetch(Some("origin")).unwrap();
    assert_eq!(ids(&sr), tk(&[A]));
}

/// The command line reaches git-meta through the store trait
/// ([`GitMetaStore`]), whose batch writes git-meta's tables itself in one
/// transaction (2.8): in a linked worktree that transaction is on the
/// shared store, so the main worktree reads the units once it commits and
/// not before, and `vci store info` names the shared file.
#[test]
fn the_trait_store_of_a_linked_worktree_writes_the_shared_one() {
    let w = world(1);
    let main = &w.clones[0];
    let wa = worktree(main, "wa");
    let ga = GitMetaStore::new(repo(&wa));
    let common = main.join(".git").canonicalize_utf8().unwrap();
    assert_eq!(
        ga.location(),
        format!(
            "{common}/git-meta.sqlite, shared by every worktree of the repository (exchanged on refs/meta/main)"
        )
    );
    assert_eq!(
        GitMetaStore::new(repo(main)).location(),
        ".git/git-meta.sqlite (exchanged on refs/meta/main)"
    );
    // A store must exist for a batch to write in process: the first put
    // (through git-meta) creates it.
    ga.put_for_test(C, S1, &hex64(3), None, &big("first"))
        .unwrap();
    let batch = ga.batch().unwrap();
    assert!(batch.defers_writes());
    ga.put_for_test(A, S1, &hex64(1), None, &big("from a"))
        .unwrap();
    ga.put_for_test(B, S1, &hex64(2), None, &big("from b"))
        .unwrap();
    let rm = repo(main);
    let sm = AttestStore::new(&rm);
    assert_eq!(ids(&sm), tk(&[C]), "the batch has not committed");
    assert!(batch.finish().unwrap().is_empty());
    assert_eq!(ids(&sm), tk(&[A, B, C]));
    assert!(worktree_stores(main).is_empty(), "no per-worktree store");
    let ra = repo(&wa);
    assert_eq!(
        sm.store_path().unwrap(),
        AttestStore::new(&ra).store_path().unwrap()
    );
}

#[test]
fn a_fetch_in_one_worktree_serves_a_plan_in_another() {
    let w = world(2);
    let (publisher, clone) = (&w.clones[0], &w.clones[1]);
    let rp = repo(publisher);
    let sp = AttestStore::new(&rp);
    sp.put(A, S1, &hex64(1), &big("published a")).unwrap();
    sp.put(B, S1, &hex64(2), &big("published b")).unwrap();
    sp.push(Some("origin")).unwrap();

    let wa = worktree(clone, "wa");
    let wb = worktree(clone, "wb");
    let ra = repo(&wa);
    AttestStore::new(&ra).fetch(Some("origin")).unwrap();

    // A plan in the other worktree: the units' values fetched, then read.
    let rb = repo(&wb);
    let sb = AttestStore::new(&rb);
    sb.hydrate_units([A, B]).unwrap();
    let reader = sb.reader().unwrap();
    for (id, tag) in [(A, "published a"), (B, "published b")] {
        let mut c = reader.candidates_reading(id, |_| false).unwrap();
        assert_eq!(c.len(), 1, "{id}");
        sb.read_values(c.iter_mut()).unwrap();
        assert_eq!(c[0].bytes, big(tag), "{id}");
        assert!(c[0].error.is_none(), "{id}: {:?}", c[0].error);
    }
    assert!(worktree_stores(clone).is_empty());
}

#[test]
fn concurrent_writers_in_two_worktrees_leave_one_consistent_store() {
    let w = world(1);
    let main = w.clones[0].clone();
    let wa = worktree(&main, "wa");
    let wb = worktree(&main, "wb");
    let units = |tag: &str| -> Vec<String> {
        (0..12)
            .map(|i| format!("src/{tag}/t{i:02}.test.ts"))
            .collect()
    };
    let (ua, ub) = (units("a"), units("b"));
    std::thread::scope(|s| {
        for (dir, ids, seed, exchange) in [(&wa, &ua, 0x10u8, "push"), (&wb, &ub, 0x40u8, "fetch")]
        {
            s.spawn(move || {
                let r = repo(dir);
                let st = AttestStore::new(&r);
                for (i, id) in ids.iter().enumerate() {
                    st.put(id, S1, &hex64(seed + i as u8), &big(id)).unwrap();
                    if i == ids.len() / 2 {
                        // An exchange half-way, under the exchange lock
                        // the other worktree's exchange also takes.
                        match exchange {
                            "push" => drop(st.push(Some("origin")).unwrap()),
                            _ => drop(st.fetch(Some("origin")).unwrap()),
                        }
                    }
                }
            });
        }
    });
    let all: BTreeSet<String> = ua
        .iter()
        .chain(&ub)
        .map(|i| vci_core::test_key(i))
        .collect();
    let rm = repo(&main);
    let sm = AttestStore::new(&rm);
    assert_eq!(ids(&sm), all);
    let db = rusqlite::Connection::open(main.join(".git/git-meta.sqlite")).unwrap();
    let ok: String = db
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ok, "ok");
    drop(db);
    assert!(worktree_stores(&main).is_empty());

    // Everything is pushed from either worktree, and nothing is lost.
    let rb = repo(&wb);
    AttestStore::new(&rb).push(Some("origin")).unwrap();
    let reader = w.remote.parent().unwrap().join("reader");
    git(
        w.remote.parent().unwrap(),
        &["clone", "-q", w.remote.as_str(), reader.as_str()],
    );
    let rr = repo(&reader);
    let sr = AttestStore::new(&rr);
    sr.fetch(Some("origin")).unwrap();
    assert_eq!(ids(&sr), all);
}

#[test]
fn an_old_worktree_store_becomes_the_shared_one() {
    let w = world(1);
    let main = &w.clones[0];
    let wt = worktree(main, "old");
    old_worktree_store(&wt, A, &hex64(1), &big("only in the old store"));
    let own = own_git_dir(&wt);
    std::fs::write(own.join("vci-materialized-refs_meta_remotes_main"), "x\n").unwrap();
    assert!(!main.join(".git/git-meta.sqlite").exists());

    let rw = repo(&wt);
    let sw = AttestStore::new(&rw);
    assert_eq!(ids(&sw), tk(&[A]), "the old store's attestation is kept");
    assert!(!own.join("git-meta.sqlite").exists(), "moved, not copied");
    assert!(main.join(".git/git-meta.sqlite").exists());
    assert!(!own.join("vci-materialized-refs_meta_remotes_main").exists());
    assert!(
        main.join(".git/vci-materialized-refs_meta_remotes_main")
            .exists()
    );
    let moved = notes_naming(&own.join("git-meta.sqlite"));
    assert_eq!(moved.len(), 1, "{moved:?}");
    assert!(moved[0].starts_with("moved this worktree's git-meta store"));

    // The main worktree and a new worktree see it; a push publishes it.
    let rm = repo(main);
    assert_eq!(ids(&AttestStore::new(&rm)), tk(&[A]));
    let other = worktree(main, "other");
    let ro = repo(&other);
    let so = AttestStore::new(&ro);
    so.put(B, S1, &hex64(2), &big("b")).unwrap();
    so.push(Some("origin")).unwrap();
    assert_eq!(ids(&sw), tk(&[A, B]));
    assert!(worktree_stores(main).is_empty());
}

#[test]
fn an_old_worktree_store_in_use_is_left_and_the_shared_one_restored() {
    let w = world(1);
    let main = &w.clones[0];
    let rm = repo(main);
    let sm = AttestStore::new(&rm);
    sm.put(A, S1, &hex64(1), &big("published")).unwrap();
    sm.push(Some("origin")).unwrap();
    // The published store is gone: only refs/meta/local/main holds A.
    for s in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(main.join(format!(".git/git-meta.sqlite{s}")));
    }
    let wt = worktree(main, "busy");
    old_worktree_store(&wt, C, &hex64(3), &big("unpushed, in the old store"));
    let old = own_git_dir(&wt).join("git-meta.sqlite");
    let before = std::fs::read(&old).unwrap();
    // Another process (a vci before 2.7.33) has it open.
    let holder = rusqlite::Connection::open(&old).unwrap();
    let mode: String = holder
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let n: i64 = holder
        .query_row("SELECT count(*) FROM metadata", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);

    let rw = repo(&wt);
    let sw = AttestStore::new(&rw);
    sw.fetch(Some("origin")).unwrap();
    assert_eq!(ids(&sw), tk(&[A]), "restored from the published ref");
    drop(holder);
    assert!(old.exists(), "the old store is left alone");
    assert_eq!(std::fs::read(&old).unwrap(), before);
    assert!(main.join(".git/git-meta.sqlite").exists());
}

#[test]
fn an_old_worktree_store_is_left_unused_when_a_shared_one_exists() {
    let w = world(1);
    let main = &w.clones[0];
    let rm = repo(main);
    AttestStore::new(&rm)
        .put(A, S1, &hex64(1), &big("in the shared store"))
        .unwrap();
    let wt = worktree(main, "stale");
    old_worktree_store(&wt, B, &hex64(2), &big("in the old store"));
    let own = own_git_dir(&wt);
    let old = own.join("git-meta.sqlite");
    let before = std::fs::read(&old).unwrap();

    let rw = repo(&wt);
    let sw = AttestStore::new(&rw);
    assert_eq!(ids(&sw), tk(&[A]), "the shared store, not the old one");
    sw.put(C, S1, &hex64(3), &big("c")).unwrap();
    assert_eq!(ids(&AttestStore::new(&rm)), tk(&[A, C]));
    assert_eq!(std::fs::read(&old).unwrap(), before, "never deleted");

    // Said once: a new Repo (another command) does not say it again.
    for _ in 0..2 {
        let r = repo(&wt);
        let st = AttestStore::new(&r);
        st.list(None).unwrap();
        st.fetch(Some("origin")).unwrap();
    }
    let said = notes_naming(&old);
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(
        said[0],
        format!(
            "{old} is no longer used: every worktree of this repository now shares the git-meta store {}; the old file (with its -wal and -shm files) can be deleted",
            sw.store_path().unwrap()
        )
    );
    assert!(own.join("git-meta.sqlite.vci-unused").exists());
    assert!(old.exists());
}
