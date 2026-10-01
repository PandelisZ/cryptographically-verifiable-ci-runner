//! Regression tests for adversarial findings against the git-meta store:
//! stores that do not cover the shared local metadata ref (linked worktrees,
//! lost or emptied SQLite files, a local ref fetched by hand), filter rules
//! that hide attestations, malformed remote trees, unreadable values, a
//! read-only `.git`, concurrent pushes in one clone, and `.git-meta` URLs.

mod common;

use std::collections::BTreeSet;
use std::io::Write as _;
use std::process::{Command, Stdio};

use camino::{Utf8Path, Utf8PathBuf};
use common::*;
use git_meta_lib::{Session, Target};
use vci_git::{AttestStore, Repo};

const S1: &str = "0123456789abcdef";
const S2: &str = "fedcba9876543210";
const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";
const D: &str = "src/d.test.ts";

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

/// Test ids of every stored value (readable or not).
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

/// A clone of the world's remote that only reads.
fn fresh_reader(w: &World, name: &str) -> Utf8PathBuf {
    let base = w.remote.parent().unwrap();
    let dir = base.join(name);
    git(base, &["clone", "-q", w.remote.as_str(), dir.as_str()]);
    dir
}

fn remote_keys(w: &World) -> BTreeSet<String> {
    let dir = fresh_reader(w, &format!("reader-{}", rand_suffix()));
    let r = repo(&dir);
    let st = AttestStore::new(&r);
    st.fetch(Some("origin")).unwrap();
    ids(&st)
}

fn rand_suffix() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

fn rm_store(root: &Utf8Path, git_dir: &str) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(root.join(format!("{git_dir}/git-meta.sqlite{suffix}")));
    }
}

// ---- stores that do not cover refs/meta/local/main -----------------------

#[test]
fn a_linked_worktree_sees_and_keeps_published_attestations() {
    let w = world(2);
    let main = &w.clones[0];
    let r = repo(main);
    let sa = AttestStore::new(&r);
    for (i, id) in [A, B, C].iter().enumerate() {
        sa.put(id, S1, &hex64(i as u8 + 1), &big(id)).unwrap();
    }
    sa.put(B, S2, &hex64(7), &big("second signer")).unwrap();
    sa.push(Some("origin")).unwrap();

    // A linked worktree has its own (empty) git-meta store but shares
    // refs/meta/local/main with the main worktree.
    let wt = main.parent().unwrap().join("wt2");
    git(
        main,
        &["worktree", "add", "-q", "-b", "wt-branch", wt.as_str()],
    );
    let rw = repo(&wt);
    let sw = AttestStore::new(&rw);
    sw.fetch(None).unwrap();
    assert_eq!(
        ids(&sw),
        tk(&[A, B, C]),
        "the worktree sees what was published"
    );
    sw.put(D, S1, &hex64(9), &big("from the worktree")).unwrap();
    sw.push(None).unwrap();
    assert_eq!(remote_keys(&w), tk(&[A, B, C, D]), "nothing was deleted");
    assert_eq!(sw.list(None).unwrap().len(), 5);

    // The main worktree keeps its values and sees the worktree's.
    sa.fetch(None).unwrap();
    assert_eq!(sa.list(None).unwrap().len(), 5);
    sa.put(A, S2, &hex64(8), b"main again").unwrap();
    sa.push(None).unwrap();
    let dir = fresh_reader(&w, "last");
    let rl = repo(&dir);
    let sl = AttestStore::new(&rl);
    sl.fetch(Some("origin")).unwrap();
    assert_eq!(sl.list(None).unwrap().len(), 6);
}

#[test]
fn a_deleted_or_emptied_store_never_deletes_published_attestations() {
    for mode in ["deleted", "emptied"] {
        let w = world(1);
        let c = &w.clones[0];
        let r = repo(c);
        let st = AttestStore::new(&r);
        for (i, id) in [A, B, C].iter().enumerate() {
            st.put(id, S1, &hex64(i as u8 + 1), &big(id)).unwrap();
        }
        st.push(Some("origin")).unwrap();
        rm_store(c, ".git");
        if mode == "emptied" {
            std::fs::write(c.join(".git/git-meta.sqlite"), b"").unwrap();
        }
        st.fetch(None).unwrap();
        assert_eq!(ids(&st), tk(&[A, B, C]), "{mode}: fetch restores the store");
        st.put(D, S1, &hex64(4), b"new").unwrap();
        st.push(None).unwrap();
        assert_eq!(remote_keys(&w), tk(&[A, B, C, D]), "{mode}");
    }
}

#[test]
fn a_store_lost_after_attesting_never_deletes_published_attestations() {
    // No fetch in between: `vci run` writes into a new store, then `vci push`.
    let w = world(1);
    let c = &w.clones[0];
    let r = repo(c);
    let st = AttestStore::new(&r);
    st.put(A, S1, &hex64(1), &big("a")).unwrap();
    st.put(B, S1, &hex64(2), &big("b")).unwrap();
    st.push(Some("origin")).unwrap();
    rm_store(c, ".git");
    st.put(C, S1, &hex64(3), b"c").unwrap();
    st.push(None).unwrap();
    assert_eq!(remote_keys(&w), tk(&[A, B, C]));
}

#[test]
fn a_hand_fetched_local_ref_is_materialized() {
    let w = world(2);
    let r = repo(&w.clones[0]);
    let sa = AttestStore::new(&r);
    sa.put(A, S1, &hex64(1), &big("a")).unwrap();
    sa.put(B, S1, &hex64(2), &big("b")).unwrap();
    sa.push(Some("origin")).unwrap();

    let b = &w.clones[1];
    git(
        b,
        &[
            "fetch",
            "-q",
            "origin",
            "+refs/meta/main:refs/meta/local/main",
        ],
    );
    let rb = repo(b);
    let sb = AttestStore::new(&rb);
    sb.fetch(Some("origin")).unwrap();
    assert_eq!(ids(&sb), tk(&[A, B]));
    sb.put(C, S1, &hex64(3), b"c").unwrap();
    sb.push(None).unwrap();
    assert_eq!(remote_keys(&w), tk(&[A, B, C]));
}

#[test]
fn a_filter_rule_that_hides_attestations_never_deletes_them() {
    for with_other_keys in [true, false] {
        let w = world(2);
        let r = repo(&w.clones[0]);
        let sa = AttestStore::new(&r);
        sa.put(A, S1, &hex64(1), &big("a")).unwrap();
        sa.put(B, S1, &hex64(2), &big("b")).unwrap();
        sa.push(Some("origin")).unwrap();

        let b = &w.clones[1];
        let rb = repo(b);
        let sb = AttestStore::new(&rb);
        sb.fetch(Some("origin")).unwrap();
        // A (local) filter rule excludes vci's keys from serialization.
        let s = Session::open(b.as_std_path()).unwrap();
        s.target(&Target::project())
            .set_add("local:meta:filter", "exclude vci:**")
            .unwrap();
        if with_other_keys {
            // Another key makes git-meta write a new tree (without vci's).
            s.target(&Target::project())
                .set("owner", "someone")
                .unwrap();
        }
        drop(s);
        sb.put(C, S1, &hex64(3), b"c").unwrap();
        match sb.push(None) {
            Err(e) => assert!(with_other_keys, "{e}"),
            Ok(out) => {
                assert!(
                    !with_other_keys,
                    "a push that would delete A and B is refused"
                );
                assert!(
                    out.warnings.iter().any(|w| w.contains("filter rule")),
                    "{out:?}"
                );
            }
        }
        assert_eq!(remote_keys(&w), tk(&[A, B]), "the remote keeps A and B");
        assert_eq!(ids(&sb), tk(&[A, B, C]), "the local store keeps everything");
    }
}

// ---- malformed remote trees ----------------------------------------------

/// Add `entries` (raw path bytes, contents) to the remote's refs/meta/main
/// as a new commit on top of it.
fn graft(remote: &Utf8Path, entries: &[(Vec<u8>, &[u8])]) {
    let ls = Command::new("git")
        .args(["-C", remote.as_str(), "ls-tree", "-r", "-z", "--full-tree"])
        .arg("refs/meta/main")
        .output()
        .unwrap();
    assert!(ls.status.success());
    let mut index_info = ls.stdout.clone();
    for (path, content) in entries {
        let mut h = Command::new("git")
            .args(["-C", remote.as_str(), "hash-object", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        h.stdin.take().unwrap().write_all(content).unwrap();
        let out = h.wait_with_output().unwrap();
        let oid = String::from_utf8(out.stdout).unwrap().trim().to_owned();
        index_info.extend_from_slice(format!("100644 blob {oid}\t").as_bytes());
        index_info.extend_from_slice(path);
        index_info.push(0);
    }
    let idx = remote.join("graft-index");
    let _ = std::fs::remove_file(&idx);
    let mut u = Command::new("git")
        .args(["-C", remote.as_str(), "update-index", "-z", "--index-info"])
        .env("GIT_INDEX_FILE", idx.as_str())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    u.stdin.take().unwrap().write_all(&index_info).unwrap();
    assert!(u.wait().unwrap().success());
    let tree = Command::new("git")
        .args(["-C", remote.as_str(), "write-tree"])
        .env("GIT_INDEX_FILE", idx.as_str())
        .output()
        .unwrap();
    assert!(
        tree.status.success(),
        "{}",
        String::from_utf8_lossy(&tree.stderr)
    );
    let tree = String::from_utf8(tree.stdout).unwrap().trim().to_owned();
    std::fs::remove_file(&idx).unwrap();
    let commit = git(
        remote,
        &["commit-tree", &tree, "-p", "refs/meta/main", "-m", "graft"],
    );
    git(remote, &["update-ref", "refs/meta/main", &commit]);
}

fn bad_non_utf8() -> Vec<u8> {
    b"path/src/z\xff.ts/__target__/foo/__value".to_vec()
}

fn bad_short_target() -> Vec<u8> {
    b"path/ab/__target__/foo/__value".to_vec()
}

#[test]
fn malformed_remote_entries_are_ignored() {
    for bad in [bad_non_utf8(), bad_short_target()] {
        let w = world(2);
        let r = repo(&w.clones[0]);
        let sa = AttestStore::new(&r);
        sa.put(A, S1, &hex64(1), &big("a")).unwrap();
        sa.put(B, S1, &hex64(2), b"b").unwrap();
        sa.push(Some("origin")).unwrap();
        graft(&w.remote, &[(bad.clone(), b"\"poison\"")]);

        // A fresh clone reads the good values.
        let dir = fresh_reader(&w, "fresh");
        let rf = repo(&dir);
        let sf = AttestStore::new(&rf);
        let out = sf.fetch(Some("origin")).unwrap();
        assert_eq!(ids(&sf), tk(&[A, B]), "{}", String::from_utf8_lossy(&bad));
        assert!(
            out.warnings
                .iter()
                .any(|w| w.contains("git-meta cannot read")),
            "{out:?}"
        );
        // Fetching the same remote again merges the same cleaned-up commit.
        let tracking = git(&dir, &["rev-parse", "refs/meta/remotes/main"]);
        let local = git(&dir, &["rev-parse", "refs/meta/local/main"]);
        sf.fetch(None).unwrap();
        assert_eq!(
            git(&dir, &["rev-parse", "refs/meta/remotes/main"]),
            tracking
        );
        assert_eq!(git(&dir, &["rev-parse", "refs/meta/local/main"]), local);
        // An existing clone can still publish, and its push leaves the
        // entries out.
        sa.put(C, S1, &hex64(3), b"c").unwrap();
        sa.push(None).unwrap();
        assert_eq!(remote_keys(&w), tk(&[A, B, C]));
        let names = Command::new("git")
            .args([
                "-C",
                w.remote.as_str(),
                "ls-tree",
                "-r",
                "-z",
                "--name-only",
            ])
            .arg("refs/meta/main")
            .output()
            .unwrap()
            .stdout;
        assert!(
            !names.split(|b| *b == 0).any(|n| n == bad.as_slice()),
            "the push left the malformed entry out"
        );
        sf.fetch(None).unwrap();
        assert_eq!(ids(&sf), tk(&[A, B, C]));
    }
}

#[test]
fn a_store_poisoned_by_an_earlier_fetch_recovers() {
    // What an earlier vci (or `git meta pull`) left behind after fetching a
    // tree with a path target shorter than git-meta's minimum: the value in
    // SQLite and in refs/meta/local/main.
    let w = world(1);
    let c = &w.clones[0];
    let r = repo(c);
    let st = AttestStore::new(&r);
    st.put(A, S1, &hex64(1), &big("a")).unwrap();
    st.push(Some("origin")).unwrap();
    graft(&w.remote, &[(bad_short_target(), b"\"poison\"")]);
    git(
        c,
        &[
            "fetch",
            "-q",
            "meta",
            "+refs/meta/main:refs/meta/remotes/main",
        ],
    );
    let s = Session::open(c.as_std_path()).unwrap();
    let _ = s.materialize(None).unwrap();
    drop(s);

    st.fetch(None).unwrap();
    st.put(B, S1, &hex64(2), b"b").unwrap();
    st.push(None).unwrap();
    assert_eq!(remote_keys(&w), tk(&[A, B]));
}

// ---- unreadable values and read-only stores ------------------------------

#[test]
fn one_unreadable_value_only_hides_its_own_unit() {
    let w = world(2);
    let r = repo(&w.clones[0]);
    let sa = AttestStore::new(&r);
    sa.put(A, S1, &hex64(1), &big("a")).unwrap();
    sa.put(B, S1, &hex64(2), &big("b")).unwrap();
    sa.push(Some("origin")).unwrap();
    // A fresh clone keeps both values as blob references (git-meta stores
    // values over 1 KiB that way when it materializes them).
    let c = &w.clones[1];
    let rc = repo(c);
    let sc = AttestStore::new(&rc);
    sc.fetch(Some("origin")).unwrap();
    let blob_of = |id: &str, sk: &str| {
        git(
            c,
            &[
                "rev-parse",
                &format!(
                    "refs/meta/remotes/main:path/{id}/__target__/vci/attestation/{}/{S1}/{sk}/__value",
                    vci_core::test_key(id)
                ),
            ],
        )
    };
    let a_blob = blob_of(A, &hex64(1));
    let _ = blob_of(B, &hex64(2));
    // Every metadata ref goes; only A's blob stays reachable; gc drops B's.
    for r in git(c, &["for-each-ref", "--format=%(refname)", "refs/meta"]).lines() {
        git(c, &["update-ref", "-d", r]);
    }
    git(c, &["update-ref", "refs/keep/a", &a_blob]);
    git(c, &["reflog", "expire", "--expire=now", "--all"]);
    git(c, &["gc", "-q", "--prune=now"]);

    let a = sc.list(Some(A)).unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].bytes, big("a"));
    let b = sc.list(Some(B));
    assert!(b.is_ok(), "{b:?}");
    assert_eq!(
        sc.list(None).map(|l| l.len()).ok(),
        Some(2),
        "listing works too"
    );
}

#[cfg(unix)]
#[test]
fn a_read_only_git_dir_can_still_be_read() {
    use std::os::unix::fs::PermissionsExt;
    let (_t, root) = init_repo();
    let r = repo(&root);
    let st = AttestStore::new(&r);
    st.put(A, S1, &hex64(1), &big("a")).unwrap();
    st.put(B, S1, &hex64(2), b"b").unwrap();
    let chmod = |mode_dir: u32, mode_file: u32| {
        for e in walk(&root.join(".git")) {
            let m = if e.is_dir() { mode_dir } else { mode_file };
            std::fs::set_permissions(&e, std::fs::Permissions::from_mode(m)).unwrap();
        }
    };
    chmod(0o555, 0o444);
    let got = st.list(None);
    chmod(0o755, 0o644);
    let got = got.unwrap();
    assert_eq!(got.len(), 2);
    assert!(got.iter().any(|e| e.bytes == big("a")));
}

fn walk(dir: &Utf8Path) -> Vec<Utf8PathBuf> {
    let mut out = vec![dir.to_owned()];
    for e in std::fs::read_dir(dir).unwrap() {
        let p = Utf8PathBuf::from_path_buf(e.unwrap().path()).unwrap();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

// ---- concurrency ------------------------------------------------------------

#[test]
fn concurrent_pushes_in_one_clone_all_succeed() {
    let w = world(2);
    let root = &w.clones[0];
    AttestStore::new(&repo(root)).push(Some("origin")).unwrap();
    for round in 0..3u8 {
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for i in 0..3u8 {
                handles.push(scope.spawn(move || {
                    let r = repo(root);
                    let st = AttestStore::new(&r);
                    let n = round * 16 + i;
                    st.put(&format!("src/t{n}.test.ts"), S1, &hex64(n), &[b'a' + i])
                        .unwrap();
                    st.push(None).map(|_| ())
                }));
            }
            // A git-meta client writing and serializing alongside.
            handles.push(scope.spawn(move || {
                let s = Session::open(root.as_std_path()).unwrap();
                s.target(&Target::project())
                    .set(&format!("other:key{round}"), "x")
                    .unwrap();
                s.serialize()
                    .map(|_| ())
                    .map_err(|e| vci_git::GitError::Meta(format!("git-meta serialize: {e}")))
            }));
            for h in handles {
                h.join().unwrap().unwrap();
            }
        });
    }
    let r = repo(root);
    let st = AttestStore::new(&r);
    st.push(None).unwrap();
    assert_eq!(remote_keys(&w).len(), 9);
}

// ---- .git-meta ---------------------------------------------------------------

#[test]
fn setup_file_urls_that_run_programs_or_read_descriptors_are_refused() {
    for bad in [
        "fd::3",
        "ext::sh -c touch% /tmp/vci-pwned",
        "-oProxyCommand=touch /tmp/vci-pwned",
        "--upload-pack=touch /tmp/vci-pwned",
        "foo::bar",
    ] {
        let w = world(1);
        let c = &w.clones[0];
        git(c, &["remote", "remove", "origin"]);
        write(c, ".git-meta", &format!("url: {bad}\n"));
        let r = repo(c);
        let res = AttestStore::new(&r).ensure_remote(None);
        assert!(res.is_err(), "{bad}: {res:?}");
        let cfg = git_raw(c, &["config", "--get-regexp", "^remote\\."]);
        assert!(
            String::from_utf8_lossy(&cfg.stdout).trim().is_empty(),
            "{bad}: nothing was configured"
        );
    }
    for good in [
        "https://github.com/o/r.git",
        "git@github.com:o/r.git",
        "ssh://git@example.com/o/r.git",
        "file:///srv/meta.git",
        "/srv/meta.git",
        "../meta.git",
    ] {
        let w = world(1);
        let c = &w.clones[0];
        git(c, &["remote", "remove", "origin"]);
        write(c, ".git-meta", &format!("url: {good}\n"));
        let r = repo(c);
        assert_eq!(
            AttestStore::new(&r).ensure_remote(None).unwrap(),
            "meta",
            "{good}"
        );
    }
}

// ---- shared settings and push outcomes -----------------------------------------

#[test]
fn shared_auto_prune_is_reported_by_fetch() {
    let w = world(2);
    let r = repo(&w.clones[0]);
    let sa = AttestStore::new(&r);
    for i in 0..6u8 {
        sa.put(&format!("src/t{i}.test.ts"), S1, &hex64(i + 1), &big("t"))
            .unwrap();
    }
    let first = sa.push(Some("origin")).unwrap();
    assert!(first.warnings.is_empty(), "{first:?}");

    // Another collaborator turns on git-meta's auto-prune in the shared
    // metadata and publishes with git-meta (serialize + push).
    let b = &w.clones[1];
    let rb = repo(b);
    AttestStore::new(&rb).fetch(Some("origin")).unwrap();
    let s = Session::open(b.as_std_path()).unwrap();
    let project = s.target(&Target::project());
    project.set("meta:prune:max-keys", "4").unwrap();
    project.set("meta:prune:min-keys", "2").unwrap();
    let out = s.serialize().unwrap();
    assert!(out.pruned > 0, "git-meta pruned: {out:?}");
    drop(s);
    git(
        b,
        &["push", "-q", "meta", "refs/meta/local/main:refs/meta/main"],
    );

    let out = sa.fetch(None).unwrap();
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("auto-prune is configured")),
        "{out:?}"
    );
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("without a deletion record")),
        "{out:?}"
    );
    assert!(sa.list(None).unwrap().len() < 6);
    // vci's push warns too (it never prunes itself).
    let pushed = sa.push(None).unwrap();
    assert!(
        pushed
            .warnings
            .iter()
            .any(|w| w.contains("auto-prune is configured")),
        "{pushed:?}"
    );
}

#[test]
fn push_says_whether_anything_was_sent() {
    use vci_git::PushStatus;
    let w = world(1);
    let r = repo(&w.clones[0]);
    let st = AttestStore::new(&r);
    assert_eq!(
        st.push(Some("origin")).unwrap().status,
        PushStatus::NothingStored
    );
    st.put(A, S1, &hex64(1), b"a").unwrap();
    assert_eq!(st.push(None).unwrap().status, PushStatus::Pushed);
    let tip = git(&w.remote, &["rev-parse", "refs/meta/main"]);
    assert_eq!(st.push(None).unwrap().status, PushStatus::UpToDate);
    assert_eq!(git(&w.remote, &["rev-parse", "refs/meta/main"]), tip);
}
