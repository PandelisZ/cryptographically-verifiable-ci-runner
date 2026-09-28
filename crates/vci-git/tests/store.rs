mod common;

use std::collections::BTreeSet;

use camino::Utf8Path;
use common::*;
use vci_git::{AttestStore, GitError, REF_PREFIX, Repo, StoredEnvelope};

const S1: &str = "0123456789abcdef";
const S2: &str = "fedcba9876543210";

fn keys(list: &[StoredEnvelope]) -> BTreeSet<(String, String, String, Vec<u8>)> {
    list.iter()
        .map(|e| {
            (
                e.signer_ref.clone(),
                e.test_key.clone(),
                e.input_root.clone(),
                e.bytes.clone(),
            )
        })
        .collect()
}

fn all_refs(root: &Utf8Path) -> String {
    git(root, &["for-each-ref", "--format=%(objectname) %(refname)"])
}

#[test]
fn put_then_list() {
    let (_t, root) = init_repo();
    let repo = Repo::discover(&root).unwrap();
    let store = AttestStore::new(&repo);
    assert!(store.list(None).unwrap().is_empty());

    let (k1, k2) = (hex64(0x11), hex64(0x22));
    let (r1, r2) = (hex64(0xa1), hex64(0xa2));
    store.put(S1, &k1, &r1, b"{\"env\":1}").unwrap();
    store.put(S1, &k1, &r2, b"{\"env\":2}").unwrap();
    store.put(S1, &k2, &r1, b"{\"env\":3}").unwrap();
    store.put(S2, &k1, &r1, b"{\"env\":4}\n\0binary").unwrap();

    let all = store.list(None).unwrap();
    assert_eq!(all.len(), 4);
    let s1_ref = format!("{REF_PREFIX}{S1}");
    let s2_ref = format!("{REF_PREFIX}{S2}");
    assert_eq!(
        all[0],
        StoredEnvelope {
            signer_ref: s1_ref.clone(),
            test_key: k1.clone(),
            input_root: r1.clone(),
            bytes: b"{\"env\":1}".to_vec(),
        }
    );
    assert_eq!(all[3].signer_ref, s2_ref);
    assert_eq!(
        all[3].bytes, b"{\"env\":4}\n\0binary",
        "bytes are stored verbatim"
    );

    let only_k1 = store.list(Some(&k1)).unwrap();
    assert_eq!(only_k1.len(), 3);
    assert!(only_k1.iter().all(|e| e.test_key == k1));
    assert!(store.list(Some(&hex64(0x33))).unwrap().is_empty());

    // Tree layout on the ref is <key[0..2]>/<key>/<root>.dsse.json.
    let files = git(&root, &["ls-tree", "-r", "--name-only", &s1_ref]);
    assert_eq!(
        files.lines().collect::<Vec<_>>(),
        vec![
            format!("11/{k1}/{r1}.dsse.json"),
            format!("11/{k1}/{r2}.dsse.json"),
            format!("22/{k2}/{r1}.dsse.json"),
        ]
    );

    // Putting identical bytes again is a no-op; different bytes replace.
    let before = git(&root, &["rev-parse", &s1_ref]);
    store.put(S1, &k1, &r1, b"{\"env\":1}").unwrap();
    assert_eq!(git(&root, &["rev-parse", &s1_ref]), before);
    store.put(S1, &k1, &r1, b"{\"env\":1,\"v\":2}").unwrap();
    assert_ne!(git(&root, &["rev-parse", &s1_ref]), before);
    let again = store.list(Some(&k1)).unwrap();
    assert_eq!(again.len(), 3);
    assert_eq!(again[0].bytes, b"{\"env\":1,\"v\":2}");
}

#[test]
fn put_does_not_touch_status_head_or_index() {
    let (_t, root) = init_repo();
    // Make every kind of local state present: staged, unstaged, untracked.
    write(&root, "a.txt", "staged change\n");
    git(&root, &["add", "a.txt"]);
    write(&root, "a.txt", "staged change\nplus unstaged\n");
    write(&root, "untracked.txt", "u\n");
    git(&root, &["checkout", "-q", "-b", "work"]);

    let index_path = root.join(".git/index");
    let status = git(
        &root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    );
    let head_sym = git(&root, &["symbolic-ref", "HEAD"]);
    let head = git(&root, &["rev-parse", "HEAD"]);
    let staged = git(&root, &["diff", "--cached"]);
    let unstaged = git(&root, &["diff"]);
    let branches = git(&root, &["for-each-ref", "refs/heads"]);
    // Captured last, so no setup command above can be what rewrote it.
    let index = std::fs::read(&index_path).unwrap();
    let index_mtime = std::fs::metadata(&index_path).unwrap().modified().unwrap();

    let repo = Repo::discover(&root).unwrap();
    let store = AttestStore::new(&repo);
    store.put(S1, &hex64(1), &hex64(2), b"env-a").unwrap();
    store.put(S1, &hex64(3), &hex64(4), b"env-b").unwrap();
    store.put(S2, &hex64(1), &hex64(2), b"env-c").unwrap();
    assert_eq!(store.list(None).unwrap().len(), 3);
    // Checked before any other git command can refresh the index.
    assert_eq!(
        std::fs::read(&index_path).unwrap(),
        index,
        "index bytes unchanged"
    );
    assert_eq!(
        std::fs::metadata(&index_path).unwrap().modified().unwrap(),
        index_mtime,
        "index not rewritten"
    );

    assert_eq!(
        git(
            &root,
            &["status", "--porcelain=v1", "--untracked-files=all"]
        ),
        status
    );
    assert_eq!(git(&root, &["symbolic-ref", "HEAD"]), head_sym);
    assert_eq!(git(&root, &["rev-parse", "HEAD"]), head);
    assert_eq!(git(&root, &["diff", "--cached"]), staged);
    assert_eq!(git(&root, &["diff"]), unstaged);
    assert_eq!(git(&root, &["for-each-ref", "refs/heads"]), branches);
    assert_eq!(
        std::fs::read_to_string(root.join("a.txt")).unwrap(),
        "staged change\nplus unstaged\n"
    );
    // No stray files in the work tree.
    let untracked = git(&root, &["ls-files", "--others", "--exclude-standard"]);
    assert_eq!(untracked, "untracked.txt");
}

#[test]
fn put_works_without_configured_identity() {
    let (_t, root) = init_repo();
    // An empty configured identity makes plain `git commit-tree` fail.
    git(&root, &["config", "user.name", ""]);
    git(&root, &["config", "user.email", ""]);
    git(&root, &["config", "user.useConfigOnly", "true"]);
    let repo = Repo::discover(&root).unwrap();
    AttestStore::new(&repo)
        .put(S1, &hex64(1), &hex64(2), b"x")
        .unwrap();
    let author = git(
        &root,
        &[
            "log",
            "-1",
            "--format=%an <%ae> / %cn <%ce>",
            &format!("{REF_PREFIX}{S1}"),
        ],
    );
    assert_eq!(author, "vci <vci@localhost> / vci <vci@localhost>");
}

#[test]
fn put_ignores_commit_signing_config() {
    let (_t, root) = init_repo();
    git(&root, &["config", "commit.gpgSign", "true"]);
    git(&root, &["config", "gpg.program", "/nonexistent/gpg"]);
    let repo = Repo::discover(&root).unwrap();
    AttestStore::new(&repo)
        .put(S1, &hex64(1), &hex64(2), b"x")
        .unwrap();
}

#[test]
fn malformed_ids_are_rejected() {
    let (_t, root) = init_repo();
    let repo = Repo::discover(&root).unwrap();
    let store = AttestStore::new(&repo);
    let refs_before = all_refs(&root);
    let good_key = hex64(1);
    let good_root = hex64(2);

    let bad_signers = [
        "",
        "0123456789ABCDEF",
        "0123456789abcde",
        "0123456789abcdef00",
        "../../heads/main",
        "..%2f..%2fheads",
        "0123456789abcdeg",
        "0123456/89abcdef",
        "0123456789abcde\n",
        "heads/main",
    ];
    for s in bad_signers {
        assert!(
            matches!(
                store.put(s, &good_key, &good_root, b"x"),
                Err(GitError::Invalid {
                    what: "signer_id",
                    ..
                })
            ),
            "signer {s:?}"
        );
    }
    let bad_hex = [
        "", "a", "AB", "../../x", "ab/cd", "ab.dsse", "abc\0", " ab", "zz",
    ];
    let too_long = "a".repeat(129);
    for h in bad_hex.iter().copied().chain([too_long.as_str()]) {
        assert!(
            matches!(
                store.put(S1, h, &good_root, b"x"),
                Err(GitError::Invalid {
                    what: "test_key",
                    ..
                })
            ),
            "test_key {h:?}"
        );
        assert!(
            matches!(
                store.put(S1, &good_key, h, b"x"),
                Err(GitError::Invalid {
                    what: "input_root",
                    ..
                })
            ),
            "input_root {h:?}"
        );
        assert!(
            matches!(store.list(Some(h)), Err(GitError::Invalid { .. })),
            "list {h:?}"
        );
    }
    for r in ["", "--upload-pack=touch /tmp/pwned", "-o", "a\nb"] {
        assert!(
            matches!(store.fetch(r), Err(GitError::Invalid { .. })),
            "{r:?}"
        );
        assert!(
            matches!(store.push(r), Err(GitError::Invalid { .. })),
            "{r:?}"
        );
    }
    assert_eq!(all_refs(&root), refs_before, "nothing was written");
}

#[test]
fn list_skips_malformed_refs_and_entries() {
    let (_t, root) = init_repo();
    let repo = Repo::discover(&root).unwrap();
    let store = AttestStore::new(&repo);
    store.put(S1, &hex64(1), &hex64(2), b"good").unwrap();

    // A ref with a non-hex name, a ref pointing at a blob, and a signer ref
    // whose tree holds only junk.
    let head = git(&root, &["rev-parse", "HEAD"]);
    git(
        &root,
        &["update-ref", &format!("{REF_PREFIX}NOT-A-SIGNER"), &head],
    );
    let blob = git(&root, &["rev-parse", "HEAD:a.txt"]);
    git(
        &root,
        &[
            "update-ref",
            &format!("{REF_PREFIX}aaaaaaaaaaaaaaaa"),
            &blob,
        ],
    );
    git(
        &root,
        &[
            "update-ref",
            &format!("{REF_PREFIX}bbbbbbbbbbbbbbbb"),
            &head,
        ],
    );

    let all = store.list(None).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].bytes, b"good");
}

#[test]
fn two_clones_push_and_fetch_end_with_union() {
    let w = world(3);
    let (a_root, b_root, c_root) = (&w.clones[0], &w.clones[1], &w.clones[2]);
    let a = Repo::discover(a_root).unwrap();
    let b = Repo::discover(b_root).unwrap();
    let c = Repo::discover(c_root).unwrap();
    let (sa, sb, sc) = (
        AttestStore::new(&a),
        AttestStore::new(&b),
        AttestStore::new(&c),
    );

    let status_a = git(a_root, &["status", "--porcelain=v1"]);
    let head_a = git(a_root, &["rev-parse", "HEAD"]);

    // Same signer, different envelopes, written independently.
    sa.put(S1, &hex64(1), &hex64(0xa), b"from A").unwrap();
    sb.put(S1, &hex64(2), &hex64(0xb), b"from B").unwrap();
    sb.put(S2, &hex64(3), &hex64(0xc), b"other signer from B")
        .unwrap();

    sa.push("origin").unwrap();
    sb.push("origin").unwrap(); // must merge A's commit, not overwrite it
    sa.fetch("origin").unwrap();
    sb.fetch("origin").unwrap();
    sc.fetch(w.remote.as_str()).unwrap(); // by path, not remote name

    let expected: BTreeSet<_> = [
        (
            format!("{REF_PREFIX}{S1}"),
            hex64(1),
            hex64(0xa),
            b"from A".to_vec(),
        ),
        (
            format!("{REF_PREFIX}{S1}"),
            hex64(2),
            hex64(0xb),
            b"from B".to_vec(),
        ),
        (
            format!("{REF_PREFIX}{S2}"),
            hex64(3),
            hex64(0xc),
            b"other signer from B".to_vec(),
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(keys(&sa.list(None).unwrap()), expected);
    assert_eq!(keys(&sb.list(None).unwrap()), expected);
    assert_eq!(keys(&sc.list(None).unwrap()), expected);

    // Remote holds the union too, and both clones agree on the ref values.
    let remote_tree = git(
        &w.remote,
        &["ls-tree", "-r", "--name-only", &format!("{REF_PREFIX}{S1}")],
    );
    assert_eq!(remote_tree.lines().count(), 2);
    for s in [S1, S2] {
        let r = format!("{REF_PREFIX}{s}");
        assert_eq!(
            git(a_root, &["rev-parse", &r]),
            git(b_root, &["rev-parse", &r])
        );
    }

    // Sync never touched A's work tree, index or HEAD.
    assert_eq!(git(a_root, &["status", "--porcelain=v1"]), status_a);
    assert_eq!(git(a_root, &["rev-parse", "HEAD"]), head_a);
}

#[test]
fn push_retries_when_remote_moves_underneath() {
    let w = world(2);
    let a = Repo::discover(&w.clones[0]).unwrap();
    let b = Repo::discover(&w.clones[1]).unwrap();
    let (sa, sb) = (AttestStore::new(&a), AttestStore::new(&b));
    sa.put(S1, &hex64(1), &hex64(1), b"A1").unwrap();
    sb.put(S1, &hex64(2), &hex64(2), b"B1").unwrap();

    // B pushes in the window between A's fetch+merge and A's push, so A's
    // first push is a non-fast-forward and must be retried.
    let mut attempts = Vec::new();
    sa.push_with_hook("origin", |attempt| {
        attempts.push(attempt);
        if attempt == 1 {
            sb.push("origin").unwrap();
        }
    })
    .unwrap();
    assert_eq!(
        attempts,
        vec![1, 2],
        "first push rejected, second succeeded"
    );

    sb.fetch("origin").unwrap();
    let want: BTreeSet<_> = [b"A1".to_vec(), b"B1".to_vec()].into_iter().collect();
    for s in [&sa, &sb] {
        let got: BTreeSet<_> = s.list(None).unwrap().into_iter().map(|e| e.bytes).collect();
        assert_eq!(got, want);
    }
}

#[test]
fn concurrent_pushers_converge_on_union() {
    const CLONES: usize = 4;
    const PER_CLONE: u8 = 3;
    let w = world(CLONES);
    std::thread::scope(|scope| {
        for (i, clone) in w.clones.iter().enumerate() {
            scope.spawn(move || {
                let repo = Repo::discover(clone).unwrap();
                let store = AttestStore::new(&repo);
                for j in 0..PER_CLONE {
                    let n = (i as u8) * 16 + j;
                    store
                        .put(
                            S1,
                            &hex64(n),
                            &hex64(n),
                            format!("clone {i} env {j}").as_bytes(),
                        )
                        .unwrap();
                    store.push("origin").unwrap();
                }
            });
        }
    });
    let mut expected = BTreeSet::new();
    for i in 0..CLONES {
        for j in 0..PER_CLONE {
            expected.insert(format!("clone {i} env {j}").into_bytes());
        }
    }
    for clone in &w.clones {
        let repo = Repo::discover(clone).unwrap();
        let store = AttestStore::new(&repo);
        store.fetch("origin").unwrap();
        let got: BTreeSet<_> = store
            .list(None)
            .unwrap()
            .into_iter()
            .map(|e| e.bytes)
            .collect();
        assert_eq!(got, expected, "clone {clone}");
    }
}

#[test]
fn conflicting_bytes_for_same_key_converge() {
    let w = world(2);
    let a = Repo::discover(&w.clones[0]).unwrap();
    let b = Repo::discover(&w.clones[1]).unwrap();
    let (sa, sb) = (AttestStore::new(&a), AttestStore::new(&b));
    sa.put(S1, &hex64(1), &hex64(1), b"version A").unwrap();
    sb.put(S1, &hex64(1), &hex64(1), b"version B").unwrap();
    sa.put(S1, &hex64(2), &hex64(2), b"only A").unwrap();
    sa.push("origin").unwrap();
    sb.push("origin").unwrap();
    sa.fetch("origin").unwrap();
    sb.fetch("origin").unwrap();
    let la = sa.list(None).unwrap();
    let lb = sb.list(None).unwrap();
    assert_eq!(la, lb, "both clones agree");
    assert_eq!(la.len(), 2);
    assert!(la.iter().any(|e| e.bytes == b"only A"));
}

#[test]
fn sync_with_empty_remote_and_empty_store() {
    let w = world(2);
    let a = Repo::discover(&w.clones[0]).unwrap();
    let sa = AttestStore::new(&a);
    sa.fetch("origin").unwrap();
    sa.push("origin").unwrap();
    assert!(sa.list(None).unwrap().is_empty());
    assert_eq!(git(&w.remote, &["for-each-ref", "refs/attest"]), "");

    sa.put(S2, &hex64(9), &hex64(9), b"x").unwrap();
    sa.push("origin").unwrap();
    // Pushing again with nothing new is fine.
    sa.push("origin").unwrap();
    let b = Repo::discover(&w.clones[1]).unwrap();
    let sb = AttestStore::new(&b);
    sb.fetch("origin").unwrap();
    assert_eq!(sb.list(None).unwrap().len(), 1);
    // Fetch into an existing identical ref is a no-op.
    let before = all_refs(&w.clones[1]);
    sb.fetch("origin").unwrap();
    assert_eq!(all_refs(&w.clones[1]), before);
}

#[test]
fn fetch_from_unreachable_remote_is_an_error() {
    let (_t, root) = init_repo();
    let repo = Repo::discover(&root).unwrap();
    let store = AttestStore::new(&repo);
    let missing = root.join("no-such-remote.git");
    assert!(matches!(
        store.fetch(missing.as_str()),
        Err(GitError::Command { .. })
    ));
    store.put(S1, &hex64(1), &hex64(1), b"x").unwrap();
    assert!(store.push(missing.as_str()).is_err());
}

#[test]
fn concurrent_puts_in_one_repo_lose_nothing() {
    let (_t, root) = init_repo();
    std::thread::scope(|scope| {
        for i in 0..8u8 {
            let root = &root;
            scope.spawn(move || {
                let repo = Repo::discover(root).unwrap();
                let store = AttestStore::new(&repo);
                for j in 0..3u8 {
                    let n = i * 16 + j;
                    store.put(S1, &hex64(n), &hex64(n), &[n]).unwrap();
                }
            });
        }
    });
    let repo = Repo::discover(&root).unwrap();
    assert_eq!(AttestStore::new(&repo).list(None).unwrap().len(), 24);
}
