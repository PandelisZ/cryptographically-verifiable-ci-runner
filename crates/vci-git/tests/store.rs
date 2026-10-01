//! The git-meta attestation store: local writes, exchange through a bare
//! remote, merge behaviour, and interoperability with the `git meta` CLI.

mod common;

use std::collections::BTreeSet;
use std::process::Command;

use camino::{Utf8Path, Utf8PathBuf};
use common::*;
use git_meta_lib::{Session, Target};
use vci_git::{AttestStore, GitError, Repo, StoredEnvelope};

const S1: &str = "0123456789abcdef";
const S2: &str = "fedcba9876543210";
const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";

type Row = (String, String, String, String, Vec<u8>);

fn rows(list: &[StoredEnvelope]) -> BTreeSet<Row> {
    list.iter()
        .map(|e| {
            (
                e.target.clone(),
                e.test_key.clone(),
                e.signer.clone(),
                e.storage_key.clone(),
                e.bytes.clone(),
            )
        })
        .collect()
}

fn row(test_id: &str, signer: &str, sk: &str, bytes: &[u8]) -> Row {
    (
        format!("path:{test_id}"),
        vci_core::test_key(test_id),
        signer.to_owned(),
        sk.to_owned(),
        bytes.to_vec(),
    )
}

fn all_refs(root: &Utf8Path) -> String {
    git(root, &["for-each-ref", "--format=%(objectname) %(refname)"])
}

fn store(root: &Utf8Path) -> (Repo, Utf8PathBuf) {
    (Repo::discover(root).unwrap(), root.to_owned())
}

/// An envelope-sized value: git-meta keeps values over 1 KiB as blob
/// references, which must come back byte for byte.
fn big(tag: &str, n: usize) -> Vec<u8> {
    let mut v = format!("{{\"payloadType\":\"{tag}\",\"payload\":\"").into_bytes();
    v.extend(std::iter::repeat_n(b'A', n));
    v.extend_from_slice(b"\",\"signatures\":[]}");
    v
}

#[test]
fn put_then_list() {
    let (_t, root) = init_repo();
    let (repo, _) = store(&root);
    let st = AttestStore::new(&repo);
    assert!(st.list(None).unwrap().is_empty());
    assert!(
        !root.join(".git/git-meta.sqlite").exists(),
        "reading creates no store"
    );

    let (r1, r2) = (hex64(0xa1), hex64(0xa2));
    let e1 = big("one", 5000);
    st.put(A, S1, &r1, &e1).unwrap();
    st.put(A, S1, &r2, b"{\"env\":2}").unwrap();
    st.put(B, S1, &r1, b"{\"env\":3}").unwrap();
    st.put(A, S2, &r1, b"{\"env\":4}\n\ttabs and newlines\n")
        .unwrap();

    let all = st.list(None).unwrap();
    assert_eq!(all.len(), 4);
    assert_eq!(
        rows(&all),
        [
            row(A, S1, &r1, &e1),
            row(A, S1, &r2, b"{\"env\":2}"),
            row(B, S1, &r1, b"{\"env\":3}"),
            row(A, S2, &r1, b"{\"env\":4}\n\ttabs and newlines\n"),
        ]
        .into_iter()
        .collect()
    );
    let a = st.list(Some(A)).unwrap();
    assert_eq!(a.len(), 3);
    assert!(a.iter().all(|e| e.test_key == vci_core::test_key(A)));
    assert_eq!(
        a.iter()
            .find(|e| e.storage_key == r1 && e.signer == S1)
            .unwrap()
            .key,
        format!("vci:attestation:{}:{S1}:{r1}", vci_core::test_key(A))
    );
    assert!(st.list(Some("src/none.test.ts")).unwrap().is_empty());

    // Identical bytes again: no write at all. Different bytes: replaced.
    let log = || {
        Session::open(root.as_std_path())
            .unwrap()
            .target(&Target::path(A))
            .get_authorship(&format!(
                "vci:attestation:{}:{S1}:{r1}",
                vci_core::test_key(A)
            ))
            .unwrap()
    };
    let before = log();
    st.put(A, S1, &r1, &e1).unwrap();
    assert_eq!(log(), before, "identical bytes are not rewritten");
    st.put(A, S1, &r1, b"{\"env\":1,\"v\":2}").unwrap();
    let again = st.list(Some(A)).unwrap();
    assert_eq!(again.len(), 3);
    assert!(again.iter().any(|e| e.bytes == b"{\"env\":1,\"v\":2}"));
}

#[test]
fn values_are_git_meta_metadata_on_the_unit_path() {
    let w = world(1);
    let c = &w.clones[0];
    let (repo, _) = store(c);
    let st = AttestStore::new(&repo);
    let e = big("x", 200_000);
    st.put(A, S1, &hex64(1), &e).unwrap();
    st.put("rust/core#test:it", S1, &hex64(2), b"cargo")
        .unwrap();
    st.put("rs#lib", S1, &hex64(3), b"short dir").unwrap();
    st.put(".", S1, &hex64(4), b"root package").unwrap();
    st.push(Some("origin")).unwrap();

    // The exchange tree on the remote is git-meta's documented layout.
    let tree = git(
        &w.remote,
        &["ls-tree", "-r", "--name-only", "refs/meta/main"],
    );
    let tka = vci_core::test_key(A);
    let want = [
        format!(
            "path/src/a.test.ts/__target__/vci/attestation/{tka}/{S1}/{}/__value",
            hex64(1)
        ),
        format!(
            "path/rust/core/__target__/vci/attestation/{}/{S1}/{}/__value",
            vci_core::test_key("rust/core#test:it"),
            hex64(2)
        ),
        format!(
            "project/vci/attestation/{}/{S1}/{}/__value",
            vci_core::test_key("rs#lib"),
            hex64(3)
        ),
        format!(
            "project/vci/attestation/{}/{S1}/{}/__value",
            vci_core::test_key("."),
            hex64(4)
        ),
    ];
    for p in &want {
        assert!(tree.lines().any(|l| l == p), "{p} not in\n{tree}");
    }
    // The blob is the envelope, byte for byte.
    let blob = Command::new("git")
        .args(["-C", w.remote.as_str(), "cat-file", "blob"])
        .arg(format!("refs/meta/main:{}", want[0]))
        .output()
        .unwrap();
    assert_eq!(blob.stdout, e);
    // Remote and local config are git-meta's.
    assert_eq!(git(c, &["config", "remote.meta.meta"]), "true");
    assert_eq!(
        git(c, &["config", "remote.meta.fetch"]),
        "+refs/meta/main:refs/meta/remotes/main"
    );
    assert_eq!(
        git(c, &["config", "remote.meta.url"]),
        git(c, &["config", "remote.origin.url"])
    );
}

#[test]
fn put_and_sync_do_not_touch_status_head_or_index() {
    let w = world(1);
    let root = &w.clones[0];
    // Make every kind of local state present: staged, unstaged, untracked.
    write(root, "a.txt", "staged change\n");
    git(root, &["add", "a.txt"]);
    write(root, "a.txt", "staged change\nplus unstaged\n");
    write(root, "untracked.txt", "u\n");
    git(root, &["checkout", "-q", "-b", "work"]);

    let index_path = root.join(".git/index");
    let status = git(root, &["status", "--porcelain=v1", "--untracked-files=all"]);
    let head_sym = git(root, &["symbolic-ref", "HEAD"]);
    let head = git(root, &["rev-parse", "HEAD"]);
    let staged = git(root, &["diff", "--cached"]);
    let unstaged = git(root, &["diff"]);
    let branches = git(root, &["for-each-ref", "refs/heads", "refs/remotes"]);
    // Captured last, so no setup command above can be what rewrote it.
    let index = std::fs::read(&index_path).unwrap();
    let index_mtime = std::fs::metadata(&index_path).unwrap().modified().unwrap();

    let (repo, _) = store(root);
    let st = AttestStore::new(&repo);
    st.put(A, S1, &hex64(2), b"env-a").unwrap();
    st.put(B, S1, &hex64(4), b"env-b").unwrap();
    st.put(A, S2, &hex64(2), b"env-c").unwrap();
    st.push(Some("origin")).unwrap();
    st.fetch(None).unwrap();
    assert_eq!(st.list(None).unwrap().len(), 3);
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
        git(root, &["status", "--porcelain=v1", "--untracked-files=all"]),
        status
    );
    assert_eq!(git(root, &["symbolic-ref", "HEAD"]), head_sym);
    assert_eq!(git(root, &["rev-parse", "HEAD"]), head);
    assert_eq!(git(root, &["diff", "--cached"]), staged);
    assert_eq!(git(root, &["diff"]), unstaged);
    assert_eq!(
        git(root, &["for-each-ref", "refs/heads", "refs/remotes"]),
        branches
    );
    assert_eq!(
        std::fs::read_to_string(root.join("a.txt")).unwrap(),
        "staged change\nplus unstaged\n"
    );
    // No stray files in the work tree.
    let untracked = git(root, &["ls-files", "--others", "--exclude-standard"]);
    assert_eq!(untracked, "untracked.txt");
}

#[test]
fn push_works_without_identity_and_ignores_signing_config() {
    let w = world(2);
    let c = &w.clones[0];
    // An empty configured identity makes plain `git commit-tree` fail, and a
    // signing program that does not exist makes signed commits fail.
    git(c, &["config", "user.name", ""]);
    git(c, &["config", "user.email", ""]);
    git(c, &["config", "user.useConfigOnly", "true"]);
    git(c, &["config", "commit.gpgSign", "true"]);
    git(c, &["config", "gpg.program", "/nonexistent/gpg"]);
    let (b, _) = store(&w.clones[1]);
    AttestStore::new(&b)
        .put(B, S2, &hex64(9), b"first")
        .unwrap();
    AttestStore::new(&b).push(Some("origin")).unwrap();
    let (repo, _) = store(c);
    let st = AttestStore::new(&repo);
    st.put(A, S1, &hex64(1), b"x").unwrap();
    // The remote already has metadata, so this push rewrites the local
    // metadata commit onto the remote tip (vci's own commit).
    st.push(Some("origin")).unwrap();
    assert_eq!(
        git(&w.remote, &["rev-list", "--count", "refs/meta/main"]),
        "2",
        "linear history: one new commit per push"
    );
    assert_eq!(st.list(None).unwrap().len(), 2);
}

#[test]
fn malformed_ids_are_rejected() {
    let (_t, root) = init_repo();
    let (repo, _) = store(&root);
    let st = AttestStore::new(&repo);
    let refs_before = all_refs(&root);
    let good = hex64(2);
    for s in [
        "",
        "0123456789ABCDEF",
        "0123456789abcde",
        "0123456789abcdef00",
        "../../heads/main",
        "0123456789abcdeg",
        "0123456/89abcdef",
        "01234567:9abcdef",
        "0123456789abcde\n",
    ] {
        assert!(
            matches!(
                st.put(A, s, &good, b"x"),
                Err(GitError::Invalid {
                    what: "signer_id",
                    ..
                })
            ),
            "signer {s:?}"
        );
    }
    let too_long = "a".repeat(129);
    for h in [
        "", "a", "AB", "../../x", "ab/cd", "ab:cd", "ab.dsse", "abc\0", " ab", "zz",
    ]
    .iter()
    .copied()
    .chain([too_long.as_str()])
    {
        assert!(
            matches!(
                st.put(A, S1, h, b"x"),
                Err(GitError::Invalid {
                    what: "storage_key",
                    ..
                })
            ),
            "storage_key {h:?}"
        );
    }
    assert!(matches!(
        st.put(A, S1, &good, b"\xff\xfe"),
        Err(GitError::Invalid { .. })
    ));
    for r in ["", "--upload-pack=touch /tmp/pwned", "-o", "a\nb"] {
        assert!(
            matches!(st.fetch(Some(r)), Err(GitError::Invalid { .. })),
            "{r:?}"
        );
        assert!(
            matches!(st.push(Some(r)), Err(GitError::Invalid { .. })),
            "{r:?}"
        );
    }
    assert_eq!(all_refs(&root), refs_before, "nothing was written");
    assert!(st.list(None).unwrap().is_empty());
}

#[test]
fn list_skips_foreign_keys_and_values() {
    let (_t, root) = init_repo();
    let (repo, _) = store(&root);
    let st = AttestStore::new(&repo);
    st.put(A, S1, &hex64(2), b"good").unwrap();
    let s = Session::open(root.as_std_path()).unwrap();
    let tk = vci_core::test_key(A);
    let h = s.target(&Target::path(A));
    // Wrong shapes, a list, an unrelated namespace.
    h.set(&format!("vci:attestation:{tk}:{S1}"), "short")
        .unwrap();
    h.set(
        &format!("vci:attestation:{tk}:NOTHEX0123456789:{}", hex64(1)),
        "x",
    )
    .unwrap();
    h.set(
        &format!("vci:attestation:{tk}:{S1}:{}:extra", hex64(1)),
        "deeper",
    )
    .unwrap();
    h.list_push(&format!("vci:attestation:{tk}:{S2}:{}", hex64(3)), "a list")
        .unwrap();
    h.set("owner", "someone").unwrap();
    // Another unit's attestation under this path is not a candidate for A.
    h.set(
        &format!(
            "vci:attestation:{}:{S1}:{}",
            vci_core::test_key(B),
            hex64(5)
        ),
        "B's",
    )
    .unwrap();

    let a = st.list(Some(A)).unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].bytes, b"good");
    // Listing everything sees the well-formed key under A's path too.
    assert_eq!(st.list(None).unwrap().len(), 2);
}

#[test]
fn two_clones_push_and_fetch_end_with_union() {
    let w = world(3);
    let (a, _) = store(&w.clones[0]);
    let (b, _) = store(&w.clones[1]);
    let (c, _) = store(&w.clones[2]);
    let (sa, sb, sc) = (
        AttestStore::new(&a),
        AttestStore::new(&b),
        AttestStore::new(&c),
    );
    let status_a = git(&w.clones[0], &["status", "--porcelain=v1"]);
    let head_a = git(&w.clones[0], &["rev-parse", "HEAD"]);

    // Same signer on two machines, plus a second signer.
    sa.put(A, S1, &hex64(0xa), b"from A").unwrap();
    sb.put(B, S1, &hex64(0xb), b"from B").unwrap();
    sb.put(A, S2, &hex64(0xc), b"other signer from B").unwrap();

    sa.push(Some("origin")).unwrap();
    sb.push(Some("origin")).unwrap(); // must merge A's values, not drop them
    sa.fetch(None).unwrap();
    sb.fetch(None).unwrap();
    sc.fetch(Some(w.remote.as_str())).unwrap(); // by path, not remote name

    let expected: BTreeSet<_> = [
        row(A, S1, &hex64(0xa), b"from A"),
        row(B, S1, &hex64(0xb), b"from B"),
        row(A, S2, &hex64(0xc), b"other signer from B"),
    ]
    .into_iter()
    .collect();
    for s in [&sa, &sb, &sc] {
        assert_eq!(rows(&s.list(None).unwrap()), expected);
    }
    // Every clone ends on the remote's metadata commit.
    let tip = git(&w.remote, &["rev-parse", "refs/meta/main"]);
    for c in &w.clones[..2] {
        assert_eq!(git(c, &["rev-parse", "refs/meta/remotes/main"]), tip);
    }
    // Linear history on the remote (git-meta's preferred shape).
    let merges = git(&w.remote, &["rev-list", "--merges", "refs/meta/main"]);
    assert_eq!(merges, "");
    // Sync never touched A's work tree, index or HEAD.
    assert_eq!(git(&w.clones[0], &["status", "--porcelain=v1"]), status_a);
    assert_eq!(git(&w.clones[0], &["rev-parse", "HEAD"]), head_a);
}

#[test]
fn push_retries_when_remote_moves_underneath() {
    let w = world(2);
    let (a, _) = store(&w.clones[0]);
    let (b, _) = store(&w.clones[1]);
    let (sa, sb) = (AttestStore::new(&a), AttestStore::new(&b));
    sa.put(A, S1, &hex64(1), b"A1").unwrap();
    sb.put(B, S1, &hex64(2), b"B1").unwrap();

    // B pushes in the window between A's fetch+merge and A's push, so A's
    // first push is a non-fast-forward and must be retried.
    let mut attempts = Vec::new();
    sa.push_with_hook(Some("origin"), |attempt| {
        attempts.push(attempt);
        if attempt == 1 {
            sb.push(Some("origin")).unwrap();
        }
    })
    .unwrap();
    assert_eq!(
        attempts,
        vec![1, 2],
        "first push rejected, second succeeded"
    );
    sb.fetch(None).unwrap();
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
                let st = AttestStore::new(&repo);
                for j in 0..PER_CLONE {
                    let n = (i as u8) * 16 + j;
                    st.put(
                        &format!("src/t{n}.test.ts"),
                        S1,
                        &hex64(n),
                        format!("clone {i} env {j}").as_bytes(),
                    )
                    .unwrap();
                    st.push(Some("origin")).unwrap();
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
        let st = AttestStore::new(&repo);
        st.fetch(None).unwrap();
        let got: BTreeSet<_> = st
            .list(None)
            .unwrap()
            .into_iter()
            .map(|e| e.bytes)
            .collect();
        assert_eq!(got, expected, "clone {clone}");
    }
}

#[test]
fn same_key_from_two_machines_converges() {
    // The same signer attesting the same unit and inputs on two machines
    // writes the same key with different bytes (different issue times).
    // Either envelope covers the unit; both clones must agree on one.
    let w = world(2);
    let (a, _) = store(&w.clones[0]);
    let (b, _) = store(&w.clones[1]);
    let (sa, sb) = (AttestStore::new(&a), AttestStore::new(&b));
    sa.put(A, S1, &hex64(1), b"version A").unwrap();
    sb.put(A, S1, &hex64(1), b"version B").unwrap();
    sa.put(B, S1, &hex64(2), b"only A").unwrap();
    sa.push(Some("origin")).unwrap();
    sb.push(Some("origin")).unwrap();
    sa.fetch(None).unwrap();
    sb.fetch(None).unwrap();
    let la = sa.list(None).unwrap();
    let lb = sb.list(None).unwrap();
    assert_eq!(la, lb, "both clones agree");
    assert_eq!(la.len(), 2);
    assert!(la.iter().any(|e| e.bytes == b"only A"));
    let one = la
        .iter()
        .find(|e| e.test_key == vci_core::test_key(A))
        .unwrap();
    assert!(one.bytes == b"version A" || one.bytes == b"version B");
}

#[test]
fn baseless_histories_merge_to_the_union() {
    // Two clones each serialize metadata before either has seen the other's
    // (no common ancestor): git-meta's two-way merge keeps both sides' keys.
    let w = world(2);
    let (a, _) = store(&w.clones[0]);
    let (b, _) = store(&w.clones[1]);
    let (sa, sb) = (AttestStore::new(&a), AttestStore::new(&b));
    sa.put(A, S1, &hex64(1), b"A").unwrap();
    sb.put(B, S2, &hex64(2), b"B").unwrap();
    // B serializes a local history of its own first.
    let _ = Session::open(w.clones[1].as_std_path())
        .unwrap()
        .serialize_full()
        .unwrap();
    sa.push(Some("origin")).unwrap();
    sb.push(Some("origin")).unwrap();
    sa.fetch(None).unwrap();
    let want: BTreeSet<_> = [b"A".to_vec(), b"B".to_vec()].into_iter().collect();
    for s in [&sa, &sb] {
        let got: BTreeSet<_> = s.list(None).unwrap().into_iter().map(|e| e.bytes).collect();
        assert_eq!(got, want);
    }
}

#[test]
fn tombstones_propagate_and_lose_to_concurrent_re_attestation() {
    let w = world(3);
    let (a, _) = store(&w.clones[0]);
    let (b, _) = store(&w.clones[1]);
    let (c, _) = store(&w.clones[2]);
    let (sa, sb, sc) = (
        AttestStore::new(&a),
        AttestStore::new(&b),
        AttestStore::new(&c),
    );
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    sa.put(B, S1, &hex64(2), b"b1").unwrap();
    sa.push(Some("origin")).unwrap();
    sb.fetch(Some("origin")).unwrap();
    sc.fetch(Some("origin")).unwrap();

    // B deletes both; meanwhile C re-attests B's unit with new bytes.
    for e in sb.list(None).unwrap() {
        assert!(sb.remove(&e).unwrap());
    }
    assert!(sb.list(None).unwrap().is_empty());
    sc.put(B, S1, &hex64(2), b"b2 renewed").unwrap();
    sb.push(None).unwrap();
    sc.push(None).unwrap();
    for s in [&sa, &sb, &sc] {
        s.fetch(None).unwrap();
        let got: Vec<Vec<u8>> = s.list(None).unwrap().into_iter().map(|e| e.bytes).collect();
        // The deletion of A's unit propagates; the modification wins over the
        // deletion of B's unit.
        assert_eq!(got, vec![b"b2 renewed".to_vec()]);
    }
}

#[test]
fn sync_with_empty_remote_and_empty_store() {
    let w = world(2);
    let (a, _) = store(&w.clones[0]);
    let sa = AttestStore::new(&a);
    assert!(!sa.fetch(Some("origin")).unwrap().found);
    sa.push(None).unwrap();
    assert!(sa.list(None).unwrap().is_empty());
    assert_eq!(git(&w.remote, &["for-each-ref", "refs/meta"]), "");

    sa.put(A, S2, &hex64(9), b"x").unwrap();
    sa.push(None).unwrap();
    let tip = git(&w.remote, &["rev-parse", "refs/meta/main"]);
    // Pushing again with nothing new is a no-op.
    sa.push(None).unwrap();
    assert_eq!(git(&w.remote, &["rev-parse", "refs/meta/main"]), tip);
    let (b, _) = store(&w.clones[1]);
    let sb = AttestStore::new(&b);
    assert!(sb.fetch(Some("origin")).unwrap().found);
    assert_eq!(sb.list(None).unwrap().len(), 1);
    // Fetching an unchanged remote changes no ref.
    let before = all_refs(&w.clones[1]);
    sb.fetch(None).unwrap();
    assert_eq!(all_refs(&w.clones[1]), before);
}

#[test]
fn fresh_clone_reads_what_was_pushed() {
    // CI: a new clone with no .git/git-meta.sqlite and no metadata remote.
    let w = world(1);
    let (a, _) = store(&w.clones[0]);
    let sa = AttestStore::new(&a);
    let e = big("ci", 300_000);
    sa.put(A, S1, &hex64(1), &e).unwrap();
    sa.put("rs#lib", S1, &hex64(2), b"project target").unwrap();
    sa.push(Some("origin")).unwrap();
    let fresh = w.remote.parent().unwrap().join("fresh");
    git(
        w.remote.parent().unwrap(),
        &["clone", "-q", w.remote.as_str(), fresh.as_str()],
    );
    assert!(!fresh.join(".git/git-meta.sqlite").exists());
    let (f, _) = store(&fresh);
    let sf = AttestStore::new(&f);
    assert!(sf.list(None).unwrap().is_empty());
    let out = sf.fetch(Some("origin")).unwrap();
    assert_eq!(out.remote, "meta");
    assert!(out.found);
    assert_eq!(rows(&sf.list(None).unwrap()), rows(&sa.list(None).unwrap()));
    assert_eq!(sf.list(Some(A)).unwrap()[0].bytes, e);
}

#[test]
fn remote_resolution() {
    let w = world(1);
    let c = &w.clones[0];
    let (repo, _) = store(c);
    let st = AttestStore::new(&repo);
    // No metadata remote: `.git-meta` wins over origin.
    let other = w.remote.parent().unwrap().join("other.git");
    git(
        w.remote.parent().unwrap(),
        &["init", "-q", "--bare", other.as_str()],
    );
    write(c, ".git-meta", &format!("url: {other}\n"));
    assert_eq!(st.ensure_remote(None).unwrap(), "meta");
    assert_eq!(git(c, &["config", "remote.meta.url"]), other.as_str());
    // A configured metadata remote is used as is.
    assert_eq!(st.ensure_remote(None).unwrap(), "meta");
    assert_eq!(st.ensure_remote(Some("meta")).unwrap(), "meta");
    // Naming a code remote with another URL adds a side metadata remote.
    let side = st.ensure_remote(Some("origin")).unwrap();
    assert_eq!(side, "vci-meta");
    assert_eq!(git(c, &["config", "remote.vci-meta.metaside"]), "true");
    assert_eq!(
        git(c, &["config", "remote.vci-meta.fetch"]),
        "+refs/meta/main:refs/meta/remotes/vci-meta/main"
    );
    assert_eq!(st.ensure_remote(Some("origin")).unwrap(), "vci-meta");
    // A side remote is read from, never published to (git-meta keeps its
    // values out of the local metadata commit).
    st.put(A, S1, &hex64(1), b"side").unwrap();
    assert!(matches!(
        st.push(Some("origin")),
        Err(GitError::NoMetaRemote(_))
    ));
    assert_eq!(git(&w.remote, &["for-each-ref", "refs/meta"]), "");
    // Publish to the primary (`.git-meta`'s URL), copy that metadata to
    // origin, and read it in another clone through a side remote.
    st.push(None).unwrap();
    git(
        &w.remote,
        &[
            "fetch",
            "-q",
            other.as_str(),
            "+refs/meta/main:refs/meta/main",
        ],
    );
    let reader = w.remote.parent().unwrap().join("reader");
    git(
        w.remote.parent().unwrap(),
        &["clone", "-q", w.remote.as_str(), reader.as_str()],
    );
    write(&reader, ".git-meta", &format!("url: {other}\n"));
    let (rr, _) = store(&reader);
    let sr = AttestStore::new(&rr);
    assert_eq!(sr.ensure_remote(None).unwrap(), "meta");
    assert!(sr.fetch(Some(w.remote.as_str())).unwrap().found);
    assert_eq!(
        git(&reader, &["config", "remote.vci-meta.metaside"]),
        "true"
    );
    assert_eq!(sr.list(Some(A)).unwrap()[0].bytes, b"side");
    let (t, root) = init_repo();
    let (r2, _) = store(&root);
    assert!(matches!(
        AttestStore::new(&r2).ensure_remote(None),
        Err(GitError::NoMetaRemote(_))
    ));
    drop(t);
}

#[test]
fn fetch_from_unreachable_remote_is_an_error() {
    let (_t, root) = init_repo();
    let (repo, _) = store(&root);
    let st = AttestStore::new(&repo);
    let missing = root.join("no-such-remote.git");
    assert!(st.fetch(Some(missing.as_str())).is_err());
    st.put(A, S1, &hex64(1), b"x").unwrap();
    assert!(st.push(Some(missing.as_str())).is_err());
    // The local value is still there.
    assert_eq!(st.list(None).unwrap().len(), 1);
}

#[test]
fn concurrent_puts_in_one_repo_lose_nothing() {
    let w = world(2);
    let root = &w.clones[0];
    std::thread::scope(|scope| {
        for i in 0..8u8 {
            scope.spawn(move || {
                let repo = Repo::discover(root).unwrap();
                let st = AttestStore::new(&repo);
                for j in 0..3u8 {
                    let n = i * 16 + j;
                    st.put(&format!("src/t{n}.test.ts"), S1, &hex64(n), &[b'a' + j])
                        .unwrap();
                }
            });
        }
        // A push running alongside the writers must not lose any of them.
        scope.spawn(move || {
            let repo = Repo::discover(root).unwrap();
            AttestStore::new(&repo).push(Some("origin")).unwrap();
        });
    });
    let repo = Repo::discover(root).unwrap();
    let st = AttestStore::new(&repo);
    assert_eq!(st.list(None).unwrap().len(), 24);
    st.push(None).unwrap();
    let (b, _) = store(&w.clones[1]);
    let sb = AttestStore::new(&b);
    sb.fetch(Some("origin")).unwrap();
    assert_eq!(
        sb.list(None).unwrap().len(),
        24,
        "every value was published"
    );
}

// ---- interoperability with the stock `git meta` CLI -----------------------

/// The `git-meta` binary: `$VCI_TEST_GIT_META`, else `git-meta` on PATH.
fn git_meta_bin() -> Option<String> {
    let bin = std::env::var("VCI_TEST_GIT_META")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "git-meta".to_owned());
    let ok = Command::new(&bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    ok.then_some(bin)
}

fn git_meta(bin: &str, dir: &Utf8Path, args: &[&str]) -> std::process::Output {
    let out = Command::new(bin)
        .current_dir(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git meta {args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

#[test]
fn interop_with_the_git_meta_cli() {
    let Some(bin) = git_meta_bin() else {
        eprintln!(
            "skipping: no git-meta CLI (cargo install git-meta-cli, or set VCI_TEST_GIT_META)"
        );
        return;
    };
    let w = world(2);
    let (a, b) = (&w.clones[0], &w.clones[1]);
    let (ra, _) = store(a);
    let sa = AttestStore::new(&ra);
    let tk = vci_core::test_key(A);
    let env_a = big("from-vci", 40_000);
    sa.put(A, S1, &hex64(1), &env_a).unwrap();
    sa.push(Some("origin")).unwrap();

    // B sets up git-meta with the stock CLI and reads vci's value.
    git_meta(
        &bin,
        b,
        &["remote", "add", w.remote.as_str(), "--name", "meta"],
    );
    git_meta(&bin, b, &["pull"]);
    let key = format!("vci:attestation:{tk}:{S1}:{}", hex64(1));
    let got = git_meta(&bin, b, &["get", &format!("path:{A}"), &key, "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&got.stdout).unwrap();
    assert_eq!(
        v[A][&key].as_str().unwrap().as_bytes(),
        env_a.as_slice(),
        "git meta get returns the exact envelope"
    );

    // B writes a value by hand and deletes vci's; `git meta push`.
    let env_b = String::from_utf8(big("by-hand", 3000)).unwrap();
    let key_b = format!(
        "vci:attestation:{}:{S2}:{}",
        vci_core::test_key(B),
        hex64(2)
    );
    git_meta(&bin, b, &["set", &format!("path:{B}"), &key_b, &env_b]);
    git_meta(&bin, b, &["rm", &format!("path:{A}"), &key]);
    git_meta(&bin, b, &["push"]);

    // A sees both through vci.
    sa.fetch(None).unwrap();
    let la = sa.list(None).unwrap();
    assert_eq!(la.len(), 1, "{la:?}");
    assert_eq!(la[0].bytes, env_b.as_bytes());
    assert_eq!(la[0].target, format!("path:{B}"));

    // And B's `git meta pull` sees what vci pushes next.
    sa.put(A, S1, &hex64(3), b"{\"third\":true}").unwrap();
    sa.push(None).unwrap();
    git_meta(&bin, b, &["pull"]);
    let (rb, _) = store(b);
    let lb = AttestStore::new(&rb).list(None).unwrap();
    assert_eq!(rows(&lb), rows(&sa.list(None).unwrap()));
}
