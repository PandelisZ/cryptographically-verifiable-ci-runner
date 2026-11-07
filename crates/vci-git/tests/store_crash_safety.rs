//! The local metadata commit never holds an unchecked serialization, and a
//! clone whose local metadata lost shared values without deleting them gets
//! them back by itself (2.10).
//!
//! On 6 November 2026 a vex laptop's `refs/meta/local/main` became a
//! git-meta serialization that dropped 4,484 manifests and objects the
//! clone had never fetched, with no deletion record: git-meta moved the ref
//! and failed on the store's marker write before vci's check could graft
//! them back; the merges after it carried the loss on, and every push
//! refused ("pushing would delete 4402 value(s) ... that this store never
//! deleted") until the store was reset by hand. Here: a serialization killed
//! right after git-meta's leaves the ref alone and the next command
//! publishes what it was serializing; a store locked by another writer
//! during a fetch never leaves the ref dropping values; a push from that
//! state succeeds, deletes nothing it did not delete and says it restored
//! the values; and a fetch puts them back so that plans read them.

mod common;

use std::collections::BTreeMap;
use std::process::Command;

use base64::Engine as _;
use camino::{Utf8Path, Utf8PathBuf};
use common::*;
use git_meta_lib::Target;
use vci_core::ObjectKind;
use vci_git::meta::target_for;
use vci_git::{AttestStore, PushStatus, Repo};

const S1: &str = "0123456789abcdef";
const S2: &str = "fedcba9876543210";
const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";
const D: &str = "src/d.test.ts";

/// A world whose remote serves partial clones (as GitHub does).
fn lazy_world(n: usize) -> World {
    let w = world(n);
    git(&w.remote, &["config", "uploadpack.allowFilter", "true"]);
    w
}

fn repo(root: &Utf8Path) -> Repo {
    Repo::discover(root).unwrap()
}

/// An attestation-sized envelope whose payload references `manifest_root`.
fn env(tag: &str, manifest_root: &str) -> Vec<u8> {
    let payload = serde_json::json!({
        "predicate": {"manifestRef": manifest_root},
        "pad": tag.repeat(2000 / tag.len().max(1)),
    });
    serde_json::json!({
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64::engine::general_purpose::STANDARD.encode(payload.to_string()),
        "signatures": [],
    })
    .to_string()
    .into_bytes()
}

fn manifest(tag: &str) -> Vec<u8> {
    format!("manifest {tag} {}", "m".repeat(3000)).into_bytes()
}

/// A format-3 object of `kind` holding `tag` (id: BLAKE3 of the bytes).
fn object(kind: ObjectKind, tag: &str) -> (ObjectKind, String, String) {
    let bytes = object_bytes(tag);
    (
        kind,
        vci_core::blake3_hex(&bytes),
        base64::engine::general_purpose::STANDARD.encode(&bytes),
    )
}

fn object_bytes(tag: &str) -> Vec<u8> {
    format!("object {tag} {}", "o".repeat(500)).into_bytes()
}

/// A fresh clone of the world's remote (code only: no metadata, no store).
fn fresh_clone(w: &World, name: &str) -> Utf8PathBuf {
    let base = w.remote.parent().unwrap();
    let dir = base.join(name);
    git(
        base,
        &["clone", "-q", "--no-local", w.remote.as_str(), dir.as_str()],
    );
    dir
}

/// Every blob of `rev`'s tree in `dir`, by path.
fn tree_blobs(dir: &Utf8Path, rev: &str) -> BTreeMap<String, String> {
    git(dir, &["ls-tree", "-r", "--full-tree", rev])
        .lines()
        .filter_map(|l| {
            let (meta, path) = l.split_once('\t')?;
            let mut f = meta.split(' ');
            let (_, kind, oid) = (f.next()?, f.next()?, f.next()?);
            (kind == "blob").then(|| (path.to_owned(), oid.to_owned()))
        })
        .collect()
}

fn manifest_path(root: &str) -> String {
    git_meta_lib::tree_paths::tree_path(&Target::project(), &vci_git::manifest_key(root)).unwrap()
}

fn manifest_record_path(root: &str) -> String {
    git_meta_lib::tree_paths::tombstone_path(&Target::project(), &vci_git::manifest_key(root))
        .unwrap()
}

fn object_path(o: &(ObjectKind, String, String)) -> String {
    let key = vci_store::key::object_key(o.0, &o.1);
    git_meta_lib::tree_paths::tree_path(&Target::project(), &key).unwrap()
}

fn attestation_path(test_id: &str, signer: &str, sk: &str) -> String {
    let key = vci_git::meta::attestation_key(&vci_core::test_key(test_id), signer, sk);
    git_meta_lib::tree_paths::tree_path(&target_for(test_id), &key).unwrap()
}

fn local_ref(dir: &Utf8Path) -> String {
    git(dir, &["rev-parse", "refs/meta/local/main"])
}

/// Make `refs/meta/local/main` in `dir` a commit on top of it whose tree
/// lacks `paths`, with no deletion record for them, and the store left as
/// it is: what git-meta's unchecked serialization left on vex.
fn lose_without_records(dir: &Utf8Path, paths: &[String]) {
    let local = local_ref(dir);
    let tmp = tempfile::tempdir().unwrap();
    let index = tmp.path().join("index");
    let run = |args: &[&str], stdin: Option<&[u8]>| -> String {
        let mut cmd = Command::new("git");
        cmd.arg("-C")
            .arg(dir.as_std_path())
            .args(args)
            .env("GIT_INDEX_FILE", &index)
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        {
            use std::io::Write as _;
            let mut i = child.stdin.take().unwrap();
            if let Some(b) = stdin {
                i.write_all(b).unwrap();
            }
        }
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    run(&["read-tree", &format!("{local}^{{tree}}")], None);
    let mut info = Vec::new();
    for p in paths {
        info.extend_from_slice(format!("0 {}\t{p}", "0".repeat(40)).as_bytes());
        info.push(0);
    }
    run(&["update-index", "-z", "--index-info"], Some(&info));
    let tree = run(&["write-tree", "--missing-ok"], None);
    let commit = run(
        &[
            "commit-tree",
            &tree,
            "-p",
            &local,
            "-m",
            "git-meta: serialize (1 changes)",
        ],
        None,
    );
    git(
        dir,
        &["update-ref", "refs/meta/local/main", &commit, &local],
    );
    let left = tree_blobs(dir, "refs/meta/local/main");
    for p in paths {
        assert!(!left.contains_key(p), "{p} is still there");
    }
}

/// Run `op` (`push` or `fetch`) on the store of `dir` in a child process
/// (this test binary, running only [`child_op`]) with `env` added.
fn in_child(dir: &Utf8Path, op: &str, env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "child_op",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .env("VCI_TEST_CHILD_DIR", dir.as_str())
    .env("VCI_TEST_CHILD_OP", op);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// What [`in_child`] runs; does nothing in a normal test run.
#[test]
#[ignore = "run in a child process by the tests that kill it"]
fn child_op() {
    let Ok(dir) = std::env::var("VCI_TEST_CHILD_DIR") else {
        return;
    };
    let r = repo(Utf8Path::new(&dir));
    let st = AttestStore::new(&r);
    match std::env::var("VCI_TEST_CHILD_OP").as_deref() {
        Ok("push") => {
            st.push(Some("origin")).unwrap();
        }
        Ok("fetch") => {
            st.fetch(Some("origin")).unwrap();
        }
        other => panic!("unknown child op {other:?}"),
    }
}

/// The scratch git directories a serialization left in `dir`'s git
/// directory.
fn scratch_dirs(dir: &Utf8Path) -> Vec<Utf8PathBuf> {
    let mut out: Vec<Utf8PathBuf> = std::fs::read_dir(dir.join(".git"))
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("vci-serialize-")
        })
        .map(|e| Utf8PathBuf::from_path_buf(e.path()).unwrap())
        .collect();
    out.sort();
    out
}

/// The publisher's store: two manifests, two objects, attestations on A and
/// B; pushed. Returns its repository and the manifest roots and objects.
struct Published {
    a: Repo,
    roots: [String; 3],
    objects: [(ObjectKind, String, String); 2],
}

fn publish(w: &World) -> Published {
    let a = repo(&w.clones[0]);
    let st = AttestStore::new(&a);
    let roots = [hex64(0xe1), hex64(0xe2), hex64(0xe4)];
    for (r, tag) in roots.iter().zip(["one", "two", "four"]) {
        st.put_manifest(r, &manifest(tag)).unwrap();
    }
    let objects = [
        object(ObjectKind::Hdr, "hdr"),
        object(ObjectKind::State, "state"),
    ];
    st.put_objects(&objects).unwrap();
    st.put(A, S1, &hex64(1), &env("a1", &roots[0])).unwrap();
    st.put(B, S1, &hex64(2), &env("b1", &roots[1])).unwrap();
    assert_eq!(st.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    Published { a, roots, objects }
}

/// A serialization killed right after git-meta's own returned (git-meta's
/// commit dropped the manifests this clone never fetched) leaves
/// `refs/meta/local/main` where it was and publishes nothing; the next push
/// publishes what was being serialized and deletes nothing.
#[test]
fn a_serialization_killed_after_git_meta_leaves_the_local_ref_where_it_was() {
    let w = lazy_world(1);
    let p = publish(&w);
    let published = tree_blobs(&w.remote, "refs/meta/main");
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    assert!(sf.fetch(Some("origin")).unwrap().found);
    assert!(sf.reader().unwrap().promised().unwrap() > 0);
    // A new manifest on the project target, whose other values this clone
    // never fetched: git-meta rebuilds the target from the rows it has
    // values for.
    let r3 = hex64(0xe3);
    sf.put_manifest(&r3, &manifest("three")).unwrap();
    sf.put(C, S2, &hex64(3), &env("c2", &r3)).unwrap();
    let before = local_ref(&f);

    let out = in_child(
        &f,
        "push",
        &[
            ("VCI_SERIALIZE", "git-meta"),
            ("VCI_FAILPOINT", "serialize-after-git-meta"),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "the child was not killed: {stderr} {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        stderr.contains("failpoint serialize-after-git-meta"),
        "{stderr}"
    );
    // The local ref is where it was (it held git-meta's commit, which drops
    // the values this clone never fetched, before 2.10), every value is
    // still in it, and nothing was published.
    assert_eq!(local_ref(&f), before);
    let ours = tree_blobs(&f, "refs/meta/local/main");
    for r in &p.roots {
        assert!(ours.contains_key(&manifest_path(r)), "{r} was dropped");
    }
    assert_eq!(tree_blobs(&w.remote, "refs/meta/main"), published);

    // git-meta's commit (in the scratch directory the process left) did
    // drop the values not fetched: the instant that left vex's ref broken.
    let scratch = scratch_dirs(&f);
    assert_eq!(scratch.len(), 1, "{scratch:?}");
    let theirs = std::fs::read_to_string(scratch[0].join("refs/meta/local/main")).unwrap();
    let theirs = tree_blobs(&f, theirs.trim());
    assert!(!theirs.contains_key(&manifest_path(&p.roots[0])));
    assert!(theirs.contains_key(&manifest_path(&r3)));
    // SQLite resolved the link: its log and locks are the store's own.
    for f in ["git-meta.sqlite-wal", "git-meta.sqlite-shm"] {
        assert!(!scratch[0].join(f).exists(), "{f} in the scratch directory");
    }

    // The next push proceeds: every value published before is still
    // there, and the manifest and attestation stored before the kill are
    // published (the marker git-meta had moved was put back).
    let out = sf.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
    let after = tree_blobs(&w.remote, "refs/meta/main");
    for (path, oid) in &published {
        assert_eq!(after.get(path), Some(oid), "{path} changed or was dropped");
    }
    assert!(after.contains_key(&manifest_path(&r3)));
    assert!(after.contains_key(&attestation_path(C, S2, &hex64(3))));
    assert!(scratch_dirs(&f).is_empty(), "the scratch directory is left");
    // The publisher reads all of it.
    let sa = AttestStore::new(&p.a);
    sa.fetch(Some("origin")).unwrap();
    sa.hydrate_manifests([r3.as_str()]).unwrap();
    assert_eq!(sa.manifest(&r3).unwrap().unwrap().bytes, manifest("three"));
    assert_eq!(sa.list(Some(C)).unwrap().len(), 1);
}

/// git-meta's serialization, run in its scratch directory, still lands:
/// the local ref moves to the checked commit (the values not fetched
/// grafted back) and the scratch directory is gone.
#[test]
fn a_git_meta_serialization_moves_the_local_ref_once_checked() {
    let w = lazy_world(1);
    let p = publish(&w);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();
    let r3 = hex64(0xe3);
    sf.put_manifest(&r3, &manifest("three")).unwrap();
    let out = in_child(&f, "fetch", &[("VCI_SERIALIZE", "git-meta")]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tree = tree_blobs(&f, "refs/meta/local/main");
    for r in &p.roots {
        assert!(tree.contains_key(&manifest_path(r)), "{r} was dropped");
    }
    for o in &p.objects {
        assert!(tree.contains_key(&object_path(o)), "{} was dropped", o.1);
    }
    assert!(tree.contains_key(&manifest_path(&r3)));
    // git-meta's commit (the values not fetched grafted back into it).
    let subject = git(&f, &["log", "-1", "--format=%s", "refs/meta/local/main"]);
    assert!(subject.starts_with("git-meta: serialize ("), "{subject}");
    assert!(scratch_dirs(&f).is_empty());
}

/// The vex incident itself, step by step: the store's serialization marker
/// cannot be written (on vex `database is locked`: another writer held the
/// shared store for minutes; here a trigger that fails the same way), after
/// vci's serialization moved the ref. vci 2.9.0 then let git-meta serialize
/// the same changes, which moved the ref to a commit without the values
/// this clone never fetched and failed on the marker before vci's check;
/// the fetch's retries took that ref as it was. The local ref never drops
/// them now, and once the store can be written again a push publishes
/// everything.
#[test]
fn a_store_that_cannot_mark_a_serialization_never_drops_values_not_fetched() {
    let w = lazy_world(1);
    let p = publish(&w);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();
    let r3 = hex64(0xe3);
    sf.put_manifest(&r3, &manifest("three")).unwrap();
    let db = rusqlite::Connection::open(f.join(".git/git-meta.sqlite")).unwrap();
    db.execute_batch(
        "CREATE TRIGGER vci_test_locked BEFORE UPDATE ON sync_state
         BEGIN SELECT RAISE(ABORT, 'database is locked'); END;",
    )
    .unwrap();
    // The child's fetch, whatever it ends with while the marker cannot be
    // written.
    let _ = in_child(&f, "fetch", &[]);
    let check = |when: &str| {
        let tree = tree_blobs(&f, "refs/meta/local/main");
        for r in &p.roots {
            assert!(tree.contains_key(&manifest_path(r)), "{when}: {r} dropped");
        }
        for o in &p.objects {
            assert!(
                tree.contains_key(&object_path(o)),
                "{when}: {} dropped",
                o.1
            );
        }
    };
    check("after the fetch that could not mark the store");
    db.execute_batch("DROP TRIGGER vci_test_locked").unwrap();
    drop(db);
    sf.fetch(Some("origin")).unwrap();
    check("after a fetch that could");
    assert_eq!(sf.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    let remote = tree_blobs(&w.remote, "refs/meta/main");
    for r in p.roots.iter().chain([&r3]) {
        assert!(remote.contains_key(&manifest_path(r)), "{r} not published");
    }
}

/// The state vex's laptop was left in: the local metadata commit lost
/// shared manifests and objects without deletion records, and the remote
/// moved on. The push succeeds, deletes only what this store deleted, and
/// says what it restored.
#[test]
fn a_push_restores_shared_values_the_local_commit_lost_without_deleting_them() {
    let w = lazy_world(1);
    let p = publish(&w);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();
    // A deletion of this store's own, which the push publishes.
    sf.remove_manifests([p.roots[2].as_str()]).unwrap();
    // A new attestation, to publish too.
    sf.put(D, S2, &hex64(9), &env("d2", &p.roots[0])).unwrap();
    sf.fetch(Some("origin")).unwrap();
    let lost = [
        manifest_path(&p.roots[0]),
        manifest_path(&p.roots[1]),
        object_path(&p.objects[0]),
        object_path(&p.objects[1]),
    ];
    lose_without_records(&f, &lost);
    // The remote moves on.
    let sa = AttestStore::new(&p.a);
    sa.put(B, S2, &hex64(5), &env("b2", &p.roots[1])).unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    let published = tree_blobs(&w.remote, "refs/meta/main");

    let out = sf.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
    assert!(
        out.notes.iter().any(|n| n.starts_with(
            "restored 4 value(s) of meta's refs/meta/main that this store had lost without deleting them (first: project vci:"
        )),
        "{out:?}"
    );
    // Nothing the store did not delete is gone, at the same blobs; its own
    // deletion is published with its record.
    let after = tree_blobs(&w.remote, "refs/meta/main");
    let deleted = manifest_path(&p.roots[2]);
    for (path, oid) in &published {
        if *path == deleted {
            continue;
        }
        assert_eq!(after.get(path), Some(oid), "{path} changed or was dropped");
    }
    assert!(!after.contains_key(&deleted));
    assert!(after.contains_key(&manifest_record_path(&p.roots[2])));
    assert!(after.contains_key(&attestation_path(D, S2, &hex64(9))));
    // The local metadata holds them again; nothing is left to restore.
    let local = tree_blobs(&f, "refs/meta/local/main");
    for path in &lost {
        assert_eq!(local.get(path), published.get(path), "{path}");
    }
    let out = sf.fetch(Some("origin")).unwrap();
    assert!(
        !out.notes.iter().any(|n| n.starts_with("restored ")),
        "{out:?}"
    );
    assert_eq!(
        sf.push(Some("origin")).unwrap().status,
        PushStatus::UpToDate
    );
}

/// A fetch puts back what the local metadata commit lost of the fetched tip
/// without a deletion record, so that this clone's plans read it again;
/// before, the store's rows for them pointed at a path the local commit no
/// longer had, and read as not fetched.
#[test]
fn a_fetch_restores_lost_values_and_plans_read_them_again() {
    let w = lazy_world(1);
    let p = publish(&w);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();
    let lost = [manifest_path(&p.roots[0]), object_path(&p.objects[0])];
    lose_without_records(&f, &lost);

    let out = sf.fetch(Some("origin")).unwrap();
    assert!(
        out.notes.iter().any(|n| n.starts_with(
            "restored 2 value(s) of meta's refs/meta/main that this store had lost without deleting them (first: project vci:"
        )),
        "{out:?}"
    );
    let remote = tree_blobs(&w.remote, "refs/meta/main");
    let local = tree_blobs(&f, "refs/meta/local/main");
    for path in &lost {
        assert_eq!(local.get(path), remote.get(path), "{path}");
    }
    // A plan reads them: the manifest an attestation of A references.
    let h = sf.hydrate_units([A]).unwrap();
    assert_eq!((h.unresolved, h.error.as_deref()), (0, None), "{h:?}");
    assert_eq!(
        sf.manifest(&p.roots[0]).unwrap().unwrap().bytes,
        manifest("one")
    );
    let (kind, id, text) = &p.objects[0];
    let h = sf.hydrate_objects([id.as_str()]).unwrap();
    assert_eq!((h.unresolved, h.error.as_deref()), (0, None), "{h:?}");
    assert_eq!(
        sf.reader().unwrap().object(*kind, id).unwrap(),
        Some(Ok(text.clone().into_bytes()))
    );
    // Nothing more to restore; a push has nothing to delete.
    let out = sf.fetch(Some("origin")).unwrap();
    assert!(
        !out.notes.iter().any(|n| n.starts_with("restored ")),
        "{out:?}"
    );
    sf.push(Some("origin")).unwrap();
    assert_eq!(tree_blobs(&w.remote, "refs/meta/main"), remote);
}
