//! A long metadata history published again as one commit (`vci prune`
//! does it once the history passes `[store] history_max_commits`, through
//! `vci push --rewrite-history`), and the clones that still hold the old
//! history: they fetch, merge and push on top of the new one without
//! losing a value, without a refusal, and without publishing again a value
//! deleted before the rewrite. (Its own binary: one test sets
//! the process's deletion-record window.)

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use base64::Engine as _;
use camino::Utf8Path;
use common::*;
use git_meta_lib::Target;
use vci_core::ObjectKind;
use vci_git::{AttestStore, PushStatus, Repo};

const S1: &str = "0123456789abcdef";
const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";
const D: &str = "src/d.test.ts";
const E: &str = "src/e.test.ts";

fn repo(root: &Utf8Path) -> Repo {
    Repo::discover(root).unwrap()
}

/// The storage keys a store lists, of every unit.
fn keys(s: &AttestStore<'_>) -> BTreeSet<String> {
    s.list(None)
        .unwrap()
        .into_iter()
        .map(|e| e.storage_key)
        .collect()
}

fn set(ks: &[u8]) -> BTreeSet<String> {
    ks.iter().map(|k| hex64(*k)).collect()
}

fn commits(dir: &Utf8Path, rev: &str) -> usize {
    git(dir, &["rev-list", "--count", rev]).parse().unwrap()
}

/// The storage keys of the attestations the remote's tip holds (from its
/// tree's paths: `.../vci/attestation/<test key>/<signer>/<storage key>/__value`).
fn remote_keys(w: &World) -> BTreeSet<String> {
    git(
        &w.remote,
        &[
            "ls-tree",
            "-r",
            "--name-only",
            "--full-tree",
            "refs/meta/main",
        ],
    )
    .lines()
    .filter(|p| p.ends_with("/__value") && !p.contains("__tombstones"))
    .filter_map(|p| {
        let parts: Vec<&str> = p.split('/').collect();
        let i = parts.iter().position(|s| *s == "attestation")?;
        parts.get(i + 3).map(|s| (*s).to_owned())
    })
    .collect()
}

/// A history of `n` publications by `s` (one attestation each, of unit
/// `D`), so that the rewrite has something to drop.
fn grow_history(s: &AttestStore<'_>, n: u8, from: u8) {
    for i in 0..n {
        s.put(D, S1, &hex64(from + i), b"d").unwrap();
        assert_eq!(s.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    }
}

/// A clone holding the history before a rewrite, and the attestation
/// deleted before it, merges the rewritten history: the deletion record
/// the new tip carries wins over the value it still holds (an attestation
/// key is never written twice), its own new attestation is published on
/// top of the one-commit history without bringing the old history back,
/// and a clone that pushes while the rewrite is in flight keeps its value:
/// the rewrite's lease fails, and its next round merges the value and
/// publishes one commit again.
#[test]
fn stale_and_concurrent_clones_push_on_top_of_a_rewritten_history() {
    let w = world(3);
    let (a, s, c) = (&w.clones[0], &w.clones[1], &w.clones[2]);
    let (ra, rs, rc) = (repo(a), repo(s), repo(c));
    let (sa, ss, sc) = (
        AttestStore::new(&ra),
        AttestStore::new(&rs),
        AttestStore::new(&rc),
    );
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    sa.put(B, S1, &hex64(2), b"b1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    grow_history(&sa, 4, 10);
    // The stale clone and the concurrent one hold every value so far.
    ss.fetch(Some("origin")).unwrap();
    ss.hydrate_attestations().unwrap();
    sc.fetch(Some("origin")).unwrap();
    assert!(keys(&ss).contains(&hex64(1)));

    // The pruner deletes a1 (a deletion record) and publishes one commit,
    // while the concurrent clone pushes c1 in the window before its push.
    let gone = sa.list(Some(A)).unwrap().remove(0);
    assert!(sa.remove(&gone).unwrap());
    sc.put(C, S1, &hex64(3), b"c1").unwrap();
    let mut raced = false;
    let out = sa
        .push_rewriting_history_with_hook(Some("origin"), |attempt| {
            if attempt == 1 {
                assert_eq!(sc.push(Some("origin")).unwrap().status, PushStatus::Pushed);
                raced = true;
            }
        })
        .unwrap();
    assert!(raced);
    assert_eq!(out.status, PushStatus::Pushed);
    assert_eq!(commits(&w.remote, "refs/meta/main"), 1, "one commit");
    let after_rewrite = set(&[2, 3, 10, 11, 12, 13]);
    assert_eq!(remote_keys(&w), after_rewrite, "c1 kept, a1 deleted");

    // The stale clone attests e and pushes: on top of the new history, a1
    // not published again, nothing refused.
    ss.put(E, S1, &hex64(5), b"e1").unwrap();
    let out = ss.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
    assert_eq!(
        commits(&w.remote, "refs/meta/main"),
        2,
        "the stale clone's old history is not published again"
    );
    let mut want = after_rewrite.clone();
    want.insert(hex64(5));
    assert_eq!(remote_keys(&w), want);
    assert!(!keys(&ss).contains(&hex64(1)), "deleted here too");

    // Every clone converges and has nothing left to push.
    for st in [&sa, &ss, &sc] {
        st.fetch(Some("origin")).unwrap();
        assert_eq!(keys(st), want);
        let status = st.push(Some("origin")).unwrap().status;
        assert!(
            matches!(status, PushStatus::UpToDate | PushStatus::Pushed),
            "{status:?}"
        );
    }
    assert_eq!(remote_keys(&w), want);
    // And the next rewrite is one commit again.
    sa.push_rewriting_history(Some("origin")).unwrap();
    assert_eq!(commits(&w.remote, "refs/meta/main"), 1);
    assert_eq!(remote_keys(&w), want);
}

/// A clone that has not fetched since before the deletion record of a
/// value was dropped (past `[store] deletion_records_hours`), then
/// rewritten away, does not publish that value again (2.10; it did once
/// before): it merges the new history three-way on the tip it last
/// fetched, which held the value, so the new tip's lack of it is a
/// deletion. Its push is not refused, its own attestation is published,
/// and so are its later ones.
#[test]
fn a_value_deleted_before_the_window_stays_deleted_after_a_rewrite() {
    let w = world(2);
    let (a, s) = (&w.clones[0], &w.clones[1]);
    let (ra, rs) = (repo(a), repo(s));
    let (sa, ss) = (AttestStore::new(&ra), AttestStore::new(&rs));
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    sa.put(B, S1, &hex64(2), b"b1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    ss.fetch(Some("origin")).unwrap();
    ss.hydrate_attestations().unwrap();

    let gone = sa.list(Some(A)).unwrap().remove(0);
    assert!(sa.remove(&gone).unwrap());
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    // Past the window: `vci prune` drops the record, then rewrites.
    std::thread::sleep(Duration::from_millis(20));
    vci_git::meta::set_deletion_records_keep(Duration::ZERO);
    assert_eq!(sa.drop_deletion_records().unwrap().dropped, 1);
    vci_git::meta::set_deletion_records_keep(Duration::from_secs(6 * 3600));
    sa.push_rewriting_history(Some("origin")).unwrap();
    assert_eq!(remote_keys(&w), set(&[2]));
    assert!(
        !git(
            &w.remote,
            &[
                "ls-tree",
                "-r",
                "--name-only",
                "--full-tree",
                "refs/meta/main"
            ]
        )
        .contains("__tombstones"),
        "no deletion record left"
    );

    // The stale clone publishes its own attestation, not a1.
    ss.put(C, S1, &hex64(3), b"c1").unwrap();
    let out = ss.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("history was rewritten since this clone last fetched it")),
        "{out:?}"
    );
    assert!(
        out.warnings.is_empty(),
        "no warning about values dropped without a record: {out:?}"
    );
    assert_eq!(remote_keys(&w), set(&[2, 3]), "a1 stays deleted");
    assert_eq!(keys(&ss), set(&[2, 3]), "and is deleted here too");

    // Its next pushes keep it deleted; every clone converges.
    ss.put(D, S1, &hex64(4), b"d1").unwrap();
    assert_eq!(ss.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    assert_eq!(remote_keys(&w), set(&[2, 3, 4]));
    assert_eq!(keys(&ss), set(&[2, 3, 4]));
    sa.fetch(Some("origin")).unwrap();
    assert_eq!(keys(&sa), set(&[2, 3, 4]));
    assert_eq!(
        sa.push(Some("origin")).unwrap().status,
        PushStatus::UpToDate
    );
}

/// `vci prune`'s git-meta helpers: the deletion records are counted with
/// the window, dropped (all of them past it) from the store and the local
/// tree, and the history fetched from the remote is counted.
#[test]
fn deletion_records_are_counted_and_dropped_and_the_history_counted() {
    let w = world(1);
    let a = &w.clones[0];
    let ra = repo(a);
    let sa = AttestStore::new(&ra);
    assert_eq!(sa.history_commits().unwrap(), None, "nothing fetched yet");
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    sa.put(B, S1, &hex64(2), b"b1").unwrap();
    sa.push(Some("origin")).unwrap();
    grow_history(&sa, 3, 10);
    assert_eq!(sa.history_commits().unwrap(), Some(4));
    let gone = sa.list(Some(A)).unwrap().remove(0);
    assert!(sa.remove(&gone).unwrap());
    sa.push(Some("origin")).unwrap();
    // (The window is the process's: another test here sets it.)
    let counts = sa.deletion_record_counts().unwrap();
    assert_eq!(counts.total, 1, "{counts:?}");
    assert!(counts.old <= 1, "{counts:?}");
    // The store's file: nothing worth freeing in a store this small.
    assert_eq!(sa.compact_store().unwrap().vacuumed, None);
}

// ---- rewrites racing other clones (2.10) ------------------------------------

/// The paths and blob ids of `rev`'s tree in `dir`.
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

/// An object of `kind` (bytes made from `tag`): (kind, id, base64).
fn object(kind: ObjectKind, tag: &str) -> (ObjectKind, String, String) {
    let bytes = format!("object {tag} {}", "o".repeat(500)).into_bytes();
    (
        kind,
        vci_core::blake3_hex(&bytes),
        base64::engine::general_purpose::STANDARD.encode(&bytes),
    )
}

fn object_key(o: &(ObjectKind, String, String)) -> String {
    vci_store::key::object_key(o.0, &o.1)
}

fn object_path(o: &(ObjectKind, String, String)) -> String {
    git_meta_lib::tree_paths::tree_path(&Target::project(), &object_key(o)).unwrap()
}

/// The parentless commits `rev`'s history holds in `dir`.
fn roots(dir: &Utf8Path, rev: &str) -> Vec<String> {
    git(dir, &["rev-list", "--max-parents=0", rev])
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Another clone deletes a manifest and an attestation and adds one while
/// the rewrite is in flight (in the window before its `git push`): the
/// rewrite's lease fails, and its next round merges that push on the tip
/// both shared, so the deletions and the addition all survive, as do the
/// rewriter's own deletion and addition. 2.10 moved the local metadata
/// commit to the parentless commit before the push landed, so that round
/// merged without a common ancestor and the local side won: the manifest
/// came back (the attestation only through the rule that the tip's record
/// of one wins). The local metadata commit moves to the rewrite once it is
/// published.
#[test]
fn what_a_clone_pushes_during_a_rewrite_is_kept() {
    let w = world(2);
    let (ra, rc) = (repo(&w.clones[0]), repo(&w.clones[1]));
    let (sa, sc) = (AttestStore::new(&ra), AttestStore::new(&rc));
    let m = hex64(0xe1);
    sa.put_manifest(&m, format!("manifest {}", "m".repeat(300)).as_bytes())
        .unwrap();
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    sa.put(B, S1, &hex64(2), b"b1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    grow_history(&sa, 3, 10);
    sc.fetch(Some("origin")).unwrap();
    sc.hydrate_attestations().unwrap();
    // The rewriter deletes b1 and attests e.
    let b1 = sa.list(Some(B)).unwrap().remove(0);
    assert!(sa.remove(&b1).unwrap());
    sa.put(E, S1, &hex64(5), b"e1").unwrap();

    let mut raced = false;
    let out = sa
        .push_rewriting_history_with_hook(Some("origin"), |attempt| {
            if attempt == 1 {
                assert_eq!(sc.remove_manifests([m.as_str()]).unwrap(), 1);
                let a1 = sc.list(Some(A)).unwrap().remove(0);
                assert!(sc.remove(&a1).unwrap());
                sc.put(C, S1, &hex64(3), b"c1").unwrap();
                assert_eq!(sc.push(Some("origin")).unwrap().status, PushStatus::Pushed);
                raced = true;
            }
        })
        .unwrap();
    assert!(raced);
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
    assert!(out.rewritten, "{out:?}");
    assert_eq!(commits(&w.remote, "refs/meta/main"), 1, "one commit");
    let after = tree_blobs(&w.remote, "refs/meta/main");
    assert!(
        !after.contains_key(&manifest_path(&m)),
        "the manifest the other clone deleted during the rewrite was published again"
    );
    let want = set(&[3, 5, 10, 11, 12]);
    assert_eq!(remote_keys(&w), want, "a1 and b1 deleted, c1 and e1 kept");
    let tip = git(&w.remote, &["rev-parse", "refs/meta/main"]);
    assert_eq!(
        git(&w.clones[0], &["rev-parse", "refs/meta/local/main"]),
        tip,
        "the local metadata commit is the published rewrite"
    );
    // Both clones converge, with nothing left to push.
    for st in [&sa, &sc] {
        st.fetch(Some("origin")).unwrap();
        assert_eq!(keys(st), want);
        assert!(st.manifest(&m).unwrap().is_none());
        assert_eq!(
            st.push(Some("origin")).unwrap().status,
            PushStatus::UpToDate
        );
    }
    assert_eq!(remote_keys(&w), want);
}

/// `vci prune`'s rewrite past `[store] history_max_commits` decides on the
/// history each attempt fetched: two clones that both find it long (vex's
/// two hourly attest jobs) rewrite it once. The second one's lease fails,
/// and its next round finds the first one's rewrite, one commit, and
/// pushes its own deletion and attestation on top of it; a clone that last
/// fetched before the rewrite does the same. 2.10 counted the history as
/// last fetched, and such a clone rewrote it again, dropping the first
/// rewrite and what was pushed on it.
#[test]
fn a_long_history_is_rewritten_once_by_clones_that_both_find_it_long() {
    let w = world(3);
    let (ra, rb, rc) = (repo(&w.clones[0]), repo(&w.clones[1]), repo(&w.clones[2]));
    let (sa, sb, sc) = (
        AttestStore::new(&ra),
        AttestStore::new(&rb),
        AttestStore::new(&rc),
    );
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    sa.put(B, S1, &hex64(2), b"b1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    grow_history(&sa, 4, 10);
    for s in [&sb, &sc] {
        s.fetch(Some("origin")).unwrap();
        s.hydrate_attestations().unwrap();
    }
    assert_eq!(sb.history_commits().unwrap(), Some(5));
    // Under the limit: a plain push on top.
    sa.put(C, S1, &hex64(3), b"c1").unwrap();
    let out = sa
        .push_rewriting_history_longer_than(Some("origin"), 9)
        .unwrap();
    assert!(!out.rewritten, "{out:?}");
    assert_eq!(out.status, PushStatus::Pushed);
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("history holds 5 commit(s), not more than 9")),
        "{out:?}"
    );
    assert_eq!(commits(&w.remote, "refs/meta/main"), 6);

    // Both prune (a1 by one, b1 by the other) and find the history long.
    let a1 = sa.list(Some(A)).unwrap().remove(0);
    assert!(sa.remove(&a1).unwrap());
    let b1 = sb.list(Some(B)).unwrap().remove(0);
    assert!(sb.remove(&b1).unwrap());
    sb.put(D, S1, &hex64(4), b"d1").unwrap();
    let mut first = None;
    let out = sb
        .push_rewriting_history_longer_than_with_hook(Some("origin"), 3, |attempt| {
            if attempt == 1 {
                let out = sa
                    .push_rewriting_history_longer_than(Some("origin"), 3)
                    .unwrap();
                assert!(out.rewritten, "{out:?}");
                first = Some(git(&w.remote, &["rev-parse", "refs/meta/main"]));
            }
        })
        .unwrap();
    let first = first.expect("the other clone rewrote first");
    assert!(!out.rewritten, "the second clone rewrote again: {out:?}");
    assert_eq!(out.status, PushStatus::Pushed);
    assert_eq!(
        roots(&w.remote, "refs/meta/main"),
        std::slice::from_ref(&first)
    );
    assert_eq!(commits(&w.remote, "refs/meta/main"), 2);
    let want = set(&[3, 4, 10, 11, 12, 13]);
    assert_eq!(remote_keys(&w), want, "both deletions and d1 published");

    // A clone that last fetched before the rewrite: on top of it as well.
    assert_eq!(sc.history_commits().unwrap(), Some(5), "its stale count");
    sc.put(E, S1, &hex64(5), b"e1").unwrap();
    let out = sc
        .push_rewriting_history_longer_than(Some("origin"), 3)
        .unwrap();
    assert!(!out.rewritten, "{out:?}");
    assert_eq!(out.status, PushStatus::Pushed);
    assert_eq!(roots(&w.remote, "refs/meta/main"), [first]);
    assert_eq!(commits(&w.remote, "refs/meta/main"), 3);
    let mut want = want;
    want.insert(hex64(5));
    assert_eq!(remote_keys(&w), want, "a1 and b1 not published again");
}

/// After a rewrite, a clone whose stale tree still carries the deletion
/// record of a state object and a manifest that a later run stored again
/// keeps them: it merges three-way on the tip it last fetched, where the
/// record was already there, so the value is the remote's newer change.
#[test]
fn a_stale_record_does_not_delete_a_value_stored_again_after_a_rewrite() {
    let w = world(2);
    let (ra, rs) = (repo(&w.clones[0]), repo(&w.clones[1]));
    let (sa, ss) = (AttestStore::new(&ra), AttestStore::new(&rs));
    let st = object(ObjectKind::State, "state");
    let m = hex64(0xe1);
    let mbytes = format!("manifest {}", "m".repeat(300)).into_bytes();
    sa.put_objects(std::slice::from_ref(&st)).unwrap();
    sa.put_manifest(&m, &mbytes).unwrap();
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    ss.fetch(Some("origin")).unwrap();
    sa.remove_object_keys(vec![object_key(&st)]).unwrap();
    sa.remove_manifests([m.as_str()]).unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    ss.fetch(Some("origin")).unwrap();
    // A later run stores the same state and manifest again.
    sa.put_objects(std::slice::from_ref(&st)).unwrap();
    sa.put_manifest(&m, &mbytes).unwrap();
    sa.put(B, S1, &hex64(2), b"b1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sa.push_rewriting_history(Some("origin")).unwrap();
    ss.put(C, S1, &hex64(3), b"c1").unwrap();
    let out = ss.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
    let after = tree_blobs(&w.remote, "refs/meta/main");
    assert!(
        after.contains_key(&object_path(&st)),
        "state object deleted"
    );
    assert!(after.contains_key(&manifest_path(&m)), "manifest deleted");
    assert_eq!(remote_keys(&w), set(&[1, 2, 3]));
}

/// A clone without a base for the rewritten history (it never fetched, so
/// nothing says what it had from the remote) merges it without a common
/// ancestor: the new tip's deletion record of a manifest or object
/// (content-addressed: a later run may put it again) wins over the value
/// the clone wrote before the record was made, and loses to one written
/// after it. Before, the local value always won, and such a clone
/// published again what the rewrite's prune had deleted, until the next
/// prune. (No attestation here: an attestation this clone cannot read
/// might reference any object, and the merge then puts every one back.)
#[test]
fn without_a_base_a_deletion_record_wins_over_a_manifest_or_object_written_before_it() {
    let pause = || std::thread::sleep(Duration::from_millis(20));
    let w = world(3);
    let (ra, rs, rn) = (repo(&w.clones[0]), repo(&w.clones[1]), repo(&w.clones[2]));
    let (sa, ss, sn) = (
        AttestStore::new(&ra),
        AttestStore::new(&rs),
        AttestStore::new(&rn),
    );
    let hdr = object(ObjectKind::Hdr, "hdr");
    let state = object(ObjectKind::State, "state");
    let m = hex64(0xe1);
    let mbytes = format!("manifest {}", "m".repeat(300)).into_bytes();
    let put_all = |s: &AttestStore<'_>| {
        s.put_objects(&[hdr.clone(), state.clone()]).unwrap();
        s.put_manifest(&m, &mbytes).unwrap();
    };
    let paths = [
        ("hdr", object_path(&hdr)),
        ("state", object_path(&state)),
        ("manifest", manifest_path(&m)),
    ];
    let on_remote = || -> Vec<&str> {
        let t = tree_blobs(&w.remote, "refs/meta/main");
        paths
            .iter()
            .filter(|(_, p)| t.contains_key(p))
            .map(|(n, _)| *n)
            .collect()
    };
    // The stale clone holds them first (an earlier run of the same inputs).
    put_all(&ss);
    pause();
    // The pruner had them too, deletes them (nothing references them) and
    // rewrites the history.
    put_all(&sa);
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sa.remove_object_keys(vec![object_key(&hdr), object_key(&state)])
        .unwrap();
    sa.remove_manifests([m.as_str()]).unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sa.push_rewriting_history(Some("origin")).unwrap();
    assert_eq!(commits(&w.remote, "refs/meta/main"), 1);
    assert!(on_remote().is_empty());
    pause();
    // Another clone that never fetched either runs them again now.
    put_all(&sn);

    // The stale clone publishes a manifest of its own, and not the others.
    let m2 = hex64(0xe2);
    ss.put_manifest(&m2, format!("manifest {}", "n".repeat(300)).as_bytes())
        .unwrap();
    let out = ss.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
    assert!(
        on_remote().is_empty(),
        "the stale clone published again {:?}",
        on_remote()
    );
    assert!(
        tree_blobs(&w.remote, "refs/meta/main").contains_key(&manifest_path(&m2)),
        "its own manifest"
    );
    assert!(ss.manifest(&m).unwrap().is_none(), "deleted there too");

    // The one written after the records publishes them.
    let out = sn.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
    assert_eq!(on_remote(), ["hdr", "state", "manifest"]);
}
