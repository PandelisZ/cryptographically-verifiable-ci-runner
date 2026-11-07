//! A long metadata history published again as one commit (`vci prune`
//! does it once the history passes `[store] history_max_commits`, through
//! `vci push --rewrite-history`), and the clones that still hold the old
//! history: they fetch, merge and push on top of the new one without
//! losing a value, without a refusal, and without publishing for good an
//! attestation deleted before the rewrite. (Its own binary: one test sets
//! the process's deletion-record window.)

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use camino::Utf8Path;
use common::*;
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
/// rewritten away, publishes that value again once: nothing tells it the
/// value was deleted. Its push is not refused, no value is lost, the next
/// removal (the next `vci prune`) deletes it again, and the stale clone's
/// later pushes do not bring it back: it merged the new history, and
/// merges three-way from then on.
#[test]
fn a_value_deleted_before_the_window_comes_back_once_and_goes_again() {
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
    assert_eq!(sa.drop_deletion_records().unwrap(), Some(1));
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

    // The stale clone publishes a1 again with its own attestation.
    ss.put(C, S1, &hex64(3), b"c1").unwrap();
    assert_eq!(ss.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    assert_eq!(remote_keys(&w), set(&[1, 2, 3]), "a1 came back once");

    // The pruner fetches it (no refusal) and deletes it again.
    sa.fetch(Some("origin")).unwrap();
    assert_eq!(keys(&sa), set(&[1, 2, 3]));
    let again = sa.list(Some(A)).unwrap().remove(0);
    assert!(sa.remove(&again).unwrap());
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    assert_eq!(remote_keys(&w), set(&[2, 3]));

    // The stale clone's next pushes keep it deleted.
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
