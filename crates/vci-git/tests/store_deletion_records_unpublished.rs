//! `vci prune` drops a deletion record past the window only once its
//! deletion is published: the local metadata tree no longer holds the value
//! (the record was serialized) and neither does the remote tip this clone
//! last fetched or pushed. Before, it dropped every record past the window:
//! one never serialized left the store without the value or a record while
//! the local tree still held the value, so with `[store]
//! deletion_records_hours = 0` every push and fetch after the prune was
//! refused, and with the default window the next push put the value back.
//! (Its own binary: the tests set the process's deletion-record window.)

mod common;

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Duration;

use camino::Utf8Path;
use common::*;
use vci_git::{AttestStore, PushStatus, Repo};

const S1: &str = "0123456789abcdef";
const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";

/// The deletion-record window is the process's: one test at a time.
static WINDOW: Mutex<()> = Mutex::new(());

fn repo(root: &Utf8Path) -> Repo {
    Repo::discover(root).unwrap()
}

fn set(ks: &[u8]) -> BTreeSet<String> {
    ks.iter().map(|k| hex64(*k)).collect()
}

fn tree(dir: &Utf8Path, rev: &str) -> String {
    git(dir, &["ls-tree", "-r", "--name-only", "--full-tree", rev])
}

/// The storage keys of the attestations `rev`'s tree holds in `dir`.
fn tree_keys(dir: &Utf8Path, rev: &str) -> BTreeSet<String> {
    tree(dir, rev)
        .lines()
        .filter(|p| p.ends_with("/__value") && !p.contains("__tombstones"))
        .filter_map(|p| {
            let parts: Vec<&str> = p.split('/').collect();
            let i = parts.iter().position(|s| *s == "attestation")?;
            parts.get(i + 3).map(|s| (*s).to_owned())
        })
        .collect()
}

/// `drop_deletion_records` with a zero window (every record is past it).
fn drop_all(s: &AttestStore<'_>) -> vci_git::DeletionRecords {
    std::thread::sleep(Duration::from_millis(20));
    vci_git::meta::set_deletion_records_keep(Duration::ZERO);
    let out = s.drop_deletion_records();
    vci_git::meta::set_deletion_records_keep(Duration::from_secs(6 * 3600));
    out.unwrap()
}

/// a1 and b1 published by clone 0, then a1 deleted there.
fn deleted_a1(w: &World) -> Repo {
    let r = repo(&w.clones[0]);
    let s = AttestStore::new(&r);
    s.put(A, S1, &hex64(1), b"a1").unwrap();
    s.put(B, S1, &hex64(2), b"b1").unwrap();
    assert_eq!(s.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    let gone = s.list(Some(A)).unwrap().remove(0);
    assert!(s.remove(&gone).unwrap());
    r
}

/// A deletion not yet serialized (`vci prune` writes it in the store only)
/// keeps its record past the window; the push publishes the deletion, and
/// the next drop takes the record.
#[test]
fn a_record_not_yet_serialized_stays_past_the_window_and_the_push_publishes_it() {
    let _one = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    let w = world(1);
    let r = deleted_a1(&w);
    let s = AttestStore::new(&r);
    let out = drop_all(&s);
    assert_eq!((out.dropped, out.unpublished), (0, 1), "{out:?}");
    let pushed = s.push(Some("origin")).unwrap();
    assert_eq!(pushed.status, PushStatus::Pushed, "{pushed:?}");
    assert!(
        !pushed.notes.iter().any(|n| n.contains("restored")),
        "{pushed:?}"
    );
    assert_eq!(tree_keys(&w.remote, "refs/meta/main"), set(&[2]));
    assert!(tree(&w.remote, "refs/meta/main").contains("__tombstones"));
    // Published: the next drop takes it, and the push after it publishes
    // the drop.
    let out = drop_all(&s);
    assert_eq!((out.dropped, out.unpublished), (1, 0), "{out:?}");
    assert_eq!(s.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    assert!(!tree(&w.remote, "refs/meta/main").contains("__tombstones"));
    assert_eq!(tree_keys(&w.remote, "refs/meta/main"), set(&[2]));
    assert_eq!(s.push(Some("origin")).unwrap().status, PushStatus::UpToDate);
}

/// A deletion serialized into the local metadata tree (a fetch did it) but
/// not pushed keeps its record past the window while the remote tip holds
/// the value: dropped, the push would have put the value back.
#[test]
fn a_record_serialized_but_not_pushed_stays_past_the_window() {
    let _one = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    let w = world(1);
    let r = deleted_a1(&w);
    let s = AttestStore::new(&r);
    s.fetch(Some("origin")).unwrap();
    assert!(!tree_keys(&w.clones[0], "refs/meta/local/main").contains(&hex64(1)));
    let out = drop_all(&s);
    assert_eq!((out.dropped, out.unpublished), (0, 1), "{out:?}");
    let pushed = s.push(Some("origin")).unwrap();
    assert_eq!(pushed.status, PushStatus::Pushed, "{pushed:?}");
    assert_eq!(tree_keys(&w.remote, "refs/meta/main"), set(&[2]));
    let out = drop_all(&s);
    assert_eq!((out.dropped, out.unpublished), (1, 0), "{out:?}");
}

/// A clone with no remote tip (nothing fetched or pushed yet) drops a
/// serialized record: there is nothing to publish its deletion to.
#[test]
fn a_record_of_a_clone_that_never_exchanged_goes_once_serialized() {
    let _one = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    let w = world(1);
    let r = repo(&w.clones[0]);
    let s = AttestStore::new(&r);
    s.put(A, S1, &hex64(1), b"a1").unwrap();
    s.put(B, S1, &hex64(2), b"b1").unwrap();
    let gone = s.list(Some(A)).unwrap().remove(0);
    assert!(s.remove(&gone).unwrap());
    // Nothing serialized yet: the local metadata tree is empty or lacks it.
    let out = drop_all(&s);
    assert_eq!(out.dropped + out.unpublished, 1, "{out:?}");
    assert_eq!(s.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    assert_eq!(tree_keys(&w.remote, "refs/meta/main"), set(&[2]));
}
