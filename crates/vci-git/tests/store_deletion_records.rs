//! Old deletion records (vci 2.7.20): a push drops the deletion records
//! older than the retention window from the store and the metadata tree once
//! there are enough of them, and another clone's fetch drops them from its
//! store too rather than stamping them as new deletions. (Its own binary:
//! the window is set through the environment.)

mod common;

use camino::Utf8Path;
use common::*;
use vci_git::{AttestStore, PushStatus, Repo};

const S1: &str = "0123456789abcdef";
const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";

fn repo(root: &Utf8Path) -> Repo {
    Repo::discover(root).unwrap()
}

fn records(dir: &Utf8Path) -> i64 {
    let db = rusqlite::Connection::open(dir.join(".git/git-meta.sqlite")).unwrap();
    db.query_row(
        "SELECT count(*) FROM tombstones WHERE tombstone_type = 'metadata'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

fn tree_records(dir: &Utf8Path, rev: &str) -> usize {
    git(dir, &["ls-tree", "-r", "--name-only", "--full-tree", rev])
        .lines()
        .filter(|p| p.contains("__tombstones"))
        .count()
}

#[test]
fn old_deletion_records_are_dropped_by_a_push_and_by_the_next_fetch() {
    // SAFETY: the only test in this binary, set before any thread starts.
    unsafe {
        std::env::set_var("VCI_DELETION_RECORDS_DROP_AT", "1000000");
    }
    let w = world(2);
    let (a, b) = (&w.clones[0], &w.clones[1]);
    let ra = repo(a);
    let sa = AttestStore::new(&ra);
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    sa.put(B, S1, &hex64(2), b"b1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    let gone = sa
        .list(Some(A))
        .unwrap()
        .into_iter()
        .next()
        .expect("A's attestation");
    assert!(sa.remove(&gone).unwrap());
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    assert_eq!(tree_records(a, "refs/meta/local/main"), 1);
    // The other clone holds the record.
    let rb = repo(b);
    let sb = AttestStore::new(&rb);
    sb.fetch(Some("origin")).unwrap();
    assert_eq!(records(b), 1);
    assert!(sb.list(Some(A)).unwrap().is_empty());

    // Past the window, a push drops it.
    std::thread::sleep(std::time::Duration::from_millis(20));
    unsafe {
        std::env::set_var("VCI_DELETION_RECORDS_KEEP_SECS", "0");
        std::env::set_var("VCI_DELETION_RECORDS_DROP_AT", "1");
    }
    sa.put(C, S1, &hex64(3), b"c1").unwrap();
    let out = sa.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed);
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("dropped 1 deletion record")),
        "{:?}",
        out.notes
    );
    assert_eq!(records(a), 0);
    assert_eq!(tree_records(&w.remote, "refs/meta/main"), 0);
    unsafe {
        std::env::set_var("VCI_DELETION_RECORDS_DROP_AT", "1000000");
    }

    // The other clone's fetch drops it from its store (not a new deletion),
    // and its next push does not bring it back.
    sb.fetch(Some("origin")).unwrap();
    assert_eq!(records(b), 0);
    assert!(sb.list(Some(A)).unwrap().is_empty());
    assert_eq!(sb.list(Some(C)).unwrap().len(), 1);
    sb.put(A, S1, &hex64(4), b"a2").unwrap();
    assert_eq!(sb.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    assert_eq!(tree_records(&w.remote, "refs/meta/main"), 0);
    sa.fetch(Some("origin")).unwrap();
    let mut keys: Vec<String> = sa
        .list(None)
        .unwrap()
        .into_iter()
        .map(|e| e.storage_key)
        .collect();
    keys.sort();
    assert_eq!(keys, vec![hex64(2), hex64(3), hex64(4)]);
}
