//! A fetch whose merge both deletes many values and drops many deletion
//! records is not quadratic (2.10; found rehearsing 2.10 on a copy of vex's
//! store): it spent O(deleted × dropped) forgetting the dropped records. The merge's deletions
//! fill `vci_cover_gone` (the `vci_cover_gone_rows` trigger, one row per
//! deleted value), and the drop then runs `DELETE FROM vci_cover_gone WHERE
//! target_type = ? AND target_value = ? AND key = ?` once per dropped
//! record, a full scan of a table without an index. On a copy of vex's
//! store, the first fetch after `vci prune` rewrote the history (23,300
//! values deleted, 103,700 records dropped) spent 175 to 273 s there, of a
//! 190 to 300 s fetch; a cache 5.5 hours older, 376 s of 401 s. With an
//! index on the table, 37 s.

mod common;

use std::time::{Duration, Instant};

use common::*;
use vci_git::{AttestStore, PushStatus, Repo, StoredEnvelope};

const S1: &str = "0123456789abcdef";

fn storage_key(i: usize) -> String {
    format!("{i:064x}")
}

/// The number a value was stored under (its storage key).
fn index(e: &StoredEnvelope) -> usize {
    let k = e.key.split(':').nth(4).expect("storage key");
    usize::from_str_radix(&k[48..], 16).unwrap()
}

#[test]
fn a_fetch_that_deletes_and_drops_many_is_not_quadratic() {
    // Values the remote deletes and whose records it then drops, and values
    // it deletes in the same push (their records stay).
    // (At 8,000 each the fetch took 6.9 s before the index, 1.3 s with it;
    // the query plan below says which, at any size.)
    let dropped = 2000usize;
    let deleted = 2000usize;
    let w = world(2);
    let r0 = Repo::discover(&w.clones[0]).unwrap();
    let s0 = AttestStore::new(&r0);
    {
        let _batch = s0.batch().unwrap();
        for i in 0..dropped + deleted {
            s0.put(
                &format!("t/{}.test.ts", i % 400),
                S1,
                &storage_key(i),
                format!("value {i}").as_bytes(),
            )
            .unwrap();
        }
    }
    assert_eq!(s0.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    let r1 = Repo::discover(&w.clones[1]).unwrap();
    let s1 = AttestStore::new(&r1);
    s1.fetch(Some("origin")).unwrap();
    assert_eq!(s1.list(None).unwrap().len(), dropped + deleted);

    // The remote deletes the first `dropped` values; clone 1 applies the
    // records.
    let (first, rest): (Vec<_>, Vec<_>) = s0
        .list(None)
        .unwrap()
        .into_iter()
        .partition(|e| index(e) < dropped);
    s0.remove_envelopes(first).unwrap();
    assert_eq!(s0.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    s1.fetch(Some("origin")).unwrap();
    assert_eq!(s1.list(None).unwrap().len(), deleted);

    // Then it deletes the rest and drops the published records (a zero
    // window: every record is past it), in one push.
    s0.remove_envelopes(rest).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    vci_git::meta::set_deletion_records_keep(Duration::ZERO);
    let d = s0.drop_deletion_records().unwrap();
    vci_git::meta::set_deletion_records_keep(Duration::from_secs(6 * 3600));
    assert!(d.dropped >= dropped, "dropped {} records", d.dropped);
    assert_eq!(s0.push(Some("origin")).unwrap().status, PushStatus::Pushed);

    // Clone 1's merge deletes `deleted` values and drops `dropped` records.
    let t = Instant::now();
    s1.fetch(Some("origin")).unwrap();
    let secs = t.elapsed().as_secs_f64();
    assert!(s1.list(None).unwrap().is_empty());
    eprintln!("fetch that deleted {deleted} values and dropped {dropped} records: {secs:.2} s");

    // The statement the drop runs once per record must not scan.
    let db = rusqlite::Connection::open(s1.store_path().unwrap().as_std_path()).unwrap();
    let plan: Vec<String> = db
        .prepare(
            "EXPLAIN QUERY PLAN DELETE FROM vci_cover_gone WHERE target_type = ?1 AND target_value = ?2 AND key = ?3",
        )
        .unwrap()
        .query_map(rusqlite::params!["path", "t/1.test.ts", "k"], |r| {
            r.get::<_, String>(3)
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(
        plan.iter().all(|p| !p.starts_with("SCAN")),
        "the per-record delete from vci_cover_gone scans the table: {plan:?} (the fetch took {secs:.2} s)"
    );
}
