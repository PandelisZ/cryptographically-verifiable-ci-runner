//! A CI cache of a clone saved before `vci prune` rewrote the metadata
//! history, restored again and again: every job that restores it merges the
//! rewritten history without a common ancestor, and before 2.10 published
//! again every value deleted (and its deletion record dropped, past
//! `[store] deletion_records_hours`) since the cache was saved, each time
//! it was restored. The merge now takes as its base the tip this clone
//! last fetched (the tracking ref before the fetch, or the tip it last
//! materialized), so a value the clone got from the remote that the new tip
//! lacks is a deletion made there. (Its own binary: the tests set the
//! process's deletion-record window.)

mod common;

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use common::*;
use vci_git::{AttestStore, PushStatus, Repo};

const S1: &str = "0123456789abcdef";
const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";
const D: &str = "src/d.test.ts";
const E: &str = "src/e.test.ts";

/// The deletion-record window is the process's: one scenario at a time.
static WINDOW: Mutex<()> = Mutex::new(());

fn repo(root: &Utf8Path) -> Repo {
    Repo::discover(root).unwrap()
}

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

/// The storage keys of the attestations the remote's tip holds.
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

/// `cp -R src dst`: a CI cache of a whole clone, restored.
fn restore_cache(src: &Utf8Path, dst: &Utf8Path) {
    let st = std::process::Command::new("cp")
        .args(["-R", src.as_str(), dst.as_str()])
        .status()
        .unwrap();
    assert!(st.success());
}

/// Past the window: drop every deletion record whose deletion is
/// published (what `vci prune` does once they are older than `[store]
/// deletion_records_hours`), then publish the drop.
fn records_expire(sa: &AttestStore<'_>) {
    std::thread::sleep(Duration::from_millis(20));
    vci_git::meta::set_deletion_records_keep(Duration::ZERO);
    sa.drop_deletion_records().unwrap();
    vci_git::meta::set_deletion_records_keep(Duration::from_secs(6 * 3600));
    sa.push(Some("origin")).unwrap();
}

#[derive(Clone, Copy, PartialEq)]
enum Job {
    /// The job attests and pushes.
    Push,
    /// The job's cache was saved after a `vci fetch` killed between its
    /// `git fetch` (which moved the tracking ref to the rewritten tip) and
    /// its merge: only the tip it last materialized says what it had.
    InterruptedFetch,
}

/// The remote's attestation keys after each of three jobs that restore
/// the same cache, attest one unit each and push; between jobs the pruner
/// deletes a1 again when it came back, and the records pass the window.
fn scenario(rewrite: bool, job: Job) -> Vec<BTreeSet<String>> {
    let _one = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    let w = world(1);
    let a = &w.clones[0];
    let base = w.remote.parent().unwrap().to_owned();
    let ra = repo(a);
    let sa = AttestStore::new(&ra);
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    sa.put(B, S1, &hex64(2), b"b1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);

    // A CI job's clone, cached after its fetch (values read, as a plan
    // reads the candidates it verifies).
    let cache: Utf8PathBuf = base.join("cache");
    git(&base, &["clone", "-q", w.remote.as_str(), cache.as_str()]);
    {
        let rc = repo(&cache);
        let sc = AttestStore::new(&rc);
        sc.fetch(Some("origin")).unwrap();
        sc.hydrate_attestations().unwrap();
        assert_eq!(keys(&sc), set(&[1, 2]));
    }

    // The hourly prune deletes a1 (superseded) and publishes it; its record
    // passes the window; then the history is published as one commit.
    let gone = sa.list(Some(A)).unwrap().remove(0);
    assert!(sa.remove(&gone).unwrap());
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    records_expire(&sa);
    if rewrite {
        sa.push_rewriting_history(Some("origin")).unwrap();
    }
    assert_eq!(remote_keys(&w), set(&[2]));

    let mut seen = Vec::new();
    for (i, (unit, k)) in [(C, 3u8), (D, 4), (E, 5)].into_iter().enumerate() {
        let dir = base.join(format!("job{i}"));
        restore_cache(&cache, &dir);
        if job == Job::InterruptedFetch {
            git(
                &dir,
                &[
                    "fetch",
                    "-q",
                    "origin",
                    "+refs/meta/main:refs/meta/remotes/main",
                ],
            );
        }
        let rj = repo(&dir);
        let sj = AttestStore::new(&rj);
        sj.put(unit, S1, &hex64(k), b"x").unwrap();
        let out = sj.push(Some("origin")).unwrap();
        assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
        let now = remote_keys(&w);
        assert!(
            now.contains(&hex64(k)),
            "job {i}'s own attestation: {now:?}"
        );
        assert!(now.contains(&hex64(2)), "b1 kept: {now:?}");
        seen.push(now);
        // The next hourly prune deletes a1 again when it came back, and
        // its record passes the window before the next job.
        sa.fetch(Some("origin")).unwrap();
        if let Some(e) = sa.list(Some(A)).unwrap().into_iter().next() {
            assert!(sa.remove(&e).unwrap());
            sa.push(Some("origin")).unwrap();
        }
        records_expire(&sa);
    }
    seen
}

/// Control: no rewrite. Every restored cache merges three-way (its old tip
/// is an ancestor of the remote's), so a1 never comes back.
#[test]
fn without_a_rewrite_a_restored_cache_never_brings_back_a_deleted_value() {
    let seen = scenario(false, Job::Push);
    for s in &seen {
        assert!(!s.contains(&hex64(1)), "a1 came back: {seen:?}");
    }
}

/// After the rewrite, no job restoring the pre-rewrite cache publishes a1
/// again: the merge's base is the tip the cache last fetched, which held
/// a1, so the new tip's lack of it is a deletion.
#[test]
fn after_a_rewrite_no_restore_of_a_stale_cache_brings_back_a_deleted_value() {
    let seen = scenario(true, Job::Push);
    let back = seen.iter().filter(|s| s.contains(&hex64(1))).count();
    assert_eq!(
        back,
        0,
        "a1 was published again by {back} of {} jobs restoring the same cache: {seen:?}",
        seen.len()
    );
}

/// As above, for a cache whose last `vci fetch` was killed after `git
/// fetch` moved the tracking ref to the rewritten tip: the tip it last
/// materialized is the base.
#[test]
fn after_a_rewrite_a_cache_saved_mid_fetch_does_not_bring_back_a_deleted_value() {
    let seen = scenario(true, Job::InterruptedFetch);
    let back = seen.iter().filter(|s| s.contains(&hex64(1))).count();
    assert_eq!(back, 0, "{seen:?}");
}

/// A clone whose last fetched tip is not in its local history (nothing
/// says what it had from the remote) still merges as before: every value
/// it holds is kept and its push is not refused.
#[test]
fn after_a_rewrite_a_clone_without_a_usable_base_keeps_its_values() {
    let _one = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    let w = world(2);
    let (a, s) = (&w.clones[0], &w.clones[1]);
    let (ra, rs) = (repo(a), repo(s));
    let (sa, ss) = (AttestStore::new(&ra), AttestStore::new(&rs));
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    // The other clone never fetched; it attests b and c locally.
    ss.put(B, S1, &hex64(2), b"b1").unwrap();
    ss.put(C, S1, &hex64(3), b"c1").unwrap();
    sa.put(D, S1, &hex64(4), b"d1").unwrap();
    sa.push_rewriting_history(Some("origin")).unwrap();
    let out = ss.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
    assert_eq!(remote_keys(&w), set(&[1, 2, 3, 4]));
}
