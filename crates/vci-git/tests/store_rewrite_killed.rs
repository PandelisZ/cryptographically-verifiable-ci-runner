//! A fetch or push killed between git's move of the tracking ref and the
//! end of vci's own work, across a rewrite of the metadata history (2.10).
//!
//! A merge with a rewritten history takes as its base the newest tip this
//! clone had from the remote ([`AttestStore::fetch`]'s `rewritten_base`).
//! Before these fixes it could pick an older one: a `git fetch` (or `git
//! push`, through the remote's fetch refspec) moves the tracking ref
//! itself, and a process killed before vci finished left the ref at a tip
//! nothing was merged with, while the marker named the tip before this
//! clone's own last push. What this clone had pushed since then counted as
//! its own additions: a value another clone deleted (with a record) before
//! rewriting the history was published again, by every job restoring a CI
//! cache saved in that state, and a clone's own deletion of a value its
//! killed rewrite had published was undone. Now the marker names the
//! commit each push published, the tips a fetch moves the tracking ref
//! from are noted until its merge is done, a rewrite's commit names the
//! local commit it publishes, and a merged tree never keeps an
//! attestation's value beside its deletion record. (Kills: the
//! `fetch-after-git-fetch` and `push-after-git-push` failpoints, or a
//! plain `git fetch` of the tracking ref, which is what a fetch killed
//! right after it leaves.)

mod common;

use std::collections::BTreeSet;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use camino::Utf8Path;
use common::*;
use vci_git::{AttestStore, PushStatus, Repo};

const S1: &str = "0123456789abcdef";
const A: &str = "src/a.test.ts";
const K: &str = "src/k.test.ts";
const P2: &str = "src/p2.test.ts";

/// The deletion-record window is the process's: one scenario at a time.
static WINDOW: Mutex<()> = Mutex::new(());

fn repo(root: &Utf8Path) -> Repo {
    Repo::discover(root).unwrap()
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
fn copy(src: &Utf8Path, dst: &Utf8Path) {
    let st = Command::new("cp")
        .args(["-R", src.as_str(), dst.as_str()])
        .status()
        .unwrap();
    assert!(st.success());
}

/// Drop every published deletion record (a zero window), as `vci prune`
/// does once they pass `[store] deletion_records_hours`.
fn drop_records(s: &AttestStore<'_>) {
    std::thread::sleep(Duration::from_millis(20));
    vci_git::meta::set_deletion_records_keep(Duration::ZERO);
    s.drop_deletion_records().unwrap();
    vci_git::meta::set_deletion_records_keep(Duration::from_secs(6 * 3600));
}

/// Run `op` on the clone `dir` in a child process killed at `failpoint`.
fn killed(dir: &Utf8Path, op: &str, failpoint: &str) {
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_op",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("VCI_TEST_CHILD_DIR", dir.as_str())
        .env("VCI_TEST_CHILD_OP", op)
        .env("VCI_FAILPOINT", failpoint)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{op} was not killed: {stderr}");
    assert!(
        stderr.contains(&format!("failpoint {failpoint}")),
        "{stderr}"
    );
}

/// What [`killed`] runs; does nothing in a normal test run.
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
        // `vci prune`'s publication past `[store] history_max_commits`.
        Ok("rewrite") => {
            st.push_rewriting_history_longer_than(Some("origin"), 1)
                .unwrap();
        }
        Ok("fetch") => {
            st.fetch(Some("origin")).unwrap();
        }
        other => panic!("unknown child op {other:?}"),
    }
}

/// What a fetch killed right after its `git fetch` leaves: the tracking
/// ref at the remote's tip, nothing merged.
fn tracking_moved(dir: &Utf8Path) {
    git(
        dir,
        &[
            "fetch",
            "-q",
            "origin",
            "+refs/meta/main:refs/meta/remotes/main",
        ],
    );
}

/// The clone P attests k and pushes it; the pruner A deletes k (with a
/// record), publishes that, drops the record when `drop` (the window
/// passed) and rewrites the history. With `killed_fetch` P's fetch is
/// killed after `git fetch` moved its tracking ref to the rewrite. Then P
/// attests and pushes `pushes` times, A deleting k again whenever it came
/// back. Whether k was on the remote after each of P's pushes.
fn stale_base_scenario(drop: bool, killed_fetch: bool, pushes: usize) -> Vec<bool> {
    let _one = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    let w = world(2);
    let (ra, rp) = (repo(&w.clones[0]), repo(&w.clones[1]));
    let (sa, sp) = (AttestStore::new(&ra), AttestStore::new(&rp));
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sp.fetch(Some("origin")).unwrap();
    sp.put(K, S1, &hex64(0x0c), b"k").unwrap();
    assert_eq!(sp.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sa.fetch(Some("origin")).unwrap();
    sa.hydrate_attestations().unwrap();
    let k = sa.list(Some(K)).unwrap().remove(0);
    assert!(sa.remove(&k).unwrap());
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    if drop {
        drop_records(&sa);
    }
    assert!(sa.push_rewriting_history(Some("origin")).unwrap().rewritten);
    assert!(!remote_keys(&w).contains(&hex64(0x0c)));
    if killed_fetch {
        tracking_moved(&w.clones[1]);
    }
    let mut back = Vec::new();
    for i in 0..pushes {
        sp.put(P2, S1, &hex64(0x20 + i as u8), b"p").unwrap();
        let out = sp.push(Some("origin")).unwrap();
        assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
        back.push(remote_keys(&w).contains(&hex64(0x0c)));
        sa.fetch(Some("origin")).unwrap();
        sa.hydrate_attestations().unwrap();
        if let Some(e) = sa.list(Some(K)).unwrap().into_iter().next() {
            assert!(sa.remove(&e).unwrap());
            sa.push(Some("origin")).unwrap();
        }
    }
    back
}

/// Control: nothing killed, k stays deleted (with its record, or after the
/// record was dropped). A tree equal to an older commit's (a1 alone,
/// once k is deleted and its record dropped) does not make that commit
/// the base.
#[test]
fn without_a_kill_a_value_deleted_before_the_rewrite_stays_deleted() {
    for drop in [false, true] {
        assert_eq!(
            stale_base_scenario(drop, false, 1),
            [false],
            "records dropped: {drop}"
        );
    }
}

/// A fetch killed after `git fetch` moved the tracking ref to the
/// rewrite: the next merge's base is the commit this clone last pushed
/// (the marker names it), not the tip before that push, so k, which it
/// pushed and the pruner deleted, is not published again. Before, it was,
/// with the record on the tip or without it, once per such fetch.
#[test]
fn after_a_killed_fetch_a_value_deleted_before_the_rewrite_is_not_published_again() {
    for drop in [false, true] {
        assert_eq!(
            stale_base_scenario(drop, true, 3),
            [false, false, false],
            "records dropped: {drop}"
        );
    }
}

/// vex's attest job: its fetch is killed after `git fetch` moved the
/// tracking ref to another job's rewrite, and the keep step (`if:
/// always()`) saves that `.git` as the pull request jobs' cache. No job
/// restoring it publishes k again (before: every one did).
#[test]
fn a_cache_saved_after_a_killed_fetch_does_not_publish_a_deleted_value_again() {
    let w = world(2);
    let (ra, rp) = (repo(&w.clones[0]), repo(&w.clones[1]));
    let (sa, sp) = (AttestStore::new(&ra), AttestStore::new(&rp));
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sp.fetch(Some("origin")).unwrap();
    sp.put(K, S1, &hex64(0x0c), b"k").unwrap();
    assert_eq!(sp.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sa.fetch(Some("origin")).unwrap();
    sa.hydrate_attestations().unwrap();
    let k = sa.list(Some(K)).unwrap().remove(0);
    assert!(sa.remove(&k).unwrap());
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    assert!(sa.push_rewriting_history(Some("origin")).unwrap().rewritten);
    tracking_moved(&w.clones[1]);
    let base = w.remote.parent().unwrap().to_owned();
    let cache = base.join("cache");
    copy(&w.clones[1], &cache);
    let mut back = Vec::new();
    for i in 0..3u8 {
        let job = base.join(format!("job{i}"));
        copy(&cache, &job);
        let rj = repo(&job);
        let sj = AttestStore::new(&rj);
        sj.put(P2, S1, &hex64(0x30 + i), b"p").unwrap();
        let out = sj.push(Some("origin")).unwrap();
        assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
        back.push(remote_keys(&w).contains(&hex64(0x0c)));
        sa.fetch(Some("origin")).unwrap();
        sa.hydrate_attestations().unwrap();
        if let Some(e) = sa.list(Some(K)).unwrap().into_iter().next() {
            assert!(sa.remove(&e).unwrap());
            sa.push(Some("origin")).unwrap();
        }
    }
    assert_eq!(back, [false, false, false]);
}

/// The clone's push (a plain one, or its prune's rewrite) lands and the
/// process is killed before vci moves its refs; another clone deletes k
/// (with a record, dropped or not by the time it rewrites the history),
/// which that push published first, and rewrites the history. The killed
/// clone's next push does not publish k again: after a plain push the
/// tracking ref git moved is the base; after a rewrite, the rewrite
/// commit, which names the local commit it publishes. Before, the base
/// after a rewrite was the tip before it.
#[test]
fn a_push_killed_after_it_landed_does_not_bring_back_what_was_deleted_after_it() {
    let _one = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    for (op, drop) in [
        ("push", false),
        ("push", true),
        ("rewrite", false),
        ("rewrite", true),
    ] {
        let op_drop = format!("{op}, records dropped: {drop}");
        let op = op_drop.as_str();
        let w = world(2);
        let (ra, rp) = (repo(&w.clones[0]), repo(&w.clones[1]));
        let (sa, sp) = (AttestStore::new(&ra), AttestStore::new(&rp));
        sa.put(A, S1, &hex64(1), b"a1").unwrap();
        assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
        sa.put(A, S1, &hex64(2), b"a2").unwrap();
        assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
        sp.fetch(Some("origin")).unwrap();
        sp.put(K, S1, &hex64(0x0c), b"k").unwrap();
        let local = git(&w.clones[1], &["rev-parse", "refs/meta/local/main"]);
        let child = op_drop.split(',').next().unwrap();
        killed(&w.clones[1], child, "push-after-git-push");
        assert!(remote_keys(&w).contains(&hex64(0x0c)), "{op}: k landed");
        if child == "rewrite" {
            // The rewrite landed; the local metadata commit is the one it
            // was made from (serialized with k), not the rewrite.
            let pushed = git(&w.remote, &["rev-parse", "refs/meta/main"]);
            assert_ne!(
                git(&w.clones[1], &["rev-parse", "refs/meta/local/main"]),
                pushed
            );
            assert_ne!(local, pushed);
        }
        sa.fetch(Some("origin")).unwrap();
        sa.hydrate_attestations().unwrap();
        let k = sa.list(Some(K)).unwrap().remove(0);
        assert!(sa.remove(&k).unwrap());
        assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
        if drop {
            drop_records(&sa);
        }
        assert!(sa.push_rewriting_history(Some("origin")).unwrap().rewritten);
        sp.put(P2, S1, &hex64(0x21), b"p").unwrap();
        let out = sp.push(Some("origin")).unwrap();
        assert_eq!(out.status, PushStatus::Pushed, "{op}: {out:?}");
        let now = remote_keys(&w);
        assert!(!now.contains(&hex64(0x0c)), "{op}: k published again");
        assert!(now.contains(&hex64(0x21)), "{op}: {now:?}");
    }
}

/// The clone's own rewrite lands and the process is killed before the
/// local metadata commit moves to it; the clone then deletes k, which that
/// rewrite published first, and pushes. The deletion is published (the
/// merge's base is the rewrite, which names the commit it was made from):
/// before, the base was the tip before the rewrite, and the published tree
/// held both k's value and its record, and the other clone kept k.
#[test]
fn an_own_deletion_after_an_own_rewrite_killed_after_it_landed_is_published() {
    let w = world(2);
    let (ra, rp) = (repo(&w.clones[0]), repo(&w.clones[1]));
    let (sa, sp) = (AttestStore::new(&ra), AttestStore::new(&rp));
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sa.put(A, S1, &hex64(2), b"a2").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sp.fetch(Some("origin")).unwrap();
    sp.put(K, S1, &hex64(0x0c), b"k").unwrap();
    killed(&w.clones[1], "rewrite", "push-after-git-push");
    assert!(remote_keys(&w).contains(&hex64(0x0c)), "k landed");
    sp.hydrate_attestations().unwrap();
    let k = sp.list(Some(K)).unwrap().remove(0);
    assert!(sp.remove(&k).unwrap());
    let out = sp.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
    let paths: Vec<String> = git(
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
    .filter(|p| p.contains(&hex64(0x0c)))
    .map(str::to_owned)
    .collect();
    assert_eq!(paths.len(), 1, "{paths:?}");
    assert!(paths[0].ends_with("/__deleted"), "{paths:?}");
    sa.fetch(Some("origin")).unwrap();
    assert!(sa.list(Some(K)).unwrap().is_empty());
}

/// vex's shape: the attest job's prune rewrite lands and the job is killed
/// before the local metadata commit moves (the step's timeout), the keep
/// step saves that `.git` as the pull request jobs' cache, and another
/// clone deletes (with a record) a value the rewrite published first. No
/// job restoring the cache publishes it again (before: every one did).
#[test]
fn a_cache_saved_after_a_rewrite_killed_after_it_landed_does_not_publish_a_deleted_value_again() {
    let w = world(2);
    let (ra, rp) = (repo(&w.clones[0]), repo(&w.clones[1]));
    let (sa, sp) = (AttestStore::new(&ra), AttestStore::new(&rp));
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sa.put(A, S1, &hex64(2), b"a2").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sp.fetch(Some("origin")).unwrap();
    sp.put(K, S1, &hex64(0x0c), b"k").unwrap();
    killed(&w.clones[1], "rewrite", "push-after-git-push");
    let base = w.remote.parent().unwrap().to_owned();
    let cache = base.join("cache");
    copy(&w.clones[1], &cache);
    sa.fetch(Some("origin")).unwrap();
    sa.hydrate_attestations().unwrap();
    let k = sa.list(Some(K)).unwrap().remove(0);
    assert!(sa.remove(&k).unwrap());
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    let mut back = Vec::new();
    for i in 0..3u8 {
        let job = base.join(format!("job{i}"));
        copy(&cache, &job);
        let rj = repo(&job);
        let sj = AttestStore::new(&rj);
        sj.put(P2, S1, &hex64(0x40 + i), b"p").unwrap();
        let out = sj.push(Some("origin")).unwrap();
        assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
        back.push(remote_keys(&w).contains(&hex64(0x0c)));
        sa.fetch(Some("origin")).unwrap();
        sa.hydrate_attestations().unwrap();
        if let Some(e) = sa.list(Some(K)).unwrap().into_iter().next() {
            assert!(sa.remove(&e).unwrap());
            sa.push(Some("origin")).unwrap();
        }
    }
    assert_eq!(back, [false, false, false]);
}

/// A push killed after it landed (the marker still names the tip before
/// it), then a fetch killed after its `git fetch` moved the tracking ref
/// to a rewrite that dropped k's record: the fetch noted the tip it moved
/// the ref from (this clone's push) before moving it, and the next merge
/// takes that as its base, so k stays deleted. Neither the marker nor the
/// tracking ref names that push any more; before, the base was the tip
/// before it, and k came back.
#[test]
fn a_fetch_killed_after_a_push_killed_merges_on_the_push() {
    let _one = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    let w = world(2);
    let (ra, rp) = (repo(&w.clones[0]), repo(&w.clones[1]));
    let (sa, sp) = (AttestStore::new(&ra), AttestStore::new(&rp));
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sp.fetch(Some("origin")).unwrap();
    sp.put(K, S1, &hex64(0x0c), b"k").unwrap();
    let p = &w.clones[1];
    killed(p, "push", "push-after-git-push");
    let pushed = git(&w.remote, &["rev-parse", "refs/meta/main"]);
    assert_eq!(git(p, &["rev-parse", "refs/meta/remotes/main"]), pushed);
    sa.fetch(Some("origin")).unwrap();
    sa.hydrate_attestations().unwrap();
    let k = sa.list(Some(K)).unwrap().remove(0);
    assert!(sa.remove(&k).unwrap());
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    drop_records(&sa);
    assert!(sa.push_rewriting_history(Some("origin")).unwrap().rewritten);
    killed(p, "fetch", "fetch-after-git-fetch");
    let tip = git(&w.remote, &["rev-parse", "refs/meta/main"]);
    assert_eq!(git(p, &["rev-parse", "refs/meta/remotes/main"]), tip);
    let unmerged =
        std::fs::read_to_string(p.join(".git/vci-materialized-refs_meta_remotes_main.unmerged"))
            .unwrap();
    assert_eq!(unmerged.trim(), pushed);
    sp.put(P2, S1, &hex64(0x22), b"p").unwrap();
    let out = sp.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
    let now = remote_keys(&w);
    assert!(!now.contains(&hex64(0x0c)), "k published again: {now:?}");
    assert!(now.contains(&hex64(0x22)), "{now:?}");
    // The merge finished: the noted tips are gone, the marker names the
    // push.
    assert!(
        !p.join(".git/vci-materialized-refs_meta_remotes_main.unmerged")
            .exists()
    );
    assert_eq!(
        std::fs::read_to_string(p.join(".git/vci-materialized-refs_meta_remotes_main"))
            .unwrap()
            .trim(),
        git(&w.remote, &["rev-parse", "refs/meta/main"])
    );
}

/// A base older than the tip this clone last had (here a marker a vci
/// before 2.10 left on the tip before its push, then a fetch killed after
/// `git fetch`) takes the clone's own pushed values for its additions and
/// the tip's records of them for the tip's: the merged tree holds both.
/// The record wins for an attestation (its key is never written twice)
/// and for a manifest the clone put before the record, so neither is
/// published again; before, the value won.
#[test]
fn a_merged_tree_keeps_the_record_not_the_value_of_a_deleted_attestation() {
    let w = world(2);
    let (ra, rp) = (repo(&w.clones[0]), repo(&w.clones[1]));
    let (sa, sp) = (AttestStore::new(&ra), AttestStore::new(&rp));
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sp.fetch(Some("origin")).unwrap();
    let p = &w.clones[1];
    let marker = p.join(".git/vci-materialized-refs_meta_remotes_main");
    let before_push = std::fs::read_to_string(&marker).unwrap();
    let m = hex64(0xe1);
    sp.put_manifest(&m, format!("manifest {}", "m".repeat(300)).as_bytes())
        .unwrap();
    sp.put(K, S1, &hex64(0x0c), b"k").unwrap();
    assert_eq!(sp.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    std::fs::write(&marker, before_push).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    sa.fetch(Some("origin")).unwrap();
    sa.hydrate_attestations().unwrap();
    let k = sa.list(Some(K)).unwrap().remove(0);
    assert!(sa.remove(&k).unwrap());
    sa.remove_manifests([m.as_str()]).unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    assert!(sa.push_rewriting_history(Some("origin")).unwrap().rewritten);
    tracking_moved(p);
    sp.put(P2, S1, &hex64(0x23), b"p").unwrap();
    let out = sp.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("held both a value and a deletion record of 2 key(s)")),
        "{out:?}"
    );
    let paths = git(
        &w.remote,
        &[
            "ls-tree",
            "-r",
            "--name-only",
            "--full-tree",
            "refs/meta/main",
        ],
    );
    let of = |id: &str| -> Vec<&str> { paths.lines().filter(|l| l.contains(id)).collect() };
    for id in [hex64(0x0c), m.clone()] {
        let p = of(&id);
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(p[0].ends_with("/__deleted"), "{p:?}");
    }
    assert!(sp.list(Some(K)).unwrap().is_empty());
    assert!(sp.manifest(&m).unwrap().is_none());
}
