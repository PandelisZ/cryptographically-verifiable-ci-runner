//! A clone whose metadata refs are damaged (a CI cache restored with its
//! refs but not every object they name, a copy made by hand) is never stuck
//! (2.10). A local metadata ref naming a commit the clone lacks failed every
//! `git fetch` (`fatal: bad object refs/meta/local/main`: git checks every
//! ref) and every serialization, so nothing the store held was published
//! again until the ref was removed by hand; it is now deleted with a
//! warning and the store serialized again in full. A tracking ref that is
//! missing or names a commit the clone lacks, across a rewrite of the
//! history by another clone, was already handled; checked here too.

mod common;

use std::collections::BTreeSet;

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

fn markers(dir: &Utf8Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir.join(".git"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("vci-materialized-"))
        })
        .collect()
}

#[derive(Debug, Clone, Copy)]
enum Damage {
    TrackingMissing,
    TrackingAndMarkerMissing,
    TrackingNamesAMissingCommit,
    TrackingNamesARemoteCommitNotHere,
    LocalNamesAMissingCommit,
}

fn damaged(d: Damage) -> Vec<String> {
    let mut problems = Vec::new();
    let w = world(2);
    git(&w.remote, &["config", "uploadpack.allowFilter", "true"]);
    git(
        &w.remote,
        &["config", "uploadpack.allowAnySHA1InWant", "true"],
    );
    let (ra, rs) = (repo(&w.clones[0]), repo(&w.clones[1]));
    let (sa, ss) = (AttestStore::new(&ra), AttestStore::new(&rs));
    sa.put(A, S1, &hex64(1), b"a1").unwrap();
    sa.put(B, S1, &hex64(2), b"b1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    ss.fetch(Some("origin")).unwrap();
    ss.hydrate_attestations().unwrap();
    // The other clone deletes a1 and rewrites the history.
    let a1 = sa.list(Some(A)).unwrap().remove(0);
    assert!(sa.remove(&a1).unwrap());
    sa.put(C, S1, &hex64(3), b"c1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    let pre_rewrite = git(&w.remote, &["rev-parse", "refs/meta/main"]);
    assert!(sa.push_rewriting_history(Some("origin")).unwrap().rewritten);
    let dir = &w.clones[1];
    match d {
        Damage::TrackingMissing => {
            git(dir, &["update-ref", "-d", "refs/meta/remotes/main"]);
        }
        Damage::TrackingAndMarkerMissing => {
            git(dir, &["update-ref", "-d", "refs/meta/remotes/main"]);
            for m in markers(dir) {
                std::fs::remove_file(m).unwrap();
            }
        }
        Damage::TrackingNamesAMissingCommit => {
            git(dir, &["update-ref", "-d", "refs/meta/remotes/main"]);
            std::fs::create_dir_all(dir.join(".git/refs/meta/remotes")).unwrap();
            std::fs::write(
                dir.join(".git/refs/meta/remotes/main"),
                "1234567890abcdef1234567890abcdef12345678\n",
            )
            .unwrap();
        }
        Damage::TrackingNamesARemoteCommitNotHere => {
            git(dir, &["update-ref", "-d", "refs/meta/remotes/main"]);
            std::fs::create_dir_all(dir.join(".git/refs/meta/remotes")).unwrap();
            std::fs::write(
                dir.join(".git/refs/meta/remotes/main"),
                format!("{pre_rewrite}\n"),
            )
            .unwrap();
        }
        Damage::LocalNamesAMissingCommit => {
            git(dir, &["update-ref", "-d", "refs/meta/local/main"]);
            std::fs::create_dir_all(dir.join(".git/refs/meta/local")).unwrap();
            std::fs::write(
                dir.join(".git/refs/meta/local/main"),
                "1234567890abcdef1234567890abcdef12345678\n",
            )
            .unwrap();
        }
    }
    // The damaged clone attests and exchanges, twice round.
    ss.put("src/s.test.ts", S1, &hex64(9), b"s").unwrap();
    for i in 0..2 {
        match ss.push(Some("origin")) {
            Ok(o) => eprintln!("{d:?} push {i}: {o:?}"),
            Err(e) => problems.push(format!("{d:?}: push {i} failed: {e}")),
        }
        match ss.fetch(Some("origin")) {
            Ok(o) => eprintln!("{d:?} fetch {i}: {o:?}"),
            Err(e) => problems.push(format!("{d:?}: fetch {i} failed: {e}")),
        }
    }
    let r = remote_keys(&w);
    for k in [2u8, 3] {
        if !r.contains(&hex64(k)) {
            problems.push(format!("{d:?}: remote lost {}", hex64(k)));
        }
    }
    if r.contains(&hex64(1)) {
        problems.push(format!(
            "{d:?}: a1, deleted with its record on the tip, was published again"
        ));
    }
    if !r.contains(&hex64(9)) {
        problems.push(format!(
            "{d:?}: the damaged clone's own attestation was never published"
        ));
    }
    // The other clone still converges.
    if let Err(e) = sa.push(Some("origin")) {
        problems.push(format!("{d:?}: the other clone's push failed: {e}"));
    }
    problems
}

#[test]
fn a_damaged_tracking_or_local_ref_across_a_rewrite() {
    let mut problems = Vec::new();
    for d in [
        Damage::TrackingMissing,
        Damage::TrackingAndMarkerMissing,
        Damage::TrackingNamesAMissingCommit,
        Damage::TrackingNamesARemoteCommitNotHere,
        Damage::LocalNamesAMissingCommit,
    ] {
        problems.extend(damaged(d));
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn a_local_ref_naming_a_missing_commit_does_not_stick_the_clone() {
    let w = world(2);
    let (ra, rs) = (repo(&w.clones[0]), repo(&w.clones[1]));
    let (sa, ss) = (AttestStore::new(&ra), AttestStore::new(&rs));
    sa.put("src/a.test.ts", S1, &hex64(1), b"a1").unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    ss.fetch(Some("origin")).unwrap();
    ss.put("src/s.test.ts", S1, &hex64(2), b"s").unwrap();
    assert_eq!(ss.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    let dir = &w.clones[1];
    git(dir, &["update-ref", "-d", "refs/meta/local/main"]);
    std::fs::create_dir_all(dir.join(".git/refs/meta/local")).unwrap();
    std::fs::write(
        dir.join(".git/refs/meta/local/main"),
        "1234567890abcdef1234567890abcdef12345678\n",
    )
    .unwrap();
    ss.put("src/t.test.ts", S1, &hex64(3), b"t").unwrap();
    let mut errs = Vec::new();
    let mut warned = false;
    for i in 0..3 {
        match ss.fetch(Some("origin")) {
            Ok(o) => warned |= o.warnings.iter().any(|w| w.contains("1234567890abcdef")),
            Err(e) => errs.push(format!("fetch {i}: {e}")),
        }
        if let Err(e) = ss.push(Some("origin")) {
            errs.push(format!("push {i}: {e}"));
        }
    }
    assert!(errs.is_empty(), "{errs:#?}");
    assert!(warned, "no warning named the missing commit");
    // Everything the store held is on the remote, t too.
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
    for k in [1u8, 2, 3] {
        assert!(
            paths
                .lines()
                .any(|p| p.contains(&hex64(k)) && p.ends_with("/__value")),
            "{} is not on the remote:\n{paths}",
            hex64(k)
        );
    }
}
