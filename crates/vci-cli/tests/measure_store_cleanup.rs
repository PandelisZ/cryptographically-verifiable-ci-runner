//! A measurement, not a test (ignored): what the cleanup a push does (2.11:
//! expired attestations, unreferenced objects and run links, all decided
//! from keys) costs on a store shaped like vex's of 14 November 2026, and
//! what it removes, from a fresh lazy clone (the clone a CI job pushes
//! from). Run with
//!
//! ```text
//! cargo test -p vci-cli --test measure_store_cleanup -- --ignored --nocapture
//! ```
//!
//! The store: 33,800 attestations (8,450 units, 4 each) from 1,032 runs
//! that each wrote 13 hdr objects, a tables, a shape and a state object
//! (16,512 objects the records name), plus 43,488 objects no record names
//! (vex: 40,753), all of them under the runs of 2,718 earlier runs none of
//! whose records remain; 1,032 run-state links. Values are filler of
//! realistic size (a record 600 bytes, an hdr 1,500, a state object 8,000).
//! Two shapes: `linked`, as runs of vci 2.11 write it (a run-object link
//! per run and object), and `legacy`, as vex's store is today (no
//! run-object links: the records may name any object, and their values
//! are not here, so no hdr, tables or shape object goes).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use assert_cmd::cargo::CommandCargoExt;
use vci_core::ObjectKind;
use vci_git::{AttestStore, KeyHint, Repo};

const UNITS: usize = 8_450;
const PER_UNIT: usize = 4;
const RUNS: usize = 1_032;
const DEAD_RUNS: usize = 2_718;
const HDRS_PER_RUN: usize = 13;
const SIGNER: &str = "4d42727252e0e45f";

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn hex(seed: &str) -> String {
    vci_core::test_key(seed)
}

fn filler(seed: &str, len: usize) -> String {
    let mut s = String::with_capacity(len);
    let mut i = 0;
    while s.len() < len {
        s.push_str(&hex(&format!("{seed}:{i}")));
        i += 1;
    }
    s.truncate(len);
    s
}

/// The seed repository with the synthetic store, pushed to `remote`.
fn build(base: &Path, remote: &Path, linked: bool) {
    let seed = base.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q", "-b", "main"]);
    std::fs::write(seed.join("README.md"), "seed\n").unwrap();
    git(&seed, &["add", "-A"]);
    git(&seed, &["commit", "-qm", "seed"]);
    git(
        &seed,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git(&seed, &["push", "-q", "origin", "main"]);
    let repo = Repo::discover(camino::Utf8Path::from_path(&seed).unwrap()).unwrap();
    let st = AttestStore::new(&repo);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let hint = |run: usize, dead: bool| KeyHint {
        // Live runs over the last 10 days, dead ones over the 10 before.
        issued: now
            - if dead { 10 * 86_400 } else { 0 }
            - 3_600
            - (run as i64 * 811) % (10 * 86_400),
        tree: Some(hex(&format!("tree{run}:{dead}"))[..16].to_owned()),
    };
    let t = Instant::now();
    let guard = st.batch().unwrap();
    let mut objects: Vec<(ObjectKind, String, String)> = Vec::new();
    let mut links: Vec<String> = Vec::new();
    let mut run_states: Vec<(String, String)> = Vec::new();
    for (dead, runs) in [(false, RUNS), (true, DEAD_RUNS)] {
        for run in 0..runs {
            let h = hint(run, dead);
            let mut objs: Vec<(ObjectKind, String, usize)> = (0..HDRS_PER_RUN)
                .map(|i| (ObjectKind::Hdr, hex(&format!("hdr{run}:{dead}:{i}")), 1_500))
                .collect();
            // The dead runs wrote hdr objects only (16 per run, so that the
            // objects nothing names are about vex's 40,753).
            if dead {
                objs.extend(
                    (HDRS_PER_RUN..16)
                        .map(|i| (ObjectKind::Hdr, hex(&format!("hdr{run}:{dead}:{i}")), 1_500)),
                );
            } else {
                objs.push((ObjectKind::Tables, hex(&format!("tables{run}")), 500));
                objs.push((ObjectKind::Shape, hex(&format!("shape{run}")), 2_000));
                let state = hex(&format!("state{run}"));
                objs.push((ObjectKind::State, state.clone(), 8_000));
                run_states.push((
                    vci_store::run_state_key(&hex(&format!("shape{run}")), &h, &state),
                    state,
                ));
            }
            for (kind, id, size) in objs {
                if linked {
                    links.push(vci_store::run_object_key(&h, SIGNER, kind, &id));
                }
                objects.push((kind, id.clone(), filler(&id, size)));
            }
        }
    }
    st.put_objects(&objects).unwrap();
    st.put_run_object_links(&links).unwrap();
    st.put_run_state_links(&run_states).unwrap();
    for u in 0..UNITS {
        let test_id = format!("packages/p{}/test/unit{u}.test.ts", u % 40);
        for k in 0..PER_UNIT {
            let run = (u * PER_UNIT + k) % RUNS;
            let sk = hex(&format!("sk{u}:{k}"));
            st.put_hinted(
                &test_id,
                SIGNER,
                &sk,
                Some(&hint(run, false)),
                filler(&sk, 600).as_bytes(),
            )
            .unwrap();
        }
    }
    guard.finish().unwrap();
    eprintln!(
        "built the store ({} objects, {} run-object links, {} attestations) in {:.1}s",
        objects.len(),
        links.len(),
        UNITS * PER_UNIT,
        t.elapsed().as_secs_f64()
    );
    let t = Instant::now();
    st.push(Some("origin")).unwrap();
    eprintln!("pushed it in {:.1}s", t.elapsed().as_secs_f64());
}

fn vci(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> (f64, String) {
    let mut cmd = Command::cargo_bin("vci").unwrap();
    cmd.current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("VCI_TIMING", "1");
    for k in vci_store::select::ENV_VARS {
        cmd.env_remove(k);
    }
    cmd.env_remove("CI");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let t = Instant::now();
    let out = cmd.output().unwrap();
    let secs = t.elapsed().as_secs_f64();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "vci {args:?}: {err}");
    (secs, err)
}

fn lazy_clone(base: &Path, remote: &Path, name: &str) -> PathBuf {
    git(
        base,
        &["clone", "-q", "--no-local", remote.to_str().unwrap(), name],
    );
    let dir = base.join(name);
    let (secs, _) = vci(&dir, &["fetch", "--remote", "origin"], &[]);
    eprintln!("{name}: vci fetch {secs:.1}s");
    dir
}

fn lines<'a>(err: &'a str, what: &[&str]) -> Vec<&'a str> {
    err.lines()
        .filter(|l| what.iter().any(|w| l.contains(w)))
        .collect()
}

fn measure(linked: bool) {
    let shape = if linked { "linked" } else { "legacy" };
    // `VCI_MEASURE_DIR`: build the store there once and keep it (each run
    // then measures fresh clones of it).
    let tmp = tempfile::tempdir().unwrap();
    let base = match std::env::var_os("VCI_MEASURE_DIR") {
        Some(d) => {
            let d = PathBuf::from(d).join(shape);
            std::fs::create_dir_all(&d).unwrap();
            d.canonicalize().unwrap()
        }
        None => tmp.path().canonicalize().unwrap(),
    };
    let remote = base.join("remote.git");
    if !remote.exists() {
        git(&base, &["init", "-q", "--bare", "remote.git"]);
        git(&remote, &["config", "uploadpack.allowFilter", "true"]);
        git(
            &remote,
            &["config", "uploadpack.allowAnySHA1InWant", "true"],
        );
        build(&base, &remote, linked);
        // A copy of the remote as built, so that later runs start from it.
        git(
            &base,
            &["clone", "-q", "--mirror", "remote.git", "pristine.git"],
        );
    } else {
        std::fs::remove_dir_all(&remote).unwrap();
        git(
            &base,
            &["clone", "-q", "--mirror", "pristine.git", "remote.git"],
        );
        git(&remote, &["config", "uploadpack.allowFilter", "true"]);
        git(
            &remote,
            &["config", "uploadpack.allowAnySHA1InWant", "true"],
        );
        for d in ["off", "on", "next"] {
            let _ = std::fs::remove_dir_all(base.join(d));
        }
    }
    // The same push with the cleanup off, then on, from two fresh clones.
    let off = lazy_clone(&base, &remote, "off");
    let (secs_off, _) = vci(
        &off,
        &["push", "--remote", "origin"],
        &[("VCI_STORE_AUTO_PRUNE", "0")],
    );
    let on = lazy_clone(&base, &remote, "on");
    let (secs_on, err) = vci(&on, &["push", "--remote", "origin"], &[]);
    eprintln!("[{shape}] push without the cleanup: {secs_off:.2}s; with it: {secs_on:.2}s");
    for l in lines(
        &err,
        &[
            "vci: removed",
            "vci: note: kept",
            "before the push:",
            "collect objects:",
            "push: ",
            "pushed",
        ],
    ) {
        eprintln!("[{shape}]   {l}");
    }
    // Steady state: the next job's push, nothing left to remove.
    let next = lazy_clone(&base, &remote, "next");
    let (secs_next, err) = vci(&next, &["push", "--remote", "origin"], &[]);
    eprintln!("[{shape}] the next clone's push: {secs_next:.2}s");
    for l in lines(
        &err,
        &["vci: removed", "vci: note: kept", "before the push:"],
    ) {
        eprintln!("[{shape}]   {l}");
    }
    let objects = git(
        &remote,
        &[
            "ls-tree",
            "-r",
            "--name-only",
            "--full-tree",
            "refs/meta/main",
        ],
    )
    .lines()
    .filter(|l| l.starts_with("project/vci/object/"))
    .count();
    eprintln!("[{shape}] objects on the remote after: {objects}");
}

#[test]
#[ignore = "a measurement: builds a store of about 100,000 keys"]
fn cleanup_on_a_store_shaped_like_vex() {
    let only = std::env::var("VCI_MEASURE_SHAPE").unwrap_or_default();
    if only != "legacy" {
        measure(true);
    }
    if only != "linked" {
        measure(false);
    }
}
