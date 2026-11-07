//! `vci prune` (2.10's rules) on the same hand-made records in a git-meta
//! store, a SQLite store and libSQL's local file: the dry run and the run
//! list the same removals on every backend, and the run the same as its
//! dry run; the removals are the ones `decide`'s rules name.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::{Command, Output};

use assert_cmd::cargo::CommandCargoExt;
use base64::Engine as _;
use serde_json::json;
use vci_git::{GitMetaStore, Repo};
use vci_store::{AttestationStore, Columns, KeyHint, NewAttestation};
use vci_store_sqlite::{SqliteOptions, SqliteStore};

const DAY: i64 = 86_400;
const SIGNER: &str = "2222222222222222";

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn rfc(t: i64) -> String {
    jiff::Timestamp::from_second(t)
        .unwrap()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn statement_m(
    unit: &str,
    issued: i64,
    expires: i64,
    tree: Option<&str>,
    mref: Option<&str>,
) -> Vec<u8> {
    let mut p = json!({
        "testId": unit,
        "issuedAt": rfc(issued),
        "expiresAt": rfc(expires),
        "commit": "c".repeat(40),
        "toolchain": {"os": "linux", "arch": "x86_64"},
        "result": {"state": "passed", "tests": 1, "failed": 0, "skipped": 0, "durationMs": 7},
    });
    if let Some(t) = tree {
        p["tree"] = json!(t);
    }
    if let Some(m) = mref {
        p["manifestRef"] = json!(m);
    }
    serde_json::to_vec(&json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": unit, "digest": {"blake3": "0".repeat(64)}}],
        "predicateType": vci_core::PREDICATE_TYPE,
        "predicate": p,
    }))
    .unwrap()
}

fn format1(st: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "payloadType": vci_attest::PAYLOAD_TYPE,
        "payload": base64::engine::general_purpose::STANDARD.encode(st),
        "signatures": [{"keyid": "", "sig": "AA=="}],
    }))
    .unwrap()
}

fn format3(st: &[u8]) -> Vec<u8> {
    vci_core::Frame {
        statement: st.to_vec(),
        keyid: "SHA256:test".into(),
        sig: vci_core::FrameSig::SshSig(vec![1, 2, 3]),
        descriptor: vec![0; 33],
    }
    .encode()
    .unwrap()
    .into_bytes()
}

/// One record of the script: label, unit, issued (days ago), expires (days
/// from now), on the live tree, format.
struct Rec {
    label: &'static str,
    unit: &'static str,
    issued_days_ago: f64,
    expires_in_days: i64,
    live: bool,
    format: u8,
}

const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";

fn script() -> Vec<Rec> {
    let r = |label, unit, issued_days_ago, expires_in_days, live, format| Rec {
        label,
        unit,
        issued_days_ago,
        expires_in_days,
        live,
        format,
    };
    vec![
        // a: format-1 rule, keep, live trees, age.
        r("a1-f3-1d", A, 1.0, 30, false, 3),
        r("a2-f3-3d-live", A, 3.0, 30, true, 3),
        r("a3-f3-5d", A, 5.0, 30, false, 3),
        r("a4-f3-6d-live", A, 6.0, 30, true, 3),
        r("a5-f3-20d-live", A, 20.0, 30, true, 3),
        r("a6-f1-2d", A, 2.0, 30, false, 1),
        r("a7-f1-0.5d", A, 0.5, 30, false, 1),
        // A format-1 record on a live tree within max_age_days stays (2.10).
        r("a8-f1-1.5d-live", A, 1.5, 30, true, 1),
        // b: the plan memo keeps an old format-1 record; one expired.
        r("b1-f3-1d", B, 1.0, 30, false, 3),
        r("b2-f1-2d-used", B, 2.0, 30, false, 1),
        r("b3-f3-40d-expired", B, 40.0, -1, false, 3),
        r("b4-f1-3d", B, 3.0, 30, false, 1),
        // On a live tree, but past max_age_days: the format rule removes it.
        r("b5-f1-18d-live", B, 18.0, 30, true, 1),
        // c: format 3 only (SQL: the key hints' path).
        r("c1-f3-1d", C, 1.0, 30, false, 3),
        r("c2-f3-20d", C, 20.0, 30, false, 3),
        r("c3-f3-2d", C, 2.0, 30, false, 3),
        r("c4-f3-4d", C, 4.0, 30, false, 3),
        r("c5-f3-16d-live", C, 16.0, 30, true, 3),
    ]
}

struct World {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
    live_tree: String,
    head_tree: String,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    git(&root, &["init", "-q"]);
    std::fs::write(root.join("a.txt"), "alpha\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "initial"]);
    git(&root, &["checkout", "-q", "-b", "live"]);
    std::fs::write(root.join("a.txt"), "live\n").unwrap();
    git(&root, &["commit", "-qam", "live"]);
    let live_tree = git(&root, &["rev-parse", "HEAD^{tree}"]);
    git(&root, &["checkout", "-q", "main"]);
    let head_tree = git(&root, &["rev-parse", "HEAD^{tree}"]);
    World {
        _tmp: tmp,
        root,
        live_tree,
        head_tree,
    }
}

/// Put the script into `store`; label -> key.
fn fill(store: &dyn AttestationStore, w: &World, now: i64) -> BTreeMap<String, String> {
    fill_m(store, w, now, false)
}

fn manifest(tag: &str) -> (String, Vec<u8>) {
    let m = vci_store::conformance::scenarios::manifest_of(&[&format!("src/{tag}.rs")]);
    (m.root(), m.to_compact().into_bytes())
}

fn fill_m(
    store: &dyn AttestationStore,
    w: &World,
    now: i64,
    manifests: bool,
) -> BTreeMap<String, String> {
    let mut keys = BTreeMap::new();
    if manifests {
        for tag in ["m-b2-used", "m-b4", "m-orphan", "m-a6"] {
            let (root, bytes) = manifest(tag);
            store.put_manifest(&root, &bytes).unwrap();
            keys.insert(tag.to_owned(), format!("vci:manifest:{root}"));
        }
    }
    for (i, r) in script().iter().enumerate() {
        let issued = now - (r.issued_days_ago * DAY as f64) as i64;
        let expires = now + r.expires_in_days * DAY;
        let tree = r.live.then_some(w.live_tree.as_str());
        let mref = match (manifests, r.label) {
            (true, "b2-f1-2d-used") => Some(manifest("m-b2-used").0),
            (true, "b4-f1-3d") => Some(manifest("m-b4").0),
            (true, "a6-f1-2d") => Some(manifest("m-a6").0),
            _ => None,
        };
        let st = statement_m(r.unit, issued, expires, tree, mref.as_deref());
        let value = if r.format == 1 {
            format1(&st)
        } else {
            format3(&st)
        };
        let hint = KeyHint {
            issued,
            tree: tree.map(|t| t[..16].to_owned()),
        };
        let sk = format!("{:02x}", i + 1).repeat(32);
        let columns = Columns {
            format: Some(3),
            expires: Some(expires),
            ..Columns::default()
        };
        let att = NewAttestation::for_test(r.unit, SIGNER, &sk, Some(&hint), &value);
        let att = if r.format == 3 {
            att.with_columns(&columns)
        } else {
            att
        };
        let key = store.put(&att).unwrap().key;
        keys.insert(r.label.to_owned(), key);
    }
    // The plan of the checked-out commit used b's old format-1 record.
    let head16: String = w.head_tree.chars().take(16).collect();
    store.remember_passing(
        &head16,
        &[(vci_store::key::test_key(B), keys["b2-f1-2d-used"].clone())],
    );
    keys
}

fn vci(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    // `VCI_E2E_BIN` runs another vci binary (a build from before a fix).
    let mut cmd = match std::env::var_os("VCI_E2E_BIN") {
        Some(b) => Command::new(b),
        None => Command::cargo_bin("vci").unwrap(),
    };
    cmd.current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("NO_COLOR", "1");
    for k in vci_store::select::ENV_VARS {
        cmd.env_remove(k);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    eprintln!(
        "$ vci {} {env:?} -> {:?}\n{}{}",
        args.join(" "),
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// The attestation removals a prune printed, as (label, note), and its
/// "attestations by rule" line.
fn removals(out: &Output, keys: &BTreeMap<String, String>) -> (BTreeSet<(String, String)>, String) {
    let by_key: BTreeMap<&str, &str> = keys.iter().map(|(l, k)| (k.as_str(), l.as_str())).collect();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut set = BTreeSet::new();
    for line in stdout.lines() {
        let rest = line
            .strip_prefix("would remove ")
            .or_else(|| line.strip_prefix("removed "))
            .unwrap_or_else(|| panic!("{line}"));
        let mut parts = rest.splitn(3, ' ');
        let _target = parts.next().unwrap();
        let key = parts.next().unwrap();
        let note = parts.next().unwrap_or("").to_owned();
        let label = by_key
            .get(key)
            .map(|l| l.to_string())
            .unwrap_or_else(|| key.to_owned());
        set.insert((label, note));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let rule = stderr
        .lines()
        .find(|l| l.starts_with("vci prune: attestations by rule"))
        .unwrap_or("")
        .replace(" (dry run)", "");
    (set, rule)
}

/// Every backend removes the same records, by the same rule, in the dry run
/// and the run.
#[test]
fn prune_is_the_same_on_git_meta_sqlite_and_libsql_and_dry_runs_match() {
    let now = jiff::Timestamp::now().as_second();
    let gm_world = world();
    let sq_world = world();
    let gm = GitMetaStore::new(
        Repo::discover(camino::Utf8Path::from_path(&gm_world.root).unwrap()).unwrap(),
    );
    let gm_keys = fill(&gm, &gm_world, now);
    drop(gm);
    let sq_path = sq_world.root.join(".git/vci-store.sqlite");
    let sq = SqliteStore::open_path(&sq_path, SqliteOptions::default());
    // The live tree of the SQLite world differs from git-meta's world only
    // by its id; each world's records name its own.
    let sq_keys = fill(&sq, &sq_world, now);
    drop(sq);
    let sqlite = [("VCI_STORE", "sqlite")];
    // libSQL's local file.
    let lq_world = world();
    let lq_git = lq_world.root.join(".git");
    let lq_path = lq_git.join("vci-store.libsql");
    let sel = vci_store_libsql::testkit::selection(
        vci_store::select::LibsqlMode::Local,
        None,
        None,
        None,
        Some(&lq_path),
    );
    let mut cx = vci_store_libsql::testkit::cx_in(&lq_git, false);
    let first = git(&lq_world.root, &["rev-list", "--max-parents=0", "HEAD"]);
    cx.repo_id = std::sync::Arc::new(move || Ok(first.clone()));
    cx.repo_root = lq_world.root.clone();
    let lq = vci_store_libsql::LibsqlStore::open(&sel, &cx).expect("open libsql");
    let lq_keys = fill(&lq, &lq_world, now);
    drop(lq);
    let libsql = [("VCI_STORE", "libsql")];
    let lq_dry = vci(&lq_world.root, &["prune", "--dry-run"], &libsql);
    assert!(lq_dry.status.success());
    let lq_run = vci(&lq_world.root, &["prune"], &libsql);
    assert!(lq_run.status.success());
    let (lq_d, lq_rule_d) = removals(&lq_dry, &lq_keys);
    let (lq_r, lq_rule_r) = removals(&lq_run, &lq_keys);

    let gm_dry = vci(&gm_world.root, &["prune", "--dry-run"], &[]);
    assert!(gm_dry.status.success());
    let sq_dry = vci(&sq_world.root, &["prune", "--dry-run"], &sqlite);
    assert!(sq_dry.status.success());
    let (gm_d, gm_rule_d) = removals(&gm_dry, &gm_keys);
    let (sq_d, sq_rule_d) = removals(&sq_dry, &sq_keys);
    eprintln!("git-meta dry: {gm_d:#?}\n{gm_rule_d}\nsqlite dry: {sq_d:#?}\n{sq_rule_d}");

    let gm_run = vci(&gm_world.root, &["prune"], &[]);
    assert!(gm_run.status.success());
    let sq_run = vci(&sq_world.root, &["prune"], &sqlite);
    assert!(sq_run.status.success());
    let (gm_r, gm_rule_r) = removals(&gm_run, &gm_keys);
    let (sq_r, sq_rule_r) = removals(&sq_run, &sq_keys);

    // What the rules say (decide's doc): a7 is ranked (newer than the
    // newest format 3) and is the newest; a6 format 1 older; a8 format 1
    // older, but live within the age (2.10: kept, and not counted towards
    // keep); a5 aged though live; a3 beyond keep; a2/a4 live within the
    // age; b2 used; b4 format 1; b5 format 1, live but aged; b3 expired; c2
    // aged; c4 beyond keep; c5 aged though live.
    let want: BTreeSet<(String, String)> = [
        ("a3-f3-5d", " (superseded)"),
        ("a5-f3-20d-live", " (older than max_age_days)"),
        (
            "a6-f1-2d",
            " (format 1, older than its unit's newest format-3 attestation)",
        ),
        ("b3-f3-40d-expired", ""),
        (
            "b4-f1-3d",
            " (format 1, older than its unit's newest format-3 attestation)",
        ),
        (
            "b5-f1-18d-live",
            " (format 1, older than its unit's newest format-3 attestation)",
        ),
        ("c2-f3-20d", " (older than max_age_days)"),
        ("c4-f3-4d", " (superseded)"),
        ("c5-f3-16d-live", " (older than max_age_days)"),
    ]
    .into_iter()
    .map(|(l, n)| (l.to_owned(), n.trim().to_owned()))
    .collect();
    let mut problems = Vec::new();
    for (name, got) in [
        ("git-meta dry run", &gm_d),
        ("sqlite dry run", &sq_d),
        ("git-meta run", &gm_r),
        ("sqlite run", &sq_r),
        ("libsql dry run", &lq_d),
        ("libsql run", &lq_r),
    ] {
        if got != &want {
            problems.push(format!("{name}: got {got:#?}"));
        }
    }
    if gm_rule_d != sq_rule_d
        || gm_rule_d != gm_rule_r
        || sq_rule_d != sq_rule_r
        || lq_rule_d != gm_rule_d
        || lq_rule_r != gm_rule_d
    {
        problems.push(format!(
            "rule lines differ:\n{gm_rule_d}\n{sq_rule_d}\n{gm_rule_r}\n{sq_rule_r}"
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The same with stored manifests (on SQL stores the migration window:
/// every row read), referenced by format-1 records.
#[test]
fn prune_is_the_same_in_the_manifest_window() {
    let now = jiff::Timestamp::now().as_second();
    let gm_world = world();
    let sq_world = world();
    let gm = GitMetaStore::new(
        Repo::discover(camino::Utf8Path::from_path(&gm_world.root).unwrap()).unwrap(),
    );
    let gm_keys = fill_m(&gm, &gm_world, now, true);
    drop(gm);
    let sq = SqliteStore::open_path(
        sq_world.root.join(".git/vci-store.sqlite"),
        SqliteOptions::default(),
    );
    let sq_keys = fill_m(&sq, &sq_world, now, true);
    drop(sq);
    let sqlite = [("VCI_STORE", "sqlite")];
    let gm_dry = vci(&gm_world.root, &["prune", "--dry-run"], &[]);
    let sq_dry = vci(&sq_world.root, &["prune", "--dry-run"], &sqlite);
    let gm_run = vci(&gm_world.root, &["prune"], &[]);
    let sq_run = vci(&sq_world.root, &["prune"], &sqlite);
    let (gm_d, _) = removals(&gm_dry, &gm_keys);
    let (sq_d, _) = removals(&sq_dry, &sq_keys);
    let (gm_r, _) = removals(&gm_run, &gm_keys);
    let (sq_r, _) = removals(&sq_run, &sq_keys);
    eprintln!("git-meta dry run: {gm_d:#?}");
    assert_eq!(gm_d, sq_d, "dry runs");
    assert_eq!(gm_d, gm_r, "git-meta dry run and run");
    assert_eq!(sq_d, sq_r, "sqlite dry run and run");
    let manifests: BTreeSet<&str> = gm_d
        .iter()
        .filter(|(_, n)| n.contains("manifest"))
        .map(|(l, _)| l.as_str())
        .collect();
    assert_eq!(
        manifests,
        ["m-a6", "m-b4", "m-orphan"].into_iter().collect(),
        "{gm_d:#?}"
    );
}
