//! `vci run` writing store format 3 (STORE-V2 section 1.4, the M3 row of
//! section 6) on a SQLite file: every unit's record is the text frame of
//! section 1.2 whose statement is a v2 predicate naming the run's hdr and
//! tables objects, its listing columns are copied from that statement, the
//! run's four objects are stored before it and decode to their ids, no
//! input manifest is written, and the plan skips every unit from the
//! frames; supersession removes the record a later run on the branch
//! supersedes, deciding from the old record's signed statement; `[store]
//! explain_hashes = false` leaves the state object out; and
//! `record_format = 1` writes exactly what 2.8 wrote (envelope JSON with
//! its manifests and no columns).
//!
//! A copy of `fixtures/go-abcd` in a throwaway git repository. Needs `go`,
//! `git` and `ssh-keygen` on PATH; every test prints `SKIPPED:` and returns
//! early when `go` is not installed or cannot download the fixture's
//! modules.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use assert_cmd::cargo::CommandCargoExt;
use serde_json::Value;
use vci_attest::{Envelope, Statement};
use vci_core::{Hdr, PREDICATE_TYPE_V2, Shape, VciPredicateV2, object_id, objects::hex32};
use vci_store::{AttestationStore, Columns, Record, decode_record};
use vci_store_sqlite::{SqliteOptions, SqliteStore};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_owned()
}

fn go_available() -> bool {
    match Command::new("go").arg("version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!("SKIPPED: `go` is not installed; this test needs the Go toolchain on PATH");
            false
        }
    }
}

const VCI_TOML: &str = r#"project = "."
adapter = "go"

[policy]
platform = "any"
max_ttl = "30d"
"#;

/// Variables removed from every `vci` and `go` invocation so the host
/// environment cannot change the outcome (the store's own are added from
/// [`vci_store::select::ENV_VARS`]).
const SCRUB: &[&str] = &[
    "VCI_E2E_BIN",
    "VCI_BASE_REF",
    "GITHUB_BASE_REF",
    "GITHUB_REF",
    "GITHUB_OUTPUT",
    "GITHUB_ACTIONS",
    "VCI_SIGNING_KEY",
    "VCI_GO",
    "VCI_JOBS",
    "VCI_GO_TESTLOG",
    "VCI_TIMING",
    "GOFLAGS",
    "GOWORK",
    "GOOS",
    "GOARCH",
    "CGO_ENABLED",
    "GOEXPERIMENT",
    "GODEBUG",
    "GOTOOLCHAIN",
    "CI",
    "GOMAXPROCS",
];

/// The fixture's packages; a run attests every one of them.
const UNITS: &[&str] = &["a", "b", "c", "d"];

struct World {
    _tmp: tempfile::TempDir,
    work: PathBuf,
    key: PathBuf,
    gitconfig: PathBuf,
}

fn keygen(path: &Path) {
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "trusted", "-f"])
        .arg(path)
        .status()
        .unwrap();
    assert!(st.success());
}

fn pubkey(path: &Path) -> String {
    let t = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    t.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The keys of `vci: attested <unit> (…) as sqlite <target> <key>` lines,
/// by unit.
fn attested_keys(out: &Output) -> BTreeMap<String, String> {
    let mut keys = BTreeMap::new();
    for line in stderr(out).lines() {
        let Some(rest) = line.strip_prefix("vci: attested ") else {
            continue;
        };
        let unit = rest.split_whitespace().next().unwrap().to_owned();
        let (_, tail) = rest
            .split_once(") as sqlite ")
            .unwrap_or_else(|| panic!("attested as sqlite: {line}"));
        let key = tail.split_whitespace().nth(1).unwrap().to_owned();
        keys.insert(unit, key);
    }
    keys
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| (*s).to_owned()).collect()
}

impl World {
    /// `None` (test skipped) when go is unavailable.
    fn new() -> Option<Self> {
        if !go_available() {
            return None;
        }
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let gitconfig = base.join("gitconfig");
        std::fs::write(
            &gitconfig,
            "[user]\n\tname = Test\n\temail = test@example.com\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n",
        )
        .unwrap();
        let w = World {
            work: base.join("work"),
            key: base.join("trusted"),
            gitconfig,
            _tmp: tmp,
        };
        keygen(&w.key);
        w.git(&base, &["init", "-q", "--bare", "remote.git"]);
        w.git(&base, &["init", "-q", w.work.to_str().unwrap()]);
        let fx = workspace_root().join("fixtures/go-abcd");
        for name in ["go.mod", "go.sum", "a", "b", "c", "d", "internal"] {
            let st = Command::new("cp")
                .arg("-R")
                .arg(fx.join(name))
                .arg(w.work.join(name))
                .status()
                .unwrap();
            assert!(st.success());
        }
        w.put(".gitignore", ".vci/out/\n");
        w.put("vci.toml", VCI_TOML);
        w.put(
            ".vci/allowed_signers",
            &format!(
                "trusted@example.com namespaces=\"vci-attest\" {}\n",
                pubkey(&w.key)
            ),
        );
        w.git(&w.work, &["add", "-A"]);
        w.git(&w.work, &["commit", "-q", "-m", "base commit"]);
        let remote = base.join("remote.git");
        w.git(
            &w.work,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        w.git(&w.work, &["push", "-q", "origin", "main"]);
        w.git(&w.work, &["checkout", "-q", "-b", "feature"]);
        let mut cmd = Command::new("go");
        cmd.args(["mod", "download"]).current_dir(&w.work);
        for k in SCRUB.iter().chain(vci_store::select::ENV_VARS) {
            cmd.env_remove(k);
        }
        let out = cmd.output().unwrap();
        if !out.status.success() {
            eprintln!(
                "SKIPPED: `go mod download` failed for the Go fixture (offline without a module cache?): {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return None;
        }
        Some(w)
    }

    fn put(&self, rel: &str, content: &str) {
        let p = self.work.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn git(&self, dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// Append a comment to `rel` and commit (its tests still pass; its
    /// inputs change).
    fn edit_and_commit(&self, rel: &str, note: &str) {
        let src = std::fs::read_to_string(self.work.join(rel)).unwrap();
        self.put(rel, &format!("{src}\n// {note}\n"));
        self.git(&self.work, &["add", "-A"]);
        self.git(&self.work, &["commit", "-q", "-m", note]);
    }

    /// `vci <args>` in the repository on the SQLite store at its default
    /// path, with `env` added to a scrubbed environment.
    fn vci(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::cargo_bin("vci").unwrap();
        cmd.current_dir(&self.work)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("NO_COLOR", "1");
        for k in SCRUB.iter().chain(vci_store::select::ENV_VARS) {
            cmd.env_remove(k);
        }
        cmd.env("VCI_STORE", "sqlite");
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

    /// `vci run --key` of `units` (every unit when empty); it must exit 0.
    fn run(&self, units: &[&str], env: &[(&str, &str)]) -> Output {
        let key = self.key.to_str().unwrap().to_owned();
        let mut args = vec!["run"];
        args.extend_from_slice(units);
        args.extend(["--key", &key]);
        let out = self.vci(&args, env);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        out
    }

    /// The units `vci plan --base-ref main` skips.
    fn skipped(&self) -> BTreeSet<String> {
        let out = self.vci(&["plan", "--base-ref", "main", "--format", "json"], &[]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        v["files"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["skip"].as_bool().unwrap())
            .map(|f| f["testId"].as_str().unwrap().to_owned())
            .collect()
    }

    fn head(&self) -> String {
        self.git(&self.work, &["rev-parse", "HEAD"])
    }

    fn store(&self) -> SqliteStore {
        SqliteStore::open_path(
            self.work.join(".git/vci-store.sqlite"),
            SqliteOptions::default(),
        )
    }
}

/// A stored record as a frame: its statement (parsed) and the v2 predicate
/// it carries.
fn frame_of(e: &vci_store::StoredEnvelope) -> (vci_core::Frame, Statement, VciPredicateV2) {
    let Ok(Record::FormatThree(frame)) = decode_record(&e.bytes) else {
        panic!(
            "{} is not a format-3 frame: {:?}",
            e.key,
            String::from_utf8_lossy(&e.bytes[..e.bytes.len().min(60)])
        );
    };
    let stmt: Statement = serde_json::from_slice(&frame.statement).unwrap();
    assert_eq!(stmt.predicate_type, PREDICATE_TYPE_V2, "{}", e.key);
    let p: VciPredicateV2 = serde_json::from_value(stmt.predicate.clone()).unwrap();
    (frame, stmt, p)
}

/// Every unit's record is a frame whose statement names the run's hdr and
/// tables, with columns copied from it and the four objects stored; no
/// manifest is written; the plan skips every unit; a later run on the
/// branch supersedes the record of the unit it attests again, from the old
/// record's signed statement.
#[test]
fn run_writes_frames_their_columns_and_the_runs_objects_on_sqlite() {
    let Some(w) = World::new() else { return };
    let out = w.run(&[], &[("VCI_TIMING", "1")]);
    let keys = attested_keys(&out);
    assert_eq!(keys.len(), UNITS.len(), "{}", text(&out));
    let err = stderr(&out);
    assert!(
        err.contains(
            "format-3 run: 1 hdr, 1 tables, 1 shape, 1 state object(s) over 4 unit(s); objects "
        ) && err.contains(" bytes put, records ")
            && err.contains(" bytes stored, 1 batch(es)"),
        "the metrics line: {err}"
    );
    let head = w.head();
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);

    let s = w.store();
    assert!(s.caps().objects && s.caps().columns);
    assert!(
        s.manifest_roots().unwrap().is_empty(),
        "a format-3 run writes no input manifest"
    );
    let all = s.read_all().unwrap();
    assert_eq!(all.len(), UNITS.len());
    let columns = s.columns(&all.iter().collect::<Vec<_>>()).unwrap();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    let mut hdrs: BTreeSet<String> = BTreeSet::new();
    let mut shapes: BTreeSet<String> = BTreeSet::new();
    for (e, c) in all.iter().zip(&columns) {
        let (frame, stmt, p) = frame_of(e);
        assert_eq!(p.commit, head);
        assert_eq!(stmt.subject[0].name, p.test_id);
        assert!(UNITS.contains(&p.test_id.as_str()), "{}", p.test_id);
        assert_eq!(p.result.state, "passed");
        assert_eq!(
            frame.statement,
            vci_core::sorted_compact_json(&stmt).unwrap().into_bytes(),
            "compact, sorted keys"
        );
        let shape = hex32(&vci_core::Descriptor::shape_id(&frame.descriptor).unwrap());
        let expires = vci_core::objects::parse_hex32(&p.hdr).map(|_| ());
        assert!(expires.is_some(), "hdr is 64 hex: {}", p.hdr);
        assert_eq!(c.format, Some(3), "{}", e.key);
        assert_eq!(c.commit.as_deref(), Some(head.as_str()));
        assert_eq!(c.platform.as_deref(), Some(platform.as_str()));
        assert_eq!(c.state.as_deref(), Some("passed"));
        assert_eq!(c.duration_ms, Some(p.result.duration_ms));
        assert!(c.expires.is_some_and(|x| x > 1_700_000_000), "{c:?}");
        assert_eq!(c.hdr.as_deref(), Some(p.hdr.as_str()));
        assert_eq!(c.tables.as_deref(), Some(p.tables.as_str()));
        assert_eq!(c.shape.as_deref(), Some(shape.as_str()));
        assert!(c.state_obj.is_some(), "{c:?}");
        ids.extend(c.object_ids().map(str::to_owned));
        hdrs.insert(p.hdr.clone());
        shapes.insert(shape);
    }
    assert_eq!(hdrs.len(), 1, "one header group: one hdr for the run");
    assert_eq!(shapes.len(), 1, "one shape for the run");
    assert_eq!(ids.len(), 4, "hdr, tables, shape, state: {ids:?}");
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let objects = s.get_objects(&refs).unwrap();
    assert_eq!(objects.len(), 4, "every object the columns name is stored");
    for o in &objects {
        assert_eq!(hex32(&object_id(&o.bytes)), o.id, "content-addressed");
    }
    let hdr_bytes = &objects.iter().find(|o| hdrs.contains(&o.id)).unwrap().bytes;
    let hdr = Hdr::decode(hdr_bytes).unwrap();
    assert_eq!(hdr.adapter, "go");
    assert_eq!(hdr.toolchain.os, std::env::consts::OS);
    assert_eq!(hdr.global_manifest().root(), hex32(&hdr.global_input_root));
    let shape_bytes = &objects
        .iter()
        .find(|o| shapes.contains(&o.id))
        .unwrap()
        .bytes;
    let shape = Shape::decode(shape_bytes).unwrap();
    assert!(
        shape.entries.iter().any(|e| e.path.as_str() == "go.mod")
            || shape
                .entries
                .iter()
                .any(|e| e.path.as_str().ends_with("_test.go")),
        "the shape lists the units' inputs: {} entries",
        shape.entries.len()
    );
    // The plan reads them.
    assert_eq!(w.skipped(), set(UNITS));
    let out = w.vci(&["explain", "a", "--base-ref", "main"], &[]);
    assert!(text(&out).contains("a: SKIP"), "{}", text(&out));

    // A run on a commit of this branch only, then the branch moves on:
    // the next record of `a` supersedes it (decided from its signed
    // statement: same unit, commit moved on from, same platform, other
    // entries root), and the run's state objects are not aged yet.
    w.edit_and_commit("a/a.go", "edit 1");
    let out = w.run(&["a"], &[]);
    assert!(!stderr(&out).contains("superseded"), "{}", text(&out));
    let first = attested_keys(&out)["a"].clone();
    assert_eq!(s.read_all().unwrap().len(), UNITS.len() + 1);
    w.edit_and_commit("a/a.go", "edit 2");
    let out = w.run(&["a"], &[]);
    let err = stderr(&out);
    assert!(
        err.contains("vci: removed 1 superseded attestation(s) "),
        "{err}"
    );
    assert!(
        !err.contains("input manifest(s)"),
        "nothing about manifests: {err}"
    );
    let second = attested_keys(&out)["a"].clone();
    assert_ne!(first, second);
    let all = s.read_all().unwrap();
    assert_eq!(all.len(), UNITS.len() + 1, "one in, one out");
    assert!(
        all.iter().all(|e| e.key != first),
        "the superseded one is gone"
    );
    let new = all.iter().find(|e| e.key == second).unwrap();
    let (_, _, p) = frame_of(new);
    assert_eq!(p.commit, w.head());
    assert_eq!(w.skipped(), set(UNITS));
    // The superseded run's objects are within the orphan rule's grace, so
    // nothing of them was removed yet; the hdr is shared by every run.
    let hdr_id = hdrs.iter().next().unwrap().as_str();
    assert_eq!(s.get_objects(&[hdr_id]).unwrap().len(), 1);
}

/// `explain_hashes = false` writes three objects and records whose columns
/// name no state object.
#[test]
fn run_without_explain_hashes_writes_no_state_object() {
    let Some(w) = World::new() else { return };
    let out = w.run(&["a", "b"], &[("VCI_STORE_EXPLAIN_HASHES", "false")]);
    assert_eq!(attested_keys(&out).len(), 2, "{}", text(&out));
    let s = w.store();
    let all = s.read_all().unwrap();
    let columns = s.columns(&all.iter().collect::<Vec<_>>()).unwrap();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for (e, c) in all.iter().zip(&columns) {
        let (_, _, p) = frame_of(e);
        assert_eq!(c.hdr.as_deref(), Some(p.hdr.as_str()));
        assert_eq!(c.state_obj, None, "{c:?}");
        ids.extend(c.object_ids().map(str::to_owned));
    }
    assert_eq!(ids.len(), 3, "hdr, tables, shape: {ids:?}");
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    assert_eq!(s.get_objects(&refs).unwrap().len(), 3);
    assert_eq!(w.skipped(), set(&["a", "b"]));
}

/// `record_format = 1` keeps 2.8's path: envelope JSON records, their
/// input manifests stored, no columns, and the plan skips them as before.
#[test]
fn record_format_1_writes_envelopes_and_manifests_as_before() {
    let Some(w) = World::new() else { return };
    let out = w.run(&[], &[("VCI_STORE_RECORD_FORMAT", "1")]);
    assert_eq!(attested_keys(&out).len(), UNITS.len(), "{}", text(&out));
    assert!(!stderr(&out).contains("format-3 run:"), "{}", stderr(&out));
    let s = w.store();
    let all = s.read_all().unwrap();
    assert_eq!(all.len(), UNITS.len());
    let columns = s.columns(&all.iter().collect::<Vec<_>>()).unwrap();
    let mut roots = BTreeSet::new();
    for (e, c) in all.iter().zip(&columns) {
        let Ok(Record::FormatOne(bytes)) = decode_record(&e.bytes) else {
            panic!("{} is not an envelope", e.key);
        };
        let env = Envelope::from_json(bytes).unwrap();
        let stmt: Statement = serde_json::from_slice(&env.payload_bytes().unwrap()).unwrap();
        assert_eq!(stmt.predicate_type, vci_core::PREDICATE_TYPE);
        roots.insert(stmt.predicate["manifestRef"].as_str().unwrap().to_owned());
        assert_eq!(*c, Columns::default(), "{}", e.key);
    }
    let stored: BTreeSet<String> = s.manifest_roots().unwrap().into_iter().collect();
    assert!(
        roots.is_subset(&stored),
        "every manifest referenced is stored: {roots:?} in {stored:?}"
    );
    assert_eq!(w.skipped(), set(UNITS));
}
