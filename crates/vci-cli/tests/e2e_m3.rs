//! Store format 3 end to end, through the `vci` binary (the M3 tests row
//! of STORE-V2 section 6): a fixture at two commits whose unit keeps its
//! set and changes its root; a store mixing format-1 and format-3
//! records; a run that stores what it signed when a unit fails; `vci
//! explain`'s per-entry text beside format 1's, the unsigned label and
//! the not-loaded form; `vci verify --envelope`; supersession across
//! moved-on commits with its orphan objects; `vci prune --objects
//! --older-than`; and `vci store upgrade --finish` around a prune of
//! expired format-1 rows. On the SQLite store (listing columns name the
//! run's objects, which the tests read back), git-meta where the store
//! does not matter, and the libSQL local file where it is cheap. The
//! multi-hdr cargo run is in `e2e_cargo.rs`; the vci 2.8 binary on a
//! store this vci wrote is in `store_backends.rs`.
//!
//! A copy of `fixtures/vitest-abcd` in a throwaway git repository. Needs
//! `node`, `git` and `ssh-keygen` on PATH, and the fixture's `node_modules`
//! installed (`npm ci` in fixtures/vitest-abcd). The mixed-store test
//! also drives a vci 2.8 binary when `VCI_TEST_VCI_2_8` names one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use assert_cmd::cargo::CommandCargoExt;
use serde_json::Value;
use vci_attest::{Envelope, Statement};
use vci_core::{PREDICATE_TYPE, PREDICATE_TYPE_V2, Shape, VciPredicateV2};
use vci_store::{AttestationStore, Columns, Record, StoredEnvelope, decode_record};
use vci_store_sqlite::{SqliteOptions, SqliteStore};

const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";
const D: &str = "src/d.test.ts";
const UNITS: &[&str] = &[A, B, C, D];

const SQLITE: &[(&str, &str)] = &[("VCI_STORE", "sqlite")];
const LIBSQL: &[(&str, &str)] = &[("VCI_STORE", "libsql")];
const GIT_META: &[(&str, &str)] = &[];

const UNSIGNED_LABEL: &str = "attested (unsigned, from the run's state object)";
const HASH_NOT_LOADED: &str = "attested hash not loaded";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_owned()
}

const VCI_TOML: &str = r#"project = "."

[policy]
platform = "any"
max_ttl = "30d"

[env]
hash = ["NODE_ENV"]
"#;

/// The same with records that expire a second after they are issued.
const VCI_TOML_SHORT_TTL: &str = r#"project = "."

[policy]
platform = "any"
max_ttl = "1s"

[env]
hash = ["NODE_ENV"]
"#;

struct World {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    work: PathBuf,
    key: PathBuf,
    gitconfig: PathBuf,
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

/// The keys of `vci: attested <unit> (…) as <kind> <target> <key>` lines,
/// by unit.
fn attested_keys(out: &Output) -> BTreeMap<String, String> {
    let mut keys = BTreeMap::new();
    for line in stderr(out).lines() {
        let Some(rest) = line.strip_prefix("vci: attested ") else {
            continue;
        };
        let unit = rest.split_whitespace().next().unwrap().to_owned();
        let (_, tail) = rest
            .split_once(") as ")
            .unwrap_or_else(|| panic!("attested as: {line}"));
        let key = tail.split_whitespace().nth(2).unwrap().to_owned();
        keys.insert(unit, key);
    }
    keys
}

/// The slot of a key (`vci:attestation:<test key>:<signer>:<storage
/// key>`), without the hint a run stamps (its issue time and tree): a run
/// of the same inputs by the same signer replaces the record in its slot.
fn slot(key: &str) -> String {
    key.rsplit_once(':').unwrap().0.to_owned()
}

impl World {
    fn new() -> Self {
        Self::with_toml(VCI_TOML)
    }

    fn with_toml(toml: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let gitconfig = base.join("gitconfig");
        std::fs::write(
            &gitconfig,
            "[user]\n\tname = Test\n\temail = test@example.com\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n",
        )
        .unwrap();
        let key = base.join("trusted");
        let st = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "trusted", "-f"])
            .arg(&key)
            .status()
            .unwrap();
        assert!(st.success());
        let pubkey = std::fs::read_to_string(key.with_extension("pub")).unwrap();
        let pubkey = pubkey
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let work = base.join("work");
        let w = World {
            _tmp: tmp,
            base: base.clone(),
            work: work.clone(),
            key,
            gitconfig,
        };
        let fx = workspace_root().join("fixtures/vitest-abcd");
        std::fs::create_dir_all(&work).unwrap();
        w.git(&work, &["init", "-q"]);
        for name in [
            "src",
            "fixtures",
            "package.json",
            "package-lock.json",
            "vitest.config.ts",
            "node_modules",
        ] {
            let st = Command::new("cp")
                .arg("-R")
                .arg(fx.join(name))
                .arg(work.join(name))
                .status()
                .unwrap();
            assert!(st.success());
        }
        w.write(".gitignore", "node_modules/\n.vci/out/\n");
        w.write("vci.toml", toml);
        std::fs::create_dir_all(work.join(".vci")).unwrap();
        w.write(
            ".vci/allowed_signers",
            &format!("trusted@example.com namespaces=\"vci-attest\" {pubkey}\n"),
        );
        w.git(&work, &["add", "-A"]);
        w.git(&work, &["commit", "-q", "-m", "base commit"]);
        w.git(&work, &["checkout", "-q", "-b", "feature"]);
        w
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

    /// Commit every change in the working tree.
    fn commit(&self, msg: &str) {
        self.git(&self.work, &["add", "-A"]);
        self.git(&self.work, &["commit", "-q", "-m", msg]);
    }

    fn head(&self) -> String {
        self.git(&self.work, &["rev-parse", "HEAD"])
    }

    /// `cmd <args>` in the repository with `env` added to a scrubbed
    /// environment: no store configured unless `env` configures one.
    fn command(&self, mut cmd: Command, args: &[&str], env: &[(&str, &str)]) -> Output {
        cmd.current_dir(&self.work)
            .args(args)
            .env("VCI_JS_PLUGIN", workspace_root().join("js/vitest-plugin"))
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("NO_COLOR", "1");
        for k in [
            "VCI_E2E_BIN",
            "VCI_BASE_REF",
            "GITHUB_BASE_REF",
            "GITHUB_REF",
            "GITHUB_OUTPUT",
            "GITHUB_ACTIONS",
            "VCI_SIGNING_KEY",
            "VCI_OUT",
            "VCI_TIMING",
            "VCI_JOBS",
            "NODE_OPTIONS",
            "NODE_ENV",
            "CI",
        ]
        .iter()
        .chain(vci_store::select::ENV_VARS)
        {
            cmd.env_remove(k);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        eprintln!(
            "$ {} {} {env:?} -> {:?}\n{}{}",
            Path::new(cmd.get_program())
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    fn vci(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        self.command(Command::cargo_bin("vci").unwrap(), args, env)
    }

    /// `vci <args>`; it must exit 0. Returns stdout.
    fn vci_ok(&self, args: &[&str], env: &[(&str, &str)]) -> String {
        let out = self.vci(args, env);
        assert_eq!(out.status.code(), Some(0), "vci {args:?}: {}", text(&out));
        stdout(&out)
    }

    /// `vci run <units> --key` (every unit when empty) with `env`; its
    /// exit code is the caller's.
    fn run_any(&self, units: &[&str], env: &[(&str, &str)]) -> Output {
        let key = self.key.to_str().unwrap().to_owned();
        let mut args = vec!["run"];
        args.extend_from_slice(units);
        args.extend(["--key", &key]);
        self.vci(&args, env)
    }

    /// [`World::run_any`]; it must exit 0 and attest every unit it ran.
    fn run(&self, units: &[&str], env: &[(&str, &str)]) -> Output {
        let out = self.run_any(units, env);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        let n = if units.is_empty() {
            UNITS.len()
        } else {
            units.len()
        };
        assert_eq!(attested_keys(&out).len(), n, "{}", text(&out));
        out
    }

    /// (skipped, run) of `vci plan --base-ref main`, which must exit 0
    /// without `runAll`.
    fn plan(&self, env: &[(&str, &str)]) -> (BTreeSet<String>, BTreeSet<String>) {
        let out = self.vci_ok(&["plan", "--base-ref", "main", "--format", "json"], env);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v["runAll"].is_null(), "{out}");
        let (mut skip, mut run) = (BTreeSet::new(), BTreeSet::new());
        for f in v["files"].as_array().unwrap() {
            let id = f["testId"].as_str().unwrap().to_owned();
            if f["skip"].as_bool().unwrap() {
                skip.insert(id);
            } else {
                run.insert(id);
            }
        }
        (skip, run)
    }

    /// `vci explain <unit> --base-ref main` (stdout).
    fn explain(&self, unit: &str, env: &[(&str, &str)]) -> String {
        self.vci_ok(&["explain", unit, "--base-ref", "main"], env)
    }

    /// `vci store info --format json`.
    fn info(&self, env: &[(&str, &str)]) -> Value {
        serde_json::from_str(&self.vci_ok(&["store", "info", "--format", "json"], env)).unwrap()
    }

    fn write(&self, rel: &str, content: &str) {
        let p = self.work.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.work.join(rel)).unwrap()
    }

    /// The SQLite store at its default path.
    fn sqlite(&self) -> SqliteStore {
        SqliteStore::open_path(self.sqlite_path(), SqliteOptions::default())
    }

    fn sqlite_path(&self) -> PathBuf {
        self.work.join(".git/vci-store.sqlite")
    }

    /// Move the objects `ids` back in time by `by` on the SQLite file,
    /// behind the store's back (the orphan rule's hour of grace).
    fn age_objects(&self, ids: &[&str], by: Duration) {
        let db = rusqlite::Connection::open(self.sqlite_path()).unwrap();
        db.busy_timeout(Duration::from_secs(20)).unwrap();
        for id in ids {
            let n = db
                .execute(
                    "UPDATE objects SET put_at = put_at - ?2 WHERE id = ?1",
                    rusqlite::params![id, i64::try_from(by.as_secs()).unwrap()],
                )
                .unwrap();
            assert_eq!(n, 1, "object {id} to age");
        }
    }
}

/// A stored record with its listing columns and, for a frame, its v2
/// predicate (the statement's test id is the unit).
struct Stored {
    e: StoredEnvelope,
    columns: Columns,
    unit: String,
    v2: Option<VciPredicateV2>,
}

/// Every record of the SQLite store, by key, with its columns.
fn records(s: &SqliteStore) -> BTreeMap<String, Stored> {
    let all = s.read_all().unwrap();
    let columns = s.columns(&all.iter().collect::<Vec<_>>()).unwrap();
    all.into_iter()
        .zip(columns)
        .map(|(e, columns)| {
            assert!(e.error.is_none(), "{}: {:?}", e.key, e.error);
            let (unit, v2) = match decode_record(&e.bytes).unwrap() {
                Record::FormatOne(bytes) => {
                    let env = Envelope::from_json(bytes).unwrap();
                    let st: Statement =
                        serde_json::from_slice(&env.payload_bytes().unwrap()).unwrap();
                    assert_eq!(st.predicate_type, PREDICATE_TYPE, "{}", e.key);
                    assert_eq!(columns, Columns::default(), "{}: no columns", e.key);
                    (st.subject[0].name.clone(), None)
                }
                Record::FormatThree(frame) => {
                    let st: Statement = serde_json::from_slice(&frame.statement).unwrap();
                    assert_eq!(st.predicate_type, PREDICATE_TYPE_V2, "{}", e.key);
                    let p: VciPredicateV2 = serde_json::from_value(st.predicate.clone()).unwrap();
                    assert_eq!(columns.format, Some(3), "{}: {columns:?}", e.key);
                    assert_eq!(columns.hdr.as_deref(), Some(p.hdr.as_str()), "{}", e.key);
                    (st.subject[0].name.clone(), Some(p))
                }
            };
            let key = e.key.clone();
            (
                key,
                Stored {
                    e,
                    columns,
                    unit,
                    v2,
                },
            )
        })
        .collect()
}

/// The record of `unit` (exactly one).
fn record_of<'a>(all: &'a BTreeMap<String, Stored>, unit: &str) -> &'a Stored {
    let mut found: Vec<&Stored> = all.values().filter(|r| r.unit == unit).collect();
    assert_eq!(found.len(), 1, "one record of {unit}");
    found.remove(0)
}

/// The ids of the objects the records' columns name, by kind: (hdr,
/// tables, shape, state).
fn object_ids(
    all: &BTreeMap<String, Stored>,
) -> (
    BTreeSet<String>,
    BTreeSet<String>,
    BTreeSet<String>,
    BTreeSet<String>,
) {
    let mut out: (
        BTreeSet<String>,
        BTreeSet<String>,
        BTreeSet<String>,
        BTreeSet<String>,
    ) = Default::default();
    for r in all.values() {
        let c = &r.columns;
        out.0.extend(c.hdr.clone());
        out.1.extend(c.tables.clone());
        out.2.extend(c.shape.clone());
        out.3.extend(c.state_obj.clone());
    }
    out
}

/// The ids of `ids` the store holds.
fn held(s: &dyn AttestationStore, ids: &BTreeSet<String>) -> BTreeSet<String> {
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    s.get_objects(&refs)
        .unwrap()
        .into_iter()
        .map(|o| o.id)
        .collect()
}

/// The `expected:` and `actual:` lines under the detail `what` of an
/// explain's failed check.
fn detail(explain: &str, what: &str) -> (String, String) {
    let lines: Vec<&str> = explain.lines().collect();
    let i = lines
        .iter()
        .position(|l| l.trim() == what)
        .unwrap_or_else(|| panic!("no detail {what:?} in:\n{explain}"));
    let expected = lines[i + 1]
        .trim()
        .strip_prefix("expected: ")
        .unwrap_or_else(|| panic!("{what}: {}", lines[i + 1]))
        .to_owned();
    let actual = lines[i + 2]
        .trim()
        .strip_prefix("actual:")
        .unwrap_or_else(|| panic!("{what}: {}", lines[i + 2]))
        .trim()
        .to_owned();
    (expected, actual)
}

/// The vci 2.8 binary `VCI_TEST_VCI_2_8` names, or `None` (the part of a
/// test that drives it is skipped, with a message) when it is unset. What
/// it names must say it is a 2.8 and must not be this build's own vci.
fn vci_2_8() -> Option<PathBuf> {
    let Some(p) = std::env::var_os("VCI_TEST_VCI_2_8") else {
        eprintln!("SKIPPED (the vci 2.8 part): VCI_TEST_VCI_2_8 names no vci 2.8 binary");
        return None;
    };
    let p = PathBuf::from(p);
    let out = Command::new(&p)
        .arg("--version")
        .output()
        .unwrap_or_else(|e| panic!("VCI_TEST_VCI_2_8={}: {e}", p.display()));
    let v = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    assert!(
        v.starts_with("vci 2.8."),
        "VCI_TEST_VCI_2_8={} says {v:?}, not a vci 2.8",
        p.display()
    );
    let ours = Path::new(env!("CARGO_BIN_EXE_vci"));
    assert!(
        std::fs::read(&p).unwrap_or_default() != std::fs::read(ours).unwrap_or_default(),
        "VCI_TEST_VCI_2_8={} is this build's own vci",
        p.display()
    );
    Some(p)
}

// ---------------------------------------------------------------------------
// (a) Two commits, the same set, another root.

/// A run at the first commit, then one input file of B edited and
/// committed: the plan at the second commit skips the units whose inputs
/// did not change and runs B, naming the edited entry with its attested
/// hash from the run's state object; B's run at the second commit writes a
/// new record (the first is superseded) and a new shape, sharing the hdr,
/// and the plan then skips every unit.
#[test]
fn an_edited_input_at_the_next_commit_runs_its_unit_alone_and_the_rerun_shares_the_hdr() {
    let w = World::new();
    // The first run on a commit only this branch holds, so that the next
    // commit moves on from it (a commit main holds is never superseded).
    w.write("NOTES", "first\n");
    w.commit("feature 1");
    w.run(&[], SQLITE);
    assert_eq!(
        w.plan(SQLITE).0,
        set(UNITS),
        "the first run skips every unit"
    );
    let s = w.sqlite();
    let first = records(&s);
    assert_eq!(first.len(), UNITS.len());
    let (hdrs, _, shapes, states) = object_ids(&first);
    // Each test file's global manifest (the package.json context of the
    // modules it loads) is its own, so a header group per unit.
    assert_eq!(hdrs.len(), UNITS.len(), "a header group per unit: {hdrs:?}");
    assert_eq!(shapes.len(), 1, "one shape: {shapes:?}");
    assert_eq!(states.len(), 1, "one state object: {states:?}");
    let b_first = record_of(&first, B).e.key.clone();
    let b_hdr = record_of(&first, B).columns.hdr.clone();
    let attested_b_json = vci_core::blake3_hex(w.read("fixtures/b.json").as_bytes());

    // The same set (B still reads fixtures/b.json), another root.
    w.write(
        "fixtures/b.json",
        "{ \"greeting\": \"hello\", \"edited\": true }\n",
    );
    w.commit("edit b.json");
    let (skip, run) = w.plan(SQLITE);
    assert_eq!(skip, set(&[A, C, D]), "the unchanged units skip");
    assert_eq!(run, set(&[B]), "B runs on its edited input");
    let ex = w.explain(B, SQLITE);
    assert!(ex.contains("failed check: inputs"), "{ex}");
    let (expected, actual) = detail(&ex, "entry:fixtures/b.json");
    assert!(
        expected.contains(&attested_b_json) && expected.ends_with(&format!("({UNSIGNED_LABEL})")),
        "the attested hash, unsigned: {expected}"
    );
    assert!(
        actual.contains(&vci_core::blake3_hex(w.read("fixtures/b.json").as_bytes())),
        "the observed hash: {actual}"
    );

    let out = w.run(&[B], &[SQLITE, &[("VCI_TIMING", "1")]].concat());
    assert!(
        stderr(&out)
            .contains("format-3 run: 1 hdr, 1 tables, 1 shape, 1 state object(s) over 1 unit(s)"),
        "{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("vci: removed 1 superseded attestation(s)"),
        "B's first record, made on a commit this one moved on from, of other inputs: {}",
        stderr(&out)
    );
    let second = records(&s);
    assert_eq!(second.len(), UNITS.len(), "one record per unit still");
    assert!(!second.contains_key(&b_first), "B's first record is gone");
    let b = record_of(&second, B);
    assert_eq!(b.v2.as_ref().unwrap().commit, w.head());
    assert_eq!(
        b.columns.hdr, b_hdr,
        "the hdr is shared with B's first record"
    );
    assert!(
        !shapes.contains(b.columns.shape.as_ref().unwrap()),
        "the second run's shape is new: {:?} not in {shapes:?}",
        b.columns.shape
    );
    assert!(
        !states.contains(b.columns.state_obj.as_ref().unwrap()),
        "the second run's state object is new"
    );
    let (hdrs2, _, shapes2, _) = object_ids(&second);
    assert_eq!(hdrs2, hdrs);
    assert_eq!(shapes2.len(), 2, "both runs' shapes are referenced");
    assert_eq!(held(&s, &shapes2), shapes2, "and held");
    assert_eq!(w.plan(SQLITE).0, set(UNITS), "every unit skips");
    assert!(w.explain(B, SQLITE).contains("all checks passed"));
}

// ---------------------------------------------------------------------------
// (b) A store mixing format-1 and format-3 records.

/// Format-1 records (`record_format = 1`, or written by a vci 2.8 when
/// `VCI_TEST_VCI_2_8` names one) and format-3 records for different units
/// in one store: the plan skips every unit from whichever form its record
/// has. The vci 2.8 fails open on the format-3 ones (runs them) and skips
/// its own.
fn mixed_store_skips_every_unit(env: &[(&str, &str)]) {
    let w = World::new();
    w.run(
        &[A, B],
        &[env, &[("VCI_STORE_RECORD_FORMAT", "1")]].concat(),
    );
    w.run(&[C, D], env);
    assert_eq!(w.plan(env).0, set(UNITS), "every unit skips");
    for u in [A, C] {
        let ex = w.explain(u, env);
        assert!(ex.contains("all checks passed"), "{ex}");
    }
    if env == SQLITE {
        let all = records(&w.sqlite());
        assert_eq!(all.len(), 4);
        for u in [A, B] {
            assert!(record_of(&all, u).v2.is_none(), "{u} is a format-1 record");
        }
        for u in [C, D] {
            assert!(record_of(&all, u).v2.is_some(), "{u} is a format-3 record");
        }
    }
}

#[test]
fn a_store_mixing_format_1_and_format_3_records_skips_every_unit_on_sqlite() {
    mixed_store_skips_every_unit(SQLITE);
}

#[test]
fn a_store_mixing_format_1_and_format_3_records_skips_every_unit_on_git_meta() {
    mixed_store_skips_every_unit(GIT_META);
}

#[test]
fn a_store_mixing_records_a_vci_2_8_wrote_and_format_3_records_skips_every_unit() {
    let Some(old) = vci_2_8() else { return };
    let w = World::new();
    let key = w.key.to_str().unwrap().to_owned();
    let out = w.command(Command::new(&old), &["run", A, B, "--key", &key], SQLITE);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(attested_keys(&out).len(), 2, "{}", text(&out));
    w.run(&[C, D], SQLITE);
    assert_eq!(w.plan(SQLITE).0, set(UNITS), "this vci skips every unit");
    let all = records(&w.sqlite());
    for u in [A, B] {
        assert!(record_of(&all, u).v2.is_none(), "{u} is 2.8's record");
    }
    for u in [C, D] {
        assert!(record_of(&all, u).v2.is_some(), "{u} is a format-3 record");
    }
    // 2.8 skips its own and runs the two it cannot read, with no error.
    let out = w.command(
        Command::new(&old),
        &["plan", "--base-ref", "main", "--format", "json"],
        SQLITE,
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let skipped: BTreeSet<String> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["skip"].as_bool().unwrap())
        .map(|f| f["testId"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(skipped, set(&[A, B]), "{v}");
    assert!(!stderr(&out).contains("error"), "{}", stderr(&out));
}

// ---------------------------------------------------------------------------
// (c) A run that does not finish every unit.

/// A run in which B fails stores the records it signed for A, C and D
/// (with the run's objects: the shape covers those three), refuses B, and
/// exits non-zero; the next plan skips the three and runs B.
fn a_failing_unit_keeps_the_others_records(env: &[(&str, &str)]) {
    let w = World::new();
    w.write(
        B,
        "import { expect, test } from \"vitest\";\n\ntest(\"fails\", () => {\n  expect(1).toBe(2);\n});\n",
    );
    w.commit("B fails");
    let out = w.run_any(&[], env);
    assert_ne!(out.status.code(), Some(0), "the failing test fails the run");
    let err = stderr(&out);
    assert!(
        err.contains(&format!("vci: not attesting {B}: result failed")),
        "{err}"
    );
    assert!(err.contains("vci: 3 attested, 1 not attested"), "{err}");
    assert_eq!(
        attested_keys(&out).keys().cloned().collect::<BTreeSet<_>>(),
        set(&[A, C, D])
    );
    let (skip, run) = w.plan(env);
    assert_eq!(skip, set(&[A, C, D]), "what the run stored skips");
    assert_eq!(run, set(&[B]));
    if env == SQLITE {
        let s = w.sqlite();
        let all = records(&s);
        assert_eq!(all.len(), 3);
        let (hdrs, tables, shapes, states) = object_ids(&all);
        assert_eq!(
            (hdrs.len(), shapes.len(), states.len()),
            (3, 1, 1),
            "{hdrs:?}"
        );
        assert!(!tables.is_empty());
        let shape_id = shapes.iter().next().unwrap().as_str();
        let shape = Shape::decode(&s.get_objects(&[shape_id]).unwrap()[0].bytes).unwrap();
        let paths: BTreeSet<&str> = shape.entries.iter().map(|e| e.path.as_str()).collect();
        assert!(
            paths.contains("src/a.ts") && paths.contains("src/d.ts"),
            "{paths:?}"
        );
        assert!(
            !paths.contains("src/b.ts") && !paths.contains("fixtures/b.json"),
            "B's inputs are not in the shape: {paths:?}"
        );
    }
    // B fixed: it runs and joins the rest.
    w.write(
        B,
        &std::fs::read_to_string(workspace_root().join("fixtures/vitest-abcd").join(B)).unwrap(),
    );
    w.commit("B fixed");
    w.run(&[B], env);
    assert_eq!(w.plan(env).0, set(UNITS));
}

#[test]
fn a_run_with_a_failing_unit_stores_the_records_it_signed_on_sqlite() {
    a_failing_unit_keeps_the_others_records(SQLITE);
}

#[test]
fn a_run_with_a_failing_unit_stores_the_records_it_signed_on_git_meta() {
    a_failing_unit_keeps_the_others_records(GIT_META);
}

// ---------------------------------------------------------------------------
// (e) explain snapshots and vci verify --envelope.

/// `vci explain` prints, for an edited entry of a format-3 record whose
/// state object is at hand, the format-1 text of the attested entry with
/// the unsigned label after it and the observed entry word for word;
/// without a state object (`explain_hashes = false`) the entry is reported
/// as changed with the attested hash not loaded.
#[test]
fn explain_prints_the_format_1_entry_text_with_the_unsigned_label_or_not_loaded() {
    let w = World::new();
    let original = w.read("fixtures/b.json");
    let edited = "{ \"greeting\": \"hello\", \"edited\": true }\n";
    let snapshot = |env: &[(&str, &str)]| -> String {
        w.run(&[B], env);
        assert_eq!(w.plan(SQLITE).0, set(&[B]));
        w.write("fixtures/b.json", edited);
        let ex = w.explain(B, SQLITE);
        w.write("fixtures/b.json", &original);
        assert!(ex.contains("failed check: inputs"), "{ex}");
        ex
    };
    let three = snapshot(SQLITE);
    let one = snapshot(&[SQLITE, &[("VCI_STORE_RECORD_FORMAT", "1")]].concat());
    let (expected3, actual3) = detail(&three, "entry:fixtures/b.json");
    let (expected1, actual1) = detail(&one, "entry:fixtures/b.json");
    assert_eq!(
        expected3,
        format!("{expected1} ({UNSIGNED_LABEL})"),
        "the attested entry as format 1 prints it, labelled unsigned"
    );
    assert_eq!(actual3, actual1, "the observed entry");
    assert!(
        expected1.starts_with("file exec=false size=")
            && expected1.contains(&vci_core::blake3_hex(original.as_bytes())),
        "{expected1}"
    );
    assert!(
        actual1.contains(&vci_core::blake3_hex(edited.as_bytes())),
        "{actual1}"
    );
    assert!(!three.contains(HASH_NOT_LOADED), "{three}");

    let none = snapshot(&[SQLITE, &[("VCI_STORE_EXPLAIN_HASHES", "false")]].concat());
    let (expected, actual) = detail(&none, &format!("entry: changed ({HASH_NOT_LOADED})"));
    assert!(expected.starts_with("input root "), "{expected}");
    assert!(actual.starts_with("input root "), "{actual}");
    assert!(!none.contains(UNSIGNED_LABEL), "{none}");
    assert!(
        !none.contains(&vci_core::blake3_hex(original.as_bytes())),
        "no attested hash without a state object: {none}"
    );
}

/// `vci verify` of the format-3 record `vci run` stored: VALID with the
/// set resolved from the run's objects; `--envelope` prints the DSSE
/// envelope rebuilt from it, which parses as one, whose statement is the
/// signed v2 statement, and whose signature `vci verify` and the DSSE
/// verifier the plan uses accept against the repository's allowed signers.
#[test]
fn verify_envelope_of_a_format_3_record_is_the_dsse_envelope_in_toto_tooling_reads() {
    let w = World::new();
    w.run(&[B], SQLITE);
    let all = records(&w.sqlite());
    let b = record_of(&all, B);
    let Ok(Record::FormatThree(frame)) = decode_record(&b.e.bytes) else {
        panic!("a frame")
    };
    let record = w.base.join("b.vci3");
    std::fs::write(&record, &b.e.bytes).unwrap();
    let out = w.vci_ok(
        &["verify", record.to_str().unwrap(), "--base-ref", "main"],
        SQLITE,
    );
    assert!(
        out.contains("VALID signature by trusted@example.com"),
        "{out}"
    );
    assert!(
        out.contains("(set resolved from the run's shape object; root not recomputed"),
        "{out}"
    );
    assert!(out.contains(&format!("test: {B}")), "{out}");

    let printed = w.vci_ok(&["verify", record.to_str().unwrap(), "--envelope"], SQLITE);
    let envelope = Envelope::from_json(printed.as_bytes()).unwrap();
    assert_eq!(
        envelope.payload_bytes().unwrap(),
        frame.statement,
        "the statement as signed"
    );
    let st: Statement = serde_json::from_slice(&frame.statement).unwrap();
    assert_eq!(st.predicate_type, PREDICATE_TYPE_V2);
    let signers = vci_attest::AllowedSigners::parse(&w.read(".vci/allowed_signers")).unwrap();
    let now = jiff::Timestamp::now().as_second();
    let verified = vci_attest::verify_envelope(&envelope, &signers, now).unwrap();
    assert_eq!(verified.principal, "trusted@example.com");
    assert_eq!(verified.statement.subject[0].name, B);
    // The printed envelope verifies as a DSSE envelope; its manifest line
    // needs the record's descriptor or a manifest file.
    let rebuilt = w.base.join("b.rebuilt.json");
    std::fs::write(&rebuilt, printed.as_bytes()).unwrap();
    let out = w.vci(
        &["verify", rebuilt.to_str().unwrap(), "--base-ref", "main"],
        SQLITE,
    );
    let text = stdout(&out);
    assert!(
        text.contains("VALID signature by trusted@example.com"),
        "{text}"
    );
    assert!(text.contains("without its record's descriptor"), "{text}");
    // Tampered inside the frame: INVALID.
    let mut tampered = frame.clone();
    let pos = tampered
        .statement
        .windows(9)
        .position(|x| x == b"\"tests\":1")
        .expect("the statement holds the test count");
    tampered.statement[pos + 8] = b'2';
    let bad = w.base.join("b.tampered.vci3");
    std::fs::write(&bad, tampered.encode().unwrap()).unwrap();
    let out = w.vci(
        &["verify", bad.to_str().unwrap(), "--base-ref", "main"],
        SQLITE,
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("INVALID"), "{}", stdout(&out));
}

/// `vci verify` takes the run's objects by the id asked for, recomputed
/// over the bytes the store returned, as the plan does: another
/// well-formed shape filed under the descriptor's shape id (a store row
/// whose bytes are not its id) is refused as corrupt, the manifest line
/// is INVALID and names the BLAKE3 found, and nothing of the planted
/// shape's set is printed; the hdr and tables, which recompute, still
/// resolve. Restored, the record is VALID again.
#[test]
fn verify_refuses_a_shape_object_whose_bytes_are_not_its_id() {
    let w = World::new();
    w.run(&[], SQLITE);
    let all = records(&w.sqlite());
    let b = record_of(&all, B);
    let shape_id = b.columns.shape.clone().expect("B's shape column");
    let record = w.base.join("b.vci3");
    std::fs::write(&record, &b.e.bytes).unwrap();
    let valid = w.vci_ok(
        &["verify", record.to_str().unwrap(), "--base-ref", "main"],
        SQLITE,
    );
    assert!(
        valid.contains("(set resolved from the run's shape object; root not recomputed"),
        "{valid}"
    );
    let db = rusqlite::Connection::open(w.sqlite_path()).unwrap();
    db.busy_timeout(Duration::from_secs(20)).unwrap();
    let genuine: Vec<u8> = db
        .query_row(
            "SELECT bytes FROM objects WHERE id = ?1",
            [&shape_id],
            |r| r.get(0),
        )
        .unwrap();
    // A well-formed shape of one entry, which decodes, under B's shape id.
    let planted = Shape {
        entries: vec![vci_core::ShapeEntry {
            path: vci_core::RepoPath::new("planted/only.ts").unwrap(),
            kind: vci_core::EntryKind::File,
            exec: false,
        }],
        groups: vec![],
    }
    .encode()
    .unwrap();
    let found = vci_core::objects::hex32(&vci_core::object_id(&planted));
    assert_ne!(found, shape_id);
    assert_eq!(
        db.execute(
            "UPDATE objects SET bytes = ?2 WHERE id = ?1",
            rusqlite::params![shape_id, planted],
        )
        .unwrap(),
        1
    );
    let out = w.vci(
        &["verify", record.to_str().unwrap(), "--base-ref", "main"],
        SQLITE,
    );
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(
        text.contains(&format!(
            "manifest: INVALID: the shape object {shape_id} is corrupt (its BLAKE3 is {found})"
        )),
        "{text}"
    );
    assert!(
        !text.contains("1 entries, 0 externals"),
        "the planted shape's set is never resolved: {text}"
    );
    assert!(
        !text.contains("repo id: (in the hdr object"),
        "the hdr and tables still resolve: {text}"
    );
    assert_eq!(
        db.execute(
            "UPDATE objects SET bytes = ?2 WHERE id = ?1",
            rusqlite::params![shape_id, genuine],
        )
        .unwrap(),
        1
    );
    let restored = w.vci_ok(
        &["verify", record.to_str().unwrap(), "--base-ref", "main"],
        SQLITE,
    );
    assert_eq!(restored, valid, "restored");
}

// ---------------------------------------------------------------------------
// (g) Supersession across runs at moved-on commits.

/// Run 1 at the first commit; the branch moves on with A's input edited.
/// A run of B there under another env hash (another storage key) keeps
/// B's first record, whose entries root is unchanged. A run of every unit
/// then supersedes A's first record alone (other entries root, commit
/// moved on from) while B, C and D replace theirs in their slots, and
/// collects the first run's tables, shape and state objects, which nothing
/// references any more and whose hour of grace has passed (aged behind the
/// store's back); the shared hdr stays. The plan skips every unit.
#[test]
fn supersession_across_moved_on_commits_removes_the_right_records_and_their_objects() {
    let w = World::new();
    w.write("NOTES", "first\n");
    w.commit("feature 1");
    w.run(&[], SQLITE);
    let s = w.sqlite();
    let first = records(&s);
    let keys1: BTreeMap<String, String> = first
        .values()
        .map(|r| (r.unit.clone(), r.e.key.clone()))
        .collect();
    let (hdrs, tables1, shapes1, states1) = object_ids(&first);
    assert_eq!(
        (hdrs.len(), shapes1.len(), states1.len()),
        (UNITS.len(), 1, 1)
    );
    let hdr_b = record_of(&first, B).columns.hdr.clone().unwrap();
    let run1: BTreeSet<String> = hdrs
        .iter()
        .chain(&tables1)
        .chain(&shapes1)
        .chain(&states1)
        .cloned()
        .collect();

    w.write(
        "src/a.ts",
        "export const add = (x: number, y: number) => x + y; // edited\n",
    );
    w.commit("edit a.ts");
    assert_eq!(w.plan(SQLITE), (set(&[B, C, D]), set(&[A])));

    // B under another env hash: another storage key, the same entries
    // root as B's first record, which stays.
    let out = w.run(&[B], &[SQLITE, &[("NODE_ENV", "production")]].concat());
    assert!(!stderr(&out).contains("superseded"), "{}", stderr(&out));
    let b_prod = attested_keys(&out)[B].clone();
    assert_ne!(slot(&b_prod), slot(&keys1[B]), "another storage key");
    let now = records(&s);
    assert_eq!(now.len(), 5, "B's first record is kept beside the new one");
    assert!(now.contains_key(&keys1[B]));
    let b_prod_objects: BTreeSet<String> = now[&b_prod]
        .columns
        .object_ids()
        .map(str::to_owned)
        .collect();
    assert!(b_prod_objects.contains(&hdr_b), "B's hdr is shared");

    // Every unit at the moved-on commit, the first run's objects past the
    // grace hour. The superseded record's objects that nothing references
    // any more go (its state object at least: A's hashes changed; the
    // hdrs, the tables and the shape are content-addressed and this run
    // of the same four units names them again, as B's production record
    // may).
    let ids: Vec<&str> = run1.iter().map(String::as_str).collect();
    w.age_objects(&ids, Duration::from_secs(7_200));
    let out = w.run(&[], SQLITE);
    let err = stderr(&out);
    assert!(
        err.contains("vci: removed 1 superseded attestation(s)"),
        "{err}"
    );
    let keys2 = attested_keys(&out);
    let after = records(&s);
    let referenced: BTreeSet<String> = after
        .values()
        .flat_map(|r| r.columns.object_ids().map(str::to_owned))
        .collect();
    let gone: BTreeSet<String> = run1.difference(&referenced).cloned().collect();
    assert!(
        gone.is_superset(&states1),
        "the first run's state object: {gone:?}"
    );
    assert!(
        err.contains(&format!(
            "vci: removed {} object(s) no attestation references any more",
            gone.len()
        )),
        "{gone:?}: {err}"
    );
    let kept: BTreeSet<String> = run1.intersection(&referenced).cloned().collect();
    assert_eq!(
        held(&s, &run1),
        kept,
        "of the first run's objects, the referenced ones stay"
    );
    assert_eq!(after.len(), 5, "A, B, C, D and B's production record");
    assert!(
        !after.contains_key(&keys1[A]),
        "A's first record was superseded"
    );
    for u in [B, C, D] {
        assert!(
            !after.contains_key(&keys1[u]),
            "{u}'s first record was replaced"
        );
        assert_eq!(slot(&keys2[u]), slot(&keys1[u]), "{u}: in its slot");
    }
    assert_ne!(
        slot(&keys2[A]),
        slot(&keys1[A]),
        "A: other inputs, another slot"
    );
    assert!(after.contains_key(&b_prod), "the production record stays");
    let (hdrs2, _, _, _) = object_ids(&after);
    assert_eq!(hdrs2, hdrs, "the hdrs are shared across the runs");
    assert_eq!(
        held(&s, &referenced),
        referenced,
        "every referenced object is held"
    );
    assert_eq!(w.plan(SQLITE).0, set(UNITS));
    assert_eq!(
        w.plan(&[SQLITE, &[("NODE_ENV", "production")]].concat()).0,
        set(&[B]),
        "under the other env hash only B's production record matches"
    );
}

// ---------------------------------------------------------------------------
// (h) vci prune --objects --older-than.

/// `vci prune --objects --older-than 0` removes the run's state object and
/// nothing else: the records stay, the plan skips every unit, and `vci
/// explain` of an edited input reports the attested hash as not loaded.
fn prune_objects_removes_the_state_object_and_the_records_stay(env: &[(&str, &str)]) {
    let w = World::new();
    w.run(&[], env);
    assert_eq!(w.plan(env).0, set(UNITS));
    let objects = |w: &World| -> i64 {
        let path = w.work.join(format!(".git/vci-store.{}", env[0].1));
        let db = rusqlite::Connection::open(path).unwrap();
        db.query_row("SELECT count(*) FROM objects", [], |r| r.get(0))
            .unwrap()
    };
    let before = objects(&w);
    assert!(
        before >= 4,
        "hdr, tables, shape and state objects: {before}"
    );
    // The state TTL compares whole seconds.
    std::thread::sleep(Duration::from_millis(1_100));
    let out = w.vci(&["prune", "--objects", "--older-than", "0"], env);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stderr(&out).contains("vci prune: 1 state object(s) older than 0 day(s) removed"),
        "{}",
        text(&out)
    );
    assert_eq!(stdout(&out), "", "no attestation or manifest line");
    assert!(
        !stderr(&out).contains("run `vci push`"),
        "the store removed it at once; its push has nothing to publish: {}",
        text(&out)
    );
    assert_eq!(objects(&w), before - 1, "the state object alone");
    assert_eq!(w.info(env)["count"], UNITS.len());
    assert_eq!(
        w.plan(env).0,
        set(UNITS),
        "the records are valid without it"
    );
    w.write(
        "fixtures/b.json",
        "{ \"greeting\": \"hello\", \"edited\": true }\n",
    );
    let (skip, run) = w.plan(env);
    assert_eq!((skip, run), (set(&[A, C, D]), set(&[B])));
    let ex = w.explain(B, env);
    assert!(
        ex.contains(&format!("entry: changed ({HASH_NOT_LOADED})")),
        "{ex}"
    );
    assert!(!ex.contains(UNSIGNED_LABEL), "{ex}");
    if env == SQLITE {
        let s = w.sqlite();
        let (hdrs, tables, shapes, states) = object_ids(&records(&s));
        assert_eq!(states.len(), 1, "the records still name it");
        assert!(held(&s, &states).is_empty(), "the state object is gone");
        let rest: BTreeSet<String> = hdrs.iter().chain(&tables).chain(&shapes).cloned().collect();
        assert_eq!(held(&s, &rest), rest, "the rest is held");
    }
}

#[test]
fn prune_objects_older_than_removes_the_state_object_on_sqlite() {
    prune_objects_removes_the_state_object_and_the_records_stay(SQLITE);
}

#[test]
fn prune_objects_older_than_removes_the_state_object_on_libsql() {
    prune_objects_removes_the_state_object_and_the_records_stay(LIBSQL);
}

// ---------------------------------------------------------------------------
// (i) vci store upgrade --finish around expired format-1 rows.

/// Under a one-second `max_ttl` (a commit of the branch; the plan reads
/// the policy at the base), A and B are attested as format-1 records and
/// expire; `vci store upgrade --finish` is refused while they exist
/// (counted by the value, before and after C and D are attested as
/// format-3 records under the base's TTL again); `vci prune` removes the
/// two expired rows; `--finish` then upgrades the store, after which the
/// plan still skips C and D.
#[test]
fn store_upgrade_finish_is_refused_until_the_expired_format_1_rows_are_pruned() {
    let w = World::new();
    w.write("vci.toml", VCI_TOML_SHORT_TTL);
    w.commit("a one-second ttl");
    let key = w.key.to_str().unwrap().to_owned();
    let out = w.vci(
        &["run", A, B, "--key", &key, "--ttl", "1s"],
        &[SQLITE, &[("VCI_STORE_RECORD_FORMAT", "1")]].concat(),
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let keys = attested_keys(&out);
    assert_eq!(keys.len(), 2, "{}", text(&out));
    let out = w.vci(&["store", "upgrade", "--finish"], SQLITE);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stdout(&out).contains("not finished: 2 attestation(s) are not format-3 records"),
        "{}",
        text(&out)
    );
    assert_eq!(w.info(SQLITE)["schemaVersion"], 1);

    w.write("vci.toml", VCI_TOML);
    w.commit("the base's ttl again");
    w.run(&[C, D], SQLITE);
    let out = w.vci(&["store", "upgrade", "--finish"], SQLITE);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stdout(&out).contains("not finished: 2 attestation(s) are not format-3 records"),
        "{}",
        text(&out)
    );
    // A and B's records are past their second.
    std::thread::sleep(Duration::from_millis(1_500));
    let out = w.vci(&["prune"], SQLITE);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let mut removed: Vec<String> = stdout(&out)
        .lines()
        .filter(|l| l.starts_with("removed path:"))
        .map(str::to_owned)
        .collect();
    removed.sort();
    let mut want: Vec<String> = keys
        .iter()
        .map(|(unit, k)| format!("removed path:{unit} {k}"))
        .collect();
    want.sort();
    assert_eq!(removed, want, "{}", text(&out));
    assert!(
        stderr(&out).contains("vci prune: 2 expired, 2 current"),
        "{}",
        stderr(&out)
    );
    let out = w.vci(&["store", "upgrade", "--finish"], SQLITE);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).contains("upgraded to schema version 2"),
        "{}",
        text(&out)
    );
    let info = w.info(SQLITE);
    assert_eq!(info["schemaVersion"], 2);
    assert_eq!(info["count"], 2);
    assert_eq!(w.plan(SQLITE), (set(&[C, D]), set(&[A, B])));
    // A run after the upgrade writes format 3 as before.
    w.run(&[A], SQLITE);
    assert_eq!(w.plan(SQLITE).0, set(&[A, C, D]));
    let all = records(&w.sqlite());
    assert!(all.values().all(|r| r.v2.is_some()));
}
