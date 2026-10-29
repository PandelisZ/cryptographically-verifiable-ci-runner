//! A store writer against the plan's trust path (STORE-V2 sections 1.5
//! and 4, the M3 review): every attempt to turn a store edit into a wrong
//! skip, made on a SQLite store `vci run` wrote, edited directly with
//! rusqlite behind the store's back. A unit must run (never skip) when its
//! record's columns lie, when its descriptor names another shape or
//! another unit's set, when a hdr's or a shape's bytes are not their id,
//! when its record sits under another trusted signer's key segment, when a
//! 2.8 value sits in a format-3 slot beside the slot's stale columns, and
//! when the verdict-object byte cap is filled by a decoy's objects before
//! its own are loaded; and it must skip again once the edit is undone.
//!
//! A copy of `fixtures/vitest-abcd` in a throwaway git repository, as
//! `e2e_m3.rs` makes it, with two trusted keys at the base commit. Needs
//! `node`, `git` and `ssh-keygen` on PATH, and the fixture's `node_modules`
//! installed (`npm ci` in fixtures/vitest-abcd). The 2.8 test drives a vci
//! 2.8 binary when `VCI_TEST_VCI_2_8` names one.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use assert_cmd::cargo::CommandCargoExt;
use base64::Engine as _;
use serde_json::Value;
use sha2::Digest as _;
use vci_core::{EntryKind, Frame, Hdr, RepoPath, Shape, ShapeEntry, object_id, objects::hex32};

const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";
const D: &str = "src/d.test.ts";
const UNITS: &[&str] = &[A, B, C, D];

const SQLITE: &[(&str, &str)] = &[("VCI_STORE", "sqlite")];

const UNSIGNED_LABEL: &str = "attested (unsigned, from the run's state object)";
const HASH_NOT_LOADED: &str = "attested hash not loaded";

/// The plan's verdict-object byte cap (`plan.rs` `VERDICT_OBJECT_BYTES`).
const VERDICT_OBJECT_BYTES: usize = 16 << 20;
/// A shape's size limit (`ObjectKind::Shape.max_bytes()`).
const SHAPE_MAX: usize = 8 << 20;

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

struct World {
    _tmp: tempfile::TempDir,
    work: PathBuf,
    /// The key `vci run` signs with (trusted at the base commit).
    key: PathBuf,
    /// Another key trusted at the base commit, which never signs here.
    other_key: PathBuf,
    gitconfig: PathBuf,
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

fn keygen(path: &Path, comment: &str) -> String {
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(path)
        .status()
        .unwrap();
    assert!(st.success());
    let pubkey = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    pubkey
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The signer id of a public key (`keys::signer_id`: the first 16 hex of
/// SHA-256 over the key blob), as the store key's signer segment carries it.
fn signer_id_of(key: &Path) -> String {
    let pubkey = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let b64 = pubkey.split_whitespace().nth(1).unwrap();
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap();
    hex::encode(sha2::Sha256::digest(blob))[..16].to_owned()
}

impl World {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let gitconfig = base.join("gitconfig");
        std::fs::write(
            &gitconfig,
            "[user]\n\tname = Test\n\temail = test@example.com\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n",
        )
        .unwrap();
        let key = base.join("trusted");
        let other_key = base.join("other");
        let pubkey = keygen(&key, "trusted");
        let other_pubkey = keygen(&other_key, "other");
        let work = base.join("work");
        let w = World {
            _tmp: tmp,
            work: work.clone(),
            key,
            other_key,
            gitconfig,
        };
        let fx = workspace_root().join("fixtures/vitest-abcd");
        std::fs::create_dir_all(&work).unwrap();
        w.git(&["init", "-q"]);
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
        w.write("vci.toml", VCI_TOML);
        std::fs::create_dir_all(work.join(".vci")).unwrap();
        w.write(
            ".vci/allowed_signers",
            &format!(
                "trusted@example.com namespaces=\"vci-attest\" {pubkey}\nother@example.com namespaces=\"vci-attest\" {other_pubkey}\n"
            ),
        );
        w.git(&["add", "-A"]);
        w.git(&["commit", "-q", "-m", "base commit"]);
        w.git(&["checkout", "-q", "-b", "feature"]);
        // A commit only this branch holds, as a pull request's.
        w.write("NOTES", "feature\n");
        w.git(&["add", "-A"]);
        w.git(&["commit", "-q", "-m", "feature"]);
        w
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(&self.work)
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
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// `vci run --key` of every unit on the SQLite store; it must exit 0
    /// and attest the four units.
    fn run(&self) {
        let key = self.key.to_str().unwrap().to_owned();
        let out = self.vci(&["run", "--key", &key], SQLITE);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        let attested = String::from_utf8_lossy(&out.stderr)
            .lines()
            .filter(|l| l.starts_with("vci: attested "))
            .count();
        assert_eq!(attested, UNITS.len(), "{}", text(&out));
    }

    /// (skipped, run) of `vci plan --base-ref main` on the SQLite store,
    /// which must exit 0 without `runAll`; `extra` adds to the environment.
    fn plan_with(&self, extra: &[(&str, &str)]) -> (BTreeSet<String>, BTreeSet<String>, String) {
        let mut env: Vec<(&str, &str)> = SQLITE.to_vec();
        env.extend_from_slice(extra);
        let out = self.vci(&["plan", "--base-ref", "main", "--format", "json"], &env);
        assert_eq!(out.status.code(), Some(0), "vci plan: {}", text(&out));
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let v: Value = serde_json::from_str(&stdout).unwrap();
        assert!(v["runAll"].is_null(), "{stdout}");
        let (mut skip, mut run) = (BTreeSet::new(), BTreeSet::new());
        for f in v["files"].as_array().unwrap() {
            let id = f["testId"].as_str().unwrap().to_owned();
            if f["skip"].as_bool().unwrap() {
                skip.insert(id);
            } else {
                run.insert(id);
            }
        }
        (skip, run, String::from_utf8_lossy(&out.stderr).into_owned())
    }

    fn plan(&self) -> (BTreeSet<String>, BTreeSet<String>) {
        let (skip, run, _) = self.plan_with(&[]);
        (skip, run)
    }

    /// `vci explain <unit> --base-ref main` (stdout).
    fn explain(&self, unit: &str) -> String {
        self.vci_ok(&["explain", unit, "--base-ref", "main"], SQLITE)
    }

    fn write(&self, rel: &str, content: &str) {
        let p = self.work.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.work.join(rel)).unwrap()
    }

    /// A connection to the SQLite store file, behind the store's back.
    fn db(&self) -> rusqlite::Connection {
        let db = rusqlite::Connection::open(self.work.join(".git/vci-store.sqlite")).unwrap();
        db.busy_timeout(Duration::from_secs(20)).unwrap();
        db
    }

    /// The one row of `unit`.
    fn row(&self, unit: &str) -> Row {
        let db = self.db();
        let tk = vci_core::test_key(unit);
        let mut rows: Vec<Row> = db
            .prepare(
                "SELECT key, signer, issued, tree16, value, format, hdr, tables_id, shape, state_obj
                 FROM attestations WHERE test_key = ?1",
            )
            .unwrap()
            .query_map([&tk], |r| {
                Ok(Row {
                    key: r.get(0)?,
                    signer: r.get(1)?,
                    issued: r.get(2)?,
                    tree16: r.get(3)?,
                    value: r.get(4)?,
                    format: r.get(5)?,
                    hdr: r.get(6)?,
                    tables: r.get(7)?,
                    shape: r.get(8)?,
                    state_obj: r.get(9)?,
                })
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(rows.len(), 1, "one row of {unit}: {rows:?}");
        rows.remove(0)
    }

    fn object(&self, id: &str) -> Vec<u8> {
        self.db()
            .query_row("SELECT bytes FROM objects WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap_or_else(|e| panic!("object {id}: {e}"))
    }

    fn set_object(&self, id: &str, bytes: &[u8]) {
        let n = self
            .db()
            .execute(
                "UPDATE objects SET bytes = ?2 WHERE id = ?1",
                rusqlite::params![id, bytes],
            )
            .unwrap();
        assert_eq!(n, 1, "object {id}");
    }

    /// Add an object the store never put (the writer's choice of bytes
    /// under their own id), of the kind its bytes say.
    fn add_object(&self, kind: u8, bytes: &[u8]) -> String {
        let id = hex32(&object_id(bytes));
        self.db()
            .execute(
                "INSERT OR REPLACE INTO objects (id, kind, put_at, bytes) VALUES (?1, ?2, strftime('%s', 'now'), ?3)",
                rusqlite::params![id, i64::from(kind), bytes],
            )
            .unwrap();
        id
    }

    fn set_value(&self, key: &str, value: &[u8]) {
        let n = self
            .db()
            .execute(
                "UPDATE attestations SET value = ?2 WHERE key = ?1",
                rusqlite::params![key, value],
            )
            .unwrap();
        assert_eq!(n, 1, "row {key}");
    }
}

#[derive(Debug, Clone)]
struct Row {
    key: String,
    signer: String,
    issued: Option<i64>,
    tree16: Option<String>,
    value: Vec<u8>,
    format: Option<i64>,
    hdr: Option<String>,
    tables: Option<String>,
    shape: Option<String>,
    state_obj: Option<String>,
}

impl Row {
    fn frame(&self) -> Frame {
        Frame::decode(&self.value).unwrap_or_else(|e| panic!("{}: {e}", self.key))
    }

    /// The value with the descriptor's shape id replaced.
    fn value_naming_shape(&self, shape: &str) -> Vec<u8> {
        let mut f = self.frame();
        f.descriptor[..32].copy_from_slice(&vci_core::objects::parse_hex32(shape).unwrap());
        f.encode().unwrap().into_bytes()
    }
}

/// The hint of a key (`<hex issued>.<tree16>`) and the key without it.
fn split_hint(key: &str) -> (&str, &str) {
    key.rsplit_once(':').unwrap()
}

// ---------------------------------------------------------------------------

/// The listing columns of a record (format, commit, platform, result
/// state, duration, expiry, the four object ids) choose, order and
/// pre-filter only: with every one of B's edited to lie, the plan still
/// decides from the signed statement and the objects its signed ids and
/// its descriptor name, so B skips while its inputs are unchanged and runs
/// once they change; the `state_obj` column only names which state object
/// the failure text reads, labelled unsigned, and a column naming none
/// gives the not-loaded text.
#[test]
fn edited_columns_never_decide_a_verdict() {
    let w = World::new();
    w.run();
    assert_eq!(w.plan().0, set(UNITS), "the run skips every unit");
    let b = w.row(B);
    assert_eq!(b.format, Some(3));
    let none = hex32(&[0xaa; 32]);
    let n = w
        .db()
        .execute(
            "UPDATE attestations SET format = 1, commit_id = ?2, platform = 'plan9-mips', state = 'failed',
             duration_ms = 0, expires = 0, hdr = ?3, tables_id = ?3, shape = ?3, state_obj = ?3 WHERE key = ?1",
            rusqlite::params![b.key, "0".repeat(40), none],
        )
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(w.plan().0, set(UNITS), "the columns say nothing: B skips");
    let ex = w.explain(B);
    assert!(ex.contains("all checks passed"), "{ex}");

    // The input edited: B runs on its signed root, whatever the columns
    // say; the state object column names no object, so no attested hash,
    // and the file's kind did not change, so no entry can be named: the
    // one line says the entries changed and gives both roots.
    let original = w.read("fixtures/b.json");
    w.write("fixtures/b.json", "{ \"greeting\": \"hello, world\" }\n");
    let (skip, run) = w.plan();
    assert_eq!(run, set(&[B]), "B runs: {run:?} skip {skip:?}");
    let ex = w.explain(B);
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(
        ex.contains(&format!("entry: changed ({HASH_NOT_LOADED})")),
        "{ex}"
    );
    assert!(!ex.contains("entry:fixtures/b.json"), "{ex}");
    assert!(!ex.contains(UNSIGNED_LABEL), "{ex}");
    // The column pointed back at the run's state object: the attested
    // hash, labelled unsigned (presentation only: B still runs).
    w.db()
        .execute(
            "UPDATE attestations SET state_obj = ?2 WHERE key = ?1",
            rusqlite::params![b.key, b.state_obj.as_deref().unwrap()],
        )
        .unwrap();
    assert_eq!(w.plan().1, set(&[B]));
    let ex = w.explain(B);
    assert!(ex.contains("entry:fixtures/b.json"), "{ex}");
    assert!(ex.contains(UNSIGNED_LABEL), "{ex}");
    assert!(
        ex.contains(&vci_core::blake3_hex(original.as_bytes())),
        "the attested hash of the original fixture: {ex}"
    );
    w.write("fixtures/b.json", &original);
    assert_eq!(w.plan().0, set(UNITS), "restored");
}

/// The descriptor is unsigned: naming another shape (one the writer added,
/// in which B's entry for `fixtures/b.json` is another path) or carrying
/// another unit's descriptor makes the resolved set another one, whose
/// observation at HEAD does not hash to B's signed root, so B runs on
/// `inputs` while the units whose records are untouched skip; and a shape
/// whose bytes are not its id fails every candidate naming it (all four
/// units of the run share it).
#[test]
fn a_swapped_shape_a_swapped_descriptor_and_a_corrupt_shape_fail_inputs() {
    let w = World::new();
    w.run();
    assert_eq!(w.plan().0, set(UNITS));
    let b = w.row(B);
    let a = w.row(A);
    let shape_id = b.shape.clone().unwrap();
    assert_eq!(a.shape, b.shape, "one shape per run");
    let genuine = w.object(&shape_id);
    let mut forged = Shape::decode(&genuine).unwrap();
    let i = forged
        .entries
        .iter()
        .position(|e| e.path.as_str() == "fixtures/b.json")
        .expect("fixtures/b.json is in the run's shape");
    assert_eq!(forged.entries[i].kind, EntryKind::File);
    forged.entries[i].path = RepoPath::new("fixtures/b.jsonx").unwrap();
    let forged_bytes = forged.encode().expect("still strictly increasing");
    let forged_id = w.add_object(3, &forged_bytes);
    assert_ne!(forged_id, shape_id);

    // (1) B's descriptor names the forged shape.
    w.set_value(&b.key, &b.value_naming_shape(&forged_id));
    let (skip, run) = w.plan();
    assert_eq!(run, set(&[B]), "B runs: {run:?} skip {skip:?}");
    let ex = w.explain(B);
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(ex.contains("entry:fixtures/b.jsonx"), "{ex}");

    // (2) B's value carries A's descriptor (A's set under B's statement).
    let mut f = b.frame();
    f.descriptor = a.frame().descriptor;
    w.set_value(&b.key, f.encode().unwrap().as_bytes());
    let (skip, run) = w.plan();
    assert_eq!(run, set(&[B]), "B runs: {run:?} skip {skip:?}");
    let ex = w.explain(B);
    assert!(ex.contains("failed check: inputs"), "{ex}");
    w.set_value(&b.key, &b.value);
    assert_eq!(w.plan().0, set(UNITS), "B's own value restored");

    // (3) The run's shape replaced in place by the forged bytes: every
    // record naming the id fails on it.
    w.set_object(&shape_id, &forged_bytes);
    let (skip, run) = w.plan();
    assert_eq!(run, set(UNITS), "every unit runs: skip {skip:?}");
    let ex = w.explain(B);
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(ex.contains("corrupt"), "{ex}");
    assert!(ex.contains("its BLAKE3 is"), "{ex}");
    w.set_object(&shape_id, &genuine);
    assert_eq!(w.plan().0, set(UNITS), "restored");
}

/// An hdr with another global manifest under the same id cannot exist: the
/// id is the BLAKE3 of the bytes and the plan recomputes it before it
/// decodes anything. What a writer can do is put other bytes under the id
/// (here the hdr re-encoded with another `globalInputRoot`, which would
/// fail `global-inputs` were it believed): every candidate naming the id
/// fails `statement` as corrupt, and nothing in those bytes is read.
#[test]
fn a_hdr_whose_bytes_are_not_its_id_fails_statement() {
    let w = World::new();
    w.run();
    assert_eq!(w.plan().0, set(UNITS));
    let b = w.row(B);
    let hdr_id = b.hdr.clone().unwrap();
    // The units whose records name the hdr (one per header group: on the
    // vitest adapter the global manifest differs per unit, so usually B
    // alone).
    let naming: BTreeSet<String> = UNITS
        .iter()
        .filter(|u| w.row(u).hdr.as_deref() == Some(hdr_id.as_str()))
        .map(|u| u.to_string())
        .collect();
    assert!(naming.contains(B));
    let genuine = w.object(&hdr_id);
    let mut other = Hdr::decode(&genuine).unwrap();
    other.global_input_root = [0xab; 32];
    let other = other.encode().unwrap();
    assert_ne!(hex32(&object_id(&other)), hdr_id);
    w.set_object(&hdr_id, &other);
    let (skip, run) = w.plan();
    assert_eq!(run, naming, "every unit naming the hdr runs: skip {skip:?}");
    let ex = w.explain(B);
    assert!(ex.contains("failed check: statement"), "{ex}");
    assert!(ex.contains("corrupt"), "{ex}");
    assert!(ex.contains("its BLAKE3 is"), "{ex}");
    assert!(
        !ex.contains("global-inputs"),
        "the bytes were never believed: {ex}"
    );
    w.set_object(&hdr_id, &genuine);
    assert_eq!(w.plan().0, set(UNITS), "restored");
}

/// A record moved under another trusted signer's key segment (its
/// signature is still the trusted key's, so `signature` passes) fails
/// `signer`: the segment must be the signer id of the key that verified,
/// and the other key's signer id is not it.
#[test]
fn a_record_under_another_trusted_signers_segment_fails_signer() {
    let w = World::new();
    w.run();
    assert_eq!(w.plan().0, set(UNITS));
    let b = w.row(B);
    let mine = signer_id_of(&w.key);
    let other = signer_id_of(&w.other_key);
    assert_eq!(b.signer, mine, "the run's key segment is its signer id");
    assert_ne!(mine, other);
    let moved = b
        .key
        .replacen(&format!(":{mine}:"), &format!(":{other}:"), 1);
    assert_ne!(moved, b.key);
    let n = w
        .db()
        .execute(
            "UPDATE attestations SET key = ?2, signer = ?3 WHERE key = ?1",
            rusqlite::params![b.key, moved, other],
        )
        .unwrap();
    assert_eq!(n, 1);
    let (skip, run) = w.plan();
    assert_eq!(run, set(&[B]), "B runs: {run:?} skip {skip:?}");
    let ex = w.explain(B);
    assert!(ex.contains("failed check: signer"), "{ex}");
    assert!(
        ex.contains("signer id (the store key's signer segment)")
            && ex.contains(&format!("{mine} (the signer id of the verified key)")),
        "the check's text names the segment and the verified key's id: {ex}"
    );
    assert!(ex.contains(&other), "{ex}");
    assert!(ex.contains(&mine), "{ex}");
    assert!(
        !ex.contains("failed check: signature"),
        "the signature itself holds: {ex}"
    );
    w.db()
        .execute(
            "UPDATE attestations SET key = ?2, signer = ?3 WHERE key = ?1",
            rusqlite::params![moved, b.key, mine],
        )
        .unwrap();
    assert_eq!(w.plan().0, set(UNITS), "restored");
}

/// A vci 2.8 that reuses a slot holding a format-3 row writes its format-1
/// value beside the slot's format-3 columns (M2 fact 1). The plan tells the
/// value by its first byte and never by the columns: B is planned through
/// the format-1 path from its own statement and manifest, skips while its
/// inputs are unchanged and runs once they change, with format 1's entry
/// text (the attested hash from the manifest, no unsigned label), whatever
/// the stale columns name. Skipped without `VCI_TEST_VCI_2_8`.
#[test]
fn a_2_8_value_in_a_format_3_slot_is_planned_from_its_own_statement() {
    let Some(old) = std::env::var_os("VCI_TEST_VCI_2_8").map(PathBuf::from) else {
        eprintln!("SKIPPED: VCI_TEST_VCI_2_8 names no vci 2.8 binary");
        return;
    };
    let out = Command::new(&old).arg("--version").output().unwrap();
    let v = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    assert!(v.starts_with("vci 2.8."), "VCI_TEST_VCI_2_8 says {v:?}");
    let w = World::new();
    w.run();
    assert_eq!(w.plan().0, set(UNITS));
    let before = w.row(B);
    assert_eq!(before.format, Some(3));
    let key = w.key.to_str().unwrap().to_owned();
    let out = w.command(Command::new(&old), &["run", B, "--key", &key], SQLITE);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let tk = vci_core::test_key(B);
    let rows: i64 = w
        .db()
        .query_row(
            "SELECT count(*) FROM attestations WHERE test_key = ?1",
            [&tk],
            |r| r.get(0),
        )
        .unwrap();
    eprintln!("rows of B after the 2.8 run: {rows} (1: 2.8 reused the format-3 slot)");
    if rows != 1 {
        // 2.8 keyed another slot (its storage key is not this vci's): put
        // its value into the format-3 row and drop its own, which is the
        // state a reused slot is in.
        let old_value: Vec<u8> = w
            .db()
            .query_row(
                "SELECT value FROM attestations WHERE test_key = ?1 AND key != ?2",
                [&tk, &before.key],
                |r| r.get(0),
            )
            .unwrap();
        w.db()
            .execute(
                "DELETE FROM attestations WHERE test_key = ?1 AND key != ?2",
                [&tk, &before.key],
            )
            .unwrap();
        w.set_value(&before.key, &old_value);
    }
    let after = w.row(B);
    assert_eq!(
        after.value.first(),
        Some(&b'{'),
        "a format-1 value in the slot"
    );
    assert_eq!(after.format, Some(3), "the slot's columns stay");
    assert_eq!(after.hdr, before.hdr);
    assert_eq!(after.shape, before.shape);
    assert_eq!(after.state_obj, before.state_obj);
    assert_eq!(w.plan().0, set(UNITS), "B skips through the format-1 path");
    let ex = w.explain(B);
    assert!(ex.contains("all checks passed"), "{ex}");

    let original = w.read("fixtures/b.json");
    w.write("fixtures/b.json", "{ \"greeting\": \"hello, world\" }\n");
    let (skip, run) = w.plan();
    assert_eq!(run, set(&[B]), "B runs: {run:?} skip {skip:?}");
    let ex = w.explain(B);
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(ex.contains("entry:fixtures/b.json"), "{ex}");
    assert!(
        ex.contains(&vci_core::blake3_hex(original.as_bytes())),
        "format 1 prints the attested hash from its manifest: {ex}"
    );
    assert!(!ex.contains(UNSIGNED_LABEL), "{ex}");
    assert!(!ex.contains(HASH_NOT_LOADED), "{ex}");
    w.write("fixtures/b.json", &original);
    assert_eq!(w.plan().0, set(UNITS), "restored");
}

/// A shape of about `target` bytes (never over it) whose entries are
/// paths no checkout has.
fn decoy_shape(target: usize) -> Vec<u8> {
    let entry = |i: usize| ShapeEntry {
        path: RepoPath::new(&format!("p/{}", vci_core::blake3_hex(&i.to_le_bytes()))).unwrap(),
        kind: EntryKind::File,
        exec: false,
    };
    let encode = |n: usize| -> Vec<u8> {
        let mut entries: Vec<ShapeEntry> = (0..n).map(entry).collect();
        entries.sort();
        entries.dedup();
        Shape {
            entries,
            groups: vec![],
        }
        .encode()
        .unwrap()
    };
    let probe = 20_000;
    let per = encode(probe).len() as f64 / probe as f64;
    let mut n = (target as f64 / per) as usize;
    let mut bytes = encode(n);
    for _ in 0..32 {
        let len = bytes.len();
        if len > target {
            n -= ((len - target) as f64 / per).ceil() as usize + 1;
        } else if target - len > 2 * per as usize {
            n += ((target - len) as f64 / per).floor() as usize;
        } else {
            break;
        }
        bytes = encode(n);
    }
    assert!(
        bytes.len() <= target && target - bytes.len() < 4 * per as usize,
        "{} for {target}",
        bytes.len()
    );
    bytes
}

/// The verdict-object byte cap is reached in candidate-priority order: two
/// decoy candidates of B (its own record with the descriptor naming a huge
/// shape each, newer by their key hint so they rank first) have their
/// shapes loaded, sized so that the run's real shape would pass the cap;
/// every candidate naming the real shape then fails `inputs` and the four
/// units run (the cap turns a skip into a run, never a run into a skip),
/// the plan counts them, and once the decoys are gone the units skip again.
#[test]
fn verdict_objects_past_the_byte_cap_fail_their_candidates_and_never_skip() {
    let w = World::new();
    w.run();
    let b = w.row(B);
    let shape_id = b.shape.clone().unwrap();
    let real = w.object(&shape_id).len();
    let hdr = w.object(b.hdr.as_deref().unwrap()).len();
    let tables = w.object(b.tables.as_deref().unwrap()).len();
    // Loaded before the real shape: hdr, tables and the two decoys; the
    // real shape must then not fit, while each decoy is under its own
    // size limit.
    let first = decoy_shape(SHAPE_MAX - 64);
    let second = decoy_shape(VERDICT_OBJECT_BYTES - hdr - tables - first.len() - real / 2);
    assert!(second.len() <= SHAPE_MAX);
    let loaded = hdr + tables + first.len() + second.len();
    assert!(
        loaded <= VERDICT_OBJECT_BYTES && loaded + real > VERDICT_OBJECT_BYTES,
        "{loaded} + {real}"
    );
    let (_, hint) = split_hint(&b.key);
    let (_, tree16) = hint.split_once('.').unwrap();
    assert_eq!(Some(tree16), b.tree16.as_deref());
    let mut decoys = Vec::new();
    for (i, bytes) in [first, second].iter().enumerate() {
        let id = w.add_object(3, bytes);
        let sk = vci_core::blake3_hex(&[i as u8; 8]);
        let issued = b.issued.unwrap() + 1000 + i as i64;
        let key = format!(
            "vci:attestation:{}:{}:{}:{:x}.{}",
            vci_core::test_key(B),
            b.signer,
            sk,
            issued,
            tree16
        );
        let n = w
            .db()
            .execute(
                "INSERT INTO attestations (key, test_key, signer, storage_key, target, issued, tree16, manifest_ref,
                   ref_state, stored_at, encoding, value, format, commit_id, platform, state, duration_ms, expires,
                   hdr, tables_id, shape, state_obj)
                 SELECT ?1, test_key, signer, ?2, target, ?3, tree16, manifest_ref, ref_state, stored_at, encoding,
                   ?4, format, commit_id, platform, state, duration_ms, expires, hdr, tables_id, ?5, state_obj
                 FROM attestations WHERE key = ?6",
                rusqlite::params![key, sk, issued, b.value_naming_shape(&id), id, b.key],
            )
            .unwrap();
        assert_eq!(n, 1);
        decoys.push((key, id));
    }
    let (skip, run, stderr) = w.plan_with(&[("VCI_TIMING", "1")]);
    assert_eq!(run, set(UNITS), "every unit runs: skip {skip:?}");
    let metrics = stderr
        .lines()
        .find(|l| l.contains("candidate(s) past the cap"))
        .unwrap_or_else(|| panic!("no objects line in:\n{stderr}"));
    assert!(metrics.contains("4 candidate(s) past the cap"), "{metrics}");
    assert!(metrics.contains("2 shape"), "{metrics}");
    let ex = w.explain(B);
    assert!(ex.contains("verdict-object cap"), "{ex}");
    assert!(!ex.contains("all checks passed"), "{ex}");
    for (key, id) in &decoys {
        w.db()
            .execute("DELETE FROM attestations WHERE key = ?1", [key])
            .unwrap();
        w.db()
            .execute("DELETE FROM objects WHERE id = ?1", [id])
            .unwrap();
    }
    let (skip, _, stderr) = w.plan_with(&[("VCI_TIMING", "1")]);
    assert_eq!(skip, set(UNITS), "the decoys gone, every unit skips");
    assert!(stderr.contains("0 candidate(s) past the cap"), "{stderr}");
}
