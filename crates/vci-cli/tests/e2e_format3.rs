//! The plan over a store format 3 record (STORE-V2 section 1.5): a unit's
//! format-1 attestation, as `vci run` 2.8 stores it (here `vci run` with
//! `record_format = 1`), is rewritten by the test into the four objects of
//! section 1.3, a v2 statement signed by the
//! same key and the text frame of section 1.2 (exactly what `vci run` 2.9
//! writes once run.rs is on format 3), and `vci plan` must then skip the
//! unit from the frame alone, name the entry that changed when its fixture
//! is edited, and refuse the record once it sits under another signer's
//! slot. On git-meta (no columns, so no state object) the entry's attested
//! hash is reported as not loaded; on SQLite (columns name the state
//! object) it is printed with the unsigned label.
//!
//! Needs `node`, `git` and `ssh-keygen` on PATH, and the fixture's
//! `node_modules` installed (`npm ci` in fixtures/vitest-abcd).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use assert_cmd::cargo::CommandCargoExt;
use camino::Utf8Path;
use serde_json::Value;
use vci_attest::{Envelope, Frame, FrameExt, SshSigner, Statement, Subject};
use vci_core::{
    Encoded, InputManifest, ObjectKind, PREDICATE_TYPE, PREDICATE_TYPE_V2, Run, UnitInputs,
    VciPredicate, objects::hex32, sorted_compact_json,
};
use vci_git::{GitMetaStore, Repo};
use vci_store::{AttestationStore, Columns, KeyHint, NewAttestation, NewObject, Record};
use vci_store_sqlite::{SqliteOptions, SqliteStore};

const B: &str = "src/b.test.ts";
const ANOTHER_SIGNER: &str = "0123456789abcdef";

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
    key: PathBuf,
    gitconfig: PathBuf,
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
        std::fs::write(work.join(".gitignore"), "node_modules/\n.vci/out/\n").unwrap();
        std::fs::write(work.join("vci.toml"), VCI_TOML).unwrap();
        std::fs::create_dir_all(work.join(".vci")).unwrap();
        std::fs::write(
            work.join(".vci/allowed_signers"),
            format!("trusted@example.com namespaces=\"vci-attest\" {pubkey}\n"),
        )
        .unwrap();
        w.git(&work, &["add", "-A"]);
        w.git(&work, &["commit", "-q", "-m", "base commit"]);
        w.git(&work, &["checkout", "-q", "-b", "feature"]);
        w
    }

    fn git(&self, dir: &Path, args: &[&str]) {
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
    }

    fn vci(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::cargo_bin("vci").unwrap();
        cmd.current_dir(&self.work)
            .args(args)
            .env("VCI_JS_PLUGIN", workspace_root().join("js/vitest-plugin"))
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("NO_COLOR", "1");
        for k in [
            "VCI_BASE_REF",
            "GITHUB_BASE_REF",
            "GITHUB_REF",
            "GITHUB_OUTPUT",
            "VCI_SIGNING_KEY",
            "VCI_OUT",
            "NODE_OPTIONS",
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
            "$ vci {}\n{}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    fn vci_ok(&self, args: &[&str], env: &[(&str, &str)]) -> String {
        let out = self.vci(args, env);
        assert!(
            out.status.success(),
            "vci {args:?} exited {:?}",
            out.status.code()
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// `vci run B` writing a format-1 record (`record_format = 1`: what
    /// `vci run` 2.8 stores, which [`rewrite_as_format3`] then rewrites by
    /// hand; a run under the format-3 default would store the frame
    /// itself).
    fn run(&self, env: &[(&str, &str)]) {
        let env = [env, &[("VCI_STORE_RECORD_FORMAT", "1")]].concat();
        self.vci_ok(&["run", B, "--key", self.key.to_str().unwrap()], &env);
    }

    /// (skipped, run) of `vci plan --base-ref main`.
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

    fn explain(&self, env: &[(&str, &str)]) -> String {
        self.vci_ok(&["explain", B, "--base-ref", "main"], env)
    }

    fn write(&self, rel: &str, content: &str) {
        std::fs::write(self.work.join(rel), content).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.work.join(rel)).unwrap()
    }
}

/// The format-3 record of unit `B`'s stored format-1 attestation: its
/// objects put into `store`, and the frame returned with the slot (signer
/// and storage key) and hint of the format-1 record and the columns a 2.9
/// writer would store beside it.
struct Rewritten {
    frame: Vec<u8>,
    signer: String,
    storage_key: String,
    hint: KeyHint,
    columns: Columns,
    /// The attested hash of fixtures/b.json, from the manifest.
    attested_b_json: String,
}

fn rewrite_as_format3(store: &dyn AttestationStore, key: &Path) -> Rewritten {
    let mut listed = store.list_units(&[B]).unwrap().remove(0);
    assert_eq!(listed.len(), 1, "one format-1 record of B");
    let mut refs: Vec<&mut vci_store::StoredEnvelope> = listed.iter_mut().collect();
    store.read_values(&mut refs).unwrap();
    let stored = listed.remove(0);
    assert!(stored.error.is_none(), "{:?}", stored.error);
    assert!(
        matches!(
            vci_store::decode_record(&stored.bytes),
            Ok(Record::FormatOne(_))
        ),
        "vci run wrote a format-1 record"
    );
    let envelope = Envelope::from_json(&stored.bytes).unwrap();
    let payload = envelope.payload_bytes().unwrap();
    let st: Statement = serde_json::from_slice(&payload).unwrap();
    assert_eq!(st.predicate_type, PREDICATE_TYPE);
    let p: VciPredicate = serde_json::from_value(st.predicate.clone()).unwrap();
    // The whole manifest (its base put back), as the run's unit saw it.
    let root = p
        .core
        .manifest_ref
        .clone()
        .expect("a manifest by reference");
    let m = store.manifest(&root).unwrap().expect("the manifest");
    let manifest = InputManifest::from_compact_with(&m.bytes, |b| {
        Ok(store.manifest(b).unwrap().expect("the base").bytes)
    })
    .unwrap();
    assert_eq!(manifest.root(), p.core.input_root);
    let attested_b_json = manifest
        .entries
        .iter()
        .find(|e| e.path.as_str() == "fixtures/b.json")
        .expect("b.json is an input of B")
        .hash
        .clone();
    // Section 1.4 steps 2 and 3: the objects, the v2 statement, the frame.
    let hdr = p.hdr().unwrap();
    let hdr = Encoded::new(hdr.clone(), hdr.encode().unwrap());
    let run = Run::build(&[UnitInputs {
        header: 0,
        group: None,
        manifest: &manifest,
        waived: &p.waived,
    }])
    .unwrap();
    let tables = &run.tables[0];
    let v2 = p
        .to_v2(&hdr.id, &tables.id, &tables.value, &manifest.entries_root())
        .unwrap();
    let mut digest = std::collections::BTreeMap::new();
    digest.insert("blake3".to_owned(), p.core.input_root.clone());
    let statement = Statement::new(
        vec![Subject {
            name: p.core.test_id.clone(),
            digest,
        }],
        PREDICATE_TYPE_V2,
        serde_json::to_value(&v2).unwrap(),
    );
    let statement = sorted_compact_json(&statement).unwrap();
    let signed = SshSigner::load(Utf8Path::from_path(key).unwrap())
        .sign_payload(statement.as_bytes())
        .unwrap();
    let descriptor = run.units[0].descriptor.encode(&tables.value).unwrap();
    let frame = Frame::from_envelope(&signed, descriptor).unwrap();
    let frame = frame.encode().unwrap().into_bytes();
    let objects = [
        NewObject::new(ObjectKind::Hdr, &hdr.bytes),
        NewObject::new(ObjectKind::Tables, &tables.bytes),
        NewObject::new(ObjectKind::Shape, &run.shape.bytes),
        NewObject::new(ObjectKind::State, &run.state.bytes),
    ];
    store.put_objects(&objects).unwrap();
    let columns = Columns {
        format: Some(3),
        commit: Some(p.core.commit.clone()),
        platform: Some(format!("{}-{}", p.core.toolchain.os, p.core.toolchain.arch)),
        state: Some(p.core.result.state.clone()),
        hdr: Some(hex32(&hdr.id)),
        tables: Some(hex32(&tables.id)),
        shape: Some(hex32(&run.shape.id)),
        state_obj: Some(hex32(&run.state.id)),
        ..Columns::default()
    };
    Rewritten {
        frame,
        signer: stored.signer.clone(),
        storage_key: stored.storage_key.clone(),
        hint: KeyHint {
            issued: stored.issued.unwrap_or(0),
            tree: stored.tree.clone(),
        },
        columns,
        attested_b_json,
    }
}

/// Put the frame under its slot (replacing the format-1 record there).
fn put(store: &dyn AttestationStore, r: &Rewritten, signer: &str) {
    let att = NewAttestation::for_test(B, signer, &r.storage_key, Some(&r.hint), &r.frame)
        .with_columns(&r.columns);
    store.put(&att).unwrap();
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

/// git-meta: the frame alone skips the unit; an edited fixture runs it with
/// the entry named and its attested hash reported as not loaded (no
/// columns, so no state object); the record under another signer's slot
/// fails `signer`.
#[test]
fn a_format3_record_on_git_meta_skips_names_the_entry_and_needs_its_signer() {
    let w = World::new();
    w.run(&[]);
    assert_eq!(w.plan(&[]).0, set(&[B]), "the format-1 record skips B");
    let store = GitMetaStore::new(Repo::discover(Utf8Path::from_path(&w.work).unwrap()).unwrap());
    let r = rewrite_as_format3(&store, &w.key);
    put(&store, &r, &r.signer);
    let listed = store.list_units(&[B]).unwrap().remove(0);
    assert_eq!(listed.len(), 1, "the frame took the format-1 record's slot");

    assert_eq!(w.plan(&[]).0, set(&[B]), "the frame skips B");
    let ex = w.explain(&[]);
    assert!(ex.contains("all checks passed"), "{ex}");
    assert!(ex.contains("signer: trusted@example.com"), "{ex}");

    // The fixture edited: B runs on its inputs (an `entry:` detail, which
    // round 2 keys on). git-meta keeps no columns, so no state object names
    // the attested hashes and the entry that changed cannot be told from
    // the others: the text says so, with both roots.
    let original = w.read("fixtures/b.json");
    w.write("fixtures/b.json", "{ \"greeting\": \"hello, world\" }\n");
    let (skip, run) = w.plan(&[]);
    assert!(run.contains(B) && !skip.contains(B), "B runs: {run:?}");
    let ex = w.explain(&[]);
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(
        ex.contains("entry: changed (attested hash not loaded)"),
        "{ex}"
    );
    assert!(
        !ex.contains(&r.attested_b_json),
        "no attested hash without a state object: {ex}"
    );
    // A file gone is told apart by its kind, without any hash.
    std::fs::remove_file(w.work.join("fixtures/b.json")).unwrap();
    let (skip, run) = w.plan(&[]);
    assert!(run.contains(B) && !skip.contains(B), "B runs: {run:?}");
    let ex = w.explain(&[]);
    assert!(ex.contains("entry:fixtures/b.json"), "{ex}");
    assert!(
        ex.contains("file exec=false changed (attested hash not loaded)"),
        "{ex}"
    );
    assert!(ex.contains("actual:   absent"), "{ex}");
    w.write("fixtures/b.json", &original);
    assert_eq!(w.plan(&[]).0, set(&[B]), "restored");

    // The same record under another signer's slot: the signature is that
    // signer's, the slot is not.
    store.remove(listed).unwrap();
    put(&store, &r, ANOTHER_SIGNER);
    let (skip, run) = w.plan(&[]);
    assert!(run.contains(B) && !skip.contains(B), "B runs: {run:?}");
    let ex = w.explain(&[]);
    assert!(ex.contains("failed check: signer"), "{ex}");
    assert!(ex.contains(ANOTHER_SIGNER), "{ex}");
    assert!(ex.contains(&r.signer), "{ex}");
}

/// SQLite: the same, with the columns naming the run's state object, so
/// that the attested hash of the edited entry is printed with the unsigned
/// label.
#[test]
fn a_format3_record_on_sqlite_prints_the_attested_hash_unsigned() {
    let w = World::new();
    let env = [("VCI_STORE", "sqlite")];
    w.run(&env);
    assert_eq!(w.plan(&env).0, set(&[B]), "the format-1 record skips B");
    let store = SqliteStore::open_path(
        w.work.join(".git/vci-store.sqlite"),
        SqliteOptions::default(),
    );
    store.upgrade_begin().unwrap();
    let r = rewrite_as_format3(&store, &w.key);
    put(&store, &r, &r.signer);
    assert_eq!(w.plan(&env).0, set(&[B]), "the frame skips B");

    let original = w.read("fixtures/b.json");
    w.write("fixtures/b.json", "{ \"greeting\": \"hello, world\" }\n");
    let (skip, run) = w.plan(&env);
    assert!(run.contains(B) && !skip.contains(B), "B runs: {run:?}");
    let ex = w.explain(&env);
    assert!(ex.contains("failed check: inputs"), "{ex}");
    assert!(ex.contains("entry:fixtures/b.json"), "{ex}");
    assert!(
        ex.contains("attested (unsigned, from the run's state object)"),
        "{ex}"
    );
    assert!(ex.contains(&r.attested_b_json), "the attested hash: {ex}");
    assert!(
        ex.contains(&vci_core::blake3_hex(w.read("fixtures/b.json").as_bytes())),
        "the observed hash: {ex}"
    );
    assert!(!ex.contains("attested hash not loaded"), "{ex}");
    w.write("fixtures/b.json", &original);
    assert_eq!(w.plan(&env).0, set(&[B]), "restored");
}
