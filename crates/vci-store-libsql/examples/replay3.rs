//! MEASUREMENT ONLY (docs/design/measure/sqld/writes, docs/design/STORE-V2.md
//! section 10; not part of vci): replay a vex-sized
//! partition of real units (`pairs.json`) into a libSQL namespace through
//! the store's batch the way `vci run` drives it, in store format 3
//! (objects first, then records with columns) or format 1 (manifest, then
//! envelope), and the same units again at a "moved-on" commit (new storage
//! keys: supersession removes the old records, then the orphan pass).
//!
//! Modes (every one opens `$VCI_STORE_URL`, remote, no token):
//!   write     FMT NS LABEL PAIRS START COUNT      the first run (seed 1)
//!   supersede FMT NS LABEL PAIRS START COUNT      the second run (seed 2)
//! One JSON line on stdout; `VCI_TIMING=1` makes the store report its
//! batches on stderr.
//!
//! Built with `cargo build --release -p vci-store-libsql --example replay3`
//! and driven by `docs/design/measure/sqld/writes/run.sh` against a local
//! `sqld` started by that script; `PAIRS` is a `{"pairs": [[envelope JSON,
//! compact manifest JSON, root hex], ...]}` file such as `mkpairs.py` writes
//! from the private vex sample. Never point it at a shared server.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use base64::Engine as _;
use vci_attest::FrameExt as _;
use vci_core::ObjectKind;
use vci_store::select::LibsqlMode;
use vci_store::{AttestationStore, Columns, KeyHint, NewAttestation, NewObject, StoredEnvelope};
use vci_store_libsql::{LibsqlStore, testkit};

const S1: &str = "1111111111111111";

struct Unit {
    test_id: String,
    env_json: String,
    man_json: String,
    root: String,
    envelope: vci_attest::Envelope,
    pred: vci_core::VciPredicate,
    subject: String,
    manifest: vci_core::InputManifest,
    base: Option<String>,
}

/// `count` units of the largest run in `path`, from `start` wrapping, each
/// named `{label}/{test_id}`; at a `seed` other than 1 the files have
/// "changed": every 50th entry's hash (format 3's state differs, the shape
/// does not) and, for format 1, the manifest root the envelope names.
fn load(path: &str, start: usize, count: usize, label: &str, seed: u8, fmt: u8) -> Vec<Unit> {
    let data = std::fs::read(path).expect("pairs readable");
    let json: serde_json::Value = serde_json::from_slice(&data).expect("pairs JSON");
    let mut runs: BTreeMap<(String, String, String, String), Vec<Unit>> = BTreeMap::new();
    for p in json["pairs"].as_array().expect("a pairs array") {
        let s = |i: usize| p[i].as_str().expect("a string").to_owned();
        let (env_s, man_s, root) = (s(0), s(1), s(2));
        let envelope = vci_attest::Envelope::from_json(env_s.as_bytes()).expect("envelope");
        let payload = envelope.payload_bytes().expect("payload");
        let statement: vci_attest::Statement = serde_json::from_slice(&payload).expect("statement");
        let pred: vci_core::VciPredicate =
            serde_json::from_value(statement.predicate.clone()).expect("predicate");
        let subject = statement.subject[0].digest["blake3"].clone();
        let mut compact: serde_json::Value = serde_json::from_str(&man_s).expect("manifest");
        let base = compact
            .as_object_mut()
            .unwrap()
            .remove("base")
            .map(|b| b.as_str().unwrap().to_owned());
        let manifest =
            vci_core::InputManifest::from_compact(&serde_json::to_vec(&compact).unwrap()).unwrap();
        let k = (
            pred.core.commit.clone(),
            pred.core.issued_at.clone(),
            pred.project_name.clone(),
            pred.core.adapter.clone(),
        );
        runs.entry(k).or_default().push(Unit {
            test_id: pred.core.test_id.clone(),
            env_json: env_s,
            man_json: man_s,
            root,
            envelope,
            pred,
            subject,
            manifest,
            base,
        });
    }
    let (_, run) = runs.into_iter().max_by_key(|(_, u)| u.len()).unwrap();
    let n = run.len();
    let mut out = Vec::with_capacity(count);
    for j in 0..count {
        let src = &run[(start + j) % n];
        let test_id = format!("{label}/{}", src.test_id);
        let mut manifest = src.manifest.clone();
        let mut root = src.root.clone();
        let mut env_json = src.env_json.clone();
        if seed != 1 {
            for (i, e) in manifest.entries.iter_mut().enumerate() {
                if i % 50 == 0 && e.kind == vci_core::EntryKind::File {
                    e.hash = vci_core::blake3_hex(format!("{seed}:{}", e.hash).as_bytes());
                }
            }
            root = vci_core::blake3_hex(format!("{seed}:{root}").as_bytes());
            if fmt == 1 {
                // The envelope names the new root (unsigned: a measurement).
                let mut env: serde_json::Value = serde_json::from_str(&env_json).unwrap();
                let b64 = base64::engine::general_purpose::STANDARD;
                let payload = b64.decode(env["payload"].as_str().unwrap()).unwrap();
                let mut st: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                st["predicate"]["manifestRef"] = serde_json::Value::String(root.clone());
                env["payload"] = serde_json::Value::String(b64.encode(st.to_string()));
                env_json = env.to_string();
            }
        }
        let envelope = vci_attest::Envelope::from_json(env_json.as_bytes()).unwrap();
        out.push(Unit {
            test_id,
            env_json,
            man_json: src.man_json.clone(),
            root,
            envelope,
            pred: src.pred.clone(),
            subject: src.subject.clone(),
            manifest,
            base: src.base.clone(),
        });
    }
    out
}

type Built = (
    Vec<(ObjectKind, Vec<u8>)>,
    Vec<(String, String, Vec<u8>, Columns)>,
);

/// The run's objects and format-3 records (STORE-V2 section 1.4), as
/// format3.rs's measurement builds them.
fn build3(units: &[Unit], seed: u8) -> Built {
    let mut hdrs: Vec<vci_core::Encoded<vci_core::Hdr>> = Vec::new();
    let mut headers = Vec::new();
    for u in units {
        let h = u.pred.hdr().unwrap();
        let bytes = h.encode().unwrap();
        let i = hdrs
            .iter()
            .position(|x| x.bytes == bytes)
            .unwrap_or_else(|| {
                hdrs.push(vci_core::Encoded::new(h, bytes));
                hdrs.len() - 1
            });
        headers.push(i);
    }
    let inputs: Vec<vci_core::UnitInputs<'_>> = units
        .iter()
        .zip(&headers)
        .map(|(u, &header)| vci_core::UnitInputs {
            header,
            group: u.base.as_deref(),
            manifest: &u.manifest,
            waived: &u.pred.waived,
        })
        .collect();
    let run = vci_core::Run::build(&inputs).unwrap();
    let mut objects: Vec<(ObjectKind, Vec<u8>)> = hdrs
        .iter()
        .map(|h| (ObjectKind::Hdr, h.bytes.clone()))
        .collect();
    objects.extend(
        run.tables
            .iter()
            .map(|t| (ObjectKind::Tables, t.bytes.clone())),
    );
    objects.push((ObjectKind::Shape, run.shape.bytes.clone()));
    objects.push((ObjectKind::State, run.state.bytes.clone()));
    let shape_id = vci_core::objects::hex32(&run.shape.id);
    let state_id = vci_core::objects::hex32(&run.state.id);
    let mut records = Vec::new();
    for ((u, rec), &header) in units.iter().zip(&run.units).zip(&headers) {
        let h = &hdrs[header];
        let t = &run.tables[header];
        let v2 = u
            .pred
            .to_v2(&h.id, &t.id, &t.value, &u.manifest.entries_root())
            .unwrap();
        let statement = vci_attest::Statement::new(
            vec![vci_attest::Subject {
                name: u.test_id.clone(),
                digest: BTreeMap::from([("blake3".to_owned(), u.subject.clone())]),
            }],
            vci_core::PREDICATE_TYPE_V2,
            serde_json::to_value(&v2).unwrap(),
        );
        let statement = vci_core::sorted_compact_json(&statement)
            .unwrap()
            .into_bytes();
        let descriptor = rec.descriptor.encode(&t.value).unwrap();
        let mut frame = vci_attest::Frame::from_envelope(&u.envelope, descriptor).unwrap();
        frame.statement = statement;
        let record = frame.encode().unwrap().into_bytes();
        let columns = Columns {
            format: Some(3),
            commit: Some(u.pred.core.commit.clone()),
            platform: Some(format!(
                "{}-{}",
                u.pred.core.toolchain.os, u.pred.core.toolchain.arch
            )),
            state: Some(u.pred.core.result.state.clone()),
            duration_ms: Some(u.pred.core.result.duration_ms),
            expires: None,
            hdr: Some(vci_core::objects::hex32(&h.id)),
            tables: Some(vci_core::objects::hex32(&t.id)),
            shape: Some(shape_id.clone()),
            state_obj: Some(state_id.clone()),
        };
        let storage_key =
            vci_core::blake3_hex(format!("{seed}:{}", u.pred.core.input_root).as_bytes());
        records.push((u.test_id.clone(), storage_key, record, columns));
    }
    (objects, records)
}

fn open(ns: &str) -> LibsqlStore {
    let url = std::env::var("VCI_STORE_URL").expect("VCI_STORE_URL");
    assert!(url.starts_with("http://127.0.0.1:"), "a local sqld only");
    assert!(std::env::var("VCI_STORE_TOKEN").is_err(), "no token");
    let s = testkit::selection(LibsqlMode::Remote, Some(&url), None, Some(ns), None);
    LibsqlStore::open(&s, &testkit::cx()).expect("open")
}

fn hint(now: i64) -> KeyHint {
    KeyHint {
        issued: now,
        tree: Some("0123456789abcdef".to_owned()),
    }
}

fn finish(b: vci_store::WriteBatch) -> (usize, Option<String>) {
    match b.finish_partial() {
        Ok(f) => {
            let n = f.lost_count();
            (n, f.into_error().map(|e| e.to_string()))
        }
        Err(e) => (usize::MAX, Some(e.to_string())),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a[1] == "prep" {
        // prep NS: make the namespace (its tables) before the writers
        // start, as it exists in production; one flag row.
        let s = open(&a[2]);
        s.status().expect("status");
        s.set_flag("measure-prep");
        println!(
            "{}",
            serde_json::json!({"mode": "prep", "ns": a[2], "requests": s.requests()})
        );
        return;
    }
    let (mode, fmt, ns, label, pairs) = (&a[1], a[2].parse::<u8>().unwrap(), &a[3], &a[4], &a[5]);
    let (start, count): (usize, usize) = (a[6].parse().unwrap(), a[7].parse().unwrap());
    let seed: u8 = if mode == "write" { 1 } else { 2 };
    let units = load(pairs, start, count, label, seed, fmt);
    let s = open(ns);
    s.status().expect("status");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (objects, records) = if fmt == 3 {
        build3(&units, seed)
    } else {
        (Vec::new(), Vec::new())
    };
    let object_bytes: usize = objects.iter().map(|(_, b)| b.len()).sum();
    let record_bytes: usize = if fmt == 3 {
        records.iter().map(|(_, _, r, _)| r.len()).sum()
    } else {
        units.iter().map(|u| u.env_json.len()).sum()
    };
    let manifest_bytes: usize = if fmt == 1 {
        units.iter().map(|u| u.man_json.len()).sum()
    } else {
        0
    };
    let mut out = serde_json::json!({
        "mode": mode, "format": fmt, "label": label, "units": count,
        "objects": objects.len(), "object_bytes": object_bytes,
        "record_bytes": record_bytes, "manifest_bytes": manifest_bytes,
    });

    // The second run: what supersession reads first, as run.rs does for
    // the whole run (the listing of its units, their columns, the hdr
    // objects the old records name, then the old values it confirms).
    let mut old_by_unit: BTreeMap<String, Vec<(StoredEnvelope, Columns)>> = BTreeMap::new();
    if mode == "supersede" {
        let t = Instant::now();
        let (req0, ret0) = (s.requests(), s.retries());
        let ids: Vec<&str> = units.iter().map(|u| u.test_id.as_str()).collect();
        let listed = s.list_units(&ids).expect("list the units");
        // The listing answers per unit asked, in order: the unit of each
        // old record by index (a test key is derived from the id).
        let unit_of: Vec<String> = listed
            .iter()
            .zip(&units)
            .flat_map(|(l, u)| std::iter::repeat_n(u.test_id.clone(), l.len()))
            .collect();
        let mut old: Vec<StoredEnvelope> = listed.into_iter().flatten().collect();
        let refs: Vec<&StoredEnvelope> = old.iter().collect();
        let cols = s.columns(&refs).expect("columns");
        let hdr_ids: BTreeSet<&str> = cols.iter().filter_map(|c| c.hdr.as_deref()).collect();
        let mut hdr_objects = 0;
        if !hdr_ids.is_empty() {
            let v: Vec<&str> = hdr_ids.iter().copied().collect();
            hdr_objects = s.get_objects(&v).expect("hdr objects").len();
        }
        {
            let mut refs: Vec<&mut StoredEnvelope> = old.iter_mut().collect();
            s.read_values(&mut refs).expect("old values");
        }
        let old_bytes: usize = old.iter().map(|e| e.bytes.len()).sum();
        let n_old = old.len();
        for ((e, c), unit) in old.into_iter().zip(cols).zip(unit_of) {
            old_by_unit.entry(unit).or_default().push((e, c));
        }
        out["find_secs"] = t.elapsed().as_secs_f64().into();
        out["find_requests"] = (s.requests() - req0).into();
        out["find_retries"] = (s.retries() - ret0).into();
        out["old_records"] = n_old.into();
        out["old_bytes_read"] = old_bytes.into();
        out["old_hdr_objects"] = hdr_objects.into();
    }

    // The write: objects (format 3) or manifests (format 1) ahead of the
    // records that name them, and the removals of what each supersedes.
    let (txs0, stored0, sql0) = s.written();
    let (req0, ret0) = (s.requests(), s.retries());
    let t0 = Instant::now();
    let b = s.batch().unwrap();
    let mut objects_new = 0;
    if fmt == 3 {
        let news: Vec<NewObject<'_>> = objects.iter().map(|(k, b)| NewObject::new(*k, b)).collect();
        objects_new = s.put_objects(&news).expect("put objects");
    }
    let mut dropped_objects: BTreeSet<String> = BTreeSet::new();
    let mut dropped_roots: BTreeSet<String> = BTreeSet::new();
    let mut doomed_total = 0usize;
    let mut removed_total = 0usize;
    let mut remove_errors = 0usize;
    let hint = hint(now);
    for (i, u) in units.iter().enumerate() {
        let stored = if fmt == 3 {
            let (unit, sk, rec, cols) = &records[i];
            s.put(&NewAttestation::for_test(unit, S1, sk, Some(&hint), rec).with_columns(cols))
                .expect("put a format-3 record")
        } else {
            s.put_manifest(&u.root, u.man_json.as_bytes())
                .expect("put the manifest");
            let sk = vci_core::blake3_hex(format!("{seed}:{}", u.pred.core.input_root).as_bytes());
            s.put_for_test(&u.test_id, S1, &sk, Some(&hint), u.env_json.as_bytes())
                .expect("put a format-1 record")
        };
        if let Some(olds) = old_by_unit.remove(&u.test_id) {
            let mut doomed = Vec::new();
            for (e, c) in olds {
                if e.key == stored.key {
                    continue;
                }
                dropped_objects.extend(c.object_ids().map(str::to_owned));
                if fmt == 1 {
                    // run.rs takes the root from the old envelope's manifestRef.
                    if let Some(r) = manifest_ref(&e.bytes) {
                        dropped_roots.insert(r);
                    }
                }
                doomed.push(e);
            }
            doomed_total += doomed.len();
            if !doomed.is_empty() {
                match s.remove(doomed) {
                    Ok(r) => removed_total += r.len(),
                    Err(_) => remove_errors += 1,
                }
            }
        }
    }
    let queued = t0.elapsed().as_secs_f64();
    let (lost, err) = finish(b);
    let secs = t0.elapsed().as_secs_f64();
    let (txs, stored_b, sql) = s.written();
    out["write_secs"] = secs.into();
    out["queued_secs"] = queued.into();
    out["lost"] = lost.into();
    out["error"] = err.into();
    out["transactions"] = (txs - txs0).into();
    out["stored_literal_bytes"] = (stored_b - stored0).into();
    out["sql_bytes"] = (sql - sql0).into();
    out["write_requests"] = (s.requests() - req0).into();
    out["write_retries"] = (s.retries() - ret0).into();
    out["objects_new"] = objects_new.into();
    out["doomed"] = doomed_total.into();
    out["removed"] = removed_total.into();
    out["remove_errors"] = remove_errors.into();

    // The orphan pass, once per run (run.rs after supersession).
    if mode == "supersede" {
        let (txs0, _, sql0) = s.written();
        let req0 = s.requests();
        let t = Instant::now();
        if fmt == 3 {
            let ids: Vec<&str> = dropped_objects.iter().map(String::as_str).collect();
            let n = s.remove_objects(&ids).expect("remove objects");
            let pruned = s
                .prune_state_objects(std::time::Duration::from_secs(2 * 86_400))
                .expect("prune state");
            out["orphan_candidates"] = ids.len().into();
            out["orphan_objects_removed"] = n.into();
            out["state_objects_pruned"] = pruned.into();
        } else {
            let roots: Vec<&str> = dropped_roots.iter().map(String::as_str).collect();
            let orphans = s.orphan_manifests(&roots).expect("orphan manifests");
            let o: Vec<&str> = orphans.iter().map(String::as_str).collect();
            let n = s.remove_manifests(&o).expect("remove manifests");
            out["orphan_candidates"] = roots.len().into();
            out["orphan_manifests_found"] = orphans.len().into();
            out["orphan_manifests_removed"] = n.into();
        }
        let (txs, _, sql) = s.written();
        out["orphan_secs"] = t.elapsed().as_secs_f64().into();
        out["orphan_requests"] = (s.requests() - req0).into();
        out["orphan_transactions"] = (txs - txs0).into();
        out["orphan_sql_bytes"] = (sql - sql0).into();
    }
    let t = Instant::now();
    let st = s.status();
    out["status_after_ok"] = st.is_ok().into();
    out["status_secs"] = t.elapsed().as_secs_f64().into();
    out["count_after"] = s.count().map(|n| n as i64).unwrap_or(-1).into();
    out["requests_total"] = s.requests().into();
    out["retries_total"] = s.retries().into();
    println!("{out}");
}

/// `predicate.manifestRef` of a format-1 envelope.
fn manifest_ref(bytes: &[u8]) -> Option<String> {
    let env: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(env["payload"].as_str()?)
        .ok()?;
    let st: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    st["predicate"]["manifestRef"].as_str().map(str::to_owned)
}
