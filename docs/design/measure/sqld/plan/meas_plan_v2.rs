//! Measurement harness (not a test of vci): re-signs the 1,175 real vex
//! units of `pairs.json` for a local checkout and writes them into a local
//! sqld, once as format-3 records (store-v2) and once as format-1 records
//! (what vci 2.8.1 stored), so that `vci plan` over that checkout can be
//! timed at vex scale. Gated on `VCI_MEAS_CONFIG` (a JSON file); without it
//! the test does nothing.
//!
//! Per unit: the v1 predicate and the compact manifest are parsed; the
//! manifest's base (not in `pairs.json`) is read from a local copy of the
//! production `manifests` table; the unit's full `(path, kind, exec)` set
//! (base + own) is observed at the checkout through vci-core's
//! `CheckoutCache` exactly as the plan observes it, so that the signed root
//! is the root the plan recomputes; the predicate's commit, tree, times,
//! toolchain (os, arch, superuser and the overrides of the config), global
//! manifest (the attested global paths observed here) and envConfigDigest
//! are rewritten for this machine; the statement is signed with the
//! config's key (vci-attest's SshSigner, as `vci run` signs).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use camino::{Utf8Path, Utf8PathBuf};
use serde_json::{Value, json};
use vci_attest::{Envelope, FrameExt, SshSigner, Statement, Subject};
use vci_core::{
    CheckoutCache, Encoded, EntryKind, Frame, Hdr, InputManifest, ObjectKind, PREDICATE_TYPE,
    PREDICATE_TYPE_V2, RepoPath, ResolvedPredicate, Run, ShapeEntry, Tables, UnitInputs,
    VciPredicate, sorted_compact_json,
};
use vci_store::select::LibsqlMode;
use vci_store::{AttestationStore, Columns, KeyHint, NewAttestation, NewObject};
use vci_store_libsql::{LibsqlStore, testkit};

#[derive(serde::Deserialize)]
struct Config {
    pairs: String,
    proddb: String,
    proddb_prefix: String,
    checkout: String,
    key: String,
    url: String,
    ns3: String,
    ns1: String,
    commit: String,
    tree: String,
    #[serde(default)]
    ttl_days: Option<i64>,
    /// Per project name: {"toolchain": {...partial...}, "envConfigDigest":
    /// "...", "globalPaths": [...]} applied to every unit of the project.
    #[serde(default)]
    overrides: BTreeMap<String, Value>,
    /// Which formats to write: "3", "1" or both.
    #[serde(default)]
    write: Vec<String>,
    out: String,
}

struct Unit {
    index: usize,
    pred: VciPredicate,
    subject_digest: String,
    own: InputManifest,
    base: Option<String>,
    run_key: (String, String, String, String),
}

/// `ctx.rs::storage_key` of store-v2, copied: the slot key over the
/// resolved view (the waived list sorted and distinct).
fn storage_key(p: &ResolvedPredicate<'_>) -> String {
    let tc = p.toolchain();
    let global_input_root = p.global_input_root();
    let env_config_digest = p.env_config_digest();
    let mut parts = vec![
        "vci/storage-key/v1",
        p.repo_id(),
        p.test_id(),
        p.input_root(),
        &global_input_root,
        &env_config_digest,
        tc.node.as_str(),
        tc.vitest.as_str(),
        tc.vite.as_str(),
        tc.os.as_str(),
        tc.arch.as_str(),
    ];
    let argv = p.argv().join("\0");
    parts.push(&argv);
    let dists = if tc.python_dists.is_empty() {
        String::new()
    } else {
        vci_core::blake3_hex(tc.python_dists.join("\n").as_bytes())
    };
    let go_env = if tc.go_env.is_empty() {
        String::new()
    } else {
        vci_core::blake3_hex(tc.go_env.join("\n").as_bytes())
    };
    let platform_specific = p.platform_specific().join("\0");
    let arch_specific = p.arch_specific().join("\0");
    let waived = p.waived_canonical().join("\0");
    let rust_cfg = if tc.rust_cfg.is_empty() {
        String::new()
    } else {
        vci_core::blake3_hex(tc.rust_cfg.join("\n").as_bytes())
    };
    let cfg_predicates = p.cfg_predicates().join("\0");
    let ruby_gems = if tc.ruby_gems.is_empty() {
        String::new()
    } else {
        vci_core::blake3_hex(tc.ruby_gems.join("\n").as_bytes())
    };
    let declared_inputs = p.declared_inputs().join("\0");
    let extra = [
        ("python", tc.python.as_str()),
        ("implementation", tc.implementation.as_str()),
        ("pytest", tc.pytest.as_str()),
        ("python_libs", tc.python_libs.as_str()),
        ("python_dists", &dists),
        ("go", tc.go.as_str()),
        ("go_env", &go_env),
        ("go_arch_level", tc.go_arch_level.as_str()),
        ("platform_specific", &platform_specific),
        ("arch_specific", &arch_specific),
        ("waived", &waived),
        ("rust", tc.rust.as_str()),
        ("cargo", tc.cargo.as_str()),
        ("rust_host", tc.rust_host.as_str()),
        ("rust_cfg", &rust_cfg),
        ("cfg_predicates", &cfg_predicates),
        ("declared_inputs", &declared_inputs),
        ("ruby", tc.ruby.as_str()),
        ("ruby_engine", tc.ruby_engine.as_str()),
        ("rails", tc.rails.as_str()),
        ("bundler", tc.bundler.as_str()),
        ("ruby_test", tc.ruby_test.as_str()),
        ("ruby_libs", tc.ruby_libs.as_str()),
        ("ruby_db", tc.ruby_db.as_str()),
        ("ruby_gems", &ruby_gems),
        ("project", p.project_name()),
        ("superuser", if tc.superuser { "1" } else { "" }),
        (
            "adapter",
            if p.adapter() == "vitest" {
                ""
            } else {
                p.adapter()
            },
        ),
    ];
    let extra: Vec<String> = extra
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    for e in &extra {
        parts.push(e);
    }
    vci_core::blake3_hex(parts.join("\n").as_bytes())
}

/// The signer id of an OpenSSH public key line: SHA-256 of the blob, 16 hex.
fn signer_id_of_pub(line: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let b64 = line.split_whitespace().nth(1).expect("public key blob");
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("public key base64");
    hex::encode(sha2::Sha256::digest(&blob))[..16].to_owned()
}

/// `git check-ignore --stdin` of `paths` at `root`: the ignored ones.
fn git_check_ignore(root: &Utf8Path, paths: &[String]) -> Vec<String> {
    use std::io::Write as _;
    if paths.is_empty() {
        return vec![];
    }
    let mut child = std::process::Command::new("git")
        .args(["-C", root.as_str(), "check-ignore", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("git");
    if let Some(mut i) = child.stdin.take() {
        let _ = i.write_all(paths.join("\n").as_bytes());
        let _ = i.write_all(b"\n");
    }
    let out = child.wait_with_output().expect("git check-ignore");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The plan's `IgnoredChildren::of`: the git-ignored children of the
/// manifest's listed directories that the manifest does not name.
struct Ignored<'a> {
    cache: &'a CheckoutCache,
    known: HashMap<RepoPath, Vec<String>>,
}

impl Ignored<'_> {
    fn of(&mut self, set: &[ShapeEntry]) -> Vec<RepoPath> {
        let dirs: Vec<&RepoPath> = set
            .iter()
            .filter(|e| e.kind == EntryKind::DirListing)
            .map(|e| &e.path)
            .collect();
        if dirs.is_empty() {
            return vec![];
        }
        let child_path = |d: &RepoPath, n: &str| {
            if d.is_root() {
                n.to_owned()
            } else {
                format!("{}/{n}", d.as_str())
            }
        };
        for d in &dirs {
            if self.known.contains_key(*d) {
                continue;
            }
            let names = self.cache.child_names(d);
            let paths: Vec<String> = names.iter().map(|n| child_path(d, n)).collect();
            let ignored = git_check_ignore(self.cache.root(), &paths);
            let set: HashSet<String> = ignored.into_iter().collect();
            let found: Vec<String> = names
                .into_iter()
                .filter(|n| set.contains(&child_path(d, n)))
                .collect();
            self.known.insert((*d).clone(), found);
        }
        let seen: HashSet<&str> = set.iter().map(|e| e.path.as_str()).collect();
        let mut out: Vec<RepoPath> = dirs
            .iter()
            .flat_map(|d| {
                self.known[*d]
                    .iter()
                    .map(|n| child_path(d, n))
                    .collect::<Vec<_>>()
            })
            .filter(|c| !seen.contains(c.as_str()))
            .filter_map(|c| RepoPath::new(&c).ok())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// Observe `set` at the checkout as the plan does: the manifest whose root
/// the plan will recompute.
fn observe(
    set: &[ShapeEntry],
    cache: &CheckoutCache,
    ignored: &mut Ignored<'_>,
    externals: Vec<vci_core::External>,
    env: Vec<vci_core::EnvEntry>,
) -> InputManifest {
    let extra = ignored.of(set);
    let observed = InputManifest::observe(set, cache, &extra).expect("observe");
    InputManifest::from_observed(set, observed, externals, env).expect("from_observed")
}

fn rfc3339(ts: jiff::Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn open_store(url: &str, ns: &str, dir: &Path) -> LibsqlStore {
    let sel = testkit::selection(LibsqlMode::Remote, Some(url), None, Some(ns), None);
    LibsqlStore::open(&sel, &testkit::cx_in(dir, false)).expect("open the libsql store")
}

#[test]
fn measure_plan_v2() {
    let Ok(cfg_path) = std::env::var("VCI_MEAS_CONFIG") else {
        eprintln!("VCI_MEAS_CONFIG not set: nothing to do");
        return;
    };
    let cfg: Config =
        serde_json::from_slice(&std::fs::read(&cfg_path).expect("config")).expect("config JSON");
    let t0 = std::time::Instant::now();
    let checkout = Utf8PathBuf::from(&cfg.checkout);
    let key_path = Utf8PathBuf::from(&cfg.key);
    let pub_line = std::fs::read_to_string(format!("{}.pub", cfg.key)).expect("public key");
    let signer = signer_id_of_pub(&pub_line);
    let ssh = SshSigner::load(&key_path);
    assert!(ssh.in_process(), "the key signs in process");

    // ---- the units
    let pairs: Value = serde_json::from_slice(&std::fs::read(&cfg.pairs).expect("pairs")).unwrap();
    let pairs = pairs["pairs"].as_array().expect("pairs array");
    let mut units: Vec<Unit> = Vec::with_capacity(pairs.len());
    for (index, p) in pairs.iter().enumerate() {
        let env_s = p[0].as_str().unwrap();
        let man_s = p[1].as_str().unwrap();
        let envelope = Envelope::from_json(env_s.as_bytes()).expect("envelope");
        let payload = envelope.payload_bytes().unwrap();
        let st: Statement = serde_json::from_slice(&payload).unwrap();
        assert_eq!(st.predicate_type, PREDICATE_TYPE);
        let pred: VciPredicate = serde_json::from_value(st.predicate.clone()).expect("v1");
        let subject_digest = st.subject[0].digest["blake3"].clone();
        let mut compact: Value = serde_json::from_str(man_s).unwrap();
        let base = compact
            .as_object_mut()
            .unwrap()
            .remove("base")
            .map(|b| b.as_str().unwrap().to_owned());
        let own = InputManifest::from_compact(&serde_json::to_vec(&compact).unwrap()).unwrap();
        let run_key = (
            pred.core.commit.clone(),
            pred.core.issued_at.clone(),
            pred.project_name.clone(),
            pred.core.adapter.clone(),
        );
        units.push(Unit {
            index,
            pred,
            subject_digest,
            own,
            base,
            run_key,
        });
    }
    eprintln!("meas: {} units parsed in {:.1}s", units.len(), t0.elapsed().as_secs_f64());

    // ---- the bases, from the local copy of the production manifests table
    let db = rusqlite::Connection::open(&cfg.proddb).expect("proddb");
    let mut base_of: BTreeMap<String, InputManifest> = BTreeMap::new();
    let wanted: BTreeSet<String> = units.iter().filter_map(|u| u.base.clone()).collect();
    for root in &wanted {
        let bytes: Option<Vec<u8>> = db
            .query_row(
                &format!(
                    "SELECT value FROM {}manifests WHERE root = ?1 AND encoding = 0",
                    cfg.proddb_prefix
                ),
                [root],
                |r| r.get(0),
            )
            .ok();
        if let Some(b) = bytes {
            let m = InputManifest::from_compact(&b).expect("base manifest");
            assert_eq!(&m.root(), root, "the base's root");
            base_of.insert(root.clone(), m);
        }
    }
    eprintln!(
        "meas: {} of {} bases found in the production copy",
        base_of.len(),
        wanted.len()
    );
    // A missing base is substituted by the largest found base of the same
    // project (the plan then observes a realistic set; the hashes are
    // re-observed here anyway).
    let mut substitute: BTreeMap<String, String> = BTreeMap::new();
    let mut by_project: BTreeMap<String, Vec<(usize, String)>> = BTreeMap::new();
    let mut by_adapter: BTreeMap<String, Vec<(usize, String)>> = BTreeMap::new();
    for u in &units {
        if let Some(b) = &u.base
            && let Some(m) = base_of.get(b)
        {
            by_project
                .entry(u.pred.project_name.clone())
                .or_default()
                .push((m.entries.len(), b.clone()));
            by_adapter
                .entry(u.pred.core.adapter.clone())
                .or_default()
                .push((m.entries.len(), b.clone()));
        }
    }
    // A missing base: the largest found base of the same project, else of
    // the same adapter, else none (the unit's own entries alone).
    let mut no_base_at_all = 0usize;
    for u in &units {
        if let Some(b) = &u.base
            && !base_of.contains_key(b)
            && !substitute.contains_key(b)
        {
            let best = by_project
                .get(&u.pred.project_name)
                .or_else(|| by_adapter.get(&u.pred.core.adapter))
                .and_then(|v| v.iter().max())
                .map(|(_, b)| b.clone());
            match best {
                Some(best) => {
                    substitute.insert(b.clone(), best);
                }
                None => no_base_at_all += 1,
            }
        }
    }
    let effective_base = |u: &Unit| -> Option<String> {
        u.base.as_ref().and_then(|b| {
            if base_of.contains_key(b) {
                Some(b.clone())
            } else {
                substitute.get(b).cloned()
            }
        })
    };
    eprintln!("meas: {} substituted bases, {} units without any base", substitute.len(), no_base_at_all);

    // ---- validate the reconstruction: base + own has the signed root
    let mut root_ok = 0usize;
    let mut root_checked = 0usize;
    for u in &units {
        let Some(b) = &u.base else {
            if u.own.root() == u.subject_digest {
                root_ok += 1;
            }
            root_checked += 1;
            continue;
        };
        let Some(bm) = base_of.get(b) else { continue };
        let mut full = u.own.clone();
        full.entries.extend(bm.entries.iter().cloned());
        full.entries.sort();
        full.entries.dedup();
        root_checked += 1;
        if full.root() == u.subject_digest {
            root_ok += 1;
        }
    }
    eprintln!("meas: reconstruction: {root_ok} of {root_checked} units with a real base recompute the signed root");

    // ---- observe every unit's full set at the checkout
    let t = std::time::Instant::now();
    let cache = CheckoutCache::new(&checkout);
    let mut ignored = Ignored {
        cache: &cache,
        known: HashMap::new(),
    };
    let now = jiff::Timestamp::now();
    let issued = rfc3339(now);
    let ttl = cfg.ttl_days.unwrap_or(14);
    let expires = rfc3339(now + jiff::SignedDuration::from_hours(ttl * 24));
    let mut full_of: Vec<InputManifest> = Vec::with_capacity(units.len());
    let mut base_obs: BTreeMap<String, InputManifest> = BTreeMap::new();
    let mut entries_total = 0usize;
    for u in &mut units {
        let eb = effective_base(u);
        let mut set: Vec<ShapeEntry> = u.own.entries.iter().map(ShapeEntry::of).collect();
        if let Some(b) = &eb {
            let bm = &base_of[b];
            set.extend(bm.entries.iter().map(ShapeEntry::of));
            if !base_obs.contains_key(b) {
                let bset: Vec<ShapeEntry> = bm.entries.iter().map(ShapeEntry::of).collect();
                let m = observe(&bset, &cache, &mut ignored, vec![], vec![]);
                base_obs.insert(b.clone(), m);
            }
        }
        set.sort();
        set.dedup();
        let full = observe(
            &set,
            &cache,
            &mut ignored,
            u.own.externals.clone(),
            u.own.env.clone(),
        );
        entries_total += full.entries.len();
        // The global manifest: the attested global paths, observed here.
        let gset: Vec<ShapeEntry> = u
            .pred
            .core
            .global_manifest
            .entries
            .iter()
            .map(ShapeEntry::of)
            .collect();
        let gm = observe(
            &gset,
            &cache,
            &mut ignored,
            u.pred.core.global_manifest.externals.clone(),
            u.pred.core.global_manifest.env.clone(),
        );
        let ov = cfg.overrides.get(&u.pred.project_name);
        let p = &mut u.pred;
        p.core.commit = cfg.commit.clone();
        p.core.tree = Some(cfg.tree.clone());
        p.core.tree_dirty = false;
        p.core.issued_at = issued.clone();
        p.core.expires_at = expires.clone();
        p.core.global_input_root = gm.root();
        p.core.global_manifest = gm;
        p.core.input_root = full.root();
        p.core.manifest_ref = Some(full.root());
        p.core.manifest = None;
        p.core.toolchain.os = std::env::consts::OS.to_owned();
        p.core.toolchain.arch = std::env::consts::ARCH.to_owned();
        p.core.toolchain.superuser = false;
        if let Some(ov) = ov {
            if let Some(tc) = ov.get("toolchain").and_then(Value::as_object) {
                let mut v = serde_json::to_value(&p.core.toolchain).unwrap();
                for (k, val) in tc {
                    v[k] = val.clone();
                }
                p.core.toolchain = serde_json::from_value(v).expect("toolchain override");
            }
            if let Some(d) = ov.get("envConfigDigest").and_then(Value::as_str) {
                p.env_config_digest = d.to_owned();
            }
        }
        full_of.push(full);
    }
    eprintln!(
        "meas: observed {} units ({} entries) at the checkout in {:.1}s",
        units.len(),
        entries_total,
        t.elapsed().as_secs_f64()
    );

    // ---- runs
    let mut runs: BTreeMap<(String, String, String, String), Vec<usize>> = BTreeMap::new();
    for u in &units {
        runs.entry(u.run_key.clone()).or_default().push(u.index);
    }
    let write3 = cfg.write.is_empty() || cfg.write.iter().any(|w| w == "3");
    let write1 = cfg.write.is_empty() || cfg.write.iter().any(|w| w == "1");
    let git_dir = checkout.join(".git");
    let mut summary = json!({
        "units": units.len(),
        "runs": runs.len(),
        "bases_found": base_of.len(),
        "bases_wanted": wanted.len(),
        "substituted_bases": substitute,
        "reconstruction_root_ok": root_ok,
        "reconstruction_root_checked": root_checked,
        "entries_total": entries_total,
        "signer": signer,
        "commit": cfg.commit,
        "issued_at": issued,
        "expires_at": expires,
    });

    // ---- format 3
    if write3 {
        let t = std::time::Instant::now();
        let store = open_store(&cfg.url, &cfg.ns3, git_dir.as_std_path());
        let mut records_bytes = 0usize;
        let mut objects_bytes = 0usize;
        let mut objects_n = 0usize;
        let mut record_sizes: Vec<usize> = Vec::new();
        for (key, idx) in &runs {
            // Header groups by hdr bytes.
            let mut hdr: Vec<Encoded<Hdr>> = Vec::new();
            let mut header_of: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
            let mut headers = Vec::with_capacity(idx.len());
            for &i in idx {
                let h = units[i].pred.hdr().expect("hdr");
                let bytes = h.encode().expect("hdr encode");
                let next = hdr.len();
                let hi = *header_of.entry(bytes.clone()).or_insert_with(|| {
                    hdr.push(Encoded::new(h, bytes));
                    next
                });
                headers.push(hi);
            }
            let groups: Vec<Option<String>> = idx.iter().map(|&i| effective_base(&units[i])).collect();
            let inputs: Vec<UnitInputs<'_>> = idx
                .iter()
                .zip(&headers)
                .zip(&groups)
                .map(|((&i, &header), g)| UnitInputs {
                    header,
                    group: g.as_deref(),
                    manifest: &full_of[i],
                    waived: &units[i].pred.waived,
                })
                .collect();
            let run = Run::build(&inputs).expect("Run::build");
            let shape_hex = vci_core::objects::hex32(&run.shape.id);
            let state_hex = vci_core::objects::hex32(&run.state.id);
            // Objects first, then every record, in one batch.
            let batch = store.batch().expect("batch");
            let mut news: Vec<NewObject<'_>> = Vec::new();
            for h in &hdr {
                news.push(NewObject::new(ObjectKind::Hdr, &h.bytes));
            }
            for t in &run.tables {
                news.push(NewObject::new(ObjectKind::Tables, &t.bytes));
            }
            news.push(NewObject::new(ObjectKind::Shape, &run.shape.bytes));
            news.push(NewObject::new(ObjectKind::State, &run.state.bytes));
            objects_n += news.len();
            objects_bytes += news.iter().map(|o| o.bytes.len()).sum::<usize>();
            store.put_objects(&news).expect("put_objects");
            for (k, &i) in idx.iter().enumerate() {
                let u = &units[i];
                let p = &u.pred;
                let h = &hdr[headers[k]];
                let t: &Encoded<Tables> = &run.tables[headers[k]];
                let entries_root = full_of[i].entries_root();
                let v2 = p.to_v2(&h.id, &t.id, &t.value, &entries_root).expect("to_v2");
                let stmt = Statement::new(
                    vec![Subject {
                        name: p.core.test_id.clone(),
                        digest: BTreeMap::from([("blake3".to_owned(), p.core.input_root.clone())]),
                    }],
                    PREDICATE_TYPE_V2,
                    serde_json::to_value(&v2).unwrap(),
                );
                let statement = sorted_compact_json(&stmt).unwrap().into_bytes();
                let descriptor = run.units[k].descriptor.encode(&t.value).expect("descriptor");
                let env = ssh.sign_payload(&statement).expect("sign");
                let frame = Frame::from_envelope(&env, descriptor).expect("frame");
                let record = frame.encode().expect("record");
                let columns = Columns {
                    format: Some(3),
                    commit: Some(v2.commit.clone()),
                    platform: Some(format!("{}-{}", p.core.toolchain.os, p.core.toolchain.arch)),
                    state: Some(v2.result.state.clone()),
                    duration_ms: Some(v2.result.duration_ms),
                    expires: Some((now + jiff::SignedDuration::from_hours(ttl * 24)).as_second()),
                    hdr: Some(v2.hdr.clone()),
                    tables: Some(v2.tables.clone()),
                    shape: Some(shape_hex.clone()),
                    state_obj: Some(state_hex.clone()),
                };
                let sk = storage_key(&ResolvedPredicate::v1(p));
                let hint = KeyHint {
                    issued: now.as_second(),
                    tree: Some(cfg.tree.chars().take(16).collect()),
                };
                let att = NewAttestation::for_test(&p.core.test_id, &signer, &sk, Some(&hint), record.as_bytes())
                    .with_columns(&columns);
                store.put(&att).expect("put");
                records_bytes += record.len();
                record_sizes.push(record.len());
            }
            batch.finish().expect("finish the batch");
            eprintln!(
                "meas: format 3: run {:?}: {} units, {} hdr, shape {} B, state {} B, tables {:?} B",
                key,
                idx.len(),
                hdr.len(),
                run.shape.bytes.len(),
                run.state.bytes.len(),
                run.tables.iter().map(|t| t.bytes.len()).collect::<Vec<_>>()
            );
        }
        record_sizes.sort_unstable();
        summary["format3"] = json!({
            "seconds": t.elapsed().as_secs_f64(),
            "records": record_sizes.len(),
            "records_bytes": records_bytes,
            "record_p50": record_sizes[record_sizes.len() / 2],
            "record_max": record_sizes.last().copied().unwrap_or(0),
            "objects": objects_n,
            "objects_bytes": objects_bytes,
        });
        eprintln!("meas: format 3 written in {:.1}s", t.elapsed().as_secs_f64());
    }

    // ---- format 1
    if write1 {
        let t = std::time::Instant::now();
        let store = open_store(&cfg.url, &cfg.ns1, git_dir.as_std_path());
        let mut env_bytes = 0usize;
        let mut man_bytes = 0usize;
        let mut base_bytes = 0usize;
        for (key, idx) in &runs {
            let batch = store.batch().expect("batch");
            let mut put_bases: BTreeSet<String> = BTreeSet::new();
            for &i in idx {
                let u = &units[i];
                let p = &u.pred;
                let full = &full_of[i];
                let base = effective_base(u).map(|b| &base_obs[&b]);
                if let Some(b) = base {
                    let root = b.root();
                    if put_bases.insert(root.clone()) {
                        let bytes = b.to_compact();
                        base_bytes += bytes.len();
                        store.put_manifest(&root, bytes.as_bytes()).expect("put base");
                    }
                }
                let compact = match base {
                    Some(b) => full.to_compact_on(b),
                    None => full.to_compact(),
                };
                man_bytes += compact.len();
                store
                    .put_manifest(&p.core.input_root, compact.as_bytes())
                    .expect("put manifest");
                let stmt = Statement::new(
                    vec![Subject {
                        name: p.core.test_id.clone(),
                        digest: BTreeMap::from([("blake3".to_owned(), p.core.input_root.clone())]),
                    }],
                    PREDICATE_TYPE,
                    serde_json::to_value(p).unwrap(),
                );
                let envelope = ssh.sign_statement(&stmt).expect("sign").to_json();
                env_bytes += envelope.len();
                let sk = storage_key(&ResolvedPredicate::v1(p));
                let hint = KeyHint {
                    issued: now.as_second(),
                    tree: Some(cfg.tree.chars().take(16).collect()),
                };
                let att = NewAttestation::for_test(&p.core.test_id, &signer, &sk, Some(&hint), &envelope);
                store.put(&att).expect("put");
            }
            batch.finish().expect("finish the batch");
            eprintln!("meas: format 1: run {:?}: {} units, {} bases", key, idx.len(), put_bases.len());
        }
        summary["format1"] = json!({
            "seconds": t.elapsed().as_secs_f64(),
            "envelope_bytes": env_bytes,
            "manifest_bytes": man_bytes,
            "base_bytes": base_bytes,
        });
        eprintln!("meas: format 1 written in {:.1}s", t.elapsed().as_secs_f64());
    }
    summary["total_seconds"] = json!(t0.elapsed().as_secs_f64());
    std::fs::write(&cfg.out, serde_json::to_string_pretty(&summary).unwrap()).expect("out");
    eprintln!("meas: done in {:.1}s", t0.elapsed().as_secs_f64());
}
