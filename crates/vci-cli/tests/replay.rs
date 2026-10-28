//! The replay check of STORE-V2 section 6 M1: real v1 records (a DSSE
//! envelope and the compact manifest it references, as `vci run` 2.8 stored
//! them) go through the format-3 pipeline exactly as `vci run` will build it
//! and the plan will read it, and every signed fact comes back.
//!
//! The test lives in vci-cli, which depends on vci-core and vci-attest,
//! rather than in vci-core: a dev-dependency of vci-core on vci-attest would
//! put vci-attest's sources among the inputs the cargo adapter sees for
//! `vci attest crates/vci-core#lib`, and `e2e_cargo.rs` checks that unit is
//! not tainted.
//!
//! For every unit: the envelope and the compact manifest are parsed; units
//! are grouped into runs by (commit, issuedAt, projectName, adapter), the
//! design's run (one `vci run` of one project; `design/final/measure.py`
//! groups the same way), and inside a run into header groups by the hdr
//! their predicate's facts make (section 1.4 step 1); [`Run::build`] makes
//! the shape (its groups the distinct `base` ids of the compact manifests,
//! each the entries the units of that base share), the state, one tables
//! object per header group and every unit's descriptor; the v2 statement is
//! made from the v1 predicate, and the record is the text frame of section
//! 1.2 with the unit's own SSHSIG. Then everything is decoded back and:
//!
//! (a) the descriptor resolved against its shape and tables gives the unit's
//!     manifest's `(path, kind, exec)` set, externals and env;
//! (b) [`InputManifest::from_observed`] over the resolved set, with the
//!     attested sizes and hashes taken from the state object, has the
//!     `root()` of the unit's manifest and the `entries_root()` the
//!     statement signed. The sample's compact manifests are deltas on base
//!     manifests that are not in the file (1,172 of 1,175 units), so the
//!     manifest here is the unit's own entries and only a base-less unit's
//!     root is the subject digest; every unit's subject digest is checked to
//!     be the file's root hex, and the three base-less units' roots to be it;
//! (c) the v2 statement re-parsed through [`ResolvedPredicate`] gives every
//!     v1 accessor's value;
//! (d) every object id recomputes from the bytes, and every object decodes
//!     to the value it was encoded from.
//!
//! Signatures are not verified here: the statement bytes changed (a v2
//! statement is signed over other bytes than the v1 one the sample's SSHSIG
//! covers), and the signers' keys are not part of the sample. The frame
//! carries each unit's real SSHSIG blob so that the record is measured at
//! its true size.
//!
//! The sizes of every statement, signature frame, descriptor, record and
//! object are collected and, when `VCI_PAIRS` names the 1,175-unit sample
//! (`scratchpad/wr/pairs.json`), printed and compared with the design's
//! size model (`design/final/numbers.json` beside the sample, or
//! `VCI_NUMBERS`), flagging any figure off by more than 10%; the figures
//! and the comparison are written to the file `VCI_REPLAY_OUT` names
//! (`design/final/replay-numbers.json` is kept that way) and nowhere
//! otherwise. Without `VCI_PAIRS` the test over the real sample is
//! skipped; the synthetic sample below runs always.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use vci_attest::{Envelope, Frame, FrameSig, Statement, Subject};
use vci_core::{
    ABSENT_HASH, Context, Descriptor, Encoded, EntryKind, EnvEntry, External, Hdr, InputEntry,
    InputManifest, PREDICATE_TYPE, PREDICATE_TYPE_V2, Predicate, RepoPath, ResolvedManifest,
    ResolvedPredicate, Run, Shape, ShapeEntry, State, Tables, TestResult, Toolchain, UnitInputs,
    VciPredicate, VciPredicateV2, object_id, sorted_compact_json,
};

// ---------------------------------------------------------------- the units

/// One unit of the sample: a `pairs.json` triple parsed.
struct Unit {
    index: usize,
    envelope: Envelope,
    pred: VciPredicate,
    /// The subject's `blake3` digest: the signed input root.
    subject_digest: String,
    /// `pairs[i][2]`, the root the manifest was stored under.
    root_hex: String,
    /// The compact manifest's own entries, externals and env (a delta's
    /// base entries are not in the file).
    manifest: InputManifest,
    /// The `base` member of the compact manifest: today's shared base, the
    /// shape's group key.
    base: Option<String>,
    envelope_bytes: usize,
    manifest_bytes: usize,
}

fn parse_units(pairs: &[(String, String, String)]) -> Vec<Unit> {
    pairs
        .iter()
        .enumerate()
        .map(|(index, (env_s, man_s, root_hex))| {
            let envelope = Envelope::from_json(env_s.as_bytes()).expect("envelope JSON");
            let payload = envelope.payload_bytes().expect("payload base64");
            let statement: Statement = serde_json::from_slice(&payload).expect("statement JSON");
            assert_eq!(statement.predicate_type, PREDICATE_TYPE, "unit {index}");
            let pred: VciPredicate =
                serde_json::from_value(statement.predicate.clone()).expect("v1 predicate");
            assert_eq!(statement.subject.len(), 1, "unit {index}");
            let subject = &statement.subject[0];
            assert_eq!(subject.name, pred.core.test_id, "unit {index}");
            let subject_digest = subject.digest["blake3"].clone();
            assert_eq!(subject_digest, pred.core.input_root, "unit {index}");
            // The compact manifest without its `base` member: the base's
            // entries are not here, so the unit's own entries are its set.
            let mut compact: Value = serde_json::from_str(man_s).expect("compact manifest JSON");
            let base = compact
                .as_object_mut()
                .expect("an object")
                .remove("base")
                .map(|b| b.as_str().expect("base is a string").to_owned());
            let manifest = InputManifest::from_compact(&serde_json::to_vec(&compact).unwrap())
                .unwrap_or_else(|e| panic!("unit {index}: compact manifest: {e}"));
            Unit {
                index,
                envelope,
                pred,
                subject_digest,
                root_hex: root_hex.clone(),
                manifest,
                base,
                envelope_bytes: env_s.len(),
                manifest_bytes: man_s.len(),
            }
        })
        .collect()
}

/// The design's run: one `vci run` of one project.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RunKey {
    commit: String,
    issued_at: String,
    project_name: String,
    adapter: String,
}

impl RunKey {
    fn of(p: &VciPredicate) -> Self {
        RunKey {
            commit: p.core.commit.clone(),
            issued_at: p.core.issued_at.clone(),
            project_name: p.project_name.clone(),
            adapter: p.core.adapter.clone(),
        }
    }
}

/// Runs in the model's order: the largest first, then by key.
fn runs(units: &[Unit]) -> Vec<(RunKey, Vec<usize>)> {
    let mut by_key: BTreeMap<RunKey, Vec<usize>> = BTreeMap::new();
    for u in units {
        by_key.entry(RunKey::of(&u.pred)).or_default().push(u.index);
    }
    let mut runs: Vec<(RunKey, Vec<usize>)> = by_key.into_iter().collect();
    runs.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
    runs
}

// ---------------------------------------------------------------- the replay of one run

/// What one unit's record measured as, and what its checks found.
struct UnitFigures {
    statement: usize,
    sig_frame: usize,
    descriptor: usize,
    record: usize,
    own_entries: usize,
    /// The root of the resolved set with the state's values equals the
    /// subject digest (true exactly for a unit whose manifest has no base).
    root_is_subject: bool,
    /// Entries of the set the state object held with more than one value
    /// (a file written during the run): none in the sample.
    state_conflicts: usize,
    adapter: String,
}

struct RunFigures {
    key: RunKey,
    units: usize,
    hdr: Vec<Encoded<Hdr>>,
    /// Per header group: the tables object's id and bytes (two groups of
    /// the same unions make the same object, stored once).
    tables: Vec<([u8; 32], usize)>,
    shape_bytes: usize,
    shape_entries: usize,
    groups: usize,
    group_entries: usize,
    state_bytes: usize,
    state_entries: usize,
    per_unit: Vec<UnitFigures>,
}

/// The bytes of a `uv` varint.
fn uv_len(mut n: usize) -> usize {
    let mut len = 1;
    while n >= 0x80 {
        n >>= 7;
        len += 1;
    }
    len
}

/// Builds the run's objects and every unit's statement, descriptor and
/// record, decodes them back and runs checks (a) to (d).
fn replay_run(key: &RunKey, units: &[&Unit]) -> RunFigures {
    // Section 1.4 step 1: header groups by the hdr the facts make, dense
    // from 0 in first-seen order.
    let mut hdr: Vec<Encoded<Hdr>> = Vec::new();
    let mut header_of: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    let mut headers = Vec::with_capacity(units.len());
    for u in units {
        let h = u
            .pred
            .hdr()
            .unwrap_or_else(|e| panic!("unit {}: hdr: {e}", u.index));
        let bytes = h
            .encode()
            .unwrap_or_else(|e| panic!("unit {}: hdr encode: {e}", u.index));
        let next = hdr.len();
        let i = *header_of.entry(bytes.clone()).or_insert_with(|| {
            hdr.push(Encoded::new(h, bytes));
            next
        });
        headers.push(i);
    }
    // Step 2: the shape, state, tables and descriptors.
    let inputs: Vec<UnitInputs<'_>> = units
        .iter()
        .zip(&headers)
        .map(|(u, &header)| UnitInputs {
            header,
            group: u.base.as_deref(),
            manifest: &u.manifest,
            waived: &u.pred.waived,
        })
        .collect();
    let run = Run::build(&inputs).expect("Run::build");
    assert_eq!(run.tables.len(), hdr.len());
    assert_eq!(run.units.len(), units.len());

    // (d) for the per-run objects: ids recompute, bytes decode to the value.
    assert_eq!(object_id(&run.shape.bytes), run.shape.id);
    assert_eq!(object_id(&run.state.bytes), run.state.id);
    let shape = Shape::decode(&run.shape.bytes).expect("shape decodes");
    assert_eq!(shape, run.shape.value);
    let state = State::decode(&run.state.bytes).expect("state decodes");
    assert_eq!(state, run.state.value);
    for t in &run.tables {
        assert_eq!(object_id(&t.bytes), t.id);
        assert_eq!(Tables::decode(&t.bytes).expect("tables decodes"), t.value);
    }
    for h in &hdr {
        assert_eq!(object_id(&h.bytes), h.id);
        assert_eq!(Hdr::decode(&h.bytes).expect("hdr decodes"), h.value);
    }
    // Every group is a distinct base shared by two or more units, in range.
    assert!(shape.groups.len() <= 255);
    let bases: BTreeSet<&str> = units.iter().filter_map(|u| u.base.as_deref()).collect();
    assert!(shape.groups.len() <= bases.len());
    for g in &shape.groups {
        assert!(g.windows(2).all(|w| w[0] < w[1]));
        assert!(g.last().is_some_and(|&i| i < shape.entries.len()));
    }

    // Step 3 per unit, then the read path.
    let mut per_unit = Vec::with_capacity(units.len());
    for ((u, rec), &header) in units.iter().zip(&run.units).zip(&headers) {
        let at = |what: &str| format!("unit {} ({}): {what}", u.index, u.pred.core.test_id);
        let h = &hdr[header];
        let t = &run.tables[header];
        let entries_root = u.manifest.entries_root();
        let v2 = u
            .pred
            .to_v2(&h.id, &t.id, &t.value, &entries_root)
            .unwrap_or_else(|e| panic!("{}", at(&format!("to_v2: {e}"))));
        assert_eq!(v2.waived, rec.waived, "{}", at("waived ids"));
        // The statement: the v1 subject, the v2 predicate, compact JSON
        // with sorted keys at every level (section 1.1).
        let statement = Statement::new(
            vec![Subject {
                name: u.pred.core.test_id.clone(),
                digest: BTreeMap::from([("blake3".to_owned(), u.subject_digest.clone())]),
            }],
            PREDICATE_TYPE_V2,
            serde_json::to_value(&v2).unwrap(),
        );
        let statement = sorted_compact_json(&statement).unwrap().into_bytes();
        let descriptor = rec
            .descriptor
            .encode(&t.value)
            .unwrap_or_else(|e| panic!("{}", at(&format!("descriptor encode: {e}"))));
        // The frame: the unit's own keyid and SSHSIG blob (not verified
        // here, see the module comment) over the v2 statement.
        let mut frame = Frame::from_envelope(&u.envelope, descriptor.clone())
            .unwrap_or_else(|e| panic!("{}", at(&format!("frame: {e}"))));
        frame.statement = statement.clone();
        let record = frame
            .encode()
            .unwrap_or_else(|e| panic!("{}", at(&format!("record: {e}"))));
        let FrameSig::SshSig(blob) = &frame.sig else {
            panic!("{}", at("an SSH-signed record"));
        };
        let sig_frame =
            1 + uv_len(frame.keyid.len()) + frame.keyid.len() + uv_len(blob.len()) + blob.len();

        // The read path: the record back, its statement, its objects.
        let back = Frame::decode(record.as_bytes()).expect("the record decodes");
        assert_eq!(back, frame, "{}", at("the frame round trips"));
        assert_eq!(
            Envelope::from_frame(&back).signatures[0].keyid,
            u.envelope.signatures[0].keyid
        );
        let read: Statement = serde_json::from_slice(&back.statement).expect("statement JSON");
        assert_eq!(read.predicate_type, PREDICATE_TYPE_V2);
        assert_eq!(read.subject[0].name, u.pred.core.test_id);
        assert_eq!(read.subject[0].digest["blake3"], u.subject_digest);
        assert_eq!(
            u.subject_digest,
            u.root_hex,
            "{}",
            at("the file's root is the subject")
        );
        let v2_read: VciPredicateV2 = serde_json::from_value(read.predicate).expect("v2 predicate");
        assert_eq!(v2_read, v2, "{}", at("the v2 predicate round trips"));
        let ctx = Context::decode(&v2_read, &h.bytes, &t.bytes)
            .unwrap_or_else(|e| panic!("{}", at(&format!("context: {e}"))));
        assert_eq!(ctx.hdr, h.value);
        assert_eq!(ctx.tables, t.value);

        // (c) every v1 accessor's value through the v2 view.
        let resolved = ctx
            .resolve(&v2_read, &read.subject[0].digest["blake3"])
            .unwrap_or_else(|e| panic!("{}", at(&format!("resolve: {e}"))));
        assert_parity(
            ResolvedPredicate::v1(&u.pred),
            resolved,
            &v2_read,
            &entries_root,
            &at(""),
        );

        // (a) the descriptor resolves to the manifest's set, externals, env.
        assert_eq!(
            Descriptor::shape_id(&back.descriptor).unwrap(),
            run.shape.id
        );
        let d = Descriptor::decode(&back.descriptor, &ctx.tables)
            .unwrap_or_else(|e| panic!("{}", at(&format!("descriptor decode: {e}"))));
        assert_eq!(d, rec.descriptor);
        let resolved_manifest = d
            .resolve(&shape, &ctx.tables)
            .unwrap_or_else(|e| panic!("{}", at(&format!("descriptor resolve: {e}"))));
        assert_eq!(
            resolved_manifest,
            ResolvedManifest::of(&u.manifest),
            "{}",
            at("the resolved set, externals and env are the manifest's")
        );
        if let Some(base) = &u.base {
            // A unit in a group lists none of the group's entries itself.
            if let Some(g) = d.group {
                let group = &shape.groups[g as usize];
                assert!(d.own.iter().all(|i| group.binary_search(i).is_err()));
                // The group is the intersection of its units' entries, so
                // every unit of the base has every group entry.
                let set: BTreeSet<&ShapeEntry> = resolved_manifest.set.iter().collect();
                assert!(
                    group.iter().all(|&i| set.contains(&shape.entries[i])),
                    "{}",
                    at(base)
                );
            }
        } else {
            assert_eq!(d.group, None, "{}", at("no base, no group"));
        }

        // (b) observe-then-root with the attested values from the state.
        let mut conflicts = 0;
        let observed: Vec<InputEntry> = resolved_manifest
            .set
            .iter()
            .map(|e| {
                let values: Vec<&InputEntry> = state
                    .lookup(&e.path)
                    .iter()
                    .filter(|s| s.kind == e.kind && s.exec == e.exec)
                    .collect();
                assert!(
                    !values.is_empty(),
                    "{}",
                    at(&format!("{} is in the state", e.path))
                );
                if values.len() > 1 {
                    conflicts += 1;
                }
                values[0].clone()
            })
            .collect();
        let observed = InputManifest::from_observed(
            &resolved_manifest.set,
            observed,
            resolved_manifest.externals.clone(),
            resolved_manifest.env.clone(),
        )
        .unwrap_or_else(|e| panic!("{}", at(&format!("from_observed: {e}"))));
        assert_eq!(
            observed.root(),
            u.manifest.root(),
            "{}",
            at("root of the own entries")
        );
        assert_eq!(
            observed.entries_root(),
            v2_read.entries_root,
            "{}",
            at("entries root")
        );
        let root_is_subject = observed.root() == u.subject_digest;
        assert_eq!(
            root_is_subject,
            u.base.is_none(),
            "{}",
            at("the root is the subject digest exactly for a base-less unit")
        );

        per_unit.push(UnitFigures {
            statement: statement.len(),
            sig_frame,
            descriptor: descriptor.len(),
            record: record.len(),
            own_entries: u.manifest.entries.len(),
            root_is_subject,
            state_conflicts: conflicts,
            adapter: u.pred.core.adapter.clone(),
        });
    }
    RunFigures {
        key: key.clone(),
        units: units.len(),
        tables: run.tables.iter().map(|t| (t.id, t.bytes.len())).collect(),
        shape_bytes: run.shape.bytes.len(),
        shape_entries: shape.entries.len(),
        groups: shape.groups.len(),
        group_entries: shape.groups.iter().map(Vec::len).sum(),
        state_bytes: run.state.bytes.len(),
        state_entries: state.entries.len(),
        hdr,
        per_unit,
    }
}

/// Every accessor of the v1 view equals the v2 view's (c).
fn assert_parity(
    a: ResolvedPredicate<'_>,
    b: ResolvedPredicate<'_>,
    v2: &VciPredicateV2,
    entries_root: &str,
    at: &str,
) {
    assert_eq!((a.version(), b.version()), (1, 2), "{at}");
    assert_eq!(a.tool_version(), b.tool_version(), "{at}");
    assert_eq!(a.adapter(), b.adapter(), "{at}");
    assert_eq!(a.test_id(), b.test_id(), "{at}");
    assert_eq!(a.argv(), b.argv(), "{at}");
    assert_eq!(a.repo_id(), b.repo_id(), "{at}");
    assert_eq!(a.commit(), b.commit(), "{at}");
    assert_eq!(a.tree_dirty(), b.tree_dirty(), "{at}");
    assert_eq!(a.tree(), b.tree(), "{at}");
    assert_eq!(a.toolchain(), b.toolchain(), "{at}");
    assert_eq!(a.global_input_root(), b.global_input_root(), "{at}");
    assert_eq!(a.input_root(), b.input_root(), "{at}");
    assert_eq!(
        a.global_manifest().root(),
        b.global_manifest().root(),
        "{at}"
    );
    assert_eq!(a.result(), b.result(), "{at}");
    assert_eq!(a.tainted(), b.tainted(), "{at}");
    assert_eq!(a.issued_at(), b.issued_at(), "{at}");
    assert_eq!(a.expires_at(), b.expires_at(), "{at}");
    assert_eq!(a.env_config_digest(), b.env_config_digest(), "{at}");
    assert_eq!(a.project_dir(), b.project_dir(), "{at}");
    assert_eq!(a.runner_project(), b.runner_project(), "{at}");
    assert_eq!(a.project_name(), b.project_name(), "{at}");
    assert_eq!(a.platform_specific(), b.platform_specific(), "{at}");
    assert_eq!(a.arch_specific(), b.arch_specific(), "{at}");
    // v1 may repeat a waived string or list them unsorted; the ids are
    // sorted and distinct, so the two versions meet on the canonical list
    // (what the storage key is computed over, STORE-V2 section 1.1).
    assert_eq!(a.waived_canonical(), b.waived(), "{at}");
    assert_eq!(b.waived(), b.waived_canonical(), "{at}");
    assert_eq!(a.cfg_predicates(), b.cfg_predicates(), "{at}");
    assert_eq!(a.declared_inputs(), b.declared_inputs(), "{at}");
    assert_eq!(a.env_set(), b.env_set(), "{at}");
    assert_eq!(a.rails_inputs(), b.rails_inputs(), "{at}");
    assert_eq!(a.ignored_inputs(), b.ignored_inputs(), "{at}");
    assert_eq!(a.hdr_id(), None, "{at}");
    assert_eq!(b.hdr_id(), Some(v2.hdr.as_str()), "{at}");
    assert_eq!(b.tables_id(), Some(v2.tables.as_str()), "{at}");
    assert_eq!(b.entries_root(), Some(entries_root), "{at}");
}

// ---------------------------------------------------------------- the figures

/// `measure.py`'s `stat`: n, mean to one decimal, p50 = sorted[n/2], p90 =
/// sorted[int(0.9 n)], max, sum.
fn stat(xs: &[usize]) -> Value {
    let mut s = xs.to_vec();
    s.sort_unstable();
    let n = s.len();
    if n == 0 {
        return json!({"n": 0, "mean": 0, "p50": 0, "p90": 0, "max": 0, "sum": 0});
    }
    let sum: usize = s.iter().sum();
    json!({
        "n": n,
        "mean": (sum as f64 / n as f64 * 10.0).round() / 10.0,
        "p50": s[n / 2],
        "p90": s[((n as f64) * 0.9) as usize],
        "max": s[n - 1],
        "sum": sum,
    })
}

/// Replays every run of `units` and gathers the figures of the whole sample.
fn replay(units: &[Unit]) -> Value {
    let runs = runs(units);
    let figures: Vec<RunFigures> = runs
        .iter()
        .map(|(key, idx)| {
            let members: Vec<&Unit> = idx.iter().map(|&i| &units[i]).collect();
            replay_run(key, &members)
        })
        .collect();

    let all: Vec<&UnitFigures> = figures.iter().flat_map(|r| r.per_unit.iter()).collect();
    assert_eq!(all.len(), units.len());
    let col = |f: fn(&UnitFigures) -> usize| -> Vec<usize> { all.iter().map(|u| f(u)).collect() };
    let records = col(|u| u.record);
    let mut by_adapter: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for u in &all {
        by_adapter.entry(&u.adapter).or_default().push(u.record);
    }
    let distinct_hdr: BTreeMap<[u8; 32], usize> = figures
        .iter()
        .flat_map(|r| r.hdr.iter().map(|h| (h.id, h.bytes.len())))
        .collect();
    let hdr_bytes: Vec<usize> = distinct_hdr.values().copied().collect();
    // Objects are stored once per id: a hdr shared by runs, a tables object
    // shared by header groups (the node runs' header groups make the same
    // three tables objects) count once at rest.
    let distinct_tables: BTreeMap<[u8; 32], usize> = figures
        .iter()
        .flat_map(|r| r.tables.iter().copied())
        .collect();
    let tables_bytes: Vec<usize> = distinct_tables.values().copied().collect();
    let header_groups: usize = figures.iter().map(|r| r.tables.len()).sum();
    let today_envelope: Vec<usize> = units.iter().map(|u| u.envelope_bytes).collect();
    let today_manifest: Vec<usize> = units.iter().map(|u| u.manifest_bytes).collect();
    let today_total: usize =
        today_envelope.iter().sum::<usize>() + today_manifest.iter().sum::<usize>();
    let sums = |xs: &[usize]| xs.iter().sum::<usize>();
    let records_sum = sums(&records);
    let hdr_sum = sums(&hdr_bytes);
    let tables_sum = sums(&tables_bytes);
    let shape_sum: usize = figures.iter().map(|r| r.shape_bytes).sum();
    let state_sum: usize = figures.iter().map(|r| r.state_bytes).sum();
    let total = records_sum + hdr_sum + tables_sum + shape_sum + state_sum;
    let ratio = |a: usize, b: usize| (a as f64 / b as f64 * 10.0).round() / 10.0;

    json!({
        "units": units.len(),
        "signatures": "not verified: the statement bytes changed (v2) and the keys are not here; each record carries its unit's real SSHSIG blob",
        "runs": figures.iter().map(|r| json!({
            "commit": &r.key.commit[..8],
            "issued": r.key.issued_at,
            "project": r.key.project_name,
            "adapter": r.key.adapter,
            "units": r.units,
            "hdr_count": r.hdr.len(),
            // The sorted distinct sizes, as `measure.py` lists them
            // (`sorted({hdr_sizes[i] for i in hdr_ids})`), so that the
            // comparison's per-run sum is over the same statistic.
            "hdr_bytes": r.hdr.iter().map(|h| h.bytes.len()).collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>(),
            "tables_count": r.tables.len(),
            "tables_bytes": r.tables.iter().map(|t| t.1).collect::<Vec<_>>(),
            "shape_bytes": r.shape_bytes,
            "shape_entries": r.shape_entries,
            "groups": r.groups,
            "group_entries": r.group_entries,
            "state_bytes": r.state_bytes,
            "state_entries": r.state_entries,
            "conflicts": r.per_unit.iter().map(|u| u.state_conflicts).sum::<usize>(),
            "root_is_subject_units": r.per_unit.iter().filter(|u| u.root_is_subject).count(),
        })).collect::<Vec<_>>(),
        "today": {
            "envelope": stat(&today_envelope),
            "manifest": stat(&today_manifest),
            "per_unit": today_total / units.len().max(1),
            "total": today_total,
        },
        "v2": {
            "statement": stat(&col(|u| u.statement)),
            "sig_frame": stat(&col(|u| u.sig_frame)),
            "descriptor": stat(&col(|u| u.descriptor)),
            "record": stat(&records),
            "record_by_adapter": by_adapter.iter().map(|(k, v)| (k.to_string(), stat(v))).collect::<BTreeMap<_, _>>(),
            "own_entries": stat(&col(|u| u.own_entries)),
            "hdr": {"distinct_in_sample": distinct_hdr.len(), "bytes": stat(&hdr_bytes)},
            "tables": {"count": distinct_tables.len(), "header_groups": header_groups, "bytes": stat(&tables_bytes)},
            "shape": {"bytes_sum": shape_sum, "entries_sum": figures.iter().map(|r| r.shape_entries).sum::<usize>(),
                      "groups": figures.iter().map(|r| r.groups).sum::<usize>(),
                      "group_entries": figures.iter().map(|r| r.group_entries).sum::<usize>()},
            "state": {"bytes_sum": state_sum, "entries_sum": figures.iter().map(|r| r.state_entries).sum::<usize>()},
            "at_rest": {
                "records": records_sum,
                "hdr": hdr_sum,
                "tables": tables_sum,
                "shape": shape_sum,
                "state": state_sum,
                "total": total,
                "total_without_state": total - state_sum,
                "per_unit": total / units.len().max(1),
                "per_unit_without_state": (total - state_sum) / units.len().max(1),
                "ratio_vs_today": ratio(today_total, total),
                "ratio_vs_today_without_state": ratio(today_total, total - state_sum),
            },
        },
        "checks": {
            "subject_digest_is_file_root": units.len(),
            "resolved_set_externals_env_equal_manifest": units.len(),
            "own_entries_root_recomputed": units.len(),
            "entries_root_recomputed": units.len(),
            "root_is_subject_digest": all.iter().filter(|u| u.root_is_subject).count(),
            "baseless_units": units.iter().filter(|u| u.base.is_none()).count(),
            "v1_accessor_parity": units.len(),
            "object_ids_recomputed": distinct_hdr.len() + header_groups + 2 * figures.len(),
            "state_conflicts": all.iter().map(|u| u.state_conflicts).sum::<usize>(),
        },
    })
}

// ---------------------------------------------------------------- the comparison with the model

/// The figures of `replay` against the design's `numbers.json`, one row per
/// figure: (name, model, replay, flagged when off by more than 10%).
fn compare(model: &Value, replay: &Value) -> Vec<(String, f64, f64, bool)> {
    let mut rows = Vec::new();
    let mut row = |name: String, m: &Value, r: &Value| {
        let (Some(m), Some(r)) = (m.as_f64(), r.as_f64()) else {
            return;
        };
        let off = if m == 0.0 {
            r != 0.0
        } else {
            ((r - m) / m).abs() > 0.10
        };
        rows.push((name, m, r, off));
    };
    for what in [
        "statement",
        "sig_frame",
        "descriptor",
        "record",
        "own_entries",
    ] {
        for k in ["mean", "p50", "p90", "max", "sum"] {
            row(
                format!("v2.{what}.{k}"),
                &model["v2"][what][k],
                &replay["v2"][what][k],
            );
        }
    }
    for adapter in ["rails", "cargo", "node-test"] {
        row(
            format!("v2.record_by_adapter.{adapter}.mean"),
            &model["v2"]["record_by_adapter"][adapter]["mean"],
            &replay["v2"]["record_by_adapter"][adapter]["mean"],
        );
    }
    row(
        "v2.hdr.distinct_in_sample".into(),
        &model["v2"]["hdr"]["distinct_in_sample"],
        &replay["v2"]["hdr"]["distinct_in_sample"],
    );
    row(
        "v2.hdr.bytes.sum".into(),
        &model["v2"]["hdr"]["bytes"]["sum"],
        &replay["v2"]["hdr"]["bytes"]["sum"],
    );
    row(
        "v2.hdr.bytes.max".into(),
        &model["v2"]["hdr"]["bytes"]["max"],
        &replay["v2"]["hdr"]["bytes"]["max"],
    );
    row(
        "v2.tables.count".into(),
        &model["v2"]["tables"]["count"],
        &replay["v2"]["tables"]["count"],
    );
    row(
        "v2.tables.bytes.sum".into(),
        &model["v2"]["tables"]["bytes"]["sum"],
        &replay["v2"]["tables"]["bytes"]["sum"],
    );
    row(
        "v2.shape.bytes_sum".into(),
        &model["v2"]["shape"]["bytes_sum"],
        &replay["v2"]["shape"]["bytes_sum"],
    );
    row(
        "v2.state.bytes_sum".into(),
        &model["v2"]["state"]["bytes_sum"],
        &replay["v2"]["state"]["bytes_sum"],
    );
    row(
        "today.total".into(),
        &model["today"]["total"],
        &replay["today"]["total"],
    );
    for k in ["records", "hdr", "tables", "shape", "state"] {
        row(
            format!("at_rest.{k}"),
            &model["v2"]["at_rest_1175"][k],
            &replay["v2"]["at_rest"][k],
        );
    }
    // The model's totals carry an estimate of the groups' bytes (section
    // 1.3: the bases are not in the file); the replay encodes the real
    // groups inside the shape, so its total is compared with the model's
    // total less that estimate, and the model's figure with the estimate is
    // listed beside it.
    let m = &model["v2"]["at_rest_1175"];
    if let (Some(total), Some(est)) = (m["total_with_state"].as_f64(), m["groups_est"].as_f64()) {
        row(
            "at_rest.total (model less groups_est)".into(),
            &json!(total - est),
            &replay["v2"]["at_rest"]["total"],
        );
        row(
            "at_rest.total (model with groups_est)".into(),
            &json!(total),
            &replay["v2"]["at_rest"]["total"],
        );
        if let Some(state) = m["state"].as_f64() {
            row(
                "at_rest.total_without_state (model less groups_est)".into(),
                &json!(total - est - state),
                &replay["v2"]["at_rest"]["total_without_state"],
            );
        }
        if let Some(today) = model["today"]["total"].as_f64() {
            row(
                "at_rest.ratio_vs_today (model less groups_est)".into(),
                &json!((today / (total - est) * 10.0).round() / 10.0),
                &replay["v2"]["at_rest"]["ratio_vs_today"],
            );
        }
    }
    row(
        "at_rest.ratio_vs_today (model with groups_est)".into(),
        &m["ratio_vs_today"],
        &replay["v2"]["at_rest"]["ratio_vs_today"],
    );
    // Per run, matched by commit prefix, issued time and project.
    let sum_of = |v: &Value| -> Value {
        json!(
            v.as_array()
                .map(|a| a.iter().filter_map(Value::as_f64).sum::<f64>())
                .unwrap_or(0.0)
        )
    };
    for mr in model["runs"].as_array().into_iter().flatten() {
        let Some(rr) = replay["runs"].as_array().into_iter().flatten().find(|r| {
            r["commit"] == mr["commit"]
                && r["issued"] == mr["issued"]
                && r["project"] == mr["project"]
        }) else {
            continue;
        };
        let name = format!(
            "run {} {} {} ({} units)",
            mr["commit"].as_str().unwrap_or(""),
            mr["project"].as_str().unwrap_or(""),
            mr["issued"].as_str().unwrap_or(""),
            mr["units"]
        );
        row(format!("{name}: units"), &mr["units"], &rr["units"]);
        row(
            format!("{name}: hdr_count"),
            &mr["hdr_count"],
            &rr["hdr_count"],
        );
        row(
            format!("{name}: hdr_bytes sum"),
            &sum_of(&mr["hdr_bytes"]),
            &sum_of(&rr["hdr_bytes"]),
        );
        row(
            format!("{name}: tables_count"),
            &mr["tables_count"],
            &rr["tables_count"],
        );
        row(
            format!("{name}: tables_bytes sum"),
            &sum_of(&mr["tables_bytes"]),
            &sum_of(&rr["tables_bytes"]),
        );
        for k in [
            "shape_bytes",
            "shape_entries",
            "state_bytes",
            "state_entries",
            "conflicts",
        ] {
            row(format!("{name}: {k}"), &mr[k], &rr[k]);
        }
    }
    rows
}

fn print_comparison(rows: &[(String, f64, f64, bool)]) {
    println!(
        "\n{:<72} {:>14} {:>14} {:>8}",
        "figure", "model", "replay", "delta"
    );
    let mut flagged = 0;
    for (name, m, r, off) in rows {
        let delta = if *m == 0.0 {
            if *r == 0.0 { 0.0 } else { f64::INFINITY }
        } else {
            (r - m) / m * 100.0
        };
        println!(
            "{:<72} {:>14} {:>14} {:>7.1}% {}",
            name,
            m,
            r,
            delta,
            if *off { "FLAG" } else { "" }
        );
        flagged += usize::from(*off);
    }
    println!("{flagged} of {} figures off by more than 10%", rows.len());
}

// ---------------------------------------------------------------- the synthetic sample (always on)

/// A `pairs.json`-shaped sample made in the test: two Rails-like runs
/// (six units at one commit, three of them on one base and two on another,
/// each base's units sharing entries the base lacks, one unit base-less;
/// two units at a second commit sharing the first run's hdr) and a
/// cargo-like unit with `cfgPredicates`, `waived` and an absent env
/// variable. As in the real sample, a compact manifest on a base lists only
/// the entries the base lacks, and the base is not in the sample. The
/// signature is a fake 180-byte blob in ssh-keygen's armor: signatures are
/// not verified in the replay.
fn synthetic_pairs() -> Vec<(String, String, String)> {
    fn entry(path: &str, kind: EntryKind, size: u64, seed: u8) -> InputEntry {
        let hash = match kind {
            EntryKind::Absent => ABSENT_HASH.to_owned(),
            EntryKind::Excluded => vci_core::manifest::excluded_hash(),
            EntryKind::AutoloadDir => vci_core::manifest::autoload_dir_hash(),
            EntryKind::Dir => vci_core::manifest::dir_type_hash(),
            _ => vci_core::blake3_hex(&[seed, path.len() as u8]),
        };
        InputEntry {
            path: RepoPath::new(path).unwrap(),
            kind,
            exec: false,
            size,
            hash,
        }
    }
    let base_a = InputManifest {
        entries: (0..40)
            .map(|i| {
                entry(
                    &format!("app/models/m{i:02}.rb"),
                    EntryKind::File,
                    100 + i,
                    1,
                )
            })
            .chain([
                entry("app/models", EntryKind::DirListing, 40, 2),
                entry("config/boot.rb", EntryKind::File, 300, 3),
                entry("lib/.vci-autoload", EntryKind::AutoloadDir, 0, 0),
                entry(".vci-autoload/missing", EntryKind::AutoloadMiss, 0, 0),
                entry("tmp", EntryKind::Excluded, 0, 0),
                entry("vendor", EntryKind::Dir, 0, 0),
            ])
            .collect(),
        ..Default::default()
    };
    let base_b = InputManifest {
        entries: (0..20)
            .map(|i| {
                entry(
                    &format!("app/services/s{i:02}.rb"),
                    EntryKind::File,
                    50 + i,
                    4,
                )
            })
            .chain([entry("config/boot.rb", EntryKind::File, 300, 3)])
            .collect(),
        ..Default::default()
    };
    let rails_toolchain = Toolchain {
        ruby: "3.4.9p82".into(),
        ruby_engine: "ruby 3.4.9".into(),
        rails: "8.1.1".into(),
        bundler: "2.7.3".into(),
        ruby_test: "minitest 6.0.6".into(),
        ruby_libs: "sqlite=3.51.0;yaml=0.2.5".into(),
        ruby_db: "postgresql".into(),
        ruby_gems: (0..30).map(|i| format!("gem{i:02}==1.{i}.0")).collect(),
        os: "linux".into(),
        arch: "x86_64".into(),
        ..Default::default()
    };
    let global = InputManifest {
        entries: vec![
            entry("Gemfile", EntryKind::File, 1200, 5),
            entry("Gemfile.lock", EntryKind::File, 9000, 6),
            entry("config/environments/test.rb", EntryKind::File, 800, 7),
        ],
        ..Default::default()
    };
    let make = |adapter: &str,
                test_id: &str,
                commit: &str,
                issued: &str,
                toolchain: &Toolchain,
                global: &InputManifest,
                manifest: &InputManifest,
                base: Option<&InputManifest>,
                waived: &[&str],
                cfg: &[&str],
                env_absent: bool|
     -> (String, String, String) {
        let mut manifest = manifest.clone();
        manifest.externals = vec![
            External {
                name: "rails".into(),
                version: "8.1.1".into(),
            },
            External {
                name: "minitest".into(),
                version: "6.0.6".into(),
            },
        ];
        manifest.env = vec![
            EnvEntry {
                key: "RAILS_ENV".into(),
                hash: vci_core::blake3_hex(b"test"),
            },
            EnvEntry {
                key: "CI".into(),
                hash: if env_absent {
                    ABSENT_HASH.into()
                } else {
                    vci_core::blake3_hex(b"1")
                },
            },
        ];
        let input_root = manifest.root();
        let pred = VciPredicate {
            core: Predicate {
                tool_version: "2.9.0".into(),
                adapter: adapter.into(),
                test_id: test_id.into(),
                argv: vec!["bin/rails".into(), "test".into(), test_id.into()],
                repo_id: "0123456789abcdef0123456789abcdef01234567".into(),
                commit: commit.into(),
                tree_dirty: false,
                tree: Some(format!("{}{}", &commit[..20], &commit[..20])),
                toolchain: toolchain.clone(),
                global_input_root: global.root(),
                input_root: input_root.clone(),
                manifest: None,
                manifest_ref: Some(input_root.clone()),
                global_manifest: global.clone(),
                result: TestResult {
                    state: "passed".into(),
                    tests: 3,
                    failed: 0,
                    skipped: 0,
                    duration_ms: 1234,
                },
                tainted: vec![],
                issued_at: issued.into(),
                expires_at: "2026-11-11T04:11:29Z".into(),
            },
            env_config_digest: vci_core::blake3_hex(b"env config"),
            project_dir: "api".into(),
            runner_project: String::new(),
            project_name: "api".into(),
            platform_specific: vec![],
            arch_specific: vec![],
            waived: waived.iter().map(|w| w.to_string()).collect(),
            cfg_predicates: cfg.iter().map(|c| c.to_string()).collect(),
            declared_inputs: vec![],
            env_set: vec!["RAILS_ENV".into()],
            rails_inputs: if adapter == "rails" {
                "loose".into()
            } else {
                String::new()
            },
            ignored_inputs: if adapter == "rails" {
                vec!["log/**".into()]
            } else {
                vec![]
            },
        };
        let statement = Statement::new(
            vec![Subject {
                name: test_id.into(),
                digest: BTreeMap::from([("blake3".to_owned(), input_root.clone())]),
            }],
            PREDICATE_TYPE,
            serde_json::to_value(&pred).unwrap(),
        );
        let mut blob = b"SSHSIG".to_vec();
        blob.extend(std::iter::repeat_n(0x5a, 174));
        let envelope = Envelope::from_frame(&Frame {
            statement: serde_json::to_vec(&statement).unwrap(),
            keyid: "SHA256:JMGwSg92DBOfvirgRPTn4rYsH0hnx9wpYXhm+FqGHlc".into(),
            sig: FrameSig::SshSig(blob),
            descriptor: Vec::new(),
        });
        let compact = match base {
            Some(b) => manifest.to_compact_on(b),
            None => manifest.to_compact(),
        };
        (
            String::from_utf8(envelope.to_json()).unwrap(),
            compact,
            input_root,
        )
    };
    let helper = || entry("test/test_helper.rb", EntryKind::File, 2000, 30);
    let rewritten = || entry("app/models/m00.rb", EntryKind::File, 101, 31);
    let on = |base: &InputManifest, own: Vec<InputEntry>| InputManifest {
        entries: base.entries.iter().cloned().chain(own).collect(),
        ..Default::default()
    };
    let c1 = "2cb18b86448f1a5d47490e33330b721398073236";
    let c2 = "90ce3d34b422f327cdd11f56e16ab043a10ef2a8";
    let t1 = "2026-10-28T04:11:29Z";
    let t2 = "2026-10-28T04:06:21Z";
    vec![
        // Base A's units share the test helper and a model rewritten since
        // the base was made (a changed file is a delta entry too).
        make(
            "rails",
            "test/models/a_test.rb",
            c1,
            t1,
            &rails_toolchain,
            &global,
            &on(
                &base_a,
                vec![
                    entry("test/models/a_test.rb", EntryKind::File, 500, 10),
                    entry("app/models/a.rb", EntryKind::File, 50, 11),
                    helper(),
                    rewritten(),
                ],
            ),
            Some(&base_a),
            &["flaky:order"],
            &[],
            false,
        ),
        make(
            "rails",
            "test/models/b_test.rb",
            c1,
            t1,
            &rails_toolchain,
            &global,
            &on(
                &base_a,
                vec![
                    entry("test/models/b_test.rb", EntryKind::File, 600, 12),
                    entry("app/models/b.rb", EntryKind::Absent, 0, 0),
                    helper(),
                    rewritten(),
                ],
            ),
            Some(&base_a),
            &[],
            &[],
            false,
        ),
        make(
            "rails",
            "test/models/c_test.rb",
            c1,
            t1,
            &rails_toolchain,
            &global,
            &on(
                &base_a,
                vec![
                    entry("test/models/c_test.rb", EntryKind::File, 700, 13),
                    helper(),
                    rewritten(),
                ],
            ),
            Some(&base_a),
            &["flaky:order", "flaky:order"],
            &[],
            true,
        ),
        make(
            "rails",
            "test/services/d_test.rb",
            c1,
            t1,
            &rails_toolchain,
            &global,
            &on(
                &base_b,
                vec![
                    entry("test/services/d_test.rb", EntryKind::File, 800, 14),
                    helper(),
                ],
            ),
            Some(&base_b),
            &[],
            &[],
            false,
        ),
        make(
            "rails",
            "test/services/e_test.rb",
            c1,
            t1,
            &rails_toolchain,
            &global,
            &on(
                &base_b,
                vec![
                    entry("test/services/e_test.rb", EntryKind::File, 900, 15),
                    helper(),
                ],
            ),
            None,
            &[],
            &[],
            false,
        ),
        make(
            "rails",
            "test/services/f_test.rb",
            c1,
            t1,
            &rails_toolchain,
            &global,
            &on(
                &base_b,
                vec![
                    entry("test/services/f_test.rb", EntryKind::File, 950, 16),
                    helper(),
                ],
            ),
            Some(&base_b),
            &[],
            &[],
            false,
        ),
        make(
            "rails",
            "test/models/a_test.rb",
            c2,
            t2,
            &rails_toolchain,
            &global,
            &on(
                &base_a,
                vec![entry("test/models/a_test.rb", EntryKind::File, 500, 10)],
            ),
            Some(&base_a),
            &[],
            &[],
            false,
        ),
        make(
            "rails",
            "test/models/c_test.rb",
            c2,
            t2,
            &rails_toolchain,
            &global,
            &on(
                &base_a,
                vec![entry("test/models/c_test.rb", EntryKind::File, 700, 13)],
            ),
            Some(&base_a),
            &[],
            &[],
            false,
        ),
        make(
            "cargo",
            "crates/x::tests::y",
            c2,
            "2026-10-28T04:06:52Z",
            &Toolchain {
                rust: "1.93.0 abc LLVM 21".into(),
                cargo: "1.93.0 abc".into(),
                rust_host: "x86_64-unknown-linux-gnu".into(),
                rust_cfg: vec!["target_arch=\"x86_64\"".into(), "unix".into()],
                os: "linux".into(),
                arch: "x86_64".into(),
                ..Default::default()
            },
            &InputManifest {
                entries: vec![entry("Cargo.lock", EntryKind::File, 40000, 20)],
                ..Default::default()
            },
            &InputManifest {
                entries: vec![
                    entry("crates/x/src/lib.rs", EntryKind::File, 2000, 21),
                    entry("crates/x/Cargo.toml", EntryKind::File, 300, 22),
                ],
                ..Default::default()
            },
            None,
            &["privileges:root"],
            &["unix", "target_os = \"linux\""],
            true,
        ),
    ]
}

#[test]
fn the_synthetic_sample_replays() {
    let pairs = synthetic_pairs();
    let units = parse_units(&pairs);
    assert_eq!(units.len(), 9);
    assert_eq!(units.iter().filter(|u| u.base.is_none()).count(), 2);
    // A unit on a base holds only the entries the base lacks.
    assert_eq!(units[0].manifest.entries.len(), 4);
    assert_eq!(units[4].manifest.entries.len(), 23);
    let figures = replay(&units);
    let runs = figures["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 3);
    // The six-unit run: one hdr, one tables object, two groups (base A's
    // three units share two entries, base B's two share one; the base-less
    // unit is in none).
    assert_eq!(runs[0]["units"], 6);
    assert_eq!(runs[0]["hdr_count"], 1);
    assert_eq!(runs[0]["tables_count"], 1);
    assert_eq!(runs[0]["groups"], 2);
    assert_eq!(runs[0]["group_entries"], 3);
    assert_eq!(runs[0]["root_is_subject_units"], 1);
    // The second Rails run shares the first's hdr: 2 distinct hdr in all.
    assert_eq!(figures["v2"]["hdr"]["distinct_in_sample"], 2);
    assert_eq!(figures["checks"]["root_is_subject_digest"], 2);
    assert_eq!(figures["checks"]["state_conflicts"], 0);
    let record = &figures["v2"]["record"];
    assert!(record["mean"].as_f64().unwrap() > 1000.0, "{record}");
    assert!(record["max"].as_f64().unwrap() < 4000.0, "{record}");
    // The comparison against a model of the same figures flags nothing.
    let rows = compare(&figures, &figures);
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|r| !r.3));
}

// ---------------------------------------------------------------- the real sample

/// `VCI_PAIRS` names the 1,175-unit sample; `VCI_REPLAY_OUT` where to write
/// `replay-numbers.json` (default: `design/final/replay-numbers.json` beside
/// the sample's `wr` directory when that directory exists); `VCI_NUMBERS`
/// the model's `numbers.json` to compare with (default: next to the output).
#[test]
fn the_real_sample_replays() {
    let Ok(pairs_path) = std::env::var("VCI_PAIRS") else {
        eprintln!("VCI_PAIRS is unset: the replay of the real sample is skipped");
        return;
    };
    let pairs_path = PathBuf::from(pairs_path);
    #[derive(serde::Deserialize)]
    struct Pairs {
        pairs: Vec<(String, String, String)>,
    }
    let data = std::fs::read(&pairs_path).expect("VCI_PAIRS readable");
    let pairs: Pairs = serde_json::from_slice(&data).expect("pairs JSON");
    let units = parse_units(&pairs.pairs);
    println!("{} units parsed from {}", units.len(), pairs_path.display());

    let figures = replay(&units);
    println!(
        "{}",
        serde_json::to_string_pretty(&figures["checks"]).unwrap()
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&figures["v2"]["at_rest"]).unwrap()
    );
    for r in figures["runs"].as_array().unwrap() {
        println!("{}", serde_json::to_string(r).unwrap());
    }

    let final_dir = pairs_path
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join("design").join("final"));
    // Written only where `VCI_REPLAY_OUT` says: a test does not write
    // outside the target directory on its own.
    let out = std::env::var_os("VCI_REPLAY_OUT").map(PathBuf::from);
    if let Some(out) = &out {
        std::fs::write(out, serde_json::to_string_pretty(&figures).unwrap())
            .expect("write replay-numbers.json");
        println!("wrote {}", out.display());
    }
    let numbers = std::env::var_os("VCI_NUMBERS")
        .map(PathBuf::from)
        .or_else(|| {
            final_dir
                .map(|d| d.join("numbers.json"))
                .filter(|p| p.is_file())
        });
    if let Some(numbers) = numbers {
        let model: Value =
            serde_json::from_slice(&std::fs::read(&numbers).expect("numbers.json")).unwrap();
        let rows = compare(&model, &figures);
        print_comparison(&rows);
        if let Some(out) = &out {
            let mut with = figures.clone();
            with["comparison"] = json!(rows.iter().map(|(name, m, r, off)| json!({
                "figure": name, "model": m, "replay": r,
                "delta_pct": if *m == 0.0 { 0.0 } else { ((r - m) / m * 1000.0).round() / 10.0 },
                "flag": off,
            })).collect::<Vec<_>>());
            with["model"] = json!(numbers.display().to_string());
            std::fs::write(out, serde_json::to_string_pretty(&with).unwrap())
                .expect("write replay-numbers.json");
        }
    }
    assert_eq!(figures["units"], units.len());
    assert_eq!(figures["checks"]["state_conflicts"], 0);
}
