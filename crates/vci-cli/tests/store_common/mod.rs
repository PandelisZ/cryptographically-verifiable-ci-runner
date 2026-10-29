//! Reading stored predicates in the e2e tests: since vci 1.9.0 an
//! attestation references its input manifest (`manifestRef`) instead of
//! embedding it, and the manifest is stored once under git-meta's `project`
//! target (`vci:manifest:<root>`). [`inline_manifest`] puts it back where the
//! tests read it (`predicate.manifest`), in the predicate's JSON form.

#![allow(dead_code)]

use base64::Engine as _;
use serde_json::Value;
use vci_git::{AttestStore, Repo};

/// Set `predicate["manifest"]` from the stored manifest `manifestRef` names
/// (unchanged when the manifest is inline). Panics when it is not stored or
/// its root is not the predicate's `inputRoot`.
pub fn inline_manifest(repo: &Repo, mut predicate: Value) -> Value {
    if !predicate["manifest"].is_null() {
        return predicate;
    }
    let Some(root) = predicate["manifestRef"].as_str().map(str::to_owned) else {
        return predicate;
    };
    let stored = AttestStore::new(repo)
        .manifest(&root)
        .unwrap()
        .unwrap_or_else(|| panic!("manifest {root} is not stored"));
    assert_eq!(stored.error, None);
    let m = AttestStore::new(repo)
        .manifest_decoded(&root)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(m.root(), root, "the stored manifest's root");
    assert_eq!(predicate["inputRoot"], root.as_str());
    predicate["manifest"] = serde_json::to_value(m).unwrap();
    predicate
}

/// [`inline_manifest`] on a statement's predicate.
pub fn inline_statement_manifest(repo: &Repo, mut statement: Value) -> Value {
    let p = statement["predicate"].take();
    statement["predicate"] = inline_manifest(repo, p);
    statement
}

/// The DSSE envelope JSON of a stored value: the value itself for a
/// format-1 record, or the envelope rebuilt from a format-3 frame (the
/// text record `vci run` stores since 2.9: its statement bytes as signed,
/// the signature re-armored), for tests that edit or verify an envelope.
pub fn envelope_json(bytes: &[u8]) -> Vec<u8> {
    use vci_attest::FrameExt as _;
    match vci_store::decode_record(bytes).expect("a stored record") {
        vci_store::Record::FormatOne(b) => b.to_vec(),
        vci_store::Record::FormatThree(frame) => frame.to_stored_json(),
    }
}

/// The predicate of a stored value in its v1 JSON form, with its manifest
/// inline, whatever the record's format: a format-1 record's predicate
/// through [`inline_manifest`]; a format-3 record's v2 statement resolved
/// over the run's hdr and tables objects in the repository's git-meta
/// store (every v1 field, as the plan reads it), with `manifest` resolved
/// from its descriptor against the run's shape (the entries' paths, kinds
/// and exec bits, the externals and the env names; no sizes or hashes,
/// which a format-3 record does not sign) and no `manifestRef`.
pub fn predicate_of(repo: &Repo, bytes: &[u8]) -> Value {
    use vci_store::AttestationStore as _;
    let frame = match vci_store::decode_record(bytes).expect("a stored record") {
        vci_store::Record::FormatOne(b) => {
            let env: Value = serde_json::from_slice(b).unwrap();
            let payload = base64::engine::general_purpose::STANDARD
                .decode(env["payload"].as_str().unwrap())
                .unwrap();
            let st: Value = serde_json::from_slice(&payload).unwrap();
            return inline_manifest(repo, st["predicate"].clone());
        }
        vci_store::Record::FormatThree(frame) => frame,
    };
    let st: vci_attest::Statement = serde_json::from_slice(&frame.statement).unwrap();
    assert_eq!(st.predicate_type, vci_core::PREDICATE_TYPE_V2);
    let p: vci_core::VciPredicateV2 = serde_json::from_value(st.predicate.clone()).unwrap();
    let input_root = st.subject[0].digest["blake3"].clone();
    let shape_id = vci_core::objects::hex32(
        &vci_core::Descriptor::shape_id(&frame.descriptor).expect("the descriptor's shape id"),
    );
    let store = vci_git::GitMetaStore::new(repo.clone());
    let objects = store
        .get_objects(&[p.hdr.as_str(), p.tables.as_str(), shape_id.as_str()])
        .unwrap();
    let bytes_of = |id: &str| -> &[u8] {
        &objects
            .iter()
            .find(|o| o.id == id)
            .unwrap_or_else(|| panic!("object {id} is not stored"))
            .bytes
    };
    let ctx = vci_core::Context::decode(&p, bytes_of(&p.hdr), bytes_of(&p.tables)).unwrap();
    let rp = ctx.resolve(&p, &input_root).unwrap();
    let shape = vci_core::Shape::decode(bytes_of(&shape_id)).unwrap();
    let m = vci_core::Descriptor::decode(&frame.descriptor, &ctx.tables)
        .unwrap()
        .resolve(&shape, &ctx.tables)
        .unwrap();
    let manifest = vci_core::InputManifest {
        entries: m
            .set
            .iter()
            .map(|e| vci_core::InputEntry {
                path: e.path.clone(),
                kind: e.kind,
                exec: e.exec,
                size: 0,
                hash: String::new(),
            })
            .collect(),
        externals: m.externals.clone(),
        env: m.env.clone(),
    };
    let v1 = vci_core::VciPredicate {
        core: vci_core::Predicate {
            tool_version: rp.tool_version().to_owned(),
            adapter: rp.adapter().to_owned(),
            test_id: rp.test_id().to_owned(),
            argv: rp.argv().to_vec(),
            repo_id: rp.repo_id().to_owned(),
            commit: rp.commit().to_owned(),
            tree_dirty: rp.tree_dirty(),
            tree: rp.tree().map(str::to_owned),
            toolchain: rp.toolchain().clone(),
            global_input_root: rp.global_input_root().into_owned(),
            input_root: rp.input_root().to_owned(),
            manifest: Some(manifest),
            manifest_ref: None,
            global_manifest: rp.global_manifest().into_owned(),
            result: rp.result().clone(),
            tainted: rp.tainted().to_vec(),
            issued_at: rp.issued_at().to_owned(),
            expires_at: rp.expires_at().to_owned(),
        },
        env_config_digest: rp.env_config_digest().into_owned(),
        project_dir: rp.project_dir().to_owned(),
        runner_project: rp.runner_project().to_owned(),
        project_name: rp.project_name().to_owned(),
        platform_specific: rp.platform_specific().to_vec(),
        arch_specific: rp.arch_specific().to_vec(),
        waived: rp.waived().iter().map(|s| (*s).to_owned()).collect(),
        cfg_predicates: rp.cfg_predicates().to_vec(),
        declared_inputs: rp.declared_inputs().to_vec(),
        env_set: rp.env_set().to_vec(),
        rails_inputs: rp.rails_inputs().to_owned(),
        ignored_inputs: rp.ignored_inputs().to_vec(),
    };
    serde_json::to_value(&v1).unwrap()
}
