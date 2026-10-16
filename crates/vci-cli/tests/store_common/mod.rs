//! Reading stored predicates in the e2e tests: since vci 1.9.0 an
//! attestation references its input manifest (`manifestRef`) instead of
//! embedding it, and the manifest is stored once under git-meta's `project`
//! target (`vci:manifest:<root>`). [`inline_manifest`] puts it back where the
//! tests read it (`predicate.manifest`), in the predicate's JSON form.

#![allow(dead_code)]

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
    let m = vci_core::InputManifest::from_compact(&stored.bytes).unwrap();
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
