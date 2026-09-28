//! Core data model for `vci`: repo paths, input manifests, the input root and
//! the attestation predicate. See `docs/PLAN.md` and `docs/CONTRACTS.md`.
//!
//! Safety rule: **fail open**. Every function here errs towards reporting an
//! error or a mismatch, which makes the caller run the test, rather than ever
//! claiming inputs are unchanged when they might not be.

pub mod hash;
pub mod manifest;
pub mod path;
pub mod predicate;

pub use hash::{ABSENT_HASH, blake3_hex};
pub use manifest::{
    EntryKind, EnvEntry, External, InputEntry, InputManifest, ManifestError, Mismatch, Observation,
    env_value_hash,
};
pub use path::{PathError, RepoPath};
pub use predicate::{PREDICATE_TYPE, Predicate, TestResult, Toolchain, test_key};

#[cfg(test)]
mod manifest_tests;
