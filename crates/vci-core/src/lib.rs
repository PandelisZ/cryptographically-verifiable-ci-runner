//! Core data model for `vci`: repo paths, input manifests, the input root and
//! the attestation predicate. See `docs/PLAN.md` and `docs/CONTRACTS.md`.
//!
//! Safety rule: **fail open**. Every function here errs towards reporting an
//! error or a mismatch, which makes the caller run the test, rather than ever
//! claiming inputs are unchanged when they might not be.

pub mod hash;
pub mod manifest;
pub mod objects;
pub mod path;
pub mod predicate;

pub mod metrics;
pub use hash::{ABSENT_HASH, blake3_hex};
pub use manifest::{
    AUTOLOAD_MARK, CheckoutCache, ENTRIES_ROOT_DOMAIN, EntryKind, EnvEntry, External, InputEntry,
    InputManifest, ManifestError, Mismatch, Observation, autoload_name, env_value_hash,
};
pub use objects::{
    DecodeError, Descriptor, EncodeError, Encoded, Hdr, ObjectId, ObjectKind, ResolvedManifest,
    Run, Shape, ShapeEntry, State, Tables, UnitInputs, UnitRecord, object_id,
};
pub use path::{PathError, RepoPath};
pub use predicate::{
    Context, PREDICATE_TYPE, PREDICATE_TYPE_V2, PRIVILEGES_DIFF, PYTHON_LIBS_DIFF, Predicate,
    PredicateError, RUBY_LIBS_DIFF, ResolvedPredicate, TestResult, Toolchain, V2View, VciPredicate,
    VciPredicateV2, sorted_compact_json, test_key,
};

#[cfg(test)]
mod manifest_tests;
