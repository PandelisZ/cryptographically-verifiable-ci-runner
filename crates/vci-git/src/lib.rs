//! Git access for `vci`, implemented by shelling out to the `git` CLI.
//!
//! * [`Repo`] answers repository questions (root, identity, HEAD, dirtiness,
//!   revision resolution) and reads files at a revision.
//! * [`AttestStore`] keeps content-addressed attestation envelopes on one ref
//!   per signer under [`REF_PREFIX`], using plumbing commands only. It never
//!   touches the user's index, `HEAD` or working tree.
//!
//! Every identifier that ends up in a ref name or tree path (signer id, test
//! key, input root) is validated as lowercase hex first, so callers cannot
//! inject paths or ref names.

mod cmd;
mod repo;
mod store;
mod validate;

pub use repo::Repo;
pub use store::{AttestStore, REF_PREFIX, REMOTE_REF_PREFIX, StoredEnvelope};

/// Errors from git operations.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    /// The `git` binary could not be started, or I/O with it failed.
    #[error("failed to run git: {0}")]
    Io(#[from] std::io::Error),
    /// A git command exited unsuccessfully.
    #[error("`git {args}` failed ({status}): {stderr}")]
    Command {
        args: String,
        status: String,
        stderr: String,
    },
    /// The start directory is not inside a git repository.
    #[error("not a git repository: {path}: {detail}")]
    NotARepo { path: String, detail: String },
    /// The repository has no commits (HEAD is unborn).
    #[error("repository has no commits")]
    NoCommits,
    /// A revision did not resolve to a commit.
    #[error("unknown revision: {0:?}")]
    UnknownRevision(String),
    /// Two commits share no history.
    #[error("no merge base between {0:?} and {1:?}")]
    NoMergeBase(String, String),
    /// The path exists at the revision but is not a regular file or symlink.
    #[error("{path:?} at {rev} is not a file (it is a {kind})")]
    NotAFile {
        rev: String,
        path: String,
        kind: String,
    },
    /// An argument failed validation (bad hex id, unsafe path, option-like rev...).
    #[error("invalid {what}: {value:?}: {reason}")]
    Invalid {
        what: &'static str,
        value: String,
        reason: &'static str,
    },
    /// Git printed something we could not parse.
    #[error("unexpected git output: {0}")]
    Parse(String),
    /// Output that must be UTF-8 (paths, object ids) was not.
    #[error("git output was not valid UTF-8")]
    NonUtf8,
    /// A local ref kept changing under us and the compare-and-swap never won.
    #[error(
        "ref {refname} kept changing concurrently; gave up after {attempts} attempts: {detail}"
    )]
    Contention {
        refname: String,
        attempts: u32,
        detail: String,
    },
    /// The remote kept rejecting the push after retries.
    #[error("push to {remote:?} still rejected after {attempts} attempts: {detail}")]
    PushRejected {
        remote: String,
        attempts: u32,
        detail: String,
    },
}
