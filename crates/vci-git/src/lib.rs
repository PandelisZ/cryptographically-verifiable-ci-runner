//! Git access for `vci`, implemented by shelling out to the `git` CLI.
//!
//! * [`Repo`] answers repository questions (root, identity, HEAD, dirtiness,
//!   revision resolution) and reads files at a revision.
//! * [`AttestStore`] keeps attestation envelopes as [git-meta] metadata (see
//!   [`meta`] for the layout), exchanged on `refs/meta/main` by ordinary git
//!   push and fetch. It never touches the user's index, `HEAD` or working
//!   tree.
//!
//! Every identifier that ends up in a git-meta key (signer id, storage key)
//! is validated as lowercase hex first, so callers cannot inject key
//! segments.
//!
//! [git-meta]: https://git-meta.com/

mod cmd;
pub mod meta;
mod repo;
mod validate;

pub use meta::{
    AttestStore, FetchOutcome, KEY_PREFIX, PushOutcome, PushStatus, Reader, SETUP_FILE,
    StoredEnvelope,
};
pub use repo::Repo;

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
    /// git-meta (the metadata store or its merge) failed.
    #[error("git-meta: {0}")]
    Meta(String),
    /// The local git-meta store (`.git/git-meta.sqlite`) or a lock file next
    /// to it could not be opened, read or written.
    #[error("git-meta store: {0}")]
    Store(String),
    /// No metadata remote could be found or configured.
    #[error("{0}")]
    NoMetaRemote(String),
    /// The remote kept rejecting the push after retries.
    #[error("push to {remote:?} still rejected after {attempts} attempts: {detail}")]
    PushRejected {
        remote: String,
        attempts: u32,
        detail: String,
    },
}
