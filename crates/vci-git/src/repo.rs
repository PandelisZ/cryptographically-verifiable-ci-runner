//! Repository discovery and queries.

use camino::{Utf8Path, Utf8PathBuf};

use crate::GitError;
use crate::cmd::{Git, command_error};
use crate::validate;

/// A git repository, identified by its root directory (the work tree root, or
/// the git directory for a bare repository).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    root: Utf8PathBuf,
}

impl Repo {
    /// Find the repository containing `start` (a directory or a file).
    pub fn discover(start: &Utf8Path) -> Result<Self, GitError> {
        let dir = if start.is_file() {
            start.parent().unwrap_or(start)
        } else {
            start
        };
        let not_repo = |detail: String| GitError::NotARepo {
            path: start.to_string(),
            detail,
        };
        let (describe, out) = Git::at(dir)
            .args(["rev-parse", "--is-bare-repository"])
            .output_described()?;
        if !out.status.success() {
            return Err(not_repo(command_error(&describe, &out).to_string()));
        }
        let bare = String::from_utf8_lossy(&out.stdout).trim() == "true";
        let which = if bare {
            "--absolute-git-dir"
        } else {
            "--show-toplevel"
        };
        let root = Git::at(dir)
            .args(["rev-parse", which])
            .run_str()
            .map_err(|e| not_repo(e.to_string()))?;
        if root.is_empty() {
            return Err(not_repo("git reported no top-level directory".into()));
        }
        Ok(Repo {
            root: Utf8PathBuf::from(root),
        })
    }

    /// The repository root.
    pub fn root(&self) -> &Utf8Path {
        &self.root
    }

    pub(crate) fn git(&self) -> Git {
        Git::at(&self.root)
    }

    /// Stable repository identity: the lexicographically smallest root commit
    /// reachable from HEAD.
    pub fn repo_id(&self) -> Result<String, GitError> {
        // Fail with NoCommits rather than a raw git error on an unborn HEAD.
        self.head_commit()?;
        let out = self
            .git()
            .args(["rev-list", "--max-parents=0", "HEAD"])
            .run_str()?;
        let mut roots: Vec<&str> = out
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        roots.sort_unstable();
        roots
            .first()
            .map(|s| (*s).to_owned())
            .ok_or_else(|| GitError::Parse("rev-list reported no root commits".into()))
    }

    /// The commit HEAD points at.
    pub fn head_commit(&self) -> Result<String, GitError> {
        let (describe, out) = self
            .git()
            .args(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])
            .output_described()?;
        if out.status.success() {
            return parse_oid(&out.stdout);
        }
        if out.status.code() == Some(1) {
            return Err(GitError::NoCommits);
        }
        Err(command_error(&describe, &out))
    }

    /// True if the work tree or index differs from HEAD, or there are
    /// untracked (non-ignored) files. Does not write the index.
    pub fn is_dirty(&self) -> Result<bool, GitError> {
        let out = self
            .git()
            .args([
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=normal",
                "--ignore-submodules=none",
            ])
            .run()?;
        Ok(!out.is_empty())
    }

    /// Resolve a revision to a full commit id (tags are peeled).
    pub fn resolve(&self, rev: &str) -> Result<String, GitError> {
        validate::rev(rev)?;
        let (describe, out) = self
            .git()
            .args(["rev-parse", "--verify", "--quiet"])
            .arg(format!("{rev}^{{commit}}"))
            .output_described()?;
        if out.status.success() {
            return parse_oid(&out.stdout);
        }
        if out.status.code() == Some(1) {
            return Err(GitError::UnknownRevision(rev.to_owned()));
        }
        Err(command_error(&describe, &out))
    }

    /// The best common ancestor of two revisions.
    pub fn merge_base(&self, a: &str, b: &str) -> Result<String, GitError> {
        let ca = self.resolve(a)?;
        let cb = self.resolve(b)?;
        let (describe, out) = self
            .git()
            .args(["merge-base", &ca, &cb])
            .output_described()?;
        if out.status.success() {
            return parse_oid(&out.stdout);
        }
        if out.status.code() == Some(1) && out.stdout.is_empty() {
            return Err(GitError::NoMergeBase(a.to_owned(), b.to_owned()));
        }
        Err(command_error(&describe, &out))
    }

    /// Contents of `path` at `rev` (like `git show <rev>:<path>`).
    ///
    /// `Ok(None)` if the path does not exist at that revision. A symlink
    /// yields its target. A directory or submodule is an error, as is an
    /// unknown revision.
    pub fn show_file(&self, rev: &str, path: &str) -> Result<Option<Vec<u8>>, GitError> {
        validate::repo_path(path)?;
        let commit = self.resolve(rev)?;
        let listing = self
            .git()
            .args(["ls-tree", "-z", "--full-tree", &commit, "--", path])
            .run()?;
        for record in listing.split(|b| *b == 0).filter(|r| !r.is_empty()) {
            let entry = TreeEntry::parse(record)?;
            if entry.path != path.as_bytes() {
                continue;
            }
            return match (entry.mode.as_str(), entry.kind.as_str()) {
                ("100644" | "100755" | "120000", "blob") => Ok(Some(
                    self.git().args(["cat-file", "blob", &entry.oid]).run()?,
                )),
                (_, kind) => Err(GitError::NotAFile {
                    rev: rev.to_owned(),
                    path: path.to_owned(),
                    kind: kind.to_owned(),
                }),
            };
        }
        Ok(None)
    }
}

/// One record of `git ls-tree -z` output.
pub(crate) struct TreeEntry<'a> {
    pub mode: String,
    pub kind: String,
    pub oid: String,
    pub path: &'a [u8],
}

impl<'a> TreeEntry<'a> {
    pub fn parse(record: &'a [u8]) -> Result<Self, GitError> {
        let bad = || {
            GitError::Parse(format!(
                "ls-tree record {:?}",
                String::from_utf8_lossy(record)
            ))
        };
        let tab = record.iter().position(|b| *b == b'\t').ok_or_else(bad)?;
        let head = std::str::from_utf8(&record[..tab]).map_err(|_| bad())?;
        let mut parts = head.split(' ');
        let (Some(mode), Some(kind), Some(oid), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad());
        };
        if !is_oid(oid) {
            return Err(bad());
        }
        Ok(TreeEntry {
            mode: mode.to_owned(),
            kind: kind.to_owned(),
            oid: oid.to_owned(),
            path: &record[tab + 1..],
        })
    }
}

pub(crate) fn is_oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64)
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub(crate) fn parse_oid(stdout: &[u8]) -> Result<String, GitError> {
    let s = std::str::from_utf8(stdout)
        .map_err(|_| GitError::NonUtf8)?
        .trim();
    if is_oid(s) {
        Ok(s.to_owned())
    } else {
        Err(GitError::Parse(format!("expected an object id, got {s:?}")))
    }
}
