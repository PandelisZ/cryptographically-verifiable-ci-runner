//! Repository discovery and queries.

use camino::{Utf8Path, Utf8PathBuf};

use std::collections::BTreeSet;

use crate::GitError;
use crate::cmd::{Git, command_error};
use crate::validate;

/// Set on the git commands that look up commits (a base ref, an earlier
/// attestation's commit): a commit missing here is unknown, as in a shallow
/// clone, rather than downloaded with its whole history from a promisor
/// remote (a partial clone of the code; the promisor remote vci's metadata
/// fetches configure fails such a fetch at once anyway, see [`crate::meta`]).
/// Versions of git older than this variable (2024) ignore it. Reading file
/// contents is left alone: a partial clone of the code needs those fetched.
const NO_LAZY_FETCH: &str = "GIT_NO_LAZY_FETCH";

/// A git repository, identified by its root directory (the work tree root, or
/// the git directory for a bare repository).
#[derive(Debug, Clone)]
pub struct Repo {
    root: Utf8PathBuf,
    /// The git directory, asked of git once ([`Repo::git_dir`]: storing an
    /// attestation asked about eight times, a `git rev-parse` each, most of
    /// the 20 ms each unit took to store on vex's runners).
    git_dir: std::sync::OnceLock<Utf8PathBuf>,
    /// The common git directory of a linked worktree, `None` elsewhere,
    /// asked of git once ([`Repo::common_git_dir`]).
    linked_common: std::sync::OnceLock<Option<Utf8PathBuf>>,
}

/// How many of `oids` the object database at `root` holds, asked without
/// fetching any (`git rev-list --missing=allow-any`, any git version).
pub(crate) fn present_count(root: &Utf8Path, oids: &[String]) -> usize {
    let mut input = Vec::new();
    for o in oids.iter().filter(|o| is_oid(o)) {
        input.extend_from_slice(o.as_bytes());
        input.push(b'\n');
    }
    if input.is_empty() {
        return 0;
    }
    Git::at(root)
        .args([
            "rev-list",
            "--objects",
            "--no-walk",
            "--missing=allow-any",
            "--ignore-missing",
            "--stdin",
        ])
        .env(NO_LAZY_FETCH, "1")
        .run_with_stdin(&input)
        .map(|out| String::from_utf8_lossy(&out).lines().count())
        .unwrap_or(0)
}

impl PartialEq for Repo {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}

impl Eq for Repo {}

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
            git_dir: std::sync::OnceLock::new(),
            linked_common: std::sync::OnceLock::new(),
        })
    }

    /// The repository root.
    pub fn root(&self) -> &Utf8Path {
        &self.root
    }

    pub(crate) fn git(&self) -> Git {
        Git::at(&self.root)
    }

    /// The repository's git directory (for a linked worktree, its own).
    pub fn git_dir(&self) -> Result<Utf8PathBuf, GitError> {
        if let Some(d) = self.git_dir.get() {
            return Ok(d.clone());
        }
        let dir = self
            .git()
            .args(["rev-parse", "--absolute-git-dir"])
            .run_str()?;
        Ok(self.git_dir.get_or_init(|| Utf8PathBuf::from(dir)).clone())
    }

    /// The git directory every worktree of the repository shares: for a
    /// linked worktree (`git worktree add`) the common git directory (the
    /// main checkout's `.git`, or the bare repository), elsewhere
    /// [`Repo::git_dir`], spelled as that returns it. vci's git-meta store
    /// lives here (2.7.33: one per repository, not one per worktree).
    pub fn common_git_dir(&self) -> Result<Utf8PathBuf, GitError> {
        match self.linked_common() {
            Some(common) => Ok(common),
            None => self.git_dir(),
        }
    }

    /// [`Repo::linked_worktree_common_dir`], asked of git once.
    pub(crate) fn linked_common(&self) -> Option<Utf8PathBuf> {
        self.linked_common
            .get_or_init(|| self.linked_worktree_common_dir())
            .clone()
    }

    /// For a linked worktree (`git worktree add`), the repository's common
    /// git directory, whose `config` every worktree shares; `None` in the
    /// main worktree (or when git cannot say).
    pub fn linked_worktree_common_dir(&self) -> Option<Utf8PathBuf> {
        let out = self
            .git()
            .args([
                "rev-parse",
                "--path-format=absolute",
                "--git-dir",
                "--git-common-dir",
            ])
            .run_str()
            .ok()?;
        let mut lines = out.lines();
        let (git_dir, common) = (lines.next()?.trim(), lines.next()?.trim());
        let canon = |p: &str| {
            Utf8Path::new(p)
                .canonicalize_utf8()
                .unwrap_or_else(|_| Utf8PathBuf::from(p))
        };
        (!git_dir.is_empty() && !common.is_empty() && canon(git_dir) != canon(common))
            .then(|| canon(common))
    }

    /// The work tree root, or `None` for a bare repository.
    pub fn work_tree(&self) -> Option<Utf8PathBuf> {
        let out = self
            .git()
            .args(["rev-parse", "--is-bare-repository"])
            .run_str()
            .ok()?;
        (out.trim() != "true").then(|| self.root.clone())
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

    /// The tree HEAD's commit points at.
    pub fn head_tree(&self) -> Result<String, GitError> {
        let out = self
            .git()
            .args(["rev-parse", "--verify", "--quiet", "HEAD^{tree}"])
            .run()?;
        parse_oid(&out)
    }

    /// The tree of commit `rev`.
    pub fn tree_of(&self, rev: &str) -> Result<String, GitError> {
        let out = self
            .git()
            .args(["rev-parse", "--verify", "--quiet"])
            .arg(format!("{rev}^{{tree}}"))
            .run()?;
        parse_oid(&out)
    }

    /// The trees at the tips of every branch, remote-tracking branch and
    /// tag: the trees that can be checked out by name now. The current
    /// branch's namesakes on the remotes (`origin/<branch>` behind it) do
    /// not count, as for [`Self::moved_on`]: the same line of work, not yet
    /// pushed; nor does a remote's `HEAD`.
    pub fn live_trees(&self) -> Result<BTreeSet<String>, GitError> {
        let namesakes = self.branch_namesakes()?;
        let out = self
            .git()
            .args([
                "for-each-ref",
                "--format=%(refname)%09%(tree)%09%(*tree)",
                "refs/heads",
                "refs/remotes",
                "refs/tags",
            ])
            .env(NO_LAZY_FETCH, "1")
            .run_str()?;
        let mut trees = BTreeSet::new();
        for line in out.lines() {
            let mut parts = line.split('\t');
            let Some(name) = parts.next() else { continue };
            if name.ends_with("/HEAD") || namesakes.iter().any(|n| n == name) {
                continue;
            }
            for t in parts.map(str::trim).filter(|t| is_oid(t)) {
                trees.insert(t.to_owned());
            }
        }
        Ok(trees)
    }

    /// `refs/remotes/<remote>/<branch>` for every remote, when HEAD is on a
    /// branch: the branch's own line on the remotes.
    fn branch_namesakes(&self) -> Result<Vec<String>, GitError> {
        let (_, out) = self
            .git()
            .args(["symbolic-ref", "--quiet", "--short", "HEAD"])
            .output_described()?;
        let branch = out
            .status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
            .filter(|b| !b.is_empty());
        let Some(b) = branch else {
            return Ok(Vec::new());
        };
        let remotes = self.git().args(["remote"]).run_str()?;
        Ok(remotes
            .lines()
            .map(|r| format!("refs/remotes/{}/{b}", r.trim()))
            .collect())
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

    /// Resolve a revision to a full commit id (tags are peeled). A commit
    /// this clone does not have is unknown, never fetched (see
    /// [`NO_LAZY_FETCH`]).
    pub fn resolve(&self, rev: &str) -> Result<String, GitError> {
        validate::rev(rev)?;
        let (describe, out) = self
            .git()
            .args(["rev-parse", "--verify", "--quiet"])
            .arg(format!("{rev}^{{commit}}"))
            .env(NO_LAZY_FETCH, "1")
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
            .env(NO_LAZY_FETCH, "1")
            .output_described()?;
        if out.status.success() {
            return parse_oid(&out.stdout);
        }
        if out.status.code() == Some(1) && out.stdout.is_empty() {
            return Err(GitError::NoMergeBase(a.to_owned(), b.to_owned()));
        }
        Err(command_error(&describe, &out))
    }

    /// Whether the object database holds `oid`, asked without fetching it:
    /// `git cat-file -e` (and `merge-base`) of a commit the clone lacks asks
    /// the promisor remote for it, and git before 2.44 ignores
    /// `GIT_NO_LAZY_FETCH` (vex's runners, 2.43: 12.7 s each, two per
    /// earlier pull request commit supersession asked about). `git rev-list
    /// --missing=print` never fetches on any version.
    pub fn has_object(&self, oid: &str) -> Result<bool, GitError> {
        if !is_oid(oid) {
            return Ok(false);
        }
        let out = self
            .git()
            .args(["rev-list", "--no-walk", "--missing=print", oid])
            .env(NO_LAZY_FETCH, "1")
            .output_described()?
            .1;
        Ok(out.status.success()
            && String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|l| l.trim() == oid))
    }

    /// Write a commit-graph of every commit the refs reach when the
    /// repository has none (a fresh CI checkout): `git for-each-ref
    /// --contains` and `git merge-base` then read commits from it instead
    /// of parsing each one (on vex's history, 0.35 s a question instead of
    /// 0.04 s). What `git maintenance` or `git gc` keeps anyway; a failure
    /// (a shallow clone, an old git) only leaves the questions slower.
    /// Returns whether one was written.
    pub fn ensure_commit_graph(&self) -> bool {
        let Ok(info) = self
            .git()
            .args([
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "objects/info",
            ])
            .run_str()
        else {
            return false;
        };
        let info = Utf8PathBuf::from(info);
        if info.join("commit-graph").exists()
            || info.join("commit-graphs/commit-graph-chain").exists()
        {
            return false;
        }
        self.git()
            .args(["commit-graph", "write", "--reachable", "--no-progress"])
            .env(NO_LAZY_FETCH, "1")
            .output_described()
            .is_ok_and(|(_, out)| out.status.success())
    }

    /// The commits only `new`'s line of history holds: reachable from
    /// `new` and from no branch, remote-tracking branch or tag that does
    /// not contain `new` (the current branch's namesakes on the remotes
    /// and remote `HEAD`s aside, as in [`Repo::moved_on`]). An ancestor
    /// `old` of `new` was moved on from exactly when it is among them, so
    /// one walk of the refs answers [`Repo::moved_on`] for every such
    /// `old` (2.3.5: vex has thousands of remote branches, and asking
    /// about each earlier commit walked them all every time).
    pub fn only_on(&self, new: &str) -> Result<std::collections::BTreeSet<String>, GitError> {
        if !is_oid(new) {
            return Err(GitError::Invalid {
                what: "commit",
                value: new.to_owned(),
                reason: "not an object id",
            });
        }
        let namesakes = self.branch_namesakes()?;
        let refs = self
            .git()
            .args(["for-each-ref", "--format=%(refname)", "--no-contains", new])
            .args(["refs/heads", "refs/remotes", "refs/tags"])
            .env(NO_LAZY_FETCH, "1")
            .run_str()?;
        let mut input = format!("{new}\n--not\n");
        for r in refs
            .lines()
            .filter(|r| !r.is_empty() && !namesakes.iter().any(|n| n == r) && !r.ends_with("/HEAD"))
        {
            input.push_str(r);
            input.push('\n');
        }
        let out = self
            .git()
            .args(["rev-list", "--stdin"])
            .env(NO_LAZY_FETCH, "1")
            .run_with_stdin(input.as_bytes())?;
        Ok(String::from_utf8_lossy(&out)
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| is_oid(l))
            .collect())
    }

    /// [`Repo::moved_on`], given [`Repo::only_on`] of `new`: an `old` among
    /// them was moved on from; another ancestor of `new` was not; anything
    /// else is asked as `moved_on` asks.
    pub fn moved_on_given(
        &self,
        old: &str,
        new: &str,
        only: &std::collections::BTreeSet<String>,
    ) -> Result<bool, GitError> {
        if !is_oid(old) || !is_oid(new) || old == new {
            return Ok(false);
        }
        if only.contains(old) {
            return Ok(true);
        }
        if !self.has_object(old)? {
            return self.moved_on(old, new);
        }
        let (_, out) = self
            .git()
            .args(["merge-base", "--is-ancestor", old, new])
            .env(NO_LAZY_FETCH, "1")
            .output_described()?;
        if out.status.code() == Some(0) {
            return Ok(false);
        }
        self.moved_on(old, new)
    }

    /// Whether a line of history has moved on from `old` to `new`, so that
    /// nothing else still needs `old`: no branch, remote-tracking branch or
    /// tag contains `old` without containing `new`, except the current
    /// branch's namesakes on the remotes (`origin/<branch>` behind a local
    /// `<branch>` is the same line of work, not yet pushed), and either
    /// `old` is an ancestor of `new` or no ref at all contains `old` (a
    /// commit rebased or amended away: nothing can check its files out by
    /// name). Any other ref containing `old` (`main` under a feature branch,
    /// a sibling branch, a release tag) may be checked out with `old`'s
    /// files, and so may `old` itself when `new` is behind it (a bisect).
    /// An `old` this clone does not have at all is on none of its refs: moved
    /// on in a full clone; `false` in a shallow one, which may just lack it
    /// (nothing is concluded from a history that is not there).
    pub fn moved_on(&self, old: &str, new: &str) -> Result<bool, GitError> {
        if !is_oid(old) || !is_oid(new) || old == new {
            return Ok(false);
        }
        if !self.has_object(old)? {
            return Ok(!self.is_shallow()?);
        }
        let namesakes = self.branch_namesakes()?;
        let counts = |r: &str| namesakes.iter().any(|n| n == r) || r.ends_with("/HEAD");
        // The ancestry test first (cheap): when `new` descends from `old`,
        // the refs holding `old` but not `new` decide alone (were none of
        // them holding `old` at all, none holds it without `new` either),
        // so one walk of every ref's history instead of two (vex has
        // thousands of remote branches: 2.3.2).
        let (_, out) = self
            .git()
            .args(["merge-base", "--is-ancestor", old, new])
            .env(NO_LAZY_FETCH, "1")
            .output_described()?;
        if out.status.code() != Some(0) {
            let holders = self
                .git()
                .args(["for-each-ref", "--format=%(refname)", "--contains", old])
                .args(["refs/heads", "refs/remotes", "refs/tags"])
                .env(NO_LAZY_FETCH, "1")
                .run_str()?;
            // On no ref (namesakes aside): rebased or amended away.
            return Ok(holders.lines().all(counts));
        }
        let others = self
            .git()
            .args(["for-each-ref", "--format=%(refname)", "--contains", old])
            .args(["--no-contains", new])
            .args(["refs/heads", "refs/remotes", "refs/tags"])
            .env(NO_LAZY_FETCH, "1")
            .run_str()?;
        Ok(others.lines().all(counts))
    }

    /// `git rev-parse --is-shallow-repository`.
    pub fn is_shallow(&self) -> Result<bool, GitError> {
        Ok(self
            .git()
            .args(["rev-parse", "--is-shallow-repository"])
            .run_str()?
            .trim()
            == "true")
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

    /// The submodules checked out in the work tree, recursively: paths the
    /// index records as gitlinks (mode 160000) whose directory holds a `.git`
    /// entry, as absolute paths, sorted. A submodule's own submodules come
    /// from its index; one whose index cannot be read is left out.
    pub fn submodules(&self) -> Result<Vec<Utf8PathBuf>, GitError> {
        let mut out = Vec::new();
        let mut todo = vec![self.root.clone()];
        while let Some(root) = todo.pop() {
            let listing = match Git::at(&root).args(["ls-files", "--stage", "-z"]).run() {
                Ok(l) => l,
                Err(e) if root == self.root => return Err(e),
                Err(_) => continue,
            };
            for record in listing.split(|b| *b == 0) {
                let Some(rest) = record.strip_prefix(b"160000 ") else {
                    continue;
                };
                let Some(tab) = rest.iter().position(|b| *b == b'\t') else {
                    continue;
                };
                let Ok(path) = std::str::from_utf8(&rest[tab + 1..]) else {
                    continue;
                };
                let dir = root.join(path);
                if dir.join(".git").exists() {
                    todo.push(dir.clone());
                    out.push(dir);
                }
            }
        }
        out.sort();
        Ok(out)
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
