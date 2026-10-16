//! Metadata snapshot of the working tree, taken before a run, used to refuse
//! attesting inputs that changed while the tests were running (including a
//! file modified and then restored: its ctime still moves).

use std::collections::HashMap;
use std::fs::Metadata;
use std::sync::Mutex;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use vci_core::{EntryKind, InputEntry};

/// Directories that are never walked (externals are represented by the
/// lockfile and package versions, git internals are not inputs). `.venv` is
/// the environment `uv run` manages (and may sync during a run); the pytest
/// collector reports what tests take from it as externals, never as paths.
const SKIP_DIRS: &[&str] = &[".git", "node_modules", ".venv"];

/// The entry whose presence makes a directory other than the root a nested
/// git repository or a git worktree (a `.git` directory, or the `.git` file
/// of a linked worktree). Such a directory is never walked (what is inside
/// it is never an input), but its own metadata is recorded, so that creating
/// or removing one, or a change at its top level, is still a change. A
/// submodule of the repository (a gitlink in the index) is walked like any
/// other directory: its files can be inputs.
const GIT_ENTRY: &str = ".git";

/// Why [`TreeStat::unchanged`] cannot vouch for an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unverified {
    /// The entry is somewhere vci does not snapshot (a skipped directory,
    /// build output, a nested repository or worktree): whether it changed
    /// during the run is unknown.
    Untracked(String),
    /// The entry is not the same as before the run.
    Changed(String),
}

impl std::fmt::Display for Unverified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unverified::Untracked(r) => write!(f, "input cannot be checked for changes: {r}"),
            Unverified::Changed(r) => write!(f, "input changed during the run: {r}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StatKey {
    kind: u8,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    ino: u64,
    mode: u32,
}

fn key(m: &Metadata) -> StatKey {
    let ft = m.file_type();
    let kind = if ft.is_symlink() {
        2
    } else if ft.is_dir() {
        1
    } else if ft.is_file() {
        0
    } else {
        3
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        StatKey {
            kind,
            len: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
            ino: m.ino(),
            mode: m.mode(),
        }
    }
    #[cfg(not(unix))]
    {
        let t = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| (d.as_secs() as i64, d.subsec_nanos() as i64))
            .unwrap_or((0, 0));
        StatKey {
            kind,
            len: m.len(),
            mtime: t,
            ctime: (0, 0),
            ino: 0,
            mode: m.permissions().readonly() as u32,
        }
    }
}

pub struct TreeStat {
    root: Utf8PathBuf,
    /// Absolute directories not walked (build output, e.g. Cargo's target
    /// dir), in addition to [`SKIP_DIRS`].
    skip: Vec<Utf8PathBuf>,
    /// The repository's checked-out submodules (absolute): walked although
    /// they hold a [`GIT_ENTRY`].
    submodules: Vec<Utf8PathBuf>,
    /// Directories below the root that hold a [`GIT_ENTRY`] and are not
    /// submodules (nested repositories, worktrees): their own metadata is
    /// recorded, they are not walked.
    nested: Vec<Utf8PathBuf>,
    map: HashMap<Utf8PathBuf, StatKey>,
}

/// One directory's share of a snapshot: its children's metadata (and its
/// own, handed down by its parent), or the fact that it is a nested
/// repository.
enum DirResult {
    Entries(Vec<(Utf8PathBuf, StatKey)>),
    Nested(Utf8PathBuf),
}

/// State shared by the parallel walk of [`TreeStat::snapshot_skipping`].
struct Walk<'a> {
    root: &'a Utf8Path,
    skip: &'a [Utf8PathBuf],
    submodules: &'a [Utf8PathBuf],
    results: Mutex<Vec<DirResult>>,
}

impl Walk<'_> {
    /// Lists `dir` (whose own metadata is `own`, `None` for the root, which
    /// the caller records) and spawns a task per subdirectory to walk. A
    /// directory other than the root that holds a [`GIT_ENTRY`] and is not a
    /// submodule contributes its own entry only. An unreadable directory is
    /// recorded but not walked.
    fn dir<'s>(&'s self, scope: &rayon::Scope<'s>, dir: Utf8PathBuf, own: Option<StatKey>) {
        let mut out = Vec::new();
        if let Some(k) = own {
            out.push((dir.clone(), k));
        }
        let Ok(rd) = std::fs::read_dir(&dir) else {
            self.push(DirResult::Entries(out));
            return;
        };
        let names: Vec<std::ffi::OsString> = rd.flatten().map(|e| e.file_name()).collect();
        if dir != self.root
            && names.iter().any(|n| n == GIT_ENTRY)
            && !self.submodules.contains(&dir)
        {
            self.push(DirResult::Entries(out));
            self.push(DirResult::Nested(dir));
            return;
        }
        for name in names {
            let Ok(name) = name.into_string() else {
                continue;
            };
            let p = dir.join(&name);
            if self.skip.contains(&p) {
                continue;
            }
            let Ok(m) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            let k = key(&m);
            if m.is_dir() && !SKIP_DIRS.contains(&name.as_str()) {
                scope.spawn(move |s| self.dir(s, p, Some(k)));
            } else {
                out.push((p, k));
            }
        }
        self.push(DirResult::Entries(out));
    }

    fn push(&self, r: DirResult) {
        self.results
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(r);
    }
}

impl TreeStat {
    pub fn snapshot(root: &Utf8Path) -> Result<Self> {
        Self::snapshot_skipping(root, &[])
    }

    /// [`Self::snapshot`] without the directories in `skip` (absolute): they
    /// are neither recorded nor walked. Directories below the root that hold
    /// a `.git` entry and are not submodules of the repository (nested
    /// repositories and git worktrees, such as agents' worktrees under the
    /// checkout: never inputs, and often most of the tree) are recorded but
    /// not walked. The walk runs in parallel, one task per directory.
    pub fn snapshot_skipping(root: &Utf8Path, skip: &[Utf8PathBuf]) -> Result<Self> {
        Self::snapshot_with(root, skip, submodules_of(root))
    }

    fn snapshot_with(
        root: &Utf8Path,
        skip: &[Utf8PathBuf],
        submodules: Vec<Utf8PathBuf>,
    ) -> Result<Self> {
        let root_key = key(&std::fs::symlink_metadata(root)?);
        let walk = Walk {
            root,
            skip,
            submodules: &submodules,
            results: Mutex::new(Vec::new()),
        };
        rayon::scope(|s| walk.dir(s, root.to_owned(), None));
        let results = walk.results.into_inner().unwrap_or_else(|p| p.into_inner());
        let len = results
            .iter()
            .map(|r| match r {
                DirResult::Entries(e) => e.len(),
                DirResult::Nested(_) => 0,
            })
            .sum::<usize>();
        let mut map = HashMap::with_capacity(len + 1);
        let mut nested = Vec::new();
        map.insert(root.to_owned(), root_key);
        for r in results {
            match r {
                DirResult::Entries(e) => map.extend(e),
                DirResult::Nested(d) => nested.push(d),
            }
        }
        nested.sort();
        Ok(Self {
            root: root.to_owned(),
            skip: skip.to_vec(),
            submodules,
            nested,
            map,
        })
    }

    /// Repo-relative paths that were added, removed or changed since the
    /// snapshot (directories vci does not walk excluded), sorted. Used where
    /// the collector cannot report writes (Go: `os.Remove`, `os.Rename`,
    /// `os.Mkdir` are not logged).
    pub fn changes(&self) -> Result<Vec<String>> {
        let now = Self::snapshot_with(&self.root, &self.skip, self.submodules.clone())?;
        let rel = |p: &Utf8PathBuf| -> Option<String> {
            let r = p.strip_prefix(&self.root).ok()?.as_str();
            if r.split('/').any(|c| SKIP_DIRS.contains(&c)) {
                return None;
            }
            Some(if r.is_empty() {
                ".".to_owned()
            } else {
                r.to_owned()
            })
        };
        let mut out: Vec<String> = Vec::new();
        for (p, k) in &now.map {
            if self.map.get(p) != Some(k) {
                out.extend(rel(p));
            }
        }
        for p in self.map.keys() {
            if !now.map.contains_key(p) {
                out.extend(rel(p));
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// `Err(reason)` if the entry's filesystem object is not provably the
    /// same as when the snapshot was taken.
    pub fn unchanged(&self, e: &InputEntry) -> Result<(), Unverified> {
        self.unchanged_excluding(e, None)
    }

    /// [`Self::unchanged`] for a manifest whose directory listings leave out
    /// `excluded` child names (`EntryKind::Excluded` entries, such as Cargo's
    /// target directory, which the first build creates during the run, or a
    /// Rails test database with its `-journal`/`-wal`/`-shm` files, which
    /// SQLite creates and removes while the tests run). An excluded entry
    /// itself is never an input. A listing that leaves out some of its
    /// children and whose directory's own metadata changed is compared by
    /// its children instead: the same names and types, apart from the
    /// excluded ones, as before the run (what the listing's hash covers).
    pub fn unchanged_excluding(
        &self,
        e: &InputEntry,
        excluded: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<(), Unverified> {
        if e.kind == EntryKind::Excluded {
            return Ok(());
        }
        let rel = e.path.as_str();
        if rel.split('/').any(|c| SKIP_DIRS.contains(&c)) {
            return Err(Unverified::Untracked(format!(
                "{rel}: inside a directory vci does not track"
            )));
        }
        let abs = e.path.to_abs(&self.root);
        if self.skip.iter().any(|s| abs.starts_with(s)) {
            return Err(Unverified::Untracked(format!(
                "{rel}: inside build output vci does not track"
            )));
        }
        if self.nested.iter().any(|n| abs.starts_with(n) && abs != *n) {
            return Err(Unverified::Untracked(format!(
                "{rel}: inside a nested git repository or worktree vci does not track"
            )));
        }
        let changed = |r: String| Err(Unverified::Changed(r));
        let now = std::fs::symlink_metadata(&abs).ok().map(|m| key(&m));
        let before = self.map.get(&abs);
        match (e.kind, before, now) {
            (EntryKind::Absent, None, None) => Ok(()),
            (EntryKind::Absent, _, _) => changed(format!("{rel}: existed during the run")),
            (_, Some(b), Some(n)) if *b == n => Ok(()),
            // Only the type of a `Dir` entry is an input: entries added or
            // removed inside it (a cache dir pytest creates) do not matter.
            (EntryKind::Dir, Some(b), Some(n)) if b.kind == n.kind && b.ino == n.ino => Ok(()),
            (EntryKind::DirListing, Some(b), Some(n))
                if b.kind == n.kind
                    && b.ino == n.ino
                    && excluded.is_some_and(|x| !x.is_empty()) =>
            {
                let x = excluded.expect("checked");
                let before = self.children_before(&abs, x);
                let now = children_now(&abs, x)
                    .map_err(|err| Unverified::Changed(format!("{rel}: {err}")))?;
                if before == now {
                    Ok(())
                } else {
                    changed(format!("{rel}: modified during the run"))
                }
            }
            // Present now under this spelling but not in the snapshot: on a
            // case-insensitive file system, a path spelled with another letter
            // case than the file on disk (or a file created during the run).
            (_, None, Some(_)) => changed(format!(
                "{rel}: not found under this spelling before the run (its letter case differs from the file on disk, or it was created during the run)"
            )),
            (_, None, None) => changed(format!("{rel}: did not exist before the run")),
            _ => changed(format!("{rel}: modified during the run")),
        }
    }
}

impl TreeStat {
    /// Names and kinds of `dir`'s children in the snapshot, without `skip`.
    fn children_before(
        &self,
        dir: &Utf8Path,
        skip: &std::collections::BTreeSet<String>,
    ) -> std::collections::BTreeSet<(String, u8)> {
        self.map
            .iter()
            .filter(|(p, _)| p.parent() == Some(dir))
            .filter_map(|(p, k)| Some((p.file_name()?.to_owned(), k.kind)))
            .filter(|(n, _)| !skip.contains(n))
            .collect()
    }
}

/// Names and kinds of `dir`'s children now, without `skip` (nested
/// repositories and worktrees included: the snapshot records them too).
fn children_now(
    dir: &Utf8Path,
    skip: &std::collections::BTreeSet<String>,
) -> std::io::Result<std::collections::BTreeSet<(String, u8)>> {
    let mut out = std::collections::BTreeSet::new();
    for ent in std::fs::read_dir(dir)? {
        let ent = ent?;
        let Ok(name) = ent.file_name().into_string() else {
            return Err(std::io::Error::other("non-UTF-8 name"));
        };
        if skip.contains(&name) {
            continue;
        }
        let m = std::fs::symlink_metadata(dir.join(&name))?;
        out.insert((name, key(&m).kind));
    }
    Ok(out)
}

/// The checked-out submodules of the repository whose work tree is `root`
/// (see [`vci_git::Repo::submodules`]); none when `root` is not the top of a
/// work tree or git cannot list them (they are then left out of the
/// snapshot like other nested repositories, and their files are refused as
/// inputs: fail closed).
fn submodules_of(root: &Utf8Path) -> Vec<Utf8PathBuf> {
    let canon = |p: &Utf8Path| p.canonicalize_utf8().unwrap_or_else(|_| p.to_owned());
    let Ok(repo) = vci_git::Repo::discover(root) else {
        return vec![];
    };
    let top = canon(repo.root());
    if top != canon(root) {
        return vec![];
    }
    repo.submodules()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|d| Some(root.join(d.strip_prefix(repo.root()).ok()?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_lists_added_removed_and_modified_paths() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        std::fs::create_dir_all(root.join("a/sub")).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join("a/x.txt"), "x").unwrap();
        std::fs::write(root.join("a/sub/y.txt"), "y").unwrap();
        let before = TreeStat::snapshot(&root).unwrap();
        assert!(before.changes().unwrap().is_empty());
        std::fs::remove_file(root.join("a/sub/y.txt")).unwrap();
        std::fs::write(root.join("a/new.txt"), "n").unwrap();
        std::fs::write(root.join(".git/HEAD"), "ref").unwrap();
        let ch = before.changes().unwrap();
        assert!(ch.contains(&"a/sub/y.txt".to_owned()), "{ch:?}");
        assert!(ch.contains(&"a/new.txt".to_owned()), "{ch:?}");
        assert!(ch.contains(&"a".to_owned()), "{ch:?}");
        assert!(!ch.iter().any(|c| c.starts_with(".git")), "{ch:?}");
    }

    /// Regression (a package at the repository root): the first `cargo test`
    /// creates `target/` in the root during the run, which changed the root's
    /// metadata, so its listing was refused as "modified during the run"
    /// although the listing without the target dir is the same.
    #[test]
    fn a_listing_without_the_target_dir_survives_its_creation() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "x").unwrap();
        let target = root.join("target");
        let before = TreeStat::snapshot_skipping(&root, std::slice::from_ref(&target)).unwrap();
        std::fs::create_dir_all(target.join("debug")).unwrap();
        let listing = InputEntry {
            path: vci_core::RepoPath::root(),
            kind: EntryKind::DirListing,
            exec: false,
            size: 1,
            hash: String::new(),
        };
        let x: std::collections::BTreeSet<String> = ["target".to_owned()].into();
        assert!(before.unchanged(&listing).is_err(), "plain check: modified");
        assert_eq!(before.unchanged_excluding(&listing, Some(&x)), Ok(()));
        // Another new name in the same directory is still a change.
        std::fs::write(root.join("new.rs"), "").unwrap();
        assert!(before.unchanged_excluding(&listing, Some(&x)).is_err());
    }

    /// A Rails test database (not a skipped directory) created, journaled
    /// and written during the run: a listing of db/ that leaves it and its
    /// siblings out is unchanged; any other new name is a change.
    #[test]
    fn a_listing_without_the_test_database_survives_its_creation() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        std::fs::create_dir_all(root.join("db")).unwrap();
        std::fs::write(root.join("db/schema.rb"), "x").unwrap();
        let before = TreeStat::snapshot(&root).unwrap();
        std::fs::write(root.join("db/test.sqlite3"), "db").unwrap();
        std::fs::write(root.join("db/test.sqlite3-wal"), "").unwrap();
        std::fs::write(root.join("db/test.sqlite3-shm"), "").unwrap();
        let listing = InputEntry {
            path: vci_core::RepoPath::new("db").unwrap(),
            kind: EntryKind::DirListing,
            exec: false,
            size: 1,
            hash: String::new(),
        };
        let x: std::collections::BTreeSet<String> = [
            "test.sqlite3",
            "test.sqlite3-wal",
            "test.sqlite3-shm",
            "test.sqlite3-journal",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert!(before.unchanged(&listing).is_err(), "plain check: modified");
        assert_eq!(before.unchanged_excluding(&listing, Some(&x)), Ok(()));
        std::fs::write(root.join("db/other.sqlite3"), "").unwrap();
        assert!(before.unchanged_excluding(&listing, Some(&x)).is_err());
    }

    /// Regression: an import spelled with another letter case than the file
    /// (it resolves on a case-insensitive file system) was reported as "did
    /// not exist before the run".
    #[test]
    fn a_path_missing_from_the_snapshot_but_present_names_the_likely_cause() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        std::fs::write(root.join("Foo.mjs"), "x").unwrap();
        let before = TreeStat::snapshot(&root).unwrap();
        std::fs::write(root.join("new.mjs"), "x").unwrap();
        let entry = |p: &str| InputEntry {
            path: vci_core::RepoPath::from_abs(&root, &root.join(p)).unwrap(),
            kind: EntryKind::File,
            exec: false,
            size: 1,
            hash: String::new(),
        };
        let e = before.unchanged(&entry("new.mjs")).unwrap_err().to_string();
        assert!(
            e.contains("letter case") && !e.contains("did not exist"),
            "{e}"
        );
        let e = before
            .unchanged(&entry("gone.mjs"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("did not exist before the run"), "{e}");
    }

    /// A directory below the root holding a `.git` entry (a linked
    /// worktree's `.git` file, or a nested repository's `.git` directory) is
    /// recorded but not walked; the root, which holds `.git` too, is walked.
    #[test]
    fn nested_repositories_and_worktrees_are_not_walked() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/HEAD"), "ref").unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "x").unwrap();
        let wt = root.join(".claude/worktrees/agent-1");
        std::fs::create_dir_all(wt.join("src")).unwrap();
        std::fs::write(wt.join(".git"), "gitdir: ../../../.git/worktrees/agent-1").unwrap();
        std::fs::write(wt.join("src/lib.rs"), "x").unwrap();
        let sub = root.join("vendor/repo");
        std::fs::create_dir_all(sub.join(".git")).unwrap();
        std::fs::create_dir_all(sub.join("doc")).unwrap();
        std::fs::write(sub.join("doc/README"), "r").unwrap();
        let before = TreeStat::snapshot(&root).unwrap();
        for p in [
            &root,
            &root.join(".git"),
            &root.join("src/lib.rs"),
            &wt,
            &sub,
        ] {
            assert!(before.map.contains_key(p), "{p} not recorded");
        }
        assert!(
            !before
                .map
                .keys()
                .any(|p| p.strip_prefix(&wt).is_ok_and(|r| r != "")
                    || p.strip_prefix(&sub).is_ok_and(|r| r != "")),
            "{:?}",
            before.map.keys().collect::<Vec<_>>()
        );
        assert_eq!(before.nested, vec![wt.clone(), sub.clone()]);
        // Changes inside them (below their top level) are not changes of
        // the repository.
        std::fs::write(wt.join("src/lib.rs"), "changed").unwrap();
        std::fs::write(wt.join("src/new.rs"), "n").unwrap();
        std::fs::remove_file(sub.join("doc/README")).unwrap();
        assert_eq!(before.changes().unwrap(), Vec::<String>::new());
        // An entry inside one is refused with that reason; the directory
        // itself is checked like any other.
        let entry = |p: &Utf8Path, kind| InputEntry {
            path: vci_core::RepoPath::from_abs(&root, p).unwrap(),
            kind,
            exec: false,
            size: 1,
            hash: String::new(),
        };
        let e = before
            .unchanged(&entry(&wt.join("src/lib.rs"), EntryKind::File))
            .unwrap_err();
        assert!(matches!(&e, Unverified::Untracked(r) if r.contains("nested git repository")));
        assert!(
            e.to_string()
                .starts_with("input cannot be checked for changes: "),
            "{e}"
        );
        assert_eq!(before.unchanged(&entry(&wt, EntryKind::Dir)), Ok(()));
        // A listing of their parent compared by its children: a new
        // worktree is a new child, as is a new plain directory.
        let listing = entry(&root.join(".claude/worktrees"), EntryKind::DirListing);
        let x: std::collections::BTreeSet<String> = ["unrelated".to_owned()].into();
        std::fs::write(root.join(".claude/worktrees/unrelated"), "").unwrap();
        assert!(before.unchanged(&listing).is_err(), "plain check: modified");
        assert_eq!(before.unchanged_excluding(&listing, Some(&x)), Ok(()));
        let wt2 = root.join(".claude/worktrees/agent-2");
        std::fs::create_dir_all(&wt2).unwrap();
        std::fs::write(wt2.join(".git"), "gitdir: x").unwrap();
        assert!(matches!(
            before.unchanged_excluding(&listing, Some(&x)),
            Err(Unverified::Changed(_))
        ));
        assert!(
            before
                .changes()
                .unwrap()
                .contains(&".claude/worktrees/agent-2".to_owned())
        );
    }

    /// Regression: a test that deletes a nested repository in its package
    /// directory (the repository root, whose listing leaves out `target`)
    /// changed the tree it ran in, but the nested repository was in neither
    /// the snapshot nor the listing compared by its children, so the unit
    /// was attested for a tree without it.
    #[test]
    fn removing_a_nested_repository_is_a_change() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "x").unwrap();
        let inner = root.join("inner");
        std::fs::create_dir_all(inner.join(".git")).unwrap();
        std::fs::write(inner.join("README"), "r").unwrap();
        let target = root.join("target");
        let before = TreeStat::snapshot_skipping(&root, std::slice::from_ref(&target)).unwrap();
        std::fs::create_dir_all(target.join("debug")).unwrap();
        std::fs::remove_dir_all(&inner).unwrap();
        let listing = InputEntry {
            path: vci_core::RepoPath::root(),
            kind: EntryKind::DirListing,
            exec: false,
            size: 1,
            hash: String::new(),
        };
        let x: std::collections::BTreeSet<String> = ["target".to_owned()].into();
        assert_eq!(
            before.unchanged_excluding(&listing, Some(&x)),
            Err(Unverified::Changed(".: modified during the run".into()))
        );
        assert!(before.changes().unwrap().contains(&"inner".to_owned()));
        // Creating one is a change too.
        let before = TreeStat::snapshot_skipping(&root, std::slice::from_ref(&target)).unwrap();
        std::fs::create_dir_all(inner.join(".git")).unwrap();
        assert!(before.unchanged_excluding(&listing, Some(&x)).is_err());
        assert_eq!(
            before.changes().unwrap(),
            vec![".".to_owned(), "inner".to_owned()]
        );
    }

    fn git(dir: &Utf8Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
    }

    /// A submodule (a gitlink in the repository's index) is walked: its
    /// files are inputs like any other, checked like any other.
    #[test]
    fn submodules_are_walked() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("lib.go"), "package sub").unwrap();
        git(&sub, &["init", "-q"]);
        git(&sub, &["add", "."]);
        git(&sub, &["commit", "-q", "-m", "s"]);
        std::fs::write(root.join("main.go"), "package main").unwrap();
        let other = root.join("other");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("x"), "x").unwrap();
        git(&other, &["init", "-q"]);
        git(&root, &["init", "-q"]);
        // `git add` of a repository with commits records a gitlink.
        git(&root, &["add", "main.go", "sub"]);
        git(&root, &["commit", "-q", "-m", "r"]);
        let before = TreeStat::snapshot(&root).unwrap();
        assert_eq!(before.submodules, vec![sub.clone()]);
        assert_eq!(before.nested, vec![other.clone()]);
        let entry = |p: &Utf8Path| InputEntry {
            path: vci_core::RepoPath::from_abs(&root, p).unwrap(),
            kind: EntryKind::File,
            exec: false,
            size: 1,
            hash: String::new(),
        };
        assert_eq!(before.unchanged(&entry(&sub.join("lib.go"))), Ok(()));
        assert!(matches!(
            before.unchanged(&entry(&other.join("x"))),
            Err(Unverified::Untracked(_))
        ));
        assert_eq!(before.changes().unwrap(), Vec::<String>::new());
        std::fs::write(sub.join("lib.go"), "package sub // changed").unwrap();
        assert!(matches!(
            before.unchanged(&entry(&sub.join("lib.go"))),
            Err(Unverified::Changed(_))
        ));
        assert_eq!(before.changes().unwrap(), vec!["sub/lib.go".to_owned()]);
    }

    /// Timing probe (not a check): snapshots the directory named by
    /// `VCI_TREESTAT_ROOT` and prints how long it took and how many entries it
    /// recorded. `cargo test --release -p vci-cli --lib -- --ignored
    /// --nocapture snapshot_timing`.
    #[test]
    #[ignore = "measures a real tree named by VCI_TREESTAT_ROOT"]
    fn snapshot_timing() {
        let Ok(root) = std::env::var("VCI_TREESTAT_ROOT") else {
            return;
        };
        let root = Utf8PathBuf::from(root);
        for _ in 0..2 {
            let t = std::time::Instant::now();
            let s = TreeStat::snapshot(&root).unwrap();
            eprintln!("treestat: {} entries in {:.2?}", s.map.len(), t.elapsed());
        }
    }
}
