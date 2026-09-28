//! Metadata snapshot of the working tree, taken before a run, used to refuse
//! attesting inputs that changed while the tests were running (including a
//! file modified and then restored: its ctime still moves).

use std::collections::HashMap;
use std::fs::Metadata;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use vci_core::{EntryKind, InputEntry};

/// Directories that are never walked (externals are represented by the
/// lockfile and package versions, git internals are not inputs). `.venv` is
/// the environment `uv run` manages (and may sync during a run); the pytest
/// collector reports what tests take from it as externals, never as paths.
const SKIP_DIRS: &[&str] = &[".git", "node_modules", ".venv"];

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
    map: HashMap<Utf8PathBuf, StatKey>,
}

impl TreeStat {
    pub fn snapshot(root: &Utf8Path) -> Result<Self> {
        Self::snapshot_skipping(root, &[])
    }

    /// [`Self::snapshot`] without the directories in `skip` (absolute): they
    /// are neither recorded nor walked.
    pub fn snapshot_skipping(root: &Utf8Path, skip: &[Utf8PathBuf]) -> Result<Self> {
        let mut map = HashMap::new();
        map.insert(root.to_owned(), key(&std::fs::symlink_metadata(root)?));
        let mut stack = vec![root.to_owned()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for ent in rd.flatten() {
                let Ok(name) = ent.file_name().into_string() else {
                    continue;
                };
                let p = dir.join(&name);
                if skip.contains(&p) {
                    continue;
                }
                let Ok(m) = std::fs::symlink_metadata(&p) else {
                    continue;
                };
                if m.is_dir() && !SKIP_DIRS.contains(&name.as_str()) {
                    stack.push(p.clone());
                }
                map.insert(p, key(&m));
            }
        }
        Ok(Self {
            root: root.to_owned(),
            skip: skip.to_vec(),
            map,
        })
    }

    /// Repo-relative paths that were added, removed or changed since the
    /// snapshot (directories vci does not walk excluded), sorted. Used where
    /// the collector cannot report writes (Go: `os.Remove`, `os.Rename`,
    /// `os.Mkdir` are not logged).
    pub fn changes(&self) -> Result<Vec<String>> {
        let now = Self::snapshot_skipping(&self.root, &self.skip)?;
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
    pub fn unchanged(&self, e: &InputEntry) -> Result<(), String> {
        self.unchanged_excluding(e, None)
    }

    /// [`Self::unchanged`] for a manifest whose directory listings leave out
    /// `excluded` child names (`EntryKind::Excluded` entries, such as Cargo's
    /// target directory, which the first build creates during the run). An
    /// excluded entry itself is never an input. A listing of a directory that
    /// directly holds a directory the snapshot skipped (the target dir) and
    /// whose own metadata changed is compared by its children instead: the
    /// same names and types, apart from the excluded ones, as before the run.
    pub fn unchanged_excluding(
        &self,
        e: &InputEntry,
        excluded: Option<&std::collections::BTreeSet<String>>,
    ) -> Result<(), String> {
        if e.kind == EntryKind::Excluded {
            return Ok(());
        }
        let rel = e.path.as_str();
        if rel.split('/').any(|c| SKIP_DIRS.contains(&c)) {
            return Err(format!("{rel}: inside a directory vci does not track"));
        }
        let abs = e.path.to_abs(&self.root);
        if self.skip.iter().any(|s| abs.starts_with(s)) {
            return Err(format!("{rel}: inside build output vci does not track"));
        }
        let now = std::fs::symlink_metadata(&abs).ok().map(|m| key(&m));
        let before = self.map.get(&abs);
        match (e.kind, before, now) {
            (EntryKind::Absent, None, None) => Ok(()),
            (EntryKind::Absent, _, _) => Err(format!("{rel}: existed during the run")),
            (_, Some(b), Some(n)) if *b == n => Ok(()),
            // Only the type of a `Dir` entry is an input: entries added or
            // removed inside it (a cache dir pytest creates) do not matter.
            (EntryKind::Dir, Some(b), Some(n)) if b.kind == n.kind && b.ino == n.ino => Ok(()),
            (EntryKind::DirListing, Some(b), Some(n))
                if b.kind == n.kind
                    && b.ino == n.ino
                    && excluded.is_some_and(|x| !x.is_empty())
                    && self.skip.iter().any(|s| s.parent() == Some(abs.as_path())) =>
            {
                let x = excluded.expect("checked");
                let before = self.children_before(&abs, x);
                let now = children_now(&abs, x).map_err(|err| format!("{rel}: {err}"))?;
                if before == now {
                    Ok(())
                } else {
                    Err(format!("{rel}: modified during the run"))
                }
            }
            (_, None, _) => Err(format!("{rel}: did not exist before the run")),
            _ => Err(format!("{rel}: modified during the run")),
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

/// Names and kinds of `dir`'s children now, without `skip`.
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
}
