//! Metadata snapshot of the working tree, taken before a run, used to refuse
//! attesting inputs that changed while the tests were running (including a
//! file modified and then restored: its ctime still moves).

use std::collections::HashMap;
use std::fs::Metadata;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use vci_core::{EntryKind, InputEntry};

/// Directories that are never walked (externals are represented by the
/// lockfile and package versions, git internals are not inputs).
const SKIP_DIRS: &[&str] = &[".git", "node_modules"];

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
    map: HashMap<Utf8PathBuf, StatKey>,
}

impl TreeStat {
    pub fn snapshot(root: &Utf8Path) -> Result<Self> {
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
            map,
        })
    }

    /// `Err(reason)` if the entry's filesystem object is not provably the
    /// same as when the snapshot was taken.
    pub fn unchanged(&self, e: &InputEntry) -> Result<(), String> {
        let rel = e.path.as_str();
        if rel.split('/').any(|c| SKIP_DIRS.contains(&c)) {
            return Err(format!("{rel}: inside a directory vci does not track"));
        }
        let abs = e.path.to_abs(&self.root);
        let now = std::fs::symlink_metadata(&abs).ok().map(|m| key(&m));
        let before = self.map.get(&abs);
        match (e.kind, before, now) {
            (EntryKind::Absent, None, None) => Ok(()),
            (EntryKind::Absent, _, _) => Err(format!("{rel}: existed during the run")),
            (_, Some(b), Some(n)) if *b == n => Ok(()),
            (_, None, _) => Err(format!("{rel}: did not exist before the run")),
            _ => Err(format!("{rel}: modified during the run")),
        }
    }
}
