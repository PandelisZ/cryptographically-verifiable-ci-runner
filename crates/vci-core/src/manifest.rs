//! Input manifests: capture from the working tree, the input root, and
//! re-verification against a checkout.
//!
//! Safety rule: **fail open**. Anything unexpected during capture is an error
//! (the test is then not attestable and simply runs); anything that differs
//! during verification is a [`Mismatch`] or an error (the test runs).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::hash::{self, ABSENT_HASH, ChildType, Enc, INPUT_ROOT_DOMAIN, blake3_hex};
use crate::path::{PathError, RepoPath, strip_root};

/// Maximum symlink hops followed from one observed path.
pub const MAX_SYMLINK_HOPS: usize = 40;

/// `hash` of an [`EntryKind::Dir`] entry: BLAKE3 of the bytes `dir`.
pub fn dir_type_hash() -> String {
    blake3_hex(b"dir")
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub enum EntryKind {
    /// Regular file; `hash` is BLAKE3 of the contents, `size` the byte length.
    File,
    /// Symbolic link; `hash` is BLAKE3 of the link target string, `size` its
    /// byte length. The link's resolution is recorded as separate entries.
    Symlink,
    /// Nothing exists at the path; `hash` is [`ABSENT_HASH`], `size` 0.
    Absent,
    /// Directory; `hash` covers the sorted child names (and their types),
    /// `size` is the number of children.
    DirListing,
    /// A real directory (not a symlink) whose contents were not observed, only
    /// its type (e.g. a path component `realpath()` walked through); `hash` is
    /// [`dir_type_hash`], `size` 0.
    Dir,
}

impl EntryKind {
    /// Tag used in the input root encoding (same spelling as the JSON form).
    pub fn tag(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Symlink => "symlink",
            EntryKind::Absent => "absent",
            EntryKind::DirListing => "dirListing",
            EntryKind::Dir => "dir",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct InputEntry {
    pub path: RepoPath,
    pub kind: EntryKind,
    /// Owner-executable bit (`mode & 0o100`), as git records it. Only
    /// meaningful for files; always false otherwise.
    pub exec: bool,
    pub size: u64,
    pub hash: String,
}

impl InputEntry {
    pub fn absent(path: RepoPath) -> Self {
        InputEntry {
            path,
            kind: EntryKind::Absent,
            exec: false,
            size: 0,
            hash: ABSENT_HASH.to_owned(),
        }
    }

    fn describe(&self) -> String {
        match self.kind {
            EntryKind::Absent => "absent".to_owned(),
            EntryKind::File => {
                format!(
                    "file exec={} size={} blake3={}",
                    self.exec, self.size, self.hash
                )
            }
            EntryKind::Symlink => format!("symlink size={} blake3={}", self.size, self.hash),
            EntryKind::DirListing => {
                format!("dirListing entries={} blake3={}", self.size, self.hash)
            }
            EntryKind::Dir => "directory".to_owned(),
        }
    }

    fn same_state(&self, other: &InputEntry) -> bool {
        self.kind == other.kind
            && self.exec == other.exec
            && self.size == other.size
            && self.hash == other.hash
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct External {
    pub name: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct EnvEntry {
    pub key: String,
    /// BLAKE3 of the value's bytes; [`ABSENT_HASH`] if unset.
    pub hash: String,
}

/// What the collector saw a test do with a path.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub enum Observation {
    /// Successful read or stat. Must exist at capture time.
    Read,
    /// stat/exists/read that failed with ENOENT. Must be absent at capture time.
    Probe,
    /// Directory listing. Must be a directory at capture time.
    ReadDir,
    /// The path's type was observed, not its contents (`realpath()` walking a
    /// component). Must exist at capture time: a file is recorded like a
    /// `Read`, a directory as a type-only [`EntryKind::Dir`].
    Stat,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct InputManifest {
    pub entries: Vec<InputEntry>,
    pub externals: Vec<External>,
    pub env: Vec<EnvEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Mismatch {
    /// `entry:<repo path>` or `env:<KEY>`.
    pub what: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("{0} was read by the test but does not exist now")]
    ReadMissing(String),
    #[error("{0} was probed as absent by the test but exists now")]
    ProbeExists(String),
    #[error("{0} was listed as a directory by the test but is not a directory now")]
    NotADirectory(String),
    #[error("symlink {link} points outside the repository (target {target:?})")]
    SymlinkOutsideRepo { link: String, target: String },
    #[error(
        "symlink {link} target {target:?} cannot be resolved lexically (a '..' crosses a symlink or missing directory)"
    )]
    SymlinkUnresolvable { link: String, target: String },
    #[error("too many symlink hops starting at {0}")]
    SymlinkLoop(String),
    #[error("non-UTF-8 name under {0}")]
    NonUtf8Name(String),
    #[error("{0} is not a regular file, directory or symlink")]
    UnsupportedFileType(String),
    #[error("conflicting entries recorded for {0}")]
    ConflictingEntries(String),
    #[error("paths collide under case folding: {a:?} and {b:?}")]
    CaseCollision { a: String, b: String },
    #[error("invalid environment variable name {0:?}")]
    InvalidEnvKey(String),
}

fn io_err(path: &Utf8Path, source: io::Error) -> ManifestError {
    ManifestError::Io {
        path: path.to_string(),
        source,
    }
}

fn is_absent_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// `lstat`, except that the repository root itself is always followed (the
/// caller chose it; it is never a recorded symlink).
fn lstat(abs: &Utf8Path, is_root: bool) -> io::Result<fs::Metadata> {
    if is_root {
        fs::metadata(abs)
    } else {
        fs::symlink_metadata(abs)
    }
}

#[cfg(unix)]
fn exec_bit(md: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o100 != 0
}

#[cfg(not(unix))]
fn exec_bit(_md: &fs::Metadata) -> bool {
    false
}

fn read_link_utf8(abs: &Utf8Path) -> Result<Utf8PathBuf, ManifestError> {
    let t = fs::read_link(abs).map_err(|e| io_err(abs, e))?;
    Utf8PathBuf::from_path_buf(t).map_err(|_| ManifestError::NonUtf8Name(abs.to_string()))
}

fn hash_file(abs: &Utf8Path) -> Result<(String, u64), ManifestError> {
    let mut f = fs::File::open(abs).map_err(|e| io_err(abs, e))?;
    let mut h = blake3::Hasher::new();
    let n = io::copy(&mut f, &mut h).map_err(|e| io_err(abs, e))?;
    Ok((h.finalize().to_hex().to_string(), n))
}

fn hash_dir(abs: &Utf8Path) -> Result<(String, u64), ManifestError> {
    let mut children = Vec::new();
    for ent in fs::read_dir(abs).map_err(|e| io_err(abs, e))? {
        let ent = ent.map_err(|e| io_err(abs, e))?;
        let name = ent
            .file_name()
            .into_string()
            .map_err(|_| ManifestError::NonUtf8Name(abs.to_string()))?;
        let ft = ent.file_type().map_err(|e| io_err(abs, e))?;
        children.push((name, ChildType::from_file_type(ft)));
    }
    let n = children.len() as u64;
    Ok((hash::dir_listing_hash(&mut children), n))
}

/// Observe the current state of one path without following a final symlink.
/// With `dir_type_only`, a directory is recorded as a type-only
/// [`EntryKind::Dir`] instead of its listing.
fn observe_as(
    repo_root: &Utf8Path,
    path: &RepoPath,
    dir_type_only: bool,
) -> Result<InputEntry, ManifestError> {
    let abs = path.to_abs(repo_root);
    let md = match lstat(&abs, path.is_root()) {
        Ok(md) => md,
        Err(e) if is_absent_error(&e) => return Ok(InputEntry::absent(path.clone())),
        Err(e) => return Err(io_err(&abs, e)),
    };
    let ft = md.file_type();
    let (kind, exec, size, hash) = if ft.is_symlink() {
        let target = read_link_utf8(&abs)?;
        let t = target.as_str();
        (
            EntryKind::Symlink,
            false,
            t.len() as u64,
            blake3_hex(t.as_bytes()),
        )
    } else if ft.is_file() {
        let (h, n) = hash_file(&abs)?;
        (EntryKind::File, exec_bit(&md), n, h)
    } else if ft.is_dir() && dir_type_only {
        (EntryKind::Dir, false, 0, dir_type_hash())
    } else if ft.is_dir() {
        let (h, n) = hash_dir(&abs)?;
        (EntryKind::DirListing, false, n, h)
    } else {
        return Err(ManifestError::UnsupportedFileType(path.to_string()));
    };
    Ok(InputEntry {
        path: path.clone(),
        kind,
        exec,
        size,
        hash,
    })
}

/// Resolve a symlink's target to the repo path the OS will follow next.
///
/// Relative targets are resolved lexically against the link's parent. A `..`
/// is only accepted when the component it cancels is an existing real
/// directory (not a symlink), which is exactly when lexical and physical
/// resolution agree. Absolute targets must be lexically inside the repo root
/// (as given or canonical).
fn resolve_link_target(
    repo_root: &Utf8Path,
    link: &RepoPath,
    target: &Utf8Path,
) -> Result<RepoPath, ManifestError> {
    let outside = || ManifestError::SymlinkOutsideRepo {
        link: link.to_string(),
        target: target.to_string(),
    };
    let unresolvable = || ManifestError::SymlinkUnresolvable {
        link: link.to_string(),
        target: target.to_string(),
    };
    if target.as_str().is_empty() {
        return Err(unresolvable());
    }
    if target.is_absolute() {
        return match strip_root(repo_root, target, false) {
            Ok(p) => Ok(p),
            Err(PathError::OutsideRepo { .. }) => Err(outside()),
            Err(_) => Err(unresolvable()),
        };
    }
    let mut parts: Vec<String> = link
        .parent()
        .map(|p| p.components().map(str::to_owned).collect())
        .unwrap_or_default();
    for c in target.components() {
        match c {
            Utf8Component::CurDir => {}
            Utf8Component::ParentDir => {
                if parts.is_empty() {
                    return Err(outside());
                }
                let cancelled = repo_root.join(parts.join("/"));
                match fs::symlink_metadata(&cancelled) {
                    Ok(md) if md.file_type().is_dir() => {}
                    _ => return Err(unresolvable()),
                }
                parts.pop();
            }
            Utf8Component::Normal(n) => parts.push(n.to_owned()),
            Utf8Component::RootDir | Utf8Component::Prefix(_) => return Err(unresolvable()),
        }
    }
    if parts.is_empty() {
        return Ok(RepoPath::root());
    }
    RepoPath::new(&parts.join("/")).map_err(|_| unresolvable())
}

/// Follow symlinks starting at `start`, pushing a `Symlink` entry for every
/// hop. Returns the first path that is not a symlink (possibly absent).
fn resolve_chain(
    repo_root: &Utf8Path,
    start: &RepoPath,
    out: &mut Vec<InputEntry>,
) -> Result<RepoPath, ManifestError> {
    let mut cur = start.clone();
    for _ in 0..MAX_SYMLINK_HOPS {
        let abs = cur.to_abs(repo_root);
        let md = match lstat(&abs, cur.is_root()) {
            Ok(md) => md,
            Err(e) if is_absent_error(&e) => return Ok(cur),
            Err(e) => return Err(io_err(&abs, e)),
        };
        if !md.file_type().is_symlink() {
            return Ok(cur);
        }
        let target = read_link_utf8(&abs)?;
        let next = resolve_link_target(repo_root, &cur, &target)?;
        out.push(InputEntry {
            path: cur.clone(),
            kind: EntryKind::Symlink,
            exec: false,
            size: target.as_str().len() as u64,
            hash: blake3_hex(target.as_str().as_bytes()),
        });
        cur = next;
    }
    Err(ManifestError::SymlinkLoop(start.to_string()))
}

fn capture_one(
    repo_root: &Utf8Path,
    path: &RepoPath,
    obs: Observation,
) -> Result<Vec<InputEntry>, ManifestError> {
    let mut out = Vec::new();
    let fin = resolve_chain(repo_root, path, &mut out)?;
    let e = observe_as(repo_root, &fin, obs == Observation::Stat)?;
    match (obs, e.kind) {
        (Observation::Read | Observation::ReadDir | Observation::Stat, EntryKind::Absent) => {
            return Err(ManifestError::ReadMissing(path.to_string()));
        }
        (Observation::Stat, EntryKind::File | EntryKind::Dir) => {}
        (Observation::Stat, _) => {
            return Err(ManifestError::ConflictingEntries(fin.to_string()));
        }
        (Observation::ReadDir, EntryKind::DirListing) => {}
        (Observation::ReadDir, _) => return Err(ManifestError::NotADirectory(path.to_string())),
        (Observation::Probe, EntryKind::Absent) => {}
        (Observation::Probe, _) => return Err(ManifestError::ProbeExists(path.to_string())),
        (Observation::Read, EntryKind::File | EntryKind::DirListing) => {}
        (Observation::Read, EntryKind::Symlink | EntryKind::Dir) => {
            // resolve_chain only stops on a symlink if it vanished and was
            // recreated underneath us.
            return Err(ManifestError::ConflictingEntries(fin.to_string()));
        }
    }
    out.push(e);
    Ok(out)
}

fn validate_env_key(k: &str) -> Result<(), ManifestError> {
    if k.is_empty() || k.contains('=') || k.contains('\0') {
        return Err(ManifestError::InvalidEnvKey(k.to_owned()));
    }
    Ok(())
}

/// Hash of an environment variable value; [`ABSENT_HASH`] if unset.
pub fn env_value_hash(value: Option<&std::ffi::OsStr>) -> String {
    match value {
        Some(v) => blake3_hex(v.as_encoded_bytes()),
        None => ABSENT_HASH.to_owned(),
    }
}

fn process_env(k: &str) -> Option<OsString> {
    std::env::var_os(k)
}

/// Case folding used for collision checks: full Unicode upper- then
/// lower-casing (so `ß` and `SS` also collide). Deliberately over-eager.
fn fold(s: &str) -> String {
    s.to_uppercase().to_lowercase()
}

impl InputManifest {
    /// Build from observations by hashing the working tree under `repo_root`,
    /// reading env values from the current process. Sorts and dedups.
    ///
    /// Per observation: symlinks along the path are followed hop by hop, each
    /// hop recorded as a `Symlink` entry, and the final target recorded as its
    /// own entry (error if any hop leaves the repo). `Read` must find a file
    /// or directory (a directory is recorded as a `DirListing`), `ReadDir` a
    /// directory, and `Probe` nothing. Any other state is an error.
    ///
    /// Does not check case collisions; call [`Self::check_case_collisions`].
    pub fn capture(
        repo_root: &Utf8Path,
        observed: &[(RepoPath, Observation)],
        externals: Vec<External>,
        env_keys: &[String],
    ) -> Result<Self, ManifestError> {
        Self::capture_with_env(repo_root, observed, externals, env_keys, process_env)
    }

    /// [`Self::capture`] with an explicit environment lookup.
    pub fn capture_with_env<F>(
        repo_root: &Utf8Path,
        observed: &[(RepoPath, Observation)],
        mut externals: Vec<External>,
        env_keys: &[String],
        env: F,
    ) -> Result<Self, ManifestError>
    where
        F: Fn(&str) -> Option<OsString> + Sync,
    {
        let per_obs: Vec<Vec<InputEntry>> = observed
            .par_iter()
            .map(|(p, o)| capture_one(repo_root, p, *o))
            .collect::<Result<_, _>>()?;
        let mut entries: Vec<InputEntry> = per_obs.into_iter().flatten().collect();
        // A type-only `Dir` is implied by a listing of the same directory.
        let listed: std::collections::BTreeSet<RepoPath> = entries
            .iter()
            .filter(|e| e.kind == EntryKind::DirListing)
            .map(|e| e.path.clone())
            .collect();
        entries.retain(|e| e.kind != EntryKind::Dir || !listed.contains(&e.path));
        entries.sort();
        entries.dedup();
        for w in entries.windows(2) {
            if w[0].path == w[1].path {
                return Err(ManifestError::ConflictingEntries(w[0].path.to_string()));
            }
        }

        externals.sort();
        externals.dedup();

        let mut keys: Vec<&str> = env_keys.iter().map(String::as_str).collect();
        keys.sort_unstable();
        keys.dedup();
        let mut envs = Vec::with_capacity(keys.len());
        for k in keys {
            validate_env_key(k)?;
            envs.push(EnvEntry {
                key: k.to_owned(),
                hash: env_value_hash(env(k).as_deref()),
            });
        }

        Ok(InputManifest {
            entries,
            externals,
            env: envs,
        })
    }

    /// Deterministic BLAKE3 input root, lowercase hex.
    ///
    /// Encoding (see [`crate::hash`] for field encoding): domain tag
    /// `vci/input-root/v1`; `"entries"`, count, then per entry in sorted
    /// order: path, kind tag, exec (u64 0/1), size (u64), hash;
    /// `"externals"`, count, then name, version per external in sorted order;
    /// `"env"`, count, then key, hash per entry in sorted order.
    ///
    /// The result does not depend on the order of the vectors.
    pub fn root(&self) -> String {
        let mut entries: Vec<&InputEntry> = self.entries.iter().collect();
        entries.sort();
        let mut externals: Vec<&External> = self.externals.iter().collect();
        externals.sort();
        let mut env: Vec<&EnvEntry> = self.env.iter().collect();
        env.sort();

        let mut e = Enc::new(INPUT_ROOT_DOMAIN);
        e.str("entries").u64(entries.len() as u64);
        for x in entries {
            e.str(x.path.as_str())
                .str(x.kind.tag())
                .u64(x.exec as u64)
                .u64(x.size)
                .str(&x.hash);
        }
        e.str("externals").u64(externals.len() as u64);
        for x in externals {
            e.str(&x.name).str(&x.version);
        }
        e.str("env").u64(env.len() as u64);
        for x in env {
            e.str(&x.key).str(&x.hash);
        }
        e.finish()
    }

    /// Re-observe every entry path under `repo_root` (without re-following
    /// symlinks: each recorded hop is checked on its own) and every env key in
    /// the current process environment, and list differences. Externals are
    /// compared by the caller. An empty result means everything matches.
    pub fn diff_against_checkout(
        &self,
        repo_root: &Utf8Path,
    ) -> Result<Vec<Mismatch>, ManifestError> {
        self.diff_against_checkout_with_env(repo_root, process_env)
    }

    /// [`Self::diff_against_checkout`] with an explicit environment lookup.
    pub fn diff_against_checkout_with_env<F>(
        &self,
        repo_root: &Utf8Path,
        env: F,
    ) -> Result<Vec<Mismatch>, ManifestError>
    where
        F: Fn(&str) -> Option<OsString> + Sync,
    {
        let entry_results: Vec<Option<Mismatch>> = self
            .entries
            .par_iter()
            .map(|exp| {
                let act = observe_as(repo_root, &exp.path, exp.kind == EntryKind::Dir)?;
                Ok(if exp.same_state(&act) {
                    None
                } else {
                    Some(Mismatch {
                        what: format!("entry:{}", exp.path),
                        expected: exp.describe(),
                        actual: act.describe(),
                    })
                })
            })
            .collect::<Result<_, ManifestError>>()?;
        let mut out: Vec<Mismatch> = entry_results.into_iter().flatten().collect();

        for exp in &self.env {
            validate_env_key(&exp.key)?;
            let act = env_value_hash(env(&exp.key).as_deref());
            if act != exp.hash {
                let show = |h: &str| {
                    if h == ABSENT_HASH {
                        "unset".to_owned()
                    } else {
                        format!("blake3={h}")
                    }
                };
                out.push(Mismatch {
                    what: format!("env:{}", exp.key),
                    expected: show(&exp.hash),
                    actual: show(&act),
                });
            }
        }
        Ok(out)
    }

    /// Err if two distinct paths (or directory prefixes of paths) are equal
    /// under case folding, which would make them the same file on a
    /// case-insensitive filesystem.
    pub fn check_case_collisions(&self) -> Result<(), ManifestError> {
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        let mut paths: Vec<&str> = self.entries.iter().map(|e| e.path.as_str()).collect();
        paths.sort_unstable();
        for p in paths {
            let mut end = 0;
            loop {
                end = match p[end..].find('/') {
                    Some(i) => end + i,
                    None => p.len(),
                };
                let prefix = &p[..end];
                let folded = fold(prefix);
                match seen.get(&folded) {
                    Some(prev) if prev != prefix => {
                        return Err(ManifestError::CaseCollision {
                            a: prev.clone(),
                            b: prefix.to_owned(),
                        });
                    }
                    Some(_) => {}
                    None => {
                        seen.insert(folded, prefix.to_owned());
                    }
                }
                if end == p.len() {
                    break;
                }
                end += 1;
            }
        }
        Ok(())
    }
}
