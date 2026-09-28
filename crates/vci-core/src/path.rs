//! Repo-relative paths.
//!
//! A [`RepoPath`] is always relative to the repository root, uses `/` as the
//! only separator, contains no `.` or `..` components, no empty components,
//! no leading or trailing `/`, no NUL and no `\`. The repository root itself is
//! spelled `.`.
//!
//! Paths are compared byte-exactly. No Unicode normalisation or case folding is
//! applied here; case-fold collisions are detected separately by
//! [`crate::InputManifest::check_case_collisions`].

use std::fmt;

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

/// Spelling of the repository root as a [`RepoPath`].
pub const ROOT: &str = ".";

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PathError {
    #[error("empty path")]
    Empty,
    #[error("path must be repo-relative, got absolute path {0:?}")]
    Absolute(String),
    #[error("path {0:?} contains a '..' component")]
    ParentComponent(String),
    #[error("path {0:?} contains a backslash")]
    Backslash(String),
    #[error("path {0:?} contains a NUL byte")]
    Nul(String),
    #[error("path {0:?} is not absolute")]
    NotAbsolute(String),
    #[error("path {path:?} is outside the repository root {root:?}")]
    OutsideRepo { root: String, path: String },
    #[error("path {0:?} has an unsupported prefix component")]
    Prefix(String),
    #[error("path {0:?} is not in canonical form")]
    NotCanonical(String),
}

/// Repo-relative, `/`-separated, normalised path. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RepoPath(String);

impl RepoPath {
    /// Parse and normalise a repo-relative path.
    ///
    /// Normalisation removes `.` components, empty components (`a//b`) and a
    /// trailing `/`. Rejected: empty input, a leading `/`, any `..` component,
    /// `\` and NUL. `.` (or `./`) denotes the repository root.
    pub fn new(s: &str) -> Result<Self, PathError> {
        if s.is_empty() {
            return Err(PathError::Empty);
        }
        if s.starts_with('/') {
            return Err(PathError::Absolute(s.to_owned()));
        }
        if s.contains('\0') {
            return Err(PathError::Nul(s.to_owned()));
        }
        if s.contains('\\') {
            return Err(PathError::Backslash(s.to_owned()));
        }
        let mut parts: Vec<&str> = Vec::new();
        for comp in s.split('/') {
            match comp {
                "" | "." => {}
                ".." => return Err(PathError::ParentComponent(s.to_owned())),
                other => parts.push(other),
            }
        }
        if parts.is_empty() {
            return Ok(Self::root());
        }
        Ok(RepoPath(parts.join("/")))
    }

    /// The repository root, spelled `.`.
    pub fn root() -> Self {
        RepoPath(ROOT.to_owned())
    }

    pub fn is_root(&self) -> bool {
        self.0 == ROOT
    }

    /// Convert an absolute path into a repo-relative one.
    ///
    /// `abs` is normalised lexically (`.` and empty components removed); a `..`
    /// component is rejected rather than resolved. The prefix is first matched
    /// against `repo_root` as given, then against its canonical form (so that
    /// e.g. `/private/var/...` matches a root given as `/var/...` on macOS), and
    /// finally the parent directory of `abs` is canonicalised (the last
    /// component is kept as-is so a symlink stays a symlink). Returns
    /// [`PathError::OutsideRepo`] if none match.
    pub fn from_abs(repo_root: &Utf8Path, abs: &Utf8Path) -> Result<Self, PathError> {
        strip_root(repo_root, abs, true)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Path on disk under `repo_root`.
    pub fn to_abs(&self, repo_root: &Utf8Path) -> Utf8PathBuf {
        if self.is_root() {
            repo_root.to_owned()
        } else {
            repo_root.join(&self.0)
        }
    }

    /// Parent directory; the root for a single-component path; `None` for the
    /// root itself.
    pub fn parent(&self) -> Option<RepoPath> {
        if self.is_root() {
            return None;
        }
        match self.0.rfind('/') {
            Some(i) => Some(RepoPath(self.0[..i].to_owned())),
            None => Some(Self::root()),
        }
    }

    /// Path components (empty for the root).
    pub fn components(&self) -> impl Iterator<Item = &str> {
        let s: &str = if self.is_root() { "" } else { &self.0 };
        s.split('/').filter(|c| !c.is_empty())
    }
}

/// Lexically normalise an absolute path: drop `.` and empty components; reject
/// `..` and platform prefixes.
fn normalise_abs(p: &Utf8Path) -> Result<Utf8PathBuf, PathError> {
    if !p.is_absolute() {
        return Err(PathError::NotAbsolute(p.to_string()));
    }
    let mut out = Utf8PathBuf::new();
    for c in p.components() {
        match c {
            Utf8Component::RootDir => out.push("/"),
            Utf8Component::CurDir => {}
            Utf8Component::ParentDir => return Err(PathError::ParentComponent(p.to_string())),
            Utf8Component::Normal(n) => out.push(n),
            Utf8Component::Prefix(_) => return Err(PathError::Prefix(p.to_string())),
        }
    }
    Ok(out)
}

fn try_strip(root: &Utf8Path, abs: &Utf8Path) -> Option<Result<RepoPath, PathError>> {
    let rel = abs.strip_prefix(root).ok()?;
    if rel.as_str().is_empty() {
        return Some(Ok(RepoPath::root()));
    }
    Some(RepoPath::new(rel.as_str()))
}

/// Shared implementation of [`RepoPath::from_abs`]. With
/// `canonicalise_parent == false` only lexical matching against the root (as
/// given, then canonical) is attempted: used when resolving symlink targets,
/// where resolving intermediate symlinks would record a path different from
/// the one the OS follows.
pub(crate) fn strip_root(
    repo_root: &Utf8Path,
    abs: &Utf8Path,
    canonicalise_parent: bool,
) -> Result<RepoPath, PathError> {
    let abs_n = normalise_abs(abs)?;
    let outside = || PathError::OutsideRepo {
        root: repo_root.to_string(),
        path: abs.to_string(),
    };

    if repo_root.is_absolute()
        && let Ok(root_n) = normalise_abs(repo_root)
        && let Some(r) = try_strip(&root_n, &abs_n)
    {
        return r;
    }
    let Some(canon_root) = repo_root
        .canonicalize_utf8()
        .ok()
        .and_then(|p| normalise_abs(&p).ok())
    else {
        return Err(outside());
    };
    if let Some(r) = try_strip(&canon_root, &abs_n) {
        return r;
    }
    if canonicalise_parent
        && let (Some(parent), Some(name)) = (abs_n.parent(), abs_n.file_name())
        && let Ok(cp) = parent.canonicalize_utf8()
        && let Ok(cp) = normalise_abs(&cp)
        && let Some(r) = try_strip(&canon_root, &cp.join(name))
    {
        return r;
    }
    Err(outside())
}

impl fmt::Display for RepoPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RepoPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Strict conversion used by deserialisation: the input must already be in
/// canonical form (what [`RepoPath::new`] would produce), so two different
/// serialised manifests never decode to the same paths.
impl TryFrom<String> for RepoPath {
    type Error = PathError;
    fn try_from(s: String) -> Result<Self, PathError> {
        let p = RepoPath::new(&s)?;
        if p.0 != s {
            return Err(PathError::NotCanonical(s));
        }
        Ok(p)
    }
}

impl TryFrom<&str> for RepoPath {
    type Error = PathError;
    fn try_from(s: &str) -> Result<Self, PathError> {
        RepoPath::new(s)
    }
}

impl std::str::FromStr for RepoPath {
    type Err = PathError;
    fn from_str(s: &str) -> Result<Self, PathError> {
        RepoPath::new(s)
    }
}

impl From<RepoPath> for String {
    fn from(p: RepoPath) -> String {
        p.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(s: &str) -> String {
        RepoPath::new(s).unwrap().as_str().to_owned()
    }

    #[test]
    fn normalises() {
        assert_eq!(rp("a/b.ts"), "a/b.ts");
        assert_eq!(rp("./a/b.ts"), "a/b.ts");
        assert_eq!(rp("a//b.ts"), "a/b.ts");
        assert_eq!(rp("a/./b.ts"), "a/b.ts");
        assert_eq!(rp("a/b/"), "a/b");
        assert_eq!(rp("."), ".");
        assert_eq!(rp("./"), ".");
        assert_eq!(rp(".//."), ".");
        assert_eq!(rp(".hidden"), ".hidden");
        assert_eq!(rp("a/..b"), "a/..b");
        assert_eq!(rp("a/b.."), "a/b..");
        assert_eq!(rp("with space/ü.ts"), "with space/ü.ts");
    }

    #[test]
    fn rejects() {
        assert_eq!(RepoPath::new(""), Err(PathError::Empty));
        assert!(matches!(RepoPath::new("/a"), Err(PathError::Absolute(_))));
        assert!(matches!(
            RepoPath::new(".."),
            Err(PathError::ParentComponent(_))
        ));
        assert!(matches!(
            RepoPath::new("a/../b"),
            Err(PathError::ParentComponent(_))
        ));
        assert!(matches!(
            RepoPath::new("a/.."),
            Err(PathError::ParentComponent(_))
        ));
        assert!(matches!(
            RepoPath::new("a\\b"),
            Err(PathError::Backslash(_))
        ));
        assert!(matches!(RepoPath::new("a\0b"), Err(PathError::Nul(_))));
    }

    #[test]
    fn no_unicode_normalisation() {
        let nfc = RepoPath::new("caf\u{e9}.ts").unwrap();
        let nfd = RepoPath::new("cafe\u{301}.ts").unwrap();
        assert_ne!(nfc, nfd);
        assert_ne!(nfc.as_str().as_bytes(), nfd.as_str().as_bytes());
    }

    #[test]
    fn byte_order_sorting() {
        let mut v: Vec<RepoPath> = ["b", "a/b", "a", "B", "a-b", "a/a"]
            .iter()
            .map(|s| RepoPath::new(s).unwrap())
            .collect();
        v.sort();
        let got: Vec<&str> = v.iter().map(|p| p.as_str()).collect();
        assert_eq!(got, vec!["B", "a", "a-b", "a/a", "a/b", "b"]);
    }

    #[test]
    fn parent_and_components() {
        let p = RepoPath::new("a/b/c").unwrap();
        assert_eq!(p.parent().unwrap().as_str(), "a/b");
        assert_eq!(
            RepoPath::new("a").unwrap().parent().unwrap(),
            RepoPath::root()
        );
        assert_eq!(RepoPath::root().parent(), None);
        assert_eq!(p.components().collect::<Vec<_>>(), vec!["a", "b", "c"]);
        assert_eq!(RepoPath::root().components().count(), 0);
    }

    #[test]
    fn from_abs_lexical() {
        let root = Utf8Path::new("/nonexistent-vci/repo");
        let f = |s: &str| RepoPath::from_abs(root, Utf8Path::new(s));
        assert_eq!(
            f("/nonexistent-vci/repo/src/a.ts").unwrap().as_str(),
            "src/a.ts"
        );
        assert_eq!(
            f("/nonexistent-vci/repo/./src//a.ts").unwrap().as_str(),
            "src/a.ts"
        );
        assert_eq!(f("/nonexistent-vci/repo").unwrap(), RepoPath::root());
        assert_eq!(f("/nonexistent-vci/repo/").unwrap(), RepoPath::root());
        assert!(matches!(
            f("/nonexistent-vci/repo2/a.ts"),
            Err(PathError::OutsideRepo { .. })
        ));
        assert!(matches!(
            f("/nonexistent-vci/a.ts"),
            Err(PathError::OutsideRepo { .. })
        ));
        assert!(matches!(
            f("/nonexistent-vci/repo/../repo/a.ts"),
            Err(PathError::ParentComponent(_))
        ));
        assert!(matches!(f("src/a.ts"), Err(PathError::NotAbsolute(_))));
    }

    #[test]
    fn from_abs_canonical_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(dir.path().to_owned()).unwrap();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.ts"), "x").unwrap();
        let canon = root.canonicalize_utf8().unwrap();
        // Root given one way, path given the other (differs on macOS: /var vs /private/var).
        assert_eq!(
            RepoPath::from_abs(&root, &canon.join("src/a.ts"))
                .unwrap()
                .as_str(),
            "src/a.ts"
        );
        assert_eq!(
            RepoPath::from_abs(&canon, &root.join("src/a.ts"))
                .unwrap()
                .as_str(),
            "src/a.ts"
        );
    }

    #[cfg(unix)]
    #[test]
    fn from_abs_via_outside_symlink_to_repo_dir() {
        let dir = tempfile::tempdir().unwrap();
        let base = Utf8PathBuf::from_path_buf(dir.path().canonicalize().unwrap()).unwrap();
        let root = base.join("repo");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.ts"), "x").unwrap();
        std::os::unix::fs::symlink(root.join("src"), base.join("alias")).unwrap();
        assert_eq!(
            RepoPath::from_abs(&root, &base.join("alias/a.ts"))
                .unwrap()
                .as_str(),
            "src/a.ts"
        );
    }

    #[test]
    fn serde_validates() {
        let p: RepoPath = serde_json::from_str("\"src/a.ts\"").unwrap();
        assert_eq!(p.as_str(), "src/a.ts");
        assert_eq!(serde_json::to_string(&p).unwrap(), "\"src/a.ts\"");
        assert!(serde_json::from_str::<RepoPath>("\"../etc/passwd\"").is_err());
        assert!(serde_json::from_str::<RepoPath>("\"/etc/passwd\"").is_err());
        assert!(serde_json::from_str::<RepoPath>("\"\"").is_err());
        // Serialised paths must already be canonical.
        assert!(serde_json::from_str::<RepoPath>("\"./a//b\"").is_err());
        assert!(serde_json::from_str::<RepoPath>("\"a/\"").is_err());
        let p: RepoPath = serde_json::from_str("\".\"").unwrap();
        assert!(p.is_root());
    }
}
