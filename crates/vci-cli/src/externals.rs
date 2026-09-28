//! Check that an attested external package version is what is installed now.
//!
//! npm (Vitest): looked up in `node_modules` from the project dir.
//! Python (pytest): the adapter enumerates the distributions installed in the
//! environment `uv run --locked` uses, and the version must also be the one
//! `uv.lock` pins. A package that is not installed, installed in more than
//! one version, or not pinned to that version is a mismatch. So is a package
//! built from a local directory or file (`source = { directory = ... }` or
//! `{ path = ... }`, e.g. `editable = false` path dependencies): its code
//! lives in the repository but is identified by a version that editing it
//! does not change.

use std::collections::{BTreeMap, BTreeSet};

use camino::Utf8Path;
use serde_json::Value;
use vci_adapter::InstalledExternals;

/// Packages pinned by a `uv.lock`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockedPackages {
    /// name -> versions.
    pub versions: BTreeMap<String, BTreeSet<String>>,
    /// Names built from a local directory or file (`source.directory` /
    /// `source.path`): not identified by their version.
    pub local: BTreeSet<String>,
}

impl LockedPackages {
    pub fn get(&self, name: &str) -> Option<&BTreeSet<String>> {
        self.versions.get(name)
    }
}

/// Why an external cannot be identified by `name@version`, if it cannot.
pub fn local_source_reason(lock: &LockedPackages, name: &str) -> Option<String> {
    let name = normalise_dist(name);
    lock.local.contains(&name).then(|| {
        format!(
            "{name} is built from a local directory or file (uv.lock source directory/path): its code is in the repository but only its version would be recorded"
        )
    })
}

/// The nearest `uv.lock` from `project_dir` up to `repo_root`, parsed.
/// `Ok(None)` when there is none.
pub fn uv_lock_packages(
    project_dir: &Utf8Path,
    repo_root: &Utf8Path,
) -> Result<Option<LockedPackages>, String> {
    let mut dir = Some(project_dir);
    while let Some(d) = dir {
        let p = d.join("uv.lock");
        if p.is_file() {
            let text = std::fs::read_to_string(&p).map_err(|e| format!("reading {p}: {e}"))?;
            return parse_uv_lock(&text)
                .map(Some)
                .map_err(|e| format!("parsing {p}: {e}"));
        }
        if d == repo_root || !d.starts_with(repo_root) {
            break;
        }
        dir = d.parent();
    }
    Ok(None)
}

pub fn parse_uv_lock(text: &str) -> Result<LockedPackages, String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut out = LockedPackages::default();
    let pkgs = match v.get("package") {
        None => return Ok(out),
        Some(p) => p.as_array().ok_or("`package` is not an array")?,
    };
    for p in pkgs {
        let name = p
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or("package without name")?;
        // Workspace members and virtual projects have no version: they are
        // repository content, never an `external`.
        if let Some(ver) = p.get("version").and_then(toml::Value::as_str) {
            out.versions
                .entry(normalise_dist(name))
                .or_default()
                .insert(ver.to_owned());
        }
        // Built from a local directory or archive: installed as a copy in
        // site-packages whose content the version does not identify.
        // (`editable` sources are imported from the repository itself and
        // recorded as modules; `virtual` ones are not installed.)
        if let Some(src) = p.get("source").and_then(toml::Value::as_table)
            && (src.contains_key("directory") || src.contains_key("path"))
        {
            out.local.insert(normalise_dist(name));
        }
    }
    Ok(out)
}

/// PEP 503 name normalisation (as the collector and uv.lock use).
pub fn normalise_dist(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut sep = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// `Ok(())` if the Python distribution `name` is installed in exactly
/// `version` and (when a lockfile exists) `uv.lock` pins that version.
pub fn python_installed(
    installed: &Result<InstalledExternals, String>,
    locked: &Result<Option<LockedPackages>, String>,
    name: &str,
    version: &str,
) -> Result<(), String> {
    let installed = installed
        .as_ref()
        .map_err(|e| format!("cannot enumerate installed packages: {e}"))?;
    let name = normalise_dist(name);
    match installed.get(&name).map(Vec::as_slice) {
        None | Some([]) => return Err("not installed".into()),
        Some([v]) if v == version => {}
        Some([v]) => return Err(v.clone()),
        Some(vs) => return Err(format!("installed in several versions: {}", vs.join(", "))),
    }
    match locked {
        Err(e) => Err(format!("uv.lock unusable: {e}")),
        Ok(None) => Ok(()),
        Ok(Some(lock)) if lock.local.contains(&name) => Err(format!(
            "{version} built from a local directory or file (uv.lock source directory/path): not identified by its version"
        )),
        Ok(Some(lock)) => match lock.get(&name) {
            Some(vs) if vs.contains(version) => Ok(()),
            Some(vs) => Err(format!(
                "{version} installed, but uv.lock pins {}",
                vs.iter().cloned().collect::<Vec<_>>().join(", ")
            )),
            None => Err(format!("{version} installed, but not in uv.lock")),
        },
    }
}

/// `Ok(())` if the Go module `path` is in the current build list
/// (`go list -m all`) at exactly `version` (the same replacement included).
/// Module paths are compared exactly (they are case-sensitive).
pub fn go_installed(
    build_list: &Result<InstalledExternals, String>,
    path: &str,
    version: &str,
) -> Result<(), String> {
    let list = build_list
        .as_ref()
        .map_err(|e| format!("cannot load the build list: {e}"))?;
    match list.get(path).map(Vec::as_slice) {
        None | Some([]) => Err("not in the build list".into()),
        Some([v]) if v == version => Ok(()),
        Some([v]) => Err(v.clone()),
        Some(vs) => Err(format!("several versions: {}", vs.join(", "))),
    }
}

/// `Ok(())` if Cargo.lock pins crate `name` as `version` (the recorded
/// `version source checksum`). A crate can be locked in several versions.
pub fn cargo_locked(
    lock: &Result<InstalledExternals, String>,
    name: &str,
    version: &str,
) -> Result<(), String> {
    let lock = lock
        .as_ref()
        .map_err(|e| format!("cannot read Cargo.lock: {e}"))?;
    match lock.get(name) {
        None => Err("not in Cargo.lock".into()),
        Some(vs) if vs.iter().any(|v| v == version) => Ok(()),
        Some(vs) => Err(vs.join(", ")),
    }
}

fn version_of(pkg_json: &Utf8Path) -> Option<String> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(pkg_json).ok()?).ok()?;
    v.get("version")?.as_str().map(str::to_owned)
}

/// `Ok(())` if `name@version` is installed where node would find it from the
/// project dir, or anywhere in npm's hidden lockfile
/// (`node_modules/.package-lock.json`). Otherwise `Err(what was found)`.
pub fn installed(project_dir: &Utf8Path, name: &str, version: &str) -> Result<(), String> {
    if name.is_empty() || name.contains("..") || name.starts_with('/') || name.contains('\\') {
        return Err(format!("invalid package name {name:?}"));
    }
    let mut found = None;
    let mut dir = Some(project_dir);
    while let Some(d) = dir {
        let pj = d.join("node_modules").join(name).join("package.json");
        if pj.is_file() {
            found = version_of(&pj);
            if found.as_deref() == Some(version) {
                return Ok(());
            }
            break;
        }
        dir = d.parent();
    }
    // Nested installs: npm records every installed package in its hidden lockfile.
    let mut dir = Some(project_dir);
    while let Some(d) = dir {
        let hidden = d.join("node_modules/.package-lock.json");
        if let Some(pkgs) = std::fs::read_to_string(&hidden)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| v.get("packages").cloned())
            .and_then(|p| p.as_object().cloned())
        {
            let suffix = format!("node_modules/{name}");
            for (path, meta) in pkgs {
                if (path == suffix || path.ends_with(&format!("/{suffix}")))
                    && meta.get("version").and_then(Value::as_str) == Some(version)
                {
                    // The hidden lockfile can be stale; trust it only if the
                    // package.json on disk agrees.
                    if version_of(&d.join(&path).join("package.json")).as_deref() == Some(version) {
                        return Ok(());
                    }
                }
            }
            break;
        }
        dir = d.parent();
    }
    Err(found.unwrap_or_else(|| "not installed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "idna"
version = "3.20"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "typing-extensions"
version = "4.15.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest-abcd"
source = { virtual = "." }
"#;

    fn installed(pairs: &[(&str, &[&str])]) -> Result<InstalledExternals, String> {
        Ok(pairs
            .iter()
            .map(|(n, vs)| (n.to_string(), vs.iter().map(|v| v.to_string()).collect()))
            .collect())
    }

    #[test]
    fn uv_lock_parses_and_normalises() {
        let l = parse_uv_lock(LOCK).unwrap();
        assert!(l.versions["idna"].contains("3.20"));
        assert!(l.versions.contains_key("typing-extensions"));
        assert!(
            !l.versions.contains_key("pytest-abcd"),
            "virtual projects have no version"
        );
        assert!(l.local.is_empty());
        assert_eq!(normalise_dist("Typing_Extensions"), "typing-extensions");
        assert_eq!(normalise_dist("zope.interface"), "zope-interface");
        assert!(parse_uv_lock("[[package]\n").is_err());
    }

    #[test]
    fn python_externals_fail_open() {
        let lock = Ok(Some(parse_uv_lock(LOCK).unwrap()));
        let inst = installed(&[
            ("idna", &["3.20"]),
            ("pytest", &["9.1.1"]),
            ("dup", &["1", "2"]),
        ]);
        assert_eq!(python_installed(&inst, &lock, "idna", "3.20"), Ok(()));
        assert_eq!(python_installed(&inst, &lock, "IDNA", "3.20"), Ok(()));
        // A different version installed.
        assert_eq!(
            python_installed(&inst, &lock, "idna", "3.19"),
            Err("3.20".into())
        );
        // Missing package.
        assert_eq!(
            python_installed(&inst, &lock, "requests", "2.0"),
            Err("not installed".into())
        );
        // Installed but not pinned by uv.lock.
        assert!(
            python_installed(&inst, &lock, "pytest", "9.1.1")
                .unwrap_err()
                .contains("not in uv.lock")
        );
        // Ambiguous installation.
        assert!(
            python_installed(&inst, &lock, "dup", "1")
                .unwrap_err()
                .contains("several versions")
        );
        // Errors enumerating or reading the lock never match.
        assert!(python_installed(&Err("boom".into()), &lock, "idna", "3.20").is_err());
        assert!(python_installed(&inst, &Err("bad".into()), "idna", "3.20").is_err());
        // No lockfile: the installed version decides.
        assert_eq!(
            python_installed(&inst, &Ok(None), "pytest", "9.1.1"),
            Ok(())
        );
    }

    #[test]
    fn go_modules_must_be_in_the_build_list_exactly() {
        let list: Result<InstalledExternals, String> = Ok([
            ("golang.org/x/sync".to_owned(), vec!["v0.20.0".to_owned()]),
            ("example.com/Up".to_owned(), vec!["v1.0.0".to_owned()]),
            (
                "example.com/lib".to_owned(),
                vec!["local:../lib".to_owned()],
            ),
        ]
        .into_iter()
        .collect());
        assert_eq!(go_installed(&list, "golang.org/x/sync", "v0.20.0"), Ok(()));
        assert_eq!(
            go_installed(&list, "golang.org/x/sync", "v0.22.0"),
            Err("v0.20.0".into())
        );
        assert!(
            go_installed(&list, "example.com/up", "v1.0.0").is_err(),
            "case-sensitive"
        );
        assert!(go_installed(&list, "example.com/lib", "v1.0.0").is_err());
        assert!(go_installed(&Err("boom".into()), "golang.org/x/sync", "v0.20.0").is_err());
    }

    #[test]
    fn cargo_crates_must_be_locked_exactly() {
        let lock: Result<InstalledExternals, String> = Ok([(
            "syn".to_owned(),
            vec![
                "1.0.109 registry+x aa".to_owned(),
                "2.0.1 registry+x bb".to_owned(),
            ],
        )]
        .into_iter()
        .collect());
        assert_eq!(cargo_locked(&lock, "syn", "2.0.1 registry+x bb"), Ok(()));
        assert_eq!(cargo_locked(&lock, "syn", "1.0.109 registry+x aa"), Ok(()));
        assert!(
            cargo_locked(&lock, "syn", "2.0.1 registry+x cc").is_err(),
            "checksum"
        );
        assert!(cargo_locked(&lock, "hex", "0.4.3 registry+x dd").is_err());
        assert!(cargo_locked(&Err("gone".into()), "syn", "2.0.1 registry+x bb").is_err());
    }

    /// Regression: a non-editable path dependency (`source = { directory =
    /// "libs/mylib" }`) keeps its version when its code in the repository is
    /// edited; it must never match by version.
    #[test]
    fn local_directory_and_path_sources_never_match() {
        let lock = format!(
            "{LOCK}\n[[package]]\nname = \"MyLib\"\nversion = \"0.1.0\"\nsource = {{ directory = \"libs/mylib\" }}\n\n[[package]]\nname = \"wheel-dep\"\nversion = \"1.0\"\nsource = {{ path = \"vendor/wheel_dep-1.0-py3-none-any.whl\" }}\n\n[[package]]\nname = \"edit\"\nversion = \"0.2.0\"\nsource = {{ editable = \"libs/edit\" }}\n"
        );
        let l = parse_uv_lock(&lock).unwrap();
        assert!(l.local.contains("mylib") && l.local.contains("wheel-dep"));
        assert!(!l.local.contains("edit") && !l.local.contains("idna"));
        let lock = Ok(Some(l.clone()));
        let inst = installed(&[
            ("mylib", &["0.1.0"]),
            ("wheel-dep", &["1.0"]),
            ("idna", &["3.20"]),
        ]);
        let e = python_installed(&inst, &lock, "mylib", "0.1.0").unwrap_err();
        assert!(e.contains("local directory"), "{e}");
        assert!(python_installed(&inst, &lock, "wheel-dep", "1.0").is_err());
        assert_eq!(python_installed(&inst, &lock, "idna", "3.20"), Ok(()));
        assert!(local_source_reason(&l, "MyLib").is_some());
        assert!(local_source_reason(&l, "idna").is_none());
    }
}
