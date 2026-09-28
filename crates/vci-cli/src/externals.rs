//! Check that an attested external package version is what is installed now.

use camino::Utf8Path;
use serde_json::Value;

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
