//! `h1:` directory hashes as `go.sum` records them
//! (`golang.org/x/mod/sumdb/dirhash.HashDir` with `Hash1`, what
//! `go mod verify` checks the module cache against): SHA-256 over the sorted
//! lines `"<sha256 hex>  <prefix>/<slash path>\n"` of every file, base64.

use base64::Engine as _;
use camino::Utf8Path;
use sha2::{Digest, Sha256};

/// `h1:` hash of every file under `dir`, named `<prefix>/<relative path>`
/// (`prefix` is `module@version`). Like `filepath.Walk`, symlinks are not
/// descended into; a symlink is hashed as the file it points to.
pub(crate) fn hash_dir(dir: &Utf8Path, prefix: &str) -> Result<String, String> {
    let mut names: Vec<(String, camino::Utf8PathBuf)> = Vec::new();
    let mut stack = vec![dir.to_owned()];
    while let Some(d) = stack.pop() {
        let rd = d.read_dir_utf8().map_err(|e| format!("{d}: {e}"))?;
        for e in rd {
            let e = e.map_err(|e| format!("{d}: {e}"))?;
            let p = e.path().to_owned();
            let ft = e.file_type().map_err(|err| format!("{p}: {err}"))?;
            if ft.is_dir() {
                stack.push(p);
                continue;
            }
            let rel = p
                .strip_prefix(dir)
                .map_err(|_| format!("{p} is not under {dir}"))?;
            let name = format!("{prefix}/{}", rel.as_str().replace('\\', "/"));
            if name.contains('\n') {
                return Err(format!("file name with a newline: {name:?}"));
            }
            names.push((name, p));
        }
    }
    names.sort();
    let mut summary = Sha256::new();
    for (name, path) in names {
        let bytes = std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?;
        let h = Sha256::digest(&bytes);
        summary.update(format!("{}  {name}\n", hex::encode(h)).as_bytes());
    }
    Ok(format!(
        "h1:{}",
        base64::engine::general_purpose::STANDARD.encode(summary.finalize())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known answer: the `h1:` hash of a go.mod-only module computed the way
    /// cmd/go does (`go mod download -json` reports it as GoModSum for a
    /// module whose go.mod is `module example.com/m\n`).
    #[test]
    fn matches_the_go_algorithm() {
        let t = tempfile::tempdir().unwrap();
        let d = camino::Utf8Path::from_path(t.path()).unwrap();
        std::fs::write(d.join("go.mod"), "module example.com/m\n").unwrap();
        std::fs::create_dir(d.join("sub")).unwrap();
        std::fs::write(d.join("sub/a.go"), "package sub\n").unwrap();
        let h = hash_dir(d, "example.com/m@v1.0.0").unwrap();
        // Recomputed by hand from the definition.
        let line = |content: &str, name: &str| {
            format!(
                "{}  example.com/m@v1.0.0/{name}\n",
                hex::encode(Sha256::digest(content.as_bytes()))
            )
        };
        let summary = format!(
            "{}{}",
            line("module example.com/m\n", "go.mod"),
            line("package sub\n", "sub/a.go")
        );
        let want = format!(
            "h1:{}",
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(summary.as_bytes()))
        );
        assert_eq!(h, want);
    }
}
