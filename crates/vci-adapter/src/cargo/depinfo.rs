//! rustc dep-info (`.d`) files and build script output.
//!
//! rustc writes one makefile-style `.d` file per compiled crate next to its
//! artifact (`deps/foo-<hash>.d`, `build/foo-<hash>/build_script_build-<hash>.d`):
//! every source file (modules, `include_str!`/`include_bytes!` targets,
//! `#[path]` files) as a phony rule `path:`, and every environment variable
//! read by `env!`/`option_env!` as `# env-dep:NAME=value`. Relative paths are
//! relative to rustc's working directory, which cargo sets to the workspace
//! root.

use camino::{Utf8Path, Utf8PathBuf};

/// Contents of one dep-info file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DepInfo {
    /// Source files, absolute (relative ones joined to the workspace root).
    pub files: Vec<Utf8PathBuf>,
    /// Environment variables read at compile time.
    pub env: Vec<String>,
}

/// Undo makefile escaping (`\ ` for a space, `\#`, `$$`).
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' if matches!(it.peek(), Some(' ' | '#' | '\\')) => {
                out.push(it.next().expect("peeked"));
            }
            '$' if it.peek() == Some(&'$') => {
                it.next();
                out.push('$');
            }
            other => out.push(other),
        }
    }
    out
}

/// Parse a dep-info file's text.
pub fn parse(text: &str, workspace_root: &Utf8Path) -> DepInfo {
    let mut d = DepInfo::default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# env-dep:") {
            let name = rest.split_once('=').map_or(rest, |(k, _)| k);
            if !name.is_empty() {
                d.env.push(name.to_owned());
            }
            continue;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        // Phony rules: exactly `path:` (every dependency gets one). Target
        // lines (`artifact: dep dep`) name the build outputs.
        let Some(p) = line.strip_suffix(':') else {
            continue;
        };
        if p.ends_with('\\') || p.contains(": ") {
            continue;
        }
        let p = unescape(p);
        let path = Utf8PathBuf::from(&p);
        d.files.push(if path.is_absolute() {
            path
        } else {
            workspace_root.join(path)
        });
    }
    d.files.sort();
    d.files.dedup();
    d.env.sort();
    d.env.dedup();
    d
}

/// The dep-info file of a compiled artifact: `<dir>/<stem>.d` for
/// `<dir>/<stem>` or `<dir>/lib<stem>.<ext>`, else the only `.d` file in a
/// build script's directory.
pub fn dep_info_for(filenames: &[Utf8PathBuf]) -> Option<Utf8PathBuf> {
    for f in filenames {
        let dir = f.parent()?;
        let name = f.file_name()?;
        let stem = match f.extension() {
            Some("rlib" | "rmeta" | "dylib" | "so" | "a" | "dll" | "lib" | "exe" | "wasm") => {
                f.file_stem()?
            }
            _ => name,
        };
        let mut cands = vec![dir.join(format!("{stem}.d"))];
        if let Some(s) = stem.strip_prefix("lib") {
            cands.push(dir.join(format!("{s}.d")));
        }
        if let Some(c) = cands.into_iter().find(|c| c.is_file()) {
            return Some(c);
        }
    }
    // Build scripts: `build/<pkg>-<hash>/build-script-build` next to
    // `build_script_build-<hash>.d`.
    for f in filenames {
        let name = f.file_name()?;
        if !(name.starts_with("build-script-") || name.starts_with("build_script_")) {
            continue;
        }
        let dir = f.parent()?;
        let ds: Vec<Utf8PathBuf> = dir
            .read_dir_utf8()
            .ok()?
            .flatten()
            .map(|e| e.path().to_owned())
            .filter(|p| p.extension() == Some("d"))
            .collect();
        if ds.len() == 1 {
            return ds.into_iter().next();
        }
    }
    None
}

/// What a build script declared in its output (`<out_dir>/../output`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BuildOutput {
    /// `rerun-if-changed` paths as written (relative to the package dir).
    pub rerun_if_changed: Vec<String>,
    /// `rerun-if-env-changed` variable names.
    pub rerun_if_env_changed: Vec<String>,
}

/// Parse a build script's stdout (`cargo:` and `cargo::` directives).
pub fn parse_build_output(text: &str) -> BuildOutput {
    let mut o = BuildOutput::default();
    for line in text.lines() {
        let Some(rest) = line
            .strip_prefix("cargo::")
            .or_else(|| line.strip_prefix("cargo:"))
        else {
            continue;
        };
        if let Some(p) = rest.strip_prefix("rerun-if-changed=") {
            o.rerun_if_changed.push(p.to_owned());
        } else if let Some(k) = rest.strip_prefix("rerun-if-env-changed=") {
            o.rerun_if_env_changed.push(k.trim().to_owned());
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rustc_dep_info() {
        let text = "/t/debug/deps/c-09ad.d: c/src/lib.rs /t/debug/build/c-cc76/out/gen.rs c/src/../../shared/c.txt my\\ dir/x.rs\n\n/t/debug/deps/c-09ad: c/src/lib.rs\n\nc/src/lib.rs:\n/t/debug/build/c-cc76/out/gen.rs:\nc/src/../../shared/c.txt:\nmy\\ dir/x.rs:\n\n# env-dep:OUT_DIR=/t/debug/build/c-cc76/out\n# env-dep:B_FLAG\n";
        let d = parse(text, Utf8Path::new("/ws"));
        assert_eq!(
            d.files,
            [
                Utf8PathBuf::from("/t/debug/build/c-cc76/out/gen.rs"),
                Utf8PathBuf::from("/ws/c/src/../../shared/c.txt"),
                Utf8PathBuf::from("/ws/c/src/lib.rs"),
                Utf8PathBuf::from("/ws/my dir/x.rs"),
            ]
        );
        assert_eq!(d.env, ["B_FLAG", "OUT_DIR"]);
    }

    #[test]
    fn parses_build_script_output() {
        let o = parse_build_output(
            "cargo:rerun-if-changed=../shared/c-build.txt\ncargo::rerun-if-env-changed=C_MODE\ncargo:rustc-cfg=has_x\nnoise\n",
        );
        assert_eq!(o.rerun_if_changed, ["../shared/c-build.txt"]);
        assert_eq!(o.rerun_if_env_changed, ["C_MODE"]);
    }

    #[test]
    fn finds_the_dep_info_of_an_artifact() {
        let t = tempfile::tempdir().unwrap();
        let d = Utf8PathBuf::from_path_buf(t.path().to_path_buf()).unwrap();
        std::fs::write(d.join("a-1234.d"), "").unwrap();
        assert_eq!(
            dep_info_for(&[d.join("liba-1234.rlib"), d.join("liba-1234.rmeta")]),
            Some(d.join("a-1234.d"))
        );
        assert_eq!(dep_info_for(&[d.join("a-1234")]), Some(d.join("a-1234.d")));
        let b = d.join("build/c-99");
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(b.join("build_script_build-99.d"), "").unwrap();
        assert_eq!(
            dep_info_for(&[b.join("build-script-build")]),
            Some(b.join("build_script_build-99.d"))
        );
        assert_eq!(dep_info_for(&[d.join("nothing-1")]), None);
    }
}
