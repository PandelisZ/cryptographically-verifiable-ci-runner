//! Standard library hooks installed with the test log overlay.
//!
//! Package os does not report everything a test can use to reach an input to
//! internal/testlog: `os.Readlink` (and `io/fs.ReadLink`, `os.DirFS`,
//! `os.CopyFS`, `filepath.EvalSymlinks` built on it), `os.Root.Readlink`,
//! `os.Symlink`/`os.Link` and their `os.Root` forms, `os.Environ`,
//! `File.Chdir`, and package time's use of the local time zone are not
//! logged. A source scan for their names misses function values
//! (`var readlink = os.Readlink`) and every use inside the standard library.
//!
//! The overlay therefore also replaces a few files of packages os and time
//! with copies taken from the GOROOT in use, each with one call inserted at
//! the top of the function (and adds one file per package with the helpers
//! those calls use). Every insertion point must be found exactly once in the
//! file, or the hooks are not installed and every package is refused (a new
//! Go version whose sources moved fails open).

use camino::Utf8Path;

/// One insertion: in `file` (relative to `$GOROOT/src`), after `anchor`
/// (the first line of a function), insert `insert`.
struct Patch {
    file: &'static str,
    anchor: &'static str,
    insert: &'static str,
}

const PATCHES: &[Patch] = &[
    Patch {
        file: "os/file.go",
        anchor: "func Readlink(name string) (string, error) {\n",
        insert: "\tvciStat(name)\n",
    },
    Patch {
        file: "os/root.go",
        anchor: "func (r *Root) Readlink(name string) (string, error) {\n",
        insert: "\tr.logStat(name)\n",
    },
    Patch {
        file: "os/root.go",
        anchor: "func (r *Root) Link(oldname, newname string) error {\n",
        insert: "\tvciLink(\"link\", joinPath(r.Name(), oldname), joinPath(r.Name(), newname), true)\n",
    },
    Patch {
        file: "os/root.go",
        anchor: "func (r *Root) Symlink(oldname, newname string) error {\n",
        insert: "\tvciLink(\"symlink\", oldname, joinPath(r.Name(), newname), true)\n",
    },
    Patch {
        file: "os/file_unix.go",
        anchor: "func Link(oldname, newname string) error {\n",
        insert: "\tvciLink(\"link\", oldname, newname, false)\n",
    },
    Patch {
        file: "os/file_unix.go",
        anchor: "func Symlink(oldname, newname string) error {\n",
        insert: "\tvciLink(\"symlink\", oldname, newname, false)\n",
    },
    Patch {
        file: "os/env.go",
        anchor: "func Environ() []string {\n",
        insert: "\tvciEvent(\"taint\", \"os.Environ enumerates the environment (every variable would be an input)\")\n",
    },
    Patch {
        file: "os/file_posix.go",
        anchor: "func (f *File) Chdir() error {\n",
        insert: "\tvciEvent(\"wdchanged\", \"\")\n",
    },
    Patch {
        file: "time/zoneinfo_unix.go",
        anchor: "func initLocal() {\n",
        insert: "\tvciLocalZone()\n",
    },
];

/// Files added to the patched packages: the helpers the insertions call.
const ADDED: &[(&str, &str)] = &[
    (
        "os/vci_hooks.go",
        "// vci: helpers for the calls vci inserts into package os (test builds of\n\
         // `vci run` only).\n\n\
         package os\n\n\
         import \"internal/testlog\"\n\n\
         func vciStat(name string) { testlog.Stat(name) }\n\n\
         func vciEvent(op, arg string) { testlog.VCIEvent(op, arg) }\n\n\
         func vciLink(kind, oldname, newname string, inRoot bool) {\n\
         \ttestlog.VCILink(kind, oldname, newname, inRoot)\n\
         }\n",
    ),
    (
        "time/vci_hooks.go",
        "// vci: helper for the call vci inserts into package time (test builds of\n\
         // `vci run` only).\n\n\
         package time\n\n\
         import \"internal/testlog\"\n\n\
         func vciLocalZone() { testlog.VCILocalZone() }\n",
    ),
];

/// Insert every patch into `text` (the content of `file`). Errors name the
/// anchor that is missing or not unique.
fn apply(file: &str, mut text: String) -> Result<String, String> {
    for p in PATCHES.iter().filter(|p| p.file == file) {
        let n = text.matches(p.anchor).count();
        if n != 1 {
            return Err(format!(
                "{file}: `{}` found {n} times (expected once)",
                p.anchor.trim_end()
            ));
        }
        let at = text.find(p.anchor).unwrap_or_default() + p.anchor.len();
        text.insert_str(at, p.insert);
    }
    Ok(text)
}

/// Write the patched and added files into `out_dir` and return the overlay
/// `Replace` entries (`$GOROOT/src/<file>` -> written copy).
pub(crate) fn write_overlay(
    goroot: &Utf8Path,
    out_dir: &Utf8Path,
) -> Result<Vec<(String, String)>, String> {
    let mut files: Vec<&str> = PATCHES.iter().map(|p| p.file).collect();
    files.sort_unstable();
    files.dedup();
    let mut out = Vec::new();
    let write = |rel: &str, text: &str| -> Result<(String, String), String> {
        let dst = out_dir.join(rel.replace('/', "__"));
        std::fs::write(&dst, text).map_err(|e| format!("writing {dst}: {e}"))?;
        Ok((goroot.join("src").join(rel).to_string(), dst.to_string()))
    };
    for f in files {
        let src = goroot.join("src").join(f);
        let text = std::fs::read_to_string(&src).map_err(|e| format!("reading {src}: {e}"))?;
        out.push(write(f, &apply(f, text)?)?);
    }
    for (rel, text) in ADDED {
        let target = goroot.join("src").join(rel);
        if target.exists() {
            return Err(format!("{target} already exists"));
        }
        out.push(write(rel, text)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_must_be_unique() {
        let ok = apply(
            "os/env.go",
            "package os\n\nfunc Environ() []string {\n\treturn nil\n}\n".into(),
        )
        .unwrap();
        assert!(
            ok.contains("func Environ() []string {\n\tvciEvent(\"taint\""),
            "{ok}"
        );
        assert!(apply("os/env.go", "package os\n".into()).is_err());
        let twice = "func Environ() []string {\n}\nfunc Environ() []string {\n}\n";
        assert!(apply("os/env.go", twice.into()).is_err());
        // Files without patches are unchanged.
        assert_eq!(apply("os/other.go", "x".into()).unwrap(), "x");
    }

    /// The installed toolchain's sources have every anchor (checked for
    /// real, with a build, by the Go end-to-end tests).
    #[test]
    fn goroot_sources_have_every_anchor() {
        let Ok(out) = std::process::Command::new("go")
            .args(["env", "GOROOT"])
            .output()
        else {
            eprintln!("SKIPPED: go is not installed");
            return;
        };
        let goroot = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !out.status.success() || goroot.is_empty() {
            eprintln!("SKIPPED: go env GOROOT failed");
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = Utf8Path::from_path(t.path()).unwrap();
        let entries = write_overlay(Utf8Path::new(&goroot), d).unwrap();
        assert_eq!(entries.len(), 8, "{entries:?}");
        assert!(
            entries
                .iter()
                .any(|(k, _)| k.ends_with("src/os/vci_hooks.go"))
        );
    }
}
