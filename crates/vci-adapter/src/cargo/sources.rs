//! Checks that the sources of external crates a unit built are what
//! `Cargo.lock` pins.
//!
//! An external crate is recorded as `version source checksum`, but cargo
//! compiles whatever is in `$CARGO_HOME`: an extracted registry crate or a
//! git checkout edited in place is built as if it were the pinned version
//! (cargo never re-checks them). So when a unit is attested:
//!
//! * a registry crate's extracted directory must equal its downloaded
//!   `.crate` archive (`$CARGO_HOME/registry/cache/<index>/<name>-<version>.crate`),
//!   whose SHA-256 must be the `Cargo.lock` checksum;
//! * a git dependency's checkout must be clean (`git status`, ignored and
//!   untracked files included) at the locked commit;
//! * any other location (a directory or local-registry source replacement
//!   outside the repository) cannot be verified and refuses the unit.
//!
//! Crates vendored inside the repository are hashed file by file instead.

use std::process::Command;

use camino::{Utf8Path, Utf8PathBuf};
use sha2::{Digest, Sha256};

/// Files cargo itself writes into an extracted crate or a checkout.
const CARGO_MARKERS: &[&str] = &[".cargo-ok"];

/// Verify an extracted registry crate at `src_dir` against its archive.
pub(crate) fn verify_registry(
    src_dir: &Utf8Path,
    name: &str,
    version: &str,
    checksum: &str,
) -> Result<(), String> {
    let dir_name = format!("{name}-{version}");
    let not_extracted = || {
        format!(
            "{name} {version} is built from {src_dir}, which is not an extracted registry crate ($CARGO_HOME/registry/src/<index>/{dir_name}); a source replacement outside the repository cannot be verified against Cargo.lock (vendor it inside the repository, where it is hashed)"
        )
    };
    if src_dir.file_name() != Some(dir_name.as_str()) {
        return Err(not_extracted());
    }
    let index = src_dir.parent().ok_or_else(not_extracted)?;
    let src_root = index.parent().ok_or_else(not_extracted)?;
    if src_root.file_name() != Some("src") {
        return Err(not_extracted());
    }
    let registry = src_root.parent().ok_or_else(not_extracted)?;
    let crate_file = registry
        .join("cache")
        .join(index.file_name().ok_or_else(not_extracted)?)
        .join(format!("{dir_name}.crate"));
    if checksum.is_empty() {
        return Err(format!(
            "{name} {version}: Cargo.lock has no checksum to verify {src_dir} against"
        ));
    }
    let bytes = std::fs::read(&crate_file).map_err(|e| {
        format!("{name} {version}: cannot read {crate_file} to verify {src_dir}: {e}")
    })?;
    let got = hex::encode(Sha256::digest(&bytes));
    if got != checksum {
        return Err(format!(
            "{name} {version}: {crate_file} has SHA-256 {got}, Cargo.lock pins {checksum}"
        ));
    }
    let tmp = tempfile::Builder::new()
        .prefix("vci-crate-")
        .tempdir()
        .map_err(|e| format!("{name} {version}: temp dir: {e}"))?;
    let tmp_p = Utf8Path::from_path(tmp.path()).ok_or("non-UTF-8 temp dir")?;
    let out = Command::new("tar")
        .arg("-xzf")
        .arg(crate_file.as_str())
        .arg("-C")
        .arg(tmp_p.as_str())
        .output()
        .map_err(|e| format!("{name} {version}: running tar to verify {src_dir}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{name} {version}: tar -xzf {crate_file} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    compare_trees(&tmp_p.join(&dir_name), src_dir)
        .map_err(|e| format!("{name} {version}: {src_dir} differs from {crate_file}: {e}"))
}

/// `actual` has exactly the entries of `expected` (same types, file bytes
/// and link targets), apart from cargo's own marker files at the top.
fn compare_trees(expected: &Utf8Path, actual: &Utf8Path) -> Result<(), String> {
    let mut stack: Vec<Utf8PathBuf> = vec![Utf8PathBuf::new()];
    while let Some(rel) = stack.pop() {
        let e_dir = expected.join(&rel);
        let a_dir = actual.join(&rel);
        let names = |d: &Utf8Path| -> Result<std::collections::BTreeSet<String>, String> {
            d.read_dir_utf8()
                .map_err(|e| format!("listing {d}: {e}"))?
                .map(|x| x.map(|x| x.file_name().to_owned()))
                .collect::<Result<_, _>>()
                .map_err(|e| format!("listing {d}: {e}"))
        };
        let want = names(&e_dir)?;
        let mut have = names(&a_dir)?;
        if rel.as_str().is_empty() {
            have.retain(|n| !CARGO_MARKERS.contains(&n.as_str()) || want.contains(n));
        }
        if let Some(extra) = have.difference(&want).next() {
            return Err(format!("{} is not in the archive", rel.join(extra)));
        }
        if let Some(missing) = want.difference(&have).next() {
            return Err(format!("{} is missing", rel.join(missing)));
        }
        for n in want {
            let r = rel.join(&n);
            let (e, a) = (expected.join(&r), actual.join(&r));
            let em = std::fs::symlink_metadata(&e).map_err(|x| format!("{e}: {x}"))?;
            let am = std::fs::symlink_metadata(&a).map_err(|x| format!("{a}: {x}"))?;
            let (et, at) = (em.file_type(), am.file_type());
            if et.is_dir() && at.is_dir() {
                stack.push(r);
            } else if et.is_symlink() && at.is_symlink() {
                if std::fs::read_link(&e).ok() != std::fs::read_link(&a).ok() {
                    return Err(format!("{r}: another symlink target"));
                }
            } else if et.is_file() && at.is_file() {
                let same = em.len() == am.len()
                    && std::fs::read(&e).map_err(|x| format!("{e}: {x}"))?
                        == std::fs::read(&a).map_err(|x| format!("{a}: {x}"))?;
                if !same {
                    return Err(format!("{r} was modified"));
                }
            } else {
                return Err(format!("{r} has another file type"));
            }
        }
    }
    Ok(())
}

fn git(dir: &Utf8Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir.as_str())
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .output()
        .map_err(|e| format!("running git in {dir}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {} in {dir} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Verify the git checkout holding `pkg_dir` against the locked source
/// (`git+<url>?<ref>#<commit>`).
pub(crate) fn verify_git(
    pkg_dir: &Utf8Path,
    name: &str,
    locked_source: &str,
) -> Result<(), String> {
    let Some((_, rev)) = locked_source.rsplit_once('#') else {
        return Err(format!("{name}: no locked commit in {locked_source}"));
    };
    let top = git(pkg_dir, &["rev-parse", "--show-toplevel"])
        .map_err(|e| format!("{name}: {pkg_dir} is not a git checkout: {e}"))?;
    let top = Utf8PathBuf::from(top.trim());
    let head = git(&top, &["rev-parse", "HEAD"])?;
    if head.trim() != rev {
        return Err(format!(
            "{name}: the checkout {top} is at {}, Cargo.lock pins {rev}",
            head.trim()
        ));
    }
    let status = git(
        &top,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        ],
    )?;
    let dirty: Vec<&str> = status
        .lines()
        .filter(|l| {
            let path = l.get(3..).unwrap_or("");
            !CARGO_MARKERS.contains(&path)
        })
        .collect();
    if !dirty.is_empty() {
        return Err(format!(
            "{name}: the checkout {top} differs from commit {rev} ({})",
            dirty.iter().take(5).copied().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_available() -> bool {
        Command::new("tar").arg("--version").output().is_ok()
    }

    /// Regression: an extracted registry crate edited in `$CARGO_HOME` was
    /// attested as the version Cargo.lock pins.
    #[test]
    fn registry_crates_must_match_their_archive_and_checksum() {
        if !tar_available() {
            eprintln!("SKIPPED: tar is not installed");
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let home = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        let pkg = home.join("pkg/foo-1.0.0");
        std::fs::create_dir_all(pkg.join("src")).unwrap();
        std::fs::write(pkg.join("Cargo.toml"), "[package]\nname = \"foo\"\n").unwrap();
        std::fs::write(pkg.join("src/lib.rs"), "pub fn f() -> u8 { 1 }\n").unwrap();
        let cache = home.join("registry/cache/index.example-1");
        std::fs::create_dir_all(&cache).unwrap();
        let crate_file = cache.join("foo-1.0.0.crate");
        let st = Command::new("tar")
            .arg("-czf")
            .arg(crate_file.as_str())
            .arg("-C")
            .arg(home.join("pkg").as_str())
            .arg("foo-1.0.0")
            .status()
            .unwrap();
        assert!(st.success());
        let sum = hex::encode(Sha256::digest(std::fs::read(&crate_file).unwrap()));
        let src = home.join("registry/src/index.example-1/foo-1.0.0");
        std::fs::create_dir_all(src.parent().unwrap()).unwrap();
        let st = Command::new("cp")
            .arg("-R")
            .arg(pkg.as_str())
            .arg(src.as_str())
            .status()
            .unwrap();
        assert!(st.success());
        std::fs::write(src.join(".cargo-ok"), "{\"v\":1}").unwrap();
        assert_eq!(verify_registry(&src, "foo", "1.0.0", &sum), Ok(()));
        let wrong = "0".repeat(64);
        assert!(
            verify_registry(&src, "foo", "1.0.0", &wrong)
                .unwrap_err()
                .contains("SHA-256")
        );
        std::fs::write(src.join("src/lib.rs"), "pub fn f() -> u8 { 2 }\n").unwrap();
        let e = verify_registry(&src, "foo", "1.0.0", &sum).unwrap_err();
        assert!(e.contains("src/lib.rs was modified"), "{e}");
        std::fs::write(src.join("src/lib.rs"), "pub fn f() -> u8 { 1 }\n").unwrap();
        std::fs::write(src.join("src/extra.rs"), "").unwrap();
        let e = verify_registry(&src, "foo", "1.0.0", &sum).unwrap_err();
        assert!(e.contains("src/extra.rs is not in the archive"), "{e}");
        std::fs::remove_file(src.join("src/extra.rs")).unwrap();
        assert_eq!(verify_registry(&src, "foo", "1.0.0", &sum), Ok(()));
        // A directory that is not an extracted registry crate (a source
        // replacement) cannot be verified.
        let e = verify_registry(&pkg, "foo", "1.0.0", &sum).unwrap_err();
        assert!(e.contains("source replacement"), "{e}");
    }

    #[test]
    fn git_checkouts_must_be_clean_at_the_locked_commit() {
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("SKIPPED: git is not installed");
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap()).unwrap();
        let g = |args: &[&str]| {
            let st = Command::new("git")
                .arg("-C")
                .arg(d.as_str())
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(
                st.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&st.stderr)
            );
            String::from_utf8_lossy(&st.stdout).trim().to_owned()
        };
        g(&["init", "-q"]);
        std::fs::create_dir_all(d.join("gd/src")).unwrap();
        std::fs::write(d.join("gd/src/lib.rs"), "pub fn f() {}\n").unwrap();
        g(&["add", "-A"]);
        g(&[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@e",
            "commit",
            "-q",
            "-m",
            "x",
        ]);
        let rev = g(&["rev-parse", "HEAD"]);
        std::fs::write(d.join(".cargo-ok"), "").unwrap();
        let src = format!("git+file:///x?branch=main#{rev}");
        let pkg = d.join("gd");
        assert_eq!(verify_git(&pkg, "gd", &src), Ok(()));
        assert!(
            verify_git(
                &pkg,
                "gd",
                "git+file:///x#0000000000000000000000000000000000000000"
            )
            .unwrap_err()
            .contains("pins")
        );
        std::fs::write(d.join("gd/src/lib.rs"), "pub fn f() { panic!() }\n").unwrap();
        assert!(
            verify_git(&pkg, "gd", &src)
                .unwrap_err()
                .contains("differs")
        );
        g(&["checkout", "-q", "--", "gd/src/lib.rs"]);
        std::fs::write(d.join("gd/src/new.rs"), "").unwrap();
        assert!(
            verify_git(&pkg, "gd", &src)
                .unwrap_err()
                .contains("gd/src/new.rs")
        );
    }
}
