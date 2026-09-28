#![allow(dead_code)]

use std::process::Command;

use camino::{Utf8Path, Utf8PathBuf};
use tempfile::TempDir;

/// Run git in `dir` for test setup, with a fixed identity and none of the
/// caller's GIT_DIR-style overrides. Panics on failure.
pub fn git(dir: &Utf8Path, args: &[&str]) -> String {
    let out = git_raw(dir, args);
    assert!(
        out.status.success(),
        "git {args:?} in {dir} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim_end().to_owned()
}

pub fn git_raw(dir: &Utf8Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir.as_std_path());
    cmd.args([
        "-c",
        "init.defaultBranch=main",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "tag.gpgsign=false",
    ]);
    cmd.args(args);
    for v in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_COMMON_DIR",
    ] {
        cmd.env_remove(v);
    }
    cmd.env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com");
    cmd.output().unwrap()
}

pub fn utf8(dir: &TempDir) -> Utf8PathBuf {
    // Canonicalize so paths compare equal to what git reports (/var -> /private/var on macOS).
    let p = dir.path().canonicalize().unwrap();
    Utf8PathBuf::from_path_buf(p).unwrap()
}

pub fn write(root: &Utf8Path, rel: &str, contents: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, contents).unwrap();
}

/// A fresh repo with one commit containing `a.txt` and `dir/b.txt`.
pub fn init_repo() -> (TempDir, Utf8PathBuf) {
    let tmp = TempDir::new().unwrap();
    let root = utf8(&tmp);
    git(&root, &["init", "-q"]);
    write(&root, "a.txt", "alpha\n");
    write(&root, "dir/b.txt", "beta\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "initial"]);
    (tmp, root)
}

/// A bare remote seeded with a commit on main, plus `n` clones of it.
pub struct World {
    _tmp: TempDir,
    pub remote: Utf8PathBuf,
    pub clones: Vec<Utf8PathBuf>,
}

pub fn world(n: usize) -> World {
    let tmp = TempDir::new().unwrap();
    let base = utf8(&tmp);
    let remote = base.join("remote.git");
    let seed = base.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    git(&base, &["init", "-q", "--bare", remote.as_str()]);
    git(&seed, &["init", "-q"]);
    write(&seed, "a.txt", "alpha\n");
    git(&seed, &["add", "-A"]);
    git(&seed, &["commit", "-q", "-m", "root"]);
    write(&seed, "a.txt", "alpha 2\n");
    git(&seed, &["commit", "-q", "-am", "second"]);
    git(&seed, &["push", "-q", remote.as_str(), "main"]);
    let clones = (0..n)
        .map(|i| {
            let c = base.join(format!("clone{i}"));
            git(&base, &["clone", "-q", remote.as_str(), c.as_str()]);
            c
        })
        .collect();
    World {
        _tmp: tmp,
        remote,
        clones,
    }
}

pub fn hex64(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}
