mod common;

use common::*;
use tempfile::TempDir;
use vci_git::{GitError, Repo};

#[test]
fn discover_from_subdir_and_file() {
    let (_t, root) = init_repo();
    let from_sub = Repo::discover(&root.join("dir")).unwrap();
    assert_eq!(from_sub.root(), root);
    let from_file = Repo::discover(&root.join("dir/b.txt")).unwrap();
    assert_eq!(from_file.root(), root);
}

#[test]
fn discover_outside_repo_fails() {
    let tmp = TempDir::new().unwrap();
    let dir = utf8(&tmp);
    // Only meaningful if the temp dir itself isn't inside some repo.
    if git_raw(&dir, &["rev-parse", "--git-dir"]).status.success() {
        eprintln!("temp dir is inside a git repo; skipping");
        return;
    }
    assert!(matches!(
        Repo::discover(&dir),
        Err(GitError::NotARepo { .. })
    ));
}

#[test]
fn repo_id_is_stable_across_clones() {
    let w = world(2);
    let a = Repo::discover(&w.clones[0]).unwrap();
    let b = Repo::discover(&w.clones[1]).unwrap();
    let id = a.repo_id().unwrap();
    assert_eq!(id, b.repo_id().unwrap());
    let root_commit = git(&w.clones[0], &["rev-list", "--max-parents=0", "HEAD"]);
    assert_eq!(id, root_commit);
    assert_ne!(id, a.head_commit().unwrap(), "root, not head");
    // A new commit doesn't change the identity.
    write(&w.clones[1], "new.txt", "x");
    git(&w.clones[1], &["add", "-A"]);
    git(&w.clones[1], &["commit", "-q", "-m", "more"]);
    assert_eq!(b.repo_id().unwrap(), id);
}

#[test]
fn repo_id_with_multiple_roots_is_smallest() {
    let (_t, root) = init_repo();
    let first_root = git(&root, &["rev-parse", "HEAD"]);
    git(&root, &["checkout", "-q", "--orphan", "other"]);
    write(&root, "c.txt", "gamma\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "other root"]);
    let second_root = git(&root, &["rev-parse", "HEAD"]);
    git(&root, &["checkout", "-q", "main"]);
    git(
        &root,
        &[
            "merge",
            "-q",
            "--allow-unrelated-histories",
            "-m",
            "join",
            "other",
        ],
    );
    let repo = Repo::discover(&root).unwrap();
    let expected = std::cmp::min(first_root, second_root);
    assert_eq!(repo.repo_id().unwrap(), expected);
}

#[test]
fn empty_repo_has_no_commits() {
    let tmp = TempDir::new().unwrap();
    let root = utf8(&tmp);
    git(&root, &["init", "-q"]);
    let repo = Repo::discover(&root).unwrap();
    assert!(matches!(repo.head_commit(), Err(GitError::NoCommits)));
    assert!(matches!(repo.repo_id(), Err(GitError::NoCommits)));
}

#[test]
fn head_resolve_merge_base_and_dirty() {
    let (_t, root) = init_repo();
    let repo = Repo::discover(&root).unwrap();
    let c1 = git(&root, &["rev-parse", "HEAD"]);
    assert_eq!(repo.head_commit().unwrap(), c1);
    assert!(!repo.is_dirty().unwrap());

    git(&root, &["tag", "-a", "-m", "annotated", "v1"]);
    assert_eq!(
        repo.resolve("v1").unwrap(),
        c1,
        "annotated tag peels to commit"
    );

    git(&root, &["checkout", "-q", "-b", "feature"]);
    write(&root, "a.txt", "feature\n");
    git(&root, &["commit", "-q", "-am", "feature"]);
    let c2 = git(&root, &["rev-parse", "HEAD"]);
    git(&root, &["checkout", "-q", "main"]);
    write(&root, "dir/b.txt", "main\n");
    git(&root, &["commit", "-q", "-am", "main"]);

    assert_eq!(repo.resolve("feature").unwrap(), c2);
    assert_eq!(repo.merge_base("main", "feature").unwrap(), c1);
    assert!(matches!(
        repo.resolve("does-not-exist"),
        Err(GitError::UnknownRevision(_))
    ));
    assert!(matches!(
        repo.resolve("--output=/tmp/x"),
        Err(GitError::Invalid { .. })
    ));

    write(&root, "a.txt", "modified\n");
    assert!(repo.is_dirty().unwrap());
    git(&root, &["checkout", "-q", "--", "a.txt"]);
    assert!(!repo.is_dirty().unwrap());
    write(&root, "untracked.txt", "u");
    assert!(repo.is_dirty().unwrap(), "untracked files count as dirty");
}

#[test]
fn show_file_at_revision() {
    let (_t, root) = init_repo();
    let repo = Repo::discover(&root).unwrap();
    let c1 = git(&root, &["rev-parse", "HEAD"]);
    write(&root, "a.txt", "changed\n");
    write(&root, "later.txt", "later\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "second"]);

    assert_eq!(
        repo.show_file("HEAD", "a.txt").unwrap().unwrap(),
        b"changed\n"
    );
    assert_eq!(repo.show_file(&c1, "a.txt").unwrap().unwrap(), b"alpha\n");
    assert_eq!(
        repo.show_file("HEAD", "dir/b.txt").unwrap().unwrap(),
        b"beta\n"
    );

    // Missing paths are Ok(None), including ones that only exist later.
    assert_eq!(repo.show_file("HEAD", "nope.txt").unwrap(), None);
    assert_eq!(repo.show_file("HEAD", "dir/nope.txt").unwrap(), None);
    assert_eq!(repo.show_file("HEAD", "a.txt/under-a-file").unwrap(), None);
    assert_eq!(repo.show_file(&c1, "later.txt").unwrap(), None);
    // Working-tree-only changes are not visible.
    write(&root, "wt-only.txt", "x");
    assert_eq!(repo.show_file("HEAD", "wt-only.txt").unwrap(), None);
    // Pathspec magic is taken literally.
    assert_eq!(repo.show_file("HEAD", "*.txt").unwrap(), None);
    assert_eq!(repo.show_file("HEAD", ":(glob)a.txt").unwrap(), None);

    assert!(matches!(
        repo.show_file("HEAD", "dir"),
        Err(GitError::NotAFile { .. })
    ));
    assert!(matches!(
        repo.show_file("no-such-rev", "a.txt"),
        Err(GitError::UnknownRevision(_))
    ));
    for bad in [
        "",
        "/etc/passwd",
        "../a.txt",
        "dir/../a.txt",
        "./a.txt",
        "dir/",
    ] {
        assert!(
            matches!(repo.show_file("HEAD", bad), Err(GitError::Invalid { .. })),
            "{bad:?}"
        );
    }
    assert!(matches!(
        repo.show_file("HEAD:a.txt", "a.txt"),
        Err(GitError::Invalid { .. })
    ));
}

#[cfg(unix)]
#[test]
fn show_file_symlink_yields_target() {
    let (_t, root) = init_repo();
    std::os::unix::fs::symlink("a.txt", root.join("link")).unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "link"]);
    let repo = Repo::discover(&root).unwrap();
    assert_eq!(repo.show_file("HEAD", "link").unwrap().unwrap(), b"a.txt");
}

#[test]
fn moved_on_only_along_one_line_of_history() {
    let w = world(1);
    let dir = &w.clones[0];
    let repo = Repo::discover(dir).unwrap();
    let commit = |msg: &str| {
        write(dir, "a.txt", msg);
        git(dir, &["commit", "-q", "-am", msg]);
        git(dir, &["rev-parse", "HEAD"])
    };
    let main = git(dir, &["rev-parse", "HEAD"]);
    git(dir, &["checkout", "-q", "-b", "feature"]);
    let f1 = commit("f1");
    let f2 = commit("f2");
    // main (and origin/main) still contain main's commit; feature's own
    // earlier commit is contained by nothing else.
    assert!(!repo.moved_on(&main, &f2).unwrap());
    assert!(repo.moved_on(&f1, &f2).unwrap());
    assert!(!repo.moved_on(&f2, &f2).unwrap(), "the same commit");
    assert!(!repo.moved_on(&f2, &f1).unwrap(), "backwards");
    // The branch's own remote-tracking branch, behind it: the same line.
    git(dir, &["push", "-q", "origin", "feature"]);
    let f3 = commit("f3");
    assert!(repo.moved_on(&f2, &f3).unwrap());
    assert!(repo.moved_on(&f1, &f3).unwrap());
    // Another branch or a tag containing it: still needed.
    git(dir, &["branch", "other", &f1]);
    assert!(!repo.moved_on(&f1, &f3).unwrap());
    assert!(repo.moved_on(&f2, &f3).unwrap());
    git(dir, &["tag", "v1", &f2]);
    assert!(!repo.moved_on(&f2, &f3).unwrap());
    // A sibling branch's commit: not an ancestor.
    git(dir, &["checkout", "-q", "-b", "sibling", &main]);
    let s1 = commit("s1");
    assert!(!repo.moved_on(&f3, &s1).unwrap());
    // Detached: every ref counts, a namesake included.
    git(dir, &["checkout", "-q", "--detach", "feature"]);
    let d = commit("detached");
    assert!(!repo.moved_on(&f3, &d).unwrap(), "feature contains f3");
    // Unknown commits conclude nothing.
    assert!(!repo.moved_on(&"0".repeat(40), &d).unwrap());
    assert!(!repo.moved_on("HEAD", &d).unwrap());
}
