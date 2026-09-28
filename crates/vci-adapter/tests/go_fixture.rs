//! Runs the real `fixtures/go-abcd` module through the Go adapter. Skipped
//! (with a message) when `go` is not installed or the fixture's modules
//! cannot be downloaded.

use std::process::Command;

use camino::{Utf8Path, Utf8PathBuf};
use vci_adapter::{Adapter, GoAdapter};

fn workspace_root() -> Utf8PathBuf {
    Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Utf8Path::parent)
        .unwrap()
        .to_owned()
}

/// Copy the fixture and download its modules; `None` (skipped) without go.
fn copy_fixture() -> Option<(tempfile::TempDir, Utf8PathBuf)> {
    match Command::new("go").arg("version").output() {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("SKIPPED: `go` is not installed; the Go adapter tests need it on PATH");
            return None;
        }
    }
    let t = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap())
        .unwrap()
        .join("proj");
    let st = Command::new("cp")
        .arg("-R")
        .arg(workspace_root().join("fixtures/go-abcd").as_str())
        .arg(dir.as_str())
        .status()
        .unwrap();
    assert!(st.success());
    let out = Command::new("go")
        .args(["mod", "download"])
        .current_dir(&dir)
        .env_remove("GOFLAGS")
        .env_remove("GOWORK")
        .output()
        .unwrap();
    if !out.status.success() {
        eprintln!(
            "SKIPPED: `go mod download` failed for the fixture (offline without a module cache?): {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some((t, dir))
}

/// A strict-mode-like environment: PATH and HOME (and the go locations if
/// set), nothing else.
fn env() -> vci_adapter::ChildEnv {
    let mut v = Vec::new();
    for k in [
        "PATH",
        "HOME",
        "GOPATH",
        "GOMODCACHE",
        "GOCACHE",
        "GOROOT",
        "TMPDIR",
    ] {
        if let Some(x) = std::env::var_os(k) {
            v.push((k.into(), x));
        }
    }
    Some(v)
}

#[test]
fn lists_and_collects_the_abcd_fixture() {
    let Some((_t, dir)) = copy_fixture() else {
        return;
    };
    let a = GoAdapter::new(&dir);
    let env = env();
    let listed: Vec<String> = a
        .list_test_files(&env)
        .unwrap()
        .iter()
        .map(|f| f.abs.strip_prefix(&dir).unwrap().to_string())
        .collect();
    assert_eq!(listed, ["a", "b", "c", "d"], "internal/text has no tests");

    let v = a.tool_versions_with_env(&env).unwrap();
    assert!(v.runner.starts_with("go1."), "{v:?}");
    assert!(
        v.go_env.iter().any(|e| e.starts_with("CGO_ENABLED=")),
        "{v:?}"
    );
    assert!(v.go_env.contains(&"GOWORK=".to_owned()), "{v:?}");

    let files: Vec<String> = ["b", "c", "d"].iter().map(|s| s.to_string()).collect();
    let out = a.run_collect(&files, &env).unwrap();
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(out.files.len(), 3);
    let by = |id: &str| out.files.iter().find(|o| o.test_id == id).unwrap();

    let b = by("b");
    assert!(b.taints.is_empty(), "{:?}", b.taints);
    assert!(b.result.as_ref().unwrap().is_pass());
    assert_eq!(b.adapter, "go");
    assert_eq!(b.runner_version, v.runner);
    // Compile time: sources of b and of the package it imports, their
    // directory listings, go.mod.
    for f in ["b/b.go", "b/b_test.go", "internal/text/text.go", "go.mod"] {
        assert!(b.modules.contains(&dir.join(f)), "{f}: {:?}", b.modules);
    }
    assert!(b.readdirs.contains(&dir.join("b")));
    assert!(b.readdirs.contains(&dir.join("internal/text")));
    // Run time: the fixture, and the file read during package init.
    assert!(
        b.reads.contains(&dir.join("b/testdata/b.json")),
        "{:?}",
        b.reads
    );
    assert!(
        b.reads.contains(&dir.join("b/testdata/golden.txt")),
        "{:?}",
        b.reads
    );
    assert!(b.env_keys.contains("TZ") && !b.env_keys.contains("PWD"));
    assert!(b.externals.is_empty() && b.platform_files.is_empty());

    let c = by("c");
    assert!(c.taints.is_empty(), "{:?}", c.taints);
    assert!(
        c.modules.contains(&dir.join("c/data/x.txt")),
        "embedded file"
    );
    assert!(
        c.readdirs.contains(&dir.join("c/data")),
        "embed directory listing"
    );
    assert!(
        c.reads.contains(&dir.join("c/testdata/impl-x.txt")),
        "{:?}",
        c.reads
    );

    // d: the external module is recorded by version, and its extracted copy
    // in the module cache matched its go.sum hash (no module-cache taint).
    let d = by("d");
    assert!(d.taints.is_empty(), "{:?}", d.taints);
    assert!(
        d.externals
            .contains(&("golang.org/x/sync".to_owned(), "v0.20.0".to_owned())),
        "{:?}",
        d.externals
    );
    assert!(!d.modules.iter().any(|m| m.as_str().contains("x/sync@")));

    // The build list CI checks externals against.
    let ext = a.installed_externals(&env).unwrap().unwrap();
    assert_eq!(ext["golang.org/x/sync"], ["v0.20.0"]);
}
