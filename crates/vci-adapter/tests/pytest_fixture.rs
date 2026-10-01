//! Runs the real `fixtures/pytest-abcd` project through the pytest adapter.
//! Skipped (with a message) when `uv` is not installed or cannot set up the
//! fixture's environment.

use std::process::Command;

use camino::{Utf8Path, Utf8PathBuf};
use vci_adapter::{Adapter, PytestAdapter};

fn workspace_root() -> Utf8PathBuf {
    Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Utf8Path::parent)
        .unwrap()
        .to_owned()
}

fn uv_available() -> bool {
    match Command::new("uv").arg("--version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!("SKIPPED: `uv` is not installed; the pytest adapter tests need uv on PATH");
            false
        }
    }
}

/// Copy the fixture (without its venv and caches) and set up its venv.
fn copy_fixture() -> Option<(tempfile::TempDir, Utf8PathBuf)> {
    let t = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap())
        .unwrap()
        .join("proj");
    std::fs::create_dir(&dir).unwrap();
    let src = workspace_root().join("fixtures/pytest-abcd");
    for name in [
        "src",
        "tests",
        "fixtures",
        "pyproject.toml",
        "uv.lock",
        ".python-version",
    ] {
        let st = Command::new("cp")
            .arg("-R")
            .arg(src.join(name).as_str())
            .arg(dir.join(name).as_str())
            .status()
            .unwrap();
        assert!(st.success());
    }
    for pc in [
        "src/__pycache__",
        "src/pkg/__pycache__",
        "tests/__pycache__",
    ] {
        let _ = std::fs::remove_dir_all(dir.join(pc));
    }
    let out = Command::new("uv")
        .args(["sync", "--locked", "--quiet"])
        .current_dir(&dir)
        .output()
        .unwrap();
    if !out.status.success() {
        eprintln!(
            "SKIPPED: `uv sync --locked` failed for the fixture (offline without a cache?): {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some((t, dir))
}

fn adapter(dir: &Utf8Path) -> PytestAdapter {
    PytestAdapter::new(dir).with_py_plugin(workspace_root().join("py/pytest-plugin"))
}

#[test]
fn lists_and_collects_the_abcd_fixture() {
    if !uv_available() {
        return;
    }
    let Some((_t, dir)) = copy_fixture() else {
        return;
    };
    let a = adapter(&dir);

    let listed: Vec<String> = a
        .list_test_files(&None)
        .unwrap()
        .into_iter()
        .map(|f| f.abs.strip_prefix(&dir).unwrap().to_string())
        .collect();
    assert_eq!(
        listed,
        [
            "tests/test_a.py",
            "tests/test_b.py",
            "tests/test_c.py",
            "tests/test_d.py"
        ]
    );

    let v = a.tool_versions().unwrap();
    assert_eq!(v.runner, "9.1.1");
    assert_eq!(v.python.split('.').count(), 3, "{v:?}");
    assert!(!v.implementation.is_empty());
    let ext = a.installed_externals(&None).unwrap().unwrap();
    assert_eq!(ext["idna"], ["3.20"]);
    assert_eq!(ext["pytest"], ["9.1.1"]);

    let out = a
        .run_collect(
            &[
                "tests/test_b.py".into(),
                "tests/test_c.py".into(),
                "tests/test_d.py".into(),
            ],
            &None,
        )
        .unwrap();
    assert_eq!(out.exit_code, Some(0));
    let get = |id: &str| out.files.iter().find(|o| o.test_id == id).unwrap();
    assert_eq!(out.files.len(), 3);
    let b = get("tests/test_b.py");
    assert!(b.taints.is_empty(), "{:?}", b.taints);
    assert_eq!(b.adapter, "pytest");
    assert_eq!(b.runner_version, v.runner);
    assert_eq!(b.python, v.python);
    assert_eq!(b.implementation, v.implementation);
    assert!(b.reads.contains(&dir.join("fixtures/b.json")));
    assert!(b.modules.contains(&dir.join("src/b.py")));
    assert!(b.modules.contains(&dir.join("tests/conftest.py")));
    assert!(b.writes.is_empty());
    assert!(b.result.as_ref().unwrap().is_pass());
    let c = get("tests/test_c.py");
    assert!(c.modules.contains(&dir.join("src/pkg/impl_x.py")), "{c:?}");
    let d = get("tests/test_d.py");
    assert!(d.externals.contains(&("idna".into(), "3.20".into())));
    assert!(!d.reads.contains(&dir.join("fixtures/b.json")));
}

#[test]
fn strict_env_writes_and_failures_are_reported() {
    if !uv_available() {
        return;
    }
    let Some((_t, dir)) = copy_fixture() else {
        return;
    };
    std::fs::write(
        dir.join("tests/test_e.py"),
        "import os\n\ndef test_env():\n    assert os.environ.get('VCI_ADAPTER_PROBE') is None\n    assert 1 == 2\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("tests/test_w.py"),
        "from pathlib import Path\n\ndef test_write():\n    Path(__file__).with_name('out.txt').write_text('x')\n",
    )
    .unwrap();
    let a = adapter(&dir);
    let mut vars = vec![("PATH".into(), std::env::var_os("PATH").unwrap_or_default())];
    if let Some(h) = std::env::var_os("HOME") {
        vars.push(("HOME".into(), h));
    }
    let env = Some(vars);
    let out = a
        .run_collect(&["tests/test_e.py".into(), "tests/test_w.py".into()], &env)
        .unwrap();
    assert_ne!(out.exit_code, Some(0));
    let e = out
        .files
        .iter()
        .find(|o| o.test_id == "tests/test_e.py")
        .unwrap();
    assert!(e.env_keys.contains("VCI_ADAPTER_PROBE"));
    assert!(!e.result.as_ref().unwrap().is_pass());
    let w = out
        .files
        .iter()
        .find(|o| o.test_id == "tests/test_w.py")
        .unwrap();
    assert!(w.writes.contains(&dir.join("tests/out.txt")), "{w:?}");

    // A collection error makes the listing fail (vci plan then runs everything).
    std::fs::write(dir.join("tests/test_broken.py"), "import does_not_exist\n").unwrap();
    let err = a.list_test_files(&None).unwrap_err().to_string();
    assert!(err.contains("collect"), "{err}");
}

/// Regression: stale `__pycache__` bytecode (source edited with its mtime and
/// size preserved: `cp -p`, `rsync -t`, `tar`, an edit within the same
/// second) ran during the collecting run while the attestation hashed the new
/// source. The collecting run must compile from the source it hashes.
#[test]
fn stale_bytecode_is_never_used_by_the_collecting_run() {
    if !uv_available() {
        return;
    }
    let Some((_t, dir)) = copy_fixture() else {
        return;
    };
    // A plain run writes src/__pycache__/a.cpython-*.pyc.
    let st = Command::new("uv")
        .args(["run", "--locked", "pytest", "-q", "tests/test_a.py"])
        .current_dir(&dir)
        .env_remove("PYTHONPYCACHEPREFIX")
        // The setup needs the plain run to write bytecode.
        .env_remove("PYTHONDONTWRITEBYTECODE")
        .env_remove("VIRTUAL_ENV")
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stdout)
    );
    assert!(
        std::fs::read_dir(dir.join("src/__pycache__"))
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("a.")),
        "the plain run must have cached a.py's bytecode"
    );
    // Same size, same mtime, different behaviour.
    let a = dir.join("src/a.py");
    let before = std::fs::metadata(&a).unwrap().modified().unwrap();
    let src = std::fs::read_to_string(&a).unwrap();
    assert!(src.contains("x + y"));
    std::fs::write(&a, src.replace("x + y", "x - y")).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&a)
        .unwrap()
        .set_modified(before)
        .unwrap();
    let out = adapter(&dir)
        .run_collect(&["tests/test_a.py".into()], &None)
        .unwrap();
    let r = out.files[0].result.as_ref().unwrap();
    assert!(
        !r.is_pass(),
        "the edited source (x - y) must be what runs, not the cached bytecode: {r:?}"
    );
}

/// Regression: `UV_ENV_FILE` (uv's variables are pass-through) made `uv run`
/// load a repository `.env` after vci computed the env it hashes, so a test
/// depending on it was attested with none of those values recorded.
#[test]
fn uv_env_files_are_never_loaded() {
    if !uv_available() {
        return;
    }
    let Some((_t, dir)) = copy_fixture() else {
        return;
    };
    std::fs::write(dir.join(".env"), "APP_FLAG=on\n").unwrap();
    std::fs::write(
        dir.join("tests/test_envfile.py"),
        "import os\n\ndef test_envfile():\n    assert os.environ.get('APP_FLAG') == 'on'\n",
    )
    .unwrap();
    let mut vars: Vec<(std::ffi::OsString, std::ffi::OsString)> = std::env::vars_os()
        .filter(|(k, _)| k != "VIRTUAL_ENV" && k != "APP_FLAG")
        .collect();
    vars.push(("UV_ENV_FILE".into(), ".env".into()));
    let env = Some(vars);
    let a = adapter(&dir);
    let out = a
        .run_collect(&["tests/test_envfile.py".into()], &env)
        .unwrap();
    let r = out.files[0].result.as_ref().unwrap();
    assert!(!r.is_pass(), "the .env file must not reach the test: {r:?}");
    // CI runs the same way.
    assert_ne!(
        a.run_plain(&["tests/test_envfile.py".into()], &env)
            .unwrap(),
        Some(0)
    );
}

/// Regression: attestations are made one file per process, but `vci ci`
/// ran the remaining files in one pytest process, where a module-level side
/// effect of one file can break another. CI must use the same isolation.
#[test]
fn plain_runs_isolate_files_like_the_attestations() {
    if !uv_available() {
        return;
    }
    let Some((_t, dir)) = copy_fixture() else {
        return;
    };
    std::fs::write(dir.join("src/cfgmod.py"), "MODE = 'ok'\n").unwrap();
    std::fs::write(
        dir.join("tests/test_p.py"),
        "import cfgmod\ncfgmod.MODE = 'patched'\n\ndef test_p():\n    pass\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("tests/test_q.py"),
        "import cfgmod\n\ndef test_q():\n    assert cfgmod.MODE == 'ok'\n",
    )
    .unwrap();
    let a = adapter(&dir);
    // Each file passes on its own (that is what gets attested).
    let out = a
        .run_collect(&["tests/test_p.py".into(), "tests/test_q.py".into()], &None)
        .unwrap();
    assert_eq!(out.exit_code, Some(0));
    assert!(
        out.files
            .iter()
            .all(|o| o.result.as_ref().unwrap().is_pass())
    );
    // CI's run of the same files gives the same verdict.
    assert_eq!(
        a.run_plain(&["tests/test_p.py".into(), "tests/test_q.py".into()], &None)
            .unwrap(),
        Some(0)
    );
    // Control: in one process the side effect breaks test_q.
    let st = Command::new("uv")
        .args([
            "run",
            "--locked",
            "pytest",
            "-q",
            "tests/test_p.py",
            "tests/test_q.py",
        ])
        .current_dir(&dir)
        .env_remove("VIRTUAL_ENV")
        .output()
        .unwrap();
    assert!(!st.status.success(), "control: shared process must fail");
}
