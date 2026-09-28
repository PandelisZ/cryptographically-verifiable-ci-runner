//! Runs the real `fixtures/vitest-abcd` project through the Vitest adapter.

use std::process::Command;

use camino::{Utf8Path, Utf8PathBuf};
use vci_adapter::{Adapter, VitestAdapter};

fn workspace_root() -> Utf8PathBuf {
    Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Utf8Path::parent)
        .unwrap()
        .to_owned()
}

fn copy_fixture() -> (tempfile::TempDir, Utf8PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(t.path().canonicalize().unwrap())
        .unwrap()
        .join("proj");
    let src = workspace_root().join("fixtures/vitest-abcd");
    let st = Command::new("cp")
        .arg("-R")
        .arg(src.as_str())
        .arg(dir.as_str())
        .status()
        .unwrap();
    assert!(st.success());
    (t, dir)
}

#[test]
fn lists_and_collects_the_abcd_fixture() {
    let (_t, dir) = copy_fixture();
    let a = VitestAdapter::new(&dir).with_js_plugin(workspace_root().join("js/vitest-plugin"));

    let mut listed: Vec<String> = a
        .list_test_files(&None)
        .unwrap()
        .into_iter()
        .map(|f| f.abs.strip_prefix(&dir).unwrap().to_string())
        .collect();
    listed.sort();
    assert_eq!(
        listed,
        [
            "src/a.test.ts",
            "src/b.test.ts",
            "src/c.test.ts",
            "src/d.test.ts"
        ]
    );

    let v = a.tool_versions().unwrap();
    assert_eq!(v.runner, "5.0.2");
    assert!(!v.node.is_empty() && !v.bundler.is_empty());

    let out = a
        .run_collect(&["src/b.test.ts".into(), "src/d.test.ts".into()], &None)
        .unwrap();
    assert_eq!(out.exit_code, Some(0));
    let ids: Vec<&str> = out.files.iter().map(|o| o.test_id.as_str()).collect();
    assert_eq!(ids.len(), 2, "{ids:?}");
    let b = out
        .files
        .iter()
        .find(|o| o.test_id == "src/b.test.ts")
        .unwrap();
    assert!(b.taints.is_empty(), "{:?}", b.taints);
    assert!(b.reads.contains(&dir.join("fixtures/b.json")));
    assert!(b.modules.contains(&dir.join("src/b.ts")));
    assert_eq!(b.runner_version, v.runner);
    assert_eq!(b.bundler_version, v.bundler);
    assert!(b.result.as_ref().unwrap().is_pass());
    let d = out
        .files
        .iter()
        .find(|o| o.test_id == "src/d.test.ts")
        .unwrap();
    assert!(d.externals.contains(&("ms".into(), "2.1.3".into())));
    assert!(!d.reads.contains(&dir.join("fixtures/b.json")));
}

#[test]
fn strict_env_is_applied_and_failures_reported() {
    let (_t, dir) = copy_fixture();
    std::fs::write(
        dir.join("src/e.test.ts"),
        "import { expect, test } from 'vitest';\n\
         test('env', () => { expect(process.env.VCI_ADAPTER_PROBE).toBe(undefined); expect(1).toBe(2); });\n",
    )
    .unwrap();
    let a = VitestAdapter::new(&dir).with_js_plugin(workspace_root().join("js/vitest-plugin"));
    let path = std::env::var_os("PATH").unwrap();
    let env = Some(vec![("PATH".into(), path)]);
    let out = a.run_collect(&["src/e.test.ts".into()], &env).unwrap();
    assert_ne!(out.exit_code, Some(0));
    let e = &out.files[0];
    assert!(e.env_keys.contains("VCI_ADAPTER_PROBE"));
    assert!(!e.result.as_ref().unwrap().is_pass());
}
