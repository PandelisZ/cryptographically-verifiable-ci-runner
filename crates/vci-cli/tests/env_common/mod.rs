//! The `[env]` lists (docs/ENV.md), end to end, the same way for every runner:
//! each runner's e2e file writes a test that checks what it sees and calls
//! [`check_env_lists`] with its own harness.
//!
//! The test file must pass when (and only when) `APP_SET` is `"declared"`,
//! `APP_HASH` and `APP_IGNORE` are set (any value), and `APP_UNDECLARED` is
//! unset; it reads all four.

#![allow(dead_code)]

use std::path::Path;
use std::process::Output;

use serde_json::Value;

/// The `[env]` table of the tests: the new key names.
pub const ENV_NEW: &str = r#"[env]
set = { TZ = "UTC", APP_SET = "declared" }
hash = ["APP_HASH"]
ignore = ["APP_IGNORE"]
"#;

/// The same policy with the old key names (and `mode = "strict"`).
pub const ENV_OLD: &str = r#"[env]
mode = "strict"
set = { TZ = "UTC", APP_SET = "declared" }
global = ["APP_HASH"]
pass_through = ["APP_IGNORE"]
"#;

/// `toml` with its `[env]` table (the last one) replaced by `env`.
pub fn with_env(toml: &str, env: &str) -> String {
    let i = toml.find("[env]").expect("an [env] table");
    format!("{}{env}", &toml[..i])
}

/// The attesting machine: its own values of every variable.
pub const MACHINE: &[(&str, &str)] = &[
    ("APP_SET", "machine-one"),
    ("APP_HASH", "h1"),
    ("APP_IGNORE", "i1"),
    ("APP_UNDECLARED", "u1"),
    ("TZ", "America/New_York"),
];

/// [`MACHINE`] with `k` set to `v`.
pub fn with(k: &str, v: &str) -> Vec<(&'static str, String)> {
    MACHINE
        .iter()
        .map(|(mk, mv)| {
            (
                *mk,
                if *mk == k {
                    v.to_owned()
                } else {
                    mv.to_string()
                },
            )
        })
        .collect()
}

pub fn machine() -> Vec<(&'static str, String)> {
    with("", "")
}

/// Variables added to a command's environment.
pub type Env = [(&'static str, String)];

/// Runs `vci <args>` in the repository with these variables added.
pub type VciFn<'a> = &'a dyn Fn(&[&str], &Env) -> Output;

/// What a runner's harness provides.
pub struct Ops<'a> {
    /// The repository (on branch `feature`; `main` is the base).
    pub work: &'a Path,
    /// A scratch directory (for a worktree).
    pub scratch: &'a Path,
    /// `vci <args>` in `work` with these variables added to the harness's
    /// environment.
    pub vci: VciFn<'a>,
    /// `git <args>` in a directory.
    pub git: &'a dyn Fn(&Path, &[&str]) -> String,
    /// The trusted signing key.
    pub key: &'a str,
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// Whether `vci plan --base-ref base` skips `id` with `env`.
fn skips(ops: &Ops, base: &str, id: &str, env: &[(&'static str, String)]) -> (bool, String) {
    let out = (ops.vci)(&["plan", "--base-ref", base, "--format", "json"], env);
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "vci plan failed: {stderr}");
    let v: Value = serde_json::from_str(&stdout).unwrap();
    let f = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["testId"] == id)
        .unwrap_or_else(|| panic!("{id} not listed: {stdout}"));
    (f["skip"].as_bool().unwrap(), stderr)
}

/// The rows of `vci env --format json` for the first project.
fn env_rows(ops: &Ops, env: &[(&'static str, String)]) -> (Vec<Value>, Value, String) {
    let out = (ops.vci)(&["env", "--format", "json"], env);
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "vci env failed: {stderr}");
    let v: Value = serde_json::from_str(&stdout).unwrap();
    let p = v[0].clone();
    (p["rows"].as_array().unwrap().clone(), p, stderr)
}

fn blake3_12(s: &str) -> String {
    vci_core::blake3_hex(s.as_bytes())[..12].to_owned()
}

/// Attest `id` (with `run_args`, e.g. the file) on a machine where every
/// variable has its own value, then check each list end to end:
///
/// 1. a `set` variable reaches the test with its declared value, and a
///    verifier where it has a third value still skips (vci sets it);
/// 2. another `hash` value re-runs, and `vci explain` names the variable and
///    its class;
/// 3. another `ignore` value does not re-run;
/// 4. an undeclared variable never reaches the test (the test asserts it is
///    unset) and another value of it does not re-run;
/// 5. `vci env` lists the classes, sources and values here (snapshot of the
///    vci.toml rows);
/// 6. the same policy spelt with the old key names (`global`,
///    `pass_through`, `mode = "strict"`) in the base vci.toml verifies the same
///    attestation, with one deprecation warning.
pub fn check_env_lists(ops: &Ops, id: &str, run_args: &[&str]) {
    let mut args = vec!["run"];
    args.extend_from_slice(run_args);
    args.extend_from_slice(&["--key", ops.key]);
    let out = (ops.vci)(&args, &machine());
    let (_, stderr) = text(&out);
    assert!(out.status.success(), "vci run failed: {stderr}");
    assert!(
        stderr.contains(&format!("attested {id} (")),
        "{id} must be attested (APP_SET reached it as \"declared\", APP_UNDECLARED did not reach it): {stderr}"
    );
    assert!(!stderr.contains("old env key names"), "{stderr}");

    // 1. set: the verifier's own value does not matter.
    let (skip, _) = skips(ops, "main", id, &machine());
    assert!(skip, "same machine: {id} must SKIP");
    let (skip, _) = skips(ops, "main", id, &with("APP_SET", "a-third-value"));
    assert!(skip, "APP_SET is set by vci: {id} must SKIP");
    let (skip, _) = skips(ops, "main", id, &with("TZ", "Asia/Tokyo"));
    assert!(skip, "TZ is set by vci: {id} must SKIP");

    // 2. hash: another value re-runs.
    let (skip, _) = skips(ops, "main", id, &with("APP_HASH", "h2"));
    assert!(!skip, "APP_HASH changed: {id} must RUN");
    let out = (ops.vci)(
        &["explain", id, "--base-ref", "main"],
        &with("APP_HASH", "h2"),
    );
    let (ex, _) = text(&out);
    assert!(
        ex.contains("failed check: env") && ex.contains("env:APP_HASH (hash)"),
        "{ex}"
    );

    // 3. ignore: another value does not.
    let (skip, _) = skips(ops, "main", id, &with("APP_IGNORE", "i2"));
    assert!(skip, "APP_IGNORE is ignored: {id} must SKIP");

    // 4. undeclared: removed everywhere.
    let (skip, _) = skips(ops, "main", id, &with("APP_UNDECLARED", "u2"));
    assert!(skip, "APP_UNDECLARED is removed: {id} must SKIP");

    // `vci ci` applies `set` too, plain and attesting: the test (re-run as
    // APP_HASH changed) passes only if it sees APP_SET as declared.
    let ci_env = |hash: &str| -> Vec<(&'static str, String)> {
        with("APP_HASH", hash)
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    if k == "APP_SET" {
                        "ci-runner".to_owned()
                    } else {
                        v
                    },
                )
            })
            .collect()
    };
    let out = (ops.vci)(&["ci", "--base-ref", "main"], &ci_env("h2"));
    let (_, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(0), "vci ci (plain): {stderr}");
    let out = (ops.vci)(
        &["ci", "--base-ref", "main", "--key", ops.key],
        &ci_env("h3"),
    );
    let (_, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(0), "vci ci --key: {stderr}");
    let (skip, _) = skips(ops, "main", id, &with("APP_HASH", "h3"));
    assert!(skip, "attested by vci ci with APP_HASH=h3: {id} must SKIP");

    // 5. vci env.
    let (rows, project, stderr) = env_rows(ops, &machine());
    assert!(!stderr.contains("warning"), "{stderr}");
    let user: Vec<(String, String, String, String)> = rows
        .iter()
        .filter(|r| r["variable"].as_str().unwrap().starts_with("APP_"))
        .map(|r| {
            (
                r["variable"].as_str().unwrap().to_owned(),
                r["class"].as_str().unwrap().to_owned(),
                r["source"].as_str().unwrap().to_owned(),
                r["here"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let row = |v: &str, c: &str, s: &str, h: &str| {
        (v.to_owned(), c.to_owned(), s.to_owned(), h.to_owned())
    };
    assert_eq!(
        user,
        vec![
            row("APP_SET", "set", "vci.toml set", "\"declared\""),
            row(
                "APP_HASH",
                "hash",
                "vci.toml hash",
                &format!("present ({})", blake3_12("h1"))
            ),
            row("APP_IGNORE", "ignore", "vci.toml ignore", "present"),
            row("APP_UNDECLARED", "stripped", "-", "present (removed)"),
        ],
        "{rows:#?}"
    );
    let tz = rows.iter().find(|r| r["variable"] == "TZ").unwrap();
    assert_eq!(tz["class"], "set");
    assert_eq!(tz["here"], "\"UTC\"");
    // Text form: one line per variable, the same classes.
    let out = (ops.vci)(&["env", "--base-ref", "main"], &machine());
    let (txt, _) = text(&out);
    assert!(txt.contains(", same as base"), "{txt}");
    for (v, c) in [
        ("APP_SET", "set"),
        ("APP_HASH", "hash"),
        ("APP_IGNORE", "ignore"),
    ] {
        assert!(
            txt.lines().any(|l| l.split_whitespace().take(2).eq([v, c])),
            "{v} {c}: {txt}"
        );
    }
    assert!(txt.contains("APP_UNDECLARED"), "{txt}");

    // 6. The old names, in a base commit of their own.
    let wt = ops.scratch.join("oldnames-worktree");
    let wts = wt.to_str().unwrap();
    (ops.git)(
        ops.work,
        &["worktree", "add", "-q", "-b", "oldnames", wts, "main"],
    );
    let toml = std::fs::read_to_string(wt.join("vci.toml")).unwrap();
    std::fs::write(wt.join("vci.toml"), with_env(&toml, ENV_OLD)).unwrap();
    (ops.git)(&wt, &["commit", "-q", "-am", "the old env key names"]);
    (ops.git)(ops.work, &["worktree", "remove", "--force", wts]);
    let (skip, stderr) = skips(ops, "oldnames", id, &with("APP_SET", "a-third-value"));
    assert!(skip, "old names, same policy: {id} must SKIP: {stderr}");
    assert_eq!(
        stderr.matches("old env key names").count(),
        1,
        "one deprecation warning: {stderr}"
    );
    assert!(
        stderr.contains("env.global -> hash") && stderr.contains("env.pass_through -> ignore"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("loose"),
        "mode = \"strict\" is silent: {stderr}"
    );
    let (skip, _) = skips(ops, "oldnames", id, &with("APP_HASH", "h2"));
    assert!(!skip, "old names: APP_HASH changed: {id} must RUN");
    let (skip, _) = skips(ops, "oldnames", id, &with("APP_IGNORE", "i2"));
    assert!(skip, "old names: APP_IGNORE is ignored: {id} must SKIP");
    // `vci env` on the old names: the same digest, the old name as source.
    std::fs::write(
        ops.work.join("vci.toml"),
        with_env(
            &std::fs::read_to_string(ops.work.join("vci.toml")).unwrap(),
            ENV_OLD,
        ),
    )
    .unwrap();
    let (rows, old_project, stderr) = env_rows(ops, &machine());
    assert!(stderr.contains("old env key names"), "{stderr}");
    assert_eq!(old_project["digest"], project["digest"]);
    let h = rows.iter().find(|r| r["variable"] == "APP_HASH").unwrap();
    assert_eq!(h["class"], "hash");
    assert_eq!(h["source"], "vci.toml global (old name of hash)");
    (ops.git)(ops.work, &["checkout", "-q", "--", "vci.toml"]);
}
