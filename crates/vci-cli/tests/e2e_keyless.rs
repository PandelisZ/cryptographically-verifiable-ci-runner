//! `vci verify` of a keylessly signed envelope (the vci-attest fixture: a
//! local Fulcio-like authority and a real timestamp from
//! timestamp.githubapp.com), and `vci run --oidc` / `vci ci --oidc` outside
//! a job with an OIDC token.

use std::path::{Path, PathBuf};
use std::process::Command;

use assert_cmd::cargo::CommandCargoExt as _;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../vci-attest/tests/fixtures/keyless")
}

const IDENTITY: &str = r#"
[[identity]]
principal = "github-actions"
issuer = "https://token.actions.githubusercontent.com"
repository = "ComposalAI/vex"
workflow = ".github/workflows/vci.yml"
ref = "refs/heads/master"
"#;

fn verify(ids: &str) -> (i32, String) {
    let t = tempfile::tempdir().unwrap();
    let ids_path = t.path().join("identities.toml");
    std::fs::write(&ids_path, ids).unwrap();
    let out = Command::cargo_bin("vci")
        .unwrap()
        .current_dir(t.path())
        .arg("verify")
        .arg(fixtures().join("envelope.json"))
        .arg("--identities")
        .arg(&ids_path)
        .arg("--trusted-root")
        .arg(fixtures().join("trusted-root.json"))
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn verify_names_the_identity_principal_and_the_timestamp() {
    let (code, out) = verify(IDENTITY);
    assert!(
        out.starts_with("VALID signature by github-actions (oidc repo:ComposalAI/vex workflow:.github/workflows/vci.yml ref:refs/heads/master event:push)\n"),
        "{out}"
    );
    assert!(out.contains("(timestamp by timestamp.githubapp.com), run https://github.com/ComposalAI/vex/actions/runs/1/attempts/1"), "{out}");
    // The fixture's statement is not a vci test predicate.
    assert!(
        out.contains("predicate is not a vci test predicate"),
        "{out}"
    );
    assert_eq!(code, 1);
}

#[test]
fn verify_rejects_an_identity_not_in_identities_toml() {
    let (code, out) = verify(&IDENTITY.replace("ComposalAI/vex", "ComposalAI/other"));
    assert_eq!(code, 1, "{out}");
    assert!(
        out.starts_with("INVALID: identity repo:ComposalAI/vex workflow:.github/workflows/vci.yml ref:refs/heads/master event:push (issuer https://token.actions.githubusercontent.com) matches no [[identity]] in .vci/identities.toml\n"),
        "{out}"
    );
}

fn no_token(cmd: &mut Command) -> &mut Command {
    for v in [
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "SIGSTORE_ID_TOKEN",
    ] {
        cmd.env_remove(v);
    }
    cmd
}

#[test]
fn run_oidc_without_a_token_fails_before_running_anything() {
    let t = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(t.path())
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    };
    git(&["init", "-q"]);
    std::fs::write(t.path().join("vci.toml"), "").unwrap();
    let out = no_token(Command::cargo_bin("vci").unwrap().current_dir(t.path()))
        .args(["run", "--oidc"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("permissions: id-token: write"), "{err}");
}

#[test]
fn oidc_and_key_are_exclusive_and_ttl_needs_one() {
    let out = Command::cargo_bin("vci")
        .unwrap()
        .args(["ci", "--oidc", "--key", "k"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::cargo_bin("vci")
        .unwrap()
        .args(["run", "--oidc", "--key", "k"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::cargo_bin("vci")
        .unwrap()
        .args(["ci", "--ttl", "1d"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--key") || err.contains("--oidc"), "{err}");
}
