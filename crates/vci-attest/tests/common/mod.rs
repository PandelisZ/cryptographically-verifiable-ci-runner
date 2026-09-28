#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::process::{Command, Stdio};

use base64::Engine as _;
use camino::{Utf8Path, Utf8PathBuf};
use vci_attest::{Envelope, Statement, Subject};

pub fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

pub struct Key {
    pub private: Utf8PathBuf,
    pub public: Utf8PathBuf,
    /// "ssh-ed25519 AAAA... comment"
    pub pub_line: String,
    /// "SHA256:..." as printed by `ssh-keygen -l`.
    pub fingerprint: String,
}

pub fn tempdir() -> (tempfile::TempDir, Utf8PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = Utf8PathBuf::from_path_buf(t.path().to_path_buf()).unwrap();
    (t, p)
}

/// Generate a throwaway, unencrypted ed25519 key with ssh-keygen.
pub fn keygen(dir: &Utf8Path, name: &str) -> Key {
    let private = dir.join(name);
    let st = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            &format!("{name}@test"),
            "-f",
        ])
        .arg(private.as_str())
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "ssh-keygen -t ed25519 failed");
    let public = Utf8PathBuf::from(format!("{private}.pub"));
    let pub_line = std::fs::read_to_string(&public).unwrap().trim().to_string();
    let out = Command::new("ssh-keygen")
        .args(["-l", "-E", "sha256", "-f", public.as_str()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let fingerprint = String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string();
    Key {
        private,
        public,
        pub_line,
        fingerprint,
    }
}

pub fn statement(n: u32) -> Statement {
    let mut digest = BTreeMap::new();
    digest.insert("blake3".to_string(), format!("{n:064x}"));
    Statement::new(
        vec![Subject {
            name: format!("src/t{n}.test.ts"),
            digest,
        }],
        "https://vci.dev/test-attestation/v1",
        serde_json::json!({ "testId": format!("src/t{n}.test.ts"), "result": { "state": "passed" } }),
    )
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Decoded SSHSIG PEM text of signature `i`.
pub fn sig_pem(env: &Envelope, i: usize) -> String {
    String::from_utf8(b64().decode(&env.signatures[i].sig).unwrap()).unwrap()
}

/// Run `ssh-keygen -Y verify` over `message` and report whether OpenSSH accepts it.
pub fn openssh_verify(
    dir: &Utf8Path,
    allowed_text: &str,
    principal: &str,
    namespace: &str,
    pem: &str,
    message: &[u8],
) -> bool {
    let allowed = dir.join("openssh_allowed_signers");
    std::fs::write(&allowed, allowed_text).unwrap();
    let sig = dir.join("openssh.sig");
    std::fs::write(&sig, pem).unwrap();
    let mut child = Command::new("ssh-keygen")
        .args([
            "-Y",
            "verify",
            "-f",
            allowed.as_str(),
            "-I",
            principal,
            "-n",
            namespace,
            "-s",
            sig.as_str(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(message).unwrap();
    let out = child.wait_with_output().unwrap();
    out.status.success()
}

/// Sign raw bytes with ssh-keygen in an arbitrary namespace; returns PEM text.
pub fn raw_sign(key: &Key, namespace: &str, message: &[u8], extra: &[&str]) -> String {
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", namespace])
        .args(extra)
        .args(["-f", key.private.as_str()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(message).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
