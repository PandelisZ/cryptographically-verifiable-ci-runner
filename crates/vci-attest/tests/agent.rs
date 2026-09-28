//! Signing with a `.pub` path whose private half lives only in ssh-agent.
//! Kept in its own test binary because it sets SSH_AUTH_SOCK process-wide.

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::*;
use vci_attest::*;

struct Agent(std::process::Child);
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn sign_with_public_key_path_via_ssh_agent() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let sock = dir.join("agent.sock");
    let _agent = Agent(
        Command::new("ssh-agent")
            .args(["-D", "-a", sock.as_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ssh-agent"),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "ssh-agent socket never appeared");
        std::thread::sleep(Duration::from_millis(20));
    }
    let st = Command::new("ssh-add")
        .arg(key.private.as_str())
        .env("SSH_AUTH_SOCK", sock.as_str())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "ssh-add failed");

    // Remove the private key from disk: only the agent can sign now.
    std::fs::remove_file(&key.private).unwrap();
    // SAFETY: this test binary contains a single test, so no other thread reads the environment concurrently.
    unsafe { std::env::set_var("SSH_AUTH_SOCK", sock.as_str()) };

    let env = sign_statement(&statement(7), &key.public).expect("agent-backed signing");
    let a = AllowedSigners::parse(&format!("alice@example.com {}\n", key.pub_line)).unwrap();
    let v = verify_envelope(&env, &a, now()).unwrap();
    assert_eq!(v.fingerprint, key.fingerprint);
}
