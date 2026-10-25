//! Signing with a `.pub` path whose private half lives only in ssh-agent.
//! Kept in its own test binary because it sets SSH_AUTH_SOCK process-wide.

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
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
    let rsa = keygen_kind(&dir, "bob", &["-t", "rsa", "-b", "2048"], "");
    let p256 = keygen_kind(&dir, "carol", &["-t", "ecdsa", "-b", "256"], "");
    for k in [&key, &rsa, &p256] {
        let st = Command::new("ssh-add")
            .arg(k.private.as_str())
            .env("SSH_AUTH_SOCK", sock.as_str())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "ssh-add failed");
        // Remove the private key from disk: only the agent can sign now.
        std::fs::remove_file(&k.private).unwrap();
    }
    // SAFETY: this test binary contains a single test, so no other thread reads the environment concurrently.
    unsafe { std::env::set_var("SSH_AUTH_SOCK", sock.as_str()) };

    let env = sign_statement(&statement(7), &key.public).expect("agent-backed signing");
    let a = AllowedSigners::parse(&format!("alice@example.com {}\n", key.pub_line)).unwrap();
    let v = verify_envelope(&env, &a, now()).unwrap();
    assert_eq!(v.fingerprint, key.fingerprint);

    // One signer, many signatures over its agent connections, from several
    // threads: each verifies with OpenSSH and with vci, and the ed25519
    // ones are exactly what `ssh-keygen -Y sign` makes through the agent.
    for (k, principal, algorithm) in [
        (&key, "alice@example.com", "ssh-ed25519"),
        (&rsa, "bob@example.com", "rsa-sha2-512"),
        (&p256, "carol@example.com", "ecdsa-sha2-nistp256"),
    ] {
        let signer = SshSigner::load(&k.public);
        assert!(signer.uses_agent() && !signer.in_process(), "{principal}");
        let allowed_text = format!("{principal} {}\n", k.pub_line);
        let a = AllowedSigners::parse(&allowed_text).unwrap();
        let envs: Vec<Envelope> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8u32)
                .map(|n| {
                    let signer = &signer;
                    s.spawn(move || signer.sign_statement(&statement(n)).unwrap())
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(signer.uses_agent(), "{principal}: the agent failed");
        for env in &envs {
            let pem = sig_pem(env, 0);
            let sig = ssh_key::SshSig::from_pem(&pem).unwrap();
            assert_eq!(sig.hash_alg().as_str(), "sha512");
            assert_eq!(sig.algorithm().as_str(), algorithm);
            assert_eq!(
                verify_envelope(env, &a, now()).unwrap().fingerprint,
                k.fingerprint
            );
            let message = pae(PAYLOAD_TYPE, &b64().decode(&env.payload).unwrap());
            assert!(
                openssh_verify(&dir, &allowed_text, principal, NAMESPACE, &pem, &message),
                "{principal}: ssh-keygen -Y verify rejected it"
            );
            if algorithm == "ssh-ed25519" {
                let theirs = ssh_keygen_via_agent(&k.public, &message);
                assert_eq!(pem, theirs);
            }
        }
    }
}

/// `ssh-keygen -Y sign` with a `.pub` (the agent signs): the PEM text.
fn ssh_keygen_via_agent(public: &camino::Utf8Path, message: &[u8]) -> String {
    use std::io::Write as _;
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", NAMESPACE, "-f", public.as_str()])
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
