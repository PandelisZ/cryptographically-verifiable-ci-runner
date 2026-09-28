//! Signing via `ssh-keygen -Y sign`.

use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};

use camino::Utf8Path;
use ssh_key::{HashAlg, SshSig};

use crate::{Envelope, NAMESPACE, PAYLOAD_TYPE, Signature, Statement, b64_encode, pae};

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("serialising statement: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("running ssh-keygen: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("ssh-keygen -Y sign failed ({status}): {stderr}")]
    SshKeygen { status: String, stderr: String },
    #[error("ssh-keygen produced an unusable signature: {0}")]
    BadOutput(String),
}

/// Serialise `statement` to JSON once, then sign those exact bytes.
pub fn sign_statement(statement: &Statement, key_path: &Utf8Path) -> Result<Envelope, SignError> {
    let payload = serde_json::to_vec(statement)?;
    sign_payload(&payload, key_path)
}

/// Sign arbitrary in-toto payload bytes (payload type [`PAYLOAD_TYPE`]).
///
/// Shells out to `ssh-keygen -Y sign -n vci-attest -f <key>` with the DSSE PAE
/// on stdin. `key_path` may be a private key, or a `.pub` whose private half is
/// held by ssh-agent. The produced signature is re-checked in Rust before it is
/// returned.
pub fn sign_payload(payload: &[u8], key_path: &Utf8Path) -> Result<Envelope, SignError> {
    let message = pae(PAYLOAD_TYPE, payload);

    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", NAMESPACE, "-f"])
        .arg(key_path.as_std_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Feed stdin from a thread so a large message can't deadlock against a
    // full stdout/stderr pipe.
    let mut stdin = child.stdin.take().expect("stdin piped");
    let writer = std::thread::spawn(move || {
        let r = stdin.write_all(&message);
        drop(stdin);
        r.map(|_| message)
    });
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("stdout piped")
        .read_to_end(&mut stdout)?;
    let status = child.wait()?;
    let stderr = stderr_reader.join().unwrap_or_default();
    let write_result = writer
        .join()
        .map_err(|_| SignError::BadOutput("stdin writer panicked".into()))?;

    if !status.success() {
        return Err(SignError::SshKeygen {
            status: status.to_string(),
            stderr: String::from_utf8_lossy(&stderr).trim().to_string(),
        });
    }
    let message = write_result?;

    let pem = String::from_utf8(stdout)
        .map_err(|_| SignError::BadOutput("signature is not UTF-8".into()))?;
    let sshsig = SshSig::from_pem(pem.as_bytes())
        .map_err(|e| SignError::BadOutput(format!("parse SSHSIG: {e}")))?;
    if sshsig.namespace() != NAMESPACE {
        return Err(SignError::BadOutput(format!(
            "unexpected namespace {:?}",
            sshsig.namespace()
        )));
    }
    let public = ssh_key::PublicKey::new(sshsig.public_key().clone(), "");
    public
        .verify(NAMESPACE, &message, &sshsig)
        .map_err(|e| SignError::BadOutput(format!("self-check failed: {e}")))?;

    Ok(Envelope {
        payload_type: PAYLOAD_TYPE.to_string(),
        payload: b64_encode(payload),
        signatures: vec![Signature {
            keyid: sshsig.public_key().fingerprint(HashAlg::Sha256).to_string(),
            sig: b64_encode(pem.as_bytes()),
        }],
    })
}
