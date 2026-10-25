//! Signing: in process with an unencrypted OpenSSH private key file, through
//! ssh-agent for a `.pub` whose private half the agent holds, else with
//! `ssh-keygen -Y sign`.

use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};

use camino::{Utf8Path, Utf8PathBuf};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

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

/// The SSHSIG hash `ssh-keygen -Y sign` uses for every kind of key
/// (OpenSSH's default `hashalg`, sha512, for ed25519, ECDSA and RSA alike).
pub(crate) const HASH: HashAlg = HashAlg::Sha512;

/// A signing key, read once and used for many signatures ([`SshSigner::load`]).
///
/// An unencrypted OpenSSH private key file of a kind ssh-key signs with
/// (ed25519, ECDSA P-256, P-384 and P-521) signs in process: no process
/// per signature, and the same SSHSIG ssh-keygen makes (byte for byte for
/// ed25519, whose signatures are deterministic). A `.pub` (or any public
/// key file) signs through ssh-agent over one long-lived connection per
/// thread. Everything else, and any signature the agent does not make,
/// goes to `ssh-keygen -Y sign` as before: encrypted keys, RSA keys (the
/// `rsa` crate's private-key operation is not constant-time,
/// RUSTSEC-2023-0071), PEM-format keys, security keys, and key files
/// readable by others (ssh-keygen decides about those).
pub struct SshSigner {
    path: Utf8PathBuf,
    how: How,
}

enum How {
    Key(Box<PrivateKey>),
    #[cfg(unix)]
    Agent(Box<crate::agent::Agent>),
    SshKeygen,
}

impl std::fmt::Debug for SshSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let how = match &self.how {
            How::Key(_) => "in process",
            #[cfg(unix)]
            How::Agent(_) => "ssh-agent",
            How::SshKeygen => "ssh-keygen",
        };
        f.debug_struct("SshSigner")
            .field("path", &self.path)
            .field("how", &how)
            .finish()
    }
}

impl SshSigner {
    /// Read the key at `key_path` (a private key, or a `.pub` whose private
    /// half is held by ssh-agent). Never fails: a key that cannot be used in
    /// process or through the agent signs with ssh-keygen, which reports
    /// what is wrong with it.
    pub fn load(key_path: &Utf8Path) -> SshSigner {
        let how = match std::fs::read(key_path.as_std_path()) {
            Ok(bytes) if bytes.starts_with(b"-----BEGIN") => {
                in_process_key(key_path, &bytes).map_or(How::SshKeygen, |k| How::Key(Box::new(k)))
            }
            Ok(bytes) => agent_for(&bytes).unwrap_or(How::SshKeygen),
            Err(_) => How::SshKeygen,
        };
        SshSigner {
            path: key_path.to_owned(),
            how,
        }
    }

    /// Whether signatures are made in this process (no ssh-keygen, no agent).
    pub fn in_process(&self) -> bool {
        matches!(self.how, How::Key(_))
    }

    /// Whether signatures are asked of ssh-agent: a public key with an
    /// agent, until the agent fails to sign once (then ssh-keygen signs).
    pub fn uses_agent(&self) -> bool {
        #[cfg(unix)]
        if let How::Agent(a) = &self.how {
            return !a.has_failed();
        }
        false
    }

    /// Serialise `statement` to JSON once, then sign those exact bytes.
    pub fn sign_statement(&self, statement: &Statement) -> Result<Envelope, SignError> {
        let payload = serde_json::to_vec(statement)?;
        self.sign_payload(&payload)
    }

    /// Sign arbitrary in-toto payload bytes (payload type [`PAYLOAD_TYPE`]).
    /// The signature is re-checked in Rust before it is returned.
    pub fn sign_payload(&self, payload: &[u8]) -> Result<Envelope, SignError> {
        let message = pae(PAYLOAD_TYPE, payload);
        let pem = match &self.how {
            How::Key(k) => match k
                .sign(NAMESPACE, HASH, &message)
                .and_then(|s| s.to_pem(LineEnding::LF))
            {
                Ok(pem) => pem,
                Err(_) => ssh_keygen_sign(&message, &self.path)?,
            },
            #[cfg(unix)]
            How::Agent(a) => match a.sign(&message) {
                Some(pem) => pem,
                None => ssh_keygen_sign(&message, &self.path)?,
            },
            How::SshKeygen => ssh_keygen_sign(&message, &self.path)?,
        };
        envelope(payload, &message, pem)
    }
}

/// The private key in `bytes` when it can sign in process: an unencrypted
/// OpenSSH key of a kind ssh-key signs with, in a file only its owner can
/// read (ssh-keygen refuses or warns about others), whose trial signature
/// verifies.
fn in_process_key(path: &Utf8Path, bytes: &[u8]) -> Option<PrivateKey> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path.as_std_path())
            .ok()?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return None;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    if !bytes.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----") {
        return None;
    }
    let key = PrivateKey::from_openssh(bytes).ok()?;
    if key.is_encrypted()
        || !matches!(
            key.algorithm(),
            Algorithm::Ed25519 | Algorithm::Ecdsa { .. }
        )
    {
        return None;
    }
    let trial = key.sign(NAMESPACE, HASH, b"vci").ok()?;
    key.public_key().verify(NAMESPACE, b"vci", &trial).ok()?;
    Some(key)
}

/// ssh-agent for the public key in `bytes`, when there is an agent.
fn agent_for(bytes: &[u8]) -> Option<How> {
    #[cfg(unix)]
    {
        let text = std::str::from_utf8(bytes).ok()?;
        let line = text
            .lines()
            .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))?;
        let key = PublicKey::from_openssh(line.trim()).ok()?;
        crate::agent::Agent::new(key).map(|a| How::Agent(Box::new(a)))
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
        None
    }
}

/// Serialise `statement` to JSON once, then sign those exact bytes.
pub fn sign_statement(statement: &Statement, key_path: &Utf8Path) -> Result<Envelope, SignError> {
    let payload = serde_json::to_vec(statement)?;
    sign_payload(&payload, key_path)
}

/// Sign arbitrary in-toto payload bytes (payload type [`PAYLOAD_TYPE`]) with
/// the key at `key_path`, read for this one signature ([`SshSigner`] reads it
/// once for many). `key_path` may be a private key, or a `.pub` whose
/// private half is held by ssh-agent. The produced signature is re-checked in
/// Rust before it is returned.
pub fn sign_payload(payload: &[u8], key_path: &Utf8Path) -> Result<Envelope, SignError> {
    SshSigner::load(key_path).sign_payload(payload)
}

/// `ssh-keygen -Y sign -n vci-attest -f <key>` with `message` on stdin: the
/// SSHSIG PEM text.
fn ssh_keygen_sign(message: &[u8], key_path: &Utf8Path) -> Result<String, SignError> {
    // A private key on disk is used as it is: ssh-keygen consults ssh-agent
    // first whenever SSH_AUTH_SOCK is set, and an agent that asks a person
    // to approve each signature (1Password's does) refuses an unattended
    // run (`agent refused operation`, `communication with agent failed`),
    // although the key file needs nobody. Only a `.pub` needs the agent.
    let private_key_on_disk = std::fs::read(key_path.as_std_path())
        .map(|b| b.starts_with(b"-----BEGIN"))
        .unwrap_or(false);
    let mut command = Command::new("ssh-keygen");
    if private_key_on_disk {
        command.env_remove("SSH_AUTH_SOCK");
    }
    let mut child = command
        .args(["-Y", "sign", "-n", NAMESPACE, "-f"])
        .arg(key_path.as_std_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Feed stdin from a thread so a large message can't deadlock against a
    // full stdout/stderr pipe.
    let mut stdin = child.stdin.take().expect("stdin piped");
    let message = message.to_vec();
    let writer = std::thread::spawn(move || {
        let r = stdin.write_all(&message);
        drop(stdin);
        r
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
    write_result?;
    String::from_utf8(stdout).map_err(|_| SignError::BadOutput("signature is not UTF-8".into()))
}

/// Check the SSHSIG `pem` over `message` (its namespace, and the signature
/// against the key it names), then wrap it with `payload` as an envelope.
fn envelope(payload: &[u8], message: &[u8], pem: String) -> Result<Envelope, SignError> {
    let sshsig = SshSig::from_pem(pem.as_bytes())
        .map_err(|e| SignError::BadOutput(format!("parse SSHSIG: {e}")))?;
    if sshsig.namespace() != NAMESPACE {
        return Err(SignError::BadOutput(format!(
            "unexpected namespace {:?}",
            sshsig.namespace()
        )));
    }
    let public = PublicKey::new(sshsig.public_key().clone(), "");
    public
        .verify(NAMESPACE, message, &sshsig)
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
