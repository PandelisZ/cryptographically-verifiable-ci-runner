//! A minimal ssh-agent client: SSHSIG signatures over `$SSH_AUTH_SOCK`
//! (draft-miller-ssh-agent, `SSH_AGENTC_SIGN_REQUEST`), so that a key held
//! by the agent signs without an `ssh-keygen` process per signature.
//!
//! It asks exactly what `ssh-keygen -Y sign` asks (the SSHSIG signed data,
//! sha512, `rsa-sha2-512` for RSA), and connections are kept and reused.
//! Any failure is `None`: the caller then runs ssh-keygen, which reports
//! it as before. After one failure the agent is not asked again.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use ssh_key::{Algorithm, LineEnding, PublicKey, Signature, SshSig};

use crate::NAMESPACE;

const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
/// `SSH_AGENT_RSA_SHA2_512`: an `rsa-sha2-512` signature, as ssh-keygen asks.
const RSA_SHA2_512: u32 = 4;
/// Larger answers are not signatures.
const MAX_ANSWER: usize = 256 * 1024;

pub(crate) struct Agent {
    sock: PathBuf,
    key: PublicKey,
    blob: Vec<u8>,
    idle: Mutex<Vec<UnixStream>>,
    failed: AtomicBool,
}

impl Agent {
    /// The agent at `$SSH_AUTH_SOCK`, for `key`; `None` without one.
    pub(crate) fn new(key: PublicKey) -> Option<Agent> {
        let sock = std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty())?;
        let blob = key.to_bytes().ok()?;
        Some(Agent {
            sock: PathBuf::from(sock),
            key,
            blob,
            idle: Mutex::new(Vec::new()),
            failed: AtomicBool::new(false),
        })
    }

    /// The SSHSIG PEM text of `message` in vci's namespace, made by the agent.
    pub(crate) fn sign(&self, message: &[u8]) -> Option<String> {
        if self.failed.load(Ordering::Relaxed) {
            return None;
        }
        let pem = self.try_sign(message);
        if pem.is_none() {
            self.failed.store(true, Ordering::Relaxed);
        }
        pem
    }

    /// Whether a signature failed (the agent is not asked again).
    pub(crate) fn has_failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    fn try_sign(&self, message: &[u8]) -> Option<String> {
        let data = SshSig::signed_data(NAMESPACE, super::sign::HASH, message).ok()?;
        let flags = match self.key.algorithm() {
            Algorithm::Rsa { .. } => RSA_SHA2_512,
            _ => 0,
        };
        let mut request = vec![SIGN_REQUEST];
        put_string(&mut request, &self.blob);
        put_string(&mut request, &data);
        request.extend_from_slice(&flags.to_be_bytes());

        let idle = self.idle.lock().ok()?.pop();
        let mut stream = match idle {
            Some(s) => s,
            None => UnixStream::connect(&self.sock).ok()?,
        };
        let answer = exchange(&mut stream, &request)?;
        let (&kind, rest) = answer.split_first()?;
        if kind != SIGN_RESPONSE {
            return None;
        }
        let (blob, _) = take_string(rest)?;
        // The algorithm and the signature, and for a security key the flags
        // and counter after them, which ssh-key's decoding keeps.
        let signature = Signature::try_from(blob).ok()?;
        let sshsig = SshSig::new(
            self.key.key_data().clone(),
            NAMESPACE,
            super::sign::HASH,
            signature,
        )
        .ok()?;
        let pem = sshsig.to_pem(LineEnding::LF).ok()?;
        if let Ok(mut idle) = self.idle.lock() {
            idle.push(stream);
        }
        Some(pem)
    }
}

/// Send one framed request and read one framed answer.
fn exchange(stream: &mut UnixStream, request: &[u8]) -> Option<Vec<u8>> {
    let len = u32::try_from(request.len()).ok()?;
    let mut framed = Vec::with_capacity(4 + request.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(request);
    stream.write_all(&framed).ok()?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).ok()?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_ANSWER {
        return None;
    }
    let mut answer = vec![0u8; len];
    stream.read_exact(&mut answer).ok()?;
    Some(answer)
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// An SSH `string` at the start of `b`, and what follows it.
fn take_string(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = b.split_first_chunk::<4>()?;
    let len = u32::from_be_bytes(*len) as usize;
    (rest.len() >= len).then(|| rest.split_at(len))
}
