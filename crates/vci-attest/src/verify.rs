//! Pure-Rust DSSE + SSHSIG verification.

use ssh_key::{Algorithm, HashAlg, PublicKey, SshSig};

use crate::{
    AllowedSigners, Envelope, NAMESPACE, PAYLOAD_TYPE, STATEMENT_TYPE, Statement, b64_decode, pae,
};

/// Result of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// Principals field of the allowed_signers entry that authorised the key.
    pub principal: String,
    /// `SHA256:...` fingerprint of the signing key.
    pub fingerprint: String,
    /// Statement parsed from `payload` (after the signature was checked).
    pub statement: Statement,
    /// The exact payload bytes the signature covers.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed envelope: {0}")]
    Malformed(String),
    #[error("wrong payload type {0:?}")]
    WrongPayloadType(String),
    #[error("bad signature: {0}")]
    BadSignature(String),
    #[error("wrong namespace: {0}")]
    WrongNamespace(String),
    #[error("signer {0} is not in allowed_signers")]
    UnknownSigner(String),
    #[error("signer {0} is not valid at this time")]
    SignerNotValidNow(String),
    #[error("envelope has no signatures")]
    NoSignatures,
    /// The key only appears on `cert-authority` lines, which v1 rejects.
    #[error("signer {0} is only listed as a cert-authority, which is not supported")]
    CertAuthorityRejected(String),
}

/// Verify `envelope` against `allowed` at unix time `now`.
///
/// Order of checks: payload type, payload base64, presence of signatures, then
/// per signature: SSHSIG decoding, version, namespace, hash algorithm,
/// signature over `PAE(payloadType, payload)`, and signer authorisation
/// (non-cert-authority entry with that exact key, namespaces allowing
/// [`NAMESPACE`], valid-after/valid-before honoured). The first signature that
/// passes every check wins; otherwise the first signature's error is returned.
/// Only then is the payload parsed as an in-toto Statement v1.
///
/// The signature is checked over the decoded stored bytes; nothing is ever
/// re-serialised before verification.
pub fn verify_envelope(
    envelope: &Envelope,
    allowed: &AllowedSigners,
    now: i64,
) -> Result<Verified, VerifyError> {
    if envelope.payload_type != PAYLOAD_TYPE {
        return Err(VerifyError::WrongPayloadType(envelope.payload_type.clone()));
    }
    let payload = envelope.payload_bytes()?;
    if envelope.signatures.is_empty() {
        return Err(VerifyError::NoSignatures);
    }
    let message = pae(&envelope.payload_type, &payload);

    let mut first_err = None;
    for sig in &envelope.signatures {
        match verify_one(&sig.sig, &message, allowed, now) {
            Ok((principal, fingerprint)) => {
                let statement: Statement = serde_json::from_slice(&payload)
                    .map_err(|e| VerifyError::Malformed(format!("statement json: {e}")))?;
                if statement.type_ != STATEMENT_TYPE {
                    return Err(VerifyError::Malformed(format!(
                        "unsupported statement _type {:?}",
                        statement.type_
                    )));
                }
                return Ok(Verified {
                    principal,
                    fingerprint,
                    statement,
                    payload,
                });
            }
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    Err(first_err.expect("at least one signature"))
}

fn verify_one(
    sig_b64: &str,
    message: &[u8],
    allowed: &AllowedSigners,
    now: i64,
) -> Result<(String, String), VerifyError> {
    let pem = b64_decode(sig_b64)
        .map_err(|e| VerifyError::Malformed(format!("signature base64: {e}")))?;
    let sshsig =
        SshSig::from_pem(&pem).map_err(|e| VerifyError::Malformed(format!("SSHSIG: {e}")))?;

    if sshsig.version() != SshSig::VERSION {
        return Err(VerifyError::Malformed(format!(
            "SSHSIG version {}",
            sshsig.version()
        )));
    }
    if sshsig.namespace() != NAMESPACE {
        return Err(VerifyError::WrongNamespace(format!(
            "signature namespace {:?}, expected {NAMESPACE:?}",
            sshsig.namespace()
        )));
    }
    // ssh-key only decodes sha256/sha512, but keep the allowlist explicit.
    match sshsig.hash_alg() {
        HashAlg::Sha512 | HashAlg::Sha256 => {}
        #[allow(unreachable_patterns)]
        other => {
            return Err(VerifyError::BadSignature(format!(
                "hash algorithm {other} not allowed"
            )));
        }
    }
    // OpenSSH refuses SHA-1 RSA signatures in SSHSIG; so do we.
    if matches!(sshsig.algorithm(), Algorithm::Rsa { hash: None }) {
        return Err(VerifyError::BadSignature(
            "ssh-rsa (SHA-1) signatures are not allowed".into(),
        ));
    }

    let key_data = sshsig.public_key().clone();
    let fingerprint = key_data.fingerprint(HashAlg::Sha256).to_string();
    let public = PublicKey::new(key_data.clone(), "");
    public
        .verify(NAMESPACE, message, &sshsig)
        .map_err(|e| VerifyError::BadSignature(e.to_string()))?;

    // Authorisation.
    let mut matching = allowed
        .entries()
        .iter()
        .filter(|e| e.key.key_data() == &key_data)
        .peekable();
    if matching.peek().is_none() {
        return Err(VerifyError::UnknownSigner(fingerprint));
    }
    let mut err = None;
    let mut saw_plain = false;
    for entry in matching {
        if entry.cert_authority {
            continue;
        }
        saw_plain = true;
        if !entry.allows_namespace(NAMESPACE) {
            err.get_or_insert(VerifyError::WrongNamespace(format!(
                "allowed_signers line {} restricts {fingerprint} to namespaces {:?}",
                entry.line,
                entry.namespaces.as_deref().unwrap_or("")
            )));
            continue;
        }
        if !entry.valid_at(now) {
            err.get_or_insert(VerifyError::SignerNotValidNow(format!(
                "{fingerprint} (allowed_signers line {})",
                entry.line
            )));
            continue;
        }
        return Ok((entry.principals.clone(), fingerprint));
    }
    if !saw_plain {
        return Err(VerifyError::CertAuthorityRejected(fingerprint));
    }
    Err(err.expect("a plain entry failed a check"))
}
