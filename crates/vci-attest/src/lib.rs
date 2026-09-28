//! in-toto Statement v1 + DSSE envelopes signed with SSH keys (SSHSIG).
//!
//! * Signing shells out to `ssh-keygen -Y sign` so that ssh-agent and
//!   hardware-backed keys work.
//! * Verification is pure Rust (`ssh-key`), checks the SSHSIG over the DSSE
//!   PAE of the *exact stored payload bytes* (never re-serialised), and
//!   authorises the signer against an OpenSSH `allowed_signers` file.
//!
//! Everything here is fail-closed with respect to trust: any doubt produces an
//! error, which callers turn into "run the test".

mod allowed_signers;
mod sign;
mod verify;

use std::collections::BTreeMap;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

pub use allowed_signers::{AllowedSigner, AllowedSigners, AllowedSignersError};
pub use sign::{SignError, sign_payload, sign_statement};
pub use verify::{Verified, VerifyError, verify_envelope};

/// DSSE payload type for in-toto statements.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// SSHSIG namespace used for every signature produced or accepted here.
pub const NAMESPACE: &str = "vci-attest";
/// in-toto Statement v1 `_type`.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// in-toto resource descriptor (subset: name + digest).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

/// in-toto Statement v1.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Statement {
    #[serde(rename = "_type")]
    pub type_: String,
    pub subject: Vec<Subject>,
    pub predicate_type: String,
    pub predicate: serde_json::Value,
}

impl Statement {
    /// Build a Statement v1 with `_type` set to [`STATEMENT_TYPE`].
    pub fn new(
        subject: Vec<Subject>,
        predicate_type: impl Into<String>,
        predicate: serde_json::Value,
    ) -> Self {
        Self {
            type_: STATEMENT_TYPE.to_string(),
            subject,
            predicate_type: predicate_type.into(),
            predicate,
        }
    }
}

/// One DSSE signature. `sig` is standard base64 of the SSHSIG PEM armor
/// (`-----BEGIN SSH SIGNATURE-----` ...). `keyid` is the signer's
/// `SHA256:` fingerprint; it is a hint only and is never trusted.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub keyid: String,
    pub sig: String,
}

/// DSSE envelope. `payload` is standard (padded) base64.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub payload_type: String,
    pub payload: String,
    #[serde(default)]
    pub signatures: Vec<Signature>,
}

impl Envelope {
    /// Parse an envelope from its JSON encoding.
    pub fn from_json(bytes: &[u8]) -> Result<Self, VerifyError> {
        serde_json::from_slice(bytes)
            .map_err(|e| VerifyError::Malformed(format!("envelope json: {e}")))
    }

    /// Serialise the envelope as JSON (the envelope itself is not signed;
    /// only the payload bytes inside it are).
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("envelope serialisation cannot fail")
    }

    /// Decode the raw payload bytes (strict standard base64).
    pub fn payload_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        b64_decode(&self.payload)
            .map_err(|e| VerifyError::Malformed(format!("payload base64: {e}")))
    }
}

/// DSSE v1 Pre-Authentication Encoding:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, LEN in ASCII decimal.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let t = payload_type.as_bytes();
    let mut out = Vec::with_capacity(32 + t.len() + payload.len());
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(t.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(t);
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_dsse_spec_vector() {
        // Test vector from the DSSE protocol spec.
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
        assert_eq!(pae("", b""), b"DSSEv1 0  0 ".to_vec());
    }

    #[test]
    fn statement_json_field_names() {
        let mut digest = BTreeMap::new();
        digest.insert("blake3".to_string(), "ab".to_string());
        let s = Statement::new(
            vec![Subject {
                name: "t".into(),
                digest,
            }],
            "https://vci.dev/test-attestation/v1",
            serde_json::json!({"x": 1}),
        );
        let v: serde_json::Value = serde_json::to_value(&s).unwrap();
        assert_eq!(v["_type"], STATEMENT_TYPE);
        assert_eq!(v["predicateType"], "https://vci.dev/test-attestation/v1");
        assert_eq!(v["subject"][0]["digest"]["blake3"], "ab");
        let back: Statement = serde_json::from_value(v).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn envelope_json_field_names() {
        let e = Envelope {
            payload_type: PAYLOAD_TYPE.into(),
            payload: b64_encode(b"{}"),
            signatures: vec![Signature {
                keyid: "k".into(),
                sig: "s".into(),
            }],
        };
        let v: serde_json::Value = serde_json::from_slice(&e.to_json()).unwrap();
        assert_eq!(v["payloadType"], PAYLOAD_TYPE);
        assert_eq!(v["signatures"][0]["keyid"], "k");
        assert_eq!(Envelope::from_json(&e.to_json()).unwrap(), e);
    }

    #[test]
    fn payload_base64_is_strict() {
        let mut e = Envelope {
            payload_type: PAYLOAD_TYPE.into(),
            payload: "e30".into(),
            signatures: vec![],
        };
        assert!(
            e.payload_bytes().is_err(),
            "unpadded base64 must be rejected"
        );
        e.payload = "e30=".into();
        assert_eq!(e.payload_bytes().unwrap(), b"{}");
    }
}
