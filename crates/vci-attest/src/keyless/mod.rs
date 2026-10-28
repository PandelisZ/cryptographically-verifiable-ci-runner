//! Keyless signing and verification (Sigstore: an ephemeral key certified by
//! Fulcio from a CI job's OIDC token, plus an RFC 3161 timestamp).
//!
//! The stored form is vci's DSSE envelope JSON (`payloadType`, `payload`,
//! `signatures`, the signature a DER ECDSA signature over the PAE) plus a
//! top-level `sigstore` member: a Sigstore bundle without its
//! `dsseEnvelope` (`mediaType`, `verificationMaterial` with the certificate
//! and the timestamps). Putting the envelope's fields back as `dsseEnvelope`
//! gives a standard v0.3 bundle.
//!
//! Verification is offline and pure Rust: the certificate chains to a
//! certificate authority of the trust root, a timestamp authority of the
//! trust root vouches for the signature at a time inside the certificate's
//! validity, the signature verifies over the PAE, and the certificate's
//! identity matches an `[[identity]]` of `.vci/identities.toml`, whose
//! principal is the signer.

mod http;
mod identity;
mod root;
mod sign;
mod tsa;
mod x509;

use serde::{Deserialize, Serialize};

use crate::{
    Envelope, PAYLOAD_TYPE, STATEMENT_TYPE, Statement, Verified, VerifyError, b64_decode, pae,
};

pub use identity::{CertIdentity, IDENTITIES_FILE, Identities, IdentityRule, glob_match};
pub use root::{TRUSTED_ROOT_FILE, TrustedRoot};
pub use sign::{Instance, KeylessError, KeylessSigner, token_claims};
pub use tsa::{Timestamp, verify_timestamp};

pub use vci_core::frame::{
    BUNDLE_MEDIA_TYPE, CertificateChain, RawBytes, Rfc3161Timestamp, SigstoreMaterial,
    TimestampVerificationData, VerificationMaterial,
};

/// Clock skew allowed between a timestamp and the verifier's clock.
const FUTURE_SKEW: i64 = 300;

/// The DER of the bundle's leaf certificate (v0.3 `certificate`, else the
/// first of a v0.1/v0.2 chain).
fn leaf_der(material: &SigstoreMaterial) -> Result<Vec<u8>, String> {
    let vm = &material.verification_material;
    let raw = match (&vm.certificate, &vm.x509_certificate_chain) {
        (Some(c), _) => &c.raw_bytes,
        (None, Some(ch)) => {
            &ch.certificates
                .first()
                .ok_or("empty x509CertificateChain")?
                .raw_bytes
        }
        (None, None) => return Err("the bundle has no certificate".into()),
    };
    b64_decode(raw).map_err(|e| format!("certificate base64: {e}"))
}

/// The stored JSON: the envelope's fields plus `sigstore`.
#[derive(Serialize)]
struct StoredRef<'a> {
    #[serde(flatten)]
    envelope: &'a Envelope,
    sigstore: &'a SigstoreMaterial,
}

#[derive(Deserialize)]
struct SigstoreOnly {
    #[serde(default)]
    sigstore: Option<serde_json::Value>,
}

/// Serialise a keylessly signed envelope for the store.
pub fn to_stored_json(envelope: &Envelope, material: &SigstoreMaterial) -> Vec<u8> {
    serde_json::to_vec(&StoredRef {
        envelope,
        sigstore: material,
    })
    .expect("envelope serialisation cannot fail")
}

/// The `sigstore` member of stored envelope JSON: `Ok(None)` for an
/// envelope without one (SSH-signed), an error for one that does not parse.
pub fn material_from_json(bytes: &[u8]) -> Result<Option<SigstoreMaterial>, VerifyError> {
    let s: SigstoreOnly = serde_json::from_slice(bytes)
        .map_err(|e| VerifyError::Malformed(format!("envelope json: {e}")))?;
    s.sigstore
        .map(|v| {
            serde_json::from_value(v)
                .map_err(|e| VerifyError::Malformed(format!("sigstore bundle: {e}")))
        })
        .transpose()
}

/// A standard Sigstore bundle (v0.3 JSON) for `envelope` + `material`,
/// for `gh attestation verify --bundle` or cosign.
pub fn to_bundle_json(envelope: &Envelope, material: &SigstoreMaterial) -> serde_json::Value {
    let mut v = serde_json::to_value(material).expect("serialisable");
    v["dsseEnvelope"] = serde_json::to_value(envelope).expect("serialisable");
    v
}

/// What keyless verification established besides the principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeylessVerified {
    pub verified: Verified,
    pub identity: CertIdentity,
    pub timestamp: Timestamp,
}

/// Verify a keylessly signed envelope (see the module docs) at unix time
/// `now`. The returned [`Verified`]'s `fingerprint` describes the identity
/// (`oidc repo:... workflow:... ref:... event:...`).
pub fn verify_keyless(
    envelope: &Envelope,
    material: &SigstoreMaterial,
    identities: &Identities,
    root: &TrustedRoot,
    now: i64,
) -> Result<KeylessVerified, VerifyError> {
    if envelope.payload_type != PAYLOAD_TYPE {
        return Err(VerifyError::WrongPayloadType(envelope.payload_type.clone()));
    }
    if !material
        .media_type
        .starts_with("application/vnd.dev.sigstore.bundle")
    {
        return Err(VerifyError::Malformed(format!(
            "sigstore mediaType {:?}",
            material.media_type
        )));
    }
    let payload = envelope.payload_bytes()?;
    let sig = match envelope.signatures.as_slice() {
        [] => return Err(VerifyError::NoSignatures),
        [one] => b64_decode(&one.sig)
            .map_err(|e| VerifyError::Malformed(format!("signature base64: {e}")))?,
        _ => {
            return Err(VerifyError::Malformed(
                "a keyless envelope has exactly one signature".into(),
            ));
        }
    };
    let leaf = leaf_der(material)
        .and_then(|d| x509::Cert::parse(&d))
        .map_err(VerifyError::Malformed)?;

    // The signature, with the certified key.
    let key = leaf
        .key()
        .map_err(|e| VerifyError::BadSignature(format!("certificate key: {e}")))?;
    key.verify(
        &key.default_alg(),
        &pae(&envelope.payload_type, &payload),
        &sig,
    )
    .map_err(VerifyError::BadSignature)?;

    // When: a trusted timestamp over the signature.
    let stamps = material
        .verification_material
        .timestamp_verification_data
        .as_ref()
        .map(|t| t.rfc3161_timestamps.as_slice())
        .unwrap_or_default();
    if stamps.is_empty() {
        return Err(VerifyError::Untrusted(
            "the bundle has no RFC 3161 timestamp (vci does not use transparency log entries)"
                .into(),
        ));
    }
    let mut ts_err = String::new();
    let mut timestamp = None;
    for s in stamps {
        let r = b64_decode(&s.signed_timestamp)
            .map_err(|e| format!("timestamp base64: {e}"))
            .and_then(|der| verify_timestamp(&der, &sig, root));
        match r {
            Ok(t) => {
                timestamp = Some(t);
                break;
            }
            Err(e) => {
                if ts_err.is_empty() {
                    ts_err = e;
                }
            }
        }
    }
    let timestamp =
        timestamp.ok_or_else(|| VerifyError::Untrusted(format!("timestamp: {ts_err}")))?;
    let t = timestamp.time;
    if t > now + FUTURE_SKEW {
        return Err(VerifyError::Untrusted(format!(
            "the timestamp ({}) is in the future",
            fmt_time(t)
        )));
    }
    if t < leaf.not_before() || t > leaf.not_after() {
        return Err(VerifyError::Untrusted(format!(
            "signed at {} (timestamp by {}), outside the certificate's validity {} .. {}",
            fmt_time(t),
            timestamp.authority,
            fmt_time(leaf.not_before()),
            fmt_time(leaf.not_after())
        )));
    }

    // Who: the certificate chains to a certificate authority of the trust root.
    let mut chain_err = format!(
        "the certificate's issuer ({}) is no certificate authority of the trust root (refresh .vci/sigstore-trusted-root.json with `gh attestation trusted-root`)",
        leaf.issuer()
    );
    let mut chained = false;
    for ca in &root.certificate_authorities {
        let Some(issuer) = ca.chain.first() else {
            continue;
        };
        if leaf.issuer_der() != issuer.subject_der() {
            continue;
        }
        if let Err(e) = leaf.issued_by(issuer) {
            chain_err = format!("{}: {e}", ca.uri);
            continue;
        }
        if !ca.valid_for.contains(t) {
            chain_err = format!(
                "signed at {}, outside the trust root's validFor of {} ({})",
                fmt_time(t),
                ca.uri,
                issuer.subject()
            );
            continue;
        }
        if let Some(bad) = ca
            .chain
            .iter()
            .find(|c| t < c.not_before() || t > c.not_after())
        {
            chain_err = format!(
                "signed at {}, outside the validity of {}",
                fmt_time(t),
                bad.subject()
            );
            continue;
        }
        if let Err(e) = tsa::chain_ok(&ca.chain) {
            chain_err = e;
            continue;
        }
        chained = true;
        break;
    }
    if !chained {
        return Err(VerifyError::Untrusted(chain_err));
    }
    if !leaf.has_code_signing() {
        return Err(VerifyError::Untrusted(
            "the certificate is not for code signing".into(),
        ));
    }

    // Which principal.
    let identity = CertIdentity::from_cert(&leaf).map_err(VerifyError::Untrusted)?;
    let rule = identities.matching(&identity).ok_or_else(|| {
        VerifyError::UnknownIdentity(format!(
            "identity {} (issuer {}) matches no [[identity]] in {IDENTITIES_FILE}",
            identity.describe(),
            identity.issuer
        ))
    })?;

    let statement: Statement = serde_json::from_slice(&payload)
        .map_err(|e| VerifyError::Malformed(format!("statement json: {e}")))?;
    if statement.type_ != STATEMENT_TYPE {
        return Err(VerifyError::Malformed(format!(
            "unsupported statement _type {:?}",
            statement.type_
        )));
    }
    Ok(KeylessVerified {
        verified: Verified {
            principal: rule.principal.clone(),
            fingerprint: format!("oidc {}", identity.describe()),
            statement,
            payload,
        },
        identity,
        timestamp,
    })
}

fn fmt_time(t: i64) -> String {
    jiff::Timestamp::from_second(t)
        .map(|t| t.to_string())
        .unwrap_or_else(|_| t.to_string())
}
