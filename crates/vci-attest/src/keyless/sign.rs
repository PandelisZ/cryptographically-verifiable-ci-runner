//! Keyless signing in a CI job: the job's OIDC token, an ephemeral P-256
//! key certified by Fulcio, and an RFC 3161 timestamp per signature.

use std::sync::Mutex;

use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::EncodePublicKey as _;
use sha2::Digest as _;

use super::identity::CertIdentity;
use super::x509::{self, Cert, EcKey};
use super::{
    BUNDLE_MEDIA_TYPE, RawBytes, Rfc3161Timestamp, SigstoreMaterial, TimestampVerificationData,
    VerificationMaterial, http,
};
use crate::{Envelope, PAYLOAD_TYPE, Signature, Statement, b64_encode, pae};

#[derive(Debug, thiserror::Error)]
pub enum KeylessError {
    #[error(
        "no OIDC token: the job needs `permissions: id-token: write` (ACTIONS_ID_TOKEN_REQUEST_URL is not set), or set SIGSTORE_ID_TOKEN"
    )]
    NoToken,
    #[error("OIDC token: {0}")]
    Token(String),
    #[error("Fulcio ({url}): {msg}")]
    Fulcio { url: String, msg: String },
    #[error("timestamp authority ({url}): {msg}")]
    Tsa { url: String, msg: String },
    #[error("serialising statement: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

/// Which Sigstore instance signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    pub fulcio: String,
    pub tsa: String,
}

impl Instance {
    /// GitHub's instance (`fulcio.githubapp.com`, `timestamp.githubapp.com`;
    /// on a GHE.com tenant `fulcio.<tenant>.ghe.com`), from `GITHUB_SERVER_URL`.
    pub fn github() -> Self {
        let server =
            std::env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".into());
        let host = server
            .split_once("://")
            .map(|(_, h)| h)
            .unwrap_or(&server)
            .trim_end_matches('/');
        let host = if host == "github.com" || host.is_empty() {
            "githubapp.com"
        } else {
            host
        };
        Self {
            fulcio: format!("https://fulcio.{host}"),
            tsa: format!("https://timestamp.{host}"),
        }
    }

    /// The public-good instance (`fulcio.sigstore.dev`, `timestamp.sigstore.dev`).
    pub fn public_good() -> Self {
        Self {
            fulcio: "https://fulcio.sigstore.dev".into(),
            tsa: "https://timestamp.sigstore.dev".into(),
        }
    }

    /// `github` or `public-good`, then `VCI_FULCIO_URL` / `VCI_TSA_URL`
    /// override either endpoint.
    pub fn named(name: &str) -> Result<Self, String> {
        let mut i = match name {
            "github" => Self::github(),
            "public-good" => Self::public_good(),
            o => {
                return Err(format!(
                    "unknown Sigstore instance {o:?} (github, public-good)"
                ));
            }
        };
        if let Ok(u) = std::env::var("VCI_FULCIO_URL")
            && !u.is_empty()
        {
            i.fulcio = u;
        }
        if let Ok(u) = std::env::var("VCI_TSA_URL")
            && !u.is_empty()
        {
            i.tsa = u;
        }
        Ok(i)
    }
}

/// An ephemeral key and the certificate Fulcio issued for it.
struct Certified {
    key: p256::ecdsa::SigningKey,
    leaf_der: Vec<u8>,
    not_after: i64,
}

/// Signs statements keylessly. Obtains a token at creation (so a job
/// without `id-token: write` fails before anything runs), and a Fulcio
/// certificate on first use, reused while it is valid for another minute.
pub struct KeylessSigner {
    instance: Instance,
    identity: CertIdentity,
    certified: Mutex<Option<Certified>>,
}

/// Request the job's OIDC token for audience `sigstore`.
fn fetch_token() -> Result<String, KeylessError> {
    if let Ok(t) = std::env::var("SIGSTORE_ID_TOKEN")
        && !t.trim().is_empty()
    {
        return Ok(t.trim().to_owned());
    }
    let url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").unwrap_or_default();
    let bearer = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").unwrap_or_default();
    if url.is_empty() || bearer.is_empty() {
        return Err(KeylessError::NoToken);
    }
    let sep = if url.contains('?') { '&' } else { '?' };
    let url = format!("{url}{sep}audience=sigstore");
    let auth = format!("bearer {bearer}");
    let (code, body) = http::request(
        &url,
        &[("Accept", "application/json"), ("Authorization", &auth)],
        None,
    )
    .map_err(KeylessError::Token)?;
    if code != 200 {
        return Err(KeylessError::Token(format!(
            "{} answered HTTP {code}",
            http::url_for_messages(&url)
        )));
    }
    let v: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| KeylessError::Token(format!("response: {e}")))?;
    v.get("value")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| KeylessError::Token("response has no value".into()))
}

/// The claims of a JWT (its payload, not verified: only Fulcio's certificate
/// is trusted, and Fulcio verifies the token).
pub fn token_claims(jwt: &str) -> Result<serde_json::Value, String> {
    let payload = jwt.split('.').nth(1).ok_or("not a JWT")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|e| format!("JWT payload base64: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("JWT payload: {e}"))
}

fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

impl KeylessSigner {
    pub fn new(instance: Instance) -> Result<Self, KeylessError> {
        let token = fetch_token()?;
        let claims = token_claims(&token).map_err(KeylessError::Token)?;
        let identity = CertIdentity::from_claims(&claims).map_err(KeylessError::Token)?;
        Ok(Self {
            instance,
            identity,
            certified: Mutex::new(None),
        })
    }

    /// The job's identity, from its token's claims.
    pub fn identity(&self) -> &CertIdentity {
        &self.identity
    }

    pub fn instance(&self) -> &Instance {
        &self.instance
    }

    /// Store key signer id (see [`CertIdentity::signer_id`]).
    pub fn signer_id(&self) -> String {
        self.identity.signer_id()
    }

    fn certify(&self) -> Result<Certified, KeylessError> {
        let token = fetch_token()?;
        let claims = token_claims(&token).map_err(KeylessError::Token)?;
        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KeylessError::Token("the token has no sub claim".into()))?;
        let key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let public = key.verifying_key();
        let pem = public
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .map_err(|e| KeylessError::Other(format!("public key PEM: {e}")))?;
        let pop: p256::ecdsa::Signature = key.sign(sub.as_bytes());
        let body = serde_json::json!({
            "credentials": {"oidcIdentityToken": token},
            "publicKeyRequest": {
                "publicKey": {"algorithm": "ECDSA", "content": pem},
                "proofOfPossession": b64_encode(pop.to_der().as_bytes()),
            },
        });
        let url = format!("{}/api/v2/signingCert", self.instance.fulcio);
        let fulcio = |msg: String| KeylessError::Fulcio {
            url: url.clone(),
            msg,
        };
        let (code, resp) = http::request(
            &url,
            &[
                ("Content-Type", "application/json"),
                ("Accept", "application/json"),
            ],
            Some(body.to_string().as_bytes()),
        )
        .map_err(fulcio)?;
        if code != 200 && code != 201 {
            return Err(fulcio(format!(
                "HTTP {code}: {}",
                String::from_utf8_lossy(&resp)
                    .chars()
                    .take(500)
                    .collect::<String>()
            )));
        }
        let v: serde_json::Value =
            serde_json::from_slice(&resp).map_err(|e| fulcio(format!("response: {e}")))?;
        let chain = v
            .get("signedCertificateEmbeddedSct")
            .or_else(|| v.get("signedCertificateDetachedSct"))
            .and_then(|c| c.pointer("/chain/certificates/0"))
            .and_then(|c| c.as_str())
            .ok_or_else(|| fulcio("response has no certificate chain".into()))?;
        let leaf_der = x509::pem_to_der(chain).map_err(fulcio)?;
        let leaf = Cert::parse(&leaf_der).map_err(fulcio)?;
        match leaf.key().map_err(fulcio)? {
            EcKey::P256(k) if &k == public => {}
            _ => return Err(fulcio("the certificate is for another key".into())),
        }
        Ok(Certified {
            key,
            leaf_der,
            not_after: leaf.not_after(),
        })
    }

    fn timestamp(&self, sig: &[u8]) -> Result<Vec<u8>, KeylessError> {
        let url = format!("{}/api/v1/timestamp", self.instance.tsa);
        let tsa = |msg: String| KeylessError::Tsa {
            url: url.clone(),
            msg,
        };
        let body = serde_json::json!({
            "artifactHash": b64_encode(&sha2::Sha256::digest(sig)),
            "hashAlgorithm": "sha256",
        });
        let (code, resp) = http::request(
            &url,
            &[("Content-Type", "application/json")],
            Some(body.to_string().as_bytes()),
        )
        .map_err(tsa)?;
        if code != 200 && code != 201 {
            return Err(tsa(format!(
                "HTTP {code}: {}",
                String::from_utf8_lossy(&resp)
                    .chars()
                    .take(500)
                    .collect::<String>()
            )));
        }
        Ok(resp)
    }

    /// Serialise `statement` once and sign those bytes.
    pub fn sign_statement(
        &self,
        statement: &Statement,
    ) -> Result<(Envelope, SigstoreMaterial), KeylessError> {
        let payload = serde_json::to_vec(statement)?;
        self.sign_payload(&payload)
    }

    /// Sign in-toto payload bytes: DSSE envelope plus its Sigstore material.
    pub fn sign_payload(
        &self,
        payload: &[u8],
    ) -> Result<(Envelope, SigstoreMaterial), KeylessError> {
        let (sig, leaf_der) = {
            let mut guard = self
                .certified
                .lock()
                .map_err(|_| KeylessError::Other("signer lock poisoned".into()))?;
            if guard.as_ref().is_none_or(|c| c.not_after - now() < 60) {
                *guard = Some(self.certify()?);
            }
            let c = guard.as_ref().expect("just set");
            let sig: p256::ecdsa::Signature = c.key.sign(&pae(PAYLOAD_TYPE, payload));
            (sig.to_der().as_bytes().to_vec(), c.leaf_der.clone())
        };
        let ts = self.timestamp(&sig)?;
        Ok((
            Envelope {
                payload_type: PAYLOAD_TYPE.to_string(),
                payload: b64_encode(payload),
                signatures: vec![Signature {
                    keyid: String::new(),
                    sig: b64_encode(&sig),
                }],
            },
            SigstoreMaterial {
                media_type: BUNDLE_MEDIA_TYPE.into(),
                verification_material: VerificationMaterial {
                    certificate: Some(RawBytes {
                        raw_bytes: b64_encode(&leaf_der),
                    }),
                    x509_certificate_chain: None,
                    tlog_entries: vec![],
                    timestamp_verification_data: Some(TimestampVerificationData {
                        rfc3161_timestamps: vec![Rfc3161Timestamp {
                            signed_timestamp: b64_encode(&ts),
                        }],
                    }),
                },
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_claims_decode_without_padding() {
        let p =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"sub":"repo:a/b:ref:x"}"#);
        let c = token_claims(&format!("eyJhbGciOiJub25lIn0.{p}.sig")).unwrap();
        assert_eq!(c["sub"], "repo:a/b:ref:x");
        assert!(token_claims("nodots").is_err());
    }

    #[test]
    fn instances() {
        assert_eq!(
            Instance::public_good().fulcio,
            "https://fulcio.sigstore.dev"
        );
        assert!(Instance::named("other").is_err());
    }
}
