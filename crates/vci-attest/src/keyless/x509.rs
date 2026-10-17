//! The few X.509 and ECDSA operations keyless verification needs: parse a
//! certificate, check a signature made by its key, check that one certificate
//! issued another, and read Fulcio's identity extensions.

use der::asn1::{ObjectIdentifier, Utf8StringRef};
use der::{Any, Decode as _, Encode as _, Reader as _, SliceReader};
use sha2::Digest as _;
use x509_cert::Certificate;

const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
pub(crate) const ECDSA_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub(crate) const ECDSA_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
pub(crate) const ECDSA_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
pub(crate) const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub(crate) const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
pub(crate) const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const KP_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

/// Fulcio certificate extensions (`docs/oid-info.md` in sigstore/fulcio).
pub(crate) mod fulcio {
    use der::asn1::ObjectIdentifier;
    pub const ISSUER_V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");
    pub const ISSUER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.8");
    pub const BUILD_SIGNER_URI: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.9");
    pub const RUNNER_ENVIRONMENT: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.11");
    pub const SOURCE_REPOSITORY_URI: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.12");
    pub const SOURCE_REPOSITORY_DIGEST: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.13");
    pub const SOURCE_REPOSITORY_REF: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.14");
    pub const BUILD_TRIGGER: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.20");
    pub const RUN_INVOCATION_URI: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.21");
    pub const DEPLOYMENT_ENVIRONMENT: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.23");
}

/// A parsed certificate plus the exact bytes its issuer signed.
pub(crate) struct Cert {
    pub cert: Certificate,
    pub tbs_raw: Vec<u8>,
}

/// An ECDSA public key on one of the two curves Sigstore uses.
#[derive(Clone)]
pub(crate) enum EcKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
}

impl Cert {
    pub fn parse(der_bytes: &[u8]) -> Result<Self, String> {
        let cert = Certificate::from_der(der_bytes).map_err(|e| format!("certificate: {e}"))?;
        // The signed part, byte for byte (never re-encoded from the parse).
        let mut r = SliceReader::new(der_bytes).map_err(|e| format!("certificate: {e}"))?;
        let tbs_raw = r
            .sequence(|r| {
                let tbs: Any = r.decode()?;
                let _alg: Any = r.decode()?;
                let _sig: Any = r.decode()?;
                tbs.to_der()
            })
            .map_err(|e| format!("certificate: {e}"))?;
        Ok(Self { cert, tbs_raw })
    }

    pub fn not_before(&self) -> i64 {
        self.cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs() as i64
    }

    pub fn not_after(&self) -> i64 {
        self.cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs() as i64
    }

    pub fn subject_der(&self) -> Vec<u8> {
        self.cert
            .tbs_certificate
            .subject
            .to_der()
            .unwrap_or_default()
    }

    pub fn issuer_der(&self) -> Vec<u8> {
        self.cert
            .tbs_certificate
            .issuer
            .to_der()
            .unwrap_or_default()
    }

    pub fn subject(&self) -> String {
        self.cert.tbs_certificate.subject.to_string()
    }

    pub fn issuer(&self) -> String {
        self.cert.tbs_certificate.issuer.to_string()
    }

    pub fn serial(&self) -> &[u8] {
        self.cert.tbs_certificate.serial_number.as_bytes()
    }

    pub fn key(&self) -> Result<EcKey, String> {
        let spki = &self.cert.tbs_certificate.subject_public_key_info;
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(format!(
                "public key algorithm {} is not ECDSA",
                spki.algorithm.oid
            ));
        }
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
            .ok_or("ECDSA key without a named curve")?;
        let point = spki.subject_public_key.raw_bytes();
        match curve {
            c if c == SECP256R1 => p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map(EcKey::P256)
                .map_err(|e| format!("P-256 key: {e}")),
            c if c == SECP384R1 => p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map(EcKey::P384)
                .map_err(|e| format!("P-384 key: {e}")),
            c => Err(format!("unsupported curve {c}")),
        }
    }

    /// Whether `issuer` signed this certificate (names match and the
    /// signature over the TBS bytes verifies with the issuer's key).
    pub fn issued_by(&self, issuer: &Cert) -> Result<(), String> {
        if self.issuer_der() != issuer.subject_der() {
            return Err(format!(
                "issuer {} is not {}",
                self.issuer(),
                issuer.subject()
            ));
        }
        let key = issuer.key()?;
        key.verify(
            &self.cert.signature_algorithm.oid,
            &self.tbs_raw,
            self.cert.signature.raw_bytes(),
        )
    }

    fn extension(&self, oid: ObjectIdentifier) -> Option<&[u8]> {
        self.cert
            .tbs_certificate
            .extensions
            .as_ref()?
            .iter()
            .find(|e| e.extn_id == oid)
            .map(|e| e.extn_value.as_bytes())
    }

    /// A Fulcio extension's string value: DER UTF8String for `.8` and up,
    /// raw bytes for the deprecated `.1` to `.6`.
    pub fn fulcio_string(&self, oid: ObjectIdentifier) -> Option<String> {
        let v = self.extension(oid)?;
        if oid == fulcio::ISSUER_V1 {
            return std::str::from_utf8(v).ok().map(str::to_owned);
        }
        Utf8StringRef::from_der(v)
            .ok()
            .map(|s| s.as_str().to_owned())
    }

    /// The extended key usage lists code signing.
    pub fn has_code_signing(&self) -> bool {
        let Some(v) = self.extension(EXT_KEY_USAGE) else {
            return false;
        };
        Vec::<ObjectIdentifier>::from_der(v).is_ok_and(|oids| oids.contains(&KP_CODE_SIGNING))
    }
}

impl EcKey {
    /// Verify a DER ECDSA signature over `msg` with the hash `alg` names
    /// (ecdsa-with-SHA256/384/512).
    pub fn verify(&self, alg: &ObjectIdentifier, msg: &[u8], sig_der: &[u8]) -> Result<(), String> {
        let digest = match *alg {
            a if a == ECDSA_SHA256 => sha2::Sha256::digest(msg).to_vec(),
            a if a == ECDSA_SHA384 => sha2::Sha384::digest(msg).to_vec(),
            a if a == ECDSA_SHA512 => sha2::Sha512::digest(msg).to_vec(),
            a => return Err(format!("signature algorithm {a} is not ECDSA with SHA-2")),
        };
        self.verify_prehash(&digest, sig_der)
    }

    pub fn verify_prehash(&self, digest: &[u8], sig_der: &[u8]) -> Result<(), String> {
        use ecdsa_hazmat::PrehashVerifier as _;
        match self {
            EcKey::P256(k) => {
                let sig = p256::ecdsa::Signature::from_der(sig_der)
                    .map_err(|e| format!("ECDSA signature: {e}"))?;
                k.verify_prehash(digest, &sig)
                    .map_err(|_| "ECDSA signature does not verify".to_owned())
            }
            EcKey::P384(k) => {
                let sig = p384::ecdsa::Signature::from_der(sig_der)
                    .map_err(|e| format!("ECDSA signature: {e}"))?;
                k.verify_prehash(digest, &sig)
                    .map_err(|_| "ECDSA signature does not verify".to_owned())
            }
        }
    }

    /// The signature algorithm a signer with this key uses by default.
    pub fn default_alg(&self) -> ObjectIdentifier {
        match self {
            EcKey::P256(_) => ECDSA_SHA256,
            EcKey::P384(_) => ECDSA_SHA384,
        }
    }
}

mod ecdsa_hazmat {
    pub use p256::ecdsa::signature::hazmat::PrehashVerifier;
}

/// Hash `data` with the digest algorithm `oid` names (SHA-256/384/512).
pub(crate) fn digest(oid: &ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>, String> {
    match *oid {
        o if o == SHA256 => Ok(sha2::Sha256::digest(data).to_vec()),
        o if o == SHA384 => Ok(sha2::Sha384::digest(data).to_vec()),
        o if o == SHA512 => Ok(sha2::Sha512::digest(data).to_vec()),
        o => Err(format!("digest algorithm {o} is not SHA-2")),
    }
}

/// Decode PEM armor (any label) to DER.
pub(crate) fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    crate::b64_decode(&body).map_err(|e| format!("PEM base64: {e}"))
}
