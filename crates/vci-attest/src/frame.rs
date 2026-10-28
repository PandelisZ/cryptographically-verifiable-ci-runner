//! The format-3 record frame (STORE-V2 section 1.2): the slot's value from
//! vci 2.9 on, a UTF-8 text without NUL that holds the signed statement
//! bytes exactly as signed, the signature, the signer's key id and the
//! unit's descriptor.
//!
//! ```text
//! record     = "vci3" LF statement LF sig LF descriptor
//! statement  = the statement JSON exactly as signed (compact, no LF, no
//!              NUL); it starts with '{'
//! sig        = base64(sig_frame)
//! descriptor = base64(descriptor_bytes)
//!
//! sig_frame  = u8 sig_kind (1 = SSHSIG, 2 = Sigstore bundle)
//!              uv keyid_len; bytes keyid
//!              uv sig_len;   bytes sig
//! ```
//!
//! `uv` is a minimal unsigned LEB128 varint; base64 is RFC 4648 section 4
//! with `=` padding, canonical. A format-1 value (today's envelope JSON)
//! starts with `{`; a frame starts with `v`, and its first line is exactly
//! `vci3`.
//!
//! The SSHSIG travels as its binary blob (the bytes inside the
//! `-----BEGIN SSH SIGNATURE-----` armor): 180 B for ed25519, where the
//! envelope carries 404 B of base64 of the armor. [`Envelope::from_frame`]
//! puts the armor back in ssh-keygen's form (70-column lines, LF), so that
//! verification sees the bytes it sees today; [`Frame::from_envelope`]
//! accepts only that form, so that the two are inverses. A keyless
//! signature (kind 2) travels as the compact JSON `{"sig": <the DSSE
//! signature as the envelope carries it>, "sigstore": <the stored
//! envelope's sigstore member>}`: everything of today's stored keyless JSON
//! that the frame does not hold elsewhere.
//!
//! The descriptor is opaque here: `vci-core` decodes it against the run's
//! shape and tables objects.
//!
//! Decoding is fail-closed under the rules of STORE-V2 section 1.6: every
//! deviation is a named [`FrameError`], which callers turn into a failed
//! `envelope` check (the unit runs), except [`FrameError::NotAFrame`],
//! which routes a format-1 value to today's path.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::keyless::{self, SigstoreMaterial};
use crate::{Envelope, PAYLOAD_TYPE, Signature, b64_decode, b64_encode};

/// The first line of a format-3 record.
pub const FRAME_FIRST_LINE: &str = "vci3";
/// The largest record a decoder accepts (STORE-V2 section 4; the largest
/// real one is 2.7 KB).
pub const MAX_RECORD: usize = 1 << 20;

const SIG_KIND_SSHSIG: u8 = 1;
const SIG_KIND_BUNDLE: u8 = 2;
/// The longest minimal LEB128 encoding of a u64.
const MAX_VARINT_BYTES: usize = 10;

const ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----\n";
const ARMOR_END: &str = "-----END SSH SIGNATURE-----\n";
/// ssh-keygen's (and ssh-encoding's) PEM line width.
const ARMOR_WIDTH: usize = 70;

/// Why a value is not a well-formed frame, or an envelope cannot become one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The value starts with `{`: a format-1 envelope, for today's path.
    #[error("not a frame: the value starts with '{{' (a format-1 envelope)")]
    NotAFrame,
    #[error("the record is {0} bytes, over the bound of {max}", max = MAX_RECORD)]
    TooLarge(usize),
    #[error("the record is not UTF-8")]
    NotUtf8,
    #[error("the record holds a NUL byte")]
    Nul,
    #[error("the first line is {0:?}, not {first:?}", first = FRAME_FIRST_LINE)]
    FirstLine(String),
    #[error("the record has {0} line feeds, not 3")]
    Lines(usize),
    #[error("the statement is empty")]
    EmptyStatement,
    #[error("the statement starts with {0:?}, not '{{'")]
    StatementStart(char),
    #[error("the statement holds a line feed")]
    StatementLineFeed,
    #[error("{field} base64: {reason}")]
    Base64 { field: &'static str, reason: String },
    #[error("signature frame: {what}: {err}")]
    Varint {
        what: &'static str,
        err: VarintError,
    },
    #[error("signature frame ends inside the {0}")]
    Truncated(&'static str),
    #[error("signature kind {0} is not 1 (SSHSIG) or 2 (Sigstore bundle)")]
    SigKind(u8),
    #[error("the keyid is not UTF-8")]
    KeyidUtf8,
    #[error("the signature is empty")]
    EmptySignature,
    #[error("signature frame: {0} bytes after the signature")]
    TrailingBytes(usize),
    /// The envelope's `payloadType` is not [`PAYLOAD_TYPE`].
    #[error("payload type {0:?}")]
    PayloadType(String),
    /// A frame holds one signature; the envelope has another number.
    #[error("the envelope has {0} signatures, not 1")]
    Signatures(usize),
    /// The signature is not an SSHSIG in ssh-keygen's armor.
    #[error("SSHSIG armor: {0}")]
    Armor(String),
    /// Stored envelope JSON, or a kind-2 signature's JSON, that does not parse.
    #[error("json: {0}")]
    Json(String),
}

/// What is wrong with a `uv` varint (STORE-V2 section 1.6 rule 2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VarintError {
    #[error("ends inside the varint")]
    Truncated,
    #[error("non-minimal varint (a continuation byte followed by a zero byte)")]
    NonMinimal,
    #[error("varint longer than {max} bytes", max = MAX_VARINT_BYTES)]
    TooLong,
    #[error("varint past u64::MAX")]
    Overflow,
}

/// The signature a frame carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameSig {
    /// Kind 1: the SSHSIG blob, the bytes inside the PEM armor.
    SshSig(Vec<u8>),
    /// Kind 2: a keyless signature, `sig` as the envelope's `signatures[0].sig`
    /// carries it (base64 of the DER ECDSA signature over the PAE) and the
    /// stored envelope's `sigstore` member.
    Bundle {
        sig: String,
        material: SigstoreMaterial,
    },
}

/// A format-3 record, decoded or about to be encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The statement JSON exactly as signed: the signature is checked over
    /// these bytes, which are never re-serialised.
    pub statement: Vec<u8>,
    /// Today's `keyid` (`SHA256:<b64 of the key blob hash>`, or the keyless
    /// signer's id): a hint, never trusted.
    pub keyid: String,
    pub sig: FrameSig,
    /// The unit's descriptor (STORE-V2 section 1.2), opaque here.
    pub descriptor: Vec<u8>,
}

/// Kind 2's signature bytes: the stored keyless JSON minus what the frame
/// holds elsewhere.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleJson<'a> {
    sig: Cow<'a, str>,
    sigstore: Cow<'a, SigstoreMaterial>,
}

/// Whether `value` is a format-3 record by its first byte (`v`). A value
/// that starts with `{` is a format-1 envelope; anything else is neither,
/// and [`Frame::decode`] says why.
pub fn is_frame(value: &[u8]) -> bool {
    value.first() == Some(&b'v')
}

impl Frame {
    /// The frame for an SSH-signed envelope (`sig` base64 of SSHSIG armor in
    /// ssh-keygen's form) and the unit's descriptor.
    pub fn from_envelope(envelope: &Envelope, descriptor: Vec<u8>) -> Result<Frame, FrameError> {
        let (statement, signature) = envelope_parts(envelope)?;
        let pem = b64_decode(&signature.sig).map_err(|e| FrameError::Base64 {
            field: "signature",
            reason: e.to_string(),
        })?;
        let pem = std::str::from_utf8(&pem)
            .map_err(|_| FrameError::Armor("the armor is not UTF-8".into()))?;
        Ok(Frame {
            statement,
            keyid: signature.keyid.clone(),
            sig: FrameSig::SshSig(sshsig_dearmor(pem)?),
            descriptor,
        })
    }

    /// The frame for a keylessly signed envelope, its `sigstore` member and
    /// the unit's descriptor.
    pub fn from_keyless(
        envelope: &Envelope,
        material: &SigstoreMaterial,
        descriptor: Vec<u8>,
    ) -> Result<Frame, FrameError> {
        let (statement, signature) = envelope_parts(envelope)?;
        Ok(Frame {
            statement,
            keyid: signature.keyid.clone(),
            sig: FrameSig::Bundle {
                sig: signature.sig.clone(),
                material: material.clone(),
            },
            descriptor,
        })
    }

    /// The frame for a format-1 value (today's stored JSON: the envelope,
    /// plus a `sigstore` member for a keyless signature) and the unit's
    /// descriptor.
    pub fn from_stored_json(bytes: &[u8], descriptor: Vec<u8>) -> Result<Frame, FrameError> {
        let material =
            keyless::material_from_json(bytes).map_err(|e| FrameError::Json(e.to_string()))?;
        let envelope = Envelope::from_json(bytes).map_err(|e| FrameError::Json(e.to_string()))?;
        match material {
            Some(m) => Frame::from_keyless(&envelope, &m, descriptor),
            None => Frame::from_envelope(&envelope, descriptor),
        }
    }

    /// The `sigstore` member of the stored form, for a keyless signature.
    pub fn sigstore(&self) -> Option<&SigstoreMaterial> {
        match &self.sig {
            FrameSig::SshSig(_) => None,
            FrameSig::Bundle { material, .. } => Some(material),
        }
    }

    /// Today's stored JSON for this record: the DSSE envelope (`payloadType`,
    /// base64 `payload`, `signatures[{keyid, sig}]`), with the `sigstore`
    /// member for a keyless signature; byte for byte what `vci run` stored
    /// before format 3 and what `vci verify` reads.
    pub fn to_stored_json(&self) -> Vec<u8> {
        let envelope = Envelope::from_frame(self);
        match &self.sig {
            FrameSig::SshSig(_) => envelope.to_json(),
            FrameSig::Bundle { material, .. } => keyless::to_stored_json(&envelope, material),
        }
    }

    /// The record text. Fails when the frame would not decode: a statement
    /// that is empty, does not start with `{`, is not UTF-8 or holds a line
    /// feed or NUL; an empty SSHSIG; a record over [`MAX_RECORD`].
    pub fn encode(&self) -> Result<String, FrameError> {
        check_statement(&self.statement)?;
        let mut sig_frame = Vec::new();
        let (kind, sig): (u8, Cow<'_, [u8]>) = match &self.sig {
            FrameSig::SshSig(blob) => (SIG_KIND_SSHSIG, Cow::Borrowed(blob.as_slice())),
            FrameSig::Bundle { sig, material } => {
                let json = serde_json::to_vec(&BundleJson {
                    sig: Cow::Borrowed(sig),
                    sigstore: Cow::Borrowed(material),
                })
                .expect("bundle serialisation cannot fail");
                (SIG_KIND_BUNDLE, Cow::Owned(json))
            }
        };
        if sig.is_empty() {
            return Err(FrameError::EmptySignature);
        }
        sig_frame.push(kind);
        put_uv(&mut sig_frame, self.keyid.len() as u64);
        sig_frame.extend_from_slice(self.keyid.as_bytes());
        put_uv(&mut sig_frame, sig.len() as u64);
        sig_frame.extend_from_slice(&sig);

        let mut record = String::with_capacity(
            FRAME_FIRST_LINE.len()
                + 3
                + self.statement.len()
                + sig_frame.len().div_ceil(3) * 4
                + self.descriptor.len().div_ceil(3) * 4,
        );
        record.push_str(FRAME_FIRST_LINE);
        record.push('\n');
        record.push_str(std::str::from_utf8(&self.statement).expect("checked above"));
        record.push('\n');
        record.push_str(&b64_encode(&sig_frame));
        record.push('\n');
        record.push_str(&b64_encode(&self.descriptor));
        if record.len() > MAX_RECORD {
            return Err(FrameError::TooLarge(record.len()));
        }
        Ok(record)
    }

    /// Decode a record under the rules of STORE-V2 section 1.6: at most
    /// [`MAX_RECORD`] bytes of UTF-8 without NUL, first line exactly `vci3`,
    /// exactly three line feeds, a non-empty statement starting with `{`,
    /// canonical base64, a signature frame with minimal varints, lengths
    /// within the bytes, a known kind, a UTF-8 keyid, a non-empty signature
    /// and nothing after it. A value starting with `{` is
    /// [`FrameError::NotAFrame`].
    pub fn decode(value: &[u8]) -> Result<Frame, FrameError> {
        if value.first() == Some(&b'{') {
            return Err(FrameError::NotAFrame);
        }
        if value.len() > MAX_RECORD {
            return Err(FrameError::TooLarge(value.len()));
        }
        let text = std::str::from_utf8(value).map_err(|_| FrameError::NotUtf8)?;
        if text.contains('\0') {
            return Err(FrameError::Nul);
        }
        // The error quotes at most the first 16 characters of a wrong line.
        let first_line = |line: &str| FrameError::FirstLine(line.chars().take(16).collect());
        let (first, rest) = text.split_once('\n').ok_or_else(|| first_line(text))?;
        if first != FRAME_FIRST_LINE {
            return Err(first_line(first));
        }
        let lines = rest.matches('\n').count() + 1;
        if lines != 3 {
            return Err(FrameError::Lines(lines));
        }
        let (statement, rest) = rest.split_once('\n').expect("three lines");
        let (sig_b64, descriptor_b64) = rest.split_once('\n').expect("three lines");
        check_statement(statement.as_bytes())?;
        let sig_frame = b64_decode(sig_b64).map_err(|e| FrameError::Base64 {
            field: "signature",
            reason: e.to_string(),
        })?;
        let descriptor = b64_decode(descriptor_b64).map_err(|e| FrameError::Base64 {
            field: "descriptor",
            reason: e.to_string(),
        })?;
        let (keyid, sig) = decode_sig_frame(&sig_frame)?;
        Ok(Frame {
            statement: statement.as_bytes().to_vec(),
            keyid,
            sig,
            descriptor,
        })
    }
}

impl Envelope {
    /// The DSSE envelope for a frame: `payloadType` [`PAYLOAD_TYPE`], the
    /// statement bytes as base64 and one signature with the frame's keyid
    /// (an SSHSIG re-armored in ssh-keygen's form). What verification sees
    /// today; the `sigstore` member of a keyless record is
    /// [`Frame::sigstore`].
    pub fn from_frame(frame: &Frame) -> Envelope {
        let sig = match &frame.sig {
            FrameSig::SshSig(blob) => b64_encode(sshsig_armor(blob).as_bytes()),
            FrameSig::Bundle { sig, .. } => sig.clone(),
        };
        Envelope {
            payload_type: PAYLOAD_TYPE.to_owned(),
            payload: b64_encode(&frame.statement),
            signatures: vec![Signature {
                keyid: frame.keyid.clone(),
                sig,
            }],
        }
    }
}

/// The payload bytes (checked as a statement) and the one signature of an
/// envelope a frame can hold.
fn envelope_parts(envelope: &Envelope) -> Result<(Vec<u8>, &Signature), FrameError> {
    if envelope.payload_type != PAYLOAD_TYPE {
        return Err(FrameError::PayloadType(envelope.payload_type.clone()));
    }
    let [signature] = envelope.signatures.as_slice() else {
        return Err(FrameError::Signatures(envelope.signatures.len()));
    };
    let statement = b64_decode(&envelope.payload).map_err(|e| FrameError::Base64 {
        field: "payload",
        reason: e.to_string(),
    })?;
    check_statement(&statement)?;
    Ok((statement, signature))
}

/// Rule 1 for the statement: non-empty, starts with `{`, UTF-8, no line
/// feed (the frame's separator) and no NUL.
fn check_statement(statement: &[u8]) -> Result<(), FrameError> {
    let text = std::str::from_utf8(statement).map_err(|_| FrameError::NotUtf8)?;
    let Some(first) = text.chars().next() else {
        return Err(FrameError::EmptyStatement);
    };
    if first != '{' {
        return Err(FrameError::StatementStart(first));
    }
    if text.contains('\0') {
        return Err(FrameError::Nul);
    }
    if text.contains('\n') {
        return Err(FrameError::StatementLineFeed);
    }
    Ok(())
}

/// The keyid and the signature of a signature frame.
fn decode_sig_frame(bytes: &[u8]) -> Result<(String, FrameSig), FrameError> {
    let mut rest = bytes;
    let Some((&kind, after)) = rest.split_first() else {
        return Err(FrameError::Truncated("signature kind"));
    };
    rest = after;
    if kind != SIG_KIND_SSHSIG && kind != SIG_KIND_BUNDLE {
        return Err(FrameError::SigKind(kind));
    }
    let keyid = take_bytes(&mut rest, "keyid")?;
    let keyid = String::from_utf8(keyid.to_vec()).map_err(|_| FrameError::KeyidUtf8)?;
    let sig = take_bytes(&mut rest, "signature")?;
    if sig.is_empty() {
        return Err(FrameError::EmptySignature);
    }
    if !rest.is_empty() {
        return Err(FrameError::TrailingBytes(rest.len()));
    }
    let sig = match kind {
        SIG_KIND_SSHSIG => FrameSig::SshSig(sig.to_vec()),
        _ => {
            let bundle: BundleJson<'_> =
                serde_json::from_slice(sig).map_err(|e| FrameError::Json(e.to_string()))?;
            FrameSig::Bundle {
                sig: bundle.sig.into_owned(),
                material: bundle.sigstore.into_owned(),
            }
        }
    };
    Ok((keyid, sig))
}

/// A `uv` length and that many bytes, which must be within `rest`
/// (the length is checked before anything is read or allocated).
fn take_bytes<'a>(rest: &mut &'a [u8], what: &'static str) -> Result<&'a [u8], FrameError> {
    let len = take_uv(rest, what)?;
    if len > rest.len() as u64 {
        return Err(FrameError::Truncated(what));
    }
    let (bytes, after) = rest.split_at(len as usize);
    *rest = after;
    Ok(bytes)
}

/// A minimal unsigned LEB128 varint at the start of `rest`.
fn take_uv(rest: &mut &[u8], what: &'static str) -> Result<u64, FrameError> {
    let err = |err| FrameError::Varint { what, err };
    let mut value = 0u64;
    for i in 0..MAX_VARINT_BYTES {
        let Some(&byte) = rest.get(i) else {
            return Err(err(VarintError::Truncated));
        };
        if i == MAX_VARINT_BYTES - 1 {
            if byte & 0x80 != 0 {
                return Err(err(VarintError::TooLong));
            }
            if byte > 1 {
                return Err(err(VarintError::Overflow));
            }
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            if i > 0 && byte == 0 {
                return Err(err(VarintError::NonMinimal));
            }
            *rest = &rest[i + 1..];
            return Ok(value);
        }
    }
    unreachable!("the last byte returns")
}

fn put_uv(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// The SSHSIG PEM armor of `blob` in ssh-keygen's form: the BEGIN line,
/// base64 in 70-column lines, the END line, LF line ends, a final LF.
pub fn sshsig_armor(blob: &[u8]) -> String {
    let b64 = b64_encode(blob);
    let mut out = String::with_capacity(
        ARMOR_BEGIN.len() + b64.len() + b64.len() / ARMOR_WIDTH + 1 + ARMOR_END.len(),
    );
    out.push_str(ARMOR_BEGIN);
    for line in b64.as_bytes().chunks(ARMOR_WIDTH) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(ARMOR_END);
    out
}

/// The SSHSIG blob inside `pem`, which must be exactly [`sshsig_armor`] of
/// it (ssh-keygen's form: any other line width, CRLF, whitespace or a
/// missing final LF is refused), so that the armor comes back byte for byte.
pub fn sshsig_dearmor(pem: &str) -> Result<Vec<u8>, FrameError> {
    let body = pem
        .strip_prefix(ARMOR_BEGIN)
        .and_then(|b| b.strip_suffix(ARMOR_END))
        .ok_or_else(|| {
            FrameError::Armor("not between the SSH SIGNATURE BEGIN and END lines".into())
        })?;
    let joined: String = body.split('\n').collect();
    let blob = b64_decode(&joined).map_err(|e| FrameError::Armor(format!("body base64: {e}")))?;
    if blob.is_empty() {
        return Err(FrameError::Armor("empty body".into()));
    }
    if sshsig_armor(&blob) != pem {
        return Err(FrameError::Armor(
            "not ssh-keygen's form (70-column lines, LF)".into(),
        ));
    }
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, SshSig};

    use super::*;
    use crate::keyless::{RawBytes, VerificationMaterial};
    use crate::{AllowedSigners, NAMESPACE, Statement, pae, sign::HASH, verify_envelope};

    fn statement_bytes() -> Vec<u8> {
        let mut digest = std::collections::BTreeMap::new();
        digest.insert("blake3".to_owned(), "ab".repeat(32));
        let s = Statement::new(
            vec![crate::Subject {
                name: "src/t.test.ts".into(),
                digest,
            }],
            "https://vci.dev/test-attestation/v2",
            serde_json::json!({ "testId": "src/t.test.ts", "result": { "state": "passed" } }),
        );
        serde_json::to_vec(&s).unwrap()
    }

    /// A real ed25519 SSHSIG over the PAE of `payload`, as `sign_payload`
    /// makes it: the envelope, the key's allowed_signers line and the PEM.
    fn ssh_signed(payload: &[u8]) -> (Envelope, AllowedSigners, String) {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let sshsig = key
            .sign(NAMESPACE, HASH, &pae(PAYLOAD_TYPE, payload))
            .unwrap();
        let pem = sshsig.to_pem(LineEnding::LF).unwrap();
        let envelope = Envelope {
            payload_type: PAYLOAD_TYPE.to_owned(),
            payload: b64_encode(payload),
            signatures: vec![Signature {
                keyid: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
                sig: b64_encode(pem.as_bytes()),
            }],
        };
        let allowed = AllowedSigners::parse(&format!(
            "alice@example.com {}\n",
            key.public_key().to_openssh().unwrap()
        ))
        .unwrap();
        (envelope, allowed, pem)
    }

    fn ssh_frame() -> (Frame, Envelope, AllowedSigners) {
        let payload = statement_bytes();
        let (envelope, allowed, _) = ssh_signed(&payload);
        let frame = Frame::from_envelope(&envelope, vec![7, 8, 9]).unwrap();
        (frame, envelope, allowed)
    }

    fn material() -> SigstoreMaterial {
        SigstoreMaterial {
            media_type: keyless::BUNDLE_MEDIA_TYPE.to_owned(),
            verification_material: VerificationMaterial {
                certificate: Some(RawBytes {
                    raw_bytes: "MIIB".into(),
                }),
                ..VerificationMaterial::default()
            },
        }
    }

    fn keyless_frame() -> (Frame, Envelope, SigstoreMaterial) {
        let envelope = Envelope {
            payload_type: PAYLOAD_TYPE.to_owned(),
            payload: b64_encode(&statement_bytes()),
            signatures: vec![Signature {
                keyid: String::new(),
                sig: "MEQCIFKf".into(),
            }],
        };
        let m = material();
        let frame = Frame::from_keyless(&envelope, &m, vec![1]).unwrap();
        (frame, envelope, m)
    }

    /// A record from parts, for malformed cases.
    fn record(statement: &str, sig_frame: &[u8], descriptor: &[u8]) -> Vec<u8> {
        format!(
            "vci3\n{statement}\n{}\n{}",
            b64_encode(sig_frame),
            b64_encode(descriptor)
        )
        .into_bytes()
    }

    fn sig_frame(kind: u8, keyid: &[u8], sig: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        put_uv(&mut out, keyid.len() as u64);
        out.extend_from_slice(keyid);
        put_uv(&mut out, sig.len() as u64);
        out.extend_from_slice(sig);
        out
    }

    fn decode_err(value: &[u8]) -> FrameError {
        Frame::decode(value).expect_err("must be refused")
    }

    #[test]
    fn an_ssh_frame_round_trips_and_verifies_as_today() {
        let (frame, envelope, allowed) = ssh_frame();
        let statement = statement_bytes();
        assert_eq!(frame.statement, statement);
        assert_eq!(frame.keyid, envelope.signatures[0].keyid);
        let FrameSig::SshSig(blob) = &frame.sig else {
            panic!("kind 1");
        };
        assert_eq!(blob.len(), 180, "an ed25519 SSHSIG blob");
        assert_eq!(frame.descriptor, vec![7, 8, 9]);

        let text = frame.encode().unwrap();
        assert!(is_frame(text.as_bytes()));
        assert!(text.starts_with("vci3\n{"));
        assert_eq!(text.matches('\n').count(), 3);
        assert!(!text.contains('\0'));
        let back = Frame::decode(text.as_bytes()).unwrap();
        assert_eq!(back, frame);

        // The envelope the frame rebuilds is the one it came from, field
        // for field and byte for byte, and verification sees what it saw.
        assert_eq!(Envelope::from_frame(&back), envelope);
        assert_eq!(back.to_stored_json(), envelope.to_json());
        assert_eq!(back.sigstore(), None);
        let v = verify_envelope(&Envelope::from_frame(&back), &allowed, 1_800_000_000).unwrap();
        assert_eq!(v.payload, statement);
        assert_eq!(v.principal, "alice@example.com");
    }

    #[test]
    fn the_signature_frame_is_234_bytes_for_ed25519() {
        // 1 kind + 1 len + 50 keyid + 2 len + 180 blob, as STORE-V2 measured.
        let (frame, _, _) = ssh_frame();
        let text = frame.encode().unwrap();
        let sig_b64 = text.split('\n').nth(2).unwrap();
        assert_eq!(sig_b64.len(), 312);
        assert_eq!(b64_decode(sig_b64).unwrap().len(), 234);
    }

    #[test]
    fn a_keyless_frame_round_trips_to_the_stored_form() {
        let (frame, envelope, m) = keyless_frame();
        assert_eq!(frame.sigstore(), Some(&m));
        let text = frame.encode().unwrap();
        let back = Frame::decode(text.as_bytes()).unwrap();
        assert_eq!(back, frame);
        assert_eq!(Envelope::from_frame(&back), envelope);
        let stored = keyless::to_stored_json(&envelope, &m);
        assert_eq!(back.to_stored_json(), stored);
        assert_eq!(Frame::from_stored_json(&stored, vec![1]).unwrap(), frame);
        // Kind 2's bytes are the compact `{"sig", "sigstore"}` JSON.
        let sig_frame = b64_decode(text.split('\n').nth(2).unwrap()).unwrap();
        assert_eq!(sig_frame[0], 2);
        let json = &sig_frame[sig_frame.iter().position(|&b| b == b'{').unwrap()..];
        assert!(
            json.starts_with(br#"{"sig":"MEQCIFKf","sigstore":{"mediaType":"#),
            "{}",
            String::from_utf8_lossy(json)
        );
    }

    #[test]
    fn from_stored_json_takes_an_ssh_envelope_too() {
        let (frame, envelope, _) = ssh_frame();
        assert_eq!(
            Frame::from_stored_json(&envelope.to_json(), vec![7, 8, 9]).unwrap(),
            frame
        );
        assert!(matches!(
            Frame::from_stored_json(b"nope", vec![]).unwrap_err(),
            FrameError::Json(_)
        ));
        assert!(matches!(
            Frame::from_stored_json(br#"{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[],"sigstore":{"mediaType":1}}"#, vec![]).unwrap_err(),
            FrameError::Json(_)
        ));
    }

    #[test]
    fn armor_round_trips_a_real_sshsig_byte_for_byte() {
        let payload = statement_bytes();
        let (_, _, pem) = ssh_signed(&payload);
        let blob = sshsig_dearmor(&pem).unwrap();
        assert_eq!(blob.len(), 180);
        assert_eq!(sshsig_armor(&blob), pem);
        // The armor is what ssh-key (and ssh-keygen) write: 70-column lines.
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines[0], "-----BEGIN SSH SIGNATURE-----");
        assert_eq!(lines[1].len(), 70);
        assert_eq!(*lines.last().unwrap(), "-----END SSH SIGNATURE-----");
        assert!(pem.ends_with('\n'));
        // And the re-armored blob is the same SSHSIG.
        let a = SshSig::from_pem(pem.as_bytes()).unwrap();
        let b = SshSig::from_pem(sshsig_armor(&blob).as_bytes()).unwrap();
        assert_eq!(a, b);
        // A long blob wraps the same way (ssh-rsa sized).
        let long = vec![0x5a; 700];
        assert_eq!(sshsig_dearmor(&sshsig_armor(&long)).unwrap(), long);
    }

    #[test]
    fn armor_in_another_form_is_refused() {
        let payload = statement_bytes();
        let (_, _, pem) = ssh_signed(&payload);
        let armor = |e: FrameError| match e {
            FrameError::Armor(s) => s,
            other => panic!("{other:?}"),
        };
        assert!(
            armor(sshsig_dearmor(&pem.replace('\n', "\r\n")).unwrap_err())
                .contains("BEGIN and END")
        );
        let crlf_body = format!(
            "{ARMOR_BEGIN}{}{ARMOR_END}",
            pem[ARMOR_BEGIN.len()..pem.len() - ARMOR_END.len()].replace('\n', "\r\n")
        );
        assert!(armor(sshsig_dearmor(&crlf_body).unwrap_err()).contains("base64"));
        assert!(armor(sshsig_dearmor(pem.trim_end()).unwrap_err()).contains("BEGIN and END"));
        assert!(armor(sshsig_dearmor(&pem[1..]).unwrap_err()).contains("BEGIN and END"));
        let b64 = b64_encode(&sshsig_dearmor(&pem).unwrap());
        let at_64 = format!(
            "{ARMOR_BEGIN}{}\n{ARMOR_END}",
            b64.as_bytes()
                .chunks(64)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert!(armor(sshsig_dearmor(&at_64).unwrap_err()).contains("70-column"));
        let one_line = format!("{ARMOR_BEGIN}{b64}\n{ARMOR_END}");
        assert!(armor(sshsig_dearmor(&one_line).unwrap_err()).contains("70-column"));
        assert!(
            armor(sshsig_dearmor(&format!("{ARMOR_BEGIN}{ARMOR_END}")).unwrap_err())
                .contains("empty")
        );
        assert!(
            armor(sshsig_dearmor(&format!("{ARMOR_BEGIN}not base64!\n{ARMOR_END}")).unwrap_err())
                .contains("base64")
        );
        assert!(
            armor(
                sshsig_dearmor(&format!(
                    "{ARMOR_BEGIN}{}\n{ARMOR_END}",
                    &b64[..b64.len() - 1]
                ))
                .unwrap_err()
            )
            .contains("base64")
        );
    }

    #[test]
    fn from_envelope_refuses_what_a_frame_cannot_hold() {
        let (_, envelope, _) = ssh_frame();
        let mut e = envelope.clone();
        e.payload_type = "text/plain".into();
        assert_eq!(
            Frame::from_envelope(&e, vec![]).unwrap_err(),
            FrameError::PayloadType("text/plain".into())
        );
        let mut e = envelope.clone();
        e.signatures.clear();
        assert_eq!(
            Frame::from_envelope(&e, vec![]).unwrap_err(),
            FrameError::Signatures(0)
        );
        let mut e = envelope.clone();
        e.signatures.push(envelope.signatures[0].clone());
        assert_eq!(
            Frame::from_envelope(&e, vec![]).unwrap_err(),
            FrameError::Signatures(2)
        );
        let mut e = envelope.clone();
        e.payload = "e30".into();
        assert!(matches!(
            Frame::from_envelope(&e, vec![]).unwrap_err(),
            FrameError::Base64 {
                field: "payload",
                ..
            }
        ));
        let mut e = envelope.clone();
        e.signatures[0].sig = "LS0t".into();
        assert!(matches!(
            Frame::from_envelope(&e, vec![]).unwrap_err(),
            FrameError::Armor(_)
        ));
        e.signatures[0].sig = "LS0t=".into();
        assert!(matches!(
            Frame::from_envelope(&e, vec![]).unwrap_err(),
            FrameError::Base64 {
                field: "signature",
                ..
            }
        ));
        e.signatures[0].sig = b64_encode(&[0xff, 0xfe]);
        assert!(matches!(
            Frame::from_envelope(&e, vec![]).unwrap_err(),
            FrameError::Armor(_)
        ));
        // A keyless envelope's DER signature is no SSHSIG armor.
        let (_, keyless, _) = keyless_frame();
        assert!(matches!(
            Frame::from_envelope(&keyless, vec![]).unwrap_err(),
            FrameError::Armor(_)
        ));
        // The statement rules apply to the payload.
        let mut e = envelope.clone();
        e.payload = b64_encode(b"");
        assert_eq!(
            Frame::from_envelope(&e, vec![]).unwrap_err(),
            FrameError::EmptyStatement
        );
        e.payload = b64_encode(b"[]");
        assert_eq!(
            Frame::from_envelope(&e, vec![]).unwrap_err(),
            FrameError::StatementStart('[')
        );
        e.payload = b64_encode(b"{\n}");
        assert_eq!(
            Frame::from_envelope(&e, vec![]).unwrap_err(),
            FrameError::StatementLineFeed
        );
        e.payload = b64_encode(b"{\0}");
        assert_eq!(
            Frame::from_envelope(&e, vec![]).unwrap_err(),
            FrameError::Nul
        );
        e.payload = b64_encode(b"{\xff}");
        assert_eq!(
            Frame::from_envelope(&e, vec![]).unwrap_err(),
            FrameError::NotUtf8
        );
        let mut k = keyless.clone();
        k.payload_type = "x".into();
        assert_eq!(
            Frame::from_keyless(&k, &material(), vec![]).unwrap_err(),
            FrameError::PayloadType("x".into())
        );
    }

    #[test]
    fn encode_refuses_a_frame_that_would_not_decode() {
        let (frame, _, _) = ssh_frame();
        let mut f = frame.clone();
        f.statement = b"{\"a\":\n1}".to_vec();
        assert_eq!(f.encode().unwrap_err(), FrameError::StatementLineFeed);
        f.statement = Vec::new();
        assert_eq!(f.encode().unwrap_err(), FrameError::EmptyStatement);
        f.statement = b"x".to_vec();
        assert_eq!(f.encode().unwrap_err(), FrameError::StatementStart('x'));
        f.statement = b"{\0}".to_vec();
        assert_eq!(f.encode().unwrap_err(), FrameError::Nul);
        f.statement = vec![b'{', 0xc3];
        assert_eq!(f.encode().unwrap_err(), FrameError::NotUtf8);
        let mut f = frame.clone();
        f.sig = FrameSig::SshSig(Vec::new());
        assert_eq!(f.encode().unwrap_err(), FrameError::EmptySignature);
        let mut f = frame.clone();
        f.descriptor = vec![0; MAX_RECORD];
        assert!(matches!(f.encode().unwrap_err(), FrameError::TooLarge(_)));
        // The bound is on the record: a record of exactly 1 MiB passes.
        let mut f = frame;
        let fixed = f.encode().unwrap().len();
        let room = MAX_RECORD - fixed;
        f.statement.pop();
        f.statement.extend(std::iter::repeat_n(b' ', room));
        f.statement.push(b'}');
        let text = f.encode().unwrap();
        assert_eq!(text.len(), MAX_RECORD);
        assert_eq!(Frame::decode(text.as_bytes()).unwrap(), f);
        f.statement.insert(1, b' ');
        assert_eq!(
            f.encode().unwrap_err(),
            FrameError::TooLarge(MAX_RECORD + 1)
        );
    }

    #[test]
    fn a_format_1_value_is_not_a_frame() {
        assert!(!is_frame(b"{\"payloadType\":1}"));
        assert!(!is_frame(b""));
        assert!(!is_frame(b"x"));
        assert!(is_frame(b"vci3\n"));
        assert_eq!(decode_err(b"{\"payloadType\":1}"), FrameError::NotAFrame);
        assert_eq!(decode_err(b"{"), FrameError::NotAFrame);
    }

    #[test]
    fn the_record_bound_is_one_mib() {
        let (frame, _, _) = ssh_frame();
        let mut text = frame.encode().unwrap().into_bytes();
        let n = MAX_RECORD + 1 - text.len();
        text.extend(std::iter::repeat_n(b'A', n));
        assert_eq!(decode_err(&text), FrameError::TooLarge(MAX_RECORD + 1));
    }

    #[test]
    fn the_record_is_utf8_without_nul() {
        let (frame, _, _) = ssh_frame();
        let text = frame.encode().unwrap();
        let mut bad = text.clone().into_bytes();
        bad[6] = 0xff;
        assert_eq!(decode_err(&bad), FrameError::NotUtf8);
        let mut bad = text.clone().into_bytes();
        bad[6] = 0;
        assert_eq!(decode_err(&bad), FrameError::Nul);
        let mut bad = text.into_bytes();
        bad.push(0);
        assert_eq!(decode_err(&bad), FrameError::Nul);
    }

    #[test]
    fn the_first_line_is_exactly_vci3() {
        let (frame, _, _) = ssh_frame();
        let text = frame.encode().unwrap();
        let rest = &text[4..];
        assert_eq!(
            decode_err(format!("vci3z{rest}").as_bytes()),
            FrameError::FirstLine("vci3z".into())
        );
        assert_eq!(
            decode_err(format!("vci2{rest}").as_bytes()),
            FrameError::FirstLine("vci2".into())
        );
        assert_eq!(
            decode_err(format!("v{rest}").as_bytes()),
            FrameError::FirstLine("v".into())
        );
        assert_eq!(
            decode_err(format!("VCI3{rest}").as_bytes()),
            FrameError::FirstLine("VCI3".into())
        );
        assert_eq!(
            decode_err(format!("vci3 {rest}").as_bytes()),
            FrameError::FirstLine("vci3 ".into())
        );
        assert_eq!(
            decode_err(format!("vci3\r{rest}").as_bytes()),
            FrameError::FirstLine("vci3\r".into())
        );
        assert_eq!(
            decode_err(format!(" vci3{rest}").as_bytes()),
            FrameError::FirstLine(" vci3".into())
        );
        assert_eq!(decode_err(b""), FrameError::FirstLine(String::new()));
        assert_eq!(decode_err(b"vci3"), FrameError::FirstLine("vci3".into()));
        assert_eq!(decode_err(b"x"), FrameError::FirstLine("x".into()));
    }

    #[test]
    fn the_record_has_exactly_three_line_feeds() {
        let (frame, _, _) = ssh_frame();
        let text = frame.encode().unwrap();
        assert_eq!(
            decode_err(format!("{text}\n").as_bytes()),
            FrameError::Lines(4)
        );
        assert_eq!(
            decode_err(format!("{text}\n\n").as_bytes()),
            FrameError::Lines(5)
        );
        let two = text.rsplit_once('\n').unwrap().0;
        assert_eq!(decode_err(two.as_bytes()), FrameError::Lines(2));
        assert_eq!(decode_err(b"vci3\n"), FrameError::Lines(1));
        assert_eq!(decode_err(b"vci3\n{}\n\n\n"), FrameError::Lines(4));
    }

    #[test]
    fn the_statement_is_a_non_empty_json_object() {
        let sf = sig_frame(1, b"k", b"s");
        assert_eq!(
            decode_err(&record("", &sf, b"")),
            FrameError::EmptyStatement
        );
        assert_eq!(
            decode_err(&record("[]", &sf, b"")),
            FrameError::StatementStart('[')
        );
        assert_eq!(
            decode_err(&record(" {}", &sf, b"")),
            FrameError::StatementStart(' ')
        );
        assert_eq!(
            decode_err(&record("é", &sf, b"")),
            FrameError::StatementStart('é')
        );
        // The statement bytes are kept as found, never parsed.
        let f = Frame::decode(&record("{not json", &sf, b"")).unwrap();
        assert_eq!(f.statement, b"{not json");
        // An empty descriptor decodes (opaque here).
        assert_eq!(f.descriptor, Vec::<u8>::new());
    }

    #[test]
    fn base64_must_be_canonical() {
        let sf = sig_frame(1, b"k", b"s");
        let b64 = b64_encode(&sf);
        let base64 = |e: FrameError| match e {
            FrameError::Base64 { field, .. } => field,
            other => panic!("{other:?}"),
        };
        let rec = |sig: &str, desc: &str| format!("vci3\n{{}}\n{sig}\n{desc}").into_bytes();
        // Length not a multiple of 4 (padding left out).
        assert_eq!(
            base64(decode_err(&rec(b64.trim_end_matches('='), ""))),
            "signature"
        );
        // A byte outside the alphabet (URL-safe '-', a space).
        assert_eq!(
            base64(decode_err(&rec(
                &b64.replacen('/', "_", 1)
                    .replacen('+', "-", 1)
                    .replacen('A', "-", 1),
                ""
            ))),
            "signature"
        );
        assert_eq!(
            base64(decode_err(&rec(
                &format!("{} {}", &b64[..4], &b64[4..]),
                ""
            ))),
            "signature"
        );
        // Whitespace and line breaks.
        assert_eq!(
            base64(decode_err(&rec(&format!("{b64}\t"), ""))),
            "signature"
        );
        assert_eq!(
            base64(decode_err(&rec(&format!("{b64}\r"), ""))),
            "signature"
        );
        // Padding in the middle.
        assert_eq!(
            base64(decode_err(&rec(&format!("QQ=={b64}"), ""))),
            "signature"
        );
        // Non-zero unused trailing bits ("QR==" would decode to "A" leniently).
        assert_eq!(base64(decode_err(&rec(&b64, "QR=="))), "descriptor");
        assert_eq!(base64(decode_err(&rec(&b64, "QUJD="))), "descriptor");
        assert_eq!(base64(decode_err(&rec(&b64, "QUJDRA"))), "descriptor");
        assert_eq!(base64(decode_err(&rec(&b64, "QU JD"))), "descriptor");
        // Canonical forms of the same bytes decode.
        assert!(Frame::decode(&rec(&b64, "QQ==")).is_ok());
        assert!(Frame::decode(&rec(&b64, "QUJDRA==")).is_ok());
        assert!(Frame::decode(&rec(&b64, "")).is_ok());
    }

    #[test]
    fn the_signature_frame_is_checked_field_by_field() {
        let rec = |sf: &[u8]| record("{}", sf, b"d");
        assert_eq!(
            decode_err(&rec(b"")),
            FrameError::Truncated("signature kind")
        );
        assert_eq!(decode_err(&rec(&[0])), FrameError::SigKind(0));
        assert_eq!(decode_err(&rec(&[3, 0, 1, b's'])), FrameError::SigKind(3));
        assert_eq!(decode_err(&rec(&[0xff])), FrameError::SigKind(0xff));
        assert_eq!(
            decode_err(&rec(&[1])),
            FrameError::Varint {
                what: "keyid",
                err: VarintError::Truncated
            }
        );
        assert_eq!(
            decode_err(&rec(&[1, 5, b'k'])),
            FrameError::Truncated("keyid")
        );
        assert_eq!(
            decode_err(&rec(&[1, 1, b'k'])),
            FrameError::Varint {
                what: "signature",
                err: VarintError::Truncated
            }
        );
        assert_eq!(
            decode_err(&rec(&[1, 1, b'k', 2, b's'])),
            FrameError::Truncated("signature")
        );
        assert_eq!(
            decode_err(&rec(&[1, 1, b'k', 0])),
            FrameError::EmptySignature
        );
        assert_eq!(decode_err(&rec(&[2, 0, 0])), FrameError::EmptySignature);
        assert_eq!(
            decode_err(&rec(&[1, 1, b'k', 1, b's', 0])),
            FrameError::TrailingBytes(1)
        );
        assert_eq!(
            decode_err(&rec(&[1, 1, b'k', 1, b's', 1, 2, 3])),
            FrameError::TrailingBytes(3)
        );
        assert_eq!(
            decode_err(&rec(&[1, 1, 0xff, 1, b's'])),
            FrameError::KeyidUtf8
        );
        assert_eq!(
            decode_err(&rec(&[1, 2, 0xc3, 0x28, 1, b's'])),
            FrameError::KeyidUtf8
        );
        // A length far past the end is refused before anything is read.
        assert_eq!(
            decode_err(&rec(&[
                1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, b'k'
            ])),
            FrameError::Truncated("keyid")
        );
        // Kind 2's signature must be the `{"sig", "sigstore"}` JSON.
        assert!(matches!(
            decode_err(&rec(&sig_frame(2, b"", b"{}"))),
            FrameError::Json(_)
        ));
        assert!(matches!(
            decode_err(&rec(&sig_frame(2, b"", b"[1]"))),
            FrameError::Json(_)
        ));
        assert!(matches!(
            decode_err(&rec(&sig_frame(
                2,
                b"",
                br#"{"sig":"x","sigstore":{"mediaType":"m"}}"#
            ))),
            FrameError::Json(_)
        ));
        assert!(matches!(
            decode_err(&rec(&sig_frame(
                2,
                b"",
                br#"{"sig":"x","sigstore":{"mediaType":"m","verificationMaterial":{}},"extra":1}"#
            ))),
            FrameError::Json(_)
        ));
        let ok = Frame::decode(&rec(&sig_frame(
            2,
            b"",
            br#"{"sig":"x","sigstore":{"mediaType":"m","verificationMaterial":{}}}"#,
        )))
        .unwrap();
        assert!(matches!(ok.sig, FrameSig::Bundle { .. }));
        // An empty keyid is fine (today's keyless envelopes have one).
        let ok = Frame::decode(&rec(&sig_frame(1, b"", b"s"))).unwrap();
        assert_eq!(ok.keyid, "");
        assert_eq!(ok.sig, FrameSig::SshSig(b"s".to_vec()));
    }

    #[test]
    fn varints_are_minimal_leb128() {
        let uv = |bytes: &[u8]| {
            let mut rest = bytes;
            take_uv(&mut rest, "n").map(|v| (v, rest.len()))
        };
        assert_eq!(uv(&[0]), Ok((0, 0)));
        assert_eq!(uv(&[0x7f, 9]), Ok((127, 1)));
        assert_eq!(uv(&[0x80, 1]), Ok((128, 0)));
        assert_eq!(
            uv(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]),
            Ok((u64::MAX, 0))
        );
        assert_eq!(
            uv(&[]),
            Err(FrameError::Varint {
                what: "n",
                err: VarintError::Truncated
            })
        );
        assert_eq!(
            uv(&[0x80]),
            Err(FrameError::Varint {
                what: "n",
                err: VarintError::Truncated
            })
        );
        assert_eq!(
            uv(&[0x80, 0]),
            Err(FrameError::Varint {
                what: "n",
                err: VarintError::NonMinimal
            })
        );
        assert_eq!(
            uv(&[0xff, 0x80, 0]),
            Err(FrameError::Varint {
                what: "n",
                err: VarintError::NonMinimal
            })
        );
        assert_eq!(
            uv(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]),
            Err(FrameError::Varint {
                what: "n",
                err: VarintError::Overflow
            })
        );
        assert_eq!(
            uv(&[
                0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01
            ]),
            Err(FrameError::Varint {
                what: "n",
                err: VarintError::TooLong
            })
        );
        assert_eq!(
            uv(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80]),
            Err(FrameError::Varint {
                what: "n",
                err: VarintError::TooLong
            })
        );
        for v in [
            0u64,
            1,
            127,
            128,
            300,
            16_383,
            16_384,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut out = Vec::new();
            put_uv(&mut out, v);
            assert_eq!(uv(&out), Ok((v, 0)), "{v}");
        }
        let mut out = Vec::new();
        put_uv(&mut out, 300);
        assert_eq!(out, [0xac, 0x02]);
    }

    #[test]
    fn a_malformed_record_fails_as_a_whole_before_its_parts() {
        // Each rule's error names the rule; the order is size, UTF-8, NUL,
        // the first line, the line count, the statement, base64, the
        // signature frame.
        assert_eq!(decode_err(b"vci3\n\xff\n"), FrameError::NotUtf8);
        assert_eq!(decode_err(b"vci3\n\0\n"), FrameError::Nul);
        assert_eq!(
            decode_err(b"vci2\n\n\n"),
            FrameError::FirstLine("vci2".into())
        );
        assert_eq!(decode_err(b"vci3\n\n"), FrameError::Lines(2));
        assert_eq!(decode_err(b"vci3\n\nAQ\n"), FrameError::EmptyStatement);
        assert_eq!(
            decode_err(b"vci3\n{}\nAQ\n"),
            FrameError::Base64 {
                field: "signature",
                reason: b64_decode("AQ").unwrap_err().to_string()
            }
        );
        assert_eq!(
            decode_err(b"vci3\n{}\nAQ==\nAQ"),
            FrameError::Base64 {
                field: "descriptor",
                reason: b64_decode("AQ").unwrap_err().to_string()
            }
        );
        assert_eq!(
            decode_err(b"vci3\n{}\nAQ==\n"),
            FrameError::Varint {
                what: "keyid",
                err: VarintError::Truncated
            }
        );
    }
}
