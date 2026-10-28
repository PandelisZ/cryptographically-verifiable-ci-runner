//! The format-3 record frame against the DSSE envelope: the conversions
//! between [`Frame`] (the codec is `vci_core::frame`, STORE-V2 section 1.2,
//! which every store reads records through and which depends on nothing
//! that signs or talks to a network) and the [`Envelope`] that is signed
//! and verified here.
//!
//! The SSHSIG travels in the frame as its binary blob (the bytes inside the
//! `-----BEGIN SSH SIGNATURE-----` armor): 180 B for ed25519, where the
//! envelope carries 404 B of base64 of the armor. [`Envelope::from_frame`]
//! puts the armor back in ssh-keygen's form (70-column lines, LF), so that
//! verification sees the bytes it sees today; [`FrameExt::from_envelope`]
//! accepts only that form, so that the two are inverses. A keyless
//! signature (kind 2) travels as the envelope's `sig` and the stored
//! envelope's `sigstore` member: everything of today's stored keyless JSON
//! that the frame does not hold elsewhere.

pub use vci_core::frame::{
    FRAME_FIRST_LINE, Frame, FrameError, FrameSig, MAX_RECORD, VarintError, is_frame,
};
use vci_core::frame::{check_statement, sshsig_armor, sshsig_dearmor};

use crate::keyless::{self, SigstoreMaterial};
use crate::{Envelope, PAYLOAD_TYPE, Signature, b64_decode, b64_encode};

/// The conversions between a [`Frame`] and today's stored forms: `use
/// vci_attest::FrameExt` brings `Frame::from_envelope`, `from_keyless`,
/// `from_stored_json` and `to_stored_json` into scope.
pub trait FrameExt: Sized {
    /// The frame for an SSH-signed envelope (`sig` base64 of SSHSIG armor in
    /// ssh-keygen's form) and the unit's descriptor.
    fn from_envelope(envelope: &Envelope, descriptor: Vec<u8>) -> Result<Self, FrameError>;

    /// The frame for a keylessly signed envelope, its `sigstore` member and
    /// the unit's descriptor.
    fn from_keyless(
        envelope: &Envelope,
        material: &SigstoreMaterial,
        descriptor: Vec<u8>,
    ) -> Result<Self, FrameError>;

    /// The frame for a format-1 value (today's stored JSON: the envelope,
    /// plus a `sigstore` member for a keyless signature) and the unit's
    /// descriptor.
    fn from_stored_json(bytes: &[u8], descriptor: Vec<u8>) -> Result<Self, FrameError>;

    /// Today's stored JSON for this record: the DSSE envelope (`payloadType`,
    /// base64 `payload`, `signatures[{keyid, sig}]`), with the `sigstore`
    /// member for a keyless signature; byte for byte what `vci run` stored
    /// before format 3 and what `vci verify` reads.
    fn to_stored_json(&self) -> Vec<u8>;
}

impl FrameExt for Frame {
    fn from_envelope(envelope: &Envelope, descriptor: Vec<u8>) -> Result<Frame, FrameError> {
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

    fn from_keyless(
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

    fn from_stored_json(bytes: &[u8], descriptor: Vec<u8>) -> Result<Frame, FrameError> {
        let material =
            keyless::material_from_json(bytes).map_err(|e| FrameError::Json(e.to_string()))?;
        let envelope = Envelope::from_json(bytes).map_err(|e| FrameError::Json(e.to_string()))?;
        match material {
            Some(m) => Frame::from_keyless(&envelope, &m, descriptor),
            None => Frame::from_envelope(&envelope, descriptor),
        }
    }

    fn to_stored_json(&self) -> Vec<u8> {
        let envelope = Envelope::from_frame(self);
        match &self.sig {
            FrameSig::SshSig(_) => envelope.to_json(),
            FrameSig::Bundle { material, .. } => keyless::to_stored_json(&envelope, material),
        }
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
}
