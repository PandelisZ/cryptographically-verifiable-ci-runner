//! Adversarial records against the envelope a frame rebuilds
//! (`design/STORE-V2.md` section 1.6 rule 1, section 4): nothing a frame's
//! base64 fields carry may change the bytes the signature is checked over.
//! The decoder's own cases (malformed, oversized, truncated,
//! section-confusing and non-canonical values) are vci-core's
//! tests/adversarial.rs, beside the codec.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use vci_attest::{Envelope, Frame, FrameExt, FrameSig, PAYLOAD_TYPE};

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn uv(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn sig_frame(kind: u8, keyid: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    uv(&mut out, keyid.len() as u64);
    out.extend_from_slice(keyid);
    uv(&mut out, sig.len() as u64);
    out.extend_from_slice(sig);
    out
}

const STATEMENT: &str = r#"{"_type":"https://in-toto.io/Statement/v1","predicate":{"testId":"t"},"predicateType":"https://vci.dev/test-attestation/v2","subject":[{"digest":{"blake3":"ab"},"name":"t"}]}"#;

fn record(statement: &str, sig: &[u8], descriptor: &[u8]) -> Vec<u8> {
    format!("vci3\n{statement}\n{}\n{}", b64(sig), b64(descriptor)).into_bytes()
}

fn good() -> Vec<u8> {
    record(STATEMENT, &sig_frame(1, b"SHA256:k", &[9; 180]), &[1, 2, 3])
}

#[test]
fn the_good_record_rebuilds_the_envelope_over_the_statement_bytes_as_found() {
    let f = Frame::decode(&good()).unwrap();
    assert_eq!(f.statement, STATEMENT.as_bytes());
    let e = Envelope::from_frame(&f);
    assert_eq!(e.payload_type, PAYLOAD_TYPE);
    assert_eq!(STANDARD.decode(&e.payload).unwrap(), STATEMENT.as_bytes());
    assert_eq!(e.signatures.len(), 1);
    assert_eq!(e.signatures[0].keyid, "SHA256:k");
    // The keyid may hold anything UTF-8, line feeds and NUL included: it
    // is a hint, never parsed, and goes into the envelope as it is.
    let f = Frame::decode(&record(STATEMENT, &sig_frame(1, b"k\n\0id", &[1]), &[1])).unwrap();
    assert_eq!(Envelope::from_frame(&f).signatures[0].keyid, "k\n\0id");
}

#[test]
fn a_bundle_signature_goes_into_the_envelope_as_is() {
    let rec = |json: &[u8]| record(STATEMENT, &sig_frame(2, b"", json), &[1]);
    let ok = rec(b"{\"sig\":\"x\",\"sigstore\":{\"mediaType\":\"m\",\"verificationMaterial\":{}}}");
    let f = Frame::decode(&ok).unwrap();
    let FrameSig::Bundle { sig, material } = &f.sig else {
        panic!("kind 2");
    };
    assert_eq!(sig, "x");
    assert_eq!(material.media_type, "m");
    // The bundle's `sig` goes into the envelope's signature as is and
    // the payload is still the statement line: nothing in the base64
    // field moves what the signature covers.
    let e = Envelope::from_frame(&f);
    assert_eq!(e.signatures[0].sig, "x");
    assert_eq!(e.payload, b64(STATEMENT.as_bytes()));
    assert_eq!(e.payload_type, PAYLOAD_TYPE);
    assert_eq!(f.sigstore(), Some(material));
    // A frame's stored JSON is what a format-1 keyless record holds.
    assert!(matches!(
        Frame::from_stored_json(&f.to_stored_json(), vec![1]),
        Ok(back) if back == f
    ));
}

#[test]
fn the_envelope_a_frame_rebuilds_covers_the_statement_line_only() {
    // Two records that differ only in their base64 fields rebuild
    // envelopes with the same payload; the signature is checked over the
    // PAE of that payload, so the fields cannot move it.
    let a = Frame::decode(&record(STATEMENT, &sig_frame(1, b"k1", &[1; 10]), &[1])).unwrap();
    let b = Frame::decode(&record(
        STATEMENT,
        &sig_frame(1, b"k2", &[2; 20]),
        &[2; 500],
    ))
    .unwrap();
    let (ea, eb) = (Envelope::from_frame(&a), Envelope::from_frame(&b));
    assert_eq!(ea.payload, eb.payload);
    assert_eq!(ea.payload_type, eb.payload_type);
    assert_ne!(ea.signatures, eb.signatures);
    // A statement line that differs by one byte is another payload.
    let c = Frame::decode(&record(
        &STATEMENT.replace("\"t\"", "\"u\""),
        &sig_frame(1, b"k1", &[1; 10]),
        &[1],
    ))
    .unwrap();
    assert_ne!(Envelope::from_frame(&c).payload, ea.payload);
    // The stored JSON of a frame holds the statement as base64 of the
    // line, byte for byte, and parses back to the same envelope.
    let json = a.to_stored_json();
    let back = Envelope::from_json(&json).unwrap();
    assert_eq!(back, ea);
    assert_eq!(
        STANDARD.decode(&back.payload).unwrap(),
        STATEMENT.as_bytes()
    );
}
