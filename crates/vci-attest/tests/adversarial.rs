//! Adversarial records for the format-3 frame decoder (`design/STORE-V2.md`
//! section 1.6 rule 1 and 2, section 4): malformed, oversized, truncated,
//! section-confusing and non-canonical values built by hand. Every attack
//! must be refused with an error, never a panic, and nothing a frame's
//! base64 fields carry may change the bytes the signature is checked over.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use vci_attest::{
    Envelope, FRAME_FIRST_LINE, Frame, FrameError, FrameSig, MAX_RECORD, PAYLOAD_TYPE, VarintError,
    is_frame,
};

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

fn err(value: &[u8]) -> FrameError {
    Frame::decode(value).expect_err("must be refused")
}

#[test]
fn the_good_record_decodes_to_the_statement_bytes_as_found() {
    let f = Frame::decode(&good()).unwrap();
    assert_eq!(f.statement, STATEMENT.as_bytes());
    assert_eq!(f.keyid, "SHA256:k");
    assert_eq!(f.sig, FrameSig::SshSig(vec![9; 180]));
    assert_eq!(f.descriptor, [1, 2, 3]);
    let e = Envelope::from_frame(&f);
    assert_eq!(e.payload_type, PAYLOAD_TYPE);
    assert_eq!(STANDARD.decode(&e.payload).unwrap(), STATEMENT.as_bytes());
    assert_eq!(e.signatures.len(), 1);
    assert_eq!(FRAME_FIRST_LINE, "vci3");
}

#[test]
fn every_truncation_and_every_byte_value_of_a_record_is_refused_or_decoded_without_panic() {
    let g = good();
    // A cut inside the descriptor line at a multiple of four base64
    // characters is a shorter descriptor (its binding is the root, not
    // the frame); every other cut is refused.
    let descriptor_line = g.iter().rposition(|&b| b == b'\n').unwrap() + 1;
    for n in 0..g.len() {
        let r = Frame::decode(&g[..n]);
        if n >= descriptor_line && (n - descriptor_line) % 4 == 0 {
            assert!(r.is_ok(), "prefix {n}");
        } else {
            assert!(r.is_err(), "prefix {n}");
        }
    }
    let mut buf = g.clone();
    for i in 0..g.len() {
        for v in 0..=255u8 {
            buf[i] = v;
            let _ = Frame::decode(&buf);
        }
        buf[i] = g[i];
    }
    // Inside the signature frame too (the base64 hides single-byte flips
    // from the outer loop).
    let sf = sig_frame(1, b"SHA256:k", &[9; 180]);
    let mut buf = sf.clone();
    for i in 0..sf.len() {
        for v in 0..=255u8 {
            buf[i] = v;
            let _ = Frame::decode(&record(STATEMENT, &buf, &[1]));
        }
        buf[i] = sf[i];
    }
    for n in 0..sf.len() {
        assert!(
            Frame::decode(&record(STATEMENT, &sf[..n], &[1])).is_err(),
            "signature frame prefix {n}"
        );
    }
}

#[test]
fn a_format_1_value_and_a_frame_cannot_be_mistaken_for_each_other() {
    // Format 1 starts with `{`: routed away whatever follows.
    assert_eq!(err(b"{"), FrameError::NotAFrame);
    assert_eq!(err(b"{}"), FrameError::NotAFrame);
    assert_eq!(err(b"{\"payloadType\":\"x\"}"), FrameError::NotAFrame);
    assert_eq!(err(b"{vci3\n"), FrameError::NotAFrame);
    assert!(!is_frame(b"{"));
    // A JSON value that is not an object, or has leading whitespace or a
    // BOM, is neither: it fails the first line, and is not routed to the
    // format-1 path.
    for v in [
        &b" {}"[..],
        b"\n{}",
        b"\t{}",
        b"\xef\xbb\xbf{}",
        b"[]",
        b"\"vci3\"",
        b"null",
        b"",
        b"v",
        b"vci",
        b"vci3",
        b"vci30\n",
        b"VCI3\n",
        b"vci3 \n",
        b"vci3\r\n",
        b" vci3\n",
        b"\xef\xbb\xbfvci3\n",
        b"vci2\n",
        b"vci4\n",
        b"vci3z\n",
        b"vci3\0\n",
    ] {
        let e = err(v);
        assert!(
            matches!(
                e,
                FrameError::FirstLine(_) | FrameError::Nul | FrameError::NotUtf8
            ),
            "{:?}: {e:?}",
            String::from_utf8_lossy(v)
        );
        assert_ne!(e, FrameError::NotAFrame);
    }
    assert!(is_frame(b"vci3\n"));
    assert!(is_frame(b"v"));
    // A frame's first line is never valid JSON, and a frame's statement
    // line is never `vci3`.
    assert!(Envelope::from_json(&good()).is_err());
    let e = err(b"vci3\nvci3\nAA==\nAA==");
    assert_eq!(e, FrameError::StatementStart('v'));
    // A frame inside a frame: the statement line holding a whole record is
    // more line feeds.
    let mut nested = b"vci3\n".to_vec();
    nested.extend_from_slice(&good());
    nested.extend_from_slice(b"\nAA==\nAA==");
    assert_eq!(err(&nested), FrameError::Lines(6));
}

#[test]
fn the_line_structure_is_exact() {
    assert_eq!(err(b"vci3\n"), FrameError::Lines(1));
    assert_eq!(err(b"vci3\n{}"), FrameError::Lines(1));
    assert_eq!(err(b"vci3\n{}\n"), FrameError::Lines(2));
    assert_eq!(err(b"vci3\n{}\nAA=="), FrameError::Lines(2));
    assert_eq!(err(b"vci3\n{}\nAA==\nAA==\n"), FrameError::Lines(4));
    assert_eq!(err(b"vci3\n{}\nAA==\nAA==\nAA=="), FrameError::Lines(4));
    assert_eq!(err(b"vci3\n{}\n\nAA==\nAA=="), FrameError::Lines(4));
    // A CR is not a line end; CRLF breaks the first line and the base64.
    assert!(matches!(
        err(b"vci3\r\n{}\r\nAA==\r\nAA=="),
        FrameError::FirstLine(_)
    ));
    // A CR before the statement's LF stays in the statement: the bytes are
    // taken as found (a signature over them would not verify).
    let cr = format!("vci3\n{{}}\r\n{}\nAA==", b64(&sig_frame(1, b"k", &[1])));
    assert_eq!(Frame::decode(cr.as_bytes()).unwrap().statement, b"{}\r");
    // The statement line.
    assert_eq!(err(b"vci3\n\nAA==\nAA=="), FrameError::EmptyStatement);
    assert_eq!(
        err(b"vci3\n {}\nAA==\nAA=="),
        FrameError::StatementStart(' ')
    );
    assert_eq!(
        err(b"vci3\n[]\nAA==\nAA=="),
        FrameError::StatementStart('[')
    );
    assert_eq!(
        err(b"vci3\n\xc3\xa9\nAA==\nAA=="),
        FrameError::StatementStart('\u{e9}')
    );
    assert_eq!(err(b"vci3\n{\0}\nAA==\nAA=="), FrameError::Nul);
    assert_eq!(err(b"vci3\n{\xff}\nAA==\nAA=="), FrameError::NotUtf8);
    // The statement is not parsed here: any bytes starting with `{` and
    // free of LF and NUL are the statement, exactly as found.
    let f = Frame::decode(&record("{not json", &sig_frame(1, b"", &[1]), &[])).unwrap();
    assert_eq!(f.statement, b"{not json");
    let f = Frame::decode(&record("{\r\t }", &sig_frame(1, b"", &[1]), &[])).unwrap();
    assert_eq!(f.statement, b"{\r\t }");
}

#[test]
fn the_record_bound_and_the_encoding_are_checked_first() {
    let mut big = good();
    let pad = MAX_RECORD + 1 - big.len();
    // Pad the descriptor with canonical base64 so the content is valid
    // but the size is not.
    let extra = b64(&vec![0u8; pad / 4 * 3]);
    big.extend_from_slice(extra.as_bytes());
    assert!(big.len() > MAX_RECORD);
    assert!(matches!(err(&big), FrameError::TooLarge(n) if n == big.len()));
    // Not UTF-8, in the first line, the statement or the base64: NotUtf8
    // (the line structure is never looked at).
    assert_eq!(err(b"vci3\xff\n{}\nAA==\nAA=="), FrameError::NotUtf8);
    assert_eq!(err(b"vci3\n{}\nAA==\n\xff"), FrameError::NotUtf8);
    // A NUL anywhere.
    assert_eq!(err(b"vci3\n{}\nAA==\nAA==\0"), FrameError::Nul);
    assert_eq!(err(b"vci3\0\n{}\nAA==\nAA=="), FrameError::Nul);
    // A record of exactly 1 MiB that is otherwise valid decodes.
    let sf = sig_frame(1, b"k", &[1]);
    let fixed = format!("vci3\n{STATEMENT}\n{}\n", b64(&sf)).len();
    let desc_len = (MAX_RECORD - fixed) / 4 * 3;
    let desc = vec![7u8; desc_len];
    let r = record(STATEMENT, &sf, &desc);
    assert!(r.len() <= MAX_RECORD && r.len() > MAX_RECORD - 4);
    assert_eq!(Frame::decode(&r).unwrap().descriptor.len(), desc_len);
}

#[test]
fn base64_fields_must_be_canonical() {
    let sf = b64(&sig_frame(1, b"k", &[1]));
    let rec = |sig: &str, desc: &str| format!("vci3\n{STATEMENT}\n{sig}\n{desc}").into_bytes();
    let bad_desc: [&str; 12] = [
        "AQ",        // missing padding
        "AQ=",       // short padding
        "AQ===",     // long padding
        "AR==",      // trailing bits set (Q == 010000, R == 010001)
        "AQ== ",     // trailing space
        " AQ==",     // leading space
        "AQ=A",      // padding inside
        "A===",      // one character
        "A",         // length not a multiple of 4
        "AQ-_",      // URL-safe alphabet
        "AQ==\r",    // CR
        "\u{e9}Q==", // non-ASCII
    ];
    for d in bad_desc {
        let e = err(&rec(&sf, d));
        assert!(
            matches!(
                e,
                FrameError::Base64 {
                    field: "descriptor",
                    ..
                }
            ),
            "{d:?}: {e:?}"
        );
        let e = err(&rec(d, "AQ=="));
        assert!(
            matches!(
                e,
                FrameError::Base64 {
                    field: "signature",
                    ..
                }
            ),
            "{d:?} as signature: {e:?}"
        );
    }
    // Canonical forms with set trailing bits refused, zero accepted.
    assert!(Frame::decode(&rec(&sf, "AQ==")).is_ok());
    assert!(Frame::decode(&rec(&sf, "AQI=")).is_ok());
    assert!(matches!(
        err(&rec(&sf, "AQJ=")),
        FrameError::Base64 {
            field: "descriptor",
            ..
        }
    ));
    // An empty descriptor is an empty base64 line.
    assert_eq!(
        Frame::decode(&rec(&sf, "")).unwrap().descriptor,
        Vec::<u8>::new()
    );
    // An empty signature field is a truncated signature frame.
    assert_eq!(
        err(&rec("", "AQ==")),
        FrameError::Truncated("signature kind")
    );
}

#[test]
fn the_signature_frame_is_read_within_its_bytes() {
    let rec = |sf: &[u8]| record(STATEMENT, sf, &[1]);
    // Kinds.
    for k in [0u8, 3, 4, 0x81, 0xff] {
        assert_eq!(err(&rec(&sig_frame(k, b"k", &[1]))), FrameError::SigKind(k));
    }
    // Lengths past the bytes.
    let mut sf = vec![1];
    uv(&mut sf, 5);
    sf.extend_from_slice(b"ab");
    assert_eq!(err(&rec(&sf)), FrameError::Truncated("keyid"));
    let mut sf = vec![1];
    uv(&mut sf, 1 << 40);
    assert_eq!(err(&rec(&sf)), FrameError::Truncated("keyid"));
    let mut sf = vec![1];
    uv(&mut sf, 0);
    uv(&mut sf, 3);
    sf.extend_from_slice(b"ab");
    assert_eq!(err(&rec(&sf)), FrameError::Truncated("signature"));
    let mut sf = vec![1];
    uv(&mut sf, 0);
    uv(&mut sf, u64::MAX);
    assert_eq!(err(&rec(&sf)), FrameError::Truncated("signature"));
    let mut sf = vec![1];
    uv(&mut sf, 0);
    assert_eq!(
        err(&rec(&sf)),
        FrameError::Varint {
            what: "signature",
            err: VarintError::Truncated
        }
    );
    assert_eq!(
        err(&rec(&[1])),
        FrameError::Varint {
            what: "keyid",
            err: VarintError::Truncated
        }
    );
    // Empty signature, trailing bytes, non-UTF-8 keyid.
    assert_eq!(
        err(&rec(&sig_frame(1, b"k", b""))),
        FrameError::EmptySignature
    );
    let mut sf = sig_frame(1, b"k", &[1]);
    sf.push(0);
    assert_eq!(err(&rec(&sf)), FrameError::TrailingBytes(1));
    sf.extend_from_slice(&[0; 9]);
    assert_eq!(err(&rec(&sf)), FrameError::TrailingBytes(10));
    assert_eq!(
        err(&rec(&sig_frame(1, b"\xff", &[1]))),
        FrameError::KeyidUtf8
    );
    // Varints: non-minimal, too long, past u64::MAX, cut.
    let with_len = |bytes: &[u8]| {
        let mut sf = vec![1];
        sf.extend_from_slice(bytes);
        sf.push(b'k');
        uv(&mut sf, 1);
        sf.push(1);
        sf
    };
    assert_eq!(
        err(&rec(&with_len(&[0x81, 0x00]))),
        FrameError::Varint {
            what: "keyid",
            err: VarintError::NonMinimal
        }
    );
    assert_eq!(
        err(&rec(&with_len(&[0x80, 0x00]))),
        FrameError::Varint {
            what: "keyid",
            err: VarintError::NonMinimal
        }
    );
    let mut long = vec![0x80; 10];
    long.push(0x01);
    assert_eq!(
        err(&rec(&with_len(&long))),
        FrameError::Varint {
            what: "keyid",
            err: VarintError::TooLong
        }
    );
    let mut over = vec![0xff; 9];
    over.push(0x02);
    assert_eq!(
        err(&rec(&with_len(&over))),
        FrameError::Varint {
            what: "keyid",
            err: VarintError::Overflow
        }
    );
    let mut ten_zero = vec![0x80; 9];
    ten_zero.push(0x00);
    assert_eq!(
        err(&rec(&with_len(&ten_zero))),
        FrameError::Varint {
            what: "keyid",
            err: VarintError::NonMinimal
        }
    );
    assert_eq!(
        err(&rec(&[1, 0x80])),
        FrameError::Varint {
            what: "keyid",
            err: VarintError::Truncated
        }
    );
    // u64::MAX as a 10-byte minimal varint is read, then refused as a
    // length past the bytes.
    let mut sf = vec![1];
    sf.extend_from_slice(&[0xff; 9]);
    sf.push(0x01);
    assert_eq!(err(&rec(&sf)), FrameError::Truncated("keyid"));
    // The keyid may hold anything UTF-8, line feeds and NUL included: it
    // is a hint, never parsed.
    let f = Frame::decode(&rec(&sig_frame(1, b"k\n\0id", &[1]))).unwrap();
    assert_eq!(f.keyid, "k\n\0id");
    assert_eq!(Envelope::from_frame(&f).signatures[0].keyid, "k\n\0id");
    // Section confusion: an SSHSIG blob that holds a whole signature
    // frame, or JSON, is just the blob.
    let inner = sig_frame(2, b"x", b"{}");
    let f = Frame::decode(&rec(&sig_frame(1, b"k", &inner))).unwrap();
    assert_eq!(f.sig, FrameSig::SshSig(inner));
}

#[test]
fn a_bundle_signature_is_json_of_exactly_sig_and_sigstore() {
    let rec = |json: &[u8]| record(STATEMENT, &sig_frame(2, b"", json), &[1]);
    for json in [
        &b"{}"[..],
        b"[]",
        b"null",
        b"{\"sig\":\"x\"}",
        b"{\"sigstore\":{\"mediaType\":\"m\",\"verificationMaterial\":{}}}",
        b"{\"sig\":\"x\",\"sigstore\":{\"mediaType\":\"m\",\"verificationMaterial\":{}},\"extra\":1}",
        b"{\"sig\":1,\"sigstore\":{\"mediaType\":\"m\",\"verificationMaterial\":{}}}",
        b"{\"sig\":\"x\",\"sigstore\":null}",
        b"{\"sig\":\"x\",\"sigstore\":\"s\"}",
        b"{\"sig\":\"x\",\"sigstore\":{}}",
        b"{\"sig\":\"x\",\"sigstore\":{\"mediaType\":\"m\",\"verificationMaterial\":{}}",
        b"\xff",
    ] {
        let e = err(&rec(json));
        assert!(
            matches!(e, FrameError::Json(_)),
            "{:?}: {e:?}",
            String::from_utf8_lossy(json)
        );
    }
    // serde_json takes trailing whitespace, so kind 2's JSON has more than
    // one spelling; the signature frame is not content-addressed, so
    // nothing keys on it.
    assert!(
        Frame::decode(&rec(
            b"{\"sig\":\"x\",\"sigstore\":{\"mediaType\":\"m\",\"verificationMaterial\":{}}} "
        ))
        .is_ok()
    );
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
    // Deep nesting is bounded by serde_json.
    let deep = format!(
        "{{\"sig\":{}1{},\"sigstore\":null}}",
        "[".repeat(200_000),
        "]".repeat(200_000)
    );
    assert!(matches!(err(&rec(deep.as_bytes())), FrameError::Json(_)));
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
