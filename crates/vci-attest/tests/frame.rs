//! The format-3 frame against real records: a vex unit's SSH-signed
//! envelope as `vci run` 2.8 stored it (tests/fixtures/frame/pair0-envelope.json,
//! unit 0 of the 1,175-unit sample STORE-V2 was measured on) and the keyless
//! fixture of tests/fixtures/keyless.

use base64::Engine as _;
use ssh_key::{HashAlg, PublicKey, SshSig};
use vci_attest::keyless::{material_from_json, to_stored_json};
use vci_attest::{AllowedSigners, Envelope, Frame, FrameSig, is_frame, verify_envelope};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).unwrap()
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

#[test]
fn a_real_vex_record_becomes_a_frame_and_comes_back_byte_for_byte() {
    let stored = read("frame/pair0-envelope.json");
    let envelope = Envelope::from_json(&stored).unwrap();
    let descriptor: Vec<u8> = (0..=255).collect();

    let frame = Frame::from_stored_json(&stored, descriptor.clone()).unwrap();
    assert_eq!(frame.statement, b64(&envelope.payload));
    assert!(
        frame
            .statement
            .starts_with(br#"{"_type":"https://in-toto.io/Statement/v1""#)
    );
    assert_eq!(frame.statement.len(), 15_885);
    assert_eq!(
        frame.keyid,
        "SHA256:JMGwSg92DBOfvirgRPTn4rYsH0hnx9wpYXhm+FqGHlc"
    );
    let FrameSig::SshSig(blob) = &frame.sig else {
        panic!("an SSH-signed record");
    };
    assert_eq!(blob.len(), 180);
    assert!(blob.starts_with(b"SSHSIG"));
    assert_eq!(frame.descriptor, descriptor);
    assert_eq!(frame.sigstore(), None);

    // The record: first line, the statement as it is, 312 B of base64 for
    // the 234 B signature frame, the descriptor.
    let text = frame.encode().unwrap();
    assert!(is_frame(text.as_bytes()));
    let lines: Vec<&str> = text.split('\n').collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[0], "vci3");
    assert_eq!(lines[1].as_bytes(), frame.statement.as_slice());
    assert_eq!(lines[2].len(), 312);
    assert_eq!(lines[3].len(), 344);
    assert_eq!(text.len(), 5 + 15_885 + 1 + 312 + 1 + 344);

    // Back: the same frame, and today's stored value byte for byte.
    let back = Frame::decode(text.as_bytes()).unwrap();
    assert_eq!(back, frame);
    assert_eq!(back.to_stored_json(), stored);
    assert_eq!(Envelope::from_frame(&back), envelope);

    // The re-armored SSHSIG is the signature the record was stored with,
    // and it verifies over the frame's statement bytes with its own key.
    let pem = b64(&envelope.signatures[0].sig);
    let rebuilt = b64(&Envelope::from_frame(&back).signatures[0].sig);
    assert_eq!(rebuilt, pem);
    let sshsig = SshSig::from_pem(&pem).unwrap();
    let key = PublicKey::new(sshsig.public_key().clone(), "");
    assert_eq!(key.fingerprint(HashAlg::Sha256).to_string(), frame.keyid);
    let allowed = AllowedSigners::parse(&format!("vex {}\n", key.to_openssh().unwrap())).unwrap();
    let v = verify_envelope(&Envelope::from_frame(&back), &allowed, 1_800_000_000).unwrap();
    assert_eq!(v.payload, frame.statement);
    assert_eq!(v.fingerprint, frame.keyid);
    assert_eq!(
        v.statement.subject[0].name,
        "vex-api/test/services/builders/gateway_endpoint_test.rb"
    );
}

#[test]
fn a_real_keyless_record_becomes_a_frame_and_comes_back_whole() {
    for name in ["keyless/envelope.json", "keyless/github-pr10-envelope.json"] {
        let pretty = read(name);
        let envelope = Envelope::from_json(&pretty).unwrap();
        let material = material_from_json(&pretty)
            .unwrap()
            .expect("sigstore member");
        let stored = to_stored_json(&envelope, &material);

        let frame = Frame::from_stored_json(&stored, vec![1, 2, 3]).unwrap();
        assert_eq!(frame.statement, b64(&envelope.payload));
        assert_eq!(frame.keyid, envelope.signatures[0].keyid);
        assert_eq!(
            frame.sig,
            FrameSig::Bundle {
                sig: envelope.signatures[0].sig.clone(),
                material: material.clone()
            }
        );
        assert_eq!(frame.sigstore(), Some(&material));

        let text = frame.encode().unwrap();
        let back = Frame::decode(text.as_bytes()).unwrap();
        assert_eq!(back, frame, "{name}");
        assert_eq!(back.to_stored_json(), stored, "{name}");
        assert_eq!(Envelope::from_frame(&back), envelope, "{name}");
        assert_eq!(
            material_from_json(&back.to_stored_json()).unwrap().unwrap(),
            material,
            "{name}"
        );
    }
}
