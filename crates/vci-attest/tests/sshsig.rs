//! End-to-end tests against real `ssh-keygen` with throwaway ed25519 keys.

mod common;

use base64::Engine as _;
use common::*;
use vci_attest::*;

fn allowed(text: &str) -> AllowedSigners {
    AllowedSigners::parse(text).expect("allowed_signers parses")
}

fn signed(key: &Key, n: u32) -> Envelope {
    sign_statement(&statement(n), &key.private).expect("sign")
}

#[test]
fn round_trip() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let st = statement(1);
    let env = sign_statement(&st, &key.private).unwrap();

    assert_eq!(env.payload_type, PAYLOAD_TYPE);
    assert_eq!(env.signatures.len(), 1);
    assert_eq!(env.signatures[0].keyid, key.fingerprint);
    assert!(sig_pem(&env, 0).starts_with("-----BEGIN SSH SIGNATURE-----"));

    // Through JSON and back, as it would be stored.
    let env = Envelope::from_json(&env.to_json()).unwrap();
    let a = allowed(&format!("alice@example.com {}\n", key.pub_line));
    let v = verify_envelope(&env, &a, now()).unwrap();
    assert_eq!(v.principal, "alice@example.com");
    assert_eq!(v.fingerprint, key.fingerprint);
    assert_eq!(v.statement, st);
    assert_eq!(v.payload, b64().decode(&env.payload).unwrap());
    assert_eq!(v.payload, serde_json::to_vec(&st).unwrap());
}

#[test]
fn openssh_accepts_our_signature_over_pae() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let env = signed(&key, 1);
    let payload = b64().decode(&env.payload).unwrap();
    let message = pae(PAYLOAD_TYPE, &payload);
    let allowed_text = format!("alice@example.com {}\n", key.pub_line);

    assert!(openssh_verify(
        &dir,
        &allowed_text,
        "alice@example.com",
        NAMESPACE,
        &sig_pem(&env, 0),
        &message
    ));

    // The cross-check is not vacuous: OpenSSH rejects a tampered PAE, the raw
    // payload without PAE, and another namespace.
    let mut tampered = message.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(!openssh_verify(
        &dir,
        &allowed_text,
        "alice@example.com",
        NAMESPACE,
        &sig_pem(&env, 0),
        &tampered
    ));
    assert!(!openssh_verify(
        &dir,
        &allowed_text,
        "alice@example.com",
        NAMESPACE,
        &sig_pem(&env, 0),
        &payload
    ));
    assert!(!openssh_verify(
        &dir,
        &allowed_text,
        "alice@example.com",
        "git",
        &sig_pem(&env, 0),
        &message
    ));
}

#[test]
fn we_accept_openssh_signature_made_directly_over_pae() {
    // Independent of sign_statement: sign PAE bytes with ssh-keygen ourselves,
    // using both supported hash algorithms.
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let payload = serde_json::to_vec(&statement(3)).unwrap();
    let a = allowed(&format!("alice@example.com {}\n", key.pub_line));
    for hashalg in ["sha512", "sha256"] {
        let pem = raw_sign(
            &key,
            NAMESPACE,
            &pae(PAYLOAD_TYPE, &payload),
            &["-O", &format!("hashalg={hashalg}")],
        );
        let env = Envelope {
            payload_type: PAYLOAD_TYPE.into(),
            payload: b64().encode(&payload),
            signatures: vec![Signature {
                keyid: String::new(),
                sig: b64().encode(pem.as_bytes()),
            }],
        };
        let v = verify_envelope(&env, &a, now()).unwrap_or_else(|e| panic!("{hashalg}: {e}"));
        assert_eq!(v.payload, payload);
    }
}

#[test]
fn verifies_exact_stored_bytes_never_reserialises() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    // Valid statement JSON with odd key order and whitespace: not what serde would emit.
    let raw = br#"{ "predicate": {"z":1, "a":2},
  "predicateType":"https://vci.dev/test-attestation/v1", "subject":[{"digest":{"blake3":"00"},"name":"x"}],
  "_type":"https://in-toto.io/Statement/v1" }"#
        .to_vec();
    let env = sign_payload(&raw, &key.private).unwrap();
    let a = allowed(&format!("alice@example.com {}\n", key.pub_line));
    let v = verify_envelope(&env, &a, now()).unwrap();
    assert_eq!(
        v.payload, raw,
        "Verified.payload must be the exact signed bytes"
    );
    let reserialised = serde_json::to_vec(&v.statement).unwrap();
    assert_ne!(reserialised, raw);

    // Swapping in the canonical re-serialisation (same Statement value!) must fail:
    // the signature covers bytes, not the parsed value.
    let mut swapped = env.clone();
    swapped.payload = b64().encode(&reserialised);
    assert!(matches!(
        verify_envelope(&swapped, &a, now()),
        Err(VerifyError::BadSignature(_))
    ));
}

#[test]
fn one_byte_payload_tamper_is_rejected_at_every_position() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let env = signed(&key, 1);
    let a = allowed(&format!("alice@example.com {}\n", key.pub_line));
    let payload = b64().decode(&env.payload).unwrap();
    for i in 0..payload.len() {
        let mut p = payload.clone();
        p[i] ^= 0x01;
        let mut t = env.clone();
        t.payload = b64().encode(&p);
        match verify_envelope(&t, &a, now()) {
            Err(VerifyError::BadSignature(_)) => {}
            other => panic!("byte {i}: expected BadSignature, got {other:?}"),
        }
    }
    // Appending a byte is also caught (PAE length changes).
    let mut p = payload.clone();
    p.push(b' ');
    let mut t = env.clone();
    t.payload = b64().encode(&p);
    assert!(matches!(
        verify_envelope(&t, &a, now()),
        Err(VerifyError::BadSignature(_))
    ));
    // Untouched still verifies.
    verify_envelope(&env, &a, now()).unwrap();
}

#[test]
fn signature_swapped_from_another_envelope_is_rejected() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let e1 = signed(&key, 1);
    let e2 = signed(&key, 2);
    let a = allowed(&format!("alice@example.com {}\n", key.pub_line));
    let mut franken = e1.clone();
    franken.signatures = e2.signatures.clone();
    assert!(matches!(
        verify_envelope(&franken, &a, now()),
        Err(VerifyError::BadSignature(_))
    ));
    verify_envelope(&e1, &a, now()).unwrap();
    verify_envelope(&e2, &a, now()).unwrap();
}

#[test]
fn wrong_signature_namespace_is_rejected() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let payload = serde_json::to_vec(&statement(1)).unwrap();
    let message = pae(PAYLOAD_TYPE, &payload);
    let pem = raw_sign(&key, "git", &message, &[]);
    let env = Envelope {
        payload_type: PAYLOAD_TYPE.into(),
        payload: b64().encode(&payload),
        signatures: vec![Signature {
            keyid: key.fingerprint.clone(),
            sig: b64().encode(pem.as_bytes()),
        }],
    };
    let allowed_text = format!("alice@example.com {}\n", key.pub_line);
    assert!(matches!(
        verify_envelope(&env, &allowed(&allowed_text), now()),
        Err(VerifyError::WrongNamespace(_))
    ));
    assert!(!openssh_verify(
        &dir,
        &allowed_text,
        "alice@example.com",
        NAMESPACE,
        &pem,
        &message
    ));
}

#[test]
fn signer_missing_from_allowed_signers_is_rejected() {
    let (_t, dir) = tempdir();
    let alice = keygen(&dir, "alice");
    let mallory = keygen(&dir, "mallory");
    let env = signed(&mallory, 1);
    let allowed_text = format!("alice@example.com {}\n", alice.pub_line);
    match verify_envelope(&env, &allowed(&allowed_text), now()) {
        Err(VerifyError::UnknownSigner(fp)) => assert_eq!(fp, mallory.fingerprint),
        other => panic!("expected UnknownSigner, got {other:?}"),
    }
    // Lying about keyid changes nothing.
    let mut lying = env.clone();
    lying.signatures[0].keyid = alice.fingerprint.clone();
    assert!(matches!(
        verify_envelope(&lying, &allowed(&allowed_text), now()),
        Err(VerifyError::UnknownSigner(_))
    ));
    // An empty allowed_signers trusts no one.
    assert!(matches!(
        verify_envelope(&env, &allowed("# nobody\n"), now()),
        Err(VerifyError::UnknownSigner(_))
    ));

    let message = pae(PAYLOAD_TYPE, &b64().decode(&env.payload).unwrap());
    assert!(!openssh_verify(
        &dir,
        &allowed_text,
        "alice@example.com",
        NAMESPACE,
        &sig_pem(&env, 0),
        &message
    ));
}

#[test]
fn expired_valid_before_is_rejected() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let env = signed(&key, 1);
    let allowed_text = format!(
        "alice@example.com valid-before=\"20000101Z\" {}\n",
        key.pub_line
    );
    assert!(matches!(
        verify_envelope(&env, &allowed(&allowed_text), now()),
        Err(VerifyError::SignerNotValidNow(_))
    ));
    let message = pae(PAYLOAD_TYPE, &b64().decode(&env.payload).unwrap());
    assert!(!openssh_verify(
        &dir,
        &allowed_text,
        "alice@example.com",
        NAMESPACE,
        &sig_pem(&env, 0),
        &message
    ));

    // `now` is honoured exactly: 2030-01-01T00:00:00Z = 1893456000, inclusive.
    let a = allowed(&format!(
        "alice@example.com valid-before=\"20300101Z\" {}\n",
        key.pub_line
    ));
    verify_envelope(&env, &a, 1893456000).unwrap();
    assert!(matches!(
        verify_envelope(&env, &a, 1893456001),
        Err(VerifyError::SignerNotValidNow(_))
    ));
}

#[test]
fn not_yet_valid_valid_after_is_rejected() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let env = signed(&key, 1);
    let allowed_text = format!(
        "alice@example.com valid-after=\"29990101\" {}\n",
        key.pub_line
    );
    assert!(matches!(
        verify_envelope(&env, &allowed(&allowed_text), now()),
        Err(VerifyError::SignerNotValidNow(_))
    ));
    let message = pae(PAYLOAD_TYPE, &b64().decode(&env.payload).unwrap());
    assert!(!openssh_verify(
        &dir,
        &allowed_text,
        "alice@example.com",
        NAMESPACE,
        &sig_pem(&env, 0),
        &message
    ));

    let a = allowed(&format!(
        "alice@example.com valid-after=\"20300101Z\" {}\n",
        key.pub_line
    ));
    assert!(matches!(
        verify_envelope(&env, &a, 1893455999),
        Err(VerifyError::SignerNotValidNow(_))
    ));
    verify_envelope(&env, &a, 1893456000).unwrap();

    // Inside a window: accepted by us and by OpenSSH.
    let ok_text = format!(
        "alice@example.com valid-after=\"20200101Z\",valid-before=\"29990101Z\" {}\n",
        key.pub_line
    );
    verify_envelope(&env, &allowed(&ok_text), now()).unwrap();
    assert!(openssh_verify(
        &dir,
        &ok_text,
        "alice@example.com",
        NAMESPACE,
        &sig_pem(&env, 0),
        &message
    ));
}

#[test]
fn namespaces_option_excluding_ours_is_rejected() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let env = signed(&key, 1);
    let message = pae(PAYLOAD_TYPE, &b64().decode(&env.payload).unwrap());
    let pem = sig_pem(&env, 0);

    for ns in ["git,file", "vci", "*,!vci-attest"] {
        let text = format!("alice@example.com namespaces=\"{ns}\" {}\n", key.pub_line);
        assert!(
            matches!(
                verify_envelope(&env, &allowed(&text), now()),
                Err(VerifyError::WrongNamespace(_))
            ),
            "namespaces={ns}"
        );
        assert!(
            !openssh_verify(&dir, &text, "alice@example.com", NAMESPACE, &pem, &message),
            "openssh namespaces={ns}"
        );
    }
    for ns in ["vci-attest", "git,vci-attest", "vci-*"] {
        let text = format!("alice@example.com namespaces=\"{ns}\" {}\n", key.pub_line);
        verify_envelope(&env, &allowed(&text), now())
            .unwrap_or_else(|e| panic!("namespaces={ns}: {e}"));
        assert!(
            openssh_verify(&dir, &text, "alice@example.com", NAMESPACE, &pem, &message),
            "openssh namespaces={ns}"
        );
    }
}

#[test]
fn cert_authority_line_is_rejected() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let env = signed(&key, 1);
    let text = format!("*@example.com cert-authority {}\n", key.pub_line);
    match verify_envelope(&env, &allowed(&text), now()) {
        Err(VerifyError::CertAuthorityRejected(fp)) => assert_eq!(fp, key.fingerprint),
        other => panic!("expected CertAuthorityRejected, got {other:?}"),
    }
    let message = pae(PAYLOAD_TYPE, &b64().decode(&env.payload).unwrap());
    assert!(!openssh_verify(
        &dir,
        &text,
        "alice@example.com",
        NAMESPACE,
        &sig_pem(&env, 0),
        &message
    ));

    // A separate plain line for the same key still authorises it.
    let both = format!("{text}alice@example.com {}\n", key.pub_line);
    assert_eq!(
        verify_envelope(&env, &allowed(&both), now())
            .unwrap()
            .principal,
        "alice@example.com"
    );
}

#[test]
fn envelope_with_zero_signatures_is_rejected() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let mut env = signed(&key, 1);
    env.signatures.clear();
    let a = allowed(&format!("alice@example.com {}\n", key.pub_line));
    assert_eq!(
        verify_envelope(&env, &a, now()),
        Err(VerifyError::NoSignatures)
    );
    // Missing `signatures` field entirely.
    let json = format!(
        r#"{{"payloadType":"{PAYLOAD_TYPE}","payload":"{}"}}"#,
        env.payload
    );
    let parsed = Envelope::from_json(json.as_bytes()).unwrap();
    assert_eq!(
        verify_envelope(&parsed, &a, now()),
        Err(VerifyError::NoSignatures)
    );
}

#[test]
fn wrong_payload_type_is_rejected() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let mut env = signed(&key, 1);
    env.payload_type = "application/json".into();
    let a = allowed(&format!("alice@example.com {}\n", key.pub_line));
    assert!(matches!(
        verify_envelope(&env, &a, now()),
        Err(VerifyError::WrongPayloadType(_))
    ));
}

#[test]
fn malformed_signatures_and_payloads_are_rejected() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let env = signed(&key, 1);
    let a = allowed(&format!("alice@example.com {}\n", key.pub_line));

    let mut e = env.clone();
    e.signatures[0].sig = "not base64!".into();
    assert!(matches!(
        verify_envelope(&e, &a, now()),
        Err(VerifyError::Malformed(_))
    ));

    let mut e = env.clone();
    e.signatures[0].sig =
        b64().encode(b"-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n");
    assert!(matches!(
        verify_envelope(&e, &a, now()),
        Err(VerifyError::Malformed(_))
    ));

    let mut e = env.clone();
    e.payload.push('!');
    assert!(matches!(
        verify_envelope(&e, &a, now()),
        Err(VerifyError::Malformed(_))
    ));

    // Validly signed payload that is not an in-toto Statement v1.
    let bad = sign_payload(br#"{"_type":"https://in-toto.io/Statement/v0.1","subject":[],"predicateType":"x","predicate":{}}"#, &key.private).unwrap();
    assert!(matches!(
        verify_envelope(&bad, &a, now()),
        Err(VerifyError::Malformed(_))
    ));
    let bad = sign_payload(b"not json", &key.private).unwrap();
    assert!(matches!(
        verify_envelope(&bad, &a, now()),
        Err(VerifyError::Malformed(_))
    ));
}

/// Split an SSHSIG binary blob into (preamble+version, [pubkey, ns, reserved, hashalg, sig]).
fn split_sshsig(blob: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    assert_eq!(&blob[..6], b"SSHSIG");
    let head = blob[..10].to_vec();
    let mut rest = &blob[10..];
    let mut fields = Vec::new();
    for _ in 0..5 {
        let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        fields.push(rest[4..4 + n].to_vec());
        rest = &rest[4 + n..];
    }
    assert!(rest.is_empty());
    (head, fields)
}

fn join_sshsig(head: &[u8], fields: &[Vec<u8>]) -> String {
    let mut blob = head.to_vec();
    for f in fields {
        blob.extend_from_slice(&(f.len() as u32).to_be_bytes());
        blob.extend_from_slice(f);
    }
    let body = b64().encode(&blob);
    let mut pem = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in body.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END SSH SIGNATURE-----\n");
    pem
}

#[test]
fn hash_algorithms_other_than_sha512_sha256_are_rejected() {
    let (_t, dir) = tempdir();
    let key = keygen(&dir, "alice");
    let env = signed(&key, 1);
    let a = allowed(&format!("alice@example.com {}\n", key.pub_line));
    let pem = sig_pem(&env, 0);
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let (head, fields) = split_sshsig(&b64().decode(body).unwrap());
    assert_eq!(fields[3], b"sha512");

    // Sanity: re-assembling unchanged still verifies (so the rebuild is faithful).
    let mut e = env.clone();
    e.signatures[0].sig = b64().encode(join_sshsig(&head, &fields).as_bytes());
    verify_envelope(&e, &a, now()).unwrap();

    for alg in ["sha384", "sha1", "md5", "SHA512", ""] {
        let mut f = fields.clone();
        f[3] = alg.as_bytes().to_vec();
        let mut e = env.clone();
        e.signatures[0].sig = b64().encode(join_sshsig(&head, &f).as_bytes());
        let r = verify_envelope(&e, &a, now());
        assert!(
            matches!(
                r,
                Err(VerifyError::Malformed(_)) | Err(VerifyError::BadSignature(_))
            ),
            "{alg:?}: {r:?}"
        );
    }

    // Relabelling sha512 as sha256 (both allowed) breaks the signature.
    let mut f = fields.clone();
    f[3] = b"sha256".to_vec();
    let mut e = env.clone();
    e.signatures[0].sig = b64().encode(join_sshsig(&head, &f).as_bytes());
    assert!(matches!(
        verify_envelope(&e, &a, now()),
        Err(VerifyError::BadSignature(_))
    ));

    // Unsupported SSHSIG version.
    let mut h = head.clone();
    h[9] = 2;
    let mut e = env.clone();
    e.signatures[0].sig = b64().encode(join_sshsig(&h, &fields).as_bytes());
    assert!(matches!(
        verify_envelope(&e, &a, now()),
        Err(VerifyError::Malformed(_))
    ));
}

#[test]
fn any_one_trusted_signature_suffices() {
    let (_t, dir) = tempdir();
    let alice = keygen(&dir, "alice");
    let mallory = keygen(&dir, "mallory");
    let good = signed(&alice, 1);
    let untrusted = sign_statement(&statement(1), &mallory.private).unwrap();
    assert_eq!(good.payload, untrusted.payload);
    let a = allowed(&format!("alice@example.com {}\n", alice.pub_line));

    let mut both = good.clone();
    both.signatures.insert(0, untrusted.signatures[0].clone());
    let v = verify_envelope(&both, &a, now()).unwrap();
    assert_eq!(v.fingerprint, alice.fingerprint);

    // Only untrusted ones: first error is reported.
    let mut only_bad = untrusted.clone();
    only_bad
        .signatures
        .push(signed(&alice, 2).signatures[0].clone());
    assert!(matches!(
        verify_envelope(&only_bad, &a, now()),
        Err(VerifyError::UnknownSigner(_))
    ));
}

#[test]
fn signing_with_missing_key_fails_cleanly() {
    let (_t, dir) = tempdir();
    let r = sign_statement(&statement(1), &dir.join("does-not-exist"));
    assert!(matches!(r, Err(SignError::SshKeygen { .. })), "{r:?}");
}
