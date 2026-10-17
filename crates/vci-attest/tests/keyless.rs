//! Keyless verification against fixtures (see tests/fixtures/keyless/make.sh):
//! a leaf from a local Fulcio-like authority, a real timestamp from
//! timestamp.githubapp.com, and the real trust root `gh attestation
//! trusted-root` printed on 2026-10-16.

use base64::Engine as _;
use vci_attest::keyless::{
    self, Identities, SigstoreMaterial, TrustedRoot, material_from_json, to_stored_json,
    verify_keyless, verify_timestamp,
};
use vci_attest::{Envelope, VerifyError};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/keyless");
/// 2100-01-01: the checks use the timestamp's time, not the clock (which
/// only must not be earlier than the timestamp).
const LATER: i64 = 4_102_444_800;

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).unwrap()
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn fixture() -> (Envelope, SigstoreMaterial) {
    let bytes = read("envelope.json");
    let env = Envelope::from_json(&bytes).unwrap();
    let m = material_from_json(&bytes)
        .unwrap()
        .expect("sigstore member");
    (env, m)
}

fn root() -> TrustedRoot {
    TrustedRoot::parse(std::str::from_utf8(&read("trusted-root.json")).unwrap()).unwrap()
}

const IDENTITY: &str = r#"
[[identity]]
principal = "github-actions"
issuer = "https://token.actions.githubusercontent.com"
repository = "ComposalAI/vex"
workflow = ".github/workflows/vci.yml"
ref = "refs/heads/master"
event = "push"
"#;

fn ids(t: &str) -> Identities {
    Identities::parse(t).unwrap()
}

#[test]
fn the_fixture_verifies_and_names_the_principal() {
    let (env, m) = fixture();
    let v = verify_keyless(&env, &m, &ids(IDENTITY), &root(), LATER).unwrap();
    assert_eq!(v.verified.principal, "github-actions");
    assert_eq!(
        v.verified.fingerprint,
        "oidc repo:ComposalAI/vex workflow:.github/workflows/vci.yml ref:refs/heads/master event:push"
    );
    assert_eq!(v.verified.statement.subject[0].name, "t.test.ts");
    assert_eq!(v.timestamp.authority, "timestamp.githubapp.com");
    assert_eq!(
        v.identity.runner_environment.as_deref(),
        Some("github-hosted")
    );
    assert_eq!(
        v.identity.run.as_deref(),
        Some("https://github.com/ComposalAI/vex/actions/runs/1/attempts/1")
    );
}

#[test]
fn an_ssh_envelope_has_no_sigstore_member_and_the_stored_form_round_trips() {
    let ssh = br#"{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}"#;
    assert_eq!(material_from_json(ssh).unwrap(), None);
    assert!(material_from_json(br#"{"sigstore":{"mediaType":1}}"#).is_err());
    let (env, m) = fixture();
    let stored = to_stored_json(&env, &m);
    assert_eq!(Envelope::from_json(&stored).unwrap(), env);
    assert_eq!(material_from_json(&stored).unwrap().unwrap(), m);
    let bundle = keyless::to_bundle_json(&env, &m);
    assert_eq!(bundle["dsseEnvelope"]["payload"], env.payload);
    assert_eq!(bundle["mediaType"], keyless::BUNDLE_MEDIA_TYPE);
}

#[test]
fn a_tampered_payload_or_signature_fails_the_signature() {
    let (mut env, m) = fixture();
    let mut p = env.payload_bytes().unwrap();
    p[10] ^= 1;
    env.payload = b64(&p);
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &root(), LATER).unwrap_err();
    assert!(matches!(e, VerifyError::BadSignature(_)), "{e}");

    let (mut env, m) = fixture();
    env.signatures[0].sig = b64(b"\x30\x06\x02\x01\x01\x02\x01\x01");
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &root(), LATER).unwrap_err();
    assert!(matches!(e, VerifyError::BadSignature(_)), "{e}");
}

#[test]
fn an_identity_outside_identities_toml_is_named() {
    let (env, m) = fixture();
    let other = IDENTITY.replace("refs/heads/master", "refs/heads/main");
    let e = verify_keyless(&env, &m, &ids(&other), &root(), LATER).unwrap_err();
    assert!(matches!(e, VerifyError::UnknownIdentity(_)), "{e}");
    assert_eq!(
        e.to_string(),
        "identity repo:ComposalAI/vex workflow:.github/workflows/vci.yml ref:refs/heads/master event:push (issuer https://token.actions.githubusercontent.com) matches no [[identity]] in .vci/identities.toml"
    );
    let e = verify_keyless(&env, &m, &Identities::default(), &root(), LATER).unwrap_err();
    assert!(matches!(e, VerifyError::UnknownIdentity(_)), "{e}");
}

#[test]
fn an_expired_certificate_fails() {
    let (env, mut m) = fixture();
    m.verification_material
        .certificate
        .as_mut()
        .unwrap()
        .raw_bytes = b64(&read("expired-leaf.der"));
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &root(), LATER).unwrap_err();
    assert!(matches!(e, VerifyError::Untrusted(_)), "{e}");
    assert!(
        e.to_string().contains("outside the certificate's validity"),
        "{e}"
    );
}

#[test]
fn a_timestamp_in_the_future_fails() {
    let (env, m) = fixture();
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &root(), 1_600_000_000).unwrap_err();
    assert!(e.to_string().contains("in the future"), "{e}");
}

#[test]
fn a_timestamp_of_other_data_or_none_fails() {
    let (env, mut m) = fixture();
    m.verification_material
        .timestamp_verification_data
        .as_mut()
        .unwrap()
        .rfc3161_timestamps[0]
        .signed_timestamp = b64(&read("tsr-githubapp-hello.der"));
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &root(), LATER).unwrap_err();
    assert!(e.to_string().contains("message imprint differs"), "{e}");

    let (env, mut m) = fixture();
    m.verification_material.timestamp_verification_data = None;
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &root(), LATER).unwrap_err();
    assert!(e.to_string().contains("no RFC 3161 timestamp"), "{e}");
}

#[test]
fn a_tampered_timestamp_fails() {
    let (env, mut m) = fixture();
    let ts = &mut m
        .verification_material
        .timestamp_verification_data
        .as_mut()
        .unwrap()
        .rfc3161_timestamps[0]
        .signed_timestamp;
    let mut der = base64::engine::general_purpose::STANDARD
        .decode(&*ts)
        .unwrap();
    // Flip a bit in the TSA's signature (the last bytes of the response).
    let n = der.len();
    der[n - 3] ^= 1;
    *ts = b64(&der);
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &root(), LATER).unwrap_err();
    assert!(matches!(e, VerifyError::Untrusted(_)), "{e}");
}

#[test]
fn a_trust_root_without_the_authorities_fails_with_the_reason() {
    let (env, m) = fixture();
    // GitHub's real root: right TSA, but not the test's certificate authority.
    let gh =
        TrustedRoot::parse(std::str::from_utf8(&read("gh-trusted-root-2026-10-16.jsonl")).unwrap())
            .unwrap();
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &gh, LATER).unwrap_err();
    assert!(
        e.to_string()
            .contains("is no certificate authority of the trust root"),
        "{e}"
    );

    // The test authority but no timestamp authority.
    let mut v: serde_json::Value = serde_json::from_slice(&read("trusted-root.json")).unwrap();
    v["timestampAuthorities"] = serde_json::json!([]);
    let no_tsa = TrustedRoot::parse(&v.to_string()).unwrap();
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &no_tsa, LATER).unwrap_err();
    assert!(e.to_string().contains("timestamp"), "{e}");

    // The authority's validFor ended before the signature.
    let mut v: serde_json::Value = serde_json::from_slice(&read("trusted-root.json")).unwrap();
    v["certificateAuthorities"][0]["validFor"]["end"] = "2021-01-01T00:00:00Z".into();
    let ended = TrustedRoot::parse(&v.to_string()).unwrap();
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &ended, LATER).unwrap_err();
    assert!(e.to_string().contains("validFor"), "{e}");

    // A certificate authority listing only the root (the leaf's issuer is
    // the intermediate): no chain.
    let mut v: serde_json::Value = serde_json::from_slice(&read("trusted-root.json")).unwrap();
    let chain = v["certificateAuthorities"][0]["certChain"]["certificates"]
        .as_array_mut()
        .unwrap();
    chain.remove(0);
    let root_only = TrustedRoot::parse(&v.to_string()).unwrap();
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &root_only, LATER).unwrap_err();
    assert!(matches!(e, VerifyError::Untrusted(_)), "{e}");
}

#[test]
fn an_intermediate_with_the_same_name_and_another_key_is_not_the_issuer() {
    let (env, m) = fixture();
    let mut v: serde_json::Value = serde_json::from_slice(&read("trusted-root.json")).unwrap();
    v["certificateAuthorities"][0]["certChain"]["certificates"][0]["rawBytes"] =
        b64(&read("impostor-intermediate.der")).into();
    let r = TrustedRoot::parse(&v.to_string()).unwrap();
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &r, LATER).unwrap_err();
    assert!(matches!(e, VerifyError::Untrusted(_)), "{e}");
    assert!(e.to_string().contains("does not verify"), "{e}");
}

#[test]
fn real_tsa_responses_verify_against_the_real_trust_root() {
    let gh =
        TrustedRoot::parse(std::str::from_utf8(&read("gh-trusted-root-2026-10-16.jsonl")).unwrap())
            .unwrap();
    assert_eq!(gh.certificate_authorities.len(), 8);
    assert_eq!(gh.timestamp_authorities.len(), 7);
    let t = verify_timestamp(&read("tsr-githubapp-hello.der"), b"hello", &gh).unwrap();
    assert_eq!(t.authority, "timestamp.githubapp.com");
    let t2 = verify_timestamp(&read("tsr-sigstore-hello.der"), b"hello", &gh).unwrap();
    assert_eq!(
        t2.authority,
        "https://timestamp.sigstore.dev/api/v1/timestamp"
    );
    assert!((t.time - t2.time).abs() < 10);
    assert!(verify_timestamp(&read("tsr-githubapp-hello.der"), b"hellO", &gh).is_err());
    assert!(verify_timestamp(b"\x30\x00", b"hello", &gh).is_err());
}

#[test]
fn a_missing_certificate_or_extra_signature_is_malformed() {
    let (env, mut m) = fixture();
    m.verification_material.certificate = None;
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &root(), LATER).unwrap_err();
    assert!(matches!(e, VerifyError::Malformed(_)), "{e}");

    let (mut env, m) = fixture();
    env.signatures.push(env.signatures[0].clone());
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &root(), LATER).unwrap_err();
    assert!(matches!(e, VerifyError::Malformed(_)), "{e}");
    env.signatures.clear();
    let e = verify_keyless(&env, &m, &ids(IDENTITY), &root(), LATER).unwrap_err();
    assert_eq!(e, VerifyError::NoSignatures);
}

#[test]
fn ssh_verification_rejects_a_keyless_envelope() {
    // An older vci (or the SSH path) sees a keyless envelope as malformed:
    // the unit runs.
    let (env, _) = fixture();
    let allowed = vci_attest::AllowedSigners::parse("").unwrap();
    let e = vci_attest::verify_envelope(&env, &allowed, LATER).unwrap_err();
    assert!(matches!(e, VerifyError::Malformed(_)), "{e}");
}

/// A real envelope from this repository's CI (ci.yml `demo-oidc`, pull
/// request 10 of PandelisZ/cryptographically-verifiable-ci-runner, run
/// 38991254498): a certificate from fulcio.githubapp.com and a timestamp
/// from timestamp.githubapp.com, against the real trust root.
#[test]
fn a_real_github_actions_envelope_verifies_against_the_real_trust_root() {
    let bytes = read("github-pr10-envelope.json");
    let env = Envelope::from_json(&bytes).unwrap();
    let m = material_from_json(&bytes).unwrap().unwrap();
    let gh =
        TrustedRoot::parse(std::str::from_utf8(&read("gh-trusted-root-2026-10-16.jsonl")).unwrap())
            .unwrap();
    let pr = Identities::parse(
        r#"
[[identity]]
principal = "github-actions-oidc-pr"
issuer = "https://token.actions.githubusercontent.com"
repository = "PandelisZ/cryptographically-verifiable-ci-runner"
workflow = ".github/workflows/ci.yml"
ref = "refs/pull/*/merge"
event = "pull_request"
runner_environment = "github-hosted"
"#,
    )
    .unwrap();
    let v = verify_keyless(&env, &m, &pr, &gh, LATER).unwrap();
    assert_eq!(v.verified.principal, "github-actions-oidc-pr");
    assert_eq!(v.timestamp.authority, "timestamp.githubapp.com");
    assert_eq!(v.identity.ref_, "refs/pull/10/merge");
    assert_eq!(
        v.identity.workflow,
        "PandelisZ/cryptographically-verifiable-ci-runner/.github/workflows/ci.yml"
    );
    assert_eq!(
        v.identity.run.as_deref(),
        Some(
            "https://github.com/PandelisZ/cryptographically-verifiable-ci-runner/actions/runs/38991254498/attempts/1"
        )
    );
    assert_eq!(
        v.identity.signer_id(),
        keyless::CertIdentity {
            issuer: "https://token.actions.githubusercontent.com".into(),
            repository: "PandelisZ/cryptographically-verifiable-ci-runner".into(),
            workflow: "PandelisZ/cryptographically-verifiable-ci-runner/.github/workflows/ci.yml"
                .into(),
            ..Default::default()
        }
        .signer_id()
    );

    // The same run is not main's identity.
    let main = Identities::parse(
        r#"
[[identity]]
principal = "github-actions"
issuer = "https://token.actions.githubusercontent.com"
repository = "PandelisZ/cryptographically-verifiable-ci-runner"
workflow = ".github/workflows/ci.yml"
ref = "refs/heads/main"
event = "push"
"#,
    )
    .unwrap();
    let e = verify_keyless(&env, &m, &main, &gh, LATER).unwrap_err();
    assert!(matches!(e, VerifyError::UnknownIdentity(_)), "{e}");

    // The public-good instance's authorities alone do not certify it.
    let public: String = std::str::from_utf8(&read("gh-trusted-root-2026-10-16.jsonl"))
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned();
    let e =
        verify_keyless(&env, &m, &pr, &TrustedRoot::parse(&public).unwrap(), LATER).unwrap_err();
    assert!(matches!(e, VerifyError::Untrusted(_)), "{e}");
}
