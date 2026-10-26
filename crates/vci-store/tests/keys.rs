//! The key format, the records and the errors every backend shares. The key
//! tests moved here from vci-git's `meta.rs` (vci 2.2 keys and their hints)
//! keep their assertions.

use std::cell::Cell;
use std::rc::Rc;

use base64::Engine as _;
use vci_store::key::{self, ManifestRef};
use vci_store::{
    AttestationStore, BackendFactory, BatchEnd, Caps, EMPTY_VALUE, FailedStore, GONE, KeyHint,
    MissingBackend, NOT_FETCHED, NewAttestation, Prefetch, StoreError, StoredEnvelope,
    StoredManifest, ValueState, WriteBatch, attestation_key, attestation_key_hinted, manifest_key,
    parse_key, parse_key_hint, parse_manifest_key,
};

const SIGNER: &str = "0123456789abcdef";

fn hex64(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

fn envelope(payload: &str) -> String {
    serde_json::json!({
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64::engine::general_purpose::STANDARD.encode(payload),
        "signatures": [],
    })
    .to_string()
}

fn statement(v: serde_json::Value) -> String {
    envelope(&v.to_string())
}

// ---- moved from vci-git ------------------------------------------------------

#[test]
fn key_round_trip() {
    let (tk, sk) = ("ab".repeat(32), "cd".repeat(32));
    let k = attestation_key(&tk, "0123456789abcdef", &sk);
    assert_eq!(k, format!("vci:attestation:{tk}:0123456789abcdef:{sk}"));
    assert_eq!(
        parse_key(&k),
        Some((tk.as_str(), "0123456789abcdef", sk.as_str()))
    );
    for bad in [
        "vci:attestation",
        "vci:attestation:ab:0123456789abcdef",
        "vci:attestation:ab:0123456789abcdef:cd:x",
        "vci:attestation:AB:0123456789abcdef:cd",
        "vci:attestation:ab:0123:cd",
        "other:attestation:ab:0123456789abcdef:cd",
    ] {
        assert_eq!(parse_key(bad), None, "{bad}");
    }
}

#[test]
fn hinted_keys_parse_and_plain_ones_still_do() {
    let (tk, signer, sk) = ("ab".repeat(32), "0123456789abcdef", "cd".repeat(32));
    let plain = attestation_key(&tk, signer, &sk);
    assert_eq!(parse_key(&plain), Some((tk.as_str(), signer, sk.as_str())));
    assert_eq!(parse_key_hint(&plain), None);
    let hint = KeyHint {
        issued: 1_792_430_181,
        tree: Some("0123456789abcdef".to_owned()),
    };
    let k = attestation_key_hinted(&tk, signer, &sk, &hint);
    assert!(k.ends_with(":6ad65065.0123456789abcdef"), "{k}");
    assert_eq!(parse_key(&k), Some((tk.as_str(), signer, sk.as_str())));
    assert_eq!(parse_key_hint(&k), Some(hint.clone()));
    let no_tree = attestation_key_hinted(
        &tk,
        signer,
        &sk,
        &KeyHint {
            issued: 7,
            tree: None,
        },
    );
    assert!(no_tree.ends_with(":7.-"), "{no_tree}");
    assert_eq!(parse_key_hint(&no_tree).unwrap().tree, None);
    // A 40-digit tree is cut to 16; a bad one reads as none.
    let long = attestation_key_hinted(
        &tk,
        signer,
        &sk,
        &KeyHint {
            issued: 1,
            tree: Some("f".repeat(40)),
        },
    );
    assert_eq!(
        parse_key_hint(&long).unwrap().tree.as_deref(),
        Some("ffffffffffffffff")
    );
    for bad in [
        format!("{plain}:zz.-"),
        format!("{plain}:1.abc"),
        format!("{plain}:1.-:more"),
        format!("{plain}:"),
    ] {
        assert_eq!(parse_key(&bad), None, "{bad}");
    }
}

/// vci-git's `manifest_refs_of_envelopes`, now with the three states: a
/// predicate without `manifestRef` is `Inline` (it named none before too).
#[test]
fn manifest_refs_of_envelopes() {
    let root = "ab".repeat(32);
    let env = statement(serde_json::json!({"predicate": {"manifestRef": root}}));
    assert_eq!(
        key::envelope_manifest_ref(env.as_bytes()),
        ManifestRef::Root(root)
    );
    assert_eq!(
        key::envelope_manifest_ref(
            statement(serde_json::json!({"predicate": {"manifest": {}}})).as_bytes()
        ),
        ManifestRef::Inline
    );
    for bad in [
        statement(serde_json::json!({"predicate": {"manifestRef": "../x"}})),
        "not json".to_owned(),
    ] {
        assert_eq!(
            key::envelope_manifest_ref(bad.as_bytes()),
            ManifestRef::Unknown,
            "{bad}"
        );
    }
}

// ---- hints: edge cases ---------------------------------------------------------

#[test]
fn hint_edge_cases() {
    let (tk, sk) = (hex64(0xab), hex64(0xcd));
    let plain = attestation_key(&tk, SIGNER, &sk);
    let parsed = |k: &str| (parse_key(k).is_some(), parse_key_hint(k));

    // Uppercase hex reads as hex (as vci-git's parser did); vci writes
    // lowercase.
    assert_eq!(
        parsed(&format!("{plain}:6AD65065.0123456789ABCDEF")),
        (
            true,
            Some(KeyHint {
                issued: 0x6ad6_5065,
                tree: Some("0123456789ABCDEF".to_owned()),
            })
        )
    );
    // `issued`: at most 16 hex digits, and it must fit an i64.
    assert_eq!(
        parsed(&format!("{plain}:7fffffffffffffff.-")),
        (
            true,
            Some(KeyHint {
                issued: i64::MAX,
                tree: None,
            })
        )
    );
    for bad_issued in ["8000000000000000", "11111111111111111", "", "-1", "x1"] {
        let k = format!("{plain}:{bad_issued}.-");
        assert_eq!(parsed(&k), (false, None), "{k}");
    }
    // The tree: exactly 16 hex digits, or `-`.
    for bad_tree in [
        "0123456789abcde",
        "0123456789abcdef0",
        "0123456789abcdeg",
        "",
        "--",
        "-0",
    ] {
        let k = format!("{plain}:1.{bad_tree}");
        assert_eq!(parsed(&k), (false, None), "{k}");
    }
    // No `.` at all.
    assert_eq!(parsed(&format!("{plain}:1")), (false, None));
    // Writing: a negative `issued` is written as 0; a tree that is not 16
    // hex digits as `-`.
    let k = attestation_key_hinted(
        &tk,
        SIGNER,
        &sk,
        &KeyHint {
            issued: -5,
            tree: Some("0123456789abcdeg".to_owned()),
        },
    );
    assert!(k.ends_with(":0.-"), "{k}");
    let short = attestation_key_hinted(
        &tk,
        SIGNER,
        &sk,
        &KeyHint {
            issued: 1,
            tree: Some("abc".to_owned()),
        },
    );
    assert!(short.ends_with(":1.-"), "{short}");
}

#[test]
fn manifest_keys() {
    let root = hex64(0xe1);
    let k = manifest_key(&root);
    assert_eq!(k, format!("vci:manifest:{root}"));
    assert_eq!(parse_manifest_key(&k), Some(root.as_str()));
    for bad in [
        "vci:manifest:",
        "vci:manifest:A1",
        "vci:manifest:a",
        "vci:manifestab",
        "vci:attestation:ab",
    ] {
        assert_eq!(parse_manifest_key(bad), None, "{bad}");
    }
    assert_eq!(key::unit_prefix("ab"), "vci:attestation:ab:");
}

// ---- ManifestRef ---------------------------------------------------------------

#[test]
fn manifest_ref_states() {
    let root = hex64(0x42);
    let of = |s: &str| key::envelope_manifest_ref(s.as_bytes());
    assert_eq!(
        of(&statement(
            serde_json::json!({"predicate": {"manifestRef": root, "testId": "a"}})
        )),
        ManifestRef::Root(root.clone())
    );
    // Inline: a predicate whose manifestRef is null or absent (vci before
    // 1.9.0 embedded the manifest).
    for inline in [
        serde_json::json!({"predicate": {"manifestRef": null}}),
        serde_json::json!({"predicate": {}}),
        serde_json::json!({"predicate": {"manifest": {"entries": []}}}),
    ] {
        assert_eq!(
            of(&statement(inline.clone())),
            ManifestRef::Inline,
            "{inline}"
        );
    }
    // Unknown: anything that does not parse that far.
    let bad_base64 = serde_json::json!({"payload": "%%% not base64 %%%"}).to_string();
    let no_payload = serde_json::json!({"payloadType": "x"}).to_string();
    for unknown in [
        "not json".to_owned(),
        String::new(),
        bad_base64,
        no_payload,
        envelope("not json"),
        statement(serde_json::json!({"subject": []})),
        statement(serde_json::json!({"predicate": "a string"})),
        statement(serde_json::json!({"predicate": {"manifestRef": "../x"}})),
        statement(serde_json::json!({"predicate": {"manifestRef": "AB".repeat(32)}})),
        statement(serde_json::json!({"predicate": {"manifestRef": "a"}})),
        statement(serde_json::json!({"predicate": {"manifestRef": 7}})),
    ] {
        assert_eq!(of(&unknown), ManifestRef::Unknown, "{unknown}");
    }
}

// ---- records -------------------------------------------------------------------

#[test]
fn stored_envelopes_from_keys() {
    let (tk, sk) = (hex64(1), hex64(2));
    let hinted = attestation_key_hinted(
        &tk,
        SIGNER,
        &sk,
        &KeyHint {
            issued: 0x6ad6_5065,
            tree: Some("0123456789abcdef".to_owned()),
        },
    );
    let e = StoredEnvelope::from_key("path:src/a.test.ts", &hinted).unwrap();
    assert_eq!(
        e,
        StoredEnvelope {
            target: "path:src/a.test.ts".to_owned(),
            key: hinted.clone(),
            test_key: tk.clone(),
            signer: SIGNER.to_owned(),
            storage_key: sk.clone(),
            issued: Some(0x6ad6_5065),
            tree: Some("0123456789abcdef".to_owned()),
            bytes: Vec::new(),
            error: None,
        }
    );
    assert_eq!(e.state(), ValueState::Unread);

    let plain = attestation_key(&tk, SIGNER, &sk);
    let p = StoredEnvelope::from_key("project", &plain).unwrap();
    assert_eq!((p.issued, p.tree.as_deref()), (None, None));
    assert_eq!(
        (p.target.as_str(), p.key.as_str()),
        ("project", plain.as_str())
    );

    // Foreign keys are not records.
    for foreign in [
        "other:key".to_owned(),
        manifest_key(&tk),
        format!("vci:attestation:{}:{SIGNER}:{sk}", "AB".repeat(32)),
        format!("{plain}:1.abc"),
        format!("vci:attestation:{tk}:0123:{sk}"),
    ] {
        assert_eq!(
            StoredEnvelope::from_key("project", &foreign),
            None,
            "{foreign}"
        );
    }
}

#[test]
fn value_states() {
    let mut e = StoredEnvelope::from_key("project", &attestation_key(&hex64(1), SIGNER, &hex64(2)))
        .unwrap();
    assert_eq!(e.state(), ValueState::Unread);
    assert_eq!(e.manifest_ref(), ManifestRef::Unknown);

    e.set_value(b"{}".to_vec());
    assert_eq!(e.state(), ValueState::Read(b"{}"));
    assert!(!e.not_fetched());

    e.mark_not_fetched();
    assert_eq!(
        (e.state(), e.bytes.is_empty()),
        (ValueState::NotFetched, true)
    );
    assert!(e.not_fetched());
    assert_eq!(e.manifest_ref(), ManifestRef::Unknown);

    e.set_error(GONE);
    assert_eq!(e.state(), ValueState::Unreadable(GONE));
    assert!(!e.not_fetched());

    // Empty bytes are never a value.
    e.set_value(Vec::new());
    assert_eq!(e.state(), ValueState::Unreadable(EMPTY_VALUE));

    // An error wins over bytes, whichever way a backend filled the fields.
    let with_both = |error: &str| StoredEnvelope {
        bytes: b"x".to_vec(),
        error: Some(error.to_owned()),
        ..e.clone()
    };
    assert_eq!(with_both(NOT_FETCHED).state(), ValueState::NotFetched);
    assert_eq!(
        with_both("blob 1 is missing").state(),
        ValueState::Unreadable("blob 1 is missing")
    );

    // A read value names its manifest.
    let root = hex64(9);
    e.set_value(statement(serde_json::json!({"predicate": {"manifestRef": root}})).into_bytes());
    assert_eq!(e.error, None);
    assert_eq!(e.manifest_ref(), ManifestRef::Root(root));
}

#[test]
fn value_texts_are_pinned() {
    // Tests and log scrapers match NOT_FETCHED's text, byte for byte.
    assert_eq!(
        NOT_FETCHED,
        "value not fetched: run `vci fetch` online (a git-meta promised entry; its blob is not in this clone yet)"
    );
    assert_eq!(GONE, "the store no longer holds this key");
    assert_eq!(EMPTY_VALUE, "the stored value is empty");
}

#[test]
fn stored_manifests() {
    let root = hex64(3);
    let m = StoredManifest::with_bytes(&root, b"m".to_vec());
    assert_eq!(m.key, manifest_key(&root));
    assert!(m.is_read() && !m.not_fetched());
    let p = StoredManifest::pending(&root);
    assert!(!p.is_read() && p.not_fetched());
    assert_eq!(p.error.as_deref(), Some(NOT_FETCHED));
    let u = StoredManifest::with_error(&root, "blob x is missing");
    assert!(!u.is_read() && !u.not_fetched() && u.bytes.is_empty());
}

#[test]
fn new_attestations() {
    let hint = KeyHint {
        issued: 0x10,
        tree: Some("f".repeat(40)),
    };
    let sk = hex64(2);
    let a = NewAttestation::for_test("rust/core#test:it", SIGNER, &sk, Some(&hint), b"{}");
    assert_eq!(a.target, "path:rust/core");
    assert_eq!(a.test_key, vci_core::test_key("rust/core#test:it"));
    assert_eq!(a.validate().unwrap(), "{}");
    let k = a.hinted_key().unwrap();
    assert_eq!(k, attestation_key_hinted(&a.test_key, SIGNER, &sk, &hint));
    assert_eq!(a.plain_key(), attestation_key(&a.test_key, SIGNER, &sk));
    // What a put returns: issued and tree from the key (the tree cut to 16).
    let s = a.stored(k.clone());
    assert_eq!(
        (
            s.key.as_str(),
            s.issued,
            s.tree.as_deref(),
            s.bytes.as_slice()
        ),
        (k.as_str(), Some(0x10), Some("ffffffffffffffff"), &b"{}"[..])
    );
    assert_eq!(s.target, "path:rust/core");
    assert_eq!(s.state(), ValueState::Read(b"{}"));
    // A copy keeps target, test key, signer, storage key and key.
    let h = parse_key_hint(&s.key);
    let c = NewAttestation::copy_of(&s, h.as_ref());
    assert_eq!(
        (
            c.target.as_str(),
            c.test_key.as_str(),
            c.signer,
            c.storage_key
        ),
        ("path:rust/core", a.test_key.as_str(), SIGNER, sk.as_str())
    );
    assert_eq!(c.hinted_key().as_deref(), Some(k.as_str()));
    assert_eq!(c.envelope, b"{}");
    assert_eq!(
        NewAttestation::for_test(".", SIGNER, &sk, None, b"x").target,
        "project"
    );
    assert_eq!(
        NewAttestation::for_test(".", SIGNER, &sk, None, b"x").hinted_key(),
        None
    );
}

#[test]
fn invalid_arguments_name_what_and_why() {
    let sk = hex64(2);
    let ok = NewAttestation::for_test("src/a.test.ts", SIGNER, &sk, None, b"{}");
    let what = |a: &NewAttestation| match a.validate() {
        Err(StoreError::Invalid { what, reason, .. }) => (what, reason),
        other => panic!("expected Invalid, got {other:?}"),
    };
    assert_eq!(
        what(&NewAttestation {
            signer: "XYZ",
            ..ok.clone()
        }),
        ("signer_id", "must be exactly 16 characters")
    );
    assert_eq!(
        what(&NewAttestation {
            signer: "0123456789ABCDEF",
            ..ok.clone()
        }),
        ("signer_id", "must be lowercase hex")
    );
    assert_eq!(
        what(&NewAttestation {
            storage_key: "a",
            ..ok.clone()
        }),
        ("storage_key", "must be 2 to 128 characters")
    );
    assert_eq!(
        what(&NewAttestation {
            test_key: "XY".to_owned(),
            ..ok.clone()
        }),
        ("test_key", "must be lowercase hex")
    );
    for target in [
        "path:ab",
        "path:/abs",
        "path:a#b",
        "path:a/../b",
        "commit:abc",
        "",
    ] {
        assert_eq!(
            what(&NewAttestation {
                target: target.to_owned(),
                ..ok.clone()
            }),
            ("target", "must be `project` or `path:<relative path>`"),
            "{target}"
        );
    }
    assert_eq!(
        what(&NewAttestation {
            envelope: b"",
            ..ok.clone()
        }),
        ("envelope", "must not be empty")
    );
    assert_eq!(
        what(&NewAttestation {
            envelope: b"\xff\xfe",
            ..ok.clone()
        }),
        ("envelope", "must be UTF-8")
    );
    assert!(key::is_target_label("project") && key::is_target_label("path:src/a.test.ts"));

    // The display is vci-git's, word for word.
    assert_eq!(
        StoreError::invalid("signer_id", "XYZ", "must be exactly 16 characters").to_string(),
        "invalid signer_id: \"XYZ\": must be exactly 16 characters"
    );
    assert_eq!(
        key::check_utf8("manifest", b"\xff")
            .unwrap_err()
            .to_string(),
        "invalid manifest: \"\": must be UTF-8"
    );
    assert_eq!(
        key::check_hex("input root", "../x")
            .unwrap_err()
            .to_string(),
        "invalid input root: \"../x\": must be lowercase hex"
    );
}

#[test]
fn errors_say_what_happened() {
    let cases: Vec<(StoreError, &str, &str, bool)> = vec![
        (
            StoreError::Config("bad".into()),
            "attestation store: bad",
            "config",
            false,
        ),
        (
            StoreError::unavailable("postgres", "connection refused"),
            "postgres store unavailable: connection refused",
            "unavailable",
            true,
        ),
        (
            StoreError::Timeout {
                backend: "postgres",
                operation: "connecting",
                after: std::time::Duration::from_secs(5),
            },
            "postgres store: connecting timed out after 5s",
            "timeout",
            true,
        ),
        (
            StoreError::NotInitialized {
                backend: "postgres",
                advice: "run it as the owner".into(),
            },
            "postgres store is not set up: run it as the owner",
            "not-initialized",
            false,
        ),
        (
            StoreError::Incompatible {
                backend: "sqlite",
                found: 2,
                supported: 1,
            },
            "sqlite store schema version 2 is newer than this vci reads (up to 1): upgrade vci",
            "incompatible",
            false,
        ),
        (
            StoreError::Denied {
                backend: "postgres",
                operation: "write",
                detail: "permission denied".into(),
            },
            "postgres store refused to write: permission denied",
            "denied",
            false,
        ),
        (
            StoreError::Unsupported {
                backend: "sqlite",
                operation: "rewriting history",
            },
            "the sqlite store does not support rewriting history",
            "unsupported",
            false,
        ),
        (
            StoreError::backend(std::io::Error::other("disk on fire")),
            "disk on fire",
            "backend",
            false,
        ),
        (StoreError::other("as text"), "as text", "other", false),
    ];
    for (e, text, code, transient) in cases {
        assert_eq!(e.to_string(), text);
        assert_eq!(e.code(), code);
        assert_eq!(e.is_transient(), transient, "{text}");
    }
    let e = StoreError::backend(std::io::Error::other("x"));
    assert!(e.downcast_backend::<std::io::Error>().is_some());
    assert!(e.downcast_backend::<std::fmt::Error>().is_none());
    assert!(
        StoreError::other("x")
            .downcast_backend::<std::io::Error>()
            .is_none()
    );
}

// ---- batches -------------------------------------------------------------------

struct Recorder {
    finished: Rc<Cell<u32>>,
    fail: bool,
}

impl BatchEnd for Recorder {
    fn finish(self: Box<Self>) -> Result<Vec<String>, StoreError> {
        self.finished.set(self.finished.get() + 1);
        if self.fail {
            Err(StoreError::other("flush failed"))
        } else {
            Ok(Vec::new())
        }
    }
}

#[test]
fn write_batches_end_once() {
    assert!(WriteBatch::none().finish().is_ok());
    assert!(!WriteBatch::none().defers_writes());

    let n = Rc::new(Cell::new(0));
    let b = WriteBatch::immediate(Box::new(Recorder {
        finished: n.clone(),
        fail: false,
    }));
    assert!(!b.defers_writes());
    assert!(b.finish().is_ok());
    assert_eq!(n.get(), 1, "finished once");

    let d = WriteBatch::deferred(Box::new(Recorder {
        finished: n.clone(),
        fail: true,
    }));
    assert!(d.defers_writes());
    assert_eq!(d.finish().unwrap_err().to_string(), "flush failed");
    assert_eq!(n.get(), 2);

    // Dropping ends it too (and ignores the error).
    drop(WriteBatch::deferred(Box::new(Recorder {
        finished: n.clone(),
        fail: true,
    })));
    assert_eq!(n.get(), 3);
}

// ---- a store that failed -------------------------------------------------------

#[test]
fn failed_store_fails_every_call() {
    let s = FailedStore::new("postgres", "connection refused");
    let unavailable = |r: Result<(), StoreError>| match r {
        Err(StoreError::Unavailable { backend, detail }) => {
            assert_eq!(
                (backend, detail.as_str()),
                ("postgres", "connection refused")
            )
        }
        other => panic!("expected Unavailable, got {other:?}"),
    };
    let sk = hex64(2);
    let root = hex64(3);
    let mut e =
        StoredEnvelope::from_key("project", &attestation_key(&hex64(1), SIGNER, &sk)).unwrap();
    assert_eq!(s.kind(), "postgres");
    assert!(s.location().contains("unavailable: connection refused"));
    assert_eq!(s.caps(), Caps::LOCAL);
    unavailable(s.status().map(drop));
    unavailable(s.list_units(&["a"]).map(drop));
    unavailable(s.list_all().map(drop));
    unavailable(s.read_values(&mut [&mut e]));
    unavailable(s.manifest(&root).map(drop));
    unavailable(s.manifest_roots().map(drop));
    unavailable(
        s.put(&NewAttestation::for_test("a", SIGNER, &sk, None, b"{}"))
            .map(drop),
    );
    unavailable(s.put_manifest(&root, b"{}").map(drop));
    unavailable(s.remove(vec![e.clone()]).map(drop));
    unavailable(s.remove_manifests(&[root.as_str()]).map(drop));
    unavailable(s.batch().map(drop));
    unavailable(s.prefetch(Prefetch::Attestations).map(drop));
    unavailable(
        s.prefetch(Prefetch::Units {
            test_ids: &["a"],
            choose: None,
        })
        .map(drop),
    );
    unavailable(s.prefetch(Prefetch::Manifests { roots: &[] }).map(drop));
    // The provided methods fail through the required ones.
    unavailable(s.read_units(&["a"]).map(drop));
    unavailable(s.read_all().map(drop));
    unavailable(s.count().map(drop));
    unavailable(s.manifests(&[root.as_str()]).map(drop));
    unavailable(s.manifest_decoded(&root).map(drop));
    unavailable(s.orphan_manifests(&[root.as_str()]).map(drop));
    unavailable(s.put_for_test("a", SIGNER, &sk, None, b"{}").map(drop));
    // Hints do nothing, and there is no exchange.
    assert!(s.passing_on("0123456789abcdef").is_empty());
    s.remember_passing("0123456789abcdef", &[("a".into(), "b".into())]);
    assert!(!s.flag("plan:natives:x"));
    s.set_flag("plan:natives:x");
    s.warm();
    assert!(s.timing_report().is_empty());
    assert!(s.exchange().is_none());
}

#[test]
fn failed_store_is_named_after_the_request() {
    let sqlite = MissingBackend {
        kind: "sqlite",
        feature: "sqlite",
    };
    let factories: [&dyn BackendFactory; 1] = [&sqlite];
    let err = StoreError::Config("nope".into());
    assert_eq!(
        FailedStore::for_request(&factories, "sqlite", &err).kind(),
        "sqlite"
    );
    assert_eq!(
        FailedStore::for_request(&factories, "redis", &err).kind(),
        "unknown"
    );
    let f = FailedStore::for_request(&factories, "sqlite", &err);
    assert!(
        f.location().contains("attestation store: nope"),
        "{}",
        f.location()
    );
}
