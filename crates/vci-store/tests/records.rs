//! The format-3 additions of vci-store (STORE-V2 section 6, M2): the
//! record decoder over both formats, the object references and keys, the
//! validation of objects and columns, and the trait defaults a backend has
//! before it keeps objects.

use std::sync::Arc;

use vci_core::ObjectKind;
use vci_store::{
    AttestationStore, Caps, Columns, FailedStore, ManifestRef, NewAttestation, NewObject,
    OBJECT_GRACE, ObjectRefs, Prefetch, Record, RecordError, StoreError, StoredEnvelope,
    StoredManifest, decode_record, envelope_manifest_ref, key, object_from_base64, object_key,
    object_kind, object_to_base64, parse_object_key, record_object_refs,
};

fn hex64(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

/// A format-1 envelope whose payload names `manifest_ref`.
fn envelope(manifest_ref: Option<&str>) -> Vec<u8> {
    use base64::Engine as _;
    let payload = serde_json::json!({"predicate": {"manifestRef": manifest_ref}});
    serde_json::json!({
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64::engine::general_purpose::STANDARD.encode(payload.to_string()),
        "signatures": [{"keyid": "SHA256:k", "sig": "c2ln"}],
    })
    .to_string()
    .into_bytes()
}

/// A frame whose statement names `hdr` and `tables` and whose descriptor
/// starts with `shape`.
fn frame(hdr: &str, tables: &str, shape: &[u8; 32]) -> Vec<u8> {
    let tables_obj = vci_core::Tables {
        waivers: vec![],
        env_names: vec![],
        externals: vec![],
    };
    let descriptor = vci_core::Descriptor {
        shape: *shape,
        group: None,
        own: vec![0],
        env_read: vec![],
        env_values: vec![],
        externals: vec![],
        extras: vec![],
    }
    .encode(&tables_obj)
    .unwrap();
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "src/a.test.ts", "digest": {"blake3": hex64(9)}}],
        "predicateType": vci_core::PREDICATE_TYPE_V2,
        "predicate": {"hdr": hdr, "tables": tables},
    });
    vci_core::Frame {
        statement: statement.to_string().into_bytes(),
        keyid: "SHA256:k".into(),
        sig: vci_core::FrameSig::SshSig(vec![1, 2, 3]),
        descriptor,
    }
    .encode()
    .unwrap()
    .into_bytes()
}

#[test]
fn decode_record_tells_the_formats_apart_by_the_first_byte() {
    let one = envelope(Some(&hex64(1)));
    match decode_record(&one) {
        // The bytes as stored, for the reader to parse as an envelope.
        Ok(Record::FormatOne(bytes)) => assert_eq!(bytes, one.as_slice()),
        other => panic!("{other:?}"),
    }
    let three = frame(&hex64(1), &hex64(2), &[3; 32]);
    match decode_record(&three) {
        Ok(Record::FormatThree(f)) => {
            assert_eq!(f.keyid, "SHA256:k");
            assert_eq!(f.sig, vci_core::FrameSig::SshSig(vec![1, 2, 3]));
            assert_eq!(
                vci_core::Descriptor::shape_id(&f.descriptor).unwrap(),
                [3; 32]
            );
            assert!(f.statement.starts_with(b"{"));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(decode_record(b""), Err(RecordError::Empty));
    assert_eq!(decode_record(b"x"), Err(RecordError::FirstByte(b'x')));
    assert_eq!(decode_record(b" {"), Err(RecordError::FirstByte(b' ')));
    // A `{` value is handed on unparsed: the envelope parse that refuses
    // it is the reader's, as before.
    assert_eq!(
        decode_record(b"{not json"),
        Ok(Record::FormatOne(b"{not json"))
    );
    assert!(matches!(
        decode_record(b"vci3z\n{}\nAA==\nAA=="),
        Err(RecordError::Frame(vci_core::FrameError::FirstLine(_)))
    ));
    let mut cut = three.clone();
    cut.truncate(cut.len() - 1);
    assert!(matches!(
        decode_record(&cut),
        Err(RecordError::Frame(vci_core::FrameError::Base64 { .. }))
    ));
    let mut big = b"vci3\n{".to_vec();
    big.resize(vci_core::MAX_RECORD + 1, b' ');
    assert_eq!(
        decode_record(&big),
        Err(RecordError::Frame(vci_core::FrameError::TooLarge(
            vci_core::MAX_RECORD + 1
        )))
    );
    // The display of each, for the `envelope` check's text.
    assert_eq!(
        RecordError::FirstByte(0x00).to_string(),
        "the record starts with byte 0x00, not '{' (an envelope) or 'v' (a frame)"
    );
    assert_eq!(RecordError::Empty.to_string(), "the record is empty");
    assert!(
        RecordError::Frame(vci_core::FrameError::Nul)
            .to_string()
            .starts_with("frame: ")
    );
}

#[test]
fn a_frame_names_no_manifest_and_names_its_objects() {
    let (hdr, tables) = (hex64(0xaa), hex64(0xbb));
    let three = frame(&hdr, &tables, &[0xcc; 32]);
    assert_eq!(envelope_manifest_ref(&three), ManifestRef::Inline);
    let mut want = vec![hdr.clone(), tables.clone(), "cc".repeat(32)];
    want.sort();
    assert_eq!(record_object_refs(&three), ObjectRefs::Named(want));
    // The same ids twice collapse.
    let same = frame(&hdr, &hdr, &[0xaa; 32]);
    assert_eq!(
        record_object_refs(&same),
        ObjectRefs::Named(vec![hdr.clone()])
    );
    // A format-1 record names no object; its manifest reference is as before.
    let one = envelope(Some(&hex64(1)));
    assert_eq!(record_object_refs(&one), ObjectRefs::FormatOne);
    assert_eq!(envelope_manifest_ref(&one), ManifestRef::Root(hex64(1)));
    assert_eq!(envelope_manifest_ref(&envelope(None)), ManifestRef::Inline);
    // A broken frame is unknown to both collectors.
    assert_eq!(envelope_manifest_ref(b"vci3\n{}\n"), ManifestRef::Unknown);
    assert_eq!(record_object_refs(b"vci3\n{}\n"), ObjectRefs::Unknown);
    assert_eq!(record_object_refs(b""), ObjectRefs::Unknown);
    // A statement without the ids, or with ids of another spelling, is unknown.
    let upper = frame(&hdr.to_uppercase(), &tables, &[1; 32]);
    assert_eq!(record_object_refs(&upper), ObjectRefs::Unknown);
    let short = frame("abc", &tables, &[1; 32]);
    assert_eq!(record_object_refs(&short), ObjectRefs::Unknown);
    let mut e = StoredEnvelope::from_key(
        "project",
        &key::attestation_key(&hex64(1), &"1".repeat(16), &hex64(2)),
    )
    .unwrap();
    e.set_value(three);
    assert_eq!(e.manifest_ref(), ManifestRef::Inline);
}

#[test]
fn object_keys_and_ids() {
    let id = hex64(0x5a);
    assert_eq!(
        object_key(ObjectKind::Hdr, &id),
        format!("vci:object:1:{id}")
    );
    assert_eq!(
        object_key(ObjectKind::State, &id),
        format!("vci:object:4:{id}")
    );
    for (kind, byte) in [
        (ObjectKind::Hdr, 1),
        (ObjectKind::Tables, 2),
        (ObjectKind::Shape, 3),
        (ObjectKind::State, 4),
    ] {
        assert_eq!(kind as u8, byte);
        assert_eq!(object_kind(byte), Some(kind));
        assert_eq!(
            parse_object_key(&object_key(kind, &id)),
            Some((kind, id.as_str()))
        );
    }
    for byte in [0u8, 5, 0x7f, 0xff] {
        assert_eq!(object_kind(byte), None);
    }
    for foreign in [
        "vci:object:5:",
        &format!("vci:object:5:{id}"),
        &format!("vci:object:1:{}", id.to_uppercase()),
        &format!("vci:object:1:{}", &id[..62]),
        &format!("vci:object::{id}"),
        &format!("vci:objects:1:{id}"),
        &format!("vci:manifest:{id}"),
        &format!("vci:object:1:{id}:x"),
    ] {
        assert_eq!(parse_object_key(foreign), None, "{foreign}");
    }
    assert!(key::is_object_id(&id));
    assert!(!key::is_object_id(&id[..62]));
    assert!(!key::is_object_id(&id.to_uppercase()));
    assert_eq!(
        key::check_object_id("zz").unwrap_err().to_string(),
        "invalid object id: \"zz\": must be exactly 64 characters"
    );
    assert_eq!(
        key::check_object_id(&"Z".repeat(64))
            .unwrap_err()
            .to_string(),
        format!(
            "invalid object id: {:?}: must be lowercase hex",
            "Z".repeat(64)
        )
    );
    // The base64 form of a text backend, canonical and padded.
    assert_eq!(object_to_base64(b"vo\x01\x01"), "dm8BAQ==");
    assert_eq!(object_from_base64("dm8BAQ==").unwrap(), b"vo\x01\x01");
    assert!(object_from_base64("dm8BAQ").is_err(), "unpadded");
    assert!(object_from_base64("dm8B AQ==").is_err(), "whitespace");
}

#[test]
fn objects_and_columns_are_validated() {
    let what = |r: Result<String, StoreError>| match r {
        Err(StoreError::Invalid { what, reason, .. }) => (what, reason),
        other => panic!("expected Invalid, got {other:?}"),
    };
    assert_eq!(
        what(NewObject::new(ObjectKind::Hdr, b"").validate()),
        ("object", "must not be empty")
    );
    assert_eq!(
        what(NewObject::new(ObjectKind::Hdr, b"vo\x02\x01").validate()),
        (
            "object",
            "must start with the object magic and this kind's byte"
        )
    );
    assert_eq!(
        what(NewObject::new(ObjectKind::Hdr, b"vo\x01").validate()),
        (
            "object",
            "must start with the object magic and this kind's byte"
        )
    );
    assert_eq!(
        what(NewObject::new(ObjectKind::Hdr, b"{}\x01\x01").validate()),
        (
            "object",
            "must start with the object magic and this kind's byte"
        )
    );
    let mut big = b"vo\x02\x01".to_vec();
    big.resize(ObjectKind::Tables.max_bytes() + 1, 0);
    assert_eq!(
        what(NewObject::new(ObjectKind::Tables, &big).validate()),
        ("object", "is over the bound of its kind")
    );
    big.truncate(ObjectKind::Tables.max_bytes());
    let id = NewObject::new(ObjectKind::Tables, &big).validate().unwrap();
    assert_eq!(id, vci_core::objects::hex32(&vci_core::object_id(&big)));
    assert!(key::is_object_id(&id));

    let empty = Columns::default();
    assert!(empty.is_empty());
    assert!(empty.validate().is_ok());
    assert_eq!(empty.object_ids().count(), 0);
    let mut c = Columns {
        hdr: Some(hex64(1)),
        state_obj: Some(hex64(4)),
        shape: Some(hex64(3)),
        ..Columns::default()
    };
    assert!(!c.is_empty());
    assert_eq!(
        c.object_ids().collect::<Vec<_>>(),
        [hex64(1), hex64(3), hex64(4)]
    );
    assert!(c.validate().is_ok());
    c.tables = Some("x".repeat(64));
    assert_eq!(
        what(c.validate().map(|()| String::new())),
        ("object id", "must be lowercase hex")
    );
    // A put carries them through `validate`, after the key fields.
    let rec = frame(&hex64(1), &hex64(2), &[3; 32]);
    let (signer, sk) = ("1".repeat(16), hex64(2));
    let att = NewAttestation::for_test("src/a.test.ts", &signer, &sk, None, &rec);
    assert!(att.columns.is_none());
    assert!(att.validate().is_ok());
    let att = att.with_columns(&c);
    assert_eq!(
        what(att.validate().map(str::to_owned)),
        ("object id", "must be lowercase hex")
    );
    c.tables = None;
    let att = NewAttestation::for_test("src/a.test.ts", &signer, &sk, None, &rec).with_columns(&c);
    assert_eq!(att.validate().unwrap().as_bytes(), rec.as_slice());
    assert_eq!(att.columns, Some(&c));
    let stored = att.stored(att.plain_key());
    assert_eq!(
        NewAttestation::copy_of(&stored, None).columns,
        None,
        "a copy carries none until asked"
    );
    assert_eq!(
        NewAttestation::copy_of(&stored, None)
            .with_columns(&c)
            .columns,
        Some(&c)
    );
    assert_eq!(OBJECT_GRACE.as_secs(), 3600);
}

/// A backend with only the ten required methods: what the objects section
/// does before the backend keeps objects.
struct Bare;

impl AttestationStore for Bare {
    fn kind(&self) -> &'static str {
        "bare"
    }
    fn list_units(&self, ids: &[&str]) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
        Ok(ids.iter().map(|_| Vec::new()).collect())
    }
    fn list_all(&self) -> Result<Vec<StoredEnvelope>, StoreError> {
        Ok(Vec::new())
    }
    fn read_values(&self, _envs: &mut [&mut StoredEnvelope]) -> Result<(), StoreError> {
        Ok(())
    }
    fn manifest(&self, _root: &str) -> Result<Option<StoredManifest>, StoreError> {
        Ok(None)
    }
    fn manifest_roots(&self) -> Result<Vec<String>, StoreError> {
        Ok(Vec::new())
    }
    fn put(&self, att: &NewAttestation<'_>) -> Result<StoredEnvelope, StoreError> {
        att.validate()?;
        Ok(att.stored(att.plain_key()))
    }
    fn put_manifest(&self, _root: &str, _bytes: &[u8]) -> Result<bool, StoreError> {
        Ok(true)
    }
    fn remove(&self, doomed: Vec<StoredEnvelope>) -> Result<Vec<StoredEnvelope>, StoreError> {
        Ok(doomed)
    }
    fn remove_manifests(&self, _roots: &[&str]) -> Result<usize, StoreError> {
        Ok(0)
    }
}

#[test]
fn the_defaults_refuse_objects_as_unsupported_and_keep_no_columns() {
    let s: Arc<dyn AttestationStore> = Arc::new(Bare);
    assert_eq!(s.caps(), Caps::LOCAL);
    assert!(!s.caps().objects && !s.caps().columns);
    assert!(Caps::LOCAL.with_objects(true).objects);
    assert!(Caps::LOCAL.with_columns(true).columns);
    let id = hex64(1);
    let unsupported = |what: &str, r: Result<(), StoreError>| match r {
        Err(StoreError::Unsupported {
            backend: "bare",
            operation: "format-3 objects",
        }) => {}
        other => panic!("{what}: expected Unsupported, got {other:?}"),
    };
    unsupported("get_objects", s.get_objects(&[&id]).map(drop));
    let bytes = b"vo\x01\x01";
    unsupported(
        "put_objects",
        s.put_objects(&[NewObject::new(ObjectKind::Hdr, bytes)])
            .map(drop),
    );
    unsupported("remove_objects", s.remove_objects(&[&id]).map(drop));
    unsupported("orphan_objects", s.orphan_objects().map(drop));
    unsupported(
        "prune_state_objects",
        s.prune_state_objects(OBJECT_GRACE).map(drop),
    );
    assert_eq!(
        StoreError::Unsupported {
            backend: "bare",
            operation: "format-3 objects"
        }
        .to_string(),
        "the bare store does not support format-3 objects"
    );
    // Validation comes before the refusal.
    let invalid = |what: &'static str, r: Result<(), StoreError>| match r {
        Err(StoreError::Invalid { what: w, .. }) if w == what => {}
        other => panic!("expected Invalid {what}, got {other:?}"),
    };
    invalid("object id", s.get_objects(&["nope"]).map(drop));
    invalid("object id", s.remove_objects(&[&id, "nope"]).map(drop));
    invalid(
        "object",
        s.put_objects(&[NewObject::new(ObjectKind::Hdr, b"")])
            .map(drop),
    );
    // Columns: none, one per entry.
    let e = StoredEnvelope::from_key(
        "project",
        &key::attestation_key(&hex64(1), &"1".repeat(16), &hex64(2)),
    )
    .unwrap();
    assert_eq!(
        s.columns(&[&e, &e]).unwrap(),
        vec![Columns::default(), Columns::default()]
    );
    assert!(s.columns(&[]).unwrap().is_empty());
    // A put with columns is accepted and ignored.
    let c = Columns {
        format: Some(3),
        ..Columns::default()
    };
    let rec = frame(&hex64(1), &hex64(2), &[3; 32]);
    let (signer, sk) = ("1".repeat(16), hex64(2));
    let att = NewAttestation::for_test("src/a.test.ts", &signer, &sk, None, &rec).with_columns(&c);
    assert_eq!(s.put(&att).unwrap().bytes, rec);
    // Prefetch of objects is a no-op on the default, with a Debug of counts.
    assert_eq!(
        s.prefetch(Prefetch::Objects { ids: &[&id] }).unwrap(),
        vci_store::Hydration::default()
    );
    assert_eq!(
        format!("{:?}", Prefetch::Objects { ids: &[&id, &id] }),
        "Objects { ids: 2 }"
    );
    // A failed store fails these too.
    let failed = FailedStore::new("x", "down");
    for (what, r) in [
        ("get_objects", failed.get_objects(&[&id]).map(drop)),
        ("remove_objects", failed.remove_objects(&[&id]).map(drop)),
        ("orphan_objects", failed.orphan_objects().map(drop)),
        (
            "prune_state_objects",
            failed.prune_state_objects(OBJECT_GRACE).map(drop),
        ),
        ("columns", failed.columns(&[&e]).map(drop)),
        (
            "put_objects",
            failed
                .put_objects(&[NewObject::new(ObjectKind::Hdr, bytes)])
                .map(drop),
        ),
    ] {
        assert!(
            matches!(r, Err(StoreError::Unavailable { backend: "x", .. })),
            "{what}: {r:?}"
        );
    }
}
