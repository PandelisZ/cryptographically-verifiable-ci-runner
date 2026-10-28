//! Adversarial inputs for the store format 3 decoders (`design/STORE-V2.md`
//! section 1.6 and section 4): the record frame, every object kind, the
//! descriptor, the context and the v2 statement's own fields are fed malformed, oversized,
//! duplicated, conflicting, out-of-range, non-minimal, non-canonical,
//! section-confusing and truncated bytes, built by hand (the encoders are
//! not used for the malformed parts, so that the decoder is tested alone).
//! Every attack must be refused with an error and must never panic: a panic
//! on untrusted bytes is a finding, as is an acceptance.

use std::collections::BTreeMap;

use vci_core::frame::b64_encode;
use vci_core::manifest::{autoload_dir_hash, dir_type_hash, excluded_hash};
use vci_core::objects::{DESCRIPTOR_MAX, NO_GROUP, hex32, parse_hex32};
use vci_core::{
    ABSENT_HASH, Context, DecodeError, Descriptor, EntryKind, EnvEntry, External, FRAME_FIRST_LINE,
    Frame, FrameError, FrameSig, Hdr, InputEntry, InputManifest, MAX_RECORD, ObjectKind,
    PredicateError, RepoPath, ResolvedManifest, ResolvedPredicate, Shape, ShapeEntry, State,
    Tables, VarintError, VciPredicateV2, is_frame, object_id,
};

// ---------------------------------------------------------------- a hand encoder

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

fn uv_bytes(n: u64) -> Vec<u8> {
    let mut v = Vec::new();
    uv(&mut v, n);
    v
}

fn string(out: &mut Vec<u8>, s: &[u8]) {
    uv(out, s.len() as u64);
    out.extend_from_slice(s);
}

/// A prefix-coded item with the longest shared prefix (what the writer
/// does); `prev` is updated.
fn prefixed(out: &mut Vec<u8>, prev: &mut Vec<u8>, item: &[u8]) {
    let shared = item
        .iter()
        .zip(prev.iter())
        .take_while(|(a, b)| a == b)
        .count();
    uv(out, shared as u64);
    uv(out, (item.len() - shared) as u64);
    out.extend_from_slice(&item[shared..]);
    *prev = item.to_vec();
}

/// A prefix-coded item spelled by the attacker: `shared` and the suffix as
/// given.
fn raw_prefixed(out: &mut Vec<u8>, shared: u64, suffix: &[u8]) {
    uv(out, shared);
    uv(out, suffix.len() as u64);
    out.extend_from_slice(suffix);
}

fn header(kind: u8) -> Vec<u8> {
    vec![b'v', b'o', kind, 1]
}

// kind codes: f=0 l=1 a=2 d=3 t=4 x=5 m=6 u=7; exec is bit 7.
const F: u8 = 0;
const A: u8 = 2;
const D: u8 = 3;
const T: u8 = 4;
const X: u8 = 5;
const M: u8 = 6;
const U: u8 = 7;
const EXEC: u8 = 0x80;

/// A shape from (path, kind byte) entries in the order given and groups as
/// absolute index lists (delta-coded here).
fn shape_bytes(entries: &[(&[u8], u8)], groups: &[&[u64]]) -> Vec<u8> {
    let mut out = header(3);
    uv(&mut out, entries.len() as u64);
    let mut prev = Vec::new();
    for (p, k) in entries {
        prefixed(&mut out, &mut prev, p);
        out.push(*k);
    }
    uv(&mut out, groups.len() as u64);
    for g in groups {
        indices(&mut out, g);
    }
    out
}

fn indices(out: &mut Vec<u8>, list: &[u64]) {
    uv(out, list.len() as u64);
    let mut prev: Option<u64> = None;
    for &i in list {
        uv(out, i - prev.map_or(0, |p| p + 1));
        prev = Some(i);
    }
}

/// A state entry as the attacker spells it: path, kind byte, size, and the
/// hash if one is written.
type RawStateEntry<'a> = (&'a [u8], u8, u64, Option<[u8; 32]>);

/// A state from entries in the order given.
fn state_bytes(entries: &[RawStateEntry<'_>]) -> Vec<u8> {
    let mut out = header(4);
    uv(&mut out, entries.len() as u64);
    let mut prev = Vec::new();
    for (p, k, size, hash) in entries {
        prefixed(&mut out, &mut prev, p);
        out.push(*k);
        uv(&mut out, *size);
        if let Some(h) = hash {
            out.extend_from_slice(h);
        }
    }
    out
}

/// A tables object from its three lists in the order given.
fn tables_bytes(waivers: &[&[u8]], env_names: &[&[u8]], externals: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = header(2);
    uv(&mut out, waivers.len() as u64);
    for w in waivers {
        string(&mut out, w);
    }
    uv(&mut out, env_names.len() as u64);
    let mut prev = Vec::new();
    for n in env_names {
        prefixed(&mut out, &mut prev, n);
    }
    uv(&mut out, externals.len() as u64);
    let mut prev = Vec::new();
    for (n, v) in externals {
        prefixed(&mut out, &mut prev, n);
        string(&mut out, v);
    }
    out
}

/// A descriptor from its parts: own as absolute indices, overrides as
/// (index, hash), the two bitmaps as raw bytes, extras as (name, version).
fn descriptor_bytes(
    shape: &[u8; 32],
    group: u8,
    own: &[u64],
    overrides: &[(u64, [u8; 32])],
    env_bitmap: &[u8],
    ext_bitmap: &[u8],
    extras: &[(&[u8], &[u8])],
) -> Vec<u8> {
    let mut out = shape.to_vec();
    out.push(group);
    indices(&mut out, own);
    uv(&mut out, overrides.len() as u64);
    for (i, h) in overrides {
        uv(&mut out, *i);
        out.extend_from_slice(h);
    }
    out.extend_from_slice(env_bitmap);
    out.extend_from_slice(ext_bitmap);
    uv(&mut out, extras.len() as u64);
    for (n, v) in extras {
        string(&mut out, n);
        string(&mut out, v);
    }
    out
}

fn rp(s: &str) -> RepoPath {
    RepoPath::new(s).unwrap()
}

fn h(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn entry(path: &str, kind: EntryKind, exec: bool, size: u64, hash: &str) -> InputEntry {
    InputEntry {
        path: rp(path),
        kind,
        exec,
        size,
        hash: hash.to_owned(),
    }
}

/// The valid objects the attacks start from.
fn good_shape() -> Vec<u8> {
    shape_bytes(
        &[
            (b"a", F),
            (b"a/b.rb", F),
            (b"a/c.rb", F | EXEC),
            (b"lib", D),
            (b"lib/x", X),
            (b"z", A),
        ],
        &[&[0, 1, 3], &[1, 2]],
    )
}

fn good_tables() -> Vec<u8> {
    tables_bytes(
        &[b"go:net:dial: a", b"go:unsafe: b"],
        &[b"HOME", b"PATH", b"RAILS_ENV"],
        &[(b"rails", b"7.1"), (b"rake", b"13.0")],
    )
}

fn decoded_tables() -> Tables {
    Tables::decode(&good_tables()).unwrap()
}

fn decoded_shape() -> Shape {
    Shape::decode(&good_shape()).unwrap()
}

fn good_descriptor() -> Vec<u8> {
    descriptor_bytes(
        &object_id(&good_shape()),
        0,
        &[2, 4],
        &[(1, h(9))],
        &[0b011],
        &[0b10],
        &[(b"zlib", b"1.3")],
    )
}

fn good_state() -> Vec<u8> {
    state_bytes(&[
        (b"a", F, 10, Some(h(1))),
        (b"a", F, 11, Some(h(2))),
        (b"lib", D, 2, Some(h(3))),
        (b"lib/x", X, 0, None),
        (b"z", A, 0, None),
    ])
}

/// Every proper prefix of `bytes` must be refused without a panic.
fn every_truncation<T>(bytes: &[u8], decode: impl Fn(&[u8]) -> Result<T, DecodeError>) {
    for n in 0..bytes.len() {
        assert!(
            decode(&bytes[..n]).is_err(),
            "a prefix of {n} of {} bytes was accepted",
            bytes.len()
        );
    }
}

/// Every single-byte value at every position: decode (and `then`) must
/// return, never panic. Nothing is asserted about the outcome: the point
/// is that no byte pattern reaches an index, a slice or an arithmetic
/// panic.
fn every_byte_value<T>(bytes: &[u8], decode: impl Fn(&[u8]) -> Result<T, DecodeError>) {
    let mut buf = bytes.to_vec();
    for i in 0..bytes.len() {
        for v in 0..=255u8 {
            buf[i] = v;
            let _ = decode(&buf);
        }
        buf[i] = bytes[i];
    }
}

// ---------------------------------------------------------------- the object header

#[test]
fn objects_decode_as_built_by_hand() {
    let s = decoded_shape();
    assert_eq!(s.entries.len(), 6);
    assert_eq!(s.groups, vec![vec![0, 1, 3], vec![1, 2]]);
    let t = decoded_tables();
    assert_eq!(t.waivers.len(), 2);
    assert_eq!(t.env_names, ["HOME", "PATH", "RAILS_ENV"]);
    assert_eq!(t.externals.len(), 2);
    let st = State::decode(&good_state()).unwrap();
    assert_eq!(st.entries.len(), 5);
    assert_eq!(st.entries[3].hash, excluded_hash());
    assert_eq!(st.entries[4].hash, ABSENT_HASH);
    let d = Descriptor::decode(&good_descriptor(), &t).unwrap();
    assert_eq!(d.group, Some(0));
    assert_eq!(d.own, [2, 4]);
    assert_eq!(d.env_read, [0, 1]);
    assert_eq!(d.externals, [1]);
    let r = d.resolve(&s, &t).unwrap();
    assert_eq!(r.set.len(), 5);
    assert_eq!(r.env[1].hash, hex32(&h(9)));
    assert_eq!(r.env[0].hash, ABSENT_HASH);
    assert_eq!(r.externals.len(), 2);
    Hdr::decode(&Hdr::default().encode().unwrap()).unwrap();
}

#[test]
fn the_header_is_checked_for_every_kind() {
    type Decoder = fn(&[u8]) -> Result<(), DecodeError>;
    let cases: [(&str, Vec<u8>, Decoder); 4] = [
        ("hdr", Hdr::default().encode().unwrap(), |b| {
            Hdr::decode(b).map(drop)
        }),
        ("tables", good_tables(), |b| Tables::decode(b).map(drop)),
        ("shape", good_shape(), |b| Shape::decode(b).map(drop)),
        ("state", good_state(), |b| State::decode(b).map(drop)),
    ];
    for (what, good, decode) in &cases {
        assert_eq!(decode(good), Ok(()), "{what}");
        let mut b = good.clone();
        b[0] = b'V';
        assert_eq!(decode(&b), Err(DecodeError::Magic), "{what} magic");
        let mut b = good.clone();
        b[3] = 2;
        assert_eq!(decode(&b), Err(DecodeError::Version(2)), "{what} version");
        let mut b = good.clone();
        b[3] = 0;
        assert_eq!(decode(&b), Err(DecodeError::Version(0)), "{what} version 0");
        // Section confusion: the bytes of another kind under this kind's
        // decoder, and this kind's bytes with another kind byte.
        for (other, bytes, _) in &cases {
            if other != what {
                assert!(
                    matches!(decode(bytes), Err(DecodeError::Kind { .. })),
                    "{what} decoder given {other} bytes"
                );
            }
        }
        for k in [0u8, 5, 0xff] {
            let mut b = good.clone();
            b[2] = k;
            assert!(matches!(decode(&b), Err(DecodeError::Kind { found, .. }) if found == k));
        }
        // A trailing byte, whatever it is.
        for extra in [0u8, 1, 0x80, 0xff] {
            let mut b = good.clone();
            b.push(extra);
            assert_eq!(decode(&b), Err(DecodeError::Trailing(1)), "{what} trailing");
        }
        every_truncation(good, decode);
        every_byte_value(good, decode);
    }
}

#[test]
fn object_bounds_refuse_the_byte_past_the_limit_before_reading() {
    // A buffer one byte over the bound, holding nothing an object holds.
    let over = |kind: ObjectKind| vec![0u8; kind.max_bytes() + 1];
    assert!(matches!(
        Hdr::decode(&over(ObjectKind::Hdr)),
        Err(DecodeError::TooLarge { what: "hdr", .. })
    ));
    assert!(matches!(
        Tables::decode(&over(ObjectKind::Tables)),
        Err(DecodeError::TooLarge { what: "tables", .. })
    ));
    assert!(matches!(
        Shape::decode(&over(ObjectKind::Shape)),
        Err(DecodeError::TooLarge { what: "shape", .. })
    ));
    assert!(matches!(
        State::decode(&over(ObjectKind::State)),
        Err(DecodeError::TooLarge { what: "state", .. })
    ));
    let t = decoded_tables();
    assert!(matches!(
        Descriptor::decode(&vec![0u8; DESCRIPTOR_MAX + 1], &t),
        Err(DecodeError::TooLarge {
            what: "descriptor",
            ..
        })
    ));
    assert!(matches!(
        Descriptor::shape_id(&vec![0u8; DESCRIPTOR_MAX + 1]),
        Err(DecodeError::TooLarge {
            what: "descriptor",
            ..
        })
    ));
    // At the bound exactly, the bytes are read (and refused for what they
    // hold, not for their length).
    let at = vec![0u8; ObjectKind::Hdr.max_bytes()];
    assert_eq!(Hdr::decode(&at), Err(DecodeError::Magic));
}

// ---------------------------------------------------------------- varints and counts

#[test]
fn a_non_minimal_count_is_refused_in_every_list() {
    // The shape's entry count as 0 spelled in two bytes.
    let mut b = header(3);
    b.extend_from_slice(&[0x80, 0x00]);
    b.push(0);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Varint(_))));
    // 6 spelled in two bytes, before six valid entries.
    let good = good_shape();
    let mut b = header(3);
    b.extend_from_slice(&[0x86, 0x00]);
    b.extend_from_slice(&good[5..]);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Varint(_))));
    // A group count of 2 spelled in two bytes.
    let mut b = shape_bytes(&[(b"a", F)], &[]);
    b.pop();
    b.extend_from_slice(&[0x80, 0x00]);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Varint(_))));
    // A state entry's size as a non-minimal varint.
    let mut b = header(4);
    uv(&mut b, 1);
    raw_prefixed(&mut b, 0, b"a");
    b.push(A);
    b.extend_from_slice(&[0x80, 0x00]);
    assert!(matches!(State::decode(&b), Err(DecodeError::Varint(_))));
    // A tables waiver string length as a non-minimal varint.
    let mut b = header(2);
    uv(&mut b, 1);
    b.extend_from_slice(&[0x81, 0x00, b'x']);
    assert!(matches!(Tables::decode(&b), Err(DecodeError::Varint(_))));
    // Eleven continuation bytes, and a value past u64::MAX.
    let mut b = header(3);
    b.extend_from_slice(&[0x80; 11]);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Varint(_))));
    let mut b = header(3);
    b.extend_from_slice(&[0xff; 9]);
    b.push(0x02);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Varint(_))));
}

#[test]
fn a_count_past_the_bytes_remaining_is_refused_before_allocation() {
    // u64::MAX entries announced with nothing after the count. Were the
    // count trusted, Vec::with_capacity would abort the process.
    for kind in [3u8, 4] {
        let mut b = header(kind);
        uv(&mut b, u64::MAX);
        let r = match kind {
            3 => Shape::decode(&b).map(drop),
            _ => State::decode(&b).map(drop),
        };
        assert!(matches!(r, Err(DecodeError::Count { .. })), "{r:?}");
    }
    // u32::MAX + 1 shape entries with ten bytes behind them.
    let mut b = header(3);
    uv(&mut b, 1 << 32);
    b.extend_from_slice(&[0; 10]);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Count { .. })));
    // The waiver table, env names, externals, hdr lists and descriptor
    // lists each check their count.
    let mut b = header(2);
    uv(&mut b, 1 << 40);
    assert!(matches!(Tables::decode(&b), Err(DecodeError::Count { .. })));
    let mut b = header(2);
    uv(&mut b, 0);
    uv(&mut b, 1 << 40);
    assert!(matches!(Tables::decode(&b), Err(DecodeError::Count { .. })));
    let mut b = header(2);
    uv(&mut b, 0);
    uv(&mut b, 0);
    uv(&mut b, 1 << 40);
    assert!(matches!(Tables::decode(&b), Err(DecodeError::Count { .. })));
    let t = decoded_tables();
    let mut b = [7u8; 32].to_vec();
    b.push(NO_GROUP);
    uv(&mut b, 1 << 40);
    assert!(matches!(
        Descriptor::decode(&b, &t),
        Err(DecodeError::Count { .. })
    ));
    let mut b = [7u8; 32].to_vec();
    b.push(NO_GROUP);
    uv(&mut b, 0);
    uv(&mut b, 1 << 40);
    assert!(matches!(
        Descriptor::decode(&b, &t),
        Err(DecodeError::Count { .. })
    ));
    let mut b = [7u8; 32].to_vec();
    b.push(NO_GROUP);
    uv(&mut b, 0);
    uv(&mut b, 0);
    b.push(0);
    b.push(0);
    uv(&mut b, 1 << 40);
    assert!(matches!(
        Descriptor::decode(&b, &t),
        Err(DecodeError::Count { .. })
    ));
    // A hdr whose first string announces a 1 GiB length.
    let mut b = header(1);
    uv(&mut b, 1 << 30);
    assert!(matches!(Hdr::decode(&b), Err(DecodeError::Count { .. })));
}

// ---------------------------------------------------------------- paths

#[test]
fn non_canonical_paths_are_refused_in_shapes_states_and_hdrs() {
    let bad: [&[u8]; 14] = [
        b"",
        b"..",
        b"a/..",
        b"../a",
        b"a/../b",
        b"/a",
        b"a/",
        b"a//b",
        b"./a",
        b"a/./b",
        b"a\\b",
        b"a\0b",
        b"a/.",
        b"..a/../b",
    ];
    for p in bad {
        let s = shape_bytes(&[(p, F)], &[]);
        assert!(
            matches!(Shape::decode(&s), Err(DecodeError::Path(_))),
            "shape accepted {:?}: {:?}",
            String::from_utf8_lossy(p),
            Shape::decode(&s)
        );
        let st = state_bytes(&[(p, F, 1, Some(h(1)))]);
        assert!(
            matches!(State::decode(&st), Err(DecodeError::Path(_))),
            "state accepted {:?}",
            String::from_utf8_lossy(p)
        );
        // A hdr's global manifest entry.
        let mut hb = Hdr::default().encode().unwrap();
        // The default hdr: 7 empty strings, two zero digests, then the
        // entries count (0) at a fixed offset.
        let at = 4 + 7 + 64;
        assert_eq!(hb[at], 0, "the global manifest count");
        let mut tail = hb.split_off(at);
        tail.remove(0);
        uv(&mut hb, 1);
        raw_prefixed(&mut hb, 0, p);
        hb.push(F);
        uv(&mut hb, 1);
        hb.extend_from_slice(&h(1));
        hb.extend_from_slice(&tail);
        assert!(
            matches!(Hdr::decode(&hb), Err(DecodeError::Path(_))),
            "hdr accepted {:?}: {:?}",
            String::from_utf8_lossy(p),
            Hdr::decode(&hb)
        );
    }
    // Non-UTF-8 bytes in a path.
    let s = shape_bytes(&[(b"a\xff", F)], &[]);
    assert_eq!(Shape::decode(&s), Err(DecodeError::Utf8("shape entries")));
    // The root `.` is canonical and accepted (a root listing).
    let s = shape_bytes(&[(b".", D)], &[]);
    assert!(Shape::decode(&s).is_ok());
    // "..." and ".a" are ordinary names.
    let s = shape_bytes(&[(b"...", F), (b".a", F)], &[]);
    assert!(Shape::decode(&s).is_ok());
}

#[test]
fn a_prefix_coded_path_cannot_be_spelled_two_ways() {
    // The first item shares with nothing.
    let mut b = header(3);
    uv(&mut b, 1);
    raw_prefixed(&mut b, 1, b"a");
    b.push(F);
    uv(&mut b, 0);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Prefix(_))));
    // Shared past the previous item's length.
    let mut b = header(3);
    uv(&mut b, 2);
    raw_prefixed(&mut b, 0, b"ab");
    b.push(F);
    raw_prefixed(&mut b, 3, b"c");
    b.push(F);
    uv(&mut b, 0);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Prefix(_))));
    // "ab" then "abc" spelled as shared 1 + "bc": not the longest prefix.
    let mut b = header(3);
    uv(&mut b, 2);
    raw_prefixed(&mut b, 0, b"ab");
    b.push(F);
    raw_prefixed(&mut b, 1, b"bc");
    b.push(F);
    uv(&mut b, 0);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Prefix(_))));
    // "ab" then "ab" spelled as shared 2 + "": a duplicate.
    let mut b = header(3);
    uv(&mut b, 2);
    raw_prefixed(&mut b, 0, b"ab");
    b.push(F);
    raw_prefixed(&mut b, 2, b"");
    b.push(F);
    uv(&mut b, 0);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Unsorted(_))));
    // "ab" then "a" spelled as shared 1 + "": out of order.
    let mut b = header(3);
    uv(&mut b, 2);
    raw_prefixed(&mut b, 0, b"ab");
    b.push(F);
    raw_prefixed(&mut b, 1, b"");
    b.push(F);
    uv(&mut b, 0);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Unsorted(_))));
    // A shared prefix that splits a multi-byte character, joined back to
    // valid UTF-8, is accepted (the writer does the same); joined to
    // invalid UTF-8 it is refused.
    let mut b = header(3);
    uv(&mut b, 2);
    raw_prefixed(&mut b, 0, "é".as_bytes());
    b.push(F);
    raw_prefixed(&mut b, 1, &[0xaa]);
    b.push(F);
    uv(&mut b, 0);
    assert_eq!(
        Shape::decode(&b).unwrap().entries[1].path.as_str(),
        "\u{00ea}"
    );
    let mut b = header(3);
    uv(&mut b, 2);
    raw_prefixed(&mut b, 0, "é".as_bytes());
    b.push(F);
    raw_prefixed(&mut b, 1, &[0x41]);
    b.push(F);
    uv(&mut b, 0);
    assert_eq!(Shape::decode(&b), Err(DecodeError::Utf8("shape entries")));
}

// ---------------------------------------------------------------- shape

#[test]
fn shape_entries_duplicated_or_out_of_order_are_refused() {
    let cases: [&[(&[u8], u8)]; 6] = [
        &[(b"a", F), (b"a", F)],
        &[(b"b", F), (b"a", F)],
        &[(b"a", F | EXEC), (b"a", F)],
        &[(b"a", D), (b"a", F)],
        &[(b"a", U), (b"a", F)],
        &[(b"a/b", F), (b"a", F)],
    ];
    for entries in cases {
        let s = shape_bytes(entries, &[]);
        assert_eq!(
            Shape::decode(&s),
            Err(DecodeError::Unsorted("shape entries")),
            "{entries:?}"
        );
    }
    // The same path under two kinds in kind order is two entries.
    let s = shape_bytes(&[(b"a", F), (b"a", F | EXEC), (b"a", D)], &[]);
    assert_eq!(Shape::decode(&s).unwrap().entries.len(), 3);
}

#[test]
fn shape_kind_bytes_and_autoload_misses_are_checked() {
    for k in [8u8, 9, 0x7f, 0x88, 0xff] {
        let s = shape_bytes(&[(b"a", k)], &[]);
        assert_eq!(Shape::decode(&s), Err(DecodeError::KindByte(k)));
        let st = state_bytes(&[(b"a", k, 0, Some(h(1)))]);
        assert_eq!(State::decode(&st), Err(DecodeError::KindByte(k)));
    }
    for p in [
        &b"a"[..],
        b".vci-autoload",
        b".vci-autoload/a/b",
        b"x/.vci-autoload/a",
        b".",
    ] {
        let s = shape_bytes(&[(p, M)], &[]);
        assert!(
            matches!(Shape::decode(&s), Err(DecodeError::AutoloadMiss(_))),
            "{:?}",
            String::from_utf8_lossy(p)
        );
        let st = state_bytes(&[(p, M, 0, Some(h(1)))]);
        assert!(matches!(
            State::decode(&st),
            Err(DecodeError::AutoloadMiss(_))
        ));
    }
    let s = shape_bytes(&[(b".vci-autoload/Foo", M)], &[]);
    assert_eq!(
        Shape::decode(&s).unwrap().entries[0].kind,
        EntryKind::AutoloadMiss
    );
    // The exec bit on a kind that has no mode decodes (the root decides).
    let s = shape_bytes(&[(b"a", D | EXEC), (b"b", A | EXEC)], &[]);
    let d = Shape::decode(&s).unwrap();
    assert!(d.entries.iter().all(|e| e.exec));
}

#[test]
fn shape_groups_are_bounded_and_in_range() {
    // 256 groups.
    let mut b = shape_bytes(&[(b"a", F)], &[]);
    b.pop();
    uv(&mut b, 256);
    for _ in 0..256 {
        indices(&mut b, &[0]);
    }
    assert_eq!(Shape::decode(&b), Err(DecodeError::TooManyGroups(256)));
    // 255 groups of one entry decode.
    let groups: Vec<&[u64]> = vec![&[0]; 255];
    let b = shape_bytes(&[(b"a", F)], &groups);
    assert_eq!(Shape::decode(&b).unwrap().groups.len(), 255);
    // An index equal to the entry count, in the first and a later position.
    let b = shape_bytes(&[(b"a", F), (b"b", F)], &[&[2]]);
    assert!(matches!(
        Shape::decode(&b),
        Err(DecodeError::Index {
            index: 2,
            len: 2,
            ..
        })
    ));
    let b = shape_bytes(&[(b"a", F), (b"b", F)], &[&[0, 2]]);
    assert!(matches!(
        Shape::decode(&b),
        Err(DecodeError::Index {
            index: 2,
            len: 2,
            ..
        })
    ));
    // A group count announced past the bytes.
    let mut b = shape_bytes(&[(b"a", F)], &[]);
    b.pop();
    uv(&mut b, 200);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Truncated(_))));
    // A group's own count past the bytes.
    let mut b = shape_bytes(&[(b"a", F)], &[]);
    b.pop();
    uv(&mut b, 1);
    uv(&mut b, 1 << 20);
    assert!(matches!(Shape::decode(&b), Err(DecodeError::Count { .. })));
    // A delta that would carry the index past u64::MAX in a group.
    let mut b = shape_bytes(&[(b"a", F)], &[]);
    b.pop();
    uv(&mut b, 1);
    uv(&mut b, 2);
    uv(&mut b, 0);
    uv(&mut b, u64::MAX);
    assert!(Shape::decode(&b).is_err());
    // An empty group decodes (the writer never makes one).
    let b = shape_bytes(&[(b"a", F)], &[&[]]);
    assert_eq!(Shape::decode(&b).unwrap().groups, vec![Vec::<usize>::new()]);
}

// ---------------------------------------------------------------- state

#[test]
fn state_entries_are_sorted_and_hashes_follow_their_kind() {
    // An exact duplicate.
    let b = state_bytes(&[(b"a", F, 1, Some(h(1))), (b"a", F, 1, Some(h(1)))]);
    assert_eq!(
        State::decode(&b),
        Err(DecodeError::Unsorted("state entries"))
    );
    // The same (path, kind, exec, size) with hashes in decreasing order.
    let b = state_bytes(&[(b"a", F, 1, Some(h(2))), (b"a", F, 1, Some(h(1)))]);
    assert_eq!(
        State::decode(&b),
        Err(DecodeError::Unsorted("state entries"))
    );
    // Sizes in decreasing order.
    let b = state_bytes(&[(b"a", F, 2, Some(h(1))), (b"a", F, 1, Some(h(1)))]);
    assert_eq!(
        State::decode(&b),
        Err(DecodeError::Unsorted("state entries"))
    );
    // A constant-hash kind followed by 32 bytes it should not carry: the
    // bytes are read as the next entry and the object is refused.
    let mut b = state_bytes(&[(b"z", A, 0, None)]);
    b.extend_from_slice(&h(1));
    assert!(State::decode(&b).is_err());
    // A hashed kind without its hash.
    let b = state_bytes(&[(b"a", F, 1, None)]);
    assert_eq!(
        State::decode(&b),
        Err(DecodeError::Truncated("state entries"))
    );
    // The constant kinds decode to their constants whatever the size says.
    let b = state_bytes(&[(b"a", A, 7, None), (b"b", X, 7, None), (b"c", U, 7, None)]);
    let s = State::decode(&b).unwrap();
    assert_eq!(s.entries[0].hash, ABSENT_HASH);
    assert_eq!(s.entries[1].hash, excluded_hash());
    assert_eq!(s.entries[2].hash, autoload_dir_hash());
    // A type-only dir carries its (constant) hash in full.
    let dt = parse_hex32(&dir_type_hash()).unwrap();
    let b = state_bytes(&[(b"d", T, 0, Some(dt))]);
    assert_eq!(State::decode(&b).unwrap().entries[0].hash, dir_type_hash());
    // Lookup never indexes past the entries.
    let s = State::decode(&good_state()).unwrap();
    assert_eq!(s.lookup(&rp("a")).len(), 2);
    assert_eq!(s.lookup(&rp("zz")).len(), 0);
    assert_eq!(s.lookup(&rp("0")).len(), 0);
    assert_eq!(
        State::decode(&header(4)).unwrap_err(),
        DecodeError::Truncated("state entries")
    );
    let mut e = header(4);
    e.push(0);
    assert!(State::decode(&e).unwrap().lookup(&rp("a")).is_empty());
}

// ---------------------------------------------------------------- tables

#[test]
fn tables_lists_are_sorted_distinct_and_keys_valid() {
    assert!(matches!(
        Tables::decode(&tables_bytes(&[b"b", b"a"], &[], &[])),
        Err(DecodeError::Unsorted("waiver table"))
    ));
    assert!(matches!(
        Tables::decode(&tables_bytes(&[b"a", b"a"], &[], &[])),
        Err(DecodeError::Unsorted("waiver table"))
    ));
    assert!(matches!(
        Tables::decode(&tables_bytes(&[b"\xff"], &[], &[])),
        Err(DecodeError::Utf8("waiver table"))
    ));
    for k in [&b""[..], b"A=B", b"A\0B"] {
        assert!(
            matches!(
                Tables::decode(&tables_bytes(&[], &[k], &[])),
                Err(DecodeError::EnvKey(_))
            ),
            "{k:?}"
        );
    }
    assert!(matches!(
        Tables::decode(&tables_bytes(&[], &[b"B", b"A"], &[])),
        Err(DecodeError::Unsorted("env names"))
    ));
    assert!(matches!(
        Tables::decode(&tables_bytes(&[], &[], &[(b"a", b"1"), (b"a", b"1")])),
        Err(DecodeError::Unsorted("externals table"))
    ));
    assert!(matches!(
        Tables::decode(&tables_bytes(&[], &[], &[(b"a", b"2"), (b"a", b"1")])),
        Err(DecodeError::Unsorted("externals table"))
    ));
    // An external whose version is missing.
    let mut b = header(2);
    uv(&mut b, 0);
    uv(&mut b, 0);
    uv(&mut b, 1);
    raw_prefixed(&mut b, 0, b"a");
    assert_eq!(
        Tables::decode(&b),
        Err(DecodeError::Truncated("externals table"))
    );
    // Section confusion: a tables object whose waiver strings are the bytes
    // of an env-name list is still three lists, read in order.
    let t = Tables::decode(&tables_bytes(&[b"", b"HOME"], &[], &[])).unwrap();
    assert_eq!(t.waivers, ["", "HOME"]);
    assert!(t.env_names.is_empty());
}

// ---------------------------------------------------------------- hdr

/// The default hdr's bytes with its toolchain JSON replaced by `json`.
fn hdr_with_toolchain_json(json: &[u8]) -> Vec<u8> {
    let good = Hdr::default().encode().unwrap();
    let at = good.iter().position(|&b| b == b'{').unwrap();
    // The length byte precedes the JSON; the four empty lists follow it.
    let len = good[at - 1] as usize;
    let mut out = good[..at - 1].to_vec();
    string(&mut out, json);
    out.extend_from_slice(&good[at + len..]);
    out
}

#[test]
fn hdr_toolchain_json_has_one_spelling() {
    // The default toolchain's canonical scalars: `os` and `arch` are always
    // written, every other scalar only when set, keys sorted, no spaces.
    const CANON: &[u8] = b"{\"arch\":\"\",\"os\":\"\"}";
    let good = Hdr::default().encode().unwrap();
    assert!(good.windows(CANON.len()).any(|w| w == CANON));
    assert!(Hdr::decode(&hdr_with_toolchain_json(CANON)).is_ok());
    for json in [
        &b"{}"[..],
        b"{ \"arch\":\"\",\"os\":\"\"}",
        b"{\"arch\":\"\",\"os\":\"\"} ",
        b"{\"arch\":\"\", \"os\":\"\"}",
        b"{\"os\":\"\",\"arch\":\"\"}",
        b"{\"arch\":\"\",\"node\":\"\",\"os\":\"\"}",
        b"{\"arch\":\"\",\"os\":\"\",\"unknown\":1}",
        b"{\"arch\":\"\",\"os\":\"\",\"rubyGems\":[\"a\"]}",
        b"{\"arch\":\"\",\"os\":\"\",\"superuser\":false}",
        b"{\"arch\":\"\",\"os\":\"\",\"arch\":\"x\"}",
        b"[]",
        b"null",
        b"{",
        b"",
        b"{\"arch\":\"\",\"os\":\"\",\"rust\":\"1\",\"node\":\"2\"}",
    ] {
        assert!(
            matches!(
                Hdr::decode(&hdr_with_toolchain_json(json)),
                Err(DecodeError::Toolchain(_))
            ),
            "{:?}: {:?}",
            String::from_utf8_lossy(json),
            Hdr::decode(&hdr_with_toolchain_json(json))
        );
    }
    let tc = Hdr::decode(&hdr_with_toolchain_json(
        b"{\"arch\":\"\",\"node\":\"2\",\"os\":\"\",\"rust\":\"1\",\"superuser\":true}",
    ))
    .unwrap()
    .toolchain;
    assert_eq!(
        (tc.rust.as_str(), tc.node.as_str(), tc.superuser),
        ("1", "2", true)
    );
    // Deep nesting in the toolchain JSON is bounded by serde_json, not
    // by the stack.
    let deep = format!(
        "{{\"arch\":{}1{},\"os\":\"\"}}",
        "[".repeat(100_000),
        "]".repeat(100_000)
    );
    assert!(matches!(
        Hdr::decode(&hdr_with_toolchain_json(deep.as_bytes())),
        Err(DecodeError::Toolchain(_))
    ));
}

#[test]
fn hdr_global_env_and_externals_are_checked() {
    let good = Hdr::default().encode().unwrap();
    let at = 4 + 7 + 64;
    // entries 0, externals 0, env 0, ignored 0, envSet 0, toolchain JSON, 4 lists.
    assert_eq!(&good[at..at + 3], &[0, 0, 0]);
    let tail = &good[at + 3..];
    let with_env = |env: &[(&[u8], [u8; 32])]| {
        let mut b = good[..at].to_vec();
        b.push(0);
        b.push(0);
        uv(&mut b, env.len() as u64);
        let mut prev = Vec::new();
        for (k, h) in env {
            prefixed(&mut b, &mut prev, k);
            b.extend_from_slice(h);
        }
        b.extend_from_slice(tail);
        b
    };
    for k in [&b""[..], b"A=B", b"A\0"] {
        assert!(matches!(
            Hdr::decode(&with_env(&[(k, h(1))])),
            Err(DecodeError::EnvKey(_))
        ));
    }
    assert!(matches!(
        Hdr::decode(&with_env(&[(b"B", h(1)), (b"A", h(1))])),
        Err(DecodeError::Unsorted(_))
    ));
    assert!(matches!(
        Hdr::decode(&with_env(&[(b"A", h(1)), (b"A", h(2))])),
        Err(DecodeError::Unsorted(_))
    ));
    let ok = Hdr::decode(&with_env(&[(b"A", [0; 32]), (b"B", h(2))])).unwrap();
    assert_eq!(ok.global_env[0].hash, ABSENT_HASH);
    // An env entry whose hash is cut short.
    let mut b = with_env(&[(b"A", h(1))]);
    let cut = b.len() - tail.len() - 1;
    b.remove(cut);
    assert!(Hdr::decode(&b).is_err());
    // Externals out of order.
    let with_ext = |ext: &[(&[u8], &[u8])]| {
        let mut b = good[..at].to_vec();
        b.push(0);
        uv(&mut b, ext.len() as u64);
        let mut prev = Vec::new();
        for (n, v) in ext {
            prefixed(&mut b, &mut prev, n);
            string(&mut b, v);
        }
        b.push(0);
        b.extend_from_slice(tail);
        b
    };
    assert!(matches!(
        Hdr::decode(&with_ext(&[(b"b", b"1"), (b"a", b"1")])),
        Err(DecodeError::Unsorted(_))
    ));
    assert!(Hdr::decode(&with_ext(&[(b"a", b"1"), (b"a", b"2")])).is_ok());
    // A global manifest entry with a bad kind byte, and with a hash where
    // its kind has a constant.
    let with_entries = |raw: &[u8]| {
        let mut b = good[..at].to_vec();
        b.extend_from_slice(raw);
        b.extend_from_slice(&good[at + 1..]);
        b
    };
    let mut raw = uv_bytes(1);
    raw_prefixed(&mut raw, 0, b"a");
    raw.push(9);
    raw.push(0);
    raw.extend_from_slice(&h(1));
    assert_eq!(
        Hdr::decode(&with_entries(&raw)),
        Err(DecodeError::KindByte(9))
    );
    let mut raw = uv_bytes(1);
    raw_prefixed(&mut raw, 0, b"a");
    raw.push(X);
    raw.push(0);
    raw.extend_from_slice(&h(1));
    assert!(Hdr::decode(&with_entries(&raw)).is_err());
    // The hdr's strings may hold anything, line feeds and NUL included:
    // they are compared, never parsed.
    let mut b = header(1);
    string(&mut b, b"repo\n\0");
    b.extend_from_slice(&good[5..]);
    assert_eq!(Hdr::decode(&b).unwrap().repo_id, "repo\n\0");
}

// ---------------------------------------------------------------- descriptor

#[test]
fn descriptor_shape_id_and_group_are_read_within_the_bytes() {
    let t = decoded_tables();
    for n in 0..32 {
        assert_eq!(
            Descriptor::shape_id(&vec![1u8; n]),
            Err(DecodeError::Truncated("shape id"))
        );
    }
    assert_eq!(Descriptor::shape_id(&[1u8; 32]), Ok([1u8; 32]));
    assert_eq!(
        Descriptor::decode(&[1u8; 32], &t),
        Err(DecodeError::Truncated("group"))
    );
    assert_eq!(
        Descriptor::decode(&[], &t),
        Err(DecodeError::Truncated("shape id"))
    );
    every_truncation(&good_descriptor(), |b| Descriptor::decode(b, &t));
    every_byte_value(&good_descriptor(), |b| {
        Descriptor::decode(b, &t).and_then(|d| d.resolve(&decoded_shape(), &t))
    });
    // A trailing byte.
    let mut b = good_descriptor();
    b.push(0);
    assert_eq!(Descriptor::decode(&b, &t), Err(DecodeError::Trailing(1)));
}

#[test]
fn descriptor_own_indices_are_delta_coded_distinct_and_bounded_by_the_shape() {
    let t = decoded_tables();
    let s = decoded_shape();
    let sid = object_id(&good_shape());
    let d = |own: &[u64]| descriptor_bytes(&sid, NO_GROUP, own, &[], &[0], &[0], &[]);
    // Past the shape: refused at resolve.
    let dec = Descriptor::decode(&d(&[6]), &t).unwrap();
    assert!(matches!(
        dec.resolve(&s, &t),
        Err(DecodeError::Index {
            index: 6,
            len: 6,
            ..
        })
    ));
    let dec = Descriptor::decode(&d(&[0, 1 << 40]), &t).unwrap();
    assert!(matches!(
        dec.resolve(&s, &t),
        Err(DecodeError::Index { .. })
    ));
    // u64::MAX as the first (absolute) index.
    let dec = Descriptor::decode(&d(&[u64::MAX]), &t);
    assert!(matches!(dec, Err(DecodeError::Index { .. })), "{dec:?}");
    // A delta that carries past u64::MAX.
    let mut b = sid.to_vec();
    b.push(NO_GROUP);
    uv(&mut b, 2);
    uv(&mut b, u64::MAX - 1);
    uv(&mut b, 1);
    b.push(0);
    b.push(0);
    b.push(0);
    b.push(0);
    assert!(matches!(
        Descriptor::decode(&b, &t),
        Err(DecodeError::Varint(_))
    ));
    // Own entries that the group already has.
    let b = descriptor_bytes(&sid, 0, &[1], &[], &[0], &[0], &[]);
    let dec = Descriptor::decode(&b, &t).unwrap();
    assert_eq!(dec.resolve(&s, &t), Err(DecodeError::Overlap(1)));
    let b = descriptor_bytes(&sid, 0, &[2, 3], &[], &[0], &[0], &[]);
    let dec = Descriptor::decode(&b, &t).unwrap();
    assert_eq!(dec.resolve(&s, &t), Err(DecodeError::Overlap(3)));
    // A group the shape lacks.
    for g in [2u8, 3, 0xfe] {
        let b = descriptor_bytes(&sid, g, &[], &[], &[0], &[0], &[]);
        let dec = Descriptor::decode(&b, &t).unwrap();
        assert_eq!(dec.resolve(&s, &t), Err(DecodeError::Group(g)));
    }
    // A unit in no group with no entries resolves to the empty set.
    let dec = Descriptor::decode(&d(&[]), &t).unwrap();
    assert!(dec.resolve(&s, &t).unwrap().set.is_empty());
    // The shape id in the descriptor is not checked here (the caller
    // recomputes it from the shape's bytes); any 32 bytes decode.
    let b = descriptor_bytes(&[0; 32], NO_GROUP, &[], &[], &[0], &[0], &[]);
    assert!(Descriptor::decode(&b, &t).is_ok());
}

#[test]
fn descriptor_env_overrides_and_bitmaps_are_checked_against_the_tables() {
    let t = decoded_tables();
    let s = decoded_shape();
    let sid = object_id(&good_shape());
    let d = |ov: &[(u64, [u8; 32])], env: &[u8], ext: &[u8]| {
        descriptor_bytes(&sid, NO_GROUP, &[], ov, env, ext, &[])
    };
    // An override index past the three env names.
    for i in [3u64, 4, 1 << 20, u64::MAX] {
        assert!(
            matches!(
                Descriptor::decode(&d(&[(i, h(1))], &[0b111], &[0]), &t),
                Err(DecodeError::Index { .. })
            ),
            "{i}"
        );
    }
    // ABSENT_HASH as a value.
    assert!(matches!(
        Descriptor::decode(&d(&[(0, [0; 32])], &[0b111], &[0]), &t),
        Err(DecodeError::EnvOverride(_))
    ));
    // Duplicate and unsorted indices.
    assert!(matches!(
        Descriptor::decode(&d(&[(0, h(1)), (0, h(2))], &[0b111], &[0]), &t),
        Err(DecodeError::EnvOverride(_))
    ));
    assert!(matches!(
        Descriptor::decode(&d(&[(1, h(1)), (0, h(2))], &[0b111], &[0]), &t),
        Err(DecodeError::EnvOverride(_))
    ));
    // An override whose bitmap bit is clear.
    assert!(matches!(
        Descriptor::decode(&d(&[(1, h(1))], &[0b101], &[0]), &t),
        Err(DecodeError::EnvOverride(_))
    ));
    // A padding bit set in either bitmap.
    assert_eq!(
        Descriptor::decode(&d(&[], &[0b1000], &[0]), &t),
        Err(DecodeError::Bitmap("env names"))
    );
    assert_eq!(
        Descriptor::decode(&d(&[], &[0x80], &[0]), &t),
        Err(DecodeError::Bitmap("env names"))
    );
    assert_eq!(
        Descriptor::decode(&d(&[], &[0], &[0b100]), &t),
        Err(DecodeError::Bitmap("externals"))
    );
    // A bitmap cut short.
    let mut b = sid.to_vec();
    b.push(NO_GROUP);
    uv(&mut b, 0);
    uv(&mut b, 0);
    assert_eq!(
        Descriptor::decode(&b, &t),
        Err(DecodeError::Truncated("env names"))
    );
    b.push(0);
    assert_eq!(
        Descriptor::decode(&b, &t),
        Err(DecodeError::Truncated("externals"))
    );
    // Against tables with no names, the bitmaps are zero bytes long and an
    // override has nowhere to point.
    let empty = Tables::default();
    let b = descriptor_bytes(&sid, NO_GROUP, &[], &[], &[], &[], &[]);
    let dec = Descriptor::decode(&b, &empty).unwrap();
    assert!(dec.env_read.is_empty() && dec.externals.is_empty());
    assert!(matches!(
        Descriptor::decode(&d(&[(0, h(1))], &[], &[]), &empty),
        Err(DecodeError::Index { len: 0, .. })
    ));
    // The same descriptor bytes against another tables object (a store
    // that serves the wrong one) decode to other sets or fail; never a
    // panic, and the resolved env is the tables' names.
    let other = Tables::decode(&tables_bytes(&[], &[b"A"], &[])).unwrap();
    let good = good_descriptor();
    let _ = Descriptor::decode(&good, &other).map(|d| d.resolve(&s, &other));
    let ok = Descriptor::decode(&d(&[(0, h(5))], &[1], &[0]), &t).unwrap();
    let r = ok.resolve(&s, &t).unwrap();
    assert_eq!(
        r.env,
        [EnvEntry {
            key: "HOME".into(),
            hash: hex32(&h(5))
        }]
    );
}

#[test]
fn descriptor_inline_externals_are_sorted_distinct_and_not_in_the_table() {
    let t = decoded_tables();
    let s = decoded_shape();
    let sid = object_id(&good_shape());
    let d = |extras: &[(&[u8], &[u8])]| {
        descriptor_bytes(&sid, NO_GROUP, &[], &[], &[0], &[0b11], extras)
    };
    assert!(matches!(
        Descriptor::decode(&d(&[(b"b", b"1"), (b"a", b"1")]), &t),
        Err(DecodeError::Unsorted("inline externals"))
    ));
    assert!(matches!(
        Descriptor::decode(&d(&[(b"a", b"1"), (b"a", b"1")]), &t),
        Err(DecodeError::Unsorted("inline externals"))
    ));
    assert!(matches!(
        Descriptor::decode(&d(&[(b"\xff", b"1")]), &t),
        Err(DecodeError::Utf8(_))
    ));
    // In the table and in the extras: refused at resolve.
    let dec = Descriptor::decode(&d(&[(b"rails", b"7.1")]), &t).unwrap();
    assert!(matches!(dec.resolve(&s, &t), Err(DecodeError::Extra(_))));
    // The same name at another version is another pair.
    let dec = Descriptor::decode(&d(&[(b"rails", b"7.2")]), &t).unwrap();
    assert_eq!(dec.resolve(&s, &t).unwrap().externals.len(), 3);
    // Empty names and versions are strings like any other.
    let dec = Descriptor::decode(&d(&[(b"", b"")]), &t).unwrap();
    assert_eq!(
        dec.resolve(&s, &t).unwrap().externals[0],
        External {
            name: String::new(),
            version: String::new()
        }
    );
}

// ---------------------------------------------------------------- context and statement

fn v2(hdr: &str, tables: &str, waived: Vec<u16>) -> VciPredicateV2 {
    VciPredicateV2 {
        arch_specific: vec![],
        argv: vec![],
        cfg_predicates: vec![],
        commit: "c".into(),
        declared_inputs: vec![],
        entries_root: "e".into(),
        expires_at: "x".into(),
        hdr: hdr.into(),
        issued_at: "i".into(),
        platform_specific: vec![],
        result: vci_core::TestResult {
            state: "passed".into(),
            tests: 1,
            failed: 0,
            skipped: 0,
            duration_ms: 1,
        },
        tables: tables.into(),
        tainted: vec![],
        test_id: "t".into(),
        tree: None,
        tree_dirty: false,
        waived,
    }
}

#[test]
fn context_checks_the_ids_over_exactly_the_bytes_given() {
    let hb = Hdr::default().encode().unwrap();
    let tb = good_tables();
    let hid = hex32(&object_id(&hb));
    let tid = hex32(&object_id(&tb));
    assert!(Context::decode(&v2(&hid, &tid, vec![]), &hb, &tb).is_ok());
    // Upper-case hex is another spelling and never matches.
    assert!(matches!(
        Context::decode(&v2(&hid.to_uppercase(), &tid, vec![]), &hb, &tb),
        Err(PredicateError::ObjectId { what: "hdr", .. })
    ));
    // The bytes with a trailing byte: another id, and refused on both
    // counts (the id first).
    let mut hb2 = hb.clone();
    hb2.push(0);
    assert!(matches!(
        Context::decode(&v2(&hid, &tid, vec![]), &hb2, &tb),
        Err(PredicateError::ObjectId { what: "hdr", .. })
    ));
    let hid2 = hex32(&object_id(&hb2));
    assert!(matches!(
        Context::decode(&v2(&hid2, &tid, vec![]), &hb2, &tb),
        Err(PredicateError::Object {
            what: "hdr",
            source: DecodeError::Trailing(1)
        })
    ));
    // Section confusion: the tables bytes under the hdr id (the id of the
    // tables bytes written into the hdr field) decode as the wrong kind.
    assert!(matches!(
        Context::decode(&v2(&tid, &hid, vec![]), &tb, &hb),
        Err(PredicateError::Object {
            what: "hdr",
            source: DecodeError::Kind { .. }
        })
    ));
    // Ids that are not hex at all, or the right id of other bytes.
    assert!(matches!(
        Context::decode(&v2("", &tid, vec![]), &hb, &tb),
        Err(PredicateError::ObjectId { .. })
    ));
    assert!(matches!(
        Context::decode(&v2(&hid, &tid, vec![]), &hb, b""),
        Err(PredicateError::ObjectId { what: "tables", .. })
    ));
    // Waived ids are checked at resolve: out of range, unsorted, duplicate.
    let ctx = Context::decode(&v2(&hid, &tid, vec![]), &hb, &tb).unwrap();
    for (w, ok) in [
        (vec![0u16, 1], true),
        (vec![1], true),
        (vec![], true),
        (vec![2], false),
        (vec![u16::MAX], false),
        (vec![1, 0], false),
        (vec![0, 0], false),
        (vec![0, 1, 1], false),
    ] {
        let p = v2(&hid, &tid, w.clone());
        let r = ctx.resolve(&p, "r");
        assert_eq!(r.is_ok(), ok, "{w:?}: {:?}", r.err());
        if let Ok(r) = r {
            let waived = r.waived();
            assert_eq!(waived.len(), w.len());
            for (i, s) in w.iter().zip(&waived) {
                assert_eq!(*s, ctx.tables.waivers[usize::from(*i)]);
            }
        }
    }
    let _ = ResolvedPredicate::v1;
}

#[test]
fn the_v2_predicate_json_refuses_ids_that_are_not_u16() {
    let good = v2(&"a".repeat(64), &"b".repeat(64), vec![1]);
    let text = good.to_json().unwrap();
    assert!(VciPredicateV2::from_json(text.as_bytes()).is_ok());
    for (from, to) in [
        ("[1]", "[65536]"),
        ("[1]", "[-1]"),
        ("[1]", "[1.5]"),
        ("[1]", "[\"1\"]"),
        ("[1]", "[null]"),
        ("[1]", "[1e3]"),
        ("[1]", "[18446744073709551616]"),
    ] {
        let t = text.replacen(from, to, 1);
        assert_ne!(t, text);
        assert!(
            VciPredicateV2::from_json(t.as_bytes()).is_err(),
            "{to} accepted"
        );
    }
    // Numbers that fit decode; a float with no fraction does not.
    let t = text.replacen("[1]", "[65535]", 1);
    assert_eq!(
        VciPredicateV2::from_json(t.as_bytes()).unwrap().waived,
        [65535]
    );
    let t = text.replacen("[1]", "[1.0]", 1);
    assert!(VciPredicateV2::from_json(t.as_bytes()).is_err());
    // Missing required members.
    let t = text.replacen("\"commit\":\"c\",", "", 1);
    assert_ne!(t, text);
    assert!(VciPredicateV2::from_json(t.as_bytes()).is_err());
}

// ---------------------------------------------------------------- the binding

/// The security argument's mutations (section 4): a store that changes the
/// resolved set changes what is observed and so the root. Observation is
/// simulated by looking the resolved entries up in the attested manifest
/// (what a checkout at HEAD would give for an unchanged tree).
#[test]
fn a_store_side_change_of_the_resolved_set_changes_the_root() {
    let m = InputManifest {
        entries: vec![
            entry("a.rb", EntryKind::File, false, 10, &hex32(&h(1))),
            entry("bin/run", EntryKind::File, true, 20, &hex32(&h(2))),
            entry("lib", EntryKind::DirListing, false, 2, &hex32(&h(3))),
            entry("lib/x", EntryKind::Excluded, false, 0, &excluded_hash()),
            entry("tmp", EntryKind::Dir, false, 0, &dir_type_hash()),
            entry("gone", EntryKind::Absent, false, 0, ABSENT_HASH),
        ],
        externals: vec![External {
            name: "rails".into(),
            version: "7.1".into(),
        }],
        env: vec![
            EnvEntry {
                key: "HOME".into(),
                hash: ABSENT_HASH.into(),
            },
            EnvEntry {
                key: "RAILS_ENV".into(),
                hash: hex32(&h(4)),
            },
        ],
    };
    let signed = m.root();
    let attested: BTreeMap<RepoPath, InputEntry> = m
        .entries
        .iter()
        .map(|e| (e.path.clone(), e.clone()))
        .collect();
    let observe = |set: &[ShapeEntry]| -> Vec<InputEntry> {
        set.iter()
            .map(|s| match s.kind {
                // The constant kinds come back as constants (manifest.rs
                // observe_from); every other kind as what is on disk.
                EntryKind::Excluded => entry(
                    s.path.as_str(),
                    EntryKind::Excluded,
                    false,
                    0,
                    &excluded_hash(),
                ),
                EntryKind::AutoloadDir => entry(
                    s.path.as_str(),
                    EntryKind::AutoloadDir,
                    false,
                    0,
                    &autoload_dir_hash(),
                ),
                _ => attested
                    .get(&s.path)
                    .cloned()
                    .unwrap_or_else(|| InputEntry::absent(s.path.clone())),
            })
            .collect()
    };
    let r = ResolvedManifest::of(&m);
    let root_of = |r: &ResolvedManifest| {
        InputManifest::from_observed(&r.set, observe(&r.set), r.externals.clone(), r.env.clone())
            .unwrap()
            .root()
    };
    assert_eq!(root_of(&r), signed, "the honest set gives the signed root");

    let mut muts: Vec<(&str, ResolvedManifest)> = Vec::new();
    // Omitted entry.
    let mut x = r.clone();
    x.set.remove(0);
    muts.push(("omitted entry", x));
    // Added entry (absent at HEAD).
    let mut x = r.clone();
    x.set.insert(
        0,
        ShapeEntry {
            path: rp("0"),
            kind: EntryKind::File,
            exec: false,
        },
    );
    muts.push(("added entry", x));
    // Exec bit flipped: the observer reports the real mode, so the set's
    // bit alone changes nothing; the root compares what is on disk.
    // Kind relabel to a constant kind: the file is not observed.
    let mut x = r.clone();
    x.set[0].kind = EntryKind::Excluded;
    muts.push(("file relabelled excluded", x));
    let mut x = r.clone();
    x.set[0].kind = EntryKind::AutoloadDir;
    muts.push(("file relabelled autoload dir", x));
    // Env override and bitmap.
    let mut x = r.clone();
    x.env[0].hash = hex32(&h(9));
    muts.push(("env value", x));
    let mut x = r.clone();
    x.env.pop();
    muts.push(("env name dropped", x));
    let mut x = r.clone();
    x.env.push(EnvEntry {
        key: "ZZ".into(),
        hash: ABSENT_HASH.into(),
    });
    muts.push(("env name added", x));
    // Externals.
    let mut x = r.clone();
    x.externals[0].version = "7.2".into();
    muts.push(("external version", x));
    let mut x = r.clone();
    x.externals.clear();
    muts.push(("externals cleared", x));
    // Duplicate rows.
    let mut x = r.clone();
    let dup = x.set[0].clone();
    x.set.insert(0, dup);
    muts.push(("duplicate row", x));
    for (what, x) in &muts {
        assert_ne!(root_of(x), signed, "{what} kept the signed root");
    }
    // An observation that does not follow the set is refused, not hashed.
    let obs = observe(&r.set);
    assert!(InputManifest::from_observed(&r.set[1..], obs.clone(), vec![], vec![]).is_err());
    let mut swapped = obs.clone();
    swapped.swap(0, 1);
    assert!(InputManifest::from_observed(&r.set, swapped, vec![], vec![]).is_err());
    let mut short = obs.clone();
    short.pop();
    assert!(InputManifest::from_observed(&r.set, short, vec![], vec![]).is_err());
    // from_observed over the attested values gives back the manifest's
    // entries root too.
    let back =
        InputManifest::from_observed(&r.set, obs, r.externals.clone(), r.env.clone()).unwrap();
    assert_eq!(back.entries_root(), m.entries_root());
    assert_ne!(back.entries_root(), back.root(), "another domain");
}

// ---------------------------------------------------------------- the record frame

// Adversarial records for the frame decoder (section 1.6 rule 1 and 2,
// section 4): malformed, oversized, truncated, section-confusing and
// non-canonical values built by hand. Every attack must be refused with an
// error, never a panic. What the envelope a frame rebuilds covers is
// vci-attest's tests/adversarial.rs, beside the conversion.

fn frame_sig(kind: u8, keyid: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    uv(&mut out, keyid.len() as u64);
    out.extend_from_slice(keyid);
    uv(&mut out, sig.len() as u64);
    out.extend_from_slice(sig);
    out
}

const STATEMENT: &str = r#"{"_type":"https://in-toto.io/Statement/v1","predicate":{"testId":"t"},"predicateType":"https://vci.dev/test-attestation/v2","subject":[{"digest":{"blake3":"ab"},"name":"t"}]}"#;

fn record(statement: &str, sig: &[u8], descriptor: &[u8]) -> Vec<u8> {
    format!(
        "vci3\n{statement}\n{}\n{}",
        b64_encode(sig),
        b64_encode(descriptor)
    )
    .into_bytes()
}

fn good() -> Vec<u8> {
    record(STATEMENT, &frame_sig(1, b"SHA256:k", &[9; 180]), &[1, 2, 3])
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
    let sf = frame_sig(1, b"SHA256:k", &[9; 180]);
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
    assert!(serde_json::from_slice::<serde_json::Value>(&good()).is_err());
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
    let cr = format!(
        "vci3\n{{}}\r\n{}\nAA==",
        b64_encode(&frame_sig(1, b"k", &[1]))
    );
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
    let f = Frame::decode(&record("{not json", &frame_sig(1, b"", &[1]), &[])).unwrap();
    assert_eq!(f.statement, b"{not json");
    let f = Frame::decode(&record("{\r\t }", &frame_sig(1, b"", &[1]), &[])).unwrap();
    assert_eq!(f.statement, b"{\r\t }");
}

#[test]
fn the_record_bound_and_the_encoding_are_checked_first() {
    let mut big = good();
    let pad = MAX_RECORD + 1 - big.len();
    // Pad the descriptor with canonical base64 so the content is valid
    // but the size is not.
    let extra = b64_encode(&vec![0u8; pad / 4 * 3]);
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
    let sf = frame_sig(1, b"k", &[1]);
    let fixed = format!("vci3\n{STATEMENT}\n{}\n", b64_encode(&sf)).len();
    let desc_len = (MAX_RECORD - fixed) / 4 * 3;
    let desc = vec![7u8; desc_len];
    let r = record(STATEMENT, &sf, &desc);
    assert!(r.len() <= MAX_RECORD && r.len() > MAX_RECORD - 4);
    assert_eq!(Frame::decode(&r).unwrap().descriptor.len(), desc_len);
}

#[test]
fn base64_fields_must_be_canonical() {
    let sf = b64_encode(&frame_sig(1, b"k", &[1]));
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
        assert_eq!(err(&rec(&frame_sig(k, b"k", &[1]))), FrameError::SigKind(k));
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
        err(&rec(&frame_sig(1, b"k", b""))),
        FrameError::EmptySignature
    );
    let mut sf = frame_sig(1, b"k", &[1]);
    sf.push(0);
    assert_eq!(err(&rec(&sf)), FrameError::TrailingBytes(1));
    sf.extend_from_slice(&[0; 9]);
    assert_eq!(err(&rec(&sf)), FrameError::TrailingBytes(10));
    assert_eq!(
        err(&rec(&frame_sig(1, b"\xff", &[1]))),
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
    let f = Frame::decode(&rec(&frame_sig(1, b"k\n\0id", &[1]))).unwrap();
    assert_eq!(f.keyid, "k\n\0id");
    // Section confusion: an SSHSIG blob that holds a whole signature
    // frame, or JSON, is just the blob.
    let inner = frame_sig(2, b"x", b"{}");
    let f = Frame::decode(&rec(&frame_sig(1, b"k", &inner))).unwrap();
    assert_eq!(f.sig, FrameSig::SshSig(inner));
}

#[test]
fn a_bundle_signature_is_json_of_exactly_sig_and_sigstore() {
    let rec = |json: &[u8]| record(STATEMENT, &frame_sig(2, b"", json), &[1]);
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
    assert_eq!(f.sigstore(), Some(material));
    assert_eq!(f.statement, STATEMENT.as_bytes());
    // Deep nesting is bounded by serde_json.
    let deep = format!(
        "{{\"sig\":{}1{},\"sigstore\":null}}",
        "[".repeat(200_000),
        "]".repeat(200_000)
    );
    assert!(matches!(err(&rec(deep.as_bytes())), FrameError::Json(_)));
}
