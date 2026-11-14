//! Which format-3 objects and run links a push removes, decided from keys
//! and local data alone (vci 2.11, [`vci_store::AttestationStore::collect_objects`]).
//!
//! # The rule
//!
//! A run writes, in the batch that stores its records, a run-object link
//! `vci:run-object:<hint>:<signer>:<kind>:<id>` ([`vci_store::run_object_key`])
//! for each of its objects (hdr, tables, shape, state) and each key hint its
//! records carry, whether it put the object or found it stored. A record
//! names only objects of its own run (its statement's hdr and tables, its
//! descriptor's shape; the plan finds its state through the run-state link
//! of its hint), so the objects a record whose key carries `(hint, signer)`
//! may name are among those the links of `(hint, signer)` name: its run's
//! **family** of links. Then, from keys alone:
//!
//! * a family is **live** while some record's key carries its hint and
//!   signer, or while its hint was issued less than [`run_grace_secs`] ago
//!   (an hour: a run still storing outside a batch, which writes its links
//!   before its records);
//! * a record whose `(hint, signer)` has no family (a vci before 2.11, or a
//!   key without a hint) is **legacy**: it may name any object;
//! * an object is **named** when a live family's link, or a run-state link
//!   of a hint some record carries, names it, or when a legacy record's
//!   value, read here, names it;
//! * an hdr, tables or shape object nothing names goes, unless a legacy
//!   record's value is not here (or cannot be read, or there are more than
//!   [`LEGACY_READS_MAX`] to read): then none goes;
//! * a state object goes when nothing names it, or when the newest live
//!   link that names it was issued longer ago than the state TTL (`[store]
//!   explain_hashes_days`); legacy records do not keep one (a record finds
//!   its state only through a run-state link);
//! * a run link goes when its family (its hint, for a run-state link) is
//!   not live.
//!
//! The objects and links chosen are removed only when their row was last
//! put or fetched before the collection began (checked in the delete's
//! write transaction), so a run beside it that names an object again (an
//! idempotent put moves the row's time to now) keeps it. A record pushed
//! by another clone after this one fetched names objects through its own
//! links: the merge of the push puts back an object this clone removed that
//! a live family names ([`crate::AttestStore`]'s put-back of objects).

use std::collections::{BTreeMap, BTreeSet};

use vci_core::ObjectKind;
use vci_store::key::object_key;

use crate::meta::ObjectRow;

/// How long after its hint's issue time a family counts as live without
/// a record, by default: a run that stores outside a batch (only the first
/// one into a repository without a store) puts its links before its
/// records. Inside a batch the links and the records are one transaction,
/// and a row written after a collection began is never removed by it.
pub const RUN_GRACE_SECS: i64 = 60 * 60;

/// [`RUN_GRACE_SECS`], or `VCI_STORE_RUN_GRACE_SECS` (tests).
pub fn run_grace_secs() -> i64 {
    std::env::var("VCI_STORE_RUN_GRACE_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map_or(RUN_GRACE_SECS, |v| v.max(0))
}

/// The most legacy record values a collection reads (local reads only,
/// never a fetch); with more, the legacy records are not read and keep
/// every hdr, tables and shape object.
pub const LEGACY_READS_MAX: usize = 10_000;

/// What the store holds, as keys (values not read).
#[derive(Debug, Default)]
pub struct Keys {
    /// Every attestation key and whether its value is not here (promised).
    pub records: Vec<(String, bool)>,
    /// Every run-object link's key.
    pub run_object_links: Vec<String>,
    /// Every run-state link's key.
    pub run_state_links: Vec<String>,
    /// Every object row.
    pub objects: Vec<ObjectRow>,
}

/// What a collection removes, as `project` keys, and what it found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Decision {
    /// hdr, tables and shape objects.
    pub objects: Vec<String>,
    /// State objects.
    pub state: Vec<String>,
    /// Run-object and run-state links.
    pub links: Vec<String>,
    /// Legacy records (see the module docs).
    pub legacy: usize,
    /// Legacy records whose value is not here.
    pub legacy_unread: usize,
    /// Whether the legacy records keep every hdr, tables and shape object.
    pub blocked: bool,
}

/// The objects the legacy records name, from their values read here:
/// `None` when one cannot be decided (it may name any object).
pub type LegacyNames = Option<BTreeSet<String>>;

/// Decide what to remove (see the module docs). `now` is in seconds,
/// `state_ttl_secs` the state TTL, `grace_secs` [`run_grace_secs`]; `read_legacy` reads the values of the
/// legacy records (all here) and returns the objects they name, or `None`.
pub fn decide(
    keys: &Keys,
    now: i64,
    state_ttl_secs: i64,
    grace_secs: i64,
    read_legacy: impl FnOnce(&[&str]) -> LegacyNames,
) -> Decision {
    let mut out = Decision::default();
    // The families of links, and the record families and hints.
    let mut families: BTreeSet<(&str, &str)> = BTreeSet::new();
    let links: Vec<(&str, &str, &str, ObjectKind, &str)> = keys
        .run_object_links
        .iter()
        .filter_map(|k| {
            let (hint, signer, kind, id) = vci_store::parse_run_object_key(k)?;
            families.insert((hint, signer));
            Some((k.as_str(), hint, signer, kind, id))
        })
        .collect();
    let mut record_families: BTreeSet<(String, &str)> = BTreeSet::new();
    let mut record_hints: BTreeSet<String> = BTreeSet::new();
    let mut legacy: Vec<(&str, bool)> = Vec::new();
    for (key, promised) in &keys.records {
        let Some((_, signer, _)) = vci_store::parse_key(key) else {
            continue;
        };
        match vci_store::parse_key_hint(key) {
            Some(h) => {
                let seg = vci_store::hint_segment(&h);
                if !families.contains(&(seg.as_str(), signer)) {
                    legacy.push((key, *promised));
                }
                record_families.insert((seg.clone(), signer));
                record_hints.insert(seg);
            }
            None => legacy.push((key, *promised)),
        }
    }
    let recent = |seg: &str| hint_issued(seg).is_some_and(|t| t > now - grace_secs);
    let live = |hint: &str, signer: &str| {
        record_families.contains(&(hint.to_owned(), signer)) || recent(hint)
    };
    // What the live links name, with the newest issue time of a live link
    // naming each state object.
    let mut named: BTreeSet<&str> = BTreeSet::new();
    let mut state_newest: BTreeMap<&str, i64> = BTreeMap::new();
    for (key, hint, signer, kind, id) in &links {
        if live(hint, signer) {
            named.insert(id);
            if *kind == ObjectKind::State {
                note_state(&mut state_newest, id, hint);
            }
        } else {
            out.links.push((*key).to_owned());
        }
    }
    for key in &keys.run_state_links {
        let Some((shape, hint, state)) = vci_store::parse_run_state_key(key) else {
            continue;
        };
        let seg = vci_store::hint_segment(&hint);
        if record_hints.contains(&seg) || recent(&seg) {
            named.insert(shape);
            named.insert(state);
            note_state(&mut state_newest, state, &seg);
        } else {
            out.links.push(key.clone());
        }
    }
    // The legacy records: read here, or keeping every hdr, tables and shape.
    out.legacy = legacy.len();
    out.legacy_unread = legacy.iter().filter(|(_, p)| *p).count();
    let legacy_names: LegacyNames = if legacy.is_empty() {
        Some(BTreeSet::new())
    } else if out.legacy_unread > 0 || legacy.len() > LEGACY_READS_MAX {
        None
    } else {
        let ks: Vec<&str> = legacy.iter().map(|(k, _)| *k).collect();
        read_legacy(&ks)
    };
    out.blocked = legacy_names.is_none();
    let state_cutoff = now.saturating_sub(state_ttl_secs);
    for o in &keys.objects {
        let key = object_key(o.kind, &o.id);
        if o.kind == ObjectKind::State {
            let aged = state_newest
                .get(o.id.as_str())
                .is_none_or(|t| *t < state_cutoff);
            if aged {
                out.state.push(key);
            }
            continue;
        }
        let Some(legacy) = &legacy_names else {
            continue;
        };
        if !named.contains(o.id.as_str()) && !legacy.contains(&o.id) {
            out.objects.push(key);
        }
    }
    out.objects.sort();
    out.state.sort();
    out.links.sort();
    out
}

/// Note that a live link issued at `hint` names the state object `id`.
fn note_state<'a>(map: &mut BTreeMap<&'a str, i64>, id: &'a str, hint: &str) {
    let t = hint_issued(hint).unwrap_or(i64::MAX);
    let e = map.entry(id).or_insert(i64::MIN);
    *e = (*e).max(t);
}

/// The issue time (seconds) a hint segment (`<issued hex>.<tree>`) gives.
fn hint_issued(seg: &str) -> Option<i64> {
    let (issued, _) = seg.split_once('.')?;
    i64::from_str_radix(issued, 16).ok()
}

/// The ids of the objects the live families name, and the shape and state
/// of each run-state link whose hint a record carries (the merge's put-back
/// of objects, key-only): see [`decide`].
pub fn live_named(keys: &Keys, now: i64, grace_secs: i64) -> BTreeSet<String> {
    let mut record_families: BTreeSet<(String, String)> = BTreeSet::new();
    let mut record_hints: BTreeSet<String> = BTreeSet::new();
    for (key, _) in &keys.records {
        let (Some((_, signer, _)), Some(h)) =
            (vci_store::parse_key(key), vci_store::parse_key_hint(key))
        else {
            continue;
        };
        let seg = vci_store::hint_segment(&h);
        record_families.insert((seg.clone(), signer.to_owned()));
        record_hints.insert(seg);
    }
    let recent = |seg: &str| hint_issued(seg).is_some_and(|t| t > now - grace_secs);
    let mut out = BTreeSet::new();
    for k in &keys.run_object_links {
        if let Some((hint, signer, _, id)) = vci_store::parse_run_object_key(k)
            && (record_families.contains(&(hint.to_owned(), signer.to_owned())) || recent(hint))
        {
            out.insert(id.to_owned());
        }
    }
    for k in &keys.run_state_links {
        if let Some((shape, hint, state)) = vci_store::parse_run_state_key(k) {
            let seg = vci_store::hint_segment(&hint);
            if record_hints.contains(&seg) || recent(&seg) {
                out.insert(shape.to_owned());
                out.insert(state.to_owned());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vci_store::{KeyHint, attestation_key_hinted, run_object_key, run_state_key};

    const NOW: i64 = 2_000_000_000;
    const DAY: i64 = 86_400;
    const SIGNER: &str = "0123456789abcdef";
    const OTHER: &str = "fedcba9876543210";

    fn id(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn hint(issued: i64) -> KeyHint {
        KeyHint {
            issued,
            tree: Some("aaaaaaaaaaaaaaaa".to_owned()),
        }
    }

    fn record(unit: char, signer: &str, issued: i64) -> String {
        attestation_key_hinted(&unit.to_string().repeat(64), signer, "bb", &hint(issued))
    }

    fn row(kind: ObjectKind, c: char) -> ObjectRow {
        ObjectRow {
            kind,
            id: id(c),
            put_at: 0,
            fetched: true,
        }
    }

    /// A run issued at `issued` by `signer`, naming hdr `h`, tables `t`,
    /// shape `s` and state `st`.
    fn links(issued: i64, signer: &str, objs: &[(ObjectKind, char)]) -> Vec<String> {
        objs.iter()
            .map(|(k, c)| run_object_key(&hint(issued), signer, *k, &id(*c)))
            .collect()
    }

    fn all_rows() -> Vec<ObjectRow> {
        vec![
            row(ObjectKind::Hdr, '1'),
            row(ObjectKind::Hdr, '2'),
            row(ObjectKind::Tables, '3'),
            row(ObjectKind::Shape, '4'),
            row(ObjectKind::Shape, '5'),
            row(ObjectKind::State, '6'),
            row(ObjectKind::State, '7'),
        ]
    }

    fn run_a() -> Vec<String> {
        links(
            NOW - 3 * DAY,
            SIGNER,
            &[
                (ObjectKind::Hdr, '1'),
                (ObjectKind::Tables, '3'),
                (ObjectKind::Shape, '4'),
                (ObjectKind::State, '6'),
            ],
        )
    }

    fn run_b() -> Vec<String> {
        // Names the tables again (content-addressed: the same object).
        links(
            NOW - 2 * DAY,
            SIGNER,
            &[
                (ObjectKind::Hdr, '2'),
                (ObjectKind::Tables, '3'),
                (ObjectKind::Shape, '5'),
                (ObjectKind::State, '7'),
            ],
        )
    }

    fn never(_: &[&str]) -> LegacyNames {
        panic!("no legacy record to read")
    }

    #[test]
    fn a_run_without_records_leaves_its_objects_unless_another_live_run_names_them() {
        let mut ls = run_a();
        ls.extend(run_b());
        let keys = Keys {
            // Only run b has a record left.
            records: vec![(record('c', SIGNER, NOW - 2 * DAY), true)],
            run_object_links: ls,
            run_state_links: vec![],
            objects: all_rows(),
        };
        let d = decide(&keys, NOW, 7 * DAY, RUN_GRACE_SECS, never);
        assert_eq!(
            d.objects,
            vec![
                object_key(ObjectKind::Hdr, &id('1')),
                object_key(ObjectKind::Shape, &id('4'))
            ],
            "the tables run b names again stay"
        );
        assert_eq!(d.state, vec![object_key(ObjectKind::State, &id('6'))]);
        assert_eq!(d.links.len(), 4, "run a's links");
        assert!(d.links.iter().all(|l| run_a().contains(l)));
        assert!(!d.blocked);
    }

    #[test]
    fn a_family_is_its_hint_and_signer() {
        // A record of run a's hint by another signer does not keep run a.
        let keys = Keys {
            records: vec![(record('c', OTHER, NOW - 3 * DAY), true)],
            run_object_links: run_a(),
            run_state_links: vec![],
            objects: all_rows(),
        };
        let d = decide(&keys, NOW, 7 * DAY, RUN_GRACE_SECS, |_| None);
        // That record is legacy (no family of its own) and not here: it
        // keeps every hdr, tables and shape object.
        assert!(d.blocked);
        assert_eq!((d.legacy, d.legacy_unread), (1, 1));
        assert!(d.objects.is_empty());
        // State objects are kept only by links: both go.
        assert_eq!(d.state.len(), 2);
    }

    #[test]
    fn legacy_records_read_here_name_what_they_keep() {
        let legacy_key = record('d', SIGNER, NOW - 9 * DAY);
        let keys = Keys {
            records: vec![(legacy_key.clone(), false)],
            run_object_links: vec![],
            run_state_links: vec![],
            objects: all_rows(),
        };
        let d = decide(&keys, NOW, 7 * DAY, RUN_GRACE_SECS, |ks| {
            assert_eq!(ks, [legacy_key.as_str()]);
            Some([id('2'), id('3'), id('5')].into_iter().collect())
        });
        assert_eq!(
            d.objects,
            vec![
                object_key(ObjectKind::Hdr, &id('1')),
                object_key(ObjectKind::Shape, &id('4'))
            ]
        );
        // One that cannot be decided keeps them all.
        let d = decide(&keys, NOW, 7 * DAY, RUN_GRACE_SECS, |_| None);
        assert!(d.blocked && d.objects.is_empty());
    }

    #[test]
    fn a_legacy_run_state_link_keeps_its_shape_and_state_while_its_hint_has_a_record() {
        let k = record('d', SIGNER, NOW - 3 * DAY);
        let keys = Keys {
            records: vec![(k, false)],
            run_object_links: vec![],
            run_state_links: vec![run_state_key(&id('4'), &hint(NOW - 3 * DAY), &id('6'))],
            objects: all_rows(),
        };
        let d = decide(&keys, NOW, 7 * DAY, RUN_GRACE_SECS, |_| {
            Some(BTreeSet::from([id('1'), id('3')]))
        });
        assert_eq!(
            d.objects,
            vec![
                object_key(ObjectKind::Hdr, &id('2')),
                object_key(ObjectKind::Shape, &id('5'))
            ]
        );
        assert_eq!(d.state, vec![object_key(ObjectKind::State, &id('7'))]);
        assert!(d.links.is_empty());
        // With a state TTL of two days, the run's state is aged.
        let d = decide(&keys, NOW, 2 * DAY, RUN_GRACE_SECS, |_| {
            Some(BTreeSet::from([id('1'), id('3')]))
        });
        assert_eq!(d.state.len(), 2);
    }

    #[test]
    fn a_recent_run_without_records_is_live() {
        // Its records may not be stored yet.
        let ls = links(NOW - 60, SIGNER, &[(ObjectKind::Hdr, '1')]);
        let keys = Keys {
            records: vec![],
            run_object_links: ls,
            run_state_links: vec![],
            objects: vec![row(ObjectKind::Hdr, '1')],
        };
        let d = decide(&keys, NOW, 7 * DAY, RUN_GRACE_SECS, never);
        assert!(d.objects.is_empty() && d.links.is_empty(), "{d:?}");
    }

    #[test]
    fn a_key_without_a_hint_is_legacy() {
        let k = vci_store::attestation_key(&"e".repeat(64), SIGNER, "bb");
        let keys = Keys {
            records: vec![(k, true)],
            run_object_links: vec![],
            run_state_links: vec![],
            objects: all_rows(),
        };
        let d = decide(&keys, NOW, 7 * DAY, RUN_GRACE_SECS, never);
        assert!(d.blocked && d.objects.is_empty());
        assert_eq!(d.legacy, 1);
    }

    #[test]
    fn live_named_is_what_the_live_families_name() {
        let mut ls = run_a();
        ls.extend(run_b());
        let keys = Keys {
            records: vec![(record('c', SIGNER, NOW - 2 * DAY), true)],
            run_object_links: ls,
            run_state_links: vec![],
            objects: vec![],
        };
        let named = live_named(&keys, NOW, RUN_GRACE_SECS);
        assert_eq!(named, BTreeSet::from([id('2'), id('3'), id('5'), id('7')]));
    }
}
