//! Lazy values (vci 2.0): a fetch downloads the metadata commits and the
//! tip's trees (blobless; a clone's first fetch takes the older commits
//! without their trees, never shallow), the store gets a
//! row per key without reading a value, and values are fetched in batches
//! when read. Pushing, merging, rewriting history and failing offline all
//! work without the values a clone never read.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use base64::Engine as _;
use camino::{Utf8Path, Utf8PathBuf};
use common::*;
use git_meta_lib::Target;
use vci_git::meta::target_for;
use vci_git::{AttestStore, PushStatus, Repo};

const S1: &str = "0123456789abcdef";
const S2: &str = "fedcba9876543210";
const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";
const D: &str = "src/d.test.ts";

/// A world whose remote serves partial clones (as GitHub does).
fn lazy_world(n: usize) -> World {
    let w = world(n);
    git(&w.remote, &["config", "uploadpack.allowFilter", "true"]);
    w
}

fn repo(root: &Utf8Path) -> Repo {
    Repo::discover(root).unwrap()
}

/// An attestation-sized envelope whose payload references `manifest_root`
/// (`predicate.manifestRef`), as vci 1.9's are.
fn env(tag: &str, manifest_root: &str) -> Vec<u8> {
    let payload = serde_json::json!({
        "predicate": {"manifestRef": manifest_root},
        "pad": tag.repeat(2000 / tag.len().max(1)),
    });
    serde_json::json!({
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64::engine::general_purpose::STANDARD.encode(payload.to_string()),
        "signatures": [],
    })
    .to_string()
    .into_bytes()
}

fn manifest(tag: &str) -> Vec<u8> {
    format!("manifest {tag} {}", "m".repeat(3000)).into_bytes()
}

/// A fresh clone of the world's remote (code only: no metadata, no store;
/// `--no-local`: a local clone would hard-link every object of the remote,
/// metadata included).
fn fresh_clone(w: &World, name: &str) -> Utf8PathBuf {
    let base = w.remote.parent().unwrap();
    let dir = base.join(name);
    git(
        base,
        &["clone", "-q", "--no-local", w.remote.as_str(), dir.as_str()],
    );
    dir
}

/// Whether the clone's object database holds `oid` (never fetching it).
fn has_object(dir: &Utf8Path, oid: &str) -> bool {
    Command::new("git")
        .args(["-C", dir.as_str(), "cat-file", "-e", oid])
        .env("GIT_NO_LAZY_FETCH", "1")
        .status()
        .unwrap()
        .success()
}

/// Every blob of `rev`'s tree in `dir`, by path.
fn tree_blobs(dir: &Utf8Path, rev: &str) -> BTreeMap<String, String> {
    git(dir, &["ls-tree", "-r", "--full-tree", rev])
        .lines()
        .filter_map(|l| {
            let (meta, path) = l.split_once('\t')?;
            let mut f = meta.split(' ');
            let (_, kind, oid) = (f.next()?, f.next()?, f.next()?);
            (kind == "blob").then(|| (path.to_owned(), oid.to_owned()))
        })
        .collect()
}

/// The blob holding the value of `test_id`'s attestation `(signer, sk)` in
/// the remote's metadata.
fn value_blob(w: &World, test_id: &str, signer: &str, sk: &str) -> String {
    let key = vci_git::meta::attestation_key(&vci_core::test_key(test_id), signer, sk);
    let path = git_meta_lib::tree_paths::tree_path(&target_for(test_id), &key).unwrap();
    git(&w.remote, &["rev-parse", &format!("refs/meta/main:{path}")])
}

fn manifest_blob(w: &World, root: &str) -> String {
    let path =
        git_meta_lib::tree_paths::tree_path(&Target::project(), &vci_git::manifest_key(root))
            .unwrap();
    git(&w.remote, &["rev-parse", &format!("refs/meta/main:{path}")])
}

/// Bytes of every stored attestation, by (test key, signer, storage key);
/// a value that cannot be read maps to its error.
type Contents = BTreeMap<(String, String, String), Result<Vec<u8>, String>>;

fn contents(st: &AttestStore) -> Contents {
    st.list(None)
        .unwrap()
        .into_iter()
        .map(|e| {
            (
                (e.test_key, e.signer, e.storage_key),
                match e.error {
                    Some(err) => Err(err),
                    None => Ok(e.bytes),
                },
            )
        })
        .collect()
}

/// The published store: four attestations on three units, two manifests.
/// Returns the publishing clone's store owner and the roots.
fn publish(w: &World) -> (Repo, [String; 2]) {
    let a = repo(&w.clones[0]);
    let st = AttestStore::new(&a);
    let (r1, r2) = (hex64(0xe1), hex64(0xe2));
    st.put_manifest(&r1, &manifest("one")).unwrap();
    st.put_manifest(&r2, &manifest("two")).unwrap();
    st.put(A, S1, &hex64(1), &env("a1", &r1)).unwrap();
    st.put(A, S2, &hex64(2), &env("a2", &r1)).unwrap();
    st.put(B, S1, &hex64(3), &env("b1", &r2)).unwrap();
    st.put(C, S1, &hex64(4), &env("c1", &r2)).unwrap();
    assert_eq!(st.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    (a, [r1, r2])
}

#[test]
fn a_fresh_clone_fetches_keys_only_and_reads_what_it_hydrates() {
    let w = lazy_world(1);
    let (_a, [r1, r2]) = publish(&w);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    let out = sf.fetch(Some("origin")).unwrap();
    assert!(out.found);
    assert!(!out.notes.iter().any(|n| n.contains("in full")), "{out:?}");

    // The first fetch is blobless: not one value is here, but every key
    // is. The repository's promisor is the remote without a URL, never the
    // metadata remote.
    assert_eq!(git(&f, &["rev-parse", "--is-shallow-repository"]), "false");
    assert!(
        !git_raw(&f, &["config", "remote.meta.promisor"])
            .status
            .success()
    );
    assert_eq!(
        git(&f, &["config", "remote.vci-no-lazy-fetch.promisor"]),
        "true"
    );
    let values = [
        value_blob(&w, A, S1, &hex64(1)),
        value_blob(&w, A, S2, &hex64(2)),
        value_blob(&w, B, S1, &hex64(3)),
        value_blob(&w, C, S1, &hex64(4)),
        manifest_blob(&w, &r1),
        manifest_blob(&w, &r2),
    ];
    for oid in &values {
        assert!(!has_object(&f, oid), "{oid} was downloaded by the fetch");
    }
    assert_eq!(sf.count().unwrap(), 4);
    assert_eq!(sf.reader().unwrap().promised().unwrap(), 6);
    let cands = sf.list(Some(A)).unwrap();
    assert_eq!(cands.len(), 2);
    for e in &cands {
        let err = e.error.as_deref().unwrap();
        assert!(err.contains("value not fetched"), "{err}");
    }
    assert!(sf.manifest(&r1).unwrap().unwrap().error.is_some());

    // A plan of unit A reads A's attestations and the manifest they
    // reference: those, and only those, are fetched (one batch each).
    let h = sf.hydrate_units([A]).unwrap();
    assert_eq!(
        (h.resolved, h.unresolved, h.error.as_deref()),
        (3, 0, None),
        "{h:?}"
    );
    assert_eq!(h.fetched, 3);
    let got: BTreeSet<Vec<u8>> = sf
        .list(Some(A))
        .unwrap()
        .into_iter()
        .map(|e| {
            assert_eq!(e.error, None);
            e.bytes
        })
        .collect();
    let want: BTreeSet<Vec<u8>> = [env("a1", &r1), env("a2", &r1)].into_iter().collect();
    assert_eq!(got, want);
    assert_eq!(sf.manifest(&r1).unwrap().unwrap().bytes, manifest("one"));
    for (i, oid) in values.iter().enumerate() {
        assert_eq!(has_object(&f, oid), [0, 1, 4].contains(&i), "value {i}");
    }
    assert!(sf.list(Some(B)).unwrap()[0].error.is_some());
    assert!(sf.manifest(&r2).unwrap().unwrap().error.is_some());
    // Nothing left to fetch for A.
    assert_eq!(sf.hydrate_units([A]).unwrap().resolved, 0);

    // `vci prune` reads every attestation: all of them are fetched, the
    // manifests are not (it only lists their roots).
    let h = sf.hydrate_attestations().unwrap();
    assert_eq!((h.resolved, h.unresolved), (2, 0), "{h:?}");
    assert!(sf.list(None).unwrap().iter().all(|e| e.error.is_none()));
    assert_eq!(sf.reader().unwrap().promised().unwrap(), 1);
    assert!(!has_object(&f, &values[5]));
}

/// A plan fetches the manifests of the attestations it chooses (each unit's
/// newest) and the rest in a later round, for the units that need them: the
/// first round downloads the unit's attestations and only the chosen
/// manifest, the second the other.
#[test]
fn a_plan_fetches_the_chosen_manifests_first_and_the_rest_in_a_later_round() {
    let w = lazy_world(1);
    let a = repo(&w.clones[0]);
    let st = AttestStore::new(&a);
    let (r1, r2) = (hex64(0xe1), hex64(0xe2));
    st.put_manifest(&r1, &manifest("one")).unwrap();
    st.put_manifest(&r2, &manifest("two")).unwrap();
    st.put(A, S1, &hex64(1), &env("a1", &r1)).unwrap();
    st.put(A, S2, &hex64(2), &env("a2", &r2)).unwrap();
    st.put(B, S1, &hex64(3), &env("b1", &r2)).unwrap();
    assert_eq!(st.push(Some("origin")).unwrap().status, PushStatus::Pushed);

    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    assert!(sf.fetch(Some("origin")).unwrap().found);
    // Choose A's attestation by S2 (the one referencing r2): that envelope
    // and r2 are fetched (vci 2.2: the chosen envelopes only), S1's and r1
    // are not.
    let h = sf
        .hydrate_units_choosing([A], |c| {
            c.iter()
                .enumerate()
                .filter(|(_, e)| e.signer == S2)
                .map(|(i, _)| i)
                .collect()
        })
        .unwrap();
    assert_eq!((h.resolved, h.unresolved, h.fetched), (2, 0, 2), "{h:?}");
    let a_list = sf.list(Some(A)).unwrap();
    assert!(a_list.iter().any(|e| e.signer == S2 && e.error.is_none()));
    assert!(a_list.iter().any(|e| e.signer == S1 && e.not_fetched()));
    assert_eq!(sf.manifest(&r2).unwrap().unwrap().bytes, manifest("two"));
    let m1 = sf.manifest(&r1).unwrap().unwrap();
    assert!(m1.not_fetched(), "{m1:?}");
    assert!(!has_object(&f, &manifest_blob(&w, &r1)));
    // The later round takes r1 alone.
    let h = sf.hydrate_manifests([r1.as_str()]).unwrap();
    assert_eq!((h.resolved, h.fetched), (1, 1), "{h:?}");
    assert_eq!(sf.manifest(&r1).unwrap().unwrap().bytes, manifest("one"));
    // B's value was never asked for.
    assert!(sf.list(Some(B)).unwrap()[0].not_fetched());
}

/// A plan fetches the envelopes of the candidates it chooses (vci 2.2:
/// chosen from the keys' hints, nothing read), not every candidate's, and
/// an attestation of the same inputs stored again under a newer hint
/// replaces the old key.
#[test]
fn a_plan_fetches_only_the_chosen_envelopes_and_a_rewrite_replaces_the_key() {
    use vci_git::KeyHint;
    let w = lazy_world(1);
    let a = repo(&w.clones[0]);
    let st = AttestStore::new(&a);
    let (r1, r2) = (hex64(0xe1), hex64(0xe2));
    st.put_manifest(&r1, &manifest("one")).unwrap();
    st.put_manifest(&r2, &manifest("two")).unwrap();
    let old = KeyHint {
        issued: 100,
        tree: None,
    };
    let new = KeyHint {
        issued: 200,
        tree: Some("0123456789abcdef".to_owned()),
    };
    // Two attestations of A by one signer with different inputs (storage
    // keys), one older; the same inputs attested again replace their key.
    st.put_hinted(A, S1, &hex64(1), Some(&old), &env("a-old", &r1))
        .unwrap();
    st.put_hinted(A, S1, &hex64(2), Some(&old), &env("a-new-first", &r2))
        .unwrap();
    st.put_hinted(A, S1, &hex64(2), Some(&new), &env("a-new", &r2))
        .unwrap();
    let keys: Vec<String> = st
        .list(Some(A))
        .unwrap()
        .into_iter()
        .map(|e| e.key)
        .collect();
    assert_eq!(keys.len(), 2, "{keys:?}");
    assert!(
        keys.iter().any(|k| k.ends_with(":c8.0123456789abcdef")),
        "{keys:?}"
    );
    assert!(
        !keys
            .iter()
            .any(|k| k.ends_with(":64.-") && k.contains(&hex64(2))),
        "{keys:?}"
    );
    assert_eq!(st.push(Some("origin")).unwrap().status, PushStatus::Pushed);

    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    assert!(sf.fetch(Some("origin")).unwrap().found);
    // The keys say which is newest before any value is read.
    let cands = sf.list(Some(A)).unwrap();
    assert!(cands.iter().all(|e| e.not_fetched()));
    let newest: Vec<&vci_git::StoredEnvelope> =
        cands.iter().filter(|e| e.issued == Some(200)).collect();
    assert_eq!(newest.len(), 1);
    assert_eq!(newest[0].tree.as_deref(), Some("0123456789abcdef"));
    // Choosing the newest fetches its envelope and manifest only: 2 blobs.
    let h = sf
        .hydrate_units_choosing([A], |c| {
            c.iter()
                .enumerate()
                .filter(|(_, e)| e.issued == Some(200))
                .map(|(i, _)| i)
                .collect()
        })
        .unwrap();
    assert_eq!((h.resolved, h.fetched), (2, 2), "{h:?}");
    let after = sf.list(Some(A)).unwrap();
    assert!(
        after
            .iter()
            .any(|e| e.issued == Some(200) && e.error.is_none())
    );
    assert!(
        after
            .iter()
            .any(|e| e.issued == Some(100) && e.not_fetched())
    );
    assert_eq!(sf.manifest(&r2).unwrap().unwrap().bytes, manifest("two"));
    assert!(sf.manifest(&r1).unwrap().unwrap().not_fetched());
}

/// Two blobless clones delete the same attestation (two jobs superseding
/// the same older one), in either order of their deletion records' stamps;
/// the second to push also stores a new value in that target. Its push must
/// not need the other's deletion record from the remote (vci 2.2.1: vex
/// jobs failed `could not fetch <record> from promisor remote`).
#[test]
fn two_blobless_clones_deleting_the_same_value_both_push() {
    for later_first in [true, false] {
        let w = lazy_world(1);
        publish(&w);
        let open = |name: &str| {
            let dir = fresh_clone(&w, name);
            let r = repo(&dir);
            assert!(AttestStore::new(&r).fetch(Some("origin")).unwrap().found);
            r
        };
        let (r1, r2) = (open("one"), open("two"));
        let (s1, s2) = (AttestStore::new(&r1), AttestStore::new(&r2));
        let doomed = |s: &AttestStore| {
            s.list(Some(A))
                .unwrap()
                .into_iter()
                .find(|e| e.signer == S1)
                .unwrap()
        };
        let (d1, d2) = (doomed(&s1), doomed(&s2));
        if later_first {
            s2.remove(&d2).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
            s1.remove(&d1).unwrap();
        } else {
            s1.remove(&d1).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
            s2.remove(&d2).unwrap();
        }
        s1.put(A, S1, &hex64(0x51), &env("a-one", &hex64(0xe1)))
            .unwrap();
        assert_eq!(s1.push(Some("origin")).unwrap().status, PushStatus::Pushed);
        s2.put(A, S1, &hex64(0x52), &env("a-two", &hex64(0xe1)))
            .unwrap();
        let out = s2.push(Some("origin"));
        assert!(
            matches!(&out, Ok(o) if o.status == PushStatus::Pushed),
            "later_first={later_first}: {out:?}"
        );
    }
}

/// A blobless clone's push when the remote's tip moved since its fetch
/// (another writer's push landed in between): git has no commit of the
/// remote's to build the pack against, so it would walk the whole tree into
/// values this clone never fetched (and, lazy fetch disabled, fail). The
/// push notices the tip moved, fetches it, merges and pushes on top.
#[test]
fn a_blobless_push_retries_when_the_remote_moves_underneath() {
    let w = lazy_world(1);
    let (a, _) = publish(&w);
    let sa = AttestStore::new(&a);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    assert!(sf.fetch(Some("origin")).unwrap().found);
    assert!(sf.reader().unwrap().promised().unwrap() > 0);
    sf.put(D, S2, &hex64(9), &env("d2", &hex64(0xe2))).unwrap();

    let mut attempts = Vec::new();
    let outcome = sf
        .push_with_hook(Some("origin"), |attempt| {
            attempts.push(attempt);
            if attempt == 1 {
                sa.put(D, S1, &hex64(8), &env("d1", &hex64(0xe1))).unwrap();
                assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
            }
        })
        .unwrap();
    assert_eq!(attempts, vec![1, 2], "first push failed, second succeeded");
    eprintln!("push notes: {:?}", outcome.notes);
    // Both writers' values are on the remote; the blobless clone still has
    // not fetched the others' values.
    assert!(sa.fetch(Some("origin")).unwrap().found);
    sa.hydrate_units([D]).unwrap();
    let d: BTreeSet<Vec<u8>> = sa
        .list(Some(D))
        .unwrap()
        .into_iter()
        .map(|e| e.bytes)
        .collect();
    let want: BTreeSet<Vec<u8>> = [env("d1", &hex64(0xe1)), env("d2", &hex64(0xe2))]
        .into_iter()
        .collect();
    assert_eq!(d, want);
    assert!(sf.list(Some(B)).unwrap()[0].not_fetched());
}

/// Storing a manifest whose key the store holds as a promised row (the
/// same bytes, pushed by someone else, fetched as a key only) must leave
/// the value readable here: a row that stays promised is serialized at the
/// blob id the previous commit held, and when the remote has since deleted
/// that manifest the push must send a blob this clone never fetched (vex,
/// 2.1.13 to 2.1.17: every master attest job's push failed on such a
/// manifest).
#[test]
fn storing_the_bytes_of_a_promised_manifest_makes_it_readable() {
    let w = lazy_world(1);
    let (a, [r1, _r2]) = publish(&w);
    let sa = AttestStore::new(&a);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    assert!(sf.fetch(Some("origin")).unwrap().found);
    assert!(sf.manifest(&r1).unwrap().unwrap().not_fetched());
    // The same bytes the remote holds, stored here without fetching them.
    let wrote = sf.put_manifest(&r1, &manifest("one")).unwrap();
    let m = sf.manifest(&r1).unwrap().unwrap();
    assert!(
        m.error.is_none() && m.bytes == manifest("one"),
        "wrote={wrote}: the manifest stays unreadable after storing its bytes: {m:?}"
    );
    // The remote drops that manifest; this clone's push must still work
    // (it carries the manifest, and has its bytes).
    sa.remove_manifests([r1.as_str()]).unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sf.put(D, S2, &hex64(9), &env("d2", &r1)).unwrap();
    let out = sf.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
}

/// As above, with a manifest too large to be stored inline (a blob
/// reference in the store), the size of a Rails file's manifest.
#[test]
fn storing_the_bytes_of_a_promised_large_manifest_makes_it_readable() {
    let w = lazy_world(1);
    let a = repo(&w.clones[0]);
    let sa = AttestStore::new(&a);
    let big: Vec<u8> = format!("manifest big {}", "x".repeat(200_000)).into_bytes();
    let r = hex64(0xb1);
    sa.put_manifest(&r, &big).unwrap();
    sa.put(A, S1, &hex64(1), &env("a1", &r)).unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    assert!(sf.fetch(Some("origin")).unwrap().found);
    assert!(sf.manifest(&r).unwrap().unwrap().not_fetched());
    let wrote = sf.put_manifest(&r, &big).unwrap();
    let m = sf.manifest(&r).unwrap().unwrap();
    assert!(
        m.error.is_none() && m.bytes == big,
        "wrote={wrote}: large manifest unreadable after storing its bytes: {:?} {}",
        m.error,
        m.bytes.len()
    );
    sa.remove_manifests([r.as_str()]).unwrap();
    assert_eq!(sa.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    sf.put(D, S2, &hex64(9), &env("d2", &r)).unwrap();
    let out = sf.push(Some("origin")).unwrap();
    assert_eq!(out.status, PushStatus::Pushed, "{out:?}");
}

#[test]
fn a_push_from_a_blobless_clone_fetches_nothing_and_drops_nothing() {
    let w = lazy_world(1);
    let (a, [_, r2]) = publish(&w);
    let before = tree_blobs(&w.remote, "refs/meta/main");
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();

    // A new attestation on unit C, whose other value (and every other
    // manifest of the project target) was never fetched: git-meta rebuilds
    // both targets' subtrees from rows with values.
    let r3 = hex64(0xe3);
    sf.put_manifest(&r3, &manifest("three")).unwrap();
    sf.put(C, S2, &hex64(5), &env("c2", &r3)).unwrap();
    assert_eq!(sf.push(None).unwrap().status, PushStatus::Pushed);
    let after = tree_blobs(&w.remote, "refs/meta/main");
    for (path, oid) in &before {
        assert_eq!(after.get(path), Some(oid), "{path} changed or was dropped");
    }
    assert_eq!(after.len(), before.len() + 2);
    // No value the clone did not write was fetched to do it.
    for oid in before.values().filter(|o| !o.starts_with("0000")) {
        if !path_is_tombstone(&before, oid) {
            assert!(!has_object(&f, oid), "{oid} was fetched by the push");
        }
    }
    // The push left a fast-forward: the publisher merges it and reads all.
    let sa = AttestStore::new(&a);
    sa.fetch(None).unwrap();
    sa.hydrate_attestations().unwrap();
    sa.hydrate_manifests([r2.as_str(), r3.as_str()]).unwrap();
    assert_eq!(sa.list(Some(C)).unwrap().len(), 2);
    assert!(sa.list(None).unwrap().iter().all(|e| e.error.is_none()));
    assert_eq!(sa.manifest(&r3).unwrap().unwrap().bytes, manifest("three"));
    assert_eq!(sa.manifest(&r2).unwrap().unwrap().bytes, manifest("two"));
    // Nothing is left to push from the blobless clone.
    assert_eq!(sf.push(None).unwrap().status, PushStatus::UpToDate);
}

fn path_is_tombstone(tree: &BTreeMap<String, String>, oid: &str) -> bool {
    tree.iter()
        .any(|(p, o)| o == oid && p.contains("__tombstones"))
}

#[test]
fn a_second_fetch_takes_only_what_changed() {
    let w = lazy_world(1);
    let (a, [r1, _]) = publish(&w);
    let sa = AttestStore::new(&a);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();
    let first_tip = git(&f, &["rev-parse", "refs/meta/remotes/main"]);

    // The publisher adds one attestation and deletes one.
    sa.put(D, S1, &hex64(6), &env("d1", &r1)).unwrap();
    let gone = sa.list(Some(B)).unwrap().remove(0);
    assert!(sa.remove(&gone).unwrap());
    sa.push(None).unwrap();
    let tip = git(&w.remote, &["rev-parse", "refs/meta/main"]);

    let out = sf.fetch(None).unwrap();
    assert!(!out.notes.iter().any(|n| n.contains("in full")), "{out:?}");
    assert_eq!(git(&f, &["rev-parse", "refs/meta/local/main"]), tip);
    // The new commits came with their history: the first tip is an
    // ancestor (later merges keep a merge base).
    git(&f, &["merge-base", "--is-ancestor", &first_tip, &tip]);
    let ids: BTreeSet<String> = sf
        .list(None)
        .unwrap()
        .into_iter()
        .map(|e| e.test_key)
        .collect();
    let want: BTreeSet<String> = [A, C, D].iter().map(|i| vci_core::test_key(i)).collect();
    assert_eq!(ids, want);
    assert!(!has_object(&f, &value_blob(&w, D, S1, &hex64(6))));
    sf.hydrate_units([D]).unwrap();
    assert_eq!(sf.list(Some(D)).unwrap()[0].bytes, env("d1", &r1));
    // Nothing to push: the clone holds exactly the remote's tree.
    assert_eq!(sf.push(None).unwrap().status, PushStatus::UpToDate);
}

#[test]
fn diverged_clones_merge_from_paths_and_push_the_union() {
    let w = lazy_world(1);
    let (a, [r1, r2]) = publish(&w);
    let sa = AttestStore::new(&a);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();

    // Both sides write, including the same key (the local side wins, as in
    // git-meta's merge), and the publisher deletes a value.
    sf.put(D, S1, &hex64(7), &env("d from f", &r1)).unwrap();
    sf.put(A, S1, &hex64(1), &env("a1 from f", &r1)).unwrap();
    sa.fetch(None).unwrap();
    sa.put(D, S2, &hex64(8), &env("d from a", &r2)).unwrap();
    sa.put(A, S1, &hex64(1), &env("a1 from a", &r1)).unwrap();
    let gone = sa.list(Some(C)).unwrap().remove(0);
    sa.remove(&gone).unwrap();
    sa.push(None).unwrap();

    let out = sf.fetch(None).unwrap();
    assert!(!out.notes.iter().any(|n| n.contains("in full")), "{out:?}");
    // The other side's new value was not fetched to merge it.
    assert!(!has_object(&f, &value_blob(&w, D, S2, &hex64(8))));
    assert_eq!(sf.push(None).unwrap().status, PushStatus::Pushed);
    // Linear history on the remote, as before.
    assert_eq!(
        git(&w.remote, &["rev-list", "--merges", "refs/meta/main"]),
        ""
    );

    sa.fetch(None).unwrap();
    sf.hydrate_attestations().unwrap();
    sa.hydrate_attestations().unwrap();
    let want: BTreeMap<(String, String, String), Result<Vec<u8>, String>> = [
        (A, S1, 1, env("a1 from f", &r1)),
        (A, S2, 2, env("a2", &r1)),
        (B, S1, 3, env("b1", &r2)),
        (D, S1, 7, env("d from f", &r1)),
        (D, S2, 8, env("d from a", &r2)),
    ]
    .into_iter()
    .map(|(id, s, k, v)| ((vci_core::test_key(id), s.to_owned(), hex64(k)), Ok(v)))
    .collect();
    assert_eq!(contents(&sf), want);
    assert_eq!(contents(&sa), want);
}

#[test]
fn rewriting_history_from_a_blobless_clone_keeps_every_value() {
    let w = lazy_world(1);
    let (a, [r1, _]) = publish(&w);
    let sa = AttestStore::new(&a);
    sa.fetch(None).unwrap();
    sa.put(D, S1, &hex64(6), &env("d1", &r1)).unwrap();
    sa.push(None).unwrap();
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();
    // The deletion is published, and the publisher merges it, before the
    // rewrite (a clone that still holds a value when the history it shares
    // is replaced keeps it: git-meta's merge without a common ancestor).
    let gone = sf.list(Some(B)).unwrap().remove(0);
    sf.remove(&gone).unwrap();
    sf.push(None).unwrap();
    sa.fetch(None).unwrap();
    assert_eq!(
        sf.push_rewriting_history(None).unwrap().status,
        PushStatus::Pushed
    );
    let tip = git(&w.remote, &["rev-parse", "refs/meta/main"]);
    assert_eq!(
        git(&w.remote, &["rev-list", "--count", &tip]),
        "1",
        "one commit without parents"
    );

    // A new clone reads every value but the deleted one.
    let g = fresh_clone(&w, "after");
    let rg = repo(&g);
    let sg = AttestStore::new(&rg);
    sg.fetch(Some("origin")).unwrap();
    sg.hydrate_attestations().unwrap();
    let mut want = contents(&sa);
    want.remove(&(
        gone.test_key.clone(),
        gone.signer.clone(),
        gone.storage_key.clone(),
    ));
    assert_eq!(contents(&sg), want);
    // The publisher merges the new history.
    sa.fetch(None).unwrap();
    assert_eq!(contents(&sa), want);
}

#[test]
fn values_that_cannot_be_fetched_read_as_not_fetched() {
    let w = lazy_world(1);
    let (_a, _) = publish(&w);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();
    // Offline.
    git(
        &f,
        &["config", "remote.meta.url", "/nonexistent/remote.git"],
    );
    let h = sf.hydrate_units([B]).unwrap();
    assert_eq!((h.resolved, h.unresolved), (0, 1), "{h:?}");
    assert!(h.error.is_some());
    let e = sf.list(Some(B)).unwrap().remove(0);
    assert!(
        e.error
            .as_deref()
            .unwrap()
            .contains("value not fetched: run `vci fetch` online"),
        "{e:?}"
    );
    // Back online, the same call reads it.
    git(&f, &["config", "remote.meta.url", w.remote.as_str()]);
    assert_eq!(sf.hydrate_units([B]).unwrap().resolved, 2);
    assert!(sf.list(Some(B)).unwrap()[0].error.is_none());
}

#[test]
fn a_full_clone_and_a_server_without_filters_keep_working() {
    // A remote that ignores blob filters (an older server): every value is
    // downloaded, and the store reads them directly, as before.
    let w = world(1);
    let (a, [r1, _]) = publish(&w);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();
    assert_eq!(sf.reader().unwrap().promised().unwrap(), 0);
    assert_eq!(contents(&sf), contents(&AttestStore::new(&a)));
    assert_eq!(sf.manifest(&r1).unwrap().unwrap().bytes, manifest("one"));
    assert_eq!(
        sf.hydrate_units([A, B]).unwrap(),
        vci_git::Hydration::default()
    );
}

/// Add a file at `path` with `content` to the remote's refs/meta/main, as a
/// commit on top of it.
fn add_to_remote(remote: &Utf8Path, path: &str, content: &str) {
    let blob = {
        let mut c = Command::new("git")
            .args(["-C", remote.as_str(), "hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write as _;
        c.stdin
            .take()
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();
        String::from_utf8(c.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_owned()
    };
    let index = remote.join("add-index");
    let with_index = |args: &[&str]| {
        let out = Command::new("git")
            .arg("-C")
            .arg(remote.as_str())
            .args(args)
            .env("GIT_INDEX_FILE", index.as_str())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    with_index(&["read-tree", "refs/meta/main"]);
    with_index(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("100644,{blob},{path}"),
    ]);
    let tree = with_index(&["write-tree"]);
    std::fs::remove_file(&index).unwrap();
    let commit = git(
        remote,
        &["commit-tree", &tree, "-p", "refs/meta/main", "-m", "add"],
    );
    git(remote, &["update-ref", "refs/meta/main", &commit]);
}

#[test]
fn a_tree_only_git_meta_merges_is_fetched_in_full_first() {
    // A git-meta set value: vci leaves its merge to git-meta, which reads
    // every value of the trees it merges, so those are fetched first.
    let w = lazy_world(1);
    let (a, [r1, _]) = publish(&w);
    add_to_remote(&w.remote, "project/reviewers/__set/0123456789", "someone");
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    let out = sf.fetch(Some("origin")).unwrap();
    assert!(
        out.notes
            .iter()
            .any(|n| n.contains("in full") && n.contains("project/reviewers/__set/0123456789")),
        "{out:?}"
    );
    assert_eq!(sf.reader().unwrap().promised().unwrap(), 0);
    let sa = AttestStore::new(&a);
    assert_eq!(contents(&sf), contents(&sa));
    assert_eq!(sf.manifest(&r1).unwrap().unwrap().bytes, manifest("one"));
    let s = git_meta_lib::Session::open(f.as_std_path()).unwrap();
    assert!(
        s.target(&Target::project())
            .get_value("reviewers")
            .unwrap()
            .is_some()
    );
    drop(s);

    // Later changes that are only string values merge from paths again.
    sa.fetch(None).unwrap();
    sa.put(D, S1, &hex64(6), &env("d1", &r1)).unwrap();
    sa.push(None).unwrap();
    let out = sf.fetch(None).unwrap();
    assert!(!out.notes.iter().any(|n| n.contains("in full")), "{out:?}");
    assert_eq!(sf.reader().unwrap().promised().unwrap(), 1);
}

// ---- what a blobless metadata fetch does to the rest of the repository ----

/// A commit of the world's code that `dir` does not have: one made in the
/// remote after `dir` was cloned.
fn commit_missing_from(w: &World, dir: &Utf8Path) -> String {
    let base = w.remote.parent().unwrap();
    let other = base.join("other-writer");
    if !other.exists() {
        git(
            base,
            &[
                "clone",
                "-q",
                "--no-local",
                w.remote.as_str(),
                other.as_str(),
            ],
        );
    }
    git(
        &other,
        &["commit", "-q", "--allow-empty", "-m", "elsewhere"],
    );
    git(
        &other,
        &["push", "-q", "origin", "HEAD:refs/heads/elsewhere"],
    );
    let c = git(&other, &["rev-parse", "HEAD"]);
    assert!(!has_object(dir, &c));
    c
}

fn objects_kb(dir: &Utf8Path) -> u64 {
    let out = Command::new("du")
        .args(["-sk", dir.join(".git/objects").as_str()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

/// The metadata fetch leaves the code repository as it was: never shallow
/// (`--unshallow` still refuses a complete repository), the metadata
/// remote not a promisor, so looking up a commit this clone lacks fails at
/// once instead of downloading it with its history, and `git gc`, `git
/// fsck` and `git fetch --all` keep working with the values left out.
#[test]
fn a_metadata_fetch_leaves_the_code_repository_alone() {
    let w = lazy_world(1);
    let (a, _) = publish(&w);
    // A history of several metadata commits (a fresh clone takes their
    // commits, not their trees).
    let sa = AttestStore::new(&a);
    sa.put(D, S1, &hex64(9), &env("d", &hex64(0xe1))).unwrap();
    sa.push(None).unwrap();
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();

    assert_eq!(git(&f, &["rev-parse", "--is-shallow-repository"]), "false");
    assert!(!f.join(".git/shallow").exists());
    let unshallow = git_raw(&f, &["fetch", "--unshallow", "origin"]);
    assert!(!unshallow.status.success(), "the repository is complete");
    for key in ["remote.meta.promisor", "remote.origin.promisor"] {
        assert!(!git_raw(&f, &["config", key]).status.success(), "{key}");
    }
    // The whole metadata history, the trees of the tip only.
    let tip = git(&w.remote, &["rev-parse", "refs/meta/main"]);
    assert_eq!(
        git(&f, &["rev-list", "--count", "refs/meta/remotes/main"]),
        git(&w.remote, &["rev-list", "--count", &tip])
    );
    assert!(has_object(
        &f,
        &git(&w.remote, &["rev-parse", &format!("{tip}^{{tree}}")])
    ));
    assert!(!has_object(
        &f,
        &git(&w.remote, &["rev-parse", &format!("{tip}~1^{{tree}}")])
    ));

    // A commit this clone lacks is unknown, at once and without a download,
    // to git and to vci: on none of a full clone's refs, so a line of
    // history has moved on from it (an attestation of it is superseded).
    let missing = commit_missing_from(&w, &f);
    let kb = objects_kb(&f);
    let out = git_raw(&f, &["merge-base", "--is-ancestor", &missing, "HEAD"]);
    assert!(!out.status.success());
    assert!(!has_object(&f, &missing));
    assert!(rf.resolve(&missing).is_err());
    assert!(
        rf.moved_on(&missing, &git(&f, &["rev-parse", "HEAD"]))
            .unwrap()
    );
    assert_eq!(objects_kb(&f), kb, "nothing was downloaded");

    // The repository's own maintenance accepts the values left out.
    git(&f, &["fsck", "--connectivity-only"]);
    git(&f, &["gc", "--quiet"]);
    git(&f, &["fetch", "--all", "--quiet"]);
    assert!(has_object(&f, &missing), "fetch --all fetched origin");
    // And vci still reads and fetches values after the gc.
    let h = sf.hydrate_units([A]).unwrap();
    assert_eq!((h.resolved, h.error), (3, None));
}

/// The first fetch takes the older commits without their trees; a merge
/// whose base is one of them fetches that tree first.
#[test]
fn a_merge_base_fetched_without_its_tree_is_completed() {
    let w = lazy_world(1);
    let (a, [r1, _]) = publish(&w);
    let sa = AttestStore::new(&a);
    let t1 = git(&w.remote, &["rev-parse", "refs/meta/main"]);
    sa.put(D, S1, &hex64(10), &env("d", &r1)).unwrap();
    sa.push(None).unwrap();
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();
    let t1_tree = git(&w.remote, &["rev-parse", &format!("{t1}^{{tree}}")]);
    assert!(!has_object(&f, &t1_tree));
    sf.put(C, S2, &hex64(11), &env("c from f", &r1)).unwrap();

    // The remote's history moves back to t1 and on another way (a forced
    // push elsewhere): the merge base of the clone's metadata and the new
    // tip is t1, whose tree the clone never fetched.
    let b = fresh_clone(&w, "b");
    git(
        &b,
        &["fetch", "-q", "origin", "+refs/meta/main:refs/meta/old"],
    );
    git(&b, &["update-ref", "refs/meta/main", &t1]);
    let rb = repo(&b);
    let sb = AttestStore::new(&rb);
    git(&w.remote, &["update-ref", "refs/meta/main", &t1]);
    sb.fetch(Some("origin")).unwrap();
    sb.put(B, S2, &hex64(12), &env("b from b", &r1)).unwrap();
    assert_eq!(sb.push(None).unwrap().status, PushStatus::Pushed);

    let out = sf.fetch(None).unwrap();
    assert!(!out.notes.iter().any(|n| n.contains("in full")), "{out:?}");
    assert!(
        has_object(&f, &t1_tree),
        "the merge base's tree was fetched"
    );
    assert_eq!(sf.push(None).unwrap().status, PushStatus::Pushed);
    let keys: BTreeSet<(String, String)> = sf
        .list(None)
        .unwrap()
        .into_iter()
        .map(|e| (e.test_key, e.storage_key))
        .collect();
    for (id, k) in [(C, 11), (B, 12)] {
        assert!(keys.contains(&(vci_core::test_key(id), hex64(k))), "{id}");
    }
    // d's value, which the forced push dropped and this clone never
    // fetched, is not kept (it could not be published).
    assert!(!keys.contains(&(vci_core::test_key(D), hex64(10))));
}

/// The remote's history is rewritten without a value (deleted, then
/// `--rewrite-history`) and the remote's gc removes its blob: a clone that
/// never fetched that value drops it when it merges the new history (it
/// could not publish it), and keeps pushing.
#[test]
fn a_stale_blobless_clone_pushes_after_a_rewrite_and_gc_elsewhere() {
    let w = lazy_world(1);
    let (a, [r1, _]) = publish(&w);
    let sa = AttestStore::new(&a);
    let x = fresh_clone(&w, "stale");
    let rx = repo(&x);
    let sx = AttestStore::new(&rx);
    sx.fetch(Some("origin")).unwrap();
    let b_blob = value_blob(&w, B, S1, &hex64(3));

    let gone = sa.list(Some(B)).unwrap().remove(0);
    assert!(sa.remove(&gone).unwrap());
    sa.push(None).unwrap();
    sa.push_rewriting_history(None).unwrap();
    git(&w.remote, &["reflog", "expire", "--expire=now", "--all"]);
    git(&w.remote, &["gc", "--quiet", "--prune=now"]);
    assert!(
        !has_object(&w.remote, &b_blob),
        "the remote's gc removed b's value"
    );

    sx.put(D, S1, &hex64(13), &env("d from x", &r1)).unwrap();
    assert_eq!(sx.push(None).unwrap().status, PushStatus::Pushed);
    assert!(
        sx.list(Some(B)).unwrap().is_empty(),
        "b's value is gone here too"
    );
    let sa_out = sa.fetch(None).unwrap();
    assert!(sa_out.warnings.is_empty(), "{sa_out:?}");
    sa.hydrate_attestations().unwrap();
    assert!(sa.list(Some(B)).unwrap().is_empty());
    assert_eq!(sa.list(Some(D)).unwrap()[0].bytes, env("d from x", &r1));
}

/// A local metadata commit that holds a value the clone never fetched and
/// the remote no longer has (made before the merge above dropped such
/// values): the push deletes it and publishes the rest instead of failing
/// on every attempt.
#[test]
fn a_push_deletes_values_the_remote_no_longer_has() {
    let w = lazy_world(1);
    let (a, [r1, _]) = publish(&w);
    let sa = AttestStore::new(&a);
    let x = fresh_clone(&w, "stale");
    let rx = repo(&x);
    let sx = AttestStore::new(&rx);
    sx.fetch(Some("origin")).unwrap();
    let old_local = git(&x, &["rev-parse", "refs/meta/local/main"]);

    let gone = sa.list(Some(B)).unwrap().remove(0);
    assert!(sa.remove(&gone).unwrap());
    sa.push(None).unwrap();
    sa.push_rewriting_history(None).unwrap();
    git(&w.remote, &["reflog", "expire", "--expire=now", "--all"]);
    git(&w.remote, &["gc", "--quiet", "--prune=now"]);
    let tip = git(&w.remote, &["rev-parse", "refs/meta/main"]);

    // The state an older merge left: the new tip merged, b's value kept,
    // and the store marked as having materialized that tip.
    git(
        &x,
        &[
            "fetch",
            "-q",
            "--filter=blob:none",
            "meta",
            "+refs/meta/main:refs/meta/remotes/main",
        ],
    );
    let tree = git(&x, &["rev-parse", &format!("{old_local}^{{tree}}")]);
    let merged = git(
        &x,
        &[
            "commit-tree",
            &tree,
            "-p",
            &old_local,
            "-p",
            &tip,
            "-m",
            "an old merge",
        ],
    );
    git(&x, &["update-ref", "refs/meta/local/main", &merged]);
    std::fs::write(
        x.join(".git/vci-materialized-refs_meta_remotes_main"),
        format!("{tip}\n"),
    )
    .unwrap();

    let out = sx.push(None).unwrap();
    assert_eq!(out.status, PushStatus::Pushed);
    assert!(
        out.notes.iter().any(|n| n.contains("no longer has")),
        "{out:?}"
    );
    assert!(sx.list(Some(B)).unwrap().is_empty());
    sa.fetch(None).unwrap();
    sa.hydrate_attestations().unwrap();
    assert!(sa.list(Some(B)).unwrap().is_empty());
    assert_eq!(sa.list(Some(A)).unwrap().len(), 2);
    assert_eq!(sa.list(Some(C)).unwrap().len(), 1);
    let _ = r1;
}

/// A real input manifest listing `paths`, and its root.
fn real_manifest(paths: &[&str]) -> (String, Vec<u8>) {
    let m = vci_core::InputManifest {
        entries: paths
            .iter()
            .map(|p| vci_core::manifest::InputEntry {
                path: vci_core::RepoPath::try_from(*p).unwrap(),
                kind: vci_core::manifest::EntryKind::File,
                exec: false,
                size: 1,
                hash: "ab".repeat(32),
            })
            .collect(),
        externals: vec![],
        env: vec![],
    };
    (m.root(), m.to_compact().into_bytes())
}

/// Supersession's clean-up of manifests in a clone that fetched only some
/// attestations: the attestations not fetched that could reference a
/// manifest (stored on a path the manifest lists, or on the project
/// target) are fetched and read; the others stay unfetched and do not
/// keep it; offline, the manifest is kept.
#[test]
fn manifest_referrers_are_fetched_where_they_can_be() {
    let w = lazy_world(1);
    let a = repo(&w.clones[0]);
    let sa = AttestStore::new(&a);
    // Unit A's manifest lists d's test file too (d observed the same
    // inputs); b's does not.
    let (ra, ma) = real_manifest(&[A, D]);
    let (rb, mb) = real_manifest(&[B]);
    sa.put_manifest(&ra, &ma).unwrap();
    sa.put_manifest(&rb, &mb).unwrap();
    sa.put(A, S1, &hex64(1), &env("a", &ra)).unwrap();
    sa.put(D, S1, &hex64(2), &env("d", &ra)).unwrap();
    sa.put(B, S1, &hex64(3), &env("b", &rb)).unwrap();
    sa.push(Some("origin")).unwrap();

    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();
    sf.hydrate_units([A, B]).unwrap();
    for e in sf
        .list(Some(A))
        .unwrap()
        .into_iter()
        .chain(sf.list(Some(B)).unwrap())
    {
        assert!(sf.remove(&e).unwrap());
    }
    let roots: BTreeSet<String> = [ra.clone(), rb.clone()].into_iter().collect();
    let undecided = sf.hydrate_manifest_referrers(&roots).unwrap();
    assert!(undecided.is_empty(), "{undecided:?}");
    let d = sf.list(Some(D)).unwrap();
    assert_eq!(d[0].bytes, env("d", &ra), "d's attestation was fetched");

    // Offline: d's attestation cannot be fetched, a's manifest is kept.
    let g = fresh_clone(&w, "offline");
    let rg = repo(&g);
    let sg = AttestStore::new(&rg);
    sg.fetch(Some("origin")).unwrap();
    sg.hydrate_units([A, B]).unwrap();
    for e in sg
        .list(Some(A))
        .unwrap()
        .into_iter()
        .chain(sg.list(Some(B)).unwrap())
    {
        assert!(sg.remove(&e).unwrap());
    }
    git(
        &g,
        &["config", "remote.meta.url", "/nonexistent/remote.git"],
    );
    let undecided = sg.hydrate_manifest_referrers(&roots).unwrap();
    assert_eq!(undecided, [ra].into_iter().collect());
    assert!(sg.list(Some(D)).unwrap()[0].not_fetched());
}

/// A server that serves blobless fetches but refuses tree filters: the
/// first fetch takes the commits with their trees, still no value.
#[test]
fn a_server_refusing_tree_filters_still_serves_keys_only() {
    let w = lazy_world(1);
    git(
        &w.remote,
        &["config", "uploadpackfilter.tree.allow", "false"],
    );
    let (_a, _) = publish(&w);
    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    assert!(sf.fetch(Some("origin")).unwrap().found);
    assert!(!has_object(&f, &value_blob(&w, A, S1, &hex64(1))));
    assert_eq!(sf.reader().unwrap().promised().unwrap(), 6);
    assert_eq!(sf.hydrate_units([A]).unwrap().resolved, 3);
}

/// A manifest stored on top of a base (vci 2.1.8: the entries a run's
/// units share, stored once) is read with its base: a fresh lazy clone's
/// plan read of the unit fetches the manifest and then the base, and the
/// decoded manifest is the whole one.
#[test]
fn a_manifest_on_a_base_is_fetched_with_its_base() {
    let w = lazy_world(1);
    let a = repo(&w.clones[0]);
    let sa = AttestStore::new(&a);
    let (rbase, mbase) = real_manifest(&["lib/shared.rb", "config/boot.rb"]);
    let base = vci_core::InputManifest::from_compact(&mbase).unwrap();
    let (rfull, _) = real_manifest(&["lib/shared.rb", "config/boot.rb", A]);
    let full = {
        let (_, bytes) = real_manifest(&["lib/shared.rb", "config/boot.rb", A]);
        vci_core::InputManifest::from_compact(&bytes).unwrap()
    };
    let delta = full.to_compact_on(&base);
    assert!(
        delta.contains(&rbase) && !delta.contains("lib/shared.rb"),
        "{delta}"
    );
    sa.put_manifest(&rbase, &mbase).unwrap();
    sa.put_manifest(&rfull, delta.as_bytes()).unwrap();
    sa.put(A, S1, &hex64(1), &env("a", &rfull)).unwrap();
    assert_eq!(
        sa.manifest_decoded(&rfull)
            .unwrap()
            .unwrap()
            .unwrap()
            .root(),
        rfull
    );
    sa.push(Some("origin")).unwrap();

    let f = fresh_clone(&w, "fresh");
    let rf = repo(&f);
    let sf = AttestStore::new(&rf);
    sf.fetch(Some("origin")).unwrap();
    assert!(sf.manifest(&rfull).unwrap().unwrap().error.is_some());
    assert!(sf.manifest(&rbase).unwrap().unwrap().error.is_some());
    // Without the base: the manifest cannot be decoded, never a manifest
    // with fewer entries.
    let h = sf.hydrate_units([A]).unwrap();
    assert_eq!(h.resolved, 3, "the attestation, the manifest, its base");
    assert_eq!(sf.manifest(&rbase).unwrap().unwrap().bytes, mbase);
    let m = sf.manifest_decoded(&rfull).unwrap().unwrap().unwrap();
    assert_eq!(m.root(), rfull);
    assert_eq!(m.entries.len(), 3);

    // A clone that fetched the manifest but lost its base cannot decode it.
    let g = fresh_clone(&w, "nobase");
    let rg = repo(&g);
    let sg = AttestStore::new(&rg);
    sg.fetch(Some("origin")).unwrap();
    sg.hydrate_manifests([rfull.as_str()]).unwrap();
    assert!(sg.remove_manifest(&rbase).unwrap());
    let err = sg.manifest_decoded(&rfull).unwrap().unwrap().unwrap_err();
    assert!(err.contains("not in the store"), "{err}");
}

/// Values are fetched several `git fetch` processes at once (vci 2.1.11,
/// above a few hundred of them): every one of 1,200 arrives, readable, and
/// `VCI_FETCH_JOBS=1` fetches them one batch after the other as before.
#[test]
fn many_values_are_fetched_in_parallel() {
    let w = lazy_world(1);
    let (a, [r1, _]) = publish(&w);
    let sa = AttestStore::new(&a);
    for i in 0..1200u64 {
        sa.put(
            A,
            S1,
            &format!("{:064x}", 0x1000 + i),
            &env(&format!("v{i}"), &r1),
        )
        .unwrap();
    }
    sa.push(None).unwrap();
    for (name, jobs) in [("par", "4"), ("seq", "1")] {
        let f = fresh_clone(&w, name);
        let rf = repo(&f);
        let sf = AttestStore::new(&rf);
        sf.fetch(Some("origin")).unwrap();
        let before = sf.list(Some(A)).unwrap();
        assert!(before.iter().filter(|e| e.not_fetched()).count() >= 1200);
        // SAFETY: the test's own process, before any thread reads it.
        unsafe { std::env::set_var("VCI_FETCH_JOBS", jobs) };
        let h = sf.hydrate_units([A]).unwrap();
        unsafe { std::env::remove_var("VCI_FETCH_JOBS") };
        assert_eq!(h.unresolved, 0, "{name}: {h:?}");
        assert!(h.resolved >= 1200, "{name}: {h:?}");
        let after = sf.list(Some(A)).unwrap();
        assert!(after.len() >= 1200, "{name}: {}", after.len());
        for e in &after {
            assert!(e.error.is_none() && !e.not_fetched(), "{name}: {e:?}");
            assert!(e.bytes.starts_with(b"{"), "{name}: {e:?}");
        }
        assert_eq!(sf.manifest(&r1).unwrap().unwrap().bytes, manifest("one"));
    }
}
