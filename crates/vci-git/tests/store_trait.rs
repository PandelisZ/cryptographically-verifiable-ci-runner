//! git-meta behind the attestation store trait ([`GitMetaStore`]): every
//! answer is the one the concrete [`AttestStore`] gives, the reader pool
//! never hides a store created or downloaded later, and writes keep their
//! keys.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use camino::{Utf8Path, Utf8PathBuf};
use common::*;
use vci_git::meta::reader_queries;
use vci_git::{AttestStore, GitError, GitMetaFactory, GitMetaStore, KeyHint, Repo};
use vci_store::select::Selection;
use vci_store::{
    AttestationStore, BackendFactory, GONE, NOT_FETCHED, NewAttestation, OpenContext, Prefetch,
    PushStatus, StoreError, StoreStatus, StoredEnvelope, ValueState, key,
};

const S1: &str = "0123456789abcdef";
const S2: &str = "fedcba9876543210";
const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";
const D: &str = "src/d.test.ts";
const E: &str = "src/e.test.ts";
/// The repository root: stored on the `project` target.
const ROOT: &str = ".";
/// A cargo unit: stored on `path:rust/core`.
const CARGO: &str = "rust/core#test:it";
const TREE: &str = "0123456789abcdef";
const NONE: &str = "src/none.test.ts";

/// A world whose remote serves partial clones (as GitHub does).
fn lazy_world(n: usize) -> World {
    let w = world(n);
    git(&w.remote, &["config", "uploadpack.allowFilter", "true"]);
    w
}

fn repo(root: &Utf8Path) -> Repo {
    Repo::discover(root).unwrap()
}

/// A fresh clone of the world's remote: code only, no metadata and no store
/// (`--no-local`, so no object of the remote is hard-linked).
fn fresh_clone(w: &World, name: &str) -> Utf8PathBuf {
    let base = w.remote.parent().unwrap();
    let dir = base.join(name);
    git(
        base,
        &["clone", "-q", "--no-local", w.remote.as_str(), dir.as_str()],
    );
    dir
}

/// An attestation-sized envelope whose payload references `manifest_root`.
fn env(tag: &str, manifest_root: &str) -> Vec<u8> {
    let payload = serde_json::json!({
        "predicate": {"manifestRef": manifest_root},
        "pad": tag.repeat(2000 / tag.len().max(1)),
    });
    dsse(&payload)
}

/// An envelope whose predicate has every field `vci run` writes that the
/// command line's envelope reader requires (test id, issued and expiry
/// times), referencing `manifest_root`.
fn full_env(test_id: &str, manifest_root: &str) -> Vec<u8> {
    dsse(&serde_json::json!({
        "predicate": {
            "testId": test_id,
            "issuedAt": "2026-10-01T00:00:00Z",
            "expiresAt": "2027-10-01T00:00:00Z",
            "manifestRef": manifest_root,
        },
    }))
}

fn dsse(payload: &serde_json::Value) -> Vec<u8> {
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

fn hint(issued: i64, tree: Option<&str>) -> KeyHint {
    KeyHint {
        issued,
        tree: tree.map(str::to_owned),
    }
}

/// Make the stored value of `key` a reference to a blob the object
/// database does not hold (as an interrupted download leaves it).
fn lose_blob(dir: &Utf8Path, key: &str) {
    let db = rusqlite::Connection::open(dir.join(".git/git-meta.sqlite")).unwrap();
    let n = db
        .execute(
            "UPDATE metadata SET value = ?1, is_git_ref = 1, is_promised = 0 WHERE key = ?2",
            rusqlite::params![format!("{:040x}", 0xdead_u32), key],
        )
        .unwrap();
    assert_eq!(n, 1, "{key}");
}

/// A clone holding every kind of entry: values written here (inline),
/// fetched values (blob references), a fetched value whose blob is gone,
/// values not fetched (promised), hinted and unhinted keys, on path, cargo
/// and project targets.
struct Rich {
    _w: World,
    repo: Repo,
    /// What each (test id, signer) holds.
    values: BTreeMap<(String, String), Vec<u8>>,
    /// The key whose blob is gone.
    lost: String,
}

fn rich() -> Rich {
    let w = lazy_world(1);
    let a = repo(&w.clones[0]);
    let st = AttestStore::new(&a);
    let (r1, r2) = (hex64(0xe1), hex64(0xe2));
    st.put_manifest(&r1, &manifest("one")).unwrap();
    st.put_manifest(&r2, &manifest("two")).unwrap();
    let mut values = BTreeMap::new();
    let mut put = |id: &str, signer: &str, sk: u8, h: Option<KeyHint>, v: Vec<u8>| {
        let e = st
            .put_hinted(id, signer, &hex64(sk), h.as_ref(), &v)
            .unwrap();
        values.insert((id.to_owned(), signer.to_owned()), v);
        e.key
    };
    put(A, S1, 1, None, env("a1", &r1));
    let lost = put(A, S2, 2, Some(hint(100, Some(TREE))), env("a2", &r1));
    put(B, S1, 3, Some(hint(200, None)), env("b1", &r2));
    put(C, S1, 4, None, env("c1", &r2));
    put(ROOT, S1, 5, Some(hint(300, Some(TREE))), env("root", &r1));
    put(CARGO, S2, 6, None, env("cargo", &r2));
    assert_eq!(st.push(Some("origin")).unwrap().status, PushStatus::Pushed);

    let dir = fresh_clone(&w, "fresh");
    let rf = repo(&dir);
    let sf = AttestStore::new(&rf);
    assert!(sf.fetch(Some("origin")).unwrap().found);
    // A, the root and the cargo unit fetched; B and C not.
    sf.hydrate_units([A, ROOT, CARGO]).unwrap();
    lose_blob(&dir, &lost);
    let d = env("d1", &r1);
    sf.put(D, S1, &hex64(7), &d).unwrap();
    values.insert((D.to_owned(), S1.to_owned()), d);
    Rich {
        _w: w,
        repo: rf,
        values,
        lost,
    }
}

fn unit_of(e: &StoredEnvelope) -> &'static str {
    [A, B, C, D, ROOT, CARGO]
        .into_iter()
        .find(|id| key::test_key(id) == e.test_key)
        .expect("a known unit")
}

/// Plan test 1: Key-only listings are the reader's, values cleared.
#[test]
fn listings_match() {
    let r = rich();
    let gs = GitMetaStore::new(r.repo.clone());
    let reader = AttestStore::new(&r.repo).reader().unwrap();
    let ids = [A, B, C, D, ROOT, CARGO, NONE, A];
    let got = gs.list_units(&ids).unwrap();
    assert_eq!(got.len(), ids.len());
    for (id, list) in ids.iter().zip(&got) {
        let want = reader.candidates_reading(id, |_| false).unwrap();
        assert_eq!(list, &want, "{id}");
        assert!(list.windows(2).all(|p| p[0].key < p[1].key), "{id}");
        for e in list {
            assert_eq!(e.state(), ValueState::Unread, "{id}");
            assert_eq!(e.target, key::target_label(id));
            let h = key::parse_key_hint(&e.key);
            assert_eq!(e.issued, h.as_ref().map(|h| h.issued));
            assert_eq!(e.tree, h.and_then(|h| h.tree));
        }
    }
    // A: one unhinted key and one hinted; the unknown unit: nothing; the
    // duplicate answered twice.
    assert_eq!(got[0].len(), 2);
    assert_eq!(got[0].iter().filter(|e| e.issued.is_some()).count(), 1);
    assert!(got[6].is_empty());
    assert_eq!(got[0], got[7]);
    assert_eq!(got[4][0].target, "project");
    assert_eq!(got[5][0].target, "path:rust/core");

    let all = gs.list_all().unwrap();
    let mut want = reader.all().unwrap();
    for e in &mut want {
        e.bytes.clear();
        e.error = None;
    }
    assert_eq!(all, want);
    assert_eq!(all.len(), 7);
    assert!(
        all.windows(2)
            .all(|p| (&p[0].target, &p[0].key) < (&p[1].target, &p[1].key))
    );
    assert!(all.iter().all(|e| e.state() == ValueState::Unread));
    assert!(all.iter().any(|e| e.key == r.lost));
}

/// Plan test 2: Values read in place are `AttestStore::read_values`'s, entry for
/// entry.
#[test]
fn read_values_match() {
    let r = rich();
    let gs = GitMetaStore::new(r.repo.clone());
    let st = AttestStore::new(&r.repo);
    let mut ours = gs.list_all().unwrap();
    let mut theirs = ours.clone();
    // D's key goes after the listing.
    let d: Vec<StoredEnvelope> = ours.iter().filter(|e| unit_of(e) == D).cloned().collect();
    assert_eq!(st.remove_envelopes(d).unwrap().len(), 1);

    gs.read_values(&mut ours.iter_mut().collect::<Vec<_>>())
        .unwrap();
    st.read_values(theirs.iter_mut()).unwrap();
    assert_eq!(ours, theirs);
    for e in &ours {
        let unit = unit_of(e);
        match (unit, e.state()) {
            (B | C, ValueState::NotFetched) => {
                assert_eq!(e.error.as_deref(), Some(NOT_FETCHED));
            }
            (D, ValueState::Unreadable(why)) => assert_eq!(why, GONE),
            (A, ValueState::Unreadable(why)) if e.key == r.lost => {
                assert!(
                    why.starts_with("blob ")
                        && why.ends_with(" is missing from the object database"),
                    "{why}"
                );
            }
            (_, ValueState::Read(b)) => {
                assert_eq!(
                    b,
                    r.values[&(unit.to_owned(), e.signer.clone())].as_slice(),
                    "{unit}"
                );
            }
            (unit, state) => panic!("{unit}: {state:?}"),
        }
    }
    assert_eq!(
        ours.iter()
            .filter(|e| matches!(e.state(), ValueState::Read(_)))
            .count(),
        3
    );
}

/// Plan test 3: `read_units` reads each unit with one targeted query on a pooled
/// reader (never the scan of every row `read_values` makes), and answers
/// what the default (listing, then `read_values`) answers.
#[test]
fn read_units_is_targeted_and_equal() {
    let r = rich();
    let gs = GitMetaStore::new(r.repo.clone());
    let ids = [A, B, C, D, ROOT, CARGO, NONE];

    let before = reader_queries();
    let targeted = gs.read_units(&ids).unwrap();
    let targeted_queries = reader_queries() - before;

    let before = reader_queries();
    let mut default = gs.list_units(&ids).unwrap();
    {
        let mut refs: Vec<&mut StoredEnvelope> = default.iter_mut().flatten().collect();
        gs.read_values(&mut refs).unwrap();
    }
    let default_queries = reader_queries() - before;

    assert_eq!(targeted, default);
    assert_eq!(
        targeted_queries,
        ids.len() as u64,
        "one query per unit and no scan"
    );
    assert_eq!(
        default_queries,
        ids.len() as u64 + 1,
        "the listing's queries and the scan of every row"
    );
    // A reads its fetched value and its lost one; B is not fetched.
    let a = &targeted[0];
    assert!(a.iter().any(|e| e.key == r.lost && e.error.is_some()));
    assert!(
        a.iter()
            .any(|e| e.signer == S1 && e.bytes == r.values[&(A.to_owned(), S1.to_owned())])
    );
    assert!(targeted[1].iter().all(StoredEnvelope::not_fetched));
    assert!(targeted[6].is_empty());
    // One reader served it all, and went back to the pool.
    assert_eq!(gs.pooled_readers(), 1);
}

/// Plan test 4: Errors keep their fields, their text and their type.
#[test]
fn error_mapping() {
    let e = StoreError::from(GitError::Invalid {
        what: "signer_id",
        value: "XYZ".to_owned(),
        reason: "must be exactly 16 characters",
    });
    match &e {
        StoreError::Invalid {
            what,
            value,
            reason,
        } => assert_eq!(
            (*what, value.as_str(), *reason),
            ("signer_id", "XYZ", "must be exactly 16 characters")
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        e.to_string(),
        "invalid signer_id: \"XYZ\": must be exactly 16 characters"
    );

    let (_t, root) = init_repo();
    let gs = GitMetaStore::new(repo(&root));
    match gs.put_manifest("../x", b"m") {
        Err(StoreError::Invalid { what, value, .. }) => {
            assert_eq!((what, value.as_str()), ("input root", "../x"))
        }
        other => panic!("{other:?}"),
    }
    match gs.put_manifest(&hex64(1), b"\xff") {
        Err(StoreError::Invalid { what, reason, .. }) => {
            assert_eq!((what, reason), ("manifest", "must be UTF-8"))
        }
        other => panic!("{other:?}"),
    }
    match gs.put(&NewAttestation::for_test(A, "XYZ", &hex64(1), None, b"{}")) {
        Err(StoreError::Invalid { what, .. }) => assert_eq!(what, "signer_id"),
        other => panic!("{other:?}"),
    }
    assert_eq!(gs.count().unwrap(), 0);

    // NoMetaRemote comes back out of the store error.
    let err = gs.exchange().unwrap().fetch(None).unwrap_err();
    assert!(
        matches!(
            err.downcast_backend::<GitError>(),
            Some(GitError::NoMetaRemote(_))
        ),
        "{err:?}"
    );
    assert!(
        err.to_string()
            .starts_with("no git-meta remote is configured")
    );
    let direct = StoreError::from(GitError::NoMetaRemote("no remote".to_owned()));
    assert!(matches!(
        direct.downcast_backend::<GitError>(),
        Some(GitError::NoMetaRemote(m)) if m == "no remote"
    ));

    // The text is the git error's, byte for byte.
    let g = GitError::Store("/r/.git/git-meta.sqlite: disk I/O error".to_owned());
    let text = g.to_string();
    let s = StoreError::from(g);
    assert_eq!(s.to_string(), text);
    assert_eq!(s.code(), "backend");
    assert_eq!(
        StoreError::Backend(Box::new(GitError::Store("x".to_owned()))).to_string(),
        "git-meta store: x"
    );
}

/// The published store of the lazy tests: A twice, B and C once; two
/// manifests.
fn publish(w: &World) -> [String; 2] {
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
    [r1, r2]
}

/// Plan test 5: A reader opened before the store existed is not kept: after a fetch
/// creates the store, the same handle reads it.
#[test]
fn pool_sees_a_store_created_later() {
    let w = lazy_world(1);
    publish(&w);
    let f = fresh_clone(&w, "fresh");
    let gs = GitMetaStore::new(repo(&f));
    assert_eq!(
        gs.status().unwrap(),
        StoreStatus::Absent {
            advice: "run `vci fetch`".to_owned()
        }
    );
    let before = gs.list_units(&[A, B]).unwrap();
    assert!(before.iter().all(Vec::is_empty), "{before:?}");
    assert_eq!(gs.count().unwrap(), 0);
    assert_eq!(
        gs.pooled_readers(),
        0,
        "a reader without a store is dropped"
    );
    assert!(
        !f.join(".git/git-meta.sqlite").exists(),
        "reading created it"
    );

    let out = gs.exchange().unwrap().fetch(Some("origin")).unwrap();
    assert!(out.found);
    let after = gs.list_units(&[A, B]).unwrap();
    assert_eq!((after[0].len(), after[1].len()), (2, 1), "{after:?}");
    assert_eq!(gs.count().unwrap(), 4);
    assert_eq!(
        gs.status().unwrap(),
        StoreStatus::Ready {
            schema_version: None
        }
    );
    assert_eq!(gs.pooled_readers(), 1);
}

/// Plan test 6: A value read as not fetched reads as its bytes after a prefetch,
/// through the same handle and its pooled readers.
#[test]
fn pool_is_refreshed_after_prefetch() {
    let w = lazy_world(1);
    let [r1, _] = publish(&w);
    let f = fresh_clone(&w, "fresh");
    let gs = GitMetaStore::new(repo(&f));
    gs.exchange().unwrap().fetch(Some("origin")).unwrap();
    // B fetched and read first, so the pooled reader has a `git cat-file`
    // from before A's values arrive.
    let h = gs
        .prefetch(Prefetch::Units {
            test_ids: &[B],
            choose: None,
        })
        .unwrap();
    assert_eq!(h.resolved, 2, "{h:?}");
    let b = gs.read_units(&[B]).unwrap();
    assert_eq!(b[0][0].bytes, env("b1", &hex64(0xe2)));
    assert_eq!(gs.pooled_readers(), 1);

    let mut a = gs.list_units(&[A]).unwrap().remove(0);
    gs.read_values(&mut a.iter_mut().collect::<Vec<_>>())
        .unwrap();
    assert!(
        a.iter().all(|e| e.state() == ValueState::NotFetched),
        "{a:?}"
    );
    assert!(
        gs.read_units(&[A]).unwrap()[0]
            .iter()
            .all(StoredEnvelope::not_fetched)
    );
    assert!(gs.manifest(&r1).unwrap().unwrap().not_fetched());
    assert_eq!(gs.pooled_readers(), 1);

    // Choosing A's attestation by S2 fetches it and r1; then the rest.
    let h = gs
        .prefetch(Prefetch::Units {
            test_ids: &[A],
            choose: Some(&|c: &[StoredEnvelope]| {
                c.iter()
                    .enumerate()
                    .filter(|(_, e)| e.signer == S2)
                    .map(|(i, _)| i)
                    .collect()
            }),
        })
        .unwrap();
    assert_eq!((h.resolved, h.unresolved), (2, 0), "{h:?}");
    assert_eq!(gs.pooled_readers(), 0, "the pool is emptied");
    let a = gs.read_units(&[A]).unwrap().remove(0);
    assert!(
        a.iter()
            .any(|e| e.signer == S2 && e.bytes == env("a2", &r1))
    );
    assert!(a.iter().any(|e| e.signer == S1 && e.not_fetched()));
    assert_eq!(gs.manifest(&r1).unwrap().unwrap().bytes, manifest("one"));

    let h = gs
        .prefetch(Prefetch::Units {
            test_ids: &[A],
            choose: None,
        })
        .unwrap();
    assert_eq!(h.resolved, 1, "{h:?}");
    let mut a = gs.list_units(&[A]).unwrap().remove(0);
    gs.read_values(&mut a.iter_mut().collect::<Vec<_>>())
        .unwrap();
    let got: BTreeSet<Vec<u8>> = a.into_iter().map(|e| e.bytes).collect();
    let want: BTreeSet<Vec<u8>> = [env("a1", &r1), env("a2", &r1)].into_iter().collect();
    assert_eq!(got, want);
}

/// The manifest an envelope names, as the command line's supersession
/// clean-up read it before the trait (`cmds::envelope_meta`): `None` when
/// the predicate lacks its test id or times; for this file's envelopes,
/// whose times parse, the same answer.
fn cli_manifest_ref(bytes: &[u8]) -> Option<Option<String>> {
    let env: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(env["payload"].as_str()?)
        .ok()?;
    let st: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let p = &st["predicate"];
    p["testId"].as_str()?;
    p["issuedAt"].as_str()?;
    p["expiresAt"].as_str()?;
    Some(p["manifestRef"].as_str().map(str::to_owned))
}

/// vci 2.7.32's `drop_orphan_manifests`, without the removal: the roots it
/// would remove.
fn orphans_today(st: &AttestStore, roots: &[&str]) -> Vec<String> {
    let roots: BTreeSet<String> = roots.iter().map(|r| (*r).to_owned()).collect();
    if roots.is_empty() {
        return Vec::new();
    }
    let undecided = st.hydrate_manifest_referrers(&roots).unwrap();
    let mut referenced = BTreeSet::new();
    for e in st.list(None).unwrap() {
        if e.not_fetched() {
            continue;
        }
        if e.error.is_some() {
            return Vec::new();
        }
        match cli_manifest_ref(&e.bytes) {
            Some(m) => referenced.extend(m),
            None => return Vec::new(),
        }
    }
    roots
        .difference(&referenced)
        .filter(|r| !undecided.contains(*r))
        .cloned()
        .collect()
}

/// Plan test 7: `orphan_manifests` answers as the supersession clean-up did: kept
/// when referenced, removed when not, kept when an attestation not fetched
/// could reference it, nothing removed when a referrer cannot be parsed.
#[test]
fn orphan_manifests_matches_today() {
    // A store whose values are all here.
    let w = lazy_world(1);
    let a = repo(&w.clones[0]);
    let st = AttestStore::new(&a);
    let gs = GitMetaStore::new(a.clone());
    let (ra, ma) = real_manifest(&[A, D]);
    let (rb, mb) = real_manifest(&[B]);
    let (rc, mc) = real_manifest(&[C]);
    for (r, m) in [(&ra, &ma), (&rb, &mb), (&rc, &mc)] {
        st.put_manifest(r, m).unwrap();
    }
    st.put(A, S1, &hex64(1), &full_env(A, &ra)).unwrap();
    st.put(D, S1, &hex64(2), &full_env(D, &ra)).unwrap();
    let b = st.put(B, S1, &hex64(3), &full_env(B, &rb)).unwrap();
    let roots = [ra.as_str(), rb.as_str(), rc.as_str()];
    let check = |want: &[&String]| {
        let today = orphans_today(&st, &roots);
        assert_eq!(gs.orphan_manifests(&roots).unwrap(), today);
        assert_eq!(today.iter().collect::<Vec<_>>(), want);
    };
    // Referenced kept, unreferenced removed.
    check(&[&rc]);
    // B's attestation superseded: its manifest goes too.
    gs.remove(vec![b]).unwrap();
    let mut both = vec![&rb, &rc];
    both.sort();
    check(&both);
    assert!(gs.orphan_manifests(&[]).unwrap().is_empty());
    // Publish before an unparseable referrer joins.
    assert_eq!(st.push(Some("origin")).unwrap().status, PushStatus::Pushed);
    let e = st.put(E, S1, &hex64(4), b"not json").unwrap();
    check(&[]);
    gs.remove(vec![e]).unwrap();
    check(&both);

    // Clones that fetched A's attestation (then superseded it here) and the
    // manifests: D's attestation, which could reference ra (ra lists D's
    // path), is not fetched.
    let lazy = |name: &str, online: bool| {
        let f = fresh_clone(&w, name);
        let rf = repo(&f);
        let sf = AttestStore::new(&rf);
        sf.fetch(Some("origin")).unwrap();
        sf.hydrate_units([A]).unwrap();
        sf.hydrate_manifests([ra.as_str(), rb.as_str()]).unwrap();
        for e in sf.list(Some(A)).unwrap() {
            assert!(sf.remove(&e).unwrap());
        }
        assert!(sf.list(Some(D)).unwrap()[0].not_fetched());
        if !online {
            git(
                &f,
                &["config", "remote.meta.url", "/nonexistent/remote.git"],
            );
        }
        rf
    };
    let roots = [ra.as_str(), rb.as_str()];
    for online in [true, false] {
        let x = lazy(&format!("today-{online}"), online);
        let y = lazy(&format!("trait-{online}"), online);
        let today = orphans_today(&AttestStore::new(&x), &roots);
        let ours = GitMetaStore::new(y.clone())
            .orphan_manifests(&roots)
            .unwrap();
        assert_eq!(ours, today, "online: {online}");
        // Online, D's attestation is fetched and references ra; offline, ra
        // cannot be decided. Either way only rb goes.
        assert_eq!(ours, vec![rb.clone()], "online: {online}");
        let d = AttestStore::new(&y).list(Some(D)).unwrap().remove(0);
        assert_eq!(d.not_fetched(), !online, "{d:?}");
    }
}

/// Plan test 8 (2.8): git-meta's batch is one transaction: its writes are
/// visible to other readers, and durable, once it finishes, and it ends in
/// the state its calls reach one by one (the same inputs written twice keep
/// one key, a put then removed is gone).
#[test]
fn batch_is_one_transaction() {
    let (_t, root) = init_repo();
    let r = repo(&root);
    let gs = GitMetaStore::new(r.clone());
    let before = gs
        .put_for_test(C, S1, &hex64(3), None, &env("c", &hex64(0xe0)))
        .unwrap();
    let batch = gs.batch().unwrap();
    assert!(batch.defers_writes());
    let m = hex64(0xe1);
    assert!(gs.put_manifest(&m, &manifest("one")).unwrap());
    assert!(
        !gs.put_manifest(&m, &manifest("one")).unwrap(),
        "the batch's own write"
    );
    let put = gs
        .put(&NewAttestation::for_test(
            A,
            S1,
            &hex64(1),
            Some(&hint(1, None)),
            &env("a", &m),
        ))
        .unwrap();
    // The same inputs again under a newer hint: replaces the batch's own.
    let newer = gs
        .put(&NewAttestation::for_test(
            A,
            S1,
            &hex64(1),
            Some(&hint(2, None)),
            &env("a2", &m),
        ))
        .unwrap();
    assert_ne!(newer.key, put.key);
    let b = gs
        .put_for_test(B, S1, &hex64(2), None, &env("b", &m))
        .unwrap();
    assert_eq!(gs.remove(vec![b.clone()]).unwrap(), vec![b]);
    assert_eq!(gs.remove(vec![before.clone()]).unwrap(), vec![before]);
    // Another reader sees none of it yet.
    assert!(AttestStore::new(&r).list(Some(A)).unwrap().is_empty());
    assert_eq!(AttestStore::new(&r).list(Some(C)).unwrap().len(), 1);
    batch.finish().unwrap();
    let a = AttestStore::new(&r).list(Some(A)).unwrap();
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0].key, newer.key);
    assert_eq!(a[0].bytes, env("a2", &m));
    assert!(gs.list_units(&[B]).unwrap()[0].is_empty());
    assert!(gs.list_units(&[C]).unwrap()[0].is_empty());
    assert_eq!(gs.manifest(&m).unwrap().unwrap().bytes, manifest("one"));
    assert_eq!(gs.count().unwrap(), 1);
    // A second batch on the same thread works as the first, and one inside
    // it joins it.
    let again = gs.batch().unwrap();
    let inner = gs.batch().unwrap();
    gs.put_for_test(C, S1, &hex64(3), None, &env("c", &m))
        .unwrap();
    inner.finish().unwrap();
    assert_eq!(
        AttestStore::new(&r).count().unwrap(),
        1,
        "the outer batch is open"
    );
    again.finish().unwrap();
    assert_eq!(gs.count().unwrap(), 2);
}

/// What a batch stores is what the same calls store one by one: the same
/// rows, the same log operations and deletion records, so `vci push`
/// publishes the same.
#[test]
fn a_batch_stores_what_the_calls_store_one_by_one() {
    let rows = |batched: bool| {
        let (t, root) = init_repo();
        let r = repo(&root);
        let gs = GitMetaStore::new(r.clone());
        let m = hex64(0xe1);
        let old = gs
            .put_for_test(B, S1, &hex64(9), Some(&hint(1, None)), &env("old", &m))
            .unwrap();
        let batch = batched.then(|| gs.batch().unwrap());
        gs.put_manifest(&m, &manifest("one")).unwrap();
        gs.put_manifest(&m, &manifest("one")).unwrap();
        gs.put_for_test(A, S1, &hex64(1), Some(&hint(1, None)), &env("a", &m))
            .unwrap();
        gs.put_for_test(B, S1, &hex64(9), Some(&hint(2, None)), &env("new", &m))
            .unwrap();
        gs.remove(vec![old]).unwrap();
        gs.put_for_test(C, S1, &hex64(3), None, &env("c", &m))
            .unwrap();
        gs.remove_manifests(&[m.as_str()]).unwrap();
        if let Some(b) = batch {
            b.finish().unwrap();
        }
        let db = rusqlite::Connection::open(root.join(".git/git-meta.sqlite")).unwrap();
        let q = |sql: &str| -> Vec<String> {
            let mut st = db.prepare(sql).unwrap();
            st.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let out = (
            q(
                "SELECT target_type || ' ' || target_value || ' ' || key || ' ' || value || ' ' || value_type || ' ' || is_git_ref FROM metadata ORDER BY 1",
            ),
            q(
                "SELECT target_type || ' ' || target_value || ' ' || key || ' ' || operation || ' ' || value FROM metadata_log ORDER BY rowid",
            ),
            q(
                "SELECT tombstone_type || ' ' || target_type || ' ' || target_value || ' ' || key FROM tombstones ORDER BY 1",
            ),
        );
        drop(t);
        out
    };
    assert_eq!(rows(true), rows(false));
}

/// A batch whose commit went through stored its writes, even when
/// stamping their log entries afterwards fails: `finish` is `Ok` with a
/// warning (it used to fail, and vci run refused every unit it had
/// stored).
#[test]
fn a_stamp_that_fails_after_the_commit_is_a_warning() {
    let (_t, root) = init_repo();
    let gs = GitMetaStore::new(repo(&root));
    gs.put_for_test(C, S1, &hex64(3), None, &env("c", &hex64(0xe0)))
        .unwrap();
    let db = rusqlite::Connection::open(root.join(".git/git-meta.sqlite")).unwrap();
    db.execute_batch(
        "CREATE TRIGGER no_stamp BEFORE UPDATE OF timestamp ON metadata_log
         BEGIN SELECT RAISE(ABORT, 'stamp refused by test trigger'); END;",
    )
    .unwrap();
    let batch = gs.batch().unwrap();
    let m = hex64(0xe1);
    gs.put_manifest(&m, &manifest("one")).unwrap();
    let a = gs
        .put_for_test(A, S1, &hex64(1), None, &env("a", &m))
        .unwrap();
    // A later millisecond than the writes', so the stamp is an update.
    std::thread::sleep(std::time::Duration::from_millis(5));
    let warnings = batch.finish().unwrap();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].starts_with("stamping the 2 write(s) of the batch after its commit: ")
            && warnings[0].contains("stamp refused by test trigger"),
        "{warnings:?}"
    );
    let r = repo(&root);
    assert_eq!(AttestStore::new(&r).list(Some(A)).unwrap()[0].key, a.key);
    assert!(gs.manifest(&m).unwrap().is_some());
}

/// A batch's write that SQLite refuses fails with the text git-meta gives
/// the same write one by one (`git-meta: <SQLite's message>`, as vci 2.7
/// printed it), not a path-prefixed store error.
#[test]
fn a_refused_write_reads_the_same_in_a_batch() {
    let refused = |batched: bool| {
        let (_t, root) = init_repo();
        let gs = GitMetaStore::new(repo(&root));
        gs.put_for_test(C, S1, &hex64(3), None, &env("c", &hex64(0xe0)))
            .unwrap();
        let db = rusqlite::Connection::open(root.join(".git/git-meta.sqlite")).unwrap();
        db.execute_batch(
            "CREATE TRIGGER no_insert BEFORE INSERT ON metadata
             BEGIN SELECT RAISE(ABORT, 'refused by test trigger'); END;",
        )
        .unwrap();
        let batch = batched.then(|| gs.batch().unwrap());
        let e = gs
            .put_manifest(&hex64(0xe1), &manifest("one"))
            .unwrap_err()
            .to_string();
        if let Some(b) = batch {
            b.finish().unwrap();
        }
        e
    };
    assert_eq!(refused(false), "git-meta: refused by test trigger");
    assert_eq!(refused(true), refused(false));
}

/// Plan test 9: The timing report is the line vci has always printed.
#[test]
fn timing_report_line() {
    let (_t, root) = init_repo();
    let gs = GitMetaStore::new(repo(&root));
    gs.put_manifest(&hex64(1), b"m").unwrap();
    let lines = gs.timing_report();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let l = &lines[0];
    assert!(l.starts_with("put_manifest seconds: session "), "{l}");
    let numbers: Vec<&str> = l
        .strip_prefix("put_manifest seconds: ")
        .unwrap()
        .split(", ")
        .collect();
    assert_eq!(numbers.len(), 4, "{l}");
    for (part, name) in numbers
        .iter()
        .zip(["session", "read current", "set", "stamp"])
    {
        let n = part.strip_prefix(name).unwrap().trim();
        assert!(n.parse::<f64>().is_ok() && n.contains('.'), "{l}");
    }
}

/// Plan test 10: `put` stores under the keys `put_hinted` stores under, and replaces
/// the same inputs' keys as it does.
#[test]
fn put_keeps_semantics() {
    let (_tx, x) = init_repo();
    let (_ty, y) = init_repo();
    let (rx, ry) = (repo(&x), repo(&y));
    let old = AttestStore::new(&rx);
    let gs = GitMetaStore::new(ry.clone());
    let tree40 = "0123456789abcdef0123456789abcdef01234567";
    // (test id, signer, storage key seed, hint, envelope)
    type Step<'a> = (&'a str, &'a str, u8, Option<KeyHint>, &'a [u8]);
    let steps: Vec<Step> = vec![
        (A, S1, 1, Some(hint(100, None)), b"a old"),
        // A newer hint replaces the key of the same inputs.
        (A, S1, 1, Some(hint(200, Some(TREE))), b"a new"),
        // No hint: the existing key is kept.
        (A, S1, 1, None, b"a unhinted"),
        // The same bytes again: nothing changes.
        (A, S1, 1, None, b"a unhinted"),
        // Another signer, other inputs: slots of their own.
        (A, S2, 1, None, b"a by s2"),
        (A, S1, 2, None, b"a other inputs"),
        // A plain key replaced by a hinted one.
        (A, S1, 2, Some(hint(300, None)), b"a other inputs, hinted"),
        // The project target, a 40-digit tree, and a cargo unit.
        (
            ROOT,
            S1,
            3,
            Some(hint(5, Some(tree40))),
            b"root\twith\ttabs\n",
        ),
        (CARGO, S2, 4, None, b"cargo"),
    ];
    for (id, signer, sk, h, bytes) in steps {
        let sk = hex64(sk);
        let a = old.put_hinted(id, signer, &sk, h.as_ref(), bytes).unwrap();
        let b = gs
            .put(&NewAttestation::for_test(
                id,
                signer,
                &sk,
                h.as_ref(),
                bytes,
            ))
            .unwrap();
        assert_eq!(
            (&a.key, &a.target, &a.test_key, &a.signer, &a.storage_key),
            (&b.key, &b.target, &b.test_key, &b.signer, &b.storage_key),
            "{id} {signer}"
        );
        assert_eq!(a.bytes, b.bytes);
        assert_eq!(b.state(), ValueState::Read(bytes));
        // The trait's entry takes `issued` and `tree` from the key it was
        // stored under (`put_hinted`'s from the hint it was given, so none
        // for a key kept without one, and the tree uncut).
        let from_key = key::parse_key_hint(&b.key);
        assert_eq!(b.issued, from_key.as_ref().map(|h| h.issued));
        assert_eq!(b.tree, from_key.and_then(|h| h.tree));
        if h.is_some() {
            assert_eq!(a.issued, b.issued);
        }
        let listed = |r: &Repo| -> Vec<(String, String, Vec<u8>)> {
            AttestStore::new(r)
                .list(None)
                .unwrap()
                .into_iter()
                .map(|e| (e.target, e.key, e.bytes))
                .collect()
        };
        assert_eq!(listed(&rx), listed(&ry), "after {id} {signer}");
    }
    let keys: Vec<String> = gs.read_all().unwrap().into_iter().map(|e| e.key).collect();
    assert_eq!(keys.len(), 5, "{keys:?}");
    assert!(keys.iter().any(|k| k.ends_with(":c8.0123456789abcdef")));
    assert!(keys.iter().any(|k| k.ends_with(":5.0123456789abcdef")));
    assert!(!keys.iter().any(|k| k.ends_with(":64.-")));
}

/// git-meta's put is not one atomic step (the put contract says so):
/// concurrent puts of one slot may leave several records, and the slot's
/// next put collapses them to one.
#[test]
fn racing_puts_of_one_slot_collapse_on_the_next_put() {
    let (_t, x) = init_repo();
    let gs = GitMetaStore::new(repo(&x));
    let sk = hex64(9);
    let threads = 6;
    let barrier = std::sync::Barrier::new(threads);
    std::thread::scope(|sc| {
        for i in 0..threads {
            let (gs, sk, barrier) = (&gs, &sk, &barrier);
            sc.spawn(move || {
                barrier.wait();
                let h = hint(100 + i as i64, None);
                // A racing put may also fail ("database is locked").
                let _ = gs.put_for_test(A, S1, sk, Some(&h), format!("w{i}").as_bytes());
            });
        }
    });
    let raced = gs.list_units(&[A]).unwrap().remove(0).len();
    assert!((1..=threads).contains(&raced), "{raced}");
    let last = gs
        .put_for_test(A, S1, &sk, Some(&hint(1000, None)), b"last")
        .unwrap();
    let mut l = gs.list_units(&[A]).unwrap().remove(0);
    assert_eq!(
        l.len(),
        1,
        "{:?}",
        l.iter().map(|e| &e.key).collect::<Vec<_>>()
    );
    assert_eq!(l[0].key, last.key);
    gs.read_values(&mut l.iter_mut().collect::<Vec<_>>())
        .unwrap();
    assert_eq!(l[0].bytes, b"last");
}

/// The factory opens git-meta for its repository, whatever the selection
/// says beyond the name.
#[test]
fn the_factory_opens_this_repository() {
    let (_t, root) = init_repo();
    let r = repo(&root);
    let f = GitMetaFactory::new(r.clone());
    assert_eq!(f.kind(), "git-meta");
    let cx = OpenContext {
        repo_root: root.clone().into(),
        git_dir: root.join(".git").into(),
        git_common_dir: root.join(".git").into(),
        repo_id: std::sync::Arc::new(|| Err("unused".to_owned())),
        jobs: 2,
        command: "plan".to_owned(),
        long_running: false,
    };
    let s = vci_store::open(&[&f], &Selection::for_backend("git-meta"), &cx).unwrap();
    assert_eq!(s.kind(), "git-meta");
    assert_eq!(
        s.location(),
        ".git/git-meta.sqlite (exchanged on refs/meta/main)"
    );
    let caps = s.caps();
    assert!(caps.lazy_values && caps.keeps_hints && !caps.shared_writes);
    let ex = s.exchange().unwrap();
    assert_eq!(ex.exchange_point(), "refs/meta/main");
    assert_eq!(ex.remote_location("origin"), None);
    git(
        &root,
        &[
            "remote",
            "add",
            "origin",
            "https://x-access-token:ghs_secret@github.com/o/r.git",
        ],
    );
    assert_eq!(
        ex.remote_location("origin").as_deref(),
        Some("https://***@github.com/o/r.git")
    );
    // Writes through it are the repository's; hints are kept.
    s.put_for_test(A, S1, &hex64(1), None, b"{}").unwrap();
    assert_eq!(AttestStore::new(&r).count().unwrap(), 1);
    s.set_flag("plan:natives:x");
    assert!(s.flag("plan:natives:x"));
    s.remember_passing(TREE, &[(key::test_key(A), "k".to_owned())]);
    assert_eq!(
        s.passing_on(TREE)
            .get(&key::test_key(A))
            .map(String::as_str),
        Some("k")
    );
}
