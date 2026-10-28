//! Format-3 objects and records on git-meta (STORE-V2 section 2.2): what the
//! conformance suite cannot see from the trait alone. Objects are base64
//! string values under `project` at `vci/object/<kind>/<id>/__value`; a
//! record is the text frame, read through the same lossy-UTF-8 path a vci
//! before 2.9 reads it, where it is not an envelope and only makes the unit
//! run; objects are lazy and one prefetch fetches their blobs; a merge puts
//! back an object a local record names that another clone deleted; the
//! orphan scan keeps every object while a record cannot be fetched; and an
//! idempotent put inside a batch restarts the grace period.

mod common;

use std::time::Duration;

use base64::Engine as _;
use camino::{Utf8Path, Utf8PathBuf};
use common::*;
use git_meta_lib::{MetaValue, Session, Target};
use vci_core::ObjectKind;
use vci_git::{AttestStore, GitMetaStore, Repo};
use vci_store::conformance::scenarios::Run3;
use vci_store::{
    AttestationStore, Columns, ManifestRef, NewAttestation, OBJECT_GRACE, Prefetch, PushMode,
    Record, decode_record, key,
};

const S1: &str = "0123456789abcdef";
const A: &str = "src/a.test.ts";

/// A world whose remote serves partial clones (as GitHub does).
fn lazy_world(n: usize) -> World {
    let w = world(n);
    git(&w.remote, &["config", "uploadpack.allowFilter", "true"]);
    w
}

fn repo(root: &Utf8Path) -> Repo {
    Repo::discover(root).unwrap()
}

/// A fresh clone of the world's remote: code only, no metadata and no store.
fn fresh_clone(w: &World, name: &str) -> Utf8PathBuf {
    let base = w.remote.parent().unwrap();
    let dir = base.join(name);
    git(
        base,
        &["clone", "-q", "--no-local", w.remote.as_str(), dir.as_str()],
    );
    dir
}

/// The store of `dir`, with a metadata remote for `origin`.
fn store(dir: &Utf8Path) -> GitMetaStore {
    let r = repo(dir);
    AttestStore::new(&r).ensure_remote(Some("origin")).unwrap();
    GitMetaStore::new(r)
}

fn push(s: &GitMetaStore) {
    s.exchange().unwrap().push(None, PushMode::Merge).unwrap();
}

fn fetch(s: &GitMetaStore) -> vci_store::FetchOutcome {
    s.exchange().unwrap().fetch(None).unwrap()
}

/// Move the objects `ids` of the store in `dir` back in time by `by` (every
/// kind), as the conformance world does.
fn age(dir: &Utf8Path, ids: &[&str], by: Duration) {
    let db = rusqlite::Connection::open(dir.join(".git/git-meta.sqlite")).unwrap();
    let by = i64::try_from(by.as_millis()).unwrap();
    for id in ids {
        for kind in [
            ObjectKind::Hdr,
            ObjectKind::Tables,
            ObjectKind::Shape,
            ObjectKind::State,
        ] {
            db.execute(
                "UPDATE metadata SET last_timestamp = last_timestamp - ?1
                 WHERE target_type = 'project' AND key = ?2",
                rusqlite::params![by, key::object_key(kind, id)],
            )
            .unwrap();
        }
    }
}

/// The objects `s` holds among `ids`, prefetched first.
fn objects(s: &GitMetaStore, ids: &[&str]) -> Vec<String> {
    s.prefetch(Prefetch::Objects { ids }).unwrap();
    s.get_objects(ids)
        .unwrap()
        .into_iter()
        .map(|o| o.id)
        .collect()
}

/// Put a run's objects and one record of it (signer S1, storage key `sk`).
fn put_run(s: &GitMetaStore, run: &Run3, sk: &str) -> (Vec<u8>, Columns) {
    s.put_objects(&run.new_objects()).unwrap();
    let (rec, cols) = run.record(A, 1, 7);
    s.put(&NewAttestation::for_test(A, S1, sk, None, &rec).with_columns(&cols))
        .unwrap();
    (rec, cols)
}

/// The three named ids of a run, sorted (the state object is in no field).
fn named(run: &Run3) -> Vec<String> {
    run.named()
}

#[test]
fn objects_are_base64_values_at_vci_object_paths_that_an_older_vci_never_lists() {
    let w = lazy_world(1);
    let s = store(&w.clones[0]);
    let run = Run3::build(&["src/one.ts", "src/two.ts"]);
    assert_eq!(s.put_objects(&run.new_objects()).unwrap(), 4);

    // As stored: a string value, the base64 of the bytes, under the key
    // vci:object:<kind>:<id> of the project target.
    let session = Session::open(w.clones[0].as_std_path()).unwrap();
    let project = session.target(&Target::project());
    for (kind, bytes) in &run.objects {
        let id = vci_core::objects::hex32(&vci_core::object_id(bytes));
        let k = key::object_key(*kind, &id);
        assert_eq!(k, format!("vci:object:{}:{id}", *kind as u8));
        let text = base64::engine::general_purpose::STANDARD.encode(bytes);
        assert_eq!(
            project.get_value(&k).unwrap(),
            Some(MetaValue::String(text.clone())),
            "{kind}"
        );
        let path = git_meta_lib::tree_paths::tree_path(&Target::project(), &k).unwrap();
        assert_eq!(
            path,
            format!("project/vci/object/{}/{id}/__value", *kind as u8)
        );
    }

    // What a vci before 2.9 lists: no attestation, no manifest (its key
    // prefixes are others), while the objects are there for this one.
    let st = s.attest_store();
    assert!(st.list(None).unwrap().is_empty());
    assert_eq!(st.count().unwrap(), 0);
    assert!(st.manifests().unwrap().is_empty());
    assert_eq!(s.list_all().unwrap().len(), 0);
    assert_eq!(objects(&s, &run.id_refs()), run.id_refs());
    let rows = st.reader().unwrap().object_rows().unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| (r.kind, r.id.as_str(), r.fetched))
            .collect::<Vec<_>>(),
        run.objects
            .iter()
            .zip(run.id_refs())
            .map(|((k, _), id)| (*k, id, true))
            .collect::<Vec<_>>()
    );

    // Pushed, the remote's tree holds each at its path, as its base64.
    push(&s);
    for (kind, bytes) in &run.objects {
        let id = vci_core::objects::hex32(&vci_core::object_id(bytes));
        let blob = git(
            &w.remote,
            &[
                "rev-parse",
                &format!(
                    "refs/meta/main:project/vci/object/{}/{id}/__value",
                    *kind as u8
                ),
            ],
        );
        let text = git(&w.remote, &["cat-file", "-p", &blob]);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(text.trim_end())
                .unwrap(),
            *bytes,
            "{kind}"
        );
    }
}

#[test]
fn a_frame_reads_as_text_that_an_older_vci_rejects_without_an_error() {
    let w = lazy_world(1);
    let s = store(&w.clones[0]);
    let run = Run3::build(&["src/a.test.ts"]);
    let (rec, cols) = put_run(&s, &run, &hex64(3));
    let got = s.read_units(&[A]).unwrap().remove(0);
    assert_eq!(got.len(), 1);
    let e = &got[0];
    assert_eq!(e.bytes, rec, "the frame, byte for byte");
    assert!(e.error.is_none());
    assert_eq!(
        s.columns(&[e]).unwrap(),
        vec![Columns::default()],
        "git-meta keeps no columns; the ones put are {cols:?}"
    );

    // The text a vci before 2.9 reads (git-meta's values are lossy UTF-8
    // strings): the same bytes, since a frame is UTF-8 without NUL. Its
    // envelope parser (`Envelope::from_json`, a serde_json parse of the
    // value) then refuses it as not an envelope (no panic, an `Err`): the
    // `envelope` check fails and the unit runs. Its manifest collector
    // cannot tell what it names, so it keeps every manifest.
    let text = String::from_utf8_lossy(&e.bytes).into_owned();
    assert_eq!(text.as_bytes(), rec.as_slice());
    assert!(text.starts_with("vci3\n"));
    assert!(serde_json::from_slice::<serde_json::Value>(&e.bytes).is_err());
    // This vci tells it apart by its first byte.
    assert!(matches!(
        decode_record(&e.bytes),
        Ok(Record::FormatThree(_))
    ));
    assert_eq!(e.manifest_ref(), ManifestRef::Inline);

    // Fetched into another clone through blobs, the same bytes.
    push(&s);
    let f = fresh_clone(&w, "fresh");
    let sf = store(&f);
    assert!(fetch(&sf).found);
    sf.prefetch(Prefetch::Units {
        test_ids: &[A],
        choose: None,
    })
    .unwrap();
    let got = sf.read_units(&[A]).unwrap().remove(0);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].bytes, rec);
    assert_eq!(got[0].error, None);
}

#[test]
fn objects_are_lazy_and_one_prefetch_fetches_their_blobs() {
    let w = lazy_world(1);
    let s = store(&w.clones[0]);
    let run = Run3::build(&["src/a.test.ts", "src/b.ts"]);
    put_run(&s, &run, &hex64(3));
    push(&s);

    let f = fresh_clone(&w, "fresh");
    let sf = store(&f);
    assert!(
        sf.get_objects(&run.id_refs()).unwrap().is_empty(),
        "no store"
    );
    assert!(fetch(&sf).found);
    let rows = sf.attest_store().reader().unwrap().object_rows().unwrap();
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|r| !r.fetched), "promised rows: {rows:?}");
    assert!(
        sf.get_objects(&run.id_refs()).unwrap().is_empty(),
        "not fetched: left out, no error"
    );
    assert!(sf.orphan_objects().unwrap().is_empty());

    let h = sf
        .prefetch(Prefetch::Objects {
            ids: &run.id_refs(),
        })
        .unwrap();
    assert_eq!((h.resolved, h.unresolved, h.fetched), (4, 0, 4), "{h:?}");
    let got = sf.get_objects(&run.id_refs()).unwrap();
    assert_eq!(got.len(), 4);
    for (o, (kind, bytes)) in got.iter().zip(&run.objects) {
        assert_eq!((o.kind, &o.bytes), (*kind, bytes));
    }
    let again = sf
        .prefetch(Prefetch::Objects {
            ids: &run.id_refs(),
        })
        .unwrap();
    assert_eq!((again.resolved, again.fetched), (0, 0), "{again:?}");
    let unknown = hex64(0xee);
    let h = sf.prefetch(Prefetch::Objects { ids: &[&unknown] }).unwrap();
    assert_eq!(h, vci_store::Hydration::default(), "an id the store lacks");
}

#[test]
fn a_merge_puts_back_an_object_a_local_record_names() {
    let w = lazy_world(1);
    let a = store(&w.clones[0]);
    let run = Run3::build(&["src/a.test.ts"]);
    put_run(&a, &run, &hex64(3));
    push(&a);

    // Another clone deletes the four objects (as a prune that knows no
    // record naming them would) and publishes the deletions.
    let b_dir = fresh_clone(&w, "b");
    let b = store(&b_dir);
    assert!(fetch(&b).found);
    {
        let session = Session::open(b_dir.as_std_path()).unwrap();
        let project = session.target(&Target::project());
        for (kind, id) in run.objects.iter().map(|(k, _)| *k).zip(run.id_refs()) {
            assert!(project.remove(&key::object_key(kind, id)).unwrap());
        }
    }
    // A third clone fetched the run before the deletions, values not
    // fetched: it merges them too, and puts nothing back, since a record it
    // never read is not one its plans relied on.
    let c_dir = fresh_clone(&w, "c");
    let c = store(&c_dir);
    assert!(fetch(&c).found);
    assert_eq!(
        c.attest_store()
            .reader()
            .unwrap()
            .object_rows()
            .unwrap()
            .len(),
        4
    );
    push(&b);
    let out = fetch(&c);
    assert!(out.notes.iter().all(|n| !n.contains("put back")), "{out:?}");
    assert!(
        c.attest_store()
            .reader()
            .unwrap()
            .object_rows()
            .unwrap()
            .is_empty()
    );
    assert!(objects(&c, &run.id_refs()).is_empty());

    // The first clone's merge applies the deletions, then puts back the
    // objects its record names, from its own commit before the merge; the
    // state object is in no field and stays deleted.
    let out = fetch(&a);
    assert!(
        out.notes
            .iter()
            .any(|n| n.starts_with("put back 3 object(s)")),
        "{out:?}"
    );
    let mut back = objects(&a, &run.id_refs());
    back.sort();
    assert_eq!(back, named(&run));
    assert!(a.get_objects(&[&run.ids.state]).unwrap().is_empty());
    let got = a.read_units(&[A]).unwrap().remove(0);
    assert_eq!(got.len(), 1, "the record is untouched");

    // Published, the other clone has them again.
    push(&a);
    assert!(fetch(&b).found);
    let mut again = objects(&b, &run.id_refs());
    again.sort();
    assert_eq!(again, named(&run));

    // A second fetch with nothing new puts nothing back.
    let out = fetch(&a);
    assert!(out.notes.iter().all(|n| !n.contains("put back")), "{out:?}");
}

#[test]
fn the_orphan_scan_keeps_every_object_while_a_record_cannot_be_fetched() {
    let w = lazy_world(1);
    let a = store(&w.clones[0]);
    let run = Run3::build(&["src/a.test.ts"]);
    put_run(&a, &run, &hex64(3));
    push(&a);

    let b_dir = fresh_clone(&w, "b");
    let b = store(&b_dir);
    assert!(fetch(&b).found);
    age(&b_dir, &run.id_refs(), OBJECT_GRACE * 2);
    // Offline: the record cannot be fetched, so it might name anything.
    git(
        &b_dir,
        &["config", "remote.meta.url", "/nonexistent/remote.git"],
    );
    assert!(b.orphan_objects().unwrap().is_empty());
    assert_eq!(b.remove_objects(&run.id_refs()).unwrap(), 0);
    assert_eq!(
        b.attest_store()
            .reader()
            .unwrap()
            .object_rows()
            .unwrap()
            .len(),
        4
    );
    // Online, the scan fetches the record first: it names three of them.
    git(&b_dir, &["config", "remote.meta.url", w.remote.as_str()]);
    assert!(b.orphan_objects().unwrap().is_empty());
    assert_eq!(b.remove_objects(&run.id_refs()).unwrap(), 0);
    let rec = b.read_units(&[A]).unwrap().remove(0);
    assert_eq!(rec.len(), 1);
    assert!(rec[0].error.is_none(), "fetched by the scan: {rec:?}");

    // Without the record, the three named objects are orphans; the state
    // object has no referrer a store without columns can see.
    b.remove(rec).unwrap();
    assert_eq!(b.orphan_objects().unwrap(), named(&run));
    assert_eq!(b.remove_objects(&run.id_refs()).unwrap(), 3);
    assert_eq!(objects(&b, &run.id_refs()), vec![run.ids.state.clone()]);
    assert_eq!(b.prune_state_objects(OBJECT_GRACE).unwrap(), 1);
    assert!(objects(&b, &run.id_refs()).is_empty());
    assert_eq!(b.prune_state_objects(Duration::ZERO).unwrap(), 0);
}

#[test]
fn an_idempotent_put_in_a_batch_restarts_the_grace_period() {
    let w = lazy_world(1);
    let dir = &w.clones[0];
    let s = store(dir);
    let run = Run3::build(&["src/a.test.ts"]);
    let batch = s.batch().unwrap();
    assert_eq!(s.put_objects(&run.new_objects()).unwrap(), 4);
    assert_eq!(
        s.put_objects(&run.new_objects()).unwrap(),
        0,
        "in the batch"
    );
    batch.finish().unwrap();
    assert_eq!(objects(&s, &run.id_refs()).len(), 4);

    age(dir, &run.id_refs(), OBJECT_GRACE * 2);
    assert_eq!(s.orphan_objects().unwrap(), named(&run));
    let batch = s.batch().unwrap();
    assert_eq!(s.put_objects(&run.new_objects()).unwrap(), 0);
    batch.finish().unwrap();
    assert!(
        s.orphan_objects().unwrap().is_empty(),
        "the batch's re-put moved every put time to now"
    );
    assert_eq!(s.remove_objects(&run.id_refs()).unwrap(), 0);

    age(dir, &run.id_refs(), OBJECT_GRACE * 2);
    assert_eq!(s.remove_objects(&run.id_refs()).unwrap(), 3);
    assert_eq!(objects(&s, &run.id_refs()), vec![run.ids.state.clone()]);
}
