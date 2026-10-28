//! The libSQL store's format-3 side (STORE-V2 section 2.1, section 18 of
//! `docs/STORE-BACKENDS.md`): what the conformance suite cannot see
//! through the trait. The schema upgrade as a request of its own, `seq`
//! one per transaction and rising, objects as base64 text, a batch's
//! statements (objects, then records, then removals with their `gone`
//! rows), the old log left alone by format-3 puts, the replica's sync by
//! `seq` and its forced full resync past the purge horizon, transactions
//! sized by bytes alone for format-3 records, and the memo as it was.
//! Every test needs a server ([`testkit`]) and is skipped without one; the
//! measurement over the real sample runs only with `VCI_PAIRS`.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use base64::Engine as _;
use vci_core::ObjectKind;
use vci_store::conformance::scenarios::Run3;
use vci_store::{
    AttestationStore, Columns, KeyHint, NewAttestation, NewObject, OBJECT_GRACE, Prefetch,
    StoreError, StoreStatus, StoredEnvelope, ValueState, key, object_to_base64,
};
use vci_store_libsql::{Finish, LibsqlStore, table_prefix, testkit};

const S1: &str = "1111111111111111";
const UNIT: &str = "src/f3.test.ts";

fn hex64(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

fn hint(issued: i64) -> KeyHint {
    KeyHint {
        issued,
        tree: Some("0123456789abcdef".to_owned()),
    }
}

/// A DSSE-shaped format-1 envelope.
fn envelope(pad: &str) -> Vec<u8> {
    let payload = serde_json::json!({"predicate": {"manifestRef": null}, "pad": pad});
    serde_json::json!({
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64::engine::general_purpose::STANDARD.encode(payload.to_string()),
        "signatures": [],
    })
    .to_string()
    .into_bytes()
}

/// A remote store on the test server in a namespace of its own, or `None`
/// (skipped) without a server.
fn remote() -> Option<(LibsqlStore, String)> {
    if !testkit::available() {
        return None;
    }
    let ns = testkit::namespace();
    Some((testkit::open_remote(&ns)?, ns))
}

fn put3(
    s: &LibsqlStore,
    unit: &str,
    storage_key: &str,
    hint: Option<&KeyHint>,
    record: &[u8],
    columns: &Columns,
) -> StoredEnvelope {
    s.put(&NewAttestation::for_test(unit, S1, storage_key, hint, record).with_columns(columns))
        .expect("put a format-3 record")
}

fn rows(s: &LibsqlStore, sql: &str) -> Vec<Vec<String>> {
    s.__query_for_test(sql).expect("query")
}

fn one(s: &LibsqlStore, sql: &str) -> String {
    rows(s, sql)
        .into_iter()
        .next()
        .and_then(|r| r.into_iter().next())
        .unwrap_or_default()
}

fn count(s: &LibsqlStore, sql: &str) -> i64 {
    one(s, sql).parse().expect("a count")
}

/// The names of the columns of `table` on the server.
fn columns_of(s: &LibsqlStore, table: &str) -> Vec<String> {
    rows(s, &format!("SELECT name FROM pragma_table_info('{table}')"))
        .into_iter()
        .filter_map(|r| r.into_iter().next())
        .collect()
}

/// Make `ns`'s tables as vci 2.8 made them (schema v1, the log, no
/// format-3 columns or tables), behind the store's back.
fn create_v1_namespace(s: &LibsqlStore, ns: &str) {
    let p = table_prefix(ns);
    let names = vci_store_sqlite::sql::Names::prefixed(&p);
    let shared = vci_store_sqlite::sql::Sql::new(&names);
    let mut stmts = vec![
        "CREATE TABLE IF NOT EXISTS vci_schema (ns TEXT NOT NULL PRIMARY KEY, prefix TEXT NOT NULL, \
         version INTEGER NOT NULL, vci_version TEXT NOT NULL, created_at INTEGER NOT NULL, \
         log_floor INTEGER NOT NULL DEFAULT 0)"
            .to_owned(),
    ];
    stmts.extend(
        shared
            .ddl
            .split(';')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_owned),
    );
    stmts.push(format!(
        "CREATE TABLE IF NOT EXISTS {p}log (seq INTEGER PRIMARY KEY AUTOINCREMENT, test_key TEXT, \
         signer TEXT, storage_key TEXT, root TEXT, at INTEGER NOT NULL)"
    ));
    stmts.push(format!(
        "INSERT INTO vci_schema (ns, prefix, version, vci_version, created_at) \
         VALUES ('{ns}', '{p}', 1, '2.8.1', 1) ON CONFLICT (ns) DO NOTHING"
    ));
    s.__execute_for_test(&stmts).expect("the 2.8 tables");
}

fn has_v2_layout(s: &LibsqlStore, ns: &str) -> bool {
    let p = table_prefix(ns);
    let a = columns_of(s, &format!("{p}attestations"));
    let schema = columns_of(s, "vci_schema");
    [
        "format",
        "commit_id",
        "platform",
        "state",
        "duration_ms",
        "expires",
        "hdr",
        "tables_id",
        "shape",
        "state_obj",
        "seq",
    ]
    .iter()
    .all(|c| a.iter().any(|x| x == c))
        && ["v2", "seq", "gone_floor"]
            .iter()
            .all(|c| schema.iter().any(|x| x == c))
        && !columns_of(s, &format!("{p}objects")).is_empty()
        && !columns_of(s, &format!("{p}gone")).is_empty()
        && one(s, &format!("SELECT v2 FROM vci_schema WHERE ns = '{ns}'")) == "1"
}

// ---- the schema ----------------------------------------------------------------------

/// A namespace vci 2.8 made is brought to the format-3 layout by 2.9's
/// first write, in a request of its own before the write's one
/// transaction; `vci store upgrade --begin` does the same ahead of it and
/// is idempotent; a second writer finds nothing to send.
#[test]
fn the_first_write_upgrades_a_v1_namespace_in_a_request_of_its_own() {
    let Some((setup, ns)) = remote() else {
        return;
    };
    create_v1_namespace(&setup, &ns);
    assert!(!has_v2_layout(&setup, &ns));
    assert!(matches!(setup.status(), Ok(StoreStatus::Ready { .. })));

    // 2.9's first write: the upgrade, then the batch's transaction.
    let s = testkit::open_remote(&ns).unwrap();
    let before = s.requests();
    let e = s
        .put_for_test(UNIT, S1, &hex64(1), Some(&hint(5)), &envelope("first"))
        .unwrap();
    // The version with the flag (described, then run; once more on a
    // database whose vci_schema a 2.8 made), the columns (described, then
    // run), the DDL, then the transaction.
    let used = s.requests() - before;
    assert!(
        (6..=7).contains(&used),
        "the DDL is a request of its own: {used} requests"
    );
    assert!(
        has_v2_layout(&setup, &ns),
        "the first write upgraded the namespace"
    );
    assert_eq!(s.written().0, 1, "the write itself is one transaction");
    // A format-1 row: NULL columns, a `seq`, a log row for 2.8 replicas.
    let p = table_prefix(&ns);
    assert_eq!(
        rows(
            &s,
            &format!(
                "SELECT format, commit_id, seq FROM {p}attestations WHERE key = '{}'",
                e.key
            )
        ),
        vec![vec!["NULL".to_owned(), "NULL".to_owned(), "1".to_owned()]]
    );
    assert_eq!(
        count(
            &s,
            &format!(
                "SELECT count(*) FROM {p}log WHERE test_key = '{}'",
                e.test_key
            )
        ),
        1
    );

    // Idempotent: another handle finds the layout and sends no DDL.
    let other = testkit::open_remote(&ns).unwrap();
    let before = other.requests();
    assert!(!other.upgrade_begin().unwrap(), "nothing to upgrade");
    assert_eq!(other.requests() - before, 2, "the version and the flag");
    assert!(!other.upgrade_begin().unwrap());
    assert_eq!(other.requests() - before, 2, "remembered");

    // `--begin` ahead of any write, on another 2.8 namespace.
    let ns2 = testkit::namespace();
    create_v1_namespace(&setup, &ns2);
    let s2 = testkit::open_remote(&ns2).unwrap();
    let before = s2.requests();
    assert!(s2.upgrade_begin().unwrap(), "upgraded");
    let used = s2.requests() - before;
    assert!(
        (5..=6).contains(&used),
        "the version with the flag, the columns, the DDL: {used} requests"
    );
    assert!(has_v2_layout(&s2, &ns2));
    assert_eq!(s2.written().0, 0, "no batch was sent");
    let before = s2.requests();
    s2.put_for_test(UNIT, S1, &hex64(1), Some(&hint(5)), &envelope("first"))
        .unwrap();
    assert_eq!(s2.requests() - before, 1, "the write alone");

    // `--finish` is refused while a format-1 row exists, and not done yet
    // without one.
    assert!(
        matches!(s2.upgrade_finish(), Ok(Finish::FormatOneRows(1))),
        "one format-1 row"
    );
    let run = Run3::build(&["src/f3/a.ts"]);
    let (rec, cols) = run.record(UNIT, 1, 7);
    s2.put_objects(&run.new_objects()).unwrap();
    put3(&s2, UNIT, &hex64(1), Some(&hint(6)), &rec, &cols);
    match s2.upgrade_finish() {
        Err(StoreError::Unsupported { operation, .. }) => {
            assert!(operation.contains("finishing"), "{operation}");
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// A namespace 2.9 creates has the layout from its first request, one
/// transaction for the tables and the columns; the memo is what it was.
#[test]
fn a_new_namespace_is_created_at_the_format_3_layout_in_one_request() {
    let Some((s, ns)) = remote() else {
        return;
    };
    assert!(matches!(s.status(), Ok(StoreStatus::Absent { .. })));
    let before = s.requests();
    s.put_for_test(UNIT, S1, &hex64(1), Some(&hint(5)), &envelope("new"))
        .unwrap();
    // The version (absent), the columns, the DDL, the version again, the
    // transaction.
    assert_eq!(s.requests() - before, 5);
    assert!(has_v2_layout(&s, &ns));
    assert_eq!(s.written().0, 1);
    let p = table_prefix(&ns);
    assert_eq!(
        columns_of(&s, &format!("{p}memo"))
            .iter()
            .map(|c| c.to_ascii_lowercase())
            .collect::<Vec<_>>(),
        ["tree16", "test_key", "key", "at"],
        "the memo table is unchanged"
    );
    s.remember_passing("0123456789abcdef", &[(key::test_key(UNIT), "k".to_owned())]);
    assert_eq!(
        s.passing_on("0123456789abcdef").get(&key::test_key(UNIT)),
        Some(&"k".to_owned())
    );
    let fresh = testkit::open_remote(&ns).unwrap();
    assert_eq!(fresh.passing_on("0123456789abcdef").len(), 1);
}

/// On a namespace without the layout (2.8's, not written by 2.9 yet) the
/// format-3 reads answer nothing without an error, and nothing is sent to
/// change it.
#[test]
fn a_v1_namespace_answers_no_objects_and_no_columns() {
    let Some((s, ns)) = remote() else {
        return;
    };
    create_v1_namespace(&s, &ns);
    let run = Run3::build(&["src/f3/v1.ts"]);
    assert!(s.get_objects(&run.id_refs()).unwrap().is_empty());
    assert!(s.orphan_objects().unwrap().is_empty());
    assert_eq!(s.remove_objects(&run.id_refs()).unwrap(), 0);
    assert_eq!(s.prune_state_objects(Duration::ZERO).unwrap(), 0);
    let k = NewAttestation::for_test(UNIT, S1, &hex64(1), None, b"{}").plain_key();
    let e = StoredEnvelope::from_key(key::target_label(UNIT), &k).unwrap();
    assert_eq!(s.columns(&[&e]).unwrap(), vec![Columns::default()]);
    assert!(!has_v2_layout(&s, &ns), "reads changed nothing");
}

// ---- seq, objects, gone --------------------------------------------------------------

/// Every write transaction takes one `seq` from `vci_schema`, rising, and
/// stamps it on every row it touches: a put's row, the objects it stores,
/// the `gone` rows of what it removes.
#[test]
fn seq_is_one_per_transaction_and_rises() {
    let Some((s, ns)) = remote() else {
        return;
    };
    let p = table_prefix(&ns);
    let run = Run3::build(&["src/f3/seq.ts"]);
    let (rec, cols) = run.record(UNIT, 1, 1);
    s.put_objects(&run.new_objects()).unwrap();
    let e1 = put3(&s, UNIT, &hex64(1), Some(&hint(1)), &rec, &cols);
    let e2 = put3(&s, UNIT, &hex64(2), Some(&hint(2)), &rec, &cols);
    let counter = count(&s, &format!("SELECT seq FROM vci_schema WHERE ns = '{ns}'"));
    assert_eq!(counter, 3, "three transactions");
    let seqs: Vec<i64> = rows(&s, &format!("SELECT seq FROM {p}attestations ORDER BY seq"))
        .iter()
        .map(|r| r[0].parse().unwrap())
        .collect();
    assert_eq!(seqs, [2, 3]);
    assert_eq!(
        count(&s, &format!("SELECT count(DISTINCT seq) FROM {p}objects")),
        1,
        "the four objects share their transaction's seq"
    );
    assert_eq!(count(&s, &format!("SELECT min(seq) FROM {p}objects")), 1);

    // A batch: objects, records and removals in one transaction share one
    // seq; the removed keys get `gone` rows with it.
    let b = s.batch().unwrap();
    let other = Run3::build(&["src/f3/seq2.ts"]);
    s.put_objects(&other.new_objects()).unwrap();
    let (rec3, cols3) = other.record(UNIT, 1, 3);
    let e3 = put3(&s, UNIT, &hex64(3), Some(&hint(3)), &rec3, &cols3);
    s.remove(vec![e1.clone(), e2.clone()]).unwrap();
    b.finish().unwrap();
    assert_eq!(s.written().0, 4);
    assert_eq!(
        count(&s, &format!("SELECT seq FROM vci_schema WHERE ns = '{ns}'")),
        4
    );
    assert_eq!(
        one(
            &s,
            &format!("SELECT seq FROM {p}attestations WHERE key = '{}'", e3.key)
        ),
        "4"
    );
    // (The two runs share their hdr and tables: those are re-puts, which
    // keep their seq; the second shape is new.)
    assert_eq!(
        one(
            &s,
            &format!(
                "SELECT seq FROM {p}objects WHERE id = '{}'",
                other.ids.shape
            )
        ),
        "4"
    );
    let gone: Vec<Vec<String>> = rows(&s, &format!("SELECT key, seq FROM {p}gone ORDER BY key"));
    let mut want = vec![
        vec![e1.key.clone(), "4".to_owned()],
        vec![e2.key, "4".to_owned()],
    ];
    want.sort();
    assert_eq!(
        gone, want,
        "a gone row per removed key, with the transaction's seq"
    );
    // The old log: no slot row for a format-3 put, one per removal.
    assert_eq!(
        count(
            &s,
            &format!(
                "SELECT count(*) FROM {p}log WHERE test_key = '{}'",
                e1.test_key
            )
        ),
        2,
        "the two removals, not the three puts"
    );

    // An idempotent re-put keeps the object's seq (a replica has it) and
    // refreshes put_at; a batch sent again rewrites no row.
    s.__execute_for_test(&[format!(
        "UPDATE {p}objects SET put_at = put_at - 100 WHERE id = '{}'",
        run.ids.hdr
    )])
    .unwrap();
    assert_eq!(s.put_objects(&run.new_objects()).unwrap(), 0);
    assert_eq!(
        one(
            &s,
            &format!("SELECT seq FROM {p}objects WHERE id = '{}'", run.ids.hdr)
        ),
        "1"
    );
    let put_at: i64 = one(
        &s,
        &format!("SELECT put_at FROM {p}objects WHERE id = '{}'", run.ids.hdr),
    )
    .parse()
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(now - put_at < 10, "put_at refreshed: {put_at} vs {now}");
}

/// Objects are stored as base64 text (the batch is one SQL string: a hex
/// blob would be twice the bytes), and read back as the bytes.
#[test]
fn objects_travel_as_base64_text() {
    let Some((s, ns)) = remote() else {
        return;
    };
    let p = table_prefix(&ns);
    let run = Run3::build(&["src/f3/b64.ts", "src/f3/b64-2.ts"]);
    assert_eq!(s.put_objects(&run.new_objects()).unwrap(), 4);
    for (kind, bytes) in &run.objects {
        let id = vci_core::objects::hex32(&vci_core::object_id(bytes));
        let row = rows(
            &s,
            &format!("SELECT typeof(bytes), bytes, kind FROM {p}objects WHERE id = '{id}'"),
        )
        .remove(0);
        assert_eq!(row[0], "text", "{kind}");
        assert_eq!(row[1], object_to_base64(bytes), "{kind}");
        assert_eq!(row[2], (*kind as u8).to_string());
    }
    // A fresh handle reads them back; a prefetch then costs the read no
    // request; the answer leaves the cache (another writer's removal is
    // seen next time).
    let fresh = testkit::open_remote(&ns).unwrap();
    fresh
        .prefetch(Prefetch::Objects {
            ids: &run.id_refs(),
        })
        .unwrap();
    let n = fresh.requests();
    let got = fresh.get_objects(&run.id_refs()).unwrap();
    assert_eq!(fresh.requests(), n, "answered from the prefetch");
    assert_eq!(got.len(), 4);
    for (o, (kind, bytes)) in got.iter().zip(&run.objects) {
        assert_eq!(o.kind, *kind);
        assert_eq!(&o.bytes, bytes);
    }
    // Text that is not base64 reads as not stored.
    s.__execute_for_test(&[format!(
        "UPDATE {p}objects SET bytes = 'not base64!' WHERE id = '{}'",
        run.ids.state
    )])
    .unwrap();
    assert_eq!(fresh.get_objects(&run.id_refs()).unwrap().len(), 3);
    assert_ne!(fresh.requests(), n, "asked again");
}

/// Inside a batch, `remove_objects` applies the orphan rule at once but
/// keeps the objects the batch queued (the server holds them with an old
/// `put_at`, which the batch refreshes when it finishes).
#[test]
fn remove_objects_keeps_an_open_batchs_objects() {
    let Some((s, ns)) = remote() else {
        return;
    };
    let p = table_prefix(&ns);
    let run = Run3::build(&["src/f3/keep.ts"]);
    s.put_objects(&run.new_objects()).unwrap();
    let age = |ids: &[&str]| {
        let list = ids
            .iter()
            .map(|i| format!("'{i}'"))
            .collect::<Vec<_>>()
            .join(", ");
        s.__execute_for_test(&[format!(
            "UPDATE {p}objects SET put_at = put_at - {} WHERE id IN ({list})",
            OBJECT_GRACE.as_secs() * 2
        )])
        .unwrap();
    };
    age(&run.id_refs());
    assert_eq!(s.orphan_objects().unwrap().len(), 4, "unreferenced and old");
    let b = s.batch().unwrap();
    assert_eq!(s.put_objects(&run.new_objects()).unwrap(), 4, "queued");
    assert_eq!(s.remove_objects(&run.id_refs()).unwrap(), 0, "kept: queued");
    let (rec, cols) = run.record(UNIT, 1, 9);
    put3(&s, UNIT, &hex64(1), Some(&hint(1)), &rec, &cols);
    b.finish().unwrap();
    assert_eq!(s.get_objects(&run.id_refs()).unwrap().len(), 4);
    assert!(
        s.orphan_objects().unwrap().is_empty(),
        "referenced now, and fresh"
    );
    age(&run.id_refs());
    assert!(s.orphan_objects().unwrap().is_empty(), "referenced");
    assert_eq!(s.remove_objects(&run.id_refs()).unwrap(), 0);
    assert_eq!(
        s.prune_state_objects(OBJECT_GRACE).unwrap(),
        1,
        "the state object, referenced or not"
    );
    assert_eq!(
        count(
            &s,
            &format!(
                "SELECT count(*) FROM {p}gone WHERE object = '{}'",
                run.ids.state
            )
        ),
        1,
        "a gone row for the pruned state object"
    );
}

/// Inside a batch, `remove_objects` is queued and applied under the orphan
/// rule after everything else of the batch (as PostgreSQL's batch does):
/// the objects of a record the batch removes go with it, in the batch's
/// last transaction, with a `gone` row each; the batch's own objects are
/// left out.
#[test]
fn remove_objects_in_a_batch_follows_the_batchs_removals() {
    let Some((s, ns)) = remote() else {
        return;
    };
    let p = table_prefix(&ns);
    let run = Run3::build(&["src/f3/gone.ts"]);
    s.put_objects(&run.new_objects()).unwrap();
    let (rec, cols) = run.record(UNIT, 1, 41);
    let e = put3(&s, UNIT, &hex64(1), Some(&hint(1)), &rec, &cols);
    let list = run
        .id_refs()
        .iter()
        .map(|i| format!("'{i}'"))
        .collect::<Vec<_>>()
        .join(", ");
    s.__execute_for_test(&[format!(
        "UPDATE {p}objects SET put_at = put_at - {} WHERE id IN ({list})",
        OBJECT_GRACE.as_secs() * 2
    )])
    .unwrap();
    assert!(s.orphan_objects().unwrap().is_empty(), "referenced");
    let fresh = Run3::build(&["src/f3/kept.ts"]);
    let b = s.batch().unwrap();
    assert_eq!(s.remove(vec![e]).unwrap().len(), 1);
    assert_eq!(s.put_objects(&fresh.new_objects()).unwrap(), 4);
    let mut ids = run.id_refs();
    ids.extend(fresh.id_refs());
    assert_eq!(s.remove_objects(&ids).unwrap(), 0, "queued: counts nothing");
    assert_eq!(
        count(
            &s,
            &format!("SELECT count(*) FROM {p}objects WHERE id IN ({list})")
        ),
        4,
        "nothing is applied before the batch finishes"
    );
    b.finish().unwrap();
    // The two runs share their hdr and their tables (the same header and
    // env names): those are the batch's own, kept; the removed record's
    // shape and state object went with it.
    let gone: Vec<String> = rows(
        &s,
        &format!("SELECT object FROM {p}gone WHERE object IN ({list}) ORDER BY object"),
    )
    .into_iter()
    .filter_map(|r| r.into_iter().next())
    .collect();
    let mut expected = vec![run.ids.shape.clone(), run.ids.state.clone()];
    expected.sort();
    assert_eq!(gone, expected, "a gone row each for what went");
    assert_eq!(
        count(
            &s,
            &format!("SELECT count(*) FROM {p}objects WHERE id IN ({list})")
        ),
        2,
        "the removed record's shape and state object went with it"
    );
    let mut kept: Vec<String> = s
        .get_objects(&run.id_refs())
        .unwrap()
        .iter()
        .map(|o| o.id.clone())
        .collect();
    kept.sort();
    let mut shared = vec![run.ids.hdr.clone(), run.ids.tables.clone()];
    shared.sort();
    assert_eq!(kept, shared, "what the batch's own record names stays");
    assert_eq!(
        s.get_objects(&fresh.id_refs()).unwrap().len(),
        4,
        "the batch's own objects are kept"
    );
}

/// `upgrade_finish` counts a format-1 row by its value, not by the
/// `format` column: a 2.8 writer's upsert sets the key and the value
/// alone (section 9 of vci-cli's store_backends), so a format-1 value in
/// a slot whose columns still say 3 is counted, and a frame put without
/// columns (what a copy out of git-meta passes) is not.
#[test]
fn upgrade_finish_counts_rows_by_their_value() {
    let Some((s, ns)) = remote() else {
        return;
    };
    let p = table_prefix(&ns);
    let run = Run3::build(&["src/f3/count.ts"]);
    s.put_objects(&run.new_objects()).unwrap();
    let (rec, cols) = run.record(UNIT, 1, 31);
    let e = put3(&s, UNIT, &hex64(1), Some(&hint(1)), &rec, &cols);
    let format = |key: &str| {
        one(
            &s,
            &format!("SELECT format FROM {p}attestations WHERE key = '{key}'"),
        )
    };
    assert_eq!(format(&e.key), "3");
    // What 2.8 does to the frame's slot: the value alone.
    let hex: String = envelope("2.8").iter().map(|b| format!("{b:02x}")).collect();
    s.__execute_for_test(&[format!(
        "UPDATE {p}attestations SET value = X'{hex}', encoding = 0 WHERE key = '{}'",
        e.key
    )])
    .unwrap();
    assert_eq!(format(&e.key), "3", "the frame's columns stay");
    assert!(
        matches!(s.upgrade_finish(), Ok(Finish::FormatOneRows(1))),
        "a format-1 value under a 3"
    );
    // Without it, a frame put without columns does not hold the window.
    s.remove(vec![e]).unwrap();
    let (rec2, _) = run.record(UNIT, 1, 32);
    let e2 = s
        .put(&NewAttestation::for_test(
            UNIT,
            S1,
            &hex64(2),
            Some(&hint(2)),
            &rec2,
        ))
        .unwrap();
    assert_eq!(format(&e2.key), "NULL");
    match s.upgrade_finish() {
        Err(StoreError::Unsupported { operation, .. }) => {
            assert!(operation.contains("finishing"), "{operation}");
        }
        other => panic!("expected no format-1 row, got {other:?}"),
    }
}

/// A format-3 record is under 2 kB: a transaction holds as many as fit
/// in its bytes, not `TX_UNITS` of them.
#[test]
fn transactions_of_format_3_records_are_sized_by_bytes_alone() {
    let Some((s, _ns)) = remote() else {
        return;
    };
    let run = Run3::build(&["src/f3/many.ts"]);
    let b = s.batch().unwrap();
    s.put_objects(&run.new_objects()).unwrap();
    for i in 0..200u32 {
        let unit = format!("src/f3/many-{i:03}.test.ts");
        let (rec, cols) = run.record(&unit, 1, i);
        put3(&s, &unit, &hex64(1), Some(&hint(1)), &rec, &cols);
    }
    b.finish().unwrap();
    let (txs, bytes, _) = s.written();
    assert_eq!(txs, 1, "200 records of {bytes} bytes in one transaction");
    assert!(bytes < 1 << 20, "{bytes}");
    assert_eq!(s.count().unwrap(), 200);
}

// ---- the replica ---------------------------------------------------------------------

/// A replica syncs format-3 records and their removals by `seq` (the old
/// log names neither), moving its format-3 cursor; its object and column
/// reads are the server's.
#[test]
fn a_replica_syncs_format_3_rows_and_deletions_by_seq() {
    let Some((writer, ns)) = remote() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replica.libsql");
    let side = dir.path().join("replica.libsql.sync");
    let seq2 = |path: &Path| -> i64 {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_default())
                .unwrap_or_default();
        v["seq2"].as_i64().unwrap_or(-1)
    };
    let p = table_prefix(&ns);
    let run = Run3::build(&["src/f3/rep.ts"]);
    let (rec, cols) = run.record(UNIT, 1, 5);
    writer.put_objects(&run.new_objects()).unwrap();
    let e = put3(&writer, UNIT, &hex64(1), Some(&hint(1)), &rec, &cols);
    assert_eq!(
        count(
            &writer,
            &format!(
                "SELECT count(*) FROM {p}log WHERE test_key = '{}'",
                e.test_key
            )
        ),
        0,
        "a format-3 put writes no log row"
    );

    let r = testkit::open_replica(&ns, &path).unwrap();
    let got = r.read_units(&[UNIT]).unwrap().remove(0);
    assert_eq!(got.len(), 1, "synced by seq");
    assert_eq!(got[0].key, e.key);
    assert_eq!(got[0].state(), ValueState::Read(&rec));
    assert_eq!(seq2(&side), 2, "the cursor is the counter");
    assert_eq!(
        r.get_objects(&run.id_refs()).unwrap().len(),
        4,
        "from the server"
    );
    assert_eq!(
        r.columns(&[&got[0]]).unwrap(),
        vec![cols.clone()],
        "from the server"
    );

    // Another record, synced at the next sync; the first's removal too.
    let (rec2, cols2) = run.record(UNIT, 1, 6);
    let e2 = put3(&writer, UNIT, &hex64(2), Some(&hint(2)), &rec2, &cols2);
    writer.remove(vec![e.clone()]).unwrap();
    let r2 = testkit::open_replica(&ns, &path).unwrap();
    let got = r2.read_units(&[UNIT]).unwrap().remove(0);
    assert_eq!(
        got.iter().map(|x| x.key.clone()).collect::<Vec<_>>(),
        vec![e2.key.clone()]
    );
    assert_eq!(seq2(&side), 4);
    // A sync of nothing new is one request and moves nothing.
    let r3 = testkit::open_replica(&ns, &path).unwrap();
    let n = r3.requests();
    r3.list_units(&[UNIT]).unwrap();
    assert!(
        r3.requests() - n <= 2,
        "the sync is one statement (described first on a new handle)"
    );
    assert_eq!(seq2(&side), 4);
}

/// A replica whose format-3 cursor is older than the `gone` purge horizon
/// (deletions it never saw were purged) syncs everything again, as one
/// whose cursor is past the counter (the namespace was restored) does.
#[test]
fn a_replica_behind_the_purge_horizon_syncs_everything() {
    let Some((writer, ns)) = remote() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replica.libsql");
    let p = table_prefix(&ns);
    let run = Run3::build(&["src/f3/hor.ts"]);
    let (rec, cols) = run.record(UNIT, 1, 5);
    writer.put_objects(&run.new_objects()).unwrap();
    let e = put3(&writer, UNIT, &hex64(1), Some(&hint(1)), &rec, &cols);
    let r = testkit::open_replica(&ns, &path).unwrap();
    assert_eq!(r.list_units(&[UNIT]).unwrap()[0].len(), 1);

    // Behind the store's back: the record goes without a gone row the
    // replica could sync (as one purged would have), and the floor moves
    // past the replica's cursor.
    writer
        .__execute_for_test(&[
            format!("DELETE FROM {p}attestations WHERE key = '{}'", e.key),
            format!("UPDATE vci_schema SET gone_floor = seq + 1, seq = seq + 1 WHERE ns = '{ns}'"),
        ])
        .unwrap();
    let r2 = testkit::open_replica(&ns, &path).unwrap();
    assert!(
        r2.list_units(&[UNIT]).unwrap()[0].is_empty(),
        "a full sync dropped the key the replica could not have been told about"
    );

    // Restored to an earlier point: the counter is below the cursor.
    let (rec2, cols2) = run.record(UNIT, 1, 6);
    let e2 = put3(&writer, UNIT, &hex64(2), Some(&hint(2)), &rec2, &cols2);
    let r3 = testkit::open_replica(&ns, &path).unwrap();
    assert_eq!(r3.list_units(&[UNIT]).unwrap()[0][0].key, e2.key);
    writer
        .__execute_for_test(&[
            format!("DELETE FROM {p}attestations WHERE key = '{}'", e2.key),
            format!("UPDATE vci_schema SET seq = 1, gone_floor = 0 WHERE ns = '{ns}'"),
        ])
        .unwrap();
    let r4 = testkit::open_replica(&ns, &path).unwrap();
    assert!(
        r4.list_units(&[UNIT]).unwrap()[0].is_empty(),
        "synced in full again"
    );
}

/// A row in the replica file at `path` that the server never held: what a
/// full sync drops and a sync of the changes keeps.
fn plant_row(path: &Path, unit: &str) -> String {
    let test_key = key::test_key(unit);
    let k = format!("vci:attestation:{test_key}:{S1}:{}", hex64(0x77));
    let db = rusqlite::Connection::open(path).unwrap();
    db.busy_timeout(Duration::from_secs(20)).unwrap();
    db.execute(
        "INSERT INTO attestations (key, test_key, signer, storage_key, target, issued, tree16, \
         manifest_ref, ref_state, stored_at, value) \
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL, 2, 1, ?6)",
        rusqlite::params![
            k,
            test_key,
            S1,
            hex64(0x77),
            key::target_label(unit),
            envelope("planted"),
        ],
    )
    .unwrap();
    k
}

/// A replica file a vci 2.8 kept (its sidecar says `v` 1 and no format-3
/// cursor; it synced the log, so the file holds the namespace's format-1
/// rows and none of its format-3 rows, which the log never named) is
/// synced in full once by this vci (STORE-V2 section 5, gate 7): the
/// format-3 row comes, its columns and objects answer from the server, a
/// row the server never held goes, and the sidecar then says `v` 3 with
/// the format-3 cursor at the counter. From there the syncs are by `seq`:
/// a new format-3 row and a removal arrive, and a row the file holds that
/// the server never named stays, which a full sync would not leave.
#[test]
fn a_2_8_replica_file_is_synced_in_full_once_then_by_seq() {
    let Some((writer, ns)) = remote() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replica.libsql");
    let side = dir.path().join("replica.libsql.sync");
    let sidecar = || -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(&side).unwrap_or_default())
            .unwrap_or_default()
    };
    let counter = || -> i64 {
        count(
            &writer,
            &format!("SELECT seq FROM vci_schema WHERE ns = '{ns}'"),
        )
    };
    let unit1 = "src/f3/one.test.ts";
    let unit3 = "src/f3/three.test.ts";
    let planted = "src/f3/planted.test.ts";
    let units = [unit1, unit3, planted];
    let keys_of = |r: &LibsqlStore| -> Vec<Vec<String>> {
        r.list_units(&units)
            .unwrap()
            .into_iter()
            .map(|l| l.into_iter().map(|e| e.key).collect())
            .collect()
    };

    // The server: a format-1 row (in the log) and a run's objects and a
    // format-3 row (by seq).
    let e1 = writer
        .put_for_test(unit1, S1, &hex64(1), Some(&hint(1)), &envelope("one"))
        .unwrap();
    let run = Run3::build(&["src/f3/old.ts"]);
    writer.put_objects(&run.new_objects()).unwrap();
    let (rec, cols) = run.record(unit3, 1, 8);
    let e3 = put3(&writer, unit3, &hex64(3), Some(&hint(3)), &rec, &cols);
    let r = testkit::open_replica(&ns, &path).unwrap();
    assert_eq!(
        keys_of(&r),
        vec![vec![e1.key.clone()], vec![e3.key.clone()], vec![]]
    );
    drop(r);

    // The file as 2.8 left it: without the format-3 row, with a row of
    // its own, and a sidecar from before the format-3 cursor.
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            db.execute(
                "DELETE FROM attestations WHERE key = ?1",
                rusqlite::params![e3.key]
            )
            .unwrap(),
            1
        );
    }
    let k_planted = plant_row(&path, planted);
    let mut v = sidecar();
    assert_eq!(v["v"].as_i64(), Some(3), "{v}");
    v["v"] = serde_json::json!(1);
    v.as_object_mut().unwrap().remove("seq2");
    std::fs::write(&side, v.to_string()).unwrap();

    // Synced in full once: the format-3 row is back, the planted row gone.
    let r = testkit::open_replica(&ns, &path).unwrap();
    assert_eq!(
        keys_of(&r),
        vec![vec![e1.key.clone()], vec![e3.key.clone()], vec![]],
        "synced in full"
    );
    let got = r.read_units(&[unit3]).unwrap().remove(0);
    assert_eq!(got[0].state(), ValueState::Read(&rec));
    assert_eq!(r.columns(&[&got[0]]).unwrap(), vec![cols.clone()]);
    assert_eq!(r.get_objects(&run.id_refs()).unwrap().len(), 4);
    drop(r);
    let v = sidecar();
    assert_eq!(v["v"].as_i64(), Some(3), "{v}");
    assert_eq!(v["seq2"].as_i64(), Some(counter()), "{v}");
    let cursor = counter();

    // By seq from here: a put and a removal arrive; a planted row stays.
    let k_planted2 = plant_row(&path, planted);
    assert_eq!(k_planted2, k_planted);
    let (rec4, cols4) = run.record(unit3, 1, 9);
    let e4 = put3(&writer, unit3, &hex64(4), Some(&hint(4)), &rec4, &cols4);
    writer.remove(vec![e3.clone()]).unwrap();
    let r = testkit::open_replica(&ns, &path).unwrap();
    assert_eq!(
        keys_of(&r),
        vec![vec![e1.key.clone()], vec![e4.key.clone()], vec![k_planted]],
        "the changes since the cursor, and nothing else touched"
    );
    drop(r);
    let v = sidecar();
    assert_eq!(v["seq2"].as_i64(), Some(cursor + 2), "{v}");
    assert_eq!(counter(), cursor + 2);
}

/// The `gone` rows past the purge horizon (30 days, or the policy's
/// `max_ttl` when longer) are deleted by a handle's first write, the newest
/// of them recorded as the floor.
#[test]
fn gone_rows_are_purged_at_the_horizon() {
    let Some((s, ns)) = remote() else {
        return;
    };
    let p = table_prefix(&ns);
    let e = s
        .put_for_test(UNIT, S1, &hex64(1), Some(&hint(1)), &envelope("x"))
        .unwrap();
    s.remove(vec![e]).unwrap();
    assert_eq!(count(&s, &format!("SELECT count(*) FROM {p}gone")), 1);
    // Older than 30 days, but within a 60-day max_ttl: kept by a handle
    // that knows the policy, purged by one that does not.
    s.__execute_for_test(&[format!(
        "UPDATE {p}gone SET at = at - {}",
        45 * 24 * 60 * 60
    )])
    .unwrap();
    let long = testkit::open_remote(&ns).unwrap();
    long.set_max_ttl(Duration::from_secs(60 * 24 * 60 * 60));
    long.put_for_test(UNIT, S1, &hex64(2), Some(&hint(2)), &envelope("y"))
        .unwrap();
    assert_eq!(
        count(&s, &format!("SELECT count(*) FROM {p}gone")),
        1,
        "kept"
    );
    assert_eq!(
        one(
            &s,
            &format!("SELECT gone_floor FROM vci_schema WHERE ns = '{ns}'")
        ),
        "0"
    );
    let short = testkit::open_remote(&ns).unwrap();
    short
        .put_for_test(UNIT, S1, &hex64(3), Some(&hint(3)), &envelope("z"))
        .unwrap();
    assert_eq!(
        count(&s, &format!("SELECT count(*) FROM {p}gone")),
        0,
        "purged"
    );
    assert_eq!(
        one(
            &s,
            &format!("SELECT gone_floor FROM vci_schema WHERE ns = '{ns}'")
        ),
        "2",
        "the purged row's seq is the floor"
    );
}

// ---- the write model over the real sample ---------------------------------------------

/// One 800-unit partition of the largest run of the sample `VCI_PAIRS`
/// names, written to the test server as `vci run` will write it: the
/// run's objects and its records in one batch, then a second run's records
/// with the first's removals. Prints the transactions and the wire bytes
/// (section 18, "Measured"). Skipped without `VCI_PAIRS`.
#[test]
fn an_800_unit_partition_is_a_few_transactions() {
    let Ok(pairs_path) = std::env::var("VCI_PAIRS") else {
        eprintln!("VCI_PAIRS is unset: the measurement over the real sample is skipped");
        return;
    };
    let Some((s, _ns)) = remote() else {
        return;
    };
    let data = std::fs::read(&pairs_path).expect("VCI_PAIRS readable");
    let json: serde_json::Value = serde_json::from_slice(&data).expect("pairs JSON");
    struct Pairs {
        pairs: Vec<(String, String, String)>,
    }
    let pairs = Pairs {
        pairs: json["pairs"]
            .as_array()
            .expect("a pairs array")
            .iter()
            .map(|p| {
                let s = |i: usize| p[i].as_str().expect("a string").to_owned();
                (s(0), s(1), s(2))
            })
            .collect(),
    };
    // The units of the largest run (commit, issuedAt, project, adapter).
    struct Unit {
        envelope: vci_attest::Envelope,
        pred: vci_core::VciPredicate,
        subject: String,
        manifest: vci_core::InputManifest,
        base: Option<String>,
    }
    let mut runs: BTreeMap<(String, String, String, String), Vec<Unit>> = BTreeMap::new();
    for (env_s, man_s, _) in &pairs.pairs {
        let envelope = vci_attest::Envelope::from_json(env_s.as_bytes()).expect("envelope");
        let payload = envelope.payload_bytes().expect("payload");
        let statement: vci_attest::Statement = serde_json::from_slice(&payload).expect("statement");
        let pred: vci_core::VciPredicate =
            serde_json::from_value(statement.predicate.clone()).expect("predicate");
        let subject = statement.subject[0].digest["blake3"].clone();
        let mut compact: serde_json::Value = serde_json::from_str(man_s).expect("manifest");
        let base = compact
            .as_object_mut()
            .unwrap()
            .remove("base")
            .map(|b| b.as_str().unwrap().to_owned());
        let manifest =
            vci_core::InputManifest::from_compact(&serde_json::to_vec(&compact).unwrap()).unwrap();
        let k = (
            pred.core.commit.clone(),
            pred.core.issued_at.clone(),
            pred.project_name.clone(),
            pred.core.adapter.clone(),
        );
        runs.entry(k).or_default().push(Unit {
            envelope,
            pred,
            subject,
            manifest,
            base,
        });
    }
    let (_, units) = runs.into_iter().max_by_key(|(_, u)| u.len()).unwrap();
    let units: Vec<&Unit> = units.iter().take(800).collect();
    println!("{} units of the largest run", units.len());

    // The run's objects and records (STORE-V2 section 1.4), a second run
    // of the same units under other storage keys.
    type Built = (
        Vec<(ObjectKind, Vec<u8>)>,
        Vec<(String, String, Vec<u8>, Columns)>,
    );
    let build = |seed: u8| -> Built {
        let mut hdrs: Vec<vci_core::Encoded<vci_core::Hdr>> = Vec::new();
        let mut headers = Vec::new();
        for u in &units {
            let h = u.pred.hdr().unwrap();
            let bytes = h.encode().unwrap();
            let i = hdrs
                .iter()
                .position(|x| x.bytes == bytes)
                .unwrap_or_else(|| {
                    hdrs.push(vci_core::Encoded::new(h, bytes));
                    hdrs.len() - 1
                });
            headers.push(i);
        }
        let inputs: Vec<vci_core::UnitInputs<'_>> = units
            .iter()
            .zip(&headers)
            .map(|(u, &header)| vci_core::UnitInputs {
                header,
                group: u.base.as_deref(),
                manifest: &u.manifest,
                waived: &u.pred.waived,
            })
            .collect();
        let run = vci_core::Run::build(&inputs).unwrap();
        let mut objects: Vec<(ObjectKind, Vec<u8>)> = hdrs
            .iter()
            .map(|h| (ObjectKind::Hdr, h.bytes.clone()))
            .collect();
        objects.extend(
            run.tables
                .iter()
                .map(|t| (ObjectKind::Tables, t.bytes.clone())),
        );
        objects.push((ObjectKind::Shape, run.shape.bytes.clone()));
        objects.push((ObjectKind::State, run.state.bytes.clone()));
        let shape_id = vci_core::objects::hex32(&run.shape.id);
        let state_id = vci_core::objects::hex32(&run.state.id);
        let mut records = Vec::new();
        for ((u, rec), &header) in units.iter().zip(&run.units).zip(&headers) {
            let h = &hdrs[header];
            let t = &run.tables[header];
            let v2 = u
                .pred
                .to_v2(&h.id, &t.id, &t.value, &u.manifest.entries_root())
                .unwrap();
            let statement = vci_attest::Statement::new(
                vec![vci_attest::Subject {
                    name: u.pred.core.test_id.clone(),
                    digest: BTreeMap::from([("blake3".to_owned(), u.subject.clone())]),
                }],
                vci_core::PREDICATE_TYPE_V2,
                serde_json::to_value(&v2).unwrap(),
            );
            let statement = vci_core::sorted_compact_json(&statement)
                .unwrap()
                .into_bytes();
            let descriptor = rec.descriptor.encode(&t.value).unwrap();
            let mut frame = vci_attest::Frame::from_envelope(&u.envelope, descriptor).unwrap();
            frame.statement = statement;
            let record = frame.encode().unwrap().into_bytes();
            let columns = Columns {
                format: Some(3),
                commit: Some(u.pred.core.commit.clone()),
                platform: Some(format!(
                    "{}-{}",
                    u.pred.core.toolchain.os, u.pred.core.toolchain.arch
                )),
                state: Some(u.pred.core.result.state.clone()),
                duration_ms: Some(u.pred.core.result.duration_ms),
                expires: None,
                hdr: Some(vci_core::objects::hex32(&h.id)),
                tables: Some(vci_core::objects::hex32(&t.id)),
                shape: Some(shape_id.clone()),
                state_obj: Some(state_id.clone()),
            };
            // The storage key names the inputs: the second run's differ.
            let storage_key =
                vci_core::blake3_hex(format!("{seed}:{}", u.pred.core.input_root).as_bytes());
            records.push((u.pred.core.test_id.clone(), storage_key, record, columns));
        }
        (objects, records)
    };
    let (objects, records) = build(1);
    let object_bytes: usize = objects.iter().map(|(_, b)| b.len()).sum();
    let record_bytes: usize = records.iter().map(|(_, _, r, _)| r.len()).sum();
    println!(
        "{} objects ({object_bytes} B at rest), {} records ({record_bytes} B)",
        objects.len(),
        records.len()
    );

    let began = Instant::now();
    let b = s.batch().unwrap();
    let news: Vec<NewObject<'_>> = objects.iter().map(|(k, b)| NewObject::new(*k, b)).collect();
    s.put_objects(&news).unwrap();
    let mut stored = Vec::new();
    for (unit, sk, rec, cols) in &records {
        stored.push(put3(&s, unit, sk, Some(&hint(1_700_000_000)), rec, cols));
    }
    b.finish().unwrap();
    let (txs, bytes, sql) = s.written();
    println!(
        "first run: {txs} transaction(s), {bytes} B of values and objects as literals, {sql} B of SQL on the wire, {} request(s), {:.2} s",
        s.requests(),
        began.elapsed().as_secs_f64()
    );
    assert!(txs <= 4, "{txs} transactions");

    // The second run: its records (the objects are shared: a re-put of 4
    // ids), and the supersession of the first run's.
    let (objects2, records2) = build(2);
    let (txs0, bytes0, sql0, req0) = (txs, bytes, sql, s.requests());
    let began = Instant::now();
    let b = s.batch().unwrap();
    let news: Vec<NewObject<'_>> = objects2
        .iter()
        .map(|(k, b)| NewObject::new(*k, b))
        .collect();
    s.put_objects(&news).unwrap();
    for ((unit, sk, rec, cols), old) in records2.iter().zip(stored) {
        put3(&s, unit, sk, Some(&hint(1_700_000_100)), rec, cols);
        s.remove(vec![old]).unwrap();
    }
    b.finish().unwrap();
    let (txs, bytes, sql) = s.written();
    println!(
        "second run with {} removals: {} transaction(s), {} B of values and objects as literals, {} B of SQL on the wire, {} request(s), {:.2} s",
        records.len(),
        txs - txs0,
        bytes - bytes0,
        sql - sql0,
        s.requests() - req0,
        began.elapsed().as_secs_f64()
    );
    assert_eq!(s.count().unwrap(), records.len());
}
