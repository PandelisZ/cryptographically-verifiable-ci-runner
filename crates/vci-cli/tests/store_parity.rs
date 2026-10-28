//! The four backends under one script (the M2 tests row of STORE-V2
//! section 6): the same sequence of puts, reads, removals and prunes of
//! format-1 envelopes, format-3 frames and their objects, run through the
//! store trait on git-meta, SQLite, PostgreSQL and libSQL (its local file,
//! a server, and a replica of one), gives the same observable result, the
//! transcript of every call's answer, with one allowance: the listing
//! columns are `None` on a store that keeps none (git-meta,
//! `Caps::columns`). Then every manifest, object and record of the SQLite
//! store is copied to a fresh store of each other kind through the trait,
//! objects before records (what `vci store copy` will do at M3), and the
//! copy's transcript is the source's.
//!
//! The conformance suite (`vci_store::conformance`) checks each rule on
//! each backend alone; this file checks that four backends asked the same
//! questions give the same answers. The PostgreSQL site takes its server
//! from [`vci_store_postgres::testkit::pg`] and the libSQL server and
//! replica sites theirs from [`vci_store_libsql::testkit::server`]; a site
//! without a server is left out, with a message on stderr, and the rest
//! still agree with each other.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use camino::Utf8PathBuf;
use vci_core::ObjectKind;
use vci_git::{GitMetaStore, Repo};
use vci_store::conformance::fixtures::{S1, S2, TREE_HEAD, UNIT_A, UNIT_B};
use vci_store::conformance::scenarios::{Run3, envelope, hex64, manifest_of};
use vci_store::select::LibsqlMode;
use vci_store::{
    AttestationStore, Columns, KeyHint, NewAttestation, NewObject, OBJECT_GRACE, Prefetch, Record,
    StoredEnvelope, StoredObject, ValueState, decode_record, key,
};
use vci_store_libsql::{LibsqlStore, table_prefix, testkit as libsql_kit};
use vci_store_postgres::testkit::{self as pg_kit, PgDb};
use vci_store_sqlite::{SqliteOptions, SqliteStore};

/// A unit nothing is ever stored for.
const UNIT_NONE: &str = "src/parity/none.test.ts";

/// Three days: past the two-day state TTL the script prunes with.
const THREE_DAYS: Duration = Duration::from_secs(3 * 24 * 60 * 60);
const TWO_DAYS: Duration = Duration::from_secs(2 * 24 * 60 * 60);

fn hint(issued: i64) -> KeyHint {
    KeyHint {
        issued,
        tree: Some(TREE_HEAD.to_owned()),
    }
}

// ---- the sites ---------------------------------------------------------------------

/// What one backend needs beside its handle: where its file or schema is,
/// for the aging of its objects behind the store's back, and what keeps
/// it alive.
enum Kind {
    GitMeta {
        _dir: tempfile::TempDir,
        root: Utf8PathBuf,
    },
    Sqlite {
        _dir: tempfile::TempDir,
        path: PathBuf,
    },
    Postgres {
        /// Boxed: a `PgDb` is many times the size of the other variants.
        db: Box<PgDb>,
    },
    LibsqlLocal {
        _dir: tempfile::TempDir,
        path: PathBuf,
    },
    LibsqlRemote {
        ns: String,
    },
    LibsqlReplica {
        ns: String,
        _dir: tempfile::TempDir,
        path: PathBuf,
    },
}

/// One backend under the script. The handle is declared first, so that it
/// closes before the schema or namespace behind it goes.
struct Site {
    name: &'static str,
    writer: Arc<dyn AttestationStore>,
    kind: Kind,
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

impl Site {
    /// git-meta in a repository with one commit and no remote.
    fn git_meta() -> Site {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(dir.path().canonicalize().unwrap()).unwrap();
        git(root.as_std_path(), &["init", "-q"]);
        std::fs::write(root.join("a.txt"), "alpha\n").unwrap();
        git(root.as_std_path(), &["add", "-A"]);
        git(root.as_std_path(), &["commit", "-q", "-m", "initial"]);
        let store = GitMetaStore::new(Repo::discover(&root).unwrap());
        Site {
            name: "git-meta",
            writer: Arc::new(store),
            kind: Kind::GitMeta { _dir: dir, root },
        }
    }

    fn sqlite() -> Site {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vci-store.sqlite");
        let store = SqliteStore::open_path(&path, SqliteOptions::default());
        Site {
            name: "sqlite",
            writer: Arc::new(store),
            kind: Kind::Sqlite { _dir: dir, path },
        }
    }

    /// `None` (left out) without a server.
    fn postgres() -> Option<Site> {
        let db = pg_kit::pg()?;
        let store = db.open();
        Some(Site {
            name: "postgres",
            writer: Arc::new(store),
            kind: Kind::Postgres { db: Box::new(db) },
        })
    }

    fn libsql_local() -> Site {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vci-store.libsql");
        let sel = libsql_kit::selection(LibsqlMode::Local, None, None, None, Some(&path));
        let store = LibsqlStore::open(&sel, &libsql_kit::cx_in(dir.path(), false))
            .expect("open the local libsql store");
        Site {
            name: "libsql local",
            writer: Arc::new(store),
            kind: Kind::LibsqlLocal { _dir: dir, path },
        }
    }

    /// `None` (left out) without a server.
    fn libsql_remote() -> Option<Site> {
        if !libsql_kit::available() {
            return None;
        }
        let ns = libsql_kit::namespace();
        let store = libsql_kit::open_remote(&ns)?;
        Some(Site {
            name: "libsql remote",
            writer: Arc::new(store),
            kind: Kind::LibsqlRemote { ns },
        })
    }

    /// Writes through one handle on the replica; a reader is a fresh
    /// handle, which syncs when it opens. `None` (left out) without a
    /// server.
    fn libsql_replica() -> Option<Site> {
        if !libsql_kit::available() {
            return None;
        }
        let ns = libsql_kit::namespace();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replica.libsql");
        let store = libsql_kit::open_replica(&ns, &path)?;
        Some(Site {
            name: "libsql replica",
            writer: Arc::new(store),
            kind: Kind::LibsqlReplica {
                ns,
                _dir: dir,
                path,
            },
        })
    }

    /// Every site this machine can run: SQLite first, the reference the
    /// others are compared with.
    fn all() -> Vec<Site> {
        let mut sites = vec![Site::sqlite(), Site::git_meta(), Site::libsql_local()];
        for (name, site) in [
            ("postgres", Site::postgres()),
            ("libsql remote", Site::libsql_remote()),
            ("libsql replica", Site::libsql_replica()),
        ] {
            match site {
                Some(s) => sites.push(s),
                None => eprintln!("SKIPPED: the {name} site has no server"),
            }
        }
        sites
    }

    /// A handle that sees every write made so far.
    fn reader(&self) -> Arc<dyn AttestationStore> {
        match &self.kind {
            Kind::LibsqlReplica { ns, path, .. } => {
                Arc::new(libsql_kit::open_replica(ns, path).expect("the server"))
            }
            _ => self.writer.clone(),
        }
    }

    /// Move the objects `ids` (every kind) back in time by `by`, behind the
    /// store's back, as the conformance worlds do.
    fn age(&self, ids: &[&str], by: Duration) {
        let secs = i64::try_from(by.as_secs()).unwrap();
        match &self.kind {
            Kind::GitMeta { root, .. } => {
                let db = rusqlite::Connection::open(root.join(".git/git-meta.sqlite")).unwrap();
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
            Kind::Sqlite { path, .. } | Kind::LibsqlLocal { path, .. } => {
                let db = rusqlite::Connection::open(path).unwrap();
                db.busy_timeout(Duration::from_secs(20)).unwrap();
                for id in ids {
                    let n = db
                        .execute(
                            "UPDATE objects SET put_at = put_at - ?2 WHERE id = ?1",
                            rusqlite::params![id, secs],
                        )
                        .unwrap();
                    assert_eq!(n, 1, "{}: object {id} to age", self.name);
                }
            }
            Kind::Postgres { db } => {
                let list = ids.iter().map(|i| lit(i)).collect::<Vec<_>>().join(", ");
                let rows = db.query(&format!(
                    "UPDATE {{schema}}.objects SET put_at = put_at - make_interval(secs => {secs})
                     WHERE ns = 'test' AND id IN ({list}) RETURNING 1"
                ));
                assert_eq!(rows.len(), ids.len(), "{}: objects to age", self.name);
            }
            Kind::LibsqlRemote { ns } | Kind::LibsqlReplica { ns, .. } => {
                let list = ids.iter().map(|i| lit(i)).collect::<Vec<_>>().join(", ");
                libsql_kit::open_remote(ns)
                    .expect("the server")
                    .__execute_for_test(&[format!(
                        "UPDATE {}objects SET put_at = put_at - {secs} WHERE id IN ({list})",
                        table_prefix(ns)
                    )])
                    .unwrap();
            }
        }
    }
}

/// `s` as an SQL string literal.
fn lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

// ---- the transcript ----------------------------------------------------------------

/// What a site answered, one line per call, in the words every backend
/// must agree on. A store without columns (`Caps::columns`) is checked to
/// answer none (every field `None`); with `mask` the columns lines are
/// written as `(masked)` instead of what was answered, so that a site
/// with columns and one without compare equal everywhere else.
struct Transcript {
    site: &'static str,
    mask: bool,
    lines: Vec<String>,
}

impl Transcript {
    fn say(&mut self, line: impl Into<String>) {
        let line = line.into();
        eprintln!("[{}] {line}", self.site);
        self.lines.push(line);
    }

    /// The columns of `envs` as `label`.
    fn columns(&mut self, label: &str, s: &dyn AttestationStore, envs: &[&StoredEnvelope]) {
        let got = s.columns(envs).unwrap();
        assert_eq!(got.len(), envs.len(), "{}: one answer per entry", self.site);
        if !s.caps().columns {
            assert!(
                got.iter().all(|c| *c == Columns::default()),
                "{}: a store without columns answers none: {got:?}",
                self.site
            );
        }
        let shown: Vec<String> = got
            .iter()
            .map(|c| {
                if self.mask {
                    "(masked)".to_owned()
                } else {
                    format!("{c:?}")
                }
            })
            .collect();
        self.say(format!("columns {label}: {}", shown.join(" | ")));
    }
}

fn keys(v: &[StoredEnvelope]) -> String {
    v.iter()
        .map(|e| e.key.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

fn sorted(mut v: Vec<String>) -> String {
    v.sort();
    v.join(" ")
}

/// A value as read: its BLAKE3, or why it could not be read.
fn value(e: &StoredEnvelope) -> String {
    match e.state() {
        ValueState::Read(b) => format!("read {}", vci_core::blake3_hex(b)),
        ValueState::Unreadable(why) => format!("unreadable {why}"),
        ValueState::Unread => "unread".to_owned(),
        ValueState::NotFetched => "not fetched".to_owned(),
    }
}

/// What a value decodes as.
fn record_kind(bytes: &[u8]) -> String {
    match decode_record(bytes) {
        Ok(Record::FormatOne(_)) => "envelope".to_owned(),
        Ok(Record::FormatThree(frame)) => {
            let shape = vci_core::Descriptor::shape_id(&frame.descriptor).expect("a shape id");
            format!(
                "frame shape={} keyid={}",
                vci_core::objects::hex32(&shape),
                frame.keyid
            )
        }
        Err(e) => format!("neither: {e}"),
    }
}

/// These units read, prefetched first on a lazy store.
fn read_units(s: &dyn AttestationStore, units: &[&str]) -> Vec<Vec<StoredEnvelope>> {
    if s.caps().lazy_values {
        s.prefetch(Prefetch::Units {
            test_ids: units,
            choose: None,
        })
        .unwrap();
    }
    s.read_units(units).unwrap()
}

/// These objects, prefetched first on a lazy store.
fn get_objects(s: &dyn AttestationStore, ids: &[&str]) -> Vec<StoredObject> {
    if s.caps().lazy_values {
        s.prefetch(Prefetch::Objects { ids }).unwrap();
    }
    s.get_objects(ids).unwrap()
}

/// The objects among `ids`, each checked to be filed under the BLAKE3 of
/// its bytes, as `id kind bytes`.
fn objects(s: &dyn AttestationStore, ids: &[&str]) -> String {
    get_objects(s, ids)
        .iter()
        .map(|o| {
            assert_eq!(
                o.id,
                vci_core::objects::hex32(&vci_core::object_id(&o.bytes)),
                "filed under the BLAKE3 of its bytes"
            );
            format!("{} {} {}", o.id, o.kind, vci_core::blake3_hex(&o.bytes))
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Everything a reader can observe, as `label`: the listings and values
/// of the units, what each value decodes as and names, the columns, the
/// count, the manifests, the objects among `ids`, and what the orphan
/// scans would collect.
fn snapshot(t: &mut Transcript, site: &Site, label: &str, ids: &[&str], roots: &[&str]) {
    let r = site.reader();
    let s = &*r;
    let units = [UNIT_A, UNIT_B, UNIT_NONE];
    let listed = s.list_units(&units).unwrap();
    for (u, l) in units.iter().zip(&listed) {
        t.say(format!("{label} list {u}: {}", keys(l)));
    }
    let read = read_units(s, &units);
    for (u, l) in units.iter().zip(&read) {
        for e in l {
            t.say(format!("{label} value {u} {}: {}", e.key, value(e)));
            if let ValueState::Read(b) = e.state() {
                t.say(format!(
                    "{label} record {}: {}; manifest {:?}; objects {:?}",
                    e.key,
                    record_kind(b),
                    e.manifest_ref(),
                    key::record_object_refs(b)
                ));
            }
        }
    }
    let all: Vec<&StoredEnvelope> = listed.iter().flatten().collect();
    t.columns(label, s, &all);
    t.say(format!("{label} count: {}", s.count().unwrap()));
    t.say(format!(
        "{label} list_all: {}",
        sorted(s.list_all().unwrap().into_iter().map(|e| e.key).collect())
    ));
    t.say(format!(
        "{label} manifest_roots: {}",
        sorted(s.manifest_roots().unwrap())
    ));
    for root in roots {
        let m = s.manifest(root).unwrap();
        t.say(format!(
            "{label} manifest {root}: {}",
            m.map_or("none".to_owned(), |m| format!(
                "{} {:?}",
                vci_core::blake3_hex(&m.bytes),
                m.error
            ))
        ));
    }
    t.say(format!("{label} objects: {}", objects(s, ids)));
    t.say(format!(
        "{label} orphan_manifests: {}",
        sorted(s.orphan_manifests(roots).unwrap())
    ));
    t.say(format!(
        "{label} orphan_objects: {}",
        s.orphan_objects().unwrap().join(" ")
    ));
}

/// The script's fixtures: three runs and two manifests.
struct Fixtures {
    a: Run3,
    b: Run3,
    c: Run3,
    one: vci_core::InputManifest,
    free: vci_core::InputManifest,
}

impl Fixtures {
    fn new() -> Fixtures {
        Fixtures {
            a: Run3::build(&["src/parity/a.ts", "src/parity/b.ts"]),
            b: Run3::build(&["src/parity/other.ts"]),
            c: Run3::build(&["src/parity/c.ts"]),
            one: manifest_of(&["src/parity/one.rs"]),
            free: manifest_of(&["src/parity/free.rs"]),
        }
    }

    /// Every object id the script ever stores, sorted and distinct: the
    /// three runs share their hdr and their tables (the same header and
    /// the same env names), so a's four, b's shape and c's four are seven.
    fn ids(&self) -> Vec<&str> {
        let mut v = self.a.id_refs();
        v.push(&self.b.ids.shape);
        v.extend(self.c.id_refs());
        v.sort_unstable();
        v.dedup();
        v
    }

    fn roots(&self) -> [String; 2] {
        [self.one.root(), self.free.root()]
    }
}

fn put(s: &dyn AttestationStore, att: NewAttestation<'_>) -> StoredEnvelope {
    s.put(&att).unwrap()
}

/// The script on `site`: what every backend must answer alike.
fn script(site: &Site, fx: &Fixtures) -> Transcript {
    let w = &*site.writer;
    let mut t = Transcript {
        site: site.name,
        mask: !w.caps().columns,
        lines: Vec::new(),
    };
    let ids = fx.ids();
    let roots = fx.roots();
    let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
    let root_one = roots[0];
    eprintln!(
        "[{}] objects {} columns {}",
        site.name,
        w.caps().objects,
        w.caps().columns
    );

    // 1. Manifests, objects, then two format-1 envelopes and two format-3
    // frames of the same two units.
    for m in [&fx.one, &fx.free] {
        t.say(format!(
            "put_manifest {}: {}",
            m.root(),
            w.put_manifest(&m.root(), m.to_compact().as_bytes())
                .unwrap()
        ));
    }
    t.say(format!(
        "put_objects a: {}",
        w.put_objects(&fx.a.new_objects()).unwrap()
    ));
    t.say(format!(
        "put_objects a again: {}",
        w.put_objects(&fx.a.new_objects()).unwrap()
    ));
    let b_shape = fx.b.new_objects()[2];
    t.say(format!(
        "put_objects b.shape: {}",
        w.put_objects(&[b_shape]).unwrap()
    ));
    let env_one = envelope(Some(root_one), "one");
    let env_inline = envelope(None, "inline");
    let (rec_a, cols_a) = fx.a.record(UNIT_A, 2, 11);
    let (rec_b, cols_b) = fx.a.record(UNIT_B, 1, 12);
    let (h1, h2, h3, h4) = (hint(1), hint(2), hint(3), hint(4));
    let e1 = put(
        w,
        NewAttestation::for_test(UNIT_A, S1, &hex64(1), Some(&h1), &env_one),
    );
    let e3 = put(
        w,
        NewAttestation::for_test(UNIT_A, S1, &hex64(3), Some(&h3), &rec_a).with_columns(&cols_a),
    );
    let eb = put(
        w,
        NewAttestation::for_test(UNIT_B, S2, &hex64(4), Some(&h4), &rec_b).with_columns(&cols_b),
    );
    let e2 = put(
        w,
        NewAttestation::for_test(UNIT_B, S1, &hex64(2), Some(&h2), &env_inline),
    );
    t.say(format!("put: {} {} {} {}", e1.key, e3.key, eb.key, e2.key));
    let mut asked: Vec<&str> = ids.clone();
    asked.push(ids[0]);
    let unknown = hex64(0xee);
    asked.push(&unknown);
    snapshot(&mut t, site, "1", &asked, &roots);
    t.say(format!(
        "remove_objects within the grace: {}",
        w.remove_objects(&ids).unwrap()
    ));

    // 2. A batch: a third run's objects and a record of it, and the first
    // envelope's removal. Counts inside a deferred batch may differ, so
    // only what is visible after the finish is recorded.
    let (rec_c, cols_c) = fx.c.record(UNIT_A, 1, 13);
    let h5 = hint(5);
    let batch = w.batch().unwrap();
    w.put_objects(&fx.c.new_objects()).unwrap();
    let ec = put(
        w,
        NewAttestation::for_test(UNIT_A, S1, &hex64(5), Some(&h5), &rec_c).with_columns(&cols_c),
    );
    w.remove(vec![e1.clone()]).unwrap();
    batch.finish().unwrap();
    t.say(format!("batch put: {}", ec.key));
    snapshot(&mut t, site, "2", &asked, &roots);

    // 3. Past the grace, only b's shape is an orphan; a's state object
    // expires at two days while a's records still name it; without a's
    // two records, its shape is an orphan (c's record still names the hdr
    // and the tables the runs share), and both manifests are orphans.
    site.age(&ids, OBJECT_GRACE * 2);
    t.say(format!(
        "orphan_objects past the grace: {}",
        w.orphan_objects().unwrap().join(" ")
    ));
    t.say(format!(
        "remove_objects past the grace: {}",
        w.remove_objects(&ids).unwrap()
    ));
    t.say(format!(
        "prune_state_objects young: {}",
        w.prune_state_objects(TWO_DAYS).unwrap()
    ));
    site.age(&[&fx.a.ids.state], THREE_DAYS);
    t.say(format!(
        "prune_state_objects aged: {}",
        w.prune_state_objects(TWO_DAYS).unwrap()
    ));
    t.say(format!(
        "remove e3 and eb: {}",
        sorted(
            w.remove(vec![e3.clone(), eb.clone()])
                .unwrap()
                .into_iter()
                .map(|e| e.key)
                .collect()
        )
    ));
    t.say(format!(
        "orphan_objects without a's records: {}",
        w.orphan_objects().unwrap().join(" ")
    ));
    t.say(format!(
        "remove_objects a: {}",
        w.remove_objects(&fx.a.id_refs()).unwrap()
    ));
    // `remove_manifests` is not in the script: a shared store keeps an
    // unreferenced manifest for an hour after its put (c29), a local one
    // removes it at once; `orphan_manifests` names both roots everywhere.
    snapshot(&mut t, site, "3", &asked, &roots);
    t
}

/// A columns line as a masked transcript writes it: one `(masked)` per
/// entry.
fn masked(line: &str) -> String {
    let (head, rest) = line.split_once(": ").expect("a columns line");
    let n = if rest.is_empty() {
        0
    } else {
        rest.matches(" | ").count() + 1
    };
    format!("{head}: {}", vec!["(masked)"; n].join(" | "))
}

/// `reference` and `other` line by line, naming the first difference; the
/// reference's columns lines are read masked when `other` is.
fn assert_same(reference: &Transcript, other: &Transcript) {
    for (i, (w, g)) in reference.lines.iter().zip(&other.lines).enumerate() {
        let w = if other.mask && !reference.mask && w.starts_with("columns ") {
            masked(w)
        } else {
            w.clone()
        };
        assert_eq!(
            *g, w,
            "line {i} of {} differs from {}'s",
            other.site, reference.site
        );
    }
    assert_eq!(
        other.lines.len(),
        reference.lines.len(),
        "{} answered a different number of calls than {}",
        other.site,
        reference.site
    );
}

/// The same script on every backend gives the same transcript.
#[test]
fn every_backend_answers_the_same_script_alike() {
    let fx = Fixtures::new();
    let sites = Site::all();
    let transcripts: Vec<Transcript> = sites.iter().map(|s| script(s, &fx)).collect();
    let reference = &transcripts[0];
    assert_eq!(reference.site, "sqlite");
    assert!(
        !reference.mask,
        "the reference keeps columns, so that the masked sites are checked against real ones"
    );
    for t in &transcripts[1..] {
        assert_same(reference, t);
    }
    // What the script must have ended with, so that a bug every backend
    // shares is not parity.
    let text = reference.lines.join("\n");
    for want in [
        "put_objects a: 4",
        "put_objects a again: 0",
        "put_objects b.shape: 1",
        "remove_objects within the grace: 0",
        &format!("orphan_objects past the grace: {}", fx.b.ids.shape),
        "remove_objects past the grace: 1",
        "prune_state_objects young: 0",
        "prune_state_objects aged: 1",
        &format!("orphan_objects without a's records: {}", fx.a.ids.shape),
        "remove_objects a: 1",
        "3 count: 2",
    ] {
        assert!(
            text.contains(want),
            "{want:?} not in the transcript:\n{text}"
        );
    }
    assert_eq!(fx.a.ids.hdr, fx.c.ids.hdr, "the runs share a header");
    assert!(
        text.contains("2 record") && text.contains("frame shape=") && text.contains(": envelope;"),
        "mixed formats were read: {text}"
    );
}

/// Copy everything the SQLite store holds after the script into a fresh
/// store of each other kind, manifests and objects before records, each
/// record with its columns: the copy answers as the source does.
#[test]
fn a_copy_through_the_trait_keeps_values_objects_and_columns() {
    let fx = Fixtures::new();
    let src = Site::sqlite();
    script(&src, &fx);
    let ids = fx.ids();
    let roots = fx.roots();
    let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
    let mut want = Transcript {
        site: src.name,
        mask: false,
        lines: Vec::new(),
    };
    snapshot(&mut want, &src, "copy", &ids, &roots);
    let r = src.reader();
    let source: Vec<StoredEnvelope> = {
        if r.caps().lazy_values {
            r.prefetch(Prefetch::Attestations).unwrap();
        }
        r.read_all().unwrap()
    };
    let refs: Vec<&StoredEnvelope> = source.iter().collect();
    let columns = r.columns(&refs).unwrap();
    let objects = get_objects(&*r, &ids);
    let manifests: Vec<(String, Vec<u8>)> = r
        .manifest_roots()
        .unwrap()
        .into_iter()
        .map(|root| {
            let m = r.manifest(&root).unwrap().expect("a listed manifest");
            assert_eq!(m.error, None, "{root} read");
            (root, m.bytes)
        })
        .collect();

    for dst in Site::all().into_iter().filter(|s| s.name != "sqlite") {
        let w = &*dst.writer;
        for (root, bytes) in &manifests {
            w.put_manifest(root, bytes).unwrap();
        }
        let new: Vec<NewObject<'_>> = objects
            .iter()
            .map(|o| NewObject::new(o.kind, &o.bytes))
            .collect();
        assert_eq!(w.put_objects(&new).unwrap(), new.len(), "{}", dst.name);
        for (e, c) in source.iter().zip(&columns) {
            assert!(matches!(e.state(), ValueState::Read(_)));
            let h = key::parse_key_hint(&e.key);
            w.put(&NewAttestation::copy_of(e, h.as_ref()).with_columns(c))
                .unwrap();
        }
        let mut got = Transcript {
            site: dst.name,
            mask: !w.caps().columns,
            lines: Vec::new(),
        };
        snapshot(&mut got, &dst, "copy", &ids, &roots);
        assert_same(&want, &got);
    }
}
