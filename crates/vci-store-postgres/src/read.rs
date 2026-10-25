//! Reads (`docs/STORE-BACKENDS.md` section 17, "Reads and the per-handle
//! cache"). Each read is served from the cache when it can be; a miss is
//! one statement for any number of units, keys or roots. A missing schema
//! reads as an empty store.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use postgres::Row;
use postgres::types::Type;
use vci_store::timing::Step;
use vci_store::{
    Choose, GONE, Hydration, Prefetch, StoreError, StoreStatus, StoredEnvelope, StoredManifest, key,
};

use crate::Inner;
use crate::cache::{Listed, Manifest, Value};
use crate::conn::{Fail, KIND, READ};
use crate::schema::{self, State};

/// Keys, test keys or roots per statement.
const CHUNK: usize = 5_000;

/// The read statements of one schema.
pub(crate) struct Sql {
    list_units: String,
    list_all: String,
    values: String,
    read_units: String,
    read_all: String,
    keys: String,
    manifest: String,
    manifests: String,
    manifests_and_bases: String,
    manifest_roots: String,
    orphans: String,
    memo: String,
    flags: String,
}

impl Sql {
    pub(crate) fn new(s: &str) -> Sql {
        let a = format!("\"{s}\".attestations");
        let m = format!("\"{s}\".manifests");
        Sql {
            list_units: format!(
                "SELECT test_key, key, target FROM {a} WHERE ns = $1 AND test_key = ANY($2) \
                 ORDER BY test_key, key"
            ),
            list_all: format!("SELECT target, key FROM {a} WHERE ns = $1 ORDER BY target, key"),
            values: format!(
                "SELECT key, value, encoding, manifest_ref FROM {a} WHERE ns = $1 AND key = ANY($2)"
            ),
            read_units: format!(
                "SELECT test_key, key, target, value, encoding FROM {a} \
                 WHERE ns = $1 AND test_key = ANY($2) ORDER BY test_key, key"
            ),
            read_all: format!(
                "SELECT target, key, value, encoding FROM {a} WHERE ns = $1 ORDER BY target, key"
            ),
            keys: format!("SELECT key FROM {a} WHERE ns = $1"),
            manifest: format!("SELECT value, encoding FROM {m} WHERE ns = $1 AND root = $2"),
            manifests: format!(
                "SELECT root, value, encoding FROM {m} WHERE ns = $1 AND root = ANY($2)"
            ),
            manifests_and_bases: format!(
                "SELECT root, base, value, encoding FROM {m} WHERE ns = $1 AND (root = ANY($2) \
                 OR root IN (SELECT base FROM {m} WHERE ns = $1 AND root = ANY($2) AND base IS NOT NULL))"
            ),
            manifest_roots: format!("SELECT root FROM {m} WHERE ns = $1 ORDER BY root"),
            orphans: format!(
                "SELECT r FROM unnest($2::text[]) AS u(r) \
                 WHERE NOT EXISTS (SELECT 1 FROM {a} WHERE ns = $1 AND ref_state = 0) \
                 AND NOT EXISTS (SELECT 1 FROM {a} x WHERE x.ns = $1 AND x.manifest_ref = u.r)"
            ),
            memo: format!("SELECT test_key, key FROM \"{s}\".memo WHERE ns = $1 AND tree16 = $2"),
            flags: format!("SELECT name FROM \"{s}\".flags WHERE ns = $1"),
        }
    }
}

/// A value as stored: its bytes when its encoding is raw, else why not.
fn value_of(row: &Row, value: usize, encoding: usize) -> Result<Value, postgres::Error> {
    let enc: i16 = row.try_get(encoding)?;
    Ok(if enc == 0 {
        Value::Bytes(row.try_get(value)?)
    } else {
        Value::Unreadable(format!(
            "the postgres store holds this value in an encoding this vci cannot read ({enc})"
        ))
    })
}

fn manifest_of(row: &Row, value: usize, encoding: usize) -> Result<Manifest, postgres::Error> {
    Ok(match value_of(row, value, encoding)? {
        Value::Bytes(b) => Manifest::Bytes(b),
        Value::Unreadable(why) => Manifest::Unreadable(why),
    })
}

/// A listed row, when its key has vci's shape and names its unit.
fn listed(test_key: &str, key: String, target: String) -> Option<Listed> {
    match key::parse_key(&key) {
        Some((tk, _, _)) if tk == test_key => Some(Listed { key, target }),
        _ => None,
    }
}

// ---- identity ----------------------------------------------------------------------

pub(crate) fn status(inner: &Inner) -> Result<StoreStatus, StoreError> {
    inner.conn.check()?;
    inner.ns()?;
    match schema::check(inner)? {
        State::Absent => Ok(StoreStatus::Absent {
            advice: schema::advice(&inner.schema),
        }),
        State::Version(v) => Ok(StoreStatus::Ready {
            schema_version: Some(v),
        }),
    }
}

// ---- listings ------------------------------------------------------------------------

/// The listings of these test keys from the server, by test key (one
/// statement per [`CHUNK`]).
fn query_listings(
    inner: &Inner,
    ns: &str,
    test_keys: &[&str],
) -> Result<HashMap<String, Vec<Listed>>, StoreError> {
    let mut out: HashMap<String, Vec<Listed>> = HashMap::new();
    let mut step = Step::start(KIND);
    for chunk in test_keys.chunks(CHUNK) {
        let r = inner.conn.run(READ, |db| {
            db.query(
                &inner.read_sql.list_units,
                &[(&ns, Type::TEXT), (&chunk, Type::TEXT_ARRAY)],
            )
        });
        for row in Fail::or_absent(r, Vec::new)? {
            let tk: String = row.try_get(0).map_err(|e| inner.decode_error(&e))?;
            let k: String = row.try_get(1).map_err(|e| inner.decode_error(&e))?;
            let t: String = row.try_get(2).map_err(|e| inner.decode_error(&e))?;
            if let Some(l) = listed(&tk, k, t) {
                out.entry(tk).or_default().push(l);
            }
        }
    }
    step.lap(format_args!("list {} unit(s)", test_keys.len()));
    Ok(out)
}

fn entries(listed: &[Listed]) -> Vec<StoredEnvelope> {
    listed
        .iter()
        .filter_map(|l| StoredEnvelope::from_key(l.target.clone(), &l.key))
        .collect()
}

pub(crate) fn list_units(
    inner: &Inner,
    test_ids: &[&str],
) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
    let tks: Vec<String> = test_ids.iter().map(|id| key::test_key(id)).collect();
    let mut found: HashMap<String, Vec<StoredEnvelope>> = HashMap::new();
    let mut missing: BTreeSet<&str> = BTreeSet::new();
    {
        let c = inner.cache();
        for tk in &tks {
            if found.contains_key(tk) || missing.contains(tk.as_str()) {
                continue;
            }
            match c.listing(tk) {
                Some(l) => {
                    found.insert(tk.clone(), l);
                }
                None => {
                    missing.insert(tk);
                }
            }
        }
    }
    if !missing.is_empty() {
        let ns = inner.ready()?;
        let missing: Vec<&str> = missing.into_iter().collect();
        let mut listed = query_listings(inner, ns, &missing)?;
        for tk in missing {
            let l = listed.remove(tk).unwrap_or_default();
            found.insert(tk.to_owned(), entries(&l));
        }
    }
    Ok(tks
        .iter()
        .map(|tk| found.get(tk).cloned().unwrap_or_default())
        .collect())
}

pub(crate) fn list_all(inner: &Inner) -> Result<Vec<StoredEnvelope>, StoreError> {
    let ns = inner.ready()?;
    let r = inner.conn.run(READ, |db| {
        db.query(&inner.read_sql.list_all, &[(&ns, Type::TEXT)])
    });
    let mut out = Vec::new();
    for row in Fail::or_absent(r, Vec::new)? {
        let t: String = row.try_get(0).map_err(|e| inner.decode_error(&e))?;
        let k: String = row.try_get(1).map_err(|e| inner.decode_error(&e))?;
        if let Some(e) = StoredEnvelope::from_key(t, &k) {
            out.push(e);
        }
    }
    Ok(out)
}

pub(crate) fn count(inner: &Inner) -> Result<usize, StoreError> {
    let ns = inner.ready()?;
    let mut n = 0;
    let r = inner.conn.run(READ, |db| {
        n = 0;
        db.for_each(&inner.read_sql.keys, &[(&ns, Type::TEXT)], |row| {
            let k: String = row.try_get(0)?;
            if key::parse_key(&k).is_some() {
                n += 1;
            }
            Ok(())
        })
    });
    Fail::or_absent(r, || ())?;
    Ok(n)
}

// ---- values ----------------------------------------------------------------------------

/// The values of these keys from the server, with the manifest each
/// references (keys the store does not hold are left out).
fn query_values(
    inner: &Inner,
    ns: &str,
    keys: &[&str],
) -> Result<HashMap<String, (Value, Option<String>)>, StoreError> {
    let mut out = HashMap::new();
    for chunk in keys.chunks(CHUNK) {
        let r = inner.conn.run(READ, |db| {
            db.query(
                &inner.read_sql.values,
                &[(&ns, Type::TEXT), (&chunk, Type::TEXT_ARRAY)],
            )
        });
        for row in Fail::or_absent(r, Vec::new)? {
            let k: String = row.try_get(0).map_err(|e| inner.decode_error(&e))?;
            let v = value_of(&row, 1, 2).map_err(|e| inner.decode_error(&e))?;
            let r: Option<String> = row.try_get(3).map_err(|e| inner.decode_error(&e))?;
            out.insert(k, (v, r));
        }
    }
    Ok(out)
}

pub(crate) fn read_values(
    inner: &Inner,
    envs: &mut [&mut StoredEnvelope],
) -> Result<(), StoreError> {
    let mut misses: Vec<usize> = Vec::new();
    {
        let mut c = inner.cache();
        for (i, e) in envs.iter_mut().enumerate() {
            match c.take_value(&e.key) {
                Some(v) => v.apply(e),
                None => misses.push(i),
            }
        }
    }
    if misses.is_empty() {
        return Ok(());
    }
    let ns = inner.ready()?;
    let step = Step::start(KIND);
    let keys: BTreeSet<String> = misses.iter().map(|&i| envs[i].key.clone()).collect();
    let n = keys.len();
    let read = {
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        query_values(inner, ns, &keys)?
    };
    let mut refs: BTreeSet<String> = BTreeSet::new();
    for &i in &misses {
        match read.get(&envs[i].key) {
            Some((v, r)) => {
                v.clone().apply(envs[i]);
                if let Some(r) = r {
                    refs.insert(r.clone());
                }
            }
            None => envs[i].set_error(GONE),
        }
    }
    step.done(format_args!("read {n} value(s)"));
    // Whoever reads a value verifies it next, which reads the manifest it
    // references and that manifest's base: bring them in the same way a
    // prefetch would (best effort).
    let refs: Vec<String> = {
        let c = inner.cache();
        refs.into_iter().filter(|r| !c.has_manifest(r)).collect()
    };
    if !refs.is_empty() {
        let _ = fetch_manifests(inner, ns, &refs);
    }
    Ok(())
}

pub(crate) fn read_units(
    inner: &Inner,
    test_ids: &[&str],
) -> Result<Vec<Vec<StoredEnvelope>>, StoreError> {
    let tks: Vec<String> = test_ids.iter().map(|id| key::test_key(id)).collect();
    let mut found: HashMap<String, Vec<StoredEnvelope>> = HashMap::new();
    let mut missing: BTreeSet<&str> = BTreeSet::new();
    {
        // A unit whose listing and every value are cached is answered from
        // the cache, values left there: `vci run` reads its units twice
        // (last durations, then supersession from worker threads).
        let c = inner.cache();
        for tk in &tks {
            if found.contains_key(tk) || missing.contains(tk.as_str()) {
                continue;
            }
            let cached = c.listing(tk).and_then(|mut l| {
                for e in l.iter_mut() {
                    c.value(&e.key)?.clone().apply(e);
                }
                Some(l)
            });
            match cached {
                Some(l) => {
                    found.insert(tk.clone(), l);
                }
                None => {
                    missing.insert(tk);
                }
            }
        }
    }
    if !missing.is_empty() {
        let ns = inner.ready()?;
        let missing: Vec<&str> = missing.into_iter().collect();
        for chunk in missing.chunks(CHUNK) {
            let r = inner.conn.run(READ, |db| {
                db.query(
                    &inner.read_sql.read_units,
                    &[(&ns, Type::TEXT), (&chunk, Type::TEXT_ARRAY)],
                )
            });
            for row in Fail::or_absent(r, Vec::new)? {
                let tk: String = row.try_get(0).map_err(|e| inner.decode_error(&e))?;
                let k: String = row.try_get(1).map_err(|e| inner.decode_error(&e))?;
                let t: String = row.try_get(2).map_err(|e| inner.decode_error(&e))?;
                let v = value_of(&row, 3, 4).map_err(|e| inner.decode_error(&e))?;
                let Some(l) = listed(&tk, k, t) else {
                    continue;
                };
                if let Some(mut e) = StoredEnvelope::from_key(l.target, &l.key) {
                    v.apply(&mut e);
                    found.entry(tk).or_default().push(e);
                }
            }
            for tk in chunk {
                found.entry((*tk).to_owned()).or_default();
            }
        }
    }
    Ok(tks
        .iter()
        .map(|tk| found.get(tk).cloned().unwrap_or_default())
        .collect())
}

pub(crate) fn read_all(inner: &Inner) -> Result<Vec<StoredEnvelope>, StoreError> {
    let ns = inner.ready()?;
    let mut out = Vec::new();
    let r = inner.conn.run(READ, |db| {
        out.clear();
        db.for_each(&inner.read_sql.read_all, &[(&ns, Type::TEXT)], |row| {
            let t: String = row.try_get(0)?;
            let k: String = row.try_get(1)?;
            if let Some(mut e) = StoredEnvelope::from_key(t, &k) {
                value_of(&row, 2, 3)?.apply(&mut e);
                out.push(e);
            }
            Ok(())
        })
    });
    Fail::or_absent(r, || ())?;
    Ok(out)
}

// ---- manifests ---------------------------------------------------------------------------

pub(crate) fn manifest(inner: &Inner, root: &str) -> Result<Option<StoredManifest>, StoreError> {
    if !key::is_hex_id(root) {
        return Ok(None);
    }
    if let Some(m) = inner.cache().manifest(root) {
        return Ok(m);
    }
    let ns = inner.ready()?;
    let r = inner.conn.run(READ, |db| {
        db.query(
            &inner.read_sql.manifest,
            &[(&ns, Type::TEXT), (&root, Type::TEXT)],
        )
    });
    let rows = Fail::or_absent(r, Vec::new)?;
    match rows.first() {
        None => Ok(None),
        Some(row) => Ok(manifest_of(row, 0, 1)
            .map_err(|e| inner.decode_error(&e))?
            .to_stored(root)),
    }
}

pub(crate) fn manifests(
    inner: &Inner,
    roots: &[&str],
) -> Result<Vec<Option<StoredManifest>>, StoreError> {
    let mut found: HashMap<String, Option<StoredManifest>> = HashMap::new();
    let mut missing: BTreeSet<&str> = BTreeSet::new();
    {
        let c = inner.cache();
        for r in roots.iter().copied().filter(|r| key::is_hex_id(r)) {
            match c.manifest(r) {
                Some(m) => {
                    found.insert(r.to_owned(), m);
                }
                None => {
                    missing.insert(r);
                }
            }
        }
    }
    if !missing.is_empty() {
        let ns = inner.ready()?;
        let missing: Vec<&str> = missing.into_iter().collect();
        for chunk in missing.chunks(CHUNK) {
            let r = inner.conn.run(READ, |db| {
                db.query(
                    &inner.read_sql.manifests,
                    &[(&ns, Type::TEXT), (&chunk, Type::TEXT_ARRAY)],
                )
            });
            for row in Fail::or_absent(r, Vec::new)? {
                let root: String = row.try_get(0).map_err(|e| inner.decode_error(&e))?;
                let m = manifest_of(&row, 1, 2).map_err(|e| inner.decode_error(&e))?;
                let stored = m.to_stored(&root);
                found.insert(root, stored);
            }
        }
    }
    Ok(roots
        .iter()
        .map(|r| found.get(*r).cloned().flatten())
        .collect())
}

/// Read these manifests and their bases in one statement into the cache;
/// the ones not stored are cached as absent.
fn fetch_manifests(inner: &Inner, ns: &str, roots: &[String]) -> Result<(), StoreError> {
    for chunk in roots.chunks(CHUNK) {
        let r = inner.conn.run(READ, |db| {
            db.query(
                &inner.read_sql.manifests_and_bases,
                &[(&ns, Type::TEXT), (&chunk, Type::TEXT_ARRAY)],
            )
        });
        let rows = Fail::or_absent(r, Vec::new)?;
        let mut got: BTreeMap<String, Manifest> = BTreeMap::new();
        let mut bases: BTreeSet<String> = BTreeSet::new();
        for row in rows {
            let root: String = row.try_get(0).map_err(|e| inner.decode_error(&e))?;
            let base: Option<String> = row.try_get(1).map_err(|e| inner.decode_error(&e))?;
            let m = manifest_of(&row, 2, 3).map_err(|e| inner.decode_error(&e))?;
            if let Some(b) = base {
                bases.insert(b);
            }
            got.insert(root, m);
        }
        let mut c = inner.cache();
        for r in chunk.iter().chain(bases.iter()) {
            if !got.contains_key(r) {
                c.set_manifest(r.clone(), Manifest::Absent);
            }
        }
        for (root, m) in got {
            c.set_manifest(root, m);
        }
    }
    Ok(())
}

pub(crate) fn manifest_roots(inner: &Inner) -> Result<Vec<String>, StoreError> {
    let ns = inner.ready()?;
    let r = inner.conn.run(READ, |db| {
        db.query(&inner.read_sql.manifest_roots, &[(&ns, Type::TEXT)])
    });
    let mut out = Vec::new();
    for row in Fail::or_absent(r, Vec::new)? {
        let root: String = row.try_get(0).map_err(|e| inner.decode_error(&e))?;
        if key::is_hex_id(&root) {
            out.push(root);
        }
    }
    Ok(out)
}

pub(crate) fn orphan_manifests(inner: &Inner, roots: &[&str]) -> Result<Vec<String>, StoreError> {
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let ns = inner.ready()?;
    let wanted: BTreeSet<&str> = roots.iter().copied().collect();
    let wanted: Vec<&str> = wanted.into_iter().collect();
    let r = inner.conn.run(READ, |db| {
        db.query(
            &inner.read_sql.orphans,
            &[(&ns, Type::TEXT), (&wanted, Type::TEXT_ARRAY)],
        )
    });
    let rows = match r {
        Ok(rows) => rows,
        // No schema: nothing references anything.
        Err(Fail::Absent) => return Ok(wanted.into_iter().map(str::to_owned).collect()),
        Err(Fail::Store(e)) => return Err(e),
    };
    let mut out: BTreeSet<String> = BTreeSet::new();
    for row in rows {
        out.insert(row.try_get(0).map_err(|e| inner.decode_error(&e))?);
    }
    Ok(out.into_iter().collect())
}

// ---- prefetch -----------------------------------------------------------------------------

pub(crate) fn prefetch(inner: &Inner, what: Prefetch<'_>) -> Result<Hydration, StoreError> {
    match what {
        Prefetch::Units { test_ids, choose } => prefetch_units(inner, test_ids, choose),
        Prefetch::Manifests { roots } => {
            let ns = inner.ready()?;
            let want: Vec<String> = {
                let c = inner.cache();
                let set: BTreeSet<&str> = roots
                    .iter()
                    .copied()
                    .filter(|r| key::is_hex_id(r) && !c.has_stored_manifest(r))
                    .collect();
                set.into_iter().map(str::to_owned).collect()
            };
            if !want.is_empty() {
                let step = Step::start(KIND);
                let n0 = inner.conn.statements();
                fetch_manifests(inner, ns, &want)?;
                step.done(format_args!(
                    "prefetch {} manifest(s), {} statement(s)",
                    want.len(),
                    inner.conn.statements() - n0
                ));
            }
            Ok(Hydration::default())
        }
        // Values are read with the listing that needs them (`read_all`).
        _ => Ok(Hydration::default()),
    }
}

/// The listings of these units (always read again), the values `choose`
/// picks (all without it) that are not cached, and the manifests those
/// values reference with their bases: at most three statements, whatever
/// the number of units.
fn prefetch_units(
    inner: &Inner,
    test_ids: &[&str],
    choose: Option<Choose<'_>>,
) -> Result<Hydration, StoreError> {
    if test_ids.is_empty() {
        return Ok(Hydration::default());
    }
    let ns = inner.ready()?;
    let step = Step::start(KIND);
    let n0 = inner.conn.statements();
    let mut tks: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for id in test_ids {
        let tk = key::test_key(id);
        if seen.insert(tk.clone()) {
            tks.push(tk);
        }
    }
    // 1. The listings, from the server even when cached: a prefetch is
    // where other writers' changes are picked up. A cached value stays
    // valid while its key is listed (a value never changes under its key
    // but to repair an unreadable row); one whose key went is dropped.
    let mut listings: HashMap<String, Vec<StoredEnvelope>> = HashMap::new();
    {
        let all: Vec<&str> = tks.iter().map(String::as_str).collect();
        let mut listed = query_listings(inner, ns, &all)?;
        let mut c = inner.cache();
        for tk in &tks {
            let l = listed.remove(tk.as_str()).unwrap_or_default();
            listings.insert(tk.clone(), entries(&l));
            c.refresh_listing(tk.clone(), l);
        }
    }
    // 2. The values chosen (here, with no lock held), not cached yet.
    let mut want: BTreeSet<String> = BTreeSet::new();
    for tk in &tks {
        let Some(l) = listings.get(tk) else {
            continue;
        };
        let picked: Vec<usize> = match choose {
            Some(f) => f(l),
            None => (0..l.len()).collect(),
        };
        for i in picked {
            if let Some(e) = l.get(i) {
                want.insert(e.key.clone());
            }
        }
    }
    let want: Vec<&str> = {
        let c = inner.cache();
        want.iter()
            .map(String::as_str)
            .filter(|k| !c.has_value(k))
            .collect()
    };
    let mut refs: BTreeSet<String> = BTreeSet::new();
    if !want.is_empty() {
        let mut read = query_values(inner, ns, &want)?;
        let mut c = inner.cache();
        for k in &want {
            match read.remove(*k) {
                Some((v, r)) => {
                    if let Some(r) = r {
                        refs.insert(r);
                    }
                    c.set_value((*k).to_owned(), v);
                }
                None => c.set_value((*k).to_owned(), Value::Unreadable(GONE.to_owned())),
            }
        }
    }
    // 3. Their manifests and bases, not cached as stored yet.
    let refs: Vec<String> = {
        let c = inner.cache();
        refs.into_iter()
            .filter(|r| !c.has_stored_manifest(r))
            .collect()
    };
    if !refs.is_empty() {
        fetch_manifests(inner, ns, &refs)?;
    }
    step.done(format_args!(
        "prefetch {} unit(s), {} value(s), {} statement(s)",
        tks.len(),
        want.len(),
        inner.conn.statements() - n0
    ));
    Ok(Hydration::default())
}

// ---- hints ---------------------------------------------------------------------------------

pub(crate) fn passing_on(inner: &Inner, tree16: &str) -> BTreeMap<String, String> {
    if let Some(m) = inner.memo_cache().get(tree16) {
        return m.clone();
    }
    let Ok(ns) = inner.ready() else {
        return BTreeMap::new();
    };
    let r = inner.conn.run(READ, |db| {
        db.query(
            &inner.read_sql.memo,
            &[(&ns, Type::TEXT), (&tree16, Type::TEXT)],
        )
    });
    let rows = match r {
        Ok(rows) => rows,
        Err(Fail::Absent) => Vec::new(),
        Err(Fail::Store(_)) => return BTreeMap::new(),
    };
    let mut out = BTreeMap::new();
    for row in rows {
        if let (Ok(tk), Ok(k)) = (row.try_get::<_, String>(0), row.try_get::<_, String>(1)) {
            out.insert(tk, k);
        }
    }
    inner.memo_cache().insert(tree16.to_owned(), out.clone());
    out
}

/// Every flag of the namespace, read once per handle (the probe threads
/// ask for one each).
pub(crate) fn flag(inner: &Inner, name: &str) -> bool {
    let mut flags = inner.flags();
    if flags.is_none() {
        let mut set = BTreeSet::new();
        if let Ok(ns) = inner.ready() {
            let r = inner.conn.run(READ, |db| {
                db.query(&inner.read_sql.flags, &[(&ns, Type::TEXT)])
            });
            if let Ok(rows) = r {
                for row in rows {
                    if let Ok(n) = row.try_get::<_, String>(0) {
                        set.insert(n);
                    }
                }
            }
        }
        *flags = Some(set);
    }
    flags.as_ref().is_some_and(|s| s.contains(name))
}
