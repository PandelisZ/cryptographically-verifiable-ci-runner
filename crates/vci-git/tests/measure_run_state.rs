//! A measurement, not a test (ignored): how long git-meta takes to say which
//! state object a run wrote ([`AttestationStore::run_state_objects`], one
//! key lookup per distinct run) on a real store. Point
//! `VCI_MEASURE_STORE` at a repository whose `.git/git-meta.sqlite` is a
//! **copy** of the store to measure (it is opened as git-meta opens it),
//! then:
//!
//! ```text
//! VCI_MEASURE_STORE=/path/to/copy cargo test -p vci-git --test measure_run_state -- --ignored --nocapture
//! ```
//!
//! It prints the time of one lookup (each distinct run of the store's
//! attestation keys asked alone), of asking for every distinct run at once
//! (what a plan asked for before 2.10.0 named the runs within its budget),
//! and of asking for 8 (`[store] plan_states`).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use vci_git::{GitMetaStore, Repo};
use vci_store::{AttestationStore, RunOf, StoredEnvelope};

/// A shape id no store holds a link of: every lookup misses, so it costs
/// what finding the keys costs.
const SHAPE: &str = "5ba9e0f0c0ffee00000000000000000000000000000000000000000000000000";

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

#[test]
#[ignore = "a measurement: set VCI_MEASURE_STORE to a repository holding a copy of a store"]
fn run_state_lookups_on_a_real_store() {
    let Ok(dir) = std::env::var("VCI_MEASURE_STORE") else {
        eprintln!("VCI_MEASURE_STORE is not set: nothing measured");
        return;
    };
    let store = GitMetaStore::new(Repo::discover(camino::Utf8Path::new(&dir)).unwrap());
    let all = store.list_all().unwrap();
    // One record per distinct run (its key's hint).
    let mut runs: BTreeMap<String, StoredEnvelope> = BTreeMap::new();
    for e in all {
        if let Some(h) = vci_store::parse_key_hint(&e.key) {
            runs.entry(vci_store::hint_segment(&h)).or_insert(e);
        }
    }
    let records: Vec<&StoredEnvelope> = runs.values().collect();
    println!(
        "{} distinct run(s) among the store's attestation keys",
        records.len()
    );
    let ask = |rs: &[&StoredEnvelope]| -> Duration {
        let runs: Vec<RunOf<'_>> = rs
            .iter()
            .map(|r| RunOf {
                record: r,
                shape: SHAPE,
            })
            .collect();
        let t = Instant::now();
        let named = store.run_state_objects(&runs).unwrap();
        let d = t.elapsed();
        assert_eq!(named.len(), runs.len());
        d
    };
    // Warm the pooled reader and the page cache once.
    ask(&records[..1]);
    let one: Vec<Duration> = records.iter().take(200).map(|r| ask(&[r])).collect();
    println!(
        "one lookup: median {:.3} ms, min {:.3} ms, max {:.3} ms ({} lookups)",
        median(one.clone()).as_secs_f64() * 1e3,
        one.iter().min().unwrap().as_secs_f64() * 1e3,
        one.iter().max().unwrap().as_secs_f64() * 1e3,
        one.len()
    );
    let every: Vec<Duration> = (0..3).map(|_| ask(&records)).collect();
    println!(
        "every distinct run at once ({}): median {:.3} s",
        records.len(),
        median(every).as_secs_f64()
    );
    let eight: Vec<Duration> = (0..20)
        .map(|_| ask(&records[..8.min(records.len())]))
        .collect();
    println!(
        "8 runs (plan_states): median {:.3} ms",
        median(eight).as_secs_f64() * 1e3
    );
}
