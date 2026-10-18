//! Measures what a plan pays to rehash one stored manifest many times against
//! a checkout through [`vci_core::CheckoutCache`], as `vci plan` does for every
//! candidate of every file. Run by hand:
//!
//! ```text
//! VCI_BENCH_MANIFEST=/path/to/manifest.json VCI_BENCH_ROOT=/path/to/checkout \
//!   VCI_BENCH_N=2000 VCI_BENCH_THREADS=16 \
//!   cargo test -p vci-core --test bench_rehash -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::time::Instant;

use camino::Utf8PathBuf;
use vci_core::{CheckoutCache, InputManifest};

// The CLI's allocator (crates/vci-cli/src/main.rs), so the benchmark measures
// what the binary does: musl's own allocator serializes threads.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[test]
#[ignore = "measures a real manifest named by VCI_BENCH_MANIFEST against VCI_BENCH_ROOT"]
fn rehash_one_manifest_many_times() {
    let Ok(path) = std::env::var("VCI_BENCH_MANIFEST") else {
        return;
    };
    let root = Utf8PathBuf::from(std::env::var("VCI_BENCH_ROOT").expect("VCI_BENCH_ROOT"));
    let n: usize = std::env::var("VCI_BENCH_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let threads: usize = std::env::var("VCI_BENCH_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let bytes = std::fs::read(&path).expect("manifest");
    let m = Arc::new(InputManifest::from_compact(&bytes).expect("compact manifest"));
    let kinds = {
        let mut c = std::collections::BTreeMap::new();
        for e in &m.entries {
            *c.entry(format!("{:?}", e.kind)).or_insert(0usize) += 1;
        }
        c
    };
    eprintln!("manifest: {} entries {kinds:?}", m.entries.len());
    let cache = Arc::new(CheckoutCache::new(&root));
    // One uncached-cold pass first, as the first candidate of a plan pays it.
    let t0 = Instant::now();
    let first = m.diff_against_cache(&cache, |_| None, &[]).expect("diff");
    eprintln!(
        "first pass: {:.3}s, {} mismatches",
        t0.elapsed().as_secs_f64(),
        first.len()
    );
    let t1 = Instant::now();
    let per = n.div_ceil(threads);
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let m = Arc::clone(&m);
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || {
                for _ in 0..per {
                    let _ = m.diff_against_cache(&cache, |_| None, &[]).expect("diff");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let total = t1.elapsed().as_secs_f64();
    eprintln!(
        "{} passes on {threads} thread(s): {total:.2}s, {:.4}s per pass, {:.1} passes/s",
        per * threads,
        total / (per * threads) as f64,
        (per * threads) as f64 / total
    );
}
