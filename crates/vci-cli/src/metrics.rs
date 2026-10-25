//! The metrics log (2.5.0): one JSON line per `vci` command, written when
//! it exits, and `vci metrics`, which summarizes them.
//!
//! Each line holds what the command measured about itself (every step vci
//! times, the lines `VCI_TIMING` prints: [`vci_core::metrics`]), how long it
//! took and how it ended, the attestation store's kind (`git-meta`,
//! `sqlite`, ...; never its location), and the machine (OS, architecture,
//! CPUs, whether it ran in CI). Flags are recorded by name only, never their
//! values (a key path), and no file name or test id is: a step's label can
//! name a count, a project or a git command. The log is the repository's
//! `<git common dir>/vci-metrics.jsonl`, or the file `VCI_METRICS` names;
//! `VCI_METRICS=0` writes nothing. It keeps about the last 4 MB.

use std::collections::BTreeMap;
use std::io::Write as _;

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use serde_json::{Value, json};

const MAX_BYTES: u64 = 4 << 20;

/// Where the log is, or `None` when it is off or there is no repository.
pub fn log_path() -> Option<Utf8PathBuf> {
    match std::env::var("VCI_METRICS").as_deref() {
        Ok("0") | Ok("off") | Ok("false") => return None,
        Ok(p) if !p.is_empty() && p != "1" && p != "on" => return Some(Utf8PathBuf::from(p)),
        _ => {}
    }
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let dir = String::from_utf8(out.stdout).ok()?;
    Some(Utf8PathBuf::from(dir.trim()).join("vci-metrics.jsonl"))
}

/// Append this command's line (best effort: the log never fails a command).
/// `store`: the kind of the attestation store it used, if it used one.
pub fn write(args: &[String], exit: i32, secs: f64, store: Option<&str>) {
    let lines = vci_core::metrics::take();
    let Some(path) = log_path() else { return };
    let cmd = args.get(1).cloned().unwrap_or_default();
    if cmd == "metrics" {
        return;
    }
    let flags: Vec<&str> = args
        .iter()
        .skip(2)
        .filter(|a| a.starts_with("--"))
        .map(|a| a.split('=').next().unwrap_or(a))
        .collect();
    let mut steps = Vec::new();
    let mut notes = Vec::new();
    for l in &lines {
        match vci_core::metrics::split(l) {
            Some((step, s)) => steps.push(json!({"step": step, "secs": s})),
            None => notes.push(json!(l)),
        }
    }
    let ci = std::env::var_os("GITHUB_ACTIONS").is_some() || std::env::var_os("CI").is_some();
    let line = json!({
        "v": 1,
        "at": jiff::Timestamp::now().to_string(),
        "vci": env!("CARGO_PKG_VERSION"),
        "cmd": cmd,
        "flags": flags,
        "exit": exit,
        "secs": (secs * 1000.0).round() / 1000.0,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        "ci": ci,
        "store": store,
        "steps": steps,
        "notes": notes,
    });
    let _ = append(&path, &line.to_string());
    if cmd == "ci" {
        step_summary(&lines, secs);
    }
}

/// In GitHub Actions (`GITHUB_STEP_SUMMARY`): `vci ci`'s slowest steps, so
/// every job's breakdown is on its summary page.
fn step_summary(lines: &[String], secs: f64) {
    let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") else {
        return;
    };
    let mut steps: Vec<(&str, f64)> = lines
        .iter()
        .filter_map(|l| vci_core::metrics::split(l))
        .collect();
    steps.sort_by(|a, b| b.1.total_cmp(&a.1));
    let mut md = format!(
        "\n<details><summary>vci ci: {secs:.1} s; its slowest steps</summary>\n\n| seconds | step |\n|---:|---|\n"
    );
    for (step, s) in steps.iter().take(15) {
        md.push_str(&format!("| {s:.2} | {} |\n", step.replace('|', "\\|")));
    }
    md.push_str("\n</details>\n");
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(path) {
        let _ = f.write_all(md.as_bytes());
    }
}

fn append(path: &Utf8PathBuf, line: &str) -> std::io::Result<()> {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > MAX_BYTES) {
        // Keep the newer half.
        let text = std::fs::read_to_string(path)?;
        let all: Vec<&str> = text.lines().collect();
        let keep = all[all.len() / 2..].join("\n");
        std::fs::write(path, format!("{keep}\n"))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(format!("{line}\n").as_bytes())
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

/// `vci metrics`: the last `last` commands (of `command`, when given) and
/// their steps' usual times.
pub fn report(last: usize, command: Option<&str>, json_out: bool) -> Result<i32> {
    let path = log_path().context("no metrics log: not in a git repository, or VCI_METRICS=0")?;
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {path}")),
    };
    let mut runs: Vec<Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["cmd"] != "metrics")
        .filter(|v| command.is_none_or(|c| v["cmd"] == c))
        .collect();
    let skip = runs.len().saturating_sub(last.max(1));
    runs.drain(..skip);
    // step -> (seconds in each run that had it, summed per run)
    let mut steps: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for r in &runs {
        let mut per: BTreeMap<String, f64> = BTreeMap::new();
        for s in r["steps"].as_array().into_iter().flatten() {
            if let (Some(step), Some(secs)) = (s["step"].as_str(), s["secs"].as_f64()) {
                *per.entry(vci_core::metrics::step_key(step)).or_default() += secs;
            }
        }
        for (k, v) in per {
            steps.entry(k).or_default().push(v);
        }
    }
    let mut rows: Vec<(String, usize, f64, f64, f64)> = steps
        .into_iter()
        .map(|(k, mut v)| {
            v.sort_by(|a, b| a.total_cmp(b));
            let n = v.len();
            (k, n, percentile(&v, 0.5), percentile(&v, 0.95), v[n - 1])
        })
        .collect();
    rows.sort_by(|a, b| (b.2 * b.1 as f64).total_cmp(&(a.2 * a.1 as f64)));
    let mut totals: Vec<f64> = runs.iter().filter_map(|r| r["secs"].as_f64()).collect();
    totals.sort_by(|a, b| a.total_cmp(b));
    if json_out {
        let out = json!({
            "log": path.as_str(),
            "runs": runs.len(),
            "totalSecs": {"p50": percentile(&totals, 0.5), "p95": percentile(&totals, 0.95)},
            "steps": rows.iter().map(|(k, n, p50, p95, max)| json!({"step": k, "runs": n, "p50": p50, "p95": p95, "max": max})).collect::<Vec<_>>(),
            "last": runs.last(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(0);
    }
    println!("metrics log: {path}");
    if runs.is_empty() {
        println!(
            "no runs recorded yet{}",
            command
                .map(|c| format!(" of `vci {c}`"))
                .unwrap_or_default()
        );
        return Ok(0);
    }
    println!(
        "{} run(s){}: {:.1} s median, {:.1} s at the 95th percentile",
        runs.len(),
        command
            .map(|c| format!(" of `vci {c}`"))
            .unwrap_or_default(),
        percentile(&totals, 0.5),
        percentile(&totals, 0.95)
    );
    println!();
    println!(
        "{:>8} {:>8} {:>8} {:>5}  step",
        "p50 s", "p95 s", "max s", "runs"
    );
    for (k, n, p50, p95, max) in rows.iter().take(30) {
        println!("{p50:>8.2} {p95:>8.2} {max:>8.2} {n:>5}  {k}");
    }
    if rows.len() > 30 {
        println!(
            "... and {} more step(s) (--format json lists them all)",
            rows.len() - 30
        );
    }
    println!();
    println!("recent runs:");
    for r in runs.iter().rev().take(10) {
        println!(
            "  {}  vci {} {}  {:.1} s  exit {}",
            r["at"].as_str().unwrap_or("?"),
            r["cmd"].as_str().unwrap_or("?"),
            r["flags"]
                .as_array()
                .map(|f| f
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" "))
                .unwrap_or_default(),
            r["secs"].as_f64().unwrap_or(0.0),
            r["exit"]
        );
    }
    Ok(0)
}
