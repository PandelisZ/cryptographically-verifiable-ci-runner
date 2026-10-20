//! What a vci command measured about itself (2.5.0).
//!
//! Every `vci: timing:` line vci prints under `VCI_TIMING` goes through
//! [`timing_line!`], which also keeps it here. `vci` writes what was kept, one
//! JSON line per command, to the repository's metrics log when it exits (see
//! the CLI's `metrics` module), so a run that was slow can be looked at after
//! the fact, and `vci metrics` can say which steps usually take long.

use std::sync::Mutex;

static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Whether steps are measured: always, unless `VCI_METRICS` is `0` or
/// `off` and `VCI_TIMING` is unset.
pub fn on() -> bool {
    printing()
        || !matches!(
            std::env::var("VCI_METRICS").as_deref(),
            Ok("0") | Ok("off") | Ok("false")
        )
}

/// Whether `VCI_TIMING` asks for the timing lines on stderr.
pub fn printing() -> bool {
    std::env::var_os("VCI_TIMING").is_some()
}

/// Keep `line` (without its `vci: timing: ` prefix), and print it under
/// `VCI_TIMING`.
pub fn record(line: String) {
    if printing() {
        eprintln!("vci: timing: {line}");
    }
    if let Ok(mut l) = LINES.lock()
        && l.len() < 100_000
    {
        l.push(line);
    }
}

/// Every line kept so far, in order.
pub fn take() -> Vec<String> {
    LINES
        .lock()
        .map(|mut l| std::mem::take(&mut *l))
        .unwrap_or_default()
}

/// A kept line's step and seconds, when it ends in `: <seconds>s` (most do;
/// thread-second summaries do not).
pub fn split(line: &str) -> Option<(&str, f64)> {
    let (label, secs) = line.rsplit_once(": ")?;
    let secs = secs.strip_suffix('s')?.parse::<f64>().ok()?;
    Some((label, secs))
}

/// A step's label with its numbers replaced by `#` (`fetch 2018 value(s)`
/// and `fetch 7 value(s)` are one step), and commit ids and paths cut short.
pub fn step_key(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    let mut in_num = false;
    for c in label.chars() {
        if c.is_ascii_digit() {
            if !in_num {
                out.push('#');
            }
            in_num = true;
        } else {
            in_num = false;
            out.push(c);
        }
    }
    // A git command's arguments name objects and refs: its first words do.
    if let Some(rest) = out.strip_prefix("slow git: ") {
        let words: Vec<&str> = rest
            .split_whitespace()
            .filter(|w| !w.starts_with("-c") && !w.contains('='))
            .take(2)
            .collect();
        return format!("slow git: {}", words.join(" "));
    }
    out
}

/// `vci: timing:` lines: kept for the metrics log, printed under
/// `VCI_TIMING`.
#[macro_export]
macro_rules! timing_line {
    ($($arg:tt)*) => {
        $crate::metrics::record(format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_and_keys() {
        assert_eq!(
            split("fetch 2018 value(s) (2018 blob(s) downloaded): 7.26s"),
            Some(("fetch 2018 value(s) (2018 blob(s) downloaded)", 7.26))
        );
        assert_eq!(split("vex-api: thread-seconds: check 25.5, sign 3.4"), None);
        assert_eq!(
            step_key("fetch 2018 value(s) (2018 blob(s) downloaded)"),
            "fetch # value(s) (# blob(s) downloaded)"
        );
        assert_eq!(
            step_key("slow git: -c gc.auto=0 repack -A -d -q"),
            "slow git: repack -A"
        );
    }
}
