//! Parsers for what one `go test` run produces: the vci test log
//! (`vci_testlog.go`, one `<op> <Go-quoted string>` line per event) and the
//! `go test -json` (test2json) event stream.

use std::collections::{BTreeMap, BTreeSet};

use camino::Utf8PathBuf;
use serde::Deserialize;
use vci_core::TestResult;

/// Events of one test binary (and anything it re-executed).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct LogEvents {
    /// `start` records: `<runtime.Version()> <GOOS>/<GOARCH>`.
    pub starts: Vec<String>,
    pub opens: BTreeSet<Utf8PathBuf>,
    pub stats: BTreeSet<Utf8PathBuf>,
    pub chdirs: BTreeSet<Utf8PathBuf>,
    pub execs: BTreeSet<String>,
    /// Targets of hard and symbolic links the test created (absolute).
    pub links: BTreeSet<Utf8PathBuf>,
    pub env: BTreeSet<String>,
    pub taints: Vec<String>,
}

/// Undo Go's `strconv.Quote`. Fails on anything that is not valid UTF-8
/// after unquoting (a path vci could not name) or a malformed escape.
pub(crate) fn unquote(s: &str) -> Result<String, String> {
    let inner = s
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .ok_or_else(|| format!("not a quoted string: {s}"))?;
    let mut out: Vec<u8> = Vec::with_capacity(inner.len());
    let mut it = inner.chars();
    let hex = |it: &mut std::str::Chars<'_>, n: usize| -> Result<u32, String> {
        let h: String = it.by_ref().take(n).collect();
        if h.len() != n {
            return Err(format!("short escape in {s}"));
        }
        u32::from_str_radix(&h, 16).map_err(|e| format!("bad escape {h:?} in {s}: {e}"))
    };
    while let Some(c) = it.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        let e = it.next().ok_or_else(|| format!("dangling escape in {s}"))?;
        let ch = match e {
            'a' => '\x07',
            'b' => '\x08',
            'f' => '\x0c',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\x0b',
            '\\' => '\\',
            '"' => '"',
            '\'' => '\'',
            'x' => {
                out.push(hex(&mut it, 2)? as u8);
                continue;
            }
            'u' => char::from_u32(hex(&mut it, 4)?).ok_or_else(|| format!("bad \\u in {s}"))?,
            'U' => char::from_u32(hex(&mut it, 8)?).ok_or_else(|| format!("bad \\U in {s}"))?,
            other => return Err(format!("unknown escape \\{other} in {s}")),
        };
        let mut buf = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    }
    String::from_utf8(out).map_err(|_| format!("not UTF-8 after unquoting: {s}"))
}

/// Parse the vci test log. Anything unexpected is a taint.
pub(crate) fn parse_testlog(text: &str) -> LogEvents {
    let mut ev = LogEvents::default();
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let Some((op, arg)) = line.split_once(' ') else {
            ev.taints
                .push(format!("vci:bad-testlog-line:{}: {line:?}", i + 1));
            continue;
        };
        let arg = match unquote(arg) {
            Ok(a) => a,
            Err(e) => {
                ev.taints
                    .push(format!("vci:bad-testlog-line:{}: {e}", i + 1));
                continue;
            }
        };
        let path = || Utf8PathBuf::from(&arg);
        match op {
            "start" => ev.starts.push(arg.clone()),
            "getenv" => {
                ev.env.insert(arg.clone());
            }
            "open" => {
                ev.opens.insert(path());
            }
            "stat" => {
                ev.stats.insert(path());
            }
            "chdir" => {
                ev.chdirs.insert(path());
            }
            "exec" => {
                ev.execs.insert(arg.clone());
            }
            "link" => {
                ev.links.insert(path());
            }
            "taint" => ev.taints.push(format!("go:testlog: {arg}")),
            other => ev.taints.push(format!("vci:unknown-testlog-op:{other}")),
        }
    }
    ev
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Event {
    action: String,
    package: String,
    test: String,
    output: String,
    elapsed: f64,
}

/// A `go test -json` run of one package, reduced to vci's result and the
/// human-readable output.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TestRun {
    pub result: TestResult,
    /// The output `go test -v` would print (every `Output` field, and lines
    /// that are not events).
    pub output: String,
    /// Top-level tests (`TestX`, `FuzzX`, `ExampleX`) that passed.
    pub passed: BTreeSet<String>,
}

/// Reduce the test2json events of the package `import_path`. `exit_ok` is
/// the `go test` exit status. The state is `passed` only when the package's
/// final event is `pass`, no build failed and `go test` exited 0; every
/// test and subtest counts, and a skipped one is counted as skipped (a
/// package with a skipped test is not attested). A package in which no test
/// ran (no test functions, or a `TestMain` that exits before `m.Run`)
/// passes for `go test` but is `no-tests` here: nothing was vouched for.
pub(crate) fn parse_test2json(stdout: &str, import_path: &str, exit_ok: bool) -> TestRun {
    let mut output = String::new();
    let mut tests: BTreeMap<String, String> = BTreeMap::new();
    let mut package_action = String::new();
    let mut elapsed = 0.0;
    let mut build_failed = false;
    let mut foreign = false;
    for line in stdout.lines() {
        let Ok(e) = serde_json::from_str::<Event>(line) else {
            output.push_str(line);
            output.push('\n');
            continue;
        };
        match e.action.as_str() {
            "output" | "build-output" => output.push_str(&e.output),
            "build-fail" => build_failed = true,
            _ => {}
        }
        if e.action.starts_with("build-") {
            continue;
        }
        if !e.package.is_empty() && e.package != import_path {
            foreign = true;
            continue;
        }
        if !matches!(e.action.as_str(), "pass" | "fail" | "skip") {
            continue;
        }
        if e.test.is_empty() {
            package_action = e.action.clone();
            elapsed = e.elapsed;
        } else {
            tests.insert(e.test.clone(), e.action.clone());
        }
    }
    let failed = tests.values().filter(|a| *a == "fail").count() as u32;
    let skipped = tests.values().filter(|a| *a == "skip").count() as u32;
    let passed: BTreeSet<String> = tests
        .iter()
        .filter(|(t, a)| *a == "pass" && !t.contains('/'))
        .map(|(t, _)| t.clone())
        .collect();
    let ok = package_action == "pass" && !build_failed && !foreign && exit_ok;
    let state = if ok && tests.is_empty() {
        "no-tests"
    } else if ok {
        "passed"
    } else if package_action == "skip" {
        "skipped"
    } else {
        "failed"
    };
    TestRun {
        result: TestResult {
            state: state.to_owned(),
            tests: tests.len() as u32,
            // A failed package with no failed test (build or vet failure, a
            // panic in TestMain) still must not count as a pass.
            failed: if state == "failed" {
                failed.max(1)
            } else {
                failed
            },
            skipped,
            duration_ms: (elapsed * 1000.0).max(0.0) as u64,
        },
        output,
        passed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unquote_handles_go_escapes() {
        assert_eq!(unquote(r#""/a b/c.txt""#).unwrap(), "/a b/c.txt");
        assert_eq!(unquote(r#""a\nb\t\"q\"\\""#).unwrap(), "a\nb\t\"q\"\\");
        assert_eq!(unquote(r#""é\U0001F600""#).unwrap(), "é😀");
        assert_eq!(unquote("\"é\"").unwrap(), "é");
        assert!(unquote(r#""\xff""#).is_err(), "invalid UTF-8");
        assert!(unquote(r#""\q""#).is_err());
        assert!(unquote("nope").is_err());
    }

    #[test]
    fn testlog_records() {
        let ev = parse_testlog(
            "start \"go1.26.2 darwin/arm64\"\nlink \"/r/b/testdata/x\"\ngetenv \"B_MODE\"\nopen \"/r/b/testdata/b.json\"\nstat \"/r/b/missing\"\nchdir \"/r/b/testdata\"\nexec \"/bin/echo\"\ntaint \"getwd failed\"\nwat \"x\"\ngarbage\n",
        );
        assert_eq!(ev.starts, ["go1.26.2 darwin/arm64"]);
        assert!(ev.env.contains("B_MODE"));
        assert!(
            ev.opens
                .contains(camino::Utf8Path::new("/r/b/testdata/b.json"))
        );
        assert!(ev.stats.contains(camino::Utf8Path::new("/r/b/missing")));
        assert!(ev.chdirs.contains(camino::Utf8Path::new("/r/b/testdata")));
        assert!(ev.execs.contains("/bin/echo"));
        assert!(ev.links.contains(camino::Utf8Path::new("/r/b/testdata/x")));
        let t = ev.taints.join("\n");
        assert!(t.contains("go:testlog: getwd failed"), "{t}");
        assert!(t.contains("unknown-testlog-op:wat"), "{t}");
        assert!(t.contains("bad-testlog-line:10"), "{t}");
    }

    const PKG: &str = "example.com/m/s";

    fn ev(action: &str, test: &str) -> String {
        format!(r#"{{"Action":"{action}","Package":"{PKG}","Test":"{test}","Elapsed":0.5}}"#)
    }

    #[test]
    fn passing_package_counts_every_test() {
        let s = [
            r#"{"Action":"start","Package":"example.com/m/s"}"#.to_owned(),
            ev("run", "TestA"),
            r#"{"Action":"output","Package":"example.com/m/s","Test":"TestA","Output":"=== RUN   TestA\n"}"#.to_owned(),
            ev("pass", "TestA/sub"),
            ev("pass", "TestA"),
            ev("pass", ""),
        ]
        .join("\n");
        let r = parse_test2json(&s, PKG, true);
        assert!(r.result.is_pass(), "{r:?}");
        assert_eq!(r.result.tests, 2);
        assert_eq!(r.result.duration_ms, 500);
        assert!(r.output.contains("=== RUN   TestA"));
        assert_eq!(r.passed.iter().collect::<Vec<_>>(), ["TestA"]);
        // go test exiting non-zero is never a pass.
        assert!(!parse_test2json(&s, PKG, false).result.is_pass());
    }

    #[test]
    fn skips_failures_and_build_failures_are_not_passes() {
        let skip = [
            ev("skip", "TestOK/sub"),
            ev("pass", "TestOK"),
            ev("pass", ""),
        ]
        .join("\n");
        let r = parse_test2json(&skip, PKG, true);
        assert_eq!(r.result.skipped, 1);
        assert!(!r.result.is_pass());
        let fail = [ev("fail", "TestF"), ev("fail", "")].join("\n");
        let r = parse_test2json(&fail, PKG, false);
        assert_eq!((r.result.state.as_str(), r.result.failed), ("failed", 1));
        let build = [
            r#"{"ImportPath":"example.com/m/s [example.com/m/s.test]","Action":"build-output","Output":"s_test.go:3: undefined: x\n"}"#.to_owned(),
            r#"{"ImportPath":"example.com/m/s [example.com/m/s.test]","Action":"build-fail"}"#.to_owned(),
            ev("fail", ""),
        ]
        .join("\n");
        let r = parse_test2json(&build, PKG, false);
        assert!(!r.result.is_pass());
        assert_eq!(r.result.failed, 1);
        assert!(r.output.contains("undefined: x"));
        // TestMain exiting 0 before m.Run, or no test functions: go test
        // reports a pass, but nothing ran.
        let empty = [
            r#"{"Action":"output","Package":"example.com/m/s","Output":"skipping package\n"}"#
                .to_owned(),
            ev("pass", ""),
        ]
        .join("\n");
        let r = parse_test2json(&empty, PKG, true);
        assert_eq!(r.result.state, "no-tests");
        assert!(!r.result.is_pass());
        let none = ev("skip", "");
        assert_eq!(parse_test2json(&none, PKG, true).result.state, "skipped");
        assert!(!parse_test2json("", PKG, true).result.is_pass());
        let other = [
            ev("pass", ""),
            r#"{"Action":"pass","Package":"other"}"#.to_owned(),
        ]
        .join("\n");
        assert!(!parse_test2json(&other, PKG, true).result.is_pass());
    }
}
