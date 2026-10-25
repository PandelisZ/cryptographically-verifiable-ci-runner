//! `vci update --check` against a tiny local HTTP server standing in for
//! GitHub's releases (VCI_UPDATE_BASE_URL): a newer release exits 1 and
//! names both versions, the same release exits 0, an unreachable server is
//! an error (exit 2). The binary under test is never replaced: `--check`
//! changes nothing, and a vci built in a checkout refuses to update itself.

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;
use std::process::Output;

use assert_cmd::Command;

const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// Serve `/releases/latest` with `status`, a `Location` header and `body`,
/// every other path with 404, until the test process exits.
fn serve(status: u16, location: Option<String>, body: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/releases", listener.local_addr().unwrap());
    let loc = location.map(|l| l.replace("{base}", &base));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            if reader.read_line(&mut request).is_err() {
                continue;
            }
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            let path = request.split_whitespace().nth(1).unwrap_or("");
            let (code, headers, body) = if path == "/releases/latest" {
                let h = loc
                    .as_ref()
                    .map(|l| format!("Location: {l}\r\n"))
                    .unwrap_or_default();
                (status, h, body.clone())
            } else {
                (404, String::new(), "not found".to_owned())
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {code} X\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    base
}

fn vci(base: &str, args: &[&str]) -> Output {
    Command::cargo_bin("vci")
        .unwrap()
        .args(args)
        .env("VCI_UPDATE_BASE_URL", base)
        .env("VCI_METRICS", "0")
        .env_remove("VCI_UPDATE_REPO")
        .output()
        .unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn check_reports_a_newer_release_with_exit_1() {
    let base = serve(302, Some("{base}/tag/v99.0.0".to_owned()), String::new());
    let out = vci(&base, &["update", "--check"]);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains(CURRENT) && err.contains("99.0.0"), "{err}");
    assert!(
        err.contains(&format!(
            "vci: {CURRENT} is installed; the latest release is 99.0.0"
        )),
        "{err}"
    );
    assert!(out.stdout.is_empty());

    // The alias, and an update that would replace a vci built in a checkout:
    // it refuses (exit 2) and the binary stays.
    let out = vci(&base, &["upgrade"]);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("built by cargo in a source checkout"), "{err}");
}

#[test]
fn check_on_the_latest_release_exits_0() {
    let base = serve(200, None, format!("{{\"tag_name\": \"v{CURRENT}\"}}"));
    let out = vci(&base, &["update", "--check"]);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(
        err.contains(&format!("vci: {CURRENT} is the latest release")),
        "{err}"
    );
    // Without --check, nothing to do either.
    let out = vci(&base, &["update"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

#[test]
fn an_unreachable_server_is_an_error_with_exit_2() {
    // A port nothing listens on any more.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let out = vci(
        &format!("http://127.0.0.1:{port}/releases"),
        &["update", "--check"],
    );
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("vci: error: could not fetch"), "{err}");
    assert!(!err.contains("panicked"), "{err}");

    // A release that does not exist.
    let base = serve(404, None, String::new());
    let out = vci(&base, &["update", "--check"]);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("HTTP 404"), "{err}");
}

#[test]
fn version_and_check_exclude_each_other() {
    let out = vci(
        "http://127.0.0.1:9/releases",
        &["update", "--check", "--version", "1.2.3"],
    );
    assert_eq!(out.status.code(), Some(2));
    let out = vci(
        "http://127.0.0.1:9/releases",
        &["update", "--version", "nope"],
    );
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("--version takes a release version"), "{err}");
}
