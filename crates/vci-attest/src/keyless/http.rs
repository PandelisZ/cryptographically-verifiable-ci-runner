//! HTTP through `curl` (every GitHub runner has it), the way vci already
//! shells out to `git` and `ssh-keygen`. The URL, headers and body go to
//! curl's standard input as a config file (`-K -`), so the job's tokens never
//! appear on a command line.

use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};

/// Quote a value for a curl config file (`\\` and `\"` escapes).
fn quote(s: &str) -> Result<String, String> {
    if s.contains(['\n', '\r']) {
        return Err("a curl config value with a line break".into());
    }
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// One request; returns (status, body). `body` makes it a POST.
pub(crate) fn request(
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), String> {
    let mut config = format!("url = {}\n", quote(url)?);
    for (k, v) in headers {
        config.push_str(&format!("header = {}\n", quote(&format!("{k}: {v}"))?));
    }
    if let Some(b) = body {
        let text = std::str::from_utf8(b).map_err(|_| "request body is not UTF-8")?;
        config.push_str(&format!("data-binary = {}\n", quote(text)?));
    }
    let mut child = Command::new("curl")
        .args([
            "-sS",
            "-K",
            "-",
            "--max-time",
            "60",
            "--retry",
            "3",
            "-o",
            "-",
            "-w",
            "\n%{http_code}",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("running curl: {e}"))?;
    let mut stdin = child.stdin.take().expect("stdin piped");
    let writer = std::thread::spawn(move || {
        let r = stdin.write_all(config.as_bytes());
        drop(stdin);
        r
    });
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });
    let mut out = Vec::new();
    child
        .stdout
        .take()
        .expect("stdout piped")
        .read_to_end(&mut out)
        .map_err(|e| format!("reading curl's output: {e}"))?;
    let status = child.wait().map_err(|e| format!("curl: {e}"))?;
    let stderr = stderr_reader.join().unwrap_or_default();
    let _ = writer.join();
    if !status.success() {
        return Err(format!(
            "curl {} failed ({status}): {}",
            url_for_messages(url),
            String::from_utf8_lossy(&stderr).trim()
        ));
    }
    let split = out
        .iter()
        .rposition(|&b| b == b'\n')
        .ok_or("curl printed no status code")?;
    let code = std::str::from_utf8(&out[split + 1..])
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .ok_or("curl printed no status code")?;
    out.truncate(split);
    Ok((code, out))
}

/// The URL without its query string (which may carry a token).
pub(crate) fn url_for_messages(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_quoting() {
        assert_eq!(quote(r#"{"a":"b\c"}"#).unwrap(), r#""{\"a\":\"b\\c\"}""#);
        assert!(quote("a\nb").is_err());
        assert_eq!(url_for_messages("https://x/y?token=1"), "https://x/y");
    }
}
