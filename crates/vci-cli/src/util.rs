//! Small helpers: glob matching, JSONC stripping, durations and timestamps.

use anyhow::{Context, Result, bail};

/// Glob match on `/`-separated paths: `*` matches within one segment, `**`
/// matches across segments (including none), `?` matches one non-`/` char.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        if p.starts_with(b"**") {
            let rest = &p[2..];
            // "**/" may also match zero segments.
            if rest.first() == Some(&b'/') && rec(&rest[1..], t) {
                return true;
            }
            for i in 0..=t.len() {
                if rec(rest, &t[i..]) {
                    return true;
                }
            }
            return false;
        }
        match p[0] {
            b'*' => {
                for i in 0..=t.len() {
                    if rec(&p[1..], &t[i..]) {
                        return true;
                    }
                    if i < t.len() && t[i] == b'/' {
                        break;
                    }
                }
                false
            }
            b'?' => !t.is_empty() && t[0] != b'/' && rec(&p[1..], &t[1..]),
            c => !t.is_empty() && t[0] == c && rec(&p[1..], &t[1..]),
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

/// Wildcard match for env var names: `*` matches any run of characters.
pub fn name_match(pattern: &str, name: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some(b'*') => (0..=t.len()).any(|i| rec(&p[1..], &t[i..])),
            Some(&c) => t.first() == Some(&c) && rec(&p[1..], &t[1..]),
        }
    }
    rec(pattern.as_bytes(), name.as_bytes())
}

/// Strip `//` and `/* */` comments and trailing commas from JSONC text.
pub fn strip_jsonc(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if c == b'\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_str = true;
            out.push(c);
            i += 1;
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else if c == b',' {
            // Drop a trailing comma before `}` or `]`.
            let mut j = i + 1;
            while j < b.len() && (b[j] as char).is_ascii_whitespace() {
                j += 1;
            }
            if j < b.len() && (b[j] == b'}' || b[j] == b']') {
                i += 1;
            } else {
                out.push(c);
                i += 1;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Parse a duration like `30s`, `15m`, `12h`, `14d`, `2w` into seconds.
pub fn parse_duration(s: &str) -> Result<i64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: i64 = num.parse().with_context(|| format!("bad duration {s:?}"))?;
    let mul = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" | "" => 86400,
        "w" => 7 * 86400,
        _ => bail!("bad duration unit in {s:?} (use s, m, h, d or w)"),
    };
    if n <= 0 {
        bail!("duration must be positive: {s:?}");
    }
    n.checked_mul(mul).context("duration overflow")
}

/// Current unix time in seconds.
pub fn now_unix() -> i64 {
    jiff::Timestamp::now().as_second()
}

/// RFC 3339 UTC with second precision.
pub fn rfc3339(unix: i64) -> String {
    jiff::Timestamp::from_second(unix)
        .map(|t| t.strftime("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|_| "invalid".into())
}

/// Parse RFC 3339 into unix seconds.
pub fn parse_rfc3339(s: &str) -> Result<i64> {
    let t: jiff::Timestamp = s.parse().with_context(|| format!("bad timestamp {s:?}"))?;
    Ok(t.as_second())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob_match("src/**/*.test.ts", "src/a.test.ts"));
        assert!(glob_match("src/**/*.test.ts", "src/x/y/a.test.ts"));
        assert!(!glob_match("src/*.test.ts", "src/x/a.test.ts"));
        assert!(glob_match("refs/heads/main", "refs/heads/main"));
        assert!(glob_match("refs/tags/**", "refs/tags/v1/x"));
        assert!(!glob_match("refs/heads/rel*", "refs/heads/release/x"));
        assert!(glob_match("**", "anything/at/all"));
        assert!(glob_match("?.ts", "a.ts"));
    }

    #[test]
    fn names() {
        assert!(name_match("CI_*", "CI_JOB_ID"));
        assert!(name_match("*TOKEN*", "GITHUB_TOKEN_X"));
        assert!(!name_match("CI_*", "XCI_A"));
        assert!(name_match("TZ", "TZ"));
    }

    #[test]
    fn jsonc() {
        let s = strip_jsonc("{\n // c\n \"a\": \"http://x\", /* b */ \"extends\": [\"./x\",],\n}");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["a"], "http://x");
        assert_eq!(v["extends"][0], "./x");
    }

    #[test]
    fn durations_and_times() {
        assert_eq!(parse_duration("14d").unwrap(), 14 * 86400);
        assert_eq!(parse_duration("1s").unwrap(), 1);
        assert!(parse_duration("0d").is_err());
        assert!(parse_duration("3y").is_err());
        let t = 1_790_000_000;
        assert_eq!(parse_rfc3339(&rfc3339(t)).unwrap(), t);
    }
}
