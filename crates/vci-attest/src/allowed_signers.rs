//! OpenSSH `allowed_signers` parser (see ssh-keygen(1) "ALLOWED SIGNERS").
//!
//! Line format: `principals [options] keytype base64-key [comment]`.
//!
//! * Blank lines and lines whose first non-blank character is `#` are ignored.
//! * `principals` is a comma-separated pattern list, optionally wrapped in
//!   double quotes.
//! * Options (comma-separated, names case-insensitive): `cert-authority`,
//!   `namespaces="pattern-list"`, `valid-after="time"`, `valid-before="time"`.
//!   Values must be double-quoted; `\"` escapes a quote inside a value.
//! * Times are `YYYYMMDD[HHMM[SS]]` with an optional `Z` suffix for UTC.
//!
//! Like OpenSSH, any malformed line (unknown option, bad quoting, bad time,
//! unparseable key, ...) makes the whole file an error. Callers treat that as
//! "no trusted signers", i.e. every test runs.
//!
//! Times *without* a `Z` suffix are local time in OpenSSH, which depends on the
//! verifier's time zone. We interpret them conservatively instead of guessing:
//! `valid-after` as the latest possible instant (UTC-12) and `valid-before` as
//! the earliest possible instant (UTC+14), so the accepted window is never
//! wider than OpenSSH's in any time zone.

use ssh_key::PublicKey;

/// One parsed allowed_signers line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedSigner {
    /// 1-based line number in the source text.
    pub line: usize,
    /// Raw principals field (comma-separated pattern list, quotes removed).
    pub principals: String,
    pub key: PublicKey,
    /// `cert-authority` was set. Such entries never authorise a signature (v1).
    pub cert_authority: bool,
    /// Raw `namespaces=` pattern list, if present.
    pub namespaces: Option<String>,
    /// `valid-after`, unix seconds (signature invalid when `now < valid_after`).
    pub valid_after: Option<i64>,
    /// `valid-before`, unix seconds (signature invalid when `now > valid_before`).
    pub valid_before: Option<i64>,
}

impl AllowedSigner {
    /// Whether this entry permits signatures in `namespace`
    /// (OpenSSH `match_pattern_list` semantics; absent option = all).
    pub fn allows_namespace(&self, namespace: &str) -> bool {
        match &self.namespaces {
            None => true,
            Some(list) => match_pattern_list(namespace, list) == 1,
        }
    }

    /// Whether `now` (unix seconds) lies inside the validity window.
    pub fn valid_at(&self, now: i64) -> bool {
        if let Some(after) = self.valid_after
            && now < after
        {
            return false;
        }
        if let Some(before) = self.valid_before
            && now > before
        {
            return false;
        }
        true
    }
}

/// A parsed allowed_signers file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AllowedSigners {
    entries: Vec<AllowedSigner>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("allowed_signers line {line}: {reason}")]
pub struct AllowedSignersError {
    pub line: usize,
    pub reason: String,
}

fn err(line: usize, reason: impl Into<String>) -> AllowedSignersError {
    AllowedSignersError {
        line,
        reason: reason.into(),
    }
}

impl AllowedSigners {
    pub fn parse(text: &str) -> Result<Self, AllowedSignersError> {
        let mut entries = Vec::new();
        for (idx, raw) in text.lines().enumerate() {
            let lineno = idx + 1;
            if let Some(e) = parse_line(raw, lineno)? {
                entries.push(e);
            }
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[AllowedSigner] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn is_ws(c: char) -> bool {
    c == ' ' || c == '\t'
}

fn parse_line(raw: &str, lineno: usize) -> Result<Option<AllowedSigner>, AllowedSignersError> {
    let line = raw.trim_start_matches(is_ws);
    let line = line.trim_end_matches(|c: char| c == '\r' || is_ws(c));
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }

    // principals
    let (principals, rest) = if let Some(after_quote) = line.strip_prefix('"') {
        let end = after_quote
            .find('"')
            .ok_or_else(|| err(lineno, "unterminated quoted principals"))?;
        (&after_quote[..end], &after_quote[end + 1..])
    } else {
        let end = line.find(is_ws).unwrap_or(line.len());
        (&line[..end], &line[end..])
    };
    if principals.is_empty() {
        return Err(err(lineno, "empty principals"));
    }
    if !rest.starts_with(is_ws) {
        return Err(err(lineno, "missing key"));
    }
    let rest = rest.trim_start_matches(is_ws);

    // Either `keytype base64 ...` directly, or `options keytype base64 ...`.
    let (options, key) = match parse_key(rest) {
        Some(key) => (None, key),
        None => {
            let (opts, after) =
                split_options(rest).ok_or_else(|| err(lineno, "unterminated quote in options"))?;
            let after = after.trim_start_matches(is_ws);
            if after.is_empty() {
                return Err(err(lineno, "missing key"));
            }
            let key = parse_key(after).ok_or_else(|| err(lineno, "invalid public key"))?;
            (Some(opts), key)
        }
    };

    let mut entry = AllowedSigner {
        line: lineno,
        principals: principals.to_string(),
        key,
        cert_authority: false,
        namespaces: None,
        valid_after: None,
        valid_before: None,
    };
    if let Some(opts) = options {
        parse_options(opts, &mut entry).map_err(|r| err(lineno, r))?;
    }
    if let (Some(a), Some(b)) = (entry.valid_after, entry.valid_before)
        && b <= a
    {
        return Err(err(lineno, "valid-before time is not after valid-after"));
    }
    Ok(Some(entry))
}

/// Parse `keytype base64 [comment]`; returns None if it is not a key.
fn parse_key(s: &str) -> Option<PublicKey> {
    let mut it = s.split(is_ws).filter(|t| !t.is_empty());
    let alg = it.next()?;
    let b64 = it.next()?;
    let key = PublicKey::from_openssh(&format!("{alg} {b64}")).ok()?;
    // Certificates are not plain keys; ssh-key never yields one here, but be explicit.
    if alg.contains("-cert-") {
        return None;
    }
    Some(key)
}

/// Split off the options field: it ends at the first blank outside quotes.
/// Mirrors OpenSSH `sshkey_advance_past_options`.
fn split_options(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut quoted = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if !quoted && (c == b' ' || c == b'\t') {
            break;
        }
        if c == b'\\' && bytes.get(i + 1) == Some(&b'"') {
            i += 2;
            continue;
        }
        if c == b'"' {
            quoted = !quoted;
        }
        i += 1;
    }
    if quoted {
        return None;
    }
    Some((&s[..i], &s[i..]))
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len()
        && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Read a double-quoted value; returns (value, remainder).
fn dequote(s: &str) -> Result<(String, &str), String> {
    let mut chars = s.char_indices();
    match chars.next() {
        Some((_, '"')) => {}
        _ => return Err("missing start quote".into()),
    }
    let bytes = s.as_bytes();
    let mut out = String::new();
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            return Ok((out, &s[i + 1..]));
        }
        if bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'"') {
            out.push('"');
            i += 2;
            continue;
        }
        let ch = s[i..].chars().next().expect("in bounds");
        out.push(ch);
        i += ch.len_utf8();
    }
    Err("missing end quote".into())
}

fn parse_options(mut opts: &str, e: &mut AllowedSigner) -> Result<(), String> {
    while !opts.is_empty() {
        if let Some(r) = strip_prefix_ci(opts, "cert-authority") {
            e.cert_authority = true;
            opts = r;
        } else if let Some(r) = strip_prefix_ci(opts, "namespaces=") {
            if e.namespaces.is_some() {
                return Err("multiple \"namespaces\" clauses".into());
            }
            let (v, r) = dequote(r).map_err(|m| format!("namespaces: {m}"))?;
            e.namespaces = Some(v);
            opts = r;
        } else if let Some(r) = strip_prefix_ci(opts, "valid-after=") {
            if e.valid_after.is_some() {
                return Err("multiple \"valid-after\" clauses".into());
            }
            let (v, r) = dequote(r).map_err(|m| format!("valid-after: {m}"))?;
            e.valid_after =
                Some(parse_time(&v, TimeBound::After).ok_or("invalid \"valid-after\" time")?);
            opts = r;
        } else if let Some(r) = strip_prefix_ci(opts, "valid-before=") {
            if e.valid_before.is_some() {
                return Err("multiple \"valid-before\" clauses".into());
            }
            let (v, r) = dequote(r).map_err(|m| format!("valid-before: {m}"))?;
            e.valid_before =
                Some(parse_time(&v, TimeBound::Before).ok_or("invalid \"valid-before\" time")?);
            opts = r;
        } else {
            let name = opts.split([',', '=']).next().unwrap_or(opts);
            return Err(format!("unsupported option {name:?}"));
        }
        if opts.is_empty() {
            break;
        }
        opts = opts
            .strip_prefix(',')
            .ok_or_else(|| "invalid option separator".to_string())?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TimeBound {
    After,
    Before,
}

/// Maximum local-time offsets in the tz database: UTC-12 .. UTC+14.
const MAX_WEST: i64 = 12 * 3600;
const MAX_EAST: i64 = 14 * 3600;

/// `YYYYMMDD`, `YYYYMMDDHHMM` or `YYYYMMDDHHMMSS`, optional trailing `Z`/`z`.
fn parse_time(s: &str, bound: TimeBound) -> Option<i64> {
    let (digits, utc) = match s.strip_suffix(['Z', 'z']) {
        Some(d) => (d, true),
        None => (s, false),
    };
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let num = |a: usize, b: usize| -> i64 { digits[a..b].parse().expect("ascii digits") };
    let (y, mo, d) = match digits.len() {
        8 | 12 | 14 => (num(0, 4), num(4, 6), num(6, 8)),
        _ => return None,
    };
    let (h, mi, sec) = match digits.len() {
        8 => (0, 0, 0),
        12 => (num(8, 10), num(10, 12), 0),
        _ => (num(8, 10), num(10, 12), num(12, 14)),
    };
    if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || sec > 59
    {
        return None;
    }
    let t = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec;
    Some(match (utc, bound) {
        (true, _) => t,
        // local time at UTC-12 is the latest UTC instant for this wall clock
        (false, TimeBound::After) => t + MAX_WEST,
        // local time at UTC+14 is the earliest UTC instant for this wall clock
        (false, TimeBound::Before) => t - MAX_EAST,
    })
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(y) => 29,
        _ => 28,
    }
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// OpenSSH `match_pattern`: `*` and `?` wildcards, case-sensitive.
fn match_pattern(s: &[u8], p: &[u8]) -> bool {
    // iterative wildcard matching with backtracking on the last '*'
    let (mut si, mut pi) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// OpenSSH `match_pattern_list`: 1 = positive match, -1 = negated match, 0 = none.
fn match_pattern_list(s: &str, list: &str) -> i32 {
    let mut got_positive = 0;
    for sub in list.split(',') {
        let (negated, pat) = match sub.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, sub),
        };
        if match_pattern(s.as_bytes(), pat.as_bytes()) {
            if negated {
                return -1;
            }
            got_positive = 1;
        }
    }
    got_positive
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";

    fn one(text: &str) -> AllowedSigner {
        AllowedSigners::parse(text).unwrap().entries()[0].clone()
    }

    #[test]
    fn plain_line_with_comment_and_blank_lines() {
        let text = format!(
            "# comment\n\n   \t\n  # indented comment\nalice@example.com {K1} alice laptop key\n"
        );
        let a = AllowedSigners::parse(&text).unwrap();
        assert_eq!(a.entries().len(), 1);
        let e = &a.entries()[0];
        assert_eq!(e.line, 5);
        assert_eq!(e.principals, "alice@example.com");
        assert!(
            !e.cert_authority
                && e.namespaces.is_none()
                && e.valid_after.is_none()
                && e.valid_before.is_none()
        );
        assert_eq!(e.key, PublicKey::from_openssh(K1).unwrap());
    }

    #[test]
    fn quoted_principals_and_tabs() {
        let a = AllowedSigners::parse(&format!(
            "\"alice@x,bob@y\"\t{}\r\n",
            K1.replace(' ', "\t\t")
        ))
        .unwrap();
        assert_eq!(a.entries()[0].principals, "alice@x,bob@y");
    }

    #[test]
    fn options_parse() {
        let text = format!(
            "a@b NAMESPACES=\"vci-attest,git\",valid-after=\"20240101\",Valid-Before=\"20300101123000Z\" {K1}\n"
        );
        let e = one(&text);
        assert_eq!(e.namespaces.as_deref(), Some("vci-attest,git"));
        // local time: conservative UTC-12 interpretation for valid-after
        assert_eq!(e.valid_after, Some(1704067200 + 12 * 3600));
        assert_eq!(e.valid_before, Some(1893501000));
        assert!(e.allows_namespace("vci-attest"));
        assert!(e.allows_namespace("git"));
        assert!(!e.allows_namespace("file"));
    }

    #[test]
    fn quoted_value_with_escaped_quote_and_space() {
        let text = format!("a@b namespaces=\"x \\\"y\\\",vci-*\" {K1}");
        let e = one(&text);
        assert_eq!(e.namespaces.as_deref(), Some("x \"y\",vci-*"));
        assert!(e.allows_namespace("vci-attest"));
    }

    #[test]
    fn cert_authority_flag_is_parsed() {
        let e = one(&format!("*@example.com cert-authority {K1}"));
        assert!(e.cert_authority);
        let e = one(&format!(
            "*@example.com cert-authority,namespaces=\"vci-attest\" {K1}"
        ));
        assert!(e.cert_authority);
        assert_eq!(e.namespaces.as_deref(), Some("vci-attest"));
    }

    #[test]
    fn rejects_malformed_lines() {
        let bad = [
            format!("a@b unknown-opt {K1}"),
            format!("a@b no-touch-required {K1}"),
            format!("a@b namespaces=vci-attest {K1}"),
            format!("a@b namespaces=\"vci-attest {K1}"),
            format!("a@b namespaces=\"a\",namespaces=\"b\" {K1}"),
            format!("a@b valid-after=\"2024\" {K1}"),
            format!("a@b valid-after=\"20241301\" {K1}"),
            format!("a@b valid-after=\"20240230\" {K1}"),
            format!("a@b valid-after=\"20300101Z\",valid-before=\"20200101Z\" {K1}"),
            format!("a@b cert-authorityx {K1}"),
            format!("a@b namespaces=\"a\"x {K1}"),
            "a@b".to_string(),
            "a@b ssh-ed25519".to_string(),
            "a@b ssh-ed25519 notbase64!!".to_string(),
            format!("\"a@b {K1}"),
            format!("\"\" {K1}"),
        ];
        for line in bad {
            let text = format!("ok@x {K1}\n{line}\n");
            let e = AllowedSigners::parse(&text).expect_err(&line);
            assert_eq!(e.line, 2, "{line}");
        }
    }

    #[test]
    fn time_formats() {
        assert_eq!(parse_time("19700101Z", TimeBound::After), Some(0));
        assert_eq!(parse_time("197001010001Z", TimeBound::After), Some(60));
        assert_eq!(parse_time("19700101000001z", TimeBound::After), Some(1));
        assert_eq!(parse_time("20000229Z", TimeBound::After), Some(951782400));
        assert_eq!(parse_time("19700101", TimeBound::Before), Some(-14 * 3600));
        assert_eq!(parse_time("19000229Z", TimeBound::After), None);
        assert_eq!(parse_time("1970010Z", TimeBound::After), None);
        assert_eq!(parse_time("197001012400Z", TimeBound::After), None);
        assert_eq!(parse_time("+9700101", TimeBound::After), None);
    }

    #[test]
    fn validity_window_is_inclusive_like_openssh() {
        let mut e = AllowedSigners::parse(&format!("a@b {K1}"))
            .unwrap()
            .entries()[0]
            .clone();
        e.valid_after = Some(100);
        e.valid_before = Some(200);
        assert!(!e.valid_at(99));
        assert!(e.valid_at(100));
        assert!(e.valid_at(200));
        assert!(!e.valid_at(201));
    }

    #[test]
    fn pattern_lists() {
        assert_eq!(match_pattern_list("vci-attest", "vci-attest"), 1);
        assert_eq!(match_pattern_list("vci-attest", "git,file"), 0);
        assert_eq!(match_pattern_list("vci-attest", "vci-*"), 1);
        assert_eq!(match_pattern_list("vci-attest", "vci-a?test"), 1);
        assert_eq!(match_pattern_list("vci-attest", "*,!vci-attest"), -1);
        assert_eq!(match_pattern_list("vci-attest", "!git,*"), 1);
        assert_eq!(match_pattern_list("vci-attest", "VCI-ATTEST"), 0);
        assert_eq!(match_pattern_list("vci-attest", ""), 0);
        assert!(match_pattern(b"abc", b"a*c*"));
        assert!(!match_pattern(b"abc", b"a*d"));
    }
}
