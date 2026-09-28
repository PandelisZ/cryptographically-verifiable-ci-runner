//! `cfg(...)` predicates: parsing, normalising, and deciding whether a
//! predicate evaluates the same for two hosts.
//!
//! A predicate's atoms are either *platform* atoms (keys that
//! `rustc --print cfg` reports: `unix`, `target_os`, `target_feature`,
//! `panic`, `debug_assertions`, ...) whose values come from each host's cfg
//! set, or *symbolic* atoms (`feature = "x"`, `test`, a build script's custom
//! cfg) whose values are the same on both hosts because they come from
//! hashed inputs. Two hosts agree on a predicate when, for every assignment
//! of the symbolic atoms, it evaluates the same under both cfg sets.

use std::collections::{BTreeMap, BTreeSet};

/// Keys that are properties of the target, even when a host's cfg set does
/// not mention them (`target_os = "ios"` on macOS).
const KNOWN_PLATFORM_KEYS: &[&str] = &[
    "unix",
    "windows",
    "target_os",
    "target_family",
    "target_arch",
    "target_env",
    "target_vendor",
    "target_abi",
    "target_pointer_width",
    "target_endian",
    "target_feature",
    "target_has_atomic",
    "target_has_atomic_load_store",
    "target_has_atomic_equal_alignment",
    "target_thread_local",
    "target_has_reliable_f16",
    "target_has_reliable_f128",
    "panic",
    "relocation_model",
    "sanitize",
    "overflow_checks",
    "debug_assertions",
    "ub_checks",
    "fmt_debug",
    "contract_checks",
    "emscripten_wasm_eh",
];

/// A parsed cfg predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cfg {
    All(Vec<Cfg>),
    Any(Vec<Cfg>),
    Not(Box<Cfg>),
    /// `key` or `key = "value"`.
    Atom(String, Option<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Str(String),
    LParen,
    RParen,
    Comma,
    Eq,
}

fn lex(s: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            '=' => {
                out.push(Tok::Eq);
                i += 1;
            }
            '"' => {
                let mut v = String::new();
                i += 1;
                loop {
                    match b.get(i) {
                        None => return Err("unterminated string".into()),
                        Some('"') => {
                            i += 1;
                            break;
                        }
                        Some('\\') => {
                            v.push(*b.get(i + 1).ok_or("bad escape")?);
                            i += 2;
                        }
                        Some(ch) => {
                            v.push(*ch);
                            i += 1;
                        }
                    }
                }
                out.push(Tok::Str(v));
            }
            c if c.is_alphanumeric() || c == '_' => {
                let start = i;
                while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_') {
                    i += 1;
                }
                let mut id: String = b[start..i].iter().collect();
                // Raw identifiers: `r#foo`.
                if id == "r" && b.get(i) == Some(&'#') {
                    i += 1;
                    let s2 = i;
                    while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_') {
                        i += 1;
                    }
                    id = b[s2..i].iter().collect();
                }
                out.push(Tok::Ident(id));
            }
            other => return Err(format!("unexpected {other:?}")),
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn pred(&mut self, depth: usize) -> Result<Cfg, String> {
        if depth > 64 {
            return Err("too deep".into());
        }
        let Some(Tok::Ident(id)) = self.next() else {
            return Err("expected an identifier".into());
        };
        match (id.as_str(), self.peek()) {
            ("all" | "any" | "not", Some(Tok::LParen)) => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    if self.peek() == Some(&Tok::RParen) {
                        self.pos += 1;
                        break;
                    }
                    items.push(self.pred(depth + 1)?);
                    match self.next() {
                        Some(Tok::Comma) => {}
                        Some(Tok::RParen) => break,
                        _ => return Err("expected ',' or ')'".into()),
                    }
                }
                Ok(match id.as_str() {
                    "all" => Cfg::All(items),
                    "any" => Cfg::Any(items),
                    _ => {
                        if items.len() != 1 {
                            return Err("not() takes one predicate".into());
                        }
                        Cfg::Not(Box::new(items.pop().expect("one item")))
                    }
                })
            }
            (_, Some(Tok::Eq)) => {
                self.pos += 1;
                match self.next() {
                    Some(Tok::Str(v)) => Ok(Cfg::Atom(id, Some(v))),
                    _ => Err("expected a string after '='".into()),
                }
            }
            _ => Ok(Cfg::Atom(id, None)),
        }
    }
}

/// Parse a predicate (the text inside `cfg(...)`).
pub fn parse(s: &str) -> Result<Cfg, String> {
    let mut p = Parser {
        toks: lex(s)?,
        pos: 0,
    };
    let c = p.pred(0)?;
    if p.pos != p.toks.len() {
        return Err("trailing tokens".into());
    }
    Ok(c)
}

impl std::fmt::Display for Cfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let list = |f: &mut std::fmt::Formatter<'_>, name: &str, xs: &[Cfg]| {
            write!(f, "{name}(")?;
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{x}")?;
            }
            write!(f, ")")
        };
        match self {
            Cfg::All(xs) => list(f, "all", xs),
            Cfg::Any(xs) => list(f, "any", xs),
            Cfg::Not(x) => write!(f, "not({x})"),
            Cfg::Atom(k, None) => write!(f, "{k}"),
            Cfg::Atom(k, Some(v)) => write!(f, "{k} = {v:?}"),
        }
    }
}

impl Cfg {
    fn atoms<'a>(&'a self, out: &mut BTreeSet<(&'a str, Option<&'a str>)>) {
        match self {
            Cfg::All(xs) | Cfg::Any(xs) => xs.iter().for_each(|x| x.atoms(out)),
            Cfg::Not(x) => x.atoms(out),
            Cfg::Atom(k, v) => {
                out.insert((k.as_str(), v.as_deref()));
            }
        }
    }

    fn eval(&self, val: &dyn Fn(&str, Option<&str>) -> bool) -> bool {
        match self {
            Cfg::All(xs) => xs.iter().all(|x| x.eval(val)),
            Cfg::Any(xs) => xs.iter().any(|x| x.eval(val)),
            Cfg::Not(x) => !x.eval(val),
            Cfg::Atom(k, v) => val(k, v.as_deref()),
        }
    }

    /// True if any atom is a known platform key (the predicate can depend on
    /// the target).
    pub fn mentions_platform(&self) -> bool {
        let mut a = BTreeSet::new();
        self.atoms(&mut a);
        a.iter().any(|(k, _)| KNOWN_PLATFORM_KEYS.contains(k))
    }
}

/// A host's cfg set (`rustc --print cfg` lines: `unix`, `target_os="macos"`)
/// as key -> values (an empty-string value for a bare key).
fn cfg_set(lines: &[String]) -> BTreeMap<String, BTreeSet<String>> {
    let mut m: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for l in lines {
        let l = l.trim();
        if l.is_empty() {
            continue;
        }
        match l.split_once('=') {
            Some((k, v)) => {
                let v = v.trim().trim_matches('"').to_owned();
                m.entry(k.trim().to_owned()).or_default().insert(v);
            }
            None => {
                m.entry(l.to_owned()).or_default().insert(String::new());
            }
        }
    }
    m
}

/// Does `pred` hold for the host whose cfg set is `set` (atoms the set does
/// not have are false, as cargo evaluates `[target.'cfg(..)']` tables)?
pub fn holds(pred: &str, set: &[String]) -> Result<bool, String> {
    let c = parse(pred)?;
    let m = cfg_set(set);
    Ok(c.eval(&|k, v| m.get(k).is_some_and(|vs| vs.contains(v.unwrap_or("")))))
}

/// Largest number of symbolic atoms a predicate may have (2^n evaluations).
const MAX_SYMBOLIC: usize = 12;

/// Does `pred` evaluate differently for the host whose cfg set is
/// `attested` than for the host whose cfg set is `current`? `Err` when the
/// predicate cannot be parsed or is too large to decide (callers treat that
/// as "differs").
pub fn differs(pred: &str, attested: &[String], current: &[String]) -> Result<bool, String> {
    let c = parse(pred)?;
    let a = cfg_set(attested);
    let b = cfg_set(current);
    let is_platform =
        |k: &str| KNOWN_PLATFORM_KEYS.contains(&k) || a.contains_key(k) || b.contains_key(k);
    let mut atoms = BTreeSet::new();
    c.atoms(&mut atoms);
    let symbolic: Vec<(&str, Option<&str>)> = atoms
        .iter()
        .copied()
        .filter(|(k, _)| !is_platform(k))
        .collect();
    if symbolic.len() > MAX_SYMBOLIC {
        return Err(format!("{} symbolic atoms", symbolic.len()));
    }
    let lookup =
        |set: &BTreeMap<String, BTreeSet<String>>, k: &str, v: Option<&str>| match set.get(k) {
            None => false,
            Some(vs) => vs.contains(v.unwrap_or("")),
        };
    for mask in 0u32..(1u32 << symbolic.len()) {
        let sym = |k: &str, v: Option<&str>| {
            symbolic
                .iter()
                .position(|s| *s == (k, v))
                .is_some_and(|i| mask & (1 << i) != 0)
        };
        let under = |set: &BTreeMap<String, BTreeSet<String>>| {
            c.eval(&|k, v| {
                if is_platform(k) {
                    lookup(set, k, v)
                } else {
                    sym(k, v)
                }
            })
        };
        if under(&a) != under(&b) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn mac() -> Vec<String> {
        lines(&[
            "debug_assertions",
            "panic=\"unwind\"",
            "target_arch=\"aarch64\"",
            "target_env=\"\"",
            "target_family=\"unix\"",
            "target_feature=\"neon\"",
            "target_os=\"macos\"",
            "target_pointer_width=\"64\"",
            "target_vendor=\"apple\"",
            "unix",
        ])
    }

    fn linux() -> Vec<String> {
        lines(&[
            "debug_assertions",
            "panic=\"unwind\"",
            "target_arch=\"x86_64\"",
            "target_env=\"gnu\"",
            "target_family=\"unix\"",
            "target_feature=\"sse2\"",
            "target_os=\"linux\"",
            "target_pointer_width=\"64\"",
            "target_vendor=\"unknown\"",
            "unix",
        ])
    }

    #[test]
    fn parses_and_prints() {
        let c = parse(r#"all(unix, not(target_os = "linux"), any(feature="x", test),)"#).unwrap();
        assert_eq!(
            c.to_string(),
            r#"all(unix, not(target_os = "linux"), any(feature = "x", test))"#
        );
        assert!(c.mentions_platform());
        assert!(!parse(r#"feature = "x""#).unwrap().mentions_platform());
        assert!(parse("all(").is_err());
        assert!(parse("$meta").is_err());
        assert!(parse("not(a, b)").is_err());
        assert!(parse("a b").is_err());
    }

    #[test]
    fn same_value_on_both_hosts_does_not_differ() {
        for p in [
            "unix",
            "not(windows)",
            r#"target_family = "unix""#,
            r#"any(target_os = "linux", target_os = "macos")"#,
            r#"all(unix, feature = "x")"#,
            "debug_assertions",
            r#"target_pointer_width = "64""#,
            "test",
        ] {
            assert_eq!(differs(p, &mac(), &linux()), Ok(false), "{p}");
        }
    }

    #[test]
    fn target_dependent_predicates_differ() {
        for p in [
            r#"target_os = "linux""#,
            r#"not(target_os = "macos")"#,
            r#"target_arch = "x86_64""#,
            r#"target_feature = "neon""#,
            r#"all(unix, target_env = "gnu")"#,
            r#"any(feature = "x", target_os = "macos")"#,
        ] {
            assert_eq!(differs(p, &mac(), &linux()), Ok(true), "{p}");
        }
        // Same host: never differs.
        assert_eq!(differs(r#"target_os = "linux""#, &mac(), &mac()), Ok(false));
        // A symbolic atom that masks the platform one in every assignment.
        assert_eq!(
            differs(
                r#"all(feature = "never", target_os = "linux")"#,
                &mac(),
                &linux()
            ),
            Ok(true),
            "feature may be on"
        );
        assert!(differs("$x", &mac(), &linux()).is_err());
    }
}
