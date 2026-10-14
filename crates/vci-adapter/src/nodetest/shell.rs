//! A small, strict subset of POSIX `sh` word processing, enough to read a
//! package.json test script the way `npm run` / `pnpm run` (`sh -c`) would:
//! quoting, parameter expansion (`$X`, `${X}`, `${X:-w}`, `${X-w}`,
//! `${X:+w}`, `${X+w}`), field splitting of unquoted expansions, and
//! pathname expansion of unquoted `*`, `?` and `[...]`. Everything else
//! (operators, command substitution, redirections, brace and tilde
//! expansion, comments, other expansions) is refused: the caller then makes
//! the user configure the command explicitly, and nothing is attested.

use std::collections::BTreeSet;

use camino::{Utf8Path, Utf8PathBuf};

/// A piece of a word before field splitting.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    /// Literal text; `quoted` text is never split or globbed.
    Lit { text: String, quoted: bool },
    /// The value of a parameter expansion.
    Exp { value: String, quoted: bool },
}

/// A word of the script after quote removal and expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Word {
    /// Each character, and whether it is a pathname-expansion operator
    /// (an unquoted `*`, `?` or `[`).
    chars: Vec<(char, bool)>,
}

impl Word {
    pub(crate) fn text(&self) -> String {
        self.chars.iter().map(|(c, _)| *c).collect()
    }

    fn has_glob(&self) -> bool {
        self.chars.iter().any(|(_, g)| *g)
    }
}

/// The parsed command line: leading `NAME=value` assignments and the words.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Command {
    pub(crate) assignments: Vec<(String, String)>,
    pub(crate) words: Vec<Word>,
    /// Variables the script expands (their values decided the words).
    pub(crate) referenced: BTreeSet<String>,
}

type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Parse a parameter expansion after `$` at `chars[*i]`; advances `*i`
/// past it and returns its value.
fn expansion(
    chars: &[char],
    i: &mut usize,
    env: Env,
    referenced: &mut BTreeSet<String>,
) -> Result<String, String> {
    let Some(&c) = chars.get(*i) else {
        return Err("a lone `$` at the end of the script".into());
    };
    if is_name_start(c) {
        let start = *i;
        while *i < chars.len() && is_name_char(chars[*i]) {
            *i += 1;
        }
        let name: String = chars[start..*i].iter().collect();
        referenced.insert(name.clone());
        return Ok(env(&name).unwrap_or_default());
    }
    if c != '{' {
        return Err(format!(
            "`${c}` (only $NAME and ${{NAME}}, ${{NAME:-word}}, ${{NAME:+word}} are supported)"
        ));
    }
    *i += 1;
    let start = *i;
    if !chars.get(*i).copied().is_some_and(is_name_start) {
        return Err("`${` not followed by a variable name".into());
    }
    while *i < chars.len() && is_name_char(chars[*i]) {
        *i += 1;
    }
    let name: String = chars[start..*i].iter().collect();
    referenced.insert(name.clone());
    let value = env(&name);
    // The operator and its word, up to the matching `}`.
    let mut op = String::new();
    while let Some(&c) = chars.get(*i) {
        if c == '}' || !matches!(c, ':' | '-' | '+') || op.len() >= 2 {
            break;
        }
        op.push(c);
        *i += 1;
        if op != ":" {
            break;
        }
    }
    let wstart = *i;
    let mut depth = 0usize;
    loop {
        match chars.get(*i) {
            None => return Err(format!("unterminated `${{{name}`")),
            Some('}') if depth == 0 => break,
            Some('}') => depth -= 1,
            Some('{') if *i > 0 && chars[*i - 1] == '$' => depth += 1,
            _ => {}
        }
        *i += 1;
    }
    let word: String = chars[wstart..*i].iter().collect();
    *i += 1; // `}`
    let set = value.is_some();
    let non_empty = value.as_deref().is_some_and(|v| !v.is_empty());
    let use_word = match op.as_str() {
        "" if word.is_empty() => return Ok(value.unwrap_or_default()),
        ":-" => !non_empty,
        "-" => !set,
        ":+" => non_empty,
        "+" => set,
        _ => {
            return Err(format!(
                "`${{{name}{op}{word}}}` (only ${{NAME}}, ${{NAME:-word}}, ${{NAME-word}}, ${{NAME:+word}} and ${{NAME+word}} are supported)"
            ));
        }
    };
    if !use_word {
        return Ok(if op.ends_with('+') {
            String::new()
        } else {
            value.unwrap_or_default()
        });
    }
    // The word: literal text and $NAME / ${NAME} only.
    let wchars: Vec<char> = word.chars().collect();
    let mut out = String::new();
    let mut j = 0;
    while j < wchars.len() {
        match wchars[j] {
            '$' => {
                j += 1;
                out.push_str(&expansion(&wchars, &mut j, env, referenced)?);
            }
            '\'' | '"' | '\\' | '`' => {
                return Err(format!(
                    "quoting inside `${{{name}{op}...}}` is not supported"
                ));
            }
            c => {
                out.push(c);
                j += 1;
            }
        }
    }
    Ok(out)
}

/// Split `script` into a command: leading assignments and words, with
/// expansions done against `env` and unquoted globs matched in `cwd`.
pub(crate) fn parse(script: &str, env: Env, cwd: &Utf8Path) -> Result<Command, String> {
    let chars: Vec<char> = script.chars().collect();
    let mut referenced = BTreeSet::new();
    let mut tokens: Vec<Vec<Seg>> = Vec::new();
    let mut cur: Vec<Seg> = Vec::new();
    let mut in_token = false;
    let mut i = 0;
    let push_lit = |cur: &mut Vec<Seg>, c: char, quoted: bool| match cur.last_mut() {
        Some(Seg::Lit { text, quoted: q }) if *q == quoted => text.push(c),
        _ => cur.push(Seg::Lit {
            text: c.to_string(),
            quoted,
        }),
    };
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\n' => {
                if in_token {
                    tokens.push(std::mem::take(&mut cur));
                    in_token = false;
                }
                i += 1;
            }
            '\'' => {
                let end = chars[i + 1..]
                    .iter()
                    .position(|&x| x == '\'')
                    .ok_or("unterminated single quote")?;
                let text: String = chars[i + 1..i + 1 + end].iter().collect();
                cur.push(Seg::Lit { text, quoted: true });
                in_token = true;
                i += end + 2;
            }
            '"' => {
                i += 1;
                in_token = true;
                // An empty "" still makes a (possibly empty) word.
                cur.push(Seg::Lit {
                    text: String::new(),
                    quoted: true,
                });
                loop {
                    let Some(&d) = chars.get(i) else {
                        return Err("unterminated double quote".into());
                    };
                    match d {
                        '"' => {
                            i += 1;
                            break;
                        }
                        '\\' => {
                            match chars.get(i + 1) {
                                Some(&e @ ('$' | '`' | '"' | '\\')) => push_lit(&mut cur, e, true),
                                Some('\n') => {}
                                Some(&e) => {
                                    push_lit(&mut cur, '\\', true);
                                    push_lit(&mut cur, e, true);
                                }
                                None => return Err("unterminated double quote".into()),
                            }
                            i += 2;
                        }
                        '$' => {
                            i += 1;
                            let v = expansion(&chars, &mut i, env, &mut referenced)?;
                            cur.push(Seg::Exp {
                                value: v,
                                quoted: true,
                            });
                        }
                        '`' => return Err("command substitution (`...`)".into()),
                        d => {
                            push_lit(&mut cur, d, true);
                            i += 1;
                        }
                    }
                }
            }
            '\\' => {
                match chars.get(i + 1) {
                    Some('\n') => {}
                    Some(&e) => {
                        push_lit(&mut cur, e, true);
                        in_token = true;
                    }
                    None => return Err("a trailing backslash".into()),
                }
                i += 2;
            }
            '$' => {
                if chars.get(i + 1) == Some(&'(') {
                    return Err("command substitution ($(...))".into());
                }
                i += 1;
                let v = expansion(&chars, &mut i, env, &mut referenced)?;
                cur.push(Seg::Exp {
                    value: v,
                    quoted: false,
                });
                in_token = true;
            }
            '`' => return Err("command substitution (`...`)".into()),
            '|' | '&' | ';' | '<' | '>' | '(' | ')' => {
                return Err(format!(
                    "the shell operator `{c}` (one command only: no pipes, lists, redirections or subshells)"
                ));
            }
            '{' | '}' => {
                return Err(format!(
                    "an unquoted `{c}` (brace expansion differs between shells; quote the pattern)"
                ));
            }
            '#' if !in_token => return Err("a comment (`#`)".into()),
            '~' if !in_token => return Err("tilde expansion (`~`)".into()),
            c => {
                push_lit(&mut cur, c, false);
                in_token = true;
                i += 1;
            }
        }
    }
    if in_token {
        tokens.push(cur);
    }

    let mut cmd = Command {
        referenced,
        ..Default::default()
    };
    let mut leading = true;
    for tok in tokens {
        if leading && let Some((name, value)) = assignment(&tok) {
            cmd.assignments.push((name, value));
            continue;
        }
        leading = false;
        for w in fields(&tok) {
            if w.has_glob() {
                match sh_glob(&w, cwd)? {
                    Some(matches) => cmd.words.extend(matches.into_iter().map(|m| Word {
                        chars: m.chars().map(|c| (c, false)).collect(),
                    })),
                    None => cmd.words.push(w),
                }
            } else {
                cmd.words.push(w);
            }
        }
    }
    Ok(cmd)
}

/// `NAME=value` when the token starts with an unquoted literal `NAME=`.
/// The value is not split or globbed (as in `sh`).
fn assignment(tok: &[Seg]) -> Option<(String, String)> {
    let Some(Seg::Lit {
        text,
        quoted: false,
    }) = tok.first()
    else {
        return None;
    };
    let (name, rest) = text.split_once('=')?;
    if name.is_empty() || !name.starts_with(is_name_start) || !name.chars().all(is_name_char) {
        return None;
    }
    let mut value = rest.to_owned();
    for s in &tok[1..] {
        match s {
            Seg::Lit { text, .. } => value.push_str(text),
            Seg::Exp { value: v, .. } => value.push_str(v),
        }
    }
    Some((name.to_owned(), value))
}

/// Field splitting: unquoted expansion results split on blanks; a token
/// made only of unquoted expansions that expand to nothing disappears.
fn fields(tok: &[Seg]) -> Vec<Word> {
    let mut out = Vec::new();
    let mut cur: Vec<(char, bool)> = Vec::new();
    let mut started = false;
    for s in tok {
        match s {
            Seg::Lit { text, quoted } => {
                started = true;
                for c in text.chars() {
                    cur.push((c, !quoted && matches!(c, '*' | '?' | '[')));
                }
            }
            Seg::Exp {
                value,
                quoted: true,
            } => {
                started = true;
                cur.extend(value.chars().map(|c| (c, false)));
            }
            Seg::Exp {
                value,
                quoted: false,
            } => {
                for c in value.chars() {
                    if matches!(c, ' ' | '\t' | '\n') {
                        if started || !cur.is_empty() {
                            out.push(Word {
                                chars: std::mem::take(&mut cur),
                            });
                        }
                        started = false;
                    } else {
                        started = true;
                        cur.push((c, matches!(c, '*' | '?' | '[')));
                    }
                }
            }
        }
    }
    if started || !cur.is_empty() {
        out.push(Word { chars: cur });
    }
    out
}

/// `sh` pathname expansion of `w` relative to `cwd`: the matching paths
/// (sorted), or `None` when nothing matches (the word stays as it is).
/// `*` and `?` never match `/` or a leading `.`; `**` is `*` (no globstar).
fn sh_glob(w: &Word, cwd: &Utf8Path) -> Result<Option<Vec<String>>, String> {
    let absolute = w.chars.first().map(|(c, _)| *c) == Some('/');
    let mut comps: Vec<Vec<(char, bool)>> = vec![vec![]];
    for &(c, g) in &w.chars {
        if c == '/' {
            comps.push(vec![]);
        } else {
            comps.last_mut().expect("non-empty").push((c, g));
        }
    }
    let add = |shown: &str, name: &str| {
        if shown.is_empty() {
            name.to_owned()
        } else if shown.ends_with('/') {
            format!("{shown}{name}")
        } else {
            format!("{shown}/{name}")
        }
    };
    // (path as written, filesystem path)
    let mut paths: Vec<(String, Utf8PathBuf)> = vec![if absolute {
        ("/".to_owned(), Utf8PathBuf::from("/"))
    } else {
        (String::new(), cwd.to_owned())
    }];
    let n = comps.len();
    for (k, comp) in comps.iter().enumerate() {
        if absolute && k == 0 {
            continue;
        }
        let last = k + 1 == n;
        let mut next = Vec::new();
        if comp.is_empty() {
            // `a//b` or a trailing `/`: keep the separator.
            for (shown, fs) in paths {
                next.push((format!("{shown}/"), fs));
            }
            paths = next;
            continue;
        }
        if !comp.iter().any(|(_, g)| *g) {
            let name: String = comp.iter().map(|(c, _)| *c).collect();
            for (shown, fs) in paths {
                let p = fs.join(&name);
                if last || p.is_dir() {
                    next.push((add(&shown, &name), p));
                }
            }
        } else {
            for (shown, fs) in paths {
                let Ok(rd) = fs.read_dir_utf8() else {
                    continue;
                };
                let mut names: Vec<String> = rd
                    .flatten()
                    .map(|e| e.file_name().to_owned())
                    .filter(|name| fnmatch(comp, name))
                    .collect();
                names.sort();
                for name in names {
                    let p = fs.join(&name);
                    if last || p.is_dir() {
                        next.push((add(&shown, &name), p));
                    }
                }
            }
        }
        paths = next;
    }
    let mut out: Vec<String> = paths
        .into_iter()
        .filter(|(_, fs)| fs.symlink_metadata().is_ok())
        .map(|(s, _)| s)
        .collect();
    out.sort();
    out.dedup();
    Ok((!out.is_empty()).then_some(out))
}

/// `fnmatch` of one path component (no `/`), with `sh` rules for a leading
/// dot. Inactive characters match literally.
fn fnmatch(pat: &[(char, bool)], name: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    if name.first() == Some(&'.') && pat.first() != Some(&('.', false)) {
        return false;
    }
    fn rec(p: &[(char, bool)], s: &[char]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(('*', true)) => (0..=s.len()).any(|k| rec(&p[1..], &s[k..])),
            Some(('?', true)) => !s.is_empty() && rec(&p[1..], &s[1..]),
            Some(('[', true)) => match class(&p[1..]) {
                Some((matches, used)) => {
                    !s.is_empty() && matches(s[0]) && rec(&p[1 + used..], &s[1..])
                }
                // An unterminated `[` is a literal.
                None => s.first() == Some(&'[') && rec(&p[1..], &s[1..]),
            },
            Some((c, _)) => s.first() == Some(c) && rec(&p[1..], &s[1..]),
        }
    }
    type Matcher = Box<dyn Fn(char) -> bool>;
    fn class(p: &[(char, bool)]) -> Option<(Matcher, usize)> {
        let mut i = 0;
        let negate = matches!(p.first(), Some(('!' | '^', _)));
        if negate {
            i += 1;
        }
        let mut items: Vec<(char, char)> = Vec::new();
        let mut first = true;
        loop {
            let (c, _) = *p.get(i)?;
            if c == ']' && !first {
                break;
            }
            first = false;
            if p.get(i + 1).map(|x| x.0) == Some('-') && p.get(i + 2).is_some_and(|x| x.0 != ']') {
                items.push((c, p[i + 2].0));
                i += 3;
            } else {
                items.push((c, c));
                i += 1;
            }
        }
        let m: Matcher =
            Box::new(move |ch| items.iter().any(|(a, b)| *a <= ch && ch <= *b) != negate);
        Some((m, i + 1))
    }
    rec(pat, &name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    fn words(c: &Command) -> Vec<String> {
        c.words.iter().map(Word::text).collect()
    }

    #[test]
    fn vex_web_script() {
        let t = tempfile::tempdir().unwrap();
        let cwd = Utf8Path::from_path(t.path()).unwrap();
        let s = "NODE_ENV=test node --import ./test/register-hooks.mjs --test ${TEST_CONCURRENCY:+--test-concurrency=$TEST_CONCURRENCY} 'src/**/*.test.ts' 'server/**/*.test.ts' 'scripts/*.test.mjs'";
        let c = parse(s, &env(&[]), cwd).unwrap();
        assert_eq!(c.assignments, [("NODE_ENV".into(), "test".into())]);
        assert_eq!(
            words(&c),
            [
                "node",
                "--import",
                "./test/register-hooks.mjs",
                "--test",
                "src/**/*.test.ts",
                "server/**/*.test.ts",
                "scripts/*.test.mjs"
            ]
        );
        assert!(c.referenced.contains("TEST_CONCURRENCY"));
        let c = parse(s, &env(&[("TEST_CONCURRENCY", "4")]), cwd).unwrap();
        assert_eq!(words(&c)[4], "--test-concurrency=4");
        // Unquoted expansions are split into fields.
        let c = parse(s, &env(&[("TEST_CONCURRENCY", "1 --test-only")]), cwd).unwrap();
        assert_eq!(words(&c)[4..6], ["--test-concurrency=1", "--test-only"]);
    }

    #[test]
    fn quoting_and_expansions() {
        let t = tempfile::tempdir().unwrap();
        let cwd = Utf8Path::from_path(t.path()).unwrap();
        let e = env(&[("A", "x y"), ("E", "")]);
        let c = parse(
            r#"node "$A" $A 'q $A' a\ b ${E:-d} ${E-d} ${U-u} ${A:+p} "" $E"#,
            &e,
            cwd,
        )
        .unwrap();
        assert_eq!(
            words(&c),
            ["node", "x y", "x", "y", "q $A", "a b", "d", "u", "p", ""]
        );
        for bad in [
            "a && b",
            "a | b",
            "a; b",
            "a > f",
            "echo $(x)",
            "echo `x`",
            "echo {a,b}",
            "echo ~/x",
            "echo ${A:=x}",
            "echo $1",
            "echo 'x",
        ] {
            assert!(parse(bad, &e, cwd).is_err(), "{bad}");
        }
    }

    #[test]
    fn sh_globs_match_like_sh() {
        let t = tempfile::tempdir().unwrap();
        let cwd = Utf8Path::from_path(t.path()).unwrap();
        for f in [
            "src/a.test.ts",
            "src/b.test.ts",
            "src/.hidden.test.ts",
            "src/x/c.test.ts",
            "src/[id].test.ts",
        ] {
            let p = cwd.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "").unwrap();
        }
        let c = parse("node --test src/*.test.ts", &env(&[]), cwd).unwrap();
        assert_eq!(
            words(&c)[2..],
            ["src/[id].test.ts", "src/a.test.ts", "src/b.test.ts"]
        );
        // No globstar: `**` is `*`.
        let c = parse("node --test src/**/*.test.ts", &env(&[]), cwd).unwrap();
        assert_eq!(words(&c)[2..], ["src/x/c.test.ts"]);
        // No match: the word stays.
        let c = parse("node --test lib/*.test.ts 'src/*.test.ts'", &env(&[]), cwd).unwrap();
        assert_eq!(words(&c)[2..], ["lib/*.test.ts", "src/*.test.ts"]);
        let c = parse("node --test src/[ab].test.ts src/?.test.ts", &env(&[]), cwd).unwrap();
        assert_eq!(
            words(&c)[2..],
            [
                "src/a.test.ts",
                "src/b.test.ts",
                "src/a.test.ts",
                "src/b.test.ts"
            ]
        );
    }
}
