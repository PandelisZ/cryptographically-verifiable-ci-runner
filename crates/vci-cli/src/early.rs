//! `vci plan --early` (2.12.0): a plan made right after the checkout, with
//! only the vci binary, before the job installs a toolchain.
//!
//! The full plan probes the toolchain it compares with an attestation's
//! (for Rails: one Ruby process that sets up the bundle). The early plan
//! cannot: Ruby and the gems are not installed yet. For a Rails project
//! whose base policy says `toolchain = "declared"` it compares the
//! attestation's toolchain with what the checkout declares instead
//! ([`Declared`], [`toolchain_diff`]), and runs every other check of the
//! chain as the full plan does. Any project it cannot decide that way runs
//! (every other adapter, a Rails project without the setting, a declaration
//! that is missing, inexact or ambiguous). What this compares and what it
//! does not is in docs/REFERENCE.md, "The early plan".

use camino::{Utf8Path, Utf8PathBuf};
use vci_adapter::InstalledExternals;
use vci_core::Toolchain;

use crate::config::Libraries;

/// The files that may declare the Ruby version in each directory from the
/// project dir up to the repository root besides mise's config files
/// ([`version_files_in`]): rbenv, chruby, asdf and mise read them.
const RUBY_VERSION_FILES: &[&str] = &[".ruby-version", ".tool-versions"];

/// The directories of a directory whose `*.toml` files (at any depth) mise
/// reads as config: `config.toml`, `config.<env>.toml`, `config.local.toml`,
/// `mise.toml`, `conf.d/*.toml`. The early plan reads every one of them,
/// which is more than mise reads for one `MISE_ENV`: a file of another
/// environment can only make it run more.
const MISE_CONFIG_DIRS: &[&str] = &["mise", ".mise", ".config/mise"];

/// At most this many entries in [`MISE_CONFIG_DIRS`] of one directory (an
/// error past it: the unit runs).
const MISE_CONFIG_DIR_ENTRIES: usize = 1000;

/// Variables that choose the Ruby for a version manager the job's setup
/// may use (mise, rbenv, asdf, and chruby's `RUBY_VERSION`, which the
/// official Ruby images set too): each one set where the early plan runs
/// must name the declared Ruby exactly.
const RUBY_VERSION_VARS: &[&str] = &[
    "MISE_RUBY_VERSION",
    "RTX_RUBY_VERSION",
    "RBENV_VERSION",
    "ASDF_RUBY_VERSION",
    "RUBY_VERSION",
];

/// Variables that point mise at config files other than the checkout's
/// (or at none of them): set where the early plan runs, the declared Ruby
/// and the variables mise exports cannot be read from the checkout.
const MISE_CONFIG_VARS: &[&str] = &[
    "MISE_CONFIG_FILE",
    "MISE_DEFAULT_CONFIG_FILENAME",
    "MISE_DEFAULT_TOOL_VERSIONS_FILENAME",
    "MISE_OVERRIDE_CONFIG_FILENAMES",
    "MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES",
    "MISE_IGNORED_CONFIG_PATHS",
    "MISE_CEILING_PATHS",
];

/// The test frameworks the collector's probe names (`runner_version`), in
/// its order.
const RSPEC_GEMS: &[&str] = &[
    "rspec-core",
    "rspec-expectations",
    "rspec-mocks",
    "rspec-rails",
    "rspec-support",
];

/// What the checkout declares about a Rails project's toolchain.
#[derive(Debug, Clone)]
pub struct Declared {
    /// The exact Ruby version every declaring file names (`3.4.9`).
    pub ruby: Result<DeclaredRuby, String>,
    /// The project's lockfile.
    pub lock: Result<Lockfile, String>,
    /// `VERSION` of the Ruby collector this vci runs with.
    pub collector: Result<String, String>,
    /// The project is a Rails application (`config/environment.rb`): its
    /// toolchain probe sets both default encodings to UTF-8.
    pub rails_app: bool,
    /// The variables the mise files from the project dir up to the
    /// repository root set in their `[env]` (as `file: NAME`), which the
    /// job's toolchain setup exports after the early plan ran; `_.file`,
    /// `_.source` and the like name every variable they could set as
    /// `file: _.<directive>`.
    pub mise_env: Result<Vec<(String, String)>, String>,
    /// The variables `config/database.yml`'s ERB reads, by literal name
    /// ([`database_env`]): the adapters of the test environment's databases
    /// (`rubyDb`, which the full plan's probe reports) depend on nothing
    /// else but the file itself (an input of every unit) and
    /// `DATABASE_URL`/`*_DATABASE_URL` (hashed). An error: the ERB does
    /// something else the early plan cannot follow.
    pub db_env: Result<Vec<String>, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredRuby {
    pub version: String,
    /// The repository-relative files that declare it.
    pub files: Vec<String>,
}

/// What a `Gemfile.lock` pins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lockfile {
    /// Every gem of every source section (GEM, GIT, PATH, PLUGIN SOURCE),
    /// by name: its versions as the collector records them (a git source's
    /// `<version> git <revision>`), whatever platforms the lock lists.
    pub gems: InstalledExternals,
    /// `BUNDLED WITH`.
    pub bundled_with: Option<String>,
    /// `RUBY VERSION` (`3.4.9p82`, or `3.4.9`), without the `ruby ` prefix.
    pub ruby: Option<String>,
}

/// Read what the checkout declares for the Rails project in `project_dir`.
/// `bundle_gemfile`: `BUNDLE_GEMFILE` where the tests would run (a Gemfile
/// other than the project's cannot be told apart from the checkout).
pub fn declare(root: &Utf8Path, project_dir: &Utf8Path, bundle_gemfile: Option<&str>) -> Declared {
    declare_with(root, project_dir, bundle_gemfile, &|k| {
        std::env::var_os(k).map(|v| v.to_string_lossy().into_owned())
    })
}

/// [`declare`] with the environment the early plan runs in read through
/// `var`.
pub fn declare_with(
    root: &Utf8Path,
    project_dir: &Utf8Path,
    bundle_gemfile: Option<&str>,
    var: &dyn Fn(&str) -> Option<String>,
) -> Declared {
    let redirected = mise_redirected(var);
    Declared {
        ruby: match &redirected {
            Err(e) => Err(e.clone()),
            Ok(()) => declared_ruby(root, project_dir).and_then(|r| ruby_from_env(r, var)),
        },
        mise_env: match &redirected {
            Err(e) => Err(e.clone()),
            Ok(()) => mise_env(root, project_dir),
        },
        lock: match bundle_gemfile.filter(|g| !g.is_empty()) {
            Some(g) => Err(format!(
                "BUNDLE_GEMFILE is set ({g}): the early plan reads only the project's own lockfile"
            )),
            None => read_lockfile(project_dir),
        },
        collector: collector_version(project_dir),
        rails_app: project_dir.join("config/environment.rb").is_file(),
        db_env: database_env(project_dir),
    }
}

/// An error when a variable of [`MISE_CONFIG_VARS`] is set (not empty).
fn mise_redirected(var: &dyn Fn(&str) -> Option<String>) -> Result<(), String> {
    match MISE_CONFIG_VARS
        .iter()
        .find(|k| var(k).is_some_and(|v| !v.is_empty()))
    {
        Some(k) => Err(format!(
            "{k} is set: mise reads config files other than the checkout's"
        )),
        None => Ok(()),
    }
}

/// The declared Ruby `r`, checked against the variables of
/// [`RUBY_VERSION_VARS`] set where the early plan runs: each must name
/// `r`'s version exactly (they are added to its files as `$NAME`).
fn ruby_from_env(
    mut r: DeclaredRuby,
    var: &dyn Fn(&str) -> Option<String>,
) -> Result<DeclaredRuby, String> {
    for k in RUBY_VERSION_VARS {
        let Some(v) = var(k).filter(|v| !v.is_empty()) else {
            continue;
        };
        let v = exact_ruby(&v).map_err(|e| format!("${k}: {e}"))?;
        if v != r.version {
            return Err(format!(
                "the version files declare {} ({}), and ${k} says {v}",
                r.version,
                r.files.join(", ")
            ));
        }
        r.files.push(format!("${k}"));
    }
    Ok(r)
}

fn rel(root: &Utf8Path, p: &Utf8Path) -> String {
    p.strip_prefix(root)
        .map(|r| r.as_str().to_owned())
        .unwrap_or_else(|_| p.as_str().to_owned())
}

/// The exact Ruby version of `X.Y.Z` form (an optional `ruby-` prefix
/// dropped), or why not.
fn exact_ruby(v: &str) -> Result<String, String> {
    let v = v.trim();
    let v = v.strip_prefix("ruby-").unwrap_or(v);
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        Ok(v.to_owned())
    } else {
        Err(format!("{v:?} is not an exact MRI version (X.Y.Z)"))
    }
}

/// The Ruby version one file declares: `Ok(None)` when it declares none.
fn ruby_in(name: &str, text: &str) -> Result<Option<String>, String> {
    let base = name.rsplit('/').next().unwrap_or(name);
    if base == ".ruby-version" {
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'));
        return match line {
            None => Err("empty".into()),
            Some(l) => exact_ruby(l).map(Some),
        };
    }
    if base == ".tool-versions" {
        for l in text.lines() {
            let l = l.split('#').next().unwrap_or("").trim();
            let mut words = l.split_whitespace();
            if words.next() == Some("ruby") {
                return match words.next() {
                    None => Err("`ruby` without a version".into()),
                    Some(v) => exact_ruby(v).map(Some),
                };
            }
        }
        return Ok(None);
    }
    // mise TOML: [tools] ruby = "3.4.9" | ["3.4.9"] | { version = "3.4.9" }.
    let v: toml::Table = text.parse().map_err(|e| format!("not TOML: {e}"))?;
    let Some(tools) = v.get("tools") else {
        return Ok(None);
    };
    let Some(tools) = tools.as_table() else {
        return Err("[tools] is not a table".into());
    };
    let mut found = None;
    for (k, val) in tools {
        if k != "ruby" && k != "core:ruby" {
            continue;
        }
        let one = |val: &toml::Value| -> Result<String, String> {
            match val {
                toml::Value::String(s) => exact_ruby(s),
                toml::Value::Table(t) => match t.get("version") {
                    Some(toml::Value::String(s)) => exact_ruby(s),
                    _ => Err(format!("{k} = {val} has no version string")),
                },
                _ => Err(format!("{k} = {val} is not a version")),
            }
        };
        let v = match val {
            toml::Value::Array(a) if a.len() == 1 => one(&a[0])?,
            toml::Value::Array(_) => {
                return Err(format!("{k} = {val} names several versions"));
            }
            other => one(other)?,
        };
        if found.as_ref().is_some_and(|f| f != &v) {
            return Err(format!("{k} names {v}, and another key another version"));
        }
        found = Some(v);
    }
    Ok(found)
}

/// The `[env]` keys of a mise TOML file (`Ok(empty)` for any other file).
fn mise_env_in(name: &str, text: &str) -> Result<Vec<String>, String> {
    let base = name.rsplit('/').next().unwrap_or(name);
    if base == ".ruby-version" || base == ".tool-versions" {
        return Ok(Vec::new());
    }
    let v: toml::Table = text.parse().map_err(|e| format!("not TOML: {e}"))?;
    let Some(env) = v.get("env") else {
        return Ok(Vec::new());
    };
    let env = env.as_table().ok_or("[env] is not a table")?;
    let mut out = Vec::new();
    for (k, val) in env {
        if k == "_" {
            // mise's directives: `_.path`, `_.file`, `_.source`, ...
            match val.as_table() {
                Some(t) => out.extend(t.keys().map(|d| format!("_.{d}"))),
                None => out.push("_".to_owned()),
            }
        } else {
            out.push(k.clone());
        }
    }
    Ok(out)
}

/// The `[env]` keys of every mise file from the project dir up to the
/// repository root ([`version_files_in`]), as `(file, key)`.
pub fn mise_env(root: &Utf8Path, project_dir: &Utf8Path) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut dir = Some(project_dir);
    while let Some(d) = dir {
        for f in version_files_in(d)? {
            if !f.is_file() {
                continue;
            }
            let r = rel(root, &f);
            let text = std::fs::read_to_string(&f).map_err(|e| format!("{r}: {e}"))?;
            let keys = mise_env_in(f.as_str(), &text).map_err(|e| format!("{r}: {e}"))?;
            out.extend(keys.into_iter().map(|k| (r.clone(), k)));
        }
        if d == root || !d.starts_with(root) {
            break;
        }
        dir = d.parent();
    }
    Ok(out)
}

/// Whether mise reads a file of this name as config in a project directory
/// or in its `.config/`: `mise.toml`, `mise.local.toml`,
/// `mise.<env>.toml`, `mise.<env>.local.toml`, each also with a leading dot.
fn mise_file_name(n: &str) -> bool {
    let stem = n.strip_prefix('.').unwrap_or(n);
    stem.starts_with("mise.") && stem.ends_with(".toml")
}

/// The files of `dir` that may declare Ruby or export variables:
/// [`RUBY_VERSION_FILES`], mise's config files beside them and in
/// `.config/` ([`mise_file_name`]), and every `*.toml` in
/// [`MISE_CONFIG_DIRS`] (at any depth). An error when a directory cannot be
/// listed or holds too many entries.
fn version_files_in(dir: &Utf8Path) -> Result<Vec<Utf8PathBuf>, String> {
    let mut out: Vec<Utf8PathBuf> = RUBY_VERSION_FILES.iter().map(|n| dir.join(n)).collect();
    for d in [dir.to_owned(), dir.join(".config")] {
        let rd = match d.read_dir_utf8() {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => continue,
            Err(e) => return Err(format!("listing {d}: {e}")),
        };
        let mut names: Vec<Utf8PathBuf> = Vec::new();
        for e in rd {
            let e = e.map_err(|e| format!("listing {d}: {e}"))?;
            if mise_file_name(e.file_name()) {
                names.push(d.join(e.file_name()));
            }
        }
        names.sort();
        out.extend(names);
    }
    for sub in MISE_CONFIG_DIRS {
        let top = dir.join(sub);
        if !top.is_dir() {
            continue;
        }
        let mut stack = vec![top.clone()];
        let mut found = Vec::new();
        let mut n = 0usize;
        while let Some(d) = stack.pop() {
            let rd = d.read_dir_utf8().map_err(|e| format!("listing {d}: {e}"))?;
            for e in rd {
                let e = e.map_err(|e| format!("listing {d}: {e}"))?;
                n += 1;
                if n > MISE_CONFIG_DIR_ENTRIES {
                    return Err(format!(
                        "{top} holds more than {MISE_CONFIG_DIR_ENTRIES} entries"
                    ));
                }
                let p = e.path().to_owned();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension() == Some("toml") {
                    found.push(p);
                }
            }
        }
        found.sort();
        out.extend(found);
    }
    Ok(out)
}

/// The identifiers `config/database.yml`'s ERB may use besides its own
/// local variables and `ENV` read by a literal name: Ruby's literals and
/// keywords and the methods of strings, numbers and arrays that compute a
/// value from what they are given.
const DB_ERB_WORDS: &[&str] = &[
    "nil", "true", "false", "if", "unless", "else", "elsif", "end", "then", "and", "or", "not",
    "fetch", "presence", "present?", "blank?", "empty?", "nil?", "to_i", "to_s", "to_f", "to_sym",
    "max", "min", "strip", "downcase", "upcase", "split", "first", "last",
];

/// The variables `config/database.yml` (in `project_dir`) reads in its ERB,
/// by literal name (`ENV["X"]`, `ENV.fetch("X"...)`, `ENV.key?("X")`), or
/// why the early plan cannot tell what its ERB depends on: `ENV` used any
/// other way, an interpolated string, a global, instance or class variable,
/// a constant path, a shell command, a `%` literal, or an identifier that is
/// none of [`DB_ERB_WORDS`] and no local variable the file assigns (the
/// application's code, `File`, `Rails`, ...). No such file: no variable.
pub fn database_env(project_dir: &Utf8Path) -> Result<Vec<String>, String> {
    let path = project_dir.join("config/database.yml");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("config/database.yml: {e}")),
    };
    erb_env(&text).map_err(|e| format!("config/database.yml: {e}"))
}

/// The Ruby code of each ERB tag of `text` (`<%`, `<%=`, `<%-`; not `<%%`
/// or `<%#`).
fn erb_tags(text: &str) -> Result<Vec<&str>, String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("<%") {
        let after = &rest[i + 2..];
        if let Some(a) = after.strip_prefix('%') {
            rest = a;
            continue;
        }
        let end = after.find("%>").ok_or("an ERB tag is not closed")?;
        let code = &after[..end];
        rest = &after[end + 2..];
        if code.starts_with('#') {
            continue;
        }
        let code = code.strip_prefix(['=', '-']).unwrap_or(code);
        out.push(code.strip_suffix('-').unwrap_or(code));
    }
    Ok(out)
}

/// One Ruby string literal at the start of `s` (`"..."` without `#{`, or
/// `'...'`): its text and the rest of `s`.
fn ruby_string(s: &str) -> Option<(&str, &str)> {
    let q = s.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let body = &s[1..];
    let mut esc = false;
    for (i, c) in body.char_indices() {
        if esc {
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == q {
            let lit = &body[..i];
            if q == '"' && lit.contains("#{") {
                return None;
            }
            return Some((lit, &body[i + 1..]));
        }
    }
    None
}

fn erb_env(text: &str) -> Result<Vec<String>, String> {
    let tags = erb_tags(text)?;
    let ident = |s: &str| -> usize {
        let n = s
            .char_indices()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
            .map_or(s.len(), |(i, _)| i);
        if s[n..].starts_with(['?', '!']) && !s[n..].starts_with("!=") {
            n + 1
        } else {
            n
        }
    };
    // The local variables the tags assign (`name = ...`).
    let mut locals: Vec<&str> = Vec::new();
    for code in &tags {
        let mut s = code.trim_start();
        while !s.is_empty() {
            let c = s.chars().next().unwrap();
            if c.is_ascii_lowercase() || c == '_' {
                let n = ident(s);
                let (name, rest) = s.split_at(n);
                let r = rest.trim_start();
                if r.starts_with('=')
                    && !r.starts_with("==")
                    && !r.starts_with("=~")
                    && !r.starts_with("=>")
                {
                    locals.push(name);
                }
                s = rest;
            } else {
                s = &s[c.len_utf8()..];
            }
        }
    }
    let mut vars = Vec::new();
    for code in &tags {
        let mut s: &str = code;
        while let Some(c) = s.chars().next() {
            if c.is_whitespace() {
                s = &s[c.len_utf8()..];
            } else if c == '"' || c == '\'' {
                let (_, rest) = ruby_string(s).ok_or_else(|| {
                    format!("an interpolated or unclosed string in its ERB: {code:?}")
                })?;
                s = rest;
            } else if c.is_ascii_digit() {
                let n = s
                    .find(|c: char| !(c.is_ascii_digit() || c == '_' || c == '.'))
                    .unwrap_or(s.len());
                s = &s[n..];
            } else if c.is_ascii_alphabetic() || c == '_' {
                let n = ident(s);
                let word = &s[..n];
                s = &s[n..];
                if word == "ENV" {
                    let lit = if let Some(r) = s.strip_prefix('[') {
                        ruby_string(r.trim_start())
                            .and_then(|(l, r)| r.trim_start().strip_prefix(']').map(|r| (l, r)))
                    } else if let Some(r) = s.strip_prefix('.') {
                        let m = ident(r);
                        if ["fetch", "key?", "has_key?", "include?", "member?"].contains(&&r[..m]) {
                            r[m..]
                                .trim_start()
                                .strip_prefix('(')
                                .and_then(|r| ruby_string(r.trim_start()))
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let (name, rest) = lit.ok_or_else(|| {
                        format!("its ERB uses ENV other than by a literal name: {code:?}")
                    })?;
                    vars.push(name.to_owned());
                    s = rest;
                } else if !DB_ERB_WORDS.contains(&word) && !locals.contains(&word) {
                    return Err(format!(
                        "its ERB uses `{word}`, which the early plan cannot follow: {code:?}"
                    ));
                }
            } else if c == ':' && s.starts_with("::") {
                return Err(format!("its ERB names a constant path: {code:?}"));
            } else if c == '%' && s[1..].starts_with(|c: char| !c.is_whitespace()) {
                return Err(format!("its ERB uses a % literal: {code:?}"));
            } else if matches!(c, '$' | '@' | '`') {
                return Err(format!("its ERB uses `{c}`: {code:?}"));
            } else {
                s = &s[c.len_utf8()..];
            }
        }
    }
    vars.sort();
    vars.dedup();
    Ok(vars)
}

/// The exact Ruby version the checkout declares for the project: every
/// file from the project dir up to the repository root that declares one
/// ([`version_files_in`]) must name the same `X.Y.Z`; none, a version that
/// is not exact, an unreadable file or two different versions is an error
/// (the early plan cannot tell which one the job installs).
pub fn declared_ruby(root: &Utf8Path, project_dir: &Utf8Path) -> Result<DeclaredRuby, String> {
    let mut found: Vec<(String, String)> = Vec::new();
    let mut dir = Some(project_dir);
    while let Some(d) = dir {
        for f in version_files_in(d)? {
            if !f.is_file() {
                continue;
            }
            let r = rel(root, &f);
            let text = std::fs::read_to_string(&f).map_err(|e| format!("{r}: {e}"))?;
            if let Some(v) = ruby_in(f.as_str(), &text).map_err(|e| format!("{r}: {e}"))? {
                found.push((r, v));
            }
        }
        if d == root || !d.starts_with(root) {
            break;
        }
        dir = d.parent();
    }
    let Some((_, first)) = found.first() else {
        return Err(
            "no file declares the Ruby version (.ruby-version, .tool-versions or mise.toml, from the project up to the repository root)"
                .into(),
        );
    };
    if let Some((f, v)) = found.iter().find(|(_, v)| v != first) {
        return Err(format!(
            "the files that declare Ruby disagree: {} says {first}, {f} says {v}",
            found[0].0
        ));
    }
    Ok(DeclaredRuby {
        version: first.clone(),
        files: found.into_iter().map(|(f, _)| f).collect(),
    })
}

/// The project's lockfile (`Gemfile.lock`, or `gems.locked` beside a
/// `gems.rb` without a `Gemfile`), parsed.
fn read_lockfile(project_dir: &Utf8Path) -> Result<Lockfile, String> {
    let name = if !project_dir.join("Gemfile").is_file() && project_dir.join("gems.rb").is_file() {
        "gems.locked"
    } else {
        "Gemfile.lock"
    };
    let text =
        std::fs::read_to_string(project_dir.join(name)).map_err(|e| format!("{name}: {e}"))?;
    parse_lockfile(&text).map_err(|e| format!("{name}: {e}"))
}

/// Parse a Bundler lockfile: the specs of its source sections, `BUNDLED
/// WITH` and `RUBY VERSION`. A spec line is `    name (version)` or
/// `    name (version-platform)`; a git source's specs carry its
/// `revision:` as the collector records them (`<version> git <revision>`).
pub fn parse_lockfile(text: &str) -> Result<Lockfile, String> {
    let mut out = Lockfile::default();
    let mut section = "";
    let mut revision: Option<String> = None;
    let mut in_specs = false;
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            section = match line {
                "GEM" | "GIT" | "PATH" | "PLUGIN SOURCE" | "PLATFORMS" | "DEPENDENCIES"
                | "CHECKSUMS" | "RUBY VERSION" | "BUNDLED WITH" => line,
                _ => "other",
            };
            revision = None;
            in_specs = false;
            continue;
        }
        match section {
            "GEM" | "GIT" | "PATH" | "PLUGIN SOURCE" => {
                if let Some(r) = line.strip_prefix("  revision: ") {
                    revision = Some(r.trim().to_owned());
                } else if line == "  specs:" {
                    in_specs = true;
                } else if in_specs && line.starts_with("    ") && !line.starts_with("     ") {
                    let spec = &line[4..];
                    let (name, rest) = spec
                        .split_once(" (")
                        .ok_or_else(|| format!("line {}: not a spec: {spec:?}", n + 1))?;
                    let full = rest
                        .strip_suffix(')')
                        .ok_or_else(|| format!("line {}: not a spec: {spec:?}", n + 1))?;
                    // RubyGems versions hold no `-`: what follows is the
                    // platform of a native build.
                    let version = full.split_once('-').map_or(full, |(v, _)| v);
                    if name.is_empty() || version.is_empty() {
                        return Err(format!("line {}: not a spec: {spec:?}", n + 1));
                    }
                    let recorded = match (section, &revision) {
                        ("GIT", Some(r)) => format!("{version} git {r}"),
                        ("GIT", None) => {
                            return Err(format!("line {}: a git source without a revision", n + 1));
                        }
                        _ => version.to_owned(),
                    };
                    let vs = out.gems.entry(name.to_owned()).or_default();
                    if !vs.contains(&recorded) {
                        vs.push(recorded);
                    }
                }
            }
            "BUNDLED WITH" => {
                out.bundled_with = Some(line.trim().to_owned());
            }
            "RUBY VERSION" => {
                let v = line.trim();
                out.ruby = Some(v.strip_prefix("ruby ").unwrap_or(v).to_owned());
            }
            _ => {}
        }
    }
    Ok(out)
}

/// `VERSION` of the Ruby collector this vci runs the project with (read
/// from `vci_collector.rb`, as `VERSION = "0.5.0"`).
pub fn collector_version(project_dir: &Utf8Path) -> Result<String, String> {
    let dir = vci_adapter::find_ruby_collector(project_dir).map_err(|e| e.to_string())?;
    let text = std::fs::read_to_string(dir.join("vci_collector.rb"))
        .map_err(|e| format!("{dir}/vci_collector.rb: {e}"))?;
    text.lines()
        .find_map(|l| {
            let v = l.trim().strip_prefix("VERSION = \"")?;
            v.strip_suffix('"').map(str::to_owned)
        })
        .ok_or_else(|| format!("{dir}/vci_collector.rb names no VERSION"))
}

/// The test frameworks of the bundle as the collector's probe names them
/// (`minitest 6.0.6; rspec-core 3.13.6, ...`), from the lock.
fn declared_runner(lock: &Lockfile) -> Result<String, String> {
    let one = |n: &str| -> Result<Option<&str>, String> {
        match lock.gems.get(n).map(Vec::as_slice) {
            None | Some([]) => Ok(None),
            Some([v]) => Ok(Some(v.as_str())),
            Some(vs) => Err(format!(
                "the lock pins {n} in several versions: {}",
                vs.join(", ")
            )),
        }
    };
    let mut parts = Vec::new();
    if let Some(v) = one("minitest")? {
        parts.push(format!("minitest {v}"));
    }
    let mut rs = Vec::new();
    for n in RSPEC_GEMS {
        if let Some(v) = one(n)? {
            rs.push(format!("{n} {v}"));
        }
    }
    if !rs.is_empty() {
        parts.push(rs.join(", "));
    }
    Ok(parts.join("; "))
}

/// `key=value` of a `ruby_libs` value.
fn lib_item<'a>(libs: &'a str, key: &str) -> Option<&'a str> {
    libs.split(';')
        .find_map(|i| i.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v))
}

/// The row an undecidable fact fails with.
const UNDECIDED: &str = "early plan: cannot decide without the toolchain";

/// What the early plan's toolchain check finds different between the
/// attested toolchain `tc` and what the checkout declares, as `(what,
/// expected, actual)` (expected: the attestation's, actual: here). It
/// replaces the full plan's toolchain and platform checks for a project
/// whose base policy says `toolchain = "declared"`:
///
/// - the operating system and architecture are the same (whatever
///   `policy.platform` accepts: the bundle Bundler resolves, the gems'
///   native builds and Ruby's own build are per platform);
/// - who runs the tests (root or not), unless the base policy sets
///   `allow_superuser_mismatch`;
/// - Ruby: `X.Y.Zp<patchlevel>` and `ruby X.Y.Z` for the exact version
///   every version file declares (and the lock's `RUBY VERSION`, when it
///   has one), MRI only;
/// - Bundler: the lock's `BUNDLED WITH`;
/// - Rails: the lock's `railties`; the test frameworks: the lock's
///   `minitest` and `rspec-*`;
/// - the bundle: every gem the attestation's toolchain lists
///   (`name==version`) is pinned by the lock in that version (Bundler
///   itself: `BUNDLED WITH`);
/// - the libraries: under `libraries = "exact"` their versions cannot be
///   read without Ruby (undecided: the unit runs); under "any" the
///   encodings must be what a Rails application's probe reports (UTF-8 for
///   both), the time zone data loaded exactly when the lock has `tzinfo`,
///   SQLite loaded only when it has `sqlite3`, and the collector this vci's;
/// - the database adapters (`rubyDb`) are not compared: the probe reads
///   them from `config/database.yml` (an input of every unit) with its
///   ERB, and `DATABASE_URL`/`*_DATABASE_URL` (hashed). The ERB may read
///   variables ([`database_env`]): each one must be fixed for the tests
///   (`set`), compared (`hash`, built-in hash) or kept from them (strict
///   mode removes every other one), which `db_var_decided` says; one passed
///   to the tests uncompared (`ignore`) could pick another adapter, and ERB
///   the early plan cannot follow could read anything: the unit runs.
///
/// Any declaration that could not be read is a difference (the unit runs).
pub fn toolchain_diff(
    allow_superuser_mismatch: bool,
    libraries: Libraries,
    tc: &Toolchain,
    d: &Declared,
    compared_env: &dyn Fn(&str) -> bool,
    db_var_decided: &dyn Fn(&str) -> bool,
) -> Vec<(&'static str, String, String)> {
    let mut out = Vec::new();
    match &d.db_env {
        Ok(vars) => {
            let open: Vec<&str> = vars
                .iter()
                .map(String::as_str)
                .filter(|k| !db_var_decided(k))
                .collect();
            if !open.is_empty() {
                out.push((
                    UNDECIDED,
                    format!("database adapters {:?}", tc.ruby_db),
                    format!(
                        "config/database.yml reads {}, which the env policy passes to the tests without comparing it",
                        open.join(", ")
                    ),
                ));
            }
        }
        Err(e) => out.push((
            UNDECIDED,
            format!("database adapters {:?}", tc.ruby_db),
            e.clone(),
        )),
    }
    // A variable the toolchain setup exports after the early plan (mise's
    // `[env]`) that the project's env policy compares: the early plan sees
    // the environment without it. A directive (`_.file`) could set any.
    match &d.mise_env {
        Ok(keys) => {
            let set: Vec<String> = keys
                .iter()
                .filter(|(_, k)| k.starts_with('_') || compared_env(k))
                .map(|(f, k)| format!("{f}: {k}"))
                .collect();
            if !set.is_empty() {
                out.push((
                    UNDECIDED,
                    "the environment the tests run with".into(),
                    format!(
                        "mise sets variables the env policy compares, after the early plan: {}",
                        set.join(", ")
                    ),
                ));
            }
        }
        Err(e) => out.push((UNDECIDED, "the mise files' [env]".into(), e.clone())),
    }
    let os_arch = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    if tc.os != std::env::consts::OS || tc.arch != std::env::consts::ARCH {
        out.push((
            "platform (the early plan takes the declared toolchain only for an attestation made on this platform)",
            format!("{}-{}", tc.os, tc.arch),
            os_arch,
        ));
    }
    let root = crate::run::running_as_root();
    if !allow_superuser_mismatch && tc.superuser != root {
        out.push((
            vci_core::PRIVILEGES_DIFF,
            if tc.superuser { "root" } else { "not root" }.to_owned(),
            if root { "root" } else { "not root" }.to_owned(),
        ));
    }
    if !d.rails_app {
        out.push((
            UNDECIDED,
            "a Rails application".into(),
            "no config/environment.rb: the encodings a plain Ruby project's tests get depend on the environment".into(),
        ));
    }
    match &d.ruby {
        Ok(r) => {
            let patch = tc
                .ruby
                .strip_prefix(&r.version)
                .and_then(|p| p.strip_prefix('p'));
            if patch.is_none_or(|p| p.is_empty()) {
                out.push((
                    "ruby (declared)",
                    tc.ruby.clone(),
                    format!("{}p* ({})", r.version, r.files.join(", ")),
                ));
            }
            let engine = format!("ruby {}", r.version);
            if tc.ruby_engine != engine {
                out.push(("ruby engine (declared)", tc.ruby_engine.clone(), engine));
            }
        }
        Err(e) => out.push(("ruby (declared)", tc.ruby.clone(), e.clone())),
    }
    let lock = match &d.lock {
        Ok(l) => l,
        Err(e) => {
            out.push(("bundle (declared)", "the lockfile".into(), e.clone()));
            return out;
        }
    };
    if let Some(lr) = &lock.ruby {
        let same = if lr.contains('p') {
            *lr == tc.ruby
        } else {
            tc.ruby
                .strip_prefix(lr.as_str())
                .is_some_and(|p| p.starts_with('p'))
        };
        if !same {
            out.push((
                "ruby (RUBY VERSION of the lockfile)",
                tc.ruby.clone(),
                lr.clone(),
            ));
        }
    }
    match &lock.bundled_with {
        Some(b) if *b == tc.bundler => {}
        Some(b) => out.push(("bundler (BUNDLED WITH)", tc.bundler.clone(), b.clone())),
        None => out.push((
            "bundler (BUNDLED WITH)",
            tc.bundler.clone(),
            "the lockfile has no BUNDLED WITH".into(),
        )),
    }
    let rails = match lock.gems.get("railties").map(Vec::as_slice) {
        None | Some([]) => String::new(),
        Some([v]) => v.clone(),
        Some(vs) => vs.join(", "),
    };
    if tc.rails != rails {
        out.push(("rails (railties in the lockfile)", tc.rails.clone(), rails));
    }
    match declared_runner(lock) {
        Ok(r) if r == tc.ruby_test => {}
        Ok(r) => out.push(("ruby test framework (lockfile)", tc.ruby_test.clone(), r)),
        Err(e) => out.push(("ruby test framework (lockfile)", tc.ruby_test.clone(), e)),
    }
    let not_locked: Vec<&str> = tc
        .ruby_gems
        .iter()
        .filter(|g| {
            let Some((n, v)) = g.split_once("==") else {
                return true;
            };
            if n == "bundler" {
                return lock.bundled_with.as_deref() != Some(v);
            }
            !lock.gems.get(n).is_some_and(|vs| vs.iter().any(|x| x == v))
        })
        .map(String::as_str)
        .collect();
    if tc.ruby_gems.is_empty() {
        out.push((
            "gems (bundle)",
            "no bundle recorded".into(),
            "the early plan compares the attested bundle with the lockfile".into(),
        ));
    } else if !not_locked.is_empty() {
        out.push((
            "gems (bundle) not pinned so by the lockfile",
            not_locked.join(", "),
            "absent or another version in the lockfile".into(),
        ));
    }
    match libraries {
        Libraries::Exact => out.push((
            UNDECIDED,
            format!("ruby libraries {}", tc.ruby_libs),
            "their versions are read by Ruby (policy.libraries = \"any\" does not compare them)"
                .into(),
        )),
        Libraries::Any => {
            let mut known = 0;
            let enc = lib_item(&tc.ruby_libs, "encoding");
            if enc.is_some() {
                known += 1;
            }
            if enc != Some("UTF-8/UTF-8") {
                out.push((
                    "ruby libraries: encoding (a Rails application's probe sets UTF-8)",
                    enc.unwrap_or("none").to_owned(),
                    "UTF-8/UTF-8".into(),
                ));
            }
            let tz = lib_item(&tc.ruby_libs, "tz");
            if tz.is_some() {
                known += 1;
            }
            let tz_loaded = tz.is_some_and(|v| !v.is_empty());
            if tz_loaded != lock.gems.contains_key("tzinfo") {
                out.push((
                    "ruby libraries: tz loaded (TZInfo is loaded when the bundle has tzinfo)",
                    if tz_loaded { "loaded" } else { "not loaded" }.into(),
                    if lock.gems.contains_key("tzinfo") {
                        "tzinfo in the lockfile"
                    } else {
                        "no tzinfo in the lockfile"
                    }
                    .into(),
                ));
            }
            let sqlite = lib_item(&tc.ruby_libs, "sqlite");
            if sqlite.is_some() {
                known += 1;
            }
            // Loaded exactly when the bundle has sqlite3 (the full plan
            // compares whether it is loaded): loaded without sqlite3 in the
            // lock differs; not loaded with it cannot be told apart from a
            // probe that did not load it (undecided).
            let sqlite_loaded = sqlite.is_some_and(|v| !v.is_empty() && v != "none");
            match (sqlite_loaded, lock.gems.contains_key("sqlite3")) {
                (true, false) => out.push((
                    "ruby libraries: sqlite loaded",
                    "loaded".into(),
                    "no sqlite3 in the lockfile".into(),
                )),
                (false, true) => out.push((
                    UNDECIDED,
                    "ruby libraries: sqlite not loaded".into(),
                    "sqlite3 is in the lockfile: whether the probe loads it is Ruby's to say"
                        .into(),
                )),
                _ => {}
            }
            // libyaml comes with the Ruby the job installs: taken as loaded
            // only when the attestation recorded it loaded (its version is
            // not compared under "any"); not loaded there, the unit runs.
            let yaml = lib_item(&tc.ruby_libs, "yaml");
            if yaml.is_some() {
                known += 1;
            }
            if !yaml.is_some_and(|v| !v.is_empty() && v != "none") {
                out.push((
                    UNDECIDED,
                    "ruby libraries: yaml not loaded".into(),
                    "whether the Ruby the job installs loads libyaml is Ruby's to say".into(),
                ));
            }
            let collector = lib_item(&tc.ruby_libs, "collector");
            if collector.is_some() {
                known += 1;
            }
            match &d.collector {
                Ok(c) if collector == Some(c.as_str()) => {}
                Ok(c) => out.push((
                    "ruby libraries: collector",
                    collector.unwrap_or("none").to_owned(),
                    c.clone(),
                )),
                Err(e) => out.push((
                    "ruby libraries: collector",
                    collector.unwrap_or("none").to_owned(),
                    e.clone(),
                )),
            }
            let items = tc.ruby_libs.split(';').filter(|i| !i.is_empty()).count();
            if items != known {
                out.push((
                    UNDECIDED,
                    format!("ruby libraries {}", tc.ruby_libs),
                    "an item the early plan does not know".into(),
                ));
            }
        }
    }
    out
}

/// The early plan's check of a native library an attestation records
/// (`native:<file name>`): the library comes from the system packages the
/// job installs after the early plan, so only `libraries = "any"` (which
/// compares it by library name, not by file and hash) lets the early plan
/// take it as declared; under "exact" the unit runs.
pub fn native(name: &str, libraries: Libraries) -> Result<Option<String>, String> {
    match libraries {
        Libraries::Any => Ok(Some(format!(
            "not compared by the early plan (policy.toolchain = \"declared\"): the job's setup provides {}, which the full plan requires loaded",
            crate::externals::native_stem(name)
        ))),
        Libraries::Exact => Err(format!(
            "{UNDECIDED}: native library {} is compared by file and hash (policy.libraries = \"exact\")",
            crate::externals::native_stem(name)
        )),
    }
}

/// The gems a lockfile pins, as the externals check reads a bundle: with
/// Bundler itself in its `BUNDLED WITH` version (the bundle Bundler
/// resolves holds it; a lockfile does not list it).
pub fn lock_gems(d: &Declared) -> Result<InstalledExternals, String> {
    let l = d
        .lock
        .as_ref()
        .map_err(|e| format!("the early plan reads the lockfile: {e}"))?;
    let mut gems = l.gems.clone();
    if let Some(b) = &l.bundled_with {
        gems.entry("bundler".to_owned())
            .or_insert_with(|| vec![b.clone()]);
    }
    Ok(gems)
}

/// Why the early plan cannot decide a project, or `None` when it can (a
/// Rails project whose base policy says `toolchain = "declared"`).
pub fn undecidable(adapter: &str, toolchain: crate::config::ToolchainTrust) -> Option<String> {
    match (adapter, toolchain) {
        ("rails", crate::config::ToolchainTrust::Declared) => None,
        ("rails", _) => Some(
            "early plan: the toolchain must be probed (policy.toolchain = \"declared\" is not set in the base vci.toml)"
                .into(),
        ),
        (a, _) => Some(format!(
            "early plan: a {a} project's toolchain must be probed (only Rails projects with policy.toolchain = \"declared\" are decided before the toolchain is set up)"
        )),
    }
}

/// The early plan's answer for the units it lists (`skip_all`: every unit
/// is skipped and no project runs everything), with the counts.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EarlyAnswer {
    pub skip_all: bool,
    pub skipped: usize,
    pub run: usize,
    /// `--partition I/N`: the answer is for this partition's share.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    /// Why something may run (the first project that runs everything, or
    /// the count of units to run); `None` when everything skips.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

/// The parsed declarations by project dir, for tests.
#[cfg(test)]
pub fn by_name(l: &Lockfile) -> InstalledExternals {
    l.gems.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = "GIT
  remote: https://github.com/x/y.git
  revision: 0123456789abcdef0123456789abcdef01234567
  branch: main
  specs:
    y (0.3.0)
      rack (>= 2)

GEM
  remote: https://rubygems.org/
  specs:
    minitest (5.25.4)
    nokogiri (1.18.10-arm64-darwin)
      racc (~> 1.4)
    nokogiri (1.18.10-x86_64-linux-gnu)
      racc (~> 1.4)
    racc (1.8.1)
    rack (3.2.7)
    railties (8.1.3.1)
    sqlite3 (2.8.0-x86_64-linux-gnu)
    tzinfo (2.0.6)

PATH
  remote: engines/z
  specs:
    z (0.1.0)

PLATFORMS
  arm64-darwin
  x86_64-linux

DEPENDENCIES
  nokogiri
  y!

CHECKSUMS
  minitest (5.25.4) sha256=00

RUBY VERSION
   ruby 3.4.9p82

BUNDLED WITH
   2.7.2
";

    #[test]
    fn a_lockfile_parses_into_versions_as_the_collector_records_them() {
        let l = parse_lockfile(LOCK).unwrap();
        let g = by_name(&l);
        assert_eq!(g["nokogiri"], vec!["1.18.10"]);
        assert_eq!(
            g["y"],
            vec!["0.3.0 git 0123456789abcdef0123456789abcdef01234567"]
        );
        assert_eq!(g["z"], vec!["0.1.0"]);
        assert_eq!(g["sqlite3"], vec!["2.8.0"]);
        assert!(!g.contains_key("racc (~> 1.4)"));
        assert_eq!(l.bundled_with.as_deref(), Some("2.7.2"));
        assert_eq!(l.ruby.as_deref(), Some("3.4.9p82"));
        assert_eq!(declared_runner(&l).unwrap(), "minitest 5.25.4");
        assert!(parse_lockfile("GEM\n  specs:\n    broken\n").is_err());
    }

    #[test]
    fn ruby_versions_are_read_from_each_kind_of_file() {
        assert_eq!(
            ruby_in(".ruby-version", "ruby-3.4.9\n").unwrap().as_deref(),
            Some("3.4.9")
        );
        assert!(ruby_in(".ruby-version", "3.4\n").is_err());
        assert_eq!(
            ruby_in(".tool-versions", "nodejs 22.1.0\nruby 3.4.9 3.3.1\n")
                .unwrap()
                .as_deref(),
            Some("3.4.9")
        );
        assert_eq!(ruby_in(".tool-versions", "nodejs 22.1.0\n").unwrap(), None);
        assert_eq!(
            ruby_in("mise.toml", "[tools]\nruby = \"3.4.9\"\nnode = \"22\"\n")
                .unwrap()
                .as_deref(),
            Some("3.4.9")
        );
        assert_eq!(
            ruby_in("mise.toml", "[tools]\nruby = { version = \"3.4.9\" }\n")
                .unwrap()
                .as_deref(),
            Some("3.4.9")
        );
        assert!(ruby_in("mise.toml", "[tools]\nruby = \"latest\"\n").is_err());
        assert!(ruby_in("mise.toml", "[tools]\nruby = [\"3.4.9\", \"3.3.1\"]\n").is_err());
        assert_eq!(ruby_in("mise.toml", "[env]\nX = \"1\"\n").unwrap(), None);
    }

    fn write(dir: &Utf8Path, name: &str, text: &str) {
        let p = dir.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    #[test]
    fn every_declaring_file_must_agree() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(t.path()).unwrap();
        let app = root.join("app");
        assert!(declared_ruby(root, &app).is_err(), "nothing declared");
        write(root, "mise.toml", "[tools]\nruby = \"3.4.9\"\n");
        write(&app, ".ruby-version", "3.4.9\n");
        let d = declared_ruby(root, &app).unwrap();
        assert_eq!(d.version, "3.4.9");
        assert_eq!(d.files, vec!["app/.ruby-version", "mise.toml"]);
        write(root, "mise.ci.toml", "[tools]\nruby = \"3.4.8\"\n");
        let e = declared_ruby(root, &app).unwrap_err();
        assert!(e.contains("mise.ci.toml says 3.4.8"), "{e}");
    }

    fn tc() -> Toolchain {
        Toolchain {
            ruby: "3.4.9p82".into(),
            ruby_engine: "ruby 3.4.9".into(),
            rails: "8.1.3.1".into(),
            bundler: "2.7.2".into(),
            ruby_test: "minitest 5.25.4".into(),
            ruby_libs:
                "sqlite=3.50.4;yaml=0.2.5;tz=zoneinfo 2025b;encoding=UTF-8/UTF-8;collector=0.5.0"
                    .into(),
            ruby_db: "sqlite3".into(),
            ruby_gems: vec![
                "bundler==2.7.2".into(),
                "nokogiri==1.18.10".into(),
                "rack==3.2.7".into(),
                "railties==8.1.3.1".into(),
            ],
            superuser: crate::run::running_as_root(),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            ..Default::default()
        }
    }

    fn declared() -> Declared {
        Declared {
            ruby: Ok(DeclaredRuby {
                version: "3.4.9".into(),
                files: vec![".ruby-version".into()],
            }),
            lock: parse_lockfile(LOCK),
            collector: Ok("0.5.0".into()),
            rails_app: true,
            mise_env: Ok(vec![("mise.toml".into(), "CARGO_TARGET_DIR".into())]),
            db_env: Ok(vec!["RAILS_MAX_THREADS".into()]),
        }
    }

    fn no_env(k: &str) -> bool {
        k.starts_with("RUBY")
    }

    #[test]
    fn the_declared_toolchain_matches_only_what_the_checkout_declares() {
        let d = declared();
        assert!(toolchain_diff(false, Libraries::Any, &tc(), &d, &no_env, &|_| true).is_empty());
        // Every library version is read by Ruby: undecided under "exact".
        let whats: Vec<&str> =
            toolchain_diff(false, Libraries::Exact, &tc(), &d, &no_env, &|_| true)
                .into_iter()
                .map(|x| x.0)
                .collect();
        assert_eq!(whats, vec![UNDECIDED]);
        type Edit = fn(&mut Toolchain);
        let cases: Vec<(&str, Edit)> = vec![
            ("ruby (declared)", |t| t.ruby = "3.4.8p72".into()),
            ("ruby engine (declared)", |t| {
                t.ruby_engine = "jruby 9.4.0".into()
            }),
            ("bundler (BUNDLED WITH)", |t| t.bundler = "2.6.9".into()),
            ("rails (railties in the lockfile)", |t| {
                t.rails = "8.0.0".into()
            }),
            ("ruby test framework (lockfile)", |t| {
                t.ruby_test = "minitest 6.0.0".into()
            }),
            ("gems (bundle) not pinned so by the lockfile", |t| {
                t.ruby_gems.push("pg==1.6.0".into())
            }),
            ("gems (bundle)", |t| t.ruby_gems.clear()),
            ("ruby libraries: collector", |t| {
                t.ruby_libs = t.ruby_libs.replace("collector=0.5.0", "collector=0.4.0")
            }),
            (
                "ruby libraries: encoding (a Rails application's probe sets UTF-8)",
                |t| t.ruby_libs = t.ruby_libs.replace("UTF-8/UTF-8", "US-ASCII/none"),
            ),
            (UNDECIDED, |t| t.ruby_libs.push_str(";newlib=1")),
            (UNDECIDED, |t| {
                t.ruby_libs = t.ruby_libs.replace("yaml=0.2.5;", "")
            }),
            (UNDECIDED, |t| {
                t.ruby_libs = t.ruby_libs.replace("sqlite=3.50.4;", "")
            }),
            (
                "ruby libraries: tz loaded (TZInfo is loaded when the bundle has tzinfo)",
                |t| t.ruby_libs = t.ruby_libs.replace("tz=zoneinfo 2025b", "tz="),
            ),
            (
                "platform (the early plan takes the declared toolchain only for an attestation made on this platform)",
                |t| t.os = "plan9".into(),
            ),
            (vci_core::PRIVILEGES_DIFF, |t| t.superuser = !t.superuser),
        ];
        for (what, edit) in cases {
            let mut t = tc();
            edit(&mut t);
            let d = toolchain_diff(false, Libraries::Any, &t, &declared(), &no_env, &|_| true);
            assert!(d.iter().any(|x| x.0 == what), "{what}: {d:?}");
        }
        // Who runs the tests: accepted under allow_superuser_mismatch.
        let mut t = tc();
        t.superuser = !t.superuser;
        assert!(
            toolchain_diff(true, Libraries::Any, &t, &declared(), &no_env, &|_| true).is_empty()
        );
        // A declaration that could not be read decides nothing.
        let mut d = declared();
        d.ruby = Err("no file declares the Ruby version".into());
        assert!(!toolchain_diff(false, Libraries::Any, &tc(), &d, &no_env, &|_| true).is_empty());
        let mut d = declared();
        d.lock = Err("Gemfile.lock: missing".into());
        assert!(!toolchain_diff(false, Libraries::Any, &tc(), &d, &no_env, &|_| true).is_empty());
        let mut d = declared();
        d.collector = Err("not found".into());
        assert!(!toolchain_diff(false, Libraries::Any, &tc(), &d, &no_env, &|_| true).is_empty());
        // mise exports a variable the env policy compares, or any through
        // a directive: undecided; one it does not compare: decided.
        for k in ["RUBY_YJIT_ENABLE", "_.file"] {
            let mut d = declared();
            d.mise_env
                .as_mut()
                .unwrap()
                .push(("mise.toml".into(), k.into()));
            let whats: Vec<&str> =
                toolchain_diff(false, Libraries::Any, &tc(), &d, &no_env, &|_| true)
                    .into_iter()
                    .map(|x| x.0)
                    .collect();
            assert_eq!(whats, vec![UNDECIDED], "{k}");
        }
        assert_eq!(
            mise_env_in("mise.toml", "[env]\nA = \"1\"\n_.file = \".env\"\n").unwrap(),
            vec!["A", "_.file"]
        );
        let mut d = declared();
        d.rails_app = false;
        assert!(!toolchain_diff(false, Libraries::Any, &tc(), &d, &no_env, &|_| true).is_empty());
    }

    #[test]
    fn native_libraries_are_taken_as_declared_only_by_name() {
        assert!(
            native("native:libvips.so.42", Libraries::Any)
                .unwrap()
                .is_some()
        );
        assert!(native("native:libvips.so.42", Libraries::Exact).is_err());
    }

    /// The variables config/database.yml's ERB reads (vex's file, in
    /// short), and ERB the early plan cannot follow.
    #[test]
    fn database_yml_erb_names_its_variables_or_is_undecided() {
        let vex = r#"default: &default
  adapter: sqlite3
  max_connections: <%= ENV.fetch("RAILS_MAX_THREADS") { 5 } %>
  pool: <%= ENV.fetch("VEX_PRIMARY_DB_POOL") { [ENV.fetch("RAILS_MAX_THREADS", 5).to_i, ENV.fetch('MAINTENANCE_JOB_THREADS', 8).to_i].max * 2 } %>
<% test_database_url = ENV["VEX_TEST_DATABASE_URL"].presence || "sqlite3:storage/test.sqlite3" %>
<%# a comment: Rails.env %>
test:
  <<: *default
  url: <%= test_database_url %>
  cache: <%= ENV.fetch("CACHE_DATABASE_URL", ENV["DATABASE_URL"]) %>
  literal: "<%%= not erb %>"
"#;
        assert_eq!(
            erb_env(vex).unwrap(),
            vec![
                "CACHE_DATABASE_URL",
                "DATABASE_URL",
                "MAINTENANCE_JOB_THREADS",
                "RAILS_MAX_THREADS",
                "VEX_PRIMARY_DB_POOL",
                "VEX_TEST_DATABASE_URL"
            ]
        );
        assert_eq!(
            erb_env("test:\n  adapter: sqlite3\n").unwrap(),
            Vec::<String>::new()
        );
        for bad in [
            "a: <%= ENV[name] %>",
            "a: <%= ENV.to_h[\"X\"] %>",
            "a: <%= ENV.fetch(\"#{x}\") %>",
            "a: <%= Rails.env %>",
            "a: <%= File.read(\"x\") %>",
            "a: <%= `uname` %>",
            "a: <%= %x(uname) %>",
            "a: <%= $x %>",
            "a: <%= @x %>",
            "a: <%= ::Foo %>",
            "a: <%= helper_from_the_app %>",
            "a: <%= ENV.fetch(\"X\") { |k| k } %>",
            "a: <%= 1 ",
        ] {
            assert!(erb_env(bad).is_err(), "{bad}");
        }
    }

    /// mise's config files in a directory: beside the version files, in
    /// `.config/`, and every `*.toml` under `mise/`, `.mise/` and
    /// `.config/mise/`.
    #[test]
    fn every_mise_config_file_is_a_version_file() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(t.path()).unwrap();
        for f in [
            "mise.toml",
            ".mise.ci.local.toml",
            "mise/config.toml",
            "mise/conf.d/a.toml",
            ".mise/config.local.toml",
            ".config/mise.ci.toml",
            ".config/mise/conf.d/b.toml",
            ".config/mise/config.ci.toml",
            ".config/nextest.toml",
            "mise/README.md",
            "other.toml",
        ] {
            write(root, f, "");
        }
        let mut got: Vec<String> = version_files_in(root)
            .unwrap()
            .iter()
            .filter(|p| p.is_file())
            .map(|p| rel(root, p))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ".config/mise.ci.toml",
                ".config/mise/conf.d/b.toml",
                ".config/mise/config.ci.toml",
                ".mise.ci.local.toml",
                ".mise/config.local.toml",
                "mise.toml",
                "mise/conf.d/a.toml",
                "mise/config.toml",
            ]
        );
        write(
            root,
            ".config/mise/conf.d/c.toml",
            "[tools]\nruby = \"3.4.7\"\n",
        );
        write(root, ".ruby-version", "3.4.9\n");
        let e = declared_ruby(root, root).unwrap_err();
        assert!(e.contains(".config/mise/conf.d/c.toml"), "{e}");
    }

    /// The version variables where the early plan runs must name the
    /// declared Ruby; one that points mise elsewhere decides nothing.
    #[test]
    fn ruby_version_variables_must_agree() {
        let t = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(t.path()).unwrap();
        write(root, ".ruby-version", "3.4.9\n");
        let with = |k: &'static str, v: &'static str| {
            declare_with(root, root, None, &move |n| (n == k).then(|| v.to_owned())).ruby
        };
        assert_eq!(with("NONE", "").unwrap().files, vec![".ruby-version"]);
        assert_eq!(
            with("MISE_RUBY_VERSION", "3.4.9").unwrap().files,
            vec![".ruby-version", "$MISE_RUBY_VERSION"]
        );
        for (k, v) in [
            ("MISE_RUBY_VERSION", "3.4.7"),
            ("RBENV_VERSION", "3.4.7"),
            ("ASDF_RUBY_VERSION", "3.4"),
            ("RUBY_VERSION", "3.4.8"),
            ("MISE_CONFIG_FILE", "/x/mise.toml"),
        ] {
            assert!(with(k, v).is_err(), "{k}={v}");
        }
        let d = declare_with(root, root, None, &|n| {
            (n == "MISE_CONFIG_FILE").then(|| "/x".to_owned())
        });
        assert!(d.mise_env.is_err());
    }

    /// A variable config/database.yml reads that the tests get uncompared,
    /// or ERB the early plan cannot follow: undecided.
    #[test]
    fn database_variables_passed_uncompared_are_undecided() {
        let mut d = declared();
        d.db_env = Ok(vec!["DB_ADAPTER".into(), "RAILS_MAX_THREADS".into()]);
        let decided = |k: &str| k != "DB_ADAPTER";
        let rows = toolchain_diff(false, Libraries::Any, &tc(), &d, &no_env, &decided);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].0, UNDECIDED);
        assert!(rows[0].2.contains("DB_ADAPTER"), "{rows:?}");
        assert!(toolchain_diff(false, Libraries::Any, &tc(), &d, &no_env, &|_| true).is_empty());
        d.db_env = Err("its ERB uses `Rails`".into());
        let rows = toolchain_diff(false, Libraries::Any, &tc(), &d, &no_env, &|_| true);
        assert_eq!(
            rows.iter().map(|r| r.0).collect::<Vec<_>>(),
            vec![UNDECIDED]
        );
    }
}
