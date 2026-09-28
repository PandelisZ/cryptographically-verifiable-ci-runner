//! Static checks of the Rust sources a unit compiles from the repository.
//!
//! Rust has no hook for what a test does at run time, so these are text
//! heuristics over the source (comments included, since doc comments hold
//! doctests). They fail open: a match refuses the unit or pins it to the
//! attesting platform. They are not complete (see the README): an aliased
//! import, a macro that builds the call, or an external crate doing the same
//! thing is not seen.

use std::collections::{BTreeMap, BTreeSet};

use camino::{Utf8Path, Utf8PathBuf};

use super::cfgexpr;

/// What kind of code a source file is compiled into.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Roles {
    /// Linked into a test binary or a doctest (runs when the tests run).
    pub runtime: bool,
    /// A build script (runs at build time).
    pub build_script: bool,
    /// A procedural macro (runs inside rustc).
    pub proc_macro: bool,
}

/// Findings for one unit.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Findings {
    /// Reasons the unit is not attestable.
    pub taints: BTreeSet<String>,
    /// Environment variables named literally in `env::var("X")` /
    /// `env::var_os("X")`: hashed.
    pub env_names: BTreeSet<String>,
    /// Normalised target-dependent `cfg` predicates.
    pub cfg_predicates: BTreeSet<String>,
    /// Files whose code depends on the platform in a way cfg predicates do
    /// not capture (`std::env::consts::OS`, a build script reading
    /// `TARGET`/`CARGO_CFG_*`, `[target.<triple>]` tables, a cfg that could
    /// not be parsed): the attestation needs the same OS and architecture.
    pub platform_files: BTreeSet<Utf8PathBuf>,
    /// Paths named by string literals used with file APIs, resolved against
    /// the package directory (the test's working directory), when they leave
    /// it (`../x`, absolute paths) -> where they were seen.
    pub path_refs: BTreeMap<Utf8PathBuf, String>,
    /// Paths named the same way that stay inside the package directory ->
    /// where they were seen. They are inputs already (the whole package
    /// directory is); the caller checks that each names an existing file in
    /// the same letter case, since a case-insensitive filesystem (macOS)
    /// opens `tests/Data/B.json` for `tests/data/b.json` and Linux does not.
    pub local_refs: BTreeMap<Utf8PathBuf, String>,
}

/// Starting a child process.
const PROCESS_TOKENS: &[&str] = &[
    "Command::new",
    "process::Command",
    "CommandExt",
    "posix_spawn",
    "libc::fork",
    "libc::exec",
    "libc::system",
    "execvp",
];

/// Network I/O through std (types that open sockets or resolve names).
const NET_TOKENS: &[&str] = &[
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "UnixStream",
    "UnixListener",
    "UnixDatagram",
    "ToSocketAddrs",
    "to_socket_addrs",
];

/// Native code or raw system calls: anything can happen behind them.
const NATIVE_TOKENS: &[&str] = &[
    "libc::",
    "extern \"C\" {",
    "extern \"C\"{",
    "extern \"system\" {",
    "extern {",
    "#[link(",
    "asm!(",
    "global_asm!(",
];

/// Enumerating the environment.
const ENV_ENUM_TOKENS: &[&str] = &["env::vars(", "env::vars_os("];

/// Runtime checks of the platform that cfg predicates do not show: every
/// constant of `std::env::consts` (`OS`, `ARCH`, `FAMILY`, `DLL_PREFIX`,
/// `DLL_SUFFIX`, `DLL_EXTENSION`, `EXE_SUFFIX`, `EXE_EXTENSION` differ between
/// macOS and Linux), however the module is reached (`std::env::consts::OS`,
/// `use std::env::consts; consts::OS`, `use std::env::consts::*`, an alias).
/// A `use std::env::{consts, ...}` import is found separately.
const PLATFORM_TOKENS: &[&str] = &[
    "env::consts",
    "consts::OS",
    "consts::ARCH",
    "consts::FAMILY",
    "consts::DLL_",
    "consts::EXE_",
];

/// Floating-point functions std implements by calling the platform's C math
/// library (or with unspecified precision): macOS's libm and glibc can
/// differ in the last bit, so code using them may compute other values on
/// another OS or architecture. Matched as a method call (`x.sin()`) or a
/// path call (`f64::sin(x)`).
const LIBM_FUNCTIONS: &[&str] = &[
    "sin", "cos", "tan", "sin_cos", "asin", "acos", "atan", "atan2", "sinh", "cosh", "tanh",
    "asinh", "acosh", "atanh", "exp", "exp2", "exp_m1", "ln", "ln_1p", "log", "log2", "log10",
    "powf", "powi", "cbrt", "hypot", "gamma", "ln_gamma",
];

/// A call of one of [`LIBM_FUNCTIONS`] on a float (`.log(` only after a
/// float type path, since `log` is a common method name elsewhere).
fn uses_libm(text: &str) -> Option<String> {
    LIBM_FUNCTIONS.iter().find_map(|f| {
        let method = format!(".{f}(");
        let path = [format!("f64::{f}("), format!("f32::{f}(")];
        let hit = (*f != "log" && text.contains(&method)) || path.iter().any(|p| text.contains(p));
        hit.then(|| (*f).to_owned())
    })
}

/// `use std::env::{consts, ...}` (a braced import of the consts module).
fn imports_env_consts(text: &str) -> bool {
    text.match_indices("env::{").any(|(i, m)| {
        let rest = &text[i + m.len()..];
        let inner = &rest[..rest.find('}').unwrap_or(rest.len())];
        inner
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .any(|w| w == "consts")
    })
}

/// Filesystem access from a procedural macro (not tracked by rustc).
const PROC_MACRO_FS_TOKENS: &[&str] = &[
    "std::fs",
    "fs::read",
    "File::open",
    "read_to_string",
    "read_dir",
    "OpenOptions",
    "fs::metadata",
    "canonicalize(",
];

/// Variables cargo sets for build scripts that describe the target.
fn is_target_env(name: &str) -> bool {
    matches!(name, "TARGET" | "HOST") || name.starts_with("CARGO_CFG_")
}

/// Variables cargo (or vci) sets itself: never user inputs. Their values
/// are paths or derived from hashed manifests.
pub fn is_cargo_set_env(name: &str) -> bool {
    matches!(
        name,
        "CARGO"
            | "CARGO_MANIFEST_DIR"
            | "CARGO_MANIFEST_PATH"
            | "CARGO_MANIFEST_LINKS"
            | "CARGO_CRATE_NAME"
            | "CARGO_BIN_NAME"
            | "CARGO_PRIMARY_PACKAGE"
            | "CARGO_TARGET_TMPDIR"
            | "CARGO_RUSTC_CURRENT_DIR"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "CARGO_MAKEFLAGS"
            | "CARGO_SBOM_PATH"
            | "OUT_DIR"
            | "TARGET"
            | "HOST"
            | "NUM_JOBS"
            | "OPT_LEVEL"
            | "DEBUG"
            | "PROFILE"
            | "RUSTC"
            | "RUSTDOC"
            | "RUSTC_LINKER"
            | "TMPDIR"
            | "PWD"
    ) || [
        "CARGO_PKG_",
        "CARGO_BIN_EXE_",
        "CARGO_CFG_",
        "CARGO_FEATURE_",
        "DEP_",
    ]
    .iter()
    .any(|p| name.starts_with(p))
}

/// Chunks of source text in which string literals are looked for, each
/// with the line it starts on: the code (comments replaced by blank space,
/// so line numbers stay) and each comment on its own (doc comments hold
/// doctests), so a quote in prose cannot swallow code.
fn chunks(src: &str) -> Vec<(usize, String)> {
    let b = src.as_bytes();
    let mut comments = Vec::new();
    let mut code = String::with_capacity(src.len());
    let mut i = 0;
    let mut line = 1;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if !in_str && c == b'/' && b.get(i + 1) == Some(&b'/') {
            let end = src[i..].find('\n').map_or(b.len(), |e| i + e);
            comments.push((line, src[i + 2..end].to_owned()));
            i = end;
            continue;
        }
        if !in_str && c == b'/' && b.get(i + 1) == Some(&b'*') {
            let end = src[i + 2..].find("*/").map_or(b.len(), |e| i + 2 + e + 2);
            let text = &src[i..end];
            comments.push((line, text.to_owned()));
            let nl = text.matches('\n').count();
            line += nl;
            code.push_str(&"\n".repeat(nl));
            i = end;
            continue;
        }
        if c == b'"' {
            // An escaped quote inside a string does not end it.
            let mut bs = 0;
            let mut j = i;
            while j > 0 && b[j - 1] == b'\\' {
                bs += 1;
                j -= 1;
            }
            if !in_str || bs % 2 == 0 {
                in_str = !in_str;
            }
        } else if !in_str && c == b'\'' {
            // Char literals ('"', '\'') must not start a string.
            if b.get(i + 2) == Some(&b'\'') {
                code.push_str(&src[i..i + 3]);
                i += 3;
                continue;
            }
            if b.get(i + 1) == Some(&b'\\') {
                let end = src[i + 2..].find('\'').map_or(b.len(), |e| i + 2 + e + 1);
                code.push_str(&src[i..end]);
                i = end;
                continue;
            }
        }
        if c == b'\n' {
            line += 1;
        }
        let ch_len = src[i..].chars().next().map_or(1, char::len_utf8);
        code.push_str(&src[i..i + ch_len]);
        i += ch_len;
    }
    let mut out = vec![(1, code)];
    out.extend(comments);
    out
}

/// String literals (`"..."`, `r"..."`, `r#"..."#`) in `text`, with the
/// byte offsets where each starts and ends (after the closing quote).
fn string_literals(text: &str) -> Vec<(usize, usize, String)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'r' if (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#'))
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) =>
            {
                let mut j = i + 1;
                let mut hashes = 0;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let close = format!("\"{}", "#".repeat(hashes));
                match text[j + 1..].find(&close) {
                    Some(e) => {
                        let end = j + 1 + e + close.len();
                        out.push((i, end, text[j + 1..j + 1 + e].to_owned()));
                        i = end;
                    }
                    None => break,
                }
            }
            b'\'' => {
                if b.get(i + 2) == Some(&b'\'') {
                    i += 3;
                } else if b.get(i + 1) == Some(&b'\\') {
                    i = text[i + 2..].find('\'').map_or(b.len(), |e| i + 2 + e + 1);
                } else {
                    i += 1;
                }
            }
            b'"' => {
                let mut v = String::new();
                let mut j = i + 1;
                let mut closed = false;
                while j < b.len() {
                    match b[j] {
                        b'\\' => {
                            if let Some(n) = text[j + 1..].chars().next() {
                                v.push(match n {
                                    'n' => '\n',
                                    't' => '\t',
                                    other => other,
                                });
                                j += 1 + n.len_utf8();
                            } else {
                                j += 1;
                            }
                        }
                        b'"' => {
                            closed = true;
                            break;
                        }
                        _ => {
                            let ch = text[j..].chars().next().expect("in bounds");
                            v.push(ch);
                            j += ch.len_utf8();
                        }
                    }
                }
                if !closed {
                    break;
                }
                out.push((i, j + 1, v));
                i = j + 1;
            }
            _ => i += 1,
        }
    }
    out
}

/// Words that, earlier in the same statement, mark a string literal as a
/// file path the code opens (relative to the working directory, the package
/// dir).
const IO_CONTEXT: &[&str] = &[
    "fs::",
    "File::",
    "OpenOptions",
    "read_to_string(",
    "read_dir(",
    "canonicalize(",
    "metadata(",
    "exists(",
    "CARGO_MANIFEST_DIR",
    "rerun-if-changed",
    "set_current_dir(",
];

/// Path construction: a `../` literal built into a path is reported too
/// (absolute literals only with [`IO_CONTEXT`], since tests use them as
/// data). Matched at a word boundary (`Utf8Path::new(` is not `Path::new(`).
const PATH_CONTEXT: &[&str] = &["Path::new(", "PathBuf::from(", ".join("];

/// `tok` occurs in `text` not preceded by an identifier character.
fn has_token(text: &str, tok: &str) -> bool {
    text.match_indices(tok).any(|(i, _)| {
        tok.starts_with('.')
            || text[..i]
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
    })
}

/// Macros whose path argument is relative to the source file; rustc reports
/// what they read in the dep-info.
const FILE_RELATIVE: &[&str] = &["include_str!(", "include_bytes!(", "include!(", "path ="];

/// Lexical normalisation (`a/b/../c` -> `a/c`).
pub fn lexical(p: &Utf8Path) -> Utf8PathBuf {
    let mut out = Utf8PathBuf::new();
    for c in p.components() {
        match c {
            camino::Utf8Component::CurDir => {}
            camino::Utf8Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_str()),
        }
    }
    out
}

fn line_of(text: &str, off: usize) -> usize {
    text[..off.min(text.len())].matches('\n').count()
}

/// Extract `cfg(...)` / `cfg!(...)` / `cfg_attr(<pred>, ...)` predicates.
/// Returns (predicate text, parse ok).
fn cfg_predicates(src: &str) -> Vec<String> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = src[from..].find("cfg") {
        let start = from + pos;
        from = start + 3;
        if start > 0 && (b[start - 1].is_ascii_alphanumeric() || b[start - 1] == b'_') {
            continue;
        }
        let mut j = start + 3;
        let attr = src[j..].starts_with("_attr");
        if attr {
            j += 5;
        } else if b
            .get(j)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        {
            continue;
        }
        if b.get(j) == Some(&b'!') {
            j += 1;
        }
        while b.get(j).is_some_and(|c| c.is_ascii_whitespace()) {
            j += 1;
        }
        if b.get(j) != Some(&b'(') {
            continue;
        }
        // Balanced parentheses, skipping string contents.
        let mut depth = 0usize;
        let mut k = j;
        let mut in_str = false;
        let mut end = None;
        let mut first_comma = None;
        while k < b.len() {
            match b[k] {
                b'\\' if in_str => k += 1,
                b'"' => in_str = !in_str,
                b'(' if !in_str => depth += 1,
                b')' if !in_str => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(k);
                        break;
                    }
                }
                b',' if !in_str && depth == 1 && first_comma.is_none() => first_comma = Some(k),
                _ => {}
            }
            k += 1;
        }
        let Some(end) = end else { break };
        let inner_end = if attr {
            first_comma.unwrap_or(end)
        } else {
            end
        };
        out.push(src[j + 1..inner_end].to_owned());
        from = j + 1;
    }
    out
}

impl Findings {
    /// Record the cfg predicates of `text` (a source file or a manifest).
    fn cfgs(&mut self, file: &Utf8Path, text: &str) {
        for p in cfg_predicates(text) {
            match cfgexpr::parse(&p) {
                Ok(c) if c.mentions_platform() => {
                    self.cfg_predicates.insert(c.to_string());
                }
                Ok(_) => {}
                // A macro-built cfg (`cfg($m)`) or something we cannot read:
                // it may depend on the platform.
                Err(_) => {
                    if p.contains("target_")
                        || p.contains("unix")
                        || p.contains("windows")
                        || p.contains('$')
                    {
                        self.platform_files.insert(file.to_owned());
                    }
                }
            }
        }
    }

    /// Scan one Rust source file of the unit.
    pub fn scan_source(
        &mut self,
        file: &Utf8Path,
        text: &str,
        roles: Roles,
        package_dir: &Utf8Path,
    ) {
        let found = |toks: &'static [&'static str]| -> Option<&'static str> {
            toks.iter().find(|t| text.contains(*t)).copied()
        };
        let rel = file.as_str();
        if roles.runtime || roles.build_script || roles.proc_macro {
            // What the code computes may depend on the platform where cfg
            // predicates do not show it: a runtime check, or a build script
            // or proc macro (they run on the host, which is the target for
            // `cargo test`) emitting a custom cfg from `consts::OS`.
            if found(PLATFORM_TOKENS).is_some()
                || imports_env_consts(text)
                || uses_libm(text).is_some()
            {
                self.platform_files.insert(file.to_owned());
            }
            if let Some(t) = found(PROCESS_TOKENS) {
                self.taints.insert(format!(
                    "cargo:process: {rel} mentions `{t}` (a child process's reads are not observed)"
                ));
            }
            if let Some(t) = found(ENV_ENUM_TOKENS) {
                self.taints.insert(format!(
                    "cargo:env-enumeration: {rel} mentions `{t}` (enumerating the environment cannot be hashed)"
                ));
            }
        }
        if roles.runtime {
            if let Some(t) = found(NET_TOKENS) {
                self.taints.insert(format!(
                    "cargo:net: {rel} mentions `{t}` (network I/O is not observed)"
                ));
            }
            if let Some(t) = found(NATIVE_TOKENS) {
                self.taints.insert(format!(
                    "cargo:native: {rel} mentions `{t}` (native code and system calls are not observed)"
                ));
            }
        }
        if roles.proc_macro
            && let Some(t) = found(PROC_MACRO_FS_TOKENS)
        {
            self.taints.insert(format!(
                "cargo:proc-macro-fs: {rel} is a procedural macro that mentions `{t}` (files it reads are not tracked by rustc)"
            ));
        }
        if roles.runtime && text.contains("CARGO_TARGET_TMPDIR") {
            self.taints.insert(format!(
                "cargo:target-tmpdir: {rel} uses CARGO_TARGET_TMPDIR (files there persist between runs and are not hashed)"
            ));
        }
        if roles.runtime
            && text.contains("CARGO_MANIFEST_DIR")
            && (text.contains(".parent()") || text.contains(".ancestors()"))
        {
            self.taints.insert(format!(
                "{}: {rel} combines CARGO_MANIFEST_DIR with parent()/ancestors() (it may read files outside its package directory that vci does not hash)",
                super::CARGO_UNDECLARED_TAINT
            ));
        }
        // Literal environment reads: hashed (so a read of a built-in
        // pass-through variable such as CI or HOME is compared). Build
        // scripts reading the target make the unit platform-specific.
        for name in literal_env_reads(text) {
            if roles.build_script && is_target_env(&name) {
                self.platform_files.insert(file.to_owned());
            }
            if !is_cargo_set_env(&name) {
                self.env_names.insert(name);
            }
        }
        self.cfgs(file, text);
        if roles.runtime || roles.build_script {
            self.path_literals(file, text, package_dir);
        }
    }

    /// A package manifest: target-specific dependency tables.
    pub fn scan_manifest(&mut self, file: &Utf8Path, text: &str) {
        self.cfgs(file, text);
        for line in text.lines() {
            let l = line.trim_start();
            let Some(rest) = l.strip_prefix("[target.") else {
                continue;
            };
            let rest = rest.trim_start_matches(['\'', '"']);
            if !rest.starts_with("cfg(") {
                // `[target.x86_64-unknown-linux-gnu.dependencies]`
                self.platform_files.insert(file.to_owned());
            }
        }
        // Inline form: `target.'cfg(unix)'.dependencies` keys are covered by
        // the cfg scan; a triple in a dotted key is caught here.
        if text.contains("target.x86_64") || text.contains("target.aarch64") {
            self.platform_files.insert(file.to_owned());
        }
    }

    fn path_literals(&mut self, file: &Utf8Path, text: &str, package_dir: &Utf8Path) {
        let chunks = chunks(text);
        // `const ROOT: &str = "../x";` ... `fs::read(ROOT)`: literals bound to
        // a name, checked where the name is used with a file API.
        let mut bindings: Vec<(String, String, String)> = Vec::new();
        for (i, (base_line, chunk)) in chunks.iter().enumerate() {
            let in_comment = i > 0;
            for (off, end, lit) in string_literals(chunk) {
                let before = statement_before(chunk, off);
                let after = statement_after(chunk, end);
                let line = base_line + line_of(chunk, off);
                let seen = format!("{file}:{line}: {lit:?}");
                if FILE_RELATIVE.iter().any(|t| before.contains(t)) {
                    // In code, rustc reports what these read (dep-info). In a
                    // doc comment (a doctest, compiled by rustdoc when the
                    // tests run) nothing does: relative to the source file.
                    if in_comment && let Some(dir) = file.parent() {
                        let resolved = lexical(&dir.join(&lit));
                        if !resolved.starts_with(package_dir) {
                            self.path_refs
                                .entry(resolved)
                                .or_insert_with(|| format!("{seen} (doctest)"));
                        }
                    }
                    continue;
                }
                // A path built from the package directory, wherever the
                // variable appears in the statement: `concat!(env!(
                // "CARGO_MANIFEST_DIR"), "/../x")`, `format!("{}/../x",
                // env!("CARGO_MANIFEST_DIR"))`.
                if before.contains("CARGO_MANIFEST_DIR") || after.contains("CARGO_MANIFEST_DIR") {
                    let rest = match lit.strip_prefix('{') {
                        Some(r) => r.split_once('}').map_or("", |(_, t)| t),
                        None => lit.as_str(),
                    };
                    if let Some(rel) = rest.strip_prefix('/') {
                        self.record(lexical(&package_dir.join(rel)), package_dir, &seen);
                        continue;
                    }
                }
                if let Some(name) = binding_name(before)
                    && !lit.is_empty()
                    && !lit.contains(char::is_whitespace)
                {
                    bindings.push((name, lit.clone(), seen.clone()));
                }
                let io = IO_CONTEXT.iter().any(|t| before.contains(t));
                if !io && !PATH_CONTEXT.iter().any(|t| has_token(before, t)) {
                    continue;
                }
                self.path_literal(&lit, io, package_dir, &seen);
            }
        }
        for (name, lit, seen) in bindings {
            for (_, chunk) in &chunks {
                for (at, _) in chunk.match_indices(name.as_str()) {
                    let end = at + name.len();
                    let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
                    if word(chunk[..at].chars().next_back()) || word(chunk[end..].chars().next()) {
                        continue;
                    }
                    // Only as an argument: `read_to_string(ROOT)`,
                    // `File::open(&ROOT)`, `.join(SIB)`, `f(a, ROOT)`.
                    let arg = chunk[..at]
                        .trim_end_matches(|c: char| c.is_whitespace() || c == '&')
                        .ends_with(['(', ',']);
                    if !arg {
                        continue;
                    }
                    let before = statement_before(chunk, at);
                    let io = IO_CONTEXT.iter().any(|t| before.contains(t));
                    if io || PATH_CONTEXT.iter().any(|t| has_token(before, t)) {
                        self.path_literal(&lit, io, package_dir, &format!("{seen} via {name}"));
                    }
                }
            }
        }
    }

    /// A literal used as a path relative to the package directory (the
    /// tests' working directory), or absolute (only with a file API: tests
    /// use absolute strings as data).
    fn path_literal(&mut self, lit: &str, io: bool, package_dir: &Utf8Path, seen: &str) {
        let resolved = if lit.starts_with('/') {
            if !io {
                return;
            }
            Utf8PathBuf::from(lit)
        } else {
            lexical(&package_dir.join(lit))
        };
        if resolved == Utf8Path::new("/dev/null") {
            return;
        }
        self.record(resolved, package_dir, seen);
    }

    fn record(&mut self, resolved: Utf8PathBuf, package_dir: &Utf8Path, seen: &str) {
        let map = if resolved.starts_with(package_dir) {
            &mut self.local_refs
        } else {
            &mut self.path_refs
        };
        map.entry(resolved).or_insert_with(|| seen.to_owned());
    }
}

/// The statement text before byte `off` of `chunk` (at most 80 bytes, from
/// the last `;`, `{` or `}`).
fn statement_before(chunk: &str, off: usize) -> &str {
    let mut from = off.saturating_sub(80);
    while !chunk.is_char_boundary(from) {
        from += 1;
    }
    let before = &chunk[from..off];
    match before.rfind([';', '{', '}']) {
        Some(cut) => &before[cut + 1..],
        None => before,
    }
}

/// The statement text after byte `end` of `chunk` (at most 120 bytes, up to
/// the next `;`, `{` or `}`).
fn statement_after(chunk: &str, end: usize) -> &str {
    let mut to = (end + 120).min(chunk.len());
    while !chunk.is_char_boundary(to) {
        to -= 1;
    }
    let after = &chunk[end.min(to)..to];
    match after.find([';', '{', '}']) {
        Some(cut) => &after[..cut],
        None => after,
    }
}

/// The name a literal is bound to when the statement before it is
/// `const NAME: T =`, `static NAME: T =` or `let [mut] NAME [: T] =`.
fn binding_name(before: &str) -> Option<String> {
    let lhs = before.trim_end().strip_suffix('=')?;
    let mut words = lhs.split_whitespace();
    words.find(|w| matches!(*w, "const" | "static" | "let"))?;
    let mut name = words.next()?;
    if name == "mut" {
        name = words.next()?;
    }
    let name = name.split(':').next()?;
    (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .then(|| name.to_owned())
}

/// Names in `env::var("X")`, `env::var_os("X")` (and `std::env::...`).
fn literal_env_reads(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for pat in ["env::var(", "env::var_os("] {
        let mut from = 0;
        while let Some(p) = text[from..].find(pat) {
            let mut j = from + p + pat.len();
            from = j;
            let b = text.as_bytes();
            while b.get(j).is_some_and(|c| c.is_ascii_whitespace()) {
                j += 1;
            }
            if b.get(j) != Some(&b'"') {
                continue;
            }
            if let Some(e) = text[j + 1..].find('"') {
                let name = &text[j + 1..j + 1 + e];
                if !name.is_empty() && !name.contains(char::is_whitespace) {
                    out.push(name.to_owned());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(text: &str, roles: Roles) -> Findings {
        let mut f = Findings::default();
        f.scan_source(
            Utf8Path::new("/r/p/src/lib.rs"),
            text,
            roles,
            Utf8Path::new("/r/p"),
        );
        f
    }

    const RT: Roles = Roles {
        runtime: true,
        build_script: false,
        proc_macro: false,
    };

    #[test]
    fn processes_network_native_and_enumeration_taint() {
        for (src, tag) in [
            (
                "let o = std::process::Command::new(\"ls\");",
                "cargo:process",
            ),
            (
                "use std::process::{Command};\nCommand::new(x)",
                "cargo:process",
            ),
            ("let s = std::net::TcpStream::connect(a);", "cargo:net"),
            ("unsafe { libc::getpid() }", "cargo:native"),
            ("unsafe extern \"C\" {\n fn f(); }", "cargo:native"),
            ("for (k, v) in std::env::vars() {}", "cargo:env-enumeration"),
            (
                "let d = env!(\"CARGO_TARGET_TMPDIR\");",
                "cargo:target-tmpdir",
            ),
            // In a doctest (doc comment) too.
            (
                "/// ```\n/// std::process::Command::new(\"x\");\n/// ```\npub fn f() {}",
                "cargo:process",
            ),
        ] {
            let f = scan(src, RT);
            assert!(
                f.taints.iter().any(|t| t.starts_with(tag)),
                "{src}: {:?}",
                f.taints
            );
        }
        assert!(
            scan("let x = 1; std::thread::spawn(|| {});", RT)
                .taints
                .is_empty()
        );
        let pm = Roles {
            proc_macro: true,
            ..Default::default()
        };
        assert!(
            scan("let s = std::fs::read_to_string(\"x\");", pm)
                .taints
                .iter()
                .any(|t| t.starts_with("cargo:proc-macro-fs"))
        );
        // Networking types are harmless in a build script (it does not run
        // with the tests), processes are not.
        let bs = Roles {
            build_script: true,
            ..Default::default()
        };
        assert!(scan("TcpStream", bs).taints.is_empty());
        assert!(!scan("Command::new(\"git\")", bs).taints.is_empty());
    }

    #[test]
    fn literal_env_reads_are_hashed_and_target_reads_pin_the_platform() {
        let f = scan(
            "let a = std::env::var(\"CI\"); let b = env::var_os( \"APP_MODE\" ); let c = env::var(name); let d = std::env::var(\"CARGO_PKG_NAME\");",
            RT,
        );
        assert_eq!(f.env_names.iter().collect::<Vec<_>>(), ["APP_MODE", "CI"]);
        assert!(f.taints.is_empty());
        let bs = Roles {
            build_script: true,
            ..Default::default()
        };
        let f = scan(
            "if env::var(\"CARGO_CFG_TARGET_OS\").unwrap() == \"linux\" {}",
            bs,
        );
        assert!(f.platform_files.contains(Utf8Path::new("/r/p/src/lib.rs")));
        assert!(f.env_names.is_empty());
        let f = scan("if std::env::consts::OS == \"linux\" {}", RT);
        assert_eq!(f.platform_files.len(), 1);
    }

    #[test]
    fn cfg_predicates_that_depend_on_the_target_are_recorded() {
        let f = scan(
            "#[cfg(unix)]\nfn a() {}\n#[cfg_attr(target_os = \"linux\", ignore)]\n#[test]\nfn b() {}\nif cfg!(feature = \"x\") {}\n#[cfg(all(test, not(windows)))]\nmod t {}\n// see cfg(foo) in prose\n",
            RT,
        );
        assert_eq!(
            f.cfg_predicates.iter().collect::<Vec<_>>(),
            ["all(test, not(windows))", "target_os = \"linux\"", "unix"]
        );
        assert!(f.platform_files.is_empty());
        let f = scan(
            "macro_rules! m { ($c:meta) => { #[cfg($c)] fn x() {} } }",
            RT,
        );
        assert_eq!(f.platform_files.len(), 1, "{f:?}");
        let mut m = Findings::default();
        m.scan_manifest(
            Utf8Path::new("/r/p/Cargo.toml"),
            "[target.'cfg(windows)'.dependencies]\nwinapi = \"0.3\"\n",
        );
        assert_eq!(m.cfg_predicates.iter().collect::<Vec<_>>(), ["windows"]);
        assert!(m.platform_files.is_empty());
        m.scan_manifest(
            Utf8Path::new("/r/p/Cargo.toml"),
            "[target.x86_64-unknown-linux-gnu.dependencies]\nx = \"1\"\n",
        );
        assert_eq!(m.platform_files.len(), 1);
    }

    #[test]
    fn path_literals_leaving_the_package_are_reported() {
        let f = scan(
            r#"
const T: &str = include_str!("../../shared/c.txt");
fn t() {
    let a = std::fs::read_to_string("tests/data/b.json");
    let b = std::fs::read_to_string("../shared/data.json");
    let c = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../other/x.bin"));
    let d = File::open("/etc/hosts");
    let e = "../../fixtures/b.json".to_string(); // test data, not opened here
    let n = File::open("/dev/null");
    // std::fs::read("../in/a/comment")
    let p = Path::new("../joined/dir");
    let q = Utf8Path::new("/abs/data/only"); let r = RepoPath::new("../not/a/path/api");
    let s = Path::new("/abs/without/io");
}
"#,
            RT,
        );
        let doc = scan(
            "/// ```\n/// let t = include_str!(\"../../shared/doc.txt\");\n/// ```\npub fn f() {}\nconst X: &str = include_str!(\"../../shared/code.txt\");\n",
            RT,
        );
        assert_eq!(
            doc.path_refs.keys().map(|p| p.as_str()).collect::<Vec<_>>(),
            ["/r/shared/doc.txt"],
            "doctests' includes are not in rustc's dep-info"
        );
        let got: Vec<&str> = f.path_refs.keys().map(|p| p.as_str()).collect();
        assert_eq!(
            got,
            [
                "/etc/hosts",
                "/r/in/a/comment",
                "/r/joined/dir",
                "/r/other/x.bin",
                "/r/shared/data.json"
            ]
        );
        assert!(
            f.path_refs[Utf8Path::new("/r/shared/data.json")].contains("src/lib.rs:5"),
            "{:?}",
            f.path_refs
        );
        assert!(f.taints.is_empty());
        let f = scan(
            "let root = Path::new(env!(\"CARGO_MANIFEST_DIR\")).parent().unwrap();",
            RT,
        );
        assert!(
            f.taints
                .iter()
                .any(|t| t.starts_with(crate::cargo::CARGO_UNDECLARED_TAINT))
        );
    }

    #[test]
    fn string_literal_lexing() {
        let lits: Vec<String> =
            string_literals(r####"a("x\"y"); b(r#"q"z"#); c('"'); d("é/../w")"####)
                .into_iter()
                .map(|(_, _, s)| s)
                .collect();
        assert_eq!(lits, ["x\"y", "q\"z", "é/../w"]);
    }

    /// Regression: `std::env::consts::DLL_SUFFIX` (".dylib" on macOS, ".so"
    /// on Linux) and the other consts were not platform tokens; a build
    /// script choosing a custom cfg with `consts::OS` was not checked at all
    /// (the tokens applied to runtime code only).
    #[test]
    fn every_env_const_pins_the_platform_in_every_role() {
        let bs = Roles {
            build_script: true,
            ..Default::default()
        };
        let pm = Roles {
            proc_macro: true,
            ..Default::default()
        };
        for (src, roles) in [
            (
                "format!(\"{}{}{}\", std::env::consts::DLL_PREFIX, n, std::env::consts::DLL_SUFFIX)",
                RT,
            ),
            ("use std::env::consts::*; let x = EXE_SUFFIX;", RT),
            ("use std::env::{self, consts}; consts::DLL_EXTENSION", RT),
            ("use std::env::consts as c; c::FAMILY", RT),
            (
                "if std::env::consts::OS == \"macos\" { println!(\"cargo::rustc-cfg=host_is_mac\") }",
                bs,
            ),
            ("let os = std::env::consts::OS;", pm),
            ("let y = x.sin();", RT),
            ("let y = a.powf(2.5);", RT),
            ("let y = f64::exp(x);", RT),
            ("let y = f32::log(x, 2.0);", RT),
        ] {
            let f = scan(src, roles);
            assert_eq!(f.platform_files.len(), 1, "{src}: {f:?}");
        }
        for src in [
            "let x = crate::consts::MAX;",
            "let y = x.sqrt() + x.abs();",
            "logger.log(&record);",
            "use std::env::{var, args};",
        ] {
            assert!(scan(src, RT).platform_files.is_empty(), "{src}");
        }
    }

    /// Regression: a path in a `const` (or `let`) used with a file API, and
    /// `format!("{}/../x", env!("CARGO_MANIFEST_DIR"))`, were not seen.
    #[test]
    fn paths_bound_to_names_and_built_from_the_manifest_dir_are_reported() {
        let f = scan(
            r#"
const ROOT: &str = "../rootdata.txt";
const SIB: &str = "../a/sib.txt";
static OUT: &str = "/scratch/outside.txt";
const DATA: &str = "tests/data/b.json";
const NOT_A_PATH: &str = "../only/data";
#[test]
fn t() {
    let a = std::fs::read_to_string(ROOT).unwrap();
    let b = std::fs::read(&SIB).unwrap();
    let c = std::fs::read(OUT).unwrap();
    let p = format!("{}/../shared/c.txt", env!("CARGO_MANIFEST_DIR"));
    let d = std::fs::read(DATA).unwrap();
    let s = NOT_A_PATH.to_string();
}
"#,
            RT,
        );
        let got: Vec<&str> = f.path_refs.keys().map(|p| p.as_str()).collect();
        assert_eq!(
            got,
            [
                "/r/a/sib.txt",
                "/r/rootdata.txt",
                "/r/shared/c.txt",
                "/scratch/outside.txt"
            ],
            "{f:?}"
        );
        assert!(
            f.path_refs[Utf8Path::new("/r/rootdata.txt")].contains("via ROOT"),
            "{f:?}"
        );
        assert_eq!(
            f.local_refs.keys().map(|p| p.as_str()).collect::<Vec<_>>(),
            ["/r/p/tests/data/b.json"]
        );
    }
}
