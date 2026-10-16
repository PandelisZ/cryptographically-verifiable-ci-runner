//! node:test adapter (`adapter = "node-test"`): projects whose tests run with
//! Node's built-in runner, `node --test`, usually through a package.json
//! script (`NODE_ENV=test node --import ./test/hooks.mjs --test 'src/**/*.test.ts'`).
//!
//! The unit is a test file. The command comes from a package.json script
//! (`test_script`, default `"test"`), read with a strict subset of `sh`
//! (see [`shell`]), or from `test_globs` + `node_args` in vci.toml. Every
//! node option is classified: options that cannot change which tests run
//! or what they see are kept (and recorded in the attestation's argv),
//! per-run plumbing (`--test-concurrency`, `--test-reporter`) is dropped,
//! and anything else is refused, so nothing is attested and CI runs it.
//!
//! A recording run (`vci run`, `vci ci --key`) runs each file in its own
//! `node --test` process:
//! `node --require <collector> <user flags> --import <late hooks>
//! --test-reporter=<vci reporter> --test-reporter=spec --test <file>`. The
//! collectors are the `@vci/vitest` package's `src/node-test/` modules.
//! A plain run (`vci ci` without `--key`: nothing recorded) of some files
//! is one process, the test command restricted to them:
//! `<assignments> node <every option of the command> --test <files>`; of
//! every file, the command itself (`<package manager> run <script>`).

mod shell;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use camino::{Utf8Path, Utf8PathBuf};
use serde_json::Value;

use crate::vitest::{NODE_ENV as NODE_BIN_ENV, apply_env, describe, file_url, find_js_plugin};
use crate::{
    Adapter, AdapterError, ChildEnv, ListedFile, RunOutput, ToolVersions, parse_jsonl_dir,
};

/// Hashed whenever present in loose mode (deprecated), where every variable
/// reaches the tests: vci 1.5's list of what the runtime reads where nothing
/// observes it, kept so that loose mode hashes what it did. Strict mode removes
/// these unless they are built-in or vci.toml lists them.
pub const NODE_TEST_LOOSE_HASH: &[&str] = &["NODE_*", "!NODE_OPTIONS", "UV_THREADPOOL_SIZE"];

/// Built-in hash for node:test (docs/ENV.md): what Node reads natively. ICU
/// reads `LANG`/`LC_ALL`/`LC_MESSAGES` for the default locale (`de_DE` formats
/// `1234.5` as `1.234,5`); `NODE_OPTIONS` reaches every process before the
/// collector (it is also a global input); `UV_THREADPOOL_SIZE` sizes libuv's
/// pool. Every other `NODE_*` variable (`NODE_PATH`, `NODE_EXTRA_CA_CERTS`,
/// ...) is removed unless vci.toml lists it.
pub const NODE_TEST_HASH: &[&str] = &[
    "LANG",
    "LC_ALL",
    "LC_MESSAGES",
    "NODE_OPTIONS",
    "UV_THREADPOOL_SIZE",
];

/// Variables vci sets for every node:test process (never inputs).
pub const NODE_TEST_RUN_VARS: &[&str] = &["VCI_OUT", "VCI_TEST_FILE", "VCI_ROOT"];

/// Packages whose module hooks are accepted in `--import`/`--require`;
/// their TypeScript configuration (the `tsconfig.json` chain) becomes a
/// global input. The collector accepts `module.register` only from them.
pub const NODE_TEST_TS_LOADERS: &[&str] = &[
    "tsx",
    "ts-node",
    "@swc-node/register",
    "amaro",
    "@esbuild-kit/esm-loader",
    "esbuild-register",
];

/// The listing helper (`js/vitest-plugin/src/node-test/list.js`), run with
/// `node -e` so that listing needs no collector.
const LIST_JS: &str = include_str!("../../../../js/vitest-plugin/src/node-test/list.js");

/// vci.toml settings of a node-test project.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeTestOptions {
    /// The package.json script that runs the tests (default `"test"`).
    pub test_script: Option<String>,
    /// Test file globs (node:test's glob syntax, relative to the project
    /// dir), instead of a script.
    pub test_globs: Option<Vec<String>>,
    /// Node options for `test_globs` (e.g. `["--import", "./test/hooks.mjs"]`).
    pub node_args: Option<Vec<String>>,
}

/// A module preloaded with `--import` / `--require`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preload {
    /// A file (relative or absolute path, or `file:` URL), resolved.
    File(Utf8PathBuf),
    /// A package specifier (`tsx`, `ts-node/esm`).
    Package(String),
}

/// The test command, as vci understands it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Invocation {
    /// Where it came from (for messages).
    pub source: String,
    /// The package.json script name (`None` with `test_globs`).
    pub script: Option<String>,
    /// Leading `NAME=value` assignments of the script.
    pub assignments: Vec<(String, String)>,
    /// Kept node options, normalised (`--import=./x.mjs`), in order.
    pub flags: Vec<String>,
    /// Every node option of the command, normalised, in order: the kept
    /// ones and the per-run plumbing vci's recording runs drop
    /// (`--test-concurrency`, `--test-reporter`, `--test-isolation=process`).
    /// What a plain run (nothing recorded) passes to node.
    pub plain_flags: Vec<String>,
    /// Test file patterns (node:test globs).
    pub patterns: Vec<String>,
    pub preloads: Vec<Preload>,
    /// `--env-file` (true: must exist) and `--env-file-if-exists` files.
    pub env_files: Vec<(Utf8PathBuf, bool)>,
    /// Node options that decide type stripping (passed to the listing).
    pub strip_flags: Vec<String>,
    /// A known TypeScript loader is preloaded.
    pub ts_loader: bool,
    /// `--test-concurrency=N`: how many test files may run at once (vci
    /// runs at most this many of its per-file processes at a time).
    pub concurrency: Option<usize>,
}

/// `w` quoted for `sh` when it needs it.
fn sh_quote(w: &str) -> String {
    if !w.is_empty()
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./=:@%+,-".contains(c))
    {
        w.to_owned()
    } else {
        format!("'{}'", w.replace('\'', "'\\''"))
    }
}

impl Invocation {
    /// The command as `sh` would read it: the assignments, `node`, the kept
    /// options, `--test` and the patterns, quoted where needed.
    pub fn command_line(&self) -> String {
        let mut words: Vec<String> = self
            .assignments
            .iter()
            .map(|(k, v)| format!("{k}={}", sh_quote(v)))
            .collect();
        words.push("node".into());
        words.extend(self.flags.iter().map(|f| sh_quote(f)));
        words.push("--test".into());
        words.extend(self.patterns.iter().map(|p| sh_quote(p)));
        words.join(" ")
    }
}

/// How a node option is treated.
#[derive(Debug, PartialEq, Eq)]
enum Class {
    /// Kept as is (no value).
    Keep,
    /// Kept, takes a value (`--flag=value` or `--flag value`).
    KeepValue,
    /// Kept, takes a value only as `--flag=value` (V8 options).
    KeepEqValue,
    /// Per-run plumbing vci replaces, with a value.
    DropValue,
    /// `--test`.
    Test,
    /// Refused, with the reason.
    Refuse(&'static str),
}

const KEEP: &[&str] = &[
    "--experimental-strip-types",
    "--no-experimental-strip-types",
    "--experimental-transform-types",
    "--no-experimental-transform-types",
    "--experimental-test-module-mocks",
    "--experimental-test-snapshots",
    "--experimental-vm-modules",
    "--experimental-sqlite",
    "--no-experimental-sqlite",
    "--experimental-websocket",
    "--no-experimental-websocket",
    "--experimental-require-module",
    "--no-experimental-require-module",
    "--experimental-detect-module",
    "--no-experimental-detect-module",
    "--experimental-import-meta-resolve",
    "--experimental-wasm-modules",
    "--experimental-eventsource",
    "--experimental-global-navigator",
    "--no-experimental-global-navigator",
    "--experimental-json-modules",
    "--enable-source-maps",
    "--no-warnings",
    "--trace-warnings",
    "--no-deprecation",
    "--trace-deprecation",
    "--throw-deprecation",
    "--pending-deprecation",
    "--trace-uncaught",
    "--expose-gc",
    "--preserve-symlinks",
    "--preserve-symlinks-main",
    "--test-force-exit",
    "--frozen-intrinsics",
    "--no-addons",
    "--no-global-search-paths",
];

const KEEP_VALUE: &[&str] = &[
    "--import",
    "--require",
    "--conditions",
    "--env-file",
    "--env-file-if-exists",
    "--disable-warning",
    "--unhandled-rejections",
    "--test-timeout",
    "--input-type",
    "--dns-result-order",
];

const KEEP_EQ_VALUE: &[&str] = &[
    "--max-old-space-size",
    "--max-semi-space-size",
    "--stack-trace-limit",
    "--stack-size",
];

const DROP_VALUE: &[&str] = &[
    "--test-concurrency",
    "--test-reporter",
    "--test-reporter-destination",
];

fn classify(name: &str) -> Class {
    if name == "--test" {
        return Class::Test;
    }
    if KEEP.contains(&name) {
        return Class::Keep;
    }
    if KEEP_VALUE.contains(&name) {
        return Class::KeepValue;
    }
    if KEEP_EQ_VALUE.contains(&name) {
        return Class::KeepEqValue;
    }
    if DROP_VALUE.contains(&name) {
        return Class::DropValue;
    }
    Class::Refuse(match name {
        "--test-only"
        | "--test-name-pattern"
        | "--test-skip-pattern"
        | "--experimental-test-tag-filter"
        | "--test-shard" => {
            "it filters the tests that run (a filtered run cannot vouch for the file)"
        }
        "--test-update-snapshots" => "it writes snapshot files",
        "--test-isolation" => "only --test-isolation=process (the default) is supported",
        "--watch" | "--watch-path" | "--watch-preserve-output" => "watch mode never finishes",
        "--test-randomize" | "--test-random-seed" | "--test-rerun-failures" => {
            "it changes which tests run, or in which order"
        }
        "--experimental-test-coverage" => {
            "coverage is not collected by vci; run it in a separate job"
        }
        "--experimental-config-file" | "--experimental-default-config-file" => {
            "a node.config.json can set any option; give the options on the command line"
        }
        "--loader" | "--experimental-loader" => {
            "loader hooks run on another thread, where vci cannot see what they read; use --import with module.registerHooks"
        }
        "--test-global-setup" => "global setup runs outside the test file's process",
        "--eval" | "-e" | "--print" | "-p" | "--check" | "-c" | "--interactive" | "-i" => {
            "not a test run"
        }
        "--permission" | "--experimental-permission" => {
            "the permission model changes what tests may read"
        }
        _ if name.starts_with("--test-coverage") => {
            "coverage is not collected by vci; run it in a separate job"
        }
        _ if name.starts_with("--inspect") || name.starts_with("--debug") => {
            "a debugger is not a test run"
        }
        _ if name.starts_with("--allow-") => "the permission model changes what tests may read",
        _ => "vci does not know whether it changes what tests run or see",
    })
}

/// Normalise a node option name: `_` is `-` (Node accepts both), and the
/// short forms.
fn normalise_name(name: &str) -> String {
    match name {
        "-r" => "--require".into(),
        "-C" => "--conditions".into(),
        _ if name.starts_with("--") => format!("--{}", name[2..].replace('_', "-")),
        _ => name.to_owned(),
    }
}

/// Is `spec` a package specifier (not a path or URL)?
fn is_package(spec: &str) -> bool {
    !(spec.starts_with("./")
        || spec.starts_with("../")
        || spec.starts_with('/')
        || spec == "."
        || spec == ".."
        || spec.contains(':'))
}

/// The package name of a specifier (`@s/p/x` -> `@s/p`).
fn package_name(spec: &str) -> &str {
    let mut parts = spec.splitn(3, '/');
    let first = parts.next().unwrap_or("");
    if first.starts_with('@') {
        match parts.next() {
            Some(second) => &spec[..first.len() + 1 + second.len()],
            None => first,
        }
    } else {
        first
    }
}

/// Parse node arguments: options (classified) and positional patterns.
/// `allow_positional`: a script's arguments (patterns follow `--test`);
/// false for vci.toml `node_args`.
fn parse_node_args(
    args: &[String],
    cwd: &Utf8Path,
    allow_positional: bool,
    inv: &mut Invocation,
) -> Result<bool, String> {
    let mut saw_test = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if !inv.patterns.is_empty() {
            // After the first positional argument Node passes everything to
            // the "script": with --test, every one is a pattern.
            if a.starts_with('-') {
                return Err(format!(
                    "{a:?} comes after a test pattern (Node would not read it as an option)"
                ));
            }
            inv.patterns.push(a.clone());
            continue;
        }
        if a == "--" {
            return Err("`--` in the node command".into());
        }
        if !a.starts_with('-') || a == "-" {
            if !allow_positional {
                return Err(format!(
                    "{a:?} in node_args is not an option (put test patterns in test_globs)"
                ));
            }
            if !saw_test {
                return Err(format!(
                    "{a:?} is a script to run, not a test pattern (the command has no --test before it)"
                ));
            }
            inv.patterns.push(a.clone());
            continue;
        }
        let (raw_name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_owned())),
            _ => (a.as_str(), None),
        };
        let name = normalise_name(raw_name);
        let mut value = |what: &str| -> Result<String, String> {
            if let Some(v) = &inline {
                return Ok(v.clone());
            }
            let v = args
                .get(i)
                .cloned()
                .ok_or_else(|| format!("{what} without a value"))?;
            i += 1;
            Ok(v)
        };
        match classify(&name) {
            Class::Test => {
                if inline.is_some() {
                    return Err(format!("{a:?}"));
                }
                if !allow_positional {
                    return Err("node_args must not contain --test (vci adds it)".into());
                }
                saw_test = true;
            }
            Class::Keep => {
                if inline.is_some() {
                    return Err(format!("{a:?}: {name} takes no value"));
                }
                if name.contains("strip-types") || name.contains("transform-types") {
                    inv.strip_flags.push(name.clone());
                }
                inv.plain_flags.push(name.clone());
                inv.flags.push(name);
            }
            Class::KeepEqValue => {
                let Some(v) = inline else {
                    return Err(format!("{name} must be written as {name}=<value>"));
                };
                inv.plain_flags.push(format!("{name}={v}"));
                inv.flags.push(format!("{name}={v}"));
            }
            Class::KeepValue => {
                let v = value(&name)?;
                match name.as_str() {
                    "--import" | "--require" => {
                        let p = if is_package(&v) {
                            let pkg = package_name(&v);
                            if NODE_TEST_TS_LOADERS.contains(&pkg) {
                                inv.ts_loader = true;
                            }
                            Preload::Package(v.clone())
                        } else if let Some(rest) = v.strip_prefix("file://") {
                            Preload::File(Utf8PathBuf::from(percent_decode(rest)?))
                        } else if v.contains(':') {
                            return Err(format!(
                                "{name}={v}: only paths and packages are supported"
                            ));
                        } else {
                            Preload::File(normalize(&cwd.join(&v)))
                        };
                        inv.preloads.push(p);
                    }
                    "--env-file" | "--env-file-if-exists" => {
                        inv.env_files
                            .push((normalize(&cwd.join(&v)), name == "--env-file"));
                    }
                    "--test-timeout" if v.parse::<u64>().is_err() => {
                        return Err(format!("{name}={v}: not a number"));
                    }
                    _ => {}
                }
                inv.plain_flags.push(format!("{name}={v}"));
                inv.flags.push(format!("{name}={v}"));
            }
            Class::DropValue => {
                let v = value(&name)?;
                if name == "--test-concurrency" {
                    let n: usize = v.parse().map_err(|_| format!("{name}={v}: not a number"))?;
                    inv.concurrency = (n > 0).then_some(n);
                }
                inv.plain_flags.push(format!("{name}={v}"));
            }
            Class::Refuse(why) => {
                if name == "--test-isolation" {
                    let v = value(&name)?;
                    if v == "process" {
                        inv.plain_flags.push(format!("{name}={v}"));
                        continue;
                    }
                    return Err(format!("--test-isolation={v}: {why}"));
                }
                return Err(format!("{a}: {why}"));
            }
        }
    }
    Ok(saw_test)
}

fn percent_decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| format!("bad file URL {s:?}"))?;
            out.push(h);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("non-UTF-8 file URL {s:?}"))
}

/// Lexical normalisation (`a/./b/../c` -> `a/c`).
fn normalize(p: &Utf8Path) -> Utf8PathBuf {
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

/// Parse a package.json test script into an [`Invocation`]. `env` provides
/// the values of variables the script expands (vci's own environment, as
/// for `npm run`).
pub fn parse_script(
    script: &str,
    cwd: &Utf8Path,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Invocation, String> {
    let cmd = shell::parse(script, env, cwd)?;
    let mut words: Vec<String> = cmd.words.iter().map(shell::Word::text).collect();
    let mut inv = Invocation {
        assignments: cmd.assignments,
        ..Default::default()
    };
    // `cross-env A=b node ...` and `env A=b node ...`.
    if matches!(words.first().map(String::as_str), Some("cross-env" | "env")) {
        words.remove(0);
        while let Some(w) = words.first() {
            match w.split_once('=') {
                Some((n, v))
                    if !n.is_empty()
                        && n.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') =>
                {
                    inv.assignments.push((n.to_owned(), v.to_owned()));
                    words.remove(0);
                }
                _ => break,
            }
        }
    }
    match words.first().map(String::as_str) {
        Some("node") => {}
        Some(other) => {
            return Err(format!(
                "the script runs {other:?}, not `node --test` (set test_globs and node_args in vci.toml instead)"
            ));
        }
        None => return Err("the script is empty".into()),
    }
    for (n, _) in &inv.assignments {
        if n == "NODE_OPTIONS" {
            return Err("the script sets NODE_OPTIONS (give the options to node directly)".into());
        }
    }
    let saw_test = parse_node_args(&words[1..], cwd, true, &mut inv)?;
    if !saw_test {
        return Err("the script does not run `node --test`".into());
    }
    Ok(inv)
}

/// The test command from vci.toml `test_globs` + `node_args`.
pub fn from_globs(
    globs: &[String],
    node_args: &[String],
    cwd: &Utf8Path,
) -> Result<Invocation, String> {
    let mut inv = Invocation {
        source: "vci.toml test_globs".into(),
        ..Default::default()
    };
    parse_node_args(node_args, cwd, false, &mut inv)?;
    for g in globs {
        if g.is_empty() || g.starts_with('-') {
            return Err(format!("test glob {g:?}"));
        }
    }
    inv.patterns = globs.to_vec();
    Ok(inv)
}

/// Escape a path for node:test's glob: `*`, `?`, `[`, `]`, `(` and `)` each
/// in a class of its own (`[id]` -> `[[]id[]]`; an escaped `(` also disarms
/// `+(`/`@(`/`!(` extglobs, and `!` is only special at the start of a
/// pattern, which is `/` here). Braces cannot be escaped this way (brace
/// expansion comes first) and backslashes are path separators on Windows:
/// both are refused, so such a file is never attested.
pub fn glob_escape(p: &str) -> Result<String, String> {
    if p.contains(['\\', '{', '}']) {
        return Err(format!(
            "{p:?} contains a brace or a backslash, which node:test's glob cannot match literally"
        ));
    }
    let mut out = String::with_capacity(p.len());
    for c in p.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '(' | ')') {
            out.push('[');
            out.push(c);
            out.push(']');
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// The directories from `project_dir` up to the repository root (the first
/// one holding `.git`; only `project_dir` when there is none).
fn repo_chain(project_dir: &Utf8Path) -> Vec<Utf8PathBuf> {
    let mut out = Vec::new();
    for d in project_dir.ancestors() {
        out.push(d.to_owned());
        if d.join(".git").exists() {
            return out;
        }
    }
    vec![project_dir.to_owned()]
}

/// Node options accepted where they reach every process before vci's
/// collector (`NODE_OPTIONS`, `.npmrc` `node-options`): memory, warning and
/// stack-trace options. Returns the tokens that are not.
pub fn node_options_value_problems(value: &str) -> Vec<String> {
    let mut out = vec![];
    for tok in value.split_whitespace() {
        let name = normalise_name(tok.split_once('=').map_or(tok, |(n, _)| n));
        let ok = matches!(classify(&name), Class::KeepEqValue | Class::DropValue)
            || matches!(
                name.as_str(),
                "--enable-source-maps"
                    | "--no-warnings"
                    | "--trace-warnings"
                    | "--no-deprecation"
                    | "--trace-deprecation"
                    | "--disable-warning"
                    | "--unhandled-rejections"
                    | "--trace-uncaught"
            );
        if !ok || tok.contains(['"', '\'', '\\']) {
            out.push(tok.to_owned());
        }
    }
    out
}

/// The `node-options` value of an `.npmrc`-style ini file (top-level key
/// `node-options` or `node_options`, quotes removed, `${VAR}` expanded).
fn npmrc_node_options(text: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            break;
        }
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        if k != "node-options" && k != "node_options" {
            continue;
        }
        let mut v = v.trim();
        if v.len() >= 2
            && ((v.starts_with('"') && v.ends_with('"'))
                || (v.starts_with('\'') && v.ends_with('\'')))
        {
            v = &v[1..v.len() - 1];
        }
        // npm expands ${VAR} in .npmrc values.
        let mut out = String::new();
        let mut rest = v;
        while let Some(i) = rest.find("${") {
            out.push_str(&rest[..i]);
            match rest[i + 2..].find('}') {
                Some(j) => {
                    out.push_str(&env(&rest[i + 2..i + 2 + j]).unwrap_or_default());
                    rest = &rest[i + 2 + j + 1..];
                }
                None => {
                    out.push_str(&rest[i..]);
                    rest = "";
                }
            }
        }
        out.push_str(rest);
        found = Some(out);
    }
    found
}

/// `node-options` that `npm run`/`pnpm run` would hand the test script as
/// `NODE_OPTIONS` (vci runs node directly, so its runs never see them):
/// `npm_config_node_options` in the environment, the `.npmrc` files from
/// the project dir up to the repository root, the user's (`~/.npmrc` or
/// `$NPM_CONFIG_USERCONFIG`), npm's global one (`$NPM_CONFIG_GLOBALCONFIG`,
/// else `<prefix>/etc/npmrc`) and pnpm's rc files. Returns problems
/// (options other than memory, warning and stack-trace ones).
pub fn npm_node_options_problems(
    project_dir: &Utf8Path,
    vars: &[(String, String)],
    node_prefix: Option<&Utf8Path>,
) -> Vec<String> {
    let get = |k: &str| -> Option<String> {
        vars.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
    };
    let mut sources: Vec<(String, String)> = vec![];
    for (k, v) in vars {
        if k.to_ascii_lowercase().replace('-', "_") == "npm_config_node_options" && !v.is_empty() {
            sources.push((format!("${k}"), v.clone()));
        }
    }
    let mut files: Vec<Utf8PathBuf> = repo_chain(project_dir)
        .into_iter()
        .map(|d| d.join(".npmrc"))
        .collect();
    let home = get("HOME").map(Utf8PathBuf::from);
    match get("NPM_CONFIG_USERCONFIG") {
        Some(f) => files.push(f.into()),
        None => {
            if let Some(h) = &home {
                files.push(h.join(".npmrc"));
            }
        }
    }
    match (get("NPM_CONFIG_GLOBALCONFIG"), get("NPM_CONFIG_PREFIX")) {
        (Some(f), _) => files.push(f.into()),
        (None, Some(p)) => files.push(Utf8PathBuf::from(p).join("etc/npmrc")),
        (None, None) => {
            if let Some(p) = node_prefix {
                files.push(p.join("etc/npmrc"));
            }
        }
    }
    match get("XDG_CONFIG_HOME") {
        Some(x) => files.push(Utf8PathBuf::from(x).join("pnpm/rc")),
        None => {
            if let Some(h) = &home {
                files.push(h.join(".config/pnpm/rc"));
            }
        }
    }
    if let Some(h) = &home {
        files.push(h.join("Library/Preferences/pnpm/rc"));
    }
    for f in files {
        if let Ok(text) = std::fs::read_to_string(&f)
            && let Some(v) = npmrc_node_options(&text, &get)
        {
            sources.push((f.to_string(), v));
        }
    }
    let mut out = vec![];
    for (src, v) in sources {
        for tok in node_options_value_problems(&v) {
            out.push(format!(
                "node-options {tok:?} in {src}: `npm run`/`pnpm run` pass it to the test script as NODE_OPTIONS, while vci runs node directly (only memory, warning and stack-trace options are accepted there)"
            ));
        }
    }
    out
}

/// npm/pnpm lifecycle scripts that run on install.
const INSTALL_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
    "dependencies",
];

/// Install scripts known not to change installed packages or repository
/// files tests read: git hook installers, and patch-package (its `patches/`
/// directory is a global input).
fn harmless_install_script(cmd: &str) -> bool {
    let mut s = cmd.split_whitespace().collect::<Vec<_>>().join(" ");
    for p in ["is-ci || ", "npx --no-install ", "npx "] {
        if let Some(r) = s.strip_prefix(p) {
            s = r.to_owned();
        }
    }
    for suf in [" || true", " || exit 0"] {
        if let Some(r) = s.strip_suffix(suf) {
            s = r.to_owned();
        }
    }
    if s.contains([
        ';', '&', '|', '<', '>', '$', '`', '(', ')', '\\', '"', '\'', '\n',
    ]) {
        return false;
    }
    let w: Vec<&str> = s.split(' ').collect();
    matches!(
        w.as_slice(),
        ["husky"]
            | ["husky", _]
            | ["husky", "install", _]
            | ["simple-git-hooks"]
            | ["lefthook", "install"]
            | ["patch-package"]
    )
}

/// Install lifecycle scripts that may change what tests load without
/// changing a package version or a hashed file (a postinstall that patches
/// `node_modules`, a `prepare` that writes files): in the package.json files
/// from the project dir up to the repository root, and in the workspace
/// packages linked into their `node_modules`.
pub fn install_script_problems(project_dir: &Utf8Path) -> Vec<String> {
    let chain = repo_chain(project_dir);
    let root = chain
        .last()
        .cloned()
        .unwrap_or_else(|| project_dir.to_owned());
    let root = root.canonicalize_utf8().unwrap_or(root);
    let mut pjs: Vec<Utf8PathBuf> = chain.iter().map(|d| d.join("package.json")).collect();
    for d in &chain {
        let Ok(rd) = std::fs::read_dir(d.join("node_modules")) else {
            continue;
        };
        let mut entries: Vec<Utf8PathBuf> = vec![];
        for e in rd.flatten() {
            let Ok(p) = Utf8PathBuf::from_path_buf(e.path()) else {
                continue;
            };
            let name = p.file_name().unwrap_or_default();
            if name.starts_with('@') {
                if let Ok(sub) = std::fs::read_dir(&p) {
                    entries.extend(
                        sub.flatten()
                            .filter_map(|x| Utf8PathBuf::from_path_buf(x.path()).ok()),
                    );
                }
            } else if !name.starts_with('.') {
                entries.push(p);
            }
        }
        for p in entries {
            if !p
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                continue;
            }
            if let Ok(real) = p.canonicalize_utf8()
                && real.starts_with(&root)
                && !real.components().any(|c| c.as_str() == "node_modules")
            {
                pjs.push(real.join("package.json"));
            }
        }
    }
    let mut seen = BTreeSet::new();
    let mut out = vec![];
    for pj in pjs {
        if !seen.insert(pj.clone()) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&pj) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            out.push(format!("{pj} is not valid JSON"));
            continue;
        };
        for name in INSTALL_SCRIPTS {
            if let Some(cmd) = v
                .get("scripts")
                .and_then(|s| s.get(*name))
                .and_then(Value::as_str)
                && !harmless_install_script(cmd)
            {
                out.push(format!(
                    "{pj} has an install script ({name:?}: {cmd:?}); what it changes in node_modules or the repository is not an input (packages are identified by version), so vci cannot vouch for any test"
                ));
            }
        }
    }
    out
}

/// Find `prog` on `PATH` (a name without a slash), or take it as a path.
fn which(prog: &std::ffi::OsStr) -> Option<Utf8PathBuf> {
    let p = std::path::Path::new(prog);
    if p.components().count() > 1 {
        return Utf8PathBuf::from_path_buf(p.to_owned()).ok();
    }
    let path = std::env::var_os("PATH")?;
    for d in std::env::split_paths(&path) {
        let c = d.join(prog);
        if c.is_file() {
            return Utf8PathBuf::from_path_buf(c).ok();
        }
    }
    None
}

/// Package manager of a project: package.json `packageManager` (nearest),
/// else the nearest lockfile; npm by default.
pub fn package_manager(project_dir: &Utf8Path) -> String {
    for d in project_dir.ancestors() {
        if let Ok(t) = std::fs::read_to_string(d.join("package.json"))
            && let Ok(v) = serde_json::from_str::<Value>(&t)
            && let Some(pm) = v.get("packageManager").and_then(Value::as_str)
        {
            let name = pm.split('@').next().unwrap_or("npm");
            if matches!(name, "npm" | "pnpm" | "yarn" | "bun") {
                return name.to_owned();
            }
        }
        for (f, pm) in [
            ("pnpm-lock.yaml", "pnpm"),
            ("yarn.lock", "yarn"),
            ("bun.lock", "bun"),
            ("bun.lockb", "bun"),
            ("package-lock.json", "npm"),
            ("npm-shrinkwrap.json", "npm"),
        ] {
            if d.join(f).is_file() {
                return pm.to_owned();
            }
        }
        if d.join(".git").exists() {
            break;
        }
    }
    "npm".into()
}

/// The `@vci/vitest` package directory with the node:test collectors:
/// `$VCI_JS_PLUGIN`, the project's `node_modules/@vci/vitest`, else
/// `js/vitest-plugin` / `share/vci/vitest-plugin` above the vci executable or
/// in the checkout vci was built from.
pub fn find_node_test_collector(project_dir: &Utf8Path) -> Result<Utf8PathBuf, AdapterError> {
    let ok = |d: &Utf8Path| d.join("src/node-test/preload.cjs").is_file();
    match find_js_plugin(project_dir) {
        Ok(d) if ok(&d) => return Ok(d),
        Ok(d) => {
            return Err(AdapterError::NotFound(format!(
                "{d} has no node:test collector (src/node-test/preload.cjs): the @vci/vitest package is too old"
            )));
        }
        Err(e) if std::env::var_os(crate::vitest::JS_PLUGIN_ENV).is_some_and(|v| !v.is_empty()) => {
            return Err(e);
        }
        Err(_) => {}
    }
    let mut candidates: Vec<Utf8PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Ok(exe) = exe.canonicalize()
        && let Ok(exe) = Utf8PathBuf::from_path_buf(exe)
    {
        for d in exe.ancestors().skip(1) {
            candidates.push(d.join("js/vitest-plugin"));
            candidates.push(d.join("share/vci/vitest-plugin"));
        }
    }
    if let Some(src) = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Utf8Path::parent)
    {
        candidates.push(src.join("js/vitest-plugin"));
    }
    for c in candidates {
        if ok(&c) {
            return Ok(c.canonicalize_utf8()?);
        }
    }
    Err(AdapterError::NotFound(format!(
        "the vci node:test collector was not found: set {} to the js/vitest-plugin directory of vci",
        crate::vitest::JS_PLUGIN_ENV
    )))
}

/// The node:test adapter.
#[derive(Debug)]
pub struct NodeTestAdapter {
    project_dir: Utf8PathBuf,
    node: OsString,
    js_plugin: Option<Utf8PathBuf>,
    options: NodeTestOptions,
    invocation: OnceLock<Result<Invocation, String>>,
}

impl NodeTestAdapter {
    /// `project_dir` must be absolute (it is canonicalised if possible).
    pub fn new(project_dir: &Utf8Path) -> Self {
        let project_dir = project_dir
            .canonicalize_utf8()
            .unwrap_or_else(|_| project_dir.to_owned());
        let node = std::env::var_os(NODE_BIN_ENV)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "node".into());
        Self {
            project_dir,
            node,
            js_plugin: None,
            options: NodeTestOptions::default(),
            invocation: OnceLock::new(),
        }
    }

    /// The vci.toml settings.
    pub fn with_options(mut self, options: NodeTestOptions) -> Self {
        self.options = options;
        self.invocation = OnceLock::new();
        self
    }

    /// Use this `@vci/vitest` package directory.
    pub fn with_js_plugin(mut self, dir: impl Into<Utf8PathBuf>) -> Self {
        self.js_plugin = Some(dir.into());
        self
    }

    fn script_name(&self) -> String {
        self.options
            .test_script
            .clone()
            .unwrap_or_else(|| "test".into())
    }

    /// The test command (parsed once).
    pub fn invocation(&self) -> Result<&Invocation, AdapterError> {
        self.invocation
            .get_or_init(|| self.resolve_invocation())
            .as_ref()
            .map_err(|e| AdapterError::NotFound(e.clone()))
    }

    fn resolve_invocation(&self) -> Result<Invocation, String> {
        if let Some(globs) = &self.options.test_globs {
            if self.options.test_script.is_some() {
                return Err("test_script and test_globs cannot both be set".into());
            }
            let inv = from_globs(
                globs,
                self.options.node_args.as_deref().unwrap_or_default(),
                &self.project_dir,
            )?;
            if let Some(e) = install_script_problems(&self.project_dir)
                .into_iter()
                .next()
            {
                return Err(e);
            }
            return Ok(inv);
        }
        if self.options.node_args.is_some() {
            return Err("node_args needs test_globs".into());
        }
        let name = self.script_name();
        let pj = self.project_dir.join("package.json");
        let text = std::fs::read_to_string(&pj).map_err(|e| format!("reading {pj}: {e}"))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("parsing {pj}: {e}"))?;
        let script = v
            .get("scripts")
            .and_then(|s| s.get(&name))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{pj} has no \"{name}\" script"))?;
        let env = |k: &str| std::env::var(k).ok();
        let mut inv = parse_script(script, &self.project_dir, &env)
            .map_err(|e| format!("package.json script \"{name}\" ({script:?}): {e}"))?;
        // `npm test` runs `pretest` and `posttest` around the script (pnpm
        // too); vci runs the test files itself and would skip them.
        for hook in [format!("pre{name}"), format!("post{name}")] {
            if let Some(h) = v
                .get("scripts")
                .and_then(|s| s.get(&hook))
                .and_then(Value::as_str)
            {
                return Err(format!(
                    "{pj} has a \"{hook}\" script ({h:?}), which `npm run {name}` runs around the tests and vci's per-file runs would not"
                ));
            }
        }
        let vars: Vec<(String, String)> = std::env::vars().collect();
        let prefix = which(&self.node)
            .and_then(|n| n.canonicalize_utf8().ok())
            .and_then(|n| {
                n.parent()
                    .and_then(Utf8Path::parent)
                    .map(Utf8Path::to_owned)
            });
        if let Some(e) = npm_node_options_problems(&self.project_dir, &vars, prefix.as_deref())
            .into_iter()
            .next()
        {
            return Err(e);
        }
        if let Some(e) = install_script_problems(&self.project_dir)
            .into_iter()
            .next()
        {
            return Err(e);
        }
        inv.source = format!("package.json script \"{name}\"");
        inv.script = Some(name);
        Ok(inv)
    }

    fn node_cmd(&self) -> Command {
        let mut c = Command::new(&self.node);
        c.current_dir(&self.project_dir);
        c
    }

    fn plugin(&self) -> Result<Utf8PathBuf, AdapterError> {
        match &self.js_plugin {
            Some(p) => Ok(p.canonicalize_utf8().unwrap_or_else(|_| p.clone())),
            None => find_node_test_collector(&self.project_dir),
        }
    }

    /// Environment for a test process: the child env, the script's
    /// assignments, and none of node:test's own variables.
    fn apply_test_env(&self, cmd: &mut Command, env: &ChildEnv, inv: &Invocation) {
        apply_env(cmd, env);
        for (k, v) in &inv.assignments {
            cmd.env(k, v);
        }
        for k in [
            "NODE_TEST_CONTEXT",
            "NODE_TEST_WORKER_ID",
            "VCI_TEST_FILE",
            "VCI_ROOT",
        ] {
            cmd.env_remove(k);
        }
    }

    /// Problems with `NODE_OPTIONS` in the child environment: it reaches
    /// every process, before vci's collector.
    fn node_options_problems(&self, env: &ChildEnv) -> Vec<String> {
        let value = match env {
            Some(vars) => vars
                .iter()
                .find(|(k, _)| k == "NODE_OPTIONS")
                .map(|(_, v)| v.to_string_lossy().into_owned()),
            None => std::env::var("NODE_OPTIONS").ok(),
        };
        let Some(value) = value else { return vec![] };
        node_options_value_problems(&value)
            .into_iter()
            .map(|tok| format!(
                "node-test:NODE_OPTIONS:{tok} (NODE_OPTIONS reaches every process before vci's collector; only memory, warning and stack-trace options are accepted there)"
            ))
            .collect()
    }

    /// The node arguments of a plain run (nothing recorded) of `patterns`:
    /// the command's own options (`--import` hooks, type stripping,
    /// `--test-concurrency`, its reporters), node:test's `spec` reporter
    /// when the command names none, `--test`, the patterns.
    fn plain_args(inv: &Invocation, patterns: &[String]) -> Vec<String> {
        let mut a = inv.plain_flags.clone();
        if !a.iter().any(|f| f.starts_with("--test-reporter=")) {
            a.push("--test-reporter=spec".into());
        }
        a.push("--test".into());
        a.extend(patterns.iter().cloned());
        a
    }

    /// One `node --test` process running `args` (from [`Self::plain_args`])
    /// as the test command would: from the project dir, with its `NAME=value`
    /// assignments; node's output on stderr. Returns node's exit code.
    fn run_plain_node(
        &self,
        inv: &Invocation,
        args: &[String],
        env: &ChildEnv,
    ) -> Result<Option<i32>, AdapterError> {
        let mut cmd = self.node_cmd();
        cmd.args(args);
        self.apply_test_env(&mut cmd, env, inv);
        cmd.stdin(Stdio::null()).stdout(std::io::stderr());
        Ok(cmd.status()?.code())
    }

    /// Run `files` (project-relative) one per process, at most `jobs` at a
    /// time; `make` builds each process. Output goes to stderr in blocks.
    fn run_each(
        &self,
        files: &[String],
        make: &(dyn Fn(usize, &Utf8Path) -> Result<Command, AdapterError> + Sync),
    ) -> Result<Vec<(String, std::process::ExitStatus)>, AdapterError> {
        use std::io::Write as _;
        // The script's --test-concurrency (tests that share a database or a
        // port often set 1) bounds vci's parallelism too.
        let limit = self
            .invocation()
            .ok()
            .and_then(|i| i.concurrency)
            .unwrap_or(usize::MAX);
        let jobs = crate::pytest_jobs().min(limit).max(1);
        let next = std::sync::atomic::AtomicUsize::new(0);
        let results: std::sync::Mutex<
            Vec<(usize, Result<std::process::ExitStatus, AdapterError>)>,
        > = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for _ in 0..jobs.min(files.len().max(1)) {
                s.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if i >= files.len() {
                            break;
                        }
                        let abs = self.project_dir.join(&files[i]);
                        let r = make(i, &abs).and_then(|mut cmd| {
                            let out = cmd.stdin(Stdio::null()).output()?;
                            let mut err = std::io::stderr().lock();
                            let _ = err.write_all(&out.stdout);
                            let _ = err.write_all(&out.stderr);
                            Ok(out.status)
                        });
                        results.lock().expect("lock").push((i, r));
                    }
                });
            }
        });
        let mut v = results.into_inner().expect("lock");
        v.sort_by_key(|(i, _)| *i);
        v.into_iter()
            .map(|(i, r)| r.map(|st| (files[i].clone(), st)))
            .collect()
    }
}

impl Adapter for NodeTestAdapter {
    fn name(&self) -> &'static str {
        "node-test"
    }

    fn project_dir(&self) -> &Utf8Path {
        &self.project_dir
    }

    fn list_test_files(&self, env: &ChildEnv) -> Result<Vec<ListedFile>, AdapterError> {
        let inv = self.invocation()?;
        let mut cmd = self.node_cmd();
        cmd.args(&inv.strip_flags)
            .args(["--no-warnings", "--input-type=module", "-e", LIST_JS, "--"])
            .arg(self.project_dir.as_str())
            .args(&inv.patterns);
        apply_env(&mut cmd, env);
        for (k, v) in &inv.assignments {
            cmd.env(k, v);
        }
        let out = cmd.stdin(Stdio::null()).output()?;
        if !out.status.success() {
            return Err(AdapterError::Command {
                cmd: format!("node (listing the files of {})", inv.source),
                status: out.status.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        let v: Value = serde_json::from_slice(&out.stdout).map_err(|e| AdapterError::Parse {
            what: "node:test file listing".into(),
            detail: e.to_string(),
        })?;
        let files =
            v.get("files")
                .and_then(Value::as_array)
                .ok_or_else(|| AdapterError::Parse {
                    what: "node:test file listing".into(),
                    detail: "no files".into(),
                })?;
        let mut out = Vec::new();
        for f in files {
            let p = f.as_str().ok_or_else(|| AdapterError::Parse {
                what: "node:test file listing".into(),
                detail: format!("{f}"),
            })?;
            let abs = Utf8PathBuf::from(p);
            let abs = abs.canonicalize_utf8().unwrap_or(abs);
            if !abs.starts_with(&self.project_dir) {
                return Err(AdapterError::NotFound(format!(
                    "test file {abs} is outside the project dir {}",
                    self.project_dir
                )));
            }
            out.push(ListedFile {
                abs,
                project: String::new(),
            });
        }
        if out.is_empty() {
            // Nothing matched (a build step may create the files): never
            // "nothing to run", the script itself runs.
            return Err(AdapterError::NotFound(format!(
                "no test file matches {} ({})",
                if inv.patterns.is_empty() {
                    "node:test's default patterns".to_owned()
                } else {
                    inv.patterns.join(" ")
                },
                inv.source
            )));
        }
        Ok(out)
    }

    fn tool_versions(&self) -> Result<ToolVersions, AdapterError> {
        self.tool_versions_with_env(&None)
    }

    fn tool_versions_with_env(&self, env: &ChildEnv) -> Result<ToolVersions, AdapterError> {
        let mut cmd = self.node_cmd();
        cmd.arg("--version");
        apply_env(&mut cmd, env);
        let out = cmd.stdin(Stdio::null()).output()?;
        if !out.status.success() {
            return Err(AdapterError::Command {
                cmd: describe(&cmd),
                status: out.status.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        let node = String::from_utf8_lossy(&out.stdout)
            .trim()
            .trim_start_matches('v')
            .to_owned();
        Ok(ToolVersions {
            runner: node.clone(),
            node,
            ..Default::default()
        })
    }

    fn builtin_hash(&self) -> &'static [&'static str] {
        NODE_TEST_HASH
    }

    fn loose_hash(&self) -> &'static [&'static str] {
        NODE_TEST_LOOSE_HASH
    }

    fn declared_env(&self) -> Vec<String> {
        let mut out = vec!["NODE_ENV".to_owned()];
        if let Ok(inv) = self.invocation() {
            out.extend(inv.assignments.iter().map(|(k, _)| k.clone()));
        }
        out.sort();
        out.dedup();
        out
    }

    fn forced_env(&self) -> Vec<(String, String)> {
        self.invocation()
            .map(|inv| inv.assignments.clone())
            .unwrap_or_default()
    }

    fn tsconfig_is_input(&self) -> bool {
        self.invocation().is_ok_and(|i| i.ts_loader)
    }

    fn warnings(&self, _env: &ChildEnv) -> Vec<String> {
        match self.invocation() {
            Ok(_) => vec![],
            Err(e) => vec![format!(
                "{e}: no test file of this project can be attested or skipped"
            )],
        }
    }

    fn canonical_argv(&self, _project_dir_rel_to_repo: &str, project_rel: &str) -> Vec<String> {
        match self.invocation() {
            Ok(inv) => {
                let mut v = vec!["node".to_owned()];
                v.extend(inv.flags.iter().cloned());
                v.push("--test".into());
                v.push(project_rel.into());
                v
            }
            Err(_) => vec![
                "node".into(),
                "--vci-unsupported-command".into(),
                project_rel.into(),
            ],
        }
    }

    fn config_candidates(&self) -> Vec<Utf8PathBuf> {
        let Ok(inv) = self.invocation() else {
            return vec![];
        };
        let mut out: Vec<Utf8PathBuf> = Vec::new();
        for p in &inv.preloads {
            if let Preload::File(f) = p {
                out.push(f.clone());
            }
        }
        out.extend(inv.env_files.iter().map(|(f, _)| f.clone()));
        let mut seen = BTreeSet::new();
        out.retain(|p| seen.insert(p.clone()));
        out
    }

    fn snapshot_candidates(&self, test_abs: &Utf8Path) -> Vec<Utf8PathBuf> {
        vec![Utf8PathBuf::from(format!("{test_abs}.snapshot"))]
    }

    fn collector_dirs(&self) -> Vec<Utf8PathBuf> {
        self.plugin()
            .ok()
            .and_then(|p| p.canonicalize_utf8().ok())
            .into_iter()
            .collect()
    }

    fn run_collect(&self, files: &[String], env: &ChildEnv) -> Result<RunOutput, AdapterError> {
        let inv = self.invocation()?;
        let plugin = self.plugin()?;
        let preload = plugin.join("src/node-test/preload.cjs");
        let late = plugin.join("src/node-test/late.js");
        let reporter = plugin.join("src/node-test/reporter.js");
        for f in [&preload, &late, &reporter] {
            if !f.is_file() {
                return Err(AdapterError::NotFound(format!(
                    "node:test collector {f} missing"
                )));
            }
        }
        let run_dir = tempfile::Builder::new()
            .prefix("vci-node-test-")
            .tempdir()?;
        let run_dir_p = Utf8Path::from_path(run_dir.path())
            .ok_or_else(|| AdapterError::NotFound("non-UTF-8 temp dir".into()))?
            .to_owned();
        let node_options = self.node_options_problems(env);
        // A file node:test's glob cannot name on its own cannot run alone:
        // it gets no output (so no attestation), and the run fails.
        let (files, unrunnable): (Vec<String>, Vec<String>) = files
            .iter()
            .cloned()
            .partition(|f| glob_escape(self.project_dir.join(f).as_str()).is_ok());
        for f in &unrunnable {
            eprintln!(
                "vci: cannot run {f} on its own: its path has a brace or a backslash, which node:test's glob cannot match literally"
            );
        }
        let files = files.as_slice();
        let make = |i: usize, abs: &Utf8Path| -> Result<Command, AdapterError> {
            let out_dir = run_dir_p.join(i.to_string());
            std::fs::create_dir_all(&out_dir)?;
            let pattern = glob_escape(abs.as_str()).map_err(AdapterError::NotFound)?;
            let mut cmd = self.node_cmd();
            // The collector before every preload of the user's, the late hooks after them.
            cmd.arg("--require")
                .arg(preload.as_str())
                .args(&inv.flags)
                .arg("--import")
                .arg(file_url(&late))
                .arg(format!("--test-reporter={}", file_url(&reporter)))
                .arg(format!(
                    "--test-reporter-destination={}",
                    out_dir.join("reporter.out")
                ))
                .arg("--test-reporter=spec")
                .arg("--test-reporter-destination=stderr")
                .arg("--test")
                .arg(pattern);
            self.apply_test_env(&mut cmd, env, inv);
            cmd.env("VCI_OUT", out_dir.as_str())
                .env("VCI_TEST_FILE", abs.as_str())
                .env("VCI_ROOT", self.project_dir.as_str());
            Ok(cmd)
        };
        let statuses = self.run_each(files, &make)?;
        let mut observed = Vec::new();
        let mut exit_code = if unrunnable.is_empty() {
            Some(0)
        } else {
            Some(1)
        };
        for (i, (_file, status)) in statuses.iter().enumerate() {
            let out_dir = run_dir_p.join(i.to_string());
            match (exit_code, status.code()) {
                (Some(0), c) => exit_code = c,
                (Some(_), None) => exit_code = None,
                _ => {}
            }
            let mut files = parse_jsonl_dir(&out_dir)?;
            for o in files.iter_mut() {
                o.taints.extend(node_options.iter().cloned());
                let passed = o.result.as_ref().is_some_and(|r| r.state == "passed");
                if passed && !status.success() {
                    o.taints.push(match status.code() {
                        Some(c) => format!("vci:process-exit:{c}"),
                        None => "vci:process-exit:signal".into(),
                    });
                }
            }
            observed.extend(files);
        }
        Ok(RunOutput {
            exit_code,
            files: observed,
        })
    }

    fn run_plain(&self, files: &[String], env: &ChildEnv) -> Result<Option<i32>, AdapterError> {
        if files.is_empty() {
            // Everything: the user's own command.
            match self.invocation() {
                Ok(inv) if inv.script.is_none() => {
                    let args = Self::plain_args(inv, &inv.patterns);
                    return self.run_plain_node(inv, &args, env);
                }
                _ if self.options.test_globs.is_some() => {
                    return Err(self.invocation().err().unwrap_or_else(|| {
                        AdapterError::NotFound("invalid test_globs/node_args".into())
                    }));
                }
                _ => {
                    let pm = package_manager(&self.project_dir);
                    let mut cmd = Command::new(&pm);
                    cmd.current_dir(&self.project_dir)
                        .arg("run")
                        .arg(self.script_name());
                    apply_env(&mut cmd, env);
                    cmd.stdin(Stdio::null()).stdout(std::io::stderr());
                    return Ok(cmd
                        .status()
                        .map_err(|e| {
                            AdapterError::NotFound(format!(
                                "running `{pm} run {}`: {e}",
                                self.script_name()
                            ))
                        })?
                        .code());
                }
            }
        }
        let inv = self.invocation()?;
        // One `node --test` process for every file, as the test command
        // runs them, restricted to these files (each a literal glob).
        let mut patterns: Vec<String> = Vec::with_capacity(files.len());
        for f in files {
            // A path starting with `-` would read as an option: absolute.
            let p = if f.starts_with('-') {
                self.project_dir.join(f).into_string()
            } else {
                f.clone()
            };
            match glob_escape(&p) {
                Ok(p) => patterns.push(p),
                Err(_) => {
                    eprintln!(
                        "vci: {f} cannot run on its own (node:test's glob cannot name it): running every test file"
                    );
                    return self.run_plain(&[], env);
                }
            }
        }
        let args = Self::plain_args(inv, &patterns);
        eprintln!(
            "vci: node-test: {}",
            plain_command_line(&inv.assignments, &args, PRINTED_FILES)
        );
        self.run_plain_node(inv, &args, env)
    }
}

/// How many test files [`plain_command_line`] names before `(+N more)`.
const PRINTED_FILES: usize = 20;

/// A plain run's command as `sh` would read it (assignments, `node`, the
/// arguments), naming at most `max_files` of the patterns after `--test`.
fn plain_command_line(
    assignments: &[(String, String)],
    args: &[String],
    max_files: usize,
) -> String {
    let mut words: Vec<String> = assignments
        .iter()
        .map(|(k, v)| format!("{k}={}", sh_quote(v)))
        .collect();
    words.push("node".into());
    let test = args
        .iter()
        .position(|a| a == "--test")
        .unwrap_or(args.len());
    words.extend(args[..test.min(args.len())].iter().map(|a| sh_quote(a)));
    if test < args.len() {
        words.push("--test".into());
        let files = &args[test + 1..];
        words.extend(files.iter().take(max_files).map(|a| sh_quote(a)));
        if files.len() > max_files {
            words.push(format!("(+{} more)", files.len() - max_files));
        }
    }
    words.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cwd() -> Utf8PathBuf {
        Utf8PathBuf::from("/p")
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn vex_web_script_is_understood() {
        let s = "NODE_ENV=test node --import ./test/register-hooks.mjs --test ${TEST_CONCURRENCY:+--test-concurrency=$TEST_CONCURRENCY} 'src/**/*.test.ts' 'server/**/*.test.ts' 'scripts/*.test.mjs'";
        let inv = parse_script(s, &cwd(), &no_env).unwrap();
        assert_eq!(inv.assignments, [("NODE_ENV".into(), "test".into())]);
        assert_eq!(inv.flags, ["--import=./test/register-hooks.mjs"]);
        // Regression: `vci init` printed it without NODE_ENV=test and with
        // the globs unquoted.
        assert_eq!(
            inv.command_line(),
            "NODE_ENV=test node --import=./test/register-hooks.mjs --test 'src/**/*.test.ts' 'server/**/*.test.ts' 'scripts/*.test.mjs'"
        );
        assert_eq!(
            inv.patterns,
            [
                "src/**/*.test.ts",
                "server/**/*.test.ts",
                "scripts/*.test.mjs"
            ]
        );
        assert_eq!(
            inv.preloads,
            [Preload::File("/p/test/register-hooks.mjs".into())]
        );
        // --test-concurrency is per-run plumbing: same argv either way (it
        // only bounds how many files run at once).
        let four = |k: &str| (k == "TEST_CONCURRENCY").then(|| "4".to_owned());
        let with = parse_script(s, &cwd(), &four).unwrap();
        assert_eq!(with.flags, inv.flags);
        assert_eq!((with.concurrency, inv.concurrency), (Some(4), None));
        let only = |k: &str| (k == "TEST_CONCURRENCY").then(|| "1 --test-only".to_owned());
        let e = parse_script(s, &cwd(), &only).unwrap_err();
        assert!(e.contains("--test-only"), "{e}");
    }

    /// The plain run (nothing recorded) of some files is the script's own
    /// command restricted to them: every option, the per-run plumbing a
    /// recording run drops included, then the files.
    #[test]
    fn plain_run_keeps_every_option_of_the_script() {
        let s = "NODE_ENV=test FOO='a b' node --experimental-strip-types --import ./test/register-hooks.mjs --test ${TEST_CONCURRENCY:+--test-concurrency=$TEST_CONCURRENCY} --test-isolation=process 'src/**/*.test.ts'";
        let four = |k: &str| (k == "TEST_CONCURRENCY").then(|| "4".to_owned());
        let inv = parse_script(s, &cwd(), &four).unwrap();
        assert_eq!(
            inv.flags,
            [
                "--experimental-strip-types",
                "--import=./test/register-hooks.mjs"
            ]
        );
        assert_eq!(
            inv.plain_flags,
            [
                "--experimental-strip-types",
                "--import=./test/register-hooks.mjs",
                "--test-concurrency=4",
                "--test-isolation=process"
            ]
        );
        let files = ["src/a.test.ts".to_owned(), "src/[id].test.ts".to_owned()];
        let args = NodeTestAdapter::plain_args(&inv, &files);
        assert_eq!(
            args,
            [
                "--experimental-strip-types",
                "--import=./test/register-hooks.mjs",
                "--test-concurrency=4",
                "--test-isolation=process",
                "--test-reporter=spec",
                "--test",
                "src/a.test.ts",
                "src/[id].test.ts"
            ]
        );
        assert_eq!(
            plain_command_line(&inv.assignments, &args, 1),
            "NODE_ENV=test FOO='a b' node --experimental-strip-types --import=./test/register-hooks.mjs --test-concurrency=4 --test-isolation=process --test-reporter=spec --test src/a.test.ts (+1 more)"
        );
        // The script's own reporters are kept (no spec added).
        let inv = parse_script(
            "node --test-reporter junit --test-reporter-destination=out.xml --test 'src/*.test.mjs'",
            &cwd(),
            &no_env,
        )
        .unwrap();
        assert!(inv.flags.is_empty());
        assert_eq!(
            NodeTestAdapter::plain_args(&inv, &["src/b.test.mjs".to_owned()]),
            [
                "--test-reporter=junit",
                "--test-reporter-destination=out.xml",
                "--test",
                "src/b.test.mjs"
            ]
        );
        // test_globs + node_args: the same.
        let inv = from_globs(
            &["src/*.test.mjs".to_owned()],
            &[
                "--test-concurrency=1".to_owned(),
                "--no-warnings".to_owned(),
            ],
            &cwd(),
        )
        .unwrap();
        assert_eq!(inv.flags, ["--no-warnings"]);
        assert_eq!(inv.plain_flags, ["--test-concurrency=1", "--no-warnings"]);
    }

    #[test]
    fn package_script_variants() {
        let inv = parse_script(
            "node --experimental-strip-types --test src/*.test.ts",
            &cwd(),
            &no_env,
        )
        .unwrap();
        assert_eq!(inv.flags, ["--experimental-strip-types"]);
        assert_eq!(inv.strip_flags, ["--experimental-strip-types"]);
        assert_eq!(inv.patterns, ["src/*.test.ts"]);
        let inv = parse_script("node --test", &cwd(), &no_env).unwrap();
        assert!(inv.patterns.is_empty() && inv.flags.is_empty());
        let inv = parse_script(
            "cross-env NODE_ENV=test TZ=UTC node -r tsx/cjs --import=tsx --env-file=.env.test --test --test-reporter spec --test-isolation=process 'a/**'",
            &cwd(),
            &no_env,
        )
        .unwrap();
        assert_eq!(
            inv.assignments,
            [
                ("NODE_ENV".into(), "test".into()),
                ("TZ".into(), "UTC".into())
            ]
        );
        assert_eq!(
            inv.flags,
            ["--require=tsx/cjs", "--import=tsx", "--env-file=.env.test"]
        );
        assert!(inv.ts_loader);
        assert_eq!(inv.env_files, [("/p/.env.test".into(), true)]);
        for (bad, why) in [
            ("vitest run", "not `node --test`"),
            ("node test.js", "not a test pattern"),
            ("node --test --test-only", "filters"),
            ("node --test --test-name-pattern=x", "filters"),
            ("node --test --test-isolation=none", "process"),
            ("node --test --watch", "watch"),
            ("node --loader ts-node/esm --test", "another thread"),
            ("node --test --experimental-test-coverage", "coverage"),
            ("node --test --frobnicate", "does not know"),
            ("node --test a.test.js --test-only", "after a test pattern"),
            ("tsc && node --test", "operator"),
            ("NODE_OPTIONS=--require=x node --test", "NODE_OPTIONS"),
            ("node --max-old-space-size 4096 --test", "="),
            ("node --test --test-update-snapshots", "writes"),
        ] {
            let e = parse_script(bad, &cwd(), &no_env).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn globs_and_node_args() {
        let inv = from_globs(
            &["src/**/*.test.ts".into()],
            &["--import".into(), "./hooks.mjs".into()],
            &cwd(),
        )
        .unwrap();
        assert_eq!(inv.flags, ["--import=./hooks.mjs"]);
        assert!(from_globs(&[], &["--test".into()], &cwd()).is_err());
        assert!(from_globs(&[], &["src/a.test.js".into()], &cwd()).is_err());
    }

    #[test]
    fn escaping_and_argv() {
        assert_eq!(
            glob_escape("/p/src/[id]/a+(b)!@*?.test.ts").unwrap(),
            "/p/src/[[]id[]]/a+[(]b[)]!@[*][?].test.ts"
        );
        assert!(glob_escape("/p/a\\b").is_err());
        assert!(glob_escape("/p/{a,b}.test.ts").is_err());
        let t = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(t.path()).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"scripts":{"test":"NODE_ENV=test node --import ./h.mjs --test 'src/**/*.test.ts'","unit":"vitest"}}"#,
        )
        .unwrap();
        let a = NodeTestAdapter::new(dir);
        assert_eq!(
            a.canonical_argv(".", "src/a.test.ts"),
            ["node", "--import=./h.mjs", "--test", "src/a.test.ts"]
        );
        assert_eq!(a.declared_env(), ["NODE_ENV"]);
        assert_eq!(a.forced_env(), [("NODE_ENV".into(), "test".into())]);
        assert!(a.config_candidates()[0].ends_with("h.mjs"));
        assert_eq!(
            a.snapshot_candidates(Utf8Path::new("/p/a.test.ts")),
            [Utf8PathBuf::from("/p/a.test.ts.snapshot")]
        );
        let b = NodeTestAdapter::new(dir).with_options(NodeTestOptions {
            test_script: Some("unit".into()),
            ..Default::default()
        });
        assert!(b.invocation().is_err());
        assert_eq!(b.canonical_argv(".", "x")[1], "--vci-unsupported-command");
        assert!(!b.warnings(&None).is_empty());
    }

    /// Regression: `npm test` runs `pretest`/`posttest`, vci's per-file runs
    /// do not: such a script is not accepted (vci ci then runs the script).
    #[test]
    fn pre_and_post_scripts_are_refused() {
        let t = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(t.path()).unwrap();
        std::fs::create_dir(dir.join(".git")).unwrap();
        for (scripts, ok) in [
            (r#"{"test":"node --test"}"#, true),
            (
                r#"{"pretest":"node build.mjs","test":"node --test"}"#,
                false,
            ),
            (
                r#"{"test":"node --test","posttest":"node check.mjs"}"#,
                false,
            ),
            (r#"{"pretest:unit":"x","test":"node --test"}"#, true),
        ] {
            std::fs::write(
                dir.join("package.json"),
                format!(r#"{{"scripts":{scripts}}}"#),
            )
            .unwrap();
            let a = NodeTestAdapter::new(dir);
            match a.invocation() {
                Ok(_) => assert!(ok, "{scripts}"),
                Err(e) => assert!(
                    !ok && e.to_string().contains("runs around the tests"),
                    "{scripts}: {e}"
                ),
            }
        }
    }

    /// Regression: `.npmrc` `node-options` reaches `npm test` as NODE_OPTIONS
    /// but never vci's own runs.
    #[test]
    fn npmrc_node_options_are_checked() {
        let t = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(t.path()).unwrap();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::create_dir_all(dir.join("web")).unwrap();
        std::fs::create_dir_all(dir.join("home")).unwrap();
        let home = vec![("HOME".to_owned(), dir.join("home").to_string())];
        let none: &[(String, String)] = &home;
        assert!(npm_node_options_problems(&dir.join("web"), none, None).is_empty());
        std::fs::write(
            dir.join(".npmrc"),
            "registry=https://r.example\nnode-options=--require ./setup.cjs\n",
        )
        .unwrap();
        let p = npm_node_options_problems(&dir.join("web"), none, None);
        assert!(
            p.len() == 2 && p[0].contains("--require") && p[0].contains(".npmrc"),
            "{p:?}"
        );
        std::fs::write(
            dir.join(".npmrc"),
            "node-options=\"--max-old-space-size=4096 --no-warnings\"\n",
        )
        .unwrap();
        assert!(npm_node_options_problems(&dir.join("web"), none, None).is_empty());
        // The user's npmrc, npm's global one, pnpm's rc and the environment.
        std::fs::write(dir.join("home/.npmrc"), "node_options=--import=${HOOK}\n").unwrap();
        let mut vars = home.clone();
        vars.push(("HOOK".into(), "./h.mjs".into()));
        let p = npm_node_options_problems(&dir.join("web"), &vars, None);
        assert!(p.iter().any(|x| x.contains("--import=./h.mjs")), "{p:?}");
        std::fs::remove_file(dir.join("home/.npmrc")).unwrap();
        std::fs::create_dir_all(dir.join("prefix/etc")).unwrap();
        std::fs::write(dir.join("prefix/etc/npmrc"), "node-options=--test-only\n").unwrap();
        assert!(
            !npm_node_options_problems(&dir.join("web"), none, Some(&dir.join("prefix")))
                .is_empty()
        );
        std::fs::remove_file(dir.join("prefix/etc/npmrc")).unwrap();
        std::fs::create_dir_all(dir.join("home/.config/pnpm")).unwrap();
        std::fs::write(
            dir.join("home/.config/pnpm/rc"),
            "node-options=--require=x\n",
        )
        .unwrap();
        assert!(!npm_node_options_problems(&dir.join("web"), none, None).is_empty());
        std::fs::remove_file(dir.join("home/.config/pnpm/rc")).unwrap();
        let mut vars = home.clone();
        vars.push(("npm_config_node_options".into(), "--require=x".into()));
        assert!(!npm_node_options_problems(&dir.join("web"), &vars, None).is_empty());
        // Through the adapter: a script project is refused.
        std::fs::write(dir.join(".npmrc"), "node-options=--require ./setup.cjs\n").unwrap();
        std::fs::write(
            dir.join("web/package.json"),
            r#"{"scripts":{"test":"node --test"}}"#,
        )
        .unwrap();
        let e = NodeTestAdapter::new(&dir.join("web"))
            .invocation()
            .unwrap_err();
        assert!(e.to_string().contains("node-options"), "{e}");
    }

    /// Regression: install scripts that may patch node_modules (or write
    /// files) refuse the project; git hook installers and patch-package
    /// (its patches/ are a global input) do not.
    #[test]
    fn install_scripts_are_checked() {
        let t = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(t.path()).unwrap();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::create_dir_all(dir.join("web")).unwrap();
        std::fs::write(
            dir.join("web/package.json"),
            r#"{"scripts":{"test":"node --test"}}"#,
        )
        .unwrap();
        for (root, ok) in [
            (r#"{"scripts":{"prepare":"husky"}}"#, true),
            (r#"{"scripts":{"prepare":"is-ci || husky install"}}"#, true),
            (r#"{"scripts":{"postinstall":"patch-package"}}"#, true),
            (
                r#"{"scripts":{"postinstall":"node scripts/apply-patches.mjs"}}"#,
                false,
            ),
            (r#"{"scripts":{"prepare":"npm run build"}}"#, false),
            (r#"{"scripts":{"prepare":"husky; node x.mjs"}}"#, false),
            (r#"{"scripts":{"build":"tsc"}}"#, true),
        ] {
            std::fs::write(dir.join("package.json"), root).unwrap();
            let p = install_script_problems(&dir.join("web"));
            assert_eq!(p.is_empty(), ok, "{root}: {p:?}");
            let a = NodeTestAdapter::new(&dir.join("web"));
            assert_eq!(a.invocation().is_ok(), ok, "{root}");
        }
        // A linked workspace package's install script counts too.
        std::fs::write(dir.join("package.json"), "{}").unwrap();
        std::fs::create_dir_all(dir.join("packages/lib")).unwrap();
        std::fs::write(
            dir.join("packages/lib/package.json"),
            r#"{"name":"@fx/lib","scripts":{"postinstall":"node gen.mjs"}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("web/node_modules/@fx")).unwrap();
        std::os::unix::fs::symlink(
            "../../../packages/lib",
            dir.join("web/node_modules/@fx/lib"),
        )
        .unwrap();
        let p = install_script_problems(&dir.join("web"));
        assert!(
            p.len() == 1 && p[0].contains("packages/lib/package.json"),
            "{p:?}"
        );
        let g = NodeTestAdapter::new(&dir.join("web")).with_options(NodeTestOptions {
            test_globs: Some(vec!["*.test.js".into()]),
            ..Default::default()
        });
        assert!(g.invocation().is_err());
    }

    #[test]
    fn package_managers() {
        let t = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(t.path()).unwrap();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::create_dir_all(dir.join("apps/web")).unwrap();
        assert_eq!(package_manager(&dir.join("apps/web")), "npm");
        std::fs::write(dir.join("pnpm-lock.yaml"), "").unwrap();
        assert_eq!(package_manager(&dir.join("apps/web")), "pnpm");
        std::fs::write(
            dir.join("apps/web/package.json"),
            r#"{"packageManager":"yarn@4.0.0"}"#,
        )
        .unwrap();
        assert_eq!(package_manager(&dir.join("apps/web")), "yarn");
    }
}
