//! `vci env`: the effective environment policy of every project (docs/ENV.md),
//! as vci applies it here: which variables vci sets, hashes, ignores or
//! removes, why, and what they are on this machine.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use serde::Serialize;

use crate::config::{CONFIG_FILE, Config, EnvConfig, ProjectSpec};
use crate::ctx::{Ctx, Project, open_repo, working_tree_config};
use crate::envpolicy::{ChildEnvMap, EnvClass, FileEnv, list_matches};
use crate::util::name_match;

pub struct EnvArgs {
    pub base_ref: Option<String>,
    pub project: Option<String>,
    pub json: bool,
}

#[derive(Debug, Serialize)]
pub struct Row {
    /// A variable name, or a pattern (with `*`) standing for the variables it
    /// matches.
    pub variable: String,
    pub class: EnvClass,
    pub source: String,
    /// On this machine: the value vci sets (`set`), `present` with the hash
    /// prefix (hashed classes), `present`/`absent`, or for a pattern the
    /// number of variables it matches here.
    pub here: String,
    /// With `--base-ref`: `None` when the base policy classifies it the same
    /// way, else what the base does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectEnv {
    pub project: String,
    pub adapter: String,
    /// The project-wide env config digest (per file it also depends on the
    /// `[[env.files]]` entries that match).
    pub digest: String,
    /// With `--base-ref`: whether the base commit's policy differs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_differs: Option<bool>,
    pub rows: Vec<Row>,
}

pub fn env(args: EnvArgs) -> Result<i32> {
    let (repo, root) = open_repo()?;
    let config = working_tree_config(&root)?;
    for w in config.warnings(CONFIG_FILE) {
        eprintln!("vci: warning: {w}");
    }
    let base = match &args.base_ref {
        None => None,
        Some(r) => {
            let (name, commit) =
                crate::plan::resolve_base(&repo, Some(r)).map_err(anyhow::Error::msg)?;
            let text = repo
                .show_file(&commit, CONFIG_FILE)?
                .map(String::from_utf8)
                .transpose()?;
            let c = match text {
                Some(t) => Config::parse(&t)?,
                None => {
                    eprintln!("vci: {CONFIG_FILE} is missing at {name}; comparing with defaults");
                    Config::default()
                }
            };
            for w in c.warnings(&format!("{CONFIG_FILE} at {name}")) {
                eprintln!("vci: warning: {w}");
            }
            Some(c)
        }
    };
    let ctx = Ctx::new(repo, root, config.clone())?;
    let mut out = Vec::new();
    for (i, p) in ctx.projects.iter().enumerate() {
        if let Some(want) = &args.project
            && p.name != *want
            && p.label() != *want
        {
            continue;
        }
        let base_spec = base.as_ref().map(|c| {
            c.project_specs()
                .into_iter()
                .find(|s| s.name == p.name && s.adapter == p.adapter.name())
        });
        out.push(project_env(p, &config, i, base_spec));
    }
    if out.is_empty() {
        bail!(
            "no project named {:?} in {CONFIG_FILE}",
            args.project.unwrap_or_default()
        );
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print!("{}", render(&out));
    }
    Ok(0)
}

/// The base policy of a project, built like the working tree's (with this
/// vci's built-in lists and the adapter's own declarations).
fn base_policy(p: &Project, spec: &ProjectSpec) -> FileEnv {
    let mut env = spec.env.clone();
    for k in p.adapter.declared_env() {
        if !env.hash.contains(&k) {
            env.hash.push(k);
        }
    }
    FileEnv::for_project(&env)
        .with_builtins(p.adapter.builtin_hash(), p.adapter.builtin_ignore())
        .with_loose_hash(p.adapter.loose_hash())
        .with_adapter(p.adapter.name())
}

/// Whether the project's `hash`/`ignore` came from an old key name.
fn old_name(config: &Config, idx: usize, new: &str) -> Option<&'static str> {
    let old = match new {
        "hash" => "global",
        _ => "pass_through",
    };
    let own = config
        .projects
        .get(idx)
        .and_then(|p| p.env.as_ref())
        .map(|o| {
            if new == "hash" {
                o.hash.is_some()
            } else {
                o.ignore.is_some()
            }
        })
        .unwrap_or(false);
    let at = match config.projects.get(idx) {
        Some(p) if own => format!("projects.{}.env.{old}", p.name),
        _ => format!("env.{old}"),
    };
    config
        .env_renamed
        .iter()
        .any(|(k, _)| *k == at)
        .then_some(if new == "hash" {
            "global"
        } else {
            "pass_through"
        })
}

fn project_env(
    p: &Project,
    config: &Config,
    idx: usize,
    base: Option<Option<ProjectSpec>>,
) -> ProjectEnv {
    let policy = p.project_env();
    let child = p.child_env();
    let user: &EnvConfig = &p.env;
    let base_policy = base
        .as_ref()
        .map(|b| b.as_ref().map(|spec| base_policy(p, spec)));
    let adapter = p.adapter.name();
    let mut rows: Vec<Row> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let machine: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .collect();

    let source_of = |name: &str, class: EnvClass| -> String {
        match class {
            EnvClass::Set => "vci.toml set".into(),
            EnvClass::Hash | EnvClass::Ignore => {
                let (key, own) = if class == EnvClass::Hash {
                    ("hash", &user.hash)
                } else {
                    ("ignore", &user.ignore)
                };
                if list_matches(own, name) {
                    match old_name(config, idx, key) {
                        Some(old) => format!("vci.toml {old} (old name of {key})"),
                        None => format!("vci.toml {key}"),
                    }
                } else if user.files.iter().any(|f| {
                    list_matches(
                        if class == EnvClass::Hash {
                            &f.hash
                        } else {
                            &f.ignore
                        },
                        name,
                    )
                }) {
                    format!("vci.toml [[env.files]] {key}")
                } else {
                    "test script".into()
                }
            }
            EnvClass::BuiltinHash | EnvClass::BuiltinIgnore => {
                let common = if class == EnvClass::BuiltinHash {
                    vci_adapter::COMMON_HASH
                } else {
                    vci_adapter::COMMON_IGNORE
                };
                if common.iter().any(|c| name_match(c, name)) {
                    "built-in (every runner)".into()
                } else {
                    format!("built-in {adapter}")
                }
            }
            EnvClass::Stripped => "-".into(),
        }
    };
    let here = |name: &str, class: EnvClass, child: &ChildEnvMap| -> String {
        match class {
            EnvClass::Set => format!("{:?}", policy.set.get(name).cloned().unwrap_or_default()),
            EnvClass::Hash | EnvClass::BuiltinHash => match child.get(name) {
                Some(v) => format!(
                    "present ({})",
                    &vci_core::manifest::env_value_hash(Some(v.as_os_str()))[..12]
                ),
                None => "absent".into(),
            },
            EnvClass::Ignore | EnvClass::BuiltinIgnore => if child.get(name).is_some() {
                "present"
            } else {
                "absent"
            }
            .into(),
            EnvClass::Stripped => if std::env::var_os(name).is_some() {
                "present (removed)"
            } else {
                "absent"
            }
            .into(),
        }
    };
    let base_col = |name: &str, class: EnvClass| -> Option<String> {
        let b = base_policy.as_ref()?;
        let Some(b) = b else {
            return Some("no such project".into());
        };
        let bc = b.classify(name);
        if bc != class {
            return Some(bc.label().into());
        }
        if class == EnvClass::Set && b.set.get(name) != policy.set.get(name) {
            return Some(format!(
                "set {:?}",
                b.set.get(name).cloned().unwrap_or_default()
            ));
        }
        None
    };
    // A pattern row: the pattern itself, with how many variables it matches
    // here; then one row per matching variable.
    let add = |name: &str, class: EnvClass, rows: &mut Vec<Row>, seen: &mut BTreeSet<String>| {
        if !seen.insert(name.to_owned()) {
            return;
        }
        if name.contains('*') {
            let mut matches: Vec<&String> = machine
                .iter()
                .chain(child.keys())
                .filter(|k| name_match(name, k) && policy.classify(k) == class)
                .collect();
            matches.sort();
            matches.dedup();
            let base = base_policy.as_ref().and_then(|b| match b {
                None => Some("no such project".into()),
                Some(b) => {
                    let list = match class {
                        EnvClass::Hash | EnvClass::BuiltinHash => (&b.hash, &b.builtin_hash),
                        _ => (&b.ignore, &b.builtin_ignore),
                    };
                    let own = matches!(class, EnvClass::Hash | EnvClass::Ignore);
                    let has = if own { list.0 } else { list.1 }.iter().any(|p| p == name);
                    (!has).then(|| "not listed".into())
                }
            });
            rows.push(Row {
                variable: name.to_owned(),
                class,
                source: source_of(name, class),
                here: format!("pattern: {} here", matches.len()),
                base,
            });
            for m in matches {
                if seen.insert(m.clone()) {
                    rows.push(Row {
                        variable: m.clone(),
                        class,
                        source: source_of(m, class),
                        here: here(m, class, &child),
                        base: base_col(m, class),
                    });
                }
            }
            return;
        }
        let class = policy.classify(name);
        rows.push(Row {
            variable: name.to_owned(),
            class,
            source: source_of(name, class),
            here: here(name, class, &child),
            base: base_col(name, class),
        });
    };

    for k in policy.set.keys() {
        add(k, EnvClass::Set, &mut rows, &mut seen);
    }
    for (list, class) in [
        (&policy.hash, EnvClass::Hash),
        (&policy.ignore, EnvClass::Ignore),
        (&policy.builtin_hash, EnvClass::BuiltinHash),
        (&policy.builtin_ignore, EnvClass::BuiltinIgnore),
    ] {
        for pat in list.iter().filter(|p| !p.starts_with('!')) {
            if pat.contains('*') || policy.classify(pat) == class {
                add(pat, class, &mut rows, &mut seen);
            }
        }
    }
    // Present here, removed from the test processes.
    let mut stripped: Vec<&String> = machine
        .iter()
        .filter(|k| policy.classify(k) == EnvClass::Stripped && child.get(k).is_none())
        .collect();
    stripped.sort();
    for k in stripped {
        add(k, EnvClass::Stripped, &mut rows, &mut seen);
    }
    // Set at base, gone here.
    if let Some(Some(b)) = &base_policy {
        for k in b.set.keys() {
            if !seen.contains(k) {
                let class = policy.classify(k);
                rows.push(Row {
                    variable: k.clone(),
                    class,
                    source: source_of(k, class),
                    here: here(k, class, &child),
                    base: Some(format!("set {:?}", b.set[k])),
                });
            }
        }
    }
    ProjectEnv {
        project: p.label(),
        adapter: adapter.to_owned(),
        digest: policy.digest(),
        base_differs: base_policy.as_ref().map(|b| match b {
            None => true,
            Some(b) => b.digest() != policy.digest(),
        }),
        rows,
    }
}

/// The text table.
pub fn render(projects: &[ProjectEnv]) -> String {
    let mut s = String::new();
    for (i, p) in projects.iter().enumerate() {
        if i > 0 {
            s.push('\n');
        }
        s.push_str(&format!(
            "project {} ({}): env config {}{}\n",
            p.project,
            p.adapter,
            &p.digest[..12],
            match p.base_differs {
                None => "",
                Some(true) => ", base policy differs",
                Some(false) => ", same as base",
            }
        ));
        let with_base = p.base_differs.is_some();
        let mut table: Vec<[String; 5]> = vec![[
            "VARIABLE".into(),
            "CLASS".into(),
            "SOURCE".into(),
            "HERE".into(),
            "BASE".into(),
        ]];
        // Built-in variables not set here say nothing about this machine:
        // listed in one line (all of them are rows in the JSON output).
        let quiet = |r: &Row| {
            matches!(r.class, EnvClass::BuiltinHash | EnvClass::BuiltinIgnore)
                && r.base.is_none()
                && (r.here == "absent" || r.here == "pattern: 0 here")
        };
        let mut unset: Vec<&str> = Vec::new();
        let mut removed: Vec<&str> = Vec::new();
        for r in &p.rows {
            if quiet(r) {
                unset.push(&r.variable);
                continue;
            }
            if r.class == EnvClass::Stripped && r.base.is_none() {
                removed.push(&r.variable);
                continue;
            }
            table.push([
                r.variable.clone(),
                r.class.label().into(),
                r.source.clone(),
                r.here.clone(),
                r.base.clone().unwrap_or_else(|| "=".into()),
            ]);
        }
        let cols = if with_base { 5 } else { 4 };
        let widths: Vec<usize> = (0..cols)
            .map(|c| {
                table
                    .iter()
                    .map(|r| r[c].chars().count())
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        for r in &table {
            let mut line = String::from(" ");
            for c in 0..cols {
                line.push(' ');
                if c + 1 == cols {
                    line.push_str(&r[c]);
                } else {
                    line.push_str(&format!("{:w$}", r[c], w = widths[c]));
                    line.push(' ');
                }
            }
            s.push_str(line.trim_end());
            s.push('\n');
        }
        for (what, names) in [
            ("built-in, not set here", &unset),
            (
                "present here, removed from the tests (recorded as absent if a test reads one)",
                &removed,
            ),
        ] {
            if !names.is_empty() {
                s.push_str(&format!("  {what}:\n"));
                s.push_str(&wrap(names, 4, 100));
            }
        }
    }
    s
}

/// `names` separated by spaces, in lines of at most `width` columns indented
/// by `indent`.
fn wrap(names: &[&str], indent: usize, width: usize) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for n in names {
        if !line.is_empty() && indent + line.len() + 1 + n.len() > width {
            out.push_str(&format!("{:indent$}{line}\n", ""));
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(n);
    }
    if !line.is_empty() {
        out.push_str(&format!("{:indent$}{line}\n", ""));
    }
    out
}
