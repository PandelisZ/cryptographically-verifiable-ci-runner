//! Cargo configuration files (`.cargo/config.toml`, `.cargo/config`) as far
//! as they change what a unit builds or runs.
//!
//! Configuration inside the repository is a hashed global input, so it is the
//! same wherever an attestation is checked, but parts of it do not act the
//! same everywhere or name programs vci does not hash:
//!
//! * `[target.'cfg(..)']` tables apply only where the predicate holds: the
//!   predicate is recorded like a `cfg` in the source (so a table for
//!   `target_os = "macos"` makes the unit run on Linux);
//! * `[target.<triple>]` tables apply only on that triple: the unit is pinned
//!   to the attesting OS and architecture;
//! * `runner` and `linker` (in any target table) name programs whose contents
//!   are not inputs: the unit is refused;
//! * `build.rustc-wrapper` / `build.rustc-workspace-wrapper` (and the
//!   `RUSTC_WRAPPER` family of variables) run a program around every rustc
//!   call: only `sccache` is accepted.
//!
//! The rustflags a build uses (environment, then target tables, then
//! `build.rustflags`) are also applied when vci probes `rustc --print cfg`,
//! so the recorded cfg set is the one the code was compiled with.

use std::collections::BTreeSet;

use camino::{Utf8Path, Utf8PathBuf};

use super::cfgexpr;

/// A config file cargo reads, and whether it is inside the repository.
#[derive(Debug, Clone)]
pub(crate) struct ConfigFile {
    pub path: Utf8PathBuf,
    pub inside: bool,
    pub table: Result<toml::Table, String>,
}

/// What the repository's config files mean for every unit.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ConfigFacts {
    /// Reasons no unit is attestable.
    pub taints: BTreeSet<String>,
    /// Target-dependent predicates of `[target.'cfg(..)']` tables.
    pub cfg_predicates: BTreeSet<String>,
    /// Config files with `[target.<triple>]` tables (or a cfg key vci cannot
    /// read): the attestation needs the same OS and architecture.
    pub platform_files: BTreeSet<Utf8PathBuf>,
}

/// Wrappers accepted around rustc: compilation caches keyed on the
/// compiler's inputs, which do not change what is compiled.
const ACCEPTED_WRAPPERS: &[&str] = &["sccache"];

/// Facts of the repository's config files (`files` in any order).
pub(crate) fn repo_facts(files: &[ConfigFile]) -> ConfigFacts {
    let mut f = ConfigFacts::default();
    for c in files.iter().filter(|c| c.inside) {
        let table = match &c.table {
            Ok(t) => t,
            Err(e) => {
                f.taints
                    .insert(format!("cargo:config: {} cannot be read: {e}", c.path));
                continue;
            }
        };
        let Some(targets) = table.get("target").and_then(toml::Value::as_table) else {
            continue;
        };
        for (key, v) in targets {
            if let Some(pred) = key.strip_prefix("cfg(").and_then(|k| k.strip_suffix(')')) {
                match cfgexpr::parse(pred) {
                    Ok(p) if p.mentions_platform() => {
                        f.cfg_predicates.insert(p.to_string());
                    }
                    Ok(_) => {}
                    Err(_) => {
                        f.platform_files.insert(c.path.clone());
                    }
                }
            } else {
                // `[target.x86_64-unknown-linux-gnu]`: only on that triple.
                f.platform_files.insert(c.path.clone());
            }
            let Some(t) = v.as_table() else { continue };
            for k in ["runner", "linker"] {
                if t.contains_key(k) {
                    f.taints.insert(format!(
                        "cargo:config: {} sets target.{key}.{k}: the program it names is not an input vci hashes (custom test runners and linkers are not supported)",
                        c.path
                    ));
                }
            }
        }
    }
    f
}

/// `build.<key>` of the first config (highest precedence first) that sets
/// it.
fn build_key<'a>(files: &'a [ConfigFile], key: &str) -> Option<(&'a Utf8Path, String)> {
    files.iter().find_map(|c| {
        let v = c.table.as_ref().ok()?.get("build")?.as_table()?.get(key)?;
        let s = match v {
            toml::Value::String(s) => s.clone(),
            // `rustc-wrapper = ["path", "arg"]` is not a valid form; show it.
            other => other.to_string(),
        };
        Some((c.path.as_path(), s))
    })
}

/// Wrappers around rustc that change what is compiled without being inputs:
/// every effective `RUSTC_WRAPPER`/`RUSTC_WORKSPACE_WRAPPER` (environment,
/// else config) that is not a known compilation cache. `var` looks up the
/// child's environment; `files` is highest precedence first.
pub(crate) fn wrapper_problems(
    var: &dyn Fn(&str) -> Option<String>,
    files: &[ConfigFile],
) -> Vec<String> {
    let mut out = Vec::new();
    for (envs, key) in [
        (
            ["RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER"],
            "rustc-wrapper",
        ),
        (
            [
                "RUSTC_WORKSPACE_WRAPPER",
                "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            ],
            "rustc-workspace-wrapper",
        ),
    ] {
        let (from, value) = match envs
            .iter()
            .find_map(|e| var(e).map(|v| (format!("${e}"), v)))
        {
            Some(x) => x,
            None => match build_key(files, key) {
                Some((f, v)) => (format!("build.{key} in {f}"), v),
                None => continue,
            },
        };
        if value.is_empty() {
            continue;
        }
        let name = Utf8Path::new(&value)
            .file_stem()
            .unwrap_or(value.as_str())
            .to_owned();
        if !ACCEPTED_WRAPPERS.contains(&name.as_str()) {
            out.push(format!(
                "cargo:wrapper: {from} = {value:?} runs a program around rustc that can change what is compiled, and vci does not hash it (only {} is accepted)",
                ACCEPTED_WRAPPERS.join(", ")
            ));
        }
    }
    out
}

/// A `rustflags` value: an array of strings, or a string split on
/// whitespace.
fn flags_of(v: &toml::Value) -> Vec<String> {
    match v {
        toml::Value::String(s) => s.split_whitespace().map(str::to_owned).collect(),
        toml::Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect(),
        _ => vec![],
    }
}

/// The flags cargo passes to rustc for the host, as cargo chooses them:
/// `CARGO_ENCODED_RUSTFLAGS`, else `RUSTFLAGS`, else every matching
/// `target.<host>.rustflags` / `target.'cfg(..)'.rustflags` (and
/// `CARGO_TARGET_<HOST>_RUSTFLAGS`) joined, else `build.rustflags`
/// (`CARGO_BUILD_RUSTFLAGS`). Config arrays are joined across files, the
/// highest-precedence file last. `base_cfg` is `rustc --print cfg` without
/// flags (to match `cfg(..)` tables). `files` is highest precedence first.
pub(crate) fn effective_rustflags(
    var: &dyn Fn(&str) -> Option<String>,
    files: &[ConfigFile],
    host: &str,
    base_cfg: &[String],
) -> Vec<String> {
    if let Some(enc) = var("CARGO_ENCODED_RUSTFLAGS") {
        return enc
            .split('\x1f')
            .filter(|f| !f.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if let Some(f) = var("RUSTFLAGS") {
        return f.split_whitespace().map(str::to_owned).collect();
    }
    let var = |k: &str| var(k).filter(|v| !v.is_empty());
    let mut target: Vec<String> = Vec::new();
    let mut build: Vec<String> = Vec::new();
    for c in files.iter().rev() {
        let Ok(t) = &c.table else { continue };
        if let Some(targets) = t.get("target").and_then(toml::Value::as_table) {
            for (key, v) in targets {
                let applies = key == host
                    || key
                        .strip_prefix("cfg(")
                        .and_then(|k| k.strip_suffix(')'))
                        .is_some_and(|p| cfgexpr::holds(p, base_cfg).unwrap_or(false));
                if applies && let Some(f) = v.get("rustflags") {
                    target.extend(flags_of(f));
                }
            }
        }
        if let Some(f) = t
            .get("build")
            .and_then(toml::Value::as_table)
            .and_then(|b| b.get("rustflags"))
        {
            build.extend(flags_of(f));
        }
    }
    let host_env = format!(
        "CARGO_TARGET_{}_RUSTFLAGS",
        host.to_uppercase().replace(['-', '.'], "_")
    );
    if let Some(f) = var(&host_env) {
        target.extend(f.split_whitespace().map(str::to_owned));
    }
    if !target.is_empty() {
        return target;
    }
    if let Some(f) = var("CARGO_BUILD_RUSTFLAGS") {
        return f.split_whitespace().map(str::to_owned).collect();
    }
    build
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, inside: bool, text: &str) -> ConfigFile {
        ConfigFile {
            path: Utf8PathBuf::from(path),
            inside,
            table: toml::from_str(text).map_err(|e| e.to_string()),
        }
    }

    fn mac() -> Vec<String> {
        [
            "target_arch=\"aarch64\"",
            "target_os=\"macos\"",
            "target_family=\"unix\"",
            "unix",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    #[test]
    fn target_tables_are_recorded_pinned_or_refused() {
        let f = repo_facts(&[file(
            "/r/.cargo/config.toml",
            true,
            "[target.'cfg(target_os = \"macos\")']\nrustflags = [\"--cfg\", \"on_mac\"]\n[target.'cfg(all(unix, not(windows)))']\nrustflags = []\n",
        )]);
        assert_eq!(
            f.cfg_predicates.iter().collect::<Vec<_>>(),
            ["all(unix, not(windows))", "target_os = \"macos\""]
        );
        assert!(f.platform_files.is_empty() && f.taints.is_empty(), "{f:?}");
        let f = repo_facts(&[file(
            "/r/.cargo/config.toml",
            true,
            "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"--cfg\", \"on_linux\"]\n",
        )]);
        assert_eq!(f.platform_files.len(), 1, "{f:?}");
        let f = repo_facts(&[file(
            "/r/.cargo/config.toml",
            true,
            "[target.aarch64-apple-darwin]\nrunner = \"tools/run.sh\"\n[target.'cfg(unix)']\nlinker = \"cc\"\n",
        )]);
        assert_eq!(f.taints.len(), 2, "{f:?}");
        assert!(f.taints.iter().any(|t| t.contains("runner")));
        // Outside the repository: config_problems' business, not these facts.
        let f = repo_facts(&[file(
            "/x/.cargo/config.toml",
            false,
            "[target.aarch64-apple-darwin]\nrunner = \"r\"\n",
        )]);
        assert_eq!(f, ConfigFacts::default());
    }

    #[test]
    fn only_known_caches_may_wrap_rustc() {
        let none = |_: &str| None;
        let files = [file(
            "/r/.cargo/config.toml",
            true,
            "[build]\nrustc-wrapper = \"tools/wrap.sh\"\n",
        )];
        let p = wrapper_problems(&none, &files);
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(p[0].contains("tools/wrap.sh"), "{p:?}");
        let env = |k: &str| (k == "RUSTC_WRAPPER").then(|| "/opt/bin/sccache".to_owned());
        assert!(
            wrapper_problems(&env, &files).is_empty(),
            "the variable wins"
        );
        let env = |k: &str| (k == "RUSTC_WORKSPACE_WRAPPER").then(|| "/tmp/wrap_env.sh".to_owned());
        assert_eq!(wrapper_problems(&env, &[]).len(), 1);
        let empty = |k: &str| (k == "RUSTC_WRAPPER").then(String::new);
        assert!(wrapper_problems(&empty, &[]).is_empty());
    }

    #[test]
    fn rustflags_follow_cargos_precedence() {
        let files = [
            file(
                "/r/p/.cargo/config.toml",
                true,
                "[build]\nrustflags = [\"--cfg\", \"inner\"]\n",
            ),
            file(
                "/r/.cargo/config.toml",
                true,
                "[build]\nrustflags = \"--cfg outer\"\n[target.'cfg(target_os = \"linux\")']\nrustflags = [\"--cfg\", \"on_linux\"]\n",
            ),
        ];
        let none = |_: &str| None;
        assert_eq!(
            effective_rustflags(&none, &files, "aarch64-apple-darwin", &mac()),
            ["--cfg", "outer", "--cfg", "inner"],
            "build.rustflags joined, the closer file last"
        );
        let mac_table = [file(
            "/r/.cargo/config.toml",
            true,
            "[build]\nrustflags = [\"--cfg\", \"b\"]\n[target.'cfg(target_os = \"macos\")']\nrustflags = [\"--cfg\", \"on_mac\"]\n[target.aarch64-apple-darwin]\nrustflags = [\"-Ctarget-cpu=native\"]\n",
        )];
        let got = effective_rustflags(&none, &mac_table, "aarch64-apple-darwin", &mac());
        assert!(got.contains(&"on_mac".to_owned()), "{got:?}");
        assert!(got.contains(&"-Ctarget-cpu=native".to_owned()), "{got:?}");
        assert!(
            !got.contains(&"b".to_owned()),
            "target flags replace build.rustflags"
        );
        let env = |k: &str| (k == "RUSTFLAGS").then(|| "-Dwarnings".to_owned());
        assert_eq!(
            effective_rustflags(&env, &mac_table, "aarch64-apple-darwin", &mac()),
            ["-Dwarnings"]
        );
        // Set but empty: no flags at all (cargo ignores the config then).
        let empty = |k: &str| (k == "CARGO_ENCODED_RUSTFLAGS").then(String::new);
        assert!(effective_rustflags(&empty, &mac_table, "aarch64-apple-darwin", &mac()).is_empty());
    }
}
