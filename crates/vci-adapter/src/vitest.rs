//! Vitest adapter: drives `vitest` through a generated wrapper config that
//! adds the `@vci/vitest` collectors, and parses their JSONL output.

use std::ffi::OsString;
use std::process::{Command, Stdio};

use camino::{Utf8Path, Utf8PathBuf};
use serde_json::Value;

use crate::{
    Adapter, AdapterError, ChildEnv, ListedFile, RunOutput, ToolVersions, parse_jsonl_dir,
};

/// Env var naming the `@vci/vitest` package directory (overrides the
/// project's `node_modules/@vci/vitest`).
pub const JS_PLUGIN_ENV: &str = "VCI_JS_PLUGIN";

/// Env var naming the `node` binary to use (default: `node` on PATH).
pub const NODE_ENV: &str = "VCI_NODE";

const JS_PACKAGE_NAME: &str = "@vci/vitest";

/// Config file names Vitest considers, in its lookup order. Every candidate is
/// a global input (present = read, absent = probe) so that adding a config
/// that shadows another one is noticed.
const CONFIG_NAMES: &[&str] = &[
    "vitest.config.ts",
    "vitest.config.mts",
    "vitest.config.cts",
    "vitest.config.js",
    "vitest.config.mjs",
    "vitest.config.cjs",
    "vite.config.ts",
    "vite.config.mts",
    "vite.config.cts",
    "vite.config.js",
    "vite.config.mjs",
    "vite.config.cjs",
    "vitest.workspace.ts",
    "vitest.workspace.mts",
    "vitest.workspace.js",
    "vitest.workspace.mjs",
    "vitest.workspace.json",
];

/// The Vitest adapter.
#[derive(Debug, Clone)]
pub struct VitestAdapter {
    project_dir: Utf8PathBuf,
    node: OsString,
    js_plugin: Option<Utf8PathBuf>,
}

pub(crate) fn walk_up_find(start: &Utf8Path, rel: &str) -> Option<Utf8PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let p = d.join(rel);
        if p.exists() {
            return Some(p);
        }
        dir = d.parent();
    }
    None
}

fn read_json(p: &Utf8Path) -> Result<Value, AdapterError> {
    let text = std::fs::read_to_string(p)?;
    serde_json::from_str(&text).map_err(|e| AdapterError::Parse {
        what: p.to_string(),
        detail: e.to_string(),
    })
}

fn package_version(pkg_json: &Utf8Path) -> Result<String, AdapterError> {
    read_json(pkg_json)?
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Parse {
            what: pkg_json.to_string(),
            detail: "no version".into(),
        })
}

/// Locate the `@vci/vitest` package: `$VCI_JS_PLUGIN`, else
/// `node_modules/@vci/vitest` found by walking up from the project dir.
/// Returns the package directory.
pub fn find_js_plugin(project_dir: &Utf8Path) -> Result<Utf8PathBuf, AdapterError> {
    let dir = match std::env::var(JS_PLUGIN_ENV) {
        Ok(v) if !v.is_empty() => {
            let p = Utf8PathBuf::from(v);
            if p.is_absolute() {
                p
            } else {
                Utf8PathBuf::from_path_buf(std::env::current_dir()?)
                    .map_err(|p| AdapterError::NotFound(format!("non-UTF-8 cwd {p:?}")))?
                    .join(p)
            }
        }
        _ => walk_up_find(project_dir, "node_modules/@vci/vitest").ok_or_else(|| {
            AdapterError::NotFound(format!(
                "{JS_PACKAGE_NAME} not found: set {JS_PLUGIN_ENV} or install it in {project_dir}"
            ))
        })?,
    };
    let pj = dir.join("package.json");
    let name = read_json(&pj)?
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if name.as_deref() != Some(JS_PACKAGE_NAME) {
        return Err(AdapterError::NotFound(format!(
            "{pj} is not the {JS_PACKAGE_NAME} package (name {name:?})"
        )));
    }
    Ok(dir)
}

fn wrapper_module(plugin_dir: &Utf8Path) -> Result<Utf8PathBuf, AdapterError> {
    let pj = read_json(&plugin_dir.join("package.json"))?;
    let rel = pj
        .get("exports")
        .and_then(|e| e.get("./wrapper"))
        .and_then(Value::as_str)
        .unwrap_or("./src/wrapper.js");
    let p = plugin_dir.join(rel.trim_start_matches("./"));
    if !p.is_file() {
        return Err(AdapterError::NotFound(format!(
            "wrapper module {p} missing"
        )));
    }
    Ok(p)
}

/// The main-process collector (`@vci/vitest/main-preload`), loaded with
/// `node --import` so it is installed before Vitest reads the config. Without
/// it the reporter taints every file (`vci:main-collector-missing`).
fn main_preload_module(plugin_dir: &Utf8Path) -> Result<Utf8PathBuf, AdapterError> {
    let pj = read_json(&plugin_dir.join("package.json"))?;
    let rel = pj
        .get("exports")
        .and_then(|e| e.get("./main-preload"))
        .and_then(Value::as_str)
        .unwrap_or("./src/main/preload.js");
    let p = plugin_dir.join(rel.trim_start_matches("./"));
    if !p.is_file() {
        return Err(AdapterError::NotFound(format!(
            "main-process collector {p} missing (the {JS_PACKAGE_NAME} package is too old)"
        )));
    }
    Ok(p)
}

fn file_url(p: &Utf8Path) -> String {
    // Percent-encode everything outside the unreserved set (plus '/').
    let mut s = String::from("file://");
    for b in p.as_str().bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    s
}

pub(crate) fn apply_env(cmd: &mut Command, env: &ChildEnv) {
    if let Some(vars) = env {
        cmd.env_clear();
        for (k, v) in vars {
            cmd.env(k, v);
        }
    }
    // The collectors only switch on when VCI_OUT is set; never inherit one.
    cmd.env_remove("VCI_OUT");
}

pub(crate) fn describe(cmd: &Command) -> String {
    let mut s = cmd.get_program().to_string_lossy().into_owned();
    for a in cmd.get_args() {
        s.push(' ');
        s.push_str(&a.to_string_lossy());
    }
    s
}

impl VitestAdapter {
    /// `project_dir` must be absolute (it is canonicalised if possible).
    pub fn new(project_dir: &Utf8Path) -> Self {
        let project_dir = project_dir
            .canonicalize_utf8()
            .unwrap_or_else(|_| project_dir.to_owned());
        let node = std::env::var_os(NODE_ENV)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "node".into());
        Self {
            project_dir,
            node,
            js_plugin: None,
        }
    }

    /// Use this `@vci/vitest` package directory instead of looking it up.
    pub fn with_js_plugin(mut self, dir: impl Into<Utf8PathBuf>) -> Self {
        self.js_plugin = Some(dir.into());
        self
    }

    fn vitest_bin(&self) -> Result<Utf8PathBuf, AdapterError> {
        walk_up_find(&self.project_dir, "node_modules/vitest/vitest.mjs").ok_or_else(|| {
            AdapterError::NotFound(format!(
                "vitest is not installed (no node_modules/vitest/vitest.mjs above {})",
                self.project_dir
            ))
        })
    }

    fn node_cmd(&self) -> Command {
        let mut c = Command::new(&self.node);
        c.current_dir(&self.project_dir);
        c
    }

    /// Write the wrapper config into `dir`; returns its path.
    pub fn write_wrapper(
        &self,
        plugin_dir: &Utf8Path,
        dir: &Utf8Path,
    ) -> Result<Utf8PathBuf, AdapterError> {
        let module = wrapper_module(plugin_dir)?;
        let out_file = dir.join("vitest.config.vci.mjs");
        let script = "const [root, outFile, url] = process.argv.slice(1);\
            const m = await import(url);\
            process.stdout.write(m.writeWrapperConfig({ root, outFile }));";
        let mut cmd = self.node_cmd();
        cmd.args(["--input-type=module", "-e", script])
            .arg(self.project_dir.as_str())
            .arg(out_file.as_str())
            .arg(file_url(&module));
        let out = cmd.stdin(Stdio::null()).output()?;
        if !out.status.success() {
            return Err(AdapterError::Command {
                cmd: describe(&cmd),
                status: out.status.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        let written = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !Utf8Path::new(&written).is_file() {
            return Err(AdapterError::Parse {
                what: "wrapper path".into(),
                detail: written,
            });
        }
        Ok(Utf8PathBuf::from(written))
    }
}

impl Adapter for VitestAdapter {
    fn name(&self) -> &'static str {
        "vitest"
    }

    fn project_dir(&self) -> &Utf8Path {
        &self.project_dir
    }

    fn list_test_files(&self, env: &ChildEnv) -> Result<Vec<ListedFile>, AdapterError> {
        let bin = self.vitest_bin()?;
        let tmp = tempfile::tempdir()?;
        let json_path = tmp.path().join("list.json");
        let mut cmd = self.node_cmd();
        cmd.arg(bin.as_str())
            .args(["list", "--filesOnly"])
            .arg(format!("--json={}", json_path.display()));
        apply_env(&mut cmd, env);
        let out = cmd.stdin(Stdio::null()).output()?;
        if !out.status.success() {
            return Err(AdapterError::Command {
                cmd: describe(&cmd),
                status: out.status.to_string(),
                stderr: format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ),
            });
        }
        let text = std::fs::read_to_string(&json_path)?;
        let v: Value = serde_json::from_str(&text).map_err(|e| AdapterError::Parse {
            what: "vitest list --json".into(),
            detail: e.to_string(),
        })?;
        let arr = v.as_array().ok_or_else(|| AdapterError::Parse {
            what: "vitest list --json".into(),
            detail: "not an array".into(),
        })?;
        let mut files = Vec::new();
        for item in arr {
            let file =
                item.get("file")
                    .and_then(Value::as_str)
                    .ok_or_else(|| AdapterError::Parse {
                        what: "vitest list --json".into(),
                        detail: format!("entry without file: {item}"),
                    })?;
            let p = Utf8Path::new(file);
            let abs = if p.is_absolute() {
                p.to_owned()
            } else {
                self.project_dir.join(p)
            };
            let project = item
                .get("projectName")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            files.push(ListedFile { abs, project });
        }
        Ok(files)
    }

    fn tool_versions(&self) -> Result<ToolVersions, AdapterError> {
        let mut cmd = self.node_cmd();
        cmd.arg("--version");
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
        let vitest_pj = walk_up_find(&self.project_dir, "node_modules/vitest/package.json")
            .ok_or_else(|| AdapterError::NotFound("vitest package.json".into()))?;
        let runner = package_version(&vitest_pj)?;
        // Same lookup order as the collector: vite resolved from the project
        // root first, then from vitest's own location.
        let vite_pj = walk_up_find(&self.project_dir, "node_modules/vite/package.json")
            .or_else(|| {
                let real = vitest_pj.parent()?.canonicalize_utf8().ok()?;
                walk_up_find(&real, "node_modules/vite/package.json")
            })
            .ok_or_else(|| AdapterError::NotFound("vite package.json".into()))?;
        let bundler = package_version(&vite_pj)?;
        Ok(ToolVersions {
            node,
            runner,
            bundler,
            ..Default::default()
        })
    }

    fn canonical_argv(&self, project_dir_rel_to_repo: &str, project_rel: &str) -> Vec<String> {
        vec![
            "vitest".into(),
            "run".into(),
            "--root".into(),
            project_dir_rel_to_repo.into(),
            project_rel.into(),
        ]
    }

    fn config_candidates(&self) -> Vec<Utf8PathBuf> {
        CONFIG_NAMES
            .iter()
            .map(|n| self.project_dir.join(n))
            .collect()
    }

    fn snapshot_candidates(&self, test_abs: &Utf8Path) -> Vec<Utf8PathBuf> {
        match (test_abs.parent(), test_abs.file_name()) {
            (Some(dir), Some(name)) => vec![dir.join("__snapshots__").join(format!("{name}.snap"))],
            _ => vec![],
        }
    }

    fn inferred_env_patterns(&self) -> &'static [&'static str] {
        &["VITE_*"]
    }

    fn run_collect(&self, files: &[String], env: &ChildEnv) -> Result<RunOutput, AdapterError> {
        let bin = self.vitest_bin()?;
        let plugin = match &self.js_plugin {
            Some(p) => p.clone(),
            None => find_js_plugin(&self.project_dir)?,
        };
        let wrapper_dir = tempfile::Builder::new().prefix("vci-wrapper-").tempdir()?;
        let out_dir = tempfile::Builder::new().prefix("vci-out-").tempdir()?;
        let wrapper_dir_p = Utf8Path::from_path(wrapper_dir.path())
            .ok_or_else(|| AdapterError::NotFound("non-UTF-8 temp dir".into()))?;
        let out_dir_p = Utf8Path::from_path(out_dir.path())
            .ok_or_else(|| AdapterError::NotFound("non-UTF-8 temp dir".into()))?;
        let wrapper = self.write_wrapper(&plugin, wrapper_dir_p)?;
        let main_preload = main_preload_module(&plugin)?;

        let mut cmd = self.node_cmd();
        cmd.arg("--import")
            .arg(file_url(&main_preload))
            .arg(bin.as_str())
            .arg("run")
            .arg("--config")
            .arg(wrapper.as_str())
            .args(files);
        apply_env(&mut cmd, env);
        cmd.env("VCI_OUT", out_dir_p.as_str());
        // Vitest's own output goes to our stderr so that stdout stays clean for
        // machine-readable output of the CLI.
        cmd.stdin(Stdio::null()).stdout(std::io::stderr());
        let status = cmd.status()?;
        let files = parse_jsonl_dir(out_dir_p)?;
        Ok(RunOutput {
            exit_code: status.code(),
            files,
        })
    }

    fn run_plain(&self, files: &[String], env: &ChildEnv) -> Result<Option<i32>, AdapterError> {
        let bin = self.vitest_bin()?;
        let mut cmd = self.node_cmd();
        cmd.arg(bin.as_str()).arg("run").args(files);
        apply_env(&mut cmd, env);
        cmd.stdin(Stdio::null()).stdout(std::io::stderr());
        Ok(cmd.status()?.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_url_escapes() {
        assert_eq!(
            file_url(Utf8Path::new("/a b/c#d.js")),
            "file:///a%20b/c%23d.js"
        );
    }

    #[test]
    fn snapshot_candidates_follow_vitest_layout() {
        let a = VitestAdapter::new(Utf8Path::new("/nonexistent/proj"));
        assert_eq!(
            a.snapshot_candidates(Utf8Path::new("/p/src/b.test.ts")),
            vec![Utf8PathBuf::from("/p/src/__snapshots__/b.test.ts.snap")]
        );
        assert_eq!(
            a.canonical_argv(".", "src/b.test.ts"),
            ["vitest", "run", "--root", ".", "src/b.test.ts"]
        );
        assert!(
            a.config_candidates()
                .iter()
                .any(|p| p.ends_with("vitest.config.ts"))
        );
    }
}
