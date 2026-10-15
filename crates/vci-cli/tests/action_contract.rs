//! The composite action (action.yml) never compiles vci in someone else's CI:
//! it installs the published release binary recorded in release/manifest.txt
//! and fails, with a message naming a release to use, when this commit of the
//! action has none. Compiling happens only with `build-from-source: true` (or
//! the deprecated `prebuilt: false`), which only this repository's demo jobs
//! set. Checks action.yml and ci.yml textually, and runs the install script
//! (scripts/action-binary.sh) against stub `gh`, `curl` and `wget`, and the
//! release process (scripts/publish-release.sh) against a local bare repository.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_owned()
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(workspace_root().join(rel)).unwrap()
}

/// The children of a top-level section (`inputs:`, `jobs:`) at two spaces, as
/// (name, body).
fn section(yaml: &str, name: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut inside = false;
    for line in yaml.lines() {
        if line == format!("{name}:") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('#') {
            break;
        }
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if indent == 2 && !trimmed.starts_with('#') && trimmed.ends_with(':') {
            out.push((trimmed.trim_end_matches(':').to_owned(), String::new()));
        } else if let Some((_, body)) = out.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

/// A step of the composite action: its `id`, `if`, `uses` and the rest.
struct Step {
    id: String,
    cond: String,
    uses: String,
    body: String,
}

fn steps(action: &str) -> Vec<Step> {
    let runs = action.split("\nruns:\n").nth(1).expect("runs:");
    let mut out: Vec<Step> = Vec::new();
    for line in runs.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        if let Some(first) = line.strip_prefix("    - ") {
            out.push(Step {
                id: String::new(),
                cond: String::new(),
                uses: String::new(),
                body: String::new(),
            });
            let step = out.last_mut().unwrap();
            step.body.push_str(first);
            step.body.push('\n');
            continue;
        }
        let Some(step) = out.last_mut() else { continue };
        if let Some(v) = line.strip_prefix("      id: ") {
            step.id = v.trim().to_owned();
        } else if let Some(v) = line.strip_prefix("      if: ") {
            step.cond = v.trim().to_owned();
        } else if let Some(v) = line.strip_prefix("      uses: ") {
            step.uses = v.trim().to_owned();
        }
        step.body.push_str(line);
        step.body.push('\n');
    }
    out
}

fn input_default(action: &str, name: &str) -> Option<String> {
    let inputs = section(action, "inputs");
    let (_, body) = inputs.iter().find(|(n, _)| n == name)?;
    body.lines()
        .find_map(|l| l.trim().strip_prefix("default: "))
        .map(|v| v.trim_matches('"').to_owned())
}

const GATE: &str = "steps.binary.outputs.build == 'true' && (inputs.build-from-source == 'true' || inputs.prebuilt == 'false')";

#[test]
fn build_from_source_is_off_by_default_and_prebuilt_stays_accepted() {
    let action = read("action.yml");
    assert_eq!(
        input_default(&action, "build-from-source").as_deref(),
        Some("false")
    );
    assert_eq!(input_default(&action, "prebuilt").as_deref(), Some("true"));
    let inputs = section(&action, "inputs");
    let (_, prebuilt) = inputs.iter().find(|(n, _)| n == "prebuilt").unwrap();
    assert!(prebuilt.contains("Deprecated"), "{prebuilt}");
}

#[test]
fn nothing_compiles_unless_build_from_source_asks_for_it() {
    let action = read("action.yml");
    let steps = steps(&action);
    let first = &steps[0];
    assert_eq!(first.id, "binary", "the install step must come first");
    assert!(first.cond.is_empty(), "the install step always runs");
    assert!(
        first.body.contains("scripts/action-binary.sh"),
        "{}",
        first.body
    );
    assert!(
        first
            .body
            .contains("BUILD_FROM_SOURCE: ${{ inputs.build-from-source }}")
    );
    assert!(first.body.contains("PREBUILT: ${{ inputs.prebuilt }}"));
    let mut builds = 0;
    for step in &steps[1..] {
        let toolchain = step.body.contains("cargo") || step.body.contains("rustc");
        let cache = step.uses.starts_with("actions/cache");
        if step.body.contains("cargo build") {
            builds += 1;
        }
        if toolchain || cache {
            assert!(
                step.cond.starts_with(GATE),
                "step {:?} runs without build-from-source: if: {:?}\n{}",
                step.id,
                step.cond,
                step.body
            );
        }
    }
    assert_eq!(builds, 1, "exactly one step compiles vci");
}

#[test]
fn every_action_the_action_uses_is_pinned_to_a_commit() {
    let action = read("action.yml");
    for step in steps(&action) {
        if step.uses.is_empty() {
            continue;
        }
        let (_, rest) = step.uses.split_once('@').expect(&step.uses);
        let sha = rest.split_whitespace().next().unwrap();
        assert!(
            sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
            "{} is not pinned to a full commit SHA",
            step.uses
        );
    }
}

#[test]
fn only_this_repositorys_demo_jobs_compile_vci() {
    let ci = read(".github/workflows/ci.yml");
    let jobs = section(&ci, "jobs");
    for name in ["demo", "demo-main"] {
        let (_, body) = jobs.iter().find(|(n, _)| n == name).unwrap();
        assert!(body.contains("- uses: ./\n"), "{name}: {body}");
        assert!(
            body.lines()
                .any(|l| l.trim().starts_with("build-from-source: true")),
            "{name} tests unreleased sources and must set build-from-source: true"
        );
    }
    let (_, v1) = jobs.iter().find(|(n, _)| n == "action-v1").unwrap();
    assert!(
        v1.contains("PandelisZ/cryptographically-verifiable-ci-runner@v1"),
        "{v1}"
    );
    assert!(!v1.contains("build-from-source"), "{v1}");
    assert!(!v1.contains("prebuilt"), "{v1}");
}

#[test]
fn the_manifest_has_a_binary_for_every_platform_the_script_maps() {
    let script = read("scripts/action-binary.sh");
    let manifest = read("release/manifest.txt");
    let mut targets = 0;
    for line in script.lines() {
        if let Some((_, rest)) = line.split_once(") target=") {
            let target = rest.split_whitespace().next().unwrap();
            targets += 1;
            let asset = format!("vci-{target}.tar.gz");
            assert!(
                manifest
                    .lines()
                    .any(|l| l.split_whitespace().nth(1) == Some(asset.as_str())),
                "release/manifest.txt has no checksum for {asset}"
            );
        }
    }
    assert_eq!(targets, 4);
}

#[test]
fn releases_are_built_as_drafts_never_from_a_pushed_version_tag() {
    // A version tag pushed before the binaries exist points at a commit whose
    // release/manifest.txt records the previous release, so the action would
    // refuse `@vX.Y.Z`. The tag is created only when the draft is published,
    // by scripts/publish-release.sh, on the commit that records the manifest.
    let release = read(".github/workflows/release.yml");
    let on = release
        .split("\non:\n")
        .nth(1)
        .and_then(|rest| rest.split("\npermissions:").next())
        .expect("on:");
    assert!(
        !on.contains("push:"),
        "release.yml must not run on a pushed tag: {on}"
    );
    assert!(on.contains("workflow_dispatch:"), "{on}");
    assert!(on.contains("types: [published]"), "{on}");
    assert!(
        release.contains("gh release create \"$TAG\" --draft"),
        "{release}"
    );
    let jobs = section(&release, "jobs");
    for name in ["create", "build"] {
        let (_, body) = jobs.iter().find(|(n, _)| n == name).unwrap();
        assert!(
            body.contains("if: github.event_name == 'workflow_dispatch'"),
            "{name}: {body}"
        );
    }
    let (_, brew) = jobs.iter().find(|(n, _)| n == "homebrew").unwrap();
    assert!(brew.contains("github.event_name == 'release'"), "{brew}");
    let process = read("docs/GITHUB_ACTIONS.md");
    assert!(
        process.contains("scripts/publish-release.sh v"),
        "the documented release process"
    );
    assert!(
        !process.contains("git tag v1"),
        "the documented release process pushes a version tag"
    );
}

// --- scripts/action-binary.sh, run in a copy of the action with stub `gh`,
// `curl` and `wget` on a PATH that has nothing else of the system's ---

const REPO: &str = "PandelisZ/cryptographically-verifiable-ci-runner";
const ASSET: &str = "vci-x86_64-unknown-linux-musl.tar.gz";
const TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-musl",
];

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn action(&self) -> PathBuf {
        self.dir.path().join("action")
    }
    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
}

/// A command with only the fixture's tools on PATH (the stubs named, then
/// `tools/`), a HOME of its own and a fixed git identity.
fn hermetic(fx: &Fixture, program: &str, stubs: &[&str]) -> Command {
    let mut dirs: Vec<String> = stubs
        .iter()
        .map(|s| fx.path(&format!("stub-{s}")).display().to_string())
        .collect();
    dirs.push(fx.path("tools").display().to_string());
    let mut cmd = Command::new(fx.path("tools").join(program));
    cmd.env_clear()
        .env("PATH", dirs.join(":"))
        .env("HOME", fx.path("home"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .env("STUB_LOG", fx.path("calls.log"))
        .env("STUB_ASSETS", fx.path("assets"));
    cmd
}

fn sh_in(fx: &Fixture, dir: &Path, script: &str) -> String {
    let out = hermetic(fx, "sh", &[])
        .arg("-c")
        .arg(script)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{script}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn write_exe(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

/// `tools/`: links to the system commands the scripts use, and nothing else
/// (in particular no gh, curl or wget: those are the stubs).
fn link_tools(fx: &Fixture) {
    let tools = fx.path("tools");
    std::fs::create_dir_all(&tools).unwrap();
    let path = std::env::var("PATH").unwrap();
    for tool in [
        "bash",
        "sh",
        "env",
        "sed",
        "awk",
        "mktemp",
        "cut",
        "sort",
        "find",
        "shasum",
        "sha256sum",
        "perl",
        "tar",
        "gzip",
        "cat",
        "dirname",
        "basename",
        "mkdir",
        "rm",
        "cp",
        "mv",
        "git",
        "tr",
        "head",
        "grep",
        "chmod",
        "ls",
        "wc",
        "uname",
        "xargs",
        "touch",
    ] {
        if let Some(found) = std::env::split_paths(&path)
            .map(|d| d.join(tool))
            .find(|p| p.is_file())
        {
            std::os::unix::fs::symlink(found, tools.join(tool)).unwrap();
        }
    }
    std::fs::create_dir_all(fx.path("home")).unwrap();
}

/// Stubs that serve the files in STUB_ASSETS and log their calls to STUB_LOG.
/// `gh release download` fails with STUB_FAIL set, curl and wget with
/// STUB_CURL_FAIL; `gh release edit --target SHA` creates the tag in the bare
/// repository STUB_ORIGIN, as publishing a draft does.
fn write_stubs(fx: &Fixture) {
    write_exe(
        &fx.path("stub-gh/gh"),
        r#"#!/bin/sh
echo "gh $*" >> "$STUB_LOG"
cmd="$1 $2"; tag=$3; shift 3
patterns=""
while [ $# -gt 0 ]; do
  case "$1" in
    --pattern) patterns="$patterns $2"; shift ;;
    --dir) dir=$2; shift ;;
    --target) target=$2; shift ;;
  esac
  shift
done
case "$cmd" in
  "release download")
    if [ -n "${STUB_FAIL:-}" ]; then echo "HTTP 404: Not Found" >&2; exit 1; fi
    for p in $patterns; do
      for f in "$STUB_ASSETS"/$p; do cp "$f" "$dir/"; done
    done ;;
  "release edit")
    git -C "$STUB_ORIGIN" tag "$tag" "$target" ;;
  *) echo "stub gh: $cmd" >&2; exit 1 ;;
esac
"#,
    );
    let fetch = r#"
echo "$tool $*" >> "$STUB_LOG"
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-O) out=$2; shift ;;
    -*) ;;
    *) url=$1 ;;
  esac
  shift
done
if [ -n "${STUB_CURL_FAIL:-}" ]; then echo "$tool: (22) 404" >&2; exit 22; fi
cp "$STUB_ASSETS/${url##*/}" "$out"
"#;
    write_exe(
        &fx.path("stub-curl/curl"),
        &format!("#!/bin/sh\ntool=curl{fetch}"),
    );
    write_exe(
        &fx.path("stub-wget/wget"),
        &format!("#!/bin/sh\ntool=wget{fetch}"),
    );
}

/// A copy of the action's scripts over a tiny source tree, a release asset,
/// and the stubs. `manifest_source` None records the fixture's own fingerprint.
fn fixture(manifest_source: Option<&str>, checksum: Option<&str>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let fx = Fixture { dir };
    link_tools(&fx);
    write_stubs(&fx);
    let action = fx.action();
    for rel in ["scripts", "release", "crates/x/src"] {
        std::fs::create_dir_all(action.join(rel)).unwrap();
    }
    for script in [
        "action-binary.sh",
        "source-fingerprint.sh",
        "update-release-manifest.sh",
        "publish-release.sh",
    ] {
        let to = action.join("scripts").join(script);
        std::fs::copy(workspace_root().join("scripts").join(script), &to).unwrap();
    }
    std::fs::write(action.join("Cargo.toml"), "[workspace]\n").unwrap();
    std::fs::write(action.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(action.join("crates/x/src/lib.rs"), "\n").unwrap();
    let fingerprint = sh_in(&fx, &action, "scripts/source-fingerprint.sh");

    let assets = fx.path("assets");
    std::fs::create_dir_all(assets.join("pkg")).unwrap();
    std::fs::write(assets.join("pkg/vci"), "#!/bin/sh\necho stub vci\n").unwrap();
    sh_in(&fx, &assets, &format!("tar -C pkg -czf {ASSET} vci"));
    let sum = sh_in(
        &fx,
        &assets,
        &format!(
            "if command -v sha256sum >/dev/null 2>&1; then sha256sum {ASSET}; else shasum -a 256 {ASSET}; fi | cut -d' ' -f1"
        ),
    );
    // What the release workflow uploads next to the binaries.
    std::fs::write(
        assets.join("source-fingerprint.txt"),
        format!("{fingerprint}\n"),
    )
    .unwrap();
    for target in TARGETS {
        let line = if format!("vci-{target}.tar.gz") == ASSET {
            format!("{sum}  {ASSET}\n")
        } else {
            format!("{}  vci-{target}.tar.gz\n", "1".repeat(64))
        };
        std::fs::write(assets.join(format!("SHA256SUMS-{target}")), line).unwrap();
    }
    std::fs::write(
        action.join("release/manifest.txt"),
        format!(
            "# test\ntag=v1.4.0\nsource={}\n{}  {ASSET}\n",
            manifest_source.unwrap_or(&fingerprint),
            checksum.unwrap_or(&sum)
        ),
    )
    .unwrap();
    std::fs::create_dir_all(fx.path("runner-temp")).unwrap();
    fx
}

struct Run {
    ok: bool,
    stdout: String,
    outputs: String,
    /// Every gh, curl and wget call, one per line, prefixed with the tool.
    calls: String,
}

fn run(fx: &Fixture, env: &[(&str, &str)]) -> Run {
    run_with(fx, &["gh", "curl"], env)
}

/// Runs the action's install script with only the stubs named on PATH.
fn run_with(fx: &Fixture, stubs: &[&str], env: &[(&str, &str)]) -> Run {
    run_script(fx, &fx.action(), stubs, env)
}

fn run_script(fx: &Fixture, action: &Path, stubs: &[&str], env: &[(&str, &str)]) -> Run {
    let outputs = fx.path("github-output");
    let log = fx.path("calls.log");
    let _ = std::fs::remove_file(&outputs);
    let _ = std::fs::remove_file(&log);
    let mut cmd = hermetic(fx, "bash", stubs);
    cmd.arg(action.join("scripts/action-binary.sh"))
        .env("RUNNER_OS", "Linux")
        .env("RUNNER_ARCH", "X64")
        .env("RUNNER_TEMP", fx.path("runner-temp"))
        .env("GITHUB_OUTPUT", &outputs)
        .env("GH_TOKEN", "test-token")
        .env("ACTION_REPOSITORY", REPO)
        .env("ACTION_REF", "0123456789abcdef0123456789abcdef01234567");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    Run {
        ok: out.status.success(),
        stdout: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        outputs: std::fs::read_to_string(&outputs).unwrap_or_default(),
        calls: std::fs::read_to_string(&log).unwrap_or_default(),
    }
}

fn installed(fx: &Fixture) -> bool {
    fx.path("runner-temp/vci-bin/vci").exists()
}

fn error_line(r: &Run) -> String {
    r.stdout
        .lines()
        .find(|l| l.starts_with("::error title=vci::"))
        .unwrap_or_else(|| panic!("no ::error line: {}", r.stdout))
        .to_owned()
}

#[test]
fn a_released_commit_downloads_and_verifies_the_binary() {
    let fx = fixture(None, None);
    let r = run(&fx, &[]);
    assert!(r.ok, "{}", r.stdout);
    assert!(
        r.stdout
            .contains(&format!("using vci v1.4.0 ({ASSET}, sha256 ")),
        "{}",
        r.stdout
    );
    assert!(r.outputs.contains("build=false\n"), "{}", r.outputs);
    assert!(r.outputs.contains("source="), "{}", r.outputs);
    assert_eq!(
        r.calls.lines().count(),
        1,
        "gh only, no fallback: {}",
        r.calls
    );
    assert!(
        r.calls.starts_with(&format!(
            "gh release download v1.4.0 --repo {REPO} --pattern {ASSET} --dir "
        )),
        "{}",
        r.calls
    );
    assert!(installed(&fx));
}

#[test]
fn an_unreleased_commit_fails_at_once_naming_a_release() {
    let fx = fixture(Some("0000000000000000000000000000beef"), None);
    let r = run(&fx, &[]);
    assert!(!r.ok, "{}", r.stdout);
    let error = error_line(&r);
    assert!(error.contains("has no published binary"), "{error}");
    assert!(
        error.contains("0123456789abcdef0123456789abcdef01234567"),
        "{error}"
    );
    assert!(
        error.contains("v1.4.0 built from 0000000000000000000000000000beef"),
        "{error}"
    );
    assert!(error.contains(&format!("uses: {REPO}@v1,")), "{error}");
    assert!(
        error.contains(&format!(
            "git ls-remote https://github.com/{REPO} refs/tags/v1)"
        )),
        "{error}"
    );
    // The version tag the manifest names is not advice: up to v1.4.0 each
    // version tag points at the commit before its manifest was recorded.
    assert!(!error.contains("@v1.4.0"), "{error}");
    assert!(error.contains("set build-from-source: true"), "{error}");
    assert!(!r.outputs.contains("build=true"), "{}", r.outputs);
    assert!(r.calls.is_empty(), "downloaded anyway: {}", r.calls);
    assert!(!installed(&fx));
}

#[test]
fn an_unreleased_commit_compiles_only_with_build_from_source() {
    let fx = fixture(Some("0000000000000000000000000000beef"), None);
    let r = run(&fx, &[("BUILD_FROM_SOURCE", "true")]);
    assert!(r.ok, "{}", r.stdout);
    assert!(r.outputs.contains("build=true\n"), "{}", r.outputs);
    assert!(!r.stdout.contains("::error"), "{}", r.stdout);
    assert!(r.calls.is_empty(), "{}", r.calls);
}

#[test]
fn without_gh_the_public_release_url_is_downloaded_with_curl() {
    // Container jobs and most self-hosted runners have no gh.
    let fx = fixture(None, None);
    let r = run_with(&fx, &["curl"], &[]);
    assert!(r.ok, "{}", r.stdout);
    assert!(
        r.calls.starts_with("curl ")
            && r.calls.contains(&format!(
                " https://github.com/{REPO}/releases/download/v1.4.0/{ASSET}\n"
            )),
        "{}",
        r.calls
    );
    assert!(!r.calls.contains("gh "), "{}", r.calls);
    assert!(r.outputs.contains("build=false\n"), "{}", r.outputs);
    assert!(installed(&fx));

    let r = run_with(&fx, &["wget"], &[]);
    assert!(r.ok, "{}", r.stdout);
    assert!(r.calls.starts_with("wget "), "{}", r.calls);
}

#[test]
fn without_gh_the_checksum_is_still_checked() {
    let fx = fixture(None, Some(&"0".repeat(64)));
    let r = run_with(&fx, &["curl"], &[]);
    assert!(!r.ok, "{}", r.stdout);
    assert!(
        r.stdout.contains("does not match the checksum"),
        "{}",
        r.stdout
    );
    assert!(!installed(&fx));
}

#[test]
fn a_failed_gh_download_falls_back_to_the_public_url() {
    let fx = fixture(None, None);
    let r = run(&fx, &[("STUB_FAIL", "1")]);
    assert!(r.ok, "{}", r.stdout);
    let calls: Vec<&str> = r.calls.lines().collect();
    assert_eq!(calls.len(), 2, "{}", r.calls);
    assert!(calls[0].starts_with("gh release download"), "{}", r.calls);
    assert!(calls[1].starts_with("curl "), "{}", r.calls);
    assert!(installed(&fx));
}

#[test]
fn a_failed_download_fails_unless_build_from_source() {
    let fx = fixture(None, None);
    let fail = [("STUB_FAIL", "1"), ("STUB_CURL_FAIL", "1")];
    let r = run(&fx, &fail);
    assert!(!r.ok, "{}", r.stdout);
    let error = error_line(&r);
    assert!(
        error.starts_with("::error title=vci::vci: could not download"),
        "{error}"
    );
    assert!(error.contains("gh release download failed"), "{error}");
    assert!(error.contains("curl https://github.com/"), "{error}");
    assert!(error.contains("build-from-source: true"), "{error}");
    assert!(!r.outputs.contains("build=true"), "{}", r.outputs);
    assert!(!installed(&fx));

    let r = run(&fx, &[fail[0], fail[1], ("BUILD_FROM_SOURCE", "true")]);
    assert!(r.ok, "{}", r.stdout);
    assert!(r.stdout.contains("::warning"), "{}", r.stdout);
    assert!(r.outputs.contains("build=true\n"), "{}", r.outputs);

    // Without gh, the token is not to blame.
    let r = run_with(&fx, &["curl"], &[fail[1]]);
    assert!(!r.ok, "{}", r.stdout);
    let error = error_line(&r);
    assert!(error.contains("gh is not installed; curl"), "{error}");
    assert!(!error.contains("token"), "{error}");
}

#[test]
fn with_nothing_to_download_with_it_says_so() {
    let fx = fixture(None, None);
    let r = run_with(&fx, &[], &[]);
    assert!(!r.ok, "{}", r.stdout);
    let error = error_line(&r);
    assert!(error.contains("none of gh, curl or wget"), "{error}");
    assert!(!error.contains("token"), "{error}");
    assert!(!error.contains("Re-run"), "{error}");
    assert!(!r.stdout.contains("command not found"), "{}", r.stdout);
    assert!(!installed(&fx));

    let r = run_with(&fx, &[], &[("BUILD_FROM_SOURCE", "true")]);
    assert!(r.ok, "{}", r.stdout);
    assert!(r.outputs.contains("build=true\n"), "{}", r.outputs);
}

#[test]
fn a_binary_that_does_not_match_the_manifest_is_not_installed() {
    let fx = fixture(None, Some(&"0".repeat(64)));
    let r = run(&fx, &[]);
    assert!(!r.ok, "{}", r.stdout);
    assert!(
        r.stdout.contains("does not match the checksum"),
        "{}",
        r.stdout
    );
    assert!(!installed(&fx));
}

#[test]
fn a_platform_without_a_binary_fails_unless_build_from_source() {
    let fx = fixture(None, None);
    let r = run(&fx, &[("RUNNER_OS", "Windows")]);
    assert!(!r.ok, "{}", r.stdout);
    assert!(
        r.stdout
            .contains("::error title=vci::vci: release v1.4.0 has no binary for Windows-X64"),
        "{}",
        r.stdout
    );
    assert!(r.calls.is_empty(), "{}", r.calls);
    let r = run(
        &fx,
        &[("RUNNER_OS", "Windows"), ("BUILD_FROM_SOURCE", "true")],
    );
    assert!(r.ok, "{}", r.stdout);
    assert!(r.outputs.contains("build=true\n"), "{}", r.outputs);
}

#[test]
fn prebuilt_false_is_a_deprecated_way_to_compile() {
    let fx = fixture(None, None);
    let r = run(&fx, &[("PREBUILT", "false")]);
    assert!(r.ok, "{}", r.stdout);
    assert!(r.outputs.contains("build=true\n"), "{}", r.outputs);
    assert!(r.calls.is_empty(), "{}", r.calls);
}

// --- the release process: scripts/publish-release.sh against a local bare
// repository standing in for GitHub ---

/// The action's sources as a git repository whose `origin` is a local bare
/// repository, with main at a commit whose manifest records the previous
/// release (v1.4.0, other sources), as after the release workflow built the
/// draft of the next one. Returns (work, origin).
fn release_repo(fx: &Fixture) -> (PathBuf, PathBuf) {
    let work = fx.action();
    let origin = fx.path("origin.git");
    std::fs::write(
        work.join("release/manifest.txt"),
        "# previous\ntag=v1.4.0\nsource=0000000000000000000000000000beef\n",
    )
    .unwrap();
    sh_in(
        fx,
        fx.dir.path(),
        "git init --quiet --bare -b main origin.git",
    );
    sh_in(
        fx,
        &work,
        "git init --quiet -b main && git remote add origin ../origin.git \
         && git add -A && git commit --quiet -m build && git push --quiet origin main",
    );
    (work, origin)
}

fn publish(fx: &Fixture, work: &Path, origin: &Path, tag: &str) -> (bool, String) {
    let out = hermetic(fx, "sh", &["gh"])
        .arg(work.join("scripts/publish-release.sh"))
        .arg(tag)
        .current_dir(work)
        .env("STUB_ORIGIN", origin)
        .output()
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The action as `uses: ...@<rev>` gets it: the tree of that revision of the
/// bare repository.
fn checkout(fx: &Fixture, origin: &Path, rev: &str) -> PathBuf {
    let to = fx.path(&format!("uses-{}", rev.replace('/', "-")));
    std::fs::create_dir_all(&to).unwrap();
    sh_in(
        fx,
        &to,
        &format!("git -C {} archive {rev} | tar -x", origin.display()),
    );
    to
}

#[test]
fn a_published_version_tag_installs_its_own_binary() {
    let fx = fixture(None, None);
    let (work, origin) = release_repo(&fx);
    let built = sh_in(&fx, &work, "git rev-parse HEAD");

    // What the old process tagged: the commit the binaries were built from,
    // whose manifest records the previous release. The action refuses it.
    let r = run_script(&fx, &checkout(&fx, &origin, &built), &["gh"], &[]);
    assert!(!r.ok, "{}", r.stdout);
    assert!(
        error_line(&r).contains("has no published binary"),
        "{}",
        r.stdout
    );

    let (ok, log) = publish(&fx, &work, &origin, "v1.5.0");
    assert!(ok, "{log}");
    let at = |rev: &str| sh_in(&fx, &origin, &format!("git rev-parse {rev}^{{commit}}"));
    let tagged = at("v1.5.0");
    assert_ne!(
        tagged, built,
        "the version tag must not be on the build commit"
    );
    assert_eq!(at("v1"), tagged);
    assert_eq!(at("main"), tagged);
    assert_eq!(
        sh_in(&fx, &origin, &format!("git rev-parse {tagged}^")),
        built,
        "one commit on top of the build: the manifest"
    );
    for rev in ["v1.5.0", "v1", &tagged] {
        let tree = checkout(&fx, &origin, rev);
        let _ = std::fs::remove_dir_all(fx.path("runner-temp/vci-bin"));
        let r = run_script(&fx, &tree, &["gh"], &[("ACTION_REF", rev)]);
        assert!(r.ok, "@{rev}: {}", r.stdout);
        assert!(
            r.stdout.contains(&format!("using vci v1.5.0 ({ASSET}, ")),
            "@{rev}: {}",
            r.stdout
        );
        assert!(installed(&fx), "@{rev}");
    }
}

#[test]
fn publishing_refuses_a_version_tag_that_already_exists() {
    let fx = fixture(None, None);
    let (work, origin) = release_repo(&fx);
    sh_in(
        &fx,
        &work,
        "git tag v1.5.0 && git push --quiet origin v1.5.0",
    );
    let (ok, log) = publish(&fx, &work, &origin, "v1.5.0");
    assert!(!ok, "{log}");
    assert!(log.contains("v1.5.0 already exists"), "{log}");
    assert_eq!(
        sh_in(&fx, &work, "git log --format=%s -1"),
        "build",
        "nothing was committed"
    );
}

#[test]
fn publishing_refuses_a_draft_missing_a_platform() {
    let fx = fixture(None, None);
    let (work, origin) = release_repo(&fx);
    let before = sh_in(&fx, &origin, "git rev-parse main");
    std::fs::remove_file(fx.path("assets/SHA256SUMS-aarch64-apple-darwin")).unwrap();
    let (ok, log) = publish(&fx, &work, &origin, "v1.5.0");
    assert!(!ok, "{log}");
    assert!(log.contains("no binary for aarch64-apple-darwin"), "{log}");
    assert_eq!(sh_in(&fx, &origin, "git rev-parse main"), before);
    assert_eq!(sh_in(&fx, &origin, "git tag"), "");
}
