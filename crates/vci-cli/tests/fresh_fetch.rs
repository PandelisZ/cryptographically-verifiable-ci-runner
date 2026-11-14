//! A plan in a CI job without a cached store, on a monorepo's metadata
//! remote: a fresh clone (no `refs/meta`, no `.git/git-meta.sqlite`) plans
//! one small project with `--fetch`, as vex's node:test jobs do (14 Nov
//! 2026: 462 files, ~454 skipped, a plan step of 18 to 28 s against a store
//! of 104,721 entries, 33,800 attestations of ~25 projects).
//!
//! The remote is a local bare repository that serves partial clones; its
//! `refs/meta/main` holds the planned project's real attestations (a
//! Vitest copy of `fixtures/vitest-abcd` in `web/`, attested and pushed by
//! vci) under a filler shaped like vex's store of 14 Nov
//! (`store-tree-14nov.txt`): attestations of other projects' paths, most
//! of one project, format-3 objects, run-state links, manifests and
//! deletion records, in a history of a few hundred commits. A `git` wrapper
//! first on PATH logs every `git fetch` and can sleep before each (a round
//! trip to GitHub). Needs `node`, `git`, `bash` and `ssh-keygen` on PATH and
//! the fixture's `node_modules` installed.
//!
//! The measurement is an ignored test (`cargo test -p vci-cli --test
//! fresh_fetch -- --ignored --nocapture measure_`).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Instant;

use assert_cmd::cargo::CommandCargoExt;
use serde_json::Value;
use sha2::Digest as _;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_owned()
}

const VCI_TOML: &str = r#"[policy]
platform = "any"
max_ttl = "30d"

[env]
hash = ["NODE_ENV"]

[[projects]]
name = "web"
path = "web"
adapter = "vitest"
"#;

const UNITS: &[&str] = &[
    "web/src/a.test.ts",
    "web/src/b.test.ts",
    "web/src/c.test.ts",
    "web/src/d.test.ts",
];

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The `git` wrapper: logs each `git fetch` to `$VCI_TEST_GIT_LOG` (`S <pid>
/// <start seconds> <arguments>` and, once it ended, `E <pid> <end
/// seconds>`) and sleeps `$VCI_TEST_GIT_DELAY` seconds before it.
fn wrapper_script(real_git: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
sub=""; skip=0
for a in "$@"; do
  if [ $skip = 1 ]; then skip=0; continue; fi
  case "$a" in -c|-C) skip=1;; -*) ;; *) sub="$a"; break;; esac
done
if [ "$sub" = fetch ]; then
  now() {{ perl -MTime::HiRes=time -e 'printf "%.3f", time'; }}
  if [ -n "$VCI_TEST_GIT_LOG" ]; then echo "S $$ $(now) $*" >> "$VCI_TEST_GIT_LOG"; fi
  if [ -n "$VCI_TEST_GIT_DELAY" ]; then sleep "$VCI_TEST_GIT_DELAY"; fi
  "{real_git}" "$@"
  st=$?
  if [ -n "$VCI_TEST_GIT_LOG" ]; then echo "E $$ $(now)" >> "$VCI_TEST_GIT_LOG"; fi
  exit $st
fi
exec "{real_git}" "$@"
"#
    )
}

/// The `git fetch` processes a `wrapper_script` log records, as (start,
/// end, arguments), in the order they started.
fn fetches_of(log: &str) -> Vec<(f64, f64, String)> {
    let mut started: Vec<(String, f64, String)> = Vec::new();
    let mut ended: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    for l in log.lines() {
        let mut f = l.splitn(4, ' ');
        match (
            f.next(),
            f.next(),
            f.next().and_then(|t| t.parse::<f64>().ok()),
        ) {
            (Some("S"), Some(pid), Some(t)) => {
                started.push((pid.to_owned(), t, f.next().unwrap_or("").to_owned()));
            }
            (Some("E"), Some(pid), Some(t)) => {
                ended.insert(pid.to_owned(), t);
            }
            _ => {}
        }
    }
    started
        .into_iter()
        .map(|(pid, t, args)| (t, ended.get(&pid).copied().unwrap_or(t), args))
        .collect()
}

/// The longest chain of `git fetch` processes each started after the one
/// before it ended: the round trips a command waited for one after the
/// other (fetches that ran at the same time count once).
fn serial_round_trips(fetches: &[(f64, f64, String)]) -> usize {
    let mut by_end: Vec<(f64, f64)> = fetches.iter().map(|(s, e, _)| (*s, *e)).collect();
    by_end.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    let (mut n, mut last_end) = (0, f64::MIN);
    for (s, e) in by_end {
        if s >= last_end {
            n += 1;
            last_end = e;
        }
    }
    n
}

/// A deterministic 64-hex-digit id for `what`.
fn hex64(what: &str) -> String {
    hex::encode(sha2::Sha256::digest(what.as_bytes()))
}

/// The filler's size: vex's store of 14 Nov 2026 by default, scaled down by
/// `scale` (1 = full size).
#[derive(Clone, Copy, Debug)]
struct Shape {
    /// Attestations of the large project (vex-api), and its files.
    big_attestations: usize,
    big_files: usize,
    /// Attestations of the other projects, and their files.
    other_attestations: usize,
    other_files: usize,
    other_projects: usize,
    hdr: usize,
    tables: usize,
    shape: usize,
    state: usize,
    run_state: usize,
    manifests: usize,
    path_deletions: usize,
    project_deletions: usize,
    commits: usize,
}

impl Shape {
    fn vex(divide: usize) -> Shape {
        let d = |n: usize| (n / divide).max(1);
        Shape {
            // 14 Nov: 2,522 files of vex-api, 1,100 of the others, about
            // 3 attestations a file and signer (no unit past the 4 a push
            // keeps of each signer).
            big_attestations: d(23_785),
            big_files: d(2_522),
            other_attestations: d(10_000),
            other_files: d(1_100),
            other_projects: 24,
            hdr: d(53_855),
            tables: d(2_935),
            shape: d(2_671),
            state: d(950),
            run_state: d(972),
            manifests: d(296),
            path_deletions: d(8_650),
            project_deletions: d(590),
            commits: d(300).max(3),
        }
    }
}

/// The filler's entries, as (tree path, blob content).
fn filler(shape: Shape) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let signers = ["4d42727252e0e45f", "24c1b04a0f760c13", "1caa2b096d2d9485"];
    let hint = |i: usize| {
        format!(
            "6af{:05x}.{}",
            i % 0xfffff,
            &hex64(&format!("tree{}", i % 97))[..16]
        )
    };
    let envelope = |what: &str| {
        format!(
            "{{\"payloadType\":\"application/vnd.vci.filler\",\"payload\":\"{}\",\"signatures\":[]}}",
            hex64(what).repeat(8)
        )
        .into_bytes()
    };
    let add_attestations = |out: &mut Vec<(String, Vec<u8>)>,
                            dir: &str,
                            files: usize,
                            n: usize,
                            tag: &str| {
        for i in 0..n {
            let f = i % files;
            let target = format!("{dir}/test/sub{}/f{f:05}_test.rb", f % 37);
            let test_key = hex64(&format!("{tag} unit {f}"));
            let signer = signers[i % signers.len()];
            let storage = hex64(&format!("{tag} storage {i}"));
            out.push((
                format!(
                    "path/{target}/__target__/vci/attestation/{test_key}/{signer}/{storage}/{}/__value",
                    hint(i)
                ),
                envelope(&format!("{tag} value {i}")),
            ));
        }
    };
    add_attestations(
        &mut out,
        "vex-api",
        shape.big_files,
        shape.big_attestations,
        "big",
    );
    let per = shape.other_attestations / shape.other_projects.max(1);
    let files = (shape.other_files / shape.other_projects.max(1)).max(1);
    for p in 0..shape.other_projects {
        add_attestations(
            &mut out,
            &format!("packages/p{p:02}"),
            files,
            per.max(1),
            &format!("p{p}"),
        );
    }
    for (kind, n) in [
        (1, shape.hdr),
        (2, shape.tables),
        (3, shape.shape),
        (4, shape.state),
    ] {
        for i in 0..n {
            let id = hex64(&format!("object {kind} {i}"));
            out.push((
                format!("project/vci/object/{kind}/{id}/__value"),
                hex64(&format!("object body {kind} {i}"))
                    .repeat(4)
                    .into_bytes(),
            ));
        }
    }
    for i in 0..shape.run_state {
        out.push((
            format!(
                "project/vci/run-state/{}/{}/{}/__value",
                hex64(&format!("object 3 {}", i % shape.shape.max(1))),
                hint(i),
                hex64(&format!("object 4 {}", i % shape.state.max(1)))
            ),
            b"1".to_vec(),
        ));
    }
    for i in 0..shape.manifests {
        out.push((
            format!(
                "project/vci/manifest/{}/__value",
                hex64(&format!("manifest {i}"))
            ),
            hex64(&format!("manifest body {i}")).repeat(16).into_bytes(),
        ));
    }
    let tombstone = |i: usize| {
        format!(
            "{{\"timestamp\":{},\"email\":\"ci@example.com\"}}",
            1_763_000_000_000i64 + i as i64
        )
        .into_bytes()
    };
    for i in 0..shape.path_deletions {
        let f = i % shape.big_files;
        out.push((
            format!(
                "path/vex-api/test/sub{}/f{f:05}_test.rb/__target__/__tombstones/vci/attestation/{}/{}/{}/{}/__deleted",
                f % 37,
                hex64(&format!("big unit {f}")),
                signers[0],
                hex64(&format!("deleted storage {i}")),
                hint(i)
            ),
            tombstone(i),
        ));
    }
    for i in 0..shape.project_deletions {
        out.push((
            format!(
                "project/__tombstones/vci/object/4/{}/__deleted",
                hex64(&format!("deleted object {i}"))
            ),
            tombstone(i),
        ));
    }
    out
}

/// Add `entries` to `refs/meta/main` of the bare repository `remote`, in
/// `commits` commits on top of its tip, with `git fast-import`.
fn inflate(remote: &Path, entries: &[(String, Vec<u8>)], commits: usize, gitconfig: &Path) {
    let tip = git_in(remote, &["rev-parse", "refs/meta/main"], gitconfig);
    let mut child = Command::new("git")
        .current_dir(remote)
        .args(["fast-import", "--quiet", "--force"])
        .env("GIT_CONFIG_GLOBAL", gitconfig)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut w = std::io::BufWriter::new(child.stdin.take().unwrap());
        let per = entries.len().div_ceil(commits.max(1));
        for (c, chunk) in entries.chunks(per.max(1)).enumerate() {
            let t = 1_762_000_000 + c as i64 * 60;
            writeln!(w, "commit refs/meta/main").unwrap();
            writeln!(w, "committer vci <vci@example.com> {t} +0000").unwrap();
            let msg = format!("filler {c}");
            writeln!(w, "data {}\n{msg}", msg.len()).unwrap();
            if c == 0 {
                writeln!(w, "from {tip}").unwrap();
            }
            for (path, body) in chunk {
                writeln!(w, "M 100644 inline {path}").unwrap();
                writeln!(w, "data {}", body.len()).unwrap();
                w.write_all(body).unwrap();
                writeln!(w).unwrap();
            }
            writeln!(w).unwrap();
        }
        w.flush().unwrap();
    }
    assert!(child.wait().unwrap().success());
    // A server's packs, as GitHub has them.
    git_in(remote, &["repack", "-a", "-d", "-q"], gitconfig);
}

fn git_in(dir: &Path, args: &[&str], gitconfig: &Path) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", gitconfig)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?} in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

struct World {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    key: PathBuf,
    gitconfig: PathBuf,
    wrapper: PathBuf,
    remote: PathBuf,
}

impl World {
    fn git(&self, dir: &Path, args: &[&str]) -> String {
        git_in(dir, args, &self.gitconfig)
    }

    /// `bin <args>` (this build's vci when `None`) in `dir` with `env` added
    /// to a scrubbed environment, the `git` wrapper first on PATH.
    fn vci(&self, bin: Option<&Path>, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = match bin {
            Some(b) => Command::new(b),
            None => Command::cargo_bin("vci").unwrap(),
        };
        let path = format!(
            "{}:{}",
            self.wrapper.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        cmd.current_dir(dir)
            .args(args)
            .env("PATH", path)
            .env("VCI_JS_PLUGIN", workspace_root().join("js/vitest-plugin"))
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("NO_COLOR", "1");
        for k in [
            "VCI_E2E_BIN",
            "VCI_BASE_REF",
            "GITHUB_BASE_REF",
            "GITHUB_REF",
            "GITHUB_OUTPUT",
            "GITHUB_ACTIONS",
            "VCI_SIGNING_KEY",
            "VCI_OUT",
            "VCI_TIMING",
            "VCI_JOBS",
            "VCI_FETCH_BESIDE",
            "VCI_FETCH_AHEAD",
            "VCI_PRESENT_WITH_GIT",
            "VCI_MATERIALIZE",
            "NODE_OPTIONS",
            "NODE_ENV",
            "CI",
            "VCI_TEST_GIT_LOG",
            "VCI_TEST_GIT_DELAY",
        ]
        .iter()
        .chain(vci_store::select::ENV_VARS)
        {
            cmd.env_remove(k);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }

    fn vci_ok(
        &self,
        bin: Option<&Path>,
        dir: &Path,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> Output {
        let out = self.vci(bin, dir, args, env);
        assert_eq!(
            out.status.code(),
            Some(0),
            "vci {args:?} in {}: {}",
            dir.display(),
            text(&out)
        );
        out
    }

    fn copy_modules(dir: &Path) {
        let st = Command::new("cp")
            .arg("-R")
            .arg(workspace_root().join("fixtures/vitest-abcd/node_modules"))
            .arg(dir.join("web/node_modules"))
            .status()
            .unwrap();
        assert!(st.success());
    }

    /// A clone of the remote as a CI checkout has it: blobless, no
    /// `refs/meta`, no store; on `branch`.
    fn clone(&self, name: &str, branch: &str) -> PathBuf {
        let dir = self.base.join(name);
        let _ = std::fs::remove_dir_all(&dir);
        self.git(
            &self.base,
            &[
                "clone",
                "-q",
                "--no-local",
                "--filter=blob:none",
                "-b",
                branch,
                self.remote.to_str().unwrap(),
                dir.to_str().unwrap(),
            ],
        );
        // The base branch, as `actions/checkout` with `fetch-depth: 0` has it.
        let _ = self.git(&dir, &["branch", "-q", "--track", "main", "origin/main"]);
        Self::copy_modules(&dir);
        dir
    }

    /// The world: `web` attested on `main` and pushed; the filler of
    /// `shape` added to the remote's metadata; a pull request branch `pr`
    /// that changes `b.ts` (b runs, a, c and d skip).
    fn new(shape: Option<Shape>) -> World {
        let tmp = tempfile::tempdir_in(
            std::env::var_os("VCI_MEASURE_TMP").unwrap_or_else(|| std::env::temp_dir().into()),
        )
        .unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let gitconfig = base.join("gitconfig");
        std::fs::write(
            &gitconfig,
            "[user]\n\tname = Test\n\temail = test@example.com\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n",
        )
        .unwrap();
        let key = base.join("trusted");
        let st = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "trusted", "-f"])
            .arg(&key)
            .status()
            .unwrap();
        assert!(st.success());
        let pubkey = std::fs::read_to_string(key.with_extension("pub")).unwrap();
        let pubkey = pubkey
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let real_git = String::from_utf8(
            Command::new("bash")
                .args(["-c", "command -v git"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        let wrapper = base.join("wrapper");
        std::fs::create_dir_all(&wrapper).unwrap();
        std::fs::write(wrapper.join("git"), wrapper_script(&real_git)).unwrap();
        let st = Command::new("chmod")
            .arg("+x")
            .arg(wrapper.join("git"))
            .status()
            .unwrap();
        assert!(st.success());
        let remote = base.join("origin.git");
        let w = World {
            _tmp: tmp,
            base: base.clone(),
            key,
            gitconfig,
            wrapper,
            remote: remote.clone(),
        };
        let work = base.join("work");
        std::fs::create_dir_all(work.join("web")).unwrap();
        w.git(&work, &["init", "-q"]);
        let fx = workspace_root().join("fixtures/vitest-abcd");
        for name in [
            "src",
            "fixtures",
            "package.json",
            "package-lock.json",
            "vitest.config.ts",
        ] {
            let st = Command::new("cp")
                .arg("-R")
                .arg(fx.join(name))
                .arg(work.join("web").join(name))
                .status()
                .unwrap();
            assert!(st.success());
        }
        Self::copy_modules(&work);
        std::fs::write(work.join(".gitignore"), "node_modules/\n.vci/out/\n").unwrap();
        std::fs::write(work.join("vci.toml"), VCI_TOML).unwrap();
        std::fs::create_dir_all(work.join(".vci")).unwrap();
        std::fs::write(
            work.join(".vci/allowed_signers"),
            format!("trusted@example.com namespaces=\"vci-attest\" {pubkey}\n"),
        )
        .unwrap();
        std::fs::create_dir_all(work.join("vex-api/test")).unwrap();
        std::fs::write(work.join("vex-api/test/README"), "another project\n").unwrap();
        w.git(&work, &["add", "-A"]);
        w.git(&work, &["commit", "-q", "-m", "base"]);
        w.git(&base, &["init", "-q", "--bare", remote.to_str().unwrap()]);
        w.git(&remote, &["config", "uploadpack.allowFilter", "true"]);
        w.git(
            &remote,
            &["config", "uploadpack.allowAnySHA1InWant", "true"],
        );
        w.git(
            &work,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        w.git(&work, &["push", "-q", "origin", "main"]);
        let key = w.key.to_str().unwrap().to_owned();
        let out = w.vci_ok(None, &work, &["run", "--key", &key], &[]);
        assert!(
            stderr(&out).contains("4 attested, 0 not attested"),
            "{}",
            text(&out)
        );
        w.vci_ok(None, &work, &["push", "--remote", "origin"], &[]);
        // Another branch's run of c on its own change of c.ts: c has two
        // candidates, the newer one on other inputs.
        w.git(&work, &["checkout", "-q", "-b", "other"]);
        append(&work.join("web/src/c.ts"), "// the other branch\n");
        w.git(&work, &["commit", "-q", "-am", "change c"]);
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        let out = w.vci_ok(
            None,
            &work,
            &["run", "web/src/c.test.ts", "--key", &key],
            &[],
        );
        assert!(
            stderr(&out).contains("1 attested, 0 not attested"),
            "{}",
            text(&out)
        );
        w.vci_ok(None, &work, &["push", "--remote", "origin"], &[]);
        w.git(&work, &["checkout", "-q", "main"]);
        if let Some(shape) = shape {
            let t = Instant::now();
            let entries = filler(shape);
            inflate(&remote, &entries, shape.commits, &w.gitconfig);
            eprintln!(
                "MEASURE filler: {} entries in {} commits, {:.1} s",
                entries.len(),
                shape.commits,
                t.elapsed().as_secs_f64()
            );
        }
        // The pull request: b.ts changed.
        w.git(&work, &["checkout", "-q", "-b", "pr"]);
        append(&work.join("web/src/b.ts"), "// the pull request\n");
        w.git(&work, &["commit", "-q", "-am", "change b"]);
        w.git(&work, &["push", "-q", "origin", "pr"]);
        w
    }
}

fn append(path: &Path, line: &str) {
    let mut c = std::fs::read_to_string(path).unwrap();
    c.push_str(line);
    std::fs::write(path, c).unwrap();
}

/// The number a `VCI_TIMING` line of `stderr` gives after `prefix`.
fn timing_number(stderr: &str, prefix: &str) -> Option<f64> {
    let prefix = format!("vci: timing: {prefix}");
    stderr.lines().find_map(|l| {
        l.strip_prefix(&prefix)
            .and_then(|rest| rest.trim().trim_end_matches('s').parse().ok())
    })
}

/// Bytes in a repository's object store (packs and loose objects).
fn object_bytes(dir: &Path) -> u64 {
    fn walk(p: &Path) -> u64 {
        let Ok(rd) = std::fs::read_dir(p) else {
            return 0;
        };
        rd.flatten()
            .map(|e| {
                let m = e.metadata().unwrap();
                if m.is_dir() { walk(&e.path()) } else { m.len() }
            })
            .sum()
    }
    walk(&dir.join(".git/objects"))
}

/// The plan's units as (test id, skip, reason), from `--format json`.
fn decisions(json: &str) -> Vec<(String, bool, String)> {
    let v: Value = serde_json::from_str(json).unwrap();
    v["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["testId"].as_str().unwrap().to_owned(),
                f["skip"].as_bool().unwrap(),
                f["reason"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

struct Measured {
    total: f64,
    wall: f64,
    fetches: Vec<(f64, f64, String)>,
    bytes: u64,
    objects: u64,
    sqlite: u64,
    timing: String,
    json: String,
}

/// `vci plan --fetch origin --base-ref main --project web --format json` by
/// `bin` in a fresh clone of the pull request, with `env`.
fn measure_once(w: &World, bin: Option<&Path>, tag: &str, env: &[(&str, &str)]) -> Measured {
    let dir = w.clone(tag, "pr");
    let before = object_bytes(&dir);
    let objects_before = count_objects(w, &dir);
    let log = w.base.join(format!("git-{tag}.log"));
    let _ = std::fs::remove_file(&log);
    let log_s = log.to_str().unwrap().to_owned();
    let env: Vec<(&str, &str)> =
        [env, &[("VCI_TIMING", "1"), ("VCI_TEST_GIT_LOG", &log_s)]].concat();
    let t = Instant::now();
    let out = w.vci_ok(
        bin,
        &dir,
        &[
            "plan",
            "--fetch",
            "origin",
            "--base-ref",
            "main",
            "--project",
            "web",
            "--format",
            "json",
        ],
        &env,
    );
    let wall = t.elapsed().as_secs_f64();
    let err = stderr(&out);
    let m = Measured {
        total: timing_number(&err, "plan total: ").unwrap_or(f64::NAN),
        wall,
        fetches: fetches_of(&std::fs::read_to_string(&log).unwrap_or_default()),
        bytes: object_bytes(&dir) - before,
        objects: count_objects(w, &dir) - objects_before,
        sqlite: std::fs::metadata(dir.join(".git/git-meta.sqlite"))
            .map(|m| m.len())
            .unwrap_or(0),
        timing: err
            .lines()
            .filter(|l| l.starts_with("vci: timing: ") || l.starts_with("vci: "))
            .collect::<Vec<_>>()
            .join("\n"),
        json: stdout(&out),
    };
    if std::env::var_os("VCI_MEASURE_KEEP").is_none() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    m
}

/// Objects in a repository (loose and packed).
fn count_objects(w: &World, dir: &Path) -> u64 {
    let out = w.git(dir, &["count-objects", "-v"]);
    out.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(": ")?;
            matches!(k, "count" | "in-pack").then(|| v.parse::<u64>().ok())?
        })
        .sum()
}

/// Not a check, a measurement: a fresh clone's `vci plan --fetch origin
/// --base-ref main --project web` against a remote whose metadata is shaped
/// like vex's of 14 Nov 2026 (divided by `VCI_MEASURE_DIVIDE`, default 1),
/// each `git fetch` delayed `VCI_MEASURE_DELAY` seconds (default 0.8, a
/// round trip to GitHub), by `VCI_MEASURE_BIN` (default this build) and
/// `VCI_MEASURE_BEFORE` when it names one: the plan's total, the round
/// trips, the bytes and objects downloaded, the size of
/// `.git/git-meta.sqlite` and the `VCI_TIMING` lines, `VCI_MEASURE_REPEAT`
/// (default 3) times each (medians). The temporary directory is under
/// `VCI_MEASURE_TMP` when set.
#[test]
#[ignore]
fn measure_fresh_clone_plan() {
    let divide = std::env::var("VCI_MEASURE_DIVIDE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let repeat: usize = std::env::var("VCI_MEASURE_REPEAT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let delay = std::env::var("VCI_MEASURE_DELAY").unwrap_or_else(|_| "0.8".to_owned());
    let w = World::new(Some(Shape::vex(divide)));
    let entries = git_in(
        &w.remote,
        &["ls-tree", "-r", "--name-only", "refs/meta/main"],
        &w.gitconfig,
    )
    .lines()
    .count();
    eprintln!("MEASURE remote: {entries} entries in refs/meta/main");
    type Variant = (String, Option<PathBuf>, Vec<(String, String)>);
    let mut variants: Vec<Variant> = vec![(
        "this build".to_owned(),
        std::env::var_os("VCI_MEASURE_BIN").map(PathBuf::from),
        vec![],
    )];
    if let Ok(extra) = std::env::var("VCI_MEASURE_ENV") {
        // `K=V,K=V`: this build again, with them.
        let kv = extra
            .split(',')
            .filter_map(|p| p.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        variants.push((
            format!("this build with {extra}"),
            std::env::var_os("VCI_MEASURE_BIN").map(PathBuf::from),
            kv,
        ));
    }
    if let Some(b) = std::env::var_os("VCI_MEASURE_BEFORE") {
        variants.insert(
            0,
            (
                "VCI_MEASURE_BEFORE".to_owned(),
                Some(PathBuf::from(b)),
                vec![],
            ),
        );
    }
    let median = |mut v: Vec<f64>| -> f64 {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    };
    let mut first_json: Option<Vec<(String, bool, String)>> = None;
    for (i, (what, bin, extra)) in variants.iter().enumerate() {
        let mut env: Vec<(&str, &str)> = vec![("VCI_TEST_GIT_DELAY", delay.as_str())];
        env.extend(extra.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let mut runs = Vec::new();
        for r in 0..repeat {
            runs.push(measure_once(&w, bin.as_deref(), &format!("m{i}-{r}"), &env));
        }
        let d = decisions(&runs[0].json);
        match &first_json {
            None => first_json = Some(d.clone()),
            Some(f) => assert_eq!(*f, d, "{what}: other decisions"),
        }
        let last = runs.last().unwrap();
        let t0 = last.fetches.first().map_or(0.0, |f| f.0);
        eprintln!(
            "MEASURE {what}: plan total median {:.2} s (wall {:.2} s), {} git fetch(es), {} one after the other, {:.1} MB / {} objects downloaded, git-meta.sqlite {:.1} MB, decisions {:?}\nfetches (start, end, seconds after the first started):\n  {}\n{}\n",
            median(runs.iter().map(|m| m.total).collect()),
            median(runs.iter().map(|m| m.wall).collect()),
            last.fetches.len(),
            serial_round_trips(&last.fetches),
            last.bytes as f64 / 1e6,
            last.objects,
            last.sqlite as f64 / 1e6,
            d.iter()
                .map(|(u, s, _)| (u.as_str(), *s))
                .collect::<Vec<_>>(),
            last.fetches
                .iter()
                .map(|(s, e, a)| format!(
                    "{:6.2} {:6.2} {}",
                    s - t0,
                    e - t0,
                    a.split_once(" fetch ").map_or(a.as_str(), |(_, r)| r)
                ))
                .collect::<Vec<_>>()
                .join("\n  "),
            last.timing
        );
    }
    if std::env::var_os("VCI_MEASURE_KEEP").is_some() {
        eprintln!("MEASURE kept {}", w.base.display());
        std::mem::forget(w);
    }
    let _ = UNITS;
}

/// The vci `VCI_TEST_VCI_BEFORE` names (one built before this change), or
/// `None` (that part of a test is skipped, with a message).
fn vci_before() -> Option<PathBuf> {
    let Some(p) = std::env::var_os("VCI_TEST_VCI_BEFORE") else {
        eprintln!("SKIPPED (the part against an earlier vci): VCI_TEST_VCI_BEFORE names none");
        return None;
    };
    let p = PathBuf::from(p);
    let ours = Path::new(env!("CARGO_BIN_EXE_vci"));
    assert!(
        std::fs::read(&p).unwrap_or_default() != std::fs::read(ours).unwrap_or_default(),
        "VCI_TEST_VCI_BEFORE={} is this build's own vci",
        p.display()
    );
    Some(p)
}

/// `now is <RFC 3339 time>` (an expiry check's actual value) as `now is
/// NOW`.
fn without_now(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("now is ") {
        out.push_str(&rest[..i + 7]);
        rest = &rest[i + 7..];
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || matches!(c, '-' | ':' | 'T' | 'Z')))
            .unwrap_or(rest.len());
        out.push_str("NOW");
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// What `bin` (this build's vci when `None`) with `env` says of the pull
/// request, each in a fresh clone: the plan's JSON and text (`vci plan
/// --fetch origin --base-ref main --project web`), and `vci explain` of
/// every unit after `vci fetch --remote origin`.
fn says(
    w: &World,
    bin: Option<&Path>,
    env: &[(&str, &str)],
    tag: &str,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for format in ["json", "text"] {
        let dir = w.clone(&format!("{tag}-{format}"), "pr");
        let o = w.vci_ok(
            bin,
            &dir,
            &[
                "plan",
                "--fetch",
                "origin",
                "--base-ref",
                "main",
                "--project",
                "web",
                "--format",
                format,
            ],
            env,
        );
        assert!(!stderr(&o).contains("could not fetch"), "{}", text(&o));
        out.insert(format!("plan {format}"), without_now(&stdout(&o)));
        let _ = std::fs::remove_dir_all(&dir);
    }
    for unit in UNITS {
        let dir = w.clone(&format!("{tag}-explain"), "pr");
        w.vci_ok(bin, &dir, &["fetch", "--remote", "origin"], env);
        let o = w.vci_ok(bin, &dir, &["explain", unit, "--base-ref", "main"], env);
        out.insert(format!("explain {unit}"), without_now(&stdout(&o)));
        let _ = std::fs::remove_dir_all(&dir);
    }
    out
}

/// A small store of vex's shape (about 1,000 entries besides the planned
/// project's).
fn small() -> Shape {
    Shape::vex(100)
}

/// A fresh clone's plan decides, says and explains exactly what it did
/// before 2.11, when the values it reads first are fetched while the fetch
/// merges (and the object database is asked in this process which values
/// are here): the same as with `VCI_FETCH_AHEAD=0 VCI_PRESENT_WITH_GIT=1`
/// (the plan fetches them after the fetch, and git answers), and, when
/// `VCI_TEST_VCI_BEFORE` names one, as a vci built before this change. b
/// runs (its module changed), c skips on main's attestation though another
/// branch attested it since on other inputs, a and d skip.
#[test]
fn fresh_clone_plan_decides_and_explains_as_before() {
    let w = World::new(Some(small()));
    let ours = says(&w, None, &[], "ours");
    let d = decisions(&ours["plan json"]);
    assert_eq!(
        d.iter()
            .map(|(u, s, _)| (u.as_str(), *s))
            .collect::<Vec<_>>(),
        [
            (UNITS[0], true),
            (UNITS[1], false),
            (UNITS[2], true),
            (UNITS[3], true)
        ],
        "{}",
        ours["plan text"]
    );
    assert!(
        d[1].2
            .starts_with("no valid attestation (1 candidates; best failed inputs: "),
        "{}",
        d[1].2
    );
    let off = says(
        &w,
        None,
        &[("VCI_FETCH_AHEAD", "0"), ("VCI_PRESENT_WITH_GIT", "1")],
        "off",
    );
    for (k, v) in &ours {
        assert_eq!(
            *v, off[k],
            "{k} with VCI_FETCH_AHEAD=0 VCI_PRESENT_WITH_GIT=1"
        );
    }
    if let Some(before) = vci_before() {
        let theirs = says(&w, Some(&before), &[], "before");
        for (k, v) in &ours {
            assert_eq!(*v, theirs[k], "{k} by {}", before.display());
        }
    }
}

/// Each row of a clone's git-meta store as the blob id of its value
/// (inline values hashed as git would store them; promised rows: the blob
/// at the key's path in the local metadata commit), and each deletion
/// record: what a serialization of the store publishes.
fn store_view(w: &World, dir: &Path) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let db = rusqlite::Connection::open(dir.join(".git/git-meta.sqlite")).unwrap();
    let local: BTreeMap<String, String> = listing(w, dir, "refs/meta/local/main");
    let mut rows = Vec::new();
    {
        let mut st = db
            .prepare(
                "SELECT target_type, target_value, key, value, value_type, is_git_ref, is_promised
                 FROM metadata WHERE source_ref IS NULL",
            )
            .unwrap();
        let it = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, bool>(5)?,
                    r.get::<_, bool>(6)?,
                ))
            })
            .unwrap();
        for r in it {
            rows.push(r.unwrap());
        }
    }
    let path_of = |ty: &str, tv: &str, key: &str| -> String {
        let target = if ty == "project" {
            git_meta_lib::Target::project()
        } else {
            git_meta_lib::Target::path(tv)
        };
        git_meta_lib::tree_paths::tree_path(&target, key).unwrap()
    };
    // Inline values, hashed by git in one process.
    let tmp = dir.join(".git/vci-test-inline");
    std::fs::create_dir_all(&tmp).unwrap();
    let mut inline_paths = Vec::new();
    for (i, (_, _, _, value, vt, is_ref, promised)) in rows.iter().enumerate() {
        if vt == "string" && !is_ref && !promised {
            let v: String = serde_json::from_str(value).unwrap_or_else(|_| value.clone());
            let p = tmp.join(format!("{i}"));
            std::fs::write(&p, v).unwrap();
            inline_paths.push((i, p));
        }
    }
    let mut hashed = std::collections::HashMap::new();
    if !inline_paths.is_empty() {
        let mut child = Command::new("git")
            .current_dir(dir)
            .args(["hash-object", "--stdin-paths"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        {
            let mut stdin = child.stdin.take().unwrap();
            for (_, p) in &inline_paths {
                writeln!(stdin, "{}", p.display()).unwrap();
            }
        }
        let out = child.wait_with_output().unwrap();
        for ((i, _), oid) in inline_paths
            .iter()
            .zip(String::from_utf8_lossy(&out.stdout).lines())
        {
            hashed.insert(*i, oid.to_owned());
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    let mut values = BTreeMap::new();
    for (i, (ty, tv, key, value, vt, is_ref, promised)) in rows.iter().enumerate() {
        assert_eq!(vt, "string", "{ty} {tv} {key}");
        let path = path_of(ty, tv, key);
        let oid = if *promised {
            local
                .get(&path)
                .cloned()
                .unwrap_or_else(|| format!("promised, not in the local commit: {path}"))
        } else if *is_ref {
            value.trim().to_owned()
        } else {
            hashed[&i].clone()
        };
        values.insert(path, oid);
    }
    let mut records = BTreeSet::new();
    let mut st = db
        .prepare(
            "SELECT target_type, target_value, key, timestamp, email FROM tombstones WHERE tombstone_type = 'metadata'",
        )
        .unwrap();
    for r in st
        .query_map([], |r| {
            Ok(format!(
                "{} {} {} {} {}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?
            ))
        })
        .unwrap()
    {
        records.insert(r.unwrap());
    }
    (values, records)
}

/// `rev`'s metadata tree in `dir`: path -> blob id.
fn listing(w: &World, dir: &Path, rev: &str) -> BTreeMap<String, String> {
    w.git(dir, &["ls-tree", "-r", rev])
        .lines()
        .filter_map(|l| {
            let (meta, path) = l.split_once('\t')?;
            Some((path.to_owned(), meta.split_whitespace().nth(2)?.to_owned()))
        })
        .collect()
}

/// A fresh clone's first fetch (the merge into a new store, the deletion
/// records fetched while the rows are written, the values the plan reads
/// first fetched beside it) leaves the store holding what git-meta's own
/// merge of every value leaves (`VCI_MATERIALIZE=full`, with
/// `VCI_FETCH_AHEAD=0 VCI_PRESENT_WITH_GIT=1`), and, when
/// `VCI_TEST_VCI_BEFORE` names one, what a vci built before this change
/// leaves: the same local metadata commit, the remote's tip, and rows of
/// the same values and the same deletion records, which is what a push
/// from the clone publishes.
#[test]
fn fresh_clone_fetch_stores_what_the_full_merge_stores() {
    let w = World::new(Some(small()));
    let tip_tree = w.git(&w.remote, &["rev-parse", "refs/meta/main^{tree}"]);
    let plan = |tag: &str, bin: Option<&Path>, env: &[(&str, &str)]| {
        let dir = w.clone(tag, "pr");
        w.vci_ok(
            bin,
            &dir,
            &[
                "plan",
                "--fetch",
                "origin",
                "--base-ref",
                "main",
                "--project",
                "web",
            ],
            env,
        );
        assert_eq!(
            w.git(&dir, &["rev-parse", "refs/meta/local/main^{tree}"]),
            tip_tree,
            "{tag}: the local metadata commit's tree"
        );
        store_view(&w, &dir)
    };
    let ours = plan("ours", None, &[]);
    assert!(
        ours.0.len() > 900 && ours.1.len() > 80,
        "{} {}",
        ours.0.len(),
        ours.1.len()
    );
    let full = plan(
        "full",
        None,
        &[
            ("VCI_MATERIALIZE", "full"),
            ("VCI_FETCH_AHEAD", "0"),
            ("VCI_PRESENT_WITH_GIT", "1"),
        ],
    );
    assert_eq!(ours.0, full.0, "values, against the full merge");
    assert_eq!(ours.1, full.1, "deletion records, against the full merge");
    if let Some(before) = vci_before() {
        let theirs = plan("before", Some(&before), &[]);
        assert_eq!(ours.0, theirs.0, "values, against {}", before.display());
        assert_eq!(
            ours.1,
            theirs.1,
            "deletion records, against {}",
            before.display()
        );
    }
}

/// The key path a deletion record at `path` is the record of.
fn recorded_value(path: &str) -> Option<String> {
    let p = path.strip_suffix("/__deleted")?;
    let p = p.replacen("/__tombstones/", "/", 1);
    Some(format!("{p}/__value"))
}

/// `after` is the merge of `before` with each of `sides` (trees that
/// started from `before`, or from one another): every value a side added
/// is there, every value there is one of `before` or of a side, a value of
/// `before` is gone only when a side lacks it too, and every deletion
/// record there is one of `before` or a side's.
fn merged(
    before: &BTreeMap<String, String>,
    sides: &[(&str, &BTreeMap<String, String>)],
    after: &BTreeMap<String, String>,
) {
    let is_value = |p: &str| p.ends_with("/__value");
    for (name, side) in sides {
        for (p, o) in side.iter().filter(|(p, _)| is_value(p)) {
            if before.get(p) != Some(o) {
                assert_eq!(
                    after.get(p),
                    Some(o),
                    "{name} added {p}, which the merge lost"
                );
            }
        }
    }
    for (p, o) in after {
        let known = before.get(p) == Some(o) || sides.iter().any(|(_, s)| s.get(p) == Some(o));
        assert!(known, "{p} ({o}) is in the merge but in neither side");
        if !is_value(p) {
            continue;
        }
        // Never published again once a side deleted it.
        for (name, s) in sides {
            let record = s
                .keys()
                .any(|r| recorded_value(r).as_deref() == Some(p.as_str()));
            assert!(
                !(record && !s.contains_key(p)),
                "{p}: {name} deleted it, the merge has it"
            );
        }
    }
    for (p, _) in before.iter().filter(|(p, _)| is_value(p)) {
        if !after.contains_key(p) {
            assert!(
                sides.iter().any(|(_, s)| !s.contains_key(p)),
                "{p} was lost though no side deleted it"
            );
        }
    }
}

/// What a fresh clone pushes after its plan merged the remote into a new
/// store and fetched the plan's values ahead is the remote's metadata and
/// its own run, also when a full clone pushed a run of its own meanwhile,
/// and when a third clone then rewrote the history (`vci push
/// --rewrite-history`) before the fresh clone's next push: nothing another
/// clone published is lost or deleted, nothing deleted comes back.
#[test]
fn push_after_a_fresh_clone_plan_publishes_the_merge() {
    let w = World::new(Some(small()));
    let key = w.key.to_str().unwrap().to_owned();
    let remote_tip = |w: &World| listing(w, &w.remote, "refs/meta/main");
    let t0 = remote_tip(&w);
    // The fresh clone plans, then attests b on the pull request's change.
    let x = w.clone("x", "pr");
    let o = w.vci_ok(
        None,
        &x,
        &[
            "plan",
            "--fetch",
            "origin",
            "--base-ref",
            "main",
            "--project",
            "web",
        ],
        &[("VCI_TIMING", "1")],
    );
    assert!(
        stderr(&o).contains("vci: timing: fetch ahead: "),
        "{}",
        text(&o)
    );
    let o = w.vci_ok(None, &x, &["run", "web/src/b.test.ts", "--key", &key], &[]);
    assert!(
        stderr(&o).contains("1 attested, 0 not attested"),
        "{}",
        text(&o)
    );
    // Its run serialized onto the local metadata commit (the remote has not
    // moved yet): what it publishes.
    w.vci_ok(None, &x, &["fetch", "--remote", "origin"], &[]);
    let x_local = listing(&w, &x, "refs/meta/local/main");
    assert!(
        x_local
            .keys()
            .any(|p| p.starts_with("path/web/src/b.test.ts/") && !t0.contains_key(p)),
        "the run stored nothing"
    );
    // Meanwhile a full clone attests d on its own change of d.ts and pushes.
    let f = w.base.join("full");
    w.git(
        &w.base,
        &[
            "clone",
            "-q",
            "--no-local",
            w.remote.to_str().unwrap(),
            f.to_str().unwrap(),
        ],
    );
    World::copy_modules(&f);
    w.git(&f, &["checkout", "-q", "-b", "full"]);
    append(&f.join("web/src/d.ts"), "// the full clone\n");
    w.git(&f, &["commit", "-q", "-am", "change d"]);
    w.vci_ok(None, &f, &["fetch", "--remote", "origin"], &[]);
    let o = w.vci_ok(None, &f, &["run", "web/src/d.test.ts", "--key", &key], &[]);
    assert!(
        stderr(&o).contains("1 attested, 0 not attested"),
        "{}",
        text(&o)
    );
    w.vci_ok(None, &f, &["push", "--remote", "origin"], &[]);
    let t1 = remote_tip(&w);
    // The fresh clone pushes: a merge with the full clone's push.
    w.vci_ok(None, &x, &["push", "--remote", "origin"], &[]);
    let t2 = remote_tip(&w);
    merged(
        &t0,
        &[("the full clone", &t1), ("the fresh clone", &x_local)],
        &t2,
    );
    assert!(
        t2.len() > t1.len(),
        "the fresh clone's run was not published"
    );
    // A third clone rewrites the history.
    let r = w.base.join("rewrite");
    w.git(
        &w.base,
        &[
            "clone",
            "-q",
            "--no-local",
            w.remote.to_str().unwrap(),
            r.to_str().unwrap(),
        ],
    );
    World::copy_modules(&r);
    w.vci_ok(None, &r, &["fetch", "--remote", "origin"], &[]);
    w.vci_ok(
        None,
        &r,
        &["push", "--rewrite-history", "--remote", "origin"],
        &[],
    );
    assert_eq!(
        w.git(&w.remote, &["rev-list", "--count", "refs/meta/main"]),
        "1"
    );
    let t3 = remote_tip(&w);
    // The fresh clone attests a on a change of its own (new inputs: a key
    // of its own) and pushes onto the rewrite, which it never fetched: it
    // publishes the rewritten tip and its run.
    append(&x.join("web/src/a.ts"), "// the fresh clone\n");
    w.git(&x, &["commit", "-q", "-am", "change a"]);
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let o = w.vci_ok(None, &x, &["run", "web/src/a.test.ts", "--key", &key], &[]);
    assert!(
        stderr(&o).contains("1 attested, 0 not attested"),
        "{}",
        text(&o)
    );
    w.vci_ok(None, &x, &["push", "--remote", "origin"], &[]);
    let t4 = remote_tip(&w);
    let values = |t: &BTreeMap<String, String>| -> BTreeMap<String, String> {
        t.iter()
            .filter(|(p, _)| p.ends_with("/__value"))
            .map(|(p, o)| (p.clone(), o.clone()))
            .collect()
    };
    for (p, o) in values(&t3) {
        assert_eq!(
            t4.get(&p),
            Some(&o),
            "{p}: the rewritten tip's value was lost"
        );
    }
    let added: Vec<&String> = values(&t4)
        .into_keys()
        .filter(|p| !t3.contains_key(p))
        .collect::<Vec<_>>()
        .into_iter()
        .map(|p| t4.get_key_value(&p).unwrap().0)
        .collect();
    assert!(
        added
            .iter()
            .any(|p| p.starts_with("path/web/src/a.test.ts/")),
        "a's new attestation was not published: {added:?}"
    );
    for p in &added {
        assert!(
            !t2.contains_key(*p),
            "{p}: published again after the rewrite dropped it"
        );
    }
    // Every deletion record is the rewritten tip's, or of what it added.
    for p in t4.keys().filter(|p| p.ends_with("/__deleted")) {
        assert!(
            t3.contains_key(p),
            "{p}: a deletion record the rewritten tip did not have"
        );
    }
}

/// The round trips a fresh clone's plan waits for (2.11): the values it
/// reads first and the verdict objects they name are fetched while the
/// fetch merges, so the plan itself downloads neither, and the longest
/// chain of `git fetch` processes one after the other is shorter than with
/// `VCI_FETCH_AHEAD=0` (each `git fetch` slowed by 0.3 s).
#[test]
fn fresh_clone_plan_fetches_its_values_ahead() {
    let w = World::new(Some(small()));
    let run = |tag: &str, env: &[(&str, &str)]| -> (String, Vec<(f64, f64, String)>) {
        let dir = w.clone(tag, "pr");
        let log = w.base.join(format!("git-{tag}.log"));
        let log_s = log.to_str().unwrap().to_owned();
        let env: Vec<(&str, &str)> = [
            env,
            &[
                ("VCI_TIMING", "1"),
                ("VCI_TEST_GIT_LOG", &log_s),
                ("VCI_TEST_GIT_DELAY", "0.3"),
            ],
        ]
        .concat();
        let o = w.vci_ok(
            None,
            &dir,
            &[
                "plan",
                "--fetch",
                "origin",
                "--base-ref",
                "main",
                "--project",
                "web",
                "--format",
                "json",
            ],
            &env,
        );
        let _ = std::fs::remove_dir_all(&dir);
        (
            stderr(&o),
            fetches_of(&std::fs::read_to_string(&log).unwrap_or_default()),
        )
    };
    let (err, fetches) = run("ahead", &[]);
    let (off_err, off_fetches) = run("off", &[("VCI_FETCH_AHEAD", "0")]);
    // 4 units' chosen candidates (c's newest is set aside: main's is on the
    // base commit's tree) and the 7 objects they name.
    assert!(
        err.contains("vci: timing: fetch ahead: 4 candidate value(s) of 4 unit(s): "),
        "{err}"
    );
    assert!(err.contains("; 7 object(s) they name: "), "{err}");
    // The plan downloads neither again.
    for l in err.lines().filter(|l| l.contains("blob(s) downloaded)")) {
        if l.contains("value(s) (1 blob(s) downloaded)") {
            // The state object that names b's changed input, after the
            // verdicts, as before.
            continue;
        }
        assert!(l.contains("(0 blob(s) downloaded)"), "{l}\n{err}");
    }
    assert!(
        off_err.contains("vci: timing: fetch 4 value(s) (4 blob(s) downloaded)"),
        "{off_err}"
    );
    let (ours, theirs) = (
        serial_round_trips(&fetches),
        serial_round_trips(&off_fetches),
    );
    eprintln!("serial round trips: {ours} ahead, {theirs} with VCI_FETCH_AHEAD=0");
    assert!(
        ours < theirs,
        "{ours} >= {theirs}\n{fetches:?}\n{off_fetches:?}"
    );
    assert_eq!(
        fetches.len(),
        off_fetches.len(),
        "{fetches:?}\n{off_fetches:?}"
    );
}
