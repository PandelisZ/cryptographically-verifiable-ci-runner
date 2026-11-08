//! The round trips a plan makes to a git-meta remote after its first
//! verdicts (vci 2.10.1), through the `vci` binary, in the shape of a vex
//! Rails pull request job: a cached blobless clone that fetched and planned
//! before; other clones that attested units on changed inputs since, in
//! runs of their own, and pushed; the cached clone's pull request then
//! plans with `--fetch`, as the action does. Its first verdicts leave units
//! whose newer candidates were not fetched (round 2) and units whose
//! inputs changed (the failure text names the input). 2.10.0 then fetched,
//! one after the other, the candidates, the objects they name and the state
//! objects (three round trips, about 0.8 s each against GitHub); 2.10.1
//! fetches the objects beside the candidates, in one.
//!
//! The remote is a local bare repository that serves partial clones, and
//! a `git` wrapper first on PATH logs every `git fetch` (and can slow it
//! down, or fail the ones that ask for given blobs). A copy of
//! `fixtures/vitest-abcd`; needs `node`, `git`, `bash` and `ssh-keygen` on
//! PATH and the fixture's `node_modules` installed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use assert_cmd::cargo::CommandCargoExt;
use serde_json::Value;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_owned()
}

const VCI_TOML: &str = r#"project = "."

[policy]
platform = "any"
max_ttl = "30d"

[env]
hash = ["NODE_ENV"]
"#;

/// The units of each kind: `x` and `g` import a module another clone
/// attests a change of (`g` with a global input changed too), `y` one only
/// the pull request changes, `o` none.
const KINDS: &[(&str, Option<&str>)] = &[
    ("x", Some("x")),
    ("g", Some("g")),
    ("y", Some("y")),
    ("o", None),
];
const PER_KIND: usize = 4;

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

struct World {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    key: PathBuf,
    gitconfig: PathBuf,
    /// The directory holding the `git` wrapper.
    wrapper: PathBuf,
    /// The cached clone, on the pull request's commit.
    cached: PathBuf,
    /// The blob ids of the objects the run that changed a global input
    /// published (hdr, shape, state).
    global_run_blobs: Vec<String>,
}

/// The `git` wrapper: logs each `git fetch` to `$VCI_TEST_GIT_LOG` (its
/// start time and arguments), sleeps `$VCI_TEST_GIT_DELAY` seconds first
/// when set, and fails a `git fetch --stdin` whose object ids include one
/// listed in the file `$VCI_TEST_GIT_POISON` (as a remote that no longer
/// serves an object fails the whole fetch).
fn wrapper_script(real_git: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
sub=""; skip=0
for a in "$@"; do
  if [ $skip = 1 ]; then skip=0; continue; fi
  case "$a" in -c|-C) skip=1;; -*) ;; *) sub="$a"; break;; esac
done
if [ "$sub" = fetch ]; then
  if [ -n "$VCI_TEST_GIT_LOG" ]; then echo "$(date +%s) $*" >> "$VCI_TEST_GIT_LOG"; fi
  if [ -n "$VCI_TEST_GIT_DELAY" ]; then sleep "$VCI_TEST_GIT_DELAY"; fi
  case " $* " in
    *" --stdin "*)
      input=$(cat)
      if [ -n "$VCI_TEST_GIT_POISON" ] && printf '%s\n' "$input" | grep -qFf "$VCI_TEST_GIT_POISON"; then
        echo "fatal: remote error: upload-pack: not our ref" >&2
        exit 128
      fi
      printf '%s\n' "$input" | "{real_git}" "$@"
      exit $?;;
  esac
fi
exec "{real_git}" "$@"
"#
    )
}

impl World {
    fn git(&self, dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// `vci <args>` in `dir` with `env` added to a scrubbed environment, the
    /// `git` wrapper first on PATH.
    fn vci(&self, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::cargo_bin("vci").unwrap();
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
            "NODE_OPTIONS",
            "NODE_ENV",
            "CI",
            "VCI_TEST_GIT_LOG",
            "VCI_TEST_GIT_DELAY",
            "VCI_TEST_GIT_POISON",
        ]
        .iter()
        .chain(vci_store::select::ENV_VARS)
        {
            cmd.env_remove(k);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        eprintln!(
            "$ vci {} {env:?} in {} -> {:?}\n{}",
            args.join(" "),
            dir.display(),
            out.status.code(),
            text(&out)
        );
        out
    }

    fn vci_ok(&self, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        let out = self.vci(dir, args, env);
        assert_eq!(out.status.code(), Some(0), "vci {args:?}: {}", text(&out));
        out
    }

    fn copy_fixture_modules(dir: &Path) {
        let st = Command::new("cp")
            .arg("-R")
            .arg(workspace_root().join("fixtures/vitest-abcd/node_modules"))
            .arg(dir.join("node_modules"))
            .status()
            .unwrap();
        assert!(st.success());
    }

    /// A clone of the remote (`--filter=blob:none` when `blobless`), with
    /// the fixture's modules.
    fn clone(&self, name: &str, blobless: bool) -> PathBuf {
        let dir = self.base.join(name);
        let remote = self.base.join("origin.git");
        let mut args = vec!["clone", "-q", "--no-local"];
        if blobless {
            args.push("--filter=blob:none");
        }
        args.extend([remote.to_str().unwrap(), dir.to_str().unwrap()]);
        self.git(&self.base, &args);
        Self::copy_fixture_modules(&dir);
        dir
    }

    /// Another clone attests the units of `kind` on its own change of their
    /// module (and of a global input with `global`), in a run of its own,
    /// and pushes.
    fn attest_elsewhere(&self, name: &str, kind: &str, global: bool) {
        let dir = self.clone(name, false);
        self.git(&dir, &["checkout", "-q", "-b", &format!("pr-{name}")]);
        std::fs::write(
            dir.join(format!("src/lib/{kind}.ts")),
            format!("export const {kind} = () => 10;\n"),
        )
        .unwrap();
        if global {
            let config = dir.join("vitest.config.ts");
            let mut c = std::fs::read_to_string(&config).unwrap();
            c.push_str("// another global input\n");
            std::fs::write(&config, c).unwrap();
        }
        self.git(&dir, &["commit", "-q", "-am", &format!("change {kind}")]);
        self.vci_ok(&dir, &["fetch", "--remote", "origin"], &[]);
        let key = self.key.to_str().unwrap().to_owned();
        let units: Vec<String> = (1..=PER_KIND)
            .map(|i| format!("src/{kind}{i:02}.test.ts"))
            .collect();
        let mut args: Vec<&str> = vec!["run"];
        args.extend(units.iter().map(String::as_str));
        args.extend(["--key", &key]);
        let out = self.vci_ok(&dir, &args, &[]);
        assert!(
            stderr(&out).contains(&format!("{PER_KIND} attested, 0 not attested")),
            "{}",
            text(&out)
        );
        self.vci_ok(&dir, &["push", "--remote", "origin"], &[]);
    }

    fn new() -> World {
        let tmp = tempfile::tempdir().unwrap();
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
        let mut w = World {
            _tmp: tmp,
            base: base.clone(),
            key,
            gitconfig,
            wrapper,
            cached: base.join("cached"),
            global_run_blobs: vec![],
        };

        // The main branch: every unit attested in one run, pushed.
        let work = base.join("work");
        std::fs::create_dir_all(work.join("src/lib")).unwrap();
        std::fs::create_dir_all(work.join("src/own")).unwrap();
        w.git(&work, &["init", "-q"]);
        let fx = workspace_root().join("fixtures/vitest-abcd");
        for name in ["package.json", "package-lock.json", "vitest.config.ts"] {
            std::fs::copy(fx.join(name), work.join(name)).unwrap();
        }
        World::copy_fixture_modules(&work);
        std::fs::write(work.join(".gitignore"), "node_modules/\n.vci/out/\n").unwrap();
        std::fs::write(work.join("vci.toml"), VCI_TOML).unwrap();
        std::fs::create_dir_all(work.join(".vci")).unwrap();
        std::fs::write(
            work.join(".vci/allowed_signers"),
            format!("trusted@example.com namespaces=\"vci-attest\" {pubkey}\n"),
        )
        .unwrap();
        for (kind, lib) in KINDS {
            if let Some(lib) = lib {
                std::fs::write(
                    work.join(format!("src/lib/{lib}.ts")),
                    format!("export const {lib} = () => 1;\n"),
                )
                .unwrap();
            }
            for i in 1..=PER_KIND {
                let name = format!("{kind}{i:02}");
                std::fs::write(
                    work.join(format!("src/own/{name}.ts")),
                    format!("export const own = () => {i};\n"),
                )
                .unwrap();
                let (import, expr) = match lib {
                    Some(lib) => (
                        format!("import {{ {lib} }} from \"./lib/{lib}\";\n"),
                        format!("{lib}() + own()"),
                    ),
                    None => (String::new(), "own()".to_owned()),
                };
                std::fs::write(
                    work.join(format!("src/{name}.test.ts")),
                    format!(
                        "import {{ expect, test }} from \"vitest\";\n{import}import {{ own }} from \"./own/{name}\";\n\ntest(\"{name}\", () => {{\n  expect({expr}).toBeGreaterThan(0);\n}});\n"
                    ),
                )
                .unwrap();
            }
        }
        w.git(&work, &["add", "-A"]);
        w.git(&work, &["commit", "-q", "-m", "base"]);
        let remote = base.join("origin.git");
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
        let out = w.vci_ok(&work, &["run", "--key", &key], &[]);
        let all = KINDS.len() * PER_KIND;
        assert!(
            stderr(&out).contains(&format!("{all} attested, 0 not attested")),
            "{}",
            text(&out)
        );
        w.vci_ok(&work, &["push", "--remote", "origin"], &[]);

        // The cached clone: blobless, the metadata's keys fetched, and one
        // plan of the main branch (which fetched what it read and
        // remembered what passed).
        let cached = w.clone("cached", true);
        w.vci_ok(&cached, &["fetch", "--remote", "origin"], &[]);
        let out = w.vci_ok(&cached, &["plan", "--base-ref", "main"], &[]);
        assert!(
            stdout(&out).ends_with(&format!("{all} to skip, 0 to run\n")),
            "{}",
            text(&out)
        );

        // Since then: one clone attested the x units on a change of x.ts,
        // another the g units on a change of g.ts and of a global input
        // (new hdr objects), each in a run of its own, and pushed.
        w.attest_elsewhere("b", "x", false);
        w.attest_elsewhere("d", "g", true);
        // The objects d's run published (hdr, shape, state): the tip's
        // commit added them.
        let tip = w.git(&remote, &["rev-parse", "refs/meta/main"]);
        let added = w.git(
            &remote,
            &["diff-tree", "-r", "--no-commit-id", "--diff-filter=A", &tip],
        );
        w.global_run_blobs = added
            .lines()
            .filter(|l| l.contains("/vci/object/"))
            .map(|l| l.split_whitespace().nth(3).unwrap().to_owned())
            .collect();
        assert!(w.global_run_blobs.len() >= 3, "d's run's objects: {added}");

        // The cached clone's pull request: x.ts as b changed it, g.ts as d
        // did (without d's global input), and y.ts; another tree than
        // either of theirs, as a merge commit's is.
        w.git(&cached, &["checkout", "-q", "-b", "pr"]);
        for (lib, v) in [("x", 10), ("g", 10), ("y", 20)] {
            std::fs::write(
                cached.join(format!("src/lib/{lib}.ts")),
                format!("export const {lib} = () => {v};\n"),
            )
            .unwrap();
        }
        w.git(&cached, &["commit", "-q", "-am", "change x, g and y"]);
        w.cached = cached;
        w
    }

    /// A copy of the cached clone, for one plan.
    fn copy(&self, name: &str) -> PathBuf {
        let dir = self.base.join(name);
        let st = Command::new("cp")
            .arg("-R")
            .arg(&self.cached)
            .arg(&dir)
            .status()
            .unwrap();
        assert!(st.success());
        dir
    }
}

/// The number a `VCI_TIMING` line of `stderr` gives after `prefix`.
fn timing_number(stderr: &str, prefix: &str) -> Option<f64> {
    let prefix = format!("vci: timing: {prefix}");
    stderr.lines().find_map(|l| {
        l.strip_prefix(&prefix)
            .and_then(|rest| rest.trim().trim_end_matches('s').parse().ok())
    })
}

/// The plan's units as (test id, skip, reason, signer's key), from `--format
/// json`.
fn decisions(json: &str) -> Vec<(String, bool, String, String)> {
    let v: Value = serde_json::from_str(json).unwrap();
    assert!(v["runAll"].is_null(), "{json}");
    v["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["testId"].as_str().unwrap().to_owned(),
                f["skip"].as_bool().unwrap(),
                f["reason"].as_str().unwrap().to_owned(),
                f["by"]["metaKey"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect()
}

fn units_of(kind: &str) -> BTreeSet<String> {
    (1..=PER_KIND)
        .map(|i| format!("src/{kind}{i:02}.test.ts"))
        .collect()
}

/// What a plan of the pull request prints, and how many round trips for
/// values it made after its first verdicts.
struct Planned {
    json: String,
    text: String,
    explain: String,
    round_trips: f64,
    fetches: usize,
}

/// `vci plan --fetch origin` of the pull request in fresh copies of the
/// cached clone (`--format json`, then `--format text`), and `vci explain`
/// of a g unit after `vci fetch` in a third, with `env`.
fn plan(w: &World, tag: &str, env: &[(&str, &str)]) -> Planned {
    let log = w.base.join(format!("git-{tag}.log"));
    let log_s = log.to_str().unwrap().to_owned();
    let env: Vec<(&str, &str)> =
        [env, &[("VCI_TIMING", "1"), ("VCI_TEST_GIT_LOG", &log_s)]].concat();
    let args = ["plan", "--fetch", "origin", "--base-ref", "main"];
    let dir = w.copy(&format!("{tag}-json"));
    let out = w.vci_ok(&dir, &[&args[..], &["--format", "json"]].concat(), &env);
    let round_trips = timing_number(
        &stderr(&out),
        "round trips for values after the first verdicts: ",
    )
    .unwrap_or_else(|| panic!("no round trip line: {}", stderr(&out)));
    let fetches = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .count();
    let json = stdout(&out);
    let dir = w.copy(&format!("{tag}-text"));
    let out = w.vci_ok(&dir, &[&args[..], &["--format", "text"]].concat(), &env);
    assert_eq!(
        timing_number(
            &stderr(&out),
            "round trips for values after the first verdicts: "
        ),
        Some(round_trips),
        "{}",
        stderr(&out)
    );
    let text = stdout(&out);
    let dir = w.copy(&format!("{tag}-explain"));
    w.vci_ok(&dir, &["fetch", "--remote", "origin"], &env);
    let out = w.vci_ok(
        &dir,
        &["explain", "src/g01.test.ts", "--base-ref", "main"],
        &env,
    );
    Planned {
        json,
        text,
        explain: stdout(&out),
        round_trips,
        fetches,
    }
}

/// 2.10.1: after its first verdicts the pull request's plan makes one round
/// trip for values (2.10.0: three, one after the other: the x and g units'
/// newer candidates, the hdr and shape objects they name, then the state
/// objects that name the inputs that changed), and decides, says and
/// explains exactly what it did before: the same units skip, by the same
/// attestations, the others run for the same reasons, each naming the input
/// that changed. `VCI_FETCH_BESIDE=0` is 2.10.0's fetching.
#[test]
fn one_round_trip_after_the_first_verdicts_and_the_same_plan() {
    let w = World::new();
    let before = plan(&w, "before", &[("VCI_FETCH_BESIDE", "0")]);
    let after = plan(&w, "after", &[]);
    assert_eq!(before.round_trips, 3.0, "2.10.0's three");
    assert_eq!(after.round_trips, 1.0, "2.10.1's one");
    // The background fetch, then one `git fetch` per round trip (2.10.1's
    // one runs the candidates' and the objects' at once).
    assert_eq!(before.fetches, 1 + 3, "{}", before.fetches);
    assert_eq!(after.fetches, 1 + 2, "{}", after.fetches);

    let d = decisions(&after.json);
    assert_eq!(d, decisions(&before.json), "the same plan");
    let skipped: BTreeSet<String> = d.iter().filter(|u| u.1).map(|u| u.0.clone()).collect();
    let run: BTreeSet<String> = d.iter().filter(|u| !u.1).map(|u| u.0.clone()).collect();
    assert_eq!(
        skipped,
        units_of("x").union(&units_of("o")).cloned().collect(),
        "x units skip on b's attestations, o units on main's"
    );
    assert_eq!(run, units_of("g").union(&units_of("y")).cloned().collect());
    for (id, skip, reason, _) in &d {
        for lib in ["g", "y"] {
            if !skip && id.contains(&format!("/{lib}")) {
                assert!(
                    reason.ends_with(&format!("best failed inputs: entry:src/lib/{lib}.ts)")),
                    "{id}: {reason}"
                );
            }
        }
    }
    assert_eq!(after.text, before.text, "the same text plan");
    assert!(
        after.text.contains("src/lib/y.ts"),
        "the input named: {}",
        after.text
    );
    assert_eq!(after.explain, before.explain, "the same explanation");
}

/// 2.10.1: objects fetched beside the candidates are a guess, and a guess
/// that fails changes nothing: here the remote no longer serves the objects
/// d's run published (every `git fetch` asking for one fails, as one asking
/// for an object GitHub no longer has does). The candidates still arrive in
/// the same round trip, the plan exits 0 and decides and says what 2.10.0's
/// fetching does on the same remote (whose own fetch of those objects
/// fails too: the g units, and the x units whose shape object was asked in
/// the same `git fetch`, run).
#[test]
fn a_failed_guess_changes_nothing() {
    let w = World::new();
    let poison = w.base.join("poison");
    std::fs::write(&poison, w.global_run_blobs.join("\n") + "\n").unwrap();
    let poison = poison.to_str().unwrap().to_owned();
    let env = [("VCI_TEST_GIT_POISON", poison.as_str())];
    let before = plan(
        &w,
        "before",
        &[&env[..], &[("VCI_FETCH_BESIDE", "0")]].concat(),
    );
    let after = plan(&w, "after", &env);
    let d = decisions(&after.json);
    assert_eq!(d, decisions(&before.json), "the same plan");
    assert!(
        d.iter().filter(|u| u.0.contains("/o")).all(|u| u.1),
        "{d:?}"
    );
    assert!(
        d.iter().filter(|u| u.0.contains("/g")).all(|u| !u.1),
        "{d:?}"
    );
    assert_eq!(after.text, before.text);
    assert_eq!(after.explain, before.explain);
}

/// Not a check, a measurement (`cargo test -p vci-cli --test
/// e2e_round_trips -- --ignored --nocapture measure_`): the pull request's
/// plan with every `git fetch` slowed by `VCI_MEASURE_DELAY` seconds
/// (default 0.8, a round trip to GitHub), with 2.10.0's fetching
/// (`VCI_FETCH_BESIDE=0`) and 2.10.1's, alternately, `VCI_MEASURE_REPEAT`
/// times (default 3) each; prints each plan's total and round trips and
/// the medians.
#[test]
#[ignore]
fn measure_round_trips_after_the_first_verdicts() {
    let delay = std::env::var("VCI_MEASURE_DELAY").unwrap_or_else(|_| "0.8".into());
    let repeat: usize = std::env::var("VCI_MEASURE_REPEAT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let w = World::new();
    let median = |mut v: Vec<f64>| -> f64 {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    };
    let mut totals: [Vec<f64>; 2] = [vec![], vec![]];
    for n in 0..repeat {
        for (i, (label, extra)) in [
            ("2.10.0 fetching", vec![("VCI_FETCH_BESIDE", "0")]),
            ("2.10.1", vec![]),
        ]
        .into_iter()
        .enumerate()
        {
            let dir = w.copy(&format!("measure-{n}-{i}"));
            let env = [
                &extra[..],
                &[("VCI_TIMING", "1"), ("VCI_TEST_GIT_DELAY", delay.as_str())],
            ]
            .concat();
            let t = std::time::Instant::now();
            let out = w.vci_ok(
                &dir,
                &["plan", "--fetch", "origin", "--base-ref", "main"],
                &env,
            );
            let wall = t.elapsed().as_secs_f64();
            let err = stderr(&out);
            let total = timing_number(&err, "plan total: ").unwrap_or(0.0);
            totals[i].push(total);
            eprintln!(
                "MEASURE {label}: plan total {total:.2} s, wall {wall:.2} s, round trips after the first verdicts {}\n{}",
                timing_number(&err, "round trips for values after the first verdicts: ")
                    .unwrap_or(-1.0),
                err.lines()
                    .filter(|l| l.contains("value(s) (")
                        || l.contains("beside")
                        || l.contains("round 2")
                        || l.contains("name the inputs"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }
    eprintln!(
        "MEASURE medians with {delay} s per git fetch: 2.10.0 fetching {:.2} s, 2.10.1 {:.2} s",
        median(totals[0].clone()),
        median(totals[1].clone())
    );
}
