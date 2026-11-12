//! The plan's rounds after the first (2.10.1): a unit the first pass could
//! not skip is checked again with the candidates the plan set aside, and
//! the outcomes the first pass found are kept instead of checked a second
//! time, and the observations of a run's shape are shared by its units'
//! candidates. None of that may change what the plan decides or says: on a
//! store whose units have many candidates each (one that passes, one by a
//! signer the base does not trust, one expired, one whose signature was
//! edited, and ones made on other inputs), the plan's text and JSON and
//! `vci explain` of every unit are the same as with `VCI_PLAN_RECHECK=1`,
//! which checks every candidate in full in every round and observes each
//! one's inputs on its own, as vci 2.10.0 did, and, when
//! `VCI_TEST_VCI_BEFORE` names one, as a vci built before this change.
//!
//! A copy of `fixtures/vitest-abcd` in a throwaway git repository, as
//! `e2e_m3.rs` makes it. Needs `node`, `git` and `ssh-keygen` on PATH, and
//! the fixture's `node_modules` installed (`npm ci` in
//! fixtures/vitest-abcd). The timing measurement is an ignored test.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use assert_cmd::cargo::CommandCargoExt;
use serde_json::Value;

const A: &str = "src/a.test.ts";
const B: &str = "src/b.test.ts";
const C: &str = "src/c.test.ts";
const D: &str = "src/d.test.ts";
const UNITS: &[&str] = &[A, B, C, D];

const SQLITE: &[(&str, &str)] = &[("VCI_STORE", "sqlite")];
const GIT_META: &[(&str, &str)] = &[];

const RECHECK: (&str, &str) = ("VCI_PLAN_RECHECK", "1");

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

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn keygen(path: &Path, comment: &str) -> String {
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(path)
        .status()
        .unwrap();
    assert!(st.success());
    let pubkey = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    pubkey
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

struct World {
    _tmp: tempfile::TempDir,
    work: PathBuf,
    /// Trusted at the base commit.
    key: PathBuf,
    /// Not in the base commit's allowed_signers.
    stranger: PathBuf,
    gitconfig: PathBuf,
}

impl World {
    /// The fixture at a base commit on `main` whose four units all import
    /// `src/shared.ts` (and the generated units `generate` writes).
    fn new(generate: impl FnOnce(&World)) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let gitconfig = base.join("gitconfig");
        std::fs::write(
            &gitconfig,
            "[user]\n\tname = Test\n\temail = test@example.com\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n",
        )
        .unwrap();
        let key = base.join("trusted");
        let stranger = base.join("stranger");
        let pubkey = keygen(&key, "trusted");
        keygen(&stranger, "stranger");
        let work = base.join("work");
        let w = World {
            _tmp: tmp,
            work: work.clone(),
            key,
            stranger,
            gitconfig,
        };
        let fx = workspace_root().join("fixtures/vitest-abcd");
        std::fs::create_dir_all(&work).unwrap();
        w.git(&["init", "-q"]);
        for name in [
            "src",
            "fixtures",
            "package.json",
            "package-lock.json",
            "vitest.config.ts",
            "node_modules",
        ] {
            let st = Command::new("cp")
                .arg("-R")
                .arg(fx.join(name))
                .arg(work.join(name))
                .status()
                .unwrap();
            assert!(st.success());
        }
        w.write(".gitignore", "node_modules/\n.vci/out/\n");
        w.write("vci.toml", VCI_TOML);
        std::fs::create_dir_all(work.join(".vci")).unwrap();
        w.write(
            ".vci/allowed_signers",
            &format!("trusted@example.com namespaces=\"vci-attest\" {pubkey}\n"),
        );
        w.write("src/shared.ts", "export const shared = 0;\n");
        for unit in ["a", "b", "c", "d"] {
            let rel = format!("src/{unit}.ts");
            let body = w.read(&rel);
            w.write(
                &rel,
                &format!(
                    "import {{ shared }} from \"./shared\";\nexport const touched = shared;\n{body}"
                ),
            );
        }
        generate(&w);
        w.commit("base commit");
        w
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(&self.work)
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

    fn commit(&self, msg: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", msg]);
    }

    /// `bin <args>` in the repository with `env` added to a scrubbed
    /// environment: no store configured unless `env` configures one.
    fn command(&self, bin: Option<&Path>, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = match bin {
            Some(b) => Command::new(b),
            None => Command::cargo_bin("vci").unwrap(),
        };
        cmd.current_dir(&self.work)
            .args(args)
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
            "VCI_PLAN_RECHECK",
            "NODE_OPTIONS",
            "NODE_ENV",
            "CI",
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

    /// `vci <args>`; it must exit 0. Returns stdout.
    fn vci_ok(&self, bin: Option<&Path>, args: &[&str], env: &[(&str, &str)]) -> String {
        let out = self.command(bin, args, env);
        assert_eq!(out.status.code(), Some(0), "vci {args:?}: {}", text(&out));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// On a new branch from `main`: `shared.ts` set to `shared`, committed,
    /// and `vci run <units> --key <key> <extra>` (every unit when `units`
    /// is empty), which must attest them all.
    fn attest(
        &self,
        branch: &str,
        shared: u32,
        key: &Path,
        units: &[&str],
        extra: &[&str],
        env: &[(&str, &str)],
    ) {
        self.git(&["checkout", "-q", "-b", branch, "main"]);
        self.write(
            "src/shared.ts",
            &format!("export const shared = {shared};\n"),
        );
        self.commit(branch);
        let key = key.to_str().unwrap().to_owned();
        let mut args = vec!["run"];
        args.extend_from_slice(units);
        args.extend(["--key", &key]);
        args.extend_from_slice(extra);
        let out = self.command(None, &args, env);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        let attested = String::from_utf8_lossy(&out.stderr)
            .lines()
            .filter(|l| l.starts_with("vci: attested "))
            .count();
        let n = if units.is_empty() {
            UNITS.len()
        } else {
            units.len()
        };
        assert!(attested >= n, "{}", text(&out));
        // The next run's issue time (seconds) is later.
        std::thread::sleep(Duration::from_millis(1_100));
    }

    fn write(&self, rel: &str, content: &str) {
        let p = self.work.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.work.join(rel)).unwrap()
    }

    /// A connection to the SQLite store file, behind the store's back.
    fn db(&self) -> rusqlite::Connection {
        let db = rusqlite::Connection::open(self.work.join(".git/vci-store.sqlite")).unwrap();
        db.busy_timeout(Duration::from_secs(20)).unwrap();
        db
    }

    /// A copy of the repository's `.git` (its stores with it), for
    /// [`World::restore`].
    fn snapshot(&self) -> PathBuf {
        let to = self.work.with_file_name("snapshot.git");
        let st = Command::new("cp")
            .arg("-R")
            .arg(self.work.join(".git"))
            .arg(&to)
            .status()
            .unwrap();
        assert!(st.success());
        to
    }

    /// The repository's `.git` as [`World::snapshot`] copied it: what a
    /// plan remembers (the attestations that passed on its tree, which the
    /// next plan reads first) is forgotten.
    fn restore(&self, snapshot: &Path) {
        let git = self.work.join(".git");
        std::fs::remove_dir_all(&git).unwrap();
        let st = Command::new("cp")
            .arg("-R")
            .arg(snapshot)
            .arg(&git)
            .status()
            .unwrap();
        assert!(st.success());
    }

    /// The plan's text and JSON and `vci explain` of every unit, by
    /// `bin` (this build's vci when `None`) with `env`, each from the store
    /// as `snapshot` holds it, the current time in an expiry failure's
    /// text left out.
    fn says(
        &self,
        snapshot: &Path,
        bin: Option<&Path>,
        env: &[(&str, &str)],
    ) -> BTreeMap<String, String> {
        let now = regex_lite_now();
        let mut out = BTreeMap::new();
        let mut say = |what: String, args: &[&str]| {
            self.restore(snapshot);
            out.insert(what, now(&self.vci_ok(bin, args, env)));
        };
        say("plan".to_owned(), &["plan", "--base-ref", "main"]);
        say(
            "json".to_owned(),
            &["plan", "--base-ref", "main", "--format", "json"],
        );
        for u in UNITS {
            say(
                format!("explain {u}"),
                &["explain", u, "--base-ref", "main"],
            );
        }
        out
    }
}

/// A function that replaces `now is <RFC 3339 time>` (the expiry check's
/// actual value) by `now is NOW`.
fn regex_lite_now() -> impl Fn(&str) -> String {
    |s: &str| {
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
}

/// The verdict's `(skip, reason)` of each unit, from the plan's JSON.
fn verdicts(json: &str) -> BTreeMap<String, (bool, String)> {
    let v: Value = serde_json::from_str(json).unwrap();
    assert!(v["runAll"].is_null(), "{json}");
    v["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["testId"].as_str().unwrap().to_owned(),
                (
                    f["skip"].as_bool().unwrap(),
                    f["reason"].as_str().unwrap().to_owned(),
                ),
            )
        })
        .collect()
}

/// The vci `VCI_TEST_VCI_BEFORE` names (one built before 2.10.1), or `None`
/// (that part of the test is skipped, with a message).
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

/// Every unit with five or six candidates from as many runs, each on its
/// own branch (none supersedes another), oldest first: r1 on the inputs
/// the pull request has (b and c pass with it, a's own file changed
/// since), r2 by the stranger (fails `signer`), r3 with a one-second TTL
/// (fails `expiry`), r4 whose records' signatures are then edited on
/// SQLite (fails `signature`; on git-meta, where no record is edited, it
/// fails `inputs`), r5 on other inputs (fails `inputs`), and r6, of d
/// alone, on the pull request's inputs. The pull request, from `main`
/// (never attested: no memo), changes `shared.ts` to r1's and edits
/// `a.ts`. The first pass reads each unit's newest two (and d skips with
/// r6); a, b and c go to round 2, which reads the three set aside, keeps
/// the two outcomes it had, skips b and c with r1 and runs a, whose
/// reason names the furthest failure (`inputs`, which r5 and r1 both
/// reach: the last in the store's order).
fn same_decisions_and_reasons(env: &[(&str, &str)]) {
    let w = World::new(|_| {});
    let sqlite = !env.is_empty();
    w.attest("r1", 1, &w.key, &[], &[], env);
    w.attest("r2", 2, &w.stranger, &[], &[], env);
    w.attest("r3", 3, &w.key, &[], &["--ttl", "1s"], env);
    w.attest("r4", 4, &w.key, &[], &[], env);
    if sqlite {
        // r4's records (each unit's newest), their signatures edited: the
        // last byte of an SSHSIG blob is the signature's.
        let db = w.db();
        let rows: Vec<(String, Vec<u8>)> = db
            .prepare(
                "SELECT key, value FROM attestations a
                 WHERE issued = (SELECT max(issued) FROM attestations b WHERE b.test_key = a.test_key)",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let mut edited = 0;
        for (key, value) in rows {
            let mut frame = vci_core::Frame::decode(&value).unwrap();
            let vci_core::FrameSig::SshSig(blob) = &mut frame.sig else {
                panic!("{key}: not an SSH signature");
            };
            let last = blob.len() - 1;
            blob[last] ^= 0x01;
            db.execute(
                "UPDATE attestations SET value = ?2 WHERE key = ?1",
                rusqlite::params![key, frame.encode().unwrap().into_bytes()],
            )
            .unwrap();
            edited += 1;
        }
        assert_eq!(edited, UNITS.len());
    }
    w.attest("r5", 5, &w.key, &[], &[], env);
    w.attest("r6", 1, &w.key, &[D], &[], env);
    w.git(&["checkout", "-q", "-b", "pr", "main"]);
    w.write("src/shared.ts", "export const shared = 1;\n");
    w.write(
        "src/a.ts",
        &format!("{}// the pull request\n", w.read("src/a.ts")),
    );
    w.commit("the pull request");
    // r3's records expire a second after they were issued.
    std::thread::sleep(Duration::from_millis(1_100));
    let snapshot = w.snapshot();

    let ours = w.says(&snapshot, None, env);
    let v = verdicts(&ours["json"]);
    assert_eq!(
        v.iter()
            .map(|(u, (skip, _))| (u.as_str(), *skip))
            .collect::<Vec<_>>(),
        [(A, false), (B, true), (C, true), (D, true)],
        "{}",
        ours["plan"]
    );
    let a = &ours[&format!("explain {A}")];
    for check in ["signer", "expiry", "inputs"] {
        assert!(
            a.contains(&format!("failed check: {check}\n")),
            "{check}: {a}"
        );
    }
    if sqlite {
        assert!(a.contains("failed check: signature\n"), "{a}");
    }
    assert!(
        v[A].1
            .starts_with("no valid attestation (5 candidates; best failed inputs: entry:"),
        "{}",
        v[A].1
    );
    // Round 2 ran, and kept what the first pass found.
    w.restore(&snapshot);
    let out = w.command(
        None,
        &["plan", "--base-ref", "main"],
        &[env, &[("VCI_TIMING", "1")]].concat(),
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(
            "vci: timing: round 2: read 9 candidate(s) set aside for 3 unit(s) not skipped, check them again (1 still not): "
        ),
        "{err}"
    );
    assert!(
        err.contains("vci: timing: round 2: 6 candidate outcome(s) kept from the rounds before\n"),
        "{err}"
    );

    let rechecked = w.says(&snapshot, None, &[env, &[RECHECK]].concat());
    for (k, v) in &ours {
        assert_eq!(*v, rechecked[k], "{k} with VCI_PLAN_RECHECK=1");
    }
    if let Some(before) = vci_before() {
        let theirs = w.says(&snapshot, Some(&before), env);
        for (k, v) in &ours {
            assert_eq!(*v, theirs[k], "{k} by {}", before.display());
        }
    }
}

#[test]
fn round_two_decides_and_explains_as_checking_every_candidate_again_on_sqlite() {
    same_decisions_and_reasons(SQLITE);
}

#[test]
fn round_two_decides_and_explains_as_checking_every_candidate_again_on_git_meta() {
    same_decisions_and_reasons(GIT_META);
}

/// Round 2 reads a unit's newest candidates only (2.10.3). Five runs by one
/// signer on five inputs, the oldest on the inputs the pull request has:
/// a plan reads all five and skips every unit on the oldest, as before;
/// with `VCI_PLAN_CANDIDATES=2` it reads each unit's two newest after its
/// first pass, the units run, and it says that older attestations were not
/// read and that `vci prune` removes them. On vex, 12 November 2026, a
/// store nothing had pruned for four days held 125 attestations of each
/// Rails file, and round 2 fetched and read 180,033 of them in 288 s.
fn round_two_reads_the_newest_candidates(env: &[(&str, &str)]) {
    let w = World::new(|_| {});
    for (i, shared) in [1, 2, 3, 4, 5].into_iter().enumerate() {
        w.attest(&format!("r{}", i + 1), shared, &w.key, &[], &[], env);
    }
    w.git(&["checkout", "-q", "-b", "pr", "main"]);
    w.write("src/shared.ts", "export const shared = 1;\n");
    // Another tree than the oldest run's, so that the first pass, which
    // reads the candidate made on the checkout's tree, reads the newest.
    w.write("docs/pull-request.md", "no unit reads this\n");
    w.commit("the pull request");
    let snapshot = w.snapshot();
    let plan = |extra: &[(&str, &str)]| -> (BTreeMap<String, (bool, String)>, String) {
        w.restore(&snapshot);
        let env: Vec<(&str, &str)> = [env, extra].concat();
        let out = w.command(
            None,
            &["plan", "--base-ref", "main", "--format", "json"],
            &env,
        );
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        (
            verdicts(&String::from_utf8_lossy(&out.stdout)),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (all, err) = plan(&[]);
    assert!(all.values().all(|(skip, _)| *skip), "{all:?}\n{err}");
    assert!(!err.contains("were not read"), "{err}");
    let (capped, err) = plan(&[("VCI_PLAN_CANDIDATES", "2")]);
    assert!(capped.values().all(|(skip, _)| !*skip), "{capped:?}\n{err}");
    assert!(
        err.contains("older one(s) were not read") && err.contains("`vci prune`"),
        "{err}"
    );
    // Every one again with the cap off.
    let (off, _) = plan(&[("VCI_PLAN_CANDIDATES", "0")]);
    assert_eq!(off, all);
}

#[test]
fn round_two_reads_the_newest_candidates_on_sqlite() {
    round_two_reads_the_newest_candidates(SQLITE);
}

#[test]
fn round_two_reads_the_newest_candidates_on_git_meta() {
    round_two_reads_the_newest_candidates(GIT_META);
}

/// The seconds the first `VCI_TIMING` line of `stderr` starting with
/// `step` and containing `with` gives (the number after its last `: `).
fn timing_of(stderr: &str, step: &str, with: &str) -> Option<f64> {
    let prefix = format!("vci: timing: {step}");
    stderr
        .lines()
        .find(|l| l.starts_with(&prefix) && l.contains(with))
        .and_then(|l| l.rsplit_once(": "))
        .and_then(|(_, s)| s.trim_end_matches('s').parse().ok())
}

/// Not a check, a measurement (`cargo test -p vci-cli --test plan_rounds
/// -- --ignored --nocapture measure_`): round 2 of a plan in which every
/// unit runs, on a Vitest project of `VCI_MEASURE_UNITS` (default 2,000)
/// test files that each import `VCI_MEASURE_SHARED` (default 200) shared
/// modules through one barrel, attested by `VCI_MEASURE_RUNS` (default 8)
/// runs on as many branches (the odd ones edit `vitest.config.ts`, a
/// global input, the even ones a shared module; with
/// `VCI_MEASURE_SHAPES=distinct` each run also adds a module to the
/// barrel, so that no two runs share a shape), and a pull request from
/// `main` (never attested) that edits another shared module: every unit
/// runs, the first pass reads each unit's newest two candidates and round
/// 2 reads the rest. With `VCI_MEASURE_BIN` (a release build) as the vci
/// under test, prints for the store `VCI_MEASURE_STORE` (`git-meta` or
/// `sqlite`, default git-meta) the median of `VCI_MEASURE_REPEAT`
/// (default 3) plans' round 2 and total, as they are and with
/// `VCI_PLAN_RECHECK=1` (every candidate checked in full in every round,
/// as 2.10.0 did), and with `VCI_MEASURE_BEFORE` (a vci built before
/// 2.10.1) when it names one, and each one's `VCI_TIMING` lines.
#[test]
#[ignore]
fn measure_round_two_when_every_unit_runs() {
    let var = |k: &str, d: usize| -> usize {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let (units, shared, runs, repeat) = (
        var("VCI_MEASURE_UNITS", 2_000),
        var("VCI_MEASURE_SHARED", 200),
        var("VCI_MEASURE_RUNS", 8),
        var("VCI_MEASURE_REPEAT", 3),
    );
    let distinct = std::env::var("VCI_MEASURE_SHAPES").is_ok_and(|v| v == "distinct");
    let bin = std::env::var_os("VCI_MEASURE_BIN").map(PathBuf::from);
    let env: &[(&str, &str)] = match std::env::var("VCI_MEASURE_STORE").as_deref() {
        Ok("sqlite") => SQLITE,
        _ => GIT_META,
    };
    let barrel = |w: &World, extra: usize| {
        let mut all = String::new();
        let mut total = String::from("export const total = () => 0");
        for j in 0..shared {
            all.push_str(&format!("import {{ m{j} }} from \"./m{j:04}\";\n"));
            total.push_str(&format!(" + m{j}"));
        }
        for x in 0..extra {
            all.push_str(&format!("import {{ x{x} }} from \"./x{x:04}\";\n"));
            total.push_str(&format!(" + x{x}"));
        }
        all.push_str(&total);
        all.push_str(";\n");
        w.write("src/lib/all.ts", &all);
    };
    let w = World::new(|w| {
        for j in 0..shared {
            w.write(
                &format!("src/lib/m{j:04}.ts"),
                &format!("export const m{j} = {j};\n"),
            );
        }
        barrel(w, 0);
        for i in 0..units {
            w.write(
                &format!("src/own/o{i:04}.ts"),
                &format!("export const own = () => {i} + 1;\n"),
            );
            w.write(
                &format!("src/u{i:04}.test.ts"),
                &format!(
                    "import {{ expect, test }} from \"vitest\";\nimport {{ total }} from \"./lib/all\";\nimport {{ own }} from \"./own/o{i:04}\";\n\ntest(\"u{i}\", () => {{\n  expect(total() + own()).toBeGreaterThan(0);\n}});\n"
                ),
            );
        }
    });
    let key = w.key.to_str().unwrap().to_owned();
    for r in 1..=runs {
        w.git(&["checkout", "-q", "-b", &format!("run{r}"), "main"]);
        if r % 2 == 1 {
            let config = w.read("vitest.config.ts");
            w.write("vitest.config.ts", &format!("{config}// run {r}\n"));
        } else {
            w.write(
                &format!("src/lib/m{:04}.ts", r % shared.max(1)),
                &format!("export const m{} = {r} + {r};\n", r % shared.max(1)),
            );
        }
        if distinct {
            for x in 0..r {
                w.write(
                    &format!("src/lib/x{x:04}.ts"),
                    &format!("export const x{x} = {x};\n"),
                );
            }
            barrel(&w, r);
        }
        w.commit(&format!("run {r}"));
        let t = std::time::Instant::now();
        let out = w.command(bin.as_deref(), &["run", "--key", &key], env);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        eprintln!("MEASURE run {r}: {:.1} s", t.elapsed().as_secs_f64());
        std::thread::sleep(Duration::from_millis(1_100));
    }
    w.git(&["checkout", "-q", "-b", "pr", "main"]);
    w.write("src/lib/m0000.ts", "export const m0 = 0 + 0;\n");
    w.commit("the pull request");
    let median = |mut v: Vec<f64>| -> f64 {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    };
    let before = std::env::var_os("VCI_MEASURE_BEFORE").map(PathBuf::from);
    let mut variants = vec![
        ("as is", bin.clone(), vec![]),
        ("VCI_PLAN_RECHECK=1", bin.clone(), vec![RECHECK]),
    ];
    if let Some(b) = before {
        variants.push(("VCI_MEASURE_BEFORE", Some(b), vec![]));
    }
    for (what, bin, extra) in variants {
        let env = [env, &extra, &[("VCI_TIMING", "1")]].concat();
        let (mut rounds, mut totals, mut sample) = (Vec::new(), Vec::new(), String::new());
        for _ in 0..repeat {
            let out = w.command(bin.as_deref(), &["plan", "--base-ref", "main"], &env);
            assert_eq!(out.status.code(), Some(0), "{}", text(&out));
            let err = String::from_utf8_lossy(&out.stderr);
            rounds.push(timing_of(&err, "round 2: ", "check them again").unwrap_or(0.0));
            totals.push(timing_of(&err, "plan total", "").unwrap_or(0.0));
            sample = err
                .lines()
                .filter(|l| l.starts_with("vci: timing: "))
                .collect::<Vec<_>>()
                .join("\n");
            let plan = String::from_utf8_lossy(&out.stdout);
            if let Some(l) = plan.lines().last() {
                sample.push_str(&format!("\n{l}"));
            }
        }
        eprintln!(
            "MEASURE {what}: round 2 median {:.2} s, plan total median {:.2} s ({repeat} plans)\n{sample}\n",
            median(rounds),
            median(totals)
        );
    }
}
