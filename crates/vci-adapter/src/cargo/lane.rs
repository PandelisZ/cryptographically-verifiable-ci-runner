//! The cargo lane and the execution pool.
//!
//! One `cargo` runs at a time (cargo locks the build directory): the lane, a
//! single thread, makes every cargo invocation of a run in order:
//!
//! 1. a warm-up build of each package with a requested unit (`cargo test
//!    --no-run --manifest-path <package>`), which compiles all its test
//!    targets with cargo's full parallelism. One package at a time, like the
//!    units' own builds, so that features are unified as they are for its
//!    units (a build of several packages unifies their dependencies'
//!    features, and the units' builds would then compile again what
//!    differs). Its failure is not fatal: each unit's own build then
//!    compiles what it needs, as before;
//! 2. per unit, `cargo test <unit> --no-run --message-format=json`: the unit
//!    alone, so its feature unification, the artifacts analysed and the
//!    executable run are its own (after the warm-up, mostly fresh). `#doc`
//!    units run `cargo test --doc` here (doctests cannot be built without
//!    running them).
//!
//! Each prepared unit goes to the execution pool (`VCI_CARGO_JOBS` threads,
//! default the number of CPUs), which runs its test executable (see
//! [`exec`]) and prints its output as one block when it is done. A unit
//! whose build fails, or whose executable is missing or cannot be started,
//! is refused with a taint; the others proceed.
//!
//! Units are analysed once every test of the run has run (by as many
//! threads): the walks of package directories, shared by the units of the
//! run, then follow every unit's own test, as they did when each unit was
//! analysed right after it ran alone, and do not depend on which units ran
//! first.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::sync::{Mutex, mpsc};

use camino::Utf8PathBuf;

use super::{
    Artifact, BuildRun, CargoAdapter, LIB_KINDS, RunCtx, UnitKind, exec, lock, manifest_arg,
    parse_unit, rustc_sysroot, rustc_used, split_messages, unit_result,
};
use crate::vitest::describe;
use crate::{AdapterError, ChildEnv, Observed};

/// What is left to do for a unit after the cargo lane.
enum Step {
    /// Run the test executable.
    Exec(exec::Spec),
    /// It ran in the lane (doctests), or its build failed: (exit code,
    /// harness output, milliseconds).
    Ran {
        code: Option<i32>,
        text: String,
        elapsed: u64,
    },
    /// Nothing to run or analyse (not a unit id).
    Done { code: Option<i32> },
}

/// A unit as the cargo lane hands it to the execution pool.
struct Prepared {
    idx: usize,
    o: Observed,
    arts: Vec<Artifact>,
    runs: Vec<BuildRun>,
    /// Output so far (the cargo invocations).
    block: Vec<u8>,
    step: Step,
}

/// A unit after the execution pool, before its analysis.
struct Ran {
    /// The exit code `cargo test` would have had.
    code: Option<i32>,
    o: Observed,
    arts: Vec<Artifact>,
    runs: Vec<BuildRun>,
    /// Whether there is anything to analyse (not for an id that is not a
    /// unit).
    analyse: bool,
}

/// Whether artifact `a` is the test harness of `kind`.
fn is_unit_target(a: &Artifact, kind: &UnitKind) -> bool {
    let is = |k: &str| a.kind.iter().any(|x| x == k);
    let named = |k: &str, n: &str| is(k) && a.target_name == n;
    a.test_profile
        && a.executable.is_some()
        && match kind {
            UnitKind::Lib => LIB_KINDS.iter().any(|k| is(k)),
            UnitKind::Doc => false,
            UnitKind::Bin(n) => named("bin", n),
            UnitKind::Test(n) => named("test", n),
            UnitKind::Example(n) => named("example", n),
            UnitKind::Bench(n) => named("bench", n),
        }
}

impl CargoAdapter {
    /// Build and run `files` (unit ids relative to the project dir): the
    /// cargo lane on this thread, the execution pool on others. Per unit, in
    /// order: the exit code `cargo test` would have had, and the
    /// observations (analysed when `collect`).
    pub(super) fn run_units(
        &self,
        files: &[String],
        env: &ChildEnv,
        ctx: &RunCtx,
        collect: bool,
    ) -> Result<Vec<(Option<i32>, Observed)>, AdapterError> {
        let results: Mutex<Vec<Option<Ran>>> = Mutex::new(files.iter().map(|_| None).collect());
        let workers = exec::pool_size().min(files.len()).max(1);
        let (tx, rx) = mpsc::channel::<Prepared>();
        let rx = Mutex::new(rx);
        let lane = std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| {
                    loop {
                        // One worker waits for the next unit at a time.
                        let next = lock(&rx).recv();
                        let Ok(p) = next else { break };
                        let idx = p.idx;
                        let (ran, block) = Self::execute(p, env);
                        let _ = std::io::stderr().write_all(&block);
                        lock(&results)[idx] = Some(ran);
                    }
                });
            }
            let r = self.lane(files, env, ctx, collect, &tx);
            drop(tx);
            r
        });
        lane?;
        let mut results: Vec<Ran> = results
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .into_iter()
            .zip(files)
            .map(|(r, f)| {
                r.unwrap_or_else(|| {
                    // Defensive: a worker that panicked panics the scope
                    // above, so every unit has a result here.
                    let mut o = Observed {
                        shared_group: None,
                        test_id: f.clone(),
                        ..Default::default()
                    };
                    o.taints.push("cargo: the unit was not run".into());
                    o.result = Some(unit_result("", false, 0));
                    Ran {
                        code: Some(101),
                        o,
                        arts: vec![],
                        runs: vec![],
                        analyse: false,
                    }
                })
            })
            .collect();
        if collect {
            // Every test of the run has run: analyse the units, in parallel.
            let queue = Mutex::new(results.iter_mut());
            std::thread::scope(|s| {
                for _ in 0..workers {
                    s.spawn(|| {
                        loop {
                            let Some(r) = lock(&queue).next() else { break };
                            if r.analyse {
                                self.analyse(&mut r.o, &r.arts, &r.runs, ctx);
                            }
                        }
                    });
                }
            });
        }
        Ok(results.into_iter().map(|r| (r.code, r.o)).collect())
    }

    /// The cargo lane: the warm-up build, then each unit's build, handed to
    /// the pool in order.
    fn lane(
        &self,
        files: &[String],
        env: &ChildEnv,
        ctx: &RunCtx,
        collect: bool,
        tx: &mpsc::Sender<Prepared>,
    ) -> Result<(), AdapterError> {
        self.warm_up(files, env, ctx, collect)?;
        for (idx, unit) in files.iter().enumerate() {
            let p = self.prepare(idx, unit, env, ctx, collect)?;
            if tx.send(p).is_err() {
                // Every worker is gone (they panicked); the scope reports it.
                break;
            }
        }
        Ok(())
    }

    /// One `cargo test --no-run` of each package with a requested unit, so
    /// the units' own builds find their artifacts fresh. With `collect`, a
    /// repository crate cargo reused from a build vci did not make in this
    /// run is cleaned and the package's warm-up repeated, once.
    fn warm_up(
        &self,
        files: &[String],
        env: &ChildEnv,
        ctx: &RunCtx,
        collect: bool,
    ) -> Result<(), AdapterError> {
        let mut seen = BTreeSet::new();
        let pkgs: Vec<String> = files
            .iter()
            .filter_map(|f| parse_unit(f))
            .filter(|(d, _)| ctx.member(&self.project_dir, d).is_some())
            .filter(|(d, _)| seen.insert(ctx.canon(&self.project_dir.join(d))))
            .map(|(d, _)| d)
            .collect();
        for pkg_rel in pkgs {
            if !self.warm_up_package(&pkg_rel, env, ctx, collect)? {
                break;
            }
        }
        Ok(())
    }

    /// The warm-up build of the package in `pkg_rel`; `false` when a
    /// temporary directory cannot be made (the units' own builds then
    /// compile, or are refused).
    fn warm_up_package(
        &self,
        pkg_rel: &str,
        env: &ChildEnv,
        ctx: &RunCtx,
        collect: bool,
    ) -> Result<bool, AdapterError> {
        let mut retried = false;
        loop {
            let tmp = match tempfile::Builder::new().prefix("vci-cargotmp-").tempdir() {
                Ok(t) => t,
                Err(e) => {
                    let _ = writeln!(
                        std::io::stderr(),
                        "vci: no warm-up build: creating a temporary directory: {e}"
                    );
                    return Ok(false);
                }
            };
            let mut cmd = self.cargo_cmd(env);
            cmd.args(["test", "--locked", "--no-run", "--manifest-path"])
                .arg(manifest_arg(pkg_rel))
                .arg("--message-format=json")
                .arg("--target-dir")
                .arg(ctx.target_dir.as_str())
                .env("TMPDIR", tmp.path());
            let out = cmd.output().map_err(|e| self.not_installed("cargo", e))?;
            let (arts, _, _) = split_messages(&String::from_utf8_lossy(&out.stdout));
            let mut block = format!(
                "vci: warm-up build: {} (exit {})\n",
                describe(&cmd),
                out.status
                    .code()
                    .map_or_else(|| "signal".to_owned(), |c| c.to_string())
            )
            .into_bytes();
            block.extend_from_slice(&out.stderr);
            if collect && !retried {
                let reused = self.reused_repo_packages(&arts, ctx);
                if !reused.is_empty() {
                    retried = true;
                    block.extend_from_slice(
                        format!(
                            "vci: cargo reused {} from an earlier build; rebuilding it\n",
                            reused
                                .iter()
                                .map(|(n, v)| format!("{n}@{v}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                        .as_bytes(),
                    );
                    block.extend(self.clean(&reused, env, ctx)?);
                    let _ = std::io::stderr().write_all(&block);
                    continue;
                }
            }
            if !out.status.success() {
                block.extend_from_slice(
                    b"vci: the warm-up build failed; each unit's own build compiles what it needs\n",
                );
            }
            let _ = std::io::stderr().write_all(&block);
            return Ok(true);
        }
    }

    /// The cargo lane's part of one unit: its build (`--no-run`), or its
    /// doctests.
    fn prepare(
        &self,
        idx: usize,
        unit: &str,
        env: &ChildEnv,
        ctx: &RunCtx,
        collect: bool,
    ) -> Result<Prepared, AdapterError> {
        let mut p = Prepared {
            idx,
            o: Observed {
                shared_group: None,
                test_id: unit.to_owned(),
                root: self.project_dir.to_string(),
                adapter: "cargo".into(),
                collector: "cargo".into(),
                runner_version: ctx.probe.versions.runner.clone(),
                ..Default::default()
            },
            arts: vec![],
            runs: vec![],
            block: vec![],
            step: Step::Done { code: Some(1) },
        };
        let Some((pkg_rel, kind)) = parse_unit(unit) else {
            p.o.taints.push(format!("cargo: {unit:?} is not a unit id"));
            p.o.result = Some(unit_result("", false, 0));
            p.block = format!("vci: {unit:?} is not a cargo unit\n").into_bytes();
            return Ok(p);
        };
        let doc = kind == UnitKind::Doc;
        let mut retried = false;
        loop {
            let tmp = match tempfile::Builder::new().prefix("vci-cargotmp-").tempdir() {
                Ok(t) => t,
                Err(e) => {
                    let msg = format!("creating a temporary directory for the build: {e}");
                    p.block
                        .extend_from_slice(format!("vci: {unit}: {msg}\n").as_bytes());
                    p.o.taints.push(format!("cargo: {msg}"));
                    p.o.result = Some(unit_result("", false, 0));
                    p.step = Step::Done { code: Some(101) };
                    return Ok(p);
                }
            };
            let mut cmd = self.cargo_cmd(env);
            cmd.args(["test", "--locked", "--manifest-path"])
                .arg(manifest_arg(&pkg_rel))
                .args(kind.selector());
            if !doc {
                cmd.arg("--no-run");
            }
            cmd.arg("--message-format=json")
                .arg("--target-dir")
                .arg(ctx.target_dir.as_str())
                .env("TMPDIR", tmp.path());
            let started = std::time::Instant::now();
            let out = cmd.output().map_err(|e| self.not_installed("cargo", e))?;
            let elapsed = started.elapsed().as_millis() as u64;
            let stdout = String::from_utf8_lossy(&out.stdout);
            let (arts, runs, text) = split_messages(&stdout);
            p.block.extend_from_slice(
                format!(
                    "vci: {} (exit {})\n",
                    describe(&cmd),
                    out.status
                        .code()
                        .map_or_else(|| "signal".to_owned(), |c| c.to_string())
                )
                .as_bytes(),
            );
            p.block.extend_from_slice(&out.stderr);
            p.block.extend_from_slice(text.as_bytes());
            if collect {
                // A crate of the repository vci did not clean at the start
                // of the run (a path dependency outside the workspace, a
                // crate vendored in the repository) and that cargo reused:
                // clean it and build the unit again, once.
                let reused = self.reused_repo_packages(&arts, ctx);
                if !reused.is_empty() && !retried {
                    retried = true;
                    p.block.extend_from_slice(
                        format!(
                            "vci: cargo reused {} from an earlier build; rebuilding it and running {unit} again\n",
                            reused
                                .iter()
                                .map(|(n, v)| format!("{n}@{v}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                        .as_bytes(),
                    );
                    p.block.extend(self.clean(&reused, env, ctx)?);
                    continue;
                }
                // The rustc cargo actually built with; `vci run` refuses the
                // unit if it is not the one probed (and recorded in the
                // toolchain).
                if let Some(used) = rustc_used(&ctx.target_dir) {
                    p.o.runner_version = used;
                }
            }
            p.step = if doc || !out.status.success() {
                Step::Ran {
                    code: out.status.code(),
                    text,
                    elapsed,
                }
            } else {
                match self.exec_spec(&pkg_rel, &kind, &arts, &runs, env, ctx) {
                    Ok(spec) => Step::Exec(spec),
                    Err(e) => {
                        p.block
                            .extend_from_slice(format!("vci: {unit}: {e}\n").as_bytes());
                        p.o.taints.push(format!("cargo: {e}"));
                        Step::Ran {
                            code: Some(101),
                            text: String::new(),
                            elapsed: 0,
                        }
                    }
                }
            };
            p.arts = arts;
            p.runs = runs;
            return Ok(p);
        }
    }

    /// How to run the unit's test executable: the one its own build
    /// reported, with what `cargo test` adds to the environment.
    fn exec_spec(
        &self,
        pkg_rel: &str,
        kind: &UnitKind,
        arts: &[Artifact],
        runs: &[BuildRun],
        env: &ChildEnv,
        ctx: &RunCtx,
    ) -> Result<exec::Spec, String> {
        let pkg = ctx
            .member(&self.project_dir, pkg_rel)
            .ok_or_else(|| format!("no workspace member has the package directory {pkg_rel}"))?;
        let manifest = Utf8PathBuf::from(&pkg.manifest_path);
        let dir = manifest
            .parent()
            .ok_or_else(|| format!("{manifest} has no directory"))?
            .to_owned();
        let pkg_dir = ctx.canon(&dir);
        let own: Vec<&Artifact> = arts
            .iter()
            .filter(|a| {
                a.manifest_path
                    .parent()
                    .is_some_and(|d| ctx.canon(d) == pkg_dir)
            })
            .collect();
        let unit = own
            .iter()
            .find(|a| is_unit_target(a, kind))
            .ok_or_else(|| {
                format!(
                    "the build of {pkg_rel}#{} reported no test executable for it",
                    kind.id()
                )
            })?;
        let exe = unit.executable.clone().expect("is_unit_target checks it");
        // Integration tests and benches: the package's binaries.
        let bins = if matches!(kind, UnitKind::Test(_) | UnitKind::Bench(_)) {
            own.iter()
                .filter(|a| !a.test_profile && a.kind.iter().any(|k| k == "bin"))
                .filter_map(|a| Some((a.target_name.clone(), a.executable.clone()?)))
                .collect()
        } else {
            vec![]
        };
        let script = runs.iter().rev().find(|r| r.package_id == unit.package_id);
        // rustup's toolchain (the probe's) for the proxy's library
        // directory; the rustc cargo built with for the sysroot's (cargo
        // started by rustup's proxy can find another rustc on PATH).
        let sysroot = &ctx.probe.sysroot;
        let used_sysroot = rustc_sysroot(&ctx.target_dir).unwrap_or_else(|| sysroot.clone());
        let te = exec::TestEnv {
            cargo_exe: ctx.cargo_exe.0.clone(),
            pkg: pkg.fields(),
            bins,
            out_dir: script.map(|r| r.out_dir.clone()),
            script_env: script.map(|r| r.env.clone()).unwrap_or_default(),
            linked_paths: runs
                .iter()
                .flat_map(|r| r.linked_paths.iter().cloned())
                .collect(),
            root_output: ctx.target_dir.join("debug"),
            sysroot_libdir: used_sysroot
                .join("lib/rustlib")
                .join(&ctx.probe.versions.rust_host)
                .join("lib"),
            rustup_lib: ctx.cargo_exe.1.then(|| sysroot.join("lib")),
            config_env: ctx.config_env.clone(),
            proxy_env: ctx.proxy_env.clone(),
        };
        let var = |k: &str| Self::child_var_raw(env, k);
        Ok(exec::Spec {
            exe,
            cwd: dir,
            vars: te.vars(std::env::consts::OS, &var),
        })
    }

    /// The execution pool's part of one unit: run it. Returns what is left
    /// to analyse, with the exit code `cargo test` would have had (101 for a
    /// failed test executable, whatever its own status), and the unit's
    /// output.
    fn execute(p: Prepared, env: &ChildEnv) -> (Ran, Vec<u8>) {
        let Prepared {
            mut o,
            arts,
            runs,
            mut block,
            step,
            ..
        } = p;
        let code = match step {
            Step::Done { code } => {
                let ran = Ran {
                    code,
                    o,
                    arts,
                    runs,
                    analyse: false,
                };
                return (ran, block);
            }
            Step::Ran {
                code,
                text,
                elapsed,
            } => {
                o.result = Some(unit_result(&text, code == Some(0), elapsed));
                code
            }
            Step::Exec(spec) => match exec::run(&spec, env) {
                Ok(r) => {
                    block.extend_from_slice(r.header.as_bytes());
                    block.extend_from_slice(&r.stderr);
                    block.extend_from_slice(r.stdout.as_bytes());
                    o.result = Some(unit_result(&r.stdout, r.success, r.elapsed_ms));
                    if r.success { Some(0) } else { Some(101) }
                }
                Err(e) => {
                    let msg = format!("cannot run the test executable {}: {e}", spec.exe);
                    block.extend_from_slice(format!("vci: {msg}\n").as_bytes());
                    o.taints.push(format!("cargo: {msg}"));
                    o.result = Some(unit_result("", false, 0));
                    Some(101)
                }
            },
        };
        let ran = Ran {
            code,
            o,
            arts,
            runs,
            analyse: true,
        };
        (ran, block)
    }
}
