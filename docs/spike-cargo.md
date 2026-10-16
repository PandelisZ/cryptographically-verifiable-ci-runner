# Cargo adapter: findings

Checked on macOS arm64 with Homebrew's Rust 1.96.0 (`rustc 1.96.0 (ac68faa20 2026-05-25)`, `cargo 1.96.0
(30a34c682 2026-05-25)`) and rustup's 1.95.0, against a scratch workspace like `fixtures/cargo-abcd` and a copy of
vci's own workspace. These are the behaviours the adapter (`crates/vci-adapter/src/cargo/`) relies on.

## No run-time hook

Unlike Node (fs patching), CPython (audit hooks) and Go (package os's test log), a Rust test binary offers no place to
observe file opens, environment lookups or process starts without an `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` shim or a
tracer, both platform-specific and defeated by static linking or SIP. The adapter therefore does not observe run time
at all. Its inputs are an over-approximation (every file of the package directories of the repository crates a unit
builds) plus what the build reports, and static source checks refuse what that cannot cover. This is weaker than the
other adapters; the README says so.

## Units and listing

- `cargo metadata --format-version 1 --no-deps` lists every workspace member's targets with `kind`, `test`,
  `doctest` and `required-features`. That is enough to reproduce what `cargo test --workspace` runs: lib-like targets
  with `test = true` (unit tests) and `doctest = true` (doctests), `bin`/`test` targets with `test = true`
  (the default), examples and benches only with `test = true`, and only targets whose `required-features` are on by
  default.
- Full `cargo metadata` (with dependencies) downloads the manifest of every package of the resolve, for every
  platform: on vci's own workspace it failed offline (`failed to download curve25519-dalek-derive v0.1.1 ... --offline
  was specified`) although everything needed for this host was cached. The adapter never needs it: the build's own
  JSON messages carry each package id and `manifest_path`.
- `cargo test --doc --no-run` is an error (`error: can't skip running doc tests with --no-run`), so build and run
  cannot be split for doctests. Cargo's messages are single-line JSON objects with a `reason` key on stdout, the test
  harness's output is everything else. Until v2 the adapter ran each unit once with `--message-format=json`; it now
  builds other units with `--no-run` and runs their executables itself (see
  [Parallel execution (v2)](#parallel-execution-v2-2026-10-16)), and `#doc` units as before.

## What a build reports

- `compiler-artifact` messages are emitted for every crate of the unit's build graph, `"fresh": true` included, with
  `package_id` (`path+file:///w/a#0.1.0`, `path+file:///w/e#name@0.1.0` when the directory is not the package name,
  `registry+https://github.com/rust-lang/crates.io-index#hex@0.4.3`), `manifest_path`, `target.kind` (`lib`,
  `custom-build`, `proc-macro`, `test`, `bin`), `features` and `filenames`. `cargo test --doc` reports the libraries
  (non-test profile) the doctests link.
- `build-script-executed` carries `out_dir`, `linked_libs`, `linked_paths`, `cfgs`, `env`, but not the
  `rerun-if-*` directives; those are in the script's stdout, saved as `<out_dir>/../output` (both `cargo:` and
  `cargo::` spellings).
- rustc's dep-info sits next to each artifact: `deps/<crate>-<hash>.d` for `deps/lib<crate>-<hash>.rlib` and for test
  executables `deps/<crate>-<hash>`, `build/<pkg>-<hash>/build_script_build-<hash>.d` for build scripts. Every
  dependency has a phony rule `path:`; paths of workspace members and of path packages under the workspace root are
  relative to the workspace root (`c/src/../../shared/c.txt`), others absolute. `include_str!` targets and
  `OUT_DIR` files appear; `# env-dep:OUT_DIR=<path>` and `# env-dep:B_FLAG` (an unset `option_env!`) list the
  variables `env!`/`option_env!` read.
- A build script that prints `cargo::rerun-if-changed=../shared/c-build.txt` records exactly that path (relative to
  its package directory).

## Running tests

- `cargo test` runs test binaries (and doctests) with the package directory as working directory, so relative reads
  (`tests/data/b.json`) resolve there.
- libtest's summary is stable text: `test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out;
  finished in 0.00s`. Edition 2024 merges doctests and prints one summary followed by `all doctests ran in ...`.
  A target without tests prints `0 passed`; a `harness = false` target prints whatever it wants.
- One `cargo test` holds the build directory lock for its whole run, build and tests, so two `cargo test` calls never
  run at once; v2 builds with `--no-run` and runs the test executables outside cargo.
- `rustc --print cfg --target x86_64-unknown-linux-gnu` works without that target's standard library installed, which
  the e2e test uses to check what a Linux runner would decide about an attestation's cfg predicates.

## Toolchain identity

- `rustc -vV` gives `release`, `commit-hash`, `host` and `LLVM version`; `cargo -vV` gives `release` and
  `commit-hash`. Homebrew's 1.96.0 reports `LLVM version: 22.1.6` (Homebrew's LLVM); rustup's 1.95.0 reports
  `22.1.2` (its bundled fork). With rustup's proxy and `RUSTUP_TOOLCHAIN=1.95.0`, `vci explain` shows both the rustc
  and cargo mismatch (`crates/vci-cli/tests/e2e_cargo.rs`, `cargo_other_toolchain_runs`).
- The rustc a build uses is the one next to the cargo binary (rustup proxies, distribution packages) unless `RUSTC` or
  `build.rustc` says otherwise; a different `rustc` earlier on PATH is not it.

## Environment of this machine

- `CARGO_TARGET_DIR` was set globally (outside every repository). Both layouts work: the e2e tests unset it (target
  dir inside the repository, which `vci run` must not snapshot or hash), the vci self-test sets it.
- On vci's own workspace, a cold build of `vci-core`'s and `vci-git`'s test targets into a fresh `target/vci` took
  about a minute; `vci-core#lib` (65 tests) is attested, and every other unit is refused by the process check
  (`vci-git` runs `git`, `vci-attest` runs `ssh-keygen`, `vci-adapter` and the `vci-cli` tests run tools) or has no
  tests (`#doc` units).

## Freshness and caches (adversarial findings)

- `compiler-artifact` messages carry `"fresh": true` when cargo reused an artifact. Cargo's fingerprint for a path
  package is its files' modification times plus what its build script declares (`rerun-if-changed`,
  `rerun-if-env-changed`); an edit restored with an older mtime, a file a build script reads without declaring it, or
  a variable a build script or proc macro reads without declaring it, left a stale artifact `fresh`. vci now runs
  `cargo clean -p <member>...` in its target subdirectory before a run (about as fast as a no-op; `-p name@version`
  prints "version qualifier ... is ignored, cleaning all versions", so vci passes names), and refuses a repository
  artifact that is `fresh` without having been built in the run.
- A registry or git package's fingerprint is its package id, not its files: an extracted crate in
  `$CARGO_HOME/registry/src` or a checkout in `$CARGO_HOME/git/checkouts` edited in place is compiled as if it were the
  pinned version. The `.crate` archive stays in `$CARGO_HOME/registry/cache/<index>/<name>-<version>.crate` (its
  SHA-256 is the Cargo.lock checksum; `tar -xzf` extracts `<name>-<version>/`, and cargo adds `.cargo-ok`); git
  checkouts are real git worktrees with a `.git` directory and a `.cargo-ok` file.
- A `[source]` directory replacement serves a crate from any directory with a `.cargo-checksum.json`; with
  `"files": {}` cargo checks nothing but the package checksum it is told.
- A `[target.'cfg(..)']` or `[target.<triple>]` table in the repository's `.cargo/config.toml` applies its
  `rustflags` (and `runner`, `linker`) only where it matches; `rustc --print cfg` does not see config flags unless they
  are passed to it.

## Parallel execution (v2, 2026-10-16)

Checked with cargo 1.96.0 (Homebrew's and rustup's) on macOS arm64, against the fixtures of
`crates/vci-cli/tests/e2e_cargo.rs`, a probe crate and vex (a workspace of 26 members, 242 units, 955 packages). The
code is `crates/vci-adapter/src/cargo/lane.rs` and `exec.rs`.

**Why.** With one `cargo test` per unit, build and tests of every unit ran one after another, and each unit's analysis
walked package directories, parsed dep-info and scanned sources again. On vex, 4 small units took 83 s with a warm
`<target>/vci`, 23 s of it inside cargo; most of the rest was the repository snapshot, which walked 5.4 M entries of
nested git worktrees (now skipped, a separate change in `crates/vci-cli/src/treestat.rs`).

**Splitting build and run.**

- `cargo test --no-run --message-format=json` reports, for each test harness, a `compiler-artifact` with
  `profile.test: true` and an `executable`; bins have one too (`profile.test: false`). The unit's executable is the
  artifact of the unit's package with `profile.test: true` and the unit's target kind and name (`lib`-like kinds for
  `#lib`). Running it directly, with no arguments, in the package directory, gives the same libtest output as
  `cargo test`. `cargo test` exits 101 when a test executable fails, whatever the executable's own status.
- Doctests still cannot be split (`--doc --no-run` is an error), so `#doc` units run `cargo test --doc` in the lane.

**What `cargo test` sets for a test process.** A probe test that dumps its environment was run under `cargo test` and
directly by vci, and the two dumps compared (cargo's own code: `fill_env` and `target_process` in
`core/compiler/compilation.rs`):

- `CARGO`, `CARGO_MANIFEST_DIR`, `CARGO_MANIFEST_PATH`, every `CARGO_PKG_*` field (`CARGO_PKG_VERSION_PRE` empty when
  there is none; `CARGO_PKG_AUTHORS` joined with `:`), `OUT_DIR` and the `cargo::rustc-env` variables of the package's
  build script, `CARGO_BIN_EXE_<name>` (integration tests and benches only), and the `[env]` table of the cargo
  configuration (an existing variable wins unless `force = true`; `relative = true` is resolved against the directory
  holding `.cargo`).
- `CARGO_CRATE_NAME` and `CARGO_TARGET_TMPDIR` are not set for the test process: they are compile-time variables
  (`env!`). The design had assumed both.
- `CARGO` is `$CARGO` when set, else the cargo binary that runs: under rustup's proxy that is the toolchain's own cargo
  (`<sysroot>/bin/cargo`), not `~/.cargo/bin/cargo`. Linux reports the resolved path, macOS the path cargo was
  started by.
- The library search path (`DYLD_FALLBACK_LIBRARY_PATH` on macOS, `LD_LIBRARY_PATH` on Linux, `PATH` on Windows) is,
  in order: the build scripts' `rustc-link-search` directories that are inside the build's profile directory (cargo
  drops the others), `<target>/debug`, `<target>/debug/deps`, `<sysroot>/lib/rustlib/<host>/lib`, then the existing
  value, or macOS's defaults (`$HOME/lib`, `/usr/local/lib`, `/usr/lib`) when it was empty. The sysroot is the one of
  the rustc cargo actually used, which `<target>/.rustc_info.json` records: started through rustup's proxy, cargo can
  find another rustc than the one vci probed.
- rustup's proxy adds, for the cargo it starts and so for the tests: `<sysroot>/lib` in front of the library search
  path, and `CARGO_HOME`, `RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`, `RUSTUP_TOOLCHAIN_SOURCE`, `RUST_RECURSION_COUNT`. vci
  reads them once per run by running `cargo vci-proxy-env`, an external subcommand (a script put first on `PATH`)
  that prints the environment cargo gives it.
- After that, the only differences between the two dumps were vci's own: the variables its policy removes, the fresh
  `TMPDIR`, `VCI_JS_PLUGIN` (set by Homebrew's `vci` wrapper) and `__CF_USER_TEXT_ENCODING` (macOS adds it in cargo's
  process).

**Fresh checks after a warm-up.**

- After a warm-up build, a unit's own `cargo test <unit> --no-run` finds its artifacts `fresh` only when the warm-up
  resolved features the same way. A build of several packages (`--workspace`, or `-p a -p b`) unifies their
  dependencies' features; the unit alone does not, and cargo compiles what differs again. On vex, with a warm-up
  `-p vex-cache -p vex-overlay -p vex-testkit -p vexd`, vex-overlay's `events` test was `events-1efc091704dde7fa`
  after the warm-up and `events-da16f7451a01949d` from the unit's own build, although vex-overlay's own features were
  `[]` in both; the six units' builds compiled vex-cache, vexd and vex-overlay (once per test) again. In the e2e test
  `cargo_warm_up_unifies_features_like_the_units` (`fb` enables `fa/x`), `fa#lib`'s build printed `Compiling fa`
  again after such a warm-up. The warm-up is therefore one `cargo test --no-run --manifest-path <pkg>/Cargo.toml` per
  package, the selection the units use; then the units' builds compile nothing in that test. This costs the
  parallelism across packages and has not been measured on vex yet.
- A repository crate reported `fresh` in a unit's build after the warm-up built it in this run is not "reused": vci
  cleaned it at the start of the run. The reused-crate rule still applies to the warm-up, once per package: on vex the
  warm-up found `jj-lib-proc-macros`, `jj_backend_api`, `jj_backend_types` and `jj_diff` reused, cleaned them and
  built again; `jj-lib` was then found reused only by `vex-testkit#test:remote_lazy_fetch`'s own build, which cleaned
  it and recompiled 5 crates (jj-lib, vex-jj, vex-remote, vexd, vex-testkit) in the lane. The unit's own retry is what
  catches such a crate.
- On 6 vex units (with the multi-package warm-up above): 39.6 s against 109.4 s for vci 1.7.1 with the dependencies
  built (182.0 s cold), on a 14-CPU Mac with a load average of 12 to 43 from other builds. About 23 s warm-up, 7 s for
  the six units' own builds, 6 s for running, analysing and signing. The same three units were attested by both, with
  byte-identical attestations. A run of all 242 units filled the disk during the warm-up (`No space left on device`
  from rustc); it then ended the whole run, which is now handled per unit (a failed temporary directory skips the
  warm-up, or refuses that unit).

**Deriving a unit's crates from `cargo metadata` (rejected).** One `--workspace` build could serve every unit if each
unit's crates came from the dependency closure in `cargo metadata`'s resolve instead of the unit's own build. For
`vexd#lib`, the closure with `--filter-platform aarch64-apple-darwin` (normal and build edges, plus vexd's
dev-dependencies) has 397 packages; `cargo tree -p vexd -e normal,build,dev` (features resolved for vexd alone) has 294.
The other 103 come from features the resolve turns on for the whole workspace: jj-lib's optional `git` feature
(`gix` and its family) and rustls' `aws-lc-rs` among them. Both sets have the same 16 repository crates. (An earlier
count, 243 packages built including five unrelated repository crates, came from a `cargo test` of `vexd#lib` that
stopped with `No space left on device`, so it counted only what had compiled; it is not a valid comparison.) Rejected
because the closure is not what the unit builds: it records external crates the unit does not compile, so their
changes would re-run it, and the attestation must describe the unit's own build, with the analysed artifacts and the
executed binary coming from the same cargo invocation.

**Analysis.** Each unit is analysed once every test of the run has run, in parallel, with run-wide caches: canonical
paths, directory walks (one per directory, a unit taking the union of its walks; recorded paths are canonical, so the
result is the one a single walk gave), dep-info, source scans (per file, roles and package), manifest scans and the
registry and git source checks. Generated files under the target dir and build-script `output` files are never cached:
the lane can rebuild them during the run. Analysing after every test, rather than right after each unit's test, keeps a
package directory shared by several units from being walked before one of their tests changed it.
