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
  cannot be split for doctests. The adapter runs each unit once with `--message-format=json`: cargo's messages are
  single-line JSON objects with a `reason` key on stdout, the test harness's output is everything else.

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
- One `cargo test` holds the build directory lock for its whole run, so units run one at a time.
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

