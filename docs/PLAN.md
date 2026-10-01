# Plan: `vci` — cryptographically verifiable CI executor (Rust)

## Context

Goal: if a developer or agent runs test file B locally, CI should only need to run A, C, D. To make that safe, each client signs an attestation of *what it ran against which exact file contents*, and CI verifies the signature, recomputes the hashes from its own checkout, and skips only what is provably covered.

Research findings that shape the design:

- Turborepo, moon, Nx and Bazel hash task inputs and cache results, but trust is a writer allowlist. Turborepo's signing is a shared HMAC key; Bazel says "only CI writes"; Nx's CVE-2025-36852 showed the cost of untrusted cache writers.
- Closest prior art is `fredericrous/attest` (SSH-signed git notes over the whole tree hash). Any change invalidates everything. Our differentiator is **per-test-file input sets**.
- Static import graphs miss computed imports, fixture reads and env vars. Safe selection needs runtime-recorded dependencies (Ekstazi-style), at test-file granularity.
- A signature proves who made a claim, not that the test ran. v1 accepts this.

Decisions made: TypeScript + Vitest first; SSH keys + `allowed_signers`; git custom refs for transport; signature + policy only (no spot-check re-runs yet).

Core rule: **fail open**. Default verdict is RUN. Any error, doubt or unrecognized behaviour means the test runs.

## Layout

Empty directory today; `git init` first.

```
Cargo.toml                 workspace
crates/vci-core/           repo paths, input manifest, input root hashing
crates/vci-attest/         in-toto Statement, DSSE + PAE, SSHSIG verify, allowed_signers parser, ssh-keygen signer
crates/vci-git/            attestation storage on git-meta, base-branch file reads, repo identity (shells out to git)
crates/vci-adapter/        Adapter trait + Vitest adapter (spawn, parse JSONL)
crates/vci-cli/            binary `vci`
js/vitest-plugin/          npm package @vci/vitest (collectors)
fixtures/vitest-abcd/      end-to-end fixture project
```

Key crates: `ssh-key 0.6.7`, `blake3`, `sha2`, `clap`, `serde`/`serde_json`, `base64`, `camino`, `rayon`, `jiff`, `thiserror`, `anyhow`; dev: `assert_cmd`, `insta`, `tempfile`. Git via the `git` CLI, not `gix`.

## CLI

| Command | Purpose |
|---|---|
| `vci init` | Write `vci.toml`, `.vci/allowed_signers`, install JS package, print CI snippet |
| `vci run [FILES…] [--key PATH] [--ttl 14d]` | Run tests, collect inputs, sign, store attestation |
| `vci plan [--base-ref R] [--format json\|text\|github]` | Emit `skip` and `run` lists |
| `vci ci [--base-ref R]` | Plan, then run the remainder; write audit log of skips |
| `vci verify <envelope>` | Verify one attestation |
| `vci push` / `vci fetch` | git-meta push / pull of the attestations |
| `vci explain <test-file>` | Show which check failed for each candidate |

## Dependency collection (JS package)

The Rust CLI generates a wrapper Vitest config in a temp dir that merges the user's config with the `@vci/vitest` plugin, so users don't edit their config. JS emits **paths only**; Rust does all hashing.

Three collectors, keyed by test file, requiring `isolate: true`:

1. **Main process**: walk the Vite module graph from the test module at `onTestModuleEnd` (source files are transformed here).
2. **Worker preload** (`--import`): `module.registerHooks()` records externals and failed resolutions.
3. **Worker setup file**: patch `fs`/`fs/promises` (reads, stats, readdir, including misses), proxy `process.env`, and patch `child_process`, `net`, `http(s)`, `fetch`, `worker_threads` to mark the file **tainted** (never attestable).

Output: one JSONL file per test file with records of kind `meta`, `module`, `external`, `read`, `probe`, `readdir`, `env`, `taint`, `result`.

Always-included global inputs: lockfile, `package.json`, tsconfig chain, Vitest config, setup files, snapshot files, `vci.toml`.

`node_modules` is represented by lockfile hash + resolved package versions, not per-file hashes.

Non-attestable cases: `isolate: false`, `vmThreads`/browser pools, experimental module cache or native runner modes, reads outside the repo, snapshot writes during the run, any taint.

Supported Vitest: `>=3.2 <6`, developed against 5.0.x, 4.1.x in the test matrix.

## Data model

- **InputEntry**: repo-relative path, kind (`File`, `Symlink`, `Absent`, `DirListing`), executable bit, size, BLAKE3 hash.
- **Input root**: BLAKE3 over a domain tag plus length-prefixed, path-sorted entries, externals and env hashes.
- **Paths**: canonicalized, repo-relative, `/` separators, no `..`, byte-exact. Case-fold collisions make the file non-attestable.
- **Predicate** (`predicateType` custom, modeled on in-toto test-result): tool version, adapter, test id, canonical per-file argv, repo id (root commit), commit (informational), toolchain (node, vitest, vite, os, arch), global input root, input root, full manifest, result, `issued_at`, `expires_at`.
- **Envelope**: DSSE with `payloadType: application/vnd.in-toto+json`. Signature is SSHSIG over the PAE bytes, namespace `vci-attest`. Signing shells out to `ssh-keygen -Y sign` (supports agent and hardware keys); verification is pure Rust. Stored payload bytes are verified as-is, never re-serialized.

## Verification (`vci plan`)

1. Read `.vci/allowed_signers` and `vci.toml` from the **base commit** via `git show`. Missing means run all.
2. List test files via `vitest list --filesOnly --json`.
3. Compute global input root and toolchain digest.
4. Per test file, per candidate envelope, check in order: envelope shape; SSHSIG and namespace; signer in base `allowed_signers` (honouring `namespaces=`, `valid-after`, `valid-before`; `cert-authority` rejected in v1); not expired and TTL within policy; repo id, test id, argv, toolchain match; result passed and untainted; every manifest entry rehashed from checkout and root matches; env hashes match.
5. First fully passing candidate gives SKIP; otherwise RUN with the first failing check recorded for `explain`.

## Git storage (git-meta)

Content-addressed, so attestations survive rebases and apply across branches. Superseded the original
`refs/attest/v1/<signer>` design: attestations are [git-meta](https://git-meta.com/) metadata, so vci has no storage
format, database or ref layout of its own.

- Target `path:<unit path>` (`project` for `.` and paths under 3 bytes); key
  `vci:attestation:<blake3(test_id)>:<signer>:<storage_key>`; value the DSSE envelope.
- Different signers and different inputs write different keys; git-meta's three-way (and baseless two-way) merge keeps
  keys added on either side. The same signer re-attesting the same inputs rewrites one key.
- `vci push` / `vci fetch` follow `git meta push` / `git meta pull` on `refs/meta/main`, and interoperate with them.
  They first make the SQLite store cover the shared `refs/meta/local/main` (worktrees, lost stores), refuse any
  serialization or push that drops a value without a deletion record, leave out tree entries git-meta cannot read, and
  warn about shared auto-prune and filter settings (README, "What `vci fetch` and `vci push` guard against").
- CI: `vci fetch --remote origin` (configures the git-meta remote and materializes `.git/git-meta.sqlite`) plus the
  base SHA.

## Decision flagged for review: cross-platform skips

Strict OS/arch equality would mean a macOS laptop can never satisfy Linux CI, which defeats the main use case. Plan: `vci.toml` policy `platform = "any" | "same-os" | "exact"`, **default `any`**, with a per-glob override to force `exact` for platform-sensitive tests. Node major version and lockfile must always match. Change the default at approval time if you want it stricter.

## Threat model (v1)

Protected: forged or tampered attestations; untrusted signers, including a PR adding its own key; replay across repos, tests, toolchains or after expiry; stale inputs.

Not protected: a trusted signer lying or a stolen key; inputs the collectors can't see (native addons, time, locale); test code deliberately evading collectors; malicious `node_modules` matching the lockfile. Policy can disable skips on the default branch and release refs.

## Milestones

| # | Deliverable | Verified by |
|---|---|---|
| M0 | Spike: do computed `import()` calls appear in the Vite graph? externals coverage? worker preload injection? on Vitest 4.1 and 5.0 | Written findings in `docs/spike.md`; fallback (wrap module runner fetch) chosen if needed |
| M1 | `vci-core` | Unit + golden tests for paths and input root |
| M2 | `vci-attest` | Round trip against `ssh-keygen -Y verify`; tamper tests |
| M3 | `@vci/vitest` + fixture | Snapshot of JSONL records for A–D |
| M4 | `vci run` | Signed envelope produced for B |
| M5 | `vci-git`, `push`/`fetch` | Two clones against a bare remote |
| M6 | `plan`, `explain`, `ci` | End-to-end recipe below |
| M7 | `init`, GitHub Actions example, README | Workflow file reviewed; docs |

## End-to-end verification

Fixture: B reads `fixtures/b.json`; C does a computed `import('./impl-' + name + '.ts')`.

1. `vci run src/b.test.ts` then `vci plan` → skip B; run A, C, D.
2. Edit `fixtures/b.json` → B runs; `explain` names the file and both hashes.
3. `vci run src/c.test.ts`, edit `impl-x.ts` → C runs (proves computed imports are tracked).
4. Flip a byte in the payload → rejected at signature check.
5. Sign with a key not in `allowed_signers` → rejected.
6. Add that key to `allowed_signers` on the PR branch only → still rejected.
7. Create a file that was previously probed as absent → B runs.
8. Edit a file only A depends on → B still skipped.

Automated as an `assert_cmd` integration test using throwaway SSH keys generated in a temp dir and a local bare git remote. Also `cargo test --workspace`, `cargo clippy`, and the JS package's own tests.

## Risks

- Collector completeness is the central risk; M0 gates M3.
- `fs` patching can miss bindings captured before the setup file runs; the preload reduces but doesn't eliminate this.
- `module.registerHooks()` is release-candidate and needs Node 22.15+.
- Vitest 5 experimental module modes are treated as non-attestable until studied.
- Attestation metadata grows; `vci prune` tombstones expired entries.
- Spot-check re-runs and transparency logs are later work. The pytest adapter exists (`crates/vci-adapter/src/pytest.rs`,
  collector in `py/pytest-plugin`, findings in `docs/spike-pytest.md`); `vci.toml` can hold several projects
  (`[[projects]]`), e.g. a Vitest and a pytest project in one repository. The Go adapter
  (`crates/vci-adapter/src/golang/`, findings in `docs/spike-go.md`) attests packages: `go list -deps -test` for
  compile-time inputs, and package os's test log, installed from package initialisation on by overlaying a file
  into the standard library's `internal/testlog`, for run-time inputs. The Cargo adapter (`crates/vci-adapter/src/cargo/`,
  findings in `docs/spike-cargo.md`) attests cargo test targets (`<package dir>#lib|doc|bin:<n>|test:<n>`); Rust has
  no run-time hook, so its inputs are every file of the package directories of the repository crates the unit builds,
  rustc's dep-info, build script declarations, `Cargo.lock` entries and `[[inputs]]` declared in vci.toml, and static
  source checks refuse processes, sockets, native code and undeclared reads (a weaker guarantee than the observed-input
  adapters, documented in the README). The Rails adapter (`crates/vci-adapter/src/rails.rs`, collector in
  `ruby/vci-collector`, findings in `docs/spike-rails.md`) attests Minitest test files, one `bin/rails test <file>`
  process each: a plain-Ruby collector loaded through `RUBYOPT` wraps Ruby's file, directory, `ENV`, require and
  process entry points (Ruby has no audit hook), records Zeitwerk's directory listings and the loaded gems (checked
  against their cached archives), and redirects the test environment's SQLite databases to fresh files loaded from the
  schema for every file; database servers need `policy.rails_allow_db`.

## Environment variables

See `docs/ENV.md`. It is part of the design: `vci.toml` `[env]` config with strict/loose mode, declared and pass-through patterns, hashed into each test file input root and checked in `vci plan`.
