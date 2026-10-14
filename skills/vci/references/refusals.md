# Refusals and failed checks

Two different things stop a skip:

1. **`vci run` refuses to attest** a unit: `vci: not attesting <unit>: <reason>`. No attestation is stored; CI will run
   the unit. The tests may still have passed.
2. **`vci plan` / `vci explain` reject an attestation**: `RUN <unit> (no valid attestation (N candidates; best failed
   <check>: ...))`. An attestation exists but does not match this base commit, checkout, toolchain or policy.

Both fail open: the worst outcome is that CI runs the unit. Never "fix" either by weakening policy, editing
`.vci/allowed_signers`, deleting tests, or adding skips; report the reason to the user.

## `vci run`: "not attesting <unit>: ..."

| Reason (prefix) | Meaning | What to do |
|---|---|---|
| `result failed (F failed, S skipped or xfailed of N; ...)` | A test failed or was skipped/xfailed/pending | Fix the code (or the test, if the user agrees) and run again. Never attest around a failure. A skip is refused because the skipped test did not run |
| `result no-tests (...)` / `result filtered (...)` | No test ran, or only some (focus, `-k`, tag filters, `--only-failures`, `TestMain` filtering) | Remove the filter; every test in the unit must run |
| `result no-assertions (...)` | Minitest test without an assertion | Add assertions or leave it unattested |
| `tainted: <process event>`: `subprocess.Popen`, `os.system`, `os.fork` (pytest), `child_process...` (Vitest), `exec: <program>` (Go), `process:backtick`, `process:fork`, `process:system` (Rails), `cargo:process...` | The test (or its setup/config) started a child process, whose reads vci cannot see | Not attestable; CI runs it |
| `tainted: <network event>`: `socket.connect`, `socket.getaddrinfo` (pytest), socket/`fetch` taints (Vitest), `go:net:...` (Go: package `net` in the closure), network crates (Cargo), `network:...`, `rails:network-db:...` (Rails) | Sockets, HTTP, DNS, a database server | Not attestable. The `go_allow_net` / `rails_allow_db` waivers exist but are the user's policy decision on the default branch |
| `tainted: env:enumerated` (or a recorded env key `*`) | The test read the whole environment (`dict(os.environ)`, `process.env` spread, `ENV.to_h`, `env::vars()`) | Read specific variables instead, if the user agrees |
| `tainted: native:...`, `ctypes.dlopen:...`, `go:cgo...`, `go:syscall:...`, `cargo:native...`, `vci:not-hooked:...` | Native code that can open files unseen (cgo, FFI, `ctypes`, extensions in the repo, libxml2 options) | Not attestable |
| `tainted: pytest:...` (`--lf`, `xdist`, `reruns`, `random-order`, `no-config-file`, `plugin-imported-before-collector:...`, `partial-file-selection`), `sqlite3:...`, `multiprocessing:...` | A pytest mode that hides inputs or selects part of a file | Run whole files without those options |
| `tainted: rspec:...` (`filtered`, `retry`, `failure-cleared`, `status-mismatch`, `option-files`, `invocation`, `parallel-tests`) | RSpec ran filtered, retried, or outside vci's options | Remove focus/tag filters, rspec-retry, parallel_tests from the run |
| `tainted: ruby:file-metadata:...` | Read mtime/mode/owner of a repository file | Not reproducible on a checkout; not attestable |
| `tainted: vci:process-exit:N` | The process exited non-zero after the framework reported success (SimpleCov `minimum_coverage`, an `at_exit`) | Fix the exit status or leave it unattested |
| `tainted: cargo:undeclared-reads` / `its source refers to <path> (...), which is not an input; declare it in vci.toml ([[inputs]] ...)` | A Rust test reads a file outside its package directories | Ask the user to declare it under `[[inputs]]` in `vci.toml` and merge that to the default branch |
| `cargo:path-case` | A path literal differs in letter case from the file | Fix the path's case |
| `wrote inside the repository: <paths>` | The test created, changed or deleted files in the repo | Write to a temp dir (`tmp_path`, `t.TempDir()`, `TMPDIR`) instead |
| `input outside the repository: <path>` | A read outside the repo (`/etc/hosts`, `~/...`, an unowned temp file) | Not attestable unless the test stops reading it |
| `input changed during the run: ...` / `global inputs changed during the run` / `the repository changed during the run: ...` (Go) | Something modified the working tree while tests ran (an editor, a formatter, a watcher, another process, the test itself) | Stop other writers and run again |
| `env mode "loose": the cargo adapter only attests in strict mode ...` | `[env] mode = "loose"` with cargo | The user must switch to strict |
| `read PYTHONPATH, which vci sets to its collector` | The test reads `PYTHONPATH` | Not attestable |
| `<python/node/ruby> collector ... differs` / toolchain mismatch messages | The collector's interpreter differs from the project's | Fix the environment (uv-managed Python, same Node, same Ruby) |
| `go.work <path> is outside the repository (...)` | A `go.work` from outside the repo | `GOWORK=off` or move it in |
| `listed under more than one runner project (or by more than one vci project)` | The file belongs to two projects | Fix the project configuration (user decision) |
| `not in the runner's test file list` / `the collector produced no output for it` | The runner did not run it as a unit, or crashed | Check the path and the runner output |

Errors that stop `vci run` before anything runs:

- `<arg> is not a test file of any project (not listed by the test runner)`: wrong path, a non-test file, a Go file
  instead of its directory, a directory for pytest/Rails, or a path not relative to the current directory.
- Key errors name where the key came from (`--key`, `VCI_SIGNING_KEY`, `git config user.signingkey`). A `.pub` path
  needs the private key loaded in `ssh-agent`.

Warnings worth acting on:

- `vci: warning: <unit>: it reads CI, which CI runners set ...`: the unit will not match on a runner. For Rails,
  replace `config.eager_load = ENV["CI"].present?` with `false` (with the user's approval).
- `inputs ignored by git (a fresh checkout, e.g. in CI, will not have them ...)`: delete leftovers or accept the
  unit will run in CI. For Rails `config/master.key`, see runners.md.
- Listings with `.DS_Store` / `__pycache__`: delete the junk and attest again.
- `declared env var X looks like a secret; its hash is published in attestations`: move it to `pass_through`
  (user decision).
- `--ttl ... exceeds policy.max_ttl ...`: use a shorter `--ttl`.

## `vci plan` / `vci explain`: failed checks

`vci explain <unit> --base-ref origin/main` prints, per candidate, `failed check: <name>` with `expected` (what the
attestation recorded) and `actual` (what this checkout and the base policy give). Checks run in this order:

| Check | Fails when | Typical fix |
|---|---|---|
| `envelope` | The stored value is not a DSSE in-toto envelope | Re-attest |
| `signature` | Bad signature or namespace | Re-attest; never edit stored envelopes |
| `signer` | The key is not in the **base commit's** `.vci/allowed_signers` (`actual: signer SHA256:... is not in allowed_signers`), or outside `valid-after`/`valid-before` | The user (not you) adds the key on the default branch. A key added on the PR branch is ignored by design |
| `statement` | Predicate type or subject mismatch | Re-attest with the current vci |
| `expiry` | Expired, issued in the future (clock skew > 5 min), or lifetime above `max_ttl` | Re-attest (`--ttl` within `max_ttl`) |
| `repo`, `test-id`, `adapter`, `argv` | Attested in another repository, for another unit id, adapter, project dir or runner command | Attest in this repository and project |
| `toolchain` | Node/Vitest/Vite, Python/pytest/distributions, Go version and settings, rustc/cargo, Ruby/Rails/bundle, root vs non-root, or OS/arch per `policy.platform` differ | Pin toolchains (runners.md). Locally, compare with what CI uses |
| `env-config` | The effective `[env]` configuration differs from the base `vci.toml` | The PR changed `[env]` or the base did; re-attest after the base has the same config |
| `result` / `inputs-config` / waived refusals / `dirty` | Not passed; `[[inputs]]` globs differ from the base config; a waiver (`go_allow_net`, `rails_allow_db`) no longer set on base; dirty tree with `allow_dirty = false` | Merge config changes to the default branch first; commit before attesting when `allow_dirty = false` |
| `global-inputs` | A global input (lockfile, runner config, `vci.toml`, ...) differs | Re-attest after the change |
| `inputs` | A recorded input differs: `entry:<path>` with both hashes (file edited after attesting, new file where an absent probe was, listing changed) | Re-run `vci run` on the unit after your last edit |
| `externals` | An external package/module/crate/gem version differs | Re-attest with the lockfile CI uses |
| `env` | A hashed variable's value differs (`TZ`, a declared variable, or `CI`/`HOME` the test read) | Set declared values the same on both sides; units reading `CI`/`HOME` never skip on runners |
| `internal` | A check panicked | Report it as a vci bug |

Plan-wide reasons (`running everything: ...`, or `running everything in <project>: ...` for one project of a
`[[projects]]` configuration):

- `policy.no_skip_refs matches refs/heads/main`: you are on the default branch (or a tag). Work on a feature branch.
- `vci.toml is missing at the base commit` / `.vci/allowed_signers is missing at the base commit` / `... at base is
  invalid`: vci is not set up on the default branch yet; nothing can skip until the setup is merged.
- `listing test files failed: ...` or `could not parse ... probe`: the runner could not list tests (collection
  error, missing or wrong toolchain version, e.g. `rbenv: version '3.4.9' is not installed`).
- Warning `no git-meta store in this repository: no attestations are available (run \`vci fetch\` first)`.
- Warning that the base commit is HEAD or contains it: trust would come from the commit under test; pass the real
  base (`--base-ref origin/main`).
