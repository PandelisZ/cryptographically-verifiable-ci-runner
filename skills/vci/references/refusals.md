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
| `result failed (F failed, S skipped or xfailed of N; ...)` | A test failed (Rails/RSpec: or was skipped/pending) | Fix the code (or the test, if the user agrees) and run again. Never attest around a failure; no policy waives one |
| `result passed (0 failed, S skipped or xfailed of N; ...)` (key `result:skipped`) | It passed, but a test was skipped/xfailed/todo, so that test did not run | Leave it unattested, or (the user's decision) `ignore_taints = ["result:skipped"]`: attested with `result:skipped:S of N` recorded as waived |
| `result no-tests (...)` / `result filtered (...)` | No test ran, or only some (focus, `-k`, tag filters, `--only-failures`, `TestMain` filtering). Cargo since 1.9.1: a target without tests passes with 0 tests; only a custom harness or all-`#[ignore]`d tests refuse | Remove the filter; every test in the unit must run |
| `result no-assertions (...)` | Minitest test without an assertion | Add assertions or leave it unattested |
| `tainted: <process event>`: `subprocess.Popen`, `os.system`, `os.fork` (pytest), `child_process...` (Vitest), `exec: <program>` (Go), `process:backtick`, `process:fork`, `process:system` (Rails), `cargo:process...` | The test (or its setup/config) started a child process, whose reads vci cannot see | Not attestable; CI runs it. (Rails: the `bin/rails db:test:prepare` Active Record's `maintain_test_schema!` starts is the engine's and is not refused) |
| `tainted: <network event>`: `socket.connect`, `socket.getaddrinfo` (pytest), socket/`fetch` taints (Vitest), `go:net:...` (Go: package `net` in the closure), network crates (Cargo), `network:...` (Rails, including `network:mysql2 client` for a database client the test opened itself, and `network:mysql2 (an Active Record connection to host:port/db, ...)` for Active Record reaching a database that is not the test environment's) | Sockets, HTTP, DNS, a database client the test opens itself | Not attestable. The `go_allow_net` waiver exists but is the user's policy decision on the default branch. (Rails: the test environment's own database, SQLite or a server, is accepted with no policy since 1.4.0) |
| `tainted: env:enumerated` (or a recorded env key `*`) | The test read the whole environment (`dict(os.environ)`, `process.env` spread, `ENV.to_h`, `env::vars()`) | Read specific variables instead, if the user agrees |
| `tainted: native:...`, `ctypes.dlopen:...`, `go:cgo...`, `go:syscall:...`, `cargo:native...`, `vci:not-hooked:...` | Native code that can open files unseen (cgo, FFI, `ctypes`, extensions in the repo, libxml2 options) | Not attestable |
| `tainted: pytest:...` (`--lf`, `xdist`, `reruns`, `random-order`, `no-config-file`, `plugin-imported-before-collector:...`, `partial-file-selection`), `sqlite3:...`, `multiprocessing:...` | A pytest mode that hides inputs or selects part of a file | Run whole files without those options |
| `tainted: rspec:...` (`filtered`, `retry`, `failure-cleared`, `status-mismatch`, `option-files`, `invocation`, `parallel-tests`) | RSpec ran filtered, retried, or outside vci's options | Remove focus/tag filters, rspec-retry, parallel_tests from the run |
| `tainted: ruby:gem-outside-bundle:<path>`, `ruby:read-outside-bundle:<kind> <path>` (`read`, `stat`, ...) | The test loaded code from, or read, checked or listed (also through `Gem.read_binary`, `Bundler.read_file`, `Gem::Specification.load`, a glob) a file under a gem directory that belongs to no gem of the bundle: another installed gem, another Ruby's `vendor/bundle/ruby/<abi>`, or a check of where gems are installed (`File.directory?("vendor/bundle")`). A bundle installed inside the repository (`bundler-cache`'s `vendor/bundle`) is not itself refused: from collector 0.4.2 its gems are externals and RubyGems'/Bundler's bookkeeping there is ignored | Use only gems of the bundle (add the gem to the `Gemfile` if the user agrees). If every file is refused with `stat .../vendor/bundle/ruby/<abi>`, CI uses collector 0.4.1: update vci (existing Rails attestations then run once more) |
| `tainted: rails:sqlite-file:<path>`, `rails:sqlite-attach`, `rails:sqlite-load-extension` | The test opened a SQLite file that is not one of the test environment's databases in `config/database.yml` (another file, another environment's database, a `DATABASE_URL` naming another file), used `ATTACH`, or loaded a SQLite extension: SQLite reads those files in C | Not attestable. The configured test databases (and in-memory ones) are accepted, and their contents are not an input; do not point the test at another file to get around it |
| `tainted: ruby:file-metadata:...` | Read mtime/mode/owner of a repository file | Not reproducible on a checkout; not attestable |
| `tainted: vci:process-exit:N` | The process exited non-zero after the framework reported success (SimpleCov `minimum_coverage`, an `at_exit`) | Fix the exit status or leave it unattested |
| `tainted: cargo:undeclared-reads` / `its source refers to <path> (...), which is not an input; declare it in vci.toml ([[inputs]] ...)` | A Rust test reads a file outside its package directories | Ask the user to declare it under `[[inputs]]` in `vci.toml` and merge that to the default branch, or (1.8.0) waive the key `cargo:undeclared-reads` with `policy.ignore_taints`; the path is then recorded as waived |
| `cargo:path-case` | A path literal differs in letter case from the file | Fix the path's case |
| `wrote inside the repository: <paths>` (key `wrote-inside-repository`) | The test created, changed or deleted files in the repo. Since 1.7.1 writes under `node_modules/.vite`, `node_modules/.vite-temp` and `node_modules/.cache` (tool caches) never count | Write to a temp dir (`tmp_path`, `t.TempDir()`, `TMPDIR`) instead; or (the user's decision) `ignore_taints = ["wrote-inside-repository"]`: the written paths are then not inputs |
| `input outside the repository: <path>` (key `outside-repository`) | A read outside the repo (`/etc/hosts`, `/proc/sys/...`, `/etc/lsb-release`, `~/...`, an unowned temp file) | Stop reading it; or (the user's decision) `ignore_taints = ["outside-repository"]`: attested with `outside-repository:<path>` recorded as waived and the path not hashed |
| `input changed during the run: ...` / `global inputs changed during the run` / `the repository changed during the run: ...` (Go) | Something modified the working tree while tests ran (an editor, a formatter, a watcher, another process, the test itself) | Stop other writers and run again |
| `input cannot be checked for changes: <path>: inside ...` (`a directory vci does not track`, `build output vci does not track`, `a nested git repository or worktree vci does not track`) | The unit reads a file vci does not snapshot: under `.git`, `node_modules`, `.venv` or a build output directory, or inside a git repository or worktree nested in the checkout that is not a submodule (submodules are inputs like any other directory) | Not attestable as is: move the file into the repository proper, or make the nested repository a submodule |
| `env mode "loose": the cargo adapter only attests in strict mode ...` | `[env] mode = "loose"` (deprecated since 1.6.0) with cargo | The user must remove `mode = "loose"` (the default policy is the only one going forward) |
| `read PYTHONPATH, which vci sets to its collector` | The test reads `PYTHONPATH` | Not attestable |
| `<python/node/ruby> collector ... differs` / toolchain mismatch messages | The collector's interpreter differs from the project's | Fix the environment (uv-managed Python, same Node, same Ruby) |
| `go.work <path> is outside the repository (...)` | A `go.work` from outside the repo | `GOWORK=off` or move it in |
| `listed under more than one runner project (or by more than one vci project)` | The file belongs to two projects | Fix the project configuration (user decision) |
| `not in the runner's test file list` / `the collector produced no output for it` | The runner did not run it as a unit, or crashed | Check the path and the runner output |
| `signing or storing failed: storing the batch: <kind> store refused to write: ...` (`libsql`: `the token may not write`; `postgres`: `permission denied for table ...`) | vci 2.8+: the store's credential can only read. The tests ran and passed; nothing was stored | Report it; a read-only credential is how pull-request jobs are meant to be set up. Never look for another credential |
| `signing or storing failed: ... store is not set up: the first vci run with a token allowed to create tables creates them` (or `... a role allowed to create schema vci ...`) | A new shared store, and this credential may not create its tables | The user's first run with a credential that can write creates them |
| `signing or storing failed: ... store unavailable: ...` | The store cannot be used: no or a refused token, a server down, a failing `[store] token_command` | `vci store info` says why. For `the token_command (...) exited N; ...`, never run the command, or any other command that reads a secret, yourself, not even with its output discarded: its standard error can hold the token. Tell the user what failed and the command, and ask them to run it in their own terminal with `> /dev/null` after it; with vci 2.8.0, give the command from `vci.toml` with every argument in single quotes, or a string `token_command` as `sh -c '<the string>'` (SKILL.md, "Attestation stores") |
| `signing or storing failed: the libsql store does not support storing a record of 5,000,000 bytes or more ...` | The unit's attestation or input manifest is too large for a libSQL server's row limit | Nothing to do: that unit runs every time on such a server |

**`policy.ignore_taints` (vci 1.7.0+).** A repository's `vci.toml` can waive taints: `ignore_taints = ["process:*",
"child_process.*", "go:syscall"]` (globs over the reason key the "why not attested" lines print; `"*"` for all,
`vci:` taints never). A waived unit is attested (`vci: attested <unit> (waived: process:system, +2)`), the taints are
recorded in the attestation's `waived`, and `vci plan` accepts it only while the base branch's policy still waives
each one (otherwise the `waived` check fails). Since 1.7.1 it also waives three of vci's own refusals by key:
`outside-repository` (reads outside the repository), `wrote-inside-repository` (writes inside it) and
`result:skipped` (a pass with skipped tests); `"*"` includes them. A failed result is never waived. It knowingly
trades determinism for CI cost: what the taint stands for (a child process's reads, a network answer, a kernel
parameter or OS release file, a test that did not run) is not recorded. Adding it, widening it, or setting it to `"*"` is the
maintainers' decision: never add `ignore_taints` (or `go_allow_net`) to a repository's policy on your own to get a
unit attested; report the taint, and mention the knob only as an option for the user to decide on.

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
- `vci: warning: policy.rails_allow_db in vci.toml is ignored: rails_allow_db was removed in vci 1.4.0 ...` (`vci
  plan`: `in vci.toml at the base commit`): a no-op key left in `vci.toml`; the test database needs no policy now. Tell
  the user and suggest removing it (a `vci.toml` change on the default branch, theirs to make).
- `hashed env var X looks like a secret; its hash is published in attestations`: move it to `[env] ignore`
  (user decision).
- `--ttl ... exceeds policy.max_ttl ...`: use a shorter `--ttl`.

## `vci plan` / `vci explain`: failed checks

`vci explain <unit> --base-ref origin/main` prints, per candidate, `failed check: <name>` with `expected` (what the
attestation recorded) and `actual` (what this checkout and the base policy give). Checks run in this order:

| Check | Fails when | Typical fix |
|---|---|---|
| `envelope` | The stored value is not a DSSE in-toto envelope; or (since 2.0, whose `vci fetch` downloads keys and fetches values when they are read) it could not be fetched: ``unreadable: value not fetched: run `vci fetch` online``. A vci before 2.9 fails every store format 3 record (written by 2.9) here: it cannot parse the frame | Re-attest; for a value not fetched, run the plan or `vci explain` again online; for a 2.8 vci reading 2.9's records, upgrade the vci that plans (CI's `@v2` follows 2.x) |
| `signature` | Bad signature or namespace. For CI's keyless (`--oidc`) attestations also: the certificate's issuer is no authority of the base `.vci/sigstore-trusted-root.json` (missing, invalid or stale: GitHub renews its intermediate yearly), or the timestamp is missing, invalid or outside the certificate's ten minutes | Re-attest; never edit stored envelopes. A stale trust root is the user's to refresh on the default branch (`gh attestation trusted-root > .vci/sigstore-trusted-root.json`) |
| `signer` | The key is not in the **base commit's** `.vci/allowed_signers` (`actual: signer SHA256:... is not in allowed_signers`), or outside `valid-after`/`valid-before`; since 2.9, `signer id (the store key's signer segment)`: the record is stored under another signer's slot (its key's signer segment is not the verified key's id), as a copy in the store would be; for a keyless attestation, the job's identity matches no `[[identity]]` of the base `.vci/identities.toml` (`identity repo:... workflow:... ref:... event:... matches no [[identity]]`), or that file is missing at the base commit | The user (not you) adds the key or identity on the default branch. One added on the PR branch is ignored by design |
| `statement` | Predicate type or subject mismatch; or the predicate has both or neither of `manifest` and `manifestRef`, or a `manifestRef` other than its input root. For a store format 3 record (2.9): the hdr or tables object the statement names is missing from the store, its hash is not the one signed, or it does not decode, or a waived id is out of range (the store lost or altered the run's objects: nothing a signer can fix but attesting again). A vci before 1.9.0 fails every attestation made by 1.9.0 or later here (`best failed statement: predicate`): it cannot read a predicate whose input manifest is stored by reference | Re-attest with the current vci; for the second case, upgrade the vci that plans (CI's `@v2` follows 2.x) |
| `expiry` | Expired, issued in the future (clock skew > 5 min), or lifetime above `max_ttl` | Re-attest (`--ttl` within `max_ttl`) |
| `repo`, `test-id`, `adapter`, `argv` | Attested in another repository, for another unit id, adapter, project dir or runner command | Attest in this repository and project |
| `toolchain` | Node/Vitest/Vite, Python/pytest/distributions, Go version and settings, rustc/cargo, Ruby/Rails/bundle, root vs non-root, or OS/arch per `policy.platform` differ; `ruby libraries` / `python libraries` (SQLite, libyaml, tz data, OpenSSL versions) differ under `policy.libraries = "exact"`, or one side lacks the library (`... loaded or not`, also under `"any"`) | Pin toolchains (runners.md). Locally, compare with what CI uses. For library versions between macOS and Linux, the user may set `libraries = "any"` on the default branch |
| `env-config` | The effective `[env]` configuration (`set` values, `hash`/`ignore` lists, vci's built-in lists) differs from the base `vci.toml`'s; every attestation made before vci 1.6.0 fails this once | The PR changed `[env]`, the base did, or vci was upgraded; re-attest once the base has the same config (`vci env --base-ref <ref>` shows the difference) |
| `result` / `inputs-config` / `waived` / `dirty` | Not passed; `[[inputs]]` globs differ from the base config; a taint the attestation recorded as waived is no longer waived by the base policy (`waived taint <key>`: its `ignore_taints` or `go_allow_net` no longer covers it), or an attestation made under the removed `rails_allow_db`; dirty tree with `allow_dirty = false` | Merge config changes to the default branch first (a waiver is the user's decision); commit before attesting when `allow_dirty = false` |
| `global-inputs` | A global input (lockfile, runner config, `vci.toml`, ...) differs | Re-attest after the change |
| `inputs` | A recorded input differs: `entry:<path>` with both hashes (file edited after attesting, new file where an absent probe was, listing changed; for a store format 3 record, 2.9, the attested hash is labelled `attested (unsigned, from the run's state object)`, or the detail is `entry:<path>` with expected `<kind> exec=<bool> changed (attested hash not loaded)` (a kind or exec difference) / `entry: changed (attested hash not loaded)` with both roots once the run's state object was removed, on git-meta, or past the plan's 16 state objects: the root of what is on disk is not the signed one, and which file changed is not known). Also (2.9) a shape object missing, altered or past the plan's 16 MiB of verdict objects. Since 1.9.0 also ``manifest <root> not in the store: run `vci fetch` `` (the attestation references an input manifest, `project` key `vci:manifest:<root>`, that the local git-meta store lacks), `manifest <root> unreadable` / `corrupt`, or `inputRoot` against the root recomputed from the stored manifest (it is not the one the attestation signed) | Re-run `vci run` on the unit after your last edit. For a missing or unreadable manifest, run `vci fetch` (the attestation and its manifest are published together); if it stays missing or does not match, re-attest the unit. Never edit or copy manifests by hand |
| `externals` | An external package/module/crate/gem version differs; or a native library opened through FFI (`external:native:libvips.42.dylib`) is another file or build where CI checks, or `native library libvips: not loaded here` | Re-attest with the lockfile CI uses. For native libraries: install the library in CI; across macOS and Linux the user may set `policy.libraries = "any"` (matches by library name) on the default branch |
| `env` | A hashed variable's value differs; the detail is `env:<NAME> (<class>)`: `hash`/`built-in hash` (taken from the machine) or `built-in ignore` (`HOME`, `USER` the test read) | Give `hash` variables the same value on both sides or propose moving them to `[env] set` (the user's decision); units reading `HOME`/`USER` never skip on runners |
| `internal` | A check panicked | Report it as a vci bug |

Plan-wide reasons (`running everything: ...`, or `running everything in <project>: ...` for one project of a
`[[projects]]` configuration):

- `policy.no_skip_refs matches refs/heads/main`: you are on the default branch (or a tag). Work on a feature branch.
- `vci.toml is missing at the base commit` / `.vci/allowed_signers is missing at the base commit` / `... at base is
  invalid`: vci is not set up on the default branch yet; nothing can skip until the setup is merged.
- `listing test files failed: ...` or `could not parse ... probe`: the runner could not list tests (collection
  error, missing or wrong toolchain version, e.g. `rbenv: version '3.4.9' is not installed`).
- Warning `no git-meta store in this repository: no attestations are available (run \`vci fetch\` first)`.
- `running everything: reading attestations from <kind>: <error>` (vci 2.8+): the attestation store (SQLite,
  PostgreSQL, libSQL) cannot be used, so every unit runs. That is the safe outcome. `vci store info` prints why, and
  never a secret; see SKILL.md, "Attestation stores", for a failing `token_command`.
- Warning `no attestations are available in the <kind> store (the first \`vci run\` creates it)`: a new store that
  holds nothing yet. Every unit runs until something is stored.
- Warning that the base commit is HEAD or contains it: trust would come from the commit under test; pass the real
  base (`--base-ref origin/main`).
