# Per-runner notes

Everything here is from docs/REFERENCE.md in the vci repository (full detail there). Run `vci` from the repository root
unless noted; unit arguments are paths relative to the current directory, unit ids in output are repo-relative.

## Summary

| Adapter (`vci.toml`) | Unit | Example `vci run` argument | How inputs are found |
|---|---|---|---|
| `vitest` | test file | `src/b.test.ts` | module graph, file and env reads observed at run time |
| `pytest` | test file | `tests/test_b.py` | Python audit hooks and the import system |
| `go` | package directory | `./b`, `svc/internal/store` | `go list` plus a logger overlaid into the test binary |
| `cargo` | test target | `crates/b#lib`, `crates/b#test:it`, `crates/b#doc`, `crates/b#bin:cli`; `crates/b` = every unit of the package | conservative: every file of the package and its in-repo dependencies, plus declared `[[inputs]]` |
| `rails` (Minitest) | test file | `test/models/b_test.rb` | Ruby collector wrapping file, env, require and process entry points |
| `rails` (RSpec, `runner = "rspec"` or detected) | spec file | `spec/models/b_spec.rb` | same collector |

Rules common to every runner:

- Each unit runs in its own process with a fresh `TMPDIR`; an attestation vouches for the unit run on its own.
- A unit is attested only if every test in it ran and passed: any failure, skip, xfail, pending example, filtered
  run or "no tests" refuses it.
- Writes inside the repository, child processes, network, reading the whole environment, and reads outside the
  repository refuse a unit (Rails allows writes to git-ignored `log/`, `tmp/`, `storage/`, `coverage/`).
- Toolchain versions must be identical where the unit was attested and in CI, or the check `toolchain` fails.
- Strict env mode (default): undeclared variables are removed from the test process on both sides. Declare a
  variable in `[env] global` to set it (its value is then hashed and must match CI). Reading `CI`, `HOME`, `USER`,
  `TMPDIR`, `LANG` records their values, so such a unit never skips on a runner.
- `.DS_Store`, `__pycache__` or other junk in a directory a test lists breaks the match with a fresh checkout; `vci
  run` warns. Delete the junk and attest again.
- Never run the job in a `container:` (root on one side only is a toolchain difference).

## Vitest

- Needs Node 22.15+, Vitest `>=3.2 <6`, the `@vci/vitest` collector (`vci init` installs it, or set `VCI_JS_PLUGIN`).
- Toolchain compared: Node major, Vitest, Vite; OS/arch per `policy.platform`.
- Global inputs of every test file: `package.json`, lockfiles and `.npmrc` up to the repo root, Vitest/Vite config
  files and what they reference, the `tsconfig.json` chain, `vci.toml`, the test's `__snapshots__/<file>.snap`,
  `NODE_OPTIONS`. Changing any of them invalidates every test file.
- Refused: child processes, sockets, `fetch`, `worker_threads`, enumerating `process.env`, recursive readdir/glob,
  snapshot writes (`-u`), `isolate: false`, vm/browser pools, typecheck mode.
- Pin: Node major version, `package-lock.json` (`npm ci` in CI). External packages are matched by `name@version`.

## pytest (uv)

- The project must be a uv project with a committed `uv.lock` and a pytest config (`[tool.pytest.ini_options]`,
  `pytest.ini`, ...) in the project dir. pytest must be in the default dependency groups (`uv run --locked --exact`).
- Each file runs as `uv run --locked --exact --no-env-file pytest -p vci_pytest <file>`.
- Toolchain compared: exact Python version (major.minor.patch), implementation, bundled sqlite/OpenSSL versions,
  pytest version, the full installed distribution set.
- Pin: full Python version in `.python-version` using a uv-managed build uv also ships for Linux (e.g. `3.14.4`;
  `uv python list --all-platforms`), `UV_PYTHON_PREFERENCE=only-managed` on both sides, the same uv version locally and
  in `astral-sh/setup-uv`, `uv.lock`.
- Refused: subprocess/os.system/fork, sockets and HTTP clients, `ctypes`, multiprocessing, native extensions inside
  the repository, SQLite databases inside the repository, reading the pytest cache, `--lf`/`--ff`/`--sw`, xdist,
  reruns, unseeded random order, a `-p` plugin in `addopts`, reading `PYTHONPATH`, `sys.path` entries outside the
  repository, enumerating `os.environ`, writing inside the repository (use `tmp_path`).
- `skipif(sys.platform == ...)` or any skipped test refuses the whole file.
- `TZ` and every `PYTHON*`/`PYTEST_*` variable are hashed for every file.

## Go

- Needs a Go module (`project` = the directory holding `go.mod`), Go 1.26. The unit is every directory with
  `_test.go` files; ids are package directories relative to the repo root (`.` for the module root package at the
  repository root). `vci run` and `vci explain` take directories, not files.
- `vci run` runs `go test -count=1 -json -overlay=<logger>` per package with a fresh `TMPDIR`.
- Toolchain compared: exact Go version (`go env GOVERSION`), effective `CGO_ENABLED`, `GOFLAGS`, `GOEXPERIMENT`,
  `GODEBUG`, `GOWORK`, architecture level.
- Pin: exact Go version locally and in `actions/setup-go`, `go.sum`; declare `CGO_ENABLED` and `TZ` in
  `[env] global` and set `CGO_ENABLED=0`, `TZ=UTC` on both sides.
- Refused: `os.StartProcess`/`os/exec` actually starting a process, package `net` anywhere in the closure (testify's
  `assert` imports `net/http`; waivable only by `policy.go_allow_net = true`, the user's decision), `syscall` or
  `golang.org/x/sys` (other than `cpu`) in non-standard code, cgo, `os/user`, `plugin`, the identifier `Environ`,
  `//go:linkname`, the local time zone with `TZ` unset, `t.Skip`, a `TestMain` that does not run every test, any
  change to the repository during the run, a module cache that does not match `go.sum`, a `go.work` outside the
  repository.
- Platform pinning: a package with platform-specific files (`_linux.go`, `//go:build darwin`, `runtime.GOOS`) is only
  accepted on the same OS and architecture; floating-point code in the closure pins the architecture. A Mac
  attestation of such a package never skips on an amd64 Linux runner.

## Cargo

- `project` = the workspace root with `Cargo.lock`. Units: `<package dir>#lib`, `#doc`, `#bin:<name>`,
  `#test:<name>` (`tests/<name>.rs`), `#example:<name>`, `#bench:<name>` (with `test = true`). Quote ids in the shell
  (`'crates/b#test:b'`): `#` is a glob operator under zsh's `extendedglob`.
- `vci run` runs one `cargo test --locked --manifest-path <pkg>/Cargo.toml <target>` per unit, one at a time, and
  rebuilds the repository's crates each time (into `<target dir>/vci`). Expect it to be slower than `cargo test`.
- Inputs are decided conservatively: every file in the unit's package directory and in every repository crate it
  builds, ignored files included (they are not in a CI checkout, so such units run in CI; `vci run` warns). Files read
  elsewhere in the repository must be declared:

  ```toml
  [[inputs]]
  match = ["crates/b#test:*"]
  extra = ["testdata/**"]
  ```

  vci refuses a unit whose source names a path outside its packages that is not declared (`its source refers to
  ..., which is not an input; declare it in vci.toml ([[inputs]] ...)`). Declaring inputs is a vci.toml change the
  user must approve and merge to the default branch.
- Toolchain compared: `rustc -vV` (release, commit hash, LLVM version) and `cargo -vV`; use rustup with
  `rust-toolchain.toml` pinning an exact release, and the same release in `dtolnay/rust-toolchain`. Homebrew's rustc
  reports a different LLVM and never matches a rustup runner; put `~/.cargo/bin` first on `PATH` or set
  `VCI_CARGO=~/.cargo/bin/cargo`.
- Env mode must be `strict`. Refused (static source checks, comments included): `Command::new`/`process::Command`,
  `TcpStream`/`UdpSocket`/Unix sockets, networking or process crates (`reqwest`, `tokio` with `net`/`process`,
  `assert_cmd`, `git2`, ...), `libc::`, `extern "C"`, `asm!`, `env::vars()`, proc macros reading files, path literals
  in another letter case than the file, cross-compilation, custom runners/linkers, rustc wrappers
  other than `sccache`.
- `cfg(target_os = "linux")`-style code is evaluated for the CI host; `std::env::consts::OS` and libm float functions
  pin the unit to the attesting OS and architecture.

## Rails: Minitest and RSpec

- `adapter = "rails"`; `runner = "minitest" | "rspec"` or detected (RSpec when `rspec-core` is in `Gemfile.lock` and
  there is `spec/` and no Minitest file; both when both exist). Plain Ruby projects with RSpec work too.
- Units are files (`test/**/*_test.rb` without `test/system`; RSpec's own pattern for specs); `vci run` and `vci
  explain` take files, not directories.
- Each file runs in its own Ruby process with a fresh SQLite database loaded from `db/schema.rb`, `PARALLEL_WORKERS=1`,
  no Spring, no Bootsnap caches, seed 0 (`--seed 0` / RSpec default seed 0). RSpec runs with `--options .rspec` only
  (`~/.rspec`, XDG options and `.rspec-local` are never read).
- Global inputs of every file: `vci.toml`, `Gemfile`, `Gemfile.lock`, `config/application.rb`, `config/boot.rb`,
  `config/environment.rb`, `config/environments/test.rb`, `config.ru`, `bin/rails`, `test/test_helper.rb`,
  `Rakefile`, `.ruby-version`/`.tool-versions`/`mise.toml`, and for RSpec `.rspec`. Any `Gemfile.lock` change runs
  everything; `config/routes.rb`, a new file in `app/models`, any fixture with `fixtures :all`, any
  `spec/support` file or factory affect every test that boots Rails.
- Toolchain compared: Ruby version and patchlevel, Rails, Bundler (`BUNDLED WITH`), Minitest/RSpec gem versions,
  SQLite library, libyaml, time zone data, default encodings, collector version, the whole bundle.
- Pin: exact Ruby in `.ruby-version` (and `ruby/setup-ruby`), `Gemfile.lock` with the runner's platform
  (`bundle lock --add-platform x86_64-linux`), `gem "tzinfo-data"` for every platform, `TZ` declared in `[env] global`
  and `TZ=UTC` set on both sides (run `TZ=UTC vci run ...` locally), a UTF-8 locale on both sides (`LANG=C.UTF-8` on
  runners), `config.eager_load = false` in `config/environments/test.rb` (the generator's `ENV["CI"].present?` makes
  every file depend on `CI`), `vendor/.keep` committed.
- Stock `rails new` pitfalls: generated `pending` RSpec examples refuse their file; `config/master.key` is read at
  boot (git-ignored, so never in CI): commit test-environment credentials or drop the credentials, or declare
  `RAILS_MASTER_KEY`; `image_processing` with Homebrew libvips refuses every file (remove it if unused).
- Refused: child processes and forks, sockets/DNS/`Net::HTTP`, a database server unless `policy.rails_allow_db`
  (the user's decision), SQLite files vci did not prepare, native extensions in the repository, Fiddle/FFI, risky
  Nokogiri options, reading file mtimes/modes/owners of repository files, enumerating `ENV`, writes outside the
  git-ignored scratch dirs, gems outside the bundle, Bootsnap compile caches, Spring, Minitest tests without
  assertions, RSpec focus/tag filters, `--only-failures`, rspec-retry, parallel_tests, SimpleCov `minimum_coverage`
  failures (`vci:process-exit:2`).
- System tests that drive a browser are refused (child process and sockets); Capybara `rack_test` feature specs
  work.
- `vci run` never runs asset build hooks: build assets first if tests read them.
