# Spike: Go dependency collection

Date: 2026-09-28. macOS arm64, Go 1.26.2 (Homebrew, `GOROOT=/opt/homebrew/Cellar/go/1.26.2/libexec`).
Fixture: `fixtures/go-abcd`. Adapter: `crates/vci-adapter/src/golang/`.

## Go's own test log

`go test` caches results keyed by what the test used. It learns that from `internal/testlog`: package os calls
`testlog.Open(name)` in `OpenFile` (so `Open`, `ReadFile`, `ReadDir`, `DirFS`, `WriteFile`, `Create` too),
`testlog.Stat` in `Stat`/`Lstat` and `(*File).lstatat`, `testlog.Getenv` in `Getenv`/`LookupEnv`, and logs the new
working directory after `Chdir`; `os.Root` logs `Open`/`Stat` of `root.Name()/name`; `StartProcess` calls
`testlog.Open(<program>)`. Checked in the 1.26.2 sources (`os/file.go`, `os/stat.go`, `os/statat.go`, `os/env.go`,
`os/root.go`, `os/exec.go`).

Not logged: `os.Environ`, `os.Readlink`, `(*File).Chdir` (fchdir), `Remove`, `Rename`, `Mkdir`, `Chmod`,
`Symlink`, `Link`, everything in `syscall` and `golang.org/x/sys`, C code (cgo), and `syscall.Getenv` calls in the
standard library (package `time` reads `TZ` and `ZONEINFO` that way; the runtime reads `GODEBUG`, `GOGC`,
`GOMAXPROCS`, `GOTRACEBACK`). Names containing a newline are dropped by the default logger.

`go test -count=1 ./b -args -test.testlogfile=$PWD/b.log` (the cache is off with `-count=1`, so `go test` does not
pass its own `-test.testlogfile` and the flag reaches the binary) writes, for a test that reads `testdata/b.json`,
looks up `B_MODE`, stats a missing file, lists `testdata` and uses `t.TempDir()`:

```
# test log
open testdata/b.json
getenv B_MODE
stat testdata/missing.txt
open testdata
getenv GOTMPDIR
getenv TMPDIR
open /var/folders/qs/t9tw9znd54zdkdp00bdlbh6h0000gn/T/TestB3812926082/001/x
open /var/folders/qs/t9tw9znd54zdkdp00bdlbh6h0000gn/T
```

The package also had `var initData, _ = os.ReadFile("testdata/init.txt")`: **it is missing**. `testing` installs
the logger in `M.Run` (`testdeps.StartTestLog`), after every package initialiser and after the part of `TestMain`
that runs before `m.Run`. Go's own cache has this gap; for vci it would be a false skip (`var golden =
mustRead(...)` at package level is common).

## vci's logger: an overlay into internal/testlog

`go test -overlay=overlay.json` accepts a file inside GOROOT. vci adds `vci_testlog.go` to
`$GOROOT/src/internal/testlog` (the source is `crates/vci-adapter/src/golang/vci_testlog.go`). Its `init` runs
when internal/testlog is initialised, which is before package os (os imports it) and therefore before any
package that can reach the file system through os. It stores itself in testlog's `logger` (the same
`atomic.Pointer[Interface]` `SetLogger` uses) when `VCI_GO_TESTLOG` is set, and writes one unbuffered line per
event with `syscall.Write` (nothing is lost when the process exits or panics; a failed write panics, failing
the test). Relative paths are made absolute with `syscall.Getwd` at the time of the call, which also covers
`(*File).Chdir`. `Open` walks the stack (`runtime.CallersFrames`): a call from `os.StartProcess` is written as
`exec`. Only the standard library packages above internal/testlog are rebuilt with the overlay (about 3 s the
first time, cached afterwards).

Same package, with the overlay (`VCI_GO_TESTLOG=$PWD/b2.log go test -count=1 -overlay=... ./b`):

```
start "go1.26.2 darwin/arm64"
getenv "PWD"
open ".../exp/b/testdata/init.txt"
open ".../exp/b/testdata/b.json"
getenv "B_MODE"
stat ".../exp/b/testdata/missing.txt"
open ".../exp/b/testdata"
getenv "GOTMPDIR"
getenv "TMPDIR"
open "/var/folders/.../T/TestB2618474550/001/x"
open "/var/folders/.../T"
```

The init-time read is there. `exec.Command("echo", "hi").Output()`:

```
getenv "PATH"
stat "/opt/homebrew/Cellar/go/1.26.2/libexec/bin/echo"
...
stat "/bin/echo"
open "/dev/null"
exec "/bin/echo"
```

A fuzz target's seed corpus and `t.Chdir`:

```
chdir ".../fz/testdata"
stat ".../fz/testdata/fuzz"
open ".../fz/testdata/fuzz/FuzzX"
open ".../fz/testdata/fuzz/FuzzX/seed1"
```

`PWD` is read by `os.Getwd` (and so `filepath.Abs`); `go test` sets it to the package directory, so vci does not
treat it as an input (like the checkout location in every adapter). `TMPDIR` is a fresh empty directory vci
creates per package; files under it were created by the test.

Checked through `vci run` (predicate entries), with one test calling each API on its own file:
`fs.ReadFile(os.DirFS(...))`, `os.OpenRoot` + `Root.ReadFile`, `fs.ReadDir(root.FS(), ...)`, `filepath.Glob`
(the directory listing), `filepath.WalkDir` (every directory listing and file), `os.ReadFile`, `os.Stat`,
`os.Lstat`, `os.OpenFile`, and a `../` path: all recorded.

## Compile-time inputs: `go list -e -deps -test -json`

For `./b` the output holds `example.com/abcd/b` (`Match: ["./b"]`), the test variant
`example.com/abcd/b [example.com/abcd/b.test]` (`ForTest: example.com/abcd/b`, `GoFiles` including the
`_test.go` files, `Imports` naming other test variants), an external test package `b_test [b.test]` when there
is one, the generated `b.test` main (`GoFiles` in the build cache; imports `testing/internal/testdeps`, which
imports `internal/fuzz` and through it `os/exec`), and every dependency with `Standard`, `Module` (`Path`,
`Version`, `Dir`, `GoMod`, `Sum` from go.sum, `Replace`), `IgnoredGoFiles` (including `_test.go` files excluded
by constraints), `IgnoredOtherFiles` (`x_amd64.s` on arm64), `EmbedPatterns`/`EmbedFiles` and their `Test`/
`XTest` variants. The closure is taken from the test variants, not from the test main, so the harness's own
`os/exec` import is not held against every package.

`go list -m -json all` lists the build list (`Path`, `Version`, `Replace`, `Dir`, `Sum`); `golang.org/x/sync
v0.20.0` reports `Sum: h1:e0PTpb7pjO8GAtTs2dQ6jYa5BWYlMuX047Dco/pItO4=`, which vci's reimplementation of
`dirhash.HashDir` reproduces from the extracted module in the cache (`crates/vci-adapter/tests/go_fixture.rs`).

## `go test -json`

Events per test (`run`, `pass`, `fail`, `skip` with `Test`, subtests included), a final package event without
`Test` (`pass`, `fail`, or `skip` for "no test files"), `output` events whose `Output` fields together are what
`go test -v` prints, and for a build failure `build-output`/`build-fail` events keyed by `ImportPath` followed by
a package `fail` with `FailedBuild`. A skipped subtest inside a passing test is `skip` with `Test: TestOK/sub`.
`-json` implies `-test.v=test2json`, so `testing.Verbose()` is true; `vci ci` uses `-json` too (converted back to
text) so attestation and CI runs see the same flags.

## Toolchain

`go env -json` gives `GOVERSION` (`go1.26.2`), `GOOS`/`GOARCH`, `GOHOSTOS`/`GOHOSTARCH`, `CGO_ENABLED` (`1` on
macOS with the command line tools and on ubuntu-latest), `GOFLAGS`, `GOEXPERIMENT`, `GOFIPS140` (`off`),
`GODEBUG`, `GOWORK`, `GOMOD`, and the architecture level of the target (`GOARM64=v8.0`; `GOAMD64` is empty on
arm64). These are effective values: `go env -w` settings from the user's go env file are included. With
`GOTOOLCHAIN=auto` and a `toolchain` line in go.mod, `go env GOVERSION` reports the version the go command
switches to, and the test binary's `runtime.Version()` (the `start` record) is compared with it.
