# Spike: pytest dependency collection (`vci_pytest`)

Date: 2026-09-27. macOS arm64. CPython 3.14.7 (Homebrew), plus 3.12.6 and 3.11.14 (uv-managed).
pytest 9.1.1, pluggy 1.6.0, uv 0.11.7. Fixture: `fixtures/pytest-abcd`. Plugin: `py/pytest-plugin/vci_pytest`.
Spike harnesses: `py/pytest-plugin/spike/audit_coverage.py` (which operations raise audit events) and
`py/pytest-plugin/spike/gaps_demo.py` (known bypasses, run end to end through the plugin).

## How it collects

The Rust CLI runs one pytest process per test file:

```
PYTHONPATH=<abs>/py/pytest-plugin VCI_OUT=<dir> uv run --locked pytest -p vci_pytest tests/test_b.py
```

`-p` plugins are imported in `Config._preparse` via `consider_preparse`, before entry-point plugins,
`pytest_load_initial_conftests`, conftest files and collection (checked in `_pytest/config/__init__.py`, 9.1.1).
The plugin installs everything at import time:

1. `sys.addaudithook`: `open` (builtins/io/`os.open`/`io.open_code`/`FileIO`), `os.listdir`/`os.scandir`,
   file-mutating `os.*` events, `exec` (every module body), `tempfile.mkstemp`/`mkdtemp`, and taint events.
2. Wrappers on `os.stat`, `os.lstat`, `os.access`, `os.readlink`, `os.open` (for `dir_fd`).
3. A wrapper on `importlib.machinery.FileFinder.find_spec` that records every candidate path of every import
   lookup in every directory.
4. Wrappers on `os._Environ` (`__getitem__`, `__iter__`, `__len__`, `__repr__`, `copy`).

At `pytest_sessionfinish` it classifies paths (stdlib / venv+site-packages / root / outside), maps site-packages
files to distributions through each distribution's RECORD, adds pytest's own lookups, and writes
`$VCI_OUT/<sha256(testId)>.jsonl`.

## What audit hooks catch and what they don't

`audit_coverage.py` on 3.14.7 (3.12.6 identical except where noted):

| Operation | Audit event |
|---|---|
| `open()`, `Path.read_text`, `io.FileIO`, `io.open_code`, `os.open` | `open` (all of them, including `from builtins import open` bound early) |
| `mmap.mmap(fd)` | only `mmap.__new__(fd)`; the file is seen at the preceding `open` |
| `os.stat`, `os.path.exists` (missing), `os.access` | **none** |
| `os.listdir`, `os.scandir` (+ `DirEntry.stat`) | `os.listdir` / `os.scandir` only |
| `glob.glob`, `Path.glob` | `glob.glob`, then `os.scandir` per directory |
| `os.environ[...]`, `os.getenv` | **none** |
| `time.tzset` (C `getenv("TZ")`, `/etc/localtime`) | **none** |
| `sqlite3.connect(path)` | `sqlite3.connect(path)` |
| `ATTACH DATABASE 'x.db'` in SQL | **none** (SQLite opens it in C) |
| `ssl...load_verify_locations(cafile)` | **none** (OpenSSL `fopen`) |
| `ctypes` `libc.fopen` | only `ctypes.dlsym`, `ctypes.call_function` |
| `subprocess.run` | `subprocess.Popen`, and `_posixsubprocess.fork_exec` on 3.14 only |
| multiprocessing `spawn` `Process.start()` | 3.14: `_posixsubprocess.fork_exec`; **3.12: no process event at all** |
| `concurrent.interpreters` (3.14) create + `exec` that opens a file | **none** in the parent interpreter |

So audit hooks cover every Python-level file open (whatever alias it was bound to), but no metadata calls,
no env reads and nothing done in C by an extension or a linked library.

End-to-end check through the plugin (`gaps_demo.py`, real output):

```
gap-posix-stat   not recorded          posix.stat(missing)          C-level, bypasses the os.stat wrapper
GAP_ENV_DATA     not recorded          os.environ._data.get(...)    bypasses os._Environ
other.db         not recorded          sqlite ATTACH
ca.pem           not recorded          ssl load_verify_locations
seen-stat        RECORDED ['probe']    Path.stat() on missing file  (control)
SEEN_ENV         RECORDED ['env']      os.environ.get               (control)
b.json           RECORDED ['read']     Path.read_bytes              (control)
```

## Findings that shaped the design

**F1. Metadata calls need wrappers, and they work because the stdlib looks `os.stat` up at call time.**
`genericpath.exists/isfile/isdir/getmtime/samefile`, `pathlib.Path.stat/exists/is_file/is_dir/info`, `shutil._stat`
all call `os.stat`/`os.lstat` through the `os` module at call time (verified by patching and tracing, 3.14).
ENOENT/ENOTDIR becomes `probe`; success or any other error becomes `read` (a directory `read` is hashed as a
listing by vci-core). Wrappers are added to `os.supports_dir_fd` etc. so `shutil.copystat`'s
`fn in os.supports_follow_symlinks` checks keep working. `os.path.realpath` (and `Path.resolve()`) `lstat`s every
ancestor, including `/Users`, `/private/var`, etc.; those calls are ignored except for symlinks inside the root,
otherwise every `Path(__file__).resolve()` would put outside-root paths in the record and make the file
non-attestable.

**F2. Import resolution: record the lookups, not the directory listing.** Imports resolve through
`FileFinder`, which lists each `sys.path` directory once (`_fill_cache` -> `os.listdir`, audited) and then
stats via `posix.stat` directly (not audited, not patchable). Recording the listing as `readdir` of `src/` and
`tests/` would invalidate every attestation whenever any file is added there. Instead the `FileFinder.find_spec`
wrapper records, for each (directory, module name), all candidates: `<dir>/<name>` (package dir),
`<dir>/<name>/__init__<suffix>` and `<dir>/<name><suffix>` for every loader suffix (`.cpython-314-darwin.so`,
`.abi3.so`, `.so`, `.py`, `.pyc`). Absent candidates become `probe`; a candidate present with the wrong type
(a directory named `x.py`) becomes `read`. The `_fill_cache` listdir is dropped. This also covers failed optional
imports (`try: import optional_helper`) and shadowing (a new `tests/b.py` would shadow `src/b.py`; B's record
contains `probe tests/b/__init__.py`, `tests/b.py`, ...). Cost: ~376 probe records per fixture file.
Hits come from three sources: finder spec origins, `exec` audit events (every module body, including conftest
modules pytest later drops from `sys.modules`), and a final `sys.modules` scan (extension modules, pre-plugin
imports). `sys.path_importer_cache` keys give every directory consulted, so a `sys.path` entry inside the root
that did not exist is recorded as a probe.

**F3. Stack attribution is needed, and the console-script shim must count as tool code.** Without it the
record contains pytest's own activity: first run (before the fix) for `tests/test_d.py` had 14 reads, 26 env
keys and 2 writes, including reads of `/Users/pz/w/cryptographically-verifiable-ci/fixtures` (outside the root),
`/var/folders/.../T` (tmp dir probing), every `tests/test_*.py`, and every `*.dist-info` (pytest's entry point
scan, which also made every installed dist an `external`). Cause: `.venv/bin/pytest` is at the bottom of every
stack and was classified as user code. Rule now: an fs/env event is recorded if any frame on the stack is outside
{stdlib, frozen, this plugin, the console script, site-packages top-level `_pytest`, `pytest`, `pluggy`,
`iniconfig`, `packaging`, `pygments`, `exceptiongroup`, `tomli`, `colorama`, `py`}. Any third-party frame
(including other pytest plugins) counts as user code. After the fix the same file has 3 reads (config inputs)
and only the explicit env keys. Module/import records do not depend on the stack.
Because pytest-only activity is ignored, pytest's *semantic* lookups are added explicitly: `config.inipath`,
`pyproject.toml`, `uv.lock`, `.python-version` at the root; for every directory from the test file up to the
root: all 7 config names pytest 9 searches (`pytest.toml`, `.pytest.toml`, `pytest.ini`, `.pytest.ini`,
`pyproject.toml`, `tox.ini`, `setup.cfg`), `__init__.py` (package/module-name detection) and, up to
`confcutdir`, `conftest.py`.

**F4. pytest 9 inserts `pythonpath` entries before importing `-p` plugins** (`_configure_python_path()` right before
`consider_preparse`, `_pytest/config/__init__.py:1575`). Modules imported before the plugin loaded
(pytest itself, argparse, ...) looked up the `sys.path` of that time unobserved. The finalizer adds candidate
probes for each pre-loaded top-level module in root `sys.path` entries that precede the entry it was loaded from
(builtin/frozen modules excluded). `pythonpath` entries are excluded unless another `-p` plugin was imported
first. A first version without the position/`pythonpath` rules produced 1685 probes for B instead of 376.
With `python -m pytest` the cwd (the root) is `sys.path[0]` from interpreter start, and the record then
contains `probe pytest.py`, `_pytest/__init__.py`, `argparse.py`, ... (tested). The adapter should still prefer
the console script (`uv run pytest`).

**F5. Processes, network, native code -> taint.** Audit events `subprocess.Popen`, `_posixsubprocess.fork_exec`,
`os.system`, `os.exec`, `os.fork`, `os.forkpty`, `os.posix_spawn`, `os.spawn`, `socket.connect/bind/sendto/
sendmsg/getaddrinfo/gethostbyname/gethostbyaddr/getnameinfo/getservby*`, `urllib.Request`, `http.client.connect`,
other stdlib client `connect` events, `ctypes.dlopen` (non-NULL name). Because 3.12 raises nothing for a
multiprocessing spawn, the import of `multiprocessing.popen_*`/`multiprocessing.forkserver` (only imported when a
process is started) is also a taint. Subinterpreters are invisible (see table), so `_interpreters.create` /
`_xxsubinterpreters.create` are wrapped to taint. A root module whose origin has an extension suffix taints
(`native-extension-in-root:src/fakeext...so`, tested with a fake `.so` that fails to load). `asyncio.run` does
not taint (its self-pipe is a `socketpair`, no bind/connect; tested).

**F6. `open` is audited before it runs.** A failed `open()` of a missing file looks like a read. At the end, a
`read`/`readdir` whose path no longer exists becomes a `probe`. Deletions inside the root are `write` records, so
"read then deleted" is still flagged.

**F7. `dir_fd`-relative calls** (`shutil.rmtree`, `os.open(name, dir_fd=fd)`) carry a relative path. The fd is
resolved with `fcntl(F_GETPATH)` on macOS (buffer must be <= 1024 bytes, otherwise `fcntl` raises ValueError; the
first version hit this and correctly fell back to a taint) or `/proc/self/fd` on Linux. Unresolvable -> taint.

**F8. Self-produced files are not inputs.** Paths under pytest's basetemp (`tmp_path`), `tempfile.mkdtemp` dirs and
`tempfile.mkstemp` files (both audited after success), the pytest cache dir, `__pycache__`, `*.pyc` reads, `VCI_OUT`
and `/dev/null` are dropped. Tests using `tmp_path` + `TemporaryDirectory` produce no outside-root paths (tested).

**F9. Externals.** Every site-packages/venv module file is looked up in the RECORD of the distribution that owns
it (`importlib.metadata.distributions()`, first match in `sys.path` order), falling back to
`packages_distributions()` only for dists without RECORD. Names are PEP 503 normalised. uv venvs contain
`_virtualenv.py`, owned by no distribution; it is whitelisted. Any other unowned module -> `unmapped-module:` taint.
Reads of site-packages files (e.g. `importlib.metadata.version("x")`) map to their dist's `external`.

## Known gaps and how each is handled

| Gap | Handling |
|---|---|
| C extensions / linked libraries opening files themselves (SQLite `ATTACH`, OpenSSL cafile, libxml2 via `lxml.etree.parse(path)`, pyarrow/h5py, `numpy.fromfile`) | **Documented limitation** (PLAN threat model: native addons). `ctypes.dlopen` and native extensions *inside the root* taint; installed extensions are covered only by dist version. |
| C-level `getenv` (`TZ` in `time`, `LANG`/`LC_*` in `locale`), `os.environ._data`, `posix.environ` | `TZ` and interpreter/pytest variables (`PYTHON*`, `PYTEST_ADDOPTS`, `PYTEST_PLUGINS`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD`) are always emitted as `env`. Others: documented limitation. |
| `posix.stat` / `nt.stat` called directly, or `os.stat` bound before the plugin loaded | Documented limitation. The plugin loads before any user module, so only pre-loaded third-party code could hold an early binding. |
| `DirEntry.stat()`/`is_file()` after `scandir` | Directory listing is recorded (names + types); sizes/contents are not. Documented. |
| Symlink structure seen only through `realpath` | Symlinks inside the root are recorded; outside the root ignored. vci-core follows symlink hops when hashing. |
| Reads via stdlib-only stacks (no user frame) | Ignored by design (pytest bookkeeping). pytest's semantic lookups are added explicitly (F3). |
| Non-`FileFinder` import hooks (custom meta path finders, zipimport) | Hits are recorded (`exec`/`sys.modules`); misses are not. Zip `sys.path` entries inside the root are `read`. Documented. |
| Pre-plugin imports through a `pythonpath` entry when another `-p` plugin loads first | Over-approximated: all pre-loaded names probed in those entries (F4). |
| Case-insensitive filesystems | A probe of `src/Foo.py` while `src/foo.py` exists makes vci-core report `ProbeExists` -> non-attestable (fail-safe). |
| Platform-specific extension suffixes in probes (`.cpython-314-darwin.so`) | A Linux-only suffix file created later is not probed by a macOS attestation. Loading it would still taint on the machine that loads it; relevant only under `platform = "any"`. |
| `sys.path` entries outside root, venv and stdlib (`.pth` to another checkout, `PYTHONPATH`) | Taint (`sys.path-outside-root:`, `env:PYTHONPATH-entry:`). |
| No pytest config file, or a `pyproject.toml` without `[tool.pytest...]` | Taint: pytest then searched every ancestor up to `/` for config. |
| Threads outliving the session, work after `pytest_sessionfinish` | Not recorded. Documented. |
| Time, randomness, locale, hostname | Not inputs in this model (same as the Vitest side). Random-order plugins taint unless a seed is passed. |
| Tests reading the pytest cache (`cache` fixture, `config.cache.get` of non-`cache/` keys, `cache.mkdir`) | Taint. `--lf/--ff/--nf/--sw/--sw-skip`, xdist, reruns -> taint. |
| More than one test file or a `file::test` selection in one process | Taint (`pytest:multiple-test-files-in-process`, `pytest:partial-file-selection`). |
| Subinterpreters, multiprocessing, subprocess, sockets | Taint (F5). |

## Output (as emitted)

Real output for `tests/test_b.py` (root shortened to `/R`; 376 `probe` lines omitted):

```
{"v":1,"kind":"meta","testId":"tests/test_b.py","adapter":"pytest","python":"3.14.7","implementation":"cpython","pytest":"9.1.1","root":"/R","platform":"darwin","arch":"arm64","collector":"vci_pytest@0.1.0"}
{"kind":"module","path":"/R/src/b.py","via":"finder"}
{"kind":"module","path":"/R/tests/conftest.py","via":"finder"}
{"kind":"module","path":"/R/tests/test_b.py","via":"finder"}
{"kind":"external","name":"iniconfig","version":"2.3.0"}
{"kind":"external","name":"pluggy","version":"1.6.0"}
{"kind":"external","name":"pygments","version":"2.21.0"}
{"kind":"external","name":"pytest","version":"9.1.1"}
{"kind":"read","path":"/R/.python-version"}
{"kind":"read","path":"/R/fixtures/b.json"}
{"kind":"read","path":"/R/pyproject.toml"}
{"kind":"read","path":"/R/uv.lock"}
{"kind":"probe","path":"/R/tests/b/__init__.py"}          (one of 376)
{"kind":"env","key":"PYTEST_ADDOPTS"}                     (15 explicit keys: PYTEST_*, PYTHON*, TZ)
{"kind":"result","state":"passed","tests":1,"failed":0,"skipped":0,"durationMs":65,"deselected":0,"exitStatus":0}
```

Differences from the Vitest record in `docs/CONTRACTS.md`:

- `meta` has `adapter`, `python`, `implementation`, `pytest`, `platform`, `arch`, `collector` instead of
  `project`, `vitest`, `vite`, `node`. `root` is the realpath of pytest's rootdir; all root paths use that prefix.
- New kind `{"kind":"write","path":...}` for writes/deletes/renames/mkdir inside the root. **The current Rust parser
  (`crates/vci-adapter/src/jsonl.rs`) does not know it and turns it into `vci:unknown-record-kind:write`, i.e. a
  taint**, which is the intended effect until it is handled explicitly.
- `module.via` values: `finder`, `exec`, `sys.modules`, `pytest-plugin`, `test-file`, `conftest`.
- `result` has extra `deselected` and `exitStatus`. `state` is `passed` only if exit status is 0, nothing failed
  or errored (collection errors count as failed) and at least one test passed; zero tests or all-skipped is `failed`.
- `external.name` is the PEP 503 normalised distribution name (as in `uv.lock`).
- `env` key `*` means the environment was enumerated (`dict(os.environ)`, `.copy()`, iteration, `len`, `repr`).

## Results

`uv run --project fixtures/pytest-abcd pytest py/pytest-plugin/tests`: 30 passed on 3.14.7; 29 passed + 1 skipped
(`concurrent.interpreters` does not exist) on 3.12.6 and 3.11.14 (fixture copy synced per version, selected with
`VCI_FIXTURE_DIR`). A-D run through `uv run --locked pytest -p vci_pytest` exactly as the adapter would; the other
cases run in a temp copy of the fixture with the fixture's venv outside the root.

Overhead on B: 0.14-0.19 s wall without the plugin, 0.19 s with it (`uv run --locked`, 3 runs each).
3.10 and 3.13 were not tested (not installed).
