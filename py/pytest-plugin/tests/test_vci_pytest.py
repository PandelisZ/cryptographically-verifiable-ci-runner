"""End-to-end tests: run the fixture project through the plugin in subprocesses.

Run from the repository root:

    uv run --project fixtures/pytest-abcd pytest py/pytest-plugin/tests
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
PLUGIN_DIR = REPO / "py" / "pytest-plugin"
# VCI_FIXTURE_DIR lets the suite run against a copy of the fixture synced with another Python.
FIXTURE = Path(os.environ.get("VCI_FIXTURE_DIR") or REPO / "fixtures" / "pytest-abcd").resolve()
VENV_BIN = FIXTURE / ".venv" / ("Scripts" if os.name == "nt" else "bin")


@dataclass
class Records:
    meta: dict
    raw: list
    modules: set = field(default_factory=set)
    reads: set = field(default_factory=set)
    probes: set = field(default_factory=set)
    readdirs: set = field(default_factory=set)
    stats: set = field(default_factory=set)
    writes: set = field(default_factory=set)
    env: set = field(default_factory=set)
    externals: set = field(default_factory=set)
    taints: list = field(default_factory=list)
    result: dict | None = None

    @property
    def root(self) -> Path:
        return Path(self.meta["root"])

    def rel(self, kind: str) -> set:
        """Paths of one kind, relative to the root ('/'-separated); outside paths stay absolute."""
        out = set()
        for p in getattr(self, kind):
            pp = Path(p)
            try:
                out.add(pp.relative_to(self.root).as_posix())
            except ValueError:
                out.add(p)
        return out

    def all_paths(self) -> set:
        return self.modules | self.reads | self.probes | self.readdirs | self.stats | self.writes


def load(out: Path) -> dict:
    res = {}
    for f in sorted(out.glob("*.jsonl")):
        lines = [json.loads(l) for l in f.read_text().splitlines() if l.strip()]
        assert lines[0]["kind"] == "meta", lines[0]
        assert lines[-1]["kind"] == "result", lines[-1]
        r = Records(meta=lines[0], raw=lines)
        for rec in lines[1:]:
            k = rec["kind"]
            if k == "module":
                r.modules.add(rec["path"])
            elif k in ("read", "probe", "readdir", "write", "stat"):
                getattr(r, k + "s").add(rec["path"])
            elif k == "env":
                r.env.add(rec["key"])
            elif k == "external":
                r.externals.add((rec["name"], rec["version"]))
            elif k == "taint":
                r.taints.append(rec["reason"])
            elif k == "result":
                r.result = rec
            else:
                raise AssertionError(f"unexpected record kind {k}: {rec}")
        # file name must be sha256(testId)
        assert f.stem == hashlib.sha256(r.meta["testId"].encode()).hexdigest()
        res[r.meta["testId"]] = r
    return res


def child_env(out: Path, temproot: Path) -> dict:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("PYTEST_", "VCI_", "UV_")) and k not in ("VIRTUAL_ENV", "PYTHONPATH")
    }
    env["PYTHONPATH"] = str(PLUGIN_DIR)
    env["VCI_OUT"] = str(out)
    env["PYTEST_DEBUG_TEMPROOT"] = str(temproot)
    return env


def run(cwd: Path, args: list, out: Path, temproot: Path, via_uv: bool = False):
    temproot.mkdir(parents=True, exist_ok=True)
    if via_uv:
        cmd = ["uv", "run", "--locked", "pytest", "-p", "vci_pytest", *args]
    else:
        # Temp copies reuse the fixture's venv (a venv outside the project root).
        cmd = [str(VENV_BIN / "pytest"), "-p", "vci_pytest", *args]
    p = subprocess.run(cmd, cwd=cwd, env=child_env(out, temproot), capture_output=True, text=True, timeout=120)
    return p


# --------------------------------------------------------------------------- A-D


@pytest.fixture(scope="session")
def abcd(tmp_path_factory):
    """Run each fixture test file in its own process, exactly like the Rust adapter will."""
    base = tmp_path_factory.mktemp("abcd")
    results = {}
    for name in ("a", "b", "c", "d"):
        out = base / f"out-{name}"
        p = run(FIXTURE, [f"tests/test_{name}.py"], out, base / "temproot", via_uv=True)
        assert p.returncode == 0, p.stdout + p.stderr
        recs = load(out)
        assert list(recs) == [f"tests/test_{name}.py"], recs.keys()
        results[name] = recs[f"tests/test_{name}.py"]
    return results


def test_meta(abcd):
    import platform

    m = abcd["a"].meta
    assert m["v"] == 1 and m["adapter"] == "pytest"
    assert m["root"] == os.path.realpath(FIXTURE)
    assert m["pytest"] == pytest.__version__
    assert m["python"] == platform.python_version()
    assert m["implementation"] == sys.implementation.name
    assert m["platform"] == sys.platform
    assert m["arch"] == platform.machine()


def test_abcd_pass_untainted_and_inside_root(abcd):
    for name, r in abcd.items():
        assert r.taints == [], (name, r.taints)
        assert r.result["state"] == "passed" and r.result["tests"] == 1 and r.result["failed"] == 0
        root = str(r.root) + os.sep
        outside = {p for p in r.all_paths() if not p.startswith(root)}
        assert outside == set(), (name, outside)  # the Rust side rejects anything outside the root
        assert "*" not in r.env


def test_b_reads_fixture(abcd):
    b = abcd["b"]
    assert "fixtures/b.json" in b.rel("reads")
    assert "src/b.py" in b.rel("modules")


def test_c_computed_import(abcd):
    c = abcd["c"]
    assert {"src/c.py", "src/pkg/__init__.py", "src/pkg/impl_x.py"} <= c.rel("modules")
    # a sibling implementation that does not exist yet is a recorded probe of the import lookup
    assert "src/pkg/impl_x/__init__.py" in c.rel("probes")


def test_d_external_exact_version(abcd):
    lock = (FIXTURE / "uv.lock").read_text()
    i = lock.index('name = "idna"')
    version = lock[i:].split('version = "', 1)[1].split('"', 1)[0]
    assert ("idna", version) in abcd["d"].externals
    assert "src/d.py" in abcd["d"].rel("modules")


def test_no_cross_contamination(abcd):
    a = abcd["a"]
    paths = {Path(p).relative_to(a.root).as_posix() for p in a.modules | a.reads}
    assert "fixtures/b.json" not in paths
    assert not any(p.startswith("src/pkg/") for p in paths)
    assert not {"src/b.py", "src/c.py", "src/d.py"} & paths
    assert not any(n == "idna" for n, _ in a.externals)
    assert "fixtures/b.json" not in abcd["c"].rel("reads") | abcd["d"].rel("reads")
    assert "src/pkg/impl_x.py" not in abcd["b"].rel("modules") | abcd["d"].rel("modules")


def test_conftest_and_config_inputs_everywhere(abcd):
    for name, r in abcd.items():
        assert "tests/conftest.py" in r.rel("modules"), name
        assert f"tests/test_{name}.py" in r.rel("modules"), name
        assert {"pyproject.toml", "uv.lock"} <= r.rel("reads"), name
        # pytest's own lookups: a conftest.py / pytest.ini / __init__.py appearing later changes collection
        assert {"conftest.py", "pytest.ini", "tests/__init__.py", "tests/pytest.ini"} <= r.rel("probes"), name
        assert "PYTEST_ADDOPTS" in r.env


# --------------------------------------------------------------------------- temp copy

EXTRA_FILES = {
    "data/pathlib.txt": "p\n",
    "data/io.txt": "i\n",
    "data/bound.txt": "b\n",
    "data/module_level.txt": "m\n",
    "data/config.json": '{"k": 1}\n',
    "data/fd.txt": "fd\n",
    "src/helper_cfg.py": """
        import json
        from pathlib import Path

        # read at import time, i.e. during collection
        CONFIG = json.loads((Path(__file__).resolve().parent.parent / "data" / "config.json").read_text())
    """,
    "tests/test_subprocess.py": """
        import subprocess, sys

        def test_spawn():
            subprocess.run([sys.executable, "-c", "pass"], check=True)
    """,
    "tests/test_socket.py": """
        import socket

        def test_socket():
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            cli = socket.create_connection(srv.getsockname())
            cli.close()
            srv.close()
    """,
    "tests/test_probe.py": """
        import os
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent.parent

        def test_missing():
            assert not os.path.exists(ROOT / "does-not-exist.txt")
            assert not (ROOT / "missing-dir" / "x.json").is_file()
            try:
                import optional_helper  # noqa: F401
            except ImportError:
                pass
    """,
    "tests/test_listdir.py": """
        import os
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent.parent

        def test_listdir():
            assert "b.json" in os.listdir(ROOT / "fixtures")
            assert sorted(p.name for p in (ROOT / "data").glob("*.json")) == ["config.json"]
    """,
    "tests/test_env.py": """
        import os

        def test_env():
            os.environ.get("FOO")
            os.getenv("BAR_GETENV")
            "BAZ_CONTAINS" in os.environ
            try:
                os.environ["QUX_ITEM"]
            except KeyError:
                pass
    """,
    "tests/test_env_iter.py": """
        import os

        def test_env_iter():
            assert isinstance(dict(os.environ), dict)
    """,
    "tests/test_reads.py": """
        import io
        import os
        from builtins import open as bound_open  # bound at import time, before any patching could matter
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent.parent
        MODULE_LEVEL = (ROOT / "data" / "module_level.txt").read_text()  # read during collection

        def test_reads():
            assert (ROOT / "data" / "pathlib.txt").read_text() == "p\\n"
            with io.open(ROOT / "data" / "io.txt") as f:
                assert f.read() == "i\\n"
            with bound_open(ROOT / "data" / "bound.txt") as f:
                assert f.read() == "b\\n"
            dfd = os.open(ROOT / "data", os.O_RDONLY)
            try:
                fd = os.open("fd.txt", os.O_RDONLY, dir_fd=dfd)
                assert os.read(fd, 10) == b"fd\\n"
                os.close(fd)
            finally:
                os.close(dfd)
    """,
    "tests/test_import_read.py": """
        from helper_cfg import CONFIG

        def test_cfg():
            assert CONFIG["k"] == 1
    """,
    "tests/test_fail.py": """
        def test_fail():
            assert 1 == 2

        def test_ok():
            pass
    """,
    "tests/test_write.py": """
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent.parent

        def test_write():
            (ROOT / "generated.txt").write_text("x")
    """,
    "tests/test_tmp_path.py": """
        import tempfile
        from pathlib import Path

        def test_tmp(tmp_path):
            (tmp_path / "x.txt").write_text("x")
            assert (tmp_path / "x.txt").read_text() == "x"
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "y").write_text("y")
                assert (Path(d) / "y").exists()
    """,
    "tests/test_ctypes.py": """
        import ctypes, ctypes.util

        def test_dlopen():
            ctypes.CDLL(ctypes.util.find_library("c"))
    """,
    "tests/test_mp.py": """
        import multiprocessing as mp

        def test_process():
            p = mp.get_context("spawn").Process(target=print)
            p.start()
            p.join()
    """,
    "tests/test_native.py": """
        def test_native_extension_lookup():
            try:
                import fakeext  # noqa: F401  (an invalid .so inside the root)
            except ImportError:
                pass
    """,
    "tests/test_asyncio.py": """
        import asyncio

        def test_loop():
            async def main():
                await asyncio.sleep(0)
                return 1

            assert asyncio.run(main()) == 1
    """,
    "tests/test_subinterp.py": """
        import pytest

        interpreters = pytest.importorskip("concurrent.interpreters")

        def test_subinterpreter():
            i = interpreters.create()
            i.exec("x = 1")
            i.close()
    """,
    "tests/test_empty.py": """
        # no tests
    """,
    "tests/test_skip_all.py": """
        import pytest

        @pytest.mark.skip(reason="x")
        def test_skipped():
            pass
    """,
    # ---- regressions from adversarial verification (false skips) ----
    "data/thread.txt": "1\n",
    "data/thread_map.txt": "1\n",
    "tests/test_thread.py": """
        import asyncio
        import os
        from concurrent.futures import ThreadPoolExecutor
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent.parent

        def test_thread():
            with ThreadPoolExecutor(1) as ex:
                assert ex.submit((ROOT / "data" / "thread.txt").read_text).result() == "1\\n"
                assert list(ex.map(Path.read_text, [ROOT / "data" / "thread_map.txt"])) == ["1\\n"]
                assert ex.submit(os.getenv, "THREAD_FLAG", "on").result() == "on"

            async def main():
                return await asyncio.to_thread(os.getenv, "TO_THREAD_FLAG", "on")

            assert asyncio.run(main()) == "on"
    """,
    "data/cases/one.txt": "1\n",
    "data/cases/two.txt": "1\n",
    "data/lazy.txt": "1\n",
    "tests/test_lazy_param.py": """
        import glob
        from pathlib import Path

        import pytest

        ROOT = Path(__file__).resolve().parent.parent
        CASES = ROOT / "data" / "cases"

        @pytest.mark.parametrize("case", CASES.glob("*.txt"))
        def test_glob(case):
            assert case.name.endswith(".txt")

        @pytest.mark.parametrize("case", glob.iglob(str(CASES / "*.txt")))
        def test_iglob(case):
            assert case.endswith(".txt")

        @pytest.mark.parametrize("text", map(Path.read_text, [ROOT / "data" / "lazy.txt"]))
        def test_map(text):
            assert text == "1\\n"
    """,
    "data/sym_src.txt": "s\n",
    "data/symdir/x.txt": "x\n",
    "tests/test_symlink.py": """
        import os
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent.parent

        def test_symlink(tmp_path):
            os.symlink(ROOT / "data" / "sym_src.txt", tmp_path / "l")
            assert (tmp_path / "l").read_text() == "s\\n"
            os.symlink(ROOT / "data" / "symdir", tmp_path / "d")
            assert os.listdir(tmp_path / "d") == ["x.txt"]
    """,
    "tests/test_shadow_stdlib.py": """
        def test_hash():
            import hashlib
            import sysconfig
            assert hashlib.sha256(b"").hexdigest().startswith("e3b0")
            assert sysconfig.get_python_version()
    """,
    "tests/test_realpath.py": """
        import os
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent.parent

        def test_realpath():
            assert (ROOT / "data" / "ghost").resolve() == ROOT / "data" / "ghost"
            assert os.path.realpath(ROOT / "data" / "pathlib.txt") == str(ROOT / "data" / "pathlib.txt")
            assert (ROOT / "data").resolve() == ROOT / "data"
    """,
    "data/data.pyc": "\x01",
    "tests/test_pyc_data.py": """
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent.parent

        def test_pyc():
            assert (ROOT / "data" / "data.pyc").read_bytes() == b"\\x01"
    """,
    "tests/test_venv_cfg.py": """
        import sys
        from pathlib import Path

        def test_cfg():
            assert "home" in (Path(sys.prefix) / "pyvenv.cfg").read_text()
    """,
    "tests/test_cache_key.py": """
        def test_cache(request):
            assert request.config.cache.get("cache/lastfailed", {}) is not None
    """,
    "tests/test_cache_dir.py": """
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent.parent

        def test_cache_dir():
            p = ROOT / ".pytest_cache" / "v" / "cache" / "lastfailed"
            assert not p.exists() or p.read_text() is not None
    """,
    "tests/test_sqlite_attach.py": """
        import sqlite3
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent.parent

        def test_attach(tmp_path):
            con = sqlite3.connect(":memory:")
            con.execute("ATTACH DATABASE ? AS o", (str(tmp_path / "other.db"),))
            con.close()
    """,
    "tests/test_sqlite_repo.py": """
        import sqlite3
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent.parent

        def test_repo_db():
            con = sqlite3.connect(ROOT / "data" / "repo.db")
            con.execute("select 1")
            con.close()
    """,
    "tests/test_partly_skipped.py": """
        import sys
        import pytest

        def test_ok():
            pass

        @pytest.mark.skipif(sys.platform != "nonexistent-os", reason="other platforms only")
        def test_other_platform():
            assert False
    """,
}


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    dst = tmp_path_factory.mktemp("proj") / "pytest-abcd"
    shutil.copytree(FIXTURE, dst, ignore=shutil.ignore_patterns(".venv", ".pytest_cache", "__pycache__"))
    import importlib.machinery

    (dst / "src" / ("fakeext" + importlib.machinery.EXTENSION_SUFFIXES[0])).write_bytes(b"not a real extension")
    for rel, body in EXTRA_FILES.items():
        p = dst / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body).lstrip())
    import sqlite3

    con = sqlite3.connect(dst / "data" / "repo.db")
    con.execute("create table t (v integer)")
    con.commit()
    con.close()
    return dst


@pytest.fixture
def run_one(project, tmp_path):
    def go(*args, expect_rc=None):
        out = tmp_path / "out"
        p = run(project, list(args), out, tmp_path / "temproot")
        if expect_rc is not None:
            assert p.returncode == expect_rc, p.stdout + p.stderr
        recs = load(out)
        assert recs, p.stdout + p.stderr
        return recs

    return go


def one(recs: dict) -> Records:
    assert len(recs) == 1, list(recs)
    return next(iter(recs.values()))


def test_copy_with_external_venv_is_clean(run_one):
    r = one(run_one("tests/test_b.py", expect_rc=0))
    assert r.taints == []
    assert "fixtures/b.json" in r.rel("reads")
    root = str(r.root) + os.sep
    assert {p for p in r.all_paths() if not p.startswith(root)} == set()


def test_subprocess_taints(run_one):
    r = one(run_one("tests/test_subprocess.py", expect_rc=0))
    assert "subprocess.Popen" in r.taints


def test_socket_taints(run_one):
    r = one(run_one("tests/test_socket.py", expect_rc=0))
    assert {"socket.bind", "socket.connect"} <= set(r.taints), r.taints


def test_missing_paths_are_probes(run_one):
    r = one(run_one("tests/test_probe.py", expect_rc=0))
    probes = r.rel("probes")
    assert {"does-not-exist.txt", "missing-dir/x.json"} <= probes
    # failed optional import: every candidate on sys.path inside the root
    assert {"src/optional_helper.py", "src/optional_helper/__init__.py", "tests/optional_helper.py"} <= probes
    assert r.taints == []


def test_listdir_and_glob_are_readdirs(run_one):
    r = one(run_one("tests/test_listdir.py", expect_rc=0))
    assert {"fixtures", "data"} <= r.rel("readdirs")


def test_env_reads(run_one):
    r = one(run_one("tests/test_env.py", expect_rc=0))
    assert {"FOO", "BAR_GETENV", "BAZ_CONTAINS", "QUX_ITEM"} <= r.env
    assert "*" not in r.env


def test_env_enumeration_is_star(run_one):
    r = one(run_one("tests/test_env_iter.py", expect_rc=0))
    assert "*" in r.env


def test_reads_via_pathlib_io_bound_open_and_dir_fd(run_one):
    r = one(run_one("tests/test_reads.py", expect_rc=0))
    assert {
        "data/pathlib.txt",
        "data/io.txt",
        "data/bound.txt",
        "data/module_level.txt",
        "data/fd.txt",
    } <= r.rel("reads")
    assert r.taints == []


def test_import_time_read_during_collection(run_one):
    r = one(run_one("tests/test_import_read.py", expect_rc=0))
    assert "data/config.json" in r.rel("reads")
    assert "src/helper_cfg.py" in r.rel("modules")


def test_failing_test_gives_failed_state(run_one):
    r = one(run_one("tests/test_fail.py", expect_rc=1))
    assert r.result["state"] == "failed"
    assert r.result["tests"] == 2 and r.result["failed"] == 1


def test_write_inside_root(run_one):
    r = one(run_one("tests/test_write.py", expect_rc=0))
    assert "generated.txt" in r.rel("writes")


def test_tmp_path_and_tempfile_are_not_inputs(run_one):
    r = one(run_one("tests/test_tmp_path.py", expect_rc=0))
    assert r.taints == []
    root = str(r.root) + os.sep
    assert {p for p in r.all_paths() if not p.startswith(root)} == set()


def test_ctypes_dlopen_taints(run_one):
    r = one(run_one("tests/test_ctypes.py", expect_rc=0))
    assert any(t.startswith("ctypes.dlopen:") for t in r.taints), r.taints


def test_multiprocessing_taints(run_one):
    r = one(run_one("tests/test_mp.py", expect_rc=0))
    assert any(t.startswith("multiprocessing:") or t == "_posixsubprocess.fork_exec" for t in r.taints), r.taints


def test_zero_tests_is_failed(run_one):
    r = one(run_one("tests/test_empty.py", expect_rc=5))
    assert r.meta["testId"] == "tests/test_empty.py"
    assert r.result["state"] == "failed" and r.result["tests"] == 0


def test_all_skipped_is_not_passed(run_one):
    r = one(run_one("tests/test_skip_all.py", expect_rc=0))
    assert r.result["state"] == "failed" and r.result["skipped"] == 1


def test_two_files_in_one_process_taint(run_one):
    recs = run_one("tests/test_a.py", "tests/test_b.py", expect_rc=0)
    assert set(recs) == {"tests/test_a.py", "tests/test_b.py"}
    for r in recs.values():
        assert "pytest:multiple-test-files-in-process" in r.taints


def test_node_selection_taints(run_one):
    r = one(run_one("tests/test_fail.py::test_ok", expect_rc=0))
    assert "pytest:partial-file-selection" in r.taints


def test_cache_dependent_options_taint(run_one):
    r = one(run_one("--lf", "tests/test_a.py", expect_rc=0))
    assert "pytest:--lf" in r.taints


def test_native_extension_in_root_taints(run_one):
    r = one(run_one("tests/test_native.py", expect_rc=0))
    assert any(t.startswith("native-extension-in-root:src/fakeext") for t in r.taints), r.taints


def test_asyncio_does_not_taint(run_one):
    r = one(run_one("tests/test_asyncio.py", expect_rc=0))
    assert r.taints == []


def test_python_dash_m_records_startup_import_shadowing(project, tmp_path):
    """`python -m pytest` puts the cwd (the root) first on sys.path before the plugin loads."""
    out = tmp_path / "out"
    env = child_env(out, tmp_path / "temproot")
    p = subprocess.run(
        [str(VENV_BIN / "python"), "-m", "pytest", "-p", "vci_pytest", "tests/test_a.py"],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    r = one(load(out))
    probes = r.rel("probes")
    # modules imported before vci_pytest was loaded would be shadowed by these files
    assert {"pytest.py", "_pytest/__init__.py", "pluggy.py", "argparse.py"} <= probes
    assert r.taints == []


def test_subinterpreter_taints(run_one):
    r = one(run_one("tests/test_subinterp.py"))
    if r.result["skipped"] or r.result["tests"] == 0:  # module-level importorskip
        pytest.skip("concurrent.interpreters not available on this Python")
    assert any(t.startswith("subinterpreter:") for t in r.taints), r.taints


# --------------------------------------------------------------------------- regressions
# Each of these reproduced a false skip found by adversarial verification.


def test_worker_thread_reads_and_env_are_recorded(run_one):
    r = one(run_one("tests/test_thread.py", expect_rc=0))
    assert {"data/thread.txt", "data/thread_map.txt"} <= r.rel("reads"), r.rel("reads")
    assert {"THREAD_FLAG", "TO_THREAD_FLAG"} <= r.env, r.env
    assert r.taints == []


def test_lazy_parametrize_iterables_are_recorded(run_one, project, tmp_path):
    r = one(run_one("tests/test_lazy_param.py", expect_rc=0))
    assert "data/cases" in r.rel("readdirs"), r.rel("readdirs")
    assert "data/lazy.txt" in r.rel("reads"), r.rel("reads")

    # The collector must not change pytest's own behaviour: the same warnings
    # (naming the iterable's type) are emitted with and without it.
    def warnings_of(extra):
        p = subprocess.run(
            [str(VENV_BIN / "pytest"), *extra, "-q", "-W", "always", "tests/test_lazy_param.py"],
            cwd=project,
            env=child_env(tmp_path / "out2", tmp_path / "temproot2"),
            capture_output=True,
            text=True,
            timeout=120,
        )
        return sorted(l for l in p.stdout.splitlines() if "RemovedIn" in l or "non-Collection" in l)

    assert warnings_of(["-p", "vci_pytest"]) == warnings_of([])


def test_symlink_into_repo_from_tmp_path_is_recorded(run_one):
    r = one(run_one("tests/test_symlink.py", expect_rc=0))
    assert "data/sym_src.txt" in r.rel("reads"), r.rel("reads")
    assert "data/symdir" in r.rel("readdirs"), r.rel("readdirs")
    assert r.taints == []
    root = str(r.root) + os.sep
    assert {p for p in r.all_paths() if not p.startswith(root)} == set()


def test_stdlib_modules_are_not_preloaded_by_the_collector(run_one):
    """A module the collector imported itself would never be looked up by the test,
    so a shadowing src/hashlib.py created later would go unnoticed."""
    r = one(run_one("tests/test_shadow_stdlib.py", expect_rc=0))
    probes = r.rel("probes")
    for name in ("hashlib", "sysconfig"):
        assert {f"src/{name}.py", f"tests/{name}.py"} <= probes, (name, sorted(p for p in probes if name in p))


def test_realpath_records_missing_and_regular_components(run_one):
    r = one(run_one("tests/test_realpath.py", expect_rc=0))
    assert "data/ghost" in r.rel("probes"), r.rel("probes")
    assert "data/pathlib.txt" in r.rel("reads") | r.rel("stats"), r.rel("reads")
    assert "data" in r.rel("stats"), r.rel("stats")
    assert r.taints == []


def test_user_reads_of_pyc_files_are_recorded(run_one):
    r = one(run_one("tests/test_pyc_data.py", expect_rc=0))
    assert "data/data.pyc" in r.rel("reads"), r.rel("reads")
    assert not any("__pycache__" in p for p in r.rel("reads") | r.rel("writes")), r.rel("reads")


def test_unowned_environment_file_read_taints(run_one):
    r = one(run_one("tests/test_venv_cfg.py", expect_rc=0))
    assert any(t.startswith("unmapped-env-read:") and t.endswith("pyvenv.cfg") for t in r.taints), r.taints


def test_user_cache_key_read_taints(run_one):
    r = one(run_one("tests/test_cache_key.py", expect_rc=0))
    assert any(t.startswith("pytest:cache.get:cache/lastfailed") for t in r.taints), r.taints


def test_user_cache_dir_access_taints(run_one):
    r = one(run_one("tests/test_cache_dir.py", expect_rc=0))
    assert any(t.startswith("pytest:cache-dir-access") for t in r.taints), r.taints


def test_sqlite_attach_taints(run_one):
    r = one(run_one("tests/test_sqlite_attach.py", expect_rc=0))
    assert "sqlite3:attach" in r.taints, r.taints


def test_sqlite_database_in_repository_taints(run_one):
    r = one(run_one("tests/test_sqlite_repo.py", expect_rc=0))
    assert any(t.startswith("sqlite3:database-in-repository:") for t in r.taints), r.taints


def test_partly_skipped_file_reports_skips(run_one):
    r = one(run_one("tests/test_partly_skipped.py", expect_rc=0))
    assert r.result["skipped"] == 1 and r.result["failed"] == 0


def test_plugin_from_addopts_imported_before_collector_taints(project, tmp_path):
    """`addopts = "-p myplug"` is imported before the command line's `-p vci_pytest`,
    so what it read at import time was never seen."""
    dst = tmp_path / "addopts-proj"
    shutil.copytree(project, dst, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    pp = dst / "pyproject.toml"
    pp.write_text(pp.read_text().replace('testpaths = ["tests"]', 'testpaths = ["tests"]\naddopts = "-p myplug"'))
    (dst / "src" / "myplug.py").write_text(
        "from pathlib import Path\nDATA = (Path(__file__).resolve().parent.parent / 'data' / 'io.txt').read_text()\n"
    )
    out = tmp_path / "out"
    p = run(dst, ["tests/test_a.py"], out, tmp_path / "temproot")
    assert p.returncode == 0, p.stdout + p.stderr
    r = one(load(out))
    assert any(t.startswith("pytest:plugin-imported-before-collector:myplug") for t in r.taints), r.taints


def test_hot_patched_distribution_file_is_detected(tmp_path):
    """A site-packages file edited in place keeps its distribution's version; the
    collector compares every file it maps to a distribution with its RECORD hash."""
    import base64
    import importlib.metadata

    sys.path.insert(0, str(PLUGIN_DIR))
    try:
        from vci_pytest import _collector
    finally:
        sys.path.remove(str(PLUGIN_DIR))
    site = tmp_path / "site-packages"
    (site / "mylib").mkdir(parents=True)
    src = b"VALUE = 1\n"
    (site / "mylib" / "__init__.py").write_bytes(src)
    info = site / "mylib-1.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text("Metadata-Version: 2.1\nName: MyLib\nVersion: 1.0\n")
    digest = base64.urlsafe_b64encode(hashlib.sha256(src).digest()).rstrip(b"=").decode()
    (info / "RECORD").write_text(
        f"mylib/__init__.py,sha256={digest},{len(src)}\nmylib-1.0.dist-info/METADATA,,\nmylib-1.0.dist-info/RECORD,,\n"
    )
    idx = _collector._DistIndex([importlib.metadata.PathDistribution(info)])
    f = str(site / "mylib" / "__init__.py")
    assert idx.lookup(f) == ("mylib", "1.0")
    assert idx.modified(f) is False
    assert idx.modified(str(info / "METADATA")) is False  # no hash recorded
    (site / "mylib" / "__init__.py").write_bytes(b"VALUE = 2\n")
    idx2 = _collector._DistIndex([importlib.metadata.PathDistribution(info)])
    assert idx2.modified(f) is True
