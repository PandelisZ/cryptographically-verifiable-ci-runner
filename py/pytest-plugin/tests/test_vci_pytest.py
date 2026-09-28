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
        return self.modules | self.reads | self.probes | self.readdirs | self.writes


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
            elif k in ("read", "probe", "readdir", "write"):
                getattr(r, k + ("s" if k != "readdir" else "s")).add(rec["path"])
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
