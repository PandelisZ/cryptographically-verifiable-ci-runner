"""vci pytest collector plugin.

Usage (one pytest process per test file)::

    PYTHONPATH=<abs path to py/pytest-plugin> VCI_OUT=<dir> uv run pytest -p vci_pytest tests/test_b.py

Writes ``$VCI_OUT/<sha256(testId)>.jsonl``. Without ``VCI_OUT`` the plugin is inert.
Collection hooks are installed at import time, which with ``-p`` happens before
entry-point plugins, conftest files and test modules are imported.
"""

from __future__ import annotations

import os
import sys

from . import _collector

_OUT = os.environ.get("VCI_OUT")
_C = _collector.install(_OUT) if _OUT else None

if _C is not None:
    import pytest

    def _snap_path() -> None:
        _C.sys_path_seen.update(p for p in sys.path if isinstance(p, str))

    @pytest.hookimpl(tryfirst=True)
    def pytest_load_initial_conftests(early_config, parser, args):
        _C.config = early_config
        _snap_path()

    @pytest.hookimpl(trylast=True)
    def pytest_configure(config):
        _C.config = config
        _snap_path()
        _wrap_cache()

    def _wrap_cache() -> None:
        """Tests that read the pytest cache depend on state outside the checkout."""
        try:
            from _pytest.cacheprovider import Cache
        except Exception:
            return
        if getattr(Cache, "_vci_wrapped", False):
            return
        orig_get = Cache.get
        orig_mkdir = Cache.mkdir

        def get(self, key, default):
            if not str(key).startswith("cache/"):
                _C.taint(f"pytest:cache.get:{key}")
            return orig_get(self, key, default)

        def mkdir(self, name):
            _C.taint(f"pytest:cache.mkdir:{name}")
            return orig_mkdir(self, name)

        Cache.get = get
        Cache.mkdir = mkdir
        Cache._vci_wrapped = True

    def pytest_itemcollected(item):
        p = getattr(item, "path", None) or getattr(item, "fspath", None)
        if p is not None:
            _C.item_files.add(os.path.normpath(str(p)))

    def pytest_collectreport(report):
        if report.failed:
            _C.collect_errors += 1

    def pytest_deselected(items):
        _C.deselected += len(items)

    def pytest_collection_finish(session):
        _snap_path()

    _RANK = {"passed": 0, "skipped": 1, "failed": 2}

    def pytest_runtest_logreport(report):
        if report.outcome == "rerun":
            _C.taint("pytest:rerun")
            return
        if report.when == "teardown":
            _snap_path()
        nodeid = report.nodeid
        if report.when == "setup":
            outcome = report.outcome
        elif report.when == "call":
            outcome = report.outcome
        else:  # teardown only matters when it fails
            outcome = "failed" if report.failed else None
        prev = _C.items.get(nodeid)
        if outcome is None:
            if prev is None:
                _C.items[nodeid] = "passed"
            return
        if report.when == "call" and prev == "passed":
            _C.items[nodeid] = outcome
        elif prev is None or _RANK.get(outcome, 2) > _RANK.get(prev, 2):
            _C.items[nodeid] = outcome

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(session, exitstatus):
        _collector.finalize(session, exitstatus)
