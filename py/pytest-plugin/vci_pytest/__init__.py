"""vci pytest collector plugin.

Usage (one pytest process per test file)::

    PYTHONPATH=<abs path to py/pytest-plugin> VCI_OUT=<dir> uv run pytest -p vci_pytest tests/test_b.py

Writes ``$VCI_OUT/<sha256(testId)>.jsonl``. Without ``VCI_OUT`` the plugin is inert.
Collection hooks are installed at import time, which with ``-p`` happens before
entry-point plugins, conftest files and test modules are imported.
"""

from __future__ import annotations

import sys

# Everything imported from here on exists only because of this plugin; the
# collector adds the import lookups a plain run would have made for them.
_BEFORE = frozenset(sys.modules)

import os  # noqa: E402

from . import _collector  # noqa: E402

_OUT = os.environ.get("VCI_OUT")
_C = _collector.install(_OUT) if _OUT else None

if _C is not None:
    import pytest

    _C.own_modules.update(n for n in set(sys.modules) - _BEFORE if isinstance(n, str))

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

    def _user_on_stack() -> bool:
        if not _C.active or _collector._busy():
            return False
        return _C.stack()[1]

    def _wrap_cache() -> None:
        """Tests that read the pytest cache depend on state outside the checkout.

        Decided by the stack, not the key: pytest reads ``cache/lastfailed``
        itself, but a test (or conftest) reading it is using that state."""
        try:
            from _pytest.cacheprovider import Cache
        except Exception:
            return
        if getattr(Cache, "_vci_wrapped", False):
            return
        orig_get = Cache.get
        orig_mkdir = Cache.mkdir

        def get(self, key, default):
            if _user_on_stack():
                _C.taint(f"pytest:cache.get:{key}")
            return orig_get(self, key, default)

        def mkdir(self, name):
            if _user_on_stack():
                _C.taint(f"pytest:cache.mkdir:{name}")
            return orig_mkdir(self, name)

        Cache.get = get
        Cache.mkdir = mkdir
        Cache._vci_wrapped = True

    def _user_contexts() -> None:
        """pytest consumes the ``argvalues`` and ``ids`` given to parametrize in
        its own frames; when they are lazy iterables (a generator, ``map``,
        ``Path.glob``, ``glob.iglob``) the reads and listings they do would look
        like pytest's bookkeeping. Everything below these pytest functions on
        the stack is attributed to the test instead. (Nothing is wrapped, so
        pytest's behaviour and warnings are unchanged.)"""
        codes = set()
        try:
            from _pytest.mark.structures import ParameterSet
            from _pytest.python import Metafunc

            for fn in (
                getattr(ParameterSet, "_for_parametrize", None),
                getattr(ParameterSet, "_parse_parametrize_parameters", None),
                getattr(Metafunc, "_validate_ids", None),
            ):
                fn = getattr(fn, "__func__", fn)
                code = getattr(fn, "__code__", None)
                if code is not None:
                    codes.add(code)
        except Exception:
            pass
        if len(codes) < 3:
            _C.taint("vci:cannot-find-parametrize-internals")
        _C.user_ctx_codes = frozenset(codes)

    _user_contexts()

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
