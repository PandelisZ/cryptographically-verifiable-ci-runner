"""Dependency collector for one pytest process (pure stdlib).

Installed at import time of the plugin (``-p vci_pytest`` imports it before
conftest files, entry-point plugins and collection). It combines:

* a ``sys.addaudithook`` hook: ``open`` (builtins/io/os.open/io.open_code/FileIO),
  ``os.listdir``/``os.scandir``, file-mutating ``os.*`` events, ``exec`` of code
  objects (every Python module body), process/network/ctypes events (taint),
  ``tempfile.mkstemp``/``tempfile.mkdtemp`` (self-produced temp files);
* wrappers on ``os.stat``/``os.lstat``/``os.access``/``os.readlink``/``os.open``,
  which also cover ``os.path.exists/isfile/isdir/...`` and ``pathlib`` because those
  look ``os.stat`` up at call time; failures with ENOENT/ENOTDIR become probes;
* a wrapper on ``importlib.machinery.FileFinder.find_spec`` that records, per
  import lookup in a directory, every candidate path the finder could have used
  (so a module created later that would shadow or satisfy an import is noticed);
* wrappers on ``os._Environ`` for env reads.

Fail-open rules: anything we cannot classify is recorded; anything we cannot
track at all becomes a ``taint`` record. Activity is ignored only when the
Python stack consists solely of pytest/pluggy/stdlib/plugin frames (pytest's own
bookkeeping); pytest's own *semantic* lookups (ini files, conftest.py and
``__init__.py`` along the test path) are added explicitly at the end.
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.metadata
import json
import os
import platform
import re
import site
import stat as _stat
import sys
import sysconfig
import threading
import time
import types

try:  # macOS: F_GETPATH resolves an fd to its path.
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

VERSION = "0.1.0"
COLLECTOR = f"vci_pytest@{VERSION}"

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ENTRY = os.path.dirname(PKG_DIR)

# Originals, captured before patching.
_o_stat = os.stat
_o_lstat = os.lstat
_o_access = os.access
_o_readlink = os.readlink
_o_open = os.open
_o_getcwd = os.getcwd
_Environ = type(os.environ)
_o_env_getitem = _Environ.__getitem__
_o_env_iter = _Environ.__iter__
_o_env_len = _Environ.__len__
_o_env_repr = _Environ.__repr__
_o_env_copy = _Environ.copy
_o_find_spec = importlib.machinery.FileFinder.find_spec

_tls = threading.local()

# Distributions whose frames count as "the tool" (pytest and its own deps).
TOOL_TOPS = frozenset(
    {
        "_pytest",
        "pytest",
        "pluggy",
        "iniconfig",
        "packaging",
        "pygments",
        "exceptiongroup",
        "tomli",
        "colorama",
        "py",
        "_virtualenv",
        "_distutils_hack",
    }
)
# Venv tooling artifacts in site-packages that belong to no distribution.
UNOWNED_ENV_MODULES = frozenset({"_virtualenv"})

INI_NAMES = (
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
)
# Env vars read by pytest/the interpreter before this plugin could observe them.
EXPLICIT_ENV = (
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    "PYTHONHASHSEED",
    "PYTHONWARNINGS",
    "PYTHONOPTIMIZE",
    "PYTHONDEVMODE",
    "PYTHONUTF8",
    "PYTHONSAFEPATH",
    "PYTHONNOUSERSITE",
    "PYTHONUSERBASE",
    "PYTHONHOME",
    "PYTHONINTMAXSTRDIGITS",
    "PYTHONIOENCODING",
    "TZ",
)

TAINT_EVENTS = frozenset(
    {
        # processes
        "subprocess.Popen",
        "_posixsubprocess.fork_exec",
        "os.system",
        "os.exec",
        "os.fork",
        "os.forkpty",
        "os.posix_spawn",
        "os.spawn",
        "os.startfile",
        "pty.spawn",
        # network
        "socket.connect",
        "socket.bind",
        "socket.sendto",
        "socket.sendmsg",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.getnameinfo",
        "socket.getservbyname",
        "socket.getservbyport",
        "urllib.Request",
        "http.client.connect",
        "ftplib.connect",
        "imaplib.open",
        "nntplib.connect",
        "poplib.connect",
        "smtplib.connect",
        "telnetlib.Telnet.open",
        "webbrowser.open",
    }
)
# (event, index of the path argument(s), index of dir_fd or None)
WRITE_EVENTS = {
    "os.remove": ((0,), 1),
    "os.rmdir": ((0,), 1),
    "os.mkdir": ((0,), 2),
    "os.chmod": ((0,), 2),
    "os.chown": ((0,), 3),
    "os.utime": ((0,), 3),
    "os.mkfifo": ((0,), 2),
    "os.mknod": ((0,), 3),
    "os.truncate": ((0,), None),
    "os.chflags": ((0,), None),
    "os.lchflags": ((0,), None),
    "os.setxattr": ((0,), None),
    "os.removexattr": ((0,), None),
    "os.symlink": ((1,), 2),
    "shutil.rmtree": ((0,), 1),
}

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
_REALPATH_FUNCS = frozenset({"realpath", "_realpath", "_joinrealpath"})


def _norm_dist(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _prefixes(paths) -> tuple:
    out = []
    for p in paths:
        if not p:
            continue
        for q in {os.path.normpath(os.path.abspath(p)), os.path.realpath(p)}:
            if q not in out:
                out.append(q)
    return tuple(out)


def _under(p: str, prefixes) -> bool:
    for pre in prefixes:
        if p == pre or p.startswith(pre if pre.endswith(os.sep) else pre + os.sep):
            return True
    return False


def _is_site_component(p: str) -> bool:
    parts = p.split(os.sep)
    return "site-packages" in parts or "dist-packages" in parts


class _Unresolvable(Exception):
    pass


def _to_str(p):
    if p is None or isinstance(p, int):
        return None
    try:
        p = os.fspath(p)
    except TypeError:
        return None
    if isinstance(p, bytes):
        p = os.fsdecode(p)
    if not isinstance(p, str) or not p or "\0" in p:
        return None
    return p


def _fd_path(fd):
    try:
        fd = int(fd)
        if fcntl is not None and hasattr(fcntl, "F_GETPATH"):
            b = fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(1024))  # MAXPATHLEN; fcntl caps buffers at 1024
            return os.fsdecode(b.split(b"\0", 1)[0])
        if sys.platform.startswith("linux"):
            return _o_readlink(f"/proc/self/fd/{fd}")
    except (OSError, ValueError, TypeError):
        return None
    return None


def _busy() -> bool:
    return getattr(_tls, "busy", False)


class Collector:
    def __init__(self, out_dir: str):
        self.out_dir = os.path.abspath(out_dir)
        self.active = True
        self.t0 = time.perf_counter()
        # raw observations (absolute, lexically normalised paths)
        self.reads: set = set()
        self.probes: set = set()
        self.readdirs: set = set()
        self.writes: set = set()
        self.env: set = set()
        self.taints: dict = {}  # ordered set
        self.modules: dict = {}  # path -> via
        self.finder: set = set()  # (dir, tail, suffixes)
        self.symlink_reads: set = set()
        self.self_dirs: list = []
        self.self_files: set = set()
        self.sys_path_seen: set = set()
        # pytest-side state
        self.config = None
        self.items: dict = {}  # nodeid -> outcome
        self.item_files: set = set()
        self.collect_errors = 0
        self.deselected = 0
        self.finished = False
        self._frame_cache: dict = {}
        self._init_prefixes()
        # Imports done before this plugin loaded (pytest start-up) were looked up on
        # the sys.path of that time without us seeing it; remember where each
        # top-level module came from so the finalizer can add the lookups it implies.
        cwd = _o_getcwd()
        self.preload_path = tuple(os.path.normpath(os.path.join(cwd, e)) for e in sys.path if isinstance(e, str))
        self.preload = []  # (top-level name, directory it was found in or None if unknown)
        for n, m in list(sys.modules.items()):
            if not isinstance(n, str) or "." in n or n == "__main__" or n in sys.builtin_module_names:
                continue
            spec = getattr(m, "__spec__", None)
            origin = getattr(spec, "origin", None)
            if origin in ("built-in", "frozen"):
                continue  # BuiltinImporter/FrozenImporter run before the path finder
            loc = None
            if isinstance(origin, str) and os.path.isabs(origin):
                loc = os.path.dirname(origin)
                if os.path.basename(origin).startswith("__init__."):
                    loc = os.path.dirname(loc)
                loc = os.path.normpath(loc)
            self.preload.append((n, loc))

    # ----- classification helpers -------------------------------------------------

    def _init_prefixes(self):
        stdlib = [os.path.dirname(os.__file__)]
        for key in ("stdlib", "platstdlib"):
            try:
                p = sysconfig.get_paths().get(key)
            except Exception:
                p = None
            # platstdlib can point into the venv; only keep it if it is not a prefix of site dirs
            if p and key == "stdlib":
                stdlib.append(p)
        self.stdlib = _prefixes(stdlib)
        sites = []
        try:
            sites.extend(site.getsitepackages())
        except Exception:
            pass
        try:
            if site.ENABLE_USER_SITE:
                sites.append(site.getusersitepackages())
        except Exception:
            pass
        for key in ("purelib", "platlib"):
            try:
                sites.append(sysconfig.get_paths()[key])
            except Exception:
                pass
        for e in sys.path:
            if e and os.path.basename(os.path.normpath(e)) in ("site-packages", "dist-packages"):
                sites.append(e)
        self.sites = _prefixes(sites)
        venv = []
        if sys.prefix != sys.base_prefix:
            venv.append(sys.prefix)
        if sys.exec_prefix != sys.base_exec_prefix:
            venv.append(sys.exec_prefix)
        self.venv = _prefixes(venv)
        self.base = _prefixes({sys.base_prefix, sys.base_exec_prefix, sys.prefix, sys.exec_prefix})
        # Console-script shims (.venv/bin/pytest) sit at the bottom of every stack.
        scripts = []
        try:
            scripts.append(sysconfig.get_path("scripts"))
        except Exception:
            pass
        for pre in {sys.prefix, sys.exec_prefix}:
            scripts.append(os.path.join(pre, "bin"))
            scripts.append(os.path.join(pre, "Scripts"))
        self.scripts = _prefixes(scripts)
        argv0 = sys.argv[0] if sys.argv else ""
        self.entry_script = None
        if os.path.basename(argv0).split(".")[0] in ("pytest", "py"):
            self.entry_script = os.path.normpath(os.path.abspath(argv0))
        self.pkg = _prefixes([PKG_DIR])
        self.plugin_entry = _prefixes([PLUGIN_ENTRY])
        self.out = _prefixes([self.out_dir])

    def frame_is_tool(self, fn: str) -> bool:
        k = self._frame_cache.get(fn)
        if k is None:
            k = self._classify_frame(fn)
            self._frame_cache[fn] = k
        return k

    def _classify_frame(self, fn: str) -> bool:
        if fn.startswith("<frozen "):
            return True
        if fn.startswith("<"):
            return False  # exec'd / generated code: treat as user code
        p = os.path.normpath(fn) if os.path.isabs(fn) else os.path.normpath(os.path.join(_o_getcwd(), fn))
        if _under(p, self.pkg):
            return True
        if p == self.entry_script or (_under(p, self.scripts) and _under(p, self.venv)):
            return True
        if _under(p, self.stdlib) and not _is_site_component(p):
            return True
        for pre in self.sites:
            if _under(p, (pre,)):
                rel = p[len(pre) :].lstrip(os.sep)
                top = rel.split(os.sep, 1)[0]
                if top.endswith(".py"):
                    top = top[:-3]
                return top in TOOL_TOPS
        return False

    def stack(self):
        """Return (first frame outside this plugin, any user frame on the stack)."""
        f = sys._getframe(1)
        first = None
        user = False
        while f is not None:
            fn = f.f_code.co_filename
            if first is None and not fn.startswith(PKG_DIR):
                first = f
            if not self.frame_is_tool(fn):
                user = True
                break
            f = f.f_back
        if first is None:
            first = f
        return first, user

    def abspath(self, p, dir_fd=None):
        s = _to_str(p)
        if s is None:
            return None
        if not os.path.isabs(s):
            if dir_fd is not None and dir_fd != -1 and not (isinstance(dir_fd, int) and dir_fd < 0):
                base = _fd_path(dir_fd)
                if base is None:
                    raise _Unresolvable(s)
            else:
                base = _o_getcwd()
            s = os.path.join(base, s)
        n = os.path.normpath(s)
        if ".." in s.split(os.sep):
            # Lexical and physical resolution only agree if no symlink precedes the '..'.
            try:
                if os.path.realpath(s) != os.path.realpath(n):
                    self.taint(f"vci:ambiguous-dotdot-path:{s}")
            except OSError:
                pass
        return n

    def taint(self, reason: str):
        self.taints.setdefault(reason, None)

    # ----- event sinks ------------------------------------------------------------

    def fs(self, kind: str, abs_path):
        if abs_path is None:
            return
        getattr(self, kind + "s").add(abs_path)

    def on_open(self, args):
        path = args[0] if args else None
        mode = args[1] if len(args) > 1 else None
        flags = args[2] if len(args) > 2 else 0
        override = getattr(_tls, "open_override", None)
        if override is not None:
            _tls.open_override = None
            if override is False:
                return  # os.open(dir_fd=...) we could not resolve; already tainted
        if isinstance(path, int) or path is None:
            return
        first, user = self.stack()
        if not user:
            return
        abs_path = override if (override is not None and mode is None) else self.abspath(path)
        if isinstance(mode, str):
            write = any(c in mode for c in "wax+")
            reads = "r" in mode or "+" in mode
        else:
            try:
                fl = int(flags or 0)
            except (TypeError, ValueError):
                fl = _WRITE_FLAGS
            write = bool(fl & _WRITE_FLAGS)
            reads = (fl & (os.O_WRONLY | os.O_RDWR)) != os.O_WRONLY
        if write:
            self.fs("write", abs_path)
        if reads:
            self.fs("read", abs_path)

    def on_listdir(self, args):
        p = args[0] if args else "."
        if p is None:
            p = "."
        first, user = self.stack()
        if (
            first is not None
            and first.f_code.co_name == "_fill_cache"
            and "_bootstrap_external" in first.f_code.co_filename
        ):
            return  # FileFinder cache fill: replaced by precise candidate probes
        if not user:
            return
        if isinstance(p, int):
            abs_path = _fd_path(p)
            if abs_path is None:
                self.taint("vci:unresolvable-fd-listing")
                return
        else:
            abs_path = self.abspath(p)
        self.fs("readdir", abs_path)

    def on_write_event(self, event, args):
        idxs, fd_idx = WRITE_EVENTS[event]
        first, user = self.stack()
        if not user:
            return
        dir_fd = args[fd_idx] if fd_idx is not None and len(args) > fd_idx else None
        for i in idxs:
            if len(args) <= i:
                continue
            p = args[i]
            if isinstance(p, int):
                abs_path = _fd_path(p)
                if abs_path is None:
                    self.taint(f"vci:unresolvable-fd:{event}")
                    continue
            else:
                abs_path = self.abspath(p, dir_fd if isinstance(dir_fd, int) else None)
            self.fs("write", abs_path)

    def on_two_path_write(self, event, args):
        # os.rename(src, dst, src_dir_fd, dst_dir_fd) / os.link(src, dst, src_dir_fd, dst_dir_fd)
        first, user = self.stack()
        if not user:
            return
        src = args[0] if args else None
        dst = args[1] if len(args) > 1 else None
        sfd = args[2] if len(args) > 2 else None
        dfd = args[3] if len(args) > 3 else None
        if event == "os.rename":
            self.fs("write", self.abspath(src, sfd))
        else:
            self.fs("read", self.abspath(src, sfd))
        self.fs("write", self.abspath(dst, dfd))

    def on_exec(self, args):
        code = args[0] if args else None
        fn = getattr(code, "co_filename", None)
        if isinstance(fn, str) and os.path.isabs(fn):
            self.modules.setdefault(os.path.normpath(fn), "exec")

    def on_import(self, args):
        name = args[0] if args else ""
        if isinstance(name, str) and (
            name.startswith("multiprocessing.popen_") or name == "multiprocessing.forkserver"
        ):
            self.taint(f"multiprocessing:{name}")

    def on_dlopen(self, args):
        name = args[0] if args else None
        if name is not None:
            self.taint(f"ctypes.dlopen:{os.path.basename(str(name))}")

    def on_sqlite(self, args):
        db = _to_str(args[0] if args else None)
        if not db or db == ":memory:" or db.startswith("file:"):
            if db and db.startswith("file:"):
                self.taint("sqlite3.connect:uri")
            return
        first, user = self.stack()
        if not user:
            return
        p = self.abspath(db)
        try:
            _o_stat(p)
            self.fs("read", p)
        except OSError:
            self.fs("write", p)

    def on_tempdir(self, args):
        p = self.abspath(args[0] if args else None)
        if p:
            self.self_dirs.append(p)

    def on_tempfile(self, args):
        p = self.abspath(args[0] if args else None)
        if p:
            self.self_files.add(p)

    # ----- wrappers ---------------------------------------------------------------

    def on_stat(self, path, dir_fd, result, missing, lstat_call):
        if isinstance(path, int):
            return
        first, user = self.stack()
        if not user:
            return
        abs_path = self.abspath(path, dir_fd)
        if first is not None and first.f_code.co_name in _REALPATH_FUNCS and "posixpath" in first.f_code.co_filename:
            # realpath() lstat()s every component; only symlinks matter, and
            # whatever the resolved path is used for is recorded separately.
            if result is not None and _stat.S_ISLNK(result.st_mode):
                self.symlink_reads.add(abs_path)
            return
        self.fs("probe" if missing else "read", abs_path)

    def on_find_spec(self, finder, fullname, spec):
        path = finder.path or _o_getcwd()
        if not os.path.isabs(path):
            path = os.path.join(_o_getcwd(), path)
        path = os.path.normpath(path)
        tail = fullname.rpartition(".")[2]
        try:
            suffixes = tuple(s for s, _ in finder._loaders)
        except Exception:
            suffixes = tuple(importlib.machinery.all_suffixes())
        self.finder.add((path, tail, suffixes))
        if spec is not None:
            origin = getattr(spec, "origin", None)
            if isinstance(origin, str) and os.path.isabs(origin) and getattr(spec, "has_location", True):
                self.modules.setdefault(os.path.normpath(origin), "finder")

    def env_read(self, key):
        first, user = self.stack()
        if user:
            if isinstance(key, bytes):
                key = os.fsdecode(key)
            if isinstance(key, str):
                self.env.add(key)

    def env_all(self):
        first, user = self.stack()
        if user:
            self.env.add("*")


_COLLECTOR: Collector | None = None


def _guarded(fn, *args):
    c = _COLLECTOR
    if c is None or not c.active or _busy():
        return
    _tls.busy = True
    try:
        fn(*args)
    except _Unresolvable as e:
        c.taint(f"vci:unresolvable-dir-fd:{e}")
    except Exception as e:  # never break the test because of the collector
        c.taint(f"vci:collector-error:{type(e).__name__}:{e}")
    finally:
        _tls.busy = False


_DISPATCH = {
    "open": "on_open",
    "exec": "on_exec",
    "os.listdir": "on_listdir",
    "os.scandir": "on_listdir",
    "import": "on_import",
    "ctypes.dlopen": "on_dlopen",
    "sqlite3.connect": "on_sqlite",
    "tempfile.mkdtemp": "on_tempdir",
    "tempfile.mkstemp": "on_tempfile",
}
_DISPATCH_EVENT = {"os.rename": "on_two_path_write", "os.link": "on_two_path_write"}
_DISPATCH_EVENT.update({e: "on_write_event" for e in WRITE_EVENTS})


def _audit(event, args):
    # Called for every audit event in the process: keep the common path cheap.
    c = _COLLECTOR
    if c is None or not c.active:
        return
    name = _DISPATCH.get(event)
    if name is not None:
        _guarded(getattr(c, name), args)
    elif event in TAINT_EVENTS:
        c.taint(event)
    else:
        name = _DISPATCH_EVENT.get(event)
        if name is not None:
            _guarded(getattr(c, name), event, args)


def _stat_wrapper(orig, lstat_call):
    def wrapper(path, *args, **kwargs):
        c = _COLLECTOR
        if c is None or not c.active or _busy():
            return orig(path, *args, **kwargs)
        dir_fd = kwargs.get("dir_fd")
        try:
            r = orig(path, *args, **kwargs)
        except (FileNotFoundError, NotADirectoryError):
            _guarded(c.on_stat, path, dir_fd, None, True, lstat_call)
            raise
        except OSError:
            _guarded(c.on_stat, path, dir_fd, None, False, lstat_call)
            raise
        _guarded(c.on_stat, path, dir_fd, r, False, lstat_call)
        return r

    wrapper.__name__ = orig.__name__
    wrapper.__qualname__ = orig.__name__
    wrapper.__doc__ = orig.__doc__
    wrapper.__wrapped__ = orig
    return wrapper


def _access(path, mode, *args, **kwargs):
    c = _COLLECTOR
    r = _o_access(path, mode, *args, **kwargs)
    if c is None or not c.active or _busy() or isinstance(path, int):
        return r
    missing = False
    if not r:
        try:
            _o_stat(path, dir_fd=kwargs.get("dir_fd"))
        except (FileNotFoundError, NotADirectoryError):
            missing = True
        except OSError:
            pass
    _guarded(c.on_stat, path, kwargs.get("dir_fd"), None, missing, False)
    return r


def _readlink(path, *args, **kwargs):
    c = _COLLECTOR
    if c is None or not c.active or _busy() or isinstance(path, int):
        return _o_readlink(path, *args, **kwargs)
    try:
        r = _o_readlink(path, *args, **kwargs)
    except (FileNotFoundError, NotADirectoryError):
        _guarded(c.on_stat, path, kwargs.get("dir_fd"), None, True, True)
        raise
    except OSError:
        _guarded(c.on_stat, path, kwargs.get("dir_fd"), None, False, True)
        raise
    # A successful readlink means the path is a symlink.
    _guarded(c.on_stat, path, kwargs.get("dir_fd"), _o_lstat(path, dir_fd=kwargs.get("dir_fd")), False, True)
    return r


def _open(path, flags, mode=0o777, *, dir_fd=None):
    c = _COLLECTOR
    if c is not None and c.active and not _busy() and dir_fd is not None and not isinstance(path, int):
        s = _to_str(path)
        if s is not None and not os.path.isabs(s):
            base = _fd_path(dir_fd)
            if base is None:
                c.taint("vci:unresolvable-dir-fd:os.open")
                _tls.open_override = False
            else:
                _tls.open_override = os.path.normpath(os.path.join(base, s))
    try:
        return _o_open(path, flags, mode, dir_fd=dir_fd)
    finally:
        _tls.open_override = None


def _env_getitem(self, key):
    c = _COLLECTOR
    if c is not None and c.active and not _busy():
        _guarded(c.env_read, key)
    return _o_env_getitem(self, key)


def _env_all_wrapper(orig):
    def wrapper(self, *a, **k):
        c = _COLLECTOR
        if c is not None and c.active and not _busy():
            _guarded(c.env_all)
        return orig(self, *a, **k)

    wrapper.__name__ = orig.__name__
    return wrapper


def _find_spec(self, fullname, target=None):
    spec = _o_find_spec(self, fullname, target)
    c = _COLLECTOR
    if c is not None and c.active and not _busy():
        _guarded(c.on_find_spec, self, fullname, spec)
    return spec


def install(out_dir: str) -> Collector:
    global _COLLECTOR
    if _COLLECTOR is not None:
        return _COLLECTOR
    _COLLECTOR = Collector(out_dir)
    sys.addaudithook(_audit)
    patches = {
        "stat": _stat_wrapper(_o_stat, False),
        "lstat": _stat_wrapper(_o_lstat, True),
        "access": _access,
        "readlink": _readlink,
        "open": _open,
    }
    originals = {"stat": _o_stat, "lstat": _o_lstat, "access": _o_access, "readlink": _o_readlink, "open": _o_open}
    for name, fn in patches.items():
        setattr(os, name, fn)
        # Keep `os.X in os.supports_*` checks (shutil, pathlib) truthful.
        for sname in ("supports_dir_fd", "supports_fd", "supports_follow_symlinks", "supports_effective_ids"):
            s = getattr(os, sname, None)
            if isinstance(s, set) and originals[name] in s:
                s.add(fn)
    _Environ.__getitem__ = _env_getitem
    _Environ.__iter__ = _env_all_wrapper(_o_env_iter)
    _Environ.__len__ = _env_all_wrapper(_o_env_len)
    _Environ.__repr__ = _env_all_wrapper(_o_env_repr)
    _Environ.copy = _env_all_wrapper(_o_env_copy)
    importlib.machinery.FileFinder.find_spec = _find_spec
    # Subinterpreters have their own audit hooks, sys.modules and os module: nothing
    # they do is visible here (verified: no audit event reaches this interpreter).
    for modname in ("_interpreters", "_xxsubinterpreters"):
        try:
            mod = importlib.import_module(modname)
        except ImportError:
            continue
        orig = getattr(mod, "create", None)
        if callable(orig):

            def create(*a, _orig=orig, _name=modname, **k):
                if _COLLECTOR is not None and _COLLECTOR.active:
                    _COLLECTOR.taint(f"subinterpreter:{_name}.create")
                return _orig(*a, **k)

            try:
                mod.create = create
            except (AttributeError, TypeError):
                _COLLECTOR.taint(f"vci:cannot-wrap:{modname}.create")
    return _COLLECTOR


def get() -> Collector | None:
    return _COLLECTOR


# ----- finalisation -----------------------------------------------------------------


class _Classifier:
    IGNORE, STDLIB, ENV, ROOT, OUTSIDE, PLUGIN = range(6)

    def __init__(self, c: Collector, root: str, extra_ignore):
        self.c = c
        self.root_raw = os.path.normpath(os.path.abspath(root))
        self.root = os.path.realpath(root)
        self.roots = _prefixes([root])
        self.self_dirs = _prefixes(list(c.self_dirs) + list(extra_ignore))
        self.self_files = set(c.self_files) | {os.path.realpath(p) for p in c.self_files}

    def _raw(self, p: str) -> int:
        if p in ("/dev/null", os.devnull):
            return self.IGNORE
        if _under(p, self.c.pkg):
            return self.IGNORE
        if _under(p, self.c.plugin_entry) and not _under(p, self.roots):
            return self.PLUGIN
        if _under(p, self.c.out):
            return self.IGNORE
        if p in self.self_files or _under(p, self.self_dirs):
            return self.IGNORE
        if _under(p, self.c.stdlib) and not _is_site_component(p):
            return self.STDLIB
        if _under(p, self.c.sites) or _under(p, self.c.venv):
            return self.ENV
        if _under(p, self.roots):
            return self.ROOT
        if _under(p, self.c.base):
            return self.ENV
        return self.OUTSIDE

    def classify(self, p: str):
        """Return (class, path to emit)."""
        k = self._raw(p)
        if k == self.OUTSIDE:
            try:
                rp = os.path.realpath(p)
            except (OSError, ValueError):
                rp = p
            if rp != p:
                k2 = self._raw(rp)
                if k2 != self.OUTSIDE:
                    return k2, (self.emit(rp) if k2 == self.ROOT else rp)
            return k, p
        if k == self.ROOT:
            return k, self.emit(p)
        return k, p

    def emit(self, p: str) -> str:
        for pre in self.roots:
            if p == pre:
                return self.root
            if p.startswith(pre + os.sep):
                return self.root + p[len(pre) :]
        return p

    def rel(self, p: str) -> str:
        return os.path.relpath(p, self.root)

    def noise_in_root(self, p: str) -> bool:
        parts = self.rel(p).split(os.sep)
        return "__pycache__" in parts or ".pytest_cache" in parts


def _exists(p: str):
    """'file' | 'dir' | 'other' | None (absent)."""
    try:
        st = _o_stat(p)
    except (FileNotFoundError, NotADirectoryError):
        try:
            _o_lstat(p)
            return "other"  # dangling symlink
        except OSError:
            return None
    except OSError:
        return "other"
    if _stat.S_ISREG(st.st_mode):
        return "file"
    if _stat.S_ISDIR(st.st_mode):
        return "dir"
    return "other"


class _DistIndex:
    def __init__(self):
        self._files = None
        self._pkgs = None

    def _build(self):
        self._files = {}
        for dist in importlib.metadata.distributions():
            try:
                name = dist.metadata["Name"]
                ver = dist.version
                files = dist.files
            except Exception:
                continue
            if not name or not ver or files is None:
                continue
            for f in files:
                try:
                    p = os.path.normpath(os.path.abspath(str(dist.locate_file(f))))
                except Exception:
                    continue
                self._files.setdefault(p, (_norm_dist(name), ver))

    def lookup(self, p: str):
        if self._files is None:
            self._build()
        hit = self._files.get(p)
        if hit is None:
            hit = self._files.get(os.path.realpath(p))
        return hit

    def lookup_module(self, modname: str):
        """Fallback via packages_distributions (only for dists without a RECORD)."""
        if self._pkgs is None:
            try:
                self._pkgs = importlib.metadata.packages_distributions()
            except Exception:
                self._pkgs = {}
        top = modname.split(".", 1)[0]
        dists = self._pkgs.get(top) or []
        if len(dists) != 1:
            return None
        try:
            d = importlib.metadata.distribution(dists[0])
            if d.files is not None:
                return None  # it has a RECORD and the file is not in it
            return (_norm_dist(dists[0]), d.version)
        except Exception:
            return None


def _dirs_between(start_dir: str, root: str):
    """start_dir, its parents ... up to and including root (all inside root)."""
    out = []
    d = start_dir
    while True:
        out.append(d)
        if d == root:
            break
        parent = os.path.dirname(d)
        if parent == d or not _under(parent, (root,)):
            break
        d = parent
    return out


def finalize(session, exitstatus) -> list:
    """Compute records and write one JSONL file per collected test file. Returns paths."""
    c = _COLLECTOR
    if c is None or c.finished:
        return []
    _tls.busy = True
    try:
        return _finalize(c, session, exitstatus)
    finally:
        c.finished = True
        c.active = False
        _tls.busy = False


def _finalize(c: Collector, session, exitstatus) -> list:
    import pytest  # already imported

    config = session.config
    root_path = str(config.rootpath)
    extra_ignore = []
    try:
        factory = getattr(config, "_tmp_path_factory", None)
        bt = getattr(factory, "_basetemp", None) if factory is not None else None
        if bt is not None:
            extra_ignore.append(str(bt))
    except Exception:
        pass
    try:
        cache = getattr(config, "cache", None)
        cd = getattr(cache, "_cachedir", None)
        if cd is not None:
            extra_ignore.append(str(cd))
    except Exception:
        pass
    cl = _Classifier(c, root_path, extra_ignore)
    root = cl.root
    dists = _DistIndex()

    modules: dict = {}  # emitted path -> via
    externals: set = set()
    reads: set = set()
    probes: set = set()
    readdirs: set = set()
    writes: set = set()
    outside_paths_taint = []

    # --- module sources ---
    mod_sources = dict(c.modules)
    for name, m in list(sys.modules.items()):
        if not isinstance(m, types.ModuleType):
            continue
        d = getattr(m, "__dict__", None) or {}
        f = d.get("__file__")
        if isinstance(f, str) and os.path.isabs(f):
            mod_sources.setdefault(os.path.normpath(f), "sys.modules")
    try:
        for plugin in config.pluginmanager.get_plugins():
            f = getattr(plugin, "__file__", None) if isinstance(plugin, types.ModuleType) else None
            if isinstance(f, str) and os.path.isabs(f):
                mod_sources.setdefault(os.path.normpath(f), "pytest-plugin")
    except Exception:
        pass
    ext_suffixes = tuple(importlib.machinery.EXTENSION_SUFFIXES)
    modname_by_file = {}
    for name, m in list(sys.modules.items()):
        if isinstance(m, types.ModuleType):
            f = (getattr(m, "__dict__", None) or {}).get("__file__")
            if isinstance(f, str):
                modname_by_file.setdefault(os.path.normpath(f), name)

    for p, via in sorted(mod_sources.items()):
        k, ep = cl.classify(p)
        if k in (cl.IGNORE, cl.STDLIB):
            continue
        if k == cl.PLUGIN:
            c.taint(f"vci:module-from-plugin-dir:{p}")
        elif k == cl.ENV:
            hit = dists.lookup(p)
            if hit is None:
                mn = modname_by_file.get(p, "")
                hit = dists.lookup_module(mn) if mn else None
            if hit is not None:
                externals.add(hit)
            else:
                top = os.path.basename(p).split(".", 1)[0]
                if top in UNOWNED_ENV_MODULES:
                    continue
                c.taint(f"unmapped-module:{p}")
        else:
            modules.setdefault(ep, via)
            if k == cl.ROOT and p.endswith(ext_suffixes):
                c.taint(f"native-extension-in-root:{cl.rel(ep)}")

    # --- fs observations ---
    def put(kind, p, is_finder=False):
        k, ep = cl.classify(p)
        if k in (cl.IGNORE, cl.STDLIB, cl.PLUGIN):
            return
        if k == cl.ENV:
            if kind == "read":
                hit = dists.lookup(p)
                if hit is not None:
                    externals.add(hit)
            return
        if k == cl.ROOT:
            if cl.noise_in_root(ep):
                return
            if not is_finder and kind in ("read", "probe") and ep.endswith((".pyc", ".pyo")):
                return
        {"read": reads, "probe": probes, "readdir": readdirs, "write": writes}[kind].add(ep)

    for p in c.writes:
        put("write", p)
    for p in c.reads:
        put("read", p)
    for p in c.probes:
        put("probe", p)
    for p in c.readdirs:
        put("readdir", p)
    for p in c.symlink_reads:
        k, ep = cl.classify(p)
        if k == cl.ROOT and not cl.noise_in_root(ep):
            reads.add(ep)

    # Start-up imports (before the plugin was loaded) could be shadowed by a module
    # created in a root directory that was already on sys.path then (e.g. the cwd
    # with `python -m pytest`, or a .pth entry). A module found in sys.path entry k
    # consulted entries 0..k-1. pytest >= 8 inserts `pythonpath` ini entries right
    # before importing `-p` plugins, so those only matter if another `-p` plugin was
    # imported before this one.
    all_suffixes = tuple(
        importlib.machinery.EXTENSION_SUFFIXES
        + importlib.machinery.SOURCE_SUFFIXES
        + importlib.machinery.BYTECODE_SUFFIXES
    )
    late = set()
    if not _plugins_before_us(config):
        try:
            for pth in config.getini("pythonpath") or []:
                late.add(os.path.normpath(str(pth)))
        except Exception:
            pass
    root_entries = [
        (i, e) for i, e in enumerate(c.preload_path) if e not in late and cl.classify(e)[0] == cl.ROOT
    ]
    if root_entries:
        index = {}
        for i, e in enumerate(c.preload_path):
            index.setdefault(e, i)
            index.setdefault(os.path.realpath(e), i)
        for top, loc in c.preload:
            k = len(c.preload_path)
            if loc is not None:
                k = index.get(loc, index.get(os.path.realpath(loc), k))
            for i, e in root_entries:
                if i < k:
                    c.finder.add((e, top, all_suffixes))

    # Import lookups: every candidate the FileFinder could have used.
    for d, tail, suffixes in c.finder:
        k, ed = cl.classify(d)
        if k != cl.ROOT or cl.noise_in_root(ed):
            if k == cl.OUTSIDE:
                outside_paths_taint.append(d)
            continue
        base = os.path.join(ed, tail)
        cands = [(base, "dir")]
        cands += [(os.path.join(base, "__init__" + s), "file") for s in suffixes]
        cands += [(base + s, "file") for s in suffixes]
        for cp, want in cands:
            state = _exists(cp)
            if state is None:
                probes.add(cp)
            elif state != want:
                # Exists but cannot serve this role today (e.g. a directory named
                # x.py): hash it so a change of type is noticed.
                reads.add(cp)

    # sys.path entries and every directory the path finder consulted.
    entries = set(c.sys_path_seen) | set(sys.path)
    try:
        entries |= set(k for k in sys.path_importer_cache.keys() if isinstance(k, str))
    except Exception:
        pass
    cwd = _o_getcwd()
    for e in entries:
        p = os.path.normpath(os.path.join(cwd, e)) if not os.path.isabs(e or ".") else os.path.normpath(e)
        k, ep = cl.classify(p)
        if k == cl.ROOT:
            if cl.noise_in_root(ep):
                continue
            st = _exists(ep)
            if st is None:
                probes.add(ep)
            elif st != "dir":
                reads.add(ep)
        elif k == cl.OUTSIDE:
            outside_paths_taint.append(p)
    for p in sorted(set(outside_paths_taint)):
        c.taint(f"sys.path-outside-root:{p}")

    # --- pytest's own inputs ---
    test_files = _test_files(c, session, config)
    inipath = getattr(config, "inipath", None)
    if inipath is None:
        c.taint("pytest:no-config-file")
    else:
        ini = os.path.normpath(str(inipath))
        k, ep = cl.classify(ini)
        reads.add(ep)
        if os.path.basename(ini) == "pyproject.toml" and not _has_pytest_table(ini):
            c.taint("pytest:pyproject-without-pytest-table")
        if k != cl.ROOT:
            c.taint(f"pytest:config-outside-root:{ini}")
    for name in ("pyproject.toml", "uv.lock", ".python-version"):
        p = os.path.join(root, name)
        if _exists(p) == "file":
            reads.add(p)
    confcut = getattr(config.pluginmanager, "_confcutdir", None)
    confcut = os.path.realpath(str(confcut)) if confcut is not None else root
    if not _under(confcut, (root,)):
        c.taint(f"pytest:confcutdir-outside-root:{confcut}")
        confcut = root
    for tf in test_files:
        k, etf = cl.classify(tf)
        if k != cl.ROOT:
            continue
        modules.setdefault(etf, "test-file")
        for d in _dirs_between(os.path.dirname(etf), root):
            for name in INI_NAMES:
                p = os.path.join(d, name)
                st = _exists(p)
                (probes if st is None else reads).add(p)
            p = os.path.join(d, "__init__.py")
            st = _exists(p)
            (probes if st is None else reads).add(p)
            if _under(d, (confcut,)):
                p = os.path.join(d, "conftest.py")
                st = _exists(p)
                if st is None:
                    probes.add(p)
                elif st == "file":
                    modules.setdefault(p, "conftest")
                else:
                    reads.add(p)

    # A read of something that no longer exists was a failed open(): a probe.
    for p in list(reads):
        if _exists(p) is None:
            reads.discard(p)
            probes.add(p)
    for p in list(readdirs):
        if _exists(p) is None:
            readdirs.discard(p)
            probes.add(p)

    # --- configuration taints ---
    _config_taints(c, config)

    # --- env ---
    env = set(c.env)
    env.update(EXPLICIT_ENV)
    pp = os.environ.get("PYTHONPATH", "")  # collector is busy here: not recorded as a test read
    for e in [x for x in pp.split(os.pathsep) if x]:
        if os.path.realpath(e) != os.path.realpath(PLUGIN_ENTRY):
            c.taint(f"env:PYTHONPATH-entry:{e}")

    # --- result ---
    outcomes = list(c.items.values())
    n = len(outcomes)
    failed = sum(1 for o in outcomes if o == "failed") + c.collect_errors
    skipped = sum(1 for o in outcomes if o == "skipped")
    ran = sum(1 for o in outcomes if o == "passed")
    state = "passed" if (exitstatus == 0 and failed == 0 and ran > 0) else "failed"
    result = {
        "kind": "result",
        "state": state,
        "tests": n,
        "failed": failed,
        "skipped": skipped,
        "durationMs": int((time.perf_counter() - c.t0) * 1000),
        "deselected": c.deselected,
        "exitStatus": int(exitstatus),
    }

    if len(test_files) > 1:
        c.taint("pytest:multiple-test-files-in-process")
    if not test_files:
        c.taint("pytest:no-test-file")

    common = []
    for p in sorted(modules):
        common.append({"kind": "module", "path": p, "via": modules[p]})
    for name, ver in sorted(externals):
        common.append({"kind": "external", "name": name, "version": ver})
    for p in sorted(reads):
        common.append({"kind": "read", "path": p})
    for p in sorted(probes):
        common.append({"kind": "probe", "path": p})
    for p in sorted(readdirs):
        common.append({"kind": "readdir", "path": p})
    for p in sorted(writes):
        common.append({"kind": "write", "path": p})
    for k in sorted(env):
        common.append({"kind": "env", "key": k})

    written = []
    os.makedirs(c.out_dir, exist_ok=True)
    ids = []
    for tf in test_files or [None]:
        if tf is None:
            test_id = " ".join(str(a) for a in getattr(config, "args", [])) or "<none>"
        else:
            k, etf = cl.classify(tf)
            test_id = cl.rel(etf).replace(os.sep, "/") if k == cl.ROOT else tf
            if k != cl.ROOT:
                c.taint(f"pytest:test-file-outside-rootdir:{tf}")
        ids.append(test_id)
    for test_id in ids:
        meta = {
            "v": 1,
            "kind": "meta",
            "testId": test_id,
            "adapter": "pytest",
            "python": platform.python_version(),
            "implementation": sys.implementation.name,
            "pytest": pytest.__version__,
            "root": root,
            "platform": sys.platform,
            "arch": platform.machine(),
            "collector": COLLECTOR,
        }
        lines = [meta] + common + [{"kind": "taint", "reason": r} for r in c.taints] + [result]
        name = hashlib.sha256(test_id.encode("utf-8")).hexdigest() + ".jsonl"
        dest = os.path.join(c.out_dir, name)
        tmp = dest + f".tmp{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            for rec in lines:
                f.write(json.dumps(rec, sort_keys=False, separators=(",", ":")) + "\n")
        os.replace(tmp, dest)
        written.append(dest)
    return written


def _plugins_before_us(config) -> bool:
    """True if a `-p` plugin (other than blocks and vci_pytest) may have been imported before us."""
    try:
        args = list(config.getini("addopts") or [])
    except Exception:
        args = []
    args += os.environ.get("PYTEST_ADDOPTS", "").split()
    try:
        inv = list(config.invocation_params.args)
    except Exception:
        return True
    try:
        inv = inv[: inv.index("vci_pytest") + 1] if "vci_pytest" in inv else inv
    except ValueError:
        pass
    args += inv
    for i, a in enumerate(args):
        a = str(a)
        name = None
        if a == "-p" and i + 1 < len(args):
            name = str(args[i + 1])
        elif a.startswith("-p") and len(a) > 2:
            name = a[2:]
        if name and not name.startswith("no:") and name != "vci_pytest":
            return True
    return False


def _has_pytest_table(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return False
    try:
        import tomllib  # 3.11+

        doc = tomllib.loads(data.decode("utf-8"))
        return isinstance(doc.get("tool", {}).get("pytest"), dict)
    except ImportError:
        return re.search(rb"^\s*\[\s*tool\s*\.\s*pytest", data, re.M) is not None
    except Exception:
        return False


def _test_files(c: Collector, session, config) -> list:
    files = set(c.item_files)
    inv = str(getattr(getattr(config, "invocation_params", None), "dir", "") or _o_getcwd())
    for a in getattr(config, "args", []) or []:
        a = str(a)
        part = a.split("::", 1)[0]
        if "::" in a:
            c.taint("pytest:partial-file-selection")
        p = os.path.normpath(os.path.join(inv, part))
        st = _exists(p)
        if st == "file":
            files.add(p)
        elif st == "dir":
            c.taint("pytest:directory-argument")
    if len(getattr(config, "args", []) or []) > 1:
        c.taint("pytest:multiple-arguments")
    # dedupe by real path
    by_real = {}
    for f in sorted(files):
        by_real.setdefault(os.path.realpath(f), f)
    return sorted(by_real.values())


def _config_taints(c: Collector, config):
    opt = config.option
    for attr, reason in (
        ("lf", "pytest:--lf"),
        ("last_failed", "pytest:--lf"),
        ("failedfirst", "pytest:--ff"),
        ("newfirst", "pytest:--nf"),
        ("stepwise", "pytest:--sw"),
        ("stepwise_skip", "pytest:--sw-skip"),
    ):
        if getattr(opt, attr, False):
            c.taint(reason)
    pm = config.pluginmanager
    xdist = False
    try:
        n = getattr(opt, "numprocesses", None)
        if n not in (None, 0, "0"):
            xdist = True
        if getattr(opt, "dist", "no") not in ("no", None):
            xdist = True
        if pm.hasplugin("dsession") or pm.hasplugin("xdist.looponfail"):
            xdist = True
        if hasattr(config, "workerinput"):
            xdist = True
    except Exception:
        pass
    if xdist:
        c.taint("pytest:xdist")
    # Random ordering plugins: tainted unless a seed was given explicitly.
    try:
        argv = list(config.invocation_params.args)
    except Exception:
        argv = []
    try:
        argv += list(config.getini("addopts") or [])
    except Exception:
        pass
    argv += os.environ.get("PYTEST_ADDOPTS", "").split()
    joined = " ".join(str(a) for a in argv)
    names = set()
    try:
        for name, plugin in pm.list_name_plugin():
            if plugin is not None:
                names.add(str(name))
                names.add(str(getattr(plugin, "__name__", "")))
    except Exception:
        pass
    if any("randomly" in n for n in names):
        if not re.search(r"--randomly-seed[= ]\d+", joined):
            c.taint("pytest:random-order(pytest-randomly)")
    if any("random_order" in n or "random-order" in n for n in names):
        bucket = getattr(opt, "random_order_bucket", None)
        enabled = getattr(opt, "random_order", False) or (bucket not in (None, "none"))
        if enabled and not re.search(r"--random-order-seed[= ]\d+", joined):
            c.taint("pytest:random-order(pytest-random-order)")
    if getattr(opt, "reruns", 0):
        c.taint("pytest:reruns")
