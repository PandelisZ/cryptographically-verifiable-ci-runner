"""What does sys.addaudithook see? Prints the relevant audit events per operation.

    uv run --project fixtures/pytest-abcd python py/pytest-plugin/spike/audit_coverage.py
"""
import os, sys, io, tempfile, pathlib
d = tempfile.mkdtemp(); f = os.path.join(d, "f.txt"); open(f, "w").write("x" * 100)
open(os.path.join(d, "ca.pem"), "w").write("not a cert\n")
EV = []; ON = [False]
SKIP = ("sys._getframe", "object.", "code.", "compile", "exec", "import", "marshal", "builtins.id", "sys._current", "cpython.")
def hook(ev, args):
    if ON[0] and not ev.startswith(SKIP) and not (ev == "open" and "__pycache__" in str(args[0])) and not (ev == "os.listdir" and "python3" in str(args[0])):
        EV.append(ev + ("(" + os.path.basename(str(args[0])) + ")" if args and isinstance(args[0], (str, bytes)) else ""))
sys.addaudithook(hook)
import mmap, sqlite3, ssl, ctypes, ctypes.util, dbm.dumb, time, socket, subprocess, multiprocessing, zipfile, glob
def run(label, fn):
    EV.clear(); ON[0] = True
    try: fn()
    except Exception as e: EV.append("EXC:" + type(e).__name__)
    ON[0] = False
    print(f"{label:42s} -> {', '.join(dict.fromkeys(EV)) or '(no audit event)'}")
libc = ctypes.CDLL(ctypes.util.find_library("c"))
libc.fopen.restype = ctypes.c_void_p
run("builtins.open(r)", lambda: open(f).read())
run("pathlib.Path.read_text", lambda: pathlib.Path(f).read_text())
run("os.open(O_RDONLY)", lambda: os.close(os.open(f, os.O_RDONLY)))
run("io.FileIO", lambda: io.FileIO(f).close())
run("io.open_code", lambda: io.open_code(f).close())
run("mmap.mmap(fd)", lambda: mmap.mmap(os.open(f, os.O_RDONLY), 0, prot=mmap.PROT_READ))
run("os.stat", lambda: os.stat(f))
run("os.path.exists (missing)", lambda: os.path.exists(f + ".nope"))
run("os.access", lambda: os.access(f, os.R_OK))
run("os.readlink (not a link)", lambda: os.readlink(f))
run("os.listdir", lambda: os.listdir(d))
run("os.scandir + DirEntry.stat", lambda: [e.stat() for e in os.scandir(d)])
run("glob.glob", lambda: glob.glob(d + "/*.txt"))
run("os.environ['HOME'] / os.getenv", lambda: (os.environ["HOME"], os.getenv("NOPE")))
run("time.tzset (C getenv TZ, /etc/localtime)", lambda: time.tzset())
run("sqlite3.connect", lambda: sqlite3.connect(os.path.join(d, "a.db")).close())
run("sqlite3 ATTACH (C-level open)", lambda: sqlite3.connect(":memory:").execute(f"ATTACH DATABASE '{d}/b.db' AS b"))
run("ssl load_verify_locations (OpenSSL fopen)", lambda: ssl.create_default_context().load_verify_locations(os.path.join(d, "ca.pem")))
run("dbm.dumb.open", lambda: dbm.dumb.open(os.path.join(d, "dumb"), "c").close())
run("ctypes libc.fopen", lambda: libc.fclose(ctypes.c_void_p(libc.fopen(f.encode(), b"r"))))
run("zipfile.ZipFile(path)", lambda: zipfile.ZipFile(os.path.join(d, "z.zip"), "w").close())
run("subprocess.run", lambda: subprocess.run(["true"]))
run("os.system", lambda: os.system("true"))
run("socket.getaddrinfo", lambda: socket.getaddrinfo("localhost", 80))
run("tempfile.mkdtemp", lambda: tempfile.mkdtemp())
if __name__ == "__main__":
    ctx = multiprocessing.get_context("spawn")
    def mp():
        p = ctx.Process(target=print); p.start(); p.join()
    run("multiprocessing spawn Process.start", mp)
print(sys.version.split()[0])
