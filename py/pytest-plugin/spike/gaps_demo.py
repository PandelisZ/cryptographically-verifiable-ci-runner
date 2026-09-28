"""Show, end to end, which accesses the collector sees and which it cannot.

Copies fixtures/pytest-abcd to a temp dir, adds one test that performs each access,
runs it through `-p vci_pytest` with the fixture's venv, and prints what was recorded.

    uv run --project fixtures/pytest-abcd python py/pytest-plugin/spike/gaps_demo.py
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
FIXTURE = REPO / "fixtures" / "pytest-abcd"
PLUGIN = REPO / "py" / "pytest-plugin"

TEST = '''
import os, posix, sqlite3, ssl
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent

def test_accesses():
    try: posix.stat(str(ROOT / "gap-posix-stat"))            # C-level stat: bypasses the os.stat wrapper
    except FileNotFoundError: pass
    os.environ._data.get(b"GAP_ENV_DATA")                    # private dict: bypasses os._Environ
    sqlite3.connect(":memory:").execute(f"ATTACH DATABASE '{ROOT}/fixtures/other.db' AS o")  # SQLite's own open()
    try: ssl.create_default_context().load_verify_locations(str(ROOT / "fixtures" / "ca.pem"))  # OpenSSL fopen()
    except ssl.SSLError: pass
    try: (ROOT / "seen-stat").stat()                          # control: wrapped os.stat -> probe
    except FileNotFoundError: pass
    os.environ.get("SEEN_ENV")                                # control: env record
    (ROOT / "fixtures" / "b.json").read_bytes()               # control: audit 'open' -> read
'''

WATCH = ["gap-posix-stat", "GAP_ENV_DATA", "other.db", "ca.pem", "seen-stat", "SEEN_ENV", "b.json"]


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        proj = Path(tmp) / "proj"
        shutil.copytree(FIXTURE, proj, ignore=shutil.ignore_patterns(".venv", ".pytest_cache", "__pycache__"))
        (proj / "fixtures" / "ca.pem").write_text("not a certificate\n")
        sqlite3.connect(proj / "fixtures" / "other.db").execute("create table t(x)").connection.close()
        (proj / "tests" / "test_accesses.py").write_text(textwrap.dedent(TEST))
        out = Path(tmp) / "out"
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTEST_", "VCI_"))}
        env.update(PYTHONPATH=str(PLUGIN), VCI_OUT=str(out))
        subprocess.run(
            [str(FIXTURE / ".venv" / "bin" / "pytest"), "-q", "-p", "vci_pytest", "tests/test_accesses.py"],
            cwd=proj,
            env=env,
            check=True,
        )
        recs = [json.loads(l) for f in out.glob("*.jsonl") for l in f.read_text().splitlines()]
        for w in WATCH:
            hits = [r for r in recs if w in (r.get("path", "") + r.get("key", ""))]
            print(f"{w:16s} {'RECORDED ' + str([(r['kind']) for r in hits]) if hits else 'not recorded'}")
        print("taints:", [r["reason"] for r in recs if r["kind"] == "taint"])


if __name__ == "__main__":
    main()
