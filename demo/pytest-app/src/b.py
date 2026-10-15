import json
from pathlib import Path

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "b.json"


def load_greeting(path: Path = FIXTURE) -> str:
    with open(path, encoding="utf-8") as f:
        return json.load(f)["greeting"]

# Changed on main to show that CI re-runs only test_b after its own attestations.
