# Collect out/TAG-*.json into results.json and print the markdown tables of RESULTS.md.
# usage: python3 -I summarize.py TAG > tables.md
import glob, json, os, re, statistics, sys

W = os.path.dirname(os.path.abspath(__file__))
TAG = sys.argv[1]
OUT = os.path.join(W, "out")
NAME = {"f3": "store-v2, format 3", "f1": "store-v2, VCI_STORE_RECORD_FORMAT=1", "h281": "vci 2.8.1 store (fx3 replay-head)"}


def load(p):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return None


def batch_lines(p):
    """The store's 'write batch' timing lines of a process: transactions, requests, MB, longest."""
    out = []
    try:
        for l in open(p):
            if "write batch" not in l:
                continue
            g = lambda rx: re.search(rx, l)
            out.append({
                "transactions": int(g(r"(\d+) transaction").group(1)),
                "requests": int(g(r"(\d+) request").group(1)),
                "mb": float(g(r"([0-9.]+) MB").group(1)),
                "longest": float(g(r"longest ([0-9.]+)s").group(1)),
                "not_stored": int(g(r"(\d+) attestation\(s\) not stored").group(1)) if "not stored" in l else 0,
            })
    except Exception:
        pass
    return out


runs = {}  # (cfg, P) -> [attempt dicts]
for atrest in sorted(glob.glob(f"{OUT}/{TAG}-*-write-atrest.json")):
    m = re.match(rf"{re.escape(OUT)}/{re.escape(TAG)}-(\w+)-(\d)-(\w+)-write-atrest\.json", atrest)
    cfg, P, rep = m.group(1), int(m.group(2)), m.group(3)
    base = f"{OUT}/{TAG}-{cfg}-{P}-{rep}"
    attempt = {"cfg": cfg, "procs": P, "rep": rep, "phases": {}, "ok": True}
    for phase in ("write", "supersede"):
        if not os.path.exists(f"{base}-{phase}-atrest.json"):
            continue
        procs = []
        for i in range(P):
            j = load(f"{base}-{phase}-{i}.json") or {}
            wall = load(f"{base}-{phase}-{i}-wall.json") or {}
            proxy = load(f"{base}-{phase}-{i}-proxy.json") or {}
            lines = batch_lines(f"{base}-{phase}-{i}.err")
            if cfg == "h281":
                rec = {"wall_secs": wall.get("wall_secs"), "write_secs": j.get("secs"), "queued_secs": j.get("queued_secs"),
                       "lost": j.get("lost"), "error": j.get("error"), "requests": j.get("requests"), "retries": j.get("retries"),
                       "payload_mb": j.get("mb"),
                       "transactions": sum(x["transactions"] for x in lines), "flushes": len(lines),
                       "longest_tx_secs": max((x["longest"] for x in lines), default=None),
                       "batch_mb": round(sum(x["mb"] for x in lines), 2)}
            else:
                rec = {k: j.get(k) for k in ("write_secs", "queued_secs", "lost", "error", "transactions", "write_requests",
                                             "write_retries", "sql_bytes", "stored_literal_bytes", "objects", "object_bytes",
                                             "record_bytes", "manifest_bytes", "objects_new", "doomed", "removed",
                                             "find_secs", "find_requests", "old_records", "old_bytes_read", "old_hdr_objects",
                                             "orphan_secs", "orphan_requests", "orphan_transactions", "orphan_sql_bytes",
                                             "orphan_candidates", "orphan_objects_removed", "state_objects_pruned",
                                             "orphan_manifests_found", "orphan_manifests_removed", "count_after",
                                             "requests_total", "retries_total")}
                rec["wall_secs"] = wall.get("wall_secs")
                rec["flushes"] = len(lines)
                rec["longest_tx_secs"] = max((x["longest"] for x in lines), default=None)
            rec["rc"] = wall.get("rc")
            # When the store gave up (sqld's stalled lock), what the process got done first.
            rec["batch_transactions"] = sum(x["transactions"] for x in lines)
            rec["batch_not_stored"] = sum(x["not_stored"] for x in lines)
            rec["batch_secs_longest"] = max((x["longest"] for x in lines), default=None)
            rec["wire_c2s_bytes"] = proxy.get("c2s")
            rec["wire_s2c_bytes"] = proxy.get("s2c")
            rec["connections"] = proxy.get("connections")
            if rec["rc"] != 0 or (rec.get("lost") or 0) != 0 or any(x["not_stored"] for x in lines):
                attempt["ok"] = False
            procs.append(rec)
        at = load(f"{base}-{phase}-atrest.json") or {}
        # A phase stands on its own: a write phase whose every writer succeeded is a clean write
        # measurement even when sqld stalled afterwards and the second run could not follow.
        clean = all(p["rc"] == 0 and (p.get("lost") or 0) == 0 for p in procs) and bool(at.get("tables"))
        attempt["phases"][phase] = {"procs": procs, "atrest": at, "clean": clean}
    if os.path.exists(f"{base}-backdate.json"):
        attempt["backdate"] = load(f"{base}-backdate.json")
    runs.setdefault((cfg, P), []).append(attempt)


def med(v):
    v = [x for x in v if x is not None]
    return round(statistics.median(v), 3) if v else None


def rng(v):
    v = [x for x in v if x is not None]
    return (round(min(v), 3), round(max(v), 3)) if v else (None, None)


def fmt(v, unit="", scale=1, nd=2):
    if v is None:
        return "-"
    v = v / scale
    return (f"{v:.{nd}f}" if isinstance(v, float) or nd else f"{int(v)}") + unit


def cell(vals, scale=1, nd=2, unit=""):
    m, (lo, hi) = med(vals), rng(vals)
    if m is None:
        return "-"
    return f"{fmt(m, unit, scale, nd)} ({fmt(lo, '', scale, nd)}-{fmt(hi, '', scale, nd)})"


results = {"tag": TAG, "runs": [], "summary": {}}
for (cfg, P), attempts in sorted(runs.items()):
    for a in attempts:
        results["runs"].append(a)
    for phase in ("write", "supersede"):
        ok = [a for a in attempts if a["phases"].get(phase, {}).get("clean")]
        procs = [p for a in ok for p in a["phases"][phase]["procs"]]
        if not procs:
            continue
        ats = [a["phases"][phase]["atrest"] for a in ok]
        tried = [a for a in attempts if phase in a["phases"]]
        s = {"attempts": len(tried), "ok_attempts": len(ok), "stalled_attempts": len(tried) - len(ok), "processes": len(procs)}
        for k in ("wall_secs", "write_secs", "transactions", "flushes", "longest_tx_secs", "sql_bytes", "stored_literal_bytes",
                  "wire_c2s_bytes", "wire_s2c_bytes", "connections", "write_requests", "write_retries", "requests", "retries",
                  "lost", "removed", "doomed", "find_secs", "find_requests", "old_bytes_read", "orphan_secs", "orphan_requests",
                  "orphan_candidates", "orphan_objects_removed", "orphan_manifests_found", "orphan_manifests_removed",
                  "state_objects_pruned", "objects", "object_bytes", "record_bytes", "manifest_bytes", "batch_mb", "payload_mb"):
            vals = [p.get(k) for p in procs]
            if any(v is not None for v in vals):
                s[k] = {"median": med(vals), "min": rng(vals)[0], "max": rng(vals)[1]}
        s["atrest"] = {}
        for t in ("attestations", "manifests", "objects", "log", "gone", "memo", "flags"):
            rows = [x["tables"].get(t, {}).get("rows") for x in ats]
            bts = [x["tables"].get(t, {}).get("bytes") for x in ats]
            if any(v is not None for v in rows):
                s["atrest"][t] = {"rows": med(rows), "bytes": med(bts)}
        s["atrest"]["total"] = {"rows": med([x.get("rows") for x in ats]), "bytes": med([x.get("bytes") for x in ats])}
        results["summary"][f"{cfg}/{P}/{phase}"] = s

with open(os.path.join(W, "results.json"), "w") as f:
    json.dump(results, f, indent=1, sort_keys=True)

# ---- tables -------------------------------------------------------------------------------
S = results["summary"]


def row_write(cfg, P):
    s = S.get(f"{cfg}/{P}/write")
    if not s:
        return f"| {NAME[cfg]} | {P} | (no clean run) |"
    g = lambda k: [p.get(k) for p in [pp for a in runs[(cfg, P)] if a["phases"].get("write", {}).get("clean") for pp in a["phases"]["write"]["procs"]]]
    sql = cell(g("sql_bytes"), 1e6) if cfg != "h281" else "-"
    at = s["atrest"]
    return (f"| {NAME[cfg]} | {P} | {s['ok_attempts']}+{s['stalled_attempts']} | {cell(g('write_secs'))} | {cell(g('wall_secs'))} | "
            f"{cell(g('transactions'), nd=0)} | {cell(g('flushes'), nd=0)} | {cell(g('longest_tx_secs'))} | {sql} | {cell(g('wire_c2s_bytes'), 1e6)} | "
            f"{cell(g('write_requests') if cfg != 'h281' else g('requests'), nd=0)} / {cell(g('write_retries') if cfg != 'h281' else g('retries'), nd=0)} | "
            f"{cell(g('lost'), nd=0)} | {fmt(at['total']['rows'], nd=0)} | {fmt(at['total']['bytes'], ' MB', 1e6)} | "
            f"{fmt(at.get('attestations', {}).get('rows'), nd=0)} / {fmt(at.get('attestations', {}).get('bytes'), '', 1e6)} | "
            f"{fmt(at.get('manifests', {}).get('rows'), nd=0)} / {fmt(at.get('manifests', {}).get('bytes'), '', 1e6)} | "
            f"{fmt(at.get('objects', {}).get('rows'), nd=0)} / {fmt(at.get('objects', {}).get('bytes'), '', 1e6)} | "
            f"{fmt(at.get('log', {}).get('rows'), nd=0)} |")


print("### The first run (the namespace empty before it)\n")
print("Per writer process, median (min-max) over the clean repetitions x processes; at rest: the namespace after all P processes wrote, median over repetitions.\n")
print("| store | writers | runs clean+stalled | store write s | process wall s | transactions | flushes | longest tx s | SQL on the wire MB | TCP bytes to sqld MB | requests / resends | units lost | rows at rest | bytes at rest | attestations rows / MB | manifests rows / MB | objects rows / MB | log rows |")
print("|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|")
for P in (1, 3):
    for cfg in ("f3", "f1", "h281"):
        if (cfg, P) in runs:
            print(row_write(cfg, P))


def row_super(cfg, P):
    s = S.get(f"{cfg}/{P}/supersede")
    if not s:
        return f"| {NAME[cfg]} | {P} | (no clean run) |"
    g = lambda k: [p.get(k) for p in [pp for a in runs[(cfg, P)] if a["phases"].get("supersede", {}).get("clean") for pp in a["phases"]["supersede"]["procs"]]]
    at = s["atrest"]
    orphan = (f"{cell(g('orphan_objects_removed'), nd=0)} objects of {cell(g('orphan_candidates'), nd=0)} named; state pruned {cell(g('state_objects_pruned'), nd=0)}"
              if cfg == "f3" else f"{cell(g('orphan_manifests_removed'), nd=0)} manifests by the pass of {cell(g('orphan_manifests_found'), nd=0)} found, {cell(g('orphan_candidates'), nd=0)} roots")
    return (f"| {NAME[cfg]} | {P} | {s['ok_attempts']} | {cell(g('find_secs'))} | {cell(g('find_requests'), nd=0)} | {cell(g('old_bytes_read'), 1e6)} | "
            f"{cell(g('write_secs'))} | {cell(g('transactions'), nd=0)} | {cell(g('sql_bytes'), 1e6)} | {cell(g('wire_c2s_bytes'), 1e6)} | "
            f"{cell(g('removed'), nd=0)} of {cell(g('doomed'), nd=0)} | {cell(g('orphan_secs'), nd=3)} | {cell(g('orphan_requests'), nd=0)} | {orphan} | "
            f"{cell(g('lost'), nd=0)} | {fmt(at['total']['rows'], nd=0)} | {fmt(at['total']['bytes'], ' MB', 1e6)} | "
            f"{fmt(at.get('attestations', {}).get('rows'), nd=0)} | {fmt(at.get('manifests', {}).get('rows'), nd=0)} | {fmt(at.get('objects', {}).get('rows'), nd=0)} / {fmt(at.get('objects', {}).get('bytes'), '', 1e6)} | {fmt(at.get('log', {}).get('rows'), nd=0)} | {fmt(at.get('gone', {}).get('rows'), nd=0)} |")


print("\n### The second run at a moved-on commit (the same 800 units per process, files changed: supersession and the orphan pass)\n")
print("| store | writers | runs | find: s | find: requests | find: old values read MB | store write s (puts + removals) | transactions | SQL on the wire MB | TCP bytes to sqld MB | records removed | orphan pass s | orphan pass requests | orphan pass removed | units lost | rows at rest after | bytes at rest after | attestations rows | manifests rows | objects rows / MB | log rows | gone rows |")
print("|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|---|--:|--:|--:|--:|--:|--:|--:|--:|")
for P in (1, 3):
    for cfg in ("f3", "f1"):
        if (cfg, P) in runs and f"{cfg}/{P}/supersede" in S:
            print(row_super(cfg, P))

print("\n### Attempts under which sqld's write lock stalled (docs/STORE-BACKENDS.md section 21, item 17)\n")
print("Per writer process of each stalled attempt: what the store got committed before it gave up. A stall 'after write' left every unit stored and only the second run could not follow.\n")
print("| store | writers | attempt | phase | process | transactions committed | units lost in the flush that failed (the process then stopped) | longest request s | process wall s | TCP bytes to sqld MB | records in the namespace after (all processes, of P x 800) |")
print("|---|--:|---|---|--:|--:|--:|--:|--:|--:|--:|")
for (cfg, P), attempts in sorted(runs.items()):
    for a in attempts:
        for phase, ph in a["phases"].items():
            if ph["clean"]:
                continue
            stored = ph["atrest"].get("tables", {}).get("attestations", {}).get("rows")
            for i, p in enumerate(ph["procs"]):
                lost = p.get("lost") if p.get("lost") is not None else p.get("batch_not_stored")
                print(f"| {NAME[cfg]} | {P} | {a['rep']} | {phase} | {i} | {p.get('batch_transactions')} | {lost} | {fmt(p.get('batch_secs_longest'))} | {fmt(p.get('wall_secs'))} | {fmt(p.get('wire_c2s_bytes'), '', 1e6)} | {stored if i == 0 else ''} |")
stalls = os.path.join(OUT, "stalls.log")
if os.path.exists(stalls):
    print("\nstalls.log (every matrix run on this host, with the time of day):\n")
    print("".join("    " + l for l in open(stalls)))
