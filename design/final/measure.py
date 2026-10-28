#!/usr/bin/env python3 -I
"""Measure the STORE-V2 format (text record frame, hdr/tables ctx split) on the real vex records in pairs.json.

usage: python3 -I measure.py <pairs.json> <rails.json> <keys.json> <txsize.json> <out dir>

Builds, for every unit: the v2 statement (JSON, sorted keys, compact; `hdr` and `tables` digests), the
signature frame, the descriptor (shape id, group, delta-coded own indices, env bitmap + set values, externals
bitmap), and the text record frame `vci3 LF statement LF base64(sig frame) LF base64(descriptor)`; per run:
the hdr object (toolchain, global manifest, project scalars), the tables object (waiver table, env names,
externals), the shape (paths and kinds), the state (hashes, explain-only), groups estimated (bases are not in
the file). Then the per-partition write (rows, writes, flushes, transactions, bytes on each backend's wire),
the plan read with the production run spread (keys.json), the per-day and steady-state figures from the job
distribution of rails.json, the `gone` growth, and the Turso transaction times of txsize.json.
Writes numbers.json and prints a table. The earlier binary-frame script is measure-binary-frame.py.
"""
import base64
import collections
import hashlib
import json
import os
import random
import re
import statistics as st
import subprocess
import sys

pairs = json.load(open(sys.argv[1]))["pairs"]
rails = json.load(open(sys.argv[2]))
keys = json.load(open(sys.argv[3]))
txsize = json.load(open(sys.argv[4]))
out = sys.argv[5]
os.makedirs(out, exist_ok=True)
random.seed(1)

ZSTD = "/opt/homebrew/bin/zstd"


def zstd(b, level=19):
    if not os.path.exists(ZSTD):
        return None
    r = subprocess.run([ZSTD, f"-{level}", "-q", "-c"], input=b, capture_output=True)
    return len(r.stdout)


def varint(n):
    o = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            o.append(b | 0x80)
        else:
            o.append(b)
            return bytes(o)


def vstr(s):
    b = s.encode()
    return varint(len(b)) + b


def front_code(items):
    """items: sorted list of (path, tail bytes). Encodes varint shared, varint suffix len, suffix, tail."""
    o = bytearray(varint(len(items)))
    prev = b""
    for path, tail in items:
        p = path.encode()
        n = 0
        m = min(len(p), len(prev))
        while n < m and p[n] == prev[n]:
            n += 1
        o += varint(n) + varint(len(p) - n) + p[n:] + tail
        prev = p
    return bytes(o)


def b64(b):
    return base64.b64encode(b)


def b64len(n):
    return (n + 2) // 3 * 4


KIND = {"f": 0, "l": 1, "a": 2, "d": 3, "t": 4, "x": 5, "m": 6, "u": 7}
CONST_HASH_KINDS = {"a", "x", "u"}  # constant hashes: absent, excluded, autoload-dir
ZERO = "0" * 64
GM_KIND = {"file": "f", "absent": "a", "dir": "d", "symlink": "l", "typeOnly": "t", "excluded": "x"}


def stat(xs):
    xs = sorted(xs)
    n = len(xs)
    return {
        "n": n,
        "mean": round(st.mean(xs), 1),
        "p50": xs[n // 2],
        "p90": xs[int(n * 0.9)],
        "max": xs[-1],
        "sum": sum(xs),
    }


def oid(b):
    return hashlib.blake2b(b, digest_size=32).hexdigest()  # stands in for BLAKE3


# ---------------------------------------------------------------- decode today's records
units = []
for env_s, man_s, root in pairs:
    env = json.loads(env_s)
    payload = base64.b64decode(env["payload"])
    stmt = json.loads(payload)
    man = json.loads(man_s)
    units.append(
        {
            "env_bytes": len(env_s.encode()),
            "man_bytes": len(man_s.encode()),
            "payload": payload,
            "stmt": stmt,
            "pred": stmt["predicate"],
            "man": man,
            "sig": env["signatures"][0],
        }
    )
N = len(units)
today_env = [u["env_bytes"] for u in units]
today_man = [u["man_bytes"] for u in units]

# runs: one `vci run` of one project = (commit, issuedAt, projectName)
runs = collections.defaultdict(list)
for u in units:
    p = u["pred"]
    runs[(p["commit"], p["issuedAt"], p.get("projectName", ""), p["adapter"])].append(u)
run_list = sorted(runs.items(), key=lambda kv: -len(kv[1]))
big_rk, big_us = run_list[0]

HDR_FIELDS = (
    "repoId", "adapter", "projectName", "projectDir", "runnerProject", "toolVersion",
    "envConfigDigest", "globalInputRoot", "globalManifest", "ignoredInputs", "railsInputs",
    "envSet", "toolchain",
)


def header_tuple(p):
    return json.dumps({k: p.get(k) for k in HDR_FIELDS}, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------- hdr object (kind 1): the header tuple, shared by every run at the same toolchain and global inputs
def encode_hdr(p):
    o = bytearray(b"vo\x01\x01")
    for k in ("repoId", "adapter", "projectName", "projectDir", "runnerProject", "toolVersion", "railsInputs"):
        o += vstr(str(p.get(k, "")))
    o += bytes.fromhex(p["envConfigDigest"]) + bytes.fromhex(p["globalInputRoot"])
    gm = sorted(p["globalManifest"]["entries"], key=lambda e: (e["path"], e["kind"]))
    items = []
    for e in gm:
        kind = GM_KIND.get(e["kind"], "f")
        tail = bytes([KIND[kind] | (0x80 if e.get("exec") else 0)]) + varint(e["size"])
        if kind not in CONST_HASH_KINDS:
            tail += bytes.fromhex(e["hash"])
        items.append((e["path"], tail))
    o += front_code(items)
    o += varint(len(p.get("ignoredInputs", []))) + b"".join(vstr(s) for s in p.get("ignoredInputs", []))
    o += varint(len(p.get("envSet", []))) + b"".join(vstr(s) for s in p.get("envSet", []))
    tc = dict(p["toolchain"])
    lists = {}
    for k in ("rubyGems", "pythonDists", "goEnv", "rustCfg"):
        if k in tc:
            lists[k] = tc.pop(k)
    o += vstr(json.dumps(tc, sort_keys=True, separators=(",", ":")))
    o += varint(len(lists))
    for k, v in sorted(lists.items()):
        o += vstr(k) + front_code([(str(x), b"") for x in sorted(str(x) for x in v)])
    return bytes(o)


# ---------------------------------------------------------------- tables object (kind 2): per run, the unions over its units
def encode_tables(waiver_table, env_names, externals):
    o = bytearray(b"vo\x02\x01")
    o += varint(len(waiver_table)) + b"".join(vstr(s) for s in waiver_table)
    o += front_code([(n, b"") for n in env_names])
    o += front_code([(n, vstr(v)) for n, v in externals])
    return bytes(o)


hdr_objects, tables_objects = {}, {}
run_info = []
for rk, us in run_list:
    by_header = collections.defaultdict(list)
    for u in us:
        by_header[header_tuple(u["pred"])].append(u)
    hdr_ids, tables_ids = [], []
    for h, hu in by_header.items():
        hdr = encode_hdr(hu[0]["pred"])
        hid = oid(hdr)
        hdr_objects[hid] = hdr
        waiver_table = sorted({w for u in hu for w in u["pred"].get("waived", [])})
        env_names = sorted({k for u in hu for k, _ in u["man"].get("env", [])})
        externals = sorted({(n, v) for u in hu for n, v in u["man"].get("externals", [])})
        tb = encode_tables(waiver_table, env_names, externals)
        tid = oid(tb)
        tables_objects[tid] = tb
        hdr_ids.append(hid)
        tables_ids.append(tid)
        for u in hu:
            u["hdr"] = hid
            u["tables"] = tid
            u["waiver_table"] = waiver_table
            u["env_names"] = env_names
            u["externals_table"] = externals
    run_info.append({"run": rk, "units": len(us), "hdr_count": len(set(hdr_ids)), "tables_count": len(by_header),
                     "hdr_ids": hdr_ids, "tables_ids": tables_ids})

hdr_sizes = {i: len(b) for i, b in hdr_objects.items()}
tables_sizes = {i: len(b) for i, b in tables_objects.items()}


# ---------------------------------------------------------------- per-unit statement v2, signature frame, descriptor, text frame
def entries_root(entries):
    h = hashlib.blake2b(digest_size=32)
    for e in sorted(entries, key=lambda e: (e[0], e[1])):
        h.update(json.dumps(e, separators=(",", ":")).encode())
    return h.hexdigest()


def statement_v2(u):
    p = u["pred"]
    pred = {
        "argv": p["argv"],
        "commit": p["commit"],
        "entriesRoot": entries_root(u["man"].get("entries", [])),
        "expiresAt": p["expiresAt"],
        "hdr": u["hdr"],
        "issuedAt": p["issuedAt"],
        "result": p["result"],
        "tables": u["tables"],
        "testId": p["testId"],
        "tree": p.get("tree", ""),
        "treeDirty": p.get("treeDirty", False),
        "waived": sorted({u["waiver_table"].index(w) for w in p.get("waived", [])}),
    }
    for k in ("tainted", "declaredInputs", "platformSpecific", "archSpecific", "cfgPredicates"):
        if p.get(k):
            pred[k] = p[k]
    s = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicate": pred,
        "predicateType": "https://vci.dev/test-attestation/v2",
        "subject": u["stmt"]["subject"],
    }
    return json.dumps(s, sort_keys=True, separators=(",", ":")).encode()


def sig_frame(u):
    keyid = u["sig"]["keyid"].encode()
    return bytes([1]) + varint(len(keyid)) + keyid + varint(180) + b"\0" * 180


def bitmap(n):
    return (n + 7) // 8


# shape object per run (paths + kinds, no hashes)
shape_sizes, shape_entries, shape_zstd = {}, {}, {}
for rk, us in run_list:
    pks = sorted({(e[0], e[1], bool(e[4]) if len(e) > 4 else False) for u in us for e in u["man"].get("entries", [])})
    index = {(p, k): i for i, (p, k, _) in enumerate(pks)}
    body = b"vo\x03\x01" + front_code([(p, bytes([KIND[k] | (0x80 if ex else 0)])) for p, k, ex in pks])
    # groups (today's bases) are not in the file: estimated below, not encoded here
    shape_sizes[rk] = len(body)
    shape_entries[rk] = len(pks)
    shape_zstd[rk] = zstd(body)
    for u in us:
        u["shape_index"] = index


def descriptor(u):
    """Index list into the run's shape object."""
    m = u["man"]
    idx = u["shape_index"]
    o = bytearray(b"\0" * 32)  # shape id
    o += b"\xff" if not m.get("base") else b"\x00"  # group index (0xff none)
    ids = sorted(idx[(e[0], e[1])] for e in m.get("entries", []))
    o += varint(len(ids))
    prev = -1
    for i in ids:
        o += varint(i - prev - 1)
        prev = i
    names = u["env_names"]
    nidx = {n: i for i, n in enumerate(names)}
    setv = [(nidx[k], v) for k, v in m.get("env", []) if v is not None]
    o += varint(len(setv)) + b"".join(varint(i) + bytes.fromhex(v) for i, v in setv)
    o += b"\0" * bitmap(len(names))  # 1 bit per ctx.tables.envNames entry
    ext = u["externals_table"]
    o += b"\0" * bitmap(len(ext))  # 1 bit per ctx.tables.externals pair
    o += varint(0)  # inline externals not in the table: never by construction
    return bytes(o)


def text_frame(s, f, d):
    return b"vci3\n" + s + b"\n" + b64(f) + b"\n" + b64(d)


stmt_b, sigf_b, desc_b, rec_b, binrec_b, own_entries, quotes = [], [], [], [], [], [], 0
for u in units:
    s = statement_v2(u)
    assert b"\n" not in s and b"\0" not in s
    f = sig_frame(u)
    d = descriptor(u)
    rec = text_frame(s, f, d)
    assert rec.decode("utf-8")
    u["record"] = rec
    u["binary_record"] = b"\x03\x00" + varint(len(s)) + s + f + d  # the earlier binary frame, for the comparison row
    stmt_b.append(len(s)); sigf_b.append(len(f)); desc_b.append(len(d)); rec_b.append(len(rec)); binrec_b.append(len(u["binary_record"]))
    own_entries.append(len(u["man"].get("entries", [])))
    quotes += rec.count(b"'")  # doubled by the libSQL text literal

by_adapter = collections.defaultdict(list)
for u in units:
    by_adapter[u["pred"]["adapter"]].append(len(u["record"]))

# ---------------------------------------------------------------- state object per run (hashes, explain only)
def state_body(us):
    tuples = set()
    for u in us:
        for e in u["man"].get("entries", []):
            tuples.add((e[0], e[1], bool(e[4]) if len(e) > 4 else False, e[2], e[3]))
    items = []
    for path, kind, ex, size, h in sorted(tuples):
        tail = bytes([KIND[kind] | (0x80 if ex else 0)]) + varint(size)
        if kind not in CONST_HASH_KINDS and h != ZERO:
            tail += bytes.fromhex(h)
        items.append((path, tail))
    return b"vo\x04\x01" + front_code(items), len(tuples)


state_sizes, state_zstd, state_entries, conflicts = {}, {}, {}, {}
for rk, us in run_list:
    body, n_entries = state_body(us)
    pk = collections.defaultdict(set)
    for u in us:
        for e in u["man"].get("entries", []):
            pk[(e[0], e[1])].add((e[2], e[3]))
    state_sizes[rk] = len(body)
    state_zstd[rk] = zstd(body)
    state_entries[rk] = n_entries
    conflicts[rk] = sum(1 for v in pk.values() if len(v) > 1)

# groups (today's bases): estimated, they are not in pairs.json. In the shape a group is an index set over the
# shape's entries (delta varints, ~1.5 B each) plus the group's entries themselves if no unit lists them on its
# own. Low: the 9 groups' 440 entries are one shared set (440 extra entries); high: 9 disjoint sets (3,960).
BASE_ENTRIES = 440
BASES_PER_RUN = 9
fc_bytes_per_entry = shape_sizes[big_rk] / shape_entries[big_rk]
state_per_entry = state_sizes[big_rk] / state_entries[big_rk]
groups_index_bytes = BASES_PER_RUN * int(BASE_ENTRIES * 1.5)
groups_shape_low = groups_index_bytes + int(BASE_ENTRIES * fc_bytes_per_entry)
groups_shape_high = groups_index_bytes + int(BASES_PER_RUN * BASE_ENTRIES * fc_bytes_per_entry)
bases_state_low, bases_state_high = int(440 * state_per_entry), int(9 * 440 * state_per_entry)
bases_per_run_bytes = groups_shape_high  # the conservative figure is used in every total below


# ---------------------------------------------------------------- objects as a function of run size (subsets of the 973-unit run)
def objects_for(us):
    """(hdr, tables, shape, state, distinct entries) bytes of a run of these Rails units (no groups)."""
    p = us[0]["pred"]
    hdr = encode_hdr(p)
    waiver = sorted({w for u in us for w in u["pred"].get("waived", [])})
    env_names = sorted({k for u in us for k, _ in u["man"].get("env", [])})
    ext = sorted({(n, v) for u in us for n, v in u["man"].get("externals", [])})
    tb = encode_tables(waiver, env_names, ext)
    pks = sorted({(e[0], e[1], bool(e[4]) if len(e) > 4 else False) for u in us for e in u["man"].get("entries", [])})
    shape = b"vo\x03\x01" + front_code([(pp, bytes([KIND[k] | (0x80 if ex else 0)])) for pp, k, ex in pks])
    state, _ = state_body(us)
    return len(hdr), len(tb), len(shape), len(state), len(pks)


curve = {}
for n in (1, 2, 5, 10, 22, 45, 67, 108, 187, 231, 260, 328, 363, 516, 540, 588, 800, 867, 973):
    n = min(n, len(big_us))
    reps = 5 if n < len(big_us) else 1
    acc = [objects_for(random.sample(big_us, n)) for _ in range(reps)]
    curve[n] = [round(st.mean(x[i] for x in acc)) for i in range(5)]
HDR, TABLES, SHAPE, STATE = 0, 1, 2, 3


def interp(n, col):
    ks = sorted(curve)
    if n <= ks[0]:
        return curve[ks[0]][col]
    if n >= ks[-1]:
        a, b = ks[-2], ks[-1]
        return curve[b][col] + (curve[b][col] - curve[a][col]) * (n - b) / (b - a)
    for a, b in zip(ks, ks[1:]):
        if a <= n <= b:
            return curve[a][col] + (curve[b][col] - curve[a][col]) * (n - a) / (b - a)


def run_objects(n, groups=True):
    """(hdr, tables, shape, state) bytes of a Rails run of n units; groups at the high estimate scaled by n/800."""
    g_shape = groups_shape_high * min(1, n / 800) if groups else 0
    g_state = bases_state_high * min(1, n / 800) if groups else 0
    return interp(n, HDR), interp(n, TABLES), interp(n, SHAPE) + g_shape, interp(n, STATE) + g_state


# ---------------------------------------------------------------- the partition: a hash-parity half of the 973-unit run
half = [u for u in big_us if int(hashlib.sha256(u["pred"]["testId"].encode()).hexdigest(), 16) % 2 == 0]
half_rec = sum(len(u["record"]) for u in half)
half_today = sum(u["env_bytes"] + u["man_bytes"] for u in half)
half_state, _ = state_body(half)
half_hdr = sum(hdr_sizes[i] for i in {u["hdr"] for u in half})
half_tables = sum(tables_sizes[i] for i in {u["tables"] for u in half})
pks = sorted({(e[0], e[1], bool(e[4]) if len(e) > 4 else False) for u in half for e in u["man"].get("entries", [])})
half_shape = b"vo\x03\x01" + front_code([(p, bytes([KIND[k] | (0x80 if ex else 0)])) for p, k, ex in pks])

# ---------------------------------------------------------------- the whole sample at rest
records_total = sum(rec_b)
hdr_total = sum(hdr_sizes.values())
tables_total = sum(tables_sizes.values())
state_total = sum(state_sizes.values())
shape_total = sum(shape_sizes.values())
bases_total_est = len(run_list) * bases_per_run_bytes
today_total = sum(today_env) + sum(today_man)

# ---------------------------------------------------------------- cross-commit stability (judges' 6/6)
by_test = collections.defaultdict(list)
for u in units:
    by_test[u["pred"]["testId"]].append(
        (u["pred"]["commit"], frozenset((e[0], e[1]) for e in u["man"].get("entries", [])), u["stmt"]["subject"][0]["digest"]["blake3"])
    )
multi = {t: v for t, v in by_test.items() if len({c for c, _, _ in v}) > 1}
same_set = sum(1 for v in multi.values() if len({s for _, s, _ in v}) == 1)
same_root = sum(1 for v in multi.values() if len({r for _, _, r in v}) == 1)
ea = {(e[0], e[1]): (e[2], e[3]) for u in run_list[0][1] for e in u["man"].get("entries", [])}
eb = {(e[0], e[1]): (e[2], e[3]) for u in run_list[1][1] for e in u["man"].get("entries", [])}
common = set(ea) & set(eb)
same_state = sum(1 for k in common if ea[k] == eb[k])

# ---------------------------------------------------------------- scale to vex
UNITS_PER_PARTITION = 800        # the partition maximum class (production max 972 attempted)
UNITS_LISTED = 2305
CANDIDATES_PER_UNIT = 1.9
VALUES_PER_PLAN = 1644
KEY_BYTES = 190
FLUSH_WRITES = 2000              # crates/vci-store-libsql/src/batch.rs:95
FLUSH_BYTES = 4 << 20            # batch.rs:98
TX_BYTES = 1 << 20               # batch.rs:106
REMOVALS_PER_RECORD = 64383 / 53650  # rails.json 27 Oct: removals / attestations attempted (wb columns 2 / 1)
OBJECTS_PER_RUN = 4              # hdr, tables, shape, state
rec_mean = st.mean(rec_b)
rails_recs = [len(u["record"]) for u in units if u["pred"]["adapter"] == "rails"]
rails_rec_mean = st.mean(rails_recs)
quote_bytes_per_record = quotes / N
scale = UNITS_PER_PARTITION / len(half)  # 800-unit partition from the measured 516-unit half
shape_per_run = int(len(half_shape) * scale + bases_per_run_bytes)
state_per_run = int(len(half_state) * scale + bases_state_high)
hdr_per_run = hdr_sizes[big_us[0]["hdr"]]
tables_per_run = tables_sizes[big_us[0]["tables"]]
verdict_objects_per_run = hdr_per_run + tables_per_run + shape_per_run
objects_per_run = verdict_objects_per_run + state_per_run


def partition(n, state=True):
    """The write of an n-unit Rails partition: bytes at rest (SQLite/PostgreSQL), bytes on the libSQL wire, rows, writes."""
    records = n * rails_rec_mean
    objs = [hdr_per_run, tables_per_run, shape_per_run, state_per_run if state else 0] if n == UNITS_PER_PARTITION else list(run_objects(n))
    if not state:
        objs[3] = 0
    obj_sum = sum(objs)
    writes = OBJECTS_PER_RUN + n + 2 * REMOVALS_PER_RECORD * n  # put, removal, gone row
    wire = records + quote_bytes_per_record * n + sum(b64len(int(o)) for o in objs)
    return {
        "units": n, "rows": n + OBJECTS_PER_RUN, "records_bytes": int(records),
        "hdr": int(objs[0]), "tables": int(objs[1]), "shape": int(objs[2]), "state": int(objs[3]),
        "objects_bytes": int(obj_sum), "bytes_at_rest": int(records + obj_sum),
        "libsql_wire_bytes": int(wire), "libsql_object_wire_bytes": int(wire - records),
        "writes": int(writes), "flushes": int(-(-writes // FLUSH_WRITES)),
        "transactions_at_1MiB": int(-(-wire // TX_BYTES)),
    }


flush_threshold_units = int((FLUSH_WRITES - OBJECTS_PER_RUN) / (1 + 2 * REMOVALS_PER_RECORD))
partition_800 = partition(UNITS_PER_PARTITION)
partition_800_nostate = partition(UNITS_PER_PARTITION, state=False)
partition_970 = partition(970)
partition_328 = partition(328)
partition_540 = partition(540)
today_partition_write = UNITS_PER_PARTITION * (st.mean(today_env) + st.mean(today_man)) + BASES_PER_RUN * 50_000

# plan reads: records + objects of the runs the candidates come from. Objects per run from the curve at the
# production run spread (keys.json: the live listing of vex-api, 27 Oct 15:20).
plan_records = VALUES_PER_PLAN * rails_rec_mean
plan_listing = UNITS_LISTED * CANDIDATES_PER_UNIT * KEY_BYTES
by_unit = collections.defaultdict(list)
for k in keys:
    parts = k.split(":")
    if len(parts) != 6:
        continue
    issued, tree = parts[5].split(".")
    by_unit[parts[2]].append((int(issued, 16), tree, parts[3]))
newest = collections.Counter()
allruns = collections.Counter()
for tk, c in by_unit.items():
    for s in {s for _, _, s in c}:
        i, t = max((i, t) for i, t, ss in c if ss == s)
        newest[(i, t)] += 1
    for i, t, _ in c:
        allruns[(i, t)] += 1
sizes_newest = sorted(newest.values(), reverse=True)
sizes_all = sorted(allruns.values(), reverse=True)
HDR_DISTINCT_SAMPLE = len(hdr_objects)


def plan_objects(sizes, hdr_distinct):
    tb = sum(run_objects(n)[1] for n in sizes)
    sh = sum(run_objects(n)[2] for n in sizes)
    stt = sum(run_objects(n)[3] for n in sizes)
    hdr_ceiling = sum(run_objects(n)[0] for n in sizes)
    hdr_expected = hdr_distinct * hdr_per_run
    return {"runs": len(sizes), "tables": int(tb), "shape": int(sh), "hdr_ceiling_one_per_run": int(hdr_ceiling),
            "hdr_expected": int(hdr_expected), "verdict_objects_expected": int(tb + sh + hdr_expected),
            "verdict_objects_ceiling": int(tb + sh + hdr_ceiling), "state_all_runs": int(stt),
            "one_ctx_per_run_as_before": int(tb + sh + hdr_ceiling),
            "sizes": sizes}


plan_spread = {
    "newest per (unit,signer)": plan_objects(sizes_newest, 11),
    "every live candidate": plan_objects(sizes_all, 11),
}
plan_reads = {}
for runs_touched in (4, 10, 20, 50):
    v = runs_touched * verdict_objects_per_run
    plan_reads[runs_touched] = {
        "verdict_bytes_ceiling": int(plan_listing + plan_records + v),
        "with_state_for_explain": int(plan_listing + plan_records + runs_touched * objects_per_run),
    }
today_plan = plan_listing + VALUES_PER_PLAN * (st.mean(today_env) + st.mean(today_man))
SHAPE_CAP = 16 << 20
STATE_CAP_COUNT = 16

# ---------------------------------------------------------------- per day and steady state from rails.json (164 Rails jobs, 27 Oct)
attested, attempted = [], []
for r in rails:
    for l in r["attested"]:
        m = re.search(r"(\d+) attested, (\d+) not attested", l)
        if m:
            attested.append(int(m[1]))
            attempted.append(int(m[1]) + int(m[2]))
jobs = len(rails)
removals_day = sum(sum(w[2] for w in r["wb"]) for r in rails)
records_attempted_day = sum(sum(w[1] for w in r["wb"]) for r in rails)


def day(counts):
    rec = sum(counts) * rails_rec_mean
    objs = [run_objects(n) for n in counts if n]
    return {"units": sum(counts), "jobs_with_a_line": len(counts), "mean": round(st.mean(counts)), "max": max(counts),
            "records_mb": rec / 1e6, "hdr_ceiling_mb": sum(o[0] for o in objs) / 1e6,
            "tables_mb": sum(o[1] for o in objs) / 1e6, "shape_mb": sum(o[2] for o in objs) / 1e6,
            "state_mb": sum(o[3] for o in objs) / 1e6,
            "total_mb": (rec + sum(sum(o) for o in objs)) / 1e6,
            "total_without_state_mb": (rec + sum(o[0] + o[1] + o[2] for o in objs)) / 1e6,
            "today_mb": sum(counts) * (st.mean(today_env) + st.mean(today_man)) / 1e6}


day_attempted = day(attempted)
day_attested = day(attested)
GONE_ROW = KEY_BYTES + 8 + 8 + 8  # key, seq, at, object NULL
MAX_TTL_DAYS = 14                 # vex's max_ttl
STATE_DAYS = 2                    # explain_hashes_days default
LIVE_RECORDS = 24_000
steady = {
    "records_mb": LIVE_RECORDS * rails_rec_mean / 1e6,
    "hdr_mb_ceiling_14d": MAX_TTL_DAYS * day_attempted["hdr_ceiling_mb"],
    "tables_shape_mb_ceiling_14d": MAX_TTL_DAYS * (day_attempted["tables_mb"] + day_attempted["shape_mb"]),
    "state_mb_2d": STATE_DAYS * day_attempted["state_mb"],
    "state_mb_if_14d": MAX_TTL_DAYS * day_attempted["state_mb"],
    "gone_rows_30d": 30 * removals_day, "gone_mb_30d": 30 * removals_day * GONE_ROW / 1e6,
    "gone_rows_day": removals_day, "gone_mb_day": removals_day * GONE_ROW / 1e6,
}
steady["total_mb_ceiling"] = steady["records_mb"] + steady["hdr_mb_ceiling_14d"] + steady["tables_shape_mb_ceiling_14d"] + steady["state_mb_2d"] + steady["gone_mb_30d"]
memo_rows_day = sum(r["p1"].get("skip", 0) for r in rails if r["p1"]) + sum(r["p2"].get("skip", 0) for r in rails if r["p2"])

# ---------------------------------------------------------------- Turso transaction time vs bytes (txsize.json)
bymb = collections.defaultdict(list)
for rep, mb, rows, size, tsel, ttx in txsize:
    bymb[mb].append(ttx)
tx_table = {str(mb): {"min": min(v), "max": max(v), "mean": round(st.mean(v), 1)} for mb, v in sorted(bymb.items())}

numbers = {
    "units": N,
    "frame": "vci3 LF statement LF base64(sig frame) LF base64(descriptor); records with an apostrophe (doubled by the libSQL text literal): "
             f"{sum(1 for u in units if b"'" in u['record'])}, apostrophes per record {round(quote_bytes_per_record, 3)}",
    "runs": [{"commit": rk[0][:8], "issued": rk[1], "project": rk[2], "adapter": rk[3], "units": len(us),
              "hdr_count": ri["hdr_count"], "hdr_bytes": sorted({hdr_sizes[i] for i in ri["hdr_ids"]}),
              "tables_count": ri["tables_count"], "tables_bytes": [tables_sizes[i] for i in ri["tables_ids"]],
              "shape_bytes": shape_sizes[rk], "shape_entries": shape_entries[rk], "shape_zstd": shape_zstd[rk],
              "state_bytes": state_sizes[rk], "state_zstd": state_zstd[rk], "state_entries": state_entries[rk],
              "conflicts": conflicts[rk]}
             for (rk, us), ri in zip(run_list, run_info)],
    "today": {"envelope": stat(today_env), "manifest": stat(today_man), "per_unit": round(st.mean(today_env) + st.mean(today_man)),
              "total": today_total},
    "v2": {
        "statement": stat(stmt_b), "sig_frame": stat(sigf_b), "sig_frame_base64": b64len(234),
        "descriptor": stat(desc_b), "descriptor_base64_mean": round(st.mean(b64len(d) for d in desc_b), 1),
        "record": stat(rec_b), "binary_record_for_comparison": stat(binrec_b),
        "record_by_adapter": {a: stat(v) for a, v in by_adapter.items()},
        "own_entries": stat(own_entries),
        "hdr": {"distinct_in_sample": HDR_DISTINCT_SAMPLE, "bytes": stat(list(hdr_sizes.values())),
                "rails_bytes": sorted({hdr_sizes[u["hdr"]] for u in units if u["pred"]["adapter"] == "rails"})},
        "tables": {"count": len(tables_objects), "bytes": stat(list(tables_sizes.values())),
                   "big_run": tables_sizes[big_us[0]["tables"]], "run_185": tables_sizes[run_list[1][1][0]["tables"]]},
        "shape": {"bytes_sum": shape_total, "zstd_sum": sum(v for v in shape_zstd.values() if v),
                  "big_run": {"bytes": shape_sizes[big_rk], "entries": shape_entries[big_rk], "zstd": shape_zstd[big_rk],
                              "bytes_per_entry": round(fc_bytes_per_entry, 1)}},
        "state": {"bytes_sum": state_total, "zstd_sum": sum(v for v in state_zstd.values() if v),
                  "big_run": {"bytes": state_sizes[big_rk], "entries": state_entries[big_rk], "zstd": state_zstd[big_rk],
                              "bytes_per_entry": round(state_per_entry, 1)}},
        "groups_estimate": {"entries_per_group": BASE_ENTRIES, "groups_per_run": BASES_PER_RUN,
                            "index_bytes": groups_index_bytes, "shape_bytes_low_high": [groups_shape_low, groups_shape_high],
                            "state_bytes_low_high": [bases_state_low, bases_state_high], "used_in_totals": "high"},
        "at_rest_1175": {"records": records_total, "hdr": hdr_total, "tables": tables_total, "shape": shape_total,
                         "groups_est": bases_total_est, "state": state_total,
                         "total_verdict_path": records_total + hdr_total + tables_total + shape_total + bases_total_est,
                         "total_with_state": records_total + hdr_total + tables_total + shape_total + bases_total_est + state_total,
                         "per_unit_with_state": round((records_total + hdr_total + tables_total + shape_total + bases_total_est + state_total) / N),
                         "per_unit_without_state": round((records_total + hdr_total + tables_total + shape_total + bases_total_est) / N),
                         "ratio_vs_today": round(today_total / (records_total + hdr_total + tables_total + shape_total + bases_total_est + state_total), 1),
                         "ratio_vs_today_without_state": round(today_total / (records_total + hdr_total + tables_total + shape_total + bases_total_est), 1)},
        "curve_hdr_tables_shape_state_entries": curve,
    },
    "partition_516": {"units": len(half), "records": half_rec, "hdr": half_hdr, "tables": half_tables,
                      "shape": len(half_shape), "shape_zstd": zstd(half_shape), "groups_est": bases_per_run_bytes,
                      "state": len(half_state), "state_zstd": zstd(half_state),
                      "total": half_rec + half_hdr + half_tables + len(half_shape) + bases_per_run_bytes + len(half_state),
                      "today": half_today + BASES_PER_RUN * 50_000, "rows": len(half) + OBJECTS_PER_RUN},
    "vex_scale": {
        "assumptions": {"units_per_partition": UNITS_PER_PARTITION, "jobs_per_day": jobs, "units_listed": UNITS_LISTED,
                        "candidates_per_unit": CANDIDATES_PER_UNIT, "values_per_plan": VALUES_PER_PLAN,
                        "today_base_bytes": 50_000, "key_bytes": KEY_BYTES, "removals_per_record": round(REMOVALS_PER_RECORD, 2),
                        "flush_writes": FLUSH_WRITES, "flush_bytes": FLUSH_BYTES, "tx_bytes": TX_BYTES},
        "writes_per_record": round(1 + 2 * REMOVALS_PER_RECORD, 2),
        "second_flush_above_units": flush_threshold_units,
        "partition_800": partition_800, "partition_800_no_state": partition_800_nostate,
        "partition_970": partition_970, "partition_540": partition_540, "partition_328": partition_328,
        "partition_today": {"bytes": int(today_partition_write), "rows": UNITS_PER_PARTITION * 2 + BASES_PER_RUN,
                            "libsql_wire_bytes_hex_or_text": "JSON travels 1:1; 29.5 MB"},
        "plan_read": {"today_bytes": int(today_plan), "listing_bytes": int(plan_listing), "records_bytes": int(plan_records),
                      "by_runs_touched": plan_reads, "production_spread": plan_spread,
                      "shape_cap_bytes": SHAPE_CAP, "state_cap_count": STATE_CAP_COUNT},
        "per_day": {"attempted": day_attempted, "attested": day_attested, "records_attempted_from_wb": records_attempted_day,
                    "removals": removals_day, "memo_rows_today": memo_rows_day, "log_rows_today": "~400k"},
        "steady_state": steady,
        "turso_tx_seconds_by_mb": tx_table,
    },
    "stability": {"units_at_more_than_one_commit": len(multi), "same_path_kind_set": same_set, "same_root": same_root,
                  "entries_common_to_two_largest_runs": len(common), "same_size_and_hash": same_state},
}
json.dump(numbers, open(os.path.join(out, "numbers.json"), "w"), indent=1)

v2 = numbers["v2"]
print(f"units {N}; today {numbers['today']['per_unit']} B/unit ({today_total/1e6:.2f} MB)")
print(f"v2 statement {v2['statement']['mean']} B mean (p50 {v2['statement']['p50']}, max {v2['statement']['max']})")
print(f"v2 sig frame {v2['sig_frame']['mean']} B ({v2['sig_frame_base64']} base64); descriptor {v2['descriptor']['mean']} B mean (p50 {v2['descriptor']['p50']}, max {v2['descriptor']['max']}; base64 mean {v2['descriptor_base64_mean']})")
print(f"v2 text record {v2['record']['mean']} B mean (p50 {v2['record']['p50']}, p90 {v2['record']['p90']}, max {v2['record']['max']}); binary frame would be {v2['binary_record_for_comparison']['mean']}")
for a, s in v2["record_by_adapter"].items():
    print(f"  {a}: {s['mean']} B mean, max {s['max']}, n {s['n']}")
print(f"hdr objects: {HDR_DISTINCT_SAMPLE} distinct in the sample, {v2['hdr']['bytes']}; rails {v2['hdr']['rails_bytes']}")
print(f"tables objects: {v2['tables']['count']}, {v2['tables']['bytes']}; big run {v2['tables']['big_run']}, 185-unit run {v2['tables']['run_185']}")
for r in numbers["runs"]:
    print(f"run {r['commit']} {r['project']:10} {r['adapter']:9} units {r['units']:4} hdr {r['hdr_count']} {r['hdr_bytes']} tables {r['tables_count']} {r['tables_bytes']} shape {r['shape_bytes']} B / {r['shape_entries']} (zstd {r['shape_zstd']}) state {r['state_bytes']} B (zstd {r['state_zstd']}) conflicts {r['conflicts']}")
print(f"groups estimate: {v2['groups_estimate']}")
print(f"at rest 1175: {v2['at_rest_1175']}")
print("curve (units: hdr, tables, shape, state, entries):")
for n, v in curve.items():
    print(f"  {n:4}: {v}")
print(f"partition 516: {numbers['partition_516']}")
print(f"writes per record {numbers['vex_scale']['writes_per_record']}; second flush above {flush_threshold_units} units")
for k in ("partition_328", "partition_540", "partition_800", "partition_800_no_state", "partition_970"):
    print(f"{k}: {numbers['vex_scale'][k]}")
print(f"plan: today {today_plan/1e6:.1f} MB; listing {plan_listing/1e6:.2f} + records {plan_records/1e6:.2f} MB; by runs {json.dumps(plan_reads)}")
for k, v in plan_spread.items():
    print(f"plan objects, runs from {k}: {v['runs']} runs; tables {v['tables']/1e6:.2f} MB + shape {v['shape']/1e6:.2f} MB + hdr {v['hdr_expected']/1e3:.0f} KB (11 distinct; ceiling one per run {v['hdr_ceiling_one_per_run']/1e6:.2f} MB) = {v['verdict_objects_expected']/1e6:.2f} MB expected, {v['verdict_objects_ceiling']/1e6:.2f} MB ceiling; state of all runs {v['state_all_runs']/1e6:.2f} MB; shape cap headroom {SHAPE_CAP/v['verdict_objects_ceiling']:.1f}x")
print(f"per day attempted: {day_attempted}")
print(f"per day attested: {day_attested}")
print(f"records attempted/day (wb) {records_attempted_day}, removals/day {removals_day} ({REMOVALS_PER_RECORD:.2f} per record), memo rows/day {memo_rows_day}")
print(f"steady state: {steady}")
print(f"turso tx s by MB: {tx_table}")
print(f"stability: {numbers['stability']}")
