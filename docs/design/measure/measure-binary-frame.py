#!/usr/bin/env python3 -I
"""Measure the STORE-V2 format on the real vex records in pairs.json.

usage: python3 -I measure.py <pairs.json> <out dir>

Builds, for every unit: the v2 statement (JSON, sorted keys, compact), the signature frame, the
manifest part (base ref, front-coded own (path, kind) list without hashes, env bitmap + set values,
externals bitmap), and per run: the ctx object, the base objects (estimated: bases are not in the
file), the state object (hashes, explain-only). Writes numbers.json and prints a table.
"""
import base64
import collections
import hashlib
import json
import os
import statistics as st
import subprocess
import sys

pairs = json.load(open(sys.argv[1]))["pairs"]
out = sys.argv[2]
os.makedirs(out, exist_ok=True)

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


KIND = {"f": 0, "l": 1, "a": 2, "d": 3, "t": 4, "x": 5, "m": 6, "u": 7}
CONST_HASH_KINDS = {"a", "x", "u"}  # constant hashes: absent, excluded, autoload-dir
ZERO = "0" * 64


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


def header_tuple(p):
    return json.dumps(
        {
            k: p.get(k)
            for k in (
                "repoId", "adapter", "projectName", "projectDir", "runnerProject", "toolVersion",
                "envConfigDigest", "globalInputRoot", "globalManifest", "ignoredInputs", "railsInputs",
                "envSet", "toolchain",
            )
        },
        sort_keys=True,
        separators=(",", ":"),
    )


# ---------------------------------------------------------------- ctx objects (one per distinct header per run)
def encode_ctx(p, waiver_table, env_names, externals):
    o = bytearray(b"vo\x01\x01")
    for k in ("repoId", "adapter", "projectName", "projectDir", "runnerProject", "toolVersion", "railsInputs"):
        o += vstr(str(p.get(k, "")))
    o += bytes.fromhex(p["envConfigDigest"]) + bytes.fromhex(p["globalInputRoot"])
    gm = sorted(p["globalManifest"]["entries"], key=lambda e: (e["path"], e["kind"]))
    items = []
    for e in gm:
        kind = {"file": "f", "absent": "a", "dir": "d", "symlink": "l", "typeOnly": "t", "excluded": "x"}.get(e["kind"], "f")
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
    o += varint(len(waiver_table)) + b"".join(vstr(s) for s in waiver_table)
    o += front_code([(n, b"") for n in env_names])
    o += front_code([(n, vstr(v)) for n, v in externals])
    return bytes(o)


ctx_of_unit = {}
ctx_objects = {}  # id -> bytes
run_info = []
for rk, us in run_list:
    by_header = collections.defaultdict(list)
    for u in us:
        by_header[header_tuple(u["pred"])].append(u)
    ctx_ids = []
    for h, hu in by_header.items():
        waiver_table = sorted({w for u in hu for w in u["pred"].get("waived", [])})
        env_names = sorted({k for u in hu for k, _ in u["man"].get("env", [])})
        externals = sorted({(n, v) for u in hu for n, v in u["man"].get("externals", [])})
        body = encode_ctx(hu[0]["pred"], waiver_table, env_names, externals)
        cid = hashlib.blake2b(body, digest_size=32).hexdigest()  # stands in for BLAKE3
        ctx_objects[cid] = body
        ctx_ids.append(cid)
        for u in hu:
            u["ctx"] = cid
            u["waiver_table"] = waiver_table
            u["env_names"] = env_names
            u["externals_table"] = externals
    run_info.append({"run": rk, "units": len(us), "ctx_count": len(by_header), "ctx_ids": ctx_ids})

ctx_sizes = {cid: len(b) for cid, b in ctx_objects.items()}
ctx_zstd = {cid: zstd(b) for cid, b in ctx_objects.items()}

# ---------------------------------------------------------------- per-unit statement v2, signature frame, manifest part
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
        "ctx": u["ctx"],
        "entriesRoot": entries_root(u["man"].get("entries", [])),
        "expiresAt": p["expiresAt"],
        "issuedAt": p["issuedAt"],
        "result": p["result"],
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


def manifest_part(u):
    m = u["man"]
    o = bytearray()
    o += (b"\x01" + bytes.fromhex(m["base"])) if m.get("base") else b"\x00"
    ents = sorted(((e[0], e[1], (e[4] if len(e) > 4 else False)) for e in m.get("entries", [])), key=lambda e: (e[0], e[1]))
    o += front_code([(path, bytes([KIND[k] | (0x80 if ex else 0)])) for path, k, ex in ents])
    names = u["env_names"]
    idx = {n: i for i, n in enumerate(names)}
    o += varint(len(names)) + b"\0" * bitmap(len(names))
    setv = [(idx[k], v) for k, v in m.get("env", []) if v is not None]
    o += varint(len(setv)) + b"".join(varint(i) + bytes.fromhex(v) for i, v in setv)
    ext = u["externals_table"]
    o += varint(len(ext)) + b"\0" * bitmap(len(ext))
    o += varint(0)  # inline externals not in the table (never, the table is the union)
    return bytes(o)


# ---------------------------------------------------------------- shape object per run (paths + kinds, no hashes)
shape_sizes, shape_entries, shape_zstd = {}, {}, {}
for rk, us in run_list:
    pks = sorted({(e[0], e[1], bool(e[4]) if len(e) > 4 else False) for u in us for e in u["man"].get("entries", [])})
    index = {(p, k): i for i, (p, k, _) in enumerate(pks)}
    body = b"vo\x02\x01" + front_code([(p, bytes([KIND[k] | (0x80 if ex else 0)])) for p, k, ex in pks])
    # groups (today's bases) are not in the file: estimated below, not encoded here
    shape_sizes[rk] = len(body)
    shape_entries[rk] = len(pks)
    shape_zstd[rk] = zstd(body)
    for u in us:
        u["shape_index"] = index


def descriptor(u):
    """Layout B: index list into the run's shape object."""
    m = u["man"]
    idx = u["shape_index"]
    o = bytearray(b"\0" * 32)  # shape id
    o += b"\x00" if not m.get("base") else b"\x01"  # group index (0xff none); the group is a named index set in the shape
    ids = sorted(idx[(e[0], e[1])] for e in m.get("entries", []))
    o += varint(len(ids))
    prev = -1
    for i in ids:
        o += varint(i - prev - 1)
        prev = i
    names = u["env_names"]
    nidx = {n: i for i, n in enumerate(names)}
    o += varint(len(names)) + b"\0" * bitmap(len(names))
    setv = [(nidx[k], v) for k, v in m.get("env", []) if v is not None]
    o += varint(len(setv)) + b"".join(varint(i) + bytes.fromhex(v) for i, v in setv)
    ext = u["externals_table"]
    o += varint(len(ext)) + b"\0" * bitmap(len(ext))
    o += varint(0)  # inline (path, kind) entries not in the shape: never by construction
    return bytes(o)


stmt_b, sigf_b, manp_b, rec_b, own_entries, desc_b, recB_b = [], [], [], [], [], [], []
for u in units:
    s = statement_v2(u)
    f = sig_frame(u)
    m = manifest_part(u)
    d = descriptor(u)
    rec = b"\x03\x00" + varint(len(s)) + s + f + m  # layout A (inline set)
    recB = b"\x03\x00" + varint(len(s)) + s + f + d  # layout B (descriptor into the shape)
    u["record_inline"] = rec
    u["record"] = recB
    stmt_b.append(len(s)); sigf_b.append(len(f)); manp_b.append(len(m)); rec_b.append(len(rec))
    desc_b.append(len(d)); recB_b.append(len(recB))
    own_entries.append(len(u["man"].get("entries", [])))

# per-adapter record sizes
by_adapter = collections.defaultdict(list)
for u in units:
    by_adapter[u["pred"]["adapter"]].append(len(u["record"]))

# ---------------------------------------------------------------- state object per run (hashes, explain only)
state_sizes, state_zstd, state_entries, conflicts = {}, {}, {}, {}
for rk, us in run_list:
    tuples = set()
    pk = collections.defaultdict(set)
    for u in us:
        for e in u["man"].get("entries", []):
            t = (e[0], e[1], bool(e[4]) if len(e) > 4 else False, e[2], e[3])
            tuples.add(t)
            pk[(e[0], e[1])].add((e[2], e[3]))
    items = []
    for path, kind, ex, size, h in sorted(tuples):
        tail = bytes([KIND[kind] | (0x80 if ex else 0)]) + varint(size)
        if kind not in CONST_HASH_KINDS and h != ZERO:
            tail += bytes.fromhex(h)
        items.append((path, tail))
    body = b"vo\x03\x01" + front_code(items)
    state_sizes[rk] = len(body)
    state_zstd[rk] = zstd(body)
    state_entries[rk] = len(tuples)
    conflicts[rk] = sum(1 for v in pk.values() if len(v) > 1)

# groups (today's bases): estimated, they are not in pairs.json. In the shape a group is an index set over the
# shape's entries (delta varints, ~1.5 B each) plus the group's entries themselves if no unit lists them on its
# own. Low: the 9 groups' 440 entries are one shared set (440 extra entries); high: 9 disjoint sets (3,960).
big_rk, big_us = run_list[0]
BASE_ENTRIES = 440
BASES_PER_RUN = 9
fc_bytes_per_entry = shape_sizes[big_rk] / shape_entries[big_rk]
state_per_entry = state_sizes[big_rk] / state_entries[big_rk]
groups_index_bytes = BASES_PER_RUN * int(BASE_ENTRIES * 1.5)
groups_shape_low = groups_index_bytes + int(BASE_ENTRIES * fc_bytes_per_entry)
groups_shape_high = groups_index_bytes + int(BASES_PER_RUN * BASE_ENTRIES * fc_bytes_per_entry)
bases_state_low, bases_state_high = int(440 * state_per_entry), int(9 * 440 * state_per_entry)
bases_per_run_bytes = groups_shape_high  # the conservative figure is used in every total below
base_obj_bytes = groups_shape_high // BASES_PER_RUN

# ---------------------------------------------------------------- the partition: a hash-parity half of the 973-unit run
half = [u for u in big_us if int(hashlib.sha256(u["pred"]["testId"].encode()).hexdigest(), 16) % 2 == 0]
half_rec = sum(len(u["record"]) for u in half)
half_today = sum(u["env_bytes"] + u["man_bytes"] for u in half)
# state object for the half
tuples = set()
for u in half:
    for e in u["man"].get("entries", []):
        tuples.add((e[0], e[1], bool(e[4]) if len(e) > 4 else False, e[2], e[3]))
items = []
for path, kind, ex, size, h in sorted(tuples):
    tail = bytes([KIND[kind] | (0x80 if ex else 0)]) + varint(size)
    if kind not in CONST_HASH_KINDS and h != ZERO:
        tail += bytes.fromhex(h)
    items.append((path, tail))
half_state = b"vo\x03\x01" + front_code(items)
half_ctx = sum(ctx_sizes[c] for c in {u["ctx"] for u in half})
pks = sorted({(e[0], e[1], bool(e[4]) if len(e) > 4 else False) for u in half for e in u["man"].get("entries", [])})
half_shape = b"vo\x02\x01" + front_code([(p, bytes([KIND[k] | (0x80 if ex else 0)])) for p, k, ex in pks])
half_rec_inline = sum(len(u["record_inline"]) for u in half)

# ---------------------------------------------------------------- the whole-sample at rest
records_total = sum(recB_b)
records_inline_total = sum(rec_b)
ctx_total = sum(ctx_sizes.values())
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
# per-entry stability between the two largest runs
ea = {(e[0], e[1]): (e[2], e[3]) for u in run_list[0][1] for e in u["man"].get("entries", [])}
eb = {(e[0], e[1]): (e[2], e[3]) for u in run_list[1][1] for e in u["man"].get("entries", [])}
common = set(ea) & set(eb)
same_state = sum(1 for k in common if ea[k] == eb[k])

# ---------------------------------------------------------------- scale to vex
UNITS_PER_PARTITION = 800
PARTITIONS_PER_JOB = 2
JOBS_PER_DAY = 164
PLANS_PER_JOB = 2
UNITS_LISTED = 2305
CANDIDATES_PER_UNIT = 1.9
VALUES_PER_PLAN = 1644
KEY_BYTES = 190
rec_mean = st.mean(recB_b)
rails_rec_mean = st.mean(len(u["record"]) for u in units if u["pred"]["adapter"] == "rails")
rails_rec_inline_mean = st.mean(len(u["record_inline"]) for u in units if u["pred"]["adapter"] == "rails")
scale = UNITS_PER_PARTITION / len(half)  # 800-unit partition from the measured 516-unit half
shape_per_run = int(len(half_shape) * scale + bases_per_run_bytes)
state_per_run = int(len(half_state) * scale + bases_state_high)
ctx_per_run = ctx_sizes[big_us[0]["ctx"]]
verdict_objects_per_run = ctx_per_run + shape_per_run
objects_per_run = verdict_objects_per_run + state_per_run
partition_write = UNITS_PER_PARTITION * rails_rec_mean + objects_per_run
partition_rows = UNITS_PER_PARTITION + 3
today_partition_write = UNITS_PER_PARTITION * (st.mean(today_env) + st.mean(today_man)) + BASES_PER_RUN * 50_000
plan_records = VALUES_PER_PLAN * rails_rec_mean
plan_listing = UNITS_LISTED * CANDIDATES_PER_UNIT * KEY_BYTES
plan_reads = {}
for runs_touched in (4, 10, 20, 50):
    plan_reads[runs_touched] = {
        "verdict_bytes": int(plan_listing + plan_records + runs_touched * verdict_objects_per_run),
        "with_state_for_explain": int(plan_listing + plan_records + runs_touched * objects_per_run),
    }
today_plan = plan_listing + VALUES_PER_PLAN * (st.mean(today_env) + st.mean(today_man))
runs_per_day = JOBS_PER_DAY * PARTITIONS_PER_JOB
day_written = runs_per_day * partition_write
today_day_written = runs_per_day * today_partition_write
day_objects = runs_per_day * objects_per_run

numbers = {
    "units": N,
    "runs": [{"commit": rk[0][:8], "issued": rk[1], "project": rk[2], "adapter": rk[3], "units": len(us),
              "ctx_count": ri["ctx_count"], "ctx_bytes": [ctx_sizes[c] for c in ri["ctx_ids"]],
              "ctx_zstd": [ctx_zstd[c] for c in ri["ctx_ids"]],
              "state_bytes": state_sizes[rk], "state_zstd": state_zstd[rk], "state_entries": state_entries[rk],
              "conflicts": conflicts[rk]}
             for (rk, us), ri in zip(run_list, run_info)],
    "today": {"envelope": stat(today_env), "manifest": stat(today_man), "per_unit": round(st.mean(today_env) + st.mean(today_man)),
              "total": today_total},
    "v2": {
        "statement": stat(stmt_b), "sig_frame": stat(sigf_b),
        "descriptor": stat(desc_b), "record": stat(recB_b),
        "record_by_adapter": {a: stat([len(u["record"]) for u in units if u["pred"]["adapter"] == a]) for a in by_adapter},
        "alt_inline_manifest_part": stat(manp_b), "alt_inline_record": stat(rec_b),
        "own_entries": stat(own_entries),
        "ctx": {"count": len(ctx_objects), "bytes": stat(list(ctx_sizes.values())), "zstd_sum": sum(v for v in ctx_zstd.values() if v)},
        "shape": {"bytes_sum": shape_total, "zstd_sum": sum(v for v in shape_zstd.values() if v),
                  "big_run": {"bytes": shape_sizes[big_rk], "entries": shape_entries[big_rk], "zstd": shape_zstd[big_rk],
                              "bytes_per_entry": round(fc_bytes_per_entry, 1)}},
        "state": {"bytes_sum": state_total, "zstd_sum": sum(v for v in state_zstd.values() if v),
                  "big_run": {"bytes": state_sizes[big_rk], "entries": state_entries[big_rk], "zstd": state_zstd[big_rk],
                              "bytes_per_entry": round(state_per_entry, 1)}},
        "groups_estimate": {"entries_per_group": BASE_ENTRIES, "groups_per_run": BASES_PER_RUN,
                            "index_bytes": groups_index_bytes, "shape_bytes_low_high": [groups_shape_low, groups_shape_high],
                            "state_bytes_low_high": [bases_state_low, bases_state_high], "used_in_totals": "high"},
        "at_rest_1175": {"records": records_total, "ctx": ctx_total, "shape": shape_total, "groups_est": bases_total_est,
                         "state": state_total,
                         "total_verdict_path": records_total + ctx_total + shape_total + bases_total_est,
                         "total_with_state": records_total + ctx_total + shape_total + bases_total_est + state_total,
                         "per_unit_with_state": round((records_total + ctx_total + shape_total + bases_total_est + state_total) / N),
                         "ratio_vs_today": round(today_total / (records_total + ctx_total + shape_total + bases_total_est + state_total), 1),
                         "alt_inline_records": records_inline_total},
    },
    "partition_516": {"units": len(half), "records": half_rec, "records_inline_alt": half_rec_inline, "ctx": half_ctx,
                      "shape": len(half_shape), "shape_zstd": zstd(half_shape), "groups_est": bases_per_run_bytes,
                      "state": len(half_state), "state_zstd": zstd(half_state),
                      "total": half_rec + half_ctx + len(half_shape) + bases_per_run_bytes + len(half_state),
                      "today": half_today + BASES_PER_RUN * 50_000, "rows": len(half) + 3},
    "vex_scale": {
        "assumptions": {"units_per_partition": UNITS_PER_PARTITION, "partitions_per_job": PARTITIONS_PER_JOB, "jobs_per_day": JOBS_PER_DAY,
                        "units_listed": UNITS_LISTED, "candidates_per_unit": CANDIDATES_PER_UNIT, "values_per_plan": VALUES_PER_PLAN,
                        "today_base_bytes": 50_000, "key_bytes": KEY_BYTES},
        "partition_write": {"today_bytes": int(today_partition_write), "today_rows": UNITS_PER_PARTITION * 2 + BASES_PER_RUN,
                            "v2_bytes": int(partition_write), "v2_rows": partition_rows,
                            "v2_records_bytes": int(UNITS_PER_PARTITION * rails_rec_mean),
                            "v2_ctx_bytes": ctx_per_run, "v2_shape_bytes": shape_per_run, "v2_state_bytes": state_per_run,
                            "v2_objects_bytes": int(objects_per_run), "v2_verdict_objects_bytes": int(verdict_objects_per_run),
                            "alt_inline_bytes": int(UNITS_PER_PARTITION * rails_rec_inline_mean + ctx_per_run + bases_per_run_bytes + state_per_run)},
        "plan_read": {"today_bytes": int(today_plan), "today_requests": "list 1 + prefetch 4 + manifests 1-2 + memo 2-3",
                      "v2": plan_reads, "v2_requests": "list 1 + read_values 1-2 + get_objects 1 (+1 for state objects when naming entries)"},
        "per_day": {"today_bytes": int(today_day_written), "v2_bytes": int(day_written), "v2_objects_bytes": int(day_objects),
                    "runs_per_day": runs_per_day, "log_rows_today": "~400k", "log_rows_v2": 0, "memo_rows_today": "~130k",
                    "memo_rows_v2": JOBS_PER_DAY * PLANS_PER_JOB},
    },
    "stability": {"units_at_more_than_one_commit": len(multi), "same_path_kind_set": same_set, "same_root": same_root,
                  "entries_common_to_two_largest_runs": len(common), "same_size_and_hash": same_state},
}
json.dump(numbers, open(os.path.join(out, "numbers.json"), "w"), indent=1)

print(f"units {N}; today {numbers['today']['per_unit']} B/unit ({today_total/1e6:.2f} MB)")
print(f"v2 statement {numbers['v2']['statement']['mean']} B mean (p50 {numbers['v2']['statement']['p50']}, max {numbers['v2']['statement']['max']})")
print(f"v2 sig frame {numbers['v2']['sig_frame']['mean']} B; descriptor {numbers['v2']['descriptor']['mean']} B mean (p50 {numbers['v2']['descriptor']['p50']}, max {numbers['v2']['descriptor']['max']})")
print(f"v2 record {numbers['v2']['record']['mean']} B mean (p50 {numbers['v2']['record']['p50']}, p90 {numbers['v2']['record']['p90']}, max {numbers['v2']['record']['max']})")
print(f"   alt inline-set record {numbers['v2']['alt_inline_record']['mean']} B mean (manifest part {numbers['v2']['alt_inline_manifest_part']['mean']}, p50 {numbers['v2']['alt_inline_manifest_part']['p50']})")
for a, s in numbers["v2"]["record_by_adapter"].items():
    print(f"  {a}: {s['mean']} B mean, max {s['max']}, n {s['n']}")
print(f"ctx objects {len(ctx_objects)}: {numbers['v2']['ctx']['bytes']}")
for (rk, us), r in zip(run_list, numbers["runs"]):
    print(f"run {r['commit']} {r['project']:10} {r['adapter']:9} units {r['units']:4} ctx {r['ctx_count']} {r['ctx_bytes']} (zstd {r['ctx_zstd']}) shape {shape_sizes[rk]} B / {shape_entries[rk]} (zstd {shape_zstd[rk]}) state {r['state_bytes']} B (zstd {r['state_zstd']}) conflicts {r['conflicts']}")
print(f"groups estimate: {numbers['v2']['groups_estimate']}")
print(f"at rest 1175: {numbers['v2']['at_rest_1175']}")
print(f"partition 516: {numbers['partition_516']}")
print(f"vex partition write: today {today_partition_write/1e6:.1f} MB -> v2 {partition_write/1e6:.2f} MB ({partition_rows} rows): {numbers['vex_scale']['partition_write']}")
print(f"vex plan: today {today_plan/1e6:.1f} MB -> v2 {json.dumps(plan_reads)}")
print(f"vex per day: today {today_day_written/1e9:.1f} GB -> v2 {day_written/1e6:.0f} MB (objects {day_objects/1e6:.0f} MB)")
print(f"stability: {numbers['stability']}")
