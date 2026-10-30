#!/usr/bin/env python3 -I
"""Real-git measurement of git-meta pack growth and object counts, today's format against format 3 with the
TEXT record frame (vci3 LF statement LF base64(sig) LF base64(descriptor)), base64 objects, hdr/tables ctx split.
Adapted from design/review-perf-ops/gitmeta.py (binary frame, one ctx).

Builds two repositories in <out>/today and <out>/v2 with git-meta's tree layout
(`path/<unit>/__target__/vci/attestation/<tk>/<signer>/<sk>/<issued>.<tree16>/__value`, manifests and objects
under `project/...`), commit A = the 973-unit Rails run, commit B = the 185-unit run (replacing records of
the same units), then measures the thin pack a push of B sends, object counts by type, and the repacked size.

usage: python3 -I gitmeta.py <pairs.json> <out dir>
"""
import base64, collections, hashlib, json, os, random, shutil, subprocess, sys

pairs = json.load(open(sys.argv[1]))["pairs"]
out = sys.argv[2]
random.seed(2)

def varint(n):
    o = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: o.append(b | 0x80)
        else: o.append(b); return bytes(o)

def front_code(items):
    o = bytearray(varint(len(items))); prev = b""
    for path, tail in items:
        p = path.encode(); n = 0; m = min(len(p), len(prev))
        while n < m and p[n] == prev[n]: n += 1
        o += varint(n) + varint(len(p) - n) + p[n:] + tail; prev = p
    return bytes(o)

KIND = {"f": 0, "l": 1, "a": 2, "d": 3, "t": 4, "x": 5, "m": 6, "u": 7}
CONST = {"a", "x", "u"}; ZERO = "0" * 64
SIGNER = "24c1b04a0f760c13"

units = []
for env_s, man_s, root in pairs:
    env = json.loads(env_s); payload = base64.b64decode(env["payload"]); stmt = json.loads(payload)
    units.append({"env_s": env_s, "man_s": man_s, "root": root, "stmt": stmt, "pred": stmt["predicate"], "man": json.loads(man_s), "sig": env["signatures"][0]})
runs = collections.defaultdict(list)
for u in units:
    p = u["pred"]; runs[(p["commit"], p["issuedAt"], p.get("projectName", ""), p["adapter"])].append(u)
run_list = sorted(runs.items(), key=lambda kv: -len(kv[1]))
run_a, run_b = run_list[0][1], run_list[1][1]
print("run A", len(run_a), "units; run B", len(run_b), "units; units of B also in A:", len({u["pred"]["testId"] for u in run_b} & {u["pred"]["testId"] for u in run_a}))

def tk(test_id): return hashlib.blake2b(test_id.encode(), digest_size=32).hexdigest()
def sk(u): return hashlib.blake2b((u["root"] + u["pred"]["toolVersion"]).encode(), digest_size=32).hexdigest()
def hint(u):
    import datetime
    t = datetime.datetime.fromisoformat(u["pred"]["issuedAt"].replace("Z", "+00:00")); return f"{int(t.timestamp()):x}.{u['pred']['tree'][:16]}"
def record_path(u):
    return f"path/{u['pred']['testId']}/__target__/vci/attestation/{tk(u['pred']['testId'])}/{SIGNER}/{sk(u)}/{hint(u)}/__value"

# ---- format 3 encoders (as measure.py)
def entries_root(entries):
    h = hashlib.blake2b(digest_size=32)
    for e in sorted(entries, key=lambda e: (e[0], e[1])): h.update(json.dumps(e, separators=(",", ":")).encode())
    return h.hexdigest()

def build_v2(us):
    """-> (ctx bytes, shape bytes, state bytes, {unit: frame bytes})"""
    p = us[0]["pred"]
    waiver = sorted({w for u in us for w in u["pred"].get("waived", [])})
    env_names = sorted({k for u in us for k, _ in u["man"].get("env", [])})
    ext = sorted({(n, v) for u in us for n, v in u["man"].get("externals", [])})
    tc = dict(p["toolchain"]); lists = {k: tc.pop(k) for k in ("rubyGems", "pythonDists", "goEnv", "rustCfg") if k in tc}
    ctx = bytearray(b"vo\x01\x01")
    ctx += json.dumps({k: p.get(k) for k in ("repoId", "adapter", "projectName", "projectDir", "runnerProject", "toolVersion", "railsInputs", "envConfigDigest", "globalInputRoot", "ignoredInputs", "envSet")}, sort_keys=True, separators=(",", ":")).encode()
    gm = sorted(p["globalManifest"]["entries"], key=lambda e: (e["path"], e["kind"]))
    ctx += front_code([(e["path"], bytes([0]) + varint(e["size"]) + (bytes.fromhex(e["hash"]) if e.get("hash") and e["kind"] == "file" else b"")) for e in gm])
    ctx += json.dumps(tc, sort_keys=True, separators=(",", ":")).encode()
    for k, v in sorted(lists.items()): ctx += front_code([(str(x), b"") for x in sorted(str(x) for x in v)])
    tables = b"vo\x02\x01" + b"".join(varint(len(w)) + w.encode() for w in waiver) + front_code([(n, b"") for n in env_names]) + front_code([(n, varint(len(v)) + v.encode()) for n, v in ext])
    tid = hashlib.blake2b(tables, digest_size=32).hexdigest()
    cid = hashlib.blake2b(bytes(ctx), digest_size=32).hexdigest()
    pks = sorted({(e[0], e[1], bool(e[4]) if len(e) > 4 else False) for u in us for e in u["man"].get("entries", [])})
    index = {(pp, k): i for i, (pp, k, _) in enumerate(pks)}
    shape = b"vo\x02\x01" + front_code([(pp, bytes([KIND[k] | (0x80 if ex else 0)])) for pp, k, ex in pks])
    sid = hashlib.blake2b(shape, digest_size=32).hexdigest()
    tuples = sorted({(e[0], e[1], bool(e[4]) if len(e) > 4 else False, e[2], e[3]) for u in us for e in u["man"].get("entries", [])})
    items = []
    for path, kind, ex, size, h in tuples:
        tail = bytes([KIND[kind] | (0x80 if ex else 0)]) + varint(size)
        if kind not in CONST and h != ZERO: tail += bytes.fromhex(h)
        items.append((path, tail))
    state = b"vo\x03\x01" + front_code(items)
    nidx = {n: i for i, n in enumerate(env_names)}
    frames = {}
    for u in us:
        pr = u["pred"]
        pred = {"argv": pr["argv"], "commit": pr["commit"], "hdr": cid, "tables": tid, "entriesRoot": entries_root(u["man"].get("entries", [])), "expiresAt": pr["expiresAt"], "issuedAt": pr["issuedAt"], "result": pr["result"], "testId": pr["testId"], "tree": pr.get("tree", ""), "treeDirty": pr.get("treeDirty", False), "waived": sorted({waiver.index(w) for w in pr.get("waived", [])})}
        for k in ("tainted", "declaredInputs", "platformSpecific", "archSpecific", "cfgPredicates"):
            if pr.get(k): pred[k] = pr[k]
        s = json.dumps({"_type": "https://in-toto.io/Statement/v1", "predicate": pred, "predicateType": "https://vci.dev/test-attestation/v2", "subject": u["stmt"]["subject"]}, sort_keys=True, separators=(",", ":")).encode()
        keyid = u["sig"]["keyid"].encode()
        sigf = bytes([1]) + varint(len(keyid)) + keyid + varint(180) + random.randbytes(180)  # a real signature is incompressible
        d = bytearray(bytes.fromhex(sid)) + (b"\x01" if u["man"].get("base") else b"\xff")
        ids = sorted(index[(e[0], e[1])] for e in u["man"].get("entries", [])); d += varint(len(ids)); prev = -1
        for i in ids: d += varint(i - prev - 1); prev = i
        setv = [(nidx[k], v) for k, v in u["man"].get("env", []) if v is not None]
        d += varint(len(setv)) + b"".join(varint(i) + bytes.fromhex(v) for i, v in setv)
        d += varint(len(env_names)) + b"\0" * ((len(env_names) + 7) // 8) + varint(len(ext)) + b"\0" * ((len(ext) + 7) // 8) + varint(0)
        frames[u["pred"]["testId"]] = b"vci3\n" + s + b"\n" + base64.b64encode(sigf) + b"\n" + base64.b64encode(bytes(d))
    return bytes(ctx), cid, tables, tid, shape, sid, state, hashlib.blake2b(state, digest_size=32).hexdigest(), frames

def git(repo, *args, inp=None):
    r = subprocess.run(["git", "-C", repo, *args], input=inp, capture_output=True)
    if r.returncode != 0: raise SystemExit(f"git {args}: {r.stderr.decode()[:400]}")
    return r.stdout

def write(repo, rel, data):
    p = os.path.join(repo, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f: f.write(data)

def bases_for(us, n=9, size=440):
    tuples = sorted({(e[0], e[1], e[2], e[3]) for u in us for e in u["man"].get("entries", [])})
    out = []
    for i in range(n):
        ents = random.sample(tuples, min(size, len(tuples)))
        out.append(json.dumps({"v": 1, "entries": sorted(ents)}, separators=(",", ":")).encode())
    return out

def populate_today(repo, us, prev_paths):
    for pth in prev_paths:
        if os.path.exists(os.path.join(repo, pth)): os.remove(os.path.join(repo, pth))
    paths = {}
    for u in us:
        pth = record_path(u); write(repo, pth, u["env_s"].encode()); paths[u["pred"]["testId"]] = pth
        write(repo, f"project/vci/manifest/{u['root']}/__value", u["man_s"].encode())
    for b in bases_for(us): write(repo, f"project/vci/manifest/{hashlib.blake2b(b, digest_size=32).hexdigest()}/__value", b)
    return paths

def populate_v2(repo, us, prev_paths):
    for pth in prev_paths:
        if os.path.exists(os.path.join(repo, pth)): os.remove(os.path.join(repo, pth))
    ctx, cid, tables, tid, shape, sid, state, stid, frames = build_v2(us)
    b64 = base64.b64encode
    write(repo, f"project/vci/object/1/{cid}/__value", b64(ctx)); write(repo, f"project/vci/object/2/{tid}/__value", b64(tables)); write(repo, f"project/vci/object/3/{sid}/__value", b64(shape)); write(repo, f"project/vci/object/4/{stid}/__value", b64(state))
    paths = {}
    for u in us:
        pth = record_path(u); write(repo, pth, frames[u["pred"]["testId"]]); paths[u["pred"]["testId"]] = pth
    return paths

def types(repo, rev_range):
    oids = git(repo, "rev-list", "--objects", *rev_range).decode().split("\n")
    oids = [l.split(" ")[0] for l in oids if l]
    info = git(repo, "cat-file", "--batch-check=%(objecttype) %(objectsize)", inp="\n".join(oids).encode()).decode().split("\n")
    c = collections.Counter(); b = collections.Counter()
    for l in info:
        if not l: continue
        t, s = l.split(); c[t] += 1; b[t] += int(s)
    return c, b

def measure(name, pop):
    repo = os.path.join(out, name); shutil.rmtree(repo, ignore_errors=True); os.makedirs(repo)
    git(repo, "init", "-q"); git(repo, "config", "user.email", "r@x"); git(repo, "config", "user.name", "r"); git(repo, "config", "gc.auto", "0")
    paths = pop(repo, run_a, {})
    git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "A"); a = git(repo, "rev-parse", "HEAD").decode().strip()
    old = [paths[t] for t in paths if t in {u["pred"]["testId"] for u in run_b}]
    pop(repo, run_b, old)
    git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "B"); b = git(repo, "rev-parse", "HEAD").decode().strip()
    thin_b = git(repo, "pack-objects", "--revs", "--thin", "--stdout", "-q", inp=f"^{a}\n{b}\n".encode())
    full_a = git(repo, "pack-objects", "--revs", "--stdout", "-q", inp=f"{a}\n".encode())
    ca, ba = types(repo, [a]); cb, bb = types(repo, [f"{a}..{b}"])
    git(repo, "repack", "-adfq"); size = sum(os.path.getsize(os.path.join(repo, ".git/objects/pack", f)) for f in os.listdir(os.path.join(repo, ".git/objects/pack")) if f.endswith(".pack"))
    print(f"\n{name}:")
    print(f"  commit A ({len(run_a)} units): {dict(ca)} objects, raw {dict(ba)}; pack of A alone {len(full_a)/1e6:.2f} MB")
    print(f"  push of B ({len(run_b)} units): new objects {dict(cb)}, raw bytes {dict(bb)}; thin pack sent {len(thin_b)/1e6:.3f} MB  ({len(thin_b)/len(run_b)/1e3:.2f} KB per unit)")
    print(f"  repacked repository (A+B): {size/1e6:.2f} MB")
    return {"A": dict(ca), "A_raw": dict(ba), "B_new": dict(cb), "B_raw": dict(bb), "thin_B": len(thin_b), "pack_A": len(full_a), "repacked": size}

res = {"today": measure("today", populate_today), "v2": measure("v2", populate_v2)}
json.dump(res, open(os.path.join(out, "gitmeta.json"), "w"), indent=1)
