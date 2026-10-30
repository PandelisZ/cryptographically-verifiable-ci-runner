# The 973 units of the largest run of pairs.json (one commit, vex-api, rails), in file
# order, as a pairs file of their own, so that fx3's replay-head (which takes pairs[i % n])
# and replay3 (which takes the largest run) write the same units at the same offsets.
# usage: python3 -I mkpairs.py IN OUT
import base64, collections, json, sys

d = json.load(open(sys.argv[1]))["pairs"]
runs = collections.OrderedDict()
for i, (e, m, r) in enumerate(d):
    p = json.loads(base64.b64decode(json.loads(e)["payload"]))["predicate"]
    runs.setdefault((p["commit"], p["issuedAt"], p.get("projectName"), p["adapter"]), []).append(i)
k = max(runs, key=lambda k: len(runs[k]))
sel = [d[i] for i in runs[k]]
json.dump({"pairs": sel}, open(sys.argv[2], "w"))
env = sum(len(p[0]) for p in sel)
man = sum(len(p[1]) for p in sel)
print(json.dumps({"run": list(k), "units": len(sel), "envelope_bytes": env, "manifest_bytes": man,
                  "first800_envelope_bytes": sum(len(p[0]) for p in sel[:800]),
                  "first800_manifest_bytes": sum(len(p[1]) for p in sel[:800])}))
