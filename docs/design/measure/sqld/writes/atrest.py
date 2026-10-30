# Rows and bytes at rest of a namespace on the local sqld (Hrana v2 pipeline, no token),
# or a backdate of its objects' put_at past the orphan grace.
# usage: python3 -I atrest.py URL NS [backdate SECONDS]
import json, sys, urllib.request


def run(url, stmts):
    reqs = [{"type": "execute", "stmt": {"sql": s}} for s in stmts] + [{"type": "close"}]
    req = urllib.request.Request(url + "/v2/pipeline", data=json.dumps({"requests": reqs}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        res = json.load(urllib.request.urlopen(req, timeout=60))["results"]
    except Exception as e:  # a stalled sqld answers a write never: say so and leave
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        sys.exit(2)
    out = []
    for r in res[:-1]:
        if r["type"] != "ok":
            raise SystemExit(json.dumps(r))
        out.append([[c.get("value") for c in row] for row in r["response"]["result"]["rows"]])
    return out


url, ns = sys.argv[1], sys.argv[2]
(rows,) = run(url, [f"SELECT prefix FROM vci_schema WHERE ns = '{ns}'"])
if not rows:
    print(json.dumps({"ns": ns, "tables": {}}))
    sys.exit()
p = rows[0][0]
if len(sys.argv) > 3 and sys.argv[3] == "backdate":
    secs = int(sys.argv[4])
    # Objects and manifests both keep an hour of grace before an orphan pass may take them.
    (n,), (m,) = run(url, [f"UPDATE {p}objects SET put_at = put_at - {secs}",
                           f"UPDATE {p}manifests SET put_at = put_at - {secs}"]) and \
        run(url, [f"SELECT count(*) FROM {p}objects", f"SELECT count(*) FROM {p}manifests"])
    print(json.dumps({"ns": ns, "backdated_objects": int(n[0]), "backdated_manifests": int(m[0]), "by_secs": secs}))
    sys.exit()
(tables,) = run(url, [f"SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '{p}%'"])
res = {}
total_rows = total_bytes = 0
for (t,) in tables:
    (cols,) = run(url, [f"SELECT name FROM pragma_table_info('{t}')"])
    names = [c[0] for c in cols]
    expr = " + ".join(f"coalesce(length({c}), 0)" for c in names)
    (r,) = run(url, [f"SELECT count(*), coalesce(sum({expr}), 0) FROM {t}"])
    n, b = int(r[0][0]), int(r[0][1])
    short = t[len(p):]
    res[short] = {"rows": n, "bytes": b}
    if short == "objects":
        (k,) = run(url, [f"SELECT kind, count(*), sum(length(bytes)) FROM {t} GROUP BY kind"])
        res[short]["by_kind"] = {str(x[0]): {"rows": int(x[1]), "bytes": int(x[2])} for x in k}
    if short == "attestations":
        (k,) = run(url, [f"SELECT coalesce(format, 1), count(*) FROM {t} GROUP BY 1"]) if "format" in names else [[]]
        res[short]["by_format"] = {str(x[0]): int(x[1]) for x in k}
    total_rows += n
    total_bytes += b
print(json.dumps({"ns": ns, "prefix": p, "tables": res, "rows": total_rows, "bytes": total_bytes}))
