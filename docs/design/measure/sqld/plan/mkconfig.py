"""The harness's configuration (meas_plan_v2.rs, VCI_MEAS_CONFIG).

python3 -I mkconfig.py NS3 NS1 WRITE OUT [extra] [--commit C --tree T --checkout DIR --key FILE
                       --proddb FILE --url URL --rustc-cfg FILE --config FILE]

NS3/NS1: the format-3 and format-1 namespaces; WRITE: which to write ("3,1"); OUT: the harness's
summary. Without the options it writes what 28 October's run used (config.json: commit 47bb7b8f,
tree 42505257, under $MEAS_ROOT/meas-v2); setup2.sh passes every option for a rebuilt checkout.
`extra` (any fifth argument) merges plan/overrides-extra.json into the overrides."""
import argparse, base64, json, os

S = os.environ['MEAS_ROOT']  # the directory holding wr/pairs.json and meas-v2/
M = S + '/meas-v2'
ap = argparse.ArgumentParser()
ap.add_argument('ns3'); ap.add_argument('ns1'); ap.add_argument('write'); ap.add_argument('out')
ap.add_argument('extra', nargs='?')
ap.add_argument('--commit', default='47bb7b8f318f9bffe2c95b367e65a40be7ca187c')
ap.add_argument('--tree', default='4250525740c7b5abfdca5d2e567641dbad8f56a1')
ap.add_argument('--checkout', default=M + '/vex-at-5eb7312')
ap.add_argument('--key', default=M + '/key/vci-meas')
ap.add_argument('--proddb', default=M + '/proddb/data')
ap.add_argument('--url', default='http://127.0.0.1:18181')
ap.add_argument('--rustc-cfg', default=M + '/plan/rustc-cfg.txt')
ap.add_argument('--config', default=M + '/plan/config.json')
a = ap.parse_args()
d = json.load(open(S + '/wr/pairs.json'))['pairs']
gems = None
for e, m, r in d:
    p = json.loads(base64.b64decode(json.loads(e)['payload']))['predicate']
    if p['adapter'] == 'rails':
        gems = p['toolchain']['rubyGems']
        break
gems = sorted(set(gems) | {'aws-sdk-sns==1.121.0', 'aws-sdk-sqs==1.122.0'})
cfg = sorted(l.strip() for l in open(a.rustc_cfg) if l.strip())
extra = json.load(open(M + '/plan/overrides-extra.json')) if a.extra else {}
rust_tc = {"rust": "1.99.1 58cf8f9c35b355199727627d07ae34a4e2846d67 LLVM 23.1.3", "rustHost": "aarch64-apple-darwin", "rustCfg": cfg}
ov = {"vex-api": {"toolchain": {"rubyGems": gems}}, "rust": {"toolchain": dict(rust_tc)}, "vex-roder": {"toolchain": dict(rust_tc)}}
for k, v in extra.items():
    ov.setdefault(k, {}).setdefault("toolchain", {}).update(v.get("toolchain", {}))
    for kk in ("envConfigDigest",):
        if kk in v:
            ov[k][kk] = v[kk]
c = {"pairs": S + "/wr/pairs.json", "proddb": a.proddb, "proddb_prefix": "vci_b7e6b2d04b31bb5b_", "checkout": a.checkout,
     "key": a.key, "url": a.url, "ns3": a.ns3, "ns1": a.ns1, "commit": a.commit, "tree": a.tree, "overrides": ov,
     "write": a.write.split(','), "out": a.out}
json.dump(c, open(a.config, 'w'), indent=1)
print("config written:", a.config, "gems", len(gems), "cfg", len(cfg))
