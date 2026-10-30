import json, base64, sys, os
S=os.environ['MEAS_ROOT']  # the directory holding wr/pairs.json and meas-v2/
M=S+'/meas-v2'
ns3, ns1, write, out = sys.argv[1], sys.argv[2], sys.argv[3].split(','), sys.argv[4]
d=json.load(open(S+'/wr/pairs.json'))['pairs']
gems=None
for e,m,r in d:
    p=json.loads(base64.b64decode(json.loads(e)['payload']))['predicate']
    if p['adapter']=='rails': gems=p['toolchain']['rubyGems']; break
gems=sorted(set(gems)|{'aws-sdk-sns==1.121.0','aws-sdk-sqs==1.122.0'})
cfg=sorted(l.strip() for l in open(M+"/plan/rustc-cfg.txt") if l.strip())
extra=json.load(open(M+'/plan/overrides-extra.json')) if len(sys.argv)>5 else {}
rust_tc={"rust":"1.99.1 58cf8f9c35b355199727627d07ae34a4e2846d67 LLVM 23.1.3","rustHost":"aarch64-apple-darwin","rustCfg":cfg}
ov={"vex-api":{"toolchain":{"rubyGems":gems}}, "rust":{"toolchain":dict(rust_tc)}, "vex-roder":{"toolchain":dict(rust_tc)}}
for k,v in extra.items():
    ov.setdefault(k,{}).setdefault("toolchain",{}).update(v.get("toolchain",{}))
    for kk in ("envConfigDigest",):
        if kk in v: ov[k][kk]=v[kk]
c={"pairs": S+"/wr/pairs.json", "proddb": M+"/proddb/data", "proddb_prefix": "vci_b7e6b2d04b31bb5b_", "checkout": M+"/vex-at-5eb7312", "key": M+"/key/vci-meas", "url": "http://127.0.0.1:18181", "ns3": ns3, "ns1": ns1, "commit": "47bb7b8f318f9bffe2c95b367e65a40be7ca187c", "tree": "4250525740c7b5abfdca5d2e567641dbad8f56a1", "overrides": ov, "write": write, "out": out}
json.dump(c, open(M+'/plan/config.json','w'), indent=1)
print("config written:", M+'/plan/config.json', "gems", len(gems), "cfg", len(cfg))
