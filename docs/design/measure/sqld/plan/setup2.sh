#!/bin/bash
# Everything RESULTS-2.md's runs need, rebuilt from the inputs, under one directory WORK.
#
#   setup2.sh up WORK PORT   build it: the production manifests copy, a fresh throwaway key (0600),
#                            the vex checkout with the key trusted, a local sqld on 127.0.0.1:PORT,
#                            config.json for the harness (mkconfig.py, with that commit and tree),
#                            the harness's records in meas3c (format 3) and meas1c (format 1), and
#                            one warm-up plan per namespace so that the natives flags are set (the
#                            `api` and `all` variants of measure2.sh assume them; measure2.sh
#                            checks and warms up again when one is missing)
#   setup2.sh down WORK      stop that sqld, remove the checkout, the key, the copies
#
# Reads MEAS_ROOT (wr/pairs.json, the sample; wr/sqld/data.sqld/dbs/default/data and data-wal, the
# local copy of the production manifests table; meas-v2/plan/PATH.txt unless MEAS_PATH_FILE names
# another), VEX_GIT (a vex clone holding VEX_COMMIT, default 5eb73122, origin/master of 28 Oct;
# only a worktree is added to it), VCI_SRC (this repository's checkout, where the harness runs as a
# test file for the time of the run; default the checkout holding this script), CARGO_TARGET_DIR,
# VCI_WARMUP (the vci binary of the warm-up plans; default meas-v2/vci-after).
# Never point it at a shared or hosted server: the store URL carries a placeholder token, so vex's
# [store] token_command never runs, and a `com` that exits 1 is first on PATH.
set -euo pipefail
S=${MEAS_ROOT:?MEAS_ROOT: the directory holding wr/pairs.json and meas-v2/}
M=$S/meas-v2
HERE=$(cd "$(dirname "$0")" && pwd)
cmd=${1:?usage: setup2.sh up WORK PORT | down WORK}
W=${2:?WORK}
co=$W/vex-at-5eb7312

prefix() { printf 'vci_%s_' "$(printf %s "$1" | b3sum --no-names | cut -c1-16)"; } # remote.rs table_prefix
q() { curl -s -m 20 "http://127.0.0.1:$PORT/v2/pipeline" -H 'Content-Type: application/json' \
  -d "{\"requests\":[{\"type\":\"execute\",\"stmt\":{\"sql\":\"$1\"}},{\"type\":\"close\"}]}"; }
has_flag() { # namespace, flag name
  q "SELECT count(*) FROM $(prefix "$1")flags WHERE name = '$2'" \
    | python3 -I -c "import json,sys; r=json.load(sys.stdin)['results'][0]; print(r['response']['result']['rows'][0][0]['value'] if r['type']=='ok' else 0)"
}

case $cmd in
down)
  if [ -f "$W/sqld/pid" ]; then
    pid=$(cat "$W/sqld/pid")
    if ps -p "$pid" -o comm= | grep -q sqld; then kill "$pid"; fi
    rm -f "$W/sqld/pid"
  fi
  if [ -d "$co" ]; then git -C "${VEX_GIT:?VEX_GIT}" worktree remove --force "$co"; fi
  rm -f "$W/key/vci-meas" "$W/key/vci-meas.pub"
  rm -rf "$W/proddb" "$W/sqld/data.sqld"
  echo "down: $W (logs, config.json and harness-out.json kept)"
  exit 0;;
up) ;;
*) echo "usage: setup2.sh up WORK PORT | down WORK" >&2; exit 2;;
esac

PORT=${3:?PORT}
VEX_GIT=${VEX_GIT:?VEX_GIT: a vex clone}
VEX_COMMIT=${VEX_COMMIT:-5eb73122037c6d01da60551f3df9f716af599d1c}
VCI_SRC=${VCI_SRC:-$(git -C "$HERE" rev-parse --show-toplevel)}
VCI_WARMUP=${VCI_WARMUP:-$M/vci-after}
if [ -e "$W" ] && [ -n "$(ls -A "$W")" ]; then echo "$W is not empty: setup2.sh down it, or name another" >&2; exit 2; fi
if curl -s -m 2 -o /dev/null "http://127.0.0.1:$PORT/health"; then echo "something answers on $PORT already" >&2; exit 2; fi
mkdir -p "$W"/{proddb,key,sqld,comshim}

# The production manifests table (the bases of the sample's units), as 28 Oct's runs read it.
src=$S/wr/sqld/data.sqld/dbs/default
cp "$src/data" "$W/proddb/data"
if [ -f "$src/data-wal" ]; then cp "$src/data-wal" "$W/proddb/data-wal"; fi

# A fresh throwaway key, 0600, trusted by one commit on top of vex's master.
(umask 077 && ssh-keygen -q -t ed25519 -N '' -C vci-meas-v2 -f "$W/key/vci-meas")
GIT_NO_LAZY_FETCH=1 git -C "$VEX_GIT" worktree add -q --detach "$co" "$VEX_COMMIT"
echo "vci-meas-v2 namespaces=\"vci-attest\" $(cut -d' ' -f1,2 "$W/key/vci-meas.pub")" >> "$co/.vci/allowed_signers"
git -C "$co" -c user.name=vci-meas -c user.email=vci-meas@localhost -c commit.gpgsign=false \
  commit -q -am "vci-meas-v2: trust the throwaway measurement key"
commit=$(git -C "$co" rev-parse HEAD)
tree=$(git -C "$co" rev-parse 'HEAD^{tree}')

# This machine's toolchain, as the harness rewrites the statements to it.
cp "${MEAS_PATH_FILE:-$M/plan/PATH.txt}" "$W/PATH.txt"
rustc --print cfg > "$W/rustc-cfg.txt"
case "$(rustc -vV)" in *"LLVM version: 23.1.3"*) ;; *) echo "warning: mkconfig.py's rust override names rustc 1.99.1 / LLVM 23.1.3; this rustc differs" >&2;; esac
printf '#!/bin/sh\necho "com shim called: $1 $2 $3 ..." >> %s/comshim/log\nexit 1\n' "$W" > "$W/comshim/com"
chmod +x "$W/comshim/com"

# A local sqld of its own.
nohup /opt/homebrew/bin/sqld --db-path "$W/sqld/data.sqld" --http-listen-addr "127.0.0.1:$PORT" --no-welcome \
  > "$W/sqld/sqld.log" 2>&1 &
echo $! > "$W/sqld/pid"
echo "$PORT" > "$W/port"
for i in $(seq 1 50); do curl -s -m 1 -o /dev/null "http://127.0.0.1:$PORT/health" && break; sleep 0.2; done

# The harness's records.
python3 -I "$HERE/mkconfig.py" meas3c meas1c 3,1 "$W/harness-out.json" --commit "$commit" --tree "$tree" \
  --checkout "$co" --key "$W/key/vci-meas" --proddb "$W/proddb/data" --url "http://127.0.0.1:$PORT" \
  --rustc-cfg "$W/rustc-cfg.txt" --config "$W/config.json"
harness=$VCI_SRC/crates/vci-cli/tests/meas_plan_v2.rs
if [ -e "$harness" ]; then echo "$harness exists already" >&2; exit 2; fi
cp "$HERE/meas_plan_v2.rs" "$harness"
trap 'rm -f "$harness"' EXIT
(cd "$VCI_SRC" && env -u RUSTC_WRAPPER -u VCI_STORE_TOKEN VCI_MEAS_CONFIG="$W/config.json" \
  cargo test --release -p vci-cli --test meas_plan_v2 -- --nocapture) > "$W/harness.log" 2>&1
rm -f "$harness"
trap - EXIT

# One warm-up plan per namespace: sets plan:natives:vex-api (the steady state measure2.sh's `api`
# and `all` variants measure).
export PATH=$W/comshim:$(cat "$W/PATH.txt")
for ns in meas3c meas1c; do
  (cd "$co" && env -u VCI_STORE_TOKEN -u RUBYLIB -u RUBYOPT VCI_STORE=libsql \
    "VCI_STORE_URL=http://127.0.0.1:$PORT?authToken=placeholder-not-a-credential" VCI_STORE_NAMESPACE=$ns \
    "$VCI_WARMUP" plan --base-ref HEAD --format json --project vex-api --project vex-web --project rust \
    --project vex-roder > "$W/warmup-$ns.json" 2> "$W/warmup-$ns.err") || true
  echo "$ns: plan:natives:vex-api set: $(has_flag $ns plan:natives:vex-api)"
done
echo "up: $W, sqld pid $(cat "$W/sqld/pid") on 127.0.0.1:$PORT, checkout $commit tree $tree"
grep -E '^meas: (reconstruction|format|done)' "$W/harness.log" || true
