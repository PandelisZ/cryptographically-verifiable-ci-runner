#!/bin/bash
# Plan-side measurement at vex scale, on the local sqld (127.0.0.1:18181).
# usage: measure.sh RUNS [START]  -> runs/<config>-<variant>-<n>.{json,err,time}, n from START (default 1)
# Configs: v2-f3 (store-v2 release binary on the format-3 namespace meas3c),
#          v2-f1 (store-v2 on the format-1 namespace meas1c),
#          281-f1 (vci 2.8.1 on meas1c), 281-f3 (vci 2.8.1 on meas3c: fail-open).
# Variants: api (--project vex-api, what a Rails job's `vci ci` plans),
#           all (vex-api, vex-web, rust, vex-roder: every project the sample covers).
# Before every run the memo tables of every namespace are emptied, so each
# run is a "plan 1" (no memo of a previous plan on this tree), as the
# production figure (prodlogs/rails.json plan 1) is.
set -u
S=${MEAS_ROOT:?MEAS_ROOT: the directory holding wr/pairs.json, the target dir and meas-v2/}
M=$S/meas-v2
RUNS=${1:-3}
START=${2:-1}
V2=$S/target-v2/release/vci
V281=/opt/homebrew/bin/vci
export PATH=$(cat $M/plan/PATH.txt)
OUT=$M/plan/runs
mkdir -p $OUT
clear_memos() {
  tables=$(curl -s -m 20 http://127.0.0.1:18181/v2/pipeline -H 'Content-Type: application/json' \
    -d '{"requests":[{"type":"execute","stmt":{"sql":"SELECT name FROM sqlite_master WHERE name LIKE '"'"'%_memo'"'"'"}},{"type":"close"}]}' \
    | python3 -I -c "import json,sys; r=json.load(sys.stdin); print(' '.join(row[0]['value'] for x in r['results'] if x['type']=='ok' and x['response']['type']=='execute' for row in x['response']['result']['rows']))")
  for t in $tables; do
    curl -s -m 20 -o /dev/null http://127.0.0.1:18181/v2/pipeline -H 'Content-Type: application/json' \
      -d "{\"requests\":[{\"type\":\"execute\",\"stmt\":{\"sql\":\"DELETE FROM $t\"}},{\"type\":\"close\"}]}"
  done
}
run_one() {
  local cfg=$1 variant=$2 n=$3 bin ns projects
  case $cfg in
    v2-f3) bin=$V2; ns=meas3c;;
    v2-f1) bin=$V2; ns=meas1c;;
    281-f1) bin=$V281; ns=meas1c;;
    281-f3) bin=$V281; ns=meas3c;;
  esac
  case $variant in
    api) projects="--project vex-api";;
    all) projects="--project vex-api --project vex-web --project rust --project vex-roder";;
  esac
  clear_memos
  sync; sleep 1
  local tag=$OUT/$cfg-$variant-$n
  cd $M/vex-at-5eb7312
  start=$(python3 -c 'import time;print(time.time())')
  env -u VCI_STORE_TOKEN -u RUBYLIB -u RUBYOPT VCI_STORE=libsql VCI_STORE_URL=http://127.0.0.1:18181 VCI_STORE_NAMESPACE=$ns VCI_TIMING=1 \
    /usr/bin/time -l $bin plan --base-ref HEAD --format json $projects > $tag.json 2> $tag.err
  code=$?
  end=$(python3 -c 'import time;print(time.time())')
  echo "exit=$code wall=$(python3 -c "print(round($end-$start,3))")" > $tag.time
  echo "$(date -u +%H:%M:%S) $cfg $variant $n exit=$code wall=$(python3 -c "print(round($end-$start,2))") $(grep -o 'plan total: [0-9.]*s' $tag.err)"
}
for n in $(seq $START $((START+RUNS-1))); do
  for variant in api all; do
    for cfg in v2-f3 v2-f1 281-f1 281-f3; do
      run_one $cfg $variant $n
    done
  done
done
echo done
