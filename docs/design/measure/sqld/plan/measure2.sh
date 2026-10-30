#!/bin/bash
# RESULTS-2.md's before/after matrix, interleaved round-robin, on what setup2.sh built in WORK.
# usage: measure2.sh WORK OUT RUNS [START] -> OUT/<config>-<variant>-<n>.{json,err,time}, n from START
#   (default 1); a run whose files exist already is refused, so a re-run never overwrites the
#   published runs (give a new OUT, or a START past the rounds there).
# Configs: before-f3 / before-f1 ($VCI_BEFORE: store-v2 at 86bd306), fix1-f3 ($VCI_FIX1: + eaa13b3,
#          decode each verdict object once), after-f3 / after-f1 ($VCI_AFTER: + a397027, the boot
#          started early and killed when unused), 281-f1 ($VCI_281: vci 2.8.1). Defaults: the
#          release binaries meas-v2/vci-before, vci-fix1, vci-after and /opt/homebrew/bin/vci.
# Variants: api (--project vex-api, with the namespace's plan:natives:vex-api flag set: every plan
#          after a store's first), all (the four projects, flag set), api-first (vex-api with the
#          namespace's flags emptied first: a store's first plan). Before an api or all run whose
#          flag is missing (an api-first run of the same namespace emptied it), one warm-up plan
#          of the same binary sets it again ($tag.warmup.err).
# Every run: the memo tables emptied first; the store URL carries a placeholder authToken so that
# vex's [store] token_command (com ...) is never run; a com shim that exits 1 is first on PATH.
# VARIANTS and CONFIGS (space-separated) narrow the matrix.
set -u
S=${MEAS_ROOT:?MEAS_ROOT: the directory holding meas-v2/}
M=$S/meas-v2
W=${1:?usage: measure2.sh WORK OUT RUNS [START]}
OUT=${2:?OUT}
RUNS=${3:?RUNS}
START=${4:-1}
PORT=$(cat "$W/port")
VCI_BEFORE=${VCI_BEFORE:-$M/vci-before}
VCI_FIX1=${VCI_FIX1:-$M/vci-fix1}
VCI_AFTER=${VCI_AFTER:-$M/vci-after}
VCI_281=${VCI_281:-/opt/homebrew/bin/vci}
export PATH=$W/comshim:$(cat "$W/PATH.txt")
mkdir -p "$OUT"
URL="http://127.0.0.1:$PORT?authToken=placeholder-not-a-credential"
q() { curl -s -m 20 "http://127.0.0.1:$PORT/v2/pipeline" -H 'Content-Type: application/json' -d "{\"requests\":[{\"type\":\"execute\",\"stmt\":{\"sql\":\"$1\"}},{\"type\":\"close\"}]}" ; }
rows() { python3 -I -c "import json,sys; r=json.load(sys.stdin)['results'][0]; print(' '.join(str(row[0]['value']) for row in r['response']['result']['rows']) if r['type']=='ok' else '')"; }
prefix() { printf 'vci_%s_' "$(printf %s "$1" | b3sum --no-names | cut -c1-16)"; } # remote.rs table_prefix
empty_memos() { for t in $(q "SELECT name FROM sqlite_master WHERE name LIKE '%_memo'" | rows); do q "DELETE FROM $t" > /dev/null; done; }
has_flag() { q "SELECT count(*) FROM $(prefix "$1")flags WHERE name = 'plan:natives:vex-api'" | rows; }
plan() { # bin ns projects...
  local bin=$1 ns=$2; shift 2
  (cd "$W/vex-at-5eb7312" && env -u VCI_STORE_TOKEN -u RUBYLIB -u RUBYOPT VCI_STORE=libsql "VCI_STORE_URL=$URL" \
    VCI_STORE_NAMESPACE=$ns VCI_TIMING=1 /usr/bin/time -l "$bin" plan --base-ref HEAD --format json "$@")
}
run_one() {
  local cfg=$1 variant=$2 n=$3 bin ns projects
  case $cfg in
    before-f3) bin=$VCI_BEFORE; ns=meas3c;;
    before-f1) bin=$VCI_BEFORE; ns=meas1c;;
    fix1-f3) bin=$VCI_FIX1; ns=meas3c;;
    after-f3) bin=$VCI_AFTER; ns=meas3c;;
    after-f1) bin=$VCI_AFTER; ns=meas1c;;
    281-f1) bin=$VCI_281; ns=meas1c;;
  esac
  case $variant in
    api|api-first) projects="--project vex-api";;
    all) projects="--project vex-api --project vex-web --project rust --project vex-roder";;
  esac
  local tag=$OUT/$cfg-$variant-$n
  if [ -e "$tag.time" ] || [ -e "$tag.err" ]; then echo "$tag exists: not overwritten" >&2; exit 2; fi
  if [ "$variant" = api-first ]; then
    q "DELETE FROM $(prefix $ns)flags" > /dev/null
  elif [ "$(has_flag $ns)" != 1 ]; then
    empty_memos
    plan "$bin" $ns $projects > /dev/null 2> "$tag.warmup.err"
    echo "$(date -u +%H:%M:%S) $cfg $variant $n: warm-up plan (flag was missing), flag now $(has_flag $ns)"
  fi
  empty_memos
  sync; sleep 1
  start=$(python3 -c 'import time;print(time.time())')
  plan "$bin" $ns $projects > "$tag.json" 2> "$tag.err"
  code=$?
  end=$(python3 -c 'import time;print(time.time())')
  echo "exit=$code wall=$(python3 -c "print(round($end-$start,3))")" > "$tag.time"
  # a boot left running after vci exited (before a397027: orphaned)
  sleep 0.2; echo "probes_after_exit=$(ps -ax -o ppid=,command= | awk '$1==1 && /vci-rails-.*vci-probe\.rb/' | wc -l | tr -d ' ')" >> "$tag.time"
  echo "$(date -u +%H:%M:%S) $cfg $variant $n exit=$code wall=$(python3 -c "print(round($end-$start,2))") $(grep -o 'plan total: [0-9.]*s' "$tag.err")"
}
for n in $(seq "$START" $((START+RUNS-1))); do
  for variant in ${VARIANTS:-api all api-first}; do
    for cfg in ${CONFIGS:-before-f3 fix1-f3 after-f3 before-f1 after-f1 281-f1}; do
      run_one $cfg $variant $n
    done
  done
done
empty_memos
echo done
