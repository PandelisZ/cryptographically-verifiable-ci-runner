#!/bin/bash
# usage: run.sh TAG PROCS REP CFG   (cfg: f3 = store-v2 format 3; f1 = store-v2 with
# VCI_STORE_RECORD_FORMAT=1 (envelopes + manifests); h281 = fx3's replay-head, vci 2.8.1's
# libSQL store write path). PROCS concurrent writer processes of UNITS (800) units each into
# one fresh namespace m-TAG-CFG-PROCS-REP on the local sqld ($SQLD_PORT, started from
# /opt/homebrew/bin/sqld by this script when it is not answering, its PID in sqld.pid), each
# process behind a counting proxy of its own; then (f3, f1) the same units again at a
# moved-on commit (supersession + the orphan pass). Everything lands in out/.
# Exit 1 when a phase lost units (sqld 0.24.32's write lock stalls for good under concurrent
# writers, docs/STORE-BACKENDS.md section 21 item 17): the caller runs the repetition again.
S=${MEAS_ROOT:?MEAS_ROOT: the directory holding wr/pairs.json, the target dir and meas-v2/}
W=$S/meas-v2/writes
BIN=${BIN:-$S/target-v2/release/examples/replay3}
HEAD=$S/fx3/bin/replay-head
PAIRS=$W/pairs-run.json
SQLD_PORT=${SQLD_PORT:-48111}
SQLD_DIR=$S/meas-v2/sqld-data
PBASE=${PBASE:-48120}
N=${UNITS:-800}
TAG=$1 P=$2 REP=$3 CFG=$4
ts() { python3 -I -c "import time;print(f'{time.time():.3f}')"; }
mkdir -p $W/out $SQLD_DIR
STALLED=0

start_sqld() { # a fresh data directory each time: a restart after a stall then has no WAL log to restore
  local data=$SQLD_DIR/data.sqld-$(date +%s)
  echo $data > $SQLD_DIR/current
  cd $SQLD_DIR
  nohup /opt/homebrew/bin/sqld --db-path $data --http-listen-addr 127.0.0.1:$SQLD_PORT --no-welcome >> $SQLD_DIR/sqld.log 2>&1 &
  echo $! > $SQLD_DIR/sqld.pid
  cd $W
  for i in $(seq 1 60); do probe && break; sleep 1; done
  echo "sqld started, pid $(cat $SQLD_DIR/sqld.pid), $data, answering after ${i}s $(date -u +%H:%M:%S)" | tee -a $W/out/sqld-restarts.log
}
probe() { # a 5 s-capped write: sqld's stalled lock answers nothing
  curl -s -m 5 -X POST http://127.0.0.1:$SQLD_PORT/v2/pipeline -H 'Content-Type: application/json' \
    -d '{"requests":[{"type":"execute","stmt":{"sql":"CREATE TABLE IF NOT EXISTS probe (k INTEGER)"}},{"type":"execute","stmt":{"sql":"INSERT INTO probe VALUES (1)"}},{"type":"close"}]}' | grep -q '"type":"ok"'
}
ensure_sqld() {
  probe && return 0
  # Every sqld on this script's own data directory (started by it): stopped.
  local mine=$(pgrep -f "sqld --db-path $SQLD_DIR/")
  if [ -n "$mine" ]; then
    echo "sqld: the write probe failed: stopping pid(s) $mine $(date -u +%H:%M:%S)" | tee -a $W/out/sqld-restarts.log
    kill $mine; sleep 1
    kill -9 $mine 2>/dev/null
    for i in $(seq 1 20); do [ -z "$(pgrep -f "sqld --db-path $SQLD_DIR/")" ] && break; sleep 0.5; done
  fi
  start_sqld
  probe || { echo "sqld: still not taking writes"; exit 3; }
}
wait_port() { for i in $(seq 1 50); do nc -z 127.0.0.1 $1 2>/dev/null && return 0; sleep 0.1; done; echo "port $1 never answered"; return 1; }

phase() { # phase NAME NS : P writer processes of mode NAME (write|supersede; batch for h281)
  local name=$1 ns=$2
  local out=$W/out/$TAG-$CFG-$P-$REP-$name
  local fmt=3 bin=$BIN env=()
  case $CFG in f1) fmt=1; env=(VCI_STORE_RECORD_FORMAT=1);; h281) bin=$HEAD;; esac
  ensure_sqld
  echo "== $CFG $name P=$P rep=$REP ns=$ns $(date -u +%H:%M:%S)"
  touch $out.flag
  local pids=() ppids=()
  for i in $(seq 0 $((P-1))); do
    python3 -I $W/proxy.py $((PBASE+i)) $SQLD_PORT $out-$i-proxy.json $out.flag & ppids+=($!)
  done
  for i in $(seq 0 $((P-1))); do wait_port $((PBASE+i)); done
  for i in $(seq 0 $((P-1))); do
    (
      t0=$(ts)
      if [ $CFG = h281 ]; then
        env VCI_STORE_URL=http://127.0.0.1:$((PBASE+i)) VCI_TIMING=1 $bin batch $ns w$i $PAIRS $((i*390)) $N > $out-$i.json 2> $out-$i.err
      else
        env "${env[@]}" VCI_STORE_URL=http://127.0.0.1:$((PBASE+i)) VCI_TIMING=1 $bin $name $fmt $ns w$i $PAIRS $((i*390)) $N > $out-$i.json 2> $out-$i.err
      fi
      echo "{\"rc\": $?, \"wall_secs\": $(python3 -I -c "print(round($(ts) - $t0, 3))")}" > $out-$i-wall.json
    ) &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait $p; done
  rm -f $out.flag
  for p in "${ppids[@]}"; do wait $p; done
  echo "end $(date -u +%H:%M:%S)"
  for i in $(seq 0 $((P-1))); do
    echo "proc $i: $(cat $out-$i-wall.json) $(cat $out-$i-proxy.json)"
    cat $out-$i.json
    grep -h "write batch" $out-$i.err | sed 's/^/  /' | head -20
    if grep -q '"rc": [^0]' $out-$i-wall.json || ! grep -q '"lost":0,' $out-$i.json || grep -q "not stored" $out-$i.err; then STALLED=1; fi
  done
  python3 -I $W/atrest.py http://127.0.0.1:$SQLD_PORT $ns | tee $out-atrest.json
  echo "sqld dbs/default KiB on disk (data + wal, every namespace since its start): $(du -sk $(cat $SQLD_DIR/current)/dbs/default 2>/dev/null | cut -f1)"
  [ $STALLED = 1 ] && echo "STALL: $CFG $name P=$P rep=$REP $(date -u +%H:%M:%S)" | tee -a $W/out/stalls.log
  return 0
}

ns=m-$TAG-$CFG-$P-$REP
ensure_sqld
VCI_STORE_URL=http://127.0.0.1:$SQLD_PORT $BIN prep $ns
phase write $ns
if [ $CFG != h281 ] && [ $STALLED = 0 ]; then
  # sqld's lock can stall after a phase whose every write succeeded: the write phase stands,
  # the second run cannot follow on a restarted (empty) server.
  if ! probe; then
    echo "STALL: $CFG after write (the lock stalled once the writers were done) P=$P rep=$REP $(date -u +%H:%M:%S)" | tee -a $W/out/stalls.log
    STALLED=1
  fi
fi
if [ $CFG != h281 ] && [ $STALLED = 0 ]; then
  # The first run's objects and manifests were put minutes ago: past the hour of grace they
  # would be at a real moved-on commit, so that the orphan pass has something to collect.
  if python3 -I $W/atrest.py http://127.0.0.1:$SQLD_PORT $ns backdate 7200 | tee $W/out/$TAG-$CFG-$P-$REP-backdate.json && grep -q backdated $W/out/$TAG-$CFG-$P-$REP-backdate.json; then
    phase supersede $ns
  else
    echo "STALL: $CFG at the backdate P=$P rep=$REP $(date -u +%H:%M:%S)" | tee -a $W/out/stalls.log
    STALLED=1
  fi
fi
exit $STALLED
