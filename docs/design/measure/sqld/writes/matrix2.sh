#!/bin/bash
# The rest of the m3 matrix after its first pass: the cases that complete get up to 8 attempts,
# the three-writer format-1 cases (which stalled sqld in 17 of 17 attempts so far) 2 per
# repetition, so the matrix ends in minutes rather than an hour of the same stall.
# usage: matrix2.sh TAG  -> out/matrix2-TAG.log; each line of TASKS: rep P cfg attempts
S=${MEAS_ROOT:?MEAS_ROOT: the directory holding wr/pairs.json, the target dir and meas-v2/}
W=$S/meas-v2/writes
TAG=$1
TASKS="3 1 f3 8
3 1 f1 8
3 1 h281 8
3 3 f3 8
2 3 f1 2
3 3 f1 2
2 3 h281 2
3 3 h281 2"
echo "$TASKS" | while read rep P cfg max; do
  n=0
  for attempt in x y z u v w q r; do
    n=$((n+1)); [ $n -gt $max ] && break
    echo "##### $TAG rep $rep P=$P $cfg attempt $attempt $(date -u +%H:%M:%S)"
    if $W/run.sh $TAG $P $rep$attempt $cfg; then echo "##### ok"; break; else echo "##### stalled: again"; fi
  done
done
echo "##### matrix done $(date -u +%H:%M:%S)"
