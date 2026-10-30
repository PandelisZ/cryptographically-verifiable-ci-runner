#!/bin/bash
# The whole matrix: REPS repetitions x (1 and 3 writers) x (f3 f1 h281), each repetition run
# again (up to 4 attempts, tagged a b c d) when sqld's write lock stalled under it.
# usage: matrix.sh TAG [REPS]  -> out/matrix-TAG.log
S=${MEAS_ROOT:?MEAS_ROOT: the directory holding wr/pairs.json, the target dir and meas-v2/}
W=$S/meas-v2/writes
TAG=$1 REPS=${2:-3}
for rep in $(seq 1 $REPS); do
  for P in 1 3; do
    for cfg in f3 f1 h281; do
      for attempt in a b c d e f g h; do
        echo "##### $TAG rep $rep P=$P $cfg attempt $attempt $(date -u +%H:%M:%S)"
        if $W/run.sh $TAG $P $rep$attempt $cfg; then echo "##### ok"; break; else echo "##### stalled: again"; fi
      done
    done
  done
done
echo "##### matrix done $(date -u +%H:%M:%S)"
