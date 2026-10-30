# Measurements behind STORE-V2

The scripts and outputs that the numbers of [../STORE-V2.md](../STORE-V2.md) and
[../STORE-V2-DECISIONS.md](../STORE-V2-DECISIONS.md) come from. Their inputs are vex's data and are not in the
repository: the 1,175-unit sample (`pairs.json`: `{"pairs": [[envelope JSON, compact manifest JSON, root hex],
...]}`), the production logs of 27 October 2026 (`rails.json`), a production listing (`keys.json`) and the Turso
transaction timings by size (`txsize.json`). Run every Python script with `python3 -I`.

| file | what it is |
|---|---|
| `measure.py` | the size model: `python3 -I measure.py <pairs.json> <rails.json> <keys.json> <txsize.json> <out dir>`; writes `numbers.json` and prints `measure-output.txt` (sections 0 and 3) |
| `measure-binary-frame.py` | the earlier model with a binary frame, kept for the decisions that replaced it |
| `gitmeta.py`, `gitmeta.txt`, `git-text/gitmeta.json` | the real-git experiment of section 2.2 (git-meta's tree layout, today against format 3) |
| `replay-numbers.json` | what `crates/vci-cli/tests/replay.rs` measures over the sample (`VCI_PAIRS=<pairs.json> VCI_REPLAY_OUT=<file>`), with its comparison against `numbers.json` |
| `sqld/writes/` | section 10.1: 800-unit writes into a local `sqld`. `run.sh` (one configuration; starts its own `sqld` from `/opt/homebrew/bin/sqld` in a throwaway directory, every writer behind `proxy.py`), `matrix.sh`/`matrix2.sh` (the matrix), `mkpairs.py` (the run's units from the sample), `atrest.py` (rows and bytes at rest), `summarize.py` (`results.json`, `tables.md`), `RESULTS.md` (the write-up). The writer is `crates/vci-store-libsql/examples/replay3.rs` (`cargo build --release -p vci-store-libsql --example replay3`); the `h281` configuration also needs a `replay-head` binary built from 2.8.1's crates, which is not here |
| `sqld/plan/` | section 10.2: vex-api plans against a local `sqld`. `meas_plan_v2.rs` (the records' writer, a test file placed in `crates/vci-cli/tests/` for the run and gated on `VCI_MEAS_CONFIG`), `mkconfig.py` (its configuration), `measure.sh` (the interleaved runs), `parse.py` (`results.json`), `RESULTS.md` (the write-up). Section 10.2's re-measurement of 30 October after the two plan fixes: `setup2.sh` (`up WORK PORT` rebuilds the checkout, key, `sqld`, records and flags under one directory; `down WORK` removes them), `measure2.sh WORK OUT RUNS` (the before/after matrix; never overwrites a run), `parse2.py RUNS RESULTS` (`results2.json`), `RESULTS-2.md` (the write-up) |

The shell and Python scripts of `sqld/` read `MEAS_ROOT`, the directory that held the inputs, the target
directory and the outputs where they were run; the per-run raw files they wrote stayed on the measurement host.
Point them only at a `sqld` you started: never at a shared or hosted server, and never with `VCI_STORE_TOKEN` set.
