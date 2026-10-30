### The first run (the namespace empty before it)

Per writer process, median (min-max) over the clean repetitions x processes; at rest: the namespace after all P processes wrote, median over repetitions.

| store | writers | runs clean+stalled | store write s | process wall s | transactions | flushes | longest tx s | SQL on the wire MB | TCP bytes to sqld MB | requests / resends | units lost | rows at rest | bytes at rest | attestations rows / MB | manifests rows / MB | objects rows / MB | log rows |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| store-v2, format 3 | 1 | 3+0 | 0.15 (0.14-0.15) | 0.60 (0.58-0.65) | 2 (2-2) | 1 (1-1) | 0.09 (0.07-0.09) | 2.59 (2.59-2.59) | 2.68 (2.68-2.68) | 6 (6-6) / 0 (0-0) | 0 (0-0) | 806 | 2.46 MB | 800 / 2.02 | 0 / 0.00 | 4 / 0.44 | 2 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 1 | 3+0 | 0.86 (0.76-0.93) | 1.23 (1.07-1.26) | 33 (33-33) | 7 (7-7) | 0.06 (0.04-0.10) | 30.24 (30.24-30.24) | 31.21 (31.21-31.21) | 37 (37-37) / 0 (0-0) | 0 (0-0) | 3233 | 28.86 MB | 800 / 17.82 | 800 / 10.85 | 0 / 0.00 | 1633 |
| vci 2.8.1 store (fx3 replay-head) | 1 | 3+0 | 0.69 (0.65-0.73) | 0.77 (0.72-0.80) | 33 (33-33) | 7 (7-7) | 0.04 (0.04-0.04) | - | 31.03 (31.03-31.03) | 38 (38-38) / 0 (0-0) | 0 (0-0) | 3233 | 28.82 MB | 800 / 17.78 | 800 / 10.85 | - / - | 1633 |
| store-v2, format 3 | 3 | 4+0 | 0.33 (0.17-0.39) | 0.85 (0.65-1.06) | 2 (2-3) | 1 (1-1) | 0.17 (0.10-0.27) | 2.68 (2.59-2.73) | 2.76 (2.68-2.81) | 6 (4-9) / 0 (0-0) | 0 (0-0) | 2417 | 7.60 MB | 2400 / 6.12 | 0 / 0.00 | 10 / 1.49 | 7 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | (no clean run) |
| vci 2.8.1 store (fx3 replay-head) | 3 | (no clean run) |

### The second run at a moved-on commit (the same 800 units per process, files changed: supersession and the orphan pass)

| store | writers | runs | find: s | find: requests | find: old values read MB | store write s (puts + removals) | transactions | SQL on the wire MB | TCP bytes to sqld MB | records removed | orphan pass s | orphan pass requests | orphan pass removed | units lost | rows at rest after | bytes at rest after | attestations rows | manifests rows | objects rows / MB | log rows | gone rows |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|---|--:|--:|--:|--:|--:|--:|--:|--:|
| store-v2, format 3 | 1 | 3 | 0.06 (0.06-0.07) | 15 (15-15) | 1.42 (1.42-1.42) | 0.14 (0.13-0.15) | 2 (2-2) | 3.05 (3.05-3.05) | 3.51 (3.51-3.51) | 800 (800-800) of 800 (800-800) | 0.004 (0.003-0.004) | 5 (5-5) | 1 (1-1) objects of 4 (4-4) named; state pruned 0 (0-0) | 0 (0-0) | 2409 | 2.76 MB | 800 | 0 | 4 / 0.45 | 804 | 801 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 1 | 3 | 0.09 (0.08-0.10) | 13 (13-13) | 17.42 (17.42-17.42) | 0.96 (0.90-1.29) | 33 (33-33) | 31.31 (31.31-31.31) | 32.77 (32.77-32.77) | 800 (800-800) of 800 (800-800) | 0.020 (0.016-0.022) | 4 (4-4) | 0 (0-0) manifests by the pass of 800 (800-800) found, 800 (800-800) roots | 0 (0-0) | 7266 | 29.40 MB | 800 | 800 | 0 / 0.00 | 4866 | 800 |
| store-v2, format 3 | 3 | 3 | 0.10 (0.06-0.17) | 15 (15-15) | 1.43 (1.42-1.45) | 0.50 (0.18-0.71) | 3 (2-3) | 3.14 (3.05-3.20) | 3.61 (3.51-3.66) | 800 (800-800) of 800 (800-800) | 0.012 (0.003-0.181) | 5 (5-5) | 1 (1-1) objects of 4 (4-4) named; state pruned 0 (0-0) | 0 (0-0) | 7228 | 8.51 MB | 2400 | 0 | 10 / 1.54 | 2415 | 2403 |

### Attempts under which sqld's write lock stalled (docs/STORE-BACKENDS.md section 21, item 17)

Per writer process of each stalled attempt: what the store got committed before it gave up. A stall 'after write' left every unit stored and only the second run could not follow.

| store | writers | attempt | phase | process | transactions committed | units lost in the flush that failed (the process then stopped) | longest request s | process wall s | TCP bytes to sqld MB | records in the namespace after (all processes, of P x 800) |
|---|--:|---|---|--:|--:|--:|--:|--:|--:|--:|
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1a | write | 0 | 2 | 69 | 30.05 | 60.59 | 4.55 | 140 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1a | write | 1 | 1 | 89 | 30.03 | 60.59 | 3.42 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1a | write | 2 | 2 | 45 | 30.04 | 60.59 | 4.43 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1b | write | 0 | 2 | 69 | 30.00 | 60.60 | 4.55 | 168 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1b | write | 1 | 2 | 61 | 30.01 | 60.60 | 4.59 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1b | write | 2 | 2 | 45 | 30.00 | 60.60 | 4.45 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1c | write | 0 | 8 | 36 | 30.02 | 61.56 | 12.62 | 634 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1c | write | 1 | 10 | 102 | 30.01 | 61.76 | 11.46 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1c | write | 2 | 9 | 126 | 30.01 | 61.88 | 12.41 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1d | write | 0 | 3 | 36 | 30.01 | 90.83 | 4.60 | 173 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1d | write | 1 | 1 | 89 | 30.01 | 60.91 | 3.42 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1d | write | 2 | 2 | 45 | 30.01 | 60.91 | 4.43 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1e | write | 0 | 10 | 129 | 30.02 | 61.55 | 11.54 | 698 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1e | write | 1 | 9 | 3 | 30.02 | 61.55 | 9.28 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1e | write | 2 | 10 | 95 | 30.01 | 61.55 | 12.45 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1f | write | 0 | 2 | 69 | 30.01 | 60.66 | 4.55 | 168 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1f | write | 1 | 2 | 61 | 30.01 | 60.66 | 4.57 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1f | write | 2 | 2 | 45 | 30.01 | 60.66 | 4.43 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1g | write | 0 | 7 | 68 | 30.04 | 61.23 | 9.15 | 446 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1g | write | 1 | 4 | 2 | 30.07 | 61.17 | 4.67 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1g | write | 2 | 7 | 44 | 30.03 | 61.35 | 8.99 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1h | write | 0 | 2 | 69 | 30.01 | 60.90 | 4.55 | 162 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1h | write | 1 | 1 | 89 | 30.01 | 60.90 | 3.44 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 1h | write | 2 | 3 | 23 | 30.02 | 60.90 | 5.55 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 2x | write | 0 | 2 | 69 | 30.06 | 60.80 | 4.55 | 168 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 2x | write | 1 | 2 | 61 | 30.08 | 60.80 | 4.57 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 2x | write | 2 | 2 | 45 | 30.08 | 60.80 | 4.43 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 2y | write | 0 | 7 | 68 | 30.10 | 61.13 | 9.16 | 481 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 2y | write | 1 | 7 | 58 | 30.09 | 61.13 | 9.05 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 2y | write | 2 | 6 | 65 | 30.08 | 61.13 | 7.86 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 3x | write | 0 | 2 | 69 | 30.07 | 60.72 | 4.55 | 168 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 3x | write | 1 | 2 | 61 | 30.08 | 60.72 | 4.57 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 3x | write | 2 | 2 | 45 | 30.08 | 60.72 | 4.45 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 3y | write | 0 | 2 | 69 | 30.07 | 61.26 | 4.55 | 168 |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 3y | write | 1 | 2 | 61 | 30.05 | 61.26 | 4.57 |  |
| store-v2, VCI_STORE_RECORD_FORMAT=1 | 3 | 3y | write | 2 | 2 | 45 | 30.07 | 61.26 | 4.44 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1a | write | 0 | 6 | 100 | 30.01 | 60.89 | 8.02 | 472 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1a | write | 1 | 7 | 58 | 30.03 | 60.89 | 9.10 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1a | write | 2 | 7 | 42 | 30.04 | 60.89 | 8.90 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1b | write | 0 | 2 | 69 | 30.10 | 60.70 | 4.52 | 171 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1b | write | 1 | 2 | 59 | 30.10 | 60.70 | 4.51 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1b | write | 2 | 2 | 44 | 30.08 | 60.70 | 4.41 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1c | write | 0 | 2 | 69 | 30.05 | 60.41 | 4.52 | 171 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1c | write | 1 | 2 | 59 | 30.05 | 60.41 | 4.51 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1c | write | 2 | 2 | 44 | 30.01 | 60.41 | 4.41 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1d | write | 0 | 4 | 3 | 30.05 | 60.79 | 4.70 | 280 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1d | write | 1 | 2 | 59 | 30.21 | 60.79 | 4.50 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1d | write | 2 | 5 | 86 | 30.08 | 60.79 | 6.70 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1e | write | 0 | 10 | 129 | 30.02 | 61.19 | 11.49 | 694 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1e | write | 1 | 10 | 77 | 30.01 | 61.19 | 12.44 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1e | write | 2 | 10 | 126 | 30.07 | 91.34 | 10.11 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1f | write | 0 | 4 | 3 | 30.01 | 60.52 | 4.70 | 336 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1f | write | 1 | 4 | 2 | 30.02 | 60.52 | 4.64 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1f | write | 2 | 4 | 2 | 30.02 | 60.52 | 4.55 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1g | write | 0 | 9 | 2 | 30.32 | 61.65 | 11.51 | 1038 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1g | write | 1 | 16 | 50 | 30.32 | 61.65 | 18.04 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1g | write | 2 | 18 | 34 | 30.29 | 61.65 | 19.20 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1h | write | 0 | 13 | 35 | 30.08 | 61.45 | 14.90 | 955 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1h | write | 1 | 13 | 2 | 30.11 | 61.46 | 13.69 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 1h | write | 2 | 13 | 34 | 30.09 | 61.48 | 14.59 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 2x | write | 0 | 4 | 3 | 30.02 | 60.44 | 4.70 | 336 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 2x | write | 1 | 4 | 2 | 30.00 | 60.44 | 4.64 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 2x | write | 2 | 4 | 2 | 30.01 | 60.44 | 4.55 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 2y | write | 0 | 2 | 69 | 30.01 | 60.38 | 4.52 | 171 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 2y | write | 1 | 2 | 59 | 30.00 | 60.38 | 4.50 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 2y | write | 2 | 2 | 44 | 30.00 | 60.38 | 4.41 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 3x | write | 0 | 2 | 69 | 30.01 | 60.36 | 4.52 | 171 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 3x | write | 1 | 2 | 59 | 30.02 | 60.36 | 4.51 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 3x | write | 2 | 2 | 44 | 30.01 | 60.36 | 4.41 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 3y | write | 0 | 4 | 3 | 30.02 | 60.52 | 4.69 | 336 |
| vci 2.8.1 store (fx3 replay-head) | 3 | 3y | write | 1 | 4 | 2 | 30.01 | 60.52 | 4.64 |  |
| vci 2.8.1 store (fx3 replay-head) | 3 | 3y | write | 2 | 4 | 2 | 30.01 | 60.52 | 4.55 |  |

stalls.log (every matrix run on this host, with the time of day):

    STALL: f1 write P=3 rep=1a 03:43:50
    STALL: f1 supersede P=1 rep=2a 03:45:34
    STALL: f3 after write (the lock stalled once the writers were done) P=3 rep=1a 03:58:09
    STALL: f1 write P=3 rep=1a 03:59:21
    STALL: f1 write P=3 rep=1b 04:00:29
    STALL: f1 write P=3 rep=1c 04:01:40
    STALL: f1 write P=3 rep=1d 04:03:19
    STALL: f1 write P=3 rep=1e 04:04:29
    STALL: f1 write P=3 rep=1f 04:05:38
    STALL: f1 write P=3 rep=1g 04:06:47
    STALL: f1 write P=3 rep=1h 04:07:56
    STALL: h281 write P=3 rep=1a 04:09:05
    STALL: h281 write P=3 rep=1b 04:10:14
    STALL: h281 write P=3 rep=1c 04:11:23
    STALL: h281 write P=3 rep=1d 04:12:32
    STALL: h281 write P=3 rep=1e 04:14:12
    STALL: h281 write P=3 rep=1f 04:15:21
    STALL: h281 write P=3 rep=1g 04:16:31
    STALL: h281 write P=3 rep=1h 04:17:41
    STALL: f1 write P=3 rep=2x 04:20:34
    STALL: f1 write P=3 rep=2y 04:21:44
    STALL: f1 write P=3 rep=3x 04:22:53
    STALL: f1 write P=3 rep=3y 04:24:03
    STALL: h281 write P=3 rep=2x 04:25:11
    STALL: h281 write P=3 rep=2y 04:26:19
    STALL: h281 write P=3 rep=3x 04:27:27
    STALL: h281 write P=3 rep=3y 04:28:36

