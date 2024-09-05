Management Canister Benchmark Results
=====================================

The `canister_snapshot` methods
-------------------------------

| Benchmark                                      | Result      |
| ---------------------------------------------- | ----------- |
| canister_snapshot_baseline/10 MiB              | 67.42 ms    |
| canister_snapshot_baseline/10 MiB+checkpoint   | 71.86 ms    |
| canister_snapshot_baseline/100 MiB             | 81.20 ms    |
| canister_snapshot_baseline/100 MiB+checkpoint  | 236.19 ms   |
| canister_snapshot_baseline/1000 MiB            | 209.69 ms   |
| canister_snapshot_baseline/1000 MiB+checkpoint | 2080.84 ms  |
| canister_snapshot_baseline/2000 MiB            | 320.58 ms   |
| canister_snapshot_baseline/2000 MiB+checkpoint | 3948.84 ms  |
| canister_snapshot_baseline/3000 MiB            | 446.00 ms   |
| canister_snapshot_baseline/3000 MiB+checkpoint | 5866.47 ms  |
| canister_snapshot_baseline/4000 MiB            | 558.36 ms   |
| canister_snapshot_baseline/4000 MiB+checkpoint | 7812.42 ms  |
| take_canister_snapshot/10 MiB                  | 67.43 ms    |
| take_canister_snapshot/10 MiB+checkpoint       | 76.36 ms    |
| take_canister_snapshot/100 MiB                 | 89.78 ms    |
| take_canister_snapshot/100 MiB+checkpoint      | 329.88 ms   |
| take_canister_snapshot/1000 MiB                | 205.80 ms   |
| take_canister_snapshot/1000 MiB+checkpoint     | 3104.20 ms  |
| take_canister_snapshot/2000 MiB                | 339.07 ms   |
| take_canister_snapshot/2000 MiB+checkpoint     | 6190.93 ms  |
| take_canister_snapshot/3000 MiB                | 483.03 ms   |
| take_canister_snapshot/3000 MiB+checkpoint     | 8796.62 ms  |
| take_canister_snapshot/4000 MiB                | 602.10 ms   |
| take_canister_snapshot/4000 MiB+checkpoint     | 11806.69 ms |
| replace_canister_snapshot/10 MiB               | 135.83 ms   |
| replace_canister_snapshot/10 MiB+checkpoint    | 141.99 ms   |
| replace_canister_snapshot/100 MiB              | 155.47 ms   |
| replace_canister_snapshot/100 MiB+checkpoint   | 313.65 ms   |
| replace_canister_snapshot/1000 MiB             | 251.70 ms   |
| replace_canister_snapshot/1000 MiB+checkpoint  | 3124.97 ms  |
| replace_canister_snapshot/2000 MiB             | 368.62 ms   |
| replace_canister_snapshot/2000 MiB+checkpoint  | 5966.05 ms  |
| replace_canister_snapshot/3000 MiB             | 483.03 ms   |
| replace_canister_snapshot/3000 MiB+checkpoint  | 8879.84 ms  |
| replace_canister_snapshot/4000 MiB             | 612.95 ms   |
| replace_canister_snapshot/4000 MiB+checkpoint  | 11538.85 ms |
| load_canister_snapshot/10 MiB                  | 136.72 ms   |
| load_canister_snapshot/10 MiB+checkpoint       | 143.49 ms   |
| load_canister_snapshot/100 MiB                 | 151.36 ms   |
| load_canister_snapshot/100 MiB+checkpoint      | 362.52 ms   |
| load_canister_snapshot/1000 MiB                | 251.78 ms   |
| load_canister_snapshot/1000 MiB+checkpoint     | 3027.24 ms  |
| load_canister_snapshot/2000 MiB                | 381.97 ms   |
| load_canister_snapshot/2000 MiB+checkpoint     | 6044.03 ms  |
| load_canister_snapshot/3000 MiB                | 491.07 ms   |
| load_canister_snapshot/3000 MiB+checkpoint     | 8806.15 ms  |
| load_canister_snapshot/4000 MiB                | 636.09 ms   |
| load_canister_snapshot/4000 MiB+checkpoint     | 11603.81 ms |
