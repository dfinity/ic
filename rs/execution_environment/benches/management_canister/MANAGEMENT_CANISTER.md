Management Canister Benchmark Results
=====================================

The `canister_snapshot` methods
-------------------------------

| Benchmark                                    | Result     |
| -------------------------------------------- | ---------- |
| canister_snapshot_baseline/10MiB             | 14.11 ms   |
| canister_snapshot_baseline/10MiB+checkpoint  | 71.37 ms   |
| canister_snapshot_baseline/100MiB            | 58.09 ms   |
| canister_snapshot_baseline/100MiB+checkpoint | 229.77 ms  |
| canister_snapshot_baseline/1GiB              | 207.20 ms  |
| canister_snapshot_baseline/1GiB+checkpoint   | 2089.63 ms |
| canister_snapshot_baseline/2GiB              | 353.34 ms  |
| canister_snapshot_baseline/2GiB+checkpoint   | 4137.00 ms |
| take_canister_snapshot/10MiB                 | 67.71 ms   |
| take_canister_snapshot/10MiB+checkpoint      | 77.87 ms   |
| take_canister_snapshot/100MiB                | 89.81 ms   |
| take_canister_snapshot/100MiB+checkpoint     | 326.74 ms  |
| take_canister_snapshot/1GiB                  | 213.29 ms  |
| take_canister_snapshot/1GiB+checkpoint       | 3147.48 ms |
| take_canister_snapshot/2GiB                  | 354.72 ms  |
| take_canister_snapshot/2GiB+checkpoint       | 6212.27 ms |
| replace_canister_snapshot/10MiB              | 131.38 ms  |
| replace_canister_snapshot/10MiB+checkpoint   | 141.67 ms  |
| replace_canister_snapshot/100MiB             | 151.95 ms  |
| replace_canister_snapshot/100MiB+checkpoint  | 327.52 ms  |
| replace_canister_snapshot/1GiB               | 257.70 ms  |
| replace_canister_snapshot/1GiB+checkpoint    | 3076.36 ms |
| replace_canister_snapshot/2GiB               | 392.65 ms  |
| replace_canister_snapshot/2GiB+checkpoint    | 6183.87 ms |
| load_canister_snapshot/10MiB                 | 135.08 ms  |
| load_canister_snapshot/10MiB+checkpoint      | 142.11 ms  |
| load_canister_snapshot/100MiB                | 150.63 ms  |
| load_canister_snapshot/100MiB+checkpoint     | 360.40 ms  |
| load_canister_snapshot/1GiB                  | 250.59 ms  |
| load_canister_snapshot/1GiB+checkpoint       | 3173.48 ms |
| load_canister_snapshot/2GiB                  | 400.39 ms  |
| load_canister_snapshot/2GiB+checkpoint       | 6207.83 ms |
