Management Canister Benchmark Results
=====================================

The `canister_snapshot` methods
-------------------------------

| Benchmark                                                    | Result     |
| ---                                                          | ---        |
|  canister_snapshot_baseline/10 MiB                           | 0 ms       |
|  canister_snapshot_baseline/10 MiB+checkpoint                | 38.18 ms   |
|  canister_snapshot_baseline/100 MiB                          | 0 ms       |
|  canister_snapshot_baseline/100 MiB+checkpoint               | 324.37 ms  |
|  canister_snapshot_baseline/1000 MiB                         | 0 ms       |
|  canister_snapshot_baseline/1000 MiB+checkpoint              | 3115.18 ms |
|  canister_snapshot_baseline/2000 MiB                         | 0 ms       |
|  canister_snapshot_baseline/2000 MiB+checkpoint              | 6476.05 ms |
|  canister_snapshot_baseline/3000 MiB                         | 0 ms       |
|  canister_snapshot_baseline/3000 MiB+checkpoint              | 9573.92 ms |
|  canister_snapshot_baseline/4000 MiB                         | 0 ms       |
|  canister_snapshot_baseline/4000 MiB+checkpoint              | 12530.35 ms |
|  take_canister_snapshot/10 MiB                               | 2.43 ms    |
|  take_canister_snapshot/10 MiB+checkpoint                    | 52.38 ms   |
|  take_canister_snapshot/100 MiB                              | 3.92 ms    |
|  take_canister_snapshot/100 MiB+checkpoint                   | 403.96 ms  |
|  take_canister_snapshot/1000 MiB                             | 32.25 ms   |
|  take_canister_snapshot/1000 MiB+checkpoint                  | 3804.51 ms |
|  take_canister_snapshot/2000 MiB                             | 65.10 ms   |
|  take_canister_snapshot/3000 MiB                             | 91.00 ms   |
|  take_canister_snapshot/3000 MiB+checkpoint                  | 12238.36 ms |
|  take_canister_snapshot/4000 MiB                             | 121.25 ms  |
|  take_canister_snapshot/4000 MiB+checkpoint                  | 16344.52 ms |
|  replace_canister_snapshot/10 MiB                            | 2.51 ms    |
|  replace_canister_snapshot/10 MiB+checkpoint                 | 47.95 ms   |
|  replace_canister_snapshot/100 MiB                           | 2.85 ms    |
|  replace_canister_snapshot/100 MiB+checkpoint                | 413.80 ms  |
|  replace_canister_snapshot/1000 MiB                          | 35.03 ms   |
|  replace_canister_snapshot/1000 MiB+checkpoint               | 3860.57 ms |
|  replace_canister_snapshot/2000 MiB                          | 65.43 ms   |
|  replace_canister_snapshot/2000 MiB+checkpoint               | 8371.56 ms |
|  replace_canister_snapshot/3000 MiB                          | 93.29 ms   |
|  replace_canister_snapshot/3000 MiB+checkpoint               | 12305.84 ms |
|  replace_canister_snapshot/4000 MiB                          | 117.81 ms  |
|  replace_canister_snapshot/4000 MiB+checkpoint               | 15031.26 ms |
|  load_canister_snapshot/10 MiB                               | 7.60 ms    |
|  load_canister_snapshot/10 MiB+checkpoint                    | 62.35 ms   |
|  load_canister_snapshot/100 MiB                              | 5.37 ms    |
|  load_canister_snapshot/100 MiB+checkpoint                   | 438.70 ms  |
|  load_canister_snapshot/1000 MiB                             | 35.73 ms   |
|  load_canister_snapshot/1000 MiB+checkpoint                  | 3794.54 ms |
|  load_canister_snapshot/2000 MiB                             | 64.80 ms   |
|  load_canister_snapshot/2000 MiB+checkpoint                  | 7985.54 ms |
|  load_canister_snapshot/3000 MiB                             | 90.69 ms   |
|  load_canister_snapshot/3000 MiB+checkpoint                  | 12256.09 ms |
|  load_canister_snapshot/4000 MiB                             | 114.41 ms  |
|  load_canister_snapshot/4000 MiB+checkpoint                  | 16743.17 ms |
|  read_canister_snapshot_data/10 MiB                          | 2.37 ms    |
|  read_canister_snapshot_data/10 MiB+checkpoint               | 55.74 ms   |
|  read_canister_snapshot_data/100 MiB                         | 2.30 ms    |
|  read_canister_snapshot_data/100 MiB+checkpoint              | 392.66 ms  |
|  read_canister_snapshot_data/1000 MiB                        | 2.29 ms    |
|  read_canister_snapshot_data/1000 MiB+checkpoint             | 3908.44 ms |
|  read_canister_snapshot_data/2000 MiB                        | 2.27 ms    |
|  read_canister_snapshot_data/2000 MiB+checkpoint             | 8305.71 ms |
|  read_canister_snapshot_data/3000 MiB                        | 2.35 ms    |
|  read_canister_snapshot_data/3000 MiB+checkpoint             | 12287.63 ms |
|  read_canister_snapshot_data/4000 MiB                        | 2.21 ms    |
|  read_canister_snapshot_data/4000 MiB+checkpoint             | 16328.17 ms |