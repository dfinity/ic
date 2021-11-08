Benchmark Results for `execute_update()`
========================================

Results
-------

Note: the benchmarks are synthetic, so all the numbers, including the baseline, are a bit more
optimistic than the reality.

**How to read the table:**

* `IPS` -- Instructions per second we charge executing the benchmark (`elements/s` in Criterion)
* `Time` -- average benchmark run time
* `Instr` -- actual number of Instructions charged per benchmark
* `Cost` -- suggested cost adjustment in Instructions, see below for the details

The most important metric is `IPS`. We can think of it as of "price" we charge running Canister
per second.

| Bench name                  |   IPS |    Time | Instr | Cost | Comment                        |
| --------------------------- | ----: | ------: | ----: | ---: | ------------------------------ |
| empty test                  | .002M | 0.98 ms |     2 |      | OK, as we charge per message   |
| empty loop                  | 3486M | 2.58 ms |    9M |      | BASELINE: 3486 IPS             |
| adds loop                   | 5864M | 2.38 ms |   14M |      | BASELINE: simple memory access |
| msg_caller_copy()/1B        |  166M | 78.2 ms |   13M | +259 | VERY LOW                       |
| msg_caller_copy()/29B       |  164M | 79.1 ms |   13M | +262 | VERY LOW                       |
| msg_caller_size()           | 1085M | 10.1 ms |   11M |  +24 |                                |
| msg_arg_data_size()         | 1301M | 8.45 ms |   11M |  +18 |                                |
| msg_arg_data_copy()/1B      |  121M |  115 ms |   14M | +386 | VERY LOW                       |
| msg_arg_data_copy()/8K      | 41.8G |  195 ms |  8.2G |  -7K | VERY HIGH                      |
| msg_reply_data_append()/1B  |  111M |  117 ms |   13M | +394 | VERY LOW                       |
| msg_reply_data_append()/2B  |  120M |  116 ms |   13M | +391 | VERY LOW                       |
| msg_reply()                 |   965 | 1.03 ms |     1 |   +2 | OK, includes starting cost     |
| msg_reject()                |  2.6K | 1.14 ms |     3 |   +1 | OK, includes starting cost     |
| canister_self_size()        |  572M | 19.2 ms |   11M |  +55 |                                |
| canister_self_copy()/1B     |  156M | 86.1 ms |   13M | +287 | VERY LOW                       |
| canister_self_copy()/10B    |  156M | 82.2 ms |   13M | +273 | VERY LOW                       |
| controller_size()           |  449M | 24.4 ms |   11M |  +74 |                                |
| controller_copy()/1B        |  150M | 86.5 ms |   13M | +288 | VERY LOW                       |
| controller_copy()/10B       |  150M | 86.3 ms |   13M | +287 | VERY LOW                       |
| stable_size()               | 1063M | 10.3 ms |   11M |  +24 |                                |
| stable_grow()               |  196M | 60.9 ms |   12M | +200 | VERY LOW                       |
| stable_read()/1B            |  106M |  131 ms |   14M | +442 | VERY LOW                       |
| stable_read()/8K            |   36G |  227 ms |  8.2G |  -7K | VERY HIGH                      |
| stable_write()/1B           | 98.7M |  141 ms |   14M | +477 | VERY LOW                       |
| stable_write()/8K           |   29G |  275 ms |  8.2G |  -7K | VERY HIGH                      |
| stable64_size()             | 1141M |  9.6 ms |   11M |  +22 |                                |
| stable64_grow()             |  200M | 59.8 ms |   12M | +196 | VERY LOW                       |
| stable64_read()/1B          |  102M |  136 ms |   14M | +460 | VERY LOW                       |
| stable64_read()/8K          |   35G |  232 ms |  8.2G |  -7K | VERY HIGH                      |
| stable64_write()/1B         |  102M |  137 ms |   14M | +463 | VERY LOW                       |
| stable64_write()/8K         |   30G |  272 ms |  8.2G |  -7K | VERY HIGH                      |
| time()                      | 1015M | 10.8 ms |   11M |  +26 |                                |
| canister_cycle_balance()    |  964M | 11.4 ms |   11M |  +28 |                                |
| canister_cycle_balance128() |  888M | 12.3 ms |   11M |  +31 |                                |
| msg_cycles_available()      |  362M | 30.3 ms |   11M |  +94 |                                |
| msg_cycles_available128()   |  453M | 25.1 ms |   11M |  +76 |                                |
| msg_cycles_accept()         |  193M |   62 ms |   12M | +204 | VERY LOW                       |
| msg_cycles_accept128()      |  328M | 39.5 ms |   13M | +124 | VERY LOW                       |
| data_certificate_present()  | 1550M | 7.09 ms |   11M |  +13 |                                |
| certified_data_set()/1B     |  152M | 78.8 ms |   12M | +262 | VERY LOW                       |
| certified_data_set()/8K     |  153M | 78.1 ms |   12M | +260 | VERY LOW                       |
| canister_status()           | 95.3M |  115 ms |   11M | +389 | VERY LOW                       |

First Iteration of Changes
--------------------------

**Code changes:**

```Rust
pub const MSG_ARG_DATA_COPY = NumInstructions::new(20);
pub const MSG_METHOD_NAME_COPY = NumInstructions::new(20);
pub const MSG_REPLY_DATA_APPEND = NumInstructions::new(20);
pub const STABLE_READ = NumInstructions::new(20);
pub const STABLE_WRITE = NumInstructions::new(20);
pub const STABLE64_READ = NumInstructions::new(20);
pub const STABLE64_WRITE = NumInstructions::new(20);
```

**Results:**

| Bench name                 |   IPS |   New |   Time |    New | Instr |  New | Cost |  New |
| -------------------------- | ----: | ----: | -----: | -----: | ----: | ---: | ---: | ---: |
| msg_arg_data_copy()/1B     |  121M |  305M | 115 ms | 111 ms |   14M |  34M | +386 | +352 |
| msg_arg_data_copy()/8K     | 41.8G | 43.5G | 195 ms | 188 ms |  8.2G | 8.2G |  -7K |  -7K |
| msg_reply_data_append()/1B |  111M |  307M | 117 ms | 107 ms |   13M |  33M | +394 | +340 |
| msg_reply_data_append()/2B |  120M |  315M | 116 ms | 107 ms |   13M |  34M | +391 | +339 |
| stable_read()/1B           |  106M |  268M | 131 ms | 126 ms |   14M |  34M | +442 | +405 |
| stable_read()/8K           |   36G |   36G | 227 ms | 224 ms |  8.2G | 8.2G |  -7K |  -7K |
| stable_write()/1B          | 98.7M |  266M | 141 ms | 127 ms |   14M |  34M | +477 | +408 |
| stable_write()/8K          |   29G |   32G | 275 ms | 255 ms |  8.2G | 8.2G |  -7K |  -7K |
| stable64_read()/1B         |  102M |  267M | 136 ms | 127 ms |   14M |  34M | +460 | +408 |
| stable64_read()/8K         |   35G |   36G | 232 ms | 225 ms |  8.2G | 8.2G |  -7K |  -7K |
| stable64_write()/1B        |  102M |  268M | 137 ms | 126 ms |   14M |  34M | +463 | +405 |
| stable64_write()/8K        |   30G |   31G | 272 ms | 258 ms |  8.2G | 8.2G |  -7K |  -7K |

Calculating System API Cost
---------------------------

**How to calculate cost adjustment:**

Imagine we run a baseline benchmark with 1M loop iterations, it takes 1 second, and we execute 10M
Instructions. So we charge `10M Instructions / 1 second = 10M IPS` (Instructions per second).
That's our baseline "price".

Now, we add one System API call inside the loop. Say, it takes now 2 seconds to run the benchmark,
and we execute 12M Instructions. And our charges dropped from `10M IPS` in the baseline bench
to `12M Instructions / 2 second = 6M IPS`.

For charges to stay at the same level as the baseline `10M IPS`, we should have charged
`10M IPS * 2 seconds = 20M Instructions` for the System API benchmark, while we charged just `12M`.

So the System API call should cost `(20M - 12M) / 1M loop iterations = 8 Instructions` more.

The final formula is:

`cost adjustment = (baseline IPS * API bench time - API bench Instructions) / loop iterations`

**Example cost adjustment:**

For example, having those results:

```Rust
BENCH: baseline/empty loop/1M
    Instructions per bench iteration: 9000004 (9M)
                        time:   [2.5563 ms 2.5814 ms 2.6091 ms]
                        thrpt:  [3.4495 Gelem/s 3.4865 Gelem/s 3.5207 Gelem/s]
-> baseline Instructions per second (IPS)       ^^^
[...]
BENCH: ic0.msg_caller_copy() loop/1M/1B
-> loop iterations                ^^^
    Instructions per bench iteration: 13000004 (13M)
-> API bench Instructions             ^^^
                        time:   [78.073 ms 78.207 ms 78.349 ms]
-> API bench time                          ^^^
                        thrpt:  [165.93 Melem/s 166.23 Melem/s 166.51 Melem/s]
```

Applying the formula:
`cost adjustment = (baseline IPS * API bench time - API bench Instructions) / loop iterations`

we get:

`msg_caller_copy() cost adjustment = (3486M/s * 0.078 s - 13M)/1M = 272 - 13 = 259 Instructions more`

Note: according to the results, the cost of the `ic0.msg_caller_copy()` at the moment is
`13 - 9 = 4 Instructions`, so the total cost will be `259 + 4 = 263 Instructions`

Detailed output
---------------

**Criterion:**

Note: for the sake of space, only some WAT are listed for the reference. Running `cargo bench`
produces all the WATs for each benchmark.

```Rust
BENCH: baseline/empty test
    WAT: 
            (module
                (memory $mem 1)
                (func $test (export "canister_update test") (local $i i32) (local $s i32)
                    (drop (i32.const 0))
                )
            )
    Instructions per bench iteration: 2 (2M)
                        time:   [978.47 us 984.18 us 990.10 us]
                        thrpt:  [2.0200 Kelem/s 2.0322 Kelem/s 2.0440 Kelem/s]

BENCH: baseline/empty loop/1M
    WAT: 
            (module
                (memory $mem 1)
                (func $test (export "canister_update test") (local $i i32) (local $s i32)
                    (loop $loop
                        (if (i32.lt_s (get_local $i) (i32.const 1000000))
                            (then
                                (set_local $i (i32.add (get_local $i) (i32.const 1)))
                                (br $loop)
                            )
                        )
                    )
                )
            )
    Instructions per bench iteration: 9000004 (9M)
                        time:   [2.5563 ms 2.5814 ms 2.6091 ms]
                        thrpt:  [3.4495 Gelem/s 3.4865 Gelem/s 3.5207 Gelem/s]

BENCH: baseline/adds loop/1M
    Instructions per bench iteration: 14000004 (14M)
                        time:   [2.3674 ms 2.3875 ms 2.4085 ms]
                        thrpt:  [5.8127 Gelem/s 5.8638 Gelem/s 5.9136 Gelem/s]
BENCH: ic0.msg_caller_copy() loop/1M/1B
    WAT: 
            (module
                (import "ic0" "msg_caller_copy"
                    (func $ic0_msg_caller_copy (param $p1 i32) (param $p2 i32) (param $p3 i32)))
                (memory $mem 1)
                (func $test (export "canister_update test") (local $i i32) (local $s i32)
                    (loop $loop
                        (if (i32.lt_s (get_local $i) (i32.const 1000000))
                            (then
                                (set_local $i (i32.add (get_local $i) (i32.const 1)))
                                (call $ic0_msg_caller_copy (i32.const 0) (i32.const 0) (i32.const 1))
                                (br $loop)
                            )
                        )
                    )
                )
            )
     Instructions per bench iteration: 13000004 (13M)
                        time:   [78.073 ms 78.207 ms 78.349 ms]
                        thrpt:  [165.93 Melem/s 166.23 Melem/s 166.51 Melem/s]
BENCH: ic0.msg_caller_copy() loop/1M/29B
    Instructions per bench iteration: 13000004 (13M)
                        time:   [79.007 ms 79.156 ms 79.296 ms]
                        thrpt:  [163.94 Melem/s 164.23 Melem/s 164.54 Melem/s]
BENCH: ic0.msg_caller_size() loop/1M
    Instructions per bench iteration: 11000004 (11M)
                        time:   [10.104 ms 10.138 ms 10.178 ms]
                        thrpt:  [1.0808 Gelem/s 1.0851 Gelem/s 1.0887 Gelem/s]
BENCH: ic0.msg_arg_data_size() loop/1M
    Instructions per bench iteration: 11000004 (11M)
                        time:   [8.4033 ms 8.4525 ms 8.5106 ms]
                        thrpt:  [1.2925 Gelem/s 1.3014 Gelem/s 1.3090 Gelem/s]
BENCH: ic0.msg_arg_data_copy() loop/1M/1B
    Instructions per bench iteration: 14000004 (14M)
                        time:   [114.73 ms 115.13 ms 115.59 ms]
                        thrpt:  [121.12 Melem/s 121.60 Melem/s 122.03 Melem/s]
BENCH: ic0.msg_arg_data_copy() loop/1M/8KiB
    Instructions per bench iteration: 8205000004 (8205M)
                        time:   [195.02 ms 195.88 ms 196.83 ms]
                        thrpt:  [41.685 Gelem/s 41.887 Gelem/s 42.073 Gelem/s]
BENCH: ic0.msg_reply_data_append() loop/1M/1B
    Instructions per bench iteration: 13000004 (13M)
                        time:   [116.54 ms 117.00 ms 117.50 ms]
                        thrpt:  [110.64 Melem/s 111.11 Melem/s 111.55 Melem/s]
BENCH: ic0.msg_reply_data_append() loop/1M/2B
    Instructions per bench iteration: 14000004 (14M)
                        time:   [115.73 ms 116.19 ms 116.66 ms]
                        thrpt:  [120.00 Melem/s 120.49 Melem/s 120.97 Melem/s]
BENCH: ic0.msg_reply()
    Instructions per bench iteration: 1 (1M)
                        time:   [1.0315 ms 1.0358 ms 1.0396 ms]
                        thrpt:  [961.89  elem/s 965.45  elem/s 969.51  elem/s]
BENCH: ic0.msg_reject()
    Instructions per bench iteration: 3 (3M)
                        time:   [1.1401 ms 1.1464 ms 1.1526 ms]
                        thrpt:  [2.6027 Kelem/s 2.6170 Kelem/s 2.6313 Kelem/s]
BENCH: ic0.canister_self_size() loop/1M
    Instructions per bench iteration: 11000004 (11M)
                        time:   [19.110 ms 19.212 ms 19.331 ms]
                        thrpt:  [569.04 Melem/s 572.57 Melem/s 575.60 Melem/s]
BENCH: ic0.canister_self_copy() loop/1M/1B
    Instructions per bench iteration: 13000004 (13M)
                        time:   [82.970 ms 83.166 ms 83.404 ms]
                        thrpt:  [155.87 Melem/s 156.31 Melem/s 156.68 Melem/s]
BENCH: ic0.canister_self_copy() loop/1M/10B
    Instructions per bench iteration: 13000004 (13M)
                        time:   [83.020 ms 83.235 ms 83.496 ms]
                        thrpt:  [155.70 Melem/s 156.18 Melem/s 156.59 Melem/s]
BENCH: ic0.controller_size() loop/1M
    Instructions per bench iteration: 11000004 (11M)
                        time:   [24.366 ms 24.480 ms 24.619 ms]
                        thrpt:  [446.80 Melem/s 449.34 Melem/s 451.45 Melem/s]
BENCH: ic0.controller_copy() loop/1M/1B
    Instructions per bench iteration: 13000004 (13M)
                        time:   [86.442 ms 86.565 ms 86.693 ms]
                        thrpt:  [149.96 Melem/s 150.18 Melem/s 150.39 Melem/s]
BENCH: ic0.controller_copy() loop/1M/10B
    Instructions per bench iteration: 13000004 (13M)
                        time:   [86.223 ms 86.384 ms 86.554 ms]
                        thrpt:  [150.20 Melem/s 150.49 Melem/s 150.77 Melem/s]
BENCH: ic0.stable_size() loop/1M
    Instructions per bench iteration: 11000007 (11M)
                        time:   [10.290 ms 10.346 ms 10.412 ms]
                        thrpt:  [1.0565 Gelem/s 1.0632 Gelem/s 1.0690 Gelem/s]
BENCH: ic0.stable_grow() loop/1M
    Instructions per bench iteration: 12000004 (12M)
                        time:   [60.916 ms 60.948 ms 60.983 ms]
                        thrpt:  [196.78 Melem/s 196.89 Melem/s 196.99 Melem/s]
BENCH: ic0.stable_read() loop/1M/1B
    WAT: 
            (module
                (import "ic0" "stable_grow"
                    (func $ic0_stable_grow (param $additional_pages i32) (result i32)))
                (import "ic0" "stable_read"
                    (func $ic0_stable_read (param $p1 i32) (param $p2 i32) (param $p3 i32)))
                (memory $mem 1)
                (func $test (export "canister_update test") (local $i i32) (local $s i32)
                    (drop (call $ic0_stable_grow (i32.const 1)))
                    (loop $loop
                        (if (i32.lt_s (get_local $i) (i32.const 1000000))
                            (then
                                (set_local $i (i32.add (get_local $i) (i32.const 1)))
                                (call $ic0_stable_read (i32.const 0) (i32.const 0) (i32.const 1))
                                (br $loop)
                            )
                        )
                    )
                )
            )
    Instructions per bench iteration: 14000007 (14M)
                        time:   [131.40 ms 131.74 ms 132.09 ms]
                        thrpt:  [105.99 Melem/s 106.27 Melem/s 106.55 Melem/s]
BENCH: ic0.stable_read() loop/1M/8KiB
    Instructions per bench iteration: 8205000007 (8205M)
                        time:   [226.71 ms 227.23 ms 227.82 ms]
                        thrpt:  [36.015 Gelem/s 36.108 Gelem/s 36.191 Gelem/s]
BENCH: ic0.stable_write() loop/1M/1B
    Instructions per bench iteration: 14000007 (14M)
                        time:   [141.39 ms 141.75 ms 142.15 ms]
                        thrpt:  [98.488 Melem/s 98.762 Melem/s 99.019 Melem/s]
BENCH: ic0.stable_write() loop/1M/8KiB
    Instructions per bench iteration: 8205000007 (8205M)
                        time:   [274.21 ms 275.27 ms 276.29 ms]
                        thrpt:  [29.697 Gelem/s 29.808 Gelem/s 29.922 Gelem/s]
BENCH: ic0.stable64_size() loop/1M
    Instructions per bench iteration: 11000007 (11M)
                        time:   [9.5864 ms 9.6352 ms 9.6897 ms]
                        thrpt:  [1.1352 Gelem/s 1.1417 Gelem/s 1.1475 Gelem/s]
BENCH: ic0.stable64_grow() loop/1M
    Instructions per bench iteration: 12000007 (12M)
                        time:   [59.770 ms 59.848 ms 59.954 ms]
                        thrpt:  [200.15 Melem/s 200.51 Melem/s 200.77 Melem/s]
BENCH: ic0.stable64_read() loop/1M/1B
    Instructions per bench iteration: 14000007 (14M)
                        time:   [135.83 ms 136.76 ms 137.81 ms]
                        thrpt:  [101.59 Melem/s 102.37 Melem/s 103.07 Melem/s]
BENCH: ic0.stable64_read() loop/1M/8KiB
    Instructions per bench iteration: 8205000007 (8205M)
                        time:   [232.41 ms 232.94 ms 233.51 ms]
                        thrpt:  [35.138 Gelem/s 35.224 Gelem/s 35.305 Gelem/s]
BENCH: ic0.stable64_write() loop/1M/1B
    Instructions per bench iteration: 14000007 (14M)
                        time:   [136.52 ms 137.14 ms 137.78 ms]
                        thrpt:  [101.61 Melem/s 102.09 Melem/s 102.55 Melem/s]
BENCH: ic0.stable64_write() loop/1M/8KiB
    Instructions per bench iteration: 8205000007 (8205M)
                        time:   [271.44 ms 272.90 ms 274.51 ms]
                        thrpt:  [29.890 Gelem/s 30.066 Gelem/s 30.227 Gelem/s]
BENCH: ic0.time() loop/1M
    Instructions per bench iteration: 11000004 (11M)
                        time:   [10.737 ms 10.832 ms 10.945 ms]
                        thrpt:  [1.0051 Gelem/s 1.0155 Gelem/s 1.0245 Gelem/s]
BENCH: ic0.canister_cycle_balance() loop/1M
    Instructions per bench iteration: 11000004 (11M)
                        time:   [11.206 ms 11.408 ms 11.649 ms]
                        thrpt:  [944.26 Melem/s 964.21 Melem/s 981.61 Melem/s]
BENCH: ic0.canister_cycles_balance128() loop/1M
    Instructions per bench iteration: 11000004 (11M)
                        time:   [12.348 ms 12.384 ms 12.423 ms]
                        thrpt:  [885.45 Melem/s 888.22 Melem/s 890.82 Melem/s]
BENCH: ic0.msg_cycles_available() loop/1M
    Instructions per bench iteration: 11000004 (11M)
                        time:   [28.699 ms 30.325 ms 32.080 ms]
                        thrpt:  [342.89 Melem/s 362.74 Melem/s 383.28 Melem/s]
BENCH: ic0.msg_cycles_available128() loop/1M
    Instructions per bench iteration: 11000004 (11M)
                        time:   [24.176 ms 24.270 ms 24.391 ms]
                        thrpt:  [450.99 Melem/s 453.23 Melem/s 455.01 Melem/s]
BENCH: ic0.msg_cycles_accept() loop/1M
    Instructions per bench iteration: 12000004 (12M)
                        time:   [59.460 ms 62.037 ms 64.637 ms]
                        thrpt:  [185.65 Melem/s 193.43 Melem/s 201.82 Melem/s]
BENCH: ic0.msg_cycles_accept128() loop/1M
    Instructions per bench iteration: 13000004 (13M)
                        time:   [39.501 ms 39.574 ms 39.653 ms]
                        thrpt:  [327.85 Melem/s 328.50 Melem/s 329.10 Melem/s]
BENCH: ic0.data_certificate_present() loop/1M
    Instructions per bench iteration: 11000004 (11M)
                        time:   [7.0119 ms 7.0945 ms 7.1892 ms]
                        thrpt:  [1.5301 Gelem/s 1.5505 Gelem/s 1.5688 Gelem/s]
BENCH: ic0.certified_data_set() loop/1M/1B
    Instructions per bench iteration: 12000004 (12M)
                        time:   [78.446 ms 78.814 ms 79.203 ms]
                        thrpt:  [151.51 Melem/s 152.26 Melem/s 152.97 Melem/s]
BENCH: ic0.certified_data_set() loop/1M/32B
    Instructions per bench iteration: 12000004 (12M)
                        time:   [77.851 ms 78.106 ms 78.369 ms]
                        thrpt:  [153.12 Melem/s 153.64 Melem/s 154.14 Melem/s]
BENCH: ic0.canister_status() loop/1M
    Instructions per bench iteration: 11000004 (11M)
                        time:   [114.54 ms 115.41 ms 116.19 ms]
                        thrpt:  [94.670 Melem/s 95.311 Melem/s 96.034 Melem/s]
```

**Iai:**

Iai uses `valgrind` to estimate number of CPU and memory subsystem load. For now the
data is not used for the final cost adjustments, yet it's included for the sake of
completeness.

```Rust
iai_baseline_empty_test
  Instructions:            25478948 <- Note: those are CPU instructions
  L1 Accesses:             38095846
  L2 Accesses:               124075
  RAM Accesses:              106100
  Estimated Cycles:        42429721 <- Note: those are CPU cycles

iai_baseline_empty_loop_1m
  Instructions:            40908532
  L1 Accesses:             58687111
  L2 Accesses:               148744
  RAM Accesses:              108410
  Estimated Cycles:        63225181

iai_baseline_add_loop_1m
  Instructions:            41966155
  L1 Accesses:             60791631
  L2 Accesses:               123082
  RAM Accesses:              107929
  Estimated Cycles:        65184556

iai_ic0_stable_size_loop_1m
  Instructions:           132398788
  L1 Accesses:            194381655
  L2 Accesses:               191511
  RAM Accesses:              104406
  Estimated Cycles:       198993420

iai_ic0_stable_read_loop_1m_1b
  Instructions:          1139126041
  L1 Accesses:           1651462415
  L2 Accesses:               195979
  RAM Accesses:               99570
  Estimated Cycles:      1655927260

iai_ic0_stable_read_loop_1m_8kb
  Instructions:          2223777275
  L1 Accesses:           3314395294
  L2 Accesses:               213405
  RAM Accesses:              108253
  Estimated Cycles:      3319251174

iai_ic0_stable_write_loop_1m_1b
  Instructions:          1143749169
  L1 Accesses:           1653851803
  L2 Accesses:               209683
  RAM Accesses:              111565
  Estimated Cycles:      1658804993

iai_ic0_stable_write_loop_1m_8kb
  Instructions:          2238785859
  L1 Accesses:           3334450124
  L2 Accesses:               165681
  RAM Accesses:              109961
  Estimated Cycles:      3339127164
```
