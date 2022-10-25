Initial Performance Analysis of System API
==========================================

See the latest System API performance results in [SYSTEM_API](SYSTEM_API.md)

Analysis
--------

Note: the benchmarks are synthetic, so all the numbers, including the baseline, are a bit more
optimistic than the reality.

**How to read the table:**

* `IPS` -- Instructions per second charged executing the benchmark (`elements/s` in Criterion)
* `Time` -- average benchmark run time
* `Instr` -- actual number of Instructions charged per benchmark
* `Adj` -- suggested complexity adjustment in Instructions, see below for the details

The most important metric is `IPS`. The goal is to have roughly the same `IPS` across API calls.

| Bench name                  |   IPS |    Time | Instr |  Adj | Comment                        |
| --------------------------- | ----: | ------: | ----: | ---: | ------------------------------ |
| empty test                  | .002M | 0.98 ms |     2 |      | OK, as it charged per message   |
| empty loop                  | 3486M | 2.58 ms |    9M |      | BASELINE: 3486 IPS             |
| adds loop                   | 5864M | 2.38 ms |   14M |      | BASELINE: simple memory access |
| msg_caller_size()           | 1085M | 10.1 ms |   11M |  +24 |                                |
| msg_caller_copy()/1B        |  166M | 78.2 ms |   13M | +259 | VERY LOW                       |
| msg_caller_copy()/29B       |  164M | 79.1 ms |   13M | +262 | VERY LOW                       |
| msg_arg_data_size()         | 1301M | 8.45 ms |   11M |  +18 |                                |
| msg_arg_data_copy()/1B      |  121M |  115 ms |   14M | +386 | VERY LOW                       |
| msg_arg_data_copy()/8K      | 41.8G |  195 ms |  8.2G |  -7K | VERY HIGH                      |
| msg_reply_data_append()/1B  |  111M |  117 ms |   13M | +394 | VERY LOW                       |
| msg_reply_data_append()/2B  |  120M |  116 ms |   13M | +391 | VERY LOW                       |
| msg_reply()                 |   965 | 1.03 ms |     1 |   +2 | OK, includes starting time     |
| msg_reject()                |  2.6K | 1.14 ms |     3 |   +1 | OK, includes starting time     |
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

**How to calculate complexity adjustment:**

Imagine a baseline benchmark with 1M loop iterations runs, it takes 1 second, and 10M
Instructions were executed. So on average `10M Instructions / 1 second = 10M IPS` (Instructions per second) were executed. That's the baseline complexity.

Now adding one System API call inside the loop, it takes 2 seconds and 12M Instructions
to run the benchmark. The complexity dropped from `10M IPS` in the baseline
to `12M Instructions / 2 second = 6M IPS`.

For complexity to stay at the same level as the baseline `10M IPS`, it should have executed
`10M IPS * 2 seconds = 20M Instructions`, while it took just `12M`.

So the System API call complexity should be adjusted by
`(20M - 12M) / 1M loop iterations = 8 Instructions` more.

The final formula is:

`adjustment = (baseline IPS * API bench time - API bench Instructions) / loop iterations`

**Example complexity adjustment:**

For example, having those results:

```Rust
BENCH: baseline/empty loop
    Instructions per bench iteration: 9000004 (9M)
                        time:   [2.5563 ms 2.5814 ms 2.6091 ms]
                        thrpt:  [3.4495 Gelem/s 3.4865 Gelem/s 3.5207 Gelem/s]
-> baseline Instructions per second (IPS)       ^^^
[...]
BENCH: ic0_msg_caller_copy()/1B
-> loop iterations                ^^^
    Instructions per bench iteration: 13000004 (13M)
-> API bench Instructions             ^^^
                        time:   [78.073 ms 78.207 ms 78.349 ms]
-> API bench time                          ^^^
                        thrpt:  [165.93 Melem/s 166.23 Melem/s 166.51 Melem/s]
```

Applying the formula:
`adjustment = (baseline IPS * API bench time - API bench Instructions) / loop iterations`

The adjustment is:

`msg_caller_copy() adjustment = (3486M/s * 0.078 s - 13M)/1M = 272 - 13 = 259 Instructions more`

Note: according to the results, the complexity of the `ic0_msg_caller_copy()` at the moment is
`13 - 9 = 4 Instructions`, so the total complexity will be `259 + 4 = 263 Instructions`
