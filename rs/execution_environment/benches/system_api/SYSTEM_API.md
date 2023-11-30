System API Performance Report
=============================

Remote (old) commit:987f50c19 branch:987f50c19
Local  (new) commit:69045aaa1 branch:andriy/fix-system-api-benchmarks-2

| API Type / System API Call                 | Old IPS  | New IPS  | Speedup | Round Time |
| ------------------------------------------ | -------- | -------- | ------- | ---------- |
| inspect/ic0_msg_method_name_size()         |    8.43G |    10.6G |    +25% |      0.66s |
| inspect/ic0_msg_method_name_copy()/1B      |    4.13G |    4.51G |     +9% |      1.55s |
| inspect/ic0_msg_method_name_copy()/30B     |    4.09G |    4.55G |    +11% |      1.54s |
| inspect/ic0_accept_message()*              |    2.49M |    4.61M |    +85% |          - |
| query/ic0_data_certificate_size()          |    7.99G |    9.63G |    +20% |      0.73s |
| query/ic0_data_certificate_copy()/1B       |    3.83G |    4.29G |    +12% |      1.63s |
| query/ic0_data_certificate_copy()/64B      |    4.11G |    4.79G |    +16% |      1.46s |
| update/baseline/empty test*                |    10.3K |    22.7K |   +120% |          - |
| update/baseline/empty loop                 |    6.29G |    6.48G |     +3% |      1.08s |
| update/baseline/adds                       |    9.21G |    9.47G |     +2% |      0.74s |
| update/ic0_msg_caller_size()               |    7.91G |    10.2G |    +28% |      0.69s |
| update/ic0_msg_caller_copy()/1B            |    3.77G |    4.40G |    +16% |      1.59s |
| update/ic0_msg_caller_copy()/10B           |    3.83G |    4.46G |    +16% |      1.57s |
| update/ic0_msg_arg_data_size()             |    7.93G |    10.5G |    +32% |      0.67s |
| update/ic0_msg_arg_data_copy()/1B          |    3.90G |    4.49G |    +15% |      1.56s |
| update/ic0_msg_arg_data_copy()/1K          |    10.2G |    11.7G |    +14% |      0.60s |
| update/ic0_msg_reply()*                    |    2.84M |    4.18M |    +47% |          - |
| update/ic0_msg_reply_data_append()/1B      |    3.86G |    4.78G |    +23% |      1.46s |
| update/ic0_msg_reply_data_append()/2B      |    3.86G |    5.15G |    +33% |      1.36s |
| update/ic0_msg_reject()*                   |    2.78M |    4.07M |    +46% |          - |
| update/ic0_canister_self_size()            |    7.91G |    9.70G |    +22% |      0.72s |
| update/ic0_canister_self_copy()/1B         |    3.78G |    4.34G |    +14% |      1.61s |
| update/ic0_canister_self_copy()/10B        |    3.79G |    4.40G |    +16% |      1.59s |
| update/ic0_debug_print()/1B                |    1.93G |    2.30G |    +19% |      3.04s |
| update/ic0_debug_print()/1K                |    18.6G |    22.1G |    +18% |      0.32s |
| update/ic0_call_new()                      |    5.52G |    5.89G |     +6% |      1.19s |
| update/call_new+ic0_call_data_append()/1B  |    4.63G |    5.17G |    +11% |      1.35s |
| update/call_new+ic0_call_data_append()/1K  |    6.77G |     128G |  +1790% |      0.05s |
| update/call_new+ic0_call_on_cleanup()      |    5.94G |    6.49G |     +9% |      1.08s |
| update/call_new+ic0_call_cycles_add()      |    4.90G |    5.08G |     +3% |      1.38s |
| update/call_new+ic0_call_cycles_add128()   |    4.86G |    4.98G |     +2% |      1.41s |
| update/call_new+ic0_call_perform()         |    4.45G |    4.45G |     +0% |      1.57s |
| update/ic0_stable_size()                   |    1.94G |    1.95G |     +0% |      3.59s |
| update/ic0_stable_grow()                   |     577M |     640M |    +10% |     10.94s |
| update/ic0_stable_read()/1B                |    1.28G |    1.27G |     -1% |      5.51s |
| update/ic0_stable_read()/1K                |    25.7G |    25.7G |     +0% |      0.27s |
| update/ic0_stable_write()/1B               |     810M |     645M |    -21% |     10.85s |
| update/ic0_stable_write()/1K               |    18.1G |    13.8G |    -24% |      0.51s |
| update/ic0_stable64_size()                 |    3.81G |    3.84G |     +0% |      1.82s |
| update/ic0_stable64_grow()                 |     564M |     642M |    +13% |     10.90s |
| update/ic0_stable64_read()/1B              |    1.19G |    1.26G |     +5% |      5.56s |
| update/ic0_stable64_read()/1K              |    24.9G |    25.4G |     +2% |      0.28s |
| update/ic0_stable64_write()/1B             |     777M |     634M |    -19% |     11.04s |
| update/ic0_stable64_write()/1K             |    17.7G |    13.6G |    -24% |      0.51s |
| update/ic0_time()                          |    7.98G |    9.53G |    +19% |      0.73s |
| update/ic0_global_timer_set()              |    6.86G |    8.17G |    +19% |      0.86s |
| update/ic0_performance_counter()           |    3.09G |    3.69G |    +19% |      1.90s |
| update/ic0_canister_cycle_balance()        |    7.46G |    9.56G |    +28% |      0.73s |
| update/ic0_canister_cycle_balance128()     |    3.76G |    4.53G |    +20% |      1.55s |
| update/ic0_msg_cycles_available()          |    6.39G |    8.02G |    +25% |      0.87s |
| update/ic0_msg_cycles_available128()       |    3.52G |    4.07G |    +15% |      1.72s |
| update/ic0_msg_cycles_accept()             |    5.09G |    6.02G |    +18% |      1.16s |
| update/ic0_msg_cycles_accept128()          |    2.96G |    3.46G |    +16% |      2.02s |
| update/ic0_data_certificate_present()      |    8.02G |    10.4G |    +29% |      0.67s |
| update/ic0_certified_data_set()/1B         |    3.46G |    3.96G |    +14% |      1.77s |
| update/ic0_certified_data_set()/32B        |    3.63G |    4.23G |    +16% |      1.65s |
| update/ic0_canister_status()               |    8.15G |    10.5G |    +28% |      0.67s |
| update/ic0_mint_cycles()                   |     430M |     430M |     +0% |     16.28s |
| update/ic0_is_controller()                 |    6.42G |    6.92G |     +7% |      1.01s |
| update/ic0_cycles_burn128()                |     116M |     111M |     -5% |     63.06s |

Average speedup of the local (new) changes: +44% (throughput)

| API Type / System API Call (1M Iterations) | Old Time | New Time | Speedup |
| ------------------------------------------ | -------- | -------- | ------- |
| inspect/ic0_msg_method_name_size()         |   61.3ms |   48.7ms |    -21% |
| inspect/ic0_msg_method_name_copy()/1B      |    125ms |    115ms |     -8% |
| inspect/ic0_msg_method_name_copy()/30B     |    131ms |    118ms |    -10% |
| inspect/ic0_accept_message()*              |    202µs |    109µs |    -47% |
| query/ic0_data_certificate_size()          |   64.6ms |   53.6ms |    -18% |
| query/ic0_data_certificate_copy()/1B       |    135ms |    121ms |    -11% |
| query/ic0_data_certificate_copy()/64B      |    141ms |    121ms |    -15% |
| update/baseline/empty test*                |    193µs |    131µs |    -33% |
| update/baseline/empty loop                 |   1.74ms |   1.69ms |     -3% |
| update/baseline/adds                       |   1.73ms |   1.68ms |     -3% |
| update/ic0_msg_caller_size()               |   65.3ms |   50.6ms |    -23% |
| update/ic0_msg_caller_copy()/1B            |    137ms |    118ms |    -14% |
| update/ic0_msg_caller_copy()/10B           |    138ms |    118ms |    -15% |
| update/ic0_msg_arg_data_size()             |   65.1ms |   49.1ms |    -25% |
| update/ic0_msg_arg_data_copy()/1B          |    133ms |    115ms |    -14% |
| update/ic0_msg_arg_data_copy()/1K          |    150ms |    130ms |    -14% |
| update/ic0_msg_reply()*                    |    177µs |    120µs |    -33% |
| update/ic0_msg_reply_data_append()/1B      |    134ms |    118ms |    -12% |
| update/ic0_msg_reply_data_append()/2B      |    134ms |    119ms |    -12% |
| update/ic0_msg_reject()*                   |    181µs |    124µs |    -32% |
| update/ic0_canister_self_size()            |   65.3ms |   53.2ms |    -19% |
| update/ic0_canister_self_copy()/1B         |    137ms |    119ms |    -14% |
| update/ic0_canister_self_copy()/10B        |    139ms |    120ms |    -14% |
| update/ic0_debug_print()/1B                |   61.6ms |   51.7ms |    -17% |
| update/ic0_debug_print()/1K                |   61.3ms |   51.5ms |    -16% |
| update/ic0_call_new()                      |    280ms |    263ms |     -7% |
| update/call_new+ic0_call_data_append()/1B  |    444ms |    407ms |     -9% |
| update/call_new+ic0_call_data_append()/1K  |    454ms |    415ms |     -9% |
| update/call_new+ic0_call_on_cleanup()      |    346ms |    317ms |     -9% |
| update/call_new+ic0_call_cycles_add()      |    419ms |    404ms |     -4% |
| update/call_new+ic0_call_cycles_add128()   |    423ms |    412ms |     -3% |
| update/call_new+ic0_call_perform()         |    1.47s |    1.47s |     +0% |
| update/ic0_stable_size()                   |   8.74ms |   8.68ms |     -1% |
| update/ic0_stable_grow()                   |    204ms |    184ms |    -10% |
| update/ic0_stable_read()/1B                |   31.2ms |   31.3ms |     +0% |
| update/ic0_stable_read()/1K                |   41.3ms |   41.2ms |     -1% |
| update/ic0_stable_write()/1B               |   49.3ms |   61.9ms |    +25% |
| update/ic0_stable_write()/1K               |   58.4ms |   76.9ms |    +31% |
| update/ic0_stable64_size()                 |   4.46ms |   4.41ms |     -2% |
| update/ic0_stable64_grow()                 |    208ms |    183ms |    -13% |
| update/ic0_stable64_read()/1B              |   33.4ms |   31.6ms |     -6% |
| update/ic0_stable64_read()/1K              |   42.6ms |   41.7ms |     -3% |
| update/ic0_stable64_write()/1B             |   51.4ms |   62.9ms |    +22% |
| update/ic0_stable64_write()/1K             |   59.8ms |     78ms |    +30% |
| update/ic0_time()                          |   64.7ms |   54.2ms |    -17% |
| update/ic0_global_timer_set()              |   75.5ms |   63.3ms |    -17% |
| update/ic0_performance_counter()           |   70.4ms |   58.9ms |    -17% |
| update/ic0_canister_cycle_balance()        |   69.2ms |     54ms |    -22% |
| update/ic0_canister_cycle_balance128()     |    137ms |    114ms |    -17% |
| update/ic0_msg_cycles_available()          |   80.8ms |   64.4ms |    -21% |
| update/ic0_msg_cycles_available128()       |    146ms |    126ms |    -14% |
| update/ic0_msg_cycles_accept()             |    101ms |   85.9ms |    -15% |
| update/ic0_msg_cycles_accept128()          |    175ms |    149ms |    -15% |
| update/ic0_data_certificate_present()      |   64.4ms |   49.3ms |    -24% |
| update/ic0_certified_data_set()/1B         |    149ms |    130ms |    -13% |
| update/ic0_certified_data_set()/32B        |    151ms |    129ms |    -15% |
| update/ic0_canister_status()               |   63.3ms |   48.8ms |    -23% |
| update/ic0_mint_cycles()                   |   41.8ms |   41.8ms |     +0% |
| update/ic0_is_controller()                 |    163ms |    151ms |     -8% |
| update/ic0_cycles_burn128()                |    162ms |    170ms |     +4% |

Average speedup of the local (new) changes: -10% (time)

Note: marked calls have no loop, so those results should not be compared with other calls
