System API Performance Report
=============================

Remote (old) commit:04f38ce0d branch:04f38ce0d
Local  (new) commit:16ea5de52 branch:andriy/run-803-fix-system-api-benchmarks

| API Type / System API Call                 | Old IPS  | New IPS  | Speedup | Round Time |
| ------------------------------------------ | -------- | -------- | ------- | ---------- |
| inspect/ic0_msg_method_name_size()         |    1.35G |    8.43G |   +524% |      0.83s |
| inspect/ic0_msg_method_name_copy()/1B      |     481M |    4.13G |   +758% |      1.69s |
| inspect/ic0_msg_method_name_copy()/30B     |     747M |    4.09G |   +447% |      1.71s |
| inspect/ic0_accept_message()*              |    6.28K |    2.49M | +39549% |          - |
| query/ic0_data_certificate_size()          |        - |    7.99G |       - |      0.88s |
| query/ic0_data_certificate_copy()/1B       |        - |    3.83G |       - |      1.83s |
| query/ic0_data_certificate_copy()/64B      |        - |    4.11G |       - |      1.70s |
| update/baseline/empty test*                |    8.72K |    10.3K |    +18% |          - |
| update/baseline/empty loop                 |       8G |    6.29G |    -22% |      1.11s |
| update/baseline/adds                       |    7.82G |    9.21G |    +17% |      0.76s |
| update/ic0_msg_caller_size()               |    1.33G |    7.91G |   +494% |      0.88s |
| update/ic0_msg_caller_copy()/1B            |     225M |    3.77G |  +1575% |      1.86s |
| update/ic0_msg_caller_copy()/10B           |     226M |    3.83G |  +1594% |      1.83s |
| update/ic0_msg_arg_data_size()             |    1.29G |    7.93G |   +514% |      0.88s |
| update/ic0_msg_arg_data_copy()/1B          |     444M |    3.90G |   +778% |      1.79s |
| update/ic0_msg_arg_data_copy()/1K          |        - |    10.2G |       - |      0.69s |
| update/ic0_msg_reply()*                    |    4.24K |    2.84M | +66881% |          - |
| update/ic0_msg_reply_data_append()/1B      |     499M |    3.86G |   +673% |      1.81s |
| update/ic0_msg_reply_data_append()/2B      |     513M |    3.86G |   +652% |      1.81s |
| update/ic0_msg_reject()*                   |    99.8K |    2.78M |  +2685% |          - |
| update/ic0_canister_self_size()            |    1.30G |    7.91G |   +508% |      0.88s |
| update/ic0_canister_self_copy()/1B         |     224M |    3.78G |  +1587% |      1.85s |
| update/ic0_canister_self_copy()/10B        |     224M |    3.79G |  +1591% |      1.85s |
| update/ic0_debug_print()/1B                |    5.45G |    1.93G |    -65% |      3.63s |
| update/ic0_debug_print()/1K                |        - |    18.6G |       - |      0.38s |
| update/ic0_call_new()                      |    10.8M |    5.52G | +51011% |      1.27s |
| update/call_new+ic0_call_data_append()/1B  |     118M |    4.63G |  +3823% |      1.51s |
| update/call_new+ic0_call_data_append()/1K  |        - |    6.77G |       - |      1.03s |
| update/call_new+ic0_call_on_cleanup()      |    81.3M |    5.94G |  +7206% |      1.18s |
| update/call_new+ic0_call_cycles_add()      |    77.9M |    4.90G |  +6190% |      1.43s |
| update/call_new+ic0_call_cycles_add128()   |    77.9M |    4.86G |  +6138% |      1.44s |
| update/call_new+ic0_call_perform()         |    10.8M |    4.45G | +41103% |      1.57s |
| update/ic0_stable_size()                   |    1.35G |    1.94G |    +43% |      3.61s |
| update/ic0_stable_grow()                   |     225M |     577M |   +156% |     12.13s |
| update/ic0_stable_read()/1B                |     399M |    1.28G |   +220% |      5.47s |
| update/ic0_stable_read()/1K                |        - |    25.7G |       - |      0.27s |
| update/ic0_stable_write()/1B               |     347M |     810M |   +133% |      8.64s |
| update/ic0_stable_write()/1K               |        - |    18.1G |       - |      0.39s |
| update/ic0_stable64_size()                 |    1.35G |    3.81G |   +182% |      1.84s |
| update/ic0_stable64_grow()                 |     225M |     564M |   +150% |     12.41s |
| update/ic0_stable64_read()/1B              |     351M |    1.19G |   +239% |      5.88s |
| update/ic0_stable64_read()/1K              |        - |    24.9G |       - |      0.28s |
| update/ic0_stable64_write()/1B             |     334M |     777M |   +132% |      9.01s |
| update/ic0_stable64_write()/1K             |        - |    17.7G |       - |      0.40s |
| update/ic0_time()                          |    1.34G |    7.98G |   +495% |      0.88s |
| update/ic0_global_timer_set()              |        - |    6.86G |       - |      1.02s |
| update/ic0_performance_counter()           |        - |    3.09G |       - |      2.27s |
| update/ic0_canister_cycle_balance()        |    1.30G |    7.46G |   +473% |      0.94s |
| update/ic0_canister_cycle_balance128()     |        - |    3.76G |       - |      1.86s |
| update/ic0_msg_cycles_available()          |     786M |    6.39G |   +712% |      1.10s |
| update/ic0_msg_cycles_available128()       |     206M |    3.52G |  +1608% |      1.99s |
| update/ic0_msg_cycles_accept()             |     514M |    5.09G |   +890% |      1.38s |
| update/ic0_msg_cycles_accept128()          |     177M |    2.96G |  +1572% |      2.36s |
| update/ic0_data_certificate_present()      |    2.12G |    8.02G |   +278% |      0.87s |
| update/ic0_certified_data_set()/1B         |     187M |    3.46G |  +1750% |      2.02s |
| update/ic0_certified_data_set()/32B        |     190M |    3.63G |  +1810% |      1.93s |
| update/ic0_canister_status()               |    1.29G |    8.15G |   +531% |      0.86s |
| update/ic0_mint_cycles()                   |     410M |     430M |     +4% |     16.28s |
| update/ic0_is_controller()                 |        - |    6.42G |       - |      1.09s |
| update/ic0_cycles_burn128()                |        - |     116M |       - |     60.34s |

Average speedup of the local (new) changes: +5502% (throughput)

| API Type / System API Call (1M Iterations) | Old Time | New Time | Speedup |
| ------------------------------------------ | -------- | -------- | ------- |
| inspect/ic0_msg_method_name_size()         |   8.11ms |   61.3ms |   +655% |
| inspect/ic0_msg_method_name_copy()/1B      |   70.6ms |    125ms |    +77% |
| inspect/ic0_msg_method_name_copy()/30B     |   70.8ms |    131ms |    +85% |
| inspect/ic0_accept_message()*              |    159us |    202µs |    +27% |
| query/ic0_data_certificate_size()          |        - |   64.6ms |       - |
| query/ic0_data_certificate_copy()/1B       |        - |    135ms |       - |
| query/ic0_data_certificate_copy()/64B      |        - |    141ms |       - |
| update/baseline/empty test*                |    229us |    193µs |    -16% |
| update/baseline/empty loop                 |   1.12ms |   1.74ms |    +55% |
| update/baseline/adds                       |   1.78ms |   1.73ms |     -3% |
| update/ic0_msg_caller_size()               |   8.22ms |   65.3ms |   +694% |
| update/ic0_msg_caller_copy()/1B            |   57.5ms |    137ms |   +138% |
| update/ic0_msg_caller_copy()/10B           |   57.3ms |    138ms |   +140% |
| update/ic0_msg_arg_data_size()             |   8.47ms |   65.1ms |   +668% |
| update/ic0_msg_arg_data_copy()/1B          |   76.4ms |    133ms |    +74% |
| update/ic0_msg_arg_data_copy()/1K          |        - |    150ms |       - |
| update/ic0_msg_reply()*                    |    235us |    177µs |    -25% |
| update/ic0_msg_reply_data_append()/1B      |     66ms |    134ms |   +103% |
| update/ic0_msg_reply_data_append()/2B      |   66.1ms |    134ms |   +102% |
| update/ic0_msg_reject()*                   |    230us |    181µs |    -22% |
| update/ic0_canister_self_size()            |   8.45ms |   65.3ms |   +672% |
| update/ic0_canister_self_copy()/1B         |   57.8ms |    137ms |   +137% |
| update/ic0_canister_self_copy()/10B        |     58ms |    139ms |   +139% |
| update/ic0_debug_print()/1B                |   20.7ms |   61.6ms |   +197% |
| update/ic0_debug_print()/1K                |        - |   61.3ms |       - |
| update/ic0_call_new()                      |    251ms |    280ms |    +11% |
| update/call_new+ic0_call_data_append()/1B  |    355ms |    444ms |    +25% |
| update/call_new+ic0_call_data_append()/1K  |        - |    454ms |       - |
| update/call_new+ic0_call_on_cleanup()      |    258ms |    346ms |    +34% |
| update/call_new+ic0_call_cycles_add()      |    265ms |    419ms |    +58% |
| update/call_new+ic0_call_cycles_add128()   |    269ms |    423ms |    +57% |
| update/call_new+ic0_call_perform()         |    1.83s |    1.47s |    -20% |
| update/ic0_stable_size()                   |   8.14ms |   8.74ms |     +7% |
| update/ic0_stable_grow()                   |   53.3ms |    204ms |   +282% |
| update/ic0_stable_read()/1B                |   85.1ms |   31.2ms |    -64% |
| update/ic0_stable_read()/1K                |        - |   41.3ms |       - |
| update/ic0_stable_write()/1B               |   97.7ms |   49.3ms |    -50% |
| update/ic0_stable_write()/1K               |        - |   58.4ms |       - |
| update/ic0_stable64_size()                 |   8.14ms |   4.46ms |    -46% |
| update/ic0_stable64_grow()                 |   53.3ms |    208ms |   +290% |
| update/ic0_stable64_read()/1B              |   96.7ms |   33.4ms |    -66% |
| update/ic0_stable64_read()/1K              |        - |   42.6ms |       - |
| update/ic0_stable64_write()/1B             |    101ms |   51.4ms |    -50% |
| update/ic0_stable64_write()/1K             |        - |   59.8ms |       - |
| update/ic0_time()                          |   8.18ms |   64.7ms |   +690% |
| update/ic0_global_timer_set()              |        - |   75.5ms |       - |
| update/ic0_performance_counter()           |        - |   70.4ms |       - |
| update/ic0_canister_cycle_balance()        |   8.43ms |   69.2ms |   +720% |
| update/ic0_canister_cycle_balance128()     |        - |    137ms |       - |
| update/ic0_msg_cycles_available()          |   13.9ms |   80.8ms |   +481% |
| update/ic0_msg_cycles_available128()       |   53.3ms |    146ms |   +173% |
| update/ic0_msg_cycles_accept()             |   23.3ms |    101ms |   +333% |
| update/ic0_msg_cycles_accept128()          |     73ms |    175ms |   +139% |
| update/ic0_data_certificate_present()      |   5.16ms |   64.4ms |  +1148% |
| update/ic0_certified_data_set()/1B         |   63.8ms |    149ms |   +133% |
| update/ic0_certified_data_set()/32B        |   63.1ms |    151ms |   +139% |
| update/ic0_canister_status()               |   8.48ms |   63.3ms |   +646% |
| update/ic0_mint_cycles()                   |   29.2ms |   41.8ms |    +43% |
| update/ic0_is_controller()                 |        - |    163ms |       - |
| update/ic0_cycles_burn128()                |        - |    162ms |       - |

Average speedup of the local (new) changes: +200% (time)

Note: marked calls have no loop, so those results should not be compared with other calls
