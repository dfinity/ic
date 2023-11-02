System API Performance Report
=============================

Remote (old) profile:            commit:04f38ce0
Local  (new) profile:            commit:178e1678

| API Type / System API Call                 | Old IPS  | New IPS  | Speedup | Round Time |
| ------------------------------------------ | -------- | -------- | ------- | ---------- |
| inspect/ic0_msg_method_name_size()         |    1.35G |     358M |    -74% |     19.55s |
| inspect/ic0_msg_method_name_copy()/1B      |     481M |     266M |    -45% |     26.32s |
| inspect/ic0_msg_method_name_copy()/30B     |     747M |     402M |    -47% |     17.41s |
| inspect/ic0_accept_message()*              |    6.28K |    5.72K |     -9% |          - |
| query/ic0_data_certificate_size()          |          |     348M |       - |     20.11s |
| query/ic0_data_certificate_copy()/1B       |          |     107M |       - |     65.42s |
| query/ic0_data_certificate_copy()/64B      |          |     568M |       - |     12.32s |
| update/baseline/empty test*                |          |        - |       - |
| update/baseline/empty loop                 |       8G |    6.14G |    -24% |      1.14s |
| update/baseline/adds                       |    7.82G |    6.68G |    -15% |      1.05s |
| update/ic0_msg_caller_size()               |    1.33G |     303M |    -78% |     23.10s |
| update/ic0_msg_caller_copy()/1B            |     225M |     105M |    -54% |     66.67s |
| update/ic0_msg_caller_copy()/10B           |     226M |     169M |    -26% |     41.42s |
| update/ic0_msg_arg_data_size()             |    1.29G |     348M |    -74% |     20.11s |
| update/ic0_msg_arg_data_copy()/1B          |     444M |     255M |    -43% |     27.45s |
| update/ic0_msg_arg_data_copy()/8K          |      53G |      28G |    -48% |      0.25s |
| update/ic0_msg_reply()*                    |    4.24K |    4.81K |    +13% |          - |
| update/ic0_msg_reply_data_append()/1B      |     499M |     254M |    -50% |     27.56s |
| update/ic0_msg_reply_data_append()/2B      |     513M |     264M |    -49% |     26.52s |
| update/ic0_msg_reject()*                   |    99.8K |     106K |     +6% |          - |
| update/ic0_canister_self_size()            |    1.30G |     320M |    -76% |     21.88s |
| update/ic0_canister_self_copy()/1B         |     224M |     102M |    -55% |     68.63s |
| update/ic0_canister_self_copy()/10B        |     224M |     168M |    -25% |     41.67s |
| update/ic0_debug_print()/1B                |    5.45G |    1.93G |    -65% |      3.63s |
| update/ic0_debug_print()/64B               |    8.48G |    3.02G |    -65% |      2.32s |
| update/ic0_call_new()                      |    10.8M |     164M |  +1418% |     42.68s |
| update/call_new+ic0_call_data_append()/1B  |     118M |     158M |    +33% |     44.30s |
| update/call_new+ic0_call_data_append()/8K  |    17.1G |    14.1G |    -18% |      0.50s |
| update/call_new+ic0_call_on_cleanup()      |    81.3M |     152M |    +86% |     46.05s |
| update/call_new+ic0_call_cycles_add()      |    77.9M |     119M |    +52% |     58.82s |
| update/call_new+ic0_call_cycles_add128()   |    77.9M |     123M |    +57% |     56.91s |
| update/call_new+ic0_call_perform()         |    10.8M |    30.9M |   +186% |    226.54s |
| update/ic0_stable_size()                   |    1.35G |    1.25G |     -8% |      5.60s |
| update/ic0_stable_grow()                   |     225M |    95.2M |    -58% |     73.53s |
| update/ic0_stable_read()/1B                |     399M |     957M |   +139% |      7.31s |
| update/ic0_stable_read()/8K                |    31.7G |      58G |    +82% |      0.12s |
| update/ic0_stable_write()/1B               |     347M |     610M |    +75% |     11.48s |
| update/ic0_stable_write()/8K               |      34G |      51G |    +50% |      0.14s |
| update/ic0_stable64_size()                 |    1.35G |    2.45G |    +81% |      2.86s |
| update/ic0_stable64_grow()                 |     225M |    94.8M |    -58% |     73.84s |
| update/ic0_stable64_read()/1B              |     351M |     942M |   +168% |      7.43s |
| update/ic0_stable64_read()/8K              |    30.7G |    57.2G |    +86% |      0.12s |
| update/ic0_stable64_write()/1B             |     334M |     589M |    +76% |     11.88s |
| update/ic0_stable64_write()/8K             |    33.9G |    50.5G |    +48% |      0.14s |
| update/ic0_time()                          |    1.34G |     334M |    -76% |     20.96s |
| update/ic0_global_timer_set()              |          |     317M |       - |     22.08s |
| update/ic0_performance_counter()           |          |    3.02G |       - |      2.32s |
| update/ic0_canister_cycle_balance()        |    1.30G |     307M |    -77% |     22.80s |
| update/ic0_canister_cycle_balance128()     |          |     110M |       - |     63.64s |
| update/ic0_msg_cycles_available()          |     786M |     250M |    -69% |     28.00s |
| update/ic0_msg_cycles_available128()       |     206M |    97.6M |    -53% |     71.72s |
| update/ic0_msg_cycles_accept()             |     514M |     165M |    -68% |     42.42s |
| update/ic0_msg_cycles_accept128()          |     177M |      91M |    -49% |     76.92s |
| update/ic0_data_certificate_present()      |    2.12G |     353M |    -84% |     19.83s |

Average speedup of the local (new) changes: +23% (throughput)

| API Type / System API Call (1M Iterations) | Old Time | New Time | Speedup |
| ------------------------------------------ | -------- | -------- | ------- |
| inspect/ic0_msg_method_name_size()         |   8.11ms |   30.6ms |   +277% |
| inspect/ic0_msg_method_name_copy()/1B      |   70.6ms |    127ms |    +79% |
| inspect/ic0_msg_method_name_copy()/30B     |   70.8ms |    131ms |    +85% |
| inspect/ic0_accept_message()*              |    159us |    174µs |     +9% |
| query/ic0_data_certificate_size()          |          |   31.5ms |       - |
| query/ic0_data_certificate_copy()/1B       |          |    130ms |       - |
| query/ic0_data_certificate_copy()/64B      |          |    135ms |       - |
| update/baseline/empty test*                |          |        - |       - |
| update/baseline/empty loop                 |   1.12ms |   1.46ms |    +30% |
| update/baseline/adds                       |   1.78ms |   2.09ms |    +17% |
| update/ic0_msg_caller_size()               |   8.22ms |   36.2ms |   +340% |
| update/ic0_msg_caller_copy()/1B            |   57.5ms |    132ms |   +129% |
| update/ic0_msg_caller_copy()/10B           |   57.3ms |    135ms |   +135% |
| update/ic0_msg_arg_data_size()             |   8.47ms |   31.5ms |   +271% |
| update/ic0_msg_arg_data_copy()/1B          |   76.4ms |    133ms |    +74% |
| update/ic0_msg_arg_data_copy()/8K          |    155ms |    292ms |    +88% |
| update/ic0_msg_reply()*                    |    235us |    207µs |    -12% |
| update/ic0_msg_reply_data_append()/1B      |     66ms |    129ms |    +95% |
| update/ic0_msg_reply_data_append()/2B      |   66.1ms |    128ms |    +93% |
| update/ic0_msg_reject()*                   |    230us |    215µs |     -7% |
| update/ic0_canister_self_size()            |   8.45ms |   34.3ms |   +305% |
| update/ic0_canister_self_copy()/1B         |   57.8ms |    136ms |   +135% |
| update/ic0_canister_self_copy()/10B        |     58ms |    136ms |   +134% |
| update/ic0_debug_print()/1B                |   20.7ms |   58.4ms |   +182% |
| update/ic0_debug_print()/64B               |   20.7ms |   58.2ms |   +181% |
| update/ic0_call_new()                      |    251ms |    280ms |    +11% |
| update/call_new+ic0_call_data_append()/1B  |    355ms |    441ms |    +24% |
| update/call_new+ic0_call_data_append()/8K  |    479ms |    583ms |    +21% |
| update/call_new+ic0_call_on_cleanup()      |    258ms |    321ms |    +24% |
| update/call_new+ic0_call_cycles_add()      |    265ms |    401ms |    +51% |
| update/call_new+ic0_call_cycles_add128()   |    269ms |    398ms |    +47% |
| update/call_new+ic0_call_perform()         |    1.83s |    1.54s |    -16% |
| update/ic0_stable_size()                   |   8.14ms |   8.77ms |     +7% |
| update/ic0_stable_grow()                   |   53.3ms |    125ms |   +134% |
| update/ic0_stable_read()/1B                |   85.1ms |   35.5ms |    -59% |
| update/ic0_stable_read()/8K                |    259ms |    141ms |    -46% |
| update/ic0_stable_write()/1B               |   97.7ms |   55.6ms |    -44% |
| update/ic0_stable_write()/8K               |    241ms |    161ms |    -34% |
| update/ic0_stable64_size()                 |   8.14ms |   4.48ms |    -45% |
| update/ic0_stable64_grow()                 |   53.3ms |    126ms |   +136% |
| update/ic0_stable64_read()/1B              |   96.7ms |     36ms |    -63% |
| update/ic0_stable64_read()/8K              |    267ms |    143ms |    -47% |
| update/ic0_stable64_write()/1B             |    101ms |   57.6ms |    -43% |
| update/ic0_stable64_write()/8K             |    242ms |    162ms |    -34% |
| update/ic0_time()                          |   8.18ms |   32.9ms |   +302% |
| update/ic0_global_timer_set()              |          |   37.7ms |       - |
| update/ic0_performance_counter()           |          |   70.1ms |       - |
| update/ic0_canister_cycle_balance()        |   8.43ms |   35.8ms |   +324% |
| update/ic0_canister_cycle_balance128()     |          |   99.2ms |       - |
| update/ic0_msg_cycles_available()          |   13.9ms |   43.9ms |   +215% |
| update/ic0_msg_cycles_available128()       |   53.3ms |    112ms |   +110% |
| update/ic0_msg_cycles_accept()             |   23.3ms |   72.4ms |   +210% |
| update/ic0_msg_cycles_accept128()          |     73ms |    142ms |    +94% |
| update/ic0_data_certificate_present()      |   5.16ms |   31.1ms |   +502% |

Average speedup of the local (new) changes: +94% (time)

Note: marked calls have no loop, so those results should not be compared vs other calls
