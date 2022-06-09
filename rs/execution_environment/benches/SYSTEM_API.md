System API Performance Report
=============================

Remote (old) profile:release-lto commit:04f38ce0 branch:master
Local  (new) profile:release-lto commit:04f38ce0 branch:master

| API Type / System API Call                 | Old IPS  | New IPS  | Speedup | Round Time |
| ------------------------------------------ | -------- | -------- | ------- | ---------- |
| callback/ic0_msg_reject_code()             |    1.20G |    1.33G |    +10% |      5.26s |
| callback/ic0_msg_reject_msg_size()         |    1.33G |    1.33G |     +0% |      5.26s |
| callback/ic0_msg_reject_msg_copy()/1B      |     393M |     343M |    -13% |     20.41s |
| callback/ic0_msg_reject_msg_copy()/10B     |     495M |     427M |    -14% |     16.39s |
| callback/ic0_msg_cycles_refunded()         |    1.29G |    1.20G |     -7% |      5.83s |
| callback/ic0_msg_cycles_refunded128()      |     227M |     184M |    -19% |     38.04s |
| inspect/ic0_msg_method_name_size()         |    1.35G |    1.81G |    +34% |      3.87s |
| inspect/ic0_msg_method_name_copy()/1B      |     481M |     402M |    -17% |     17.41s |
| inspect/ic0_msg_method_name_copy()/30B     |     747M |     630M |    -16% |     11.11s |
| inspect/ic0_accept_message()*              |    6.28K |    4.41K |    -30% |          - |
| inspect/ic0_data_certificate_size()        |    1.30G |    1.23G |     -6% |      5.69s |
| inspect/ic0_data_certificate_copy()/1B     |     232M |     199M |    -15% |     35.18s |
| inspect/ic0_data_certificate_copy()/64B    |     231M |     199M |    -14% |     35.18s |
| update/baseline/empty test*                |    8.72K |    6.78K |    -23% |          - |
| update/baseline/empty loop                 |       8G |    7.64G |     -5% |      0.92s |
| update/baseline/adds                       |    7.82G |    7.41G |     -6% |      0.94s |
| update/ic0_msg_caller_size()               |    1.33G |    1.23G |     -8% |      5.69s |
| update/ic0_msg_caller_copy()/1B            |     225M |     168M |    -26% |     41.67s |
| update/ic0_msg_caller_copy()/10B           |     226M |     183M |    -20% |     38.25s |
| update/ic0_msg_arg_data_size()             |    1.29G |    1.29G |     +0% |      5.43s |
| update/ic0_msg_arg_data_copy()/1B          |     444M |     380M |    -15% |     18.42s |
| update/ic0_msg_arg_data_copy()/8K          |      53G |    48.6G |     -9% |      0.14s |
| update/ic0_msg_reply()*                    |    4.24K |    3.36K |    -21% |          - |
| update/ic0_msg_reply_data_append()/1B      |     499M |     370M |    -26% |     18.92s |
| update/ic0_msg_reply_data_append()/2B      |     513M |     381M |    -26% |     18.37s |
| update/ic0_msg_reject()*                   |    99.8K |      80K |    -20% |          - |
| update/ic0_canister_self_size()            |    1.30G |    1.85G |    +42% |      3.78s |
| update/ic0_canister_self_copy()/1B         |     224M |     193M |    -14% |     36.27s |
| update/ic0_canister_self_copy()/10B        |     224M |     191M |    -15% |     36.65s |
| update/ic0_controller_size()               |    1.29G |    1.80G |    +39% |      3.89s |
| update/ic0_controller_copy()/1B            |     224M |     193M |    -14% |     36.27s |
| update/ic0_controller_copy()/10B           |     223M |     192M |    -14% |     36.46s |
| update/ic0_debug_print()/1B                |    5.45G |    3.27G |    -40% |      2.14s |
| update/ic0_debug_print()/64B               |    8.48G |    5.13G |    -40% |      1.36s |
| update/ic0_call_simple()                   |    92.6M |    91.3M |     -2% |     76.67s |
| update/ic0_call_new()                      |    10.8M |    73.1M |   +576% |     95.76s |
| update/call_new+ic0_call_data_append()/1B  |     118M |     113M |     -5% |     61.95s |
| update/call_new+ic0_call_data_append()/8K  |    17.1G |    16.3G |     -5% |      0.43s |
| update/call_new+ic0_call_on_cleanup()      |    81.3M |    79.8M |     -2% |     87.72s |
| update/call_new+ic0_call_cycles_add()      |    77.9M |    73.7M |     -6% |     94.98s |
| update/call_new+ic0_call_cycles_add128()   |    77.9M |      77M |     -2% |     90.91s |
| update/call_new+ic0_call_perform()         |    10.8M |    12.1M |    +12% |    578.51s |
| update/ic0_stable_size()                   |    1.35G |    1.81G |    +34% |      3.87s |
| update/ic0_stable_grow()                   |     225M |     175M |    -23% |     40.00s |
| update/ic0_stable_read()/1B                |     399M |     392M |     -2% |     17.86s |
| update/ic0_stable_read()/8K                |    31.7G |      49G |    +54% |      0.14s |
| update/ic0_stable_write()/1B               |     347M |     297M |    -15% |     23.57s |
| update/ic0_stable_write()/8K               |      34G |    33.1G |     -3% |      0.21s |
| update/ic0_stable64_size()                 |    1.35G |    1.84G |    +36% |      3.80s |
| update/ic0_stable64_grow()                 |     225M |     186M |    -18% |     37.63s |
| update/ic0_stable64_read()/1B              |     351M |     411M |    +17% |     17.03s |
| update/ic0_stable64_read()/8K              |    30.7G |    48.6G |    +58% |      0.14s |
| update/ic0_stable64_write()/1B             |     334M |     303M |    -10% |     23.10s |
| update/ic0_stable64_write()/8K             |    33.9G |    33.5G |     -2% |      0.21s |
| update/ic0_time()                          |    1.34G |    1.28G |     -5% |      5.47s |
| update/ic0_performance_counter()           |          |    4.56G |       - |      1.54s |
| update/ic0_canister_cycle_balance()        |    1.30G |    1.26G |     -4% |      5.56s |
| update/ic0_canister_cycles_balance128()    |     224M |     190M |    -16% |     36.84s |
| update/ic0_msg_cycles_available()          |     786M |     777M |     -2% |      9.01s |
| update/ic0_msg_cycles_available128()       |     206M |     175M |    -16% |     40.00s |
| update/ic0_msg_cycles_accept()             |     514M |     486M |     -6% |     14.40s |
| update/ic0_msg_cycles_accept128()          |     177M |     169M |     -5% |     41.42s |
| update/ic0_data_certificate_present()      |    2.12G |    1.80G |    -16% |      3.89s |
| update/ic0_certified_data_set()/1B         |     187M |     158M |    -16% |     44.30s |
| update/ic0_certified_data_set()/32B        |     190M |     157M |    -18% |     44.59s |
| update/ic0_canister_status()               |    1.29G |    1.09G |    -16% |      6.42s |
| update/ic0_mint_cycles()                   |     410M |     501M |    +22% |     13.97s |

Average speedup of the local (new) changes: +3% (throughput)

| API Type / System API Call (1M Iterations) | Old Time | New Time | Speedup |
| ------------------------------------------ | -------- | -------- | ------- |
| callback/ic0_msg_reject_code()             |   9.09ms |   8.25ms |    -10% |
| callback/ic0_msg_reject_msg_size()         |   8.21ms |   8.25ms |     +0% |
| callback/ic0_msg_reject_msg_copy()/1B      |   86.4ms |     99ms |    +14% |
| callback/ic0_msg_reject_msg_copy()/10B     |   86.8ms |    100ms |    +15% |
| callback/ic0_msg_cycles_refunded()         |   8.46ms |   9.14ms |     +8% |
| callback/ic0_msg_cycles_refunded128()      |   48.3ms |   59.7ms |    +23% |
| inspect/ic0_msg_method_name_size()         |   8.11ms |   6.05ms |    -26% |
| inspect/ic0_msg_method_name_copy()/1B      |   70.6ms |   84.4ms |    +19% |
| inspect/ic0_msg_method_name_copy()/30B     |   70.8ms |     84ms |    +18% |
| inspect/ic0_accept_message()*              |    159us |    226us |    +42% |
| inspect/ic0_data_certificate_size()        |   8.40ms |   8.88ms |     +5% |
| inspect/ic0_data_certificate_copy()/1B     |   55.9ms |   65.2ms |    +16% |
| inspect/ic0_data_certificate_copy()/64B    |     56ms |   65.3ms |    +16% |
| update/baseline/empty test*                |    229us |    294us |    +28% |
| update/baseline/empty loop                 |   1.12ms |   1.17ms |     +4% |
| update/baseline/adds                       |   1.78ms |   1.88ms |     +5% |
| update/ic0_msg_caller_size()               |   8.22ms |   8.90ms |     +8% |
| update/ic0_msg_caller_copy()/1B            |   57.5ms |   77.1ms |    +34% |
| update/ic0_msg_caller_copy()/10B           |   57.3ms |   70.9ms |    +23% |
| update/ic0_msg_arg_data_size()             |   8.47ms |   8.49ms |     +0% |
| update/ic0_msg_arg_data_copy()/1B          |   76.4ms |   89.4ms |    +17% |
| update/ic0_msg_arg_data_copy()/8K          |    155ms |    168ms |     +8% |
| update/ic0_msg_reply()*                    |    235us |    297us |    +26% |
| update/ic0_msg_reply_data_append()/1B      |     66ms |   89.1ms |    +35% |
| update/ic0_msg_reply_data_append()/2B      |   66.1ms |     89ms |    +34% |
| update/ic0_msg_reject()*                   |    230us |    287us |    +24% |
| update/ic0_canister_self_size()            |   8.45ms |   5.91ms |    -31% |
| update/ic0_canister_self_copy()/1B         |   57.8ms |   67.3ms |    +16% |
| update/ic0_canister_self_copy()/10B        |     58ms |   67.7ms |    +16% |
| update/ic0_controller_size()               |   8.47ms |   6.09ms |    -29% |
| update/ic0_controller_copy()/1B            |   57.9ms |   67.1ms |    +15% |
| update/ic0_controller_copy()/10B           |     58ms |   67.4ms |    +16% |
| update/ic0_debug_print()/1B                |   20.7ms |   34.4ms |    +66% |
| update/ic0_debug_print()/64B               |   20.7ms |   34.2ms |    +65% |
| update/ic0_call_simple()                   |    1.52s |    1.54s |     +1% |
| update/ic0_call_new()                      |    251ms |    246ms |     -2% |
| update/call_new+ic0_call_data_append()/1B  |    355ms |    371ms |     +4% |
| update/call_new+ic0_call_data_append()/8K  |    479ms |    502ms |     +4% |
| update/call_new+ic0_call_on_cleanup()      |    258ms |    262ms |     +1% |
| update/call_new+ic0_call_cycles_add()      |    265ms |    271ms |     +2% |
| update/call_new+ic0_call_cycles_add128()   |    269ms |    272ms |     +1% |
| update/call_new+ic0_call_perform()         |    1.83s |    1.63s |    -11% |
| update/ic0_stable_size()                   |   8.14ms |   6.06ms |    -26% |
| update/ic0_stable_grow()                   |   53.3ms |   68.3ms |    +28% |
| update/ic0_stable_read()/1B                |   85.1ms |   86.6ms |     +1% |
| update/ic0_stable_read()/8K                |    259ms |    167ms |    -36% |
| update/ic0_stable_write()/1B               |   97.7ms |    114ms |    +16% |
| update/ic0_stable_write()/8K               |    241ms |    247ms |     +2% |
| update/ic0_stable64_size()                 |   8.14ms |   5.94ms |    -28% |
| update/ic0_stable64_grow()                 |   53.3ms |   64.4ms |    +20% |
| update/ic0_stable64_read()/1B              |   96.7ms |   82.6ms |    -15% |
| update/ic0_stable64_read()/8K              |    267ms |    169ms |    -37% |
| update/ic0_stable64_write()/1B             |    101ms |    112ms |    +10% |
| update/ic0_stable64_write()/8K             |    242ms |    245ms |     +1% |
| update/ic0_time()                          |   8.18ms |   8.57ms |     +4% |
| update/ic0_performance_counter()           |          |   46.4ms |       - |
| update/ic0_canister_cycle_balance()        |   8.43ms |   8.71ms |     +3% |
| update/ic0_canister_cycles_balance128()    |   48.9ms |   57.6ms |    +17% |
| update/ic0_msg_cycles_available()          |   13.9ms |   14.1ms |     +1% |
| update/ic0_msg_cycles_available128()       |   53.3ms |   62.7ms |    +17% |
| update/ic0_msg_cycles_accept()             |   23.3ms |   24.6ms |     +5% |
| update/ic0_msg_cycles_accept128()          |     73ms |   76.6ms |     +4% |
| update/ic0_data_certificate_present()      |   5.16ms |   6.11ms |    +18% |
| update/ic0_certified_data_set()/1B         |   63.8ms |   75.7ms |    +18% |
| update/ic0_certified_data_set()/32B        |   63.1ms |     76ms |    +20% |
| update/ic0_canister_status()               |   8.48ms |     10ms |    +17% |
| update/ic0_mint_cycles()                   |   29.2ms |   23.9ms |    -19% |

Average speedup of the local (new) changes: +8% (time)

Note: marked calls have no loop, so those results should not be compared vs other calls
