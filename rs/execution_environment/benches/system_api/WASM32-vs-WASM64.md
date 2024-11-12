System API Wasm32 vs. Wasm64 Performance Report
=============================

| API Type / System API Call                 | Wasm32 IPS  | Wasm64 IPS  | Speedup | Round Time |
| ------------------------------------------ | ----------- | ----------- | ------- | ---------- |
| inspect/ic0_msg_method_name_size()         |       7.38G |       7.03G |     -5% |      1.00s |
| inspect/ic0_msg_method_name_copy()/1B      |       2.01G |       2.02G |     +0% |      3.47s |
| inspect/ic0_msg_method_name_copy()/30B     |       2.11G |       2.09G |     -1% |      3.35s |
| inspect/ic0_accept_message()*              |       3.55M |       2.90M |    -19% |          - |
| query/ic0_data_certificate_size()          |       6.53G |       7.17G |     +9% |      0.98s |
| query/ic0_data_certificate_copy()/1B       |       2.01G |          2G |     -1% |      3.50s |
| query/ic0_data_certificate_copy()/64B      |       2.27G |       2.25G |     -1% |      3.11s |
| update/baseline/empty test*                |       17.4K |       16.8K |     -4% |          - |
| update/baseline/empty loop                 |       4.25G |       4.11G |     -4% |      1.70s |
| update/baseline/adds                       |       6.05G |       5.92G |     -3% |      1.18s |
| update/ic0_msg_caller_size()               |       7.25G |       7.02G |     -4% |      1.00s |
| update/ic0_msg_caller_copy()/1B            |       2.05G |       2.06G |     +0% |      3.40s |
| update/ic0_msg_caller_copy()/10B           |       2.07G |       2.06G |     -1% |      3.40s |
| update/ic0_msg_arg_data_size()             |       7.45G |       7.31G |     -2% |      0.96s |
| update/ic0_msg_arg_data_copy()/1B          |       2.05G |       2.08G |     +1% |      3.37s |
| update/ic0_msg_arg_data_copy()/1K          |       5.75G |       5.82G |     +1% |      1.20s |
| update/ic0_msg_reply()*                    |       3.55M |       2.88M |    -19% |          - |
| update/ic0_msg_reply_data_append()/1B      |       2.31G |       2.25G |     -3% |      3.11s |
| update/ic0_msg_reply_data_append()/2B      |       2.48G |       2.41G |     -3% |      2.90s |
| update/ic0_msg_reject()*                   |       3.52M |       2.85M |    -20% |          - |
| update/ic0_canister_self_size()            |       6.98G |       7.07G |     +1% |      0.99s |
| update/ic0_canister_self_copy()/1B         |       2.02G |       2.03G |     +0% |      3.45s |
| update/ic0_canister_self_copy()/10B        |       2.04G |       2.04G |     +0% |      3.43s |
| update/ic0_debug_print()/1B                |        586M |        585M |     -1% |     11.97s |
| update/ic0_debug_print()/1K                |        154G |        155G |     +0% |      0.05s |
| update/ic0_call_new()                      |       4.10G |       4.24G |     +3% |      1.65s |
| update/call_new+ic0_call_data_append()/1B  |       3.20G |       3.23G |     +0% |      2.17s |
| update/call_new+ic0_call_data_append()/1K  |       79.4G |       79.6G |     +0% |      0.09s |
| update/call_new+ic0_call_on_cleanup()      |       4.53G |       4.58G |     +1% |      1.53s |
| update/call_new+ic0_call_cycles_add128()   |       3.96G |       4.11G |     +3% |      1.70s |
| update/call_new+ic0_call_perform()         |       4.30G |       4.25G |     -2% |      1.65s |
| update/ic0_stable64_size()                 |       6.37G |       6.30G |     -2% |      1.11s |
| update/ic0_stable64_grow()                 |        650M |        624M |     -4% |     11.22s |
| update/ic0_stable64_read()/1B              |       1.51G |       1.62G |     +7% |      4.32s |
| update/ic0_stable64_read()/1K              |       28.3G |       28.9G |     +2% |      0.24s |
| update/ic0_stable64_write()/1B             |        708M |        766M |     +8% |      9.14s |
| update/ic0_stable64_write()/1K             |       14.9G |       16.2G |     +8% |      0.43s |
| update/ic0_time()                          |       7.32G |       6.98G |     -5% |      1.00s |
| update/ic0_global_timer_set()              |       7.32G |       7.16G |     -3% |      0.98s |
| update/ic0_performance_counter()           |       2.52G |       2.63G |     +4% |      2.66s |
| update/ic0_canister_cycle_balance128()     |       3.52G |       3.51G |     -1% |      1.99s |
| update/ic0_msg_cycles_available128()       |       3.63G |       3.06G |    -16% |      2.29s |
| update/ic0_msg_cycles_accept128()          |       3.16G |       3.05G |     -4% |      2.30s |
| update/ic0_data_certificate_present()      |       7.03G |       7.05G |     +0% |      0.99s |
| update/ic0_certified_data_set()/1B         |       1.91G |       1.98G |     +3% |      3.54s |
| update/ic0_certified_data_set()/32B        |          2G |       2.08G |     +4% |      3.37s |
| update/ic0_canister_status()               |       7.04G |       7.30G |     +3% |      0.96s |
| update/ic0_mint_cycles()                   |        481M |        494M |     +2% |     14.17s |
| update/ic0_is_controller()                 |       3.88G |       3.88G |     +0% |      1.80s |
| update/ic0_in_replicated_execution()       |       7.82G |       7.63G |     -3% |      0.92s |
| update/ic0_cycles_burn128()                |        112M |        113M |     +0% |     61.95s |

Average speedup of Wasm64: -1%(throughput)

| API Type / System API Call (1M Iterations) | Wasm32 Time | Wasm64 Time | Speedup |
| ------------------------------------------ | ----------- | ----------- | ------- |
| inspect/ic0_msg_method_name_size()         |      69.9ms |      73.4ms |     +5% |
| inspect/ic0_msg_method_name_copy()/1B      |       257ms |       256ms |     -1% |
| inspect/ic0_msg_method_name_copy()/30B     |       254ms |       256ms |     +0% |
| inspect/ic0_accept_message()*              |       142µs |       174µs |    +22% |
| query/ic0_data_certificate_size()          |      79.1ms |        72ms |     -9% |
| query/ic0_data_certificate_copy()/1B       |       257ms |       259ms |     +0% |
| query/ic0_data_certificate_copy()/64B      |       256ms |       258ms |     +0% |
| update/baseline/empty test*                |       171µs |       177µs |     +3% |
| update/baseline/empty loop                 |      2.58ms |      2.67ms |     +3% |
| update/baseline/adds                       |      2.64ms |      2.69ms |     +1% |
| update/ic0_msg_caller_size()               |      71.2ms |      73.6ms |     +3% |
| update/ic0_msg_caller_copy()/1B            |       252ms |       251ms |     -1% |
| update/ic0_msg_caller_copy()/10B           |       255ms |       251ms |     -2% |
| update/ic0_msg_arg_data_size()             |      69.3ms |      70.6ms |     +1% |
| update/ic0_msg_arg_data_copy()/1B          |       252ms |       249ms |     -2% |
| update/ic0_msg_arg_data_copy()/1K          |       267ms |       264ms |     -2% |
| update/ic0_msg_reply()*                    |       142µs |       175µs |    +23% |
| update/ic0_msg_reply_data_append()/1B      |       244ms |       251ms |     +2% |
| update/ic0_msg_reply_data_append()/2B      |       249ms |       255ms |     +2% |
| update/ic0_msg_reject()*                   |       144µs |       177µs |    +22% |
| update/ic0_canister_self_size()            |      73.9ms |        73ms |     -2% |
| update/ic0_canister_self_copy()/1B         |       256ms |       255ms |     -1% |
| update/ic0_canister_self_copy()/10B        |       258ms |       258ms |     +0% |
| update/ic0_debug_print()/1B                |       289ms |       290ms |     +0% |
| update/ic0_debug_print()/1K                |       305ms |       304ms |     -1% |
| update/ic0_call_new()                      |       378ms |       365ms |     -4% |
| update/call_new+ic0_call_data_append()/1B  |       658ms |       652ms |     -1% |
| update/call_new+ic0_call_data_append()/1K  |       670ms |       668ms |     -1% |
| update/call_new+ic0_call_on_cleanup()      |       454ms |       448ms |     -2% |
| update/call_new+ic0_call_cycles_add128()   |       519ms |       500ms |     -4% |
| update/call_new+ic0_call_perform()         |       1.52s |       1.54s |     +1% |
| update/ic0_stable64_size()                 |      2.66ms |      2.69ms |     +1% |
| update/ic0_stable64_grow()                 |       181ms |       189ms |     +4% |
| update/ic0_stable64_read()/1B              |      26.3ms |      24.5ms |     -7% |
| update/ic0_stable64_read()/1K              |      37.4ms |      36.6ms |     -3% |
| update/ic0_stable64_write()/1B             |      56.4ms |      52.1ms |     -8% |
| update/ic0_stable64_write()/1K             |      70.9ms |      65.5ms |     -8% |
| update/ic0_time()                          |      70.6ms |        74ms |     +4% |
| update/ic0_global_timer_set()              |      70.7ms |      72.2ms |     +2% |
| update/ic0_performance_counter()           |      86.3ms |      82.6ms |     -5% |
| update/ic0_canister_cycle_balance128()     |       146ms |       147ms |     +0% |
| update/ic0_msg_cycles_available128()       |       142ms |       168ms |    +18% |
| update/ic0_msg_cycles_accept128()          |       164ms |       169ms |     +3% |
| update/ic0_data_certificate_present()      |      73.4ms |      73.2ms |     -1% |
| update/ic0_certified_data_set()/1B         |       271ms |       261ms |     -4% |
| update/ic0_certified_data_set()/32B        |       273ms |       263ms |     -4% |
| update/ic0_canister_status()               |      73.3ms |      70.7ms |     -4% |
| update/ic0_mint_cycles()                   |      37.3ms |      36.4ms |     -3% |
| update/ic0_is_controller()                 |       269ms |       269ms |     +0% |
| update/ic0_in_replicated_execution()       |        66ms |      67.7ms |     +2% |
| update/ic0_cycles_burn128()                |       168ms |       166ms |     -2% |

Average speedup of Wasm64: +0%(time)

Note: marked calls have no loop, so those results should not be compared with other calls
