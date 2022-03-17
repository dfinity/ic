System API Performance Report
=============================

Local  profile: release-lto commit: 7530321b andriy/exc-770-rebased
Remote profile: release     commit: 07114506 master

| API Type / System API Call                 | Remote, IPS | Local, IPS  | Speedup |
| ------------------------------------------ | ----------- | ----------- | ------- |
| callback/ic0_msg_reject_code()             |           - |       1.29G |       - |
| callback/ic0_msg_reject_msg_size()         |           - |       1.34G |       - |
| callback/ic0_msg_reject_msg_copy()/1B      |           - |        173M |       - |
| callback/ic0_msg_reject_msg_copy()/10B     |           - |        282M |       - |
| callback/ic0_msg_cycles_refunded()         |           - |       1.29G |       - |
| callback/ic0_msg_cycles_refunded128()      |           - |        228M |       - |
| inspect/ic0_msg_method_name_size()         |           - |       1.35G |       - |
| inspect/ic0_msg_method_name_copy()/1B      |           - |        480M |       - |
| inspect/ic0_msg_method_name_copy()/30B     |           - |        745M |       - |
| inspect/ic0_accept_message()*              |           - |       6.44K |       - |
| inspect/ic0_data_certificate_size()        |           - |       1.35G |       - |
| inspect/ic0_data_certificate_copy()/1B     |           - |        231M |       - |
| inspect/ic0_data_certificate_copy()/64B    |           - |        232M |       - |
| update/baseline/empty test*                |       7.84K |       8.31K |     +5% |
| update/baseline/empty loop                 |       7.93G |       7.91G |     -1% |
| update/baseline/adds                       |       7.88G |       7.87G |     -1% |
| update/ic0_msg_caller_size()               |       1.13G |       1.34G |    +18% |
| update/ic0_msg_caller_copy()/1B            |        204M |        224M |     +9% |
| update/ic0_msg_caller_copy()/10B           |           - |        225M |       - |
| update/ic0_msg_arg_data_size()             |       1.28G |       1.29G |     +0% |
| update/ic0_msg_arg_data_copy()/1B          |        374M |        453M |    +21% |
| update/ic0_msg_arg_data_copy()/8K          |       33.5G |       53.5G |    +59% |
| update/ic0_msg_reply()*                    |       4.16K |       4.47K |     +7% |
| update/ic0_msg_reply_data_append()/1B      |        358M |        504M |    +40% |
| update/ic0_msg_reply_data_append()/2B      |        368M |        511M |    +38% |
| update/ic0_msg_reject()*                   |       10.8K |       12.4K |    +14% |
| update/ic0_canister_self_size()            |          1G |       1.21G |    +21% |
| update/ic0_canister_self_copy()/1B         |        204M |        224M |     +9% |
| update/ic0_canister_self_copy()/10B        |        200M |        224M |    +12% |
| update/ic0_controller_size()               |       1.09G |       1.29G |    +18% |
| update/ic0_controller_copy()/1B            |        202M |        224M |    +10% |
| update/ic0_controller_copy()/10B           |        196M |        223M |    +13% |
| update/ic0_debug_print()/1B                |           - |       5.45G |       - |
| update/ic0_debug_print()/64B               |           - |       8.49G |       - |
| update/ic0_call_simple()                   |           - |       77.6M |       - |
| update/ic0_call_new()                      |           - |       10.7M |       - |
| update/call_new+ic0_call_data_append()/1B  |           - |       62.9M |       - |
| update/call_new+ic0_call_data_append()/8K  |           - |       17.2G |       - |
| update/call_new+ic0_call_on_cleanup()      |           - |       80.8M |       - |
| update/call_new+ic0_call_cycles_add()      |           - |       76.8M |       - |
| update/call_new+ic0_call_cycles_add128()   |           - |       76.8M |       - |
| update/call_new+ic0_call_perform()         |           - |       10.7M |       - |
| update/ic0_stable_size()                   |       1.38G |       1.39G |     +0% |
| update/ic0_stable_grow()                   |        211M |        225M |     +6% |
| update/ic0_stable_read()/1B                |        300M |        398M |    +32% |
| update/ic0_stable_read()/8K                |       28.4G |       31.6G |    +11% |
| update/ic0_stable_write()/1B               |        274M |        340M |    +24% |
| update/ic0_stable_write()/8K               |       23.5G |       34.1G |    +45% |
| update/ic0_stable64_size()                 |       1.38G |       1.39G |     +0% |
| update/ic0_stable64_grow()                 |        211M |        225M |     +6% |
| update/ic0_stable64_read()/1B              |        295M |        363M |    +23% |
| update/ic0_stable64_read()/8K              |       28.2G |       30.7G |     +8% |
| update/ic0_stable64_write()/1B             |        274M |        340M |    +24% |
| update/ic0_stable64_write()/8K             |       23.4G |       33.6G |    +43% |
| update/ic0_time()                          |       1.09G |       1.25G |    +14% |
| update/ic0_canister_cycle_balance()        |        903M |       1.29G |    +42% |
| update/ic0_canister_cycles_balance128()    |           - |        226M |       - |
| update/ic0_msg_cycles_available()          |        623M |        802M |    +28% |
| update/ic0_msg_cycles_available128()       |        168M |        208M |    +23% |
| update/ic0_msg_cycles_accept()             |        313M |        515M |    +64% |
| update/ic0_msg_cycles_accept128()          |           - |        207M |       - |
| update/ic0_data_certificate_present()      |       1.44G |       2.01G |    +39% |
| update/ic0_certified_data_set()/1B         |        141M |        194M |    +37% |
| update/ic0_certified_data_set()/32B        |        157M |        192M |    +22% |
| update/ic0_canister_status()               |       1.29G |       1.39G |     +7% |
| update/ic0_mint_cycles()                   |           - |        411M |       - |

Average speedup of the local changes: +20% (throughput)

| API Type / System API Call                 | Remote Time | Local Time  | Speedup |
| ------------------------------------------ | ----------- | ----------- | ------- |
| callback/ic0_msg_reject_code()             |           - |      8.46ms |       - |
| callback/ic0_msg_reject_msg_size()         |           - |      8.18ms |       - |
| callback/ic0_msg_reject_msg_copy()/1B      |           - |      80.8ms |       - |
| callback/ic0_msg_reject_msg_copy()/10B     |           - |      81.2ms |       - |
| callback/ic0_msg_cycles_refunded()         |           - |      8.50ms |       - |
| callback/ic0_msg_cycles_refunded128()      |           - |      48.1ms |       - |
| inspect/ic0_msg_method_name_size()         |           - |      8.11ms |       - |
| inspect/ic0_msg_method_name_copy()/1B      |           - |      70.8ms |       - |
| inspect/ic0_msg_method_name_copy()/30B     |           - |        71ms |       - |
| inspect/ic0_accept_message()*              |           - |       155us |       - |
| inspect/ic0_data_certificate_size()        |           - |      8.14ms |       - |
| inspect/ic0_data_certificate_copy()/1B     |           - |      56.1ms |       - |
| inspect/ic0_data_certificate_copy()/64B    |           - |      55.9ms |       - |
| update/baseline/empty test*                |       255us |       240us |     -6% |
| update/baseline/empty loop                 |      1.13ms |      1.13ms |     +0% |
| update/baseline/adds                       |      1.77ms |      1.77ms |     +0% |
| update/ic0_msg_caller_size()               |      9.73ms |      8.18ms |    -16% |
| update/ic0_msg_caller_copy()/1B            |      63.4ms |      57.8ms |     -9% |
| update/ic0_msg_caller_copy()/10B           |           - |      57.5ms |       - |
| update/ic0_msg_arg_data_size()             |      8.54ms |      8.50ms |     -1% |
| update/ic0_msg_arg_data_copy()/1B          |      90.8ms |      74.9ms |    -18% |
| update/ic0_msg_arg_data_copy()/8K          |       244ms |       153ms |    -38% |
| update/ic0_msg_reply()*                    |       239us |       223us |     -7% |
| update/ic0_msg_reply_data_append()/1B      |      92.1ms |      65.4ms |    -29% |
| update/ic0_msg_reply_data_append()/2B      |      92.1ms |      66.4ms |    -28% |
| update/ic0_msg_reject()*                   |       276us |       240us |    -14% |
| update/ic0_canister_self_size()            |      10.9ms |      9.07ms |    -17% |
| update/ic0_canister_self_copy()/1B         |      63.5ms |      57.9ms |     -9% |
| update/ic0_canister_self_copy()/10B        |      64.9ms |      57.8ms |    -11% |
| update/ic0_controller_size()               |        10ms |      8.46ms |    -16% |
| update/ic0_controller_copy()/1B            |      64.1ms |      57.9ms |    -10% |
| update/ic0_controller_copy()/10B           |      66.2ms |        58ms |    -13% |
| update/ic0_debug_print()/1B                |           - |      20.7ms |       - |
| update/ic0_debug_print()/64B               |           - |      20.7ms |       - |
| update/ic0_call_simple()                   |           - |       1.55s |       - |
| update/ic0_call_new()                      |           - |       252ms |       - |
| update/call_new+ic0_call_data_append()/1B  |           - |       349ms |       - |
| update/call_new+ic0_call_data_append()/8K  |           - |       476ms |       - |
| update/call_new+ic0_call_on_cleanup()      |           - |       259ms |       - |
| update/call_new+ic0_call_cycles_add()      |           - |       269ms |       - |
| update/call_new+ic0_call_cycles_add128()   |           - |       273ms |       - |
| update/call_new+ic0_call_perform()         |           - |       1.85s |       - |
| update/ic0_stable_size()                   |      7.93ms |      7.88ms |     -1% |
| update/ic0_stable_grow()                   |      56.7ms |      53.2ms |     -7% |
| update/ic0_stable_read()/1B                |       113ms |      85.3ms |    -25% |
| update/ic0_stable_read()/8K                |       289ms |       260ms |    -11% |
| update/ic0_stable_write()/1B               |       123ms |      99.8ms |    -19% |
| update/ic0_stable_write()/8K               |       349ms |       240ms |    -32% |
| update/ic0_stable64_size()                 |      7.93ms |      7.88ms |     -1% |
| update/ic0_stable64_grow()                 |      56.7ms |      53.2ms |     -7% |
| update/ic0_stable64_read()/1B              |       114ms |      93.4ms |    -19% |
| update/ic0_stable64_read()/8K              |       290ms |       267ms |     -8% |
| update/ic0_stable64_write()/1B             |       123ms |      99.8ms |    -19% |
| update/ic0_stable64_write()/8K             |       350ms |       244ms |    -31% |
| update/ic0_time()                          |       239us |      8.77ms |   -100% |
| update/ic0_canister_cycle_balance()        |      12.1ms |      8.46ms |    -31% |
| update/ic0_canister_cycles_balance128()    |           - |      48.5ms |       - |
| update/ic0_msg_cycles_available()          |      17.6ms |      13.7ms |    -23% |
| update/ic0_msg_cycles_available128()       |      65.1ms |      52.8ms |    -19% |
| update/ic0_msg_cycles_accept()             |      38.2ms |      23.2ms |    -40% |
| update/ic0_msg_cycles_accept128()          |           - |      62.5ms |       - |
| update/ic0_data_certificate_present()      |      7.60ms |      5.45ms |    -29% |
| update/ic0_certified_data_set()/1B         |      84.5ms |      61.7ms |    -27% |
| update/ic0_certified_data_set()/32B        |      76.2ms |      62.2ms |    -19% |
| update/ic0_canister_status()               |      8.48ms |      7.87ms |     -8% |
| update/ic0_mint_cycles()                   |           - |      29.1ms |       - |

Average speedup of the local changes: -18% (time)

Note: marked calls have no loop, so those results should not be compared vs other calls
