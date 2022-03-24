System API Performance Report
=============================

Local  profile: release-lto commit: 591e728e andriy/exc-771-lto-performance
Remote profile: release-lto commit: e27405a7 andriy/exc-770-execute-query

| API Type / System API Call                 | Remote, IPS | Local, IPS  | Speedup |
| ------------------------------------------ | ----------- | ----------- | ------- |
| callback/ic0_msg_reject_code()             |       1.29G |       1.20G |     -7% |
| callback/ic0_msg_reject_msg_size()         |       1.34G |       1.33G |     -1% |
| callback/ic0_msg_reject_msg_copy()/1B      |        168M |        393M |   +133% |
| callback/ic0_msg_reject_msg_copy()/10B     |        276M |        495M |    +79% |
| callback/ic0_msg_cycles_refunded()         |       1.29G |       1.29G |     +0% |
| callback/ic0_msg_cycles_refunded128()      |        228M |        227M |     -1% |
| inspect/ic0_msg_method_name_size()         |       1.35G |       1.35G |     +0% |
| inspect/ic0_msg_method_name_copy()/1B      |        480M |        481M |     +0% |
| inspect/ic0_msg_method_name_copy()/30B     |        746M |        747M |     +0% |
| inspect/ic0_accept_message()*              |       6.19K |       6.28K |     +1% |
| inspect/ic0_data_certificate_size()        |       1.35G |       1.30G |     -4% |
| inspect/ic0_data_certificate_copy()/1B     |        231M |        232M |     +0% |
| inspect/ic0_data_certificate_copy()/64B    |        231M |        231M |     +0% |
| update/baseline/empty test*                |       9.02K |       8.72K |     -4% |
| update/baseline/empty loop                 |       7.85G |          8G |     +1% |
| update/baseline/adds                       |       7.83G |       7.82G |     -1% |
| update/ic0_msg_caller_size()               |       1.33G |       1.33G |     +0% |
| update/ic0_msg_caller_copy()/1B            |        229M |        225M |     -2% |
| update/ic0_msg_caller_copy()/10B           |        227M |        226M |     -1% |
| update/ic0_msg_arg_data_size()             |       1.29G |       1.29G |     +0% |
| update/ic0_msg_arg_data_copy()/1B          |        452M |        444M |     -2% |
| update/ic0_msg_arg_data_copy()/8K          |       53.6G |         53G |     -2% |
| update/ic0_msg_reply()*                    |       4.21K |       4.24K |     +0% |
| update/ic0_msg_reply_data_append()/1B      |        504M |        499M |     -1% |
| update/ic0_msg_reply_data_append()/2B      |        510M |        513M |     +0% |
| update/ic0_msg_reject()*                   |       13.3K |       99.8K |   +650% |
| update/ic0_canister_self_size()            |       1.21G |       1.30G |     +7% |
| update/ic0_canister_self_copy()/1B         |        225M |        224M |     -1% |
| update/ic0_canister_self_copy()/10B        |        223M |        224M |     +0% |
| update/ic0_controller_size()               |       1.29G |       1.29G |     +0% |
| update/ic0_controller_copy()/1B            |        224M |        224M |     +0% |
| update/ic0_controller_copy()/10B           |        222M |        223M |     +0% |
| update/ic0_debug_print()/1B                |       5.46G |       5.45G |     -1% |
| update/ic0_debug_print()/64B               |       8.50G |       8.48G |     -1% |
| update/ic0_call_simple()                   |       80.2M |       92.6M |    +15% |
| update/ic0_call_new()                      |       10.9M |       10.8M |     -1% |
| update/call_new+ic0_call_data_append()/1B  |       62.8M |        118M |    +87% |
| update/call_new+ic0_call_data_append()/8K  |       17.2G |       17.1G |     -1% |
| update/call_new+ic0_call_on_cleanup()      |       80.8M |       81.3M |     +0% |
| update/call_new+ic0_call_cycles_add()      |       76.8M |       77.9M |     +1% |
| update/call_new+ic0_call_cycles_add128()   |       76.8M |       77.9M |     +1% |
| update/call_new+ic0_call_perform()         |       10.9M |       10.8M |     -1% |
| update/ic0_stable_size()                   |       1.39G |       1.35G |     -3% |
| update/ic0_stable_grow()                   |        225M |        225M |     +0% |
| update/ic0_stable_read()/1B                |        397M |        399M |     +0% |
| update/ic0_stable_read()/8K                |       31.6G |       31.7G |     +0% |
| update/ic0_stable_write()/1B               |        340M |        347M |     +2% |
| update/ic0_stable_write()/8K               |       33.6G |         34G |     +1% |
| update/ic0_stable64_size()                 |       1.39G |       1.35G |     -3% |
| update/ic0_stable64_grow()                 |        225M |        225M |     +0% |
| update/ic0_stable64_read()/1B              |        363M |        351M |     -4% |
| update/ic0_stable64_read()/8K              |       30.7G |       30.7G |     +0% |
| update/ic0_stable64_write()/1B             |        340M |        334M |     -2% |
| update/ic0_stable64_write()/8K             |       33.6G |       33.9G |     +0% |
| update/ic0_time()                          |       1.25G |       1.34G |     +7% |
| update/ic0_canister_cycle_balance()        |       1.29G |       1.30G |     +0% |
| update/ic0_canister_cycles_balance128()    |        226M |        224M |     -1% |
| update/ic0_msg_cycles_available()          |        801M |        786M |     -2% |
| update/ic0_msg_cycles_available128()       |        208M |        206M |     -1% |
| update/ic0_msg_cycles_accept()             |        513M |        514M |     +0% |
| update/ic0_msg_cycles_accept128()          |        207M |        177M |    -15% |
| update/ic0_data_certificate_present()      |       2.01G |       2.12G |     +5% |
| update/ic0_certified_data_set()/1B         |        194M |        187M |     -4% |
| update/ic0_certified_data_set()/32B        |        192M |        190M |     -2% |
| update/ic0_canister_status()               |       1.38G |       1.29G |     -7% |
| update/ic0_mint_cycles()                   |        412M |        410M |     -1% |

Average speedup of the local changes: +13% (throughput)

| API Type / System API Call                 | Remote Time | Local Time  | Speedup |
| ------------------------------------------ | ----------- | ----------- | ------- |
| callback/ic0_msg_reject_code()             |      8.46ms |      9.09ms |     +7% |
| callback/ic0_msg_reject_msg_size()         |      8.20ms |      8.21ms |     +0% |
| callback/ic0_msg_reject_msg_copy()/1B      |        83ms |      86.4ms |     +4% |
| callback/ic0_msg_reject_msg_copy()/10B     |      83.1ms |      86.8ms |     +4% |
| callback/ic0_msg_cycles_refunded()         |      8.50ms |      8.46ms |     -1% |
| callback/ic0_msg_cycles_refunded128()      |      48.1ms |      48.3ms |     +0% |
| inspect/ic0_msg_method_name_size()         |      8.12ms |      8.11ms |     -1% |
| inspect/ic0_msg_method_name_copy()/1B      |      70.7ms |      70.6ms |     -1% |
| inspect/ic0_msg_method_name_copy()/30B     |      70.9ms |      70.8ms |     -1% |
| inspect/ic0_accept_message()*              |       161us |       159us |     -2% |
| inspect/ic0_data_certificate_size()        |      8.12ms |      8.40ms |     +3% |
| inspect/ic0_data_certificate_copy()/1B     |      56.1ms |      55.9ms |     -1% |
| inspect/ic0_data_certificate_copy()/64B    |      56.2ms |        56ms |     -1% |
| update/baseline/empty test*                |       221us |       229us |     +3% |
| update/baseline/empty loop                 |      1.14ms |      1.12ms |     -2% |
| update/baseline/adds                       |      1.78ms |      1.78ms |     +0% |
| update/ic0_msg_caller_size()               |      8.23ms |      8.22ms |     -1% |
| update/ic0_msg_caller_copy()/1B            |      56.6ms |      57.5ms |     +1% |
| update/ic0_msg_caller_copy()/10B           |        57ms |      57.3ms |     +0% |
| update/ic0_msg_arg_data_size()             |      8.48ms |      8.47ms |     -1% |
| update/ic0_msg_arg_data_copy()/1B          |        75ms |      76.4ms |     +1% |
| update/ic0_msg_arg_data_copy()/8K          |       153ms |       155ms |     +1% |
| update/ic0_msg_reply()*                    |       237us |       235us |     -1% |
| update/ic0_msg_reply_data_append()/1B      |      65.4ms |        66ms |     +0% |
| update/ic0_msg_reply_data_append()/2B      |      66.5ms |      66.1ms |     -1% |
| update/ic0_msg_reject()*                   |       224us |       230us |     +2% |
| update/ic0_canister_self_size()            |      9.08ms |      8.45ms |     -7% |
| update/ic0_canister_self_copy()/1B         |      57.7ms |      57.8ms |     +0% |
| update/ic0_canister_self_copy()/10B        |      58.2ms |        58ms |     -1% |
| update/ic0_controller_size()               |      8.47ms |      8.47ms |     +0% |
| update/ic0_controller_copy()/1B            |      57.8ms |      57.9ms |     +0% |
| update/ic0_controller_copy()/10B           |      58.3ms |        58ms |     -1% |
| update/ic0_debug_print()/1B                |      20.6ms |      20.7ms |     +0% |
| update/ic0_debug_print()/64B               |      20.7ms |      20.7ms |     +0% |
| update/ic0_call_simple()                   |       1.50s |       1.52s |     +1% |
| update/ic0_call_new()                      |       252ms |       251ms |     -1% |
| update/call_new+ic0_call_data_append()/1B  |       350ms |       355ms |     +1% |
| update/call_new+ic0_call_data_append()/8K  |       476ms |       479ms |     +0% |
| update/call_new+ic0_call_on_cleanup()      |       259ms |       258ms |     -1% |
| update/call_new+ic0_call_cycles_add()      |       269ms |       265ms |     -2% |
| update/call_new+ic0_call_cycles_add128()   |       273ms |       269ms |     -2% |
| update/call_new+ic0_call_perform()         |       1.82s |       1.83s |     +0% |
| update/ic0_stable_size()                   |      7.90ms |      8.14ms |     +3% |
| update/ic0_stable_grow()                   |      53.2ms |      53.3ms |     +0% |
| update/ic0_stable_read()/1B                |      85.6ms |      85.1ms |     -1% |
| update/ic0_stable_read()/8K                |       259ms |       259ms |     +0% |
| update/ic0_stable_write()/1B               |      99.9ms |      97.7ms |     -3% |
| update/ic0_stable_write()/8K               |       244ms |       241ms |     -2% |
| update/ic0_stable64_size()                 |      7.90ms |      8.14ms |     +3% |
| update/ic0_stable64_grow()                 |      53.2ms |      53.3ms |     +0% |
| update/ic0_stable64_read()/1B              |      93.6ms |      96.7ms |     +3% |
| update/ic0_stable64_read()/8K              |       267ms |       267ms |     +0% |
| update/ic0_stable64_write()/1B             |      99.9ms |       101ms |     +1% |
| update/ic0_stable64_write()/8K             |       244ms |       242ms |     -1% |
| update/ic0_time()                          |      8.76ms |      8.18ms |     -7% |
| update/ic0_canister_cycle_balance()        |      8.47ms |      8.43ms |     -1% |
| update/ic0_canister_cycles_balance128()    |      48.5ms |      48.9ms |     +0% |
| update/ic0_msg_cycles_available()          |      13.7ms |      13.9ms |     +1% |
| update/ic0_msg_cycles_available128()       |      52.6ms |      53.3ms |     +1% |
| update/ic0_msg_cycles_accept()             |      23.3ms |      23.3ms |     +0% |
| update/ic0_msg_cycles_accept128()          |      62.7ms |        73ms |    +16% |
| update/ic0_data_certificate_present()      |      5.44ms |      5.16ms |     -6% |
| update/ic0_certified_data_set()/1B         |      61.8ms |      63.8ms |     +3% |
| update/ic0_certified_data_set()/32B        |      62.3ms |      63.1ms |     +1% |
| update/ic0_canister_status()               |      7.91ms |      8.48ms |     +7% |
| update/ic0_mint_cycles()                   |      29.1ms |      29.2ms |     +0% |

Average speedup of the local changes: +0% (time)

Note: marked calls have no loop, so those results should not be compared vs other calls
