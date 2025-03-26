System API Performance Report
=============================

Remote (old) commit:4fea8a2f4 branch:andriy/fix-system-api-benches
Local  (new) commit:67cb8cb21 branch:andriy/fix-system-api-regression

| API Type / System API Call                           | Old IPS | New IPS | Speedup | Round Time |
| ---------------------------------------------------- | ------- | ------- | ------- | ---------- |
| inspect/ic0_msg_method_name_size()                   | 6.89G   | 7.48G   | +8%     | 0.94s      |
| inspect/ic0_msg_method_name_copy()/1B                | 2.06G   | 3.53G   | +71%    | 1.98s      |
| inspect/ic0_msg_method_name_copy()/20B               | 2.14G   | 3.67G   | +71%    | 1.91s      |
| inspect/ic0_accept_message()*                        | 3.39M   | 3.34M   | -2%     | -          |
| query/ic0_data_certificate_size()                    | 7.36G   | 7.56G   | +2%     | 0.93s      |
| query/ic0_data_certificate_copy()/1B                 | 2G      | 3.39G   | +69%    | 2.06s      |
| query/ic0_data_certificate_copy()/64B                | 2.27G   | 3.85G   | +69%    | 1.82s      |
| update/baseline/empty test*                          | 17.5K   | 18.1K   | +3%     | -          |
| update/baseline/empty loop                           | 4.12G   | 4.17G   | +1%     | 1.68s      |
| update/baseline/adds                                 | 5.94G   | 5.91G   | -1%     | 1.18s      |
| update/ic0_msg_caller_size()                         | 7.10G   | 7.41G   | +4%     | 0.94s      |
| update/ic0_msg_caller_copy()/1B                      | 2.06G   | 3.35G   | +62%    | 2.09s      |
| update/ic0_msg_caller_copy()/10B                     | 2.06G   | 3.34G   | +62%    | 2.10s      |
| update/ic0_msg_arg_data_size()                       | 7.49G   | 7.37G   | -2%     | 0.95s      |
| update/ic0_msg_arg_data_copy()/1B                    | 2.02G   | 3.63G   | +79%    | 1.93s      |
| update/ic0_msg_arg_data_copy()/1K                    | 5.73G   | 9.71G   | +69%    | 0.72s      |
| update/ic0_msg_reply()*                              | 2.91M   | 3.04M   | +4%     | -          |
| update/ic0_msg_reply_data_append()/1B                | 2.30G   | 3.75G   | +63%    | 1.87s      |
| update/ic0_msg_reply_data_append()/2B                | 2.50G   | 4.08G   | +63%    | 1.72s      |
| update/ic0_msg_reject()*                             | 2.88M   | 2.95M   | +2%     | -          |
| update/ic0_canister_self_size()                      | 7.41G   | 6.96G   | -7%     | 1.01s      |
| update/ic0_canister_self_copy()/1B                   | 2.07G   | 3.41G   | +64%    | 2.05s      |
| update/ic0_canister_self_copy()/10B                  | 2.10G   | 3.41G   | +62%    | 2.05s      |
| update/ic0_debug_print()/1B                          | 579M    | 887M    | +53%    | 7.89s      |
| update/ic0_debug_print()/1K                          | 150G    | 232G    | +54%    | 0.03s      |
| update/ic0_call_new()                                | 4.23G   | 5.79G   | +36%    | 1.21s      |
| update/call_new+ic0_call_data_append()/1B            | 3.25G   | 4.74G   | +45%    | 1.48s      |
| update/call_new+ic0_call_data_append()/1K            | 80.8G   | 118G    | +46%    | 0.06s      |
| update/call_new+ic0_call_on_cleanup()                | 4.57G   | 6.01G   | +31%    | 1.16s      |
| update/call_new+ic0_call_cycles_add()                | 3.97G   | 4.98G   | +25%    | 1.41s      |
| update/call_new+ic0_call_cycles_add128()             | 3.97G   | 4.96G   | +24%    | 1.41s      |
| update/call_new+ic0_call_perform()                   | 3.90G   | 4.29G   | +10%    | 1.63s      |
| update/call_new+ic0_call_with_best_effort_response() | 4.57G   | 5.99G   | +31%    | 1.17s      |
| update/ic0_stable_size()                             | 5.17G   | 5.23G   | +1%     | 1.34s      |
| update/ic0_stable_grow()                             | 653M    | 635M    | -3%     | 11.02s     |
| update/ic0_stable_read()/1B                          | 1.72G   | 1.72G   | +0%     | 4.07s      |
| update/ic0_stable_read()/1K                          | 30.2G   | 30G     | -1%     | 0.23s      |
| update/ic0_stable_write()/1B                         | 1.02G   | 1.02G   | +0%     | 6.86s      |
| update/ic0_stable_write()/1K                         | 20.5G   | 20.5G   | +0%     | 0.34s      |
| update/ic0_stable64_size()                           | 6.42G   | 6.45G   | +0%     | 1.09s      |
| update/ic0_stable64_grow()                           | 657M    | 640M    | -3%     | 10.94s     |
| update/ic0_stable64_read()/1B                        | 1.59G   | 1.53G   | -4%     | 4.58s      |
| update/ic0_stable64_read()/1K                        | 28.9G   | 29.3G   | +1%     | 0.24s      |
| update/ic0_stable64_write()/1B                       | 1.01G   | 1.01G   | +0%     | 6.93s      |
| update/ic0_stable64_write()/1K                       | 20.6G   | 20.6G   | +0%     | 0.34s      |
| update/ic0_time()                                    | 7.36G   | 7.49G   | +1%     | 0.93s      |
| update/ic0_global_timer_set()                        | 6.90G   | 6.97G   | +1%     | 1.00s      |
| update/ic0_performance_counter()                     | 2.51G   | 2.85G   | +13%    | 2.46s      |
| update/ic0_canister_cycle_balance()                  | 7.10G   | 7.19G   | +1%     | 0.97s      |
| update/ic0_canister_cycle_balance128()               | 3.64G   | 3.49G   | -5%     | 2.01s      |
| update/ic0_msg_cycles_available()                    | 7G      | 7.24G   | +3%     | 0.97s      |
| update/ic0_msg_cycles_available128()                 | 3.49G   | 3.65G   | +4%     | 1.92s      |
| update/ic0_msg_cycles_accept()                       | 5.87G   | 5.83G   | -1%     | 1.20s      |
| update/ic0_msg_cycles_accept128()                    | 3.09G   | 3.18G   | +2%     | 2.20s      |
| update/ic0_data_certificate_present()                | 7.28G   | 8.09G   | +11%    | 0.87s      |
| update/ic0_certified_data_set()/1B                   | 1.94G   | 3.13G   | +61%    | 2.24s      |
| update/ic0_certified_data_set()/32B                  | 2.05G   | 3.35G   | +63%    | 2.09s      |
| update/ic0_canister_status()                         | 7.13G   | 7.95G   | +11%    | 0.88s      |
| update/ic0_mint_cycles()                             | 491M    | 485M    | -2%     | 14.43s     |
| update/ic0_is_controller()                           | 3.84G   | 6.09G   | +58%    | 1.15s      |
| update/ic0_in_replicated_execution()                 | 7.19G   | 7.24G   | +0%     | 0.97s      |
| update/ic0_cycles_burn128()                          | 115M    | 109M    | -6%     | 64.22s     |
| update/ic0_msg_deadline()                            | 6.88G   | 6.99G   | +1%     | 1.00s      |

Average speedup of the local (new) changes: +21% (throughput)

| API Type / System API Call (1M Iterations)           | Old Time | New Time | Speedup |
| ---------------------------------------------------- | -------- | -------- | ------- |
| inspect/ic0_msg_method_name_size()                   | 75ms     | 69ms     | -8%     |
| inspect/ic0_msg_method_name_copy()/1B                | 251ms    | 146ms    | -42%    |
| inspect/ic0_msg_method_name_copy()/20B               | 250ms    | 146ms    | -42%    |
| inspect/ic0_accept_message()*                        | 149µs    | 151µs    | +1%     |
| query/ic0_data_certificate_size()                    | 70.1ms   | 68.3ms   | -3%     |
| query/ic0_data_certificate_copy()/1B                 | 258ms    | 153ms    | -41%    |
| query/ic0_data_certificate_copy()/64B                | 256ms    | 151ms    | -42%    |
| update/baseline/empty test*                          | 171µs    | 164µs    | -5%     |
| update/baseline/empty loop                           | 2.66ms   | 2.63ms   | -2%     |
| update/baseline/adds                                 | 2.69ms   | 2.70ms   | +0%     |
| update/ic0_msg_caller_size()                         | 72.7ms   | 69.6ms   | -5%     |
| update/ic0_msg_caller_copy()/1B                      | 251ms    | 154ms    | -39%    |
| update/ic0_msg_caller_copy()/10B                     | 256ms    | 158ms    | -39%    |
| update/ic0_msg_arg_data_size()                       | 69ms     | 70.1ms   | +1%     |
| update/ic0_msg_arg_data_copy()/1B                    | 256ms    | 143ms    | -45%    |
| update/ic0_msg_arg_data_copy()/1K                    | 269ms    | 158ms    | -42%    |
| update/ic0_msg_reply()*                              | 173µs    | 166µs    | -5%     |
| update/ic0_msg_reply_data_append()/1B                | 246ms    | 151ms    | -39%    |
| update/ic0_msg_reply_data_append()/2B                | 247ms    | 151ms    | -39%    |
| update/ic0_msg_reject()*                             | 175µs    | 172µs    | -2%     |
| update/ic0_canister_self_size()                      | 69.7ms   | 74.2ms   | +6%     |
| update/ic0_canister_self_copy()/1B                   | 250ms    | 152ms    | -40%    |
| update/ic0_canister_self_copy()/10B                  | 251ms    | 154ms    | -39%    |
| update/ic0_debug_print()/1B                          | 293ms    | 191ms    | -35%    |
| update/ic0_debug_print()/1K                          | 315ms    | 203ms    | -36%    |
| update/ic0_call_new()                                | 366ms    | 267ms    | -28%    |
| update/call_new+ic0_call_data_append()/1B            | 647ms    | 444ms    | -32%    |
| update/call_new+ic0_call_data_append()/1K            | 658ms    | 450ms    | -32%    |
| update/call_new+ic0_call_on_cleanup()                | 449ms    | 342ms    | -24%    |
| update/call_new+ic0_call_cycles_add()                | 517ms    | 413ms    | -21%    |
| update/call_new+ic0_call_cycles_add128()             | 517ms    | 414ms    | -20%    |
| update/call_new+ic0_call_perform()                   | 1.67s    | 1.52s    | -9%     |
| update/call_new+ic0_call_with_best_effort_response() | 449ms    | 343ms    | -24%    |
| update/ic0_stable_size()                             | 3.28ms   | 3.24ms   | -2%     |
| update/ic0_stable_grow()                             | 180ms    | 185ms    | +2%     |
| update/ic0_stable_read()/1B                          | 23.1ms   | 23.2ms   | +0%     |
| update/ic0_stable_read()/1K                          | 35.1ms   | 35.4ms   | +0%     |
| update/ic0_stable_write()/1B                         | 39.2ms   | 39ms     | -1%     |
| update/ic0_stable_write()/1K                         | 51.8ms   | 51.6ms   | -1%     |
| update/ic0_stable64_size()                           | 2.64ms   | 2.63ms   | -1%     |
| update/ic0_stable64_grow()                           | 179ms    | 184ms    | +2%     |
| update/ic0_stable64_read()/1B                        | 25ms     | 26ms     | +3%     |
| update/ic0_stable64_read()/1K                        | 36.7ms   | 36.2ms   | -2%     |
| update/ic0_stable64_write()/1B                       | 39.3ms   | 39.4ms   | +0%     |
| update/ic0_stable64_write()/1K                       | 51.5ms   | 51.6ms   | +0%     |
| update/ic0_time()                                    | 70.1ms   | 68.9ms   | -2%     |
| update/ic0_global_timer_set()                        | 75ms     | 74.3ms   | -1%     |
| update/ic0_performance_counter()                     | 86.6ms   | 76.4ms   | -12%    |
| update/ic0_canister_cycle_balance()                  | 72.7ms   | 71.8ms   | -2%     |
| update/ic0_canister_cycle_balance128()               | 141ms    | 147ms    | +4%     |
| update/ic0_msg_cycles_available()                    | 73.8ms   | 71.3ms   | -4%     |
| update/ic0_msg_cycles_available128()                 | 147ms    | 141ms    | -5%     |
| update/ic0_msg_cycles_accept()                       | 88.1ms   | 88.7ms   | +0%     |
| update/ic0_msg_cycles_accept128()                    | 167ms    | 163ms    | -3%     |
| update/ic0_data_certificate_present()                | 70.9ms   | 63.8ms   | -11%    |
| update/ic0_certified_data_set()/1B                   | 266ms    | 165ms    | -38%    |
| update/ic0_certified_data_set()/32B                  | 267ms    | 163ms    | -39%    |
| update/ic0_canister_status()                         | 72.4ms   | 65ms     | -11%    |
| update/ic0_mint_cycles()                             | 36.6ms   | 37.1ms   | +1%     |
| update/ic0_is_controller()                           | 272ms    | 171ms    | -38%    |
| update/ic0_in_replicated_execution()                 | 71.8ms   | 71.4ms   | -1%     |
| update/ic0_cycles_burn128()                          | 164ms    | 173ms    | +5%     |
| update/ic0_msg_deadline()                            | 75ms     | 73.9ms   | -2%     |

Average speedup of the local (new) changes: -14% (time)

Note: marked calls have no loop, so those results should not be compared with other calls
