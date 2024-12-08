System API Performance Report
=============================

Remote (old) commit:7a3fcfa9c branch:7a3fcfa9c1
Local  (new) commit:b36fae731 branch:andriy/exc-1818-system-api-benches

| API Type / System API Call                                  | Old IPS | New IPS | Speedup | Round Time |
| ----------------------------------------------------------- | ------- | ------- | ------- | ---------- |
| inspect/wasm32/ic0_msg_method_name_size()                   | 7.48G   | 8.08G   | +8%     | 0.87s      |
| inspect/wasm64/ic0_msg_method_name_size()                   | -       | 7.73G   | -       | 0.91s      |
| inspect/wasm32/ic0_msg_method_name_copy()/1B                | 3.53G   | 3.76G   | +6%     | 1.86s      |
| inspect/wasm64/ic0_msg_method_name_copy()/1B                | -       | 3.96G   | -       | 1.77s      |
| inspect/wasm32/ic0_msg_method_name_copy()/20B               | 3.67G   | 3.90G   | +6%     | 1.79s      |
| inspect/wasm64/ic0_msg_method_name_copy()/20B               | -       | 4.11G   | -       | 1.70s      |
| inspect/wasm32/ic0_accept_message()*                        | 3.34M   | 2.47M   | -27%    | -          |
| inspect/wasm64/ic0_accept_message()*                        | -       | 2.27M   | -       | -          |
| query/wasm32/ic0_data_certificate_size()                    | 7.56G   | 7.11G   | -6%     | 0.98s      |
| query/wasm64/ic0_data_certificate_size()                    | -       | 8.18G   | -       | 0.86s      |
| query/wasm32/ic0_data_certificate_copy()/1B                 | 3.39G   | 3.84G   | +13%    | 1.82s      |
| query/wasm64/ic0_data_certificate_copy()/1B                 | -       | 3.95G   | -       | 1.77s      |
| query/wasm32/ic0_data_certificate_copy()/64B                | 3.85G   | 4.33G   | +12%    | 1.62s      |
| query/wasm64/ic0_data_certificate_copy()/64B                | -       | 4.46G   | -       | 1.57s      |
| update/wasm32/baseline/empty test*                          | 18.1K   | 11.7K   | -36%    | -          |
| update/wasm64/baseline/empty test*                          | -       | 10.3K   | -       | -          |
| update/wasm32/baseline/empty loop                           | 4.17G   | 4.07G   | -3%     | 1.72s      |
| update/wasm64/baseline/empty loop                           | -       | 4.07G   | -       | 1.72s      |
| update/wasm32/baseline/adds                                 | 5.91G   | 5.83G   | -2%     | 1.20s      |
| update/wasm64/baseline/adds                                 | -       | 6.18G   | -       | 1.13s      |
| update/wasm32/ic0_msg_caller_size()                         | 7.41G   | 6.44G   | -14%    | 1.09s      |
| update/wasm64/ic0_msg_caller_size()                         | -       | 6.37G   | -       | 1.10s      |
| update/wasm32/ic0_msg_caller_copy()/1B                      | 3.35G   | 3.80G   | +13%    | 1.84s      |
| update/wasm64/ic0_msg_caller_copy()/1B                      | -       | 3.44G   | -       | 2.03s      |
| update/wasm32/ic0_msg_caller_copy()/10B                     | 3.34G   | 3.77G   | +12%    | 1.86s      |
| update/wasm364/ic0_msg_caller_copy()/10B                    | -       | 3.46G   | -       | 2.02s      |
| update/wasm32/ic0_msg_arg_data_size()                       | 7.37G   | 7.90G   | +7%     | 0.89s      |
| update/wasm64/ic0_msg_arg_data_size()                       | -       | 8.04G   | -       | 0.87s      |
| update/wasm32/ic0_msg_arg_data_copy()/1B                    | 3.63G   | 3.49G   | -4%     | 2.01s      |
| update/wasm64/ic0_msg_arg_data_copy()/1B                    | -       | 3.50G   | -       | 2.00s      |
| update/wasm32/ic0_msg_arg_data_copy()/1K                    | 9.71G   | 9.26G   | -5%     | 0.76s      |
| update/wasm64/ic0_msg_arg_data_copy()/1K                    | -       | 9.48G   | -       | 0.74s      |
| update/wasm32/ic0_msg_reply()*                              | 3.04M   | 2.20M   | -28%    | -          |
| update/wasm64/ic0_msg_reply()*                              | -       | 1.91M   | -       | -          |
| update/wasm32/ic0_msg_reply_data_append()/1B                | 3.75G   | 4.02G   | +7%     | 1.74s      |
| update/wasm64/ic0_msg_reply_data_append()/1B                | -       | 4.13G   | -       | 1.69s      |
| update/wasm32/ic0_msg_reply_data_append()/2B                | 4.08G   | 4.39G   | +7%     | 1.59s      |
| update/wasm64/ic0_msg_reply_data_append()/2B                | -       | 4.50G   | -       | 1.56s      |
| update/wasm32/ic0_msg_reject()*                             | 2.95M   | 2.12M   | -29%    | -          |
| update/wasm64/ic0_msg_reject()*                             | -       | 2.15M   | -       | -          |
| update/wasm32/ic0_canister_self_size()                      | 6.96G   | 6.84G   | -2%     | 1.02s      |
| update/wasm64/ic0_canister_self_size()                      | -       | 7.72G   | -       | 0.91s      |
| update/wasm32/ic0_canister_self_copy()/1B                   | 3.41G   | 3.42G   | +0%     | 2.05s      |
| update/wasm64/ic0_canister_self_copy()/1B                   | -       | 3.60G   | -       | 1.94s      |
| update/wasm32/ic0_canister_self_copy()/10B                  | 3.41G   | 3.46G   | +1%     | 2.02s      |
| update/wasm64/ic0_canister_self_copy()/10B                  | -       | 3.60G   | -       | 1.94s      |
| update/wasm32/ic0_debug_print()/1B                          | 887M    | 894M    | +0%     | 7.83s      |
| update/wasm64/ic0_debug_print()/1B                          | -       | 877M    | -       | 7.98s      |
| update/wasm32/ic0_debug_print()/1K                          | 232G    | 230G    | -1%     | 0.03s      |
| update/wasm64/ic0_debug_print()/1K                          | -       | 231G    | -       | 0.03s      |
| update/wasm32/ic0_call_new()                                | 5.79G   | 5.67G   | -3%     | 1.23s      |
| update/wasm64/ic0_call_new()                                | -       | 5.55G   | -       | 1.26s      |
| update/wasm32/call_new+ic0_call_cycles_add()                | 4.98G   | 4.85G   | -3%     | 1.44s      |
| update/wasm32/call_new+ic0_call_data_append()/1B            | 4.74G   | 4.55G   | -5%     | 1.54s      |
| update/wasm64/call_new+ic0_call_data_append()/1B            | -       | 4.56G   | -       | 1.54s      |
| update/wasm32/call_new+ic0_call_data_append()/1K            | 118G    | 112G    | -6%     | 0.06s      |
| update/wasm64/call_new+ic0_call_data_append()/1K            | -       | 112G    | -       | 0.06s      |
| update/wasm32/call_new+ic0_call_on_cleanup()                | 6.01G   | 5.87G   | -3%     | 1.19s      |
| update/wasm64/call_new+ic0_call_on_cleanup()                | -       | 5.72G   | -       | 1.22s      |
| update/wasm32/call_new+ic0_call_cycles_add128()             | 4.96G   | 4.87G   | -2%     | 1.44s      |
| update/wasm64/call_new+ic0_call_cycles_add128()             | -       | 4.82G   | -       | 1.45s      |
| update/wasm32/call_new+ic0_call_perform()                   | 4.29G   | 3.53G   | -18%    | 1.98s      |
| update/wasm64/call_new+ic0_call_perform()                   | -       | 3.50G   | -       | 2.00s      |
| update/wasm32/ic0_stable64_size()                           | 6.45G   | 6.23G   | -4%     | 1.12s      |
| update/wasm64/ic0_stable64_size()                           | -       | 6.21G   | -       | 1.13s      |
| update/wasm32/call_new+ic0_call_with_best_effort_response() | 5.99G   | 5.88G   | -2%     | 1.19s      |
| update/wasm64/call_new+ic0_call_with_best_effort_response() | -       | 5.69G   | -       | 1.23s      |
| update/wasm32/ic0_stable_size()                             | 5.23G   | 5.07G   | -4%     | 1.38s      |
| update/wasm32/ic0_stable_grow()                             | 635M    | 631M    | -1%     | 11.09s     |
| update/wasm32/ic0_stable64_grow()                           | 640M    | 635M    | -1%     | 11.02s     |
| update/wasm64/ic0_stable64_grow()                           | -       | 646M    | -       | 10.84s     |
| update/wasm32/ic0_stable_read()/1B                          | 1.72G   | 1.71G   | -1%     | 4.09s      |
| update/wasm32/ic0_stable64_read()/1B                        | 1.53G   | 1.64G   | +7%     | 4.27s      |
| update/wasm64/ic0_stable64_read()/1B                        | -       | 1.68G   | -       | 4.17s      |
| update/wasm32/ic0_stable_read()/1K                          | 30G     | 28.5G   | -5%     | 0.25s      |
| update/wasm32/ic0_stable64_read()/1K                        | 29.3G   | 27.9G   | -5%     | 0.25s      |
| update/wasm64/ic0_stable64_read()/1K                        | -       | 28.2G   | -       | 0.25s      |
| update/wasm32/ic0_stable_write()/1B                         | 1.02G   | 863M    | -16%    | 8.11s      |
| update/wasm32/ic0_stable64_write()/1B                       | 1.01G   | 862M    | -15%    | 8.12s      |
| update/wasm64/ic0_stable64_write()/1B                       | -       | 863M    | -       | 8.11s      |
| update/wasm32/ic0_stable_write()/1K                         | 20.5G   | 19.5G   | -5%     | 0.36s      |
| update/wasm32/ic0_stable64_write()/1K                       | 20.6G   | 19.3G   | -7%     | 0.36s      |
| update/wasm64/ic0_stable64_write()/1K                       | -       | 19.3G   | -       | 0.36s      |
| update/wasm32/ic0_time()                                    | 7.49G   | 7.78G   | +3%     | 0.90s      |
| update/wasm64/ic0_time()                                    | -       | 6.94G   | -       | 1.01s      |
| update/wasm32/ic0_global_timer_set()                        | 6.97G   | 7.09G   | +1%     | 0.99s      |
| update/wasm64/ic0_global_timer_set()                        | -       | 7.97G   | -       | 0.88s      |
| update/wasm32/ic0_performance_counter()                     | 2.85G   | 2.83G   | -1%     | 2.47s      |
| update/wasm64/ic0_performance_counter()                     | -       | 2.97G   | -       | 2.36s      |
| update/wasm32/ic0_canister_cycle_balance()                  | 7.19G   | 7.03G   | -3%     | 1.00s      |
| update/wasm32/ic0_canister_cycle_balance128()               | 3.49G   | 3.68G   | +5%     | 1.90s      |
| update/wasm64/ic0_canister_cycle_balance128()               | -       | 3.82G   | -       | 1.83s      |
| update/wasm32/ic0_msg_cycles_available()                    | 7.24G   | 7.16G   | -2%     | 0.98s      |
| update/wasm32/ic0_msg_cycles_available128()                 | 3.65G   | 3.63G   | -1%     | 1.93s      |
| update/wasm64/ic0_msg_cycles_available128()                 | -       | 3.70G   | -       | 1.89s      |
| update/wasm32/ic0_msg_cycles_accept()                       | 5.83G   | 6.44G   | +10%    | 1.09s      |
| update/wasm32/ic0_msg_cycles_accept128()                    | 3.18G   | 3.32G   | +4%     | 2.11s      |
| update/wasm64/ic0_msg_cycles_accept128()                    | -       | 3.31G   | -       | 2.11s      |
| update/wasm32/ic0_data_certificate_present()                | 8.09G   | 7.66G   | -6%     | 0.91s      |
| update/wasm64/ic0_data_certificate_present()                | -       | 6.90G   | -       | 1.01s      |
| update/wasm32/ic0_certified_data_set()/1B                   | 3.13G   | 2.94G   | -7%     | 2.38s      |
| update/wasm64/ic0_certified_data_set()/1B                   | -       | 3.13G   | -       | 2.24s      |
| update/wasm32/ic0_certified_data_set()/32B                  | 3.35G   | 3.14G   | -7%     | 2.23s      |
| update/wasm64/ic0_certified_data_set()/32B                  | -       | 3.30G   | -       | 2.12s      |
| update/wasm32/ic0_canister_status()                         | 7.95G   | 7.68G   | -4%     | 0.91s      |
| update/wasm64/ic0_canister_status()                         | -       | 8.16G   | -       | 0.86s      |
| update/wasm32/ic0_mint_cycles()                             | 485M    | 367M    | -25%    | 19.07s     |
| update/wasm64/ic0_mint_cycles()                             | -       | 389M    | -       | 17.99s     |
| update/wasm32/ic0_is_controller()                           | 6.09G   | 6.87G   | +12%    | 1.02s      |
| update/wasm64/ic0_is_controller()                           | -       | 5.65G   | -       | 1.24s      |
| update/wasm32/ic0_in_replicated_execution()                 | 7.24G   | 8.24G   | +13%    | 0.85s      |
| update/wasm64/ic0_in_replicated_execution()                 | -       | 8.49G   | -       | 0.82s      |
| update/wasm32/ic0_cycles_burn128()                          | 109M    | 114M    | +4%     | 61.40s     |
| update/wasm64/ic0_cycles_burn128()                          | -       | 110M    | -       | 63.64s     |
| update/wasm32/ic0_msg_deadline()                            | 6.99G   | 7.85G   | +12%    | 0.89s      |
| update/wasm64/ic0_msg_deadline()                            | -       | 7.98G   | -       | 0.88s      |

Average speedup of the local (new) changes: -2% (throughput)

| API Type / System API Call (1M Iterations)                  | Old Time | New Time | Speedup |
| ----------------------------------------------------------- | -------- | -------- | ------- |
| inspect/wasm32/ic0_msg_method_name_size()                   | 69ms     | 63.9ms   | -8%     |
| inspect/wasm64/ic0_msg_method_name_size()                   | -        | 66.8ms   | -       |
| inspect/wasm32/ic0_msg_method_name_copy()/1B                | 146ms    | 138ms    | -6%     |
| inspect/wasm64/ic0_msg_method_name_copy()/1B                | -        | 131ms    | -       |
| inspect/wasm32/ic0_msg_method_name_copy()/20B               | 146ms    | 138ms    | -6%     |
| inspect/wasm64/ic0_msg_method_name_copy()/20B               | -        | 130ms    | -       |
| inspect/wasm32/ic0_accept_message()*                        | 151µs    | 204µs    | +35%    |
| inspect/wasm64/ic0_accept_message()*                        | -        | 222µs    | -       |
| query/wasm32/ic0_data_certificate_size()                    | 68.3ms   | 72.6ms   | +6%     |
| query/wasm64/ic0_data_certificate_size()                    | -        | 63.1ms   | -       |
| query/wasm32/ic0_data_certificate_copy()/1B                 | 153ms    | 135ms    | -12%    |
| query/wasm64/ic0_data_certificate_copy()/1B                 | -        | 131ms    | -       |
| query/wasm32/ic0_data_certificate_copy()/64B                | 151ms    | 134ms    | -12%    |
| query/wasm64/ic0_data_certificate_copy()/64B                | -        | 130ms    | -       |
| update/wasm32/baseline/empty test*                          | 164µs    | 255µs    | +55%    |
| update/wasm64/baseline/empty test*                          | -        | 288µs    | -       |
| update/wasm32/baseline/empty loop                           | 2.63ms   | 2.69ms   | +2%     |
| update/wasm64/baseline/empty loop                           | -        | 2.69ms   | -       |
| update/wasm32/baseline/adds                                 | 2.70ms   | 2.74ms   | +1%     |
| update/wasm64/baseline/adds                                 | -        | 2.74ms   | -       |
| update/wasm32/ic0_msg_caller_size()                         | 69.6ms   | 80.1ms   | +15%    |
| update/wasm64/ic0_msg_caller_size()                         | -        | 81ms     | -       |
| update/wasm32/ic0_msg_caller_copy()/1B                      | 154ms    | 136ms    | -12%    |
| update/wasm64/ic0_msg_caller_copy()/1B                      | -        | 150ms    | -       |
| update/wasm32/ic0_msg_caller_copy()/10B                     | 158ms    | 139ms    | -13%    |
| update/wasm364/ic0_msg_caller_copy()/10B                    | -        | 150ms    | -       |
| update/wasm32/ic0_msg_arg_data_size()                       | 70.1ms   | 65.3ms   | -7%     |
| update/wasm64/ic0_msg_arg_data_size()                       | -        | 64.2ms   | -       |
| update/wasm32/ic0_msg_arg_data_copy()/1B                    | 143ms    | 148ms    | +3%     |
| update/wasm64/ic0_msg_arg_data_copy()/1B                    | -        | 148ms    | -       |
| update/wasm32/ic0_msg_arg_data_copy()/1K                    | 158ms    | 166ms    | +5%     |
| update/wasm64/ic0_msg_arg_data_copy()/1K                    | -        | 162ms    | -       |
| update/wasm32/ic0_msg_reply()*                              | 166µs    | 229µs    | +37%    |
| update/wasm64/ic0_msg_reply()*                              | -        | 264µs    | -       |
| update/wasm32/ic0_msg_reply_data_append()/1B                | 151ms    | 140ms    | -8%     |
| update/wasm64/ic0_msg_reply_data_append()/1B                | -        | 137ms    | -       |
| update/wasm32/ic0_msg_reply_data_append()/2B                | 151ms    | 140ms    | -8%     |
| update/wasm64/ic0_msg_reply_data_append()/2B                | -        | 137ms    | -       |
| update/wasm32/ic0_msg_reject()*                             | 172µs    | 239µs    | +38%    |
| update/wasm64/ic0_msg_reject()*                             | -        | 235µs    | -       |
| update/wasm32/ic0_canister_self_size()                      | 74.2ms   | 75.5ms   | +1%     |
| update/wasm64/ic0_canister_self_size()                      | -        | 66.9ms   | -       |
| update/wasm32/ic0_canister_self_copy()/1B                   | 152ms    | 151ms    | -1%     |
| update/wasm64/ic0_canister_self_copy()/1B                   | -        | 144ms    | -       |
| update/wasm32/ic0_canister_self_copy()/10B                  | 154ms    | 152ms    | -2%     |
| update/wasm64/ic0_canister_self_copy()/10B                  | -        | 146ms    | -       |
| update/wasm32/ic0_debug_print()/1B                          | 191ms    | 190ms    | -1%     |
| update/wasm64/ic0_debug_print()/1B                          | -        | 193ms    | -       |
| update/wasm32/ic0_debug_print()/1K                          | 203ms    | 205ms    | +0%     |
| update/wasm64/ic0_debug_print()/1K                          | -        | 204ms    | -       |
| update/wasm32/ic0_call_new()                                | 267ms    | 273ms    | +2%     |
| update/wasm64/ic0_call_new()                                | -        | 279ms    | -       |
| update/wasm32/call_new+ic0_call_cycles_add()                | 413ms    | 423ms    | +2%     |
| update/wasm32/call_new+ic0_call_data_append()/1B            | 444ms    | 463ms    | +4%     |
| update/wasm64/call_new+ic0_call_data_append()/1B            | -        | 461ms    | -       |
| update/wasm32/call_new+ic0_call_data_append()/1K            | 450ms    | 472ms    | +4%     |
| update/wasm64/call_new+ic0_call_data_append()/1K            | -        | 473ms    | -       |
| update/wasm32/call_new+ic0_call_on_cleanup()                | 342ms    | 350ms    | +2%     |
| update/wasm64/call_new+ic0_call_on_cleanup()                | -        | 359ms    | -       |
| update/wasm32/call_new+ic0_call_cycles_add128()             | 414ms    | 422ms    | +1%     |
| update/wasm64/call_new+ic0_call_cycles_add128()             | -        | 426ms    | -       |
| update/wasm32/call_new+ic0_call_perform()                   | 1.52s    | 1.85s    | +21%    |
| update/wasm64/call_new+ic0_call_perform()                   | -        | 1.87s    | -       |
| update/wasm32/ic0_stable64_size()                           | 2.63ms   | 2.72ms   | +3%     |
| update/wasm64/ic0_stable64_size()                           | -        | 2.73ms   | -       |
| update/wasm32/call_new+ic0_call_with_best_effort_response() | 343ms    | 349ms    | +1%     |
| update/wasm64/call_new+ic0_call_with_best_effort_response() | -        | 361ms    | -       |
| update/wasm32/ic0_stable_size()                             | 3.24ms   | 3.35ms   | +3%     |
| update/wasm32/ic0_stable_grow()                             | 185ms    | 186ms    | +0%     |
| update/wasm32/ic0_stable64_grow()                           | 184ms    | 185ms    | +0%     |
| update/wasm64/ic0_stable64_grow()                           | -        | 182ms    | -       |
| update/wasm32/ic0_stable_read()/1B                          | 23.2ms   | 23.2ms   | +0%     |
| update/wasm32/ic0_stable64_read()/1B                        | 26ms     | 24.3ms   | -7%     |
| update/wasm64/ic0_stable64_read()/1B                        | -        | 23.7ms   | -       |
| update/wasm32/ic0_stable_read()/1K                          | 35.4ms   | 37.1ms   | +4%     |
| update/wasm32/ic0_stable64_read()/1K                        | 36.2ms   | 37.9ms   | +4%     |
| update/wasm64/ic0_stable64_read()/1K                        | -        | 37.6ms   | -       |
| update/wasm32/ic0_stable_write()/1B                         | 39ms     | 46.3ms   | +18%    |
| update/wasm32/ic0_stable64_write()/1B                       | 39.4ms   | 46.3ms   | +17%    |
| update/wasm64/ic0_stable64_write()/1B                       | -        | 46.3ms   | -       |
| update/wasm32/ic0_stable_write()/1K                         | 51.6ms   | 54.4ms   | +5%     |
| update/wasm32/ic0_stable64_write()/1K                       | 51.6ms   | 54.8ms   | +6%     |
| update/wasm64/ic0_stable64_write()/1K                       | -        | 54.8ms   | -       |
| update/wasm32/ic0_time()                                    | 68.9ms   | 66.4ms   | -4%     |
| update/wasm64/ic0_time()                                    | -        | 74.4ms   | -       |
| update/wasm32/ic0_global_timer_set()                        | 74.3ms   | 73ms     | -2%     |
| update/wasm64/ic0_global_timer_set()                        | -        | 64.9ms   | -       |
| update/wasm32/ic0_performance_counter()                     | 76.4ms   | 76.8ms   | +0%     |
| update/wasm64/ic0_performance_counter()                     | -        | 73.1ms   | -       |
| update/wasm32/ic0_canister_cycle_balance()                  | 71.8ms   | 73.4ms   | +2%     |
| update/wasm32/ic0_canister_cycle_balance128()               | 147ms    | 140ms    | -5%     |
| update/wasm64/ic0_canister_cycle_balance128()               | -        | 135ms    | -       |
| update/wasm32/ic0_msg_cycles_available()                    | 71.3ms   | 72.1ms   | +1%     |
| update/wasm32/ic0_msg_cycles_available128()                 | 141ms    | 142ms    | +0%     |
| update/wasm64/ic0_msg_cycles_available128()                 | -        | 139ms    | -       |
| update/wasm32/ic0_msg_cycles_accept()                       | 88.7ms   | 80.3ms   | -10%    |
| update/wasm32/ic0_msg_cycles_accept128()                    | 163ms    | 156ms    | -5%     |
| update/wasm64/ic0_msg_cycles_accept128()                    | -        | 156ms    | -       |
| update/wasm32/ic0_data_certificate_present()                | 63.8ms   | 67.4ms   | +5%     |
| update/wasm64/ic0_data_certificate_present()                | -        | 74.8ms   | -       |
| update/wasm32/ic0_certified_data_set()/1B                   | 165ms    | 176ms    | +6%     |
| update/wasm64/ic0_certified_data_set()/1B                   | -        | 165ms    | -       |
| update/wasm32/ic0_certified_data_set()/32B                  | 163ms    | 175ms    | +7%     |
| update/wasm64/ic0_certified_data_set()/32B                  | -        | 166ms    | -       |
| update/wasm32/ic0_canister_status()                         | 65ms     | 67.2ms   | +3%     |
| update/wasm64/ic0_canister_status()                         | -        | 63.2ms   | -       |
| update/wasm32/ic0_mint_cycles()                             | 37.1ms   | 48.9ms   | +31%    |
| update/wasm64/ic0_mint_cycles()                             | -        | 46.1ms   | -       |
| update/wasm32/ic0_is_controller()                           | 171ms    | 152ms    | -12%    |
| update/wasm64/ic0_is_controller()                           | -        | 185ms    | -       |
| update/wasm32/ic0_in_replicated_execution()                 | 71.4ms   | 62.7ms   | -13%    |
| update/wasm64/ic0_in_replicated_execution()                 | -        | 60.8ms   | -       |
| update/wasm32/ic0_cycles_burn128()                          | 173ms    | 165ms    | -5%     |
| update/wasm64/ic0_cycles_burn128()                          | -        | 171ms    | -       |
| update/wasm32/ic0_msg_deadline()                            | 73.9ms   | 65.8ms   | -11%    |
| update/wasm64/ic0_msg_deadline()                            | -        | 64.7ms   | -       |

Average speedup of the local (new) changes: +2% (time)

Note: marked calls have no loop, so those results should not be compared with other calls
