System API Performance
======================

See the latest System API performance report in [SYSTEM_API](SYSTEM_API.md)

Updating the Results
--------------------

The benchmarks now cover 100% of the System API calls, so let's keep it up to date:

1. All the new System API calls should be covered with a benchmark.
2. All the changes which might affect the performance should be benchmarked with `diff-old-vs-new.sh`
3. The final report should be added to the repo and described below in this document.

For more details about System API complexity adjustments see [EXECUTE_UPDATE](EXECUTE_UPDATE.md)

2022-03-17: Normal `release` build profile vs `release-lto` build
-----------------------------------------------------------------

Average speedup of the local changes: +20% (throughput)
Average speedup of the local changes: -18% (time)

2022-03-18: Adjust complexity of all the available System APIs
--------------------------------------------------------------

Average speedup of the local changes: +13% (throughput)
Average speedup of the local changes: +0% (time)

The throughput is higher due to increased complexity:

| API Type / System API Call                 | Remote, IPS | Local, IPS  | Speedup |
| ------------------------------------------ | ----------- | ----------- | ------- |
| callback/ic0_msg_reject_msg_copy()/1B      |        168M |        393M |   +133% |
| callback/ic0_msg_reject_msg_copy()/10B     |        276M |        495M |    +79% |
| update/ic0_msg_reject()*                   |       13.3K |       99.8K |   +650% |
| update/ic0_call_simple()                   |       80.2M |       92.6M |    +15% |
| update/call_new+ic0_call_data_append()/1B  |       62.8M |        118M |    +87% |
| update/call_new+ic0_call_data_append()/8K  |       17.2G |       17.1G |     -1% |

While the actual time executing the system calls is +- the same as there were no semantic changes:

| API Type / System API Call                 | Remote Time | Local Time  | Speedup |
| ------------------------------------------ | ----------- | ----------- | ------- |
| callback/ic0_msg_reject_msg_copy()/1B      |        83ms |      86.4ms |     +4% |
| callback/ic0_msg_reject_msg_copy()/10B     |      83.1ms |      86.8ms |     +4% |
| update/ic0_msg_reject()*                   |       224us |       230us |     +2% |
| update/ic0_call_simple()                   |       1.50s |       1.52s |     +1% |
| update/call_new+ic0_call_data_append()/1B  |       350ms |       355ms |     +1% |
| update/call_new+ic0_call_data_append()/8K  |       476ms |       479ms |     +0% |
