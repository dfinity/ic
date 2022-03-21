System API Performance
======================

See the latest System API performance report in [SYSTEM_API](SYSTEM_API.md)

Updating the Results
--------------------

The benchmarks now cover 100% of the System API calls, so let's keep it up to date:

1. All the new System API calls should be covered with a benchmark.
2. All the changes which might affect the performance should be benchmarked with `local-vs-remote.sh`
3. The final report should be added to the repo and described below in this document.

For more details about System API complexity adjustments see [EXECUTE_UPDATE](EXECUTE_UPDATE.md)

2022-03-17: Normal `release` build profile vs `release-lto` build
-----------------------------------------------------------------

Average speedup of the local changes: +20% (throughput)
Average speedup of the local changes: -18% (time)
