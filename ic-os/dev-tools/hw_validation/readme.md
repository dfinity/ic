# IC Hardware Benchmark and Validation Scripts

## Dependencies (ubuntu)

* sysbench
* stress-ng

Install: `sudo apt install sysbench stress-ng`


## benchmark.sh

Uses `sysbench` to gather cpu, memory, file-io performance stats. It will write a log to the working directory.

### Analyze

Side by side including command line invocation and speed differences:

E.g.: `diff -y bench_results_zh2-spm01.zh2.dfinity.network_2022-08-12T21-08-32.txt bench_results_zh2-asu01_2022-08-12T23-08-49.txt | fgrep -e"+ sysbench" -e"|" > bench_comparison_gen1_gen2.txt`


## stress.sh

Uses `stress-ng` to exercise all HW components.

Run it: `./stress.sh` - it writes a log file to the working directory.

### Analyze

Visually scan log for errors.

`stress-ng` recommends not to use the reported speeds as benchmarks.