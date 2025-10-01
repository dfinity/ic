Execution Benchmarks
====================

This directory contains Execution Environment benchmarks, along with scripts
to run them and baseline results for comparing new changes.

Quick Start
-----------

1. To run all benchmarks and compare them to the committed baseline:

   ```sh
   ./rs/execution_environment/benches/run-all-benchmarks.sh | tee summary.txt
   ```

   The summary will be generated in the `summary.txt` file.

   To run only the Embedders Heap benchmarks for `wasm32` query reads:

   ```sh
   INCLUDE=heap FILTER=wasm32_query_read ./rs/execution_environment/benches/run-all-benchmarks.sh
   ```

2. To update the baseline:

   ```sh
   ls *.min | while read name; do cp -v ${name} rs/execution_environment/benches/baseline/${name%@*.min}.min; done
   git add rs/execution_environment/benches/baseline/*
   git commit -m "Update benches baseline"
   ```

Which benchmarks to run?
------------------------

The Execution Environment benchmarks cover the following:

1. Embedders Compilation: `//rs/embedders:compilation_bench`

   Benchmarks for compiling and running synthetic and real-world canisters.
   Useful for assessing compilation-related changes and real-world application performance.

2. Embedders Heap: `//rs/embedders:heap_bench`

   Benchmarks for heavy memory operations on the heap.
   Useful for assessing memory subsystem changes.

3. Embedders Stable Memory: `//rs/embedders:stable_memory_bench`

   Benchmarks for heavy stable memory operations.
   Useful for assessing stable memory changes.

4. System API benchmarks: `//rs/execution_environment:execute_update_bench`, etc.

   Several benchmark suites to assess System API performance in various execution modes.
   Useful for assessing System API-related changes.

5. Wasm Instructions: `//rs/execution_environment:wasm_instructions_bench`

   Benchmarks to assign a cost for each Wasm instruction.
   Should be run after every wasmtime upgrade and when adding new Wasm instructions.

6. Load simulator canister benchmarks: `//rs/execution_environment:load_simulator_canisters_bench`

   Simulates load on a subnet by running many Rust `load_simulator_canister`s.
   Benchmark's throughput roughly corresponds to the subnet finalization rate.
   Useful for assessing scheduler changes, canister sandbox improvements, etc.

All of these are primarily micro-benchmarks, allowing for quick development iterations.
However, it's important to run final benchmarks on a testnet.

The [subnet-load-tester](https://github.com/dfinity/subnet-load-tester) can be used
to run scenarios on a production-like testnet.

Where to run the benchmarks?
----------------------------

Both the baseline results and new change benchmarks should be run on the same host.
The benchmark scripts enforce this and will not compare results produced on
different hosts.

The best candidate for running the benchmarks is the `zh1-spm34` host.

Running the benchmarks in a dev container is also supported:

   ```sh
   ./ci/container/container-run.sh ./rs/execution_environment/benches/run-all-benchmarks.sh
   ```

Adding New Benchmarks
---------------------

1. Create a new benchmark and test it with `bazel run ...`.

2. To test the new benchmark in every CI pipeline run:

   ```Starlark
   rust_ic_bench(
      name = "my_new_bench",
      test_name = "my_new_bench_test",
      test_timeout = "long", # default to "moderate"
      [...]
   )
   ```

   Note: a single benchmark iteration should run in a reasonable amount of time:

   ```sh
   bazel run //rs/execution_environment:my_new_bench -- --test
   ```

3. To include the new benchmark in the comparison:

   Edit the script: `rs/execution_environment/benches/run-all-benchmarks.sh`

4. To run the benchmark nightly in CI and track the results in Grafana:

   Edit the file: `.github/workflows/schedule-rust-bench.yml`
   Add a Grafana dashboard: [example PR](https://github.com/dfinity-ops/k8s/pull/1100)
