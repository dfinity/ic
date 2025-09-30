Execution Cost Strategy
=======================

All execution costs should eventually be based on benchmarks and listed
in this document. Benchmarks should run periodically (ideally, daily in CI),
and if there is significant divergence from the current cost,
adjustments should be made.

In general, the cost (in instructions) is derived from benchmark results
and the fact that our target one-second round has 2 billion instructions.
For example, a workload executing for `1/10` second should cost
`2 * 1/10` billion instructions.

Compilation Cost
----------------

Each Wasm instruction has an associated compilation overhead defined
by `DEFAULT_COST_TO_COMPILE_WASM_INSTRUCTION` and other compilation limits.

1. ✅ Runs daily on CI.
2. ✅ Results are available in [Grafana](https://grafana.mainnet.dfinity.network/d/benchmarks-embedders-compilation/benchmarks3a-embedders-compilation).
3. ✅ Raw benchmark:
    * `bazel run //rs/embedders:compilation_bench`
4. ✅ Baseline comparison:
    * `INCLUDE=compilation ./rs/execution_environment/benches/run-all-benchmarks.sh`

TODO(EXC-2040): There is no script to derive the cost based on benchmark results.

Heap Memory Overhead
--------------------

Each Wasm heap memory page has an associated overhead defined
by `DEFAULT_DIRTY_PAGE_OVERHEAD` and other costs.

1. ✅ Runs daily on CI.
2. ✅ Results are available in [Grafana](https://grafana.mainnet.dfinity.network/d/benchmarks-embedders-heap/benchmarks3a-embedders-heap).
3. ✅ Raw benchmark:
    * `bazel run //rs/embedders:heap_bench`
4. ✅ Baseline comparison:
    * `INCLUDE=heap ./rs/execution_environment/benches/run-all-benchmarks.sh`

TODO(EXC-2040): There is no script to derive the cost based on benchmark results.

Management Canister Calls
-------------------------

A few management canister calls have an associated overhead defined
by `DEFAULT_UPLOAD_CHUNK_INSTRUCTIONS`, `DEFAULT_CANISTERS_SNAPSHOT_BASELINE_INSTRUCTIONS`,
etc.

1. ❌ Doesn't run on CI.
2. ❌ Results are not available in Grafana.
3. ✅ Raw benchmark:
    * `bazel run //rs/execution_environment:management_canister_bench`
4. ❌ Baseline is not available.

TODO(EXC-2040): The following scripts should be updated to use the `*.min` files.

Scripts: `rs/execution_environment/benches/management_canister/*`

1. Run `run_snapshot_benchmarks_forever.sh` to generate the `MANAGEMENT_CANISTER.md` file.

Stable Memory Overhead
----------------------

Each Wasm stable memory page has an associated overhead defined
by `DEFAULT_DIRTY_PAGE_OVERHEAD` and other costs.

1. ✅ Runs daily on CI.
2. ✅ Results are available in [Grafana](https://grafana.mainnet.dfinity.network/d/benchmarks-embedders-stable-memory/benchmarks3a-embedders-stable-memory).
3. ✅ Raw benchmark:
    * `bazel run //rs/embedders:stable_memory_bench`
4. ✅ Baseline comparison:
    * `INCLUDE=stable ./rs/execution_environment/benches/run-all-benchmarks.sh`

TODO(EXC-2040): There is no script to derive the cost based on benchmark results.

System API
----------

Each System API call has an associated overhead defined in
the `system_api_complexity.rs` file.

1. ✅ Runs daily on CI.
2. ✅ Results are available in Grafana for:
     * [inspect messages](https://grafana.mainnet.dfinity.network/d/benchmarks-execute-inspect-message/benchmarks3a-execute-inspect-message)
     * [queries](https://grafana.mainnet.dfinity.network/d/benchmarks-execute-query/benchmarks3a-execute-query)
     * [updates](https://grafana.mainnet.dfinity.network/d/benchmarks-execute-update/benchmarks3a-execute-update)
3. ✅ Raw benchmarks:
    * Inspect messages: `bazel run //rs/execution_environment:execute_inspect_message_bench`
    * Queries: `bazel run //rs/execution_environment:execute_query_bench`
    * Updates: `bazel run //rs/execution_environment:execute_update_bench`
4. ✅ Baseline comparison:
    * Inspect messages: `INCLUDE=inspect ./rs/execution_environment/benches/run-all-benchmarks.sh`
    * Queries: `INCLUDE=query ./rs/execution_environment/benches/run-all-benchmarks.sh`
    * Updates: `INCLUDE=update ./rs/execution_environment/benches/run-all-benchmarks.sh`

TODO(EXC-2040): The following scripts should be updated to use the `*.min` files.

Scripts: `rs/execution_environment/benches/system_api/*`

1. Run `diff-old-vs-new.sh` to generate the `SYSTEM_API.md` file.

Wasm Instructions
-----------------

Each Wasm instruction has its own weight set in the `instruction_to_cost()` function.

1. ✅ Runs daily on CI.
2. ✅ Results are available in [Grafana](https://grafana.mainnet.dfinity.network/d/benchmarks-wasm-instructions/benchmarks3a-wasm-instructions).
3. ✅ Raw benchmark:
    * `bazel run //rs/execution_environment:wasm_instructions_bench`
4. ✅ Baseline comparison:
    * `INCLUDE=wasm ./rs/execution_environment/benches/run-all-benchmarks.sh`

TODO(EXC-2040): The following scripts should be updated to use the `*.min` files.

Scripts: `rs/execution_environment/benches/wasm_instructions/*`

1. Run `run_wasm_benchmarks_forever.sh` to generate Wasm instruction costs.
2. Use `instructions_to_cost.sh` to generate the cost table in Rust.
