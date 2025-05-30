Load Simulator Canister
=======================

This `load_simulator` canister is used in `load_simulator_canisters` benchmark.
By default, each `load_simulator` canister runs a periodic timer with
a one-second interval and accesses stable memory every fifth call.

This benchmark and canister are useful for debugging and benchmarking scheduler
and sandbox eviction changes.

For more realistic testnet load tests, refer to the `dfinity/subnet-load-tester` project.
For more details see the `load_simulator_canisters` benchmark.

Build
-----

```bash
# Build the Wasm binary
bazel build //rs/rust_canisters/load_simulator:load_simulator_canister

# Find the optimized canister binary from the root `ic` directory:
ls -l bazel-bin/rs/rust_canisters/load_simulator/load_simulator_canister.wasm.gz
# From other directories:
ls -l $(bazel info bazel-bin)/rs/rust_canisters/load_simulator/load_simulator_canister.wasm.gz
```
