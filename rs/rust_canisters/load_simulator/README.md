Load Simulator Canister
=======================

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