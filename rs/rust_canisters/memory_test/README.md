Memory Test Canister Quick Start
================================

Build
-----

```bash
# Build the Wasm binary
bazel build //rs/rust_canisters/memory_test:memory_test_canister

# Find the optimized canister binary from the root `ic` directory:
ls -l bazel-bin/rs/rust_canisters/memory_test/memory_test_canister.wasm
# From other directories:
ls -l $(bazel info bazel-bin)/rs/rust_canisters/memory_test/memory_test_canister.wasm
```