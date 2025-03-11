Canister Creator Canister Quick Start
=====================================

Build
-----

```bash
# Build the Wasm binary
bazel build //rs/rust_canisters/canister_creator:canister_creator_canister

# Find the optimized canister binary from the root `ic` directory:
ls -l bazel-bin/rs/rust_canisters/canister_creator/canister_creator_canister.wasm
# From other directories:
ls -l $(bazel info bazel-bin)/rs/rust_canisters/canister_creator/canister_creator_canister.wasm
```