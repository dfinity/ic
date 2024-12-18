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

Run
---

To quickly generate 100K canisters, run 10 instances of the canister creator in parallel.

```bash
export NODE='http://[2602:fb2b:110:10:5000:67ff:fe4f:650d]:8080'
# Payload (a json string) has to be encoded in hex.
export PAYLOAD=$(echo -n '10000'|od -t x1 -A none|xargs|sed -e 's/ //g')
seq 1 10 | xargs -n 1 -P 10 bash run.sh

# Where run.sh contains:
# Bazel will produce the build artifacts in `bazel-bin` at the root of the ic repo.
WASM="$(bazel info bazel-bin)/rs/rust_canisters/canister_creator/canister_creator_canister.wasm"
bazel run //rs/workload_generator:ic-workload-generator $NODE -r 1 -n 1 \
      -m Update --call-method "create_canisters" --payload $PAYLOAD --canister canister_creator_canister.wasm
```
