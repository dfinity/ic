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

Run
---

Create a new `single_large_node` testnet:

```bash
ic$ ci/container/container-run.sh
container:/ic$ ict testnet single_large_node
```

Wait for the setup task to complete:

```bash
============================= Summary =============================
Task setup              PASSED               -- Exited with code 0.
Task debugKeepAliveTask PASSED              
===================================================================
```

Pick the node IP address from the logs above:

```bash
2023-05-04 00:18:43.754 INFO[setup:rs/tests/src/driver/farm.rs:94:0] VM(qkg7v-disch-y7mq6-ny6kj-q6aqr-sfzov-cgfrq-milqk-4veuz-3mxfp-oqe) Host: dm1-dll21.dm1.dfinity.network IPv6: 2604:6800:258:1:5071:f2ff:fea6:3fb1 vCPUs: 64 Memory: 512142680 KiB
```

Run the workload generator:

```bash
# Bazel will produce the build artifacts in `bazel-bin` at the root of the ic repo.
WASM="$(bazel info bazel-bin)/rs/rust_canisters/memory_test/memory_test_canister.wasm"
NODE='http://[2604:6800:258:1:5071:f2ff:fea6:3fb1]:8080'
# Payload (a json string) has to be encoded in hex.
PAYLOAD=$(echo -n '{"size":  5000000}'|od -t x1 -A none|xargs|sed -e 's/ //g')
# Run a query
bazel run //rs/workload_generator:ic-workload-generator -- $NODE -r 10 -n 300 \
      -m Query --call-method "query_copy" --payload $PAYLOAD --canister $WASM
# Run a replicated query
bazel run //rs/workload_generator:ic-workload-generator -- $NODE -r 10 -n 300 \
      -m Update --call-method "query_copy" --payload $PAYLOAD --canister $WASM
# Run an update
bazel run //rs/workload_generator:ic-workload-generator -- $NODE -r 10 -n 300 \
      -m Update --call-method "update_copy" --payload $PAYLOAD --canister $WASM
```

Other canister methods can be called similarly:

- `query_read`,
- `query_write`,
- `query_read_write`,
- `query_copy`,
- `query_stable_read`,
- `query_stable_write`,
- `query_stable_read_write`,
- `update_read`,
- `update_write`,
- `update_read_write`,
- `update_stable_read`,
- `update_stable_write`,
- `update_stable_read_write`,
- `update_copy`.

The payload JSON has the following structure:

```bash
payload = {
  "repeat": <usize, optional, default=1>,
  "address": <usize, optional, default=random>,
  "size": <usize, required>,
  "value": <u8, optional, default=random>,
};
```

- The `repeat` field specifies how many time to repeat the operation within a single message.
- The `address` field specifies the start address of the memory range (8 bytes aligned).
- The `size` field specifies the size of the memory range in bytes (8 bytes aligned).
- The `value` field specifies the value to write or the expected value to read.
