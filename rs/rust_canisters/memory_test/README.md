Build
-----

```
# Build the Wasm binary
cargo build --target wasm32-unknown-unknown --release

# Go to dfinity/rs
cd ../..

# Reduce the Wasm binary size
ic-cdk-optimizer target/wasm32-unknown-unknown/release/memory-test-canister.wasm --output memory-test-canister.wasm
```

Run
---

```
NODE='http://[2001:4d78:40d:0:5000:67ff:fe4f:650d]:8080'
# Payload (a json string) has to be encoded in hex.
PAYLOAD=$(echo -n '{"size":  5000000}'|od -t x1 -A none|xargs|sed -e 's/ //g')
# Run a query
cargo run --release  --bin ic-workload-generator $NODE -r 10 -n 300 \
      -m Query --call-method "query_copy"  --payload $PAYLOAD --canister memory-test-canister.wasm
# Run a replicated query
cargo run --release  --bin ic-workload-generator $NODE -r 10 -n 300 \
      -m Update --call-method "query_copy"  --payload $PAYLOAD --canister memory-test-canister.wasm
# Run an update
cargo run --release  --bin ic-workload-generator $NODE -r 10 -n 300 \
      -m Update --call-method "update_copy"  --payload $PAYLOAD --canister memory-test-canister.wasm
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
```
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
