Response Payload Canister Quick Start
================================

A canister that generates responses (consisting of all 0s) whose size
is specified in the request (using the response_size field).

Build
-----

```bash
# Build the Wasm binary
cargo build --target wasm32-unknown-unknown --release

# Go to ic/rs
cd ../..

# Optional: install ic-cdk-optimizer
cargo install ic-cdk-optimizer

# Reduce the Wasm binary size
ic-cdk-optimizer target/wasm32-unknown-unknown/release/response-payload-test-canister.wasm --output response-payload-test-canister.wasm
```

Run
---

```bash
NODE='http://[2001:4d78:40d:0:5000:67ff:fe4f:650d]:8080'
# Payload (a json string) has to be encoded in hex.
PAYLOAD=$(echo -n '{"response_size":  5000000}'|od -t x1 -A none|xargs|sed -e 's/ //g')
# Run a query
cargo run --release --bin ic-workload-generator $NODE -r 10 -n 300 \
      -m Query --call-method "query" --payload $PAYLOAD --canister payload-response-test-canister.wasm
# Run an update
cargo run --release --bin ic-workload-generator $NODE -r 10 -n 300 \
      -m Update --call-method "update" --payload $PAYLOAD --canister payload-response-test-canister.wasm
```
The payload JSON has the following structure:

```bash
payload = {
  "response_size": <usize, required>,
};
```

- The `response_size` field specifies the size of response in bytes.

