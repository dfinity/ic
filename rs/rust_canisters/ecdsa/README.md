ECDSA Canister
================================

Build
-----

```bash
# Build the Wasm binary
bazel build //rs/rust_canisters/ecdsa:ecdsa-canister

# Find the optimized canister binary from the root `ic` directory:
ls -l bazel-bin/rs/rust_canisters/ecdsa/ecdsa-canister.wasm
# From other directories:
ls -l $(bazel info bazel-bin)/rs/rust_canisters/ecdsa/ecdsa-canister.wasm
```

Run
---

```bash
# Enable ECDSA signing on a subnet:
NNS_URL='http://[2001:4d78:40d:0:5000:67ff:fe4f:650d]:8080' # An NNS node
SUBNET=ovko3-ja43o-cjmxw-ayco4-67g7l-nckpi-rplb7-cw3tc-vyoum-35bip-lqe
ic-admin --nns-url $NNS_URL propose-to-update-subnet --subnet $SUBNET --ecdsa-keys-to-generate Secp256k1:test_key  --test-neuron-proposer
ic-admin --nns-url $NNS_URL propose-to-update-subnet --subnet $SUBNET --ecdsa-key-signing-enable Secp256k1:test_key  --test-neuron-proposer

# Payload (a json string) has to be encoded in hex.
PAYLOAD=$(didc encode '(record {derivation_path = vec {}; key_name = "test_key" })' -d rust_canisters/ecdsa/ecdsa.did -t '(Options)')
# Run workload
cargo run --release --bin ic-workload-generator $NNS_URL -r 10 -n 300 -m Update --call-method "get_sig" --payload $PAYLOAD --canister ecdsa-canister.wasm
```
