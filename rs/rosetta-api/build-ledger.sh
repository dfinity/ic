#!/bin/bash
set -euo pipefail

cargo build --target wasm32-unknown-unknown --release --bin ledger-canister -p ledger-canister
# This is the worlds most primitive way of doing tree shaking, but it trims 18MB of the size of the canister
wasm2wat ../target/wasm32-unknown-unknown/release/ledger-canister.wasm -o ../target/wasm32-unknown-unknown/release/ledger-canister.wat
wat2wasm ../target/wasm32-unknown-unknown/release/ledger-canister.wat -o ../target/wasm32-unknown-unknown/release/ledger-canister-min.wasm
