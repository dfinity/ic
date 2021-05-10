#! /usr/bin/env bash

set -e

# This is a helper script to compile Ledger Archive canister Rust code to Wasm
# and then round trip through wasm2wat and wat2wasm in order to minimize the
# output

echo "Compiling Rust to Wasm"
cargo build --release --bin ledger-archive-node-canister -Z unstable-options --out-dir . --target wasm32-unknown-unknown
echo "Converting Wasm to Wat"
wasm2wat ledger-archive-node-canister.wasm -o ledger-archive-node-canister.wat
echo "Converting Wat to Wasm"
wat2wasm ledger-archive-node-canister.wat -o ledger-archive-node-canister.wasm
echo "Removing Wat file"
rm ledger-archive-node-canister.wat
echo "Done!"
