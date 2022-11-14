#!/bin/sh -ex
cargo build --target wasm32-unknown-unknown --release
cargo install ic-cdk-optimizer
ic-cdk-optimizer target/wasm32-unknown-unknown/release/universal-canister.wasm --output universal-canister.wasm
mv universal-canister.wasm ../lib/src/universal-canister.wasm
sha256sum ../lib/src/universal-canister.wasm
