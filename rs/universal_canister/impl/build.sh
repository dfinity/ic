#!/bin/sh -ex
cargo build --target wasm32-unknown-unknown --release
cargo install ic-cdk-optimizer
ic-cdk-optimizer target/wasm32-unknown-unknown/release/universal_canister.wasm --output universal_canister.wasm
mv universal_canister.wasm ../lib/src/universal_canister.wasm
sha256sum ../lib/src/universal_canister.wasm
