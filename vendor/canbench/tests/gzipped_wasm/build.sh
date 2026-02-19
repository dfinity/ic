#!/usr/bin/env bash
set -euo pipefail

cargo build --release --target wasm32-unknown-unknown --locked
gzip -n -f "../../target/wasm32-unknown-unknown/release/gzipped_wasm.wasm"
