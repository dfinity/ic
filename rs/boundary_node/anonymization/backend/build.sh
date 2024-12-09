#!/bin/sh

NAME="anonymization_backend"
OUTPUT="target/wasm32-unknown-unknown/release/${NAME}.wasm"

# Build
cargo build \
    --release \
    --target wasm32-unknown-unknown \
    --target-dir target \
    -p "${NAME}" \
    --locked

# Shrink
ic-wasm "${OUTPUT}" -o "${OUTPUT}" shrink

# Compress
gzip -f "${OUTPUT}"
