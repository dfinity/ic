#!/usr/bin/env bash
set -xeuo pipefail

cd "$CI_PROJECT_DIR/rs"
cargo fmt --all -- --check
cargo clippy --locked --all-features --tests --benches -- -D warnings -D clippy::all -D clippy::mem_forget -C debug-assertions=off

if cargo tree -e features | grep -q 'serde feature "rc"'; then
    echo 'The serde "rc" feature seems to be enabled. Instead, the module "serde_arc" in "ic-utils" should be used.'
    exit 1
fi

cd "$CI_PROJECT_DIR/rs/replica"
cargo check --features malicious_code --locked
