#!/usr/bin/env bash
set -xeuo pipefail

cd "$CI_PROJECT_DIR"
cargo fmt -- --check
cargo clippy --locked --all-features --workspace --all-targets -- \
    -D warnings \
    -D clippy::all \
    -D clippy::mem_forget \
    -C debug-assertions=off

if cargo tree --workspace --depth 1 -e features | grep -q 'serde feature "rc"'; then
    echo 'The serde "rc" feature seems to be enabled. Instead, the module "serde_arc" in "ic-utils" should be used.'
    exit 1
fi

cargo run -q -p depcheck
