#!/usr/bin/env bash
set -xeuo pipefail

cd "${CI_PROJECT_DIR:-$(git rev-parse --show-toplevel)}"

cargo fmt -- --check

if ! cargo clippy --locked --all-features --workspace --all-targets --keep-going -- \
    -D warnings \
    -D clippy::all \
    -D clippy::mem_forget \
    -D clippy::unseparated_literal_suffix \
    -A clippy::uninlined_format_args; then
    # Don't just explode: provide a solution. Our job is to provide
    # solid gold, not raw ore.
    echo ""
    echo "========================================"
    echo -ne "\033[1;31m" # Start red.
    echo "Clippy violations found!"
    echo -ne "\033[0m" # Clear formatting.
    echo ""
    echo -ne "\033[1;32m" # Start green.
    echo "To automatically fix many of these, run:"
    echo ""
    echo "    cargo clippy --fix"
    echo -ne "\033[0m" # Clear formatting.
    echo ""
    echo "========================================"
    exit 1
fi

if cargo tree --workspace --depth 1 -e features | grep -q 'serde feature "rc"'; then
    echo 'The serde "rc" feature seems to be enabled. Instead, the module "serde_arc" in "ic-utils" should be used.'
    exit 1
fi

cargo run -q -p depcheck
