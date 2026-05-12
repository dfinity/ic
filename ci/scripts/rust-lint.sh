#!/usr/bin/env bash
set -xeuo pipefail

cd "${CI_PROJECT_DIR:-$(git rev-parse --show-toplevel)}"

cargo fmt -- --check

clippy_args=(
    # Do not modify Cargo.lock.
    --locked

    # For comprehensiveness.
    --all-features
    --workspace
    --all-targets

    # Don't stop at the first error, but rather, report ALL of them.
    --keep-going

    # Everything after this is forwarded from cargo to the clippy binary itself.
    --

    # Be strict.
    --deny warnings
    --deny clippy::all

    # Ban std::mem::forget, because it is a memory leak hazard.
    --deny clippy::mem_forget

    # Require 42_u64, as opposed to 42u64. Because spaces good.
    --deny clippy::unseparated_literal_suffix

    # Allow format!("{}", x) instead of format!("{x}").
    --allow clippy::uninlined_format_args
)
if ! cargo clippy "${clippy_args[@]}"; then
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
    echo "    cargo clippy --fix ${clippy_args[@]}"
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
