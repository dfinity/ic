#!/usr/bin/env bash
set -euo pipefail

clippy_args=(
    # Do not modify Cargo.lock.
    --locked

    # For comprehensiveness.
    --workspace
    --all-features
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

exec cargo clippy "$@" "${clippy_args[@]}"
