#!/usr/bin/env bash
# Wrapper around afl-clang-lto used as Rust's linker driver (-Clinker=...).
# Rustc unconditionally passes -pass-exit-codes when it detects a gcc-flavor
# linker, but that flag is GCC-specific and rejected by Clang.  Strip it here
# before forwarding the rest of the arguments to afl-clang-lto.
args=()
for arg in "$@"; do
    case "$arg" in
        -pass-exit-codes) ;;
        *) args+=("$arg") ;;
    esac
done
exec afl-clang-lto "${args[@]}"
