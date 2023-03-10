"""
This module contains utilities to work with fuzz tests.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")

# These are rustc flags that can be used with the Rust nightly toolchain to build fuzz tests for libfuzzer.
RUSTC_FLAGS_DEFAULTS_FOR_FUZZING = [
    "-Cpasses=sancov-module",
    "-Cllvm-args=-sanitizer-coverage-level=4",
    "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
    "-Cllvm-args=-sanitizer-coverage-pc-table",
    "-Cllvm-args=-sanitizer-coverage-trace-compares",
    "-Cllvm-args=-sanitizer-coverage-stack-depth",
    "-Clink-dead-code",
    "-Cinstrument-coverage",
    "-Cdebug-assertions",
    "-Ccodegen-units=1",
    "-Zsanitizer=address",
]

def rust_fuzz_test_binary(name, srcs, proc_macro_deps = [], deps = []):
    # Builds the fuzzer using the Rust nightly toolchain so it can be run by libfuzzer. The fuzzer must be compiled using
    # Rust nightly, e.g.
    # bazel run --@rules_rust//rust/toolchain/channel=nightly --build_tag_filters=fuzz_test //rs/types/ic00_types/fuzz:decode_install_code_args
    rust_binary(
        name = name,
        srcs = srcs,
        aliases = {},
        crate_features = ["fuzzing"],
        proc_macro_deps = proc_macro_deps,
        deps = deps,
        rustc_flags = RUSTC_FLAGS_DEFAULTS_FOR_FUZZING,
        tags = [
            # Makes sure this target is not run in normal CI builds. It would fail due to non-nightly Rust toolchain.
            "fuzz_test",
        ],
    )
