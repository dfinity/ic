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

def rust_fuzz_test_binary(name, srcs, rustc_flags = [], crate_features = [], proc_macro_deps = [], deps = [], **kwargs):
    """Wrapper for the rust_binary to compile a fuzzing rust_binary

    Args:
      name: name of the fuzzer target.
      srcs: source files for the fuzzer.
      rustc_flags: Additional rustc_flags for rust_binary rule. This facilitates using additional sanitizers to the fuzzer target.
            Address sanitizer is added by default.
      crate_features: Additional crate_features to be used for compilation.
            fuzzing is added by default.
      deps: Fuzzer dependencies.
      proc_macro_deps: Fuzzer proc_macro dependencies.
      **kwargs: additional arguments to pass a rust_binary rule.
    """
    rust_binary(
        name = name,
        srcs = srcs,
        aliases = {},
        crate_features = crate_features + ["fuzzing"],
        proc_macro_deps = proc_macro_deps,
        deps = deps,
        rustc_flags = rustc_flags + RUSTC_FLAGS_DEFAULTS_FOR_FUZZING,
        tags = [
            # Makes sure this target is not run in normal CI builds. It would fail due to non-nightly Rust toolchain.
            "fuzz_test",
        ],
        **kwargs
    )
