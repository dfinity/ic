"""
This module contains utilities to work with fuzz tests.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")

# These are rustc flags that can be used with the Rust nightly toolchain to build fuzz tests for libfuzzer.
# NOTE: make sure this stays in sync with bazel/rust.MODULE.bazel
DEFAULT_RUSTC_FLAGS = [
    "-Cpasses=sancov-module",
    "-Cllvm-args=-sanitizer-coverage-level=4",
    "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
    "-Cllvm-args=-sanitizer-coverage-pc-table",
    "-Cllvm-args=-sanitizer-coverage-trace-compares",
    "-Cllvm-args=-sanitizer-coverage-stack-depth",
    "-Cllvm-args=-sanitizer-coverage-prune-blocks=0",
    "-Ctarget-cpu=native",
    "-Coverflow_checks",
    "-Copt-level=3",
    "-Clink-dead-code",
    "-Cdebug-assertions",
    "-Ccodegen-units=1",
    "-Zextra-const-ub-checks",
    "-Zstrict-init-checks",
    # TODO(PSEC): Add configuration to enable only during profiling
    # "-Cinstrument-coverage",
]

# NOTE: make sure this stays in sync with bazel/rust.MODULE.bazel
DEFAULT_SANITIZERS = [
    "-Zsanitizer=address",
    # zig doesn't like how rustc pushes the sanitizers, so do it ourselves.
    "-Zexternal-clangrt",
    "-Clink-arg=bazel-out/k8-opt/bin/external/rules_rust++rust+rust_linux_x86_64__x86_64-unknown-linux-gnu__stable_tools/rust_toolchain/lib/rustlib/x86_64-unknown-linux-gnu/lib/librustc-stable_rt.asan.a",
]

# This flag will be used by third party crates and internal rust_libraries during fuzzing
# NOTE: make sure this stays in sync with bazel/rust.MODULE.bazel
DEFAULT_RUSTC_FLAGS_FOR_FUZZING = DEFAULT_RUSTC_FLAGS + DEFAULT_SANITIZERS

def rust_fuzz_test_binary(name, srcs, rustc_flags = [], sanitizers = [], crate_features = [], proc_macro_deps = [], deps = [], allow_main = False, **kwargs):
    """Wrapper for the rust_binary to compile a fuzzing rust_binary

    Args:
      name: name of the fuzzer target.
      srcs: source files for the fuzzer.
      rustc_flags: Additional rustc_flags for rust_binary rule.
      sanitizers: Sanitizers for the fuzzer target. If nothing is provided, address sanitizer is added by default.
      crate_features: Additional crate_features to be used for compilation.
            fuzzing is added by default.
      deps: Fuzzer dependencies.
      allow_main: Allow the fuzzer to export a main function.
      proc_macro_deps: Fuzzer proc_macro dependencies.
      **kwargs: additional arguments to pass a rust_binary rule.
    """

    if not sanitizers:
        sanitizers = DEFAULT_SANITIZERS

    # This would only work inside the devcontainer
    if allow_main:
        TAGS = ["sandbox_libfuzzer"]
    else:
        # default
        TAGS = []

    RUSTC_FLAGS_LIBFUZZER = DEFAULT_RUSTC_FLAGS + ["-Clink-arg=$(location @libfuzzer//:fuzzer)"]

    kwargs.setdefault("testonly", True)

    rust_binary(
        name = name,
        srcs = srcs,
        aliases = {},
        crate_features = crate_features + ["fuzzing"],
        proc_macro_deps = proc_macro_deps,
        deps = deps,
        compile_data = ["@libfuzzer//:fuzzer"],
        rustc_flags = rustc_flags + RUSTC_FLAGS_LIBFUZZER + sanitizers,
        tags = [
            # Makes sure this target is not run in normal CI builds. It would fail due to non-nightly Rust toolchain.
            "fuzz_test",
            "libfuzzer",
        ] + TAGS,
        **kwargs
    )

# TODO(PSEC): Enable allow_main for AFL fuzzers
def rust_fuzz_test_binary_afl(name, srcs, rustc_flags = [], crate_features = [], proc_macro_deps = [], deps = [], **kwargs):
    """Wrapper for the rust_binary to compile a fuzzing rust_binary compatible with AFL

    Args:
      name: name of the fuzzer target.
      srcs: source files for the fuzzer.
      rustc_flags: Additional rustc_flags for rust_binary rule.
      crate_features: Additional crate_features to be used for compilation.
            fuzzing is added by default.
      deps: Fuzzer dependencies.
      proc_macro_deps: Fuzzer proc_macro dependencies.
      **kwargs: additional arguments to pass a rust_binary rule.
    """

    RUSTC_FLAGS_AFL = DEFAULT_RUSTC_FLAGS + [
        "-Cllvm-args=-sanitizer-coverage-trace-pc-guard",
        "-Clink-arg=-fuse-ld=gold",
        "-Clink-arg=-fsanitize=fuzzer",
        "-Clink-arg=-fsanitize=address",
    ]

    kwargs.setdefault("testonly", True)

    rust_binary(
        name = name,
        srcs = srcs,
        aliases = {},
        rustc_env = {
            "AFL_LLVM_LAF_ALL": "1",
            "AFL_USE_ASAN": "1",
            "AFL_USE_LSAN": "1",
        },
        crate_features = crate_features + ["fuzzing"],
        proc_macro_deps = proc_macro_deps,
        deps = deps,
        rustc_flags = rustc_flags + RUSTC_FLAGS_AFL,
        tags = [
            # Makes sure this target is not run in normal CI builds. It would fail due to non-nightly Rust toolchain.
            "fuzz_test",
            "afl",
        ],
        **kwargs
    )
