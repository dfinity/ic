"""
Build libfuzzer to ensure compatibility with our toolchain, and so that it can
be optionally linked by the fuzzers.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def libfuzzer_repository():
    maybe(
        http_archive,
        name = "libfuzzer",
        build_file_content = """
load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "fuzzer",
    srcs = glob(["*.cpp"]),
    hdrs = glob(["*.h"]),
    additional_compiler_inputs = glob(["*.def"]),
    cxxopts = ["-g", "-O2", "-fno-omit-frame-pointer", "-std=c++17"],
    linkstatic = True,
    visibility = ["//visibility:public"],
)
""",
        integrity = "sha256-CLw4JzN3fdo8liWeNzL/lsHfmNBHDE+FsWMnTq5of08=",
        strip_prefix = "llvm-project-llvmorg-20.1.0/compiler-rt/lib/fuzzer",
        urls = ["https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-20.1.0.tar.gz"],
    )
