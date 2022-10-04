"""
Rules for system-tests.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("//bazel:bin_test.bzl", "bin_test")

def system_test(name, test_timeout = "short", **kwargs):
    """
    Declares a system-test.
    """
    rust_binary(
        name = name + "_bin",
        srcs = ["bin/" + name + ".rs"],
        **kwargs
    )

    bin_test(
        name = name,
        src = name + "_bin",
        args = ["--working-dir", ".", "run"],
        timeout = test_timeout,
    )
