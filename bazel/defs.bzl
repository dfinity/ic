"""
Utilities for building IC replica and canisters.
"""

load("@rules_rust//rust:defs.bzl", "rust_test")

def gzip_compress(name, srcs):
    """GZip-compresses source files.

    Args:
      name: name of the compressed file.
      srcs: list of input labels.
    """
    native.genrule(
        name = "_compress_" + name,
        exec_tools = ["@pigz"],
        srcs = srcs,
        outs = [name],
        message = "Compressing into %s" % name,
        cmd_bash = "$(location @pigz) $(SRCS) --stdout > $@",
    )

def rust_test_suite_with_extra_srcs(name, srcs, extra_srcs, **kwargs):
    """ A rule for creating a test suite for a set of `rust_test` targets.

    Like `rust_test_suite`, but with ability to deal with integration
    tests that use common utils across various tests.  The sources of
    the common utils should be specified in extra_srcs` argument.

    Args:
      name: see description for `rust_test_suite`
      srcs: see description for `rust_test_suite`
      extra_srcs: list of files that e.g. implement common utils, must be disjoint from `srcs`
      **kwargs: see description for `rust_test_suite`
    """
    tests = []

    for extra_src in extra_srcs:
        if not extra_src.endswith(".rs"):
            fail("extra_srcs should have `.rs` extensions")

    for src in srcs:
        if not src.endswith(".rs"):
            fail("srcs should have `.rs` extensions")

        # Prefixed with `name` to allow parameterization with macros
        # The test name should not end with `.rs`
        test_name = name + "_" + src[:-3]
        rust_test(
            name = test_name,
            srcs = [src] + extra_srcs,
            crate_root = src,
            **kwargs
        )
        tests.append(test_name)

    native.test_suite(
        name = name,
        tests = tests,
        tags = kwargs.get("tags", None),
    )
