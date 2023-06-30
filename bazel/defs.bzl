"""
Utilities for building IC replica and canisters.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_test")
load("//publish:defs.bzl", "release_nostrip_binary")

_COMPRESS_CONCURENCY = 16

def _compress_resources(_os, _input_size):
    """ The function returns resource hints to bazel so it can properly schedule actions.

    Check https://bazel.build/rules/lib/actions#run for `resource_set` parameter to find documentation of the function, possible arguments and expected return value.
    """
    return {"cpu": _COMPRESS_CONCURENCY}

def _gzip_compress(ctx):
    """GZip-compresses source files.
    """
    out = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.run_shell(
        command = "{pigz} --processes {concurency} --no-name {srcs} --stdout > {out}".format(pigz = ctx.file._pigz.path, concurency = _COMPRESS_CONCURENCY, srcs = " ".join([s.path for s in ctx.files.srcs]), out = out.path),
        inputs = ctx.files.srcs,
        outputs = [out],
        tools = [ctx.file._pigz],
        resource_set = _compress_resources,
    )
    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles(files = [out]))]

gzip_compress = rule(
    implementation = _gzip_compress,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "_pigz": attr.label(allow_single_file = True, default = "@pigz"),
    },
)

def _zstd_compress(ctx):
    """zstd-compresses source files.
    """
    out = ctx.actions.declare_file(ctx.label.name)

    # TODO: install zstd as depedency.
    ctx.actions.run(
        executable = "zstd",
        arguments = ["--threads=0", "-10", "-f", "-z", "-o", out.path] + [s.path for s in ctx.files.srcs],
        inputs = ctx.files.srcs,
        outputs = [out],
        env = {"ZSTDMT_NBWORKERS_MAX": str(_COMPRESS_CONCURENCY)},
        resource_set = _compress_resources,
    )
    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles(files = [out]))]

zstd_compress = rule(
    implementation = _zstd_compress,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
    },
)

def _sha256sum2url_impl(ctx):
    """
    Returns cas url pointing to the artifact with checksum specified.

    Waits for the artifact to be published before returning url.
    """
    out = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.run(
        executable = "timeout",
        arguments = ["10m", ctx.executable._sha256sum2url_sh.path],
        inputs = [ctx.file.src],
        outputs = [out],
        tools = [ctx.executable._sha256sum2url_sh],
        env = {
            "SHASUMFILE": ctx.file.src.path,
            "OUT": out.path,
        },
    )
    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles(files = [out]))]

_sha256sum2url = rule(
    implementation = _sha256sum2url_impl,
    attrs = {
        "src": attr.label(allow_single_file = True),
        "_sha256sum2url_sh": attr.label(executable = True, cfg = "exec", default = "//bazel:sha256sum2url_sh"),
    },
)

def sha256sum2url(name, src, tags = [], **kwargs):
    """
    Returns cas url pointing to the artifact which checksum is returned by src.

    The rule waits until the cache will return http/200 for this artifact.
    The rule adds "requires-network" as it needs to talk to bazel cache and "manual" to only be performed
    when its result is requested (directly or by another rule) to not wait when not required.

    Args:
        name:     the name of the rule
        src:      the label that returns the file with sha256 checksum of requested artifact.
        tags:     additinal tags.
        **kwargs: the rest of arguments to be passed to the underlying rule.
    """
    _sha256sum2url(
        name = name,
        src = src,
        tags = tags + ["requires-network", "manual"],
        **kwargs
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
            fail("Wrong file in extra_srcs: " + extra_src + ". extra_srcs should have `.rs` extensions")

    for src in srcs:
        if not src.endswith(".rs"):
            fail("Wrong file in srcs: " + src + ". srcs should have `.rs` extensions")

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

def rust_bench(name, env = {}, data = [], **kwargs):
    """A rule for defining a rust benchmark.

    Args:
      name: the name of the executable target.
      env: additional environment variables to pass to the benchmark binary.
      data: data dependencies required to run the benchmark.
      **kwargs: see docs for `rust_binary`.
    """

    # The initial binary is a regular rust_binary with rustc flags as in the
    # current build configuration.
    binary_name_initial = "_" + name + "_bin_default"
    rust_binary(name = binary_name_initial, **kwargs)

    # The "publish" binary has the same compiler flags applied as for production build.
    binary_name_publish = "_" + name + "_bin_publish"
    release_nostrip_binary(
        name = binary_name_publish,
        binary = binary_name_initial,
        testonly = kwargs.get("testonly", False),
    )

    # The benchmark binary is a shell script that runs the binary
    # (similar to how `cargo bench` runs the benchmark binary).
    native.sh_binary(
        srcs = ["//bazel:generic_rust_bench.sh"],
        name = name,
        # Allow benchmark targets to use test-only libraries.
        testonly = kwargs.get("testonly", False),
        env = dict(env.items() + {"BAZEL_DEFS_BENCH_BIN": "$(location :%s)" % binary_name_publish}.items()),
        data = data + [":" + binary_name_publish],
        tags = kwargs.get("tags", []) + ["rust_bench"],
    )
