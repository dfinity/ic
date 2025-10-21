"""
Utilities for building IC replica and canisters.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_test", "rust_test_suite")
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")
load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("//publish:defs.bzl", "release_nostrip_binary")

_COMPRESS_CONCURRENCY = 16

def _compress_resources(_os, _input_size):
    """ The function returns resource hints to bazel so it can properly schedule actions.

    Check https://bazel.build/rules/lib/actions#run for `resource_set` parameter to find documentation of the function, possible arguments and expected return value.
    """
    return {"cpu": _COMPRESS_CONCURRENCY}

def _gzip_compress(ctx):
    """GZip-compresses source files.
    """
    out = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.run_shell(
        command = "{pigz} --processes {concurrency} --no-name {srcs} --stdout > {out}".format(pigz = ctx.file._pigz.path, concurrency = _COMPRESS_CONCURRENCY, srcs = " ".join([s.path for s in ctx.files.srcs]), out = out.path),
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

    ctx.actions.run(
        executable = "zstd",
        arguments = ["-q", "--threads=0", "-10", "-f", "-z", "-o", out.path] + [s.path for s in ctx.files.srcs],
        inputs = ctx.files.srcs,
        outputs = [out],
        env = {"ZSTDMT_NBWORKERS_MAX": str(_COMPRESS_CONCURRENCY)},
        resource_set = _compress_resources,
    )
    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles(files = [out]))]

zstd_compress = rule(
    implementation = _zstd_compress,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
    },
)

def _untar(ctx):
    """Unpacks tar archives.
    """
    out = ctx.actions.declare_directory(ctx.label.name)

    ctx.actions.run(
        executable = "tar",
        arguments = ["-xf", ctx.file.src.path, "-C", out.path],
        inputs = [ctx.file.src],
        outputs = [out],
    )
    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles(files = [out]))]

untar = rule(
    implementation = _untar,
    attrs = {
        "src": attr.label(allow_single_file = True),
    },
)

def _mcopy(ctx):
    """Copies Unix files to MSDOS images.
    """
    out = ctx.actions.declare_file(ctx.label.name)

    command = "cp -p {fs} {output} && chmod +w {output} ".format(fs = ctx.file.fs.path, output = out.path)
    for src in ctx.files.srcs:
        command += "&& mcopy -mi {output} -sQ {src_path} ::/{filename} ".format(output = out.path, src_path = src.path, filename = ctx.attr.remap_paths.get(src.basename, src.basename))

    ctx.actions.run_shell(
        command = command,
        inputs = ctx.files.srcs + [ctx.file.fs],
        outputs = [out],
    )
    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles(files = [out]))]

mcopy = rule(
    implementation = _mcopy,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "fs": attr.label(allow_single_file = True),
        "remap_paths": attr.string_dict(),
    },
)

# Binaries needed for testing with canister_sandbox
_SANDBOX_DATA = [
    "//rs/canister_sandbox",
    "//rs/canister_sandbox:compiler_sandbox",
    "//rs/canister_sandbox:sandbox_launcher",
]

# Env needed for testing with canister_sandbox
_SANDBOX_ENV = {
    "COMPILER_BINARY": "$(rootpath //rs/canister_sandbox:compiler_sandbox)",
    "LAUNCHER_BINARY": "$(rootpath //rs/canister_sandbox:sandbox_launcher)",
    "SANDBOX_BINARY": "$(rootpath //rs/canister_sandbox)",
}

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

def rust_ic_test_suite_with_extra_srcs(name, srcs, extra_srcs, env = {}, data = [], **kwargs):
    """ A rule for creating a test suite for a set of `rust_test` targets.

    Like `rust_test_suite_with_extra_srcs`, but adds data and env params required for canister sandbox

    Args:
      see description for `rust_test_suite_with_extra_srcs`
    """
    rust_test_suite_with_extra_srcs(
        name,
        srcs,
        extra_srcs,
        env = dict(env.items() + _SANDBOX_ENV.items()),
        data = data + _SANDBOX_DATA,
        **kwargs
    )

def rust_ic_test_suite(env = {}, data = [], **kwargs):
    """ A rule for creating a test suite for a set of `rust_test` targets.

    Like `rust_test_suite`, but adds data and env params required for canister sandbox

    Args:
      see description for `rust_test_suite`
    """
    rust_test_suite(
        env = dict(env.items() + _SANDBOX_ENV.items()),
        data = data + _SANDBOX_DATA,
        **kwargs
    )

def rust_ic_test(env = {}, data = [], **kwargs):
    """ A rule for creating a test suite for a set of `rust_test` targets.

    Like `rust_test`, but adds data and env params required for canister sandbox

    Args:
      see description for `rust_test`
    """
    rust_test(
        env = dict(env.items() + _SANDBOX_ENV.items()),
        data = data + _SANDBOX_DATA,
        **kwargs
    )

def rust_bench(name, env = {}, data = [], pin_cpu = False, test_name = None, test_timeout = None, **kwargs):
    """A rule for defining a rust benchmark.

    Args:
      name: the name of the executable target.
      env: additional environment variables to pass to the benchmark binary.
      data: data dependencies required to run the benchmark.
      pin_cpu: pins the benchmark process to a single CPU if set `True`.
      test_name: generates test with name 'test_name' to test that the benchmark work.
      test_timeout: timeout to apply in the generated test (default: `moderate`).
      **kwargs: see docs for `rust_binary`.
    """

    kwargs.setdefault("testonly", True)

    # The initial binary is a regular rust_binary with rustc flags as in the
    # current build configuration. It is marked as "manual" because it is not
    # meant to be built.
    binary_name_initial = "_" + name + "_bin_default"
    kwargs_initial = dict(kwargs)
    tags_initial = kwargs_initial.pop("tags", [])
    if "manual" not in tags_initial:
        tags_initial.append("manual")
    rust_binary(name = binary_name_initial, tags = tags_initial, **kwargs_initial)

    # The "publish" binary has the same compiler flags applied as for production build.
    binary_name_publish = "_" + name + "_bin_publish"
    release_nostrip_binary(
        name = binary_name_publish,
        binary = binary_name_initial,
        testonly = kwargs.get("testonly"),
    )

    bench_prefix = "taskset -c 0 " if pin_cpu else ""

    # The benchmark binary is a shell script that runs the binary
    # (similar to how `cargo bench` runs the benchmark binary).
    sh_binary(
        srcs = ["//bazel:generic_rust_bench.sh"],
        name = name,
        # Allow benchmark targets to use test-only libraries.
        testonly = kwargs.get("testonly"),
        env = dict(env.items() +
                   [("BAZEL_DEFS_BENCH_PREFIX", bench_prefix)] +
                   {"BAZEL_DEFS_BENCH_BIN": "$(location :%s)" % binary_name_publish}.items()),
        data = data + [":" + binary_name_publish],
        tags = kwargs.get("tags", []) + ["rust_bench"],
    )

    # To test that the benchmarks work.
    if test_name != None:
        test_timeout = test_timeout or "moderate"
        sh_test(
            name = test_name,
            testonly = True,
            timeout = test_timeout,
            env = env,
            srcs = [":" + binary_name_publish],
            data = data,
            tags = kwargs.get("tags", None),
        )

def rust_ic_bench(env = {}, data = [], **kwargs):
    """A rule for defining a rust benchmark.

    Like `rust_bench`, but adds data and env params required for canister sandbox

    Args:
      see description for `rust_bench`
    """
    rust_bench(
        env = dict(env.items() + _SANDBOX_ENV.items()),
        data = data + _SANDBOX_DATA,
        **kwargs
    )

def _symlink_dir_test(ctx):
    """
    Create a symlink to have a stable location for Rust (and maybe other) test binaries

    `rust_test` creates a binary as an output, so you can use that binary in
    other targets, including Rust tests, e.g., as a `data` dependency. But for a
    `rust_test` target `tgt`, the location of the binary in RUNFILES_DIR is
    unpredictable (Bazel will put it in a dir called something like
    `tgt_451223`). This rule creates a symlink to the binary in a stable location.
    """

    # Use the no-op script as the executable
    no_op_output = ctx.actions.declare_file("no_op")
    ctx.actions.write(output = no_op_output, content = ":")

    dirname = ctx.attr.name
    lns = []
    for target, canister_name in ctx.attr.targets.items():
        ln = ctx.actions.declare_file(dirname + "/" + canister_name)
        file = target[DefaultInfo].files.to_list()[0]
        ctx.actions.symlink(
            output = ln,
            target_file = file,
        )
        lns.append(ln)
    return [DefaultInfo(files = depset(direct = lns), executable = no_op_output)]

symlink_dir_test = rule(
    implementation = _symlink_dir_test,
    test = True,
    attrs = {
        "targets": attr.label_keyed_string_dict(allow_files = True),
    },
)

def rust_test_with_binary(name, binary_name, **kwargs):
    """
    A `rust_test` with a stable link to its produced test binary.

    Plain `rust_test` is problematic when one wants to use the produced test binary in
    other Bazel targets (e.g., upgrade/downgrade compatibility tests), as Bazel does not
    provide a stable way to refer to the binary produced by a test. This rule is a thin
    wrapper around `rust_test` that symlinks the test binary to a stable location provided
    by `binary_name`, which can then be used in other tests.

    Usage example:
    ```
    rust_test(
        name = "my_test",
        binary_name = "my_test_binary",
        crate = ":my_crate",
        deps = ["@crate_index//:proptest"]
    )
    ```

    This will generate a rust_test target named `my_test` whose corresponding binary
    will be available as the `my_test_binary` target.
    """
    symlink_dir_test(
        name = binary_name,
        targets = {
            name: binary_name,
        },
    )
    rust_test(
        name = name,
        **kwargs
    )

def _symlink_dir(ctx):
    dirname = ctx.attr.name
    lns = []
    for target, canister_name in ctx.attr.targets.items():
        ln = ctx.actions.declare_file(dirname + "/" + canister_name)
        file = target[DefaultInfo].files.to_list()[0]
        ctx.actions.symlink(
            output = ln,
            target_file = file,
        )
        lns.append(ln)
    return [DefaultInfo(files = depset(direct = lns))]

symlink_dir = rule(
    implementation = _symlink_dir,
    attrs = {
        "targets": attr.label_keyed_string_dict(allow_files = True),
    },
)

def _symlink_dirs(ctx):
    dirname = ctx.attr.name
    lns = []
    for target, childdirname in ctx.attr.targets.items():
        for file in target[DefaultInfo].files.to_list():
            ln = ctx.actions.declare_file(dirname + "/" + childdirname + "/" + file.basename)
            ctx.actions.symlink(
                output = ln,
                target_file = file,
            )
            lns.append(ln)
    return [DefaultInfo(files = depset(direct = lns))]

symlink_dirs = rule(
    implementation = _symlink_dirs,
    attrs = {
        "targets": attr.label_keyed_string_dict(allow_files = True),
    },
)

def _write_info_file_var_impl(ctx):
    """Helper rule that creates a file with the content of the provided var from the info file."""

    output = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.run_shell(
        command = """
            grep <{info_file} -e '{varname}' \\
                    | cut -d' ' -f2 > {out}""".format(varname = ctx.attr.varname, info_file = ctx.info_file.path, out = output.path),
        inputs = [ctx.info_file],
        outputs = [output],
    )
    return [DefaultInfo(files = depset([output]))]

write_info_file_var = rule(
    implementation = _write_info_file_var_impl,
    attrs = {
        "varname": attr.string(mandatory = True),
    },
)

def file_size_check(
        name,
        file,
        max_file_size,
        tags = []):
    """
    A check to make sure the given file is below the specified size.

    Args:
      name: Name of the test.
      file: File to check (label).
      max_file_size: Max accepted size in bytes.
      tags: See Bazel documentation
    """
    sh_test(
        name = name,
        srcs = ["//bazel:file_size_test.sh"],
        data = [file],
        env = {
            "FILE": "$(rootpath %s)" % file,
            "MAX_SIZE": str(max_file_size),
        },
        tags = tags,
    )
