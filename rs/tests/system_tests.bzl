"""
Rules for system-tests.
"""

load("@bazel_skylib//lib:dicts.bzl", "dicts")
load("@rules_rust//rust:defs.bzl", "rust_binary")

def _run_system_test(ctx):
    run_test_script_file = ctx.actions.declare_file(ctx.label.name + "/run-test.sh")

    ctx.actions.write(
        output = run_test_script_file,
        is_executable = True,
        content = """#!/bin/bash
            set -eEuo pipefail
            RUNFILES="$PWD"
            cd "$TEST_TMPDIR"
            cp -Rs "$RUNFILES" dependencies/
            "$RUNFILES/{test_executable}" --working-dir . run "$@"
        """.format(
            test_executable = ctx.executable.src.short_path,
        ),
    )

    runtime_deps = []
    runtime_env = {}
    has_single_file = lambda t: DefaultInfo in t and len(t[DefaultInfo].files.to_list()) == 1
    for target, env_var in ctx.attr.runtime_deps.items():
        runtime_deps.append(target.files)
        if env_var != "" and has_single_file(target):
            file = target[DefaultInfo].files.to_list()[0]
            runtime_env[env_var] = "dependencies/" + file.short_path

    return [
        DefaultInfo(
            executable = run_test_script_file,
            runfiles = ctx.runfiles(
                files = [
                    run_test_script_file,
                    ctx.executable.src,
                ],
                transitive_files = depset(
                    direct = [],
                    transitive = runtime_deps,
                ),
            ),
        ),
        RunEnvironmentInfo(
            environment = dicts.add(runtime_env, ctx.attr.env),
        ),
    ]

run_system_test = rule(
    implementation = _run_system_test,
    test = True,
    attrs = {
        "src": attr.label(executable = True, cfg = "exec"),
        "env": attr.string_dict(allow_empty = True),
        "runtime_deps": attr.label_keyed_string_dict(allow_files = True),
    },
)

def system_test(name, runtime_deps = {}, test_timeout = "long", **kwargs):
    """Declares a system-test.

    Args:
      name: base name to use for the binary and test rules.
      runtime_deps: dependencies to make available to the test when it runs.
      test_timeout: bazel test timeout (short, moderate, long or eternal).
      **kwargs: additional arguments to pass to the rust_binary rule.
    """
    bin_name = name + "_bin"

    rust_binary(
        name = bin_name,
        srcs = ["bin/" + name + ".rs"],
        **kwargs
    )

    IC_VERSION_ID = "c51e7175ad2d7c7c5327f832a5d9e1bd7f6889c5"

    test_env = {
        "FARM_BASE_URL": "https://farm.dfinity.systems",
        "IC_OS_IMG_URL": "https://download.dfinity.systems/ic/{}/guest-os/disk-img-dev/disk-img.tar.zst".format(IC_VERSION_ID),
        "IC_OS_IMG_SHA256": "2cb880cc6fbb11b3ec29aa7b65d3643c1cbe74f73c2d0cd5dcae4cc7a8a7a243",
        "IC_OS_UPD_DEV_IMG_URL": "https://download.dfinity.systems/ic/{}/guest-os/update-img-dev/update-img.tar.zst".format(IC_VERSION_ID),
        "IC_OS_UPD_DEV_IMG_SHA256": "e67df14785c367c350fcbb5aa10ffd3773443e477be61d898e2dbd4b555ce700",
        "IC_VERSION_ID": IC_VERSION_ID,
    }

    run_system_test(
        name = name,
        src = bin_name,
        runtime_deps = runtime_deps,
        tags = ["requires-network", "system_test"],
        timeout = test_timeout,
        env = test_env,
    )
