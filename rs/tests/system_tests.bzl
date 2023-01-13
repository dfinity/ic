"""
Rules for system-tests.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@io_bazel_rules_docker//container:container.bzl", "container_image")
load("@io_bazel_rules_docker//docker/util:run.bzl", "container_run_and_commit")
load("@io_bazel_rules_docker//contrib:passwd.bzl", "passwd_entry", "passwd_file")
load("@bazel_tools//tools/build_defs/pkg:pkg.bzl", "pkg_tar")

def _run_system_test(ctx):
    run_test_script_file = ctx.actions.declare_file(ctx.label.name + "/run-test.sh")

    ctx.actions.write(
        output = run_test_script_file,
        is_executable = True,
        content = """#!/bin/bash
            set -eEuo pipefail
            RUNFILES="$PWD"
            cd "$TEST_TMPDIR"
            mkdir root_env
            cp -Rs "$RUNFILES" root_env/dependencies/
            "$RUNFILES/{test_executable}" --working-dir . run
        """.format(
            test_executable = ctx.executable.src.short_path,
        ),
    )

    runtime_deps = []
    for target in ctx.attr.runtime_deps:
        runtime_deps.append(target.files)

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
            environment = ctx.attr.env,
        ),
    ]

run_system_test = rule(
    implementation = _run_system_test,
    test = True,
    attrs = {
        "src": attr.label(executable = True, cfg = "exec"),
        "env": attr.string_dict(allow_empty = True),
        "runtime_deps": attr.label_list(allow_files = True),
    },
)

def system_test(name, runtime_deps = [], tags = [], test_timeout = "long", flaky = True, is_dockerized = False, **kwargs):
    """Declares a system-test.

    Args:
      name: base name to use for the binary and test rules.
      runtime_deps: dependencies to make available to the test when it runs.
      tags: additional tags for the system_test.
      test_timeout: bazel test timeout (short, moderate, long or eternal).
      flaky: rerun in case of failure (up to 3 times).
      is_dockerized: whether this test should be dockerized
      **kwargs: additional arguments to pass to the rust_binary rule.
    """
    bin_name = name + "_bin"

    rust_binary(
        name = bin_name,
        srcs = ["bin/" + name + ".rs"],
        **kwargs
    )

    run_system_test(
        name = name,
        src = bin_name,
        runtime_deps = runtime_deps,
        tags = tags + ["requires-network", "system_test"],
        timeout = test_timeout,
        # TODO: set flaky = False by default when PFOPS-3148 is resolved
        flaky = flaky,
    )

    if is_dockerized:
        _dockerize_system_test(systest_name = name)

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

## Distributed testing-related targets

def create_test_driver_image_base():
    """
    Adds a Docker target named test_driver_image_base for dockerizing system tests.

    The resulting target can be used as follows:
    container_image(base = ":test_driver_image_base", ...)
    """
    passwd_entry(
        name = "root_user",
        home = "/home/root",
        uid = 0,
        username = "root",
    )

    passwd_file(
        name = "passwd",
        entries = [
            ":root_user",
        ],
    )

    pkg_tar(
        name = "passwd_tar",
        srcs = [":passwd"],
        mode = "0644",
        package_dir = "etc",
    )

    container_image(
        name = "test_driver_image_barebone",
        base = "@ubuntu_base//image",
        tags = ["manual"],
        tars = [
            ":passwd_tar",
        ],
    )

    container_run_and_commit(
        name = "test_driver_image_base",
        commands = [
            "apt-get update",
            "apt-get -y install wget",
            "wget http://nz2.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb",
            "dpkg -i libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb",
        ],
        image = ":test_driver_image_barebone.tar",
        target_compatible_with = ["@platforms//os:linux"],  # requires invoking docker that we avoid on Mac OS
    )

def _dockerize_system_test(systest_name):
    """Builds a Docker image with this system test as the entrypoint.

    For example, specifying dockerize_system_test("replicable_mock_test") in BUILD.bazel
    allows running "bazel build //rs/tests:replicable_mock_test_image.tar" that produces
    a Docker image tarball "replicable_mock_test_image.tar".

    Args:
      systest_name: the name of an existing system_test target that should be dockerized.
    """

    ## The final image we can publish.
    container_image(
        name = systest_name + "_image",
        base = ":test_driver_image_base",
        directory = "/home/root",
        files = [
            ":" + systest_name + "_bin",
        ],
        tags = ["manual"],
        user = "root",
        workdir = "/home/root",
    )
