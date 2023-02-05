"""
Rules for system-tests.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@io_bazel_rules_docker//container:container.bzl", "container_image")
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

def system_test(name, runtime_deps = [], tags = [], test_timeout = "long", flaky = True, **kwargs):
    """Declares a system-test.

    Args:
      name: base name to use for the binary and test rules.
      runtime_deps: dependencies to make available to the test when it runs.
      tags: additional tags for the system_test.
      test_timeout: bazel test timeout (short, moderate, long or eternal).
      flaky: rerun in case of failure (up to 3 times).
      **kwargs: additional arguments to pass to the rust_binary rule.
    """

    # Names are used as part of domain names; thus, limit their length
    if len(name) > 50:
        fail("Name of system test group too long (max 50): " + name)

    bin_name = name + "_bin"

    rust_binary(
        name = bin_name,
        srcs = ["bin/" + name + ".rs"],
        **kwargs
    )

    container_name = name + "_image"

    container_image(
        name = container_name,
        base = "//rs/tests/replicated_tests:test_driver_image_base",
        directory = "/home/root/root_env/dependencies",
        data_path = "/",
        entrypoint = "/home/root/root_env/dependencies/rs/tests/%s --working-dir . run" % bin_name,
        files = [
            ":" + bin_name,
        ] + runtime_deps,
        tags = ["manual"],  # this target will be built if required as a dependency of another target
        user = "root",
        workdir = "/home/root",
    )

    uvm_config_image_name = name + "_uvm_config_image"

    uvm_config_image(
        name = uvm_config_image_name,
        srcs = [
            ":" + container_name + ".tar",
            ":activate-systest-uvm-config",
        ],
        remap_paths = {
            "/activate-systest-uvm-config": "/activate",
        },
        mode = "664",
        modes = {
            "activate": "775",
        },
        tags = ["manual"],  # this target will be built if required as a dependency of another target
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

def _uvm_config_image_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".zst")

    input_tar = ctx.attr.input_tar[DefaultInfo].files.to_list()[0]

    create_universal_vm_config_image = ctx.executable._create_universal_vm_config_image

    ctx.actions.run(
        executable = ctx.executable._create_universal_vm_config_image_from_tar,
        arguments = [create_universal_vm_config_image.path, input_tar.path, out.path],
        inputs = [input_tar, create_universal_vm_config_image],
        outputs = [out],
    )
    return [
        DefaultInfo(
            files = depset([out]),
        ),
    ]

uvm_config_image_impl = rule(
    implementation = _uvm_config_image_impl,
    attrs = {
        "input_tar": attr.label(),
        "_create_universal_vm_config_image_from_tar": attr.label(
            executable = True,
            cfg = "exec",
            default = ":create_universal_vm_config_image_from_tar_sh",
        ),
        "_create_universal_vm_config_image": attr.label(
            executable = True,
            cfg = "exec",
            default = ":create_universal_vm_config_image_sh",
        ),
    },
)

def uvm_config_image(name, **kws):
    tar = name + "_tar"

    pkg_tar(
        name = tar,
        **kws
    )

    uvm_config_image_impl(
        name = name,
        input_tar = ":" + tar,
        tags = ["manual"],
    )
