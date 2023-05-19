"""
Rules for system-tests.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@bazel_tools//tools/build_defs/pkg:pkg.bzl", "pkg_tar")
load("//rs/tests:common.bzl", "UNIVERSAL_VM_RUNTIME_DEPS")

def _run_system_test(ctx):
    run_test_script_file = ctx.actions.declare_file(ctx.label.name + "/run-test.sh")

    ctx.actions.write(
        output = run_test_script_file,
        is_executable = True,
        content = """#!/bin/bash
            set -eEuo pipefail
            RUNFILES="$PWD"
            VERSION_FILE="$(cat $VERSION_FILE_PATH)"
            cd "$TEST_TMPDIR"
            mkdir root_env
            cp -Rs "$RUNFILES" root_env/dependencies/
            cp -v "$VERSION_FILE" root_env/dependencies/volatile-status.txt
            "$RUNFILES/{test_executable}" --working-dir . --group-base-name {group_base_name} {no_summary_report} "$@" run
        """.format(
            test_executable = ctx.executable.src.short_path,
            group_base_name = ctx.label.name,
            no_summary_report = "--no-summary-report" if ctx.executable.colocated_test_bin != None else "",
        ),
    )

    # version_file_path contains the "direct" path to the volatile status file.
    # The wrapper script copies this file instead of receiving ing as bazel dependency to not invalidate the cache.
    runtime_deps = [depset([ctx.file.version_file_path, ctx.file.ic_version_file])]
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
            environment =
                dict(
                    ctx.attr.env.items() +
                    [
                        ("VERSION_FILE_PATH", ctx.file.version_file_path.short_path),
                        ("IC_VERSION_FILE", ctx.file.ic_version_file.short_path),
                    ] +
                    ([("COLOCATED_TEST_BIN", ctx.executable.colocated_test_bin.short_path)] if ctx.executable.colocated_test_bin != None else []),
                ),
        ),
    ]

run_system_test = rule(
    implementation = _run_system_test,
    test = True,
    attrs = {
        "src": attr.label(executable = True, cfg = "exec"),
        "colocated_test_bin": attr.label(executable = True, cfg = "exec", default = None),
        "env": attr.string_dict(allow_empty = True),
        "runtime_deps": attr.label_list(allow_files = True),
        "ic_version_file": attr.label(allow_single_file = True, default = "//ic-os/guestos/envs/dev:version.txt"),
        "version_file_path": attr.label(allow_single_file = True, default = "//bazel:version_file_path"),
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
        srcs = [name + ".rs"],
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

    deps = []
    for dep in runtime_deps:
        if dep not in UNIVERSAL_VM_RUNTIME_DEPS:
            deps.append(dep)

    run_system_test(
        name = name + "_colocate",
        src = "//rs/tests/testing_verification:colocate_test_bin",
        colocated_test_bin = bin_name,
        runtime_deps = deps + UNIVERSAL_VM_RUNTIME_DEPS + [
            "//rs/tests:colocate_uvm_config_image",
            bin_name,
        ],
        env = {
            "COLOCATED_TEST": name,
        },
        tags = tags + ["requires-network", "system_test"] +
               ([] if "experimental_system_test_colocation" in tags else ["manual"]),
        timeout = test_timeout,
        # TODO: set flaky = False by default when PFOPS-3148 is resolved
        flaky = flaky,
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
