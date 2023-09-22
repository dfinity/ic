"""
Rules for system-tests.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@rules_pkg//:pkg.bzl", "pkg_tar")
load("//rs/tests:common.bzl", "GUESTOS_DEV_VERSION", "UNIVERSAL_VM_RUNTIME_DEPS")

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

    env = dict(ctx.attr.env.items() + [
        ("VERSION_FILE_PATH", ctx.file.version_file_path.short_path),
    ])
    if ctx.executable.colocated_test_bin != None:
        env["COLOCATED_TEST_BIN"] = ctx.executable.colocated_test_bin.short_path

    # version_file_path contains the "direct" path to the volatile status file.
    # The wrapper script copies this file instead of receiving ing as bazel dependency to not invalidate the cache.
    runtime_deps = [depset([ctx.file.version_file_path])]
    for target in ctx.attr.runtime_deps:
        runtime_deps.append(target.files)

    for t, e in ctx.attr.env_deps.items():
        runtime_deps.append(t.files)
        env[e] = t.files.to_list()[0].short_path

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
        RunEnvironmentInfo(environment = env),
    ]

run_system_test = rule(
    implementation = _run_system_test,
    test = True,
    attrs = {
        "src": attr.label(executable = True, cfg = "exec"),
        "colocated_test_bin": attr.label(executable = True, cfg = "exec", default = None),
        "env": attr.string_dict(allow_empty = True),
        "runtime_deps": attr.label_list(allow_files = True),
        "env_deps": attr.label_keyed_string_dict(allow_files = True),
        "version_file_path": attr.label(allow_single_file = True, default = "//bazel:version_file_path"),
    },
)

default_vm_resources = {
    "vcpus": None,
    "memory_kibibytes": None,
    "boot_image_minimal_size_gibibytes": None,
}

def system_test(
        name,
        runtime_deps = [],
        tags = [],
        test_timeout = "long",
        flaky = True,
        colocated_test_driver_vm_resources = default_vm_resources,
        colocated_test_driver_vm_required_host_features = [],
        uses_guestos_dev = False,
        uses_guestos_dev_test = False,
        ic_os_fixed_version = True,
        **kwargs):
    """Declares a system-test.

    Args:
      name: base name to use for the binary and test rules.
      runtime_deps: dependencies to make available to the test when it runs.
      tags: additional tags for the system_test.
      test_timeout: bazel test timeout (short, moderate, long or eternal).
      flaky: rerun in case of failure (up to 3 times).
      colocated_test_driver_vm_resources: a structure describing
      the required resources of the colocated test-driver VM. For example:
        {
          "vcpus": 64,
          "memory_kibibytes": 512142680,
          "boot_image_minimal_size_gibibytes": 500,
        }
      Fields can be None or left out.
      colocated_test_driver_vm_required_host_features: a list of strings
      specifying the required host features of the colocated test-driver VM.
      For example: [ "performance" ]
      uses_guestos_dev: the test uses ic-os/guestos/envs/dev (will be also automatically added as dependency).
      uses_guestos_dev_test: the test uses //ic-os/guestos/envs/dev:update-img-test (will be also automatically added as dependency).
      ic_os_fixed_version: the test can work with ic-os that contains synthetic stable ic version.
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

    # Automatically detect system tests that use guestos dev for back compatibility.
    for _d in runtime_deps:
        if _d == GUESTOS_DEV_VERSION:
            uses_guestos_dev = True
            break

    _env_deps = {}

    _guestos = "//ic-os/guestos/envs/dev-fixed-version:" if ic_os_fixed_version else "//ic-os/guestos/envs/dev:"

    # Always add version.txt for now as all test use it even that they don't declary they use dev image.
    # NOTE: we use "ENV_DEPS__" as prefix for env variables, which are passed to system-tests via Bazel.
    _env_deps[_guestos + "version.txt"] = "ENV_DEPS__IC_VERSION_FILE"

    if uses_guestos_dev:
        _env_deps[_guestos + "disk-img.tar.zst.cas-url"] = "ENV_DEPS__DEV_DISK_IMG_TAR_ZST_CAS_URL"
        _env_deps[_guestos + "disk-img.tar.zst.sha256"] = "ENV_DEPS__DEV_DISK_IMG_TAR_ZST_SHA256"
        _env_deps[_guestos + "update-img.tar.zst.cas-url"] = "ENV_DEPS__DEV_UPDATE_IMG_TAR_ZST_CAS_URL"
        _env_deps[_guestos + "update-img.tar.zst.sha256"] = "ENV_DEPS__DEV_UPDATE_IMG_TAR_ZST_SHA256"

        _env_deps["//ic-os:scripts/build-bootstrap-config-image.sh"] = "ENV_DEPS__BUILD_BOOTSTRAP_CONFIG_IMAGE"

    if uses_guestos_dev_test:
        _env_deps[_guestos + "update-img-test.tar.zst.cas-url"] = "ENV_DEPS__DEV_UPDATE_IMG_TEST_TAR_ZST_CAS_URL"
        _env_deps[_guestos + "update-img-test.tar.zst.sha256"] = "ENV_DEPS__DEV_UPDATE_IMG_TEST_TAR_ZST_SHA256"

    run_system_test(
        name = name,
        src = bin_name,
        runtime_deps = runtime_deps,
        env_deps = _env_deps,
        tags = tags + ["requires-network", "system_test"] +
               (["manual"] if "experimental_system_test_colocation" in tags else []),
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
        env_deps = _env_deps,
        env = {
            "COLOCATED_TEST": name,
            "COLOCATED_TEST_DRIVER_VM_REQUIRED_HOST_FEATURES": json.encode(colocated_test_driver_vm_required_host_features),
            "COLOCATED_TEST_DRIVER_VM_RESOURCES": json.encode(colocated_test_driver_vm_resources),
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
