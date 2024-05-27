"""
Rules for system-tests.
"""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@rules_rust//rust:defs.bzl", "rust_binary")
load("//bazel:defs.bzl", "mcopy", "zstd_compress")
load("//rs/tests:common.bzl", "GUESTOS_DEV_VERSION", "UNIVERSAL_VM_RUNTIME_DEPS")

def _run_system_test(ctx):
    run_test_script_file = ctx.actions.declare_file(ctx.label.name + "/run-test.sh")

    # whether to use k8s instead of farm
    k8s = ctx.attr._k8s[BuildSettingInfo].value

    ctx.actions.write(
        output = run_test_script_file,
        is_executable = True,
        content = """#!/bin/bash
            set -eEuo pipefail
            RUNFILES="$PWD"
            KUBECONFIG=$RUNFILES/${{KUBECONFIG:-}}
            VERSION_FILE="$(cat $VERSION_FILE_PATH)"
            cd "$TEST_TMPDIR"
            mkdir root_env
            cp -Rs "$RUNFILES" root_env/dependencies/
            cp -v "$VERSION_FILE" root_env/dependencies/volatile-status.txt
            "$RUNFILES/{test_executable}" --working-dir . {k8s} --group-base-name {group_base_name} {no_summary_report} "$@" run
        """.format(
            test_executable = ctx.executable.src.short_path,
            k8s = "--k8s" if k8s else "",
            group_base_name = ctx.label.name,
            no_summary_report = "--no-summary-report" if ctx.executable.colocated_test_bin != None else "",
        ),
    )

    env = dict(ctx.attr.env.items() + [
        ("VERSION_FILE_PATH", ctx.file.version_file_path.short_path),
    ])
    if ctx.executable.colocated_test_bin != None:
        env["COLOCATED_TEST_BIN"] = ctx.executable.colocated_test_bin.short_path

    if k8s:
        env["KUBECONFIG"] = ctx.file._k8sconfig.path

    # version_file_path contains the "direct" path to the volatile status file.
    # The wrapper script copies this file instead of receiving ing as bazel dependency to not invalidate the cache.
    runtime_deps = [depset([ctx.file.version_file_path, ctx.file._k8sconfig])]
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
        RunEnvironmentInfo(
            environment = env,
            inherited_environment = ctx.attr.env_inherit,
        ),
    ]

run_system_test = rule(
    implementation = _run_system_test,
    test = True,
    attrs = {
        "src": attr.label(executable = True, cfg = "exec"),
        "colocated_test_bin": attr.label(executable = True, cfg = "exec", default = None),
        "env": attr.string_dict(allow_empty = True),
        "_k8s": attr.label(default = "//rs/tests:k8s"),
        "_k8sconfig": attr.label(allow_single_file = True, default = "@kubeconfig//:kubeconfig.yaml"),
        "runtime_deps": attr.label_list(allow_files = True),
        "env_deps": attr.label_keyed_string_dict(allow_files = True),
        "env_inherit": attr.string_list(doc = "Specifies additional environment variables to inherit from the external environment when the test is executed by bazel test."),
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
        flaky = False,
        malicious = False,
        colocated_test_driver_vm_resources = default_vm_resources,
        colocated_test_driver_vm_required_host_features = [],
        colocated_test_driver_vm_enable_ipv4 = False,
        colocated_test_driver_vm_forward_ssh_agent = False,
        uses_guestos_dev = False,
        uses_guestos_dev_test = False,
        uses_setupos_dev = False,
        uses_hostos_dev_test = False,
        env_inherit = [],
        **kwargs):
    """Declares a system-test.

    Args:
      name: base name to use for the binary and test rules.
      runtime_deps: dependencies to make available to the test when it runs.
      tags: additional tags for the system_test.
      test_timeout: bazel test timeout (short, moderate, long or eternal).
      flaky: rerun in case of failure (up to 3 times).
      malicious: use the malicious disk image.
      colocated_test_driver_vm_resources: a structure describing
      the required resources of the colocated test-driver VM. For example:
        {
          "vcpus": 64,
          "memory_kibibytes": 512142680,
          "boot_image_minimal_size_gibibytes": 500,
        }
      Fields can be None or left out.
      colocated_test_driver_vm_required_host_features: a list of strings
      colocated_test_driver_vm_enable_ipv4: boolean whether to enable an IPv4 address for the colocated test-driver VM.
      colocated_test_driver_vm_forward_ssh_agent: forward the SSH agent to the colocated test-driver VM.
      specifying the required host features of the colocated test-driver VM.
      For example: [ "performance" ]
      uses_guestos_dev: the test uses ic-os/guestos/envs/dev (will be also automatically added as dependency).
      uses_guestos_dev_test: the test uses //ic-os/guestos/envs/dev:update-img-test (will be also automatically added as dependency).
      uses_setupos_dev: the test uses ic-os/setupos/envs/dev (will be also automatically added as dependency).
      uses_hostos_dev_test: the test uses ic-os/hostos/envs/dev:update-img-test (will be also automatically added as dependency).
      env_inherit: specifies additional environment variables to inherit from the external environment when the test is executed by bazel test.
      **kwargs: additional arguments to pass to the rust_binary rule.
    """

    # Names are used as part of domain names; thus, limit their length
    if len(name) > 50:
        fail("Name of system test group too long (max 50): " + name)

    bin_name = name + "_bin"

    rust_binary(
        name = bin_name,
        testonly = True,
        srcs = [name + ".rs"],
        **kwargs
    )

    # Automatically detect system tests that use guestos dev for back compatibility.
    for _d in runtime_deps:
        if _d == GUESTOS_DEV_VERSION:
            uses_guestos_dev = True
            break

    _env_deps = {}

    _guestos = "//ic-os/guestos/envs/dev:"
    _hostos = "//ic-os/hostos/envs/dev:"
    _setupos = "//ic-os/setupos/envs/dev:"

    # Always add version.txt for now as all test use it even that they don't declare they use dev image.
    # NOTE: we use "ENV_DEPS__" as prefix for env variables, which are passed to system-tests via Bazel.
    _env_deps[_guestos + "version.txt"] = "ENV_DEPS__IC_VERSION_FILE"

    if uses_guestos_dev:
        _env_deps[_guestos + "disk-img.tar.zst.cas-url"] = "ENV_DEPS__DEV_DISK_IMG_TAR_ZST_CAS_URL"
        _env_deps[_guestos + "disk-img.tar.zst.sha256"] = "ENV_DEPS__DEV_DISK_IMG_TAR_ZST_SHA256"
        _env_deps[_guestos + "update-img.tar.zst.cas-url"] = "ENV_DEPS__DEV_UPDATE_IMG_TAR_ZST_CAS_URL"
        _env_deps[_guestos + "update-img.tar.zst.sha256"] = "ENV_DEPS__DEV_UPDATE_IMG_TAR_ZST_SHA256"

    if uses_hostos_dev_test:
        _env_deps[_hostos + "update-img-test.tar.zst.cas-url"] = "ENV_DEPS__DEV_HOSTOS_UPDATE_IMG_TEST_TAR_ZST_CAS_URL"
        _env_deps[_hostos + "update-img-test.tar.zst.sha256"] = "ENV_DEPS__DEV_HOSTOS_UPDATE_IMG_TEST_TAR_ZST_SHA256"

    if uses_setupos_dev:
        _env_deps[_setupos + "disk-img.tar.zst"] = "ENV_DEPS__DEV_SETUPOS_IMG_TAR_ZST"
        _env_deps["//rs/ic_os/setupos-disable-checks"] = "ENV_DEPS__SETUPOS_DISABLE_CHECKS"
        _env_deps["//rs/ic_os/setupos-inject-configuration"] = "ENV_DEPS__SETUPOS_INJECT_CONFIGS"

    if uses_guestos_dev_test:
        _env_deps[_guestos + "update-img-test.tar.zst.cas-url"] = "ENV_DEPS__DEV_UPDATE_IMG_TEST_TAR_ZST_CAS_URL"
        _env_deps[_guestos + "update-img-test.tar.zst.sha256"] = "ENV_DEPS__DEV_UPDATE_IMG_TEST_TAR_ZST_SHA256"

    if malicious:
        _guestos_malicous = "//ic-os/guestos/envs/dev-malicious:"

        _env_deps[_guestos_malicous + "disk-img.tar.zst.cas-url"] = "ENV_DEPS__DEV_MALICIOUS_DISK_IMG_TAR_ZST_CAS_URL"
        _env_deps[_guestos_malicous + "disk-img.tar.zst.sha256"] = "ENV_DEPS__DEV_MALICIOUS_DISK_IMG_TAR_ZST_SHA256"
        _env_deps[_guestos_malicous + "update-img.tar.zst.cas-url"] = "ENV_DEPS__DEV_MALICIOUS_UPDATE_IMG_TAR_ZST_CAS_URL"
        _env_deps[_guestos_malicous + "update-img.tar.zst.sha256"] = "ENV_DEPS__DEV_MALICIOUS_UPDATE_IMG_TAR_ZST_SHA256"

    run_system_test(
        name = name,
        src = bin_name,
        runtime_deps = runtime_deps,
        env_deps = _env_deps,
        env_inherit = env_inherit,
        tags = tags + ["requires-network", "system_test"] +
               (["manual"] if "experimental_system_test_colocation" in tags else []),
        timeout = test_timeout,
        flaky = flaky,
    )

    deps = []
    for dep in runtime_deps:
        if dep not in UNIVERSAL_VM_RUNTIME_DEPS:
            deps.append(dep)

    env = {
        "COLOCATED_TEST": name,
        "COLOCATED_TEST_DRIVER_VM_REQUIRED_HOST_FEATURES": json.encode(colocated_test_driver_vm_required_host_features),
        "COLOCATED_TEST_DRIVER_VM_RESOURCES": json.encode(colocated_test_driver_vm_resources),
    }

    if colocated_test_driver_vm_enable_ipv4:
        env.update({"COLOCATED_TEST_DRIVER_VM_ENABLE_IPV4": "1"})

    if colocated_test_driver_vm_forward_ssh_agent:
        env.update({"COLOCATED_TEST_DRIVER_VM_FORWARD_SSH_AGENT": "1"})

    run_system_test(
        name = name + "_colocate",
        src = "//rs/tests/testing_verification:colocate_test_bin",
        colocated_test_bin = bin_name,
        runtime_deps = deps + UNIVERSAL_VM_RUNTIME_DEPS + [
            "//rs/tests:colocate_uvm_config_image",
            bin_name,
        ],
        env_deps = _env_deps,
        env_inherit = env_inherit,
        env = env,
        tags = tags + ["requires-network", "system_test"] +
               ([] if "experimental_system_test_colocation" in tags else ["manual"]),
        timeout = test_timeout,
        flaky = flaky,
    )

def uvm_config_image(name, tags = None, visibility = None, srcs = None, remap_paths = None):
    """This macro creates bazel targets for uvm config images.

    Args:
        name: This name will be used for the target.
        tags: Controls execution of targets. "manual" excludes a target from wildcard targets like (..., :*, :all). See: https://bazel.build/reference/test-encyclopedia#tag-conventions
        visibility: Target visibility controls who may depend on a target.
        srcs: Source files that are copied into a vfat image.
        remap_paths: Dict that maps a current filename to a desired filename,
            e.g. {"activate.sh": "activate"}
    """
    native.genrule(
        name = name + "_size",
        srcs = srcs,
        outs = [name + "_size.txt"],
        cmd = "du --bytes -csL $(SRCS) | awk '$$2 == \"total\" {print 2 * $$1 + 1048576}' > $@",
        tags = ["manual"],
        visibility = ["//visibility:private"],
    )

    # TODO: install dosfstools as dependency
    native.genrule(
        name = name + "_vfat",
        srcs = [":" + name + "_size"],
        outs = [name + "_vfat.img"],
        cmd = """
        truncate -s $$(cat $<) $@
        /usr/sbin/mkfs.vfat -i "0" -n CONFIG $@
        """,
        tags = ["manual"],
        visibility = ["//visibility:private"],
    )

    mcopy(
        name = name + "_mcopy",
        srcs = srcs,
        fs = ":" + name + "_vfat",
        remap_paths = remap_paths,
        tags = ["manual"],
        visibility = ["//visibility:private"],
    )

    zstd_compress(
        name = name + ".zst",
        srcs = [":" + name + "_mcopy"],
        target_compatible_with = ["@platforms//os:linux"],
        tags = tags,
        visibility = ["//visibility:private"],
    )

    native.alias(
        name = name,
        actual = name + ".zst",
        tags = tags,
        visibility = visibility,
    )
