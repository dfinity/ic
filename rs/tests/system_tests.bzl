"""
Rules for system-tests.
"""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@bazel_skylib//rules:copy_file.bzl", "copy_file")
load("@rules_oci//oci:defs.bzl", "oci_load")
load("@rules_rust//rust:defs.bzl", "rust_binary")
load("//bazel:defs.bzl", "mcopy", "zstd_compress")
load("//rs/tests:common.bzl", "BOUNDARY_NODE_GUESTOS_RUNTIME_DEPS", "GUESTOS_DEV_VERSION", "MAINNET_NNS_CANISTER_ENV", "MAINNET_NNS_CANISTER_RUNTIME_DEPS", "NNS_CANISTER_ENV", "NNS_CANISTER_RUNTIME_DEPS", "UNIVERSAL_VM_RUNTIME_DEPS")

def _run_system_test(ctx):
    run_test_script_file = ctx.actions.declare_file(ctx.label.name + "/run-test.sh")

    # whether to use k8s instead of farm
    k8s = ctx.attr._k8s[BuildSettingInfo].value

    ctx.actions.write(
        output = run_test_script_file,
        is_executable = True,
        content = """#!/bin/bash
            set -eEuo pipefail

            # for every ic-os image specified, first ensure it's in remote storage, then
            # export its download URL as an environment variable.
            if [ -n "$ICOS_IMAGES" ]; then
              # split the ";"-delimited list of "envvar:filepath;envvar2:filepath2;..."
              # into an array
              IFS=';' read -ra icos_images <<<"$ICOS_IMAGES"
              for image in "${{icos_images[@]}}"; do
                  # split "envvar:filepath"
                  image_varname=${{image%:*}}
                  image_filename=${{image#*:}}

                  # ensure the dep is uploaded
                  image_download_url=$("$UPLOAD_SYSTEST_DEP" "$image_filename")
                  echo "  -> $image_varname=$image_download_url" >&2

                  # set the environment variable for the test
                  export "$image_varname=$image_download_url"
              done
            fi
            unset ICOS_IMAGES # clean up the env for the test

            # We export RUNFILES such that the from_location_specified_by_env_var() function in
            # rs/rust_canisters/canister_test/src/canister.rs can find canisters
            # relative to the $RUNFILES directory.
            export RUNFILES="$PWD"
            KUBECONFIG=$RUNFILES/${{KUBECONFIG:-}}
            mkdir "$TEST_TMPDIR/root_env"
            "$RUNFILES/{test_executable}" \
              --working-dir "$TEST_TMPDIR" \
              {k8s} \
              --group-base-name {group_base_name} \
              {no_summary_report} \
              "$@" run
        """.format(
            test_executable = ctx.executable.src.short_path,
            k8s = "--k8s" if k8s else "",
            group_base_name = ctx.label.name,
            no_summary_report = "--no-summary-report" if ctx.executable.colocated_test_bin != None else "",
        ),
    )

    env = dict(ctx.attr.env.items())

    # Expand Make variables in env vars, with runtime_deps as targets
    for key, value in env.items():
        # If this looks like a Make variable, try to expand it
        if value.startswith("$"):
            env[key] = ctx.expand_location(value, ctx.attr.runtime_deps)

    env |= {
        "VOLATILE_STATUS_FILE_PATH": ctx.version_file.short_path,
    }

    # The test runner script expects a list of enviromment variable names to files:
    # ICOS_IMAGES=MY_DEP:./path/to/dep;MY_OTHER_DEP:./path/to/other/dep
    icos_images = ctx.attr.icos_images
    env |= {
        "ICOS_IMAGES": ";".join([k + ":" + v.files.to_list()[0].short_path for k, v in icos_images.items()]),
    }

    env_deps = ctx.attr.env_deps
    env_deps = dict(env_deps, **icos_images)

    if ctx.executable.colocated_test_bin != None:
        env["COLOCATED_TEST_BIN"] = ctx.executable.colocated_test_bin.short_path

    if k8s:
        env["KUBECONFIG"] = ctx.file._k8sconfig.path

    env["UPLOAD_SYSTEST_DEP"] = ctx.executable._upload_systest_dep.short_path

    runtime_deps = [depset([ctx.file._k8sconfig])]
    for target in ctx.attr.runtime_deps:
        runtime_deps.append(target.files)

    for e, t in env_deps.items():
        runtime_deps.append(t.files)
        env[e] = t.files.to_list()[0].short_path

    return [
        DefaultInfo(
            executable = run_test_script_file,
            runfiles = ctx.runfiles(
                files = [
                    run_test_script_file,
                    ctx.executable.src,
                    ctx.executable._upload_systest_dep,
                    ctx.version_file,
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
        "_upload_systest_dep": attr.label(executable = True, cfg = "exec", default = "//bazel:upload_systest_dep"),
        "runtime_deps": attr.label_list(allow_files = True),
        "env_deps": attr.string_keyed_label_dict(allow_files = True),
        "icos_images": attr.string_keyed_label_dict(doc = "Specifies images to be injected to the test. Values will be replaced with actual download URLs.", allow_files = True),
        "env_inherit": attr.string_list(doc = "Specifies additional environment variables to inherit from the external environment when the test is executed by bazel test."),
    },
)

default_vm_resources = {
    "vcpus": None,
    "memory_kibibytes": None,
    "boot_image_minimal_size_gibibytes": None,
}

def system_test(
        name,
        test_driver_target = None,
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
        uses_boundary_guestos = False,
        env = {},
        env_inherit = [],
        additional_colocate_tags = [],
        **kwargs):
    """Declares a system-test.

    Args:
      name: base name to use for the binary and test rules.
      test_driver_target: optional string to identify the target of the test driver binary. Defaults to None which means declare a rust_binary from <name>.rs.
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
      uses_boundary_guestos: the test uses ic-os/boundary-guestos/envs/dev:disk-img (will be also automatically added as dependency).
      env: environment variables to set in the test (subject to Make variable expansion)
      env_inherit: specifies additional environment variables to inherit from
      the external environment when the test is executed by bazel test.
      additional_colocate_tags: additional tags to pass to the colocated test.
      **kwargs: additional arguments to pass to the rust_binary rule.

    Returns:
      This macro declares 3 bazel targets:
        * If test_driver_target == None, a rust_binary <name>_bin which is the test driver.
        * A test target <name> which runs the test.
        * A test target <name>_colocate which runs the test in a colocated way.
      It returns a struct specifying test_driver_target which is the name of the test driver target ("<name>_bin") such that it can be used by other system-tests.
    """

    if test_driver_target == None:
        bin_name = name + "_bin"
        original_srcs = kwargs.pop("srcs", [])
        rust_binary(
            name = bin_name,
            testonly = True,
            srcs = original_srcs + [name + ".rs"],
            **kwargs
        )
        test_driver_target = bin_name

    # Automatically detect system tests that use guestos dev & boundary node guestos for back compatibility.
    for _d in runtime_deps:
        if _d == GUESTOS_DEV_VERSION:
            uses_guestos_dev = True
            break
    uses_boundary_guestos = uses_boundary_guestos or all([dep in runtime_deps for dep in BOUNDARY_NODE_GUESTOS_RUNTIME_DEPS])

    # Environment variable names to targets (targets are resolved)
    _env_deps = {}

    _guestos = "//ic-os/guestos/envs/dev:"
    _hostos = "//ic-os/hostos/envs/dev:"
    _setupos = "//ic-os/setupos/envs/dev:"

    # Always add version.txt for now as all test use it even that they don't declare they use dev image.
    # NOTE: we use "ENV_DEPS__" as prefix for env variables, which are passed to system-tests via Bazel.
    _env_deps["ENV_DEPS__IC_VERSION_FILE"] = _guestos + "version.txt"

    icos_images = dict()

    if uses_guestos_dev:
        icos_images["ENV_DEPS__DEV_DISK_IMG_TAR_ZST_CAS_URL"] = _guestos + "disk-img.tar.zst"
        icos_images["ENV_DEPS__DEV_UPDATE_IMG_TAR_ZST_CAS_URL"] = _guestos + "update-img.tar.zst"

    if uses_hostos_dev_test:
        icos_images["ENV_DEPS__DEV_HOSTOS_UPDATE_IMG_TEST_TAR_ZST_CAS_URL"] = _hostos + "update-img-test.tar.zst"

    if uses_setupos_dev:
        icos_images["ENV_DEPS__DEV_SETUPOS_IMG_TAR_ZST_CAS_URL"] = _setupos + "disk-img.tar.zst"

        _env_deps["ENV_DEPS__SETUPOS_DISABLE_CHECKS"] = "//rs/ic_os/dev_test_tools/setupos-disable-checks"
        _env_deps["ENV_DEPS__SETUPOS_INJECT_CONFIGS"] = "//rs/ic_os/dev_test_tools/setupos-inject-configuration"

    if uses_guestos_dev_test:
        icos_images["ENV_DEPS__DEV_UPDATE_IMG_TEST_TAR_ZST_CAS_URL"] = _guestos + "update-img-test.tar.zst"

    if malicious:
        _guestos_malicous = "//ic-os/guestos/envs/dev-malicious:"

        icos_images["ENV_DEPS__DEV_MALICIOUS_DISK_IMG_TAR_ZST_CAS_URL"] = _guestos_malicous + "disk-img.tar.zst"
        icos_images["ENV_DEPS__DEV_MALICIOUS_UPDATE_IMG_TAR_ZST_CAS_URL"] = _guestos_malicous + "update-img.tar.zst"

    if uses_boundary_guestos:
        icos_images["ENV_DEPS__BOUNDARY_GUESTOS_DISK_IMG_TAR_ZST_CAS_URL"] = "//ic-os/boundary-guestos/envs/dev:disk-img.tar.zst"

    run_system_test(
        name = name,
        src = test_driver_target,
        runtime_deps = runtime_deps,
        env_deps = _env_deps,
        env = env,
        icos_images = icos_images,
        env_inherit = env_inherit,
        tags = tags + ["requires-network", "system_test"] +
               (["manual"] if "experimental_system_test_colocation" in tags else []),
        target_compatible_with = ["@platforms//os:linux"],
        timeout = test_timeout,
        flaky = flaky,
    )

    deps = []
    for dep in runtime_deps:
        if dep not in UNIVERSAL_VM_RUNTIME_DEPS:
            deps.append(dep)

    env = env | {
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
        colocated_test_bin = test_driver_target,
        runtime_deps = deps + UNIVERSAL_VM_RUNTIME_DEPS + [
            "//rs/tests:colocate_uvm_config_image",
            test_driver_target,
        ],
        env_deps = _env_deps,
        env_inherit = env_inherit,
        env = env,
        icos_images = icos_images,
        tags = tags + ["requires-network", "system_test"] +
               (["colocated"] if "experimental_system_test_colocation" in tags else ["manual"]) +
               additional_colocate_tags,
        target_compatible_with = ["@platforms//os:linux"],
        timeout = test_timeout,
        flaky = flaky,
    )
    return struct(test_driver_target = test_driver_target)

def system_test_nns(name, extra_head_nns_tags = ["system_test_nightly"], **kwargs):
    """Declares a system-test that uses the mainnet NNS and a variant that use the HEAD NNS.

    Declares two system-tests:

    * One with the given name which uses the NNS from mainnet as specified by mainnet-canisters.bzl.
    * One with the given name suffixed with "_head_nns" which uses the NNS from the HEAD of the repo.

    The latter one is additionally tagged with "system_test_nightly" such that it only runs daily and not on PRs.
    You can override the latter behaviour by specifying different `extra_head_nns_tags`.
    If you set `extra_head_nns_tags` to `[]` the head_nns variant will have the same tags as the default variant.

    The idea being that for most system-tests which test the replica it's more realistic to test against the
    mainnet NNS since that version would be active when the replica would be released.

    However it's still useful to see if the HEAD replica works against the HEAD NNS which is why this macro
    introduces the <name>_head_nns variant which only runs daily if not overriden.

    Args:
        name: the name of the system-tests.
        extra_head_nns_tags: extra tags assigned to the head_nns variant (Use `[]` to use the original tags).
        **kwargs: the arguments of the system-tests.
    """
    runtime_deps = kwargs.pop("runtime_deps", [])
    env = kwargs.pop("env", {})

    mainnet_nns_systest = system_test(
        name,
        env = env | MAINNET_NNS_CANISTER_ENV,
        runtime_deps = runtime_deps + MAINNET_NNS_CANISTER_RUNTIME_DEPS,
        **kwargs
    )

    original_tags = kwargs.pop("tags", [])
    system_test(
        name + "_head_nns",
        test_driver_target = mainnet_nns_systest.test_driver_target,
        env = env | NNS_CANISTER_ENV,
        runtime_deps = runtime_deps + NNS_CANISTER_RUNTIME_DEPS,
        tags = [tag for tag in original_tags if tag not in extra_head_nns_tags] + extra_head_nns_tags,
        **kwargs
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
        target_compatible_with = ["@platforms//os:linux"],
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
        target_compatible_with = ["@platforms//os:linux"],
        visibility = ["//visibility:private"],
    )

    mcopy(
        name = name + "_mcopy",
        srcs = srcs,
        fs = ":" + name + "_vfat",
        remap_paths = remap_paths,
        tags = ["manual"],
        target_compatible_with = ["@platforms//os:linux"],
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
        target_compatible_with = ["@platforms//os:linux"],
        visibility = visibility,
    )

def oci_tar(name, image, repo_tags = []):
    """Create a tarball from an OCI image. The target is marked as 'manual'.

    Args:
      name: This name will be used for the tarball (must end with '.tar').
      repo_tags: OCI tags for oci_load.
      image: The OCI image to bundle.
    """

    if not name.endswith(".tar"):
        fail("Expected tarname to end with '.tar': " + name)

    basename = name.removesuffix(".tar")

    name_image = basename + "_image"

    # First load the image
    oci_load(
        name = name_image,
        image = image,
        repo_tags = repo_tags,
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    # create the tarball
    name_tarballdir = basename + "_tarballdir"
    native.filegroup(
        name = name_tarballdir,
        srcs = [":" + name_image],
        output_group = "tarball",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual"],
    )

    # Copy the tarball out so we can reference the file by 'name'
    copy_file(
        name = basename + "_tar",
        src = ":" + name_tarballdir,
        out = name,
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual"],
    )
