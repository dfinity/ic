"""
Rules for system-tests.
"""

load("@bazel_skylib//rules:copy_file.bzl", "copy_file")
load("@mainnet_icos_versions//:defs.bzl", "MAINNET_APP", "MAINNET_LATEST", "MAINNET_LATEST_HOSTOS", "MAINNET_NNS")
load("@rules_oci//oci:defs.bzl", "oci_load")
load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("//bazel:defs.bzl", "mcopy", "zstd_compress")
load("//bazel:mainnet-icos-images.bzl", "icos_dev_image_download_url", "icos_image_download_url")
load("//rs/tests:common.bzl", "MAINNET_NNS_CANISTER_ENV", "MAINNET_NNS_CANISTER_RUNTIME_DEPS", "NNS_CANISTER_ENV", "NNS_CANISTER_RUNTIME_DEPS")

default_vm_resources = {
    "vcpus": None,
    "memory_kibibytes": None,
    "boot_image_minimal_size_gibibytes": None,
}

def system_test(
        name,
        test_name = None,
        test_driver_target = None,
        runtime_deps = [],
        tags = [],
        test_timeout = "long",
        flaky = False,
        colocated_test_driver_vm_resources = default_vm_resources,
        colocated_test_driver_vm_required_host_features = [],
        colocated_test_driver_vm_enable_ipv4 = False,
        colocated_test_driver_vm_forward_ssh_agent = False,
        guestos = True,
        guestos_update = False,
        uses_setupos_img = False,
        uses_setupos_mainnet_latest_img = False,
        uses_hostos_update = False,
        uses_hostos_test_update = False,
        uses_hostos_mainnet_latest_update = False,
        env = {},
        env_inherit = [],
        exclude_logs = ["prometheus", "vector"],
        additional_colocate_tags = [],
        logs = True,
        **kwargs):
    """Declares a system-test.

    Args:
      name: base name to use for the binary and test rules.
      test_name: optional name for the test, useful when the test name is different than name.
      test_driver_target: optional string to identify the target of the test driver binary. Defaults to None which means declare a rust_binary from <name>.rs.
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
      colocated_test_driver_vm_enable_ipv4: boolean whether to enable an IPv4 address for the colocated test-driver VM.
      colocated_test_driver_vm_forward_ssh_agent: forward the SSH agent to the colocated test-driver VM.
      specifying the required host features of the colocated test-driver VM.
      For example: [ "performance" ]
      guestos: The guestos version to use. Values: True (HEAD) | False | "malicious" | "mainnet_latest" | "mainnet_latest_dev" | "mainnet_nns" | "mainnet_app" | "recovery_dev". Default: True
      guestos_update: The guestos update image to use. Values: False | True (HEAD) | "test" | "malicious" | "mainnet_latest" | "mainnet_latest_dev" | "mainnet_nns" | "mainnet_app". Default: False
      uses_setupos_img: the test uses the branch SetupOS image
      uses_setupos_mainnet_latest_img: the test uses the latest release mainnet SetupOS image
      uses_hostos_update: the test uses the branch HostOS update image
      uses_hostos_test_update: the test uses the branch HostOS update-test image
      uses_hostos_mainnet_latest_update: the test uses the latest release mainnet HostOS update image
      env: environment variables to set in the test (subject to Make variable expansion)
      env_inherit: specifies additional environment variables to inherit from
      the external environment when the test is executed by bazel test.
      additional_colocate_tags: additional tags to pass to the colocated test.
      logs: Specifies if vector vm for scraping logs should not be spawned.
      exclude_logs: Specifies uvm name patterns to exclude from streaming.
      **kwargs: additional arguments to pass to the rust_binary rule.

    Returns:
      This macro declares 3 bazel targets:
        * If test_driver_target == None, a rust_binary <name>_bin which is the test driver.
        * A test target <name> which runs the test.
        * A test target <name>_colocate which runs the test in a colocated way.
      It returns a struct specifying test_driver_target which is the name of the test driver target ("<name>_bin") such that it can be used by other system-tests.
    """

    # Convert env to a mutable dictionary
    env = dict(env)

    if test_name == None:
        test_name = name

    if test_driver_target == None:
        bin_name = test_name + "_bin"
        original_srcs = kwargs.pop("srcs", [])
        rust_binary(
            name = bin_name,
            testonly = True,
            srcs = original_srcs + [name + ".rs"],
            target_compatible_with = ["@platforms//os:linux"],
            **kwargs
        )
        test_driver_target = bin_name

    visibility = kwargs.pop("visibility", ["//visibility:public"])

    # Environment variable names to targets (targets are resolved)
    # NOTE: we use "ENV_DEPS__" as prefix for env variables, which are passed to system-tests via Bazel.
    _runtime_deps = {}
    env_var_files = {}
    icos_images = dict()

    if int(uses_setupos_img) + int(uses_setupos_mainnet_latest_img) >= 2:
        fail("More than one initial SetupOS (disk) image was provided!")

    if int(uses_hostos_update) + int(uses_hostos_test_update) + int(uses_hostos_mainnet_latest_update) >= 2:
        fail("More than one target HostOS (upgrade) image was specified!")

    # ICOS image handling
    if guestos:
        if guestos == True:  # HEAD version
            env_var_files["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = "//bazel:version.txt"
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "//ic-os/guestos/envs/dev:disk-img.tar.zst"
            icos_images["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG"] = "//ic-os/guestos/envs/dev:update-img.tar.zst"
            _runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"

        elif guestos == "malicious":
            env_var_files["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = "//bazel:version.txt"
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "//ic-os/guestos/envs/dev-malicious:disk-img.tar.zst"
            icos_images["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG"] = "//ic-os/guestos/envs/dev-malicious:update-img.tar.zst"
            _runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev-malicious:launch-measurements.json"

        elif guestos == "mainnet_latest":
            env["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = MAINNET_LATEST["version"]
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "@mainnet_latest_guestos_images//:guest-img"
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_LATEST["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH"] = MAINNET_LATEST["hash"]
            _runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_guestos_images//:launch-measurements-guest.json"

        elif guestos == "mainnet_latest_dev":
            env["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = MAINNET_LATEST["version"]
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "@mainnet_latest_guestos_images_dev//:guest-img"
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL"] = icos_dev_image_download_url(MAINNET_LATEST["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH"] = MAINNET_LATEST["dev_hash"]
            _runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_guestos_images_dev//:launch-measurements-guest.json"

        elif guestos == "mainnet_nns":
            env["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = MAINNET_NNS["version"]
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "@mainnet_nns_images//:guest-img"
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_NNS["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH"] = MAINNET_NNS["hash"]
            _runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_nns_images//:launch-measurements-guest.json"

        elif guestos == "mainnet_app":
            env["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = MAINNET_APP["version"]
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "@mainnet_app_images//:guest-img"
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_APP["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH"] = MAINNET_APP["hash"]
            _runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_app_images//:launch-measurements-guest.json"

        elif guestos == "recovery_dev":
            env_var_files["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = "//bazel:version.txt"
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "//ic-os/guestos/envs/recovery-dev:disk-img.tar.zst"
            icos_images["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG"] = "//ic-os/guestos/envs/dev:update-img.tar.zst"  # use the branch update image for initial update image
            _runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"  # use the branch update image for initial update image

        else:
            fail("unknown guestos version: " + str(guestos))

    if guestos_update:
        if guestos_update == True:  # HEAD version
            env_var_files["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = "//bazel:version.txt"
            icos_images["ENV_DEPS__GUESTOS_UPDATE_IMG"] = "//ic-os/guestos/envs/dev:update-img.tar.zst"
            _runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"

        elif guestos_update == "test":
            env_var_files["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = "//rs/tests:version-test"
            icos_images["ENV_DEPS__GUESTOS_UPDATE_IMG"] = "//ic-os/guestos/envs/dev:update-img-test.tar.zst"
            _runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements-test.json"

        elif guestos_update == "malicious":
            env_var_files["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = "//bazel:version.txt"
            icos_images["ENV_DEPS__GUESTOS_UPDATE_IMG"] = "//ic-os/guestos/envs/dev-malicious:update-img.tar.zst"
            _runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev-malicious:launch-measurements.json"

        elif guestos_update == "mainnet_latest":
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = MAINNET_LATEST["version"]
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_LATEST["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_HASH"] = MAINNET_LATEST["hash"]
            _runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_guestos_images//:launch-measurements-guest.json"

        elif guestos_update == "mainnet_nns":
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = MAINNET_NNS["version"]
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_NNS["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_HASH"] = MAINNET_NNS["hash"]
            _runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_nns_images//:launch-measurements-guest.json"

        elif guestos_update == "mainnet_app":
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = MAINNET_APP["version"]
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_APP["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_HASH"] = MAINNET_APP["hash"]
            _runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_app_images//:launch-measurements-guest.json"

        else:
            fail("unknown guestos update version: " + str(guestos_update))

    if uses_setupos_img:
        icos_images["ENV_DEPS__EMPTY_DISK_IMG"] = "//rs/tests/nested:empty-disk-img.tar.zst"
        env_var_files["ENV_DEPS__SETUPOS_DISK_IMG_VERSION"] = "//bazel:version.txt"
        icos_images["ENV_DEPS__SETUPOS_DISK_IMG"] = "//ic-os/setupos:test-img.tar.zst"
        _runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"

        _runtime_deps["ENV_DEPS__SETUPOS_BUILD_CONFIG"] = "//ic-os:dev-tools/build-setupos-config-image.sh"

    # note: which image is used here depends on guestos
    if uses_setupos_mainnet_latest_img:
        icos_images["ENV_DEPS__EMPTY_DISK_IMG"] = "//rs/tests/nested:empty-disk-img.tar.zst"
        env["ENV_DEPS__SETUPOS_DISK_IMG_VERSION"] = MAINNET_LATEST_HOSTOS["version"]
        icos_images["ENV_DEPS__SETUPOS_DISK_IMG"] = "//ic-os/setupos:mainnet-latest-test-img.tar.zst" if guestos != "mainnet_latest_dev" else "//ic-os/setupos:mainnet-latest-test-img-dev.tar.zst"
        _runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_hostos_images//:launch-measurements-guest.json" if guestos != "mainnet_latest_dev" else "@mainnet_latest_hostos_images_dev//:launch-measurements-guest.json"

        _runtime_deps["ENV_DEPS__SETUPOS_BUILD_CONFIG"] = "//ic-os:dev-tools/build-setupos-config-image.sh"

    if uses_hostos_update:
        env_var_files["ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION"] = "//bazel:version.txt"
        icos_images["ENV_DEPS__HOSTOS_UPDATE_IMG"] = "//ic-os/hostos/envs/dev:update-img.tar.zst"

    if uses_hostos_test_update:
        env_var_files["ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION"] = "//rs/tests:version-test"
        icos_images["ENV_DEPS__HOSTOS_UPDATE_IMG"] = "//ic-os/hostos/envs/dev:update-img-test.tar.zst"

    # note: which image is used here depends on guestos
    if uses_hostos_mainnet_latest_update:
        env["ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION"] = MAINNET_LATEST_HOSTOS["version"]
        env["ENV_DEPS__HOSTOS_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_LATEST_HOSTOS["version"], "host-os", True) if guestos != "mainnet_latest_dev" else icos_dev_image_download_url(MAINNET_LATEST_HOSTOS["version"], "host-os", True)
        env["ENV_DEPS__HOSTOS_UPDATE_IMG_HASH"] = MAINNET_LATEST_HOSTOS["hash" if guestos != "mainnet_latest_dev" else "dev_hash"]

    env_var_files["FARM_METADATA"] = "//rs/tests:farm_metadata.txt"

    extra_args_simple = []
    extra_args_colocated = []

    data = list(runtime_deps)

    # We use the RUN_SCRIPT_ prefix for variables that are processed by the run
    # script, and not passed directly to the test.

    # The uploader for dependencies fetched remotely from the runner
    _runtime_deps["RUN_SCRIPT_UPLOAD_SYSTEST_DEP"] = "//rs/tests:upload_systest_dep.sh"

    # Vector VM dep for logs
    if logs:
        _runtime_deps["VECTOR_VM_PATH"] = "//rs/tests:vector_with_log_fetcher_image"
    else:
        extra_args_simple.append("--no-logs")

    # colocated tests have their own vector VM logic
    extra_args_colocated.append("--no-logs")

    # no summary for colocated tests
    extra_args_colocated.append("--no-summary-report")

    for pat in exclude_logs:
        extra_args_simple.extend(["--exclude-logs", pat])
        extra_args_colocated.extend(["--exclude-logs", pat])

    extra_args_simple.extend(["--group-base-name", test_name])
    extra_args_colocated.extend(["--group-base-name", test_name + "_colocate"])

    # Convert _runtime_deps into environment variables + data dependencies
    env |= {
        name: "$(rootpath {})".format(dep)
        for name, dep in _runtime_deps.items()
    }
    for dep in _runtime_deps.values():  # Bazel 7.X does not have 'set()', Bazel 8 does
        if dep not in data:
            data.append(dep)

    # RUN_SCRIPT_ICOS_IMAGES:
    # Have the run script resolve repo based ICOS images.
    # The run script expects a map of enviromment variable prefixes to targets. e.g.
    # RUN_SCRIPT_ICOS_IMAGES=ENV_DEPS__GUESTOS_DISK_IMG:ic-os/guestos/envs/dev/disk-img.tar.zst;ENV_DEPS__GUESTOS_UPDATE_IMG:ic-os/guestos/envs/dev/update-img.tar.zst
    env["RUN_SCRIPT_ICOS_IMAGES"] = ";".join(["{image_name}:$(rootpath {image_path})".format(image_name = name, image_path = path) for name, path in icos_images.items()])
    for dep in icos_images.values():  # Bazel 7.X does not have 'set()', Bazel 8 does
        if dep not in data:
            data.append(dep)

    # RUN_SCRIPT_ENV_VAR_FILES:
    # Used to set environment variable from the content of files.
    # The run script expects a map of enviromment variable to targets. e.g.
    # RUN_SCRIPT_ENV_VAR_FILES=MY_VAR://foo/env-var-contents;BAR://other-var-content
    env["RUN_SCRIPT_ENV_VAR_FILES"] = ";".join(["{varname}:$(rootpath {varfile})".format(varname = k, varfile = v) for k, v in env_var_files.items()])
    for dep in env_var_files.values():  # Bazel 7.X does not have 'set()', Bazel 8 does
        if dep not in data:
            data.append(dep)

    tags = tags + ["requires-network", "system_test"]

    sh_test(
        name = test_name,
        srcs = ["//rs/tests:run_systest.sh"],
        data = data + [test_driver_target],
        env = env | {
            "RUN_SCRIPT_DRIVER_EXTRA_ARGS": " ".join(extra_args_simple),
            "RUN_SCRIPT_TEST_EXECUTABLE": "$(rootpath {})".format(test_driver_target),
        },
        env_inherit = env_inherit,
        tags = tags + (["manual"] if "colocate" in tags else []),
        target_compatible_with = ["@platforms//os:linux"],
        timeout = test_timeout,
        flaky = flaky,
        visibility = visibility,
    )

    sh_test(
        srcs = ["//rs/tests:run_systest.sh"],
        name = test_name + "_colocate",
        data = data + [
            "//rs/tests:colocate_uvm_config_image",
            "//rs/tests/idx:colocate_test_bin",
            test_driver_target,
        ],
        env_inherit = env_inherit,
        env = env | {
                  "COLOCATED_TEST_BIN": "$(rootpath {})".format(test_driver_target),
                  "RUN_SCRIPT_TEST_EXECUTABLE": "$(rootpath //rs/tests/idx:colocate_test_bin)",
                  "RUN_SCRIPT_DRIVER_EXTRA_ARGS": " ".join(extra_args_colocated),
                  "COLOCATED_TEST": test_name,
                  "COLOCATED_TEST_DRIVER_VM_REQUIRED_HOST_FEATURES": json.encode(colocated_test_driver_vm_required_host_features),
                  "COLOCATED_TEST_DRIVER_VM_RESOURCES": json.encode(colocated_test_driver_vm_resources),
              } | ({"COLOCATED_TEST_DRIVER_VM_ENABLE_IPV4": "1"} if colocated_test_driver_vm_enable_ipv4 else {}) |
              ({"COLOCATED_TEST_DRIVER_VM_FORWARD_SSH_AGENT": "1"} if colocated_test_driver_vm_forward_ssh_agent else {}),
        tags = tags + (["colocated"] if "colocate" in tags else ["manual"]) + additional_colocate_tags,
        target_compatible_with = ["@platforms//os:linux"],
        timeout = test_timeout,
        flaky = flaky,
        visibility = visibility,
    )
    return struct(test_driver_target = test_driver_target)

def system_test_nns(name, enable_head_nns_variant = True, enable_mainnet_nns_variant = True, **kwargs):
    """Declares a system-test that uses the mainnet NNS and a variant that use the HEAD NNS.

    Declares two system-tests:

    * One with the given name which uses the NNS from mainnet as specified by mainnet-canisters.bzl.
    * One with the given name suffixed with "_head_nns" which uses the NNS from the HEAD of the repo.

    The head_nns variant is additionally tagged with either:
    * ["manual"] if enable_head_nns_variant is disabled.
    * [] if "long_test" in tags to ensure the head_nns variant runs once on daily
    * ["system_test_large"] otherwise.

    The idea being that for most system-tests which test the replica it's more realistic to test against the
    mainnet NNS since that version would be active when the replica would be released.

    However it's still useful to see if the HEAD replica works against the HEAD NNS which is why this macro
    introduces the <name>_head_nns variant which only runs daily if not overriden.

    Alternatively, if the mainnet variant should be tagged with ["manual"], then enable_mainnet_nns_variant can be disabled.

    Args:
        name: the name of the system-tests.
        enable_head_nns_variant: whether to run the head_nns variant daily.
        enable_mainnet_nns_variant: whether to run the mainnet variant.
        **kwargs: the arguments of the system-tests.

    Returns:
      This macro declares 2 bazel targets.
      It returns a struct specifying test_driver_target which is the name of the test driver target ("<name>_bin") such that it can be used by other system-tests.
    """
    runtime_deps = kwargs.pop("runtime_deps", [])
    env = kwargs.pop("env", {})

    original_tags = kwargs.pop("tags", [])

    extra_mainnet_nns_tags = (
        # Disable the mainnet variant if requested
        ["manual"] if not enable_mainnet_nns_variant else []
    )

    mainnet_nns_systest = system_test(
        name,
        env = env | MAINNET_NNS_CANISTER_ENV,
        runtime_deps = runtime_deps + MAINNET_NNS_CANISTER_RUNTIME_DEPS,
        tags = [tag for tag in original_tags if tag not in extra_mainnet_nns_tags] + extra_mainnet_nns_tags,
        **kwargs
    )

    extra_head_nns_tags = (
        # Disable the head_nns variant if requested
        ["manual"] if not enable_head_nns_variant else
        # Don't include the default "system_test_large" tag for the head_nns variant of long_tests to ensure it only runs once.
        [] if "long_test" in original_tags else
        # Run the head_nns variant daily.
        ["system_test_large"]
    )

    kwargs["test_driver_target"] = mainnet_nns_systest.test_driver_target
    system_test(
        name + "_head_nns",
        env = env | NNS_CANISTER_ENV,
        runtime_deps = runtime_deps + NNS_CANISTER_RUNTIME_DEPS,
        tags = [tag for tag in original_tags if tag not in extra_head_nns_tags] + extra_head_nns_tags,
        **kwargs
    )
    return struct(test_driver_target = mainnet_nns_systest.test_driver_target)

def uvm_config_image(name, tags = None, visibility = None, srcs = None, remap_paths = None, testonly = True):
    """This macro creates bazel targets for uvm config images.

    Args:
        name: This name will be used for the target.
        tags: Controls execution of targets. "manual" excludes a target from wildcard targets like (..., :*, :all). See: https://bazel.build/reference/test-encyclopedia#tag-conventions
        visibility: Target visibility controls who may depend on a target.
        srcs: Source files that are copied into a vfat image.
        remap_paths: Dict that maps a current filename to a desired filename,
            e.g. {"activate.sh": "activate"}
        testonly: If True, the target is only available in test configurations.
    """
    native.genrule(
        name = name + "_size",
        srcs = srcs,
        outs = [name + "_size.txt"],
        cmd = "du --bytes -csL $(SRCS) | awk '$$2 == \"total\" {print 2 * $$1 + 1048576}' > $@",
        tags = ["manual"],
        target_compatible_with = ["@platforms//os:linux"],
        visibility = ["//visibility:private"],
        testonly = testonly,
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
        testonly = testonly,
    )

    mcopy(
        name = name + "_mcopy",
        srcs = srcs,
        fs = ":" + name + "_vfat",
        remap_paths = remap_paths,
        tags = ["manual"],
        target_compatible_with = ["@platforms//os:linux"],
        visibility = ["//visibility:private"],
        testonly = testonly,
    )

    zstd_compress(
        name = name + ".zst",
        srcs = [":" + name + "_mcopy"],
        target_compatible_with = ["@platforms//os:linux"],
        tags = tags,
        visibility = ["//visibility:private"],
        testonly = testonly,
    )

    native.alias(
        name = name,
        actual = name + ".zst",
        tags = tags,
        target_compatible_with = ["@platforms//os:linux"],
        visibility = visibility,
        testonly = testonly,
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
