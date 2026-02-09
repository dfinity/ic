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
load("//rs/tests:common.bzl", "MAINNET_NNS_CANISTER_RUNTIME_DEPS", "NNS_CANISTER_RUNTIME_DEPS")

default_vm_resources = {
    "vcpus": None,
    "memory_kibibytes": None,
    "boot_image_minimal_size_gibibytes": None,
}

def system_test(
        name,
        test_name = None,
        test_driver_target = None,
        runtime_deps = {},
        tags = [],
        test_timeout = "long",
        flaky = False,
        enable_metrics = False,
        prometheus_vm_required_host_features = [],
        prometheus_vm_resources = default_vm_resources,
        prometheus_vm_scrape_interval_secs = 10,
        colocated_test_driver_vm_resources = default_vm_resources,
        colocated_test_driver_vm_required_host_features = [],
        colocated_test_driver_vm_enable_ipv4 = False,
        colocated_test_driver_vm_forward_ssh_agent = False,
        guestos = True,
        guestos_update = False,
        setupos = False,
        hostos_update = False,
        env = {},
        env_inherit = [],
        exclude_logs = ["prometheus", "vector"],
        data = [],
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
      enable_metrics: if True, a PrometheusVm will be spawned running both p8s (configured to scrape the testnet) & Grafana.
      prometheus_vm_required_host_features: a list of strings specifying the required host features of the PrometheusVm.
      prometheus_vm_resources: a structure describing the required resources of the PrometheusVm. For example:
        {
          "vcpus": 32,
          "memory_kibibytes": 125000000,
          "boot_image_minimal_size_gibibytes": 500,
        }
      prometheus_vm_scrape_interval_secs: the scrape interval in seconds for the PrometheusVm. Defaults to 10 seconds.
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
      guestos: The guestos image version. Can be a single value or a dictionary mapping tags to versions.
        Single values: True (HEAD) | False | "malicious" | "recovery_dev" | "mainnet_latest" | "mainnet_latest_dev" | "mainnet_nns" | "mainnet_app". Default: True
        Dictionary: {"default": True, "my_tag": "mainnet_latest_dev"} - the "default" key works like the single value.
        Each tag generates env variables like ENV_DEPS__GUESTOS_{TAG}_DISK_IMG (uppercase tag).
      guestos_update: The guestos update image version. Values: False | True (HEAD) | "test" | "malicious" | "mainnet_latest" | "mainnet_latest_dev" | "mainnet_nns" | "mainnet_app". Default: False
      setupos: The setupos image version. Values: False | True (HEAD) | "mainnet_latest" | "mainnet_latest_dev". Default: False
      hostos_update: The hostos update image version. Values: False | True (HEAD) | "test" | "mainnet_latest" | "mainnet_latest_dev". Default: False
      env: environment variables to set in the test (subject to Make variable expansion)
      env_inherit: specifies additional environment variables to inherit from
      the external environment when the test is executed by bazel test.
      additional_colocate_tags: additional tags to pass to the colocated test.
      logs: Specifies if vector vm for scraping logs should not be spawned.
      exclude_logs: Specifies uvm name patterns to exclude from streaming.
      data: List of files used by the test driver.
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

    _runtime_deps = dict(runtime_deps)

    _runtime_deps["TEST_BIN"] = test_driver_target

    env_var_files = {}
    icos_images = dict()

    # IC-OS image configuration
    _configure_icos(env, env_var_files, icos_images, _runtime_deps, guestos, guestos_update, setupos, hostos_update)

    env_var_files["FARM_METADATA"] = "//rs/tests:farm_metadata.txt"

    extra_args_simple = []
    extra_args_colocated = []

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
    data = list(data)
    for dep in _runtime_deps.values():  # Bazel 7.X does not have 'set()', Bazel 8 does
        if dep not in data:
            data.append(dep)

    if enable_metrics:
        extra_args_simple.append("--enable-metrics")

        # For colocated tests we want to --enable-metrics in the colocated test-driver
        # but we don't want to --enable-metrics in the wrapper test-driver (otherwise we would get two p8s VMs).
        # To implement this we set the ENABLE_METRICS environment variable.
        # The wrapper test-driver will then set --enable-metrics for the colocated test-driver if this variable is set.
        env |= {"ENABLE_METRICS": "1"}

    env |= {
        "PROMETHEUS_VM_REQUIRED_HOST_FEATURES": json.encode(prometheus_vm_required_host_features),
        "PROMETHEUS_VM_RESOURCES": json.encode(prometheus_vm_resources),
        "PROMETHEUS_VM_SCRAPE_INTERVAL_SECS": json.encode(prometheus_vm_scrape_interval_secs),
    }

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

    RUN_SCRIPT_RUNTIME_DEP_ENV_VARS = ";".join(_runtime_deps.keys())
    env["RUN_SCRIPT_RUNTIME_DEP_ENV_VARS"] = RUN_SCRIPT_RUNTIME_DEP_ENV_VARS

    tags = tags + ["requires-network", "system_test"]

    sh_test(
        name = test_name,
        srcs = ["//rs/tests:run_systest.sh"],
        data = data,
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

    COLOCATED_RUNTIME_DEP_ENV_VARS = RUN_SCRIPT_RUNTIME_DEP_ENV_VARS

    # create a colocated version of the test (marked as manual _unless_ the test is tagged with "colocate")
    sh_test(
        srcs = ["//rs/tests:run_systest.sh"],
        name = test_name + "_colocate",
        data = data + [
            "//rs/tests:colocate_uvm_config_image",
            "//rs/tests/idx:colocate_test_bin",
        ],
        env_inherit = env_inherit,
        env = env | {
                  "RUN_SCRIPT_TEST_EXECUTABLE": "$(rootpath //rs/tests/idx:colocate_test_bin)",
                  "RUN_SCRIPT_DRIVER_EXTRA_ARGS": " ".join(extra_args_colocated),
                  "COLOCATED_RUNTIME_DEP_ENV_VARS": COLOCATED_RUNTIME_DEP_ENV_VARS,
                  "COLOCATED_UVM_CONFIG_IMAGE_PATH": "$(rootpath //rs/tests:colocate_uvm_config_image)",
                  "COLOCATED_TEST_NAME": test_name,
                  "COLOCATED_TEST_DRIVER_VM_REQUIRED_HOST_FEATURES": json.encode(colocated_test_driver_vm_required_host_features),
                  "COLOCATED_TEST_DRIVER_VM_RESOURCES": json.encode(colocated_test_driver_vm_resources),
              } | ({"COLOCATED_TEST_DRIVER_VM_ENABLE_IPV4": "1"} if colocated_test_driver_vm_enable_ipv4 else {}) |
              ({"COLOCATED_TEST_DRIVER_VM_FORWARD_SSH_AGENT": "1"} if colocated_test_driver_vm_forward_ssh_agent else {}),
        tags = tags + (["manual"] if not "colocate" in tags else []) + additional_colocate_tags,
        target_compatible_with = ["@platforms//os:linux"],
        timeout = test_timeout,
        flaky = flaky,
        visibility = visibility,
    )
    return struct(test_driver_target = test_driver_target)

def _configure_icos(env, env_var_files, icos_images, runtime_deps, guestos, guestos_update, setupos, hostos_update):
    # Normalize guestos to a dictionary format
    if type(guestos) == "dict":
        guestos_dict = guestos
    else:
        guestos_dict = {"default": guestos}

    # Get the default guestos value for setupos compatibility check
    default_guestos = guestos_dict.get("default", False)

    if default_guestos and setupos and default_guestos != setupos:
        fail("If both guestos (default) and setupos are specified, they must be the same")

    def guestos_local(suffix, env):
        """Configure a GuestOS disk image (the GuestOS that the test starts with) built from the local workspace."""
        env_var_files["ENV_DEPS__GUESTOS" + suffix + "_DISK_IMG_VERSION"] = "//bazel:version.txt"
        icos_images["ENV_DEPS__GUESTOS" + suffix + "_DISK_IMG"] = "//ic-os/guestos/envs/" + env + ":disk-img.tar.zst"
        icos_images["ENV_DEPS__GUESTOS" + suffix + "_INITIAL_UPDATE_IMG"] = "//ic-os/guestos/envs/" + env + ":update-img.tar.zst"
        runtime_deps["ENV_DEPS__GUESTOS" + suffix + "_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/" + env + ":launch-measurements.json"

    def guestos_mainnet(suffix, version_dict, repo, dev = False):
        """Configure a GuestOS base image (the GuestOS that the test starts with) from the version available on mainnet."""
        url_fn = icos_dev_image_download_url if dev else icos_image_download_url
        env["ENV_DEPS__GUESTOS" + suffix + "_DISK_IMG_VERSION"] = version_dict["version"]
        icos_images["ENV_DEPS__GUESTOS" + suffix + "_DISK_IMG"] = repo + "//:guest-img"
        env["ENV_DEPS__GUESTOS" + suffix + "_INITIAL_UPDATE_IMG_URL"] = url_fn(version_dict["version"], "guest-os", True)
        env["ENV_DEPS__GUESTOS" + suffix + "_INITIAL_UPDATE_IMG_HASH"] = version_dict["dev_hash" if dev else "hash"]
        runtime_deps["ENV_DEPS__GUESTOS" + suffix + "_LAUNCH_MEASUREMENTS_FILE"] = repo + "//:launch-measurements-guest.json"

    def guestos_update_local(guestos_env, test = False):
        """Configure a GuestOS update image (the GuestOS that the test updates to) built from the local workspace."""
        suffix = "-test" if test else ""
        env_var_files["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = "//rs/tests:version-test" if test else "//bazel:version.txt"
        icos_images["ENV_DEPS__GUESTOS_UPDATE_IMG"] = "//ic-os/guestos/envs/" + guestos_env + ":update-img" + suffix + ".tar.zst"
        runtime_deps["ENV_DEPS__GUESTOS_UPDATE_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/" + guestos_env + ":launch-measurements" + suffix + ".json"

    def guestos_update_mainnet(version_dict, repo, dev = False):
        """Configure a GuestOS update image (the GuestOS that the test updates to) from the version available on mainnet."""
        url_fn = icos_dev_image_download_url if dev else icos_image_download_url
        env["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = version_dict["version"]
        env["ENV_DEPS__GUESTOS_UPDATE_IMG_URL"] = url_fn(version_dict["version"], "guest-os", True)
        env["ENV_DEPS__GUESTOS_UPDATE_IMG_HASH"] = version_dict["dev_hash" if dev else "hash"]
        runtime_deps["ENV_DEPS__GUESTOS_UPDATE_LAUNCH_MEASUREMENTS_FILE"] = repo + "//:launch-measurements-guest.json"

    def setupos_dependencies():
        """Configure required dependencies when a SetupOS is used. """
        icos_images["ENV_DEPS__EMPTY_DISK_IMG"] = "//rs/tests/nested:empty-disk-img.tar.zst"
        runtime_deps["ENV_DEPS__SETUPOS_BUILD_CONFIG"] = "//ic-os:dev-tools/build-setupos-config-image.sh"

    def setupos_local():
        """Configure a SetupOS disk image (the SetupOS that the test starts with) built from the local workspace."""
        env_var_files["ENV_DEPS__SETUPOS_DISK_IMG_VERSION"] = "//bazel:version.txt"
        icos_images["ENV_DEPS__SETUPOS_DISK_IMG"] = "//ic-os/setupos:test-img.tar.zst"
        runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"

    def setupos_mainnet(dev):
        """Configure a SetupOS disk image (the SetupOS that the test starts with) from the version available on mainnet."""
        env["ENV_DEPS__SETUPOS_DISK_IMG_VERSION"] = MAINNET_LATEST_HOSTOS["version"]
        icos_images["ENV_DEPS__SETUPOS_DISK_IMG"] = "//ic-os/setupos:mainnet-latest-test-img-dev.tar.zst" if dev else "//ic-os/setupos:mainnet-latest-test-img.tar.zst"
        runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_hostos_images_dev//:launch-measurements-guest.json" if dev else "@mainnet_latest_hostos_images//:launch-measurements-guest.json"

    def hostos_update_local(test = False):
        """Configure a HostOS update image (the HostOS that the test updates to) built from the local workspace."""
        env_var_files["ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION"] = "//rs/tests:version-test" if test else "//bazel:version.txt"
        icos_images["ENV_DEPS__HOSTOS_UPDATE_IMG"] = "//ic-os/hostos/envs/dev:update-img-test.tar.zst" if test else "//ic-os/hostos/envs/dev:update-img.tar.zst"

    def hostos_update_mainnet(dev = False):
        """Configure a HostOS update image (the HostOS that the test updates to) from the version available on mainnet."""
        url_fn = icos_dev_image_download_url if dev else icos_image_download_url
        env["ENV_DEPS__HOSTOS_UPDATE_IMG_URL"] = url_fn(MAINNET_LATEST_HOSTOS["version"], "host-os", True)
        env["ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION"] = MAINNET_LATEST_HOSTOS["version"]
        env["ENV_DEPS__HOSTOS_UPDATE_IMG_HASH"] = MAINNET_LATEST_HOSTOS["dev_hash" if dev else "hash"]

    # GuestOS base image configuration
    # Iterate over the guestos dictionary (tag -> version)
    for tag, guestos_version in guestos_dict.items():
        # For "default" tag, use empty suffix (backward compatible)
        # For other tags, use "_TAG" suffix (uppercase)
        suffix = "" if tag == "default" else "_" + tag.upper()

        if guestos_version == True:  # HEAD version
            guestos_local(suffix, "dev")
        elif guestos_version == "malicious":
            guestos_local(suffix, "dev-malicious")
        elif guestos_version == "recovery_dev":
            guestos_local(suffix, "recovery-dev")
        elif guestos_version == "mainnet_latest":
            guestos_mainnet(suffix, MAINNET_LATEST, "@mainnet_latest_guestos_images")
        elif guestos_version == "mainnet_latest_dev":
            guestos_mainnet(suffix, MAINNET_LATEST, "@mainnet_latest_guestos_images_dev", dev = True)
        elif guestos_version == "mainnet_nns":
            guestos_mainnet(suffix, MAINNET_NNS, "@mainnet_nns_images")
        elif guestos_version == "mainnet_app":
            guestos_mainnet(suffix, MAINNET_APP, "@mainnet_app_images")
        elif guestos_version:
            fail("unknown guestos version for tag '" + tag + "': " + str(guestos_version))

    # GuestOS update image configuration
    if guestos_update == True:
        guestos_update_local("dev")
    elif guestos_update == "test":
        guestos_update_local("dev", test = True)
    elif guestos_update == "malicious":
        guestos_update_local("dev-malicious")
    elif guestos_update == "mainnet_latest":
        guestos_update_mainnet(MAINNET_LATEST, "@mainnet_latest_guestos_images")
    elif guestos_update == "mainnet_latest_dev":
        guestos_update_mainnet(MAINNET_LATEST, "@mainnet_latest_guestos_images_dev", dev = True)
    elif guestos_update == "mainnet_nns":
        guestos_update_mainnet(MAINNET_NNS, "@mainnet_nns_images")
    elif guestos_update == "mainnet_app":
        guestos_update_mainnet(MAINNET_APP, "@mainnet_app_images")
    elif guestos_update:
        fail("unknown guestos_update: " + str(guestos_update))

    # SetupOS configuration
    if setupos == True:
        setupos_local()
        setupos_dependencies()
    elif setupos == "mainnet_latest":
        setupos_mainnet()
        setupos_dependencies()
    elif setupos == "mainnet_latest_dev":
        setupos_mainnet(dev = True)
        setupos_dependencies()
    elif setupos:
        fail("unknown setupos: " + str(setupos))

    # HostOS update configuration
    if hostos_update == True:
        hostos_update_local()
    elif hostos_update == "test":
        hostos_update_local(test = True)
    elif hostos_update == "mainnet_latest":
        hostos_update_mainnet()
    elif hostos_update == "mainnet_latest_dev":
        hostos_update_mainnet(dev = True)
    elif hostos_update:
        fail("unknown hostos_update: " + str(hostos_update))

def system_test_nns(name, enable_head_nns_variant = True, enable_mainnet_nns_variant = True, runtime_deps = {}, **kwargs):
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
        runtime_deps: dependencies to make available to the test when it runs. For the mainnet variant this gets merged with the mainnet NNS canisters and for the _head_nns variant it gets merged with the HEAD NNS canisters.
        **kwargs: the arguments of the system-tests.

    Returns:
      This macro declares 2 bazel targets.
      It returns a struct specifying test_driver_target which is the name of the test driver target ("<name>_bin") such that it can be used by other system-tests.
    """

    env = kwargs.pop("env", {})

    original_tags = kwargs.pop("tags", [])

    extra_mainnet_nns_tags = (
        # Disable the mainnet variant if requested
        ["manual"] if not enable_mainnet_nns_variant else []
    )

    mainnet_nns_systest = system_test(
        name,
        runtime_deps = runtime_deps | MAINNET_NNS_CANISTER_RUNTIME_DEPS,
        env = env,
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
        runtime_deps = runtime_deps | NNS_CANISTER_RUNTIME_DEPS,
        env = env,
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
