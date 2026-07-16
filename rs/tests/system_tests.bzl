"""
Rules for system-tests.
"""

load("@rules_oci//oci:defs.bzl", "oci_load")
load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("//bazel:defs.bzl", "mcopy", "zstd_compress")
load("//rs/tests:common.bzl", "MAINNET_NNS_CANISTER_RUNTIME_DEPS", "NNS_CANISTER_RUNTIME_DEPS")
load("//rs/tests:configure_icos.bzl", "configure_icos")

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
        backend = None,
        test_timeout = "long",
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
        hostos = False,
        hostos_update = False,
        env = {},
        env_inherit = [],
        exclude_logs = ["prometheus", "vector"],
        data = [],
        additional_colocate_tags = [],
        logs = True,
        vm_allocation_mode = None,
        cpus = None,
        **kwargs):
    """Declares a system-test.

    Args:
      name: base name to use for the binary and test rules.
      test_name: optional name for the test, useful when the test name is different than name.
      test_driver_target: optional string to identify the target of the test driver binary. Defaults to None which means declare a rust_binary from <name>.rs.
      runtime_deps: dependencies to make available to the test when it runs.
      tags: additional tags for the system_test.
      backend: None | "farm" | "local".
        If "farm" the `_local` variant will be tagged as "manual".
        If "local" the non `_local` variants will be tagged as "manual".
        If None, both the `_local` and the non `_local` variants won't be tagged as "manual" and will run by default.
      test_timeout: bazel test timeout (short, moderate, long or eternal).
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
      guestos: see configure_icos().
      guestos_update: see configure_icos().
      hostos: see configure_icos().
      hostos_update: see configure_icos().
      setupos: see configure_icos().
      env: environment variables to set in the test (subject to Make variable expansion)
      env_inherit: specifies additional environment variables to inherit from
      the external environment when the test is executed by bazel test.
      additional_colocate_tags: additional tags to pass to the colocated test.
      logs: Specifies if vector vm for scraping logs should not be spawned.
      exclude_logs: Specifies uvm name patterns to exclude from streaming.
      data: List of files used by the test driver.
      vm_allocation_mode: Optional VM allocation mode string forwarded to the
        test driver via the `VM_ALLOCATION_MODE` environment variable. Must
        match one of the serde rename strings of `VmAllocationMode`, e.g.
        `"performanceOptimizedAllocation"`,
        `"minIntraDistanceLoadBalanceAllocation"` or `"distributeAcrossDcs"`.
        When None it defaults to `"minIntraDistanceLoadBalanceAllocation"`.
      cpus: Optional number of CPU cores to reserve for the local variant of the test.
        This will translate into an `exec_properties = {"cpu": str(cpus)}` setting for the `_local` variant.
        Heuristic: set it to MIN_LOCAL_CPUS + number of vCPUs required for the whole testnet. DEFAULT_VCPUS_PER_VM can be used for the default number of vCPUs per VM if not overridden.
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

    # Bazel-built FAT tools the driver uses to assemble config images for
    # universal VMs / SetupOS / GuestOS, instead of system dosfstools/mtools.
    # These are set on the test process and read (by name) from the driver and
    # the config-image scripts it spawns; see run_systest.sh (symlink handling)
    # and colocate_test.rs.
    _runtime_deps["MKFS_FAT"] = "@dosfstools//:mkfs.fat"
    _runtime_deps["MCOPY"] = "@mtools//:mcopy"
    _runtime_deps["MLABEL"] = "@mtools//:mlabel"

    env_var_files = {}
    icos_images = dict()

    # # IC-OS image configuration
    icos_config = configure_icos(guestos = guestos, guestos_update = guestos_update, hostos = hostos, hostos_update = hostos_update, setupos = setupos)
    env_var_files |= icos_config.env_var_files
    env |= icos_config.env
    _runtime_deps |= icos_config.runtime_deps
    icos_images |= icos_config.icos_images

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

    if vm_allocation_mode != None:
        allowed_vm_allocation_modes = [
            "minIntraDistanceLoadBalanceAllocation",
            "performanceOptimizedAllocation",
            "distributeAcrossDcs",
        ]
        if vm_allocation_mode not in allowed_vm_allocation_modes:
            fail("Invalid vm_allocation_mode {}: must be one of {}".format(
                repr(vm_allocation_mode),
                allowed_vm_allocation_modes,
            ))
        env |= {"VM_ALLOCATION_MODE": vm_allocation_mode}

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

    # Make the test driver allocate the Farm testnet to the same DC as the
    # machine running the test (the DC volatile status variable derived from
    # NODE_NAME). This avoids slow cross-DC transfers of large images.
    # No-op when the DC is unknown, e.g. when running locally.
    farm_only_env = {
        "ALLOCATE_TESTNET_TO_LOCAL_DC": "1",
    }

    valid_backends = [None, "farm", "local"]
    if backend not in valid_backends:
        fail("Invalid backend {}: must be one of {}".format(
            repr(backend),
            valid_backends,
        ))

    tags = tags + ["system_test"]

    # The Farm backend needs sandbox network access, so it gets `requires-network`.
    # The local backend is the opposite: it creates its bridge/TAPs and boots VMs
    # inside the test's own network namespace, which (with
    # `--nosandbox_default_allow_network`) only works when the test runs in a fresh
    # network namespace owned by the sandbox's user namespace -- i.e. when
    # `requires-network` is *absent*. With the tag present the test runs in the host
    # network namespace, where the user-namespaced sandbox process lacks effective
    # CAP_NET_ADMIN and bridge creation fails with
    #`RTNETLINK answers: Operation not permitted`.
    farm_tags = tags + ["requires-network", "farm_system_test"]

    env["RUN_SCRIPT_VOLATILE_STATUS_PATH"] = "$(rootpath //bazel:volatile-status.txt)"
    data.append("//bazel:volatile-status.txt")

    # Runtime deps that are only needed when running on the local (QEMU-based) backend.
    _local_only_deps = {
        image_name + "_PATH": image_path
        for image_name, image_path in icos_images.items()
    }

    # Images that are only served by the Local backend's file server (and never
    # uploaded to Farm): e.g. the mainnet GuestOS update images. These get a
    # `_PATH` runtime dep for the local backend; their `_HASH` is already set in
    # the environment by `configure_icos`, so the file server can advertise them
    # under the correct content hash. They are intentionally *not* added to
    # `icos_images` so the Farm variant keeps downloading them from the CDN.
    for image_name, image_path in icos_config.local_only_icos_images.items():
        _local_only_deps[image_name + "_PATH"] = image_path

    _local_only_deps["ENV_DEPS__UNIVERSAL_VM_DISK_IMG_PATH"] = "@farm_universal_vm_img//file"
    _local_only_deps["ENV_DEPS__PROMETHEUS_VM_DISK_IMG_PATH"] = "@farm_prometheus_vm_img//file"
    _local_only_deps["ENV_DEPS__DNSMASQ_PATH"] = "@dnsmasq//:dnsmasq"
    _local_only_deps["ENV_DEPS__QEMU_IMG_PATH"] = "@qemu_img_prebuilt_linux_amd64//:qemu-img"
    _local_only_deps["ENV_DEPS__QEMU_SYSTEM_X86_64_PATH"] = "@qemu_system_bin_prebuilt_linux_amd64_x86_64_softmmu//:qemu-system-x86_64"
    _local_only_deps["ENV_DEPS__QEMU_SYSTEM_DATA_PATH"] = "@qemu_system_data_prebuilt_linux_amd64//:qemu-system-data"

    # Split OVMF (UEFI) firmware for the QEMU VMs (see local_backend.rs). The
    # code image is mounted read-only and shared; the vars image is a per-VM
    # writable varstore template.
    _local_only_deps["ENV_DEPS__OVMF_CODE_PATH"] = "//:OVMF_CODE_4M.fd"
    _local_only_deps["ENV_DEPS__OVMF_VARS_PATH"] = "//:OVMF_VARS_4M.fd"

    local_dep_env = {
        name: "$(rootpath {})".format(dep)
        for name, dep in _local_only_deps.items()
    }

    # The local backend runs in a sandbox without external network access, so it
    # has no Vector VM to ship logs to ElasticSearch (--no-logs). Instead, stream
    # the journald logs of all IC nodes directly to the test log
    # (--stream-ic-node-logs) and tail each VM's serial console
    # (--stream-console-logs).
    local_args = ([] if "--no-logs" in extra_args_simple else ["--no-logs"]) + ["--stream-ic-node-logs", "--stream-console-logs"]

    sh_test(
        name = test_name + "_local",
        srcs = ["//rs/tests:run_systest.sh"],
        data = data + [dep for dep in _local_only_deps.values() if dep not in data],
        env = env | local_dep_env | {
            "SYSTEM_TEST_BACKEND": "local",
            "RUN_SCRIPT_DRIVER_EXTRA_ARGS": " ".join(extra_args_simple + local_args),
            "RUN_SCRIPT_TEST_EXECUTABLE": "$(rootpath {})".format(test_driver_target),
            "RUN_SCRIPT_RUNTIME_DEP_ENV_VARS": ";".join(_runtime_deps.keys() + _local_only_deps.keys()),
        },
        env_inherit = env_inherit,
        tags = tags + ["local_system_test"] + (["manual"] if backend == "farm" else []),
        # The `cpu:n` tag is not forwarded to the Remote Execution API, so we set the execution properties explicitly:
        exec_properties = {"cpu": str(cpus)} if cpus != None else {},
        target_compatible_with = ["@platforms//os:linux"],
        timeout = test_timeout,
        visibility = visibility,
    )

    sh_test(
        name = test_name,
        srcs = ["//rs/tests:run_systest.sh"],
        data = data,
        env = env | farm_only_env | {
            "RUN_SCRIPT_DRIVER_EXTRA_ARGS": " ".join(extra_args_simple),
            "RUN_SCRIPT_TEST_EXECUTABLE": "$(rootpath {})".format(test_driver_target),
        },
        env_inherit = env_inherit,
        tags = farm_tags + (["manual"] if "colocate" in tags or backend == "local" else []),
        target_compatible_with = ["@platforms//os:linux"],
        timeout = test_timeout,
        visibility = visibility,
    )

    # create a colocated version of the test (marked as manual _unless_ the test is tagged with "colocate")
    sh_test(
        srcs = ["//rs/tests:run_systest.sh"],
        name = test_name + "_colocate",
        data = data + [
            "//rs/tests:colocate_uvm_config_image",
            "//rs/tests/idx:colocate_test_bin",
        ],
        env_inherit = env_inherit,
        env = env | farm_only_env | {
                  "RUN_SCRIPT_TEST_EXECUTABLE": "$(rootpath //rs/tests/idx:colocate_test_bin)",
                  "RUN_SCRIPT_DRIVER_EXTRA_ARGS": " ".join(extra_args_colocated),
                  "COLOCATED_UVM_CONFIG_IMAGE_PATH": "$(rootpath //rs/tests:colocate_uvm_config_image)",
                  "COLOCATED_TEST_NAME": test_name,
                  "COLOCATED_TEST_DRIVER_VM_REQUIRED_HOST_FEATURES": json.encode(colocated_test_driver_vm_required_host_features),
                  "COLOCATED_TEST_DRIVER_VM_RESOURCES": json.encode(colocated_test_driver_vm_resources),
              } | ({"COLOCATED_TEST_DRIVER_VM_ENABLE_IPV4": "1"} if colocated_test_driver_vm_enable_ipv4 else {}) |
              ({"COLOCATED_TEST_DRIVER_VM_FORWARD_SSH_AGENT": "1"} if colocated_test_driver_vm_forward_ssh_agent else {}),
        tags = farm_tags + (["manual"] if not "colocate" in tags or backend == "local" else []) + additional_colocate_tags,
        target_compatible_with = ["@platforms//os:linux"],
        timeout = test_timeout,
        visibility = visibility,
    )
    return struct(test_driver_target = test_driver_target)

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

def uvm_config_image(name, tags = None, visibility = None, srcmap = None, testonly = True):
    """This macro creates bazel targets for uvm config images.

    Args:
        name: This name will be used for the target.
        tags: Controls execution of targets. "manual" excludes a target from wildcard targets like (..., :*, :all). See: https://bazel.build/reference/test-encyclopedia#tag-conventions
        visibility: Target visibility controls who may depend on a target.
        srcmap: Dictionary of source files to copy into a vfat image mapped to their desired path in the image.
        testonly: If True, the target is only available in test configurations.
    """
    native.genrule(
        name = name + "_size",
        srcs = srcmap.keys(),
        outs = [name + "_size.txt"],
        # Round the size up to a multiple of 4096 so the raw image is
        # block-aligned: QEMU opened with cache='none' (O_DIRECT) refuses a
        # writable raw image whose size is not a multiple of the host block size.
        cmd = "du --bytes -csL $(SRCS) | awk '$$2 == \"total\" { s = 2 * $$1 + 1048576; print int((s + 4095) / 4096) * 4096 }' > $@",
        tags = ["manual"],
        target_compatible_with = ["@platforms//os:linux"],
        visibility = ["//visibility:private"],
        testonly = testonly,
    )

    native.genrule(
        name = name + "_vfat",
        srcs = [":" + name + "_size"],
        outs = [name + "_vfat.img"],
        tools = ["@dosfstools//:mkfs.fat"],
        cmd = """
        truncate -s $$(cat $<) $@
        $(location @dosfstools//:mkfs.fat) -i 0 -n CONFIG $@
        """,
        tags = ["manual"],
        target_compatible_with = ["@platforms//os:linux"],
        visibility = ["//visibility:private"],
        testonly = testonly,
    )

    mcopy(
        name = name + "_mcopy",
        srcmap = srcmap,
        fs = ":" + name + "_vfat",
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

    tarball = basename + "_tarball"

    # First load the image
    oci_load(
        name = tarball,
        image = image,
        repo_tags = repo_tags,
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    # create the tarball
    native.filegroup(
        name = name,
        srcs = [":" + tarball],
        output_group = "tarball",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual"],
    )
