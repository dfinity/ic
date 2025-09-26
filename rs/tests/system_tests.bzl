"""
Rules for system-tests.
"""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@bazel_skylib//rules:copy_file.bzl", "copy_file")
load("@rules_oci//oci:defs.bzl", "oci_load")
load("@rules_rust//rust:defs.bzl", "rust_binary")
load("//bazel:defs.bzl", "mcopy", "zstd_compress")
load("//bazel:mainnet-icos-images.bzl", "MAINNET_APP", "MAINNET_LATEST", "MAINNET_LATEST_HOSTOS", "MAINNET_NNS", "icos_dev_image_download_url", "icos_image_download_url")
load("//rs/tests:common.bzl", "MAINNET_NNS_CANISTER_ENV", "MAINNET_NNS_CANISTER_RUNTIME_DEPS", "NNS_CANISTER_ENV", "NNS_CANISTER_RUNTIME_DEPS", "UNIVERSAL_VM_RUNTIME_DEPS")

def _run_system_test(ctx):
    run_test_script_file = ctx.actions.declare_file(ctx.label.name + "/run-test.sh")

    # whether to use k8s instead of farm
    k8s = ctx.attr._k8s[BuildSettingInfo].value

    no_logs = True
    if ctx.executable.colocated_test_bin != None:
        # The colocated driver has the logic to see if it should spawn vector
        no_logs = True
    elif "VECTOR_VM_PATH" in ctx.attr.env:
        no_logs = False

    ctx.actions.write(
        output = run_test_script_file,
        is_executable = True,
        content = """#!/bin/bash
            set -eEuo pipefail

            # Resolve any RUN_SCRIPT_ variables

            # RUN_SCRIPT_ICOS_IMAGES:
            # For every ic-os image specified, first ensure it's in remote
            # storage, then export its download URL and HASH as environment variables.
            if [ -n "${{RUN_SCRIPT_ICOS_IMAGES:-}}" ]; then
              # split the ";"-delimited list of "env_prefix:filepath;env_prefix2:filepath2;..."
              # into an array
              IFS=';' read -ra icos_images <<<"$RUN_SCRIPT_ICOS_IMAGES"
              for image in "${{icos_images[@]}}"; do
                  # split "envvar:filepath"
                  image_var_prefix=${{image%:*}}
                  image_filename=${{image#*:}}

                  # ensure the dep is uploaded
                  image_download_url=$("$RUN_SCRIPT_UPLOAD_SYSTEST_DEP" "$image_filename")
                  echo "  -> $image_filename=$image_download_url" >&2

                  # Since this is a CAS url, we assume the last URL path part is the sha256
                  image_download_hash="${{image_download_url##*/}}"
                  # set the environment variables for the test
                  export "${{image_var_prefix}}_URL=$image_download_url"
                  export "${{image_var_prefix}}_HASH=$image_download_hash"
              done
            fi

            # RUN_SCRIPT_INFO_FILE_VARS:
            # For every var specified, pull the value from info_file, and
            # expose it to the test plus the given suffix.
            if [ -n "${{RUN_SCRIPT_INFO_FILE_VARS:-}}" ]; then
              # split the ";"-delimited list of "env_var:info_var:suffix;env_var2:info_var2:suffix;..."
              # into an array
              IFS=';' read -ra vars <<<"$RUN_SCRIPT_INFO_FILE_VARS"
              for var in "${{vars[@]}}"; do
                  # split "envvar:infovar:suffix"
                  IFS=':' read -ra parts <<<"$var"
                  env_var_name="${{parts[0]}}"
                  info_var_name="${{parts[1]}}"
                  suffix="${{parts[2]:-}}"

                  # Expose the variable to the test.
                  export "${{env_var_name}}"="$(grep <{info_file} -e ${{info_var_name}} | cut -d' ' -f2)${{suffix}}"
              done
            fi

            # clean up the env for the test
            unset RUN_SCRIPT_ICOS_IMAGES RUN_SCRIPT_UPLOAD_SYSTEST_DEP RUN_SCRIPT_INFO_FILE_VARS

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
              {logs} \
              {no_summary_report} \
              {exclude_logs} \
              "$@" run
        """.format(
            test_executable = ctx.executable.src.short_path,
            k8s = "--k8s" if k8s else "",
            group_base_name = ctx.label.name,
            no_summary_report = "--no-summary-report" if ctx.executable.colocated_test_bin != None else "",
            info_file = ctx.info_file.short_path,
            logs = "--no-logs" if no_logs else "",
            exclude_logs = " ".join(["--exclude-logs {pattern}".format(pattern = pattern) for pattern in ctx.attr.exclude_logs]),
        ),
    )

    env = dict(ctx.attr.env.items())
    env_deps = ctx.attr.env_deps

    # Expand Make variables in env vars, with runtime_deps as targets
    for key, value in env.items():
        # If this looks like a Make variable, try to expand it
        if value.startswith("$"):
            env[key] = ctx.expand_location(value, ctx.attr.runtime_deps)

    env |= {
        "FARM_METADATA_PATH": ctx.info_file.short_path,
    }

    # We use the RUN_SCRIPT_ prefix for variables that are processed by the run
    # script, and not passed directly to the test.

    # RUN_SCRIPT_ICOS_IMAGES:
    # Have the run script resolve repo based ICOS images.
    # The run script expects a map of enviromment variable prefixes to targets. e.g.
    # RUN_SCRIPT_ICOS_IMAGES=ENV_DEPS__GUESTOS_DISK_IMG:ic-os/guestos/envs/dev/disk-img.tar.zst;ENV_DEPS__GUESTOS_UPDATE_IMG:ic-os/guestos/envs/dev/update-img.tar.zst
    icos_images = ctx.attr.icos_images
    env |= {
        "RUN_SCRIPT_ICOS_IMAGES": ";".join([k + ":" + v.files.to_list()[0].short_path for k, v in icos_images.items()]),
    }
    env_deps = dict(env_deps, **icos_images)

    env["RUN_SCRIPT_UPLOAD_SYSTEST_DEP"] = ctx.executable._upload_systest_dep.short_path

    # RUN_SCRIPT_INFO_FILE_VARS:
    # Have the run script resolve some vars from info_file.
    # The run script expects a map of enviromment variables to their info_file counterparts plus a suffix. e.g.
    # RUN_SCRIPT_INFO_FILE_VARS=ENV_DEPS__GUESTOS_DISK_IMG_VERSION:STABLE_VERSION;ENV_DEPS__OTHER:STABLE_OTHER:suffix
    info_file_vars = ctx.attr.info_file_vars
    env |= {
        "RUN_SCRIPT_INFO_FILE_VARS": ";".join([k + ":" + ":".join(v) for k, v in info_file_vars.items()]),
    }

    if ctx.executable.colocated_test_bin != None:
        env["COLOCATED_TEST_BIN"] = ctx.executable.colocated_test_bin.short_path

    runtime_deps = []

    if k8s:
        env["KUBECONFIG"] = ctx.file._k8sconfig.path
        runtime_deps.append([ctx.file._k8sconfig])

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
                    ctx.info_file,
                    ctx.executable.src,
                    ctx.executable._upload_systest_dep,
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
        "_k8sconfig": attr.label(allow_single_file = True, default = None),
        "_upload_systest_dep": attr.label(executable = True, cfg = "exec", default = "//bazel:upload_systest_dep"),
        "runtime_deps": attr.label_list(allow_files = True),
        "env_deps": attr.string_keyed_label_dict(allow_files = True),
        "icos_images": attr.string_keyed_label_dict(doc = "Specifies images to be used by the test. Values will be replaced with actual download URLs and hashes.", allow_files = True),
        "info_file_vars": attr.string_list_dict(doc = "Specifies variables to be pulled from info_file. Expects a map of varname to [infovar_name, optional_suffix]."),
        "env_inherit": attr.string_list(doc = "Specifies additional environment variables to inherit from the external environment when the test is executed by bazel test."),
        "exclude_logs": attr.string_list(doc = "Specifies uvm name patterns to exclude from streaming."),
    },
)

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
        uses_guestos_img = True,
        uses_guestos_malicious_img = False,
        uses_guestos_mainnet_latest_img = False,
        uses_guestos_mainnet_nns_img = False,
        uses_guestos_mainnet_app_img = False,
        uses_guestos_recovery_dev_img = False,
        uses_guestos_update = False,
        uses_guestos_test_update = False,
        uses_guestos_malicious_update = False,
        uses_guestos_mainnet_latest_update = False,
        uses_guestos_mainnet_nns_update = False,
        uses_guestos_mainnet_app_update = False,
        uses_setupos_img = False,
        uses_setupos_mainnet_latest_img = False,
        uses_hostos_update = False,
        uses_hostos_test_update = False,
        uses_hostos_mainnet_latest_update = False,
        uses_dev_mainnet = False,
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
      uses_guestos_img: the test uses the branch GuestOS image
      uses_guestos_malicious_img: the test uses the malicious GuestOS image
      uses_guestos_mainnet_latest_img: the test uses the latest release mainnet GuestOS image
      uses_guestos_mainnet_nns_img: the test uses the NNS subnet mainnet GuestOS image
      uses_guestos_mainnet_app_img: the test uses the app subnet mainnet GuestOS image
      uses_guestos_recovery_dev_img: the test uses branch recovery-dev GuestOS image.
      uses_guestos_update: the test uses the branch GuestOS update image
      uses_guestos_test_update: the test uses the branch GuestOS update-test image
      uses_guestos_malicious_update: the test uses the malicious GuestOS update image
      uses_guestos_mainnet_latest_update: the test uses the latest release mainnet GuestOS update image
      uses_guestos_mainnet_nns_update: the test uses the NNS subnet mainnet GuestOS update image
      uses_guestos_mainnet_app_update: the test uses the app subnet mainnet GuestOS update image
      uses_setupos_img: the test uses the branch SetupOS image
      uses_setupos_mainnet_latest_img: the test uses the latest release mainnet SetupOS image
      uses_hostos_update: the test uses the branch HostOS update image
      uses_hostos_test_update: the test uses the branch HostOS update-test image
      uses_hostos_mainnet_latest_update: the test uses the latest release mainnet HostOS update image
      uses_dev_mainnet: the test uses dev variants for latest mainnet images,
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

    # Environment variable names to targets (targets are resolved)
    # NOTE: we use "ENV_DEPS__" as prefix for env variables, which are passed to system-tests via Bazel.
    _env_deps = {}
    icos_images = dict()
    info_file_vars = dict()

    # Guardrails for specifying source and target images
    if int(uses_guestos_img) + int(uses_guestos_malicious_img) + int(uses_guestos_mainnet_latest_img) + int(uses_guestos_mainnet_nns_img) + int(uses_guestos_mainnet_app_img) + int(uses_guestos_recovery_dev_img) >= 2:
        fail("More than one initial GuestOS (disk) image was specified!")

    if int(uses_guestos_update) + int(uses_guestos_test_update) + int(uses_guestos_malicious_update) + int(uses_guestos_mainnet_latest_update) + int(uses_guestos_mainnet_nns_update) + int(uses_guestos_mainnet_app_update) >= 2:
        fail("More than one target GuestOS (upgrade) image was specified!")

    if int(uses_setupos_img) + int(uses_setupos_mainnet_latest_img) >= 2:
        fail("More than one initial SetupOS (disk) image was provided!")

    if int(uses_hostos_update) + int(uses_hostos_test_update) + int(uses_hostos_mainnet_latest_update) >= 2:
        fail("More than one target HostOS (upgrade) image was specified!")

    # ICOS image handling
    if uses_guestos_img:
        info_file_vars["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = ["STABLE_VERSION"]
        icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "//ic-os/guestos/envs/dev:disk-img.tar.zst"
        icos_images["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG"] = "//ic-os/guestos/envs/dev:update-img.tar.zst"
        _env_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"

    if uses_guestos_malicious_img:
        info_file_vars["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = ["STABLE_VERSION"]
        icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "//ic-os/guestos/envs/dev-malicious:disk-img.tar.zst"
        icos_images["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG"] = "//ic-os/guestos/envs/dev-malicious:update-img.tar.zst"
        _env_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev-malicious:launch-measurements.json"

    if uses_guestos_mainnet_latest_img:
        env["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = MAINNET_LATEST["version"]
        icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "@mainnet_latest_guest_img" if not uses_dev_mainnet else "@mainnet_latest_guest_img_dev"
        env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_LATEST["version"], "guest-os", True) if not uses_dev_mainnet else icos_dev_image_download_url(MAINNET_LATEST["version"], "guest-os", True)
        env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH"] = MAINNET_LATEST["hash"] if not uses_dev_mainnet else MAINNET_LATEST["dev_hash"]

        # TODO(NODE-1723): Currently dev measurements are not published. Use them once they are.
        _env_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_guest_img//:launch_measurements"  # if not uses_dev_mainnet else "@mainnet_latest_guest_img_dev//:launch_measurements"

    if uses_guestos_mainnet_nns_img:
        env["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = MAINNET_NNS["version"]
        icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "@mainnet_nns_guest_img" if not uses_dev_mainnet else "@mainnet_nns_guest_img_dev"
        env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_NNS["version"], "guest-os", True) if not uses_dev_mainnet else icos_dev_image_download_url(MAINNET_NNS["version"], "guest-os", True)
        env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH"] = MAINNET_NNS["hash"] if not uses_dev_mainnet else MAINNET_NNS["dev_hash"]

        # TODO(NODE-1723): Currently dev measurements are not published. Use them once they are.
        _env_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_nns_guest_img//:launch_measurements"  # if not uses_dev_mainnet else "@mainnet_nns_guest_img_dev//:launch_measurements"

    if uses_guestos_mainnet_app_img:
        env["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = MAINNET_APP["version"]
        icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "@mainnet_app_guest_img" if not uses_dev_mainnet else "@mainnet_app_guest_img_dev"
        env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_APP["version"], "guest-os", True) if not uses_dev_mainnet else icos_dev_image_download_url(MAINNET_APP["version"], "guest-os", True)
        env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH"] = MAINNET_APP["hash"] if not uses_dev_mainnet else MAINNET_APP["dev_hash"]

        # TODO(NODE-1723): Currently dev measurements are not published. Use them once they are.
        _env_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_app_guest_img//:launch_measurements"  # if not uses_dev_mainnet else "@mainnet_app_guest_img_dev//:launch_measurements"

    if uses_guestos_recovery_dev_img:
        info_file_vars["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = ["STABLE_VERSION"]
        icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "//ic-os/guestos/envs/recovery-dev:disk-img.tar.zst"
        icos_images["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG"] = "//ic-os/guestos/envs/dev:update-img.tar.zst"  # use the branch update image for initial update image
        _env_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"  # use the branch update image for initial update image

    if uses_guestos_update:
        info_file_vars["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = ["STABLE_VERSION"]
        icos_images["ENV_DEPS__GUESTOS_UPDATE_IMG"] = "//ic-os/guestos/envs/dev:update-img.tar.zst"
        _env_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"

    if uses_guestos_test_update:
        info_file_vars["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = ["STABLE_VERSION", "-test"]
        icos_images["ENV_DEPS__GUESTOS_UPDATE_IMG"] = "//ic-os/guestos/envs/dev:update-img-test.tar.zst"
        _env_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements-test.json"

    if uses_guestos_malicious_update:
        info_file_vars["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = ["STABLE_VERSION"]
        icos_images["ENV_DEPS__GUESTOS_UPDATE_IMG"] = "//ic-os/guestos/envs/dev-malicious:update-img.tar.zst"
        _env_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev-malicious:launch-measurements.json"

    if uses_guestos_mainnet_latest_update:
        env["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = MAINNET_LATEST["version"]
        env["ENV_DEPS__GUESTOS_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_LATEST["version"], "guest-os", True) if not uses_dev_mainnet else icos_dev_image_download_url(MAINNET_LATEST["version"], "guest-os", True)
        env["ENV_DEPS__GUESTOS_UPDATE_IMG_HASH"] = MAINNET_LATEST["hash"] if not uses_dev_mainnet else MAINNET_LATEST["dev_hash"]

        # TODO(NODE-1723): Currently dev measurements are not published. Use them once they are.
        _env_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_guest_img//:launch_measurements"  #  if not uses_dev_mainnet else "@mainnet_latest_guest_img_dev//:launch_measurements"

    if uses_guestos_mainnet_nns_update:
        env["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = MAINNET_NNS["version"]
        env["ENV_DEPS__GUESTOS_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_NNS["version"], "guest-os", True) if not uses_dev_mainnet else icos_dev_image_download_url(MAINNET_NNS["version"], "guest-os", True)
        env["ENV_DEPS__GUESTOS_UPDATE_IMG_HASH"] = MAINNET_NNS["hash"] if not uses_dev_mainnet else MAINNET_NNS["dev_hash"]

        # TODO(NODE-1723): Currently dev measurements are not published. Use them once they are.
        _env_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_nns_guest_img//:launch_measurements"  # if not uses_dev_mainnet else "@mainnet_nns_guest_img_dev//:launch_measurements"

    if uses_guestos_mainnet_app_update:
        env["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = MAINNET_APP["version"]
        env["ENV_DEPS__GUESTOS_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_APP["version"], "guest-os", True) if not uses_dev_mainnet else icos_dev_image_download_url(MAINNET_APP["version"], "guest-os", True)
        env["ENV_DEPS__GUESTOS_UPDATE_IMG_HASH"] = MAINNET_APP["hash"] if not uses_dev_mainnet else MAINNET_APP["dev_hash"]

        # TODO(NODE-1723): Currently dev measurements are not published. Use them once they are.
        _env_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_app_guest_img//:launch_measurements"  # if not uses_dev_mainnet else "@mainnet_app_guest_img_dev//:launch_measurements"

    if uses_setupos_img:
        icos_images["ENV_DEPS__EMPTY_DISK_IMG"] = "//rs/tests/nested:empty-disk-img.tar.zst"
        info_file_vars["ENV_DEPS__SETUPOS_DISK_IMG_VERSION"] = ["STABLE_VERSION"]
        icos_images["ENV_DEPS__SETUPOS_DISK_IMG"] = "//ic-os/setupos:test-img.tar.zst"
        _env_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"

        _env_deps["ENV_DEPS__SETUPOS_BUILD_CONFIG"] = "//ic-os:dev-tools/build-setupos-config-image.sh"

    if uses_setupos_mainnet_latest_img:
        icos_images["ENV_DEPS__EMPTY_DISK_IMG"] = "//rs/tests/nested:empty-disk-img.tar.zst"
        env["ENV_DEPS__SETUPOS_DISK_IMG_VERSION"] = MAINNET_LATEST_HOSTOS["version"]
        icos_images["ENV_DEPS__SETUPOS_DISK_IMG"] = "//ic-os/setupos:mainnet-latest-test-img.tar.zst" if not uses_dev_mainnet else "//ic-os/setupos:mainnet-latest-test-img-dev.tar.zst"

        # TODO(NODE-1723): Currently dev measurements are not published. Use them once they are.
        _env_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_setupos_disk_image_launch_measurements"  # if not uses_dev_mainnet else "@mainnet_latest_setupos_disk_image_dev_launch_measurements"

        _env_deps["ENV_DEPS__SETUPOS_BUILD_CONFIG"] = "//ic-os:dev-tools/build-setupos-config-image.sh"

    if uses_hostos_update:
        info_file_vars["ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION"] = ["STABLE_VERSION"]
        icos_images["ENV_DEPS__HOSTOS_UPDATE_IMG"] = "//ic-os/hostos/envs/dev:update-img.tar.zst"

    if uses_hostos_test_update:
        info_file_vars["ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION"] = ["STABLE_VERSION", "-test"]
        icos_images["ENV_DEPS__HOSTOS_UPDATE_IMG"] = "//ic-os/hostos/envs/dev:update-img-test.tar.zst"

    if uses_hostos_mainnet_latest_update:
        env["ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION"] = MAINNET_LATEST_HOSTOS["version"]
        env["ENV_DEPS__HOSTOS_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_LATEST_HOSTOS["version"], "host-os", True) if not uses_dev_mainnet else icos_dev_image_download_url(MAINNET_LATEST_HOSTOS["version"], "host-os", True)
        env["ENV_DEPS__HOSTOS_UPDATE_IMG_HASH"] = MAINNET_LATEST_HOSTOS["hash"] if not uses_dev_mainnet else MAINNET_LATEST_HOSTOS["dev_hash"]

    deps = list(runtime_deps)
    if logs:
        env["VECTOR_VM_PATH"] = "$(rootpath //rs/tests:vector_with_log_fetcher_image)"
        deps = ["//rs/tests:vector_with_log_fetcher_image"]

        for dep in runtime_deps:
            if dep not in UNIVERSAL_VM_RUNTIME_DEPS:
                deps.append(dep)

        deps = deps + UNIVERSAL_VM_RUNTIME_DEPS

    run_system_test(
        name = test_name,
        src = test_driver_target,
        runtime_deps = deps,
        env_deps = _env_deps,
        env = env,
        icos_images = icos_images,
        info_file_vars = info_file_vars,
        env_inherit = env_inherit,
        tags = tags + ["requires-network", "system_test"] +
               (["manual"] if "colocate" in tags else []),
        target_compatible_with = ["@platforms//os:linux"],
        timeout = test_timeout,
        flaky = flaky,
        exclude_logs = exclude_logs,
    )

    env = env | {
        "COLOCATED_TEST": test_name,
        "COLOCATED_TEST_DRIVER_VM_REQUIRED_HOST_FEATURES": json.encode(colocated_test_driver_vm_required_host_features),
        "COLOCATED_TEST_DRIVER_VM_RESOURCES": json.encode(colocated_test_driver_vm_resources),
    }

    if colocated_test_driver_vm_enable_ipv4:
        env.update({"COLOCATED_TEST_DRIVER_VM_ENABLE_IPV4": "1"})

    if colocated_test_driver_vm_forward_ssh_agent:
        env.update({"COLOCATED_TEST_DRIVER_VM_FORWARD_SSH_AGENT": "1"})

    visibility = kwargs.get("visibility", ["//visibility:public"])

    # Add missing UVM deps if logs are disabled
    for dep in UNIVERSAL_VM_RUNTIME_DEPS:
        if dep not in deps:
            deps.append(dep)

    run_system_test(
        name = test_name + "_colocate",
        src = "//rs/tests/idx:colocate_test_bin",
        colocated_test_bin = test_driver_target,
        runtime_deps = deps + [
            "//rs/tests:colocate_uvm_config_image",
            test_driver_target,
        ],
        env_deps = _env_deps,
        env_inherit = env_inherit,
        env = env,
        icos_images = icos_images,
        info_file_vars = info_file_vars,
        tags = tags + ["requires-network", "system_test"] +
               (["colocated"] if "colocate" in tags else ["manual"]) +
               additional_colocate_tags,
        target_compatible_with = ["@platforms//os:linux"],
        timeout = test_timeout,
        flaky = flaky,
        visibility = visibility,
        exclude_logs = exclude_logs,
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
