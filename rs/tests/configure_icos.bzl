"""
IC-OS-specific system test configuration.
"""

load("@mainnet_icos_versions//:defs.bzl", "MAINNET_APP", "MAINNET_LATEST", "MAINNET_LATEST_HOSTOS", "MAINNET_NNS")
load("//bazel:mainnet-icos-images.bzl", "icos_dev_image_download_url", "icos_image_download_url")

def configure_icos(guestos, guestos_update, setupos, hostos_update):
    """IC-OS configuration.

    Args:
      guestos: The guestos image version. Can be a single value or a dictionary mapping tags to versions.
        Single values: True (HEAD) | False | "malicious" | "recovery_dev" | "mainnet_latest" | "mainnet_latest_dev" | "mainnet_nns" | "mainnet_app". Default: True
        Dictionary: {"default": True, "my_tag": "mainnet_latest_dev"} - the "default" key works like the single value.
        Each tag generates env variables like ENV_DEPS__GUESTOS_{TAG}_DISK_IMG (uppercase tag).
      guestos_update: The guestos update image version. Values: False | True (HEAD) | "test" | "malicious" | "mainnet_latest" | "mainnet_latest_dev" | "mainnet_nns" | "mainnet_app". Default: False
      setupos: The setupos image version. Values: False | True (HEAD) | "mainnet_latest" | "mainnet_latest_dev". Default: False
      hostos_update: The hostos update image version. Values: False | True (HEAD) | "test" | "mainnet_latest" | "mainnet_latest_dev". Default: False

    Returns:
        A struct of 'env_var_files', 'env', 'runtime_deps' and 'icos_images' to inject in the test.
    """
    env = {}
    env_var_files = {}
    icos_images = {}
    runtime_deps = {}

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

    return struct(env = env, env_var_files = env_var_files, runtime_deps = runtime_deps, icos_images = icos_images)
