load("@mainnet_icos_versions//:defs.bzl", "MAINNET_APP", "MAINNET_LATEST", "MAINNET_LATEST_HOSTOS", "MAINNET_NNS")
load("//bazel:mainnet-icos-images.bzl", "icos_dev_image_download_url", "icos_image_download_url")

def configure_icos(guestos = True, guestos_update = False, setupos = False, hostos_update = False):
    env = {}
    env_var_files = {}
    icos_images = {}
    runtime_deps = {}

    # IC-OS image configuration
    if guestos:
        # Configure a GuestOS disk image (the GuestOS that the test starts with) built from the local workspace.

        if guestos == True:
            env_var_files["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = "//bazel:version.txt"
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "//ic-os/guestos/envs/dev:disk-img.tar.zst"
            icos_images["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG"] = "//ic-os/guestos/envs/dev:update-img.tar.zst"
            runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"

        elif guestos == "malicious":
            env_var_files["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = "//bazel:version.txt"
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "//ic-os/guestos/envs/dev-malicious:disk-img.tar.zst"
            icos_images["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG"] = "//ic-os/guestos/envs/dev-malicious:update-img.tar.zst"
            runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev-malicious:launch-measurements.json"

        elif guestos == "recovery_dev":
            env_var_files["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = "//bazel:version.txt"
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "//ic-os/guestos/envs/recovery-dev:disk-img.tar.zst"
            icos_images["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG"] = "//ic-os/guestos/envs/dev:update-img.tar.zst"  # use the branch update image for initial update image
            runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"  # use the branch update image for initial update image

            # Configure a GuestOS base image (the GuestOS that the test starts with) from the version available on mainnet.
        elif guestos == "mainnet_latest":
            env["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = MAINNET_LATEST["version"]
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "@mainnet_latest_guestos_images//:guest-img"
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_LATEST["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH"] = MAINNET_LATEST["hash"]
            runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_guestos_images//:launch-measurements-guest.json"
        elif guestos == "mainnet_latest_dev":
            env["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = MAINNET_LATEST["version"]
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "@mainnet_latest_guestos_images_dev//:guest-img"
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL"] = icos_dev_image_download_url(MAINNET_LATEST["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH"] = MAINNET_LATEST["dev_hash"]
            runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_guestos_images_dev//:launch-measurements-guest.json"
        elif guestos == "mainnet_nns":
            env["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = MAINNET_NNS["version"]
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "@mainnet_nns_images//:guest-img"
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_NNS["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH"] = MAINNET_NNS["hash"]
            runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_nns_images//:launch-measurements-guest.json"
        elif guestos == "mainnet_app":
            env["ENV_DEPS__GUESTOS_DISK_IMG_VERSION"] = MAINNET_APP["version"]
            icos_images["ENV_DEPS__GUESTOS_DISK_IMG"] = "@mainnet_app_images//:guest-img"
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_APP["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH"] = MAINNET_APP["hash"]
            runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_app_images//:launch-measurements-guest.json"

        else:
            fail("unknown guestos version: " + str(guestos))

    if guestos_update:
        # Configure a GuestOS update image (the GuestOS that the test updates to) built from the local workspace.
        if guestos_update == True:  # HEAD version
            env_var_files["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = "//bazel:version.txt"
            icos_images["ENV_DEPS__GUESTOS_UPDATE_IMG"] = "//ic-os/guestos/envs/dev:update-img.tar.zst"
            runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"
        elif guestos_update == "test":
            env_var_files["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = "//rs/tests:version-test"
            icos_images["ENV_DEPS__GUESTOS_UPDATE_IMG"] = "//ic-os/guestos/envs/dev:update-img-test.tar.zst"
            runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements-test.json"
        elif guestos_update == "malicious":
            env_var_files["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = "//bazel:version.txt"
            icos_images["ENV_DEPS__GUESTOS_UPDATE_IMG"] = "//ic-os/guestos/envs/dev-malicious:update-img.tar.zst"
            runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev-malicious:launch-measurements.json"

            # Configure a GuestOS update image (the GuestOS that the test updates to) from the version available on mainnet.
        elif guestos_update == "mainnet_latest":
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = MAINNET_LATEST["version"]
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_LATEST["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_HASH"] = MAINNET_LATEST["hash"]
            runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_guestos_images//:launch-measurements-guest.json"

        elif guestos_update == "mainnet_nns":
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = MAINNET_NNS["version"]
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_NNS["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_HASH"] = MAINNET_NNS["hash"]
            runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_nns_images//:launch-measurements-guest.json"

        elif guestos_update == "mainnet_app":
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION"] = MAINNET_APP["version"]
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_APP["version"], "guest-os", True)
            env["ENV_DEPS__GUESTOS_UPDATE_IMG_HASH"] = MAINNET_APP["hash"]
            runtime_deps["ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_app_images//:launch-measurements-guest.json"

        else:
            fail("unknown guestos update version: " + str(guestos_update))

    if setupos:
        icos_images["ENV_DEPS__EMPTY_DISK_IMG"] = "//rs/tests/nested:empty-disk-img.tar.zst"
        runtime_deps["ENV_DEPS__SETUPOS_BUILD_CONFIG"] = "//ic-os:dev-tools/build-setupos-config-image.sh"

        if setupos == True:
            env_var_files["ENV_DEPS__SETUPOS_DISK_IMG_VERSION"] = "//bazel:version.txt"
            icos_images["ENV_DEPS__SETUPOS_DISK_IMG"] = "//ic-os/setupos:test-img.tar.zst"
            runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "//ic-os/guestos/envs/dev:launch-measurements.json"
        elif setupos == "mainnet_latest":
            env["ENV_DEPS__SETUPOS_DISK_IMG_VERSION"] = MAINNET_LATEST_HOSTOS["version"]
            icos_images["ENV_DEPS__SETUPOS_DISK_IMG"] = "//ic-os/setupos:mainnet-latest-test-img.tar.zst"
            runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_hostos_images//:launch-measurements-guest.json"
        elif setupos == "mainnet_latest_dev":
            env["ENV_DEPS__SETUPOS_DISK_IMG_VERSION"] = MAINNET_LATEST_HOSTOS["version"]
            icos_images["ENV_DEPS__SETUPOS_DISK_IMG"] = "//ic-os/setupos:mainnet-latest-test-img-dev.tar.zst"
            runtime_deps["ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE"] = "@mainnet_latest_hostos_images_dev//:launch-measurements-guest.json"
        else:
            fail("unknown setupos: " + str(setupos))

    if hostos_update:
        if hostos_update == True:
            env_var_files["ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION"] = "//bazel:version.txt"
            icos_images["ENV_DEPS__HOSTOS_UPDATE_IMG"] = "//ic-os/hostos/envs/dev:update-img.tar.zst"
        elif hostos_update == "test":
            env_var_files["ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION"] = "//rs/tests:version-test"
            icos_images["ENV_DEPS__HOSTOS_UPDATE_IMG"] = "//ic-os/hostos/envs/dev:update-img-test.tar.zst"
        elif hostos_update == "mainnet_latest":
            env["ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION"] = MAINNET_LATEST_HOSTOS["version"]
            env["ENV_DEPS__HOSTOS_UPDATE_IMG_URL"] = icos_image_download_url(MAINNET_LATEST_HOSTOS["version"], "host-os", True)
            env["ENV_DEPS__HOSTOS_UPDATE_IMG_HASH"] = MAINNET_LATEST_HOSTOS["hash"]
        elif hostos_update == "mainnet_latest_dev":
            env["ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION"] = MAINNET_LATEST_HOSTOS["version"]
            env["ENV_DEPS__HOSTOS_UPDATE_IMG_URL"] = icos_dev_image_download_url(MAINNET_LATEST_HOSTOS["version"], "host-os", True)
            env["ENV_DEPS__HOSTOS_UPDATE_IMG_HASH"] = MAINNET_LATEST_HOSTOS["dev_hash"]
        else:
            fail("unknown hostos_update: " + str(hostos_update))

    return struct(env = env, env_var_files = env_var_files, runtime_deps = runtime_deps, icos_images = icos_images)
