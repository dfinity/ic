"""
Hold manifest common to all HostOS variants.
"""

load("//ic-os/components:hostos.bzl", "component_files")
load("//toolchains/sysimage:toolchain.bzl", "lvm_image")

# Declare the dependencies that we will have for the built filesystem images.
# This needs to be done separately from the build rules because we want to
# compute the hash over all inputs going into the image and derive the
# "version.txt" file from it.

def image_deps(mode, _malicious = False):
    """
    Define all HostOS inputs.

    Args:
      mode: Variant to be built, dev or prod.
      _malicious: Unused, but currently needed to fit generic build structure.
    Returns:
      A dict containing inputs to build this image.
    """

    deps = {
        "base_dockerfile": "//ic-os/hostos/context:Dockerfile.base",
        "dockerfile": "//ic-os/hostos/context:Dockerfile",

        # Extra files to be added to rootfs and bootfs
        "bootfs": {},
        "rootfs": {
            # additional files to install
            "//rs/ic_os/release:vsock_host": "/opt/ic/bin/vsock_host:0755",
            "//rs/ic_os/release:hostos_tool": "/opt/ic/bin/hostos_tool:0755",
            "//rs/ic_os/release:guest_vm_runner": "/opt/ic/bin/guest_vm_runner:0755",
            "//rs/ic_os/release:metrics-proxy": "/opt/ic/bin/metrics-proxy:0755",
            "//rs/ic_os/release:config": "/opt/ic/bin/config:0755",
            "//cpp:infogetty": "/opt/ic/bin/infogetty:0755",

            # additional libraries to install
            "//rs/ic_os/release:nss_icos": "/usr/lib/x86_64-linux-gnu/libnss_icos.so.2:0644",
        },

        # Set various configuration values
        "container_context_files": Label("//ic-os/hostos/context:context-files"),
        "component_files": dict(component_files),  # Make a copy because we might update it later
        "partition_table": Label("//ic-os/hostos:partitions.csv"),
        "volume_table": Label("//ic-os/hostos:volumes.csv"),
        "rootfs_size": "3G",
        "bootfs_size": "100M",
        "grub_config": Label("//ic-os/bootloader:hostos_grub.cfg"),
        "boot_args_template": Label("//ic-os/bootloader:hostos_boot_args.template"),
        "requires_root_signing": False,

        # Add any custom partitions to the manifest
        "custom_partitions": _custom_partitions,
    }

    dev_build_args = ["BUILD_TYPE=dev", "ROOT_PASSWORD=root"]
    prod_build_args = ["BUILD_TYPE=prod"]
    dev_file_build_arg = "BASE_IMAGE=docker-base.dev"
    prod_file_build_arg = "BASE_IMAGE=docker-base.prod"

    # Determine build configuration based on mode name
    if "dev" in mode:
        deps.update({
            "build_args": dev_build_args,
            "file_build_arg": dev_file_build_arg,
        })
    else:
        deps.update({
            "build_args": prod_build_args,
            "file_build_arg": prod_file_build_arg,
        })

    # Update dev rootfs
    if "dev" in mode:
        deps["rootfs"].pop("//rs/ic_os/release:config", None)
        deps["rootfs"].update({"//rs/ic_os/release:config_dev": "/opt/ic/bin/config:0755"})

        deps["rootfs"].pop("//rs/ic_os/release:hostos_tool", None)
        deps["rootfs"].update({"//rs/ic_os/release:hostos_tool_dev": "/opt/ic/bin/hostos_tool:0755"})

        deps["rootfs"].pop("//rs/ic_os/release:guest_vm_runner", None)
        deps["rootfs"].update({"//rs/ic_os/release:guest_vm_runner_dev": "/opt/ic/bin/guest_vm_runner:0755"})

        # Allow root console access on dev
        console_override_label_1 = Label("//ic-os/hostos:console-override-dev")
        console_override_label_2 = Label("//ic-os/hostos:console-override-dev-alias")
    else:
        # Allow limited-console access on prod
        console_override_label_1 = Label("//ic-os/hostos:console-override-prod")
        console_override_label_2 = Label("//ic-os/hostos:console-override-prod-alias")

    # Note: We install the same override file to both serial-getty@ and getty@ service directories
    # because HostOS needs infogetty for both serial consoles (ttyS0, etc.) and VGA consoles (tty1, etc.)
    deps["component_files"].update({
        console_override_label_1: "/etc/systemd/system/serial-getty@.service.d/override.conf",
        console_override_label_2: "/etc/systemd/system/getty@.service.d/override.conf",
    })

    return deps

# Inject a step building an LVM partition. This depends on boot and root built
# earlier in the pipeline, and is depended on by the final disk image.
def _custom_partitions(_):
    lvm_image(
        name = "partition-hostlvm.tzst",
        layout = Label("//ic-os/hostos:volumes.csv"),
        partitions = [
            Label("//ic-os/hostos:partition-config.tzst"),
            ":partition-boot.tzst",
            ":partition-root.tzst",
        ],
        vg_name = "hostlvm",
        vg_uuid = "4c7GVZ-Df82-QEcJ-xXtV-JgRL-IjLE-hK0FgA",
        pv_uuid = "eu0VQE-HlTi-EyRc-GceP-xZtn-3j6t-iqEwyv",
        tags = ["manual", "no-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    return [":partition-hostlvm.tzst"]
