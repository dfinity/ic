"""
Hold manifest common to all HostOS variants.
"""

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
        "base_dockerfile": "//ic-os/hostos:rootfs/Dockerfile.base",

        # Define rootfs and bootfs
        "bootfs": {
            # base layer
            ":rootfs-tree.tar": "/",
        },
        "rootfs": {
            # base layer
            ":rootfs-tree.tar": "/",

            # additional files to install
            "//publish/binaries:vsock_host": "/opt/ic/bin/vsock_host:0755",
            "//publish/binaries:hostos_tool": "/opt/ic/bin/hostos_tool:0755",
            "//publish/binaries:metrics-proxy": "/opt/ic/bin/metrics-proxy:0755",
            "//ic-os:scripts/build-bootstrap-config-image.sh": "/opt/ic/bin/build-bootstrap-config-image.sh:0755",

            # additional libraries to install
            "//publish/binaries:nss_icos": "/usr/lib/x86_64-linux-gnu/libnss_icos.so.2:0644",
        },

        # Set various configuration values
        "container_context_files": Label("//ic-os/hostos:rootfs-files"),
        "partition_table": Label("//ic-os/hostos:partitions.csv"),
        "volume_table": Label("//ic-os/hostos:volumes.csv"),
        "rootfs_size": "3G",
        "bootfs_size": "100M",
        "grub_config": Label("//ic-os/hostos:grub.cfg"),
        "extra_boot_args": Label("//ic-os/hostos:rootfs/extra_boot_args"),

        # Add any custom partitions to the manifest
        "custom_partitions": _custom_partitions,
    }

    extra_deps = {
        "dev": {
            "build_container_filesystem_config_file": "//ic-os/hostos/envs/dev:build_container_filesystem_config.txt",
        },
        "local-base-dev": {
            # Use the non-local-base file
            "build_container_filesystem_config_file": "//ic-os/hostos/envs/dev:build_container_filesystem_config.txt",
        },
        "local-base-prod": {
            # Use the non-local-base file
            "build_container_filesystem_config_file": "//ic-os/hostos/envs/prod:build_container_filesystem_config.txt",
        },
        "prod": {
            "build_container_filesystem_config_file": "//ic-os/hostos/envs/prod:build_container_filesystem_config.txt",
        },
    }

    deps.update(extra_deps[mode])

    return deps

# Inject a step building an LVM partition. This depends on boot and root built
# earlier in the pipeline, and is depended on by the final disk image.
def _custom_partitions():
    lvm_image(
        name = "partition-hostlvm.tar",
        layout = Label("//ic-os/hostos:volumes.csv"),
        partitions = [
            Label("//ic-os/hostos:partition-config.tar"),
            ":partition-boot.tar",
            ":partition-root.tar",
        ],
        vg_name = "hostlvm",
        vg_uuid = "4c7GVZ-Df82-QEcJ-xXtV-JgRL-IjLE-hK0FgA",
        pv_uuid = "eu0VQE-HlTi-EyRc-GceP-xZtn-3j6t-iqEwyv",
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove no-remote-cache when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache", "manual"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    return [":partition-hostlvm.tar"]
