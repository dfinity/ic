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
      A dict containing all file inputs to build this image.
    """

    deps = {
        "bootfs": {
            # base layer
            ":rootfs-tree.tar": "/",
        },
        "rootfs": {
            # base layer
            ":rootfs-tree.tar": "/",
        },
    }

    deps["base_image"] = "//ic-os/hostos:rootfs/docker-base." + mode
    deps["docker_context"] = Label("//ic-os/hostos:rootfs-files")
    deps["partition_table"] = Label("//ic-os/hostos:partitions.csv")
    deps["volume_table"] = Label("//ic-os/hostos:volumes.csv")
    deps["rootfs_size"] = "3G"
    deps["bootfs_size"] = "100M"
    deps["grub_config"] = Label("//ic-os/hostos:grub.cfg")

    # Add any custom partitions to the manifest
    deps["custom_partitions"] = _custom_partitions

    deps["extra_boot_args"] = Label("//ic-os/hostos:rootfs/extra_boot_args")

    return deps

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
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    return [":partition-hostlvm.tar"]
