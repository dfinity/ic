"""
Hold manifest common to all SetupOS variants.
"""

# Declare the dependencies that we will have for the built filesystem images.
# This needs to be done separately from the build rules because we want to
# compute the hash over all inputs going into the image and derive the
# "version.txt" file from it.

def image_deps(mode, _malicious = False):
    """
    Define all SetupOS inputs.

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

    deps["base_image"] = "//ic-os/setupos:rootfs/docker-base." + mode
    deps["docker_context"] = Label("//ic-os/setupos:rootfs-files")
    deps["partition_table"] = Label("//ic-os/setupos:partitions.csv")
    deps["rootfs_size"] = "1750M"
    deps["bootfs_size"] = "100M"

    # Add any custom partitions to the manifest
    deps["custom_partitions"] = [
        Label("//ic-os/setupos:partition-config.tar"),
        Label("//ic-os/setupos:partition-data.tar"),
        Label("//ic-os/setupos/bootloader:partition-esp.tar"),
        Label("//ic-os/setupos/bootloader:partition-grub.tar"),
    ]

    deps["extra_boot_args"] = Label("//ic-os/setupos/bootloader:extra_boot_args")

    return deps
