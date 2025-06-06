"""
A macro to build grub partitions for ICOS images
"""

load("//toolchains/sysimage:toolchain.bzl", "vfat_image")

def build_grub_partition(name, grub_config, visibility = None, tags = None):
    """
    Create a grub partition with the given configuration.

    Args:
      name: Name for the generated filegroup.
      grub_config: Label pointing to the grub.cfg file to include in the partition.
      visibility: See Bazel documentation
      tags: Bazel tags to be passed
    """

    vfat_image(
        name = name,
        src = Label("//ic-os/bootloader:bootloader-tree.tar"),
        extra_files = {
            grub_config: "/boot/grub/grub.cfg:0644",
            "//ic-os/bootloader:grubenv": "/boot/grub/grubenv:0644",
        },
        partition_size = "100M",
        subdir = "boot/grub",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        visibility = visibility,
        tags = tags,
    )
