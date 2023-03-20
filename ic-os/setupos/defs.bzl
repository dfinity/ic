"""
Hold manifest common to all SetupOS variants.
"""

load("@bazel_skylib//rules:copy_file.bzl", "copy_file")
load("//toolchains/sysimage:toolchain.bzl", "ext4_image")
load("@bazel_tools//tools/build_defs/pkg:pkg.bzl", "pkg_tar")

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
    deps["grub_config"] = Label("//ic-os/setupos:grub.cfg")

    # Add any custom partitions to the manifest
    deps["custom_partitions"] = lambda: (_custom_partitions)(mode)

    deps["extra_boot_args"] = Label("//ic-os/setupos:rootfs/extra_boot_args")

    return deps

def _custom_partitions(mode):
    if mode == "dev":
        guest_image = Label("//ic-os/guestos/dev:disk-img.tar.gz")
        host_image = Label("//ic-os/hostos/envs/dev:disk-img.tar.gz")
    else:
        guest_image = Label("//ic-os/guestos/prod:disk-img.tar.gz")
        host_image = Label("//ic-os/hostos/envs/prod:disk-img.tar.gz")

    copy_file(
        name = "copy_guestos_img",
        src = guest_image,
        out = "guest-os.img.tar.gz",
        allow_symlink = True,
    )

    copy_file(
        name = "copy_hostos_img",
        src = host_image,
        out = "host-os.img.tar.gz",
        allow_symlink = True,
    )

    pkg_tar(
        name = "data_tar",
        srcs = [
            Label("//ic-os/setupos:data/nns_public_key.pem"),
            Label("//ic-os/setupos:deployment.json"),
            ":guest-os.img.tar.gz",
            ":host-os.img.tar.gz",
        ],
        mode = "0644",
        package_dir = "data",
    )

    ext4_image(
        name = "partition-data.tar",
        src = "data_tar",
        partition_size = "1750M",
        subdir = "./data",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    return [
        Label("//ic-os/setupos:partition-config.tar"),
        ":partition-data.tar",
    ]
