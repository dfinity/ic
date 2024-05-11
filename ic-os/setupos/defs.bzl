"""
Hold manifest common to all SetupOS variants.
"""

load("@bazel_skylib//rules:copy_file.bzl", "copy_file")
load("@rules_pkg//:pkg.bzl", "pkg_tar")
load("//ic-os/rootfs:setupos.bzl", "rootfs_files")
load("//toolchains/sysimage:toolchain.bzl", "ext4_image", "fat32_image")

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
      A dict containing inputs to build this image.
    """

    deps = {
        "base_dockerfile": "//ic-os/setupos/context:Dockerfile.base",

        # Extra files to be added to rootfs and bootfs
        "bootfs": {},
        "rootfs": {
            "//publish/binaries:setupos_tool": "/opt/ic/bin/setupos_tool:0755",
        },

        # Set various configuration values
        "container_context_files": Label("//ic-os/setupos/context:context-files"),
        "rootfs_files": rootfs_files,
        "partition_table": Label("//ic-os/setupos:partitions.csv"),
        "rootfs_size": "1750M",
        "bootfs_size": "100M",
        "grub_config": Label("//ic-os/setupos:grub.cfg"),
        "extra_boot_args": Label("//ic-os/setupos/context:extra_boot_args"),

        # Add any custom partitions to the manifest
        "custom_partitions": lambda: (_custom_partitions)(mode),
    }

    # Add extra files depending on image variant
    extra_deps = {
        "dev": {
            "build_container_filesystem_config_file": "//ic-os/setupos/envs/dev:build_container_filesystem_config.txt",
        },
        "local-base-dev": {
            "build_container_filesystem_config_file": "//ic-os/setupos/envs/dev:build_container_filesystem_config.txt",
        },
        "local-base-prod": {
            "build_container_filesystem_config_file": "//ic-os/setupos/envs/prod:build_container_filesystem_config.txt",
        },
        "prod": {
            "build_container_filesystem_config_file": "//ic-os/setupos/envs/prod:build_container_filesystem_config.txt",
        },
    }

    deps.update(extra_deps[mode])

    return deps

# Inject a step building a data partition that contains either dev or prod
# child images, depending on this build variant.
def _custom_partitions(mode):
    if mode == "dev":
        guest_image = Label("//ic-os/guestos/envs/dev:disk-img.tar.zst")
        host_image = Label("//ic-os/hostos/envs/dev:disk-img.tar.zst")
        nns_url = "https://dfinity.org"
    elif mode == "local-base-dev":
        guest_image = Label("//ic-os/guestos/envs/local-base-dev:disk-img.tar.zst")
        host_image = Label("//ic-os/hostos/envs/local-base-dev:disk-img.tar.zst")
        nns_url = "https://dfinity.org"
    elif mode == "local-base-prod":
        guest_image = Label("//ic-os/guestos/envs/local-base-prod:disk-img.tar.zst")
        host_image = Label("//ic-os/hostos/envs/local-base-prod:disk-img.tar.zst")
        nns_url = "https://icp-api.io,https://icp0.io,https://ic0.app"
    elif mode == "prod":
        guest_image = Label("//ic-os/guestos/envs/prod:disk-img.tar.zst")
        host_image = Label("//ic-os/hostos/envs/prod:disk-img.tar.zst")
        nns_url = "https://icp-api.io,https://icp0.io,https://ic0.app"
    else:
        fail("Unkown mode detected: " + mode)

    copy_file(
        name = "copy_guestos_img",
        src = guest_image,
        out = "guest-os.img.tar.zst",
        allow_symlink = True,
        tags = ["manual"],
    )

    copy_file(
        name = "copy_hostos_img",
        src = host_image,
        out = "host-os.img.tar.zst",
        allow_symlink = True,
        tags = ["manual"],
    )

    config_dict = {
        Label("//ic-os/setupos:config/config.ini"): "config.ini",
        Label("//ic-os/setupos:config/ssh_authorized_keys/admin"): "ssh_authorized_keys/admin",
    }

    if mode == "dev":
        config_dict[Label("//ic-os/setupos:config/node_operator_private_key.pem")] = "node_operator_private_key.pem"

    pkg_tar(
        name = "config_tar",
        files = config_dict,
        mode = "0644",
        package_dir = "config",
        tags = ["manual"],
    )

    fat32_image(
        name = "partition-config.tzst",
        src = "config_tar",
        label = "CONFIG",
        partition_size = "50M",
        subdir = "config",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual"],
    )

    native.genrule(
        name = "deployment_json",
        srcs = [Label("//ic-os/setupos:data/deployment.json.template")],
        outs = ["deployment.json"],
        cmd = "sed -e 's#NNS_URL#{nns_url}#' < $< > $@".format(nns_url = nns_url),
        tags = ["manual"],
    )

    pkg_tar(
        name = "data_tar",
        srcs = [
            Label("//ic-os/setupos:data/nns_public_key.pem"),
            ":deployment.json",
            ":guest-os.img.tar.zst",
            ":host-os.img.tar.zst",
        ],
        mode = "0644",
        package_dir = "data",
        tags = ["manual"],
    )

    ext4_image(
        name = "partition-data.tzst",
        src = "data_tar",
        partition_size = "1750M",
        subdir = "data",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual"],
    )

    return [
        ":partition-config.tzst",
        ":partition-data.tzst",
    ]
