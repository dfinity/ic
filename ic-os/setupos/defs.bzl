"""
Hold manifest common to all SetupOS variants.
"""

load("@bazel_skylib//rules:copy_file.bzl", "copy_file")
load("@rules_pkg//:pkg.bzl", "pkg_tar")
load("//ic-os/components:setupos.bzl", "component_files")
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
        "dockerfile": "//ic-os/setupos/context:Dockerfile",

        # Extra files to be added to rootfs and bootfs
        "bootfs": {},
        "rootfs": {
            "//rs/ic_os/release:setupos_tool": "/opt/ic/bin/setupos_tool:0755",
            "//rs/ic_os/release:config": "/opt/ic/bin/config:0755",
        },

        # Set various configuration values
        "container_context_files": Label("//ic-os/setupos/context:context-files"),
        "component_files": component_files,
        "partition_table": Label("//ic-os/setupos:partitions.csv"),
        "rootfs_size": "1750M",
        "bootfs_size": "100M",
        "grub_config": Label("//ic-os/bootloader:setupos_grub.cfg"),
        "boot_args_template": Label("//ic-os/bootloader:setupos_boot_args.template"),
        "requires_root_signing": False,

        # Add any custom partitions to the manifest
        "custom_partitions": _custom_partitions,
    }

    dev_build_args = ["BUILD_TYPE=dev"]
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

    return deps

# Inject a step building a data partition that contains either dev or prod
# child images, depending on this build variant.
def _custom_partitions(mode):
    if mode == "dev":
        guest_image = Label("//ic-os/guestos/envs/dev:disk-img.tar.zst")
        host_image = Label("//ic-os/hostos/envs/dev:disk-img.tar.zst")
        nns_urls = '["https://cloudflare.com/cdn-cgi/trace"]'
        include_nns_public_key_override = True
        deployment_environment = "testnet"
    elif mode == "local-base-dev":
        guest_image = Label("//ic-os/guestos/envs/local-base-dev:disk-img.tar.zst")
        host_image = Label("//ic-os/hostos/envs/local-base-dev:disk-img.tar.zst")
        nns_urls = '["https://cloudflare.com/cdn-cgi/trace"]'
        include_nns_public_key_override = True
        deployment_environment = "testnet"
    elif mode == "local-base-prod":
        guest_image = Label("//ic-os/guestos/envs/local-base-prod:disk-img.tar.zst")
        host_image = Label("//ic-os/hostos/envs/local-base-prod:disk-img.tar.zst")
        nns_urls = '["https://icp-api.io", "https://icp0.io", "https://ic0.app"]'
        include_nns_public_key_override = False
        deployment_environment = "mainnet"
    elif mode == "prod":
        guest_image = Label("//ic-os/guestos/envs/prod:disk-img.tar.zst")
        host_image = Label("//ic-os/hostos/envs/prod:disk-img.tar.zst")
        nns_urls = '["https://icp-api.io", "https://icp0.io", "https://ic0.app"]'
        include_nns_public_key_override = False
        deployment_environment = "mainnet"
    else:
        fail("Unkown mode detected: " + mode)

    copy_file(
        name = "copy_guestos_img",
        src = guest_image,
        out = "guest-os.img.tar.zst",
        allow_symlink = True,
        tags = ["manual", "no-cache"],
    )

    copy_file(
        name = "copy_hostos_img",
        src = host_image,
        out = "host-os.img.tar.zst",
        allow_symlink = True,
        tags = ["manual", "no-cache"],
    )

    config_dict = {
        Label("//ic-os/setupos:config/config.ini"): "config.ini",
        Label("//ic-os/setupos:config/ssh_authorized_keys/admin"): "ssh_authorized_keys/admin",
    }

    if "dev" in mode:
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
        cmd = "sed -e 's#NNS_URLS#{nns_urls}#' -e 's#DEPLOYMENT_ENVIRONMENT#{deployment_environment}#' < $< > $@".format(deployment_environment = deployment_environment, nns_urls = nns_urls),
        tags = ["manual"],
    )

    data_srcs = [
        ":deployment.json",
        ":guest-os.img.tar.zst",
        ":host-os.img.tar.zst",
    ]

    if include_nns_public_key_override:
        data_srcs.append(Label("//ic-os/setupos:data/nns_public_key_override.pem"))

    pkg_tar(
        name = "data_tar",
        srcs = data_srcs,
        mode = "0644",
        package_dir = "data",
        tags = ["manual", "no-cache"],
    )

    ext4_image(
        name = "partition-data.tzst",
        src = "data_tar",
        partition_size = "2250M",
        subdir = "data",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual", "no-cache"],
    )

    return [
        ":partition-config.tzst",
        ":partition-data.tzst",
    ]

def create_test_img(name, source, compat = False, **kwargs):
    native.genrule(
        name = name,
        srcs = [source],
        outs = [name + ".tar.zst"],
        cmd = """
            tmpdir="$$(mktemp -d)"
            trap "rm -rf $$tmpdir" EXIT
            tar -xf $< -C $$tmpdir
            export PATH="/usr/sbin:$$PATH"
            $(location //rs/ic_os/dev_test_tools/setupos-disable-checks) --image-path $$tmpdir/disk.img{compat_flag}
            tar --zstd -Scf $@ -C $$tmpdir disk.img
        """.format(compat_flag = " --compat" if compat else ""),
        target_compatible_with = ["@platforms//os:linux"],
        tools = ["//rs/ic_os/dev_test_tools/setupos-disable-checks"],
        **kwargs
    )
