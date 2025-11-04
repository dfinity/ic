"""
This module defines Bazel targets for the mainnet versions of ICOS images
"""

load("@mainnet_icos_versions//:defs.bzl", "mainnet_icos_versions")

MAINNET_LATEST = {
    "version": mainnet_icos_versions["guestos"]["latest_release"]["version"],
    "hash": mainnet_icos_versions["guestos"]["latest_release"]["update_img_hash"],
    "dev_hash": mainnet_icos_versions["guestos"]["latest_release"]["update_img_hash_dev"],
    "launch_measurements": mainnet_icos_versions["guestos"]["latest_release"]["launch_measurements"],
    "dev_launch_measurements": mainnet_icos_versions["guestos"]["latest_release"]["launch_measurements_dev"],
}
MAINNET_NNS = {
    "version": mainnet_icos_versions["guestos"]["subnets"]["tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"]["version"],
    "hash": mainnet_icos_versions["guestos"]["subnets"]["tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"]["update_img_hash"],
    "dev_hash": mainnet_icos_versions["guestos"]["subnets"]["tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"]["update_img_hash_dev"],
    "launch_measurements": mainnet_icos_versions["guestos"]["subnets"]["tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"]["launch_measurements"],
    "dev_launch_measurements": mainnet_icos_versions["guestos"]["subnets"]["tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"]["launch_measurements_dev"],
}
MAINNET_APP = {
    "version": mainnet_icos_versions["guestos"]["subnets"]["io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"]["version"],
    "hash": mainnet_icos_versions["guestos"]["subnets"]["io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"]["update_img_hash"],
    "dev_hash": mainnet_icos_versions["guestos"]["subnets"]["io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"]["update_img_hash_dev"],
    "launch_measurements": mainnet_icos_versions["guestos"]["subnets"]["io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"]["launch_measurements"],
    "dev_launch_measurements": mainnet_icos_versions["guestos"]["subnets"]["io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"]["launch_measurements_dev"],
}
MAINNET_LATEST_HOSTOS = {
    "version": mainnet_icos_versions["hostos"]["latest_release"]["version"],
    "hash": mainnet_icos_versions["hostos"]["latest_release"]["update_img_hash"],
    "dev_hash": mainnet_icos_versions["hostos"]["latest_release"]["update_img_hash_dev"],
    "launch_measurements": mainnet_icos_versions["hostos"]["latest_release"]["launch_measurements"],
    "dev_launch_measurements": mainnet_icos_versions["hostos"]["latest_release"]["launch_measurements_dev"],
}

def icos_image_download_url(git_commit_id, variant, update):
    return "https://download.dfinity.systems/ic/{git_commit_id}/{variant}/{component}/{component}.tar.zst".format(
        git_commit_id = git_commit_id,
        variant = variant,
        component = "update-img" if update else "disk-img",
    )

def icos_dev_image_download_url(git_commit_id, variant, update):
    return "https://download.dfinity.systems/ic/{git_commit_id}/{variant}/{component}-dev/{component}.tar.zst".format(
        git_commit_id = git_commit_id,
        variant = variant,
        component = "update-img" if update else "disk-img",
    )

def _mainnet_icos_images_impl(repository_ctx):
    """Repository rule for ic-os images.

    The setup-os image is downloaded as disk-img.tar.zst. Additionally, launch-measurements
    are written (as launch-measurements-guest.json) and a target `:guest-img` is generated.
    """

    parts = list(repository_ctx.attr.parts)

    # The path to the mainnet icos info
    json_path = repository_ctx.attr.path
    repository_ctx.watch(json_path)  # recreate the repo if the data changes

    # Read and decode mainnet data
    info = json.decode(repository_ctx.read(json_path))
    for part in parts:
        info = info[part]

    git_commit_id = info["version"]

    if repository_ctx.attr.dev:
        url = icos_dev_image_download_url(git_commit_id, "setup-os", False)
    else:
        url = icos_image_download_url(git_commit_id, "setup-os", False)

    repository_ctx.download(url, "disk-img.tar.zst")  # download the disk image

    if repository_ctx.attr.dev:
        json_measurements = json.encode(info["launch_measurements_dev"])
    else:
        json_measurements = json.encode(info["launch_measurements"])

    # write the measurements
    repository_ctx.file("launch-measurements-guest.json", content = json_measurements)

    BUILD = """\
package(default_visibility = ["//visibility:public"])
exports_files(["disk-img.tar.zst", "launch-measurements-guest.json"])

genrule(
    name = "guest-img",
    srcs = ["disk-img.tar.zst"],
    outs = ["guest-img.tar.zst"],
    tags = [ "manual" ],
    cmd = \"""#!/bin/bash
        $(location @@//rs/ic_os/build_tools/partition_tools:extract-guestos) --image $< $@
    \""",
    target_compatible_with = ["@platforms//os:linux"],
    tools = ["@@//rs/ic_os/build_tools/partition_tools:extract-guestos"],
)
    """
    repository_ctx.file("BUILD.bazel", content = BUILD)

mainnet_icos_images = repository_rule(
    implementation = _mainnet_icos_images_impl,
    attrs = {
        "parts": attr.string_list(mandatory = True, doc = "Will be used to index into the mainnet icos revisions JSON file."),
        "path": attr.label(mandatory = True, doc = "The path to the mainnet icos revisions."),
        "dev": attr.bool(mandatory = False, default = False, doc = "When 'True', dev images are pulled."),
    },
)
