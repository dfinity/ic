"""
This module defines Bazel targets for the mainnet versions of ICOS images
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")
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

def mainnet_images():
    """Set up repositories for ic-os images deployed to mainnet."""

    http_file(
        name = "mainnet_latest_disk_img",
        url = icos_image_download_url(MAINNET_LATEST["version"], "setup-os", False),
    )

    http_file(
        name = "mainnet_latest_disk_img_dev",
        url = icos_dev_image_download_url(MAINNET_LATEST["version"], "setup-os", False),
    )

    http_file(
        name = "mainnet_nns_disk_img",
        url = icos_image_download_url(MAINNET_NNS["version"], "setup-os", False),
    )

    http_file(
        name = "mainnet_nns_disk_img_dev",
        url = icos_dev_image_download_url(MAINNET_NNS["version"], "setup-os", False),
    )

    http_file(
        name = "mainnet_app_disk_img",
        url = icos_image_download_url(MAINNET_APP["version"], "setup-os", False),
    )

    http_file(
        name = "mainnet_app_disk_img_dev",
        url = icos_dev_image_download_url(MAINNET_APP["version"], "setup-os", False),
    )
