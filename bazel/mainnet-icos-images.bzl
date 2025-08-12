"""
This module defines Bazel targets for the mainnet versions of ICOS images
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")
load("//rs/tests:common.bzl", "MAINNET_LATEST_HOSTOS_REVISION", "MAINNET_NNS_SUBNET_REVISION")

def base_download_url(git_commit_id, variant, update, test, dev = True):
    return "https://download.dfinity.systems/ic/{git_commit_id}/{variant}/{component}{test}/".format(
        git_commit_id = git_commit_id,
        variant = variant,
        component = ("update-img" if update else "disk-img") + ("-dev" if dev else ""),
        test = "-test" if test else "",
    )

def mainnet_icos_images():
    http_file(
        name = "mainnet_latest_setupos_disk_image",
        downloaded_file_path = "disk-img.tar.zst",
        url = base_download_url(
            git_commit_id = MAINNET_LATEST_HOSTOS_REVISION,
            variant = "setup-os",
            update = False,
            test = False,
        ) + "disk-img.tar.zst",
    )

    # NODE-1682: use dev image once published release
    http_file(
        name = "mainnet_nns_setupos_disk_image",
        downloaded_file_path = "disk-img.tar.zst",
        url = base_download_url(
            git_commit_id = MAINNET_NNS_SUBNET_REVISION,
            variant = "setup-os",
            update = False,
            test = False,
            dev = False,
        ) + "disk-img.tar.zst",
    )
