"""
This module defines Bazel targets for the mainnet versions of ICOS images
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")
load("@mainnet_icos_versions//:defs.bzl", "mainnet_icos_versions")

MAINNET_REVISION = mainnet_icos_versions["hostos"]["latest_release"]["version"]

def mainnet_images():
    http_file(
        name = "mainnet_setupos_disk_image",
        downloaded_file_path = "disk-img.tar.zst",
        url = "https://download.dfinity.systems/ic/{git_commit_id}/setup-os/disk-img/disk-img.tar.zst".format(
            git_commit_id = MAINNET_REVISION,
        ),
    )
