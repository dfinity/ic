"""
This module defines Bazel targets for the mainnet versions of ICOS images
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")
load("@mainnet_versions//:defs.bzl", "mainnet_versions")

MAINNET_REVISION = mainnet_versions["deployments"]["hostos"]

def base_download_url(git_commit_id, variant, update, test):
    return "https://download.dfinity.systems/ic/{git_commit_id}/{variant}/{component}{test}/".format(
        git_commit_id = git_commit_id,
        variant = variant,
        component = "update-img" if update else "disk-img",
        test = "-test" if test else "",
    )

def mainnet_images():
    """
    Provides Bazel targets for mainnet ICOS images.
    """

    http_file(
        name = "mainnet_setupos_disk_image",
        downloaded_file_path = "disk-img.tar.zst",
        url = base_download_url(MAINNET_REVISION, "setup-os", False, False) + "disk-img.tar.zst",
    )

    http_file(
        name = "mainnet_hostos_shas",
        downloaded_file_path = "SHA256SUMS",
        url = base_download_url(MAINNET_REVISION, "host-os", True, False) + "SHA256SUMS",
    )

def mainnet_images_support():
    """
    Provides Bazel targets for mainnet ICOS images, that need to be created at Bazel's runtime.
    """

    native.genrule(
        name = "mainnet_hostos_version_file",
        outs = ["version.txt"],
        cmd = "echo \"{revision}\" > $@".format(revision=MAINNET_REVISION),
        tags = ["manual"],
    )

    hostos_url = base_download_url(MAINNET_REVISION, "host-os", True, False) + "update-img.tar.zst"
    native.genrule(
        name = "mainnet_hostos_url_file",
        outs = ["mainnet_hostos.url"],
        cmd = "echo \"{hostos_url}\" > $@".format(hostos_url=hostos_url),
    )

    native.genrule(
        name = "mainnet_hostos_sha_file",
        srcs = ["@mainnet_hostos_shas//file"],
        outs = ["mainnet_hostos.sha256"],
        cmd = "sed -n '2p' $(location @mainnet_hostos_shas//file) | cut -d ' ' -f 1 > $@",
        tags = ["manual"],
    )
