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

def get_mainnet_setupos_images(versions):
    """
    Pull the requested SetupOS mainnet images, and their measurements.

    Args:
      versions: A dict of target names to image info used to expose images.
    """

    for (name, info) in versions.items():
        http_file(
            name = name,
            downloaded_file_path = "disk-img.tar.zst",
            url = icos_image_download_url(info["version"], "setup-os", False),
        )

        # TODO: This could live in the same repo as above
        _mainnet_measurements(
            name = name + "_launch_measurements",
            measurements = json.encode(info["launch_measurements"]),
        )

        http_file(
            name = name + "_dev",
            downloaded_file_path = "disk-img.tar.zst",
            url = icos_dev_image_download_url(info["version"], "setup-os", False),
        )

        # TODO: This could live in the same repo as above
        _mainnet_measurements(
            name = name + "_dev_launch_measurements",
            measurements = json.encode(info["dev_launch_measurements"]),
        )

def get_mainnet_guestos_images(versions, extract_guestos):
    for (name, info) in versions.items():
        _get_mainnet_guestos_image(
            name = name,
            setupos_url = icos_image_download_url(info["version"], "setup-os", False),
            extract_guestos = extract_guestos,
            measurements = json.encode(info["launch_measurements"]),
        )

        _get_mainnet_guestos_image(
            name = name + "_dev",
            setupos_url = icos_dev_image_download_url(info["version"], "setup-os", False),
            extract_guestos = extract_guestos,
            measurements = json.encode(info["dev_launch_measurements"]),
        )

_DEFS_CONTENTS = '''\
def extract_image(name, extract_guestos, **kwargs):
    native.genrule(
        name = name,
        srcs = ["disk-img.tar.zst"],
        outs = [name + ".tar.zst"],
        cmd = """#!/bin/bash
            $(location {extract_guestos}) --image $< $@
        """.format(extract_guestos = extract_guestos),
        target_compatible_with = ["@platforms//os:linux"],
        tools = [extract_guestos],
        **kwargs
    )
'''

_BUILD_CONTENTS = """\
load(":defs.bzl", "extract_image")
load("@bazel_skylib//rules:write_file.bzl", "write_file")

package(default_visibility = ["//visibility:public"])

extract_image("{name}", "{extract_guestos}")

write_file(
    name = "launch_measurements",
    out = "launch-measurements.json",
    content = ['''{measurements}'''],
)
"""

_attrs = {
    "extract_guestos": attr.label(mandatory = True, doc = "Tool used to extract a GuestOS image from a SetupOS image."),
    "setupos_url": attr.string(mandatory = True, doc = "URL to the SetupOS image to extract from"),
    "setupos_integrity": attr.string(doc = "Optional integrity for the image. If unset, it will be set after the image is downloaded."),
    "measurements": attr.string(mandatory = True, doc = "Launch measurements for the GuestOS version extracted."),
}

def _copy_attrs(repository_ctx, attrs):
    orig = repository_ctx.attr
    keys = attrs.keys()

    result = {}
    for key in keys:
        if hasattr(orig, key):
            result[key] = getattr(orig, key)
    result["name"] = orig.name

    return result

def _get_mainnet_guestos_image_impl(repository_ctx):
    download_info = repository_ctx.download(
        repository_ctx.attr.setupos_url,
        "disk-img.tar.zst",
        integrity = repository_ctx.attr.setupos_integrity,
    )

    repository_ctx.file("defs.bzl", content = _DEFS_CONTENTS)
    repository_ctx.file("BUILD.bazel", content = _BUILD_CONTENTS.format(name = repository_ctx.name, measurements = repository_ctx.attr.measurements, extract_guestos = repository_ctx.attr.extract_guestos))

    new_attrs = _copy_attrs(repository_ctx, _attrs)
    new_attrs.update({"setupos_integrity": download_info.integrity})

    return new_attrs

_get_mainnet_guestos_image = repository_rule(
    implementation = _get_mainnet_guestos_image_impl,
    attrs = _attrs,
)

def _mainnet_measurements_impl(repository_ctx):
    repository_ctx.file("BUILD.bazel", content = """\
load("@bazel_skylib//rules:write_file.bzl", "write_file")

package(default_visibility = ["//visibility:public"])

write_file(
    name = "{name}",
    out = "launch-measurements.json",
    content = ['''{measurements}'''],
)
""".format(name = repository_ctx.name, measurements = repository_ctx.attr.measurements))

_mainnet_measurements = repository_rule(
    implementation = _mainnet_measurements_impl,
    attrs = {
        "measurements": attr.string(mandatory = True, doc = "Launch measurements to expose as file."),
    },
)
