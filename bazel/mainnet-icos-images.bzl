"""
This module defines Bazel targets for the mainnet versions of ICOS images
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

def base_download_url(git_commit_id, variant, update, test):
    return "https://download.dfinity.systems/ic/{git_commit_id}/{variant}/{component}{test}/{component}.tar.zst".format(
        git_commit_id = git_commit_id,
        variant = variant,
        component = "update-img" if update else "disk-img",
        test = "-test" if test else "",
    )

def dev_base_download_url(git_commit_id, variant, update):
    return "https://download.dfinity.systems/ic/{git_commit_id}/{variant}/{component}-dev/{component}.tar.zst".format(
        git_commit_id = git_commit_id,
        variant = variant,
        component = "update-img" if update else "disk-img",
    )

def get_mainnet_setupos_images(versions):
    for (name, version) in versions:
        http_file(
            name = name,
            downloaded_file_path = "disk-img.tar.zst",
            url = base_download_url(version, "setup-os", False, False),
        )

        http_file(
            name = name + "_dev",
            downloaded_file_path = "disk-img.tar.zst",
            url = dev_base_download_url(version, "setup-os", False),
        )

def get_mainnet_guestos_images(versions, extract_guestos):
    for (name, version) in versions:
        _get_mainnet_guestos_image(
            name = name,
            setupos_url = base_download_url(version, "setup-os", False, False),
            extract_guestos = extract_guestos,
        )

        _get_mainnet_guestos_image(
            name = name + "_dev",
            setupos_url = dev_base_download_url(version, "setup-os", False),
            extract_guestos = extract_guestos,
        )

_DEFS_CONTENTS = '''\
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")
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

package(default_visibility = ["//visibility:public"])

extract_image("{name}", "{extract_guestos}")
"""

_attrs = {
    "extract_guestos": attr.label(mandatory = True, doc = "Tool used to extract a GuestOS image from a SetupOS image."),
    "setupos_url": attr.string(mandatory = True, doc = "URL to the SetupOS image to extract from"),
    "setupos_integrity": attr.string(doc = "Optional integrity for the image. If unset, it will be set after the image is downloaded."),
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
    repository_ctx.file("BUILD.bazel", content = _BUILD_CONTENTS.format(name = repository_ctx.name, extract_guestos = repository_ctx.attr.extract_guestos))

    new_attrs = _copy_attrs(repository_ctx, _attrs)
    new_attrs.update({"setupos_integrity": download_info.integrity})

    return new_attrs

_get_mainnet_guestos_image = repository_rule(
    implementation = _get_mainnet_guestos_image_impl,
    attrs = _attrs,
)
