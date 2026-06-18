"""
This module defines Bazel targets for the mainnet versions of ICOS images
"""

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

    For GuestOS repositories the GuestOS update image is additionally downloaded
    (as guest-update-img.tar.zst) and exported. The local system-test backend
    serves this update image from its own file server to the IC nodes, since
    (unlike the Farm backend) it has no external network access to download it
    from the CDN.
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

    url_fn = icos_dev_image_download_url if repository_ctx.attr.dev else icos_image_download_url

    repository_ctx.download(url_fn(git_commit_id, "setup-os", False), "disk-img.tar.zst")  # download the disk image

    # For GuestOS repositories also download the GuestOS update image so the
    # local system-test file server can serve it to the IC nodes.
    is_guestos = parts[0] == "guestos"
    if is_guestos:
        repository_ctx.download(url_fn(git_commit_id, "guest-os", True), "guest-update-img.tar.zst")

    if repository_ctx.attr.dev:
        json_measurements = json.encode(info["launch_measurements_dev"])
    else:
        json_measurements = json.encode(info["launch_measurements"])

    # write the measurements
    repository_ctx.file("launch-measurements-guest.json", content = json_measurements)

    exported_files = ["disk-img.tar.zst", "launch-measurements-guest.json"]
    if is_guestos:
        exported_files.append("guest-update-img.tar.zst")

    BUILD = """\
package(default_visibility = ["//visibility:public"])
exports_files({EXPORTED_FILES})

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
    """.format(EXPORTED_FILES = str(exported_files))
    repository_ctx.file("BUILD.bazel", content = BUILD)

mainnet_icos_images = repository_rule(
    implementation = _mainnet_icos_images_impl,
    attrs = {
        "parts": attr.string_list(mandatory = True, doc = "Will be used to index into the mainnet icos revisions JSON file."),
        "path": attr.label(mandatory = True, doc = "The path to the mainnet icos revisions."),
        "dev": attr.bool(mandatory = False, default = False, doc = "When 'True', dev images are pulled."),
    },
)
