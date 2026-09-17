"""
This module defines Bazel targets for the mainnet versions of ICOS images.

The `mainnet_icos_images` repository rule generates a tiny repository whose BUILD
file downloads the images *at build time*. A fetch-time `repository_ctx.download`
would run whenever Bazel loads a package of the repository, which
`bazel query 'rdeps(//..., ...)'` (ci/scripts/targets.py) does for every package
in the closure of `//...`, i.e. on every PR: ~20 GB of images that PR builds
never use (https://github.com/bazelbuild/bazel/issues/13190). As build actions
the downloads run only when a consumer is actually built, and their outputs are
served from the local action cache and the remote cache like any other output.
"""

load(
    "//bazel:mainnet-artifact-refs.bzl",
    "check",
    "checked_commit_id",
    "checked_url",
    "checked_variant",
    "icos_record_error",
)

_CDN_PREFIX = "https://download.dfinity.systems/ic/"

def icos_image_download_url(git_commit_id, variant, update):
    """URL of the `variant` disk or update image published for `git_commit_id`.

    `git_commit_id` comes from the auto-merged mainnet-icos-revisions.json (directly,
    or through @mainnet_icos_versions for the system-test `*_IMG_URL` env vars), so it
    is validated here -- for every caller -- against escaping the pinned CDN prefix
    (see //bazel:mainnet-artifact-refs.bzl).

    Args:
      git_commit_id: the revision the image was published for.
      variant: the ICOS variant, e.g. "guest-os".
      update: whether to return the update image instead of the disk image.

    Returns:
      The download URL.
    """
    return checked_url("https://download.dfinity.systems/ic/{git_commit_id}/{variant}/{component}/{component}.tar.zst".format(
        git_commit_id = checked_commit_id(git_commit_id, "the mainnet ICOS version"),
        variant = checked_variant(variant, "the ICOS image variant"),
        component = "update-img" if update else "disk-img",
    ), _CDN_PREFIX)

def icos_dev_image_download_url(git_commit_id, variant, update):
    """URL of the `variant` dev disk or update image published for `git_commit_id`.

    Like `icos_image_download_url`, but for the dev channel of the same revision.

    Args:
      git_commit_id: the revision the image was published for.
      variant: the ICOS variant, e.g. "guest-os".
      update: whether to return the update image instead of the disk image.

    Returns:
      The download URL.
    """
    return checked_url("https://download.dfinity.systems/ic/{git_commit_id}/{variant}/{component}-dev/{component}.tar.zst".format(
        git_commit_id = checked_commit_id(git_commit_id, "the mainnet ICOS version"),
        variant = checked_variant(variant, "the ICOS image variant"),
        component = "update-img" if update else "disk-img",
    ), _CDN_PREFIX)

# One genrule per downloaded image.
#
# `{url}` and `{sha256}` are interpolated verbatim into the genrule `cmd`, i.e.
# into shell text. That is safe only because both were validated first (see the
# `check(icos_record_error(...))` call in the implementation below): `checked_url`
# restricts a URL to [A-Za-z0-9._-/:], which contains no shell metacharacter and
# no `$` (which genrule would treat as a Make variable), and `sha256_error`
# restricts a hash to 64 lowercase hex characters.
#
# The download and its verification live in //bazel:mainnet-icos-download.sh, so
# the shell is shfmt-checked source instead of escaped Starlark text; the
# script's digest is part of the action key, as are the URL and the sha256, so
# the action re-runs exactly when the revisions JSON re-pins the image.
_DOWNLOAD_GENRULE = """
genrule(
    name = "download_{name}",
    outs = ["{out}"],
    cmd = "$(location @@//bazel:mainnet-icos-download.sh) {url} {sha256} $@",
    # Bazel doesn't forward the "requires-network" tag to the Remote Execution API (REAPI)
    # so this Namespace.so-specific execution property is what would open up the network for
    # the action on an RBE worker. Without a remote executor the property is inert.
    exec_properties = {{"namespace_requires_network": "true"}},
    # requires-network: bazel/conf/.bazelrc.build sets --nosandbox_default_allow_network,
    #   so a locally sandboxed run needs it to leave the sandbox's network namespace.
    # no-remote-exec: run the download on the machine driving the build (the RBE driver
    #   container on CI), not on an RBE worker. On 2026-09-16 the worker sandbox had no
    #   network at all despite the execution property above (every curl failed instantly
    #   with "Could not resolve host", see
    #   https://github.com/dfinity/ic/actions/runs/35143842952/job/104955157611), while the
    #   driver has downloaded these images for months. Remotely executed consumers still
    #   get the image: Bazel uploads a locally produced output to the remote CAS when a
    #   remote action needs it as an input. Drop the tag again once a non-cached network
    #   action has been shown to work on the workers.
    # manual: never pulled in by a wildcard.
    # Deliberately no no-cache / no-remote-cache: caching this action is the point.
    tags = ["manual", "no-remote-exec", "requires-network"],
    target_compatible_with = ["@platforms//os:linux"],
    tools = ["@@//bazel:mainnet-icos-download.sh"],
)
"""

# Extracts the GuestOS disk image from the (downloaded) SetupOS disk image.
_GUEST_IMG_GENRULE = """
genrule(
    name = "guest-img",
    srcs = ["disk-img.tar.zst"],
    outs = ["guest-img.tar.zst"],
    # no-remote-exec: extract-guestos unpacks the multi-GB SetupOS image under
    # `tempdir()`, i.e. /tmp, and the RBE workers only have a 1 GB /tmp (#10797).
    # #10797's other reason, copying the multi-GB *local* SetupOS image to the
    # worker, applies as well while the download above runs locally.
    tags = ["manual", "no-remote-exec"],
    cmd = \"""#!/bin/bash
        $(location @@//rs/ic_os/build_tools/partition_tools:extract-guestos) --image $< $@
    \""",
    target_compatible_with = ["@platforms//os:linux"],
    tools = ["@@//rs/ic_os/build_tools/partition_tools:extract-guestos"],
)
"""

def _mainnet_icos_images_impl(repository_ctx):
    """Repository rule for the mainnet ICOS images of one revisions-JSON record.

    The generated repository exports:

      * `disk-img.tar.zst`: the SetupOS disk image, downloaded at build time,
      * `launch-measurements-guest.json`: the GuestOS launch measurements of the
        record, written while the repository is fetched (it is tiny),
      * `guest-img.tar.zst` (target `:guest-img`): the GuestOS disk image
        extracted from the SetupOS disk image,
      * for GuestOS records only, `guest-update-img.tar.zst`: the GuestOS update
        image, downloaded at build time. The local system-test backend serves it
        from its own file server to the IC nodes, since (unlike the Farm backend)
        it has no external network access to download it from the CDN. HostOS
        records carry the hash of the *HostOS* update image in `update_img_hash`,
        so no update image is declared for them.

    Nothing is downloaded while the repository is fetched; see the module
    docstring for why.
    """

    parts = list(repository_ctx.attr.parts)

    # The path to the mainnet icos info
    json_path = repository_ctx.attr.path
    repository_ctx.watch(json_path)  # recreate the repo if the data changes

    # Read and decode mainnet data
    info = json.decode(repository_ctx.read(json_path))
    for part in parts:
        info = info[part]

    # The JSON is not reviewed by a human before it is merged, so validate the
    # version and the image hashes before they are interpolated into download
    # URLs and into the shell commands of the generated BUILD file.
    check(icos_record_error(info), "%s: %s" % (json_path, "/".join(parts)))

    dev = repository_ctx.attr.dev
    git_commit_id = info["version"]
    url_fn = icos_dev_image_download_url if dev else icos_image_download_url
    is_guestos = parts[0] == "guestos"

    # The image files are genrule outputs, so they must not be exported as
    # source files as well: a generated file that conflicts with a source file
    # is a load error of the package.
    build = """\
package(default_visibility = ["//visibility:public"])
exports_files(["launch-measurements-guest.json"])
"""
    build += _DOWNLOAD_GENRULE.format(
        name = "disk-img",
        out = "disk-img.tar.zst",
        url = url_fn(git_commit_id, "setup-os", False),
        sha256 = info["setupos_disk_img_hash_dev" if dev else "setupos_disk_img_hash"],
    )
    if is_guestos:
        build += _DOWNLOAD_GENRULE.format(
            name = "guest-update-img",
            out = "guest-update-img.tar.zst",
            url = url_fn(git_commit_id, "guest-os", True),
            sha256 = info["update_img_hash_dev" if dev else "update_img_hash"],
        )
    build += _GUEST_IMG_GENRULE
    repository_ctx.file("BUILD.bazel", content = build)

    repository_ctx.file(
        "launch-measurements-guest.json",
        content = json.encode(info["launch_measurements_dev"] if dev else info["launch_measurements"]),
    )

    # This repo is reproducible: everything in it is derived from the watched
    # revisions JSON and the rule attributes. Declaring this makes the repo
    # eligible for Bazel 9's repo contents cache ({repository_cache}/contents);
    # it is tiny either way.
    return repository_ctx.repo_metadata(reproducible = True)

mainnet_icos_images = repository_rule(
    implementation = _mainnet_icos_images_impl,
    attrs = {
        "parts": attr.string_list(mandatory = True, doc = "Will be used to index into the mainnet icos revisions JSON file."),
        "path": attr.label(mandatory = True, doc = "The path to the mainnet icos revisions."),
        "dev": attr.bool(mandatory = False, default = False, doc = "When 'True', dev images are pulled."),
    },
)
