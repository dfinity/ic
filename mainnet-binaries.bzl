"""
This module defines Bazel targets for the mainnet versions of some of the published binaries (/publish/binaries)
"""

# This needs to be kept in sync with the git revision of the tdb26-* (NNS) subnet tracked in testnet/mainnet_revisions.json.
# TODO: read the revision from that file instead of hardcoding it here
# and automate updating the SHA256s below whenever testnet/mainnet_revisions.json changes.
MAINNET_REVISION = "afe1a18291987667fdb52dac3ca44b1aebf7176e"

# Hashes of the published binaries. These should be updated whenever MAINNET_REVISION and testnet/mainnet_revisions.json are updated.
BINARY_SHA256S = {
    "pocket-ic": "057b323263dbffefc3004ae7485b85c580c294c80eeb49dc14f66590ca14f9cd",
}

def _mainnet_binary_impl(ctx):
    binary_name = ctx.attr.binary_name
    url = "https://download.dfinity.systems/ic/{git_commit_id}/binaries/x86_64-linux/{binary_name}.gz".format(
        git_commit_id = MAINNET_REVISION,
        binary_name = binary_name,
    )
    ctx.report_progress("Fetching " + url + " ...")
    ctx.download_and_extract(
        url = url,
        sha256 = BINARY_SHA256S[binary_name],
    )
    BUILD_BAZEL = """
    package(default_visibility = ["//visibility:public"])
    exports_files(["{binary_name}}"])
    """.format(binary_name = binary_name)
    ctx.file("BUILD.bazel", BUILD_BAZEL)

_mainnet_binary = repository_rule(
    implementation = _mainnet_binary_impl,
    attrs = {
        "binary_name": attr.string(mandatory = True),
    },
)

def mainnet_binary(binary_name):
    _mainnet_binary(
        name = "mainnet_" + binary_name.replace("-", "_"),
        binary_name = binary_name,
    )

def mainnet_binaries():
    """
    Provides Bazel targets for the mainnet version of published binaries (/publish/binaries)
    """
    mainnet_binary("pocket-ic")
