"""
This module defines Bazel targets for the mainnet versions of some of the published binaries (/publish/binaries)
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

# This needs to be kept in sync with the git revision of the tdb26-* (NNS) subnet tracked in testnet/mainnet_revisions.json.
# TODO: read the revision from that file instead of hardcoding it here
# and automate updating the SHA256s below whenever testnet/mainnet_revisions.json changes.

# TODO: currently the pocket-ic lib is incompatible with the pocket-ic server from mainnet.
# We fix this by using a more recent commit (rc--2024-09-13_01-31) which makes them compatible.
#MAINNET_REVISION = "afe1a18291987667fdb52dac3ca44b1aebf7176e"
MAINNET_REVISION = "52ebccfba8855e23dcad9657a8d6e6be01df71f9"

# Hashes of the published binaries. These should be updated whenever MAINNET_REVISION and testnet/mainnet_revisions.json are updated.
MAINNET_BINARY_SHA256S = {
    # TODO: this is the mainnet hash:
    #"pocket-ic": "057b323263dbffefc3004ae7485b85c580c294c80eeb49dc14f66590ca14f9cd",
    "pocket-ic": "454891cac2421f3f894759ec5e6b6e48fbb544d79197bc29b88d34b93d78a4f1",
}

def mainnet_binary_gzs():
    """
    Declares Bazel targets for the gz-compressed mainnet versions of published binaries (/publish/binaries)
    """
    for binary_name in MAINNET_BINARY_SHA256S.keys():
        name = "mainnet_" + binary_name.replace("-", "_")
        gz = name + ".gz"
        http_file(
            name = gz,
            sha256 = MAINNET_BINARY_SHA256S[binary_name],
            url = "https://download.dfinity.systems/ic/{git_commit_id}/binaries/x86_64-linux/{binary_name}.gz".format(
                git_commit_id = MAINNET_REVISION,
                binary_name = binary_name,
            ),
        )

def mainnet_binaries():
    """
    Declares Bazel targets for the mainnet versions of published binaries (/publish/binaries)
    """
    for binary_name in MAINNET_BINARY_SHA256S.keys():
        name = "mainnet_" + binary_name.replace("-", "_")
        gz = name + ".gz"
        native.genrule(
            name = name,
            srcs = ["@" + gz + "//file"],
            outs = [binary_name],
            cmd = "gunzip -c $< > $@",
        )
