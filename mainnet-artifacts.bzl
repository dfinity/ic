"""
This module defines Bazel targets for the mainnet versions of some of the published binaries (/publish/binaries)
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

# This variable is automatically kept in sync by ci/scripts/update-mainnet-artifacts.sh
# with the IC version (git revision) of the mainnet NNS subnet (tdb26-...) tracked in testnet/mainnet_revisions.json
MAINNET_NNS_SUBNET_IC_VERSION = "99ab7f03700ba6cf832eb18ffd55228f56ae927a"

# Which published binaries to download. This dictionary maps the name of the binary to a dictionary of type:
# {"rev":"<rev>", "sha256":"<sha256>"} where
#   <rev>: is the git revision of the published binary.
#     This should always be set to MAINNET_NNS_SUBNET_IC_VERSION
#     unless there's a strong reason to override it. For example when the binary is incompatible with HEAD.
#   <sha256>: this should be the SHA256 hash of the published gz-compressed binary.
#     If <rev> equals MAINNET_NNS_SUBNET_IC_VERSION this hash is automatically updated
#     by ci/scripts/update-mainnet-artifacts.sh.
# Please make sure the key value pairs are contained on a single line otherwise ci/scripts/update-mainnet-artifacts.sh will fail to update them correctly.
PUBLISHED_BINARIES = {
    "ic-recovery": {"rev": MAINNET_NNS_SUBNET_IC_VERSION, "sha256": "8411814fd0a66fa52d1a4b096c2b1a3d7482faf6d31f3e4b6520021c2275c49b"},
    "ic-replay": {"rev": MAINNET_NNS_SUBNET_IC_VERSION, "sha256": "a6234ea2ad32cf8a5de7d45626988237f2e9ddc30cdc25d51166feb8735c5092"},
    # TODO: when the mainnet pocket-ic server is compatible with the HEAD version of the pocket-ic library
    # we should use the mainnet version again using:
    # "pocket-ic": {"rev": MAINNET_NNS_SUBNET_IC_VERSION, "sha256": "057b323263dbffefc3004ae7485b85c580c294c80eeb49dc14f66590ca14f9cd"},
    # until that's the case we use a slightly newer version of the pocket-ic server (rc--2024-09-13_01-31):
    "pocket-ic": {"rev": "52ebccfba8855e23dcad9657a8d6e6be01df71f9", "sha256": "454891cac2421f3f894759ec5e6b6e48fbb544d79197bc29b88d34b93d78a4f1"},
}

def mainnet_binary_gzs():
    """
    Declares Bazel targets for the gz-compressed mainnet versions of published binaries (/publish/binaries)
    """
    for binary_name, bin in PUBLISHED_BINARIES.items():
        http_file(
            name = "mainnet-" + binary_name + ".gz",
            sha256 = bin["sha256"],
            url = "https://download.dfinity.systems/ic/{rev}/binaries/x86_64-linux/{binary_name}.gz".format(
                rev = bin["rev"],
                binary_name = binary_name,
            ),
        )

def mainnet_binaries(name):
    """
    Declares Bazel targets for the mainnet versions of published binaries (/publish/binaries)

    Args:
      name: the name of the targets of the mainnet binaries will be prefixed with this name.
        This argument is really unnecessary since I would rather hard-code it to "mainnet". However
        `bazel test //bazel:buildifier_test` requires this function to have a "name" argument.
    """
    for binary_name in PUBLISHED_BINARIES.keys():
        target_name = name + "-" + binary_name
        native.genrule(
            name = target_name,
            srcs = ["@" + target_name + ".gz//file"],
            outs = [binary_name],
            cmd = "gunzip -c $< > $@",
        )
