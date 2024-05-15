"""A module defining the Bitcoin Core dependency, used for the testing of the bitcoin adapter"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def bitcoin_core_repository():
    maybe(
        http_archive,
        name = "bitcoin-core",
        build_file = Label("//third_party/bitcoin-core:BUILD.bitcoin-core.bazel"),
        sha256 = "5df67cf42ca3b9a0c38cdafec5bbb517da5b58d251f32c8d2a47511f9be1ebc2",
        strip_prefix = "bitcoin-25.0",
        urls = [
            "https://bitcoin.org/bin/bitcoin-core-25.0/bitcoin-25.0.tar.gz",
            "https://bitcoincore.org/bin/bitcoin-core-25.0/bitcoin-25.0.tar.gz",
        ],
    )
