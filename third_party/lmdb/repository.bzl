"""A module defining the lmdb native library used by the replica for persistence"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def lmdb_repository():
    maybe(
        http_archive,
        name = "lmdb",
        build_file = Label("//third_party/lmdb:BUILD.lmdb.bazel"),
        sha256 = "d424c1eb841d0b78b91994b6ddef31aa6a3300727b9d9e7868033edfca0f142c",
        urls = [
            "https://github.com/openldap/openldap/archive/refs/tags/OPENLDAP_REL_ENG_2_5_9.zip",
        ],
    )
