"""A module defining the lmdb native library used by the replica for persistence"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def lmdb_repository():
    maybe(
        http_archive,
        name = "lmdb",
        build_file = Label("//third_party/lmdb:BUILD.lmdb.bazel"),
        sha256 = "9f8e4f1fa8c0996043ef35db0d0d52b9cbd314572263cf2e5961912b0410fa72",
        strip_prefix = "openldap-55fd54dae6f90080b770dbc9dbcee5044976b7bf/libraries/liblmdb",
        urls = [
            "https://git.openldap.org/openldap/openldap/-/archive/55fd54dae6f90080b770dbc9dbcee5044976b7bf/openldap-55fd54dae6f90080b770dbc9dbcee5044976b7bf.zip",
        ],
    )
