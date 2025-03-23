"""
With hermetic toolchains, we would like to not depend on the openssl from the
build enviornment. Normally the vendored feature would build the library from
source alongside the crate, but this does not work when using rules_rust:
https://github.com/bazelbuild/rules_rust/issues/1519
Instead, we build it ourselves, here.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def openssl_repository():
    maybe(
        http_archive,
        name = "openssl",
        build_file_content = """
load("@rules_foreign_cc//foreign_cc:defs.bzl", "configure_make")

filegroup(
    name = "all_srcs",
    srcs = glob(
        include = ["**"],
        exclude = ["*.bazel"],
    ),
)

# https://wiki.openssl.org/index.php/Compilation_and_Installation
CONFIGURE_OPTIONS = [
    "no-comp",
    "no-idea",
    "no-weak-ssl-ciphers",
    "no-shared",
]

MAKE_TARGETS = [
    "build_libs",
    "install_dev",
]

configure_make(
    name = "openssl",
    args = ["-j12"],
    configure_command = "config",
    configure_in_place = True,
    configure_options = CONFIGURE_OPTIONS,
    lib_name = "openssl",
    lib_source = ":all_srcs",
    out_lib_dir = "lib64",
    out_shared_libs = [],
    out_static_libs = ["libssl.a"],
    targets = MAKE_TARGETS,
    visibility = ["//visibility:public"],
)

filegroup(
    name = "gen_dir",
    srcs = [":openssl"],
    output_group = "gen_dir",
    visibility = ["//visibility:public"],
)
""",
        integrity = "sha256-4V3agv4v6BOdwqwho21MoB1TE8dfmfRsTooncJtylL8=",
        strip_prefix = "openssl-3.4.0",
        urls = ["https://github.com/openssl/openssl/releases/download/openssl-3.4.0/openssl-3.4.0.tar.gz"],
    )
