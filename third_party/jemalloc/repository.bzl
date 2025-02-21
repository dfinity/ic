"""A module defining the jemalloc native library used by the replica"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def jemalloc_repository():
    maybe(
        http_archive,
        name = "jemalloc",
        build_file = Label("//third_party/jemalloc:BUILD.jemalloc.bazel"),
        sha256 = "ef6f74fd45e95ee4ef7f9e19ebe5b075ca6b7fbe0140612b2a161abafb7ee179",
        strip_prefix = "jemalloc-5.3.0",
        urls = [
            "https://github.com/jemalloc/jemalloc/archive/refs/tags/5.3.0.tar.gz",
        ],
    )
