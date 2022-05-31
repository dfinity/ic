"""
This module defines rules to fetch and build lmdb-rkv package.
"""

def _local(path):
    return Label("//third_party/lmdb-rkv-0.14.99:" + path)

def _lmdb_rkv_impl(repository_ctx):
    repository_ctx.download_and_extract(
        url = "https://github.com/dfinity-lab/lmdb-rs/archive/da5626f8ef81bba671cac0c6b7a078c6e0e73d66.zip",
        sha256 = "7530d474392861efa70b7844368ee2f607535c56005bd76cf66ad1e364623aab",
        stripPrefix = "lmdb-rs-da5626f8ef81bba671cac0c6b7a078c6e0e73d66",
    )
    repository_ctx.symlink(_local("BUILD.lmdb-rkv-sys.bazel"), "lmdb-sys/BUILD.bazel")
    repository_ctx.symlink(_local("BUILD.lmdb-rkv.bazel"), "BUILD.bazel")

lmdb_rkv_repository = repository_rule(
    implementation = _lmdb_rkv_impl,
    attrs = {},
)
