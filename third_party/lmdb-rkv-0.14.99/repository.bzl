"""
This module defines rules to fetch and build lmdb-rkv package.
"""

def _local(path):
    return Label("//third_party/lmdb-rkv-0.14.99:" + path)

def _lmdb_rkv_impl(repository_ctx):
    repository_ctx.download_and_extract(
        url = "https://github.com/dfinity-lab/lmdb-rs/archive/f62018b2deb79ea0d53914d5502389433fc3e6da.zip",
        sha256 = "b0c8ba9187c147c33aff5913723a8e08d9a8a7928b98180a8811beefbda112e8",
        stripPrefix = "lmdb-rs-f62018b2deb79ea0d53914d5502389433fc3e6da",
    )
    repository_ctx.symlink(_local("BUILD.lmdb-rkv-sys.bazel"), "lmdb-sys/BUILD.bazel")
    repository_ctx.symlink(_local("BUILD.lmdb-rkv.bazel"), "BUILD.bazel")

lmdb_rkv_repository = repository_rule(
    implementation = _lmdb_rkv_impl,
    attrs = {},
)
