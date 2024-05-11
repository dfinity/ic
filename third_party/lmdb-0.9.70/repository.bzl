"""
This module defines rules to fetch and build lmdb native library.
"""

def _lmdb_repo_impl(repository_ctx):
    repository_ctx.download_and_extract(
        url = "https://git.openldap.org/openldap/openldap/-/archive/55fd54dae6f90080b770dbc9dbcee5044976b7bf/openldap-55fd54dae6f90080b770dbc9dbcee5044976b7bf.zip",
        sha256 = "657307ba28abbf6d926b24d568098a34de5888e165d1cb0c434ef6c9f2ec392d",
        stripPrefix = "openldap-55fd54dae6f90080b770dbc9dbcee5044976b7bf/libraries/liblmdb",
    )
    repository_ctx.file("BUILD.bazel", """
package(default_visibility = ["//visibility:public"])

exports_files(["lmdb.h"])

cc_library(
name = "lmdb",
srcs = [
    "mdb.c",
    "midl.c",
    "midl.h",
],
hdrs = ["lmdb.h"],
)
""")

lmdb_repository = repository_rule(
    implementation = _lmdb_repo_impl,
    attrs = {},
)
