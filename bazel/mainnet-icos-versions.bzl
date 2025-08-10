"""Mainnet version definitions.

This creates a Bazel repository which exports 'mainnet_icos_versions'. This macro can be
called to create one Bazel repository for the entire mainnet ICOS versions list.
"""

def _mainnet_icos_versions_impl(repository_ctx):
    # Read and decode mainnet version data
    versions = json.decode(repository_ctx.read(repository_ctx.attr.path))

    # Create a minimal BUILD.bazel file (Bazel requires it)
    repository_ctx.file("BUILD.bazel", content = "\n")

    content = "mainnet_icos_versions = %s" % versions
    repository_ctx.file("defs.bzl", content = content)

mainnet_icos_versions = repository_rule(
    implementation = _mainnet_icos_versions_impl,
    attrs = {
        "path": attr.label(mandatory = True, doc = "path to mainnet ICOS versions data"),
    },
)
