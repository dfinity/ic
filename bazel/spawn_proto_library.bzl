"""
This module fetches the spawn.proto file from the bazel source code and turns it into a proto_library target.
"""

def _spawn_proto_library_impl(ctx):
    dest = ctx.path("spawn.proto")

    # Download the file
    ctx.download(
        url = ctx.attr.url,
        output = dest.basename,
        sha256 = ctx.attr.sha256,
    )

    ctx.file("BUILD.bazel", """
load("@com_google_protobuf//bazel:proto_library.bzl", "proto_library")

package(default_visibility = ["//visibility:public"])

proto_library(
    name = "spawn_pb2",
    srcs = ["spawn.proto"],
    deps = [
        "@com_google_protobuf//:duration_proto",
        "@com_google_protobuf//:timestamp_proto",
    ],
)
    """)

spawn_proto_library = repository_rule(
    implementation = _spawn_proto_library_impl,
    attrs = {
        "url": attr.string(mandatory = True),
        "sha256": attr.string(mandatory = True),
    },
)
