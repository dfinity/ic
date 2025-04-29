"""
This module fetches the spawn.proto file from the bazel source code and turns it into a proto_library target.
"""

def _spawn_proto_library_impl(ctx):
    ctx.download(
        # We assume the ExecLogEntry proto message is forward compatible such that we can use the spawn.proto from bazel-7.6.0 even after upgrading bazel.
        url = "https://raw.githubusercontent.com/bazelbuild/bazel/refs/tags/7.6.0/src/main/protobuf/spawn.proto",
        output = "spawn.proto",
        sha256 = "381bcb109e2855d4055fdc75988cc2144e0a92aa8586298123bb662cdefa6afe",
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

spawn_proto_library = repository_rule(implementation = _spawn_proto_library_impl)
