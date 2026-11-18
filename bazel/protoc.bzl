"""A rule exposing the protoc of the resolved proto toolchain as a file.

proto_library and the other protobuf rules take protoc from the proto toolchain.
Tools that run protoc themselves, like prost-build in cargo build scripts, need
it as a file instead, e.g. via `PROTOC=$(execpath //bazel:protoc)`. This rule
resolves the same toolchain and returns its protoc.
"""

_PROTO_TOOLCHAIN_TYPE = Label("@protobuf//bazel/private:proto_toolchain_type")

def _current_protoc_impl(ctx):
    protoc = ctx.toolchains[_PROTO_TOOLCHAIN_TYPE].proto.proto_compiler.executable

    # A prebuilt protoc is a source file of the repository it's downloaded to.
    # A generated one means that protobuf's from-source toolchain was resolved,
    # which compiles protoc from C++ source.
    if not protoc.is_source:
        fail(("{} resolved {}, which is compiled from C++ source. Is " +
              "--@protobuf//bazel/flags:prefer_prebuilt_protoc set to false?").format(ctx.label, protoc.owner))

    return [DefaultInfo(
        files = depset([protoc]),
        runfiles = ctx.runfiles(files = [protoc]),
    )]

current_protoc = rule(
    implementation = _current_protoc_impl,
    doc = "Returns the protoc of the resolved proto toolchain, which must be a prebuilt one.",
    toolchains = [_PROTO_TOOLCHAIN_TYPE],
)
