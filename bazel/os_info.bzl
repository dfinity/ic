"""
The module exports information on the OS in like "x86_64-linux"
"""

def _os_info_impl(repository_ctx):
    # Figure out the arch
    os_arch = repository_ctx.os.arch
    is_x86_64 = os_arch == "x86" or os_arch == "x86_64" or os_arch == "amd64"
    is_arm_64 = os_arch == "arm" or os_arch == "arm64" or os_arch == "aarch64"

    # Figure out the OS
    os_name = repository_ctx.os.name
    is_linux = os_name.lower().startswith("linux")
    is_darwin = os_name.lower().startswith("mac")

    os_arch = "x86_64" if is_x86_64 else "arm64" if is_arm_64 else "unknown"
    os_name = "linux" if is_linux else "darwin" if is_darwin else "unknown"

    os_info = os_arch + "-" + os_name

    # Create a minimal BUILD.bazel file (Bazel requires it)
    repository_ctx.file("BUILD.bazel", content = "\n")
    repository_ctx.file("defs.bzl", "os_info = \"{}\"".format(os_info))

os_info = repository_rule(
    implementation = _os_info_impl,
    attrs = {},
)
