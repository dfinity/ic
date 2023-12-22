"""
The module fetches the dfx binary from the dfinity/sdk repository
"""

DFX_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["dfx"])
"""

VERSION = "0.15.1"
SHA256 = {
    "linux": "ee770bf47debb2b01f875fd5bbc4d759f8dbdd3f4bbeabaa1b1eb6a821a1a337",
    "darwin": "c8698d4bf77d1a21809f0427158014a72a6f22602e0d5251a1f1d662c8d06833",
}

URL = "https://github.com/dfinity/sdk/releases/download/{version}/dfx-{version}-{arch}-{platform}.tar.gz"

def _dfx_impl(repository_ctx):
    os_arch = repository_ctx.os.arch

    # even if the macOS version is "x86_64" it runs on ARM chips because of
    # emulation
    if os_arch == "x86_64" or os_arch == "amd64" or os_arch == "aarch64":
        arch = "x86_64"
    else:
        fail("Unsupported architecture: '" + os_arch + "'")

    os_name = repository_ctx.os.name
    if os_name == "linux":
        platform = "linux"
    elif os_name == "mac os x":
        platform = "darwin"
    else:
        fail("Unsupported operating system: " + os_name)

    if platform not in SHA256:
        fail("Unsupported platform: '" + platform + "'")

    repository_ctx.report_progress("Fetching " + repository_ctx.name)
    repository_ctx.download_and_extract(url = URL.format(version = VERSION, platform = platform, arch = arch), sha256 = SHA256[platform])
    repository_ctx.file("BUILD.bazel", DFX_BUILD, executable = True)

_dfx = repository_rule(
    implementation = _dfx_impl,
    attrs = {},
)

def dfx(name):
    _dfx(name = name)
