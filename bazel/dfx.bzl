"""
The module fetches the dfx binary from the dfinity/sdk repository
"""

DFX_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["dfx"])
"""

VERSION = "0.19.0"
SHA256 = {
    "linux": "c40387d13ab6ed87349fa21a98835f8d384f867333806ee6b9025891ed96e5c5",
    "darwin": "f61179fa9884f111dbec20c293d77472dcf66d04b0567818fe546437aadd8ce6",
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
