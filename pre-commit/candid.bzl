"""
The module fetches candid binary to be used by bazel smoke test
"""

CANDID_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["didc"])
"""

VERSION = "0.1.6"
SHA256 = {
    "linux64": "606faeff92054a221e5e79e0cf239db3a3a8bc460c3d2aea628db58c7adca028",
    "macos": "34656fccf768db0c461ff6be821c708a5d5fcc2cf8768fa18fcf39148211cda4",
}

URL = "https://github.com/dfinity/candid/releases/download/{version}/didc-{platform}"

def _candid_impl(repository_ctx):
    os_arch = repository_ctx.os.arch

    # even if the macOS version is "x86_64" it runs on ARM chips because of
    # emulation
    if os_arch == "x86_64" or os_arch == "amd64" or os_arch == "aarch64":
        arch = "64"
    else:
        fail("Unsupported architecture: '" + os_arch + "'")

    os_name = repository_ctx.os.name
    if os_name == "linux":
        platform = "linux" + arch
    elif os_name == "mac os x":
        platform = "macos"
    else:
        fail("Unsupported operating system: " + os_name)

    if platform not in SHA256:
        fail("Unsupported platform: '" + platform + "'")

    if VERSION == "0.1.6":
        release_tag = "2022-11-17"
    else:
        fail("Unsupported version '" + VERSION + "'")

    repository_ctx.report_progress("Fetching " + repository_ctx.name)
    repository_ctx.download(url = URL.format(version = release_tag, platform = platform), sha256 = SHA256[platform], output = "didc", executable = True)
    repository_ctx.file("BUILD.bazel", CANDID_BUILD, executable = True)

_candid = repository_rule(
    implementation = _candid_impl,
    attrs = {},
)

def candid(name):
    _candid(name = name)
