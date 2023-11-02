"""
The module fetches buf binary to be used by bazel smoke test
"""

BUF_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["buf"])
"""

VERSION = "1.25.1"
SHA256 = {
    "Darwin-arm64": "08491afe7ce38784d1a25cdc9baa319a35e847c1ff3ef0b7047040c1214b2fcb",
    "Darwin-x86_64": "2bfc27902b4e75ea27d61eb22d774a3c3d969f1dd99c363a8d3dd80721414c5b",
    "Linux-x86_64": "3e013b7b7d204ee0ca2952da076fd3fd6e014d11aa92e6262a4343bd61747f34",
}

URL = "https://github.com/bufbuild/buf/releases/download/v{version}/buf-{platform}"

def _buf_impl(repository_ctx):
    os_arch = repository_ctx.os.arch

    if os_arch == "x86_64" or os_arch == "amd64":
        arch = "x86_64"
    elif os_arch == "aarch64":
        arch = "arm64"
    else:
        fail("Unsupported architecture: '" + os_arch + "'")

    os_name = repository_ctx.os.name
    if os_name == "linux":
        platform = "Linux-" + arch
    elif os_name == "mac os x":
        platform = "Darwin-" + arch

    else:
        fail("Unsupported operating system: " + os_name)

    if platform not in SHA256:
        fail("Unsupported platform: '" + platform + "'")

    repository_ctx.report_progress("Fetching " + repository_ctx.name)
    repository_ctx.download(url = URL.format(version = VERSION, platform = platform), sha256 = SHA256[platform], executable = True, output = "buf")
    repository_ctx.file("BUILD.bazel", BUF_BUILD, executable = True)

_buf = repository_rule(
    implementation = _buf_impl,
    attrs = {},
)

def buf(name):
    _buf(name = name)
