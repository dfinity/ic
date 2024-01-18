"""
The module fetches buf binary to be used by bazel smoke test
"""

BUF_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["buf"])
"""

VERSION = "1.28.1"
SHA256 = {
    "Darwin-arm64": "72bcb6c7ffd46ff3d47ca78e77b55223d71e35675d7fe5b4ab5c6b41c9814165",
    "Darwin-x86_64": "9f464e4178db03d07fb455997d9fdb579c2c67a353ff4e133e0b248aebf1446e",
    "Linux-x86_64": "855a055c8615a03ee93219f287bd7f652586c6b6b8d2b01079782cba54ee6033",
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
