"""
The module fetches buf binary to be used by bazel smoke test
"""

BUF_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["buf"])
"""

VERSION = "1.16.0"
SHA256 = {
    "Darwin-arm64": "17493c1013184554d5ca3cb886f0afdb109255cb71af6294f2119cb7c25c4b9c",
    "Darwin-x86_64": "18c51116c8b0bc420f095f548726d77f81898b58dd54574f78dd8d50a1a111b1",
    "Linux-x86_64": "07ea21f7dc6299da93fce571c53b06e86ab8cfe2b765c64e5b3175ea1a6962e0",
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
