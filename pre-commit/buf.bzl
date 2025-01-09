"""
The module fetches buf binary to be used by bazel smoke test
"""

BUF_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["buf"])
"""

VERSION = "1.46.0"
SHA256 = {
    "Darwin-arm64": "bb039f69ed1e00dd07ab4f1ee88cdceb663f448150ca8092f9348e2f66df475f",
    "Darwin-x86_64": "95a4b42bbf808194ffe5807fa869d622b6af37893c500d8ba4e3cfe2fe662e97",
    "Linux-x86_64": "04c92815f92431bea637d834bee9d2941e979b1c821c59805667c032e2e8fc1f",
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
