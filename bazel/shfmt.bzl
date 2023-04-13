"""
The module fetches shfmt binary to be used by bazel smoke test
"""

SHFMT_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["shfmt"])
"""

VERSION = "3.6.0"
SHA256 = {
    "darwin_amd64": "b8c9c025b498e2816b62f0b717f6032e9ab49e725a45b8205f52f66318f17185",
    "darwin_arm64": "633f242246ee0a866c5f5df25cbf61b6af0d5e143555aca32950059cf13d91e0",
    "linux_amd64": "5741a02a641de7e56b8da170e71a97e58050d66a3cf485fb268d6a5a8bb74afb",
}

URL = "https://github.com/mvdan/sh/releases/download/v{version}/shfmt_v{version}_{platform}"

FILE_SYM = "shfmt_v{version}_{platform}"

def _shfmt_impl(repository_ctx):
    os_arch = repository_ctx.os.arch

    if os_arch == "x86_64" or os_arch == "amd64":
        arch = "amd64"
    elif os_arch == "aarch64":
        arch = "arm64"
    else:
        fail("Unsupported architecture: '" + os_arch + "'")

    os_name = repository_ctx.os.name
    if os_name == "linux":
        platform = "linux_" + arch
    elif os_name == "mac os x":
        platform = "darwin_" + arch

    else:
        fail("Unsupported operating system: " + os_name)

    if platform not in SHA256:
        fail("Unsupported platform: '" + platform + "'")

    repository_ctx.report_progress("Fetching " + repository_ctx.name)
    repository_ctx.download(url = URL.format(version = VERSION, platform = platform), sha256 = SHA256[platform], executable = True, output = "shfmt")
    repository_ctx.file("BUILD.bazel", SHFMT_BUILD, executable = True)

_shfmt = repository_rule(
    implementation = _shfmt_impl,
    attrs = {},
)

def shfmt(name):
    _shfmt(name = name)
