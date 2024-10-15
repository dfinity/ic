"""
The module fetches ruff binary to be used by bazel smoke
"""

RUFF_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["ruff"])
"""

VERSION = "0.6.8"
SHA256 = {
    "aarch64-apple-darwin": "e554d55281391138e44b30ccd38c666388e4aeb05417c9ffb98a6cbb014aef0d",
    "x86_64-apple-darwin": "44039cea2aed4787cedcda0c35e5b352530d6ca2178f39c8bd4ff63526c43aef",
    "x86_64-unknown-linux-gnu": "7edce7075bf6d43b1ef2a9383b76a43310bbf5d70fa4471330fd5aaf655192b0",
}

URL = "https://github.com/astral-sh/ruff/releases/download/{version}/ruff-{platform}.tar.gz"

def _ruff_impl(repository_ctx):
    os_arch = repository_ctx.os.arch

    if os_arch == "x86_64" or os_arch == "amd64":
        arch = "x86_64"
    elif os_arch == "aarch64":
        arch = "aarch64"
    else:
        fail("Unsupported architecture: '" + os_arch + "'")

    os_name = repository_ctx.os.name
    if os_name == "linux":
        platform = arch + "-unknown-linux-gnu"
    elif os_name == "mac os x":
        platform = arch + "-apple-darwin"

    else:
        fail("Unsupported operating system: " + os_name)

    if platform not in SHA256:
        fail("Unsupported platform: '" + platform + "'")

    repository_ctx.report_progress("Fetching " + repository_ctx.name)
    repository_ctx.download_and_extract(url = URL.format(version = VERSION, platform = platform), sha256 = SHA256[platform], stripPrefix = "ruff-{platform}".format(platform = platform))
    repository_ctx.file("BUILD.bazel", RUFF_BUILD, executable = True)

_ruff = repository_rule(
    implementation = _ruff_impl,
    attrs = {},
)

def ruff(name):
    _ruff(name = name)
