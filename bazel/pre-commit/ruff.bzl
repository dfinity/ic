"""
The module fetches ruff binary to be used by bazel smoke
"""

RUFF_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["ruff"])
"""

VERSION = "0.0.260"
SHA256 = {
    "aarch64-apple-darwin": "4e045df5e55f1e23b34910865fe66c8e9d4ea98dbdb5320fc8ff09b8c337d69e",
    "x86_64-apple-darwin": "3b251413bd5dfa60997489b33024b5f596cb3781f5cf3763529fb24cd97059c0",
    "x86_64-unknown-linux-gnu": "abb106ee7d1434faa733e6dd442b1d306fa32e0840fde24fbbf96c2289968c63",
}

URL = "https://github.com/charliermarsh/ruff/releases/download/v{version}/ruff-{platform}.tar.gz"

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
    repository_ctx.download_and_extract(url = URL.format(version = VERSION, platform = platform), sha256 = SHA256[platform])
    repository_ctx.file("BUILD.bazel", RUFF_BUILD, executable = True)

_ruff = repository_rule(
    implementation = _ruff_impl,
    attrs = {},
)

def ruff(name):
    _ruff(name = name)
