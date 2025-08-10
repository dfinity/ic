"""
This module defines a repository rule for accessing the rosetta-cli tool.
See https://github.com/coinbase/rosetta-cli for more detail.
"""

ROSETTA_CLI_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["rosetta-cli"])
"""

BINARIES = {
    "darwin-amd64": {
        "url": "https://github.com/coinbase/mesh-cli/releases/download/v0.10.3/rosetta-cli-0.10.3-darwin-amd64.tar.gz",
        "sha256": "6426d69d8ce6851a00eb47c4b3bb5a5f2f792daca58a58d077ac5ade7c07f42b",
    },
    "darwin-arm64": {
        "url": "https://github.com/coinbase/mesh-cli/releases/download/v0.10.3/rosetta-cli-0.10.3-darwin-arm64.tar.gz",
        "sha256": "41eaa23bc2a34568549e7c0d99c3471fd0c20959ffb7a1e9fd2acc658f500b20",
    },
    "linux-amd64": {
        "url": "https://github.com/coinbase/mesh-cli/releases/download/v0.10.3/rosetta-cli-0.10.3-linux-amd64.tar.gz",
        "sha256": "1ea96b427dfa69a93d2915bc57669014b58d66a9ee7d761509d50b66486d42f8",
    },
}

def _rosetta_cli_impl(repository_ctx):
    os_name = repository_ctx.os.name
    if os_name == "linux":
        os = "linux"
    elif os_name == "mac os x":
        os = "darwin"
    else:
        fail("Unsupported operating system: " + os_name)

    os_arch = repository_ctx.os.arch
    if os_arch == "x86_64":
        platform = os + "-amd64"
    elif os_arch == "amd64":
        platform = os + "-amd64"
    elif os_arch == "aarch64":
        platform = os + "-arm64"
    else:
        fail("Unsupported architecture: '" + os_arch + "'")

    if platform not in BINARIES:
        fail("Unsupported platform: '" + platform + "'")

    bin = BINARIES[platform]

    repository_ctx.report_progress("Fetching rosetta-cli")
    repository_ctx.download_and_extract(url = bin["url"], sha256 = bin["sha256"])
    repository_ctx.symlink("rosetta-cli-0.10.3-" + platform, "rosetta-cli")
    repository_ctx.file("BUILD.bazel", ROSETTA_CLI_BUILD, executable = False)

_rosetta_cli = repository_rule(
    implementation = _rosetta_cli_impl,
    attrs = {},
)

def rosetta_cli_repository(name):
    _rosetta_cli(name = name)
