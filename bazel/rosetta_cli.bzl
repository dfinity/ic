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
        "url": "https://github.com/coinbase/rosetta-cli/releases/download/v0.6.7/rosetta-cli-0.6.7-darwin-amd64.tar.gz",
        "sha256": "5554227361d60f8b0d18b7e5d37a61d05767e106e4ecd21471abf94822cee810",
    },
    "linux-amd64": {
        "url": "https://github.com/coinbase/rosetta-cli/releases/download/v0.6.7/rosetta-cli-0.6.7-linux-amd64.tar.gz",
        "sha256": "111c6d4f08f04b3cce2fa075728b834de92c16dfaa8504e1bf81bc2adeb6645f",
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
    repository_ctx.symlink("rosetta-cli-0.6.7-" + platform, "rosetta-cli")
    repository_ctx.file("BUILD.bazel", ROSETTA_CLI_BUILD, executable = False)

_rosetta_cli = repository_rule(
    implementation = _rosetta_cli_impl,
    attrs = {},
)

def rosetta_cli_repository(name):
    _rosetta_cli(name = name)
