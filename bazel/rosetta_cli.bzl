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
        "url": "https://github.com/coinbase/rosetta-cli/releases/download/v0.9.0/rosetta-cli-0.9.0-darwin-amd64.tar.gz",
        "sha256": "bab4d431112bdc4cdac30aad6ef9e63ab99553ffc44900b6655076bbc02ade79",
    },
    "darwin-arm64": {
        "url": "https://github.com/coinbase/rosetta-cli/releases/download/v0.9.0/rosetta-cli-0.9.0-darwin-arm64.tar.gz",
        "sha256": "1a9a02bd625c39bfa717ffecfdf28db9fd7b6905670c439f58662f08fd334247",
    },
    "linux-amd64": {
        "url": "https://github.com/coinbase/rosetta-cli/releases/download/v0.9.0/rosetta-cli-0.9.0-linux-amd64.tar.gz",
        "sha256": "13216a74244053e1ced2adf78bcbefadc36044248ef880dbf79547574b28eff0",
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
    repository_ctx.symlink("rosetta-cli-0.9.0-" + platform, "rosetta-cli")
    repository_ctx.file("BUILD.bazel", ROSETTA_CLI_BUILD, executable = False)

_rosetta_cli = repository_rule(
    implementation = _rosetta_cli_impl,
    attrs = {},
)

def rosetta_cli_repository(name):
    _rosetta_cli(name = name)
