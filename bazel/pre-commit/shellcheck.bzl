"""
The module fetches shellcheck binary to be used by bazel smoke test
"""

SHELLCHECK_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["shellcheck"])
"""

VERSION = "0.9.0"

SHA256 = {
    "darwin.x86_64": "7d3730694707605d6e60cec4efcb79a0632d61babc035aa16cda1b897536acf5",
    "linux.x86_64": "700324c6dd0ebea0117591c6cc9d7350d9c7c5c287acbad7630fa17b1d4d9e2f",
}

URL = "https://github.com/koalaman/shellcheck/releases/download/v{version}/shellcheck-v{version}.{platform}.tar.xz"
ARCHIVE_OUTPUT = "shellcheck-v{version}/shellcheck"

def _shellcheck_impl(repository_ctx):
    os_arch = repository_ctx.os.arch

    if os_arch == "x86_64" or os_arch == "amd64":
        arch = "x86_64"
    else:
        fail("Unsupported architecture: '" + os_arch + "'")

    os_name = repository_ctx.os.name
    if os_name == "linux":
        platform = "linux." + arch
    elif os_name == "mac os x":
        platform = "darwin." + arch

    else:
        fail("Unsupported operating system: " + os_name)

    if platform not in SHA256:
        fail("Unsupported platform: '" + platform + "'")

    repository_ctx.report_progress("Fetching " + repository_ctx.name)
    repository_ctx.download_and_extract(url = URL.format(version = VERSION, platform = platform), sha256 = SHA256[platform])
    repository_ctx.symlink(ARCHIVE_OUTPUT.format(version = VERSION), "shellcheck")
    repository_ctx.file("BUILD.bazel", SHELLCHECK_BUILD, executable = True)

_shellcheck = repository_rule(
    implementation = _shellcheck_impl,
    attrs = {},
)

def shellcheck(name):
    _shellcheck(name = name)
