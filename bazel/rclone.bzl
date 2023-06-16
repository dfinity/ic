"""
The module fetches rclone binary to be used by upload_artifacts
"""

RCLONE_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["rclone"])
"""

VERSION = "v1.62.2"
SHA256 = {
    "osx-amd64": "afef35513c7ce89e9ed9962e2c44c604587de1faa317d9fd3bf6590dc3be8658",
    "linux-amd64": "6c8676dc56e3d2e26358b5bae616ab3ec95e26181cd9b8692e101dcc0fc966a1",
}
URL = "https://github.com/rclone/rclone/releases/download/{version}/rclone-{version}-{platform}.zip"

def _rclone_impl(repository_ctx):
    os_arch = repository_ctx.os.arch
    if os_arch == "x86_64":
        arch = "amd64"
    elif os_arch == "amd64":
        arch = "amd64"
    elif os_arch == "aarch64":
        arch = "arm64"
    else:
        fail("Unsupported architecture: '" + os_arch + "'")

    os_name = repository_ctx.os.name
    if os_name == "linux":
        platform = "linux-" + arch
    elif os_name == "mac os x":
        # No arm64 build for this version, use amd64 for now.
        platform = "osx-amd64"
    else:
        fail("Unsupported operating system: " + os_name)

    if platform not in SHA256:
        fail("Unsupported platform: '" + platform + "'")

    repository_ctx.report_progress("Fetching " + repository_ctx.name)
    repository_ctx.download_and_extract(url = URL.format(version = VERSION, platform = platform), sha256 = SHA256[platform], stripPrefix = "rclone-{version}-{platform}".format(version = VERSION, platform = platform))
    repository_ctx.file("BUILD.bazel", RCLONE_BUILD, executable = False)

_rclone = repository_rule(
    implementation = _rclone_impl,
    attrs = {},
)

def rclone_repository(name):
    _rclone(name = name)
