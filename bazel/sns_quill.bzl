"""
The module fetches the sns-quill binary from the dfinity/sns-quill repository
"""

SNS_QUILL_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["sns-quill"])
"""

VERSION = "0.4.0"
SHA256 = {
    "linux": "9add78732579525a4793dcc39955ab83b89166d66fda7a45422ecdfdef996485",
    "macos": "dfa3a0496a968440904bc9b0711aaac6497aa4c294191fe5d41c4c3495eb9da7",
}

URL = "https://github.com/dfinity/sns-quill/releases/download/v{version}/sns-quill-{platform}-{arch}"

def _sns_quill_impl(repository_ctx):
    os_arch = repository_ctx.os.arch

    # even if the macOS version is "x86_64" it runs on ARM chips because of
    # emulation
    if os_arch == "x86_64" or os_arch == "amd64" or os_arch == "aarch64":
        arch = "x86_64"
    else:
        fail("Unsupported architecture: '" + os_arch + "'")

    os_name = repository_ctx.os.name
    if os_name == "linux":
        platform = "linux"
    elif os_name == "mac os x":
        platform = "macos"
    else:
        fail("Unsupported operating system: " + os_name)

    if platform not in SHA256:
        fail("Unsupported platform: '" + platform + "'")

    repository_ctx.report_progress("Fetching " + repository_ctx.name)
    repository_ctx.download(
        url = URL.format(version = VERSION, platform = platform, arch = arch),
        sha256 = SHA256[platform],
        executable = True,
        output = "sns-quill",
    )
    repository_ctx.file("BUILD.bazel", SNS_QUILL_BUILD, executable = True)

_sns_quill = repository_rule(
    implementation = _sns_quill_impl,
    attrs = {},
)

def sns_quill(name):
    _sns_quill(name = name)
