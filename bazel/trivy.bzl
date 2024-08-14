"""
The module fetches trivy binary to be used by docker_vulnerabilities_scanning
"""

TRIVY_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["trivy"])
"""

VERSION = "0.35.0"
SHA256 = {
    "macOS-64bit": "165c501451ab91a486678107c34bfb7b0b9e117c8ed5bba746ebda31923d9330",
    "macOS-ARM64": "343fb01737e886bde797f30e5e6359fc1a7b7e1e9807f0e62ae3aea3f9508a1a",
    "Linux-64bit": "ebc1dd4d4c0594028d6a501dfc1a73d56add20b29d3dee5ab6e64aac94b1d526",
}

URL = "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_{platform}.tar.gz"

def _trivy_impl(repository_ctx):
    os_arch = repository_ctx.os.arch

    if os_arch == "x86_64" or os_arch == "amd64":
        arch = "64bit"
    elif os_arch == "aarch64":
        arch = "ARM64"
    else:
        fail("Unsupported architecture: '" + os_arch + "'")

    os_name = repository_ctx.os.name
    if os_name == "linux":
        platform = "Linux-" + arch
    elif os_name == "mac os x":
        platform = "macOS-" + arch
    else:
        fail("Unsupported operating system: " + os_name)

    if platform not in SHA256:
        fail("Unsupported platform: '" + platform + "'")

    repository_ctx.report_progress("Fetching " + repository_ctx.name)
    repository_ctx.download_and_extract(url = URL.format(version = VERSION, platform = platform), sha256 = SHA256[platform])
    repository_ctx.file("BUILD.bazel", TRIVY_BUILD, executable = False)

_trivy = repository_rule(
    implementation = _trivy_impl,
    attrs = {},
)

def trivy_scan(name):
    _trivy(name = name)
