"""
The module fetches ormolu binary to be used by bazel smoke test
"""

ORMOLU_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["ormolu"])
"""

VERSION = "0.5.3.0"
SHA256 = {
    "Linux": "1681b3ab0acfbf70978108ca99f3498e6d42624128e818e4491f64ac9aaefaf0",
    "macOS": "5b119ad731c91356095a4b56094a4ecfd3a958bfbc0d2240814eea45430ce157",
}

URL = "https://github.com/tweag/ormolu/releases/download/{version}/ormolu-{platform}.zip"

def _ormolu_impl(repository_ctx):
    os_arch = repository_ctx.os.arch

    # even if the macOS version is "x86_64" it runs on ARM chips because of
    # emulation
    if os_arch == "x86_64" or os_arch == "amd64" or os_arch == "aarch64":
        pass
    else:
        fail("Unsupported architecture: '" + os_arch + "'")

    os_name = repository_ctx.os.name
    if os_name == "linux":
        platform = "Linux"
    elif os_name == "mac os x":
        platform = "macOS"
    else:
        fail("Unsupported operating system: " + os_name)

    if platform not in SHA256:
        fail("Unsupported platform: '" + platform + "'")

    repository_ctx.report_progress("Fetching " + repository_ctx.name)
    repository_ctx.download_and_extract(url = URL.format(version = VERSION, platform = platform), sha256 = SHA256[platform])
    repository_ctx.file("BUILD.bazel", ORMOLU_BUILD, executable = True)

_ormolu = repository_rule(
    implementation = _ormolu_impl,
    attrs = {},
)

def ormolu(name):
    _ormolu(name = name)
