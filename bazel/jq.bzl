"""
The module fetches jq binary
"""

JQ_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["jq"])
"""

VERSION = "jq-1.6"
SHA256 = {
    "osx-amd64": "5c0a0a3ea600f302ee458b30317425dd9632d1ad8882259fcaf4e9b868b2b1ef",
    "linux64": "af986793a515d500ab2d35f8d2aecd656e764504b789b66d7e1a0b727a124c44",
}
URL = "https://github.com/stedolan/jq/releases/download/{version}/jq-{platform}"

def _jq_impl(repository_ctx):
    os_name = repository_ctx.os.name
    if os_name == "linux":
        platform = "linux64"
    elif os_name == "mac os x":
        platform = "osx-amd64"
    else:
        fail("Unsupported operating system: " + os_name)

    if platform not in SHA256:
        fail("Unsupported platform: '" + platform + "'")

    repository_ctx.report_progress("Fetching " + repository_ctx.name)
    repository_ctx.download(url = URL.format(version = VERSION, platform = platform), output = "jq", sha256 = SHA256[platform], executable = True)
    repository_ctx.file("BUILD.bazel", JQ_BUILD, executable = False)

_jq = repository_rule(
    implementation = _jq_impl,
    attrs = {},
)

def jq_repository(name):
    _jq(name = name)
