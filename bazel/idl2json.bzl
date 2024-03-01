"""
The module fetches the idl2json binary from the dfinity/idl2json repository
"""

IDL2JSON_BUILD = """
package(default_visibility = ["//visibility:public"])
exports_files(["idl2json"])
"""

VERSION = "0.9.2"
SHA256 = {
    "unknown-linux-musl.tar.gz": "c91863c56f94bcafa70ca6aa5aa3d937324075afdd0c0c222f27b5d11372fcfb",
    "apple-darwin.zip": "c7356d96ae091a47e180631492d1c45462e85042dcc3a7b68da60722fc87edba",
}

URL = "https://github.com/dfinity/idl2json/releases/download/v{version}/idl2json_cli-{arch}-{file}"

def _idl_to_json_impl(repository_ctx):
    os_arch = repository_ctx.os.arch

    # even if the macOS version is "x86_64" it runs on ARM chips because of
    # emulation
    if os_arch == "x86_64" or os_arch == "amd64" or os_arch == "aarch64":
        arch = "x86_64"
    else:
        fail("Unsupported architecture: '" + os_arch + "'")

    os_name = repository_ctx.os.name
    if os_name == "linux":
        file = "unknown-linux-musl.tar.gz"
    elif os_name == "mac os x":
        file = "apple-darwin.zip"
    else:
        fail("Unsupported operating system: " + os_name)

    if file not in SHA256:
        fail("Unsupported file: '" + file + "'")

    repository_ctx.report_progress("Fetching " + repository_ctx.name)
    repository_ctx.download_and_extract(url = URL.format(version = VERSION, file = file, arch = arch), sha256 = SHA256[file])
    repository_ctx.file("BUILD.bazel", IDL2JSON_BUILD, executable = True)

_idl_to_json = repository_rule(
    implementation = _idl_to_json_impl,
    attrs = {},
)

def idl_to_json(name):
    _idl_to_json(name = name)
