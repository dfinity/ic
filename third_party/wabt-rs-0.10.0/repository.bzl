"""
This module defines rules to fetch and build wabt-rs package.
"""

def _local(path):
    return Label("//third_party/wabt-rs-0.10.0:" + path)

def _wabt_rs_impl(repository_ctx):
    repository_ctx.download_and_extract(
        url = "https://github.com/dfinity-lab/wabt-rs/archive/7ab9062ddc63067843b62af8ae2cb83bf4bf601e.zip",
        sha256 = "f6081e4e068051205c782173b203762935032db806bada12a8ecf63e542fad09",
        stripPrefix = "wabt-rs-7ab9062ddc63067843b62af8ae2cb83bf4bf601e",
    )

    repository_ctx.patch(_local("CMakeLists.txt.patch"))
    repository_ctx.symlink(_local("BUILD.wabt.bazel"), "wabt-sys/wabt/BUILD.bazel")
    repository_ctx.symlink(_local("BUILD.wabt-sys.bazel"), "wabt-sys/BUILD.bazel")
    repository_ctx.symlink(_local("BUILD.wabt_rs.bazel"), "BUILD.bazel")

wabt_rs_repository = repository_rule(
    implementation = _wabt_rs_impl,
    attrs = {},
)
