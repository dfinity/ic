"""Exposes environmental variable `DFINITY_OPENSSL_STATIC` to packages."""

def _impl(repository_ctx):
    repository_ctx.file(
        "BUILD.bazel",
        content = "\n",
        executable = False,
    )
    repository_ctx.file(
        "defs.bzl",
        content = "DFINITY_OPENSSL_STATIC=" + repository_ctx.os.environ.get("DFINITY_OPENSSL_STATIC", "0") + "\n",
        executable = False,
    )

def openssl_static_env(name = None):
    rule = repository_rule(
        implementation = _impl,
        local = True,
        environ = ["DFINITY_OPENSSL_STATIC"],
    )
    rule(name = name)
