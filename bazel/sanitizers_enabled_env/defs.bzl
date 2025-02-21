"""Exposes environmental variable `SANITIZERS_ENABLED` to packages."""

def _impl(repository_ctx):
    repository_ctx.file(
        "BUILD.bazel",
        content = "\n",
        executable = False,
    )
    repository_ctx.file(
        "defs.bzl",
        content = "SANITIZERS_ENABLED=" + repository_ctx.getenv("SANITIZERS_ENABLED", "0") + "\n",
        executable = False,
    )

def sanitizers_enabled_env(name = None):
    rule = repository_rule(
        implementation = _impl,
        local = True,
    )
    rule(name = name)
