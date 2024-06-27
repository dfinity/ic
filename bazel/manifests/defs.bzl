
"""
TODO
"""

def _impl(repository_ctx):
    contents = repository_ctx.read(repository_ctx.workspace_root.get_child("Cargo.toml"))

    repository_ctx.report_progress("Fetching manifests")
    [_, contents] = contents.split("members = [\n")
    [contents,_] = contents.split("]",1)
    packages = contents.splitlines()

    def package_to_label(package):
        [_, rest] = package.split("\"", 1)
        [rest, _] = rest.split("\"", 1)
        return "\"//" + rest + ":Cargo.toml\","

    labels = [package_to_label(p) for p in packages]
    value = "".join(labels)
    repository_ctx.file("BUILD.bazel", content = "\n", executable = False)
    repository_ctx.file("defs.bzl", """
MANIFESTS = [ {value} ]
""".format(value = value), executable = False)

_manifests = repository_rule(
    implementation = _impl,
    attrs = {},
)

def manifests_repository(name):
    _manifests(name = name)
