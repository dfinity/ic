"""
A repository rule that creates a repo exporting the list of all Cargo manifests
(though not including the top-level one) as MANIFESTS
"""

# https://github.com/bazelbuild/rules_rust/issues/2724
def _impl(repository_ctx):
    # Assume a Cargo.toml in the root
    contents = repository_ctx.read(repository_ctx.workspace_root.get_child("Cargo.toml"))

    repository_ctx.report_progress("Fetching manifests")

    # Read the Cargo.toml's `members`; does this by reading
    # all lines between 'members = [' and the closing ']'
    [_, contents] = contents.split("members = [\n")
    [contents, _] = contents.split("]", 1)
    packages = contents.splitlines()

    # turn the manifest path into a Bazel label
    def package_to_label(package):
        [_, rest] = package.split("\"", 1)
        [rest, _] = rest.split("\"", 1)
        return "\"//" + rest + ":Cargo.toml\","

    labels = [package_to_label(p) for p in packages]
    manifests = "".join(labels)
    repository_ctx.file("BUILD.bazel", content = "\n", executable = False)
    repository_ctx.file("defs.bzl", "MANIFESTS = [ {manifests} ]\n".format(manifests = manifests), executable = False)

_manifests = repository_rule(
    implementation = _impl,
    attrs = {},
)

def manifests_repository(name):
    _manifests(name = name)
