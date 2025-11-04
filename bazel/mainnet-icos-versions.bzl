"""Mainnet version definitions.

This creates a Bazel repository which exports 'mainnet_icos_versions'. This macro can be
called to create one Bazel repository for the entire mainnet ICOS versions list.
"""

def _mainnet_icos_versions_impl(repository_ctx):
    # The path to the mainnet icos info
    json_path = repository_ctx.attr.path
    repository_ctx.watch(json_path)  # recreate the repo if the data changes

    # Read and decode mainnet version data
    versions = json.decode(repository_ctx.read(json_path))

    # Create a minimal BUILD.bazel file (Bazel requires it)
    repository_ctx.file("BUILD.bazel", content = "\n")

    content = "mainnet_icos_versions = %s\n" % versions + """\

MAINNET_LATEST = {
    "version": mainnet_icos_versions["guestos"]["latest_release"]["version"],
    "hash": mainnet_icos_versions["guestos"]["latest_release"]["update_img_hash"],
    "dev_hash": mainnet_icos_versions["guestos"]["latest_release"]["update_img_hash_dev"],
    "launch_measurements": mainnet_icos_versions["guestos"]["latest_release"]["launch_measurements"],
    "dev_launch_measurements": mainnet_icos_versions["guestos"]["latest_release"]["launch_measurements_dev"],
}
MAINNET_NNS = {
    "version": mainnet_icos_versions["guestos"]["subnets"]["tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"]["version"],
    "hash": mainnet_icos_versions["guestos"]["subnets"]["tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"]["update_img_hash"],
    "dev_hash": mainnet_icos_versions["guestos"]["subnets"]["tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"]["update_img_hash_dev"],
    "launch_measurements": mainnet_icos_versions["guestos"]["subnets"]["tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"]["launch_measurements"],
    "dev_launch_measurements": mainnet_icos_versions["guestos"]["subnets"]["tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"]["launch_measurements_dev"],
}
MAINNET_APP = {
    "version": mainnet_icos_versions["guestos"]["subnets"]["io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"]["version"],
    "hash": mainnet_icos_versions["guestos"]["subnets"]["io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"]["update_img_hash"],
    "dev_hash": mainnet_icos_versions["guestos"]["subnets"]["io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"]["update_img_hash_dev"],
    "launch_measurements": mainnet_icos_versions["guestos"]["subnets"]["io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"]["launch_measurements"],
    "dev_launch_measurements": mainnet_icos_versions["guestos"]["subnets"]["io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe"]["launch_measurements_dev"],
}
MAINNET_LATEST_HOSTOS = {
    "version": mainnet_icos_versions["hostos"]["latest_release"]["version"],
    "hash": mainnet_icos_versions["hostos"]["latest_release"]["update_img_hash"],
    "dev_hash": mainnet_icos_versions["hostos"]["latest_release"]["update_img_hash_dev"],
    "launch_measurements": mainnet_icos_versions["hostos"]["latest_release"]["launch_measurements"],
    "dev_launch_measurements": mainnet_icos_versions["hostos"]["latest_release"]["launch_measurements_dev"],
}
"""

    repository_ctx.file("defs.bzl", content = content)

mainnet_icos_versions = repository_rule(
    implementation = _mainnet_icos_versions_impl,
    attrs = {
        "path": attr.label(mandatory = True, doc = "path to mainnet ICOS versions data"),
    },
)
