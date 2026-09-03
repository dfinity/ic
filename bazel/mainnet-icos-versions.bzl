"""Mainnet version definitions.

This creates a Bazel repository which exports 'mainnet_icos_versions'. This macro can be
called to create one Bazel repository for the entire mainnet ICOS versions list.
"""

load("//bazel:mainnet-artifact-refs.bzl", "check", "icos_record_error")

def _validate(json_path, versions):
    """Validates every record of the mainnet ICOS revisions JSON.

    This is the choke point for the MAINNET_* dicts generated below: besides the
    download URLs built from them by //bazel:mainnet-icos-images.bzl, they end up in
    the `ENV_DEPS__*_IMG_URL` and `ENV_DEPS__*_IMG_HASH` env vars of system tests (see
    rs/tests/configure_icos.bzl), which the Farm backend uses to fetch and verify
    images itself -- a path that never passes through repository_ctx.download. The
    JSON reaches master without human review, so none of it is trusted input.

    Args:
      json_path: the label of the JSON file, for error messages.
      versions: the decoded JSON.
    """
    if type(versions) != "dict":
        fail("%s: expected a JSON object, got %r" % (json_path, versions))
    for variant in sorted(versions.keys()):
        records = versions[variant]
        if type(records) != "dict":
            fail("%s: %s: expected a JSON object, got %r" % (json_path, variant, records))
        for key in sorted(records.keys()):
            record = records[key]

            # "subnets" holds one record per subnet id, everything else (e.g.
            # "latest_release") is a record itself.
            if key == "subnets":
                if type(record) != "dict":
                    fail("%s: %s/subnets: expected a JSON object, got %r" % (json_path, variant, record))
                for subnet in sorted(record.keys()):
                    check(icos_record_error(record[subnet]), "%s: %s/subnets/%s" % (json_path, variant, subnet))
            else:
                check(icos_record_error(record), "%s: %s/%s" % (json_path, variant, key))

def _mainnet_icos_versions_impl(repository_ctx):
    # The path to the mainnet icos info
    json_path = repository_ctx.attr.path
    repository_ctx.watch(json_path)  # recreate the repo if the data changes

    # Read and decode mainnet version data
    versions = json.decode(repository_ctx.read(json_path))

    _validate(json_path, versions)

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
