"""
Macro to upload artifacts.
"""

load("//publish:defs.bzl", "checksum_rule")

# To avoid shooting ourselves in the foot, make sure that the upload rule invoker
# states explicitly whether it expects statically linked openssl.
def upload_artifacts(name, inputs, remote_subdir, **kwargs):
    """
    Uploads artifacts to the S3 storage.

    Args:
      name: the name of the resulting executable.
      inputs: the inputs to upload (will include an extra checksum file 'SHA256SUMS').
      remote_subdir: the bucket "subdirectory" to use.
      **kwargs: additional arguments to pass to the rules.
    """

    # Compute a checksum file for the inputs
    checksum_name = name + "_checksums"
    checksum_rule(
        name = checksum_name,
        inputs = inputs,
        create_symlinks = False,  # don't copy inputs
        archives_only = False,  # consider all targets
        **kwargs
    )
    checksum_label = ":" + checksum_name

    ipts = [checksum_label] + inputs
    input_locations = ["$(execpaths {})".format(label) for label in ipts]

    tags = kwargs.pop("tags", [])
    tags.append("upload")

    # run the upload script
    native.sh_binary(
        name = name,
        srcs = ["//ci/src/artifacts:upload.sh"],
        env = {
            "RCLONE": "$(location @rclone//:rclone)",
            "UPLOADABLES": " ".join(input_locations),
            "VERSION_TXT": "$(location //bazel:version.txt)",
            "REMOTE_SUBDIR": remote_subdir,
        },
        data = ipts + ["//bazel:version.txt", "@rclone//:rclone"],
        tags = tags,
        **kwargs
    )
