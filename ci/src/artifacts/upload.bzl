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

    checksum_name = name + "_checksums"
    checksum_rule(
        name = checksum_name,
        inputs = inputs,
        create_symlinks = False,
        archives_only = False,
        **kwargs
    )
    checksum_label = ":" + checksum_name

    ipts = [checksum_label] + inputs
    input_locations = ["$(execpaths {})".format(label) for label in ipts]

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
        **kwargs
    )
