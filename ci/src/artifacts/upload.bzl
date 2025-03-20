"""
Macro to upload artifacts.
"""

load("//publish:defs.bzl", "checksum_rule")

# TODO: re-upload SHA256SUMS

# To avoid shooting ourselves in the foot, make sure that the upload rule invoker
# states explicitly whether it expects statically linked openssl.
def upload_artifacts(name, inputs, remote_subdir, visibility = ["//visibility:public"], testonly = ""):
    """
    Uploads artifacts to the S3 storage.

    Args:
      **kwargs: TODO
    """

    checksum_name = name + "_checksums"
    checksum_rule(
        name = checksum_name,
        inputs = inputs,
        create_symlinks = True,
        archives_only = False,
    )

    checksum_label = ":" + checksum_name

    input_locations = "$(execpaths {})".format(checksum_label)

    native.sh_binary(
        name = name,
        testonly = True,  # TODO
        srcs = ["//ci/src/artifacts:upload.sh"],
        env = {
            "RCLONE": "$(location @rclone//:rclone)",
            "UPLOADABLES": input_locations,
            "VERSION_TXT": "$(location //bazel:version.txt)",
            "REMOTE_SUBDIR": remote_subdir,
        },
        data = [checksum_label] + ["//bazel:version.txt", "@rclone//:rclone"],
        visibility = visibility,
    )
