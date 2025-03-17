"""
Macro to upload artifacts.
"""

# To avoid shooting ourselves in the foot, make sure that the upload rule invoker
# states explicitly whether it expects statically linked openssl.
def upload_artifacts(name, inputs, remote_subdir, visibility = ["//visibility:public"], testonly = ""):
    """
    Uploads artifacts to the S3 storage.

    Args:
      **kwargs: TODO
    """

    input_locations = [ "$(execpaths {})".format(ipt) for ipt in inputs ]

    native.sh_binary(
        name = name,
        testonly = True, # TODO
        srcs = [ "//ci/src/artifacts:upload.sh" ],
        env = {
            "RCLONE": "$(location @rclone//:rclone)",
            "UPLOADABLES": " ".join(input_locations),
            "VERSION_TXT": "$(location //bazel:version.txt)",
            "REMOTE_SUBDIR": remote_subdir,
        },
        data = inputs + ["//bazel:version.txt", "@rclone//:rclone"],
        visibility = visibility,
    )
