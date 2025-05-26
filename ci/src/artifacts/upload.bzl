"""
Rules to manipulate with artifacts: download, upload etc.
"""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

def _upload_artifact_impl(ctx):
    """
    Uploads an artifact to s3 and returns download link to it
    """

    s3_upload = ctx.attr._s3_upload[BuildSettingInfo].value
    out = []

    for f in ctx.files.inputs:
        url = ctx.actions.declare_file("_" + f.path + ".urls")
        ctx.actions.run(
            executable = ctx.file._artifacts_uploader,
            arguments = [f.path, url.path],
            env = {
                "RCLONE": ctx.file._rclone.path,
                "VERSION_FILE": ctx.version_file.path,
                "VERSION_TXT": ctx.file._version_txt.path,
                "DRY_RUN": "1" if not s3_upload else "0",
            },
            inputs = [f, ctx.version_file, ctx.file._version_txt],
            outputs = [url],
            tools = [ctx.file._rclone],
        )
        out.append(url)

    return [DefaultInfo(files = depset(out), runfiles = ctx.runfiles(files = out))]

_upload_artifacts = rule(
    implementation = _upload_artifact_impl,
    attrs = {
        "inputs": attr.label_list(allow_files = True),
        "_rclone": attr.label(allow_single_file = True, default = "@rclone//:rclone"),
        "_artifacts_uploader": attr.label(allow_single_file = True, default = ":upload.sh"),
        "_version_txt": attr.label(allow_single_file = True, default = "//bazel:version.txt"),
        "_s3_upload": attr.label(default = ":s3_upload"),
    },
)

# To avoid shooting ourselves in the foot, make sure that the upload rule invoker
# states explicitly whether it expects statically linked openssl.
def upload_artifacts(**kwargs):
    """
    Uploads artifacts to the S3 storage.

    Wrapper around _upload_artifacts to always set required tags.

    Args:
      **kwargs: all arguments to pass to _upload_artifacts
    """

    tags = kwargs.get("tags", [])
    for tag in ["requires-network"]:
        if tag not in tags:
            tags.append(tag)
    kwargs["tags"] = tags
    _upload_artifacts(**kwargs)
