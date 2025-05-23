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

    version_file = ctx.file._version_txt

    uploader = ctx.file._artifacts_uploader
    exe = ctx.actions.declare_file("run-upload")
    cmds = ["{uploader} {bundle}".format(uploader = uploader.path, bundle = bundle.short_path) for bundle in ctx.files.inputs]
    ctx.actions.write(
        output = exe,
        content = """
        #!/usr/bin/env bash

        set -euo pipefail

        export DRY_RUN=1 # TODO: remove this
        VERSION_FILE={version_file}
        export VERSION=$(cat $VERSION_FILE)
        echo "$VERSION"
        {cmds}

        """.format(cmds = "\n".join(cmds), version_file = version_file.short_path),
        is_executable = True,
    )

    # TODO: check this
    deps = depset(ctx.files.inputs + [version_file])
    runfiles = ctx.runfiles(files = [uploader, version_file] + ctx.files.inputs)

    return [
        DefaultInfo(executable = exe, files = deps, runfiles = runfiles),
    ]

_upload_artifacts = rule(
    implementation = _upload_artifact_impl,
    executable = True,
    attrs = {
        "inputs": attr.label_list(allow_files = True),
        "_rclone": attr.label(allow_single_file = True, default = "@rclone//:rclone"),
        "_artifacts_uploader": attr.label(allow_single_file = True, default = ":upload.sh"),
        "_version_txt": attr.label(allow_single_file = True, default = "//bazel:version.txt"),
        "_s3_upload": attr.label(default = ":s3_upload"),  # TODO: remove this
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
    for tag in ["requires-network"]:  # TODO: remove this
        if tag not in tags:
            tags.append(tag)
    kwargs["tags"] = tags
    _upload_artifacts(**kwargs)
