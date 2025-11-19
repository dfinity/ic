"""
Rules to manipulate with artifacts: download, upload etc.
"""

def _upload_artifact_impl(ctx):
    """
    Uploads artifacts to s3.

    Will upload bundles passed a `inputs` as well as any other bundle paths specified on
    the command line.
    """

    version_file = ctx.file._version_txt
    rclone = ctx.file._rclone

    uploader = ctx.file._artifacts_uploader
    exe = ctx.actions.declare_file("run-upload-" + ctx.attr.name)
    cmds = ["$UPLOADER " + bundle.short_path for bundle in ctx.files.inputs]
    ctx.actions.write(
        output = exe,
        content = """
        #!/usr/bin/env bash

        set -euo pipefail

        UPLOADER={uploader}
        VERSION_FILE={version_file}
        export RCLONE={rclone}
        export VERSION=$(cat $VERSION_FILE)

        # upload any artifacts specified on the command line
        while [[ $# -gt 0 ]]
        do
            p=$(cd "$BUILD_WORKSPACE_DIRECTORY"; realpath "$1")
            shift
            $UPLOADER "$p"
        done

        # upload any artifacts baked into the uploader (for local bazel targets)
        {cmds}

        """.format(uploader = uploader.path, cmds = "\n".join(cmds), version_file = version_file.short_path, rclone = rclone.short_path),
        is_executable = True,
    )

    deps = depset(ctx.files.inputs + [version_file, rclone])
    runfiles = ctx.runfiles(files = [uploader, version_file, rclone] + ctx.files.inputs)

    return [
        DefaultInfo(executable = exe, files = deps, runfiles = runfiles),
    ]

_upload_artifacts = rule(
    implementation = _upload_artifact_impl,
    executable = True,
    attrs = {
        "inputs": attr.label_list(allow_files = True, default = []),
        "_rclone": attr.label(allow_single_file = True, default = "@//:rclone"),
        "_artifacts_uploader": attr.label(allow_single_file = True, default = ":upload.sh"),
        "_version_txt": attr.label(allow_single_file = True, default = "//bazel:version.txt"),
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

    _upload_artifacts(**kwargs)
