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
        filesum = ctx.actions.declare_file(ctx.label.name + "/" + f.basename + ".SHA256SUM")
        ctx.actions.run_shell(
            command = "(cd {path} && shasum --algorithm 256 --binary {src}) > {out}".format(path = f.dirname, src = f.basename, out = filesum.path),
            inputs = [f],
            outputs = [filesum],
        )
        out.append(filesum)

    checksum = ctx.actions.declare_file(ctx.label.name + "/SHA256SUMS")
    ctx.actions.run_shell(
        command = "cat " + " ".join([f.path for f in out]) + " | sort -k 2 >" + checksum.path,
        inputs = out,
        outputs = [checksum],
    )

    uploader = ctx.file._artifacts_uploader

    # If s3 upload is not enabled, then use a noop uploader.
    if not s3_upload:
        uploader = ctx.actions.declare_file("dummy_upload.sh")
        ctx.actions.write(uploader, "#!/usr/bin/env bash\necho dummy upload for $1\ntouch $2", is_executable = True)

    allinputs = ctx.files.inputs + [checksum]
    for f in allinputs:
        filename = ctx.label.name + "_" + f.basename
        url = ctx.actions.declare_file(filename + ".url")
        ctx.actions.run(
            executable = uploader,
            arguments = [f.path, url.path],
            env = {
                "RCLONE": ctx.file._rclone.path,
                "REMOTE_SUBDIR": ctx.attr.remote_subdir,
                "VERSION_FILE": ctx.version_file.path,
                "VERSION_TXT": ctx.file._version_txt.path,
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
        "remote_subdir": attr.string(mandatory = True),
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
