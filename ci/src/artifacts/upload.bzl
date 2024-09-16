"""
Rules to manipulate with artifacts: download, upload etc.
"""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("//bazel:status.bzl", "FAKE_IC_VERSION")

def _upload_artifact_impl(ctx):
    """
    Uploads an artifact to s3 and returns download link to it
    """

    uploader = ctx.actions.declare_file(ctx.label.name + "_uploader")

    rclone_config = ctx.file.rclone_config
    rclone_endpoint = ctx.attr._s3_endpoint[BuildSettingInfo].value
    if rclone_endpoint != "":
        rclone_config = ctx.file.rclone_anon_config

    s3_upload = ctx.attr._s3_upload[BuildSettingInfo].value

    ctx.actions.expand_template(
        template = ctx.file._artifacts_uploader_template,
        output = uploader,
        substitutions = {
            "@@RCLONE@@": ctx.file._rclone.path,
            "@@RCLONE_CONFIG@@": rclone_config.path,
            "@@REMOTE_SUBDIR@@": ctx.attr.remote_subdir,
            "@@VERSION_FILE@@": ctx.version_file.path,
            "@@VERSION_TXT@@": ctx.file._version_txt.path,
            "@@FAKE_IC_VERSION@@": FAKE_IC_VERSION,
        },
        is_executable = True,
    )

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

    fileurl = []
    allinputs = ctx.files.inputs + [checksum] if s3_upload else [checksum]
    for f in allinputs:
        filename = ctx.label.name + "_" + f.basename
        url = ctx.actions.declare_file(filename + ".url")
        proxy_cache_url = ctx.actions.declare_file(filename + ".proxy-cache-url")
        ctx.actions.run(
            executable = uploader,
            arguments = [f.path, url.path, proxy_cache_url.path],
            env = {
                "RCLONE_S3_ENDPOINT": rclone_endpoint,
            },
            inputs = [f, ctx.version_file, rclone_config, ctx.file._version_txt],
            outputs = [url, proxy_cache_url],
            tools = [ctx.file._rclone],
        )
        fileurl.extend([url, proxy_cache_url])

    urls = ctx.actions.declare_file(ctx.label.name + ".urls")
    ctx.actions.run_shell(
        command = "cat " + " ".join([url.path for url in fileurl]) + " >" + urls.path,
        inputs = fileurl,
        outputs = [urls],
    )
    out.append(urls)
    out.extend(fileurl)

    executable = ctx.actions.declare_file(ctx.label.name + ".bin")
    ctx.actions.write(output = executable, content = "#!/bin/sh\necho;exec cat " + urls.short_path, is_executable = True)

    return [DefaultInfo(files = depset(out), runfiles = ctx.runfiles(files = out), executable = executable)]

_upload_artifacts = rule(
    implementation = _upload_artifact_impl,
    executable = True,
    attrs = {
        "inputs": attr.label_list(allow_files = True),
        "remote_subdir": attr.string(mandatory = True),
        "rclone_config": attr.label(allow_single_file = True, default = "//:.rclone.conf"),
        "rclone_anon_config": attr.label(allow_single_file = True, default = "//:.rclone-anon.conf"),
        "_rclone": attr.label(allow_single_file = True, default = "@rclone//:rclone"),
        "_artifacts_uploader_template": attr.label(allow_single_file = True, default = ":upload.bash.template"),
        "_version_txt": attr.label(allow_single_file = True, default = "//bazel:version.txt"),
        "_s3_endpoint": attr.label(default = ":s3_endpoint"),
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
    for tag in ["requires-network", "upload"]:
        if tag not in tags:
            tags.append(tag)
    kwargs["tags"] = tags
    _upload_artifacts(**kwargs)
