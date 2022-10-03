"""
Rules to manipulate with artifacts: download, upload etc.
"""

def _upload_artifact_impl(ctx):
    """
    Uploads an artifact to s3 and returns download link to it

    ctx.version_file contains the information written by workspace_status_command.
    Bazel treats this file as never changing  - the rule only rebuilds when other dependencies change.
    Details are on https://bazel.build/docs/user-manual#workspace-status.
    """

    uploader = ctx.actions.declare_file(ctx.label.name + "_uploader")

    ctx.actions.expand_template(
        template = ctx.file._artifacts_uploader_template,
        output = uploader,
        substitutions = {
            "@@RCLONE@@": ctx.file._rclone.path,
            "@@RCLONE_CONFIG@@": ctx.file.rclone_config.path,
            "@@REMOTE_SUBDIR@@": ctx.attr.remote_subdir,
            "@@VERSION_FILE@@": ctx.version_file.path,
        },
        is_executable = True,
    )

    out = []
    for f in ctx.files.inputs:
        url = ctx.actions.declare_file(ctx.label.name + "_" + f.basename + ".url")
        ctx.actions.run(
            executable = uploader,
            arguments = [f.path, url.path],
            inputs = [f, ctx.version_file, ctx.file.rclone_config],
            outputs = [url],
            tools = [ctx.file._rclone],
            use_default_shell_env = True,
        )
        out.append(url)

    urls = ctx.actions.declare_file(ctx.label.name + ".urls")
    ctx.actions.run_shell(
        command = "cat " + " ".join([url.path for url in out]) + " >" + urls.path,
        inputs = out,
        outputs = [urls],
    )
    out.append(urls)

    return [DefaultInfo(files = depset(out), runfiles = ctx.runfiles(files = out))]

_upload_artifacts = rule(
    implementation = _upload_artifact_impl,
    attrs = {
        "inputs": attr.label_list(allow_files = True),
        "remote_subdir": attr.string(mandatory = True),
        "rclone_config": attr.label(allow_single_file = True, default = "//:.rclone.conf"),
        "_rclone": attr.label(allow_single_file = True, default = "@rclone//:rclone"),
        "_artifacts_uploader_template": attr.label(allow_single_file = True, default = ":upload.bash.template"),
    },
)

def upload_artifacts(**kwargs):
    """
    Uploads artifacts to the S3 storage.

    Wrapper around _upload_artifacts to always set required tags.

    Args:
      **kwargs: all arguments to pass to _upload_artifacts
    """

    tags = kwargs.get("tags", [])
    for tag in ["requires-network", "manual"]:
        if tag not in tags:
            tags.append(tag)
    kwargs["tags"] = tags
    _upload_artifacts(**kwargs)

def urls_test(name, inputs, tags = ["system_test"]):
    # https://github.com/bazelbuild/bazel/issues/6783S
    native.sh_library(
        name = name + "_wrapped",
        data = inputs,
        tags = tags + ["manual"],
    )
    native.sh_test(
        name = name,
        tags = tags + ["requires-network"],
        srcs = ["//gitlab-ci/src/artifacts:urls_test.sh"],
        args = ["$(rootpath :{})".format(name + "_wrapped")],
        data = [":" + name + "_wrapped"],
    )
