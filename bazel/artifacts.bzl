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
    out = ctx.actions.declare_file(ctx.label.name + ".url")

    ctx.actions.expand_template(
        template = ctx.file._artifacts_uploader_template,
        output = uploader,
        substitutions = {
            "@@BIN_DIR@@": ctx.bin_dir.path,
            "@@RCLONE_UPLOAD@@": ctx.executable._rclone_upload.path,
            "@@RCLONE_CONFIG@@": ctx.file.rclone_config.path,
            "@@REMOTE_SUBDIR@@": ctx.attr.remote_subdir,
            "@@VERSION_FILE@@": ctx.version_file.path,
            "@@URLS_OUTPUT@@": out.path,
        },
        is_executable = True,
    )

    ctx.actions.run(
        executable = uploader,
        arguments = [ctx.file.input.short_path],
        tools = [ctx.executable._rclone_upload],
        inputs = [ctx.file.input, ctx.version_file],
        outputs = [out],
    )

    return [DefaultInfo(files = depset([out]))]

_upload_artifact = rule(
    implementation = _upload_artifact_impl,
    attrs = {
        "input": attr.label(allow_single_file = True),
        "remote_subdir": attr.string(mandatory = True),
        "rclone_config": attr.label(allow_single_file = True, default = "//:.rclone.conf"),
        "_rclone_upload": attr.label(executable = True, cfg = "exec", default = "//gitlab-ci/src/artifacts:rclone_upload"),
        "_artifacts_uploader_template": attr.label(allow_single_file = True, default = "//bazel:artifacts_uploader.bash.template"),
    },
)

def upload_artifact(**kwargs):
    """
    Uploads an artifact to the S3 storage.

    Wrapper around _upload_artifact to always set "requires-network" and "manual" tags.

    Args:
      **kwargs: all arguments to pass to _upload_artifacts
    """

    tags = kwargs.get("tags", [])
    for tag in ["requires-network", "manual"]:
        if tag not in tags:
            tags.append(tag)
    kwargs["tags"] = tags
    _upload_artifact(**kwargs)

def upload_artifacts(name, inputs, **kwargs):
    """
    Uploads multiple artifacts to the S3 storage.

    Args:
      name: Name of the rule
      inputs: list of artifact targets to upload
      **kwargs: arguments to pass to upload_artifact
    """
    labels = []
    for input in inputs:
        input_name = name + input.replace(":", "_")
        labels.append(":" + input_name)
        upload_artifact(
            name = input_name,
            input = input,
            **kwargs
        )

    native.genrule(
        name = name,
        srcs = labels,
        outs = [name + ".urls"],
        cmd = "cat $(SRCS) > $(OUTS)",
        tags = kwargs.get("tags", []) + ["manual"],
    )

def urls_test(name, inputs, tags = ["system_test"]):
    # https://github.com/bazelbuild/bazel/issues/6783S
    native.sh_library(
        name = name + "_wrapped",
        data = inputs,
        tags = tags + ["manual"],
    )
    native.sh_test(
        name = name,
        tags = tags,
        srcs = ["//bazel:urls_test.sh"],
        args = ["$(rootpath :{})".format(name + "_wrapped")],
        data = [":" + name + "_wrapped"],
    )
