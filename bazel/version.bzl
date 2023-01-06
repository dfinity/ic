"""
Rules to return ic version.
"""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

def _ic_version_or_git_sha_impl(ctx):
    """
    Returns the file that contatins IC version.

    IC version is:
    * the value -f `--ic_version` flag if set
    * <git sha> if the working tree is clean
    * <git-sha>-<timestamp> if the working tree contains modifications.

    ctx.version_file contains the information written by workspace_status_command.
    Bazel treats this file as never changing  - the rule only rebuilds when other dependencies change.
    Details are on https://bazel.build/docs/user-manual#workspace-status.
    """
    out = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.run(
        executable = ctx.executable._ic_version_or_git_sha_sh,
        arguments = [ctx.version_file.path, out.path],
        inputs = [ctx.version_file],
        outputs = [out],
        env = {
            "VERSION": ctx.attr.ic_version[BuildSettingInfo].value,
        },
    )
    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles(files = [out]))]

ic_version_or_git_sha = rule(
    implementation = _ic_version_or_git_sha_impl,
    attrs = {
        "ic_version": attr.label(default = ":ic_version"),
        "_ic_version_or_git_sha_sh": attr.label(executable = True, cfg = "exec", default = ":ic_version_or_git_sha_sh"),
    },
)
