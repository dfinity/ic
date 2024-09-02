"""
Rules to return various information about the workspace, current invocation etc.
"""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

FAKE_IC_VERSION = "0000000000000000000000000000000000000000"

def _ic_version_or_git_sha_impl(ctx):
    """
    Returns the file that contains IC version.

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
        inputs = [ctx.version_file] + ctx.files._bazel_timestamp,
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
        "_bazel_timestamp": attr.label(default = "//:bazel-timestamp"),
    },
)

def _version_file_path_impl(ctx):
    """
    Returns the file containing the full path to the volatile status file.

    It can be used to read the volatile status directly, not as a bazel dependency.
    Bazel don't track direct reads and therefore changing volatile status file will not invalidate the cache.
    Documentation says "Bazel pretends that the volatile file never changes": https://bazel.build/docs/user-manual#workspace-status
    However this behaviour is only limited to the local cache: https://github.com/bazelbuild/bazel/issues/10075
    """
    out = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.run(
        executable = "awk",
        arguments = ["-v", "out=" + out.path, '/^VERSION_FILE_PATH / { printf "%s", $2 > out }', ctx.version_file.path],
        inputs = [ctx.version_file],
        outputs = [out],
    )
    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles(files = [out]))]

version_file_path = rule(
    implementation = _version_file_path_impl,
)
