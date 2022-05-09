"""
buildifier_test test rule based on keith/buildifier-prebuilt that uses prebuild
buildifier binary instead of building it from source.
"""

def _buildifier_test_impl(ctx):
    runfiles = ctx.runfiles(files = ctx.files.workspace)
    runfiles = runfiles.merge(ctx.attr.buildifier.default_runfiles)

    ctx.actions.expand_template(
        template = ctx.file._buildifier_test_template,
        output = ctx.outputs.executable,
        substitutions = {
            "@@WORKSPACE@@": ctx.files.workspace[0].path,
            "@@BUILDIFIER_BIN@@": ctx.attr.buildifier.files_to_run.executable.short_path,
        },
        is_executable = True,
    )

    return DefaultInfo(
        executable = ctx.outputs.executable,
        runfiles = runfiles,
    )

buildifier_test = rule(
    implementation = _buildifier_test_impl,
    test = True,
    attrs = {
        "buildifier": attr.label(default = "//:buildifier.check"),
        "_buildifier_test_template": attr.label(default = "//bazel:buildifier_test.bash.template", allow_single_file = True),
        "workspace": attr.label(allow_files = True, default = "//:WORKSPACE.bazel"),
    },
)
