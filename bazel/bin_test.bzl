"""
Rules to run any binary as a test.
"""

def _bin_test_impl(ctx):
    """
    Run an executable as a test.
    """
    out = ctx.actions.declare_file(ctx.label.name)

    # `executable` provided by an executable rule should be created by the same rule.
    ctx.actions.run(
        inputs = [ctx.executable.src],
        outputs = [out],
        executable = "cp",
        arguments = [ctx.executable.src.path, out.path],
    )
    return [DefaultInfo(executable = out)]

bin_test = rule(
    implementation = _bin_test_impl,
    test = True,
    attrs = {
        "src": attr.label(executable = True, cfg = "exec"),
    },
)
