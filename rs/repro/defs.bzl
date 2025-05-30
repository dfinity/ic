"""
Collect dependencies on tool and deps under a single action.
"""

def _wrapper_impl(ctx):
    script_file = ctx.actions.declare_file(ctx.label.name + "/script.sh")
    output_file = ctx.actions.declare_file(ctx.label.name + "/output")

    ctx.actions.write(
        output = script_file,
        is_executable = True,
        content = """echo "Hello world!" > {out}""".format(out = output_file.path),
    )

    ctx.actions.run(
        executable = script_file,
        outputs = [output_file],
        inputs = ctx.files.deps,
        tools = [ctx.attr.tool.files_to_run],
    )

    return [DefaultInfo(files = depset([output_file]))]

wrapper = rule(
    implementation = _wrapper_impl,
    attrs = {
        "deps": attr.label_list(
            allow_files = True,
        ),
        "tool": attr.label(
            executable = True,
            cfg = "exec",
        ),
    },
)
