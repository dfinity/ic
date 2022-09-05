"""
This module defines rules allowing scoped changes in compilation settings.
For example, you might want to build some targets with optimizations enabled
no matter what the current Bazel flags are.
"""

def _opt_debug_transition(_settings, _attr):
    return {
        "//command_line_option:compilation_mode": "opt",
        "//command_line_option:strip": "never",
    }

opt_debug_transition = transition(
    implementation = _opt_debug_transition,
    inputs = [],
    outputs = [
        "//command_line_option:compilation_mode",
        "//command_line_option:strip",
    ],
)

def _opt_debug_impl(ctx):
    bin = ctx.attr.binary[0]
    info = bin[DefaultInfo]

    executable = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(output = executable, target_file = ctx.file.binary)

    return [
        DefaultInfo(files = info.files, runfiles = info.default_runfiles, executable = executable),
    ]

opt_debug_binary = rule(
    implementation = _opt_debug_impl,
    executable = True,
    attrs = {
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
        "binary": attr.label(mandatory = True, cfg = opt_debug_transition, allow_single_file = True),
    },
)
