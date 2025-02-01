"""Create transition to disable hermetic_cc_toolchains for hs targets."""

def _disable_hermetic_cc_transition(_settings, _attr):
    return {
        "//bazel:hermetic_cc": False,
    }

disable_hermetic_cc_transition = transition(
    implementation = _disable_hermetic_cc_transition,
    inputs = [],
    outputs = [
        "//bazel:hermetic_cc",
    ],
)

def _disable_hermetic_cc_impl(ctx):
    bin = ctx.attr.binary[0]
    info = bin[DefaultInfo]

    executable = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(output = executable, target_file = ctx.file.binary)

    return [
        DefaultInfo(files = info.files, runfiles = info.default_runfiles, executable = executable),
    ]

disable_hermetic_cc_binary = rule(
    implementation = _disable_hermetic_cc_impl,
    executable = True,
    attrs = {
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
        "binary": attr.label(mandatory = True, cfg = disable_hermetic_cc_transition, allow_single_file = True),
    },
)
