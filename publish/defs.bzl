"""
This module defines rules allowing scoped changes in compilation settings.
For example, you might want to build some targets with optimizations enabled
no matter what the current Bazel flags are.
"""

def _release_nostrip_transition(_settings, _attr):
    return {
        "//command_line_option:compilation_mode": "opt",
        "//command_line_option:strip": "never",
        "@rules_rust//:extra_rustc_flags": ["-Cdebug-assertions=off"],
    }

release_nostrip_transition = transition(
    implementation = _release_nostrip_transition,
    inputs = [],
    outputs = [
        "//command_line_option:compilation_mode",
        "//command_line_option:strip",
        "@rules_rust//:extra_rustc_flags",
    ],
)

def _release_nostrip_impl(ctx):
    bin = ctx.attr.binary[0]
    info = bin[DefaultInfo]

    executable = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(output = executable, target_file = ctx.file.binary)

    return [
        DefaultInfo(files = info.files, runfiles = info.default_runfiles, executable = executable),
    ]

release_nostrip_binary = rule(
    implementation = _release_nostrip_impl,
    executable = True,
    attrs = {
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
        "binary": attr.label(mandatory = True, cfg = release_nostrip_transition, allow_single_file = True),
    },
)

def _release_strip_transition(_settings, _attr):
    return {
        "//command_line_option:compilation_mode": "opt",
        "//command_line_option:strip": "always",
        "@rules_rust//:extra_rustc_flags": ["-Cdebug-assertions=off"],
    }

release_strip_transition = transition(
    implementation = _release_strip_transition,
    inputs = [],
    outputs = [
        "//command_line_option:compilation_mode",
        "//command_line_option:strip",
        "@rules_rust//:extra_rustc_flags",
    ],
)

def _release_strip_impl(ctx):
    bin = ctx.attr.binary[0]
    info = bin[DefaultInfo]

    executable = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(output = executable, target_file = ctx.file.binary)

    return [
        DefaultInfo(files = info.files, runfiles = info.default_runfiles, executable = executable),
    ]

release_strip_binary = rule(
    implementation = _release_strip_impl,
    executable = True,
    attrs = {
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
        "binary": attr.label(mandatory = True, cfg = release_strip_transition, allow_single_file = True),
    },
)

def _malicious_code_transition(_settings, _attr):
    return {
        "//bazel:enable_malicious_code": True,
        "//command_line_option:compilation_mode": "opt",
        "//command_line_option:strip": "never",
    }

malicious_code_enabled_transition = transition(
    implementation = _malicious_code_transition,
    inputs = [],
    outputs = [
        "//bazel:enable_malicious_code",
        "//command_line_option:compilation_mode",
        "//command_line_option:strip",
    ],
)

malicious_binary = rule(
    implementation = _release_nostrip_impl,
    executable = True,
    attrs = {
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
        "binary": attr.label(mandatory = True, cfg = malicious_code_enabled_transition, allow_single_file = True),
    },
)
