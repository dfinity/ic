"""Create transition to disable hermetic_cc_toolchains for hs targets."""

load("@rules_haskell//haskell:defs.bzl", haskell_binary_inner = "haskell_binary", haskell_library_inner = "haskell_library")

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

def haskell_binary(name, **kwargs):
    """
    Wrap the rules_haskell haskell_binary with a transition that disables hermetic toolchains.

    These are not supported together, because ghc will not work with the zig compiler.

    Args:
      name: Name for the generated filegroup.
      **kwargs: Pass through args to the inner haskell_binary.
    """

    tags = kwargs.pop("tags", [])
    tags.append("manual")
    new_name = name + "_inner"
    label = ":" + new_name

    haskell_binary_inner(new_name, tags = tags, **kwargs)

    disable_hermetic_cc_binary(
        name = name,
        binary = label,
        visibility = ["//visibility:public"],
    )

def haskell_library(**kwargs):
    """
    Wrap the rules_haskell haskell_library with a transition that disables hermetic toolchains.

    These are not supported together, because ghc will not work with the zig compiler.

    Args:
      **kwargs: Pass through args to the inner haskell_library.
    """
    tags = kwargs.pop("tags", [])
    tags.append("manual")

    haskell_library_inner(tags = tags, **kwargs)
