"""Build helpers for using the pocket-ic"""

load("@bazel_skylib//lib:paths.bzl", "paths")

# This defines a transition used in the pocket-ic declaration.
# This allows tests to depend on an arbitrary version of pocket-ic
# and for dependents to override that version.
def _pocket_ic_mainnet_transition_impl(_settings, _attr):
    return {
        "//:pocket-ic-server-variant": "mainnet",
    }

pocket_ic_mainnet_transition = transition(
    implementation = _pocket_ic_mainnet_transition_impl,
    inputs = [],
    outputs = [
        "//:pocket-ic-server-variant",
    ],
)

# Provider that allows wrapping/transitioning a test executable. This
# ensure all the test data & env is forwarded.
# Adapted from github.com/aherrman/bazel-transitions-demo:
# https://github.com/aherrmann/bazel-transitions-demo/blob/f22cf40a62131eace14829f262e8d7c00b0a9a19/flag/defs.bzl#L124
TestAspectInfo = provider("some descr", fields = ["args", "env"])

def _test_aspect_impl(_target, ctx):
    data = getattr(ctx.rule.attr, "data", [])
    args = getattr(ctx.rule.attr, "args", [])
    env = getattr(ctx.rule.attr, "env", [])
    args = [ctx.expand_location(arg, data) for arg in args]
    env = {k: ctx.expand_location(v, data) for (k, v) in env.items()}
    return [TestAspectInfo(
        args = args,
        env = env,
    )]

_test_aspect = aspect(_test_aspect_impl)

def _pocket_ic_mainnet_test_impl(ctx):
    test_aspect_info = ctx.attr.test[TestAspectInfo]
    (_, extension) = paths.split_extension(ctx.executable.test.path)
    executable = ctx.actions.declare_file(
        ctx.label.name + extension,
    )
    ctx.actions.write(
        output = executable,
        content = """\
#!/usr/bin/env bash
set -euo pipefail
{commands}
""".format(
            commands = "\n".join([
                " \\\n".join([
                    '{}="{}"'.format(k, v)
                    for k, v in test_aspect_info.env.items()
                ] + [
                    ctx.executable.test.short_path,
                ] + test_aspect_info.args),
            ]),
        ),
        is_executable = True,
    )

    runfiles = ctx.runfiles(files = [executable, ctx.executable.test] + ctx.files.data)
    runfiles = runfiles.merge(ctx.attr.test[DefaultInfo].default_runfiles)
    for data_dep in ctx.attr.data:
        runfiles = runfiles.merge(data_dep[DefaultInfo].default_runfiles)

    return [DefaultInfo(
        executable = executable,
        files = depset(direct = [executable]),
        runfiles = runfiles,
    )]

# Rule to override another (test) rule. The resulting rule
# will use the mainnet pocket-ic varaint.
pocket_ic_mainnet_test = rule(
    _pocket_ic_mainnet_test_impl,
    attrs = {
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
        "data": attr.label_list(allow_files = True),
        "test": attr.label(
            aspects = [_test_aspect],
            cfg = "target",
            executable = True,
        ),
    },
    cfg = pocket_ic_mainnet_transition,
    executable = True,
    test = True,
)
