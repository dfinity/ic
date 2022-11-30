"""
Rules for system-tests.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")

def _run_system_test(ctx):
    run_test_script_file = ctx.actions.declare_file(ctx.label.name + "/run-test.sh")

    ctx.actions.write(
        output = run_test_script_file,
        is_executable = True,
        content = """#!/bin/bash
            set -eEuo pipefail
            RUNFILES="$PWD"
            cd "$TEST_TMPDIR"
            mkdir root_env
            cp -Rs "$RUNFILES" root_env/dependencies/
            "$RUNFILES/{test_executable}" --working-dir . run "$@"
        """.format(
            test_executable = ctx.executable.src.short_path,
        ),
    )

    runtime_deps = []
    for target in ctx.attr.runtime_deps:
        runtime_deps.append(target.files)

    return [
        DefaultInfo(
            executable = run_test_script_file,
            runfiles = ctx.runfiles(
                files = [
                    run_test_script_file,
                    ctx.executable.src,
                ],
                transitive_files = depset(
                    direct = [],
                    transitive = runtime_deps,
                ),
            ),
        ),
        RunEnvironmentInfo(
            environment = ctx.attr.env,
        ),
    ]

run_system_test = rule(
    implementation = _run_system_test,
    test = True,
    attrs = {
        "src": attr.label(executable = True, cfg = "exec"),
        "env": attr.string_dict(allow_empty = True),
        "runtime_deps": attr.label_list(allow_files = True),
    },
)

def system_test(name, runtime_deps = [], tags = [], test_timeout = "long", **kwargs):
    """Declares a system-test.

    Args:
      name: base name to use for the binary and test rules.
      runtime_deps: dependencies to make available to the test when it runs.
      tags: additional tags for the system_test.
      test_timeout: bazel test timeout (short, moderate, long or eternal).
      **kwargs: additional arguments to pass to the rust_binary rule.
    """
    bin_name = name + "_bin"

    rust_binary(
        name = bin_name,
        srcs = ["bin/" + name + ".rs"],
        **kwargs
    )

    run_system_test(
        name = name,
        src = bin_name,
        runtime_deps = runtime_deps,
        tags = tags + ["requires-network", "system_test"],
        timeout = test_timeout,
        # TODO: remove when PFOPS-3148 is resolved
        flaky = True,
    )

def _symlink_dir(ctx):
    dirname = ctx.attr.name
    lns = []
    for target, canister_name in ctx.attr.targets.items():
        ln = ctx.actions.declare_file(dirname + "/" + canister_name)
        file = target[DefaultInfo].files.to_list()[0]
        ctx.actions.symlink(
            output = ln,
            target_file = file,
        )
        lns.append(ln)
    return [DefaultInfo(files = depset(direct = lns))]

symlink_dir = rule(
    implementation = _symlink_dir,
    attrs = {
        "targets": attr.label_keyed_string_dict(allow_files = True),
    },
)
