"""
This module defines rules allowing scoped changes in compilation settings.
For example, you might want to build some targets with optimizations enabled
no matter what the current Bazel flags are.
"""

def _release_nostrip_transition_impl(_settings, _attr):
    return {
        "//command_line_option:compilation_mode": "opt",
        "//command_line_option:strip": "never",
        "@rules_rust//:extra_rustc_flags": ["-Cdebug-assertions=off"],
    }

release_nostrip_transition = transition(
    implementation = _release_nostrip_transition_impl,
    inputs = [],
    outputs = [
        "//command_line_option:compilation_mode",
        "//command_line_option:strip",
        "@rules_rust//:extra_rustc_flags",
    ],
)

def _release_nostrip_impl(ctx):
    release_bin = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(output = release_bin, target_file = ctx.file.binary)

    return [
        DefaultInfo(executable = release_bin),
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

release_strip_binary_test = rule(
    implementation = _release_strip_impl,
    test = True,
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

def _artifact_bundle_impl(ctx):
    # List of input files
    input_files = ctx.files.inputs

    bundle_root = ctx.actions.declare_directory("bundle-{}".format(ctx.attr.name))

    bundle_prefix = ctx.attr.prefix

    if bundle_prefix == "":
        fail("artifact bundle prefix must be set")

    # Compute checksums and print it to stdout & out file.
    # The filenames are stripped from anything but the basename.
    # NOTE: This might produce confusing output if `input_files` contain
    # files with identical names in different directories.
    ctx.actions.run_shell(
        inputs = input_files,
        arguments = [file.path for file in input_files],
        env = {
            "BUNDLE_ROOT": bundle_root.path,
            "BUNDLE_PREFIX": bundle_prefix,
        },
        outputs = [bundle_root],
        tools = [ctx.executable._sha256],
        command = """
        set -euo pipefail

        outdir="$BUNDLE_ROOT/$BUNDLE_PREFIX"

        mkdir -p "$outdir"

        out_checksums="$outdir/SHA256SUMS"

        output=$(mktemp) # temporary file bc sha256 doesn't support writing to stdout (or /dev/stdout) directly
        for input in "$@"; do
            {sha256} "$input" "$output"
            cat "$output" >> "$out_checksums"
            echo " $(basename $input)" >> "$out_checksums"
            ln -s "$( realpath "$input" )" "$outdir/$(basename $input)"
        done

        sort -o "$out_checksums" -k 2 "$out_checksums"
        """.format(sha256 = ctx.executable._sha256.path),
    )

    # Return the output file
    return [DefaultInfo(files = depset([bundle_root]))]

# A rule that re-exports symlinks to all the inputs as well
# as an extra file 'SHA256SUMS' containing the checksums of inputs.
artifact_bundle = rule(
    implementation = _artifact_bundle_impl,
    attrs = {
        "inputs": attr.label_list(
            allow_files = True,
            mandatory = True,
        ),
        "prefix": attr.string(
            mandatory = True,
        ),
        # The bazel-provided sha256 tool to avoid relying on tools from the container/env
        "_sha256": attr.label(
            default = "@bazel_tools//tools/build_defs/hash:sha256",
            executable = True,
            cfg = "exec",
        ),
    },
)
