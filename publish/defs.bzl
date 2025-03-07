"""
This module defines rules allowing scoped changes in compilation settings.
For example, you might want to build some targets with optimizations enabled
no matter what the current Bazel flags are.
"""

def _release_nostrip_transition(_settings, _attr):
    return {
        "//command_line_option:compilation_mode": "opt",
        "//command_line_option:strip": "never",
        # opt mode will have rules_rust strip debug symbols, regardless of the
        # strip setting. Unfortunately zig cc (from hermetic_cc_toolchain)
        # strips as "all or nothing", so we lose all symbols, unless we also
        # override the strip setting here.
        "@rules_rust//:extra_rustc_flags": ["-Cdebug-assertions=off", "-Cstrip=none"],
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

def _checksum_rule_impl(ctx):
    # List of input files
    input_files = ctx.files.inputs

    # Declare output files (NOTE: not windows friendly)
    out_checksums = ctx.actions.declare_file("_checksums/SHA256SUMS")

    def make_symlink(target):
        symlink = ctx.actions.declare_file("_checksums/" + target.basename)
        ctx.actions.symlink(output = symlink, target_file = target)
        return symlink

    symlinks = [make_symlink(file) for file in input_files]

    # Compute checksums and print it to stdout & out file.
    # The filenames are stripped from anything but the basename.
    # NOTE: This might produce confusing output if `input_files` contain
    # files with identical names in different directories.
    ctx.actions.run_shell(
        inputs = input_files,
        arguments = [file.path for file in input_files],
        outputs = [out_checksums],
        tools = [ctx.executable._sha256],
        command = """
        set -euo pipefail

        out_checksums="{out}"
        output=$(mktemp) # temporary file bc sha256 doesn't support writing to stdout (or /dev/stdout) directly

        for input in "$@"; do
            if ! [[ $input =~ (\\.tar|\\.gz) ]]; then
                echo "skipping non-archive file $input"
                continue
            fi
            {sha256} "$input" "$output"
            cat "$output" >> "$out_checksums"
            echo " $(basename $input)" >> "$out_checksums"
        done

        cat "$out_checksums"

        sort -o "$out_checksums" -k 2 "$out_checksums"
        """.format(out = out_checksums.path, sha256 = ctx.executable._sha256.path),
    )

    # Return the output file
    return [DefaultInfo(files = depset([out_checksums] + symlinks))]

# A rule that re-exports symlinks to all the inputs as well
# as an extra file 'SHA256SUMS' containing the checksums of inputs.
checksum_rule = rule(
    implementation = _checksum_rule_impl,
    attrs = {
        "inputs": attr.label_list(
            allow_files = True,
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
