"""
This module defines utilities for building Rust canisters.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")

def _wasm_rust_transition_impl(_settings, _attr):
    return {
        "//command_line_option:platforms": "@rules_rust//rust/platform:wasm",
        "@rules_rust//:extra_rustc_flags": [
            "-C",
            "linker-plugin-lto",
            "-C",
            "opt-level=z",
            "-C",
            "debug-assertions=no",
            "-C",
            "debuginfo=0",
            "-C",
            "lto",
        ],
    }

wasm_rust_transition = transition(
    implementation = _wasm_rust_transition_impl,
    inputs = [],
    outputs = [
        "//command_line_option:platforms",
        "@rules_rust//:extra_rustc_flags",
    ],
)

def _wasm_binary_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".wasm")
    ctx.actions.run(
        executable = "cp",
        arguments = [ctx.files.binary[0].path, out.path],
        outputs = [out],
        inputs = ctx.files.binary,
    )

    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles([out]))]

wasm_rust_binary_rule = rule(
    implementation = _wasm_binary_impl,
    attrs = {
        "binary": attr.label(mandatory = True, cfg = wasm_rust_transition),
        "_whitelist_function_transition": attr.label(default = "@bazel_tools//tools/whitelists/function_transition_whitelist"),
    },
)

def rust_canister(name, service_file, **kwargs):
    """Defines a rust program that builds into a WebAssembly module.

    Args:
      name: the name of the target that produces a Wasm module.
      service_file: the label pointing the canister candid interface file.
      **kwargs: additional arguments to pass a rust_binary rule.
    """
    wasm_name = "_wasm_" + name.replace(".", "_")
    kwargs.setdefault("visibility", ["//visibility:public"])

    rust_binary(
        name = wasm_name,
        crate_type = "bin",
        **kwargs
    )

    wasm_rust_binary_rule(
        name = name + ".raw",
        binary = ":" + wasm_name,
    )

    # Invokes canister WebAssembly module optimizer and attaches the candid file.
    native.genrule(
        name = name + ".opt",
        srcs = [name + ".raw", service_file],
        outs = [name + ".opt.wasm"],
        message = "Shrinking canister " + name,
        exec_tools = ["@crate_index//:ic-wasm__ic-wasm"],
        cmd_bash = """
        $(location @crate_index//:ic-wasm__ic-wasm) $(location {input_wasm}) -o $@ shrink && \
        $(location @crate_index//:ic-wasm__ic-wasm) $@ -o $@ metadata candid:service --visibility public --file $(location {service_file})
        """.format(input_wasm = name + ".raw", service_file = service_file),
    )

    inject_version_into_wasm(
        name = name,
        src_wasm = name + ".opt",
        version_file = "//bazel:rc_only_version.txt",
    )

def inject_version_into_wasm(*, name, src_wasm, version_file = "//bazel:version.txt", visibility = None):
    """Generates an output file named `name + '.wasm'`.

    The output file is almost identical to the input (i.e. `src_wasm`), except
    that it has an additional piece of metadata attached to in the form of a
    WASM custom section named `icp:public git_commit_id` (no quotes, of course),
    whose value is the contents of version_file (minus the trailing
    newline character).
    """
    native.genrule(
        name = name,
        srcs = [
            src_wasm,
            version_file,
        ],
        outs = [name + ".wasm"],
        message = "Injecting version into wasm.",
        exec_tools = ["@crate_index//:ic-wasm__ic-wasm"],
        cmd_bash = " ".join([
            "$(location @crate_index//:ic-wasm__ic-wasm)",
            "$(location %s)" % src_wasm,  # Input file.
            "--output $@",  # Output file.
            "metadata",  # Subcommand

            # The name of the custom section will be
            # "icp:public git_commit_id"
            "git_commit_id",
            "--visibility public",

            # Get value to inject from version_file.
            "--file $(location " + version_file + ")",
        ]),
        visibility = visibility,
    )
