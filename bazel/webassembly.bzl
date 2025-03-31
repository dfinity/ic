"""
This module defines utilities for building Rust canisters.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")

def _wasm_rust_transition_impl(_settings, attr):
    return {
        "//command_line_option:platforms": "@rules_rust//rust/platform:wasm",
        "@rules_rust//:extra_rustc_flags": [
            # rustc allocates a default stack size of 1MiB for Wasm, which causes stack overflow on certain
            # recursive workloads when compiled with 1.78.0+. Hence, we set the new stack size to 3MiB
            "-C",
            "link-args=-z stack-size=3145728",
            "-C",
            "linker-plugin-lto",
            "-C",
            "opt-level=" + attr.opt,
            "-C",
            "debug-assertions=no",
            "-C",
            "debuginfo=0",
            "-C",
            "lto",
            "-C",
            "target-feature=+bulk-memory",
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
        "_allowlist_function_transition": attr.label(default = "@bazel_tools//tools/allowlists/function_transition_allowlist"),
        "opt": attr.string(mandatory = True),
    },
)

def wasm(name, visibility = ["//visibility:public"], testonly = False, opt = "3", **kwargs):
    """Defines a Rust program that builds into a WebAssembly module.

    The following targets are generated:
        <name>.wasm: the raw Wasm module as built by rustc

    Args:
      name: the name of the target that produces a Wasm module.
      visibility: visibility of the Wasm target
      opt: opt-level for the Wasm target
      testonly: testonly attribute for Wasm target
      **kwargs: additional arguments to pass a rust_binary.
    """

    # Tags for the wasm build (popped because not relevant to bin base build)
    tags = kwargs.pop("tags", [])

    # Sanity checking (no '.' in name)
    if name.count(".") > 0:
        fail("name '{}' should not include dots".format(name))

    # Rust binary build (not actually built by default, but transitioned & used in the
    # wasm build)
    # NOTE: '_wasm_' is a misnommer since it's not a wasm build but used for legacy
    # reasons (some targets depend on this)
    bin_name = "_wasm_" + name.replace(".", "_")
    rust_binary(
        name = bin_name,
        crate_type = "bin",
        tags = ["manual"],  # don't include in wildcards like //pkg/...
        visibility = ["//visibility:private"],  # shouldn't be used
        testonly = testonly,
        **kwargs
    )

    # The actual wasm build
    wasm_rust_binary_rule(
        name = name,
        binary = ":" + bin_name,
        opt = opt,
        visibility = visibility,
        testonly = testonly,
        tags = tags,
    )
