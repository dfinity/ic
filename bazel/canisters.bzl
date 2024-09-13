"""
This module defines utilities for building Rust canisters.
"""

load("@rules_motoko//motoko:defs.bzl", "motoko_binary")
load("@rules_rust//rust:defs.bzl", "rust_binary")
load("//bazel:candid.bzl", "did_git_test")

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

def rust_canister(name, service_file, visibility = ["//visibility:public"], testonly = False, opt = "3", **kwargs):
    """Defines a Rust program that builds into a WebAssembly module.

    The following targets are generated:
        <name>.raw: the raw Wasm module as built by rustc
        <name>.wasm.gz: the Wasm module, shrunk, with metadata, gzipped.
        <name>_did_git_test: a test that checks the backwards-compatibility of the did service file from HEAD with the same file from the merge-base of the PR.

    Args:
      name: the name of the target that produces a Wasm module.
      service_file: the label pointing the canister candid interface file.
      visibility: visibility of the Wasm target
      opt: opt-level for the Wasm target
      testonly: testonly attribute for Wasm target
      **kwargs: additional arguments to pass a rust_binary.
    """

    # Tags for the wasm build (popped because not relevant to bin base build)
    tags = kwargs.pop("tags", [])
    tags.append("canister")

    # The option to keep the name section is only required for wasm finalization.
    keep_name_section = kwargs.pop("keep_name_section", False)

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

    # The actual wasm build, unoptimized
    wasm_name = name + ".raw"
    wasm_rust_binary_rule(
        name = wasm_name,
        binary = ":" + bin_name,
        opt = opt,
        visibility = visibility,
        testonly = testonly,
        tags = tags,
    )

    # The finalized wasm (optimized, versioned, etc)
    # NOTE: the name should be .wasm.gz, but '.wasm' is used by some targets
    # and kept for legacy reasons
    final_name = name + ".wasm"
    finalize_wasm(
        name = final_name,
        src_wasm = wasm_name,
        service_file = service_file,
        version_file = "//bazel:rc_only_version.txt",
        visibility = visibility,
        testonly = testonly,
        keep_name_section = keep_name_section,
    )

    native.alias(
        name = name,
        actual = name + ".wasm",
    )

    # DID service related targets
    native.alias(
        name = name + ".didfile",
        actual = service_file,
    )
    did_git_test(
        name = name + "_did_git_test",
        did = service_file,
    )

def motoko_canister(name, entry, deps):
    """Defines a Motoko program that builds into a WebAssembly module.

    Args:
      name: the name of the target that produces a Wasm module.
      entry: path to this canister's main Motoko source file.
      deps: list of actor dependencies, e.g., external_actor targets from @rules_motoko.
    """

    raw_wasm = entry.replace(".mo", ".raw")
    raw_did = entry.replace(".mo", ".did")

    native.alias(
        name = name + ".didfile",
        actual = raw_did,
    )

    motoko_binary(
        name = name + "_raw",
        entry = entry,
        idl_out = raw_did,
        wasm_out = raw_wasm,
        deps = deps,
    )

    finalize_wasm(
        name = name + ".wasm",
        src_wasm = raw_wasm,
        version_file = "//bazel:rc_only_version.txt",
        testonly = False,
    )

    native.alias(
        name = name,
        actual = name + ".wasm",
    )

def finalize_wasm(*, name, src_wasm, service_file = None, version_file, testonly, visibility = ["//visibility:public"], keep_name_section = False):
    """Generates an output file name `name + '.wasm.gz'`.

    The input file is shrunk, annotated with metadata, and gzipped. The canister
    metadata consists of:
        'icp:public git_commit_id': version used in the build
        'icp:public candid:service': the canister's candid service description
    """
    native.genrule(
        name = name,
        srcs = [src_wasm, version_file] + ([service_file] if not (service_file == None) else []),
        outs = [name + ".gz"],
        visibility = visibility,
        testonly = testonly,
        message = "Finalizing canister " + name,
        tools = ["@crate_index//:ic-wasm__ic-wasm", "@pigz"],
        cmd_bash = " && ".join([
            "{ic_wasm} {input_wasm} -o $@.shrunk shrink {keep_name_section}",
            "{ic_wasm} $@.shrunk -o $@.meta metadata candid:service {keep_name_section} --visibility public --file " + "$(location {})".format(service_file) if not (service_file == None) else "cp $@.shrunk $@.meta",  # if service_file is None, don't include a service file
            "{ic_wasm} $@.meta -o $@.ver metadata git_commit_id {keep_name_section} --visibility public --file {version_file}",
            "{pigz} --processes 16 --no-name $@.ver --stdout > $@",
        ])
            .format(input_wasm = "$(location {})".format(src_wasm), ic_wasm = "$(location @crate_index//:ic-wasm__ic-wasm)", version_file = "$(location {})".format(version_file), pigz = "$(location @pigz)", keep_name_section = "--keep-name-section" if keep_name_section else ""),
    )
