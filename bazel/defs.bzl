def _optimize_canister(ctx):
    """Invokes canister WebAssembly module optimizer.
    """
    name = ctx.label.name
    output_file = ctx.actions.declare_file(name if name.endswith(".wasm") else name + ".wasm")
    ctx.actions.run(
        mnemonic = "IcCdkOptimizer",
        executable = "/usr/bin/ic-cdk-optimizer",
        arguments = [f.path for f in ctx.attr.wasm.files.to_list()] + ["-o", output_file.path],
        inputs = ctx.attr.wasm.files.to_list(),
        outputs = [output_file],
    )
    return [DefaultInfo(files = depset([output_file]))]

optimized_canister = rule(
    implementation = _optimize_canister,
    attrs = {
        "wasm": attr.label(allow_files = True),
    },
)

def _pigz_compress(ctx):
    """GZip-compresses source files."""
    output_file = ctx.actions.declare_file(ctx.label.name)
    input_files = " ".join([f.path for f in ctx.files.srcs])
    ctx.actions.run_shell(
        mnemonic = "GZip",
        command = "/usr/bin/pigz %s --stdout > %s" % (input_files, output_file.path),
        inputs = ctx.files.srcs,
        outputs = [output_file],
    )
    return [DefaultInfo(files = depset([output_file]))]

gzip_compress = rule(
    implementation = _pigz_compress,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
    },
)

def cargo_build(name, srcs, binaries, cargo_flags, profile = "release", target = None, env_paths = {}, deps = []):
    """ Builds cargo binaries.

    Args:
      name: name of the target.
      srcs: list of input labels.
      binaries: names of binaries to build.
      cargo_flags: extra flags to pass to cargo.
      profile: cargo profile to build.
      target: the build target.
      env_paths: environment variables passing paths to files.
      deps: prerequisites for the cargo build.
    """
    args = ["$$CARGO", "build", "--profile", profile]
    if target:
        args += ["--target", target]

    suffix = ".wasm" if target and target.startswith("wasm") else ""

    out_dir = "$$CARGO_TARGET_DIR/"
    if target:
        out_dir = out_dir + target + "/"
    out_dir = out_dir + profile

    cp_cmds = []
    outs = []
    for bin in binaries:
        args += ["--bin", bin]
        bin_name = bin + suffix
        cp_cmds.append("".join(["cp ", out_dir, "/", bin_name, " $(location ", bin_name, ")"]))
        outs.append(bin_name)
    args.extend(cargo_flags)

    env_cmds = []
    for (k, v) in env_paths.items():
        env_cmds.append("export %s=$$PWD/%s" % (k, v))

    cargo_cmd = " ".join(args)
    cmds = "\n".join(env_cmds + [cargo_cmd] + cp_cmds)
    native.genrule(
        name = name,
        srcs = srcs + deps,
        message = "Cargo build",
        tools = [
            "@rules_rust//rust/toolchain:current_exec_cargo_files",
            "@rules_rust//rust/toolchain:current_exec_rustc_files",
            "@rules_rust//rust/toolchain:current_exec_rustfmt_files",
        ],
        outs = outs,
        cmd = """
        export CARGO=$(location @rules_rust//rust/toolchain:current_exec_cargo_files)
        export RUSTC=$(location @rules_rust//rust/toolchain:current_exec_rustc_files)
        export RUSTFMT=$$(realpath $(location @rules_rust//rust/toolchain:current_exec_rustfmt_files))
        export CARGO_TARGET_DIR=$(BINDIR)/cargo/target
        export CARGO_HOME=$(BINDIR)/cargo/home
        """ + cmds,
    )
