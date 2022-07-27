"""
Utilities for building IC replica and canisters.
"""

def gzip_compress(name, srcs):
    """GZip-compresses source files.

    Args:
      name: name of the compressed file.
      srcs: list of input labels.
    """
    native.genrule(
        name = "_compress_" + name,
        exec_tools = ["@pigz"],
        srcs = srcs,
        outs = [name],
        message = "Compressing into %s" % name,
        cmd_bash = "$(location @pigz) $(SRCS) --stdout > $@",
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
