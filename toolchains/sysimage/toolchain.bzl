"""
Tools for building IC OS image.
"""

# Similar to ctx.actions.run but runs the command wrapped in the ic-os build process
# wrapper that sets up the environment. Can only be used in rules defined by
# _icos_build_rule.
def _run_with_icos_wrapper(
        ctx,
        executable,
        arguments = [],
        tools = [],
        execution_requirements = {},
        **kwargs):
    ctx.actions.run(
        executable = ctx.executable._icos_build_proc_wrapper,
        arguments = [executable] + arguments,
        tools = tools + [ctx.attr._icos_build_proc_wrapper.files_to_run],
        execution_requirements = execution_requirements |
                                 {"supports-graceful-termination": "1"},
        **kwargs
    )

def _icos_build_rule(attrs = {}, **kwargs):
    return rule(
        attrs = attrs |
                {"_icos_build_proc_wrapper": attr.label(
                    default = ":proc_wrapper",
                    executable = True,
                    cfg = "exec",
                    allow_files = True,
                )},
        **kwargs
    )

def _build_container_base_image_impl(ctx):
    args = []
    inputs = []
    outputs = []

    # Output file is the name given to the target
    output_tar_file = ctx.actions.declare_file(ctx.label.name)
    args.extend(["--output", output_tar_file.path])
    outputs.append(output_tar_file)

    inputs += ctx.files.context_files
    for context_file in ctx.files.context_files:
        args.extend(["--context-file", context_file.path])

    args.extend(["--image_tag", ctx.attr.image_tag])

    inputs.append(ctx.file.dockerfile)
    args.extend(["--dockerfile", ctx.file.dockerfile.path])

    # Dir mounts prepared in `gitlab-ci/container/container-run.sh`
    args.extend(["--tmpfs_container_sys_dir"])

    if ctx.attr.build_args:
        args.extend(["--build_args"])
        for build_arg in ctx.attr.build_args:
            args.extend([build_arg])

    tool = ctx.attr._tool

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [tool.files_to_run],
        # Base image is NOT reproducible (because `apt install`)
        execution_requirements = {"no-remote-cache": "1"},
    )

    return [DefaultInfo(
        files = depset(outputs),
        runfiles = ctx.runfiles(outputs),
    )]

build_container_base_image = _icos_build_rule(
    implementation = _build_container_base_image_impl,
    attrs = {
        "context_files": attr.label_list(
            allow_files = True,
        ),
        "dockerfile": attr.label(
            allow_single_file = True,
        ),
        "image_tag": attr.string(mandatory = True),
        "build_args": attr.string_list(),
        "_tool": attr.label(
            default = "//toolchains/sysimage:build_container_base_image",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _build_container_filesystem_impl(ctx):
    args = []
    inputs = []
    outputs = []

    output_tar_file = ctx.actions.declare_file(ctx.label.name)
    args.extend(["--output", output_tar_file.path])
    outputs.append(output_tar_file)

    inputs += ctx.files.context_files
    for context_file in ctx.files.context_files:
        args.extend(["--context-file", context_file.path])

    for input_target, install_target in ctx.attr.component_files.items():
        args.extend(["--component-file", input_target.files.to_list()[0].path + ":" + install_target])
        inputs += input_target.files.to_list()

    if ctx.file.dockerfile:
        inputs.append(ctx.file.dockerfile)
        args.extend(["--dockerfile", ctx.file.dockerfile.path])

    build_args = ctx.attr.build_args
    for build_arg in build_args:
        args.extend(["--build-arg", build_arg])

    if ctx.attr.file_build_arg:
        args.extend(["--file-build-arg", ctx.attr.file_build_arg])

    if ctx.file.base_image_tar_file:
        inputs.append(ctx.file.base_image_tar_file)
        args.extend(["--base-image-tar-file", ctx.file.base_image_tar_file.path])
        args.extend(["--base-image-tar-file-tag", ctx.attr.base_image_tar_file_tag])

    # Dir mounts prepared in `gitlab-ci/container/container-run.sh`
    args.extend(["--tmpfs-container-sys-dir"])
    args.extend(["--no-cache"])

    tool = ctx.attr._tool

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [tool.files_to_run],
    )

    return [DefaultInfo(
        files = depset(outputs),
        runfiles = ctx.runfiles(outputs),
    )]

build_container_filesystem = _icos_build_rule(
    implementation = _build_container_filesystem_impl,
    attrs = {
        "context_files": attr.label_list(
            allow_files = True,
        ),
        "component_files": attr.label_keyed_string_dict(
            allow_files = True,
        ),
        "dockerfile": attr.label(
            allow_single_file = True,
        ),
        "build_args": attr.string_list(),
        "file_build_arg": attr.string(),
        "base_image_tar_file": attr.label(
            allow_single_file = True,
        ),
        "base_image_tar_file_tag": attr.string(mandatory = False),
        "_tool": attr.label(
            default = "//toolchains/sysimage:build_container_filesystem_tar",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _vfat_image_impl(ctx):
    tool = ctx.files._build_vfat_image[0]
    dflate = ctx.files._dflate[0]

    if len(ctx.files.src) > 0:
        args = ["-i", ctx.files.src[0].path]
        inputs = [ctx.files.src[0]]
    else:
        args = []
        inputs = []
    out = ctx.actions.declare_file(ctx.label.name)

    args += [
        "-o",
        out.path,
        "-s",
        ctx.attr.partition_size,
        "-p",
        ctx.attr.subdir,
        "--dflate",
        dflate.path,
    ]

    for input_target, install_target in ctx.attr.extra_files.items():
        args.append(input_target.files.to_list()[0].path + ":" + install_target)
        inputs += input_target.files.to_list()

    _run_with_icos_wrapper(
        ctx,
        executable = tool.path,
        arguments = args,
        inputs = inputs,
        outputs = [out],
        tools = [tool, dflate],
    )

    return [DefaultInfo(files = depset([out]))]

vfat_image = _icos_build_rule(
    implementation = _vfat_image_impl,
    attrs = {
        "src": attr.label(
            allow_files = True,
        ),
        "extra_files": attr.label_keyed_string_dict(
            allow_files = True,
            mandatory = False,
        ),
        "partition_size": attr.string(
            mandatory = True,
        ),
        "subdir": attr.string(
            default = "/",
        ),
        "_build_vfat_image": attr.label(
            allow_files = True,
            default = ":build_vfat_image.py",
        ),
        "_dflate": attr.label(
            allow_files = True,
            default = "//rs/ic_os/dflate",
        ),
    },
)

def _fat32_image_impl(ctx):
    tool = ctx.files._build_fat32_image[0]
    dflate = ctx.files._dflate[0]

    if len(ctx.files.src) > 0:
        args = ["-i", ctx.files.src[0].path]
        inputs = [ctx.files.src[0]]
    else:
        args = []
        inputs = []
    out = ctx.actions.declare_file(ctx.label.name)

    args += [
        "-o",
        out.path,
        "-s",
        ctx.attr.partition_size,
        "-p",
        ctx.attr.subdir,
        "--dflate",
        dflate.path,
    ]

    for input_target, install_target in ctx.attr.extra_files.items():
        args.append(input_target.files.to_list()[0].path + ":" + install_target)
        inputs += input_target.files.to_list()

    if ctx.attr.label:
        args += ["-l", ctx.attr.label]

    _run_with_icos_wrapper(
        ctx,
        executable = tool.path,
        arguments = args,
        inputs = inputs,
        outputs = [out],
        tools = [tool, dflate],
    )

    return [DefaultInfo(files = depset([out]))]

fat32_image = _icos_build_rule(
    implementation = _fat32_image_impl,
    attrs = {
        "src": attr.label(
            allow_files = True,
        ),
        "extra_files": attr.label_keyed_string_dict(
            allow_files = True,
            mandatory = False,
        ),
        "partition_size": attr.string(
            mandatory = True,
        ),
        "label": attr.string(),
        "subdir": attr.string(
            default = "/",
        ),
        "_build_fat32_image": attr.label(
            allow_files = True,
            default = ":build_fat32_image.py",
        ),
        "_dflate": attr.label(
            allow_files = True,
            default = "//rs/ic_os/dflate",
        ),
    },
)

def _ext4_image_impl(ctx):
    tool = ctx.files._build_ext4_image[0]
    diroid = ctx.files._diroid[0]
    dflate = ctx.files._dflate[0]

    out = ctx.actions.declare_file(ctx.label.name)

    inputs = []
    args = []

    if len(ctx.files.src) > 0:
        args += ["-i", ctx.files.src[0].path]
        inputs += ctx.files.src
    args += [
        "-o",
        out.path,
        "-s",
        ctx.attr.partition_size,
        "-p",
        ctx.attr.subdir,
        "--diroid",
        diroid.path,
        "--dflate",
        dflate.path,
    ]
    if len(ctx.files.file_contexts) > 0:
        args += ["-S", ctx.files.file_contexts[0].path]
        inputs += ctx.files.file_contexts

    if len(ctx.attr.strip_paths) > 0:
        args += ["--strip-paths"] + ctx.attr.strip_paths

    _run_with_icos_wrapper(
        ctx,
        executable = tool.path,
        arguments = args,
        inputs = inputs,
        outputs = [out],
        tools = [tool, diroid, dflate],
    )

    return [DefaultInfo(files = depset([out]))]

ext4_image = _icos_build_rule(
    implementation = _ext4_image_impl,
    attrs = {
        "src": attr.label(
            allow_files = True,
        ),
        "file_contexts": attr.label(
            allow_files = True,
            mandatory = False,
        ),
        "strip_paths": attr.string_list(),
        "partition_size": attr.string(
            mandatory = True,
        ),
        "subdir": attr.string(
            default = "/",
        ),
        "_build_ext4_image": attr.label(
            allow_files = True,
            default = ":build_ext4_image.py",
        ),
        "_diroid": attr.label(
            allow_files = True,
            default = "//rs/ic_os/diroid",
        ),
        "_dflate": attr.label(
            allow_files = True,
            default = "//rs/ic_os/dflate",
        ),
    },
)

def _inject_files_impl(ctx):
    tool = ctx.files._inject_files[0]
    dflate = ctx.files._dflate[0]

    out = ctx.actions.declare_file(ctx.label.name)

    inputs = [ctx.files.base[0]]

    args = [
        "--input",
        ctx.files.base[0].path,
        "--output",
        out.path,
        "--dflate",
        dflate.path,
    ]

    if len(ctx.files.file_contexts) > 0:
        args += ["--file-contexts", ctx.files.file_contexts[0].path]
        inputs += ctx.files.file_contexts

    if ctx.attr.prefix:
        args += ["--prefix", ctx.attr.prefix]

    for input_target, install_target in ctx.attr.extra_files.items():
        args.append(input_target.files.to_list()[0].path + ":" + install_target)
        inputs += input_target.files.to_list()

    _run_with_icos_wrapper(
        ctx,
        executable = tool.path,
        arguments = args,
        inputs = inputs,
        outputs = [out],
        tools = [tool, dflate],
    )

    return [DefaultInfo(files = depset([out]))]

inject_files = _icos_build_rule(
    implementation = _inject_files_impl,
    attrs = {
        "base": attr.label(
            allow_files = True,
            mandatory = True,
        ),
        "extra_files": attr.label_keyed_string_dict(
            allow_files = True,
            mandatory = True,
        ),
        "file_contexts": attr.label(
            allow_files = True,
            mandatory = False,
        ),
        "prefix": attr.string(
            mandatory = False,
        ),
        "_inject_files": attr.label(
            allow_files = True,
            default = "//rs/ic_os/inject_files:inject-files",
        ),
        "_dflate": attr.label(
            allow_files = True,
            default = "//rs/ic_os/dflate",
        ),
    },
)

def _disk_image_impl(ctx):
    tool_file = ctx.files._build_disk_image_tool[0]
    dflate = ctx.files._dflate[0]

    in_layout = ctx.files.layout[0]
    partitions = ctx.files.partitions
    out = ctx.actions.declare_file(ctx.label.name)
    expanded_size = ctx.attr.expanded_size

    partition_files = []
    for p in partitions:
        partition_files.append(p.path)

    args = ["-p", in_layout.path, "-o", out.path, "--dflate", dflate.path]

    if expanded_size:
        args += ["-s", expanded_size]

    args += partition_files

    _run_with_icos_wrapper(
        ctx,
        executable = tool_file.path,
        arguments = args,
        inputs = [in_layout] + partitions,
        outputs = [out],
        tools = [tool_file, dflate],
    )

    return [DefaultInfo(files = depset([out]))]

disk_image = _icos_build_rule(
    implementation = _disk_image_impl,
    attrs = {
        "layout": attr.label(
            allow_files = True,
            mandatory = True,
        ),
        "partitions": attr.label_list(
            allow_files = True,
        ),
        "expanded_size": attr.string(),
        "_build_disk_image_tool": attr.label(
            allow_files = True,
            default = ":build_disk_image.py",
        ),
        "_dflate": attr.label(
            allow_files = True,
            default = "//rs/ic_os/dflate",
        ),
    },
)

def _lvm_image_impl(ctx):
    tool_file = ctx.files._build_lvm_image_tool[0]
    dflate = ctx.files._dflate[0]

    in_layout = ctx.files.layout[0]
    vg_name = ctx.attr.vg_name
    vg_uuid = ctx.attr.vg_uuid
    pv_uuid = ctx.attr.pv_uuid
    partitions = ctx.files.partitions
    out = ctx.actions.declare_file(ctx.label.name)

    partition_files = []
    for p in partitions:
        partition_files.append(p.path)

    args = ["-v", in_layout.path, "-n", vg_name, "-u", vg_uuid, "-p", pv_uuid, "-o", out.path, "--dflate", dflate.path]

    args += partition_files

    _run_with_icos_wrapper(
        ctx,
        executable = tool_file.path,
        arguments = args,
        inputs = [in_layout] + partitions,
        outputs = [out],
        tools = [tool_file, dflate],
    )

    return [DefaultInfo(files = depset([out]))]

lvm_image = _icos_build_rule(
    implementation = _lvm_image_impl,
    attrs = {
        "layout": attr.label(
            allow_files = True,
            mandatory = True,
        ),
        "partitions": attr.label_list(
            allow_files = True,
        ),
        "vg_name": attr.string(),
        "vg_uuid": attr.string(),
        "pv_uuid": attr.string(),
        "_build_lvm_image_tool": attr.label(
            allow_files = True,
            default = ":build_lvm_image.py",
        ),
        "_dflate": attr.label(
            allow_files = True,
            default = "//rs/ic_os/dflate",
        ),
    },
)

def _upgrade_image_impl(ctx):
    tool_file = ctx.files._build_upgrade_image_tool[0]
    dflate = ctx.files._dflate[0]

    in_boot_partition = ctx.files.boot_partition[0]
    in_root_partition = ctx.files.root_partition[0]
    in_version_file = ctx.files.version_file[0]
    out = ctx.actions.declare_file(ctx.label.name)

    _run_with_icos_wrapper(
        ctx,
        executable = "python3",
        inputs = [in_boot_partition, in_root_partition, in_version_file],
        outputs = [out],
        arguments = [
            tool_file.path,
            "-b",
            in_boot_partition.path,
            "-r",
            in_root_partition.path,
            "-v",
            in_version_file.path,
            "-o",
            out.path,
            "--dflate",
            dflate.path,
        ],
    )

    return [DefaultInfo(files = depset([out]))]

upgrade_image = _icos_build_rule(
    implementation = _upgrade_image_impl,
    attrs = {
        "boot_partition": attr.label(
            allow_files = True,
            mandatory = True,
        ),
        "root_partition": attr.label(
            allow_files = True,
            mandatory = True,
        ),
        "version_file": attr.label(
            allow_files = True,
            mandatory = True,
        ),
        "_build_upgrade_image_tool": attr.label(
            allow_files = True,
            default = ":build_upgrade_image.py",
        ),
        "_dflate": attr.label(
            allow_files = True,
            default = "//rs/ic_os/dflate",
        ),
    },
)

def _tar_extract_impl(ctx):
    in_tar = ctx.files.src[0]
    out = ctx.actions.declare_file(ctx.label.name)

    ctx.actions.run_shell(
        inputs = [in_tar],
        outputs = [out],
        command = "tar xOf %s --occurrence=1 %s > %s" % (
            in_tar.path,
            ctx.attr.path,
            out.path,
        ),
    )

    return [DefaultInfo(files = depset([out]))]

tar_extract = rule(
    implementation = _tar_extract_impl,
    attrs = {
        "src": attr.label(
            allow_files = True,
            mandatory = True,
        ),
        "path": attr.string(
            mandatory = True,
        ),
    },
)

def _sha256sum_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name)
    input_paths = []
    for src in ctx.files.srcs:
        input_paths.append(src.path)
    input_paths = " ".join(input_paths)

    ctx.actions.run_shell(
        inputs = ctx.files.srcs,
        outputs = [out],
        command = "cat {} | sha256sum | sed -e 's/ \\+-/{}/' > {}".format(input_paths, ctx.attr.suffix, out.path),
    )

    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles([out]))]

sha256sum = rule(
    implementation = _sha256sum_impl,
    attrs = {
        "srcs": attr.label_list(
            allow_files = True,
            mandatory = True,
        ),
        "suffix": attr.string(
            default = "",
        ),
    },
)

def _tree_hash_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name)
    input_paths = []
    for src in sorted(ctx.attr.src.items(), key = lambda v: v[1]):
        input_paths.append(src[0].files.to_list()[0].path)
    input_paths = " ".join(input_paths)

    ctx.actions.run_shell(
        inputs = ctx.files.src,
        outputs = [out],
        command = "cat {} | sha256sum | sed -e 's/ \\+-//' > {}".format(input_paths, out.path),
    )

    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles([out]))]

tree_hash = rule(
    implementation = _tree_hash_impl,
    attrs = {
        "src": attr.label_keyed_string_dict(
            allow_files = True,
            mandatory = True,
        ),
    },
)
