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
    output_file = ctx.actions.declare_file(ctx.label.name)
    args.extend(["--output", output_file.path])
    outputs.append(output_file)

    for context_file in ctx.files.context_files:
        args.extend(["--context-file", context_file.path])
    inputs.extend(ctx.files.context_files)

    args.extend(["--image_tag", ctx.attr.image_tag])

    args.extend(["--dockerfile", ctx.file.dockerfile.path])
    inputs.append(ctx.file.dockerfile)

    if ctx.attr.build_args:
        args.extend(["--build_args"])
        for build_arg in ctx.attr.build_args:
            args.extend([build_arg])

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [ctx.attr._tool.files_to_run],
        # Base image is NOT reproducible (because `apt install`)
        execution_requirements = {"no-remote-cache": "1"},
    )

    return [DefaultInfo(files = depset(outputs))]

build_container_base_image = _icos_build_rule(
    implementation = _build_container_base_image_impl,
    attrs = {
        "context_files": attr.label_list(
            allow_files = True,
        ),
        "dockerfile": attr.label(
            allow_single_file = True,
            mandatory = True,
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

    # Output file is the name given to the target
    output_file = ctx.actions.declare_file(ctx.label.name)
    args.extend(["--output", output_file.path])
    outputs.append(output_file)

    for context_file in ctx.files.context_files:
        args.extend(["--context-file", context_file.path])
    inputs.extend(ctx.files.context_files)

    for input_target, install_target in ctx.attr.component_files.items():
        args.extend(["--component-file", input_target.files.to_list()[0].path + ":" + install_target])
        inputs.extend(input_target.files.to_list())

    if ctx.file.dockerfile:
        args.extend(["--dockerfile", ctx.file.dockerfile.path])
        inputs.append(ctx.file.dockerfile)

    for build_arg in ctx.attr.build_args:
        args.extend(["--build-arg", build_arg])

    if ctx.attr.file_build_arg:
        args.extend(["--file-build-arg", ctx.attr.file_build_arg])

    if ctx.file.base_image_tar_file:
        args.extend(["--base-image-tar-file", ctx.file.base_image_tar_file.path])
        args.extend(["--base-image-tar-file-tag", ctx.attr.base_image_tar_file_tag])
        inputs.append(ctx.file.base_image_tar_file)

    args.extend(["--no-cache"])

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [ctx.attr._tool.files_to_run],
    )

    return [DefaultInfo(files = depset(outputs))]

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
        "base_image_tar_file_tag": attr.string(),
        "_tool": attr.label(
            default = "//toolchains/sysimage:build_container_filesystem_tar",
            executable = True,
            cfg = "exec",
        ),
    },
)

def icos_image(
        name,
        image_type,
        partition_size = None,
        src = None,
        subdir = None,
        file_contexts = None,
        strip_paths = None,
        extra_files = None,
        label = None,
        **kwargs):
    """
    Build a filesystem image from a tar file.

    Args:
        name: Name of the output file (if compressed format, e.g. .tar.zst, the image will be compressed)
        image_type: Type of image to create ("tar", "ext4", "vfat", "fat32")
        partition_size: Size of the partition (e.g., "100M", "1G"). Required for ext4, vfat, and fat32, not allowed for tar.
        src: Optional input tar file
        subdir: Optional subdirectory to extract from input tar
        file_contexts: Optional SELinux file_contexts file
        strip_paths: Optional list of paths to remove from the tree
        extra_files: Optional dict of extra files to inject (label -> target path)
        label: Optional volume label (for fat32 filesystems)
    """

    # All image types are now handled directly by the build_fs_tar binary
    _icos_image_impl_rule(
        name = name,
        src = src,
        output = name,
        image_type = image_type,
        partition_size = partition_size or "",
        subdir = subdir,
        file_contexts = file_contexts,
        strip_paths = strip_paths or [],
        extra_files = extra_files or {},
        label = label or "",
        **kwargs
    )

def tar_image(name, **kwargs):
    icos_image(
        name = name,
        image_type = "tar",
        **kwargs
    )

def ext4_image(name, **kwargs):
    icos_image(
        name = name,
        image_type = "ext4",
        **kwargs
    )

def vfat_image(name, **kwargs):
    icos_image(
        name = name,
        image_type = "vfat",
        **kwargs
    )

def fat32_image(name, **kwargs):
    icos_image(
        name = name,
        image_type = "fat32",
        **kwargs
    )

def _icos_image_impl_rule_impl(ctx):
    args = []
    inputs = []
    outputs = []

    output_file = ctx.actions.declare_file(ctx.attr.output)
    args.extend(["-o", output_file.path])
    outputs.append(output_file)

    if ctx.files.src:
        for src_file in ctx.files.src:
            args.extend(["-i", src_file.path])
        inputs.extend(ctx.files.src)

    args.extend(["-t", ctx.attr.image_type])

    if ctx.attr.partition_size:
        args.extend(["--partition-size", ctx.attr.partition_size])

    if ctx.attr.label:
        args.extend(["--label", ctx.attr.label])

    if ctx.attr.subdir:
        args.extend(["-p", ctx.attr.subdir])

    if ctx.attr.file_contexts:
        args.extend(["-S", ctx.files.file_contexts[0].path])
        inputs.extend(ctx.files.file_contexts)

    if ctx.attr.strip_paths:
        args.extend(["--strip-paths"] + ctx.attr.strip_paths)

    if ctx.attr.extra_files:
        args.append("--extra-files")
    for input_target, install_target in ctx.attr.extra_files.items():
        args.append(input_target.files.to_list()[0].path + ":" + install_target)
        inputs.extend(input_target.files.to_list())

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [ctx.attr._tool.files_to_run],
    )

    return [DefaultInfo(files = depset(outputs))]

_icos_image_impl_rule = _icos_build_rule(
    implementation = _icos_image_impl_rule_impl,
    attrs = {
        "src": attr.label(
            allow_files = True,
        ),
        "output": attr.string(mandatory = True),
        "image_type": attr.string(mandatory = True),
        "partition_size": attr.string(),
        "label": attr.string(),
        "file_contexts": attr.label(
            allow_single_file = True,
        ),
        "strip_paths": attr.string_list(),
        "subdir": attr.string(),
        "extra_files": attr.label_keyed_string_dict(
            allow_files = True,
        ),
        "_tool": attr.label(
            default = "//toolchains/sysimage:build_fs_tar",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _disk_image_impl(ctx):
    args = []
    inputs = []
    outputs = []

    # Output file is the name given to the target
    output_file = ctx.actions.declare_file(ctx.label.name)
    args.extend(["-o", output_file.path])
    outputs.append(output_file)

    args.extend(["-p", ctx.files.layout[0].path, "--dflate", ctx.executable._dflate.path])
    inputs.extend(ctx.files.layout)

    if ctx.attr.expanded_size:
        args.extend(["-s", ctx.attr.expanded_size])

    if ctx.attr.populate_b_partitions:
        args.extend(["--populate-b-partitions"])

    for partition_file in ctx.files.partitions:
        args.append(partition_file.path)
    inputs.extend(ctx.files.partitions)

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [ctx.attr._tool.files_to_run, ctx.attr._dflate.files_to_run],
    )

    return [DefaultInfo(files = depset(outputs))]

disk_image = _icos_build_rule(
    implementation = _disk_image_impl,
    attrs = {
        "layout": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "partitions": attr.label_list(
            allow_files = True,
        ),
        "expanded_size": attr.string(),
        "populate_b_partitions": attr.bool(default = False),
        "_tool": attr.label(
            default = "//toolchains/sysimage:build_disk_image",
            executable = True,
            cfg = "exec",
        ),
        "_dflate": attr.label(
            default = "//rs/ic_os/build_tools/dflate",
            executable = True,
            cfg = "exec",
        ),
    },
)

# I had to copy pasta this from above because I did not know how
# to genericize the tools and the dflate argument being empty.
# this really shouldn't be two separate things, but rather one
# thing that produces the image and another that tars it.
def _disk_image_no_tar_impl(ctx):
    args = []
    inputs = []
    outputs = []

    # Output file is the name given to the target
    output_file = ctx.actions.declare_file(ctx.label.name)
    args.extend(["-o", output_file.path])
    outputs.append(output_file)

    args.extend(["-p", ctx.files.layout[0].path])
    inputs.extend(ctx.files.layout)

    if ctx.attr.expanded_size:
        args.extend(["-s", ctx.attr.expanded_size])

    if ctx.attr.populate_b_partitions:
        args.extend(["--populate-b-partitions"])

    for partition_file in ctx.files.partitions:
        args.append(partition_file.path)
    inputs.extend(ctx.files.partitions)

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [ctx.attr._tool.files_to_run],
    )

    return [DefaultInfo(files = depset(outputs))]

disk_image_no_tar = _icos_build_rule(
    implementation = _disk_image_no_tar_impl,
    attrs = {
        "layout": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "partitions": attr.label_list(
            allow_files = True,
        ),
        "expanded_size": attr.string(),
        "populate_b_partitions": attr.bool(default = False),
        "_tool": attr.label(
            default = "//toolchains/sysimage:build_disk_image",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _lvm_image_impl(ctx):
    args = []
    inputs = []
    outputs = []

    # Output file is the name given to the target
    output_file = ctx.actions.declare_file(ctx.label.name)
    args.extend(["-o", output_file.path])
    outputs.append(output_file)

    args.extend([
        "-v",
        ctx.files.layout[0].path,
        "-n",
        ctx.attr.vg_name,
        "-u",
        ctx.attr.vg_uuid,
        "-p",
        ctx.attr.pv_uuid,
        "--dflate",
        ctx.executable._dflate.path,
    ])
    inputs.extend(ctx.files.layout)

    for partition_file in ctx.files.partitions:
        args.append(partition_file.path)
    inputs.extend(ctx.files.partitions)

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [ctx.attr._tool.files_to_run, ctx.attr._dflate.files_to_run],
    )

    return [DefaultInfo(files = depset(outputs))]

lvm_image = _icos_build_rule(
    implementation = _lvm_image_impl,
    attrs = {
        "layout": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "partitions": attr.label_list(
            allow_files = True,
        ),
        "vg_name": attr.string(mandatory = True),
        "vg_uuid": attr.string(mandatory = True),
        "pv_uuid": attr.string(mandatory = True),
        "_tool": attr.label(
            default = "//toolchains/sysimage:build_lvm_image",
            executable = True,
            cfg = "exec",
        ),
        "_dflate": attr.label(
            default = "//rs/ic_os/build_tools/dflate",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _upgrade_image_impl(ctx):
    args = []
    inputs = []
    outputs = []

    # Output file is the name given to the target
    output_file = ctx.actions.declare_file(ctx.label.name)
    args.extend(["-o", output_file.path])
    outputs.append(output_file)

    args.extend([
        "-b",
        ctx.files.boot_partition[0].path,
        "-r",
        ctx.files.root_partition[0].path,
        "-v",
        ctx.files.version_file[0].path,
        "--dflate",
        ctx.executable._dflate.path,
    ])
    inputs.extend(ctx.files.boot_partition + ctx.files.root_partition + ctx.files.version_file)

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [ctx.attr._tool.files_to_run, ctx.attr._dflate.files_to_run],
    )

    return [DefaultInfo(files = depset(outputs))]

upgrade_image = _icos_build_rule(
    implementation = _upgrade_image_impl,
    attrs = {
        "boot_partition": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "root_partition": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "version_file": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "_tool": attr.label(
            default = "//toolchains/sysimage:build_upgrade_image",
            executable = True,
            cfg = "exec",
        ),
        "_dflate": attr.label(
            default = "//rs/ic_os/build_tools/dflate",
            executable = True,
            cfg = "exec",
        ),
    },
)
