"""
Tools for building IC OS image.
"""

def _docker_tar_impl(ctx):
    in_dir = ctx.files.src[0]
    tool = ctx.files._build_docker_save_tool[0]
    out = ctx.actions.declare_file(ctx.label.name)

    ctx.actions.run(
        executable = tool.path,
        arguments = ["-o", out.path, "--", in_dir.path] + ctx.attr.extra_args,
        inputs = [in_dir] + ctx.files.dep,
        outputs = [out],
        tools = [tool],
    )

    return [DefaultInfo(files = depset([out]))]

docker_tar = rule(
    implementation = _docker_tar_impl,
    attrs = {
        "src": attr.label(
            allow_files = True,
            mandatory = True,
        ),
        "dep": attr.label_list(
            allow_files = True,
        ),
        "extra_args": attr.string_list(),
        "_build_docker_save_tool": attr.label(
            allow_files = True,
            default = ":docker_tar.py",
        ),
    },
)

def _vfat_image_impl(ctx):
    tool = ctx.files._build_vfat_image[0]

    if len(ctx.files.src) > 0:
        input_args = ["-i", ctx.files.src[0].path]
        inputs = [ctx.files.src[0]]
    else:
        input_args = []
        inputs = []
    out = ctx.actions.declare_file(ctx.label.name)

    ctx.actions.run(
        executable = tool.path,
        arguments = input_args + ["-o", out.path, "-s", ctx.attr.partition_size, "-p", ctx.attr.subdir],
        inputs = inputs,
        outputs = [out],
        tools = [tool],
    )

    return [DefaultInfo(files = depset([out]))]

vfat_image = rule(
    implementation = _vfat_image_impl,
    attrs = {
        "src": attr.label(
            allow_files = True,
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
    },
)

def _ext4_image_impl(ctx):
    tool = ctx.files._build_ext4_image[0]

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
    ]
    if len(ctx.files.file_contexts) > 0:
        args += ["-S", ctx.files.file_contexts[0].path]
        inputs += ctx.files.file_contexts

    for input_target, install_target in ctx.attr.extra_files.items():
        args.append(input_target.files.to_list()[0].path + ":" + install_target)
        inputs += input_target.files.to_list()

    ctx.actions.run(
        executable = tool.path,
        arguments = args,
        inputs = inputs,
        outputs = [out],
        tools = [tool],
    )

    return [DefaultInfo(files = depset([out]))]

ext4_image = rule(
    implementation = _ext4_image_impl,
    attrs = {
        "src": attr.label(
            allow_files = True,
        ),
        "file_contexts": attr.label(
            allow_files = True,
            mandatory = False,
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
        "_build_ext4_image": attr.label(
            allow_files = True,
            default = ":build_ext4_image.py",
        ),
    },
)

def _disk_image_impl(ctx):
    tool_file = ctx.files._build_disk_image_tool[0]

    in_layout = ctx.files.layout[0]
    partitions = ctx.files.partitions
    out = ctx.actions.declare_file(ctx.label.name)

    partition_files = []
    for p in partitions:
        partition_files.append(p.path)

    ctx.actions.run_shell(
        inputs = [in_layout] + partitions,
        outputs = [out],
        command = "python3 %s -p %s -o %s %s" % (
            tool_file.path,
            in_layout.path,
            out.path,
            " ".join(partition_files),
        ),
    )

    return [DefaultInfo(files = depset([out]))]

disk_image = rule(
    implementation = _disk_image_impl,
    attrs = {
        "layout": attr.label(
            allow_files = True,
            mandatory = True,
        ),
        "partitions": attr.label_list(
            allow_files = True,
        ),
        "_build_disk_image_tool": attr.label(
            allow_files = True,
            default = ":build_disk_image.py",
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
