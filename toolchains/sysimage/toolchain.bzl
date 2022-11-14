"""
Tools for building IC OS image.
"""

def _docker_tar_impl(ctx):
    in_dir = ctx.files.src[0]
    tool = ctx.files._build_docker_save_tool[0]
    tar_file = ctx.actions.declare_file(ctx.label.name)
    hash_list_file = ctx.actions.declare_file(ctx.label.name + ".hash-list")

    ctx.actions.run(
        executable = tool.path,
        arguments = ["-o", tar_file.path] + ctx.attr.extra_args_before + ["--", in_dir.path] + ctx.attr.extra_args_after,
        inputs = [in_dir] + ctx.files.dep,
        outputs = [tar_file, hash_list_file],
        tools = [tool],
    )

    return [DefaultInfo(files = depset([tar_file, hash_list_file]))]

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
        "extra_args_before": attr.string_list(),
        "extra_args_after": attr.string_list(),
        "_build_docker_save_tool": attr.label(
            allow_files = True,
            default = ":docker_tar.py",
        ),
    },
)

def _vfat_image_impl(ctx):
    tool = ctx.files._build_vfat_image[0]

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
    ]

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

vfat_image = rule(
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

    if len(ctx.attr.strip_paths) > 0:
        args += ["--strip-paths"] + ctx.attr.strip_paths

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

def _upgrade_image_impl(ctx):
    tool_file = ctx.files._build_upgrade_image_tool[0]

    in_boot_partition = ctx.files.boot_partition[0]
    in_root_partition = ctx.files.root_partition[0]
    in_version_file = ctx.files.version_file[0]
    out = ctx.actions.declare_file(ctx.label.name)

    if ctx.attr.compression:
        compress = "-c %s" % ctx.attr.compression
    else:
        compress = ""

    ctx.actions.run_shell(
        inputs = [in_boot_partition, in_root_partition, in_version_file],
        outputs = [out],
        command = "python3 %s -b %s -r %s -v %s %s -o %s" % (
            tool_file.path,
            in_boot_partition.path,
            in_root_partition.path,
            in_version_file.path,
            compress,
            out.path,
        ),
    )

    return [DefaultInfo(files = depset([out]))]

upgrade_image = rule(
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
        "compression": attr.string(
            default = "",
        ),
        "_build_upgrade_image_tool": attr.label(
            allow_files = True,
            default = ":build_upgrade_image.py",
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

def summary_sha256sum(name, inputs, suffix = ""):
    """Compute summary sha256 of image inputs.

    Args:
      name: Name of the target to be built
      inputs: Input files to hash
      suffix: Suffix string to append to hash (only chars, numbers and dash allowed)

    This macro expands to individual rules that compute the sha256 of the
    individual inputs into the filesystem image artifacts, and computes
    a summary sha256 combining all into a single hash.
    """
    all_deps = {}
    for _, deps in inputs.items():
        all_deps.update(deps)
    labels = []
    for dep in all_deps.keys():
        label = name + "@" + dep.split(":")[1] + ".sha256"
        sha256sum(
            name = label,
            srcs = [dep],
        )
        labels.append(":" + label)
    sha256sum(
        name = name,
        srcs = labels,
        suffix = suffix,
    )
