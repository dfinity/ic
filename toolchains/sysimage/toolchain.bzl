"""
Tools for building IC OS image.
"""

# Mnemonics of the actions that run `podman build`: only the from-scratch base
# image builds of the local-base-* images. Rootless podman needs to create user
# namespaces, so bazel/conf/.bazelrc.build forces these (and only these) to run
# locally, outside the sandbox. All other actions of this file only operate on
# plain image files (or boot a microVM) and run sandboxed or remotely.
ICOS_CONTAINER_MNEMONICS = ["IcosContainerBaseImage"]

def _run_with_wrapper(ctx, wrapper, executable, arguments, tools, execution_requirements, inputs, **kwargs):
    ctx.actions.run(
        executable = wrapper.files_to_run.executable,
        arguments = [executable] + arguments,
        # Besides their declared tools, the image actions use some tools of the dev-container image
        # (fakeroot, libfaketime, tar, sfdisk, veritysetup, ...), which aren't Bazel inputs. Its
        # tag stands in for them, so that a new image doesn't serve images built with the old tools
        # from the cache.
        inputs = inputs + [ctx.file._icos_host_tools],
        tools = tools + [wrapper.files_to_run],
        execution_requirements = execution_requirements |
                                 {"supports-graceful-termination": "1"},
        **kwargs
    )

# Similar to ctx.actions.run but runs the command wrapped in the podman process
# wrapper that sets up a private podman storage. Only for the actions with a
# mnemonic in ICOS_CONTAINER_MNEMONICS. Can only be used in rules defined by
# _icos_build_rule.
def _run_with_podman_wrapper(ctx, executable, arguments = [], tools = [], execution_requirements = {}, inputs = [], **kwargs):
    if kwargs.get("mnemonic") not in ICOS_CONTAINER_MNEMONICS:
        fail("podman actions must use a mnemonic of ICOS_CONTAINER_MNEMONICS")
    _run_with_wrapper(ctx, ctx.attr._icos_build_proc_wrapper, executable, arguments, tools, execution_requirements, inputs, **kwargs)

# Similar to ctx.actions.run but runs the command with a private TMPDIR that is
# cleaned up afterwards. Can only be used in rules defined by _icos_build_rule.
def _run_with_icos_wrapper(ctx, executable, arguments = [], tools = [], execution_requirements = {}, inputs = [], **kwargs):
    _run_with_wrapper(ctx, ctx.attr._icos_tmpdir_wrapper, executable, arguments, tools, execution_requirements, inputs, **kwargs)

def _icos_build_rule(attrs = {}, **kwargs):
    return rule(
        attrs = attrs | {
            "_icos_build_proc_wrapper": attr.label(
                default = ":proc_wrapper",
                executable = True,
                cfg = "exec",
                allow_files = True,
            ),
            "_icos_tmpdir_wrapper": attr.label(
                default = ":tmpdir_wrapper",
                executable = True,
                cfg = "exec",
                allow_files = True,
            ),
            "_icos_host_tools": attr.label(
                default = "//:ci/container/TAG",
                allow_single_file = True,
            ),
        },
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

    _run_with_podman_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [ctx.attr._tool.files_to_run],
        mnemonic = "IcosContainerBaseImage",
        progress_message = "Building container base image %{output}",
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

IcosBaseRootfsInfo = provider(
    doc = "A base container image flattened into a root filesystem tar.",
    fields = {
        "rootfs": "File: the root filesystem tar",
        "env": "File: JSON list of the image's environment",
    },
)

def _oci_rootfs_impl(ctx):
    rootfs = ctx.actions.declare_file(ctx.label.name + ".tar")
    env = ctx.actions.declare_file(ctx.label.name + ".env.json")
    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = [
            "--layout",
            ctx.file.layout.path,
            "--output",
            rootfs.path,
            "--env-output",
            env.path,
        ],
        inputs = [ctx.file.layout],
        outputs = [rootfs, env],
        tools = [ctx.attr._tool.files_to_run],
        mnemonic = "IcosOciRootfs",
        progress_message = "Flattening base image %{label}",
    )
    return [
        DefaultInfo(files = depset([rootfs, env])),
        IcosBaseRootfsInfo(rootfs = rootfs, env = env),
    ]

oci_rootfs = _icos_build_rule(
    implementation = _oci_rootfs_impl,
    doc = "Flattens an OCI image layout (e.g. from oci_pull) into a root filesystem tar.",
    attrs = {
        "layout": attr.label(
            allow_single_file = True,
            mandatory = True,
            doc = "The OCI image layout directory (e.g. from oci_pull), or an OCI archive of one " +
                  "(from build_container_base_image).",
        ),
        "_tool": attr.label(
            default = "//toolchains/sysimage:oci_rootfs",
            executable = True,
            cfg = "exec",
        ),
    },
)

# The resources of the container build VM, reserved for its action so that Bazel
# doesn't run more of them concurrently than the machine can hold.
_VM_CPUS = 4
_VM_MEMORY_MB = 4096

def _vm_resources(_os, _inputs_size):
    # The VM's memory, plus QEMU and the build tool around it.
    return {"cpu": _VM_CPUS, "memory": _VM_MEMORY_MB + 512}

def _build_container_filesystem_vm(ctx, output_file):
    args = ["--output", output_file.path]
    inputs = []

    for context_file in ctx.files.context_files:
        args.extend(["--context-file", context_file.path])
    inputs.extend(ctx.files.context_files)

    for input_target, install_target in ctx.attr.component_files.items():
        args.extend(["--component-file", input_target.files.to_list()[0].path + ":" + install_target])
        inputs.extend(input_target.files.to_list())

    args.extend(["--dockerfile", ctx.file.dockerfile.path])
    inputs.append(ctx.file.dockerfile)

    for build_arg in ctx.attr.build_args:
        args.extend(["--build-arg", build_arg])

    if ctx.attr.file_build_arg:
        args.extend(["--file-build-arg", ctx.attr.file_build_arg])

    base = ctx.attr.base_rootfs[IcosBaseRootfsInfo]
    args.extend([
        "--base-rootfs",
        base.rootfs.path,
        "--base-env",
        base.env.path,
        "--base-image-ref",
        ctx.file.base_image_ref.path,
        "--kernel",
        ctx.file._kernel.path,
        "--qemu",
        ctx.file._qemu.path,
        "--qemu-data",
        ctx.file._qemu_data.path,
        "--mke2fs",
        ctx.file._mke2fs.path,
        "--cpus",
        str(_VM_CPUS),
        "--memory",
        "{}M".format(_VM_MEMORY_MB),
    ])
    inputs.extend([base.rootfs, base.env, ctx.file.base_image_ref, ctx.file._kernel, ctx.file._qemu, ctx.file._qemu_data, ctx.file._mke2fs])

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._vm_tool.path,
        arguments = args,
        inputs = inputs,
        outputs = [output_file],
        tools = [ctx.attr._vm_tool.files_to_run],
        mnemonic = "IcosContainerVmBuild",
        resource_set = _vm_resources,
        progress_message = "Building container filesystem %{output} in a microVM",
    )

def _build_container_filesystem_impl(ctx):
    # Output file is the name given to the target
    output_file = ctx.actions.declare_file(ctx.label.name)
    _build_container_filesystem_vm(ctx, output_file)
    return [DefaultInfo(files = depset([output_file]))]

build_container_filesystem = _icos_build_rule(
    implementation = _build_container_filesystem_impl,
    doc = "Builds a Dockerfile on a base image in a KVM microVM and exports the filesystem as a tar.",
    attrs = {
        "context_files": attr.label_list(
            allow_files = True,
        ),
        "component_files": attr.label_keyed_string_dict(
            allow_files = True,
        ),
        "dockerfile": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "build_args": attr.string_list(),
        "file_build_arg": attr.string(),
        "base_rootfs": attr.label(
            providers = [IcosBaseRootfsInfo],
            mandatory = True,
            doc = "The flattened base image (oci_rootfs) that the Dockerfile builds on.",
        ),
        "base_image_ref": attr.label(
            allow_single_file = True,
            mandatory = True,
            doc = "The docker-base* file that the Dockerfile's FROM names. base_rootfs is that " +
                  "image, except for the local-base-* images, whose base_rootfs replaces it " +
                  "(like `podman build --from`).",
        ),
        "_vm_tool": attr.label(
            default = "//toolchains/sysimage:build_container_filesystem_vm",
            executable = True,
            cfg = "exec",
        ),
        # In the target configuration, to share the flattened GuestOS base
        # image with the GuestOS builds.
        "_kernel": attr.label(
            default = "//toolchains/sysimage:build_vm_kernel",
            allow_single_file = True,
        ),
        "_qemu": attr.label(
            default = "@qemu_system_bin_prebuilt_linux_amd64_x86_64_softmmu//:qemu-system-x86_64",
            allow_single_file = True,
            cfg = "exec",
        ),
        "_qemu_data": attr.label(
            default = "@qemu_system_data_prebuilt_linux_amd64//:qemu-system-data",
            allow_single_file = True,
            cfg = "exec",
        ),
        "_mke2fs": attr.label(
            default = "//:mke2fs",
            allow_single_file = True,
            cfg = "exec",
        ),
    },
)

def _vfat_image_impl(ctx):
    args = []
    inputs = []
    outputs = []

    # Output file is the name given to the target
    output_file = ctx.actions.declare_file(ctx.label.name)
    args.extend(["-o", output_file.path])
    outputs.append(output_file)

    for src_file in ctx.files.src:
        args.extend(["-i", src_file.path])
    inputs.extend(ctx.files.src)

    inputs.extend([ctx.file._mkfs_fat, ctx.file._mtools])

    args.extend([
        "-s",
        ctx.attr.partition_size,
        "-p",
        ctx.attr.subdir,
        "--dflate",
        ctx.executable._dflate.path,
        "--zstd",
        ctx.executable._zstd.path,
        "--mkfs-fat",
        ctx.file._mkfs_fat.path,
        "--mtools",
        ctx.file._mtools.path,
    ])

    for input_target, install_target in ctx.attr.extra_files.items():
        args.append(input_target.files.to_list()[0].path + ":" + install_target)
        inputs.extend(input_target.files.to_list())

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [ctx.attr._tool.files_to_run, ctx.attr._dflate.files_to_run, ctx.attr._zstd.files_to_run],
        mnemonic = "IcosVfatImage",
        progress_message = "Building vfat image %{output}",
    )

    return [DefaultInfo(files = depset(outputs))]

vfat_image = _icos_build_rule(
    implementation = _vfat_image_impl,
    attrs = {
        "src": attr.label(
            allow_files = True,
        ),
        "extra_files": attr.label_keyed_string_dict(
            allow_files = True,
        ),
        "partition_size": attr.string(
            mandatory = True,
        ),
        "subdir": attr.string(
            default = "/",
        ),
        "_tool": attr.label(
            default = "//toolchains/sysimage:build_vfat_image",
            executable = True,
            cfg = "exec",
        ),
        "_dflate": attr.label(
            default = "//rs/ic_os/build_tools/dflate",
            executable = True,
            cfg = "exec",
        ),
        "_zstd": attr.label(
            default = "@zstd//:zstd_cli",
            executable = True,
            cfg = "exec",
        ),
        "_mkfs_fat": attr.label(
            default = "@dosfstools//:mkfs.fat",
            cfg = "exec",
            allow_single_file = True,
        ),
        "_mtools": attr.label(
            default = "@mtools//:mtools",
            cfg = "exec",
            allow_single_file = True,
        ),
    },
)

def _fat32_image_impl(ctx):
    args = []
    inputs = []
    outputs = []

    # Output file is the name given to the target
    output_file = ctx.actions.declare_file(ctx.label.name)
    args.extend(["-o", output_file.path])
    outputs.append(output_file)

    for src_file in ctx.files.src:
        args.extend(["-i", src_file.path])
    inputs.extend(ctx.files.src)

    inputs.extend([ctx.file._mkfs_fat, ctx.file._mtools, ctx.file._fatlabel])

    args.extend([
        "-s",
        ctx.attr.partition_size,
        "-p",
        ctx.attr.subdir,
        "--dflate",
        ctx.executable._dflate.path,
        "--zstd",
        ctx.executable._zstd.path,
        "--fatlabel",
        ctx.file._fatlabel.path,
        "--mkfs-fat",
        ctx.file._mkfs_fat.path,
        "--mtools",
        ctx.file._mtools.path,
    ])

    for input_target, install_target in ctx.attr.extra_files.items():
        args.append(input_target.files.to_list()[0].path + ":" + install_target)
        inputs.extend(input_target.files.to_list())

    if ctx.attr.label:
        args.extend(["-l", ctx.attr.label])

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [ctx.attr._tool.files_to_run, ctx.attr._dflate.files_to_run, ctx.attr._zstd.files_to_run],
        mnemonic = "IcosFat32Image",
        progress_message = "Building fat32 image %{output}",
    )

    return [DefaultInfo(files = depset(outputs))]

fat32_image = _icos_build_rule(
    implementation = _fat32_image_impl,
    attrs = {
        "src": attr.label(
            allow_files = True,
        ),
        "extra_files": attr.label_keyed_string_dict(
            allow_files = True,
        ),
        "partition_size": attr.string(
            mandatory = True,
        ),
        "label": attr.string(),
        "subdir": attr.string(
            default = "/",
        ),
        "_tool": attr.label(
            default = "//toolchains/sysimage:build_fat32_image",
            executable = True,
            cfg = "exec",
        ),
        "_dflate": attr.label(
            default = "//rs/ic_os/build_tools/dflate",
            executable = True,
            cfg = "exec",
        ),
        "_zstd": attr.label(
            default = "@zstd//:zstd_cli",
            executable = True,
            cfg = "exec",
        ),
        "_fatlabel": attr.label(
            default = "@dosfstools//:fatlabel",
            cfg = "exec",
            allow_single_file = True,
        ),
        "_mkfs_fat": attr.label(
            default = "@dosfstools//:mkfs.fat",
            cfg = "exec",
            allow_single_file = True,
        ),
        "_mtools": attr.label(
            default = "@mtools//:mtools",
            cfg = "exec",
            allow_single_file = True,
        ),
    },
)

def _ext4_image_impl(ctx):
    args = []
    inputs = []
    outputs = []

    # Output file is the name given to the target
    output_file = ctx.actions.declare_file(ctx.label.name)
    args.extend(["-o", output_file.path])
    outputs.append(output_file)

    for src_file in ctx.files.src:
        args.extend(["-i", src_file.path])
    inputs.extend(ctx.files.src)

    inputs.extend([ctx.file._mke2fs])
    inputs.extend([ctx.file._e2fsdroid])

    args.extend([
        "-s",
        ctx.attr.partition_size,
        "-p",
        ctx.attr.subdir,
        "--diroid",
        ctx.executable._diroid.path,
        "--dflate",
        ctx.executable._dflate.path,
        "--zstd",
        ctx.executable._zstd.path,
        "--mkfs-ext4",
        ctx.file._mke2fs.path,
        "--e2fsdroid",
        ctx.file._e2fsdroid.path,
    ])

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
        tools = [ctx.attr._tool.files_to_run, ctx.attr._diroid.files_to_run, ctx.attr._dflate.files_to_run, ctx.attr._zstd.files_to_run],
        mnemonic = "IcosExt4Image",
        progress_message = "Building ext4 image %{output}",
    )

    return [DefaultInfo(files = depset(outputs))]

ext4_image = _icos_build_rule(
    implementation = _ext4_image_impl,
    attrs = {
        "src": attr.label(
            allow_files = True,
        ),
        "file_contexts": attr.label(
            allow_single_file = True,
        ),
        "strip_paths": attr.string_list(),
        "partition_size": attr.string(
            mandatory = True,
        ),
        "subdir": attr.string(
            default = "/",
        ),
        "extra_files": attr.label_keyed_string_dict(
            allow_files = True,
        ),
        "_tool": attr.label(
            default = "//toolchains/sysimage:build_ext4_image",
            executable = True,
            cfg = "exec",
        ),
        "_mke2fs": attr.label(
            default = "//:mke2fs",
            cfg = "exec",
            allow_single_file = True,
        ),
        "_e2fsdroid": attr.label(
            default = "//:e2fsdroid",
            cfg = "exec",
            allow_single_file = True,
        ),
        "_diroid": attr.label(
            default = "//rs/ic_os/build_tools/diroid",
            executable = True,
            cfg = "exec",
        ),
        "_dflate": attr.label(
            default = "//rs/ic_os/build_tools/dflate",
            executable = True,
            cfg = "exec",
        ),
        "_zstd": attr.label(
            default = "@zstd//:zstd_cli",
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
    args.extend(["--zstd", ctx.executable._zstd.path])
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
        tools = [ctx.attr._tool.files_to_run, ctx.attr._dflate.files_to_run, ctx.attr._zstd.files_to_run],
        mnemonic = "IcosDiskImage",
        progress_message = "Building disk image %{output}",
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
        "_zstd": attr.label(
            default = "@zstd//:zstd_cli",
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
        "--zstd",
        ctx.executable._zstd.path,
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
        tools = [ctx.attr._tool.files_to_run, ctx.attr._dflate.files_to_run, ctx.attr._zstd.files_to_run],
        mnemonic = "IcosLvmImage",
        progress_message = "Building lvm image %{output}",
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
        "_zstd": attr.label(
            default = "@zstd//:zstd_cli",
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

    # Optional overlay image (ext4 .tzst) for the fast upgrade
    if ctx.files.upgrade_overlay:
        args.extend(["--overlay", ctx.files.upgrade_overlay[0].path])
        inputs.extend(ctx.files.upgrade_overlay)

    _run_with_icos_wrapper(
        ctx,
        executable = ctx.executable._tool.path,
        arguments = args,
        inputs = inputs,
        outputs = outputs,
        tools = [ctx.attr._tool.files_to_run, ctx.attr._dflate.files_to_run],
        mnemonic = "IcosUpgradeImage",
        progress_message = "Building upgrade image %{output}",
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
        "upgrade_overlay": attr.label(
            allow_single_file = True,
            mandatory = False,
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
