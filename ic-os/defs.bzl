"""
A macro to build multiple versions of the ICOS image (i.e., dev vs prod).

This macro defines the overall build process for ICOS images, including:
  - Version management.
  - Building bootloader, container, and filesystem images.
  - Injecting variant-specific extra partitions via a custom mechanism.
  - Assembling the final disk image and upload targets.
  - Additional developer and test utilities.
"""

load("@bazel_skylib//rules:copy_file.bzl", "copy_file")
load("//bazel:defs.bzl", "zstd_compress")
load("//ic-os/bootloader:defs.bzl", "build_grub_partition")
load("//ic-os/components:defs.bzl", "tree_hash")
load("//ic-os/components/conformance_tests:defs.bzl", "component_file_references_test")
load("//toolchains/sysimage:toolchain.bzl", "build_container_base_image", "build_container_filesystem", "disk_image", "disk_image_no_tar", "ext4_image", "upgrade_image")
load("@rules_rust//rust:rust_common.bzl", "CrateInfo", "DepInfo")
load("@bazel_skylib//lib:paths.bzl", "paths")

def icos_build(
        name,
        image_deps_func,
        mode = None,
        malicious = False,
        upgrades = True,
        vuln_scan = True,
        visibility = None,
        tags = None,
        build_local_base_image = False,
        ic_version = "//bazel:version.txt"):
    """
    Generic ICOS build tooling.

    Args:
      name: Name for the generated filegroup.
      image_deps_func: Function to be used to generate image manifest
      mode: dev or prod. If not specified, will use the value of `name`
      malicious: if True, bundle the `malicious_replica`
      upgrades: if True, build upgrade images as well
      vuln_scan: if True, create targets for vulnerability scanning
      visibility: See Bazel documentation
      tags: See Bazel documentation
      build_local_base_image: if True, build the base images from scratch. Do not download the docker.io base image.
      ic_version: the label pointing to the target that returns IC version

    Returns:
      A struct containing the labels of the images that were built.
    """

    if mode == None:
        mode = name

    image_deps = image_deps_func(mode, malicious)

    # -------------------- Version management --------------------

    copy_file(
        name = "copy_version_txt",
        src = ic_version,
        out = "version.txt",
        allow_symlink = True,
        visibility = ["//visibility:public"],
        tags = ["manual"],
    )

    if upgrades:
        native.genrule(
            name = "test_version_txt",
            srcs = [":copy_version_txt"],
            outs = ["version-test.txt"],
            cmd = "sed -e 's/.*/&-test/' < $< > $@",
            tags = ["manual"],
        )

    # -------------------- Build grub partition --------------------

    build_grub_partition("partition-grub.tzst", grub_config = image_deps.get("grub_config", default = None), tags = ["manual"])

    # -------------------- Build the container image --------------------

    if build_local_base_image:
        base_image_tag = "base-image-" + name  # Reuse for build_container_filesystem_tar
        package_files_arg = "PACKAGE_FILES=packages.common"
        if "dev" in mode:
            package_files_arg += " packages.dev"

        build_container_base_image(
            name = "base_image.tar",
            context_files = [image_deps["container_context_files"]],
            image_tag = base_image_tag,
            dockerfile = image_deps["base_dockerfile"],
            build_args = [package_files_arg],
            target_compatible_with = ["@platforms//os:linux"],
            tags = ["manual"],
        )

        build_container_filesystem(
            name = "rootfs-tree.tar",
            context_files = [image_deps["container_context_files"]],
            component_files = image_deps["component_files"],
            dockerfile = image_deps["dockerfile"],
            build_args = image_deps["build_args"],
            file_build_arg = image_deps["file_build_arg"],
            base_image_tar_file = ":base_image.tar",
            base_image_tar_file_tag = base_image_tag,
            target_compatible_with = ["@platforms//os:linux"],
            tags = ["manual"],
        )
    else:
        build_container_filesystem(
            name = "rootfs-tree.tar",
            context_files = [image_deps["container_context_files"]],
            component_files = image_deps["component_files"],
            dockerfile = image_deps["dockerfile"],
            build_args = image_deps["build_args"],
            file_build_arg = image_deps["file_build_arg"],
            target_compatible_with = ["@platforms//os:linux"],
            tags = ["manual"],
        )

    # Extract SElinux file_contexts to use later when building ext4 filesystems
    tar_extract(
        name = "file_contexts",
        src = "rootfs-tree.tar",
        path = "etc/selinux/default/contexts/files/file_contexts",
        target_compatible_with = ["@platforms//os:linux"],
        tags = ["manual"],
    )

    # -------------------- Extract root and boot partitions --------------------

    # NOTE: e2fsdroid does not support filenames with spaces, fortunately,
    # these only occur in firmware that we do not use.
    PARTITION_ROOT_STRIP_PATHS = [
        "/run",
        "/boot",
        "/var",
        "/usr/lib/firmware/brcm/brcmfmac43241b4-sdio.Intel Corp.-VALLEYVIEW C0 PLATFORM.txt.zst",
        "/usr/lib/firmware/brcm/brcmfmac43340-sdio.ASUSTeK COMPUTER INC.-TF103CE.txt.zst",
        "/usr/lib/firmware/brcm/brcmfmac43362-sdio.ASUSTeK COMPUTER INC.-ME176C.txt.zst",
        "/usr/lib/firmware/brcm/brcmfmac43430a0-sdio.ONDA-V80 PLUS.txt.zst",
        "/usr/lib/firmware/brcm/brcmfmac43455-sdio.MINIX-NEO Z83-4.txt.zst",
        "/usr/lib/firmware/brcm/brcmfmac43455-sdio.Raspberry Pi Foundation-Raspberry Pi 4 Model B.txt.zst",
        "/usr/lib/firmware/brcm/brcmfmac43455-sdio.Raspberry Pi Foundation-Raspberry Pi Compute Module 4.txt.zst",
        "/usr/lib/firmware/brcm/brcmfmac4356-pcie.Intel Corporation-CHERRYVIEW D1 PLATFORM.txt.zst",
        "/usr/lib/firmware/brcm/brcmfmac4356-pcie.Xiaomi Inc-Mipad2.txt.zst",
    ]

    # Generate partition images for default image and test image (when upgrades is True).
    for test_suffix in (["", "-test"] if upgrades else [""]):
        partition_root = "partition-root" + test_suffix
        partition_root_unsigned_tzst = partition_root + "-unsigned.tzst"
        partition_root_unsigned_tzst_base = partition_root + "-unsigned-base.tzst"
        partition_root_signed_tzst = partition_root + ".tzst"
        partition_root_hash = partition_root + "-hash"
        partition_boot_tzst = "partition-boot" + test_suffix + ".tzst"
        version_txt = "version" + test_suffix + ".txt"
        boot_args = "boot" + test_suffix + "_args"
        extra_boot_args = "extra_boot" + test_suffix + "_args"

        ext4_image(
            name = partition_root_unsigned_tzst_base,
            testonly = malicious,
            src = ":rootfs-tree.tar",
            file_contexts = ":file_contexts",
            partition_size = image_deps["rootfs_size"],
            strip_paths = PARTITION_ROOT_STRIP_PATHS,
            extra_files = {
                k: v
                for k, v in (image_deps["rootfs"].items() + [(version_txt, "/opt/ic/share/version.txt:0644")])
            },
            target_compatible_with = ["@platforms//os:linux"],
            tags = ["manual", "no-cache"],
        )
        if mode == "dev":
            dev_wrapper(name = partition_root_unsigned_tzst, actual = partition_root_unsigned_tzst_base, tags = ["manual", "no-cache"])
        else:
            native.alias(name = partition_root_unsigned_tzst, actual = partition_root_unsigned_tzst_base, tags = ["manual", "no-cache"])

        ext4_image(
            name = partition_boot_tzst,
            src = ":rootfs-tree.tar",
            file_contexts = ":file_contexts",
            partition_size = image_deps["bootfs_size"],
            subdir = "boot",
            target_compatible_with = ["@platforms//os:linux"],
            extra_files = {
                k: v
                for k, v in (
                    image_deps["bootfs"].items() + [
                        (version_txt, "/version.txt:0644"),
                        (extra_boot_args, "/extra_boot_args:0644"),
                    ] + ([(boot_args, "/boot_args:0644")] if "boot_args_template" in image_deps else [])
                )
            },
            tags = ["manual", "no-cache"],
        )

        # The kernel command line (boot args) was previously split into two parts:
        # 1. Dynamic args calculated at boot time in grub.cfg
        # 2. Static args stored in EXTRA_BOOT_ARGS on the boot partition
        #
        # For stable and predictable measurements with AMD SEV, we now pre-calculate and combine both parts
        # into a single complete kernel command line that is:
        # - Generated during image build
        # - Stored statically on the boot partition
        # - Measured as part of the SEV launch measurement
        #
        # For backwards compatibility in the GuestOS and compatibility with the HostOS and SetupOS, we continue
        # to support the old way of calculating the dynamic args (see :extra_boot_args) and we derive boot_args
        # from it.
        native.genrule(
            name = "generate-" + boot_args,
            outs = [boot_args],
            srcs = [extra_boot_args, ":boot_args_template"],
            cmd = """
                source "$(location """ + extra_boot_args + """)"
                if [ ! -v EXTRA_BOOT_ARGS ]; then
                    echo "EXTRA_BOOT_ARGS is not set in $(location """ + extra_boot_args + """)"
                    exit 1
                fi
                m4 --define=EXTRA_BOOT_ARGS="$${EXTRA_BOOT_ARGS}" "$(location :boot_args_template)" > $@
            """,
            tags = ["manual"],
        )

        # Sign only if extra_boot_args_template is provided
        if "extra_boot_args_template" in image_deps:
            extra_boot_args_template = str(image_deps["extra_boot_args_template"])
            native.genrule(
                name = "generate-" + partition_root_signed_tzst,
                testonly = malicious,
                srcs = [partition_root_unsigned_tzst],
                outs = [partition_root_signed_tzst, partition_root_hash],
                cmd = "$(location //toolchains/sysimage:proc_wrapper) " +
                      "$(location //toolchains/sysimage:verity_sign) " +
                      "-i $< -o $(location :" + partition_root_signed_tzst + ") " +
                      "-r $(location " + partition_root_hash + ") " +
                      "--dflate $(location //rs/ic_os/build_tools/dflate)",
                executable = False,
                tools = [
                    "//toolchains/sysimage:proc_wrapper",
                    "//toolchains/sysimage:verity_sign",
                    "//rs/ic_os/build_tools/dflate",
                ],
                tags = ["manual", "no-cache"],
            )

            native.genrule(
                name = "generate-" + extra_boot_args,
                srcs = [extra_boot_args_template, partition_root_hash],
                outs = [extra_boot_args],
                cmd = "sed -e s/ROOT_HASH/$$(cat $(location " + partition_root_hash + "))/ " +
                      "< $(location " + extra_boot_args_template + ") > $@",
                tags = ["manual"],
            )
        else:
            native.alias(name = partition_root_signed_tzst, actual = partition_root_unsigned_tzst, tags = ["manual", "no-cache"])
            native.alias(name = extra_boot_args, actual = image_deps["extra_boot_args"], tags = ["manual"])

    component_file_references_test(
        name = name + "_component_file_references_test",
        image = ":partition-root-unsigned.tzst",
        component_files = image_deps["component_files"].keys(),
        # Inherit tags for this test, to avoid triggering builds for local base images
        tags = tags,
    )

    if "boot_args_template" in image_deps:
        native.alias(
            name = "boot_args_template",
            actual = image_deps["boot_args_template"],
        )

    # -------------------- Assemble disk partitions ---------------

    # Build a list of custom partitions to allow "injecting" variant-specific partition logic.
    custom_partitions = image_deps.get("custom_partitions", lambda mode: [])(mode)

    partitions = [
        "//ic-os/bootloader:partition-esp.tzst",
        ":partition-grub.tzst",
        ":partition-boot.tzst",
        ":partition-root.tzst",
    ] + custom_partitions

    # -------------------- Assemble disk image --------------------

    disk_image(
        name = "disk-img.tar",
        layout = image_deps["partition_table"],
        partitions = partitions,
        expanded_size = image_deps.get("expanded_size", default = None),
        tags = ["manual", "no-cache"],
        target_compatible_with = ["@platforms//os:linux"],
    )

    # Disk images just for testing.
    disk_image_no_tar(
        name = "disk.img",
        layout = image_deps["partition_table"],
        partitions = partitions,
        expanded_size = image_deps.get("expanded_size", default = None),
        tags = ["manual", "no-cache"],
        target_compatible_with = ["@platforms//os:linux"],
    )

    zstd_compress(
        name = "disk-img.tar.zst",
        srcs = [":disk-img.tar"],
        visibility = visibility,
        tags = ["manual"],
    )

    # -------------------- Assemble upgrade image --------------------

    if upgrades:
        for test_suffix in ["", "-test"]:
            update_image_tar = "update-img" + test_suffix + ".tar"

            upgrade_image(
                name = update_image_tar,
                boot_partition = ":partition-boot" + test_suffix + ".tzst",
                root_partition = ":partition-root" + test_suffix + ".tzst",
                tags = ["manual", "no-cache"],
                target_compatible_with = ["@platforms//os:linux"],
                version_file = ":version" + test_suffix + ".txt",
            )

            zstd_compress(
                name = update_image_tar + ".zst",
                srcs = [update_image_tar],
                visibility = visibility,
                tags = ["manual"],
            )

    # -------------------- Vulnerability Scanning Tool ------------

    if vuln_scan:
        native.sh_binary(
            name = "vuln-scan",
            srcs = ["//ic-os:vuln-scan/vuln-scan.sh"],
            data = [
                "@trivy//:trivy",
                ":rootfs-tree.tar",
                "//ic-os:vuln-scan/vuln-scan.html",
            ],
            env = {
                "trivy_path": "$(rootpath @trivy//:trivy)",
                "CONTAINER_TAR": "$(rootpaths :rootfs-tree.tar)",
                "TEMPLATE_FILE": "$(rootpath //ic-os:vuln-scan/vuln-scan.html)",
            },
            tags = ["manual"],
        )

    # -------------------- Tree Hash Tool -------------------------

    # Helpful tool to print a hash of all input component files
    tree_hash(
        name = "component-files-hash",
        src = image_deps["component_files"],
        tags = ["manual"],
    )

    native.genrule(
        name = "echo-component-files-hash",
        srcs = [":component-files-hash"],
        outs = ["component-files-hash-script"],
        cmd = """
        HASH="$(location :component-files-hash)"
        cat <<EOF > $@
#!/usr/bin/env bash
set -euo pipefail
cat $$HASH
EOF
        """,
        executable = True,
        tags = ["manual"],
    )

    # -------------------- VM Developer Tools --------------------

    native.sh_binary(
        name = "launch-remote-vm",
        srcs = ["//ic-os:dev-tools/launch-remote-vm.sh"],
        data = [
            "//rs/ic_os/dev_test_tools/launch-single-vm:launch-single-vm",
            ":disk-img.tar.zst",
            "//rs/tests/nested:empty-disk-img.tar.zst",
            ":version.txt",
            "//bazel:upload_systest_dep",
        ],
        env = {
            "BIN": "$(location //rs/ic_os/dev_test_tools/launch-single-vm:launch-single-vm)",
            "UPLOAD_SYSTEST_DEP": "$(location //bazel:upload_systest_dep)",
            "VERSION_FILE": "$(location :version.txt)",
            "DISK_IMG": "$(location :disk-img.tar.zst)",
            "EMPTY_DISK_IMG_PATH": "$(location //rs/tests/nested:empty-disk-img.tar.zst)",
        },
        testonly = True,
        tags = ["manual"],
    )

    # -------------------- final "return" target --------------------
    # The good practice is to have the last target in the macro with `name = name`.
    # This allows users to just do `bazel build //some/path:macro_instance` without need to know internals of the macro

    native.filegroup(
        name = name,
        testonly = malicious,
        srcs = [
            ":disk-img.tar.zst",
        ] + ([
            ":update-img.tar.zst",
            ":update-img-test.tar.zst",
        ] if upgrades else []),
        visibility = visibility,
        tags = tags,
    )

    icos_images = struct(
        disk_image = ":disk-img.tar.zst",
        update_image = ":update-img.tar.zst",
        update_image_test = ":update-img-test.tar.zst",
    )
    return icos_images

# end def icos_build

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

# Transition that enables dev flag
def _dev_transition_impl(_settings, _attr):
    return {
        "//ic-os:dev": True,
    }

dev_transition = transition(
    implementation = _dev_transition_impl,
    inputs = [],
    outputs = ["//ic-os:dev"],
)


def _dev_wrapper_impl(ctx):
    """Dev wrapper that forwards providers and creates a symlinked executable."""
    if not ctx.attr.actual:
        return [DefaultInfo()]

    # Get the single dependency (actual is not a list in your rule definition)
    dep = ctx.attr.actual
    if type(dep) == type([]):
        dep = dep[0]
    providers = []

    # Forward Rust-specific providers if they exist
    for provider in [CrateInfo, DepInfo]:
        if provider in dep:
            providers.append(dep[provider])

    # Handle DefaultInfo and executable symlinking
    default_info = dep[DefaultInfo]
    original_executable = default_info.files_to_run.executable

    if not original_executable:
        # No executable to wrap, just forward existing providers
        providers.append(default_info)
        return providers

    # Create symlinked executable in subdirectory to avoid collisions
    new_executable = ctx.actions.declare_file(
        paths.join(ctx.label.name, original_executable.basename)
    )

    ctx.actions.symlink(
        output = new_executable,
        target_file = original_executable,
        is_executable = True,
    )

    # Create new DefaultInfo with symlinked executable
    new_files = depset(direct = [new_executable], transitive = [default_info.files])
    new_runfiles = default_info.default_runfiles.merge(ctx.runfiles([new_executable]))

    providers.append(DefaultInfo(
        files = new_files,
        runfiles = new_runfiles,
        executable = new_executable,
    ))

    return providers

dev_wrapper = rule(
    implementation = _dev_wrapper_impl,
    attrs = {
        "actual": attr.label(
            cfg = dev_transition,
        ),
    },
)
