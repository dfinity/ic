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
load("//bazel:defs.bzl", "gzip_compress", "zstd_compress")
load("//ci/src/artifacts:upload.bzl", "upload_artifacts")
load("//ic-os/bootloader:defs.bzl", "build_grub_partition")
load("//ic-os/components:boundary-guestos.bzl", boundary_component_files = "component_files")
load("//ic-os/components:defs.bzl", "tree_hash")
load("//ic-os/components/conformance_tests:defs.bzl", "component_file_references_test")
load("//toolchains/sysimage:toolchain.bzl", "build_container_base_image", "build_container_filesystem", "disk_image", "disk_image_no_tar", "ext4_image", "upgrade_image")

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
        installable = False,
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
      installable: if True, create install and debug targets, else create launch ones.
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

    if "extra_boot_args_template" in image_deps:
        native.alias(name = "extra_boot_args_template", actual = image_deps["extra_boot_args_template"], tags = ["manual"])

    # Generate partition images for default image and test image (when upgrades is True).
    for test_suffix in (["", "-test"] if upgrades else [""]):
        partition_root = "partition-root" + test_suffix
        partition_root_unsigned_tzst = partition_root + "-unsigned.tzst"
        partition_root_signed_tzst = partition_root + ".tzst"
        partition_root_hash = partition_root + "-hash"
        partition_boot_tzst = "partition-boot" + test_suffix + ".tzst"
        version_txt = "version" + test_suffix + ".txt"
        boot_args = "boot" + test_suffix + "_args"
        extra_boot_args = "extra_boot" + test_suffix + "_args"

        ext4_image(
            name = partition_root_unsigned_tzst,
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
                        (boot_args, "/boot_args:0644"),
                    ]
                )
            },
            tags = ["manual", "no-cache"],
        )

        # The kernel command line (boot args) was previously split into two parts:
        # 1. Dynamic args calculated at boot time in grub.cfg
        # 2. Static args stored in EXTRA_BOOT_ARGS on the boot partition
        #
        # For stable and predicatable measurements with AMD SEV, we now precalculate and combine both parts
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
                srcs = [":extra_boot_args_template", partition_root_hash],
                outs = [extra_boot_args],
                cmd = "sed -e s/ROOT_HASH/$$(cat $(location " + partition_root_hash + "))/ " +
                      "< $(location :extra_boot_args_template) > $@",
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
            "//ic-os/components:hostos-scripts/build-bootstrap-config-image.sh",
            ":disk-img.tar.zst",
            "//rs/tests/nested:empty-disk-img.tar.zst",
            ":version.txt",
            "//bazel:upload_systest_dep",
        ],
        env = {
            "BIN": "$(location //rs/ic_os/dev_test_tools/launch-single-vm:launch-single-vm)",
            "UPLOAD_SYSTEST_DEP": "$(location //bazel:upload_systest_dep)",
            "SCRIPT": "$(location //ic-os/components:hostos-scripts/build-bootstrap-config-image.sh)",
            "VERSION_FILE": "$(location :version.txt)",
            "DISK_IMG": "$(location :disk-img.tar.zst)",
            "EMPTY_DISK_IMG_PATH": "$(location //rs/tests/nested:empty-disk-img.tar.zst)",
        },
        testonly = True,
        tags = ["manual"],
    )

    native.genrule(
        name = "launch-local-vm-script",
        outs = ["launch_local_vm_script"],
        cmd = """
        cat <<"EOF" > $@
#!/usr/bin/env bash
set -eo pipefail
IMG=$$1
INSTALLABLE=$$2
VIRT=$$3
PREPROC=$$4
PREPROC_FLAGS=$$5
set -u
TEMP=$$(mktemp -d --suffix=.qemu-launch-remote-vm)
# Clean up after ourselves when exiting.
trap 'rm -rf "$$TEMP"' EXIT
CID=$$(($$RANDOM + 3))
cd "$$TEMP"
cp --reflink=auto --sparse=always --no-preserve=mode,ownership "$$IMG" disk.img
if [ "$$PREPROC" != "" ] ; then
    "$$PREPROC" $$PREPROC_FLAGS --image-path disk.img
fi
if [ "$$INSTALLABLE" == "yes" ]
then
    truncate -s 128G target.img
    add_disk="-drive file=target.img,format=raw,if=virtio"
else
    add_disk=
fi
if [ "$$VIRT" == "kvm" ]; then
    qemu-system-x86_64 -machine type=q35,accel=kvm -enable-kvm -nographic -m 4G -bios /usr/share/ovmf/OVMF.fd -device vhost-vsock-pci,guest-cid=$$CID -boot c $$add_disk -drive file=disk.img,format=raw,if=virtio -netdev user,id=user.0,hostfwd=tcp::2222-:22 -device virtio-net,netdev=user.0
    exit $$?
else
    qemu-system-x86_64 -machine type=q35 -nographic -m 4G -bios /usr/share/ovmf/OVMF.fd -boot c $$add_disk -drive file=disk.img,format=raw,if=virtio -netdev user,id=user.0,hostfwd=tcp::2222-:22 -device virtio-net,netdev=user.0
    exit $$?
fi
EOF
        """,
        executable = True,
        tags = ["manual"],
    )

    for accel, variant in (("kvm", ""), ("qemu", " no kvm")):
        if installable:
            # Installable produces interactive-install{,-no-kvm} variants that
            # cause the install to proceed fearlessly and reboot to HostOS.
            # It also produces interactive-debug{,-no-kvm} variants that cause
            # the installer to halt so SetupOS can be interactively debugged without
            # worrying that the installation routine will install then reboot.
            preproc_checks = ["//rs/ic_os/dev_test_tools/setupos-disable-checks:setupos-disable-checks"]
            for action, action_flags in (("install", ""), ("debug", "--defeat-installer")):
                native.genrule(
                    name = "interactive-" + action + variant.replace(" ", "-"),
                    srcs = [":disk.img"],
                    tools = [":launch-local-vm-script"] + preproc_checks,
                    outs = ["interactive_" + action + variant.replace(" ", "_")],
                    cmd = """
            cat <<"EOF" > $@
#!/usr/bin/env bash
set -euo pipefail
exec $(location :launch-local-vm-script) "$$PWD/$(location :disk.img)" yes """ + accel + """ "$$PWD/$(location //rs/ic_os/dev_test_tools/setupos-disable-checks:setupos-disable-checks)" """ + action_flags + """>&2
EOF
                    """,
                    executable = True,
                    tags = ["manual"],
                )
        else:
            # Variants provide KVM / non-KVM support to run inside VMs and containers.
            # VHOST for nested VMs is not configured at the moment (should be possible).
            native.genrule(
                name = "launch-local-vm" + variant.replace(" ", "-"),
                srcs = [":disk.img"],
                tools = [":launch-local-vm-script"],
                outs = ["launch_local_vm" + variant.replace(" ", "_")],
                cmd = """
                cat <<"EOF" > $@
#!/usr/bin/env bash
set -euo pipefail
exec $(location :launch-local-vm-script) "$$PWD/$(location :disk.img)" no """ + accel + """ >&2
EOF
                """,
                executable = True,
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

def boundary_node_icos_build(
        name,
        image_deps_func,
        mode = None,
        visibility = None,
        ic_version = "//bazel:version.txt"):
    """
    A boundary node ICOS build parameterized by mode.

    Args:
      name: Name for the generated filegroup.
      image_deps_func: Function to be used to generate image manifest
      mode: dev, or prod. If not specified, will use the value of `name`
      visibility: See Bazel documentation
      ic_version: the label pointing to the target that returns IC version
    """
    if mode == None:
        mode = name

    image_deps = image_deps_func(mode)

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

    build_grub_partition("partition-grub.tzst", tags = ["manual"])

    build_container_filesystem(
        name = "rootfs-tree.tar",
        context_files = ["//ic-os/boundary-guestos/context:context-files"],
        component_files = boundary_component_files,
        dockerfile = image_deps["dockerfile"],
        build_args = image_deps["build_args"],
        file_build_arg = image_deps["file_build_arg"],
        target_compatible_with = ["@platforms//os:linux"],
        tags = ["manual"],
    )

    # Helpful tool to print a hash of all input component files
    tree_hash(
        name = "component-files-hash",
        src = boundary_component_files,
        tags = ["manual"],
    )

    native.genrule(
        name = "echo-component-files-hash",
        srcs = [
            ":component-files-hash",
        ],
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

    ext4_image(
        name = "partition-config.tzst",
        partition_size = "100M",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual"],
    )

    copy_file(
        name = "copy_version_txt",
        src = ic_version,
        out = "version.txt",
        allow_symlink = True,
        tags = ["manual"],
    )

    ext4_image(
        name = "partition-boot.tzst",
        src = ":rootfs-tree.tar",
        partition_size = "1G",
        subdir = "boot/",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        extra_files = {
            k: v
            for k, v in (
                image_deps["bootfs"].items() + [
                    ("version.txt", "/version.txt:0644"),
                    ("extra_boot_args", "/extra_boot_args:0644"),
                ]
            )
        },
        tags = ["manual", "no-cache"],
    )

    ext4_image(
        name = "partition-root-unsigned.tzst",
        src = ":rootfs-tree.tar",
        partition_size = "3G",
        strip_paths = [
            "/run",
            "/boot",
        ],
        extra_files = {
            k: v
            for k, v in (image_deps["rootfs"].items() + [(":version.txt", "/opt/ic/share/version.txt:0644")])
        },
        tags = ["manual", "no-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    native.genrule(
        name = "partition-root-sign",
        srcs = ["partition-root-unsigned.tzst"],
        outs = ["partition-root.tzst", "partition-root-hash"],
        cmd = "$(location //toolchains/sysimage:proc_wrapper) $(location //toolchains/sysimage:verity_sign) -i $< -o $(location :partition-root.tzst) -r $(location partition-root-hash) --dflate $(location //rs/ic_os/build_tools/dflate)",
        executable = False,
        tools = ["//toolchains/sysimage:proc_wrapper", "//toolchains/sysimage:verity_sign", "//rs/ic_os/build_tools/dflate"],
        tags = ["manual", "no-cache"],
    )

    native.genrule(
        name = "extra_boot_args_root_hash",
        srcs = [
            "//ic-os/boundary-guestos:bootloader/extra_boot_args.template",
            ":partition-root-hash",
        ],
        outs = ["extra_boot_args"],
        cmd = "sed -e s/ROOT_HASH/$$(cat $(location :partition-root-hash))/ < $(location //ic-os/boundary-guestos:bootloader/extra_boot_args.template) > $@",
        tags = ["manual"],
    )

    disk_image(
        name = "disk-img.tar",
        layout = "//ic-os/boundary-guestos:partitions.csv",
        partitions = [
            "//ic-os/bootloader:partition-esp.tzst",
            ":partition-grub.tzst",
            ":partition-config.tzst",
            ":partition-boot.tzst",
            ":partition-root.tzst",
        ],
        expanded_size = "50G",
        tags = ["manual", "no-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    zstd_compress(
        name = "disk-img.tar.zst",
        srcs = ["disk-img.tar"],
        visibility = visibility,
        tags = ["manual"],
    )

    gzip_compress(
        name = "disk-img.tar.gz",
        srcs = ["disk-img.tar"],
        visibility = visibility,
        tags = ["manual"],
    )

    sha256sum(
        name = "disk-img.tar.gz.sha256",
        srcs = [":disk-img.tar.gz"],
        visibility = visibility,
        tags = ["manual"],
    )

    upload_suffix = ""
    if mode == "dev":
        upload_suffix += "-dev"

    upload_artifacts(
        name = "upload_disk-img",
        inputs = [
            ":disk-img.tar.zst",
            ":disk-img.tar.gz",
        ],
        remote_subdir = "boundary-os/disk-img" + upload_suffix,
        visibility = visibility,
    )

    native.filegroup(
        name = name,
        srcs = [":disk-img.tar.zst", ":disk-img.tar.gz"],
        visibility = visibility,
    )

# Only used by boundary_node_icos_build
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

# Only used by boundary_node_icos_build
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

    return [DefaultInfo(files = depset([out]))]

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
