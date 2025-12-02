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
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")
load("//bazel:defs.bzl", "zstd_compress")
load("//ic-os/bootloader:defs.bzl", "build_grub_partition")
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

    # we "declare" lots of different image combinations, though most of
    # them are not actually used. Because CI jobs make heavy use of '//...'
    # we make sure that images aren't built unless explicitly depended on.
    tags = ["manual"] + (tags if tags != None else [])

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
            visibility = ["//visibility:public"],
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

    # Extract initrd and kernel for SEV measurement
    tar_extract(
        name = "extracted_initrd.img",
        src = "rootfs-tree.tar",
        path = "boot/initrd.img-*",
        wildcards = True,
        tags = ["manual"],
    )

    tar_extract(
        name = "extracted_vmlinuz",
        src = "rootfs-tree.tar",
        path = "boot/vmlinuz-*",
        wildcards = True,
        tags = ["manual"],
    )

    # -------------------- Extract root and boot partitions --------------------

    # NOTE: e2fsdroid does not support filenames with spaces, fortunately,
    # these only occur in firmware that we do not use.
    PARTITION_ROOT_STRIP_PATHS = [
        "/run/.+",
        "/boot/.+",
        "/var/.+",
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
        partition_root_signed_tzst = partition_root + ".tzst"
        partition_root_hash = partition_root + "-hash"
        partition_boot_tzst = "partition-boot" + test_suffix + ".tzst"
        version_txt = "version" + test_suffix + ".txt"
        boot_args = "boot" + test_suffix + "_args"
        launch_measurements = "launch-measurements" + test_suffix + ".json"

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
            subdir = "/boot",
            target_compatible_with = ["@platforms//os:linux"],
            extra_files = {
                k: v
                for k, v in (
                    image_deps["bootfs"].items() + [
                        (version_txt, "/version.txt:0644"),
                        (boot_args, "/boot_args:0644"),
                        (image_deps["grub_config"], "/grub.cfg:0644"),
                    ]
                )
            },
            tags = ["manual", "no-cache"],
        )

        # The kernel command line (boot args) is generated from boot_args_template:
        # - For OS requiring root signing: Template includes ROOT_HASH placeholder that gets substituted with dm-verity hash
        # - For OS not requiring root signing: Template is used as-is without ROOT_HASH substitution
        #
        # This provides:
        # - Consistent boot argument handling across all OS types
        # - Predictable measurements for AMD SEV (especially important for signed root partitions)
        # - Static boot arguments stored on the boot partition

        if image_deps.get("requires_root_signing", False):
            # Sign the root partition and substitute ROOT_HASH in boot args
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
                name = "generate-" + boot_args,
                outs = [boot_args],
                srcs = [partition_root_hash, ":boot_args_template"],
                cmd = "sed -e s/ROOT_HASH/$$(cat $(location " + partition_root_hash + "))/ " +
                      "< $(location :boot_args_template) > $@",
                tags = ["manual"],
            )
        else:
            # No signing required, no ROOT_HASH substitution
            native.alias(name = partition_root_signed_tzst, actual = partition_root_unsigned_tzst, tags = ["manual", "no-cache"])
            native.alias(
                name = boot_args,
                actual = ":boot_args_template",
                tags = ["manual"],
            )

        if image_deps.get("generate_launch_measurements", False):
            native.genrule(
                name = "generate-" + launch_measurements,
                outs = [launch_measurements],
                srcs = ["//ic-os/components/ovmf:ovmf_sev", boot_args, ":extracted_initrd.img", ":extracted_vmlinuz"],
                visibility = visibility,
                tools = ["//ic-os:sev-snp-measure"],
                tags = ["manual"],
                cmd = r"""
                    source $(execpath """ + boot_args + """)
                    # Create GuestLaunchMeasurements JSON
                    (for cmdline in "$$BOOT_ARGS_A" "$$BOOT_ARGS_B"; do
                        hex=$$($(execpath //ic-os:sev-snp-measure) --mode snp --vcpus 64 --ovmf "$(execpath //ic-os/components/ovmf:ovmf_sev)" --vcpu-type=EPYC-v4 --append "$$cmdline" --initrd "$(location extracted_initrd.img)" --kernel "$(location extracted_vmlinuz)")
                        # Convert hex string to decimal list, e.g. "abcd" ->  171\\n205
                        measurement=$$(echo -n "$$hex" | fold -w2 | sed "s/^/0x/" | xargs printf "%d\n")
                        jq -na --arg cmd "$$cmdline" --arg m "$$measurement" '{
                          measurement: ($$m | split("\n") | map(tonumber)),
                          metadata: {kernel_cmdline: $$cmd}
                        }'
                    done) | jq -sc "{guest_launch_measurements: .}" > $@
                """,
            )

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
        tags = ["manual"],
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

    disk_image(
        name = "disk-img-for-tests.tar",
        layout = image_deps["partition_table"],
        partitions = partitions,
        expanded_size = image_deps.get("expanded_size", default = None),
        populate_b_partitions = True,
        tags = ["manual", "no-cache"],
        testonly = True,
        target_compatible_with = ["@platforms//os:linux"],
        visibility = [
            "//ic-os:__subpackages__",
            "//rs/ic_os:__subpackages__",
        ],
    )

    # Disk images just for testing.
    disk_image_no_tar(
        name = "disk.img",
        layout = image_deps["partition_table"],
        partitions = partitions,
        expanded_size = image_deps.get("expanded_size", default = None),
        tags = ["manual", "no-cache"],
        target_compatible_with = ["@platforms//os:linux"],
        visibility = visibility,
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
        sh_binary(
            name = "vuln-scan",
            srcs = ["//ic-os:vuln-scan/vuln-scan.sh"],
            data = [
                "//:trivy",
                ":rootfs-tree.tar",
                "//ic-os:vuln-scan/vuln-scan.html",
            ],
            env = {
                "trivy_path": "$(rootpath //:trivy)",
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

    if image_deps.get("generate_launch_measurements", False):
        icos_images = struct(
            disk_image = ":disk-img.tar.zst",
            update_image = ":update-img.tar.zst",
            update_image_test = ":update-img-test.tar.zst",
            launch_measurements = ":launch-measurements.json",
            launch_measurements_test = ":launch-measurements-test.json",
        )
    else:
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
        command = "tar %s -xOf %s --occurrence=1  %s > %s" % (
            "--wildcards" if ctx.attr.wildcards else "",
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
        "wildcards": attr.bool(
            default = False,
            doc = "If True, the path is treated as a glob pattern.",
        ),
    },
)
