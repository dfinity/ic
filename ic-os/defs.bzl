"""
A macro to build multiple versions of the ICOS image (i.e., dev vs prod)
"""

load("@bazel_skylib//rules:copy_file.bzl", "copy_file")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")
load("//bazel:defs.bzl", "gzip_compress", "sha256sum2url", "zstd_compress")
load("//bazel:output_files.bzl", "output_files")
load("//ci/src/artifacts:upload.bzl", "upload_artifacts")
load("//ic-os/bootloader:defs.bzl", "build_grub_partition")
load("//ic-os/components:boundary-guestos.bzl", boundary_component_files = "component_files")
load("//ic-os/components/conformance_tests:defs.bzl", "component_file_references_test")
load("//toolchains/sysimage:toolchain.bzl", "build_container_base_image", "build_container_filesystem", "disk_image", "ext4_image", "inject_files", "sha256sum", "tar_extract", "tree_hash", "upgrade_image")

def icos_build(
        name,
        upload_prefix,
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
      upload_prefix: Prefix to be used as the target when uploading
      image_deps_func: Function to be used to generate image manifest
      mode: dev or prod. If not specified, will use the value of `name`
      malicious: if True, bundle the `malicious_replica`
      upgrades: if True, build upgrade images as well
      vuln_scan: if True, create targets for vulnerability scanning
      visibility: See Bazel documentation
      tags: See Bazel documentation
      build_local_base_image: if True, build the base images from scratch. Do not download the docker.io base image.
      ic_version: the label pointing to the target that returns IC version
    """

    if mode == None:
        mode = name

    image_deps = image_deps_func(mode, malicious)

    # -------------------- Pre-check --------------------

    # Verify that all the referenced components exist
    native.genrule(
        name = name + "_pre_check",
        srcs = [k for k, v in image_deps["component_files"].items()],
        outs = [name + "_pre_check_result.txt"],
        cmd = """
            echo "Running pre_check for {name}"
            echo "All paths exist" > $@
        """,
    )

    # -------------------- Version management --------------------

    copy_file(
        name = "copy_version_txt",
        src = ic_version,
        out = "version.txt",
        allow_symlink = True,
        visibility = visibility,
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

    build_grub_partition("partition-grub.img", grub_config = image_deps.get("grub_config", default = None), tags = ["manual", "no-cache"])

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
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual"],
    )

    # -------------------- Extract root partition --------------------

    ext4_image(
        name = "static-partition-root-unsigned.img",
        src = ":rootfs-tree.tar",
        file_contexts = ":file_contexts",
        partition_size = image_deps["rootfs_size"],
        # NOTE: e2fsdroid does not support filenames with spaces, fortunately,
        # there are only two in our build.
        strip_paths = [
            "/run",
            "/boot",
            "/var",
            "/usr/lib/firmware/brcm/brcmfmac43430a0-sdio.ONDA-V80 PLUS.txt",
            "/usr/lib/firmware/brcm/brcmfmac43455-sdio.MINIX-NEO Z83-4.txt",
        ],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual", "no-cache"],
    )

    # -------------------- Extract boot partition --------------------

    ext4_image(
        name = "static-partition-boot.img",
        src = ":rootfs-tree.tar",
        file_contexts = ":file_contexts",
        partition_size = image_deps["bootfs_size"],
        subdir = "boot",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual", "no-cache"],
    )

    # Defer injection to this point to allow caching most of the built images
    # -------------------- Inject extra files --------------------

    #    native.alias(
    #        name = "partition-root-unsigned.img",
    #        actual = "static-partition-root-unsigned.img",
    #        tags = ["manual"],
    #    )

    inject_files(
        name = "partition-root-unsigned.img",
        testonly = malicious,
        base = "static-partition-root-unsigned.img",
        file_contexts = ":file_contexts",
        extra_files = {
            k: v
            for k, v in ([(":version.txt", "/opt/ic/share/version.txt:0644")] + image_deps["rootfs"].items())
        },
        tags = ["manual", "no-cache"],
    )

    #    component_file_references_test(
    #        name = name + "_component_file_references_test",
    #        image = ":partition-root-unsigned.img",
    #        component_files = image_deps["component_files"].keys(),
    #    )

    if upgrades:
        inject_files(
            name = "partition-root-test-unsigned.img",
            testonly = malicious,
            base = "static-partition-root-unsigned.img",
            file_contexts = ":file_contexts",
            extra_files = {
                k: v
                for k, v in (image_deps["rootfs"].items() + [(":version-test.txt", "/opt/ic/share/version.txt:0644")])
            },
            tags = ["manual", "no-cache"],
        )

    # When boot_args are fixed, don't bother signing
    if "boot_args_template" not in image_deps:
        native.alias(name = "partition-root.img", actual = ":partition-root-unsigned.img", tags = ["manual"])
        native.alias(name = "extra_boot_args", actual = image_deps["extra_boot_args"], tags = ["manual"])

        if upgrades:
            native.alias(name = "partition-root-test.img", actual = ":partition-root-test-unsigned.img", tags = ["manual"])
            native.alias(name = "extra_boot_test_args", actual = image_deps["extra_boot_args"], tags = ["manual"])
    else:
        native.alias(name = "extra_boot_args_template", actual = image_deps["boot_args_template"], tags = ["manual"])

        native.genrule(
            name = "partition-root-sign",
            testonly = malicious,
            srcs = ["partition-root-unsigned.img"],
            outs = ["partition-root.img", "partition-root-hash"],
            cmd = "$(location //toolchains/sysimage:proc_wrapper) $(location //toolchains/sysimage:verity_sign.py) -i $< -o $(location :partition-root.img) -r $(location partition-root-hash) --dflate $(location //rs/ic_os/dflate)",
            executable = False,
            tools = ["//toolchains/sysimage:proc_wrapper", "//toolchains/sysimage:verity_sign.py", "//rs/ic_os/dflate"],
            tags = ["manual", "no-cache"],
        )

        native.genrule(
            name = "extra_boot_args_root_hash",
            srcs = [
                ":extra_boot_args_template",
                ":partition-root-hash",
            ],
            outs = ["extra_boot_args"],
            cmd = "sed -e s/ROOT_HASH/$$(cat $(location :partition-root-hash))/ < $(location :extra_boot_args_template) > $@",
            tags = ["manual"],
        )

        if upgrades:
            native.genrule(
                name = "partition-root-test-sign",
                testonly = malicious,
                srcs = ["partition-root-test-unsigned.img"],
                outs = ["partition-root-test.img", "partition-root-test-hash"],
                cmd = "$(location //toolchains/sysimage:proc_wrapper) $(location //toolchains/sysimage:verity_sign.py) -i $< -o $(location :partition-root-test.img) -r $(location partition-root-test-hash) --dflate $(location //rs/ic_os/dflate)",
                tools = ["//toolchains/sysimage:proc_wrapper", "//toolchains/sysimage:verity_sign.py", "//rs/ic_os/dflate"],
                tags = ["manual", "no-cache"],
            )

            native.genrule(
                name = "extra_boot_args_root_test_hash",
                srcs = [
                    ":extra_boot_args_template",
                    ":partition-root-test-hash",
                ],
                outs = ["extra_boot_test_args"],
                cmd = "sed -e s/ROOT_HASH/$$(cat $(location :partition-root-test-hash))/ < $(location :extra_boot_args_template) > $@",
                tags = ["manual"],
            )

    inject_files(
        name = "partition-boot.img",
        base = "static-partition-boot.img",
        file_contexts = ":file_contexts",
        prefix = "/boot",
        extra_files = {
            k: v
            for k, v in (
                image_deps["bootfs"].items() + [
                    (":version.txt", "/version.txt:0644"),
                    (":extra_boot_args", "/extra_boot_args:0644"),
                ]
            )
        },
        tags = ["manual", "no-cache"],
    )

    if upgrades:
        inject_files(
            name = "partition-boot-test.img",
            base = "static-partition-boot.img",
            file_contexts = ":file_contexts",
            prefix = "/boot",
            extra_files = {
                k: v
                for k, v in (
                    image_deps["bootfs"].items() + [
                        (":version-test.txt", "/version.txt:0644"),
                        (":extra_boot_test_args", "/extra_boot_args:0644"),
                    ]
                )
            },
            tags = ["manual", "no-cache"],
        )

    # -------------------- Assemble disk partitions ---------------

    # Build a list of custom partitions with a function, to allow "injecting" build steps at this point
    if "custom_partitions" not in image_deps:
        custom_partitions = []
    else:
        custom_partitions = image_deps["custom_partitions"]()

    # -------------------- Assemble disk image --------------------

    disk_image(
        name = "disk-img.tar",
        layout = image_deps["partition_table"],
        partitions = [
            "//ic-os/bootloader:partition-esp.img",
            ":partition-grub.img",
            ":partition-boot.img",
            ":partition-root.img",
        ] + custom_partitions,
        expanded_size = image_deps.get("expanded_size", default = None),
        tags = ["manual", "no-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    zstd_compress(
        name = "disk-img.tar.zst",
        srcs = [":disk-img.tar"],
        visibility = visibility,
        tags = ["manual"],
    )

    sha256sum(
        name = "disk-img.tar.zst.sha256",
        srcs = [":disk-img.tar.zst"],
        visibility = visibility,
        tags = ["manual"],
    )

    sha256sum2url(
        name = "disk-img.tar.zst.cas-url",
        src = ":disk-img.tar.zst.sha256",
        visibility = visibility,
        tags = ["manual"],
    )

    # -------------------- Assemble upgrade image --------------------

    if upgrades:
        upgrade_image(
            name = "update-img.tar",
            boot_partition = ":partition-boot.img",
            root_partition = ":partition-root.img",
            target_compatible_with = [
                "@platforms//os:linux",
            ],
            version_file = ":version.txt",
            tags = ["manual", "no-cache"],
        )

        zstd_compress(
            name = "update-img.tar.zst",
            srcs = [":update-img.tar"],
            visibility = visibility,
            tags = ["manual"],
        )

        sha256sum(
            name = "update-img.tar.zst.sha256",
            srcs = [":update-img.tar.zst"],
            visibility = visibility,
            tags = ["manual"],
        )

        sha256sum2url(
            name = "update-img.tar.zst.cas-url",
            src = ":update-img.tar.zst.sha256",
            visibility = visibility,
            tags = ["manual"],
        )

        upgrade_image(
            name = "update-img-test.tar",
            boot_partition = ":partition-boot-test.img",
            root_partition = ":partition-root-test.img",
            tags = ["manual", "no-cache"],
            target_compatible_with = [
                "@platforms//os:linux",
            ],
            version_file = ":version-test.txt",
        )

        zstd_compress(
            name = "update-img-test.tar.zst",
            srcs = [":update-img-test.tar"],
            visibility = visibility,
            tags = ["manual"],
        )

        sha256sum(
            name = "update-img-test.tar.zst.sha256",
            srcs = [":update-img-test.tar.zst"],
            visibility = visibility,
            tags = ["manual"],
        )

        sha256sum2url(
            name = "update-img-test.tar.zst.cas-url",
            src = ":update-img-test.tar.zst.sha256",
            visibility = visibility,
            tags = ["manual"],
        )

    # -------------------- Upload artifacts --------------------

    upload_suffix = ""
    if mode == "dev":
        upload_suffix = "-dev"
    if malicious:
        upload_suffix += "-malicious"

    if upload_prefix != None:
        upload_artifacts(
            name = "upload_disk-img",
            inputs = [
                ":disk-img.tar.zst",
            ],
            remote_subdir = upload_prefix + "/disk-img" + upload_suffix,
            visibility = visibility,
        )

        output_files(
            name = "disk-img-url",
            target = ":upload_disk-img",
            basenames = ["upload_disk-img_disk-img.tar.zst.url"],
            visibility = visibility,
            tags = ["manual"],
        )

        if upgrades:
            upload_artifacts(
                name = "upload_update-img",
                inputs = [
                    ":update-img.tar.zst",
                    ":update-img-test.tar.zst",
                ],
                remote_subdir = upload_prefix + "/update-img" + upload_suffix,
                visibility = visibility,
            )

            output_files(
                name = "update-img-url",
                target = ":upload_update-img",
                basenames = ["upload_update-img_update-img.tar.zst.url"],
                visibility = visibility,
                tags = ["manual"],
            )

    # end if upload_prefix != None

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

    # -------------------- VM Developer Tools --------------------

    native.genrule(
        name = "launch-remote-vm",
        srcs = [
            "//rs/ic_os/launch-single-vm",
            ":disk-img.tar.zst.cas-url",
            ":disk-img.tar.zst.sha256",
            "//ic-os/components:hostos-scripts/build-bootstrap-config-image.sh",
            ":version.txt",
        ],
        outs = ["launch_remote_vm_script"],
        cmd = """
        BIN="$(location //rs/ic_os/launch-single-vm:launch-single-vm)"
        VERSION="$$(cat $(location :version.txt))"
        URL="$$(cat $(location :disk-img.tar.zst.cas-url))"
        SHA="$$(cat $(location :disk-img.tar.zst.sha256))"
        SCRIPT="$(location //ic-os/components:hostos-scripts/build-bootstrap-config-image.sh)"
        cat <<EOF > $@
#!/usr/bin/env bash
set -euo pipefail
cd "\\$$BUILD_WORKSPACE_DIRECTORY"
# Hack to switch nested for SetupOS
nested=""
if [[ "$@" =~ "setupos" ]]; then
    nested="--nested"
fi
$$BIN --version "$$VERSION" --url "$$URL" --sha256 "$$SHA" --build-bootstrap-script "$$SCRIPT" \\$${nested}
EOF
        """,
        executable = True,
        tags = ["manual"],
        testonly = True,
    )

    native.genrule(
        name = "launch-local-vm",
        srcs = [
            ":disk-img.tar",
        ],
        outs = ["launch_local_vm_script"],
        cmd = """
        IMAGE="$(location :disk-img.tar)"
        cat <<EOF > $@
#!/usr/bin/env bash
set -euo pipefail
cd "\\$$BUILD_WORKSPACE_DIRECTORY"
TEMP=\\$$(mktemp -d)
CID=\\$$((\\$$RANDOM + 3))
cp $$IMAGE \\$$TEMP
cd \\$$TEMP
tar xf disk-img.tar
qemu-system-x86_64 -machine type=q35,accel=kvm -enable-kvm -nographic -m 4G -bios /usr/share/ovmf/OVMF.fd -device vhost-vsock-pci,guest-cid=\\$$CID -drive file=disk.img,format=raw,if=virtio -netdev user,id=user.0,hostfwd=tcp::2222-:22 -device virtio-net,netdev=user.0
EOF
        """,
        executable = True,
        tags = ["manual"],
    )

    # Same as above but without KVM support to run inside VMs and containers
    # VHOST for nested VMs is not configured at the moment (should be possible)
    native.genrule(
        name = "launch-local-vm-no-kvm",
        srcs = [
            ":disk-img.tar",
        ],
        outs = ["launch_local_vm_script_no_kvm"],
        cmd = """
        IMAGE="$(location :disk-img.tar)"
        cat <<EOF > $@
#!/usr/bin/env bash
set -euo pipefail
cd "\\$$BUILD_WORKSPACE_DIRECTORY"
TEMP=\\$$(mktemp -d)
CID=\\$$((\\$$RANDOM + 3))
cp $$IMAGE \\$$TEMP
cd \\$$TEMP
tar xf disk-img.tar
qemu-system-x86_64 -machine type=q35 -nographic -m 4G -bios /usr/share/ovmf/OVMF.fd -drive file=disk.img,format=raw,if=virtio -netdev user,id=user.0,hostfwd=tcp::2222-:22 -device virtio-net,netdev=user.0
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
            name + "_pre_check_result.txt",
            ":disk-img.tar.zst",
        ] + ([
            ":update-img.tar.zst",
            ":update-img-test.tar.zst",
        ] if upgrades else []),
        visibility = visibility,
        tags = tags,
    )

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

    build_grub_partition("partition-grub.img", tags = ["manual"])

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
        name = "partition-config.img",
        partition_size = "100M",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual", "no-cache"],
    )

    copy_file(
        name = "copy_version_txt",
        src = ic_version,
        out = "version.txt",
        allow_symlink = True,
        tags = ["manual"],
    )

    ext4_image(
        name = "static-partition-boot.img",
        src = ":rootfs-tree.tar",
        partition_size = "1G",
        subdir = "boot/",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual", "no-cache"],
    )

    inject_files(
        name = "partition-boot.img",
        base = "static-partition-boot.img",
        prefix = "/boot",
        extra_files = {
            k: v
            for k, v in (
                image_deps["bootfs"].items() + [
                    ("version.txt", "/version.txt:0644"),
                    ("extra_boot_args", "/extra_boot_args:0644"),
                ]
            )
        },
        tags = ["manual"],
    )

    ext4_image(
        name = "static-partition-root-unsigned.img",
        src = ":rootfs-tree.tar",
        partition_size = "3G",
        strip_paths = [
            "/run",
            "/boot",
        ],
        tags = ["manual", "no-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    inject_files(
        name = "partition-root-unsigned.img",
        base = "static-partition-root-unsigned.img",
        extra_files = {
            k: v
            for k, v in (image_deps["rootfs"].items() + [(":version.txt", "/opt/ic/share/version.txt:0644")])
        },
        tags = ["manual"],
    )

    native.genrule(
        name = "partition-root-sign",
        srcs = ["partition-root-unsigned.img"],
        outs = ["partition-root.img", "partition-root-hash"],
        cmd = "$(location //toolchains/sysimage:proc_wrapper) $(location //toolchains/sysimage:verity_sign.py) -i $< -o $(location :partition-root.img) -r $(location partition-root-hash) --dflate $(location //rs/ic_os/dflate)",
        executable = False,
        tools = ["//toolchains/sysimage:proc_wrapper", "//toolchains/sysimage:verity_sign.py", "//rs/ic_os/dflate"],
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
            "//ic-os/bootloader:partition-esp.img",
            ":partition-grub.img",
            ":partition-config.img",
            ":partition-boot.img",
            ":partition-root.img",
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

    sha256sum(
        name = "disk-img.tar.zst.sha256",
        srcs = [":disk-img.tar.zst"],
        visibility = visibility,
        tags = ["manual"],
    )

    sha256sum2url(
        name = "disk-img.tar.zst.cas-url",
        src = ":disk-img.tar.zst.sha256",
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

    output_files(
        name = "disk-img-url",
        target = ":upload_disk-img",
        basenames = ["upload_disk-img_disk-img.tar.zst.url"],
        visibility = visibility,
        tags = ["manual"],
    )

    native.filegroup(
        name = name,
        srcs = [":disk-img.tar.zst", ":disk-img.tar.gz"],
        visibility = visibility,
    )
