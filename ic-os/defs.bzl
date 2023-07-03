"""
A macro to build multiple versions of the ICOS image (i.e., dev vs prod)
"""

load("//toolchains/sysimage:toolchain.bzl", "disk_image", "docker_tar", "ext4_image", "sha256sum", "tar_extract", "upgrade_image")
load("//gitlab-ci/src/artifacts:upload.bzl", "upload_artifacts")
load("//ic-os/bootloader:defs.bzl", "build_grub_partition")
load("//bazel:defs.bzl", "gzip_compress", "sha256sum2url", "zstd_compress")
load("//bazel:output_files.bzl", "output_files")
load("@bazel_skylib//rules:copy_file.bzl", "copy_file")

def icos_build(name, upload_prefix, image_deps, mode = None, malicious = False, upgrades = True, vuln_scan = True, visibility = None, ic_version = "//bazel:version.txt"):
    """
    Generic ICOS build tooling.

    Args:
      name: Name for the generated filegroup.
      upload_prefix: Prefix to be used as the target when uploading
      image_deps: Function to be used to generate image manifest
      mode: dev or prod. If not specified, will use the value of `name`
      malicious: if True, bundle the `malicious_replica`
      upgrades: if True, build upgrade images as well
      vuln_scan: if True, create targets for vulnerability scanning
      visibility: See Bazel documentation
      ic_version: the label pointing to the target that returns IC version
    """

    if mode == None:
        mode = name

    image_deps = image_deps(mode, malicious)

    # -------------------- Version management --------------------

    copy_file(
        name = "copy_version_txt",
        src = ic_version,
        out = "version.txt",
        allow_symlink = True,
        visibility = visibility,
    )

    if upgrades:
        native.genrule(
            name = "test_version_txt",
            srcs = [":copy_version_txt"],
            outs = ["version-test.txt"],
            cmd = "sed -e 's/.*/&-test/' < $< > $@",
        )

    # -------------------- Build grub partition --------------------

    build_grub_partition("partition-grub.tar", grub_config = image_deps.get("grub_config", default = None))

    # -------------------- Build the docker image --------------------

    build_args = ["BUILD_TYPE=" + mode]

    # set root password only in dev mode
    if mode == "dev":
        build_args.extend(["ROOT_PASSWORD=root"])

    elif mode == "dev-sev":
        build_args.extend(["ROOT_PASSWORD=root"])

    file_build_args = {image_deps["base_image"]: "BASE_IMAGE"}

    docker_tar(
        visibility = visibility,
        name = "rootfs-tree.tar",
        dep = [image_deps["docker_context"]],
        build_args = build_args,
        file_build_args = file_build_args,
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    tar_extract(
        visibility = visibility,
        name = "file_contexts",
        src = "rootfs-tree.tar",
        path = "etc/selinux/default/contexts/files/file_contexts",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    # -------------------- Extract root partition --------------------

    ext4_image(
        name = "partition-root-unsigned.tar",
        src = _dict_value_search(image_deps["rootfs"], "/"),
        # Take the dependency list declared above, and add in the "version.txt"
        # at the correct place.
        extra_files = {
            k: v
            for k, v in (image_deps["rootfs"].items() + [(":version.txt", "/opt/ic/share/version.txt:0644")])
            # Skip over special entries
            if v != "/"
        },
        file_contexts = ":file_contexts",
        partition_size = image_deps["rootfs_size"],
        strip_paths = [
            "/run",
            "/boot",
        ],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        # As it consumes version.txt it currently changes all the time - caching it makes no sense.
        # TODO(IDX-2606): Remove when at least dev images will use stable version.
        tags = ["no-remote-cache"],
    )

    if upgrades:
        ext4_image(
            name = "partition-root-test-unsigned.tar",
            src = _dict_value_search(image_deps["rootfs"], "/"),
            # Take the dependency list declared above, and add in the "version.txt"
            # at the correct place.
            extra_files = {
                k: v
                for k, v in (image_deps["rootfs"].items() + [(":version-test.txt", "/opt/ic/share/version.txt:0644")])
                # Skip over special entries
                if v != "/"
            },
            file_contexts = ":file_contexts",
            partition_size = image_deps["rootfs_size"],
            strip_paths = [
                "/run",
                "/boot",
            ],
            target_compatible_with = [
                "@platforms//os:linux",
            ],
            # As it consumes version.txt it currently changes all the time - caching it makes no sense.
            # TODO(IDX-2606): Remove when at least dev images will use stable version.
            tags = ["no-remote-cache"],
        )

    # -------------------- Extract boot partition --------------------

    if "boot_args_template" not in image_deps:
        native.alias(name = "partition-root.tar", actual = ":partition-root-unsigned.tar", visibility = [Label("//visibility:private")])
        native.alias(name = "extra_boot_args", actual = image_deps["extra_boot_args"], visibility = [Label("//visibility:private")])

        if upgrades:
            native.alias(name = "partition-root-test.tar", actual = ":partition-root-test-unsigned.tar", visibility = [Label("//visibility:private")])
            native.alias(name = "extra_boot_test_args", actual = image_deps["extra_boot_args"], visibility = [Label("//visibility:private")])
    else:
        native.alias(name = "extra_boot_args_template", actual = image_deps["boot_args_template"], visibility = [Label("//visibility:private")])

        native.genrule(
            name = "partition-root-sign",
            srcs = ["partition-root-unsigned.tar"],
            outs = ["partition-root.tar", "partition-root-hash"],
            cmd = "$(location //toolchains/sysimage:verity_sign.py) -i $< -o $(location :partition-root.tar) -r $(location partition-root-hash)",
            executable = False,
            tools = ["//toolchains/sysimage:verity_sign.py"],
            # As it consumes partition-root-unsigned.tar that uses version.txt it currently changes all the time - caching it makes no sense.
            # TODO(IDX-2606): Remove when at least dev images will use stable version.
            tags = ["no-remote-cache"],
        )

        native.genrule(
            name = "extra_boot_args_root_hash",
            srcs = [
                ":extra_boot_args_template",
                ":partition-root-hash",
            ],
            outs = ["extra_boot_args"],
            cmd = "sed -e s/ROOT_HASH/$$(cat $(location :partition-root-hash))/ < $(location :extra_boot_args_template) > $@",
        )

        if upgrades:
            native.genrule(
                name = "partition-root-test-sign",
                srcs = ["partition-root-test-unsigned.tar"],
                outs = ["partition-root-test.tar", "partition-root-test-hash"],
                cmd = "$(location //toolchains/sysimage:verity_sign.py) -i $< -o $(location :partition-root-test.tar) -r $(location partition-root-test-hash)",
                tools = ["//toolchains/sysimage:verity_sign.py"],
            )

            native.genrule(
                name = "extra_boot_args_root_test_hash",
                srcs = [
                    ":extra_boot_args_template",
                    ":partition-root-test-hash",
                ],
                outs = ["extra_boot_test_args"],
                cmd = "sed -e s/ROOT_HASH/$$(cat $(location :partition-root-test-hash))/ < $(location :extra_boot_args_template) > $@",
            )

    ext4_image(
        name = "partition-boot.tar",
        src = _dict_value_search(image_deps["bootfs"], "/"),
        # Take the dependency list declared above, and add in the "version.txt"
        # as well as the generated extra_boot_args file in the correct place.
        extra_files = {
            k: v
            for k, v in (
                image_deps["bootfs"].items() + [
                    (":version.txt", "/boot/version.txt:0644"),
                    (":extra_boot_args", "/boot/extra_boot_args:0644"),
                ]
            )
            # Skip over special entries
            if v != "/"
        },
        file_contexts = ":file_contexts",
        partition_size = image_deps["bootfs_size"],
        subdir = "boot/",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    if upgrades:
        ext4_image(
            name = "partition-boot-test.tar",
            src = _dict_value_search(image_deps["rootfs"], "/"),
            # Take the dependency list declared above, and add in the "version.txt"
            # as well as the generated extra_boot_args file in the correct place.
            extra_files = {
                k: v
                for k, v in (
                    image_deps["bootfs"].items() + [
                        (":version-test.txt", "/boot/version.txt:0644"),
                        (":extra_boot_test_args", "/boot/extra_boot_args:0644"),
                    ]
                )
                # Skip over special entries
                if v != "/"
            },
            file_contexts = ":file_contexts",
            partition_size = image_deps["bootfs_size"],
            subdir = "boot/",
            target_compatible_with = [
                "@platforms//os:linux",
            ],
        )

    # -------------------- Assemble disk image --------------------

    # Build a list of custom partitions with a funciton, to allow "injecting" build steps at this point
    if "custom_partitions" not in image_deps:
        custom_partitions = []
    else:
        custom_partitions = image_deps["custom_partitions"]()

    disk_image(
        name = "disk-img.tar",
        layout = image_deps["partition_table"],
        partitions = [
            "//ic-os/bootloader:partition-esp.tar",
            ":partition-grub.tar",
            ":partition-boot.tar",
            ":partition-root.tar",
        ] + custom_partitions,
        expanded_size = image_deps.get("expanded_size", default = None),
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    zstd_compress(
        name = "disk-img.tar.zst",
        srcs = [":disk-img.tar"],
    )

    sha256sum(
        name = "disk-img.tar.zst.sha256",
        srcs = [":disk-img.tar.zst"],
        visibility = visibility,
    )

    sha256sum2url(
        name = "disk-img.tar.zst.cas-url",
        src = ":disk-img.tar.zst.sha256",
        visibility = visibility,
    )

    gzip_compress(
        name = "disk-img.tar.gz",
        srcs = [":disk-img.tar"],
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
        visibility = visibility,
    )

    sha256sum(
        name = "disk-img.tar.gz.sha256",
        srcs = [":disk-img.tar.gz"],
    )

    # -------------------- Assemble upgrade image --------------------

    if upgrades:
        upgrade_image(
            name = "update-img.tar",
            boot_partition = ":partition-boot.tar",
            root_partition = ":partition-root.tar",
            # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
            # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
            tags = ["no-remote-cache"],
            target_compatible_with = [
                "@platforms//os:linux",
            ],
            version_file = ":version.txt",
        )

        zstd_compress(
            name = "update-img.tar.zst",
            srcs = [":update-img.tar"],
        )

        sha256sum(
            name = "update-img.tar.zst.sha256",
            srcs = [":update-img.tar.zst"],
            visibility = visibility,
        )

        sha256sum2url(
            name = "update-img.tar.zst.cas-url",
            src = ":update-img.tar.zst.sha256",
            visibility = visibility,
        )

        gzip_compress(
            name = "update-img.tar.gz",
            srcs = [":update-img.tar"],
            # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
            # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
            tags = ["no-remote-cache"],
        )

        sha256sum(
            name = "update-img.tar.gz.sha256",
            srcs = [":update-img.tar.gz"],
        )

        upgrade_image(
            name = "update-img-test.tar",
            boot_partition = ":partition-boot-test.tar",
            root_partition = ":partition-root-test.tar",
            # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
            # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
            tags = ["no-remote-cache"],
            target_compatible_with = [
                "@platforms//os:linux",
            ],
            version_file = ":version-test.txt",
        )

        zstd_compress(
            name = "update-img-test.tar.zst",
            srcs = [":update-img-test.tar"],
        )

        sha256sum(
            name = "update-img-test.tar.zst.sha256",
            srcs = [":update-img-test.tar.zst"],
            visibility = visibility,
        )

        sha256sum2url(
            name = "update-img-test.tar.zst.cas-url",
            src = ":update-img-test.tar.zst.sha256",
            visibility = visibility,
        )

        gzip_compress(
            name = "update-img-test.tar.gz",
            srcs = [":update-img-test.tar"],
            # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
            # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
            tags = ["no-remote-cache"],
        )

        sha256sum(
            name = "update-img-test.tar.gz.sha256",
            srcs = [":update-img-test.tar.gz"],
        )

    # -------------------- Upload artifacts --------------------

    upload_suffix = ""
    if mode == "dev":
        upload_suffix = "-dev"
    elif mode == "dev-sev":
        upload_suffix = "-dev-sev"
    if malicious:
        upload_suffix += "-malicious"

    if upload_prefix != None:
        upload_artifacts(
            name = "upload_disk-img",
            inputs = [
                ":disk-img.tar.zst",
                ":disk-img.tar.gz",
            ],
            remote_subdir = upload_prefix + "/disk-img" + upload_suffix,
        )

        output_files(
            name = "disk-img-url",
            target = ":upload_disk-img",
            basenames = ["upload_disk-img_disk-img.tar.zst.url"],
            visibility = ["//visibility:public"],
            tags = ["manual"],
        )

        if upgrades:
            upload_artifacts(
                name = "upload_update-img",
                inputs = [
                    ":update-img.tar.zst",
                    ":update-img.tar.gz",
                    ":update-img-test.tar.zst",
                    ":update-img-test.tar.gz",
                ],
                remote_subdir = upload_prefix + "/update-img" + upload_suffix,
            )

        # -------------------- Bazel ergonomics --------------------

        native.filegroup(
            name = "hash_and_upload_disk-img",
            srcs = [
                ":upload_disk-img",
                ":disk-img.tar.zst.sha256",
            ],
            visibility = ["//visibility:public"],
            tags = ["manual"],
        )

        if upgrades:
            native.filegroup(
                name = "hash_and_upload_update-img",
                srcs = [
                    ":upload_update-img",
                    ":update-img.tar.zst.sha256",
                ],
                visibility = ["//visibility:public"],
                tags = ["manual"],
            )

    # end if upload_prefix != None

    if upgrades:
        upgrade_outputs = [
            ":update-img.tar.zst",
            ":update-img.tar.gz",
            ":update-img-test.tar.zst",
            ":update-img-test.tar.gz",
        ]
    else:
        upgrade_outputs = []

    native.filegroup(
        name = name,
        srcs = [
            ":disk-img.tar.zst",
            ":disk-img.tar.gz",
        ] + upgrade_outputs,
        visibility = visibility,
    )

    # -------------------- Vulnerability scanning --------------------

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
                "DOCKER_TAR": "$(rootpaths :rootfs-tree.tar)",
                "TEMPLATE_FILE": "$(rootpath //ic-os:vuln-scan/vuln-scan.html)",
            },
        )

def boundary_node_icos_build(name, image_deps, mode = None, sev = False, visibility = None, ic_version = "//bazel:version.txt"):
    """
    A boundary node ICOS build parameterized by mode.

    Args:
      name: Name for the generated filegroup.
      image_deps: Function to be used to generate image manifest
      mode: dev, or prod. If not specified, will use the value of `name`
      sev: if True, build an SEV-SNP enabled image
      visibility: See Bazel documentation
      ic_version: the label pointing to the target that returns IC version
    """
    if mode == None:
        mode = name

    image_deps = image_deps(mode, sev = sev)

    rootfs_args = []

    if mode == "dev":
        rootfs_args = [
            "ROOT_PASSWORD=root",
            "SW=false",
        ]
    elif mode == "prod":
        rootfs_args = [
            "ROOT_PASSWORD=",
            "SW=true",
        ]

    if sev:
        base_suffix = "snp"
    else:
        base_suffix = "prod"
    file_build_args = {"//ic-os/boundary-guestos:rootfs/docker-base." + base_suffix: "BASE_IMAGE"}

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
            "DOCKER_TAR": "$(rootpaths :rootfs-tree.tar)",
            "TEMPLATE_FILE": "$(rootpath //ic-os:vuln-scan/vuln-scan.html)",
        },
    )

    build_grub_partition("partition-grub.tar")

    docker_tar(
        visibility = visibility,
        name = "rootfs-tree.tar",
        dep = ["//ic-os/boundary-guestos:rootfs-files"],
        build_args = [
            "BUILD_TYPE=" + mode,
        ] + rootfs_args,
        file_build_args = file_build_args,
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    ext4_image(
        name = "partition-config.tar",
        partition_size = "100M",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    copy_file(
        name = "copy_version_txt",
        src = ic_version,
        out = "version.txt",
        allow_symlink = True,
    )

    ext4_image(
        name = "partition-boot.tar",
        src = _dict_value_search(image_deps["rootfs"], "/"),
        # Take the dependency list declared above, and add in the "version.txt"
        # as well as the generated extra_boot_args file in the correct place.
        extra_files = {
            k: v
            for k, v in (
                image_deps["bootfs"].items() + [
                    ("version.txt", "/boot/version.txt:0644"),
                    ("extra_boot_args", "/boot/extra_boot_args:0644"),
                ]
            )
            # Skip over special entries
            if ":bootloader/extra_boot_args.template" not in k
            if v != "/"
        },
        partition_size = "1G",
        subdir = "boot/",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    ext4_image(
        name = "partition-root-unsigned.tar",
        src = _dict_value_search(image_deps["rootfs"], "/"),
        # Take the dependency list declared above, and add in the "version.txt"
        # at the correct place.
        extra_files = {
            k: v
            for k, v in (image_deps["rootfs"].items() + [(":version.txt", "/opt/ic/share/version.txt:0644")])
            # Skip over special entries
            if v != "/"
        },
        partition_size = "3G",
        strip_paths = [
            "/run",
            "/boot",
        ],
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    native.genrule(
        name = "partition-root-sign",
        srcs = ["partition-root-unsigned.tar"],
        outs = ["partition-root.tar", "partition-root-hash"],
        cmd = "$(location //toolchains/sysimage:verity_sign.py) -i $< -o $(location :partition-root.tar) -r $(location partition-root-hash)",
        executable = False,
        tools = ["//toolchains/sysimage:verity_sign.py"],
    )

    native.genrule(
        name = "extra_boot_args_root_hash",
        srcs = [
            "//ic-os/boundary-guestos:bootloader/extra_boot_args.template",
            ":partition-root-hash",
        ],
        outs = ["extra_boot_args"],
        cmd = "sed -e s/ROOT_HASH/$$(cat $(location :partition-root-hash))/ < $(location //ic-os/boundary-guestos:bootloader/extra_boot_args.template) > $@",
    )

    disk_image(
        name = "disk-img.tar",
        layout = "//ic-os/boundary-guestos:partitions.csv",
        partitions = [
            "//ic-os/bootloader:partition-esp.tar",
            ":partition-grub.tar",
            ":partition-config.tar",
            ":partition-boot.tar",
            ":partition-root.tar",
        ],
        expanded_size = "50G",
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    zstd_compress(
        name = "disk-img.tar.zst",
        srcs = ["disk-img.tar"],
    )

    sha256sum(
        name = "disk-img.tar.zst.sha256",
        srcs = [":disk-img.tar.zst"],
        visibility = visibility,
    )

    sha256sum2url(
        name = "disk-img.tar.zst.cas-url",
        src = ":disk-img.tar.zst.sha256",
        visibility = visibility,
    )

    gzip_compress(
        name = "disk-img.tar.gz",
        srcs = ["disk-img.tar"],
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
    )

    upload_suffix = ""
    if sev:
        upload_suffix += "-snp"
    if mode == "dev":
        upload_suffix += "-dev"

    upload_artifacts(
        name = "upload_disk-img",
        inputs = [
            ":disk-img.tar.zst",
            ":disk-img.tar.gz",
        ],
        remote_subdir = "boundary-os/disk-img" + upload_suffix,
    )

    native.filegroup(
        name = "hash_and_upload_disk-img",
        srcs = [
            ":upload_disk-img",
            ":disk-img.tar.zst.sha256",
        ],
        visibility = visibility,
        tags = ["manual"],
    )

    output_files(
        name = "disk-img-url",
        target = ":upload_disk-img",
        basenames = ["upload_disk-img_disk-img.tar.zst.url"],
        tags = ["manual"],
    )

    native.filegroup(
        name = name,
        srcs = [":disk-img.tar.zst", ":disk-img.tar.gz"],
        visibility = visibility,
    )

def boundary_api_guestos_build(name, image_deps, mode = None, visibility = None, ic_version = "//bazel:version.txt"):
    """
    A boundary API GuestOS build parameterized by mode.

    Args:
      name: Name for the generated filegroup.
      image_deps: Function to be used to generate image manifest
      mode: dev, or prod. If not specified, will use the value of `name`
      visibility: See Bazel documentation
      ic_version: the label pointing to the target that returns IC version
    """
    if mode == None:
        mode = name

    image_deps = image_deps()

    rootfs_args = []

    if mode == "dev":
        rootfs_args = [
            "ROOT_PASSWORD=root",
        ]
    elif mode == "prod":
        rootfs_args = [
            "ROOT_PASSWORD=",
        ]

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
            "DOCKER_TAR": "$(rootpaths :rootfs-tree.tar)",
            "TEMPLATE_FILE": "$(rootpath //ic-os:vuln-scan/vuln-scan.html)",
        },
    )

    build_grub_partition("partition-grub.tar")

    docker_tar(
        visibility = visibility,
        name = "rootfs-tree.tar",
        dep = ["//ic-os/boundary-api-guestos:rootfs-files"],
        build_args = [
            "BUILD_TYPE=" + mode,
        ] + rootfs_args,
        file_build_args = {
            "//ic-os/boundary-api-guestos:rootfs/docker-base.prod": "BASE_IMAGE",
        },
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    ext4_image(
        name = "partition-config.tar",
        partition_size = "100M",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    copy_file(
        name = "copy_version_txt",
        src = ic_version,
        out = "version.txt",
        allow_symlink = True,
    )

    ext4_image(
        name = "partition-boot.tar",
        src = _dict_value_search(image_deps["rootfs"], "/"),
        # Take the dependency list declared above, and add in the "version.txt"
        # as well as the generated extra_boot_args file in the correct place.
        extra_files = {
            k: v
            for k, v in (
                image_deps["bootfs"].items() + [
                    ("version.txt", "/boot/version.txt:0644"),
                    ("extra_boot_args", "/boot/extra_boot_args:0644"),
                ]
            )
            # Skip over special entries
            if ":bootloader/extra_boot_args.template" not in k
            if v != "/"
        },
        partition_size = "1G",
        subdir = "boot/",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    ext4_image(
        name = "partition-root-unsigned.tar",
        src = _dict_value_search(image_deps["rootfs"], "/"),
        # Take the dependency list declared above, and add in the "version.txt"
        # at the correct place.
        extra_files = {
            k: v
            for k, v in (image_deps["rootfs"].items() + [(":version.txt", "/opt/ic/share/version.txt:0644")])
            # Skip over special entries
            if v != "/"
        },
        partition_size = "3G",
        strip_paths = [
            "/run",
            "/boot",
        ],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    native.genrule(
        name = "partition-root-sign",
        srcs = ["partition-root-unsigned.tar"],
        outs = ["partition-root.tar", "partition-root-hash"],
        cmd = "$(location //toolchains/sysimage:verity_sign.py) -i $< -o $(location :partition-root.tar) -r $(location partition-root-hash)",
        executable = False,
        tools = ["//toolchains/sysimage:verity_sign.py"],
    )

    native.genrule(
        name = "extra_boot_args_root_hash",
        srcs = [
            "//ic-os/boundary-api-guestos:bootloader/extra_boot_args.template",
            ":partition-root-hash",
        ],
        outs = ["extra_boot_args"],
        cmd = "sed -e s/ROOT_HASH/$$(cat $(location :partition-root-hash))/ < $(location //ic-os/boundary-api-guestos:bootloader/extra_boot_args.template) > $@",
    )

    disk_image(
        name = "disk-img.tar",
        layout = "//ic-os/boundary-api-guestos:partitions.csv",
        partitions = [
            "//ic-os/bootloader:partition-esp.tar",
            ":partition-grub.tar",
            ":partition-config.tar",
            ":partition-boot.tar",
            "partition-root.tar",
        ],
        expanded_size = "50G",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    zstd_compress(
        name = "disk-img.tar.zst",
        srcs = ["disk-img.tar"],
    )

    sha256sum(
        name = "disk-img.tar.zst.sha256",
        srcs = [":disk-img.tar.zst"],
        visibility = visibility,
    )

    sha256sum2url(
        name = "disk-img.tar.zst.cas-url",
        src = ":disk-img.tar.zst.sha256",
        visibility = visibility,
    )

    gzip_compress(
        name = "disk-img.tar.gz",
        srcs = ["disk-img.tar"],
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
        remote_subdir = "boundary-api-os/disk-img" + upload_suffix,
    )

    native.filegroup(
        name = "hash_and_upload_disk-img",
        srcs = [
            ":upload_disk-img",
            ":disk-img.tar.zst.sha256",
        ],
        visibility = ["//visibility:public"],
        tags = ["manual"],
    )

    output_files(
        name = "disk-img-url",
        target = ":upload_disk-img",
        basenames = ["upload_disk-img_disk-img.tar.zst.url"],
        tags = ["manual"],
    )

    native.filegroup(
        name = name,
        srcs = [":disk-img.tar.zst", ":disk-img.tar.gz"],
        visibility = visibility,
    )

# NOTE: Really, we should be using a string keyed label dict, but this is not
# a built in. Use this hack until I switch our implementation.
def _dict_value_search(dict, value):
    for k, v in dict.items():
        if v == value:
            return k

    return None
