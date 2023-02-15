"""
A macro to build multiple versions of the ICOS image (i.e., dev vs prod)
"""

load("//toolchains/sysimage:toolchain.bzl", "disk_image", "docker_tar", "ext4_image", "sha256sum", "tar_extract", "upgrade_image")
load("//gitlab-ci/src/artifacts:upload.bzl", "upload_artifacts")
load("//bazel:defs.bzl", "gzip_compress")
load("//bazel:output_files.bzl", "output_files")
load("@bazel_skylib//rules:copy_file.bzl", "copy_file")

# Declare the dependencies that we will have for the built filesystem images.
# This needs to be done separately from the build rules because we want to
# compute the hash over all inputs going into the image and derive the
# "version.txt" file from it.
def _image_deps(mode, malicious = False):
    extra_rootfs_deps = {
        "dev": {"//ic-os/guestos:rootfs/allow_console_root": "/etc/allow_console_root:0644"},
        "prod": {},
    }
    deps = {
        "bootfs": {
            # base layer
            ":rootfs-tree.tar": "/",

            # We will install extra_boot_args onto the system, after substuting
            # the hash of the root filesystem into it. Add the template (before
            # substitution) as a dependency nevertheless such that changes
            # to the template file are reflected in the overall version hash
            # (the root_hash must include the version hash, it cannot be the
            # other way around).
            "//ic-os/guestos:bootloader/extra_boot_args.template": "/boot/extra_boot_args.template:0644",
        },
        "rootfs": {
            # base layer
            ":rootfs-tree.tar": "/",

            # additional files to install
            "//publish/binaries:canister_sandbox": "/opt/ic/bin/canister_sandbox:0755",
            "//publish/binaries:ic-btc-adapter": "/opt/ic/bin/ic-btc-adapter:0755",
            "//publish/binaries:ic-consensus-pool-util": "/opt/ic/bin/ic-consensus-pool-util:0755",
            "//publish/binaries:ic-https-outcalls-adapter": "/opt/ic/bin/ic-https-outcalls-adapter:0755",
            "//publish/binaries:ic-crypto-csp": "/opt/ic/bin/ic-crypto-csp:0755",
            "//publish/binaries:ic-onchain-observability-adapter": "/opt/ic/bin/ic-onchain-observability-adapter:0755",
            "//publish/binaries:ic-regedit": "/opt/ic/bin/ic-regedit:0755",
            "//publish/binaries:ic-recovery": "/opt/ic/bin/ic-recovery:0755",
            "//publish/binaries:orchestrator": "/opt/ic/bin/orchestrator:0755",
            ("//publish/malicious:replica" if malicious else "//publish/binaries:replica"): "/opt/ic/bin/replica:0755",
            "//publish/binaries:sandbox_launcher": "/opt/ic/bin/sandbox_launcher:0755",
            "//publish/binaries:sevctl": "/opt/ic/bin/sevctl:0755",
            "@sevtool": "/opt/ic/bin/sevtool:0755",
            "//publish/binaries:state-tool": "/opt/ic/bin/state-tool:0755",
            "//publish/binaries:vsock_agent": "/opt/ic/bin/vsock_agent:0755",
            "//ic-os/guestos/src:infogetty": "/opt/ic/bin/infogetty:0755",
            "//ic-os/guestos/src:prestorecon": "/opt/ic/bin/prestorecon:0755",
        },
    }
    deps["rootfs"].update(extra_rootfs_deps[mode])
    return deps

def icos_build(name, mode = None, malicious = False, visibility = None):
    """
    An ICOS build parameterized by mode.

    Args:
      name: Name for the generated filegroup.
      mode: dev or prod. If not specified, will use the value of `name`
      malicious: if True, bundle the `malicious_replica`
      visibility: See Bazel documentation
    """
    if mode == None:
        mode = name

    image_deps = _image_deps(mode, malicious)

    build_args = ["BUILD_TYPE=" + mode]

    # set root password only in dev mode
    if mode == "dev":
        build_args.extend(["ROOT_PASSWORD=root"])

    file_build_args = {"//ic-os/guestos:rootfs/docker-base." + mode: "BASE_IMAGE"}

    docker_tar(
        visibility = visibility,
        name = "rootfs-tree.tar",
        dockerfile = "//ic-os/guestos:rootfs/Dockerfile",
        src = "//ic-os/guestos:rootfs",
        dep = ["//ic-os/guestos:rootfs-files"],
        build_args = build_args,
        file_build_args = file_build_args,
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    native.sh_binary(
        name = "vuln-scan",
        srcs = ["//ic-os:vuln-scan.sh"],
        data = [
            "@trivy//:trivy",
            ":rootfs-tree.tar",
            "//ic-os:vuln-scan.html",
        ],
        env = {
            "trivy_path": "$(rootpath @trivy//:trivy)",
            "DOCKER_TAR": "$(rootpaths :rootfs-tree.tar)",
            "TEMPLATE_FILE": "$(rootpath //ic-os:vuln-scan.html)",
        },
    )

    ext4_image(
        name = "partition-config.tar",
        partition_size = "100M",
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

    # TODO(IDX-2538): re-enable this (or any other similar) solution when everything will be ready to have ic version that is not git revision.
    #summary_sha256sum(
    #    name = "version.txt",
    #    inputs = image_deps,
    #    suffix = "-dev" if mode == "dev" else "",
    #)

    copy_file(
        name = "copy_version_txt",
        src = "//bazel:version.txt",
        out = "version.txt",
        allow_symlink = True,
    )

    copy_file(
        name = "copy_ic_version_id",
        src = ":version.txt",
        out = "ic_version_id",
        allow_symlink = True,
        visibility = ["//visibility:public"],
        tags = ["manual"],
    )

    native.genrule(
        name = "test_version_txt",
        srcs = [":copy_version_txt"],
        outs = ["version-test.txt"],
        cmd = "sed -e 's/.*/&-test/' < $< > $@",
    )

    ext4_image(
        name = "partition-boot.tar",
        src = "rootfs-tree.tar",
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
            if ":bootloader/extra_boot_args.template" not in k
            # additional files to install
            if v != "/"
        },
        file_contexts = ":file_contexts",
        partition_size = "1G",
        subdir = "boot/",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    ext4_image(
        name = "partition-boot-test.tar",
        src = "rootfs-tree.tar",
        # Take the dependency list declared above, and add in the "version.txt"
        # as well as the generated extra_boot_args file in the correct place.
        extra_files = {
            k: v
            for k, v in (
                image_deps["bootfs"].items() + [
                    ("version-test.txt", "/boot/version.txt:0644"),
                    ("extra_boot_test_args", "/boot/extra_boot_args:0644"),
                ]
            )
            if ":bootloader/extra_boot_args.template" not in k
            # additional files to install
            if v != "/"
        },
        file_contexts = ":file_contexts",
        partition_size = "1G",
        subdir = "boot/",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    ext4_image(
        name = "partition-root-unsigned.tar",
        src = "rootfs-tree.tar",
        # Take the dependency list declared above, and add in the "version.txt"
        # at the correct place.
        extra_files = {
            k: v
            for k, v in (image_deps["rootfs"].items() + [(":version.txt", "/opt/ic/share/version.txt:0644")])
            if v != "/"
        },
        file_contexts = ":file_contexts",
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
            "//ic-os/guestos:bootloader/extra_boot_args.template",
            ":partition-root-hash",
        ],
        outs = ["extra_boot_args"],
        cmd = "sed -e s/ROOT_HASH/$$(cat $(location :partition-root-hash))/ < $(location //ic-os/guestos:bootloader/extra_boot_args.template) > $@",
    )

    ext4_image(
        name = "partition-root-test-unsigned.tar",
        src = "rootfs-tree.tar",
        # Take the dependency list declared above, and add in the "version.txt"
        # at the correct place.
        extra_files = {
            k: v
            for k, v in (image_deps["rootfs"].items() + [(":version-test.txt", "/opt/ic/share/version.txt:0644")])
            if v != "/"
        },
        file_contexts = ":file_contexts",
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
        name = "partition-root-test-sign",
        srcs = ["partition-root-test-unsigned.tar"],
        outs = ["partition-root-test.tar", "partition-root-test-hash"],
        cmd = "$(location //toolchains/sysimage:verity_sign.py) -i $< -o $(location :partition-root-test.tar) -r $(location partition-root-test-hash)",
        tools = ["//toolchains/sysimage:verity_sign.py"],
    )

    native.genrule(
        name = "extra_boot_args_root_test_hash",
        srcs = [
            "//ic-os/guestos:bootloader/extra_boot_args.template",
            ":partition-root-test-hash",
        ],
        outs = ["extra_boot_test_args"],
        cmd = "sed -e s/ROOT_HASH/$$(cat $(location :partition-root-test-hash))/ < $(location //ic-os/guestos:bootloader/extra_boot_args.template) > $@",
    )

    disk_image(
        name = "disk-img.tar",
        layout = "//ic-os/guestos:partitions.csv",
        partitions = [
            "//ic-os/bootloader:partition-esp.tar",
            "//ic-os/bootloader:partition-grub.tar",
            ":partition-config.tar",
            ":partition-boot.tar",
            "partition-root.tar",
        ],
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    native.genrule(
        name = "disk-img.tar_zst",
        srcs = ["disk-img.tar"],
        outs = ["disk-img.tar.zst"],
        cmd = "zstd --threads=0 -10 -f -z $< -o $@",
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
    )

    sha256sum(
        name = "disk-img.tar.zst.sha256",
        srcs = [":disk-img.tar.zst"],
    )

    gzip_compress(
        name = "disk-img.tar.gz",
        srcs = ["disk-img.tar"],
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
    )

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

    native.genrule(
        name = "update-img.tar_zst",
        srcs = ["update-img.tar"],
        outs = ["update-img.tar.zst"],
        cmd = "zstd --threads=0 -10 -f -z $< -o $@",
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
    )

    sha256sum(
        name = "update-img.tar.zst.sha256",
        srcs = [":update-img.tar.zst"],
    )

    gzip_compress(
        name = "update-img.tar.gz",
        srcs = ["update-img.tar"],
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
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

    native.genrule(
        name = "update-img-test.tar_zst",
        srcs = ["update-img-test.tar"],
        outs = ["update-img-test.tar.zst"],
        cmd = "zstd --threads=0 -10 -f -z $< -o $@",
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
    )

    sha256sum(
        name = "update-img-test.tar.zst.sha256",
        srcs = [":update-img-test.tar.zst"],
    )

    gzip_compress(
        name = "update-img-test.tar.gz",
        srcs = ["update-img-test.tar"],
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
    )

    upload_suffix = ""
    if mode == "dev":
        upload_suffix = "-dev"
    if malicious:
        upload_suffix += "-malicious"

    upload_artifacts(
        name = "upload_disk-img",
        inputs = [
            ":disk-img.tar.zst",
            ":disk-img.tar.gz",
        ],
        remote_subdir = "guest-os/disk-img" + upload_suffix,
    )

    upload_artifacts(
        name = "upload_update-img",
        inputs = [
            ":update-img.tar.zst",
            ":update-img.tar.gz",
            ":update-img-test.tar.zst",
            ":update-img-test.tar.gz",
        ],
        remote_subdir = "guest-os/update-img" + upload_suffix,
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

    native.filegroup(
        name = "hash_and_upload_update-img",
        srcs = [
            ":upload_update-img",
            ":update-img.tar.zst.sha256",
        ],
        visibility = ["//visibility:public"],
        tags = ["manual"],
    )

    native.filegroup(
        name = "hash_and_upload_update-img-test",
        srcs = [
            ":upload_update-img-test",
            ":update-img-test.tar.zst.sha256",
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
        srcs = [
            ":disk-img.tar.zst",
            ":disk-img.tar.gz",
            ":update-img.tar.zst",
            ":update-img.tar.gz",
            ":update-img-test.tar.zst",
            ":update-img-test.tar.gz",
        ],
        visibility = visibility,
    )

# Declare the dependencies that we will have for the built filesystem images.
# This needs to be done separately from the build rules because we want to
# compute the hash over all inputs going into the image and derive the
# "version.txt" file from it.
def _boundary_node_image_deps(mode, sev = False):
    extra_rootfs_deps = {
        "dev": {
            "//typescript/service-worker:index.html": "/var/www/html/index.html:0644",
            "//typescript/service-worker:install-script.js": "/var/www/html/install-script.js:0644",
            "//typescript/service-worker:install-script.js.map": "/var/www/html/install-script.js.map:0644",
            "//typescript/service-worker:sw.js": "/var/www/html/sw.js:0644",
            "//typescript/service-worker:sw.js.map": "/var/www/html/sw.js.map:0644",
        },
        "prod": {},
    }
    sev_rootfs_deps = {
        "@sevtool": "/opt/ic/bin/sevtool:0755",
    }
    deps = {
        "bootfs": {
            # base layer
            ":rootfs-tree.tar": "/",

            # We will install extra_boot_args onto the system, after substuting
            # the hash of the root filesystem into it. Add the template (before
            # substitution) as a dependency nevertheless such that changes
            # to the template file are reflected in the overall version hash
            # (the root_hash must include the version hash, it cannot be the
            # other way around).
            "//ic-os/boundary-guestos:bootloader/extra_boot_args.template": "/boot/extra_boot_args.template:0644",
        },
        "rootfs": {
            # base layer
            ":rootfs-tree.tar": "/",

            # additional files to install
            "//publish/binaries:boundary-node-control-plane": "/opt/ic/bin/boundary-node-control-plane:0755",
            "//publish/binaries:boundary-node-prober": "/opt/ic/bin/boundary-node-prober:0755",
            "//publish/binaries:certificate-issuer": "/opt/ic/bin/certificate-issuer:0755",
            "//publish/binaries:certificate-syncer": "/opt/ic/bin/certificate-syncer:0755",
            "//publish/binaries:denylist-updater": "/opt/ic/bin/denylist-updater:0755",
            "//publish/binaries:ic-balance-exporter": "/opt/ic/bin/ic-balance-exporter:0755",
            "//publish/binaries:ic-registry-replicator": "/opt/ic/bin/ic-registry-replicator:0755",
            "//publish/binaries:icx-proxy": "/opt/ic/bin/icx-proxy:0755",
        },
    }
    deps["rootfs"].update(extra_rootfs_deps[mode])
    if sev:
        deps["rootfs"].update(sev_rootfs_deps)

    return deps

def boundary_node_icos_build(name, mode = None, sev = False, visibility = None):
    """
    A boundary node ICOS build parameterized by mode.

    Args:
      name: Name for the generated filegroup.
      mode: dev, or prod. If not specified, will use the value of `name`
      sev: if True, build an SEV-SNP enabled image
      visibility: See Bazel documentation
    """
    if mode == None:
        mode = name

    image_deps = _boundary_node_image_deps(mode, sev = sev)

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
        srcs = ["//ic-os:vuln-scan.sh"],
        data = [
            "@trivy//:trivy",
            ":rootfs-tree.tar",
            "//ic-os:vuln-scan.html",
        ],
        env = {
            "trivy_path": "$(rootpath @trivy//:trivy)",
            "DOCKER_TAR": "$(rootpaths :rootfs-tree.tar)",
            "TEMPLATE_FILE": "$(rootpath //ic-os:vuln-scan.html)",
        },
    )

    docker_tar(
        visibility = visibility,
        name = "rootfs-tree.tar",
        src = "//ic-os/boundary-guestos:rootfs",
        dep = ["//ic-os/boundary-guestos:rootfs-files"],
        build_args = [
            "BUILD_TYPE=" + mode,
        ] + rootfs_args,
        file_build_args = file_build_args,
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
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

    # TODO(IDX-2538): re-enable this (or any other similar) solution when everything will be ready to have ic version that is not git revision.
    #summary_sha256sum(
    #    name = "version.txt",
    #    inputs = image_deps,
    #    suffix = "-dev" if mode == "dev" else "",
    #)

    copy_file(
        name = "copy_version_txt",
        src = "//bazel:version.txt",
        out = "version.txt",
        allow_symlink = True,
    )

    copy_file(
        name = "copy_ic_version_id",
        src = ":version.txt",
        out = "ic_version_id",
        allow_symlink = True,
        visibility = ["//visibility:public"],
        tags = ["manual"],
    )

    ext4_image(
        name = "partition-boot.tar",
        src = "rootfs-tree.tar",
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
            if ":bootloader/extra_boot_args.template" not in k
            # additional files to install
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
        src = "rootfs-tree.tar",
        # Take the dependency list declared above, and add in the "version.txt"
        # at the correct place.
        extra_files = {
            k: v
            for k, v in (image_deps["rootfs"].items() + [(":version.txt", "/opt/ic/share/version.txt:0644")])
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
            "//ic-os/bootloader:partition-grub.tar",
            ":partition-config.tar",
            ":partition-boot.tar",
            "partition-root.tar",
        ],
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    native.genrule(
        name = "disk-img.tar_zst",
        srcs = ["disk-img.tar"],
        outs = ["disk-img.tar.zst"],
        cmd = "zstd --threads=0 -10 -f -z $< -o $@",
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
    )

    sha256sum(
        name = "disk-img.tar.zst.sha256",
        srcs = [":disk-img.tar.zst"],
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
