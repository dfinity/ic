"""
A macro to build multiple versions of the ICOS image (i.e., dev vs prod)
"""

load("//toolchains/sysimage:toolchain.bzl", "disk_image", "docker_tar", "ext4_image", "sha256sum", "summary_sha256sum", "tar_extract", "upgrade_image")
load("//gitlab-ci/src/artifacts:upload.bzl", "upload_artifacts", "urls_test")

img_bases = {
    "dev": "dfinity/guestos-base-dev@sha256:cc19a9356b4b62a9133d93f3477293dd54996e2e7a449b9947027cbb8da200c8",
    "prod": "dfinity/guestos-base@sha256:2393f708544922105927ccae5c315bc7fd1265c0590fd2b362362ee414948312",
}

# Declare the dependencies that we will have for the built filesystem images.
# This needs to be done separately from the build rules because we want to
# compute the hash over all inputs going into the image and derive the
# "version.txt" file from it.
def _image_deps(mode, name, malicious = False):
    extra_rootfs_deps = {
        "dev": {":rootfs/allow_console_root": "/etc/allow_console_root:0644"},
        "prod": {},
    }
    deps = {
        "bootfs": {
            # base layer
            ":{}_rootfs-tree.tar".format(name): "/",

            # We will install extra_boot_args onto the system, after substuting
            # the hash of the root filesystem into it. Add the template (before
            # substitution) as a dependency nevertheless such that changes
            # to the template file are reflected in the overall version hash
            # (the root_hash must include the version hash, it cannot be the
            # other way around).
            ":bootloader/extra_boot_args.template": "/boot/extra_boot_args.template:0644",
        },
        "rootfs": {
            # base layer
            ":{}_rootfs-tree.tar".format(name): "/",

            # additional files to install
            "//:canister_sandbox": "/opt/ic/bin/canister_sandbox:0755",
            "//:ic-btc-adapter": "/opt/ic/bin/ic-btc-adapter:0755",
            "//:ic-consensus-pool-util": "/opt/ic/bin/ic-consensus-pool-util:0755",
            "//:ic-canister-http-adapter": "/opt/ic/bin/ic-canister-http-adapter:0755",
            "//:ic-crypto-csp": "/opt/ic/bin/ic-crypto-csp:0755",
            "//:ic-regedit": "/opt/ic/bin/ic-regedit:0755",
            "//:ic-recovery": "/opt/ic/bin/ic-recovery:0755",
            "//:orchestrator": "/opt/ic/bin/orchestrator:0755",
            ("//:malicious_replica" if malicious else "//:replica"): "/opt/ic/bin/replica:0755",
            "//:sandbox_launcher": "/opt/ic/bin/sandbox_launcher:0755",
            "//:state-tool": "/opt/ic/bin/state-tool:0755",
            "//:vsock_agent": "/opt/ic/bin/vsock_agent:0755",
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
      name: Name for the generated filegroup. You can access individual artifacts via
        //ic-os/guestos:{name}_{artifact}, i.e. //ic-os/guestos:dev_disk-img.tar.gz
      mode: dev or prod. If not specified, will use the value of `name`
      malicious: if True, bundle the `malicious_replica`
      visibility: See Bazel documentation
    """
    if mode == None:
        mode = name

    nm = lambda s: "{}_{}".format(name, s)

    lbl = lambda s: ":" + nm(s)

    image_deps = _image_deps(mode, name, malicious)

    dev_rootfs_args = []

    if mode == "dev":
        dev_rootfs_args = ["--extra-dockerfile", "ic-os/guestos/rootfs/Dockerfile.dev", "--dev-root-ca", "ic-os/guestos/dev-root-ca.crt"]

    docker_tar(
        visibility = visibility,
        name = nm("rootfs-tree.tar"),
        src = ":rootfs",
        dep = native.glob(["rootfs/**"] + ["dev-root-ca.crt"] if mode == "dev" else []),
        extra_args_before = dev_rootfs_args,
        extra_args_after = [
            "--build-arg",
            "ROOT_PASSWORD=root",
            "--build-arg",
            "BASE_IMAGE=" + img_bases[mode],
        ],
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    ext4_image(
        name = nm("partition-config.tar"),
        partition_size = "100M",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    tar_extract(
        visibility = visibility,
        name = nm("file_contexts"),
        src = lbl("rootfs-tree.tar"),
        path = "etc/selinux/default/contexts/files/file_contexts",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    summary_sha256sum(
        name = nm("version.txt"),
        inputs = image_deps,
        suffix = "-dev" if mode == "dev" else "",
    )

    ext4_image(
        name = nm("partition-boot.tar"),
        src = lbl("rootfs-tree.tar"),
        # Take the dependency list declared above, and add in the "version.txt"
        # as well as the generated extra_boot_args file in the correct place.
        extra_files = {
            k: v
            for k, v in (
                image_deps["bootfs"].items() + [
                    (lbl("version.txt"), "/boot/version.txt:0644"),
                    (lbl("extra_boot_args"), "/boot/extra_boot_args:0644"),
                ]
            )
            if k != ":bootloader/extra_boot_args.template"
            # additional files to install
            if v != "/"
        },
        file_contexts = lbl("file_contexts"),
        partition_size = "1G",
        subdir = "boot/",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    ext4_image(
        name = nm("partition-root-unsigned.tar"),
        src = lbl("rootfs-tree.tar"),
        # Take the dependency list declared above, and add in the "version.txt"
        # at the correct place.
        extra_files = {
            k: v
            for k, v in (image_deps["rootfs"].items() + [(lbl("version.txt"), "/opt/ic/share/version.txt:0644")])
            if v != "/"
        },
        file_contexts = lbl("file_contexts"),
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
        name = nm("partition-root-sign"),
        srcs = [lbl("partition-root-unsigned.tar")],
        outs = [nm("partition-root.tar"), nm("partition-root-hash")],
        cmd = "$(location //toolchains/sysimage:verity_sign.py) -i $< -o $(location {}) -r $(location {})".format(nm("partition-root.tar"), nm("partition-root-hash")),
        executable = False,
        tools = ["//toolchains/sysimage:verity_sign.py"],
    )

    native.genrule(
        name = nm("extra_boot_args_root_hash"),
        srcs = [
            ":bootloader/extra_boot_args.template",
            lbl("partition-root-hash"),
        ],
        outs = [lbl("extra_boot_args")],
        cmd = "sed -e s/ROOT_HASH/$$(cat $(location {}))/ < $(location :bootloader/extra_boot_args.template) > $@".format(lbl("partition-root-hash")),
    )

    disk_image(
        name = nm("disk-img.tar"),
        layout = ":partitions.csv",
        partitions = [
            "//ic-os/bootloader:partition-esp.tar",
            "//ic-os/bootloader:partition-grub.tar",
            lbl("partition-config.tar"),
            lbl("partition-boot.tar"),
            lbl("partition-root.tar"),
        ],
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    upgrade_image(
        name = nm("upgrade.tar"),
        boot_partition = lbl("partition-boot.tar"),
        root_partition = lbl("partition-root.tar"),
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        version_file = lbl("version.txt"),
    )

    native.genrule(
        name = nm("disk-img.tar_zst"),
        srcs = [lbl("disk-img.tar")],
        outs = [lbl("disk-img.tar.zst")],
        cmd = "zstd --threads=0 -10 -f -z $< -o $@",
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
    )

    sha256sum(
        name = nm("disk-img.tar.zst.sha256"),
        srcs = [lbl("disk-img.tar.zst")],
    )

    native.genrule(
        name = nm("disk-img.tar_gz"),
        srcs = [lbl("disk-img.tar")],
        outs = [lbl("disk-img.tar.gz")],
        cmd = "gzip -9 < $< > $@",
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
    )

    native.genrule(
        name = nm("upgrade.tar_zst"),
        srcs = [lbl("upgrade.tar")],
        outs = [lbl("upgrade.tar.zst")],
        cmd = "zstd --threads=0 -10 -f -z $< -o $@",
        # The image is pretty big, therefore it is usually much faster to just rebuild it instead of fetching from the cache.
        # TODO(IDX-2221): remove this when CI jobs and bazel infrastructure will run in the same clusters.
        tags = ["no-remote-cache"],
    )

    upload_artifacts(
        name = nm("upload_guestos"),
        inputs = [
            lbl("disk-img.tar.zst"),
            lbl("upgrade.tar.zst"),
        ],
        remote_subdir = "ic-os/guestos",
    )

    urls_test(
        name = nm("upload_guestos_test"),
        inputs = [lbl("upload_guestos")],
    )

    native.py_binary(
        name = nm("launch_single_vm"),
        main = "launch_single_vm.py",
        srcs = [
            ":launch_single_vm.py",
            "//ic-os/guestos/tests:ictools.py",
        ],
        env = {
            "DATA_PREFIX": nm(""),
        },
        data = [
            lbl("disk-img.tar.zst.sha256"),
            lbl("upload_guestos"),
            lbl("version.txt"),
            "//rs/prep:ic-prep",
        ],
        tags = ["manual"],
    )

    native.filegroup(
        name = name,
        srcs = [nm("disk-img.tar.zst"), nm("disk-img.tar.gz"), nm("upgrade.tar.zst")],
        visibility = visibility,
    )
