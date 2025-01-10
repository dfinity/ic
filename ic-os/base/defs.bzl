load("@bazel_skylib//lib:paths.bzl", "paths")
load("@rules_distroless//distroless:defs.bzl", "passwd")
load("@rules_oci//oci:defs.bzl", "oci_image", "oci_load")
load("//ic-os/components:hostos.bzl", "component_files")

CUSTOM_PACKAGE_DEFS_ = {
    "node_exporter": {
        "srcs": ["@node_exporter-1.8.1.linux-amd64.tar.gz//file"],
        "install": """
            mkdir -p $$CONTAINER_DIR/etc/node_exporter
            tar --strip-components=1 -C $$CONTAINER_DIR/usr/local/bin/ \
              -zvxf $(location @node_exporter-1.8.1.linux-amd64.tar.gz//file) \
              node_exporter-1.8.1.linux-amd64/node_exporter
        """,
    },
    "filebeat": {
        "srcs": ["@filebeat-oss-8.9.1-linux-x86_64.tar.gz//file"],
        "install": """
            mkdir -p $$CONTAINER_DIR/var/lib/filebeat \
                     $$CONTAINER_DIR/var/log/filebeat
            tar --strip-components=1 -C $$CONTAINER_DIR/usr/local/bin/ \
                -zvxf $(location @filebeat-oss-8.9.1-linux-x86_64.tar.gz//file) \
                filebeat-8.9.1-linux-x86_64/filebeat
        """,
    },
}

def icos_container_filesystem(name, apt_packages, component_files, build_args, custom_packages, setup_script):
    base_image_name = "base_" + name

    oci_image(
        name = name + "_base_image_test",
        architecture = "amd64",
        os = "linux",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tars = [
            #            #            "@ubuntu-base-24.04.1-base-amd64.tar.gz//file",
            #            #            "@noble//linux-image-virtual-hwe-24.04/amd64",
            "@noble//initramfs-tools/amd64",
            #
            #            # Need systemd for boot process
            #            "@noble//systemd/amd64",
            #            "@noble//systemd-sysv/amd64",
            #            "@noble//systemd-journal-remote/amd64",
            #            "@noble//systemd-resolved/amd64",
            #
            #            # Third-party services we will be running
            #            #            "@noble//chrony/amd64",
            #            #            "@noble//openssh-server/amd64",
            #            #
            #            # Runtime libraries for replica
            #            "@noble//liblmdb0/amd64",
            #            "@noble//libunwind8/amd64",
            #            "@noble//libselinux1/amd64",
            #            #
            #            # Smartcard support for replica
            #            "@noble//pcsc-tools/amd64",
            #            "@noble//pcscd/amd64",
            #            "@noble//opensc/amd64",
            #
            #            # Required system setup tools
            #            "@noble//attr/amd64",
            #            "@noble//ca-certificates/amd64",
            #            "@noble//cryptsetup/amd64",
            #            "@noble//curl/amd64",
            #            "@noble//faketime/amd64",
            #            "@noble//fdisk/amd64",
            #            "@noble//iproute2/amd64",
            #            "@noble//isc-dhcp-client/amd64",
            #            "@noble//jq/amd64",
            #            "@noble//less/amd64",
            #            "@noble//lvm2/amd64",
            #            "@noble//net-tools/amd64",
            #            "@noble//nftables/amd64",
            #            "@noble//parted/amd64",
            #            "@noble//rsync/amd64",
            #            #            "@noble//sudo/amd64",
            #            "@noble//sysfsutils/amd64",
            #            "@noble//udev/amd64",
            #            "@noble//usbutils/amd64",
            #            "@noble//xfsprogs/amd64",
            #            "@noble//zstd/amd64",
            #
            #            # This is unclear -- why is this here? This should "probably" be dev tool.
            #            "@noble//protobuf-compiler/amd64",
            #
            #            # SELinux support
            #            "@noble//selinux-policy-default/amd64",
            #            "@noble//selinux-utils/amd64",
            #            "@noble//semodule-utils/amd64",
            #            "@noble//policycoreutils/amd64",
            #            # this is required for policy building -- presently policy modules are built
            #            # inside the target which is not fully proper. When the build is moved out,
            #            # this package can be removed
            #            "@noble//selinux-policy-dev/amd64",
            #            "@noble//checkpolicy/amd64",
        ],
    )

    oci_tar(
        name = name + "_base_image_test_export.tar",
        image = name + "_base_image_test",
    )

    # First load the image
    oci_load(
        repo_tags = ["icos_base:test"],
        name = name + "_base_image_test_load",
        image = name + "_base_image_test",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    #    native.genrule(
    #        name = name + "_base_image_test_export.tar",
    #        outs = [],
    #        srcs = [name],
    #        cmd = """
    #
    #        """,
    #    )

    native.genrule(
        name = "build_" + base_image_name,
        outs = [base_image_name],
        srcs = [
            "//ic-os/base:apt_snapshot.txt",
            "//ic-os/components:networking/resolv.conf",
            "@ubuntu-base-24.04.1-base-amd64.tar.gz//file",
        ] + _package_srcs(apt_packages, custom_packages),
        tools = ["//toolchains/sysimage:run_in_namespace"],
        cmd = """
            set -xeuo pipefail

            export SOURCE_DATE_EPOCH=0

            # Create container directory
            CONTAINER_DIR=$$(mktemp -d --tmpdir "icosbuildXXXX")
            trap 'rm -rf $$CONTAINER_DIR' INT TERM EXIT

            # We put all shared files required in the setup into ICOS_BUILD_DIR
            export ICOS_BUILD_DIR="$$CONTAINER_DIR/icos_build"
            mkdir $$ICOS_BUILD_DIR

            # Untar the Ubuntu base image
            $(location //toolchains/sysimage:run_in_namespace) /bin/bash -x << EOF
                tar -xzf $(location @ubuntu-base-24.04.1-base-amd64.tar.gz//file) --no-same-owner -C $$CONTAINER_DIR
EOF

            # Set up networking
            cp $(location //ic-os/components:networking/resolv.conf) $$CONTAINER_DIR/etc/resolv.conf

            echo "{prepare_local_apt_packages_commands}"
            {prepare_local_apt_packages_commands}
            {install_custom_packages_commands}

            export APT_SNAPSHOT=$$(<$(location //ic-os/base:apt_snapshot.txt))
            # Run setup from within the newly built environment
            $(location //toolchains/sysimage:run_in_namespace) --mount --chroot $$CONTAINER_DIR /bin/bash -x << 'EOF'
                set -euo pipefail

                export ICOS_BUILD_DIR="/icos_build"

                cat /etc/subuid

                newuidmap $$BASHPID 0 1000 65534
                newgidmap $$BASHPID 0 1002 65534

                # Set timezone
                ln -snf /usr/share/zoneinfo/UTC /etc/localtime && echo UTC > /etc/timezone

                # Install packages
                apt install --update --snapshot "$$APT_SNAPSHOT" -o Acquire::Check-Valid-Until=false \
                            -o Acquire::https::Verify-Peer=false -y ca-certificates
                apt -y --snapshot "$$APT_SNAPSHOT" upgrade > /dev/null

                apt -y --no-install-recommends --snapshot "$$APT_SNAPSHOT" install {apt_packages} > /dev/null
                apt clean
EOF

            # Export root
            $(location //toolchains/sysimage:run_in_namespace) --chroot $$CONTAINER_DIR /bin/bash -x << 'EOF'
                tar -c \
                  --sort=name --mtime='UTC 1970-01-01' --sparse --hole-detection=raw \
                  -f out.tar *
EOF

            mv $$CONTAINER_DIR/out.tar $@
        """.format(
            apt_packages = _apt_packages_string(apt_packages),
            install_custom_packages_commands = _install_custom_packages_commands(custom_packages),
            prepare_local_apt_packages_commands = _prepare_local_apt_packages_commands(apt_packages),
        ),
    )

    native.genrule(
        name = "build_" + name,
        srcs = [
            base_image_name,
            setup_script,
            "//ic-os/base:build_utils.sh",
        ] + component_files.keys(),
        tools = ["//toolchains/sysimage:run_in_namespace"],
        outs = [name],
        cmd = """
            # Create container directory
            export CONTAINER_DIR=$$(mktemp -d --tmpdir "icosbuildXXXX")
            trap 'rm -rf $$CONTAINER_DIR' INT TERM EXIT

            # We put all shared files required in the setup into ICOS_BUILD_DIR
            export ICOS_BUILD_DIR="$$CONTAINER_DIR/icos_build"
            mkdir $$ICOS_BUILD_DIR
            cp -a $(location //ic-os/base:build_utils.sh) $$ICOS_BUILD_DIR
            cp -a $(location {setup_script}) $$ICOS_BUILD_DIR/setup.sh

            # Untar the base image (see definition in the previous rule)
            $(location //toolchains/sysimage:run_in_namespace) /bin/bash -x << EOF
                tar -xaf $(location {base_image_name}) -C $$CONTAINER_DIR
EOF

            # Copy components to icos build components directory
            icos_components_dir="$$ICOS_BUILD_DIR/components"
            mkdir $$icos_components_dir
            {copy_components_commands}

            export {build_args} > /dev/null

            # Run setup script in chroot
            $(location //toolchains/sysimage:run_in_namespace) --mount --chroot $$CONTAINER_DIR /bin/bash /icos_build/setup.sh

            # Export root
            $(location //toolchains/sysimage:run_in_namespace) --chroot $$CONTAINER_DIR /bin/bash -x << 'EOF'
                tar -c \
                    --exclude=var/* --exclude=etc/nvme/hostnqn --exclude=etc/nvme/hostid \
                    --exclude=icos_build \
                    --sort=name --mtime='UTC 1970-01-01' --sparse --hole-detection=raw \
                    -f out.tar *
EOF

            mv $$CONTAINER_DIR/out.tar $@
          """.format(
            copy_components_commands = _copy_components_commands(component_files),
            base_image_name = base_image_name,
            build_args = " ".join(build_args),
            setup_script = setup_script,
        ),
    )

def _package_srcs(apt_packages, custom_packages):
    srcs = []
    for package in apt_packages:
        if package.startswith("@"):
            srcs.append(package)

    for package in custom_packages:
        package_def = CUSTOM_PACKAGE_DEFS_[package] or fail("Custom package not defined: %s" % package)
        srcs.extend(package_def["srcs"])
    return srcs

def _install_custom_packages_commands(custom_packages):
    commands = ""
    for package in custom_packages:
        package_def = CUSTOM_PACKAGE_DEFS_[package] or fail("Custom package not defined: %s" % package)
        commands += package_def["install"] + "\n"
    return commands

def _apt_packages_string(apt_packages):
    result = ""
    for package in apt_packages:
        if package.startswith("@"):
            result += _apt_package_path(package)
        else:
            result += package
        result += " "
    return result

def _apt_package_path(package):
    package = package.removeprefix("@")
    package = package.removesuffix("//file")
    if not package.endswith(".deb"):
        fail("apk package names should end in .deb, found: " + package)
    return "$$ICOS_BUILD_DIR/" + package

def _prepare_local_apt_packages_commands(apt_packages):
    commands = ""
    for package in apt_packages:
        if not package.startswith("@"):
            continue
        commands += 'cp "$(location {package})" "{target_path}" \n'.format(
            package = package,
            target_path = _apt_package_path(package),
        )
    return commands

def _copy_components_commands(label_to_destination_map):
    command = ""
    for label, destination in label_to_destination_map.items():
        if destination[0] == "/":
            destination = destination[1:]

        destination = "$$icos_components_dir/" + destination
        command += """
            mkdir -p $$(dirname {destination})  # Create parent dirs
            cp -a $(location {label}) {destination}
        """.format(label = label, destination = destination)

    return command

def oci_tar(name, image, repo_tags = []):
    """Create a tarball from an OCI image. The target is marked as 'manual'.

    Args:
      name: This name will be used for the tarball (must end with '.tar').
      repo_tags: OCI tags for oci_load.
      image: The OCI image to bundle.
    """

    if not name.endswith(".tar"):
        fail("Expected tarname to end with '.tar': " + name)

    basename = name.removesuffix(".tar")

    name_image = basename + "_image"

    # First load the image
    oci_load(
        name = name_image,
        image = image,
        repo_tags = repo_tags,
        target_compatible_with = [
            "@platforms//os:linux",
        ],
    )

    # create the tarball
    name_tarballdir = basename + "_tarballdir"
    native.filegroup(
        name = name_tarballdir,
        srcs = [":" + name_image],
        output_group = "tarball",
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        tags = ["manual"],
    )

#    # Copy the tarball out so we can reference the file by 'name'
#    copy_file(
#        name = basename + "_tar",
#        src = ":" + name_tarballdir,
#        out = name,
#        target_compatible_with = [
#            "@platforms//os:linux",
#        ],
#        tags = ["manual"],
#    )
