load("@bazel_skylib//lib:paths.bzl", "paths")
load("//ic-os/base:custom_packages.bzl", "filebeat", "linux_6_1_0_snp_kernel", "node_exporter")
load("//ic-os/components:hostos.bzl", "component_files")

CUSTOM_PACKAGE_DEFS_ = {
    node_exporter: {
        "src": "@node_exporter-1.8.1.linux-amd64.tar.gz//file",
        "install": """
            mkdir -p $$CONTAINER_DIR/etc/node_exporter
            tar --strip-components=1 -C $$CONTAINER_DIR/usr/local/bin/ \
              -zvxf $(location @node_exporter-1.8.1.linux-amd64.tar.gz//file) \
              node_exporter-1.8.1.linux-amd64/node_exporter
        """,
    },
    filebeat: {
        "src": "@filebeat-oss-8.9.1-linux-x86_64.tar.gz//file",
        "install": """
            mkdir -p $$CONTAINER_DIR/var/lib/filebeat \
                     $$CONTAINER_DIR/var/log/filebeat
            tar --strip-components=1 -C $$CONTAINER_DIR/usr/local/bin/ \
                -zvxf $(location @filebeat-oss-8.9.1-linux-x86_64.tar.gz//file) \
                filebeat-8.9.1-linux-x86_64/filebeat
        """,
    },
    linux_6_1_0_snp_kernel: {
        "src": "@linux-image-6.1.0-rc4-snp-host-93fa8c5918a4_6.1.0-rc4-snp-host-93fa8c5918a4-1_amd64.deb//file",
        "install": """
            cp $(location @linux-image-6.1.0-rc4-snp-host-93fa8c5918a4_6.1.0-rc4-snp-host-93fa8c5918a4-1_amd64.deb//file) $$ICOS_BUILD_DIR
            $(location //toolchains/sysimage:run_in_namespace) --chroot $$CONTAINER_DIR /bin/bash -x << 'EOF'
                dpkg -i /icos_build/linux-image-6.1.0-rc4-snp-host-93fa8c5918a4_6.1.0-rc4-snp-host-93fa8c5918a4-1_amd64.deb
                ln -sf vmlinuz-6.1.0-rc4-snp-host-93fa8c5918a4 /boot/vmlinuz
                ln -sf initrd.img-6.1.0-rc4-snp-host-93fa8c5918a4 /boot/initrd.img
                find /boot -name "*.old" | xargs -L 1 unlink
                find /boot -name "initrd*generic" \
                    -o -name "vmlinuz*generic" \
                    -o -name "config*generic" \
                    -o -name "System*generic" \
                    | xargs rm
                find /usr/lib/modules -maxdepth 1 -type d -name "*generic" | xargs rm -rf
EOF
        """,
    },
}

def icos_container_filesystem(name, apt_packages, component_files, build_args, custom_packages, setup_script):
    base_image_name = "base_" + name
    native.genrule(
        name = "build_" + base_image_name,
        outs = [base_image_name],
        srcs = [
            "//ic-os/base:apt_snapshot.txt",
            "//ic-os/components:networking/resolv.conf",
            "@ubuntu-base-24.04.1-base-amd64.tar.gz//file",
        ] + _custom_package_srcs(custom_packages),
        tools = ["//toolchains/sysimage:run_in_namespace"],
        cmd = """
            set -euo pipefail

            export SOURCE_DATE_EPOCH=0

            # Create container directory
            CONTAINER_DIR=$$(mktemp -d "/tmp/tmpfs/icosbuildXXXX")
            trap 'rm -rf $$CONTAINER_DIR' INT TERM EXIT

            # We put all shared files required in the setup into ICOS_BUILD_DIR
            export ICOS_BUILD_DIR="$$CONTAINER_DIR/icos_build"
            mkdir $$ICOS_BUILD_DIR

            # Untar the Ubuntu base image
            $(location //toolchains/sysimage:run_in_namespace) /bin/bash -x << EOF
                tar -xzf $(location @ubuntu-base-24.04.1-base-amd64.tar.gz//file) -C $$CONTAINER_DIR
EOF

            # Set up networking
            cp $(location //ic-os/components:networking/resolv.conf) $$CONTAINER_DIR/etc/resolv.conf

            {install_custom_packages_commands}

            export APT_SNAPSHOT=$$(<$(location //ic-os/base:apt_snapshot.txt))
            # Run setup from within the newly built environment
            $(location //toolchains/sysimage:run_in_namespace) --mount --chroot $$CONTAINER_DIR /bin/bash -x << 'EOF'
                set -euo pipefail

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
                  --exclude=icos_build \
                  --sort=name --mtime='UTC 1970-01-01' --sparse --hole-detection=raw \
                  -f out.tar *
EOF

            mv $$CONTAINER_DIR/out.tar $@
        """.format(
            apt_packages = " ".join(apt_packages),
            install_custom_packages_commands = _install_custom_packages_commands(custom_packages),
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
            export CONTAINER_DIR=$$(mktemp -d "/tmp/tmpfs/icosbuildXXXX")
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

def _custom_package_srcs(custom_packages):
    srcs = []
    for package in custom_packages:
        package_def = CUSTOM_PACKAGE_DEFS_[package] or fail("Custom package not defined: %s" % package)
        srcs.append(package_def["src"])
    return srcs

def _install_custom_packages_commands(custom_packages):
    commands = ""
    for package in custom_packages:
        package_def = CUSTOM_PACKAGE_DEFS_[package] or fail("Custom package not defined: %s" % package)
        commands += package_def["install"] + "\n"
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
