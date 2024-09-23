load("@bazel_skylib//lib:paths.bzl", "paths")
load("//ic-os/components:hostos.bzl", "component_files")

def copy_components_commands(label_to_destination_map):
    command = ""
    for label, destination in label_to_destination_map.items():
        if destination[0] == "/":
            destination = destination[1:]

        command += """
#        mkdir -p $$(dirname $$container_dir/tmp/icos_components/{destination})
#        cp $(location {label}) $$container_dir/tmp/icos_components/{destination}
        mkdir -p $$(dirname $$container_dir/{destination})
        sudo cp $(location {label}) $$container_dir/{destination}
        """.format(label = label, destination = destination)

    return command

# package_list_files is a list of labels, each label pointing to a file with a list of packages
def install_packages_commands(package_list_files):
    pass

def build_hostos(name):
    base_image_name = "base_" + name + ".zst"
    native.genrule(
        name = "build_base_" + name,
        outs = [base_image_name],
        srcs = [
            "@node_exporter-1.8.1.linux-amd64.tar.gz//file",
            "@ubuntu-base-20.04.1-base-amd64.tar.gz//file",
            "//ic-os/hostos/context:packages.common",
        ],
        cmd = """
            set -euo pipefail

            # Create container directory
            container_dir=$$(mktemp -d "/tmp/tmpfs/icosbuildXXXX")
            trap 'sudo rm -rf $$container_dir' INT TERM EXIT

            # Untar the Ubuntu base image
            tar -xzf $(location @ubuntu-base-20.04.1-base-amd64.tar.gz//file) -C "$$container_dir"

            # Install node_exporter
            mkdir -p $$container_dir/etc/node_exporter
            tar --strip-components=1 -C $$container_dir/usr/local/bin/ \
              -zvxf $(location @node_exporter-1.8.1.linux-amd64.tar.gz//file) \
              node_exporter-1.8.1.linux-amd64/node_exporter

#            TODO: figure out network
          cp /etc/resolv.conf $$container_dir/etc/resolv.conf

          # Copy list of packages
          cp $(location //ic-os/hostos/context:packages.common) $$container_dir/tmp

          /home/dfrank/dev/ic/toolchains/sysimage/tschroot.sh $$container_dir /bin/bash -x << 'EOF'
              PACKAGES=(/tmp/packages.common)
              sudo mount -t proc none /proc && \
              sudo mount -t sys none /sys && \
              ln -snf /usr/share/zoneinfo/UTC /etc/localtime && echo UTC > /etc/timezone && \
              apt-get -y update && \
              apt-get -y upgrade && \
              apt-get -y --no-install-recommends install $$(for P in $$PACKAGES; do cat $$P | sed -e "s/#.*//" ; done)
EOF

          sudo chown -R ubuntu $$container_dir

          # Clean up
          rm -rf $$container_dir/dev/*
          rm -rf $$container_dir/proc/*
          rm -rf $$container_dir/var/log/*
          rm -rf $$container_dir/tmp/*

          # Export tar
          output_tar_path=$$(realpath $@)
          cd $$container_dir
          tar --mtime='UTC 1970-01-01' -caf $$output_tar_path *
        """,
    )

    native.genrule(
        name = "build_" + name,
        srcs = [
            base_image_name,
            "//ic-os/hostos/context:setup.sh",
            # "qemu",
            # "qemu-system-x86_64",
        ] + component_files.keys(),
        outs = [name],
        cmd = """
            set -euo pipefail

            # Create container directory
            container_dir=$$(mktemp -d "/tmp/tmpfs/icosbuildXXXX")
            trap 'sudo rm -rf $$container_dir' INT TERM EXIT

            # Untar the base image (see definition above)
            tar -xaf $(location {base_image_name}) -C "$$container_dir"
            sudo chown -R ubuntu $$container_dir

            # Copy components
            {copy_components_commands}

            # Copy and run setup script
            cp $(location //ic-os/hostos/context:setup.sh) $$container_dir/tmp/setup_icos.sh
            chmod 777 $$container_dir/tmp/setup_icos.sh
#            fakechroot fakeroot chroot $$container_dir /tmp/setup_icos.sh
            /home/dfrank/dev/ic/toolchains/sysimage/tschroot.sh $$container_dir env "ROOT_PASSWORD=root" /tmp/setup_icos.sh

            sudo chown -R ubuntu $$container_dir

            # Clean up
            rm -rf $$container_dir/dev/*
            rm -rf $$container_dir/proc/*
            rm -rf $$container_dir/tmp/*
            rm -rf $$container_dir/var/cache/*
            rm -rf $$container_dir/var/log/*
            rm -rf $$container_dir/var/lib/apt/lists/*

            # Export tar
            output_tar_path=$$(realpath $@)
            cd $$container_dir
            tar --mtime='UTC 1970-01-01' -caf $$output_tar_path *
          """.format(
            copy_components_commands = copy_components_commands(component_files),
            base_image_name = base_image_name,
        ),

        #    native.genrule(
        #        name = "build_" + name,
        #        srcs = [
        #            "base" + name,
        #            "@node_exporter-1.8.1.linux-amd64.tar.gz//file",
        #            "@ubuntu-base-20.04.1-base-amd64.tar.gz//file",
        #            "//ic-os/hostos/context:setup.sh",
        #            "//ic-os/hostos/context:packages.common",  # TODO: also handle dev packages
        #            # "qemu",
        #            # "qemu-system-x86_64",
        #        ] + component_files.keys(),
        #        outs = [name],
        #        cmd = """
        #            set -euo pipefail
        #
        #            # Create container directory and untar the Ubuntu base image
        #            container_dir=$$(mktemp -d "/tmp/tmpfs/icosbuildXXXX")
        #            mkdir -p $$container_dir
        #            trap 'sudo rm -rf $$container_dir' INT TERM EXIT
        #            tar -xzf $(location @ubuntu-base-20.04.1-base-amd64.tar.gz//file) -C "$$container_dir"
        #
        #            # Install node_exporter
        #            mkdir -p $$container_dir/etc/node_exporter
        #            tar --strip-components=1 -C $$container_dir/usr/local/bin/ \
        #              -zvxf $(location @node_exporter-1.8.1.linux-amd64.tar.gz//file) \
        #              node_exporter-1.8.1.linux-amd64/node_exporter
        #
        #            # TODO: figure out network
        #            cp /etc/resolv.conf $$container_dir/etc/resolv.conf
        #
        #            # Copy components
        #            {copy_components_commands}
        #
        #            # Copy list of packages
        #            cp $(location //ic-os/hostos/context:packages.common) $$container_dir/tmp
        #
        #            # Copy and run setup script
        #            cp $(location //ic-os/hostos/context:setup.sh) $$container_dir/tmp/setup_icos.sh
        #            chmod 777 $$container_dir/tmp/setup_icos.sh
        ##            fakechroot fakeroot chroot $$container_dir /tmp/setup_icos.sh
        #            /home/dfrank/dev/ic/toolchains/sysimage/tschroot.sh $$container_dir /tmp/setup_icos.sh
        #
        #            sudo chown -R ubuntu $$container_dir
        #
        #            # Export tar
        #            output_tar_path=$$(realpath $@)
        #            cd $$container_dir
        #            tar --sparse --mtime='UTC 1970-01-01' -cf $$output_tar_path *
        #          """.format(
        #            copy_components_commands = copy_components_commands(component_files),
        #        ),
    )

#def copy_components_commands(target_to_destination_map):
#    command = ""
#    for target, dest_path in target_to_destination_map:
#        file = target[DefaultInfo].files.to_list()[0]
#        if dest_path[0] == "/":
#            dest_path = dest_path[1:]
#
#        command += """
#        mkdir -p $(dirname {destination})
#        cp {source} {destination}
#        """.format(source = file.path, destination = "$container_dir/" + dest_path)
#
#    return command
#def _build_hostos_impl(ctx):
#    output_tar = ctx.actions.declare_file(ctx.label.name)
#    ctx.actions.run_shell(
#        outputs = [output_tar],
#        command = """
#            set -euo pipefail
#
#            # Create container directory and untar the Ubuntu base image
#            container_dir=$(mktemp -d --tmpdir "icosbuildXXXX")
#            mkdir -p $container_dir
#            trap 'rm -rf $container_dir' INT TERM EXIT
#            tar -xzf {base_image_tar_path} -C "$container_dir"
#
#            # Install node_exporter
#            mkdir -p $container_dir/etc/node_exporter
#            tar --strip-components=1 -C $container_dir/usr/local/bin/ \
#                -zvxf {node_exporter_tar_path} \
#                node_exporter-1.8.1.linux-amd64/node_exporter
#
#            # Copy list of packages
#            cp $(location //ic-os/hostos/context:packages.common) $container_dir/tmp
#
#            # Copy components
#            {copy_components_commands}
#
#            # Copy and run setup script
#            cp {setup_sh_path} $container_dir/tmp/setup_icos.sh
#            chmod 777 $container_dir/tmp/setup_icos.sh
#            fakechroot fakeroot chroot $container_dir /tmp/setup_icos.sh
#
#            # Export tar
#            output_tar_path=$(realpath {output_tar_path})
#            cd $container_dir
#            tar --mtime='UTC 1970-01-01' -cf $output_tar_path *
#        """.format(
#            output_tar_path = output_tar.path,
#            setup_sh_path = ctx.file.setup_sh.path,
#            base_image_tar_path = ctx.file.base_image_tar.path,
#            node_exporter_tar_path = ctx.file.node_exporter_tar.path,
#            copy_components_commands = copy_components_commands(ctx.attr.components.items()),
#        ),
#    )
#    return [DefaultInfo(files = depset([output_tar]))]
#
#build_hostos = rule(
#    implementation = _build_hostos_impl,
#    provides = [DefaultInfo],
#    attrs = {
#        "components": attr.label_keyed_string_dict(
#            default = component_files,
#            allow_files = True,
#        ),
#        "setup_sh": attr.label(
#            default = "//ic-os/hostos/context:setup.sh",
#            executable = True,
#            cfg = "exec",
#        ),
#        "base_image_tar": attr.label(
#            default = "@ubuntu-base-20.04.1-base-amd64.tar.gz//file",
#        ),
#        "node_exporter_tar": attr.label(
#            default = "@node_exporter-1.8.1.linux-amd64.tar.gz//file",
#        ),
#    },
#)
