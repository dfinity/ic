#!/usr/bin/env python3
# This script starts a minimal IC instance consisting of a single VM node
# and makes its serial console accessible interactively. Use it in the
# following way:
#
# interactive --disk_image=<your VM disk image> --version=<version> --ic_prep_bin=<path/to/ic-prep>
#
# The given disk image is first "cloned", so whenever you use this tool you
# will get a freshly bootstrapped VM. Quitting qemu will destroy the VM.
import sys

import gflags
import ictools
import vmtools

FLAGS = gflags.FLAGS

gflags.DEFINE_string("disk_image", None, "Path to disk image to use for VMs")
gflags.MarkFlagAsRequired("disk_image")


def main(argv):
    argv = FLAGS(argv)

    machines = vmtools.pool().request_machines(
        [
            {"name": "node0", "ram": "6G", "disk": "100G", "cores": 1},
        ],
    )

    system_image = vmtools.SystemImage.open_local(FLAGS.disk_image)

    ic_config = ictools.ic_prep(
        subnets=[[machines[0].get_ipv6()]],
        version=ictools.get_disk_image_version(system_image),
        root_subnet=0,
    )

    config_image = ictools.build_ic_prep_inject_config(machines[0], ic_config, 0, ictools.build_ssh_extra_config())

    vmtools.start_machine_local(machines[0], system_image, config_image, interactive=True)

    machines[0].stop()


if __name__ == "__main__":
    main(sys.argv)
