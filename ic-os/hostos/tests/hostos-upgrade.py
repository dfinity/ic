#!/usr/bin/env python3
import sys

import gflags
import ictools
import vmtools

FLAGS = gflags.FLAGS

gflags.DEFINE_string("upgrade_tar", None, "Path to upgrade tar file")
gflags.MarkFlagAsRequired("upgrade_tar")
gflags.DEFINE_string("disk_image", None, "Path to disk image to use for VMs")
gflags.MarkFlagAsRequired("disk_image")


def upgrade(machine):
    ic_url = machine.get_ipv6()

    filename = "/tmp/update-img.tar.gz"

    ictools.send_upgrade_ssh(ic_url, FLAGS.upgrade_tar, filename)
    ictools.apply_upgrade_ssh(ic_url, filename)
    machine.reboot()

    return ictools.get_upgrade_image_version(FLAGS.upgrade_tar)


def main(argv):
    argv = FLAGS(argv)

    machines = vmtools.pool().request_machines(
        [
            {"name": "node0", "ram": "6G", "disk": "101G", "cores": 1},
            {"name": "node1", "ram": "6G", "disk": "101G", "cores": 1},
        ],
    )

    system_image = vmtools.SystemImage.open_local(FLAGS.disk_image)

    ssh = ictools.prep_ssh()

    # NOTE: Instead of config image, copy the files directly onto the partition.
    # This is temporary until we run the install through setupos.
    machine_configs = [
        ictools.build_config_folder(machines[0].get_name(), machines[0].get_ips(6)[0], ssh),
        ictools.build_config_folder(machines[1].get_name(), machines[1].get_ips(6)[0], ssh),
    ]

    vmtools.start_machines(
        [(machine, system_image, config) for machine, config in zip(machines, machine_configs)],
        start_ssh_log_streaming=True,
    )

    ictools.wait_ssh_up(machines[0].get_ipv6())
    ictools.wait_ssh_up(machines[1].get_ipv6())

    # Check version on each machine
    for m in machines:
        version = ictools.get_host_version(m.get_ipv6())
        print("%-30s %s" % (m.get_ipv6(), version))

    upgrade(machines[0])
    version = upgrade(machines[1])

    # Check version on each machine
    print("Checking versions on all hosts")
    for m in machines:
        ictools.wait_host_version(m.get_ipv6(), version, 120)

    machines[0].stop()
    machines[1].stop()


if __name__ == "__main__":
    main(sys.argv)
