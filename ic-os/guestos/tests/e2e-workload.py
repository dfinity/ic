#!/usr/bin/env python3
import subprocess
import sys

import gflags
import ictools
import vmtools

FLAGS = gflags.FLAGS

gflags.DEFINE_string("ic_workload_generator_bin", None, "ic-workload-generator binary")
gflags.MarkFlagAsRequired("ic_workload_generator_bin")
gflags.DEFINE_string("disk_image", None, "Path to disk image to use for VMs")
gflags.MarkFlagAsRequired("disk_image")


def main(argv):
    argv = FLAGS(argv)

    machines = vmtools.pool().request_machines(
        [
            {"name": "node0", "ram": "6G", "disk": "100G", "cores": 1},
            {"name": "node1", "ram": "6G", "disk": "100G", "cores": 1},
        ],
    )

    system_image = vmtools.SystemImage.open_local(FLAGS.disk_image)

    ic_config = ictools.ic_prep(
        subnets=[[machines[0].get_ipv6(), machines[1].get_ipv6()]],
        version=ictools.get_disk_image_version(system_image),
        root_subnet=0,
    )

    machine_config_images = [
        ictools.build_ic_prep_inject_config(machines[n], ic_config, n, ictools.build_ssh_extra_config())
        for n in range(2)
    ]

    vmtools.start_machines(
        [(machine, system_image, config_image) for machine, config_image in zip(machines, machine_config_images)],
        start_ssh_log_streaming=True,
    )

    ic_url = "http://[%s]:8080" % machines[0].get_ipv6()

    ictools.wait_http_up(ic_url)

    subprocess.run([FLAGS.ic_workload_generator_bin, "-n", "10", "-r", "10", ic_url], check=True)

    # Make sure SSH access to the machine works. If it doesn't, we lose log access.
    # Arguments copied from log-streamer.py
    subprocess.run(
        [
            "ssh",
            "-o",
            "ConnectTimeout=1",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "ServerAliveInterval=1",
            "-o",
            "PasswordAuthentication=false",
            "-tt",
            "root@%s" % machines[0].get_ipv6(),
            "true",
        ],
        check=True,
    )

    machines[0].stop()
    machines[1].stop()


if __name__ == "__main__":
    main(sys.argv)
