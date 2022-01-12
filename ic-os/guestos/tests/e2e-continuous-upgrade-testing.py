#!/usr/bin/env python3
import atexit
import os
import subprocess
import sys
import tempfile

import gflags
import ictools
import vmtools

FLAGS = gflags.FLAGS

gflags.DEFINE_string("upgrade_tar", None, "Path to upgrade tar file")
gflags.MarkFlagAsRequired("upgrade_tar")
gflags.DEFINE_string("script_dir", None, "Path to folder with scripts")
gflags.MarkFlagAsRequired("script_dir")
gflags.DEFINE_string("disk_image", None, "Path to disk image to use for VMs")
gflags.MarkFlagAsRequired("disk_image")
gflags.DEFINE_string("version", None, "Version of the disk image")
gflags.MarkFlagAsRequired("version")


def create_upgrade_image(version):
    upgrade_image = tempfile.mktemp(suffix=".tar.gz")
    atexit.register(lambda: os.remove(upgrade_image))

    subprocess.run(
        [
            "%s/ci-change-upgrade-version.sh" % FLAGS.script_dir,
            "--upgrade-image=%s" % FLAGS.upgrade_tar,
            "--out=%s" % upgrade_image,
            "--version=%s" % version,
        ],
        check=True,
    )

    return upgrade_image


def upgrade(ic_url, origin_ip):

    for iteration in range(75):
        upgrade_image = create_upgrade_image(iteration)

        run = True
        while run:
            r = subprocess.run(
                [
                    "%s/ci-bless-version.sh" % FLAGS.script_dir,
                    "--origin-ip=%s" % origin_ip,
                    "--upgrade-image=%s" % upgrade_image,
                    "--nns-url=%s" % ic_url,
                    "--ic-admin-bin=%s" % FLAGS.ic_admin_bin,
                ],
            )
            run = r.returncode != 0

        run = True
        while run:
            r = subprocess.run(
                [
                    "%s/ci-upgrade.sh" % FLAGS.script_dir,
                    "--origin-ip=%s" % origin_ip,
                    "--upgrade-image=%s" % upgrade_image,
                    "--nns-url=%s" % ic_url,
                    "--ic-admin-bin=%s" % FLAGS.ic_admin_bin,
                ],
            )
            run = r.returncode != 0


def main(argv):
    argv = FLAGS(argv)

    machines = vmtools.pool().request_machines(
        [
            {"name": "node0", "ram": "6G", "disk": "100G", "cores": 1},
            {"name": "node1", "ram": "6G", "disk": "100G", "cores": 1},
            {"name": "node2", "ram": "6G", "disk": "100G", "cores": 1},
            {"name": "node3", "ram": "6G", "disk": "100G", "cores": 1},
            {"name": "node4", "ram": "6G", "disk": "100G", "cores": 1},
        ],
    )

    system_image = vmtools.SystemImage.open_local(FLAGS.disk_image)

    ic_config = ictools.ic_prep(
        subnets=[[machines[i].get_ipv6() for i in range(len(machines))]],
        version=FLAGS.version,
        root_subnet=0,
    )

    machine_config_images = [
        ictools.build_ic_prep_inject_config(machines[n], ic_config, n, ictools.build_ssh_extra_config())
        for n in range(len(machines))
    ]

    vmtools.start_machines(
        [(machine, system_image, config_image) for machine, config_image in zip(machines, machine_config_images)],
        start_ssh_log_streaming=True,
    )

    ic_url = "http://[%s]:8080" % machines[0].get_ipv6()

    ictools.wait_http_up(ic_url)

    ictools.nns_install(ic_config, ic_url)
    upgrade(ic_url, machines[0].get_ipv6())

    for i in range(len(machines)):
        machines[i].stop()


if __name__ == "__main__":
    main(sys.argv)
