#!/usr/bin/env python3
import os
import subprocess
import sys
import time

import gflags
import ictools
import vmtools

FLAGS = gflags.FLAGS

gflags.DEFINE_string("upgrade_tar", None, "Path to upgrade tar file")
gflags.MarkFlagAsRequired("upgrade_tar")
gflags.DEFINE_string("disk_image", None, "Path to disk image to use for VMs")
gflags.MarkFlagAsRequired("disk_image")
gflags.DEFINE_string("ic_workload_generator_bin", None, "ic-workload-generator binary")
gflags.MarkFlagAsRequired("ic_workload_generator_bin")


def upgrade(ic_url, origin_ip):
    here = os.path.dirname(os.path.abspath(__file__))

    subprocess.run(
        [
            os.path.join(here, "..", "scripts", "ci-bless-version.sh"),
            "--origin-ip=%s" % origin_ip,
            "--upgrade-image=%s" % FLAGS.upgrade_tar,
            "--nns-url=%s" % ic_url,
            "--ic-admin-bin=%s" % FLAGS.ic_admin_bin,
        ],
        check=True,
    )

    subprocess.run(
        [
            os.path.join(here, "..", "scripts", "ci-upgrade.sh"),
            "--origin-ip=%s" % origin_ip,
            "--upgrade-image=%s" % FLAGS.upgrade_tar,
            "--nns-url=%s" % ic_url,
            "--ic-admin-bin=%s" % FLAGS.ic_admin_bin,
        ],
        check=True,
    )

    return ictools.get_upgrade_image_version(FLAGS.upgrade_tar)


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
    ictools.nns_install(ic_config, ic_url)

    # Start workload generator
    workload_process = subprocess.Popen([FLAGS.ic_workload_generator_bin, "-n", "500", "-u", "-r", "10", ic_url])

    # Check version on each machine
    for m in machines:
        version = ictools.get_ic_version("http://[%s]:8080/api/v2/status" % m.get_ipv6())
        print("%-30s %s" % (m.get_ipv6(), version))

    # Give workload generator some time to come up, then trigger the upgrade
    time.sleep(10)
    version = upgrade(ic_url, machines[0].get_ipv6())

    # Check version on each machine
    print("Checking IC versions on all hosts")
    for m in machines:
        ictools.wait_ic_version("http://[%s]:8080/api/v2/status" % m.get_ipv6(), version, 120)

    # Wait a bit, then stop workload generator
    time.sleep(10)
    workload_process.terminate()

    # Run workload generator again: fail if errors
    subprocess.run(
        [FLAGS.ic_workload_generator_bin, "-n", "10", "-u", "-r", "10", ic_url],
        check=True,
    )

    # Run workload generator again: fail if errors
    subprocess.run(
        [FLAGS.ic_workload_generator_bin, "-n", "10", "-u", "-r", "10", ic_url],
        check=True,
    )

    machines[0].stop()
    machines[1].stop()


if __name__ == "__main__":
    main(sys.argv)
