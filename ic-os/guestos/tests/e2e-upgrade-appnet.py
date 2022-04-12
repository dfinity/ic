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
gflags.DEFINE_string("request_type", None, "Request type to be used by workload generator")
gflags.MarkFlagAsRequired("request_type")


def upgrade(nns_url, upgrades, origin_ip):
    here = os.path.dirname(os.path.abspath(__file__))

    # Bless version
    subprocess.run(
        [
            os.path.join(here, "..", "scripts", "ci-bless-version.sh"),
            "--upgrade-image=%s" % FLAGS.upgrade_tar,
            "--origin-ip=%s" % origin_ip,
            "--nns-url=%s" % nns_url,
            "--ic-admin-bin=%s" % FLAGS.ic_admin_bin,
        ]
    )

    # Start one process for each upgrade
    processes = []
    for (i, (subnet_url, subnet)) in enumerate(upgrades):
        cmd = [
            os.path.join(here, "..", "scripts", "ci-upgrade.sh"),
            "--origin-ip=%s" % origin_ip,
            "--upgrade-image=%s" % FLAGS.upgrade_tar,
            "--nns-url=%s" % nns_url,
            "--subnet-url=%s" % subnet_url,
            "--subnet=%s" % subnet,
            "--ic-admin-bin=%s" % FLAGS.ic_admin_bin,
        ]
        if i != 0:
            cmd.append("--no-httpd")

        processes.append(subprocess.Popen(cmd))

    # Wait for each process to terminate processes to terminate
    for i, p in enumerate(processes):
        out, errs = p.communicate()
        assert p.returncode == 0, "Upgrade %d failed with RC %d" % (i, p.returncode)


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
        subnets=[[machines[0].get_ipv6()], [machines[1].get_ipv6()]],
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

    nns_url = "http://[%s]:8080" % machines[0].get_ipv6()
    app_url = "http://[%s]:8080" % machines[1].get_ipv6()

    ictools.wait_http_up(nns_url)
    ictools.nns_install(ic_config, nns_url)

    # Start workload generator
    subprocess_args = [FLAGS.ic_workload_generator_bin, "-n", "500", "-r", "10", nns_url]
    if FLAGS.request_type == "update":
        subprocess_args.append("-u")
    nns_workload_process = subprocess.Popen(subprocess_args)
    app_workload_process = subprocess.Popen(subprocess_args)

    # Give workload generator some time to come up, then trigger the upgrade
    time.sleep(10)
    upgrade(
        nns_url,
        [(nns_url, 0), (app_url, 1)],
        machines[0].get_ipv6(),
    )

    # Wait a bit, then stop workload generator
    time.sleep(10)
    app_workload_process.terminate()
    nns_workload_process.terminate()

    subprocess_args = [FLAGS.ic_workload_generator_bin, "-n", "120", "-r", "100", nns_url]
    if FLAGS.request_type == "update":
        subprocess_args.append("-u")

    # Run workload generator again: fail if errors
    subprocess.run(subprocess_args, check=True)
    subprocess.run(subprocess_args, check=True)

    machines[0].stop()
    machines[1].stop()


if __name__ == "__main__":
    main(sys.argv)
