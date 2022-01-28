#!/usr/bin/env python3
import subprocess
import sys

import gflags
import ictools
import vmtools

FLAGS = gflags.FLAGS

gflags.DEFINE_string("disk_image", None, "Path to disk image to use for VMs")
gflags.MarkFlagAsRequired("disk_image")
gflags.DEFINE_string("artifacts_path", "", "Path to the artifacts directory")


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

    ic_url = "http://[%s]:8080" % machines[0].get_ipv6()
    ictools.wait_http_up(ic_url)
    ictools.nns_install(ic_config, ic_url)

    base_arguments = [
        "--nns_url",
        ic_url,
        "--no_flamegraphs=True",
        "--no_prometheus=True",
        "--skip_generate_report=True",
        "--testnet",
        "none",
        "--wg_testnet",
        "none",
        "--workload_generator_machines",
        str(machines[1].get_ipv6()),
        "--targets",
        str(machines[0].get_ipv6()),
    ]

    subprocess.run(
        [
            "python3",
            "run_experiment_1.py",
            "--duration",
            "10",
            "--load",
            "50",
            "--num_workload_generators",
            "1",
        ]
        + base_arguments,
        check=True,
    )

    subprocess.run(
        [
            "python3",
            "run_experiment_1.py",
            "--duration",
            "10",
            "--load",
            "50",
            "--use_updates=True",
            "--num_workload_generators",
            "1",
        ]
        + base_arguments,
        check=True,
    )

    subprocess.run(
        [
            "python3",
            "max-capacity-experiment-1-inc-payload.py",
            "--duration",
            "10",
            "--max_block_payload_size",
            "50",
            "--use_updates=True",
            "--num_workload_generators",
            "1",
            "--max_iterations",
            "1",
        ]
        + base_arguments,
        check=True,
    )

    # TODO Fails due to broken workload generator.
    # subprocess.run(
    #     [
    #         "python3",
    #         "run_experiment_2.py",
    #         "--duration",
    #         "10",
    #         "--initial_rps",
    #         "10",
    #     ]
    #     + base_arguments,
    #     check=True,
    # )

    machines[0].stop()
    machines[1].stop()


if __name__ == "__main__":
    main(sys.argv)
