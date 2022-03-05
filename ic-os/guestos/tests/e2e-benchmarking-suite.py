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
        subnets=[[m.get_ipv6()] for m in machines],
        version=ictools.get_disk_image_version(system_image),
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
    for m in machines:
        ictools.wait_http_up("http://[%s]:8080" % m.get_ipv6())

    base_arguments = [
        "--nns_url",
        ic_url,
        "--no_flamegraphs=True",
        "--no_prometheus=True",
        "--testnet",
        "none",
        "--artifacts_path",
        FLAGS.artifacts_path,
    ]

    base_arguments_load_test = base_arguments + [
        "--wg_testnet",
        "none",
        "--workload_generator_machines",
        str(machines[1].get_ipv6()),
        "--targets",
        str(machines[0].get_ipv6()),
    ]

    # Benchmarks w/o load generation
    # --------------------------------------------------
    # These have to go first, since we turn of a replica for the load generator ones

    subprocess.run(
        [
            "python3",
            "run_xnet_experiment.py",
            "--runtime",
            "20",
        ]
        + base_arguments,
        capture_output=True,
        text=True,
    )

    # Benchmarks WITH load generation
    # --------------------------------------------------
    # Turns off replicas, so only load based benchmarks from this point onward.

    subprocess.run(
        [
            "python3",
            "run_system_baseline_experiment.py",
            "--duration",
            "10",
            "--load",
            "50",
            "--median_latency_threshold=100",
            "--num_workload_generators",
            "1",
        ]
        + base_arguments_load_test,
        check=True,
    )

    subprocess.run(
        [
            "python3",
            "run_system_baseline_experiment.py",
            "--duration",
            "10",
            "--load",
            "5",
            "--use_updates=True",
            "--median_latency_threshold=5000",
            "--num_workload_generators",
            "1",
        ]
        + base_arguments_load_test,
        check=True,
    )

    subprocess.run(
        [
            "python3",
            "max_capacity_large_payload.py",
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
        + base_arguments_load_test,
        check=True,
    )

    subprocess.run(
        [
            "python3",
            "run_gossip_experiment.py",
            "--duration",
            "10",
            "--skip_generate_report=True",
        ]
        + base_arguments_load_test,
        check=True,
    )

    subprocess.run(
        [
            "python3",
            "run_large_memory_experiment.py",
            "--duration",
            "10",
            "--initial_rps",
            "10",
        ]
        + base_arguments_load_test,
        check=True,
    )

    machines[0].stop()
    machines[1].stop()


if __name__ == "__main__":
    main(sys.argv)
