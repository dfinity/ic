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


def run(args):
    print("Running ", args)
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # Fetch stdout and stderr from the running process immediate to avoid
    # output appearing in an incorrect order.
    for c in iter(lambda: proc.stdout.read(1), b""):
        sys.stdout.buffer.write(c)
    proc.wait()
    print(f"Benchmarked {args} returned with {proc.returncode}")
    assert proc.returncode == 0


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

    print("📂 Xnet experiment")
    run(
        [
            "python3",
            "experiments/run_xnet_experiment.py",
            "--iter_duration",
            "20",
            "--tests_first_subnet_index",
            "0",
            "--max_iterations",
            "1",
        ]
        + base_arguments
    )

    # Benchmarks WITH load generation
    # --------------------------------------------------
    # Turns off replicas, so only load based benchmarks from this point onward.

    print("📂 System baseline experiment with queries")
    run(
        [
            "python3",
            "experiments/run_system_baseline_experiment.py",
            "--iter_duration",
            "10",
            "--load",
            "50",
            "--num_workload_generators",
            "1",
        ]
        + base_arguments_load_test
    )

    print("📂 System baseline experiment with updates")
    run(
        [
            "python3",
            "experiments/run_system_baseline_experiment.py",
            "--iter_duration",
            "10",
            "--load",
            "5",
            "--use_updates=True",
            "--num_workload_generators",
            "1",
        ]
        + base_arguments_load_test
    )

    print("📂 Maximum capacity system baseline (query)")
    run(
        [
            "python3",
            "experiments/max_capacity_system_baseline.py",
            "--iter_duration",
            "20",
            "--query_initial_rps",
            "20",
            "--max_query_load",
            "20",
            "--num_workload_generators",
            "1",
        ]
        + base_arguments_load_test
    )

    print("📂 Maximum capacity system baseline (update)")
    run(
        [
            "python3",
            "experiments/max_capacity_system_baseline.py",
            "--iter_duration",
            "20",
            "--update_initial_rps",
            "20",
            "--max_update_load",
            "20",
            "--num_workload_generators",
            "1",
            "--use_updates=True",
        ]
        + base_arguments_load_test
    )

    print("📂 Large payload max capacity with updates")
    run(
        [
            "python3",
            "experiments/max_capacity_large_payload.py",
            "--iter_duration",
            "10",
            "--max_block_payload_size",
            "50",
            "--use_updates=True",
            "--num_workload_generators",
            "1",
            "--max_iterations",
            "1",
        ]
        + base_arguments_load_test
    )

    print("📂 Gossip experiment")
    run(
        [
            "python3",
            "experiments/run_gossip_experiment.py",
            "--duration",
            "10",
        ]
        + base_arguments_load_test
    )

    print("📂 Large memory experiment with queries")
    run(
        [
            "python3",
            "experiments/run_large_memory_experiment.py",
            "--iter_duration",
            "10",
            "--target_update_load",
            "5",
            "--use_updates=True",
        ]
        + base_arguments_load_test
    )

    print("📂 Maximum capacity large memory (query)")
    run(
        [
            "python3",
            "experiments/max_capacity_large_memory.py",
            "--iter_duration",
            "20",
            "--query_initial_rps",
            "20",
            "--max_query_load",
            "20",
        ]
        + base_arguments_load_test
    )

    print("📂 Maximum capacity large memory (update)")
    run(
        [
            "python3",
            "experiments/max_capacity_large_memory.py",
            "--iter_duration",
            "20",
            "--query_initial_rps",
            "20",
            "--max_query_load",
            "20",
        ]
        + base_arguments_load_test
    )

    machines[0].stop()
    machines[1].stop()


if __name__ == "__main__":
    main(sys.argv)
