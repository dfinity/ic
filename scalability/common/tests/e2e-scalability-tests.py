#!/usr/bin/env python3
import itertools
import os
import subprocess
import sys

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from common import farm  # noqa

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
        "ic-os/guestos/tests",
    )
)
import ictools  # noqa

FLAGS = gflags.FLAGS

gflags.DEFINE_string("ic_os_version", None, "Version of the guest OS to boot")
gflags.MarkFlagAsRequired("ic_os_version")
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

    version = farm.Farm.latest_with_disk_image() if FLAGS.ic_os_version == "latest" else FLAGS.ic_os_version
    farm_instance = farm.Farm(FLAGS.artifacts_path, [1, 1], version)
    try:
        farm_instance.create_farm_group()
        farm_instance.setup_disk_image(farm.image_url_from_git_commit(version), farm.sha256_for_image(version))
        farm_instance.prepare_and_register_config_image()
        farm_instance.start_vm()
        if not farm_instance.wait_replica_up():
            print("Warning: Could not verify that IC replica is up, continuing anyway  .. ")

        ic_url = f"http://[{farm_instance.ipv6[0][0]}]:8080"
        ictools.nns_install(farm_instance.ic_config, ic_url)

        # Wait for all replicas to come up
        for m in list(itertools.chain(*farm_instance.ipv6)):
            ictools.wait_http_up("http://[%s]:8080" % m)

        base_arguments = [
            "--nns_url",
            ic_url,
            "--no_instrument=True",
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
            str(farm_instance.ipv6[1][0]),
            "--targets",
            str(farm_instance.ipv6[0][0]),
        ]

        # Benchmarks w/o load generation
        # --------------------------------------------------
        # These have to go first, since we turn of a replica for the load generator ones

        print("📂 Xnet experiment")
        run(
            [
                "python3",
                "experiments/max_capacity_xnet.py",
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

        print("📂 Response Payload size experiment")
        run(
            [
                "python3",
                "experiments/max_capacity_response_payload_size.py",
                "--iter_duration",
                "10",
                "--initial_kb",
                "250",
                "--max_kb",
                "250",
            ]
            + base_arguments_load_test
        )

        print("📂 System baseline experiment with queries")
        run(
            [
                "python3",
                "experiments/run_system_baseline_experiment.py",
                "--iter_duration",
                "10",
                "--target_rps",
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
                "--target_rps",
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
                "--initial_rps",
                "20",
                "--max_rps",
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
                "--initial_rps",
                "20",
                "--max_rps",
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
                "--iter_duration",
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
                "--target_rps",
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
                "--initial_rps",
                "20",
                "--max_rps",
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
                "--initial_rps",
                "20",
                "--max_rps",
                "20",
            ]
            + base_arguments_load_test
        )

        print("📂 Mixed workload")
        run(
            [
                "python3",
                "experiments/run_mixed_workload_experiment.py",
                "--workload",
                "workloads/tiny.toml",
                "--initial_rps",
                "20",
                "--max_rps",
                "20",
            ]
            + base_arguments_load_test
        )

    finally:
        farm_instance.delete_farm_group()


if __name__ == "__main__":
    main(sys.argv)
