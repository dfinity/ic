#!/usr/bin/env python3
import glob
import itertools
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from common import farm  # noqa
from common import ictools  # noqa


FLAGS = gflags.FLAGS

gflags.DEFINE_string("ic_os_version", None, "Version of the guest OS to boot")
gflags.MarkFlagAsRequired("ic_os_version")
gflags.DEFINE_string("artifacts_path", "", "Path to the artifacts directory")
gflags.DEFINE_string("image_url", "", "url of ic-os guestos dev disk image. Constructed from ic_os version if not set.")
gflags.DEFINE_string("image_sha256sum", "", "sha256 sum of ic-os guestos dev disk image. Constructed from ic_os version if not set.")


def run(args):
    print("Running ", args)
    t_start = time.time()
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    # Fetch stdout and stderr from the running process immediate to avoid
    # output appearing in an incorrect order.
    for c in iter(lambda: proc.stdout.read(1), b""):
        sys.stdout.buffer.write(c)
    proc.wait()
    print(f"Benchmarked {args} returned with {proc.returncode} after {time.time()-t_start}s")
    assert proc.returncode == 0


def main(argv):
    argv = FLAGS(argv)

    version = farm.Farm.latest_with_disk_image() if FLAGS.ic_os_version == "latest" else FLAGS.ic_os_version
    farm_instance = farm.Farm(FLAGS.artifacts_path, [1, 1], version)
    image_url = farm.image_url_from_git_commit(version) if FLAGS.image_url is None else FLAGS.image_url
    image_sha256sum = farm.sha256_for_image(version) if FLAGS.image_sha256sum is None else FLAGS.image_sha256sum
    try:
        farm_instance.create_farm_group()
        farm_instance.create_vms_from_ic_os_image_via_url(image_url, image_sha256sum)
        farm_instance.prepare_and_register_config_image()

        farm_instance.create_prometheus_vm()
        farm_instance.prepare_and_register_prometheus_config_image()
        farm_instance.start_prometheus_vm()

        farm_instance.start_ic_node_vms()
        if not farm_instance.wait_replica_up():
            print("Warning: Could not verify that IC replica is up, continuing anyway  .. ")

        ic_url = f"http://[{farm_instance.ic_node_ipv6s[0][0]}]:8080"
        # Before attempting to install an NNS, we need to make sure the IC is up.
        ictools.wait_http_up(ic_url)
        ictools.nns_install(farm_instance.ic_config, ic_url)

        # Wait for all replicas to come up
        for m in list(itertools.chain(*farm_instance.ic_node_ipv6s)):
            ictools.wait_http_up("http://[%s]:8080" % m)

        base_arguments = [
            "--nns_url",
            ic_url,
            "--cache_path=/tmp/cache",
            "--no_instrument=True",
            "--no_prometheus=True",
            f"--prometheus_url=http://[{farm_instance.prometheus_ipv6}]:9090",
            f"--testnet={farm_instance.group_name}",
            "--artifacts_path",
            FLAGS.artifacts_path,
        ]

        base_arguments_load_test = base_arguments + [
            "--wg_testnet",
            "none",
            "--workload_generator_machines",
            str(farm_instance.ic_node_ipv6s[1][0]),
            "--targets",
            str(farm_instance.ic_node_ipv6s[0][0]),
        ]

        try:
            # Benchmarks w/o load generation
            # --------------------------------------------------
            # These have to go first, since we turn of a replica for the load generator ones
            scalability_dir = Path(__file__).parents[2]

            print("📂 Xnet experiment")
            run(
                [
                    "python3",
                    os.path.join(scalability_dir, "experiments/run_xnet_experiment.py"),
                    "--iter_duration",
                    "20",
                    "--tests_first_subnet_index",
                    "0",
                    "--max_iterations",
                    "1",
                ]
                + base_arguments
            )

            print("📂 Delegated workload")
            run(
                [
                    sys.executable,  # force subprocess to run on version specified in bazel, not version locally installed. So far this test was the only one that had issues related to conflicting python versions, but could make sense to add this everywhere
                    os.path.join(scalability_dir, "experiments/run_delegation_experiment.py"),
                    "--num_procs",
                    "2",
                    "--iter_duration",
                    "20",
                    "--rps",
                    "5",
                ]
                + base_arguments
            )

            print("📂 Testing for flamegraph generation")
            test_uuid = str(uuid.uuid4())
            run(
                [
                    "python3",
                    os.path.join(scalability_dir, "experiments/run_system_baseline_experiment.py"),
                    "--iter_duration",
                    "10",
                    "--datapoints",
                    "50",
                    "--num_workload_generators",
                    "1",
                    "--top_level_out_dir",
                    "foo",
                    "--second_level_out_dir",
                    test_uuid,
                ]
                + [a for a in base_arguments_load_test if not a.startswith("--no_instrument")]
            )
            result_dir = os.path.join("results", "foo", test_uuid, str(1))
            flamegraph_files = glob.glob(f"{result_dir}/flamegraph_*.svg")
            assert len(flamegraph_files) == 1, f"There should be exactly one flamegraph, got: {flamegraph_files}"
            assert (
                subprocess.run(["grep", "ERROR", flamegraph_files[0]]).returncode != 0
            ), 'Flamegraph output file was generated, but contains the keyword "ERROR"'

            # Benchmarks WITH load generation
            # --------------------------------------------------
            # Turns off replicas, so only load based benchmarks from this point onward.
            # This means that the replicas on the second subnet will be turned off, and
            # therefor also Prometheus (i.e. --no_instrument=False) will be broken.

            print("📂 Response Payload size experiment")
            run(
                [
                    "python3",
                    os.path.join(scalability_dir, "experiments/run_large_payload_experiment.py"),
                    "--iter_duration",
                    "10",
                    "--initial_kb",
                    "250",
                    "--max_kb",
                    "250",
                    "--datapoints",
                    "64",
                ]
                + base_arguments_load_test
            )

            print("📂 System baseline experiment with queries")
            run(
                [
                    "python3",
                    os.path.join(scalability_dir, "experiments/run_system_baseline_experiment.py"),
                    "--iter_duration",
                    "10",
                    "--datapoints",
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
                    os.path.join(scalability_dir, "experiments/run_system_baseline_experiment.py"),
                    "--iter_duration",
                    "10",
                    "--datapoints",
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
                    os.path.join(scalability_dir, "experiments/run_system_baseline_experiment.py"),
                    "--iter_duration",
                    "20",
                    "--datapoints",
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
                    os.path.join(scalability_dir, "experiments/run_system_baseline_experiment.py"),
                    "--iter_duration",
                    "20",
                    "--datapoints",
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
                    os.path.join(scalability_dir, "experiments/max_capacity_large_payload.py"),
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

            print("📂 Large memory experiment with queries")
            run(
                [
                    "python3",
                    os.path.join(scalability_dir, "experiments/run_large_memory_experiment.py"),
                    "--iter_duration",
                    "10",
                    "--datapoints",
                    "5",
                    "--use_updates=True",
                ]
                + base_arguments_load_test
            )

            print("📂 Maximum capacity large memory (query)")
            run(
                [
                    "python3",
                    os.path.join(scalability_dir, "experiments/run_large_memory_experiment.py"),
                    "--iter_duration",
                    "20",
                    "--datapoints",
                    "20",
                ]
                + base_arguments_load_test
            )

            print("📂 Maximum capacity large memory (update)")
            run(
                [
                    "python3",
                    os.path.join(scalability_dir, "experiments/run_large_memory_experiment.py"),
                    "--iter_duration",
                    "20",
                    "--datapoints",
                    "20",
                ]
                + base_arguments_load_test
            )

            print("📂 Mixed workload")
            run(
                [
                    "python3",
                    os.path.join(scalability_dir, "experiments/run_mixed_workload_experiment.py"),
                    "--workload",
                    os.path.join(scalability_dir, "workloads/tiny.toml"),
                    "--datapoints",
                    "20",
                ]
                + base_arguments_load_test
            )

        finally:
            # We save prometheus' data directory such that a user can later
            # manually launch a local prometheus and grafana server on this data
            # for post analysis.
            farm_instance.download_prometheus_data_dir()

    finally:
        farm_instance.delete_farm_group()


if __name__ == "__main__":
    main(sys.argv)
