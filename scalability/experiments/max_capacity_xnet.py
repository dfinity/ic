#!/usr/bin/env python3
"""
Experiment to stress Xnet.

This is using the Xnet test driver to benchmark Xnet performance.
"""
import math
import os
import sys

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import run_xnet_experiment  # noqa


FLAGS = gflags.FLAGS

# Configuration for load
gflags.DEFINE_integer("initial_rps", 500, "Initial total rate at which to send Xnet messages")
gflags.DEFINE_integer("increment_rps", 250, "Increment for total rate in each iteration")
gflags.DEFINE_integer("max_iterations", 25, "Maximum number of iterations")

if __name__ == "__main__":
    exp = run_xnet_experiment.XnetExperiment()

    rps_iterations = []

    max_capacity = None

    for i in range(FLAGS.max_iterations):

        total_rate = FLAGS.initial_rps + i * FLAGS.increment_rps
        subnet_to_subnet_rate = int(math.ceil(total_rate / (exp.num_subnets - 1)))
        canister_to_subnet_rate = int(math.ceil(subnet_to_subnet_rate / FLAGS.num_canisters_per_subnet))
        print(
            f"🚀 Running iteration {i} with total rate of {total_rate} ({subnet_to_subnet_rate} per subnet, {canister_to_subnet_rate} per canister)"
        )

        config = {
            "duration": FLAGS.iter_duration,
            "payload_size": FLAGS.payload_size,
            "num_subnets": exp.num_subnets,
            "total_rate": total_rate,
            "subnet_to_subnet_rate": subnet_to_subnet_rate,
            "canister_to_subnet_rate": canister_to_subnet_rate,
        }

        metrics = exp.run_experiment(config)

        if exp.run_accepted(metrics, config):
            max_capacity = total_rate
            rps_iterations.append(total_rate)

    exp.write_summary_file(
        "run_xnet_experiment",
        {
            "rps": rps_iterations,
            "rps_max": max_capacity,
            "is_update": True,
            "iter_duration": FLAGS.iter_duration,
        },
        [FLAGS.payload_size],
        "payload size [bytes]",
    )
    exp.end_experiment()
