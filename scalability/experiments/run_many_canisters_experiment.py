#!/usr/bin/env python3
"""
P0 Experiment 3: Management of large number of canisters.

Purpose: Measure how latency is affected by the number of canisters.
This would be similar to the kinds of workloads that we would expect for OpenChat v2.

For request type t in { Query, Update }
  For canister c in { Rust nop, Motoko nop }

    Topology: 13 node subnet, 1 machine NNS
    Deploy an increasing number of canisters c
    Run workload generators on 13 machines at 70% max_cap after each increase in canister count
    Measure and determine:
      Requests / second
      Error rate
      Request latency
      Flamegraph
      Statesync metrics (e.g. duration)
      Workload generator metrics

Suggested success criteria:
xxx canisters can be installed in a maximum of yyy seconds
"""
import logging
import math
import os
import subprocess
import sys
import time
from multiprocessing import Pool

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common.base_experiment as base_experiment  # noqa
import common.misc as misc  # noqa
import common.prometheus as prometheus  # noqa

# Number of canisters to install in each iteration
FLAGS = gflags.FLAGS
gflags.DEFINE_integer("batchsize", 20, "Number of concurrent canisters installs to execute")
gflags.DEFINE_integer("num_canisters", 50000, "Maximum number of canisters to install")


def install_single(payload):
    wl_path, target = payload
    try:
        subprocess.check_output([wl_path, f"http://[{target}]:8080", "-n", "1", "-r", "0"])
    except Exception:
        logging.error(logging.traceback.format_exc())


class ManyCanistersExperiment(base_experiment.BaseExperiment):
    """Logic for experiment 3."""

    def __init__(self):
        """Construct experiment 3."""
        super().__init__()
        self.num_canisters = self.get_num_canisters()

    def get_num_canisters(self):
        """Return the currently installed number of canisters in the subnetwork."""
        try:
            return int(
                prometheus.extract_value(
                    prometheus.get_num_canisters_installed(
                        self.testnet, [self.get_machine_to_instrument()], int(time.time())
                    )
                )[0][1]
            )
        except Exception:
            logging.error(logging.traceback.format_exc())
        return 0

    def get_canister_install_rate(self):
        """Get current rate of canister install calls."""
        try:
            return prometheus.extract_value(
                prometheus.get_canister_install_rate(self.testnet, [self.get_machine_to_instrument()], int(time.time()))
            )[0][1]
        except Exception:
            logging.error(logging.traceback.format_exc())

    def run_experiment_internal(self, config):
        """Run workload generator with the load specified in config."""
        # Install batchsize number of canisters
        iteration_max = int(math.ceil(FLAGS.num_canisters / FLAGS.batchsize))
        for i in range(iteration_max):

            num_canisters = self.get_num_canisters()
            if i % 10 == 0:
                canister_install_rate = self.get_canister_install_rate()

                print(
                    (
                        f"Iteration {i} of {iteration_max} - num canisters {num_canisters} - "
                        f"canister_install_rate = {canister_install_rate}"
                    )
                )

            wl_path = self.workload_generator_path
            target = self.get_machine_to_instrument()

            with Pool(FLAGS.batchsize) as p:
                print(p.map(install_single, [(wl_path, target)] * FLAGS.batchsize))

            self.num_canisters += FLAGS.batchsize

            print("🚀  ... total number of canisters installed so far: {}".format(self.num_canisters))


if __name__ == "__main__":
    misc.parse_command_line_args()

    exp = ManyCanistersExperiment()
    exp.init()

    exp.run_experiment({})
    exp.write_summary_file("run_many_canisters_experiment", {"iter_duration": -1}, [0], "requests / s")

    exp.end_experiment()
