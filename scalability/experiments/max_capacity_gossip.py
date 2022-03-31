#!/usr/bin/env python3
import os
import sys

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import misc  # noqa
import run_gossip_experiment  # noqa

FLAGS = gflags.FLAGS

# Flags for update mode
gflags.DEFINE_integer("target_update_load", 500, "Target update load in queries per second to issue.")
gflags.DEFINE_integer("update_rps_increment", 20, "Increment of requests per second per round for update calls.")
gflags.DEFINE_integer("update_initial_rps", 100, "Start rps and increment in update mode.")
gflags.DEFINE_integer("max_update_load", 2000, "Maximum update load in queries per second to issue.")

# Duration in seconds for which to execute workload in each round.
gflags.DEFINE_integer("iter_duration", 300, "Duration per iteration of the benchmark.")

# Maximum failure rate and median query duration limit to consider
# for rps to choose as rps_max. If failure rate or latency is higher,
# continue running the benchmark, but do not consider this RPS
# for max capacity
gflags.DEFINE_float(
    "allowable_failure_rate", 0.2, "Maximum failure rate at which to consider the iteration successful."
)
gflags.DEFINE_integer(
    "update_allowable_t_median",
    30000,
    "Maximum update median latency in unit of milliseconds at which to consider the iteration successful.",
)

# Maximum failure rate and median query duration limit for when to
# stop the benchmark.
gflags.DEFINE_float("stop_failure_rate", 0.4, "Maximum failure rate before aborting the benchmark.")
gflags.DEFINE_integer(
    "stop_t_median", 60000, "Maximum median latency in unit of milliseconds before aborting the benchmark."
)

if __name__ == "__main__":
    misc.parse_command_line_args()
    exp = run_gossip_experiment.GossipExperiment()
    exp.run_iterations()
