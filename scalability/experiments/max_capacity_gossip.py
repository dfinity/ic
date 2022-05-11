#!/usr/bin/env python3
import os
import sys

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import misc  # noqa
import run_gossip_experiment  # noqa

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("target_rps", 500, "Targeted requests per second.")
gflags.DEFINE_integer("increment_rps", 20, "Increment of requests per second per round.")
gflags.DEFINE_integer("initial_rps", 100, "Starting number for requests per second.")
gflags.DEFINE_integer(
    "max_rps", 2000, "Maximum requests per second to be sent. Experiment will wrap up beyond this number."
)

# Maximum failure rate and median query duration limit to consider
# for rps to choose as rps_max. If failure rate or latency is higher,
# continue running the benchmark, but do not consider this RPS
# for max capacity
gflags.DEFINE_integer(
    "allowable_latency",
    5000,
    "Maximum update median latency in unit of milliseconds at which to consider the iteration successful.",
)

if __name__ == "__main__":
    misc.parse_command_line_args()
    exp = run_gossip_experiment.GossipExperiment()
    exp.run_iterations()
