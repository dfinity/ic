#!/usr/bin/env python3
import os
import sys

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import misc  # noqa
import run_large_memory_experiment  # noqa

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("initial_rps", 20, "Starting number for requests per second.")
gflags.DEFINE_integer(
    "max_rps", 1000, "Maximum requests per second to be sent. Experiment will wrap up beyond this number."
)
gflags.DEFINE_integer("increment_rps", 5, "Increment of requests per second per round.")


if __name__ == "__main__":
    misc.parse_command_line_args()
    exp = run_large_memory_experiment.LargeMemoryExperiment()
    datapoints = misc.get_datapoints(FLAGS.target_rps, FLAGS.initial_rps, FLAGS.max_rps, FLAGS.increment_rps, 1.5)
    exp.run_iterations(datapoints)
