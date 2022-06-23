#!/usr/bin/env python3
"""
In this experiment, we incrementally increase the size of the response payload and observe the
latency from the perspective of the client.
"""
import os
import sys

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import run_large_payload_experiment  # noqa

FLAGS = gflags.FLAGS
gflags.DEFINE_integer("initial_kb", 250, "Initial response payload size in kb.")
gflags.DEFINE_integer("increment_kb", 250, "Increment of response payload size in kb per iteration.")
gflags.DEFINE_integer("max_kb", 2 * 1024, "Maximum response payload size to test.")


if __name__ == "__main__":

    exp = run_large_payload_experiment.ResponsePayloadExperiment()

    def KB(x):
        return x * 1024

    curr = FLAGS.initial_kb
    iterations = []
    while curr <= FLAGS.max_kb:
        iterations.append(KB(curr))
        curr += FLAGS.increment_kb

    res = exp.run_iterations(iterations)
