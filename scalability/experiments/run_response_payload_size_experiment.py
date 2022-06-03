#!/usr/bin/env python3
"""
In this experiment, we incrementally increase the size of the response payload and observe the
latency from the perspective of the client.
"""
import codecs
import json
import os
import sys

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common.misc as misc  # noqa
import common.workload_experiment as workload_experiment  # noqa

CANISTER = "response-payload-test-canister.wasm"

FLAGS = gflags.FLAGS
gflags.DEFINE_integer("initial_response_size_kb", 250, "Initial response payload size in kb.")
gflags.DEFINE_integer("response_size_increment_kb", 250, "Increment of response payload size in kb per iteration.")
gflags.DEFINE_integer("max_size_increment_kb", 2 * 1024, "Maximum response payload size to test.")


class ResponsePayloadExperiment(workload_experiment.WorkloadExperiment):
    """Logic for experiment with changing response payload size."""

    def __init__(self):
        """Init with single workload generator."""
        super().__init__(num_workload_gen=1)
        self.install_canister(
            self.target_nodes[0], canister=os.path.join(self.artifacts_path, f"../canisters/{CANISTER}")
        )

    def run_experiment_internal(self, config):
        """Run workload generator with the load specified in config."""
        return self.run_workload_generator(
            self.machines,
            self.target_nodes,
            FLAGS.target_rps,
            outdir=self.iter_outdir,
            payload=codecs.encode(
                json.dumps({"response_size_bytes": config["response_payload_size"]}).encode("utf-8"), "hex"
            ),
            call_method="query",
            method="Query",
            duration=FLAGS.iter_duration,
        )

    def run_iterations(self, datapoints=None):
        """Run heavy memory experiment in defined iterations."""
        self.start_experiment()

        print(f"🚀  running with {datapoints}kb sized response messages")
        evaluated_summaries = {}
        for datapoint in datapoints:
            summary = self.run_experiment(
                # for labels of iteration headings
                {"response_payload_size": datapoint, "load_total": datapoint}
            )
            evaluated_summaries[datapoint] = summary
            print(f"{datapoint} -> {summary.percentiles[95]} -> {summary.t_median}")

        results = []
        for datapoint, summary in evaluated_summaries.items():
            print(f"{datapoint} -> {summary.percentiles[95]} -> {summary.t_median}")
            results.append(summary.t_median[0])

        self.write_summary_file(
            "run_response_payload_size_experiment",
            {
                "rps": results,
            },
            datapoints,
            "response payload size [kb]",
            rtype="update" if self.use_updates else "query",
            state="done",
        )

        exp.end_experiment()
        return None


if __name__ == "__main__":
    misc.parse_command_line_args()

    exp = ResponsePayloadExperiment()
    exp.init()
    exp.init_experiment()

    def KB(x):
        return x * 1024

    curr = FLAGS.initial_response_size_kb
    datapoints = []
    while curr <= FLAGS.max_size_increment_kb:
        datapoints.append(KB(curr))
        curr += FLAGS.response_size_increment_kb

    res = exp.run_iterations(datapoints)
