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

FLAGS = gflags.FLAGS
CANISTER = "response-payload-test-canister.wasm"


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
            payload=codecs.encode(
                json.dumps({"response_size_bytes": config["response_payload_size"]}).encode("utf-8"), "hex"
            ),
            call_method="query",
            method="Query",
            duration=config["iter_duration"],
        )

    def run_iterations(self, iterations=None):
        """Run heavy memory experiment in defined iterations."""
        print(f"🚀  running with {iterations}kb sized response messages")
        results = []
        rps_max = 0
        iter_duration = FLAGS.iter_duration
        for idx, iteration in enumerate(iterations):
            summary = self.run_experiment(
                # for labels of iteration headings
                {"response_payload_size": iteration, "load_total": iteration, "iter_duration": iter_duration}
            )
            if summary.total_number <= 0:
                print(f"No workload generator results in iteration {idx} with payload size {iteration}, aborting")
                break
            print(f"{iteration} -> {summary.percentiles[95]} -> {summary.t_median[0]}")
            results.append(summary.t_median[0])

            run = misc.evaluate_stop_latency_failure_iter(
                summary.t_median[0],
                workload_experiment.STOP_T_MEDIAN,
                summary.failure_rate,
                workload_experiment.STOP_FAILURE_RATE,
                idx,
                len(iterations),
            )

            avg_succ_rate = summary.get_avg_success_rate(FLAGS.iter_duration)
            rps_max = (
                avg_succ_rate
                if (
                    summary.failure_rate < workload_experiment.ALLOWABLE_FAILURE_RATE
                    and summary.t_median[0] < workload_experiment.ALLOWABLE_LATENCY
                    and avg_succ_rate > rps_max
                )
                else rps_max
            )

            self.write_summary_file(
                "run_large_payload_experiment",
                {
                    "rps": results,
                    "rps_max": rps_max,
                    "target_load": iteration,
                    "t_median": summary.t_median[0],
                    "failure_rate": summary.failure_rate,
                    "is_update": True,
                    "iter_duration": iter_duration,
                },
                iterations,
                "response payload size [bytes]",
                rtype="update" if self.use_updates else "query",
                state="running" if run else "done",
            )

            if not run:
                break

        self.end_experiment()
        return None


if __name__ == "__main__":

    exp = ResponsePayloadExperiment()
    res = exp.run_iterations([2 * 1024])
