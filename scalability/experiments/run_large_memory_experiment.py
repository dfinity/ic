#!/usr/bin/env python3
"""
P0 Experiment 2: Memory under load.

Purpose: Measure memory performance for a canister that has a high memory demand.

For request type t in { Query, Update }

  Topology: 13 node subnet, 1 machine NNS
  Deploy memory test canister on subnet
  Increase memory footprint of query + update calls over time
  Run workload generators on 13 machines at 50% max_capacity
  Measure and determine:
    Requests / second
    Error rate
    Request latency
    Memory performance
    AMD uProf L2 (page faults and cache misses on various levels)
    AMD uProf memory (memory throughput demand of the system)
    Metrics from Execution (see grafana dashboard)
    Flamegraphs (e.g. SIGSEGV issue was showing up there or time spent in kernel)
    Workload generator metrics

Suggested success criteria (Queries):
Maximum number of queries not be below yyy queries per second with less than 20% failure and a maximum latency of 5000ms

Suggested success criteria (Updates):
Maximum number of updates not be below xxx updates per second with less than 20% failure and a maximum latency of 10000ms
"""
import codecs
import json
import os
import sys
import time
from statistics import mean

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import misc  # noqa
from common import workload_experiment  # noqa

CANISTER = "memory-test-canister.wasm"

FLAGS = gflags.FLAGS
gflags.DEFINE_integer("target_query_load", 160, "Target query load in queries per second to issue.")
gflags.DEFINE_integer("target_update_load", 20, "Target update load in queries per second to issue.")
gflags.DEFINE_integer("payload_size", 5000000, "Payload size to pass to memory test canister")
gflags.DEFINE_integer("iter_duration", 60, "Duration in seconds for which to execute workload in each round.")


class LargeMemoryExperiment(workload_experiment.WorkloadExperiment):
    """Logic for experiment 2."""

    def __init__(self):
        """Construct experiment 2."""
        super().__init__(num_workload_gen=1)
        self.init()
        if self.use_updates:
            self.request_type = "call"
        self.init_experiment()

    def init_experiment(self):
        """Install counter canister."""
        super().init_experiment()
        self.install_canister(
            self.target_nodes[0], canister=os.path.join(self.artifacts_path, f"../canisters/{CANISTER}")
        )

    def run_experiment_internal(self, config):
        """Run workload generator with the load specified in config."""
        duration = config["duration"] if "duration" in config else 300
        load = config["load_total"]
        call_method = config["call_method"]
        t_start = int(time.time())
        r = self.run_workload_generator(
            self.machines,
            self.target_nodes,
            load,
            outdir=self.iter_outdir,
            payload=codecs.encode(json.dumps({"size": config["payload_size"]}).encode("utf-8"), "hex"),
            method="Update" if self.use_updates else "Query",
            call_method=call_method,
            duration=duration,
        )
        self.last_duration = int(time.time()) - t_start

        t_median = max(r.t_median)
        print(f"🚀  ... failure rate for {load} rps was {r.failure_rate} median latency is {t_median}")
        return r

    def run_iterations(self, datapoints=None):
        """Run heavy memory experiment in defined iterations."""
        self.start_experiment()

        failure_rate = 0.0
        t_median = 0.0
        run = True
        rps = []

        rps_max = 0
        rps_max_in = None

        num_succ_per_iteration = []

        iteration = 0

        while run:

            load_total = datapoints[iteration]
            iteration += 1

            rps.append(load_total)
            print(f"🚀 Testing with load: {load_total} and updates={self.use_updates}")

            evaluated_summaries = super().run_experiment(
                {
                    "load_total": load_total,
                    "payload_size": FLAGS.payload_size,
                    "duration": FLAGS.iter_duration,
                    "call_method": "update_copy" if self.use_updates else "query_copy",
                }
            )
            (
                failure_rate,
                t_median_list,
                t_average_list,
                t_max_list,
                t_min_list,
                _,
                total_requests,
                num_success,
                num_failure,
            ) = evaluated_summaries.convert_tuple()

            t_median = max(t_median_list)
            t_average = mean(t_average_list)
            t_max = max(t_max_list)
            t_min = max(t_min_list)
            num_succ_per_iteration.append(num_success)

            print(f"🚀  ... failure rate for {load_total} rps was {failure_rate} median latency is {t_median}")

            if len(datapoints) == 1:
                rps_max = num_success / self.last_duration
                rps_max_in = load_total
                run = False

            else:
                if failure_rate < FLAGS.allowable_failure_rate and t_median < FLAGS.allowable_t_median:
                    if num_success / self.last_duration > rps_max:
                        rps_max = num_success / self.last_duration
                        rps_max_in = load_total

                run = (
                    failure_rate < FLAGS.stop_failure_rate
                    and t_median < FLAGS.stop_t_median
                    and iteration < len(datapoints)
                )

            # Write summary file in each iteration including experiment specific data.
            rtype = "update_copy" if self.use_updates else "query_copy"
            state = "running" if run else "done"
            self.write_summary_file(
                "run_large_memory_experiment",
                {
                    "is_update": FLAGS.use_updates,
                    "rps": rps,
                    "rps_max": rps_max,
                    "rps_max_in": rps_max_in,
                    "num_succ_per_iteration": num_succ_per_iteration,
                    "target_duration": FLAGS.iter_duration,
                    "success_rate": (num_success / total_requests) * 100,
                    "failure_rate": failure_rate * 100,
                    "failure_rate_color": "green" if failure_rate < 0.01 else "red",
                    "t_median": t_median,
                    "t_average": t_average,
                    "t_max": t_max,
                    "t_min": t_min,
                    "target_load": load_total,
                },
                rps,
                "requests / s",
                rtype=rtype,
                state=state,
            )

            print(f"🚀  ... maximum capacity so far is {rps_max}")
            return (failure_rate, t_median, t_average, t_max, t_min, total_requests, num_success, num_failure, rps_max)

        exp.end_experiment()


if __name__ == "__main__":
    misc.parse_command_line_args()
    exp = LargeMemoryExperiment()
    datapoints = [FLAGS.target_update_load]
    exp.run_iterations(datapoints)
