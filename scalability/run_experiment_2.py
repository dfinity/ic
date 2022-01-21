"""
P0 Experiment 2: Memory under load.

Purpose: Measure memory performance for a canister that has a high memory demand.

For request type t in { Query, Update }

  Topology: 13 node subnet, 1 machine NNS
  Deploy as many memory test canisters on subnet as possible (so that we can execute concurrent updates)
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
import time

import experiment
import gflags
import workload_experiment

FLAGS = gflags.FLAGS
gflags.DEFINE_integer("payload_size", 5000000, "Payload size to pass to memory test canister")
gflags.DEFINE_integer("initial_rps", 20, "Requests per second to issue")
gflags.DEFINE_integer("duration", 60, "Duration of the benchmark")

CANISTER = "memory-test-canister.wasm"


class Experiment2(workload_experiment.WorkloadExperiment):
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
        t_start = int(time.time())
        r = self.run_workload_generator(
            self.machines,
            self.target_nodes,
            load,
            outdir=self.iter_outdir,
            payload=codecs.encode(json.dumps({"size": config["payload_size"]}).encode("utf-8"), "hex"),
            method="Update" if self.use_updates else "Query",
            call_method="update_copy" if self.use_updates else "query_copy",
            duration=duration,
        )
        self.last_duration = int(time.time()) - t_start
        failure_rate, t_median, _, _, _, _, _, _ = r
        print(f"🚀  ... failure rate for {load} rps was {failure_rate} median latency is {t_median}")
        return r


if __name__ == "__main__":
    experiment.parse_command_line_args()

    exp = Experiment2()

    exp.start_experiment()
    exp.run_experiment(
        {
            "load_total": FLAGS.initial_rps,
            "payload_size": FLAGS.payload_size,
            "duration": FLAGS.duration,
        }
    )
    exp.write_summary_file("experiment_2", {"rps": [FLAGS.initial_rps]}, [FLAGS.initial_rps], "requests / s")

    exp.end_experiment()
