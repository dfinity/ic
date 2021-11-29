"""
P0 Experiment 1: System baseline overhead under load.

Purpose: Measure system overhead using a canister that does
essentially nothing for typical application subnetworks. Do so for a
canister in Rust and Motoko.

For request type t in { Query, Update }
  For canister c in { Rust nop, Motoko nop }

    Topology A: 13 node subnet, 1 machine NNS
    Topology B: 34 machine NNS, 1 machine subnet
    Deploy one instance of canister c
    Run workload generators on 13 machines, increasing requests of request type t until > ~100% HTTP errors on client side
      Measure and determine (over time, probably grouped by experiment iteration):
      Requests / second
      Error rate
      Request latency
      Flamegraph (suggest one per experiment iteration, so we can also compare them)
      Maximum capacity max_cap (maximum number of successful requests per second)
      Statesync metrics (e.g. duration)
      Workload generator metrics

Suggested success criteria (Queries):
Maximum number of queries not be below yyy queries per second with less than 20% failure and a maximum latency of 5000ms

Suggested success criteria (Updates):
Maximum number of queries not be below xxx queries per second with less than 20% failure and a maximum latency of 10000ms
"""
import experiment
import gflags

FLAGS = gflags.FLAGS
gflags.DEFINE_bool("use_updates", False, "Issue update calls instead of query calls")
gflags.DEFINE_integer("duration", 60, "Duration to run the workload in seconds")
gflags.DEFINE_integer("load", 50, "Load in requests per second to issue")
gflags.DEFINE_integer("num_workload_generators", 5, "Number of workload generators to run")


class Experiment1(experiment.Experiment):
    """Logic for experiment 1."""

    def __init__(self):
        """Construct experiment 1."""
        super().__init__(
            num_workload_gen=FLAGS.num_workload_generators, request_type="call" if FLAGS.use_updates else "query"
        )
        self.use_updates = FLAGS.use_updates
        print(f"Update calls: {self.use_updates}")
        self.init_experiment()

    def init_experiment(self):
        """Install counter canister."""
        super().init_experiment()
        self.install_canister(self.target_nodes[0])

    def run_experiment_internal(self, config):
        """Run workload generator with the load specified in config."""
        arguments = config["arguments"] if "arguments" in config else []
        if self.use_updates:
            arguments.append("-u")
        duration = config["duration"] if "duration" in config else 300

        if self.use_updates and len(self.target_nodes) < 2:
            raise Exception("Update requests have to be targeted at all subnet nodes when stressing the system.")

        return self.run_workload_generator(
            self.machines,
            self.target_nodes,
            config["load_total"],
            outdir=self.iter_outdir,
            arguments=arguments,
            duration=duration,
        )


if __name__ == "__main__":
    experiment.parse_command_line_args()

    exp = Experiment1()

    exp.start_experiment()
    exp.run_experiment({"load_total": FLAGS.load, "duration": FLAGS.duration})
    exp.write_summary_file(
        "experiment_1",
        {"rps": FLAGS.load},
        [FLAGS.load],
        "requests / s",
        rtype="update" if exp.use_updates else "query",
    )

    exp.end_experiment()
