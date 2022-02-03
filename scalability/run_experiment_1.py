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
import time

import experiment
import gflags
import workload_experiment
from termcolor import colored

FLAGS = gflags.FLAGS
gflags.DEFINE_integer("duration", 60, "Duration to run the workload in seconds")
gflags.DEFINE_integer("load", 50, "Load in requests per second to issue")
gflags.DEFINE_integer("num_workload_generators", 5, "Number of workload generators to run")


class Experiment1(workload_experiment.WorkloadExperiment):
    """Logic for experiment 1."""

    def __init__(self):
        """Construct experiment 1."""
        super().__init__(
            num_workload_gen=FLAGS.num_workload_generators,
            request_type="call" if FLAGS.use_updates else "query",
        )
        self.init()
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
            print(
                colored("⚠️  Update requests have to be targeted at all subnet nodes when stressing the system.", "red")
            )

        return self.run_workload_generator(
            self.machines,
            self.target_nodes,
            config["load_total"],
            outdir=self.iter_outdir,
            arguments=arguments,
            duration=duration,
        )

    def run_iterations(self, datapoints=None):
        """Exercise the experiment with specified iterations."""
        if datapoints is None:
            datapoints = []

        self.start_experiment()

        run = True
        iteration = 0
        rps_max = 0
        rps_max_in = None
        num_succ_per_iteration = []
        rps = []
        failure_rate = 0.0
        t_median = 0.0
        duration = []
        t_average = 0.0
        t_max = 0.0
        t_min = 0.0
        total_requests = 0
        num_success = 0
        num_failure = 0

        while run:

            load_total = datapoints[iteration]
            iteration += 1

            rps.append(load_total)
            print(f"🚀 Testing with load: {load_total} and updates={self.use_updates}")

            t_start = int(time.time())
            (
                failure_rate,
                t_median,
                t_average,
                t_max,
                t_min,
                _,
                total_requests,
                num_success,
                num_failure,
            ) = super().run_experiment(
                {
                    "load_total": load_total,
                    "duration": FLAGS.iter_duration,
                }
            )
            duration_in_iteration = int(time.time()) - t_start

            num_succ_per_iteration.append(num_success)

            print(f"🚀  ... failure rate for {load_total} rps was {failure_rate} median latency is {t_median}")

            duration.append(duration_in_iteration)

            if len(datapoints) == 1:
                rps_max = num_success / duration_in_iteration
                rps_max_in = load_total
                run = False

            else:
                max_t_median = FLAGS.update_max_t_median if self.use_updates else FLAGS.max_t_median
                if failure_rate < FLAGS.max_failure_rate and t_median < max_t_median:
                    if num_success / duration_in_iteration > rps_max:
                        rps_max = num_success / duration_in_iteration
                        rps_max_in = load_total

                run = (
                    failure_rate < FLAGS.stop_failure_rate
                    and t_median < FLAGS.stop_t_median
                    and iteration < len(datapoints)
                )

            # Write summary file in each iteration including experiment specific data.
            self.write_summary_file(
                "system-baseline-experiment",
                {
                    "total_requests": total_requests,
                    "rps": rps,
                    "rps_max": rps_max,
                    "rps_max_in": rps_max_in,
                    "num_succ_per_iteration": num_succ_per_iteration,
                    "success_rate": "{:.2f}".format((num_success / total_requests) * 100),
                    "failure_rate": "{:.2f}".format(failure_rate * 100),
                    "failure_rate_color": "green" if failure_rate < 0.01 else "red",
                    "t_median": "{:.2f}".format(t_median),
                    "t_average": "{:.2f}".format(t_average),
                    "t_max": "{:.2f}".format(t_max),
                    "t_min": "{:.2f}".format(t_min),
                    "duration": duration,
                },
                rps,
                "requests / s",
                rtype="update" if self.use_updates else "query",
                state="running" if run else "done",
            )

            print(f"🚀  ... measured capacity so far is {rps_max}")

        self.end_experiment()
        return (failure_rate, t_median, t_average, t_max, t_min, total_requests, num_success, num_failure, rps_max)


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
        rtype="update" if FLAGS.use_updates else "query",
    )

    exp.end_experiment()
