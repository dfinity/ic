"""
P0 Experiment 3: Management of large number of canisters.

Purpose: Measure how latency is affected by the number of canisters.
This would be similar to the kinds of workloads that we would expect for OpenChat v2.

For request type t in { Query, Update }
  For canister c in { Rust nop, Motoko nop }

    Topology: 13 node subnet, 1 machine NNS
    Deploy an increasing number of canisters c
    Run workload generators on 13 machines at 70% max_cap after each increase in canister count
    Measure and determine:
      Requests / second
      Error rate
      Request latency
      Flamegraph
      Statesync metrics (e.g. duration)
      Workload generator metrics

Suggested success criteria:
xxx canisters can be installed in a maximum of yyy seconds
"""
import math
import time

import experiment
import gflags
import prometheus

# Number of canisters to install in each iteration
FLAGS = gflags.FLAGS
gflags.DEFINE_integer("batchsize", 20, "Number of concurrent canisters installs to execute")


class Experiment3(experiment.Experiment):
    """Logic for experiment 3."""

    def __init__(self):
        """Construct experiment 3."""
        super().__init__(num_workload_gen=1)
        self.num_canisters = self.get_num_canisters()

    def get_num_canisters(self):
        """Return the currently installed number of canisters in the subnetwork."""
        return int(
            prometheus.extract_value(
                prometheus.get_num_canisters_installed(self.testnet, [self.target_nodes[0]], int(time.time()))
            )[0][1]
        )

    def get_canister_install_rate(self):
        """Get current rate of canister install calls."""
        return prometheus.extract_value(
            prometheus.get_canister_install_rate(self.testnet, [self.target_nodes[0]], int(time.time()))
        )[0][1]

    def run_experiment_internal(self, config):
        """Run workload generator with the load specified in config."""
        # Install batchsize number of canisters
        iteration_max = int(math.ceil(50000 / FLAGS.batchsize))
        for i in range(iteration_max):

            num_canisters = self.get_num_canisters()
            canister_install_rate = self.get_canister_install_rate()

            print(
                (
                    f"Iteration {i} of {iteration_max} - num canisters {num_canisters} - "
                    f"canister_install_rate = {canister_install_rate}"
                )
            )

            p = []
            print(f"Installing {FLAGS.batchsize} canisters in parallel .. ")
            for _ in range(FLAGS.batchsize):
                p.append(self.install_canister_nonblocking(self.target_nodes[0]))
            for process in p:
                process.wait()

            self.num_canisters += FLAGS.batchsize

            print("🚀  ... total number of canisters installed so far: {}".format(self.num_canisters))


if __name__ == "__main__":
    experiment.parse_command_line_args()

    exp = Experiment3()

    exp.start_experiment()
    exp.run_experiment({})
    exp.write_summary_file("experiment_3", {}, [0], "requests / s")

    exp.end_experiment()
