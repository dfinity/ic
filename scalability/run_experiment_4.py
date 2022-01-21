"""
P0 Experiment 4: Gossip.

Purpose: Stress P2P layer with and without boundary node rate limiting
and having a lot of clients (currently not investigated by the
networking team).  See presentation from networking team.

Topology: 13 node subnet, 1 machine NNS
Deploy one instance of the counter or nop canister
Start the workload generator to generate some load
Incrementally add nodes up to 50 nodes until performance degrades
Measure and determine:
  Requests / second
  Error rate
  Request latency
  P2P metrics
  Workload generator metrics
"""
import sys

import gflags
import workload_experiment

FLAGS = gflags.FLAGS
gflags.DEFINE_bool("use_updates", True, "Issue update calls instead of query calls")
gflags.DEFINE_integer("duration", 60, "Duration to run the workload in seconds")
gflags.DEFINE_integer("load", 50, "Load in requests per second to issue, default is 50.")
gflags.DEFINE_integer("max_nodes", 50, "Add machines until given number of nodes is reached.")
gflags.DEFINE_integer("subnet_to_grow", 1, "Index of the subnet to grow.")


class Experiment4(workload_experiment.WorkloadExperiment):
    """Logic for experiment 4."""

    def __init__(self):
        """Construct experiment 4."""
        super().__init__(num_workload_gen=1)
        self.init()
        self.use_updates = FLAGS.use_updates
        if self.use_updates:
            self.request_type = "call"
        print(f"Update calls: {self.use_updates} {self.request_type}")
        self.init_experiment()

    def init_experiment(self):
        """Install counter canister."""
        super().init_experiment()
        self.install_canister(self.target_nodes[0])

    def run_experiment_internal(self, config):
        """Add a new machine and run a bit of a workload."""
        unassigned_nodes = self.get_unassigned_nodes()
        self.add_node_to_subnet(FLAGS.subnet_to_grow, [unassigned_nodes[0]])

        members = self.get_subnet_members(FLAGS.subnet_to_grow)
        print(f"Members are ${members}")
        loadhosts = [self.get_node_ip_address(n) for n in members]
        print(f"Loadhosts: ${loadhosts}")

        arguments = ["-u"] if self.use_updates else []
        return self.run_workload_generator(
            self.machines,
            loadhosts,
            FLAGS.load,
            outdir=self.iter_outdir,
            arguments=arguments,
            duration=FLAGS.duration,
        )


if __name__ == "__main__":

    FLAGS(sys.argv)
    exp = Experiment4()
    print(exp.get_subnet_members(1))

    exp.start_experiment()
    num_nodes_installed = []

    while len(exp.get_unassigned_nodes()) > 0:
        exp.run_experiment({})

        num_nodes_installed.append(len(exp.get_subnet_members(FLAGS.subnet_to_grow)))
        exp.write_summary_file(
            "experiment_4", {}, num_nodes_installed, "#nodes", rtype="update" if exp.use_updates else "query"
        )

    exp.end_experiment()
