#!/usr/bin/env python3
"""
Gossip Experiment.

Purpose: Stress P2P layer (without boundary node rate limiting)
by increasing the subnet size.

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
import os
import sys
import time
from statistics import mean

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import workload_experiment  # noqa

FLAGS = gflags.FLAGS
gflags.DEFINE_integer("max_nodes", 50, "Add machines until given number of nodes is reached.")
gflags.DEFINE_integer("subnet_to_grow", 1, "Index of the subnet to grow.")


class GossipExperiment(workload_experiment.WorkloadExperiment):
    """Implementation for testing gossip capacity with varied size of subnets."""

    def __init__(self):
        """Initiate the Gossip experiment."""
        super().__init__(num_workload_gen=1)
        self.install_canister(self.target_nodes[0])

    def run_experiment_internal(self, config):
        """Run a bit of a workload with the new subnet size."""
        arguments = config["arguments"] if "arguments" in config else []
        duration = config["duration"] if "duration" in config else 300
        load = config["load_total"] if "load_total" in config else 50

        members = self.get_subnet_members(FLAGS.subnet_to_grow)
        loadhosts = [self.get_node_ip_address(n) for n in members]

        arguments = ["-u"] if self.use_updates else []
        return self.run_workload_generator(
            self.machines,
            loadhosts,
            load,
            outdir=self.iter_outdir,
            arguments=arguments,
            duration=duration,
        )

    def run_iterations(self):
        """Exercise the experiment with specified iterations."""
        # Algorithm:
        # As long as the there are still unassigned nodes:
        #     let current_subnet be current number of nodes in subnet
        #     Add 1/3 current_subnet number of nodes to the subnet
        #     Send the standard volume of workload
        #     Measure success
        #     Repeat

        self.start_experiment()

        run = True
        iteration = 0
        subnet_size_max = 0
        num_succ_per_iteration = []
        subnet_sizes = []
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

            iteration += 1

            subnet_size = len(self.get_subnet_members(FLAGS.subnet_to_grow))
            print(f"Current subnet {FLAGS.subnet_to_grow} size is: {subnet_size}")

            unassigned_nodes = self.get_unassigned_nodes()
            to_be_added = min(max(int(subnet_size / 3), 1), len(unassigned_nodes))
            print(f"➕ Adding {to_be_added} new nodes: {unassigned_nodes[0:to_be_added]}")
            self.add_node_to_subnet(FLAGS.subnet_to_grow, unassigned_nodes[0:to_be_added])

            members = self.get_subnet_members(FLAGS.subnet_to_grow)
            print(f"👉 Members are ${members}")

            print(f"🚀 Testing with number of nodes: {len(members)}.")

            t_start = int(time.time())
            evaluated_summaries = super().run_experiment(
                {
                    "load_total": len(members),
                    "duration": FLAGS.iter_duration,
                }
            )
            (
                failure_rate,
                t_median_list,
                t_average_list,
                t_max_list,
                t_min_list,
                percentiles,
                total_requests,
                num_success,
                num_failure,
            ) = evaluated_summaries.convert_tuple()

            t_median = max(t_median_list)
            t_average = mean(t_average_list)
            t_max = max(t_max_list)
            t_min = min(t_min_list)

            print(
                f"🚀  ... failure rate for subnet_size of {len(members)} was {failure_rate} median latency is {t_median}"
            )

            duration_in_iteration = int(time.time()) - t_start
            duration.append(duration_in_iteration)

            if failure_rate < workload_experiment.ALLOWABLE_FAILURE_RATE and t_median < FLAGS.allowable_latency:
                subnet_size_max = max(subnet_size_max, len(members))

            num_succ_per_iteration.append(num_success)
            subnet_sizes.append(subnet_size_max)

            run = (
                failure_rate < workload_experiment.STOP_FAILURE_RATE
                and t_median < workload_experiment.STOP_T_MEDIAN
                and len(self.get_unassigned_nodes()) > 0
                and len(members) <= FLAGS.max_nodes
            )

            # Write summary file in each iteration including experiment specific data.
            self.write_summary_file(
                "run_gossip_experiment",
                {
                    "total_requests": total_requests,
                    "subnet_sizes": subnet_sizes,
                    "subnet_size_max": subnet_size_max,
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
                subnet_sizes,
                "number of machines",
                rtype="update" if self.use_updates else "query",
                state="running" if run else "done",
            )

            print(f"🚀  ... measured capacity so far is {subnet_size_max}")

        self.end_experiment()
        return (
            failure_rate,
            t_median,
            t_average,
            t_max,
            t_min,
            total_requests,
            num_success,
            num_failure,
            subnet_size_max,
        )


if __name__ == "__main__":

    FLAGS(sys.argv)

    exp = GossipExperiment()
    print(exp.get_subnet_members(1))

    exp.start_experiment()
    num_nodes_installed = []

    while len(exp.get_unassigned_nodes()) > 0:
        exp.run_experiment({})

        num_nodes_installed.append(len(exp.get_subnet_members(FLAGS.subnet_to_grow)))
        exp.write_summary_file(
            "run_gossip_experiment", {}, num_nodes_installed, "#nodes", rtype="update" if exp.use_updates else "query"
        )

    exp.end_experiment()
