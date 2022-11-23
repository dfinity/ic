#!/usr/bin/env python3
import os
import sys

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import workload_experiment  # noqa
from common import misc  # noqa

FLAGS = gflags.FLAGS
NUM_ITERATIONS = 4


class tecdsa(workload_experiment.WorkloadExperiment):
    """Threshold ECDSA benchmark."""

    def init_experiment(self):
        super().init_experiment()
        self.install_canister(self.target_nodes[0], "tecdsa")

    def run_experiment_internal(self, config):
        """Run the experiment."""
        return self.run_workload_generator(
            self.machines,  # List of machines that the workload generator should run on
            self.target_nodes,  # List of IC nodes running the canister that should be targeted
            config["load_total"],  # Number of requests per second to execute
            canister_ids=None,  # None = Target all installed canisters
            duration=FLAGS.iter_duration,  # How long to run the workload (in secs)
            payload=b"4449444c016d7b0100200000000000000000000000000000000000000000000000000000000000000000",  # Payload to send to the canister
            method="update",  # Update or query, None = QueryCounter
            call_method="sign",  # Name of the caniter's method to call, works only iff method=Update or method=Query
            arguments=[],  # List of extra-arguments to the workload generator
        )


if __name__ == "__main__":
    misc.parse_command_line_args()
    exp = tecdsa()

    # exp.start_experiment()
    for i in range(NUM_ITERATIONS):
        exp.run_experiment({"load_total": 0.5 + 0.2 * (i + 1)})
    exp.write_summary_file("run_tecdsa", {"iter_duration": FLAGS.iter_duration}, [], "n.a.")

    exp.end_experiment()
