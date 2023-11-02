#!/usr/bin/env python
"""Measure ICP performance when using delegations"""
import os
import statistics
import sys
import uuid

import gflags
from termcolor import colored

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common.misc as misc  # noqa
from common.icpy_stress_experiment import IcPyStressExperiment, StressConfiguration, plot_request_distribution  # noqa
from common.delegation import get_delegation  # noqa
from common.report import EvaluatedSummaries  # noqa


FLAGS = gflags.FLAGS
gflags.DEFINE_string("rps", "30", "Comma separated list of rps rates to test.")


def parse_counter_return(r: bytes):
    """Counter returns value with least significant byte first."""
    return int.from_bytes(r, "little")


class DelegationExperiment(IcPyStressExperiment):
    def __init__(self):
        super().__init__()
        super().init()
        self.target_canister = self.install_canister()

    def run_experiment_internal(self, config):
        # Get a single agent for sanity checks.
        # This agent is not used for actual benchmarking.
        agent = self.get_agents_for_ip(self.get_machine_to_instrument())[0]
        counter_start = parse_counter_return(agent.update_raw(self.target_canister, "read", []))
        machines = self.get_machines_to_target()
        r = self.run_all(config["rps"], FLAGS.iter_duration, machines, self.target_canister)
        counter_end = parse_counter_return(agent.update_raw(self.target_canister, "read", []))
        counter_diff = counter_end - counter_start

        if counter_diff > r.num_succ_executed:
            print(
                colored(
                    f"Counter value difference {counter_diff} is larger than the number of successful calls {r.num_succ_executed}",
                    "red",
                ),
            )
        if counter_diff < r.num_succ_executed:
            print(
                colored(
                    f"Counter value difference {counter_diff} is smaller than the number of successful calls {r.num_succ_executed}. ",
                    "yellow",
                ),
                "This is not unexpected, since a submitted request might not be executed.",
            )
        num_total = r.num_succ_submit + r.num_fail_submit
        failure_rate = r.num_fail_submit / num_total
        print(
            colored(
                (
                    f"Submit succ: {r.num_succ_submit} - "
                    f"submit fail: {r.num_fail_submit} - "
                    f"submit failure rate: {failure_rate}"
                ),
                "blue",
            ),
            " (successful submit does not mean successful execution)",
        )
        failure_rate = r.num_fail_executed / num_total
        print(
            colored(
                (
                    f"Executed succ: {r.num_succ_executed} - "
                    f"Executed fail: {r.num_fail_executed} - "
                    f"Executed failure rate: {failure_rate}"
                ),
                "yellow",
            ),
            " (successful execution means the ingress message has been successfully executed by the canister)",
        )

        iteration_uuid = uuid.uuid4()
        plot_outname = os.path.join(self.iter_outdir, f"delegate_requests_start_time-{iteration_uuid}.png")
        plot_request_distribution(r.call_time, r.durations, plot_outname, config["rps"])
        plot_request_distribution(r.call_time, r.durations, "/tmp/plot.png", config["rps"])
        print(colored("Status codes:", "blue"))

        return EvaluatedSummaries(
            failure_rate,
            [failure_rate],
            statistics.median(r.durations) / num_total,
            statistics.mean(r.durations) / num_total,
            max(r.durations) / num_total,
            min(r.durations) / num_total,
            [],
            num_total,
            r.num_succ_executed,
            r.num_fail_executed,
            [],
        )

    def run_iterations(self, iterations=None):
        results = {}
        self.init_experiment()
        for idx, i in enumerate(iterations):
            results[i] = self.run_experiment({"rps": i})
            rtype = "update"
            state = "running" if idx + 1 < len(iterations) else "done"
            self.write_summary_file(
                "run_delegation_experiment",
                {
                    "iter_duration": FLAGS.iter_duration,
                    "evaluated_summaries": {k: r.to_dict() for k, r in results.items()},
                },
                iterations,
                "requests / s",
                rtype=rtype,
                state=state,
            )
        self.end_experiment()


if __name__ == "__main__":
    misc.parse_command_line_args()
    exp = DelegationExperiment()
    exp.run_iterations([int(rps) for rps in FLAGS.rps.split(",")])
