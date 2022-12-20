#!/usr/bin/env python
"""Measure ICP performance when using delegations"""
import dataclasses
import json
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
gflags.DEFINE_string("rps", "30", "Coma seperated list of rps rates to test.")


def parse_counter_return(r: bytes):
    """Counter returns value with least significant byte first."""
    return int.from_bytes(r, "little")


class DelegationExperiment(IcPyStressExperiment):
    def __init__(self):
        super().__init__()
        super().init()
        self.target_canister = self.install_canister()

    def run_experiment_internal(self, config):
        agent = self.get_agent_for_ip(self.get_machine_to_instrument())
        counter_start = parse_counter_return(agent.update_raw(self.target_canister, "read", []))
        machines = self.get_machines_to_target()
        r = self.run_all(config["rps"], machines, self.target_canister)
        counter_end = parse_counter_return(agent.update_raw(self.target_canister, "read", []))
        counter_diff = counter_end - counter_start

        iteration_uuid = str(uuid.uuid4())
        with open(os.path.join(self.iter_outdir, "stresser-results" + iteration_uuid), "w") as f:
            # Remove request IDs (they are not Json serializable) and write to file
            f.write(json.dumps(dataclasses.replace(r, req_ids=[]).__dict__, indent=4))

        if counter_diff != r.num_succ_submit:
            print(
                colored(
                    f"Number of successful calls {r.num_succ_submit} does not match counter value {counter_diff}", "red"
                )
            )
        num_total = r.num_succ_submit + r.num_fail_submit
        failure_rate = r.num_fail_submit / num_total
        calculated_rate = statistics.mean(r.durations)
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
        print(colored(f"Duration: {calculated_rate} - stderr: {statistics.stdev(r.durations)}", "blue"))
        print(
            colored(
                (
                    f"Average total rate: {num_total/calculated_rate} - "
                    f"average succ rate: {r.num_succ_submit/calculated_rate}"
                ),
                "blue",
            )
        )
        plot_outname = os.path.join(self.iter_outdir, f"delegate_requests_start_time-{iteration_uuid}.png")
        plot_request_distribution(r.call_time, plot_outname)
        print("Status codes:")
        for k, v in r.status_codes.items():
            print(k, v)

        return EvaluatedSummaries(
            failure_rate,
            [failure_rate],
            num_total / statistics.median(r.durations),
            num_total / statistics.mean(r.durations),
            num_total / max(r.durations),
            num_total / min(r.durations),
            [],
            num_total,
            r.num_succ_submit,
            r.num_fail_submit,
            [],
        )

    def run_iterations(self, iterations=None):
        self.init_experiment()
        for idx, i in enumerate(iterations):
            self.run_experiment({"rps": i})
            rtype = "update"
            state = "running" if idx + 1 < len(iterations) else "done"
            self.write_summary_file(
                "run_delegation_experiment",
                {
                    "iter_duration": -1,
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
