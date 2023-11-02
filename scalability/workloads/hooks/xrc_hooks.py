import subprocess

import common.misc as misc
from ic.agent import Agent
from ic.candid import Types, encode
from workloads.hooks.workload_hooks import WorkloadHooks


class XrcHooks(WorkloadHooks):
    @staticmethod
    def __enable_http_outcalls_in_subnet(ic_admin_path: str, nns_url: str):
        print("Enabling HTTP requests in subnetwork.")
        return subprocess.check_output(
            [
                ic_admin_path,
                "--nns-url",
                nns_url,
                "propose-to-update-subnet",
                "--features",
                "http_requests",
                "--subnet",
                "1",
                "--test-neuron-proposer",
                "--summary",
                "Updating a subnet",
            ]
        )

    @staticmethod
    def __print_result(failures: dict, succ_exchange_rates: dict):
        """Helper function for printing success rates."""
        print("Raw success results: ", succ_exchange_rates)
        sum_failures = 0
        for f in failures[0]["value"]:
            label, num = tuple(f)
            sum_failures += int(num)
            print(f"{label}: {num}")

        num_succ = len(succ_exchange_rates[0]["value"])
        print(f"Number of successful requests: {num_succ}. ")

        f_rate = sum_failures / (sum_failures + num_succ)
        print(f"Failure rate: {f_rate})")

    def iteration_hook(self, experiment, iteration_idx):
        """A hook that is called for each iteration of the benchmark."""
        XrcHooks.__enable_http_outcalls_in_subnet(
            experiment._get_ic_admin_path(),
            experiment._get_nns_url(),
        )

        stresser_canisters = [cids for cname, cids in experiment.canister_ids.items() if cname.startswith("xrc_demo")]
        stresser_canisters = [cid for cids in stresser_canisters for cid in cids]
        agent = misc.get_agent(experiment.get_machine_to_instrument(), anonymous=False)

        if iteration_idx > 0:
            for cid in stresser_canisters:
                XrcHooks.__print_result(
                    Agent.query_raw(agent, cid, "get_failures", encode([])),
                    Agent.query_raw(agent, cid, "fetch_results", encode([])),
                )

        xrc_canister_id = experiment.canister_ids.get("xrc")[0]
        set_xrc_canister_id_args = [{"type": Types.Text, "value": xrc_canister_id}]
        for cid in stresser_canisters:
            Agent.update_raw(agent, cid, "set_xrc_canister_id", encode(set_xrc_canister_id_args))
            Agent.update_raw(agent, cid, "reset", encode([]))
