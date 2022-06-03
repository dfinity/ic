import os
import re
import threading
import time
import uuid
from typing import NamedTuple

from common import misc
from common import ssh
from termcolor import colored


class WorkloadDescription(NamedTuple):
    canister_ids: list
    method: str
    call_method: str
    rps: int
    duration: int
    payload: str
    arguments: list
    start_delay: int
    rps_ratio: float


def workload_description_from_dict(values: list, canister_ids: dict):
    """
    Build workload description from toml dict representation.

    Use dictionary canister_ids to lookup canister IDs for given canister names.
    """
    workloads = [
        WorkloadDescription(
            canister_ids=canister_ids.get(value["canister"]),
            method=None,
            call_method=None,
            rps=0,
            duration=int(value.get("duration", 300)),
            payload=None,
            arguments=value.get("arguments", []),
            start_delay=int(value.get("start_delay", 0)),
            rps_ratio=float(value.get("rps_ratio", 1)),
        )
        for value in values["workload"]
    ]
    return workloads


class Workload(threading.Thread):
    """
    Threaded abstraction around workload generator execution.

    Workload generators executed via SSH on remote machines. Workload
    generator output can be copied back using fetch_results.

    The benefit of implementing a threaded abstraction is that
    we can execute multiple workloads in parallel easily.

    """

    def __init__(
        self,
        load_generators: [str],
        target_machines: [str],
        workload: WorkloadDescription,
        f_stdout: str,
        f_stderr: str,
        timeout: int,
    ):
        """Initialize workload."""
        threading.Thread.__init__(self)

        self.load_generators = load_generators
        self.target_machines = target_machines
        self.workload = workload
        self.f_stdout = f_stdout
        self.f_stderr = f_stderr
        self.timeout = timeout

        if not isinstance(self.workload.canister_ids, list):
            raise Exception(
                f"canister_ids has to be a list of canister IDs represented as string: is {self.workload.canister_ids}"
            )
        if len(self.workload.canister_ids) < 1:
            raise Exception("List of canister  IDs is empty")

    def get_commands(self) -> [str]:
        """Build a list of command line arguments to use for workload generation."""
        num_load_generators = len(self.load_generators)
        rps_per_machine = misc.distribute_load_to_n(self.workload.rps, num_load_generators)

        target_list = ",".join(f"http://[{target}]:8080" for target in self.target_machines)
        cmd = f'./ic-workload-generator "{target_list}"' f" -n {self.workload.duration} -p 9090 --no-status-check"
        cmd += " " + " ".join(self.workload.arguments)

        # Dump worklod generator command in output directory.
        if self.workload.payload is not None:
            cmd += " --payload '{}'".format(self.workload.payload.decode("utf-8"))
        if self.workload.method is not None:
            cmd += " -m {}".format(self.workload.method)
        if self.workload.call_method is not None:
            cmd += ' --call-method "{}"'.format(self.workload.call_method)

        # Each workload generator instance can target only a single canister ID currently.
        # In the case of multiple canisters, select a different canister for each machine.
        canister_ids = [
            self.workload.canister_ids[i % len(self.workload.canister_ids)] for i in range(num_load_generators)
        ]
        self.uuids = [uuid.uuid4()] * num_load_generators
        commands = [
            "{} --canister-id {} --summary-file wg_summary_{} -r {rps} ".format(
                cmd,
                canister_id,
                self.uuids[i],
                rps=rps,
            )
            for i, (canister_id, rps) in enumerate(zip(canister_ids, rps_per_machine))
        ]

        return (commands, self.load_generators)

    def run(self):
        """Start running the given workloads as a thread."""
        time.sleep(self.workload.start_delay)
        commands, machines = self.get_commands()
        ssh.run_all_ssh_in_parallel(machines, commands, self.f_stdout, self.f_stderr, self.timeout)

    def fetch_results(self, destinations, out_dir):
        """Fetch results from workload generators."""
        sources = ["admin@[{}]:wg_summary_{}".format(m, self.uuids[i]) for i, m in enumerate(self.load_generators)]
        rc = ssh.scp_in_parallel(sources, destinations)
        if not rc == [0 for _ in range(len(destinations))]:
            print(colored("⚠️  Some workload generators failed:", "red"))
            for fname in os.listdir(out_dir):
                if re.match("workload-generator.*stderr.*", fname):
                    with open(os.path.join(out_dir, fname)) as ferr:
                        lines = ferr.read().split("\n")
                        print("\n".join(lines[-10:]))
        return rc
