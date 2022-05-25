import os
import re
import threading

from common import ssh
from termcolor import colored


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
        rps_per_machine: [int],
        canister_ids: [str],
        duration: int,
        f_stdout: str,
        f_stderr: str,
        timeout: int,
        payload: str = None,
        method: str = None,
        call_method: str = None,
        arguments: [str] = [],
    ):
        """Initialize workload."""
        threading.Thread.__init__(self)

        self.load_generators = load_generators
        self.target_machines = target_machines
        self.canister_ids = canister_ids
        self.rps_per_machine = rps_per_machine
        self.duration = duration
        self.payload = payload
        self.method = method
        self.call_method = call_method
        self.arguments = arguments
        self.f_stdout = f_stdout
        self.f_stderr = f_stderr
        self.timeout = timeout

        if not isinstance(self.canister_ids, list):
            raise Exception("canister_ids has to be a list of canister IDs represented as string")
        if len(self.canister_ids) < 1:
            raise Exception("List of canister  IDs is empty")

    def get_commands(self) -> [str]:
        """Build a list of command line arguments to use for workload generation."""
        target_list = ",".join(f"http://[{target}]:8080" for target in self.target_machines)
        cmd = (
            f'./ic-workload-generator "{target_list}" --summary-file wg_summary'
            f" -n {self.duration} -p 9090 --no-status-check"
        )
        cmd += " " + " ".join(self.arguments)

        # Dump worklod generator command in output directory.
        if self.payload is not None:
            cmd += " --payload '{}'".format(self.payload.decode("utf-8"))
        if self.method is not None:
            cmd += " -m {}".format(self.method)
        if self.call_method is not None:
            cmd += ' --call-method "{}"'.format(self.call_method)

        # Each workload generator instance can target only a single canister ID currently.
        # In the case of multiple canisters, select a different canister for each machine.
        num_load_generators = len(self.load_generators)
        canister_ids = [self.canister_ids[i % len(self.canister_ids)] for i in range(num_load_generators)]
        assert num_load_generators == len(self.rps_per_machine)
        commands = [
            "{} --canister-id {} -r {rps}".format(
                cmd,
                canister_id,
                rps=rps,
            )
            for canister_id, rps in zip(canister_ids, self.rps_per_machine)
        ]

        return (commands, self.load_generators)

    def run(self):
        """Start running the given workloads as a thread."""
        commands, machines = self.get_commands()
        ssh.run_all_ssh_in_parallel(machines, commands, self.f_stdout, self.f_stderr, self.timeout)

    def fetch_results(self, destinations, out_dir):
        """Fetch results from workload generators."""
        sources = ["admin@[{}]:wg_summary".format(m) for m in self.load_generators]
        rc = ssh.scp_in_parallel(sources, destinations)
        if not rc == [0 for _ in range(len(destinations))]:
            print(colored("⚠️  Some workload generators failed:", "red"))
            for fname in os.listdir(out_dir):
                if re.match("workload-generator.*stderr.*", fname):
                    with open(os.path.join(out_dir, fname)) as ferr:
                        lines = ferr.read().split("\n")
                        print("\n".join(lines[-10:]))
        return rc
