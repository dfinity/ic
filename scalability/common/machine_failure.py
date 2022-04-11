import random
import threading
import time

import gflags
from common import ssh

FLAGS = gflags.FLAGS
gflags.DEFINE_integer("num_failing_machines", 1, "Number of failing machines.")
gflags.DEFINE_integer("sleep_time", 60, "Time to sleep before restarting in seconds.")


class MachineFailure(threading.Thread):
    """Class provides the ability to simulate machine failures."""

    def __init__(self, experiment):
        """Initialize failure scenario."""
        threading.Thread.__init__(self)
        # Tak num_failing_machines machines from the end of the list of target machines.
        self.machines = experiment.target_nodes[-FLAGS.num_failing_machines :]

    def get_services():
        # Doesn't seem like the order of those things matters
        return ["ic-replica", "ic-btc-adapter", "ic-canister-http-adapter", "ic-crypto-csp"]

    def kill_nodes(machines: [str]):
        # The order in which services are killed shouldn't matter (any order can happen in reality).
        services = MachineFailure.get_services()
        random.shuffle(services)
        for service in services:
            print(f"💥 Killing replicas on ${machines}")
            ssh.run_ssh_in_parallel(machines, "sudo systemctl kill --signal SIGKILL ic-replica")
            ssh.run_ssh_in_parallel(machines, "sudo systemctl stop ic-replica")
            ssh.run_ssh_in_parallel(machines, "sudo systemctl status ic-replica")

    def start_nodes(machines: [str]):
        print(f"🔄 Restarting replicas on ${machines}")
        for service in MachineFailure.get_services():
            ssh.run_ssh_in_parallel(machines, "sudo systemctl start ic-replica")
            ssh.run_ssh_in_parallel(machines, "sudo systemctl status ic-replica")

    def run(self):
        """Simulate failures on the given machines."""
        MachineFailure.kill_nodes(self.machines)
        time.sleep(FLAGS.sleep_time)
        MachineFailure.start_nodes(self.machines)
