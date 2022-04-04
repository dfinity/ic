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

    def run(self):
        """Simulate failures on the given machines."""
        print(f"💥 Killing replicas on ${self.machines}")
        # The order in which services are killed shouldn't matter (any order can happen in reality).
        services = MachineFailure.get_services()
        random.shuffle(services)
        for service in services:
            ssh.run_ssh_in_parallel(self.machines, "sudo systemctl kill --signal SIGKILL {service}")
            ssh.run_ssh_in_parallel(self.machines, f"sudo systemctl stop {service}")
            ssh.run_ssh_in_parallel(self.machines, f"sudo systemctl status {service}")

        time.sleep(FLAGS.sleep_time)
        print(f"🔄 Restarting replicas on ${self.machines}")
        for service in MachineFailure.get_services():
            ssh.run_ssh_in_parallel(self.machines, f"sudo systemctl start {service}")
            ssh.run_ssh_in_parallel(self.machines, f"sudo systemctl status {service}")
