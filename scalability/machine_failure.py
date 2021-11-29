import threading
import time

import gflags
import ssh

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

    def run(self):
        """Simulate failures on the given machines."""
        print(f"💥 Killing replicas on ${self.machines}")
        ssh.run_ssh_in_parallel(self.machines, "sudo systemctl kill --signal SIGKILL ic-replica")
        ssh.run_ssh_in_parallel(self.machines, "sudo systemctl stop ic-replica")
        ssh.run_ssh_in_parallel(self.machines, "sudo systemctl status ic-replica")
        time.sleep(FLAGS.sleep_time)
        print(f"🔄 Restarting replicas on ${self.machines}")
        ssh.run_ssh_in_parallel(self.machines, "sudo systemctl start ic-replica")
        ssh.run_ssh_in_parallel(self.machines, "sudo systemctl status ic-replica")
