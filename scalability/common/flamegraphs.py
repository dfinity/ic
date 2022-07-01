import os
import subprocess
import time
from dataclasses import dataclass

from common import metrics
from common import ssh

TARGET_DIR = "/var/lib/ic/data/flamegraph"
# Frequency at which we sample for flamegraph generation.
# Higher values mean more detailed flamegraphs, but longer time to generate them.
FREQUENCY = 250


@dataclass
class PreviousFlamegraphExecution:
    """State of a previous flamegraph execution."""

    iter_outdir: str
    pid: subprocess.Popen
    t_start: float


class Flamegraph(metrics.Metric):
    """Flamegraph abstraction. Can be started and stopped."""

    def init(self):
        """
        Init the metrics.

        Called once at the beginning of the benchmark.
        """
        if not self.do_instrument:
            return
        self.perf_pid = None
        self.install_flamegraph([self.target])
        self.previous_flamegraph = None

    def install_flamegraph(self, machines):
        """
        Install flamegraph binaries if not yet available.

        cargo install flamegraph --git https://github.com/flamegraph-rs/flamegraph --branch main

        This will only work if the machine you install on has IPv4 support (for github), which is not
        true for the IC OS.
        If you build on a non-IC OS machine, be sure to have compatible libc etc.
        """
        if not self.do_instrument:
            return
        r = ssh.run_ssh_in_parallel(machines, "stat flamegraph")
        if r != [0 for _ in machines]:

            # Flamegraph binary not installed: installing and setting up OS.

            # Could also think about doing this:
            # warning: Maximum frequency rate (750 Hz) exceeded, throttling from 997 Hz to 750 Hz.
            # The limit can be raised via /proc/sys/kernel/perf_event_max_sample_rate.
            # The kernel will lower it when perf's interrupts take too long.
            all_correct = [0 for _ in range(len(machines))]

            rcs = ssh.run_ssh_in_parallel(machines, "echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid")
            assert rcs == all_correct
            # ic-os now has a read-only file system. Need to remount rw
            rcs = ssh.run_ssh_in_parallel(machines, "sudo mount -o remount,rw /")
            assert rcs == all_correct
            rcs = ssh.run_ssh_in_parallel(
                machines, "sudo apt update; sudo apt install -y linux-tools-common linux-tools-$(uname -r)"
            )
            assert rcs == all_correct

            # Extract flamegraph binary, if not already done
            if not os.path.exists("common/flamegraph"):
                subprocess.check_output(["gunzip", "-k", "common/flamegraph.gz"])

            destinations = ["admin@[{}]:".format(m) for m in machines]
            sources = ["common/flamegraph" for _ in machines]
            return ssh.scp_in_parallel(sources, destinations)

        else:
            return r

    def start_iteration(self, outdir):
        """Benchmark iteration is started."""
        if not self.do_instrument:
            return
        self.wait_previous_flamegraph()
        self.perf_pid = ssh.run_ssh_with_t(
            self.target,
            (
                f"sudo rm -rf {TARGET_DIR}; "
                f"sudo mkdir {TARGET_DIR}; "
                f"sudo chmod 0777 {TARGET_DIR}; "
                f"cp -f flamegraph {TARGET_DIR}; cd {TARGET_DIR}; "
                f"sudo perf record -F {FREQUENCY} -p $(pidof ic-canister-http-adapter ic-btc-adapter ic-crypto-csp orchestrator replica sandbox_launcher canister_sandbox | sed 's/ /,/g') --call-graph dwarf,16384 -g -o {TARGET_DIR}/perf.data"
            ),
            os.path.join(outdir, "perf-{}.stdout.log".format(self.target)),
            os.path.join(outdir, "perf-{}.stderr.log".format(self.target)),
        )

    def end_iteration(self, exp):
        """Benchmark iteration is started."""
        if not self.do_instrument:
            return
        print(
            (
                "Terminating flamegraph generation, waiting to finish and fetching svg. "
                "Use --no_instrument=True to disable flamegraph generation."
            )
        )
        # It's insufficient to terminate() flamegraph itself.
        # We need to either send SIGINT to the entire process group, or simply terminate perf itself.
        # That will trigger flamegraph to start generating the flamegraph binary, which we then have
        # to wait for.
        ssh.run_ssh(self.target, "sudo kill $(pidof perf)")
        # Wait until perf has terminated
        self.perf_pid.wait()
        # Generate flamegraph out collected events on instrumented machine and download svg.
        # Downloading the entire perf data is impractical, since it can be multiple GB large.
        pid = ssh.run_ssh(
            self.target,
            (
                f"cd {TARGET_DIR}; "
                f'echo "Size of perf data:"; ls -anh {TARGET_DIR}/perf.data; '
                f"time sudo ./flamegraph --no-inline --perfdata {TARGET_DIR}/perf.data -o {TARGET_DIR}/flamegraph.svg; "
            ),
        )
        self.previous_flamegraph = PreviousFlamegraphExecution(exp.iter_outdir, pid, time.time())

    def wait_previous_flamegraph(self):
        if self.previous_flamegraph is None:
            return
        t_func_start = time.time()
        self.previous_flamegraph.pid.wait()
        duration = time.time() - self.previous_flamegraph.t_start
        blocking_duration = time.time() - t_func_start
        print(f"⏳ Took {duration}s to generate flamegraph - {blocking_duration}s of it blocking (rest async)")
        r = ssh.scp_file(
            f"admin@[{self.target}]:{TARGET_DIR}/flamegraph.svg",
            f"{self.previous_flamegraph.iter_outdir}/flamegraph_{self.target}.svg",
        ).wait()
        if r != 0:
            print("❌ Failed to fetch flamegraph, continuing")
        else:
            print("Waiting for flamegraph done .. success")
        self.previous_flamegraph = None

    def end_benchmark(self, exp):
        """Benchmark is finished."""
        if not self.do_instrument:
            return
        self.wait_previous_flamegraph()


if __name__ == "__main__":

    # Useful for more lightweight testing and development.
    # Should normally not be ran directly.

    import threading

    import common.base_experiment as base_experiment

    exp = base_experiment.BaseExperiment()
    exp.start_iteration()

    def thread():
        for i in range(50):
            subprocess.run(["echo", "hello", i])
            time.sleep(10)

    for i in range(10):

        th = threading.Thread(target=thread)
        th.start()

        m = Flamegraph("flamegraph", exp.target, True)
        m.init()
        m.start_iteration("/tmp")
        time.sleep(500)
        m.end_iteration(exp)

        th.join()
