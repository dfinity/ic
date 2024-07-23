import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from termcolor import colored

sys.path.insert(1, ".")
from common import metrics  # noqa
from common import ssh  # noqa

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
        # Try to detect if the perf installation on the target machine is broken. If so, disable flamegraph generation.
        if ssh.run_ssh_in_parallel(machines, "perf --version") != [0 for _ in machines]:
            print(
                colored(
                    (
                        "❌ Perf isn't working correctly, disabling flamegraphs for this run. "
                        "This is most likely due to a mismatch of kernel version for the perf install. "
                        "The node-team might be able to help with this."
                    ),
                    "red",
                )
            )
            self.do_instrument = False
            return
        r = ssh.run_ssh_in_parallel(machines, "stat flamegraph")
        if r != [0 for _ in machines]:

            # Flamegraph binary not installed: installing and configuring
            rcs = ssh.run_ssh_in_parallel(machines, "echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid")
            assert rcs == [0 for _ in machines]

            # Extract flamegraph binary, if not already done
            scalability_dir = Path(__file__).parents[1]
            # gunzip does not work correctly within bazel so needs to be forced
            if not os.path.exists(str(scalability_dir) + "/common/flamegraph"):
                subprocess.check_output(["gunzip", "-k", "--force", str(scalability_dir) + "/common/flamegraph.gz"])

            destinations = ["admin@[{}]:".format(m) for m in machines]
            sources = [str(scalability_dir) + "/common/flamegraph" for _ in machines]
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
                f"sudo perf record -F {FREQUENCY} -p $(pidof ic-https-outcalls-adapter ic-btc-adapter ic-crypto-csp orchestrator replica sandbox_launcher canister_sandbox | sed 's/ /,/g') --call-graph dwarf,16384 -g -o {TARGET_DIR}/perf.data"
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
                f'echo "Size of perf data:"; ls -anh {TARGET_DIR}/perf.data; chmod u+x ./flamegraph; stat ./flamegraph; '
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
    class Bla:
        def __init__(self):
            self.iter_outdir = "/tmp"

    TARGET = "2602:fb2b:110:10:506a:82ff:fe97:57b4"
    m = Flamegraph("flamegraph", TARGET, True)
    m.init()
    m.start_iteration("/tmp")
    time.sleep(500)
    exp = Bla()
    m.end_iteration(exp)
