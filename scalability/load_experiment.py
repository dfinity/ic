import json
import os
import re
import subprocess
from typing import List

import experiment
import gflags
import report
import ssh
from termcolor import colored

NUM_WORKLOAD_GEN = 2  # Number of machines to run the workload generator on

FLAGS = gflags.FLAGS
gflags.DEFINE_string(
    "wg_testnet", None, "Testnet to deploy workload generators too. Can be the same as testnet, but use with care!"
)
gflags.MarkFlagAsRequired("wg_testnet")
gflags.DEFINE_integer("subnet", 1, "Subnet from which to choose the target machine")
gflags.DEFINE_integer("wg_subnet", 0, "Subnet in which to run the workload generator")
gflags.DEFINE_integer("wg_connections_per_host", 1, "Number of connections to use per workload generator")
gflags.DEFINE_string("target_subnet_id", "", "Subnet ID that is running the canister specified by canister_id")
gflags.DEFINE_boolean("target_all", False, "Target all nodes, even when running query calls")
gflags.DEFINE_string("targets", "", "Set load target IP adresses from this coma-separated list directly")
gflags.DEFINE_string(
    "workload_generator_machines", "", "Set workload generator IP adresses from this coma-separated list directly"
)
gflags.DEFINE_integer(
    "query_target_node_idx",
    0,
    "The node idx to use within the subnetwork to target for query calls. Only relevant when running against mainnet",
)


class LoadExperiment(experiment.Experiment):
    """Wrapper class around experiments that generates query/update load."""

    def __init__(self, num_workload_gen=NUM_WORKLOAD_GEN, request_type="query"):
        """Init."""
        super().__init__(request_type)

        self.wg_testnet = FLAGS.wg_testnet

        print(
            (
                f"➡️  Executing experiment against {self.testnet} subnet {FLAGS.subnet} "
                f" with workload generators on {self.wg_testnet} subnet {FLAGS.wg_subnet}"
            )
        )

        self.target_nodes = self.get_mainnet_targets() if self.testnet == "mercury" else self.get_targets()

        workload_generator_machines = (
            FLAGS.workload_generator_machines.split(",")
            if len(FLAGS.workload_generator_machines) > 0
            else self.get_hostnames(self.wg_testnet, FLAGS.wg_subnet)
        )
        if num_workload_gen > len(workload_generator_machines):
            raise Exception(
                "Not enough machines in testnet {}'s subnet {} to run {} workload generators".format(
                    self.wg_testnet, FLAGS.wg_subnet, num_workload_gen
                )
            )

        self.machines = workload_generator_machines[:num_workload_gen]
        self.num_workload_gen = num_workload_gen
        self.subnet_id = (
            FLAGS.target_subnet_id
            if FLAGS.target_subnet_id is not None and len(FLAGS.target_subnet_id) > 0
            else self.get_subnet_for_target()
        )

        print(f"Running against an IC {self.target_nodes} with git hash: {self.git_hash} from {self.machines}")

    def init_experiment(self):
        """Initialize the experiment."""
        if not self.check_workload_generator_installed(self.machines):
            rcs = self.install_workload_generator(self.machines)
            if not rcs == [0 for _ in range(len(self.machines))]:
                raise Exception(f"Failed to install workload generators, return codes are {rcs}")
        else:
            print(f"Workload generator already installed on {self.machines}")
        self.turn_off_replica(self.machines)
        self.kill_workload_generator(self.machines)
        super().init_experiment()

    def kill_workload_generator(self, machines):
        """Kill all workload generators on the given machine."""
        ssh.run_ssh_in_parallel(machines, "kill $(pidof ic-workload-generator) || true")

    def check_workload_generator_installed(self, machines):
        """Check if the workload generator is already installed on the given machines."""
        r = ssh.run_ssh_in_parallel(machines, "stat ./ic-workload-generator")
        return r == [0 for _ in machines]

    def install_workload_generator(self, machines):
        """Install workload generator on given machines in parallel."""
        print(f"Installing workload generators on {machines}")
        destinations = ["admin@[{}]:".format(m) for m in machines]
        sources = [self.workload_generator_path for _ in machines]
        r = ssh.scp_in_parallel(sources, destinations)
        ssh.run_ssh_in_parallel(machines, "chmod a+x ic-workload-generator")

        return r

    def get_subnet_for_target(self):
        """Determine the subnet ID of the node we are targeting."""
        if len(FLAGS.target_subnet_id) > 0:
            return FLAGS.target_subnet_id
        target = self.target_nodes[0]
        res = subprocess.check_output(
            [self.get_ic_admin_path(), "--nns-url", self.get_nns_url(), "get-subnet-list"], encoding="utf-8"
        )
        for subnet in json.loads(res):
            print(f"Checking if target node {target} is in subnetwork {subnet}")
            r = json.loads(self.get_subnet_info(subnet))
            for node_id in r["records"][0]["value"]["membership"]:
                if self.get_node_ip_address(node_id) == target:
                    print(f"Node {target} is in subnet {subnet}")
                    return subnet
        raise Exception("Could not find subnet for benchmark target")

    def get_machine_to_instrument(self):
        """Instrument the machine that we target the load for."""
        return self.get_targets()[0]

    def get_subnet_to_instrument(self):
        """Instrument the subnet that we target the load for."""
        return self.get_subnet_for_target()

    def get_targets(self) -> List[str]:
        """Get list of targets when running against a testnet."""
        if len(FLAGS.targets) > 0:
            return FLAGS.targets.split(",")

        node_ips = self.get_hostnames(self.testnet, FLAGS.subnet)

        if self.request_type == "call" or FLAGS.target_all:
            return node_ips
        else:
            return [node_ips[FLAGS.query_target_node_idx]]

    def get_mainnet_target(self) -> List[str]:
        """Get target if running in mainnet."""
        # If we want boundary nodes, we can see here:
        # http://prometheus.dfinity.systems:9090/graph?g0.expr=nginx_up&g0.tab=1&g0.stacked=0&g0.range_input=1h
        r = json.loads(self.get_subnet_info(FLAGS.target_subnet_id))
        node_ips = []
        for node_id in r["records"][0]["value"]["membership"]:
            node_ips.append(self.get_node_ip_address(node_id))
        if self.request_type == "call" or FLAGS.target_all:
            return node_ips
        else:
            return [node_ips[FLAGS.query_target_node_idx]]

    def run_workload_generator(
        self,
        machines,
        targets,
        requests_per_second,
        canister_ids=None,
        duration=300,
        outdir=None,
        payload=None,
        method=None,
        call_method=None,
        arguments=[],
    ):
        """Run the workload generator on all given machines."""
        if canister_ids is None:
            canister_ids = self.canister_ids

        assert requests_per_second % self.num_workload_gen == 0
        rps_per_machine = int(requests_per_second / self.num_workload_gen)

        print("Got targets: ", targets)
        target_list = ",".join(f"http://[{target}]:8080" for target in targets)
        print("Running against target_list")

        curr_outdir = self.out_dir if outdir is None else outdir
        cmd = (
            f'./ic-workload-generator "{target_list}" --summary-file wg_summary'
            f" -n {duration} -r {rps_per_machine} -p 9090 --no-status-check"
        )
        cmd += " " + " ".join(arguments)

        # Dump worklod generator command in output directory.
        if payload is not None:
            cmd += " --payload '{}'".format(payload.decode("utf-8"))
        if method is not None:
            cmd += " -m {}".format(method)
        if call_method is not None:
            cmd += ' --call-method "{}"'.format(call_method)

        commands = [
            "{} --canister-id {}".format(cmd, canister_ids[i % len(canister_ids)]) for i in range(len(machines))
        ]

        n = 0
        while n >= 0:
            n += 1
            try:
                filename = os.path.join(self.iter_outdir, f"workload-generator-cmd-{n}")
                with open(filename, "x") as cmd_file:
                    for cmd in commands:
                        cmd_file.write(cmd + "\n")
                n = -1
            except FileExistsError:
                print("Failed to open - file already exists")

        print(f"🚚  Running workload generator with {commands}")

        f_stdout = os.path.join(curr_outdir, "workload-generator-{}.stdout.txt")
        f_stderr = os.path.join(curr_outdir, "workload-generator-{}.stderr.txt")

        # Set timeout to 2x the duration.
        ssh.run_all_ssh_in_parallel(machines, commands, f_stdout, f_stderr, 2 * duration)

        print("Fetching workload generator results")

        sources = ["admin@[{}]:wg_summary".format(m) for m in machines]
        destinations = ["{}/summary_machine_{}".format(curr_outdir, m.replace(":", "_")) for m in machines]

        rc = ssh.scp_in_parallel(sources, destinations)
        if not rc == [0 for _ in range(len(sources))]:
            print(colored("⚠️  Some workload generators failed:", "red"))
            for fname in os.listdir(curr_outdir):
                if re.match("workload-generator.*stderr.*", fname):
                    with open(os.path.join(curr_outdir, fname)) as ferr:
                        lines = ferr.read().split("\n")
                        print("\n".join(lines[-10:]))

        print("Evaluating results from {} machines".format(len(destinations)))
        return report.evaluate_summaries(destinations)

    def build_summary_file(self):
        """Build dictionary used to render summary file for report."""
        return {
            "wg_testnet": self.wg_testnet,
            "load_generator_machines": self.machines,
            "target_machines": self.target_nodes,
            "subnet_id": self.subnet_id,
        }
