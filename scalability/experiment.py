import argparse
import json
import os
import re
import subprocess
import sys
import time
import traceback
from typing import List

import flamegraphs
import generate_report
import gflags
import machine_failure
import prometheus
import report
import ssh
from termcolor import colored

NUM_WORKLOAD_GEN = 2  # Number of machines to run the workload generator on
NNS_SUBNET_INDEX = 0  # Subnet index of the NNS subnetwork

FLAGS = gflags.FLAGS
gflags.DEFINE_string("testnet", None, 'Testnet to use. Use "mercury" to run against mainnet.')
gflags.MarkFlagAsRequired("testnet")
gflags.DEFINE_string(
    "wg_testnet", None, "Testnet to deploy workload generators too. Can be the same as testnet, but use with care!"
)
gflags.MarkFlagAsRequired("wg_testnet")
gflags.DEFINE_integer("subnet", 1, "Subnet from which to choose the target machine")
gflags.DEFINE_integer("wg_subnet", 0, "Subnet in which to run the workload generator")
gflags.DEFINE_boolean("skip_generate_report", False, "Skip generating report after experiment is finished")
gflags.DEFINE_integer("wg_connections_per_host", 1, "Number of connections to use per workload generator")
gflags.DEFINE_boolean("should_deploy_ic", False, "Should the IC be deployed on testnet before the experiment.")
gflags.DEFINE_string("canister_id", "", "Use given canister ID instead of installing a new canister")
gflags.DEFINE_string("target_subnet_id", "", "Subnet ID that is running the canister specified by canister_id")
gflags.DEFINE_string("artifacts_path", "../artifacts/release", "Path to the artifacts directory")
gflags.DEFINE_boolean("no_instrument", False, "Do not instrument target machine")
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
gflags.DEFINE_string("top_level_out_dir", "", "Set the top-level output directory. Default is the git commit id.")
gflags.DEFINE_string(
    "second_level_out_dir",
    "",
    "Set the second-level output directory. Default is the UNIX timestamp at benchmark start.",
)
gflags.DEFINE_boolean("simulate_machine_failures", False, "Simulate machine failures while testing.")
gflags.DEFINE_string("nns_url", "", "Use the following NNS URL instead of getting it from the testnet configuration")


class Color:
    """Colors for the shell commands."""

    BLUE = "\033[94m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    END = "\033[0m"
    GREEN = "\033[32m"


def try_deploy_ic(testnet: str) -> None:
    """
    Try to deploy IC on the desired testnet.

    Args:
    ----
        testnet (str): name of the testnet, e.g. large01.

    """
    # TODO: command paths should be managed better.
    # Get the newest hash (containing disk image) from master.
    result_stdout = "stdout_log.txt"
    result_stderr = "stderr_log.txt"
    with open(result_stderr, "w") as errfile:
        try:
            result_newest_revision = subprocess.run(
                ["../gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh", "origin/master"],
                stdout=subprocess.PIPE,
                stderr=errfile,
            )
        except Exception as e:
            print(f"Getting newest revision failed. See {result_stderr} file for details.")
            errfile.write(str(e))
            errfile.write(traceback.format_exc())
            sys.exit(1)
        if result_newest_revision.returncode != 0:
            print(f"Getting newest revision failed. See {result_stderr} file for details.")
            sys.exit(1)
    hash_revision = result_newest_revision.stdout.decode("utf-8").strip()

    # Start the IC deployment.
    print(
        f"{Color.RED}Deploying IC on testnet={testnet}. See the intermediate output in {result_stdout}. This can take some minutes ...{Color.END}"
    )
    with open(result_stdout, "w") as outfile, open(result_stderr, "w") as errfile:
        try:
            result_deploy_ic = subprocess.run(
                ["../testnet/tools/icos_deploy.sh", f"{testnet}", "--git-revision", f"{hash_revision}"],
                stdout=outfile,
                stderr=errfile,
            )
        except Exception as e:
            print(f"Deployment of the IC failed: See {result_stderr} file for details.")
            errfile.write(str(e))
            errfile.write(traceback.format_exc())
            sys.exit(1)
    if result_deploy_ic.returncode != 0:
        print(f"Deployment of the IC failed. See {result_stderr} file for details.")
        sys.exit(1)
    print(f"{Color.BOLD}{Color.GREEN}Deployment of the IC to testnet={testnet} finished successfully.{Color.END}")


def parse_command_line_args():
    # Start: Provide command line args support #
    # Get a dictionary of gflags from all imported files.
    flags = gflags.FLAGS.__dict__["__flags"]

    parser = argparse.ArgumentParser(description=f"{Color.BOLD}{Color.BLUE}Experiment parameters.{Color.END}")
    # Create a set of command line options, based on the imported gflags.
    for key, value in flags.items():
        if key == "help":
            continue
        # gflags with default=None are required arguments. (SK: that's not true, optional flags with None as default values are not required)
        if value.default is None:
            parser.add_argument(f"--{key}", required=True, help=f"{Color.RED} Required field. {Color.END} {value.help}")
        else:
            parser.add_argument(
                f"--{key}", required=False, default=value.default, help=f"{value.help}; default={value.default}"
            )
    # Now useful help message can be queried via: `python script_name.py -h`
    parser.parse_args()
    # Initialize gflags from the command line args.
    FLAGS(sys.argv)
    # Print all gflags for the experiment.
    print(f"{Color.BOLD}{Color.RED}The following values will " f"be used in the experiment.{Color.END}")
    for key, value in flags.items():
        print(f"Parameter {Color.BLUE} {key} = {value.value} {Color.END}")

    if FLAGS.testnet == "mercury" and FLAGS.target_subnet_id is None:
        raise Exception("--target_subnet_id has to be set when running against mainnet")

    # End: Provide command line args support #


class Experiment:
    """Wrapper class around experiments."""

    def __init__(self, num_workload_gen=NUM_WORKLOAD_GEN, request_type="query"):
        """Init."""
        sys.path.insert(1, "../ic-os/guestos/tests")  # for ictools
        import ictools

        testnet = FLAGS.testnet
        wg_testnet = FLAGS.wg_testnet

        if FLAGS.should_deploy_ic:
            try_deploy_ic(testnet=testnet)

        print(
            (
                f"➡️  Executing experiment against {testnet} subnet {FLAGS.subnet}"
                f"with workload generators on {wg_testnet} subnet {FLAGS.wg_subnet}"
            )
        )

        self.load_artifacts()

        self.canister_ids = []
        self.testnet = testnet
        self.wg_testnet = wg_testnet
        # Otherwise, consensus cannot have progress in those subnets any more.
        # In the long run we probably don't want to run the workload generators on those machines
        # If users overwrite the workload generator via -wg_subnet, we assume they know what they are doing.
        print(f"Workload generator machines are: {FLAGS.workload_generator_machines}")
        if (
            len(FLAGS.workload_generator_machines) == 0
            and len(self.get_hostnames(wg_testnet, FLAGS.wg_subnet)) < 2 * num_workload_gen + 1
            and FLAGS.wg_testnet == FLAGS.testnet
        ):

            print(
                (
                    f"Cannot deploy {num_workload_gen} workload generators to subnet {FLAGS.wg_subnet} "
                    f"on {FLAGS.wg_testnet} w/o making consensus unusable. "
                    f"Either choose a different subnetwork for workload generators using --wg_subnet "
                    f"or best, choose a separate testnet for the workload generators."
                )
            )
            exit(1)

        self.request_type = request_type
        self.target_nodes = self.get_mainnet_targets() if testnet == "mercury" else self.get_targets()

        workload_generator_machines = (
            FLAGS.workload_generator_machines.split(",")
            if len(FLAGS.workload_generator_machines) > 0
            else self.get_hostnames(wg_testnet, FLAGS.wg_subnet)
        )
        if num_workload_gen > len(workload_generator_machines):
            raise Exception(
                "Not enough machines in testnet {}'s subnet {} to run {} workload generators".format(
                    wg_testnet, FLAGS.wg_subnet, num_workload_gen
                )
            )

        self.machines = workload_generator_machines[:num_workload_gen]
        self.num_workload_gen = num_workload_gen
        self.metrics = []

        self.t_experiment_start = None
        self.iteration = 0

        self.git_hash = ictools.get_ic_version("http://[{}]:8080/api/v2/status".format(self.target_nodes[0]))
        print(f"Running against an IC {self.target_nodes} with git hash: {self.git_hash} from {self.machines}")

        self.out_dir_timestamp = int(time.time())
        self.out_dir = "{}/{}/".format(
            self.git_hash if len(FLAGS.top_level_out_dir) < 1 else FLAGS.top_level_out_dir,
            self.out_dir_timestamp if len(FLAGS.second_level_out_dir) < 1 else FLAGS.second_level_out_dir,
        )
        os.makedirs(self.out_dir, 0o755)
        print(f"📂 Storing output in {self.out_dir}")

        self.subnet_id = (
            FLAGS.target_subnet_id
            if FLAGS.target_subnet_id is not None and len(FLAGS.target_subnet_id) > 0
            else self.get_subnet_for_target()
        )

        self.store_ic_info()
        self.store_hardware_info()

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

    def get_targets(self) -> List[str]:
        """Get list of targets when running against a testnet."""
        if len(FLAGS.targets) > 0:
            return FLAGS.targets.split(",")

        node_ips = self.get_hostnames(FLAGS.testnet, FLAGS.subnet)

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

    def load_artifacts(self):
        """
        Load artifacts.

        If previously downloaded, reuse, otherwise download.
        When downloading, store the GIT commit hash that has been used in a text file.
        """
        self.artifacts_path = FLAGS.artifacts_path
        f_artifacts_hash = os.path.join(self.artifacts_path, "githash")
        if subprocess.run(["stat", f_artifacts_hash]).returncode != 0:
            print("Could not find artifacts, downloading .. ")
            # Delete old artifacts directory, if it exists
            subprocess.run(["rm", "-rf", self.artifacts_path], check=True)
            # Download new artifacts.
            artifacts_env = os.environ.copy()
            artifacts_env["GIT"] = subprocess.check_output(["git", "rev-parse", "origin/master"], encoding="utf-8")
            artifacts_env["GET_GUEST_OS"] = "0"
            output = subprocess.check_output(
                ["../ic-os/guestos/scripts/get-artifacts.sh"], encoding="utf-8", env=artifacts_env
            )
            match = re.findall(r"Downloading artifacts for revision ([a-f0-9]*)", output)[0]
            f = open(f_artifacts_hash, "wt", encoding="utf-8")
            f.write(match)
        else:
            print(
                (
                    "⚠️  Re-using artifacts. While this is faster, there is a risk of inconsistencies."
                    f'Call "rm -rf {self.artifacts_path}" in case something doesn\'t work.'
                )
            )
        self.artifacts_hash = open(f_artifacts_hash, "r").read()

        print(f"Artifacts hash is {self.artifacts_hash}")
        print(f"Found artifacts at {self.artifacts_path}")
        self.workload_generator_path = os.path.join(self.artifacts_path, "ic-workload-generator")

    def run_experiment(self, config):
        """Run a single iteration of the experiment."""
        self.start_iteration()
        result = self.run_experiment_internal(config)
        self.end_iteration(config)
        return result

    def run_experiment_internal(self, config):
        """Run a single iteration of the experiment."""
        raise Exception("Needs to be implemented by each experiment")

    def init_metrics(self):
        """Initialize metrics to collect for experiment."""
        self.metrics = [
            flamegraphs.Flamegraph("flamegraph", self.target_nodes[0], not FLAGS.no_instrument),
            prometheus.Prometheus("prometheus", self.target_nodes[0], not FLAGS.no_instrument),
        ]
        for m in self.metrics:
            m.init()

    def init_experiment(self):
        """Initialize what's necessary to run experiments."""
        self.init_metrics()

        self.kill_workload_generator(self.machines)
        self.turn_off_replica(self.machines)
        if not self.check_workload_generator_installed(self.machines):
            rcs = self.install_workload_generator(self.machines)
            if not rcs == [0 for _ in range(len(self.machines))]:
                raise Exception(f"Failed to install workload generators, return codes are {rcs}")
        else:
            print("Workload generator already installed on self.machines")

    def start_iteration(self):
        """Start a new iteration of the experiment."""
        self.iteration += 1
        self.t_iter_start = int(time.time())

        # Create output directory
        self.iter_outdir = "{}/{}".format(self.out_dir, self.iteration)
        os.makedirs(self.iter_outdir, 0o755)

        if FLAGS.simulate_machine_failures:
            machine_failure.MachineFailure(self).start()

        # Start metrics for this iteration
        for m in self.metrics:
            m.start_iteration(self.iter_outdir)

    def end_iteration(self, configuration={}):
        """End a new iteration of the experiment."""
        self.t_iter_end = int(time.time())

        # Get logs from targets
        since_time = self.t_iter_end - self.t_iter_start
        self.get_iter_logs_from_targets(self.target_nodes, f"-{since_time}", self.iter_outdir)

        for m in self.metrics:
            m.end_iteration(self)

        # Dump experiment info
        with open(os.path.join(self.iter_outdir, "iteration.json"), "w") as iter_file:
            iter_file.write(
                json.dumps(
                    {
                        "t_start": self.t_iter_start,
                        "t_end": self.t_iter_end,
                        "configuration": configuration,
                    }
                )
            )

    def start_experiment(self):
        """Start the experiment."""
        self.t_experiment_start = int(time.time())

    def end_experiment(self):
        """End the experiment."""
        print(
            "Experiment finished. Generating report like: python3 generate_report.py {} {}".format(
                self.git_hash, self.out_dir_timestamp
            )
        )
        if not FLAGS.skip_generate_report:
            generate_report.generate_report(self.git_hash, self.out_dir_timestamp)

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
            f" --connections-per-host {FLAGS.wg_connections_per_host}"
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

    def get_ic_admin_path(self):
        """Return path to ic-admin."""
        return os.path.join(self.artifacts_path, "ic-admin")

    def get_topology(self):
        """Get the current topology from the registry."""
        res = subprocess.check_output(
            [self.get_ic_admin_path(), "--nns-url", self.get_nns_url(), "get-topology"], encoding="utf-8"
        )
        return json.loads(res)

    def get_node_info(self, nodeid):
        """Get info for the given node from the registry."""
        return subprocess.check_output(
            [self.get_ic_admin_path(), "--nns-url", self.get_nns_url(), "get-node", nodeid], encoding="utf-8"
        )

    def get_subnet_info(self, subnet_idx):
        """Get info for the given subnet from the registry."""
        return subprocess.check_output(
            [self.get_ic_admin_path(), "--nns-url", self.get_nns_url(), "get-subnet", str(subnet_idx)], encoding="utf-8"
        )

    def store_ic_info(self):
        """Store subnet info for the subnet that we are targeting in the experiment output directory."""
        jsondata = self.get_subnet_info(self.get_subnet_for_target())
        with open(os.path.join(self.out_dir, "subnet_info.json"), "w") as subnet_file:
            subnet_file.write(jsondata)

        jsondata = self.get_topology()
        with open(os.path.join(self.out_dir, "topology.json"), "w") as subnet_file:
            subnet_file.write(json.dumps(jsondata, indent=2))

    def store_hardware_info(self):
        """Store info for the target machine in the experiment output directory."""
        if FLAGS.no_instrument:
            return
        p = ssh.run_ssh(
            self.target_nodes[0],
            "lscpu",
            f_stdout=os.path.join(self.out_dir, "lscpu.stdout.txt"),
            f_stderr=os.path.join(self.out_dir, "lscpu.stderr.txt"),
        )
        p.wait()

        p = ssh.run_ssh(
            self.target_nodes[0],
            "free -h",
            f_stdout=os.path.join(self.out_dir, "free.stdout.txt"),
            f_stderr=os.path.join(self.out_dir, "free.stderr.txt"),
        )
        p.wait()

    def get_node_ip_address(self, nodeid):
        """Get HTTP endpoint for the given node."""
        nodeinfo = self.get_node_info(nodeid)
        ip = re.findall(r'ip_addr: "([a-f0-9:A-F]+)"', nodeinfo)
        return ip[0]

    def get_unassigned_nodes(self):
        """Return a list of unassigned node IDs in the given subnetwork."""
        topo = self.get_topology()
        return [j["node_id"] for j in topo["topology"]["unassigned_nodes"]]

    def get_subnets(self):
        """Get the currently running subnetworks."""
        topo = self.get_topology()
        return [k for (k, _) in topo["topology"]["subnets"].items()]

    def get_subnet_members(self, subnet_index):
        """Get members of subnet with the given subnet index (not subnet ID)."""
        topo = self.get_topology()
        subnet_info = [info for (_, info) in topo["topology"]["subnets"].items()]
        return subnet_info[subnet_index]["records"][0]["value"]["membership"]

    def get_nns_url(self):
        """Get the testnets NNS url."""
        if len(FLAGS.nns_url) > 0:
            return FLAGS.nns_url
        ip = (
            "2001:920:401a:1708:5000:4fff:fe92:48f1"
            if FLAGS.testnet == "mercury"
            else self.get_hostnames(FLAGS.testnet, NNS_SUBNET_INDEX)[0]
        )
        return f"http://[{ip}]:8080"

    def add_node_to_subnet(self, subnet_index, node_ids):
        """Add nodes given in node_ids to the given subnetwork."""
        assert isinstance(node_ids, list)
        processes = []
        for node_id in node_ids:
            cmd = [
                self.get_ic_admin_path(),
                "--nns-url",
                self.get_nns_url(),
                "propose-to-add-nodes-to-subnet",
                "--test-neuron-proposer",
                "--subnet-id",
                str(subnet_index),
                node_id,
            ]
            print(f"Executing {cmd}")
            p = subprocess.Popen(cmd)
            processes.append(p)

        for p in processes:
            p.wait()

        num_tries = 0
        node_added = False
        while node_added:

            print(f"Testing if node {node_id} is a member of subnet {subnet_index}")
            num_tries += 1
            assert num_tries < 10  # Otherwise timeout

            node_added = True

            for node_id in node_ids:
                node_added &= node_id in self.get_subnet_members(subnet_index)

    def turn_off_replica(self, machines):
        """Turn of replicas on the given machines."""
        for m in machines:
            print(f"💣 Stopping machine {m}")
        return ssh.run_ssh_in_parallel(machines, "sudo systemctl stop ic-replica")

    def install_canister_nonblocking(self, target, canister=None):
        """
        Install the canister on the given machine.

        Note that canisters are currently always installed as best effort.
        """
        print("Installing canister .. ")
        cmd = [self.workload_generator_path, "http://[{}]:8080".format(target), "-n", "1", "-r", "1"]
        if canister is not None:
            cmd += ["--canister", canister]
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def install_canister(self, target: str, canister=None, check=True):
        """
        Install the canister on the given machine.

        Note that canisters are currently always installed as best effort.
        """
        if FLAGS.canister_id is not None and len(FLAGS.canister_id) > 0:
            print(f"⚠️  Not installing canister, using {FLAGS.canister_id} ")
            self.canister = f"pre-installed canister {FLAGS.canister_id}"
            self.canister_ids.extend(FLAGS.canister_id.split(","))
            return

        print("Installing canister .. ")
        self.canister = canister if canister is not None else "counter"
        cmd = [self.workload_generator_path, f"http://[{target}]:8080", "-n", "1", "-r", "1"]
        if canister is not None:
            cmd += ["--canister", canister]
        try:
            p = subprocess.run(
                cmd,
                check=check,
                capture_output=True,
            )
            wg_output = p.stdout.decode("utf-8").strip()
            for line in wg_output.split("\n"):
                print("Output: ", line)
                canister_id = re.findall(r"Successfully created canister at URL [^ ]*. ID: [^ ]*", line)
                if len(canister_id):
                    cid = canister_id[0].split()[7]
                    self.canister_ids.append(cid)
                    print("Found canister ID: ", cid)
            wg_err_output = p.stderr.decode("utf-8").strip()
            for line in wg_err_output.split("\n"):
                print("Output (stderr):", line)
        except Exception as e:
            print(f"Failed to install canister, return code: {e.returncode}")
            print(f"Command was: {cmd}")
            print(e.output.decode("utf-8"))
            print(e.stderr.decode("utf-8"))
            exit(5)

    def check_workload_generator_installed(self, machines):
        """Check if the workload generator is already installed on the given machines."""
        return False
        # r = ssh.run_ssh_in_parallel(machines, "stat ./ic-workload-generator")
        # return r == [0 for _ in machines]

    def install_workload_generator(self, machines):
        """Install workload generator on given machines in parallel."""
        destinations = ["admin@[{}]:".format(m) for m in machines]
        sources = [self.workload_generator_path for _ in machines]
        r = ssh.scp_in_parallel(sources, destinations)
        ssh.run_ssh_in_parallel(machines, "chmod a+x ic-workload-generator")

        return r

    def kill_workload_generator(self, machines):
        """Kill all workload generators on the given machine."""
        ssh.run_ssh_in_parallel(machines, "kill $(pidof ic-workload-generator) || true")

    def get_machines(self, testnet, subnet=0):
        """Get a list of machines for the given subnetwork."""
        p = subprocess.run(
            ["ansible-inventory", "-i", "env/{}/hosts".format(testnet), "--list"],
            check=True,
            cwd="../testnet",
            capture_output=True,
        )
        j = json.loads(p.stdout.decode("utf-8"))

        hosts = [
            info
            for (_, info) in j["_meta"]["hostvars"].items()
            if "subnet_index" in info and info["subnet_index"] == subnet
        ]

        return hosts

    def get_hostnames(self, testnet, subnet=0):
        """Return hostnames of all machines in the given testnet and subnet."""
        return sorted([h["ansible_host"] for h in self.get_machines(testnet, subnet)])

    def write_summary_file(
        self, experiment_name, experiment_details, xlabels, xtitle="n.a.", rtype="query", state="running"
    ):
        """
        Write the current summary file.

        The idea is that we write one after each iteration, so that we can
        generate reports from intermediate versions.
        """
        with open(os.path.join(self.out_dir, "experiment.json"), "w") as iter_file:
            iter_file.write(
                json.dumps(
                    {
                        "xlabels": xlabels,
                        "xtitle": xtitle,
                        "command_line": sys.argv,
                        "subnet_id": self.subnet_id,
                        "experiment_name": experiment_name,
                        "experiment_details": experiment_details,
                        "type": rtype,
                        "workload": self.canister,
                        "testnet": self.testnet,
                        "user": subprocess.check_output(["whoami"], encoding="utf-8"),
                        "wg_testnet": self.wg_testnet,
                        "canister_id": self.canister_ids,
                        "target_machines": self.target_nodes,
                        "artifacts_githash": self.artifacts_hash,
                        "load_generator_machines": self.machines,
                        "t_experiment_start": self.t_experiment_start,
                        "t_experiment_end": int(time.time()),
                        "state": state,
                    }
                )
            )

    def get_iter_logs_from_targets(self, machines: List[str], since_time: str, outdir: str):
        """Fetch logs from target machines since the given time."""
        ssh.run_all_ssh_in_parallel(
            machines,
            [f"journalctl -u ic-replica --since={since_time}" for m in machines],
            outdir + "/replica-log-{}-stdout.txt",
            outdir + "/replica-log-{}-stderr.txt",
        )
