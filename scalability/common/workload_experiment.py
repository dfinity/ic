import json
import logging
import os
import subprocess
import time
from statistics import mean
from typing import List

import gflags
from common import ansible
from common import base_experiment
from common import misc
from common import prometheus
from common import report
from common import ssh
from common import workload
from termcolor import colored

NUM_WORKLOAD_GEN = 2  # Number of machines to run the workload generator on

FLAGS = gflags.FLAGS
gflags.DEFINE_bool("use_updates", False, "Issue update calls instead of query calls.")
gflags.DEFINE_string(
    "wg_testnet", None, "Testnet to deploy workload generators too. Can be the same as testnet, but use with care!"
)
gflags.MarkFlagAsRequired("wg_testnet")
gflags.DEFINE_integer("subnet", 1, "Subnet from which to choose the target machine.")
gflags.DEFINE_integer("wg_subnet", 0, "Subnet in which to run the workload generator.")
gflags.DEFINE_string("mainnet_target_subnet_id", "", "Subnet ID that is running the canister specified by canister_id.")
gflags.DEFINE_boolean("target_all", False, "Target all nodes, even when running query calls.")
gflags.DEFINE_string("targets", "", "Set load target IP adresses from this coma-separated list directly.")
gflags.DEFINE_string(
    "workload_generator_machines", "", "Set workload generator IP adresses from this coma-separated list directly."
)
gflags.DEFINE_integer(
    "query_target_node_idx",
    0,
    "The node idx to use within the subnetwork to target for query calls. Only relevant when running against mainnet.",
)
gflags.DEFINE_integer("target_rps", 10, "Requests per second the workload generator should execute.")


# When failure rate reaches this level, there is no point keep running, so stop following experiments.
STOP_FAILURE_RATE = 0.4
# When median latency reaches this level, there is no point keep running, so stop following experiments.
STOP_T_MEDIAN = 30000

# When failure rate is below this level, we consider the experiment successful.
ALLOWABLE_FAILURE_RATE = 0.2
# When median latency is below this level, we consider the experiment successful.
ALLOWABLE_LATENCY = 5000


class WorkloadExperiment(base_experiment.BaseExperiment):
    """Wrapper class around experiments that generates query/update load."""

    def __init__(self, num_workload_gen=NUM_WORKLOAD_GEN, request_type="query"):
        """Init."""
        self.wg_testnet = FLAGS.wg_testnet
        self.num_workload_gen = num_workload_gen
        self.use_updates = FLAGS.use_updates

        super().__init__(request_type)

        if self.use_updates:
            self.request_type = "call"
        print(f"Update calls: {self.use_updates} {self.request_type}")

        print(
            (
                f"➡️  Executing experiment against {self.testnet} subnet {FLAGS.subnet} "
                f" with workload generators on {self.wg_testnet} subnet {FLAGS.wg_subnet}"
            )
        )
        self.init()

    def get_mainnet_targets(self) -> List[str]:
        """Get target if running in mainnet."""
        # If we want boundary nodes, we can see here:
        # http://prometheus.dfinity.systems:9090/graph?g0.expr=nginx_up&g0.tab=1&g0.stacked=0&g0.range_input=1h
        r = json.loads(self._get_subnet_info(FLAGS.mainnet_target_subnet_id))
        node_ips = []
        for node_id in r["records"][0]["value"]["membership"]:
            node_ips.append(self.get_node_ip_address(node_id))
        if self.request_type == "call" or FLAGS.target_all:
            return node_ips
        else:
            return [node_ips[FLAGS.query_target_node_idx]]

    def init(self):
        """More init."""
        self.target_nodes = self.get_mainnet_targets() if self.testnet == "mercury" else self.__get_targets()

        # Determine which machines run workload generators.
        # For that, we need to query the NNS of the workload generator subnetwork
        if len(FLAGS.workload_generator_machines) > 0:
            workload_generator_machines = FLAGS.workload_generator_machines.split(",")
        else:
            wg_testnet_nns_host = ansible.get_ansible_hostnames_for_subnet(
                FLAGS.wg_testnet, base_experiment.NNS_SUBNET_INDEX, sort=False
            )[0]

            workload_generator_machines = self.get_hostnames(FLAGS.wg_subnet, f"http://[{wg_testnet_nns_host}]:8080")

        if self.num_workload_gen > len(workload_generator_machines):
            raise Exception(
                colored(
                    (
                        f"Not enough machines in testnet {self.wg_testnet}'s subnet {FLAGS.wg_subnet} "
                        f"to run {self.num_workload_gen} workload generators. "
                        "Try --num_workload_generators=X to override how many workload generators to use"
                    )
                ),
                "red",
            )

        self.machines = workload_generator_machines[: self.num_workload_gen]
        self.subnet_id = (
            FLAGS.mainnet_target_subnet_id
            if FLAGS.mainnet_target_subnet_id is not None and len(FLAGS.mainnet_target_subnet_id) > 0
            else self.__get_subnet_for_target()
        )

        print(f"Running against an IC {self.target_nodes} from {self.machines}")

        super().init()
        self.init_experiment()

    def init_experiment(self):
        """Initialize the experiment."""
        if not self.__check_workload_generator_installed(self.machines):
            rcs = self.__install_workload_generator(self.machines)
            if not rcs == [0 for _ in range(len(self.machines))]:
                raise Exception(f"Failed to install workload generators, return codes are {rcs}")
        else:
            print(f"Workload generator already installed on {self.machines}")
        self._turn_off_replica(self.machines)
        self.__kill_workload_generator(self.machines)
        super().init_experiment()

    def __kill_workload_generator(self, machines):
        """Kill all workload generators on the given machine."""
        ssh.run_ssh_in_parallel(machines, "kill $(pidof ic-workload-generator) || true")

    def __check_workload_generator_installed(self, machines):
        """Check if the workload generator is already installed on the given machines."""
        if len(FLAGS.workload_generator_path) > 0:
            print("Reinstalling workload generators since using locally built workload generator")
            return False
        r = ssh.run_ssh_in_parallel(machines, "stat ./ic-workload-generator")
        return r == [0 for _ in machines]

    def __install_workload_generator(self, machines):
        """Install workload generator on given machines in parallel."""
        print(f"Installing workload generators on {machines}")
        destinations = ["admin@[{}]:".format(m) for m in machines]
        sources = [self.workload_generator_path for _ in machines]
        r = ssh.scp_in_parallel(sources, destinations)
        ssh.run_ssh_in_parallel(machines, "chmod a+x ic-workload-generator")

        return r

    def __get_subnet_for_target(self):
        """Determine the subnet ID of the node we are targeting."""
        if len(FLAGS.mainnet_target_subnet_id) > 0:
            return FLAGS.mainnet_target_subnet_id
        target = self.target_nodes[0]
        res = subprocess.check_output(
            [self._get_ic_admin_path(), "--nns-url", self._get_nns_url(), "get-subnet-list"], encoding="utf-8"
        )
        for subnet in json.loads(res):
            print(f"Checking if target node {target} is in subnetwork {subnet}")
            r = json.loads(self._get_subnet_info(subnet))
            for node_id in r["records"][0]["value"]["membership"]:
                if self.get_node_ip_address(node_id) == target:
                    print(
                        colored(
                            (
                                f"Node {target} is in subnet {subnet} "
                                f"(to speed up suite for this deployment in the future, use --mainnet_target_subnet_id={subnet})"
                            ),
                            "yellow",
                        )
                    )
                    return subnet
        raise Exception("Could not find subnet for benchmark target")

    def get_machine_to_instrument(self):
        """Instrument the machine that we target the load for."""
        return self.__get_targets()[0]

    def __get_subnet_to_instrument(self):
        """Instrument the subnet that we target the load for."""
        return self.__get_subnet_for_target()

    def __get_targets(self) -> List[str]:
        """Get list of targets when running against a testnet."""
        if len(FLAGS.targets) > 0:
            return FLAGS.targets.split(",")

        node_ips = self.get_hostnames(FLAGS.subnet)

        if self.request_type == "call" or FLAGS.target_all:
            return node_ips
        else:
            return [node_ips[FLAGS.query_target_node_idx]]

    def __wait_for_quiet(self, max_num_iterations: int = 60, quiet_rate_rps: int = 2, sleep_per_iteration_s: int = 10):
        """
        Wait until target subnetwork recovered.

        Wait until the HTTP request rate reported by replicas is below quiet_rate_rps.
        Sleep sleep_per_iteration_s seconds after each check. Check at most
        max_num_iterations times and return unconditionally once reached.
        """
        recovered = False
        curr_i = 0

        if FLAGS.no_instrument:
            time.sleep(60)
            return

        while not recovered and curr_i < max_num_iterations:
            curr_i += 1
            try:
                r = prometheus.get_http_request_rate_for_timestamp(self.testnet, [], int(time.time()))
                v = [float(value[1]) for (value, _) in prometheus.parse(r)]
                rate_rps = mean(v)

                print(
                    (
                        f"{curr_i}/{max_num_iterations} Current mean HTTP rate of {self.testnet} "
                        f"{rate_rps} (want < {quiet_rate_rps})"
                    )
                )

                if rate_rps <= quiet_rate_rps:
                    recovered = True

            except Exception as ex:
                print(f"Failed to query http request rate from targets: {ex}")
                logging.error(logging.traceback.format_exc())

            time.sleep(sleep_per_iteration_s)

    def end_iteration(self, configuration={}):
        """End benchmark iteration."""
        super().end_iteration(configuration)
        # Get logs from targets
        since_time = self.t_iter_end - self.t_iter_start
        self.get_iter_logs_from_targets(self.target_nodes, f"-{since_time}", self.iter_outdir)

    def start_iteration(self):
        """Start a new iteration of the experiment."""
        super().start_iteration()
        self.__wait_for_quiet()

    def __get_mainnet_target(self) -> List[str]:
        """Get target if running in mainnet."""
        # If we want boundary nodes, we can see here:
        # http://prometheus.dfinity.systems:9090/graph?g0.expr=nginx_up&g0.tab=1&g0.stacked=0&g0.range_input=1h
        r = json.loads(self._get_subnet_info(FLAGS.mainnet_target_subnet_id))
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

        rps_per_machine = misc.distribute_load_to_n(requests_per_second, self.num_workload_gen)

        print("Got targets: ", targets)
        print("Running against target_list")

        curr_outdir = self.out_dir if outdir is None else outdir
        f_stdout = os.path.join(curr_outdir, "workload-generator-{}.stdout.txt")
        f_stderr = os.path.join(curr_outdir, "workload-generator-{}.stderr.txt")

        # Set timeout to 2 + len(targets) of the duration.
        # E.g. timeout will linearly increase as target machines number increase
        # Wait at least 300s, as there is a potentially high startup overhead for super-small
        # workloads.
        timeout = max((len(targets) / 10 + 2) * duration, 300)
        print(f"Setting workload generator timeout to: {timeout}")

        print(f"Running on {targets}")
        load = workload.Workload(
            machines,
            targets,
            rps_per_machine,
            canister_ids,
            duration,
            f_stdout,
            f_stderr,
            timeout,
            payload,
            method,
            call_method,
            arguments,
        )
        commands, load_generators = load.get_commands()
        assert load_generators == machines

        n = 0
        while True:
            n += 1
            try:
                filename = os.path.join(self.iter_outdir, f"workload-generator-cmd-{n}")
                # Try to open file in exclusive mode
                with open(filename, "x") as cmd_file:
                    for cmd in commands:
                        cmd_file.write(cmd + "\n")
                break
            except FileExistsError:
                print("Failed to open - file already exists")

        print(f"🚚  Running workload generator with {commands}")
        load.start()
        load.join()

        print("Fetching workload generator results")

        destinations = ["{}/summary_machine_{}".format(curr_outdir, m.replace(":", "_")) for m in machines]
        load.fetch_results(destinations, self.out_dir)
        print("Evaluating results from {} machines".format(len(destinations)))
        return report.evaluate_summaries(destinations)

    def __build_summary_file(self):
        """Build dictionary used to render summary file for report."""
        return {
            "wg_testnet": self.wg_testnet,
            "load_generator_machines": self.machines,
            "target_machines": self.target_nodes,
            "subnet_id": self.subnet_id,
        }
