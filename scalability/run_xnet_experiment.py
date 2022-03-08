"""
Experiment to stress Xnet.

This is using the Xnet test driver to benchmark Xnet performance.
"""
import json
import math
import os
import time

import experiment
import gflags
import misc
import prometheus
from ic.candid import encode
from ic.candid import Types
from ic.principal import Principal
from termcolor import colored

FLAGS = gflags.FLAGS
gflags.DEFINE_integer("duration", 600, "Duration of each iteration of the Xnet benchmark")
gflags.DEFINE_integer("payload_size", 1024, "Payload size for Xnet messages")
gflags.DEFINE_integer("rate", 10, "Rate at which to send Xnet messages")
gflags.DEFINE_integer("num_canisters_per_subnet", 2, "Number of canisters per subnetwork")
gflags.DEFINE_integer(
    "tests_first_subnet_index",
    1,
    "Start installing canisters on subnet with given index. Useful to avoid installing in NNS.",
)

CANISTER = "xnet-test-canister.wasm"


class ExperimentXnet(experiment.Experiment):
    """Logic for Xnet experiment."""

    def __init__(self):
        """Construct Xnet experiment."""
        super().__init__()
        self.init()
        self.init_experiment()
        self.canister = CANISTER

    def init_experiment(self):
        """Install counter canister."""
        super().init_experiment()

        self.host_each_subnet = []
        self.canisters_per_host = {}

        num_subnets = len(self.get_subnets())
        print(f"Number of subnetworks is: {num_subnets}")
        for subnet_index in range(FLAGS.tests_first_subnet_index, num_subnets):
            # Take the first hostname of each subnetwork
            hostnames_in_subnet = self.get_hostnames(subnet_index)
            print(subnet_index, hostnames_in_subnet)
            first_host = hostnames_in_subnet[0]
            self.host_each_subnet.append(first_host)
            self.canisters_per_host[first_host] = []

        self.install_xnet_canisters()

    def install_xnet_canisters(self):
        """Install all canisters required for the Xnet benchmark."""
        for h in self.host_each_subnet:
            for i in range(FLAGS.num_canisters_per_subnet):
                print(f"Installing canister on host {h}")
                cid = self.install_canister(h, canister=os.path.join(self.artifacts_path, f"../canisters/{CANISTER}"))
                if cid is not None:
                    self.canisters_per_host[h].append(cid)
        print(colored(f"Installing canisters done: {self.canisters_per_host}", "blue"))

    def stop(hostnames: [str], canister_ids: [str]):
        """Stop the Xnet benchmark."""
        schema = Types.Text
        for (hostname, canister_id) in zip(hostnames, canister_ids):
            agent = misc.get_anonymous_agent(hostname)
            response = agent.update_raw(canister_id, "stop", encode([]), schema)
            canister_state = response[0]["value"]
            assert canister_state == "stopped"

    def metrics(hostnames: [str], canister_ids: [str]):
        """Get metrics from Xnet canisters."""
        schema = Types.Record(
            {
                "requests_sent": Types.Nat64,
                "call_errors": Types.Nat64,
                "reject_responses": Types.Nat64,
                "seq_errors": Types.Nat64,
                "latency_distribution": Types.Record(
                    {"buckets": Types.Vec(Types.Tuple(Types.Int64, Types.Nat64)), "sum_millis": Types.Nat64}
                ),
                "log": Types.Text,
            }
        )

        results = {}
        for (hostname, canister_id) in zip(hostnames, canister_ids):
            agent = misc.get_anonymous_agent(hostname)
            req = agent.query_raw(canister_id, "metrics", encode([]), schema)
            results[canister_id] = req
        return results

    def start(hostnames: [str], canister_ids: [str], topology: [[[int]]], rate=64, payload_size_bytes=32):
        """Start Xnet canisters."""
        assert isinstance(hostnames, list)
        assert isinstance(canister_ids, list)

        schema = Types.Text
        for (hostname, canister_id) in zip(hostnames, canister_ids):

            agent = misc.get_anonymous_agent(hostname)
            params = [
                {"type": Types.Vec(Types.Vec(Types.Vec(Types.Nat8))), "value": topology},
                {"type": Types.Nat64, "value": rate},
                {"type": Types.Nat64, "value": payload_size_bytes},
            ]
            response = agent.update_raw(canister_id, "start", encode(params), schema)
            canister_state = response[0]["value"]
            assert canister_state == "started"

    def get_xnet_topology(self):
        """Return topology to use for the previously setup canisters."""
        return [self.canisters_per_host[h] for h in self.host_each_subnet]

    def get_xnet_topology_as_u8(self):
        """Return the Xnet topology in a format suitable for Candid."""
        return [
            [[b for b in Principal.from_str(canister_id)._bytes] for canister_id in canisters_per_subnet]
            for canisters_per_subnet in self.get_xnet_topology()
        ]

    def run_experiment_internal(self, config):
        """Run a single iteration of the Xnet benchmark and return it's metrics."""
        t_start = int(time.time())
        # Start benchmark
        # --------------------------------------------------
        for hostname, canisters in self.canisters_per_host.items():
            # Since we have multiple canisters per subnetwork n, each of them
            # needs to send 1/n of the desired rate.
            # We round up to the next integer number
            rate_per_canister = int(math.ceil(config["rate"] / len(canisters)))
            xnet_topology = self.get_xnet_topology_as_u8()
            print(f"Using Xnet topology is: {xnet_topology}")
            ExperimentXnet.start(
                [hostname for _ in canisters], canisters, xnet_topology, rate_per_canister, config["payload_size"]
            )

        time.sleep(config["duration"])

        # Stop benchmark
        # --------------------------------------------------
        for hostname, canisters in self.canisters_per_host.items():
            ExperimentXnet.stop([hostname for _ in canisters], canisters)

        # Get metrics
        # --------------------------------------------------
        results = {}
        for hostname, canisters in self.canisters_per_host.items():
            results.update(ExperimentXnet.metrics([hostname for _ in canisters], canisters))
        print(results)

        # Get Prometheus metrics
        # --------------------------------------------------
        if not FLAGS.no_prometheus:
            r = prometheus.get_xnet_stream_size(self.testnet, t_start, int(time.time()))
            out = json.dumps(r, indent=2)
            with open(os.path.join(self.iter_outdir, "xnet-stream-size.json"), "w") as iter_file:
                iter_file.write(out)

    def parse(path: str):
        """Parse the given json file containing Prometheus xnet-stream data."""
        results = {}
        num = 0
        with open(path) as f:
            r = json.loads(f.read())
            for entry in r["data"]["result"]:
                value = int(entry["value"][1])
                time = float(entry["value"][0])
                subnet = entry["metric"]["ic_subnet"]
                curr_value = results[(subnet, time)] if (subnet, time) in results else 0
                results[(subnet, time)] = curr_value + value
                num += 1
        for ((subnet, time), value) in results.items():
            print(f"{subnet} {time} {value}")
        print(num)


if __name__ == "__main__":
    experiment.parse_command_line_args()

    exp = ExperimentXnet()
    exp.init()

    exp.start_experiment()

    while True:

        exp.run_experiment(
            {
                "duration": FLAGS.duration,
                "payload_size": FLAGS.payload_size,
                "rate": FLAGS.rate,
            }
        )
        break

    exp.write_summary_file(
        "run_xnet_experiment", {"rps": [FLAGS.payload_size]}, [FLAGS.payload_size], "payload size [bytes]"
    )

    exp.end_experiment()
