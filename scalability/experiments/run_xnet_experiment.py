#!/usr/bin/env python3
"""
Experiment to stress Xnet.

This is using the Xnet test driver to benchmark Xnet performance.
"""
import json
import math
import os
import sys
import time

import gflags
from ic.candid import encode
from ic.candid import Types
from ic.principal import Principal
from termcolor import colored

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common.base_experiment as base_experiment  # noqa
import common.misc as misc  # noqa
import common.prometheus as prometheus  # noqa


FLAGS = gflags.FLAGS

# Has to be large enough to accomodate requested load.
gflags.DEFINE_integer("num_canisters_per_subnet", 5, "Number of canisters per subnetwork")

# Configuration for load
gflags.DEFINE_integer("iter_duration", 600, "Duration of each iteration of the Xnet benchmark")
gflags.DEFINE_integer("payload_size", 1024, "Payload size for Xnet messages")
gflags.DEFINE_integer("initial_rate", 500, "Initial total rate at which to send Xnet messages")
gflags.DEFINE_integer("rate_increment", 250, "Increment for total rate in each iteration")
gflags.DEFINE_integer("max_iterations", 25, "Maximum number of iterations")

gflags.DEFINE_float("max_error_rate", 0.05, "Maximum number of failed Xnet messages accepted per iteration.")
gflags.DEFINE_float("max_seq_errors", 0.0, "Maximum number of sequence errors to accept for iteration.")
gflags.DEFINE_float("min_send_rate", 0.3, "Minimum send rate accepted for success of iteration.")
gflags.DEFINE_integer("target_latency_secs", 40, "Targeted latency of Xnet requests.")

gflags.DEFINE_integer(
    "tests_first_subnet_index",
    1,
    "Start installing canisters on subnet with given index. Useful to avoid installing in NNS.",
)

CANISTER = "xnet-test-canister.wasm"


# Suggested subnet for experimenting: large02, large04 w/ four subnets
class XnetExperiment(base_experiment.BaseExperiment):
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

        self.num_subnets = len(self.get_subnets())
        print(f"Number of subnetworks is: {self.num_subnets}")
        for subnet_index in range(FLAGS.tests_first_subnet_index, self.num_subnets):
            # Take the first hostname of each subnetwork
            hostnames_in_subnet = self.get_hostnames(subnet_index)
            print(subnet_index, hostnames_in_subnet)
            first_host = hostnames_in_subnet[0]
            self.host_each_subnet.append(first_host)
            self.canisters_per_host[first_host] = []

        self.install_xnet_canisters()

    def install_xnet_canisters(self):
        """Install all canisters required for the Xnet benchmark."""
        t_start = time.time()
        for h in self.host_each_subnet:
            for i in range(FLAGS.num_canisters_per_subnet):
                # XXX - This installs canisters sequentially. We might want to improve this,
                # but that will make the code quite a bit more complex.
                # Also, currently install_canister_nonblocking doesn't determine the canister
                # ID at all.
                cid = self.install_canister(h, canister=os.path.join(self.artifacts_path, f"../canisters/{CANISTER}"))
                if cid is not None:
                    self.canisters_per_host[h].append(cid)
        time_install = time.time() - t_start
        print(colored(f"Installing canisters done: {self.canisters_per_host} after {time_install}", "blue"))

    def stop(hostnames: [str], canister_ids: [str]):
        """Stop the Xnet benchmark."""
        schema = Types.Text
        for (hostname, canister_id) in zip(hostnames, canister_ids):
            while True:
                try:
                    agent = misc.get_anonymous_agent(hostname)
                    response = agent.update_raw(canister_id, "stop", encode([]), schema)
                    canister_state = response[0]["value"]
                    assert canister_state == "stopped"
                    break
                except TypeError:
                    print(f"Failed to stop canister {canister_id} on {hostname} - retrying")

    def get_host_for_canister(self, canister_id):
        for host, canisters in self.canisters_per_host.items():
            if canister_id in canisters:
                return host

    class Metrics:
        """Representation of Metrics as collected by the Xnet test canister."""

        def __init__(self):
            self.requests_sent = 0
            self.call_errors = 0
            self.reject_responses = 0
            self.seq_errors = 0
            self.latency_buckets = []
            self.latency_sum_millis = 0

        def aggregate(self, metrics: dict):
            """Aggregate values from the given metrics on top of what's already stored in this class."""
            self.requests_sent += metrics["requests_sent"]
            self.call_errors += metrics["call_errors"]
            self.reject_responses += metrics["reject_responses"]
            self.seq_errors += metrics["seq_errors"]
            self.latency_sum_millis += metrics["latency_distribution"]["sum_millis"]

            latency_buckets = metrics["latency_distribution"]["buckets"]

            if len(self.latency_buckets) == 0:
                self.latency_buckets = {element[0]: element[1] for element in latency_buckets}
            else:
                assert len(self.latency_buckets) == len(latency_buckets)
                for element in latency_buckets:
                    self.latency_buckets[element[0]] += element[1]

    def get_aggregated_metrics(self, metrics: dict):
        aggregated_metrics = {}
        for canister_id, metrics in metrics.items():
            host = self.get_host_for_canister(canister_id)
            if host not in aggregated_metrics:
                aggregated_metrics[host] = XnetExperiment.Metrics()
            aggregated_metrics[host].aggregate(metrics)
        return aggregated_metrics

    def run_accepted(self, metrics: dict, config: dict):
        """Are the given metrics acceptable according to the specificatioon."""
        # print("Checking if accepted: ", metrics, config)
        runtime = config["duration"]
        canister_to_subnet_rate = config["canister_to_subnet_rate"]

        def accepted(val1, val2, fn, label):
            res = val1 is not None and val2 is not None and fn(val1, val2)
            if res:
                print(f"✅ Succeeded {label} (is: {val1} - threshold {val2})")
            else:
                print(f"❌ Failed {label}  (is: {val1} - threshold {val2})")
            return res

        res = True
        for host, m in self.get_aggregated_metrics(metrics).items():
            print("Checking success for total message rate", config["total_rate"], "for host", host)
            print("------------------------------")
            attempted_calls = m.requests_sent
            failed_calls = m.call_errors + m.reject_responses
            error_rate = failed_calls / attempted_calls if attempted_calls > 0 else None

            send_rate = (
                attempted_calls
                / (self.num_subnets - 1)
                / runtime
                / FLAGS.num_canisters_per_subnet
                / canister_to_subnet_rate
            )

            # Due to the nature of XNet, it takes a while for a
            # response to come back because one essentially needs to
            # go through consensus twice + certification it is
            # expected that at the end of the tests not all requests
            # will have received responses. This condition is there to
            # make sure that we still receive “enough” replies
            responses_received = sorted(m.latency_buckets.items())[-1][1] + m.reject_responses
            responses_expected = m.requests_sent * (runtime - FLAGS.target_latency_secs) / runtime

            avg_latency_millis = m.latency_sum_millis / responses_received if responses_received != 0 else None

            res = res and (
                accepted(error_rate, FLAGS.max_error_rate, lambda x, y: x < y, "error rate")
                and accepted(m.seq_errors, FLAGS.max_seq_errors, lambda x, y: x <= y, "seq errors")
                and accepted(responses_received, responses_expected, lambda x, y: x >= y, "enough responses")
                and accepted(send_rate, FLAGS.min_send_rate, lambda x, y: x >= y, "send rate")
                and accepted(avg_latency_millis, FLAGS.target_latency_secs * 1000, lambda x, y: x <= y, "latency")
            )
        return res

    def metrics(hostnames: [str], canister_ids: [str]) -> dict:
        """
        Get metrics from Xnet canisters.

        Returns a dict with canister ID as key.
        """
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
            results[canister_id] = req[0]["value"]
        return results

    def start(
        hostnames: [str], canister_ids: [str], topology: [[[int]]], subnet_to_subnet_rate=64, payload_size_bytes=32
    ):
        """Start Xnet canisters."""
        assert isinstance(hostnames, list)
        assert isinstance(canister_ids, list)

        schema = Types.Text
        for (hostname, canister_id) in zip(hostnames, canister_ids):

            while True:
                try:
                    agent = misc.get_anonymous_agent(hostname)
                    params = [
                        {"type": Types.Vec(Types.Vec(Types.Vec(Types.Nat8))), "value": topology},
                        {"type": Types.Nat64, "value": subnet_to_subnet_rate},
                        {"type": Types.Nat64, "value": payload_size_bytes},
                    ]
                    response = agent.update_raw(canister_id, "start", encode(params), schema)
                    canister_state = response[0]["value"]
                    assert canister_state == "started"
                    print(f"Success starting canister {canister_id} on {hostname}")
                    break
                except TypeError:
                    print(f"Failed to start canister {canister_id} on {hostname} - retrying")

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
            rate_per_canister = int(math.ceil(config["canister_to_subnet_rate"] / len(canisters)))
            xnet_topology = self.get_xnet_topology_as_u8()
            print(f"Using Xnet topology is: {xnet_topology}")
            XnetExperiment.start(
                [hostname for _ in canisters], canisters, xnet_topology, rate_per_canister, config["payload_size"]
            )

        duration = config["duration"]
        print(f"Running benchmark for {duration} seconds")
        time.sleep(duration)

        # Stop benchmark
        # --------------------------------------------------
        for hostname, canisters in self.canisters_per_host.items():
            XnetExperiment.stop([hostname for _ in canisters], canisters)

        # Get metrics
        # --------------------------------------------------
        results = {}
        for hostname, canisters in self.canisters_per_host.items():
            results.update(XnetExperiment.metrics([hostname for _ in canisters], canisters))
        # print(results)

        # Get Prometheus metrics
        # --------------------------------------------------
        if not FLAGS.no_prometheus:
            r = prometheus.get_xnet_stream_size(self.testnet, t_start, int(time.time()))
            out = json.dumps(r, indent=2)
            with open(os.path.join(self.iter_outdir, "xnet-stream-size.json"), "w") as iter_file:
                iter_file.write(out)

        return results

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
    misc.parse_command_line_args()

    exp = XnetExperiment()
    exp.init()

    exp.start_experiment()

    max_capacity = None

    for i in range(FLAGS.max_iterations):

        total_rate = FLAGS.initial_rate + i * FLAGS.rate_increment
        subnet_to_subnet_rate = int(math.ceil(total_rate / (exp.num_subnets - 1)))
        canister_to_subnet_rate = int(math.ceil(subnet_to_subnet_rate / FLAGS.num_canisters_per_subnet))
        print(
            f"🚀 Running iteration {i} with total rate of {total_rate} ({subnet_to_subnet_rate} per subnet, {canister_to_subnet_rate} per canister)"
        )

        config = {
            "duration": FLAGS.iter_duration,
            "payload_size": FLAGS.payload_size,
            "num_subnets": exp.num_subnets,
            "total_rate": total_rate,
            "subnet_to_subnet_rate": subnet_to_subnet_rate,
            "canister_to_subnet_rate": canister_to_subnet_rate,
        }

        metrics = exp.run_experiment(config)

        if exp.run_accepted(metrics, config):
            max_capacity = total_rate

    exp.write_summary_file(
        "run_xnet_experiment",
        {"rps": [FLAGS.payload_size]},
        [FLAGS.payload_size],
        "payload size [bytes]",
    )

    exp.end_experiment()
