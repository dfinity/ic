"""
Experiment to stress Xnet.

This is using the Xnet test driver to benchmark Xnet performance.
"""
import json
import os
import subprocess
import time

import experiment
import gflags
import prometheus

FLAGS = gflags.FLAGS
gflags.DEFINE_integer("runtime", 600, "Runtime as passed to the e2e test driver")  # 600 for slo tests
gflags.DEFINE_integer("payload_size", 1024, "Payload size for the e2e test driver")
gflags.DEFINE_integer("rate", 10, "Rate for the e2e test driver")

CANISTER = "xnet-test-canister.wasm"
XNET_TEST_DRIVER = "e2e-test-driver"


class ExperimentXnet(experiment.Experiment):
    """Logic for Xnet experiment."""

    def __init__(self):
        """Construct Xnet experiment."""
        super().__init__()
        self.init()
        self.init_experiment()
        self.canister = CANISTER

    def run_experiment_internal(self, config):
        """Run the e2e test driver for xnet with the given config."""
        print(f"Running with {config}")
        xnet_env = os.environ.copy()
        xnet_env["XNET_TEST_CANISTER_WASM_PATH"] = os.path.join(self.artifacts_path, f"../canisters/{CANISTER}")

        t_start = int(time.time())

        args = [
            os.path.join(self.artifacts_path, XNET_TEST_DRIVER),
            "--nns_url",
            self.get_nns_url(),
            "--subnets",
            str(len(self.get_subnets())),
            "--runtime",
            str(config["runtime"]),
            "--rate",
            str(config["rate"]),
            "--payload_size",
            str(config["payload_size"]),
            "--",
            "4.3",
        ]
        print(f"Running {args}")
        subprocess.check_output(args, env=xnet_env)

        r = prometheus.get_xnet_stream_size(self.testnet, t_start, int(time.time()))
        out = json.dumps(r, indent=2)
        with open(os.path.join(self.iter_outdir, "xnet-stream-size.json"), "w") as iter_file:
            iter_file.write(out)
        print(f"Got Prometheus metrics: {out}")

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
    exp.run_experiment(
        {
            "runtime": FLAGS.runtime,
            "payload_size": FLAGS.payload_size,
            "rate": FLAGS.rate,
        }
    )
    exp.write_summary_file(
        "experiment_xnet", {"rps": [FLAGS.payload_size]}, [FLAGS.payload_size], "payload size [bytes]"
    )

    exp.end_experiment()
