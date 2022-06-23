"""
Verifies performance of a benchmark run result in JSON file.
IMPORTANT: This script is only expected to be used for spot runs, not any experiments that go beyond
single iteration, due to the open experimental nature of those runs. For spot runs, this script is expected
to be called before the notify_dashboard.py script, so the threshold numbers used to validate results
in this script are passed to dashboard as markers.

Calling format: verify_perf.py --base_dir {} --git_revision {} --timestamp {} --median_latency_threshold {}

Expected JSON format:
{
    "experiment_details": {
        "rps_max": 3.850419,
        "is_update": true,
        "target_load": 50,
        "t_median": 120,
        "failure_rate": 0
    }
}

Output JSON format:  The incoming JSON file + below additions
{
    "is_success": true,
    "experiment_details": {
        "median_threshold_latency": 180
    }
}
"""
import json
import os
import sys

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import misc  # noqa

FLAGS = gflags.FLAGS
gflags.DEFINE_string(
    "base_dir",
    "./",
    "The base directory where output artifacts are generated into. The base_dir should contain sub folder named with git_revision.",
)
gflags.DEFINE_string(
    "git_revision",
    None,
    "Hash of the git revision which the benchmark run was exercised on. Output folder with this git_revision in name will be used to generate report.",
)
gflags.MarkFlagAsRequired("git_revision")
gflags.DEFINE_string(
    "timestamp",
    None,
    "The timestamp the benchmark run was marked with. Output folder with this timestamp in name will be used to generate report.",
)
gflags.MarkFlagAsRequired("timestamp")
gflags.DEFINE_integer(
    "median_latency_threshold", 3000, "Target median latency below which the test run is considered performant."
)


class VerifyPerf:
    """Verifies performance on metrics."""

    def __init__(self, result: str = None):
        self.__result_file = result
        self.__failures = 0

    def __print(self, message: str):
        """Prints the message to file if output file is provided. Otherwise, print to console."""
        if self.__result_file is not None and self.__result_file != "":
            with open(self.__result_file, "a") as results:
                results.write(message)
        print(message)

    def verify(self, metric: str, is_update: bool, actual: float, expected: float):
        """Check deviation is within threshold between actual and expected rate."""
        call_method = "Update" if is_update is True else "Query"

        if expected == 0 and actual != 0 or expected > 0 and actual > expected or expected < 0 and actual < expected:
            self.__print(f"❌{call_method} {metric} of value {actual} does not meet expectation {expected}, fail!\n")
            self.__failures += 1
        else:
            self.__print(f"✅{call_method} {metric} of value {actual} meets expectation {expected}, success!\n")

    def is_success(self):
        """Checks whether there is any failure in performance verifications till current point."""
        return self.__failures <= 0

    def conclude(self):
        """Concludes the performance verifications"""
        if self.__failures > 0:
            self.__print("❌ Performance did not meet expectation. 😭😭😭")
            sys.exit(1)

        self.__print("✅ Performance verifications passed! 🎉🎉🎉")
        sys.exit(0)


if __name__ == "__main__":
    misc.parse_command_line_args()
    dir = f"{FLAGS.base_dir}/{FLAGS.git_revision}/{FLAGS.timestamp}"

    with open(f"{dir}/experiment.json", "r") as experiment_file:
        j = json.loads(experiment_file.read())

    failure_rate = j["experiment_details"]["failure_rate"]
    t_median = j["experiment_details"]["t_median"]
    throughput = j["experiment_details"]["rps_max"]
    target_load = j["experiment_details"]["target_load"]
    is_update = j["experiment_details"]["is_update"]
    verifier = VerifyPerf(f"{dir}/verification_results.txt")
    verifier.verify("failure rate", is_update, failure_rate, 0)
    verifier.verify("median latency", is_update, t_median, FLAGS.median_latency_threshold)
    verifier.verify("throughput", is_update, throughput, target_load)

    with open(f"{dir}/experiment.json", "w") as experiment_file:
        j["is_success"] = verifier.is_success()
        j["experiment_details"]["median_latency_threshold"] = FLAGS.median_latency_threshold
        updated = json.dumps(j, indent=4)
        experiment_file.write(updated)

    verifier.conclude()
