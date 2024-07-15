import argparse
import math
import operator
import os
import re
import subprocess
import sys
import traceback
from pathlib import Path
from statistics import mean

import gflags
from termcolor import colored

FLAGS = gflags.FLAGS


def parse_command_line_args():
    # Start: Provide command line args support #
    # Get a dictionary of gflags from all imported files.
    flags = gflags.FLAGS.__dict__["__flags"]

    parser = argparse.ArgumentParser(description=colored("Experiment parameters.", "blue"))
    # Create a set of command line options, based on the imported gflags.
    for key, value in flags.items():
        if key == "help":
            continue
        # gflags with default=None are required arguments. (SK: that's not true, optional flags with None as default values are not required)
        if value.default is None:
            parser.add_argument(f"--{key}", required=True, help=colored(f"Required field. {value.help}", "red"))
        else:
            parser.add_argument(
                f"--{key}", required=False, default=value.default, help=f"{value.help}; default={value.default}"
            )
    # Now useful help message can be queried via: `python script_name.py -h`
    parser.parse_args()
    # Initialize gflags from the command line args.
    FLAGS(sys.argv)
    # Print all gflags for the experiment.
    print(colored("The following values will be used in the experiment.", "red"))
    for key, value in flags.items():
        print(colored(f"Parameter {key} = {value.value}", "blue"))
    # End: Provide command line args support #


def get_latest_ic_version_on_branch(branch: str):
    """Get IC version."""
    try:
        result_newest_revision = subprocess.check_output(
            ["../gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh", f"origin/{branch}"]
        )
    except Exception as e:
        print(colored("Getting newest revision failed.", "red"))
        print(str(e))
        print(traceback.format_exc())
        sys.exit(1)
    if result_newest_revision is None or result_newest_revision == "":
        print(colored("Getting newest revision failed.", "red"))
        sys.exit(1)
    return result_newest_revision.decode("utf-8").strip()


def get_iterations(target_rps=500, rps_min=50, rps_max=20000, increment=50, exponent=0.5):
    """Get a distribution around target_rps from rps_min to rps_max with increasing distance between individual measurements."""
    rps = [rps_min, target_rps, rps_max]
    for inc in sorted(set([increment * round(2 ** (i * exponent)) for i in range(100)])):

        r = target_rps - inc
        rps.append(r)

        r = target_rps + inc
        rps.append(r)

    return sorted(set([x for x in rps if x >= rps_min and x <= rps_max]))


def get_equally_distributed_datapoints(rps_min, rps_max, increment):
    """Get an equal distribution of measurements for the given configuration."""
    return range(rps_min, rps_max, increment)


def get_threshold_approaching_iterations(threshold, num_exp_points, num_lin_points):
    """
    Use if you want to measure the behaviour when the benchmark approaches some threshold value.

    First, `num_exp_points` many measurement are taken, from `threshold / 2 ** num_exp_points` to `threshold / 2`.
    Then, `num_lin_points` many measurements are taken from `threshold / 2` to `threshold`.

    """
    datapoints = []

    for i in range(num_exp_points, 0, -1):
        datapoints.append(int(threshold / 2 ** i))

    lin_step = int(threshold / (2 * num_lin_points + 1))
    start = int(threshold / 2)

    for i in range(1, num_lin_points + 1):
        datapoints.append(start + i * lin_step)

    return datapoints


def mean_or_minus_one(x):
    if len(x) > 0:
        return mean(x)
    else:
        return -1


def get_agent_for_url(url: str, anonymous=True):
    from ic.agent import Agent
    from ic.client import Client
    from ic.identity import Identity

    ident = Identity(anonymous=anonymous)
    client = Client(url=url)
    return Agent(ident, client)


def get_agent(hostname: str, anonymous=True):
    return get_agent_for_url("http://[{}]:8080".format(hostname), anonymous)


def evaluate_stop_conditions(conditions):
    okay = True
    op_labels = {
        operator.ge: ">=",
    }
    for (val1, val2, op, label1, label2) in conditions:

        op_label = op_labels[op] if op in op_labels else str(op)
        if op(val1, val2):
            okay = False
            print(colored(f"Stopping because {label1} {val1} {op_label} {label2} {val2}", "red"))
        else:
            print(colored(f"Okay since not {label1} {val1} {op_label} {label2} {val2}", "green"))

    return okay


def evaluate_stop_latency_failure_iter(latency, latency_threshold, failure, failure_threshold, iteration, max_iter):
    return evaluate_stop_conditions(
        [
            (latency, latency_threshold, operator.ge, "latency", "threshold"),
            (failure, failure_threshold, operator.ge, "failure rate", "threshold"),
            (iteration, max_iter, operator.ge, "iteration", "number datapointswork"),
        ]
    )


def distribute_load_to_n(load: float, n: int):
    """Distribute the given load to n entities."""
    assert load > 0, f"Requested to distribute load of {load} to {n} generators"
    return [math.floor(100 * load / n) / 100] * n


def load_artifacts(artifacts_path: str):
    """
    Load artifacts.

    If previously downloaded, reuse, otherwise download.
    When downloading, store the GIT commit hash that has been used in a text file.
    """
    f_artifacts_hash = os.path.join(artifacts_path, "githash")
    if subprocess.run(["stat", f_artifacts_hash], stdout=subprocess.DEVNULL).returncode != 0:
        print("Could not find artifacts, downloading .. ")
        # Delete old artifacts directory, if it exists
        subprocess.run(["rm", "-rf", artifacts_path], check=True)
        # Download new artifacts.
        artifacts_env = os.environ.copy()
        artifacts_env["GIT"] = subprocess.check_output(["git", "rev-parse", "HEAD"], encoding="utf-8")
        artifacts_env["GET_GUEST_OS"] = "0"
        output = subprocess.check_output(["../ic-os/dev-tools/get-artifacts.sh"], encoding="utf-8", env=artifacts_env)
        match = re.findall(r"Downloading artifacts for revision ([a-f0-9]*)", output)[0]
        # The script will always download the artifacts into the ic base directory, so we can just hardcode the artifacts path here
        p = Path(__file__).parents[2]
        f_artifacts_hash = os.path.join(p, "artifacts/release/githash")
        with open(f_artifacts_hash, "wt", encoding="utf-8") as f:
            f.write(match)
    else:
        print(
            (
                "⚠️  Re-using artifacts. While this is faster, there is a risk of inconsistencies."
                f'Call "rm -rf {artifacts_path}" in case something doesn\'t work.'
            )
        )
    artifacts_hash = open(f_artifacts_hash, "r").read()

    print(f"Artifacts hash is {artifacts_hash}")
    print(f"Found artifacts at {artifacts_path}")

    return artifacts_hash


def parse_datapoints(datapoints: str) -> [float]:
    """Determine the request rate to run from the given string."""
    if re.match(r"^[0-9\-:]+-[0-9\-:]+:?[0-9\-:]*$", datapoints):
        entries = datapoints.split(":")
        start, stop = tuple(map(int, entries[0].split("-")))
        steps = int(entries[1]) if len(entries) > 1 else int(math.ceil((stop - start) / 10))
        # numpy.arrange() supports floats in contrast to range() if we ever need that.
        return list(map(float, range(start, stop + 1, steps)))

    if re.match(r"^[0-9]+~[0-9]+~[0-9]+$", datapoints):
        start, target, stop = tuple(map(int, datapoints.split("~")))
        return list(map(float, get_iterations(target, start, stop)))

    if re.match(r"^[0-9,]*$", datapoints):
        return [float(e) for e in datapoints.split(",")]
