import argparse
import math
import operator
import os
import subprocess
import sys
import traceback
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


def try_deploy_ic(testnet: str, revision: str, out_dir: str) -> None:
    """
    Try to deploy IC on the desired testnet.

    Args:
    ----
        testnet (str): name of the testnet, e.g. large01.
        revision (str): git revision hash to be used to deploy.
        out_dir (str): directory for storing stdout and stderr into files.

    """
    # TODO: command paths should be managed better.
    # Get the newest hash (containing disk image) from master.

    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    result_stdout = f"{out_dir}/stdout_log.txt"
    result_stderr = f"{out_dir}/stderr_log.txt"

    if revision is None:
        print("No Git revision for deployment. Exit.")
        sys.exit(1)

    # Start the IC deployment.
    print(
        colored(
            f"Deploying IC revision {revision} on testnet={testnet}. See the intermediate output in {result_stdout}. This can take some minutes ...",
            "red",
        )
    )

    with open(result_stdout, "w") as outfile, open(result_stderr, "w") as errfile:
        try:
            deploy_cmd = ["../testnet/tools/icos_deploy.sh", "--git-revision", f"{revision}", f"{testnet}"]
            print(f"Running deploy with command: {deploy_cmd}")
            result_deploy_ic = subprocess.run(
                deploy_cmd,
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
    print(colored(f"Deployment of the IC to testnet={testnet} finished successfully.", "green"))

    return revision


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


def get_datapoints(target_rps=500, rps_min=50, rps_max=20000, increment=50, exponent=0.5):
    """Get a distribution around target_rps from rps_min to rps_max with increasing distance between individual measurements."""
    rps = [rps_min, target_rps, rps_max]
    for inc in sorted(set([increment * round(2 ** (i * exponent)) for i in range(100)])):

        r = target_rps - inc
        rps.append(r)

        r = target_rps + inc
        rps.append(r)

    datapoints = sorted(set([x for x in rps if x >= rps_min and x <= rps_max]))
    num = len(datapoints)

    print(f"Measuring {num} datapoints {datapoints}")
    return datapoints


def get_equally_distributed_datapoints(rps_min, rps_max, increment):
    """Get an equal distribution of measurements for the given configuration."""
    return range(rps_min, rps_max, increment)


def get_threshold_approaching_datapoints(threshold, num_exp_points, num_lin_points):
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


def get_anonymous_agent(hostname: str):
    from ic.agent import Agent
    from ic.client import Client
    from ic.identity import Identity

    ident = Identity(anonymous=True)
    client = Client(url="http://[{}]:8080".format(hostname))
    return Agent(ident, client)


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


def distribute_load_to_n(load: int, n: int):
    """Distribute the given load to n entities."""
    per_entity = [int(math.floor(load / n))] * n
    remainder = load % n
    add_per_machine = [1 if x < remainder else 0 for x in range(n)]
    return [x + y for x, y in zip(per_entity, add_per_machine)]
