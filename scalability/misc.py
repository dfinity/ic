from __future__ import division

import os
import subprocess
import sys
import traceback

from termcolor import colored


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
        if r > rps_min:
            rps.append(r)

        r = target_rps + inc
        if r < rps_max:
            rps.append(r)

    datapoints = sorted(set(rps))
    num = len(datapoints)

    print(f"Measuring {num} datapoints {datapoints}")
    return datapoints


def verify(metric: str, actual: float, expected: float, threshold: float, result_file: str = None):
    """Check deviation is within threshold between actual and expected rate."""
    delta = get_difference_rate(actual, expected)

    if (
        (threshold == 0 and delta != 0)
        or (threshold > 0 and delta > threshold)
        or (threshold < 0 and delta < threshold)
    ):
        result = f"❌ {metric} has a delta of {delta} between actual rate {actual} and expected rate {expected}, and is beyond threshold {threshold}, fail!\n"

        if result_file is None:
            print(result)
        else:
            with open(result_file, "a") as ver_results:
                ver_results.write(result)

        return 1
    else:
        result = f"✅ {metric} has a delta of {delta} between actual rate {actual} and expected rate {expected}, and is within threshold {threshold}, success!\n"

        if result_file is None:
            print(result)
        else:
            with open(result_file, "a") as ver_results:
                ver_results.write(result)

        return 0


def get_difference_rate(actual, expected):
    """Calculate difference rate between actual value and expected value."""
    return actual if expected == 0 else (actual - expected) / expected


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
