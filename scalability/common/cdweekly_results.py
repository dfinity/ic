#!/bin/python
import glob
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass
from datetime import datetime

import gflags
import pybars
from termcolor import colored

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import misc  # noqa
from common import report  # noqa

FLAGS = gflags.FLAGS
gflags.DEFINE_string("experiment_data", ".", "Path to experiment data")
gflags.DEFINE_string("asset_root", "", "Path to the root of the asset canister")
gflags.DEFINE_integer("num_boundary_nodes", -1, "Number of boundary nodes in the IC")
gflags.DEFINE_boolean("regenerate", False, "Regenerate all reports")

TEMPLATE_BASEDIR = "templates"
TEMPLATE_PATH = TEMPLATE_BASEDIR + "/cd-overview.html.hb"

BLACKLIST = [
    ("0b2e60bb5af556c401c4253e763c13d23e2947be", "1639340737"),
    ("7424ea8c83b86cd7867c0686eaeb2c0285450b12", "1649055686"),
    ("3633026472367a413912bf797490c9336ba762f5", "1650814521"),
    ("8a8bfb26d346a155c7988b2df001f6a665ad6a31", "1648608255"),
    ("b811b070a53962e992781c16d88b1bf90f06e004", "1650507997"),
    ("c27a168344ebc7922c862f21232f62bf9f0d9f75", "1650241110"),
    ("d3ba740100ef275aa5281c584b163d16a9c76c64", "1649858580"),
    ("c610c3fec6ea8acd1b831099317cc0b98fe4b310", "1649613136"),
    ("b0d3c45e14b116f8213ed88dea064fbc631c038c", "1667834847"),
    ("903c8b3a520c69a953b4cdf6468bf2612e86be49", "1660642902"),
]


def convert_date(ts: int):
    # Also works in plotly: https://plotly.com/javascript/time-series/
    return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def ensure_report_generated(githash, timestamp):
    """Atempt to generate report for the given githash and timestamp if not already done."""
    try:
        target_dir = (
            os.path.join(FLAGS.asset_root, githash, timestamp)
            if len(FLAGS.asset_root) > 0
            else os.path.join(FLAGS.experiment_data, githash, timestamp)
        )
        if os.path.isfile(os.path.join(target_dir, "report.html")) and not FLAGS.regenerate:
            print(f"✅ Report exists for {githash}/{timestamp}")
        else:
            print("⚠️  Report does not exists yet, generating")
            if len(FLAGS.asset_root) > 0:
                if not os.path.exists(target_dir):
                    os.makedirs(target_dir)
                cmd = [
                    "python3",
                    "common/generate_report.py",
                    "--git_revision",
                    githash,
                    "--timestamp",
                    timestamp,
                    "--base_dir",
                    FLAGS.experiment_data,
                    "--asset_root",
                    FLAGS.asset_root,
                    "--strict=True",
                ]
                print("Generating external report: ", shlex.join(cmd))
                subprocess.check_output(cmd)
                copy_results(githash, timestamp)
            else:
                subprocess.check_output(
                    [
                        "python3",
                        "common/generate_report.py",
                        "--git_revision",
                        githash,
                        "--timestamp",
                        timestamp,
                        "--base_dir",
                        FLAGS.experiment_data,
                    ]
                )
    except Exception as e:
        print(f"❌ Failed to generate report: {e}")


def copy_results(git_revision: str, timestamp: str):
    if len(FLAGS.asset_root) > 0:

        source_dir = os.path.join(FLAGS.experiment_data, git_revision, timestamp)
        target_dir = os.path.join(FLAGS.asset_root, git_revision, timestamp)

        # Search for svg files in the iteration folders
        for svg in glob.glob(f"{source_dir}/*/*.svg"):
            svg_source_dir = os.path.dirname(svg)
            svg_subdir = os.path.basename(svg_source_dir)
            svg_target_dir = os.path.join(target_dir, svg_subdir)
            if not os.path.exists(svg_target_dir):
                os.mkdir(svg_target_dir)
            shutil.copy(svg, svg_target_dir)


def parse_rps_experiment_with_evaluated_summary(data, githash, timestamp, meta_data, raw_data, f, f_label=None):

    added = False

    base_dir = os.path.join(FLAGS.experiment_data, githash, timestamp)
    assert os.path.exists(base_dir)

    experiment_file = report.parse_experiment_file(data)
    timestamp = experiment_file.t_experiment_start
    xvalue = timestamp

    for iteration, workloads in report.find_experiment_summaries(base_dir).items():

        for workload_id, summary_files in workloads.items():
            # Find xlabel for given iteration
            if f_label is None:
                label = str(workload_id) + " " + str(experiment_file.xlabels[iteration - 1]) + " rps"
            else:
                path = os.path.join(base_dir, str(iteration), "workload_command_summary_map.json")
                if os.path.exists(path):
                    with open(path, "r") as summary_map_f:
                        workload_command_summary_map = json.loads(summary_map_f.read())
                        print(colored(workload_command_summary_map, "blue"))
                        print("SKOUTPUT", colored(data, "blue"))
                        if workload_id not in workload_command_summary_map.keys():
                            print(
                                colored(
                                    f"Cannot find workload {workload_id} in {workload_command_summary_map} for {data}/{githash}",
                                    "red",
                                )
                            )
                            return
                        data = json.loads(workload_command_summary_map[workload_id]["workload_description"])
                        print(colored(data[0], "blue"))
                        print(colored(data[1], "blue"))
                        print(colored(data[3], "blue"))
                        print(colored(data[5], "blue"))
                        label = (
                            ",".join(data[0])
                            + " - "
                            + str(data[1])
                            + " - "
                            + str(data[3])
                            + "rps - payload: "
                            + str(data[5])
                        )

                        # Attempt to replace the canister ID with canister names
                        for canister_name, canister_ids in experiment_file.canister_id.items():
                            for idx, canister_id in enumerate(canister_ids):
                                label = label.replace(canister_id, f"{canister_name}_{idx}")

                        if len(label) > 60:
                            label = label[:58] + ".."

                        print(colored(label, "blue"))
                else:
                    # No workload summary mapping file, so we cannot look up anything useful as label
                    label = f"workload - {workload_id}"

            print(f"Summary files are: {summary_files}")

            evaluated_summaries = report.evaluate_summaries(summary_files)
            yvalue = float(f(evaluated_summaries))

            meta_data.append(
                {
                    "timestamp": timestamp,
                    "date": convert_date(int(timestamp)),
                    "githash": githash,
                    "yvalue": yvalue,
                    "xvalue": xvalue,
                }
            )

            raw_data[label] = raw_data.get(label, []) + [(xvalue, yvalue)]
            added = True

    return added


def parse_rps_experiment_failure_rate(data, githash, timestamp, meta_data, raw_data):
    return parse_rps_experiment_with_evaluated_summary(
        data,
        githash,
        timestamp,
        meta_data,
        raw_data,
        lambda evaluated_summaries: evaluated_summaries.get_median_failure_rate(),
    )


def parse_rps_experiment_latency(data, githash, timestamp, meta_data, raw_data):
    return parse_rps_experiment_with_evaluated_summary(
        data, githash, timestamp, meta_data, raw_data, lambda evaluated_summaries: evaluated_summaries.percentiles[90]
    )


def parse_rps_experiment_max_capacity(data, githash, experiment_timestamp, meta_data, raw_data):
    added = False

    base_dir = os.path.join(FLAGS.experiment_data, githash, experiment_timestamp)
    assert os.path.exists(base_dir)

    experiment_file = report.parse_experiment_file(data, strict=False)
    timestamp = experiment_file.t_experiment_start
    xvalue = timestamp

    MAX_FAILURE_RATE = 0.3
    MAX_LATENCY = 20000

    experiment_details = report.parse_experiment_details_with_fallback_duration(data["experiment_details"])
    experiment_summaries = None
    experiment_summaries = report.find_experiment_summaries(base_dir)

    max_rps_per_workload = report.get_maximum_capacity(
        experiment_summaries, MAX_FAILURE_RATE, MAX_LATENCY, experiment_details.iter_duration
    )

    for idx, max_rps in enumerate(max_rps_per_workload):
        yvalue = max_rps

        if yvalue <= 0:
            continue

        meta_data.append(
            {
                "timestamp": experiment_timestamp,
                "date": convert_date(int(experiment_timestamp)),
                "githash": githash,
                "yvalue": yvalue,
                "xvalue": xvalue,
            }
        )

        label = f"workload {idx}"
        raw_data[label] = raw_data.get(label, []) + [(xvalue, yvalue)]
        added = True

    return added


def parse_xnet_experiment(data, githash, timestamp, meta_data, raw_data):
    xvalue = data["t_experiment_start"]

    yvalue = None
    if "max_capacity" in data["experiment_details"]:
        yvalue = data["experiment_details"]["max_capacity"]
    if "rps_max" in data["experiment_details"]:
        yvalue = float(data["experiment_details"]["rps_max"])

    if yvalue is not None:
        meta_data.append(
            {
                "timestamp": timestamp,
                "date": convert_date(int(timestamp)),
                "githash": githash,
                "yvalue": yvalue,
                "xvalue": xvalue,
            }
        )

        print(
            "  {:40} {:30} {:10.3f}".format(data["experiment_name"], convert_date(data["t_experiment_start"]), yvalue)
        )
        label = None
        raw_data[label] = raw_data.get(label, []) + [(xvalue, yvalue)]
        return True

    else:
        return False


def parse_statesync_experiment(data, githash, timestamp, meta_data, raw_data):
    xvalue = data["t_experiment_start"]
    yvalue = data["experiment_details"]["state_sync_duration"]

    # Some older versions of the experiment data have Prometheus metrics as values,
    # instead of the extracted float value.
    if type(yvalue) is dict:
        if "result" in yvalue:
            yvalue = yvalue["result"][0]["value"][1]
        elif "data" in yvalue:
            yvalue = yvalue["data"]["result"][0]["value"][1]
    yvalue = float(yvalue)

    meta_data.append(
        {
            "timestamp": timestamp,
            "date": convert_date(int(timestamp)),
            "githash": githash,
            "yvalue": yvalue,
            "xvalue": xvalue,
        }
    )

    if yvalue > 0:
        print(
            "  {:40} {:30} {:10.3f}".format(data["experiment_name"], convert_date(data["t_experiment_start"]), yvalue)
        )
        label = False
        raw_data[label] = raw_data.get(label, []) + [(xvalue, yvalue)]
        return True
    else:
        return False


def parse_qr_experiment(data, githash, experiment_timestamp, meta_data, raw_data):
    parse_mixed_workload_experiment(data, githash, experiment_timestamp, meta_data, raw_data, "qr.toml")


def parse_sha256_experiment(data, githash, experiment_timestamp, meta_data, raw_data):
    parse_mixed_workload_experiment(data, githash, experiment_timestamp, meta_data, raw_data, "sha256.toml")


def parse_http_outcall_experiment(data, githash, experiment_timestamp, meta_data, raw_data):
    parse_mixed_workload_experiment(
        data, githash, experiment_timestamp, meta_data, raw_data, "canister-http-benchmark.toml"
    )


def parse_mixed_counter_experiment(data, githash, experiment_timestamp, meta_data, raw_data):
    parse_mixed_workload_experiment(data, githash, experiment_timestamp, meta_data, raw_data, "mixed-query-update.toml")


def parse_mixed_workload_experiment(data, githash, experiment_timestamp, meta_data, raw_data, workload_file):
    """Parse a mixed workload experiment."""
    base_dir = os.path.join(FLAGS.experiment_data, githash, experiment_timestamp)
    print(colored(f"Parsing: {base_dir}", "grey", attrs=["bold"]))
    assert os.path.exists(base_dir)

    experiment_file = report.parse_experiment_file(data)
    if os.path.join("workloads", workload_file) in experiment_file.command_line:

        try:
            return parse_rps_experiment_with_evaluated_summary(
                data,
                githash,
                experiment_timestamp,
                meta_data,
                raw_data,
                lambda evaluated_summaries: evaluated_summaries.get_median_failure_rate(),
                f_label=42,  # Replace with actual function later
            )
        except (report.WorkloadGeneratorSummaryUnmatched, FileNotFoundError):
            print(colored(traceback.format_exc(), "red"))

    return False


@dataclass
class ExperimentResultDirectory:
    """Represents a search result for find_results."""

    result_file_path: str
    result_file_content: report.ExperimentFile
    githash: str
    timestamp: str


def find_results(
    experiment_names: [str],
    experiment_type: [str],
    testnet: str,
    time_start: int,
):
    """Find experiment results matching the given data and return a list of results."""
    results = []
    for result in glob.glob(f"{FLAGS.experiment_data}/*/*/experiment.json"):
        with open(result) as resultfile:
            try:
                data = json.loads(resultfile.read())
                # Match testnet name, experiment name and experiment type in order to decide whether to include results
                if data["testnet"] == testnet and data["type"] in experiment_type:

                    include = False
                    for experiment in experiment_names:
                        include = include or data["experiment_name"] == experiment
                    if not include:
                        continue

                    githash, timestamp, _ = tuple(result.split("/")[-3:])
                    if (time_start is None or int(data["t_experiment_start"]) > time_start) and (
                        githash,
                        timestamp,
                    ) not in BLACKLIST:

                        report_file = report.parse_experiment_file(data, strict=False)
                        results.append(ExperimentResultDirectory(result, report_file, githash, timestamp))

            except ValueError as e:  # Replace with proper exception
                print(traceback.format_exc())
                print(f"Failed to check {result} - error: {e}")

    return results


def render_results(
    experiment_names,
    experiment_type,
    parser,
    threshold: [str],
    testnet="cdslo",
    time_start=None,
    yaxis_title="maximum rate [requests / s]",
):
    """Find and collect data from all experiments for the given testnet and experiment type."""
    meta_data = []
    raw_data = {}

    for result in find_results(experiment_names, experiment_type, testnet, time_start):

        resultfile = result.result_file_path
        githash = result.githash
        timestamp = result.timestamp
        data = json.loads(open(resultfile).read())

        print("Result file content: ", result.result_file_content)

        if parser(data, githash, timestamp, meta_data, raw_data):
            ensure_report_generated(githash, timestamp)

    if len(raw_data) < 1:
        raise Exception(f"Could not find any data for: {testnet} {experiment_names} {experiment_type}")

    meta_data = sorted(meta_data, key=lambda x: x["timestamp"])

    all_xdata = []
    all_ydata = []

    plots = []

    for label, data in raw_data.items():
        data = sorted(data)
        xdata = [e[0] for e in data]
        ydata = [e[1] for e in data]

        all_xdata += xdata
        all_ydata += ydata

        plots.append(
            {
                "x": [convert_date(e) for e in xdata],
                "y": ydata,
                "name": str(label),
            }
        )

    if threshold is not None:
        layout = {
            "yaxis": {"title": yaxis_title, "range": [0, 1.2 * max(all_ydata)]},
            "xaxis": {"title": "benchmark execution date [s]"},
            "shapes": [
                {
                    "type": "line",
                    "x0": convert_date(min(all_xdata)),
                    "y0": threshold,
                    "x1": convert_date(max(all_xdata)),
                    "y1": threshold,
                    "line": {
                        "color": "red",
                    },
                }
            ],
        }
    else:
        layout = {}

    return {"plot": plots, "layout": layout, "data": meta_data}


if __name__ == "__main__":

    misc.load_artifacts("../artifacts/release")
    misc.parse_command_line_args()

    with open(TEMPLATE_PATH, mode="r") as f:
        compiler = pybars.Compiler()
        source = f.read()
        template = compiler.compile(source)

        data = {
            "last_generated": int(time.time()),
        }

        data["plot_exp1_query"] = render_results(
            ["experiment_1", "run_system_baseline_experiment", "system-baseline-experiment"],
            ["query"],
            parse_rps_experiment_max_capacity,
            4000,
        )
        data["plot_exp1_update"] = render_results(
            ["experiment_1", "run_system_baseline_experiment", "system-baseline-experiment"],
            ["update"],
            parse_rps_experiment_max_capacity,
            800,
        )

        data["plot_exp2_update"] = render_results(
            ["experiment_2", "run_large_memory_experiment"],
            ["update", "update_copy"],
            parse_rps_experiment_max_capacity,
            20,
            time_start=1639939557,
        )

        data["plot_statesync"] = render_results(
            ["run_statesync_experiment"],
            ["query"],
            parse_statesync_experiment,
            2.2,
            yaxis_title="State Sync duration [s]",
        )

        data["plot_xnet"] = render_results(["run_xnet_experiment"], ["query"], parse_xnet_experiment, 5500)

        data["plot_qr"] = render_results(
            ["run_mixed_workload_experiment"],
            ["mixed"],
            parse_qr_experiment,
            None,
            yaxis_title="Failure rate",
        )

        data["plot_sha256"] = render_results(
            ["run_mixed_workload_experiment"],
            ["mixed"],
            parse_sha256_experiment,
            None,
            yaxis_title="Failure rate",
        )

        data["plot_http_outcall"] = render_results(
            ["run_mixed_workload_experiment"],
            ["mixed"],
            parse_http_outcall_experiment,
            None,
            yaxis_title="Failure rate",
        )

        data["plot_mixed_counter"] = render_results(
            ["run_mixed_workload_experiment"],
            ["mixed"],
            parse_mixed_counter_experiment,
            None,
            yaxis_title="Failure rate",
        )

        # Render the internal CD overview
        with open(f"{FLAGS.experiment_data}/cd-overview.html", "w") as outfile:
            data.update(
                {
                    "is_external": False,
                }
            )
            outfile.write(template(data))
            print("🎉 Report written")

        # Render the exeternal CD overview
        if len(FLAGS.asset_root) > 0:
            with open(f"{FLAGS.asset_root}/index.html", "w") as outfile:
                data.update(
                    {
                        "is_external": True,
                    }
                )
                outfile.write(template(data))
                print("🎉 Report written")

        LOGO = "fully_on_chain-default-bg_dark.svg"
        shutil.copy(os.path.join(TEMPLATE_BASEDIR, LOGO), FLAGS.experiment_data)
        if len(FLAGS.asset_root) > 0:
            shutil.copy(os.path.join(TEMPLATE_BASEDIR, LOGO), FLAGS.asset_root)
