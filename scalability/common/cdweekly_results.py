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
import requests

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


WATTS_PER_NODE = 700
MAINNET_CURR_TRANSACTION_RATE = 3300  # per second
# Total facility enery (incl compute + cooling) / IT equipment energy (only compute)
# https://en.wikipedia.org/wiki/Power_usage_effectiveness
PUE = 2.33


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


def parse_rps_experiment_with_evaluated_summary(data, githash, timestamp, meta_data, raw_data, f):

    added = False

    base_dir = os.path.join(FLAGS.experiment_data, githash, timestamp)
    assert os.path.exists(base_dir)

    experiment_file = report.parse_experiment_file(data)
    timestamp = experiment_file.t_experiment_start
    xvalue = timestamp

    for iteration, workloads in report.find_experiment_summaries(base_dir).items():

        for workload_id, summary_files in workloads.items():
            # Find xlabel for given iteration
            label = str(workload_id) + " " + str(experiment_file.xlabels[iteration - 1]) + " rps"
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


def parse_rps_experiment_max_capacity(data, githash, timestamp, meta_data, raw_data):
    added = False

    base_dir = os.path.join(FLAGS.experiment_data, githash, timestamp)
    assert os.path.exists(base_dir)

    experiment_file = report.parse_experiment_file(data)
    timestamp = experiment_file.t_experiment_start
    xvalue = timestamp

    MAX_FAILURE_RATE = 0.3
    MAX_LATENCY = 20000

    experiment_details = report.parse_experiment_details_with_fallback_duration(data["experiment_details"])
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
                "timestamp": timestamp,
                "date": convert_date(int(timestamp)),
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

                        report_file = report.parse_experiment_file(data)
                        results.append(ExperimentResultDirectory(result, report_file, githash, timestamp))

            except Exception as e:
                print(traceback.format_exc())
                print(f"Failed to check ${result} - error: {e}")

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

        # if githash != "9008471a1b2d3447129c348fc42fb1e2c13aa2a3" and timestamp != "1669773930":
        #     continue

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

    return {"plot": plots, "layout": layout, "data": meta_data}


def get_application_subnets():
    req = requests.get("https://ic-api.internetcomputer.org/api/v3/subnets")
    num_application_subnets = 0
    num_application_nodes = 0
    for subnet in req.json()["subnets"]:
        if subnet["subnet_type_name"] != "system":
            subnet_id = subnet["subnet_id"]
            num_application_subnets += 1
            r = requests.get(
                "https://ic-api.internetcomputer.org/api/v3/nodes", params={"include_status": "UP", "subnet": subnet_id}
            )
            num_application_nodes += len(r.json()["nodes"])

    return (num_application_subnets, num_application_nodes)


def get_num_nodes_mainnet():

    req = requests.get("https://ic-api.internetcomputer.org/api/metrics/ic-subnet-total")
    num_subnets = int(req.json()["ic_subnet_total"][1])

    req = requests.get("https://ic-api.internetcomputer.org/api/metrics/ic-nodes-count")
    num_nodes = int(req.json()["ic_nodes_count"][0][1])

    num_application_subnets, num_application_nodes = get_application_subnets()
    return (num_nodes, num_subnets, num_application_nodes, num_application_subnets)


def get_num_boundary_nodes():
    req = requests.get("https://ic-api.internetcomputer.org/api/metrics/boundary-nodes-count")
    return int(req.json()["boundary_nodes_count"][1])


if __name__ == "__main__":

    misc.load_artifacts("../artifacts/release")
    misc.parse_command_line_args()
    num_nodes, num_subnets, num_app_nodes, num_app_subnets = get_num_nodes_mainnet()
    num_boundary_nodes = get_num_boundary_nodes()
    num_boundary_nodes = int(num_boundary_nodes)
    print("Boundary nodes: ", num_boundary_nodes)

    with open(TEMPLATE_PATH, mode="r") as f:
        compiler = pybars.Compiler()
        source = f.read()
        template = compiler.compile(source)

        data = {
            "num_subnets": num_subnets,
            "num_nodes": num_nodes,
            "num_app_subnets": num_app_subnets,
            "num_app_nodes": num_app_nodes,
            "num_boundary_nodes": num_boundary_nodes,
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
