#!/bin/python
import glob
import json
import os
import subprocess
import sys
import time
from datetime import datetime

import pybars

TEMPLATE_PATH = "templates/cd-overview.html.hb"


def convert_date(ts: int):
    # Also works in plotly: https://plotly.com/javascript/time-series/
    return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def find_results(experiment_names, experiment_type, threshold, testnet="cdslo", time_start=None):
    """Find and collect data from all experiments for the given testnet and experiment type."""
    meta_data = []
    raw_data = []
    # Find all experiments
    for result in glob.glob("*/*/experiment.json"):
        with open(result) as resultfile:
            try:
                data = json.loads(resultfile.read())
                # Match testnet name, experiment name and experiment type in order to decide whether to include results
                if data["testnet"] == testnet and data["type"] == experiment_type:

                    include = False
                    for experiment in experiment_names:
                        include = include or data["experiment_name"] == experiment
                    if not include:
                        continue

                    if time_start is None or int(data["t_experiment_start"]) > time_start:
                        githash, timestamp, _ = tuple(result.split("/"))
                        meta_data.append(
                            {"timestamp": timestamp, "date": convert_date(int(timestamp)), "githash": githash}
                        )

                        print(result)
                        print(
                            "  {:40} {:30} {:10.3f}".format(
                                data["experiment_name"],
                                convert_date(data["t_experiment_start"]),
                                float(data["experiment_details"]["rps_max"]),
                            )
                        )
                        raw_data.append((data["t_experiment_start"], data["experiment_details"]["rps_max"]))

                        try:
                            if os.path.isfile(f"{githash}/{timestamp}/report.html"):
                                print("✅ Report exists")
                            else:
                                print("⚠️  Report does not exists yet, generating")
                                subprocess.check_output(["python3", "generate_report.py", githash, timestamp])
                        except Exception as e:
                            print(f"❌ Failed to generate report: {e}")

            except Exception as e:
                print(f"Failed to check ${result} - error: {e}")

    if len(raw_data) < 1:
        raise Exception(f"Could not find any data for: {testnet} {experiment_names} {experiment_type}")

    raw_data = sorted(raw_data)
    meta_data = sorted(meta_data, key=lambda x: x["timestamp"])

    xdata = [e[0] for e in raw_data]
    ydata = [e[1] for e in raw_data]

    plots = [
        {
            "x": [convert_date(e) for e in xdata],
            "y": ydata,
        }
    ]

    layout = {
        "yaxis": {"title": "maximum rate [requests / s]", "range": [0, 1.2 * max(ydata)]},
        "xaxis": {"title": "benchmark execution date [s]"},
        "shapes": [
            {
                "type": "line",
                "x0": convert_date(min(xdata)),
                "y0": threshold,
                "x1": convert_date(max(xdata)),
                "y1": threshold,
                "line": {
                    "color": "red",
                },
            }
        ],
    }

    return {"plot": plots, "layout": layout, "data": meta_data}


def get_num_nodes_mainnet():

    sys.path.insert(1, ".")
    from common.base_experiment import BaseExperiment

    nns_url = BaseExperiment.get_mainnet_nns_url()

    # Maybe deduplicate with experiment.py
    res = subprocess.check_output(
        ["../artifacts/release/ic-admin", "--nns-url", f"http://[{nns_url}]:8080", "get-topology"],
        encoding="utf-8",
    )

    return parse_topo(res)


def parse_topo(data):

    data = json.loads(data)

    subnets = data["topology"]["subnets"]
    num_subnets = len(subnets)

    num_nodes_per_subnet = [len(v["records"][0]["value"]["membership"]) for (_, v) in subnets.items()]
    num_nodes = sum(num_nodes_per_subnet)

    return (num_nodes, num_subnets)


if __name__ == "__main__":

    num_nodes, num_subnets = get_num_nodes_mainnet()
    with open(TEMPLATE_PATH, mode="r") as f:
        compiler = pybars.Compiler()
        source = f.read()
        template = compiler.compile(source)

        data = {
            "num_subnets": num_subnets,
            "num_nodes": num_nodes,
            "last_generated": int(time.time()),
        }

        print("Experiment 1")
        data["plot_exp1_query"] = find_results(
            ["experiment_1", "run_system_baseline_experiment", "system-baseline-experiment"], "query", 2800
        )
        data["plot_exp1_query"]["layout"].update(
            {
                "annotations": [
                    {
                        "x": convert_date(1639340737),
                        "y": "1750.0",
                        "xref": "x",
                        "yref": "y",
                        "text": "workload generator http1 only",
                        "textangle": "-60",
                        "showarrow": "true",
                        "arrowhead": 7,
                        "ax": 0,
                        "ay": -40,
                    },
                    {
                        "x": convert_date(1642271520),
                        "y": "4000.0",
                        "xref": "x",
                        "yref": "y",
                        "text": "likely EXC-832",
                        "textangle": "-60",
                        "showarrow": "true",
                        "arrowhead": 7,
                        "ax": 0,
                        "ay": -40,
                    },
                ]
            }
        )
        data["plot_exp1_update"] = find_results(
            ["experiment_1", "run_system_baseline_experiment", "system-baseline-experiment"], "update", 500
        )

        # Calculate theoretical stats from latest system overhead experiments
        latest_query_performance = data["plot_exp1_query"]["plot"][0]["y"][-1]
        latest_update_performance = data["plot_exp1_update"]["plot"][0]["y"][-1]
        print("query", data["plot_exp1_query"]["plot"][0]["y"], latest_query_performance)
        print("update", latest_update_performance)
        data["latest_approx_mainnet_update_performance"] = "{:.0f}".format(num_subnets * latest_update_performance)
        data["latest_approx_mainnet_query_performance"] = "{:.0f}".format(num_nodes * latest_query_performance)

        print("Experiment 2")
        data["plot_exp2_update"] = find_results(
            ["experiment_2", "run_large_memory_experiment"], "update", 20, time_start=1639939557
        )
        # data["plot_exp2_update"]["layout"].update(
        #     {
        #         "annotations": [
        #             {
        #                 "x": convert_date(1639939504),
        #                 "y": "175.0",
        #                 "xref": "x",
        #                 "yref": "y",
        #                 "text": "Up until here, running as query",
        #                 "textangle": "-60",
        #                 "showarrow": "true",
        #                 "arrowhead": 7,
        #                 "ax": 0,
        #                 "ay": -40,
        #             }
        #         ]
        #     }
        # )
        data["plot_exp2_query"] = find_results(["experiment_2", "run_large_memory_experiment"], "query", 150)
        print(data)

        with open("cd-overview.html", "w") as outfile:
            outfile.write(template(data))
            print("🎉 Report written")
