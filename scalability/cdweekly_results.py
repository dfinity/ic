#!/bin/python
import glob
import json
from datetime import datetime

import pybars

TEMPLATE_PATH = "templates/cd-overview.html.hb"


def convert_date(ts):
    # Also works in plotly: https://plotly.com/javascript/time-series/
    return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def find_results(experiment_name, experiment_type, threshold, testnet="cdslo"):
    """Find and collect data from all experiments for the given testnet and experiment type."""
    raw_data = []
    # Find all experiments
    for result in glob.glob("*/*/experiment.json"):
        with open(result) as resultfile:
            try:
                data = json.loads(resultfile.read())
                # Match testnet name, experiment name and experiment type in order to decide whether to include results
                if (
                    data["testnet"] == testnet
                    and data["experiment_name"] == experiment_name
                    and data["type"] == experiment_type
                ):
                    print(result)
                    print(
                        "  {:40} {:30} {:10.3f}".format(
                            data["experiment_name"],
                            convert_date(data["t_experiment_start"]),
                            float(data["experiment_details"]["rps_max"]),
                        )
                    )
                    raw_data.append((data["t_experiment_start"], data["experiment_details"]["rps_max"]))
            except Exception as e:
                print(f"Failed to check ${resultfile} - error: {e}")

    if len(raw_data) < 1:
        raise Exception(f"Could not find any data for: {testnet} {experiment_name} {experiment_type}")

    raw_data = sorted(raw_data)

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

    return {"plot": plots, "layout": layout}


if __name__ == "__main__":

    with open(TEMPLATE_PATH, mode="r") as f:
        compiler = pybars.Compiler()
        source = f.read()
        template = compiler.compile(source)

        data = {}

        print("Experiment 1")
        data["plot_exp1_query"] = find_results("experiment_1", "query", 1300)
        data["plot_exp1_update"] = find_results("experiment_1", "update", 500)

        print("Experiment 2")
        data["plot_exp2_query"] = find_results("experiment_2", "query", 100)
        data["plot_exp2_update"] = find_results("experiment_2", "update", 100)

        print(data)

        with open("cd-overview.html", "w") as outfile:
            outfile.write(template(data))
