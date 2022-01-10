#!/usr/bin/env python3
import json
import os
import sys

import pybars
import report


def add_file(base, path, alt):
    content = ""
    try:
        for p in path:
            content += open(os.path.join(base, p)).read()
    except Exception:
        content += alt

    return content


def generate_report(githash, timestamp):
    """Generate report for the given measurement."""
    source = open("templates/experiment.html.hb", mode="r").read()
    data = {
        "iterations": [],
        "timestamp": timestamp,
        "githash": githash,
    }

    base = "{}/{}".format(githash, timestamp)
    report_file = os.path.join(base, "report.html")
    http_request_duration = []
    wg_http_latency = []
    wg_failure_rate = []

    with open(report_file, "w") as outfile:
        for i in sorted([int(i) for i in os.listdir(base) if i.isnumeric()]):
            path = os.path.join(base, str(i))
            if os.path.isdir(path):
                iter_data = {}
                print("Found measurement iteration {} in {}".format(i, path))

                # Workload generator summaries
                files = [os.path.join(path, f) for f in os.listdir(path) if f.startswith("summary_machine_")]
                print("Files: ", files)
                if len(files) > 0:
                    (failure_rate, t_median, t_average, t_max, t_min, total_requests, _, _) = report.evaluate_summaries(
                        files
                    )

                    compiler = pybars.Compiler()
                    template = compiler.compile(source)

                    iter_data.update(
                        {
                            "header": i,
                            "failure_rate": "{:.2f}".format(failure_rate * 100),
                            "failure_rate_color": "green" if failure_rate < 0.01 else "red",
                            "t_median": "{:.2f}".format(t_median),
                            "t_average": "{:.2f}".format(t_average),
                            "t_max": "{:.2f}".format(t_max),
                            "t_min": "{:.2f}".format(t_min),
                            "total_requests": total_requests,
                        }
                    )

                    wg_http_latency.append(t_median)
                    wg_failure_rate.append(failure_rate * 100)

                # Search for flamegraph
                flamegraph = [os.path.join(str(i), f) for f in os.listdir(path) if f.startswith("flamegraph_")]
                print("Flamegraph is: ", flamegraph)
                if len(flamegraph) > 0:
                    iter_data.update({"flamegraph": flamegraph[0]})

                wg_commands = ""
                i = 0
                run = True
                while run:
                    i += 1
                    try:
                        with open(os.path.join(path, f"workload-generator-cmd-{i}")) as wg_cmd_file:
                            wg_commands += wg_cmd_file.read() + "\n"
                    except Exception:
                        run = False
                        iter_data["wg_commands"] = [
                            "./ic-workload-generator {}".format(c)
                            for c in wg_commands.split("./ic-workload-generator")
                            if len(c.strip()) > 0
                        ]

                # Iteration configuration
                load_total = None
                try:
                    with open(os.path.join(path, "iteration.json")) as iteration_conf:
                        iter_data["configuration"] = json.loads(iteration_conf.read())
                        load_total = iter_data["configuration"]["configuration"]["load_total"]

                except Exception as err:
                    print("Failed to parse iteration.json file for iteration {} - {}".format(i, err))

                # Prometheus report
                try:
                    with open(os.path.join(path, "prometheus.json")) as prometheus_metrics:
                        metrics = json.loads(prometheus_metrics.read())
                        try:
                            http_request_duration.append(metrics["http_request_duration"][0])
                        except Exception as err:
                            print(
                                f"Failed to determine HTTP request duration for iteration {i} in file {path}/prometheus.json - {err}"
                            )

                        t_start = int(metrics["http_request_rate"][0][0][0])
                        xdata = [int(x) - t_start for x, _ in metrics["http_request_rate"][0]]
                        ydata = [float(y) for _, y in metrics["http_request_rate"][0]]

                        plots = [
                            {
                                "x": xdata,
                                "y": ydata,
                            }
                        ]
                        layout = {
                            "yaxis": {"title": "rate [requests / s]", "range": [0, 1.2 * max(ydata)]},
                            "xaxis": {"title": "iteration time [s]"},
                        }

                        if load_total is not None:
                            layout["shapes"] = [
                                {
                                    "type": "line",
                                    "x0": min(xdata),
                                    "y0": load_total,
                                    "x1": max(xdata),
                                    "y1": load_total,
                                    "line": {
                                        "color": "red",
                                    },
                                }
                            ]

                        metrics.update(
                            {
                                "http_request_rate_plot": plots,
                                "http_request_rate_layout": layout,
                            }
                        )
                        iter_data.update({"prometheus": metrics})

                except Exception as err:
                    print(f"Failed to parse prometheus.json file for iteration {i} - {err}")

                data["iterations"].append(iter_data)

        # Experiment details
        try:
            with open(os.path.join(base, "experiment.json")) as experiment_info:
                experiment = json.loads(experiment_info.read())
                data.update({"experiment": experiment})
        except Exception:
            print("Failed to parse experiment.json file")
            exit(1)

        experiment_name = data["experiment"]["experiment_name"]
        experiment_template_file = "templates/{}.html.hb".format(experiment_name)
        print("Experiment template file is: {}".format(experiment_template_file))
        experiment_source = open(experiment_template_file, mode="r").read()

        experiment_template = compiler.compile(experiment_source)
        experiment_data = data["experiment"]
        experiment_data["experiment_details"]["rps_max"] = (
            "{:.1f}".format(experiment_data["experiment_details"]["rps_max"])
            if "rps_max" in experiment_data["experiment_details"]
            else "n.a."
        )

        print("Rendering experiment details with: ", experiment_data)
        experiment_details = experiment_template(experiment_data)

        data.update(
            {
                "experiment-details": experiment_details,
                "plot-http-latency": [{"y": [e[1] for e in http_request_duration], "x": data["experiment"]["xlabels"]}],
                "plot-wg-http-latency": [{"y": wg_http_latency, "x": data["experiment"]["xlabels"]}],
                "plot-wg-failure-rate": [{"y": wg_failure_rate, "x": data["experiment"]["xlabels"]}],
                "layout-http-latency": {
                    "yaxis": {"title": "latency [ms]"},
                    "xaxis": {"title": data["experiment"]["xtitle"]},
                },
                "layout-wg-http-latency": {
                    "yaxis": {"title": "latency [ms]"},
                    "xaxis": {"title": data["experiment"]["xtitle"]},
                },
                "layout-wg-failure-rate": {
                    "yaxis": {"title": "failure rate [%]"},
                    "xaxis": {"title": data["experiment"]["xtitle"]},
                },
            }
        )

        data["lscpu"] = add_file(f"{githash}/{timestamp}", ["lscpu.stdout.txt"], "lscpu data missing")

        data["free"] = add_file(f"{githash}/{timestamp}", ["free.stdout.txt"], "free data missing")

        data["subnet_info"] = add_file(f"{githash}/{timestamp}", ["subnet_info.json"], "subnet info data missing")

        data["topology"] = add_file(f"{githash}/{timestamp}", ["topology.json"], "topology data missing")

        output = template(data)
        outfile.write(output)

    print("Report is at file://{}/{}".format(os.getcwd(), report_file))


if __name__ == "__main__":
    generate_report(sys.argv[1], sys.argv[2])
