#!/usr/bin/env python3
import json
import os
import sys
import traceback

import ansible
import pybars
import report


def add_plot(name: str, xlabel: str, ylabel: str, x: [str], plots: [([str], str)]):
    """Return a dictionary representing the given plot for templating.."""
    return {
        f"plot-{name}": [{"y": y, "x": x, "name": name} for (y, name) in plots],
        f"layout-{name}": {
            "yaxis": {
                "title": ylabel,
                "rangemode": "tozero",
                "autorange": "true",
            },
            "xaxis": {"title": xlabel},
        },
    }


def resolve_ip_addresses(ips: [str], testnet: str):
    load_generators = []
    country = {
        "fr": "🇩🇪",
        "sf": "🇺🇸",
    }
    print(ips)
    try:
        for machine in ips:
            host = ansible.get_host_for_ip(testnet, machine)
            if host:
                host_prefix = host[:2]
                load_generators.append(
                    {"name": machine, "host": host, "country": country[host_prefix] if host_prefix in country else ""}
                )
            else:
                load_generators.append({"name": machine, "host": "n.a.", "country": "n.a."})
    except Exception:
        traceback.print_exc()
    return load_generators


def add_file(base, path, alt):
    content = ""
    try:
        for p in path:
            content += open(os.path.join(base, p)).read()
    except Exception:
        content += alt

    return content


def generate_report(base, githash, timestamp):
    """Generate report for the given measurement."""
    source = open("templates/experiment.html.hb", mode="r").read()
    data = {
        "iterations": [],
        "timestamp": timestamp,
        "githash": githash,
    }

    report_file = os.path.join(base, "report.html")
    http_request_duration = []
    wg_http_latency = []
    wg_http_latency_99 = []
    wg_failure_rate = []

    compiler = pybars.Compiler()
    template = compiler.compile(source)

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
                    (
                        failure_rate,
                        t_median,
                        t_average,
                        t_max,
                        t_min,
                        t_percentile,
                        total_requests,
                        _,
                        _,
                    ) = report.evaluate_summaries(files)

                    from statistics import mean

                    t_median_agg = mean(t_median)
                    t_average_agg = max(t_average)
                    t_max_agg = max(t_max)
                    t_min_agg = max(t_min)

                    iter_data.update(
                        {
                            "header": i,
                            "failure_rate": "{:.2f}".format(failure_rate * 100),
                            "failure_rate_color": "green" if failure_rate < 0.01 else "red",
                            "t_median": "{:.2f}".format(t_median_agg),
                            "t_average": "{:.2f}".format(t_average_agg),
                            "t_99": "{:.2f}".format(t_percentile[99]),
                            "t_95": "{:.2f}".format(t_percentile[95]),
                            "t_90": "{:.2f}".format(t_percentile[90]),
                            "t_max": "{:.2f}".format(t_max_agg),
                            "t_min": "{:.2f}".format(t_min_agg),
                            "total_requests": total_requests,
                        }
                    )

                    wg_http_latency.append(t_median)
                    wg_http_latency_99.append(t_percentile[99])
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

        data["experiment"]["load_generator_machines"] = resolve_ip_addresses(
            data["experiment"]["load_generator_machines"], data["experiment"]["wg_testnet"]
        )
        data["experiment"]["target_machines"] = resolve_ip_addresses(
            data["experiment"]["target_machines"], data["experiment"]["wg_testnet"]
        )

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
            }
        )

        exp = data["experiment"]
        plots = [(http_request_duration, "http duration")]
        data.update(add_plot("http-latency", exp["xtitle"], "latency [s]", exp["xlabels"], plots))

        plots = [(wg_failure_rate, "failure rate")]
        data.update(add_plot("wg-failure-rate", exp["xtitle"], "failure rate [%]", exp["xlabels"], plots))

        plots = []
        if len(wg_http_latency) > 0:
            num_results = len(wg_http_latency[0])
            for workload_generator_id in range(num_results):
                plots.append(
                    (
                        [x[workload_generator_id] for x in wg_http_latency],
                        f"median workload gen #{workload_generator_id}",
                    )
                )

        plots.append((wg_http_latency_99, "mean 99th percentile"))
        data.update(add_plot("wg-http-latency", exp["xtitle"], "latency [ms]", exp["xlabels"], plots))

        dirname = f"{githash}/{timestamp}"
        data["lscpu"] = add_file(dirname, ["lscpu.stdout.txt"], "lscpu data missing")
        data["free"] = add_file(dirname, ["free.stdout.txt"], "free data missing")
        data["subnet_info"] = add_file(dirname, ["subnet_info.json"], "subnet info data missing")
        data["topology"] = add_file(dirname, ["topology.json"], "topology data missing")

        output = template(data)
        outfile.write(output)

    print("Report is at file://{}/{}".format(os.getcwd(), report_file))


if __name__ == "__main__":
    base = sys.argv[3] if len(sys.argv) > 3 else os.path.join(sys.argv[1], sys.argv[2])
    generate_report(base, sys.argv[1], sys.argv[2])
