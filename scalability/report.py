import json

from termcolor import colored


def evaluate_summaries(summaries):
    """Evaluate a list of workload generator summary files."""
    result = {}
    t_median = []
    t_max = []
    t_min = []
    t_average = []
    num_machines = 0
    for summary in summaries:
        try:
            with open(summary, "r") as infile:
                print("Evaluating summary file: ", summary)
                num_machines += 1
                data = json.load(infile)

                # Print content of file
                # print(json.dumps(data, indent=2, sort_keys=True))

                for (c, number) in data[0]["status_counts"].items():
                    code = int(c)
                    if code not in result:
                        result[code] = 0
                    result[code] += number

                t_median.append(convert_time_from_summary(data[0]["median"]))
                t_max.append(convert_time_from_summary(data[0]["max"]))
                t_min.append(convert_time_from_summary(data[0]["min"]))
                t_average.append(convert_time_from_summary(data[0]["average"]))
        except Exception:
            print("⚠️  Failed to read one summary file from workload gnerators, continuing ..")

    total_number = 0
    success = {True: 0, False: 0}
    for (code, number) in result.items():
        success[is_success(code)] += number
        total_number += number
        print(colored("{} - {} - {}".format(code, is_success(code), number), "green" if is_success(code) else "red"))

    failure_rate = success[False] / (success[True] + success[False])
    return (
        failure_rate,
        max(t_median),
        max(t_average),
        max(t_max),
        min(t_min),
        total_number,
        success[True],
        success[False],
    )


def convert_time_from_summary(time):
    """Convert time from workload generator summary."""
    return time["secs"] * 1000.0 + time["nanos"] / 1000.0 / 1000.0


def is_success(code):
    """List of status codes considered to be successful."""
    okay = [200, 202]
    return code in okay
