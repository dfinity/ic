import json

from misc import mean_or_minus_one
from termcolor import colored


def convert_duration(data: dict):
    """
    Convert the given duration.

    Format has to be a dictionary with "nanos" and "secs".
    """
    last = None
    times = []
    for d in data:
        t_ms = d["secs"] * 1000 + d["nanos"] / 1000.0 / 1000.0
        times.append(t_ms)
        assert last is None or t_ms >= last
        last = t_ms
    return times


class EvaluatedSummaries:
    """Wrapper for storing results from evaluate_summaries."""

    def __init__(
        self,
        failure_rate,
        failure_rates,
        t_median,
        t_average,
        t_max,
        t_min,
        percentiles,
        total_number,
        num_success,
        num_fail,
    ):
        """Store evaluated summary data."""
        self.failure_rate = failure_rate
        self.failure_rates = failure_rates
        self.t_median = t_median
        self.t_average = t_average
        self.t_max = t_max
        self.t_min = t_min
        self.percentiles = percentiles
        self.total_number = total_number
        self.num_success = num_success
        self.num_fail = num_fail

    def convert_tuple(self):
        """Mostly used for backward compatibility."""
        return (
            self.failure_rate,
            self.t_median,
            self.t_average,
            self.t_max,
            self.t_min,
            self.percentiles,
            self.total_number,
            self.num_success,
            self.num_fail,
        )


def evaluate_summaries(summaries):
    """Evaluate a list of workload generator summary files."""
    result = {}
    t_median = []
    t_max = []
    t_min = []
    t_average = []
    t_percentile = []
    failure_rates = []

    num_machines = 0
    for summary in summaries:
        try:
            with open(summary, "r") as infile:
                print("Evaluating summary file: ", summary)
                num_machines += 1
                data = json.load(infile)

                # Print content of file
                # print(json.dumps(data, indent=2, sort_keys=True))

                num_succ = 0
                num_fail = 0

                for (c, number) in data[0]["status_counts"].items():
                    code = int(c)
                    if code not in result:
                        result[code] = 0
                    result[code] += number

                    if is_success(code):
                        num_succ += number
                    else:
                        num_fail += number

                t_percentile.append(convert_duration(data[0]["percentiles"]))

                t_median.append(convert_time_from_summary(data[0]["median"]))
                t_max.append(convert_time_from_summary(data[0]["max"]))
                t_min.append(convert_time_from_summary(data[0]["min"]))
                t_average.append(convert_time_from_summary(data[0]["average"]))
                failure_rates.append(num_fail / (num_succ + num_fail) if (num_succ + num_fail) > 0 else -1)
        except Exception as e:
            print("⚠️  Failed to read one summary file from workload gnerators, continuing ..")
            print(e)

    total_number = 0
    success = {True: 0, False: 0}
    for (code, number) in result.items():
        success[is_success(code)] += number
        total_number += number
        print(colored("{} - {} - {}".format(code, is_success(code), number), "green" if is_success(code) else "red"))

    percentiles = [mean_or_minus_one([x[p] for x in t_percentile]) for p in range(0, 100)]

    failure_rate = success[False] / (success[True] + success[False])
    return EvaluatedSummaries(
        failure_rate,
        failure_rates,
        t_median,
        t_average,
        t_max,
        t_min,
        percentiles,
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
