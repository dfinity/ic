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
        succ_rate_histograms,
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
        self.succ_rate_histograms = succ_rate_histograms

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

    def get_success_rate_histograms(self):
        # Aggregate historgram of successful requests
        import itertools

        aggregated_rates = {}
        succ_rate_histogram_keys = set(itertools.chain.from_iterable(self.succ_rate_histograms))
        for key in succ_rate_histogram_keys:
            key_as_int = int(key)
            aggregated_rates[key_as_int] = 0
            for succ_rate_histogram in self.succ_rate_histograms:
                if key in succ_rate_histogram:
                    aggregated_rates[key_as_int] += succ_rate_histogram[key]

        sorted_histograms = sorted([(k, v) for (k, v) in aggregated_rates.items()])
        return sorted_histograms

    def get_avg_success_rate(self, duration):
        """Return the average rate of successful requests for the given duration."""
        sorted_histogram = self.get_success_rate_histograms()
        filtered = list(filter(lambda i: i[0] < duration, sorted_histogram))
        rate = float(sum([v for (k, v) in filtered])) / duration
        return rate


def evaluate_summaries(summaries):
    """Evaluate a list of workload generator summary files."""
    result = {}
    t_median = []
    t_max = []
    t_min = []
    t_average = []
    t_percentile = []
    failure_rates = []
    succ_rate_histograms = []

    num_machines = 0
    for summary in summaries:
        try:
            with open(summary, "r") as infile:
                num_machines += 1
                summary_data = json.load(infile)[0]

                # Print content of file
                # print(json.dumps(summary_data, indent=2, sort_keys=True))

                num_succ = 0
                num_fail = 0

                for (c, number) in summary_data["status_counts"].items():
                    code = int(c)
                    if code not in result:
                        result[code] = 0
                    result[code] += number

                    if is_success(code):
                        num_succ += number
                    else:
                        num_fail += number

                t_percentile.append(convert_duration(summary_data["percentiles"]))

                t_median.append(convert_time_from_summary(summary_data["median"]))
                t_max.append(convert_time_from_summary(summary_data["max"]))
                t_min.append(convert_time_from_summary(summary_data["min"]))
                t_average.append(convert_time_from_summary(summary_data["average"]))
                failure_rates.append(num_fail / (num_succ + num_fail) if (num_succ + num_fail) > 0 else -1)
                if "succ_rate_histogram" in summary_data:
                    succ_rate_histograms.append(summary_data["succ_rate_histogram"])

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

    sum_requests = success[True] + success[False]
    failure_rate = success[False] / sum_requests if sum_requests != 0 else 1.0

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
        succ_rate_histograms,
    )


def convert_time_from_summary(time):
    """Convert time from workload generator summary."""
    return time["secs"] * 1000.0 + time["nanos"] / 1000.0 / 1000.0


def is_success(code):
    """List of status codes considered to be successful."""
    okay = [200, 202]
    return code in okay
