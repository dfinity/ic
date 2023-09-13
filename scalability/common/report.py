import dataclasses
import json
import os
import sys
from dataclasses import dataclass, fields
from statistics import mean, median

from termcolor import colored

# TODO: see if there is a better way to find "common" module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.misc import mean_or_minus_one  # noqa: E402


class WorkloadGeneratorSummaryUnmatched(Exception):
    """Raised when the workload generator summary files cannot be matched to workload"""

    pass


def convert_duration(data: [dict]):
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

    def to_dict(self):
        return {
            "failure_rate": self.failure_rate,
            "failure_rates": self.failure_rates,
            "t_median": self.t_median,
            "t_average": self.t_average,
            "t_max": self.t_max,
            "t_min": self.t_min,
            "percentiles": self.percentiles,
            "total_number": self.total_number,
            "num_success": self.num_success,
            "num_fail": self.num_fail,
            "succ_rate_histograms": self.succ_rate_histograms,
        }

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

    def get_latencies(self):
        if self.num_success > 0:
            t_median = mean(self.t_median)
            t_average = max(self.t_average)
            t_max = max(self.t_max)
            t_min = max(self.t_min)
            p99 = self.percentiles[99]
        else:
            t_median = sys.float_info.max
            t_average = sys.float_info.max
            t_max = sys.float_info.max
            t_min = sys.float_info.max
            p99 = sys.float_info.max

        return (t_median, t_average, t_max, t_min, p99)

    def get_success_rate_histograms(self):
        # Aggregate histogram of successful requests
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

    def get_median_failure_rate(self):
        return median(self.failure_rates)


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

    percentiles = [
        mean_or_minus_one([x[p] if p < len(x) else float("NaN") for x in t_percentile]) for p in range(0, 100)
    ]

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


@dataclass
class ExperimentDetails:
    """
    The dataclass acts as sort of a schema for experiment details.

    Report generation should only use entries from this dataclass to render the report.
    Extra data can be provided, but will be passed as is to the template
    when rendering on now be interpreted by the scripts.
    """

    # Duration of a single iteration of the experiment
    iter_duration: int


def parse_experiment_details(experiment_details: dict):
    schema_keys = [f.name for f in list(fields(ExperimentDetails))]
    # Filter out key value pairs that are experiment specific
    data = {k: v for k, v in experiment_details.items() if k in schema_keys}
    return ExperimentDetails(**data)


def parse_experiment_details_with_fallback_duration(experiment_details: dict):
    """
    Parse the given experiment details and fill in iter_duration if not present in report.

    This for legacy cases, where iter_duration was not persisted.
    This is very ugly and should normally not be used.
    """
    if "iter_duration" not in experiment_details:
        experiment_details["iter_duration"] = 300
    return parse_experiment_details(experiment_details)


@dataclass
class ExperimentFile:
    """
    The dataclass acts as sort of a schema for experiment file.

    Report generation should only use entries from this dataclass to render the report.
    Extra data can be provided, but will be passed as is to the template
    when rendering on now be interpreted by the scripts.
    """

    xlabels: [int]
    t_experiment_start: int
    experiment_name: str
    command_line: [str]
    canister_id: dict


def parse_experiment_file(experiment_file_content: dict, strict=True):
    schema_keys = [f.name for f in list(fields(ExperimentFile))]
    # Filter out key value pairs that are experiment specific
    if not strict:
        experiment_file_content["command_line"] = experiment_file_content.get("command_line", [])
        experiment_file_content["canister_id"] = experiment_file_content.get("canister_id", "{}")
    data = {k: v for k, v in experiment_file_content.items() if k in schema_keys}
    result = ExperimentFile(**data)
    if type(result.canister_id) is str:
        print("Parsing json data class .. ")
        result = dataclasses.replace(result, canister_id=json.loads(result.canister_id))
    # Older reports didn't store a dictionary for the canister ID, but only a single list.
    # If the list only contains one canister, we can simply convert it to a list.
    if type(result.canister_id) is list:
        if len(result.canister_id) == 1:
            print(colored(f"Converting canister ID {result.canister_id}"))
            result = dataclasses.replace(result, canister_id={"unknown": result.canister_id})

        if result.experiment_name == "run_xnet_experiment":
            # We know the canisters are Xnet canisters ..
            result = dataclasses.replace(result, canister_id={"xnet-test-canister": result.canister_id})

    assert type(result.canister_id) is dict, f"Canister ID {result.canister_id} is not a dictionary"
    return result


def __cleanup_summary_file_name_from_map_file(filename: str, iter_dir_path: str):
    """
    File names in the summary file are unfortunate.

    They are relative to the scalability suite directory,
    so they might include things like "result/". We have to
    clean that up so it works locally.
    """
    return os.path.join(iter_dir_path, os.path.basename(filename))


def _get_experiment_summaries_for_iteration(iteration_dir: str):
    """Given the iteration_dir, return a list of all workloads along with their description."""
    path = os.path.join(iteration_dir, "workload_command_summary_map.json")
    with open(path, "r") as f:
        workload_command_summary_map = json.loads(f.read())
        return {
            key: [
                __cleanup_summary_file_name_from_map_file(e["summary_file"], iteration_dir)
                for e in value["load_generators"]
            ]
            for key, value in workload_command_summary_map.items()
        }


def _legacy_get_experiment_summaries_for_iteration(iteration_dir: str):
    """
    Old reports do not have a workload_command_summary_map.json file.

    Attempt to still group summary files to workloads.
    """
    experiment_json_file = os.path.join(os.path.dirname(iteration_dir), "experiment.json")
    experiment_json_content = json.loads(open(experiment_json_file, "r").read())
    experiment_file = parse_experiment_file(experiment_json_content, strict=False)

    files = [
        os.path.join(iteration_dir, f)
        for f in os.listdir(iteration_dir)
        if f.startswith("summary_machine_") or f.startswith("summary_workload_")
    ]
    if experiment_file.experiment_name in [
        "experiment_1",
        "run_system_baseline_experiment",
        "system-baseline-experiment",
    ]:
        # For those experiments, there is only one workload
        # We will sort them in the hope that the order of workload generators in each iteration.
        return {0: sorted(files)}

    if len(files) == 1:
        # There is exactly one workload generator output file, so there is obviously only one workload
        return {0: files}

    if experiment_file.experiment_name in ["experiment_2", "run_large_memory_experiment"]:
        if int(experiment_json_content.get("num_canister", -1)) == len(files):
            # The experiment json file claims there have been
            return {idx: val for idx, val in enumerate(sorted(files))}

    print(colored(f"{experiment_file} not supported in _legacy_get_experiment_summaries_for_iteration", "red"))
    return None


def find_experiment_summaries(base: str):
    """Find summary files from workload generators and grouped by iteration."""
    result = {}
    for i in sorted([int(i) for i in os.listdir(base) if i.isnumeric()]):
        path = os.path.join(base, str(i))
        if os.path.isdir(path):
            summaries = None
            try:
                summaries = _get_experiment_summaries_for_iteration(path)
            except (KeyError, FileNotFoundError) as e:
                print(f"Failed to parse workload summary map: {e}")

            if summaries is None:
                summaries = _legacy_get_experiment_summaries_for_iteration(path)

            if summaries is None:
                raise WorkloadGeneratorSummaryUnmatched

            result[i] = summaries

    return result


def get_maximum_capacity(iterations: dict, max_failure_rate: int, max_latency: int, duration: int):
    """Determine the maximum capacity for the given set of iterations."""
    # Each iteration should have the same number of workloads
    num_workloads = set([len(val) for _, val in iterations.items()])
    assert len(num_workloads) == 1
    num_workloads = list(num_workloads)[0]

    # Maximum capacity for each workload
    max_rps = [0] * num_workloads

    for key, value in iterations.items():
        for workload_idx, summary_files in value.items():
            evaluated_summaries = evaluate_summaries(summary_files)
            if (
                evaluated_summaries.total_number > 0
                and evaluated_summaries.get_median_failure_rate() <= max_failure_rate
                and evaluated_summaries.percentiles[90] <= max_latency
            ):

                assert int(workload_idx) - 1 < len(max_rps), "Workload indices need to be consecutive integers 1..n"
                workload_idx_as_key = int(workload_idx) - 1
                iteration_rps = evaluated_summaries.get_avg_success_rate(duration)
                max_rps[workload_idx_as_key] = max(max_rps[workload_idx_as_key], iteration_rps)

    return max_rps
