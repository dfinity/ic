#!/usr/bin/env python3
import json
import os
import sys

import gflags

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import misc  # noqa
from common import report  # noqa

FLAGS = gflags.FLAGS
gflags.DEFINE_string(
    "reports",
    None,
    "Comma-separated list of reports to compare.",
)
gflags.MarkFlagAsRequired("reports")


def get_experiment_file(report_dir: str):
    with open(os.path.join(report_dir, "experiment.json")) as f:
        return report.parse_experiment_file(json.loads(f.read()))


def get_summary_files(report_dir: str):
    return report.find_experiment_summaries(report_dir)


if __name__ == "__main__":
    misc.parse_command_line_args()
    results = {}
    reports = FLAGS.reports.split(",")
    experiment_files = [get_experiment_file(r) for r in reports]
    for r_idx, report_base_dir in enumerate(reports):
        for iteration, summary_files in get_summary_files(report_base_dir).items():
            xlabel = experiment_files[r_idx].xlabels[iteration - 1]
            if xlabel not in results:
                results[xlabel] = {}
            assert len(summary_files) == 1  # Currently only works if we have only exactly one workload
            evaluated_summaries = report.evaluate_summaries(summary_files["0"])
            results[xlabel][r_idx] = {
                "failure_rate": evaluated_summaries.get_median_failure_rate(),
                "p90": evaluated_summaries.percentiles[90],
            }

    for label, r in results.items():
        out = ""
        for _, d in r.items():
            out += f" {d['failure_rate']:10.2f} {d['p90']:15.1f}  "
        print(f"{label:12} {out}")
