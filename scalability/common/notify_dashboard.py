"""Class for sending metrics to ElasticSearch ci-performance-test index."""
import datetime
import json
import os
import sys
import time
from typing import Any

import gflags
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import misc  # noqa

gflags.DEFINE_string(
    "branch",
    "N/A",
    'Git branch to measure performance. E.g. "origin/rc--2022-01-01_18-31" or "origin/feature-branch-name".',
)
gflags.DEFINE_string(
    "gitlab_job_id",
    "N/A",
    "Gitlab job ID which ran the test and generated report.",
)

gflags.DEFINE_string(
    "base_dir",
    "./",
    "The base directory where output artifacts are generated into. The base_dir should contain sub folder named with git_revision.",
)
gflags.DEFINE_string(
    "git_revision",
    None,
    "Hash of the git revision which the benchmark run was exercised on. Output folder with this git_revision in name will be used to generate report.",
)
gflags.MarkFlagAsRequired("git_revision")
gflags.DEFINE_string(
    "timestamp",
    None,
    "The timestamp the benchmark run was marked with. Output folder with this timestamp in name will be used to generate report.",
)
gflags.MarkFlagAsRequired("timestamp")
gflags.DEFINE_boolean("is_max_capacity_run", None, "Whether the data points come from a maximum capacity run.")
gflags.MarkFlagAsRequired("is_max_capacity_run")

FLAGS = gflags.FLAGS
BASE_URL = "http://elasticsearch.dfinity.systems:9200"
INDEX = "performance-trend"


class NotifyDashboard:
    """Client class for intercting with ElasticSearch."""

    def __notify(metric):
        """Client to make a call to ElasticSearch."""
        addr = f"{BASE_URL}/{INDEX}/_doc/"
        for i in range(3):
            try:
                response = requests.post(
                    url=addr,
                    data=json.dumps(metric, indent=4, default=str).encode(),
                    headers={"content-type": "application/json"},
                    timeout=30,
                )
                if response.status_code < 500:
                    if response.status_code < 400:
                        # success
                        print(f"Data points successfully sent to {addr}")
                        return True
                    else:
                        # client side error, log error and no retry
                        print(
                            f"Invalid input request: {metric}. Response received was: {response.status_code} {response.content}"
                        )
                        return False

                else:
                    # service side error, retry after 3 seconds
                    print(
                        f'Remote service error received when send metrics to {addr}. {response.status_code} {response.content}. {"" if (i == 2) else "Sleep 3 seconds before next retry."}'
                    )
                    time.sleep(3)

            except Exception as e:
                print(
                    f'Exception caught when send metrics to {addr}. {e}. {"" if (i == 2) else "Sleep 3 seconds before next retry."}'
                )
                time.sleep(3)
        return False

    def notify_spot_run(name, is_success, request_type, revision, summaries):
        """Send a performance nightly data point performance-trend index in ElasticSearch."""
        (
            failure_rate,
            failure_rate_threshold,
            median_latency,
            median_latency_threshold,
            throughput,
            throughput_threshold,
        ) = summaries

        metric = {
            "timestamp": datetime.datetime.utcfromtimestamp(int(FLAGS.timestamp)).isoformat(),
            "rev": revision,
            "branch": FLAGS.branch,
            "package": "replica-perf-trend",
            "performance": {
                "title": name,
                "request_type": request_type,
                "is_success": is_success,
                "metrics": {
                    "failure_rate": {
                        "value": failure_rate,
                        "threshold": failure_rate_threshold,
                    },
                    "median_latency": {
                        "value": median_latency,
                        "threshold": median_latency_threshold,
                    },
                    "throughput": {
                        "value": throughput,
                        "threshold": throughput_threshold,
                    },
                },
            },
        }
        return NotifyDashboard.__notify(metric)

    def notify_max_run(name, request_type, experiment_revision, rps, out_dir):
        """Send a maximum capacity data point to performance-trend index in ElasticSearch."""
        metric = {
            "timestamp": datetime.datetime.utcfromtimestamp(int(FLAGS.timestamp)).isoformat(),
            "rev": experiment_revision,
            "branch": FLAGS.branch,
            "package": "replica-perf-trend",
            "report_url": f"https://dfinity-lab.gitlab.io/-/public/ic/-/jobs/{FLAGS.gitlab_job_id}/artifacts/scalability/{out_dir}/report.html",
            "performance": {"title": name, "request_type": request_type, "metrics": {"max-capacity": rps}},
        }

        return NotifyDashboard.__notify(metric)


if __name__ == "__main__":
    misc.parse_command_line_args()
    dir = f"{FLAGS.base_dir}/{FLAGS.git_revision}/{FLAGS.timestamp}"

    j = Any
    with open(f"{dir}/experiment.json", "r") as experiment_file:
        j = json.loads(experiment_file.read())
        experiment_name = str(j["command_line"][0]).replace("experiments/", "").replace(".py", "")
        throughput = j["experiment_details"]["rps_max"]
        is_update = j["experiment_details"]["is_update"]

    if FLAGS.is_max_capacity_run:
        NotifyDashboard.notify_max_run(
            experiment_name,
            "Update" if is_update else "Query",
            FLAGS.git_revision,
            throughput,
            dir,
        )
    else:
        is_success = j["is_success"]
        median_latency_threshold = j["experiment_details"]["median_latency_threshold"]
        target_load = j["experiment_details"]["target_load"]
        t_median = j["experiment_details"]["t_median"]
        failure_rate = j["experiment_details"]["failure_rate"]

        NotifyDashboard.notify_spot_run(
            experiment_name,
            is_success,
            "Update" if is_update else "Query",
            FLAGS.git_revision,
            (
                failure_rate,
                0,
                t_median,
                median_latency_threshold,
                throughput,
                target_load,
            ),
        )
