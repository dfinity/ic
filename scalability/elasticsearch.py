"""Class for sending metrics to ElasticSearch ci-performance-test index."""
import datetime
import json
import time

import gflags
import requests

gflags.DEFINE_boolean("send_perf_metrics", False, "Send perf metrics to ElasticSearch for dashboard presentation.")

FLAGS = gflags.FLAGS
BASE_URL = "http://elasticsearch.dfinity.systems:9200"
INDEX = "performance-trend"


class ElasticSearch:
    """Client class for intercting with ElasticSearch."""

    def call_elastic_search(metric):
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

    def send_perf(name, is_success, request_type, revision, branch, is_ci_job, summaries):
        """Send a performance nightly data point performance-trend index in ElasticSearch."""
        if FLAGS.send_perf_metrics is False:
            return True

        (
            failure_rate,
            failure_rate_threshold,
            median_latency,
            median_latency_threshold,
            throughput,
            throughput_threshold,
        ) = summaries

        metric = {
            "timestamp": datetime.datetime.now().isoformat(),
            "rev": revision,
            "branch": branch,
            "is_ci_job": is_ci_job,
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
        return ElasticSearch.call_elastic_search(metric)

    def send_max_capacity(
        name, request_type, experiment_revision, experiment_branch, is_ci_job, rps, out_dir, unix_time=None
    ):
        """Send a maximum capacity data point to performance-trend index in ElasticSearch."""
        if FLAGS.send_perf_metrics is False:
            return True

        if unix_time is None:
            unix_time = int(time.time())
            timestamp = datetime.datetime.fromtimestamp(unix_time).isoformat()
        else:
            timestamp = datetime.datetime.fromtimestamp(unix_time).isoformat()

        metric = {
            "unix_time": unix_time,
            "timestamp": timestamp,
            "rev": experiment_revision,
            "branch": experiment_branch,
            "is_ci_job": is_ci_job,
            "package": "replica-perf-trend",
            "report_url": f"http://10.11.10.88:9099/{out_dir}/report.html",
            "performance": {"title": name, "request_type": request_type, "metrics": {"max-capacity": rps}},
        }

        return ElasticSearch.call_elastic_search(metric)
