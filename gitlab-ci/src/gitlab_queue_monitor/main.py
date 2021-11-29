#!/usr/bin/env python3
"""
Run the GitLabQueueMonitor.

It queries the GitLab API for the number of global pending and running jobs. As well as the runner
specific running jobs.

Example usage:

    # Run once in dry-run mode.
    ./main.py --dry-run

    # Run once and exports metrics.
    ./main.py --es-index="$USER-gitlab-queue"

    # Run in server mode.
    ./main.py --server --es-index="$USER-gitlab-queue"

"""
import argparse
import logging
import os
import sys
import time
from datetime import datetime

import beeline
from elasticsearch import Elasticsearch
from gitlab import Gitlab

DFINITY_PROJECT = 22_487_979


class GitLabQueueMonitor:
    """GitLabQueueMonitor polls the GitLab API and exports queueing related metrics."""

    def __init__(self, es_index_prefix, dry_run):
        """
        Initialize the GitLabQueueMonitor.

        Args:
        ----
            es_index_prefix: The prefix to use for the ElasticSearch index.
            dry_run: Just log, but do not export metrics to ElasticSearch.

        """
        if "GITLAB_TOKEN" not in os.environ:
            raise ValueError("could not find GITLAB_TOKEN in env vars")

        ES_NODES = ["elasticsearch-node-%s.dfinity.systems" % i for i in range(3)]
        self.es = Elasticsearch(ES_NODES)
        self.dry_run = dry_run

        self.gl = Gitlab("https://gitlab.com", private_token=os.getenv("GITLAB_TOKEN"))
        self.project = self.gl.projects.get(DFINITY_PROJECT)
        self.es_index_prefix = es_index_prefix

    def _count_jobs_by_scope(self, scope: str):
        data = {}
        jobs = self.project.jobs.list(scope=scope, all=True)

        for job in jobs:
            with beeline.tracer(name="process-jobs"):
                job_context_dict = {f"job.{key}": val for key, val in job.attributes.items()}
                beeline.add_context(job_context_dict)
            data[job.name] = data.get(job.name, 0) + 1

        return (len(jobs), data)

    def _count_runner_jobs_by_status(self, runner, status: str):
        jobs = runner.jobs.list(status=status, all=True)

        return len(jobs)

    def _export_data_to_elastic_search(self, index_infix, data):
        timestamp = datetime.utcnow()

        data["timestamp"] = timestamp

        logging.info(data)

        if not self.dry_run:
            self.es.index(
                f"{self.es_index_prefix}-{index_infix}-{timestamp.year}",
                id=timestamp,
                body=data,
            )

    @beeline.traced(name="queue-monitor-run")
    def process(self):
        """Process queries the GitLab API and exports metrics to ElasticSearch."""
        pending = self._count_jobs_by_scope("pending")
        running = self._count_jobs_by_scope("running")

        data = {}
        data["pending_queue_data"] = {"job_status": "pending", "count": pending[0]}
        self._export_data_to_elastic_search("global", data["pending_queue_data"])

        data["running_queue_data"] = {"job_status": "running", "count": running[0]}
        self._export_data_to_elastic_search("global", data["running_queue_data"])

        data["pending_job_data"] = {}
        data["running_job_data"] = {}
        for key, value in pending[1].items():
            data["pending_job_data"][key] = {
                "status": "pending",
                "job_name": key,
                "count": value,
            }
            self._export_data_to_elastic_search("job-name", data["pending_job_data"][key])

        for key, value in running[1].items():
            data["running_job_data"][key] = {
                "status": "running",
                "job_name": key,
                "count": value,
            }
            self._export_data_to_elastic_search("job-name", data["running_job_data"][key])

        data["runner_data"] = {}

        runners = self.gl.runners.list(all=True)
        for runner in runners:
            with beeline.tracer(name="process-runner"):
                runner_details = self.gl.runners.get(runner.id)
                runner_context_dict = {f"runner.{key}": val for key, val in runner_details.attributes.items()}
                beeline.add_context(runner_context_dict)

                running_jobs = self._count_runner_jobs_by_status(runner, "running")
                logging.info(f"{runner.description}: {running_jobs}")

                data["runner_data"][runner.description] = {
                    "description": runner.description,
                    "running_jobs": running_jobs,
                }
                self._export_data_to_elastic_search("runners", data["runner_data"][runner.description])

        beeline.add_context_field("error", False)
        return data


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--server",
        action="store_true",
        help="In server mode loop forever. Otherwise run once",
    )

    parser.add_argument(
        "--es-index",
        type=str,
        help="ElasticSearch index prefix to export to ",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="In dry run mode, only log but do not export metrics to ElasticSearch",
    )
    parser.add_argument(
        "--export-period",
        default="60",
        type=int,
        help="Time between export cycles",
    )

    logging.basicConfig(level=logging.INFO)

    args = parser.parse_args()

    honeycomb_token = os.getenv("HONEYCOMB_API_TOKEN")
    if not honeycomb_token:
        sys.exit("No Honeycomb token specified in HONEYCOMB_API_TOKEN env var.")

    beeline.init(
        # Get this via https://ui.honeycomb.io/account after signing up for Honeycomb
        writekey=honeycomb_token,
        # The name of your app is a good choice to start with
        dataset="gitlab-ci-daemons",
        service_name="queue-monitor",
        debug=False,  # if True, data doesn't get sent to Honeycomb
    )

    queue_monitor = GitLabQueueMonitor(args.es_index, args.dry_run)

    if not args.server:
        queue_monitor.process()
        beeline.close()
        return

    last_export_time = time.time()
    while True:
        try:
            next_export_time = last_export_time + args.export_period
            next_export_delay = max(next_export_time - time.time(), 0)

            logging.info(f"next export in {next_export_delay} seconds")
            time.sleep(next_export_delay)
            last_export_time = time.time()

            queue_monitor.process()
        except Exception as e:
            logging.error(e)

    beeline.close()


if __name__ == "__main__":
    main()
