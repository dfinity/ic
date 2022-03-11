"""Unit tests for elasticsearch.py."""
import unittest
from unittest import TestCase

import gflags
from elasticsearch import ElasticSearch


class Test_ElasticSearch(TestCase):
    """Unit tests for elasticsearch.py."""

    def setUp(self):
        """Set up needed dependencies."""
        gflags.FLAGS.send_perf_metrics = True

    def test_send_perf_trend_success(self):
        """The success case where a metric is successfully sent to ES."""
        name = "system_baseline_nightly_unit_test"
        is_success = False
        request_type = "Query"
        revision = "391fd19f2154471f01068aaa771084eac010a099"
        branch = "rc--2022-01-01_18_31"
        is_ci_job = False
        failure_rate = 20.8
        failure_rate_threshold = 0
        t_median = 195
        median_latency_threshold = 250
        rps = 220
        target_load = 230
        summaries = (
            failure_rate,
            failure_rate_threshold,
            t_median,
            median_latency_threshold,
            rps,
            target_load,
        )
        sent = ElasticSearch.send_perf(
            name,
            is_success,
            request_type,
            revision,
            branch,
            is_ci_job,
            summaries,
        )
        self.assertTrue(sent)

    def test_send_maximum_capacity_success(self):
        """Success case where a metric is successfully sent to ES."""
        name = "maximum_capacity_unit_test"
        request_type = "Update"
        experiment_revision = "391fd19f2154471f01068aaa771084eac010a099"
        experiment_branch = "rc--2022-01-01_18_31"
        is_ci_job = False
        rps = 89
        sent = ElasticSearch.send_max_capacity(
            name, request_type, experiment_revision, experiment_branch, is_ci_job, rps, "./"
        )
        self.assertTrue(sent)


if __name__ == "__main__":
    unittest.main()
