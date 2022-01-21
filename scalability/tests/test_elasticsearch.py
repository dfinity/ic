"""Unit tests for elasticsearch.py."""
from unittest import TestCase

from elasticsearch import ElasticSearch


class Test_ElasticSearch(TestCase):
    """Unit tests for elasticsearch.py."""

    def test_send_perf_trend_success(self):
        """The success case where a metric is successfully sent to ES."""
        name = "system_baseline_nightly_unit_test"
        is_success = False
        request_type = "Query"
        base_revision = "391fd19f2154471f01068aaa771084eac010a099"
        base_branch = "rc--2021-12-31_18_31"
        upgrade_revision = "391fd19f2154471f01068aaa771084eac010a099"
        upgrade_branch = "rc--2022-01-01_18_31"
        is_ci_job = False
        base_failure_rate = 20.5
        upgrade_failure_rate = 20.8
        failure_rate_threshold = 0
        failure_rate_delta_threshold = 0
        base_median_latency = 200
        upgrade_median_latency = 195
        median_latency_threshold = 250
        median_latency_delta_threshold = 0.1
        base_rps = 200
        upgrade_rps = 220
        rps_threshold = 230
        rps_delta_threshold = -0.05
        summaries = (
            base_failure_rate,
            upgrade_failure_rate,
            failure_rate_threshold,
            failure_rate_delta_threshold,
            base_median_latency,
            upgrade_median_latency,
            median_latency_threshold,
            median_latency_delta_threshold,
            base_rps,
            upgrade_rps,
            rps_threshold,
            rps_delta_threshold,
        )
        sent = ElasticSearch.send_perf_compare(
            name,
            is_success,
            request_type,
            base_revision,
            upgrade_revision,
            base_branch,
            upgrade_branch,
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
            name, request_type, experiment_revision, experiment_branch, is_ci_job, rps
        )
        self.assertTrue(sent)
