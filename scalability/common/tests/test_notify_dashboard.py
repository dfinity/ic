"""Unit tests for notify_dashboard.py."""
import sys
import unittest
from unittest import TestCase

import common.misc as misc
from common.notify_dashboard import NotifyDashboard


class Test_NotifyDashboard(TestCase):
    """Unit tests for notify_dashboard.py."""

    git_revision = "391fd19f2154471f01068aaa771084eac010a099"
    timestamp = "1648500677"

    def test_send_perf_trend_success(self):
        """The success case where a metric is successfully sent to dashboard."""
        sys.argv = [
            "test_notify_dashboard.py",
            "--branch",
            "rc--2022-01-01_18_31",
            "--git_revision",
            self.git_revision,
            "--timestamp",
            self.timestamp,
            "--is_max_capacity_run",
            "False",
        ]
        misc.parse_command_line_args()
        name = "system_baseline_nightly_unit_test"
        is_success = False
        request_type = "Query"
        revision = self.git_revision
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
        sent = NotifyDashboard.notify_spot_run(name, is_success, request_type, revision, summaries, "./")
        self.assertTrue(sent)

    def test_send_maximum_capacity_success(self):
        """Success case where a metric is successfully sent to dashboard."""
        sys.argv = [
            "test_notify_dashboard.py",
            "--branch",
            "rc--2022-01-01_18_31",
            "--git_revision",
            self.git_revision,
            "--timestamp",
            self.timestamp,
            "--is_max_capacity_run",
            "True",
        ]
        misc.parse_command_line_args()
        name = "maximum_capacity_unit_test"
        request_type = "Update"
        experiment_revision = self.git_revision
        rps = 89
        sent = NotifyDashboard.notify_max_run(name, request_type, experiment_revision, rps, "./")
        self.assertTrue(sent)


if __name__ == "__main__":
    unittest.main()
