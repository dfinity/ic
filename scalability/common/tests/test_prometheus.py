"""Unit tests for prometheus.py."""
import math
import sys
import time
import unittest

sys.path.insert(1, ".")
from common import ansible  # noqa
from common import misc  # noqa

TESTNET = "large02"


def get_machines():
    """Return some hostnames for the given subnetwork."""
    return ansible.get_ansible_hostnames_for_subnet(TESTNET)


def get_range_query_args_from_duration(duration_secs=240):
    """Get start and end time for a duration of the last duration_secs."""
    print(int(time.time()))
    t_start = 1655213772
    return (t_start - duration_secs, t_start)


class Test_Prometheus(unittest.TestCase):
    """Unit tests for Prometheus interaction."""

    def test_http_request_duration(self):
        """Test querying HTTP request duration."""
        import sys

        sys.path.insert(1, ".")
        import common.prometheus as prometheus

        t_start, t_end = get_range_query_args_from_duration(duration_secs=200)
        http_request_duration = prometheus.get_http_request_duration(TESTNET, [], t_start, t_end, "query", step=60)
        print(http_request_duration)
        assert len(http_request_duration) == math.ceil(240 / 60)

    def test_state_sync_duration(self):
        """Test state sync duration query."""
        import sys

        sys.path.insert(1, ".")
        import common.prometheus as prometheus

        timestamp = int(time.time())
        state_sync_duration = prometheus.get_state_sync_duration(TESTNET, [get_machines()[0]], timestamp)
        print(state_sync_duration)
        parsed = prometheus.parse(state_sync_duration)
        # One result per machine.
        for ((value_timestamp, value), _metric) in parsed:
            assert value_timestamp == timestamp
            print("state sync duration is:", value)


if __name__ == "__main__":
    misc.parse_command_line_args()
    unittest.main()
