"""Unit tests for prometheus.py."""
import math
import time
import unittest

TESTNET = "mercury"
MACHINES = [
    "2001:920:401a:1706:5000:87ff:fe11:a9a0",
    "2001:920:401a:1708:5000:4fff:fe92:48f1",
    "2001:920:401a:1708:5000:5fff:fec1:9ddb",
]


def get_range_query_args_from_duration(duration_secs=240):
    """Get start and end time for a duration of the last duration_secs."""
    return (int(time.time()) - duration_secs, int(time.time()))


class Test_Prometheus(unittest.TestCase):
    """Unit tests for Prometheus interaction."""

    def test_http_request_duration(self):
        """Test querying HTTP request duration."""
        import sys

        sys.path.insert(1, ".")
        import common.prometheus as prometheus

        t_start, t_end = get_range_query_args_from_duration(duration_secs=200)
        http_request_duration = prometheus.get_http_request_duration(
            TESTNET, MACHINES, t_start, t_end, "query", step=60
        )
        print(http_request_duration)
        assert len(http_request_duration) == math.ceil(240 / 60)

    def test_state_sync_duration(self):
        """Test state sync duration query."""
        import sys

        sys.path.insert(1, ".")
        import common.prometheus as prometheus

        timestamp = int(time.time())
        state_sync_duration = prometheus.get_state_sync_duration(TESTNET, [MACHINES[0]], timestamp)
        print(state_sync_duration)
        parsed = prometheus.parse(state_sync_duration)
        # One result per machine.
        for ((value_timestamp, value), _metric) in parsed:
            assert value_timestamp == timestamp
            print("state sync duration is:", value)


if __name__ == "__main__":
    unittest.main()
