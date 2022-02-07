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


class Test_Prometheus(unittest.TestCase):
    """Unit tests for prometheus.py."""

    def get_machines(self):
        """Return a bunch of machines for testing purposes."""
        return MACHINES

    def get_range(self, duration_secs=240):
        """Get start and end time for a duration of the last duration_secs."""
        return (int(time.time()) - duration_secs, int(time.time()))

    def test_http_request_duration(self):
        """Test querying HTTP request duration."""
        import sys

        sys.path.insert(1, ".")

        import prometheus

        t_start, t_end = self.get_range(duration_secs=200)
        http_request_duration = prometheus.get_http_request_duration(
            TESTNET, self.get_machines(), t_start, t_end, "query", step=60
        )
        print(http_request_duration)
        assert len(http_request_duration) == math.ceil(240 / 60)


if __name__ == "__main__":
    unittest.main()
