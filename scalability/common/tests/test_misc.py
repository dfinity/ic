"""Unit tests for misc.py."""
import os
import sys
import time
import unittest

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "../"))
from common import misc  # noqa


def get_range_query_args_from_duration(duration_secs=240):
    """Get start and end time for a duration of the last duration_secs."""
    return (int(time.time()) - duration_secs, int(time.time()))


class Test_Misc(unittest.TestCase):
    """Unit tests for Misc interaction."""

    def test_distribute_load_to_n(self):
        """Test querying HTTP request duration."""
        assert misc.distribute_load_to_n(1000, 4) == [250, 250, 250, 250]
        assert misc.distribute_load_to_n(1000, 3) == [334, 333, 333]
        assert misc.distribute_load_to_n(1000, 7) == [143, 143, 143, 143, 143, 143, 142]


if __name__ == "__main__":
    unittest.main()
