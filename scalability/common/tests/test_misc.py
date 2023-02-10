"""Unit tests for misc.py."""
import sys
import time
import unittest
from pathlib import Path

p = Path(__file__).parents[2]
sys.path.append(f"{p}/")
from common import misc  # noqa


def get_range_query_args_from_duration(duration_secs=240):
    """Get start and end time for a duration of the last duration_secs."""
    return (int(time.time()) - duration_secs, int(time.time()))


class Test_Misc(unittest.TestCase):
    """Unit tests for Misc interaction."""

    def test_distribute_load_to_n(self):
        """Test querying HTTP request duration."""
        assert misc.distribute_load_to_n(1000, 4) == [250, 250, 250, 250]
        for i, s in zip(misc.distribute_load_to_n(1000, 3), [1000 / 3.0] * 3):
            assert abs(i - s) < 1e-2
        for i, s in zip(misc.distribute_load_to_n(1000, 7), [1000 / 7.0] * 3):
            assert abs(i - s) < 1e-2


if __name__ == "__main__":
    unittest.main()
