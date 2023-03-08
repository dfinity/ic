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

    def test_parse_rps(self):
        """Test different flavors of parse_rps function."""

        def call(s):
            r = misc.parse_datapoints(s)
            print(f"{s} -> {r}")
            return r

        assert call("42") == [42.0]
        assert call("1-10") == [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
        assert call("1-10:2") == [1.0, 3.0, 5.0, 7.0, 9.0]
        assert call("1,42,1337") == [1.0, 42.0, 1337.0]
        assert call("50~1000~10000") == [
            50.0,
            200.0,
            450.0,
            600.0,
            700.0,
            800.0,
            850.0,
            900.0,
            950.0,
            1000.0,
            1050.0,
            1100.0,
            1150.0,
            1200.0,
            1300.0,
            1400.0,
            1550.0,
            1800.0,
            2150.0,
            2600.0,
            3250.0,
            4200.0,
            5550.0,
            7400.0,
            10000.0,
        ]


if __name__ == "__main__":
    unittest.main()
