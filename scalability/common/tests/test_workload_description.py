"""Unit tests for workload description."""
import unittest

import toml


class Test_Workload_Description(unittest.TestCase):
    """Unit tests for workload description."""

    def test_mixed_query_update(self):
        """Test querying HTTP request duration."""
        import sys

        sys.path.insert(1, ".")
        import common.workload as workload

        with open("workloads/mixed-query-update.toml") as f:
            description = toml.loads(f.read())
            workload.workload_description_from_dict(description, {"counter": "abc"})


if __name__ == "__main__":
    unittest.main()
