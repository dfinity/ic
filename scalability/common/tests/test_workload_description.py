"""Unit tests for workload description."""
import unittest

import gflags
import toml

FLAGS = gflags.FLAGS


class Test_Workload_Description(unittest.TestCase):
    """Unit tests for workload description."""

    def test_mixed_query_update(self):
        """Test querying HTTP request duration."""
        import sys

        sys.path.insert(1, ".")
        import common.workload as workload
        import common.base_experiment as base_experiment  # noqa

        # Need to have access to iter_duration when generating workload description
        FLAGS(["", "--testnet", "nothing"])

        with open("workloads/mixed-query-update.toml") as f:

            description = toml.loads(f.read())
            workload.workload_description_from_dict(description, {"counter": "abc"})


if __name__ == "__main__":
    unittest.main()
