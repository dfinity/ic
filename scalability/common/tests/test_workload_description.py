"""Unit tests for workload description."""
import sys
import unittest
from pathlib import Path

import gflags
import toml

p = Path(__file__).parents[2]
sys.path.append(f"{p}/")
import common.workload as workload  # noqa: E402

# even though base_experiment is not directly called, test will fail if not present
import common.base_experiment as base_experiment  # noqa

FLAGS = gflags.FLAGS


class Test_Workload_Description(unittest.TestCase):
    """Unit tests for workload description."""

    def test_mixed_query_update(self):
        """Test querying HTTP request duration."""

        # Need to have access to iter_duration when generating workload description
        FLAGS(["", "--testnet", "nothing"])

        with open("scalability/workloads/mixed-query-update.toml") as f:
            description = toml.loads(f.read())
            workload.workload_description_from_dict(description, {"counter": "abc"})


if __name__ == "__main__":
    unittest.main()
