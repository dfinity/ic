"""Unit tests for workload description."""
import json
import os
import unittest
from pathlib import Path


def write_test_summary_map_file(dirname: str, f):
    workload_command_summary_map = {}

    for i in range(2):
        workload_command_summary_map[i] = {
            "workload_description": "description",
            "load_generators": [
                {
                    "command": f"some command {j}",
                    "summary_file": f"summary_file_{j}",
                }
                for j in range(i + 1)
            ],
        }

    outfile = os.path.join(dirname, "workload_command_summary_map.json")
    with open(outfile, "w") as map_file:
        map_file.write(json.dumps(workload_command_summary_map, cls=f, indent=4))


class Test_Report_Generation(unittest.TestCase):
    """Unit tests for report generation."""

    def test_get_experiment_summaries_for_iteration(self):
        """Test determining experiment summaries for iteration."""
        import os
        import sys
        import tempfile

        # TODO: see if there is a better way to find "common" module
        p = Path(__file__).parents[2]
        sys.path.append(f"{p}/")
        import common.report as report
        import common.workload as workload

        with tempfile.TemporaryDirectory() as tempdirname:
            d1 = os.path.join(tempdirname, "1")
            d2 = os.path.join(tempdirname, "2")
            os.mkdir(d1)
            os.mkdir(d2)

            write_test_summary_map_file(d1, workload.BytesEncoder)
            write_test_summary_map_file(d2, workload.BytesEncoder)

            r = report.find_experiment_summaries(tempdirname)
            print(r)
            assert len(r) == 2, "Expected to parse two iterations"

            for k in r.keys():
                assert len(r[k]) == 2, f"Expected two workloads in iteration {k}"
                for idx, wl in enumerate(r[k].keys()):
                    assert (
                        len(r[k][wl]) == idx + 1
                    ), f"Expected one workload generation for workload 0 in iteration {wl}"


if __name__ == "__main__":
    unittest.main()
