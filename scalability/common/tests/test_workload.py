"""Unit tests for workload.py."""
import os
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "../"))
from common import workload  # noqa


class Test_Workload(unittest.TestCase):
    """Unit tests for workload class."""

    def test_get_commands(self):
        """Test producing workload_generator commands."""
        dummy_workload = workload.Workload(
            load_generators=["wg_1", "wg_2"],
            target_machines=["tm_1", "tm_2", "tm_3"],
            workload=workload.WorkloadDescription(
                canister_ids=["c_a", "c_b", "c_c"],
                method="plus",
                call_method="call",
                rps=10,
                duration=60,
                raw_payload=None,
                json_payload="",
                arguments=[],
                start_delay=10,
                rps_ratio=0.2,
                subnet=1,
            ),
            f_stdout="no stdout",
            f_stderr="no stderr",
        )
        (commands, wgs) = dummy_workload.get_commands()
        assert len(commands) == 2
        commands[0] = commands[0][: commands[0].find("wg_summary_")]
        commands[1] = commands[1][: commands[1].find("wg_summary_")]
        print(commands[0])
        print(commands[1])
        assert (
            commands[0]
            == './ic-workload-generator "http://[tm_1]:8080,http://[tm_2]:8080,http://[tm_3]:8080" -n 60 -p 9090 --no-status-check  --query-timeout-secs 30 --ingress-timeout-secs 360 --payload \'\' -m plus --call-method "call" --canister-id c_a -r 5.0 --summary-file '
        )
        assert wgs[0] == "wg_1"
        assert (
            commands[1]
            == './ic-workload-generator "http://[tm_1]:8080,http://[tm_2]:8080,http://[tm_3]:8080" -n 60 -p 9090 --no-status-check  --query-timeout-secs 30 --ingress-timeout-secs 360 --payload \'\' -m plus --call-method "call" --canister-id c_b -r 5.0 --summary-file '
        )
        assert wgs[1] == "wg_2"


if __name__ == "__main__":
    unittest.main()
