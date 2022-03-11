"""A mock experiment."""
import sys
import unittest
from unittest import TestCase
from unittest.mock import MagicMock
from unittest.mock import Mock

import experiment
from workload_experiment import WorkloadExperiment


class Test_Experiment(TestCase):
    """Implements a generic experiment with dependencies mocked away."""

    def test_verify__mock(self):
        """Test passes when the experiment runs to end."""
        sys.argv = ["mock.py", "--testnet", "abc", "--wg_testnet", "def", "--skip_generate_report", "True"]

        experiment.parse_command_line_args()

        exp = ExperimentMock()

        # Mock functions that won't work without a proper IC deployment
        exp.get_targets = Mock(return_value=["1.1.1.1", "2.2.2.2"])
        exp.get_hostnames = Mock(return_value=["3.3.3.3", "4.4.4.4"])
        exp.get_ic_version = MagicMock()
        exp.get_subnet_for_target = MagicMock()

        exp.get_subnet_info = Mock(return_value="{}")
        exp.get_topology = Mock(return_value="{}")
        exp.store_hardware_info = MagicMock()
        exp.get_iter_logs_from_targets = MagicMock()
        exp.install_canister = MagicMock()
        exp.run_workload_generator = MagicMock()
        exp.init_metrics = MagicMock()
        exp.kill_workload_generator = MagicMock()
        exp.turn_off_replica = MagicMock()
        exp.check_workload_generator_installed = Mock(return_value=True)
        exp.get_ic_version = MagicMock(return_value="deadbeef")
        exp.wait_for_quiet = MagicMock(return_value=None)

        exp.init()
        exp.init_experiment()
        exp.install_canister("some canister")

        exp.start_experiment()
        exp.run_experiment({})

        exp.subnet_id = "abc"
        exp.write_summary_file("test", {}, [], "some x value")
        exp.end_experiment()

        exp.install_canister.assert_called_once()
        exp.run_workload_generator.assert_called_once()
        exp.init_metrics.assert_called_once()


class ExperimentMock(WorkloadExperiment):
    """Logic for experiment 1."""

    def __init__(self):
        """Construct experiment 1."""
        super().__init__()

    def run_experiment_internal(self, config):
        """Mock similar to experiment 1."""
        return self.run_workload_generator(
            self.machines,
            self.target_nodes,
            200,
            outdir=self.iter_outdir,
            duration=60,
        )


if __name__ == "__main__":
    unittest.main()
