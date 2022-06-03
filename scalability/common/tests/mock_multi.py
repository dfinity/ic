"""A mock experiment."""
import os
import sys
import unittest
from unittest import TestCase
from unittest.mock import MagicMock
from unittest.mock import Mock

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "../"))
import common.misc as misc  # noqa
from common.base_experiment import BaseExperiment  # noqa
from experiments.run_mixed_workload_experiment import MixedWorkloadExperiment  # noqa
from common import ssh  # noqa


class ExperimentMock(MixedWorkloadExperiment):
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


class Test_Experiment(TestCase):
    """Implements a generic experiment with dependencies mocked away."""

    def test_verify__mock(self):
        """Test passes when the experiment runs to end."""
        sys.argv = [
            "mock.py",
            "--testnet",
            "abc",
            "--wg_testnet",
            "def",
            "--workload_generator_machines",
            "3.3.3.3,4.4.4.4",
            "--workload",
            "workloads/mixed-query-update.toml",
        ]

        misc.parse_command_line_args()

        ssh.run_all_ssh_in_parallel = Mock()
        ssh.scp_in_parallel = Mock()

        # Mock functions that won't work without a proper IC deployment
        ExperimentMock._WorkloadExperiment__get_targets = Mock(return_value=["1.1.1.1", "2.2.2.2"])
        ExperimentMock._WorkloadExperiment__get_subnet_for_target = MagicMock()
        ExperimentMock.get_subnet_to_instrument = MagicMock()
        BaseExperiment._get_subnet_info = Mock(return_value="{}")
        ExperimentMock._BaseExperiment__get_topology = Mock(return_value="{}")
        ExperimentMock._BaseExperiment__store_hardware_info = MagicMock()
        ExperimentMock.get_iter_logs_from_targets = MagicMock()
        ExperimentMock.install_canister = MagicMock()
        ExperimentMock._BaseExperiment__init_metrics = MagicMock()
        ExperimentMock._WorkloadExperiment__kill_workload_generator = MagicMock()
        BaseExperiment._turn_off_replica = MagicMock()
        ExperimentMock._WorkloadExperiment__check_workload_generator_installed = Mock(return_value=True)
        ExperimentMock.get_ic_version = MagicMock(return_value="42")
        ExperimentMock._WorkloadExperiment__wait_for_quiet = MagicMock(return_value=None)

        exp = ExperimentMock()
        exp.canister_ids = {"canistername": ["canisterid"]}

        exp._BaseExperiment__init_metrics = MagicMock()
        exp._WorkloadExperiment__kill_workload_generator = MagicMock()

        exp.canister_ids = {"counter": ["abc"]}
        exp.init_experiment()
        exp.start_experiment()
        exp.run_experiment({})

        exp.subnet_id = "abc"
        exp.write_summary_file("test", {}, [], "some x value")
        exp.end_experiment()

        # We have two canisters in the description file
        exp.install_canister.assert_called()


if __name__ == "__main__":
    unittest.main()
