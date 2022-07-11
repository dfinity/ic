#!/usr/bin/env python3
import glob
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from ast import Dict
from pathlib import Path
from typing import List
from typing import Optional

import expected_results

SUITE_EXECUTION_CONTRACT_FILE = "suite_execution_contract.json"
SUITE_RESULT_FILE = "test-results.json"

# Set path to the current script path and make it agnostic to the invocation dir.
current_path = Path(os.path.dirname(os.path.abspath(__file__)))
os.chdir(current_path.absolute())
root_ic_dir = str(current_path.parent.parent.parent.absolute())


class TestRunSystemTests(unittest.TestCase):
    """Test of the run-system-tests.py wrapper with different test suites, which pass/fail/timeout."""

    # Executed for each test.
    def setUp(self) -> None:
        IC_VERSION_ID = os.getenv("IC_VERSION_ID", default="")
        if not IC_VERSION_ID:
            raise Exception("IC_VERSION_ID env variable is required.")
        # Tests can have different input env variables.
        # Thus, we reset them for each test run.
        self.env = os.environ.copy()
        self.env["IC_VERSION_ID"] = IC_VERSION_ID
        # This duration should be sufficient for the suite execution with empty test bodies.
        self.env["SYSTEM_TESTS_TIMEOUT"] = "15"  # seconds
        # By design prod-test-driver dumps files/folders into tmp dirs within "TMPDIR" folder.
        # To alleviate clean up (tearDown), each test run creates a new tmp dir, where tmp files are stored.
        self.test_tmp_dir = tempfile.mkdtemp(prefix="tmp_test_execution")
        self.env["TMPDIR"] = self.test_tmp_dir
        self.script_path = os.path.join(root_ic_dir, "rs/tests/run-system-tests.py")
        self.suite_contract_wildcard = f"{self.env['TMPDIR']}/**/system_env/{SUITE_EXECUTION_CONTRACT_FILE}"
        self.suite_result_wildcard = f"{self.env['TMPDIR']}/**/{SUITE_RESULT_FILE}"

    # Executed for each test.
    def tearDown(self) -> None:
        # Cleanup after files content was inspected by the test.
        shutil.rmtree(self.test_tmp_dir, ignore_errors=True)

    def _find_parse_json_by_name(self, file_wildcard: str) -> Dict:
        filepath = glob.glob(file_wildcard, recursive=True)
        # Assert only a single file exists.
        self.assertEqual(len(filepath), 1)
        with open(filepath[0]) as json_file:
            data_dict = json.load(json_file)
        return data_dict

    def test__with_no_ic_version_provided_fails(self):
        # Arrange: remove IC_VERSION_ID from env variables.
        del self.env["IC_VERSION_ID"]
        # Act + assert
        expected_err = "You must specify GuestOS image version via IC_VERSION_ID"
        self._run_suite_with_early_failure(expected_err)

    def test__ci_run_with_prebuilt_artifacts_fails(self):
        # Arrange: add env variables.
        self.env["ARTIFACT_DIR"] = "some_dir"
        self.env["CI_JOB_ID"] = "some_id"
        # Act + assert
        expected_err = "One can't use locally prebuilt artifacts on the CI"
        self._run_suite_with_early_failure(expected_err)

    def test__wrong_ic_version_id_fails(self):
        # Arrange: set non-existing ic_version.
        self.env["IC_VERSION_ID"] = "some_non_existing_ic_version"
        # Act + assert
        expected_err = "Raised exception: Unexpected status_code=403 for the GET"
        self._run_suite_with_early_failure(expected_err)

    def test__suite_with_all_tests_passing(self):
        self._run_suite_to_completion(
            suite_name="suite_to_succeed",
            additional_args=["--keep_artifacts", "--keep_tmp_dirs"],
            expected_suite_contract=expected_results.suite_contract_to_succeed,
            expected_suite_result=expected_results.suite_result_to_succeed,
            expected_exit_code=0,
        )

    def test__suite_with_some_tests_failing(self):
        self._run_suite_to_completion(
            suite_name="suite_to_fail",
            additional_args=["--keep_artifacts", "--keep_tmp_dirs"],
            expected_suite_contract=expected_results.suite_contract_to_fail,
            expected_suite_result=expected_results.suite_result_to_fail,
            expected_exit_code=1,
        )

    def test__suite_with_test_timeout(self):
        self._run_suite_to_completion(
            suite_name="suite_to_timeout",
            additional_args=["--keep_artifacts", "--keep_tmp_dirs"],
            expected_suite_contract=expected_results.suite_contract_to_timeout,
            expected_suite_result=expected_results.suite_result_to_timeout,
            expected_exit_code=124,
        )

    def test__suite_to_fail_in_pot_setup(self):
        self._run_suite_to_completion(
            suite_name="suite_to_fail_in_pot_setup",
            additional_args=["--keep_artifacts", "--keep_tmp_dirs"],
            expected_suite_contract=expected_results.suite_contract_to_fail_in_pot_setup,
            expected_suite_result=expected_results.suite_result_to_fail_in_pot_setup,
            expected_exit_code=1,
        )

    def test__suite_with_include_pattern_case_1(self):
        include_pattern = "test_success_1"
        # test_success_2 is excluded from pot_success_1
        self._run_suite_to_completion(
            suite_name="suite_to_succeed",
            additional_args=[f"--include-pattern={include_pattern}", "--keep_artifacts", "--keep_tmp_dirs"],
            expected_suite_contract=expected_results.suite_contract_include_pattern_case_1,
            expected_suite_result=expected_results.suite_result_include_pattern_case_1,
            expected_exit_code=0,
        )

    def test__suite_with_include_pattern_case_2(self):
        include_pattern = "success"
        # test_fail_1 is excluded from pot_fail_1
        # test_fail_1 is also excluded from pot_fail_2, thus the pot_fail_2 itself is excluded from the suite (as it becomes empty)
        # As all failing tests are excluded, the suite should succeed.
        self._run_suite_to_completion(
            suite_name="suite_to_fail",
            additional_args=[f"--include-pattern={include_pattern}", "--keep_artifacts", "--keep_tmp_dirs"],
            expected_suite_contract=expected_results.suite_contract_include_pattern_case_2,
            expected_suite_result=expected_results.suite_result_include_pattern_case_2,
            expected_exit_code=0,
        )

    def _run_suite_with_early_failure(self, expected_error: str):
        process = subprocess.run([f"{self.script_path}", "--keep_artifacts"], env=self.env, capture_output=True)
        # Assert
        stderr = process.stderr.decode()
        self.assertEqual(process.returncode, 1)
        self.assertTrue(expected_error in stderr)

    def _run_suite_to_completion(
        self,
        suite_name: str,
        additional_args: Optional[List[str]],
        expected_exit_code: int,
        expected_suite_contract: Dict,
        expected_suite_result: Dict,
    ):
        cmd = [f"{self.script_path}", f"--suite={suite_name}"]
        if additional_args is not None:
            cmd += additional_args
        process = subprocess.run(cmd, env=self.env)
        # Assert correct exit code.
        self.assertEqual(process.returncode, expected_exit_code)
        # Assert correct suite_execution_contract.json content.
        actual_suite_contract = self._find_parse_json_by_name(self.suite_contract_wildcard)
        self.assertDictEqual(expected_suite_contract, actual_suite_contract)  # type: ignore
        # Assert correct test-result.json content.
        actual_suite_result = self._find_parse_json_by_name(self.suite_result_wildcard)
        self.assertDictEqual(expected_suite_result, actual_suite_result)  # type: ignore


if __name__ == "__main__":
    unittest.main(verbosity=2)
