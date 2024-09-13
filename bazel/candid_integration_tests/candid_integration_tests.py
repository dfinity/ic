#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys
from unittest import mock

import pytest

workspace_dir = os.path.dirname(os.path.realpath(os.environ["WORKSPACE"]))
if not os.path.isdir(workspace_dir):
    sys.exit("WORKSPACE path '{}' is not directory".format(workspace_dir))
did_file_path = os.path.realpath(os.environ["DID_FILE_PATH"])
backup_did_file_path = os.path.realpath(os.environ["BACKUP_DID_FILE_PATH"])


def modify_file_contents(path, find, replacement):
    with open(path) as f:
        contents = f.read()

    new_contents = contents.replace(find, replacement)
    if new_contents == contents:
        raise ValueError(f"No change: {contents}")

    with open(path, "w") as f:
        f.write(new_contents)


def run_example_did_git_test(test_bin = "TEST_BIN"):
    return subprocess.run(
        [os.environ[test_bin]],
        env={
            "BUILD_WORKSPACE_DIRECTORY": workspace_dir,
            "TEST_TMPDIR": os.environ["TEST_TMPDIR"],
            "CI_PULL_REQUEST_TITLE": os.environ.get("CI_PULL_REQUEST_TITLE", ""),
        },
        capture_output=True,
    )


@pytest.fixture(autouse=True)
def setup_example_did():
    # setup
    shutil.copyfile(backup_did_file_path, did_file_path)

    # run test
    yield

    # tear down
    shutil.copyfile(backup_did_file_path, did_file_path)


def test_did_check_succeeds():
    res = run_example_did_git_test()

    message = "bazel/candid_integration_tests/example.did passed candid checks"
    assert message in res.stdout.decode("utf-8")
    assert res.returncode == 0


def test_remove_variants_check_fails():
    modify_file_contents(path=did_file_path, find="happy; sad", replacement="happy")

    res = run_example_did_git_test()

    error_message = "Method do_stuff: func (Request) -> () is not a subtype of func (Request/1) -> ()"

    assert error_message in res.stderr.decode("utf-8")
    assert res.returncode == 101


def test_adding_new_did_file_succeeds():
    res = run_example_did_git_test(test_bin = "NEW_DID_TEST")

    message = "is a new file, skipping backwards compatibility check"
    assert message in res.stdout.decode("utf-8")
    assert res.returncode == 0


def test_add_variants_succeeds():
    modify_file_contents(path=did_file_path, find="sad", replacement="sad; stunned")

    res = run_example_did_git_test()

    message = "bazel/candid_integration_tests/example.did passed candid checks"
    assert message in res.stdout.decode("utf-8")
    assert res.returncode == 0


def test_remove_required_field_from_input_check_fails():
    modify_file_contents(
        path=did_file_path,
        find="existing_required_request_field : int;",
        replacement="// Blank.",
    )

    res = run_example_did_git_test(test_bin = "TEST_BIN_ALSO_REVERSE")

    error_message = "Method dance: func (DanceRequest) -> (DanceResponse) is not a subtype of func (DanceRequest/1) -> (DanceResponse/1)"
    assert error_message in res.stderr.decode("utf-8")
    assert res.returncode == 101
    assert "running also-reverse check" in res.stdout.decode("utf-8")


def test_remove_required_field_from_output_check_fails():
    modify_file_contents(
        path=did_file_path,
        find="existing_required_response_field : int;",
        replacement="// Blank.",
    )

    res = run_example_did_git_test(test_bin = "TEST_BIN_ALSO_REVERSE")

    error_message = "Method dance: func (DanceRequest) -> (DanceResponse) is not a subtype of func (DanceRequest/1) -> (DanceResponse/1)"
    assert error_message in res.stderr.decode("utf-8")
    assert res.returncode == 101


def test_adding_a_required_field_to_input_check_fails():
    modify_file_contents(
        path=did_file_path,
        find="// Insert DanceRequest fields here.",
        replacement="new_required_int : int;",
    )

    res = run_example_did_git_test(test_bin = "TEST_BIN_ALSO_REVERSE")

    error_message = "Method dance: func (DanceRequest) -> (DanceResponse) is not a subtype of func (DanceRequest/1) -> (DanceResponse/1)"
    assert error_message in res.stderr.decode("utf-8")
    assert res.returncode == 101


def test_adding_optional_field_succeeds():
    modify_file_contents(
        path=did_file_path,
        find="// Insert DanceRequest fields here.",
        replacement="new_optional_int : opt int;",
    )

    res = run_example_did_git_test(test_bin = "TEST_BIN_ALSO_REVERSE")

    message = "bazel/candid_integration_tests/example.did passed candid checks"
    assert message in res.stdout.decode("utf-8")
    assert res.returncode == 0


def test_adding_optional_field_reverse_succeeds():
    modify_file_contents(
        path=did_file_path,
        find="// Insert DanceResponse fields here.",
        replacement="new_optional_int : opt int;",
    )

    res = run_example_did_git_test(test_bin = "TEST_BIN_ALSO_REVERSE")

    message = "bazel/candid_integration_tests/example.did passed candid checks"
    assert message in res.stdout.decode("utf-8")
    assert res.returncode == 0


def test_override_didc_checks_failing_check_succeeds():
    modify_file_contents(path=did_file_path, find="happy; sad", replacement="happy")

    res = run_example_did_git_test(test_bin = "TEST_BIN_ALSO_REVERSE")

    error_message = "Method do_stuff: func (Request) -> () is not a subtype of func (Request/1) -> ()"
    assert error_message in res.stderr.decode("utf-8")
    assert res.returncode == 101

    with mock.patch.dict(os.environ, {"CI_PULL_REQUEST_TITLE": "Best change ever [override-didc-check]"}):
        res = run_example_did_git_test(test_bin = "TEST_BIN_ALSO_REVERSE")
        assert res.returncode == 0
        assert (
            "Found [override-didc-check] in merge request title. Skipping didc_check."
            in res.stdout.decode("utf-8")
        )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
