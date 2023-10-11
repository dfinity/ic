#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys

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

def run_example_did_git_test():
    return subprocess.run(
        [os.environ["TEST_BIN"]],
        env={
            "BUILD_WORKSPACE_DIRECTORY": workspace_dir,
            "TEST_TMPDIR": os.environ["TEST_TMPDIR"]
        },
        capture_output=True
    )

@pytest.fixture(autouse=True)
def setup_example_did():
    #setup
    shutil.copyfile(backup_did_file_path, did_file_path)

    # run test
    yield

    # tear down
    shutil.copyfile(backup_did_file_path, did_file_path)


def test_did_check_succeeds():
    res = run_example_did_git_test()

    assert res.returncode == 0

def test_remove_variants_check_fails():
    modify_file_contents(path=did_file_path, find="happy; sad", replacement="happy")

    res = run_example_did_git_test()

    assert "The new interface at bazel/candid_integration_tests/example.did is not compatible with the old interface" in res.stderr.decode('utf-8')
    assert res.returncode == 101

@pytest.mark.skip(reason="Not sure how to do this")
def test_adding_new_did_file_succeeds():
    shutil.copyfile(backup_did_file_path, "new.did")

def test_add_variants_succeeds():
    modify_file_contents(path=did_file_path, find="sad", replacement="sad; stunned")

    res = run_example_did_git_test()

    assert res.returncode == 0

#Todo: enable also-reverse in candid check
@pytest.mark.skip(reason="Not implemented yet")
def test_remove_required_field_from_input_check_fails():
    modify_file_contents(path=did_file_path, find="existing_required_request_field : int;", replacement="// Blank.")

    run_example_did_git_test(also_revers=True)

#Todo: enable also-reverse in candid check
@pytest.mark.skip(reason="Not implemented yet")
def test_remove_required_field_from_output_check_fails():
    modify_file_contents(path=did_file_path, find="existing_required_response_field : int;", replacement="// Blank.")

    run_example_did_git_test(also_revers=True)

#Todo: enable also-reverse in candid check
@pytest.mark.skip(reason="Not implemented yet")
def test_adding_a_required_field_to_input_check_fails():
    modify_file_contents(path=did_file_path, find="// Insert DanceRequest fields here.", replacement="new_required_int : int;" )

    run_example_did_git_test(also_revers=True)


def test_adding_optional_field_succeeds():
    modify_file_contents(path=did_file_path, find="// Insert DanceRequest fields here.", replacement="new_optional_int : opt int;")

    res = run_example_did_git_test()

    assert res.returncode == 0

#Todo: enable also-reverse in candid check
@pytest.mark.skip(reason="Not implemented yet")
def test_adding_optional_field_reverse_succeeds():
    modify_file_contents(path=did_file_path, find="// Insert DanceResponse fields here.", replacement="new_optional_int : opt int;")

    run_example_did_git_test(also_revers=True)


#Todo: enable also-reverse in candid check
@pytest.mark.skip(reason="Not implemented yet")
def test_override_also_reverse():
    # Add a method to the service.
    modify_file_contents(path=did_file_path, find="// Comment within service.", replacement="new_method : () -> ();")

    run_example_did_git_test()

    with pytest.raises(subprocess.CalledProcessError):
        run_example_did_git_test(also_revers=True)

    # When the merge request title contains the magic words, --also-reverse should be disabled.
    os.environ["CI_MERGE_REQUEST_TITLE"] = "Best change ever [override-also-reverse]"
    run_example_did_git_test(also_revers=True)

if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
