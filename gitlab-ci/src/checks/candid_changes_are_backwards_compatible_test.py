"""
Tests candid_changes_are_backwards_compatible.

To run this manually, do the usual thing when it comes to the unittest standard
library module:

  cd "${where_this_file_lives}"
  python3 -m unittest candid_changes_are_backwards_compatible_test

This gets run automatically by the python-tests Gitlab CI job, which is defined
here:

  gitlab-ci/config/20--test--python.yml

"""
import contextlib
import io
import os
import shutil
import subprocess
import unittest

import candid_changes_are_backwards_compatible

SELF_DIR = os.path.split(__file__)[0]

DIDC = candid_changes_are_backwards_compatible.find_didc_or_exit()

# Commits that serve as test data.
NO_DO_STUFF_METHOD_SHA = "019035c1b0a832d9c5da3cebea6ad07b074338cc"  # example.did lacks the do_stuff method.
HAS_SECRET_METHOD_SHA = "b6c2758bf772669035a4ae06191f1e7fbb6055e6"  # example.did has a new method named secret_method.


def fetch_commit(commit):
    repo = "git@gitlab.com:dfinity-lab/public/ic.git"
    try:
        # Do not bother decoding output.
        subprocess.run(["git", "show", commit], capture_output=True, timeout=5.0, check=True)
    except subprocess.CalledProcessError:
        run(["git", "fetch", "--depth=1", repo, commit])


def decode(s):
    return bytes.decode(s, "utf8")


def encode(b):
    return str.encode(b, "utf8")


def run(cmd):
    timeout_s = 5.0
    ch = subprocess.run(cmd, capture_output=True, timeout=timeout_s, check=True)
    return decode(ch.stdout), decode(ch.stderr)


def run_against(file_name, *, also_reverse=False):
    cmd = ["./candid_changes_are_backwards_compatible.py"]
    if also_reverse:
        cmd.append("--also-reverse")
    cmd.append(file_name)
    return run(cmd)


def didc_check(did_file_path):
    run([DIDC, "check", did_file_path])


def modify_file_contents(*, path, find, replacement):
    with open(path) as f:
        contents = f.read()

    new_contents = contents.replace(find, replacement)
    if new_contents == contents:
        raise ValueError(f"No change: {contents}")

    with open(path, "w") as f:
        f.write(new_contents)

    didc_check(path)


def improved_subprocess_called_process_error_str(e):
    f = io.StringIO()
    with contextlib.redirect_stdout(f):
        print()
        candid_changes_are_backwards_compatible.print_run_fail(e, prefix=" " * 4)
    f.seek(0)
    return f.read()


@contextlib.contextmanager
def env(name, value):
    # Get original value so that we can restore later.
    original = original = os.environ.get(name)

    os.environ[name] = value
    try:
        yield
    finally:
        restore_environment_variable(name, original)


def clobber_environment_variable(name):
    original = os.environ.get(name)
    try:
        del os.environ[name]
    except KeyError:
        pass
    return original


def restore_environment_variable(name, original_value):
    if original_value is not None:
        os.environ[name] = original_value
        return

    try:
        del os.environ[name]
    except KeyError:
        pass


class CommandLineTest(unittest.TestCase):
    """Tests candid_changes_are_backwards_compatible.py."""

    def tearDown(self):
        """Clean up after each test."""
        run(["git", "restore", "example.did"])

    @staticmethod
    def setUpClass():
        """Prepare the world to run all test_* methods."""
        self = CommandLineTest

        fetch_commit(NO_DO_STUFF_METHOD_SHA)
        fetch_commit(HAS_SECRET_METHOD_SHA)

        self.original_working_dir = os.getcwd()
        print(f"Original working directory: {CommandLineTest.original_working_dir}")
        os.chdir(SELF_DIR)

        self.original_subprocess_called_process_error_str = subprocess.CalledProcessError.__str__
        subprocess.CalledProcessError.__str__ = improved_subprocess_called_process_error_str

        self.original_ci_merge_request_title = clobber_environment_variable("CI_MERGE_REQUEST_TITLE")
        self.original_ci_merge_request_diff_base_sha = clobber_environment_variable("CI_MERGE_REQUEST_DIFF_BASE_SHA")

    @staticmethod
    def tearDownClass():
        """Undo setUpClass."""
        self = CommandLineTest

        restore_environment_variable("CI_MERGE_REQUEST_DIFF_BASE_SHA", self.original_ci_merge_request_diff_base_sha)
        restore_environment_variable("CI_MERGE_REQUEST_TITLE", self.original_ci_merge_request_title)

        subprocess.CalledProcessError.__str__ = self.original_subprocess_called_process_error_str
        os.chdir(self.original_working_dir)

    def test_new_file_is_accepted(self):
        """Accept new .did file."""
        # Create a file that isn't already tracked by git.
        shutil.copyfile("example.did", "new.did")
        try:
            run_against("new.did")
        finally:
            os.remove("new.did")

    def test_add_variants_is_ok(self):
        """Changing an existing .did file by adding a value to a variant is ok."""
        modify_file_contents(path="example.did", find="sad", replacement="sad; stunned")

        run_against("example.did")

    def test_remove_variants_is_rejected(self):
        """Changing an existing .did file by REMOVING a value to a variant is NOT ok."""
        modify_file_contents(path="example.did", find="happy; sad", replacement="happy")

        with self.assertRaises(subprocess.CalledProcessError):
            run_against("example.did")

    def test_reject_removing_a_required_field_from_an_input(self):
        """Accept removing a required field from an input, unless --also-reverse is applied."""
        modify_file_contents(path="example.did", find="existing_required_request_field : int;", replacement="// Blank.")

        run_against("example.did")

        with self.assertRaises(subprocess.CalledProcessError):
            run_against("example.did", also_reverse=True)

    def test_reject_removing_a_required_field_from_an_output(self):
        """Reject removing a required field from an output regardless of whether --also-reverse is used."""
        modify_file_contents(
            path="example.did", find="existing_required_response_field : int;", replacement="// Blank."
        )

        with self.assertRaises(subprocess.CalledProcessError):
            run_against("example.did")
        with self.assertRaises(subprocess.CalledProcessError):
            run_against("example.did", also_reverse=True)

    def test_reject_adding_a_required_field_to_an_input(self):
        """Adding a required field should not be allowed."""
        modify_file_contents(
            path="example.did", find="// Insert DanceRequest fields here.", replacement="new_required_int : int;"
        )

        with self.assertRaises(subprocess.CalledProcessError):
            run_against("example.did", also_reverse=True)

    def test_reject_adding_a_required_field_to_an_output(self):
        """Adding a required field should not be allowed."""
        modify_file_contents(
            path="example.did", find="// Insert DanceResponse fields here.", replacement="new_required_int : int;"
        )

        with self.assertRaises(subprocess.CalledProcessError):
            run_against("example.did", also_reverse=True)

    def test_ok_to_add_optional_field(self):
        """
        Adding an optional field is ok in the forward AND reverse directions.

        This is the situation that we care about the most.
        """
        modify_file_contents(
            path="example.did", find="// Insert DanceRequest fields here.", replacement="new_optional_int : opt int;"
        )
        modify_file_contents(
            path="example.did", find="// Insert DanceResponse fields here.", replacement="new_optional_int : opt int;"
        )

        run_against("example.did", also_reverse=True)

    def test_gitlab_ci_diff_base(self):
        """What happens when it looks like we are in Gitlab CI mode."""
        # Make it look like we added a method.
        with env("CI_MERGE_REQUEST_DIFF_BASE_SHA", NO_DO_STUFF_METHOD_SHA):
            # Ok when run in forward-only mode.
            run_against("example.did")

            # Not ok when run in forward-and-backward mode.
            with self.assertRaises(subprocess.CalledProcessError):
                run_against("example.did", also_reverse=True)

        # Make it look like we deleted a method.
        with env("CI_MERGE_REQUEST_DIFF_BASE_SHA", HAS_SECRET_METHOD_SHA):
            # Not ok regardless of whether --also-reverse is used.
            with self.assertRaises(subprocess.CalledProcessError):
                run_against("example.did")
            with self.assertRaises(subprocess.CalledProcessError):
                run_against("example.did", also_reverse=True)

    def test_override_also_reverse(self):
        # Add a method to the servce.
        modify_file_contents(
            path="example.did", find="// Comment within service.", replacement="new_method : () -> ();"
        )

        # Adding a method is fine going forwards.
        run_against("example.did", also_reverse=False)

        # But it's not fine going backwards.
        with self.assertRaises(subprocess.CalledProcessError):
            run_against("example.did", also_reverse=True)

        # When the merge request title contains the magic words, --also-reverse should be disabled.
        with env("CI_MERGE_REQUEST_TITLE", "Best change evar [override-also-reverse]"):
            # Does not explode.
            run_against("example.did", also_reverse=True)
