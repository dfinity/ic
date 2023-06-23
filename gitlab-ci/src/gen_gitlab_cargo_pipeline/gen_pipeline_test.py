"""
Tests for the gen_gitlab_cargo_pipeline module.

See 'run_test' for detailed description of how the tests are run.

Test cases are taken from ./test_data/${testcase}. The before and after subdirs represent
the state of the git repo before and after. To see the files that have changes run:

    diff -r before/ after/

Typical example usage:

    pytest tests.py
"""
import difflib
import filecmp
import os
import shutil

from git import Repo

from gen_gitlab_cargo_pipeline import gen_pipeline


def run_test(tmpdir, testcase, branch="feature_branch"):
    """
    Run the test defined in testdata/${testcase}.

    Performs the following operations.

        1. Create a new git repo in tmpdir.
        2. Copy testcases/before to tmpdir/rs/.
        3. Git commit the changes to master.
        4. Git creates a new feature branch.
        5. Copy testcases/after to tmpdir/rs/.
        6. Git commit to the feature branch.
        7. Run main.generate_tests against tmpdir/rs
        8. Compare testcases/before/expected.yml to the generated GitLab YAML config.

    The the test fails, print a path to the expected and generated YAML file and output the file
    diff.

    Args:
    ----
        tmpdir: A temporary directory for the test to use.
        testcase: A string that corresponds to a testcase under the test_data subdir.
        branch: A string that corresponds to the git branch to use for the test.

    """
    path = os.path.dirname(os.path.abspath(__file__))

    repo = Repo.init(tmpdir, bare=False)
    repo.config_writer().set_value("user", "name", "myusername").release()
    repo.config_writer().set_value("user", "email", "myemail").release()

    git = repo.git
    shutil.copytree(os.path.join(path, "test_data", testcase, "before"), tmpdir, dirs_exist_ok=True)
    git.add("-A")
    git.commit("-m initial commit")

    if branch != "master":
        git.checkout("HEAD", b=branch)

    for d in [f"{tmpdir}/rs", f"{tmpdir}/experimental"]:
        if os.path.isdir(d):
            shutil.rmtree(d)
    shutil.copytree(os.path.join(path, "test_data", testcase, "after"), tmpdir, dirs_exist_ok=True)
    git.add("-A")
    git.commit("--allow-empty", "-m feature commit")

    out_filename = os.path.join(tmpdir, "cargo-tests.yml")

    # Remove some some env variables when running tests on CI.
    if "CI_COMMIT_REF_NAME" in os.environ:
        # Make cargo_deps grab the git branch from git and not the env var.
        del os.environ["CI_COMMIT_REF_NAME"]

        # Remove the CI_PIPELINE_ID so that gen cargo pipeline doesn't generate PARENT_PIPELIEN_ID
        # global variable in the CI config. This existance of this env variable is inconsistent
        # across local development test runs and CI tests.
        if "CI_PIPELINE_ID" in os.environ:
            del os.environ["CI_PIPELINE_ID"]

        # Remove CI_MERGE_REQUEST_TITLE from the test suite. This will cause failures on MRs marked
        # with "lessci", because this python test will inherit that value and thus no cargo pipelines
        # will be generated.
        if "CI_MERGE_REQUEST_TITLE" in os.environ:
            del os.environ["CI_MERGE_REQUEST_TITLE"]

        if "CI_MERGE_REQUEST_EVENT_TYPE" in os.environ:
            del os.environ["CI_MERGE_REQUEST_EVENT_TYPE"]

        # Remove CI_MERGE_REQUEST_EVENT_TYPE from the test suite. This will cause the tests to fail
        # while in a merge train.
        if "CI_MERGE_REQUEST_TITLE" in os.environ:
            del os.environ["CI_MERGE_REQUEST_EVENT_TYPE"]

        if "CI_MERGE_REQUEST_TARGET_BRANCH_NAME" in os.environ:
            del os.environ["CI_MERGE_REQUEST_TARGET_BRANCH_NAME"]

    if "CI_COMMIT_REF_PROTECTED" in os.environ:
        del os.environ["CI_COMMIT_REF_PROTECTED"]

    if branch == "master":
        os.environ["CI_COMMIT_REF_PROTECTED"] = "true"

    with open(out_filename, "w") as fout:
        gen_pipeline.generate_tests(
            os.path.join(tmpdir, "rs"),
            os.path.join(tmpdir, "ic-os", "guestos"),
            fout,
            dry_run=True,
            cargo_sample_size=1,
        )

    wantf = os.path.join(path, "test_data", testcase, "expected.yml")

    if not filecmp.cmp(out_filename, wantf):
        with open(out_filename) as file1:
            f1_text = file1.readlines()
        with open(wantf) as file2:
            f2_text = file2.readlines()
        # Find and print the diff:
        assert False, out_filename + " != " + wantf + " \n" + "".join(difflib.ndiff(f1_text, f2_text))
