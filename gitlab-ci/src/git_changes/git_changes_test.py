"""
Tests for the git_changes.

See 'setup_repo' for detailed description of how the tests are setup.

Test cases are taken from ./test_data/${testcase}. The before and after subdirs represent
the state of the git repo before and after. To see the files that have changes run:

    diff -qr before/ after/

Typical example usage:

    pytest
"""
import os
import shutil

from git import Repo

import git_changes


def setup_repo(tmpdir, testcase, branch="feature_branch"):
    """
    Set up a git repo with before and after changes.

    Performs the following operations.

        1. Create a new git repo in tmpdir.
        2. Copy testcases/before to tmpdir/rs/.
        3. Git commit the changes to master.
        4. Git creates a new feature branch.
        5. Copy testcases/after to tmpdir/rs/.
        6. Git commit to the feature branch.
        7. Run git_changes.get_changed_files against tmpdir

    Args:
    ----
        tmpdir: A temporary directory for the test to use.
        testcase: A string that corresponds to a testcase under the test_data subdir.
        branch: A string that corresponds to the branch to use.

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

    # Remove the environmental variable so that when these tests run on CI, cargo_deps
    # will grab the git branch from git not from the env variable.
    if "CI_COMMIT_REF_NAME" in os.environ:
        del os.environ["CI_COMMIT_REF_NAME"]


def test_change_one_file(tmpdir):
    """Tests that a commit has changed one crate."""
    setup_repo(tmpdir, "change_one_file")

    want = os.path.join(tmpdir, "rs", "changed")
    changed_files = git_changes.get_changed_files(tmpdir, ["rs"])
    assert want in changed_files

    changed_files = git_changes.get_changed_files(tmpdir, ["foobar"])
    assert not changed_files


def test_change_file_ignore(tmpdir):
    """Tests that a commit has changed one crate."""
    setup_repo(tmpdir, "change_file_ignore")

    want = os.path.join(tmpdir, "rs", "changed")
    changed_files = git_changes.get_changed_files(tmpdir, ["rs"], ["BUILD.bazel"])
    assert want in changed_files


def test_is_master_branch_true(tmpdir):
    """Tests that a commit has changed one crate."""
    setup_repo(tmpdir, "change_one_file", branch="master")
    assert git_changes.is_master(tmpdir)


def test_is_master_branch_false(tmpdir):
    """Tests that a commit has changed one crate."""
    setup_repo(tmpdir, "change_one_file")
    assert not git_changes.is_master(tmpdir)


def test_changed_gitlab_ci(tmpdir):
    """Tests that ci config change in /gitlab-ci was detected."""
    setup_repo(tmpdir, "ci_cfg_gitlab_ci")

    assert git_changes.ci_config_changes(tmpdir)


def test_changed_ci_cfg_gitlab_ci_config_yml(tmpdir):
    """Tests that ci config change in rs/gitlab-ci-config.yml was detected."""
    setup_repo(tmpdir, "ci_cfg_gitlab-ci-config-yml")

    assert git_changes.ci_config_changes(tmpdir)


def test_change_nix(tmpdir):
    """Tests that nix config change was detected."""
    setup_repo(tmpdir, "change_nix")

    assert git_changes.nix_shell_changes(os.path.join(tmpdir, "rs"))


def test_change_cargo_nix(tmpdir):
    """Tests that Cargo.nix change is ignored."""
    setup_repo(tmpdir, "change_cargo_nix")

    assert not git_changes.nix_shell_changes(os.path.join(tmpdir, "rs"))


def test_nochange_cargo_nix(tmpdir):
    """Tests that shell.nix comment change is ignored."""
    setup_repo(tmpdir, "nochange_nix")

    assert not git_changes.nix_shell_changes(os.path.join(tmpdir, "rs"))
