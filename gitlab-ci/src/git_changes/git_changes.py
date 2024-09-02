#!/usr/bin/env python3
"""
A helper package.

This package provides common functions for deciding whether or how to run a CI job based on
changes between the merge base, or which branch CI is on.

Example usage:

Find changed files in the `rs` directory:
  python git_changes.py --changed-files-in-dirs rs
"""
import argparse
import functools
import logging
import os
import sys
import time
from pprint import pformat

import git


def target_branch() -> str:
    default_branch = os.getenv("CI_DEFAULT_BRANCH", "master")
    return os.getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", default_branch)


def git_fetch_target_branch(git_repo, max_attempts=10):
    exc = None
    tb = target_branch()
    for i in range(max_attempts):
        try:
            # Get the 1st remote name. This is typically 'origin' but may be something else as well.
            remote_name = git_repo.git.remote("show").split()[0]
            origin = git_repo.remote(name=remote_name)
            logging.info(f"Updating {tb} branch: git fetch {remote_name} {tb}:{tb}")
            origin.fetch(f"{tb}:{tb}", prune=True, prune_tags=True, force=True)
            return
        except git.exc.GitCommandError as e:
            logging.warning("Error [%d/%d] fetching changes: %s", i, max_attempts, e)
            exc = e
            time.sleep(10)
    if exc:
        raise exc  # raise the last exception if there were too many attempts


@functools.lru_cache(maxsize=32)  # Only fetch the target branch once per execution
def get_merge_base(git_repo):
    tb = target_branch()
    if not git_repo.head.is_detached and str(git_repo.active_branch) == tb:
        # Support running the function (tests) on master
        return [git_repo.head.commit]
    # Make sure the master branch is up-to-date.
    if git_repo.remotes:
        git_fetch_target_branch(git_repo)
    else:
        logging.warning("No git remotes found.")

    merge_base = git_repo.merge_base(tb, git_repo.head.commit)
    if not merge_base:
        logging.error("No common merge base exists between HEAD and {tb}")
        ref_name = git_repo.head.ref
        raise ValueError(f"No merge base between {ref_name} and {tb}.")

    return merge_base


def get_changed_files(repo_path, glob_paths, ignored_files=[]):
    """
    Return a set of changes.

    We return a set of files changed between HEAD and mergebase(target_branch, HEAD)
    that are inside one or more glob_paths.

    Args:
    ----
        repo_path: The path to the git repository.
        glob_paths: A list of string paths relative to the git repo root.
        ignored_files: A list of string paths to ignore.

    Returns
    -------
    The set of changed file paths.

    """
    git_repo = git.Repo(repo_path, search_parent_directories=True)
    git_root = git_repo.git.rev_parse("--show-toplevel")

    merge_base = get_merge_base(git_repo)

    logging.debug("The merge base is: %s", merge_base)
    changed_files = [os.path.join(git_root, item.a_path) for item in git_repo.index.diff(merge_base[0])]

    logging.debug("The following files have changed since the merge base: %s", changed_files)

    changed_files = [item for item in changed_files if os.path.basename(item) not in ignored_files]
    logging.debug(
        "The following files have changed since the merge base after ignored files have been dropped: %s", changed_files
    )

    # realpath canonicalizes the path e.g. removes trailing slashes.
    glob_paths = [os.path.realpath(os.path.join(git_root, item)) for item in glob_paths]
    logging.debug("Glob paths are: %s", pformat(glob_paths, indent=4))

    ans = set()
    for item in changed_files:
        for glob_path in glob_paths:
            logging.debug("Check %s against %s", item, glob_path)
            common_path = os.path.commonpath([item, glob_path])
            logging.debug("Common path: %s", common_path)
            if common_path.startswith(glob_path):
                logging.debug("%s matches %s", glob_path, item)
                ans.add(item)

    logging.debug("Matched files against glob dirs: %s", pformat(ans))
    return ans


def is_protected():
    return os.getenv("CI_COMMIT_REF_PROTECTED", "false") == "true"


def is_master(repo_path):
    """
    Return whether the master branch is checked out.

    Args:
    ----
        repo_path: The path to the git repository.

    Returns
    -------
    True or False

    """
    if "CI_COMMIT_REF_NAME" in os.environ:
        return os.environ["CI_COMMIT_REF_NAME"] == "master"
    else:
        git_repo = git.Repo(repo_path, search_parent_directories=True)
        return git_repo.active_branch.name == "master"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")
    parser.add_argument(
        "--changed-files-in-dirs",
        action="store",
        nargs="+",
        help="List changed files in the provided directories",
    )
    parser.add_argument(
        "--ci-config-changes",
        action="store_true",
        help="List the CI config changes in this branch",
    )

    args = parser.parse_args()

    if not args.changed_files_in_dirs:
        parser.print_help()
        sys.exit(0)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.changed_files_in_dirs:
        changed_files = get_changed_files(".", args.changed_files_in_dirs)
        logging.info("Changed files: %s", pformat(changed_files))
        sys.exit(not changed_files)
